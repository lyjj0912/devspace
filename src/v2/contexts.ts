import { createHash, randomUUID } from "node:crypto";
import { execFile } from "node:child_process";
import {
  mkdir,
  readFile,
  readdir,
  realpath,
  rm,
  rename,
  stat,
  writeFile,
} from "node:fs/promises";
import { homedir } from "node:os";
import {
  dirname,
  basename,
  isAbsolute,
  join,
  parse,
  posix,
  relative,
  resolve,
} from "node:path";
import { promisify } from "node:util";
import type { ServerConfig } from "../config.js";
import { getGitEligibility, git } from "../git.js";
import { expandHomePath, isPathInsideRoot } from "../roots.js";
import { formatPathForPrompt, loadWorkspaceSkills } from "../skills.js";
import {
  UNIVERSAL_BROKER_BUDGETS,
  type UniversalErrorCode,
} from "./contracts.js";
import {
  createCapabilityCallContextFromTrustedPrincipal,
  requireCapabilityCallContext,
  type CapabilityCallContext,
  type CapabilityCallContextProvider,
} from "./capability-call-context.js";
import { UniversalBrokerError } from "./errors.js";
import {
  SynchronousQuotaReservations,
  type QuotaReservation,
} from "./quota-reservations.js";
import {
  RESOURCE_DEFAULT_CONTEXTS,
  RESOURCE_DEFAULT_CONTEXT_TTL_MS,
} from "./resource-defaults.js";
import { UniversalTextResourceStore } from "./text-resource-store.js";
import {
  type TargetDefinition,
  type TargetRegistry,
} from "./targets.js";

const execFileAsync = promisify(execFile);
const CONTEXT_FILE_NAMES = ["AGENTS.md", "CLAUDE.md"] as const;
const MAX_SUGGESTED_SKILLS = 5;
const MAX_INITIAL_INSTRUCTION_REFERENCES = 10;
const MAX_SEARCH_RESULTS = 50;
const MAX_CONTEXTS = RESOURCE_DEFAULT_CONTEXTS;
const DEFAULT_CONTEXT_IDLE_TTL_MS = RESOURCE_DEFAULT_CONTEXT_TTL_MS;
const DEFAULT_MAXIMUM_WORKTREES = 8;
const DEFAULT_MAXIMUM_WORKTREE_BYTES = 8 * 1024 * 1024 * 1024;
const MAXIMUM_DIFF_CHARACTERS = 50_000_000;
const MAX_NESTED_SEARCH_DEPTH = 6;
const MAX_NESTED_SEARCH_ENTRIES = 5_000;
const STORE_VERSION = 2;
const SKILL_CATALOG_TTL_MS = 60_000;

export type ContextMode = "existing" | "worktree";

export interface InstructionReference {
  path: string;
  size: number;
  sha256: string;
  required: boolean;
  scope: "ancestor" | "root" | "nested";
}

export interface SkillReference {
  name: string;
  description: string;
  path: string;
  score: number;
}

export interface ContextGitSummary {
  repositoryRoot: string;
  head?: string;
  branch?: string;
  dirty: boolean;
}

export interface ContextRecord {
  contextId: string;
  principalKeyFingerprint: string;
  targetId: string;
  targetGeneration: string;
  root: string;
  mode: ContextMode;
  instructionSetHash: string;
  instructions: InstructionReference[];
  git?: ContextGitSummary;
  managed?: boolean;
  sourceRoot?: string;
  baseRef?: string;
  baseSha?: string;
  dirtySource?: boolean;
  createdAt: string;
  lastUsedAt: string;
  expiresAt: string;
}

interface ContextStoreFile {
  version: 2;
  contexts: ContextRecord[];
  tombstones: ContextTombstone[];
}

interface ContextTombstone {
  contextId: string;
  principalKeyFingerprint: string;
  targetId: string;
  targetGeneration: string;
  expiredAt: string;
  tombstonedAt: string;
  removeAfter: string;
}

export interface ContextRegistryOptions {
  storePath: string;
  targets: TargetRegistry;
  serverConfig: ServerConfig;
  now?: () => number;
  maximumContexts?: number;
  idleTtlMs?: number;
  worktreeRoot?: string;
  maximumWorktrees?: number;
  maximumWorktreeBytes?: number;
  diffStore?: UniversalTextResourceStore;
  ownerProvider?: CapabilityCallContextProvider;
  tombstoneTtlMs?: number;
  execute?: typeof execFileAsync;
}

export class ContextRegistry {
  private readonly contexts = new Map<string, ContextRecord>();
  private readonly tombstones = new Map<string, ContextTombstone>();
  private readonly contextIdByKey = new Map<string, string>();
  private readonly pendingOpen = new Map<string, Promise<ContextOpenResult>>();
  private readonly skillCatalogCache = new Map<string, {
    loadedAt: number;
    skills: ReturnType<typeof loadWorkspaceSkills>["skills"];
  }>();
  private readonly now: () => number;
  private readonly maximumContexts: number;
  private readonly idleTtlMs: number;
  private readonly worktreeRoot: string;
  private readonly maximumWorktrees: number;
  private readonly maximumWorktreeBytes: number;
  private readonly tombstoneTtlMs: number;
  private readonly diffStore: UniversalTextResourceStore;
  private readonly ownerProvider: CapabilityCallContextProvider;
  private readonly reservations: SynchronousQuotaReservations;
  private readonly worktreeReservations: SynchronousQuotaReservations;
  private readonly execute: typeof execFileAsync;
  private loaded = false;
  private loadPromise?: Promise<void>;
  private mutationQueue: Promise<void> = Promise.resolve();

  constructor(private readonly options: ContextRegistryOptions) {
    this.now = options.now ?? Date.now;
    this.maximumContexts = options.maximumContexts ?? MAX_CONTEXTS;
    this.idleTtlMs = boundedContextInteger(
      options.idleTtlMs,
      DEFAULT_CONTEXT_IDLE_TTL_MS,
      1_000,
      24 * 60 * 60_000,
      "idleTtlMs",
    );
    this.worktreeRoot = resolve(options.worktreeRoot ?? join(dirname(options.storePath), "worktrees"));
    this.maximumWorktrees = options.maximumWorktrees ?? DEFAULT_MAXIMUM_WORKTREES;
    this.maximumWorktreeBytes = options.maximumWorktreeBytes ?? DEFAULT_MAXIMUM_WORKTREE_BYTES;
    this.tombstoneTtlMs = boundedContextInteger(
      options.tombstoneTtlMs,
      RESOURCE_DEFAULT_CONTEXT_TTL_MS,
      1_000,
      7 * 24 * 60 * 60_000,
      "tombstoneTtlMs",
    );
    const compatibilityOwner = createCapabilityCallContextFromTrustedPrincipal({
      principalKeyFingerprint: createHash("sha256")
        .update(JSON.stringify({
          authority: "legacy-single-owner-context-registry",
          publicBaseUrl: options.serverConfig.publicBaseUrl,
          stateDir: options.serverConfig.stateDir,
          storePath: resolve(options.storePath),
        }))
        .digest("hex"),
    });
    this.ownerProvider = options.ownerProvider ?? (() => compatibilityOwner);
    this.diffStore = options.diffStore ?? new UniversalTextResourceStore({
      authority: "context-diff",
      maximumEntries: 64,
      maximumTotalCharacters: MAXIMUM_DIFF_CHARACTERS,
      ttlMs: 15 * 60_000,
      ownerProvider: this.ownerProvider,
    });
    this.reservations = new SynchronousQuotaReservations("context", {
      entries: this.maximumContexts,
    });
    this.worktreeReservations = new SynchronousQuotaReservations("managed-worktree", {
      entries: this.maximumWorktrees,
    });
    this.execute = options.execute ?? execFileAsync;
  }

  async open(input: {
    target?: string;
    path?: string;
    mode?: ContextMode;
    task?: string;
    baseRef?: string;
  }, callContext?: CapabilityCallContext): Promise<ContextOpenResult> {
    await this.ensureLoaded();
    await this.pruneExpiredContexts();
    const owner = this.owner(callContext);
    const { target, generation: targetGeneration } =
      await this.options.targets.resolveWithGeneration(input.target);
    const mode = input.mode ?? "existing";
    const requestedPath = input.path ?? target.defaultCwd;
    if (!requestedPath) {
      throw new UniversalBrokerError(
        "PRECONDITION_FAILED",
        `context.open requires path because target ${target.id} has no defaultCwd.`,
      );
    }
    if (mode === "worktree") {
      return this.openWorktree(
        target,
        targetGeneration,
        requestedPath,
        input.task,
        input.baseRef,
        owner,
      );
    }
    const root = await this.resolveExistingDirectory(target, requestedPath);
    const key = contextKey(owner.principalKeyFingerprint, target.id, targetGeneration, root, mode);
    const pending = this.pendingOpen.get(key);
    if (pending) return pending;

    const operation = this.openResolved(target, targetGeneration, root, mode, input.task, owner)
      .finally(() => this.pendingOpen.delete(key));
    this.pendingOpen.set(key, operation);
    return operation;
  }

  async search(input: {
    contextId?: string;
    query?: string;
    cursor?: string;
    limit?: number;
  }, callContext?: CapabilityCallContext): Promise<Record<string, unknown>> {
    await this.ensureLoaded();
    await this.pruneExpiredContexts();
    const owner = this.owner(callContext);
    const query = input.query?.trim();
    if (!query) {
      throw new UniversalBrokerError(
        "PRECONDITION_FAILED",
        "context.search requires a non-empty query.",
      );
    }
    const record = input.contextId
      ? await this.requireFreshContext(input.contextId, owner)
      : undefined;
    if (record) await this.touch(record);
    const target = record
      ? await this.options.targets.resolve(record.targetId)
      : await this.options.targets.resolve("local");
    const skillRoot = record && target.transport === "local" ? record.root : homedir();
    const skills = this.suggestSkills(skillRoot, query, input.limit ?? MAX_SUGGESTED_SKILLS);
    const instructions = record && target.transport === "local"
      ? await this.searchNestedInstructions(record.root, query)
      : record?.instructions.filter((reference) => fuzzyTextMatch(reference.path, query)) ?? [];
    const combined = [
      ...skills.map((skill) => ({ type: "skill", ...skill })),
      ...instructions.map((instruction) => ({ type: "instruction", ...instruction })),
    ];
    const offset = parseCursor(input.cursor);
    const limit = Math.min(Math.max(input.limit ?? 20, 1), MAX_SEARCH_RESULTS);
    const page = combined.slice(offset, offset + limit);
    const nextOffset = offset + page.length;
    return {
      ...(record ? { contextId: record.contextId } : {}),
      query,
      results: page,
      ...(nextOffset < combined.length ? { nextCursor: String(nextOffset) } : {}),
    };
  }

  async diff(input: {
    contextId: string;
    maxCharacters?: number;
  }, callContext?: CapabilityCallContext): Promise<Record<string, unknown>> {
    await this.ensureLoaded();
    await this.pruneExpiredContexts();
    const owner = this.owner(callContext);
    const record = await this.requireFreshContext(input.contextId, owner);
    await this.touch(record);
    const target = await this.options.targets.resolve(record.targetId);
    const generated = target.transport === "local"
      ? await localContextDiff(record.root)
      : await this.remoteContextDiff(target, record.root);
    const maximumPreview = Math.min(Math.max(input.maxCharacters ?? 12_000, 100), 100_000);
    const stored = this.diffStore.put(generated.text, "text/x-diff", owner);
    return {
      contextId: record.contextId,
      targetId: record.targetId,
      root: record.root,
      summary: generated.summary,
      preview: headTail(generated.text, maximumPreview),
      truncated: generated.text.length > maximumPreview,
      ...stored,
    };
  }

  readDiffResource(uri: string, callContext?: CapabilityCallContext): Record<string, unknown> {
    return this.diffStore.readByUri(uri, this.owner(callContext));
  }

  stats(): Record<string, unknown> {
    const managed = [...this.contexts.values()].filter((record) => record.managed === true);
    return {
      contexts: this.contexts.size,
      tombstones: this.tombstones.size,
      managedWorktrees: managed.length,
      idleTtlMs: this.idleTtlMs,
      diffResources: this.diffStore.stats(),
    };
  }

  async close(
    contextId: string,
    callContext?: CapabilityCallContext,
  ): Promise<Record<string, unknown>> {
    await this.ensureLoaded();
    await this.pruneExpiredContexts();
    const owner = this.owner(callContext);
    const record = await this.requireFreshContext(contextId, owner);
    const worktree = record.managed
      ? await this.closeManagedWorktree(record)
      : undefined;
    if (worktree?.retained === true) {
      this.refreshExpiry(record);
      await this.persist();
      return {
        contextId,
        closed: false,
        targetId: record.targetId,
        root: record.root,
        worktree,
      };
    }
    this.contexts.delete(contextId);
    this.contextIdByKey.delete(contextKey(
      record.principalKeyFingerprint,
      record.targetId,
      record.targetGeneration,
      record.root,
      record.mode,
    ));
    await this.persist();
    return {
      contextId,
      closed: true,
      targetId: record.targetId,
      root: record.root,
      ...(worktree ? { worktree } : {}),
    };
  }

  closeResources(): void {
    this.diffStore.clear();
  }

  async cleanupExpired(): Promise<Record<string, unknown>> {
    await this.ensureLoaded();
    return this.pruneExpiredContexts();
  }

  async get(
    contextId: string,
    callContext?: CapabilityCallContext,
  ): Promise<ContextRecord> {
    await this.ensureLoaded();
    await this.pruneExpiredContexts();
    const owner = this.owner(callContext);
    const record = await this.requireFreshContext(contextId, owner);
    await this.touch(record);
    return structuredClone(record);
  }

  private async openResolved(
    target: TargetDefinition,
    targetGeneration: string,
    root: string,
    mode: ContextMode,
    task: string | undefined,
    owner: CapabilityCallContext,
  ): Promise<ContextOpenResult> {
    const key = contextKey(owner.principalKeyFingerprint, target.id, targetGeneration, root, mode);
    const existingId = this.contextIdByKey.get(key);
    const reservation = existingId ? undefined : this.reserveContext();
    try {
    const instructions = await this.discoverInitialInstructions(target, root);
    const instructionSetHash = hashInstructionSet(instructions);
    if (existingId) {
      const existing = this.requireOwnedContext(existingId, owner);
      const changed = existing.instructionSetHash !== instructionSetHash;
      existing.instructions = instructions;
      existing.instructionSetHash = instructionSetHash;
      this.refreshExpiry(existing);
      await this.persist();
      const result: ContextOpenResult = {
        contextId: existing.contextId,
        targetId: existing.targetId,
        targetGeneration: existing.targetGeneration,
        reused: true,
        changed,
        instructionSetHash,
      };
      assertPayloadBudget(
        result,
        UNIVERSAL_BROKER_BUDGETS.maximumReusedContextCharacters,
        "reused context",
      );
      return result;
    }

      const timestampMs = this.now();
      const timestamp = new Date(timestampMs).toISOString();
      const record: ContextRecord = {
        contextId: `ctx_${randomUUID()}`,
        principalKeyFingerprint: owner.principalKeyFingerprint,
        targetId: target.id,
        targetGeneration,
        root,
        mode,
        instructionSetHash,
        instructions,
        git: target.transport === "local" ? await gitSummary(root) : undefined,
        createdAt: timestamp,
        lastUsedAt: timestamp,
        expiresAt: new Date(timestampMs + this.idleTtlMs).toISOString(),
      };
      reservation!.commit(() => {
        this.contexts.set(record.contextId, record);
        this.contextIdByKey.set(key, record.contextId);
      });
      await this.persist();
      return fitInitialContextPayload({
        contextId: record.contextId,
        targetId: record.targetId,
        targetGeneration: record.targetGeneration,
        root: record.root,
        mode: record.mode,
        reused: false,
        instructionSetHash,
        instructions: instructions.slice(0, MAX_INITIAL_INSTRUCTION_REFERENCES),
        suggestedSkills: task
          ? this.suggestSkills(target.transport === "local" ? root : homedir(), task, MAX_SUGGESTED_SKILLS)
          : [],
        ...(record.git ? { git: record.git } : {}),
      });
    } catch (error) {
      reservation?.release();
      throw error;
    }
  }

  private async openWorktree(
    target: TargetDefinition,
    targetGeneration: string,
    requestedPath: string,
    task: string | undefined,
    requestedBaseRef: string | undefined,
    owner: CapabilityCallContext,
  ): Promise<ContextOpenResult> {
    await this.ensureLoaded();
    const contextReservation = this.reserveContext();
    const managedCount = [...this.contexts.values()].filter((record) => record.managed).length;
    let worktreeReservation: QuotaReservation;
    try {
      worktreeReservation = this.worktreeReservations.reserve(
        { entries: managedCount },
        { entries: 1 },
      );
    } catch (error) {
      contextReservation.release();
      throw error;
    }
    let created: CreatedWorktree | undefined;
    let persisted = false;
    try {
    const sourcePath = await this.resolveExistingDirectory(target, requestedPath);
    const baseRef = requestedBaseRef?.trim() || "HEAD";
    created = target.transport === "local"
      ? await this.createLocalWorktree(sourcePath, baseRef)
      : target.platform === "windows"
        ? await this.createWindowsRemoteWorktree(target, sourcePath, baseRef)
        : await this.createPosixRemoteWorktree(target, sourcePath, baseRef);
      const createdBytes = target.transport === "local"
        ? await localDirectoryBytes(created.root)
        : await this.remoteDirectoryBytes(target, created.root);
      const currentBytes = await this.managedWorktreeBytes(target.id) + createdBytes;
      if (currentBytes > this.maximumWorktreeBytes) {
        await this.removeCreatedWorktree(target, created).catch(() => undefined);
        throw new UniversalBrokerError(
          "RESOURCE_QUOTA_EXCEEDED",
          `Managed worktree byte quota exceeded: ${this.maximumWorktreeBytes}`,
          { evidence: { currentBytes, maximumWorktreeBytes: this.maximumWorktreeBytes } },
        );
      }
      const instructions = await this.discoverInitialInstructions(target, created.root);
      const instructionSetHash = hashInstructionSet(instructions);
      const timestampMs = this.now();
      const timestamp = new Date(timestampMs).toISOString();
      const record: ContextRecord = {
        contextId: `ctx_${randomUUID()}`,
        principalKeyFingerprint: owner.principalKeyFingerprint,
        targetId: target.id,
        targetGeneration,
        root: created.root,
        mode: "worktree",
        instructionSetHash,
        instructions,
        managed: true,
        sourceRoot: created.sourceRoot,
        baseRef,
        baseSha: created.baseSha,
        dirtySource: created.dirtySource,
        git: target.transport === "local" ? await gitSummary(created.root) : {
          repositoryRoot: created.root,
          head: created.baseSha,
          dirty: false,
        },
        createdAt: timestamp,
        lastUsedAt: timestamp,
        expiresAt: new Date(timestampMs + this.idleTtlMs).toISOString(),
      };
      contextReservation.commit(() => worktreeReservation!.commit(() => {
        this.contexts.set(record.contextId, record);
        this.contextIdByKey.set(contextKey(
          record.principalKeyFingerprint,
          record.targetId,
          record.targetGeneration,
          record.root,
          record.mode,
        ), record.contextId);
      }));
      await this.persist();
      persisted = true;
      return fitInitialContextPayload({
        contextId: record.contextId,
        targetId: record.targetId,
        targetGeneration: record.targetGeneration,
        root: record.root,
        mode: record.mode,
        reused: false,
        instructionSetHash,
        instructions: instructions.slice(0, MAX_INITIAL_INSTRUCTION_REFERENCES),
        suggestedSkills: task
          ? this.suggestSkills(target.transport === "local" ? record.root : homedir(), task, MAX_SUGGESTED_SKILLS)
          : [],
        git: record.git,
        managed: true,
        sourceRoot: record.sourceRoot,
        baseRef: record.baseRef,
        baseSha: record.baseSha,
        dirtySource: record.dirtySource,
      });
    } catch (error) {
      contextReservation.release();
      worktreeReservation.release();
      if (!persisted && created) {
        await this.removeCreatedWorktree(target, created).catch(() => undefined);
      }
      throw error;
    }
  }

  private async pruneExpiredContexts(): Promise<Record<string, unknown>> {
    const now = this.now();
    let tombstonesRemoved = 0;
    for (const tombstone of this.tombstones.values()) {
      if (Date.parse(tombstone.removeAfter) > now) continue;
      this.tombstones.delete(tombstone.contextId);
      tombstonesRemoved += 1;
    }
    const expired = [...this.contexts.values()]
      .filter((record) => Date.parse(record.expiresAt) <= now)
      .sort((left, right) => left.contextId.localeCompare(right.contextId));
    let removed = 0;
    let retained = 0;
    let errors = 0;
    for (const record of expired) {
      if (!this.contexts.has(record.contextId)) continue;
      try {
        if (record.managed) {
          const worktree = await this.closeManagedWorktree(record);
          if (worktree.retained === true) {
            this.refreshExpiry(record);
            retained += 1;
            continue;
          }
        }
        this.expireContext(record, now);
        removed += 1;
      } catch {
        errors += 1;
      }
    }
    if (removed > 0 || retained > 0 || tombstonesRemoved > 0) await this.persist();
    return {
      expired: expired.length,
      removed,
      retained,
      errors,
      remaining: this.contexts.size,
    };
  }

  private async createLocalWorktree(
    sourcePath: string,
    baseRef: string,
  ): Promise<CreatedWorktree> {
    const sourceRoot = await localGitRoot(sourcePath);
    const baseSha = await localGitText(sourceRoot, ["rev-parse", "--verify", `${baseRef}^{commit}`],
      `Git baseRef does not resolve to a commit: ${baseRef}`);
    const dirtySource = (await localGitText(sourceRoot, ["status", "--porcelain=v1"], "Unable to inspect source repository.")).length > 0;
    await mkdir(this.worktreeRoot, { recursive: true, mode: 0o700 });
    const root = join(this.worktreeRoot, `${sanitizePathSegment(basename(sourceRoot))}-${randomUUID().slice(0, 8)}`);
    try {
      await execFileAsync("git", ["-C", sourceRoot, "worktree", "add", "--detach", root, baseSha], {
        encoding: "utf8",
        maxBuffer: 10 * 1024 * 1024,
      });
      return { root, sourceRoot, baseSha, dirtySource };
    } catch (error) {
      await rm(root, { recursive: true, force: true });
      throw new UniversalBrokerError(
        "PRECONDITION_FAILED",
        `Unable to create managed worktree from ${sourceRoot}.`,
        { evidence: { baseRef, error: boundedError(error) } },
      );
    }
  }

  private async createPosixRemoteWorktree(
    target: TargetDefinition,
    sourcePath: string,
    baseRef: string,
  ): Promise<CreatedWorktree> {
    if (!target.sshHost) throw new UniversalBrokerError("TARGET_OFFLINE", `SSH target has no sshHost: ${target.id}`);
    const id = randomUUID().slice(0, 8);
    const script = [
      `requested=${shellQuote(sourcePath)}`,
      `base_ref=${shellQuote(baseRef)}`,
      "source_root=$(git -C \"$requested\" rev-parse --show-toplevel 2>/dev/null) || { printf '__DEVSPACE_NOT_GIT__\\n'; exit 44; }",
      "base_sha=$(git -C \"$source_root\" rev-parse --verify \"${base_ref}^{commit}\" 2>/dev/null) || { printf '__DEVSPACE_BAD_BASE__\\n'; exit 45; }",
      "dirty=0; [ -n \"$(git -C \"$source_root\" status --porcelain=v1)\" ] && dirty=1",
      `name=$(basename "$source_root" | tr -cs 'A-Za-z0-9._-' '-')-${id}`,
      "worktree_root=$HOME/.devspace/worktrees",
      "mkdir -p \"$worktree_root\" && chmod 700 \"$worktree_root\"",
      "root=$worktree_root/$name",
      "git -C \"$source_root\" worktree add --detach \"$root\" \"$base_sha\" >/dev/null",
      "printf '__DEVSPACE_WORKTREE__\\t%s\\t%s\\t%s\\t%s\\n' \"$root\" \"$source_root\" \"$base_sha\" \"$dirty\"",
    ].join("; ");
    try {
      const result = await this.execute(
        "ssh",
        sshArguments(target.sshHost, `sh -lc ${shellQuote(script)}`),
        { timeout: 30_000, encoding: "utf8", maxBuffer: 256 * 1024 },
      );
      return parseCreatedWorktree(result.stdout);
    } catch (error) {
      const output = processOutput(error);
      throw new UniversalBrokerError(
        output.includes("__DEVSPACE_BAD_BASE__") ? "PRECONDITION_FAILED" : "TRANSPORT_INTERRUPTED",
        output.includes("__DEVSPACE_NOT_GIT__")
          ? `Remote context path is not inside a Git repository: ${sourcePath}`
          : output.includes("__DEVSPACE_BAD_BASE__")
            ? `Remote Git baseRef does not resolve to a commit: ${baseRef}`
            : `Unable to create remote managed worktree on target ${target.id}.`,
        { evidence: { targetId: target.id, baseRef, error: boundedError(error) } },
      );
    }
  }

  private async createWindowsRemoteWorktree(
    target: TargetDefinition,
    sourcePath: string,
    baseRef: string,
  ): Promise<CreatedWorktree> {
    if (!target.sshHost) throw new UniversalBrokerError("TARGET_OFFLINE", `SSH target has no sshHost: ${target.id}`);
    const id = randomUUID().slice(0, 8);
    const command = [
      `$requested='${sourcePath.replaceAll("'", "''")}'`,
      `$baseRef='${baseRef.replaceAll("'", "''")}'`,
      "$sourceRoot=(git -C $requested rev-parse --show-toplevel 2>$null)",
      "if ($LASTEXITCODE -ne 0) { Write-Output '__DEVSPACE_NOT_GIT__'; exit 44 }",
      "$baseSha=(git -C $sourceRoot rev-parse --verify ($baseRef + '^{commit}') 2>$null)",
      "if ($LASTEXITCODE -ne 0) { Write-Output '__DEVSPACE_BAD_BASE__'; exit 45 }",
      "$dirty=if ((git -C $sourceRoot status --porcelain=v1)) { 1 } else { 0 }",
      "$worktreeRoot=Join-Path $env:USERPROFILE '.devspace\\worktrees'",
      "New-Item -ItemType Directory -Force -Path $worktreeRoot | Out-Null",
      `$name=((Split-Path -Leaf $sourceRoot) -replace '[^A-Za-z0-9._-]+','-') + '-${id}'`,
      "$root=Join-Path $worktreeRoot $name",
      "git -C $sourceRoot worktree add --detach $root $baseSha | Out-Null",
      "if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }",
      "Write-Output ('__DEVSPACE_WORKTREE__' + [char]9 + $root + [char]9 + $sourceRoot + [char]9 + $baseSha + [char]9 + $dirty)",
    ].join("; ");
    try {
      const result = await this.execute(
        "ssh",
        sshArguments(target.sshHost, `powershell -NoProfile -NonInteractive -Command ${shellQuote(command)}`),
        { timeout: 30_000, encoding: "utf8", maxBuffer: 256 * 1024 },
      );
      return parseCreatedWorktree(result.stdout);
    } catch (error) {
      const output = processOutput(error);
      throw new UniversalBrokerError(
        output.includes("__DEVSPACE_BAD_BASE__") ? "PRECONDITION_FAILED" : "TRANSPORT_INTERRUPTED",
        output.includes("__DEVSPACE_NOT_GIT__")
          ? `Remote context path is not inside a Git repository: ${sourcePath}`
          : output.includes("__DEVSPACE_BAD_BASE__")
            ? `Remote Git baseRef does not resolve to a commit: ${baseRef}`
            : `Unable to create remote managed worktree on target ${target.id}.`,
        { evidence: { targetId: target.id, baseRef, error: boundedError(error) } },
      );
    }
  }

  private async closeManagedWorktree(record: ContextRecord): Promise<Record<string, unknown>> {
    const target = await this.options.targets.resolve(record.targetId);
    if (!record.sourceRoot || !record.baseSha) {
      return { removed: false, retained: true, reason: "missing_worktree_lineage" };
    }
    const state = target.transport === "local"
      ? await localWorktreeState(record.root, record.baseSha)
      : await this.remoteWorktreeState(target, record.root, record.baseSha);
    if (state.missing) return { removed: false, retained: false, reason: "already_missing" };
    if (state.dirty || state.independentCommits > 0) {
      return {
        removed: false,
        retained: true,
        reason: state.dirty ? "dirty" : "independent_commits",
        dirty: state.dirty,
        independentCommits: state.independentCommits,
      };
    }
    await this.removeCreatedWorktree(target, {
      root: record.root,
      sourceRoot: record.sourceRoot,
      baseSha: record.baseSha,
      dirtySource: record.dirtySource === true,
    });
    return { removed: true, retained: false };
  }

  private async removeCreatedWorktree(
    target: TargetDefinition,
    worktree: CreatedWorktree,
  ): Promise<void> {
    if (target.transport === "local") {
      await execFileAsync("git", ["-C", worktree.sourceRoot, "worktree", "remove", "--force", worktree.root], {
        encoding: "utf8",
        maxBuffer: 10 * 1024 * 1024,
      }).catch(async () => rm(worktree.root, { recursive: true, force: true }));
      await execFileAsync("git", ["-C", worktree.sourceRoot, "worktree", "prune"], {
        encoding: "utf8",
        maxBuffer: 10 * 1024 * 1024,
      }).catch(() => undefined);
      return;
    }
    if (!target.sshHost) return;
    if (target.platform === "windows") {
      const command = [
        `$source='${worktree.sourceRoot.replaceAll("'", "''")}'`,
        `$root='${worktree.root.replaceAll("'", "''")}'`,
        "git -C $source worktree remove --force $root",
        "git -C $source worktree prune",
      ].join("; ");
      await this.execute("ssh", sshArguments(target.sshHost, `powershell -NoProfile -NonInteractive -Command ${shellQuote(command)}`), {
        timeout: 30_000,
        encoding: "utf8",
        maxBuffer: 256 * 1024,
      });
      return;
    }
    const script = [
      `source=${shellQuote(worktree.sourceRoot)}`,
      `root=${shellQuote(worktree.root)}`,
      "git -C \"$source\" worktree remove --force \"$root\"",
      "git -C \"$source\" worktree prune",
    ].join("; ");
    await this.execute("ssh", sshArguments(target.sshHost, `sh -lc ${shellQuote(script)}`), {
      timeout: 30_000,
      encoding: "utf8",
      maxBuffer: 256 * 1024,
    });
  }

  private async managedWorktreeBytes(targetId: string): Promise<number> {
    const records = [...this.contexts.values()].filter((record) => record.managed && record.targetId === targetId);
    let total = 0;
    for (const record of records) {
      const target = await this.options.targets.resolve(targetId);
      total += target.transport === "local"
        ? await localDirectoryBytes(record.root)
        : await this.remoteDirectoryBytes(target, record.root);
    }
    return total;
  }

  private async remoteDirectoryBytes(target: TargetDefinition, root: string): Promise<number> {
    if (!target.sshHost) return 0;
    try {
      if (target.platform === "windows") {
        const command = `$p='${root.replaceAll("'", "''")}'; if (Test-Path -LiteralPath $p) { (Get-ChildItem -LiteralPath $p -Force -Recurse -File -ErrorAction SilentlyContinue | Measure-Object -Property Length -Sum).Sum } else { 0 }`;
        const result = await this.execute("ssh", sshArguments(target.sshHost, `powershell -NoProfile -NonInteractive -Command ${shellQuote(command)}`), {
          timeout: 30_000,
          encoding: "utf8",
          maxBuffer: 64 * 1024,
        });
        return Math.max(0, Number(result.stdout.trim()) || 0);
      }
      const script = `if [ -d ${shellQuote(root)} ]; then du -sk ${shellQuote(root)} | awk '{print $1 * 1024}'; else printf '0\\n'; fi`;
      const result = await this.execute("ssh", sshArguments(target.sshHost, `sh -lc ${shellQuote(script)}`), {
        timeout: 30_000,
        encoding: "utf8",
        maxBuffer: 64 * 1024,
      });
      return Math.max(0, Number(result.stdout.trim()) || 0);
    } catch {
      return 0;
    }
  }

  private async remoteWorktreeState(
    target: TargetDefinition,
    root: string,
    baseSha: string,
  ): Promise<{ missing: boolean; dirty: boolean; independentCommits: number }> {
    if (!target.sshHost) return { missing: true, dirty: false, independentCommits: 0 };
    try {
      if (target.platform === "windows") {
        const command = [
          `$root='${root.replaceAll("'", "''")}'`,
          `$base='${baseSha.replaceAll("'", "''")}'`,
          "if (-not (Test-Path -LiteralPath $root -PathType Container)) { Write-Output '__MISSING__'; exit 0 }",
          "$dirty=if ((git -C $root status --porcelain=v1)) { 1 } else { 0 }",
          "$commits=[int](git -C $root rev-list --count ($base + '..HEAD'))",
          "Write-Output ($dirty.ToString() + [char]9 + $commits.ToString())",
        ].join("; ");
        const result = await this.execute("ssh", sshArguments(target.sshHost, `powershell -NoProfile -NonInteractive -Command ${shellQuote(command)}`), { timeout: 15_000, encoding: "utf8", maxBuffer: 64 * 1024 });
        return parseWorktreeState(result.stdout);
      }
      const script = [
        `root=${shellQuote(root)}`,
        `base=${shellQuote(baseSha)}`,
        "if [ ! -d \"$root\" ]; then printf '__MISSING__\\n'; exit 0; fi",
        "dirty=0; [ -n \"$(git -C \"$root\" status --porcelain=v1)\" ] && dirty=1",
        "commits=$(git -C \"$root\" rev-list --count \"$base..HEAD\")",
        "printf '%s\\t%s\\n' \"$dirty\" \"$commits\"",
      ].join("; ");
      const result = await this.execute("ssh", sshArguments(target.sshHost, `sh -lc ${shellQuote(script)}`), { timeout: 15_000, encoding: "utf8", maxBuffer: 64 * 1024 });
      return parseWorktreeState(result.stdout);
    } catch (error) {
      throw new UniversalBrokerError("TRANSPORT_INTERRUPTED", `Unable to inspect managed worktree on target ${target.id}.`, { evidence: { root, error: boundedError(error) } });
    }
  }

  private async remoteContextDiff(
    target: TargetDefinition,
    root: string,
  ): Promise<GeneratedContextDiff> {
    if (!target.sshHost) throw new UniversalBrokerError("TARGET_OFFLINE", `SSH target has no sshHost: ${target.id}`);
    try {
      if (target.platform === "windows") {
        const command = [
          `$root='${root.replaceAll("'", "''")}'`,
          "git -C $root rev-parse --is-inside-work-tree | Out-Null",
          "if ($LASTEXITCODE -ne 0) { Write-Output '__DEVSPACE_NOT_GIT__'; exit 44 }",
          "$status=(git -C $root status --short --untracked-files=all) -join \"`n\"",
          "$diff=(git -C $root diff --binary --no-ext-diff HEAD --) -join \"`n\"",
          "Write-Output '__DEVSPACE_STATUS__'",
          "Write-Output $status",
          "Write-Output '__DEVSPACE_DIFF__'",
          "Write-Output $diff",
        ].join("; ");
        const result = await this.execute("ssh", sshArguments(target.sshHost, `powershell -NoProfile -NonInteractive -Command ${shellQuote(command)}`), { timeout: 30_000, encoding: "utf8", maxBuffer: MAXIMUM_DIFF_CHARACTERS });
        return parseRemoteDiff(result.stdout);
      }
      const script = [
        `root=${shellQuote(root)}`,
        "git -C \"$root\" rev-parse --is-inside-work-tree >/dev/null 2>&1 || { printf '__DEVSPACE_NOT_GIT__\\n'; exit 44; }",
        "printf '__DEVSPACE_STATUS__\\n'",
        "git -C \"$root\" status --short --untracked-files=all",
        "printf '__DEVSPACE_DIFF__\\n'",
        "git -C \"$root\" diff --binary --no-ext-diff HEAD --",
      ].join("; ");
      const result = await this.execute("ssh", sshArguments(target.sshHost, `sh -lc ${shellQuote(script)}`), { timeout: 30_000, encoding: "utf8", maxBuffer: MAXIMUM_DIFF_CHARACTERS });
      return parseRemoteDiff(result.stdout);
    } catch (error) {
      if (processOutput(error).includes("__DEVSPACE_NOT_GIT__")) {
        throw new UniversalBrokerError("PRECONDITION_FAILED", `Context is not inside a Git worktree: ${root}`);
      }
      throw new UniversalBrokerError("TRANSPORT_INTERRUPTED", `Unable to compute context diff on target ${target.id}.`, { evidence: { root, error: boundedError(error) } });
    }
  }

  private async resolveExistingDirectory(
    target: TargetDefinition,
    inputPath: string,
  ): Promise<string> {
    if (target.transport === "local") return resolveLocalDirectory(inputPath);
    if (target.platform === "windows") return this.resolveWindowsRemoteDirectory(target, inputPath);
    return this.resolvePosixRemoteDirectory(target, inputPath);
  }

  private async resolvePosixRemoteDirectory(
    target: TargetDefinition,
    inputPath: string,
  ): Promise<string> {
    if (!target.sshHost) {
      throw new UniversalBrokerError("TARGET_OFFLINE", `SSH target has no sshHost: ${target.id}`);
    }
    if (!inputPath.startsWith("/") && !inputPath.startsWith("~/") && inputPath !== "~") {
      throw new UniversalBrokerError(
        "PRECONDITION_FAILED",
        "Remote POSIX context path must be absolute or use a leading tilde.",
        { evidence: { targetId: target.id, path: inputPath } },
      );
    }
    const script = [
      `requested=${shellQuote(inputPath)}`,
      "case \"$requested\" in '~') requested=$HOME ;; '~/'*) requested=$HOME/${requested#\~/} ;; esac",
      "if [ ! -e \"$requested\" ]; then printf '__DEVSPACE_PATH_NOT_FOUND__\\n'; exit 44; fi",
      "if [ ! -d \"$requested\" ]; then printf '__DEVSPACE_PATH_NOT_DIRECTORY__\\n'; exit 45; fi",
      "cd -- \"$requested\" && pwd -P",
    ].join("; ");
    try {
      const result = await this.execute(
        "ssh",
        sshArguments(target.sshHost, `sh -lc ${shellQuote(script)}`),
        { timeout: 8_000, encoding: "utf8", maxBuffer: 64 * 1024 },
      );
      const resolved = result.stdout.trim().split(/\r?\n/).at(-1);
      if (!resolved?.startsWith("/")) throw new Error("Remote canonical path missing");
      return resolved;
    } catch (error) {
      const output = processOutput(error);
      if (output.includes("__DEVSPACE_PATH_NOT_FOUND__")) {
        throw new UniversalBrokerError(
          "PATH_NOT_FOUND",
          `Remote context path does not exist: ${inputPath}`,
          { evidence: { targetId: target.id, path: inputPath } },
        );
      }
      if (output.includes("__DEVSPACE_PATH_NOT_DIRECTORY__")) {
        throw new UniversalBrokerError(
          "PATH_TYPE_MISMATCH",
          `Remote context path is not a directory: ${inputPath}`,
          { evidence: { targetId: target.id, path: inputPath } },
        );
      }
      throw new UniversalBrokerError(
        "TARGET_OFFLINE",
        `Unable to resolve context path on target ${target.id}.`,
        { retryable: true, evidence: { error: boundedError(error), path: inputPath } },
      );
    }
  }

  private async resolveWindowsRemoteDirectory(
    target: TargetDefinition,
    inputPath: string,
  ): Promise<string> {
    if (!target.sshHost) {
      throw new UniversalBrokerError("TARGET_OFFLINE", `SSH target has no sshHost: ${target.id}`);
    }
    const escaped = inputPath.replaceAll("'", "''");
    const command = [
      "$p='" + escaped + "'",
      "if (-not (Test-Path -LiteralPath $p)) { Write-Output '__DEVSPACE_PATH_NOT_FOUND__'; exit 44 }",
      "if (-not (Test-Path -LiteralPath $p -PathType Container)) { Write-Output '__DEVSPACE_PATH_NOT_DIRECTORY__'; exit 45 }",
      "(Resolve-Path -LiteralPath $p).Path",
    ].join("; ");
    try {
      const result = await this.execute(
        "ssh",
        sshArguments(
          target.sshHost,
          `powershell -NoProfile -NonInteractive -Command ${shellQuote(command)}`,
        ),
        { timeout: 8_000, encoding: "utf8", maxBuffer: 64 * 1024 },
      );
      const resolved = result.stdout.trim().split(/\r?\n/).at(-1);
      if (!resolved) throw new Error("Remote canonical path missing");
      return resolved;
    } catch (error) {
      const output = processOutput(error);
      if (output.includes("__DEVSPACE_PATH_NOT_FOUND__")) {
        throw new UniversalBrokerError(
          "PATH_NOT_FOUND",
          `Remote context path does not exist: ${inputPath}`,
          { evidence: { targetId: target.id, path: inputPath } },
        );
      }
      if (output.includes("__DEVSPACE_PATH_NOT_DIRECTORY__")) {
        throw new UniversalBrokerError(
          "PATH_TYPE_MISMATCH",
          `Remote context path is not a directory: ${inputPath}`,
          { evidence: { targetId: target.id, path: inputPath } },
        );
      }
      throw new UniversalBrokerError(
        "TARGET_OFFLINE",
        `Unable to resolve context path on target ${target.id}.`,
        { retryable: true, evidence: { error: boundedError(error), path: inputPath } },
      );
    }
  }

  private async discoverInitialInstructions(
    target: TargetDefinition,
    root: string,
  ): Promise<InstructionReference[]> {
    if (target.transport !== "local") {
      return this.discoverRemoteRootInstructions(target, root);
    }
    const references: InstructionReference[] = [];
    for (const directory of ancestorDirectories(root)) {
      for (const name of CONTEXT_FILE_NAMES) {
        const path = join(directory, name);
        const reference = await localInstructionReference(
          path,
          directory === root ? "root" : "ancestor",
          true,
        );
        if (reference) references.push(reference);
      }
    }
    return deduplicateInstructions(references)
      .sort((left, right) => left.path.localeCompare(right.path));
  }

  private async discoverRemoteRootInstructions(
    target: TargetDefinition,
    root: string,
  ): Promise<InstructionReference[]> {
    if (!target.sshHost) return [];
    if (target.platform === "windows") {
      return this.discoverWindowsRootInstructions(target, root);
    }
    const script = CONTEXT_FILE_NAMES.map((name) => {
      const path = `${root.replace(/\/$/, "")}/${name}`;
      return [
        `p=${shellQuote(path)}`,
        "if [ -f \"$p\" ]; then size=$(wc -c < \"$p\" | tr -d ' '); if command -v sha256sum >/dev/null 2>&1; then hash=$(sha256sum \"$p\" | awk '{print $1}'); else hash=$(shasum -a 256 \"$p\" | awk '{print $1}'); fi; printf '%s\\t%s\\t%s\\n' \"$p\" \"$size\" \"$hash\"; fi",
      ].join("; ");
    }).join("; ");
    try {
      const result = await this.execute(
        "ssh",
        sshArguments(target.sshHost, `sh -lc ${shellQuote(script)}`),
        { timeout: 8_000, encoding: "utf8", maxBuffer: 64 * 1024 },
      );
      return result.stdout.split(/\r?\n/).flatMap((line) => {
        const [path, size, sha256] = line.split("\t");
        if (!path || !size || !sha256 || !/^\d+$/.test(size)) return [];
        return [{
          path,
          size: Number(size),
          sha256,
          required: true,
          scope: "root" as const,
        }];
      });
    } catch {
      return [];
    }
  }

  private async discoverWindowsRootInstructions(
    target: TargetDefinition,
    root: string,
  ): Promise<InstructionReference[]> {
    if (!target.sshHost) return [];
    const escapedRoot = root.replaceAll("'", "''");
    const script = [
      `$root='${escapedRoot}'`,
      "$names=@('AGENTS.md','CLAUDE.md')",
      "foreach($name in $names){$p=Join-Path $root $name;if(Test-Path -LiteralPath $p -PathType Leaf){$i=Get-Item -LiteralPath $p;$h=(Get-FileHash -LiteralPath $p -Algorithm SHA256).Hash.ToLowerInvariant();[Console]::Out.WriteLine($i.FullName+'`t'+$i.Length+'`t'+$h)}}",
    ].join("; ");
    try {
      const result = await this.execute(
        "ssh",
        sshArguments(target.sshHost, windowsEncodedCommand(script)),
        { timeout: 8_000, encoding: "utf8", maxBuffer: 64 * 1024 },
      );
      return result.stdout.split(/\r?\n/).flatMap((line) => {
        const [path, size, sha256] = line.split("\t");
        if (!path || !size || !sha256 || !/^\d+$/.test(size)) return [];
        return [{
          path,
          size: Number(size),
          sha256,
          required: true,
          scope: "root" as const,
        }];
      });
    } catch {
      return [];
    }
  }

  private suggestSkills(root: string, task: string, limit: number): SkillReference[] {
    const skills = this.skillCatalog(root);
    return skills
      .filter((skill) => !skill.disableModelInvocation)
      .map((skill) => ({
        name: skill.name,
        description: compactDescription(skill.description),
        path: formatPathForPrompt(skill.filePath),
        score: skillScore(skill.name, skill.description, task),
      }))
      .filter((skill) => skill.score > 0)
      .sort((left, right) => right.score - left.score || left.name.localeCompare(right.name))
      .slice(0, Math.min(Math.max(limit, 1), MAX_SUGGESTED_SKILLS));
  }

  private skillCatalog(root: string) {
    const cached = this.skillCatalogCache.get(root);
    if (cached && this.now() - cached.loadedAt < SKILL_CATALOG_TTL_MS) {
      return cached.skills;
    }
    const skills = loadWorkspaceSkills(this.options.serverConfig, root).skills;
    this.skillCatalogCache.set(root, { loadedAt: this.now(), skills });
    return skills;
  }

  private async searchNestedInstructions(
    root: string,
    query: string,
  ): Promise<InstructionReference[]> {
    const results: InstructionReference[] = [];
    let visited = 0;
    const walk = async (directory: string, depth: number): Promise<void> => {
      if (depth > MAX_NESTED_SEARCH_DEPTH || visited >= MAX_NESTED_SEARCH_ENTRIES) return;
      let entries;
      try {
        entries = await readdir(directory, { withFileTypes: true });
      } catch {
        return;
      }
      for (const entry of entries) {
        if (visited++ >= MAX_NESTED_SEARCH_ENTRIES) return;
        const path = join(directory, entry.name);
        if (entry.isDirectory()) {
          if (SKIPPED_CONTEXT_DIRS.has(entry.name)) continue;
          await walk(path, depth + 1);
          continue;
        }
        if (!entry.isFile() || !CONTEXT_FILE_NAMES.includes(entry.name as never)) continue;
        const relativePath = relative(root, path);
        if (!fuzzyTextMatch(relativePath, query) && !fuzzyTextMatch(entry.name, query)) continue;
        const reference = await localInstructionReference(path, "nested", false);
        if (reference) results.push(reference);
        if (results.length >= MAX_SEARCH_RESULTS) return;
      }
    };
    await walk(root, 0);
    return results.sort((left, right) => left.path.localeCompare(right.path));
  }

  private owner(explicit?: CapabilityCallContext): CapabilityCallContext {
    return requireCapabilityCallContext(explicit, this.ownerProvider);
  }

  private requireOwnedContext(
    contextId: string,
    owner: CapabilityCallContext,
  ): ContextRecord {
    const record = this.contexts.get(contextId);
    if (!record) {
      const tombstone = this.tombstones.get(contextId);
      if (tombstone) {
        this.assertContextOwner(tombstone.principalKeyFingerprint, owner, contextId);
        throw new UniversalBrokerError(
          "PRECONDITION_FAILED",
          `Context expired: ${contextId}`,
          {
            evidence: {
              reasonCode: "RESOURCE_EXPIRED",
              contextId,
              expiredAt: tombstone.expiredAt,
            },
          },
        );
      }
      throw new UniversalBrokerError(
        "PATH_NOT_FOUND",
        `Unknown context: ${contextId}`,
        { evidence: { contextId } },
      );
    }
    this.assertContextOwner(record.principalKeyFingerprint, owner, contextId);
    return record;
  }

  private async requireFreshContext(
    contextId: string,
    owner: CapabilityCallContext,
  ): Promise<ContextRecord> {
    const record = this.requireOwnedContext(contextId, owner);
    const current = await this.options.targets.resolveWithGeneration(record.targetId);
    if (current.generation !== record.targetGeneration) {
      throw new UniversalBrokerError(
        "AUTHORITY_STALE",
        `Context target binding is stale: ${contextId}`,
        {
          evidence: {
            reasonCode: "CONTEXT_TARGET_GENERATION_STALE",
            contextId,
            targetId: record.targetId,
            expectedTargetGeneration: record.targetGeneration,
            observedTargetGeneration: current.generation,
          },
        },
      );
    }
    return record;
  }

  private assertContextOwner(
    expected: string,
    owner: CapabilityCallContext,
    contextId: string,
  ): void {
    if (expected === owner.principalKeyFingerprint) return;
    throw new UniversalBrokerError(
      "AUTHORITY_PRINCIPAL_MISMATCH",
      `Context belongs to a different stable principal: ${contextId}`,
      { evidence: { reasonCode: "CONTEXT_OWNER_MISMATCH", contextId } },
    );
  }

  private reserveContext() {
    return this.reservations.reserve(
      { entries: this.contexts.size },
      { entries: 1 },
    );
  }

  private refreshExpiry(record: ContextRecord): void {
    const now = this.now();
    record.lastUsedAt = new Date(now).toISOString();
    record.expiresAt = new Date(now + this.idleTtlMs).toISOString();
  }

  private expireContext(record: ContextRecord, now: number): void {
    this.contexts.delete(record.contextId);
    this.contextIdByKey.delete(contextKey(
      record.principalKeyFingerprint,
      record.targetId,
      record.targetGeneration,
      record.root,
      record.mode,
    ));
    this.tombstones.set(record.contextId, {
      contextId: record.contextId,
      principalKeyFingerprint: record.principalKeyFingerprint,
      targetId: record.targetId,
      targetGeneration: record.targetGeneration,
      expiredAt: record.expiresAt,
      tombstonedAt: new Date(now).toISOString(),
      removeAfter: new Date(now + this.tombstoneTtlMs).toISOString(),
    });
    const maximumTombstones = Math.max(128, this.maximumContexts * 4);
    if (this.tombstones.size > maximumTombstones) {
      const oldest = [...this.tombstones.values()]
        .sort((left, right) => left.tombstonedAt.localeCompare(right.tombstonedAt)
          || left.contextId.localeCompare(right.contextId))[0];
      if (oldest) this.tombstones.delete(oldest.contextId);
    }
  }

  private async touch(record: ContextRecord): Promise<void> {
    this.refreshExpiry(record);
    await this.persist();
  }

  private async ensureLoaded(): Promise<void> {
    if (this.loaded) return;
    this.loadPromise ??= this.loadFromStore();
    await this.loadPromise;
  }

  private async loadFromStore(): Promise<void> {
    let parsed: ContextStoreFile = { version: STORE_VERSION, contexts: [], tombstones: [] };
    try {
      parsed = parseContextStore(await readFile(this.options.storePath, "utf8"));
    } catch (error) {
      if (!isNodeError(error, "ENOENT")) {
        throw new UniversalBrokerError(
          "PRECONDITION_FAILED",
          `Unable to load context store: ${this.options.storePath}`,
          { evidence: { error: boundedError(error) } },
        );
      }
    }
    if (parsed.contexts.length > this.maximumContexts) {
      throw new UniversalBrokerError(
        "PRECONDITION_FAILED",
        "Context store exceeds the configured active context quota.",
        { evidence: { contexts: parsed.contexts.length, maximumContexts: this.maximumContexts } },
      );
    }
    const keys = new Set<string>();
    for (const record of parsed.contexts) {
      validateContextRecord(record);
      const key = contextKey(
        record.principalKeyFingerprint,
        record.targetId,
        record.targetGeneration,
        record.root,
        record.mode,
      );
      if (this.contexts.has(record.contextId) || keys.has(key)) {
        throw new UniversalBrokerError(
          "PRECONDITION_FAILED",
          `Context store contains duplicate context identity: ${record.contextId}`,
          { evidence: { contextId: record.contextId, targetId: record.targetId, root: record.root } },
        );
      }
      keys.add(key);
      this.contexts.set(record.contextId, record);
      this.contextIdByKey.set(key, record.contextId);
    }
    for (const tombstone of parsed.tombstones) {
      validateContextTombstone(tombstone);
      if (this.contexts.has(tombstone.contextId) || this.tombstones.has(tombstone.contextId)) {
        throw new UniversalBrokerError(
          "PRECONDITION_FAILED",
          `Context store contains duplicate tombstone identity: ${tombstone.contextId}`,
        );
      }
      this.tombstones.set(tombstone.contextId, tombstone);
    }
    this.loaded = true;
  }

  private persist(): Promise<void> {
    const operation = this.mutationQueue.then(async () => {
      await mkdir(dirname(this.options.storePath), { recursive: true });
      const temporary = `${this.options.storePath}.tmp-${process.pid}-${randomUUID()}`;
      const payload: ContextStoreFile = {
        version: STORE_VERSION,
        contexts: [...this.contexts.values()]
          .sort((left, right) => left.contextId.localeCompare(right.contextId)),
        tombstones: [...this.tombstones.values()]
          .sort((left, right) => left.contextId.localeCompare(right.contextId)),
      };
      await writeFile(temporary, `${JSON.stringify(payload, null, 2)}\n`, { mode: 0o600 });
      await rename(temporary, this.options.storePath);
    });
    this.mutationQueue = operation.catch(() => undefined);
    return operation;
  }
}

interface CreatedWorktree {
  root: string;
  sourceRoot: string;
  baseSha: string;
  dirtySource: boolean;
}

interface GeneratedContextDiff {
  text: string;
  summary: {
    files: number;
    additions: number;
    deletions: number;
    statusLines: number;
  };
}

export interface ContextOpenResult extends Record<string, unknown> {
  contextId: string;
  targetId: string;
  targetGeneration: string;
  /** Present on a newly opened context; omitted from the compact reuse envelope. */
  root?: string;
  /** Present on a newly opened context; omitted from the compact reuse envelope. */
  mode?: ContextMode;
  reused: boolean;
  changed?: boolean;
  instructionSetHash: string;
  instructions?: InstructionReference[];
  suggestedSkills?: SkillReference[];
  git?: ContextGitSummary;
  managed?: boolean;
  sourceRoot?: string;
  baseRef?: string;
  baseSha?: string;
  dirtySource?: boolean;
  truncated?: boolean;
  omitted?: {
    instructions: number;
    skills: number;
    git: boolean;
  };
}

async function localGitRoot(path: string): Promise<string> {
  try {
    return resolve((await execFileAsync("git", ["-C", path, "rev-parse", "--show-toplevel"], {
      encoding: "utf8",
      maxBuffer: 10 * 1024 * 1024,
    })).stdout.trim());
  } catch (error) {
    throw new UniversalBrokerError(
      "PRECONDITION_FAILED",
      `Context path is not inside a Git repository: ${path}`,
      { evidence: { error: boundedError(error) } },
    );
  }
}

async function localGitText(
  root: string,
  args: string[],
  failureMessage: string,
): Promise<string> {
  try {
    return (await execFileAsync("git", ["-C", root, ...args], {
      encoding: "utf8",
      maxBuffer: MAXIMUM_DIFF_CHARACTERS,
    })).stdout.trim();
  } catch (error) {
    throw new UniversalBrokerError(
      "PRECONDITION_FAILED",
      failureMessage,
      { evidence: { root, args, error: boundedError(error) } },
    );
  }
}

async function localDirectoryBytes(root: string): Promise<number> {
  try {
    const result = await execFileAsync("du", ["-sk", root], {
      encoding: "utf8",
      maxBuffer: 64 * 1024,
    });
    return Math.max(0, (Number(result.stdout.trim().split(/\s+/, 1)[0]) || 0) * 1024);
  } catch {
    return 0;
  }
}

async function localWorktreeState(
  root: string,
  baseSha: string,
): Promise<{ missing: boolean; dirty: boolean; independentCommits: number }> {
  try {
    const metadata = await stat(root);
    if (!metadata.isDirectory()) return { missing: true, dirty: false, independentCommits: 0 };
  } catch (error) {
    if (isNodeError(error, "ENOENT")) return { missing: true, dirty: false, independentCommits: 0 };
    throw error;
  }
  const [status, count] = await Promise.all([
    localGitText(root, ["status", "--porcelain=v1"], "Unable to inspect managed worktree status."),
    localGitText(root, ["rev-list", "--count", `${baseSha}..HEAD`], "Unable to inspect managed worktree lineage."),
  ]);
  return {
    missing: false,
    dirty: status.length > 0,
    independentCommits: Math.max(0, Number(count) || 0),
  };
}

async function localContextDiff(root: string): Promise<GeneratedContextDiff> {
  await localGitRoot(root);
  const [status, trackedDiff, numstat, untrackedRaw] = await Promise.all([
    localGitText(root, ["status", "--short", "--untracked-files=all"], "Unable to inspect context status."),
    localGitText(root, ["diff", "--binary", "--no-ext-diff", "HEAD", "--"], "Unable to compute context diff."),
    localGitText(root, ["diff", "--numstat", "HEAD", "--"], "Unable to compute context statistics."),
    localGitText(root, ["ls-files", "--others", "--exclude-standard"], "Unable to list untracked files."),
  ]);
  const untracked = untrackedRaw ? untrackedRaw.split(/\r?\n/).filter(Boolean) : [];
  const additions: string[] = [];
  for (const relativePath of untracked) {
    const absolute = resolve(root, relativePath);
    let metadata;
    try {
      metadata = await stat(absolute);
    } catch {
      continue;
    }
    if (!metadata.isFile() || metadata.size > 5 * 1024 * 1024) continue;
    const result = await execFileAsync("git", ["diff", "--no-index", "--binary", "--", "/dev/null", absolute], {
      encoding: "utf8",
      maxBuffer: MAXIMUM_DIFF_CHARACTERS,
    }).catch((error: Error & { stdout?: string; code?: number }) => {
      if (error.code === 1 && typeof error.stdout === "string") return { stdout: error.stdout };
      throw error;
    });
    additions.push(result.stdout.replaceAll(absolute, relativePath));
  }
  const summary = diffSummary(status, numstat, untracked);
  const text = [
    status ? `# status\n${status}\n` : "# status\nclean\n",
    trackedDiff,
    ...additions,
  ].filter(Boolean).join("\n");
  return { text, summary };
}

function parseCreatedWorktree(output: string): CreatedWorktree {
  const line = output.split(/\r?\n/).find((entry) => entry.startsWith("__DEVSPACE_WORKTREE__\t"));
  if (!line) {
    throw new UniversalBrokerError("TRANSPORT_INTERRUPTED", "Remote worktree result marker is missing.");
  }
  const [, root, sourceRoot, baseSha, dirty] = line.split("\t");
  if (!root || !sourceRoot || !/^[0-9a-f]{40,64}$/i.test(baseSha ?? "")) {
    throw new UniversalBrokerError("TRANSPORT_INTERRUPTED", "Remote worktree result is malformed.");
  }
  return { root, sourceRoot, baseSha: baseSha!, dirtySource: dirty === "1" };
}

function parseWorktreeState(output: string): {
  missing: boolean;
  dirty: boolean;
  independentCommits: number;
} {
  if (output.includes("__MISSING__")) return { missing: true, dirty: false, independentCommits: 0 };
  const line = output.trim().split(/\r?\n/).at(-1) ?? "";
  const [dirty, commits] = line.split("\t");
  if (!/^[01]$/.test(dirty ?? "") || !/^\d+$/.test(commits ?? "")) {
    throw new UniversalBrokerError("TRANSPORT_INTERRUPTED", "Remote worktree state is malformed.");
  }
  return { missing: false, dirty: dirty === "1", independentCommits: Number(commits) };
}

function parseRemoteDiff(output: string): GeneratedContextDiff {
  const statusMarker = output.indexOf("__DEVSPACE_STATUS__");
  const diffMarker = output.indexOf("__DEVSPACE_DIFF__");
  if (statusMarker < 0 || diffMarker < 0 || diffMarker < statusMarker) {
    throw new UniversalBrokerError("TRANSPORT_INTERRUPTED", "Remote diff framing is missing.");
  }
  const status = output.slice(statusMarker + "__DEVSPACE_STATUS__".length, diffMarker).trim();
  const diff = output.slice(diffMarker + "__DEVSPACE_DIFF__".length).trim();
  const statusLines = status ? status.split(/\r?\n/).filter(Boolean) : [];
  const summary = diffSummary(status, "", []);
  return {
    text: [status ? `# status\n${status}\n` : "# status\nclean\n", diff].filter(Boolean).join("\n"),
    summary: { ...summary, statusLines: statusLines.length },
  };
}

function diffSummary(status: string, numstat: string, untracked: string[]): GeneratedContextDiff["summary"] {
  let additions = 0;
  let deletions = 0;
  const files = new Set<string>();
  for (const line of numstat.split(/\r?\n/)) {
    if (!line) continue;
    const [added, deleted, path] = line.split("\t");
    if (path) files.add(path);
    if (/^\d+$/.test(added ?? "")) additions += Number(added);
    if (/^\d+$/.test(deleted ?? "")) deletions += Number(deleted);
  }
  for (const path of untracked) files.add(path);
  const statusLines = status ? status.split(/\r?\n/).filter(Boolean) : [];
  for (const line of statusLines) {
    const path = line.replace(/^\S{1,2}\s+/, "").trim();
    if (path) files.add(path);
  }
  return { files: files.size, additions, deletions, statusLines: statusLines.length };
}

function sanitizePathSegment(value: string): string {
  return value.replace(/[^A-Za-z0-9._-]+/g, "-").replace(/^-+|-+$/g, "").slice(0, 80) || "repo";
}

function headTail(value: string, maximum: number): string {
  if (value.length <= maximum) return value;
  const head = Math.floor(maximum * 0.7);
  const tail = maximum - head;
  return `${value.slice(0, head)}\n... ${value.length - maximum} characters omitted ...\n${value.slice(-tail)}`;
}

async function resolveLocalDirectory(inputPath: string): Promise<string> {
  const expanded = expandHomePath(inputPath);
  if (!isAbsolute(expanded)) {
    throw new UniversalBrokerError(
      "PRECONDITION_FAILED",
      "Local context path must be absolute or use a leading tilde.",
      { evidence: { path: inputPath } },
    );
  }
  let metadata;
  try {
    metadata = await stat(expanded);
  } catch (error) {
    if (isNodeError(error, "ENOENT")) {
      throw new UniversalBrokerError(
        "PATH_NOT_FOUND",
        `Context path does not exist: ${inputPath}`,
        { evidence: { path: inputPath } },
      );
    }
    throw new UniversalBrokerError(
      "PERMISSION_DENIED",
      `Unable to inspect context path: ${inputPath}`,
      { evidence: { error: boundedError(error), path: inputPath } },
    );
  }
  if (!metadata.isDirectory()) {
    throw new UniversalBrokerError(
      "PATH_TYPE_MISMATCH",
      `Context path is not a directory: ${inputPath}`,
      { evidence: { path: inputPath } },
    );
  }
  return resolve(await realpath(expanded));
}

function ancestorDirectories(root: string): string[] {
  const home = resolve(homedir());
  const resolvedRoot = resolve(root);
  const boundary = isPathInsideRoot(resolvedRoot, home) ? home : parse(resolvedRoot).root;
  const directories: string[] = [];
  let current = resolvedRoot;
  while (true) {
    directories.push(current);
    if (current === boundary) break;
    const parent = dirname(current);
    if (parent === current) break;
    current = parent;
  }
  return directories.reverse();
}

async function localInstructionReference(
  path: string,
  scope: InstructionReference["scope"],
  required: boolean,
): Promise<InstructionReference | undefined> {
  try {
    const metadata = await stat(path);
    if (!metadata.isFile()) return undefined;
    const content = await readFile(path);
    return {
      path: formatPathForPrompt(path),
      size: content.byteLength,
      sha256: createHash("sha256").update(content).digest("hex"),
      required,
      scope,
    };
  } catch (error) {
    if (isNodeError(error, "ENOENT") || isNodeError(error, "EACCES")) return undefined;
    throw error;
  }
}

async function gitSummary(root: string): Promise<ContextGitSummary | undefined> {
  try {
    const eligibility = await getGitEligibility(root);
    if (!eligibility.ok || !eligibility.gitRoot) return undefined;
    const [head, branch, status] = await Promise.all([
      git(eligibility.gitRoot, ["rev-parse", "HEAD"]),
      git(eligibility.gitRoot, ["branch", "--show-current"]),
      git(eligibility.gitRoot, ["status", "--porcelain", "--untracked-files=normal"]),
    ]);
    return {
      repositoryRoot: eligibility.gitRoot,
      head: head.stdout.trim(),
      branch: branch.stdout.trim() || undefined,
      dirty: status.stdout.trim().length > 0,
    };
  } catch {
    return undefined;
  }
}

function skillScore(name: string, description: string, task: string): number {
  const normalizedTask = normalizeText(task);
  const normalizedName = normalizeText(name.replaceAll("-", " "));
  const taskTokens = tokens(normalizedTask);
  const nameTokens = tokens(normalizedName);
  const descriptionTokens = tokens(normalizeText(description));
  let score = normalizedTask.includes(normalizedName) || normalizedName.includes(normalizedTask) ? 20 : 0;
  for (const token of taskTokens) {
    if (token.length < 2) continue;
    if (nameTokens.has(token)) score += 6;
    else if (descriptionTokens.has(token)) score += 3;
    else if (normalizedName.includes(token)) score += 2;
    else if (normalizeText(description).includes(token)) score += 1;
  }
  return score;
}

function tokens(value: string): Set<string> {
  return new Set(value.split(/[^\p{L}\p{N}]+/u).filter(Boolean));
}

function normalizeText(value: string): string {
  return value.normalize("NFKC").toLocaleLowerCase("en-US");
}

function compactDescription(value: string): string {
  const normalized = value.replace(/\s+/g, " ").trim();
  return normalized.length <= 180 ? normalized : `${normalized.slice(0, 177)}...`;
}

function fuzzyTextMatch(value: string, query: string): boolean {
  const normalized = normalizeText(value);
  return [...tokens(normalizeText(query))].every((token) => normalized.includes(token));
}

function hashInstructionSet(instructions: InstructionReference[]): string {
  return createHash("sha256")
    .update(JSON.stringify(instructions.map(({ path, sha256 }) => ({ path, sha256 }))))
    .digest("hex");
}

function deduplicateInstructions(
  instructions: InstructionReference[],
): InstructionReference[] {
  const seen = new Set<string>();
  return instructions.filter((instruction) => {
    if (seen.has(instruction.path)) return false;
    seen.add(instruction.path);
    return true;
  });
}

function contextKey(
  principalKeyFingerprint: string,
  targetId: string,
  targetGeneration: string,
  root: string,
  mode: ContextMode,
): string {
  return `${principalKeyFingerprint}\0${targetId}\0${targetGeneration}\0${root}\0${mode}`;
}

function assertPayloadBudget(
  value: unknown,
  maximum: number,
  label: string,
): void {
  const characters = JSON.stringify(value).length;
  if (characters <= maximum) return;
  throw new UniversalBrokerError(
    "RESOURCE_QUOTA_EXCEEDED",
    `${label} payload uses ${characters} characters; limit is ${maximum}.`,
    { evidence: { characters, maximum, label } },
  );
}

function fitInitialContextPayload(input: ContextOpenResult): ContextOpenResult {
  const result: ContextOpenResult = structuredClone(input);
  const originalInstructions = result.instructions?.length ?? 0;
  const originalSkills = result.suggestedSkills?.length ?? 0;
  const originalGit = Boolean(result.git);

  while (
    contextPayloadCharacters(result)
    > UNIVERSAL_BROKER_BUDGETS.maximumInitialContextCharacters
  ) {
    if ((result.suggestedSkills?.length ?? 0) > 0) {
      result.suggestedSkills!.pop();
      continue;
    }
    if ((result.instructions?.length ?? 0) > 0) {
      result.instructions!.pop();
      continue;
    }
    if (result.git) {
      delete result.git;
      continue;
    }
    throw new UniversalBrokerError(
      "RESOURCE_QUOTA_EXCEEDED",
      "Context identity fields exceed the initial context payload budget.",
      {
        evidence: {
          characters: contextPayloadCharacters(result),
          maximum: UNIVERSAL_BROKER_BUDGETS.maximumInitialContextCharacters,
        },
      },
    );
  }

  const omitted = {
    instructions: originalInstructions - (result.instructions?.length ?? 0),
    skills: originalSkills - (result.suggestedSkills?.length ?? 0),
    git: originalGit && !result.git,
  };
  if (omitted.instructions > 0 || omitted.skills > 0 || omitted.git) {
    result.truncated = true;
    result.omitted = omitted;
    while (
      contextPayloadCharacters(result)
      > UNIVERSAL_BROKER_BUDGETS.maximumInitialContextCharacters
    ) {
      if ((result.suggestedSkills?.length ?? 0) > 0) {
        result.suggestedSkills!.pop();
        result.omitted.skills += 1;
      } else if ((result.instructions?.length ?? 0) > 0) {
        result.instructions!.pop();
        result.omitted.instructions += 1;
      } else {
        throw new UniversalBrokerError(
          "RESOURCE_QUOTA_EXCEEDED",
          "Context truncation metadata exceeds the initial context payload budget.",
        );
      }
    }
  }
  return result;
}

function parseCursor(cursor: string | undefined): number {
  if (cursor === undefined) return 0;
  const parsed = Number(cursor);
  if (!Number.isInteger(parsed) || parsed < 0) {
    throw new UniversalBrokerError("PRECONDITION_FAILED", `Invalid context cursor: ${cursor}`);
  }
  return parsed;
}

function boundedContextInteger(
  value: number | undefined,
  fallback: number,
  minimum: number,
  maximum: number,
  field: string,
): number {
  const parsed = value ?? fallback;
  if (!Number.isSafeInteger(parsed) || parsed < minimum || parsed > maximum) {
    throw new UniversalBrokerError(
      "PRECONDITION_FAILED",
      `${field} must be an integer from ${minimum} through ${maximum}.`,
    );
  }
  return parsed;
}

function parseContextStore(content: string): ContextStoreFile {
  const parsed = JSON.parse(content) as Partial<ContextStoreFile>;
  if (
    parsed.version !== STORE_VERSION
    || !Array.isArray(parsed.contexts)
    || !Array.isArray(parsed.tombstones)
  ) {
    throw new Error("unsupported context store format");
  }
  return {
    version: STORE_VERSION,
    contexts: parsed.contexts,
    tombstones: parsed.tombstones,
  };
}

function validateContextRecord(record: ContextRecord): void {
  const valid = Boolean(
    record
    && typeof record.contextId === "string"
    && record.contextId.startsWith("ctx_")
    && /^[a-f0-9]{64}$/.test(record.principalKeyFingerprint)
    && typeof record.targetId === "string"
    && record.targetId.length > 0
    && /^[a-f0-9]{64}$/.test(record.targetGeneration)
    && typeof record.root === "string"
    && record.root.length > 0
    && (record.mode === "existing" || record.mode === "worktree")
    && typeof record.instructionSetHash === "string"
    && Array.isArray(record.instructions)
    && Number.isFinite(Date.parse(record.createdAt))
    && Number.isFinite(Date.parse(record.lastUsedAt))
    && Number.isFinite(Date.parse(record.expiresAt))
  );
  if (!valid) {
    throw new UniversalBrokerError(
      "PRECONDITION_FAILED",
      "Context store contains an invalid record.",
      {
        evidence: {
          contextId: typeof record?.contextId === "string" ? record.contextId : undefined,
        },
      },
    );
  }
  for (const instruction of record.instructions) {
    if (
      !instruction
      || typeof instruction.path !== "string"
      || typeof instruction.size !== "number"
      || typeof instruction.sha256 !== "string"
      || typeof instruction.required !== "boolean"
      || !["ancestor", "root", "nested"].includes(instruction.scope)
    ) {
      throw new UniversalBrokerError(
        "PRECONDITION_FAILED",
        `Context store contains an invalid instruction reference: ${record.contextId}`,
      );
    }
  }
}

function validateContextTombstone(tombstone: ContextTombstone): void {
  const valid = Boolean(
    tombstone
    && typeof tombstone.contextId === "string"
    && tombstone.contextId.startsWith("ctx_")
    && /^[a-f0-9]{64}$/.test(tombstone.principalKeyFingerprint)
    && typeof tombstone.targetId === "string"
    && /^[a-f0-9]{64}$/.test(tombstone.targetGeneration)
    && Number.isFinite(Date.parse(tombstone.expiredAt))
    && Number.isFinite(Date.parse(tombstone.tombstonedAt))
    && Number.isFinite(Date.parse(tombstone.removeAfter))
  );
  if (!valid) {
    throw new UniversalBrokerError(
      "PRECONDITION_FAILED",
      "Context store contains an invalid expiry tombstone.",
      {
        evidence: {
          contextId: typeof tombstone?.contextId === "string" ? tombstone.contextId : undefined,
        },
      },
    );
  }
}

function sshArguments(host: string, command: string): string[] {
  return [
    "-T",
    "-o", "BatchMode=yes",
    "-o", "ConnectTimeout=7",
    "-o", "ConnectionAttempts=1",
    host,
    command,
  ];
}

function shellQuote(value: string): string {
  return `'${value.replaceAll("'", `'"'"'`)}'`;
}

function windowsEncodedCommand(source: string): string {
  return [
    "powershell.exe",
    "-NoLogo",
    "-NoProfile",
    "-NonInteractive",
    "-ExecutionPolicy", "Bypass",
    "-EncodedCommand",
    Buffer.from(source, "utf16le").toString("base64"),
  ].join(" ");
}

function processOutput(error: unknown): string {
  if (error instanceof Error) {
    const record = error as Error & { stdout?: string; stderr?: string };
    return `${record.stdout ?? ""}\n${record.stderr ?? ""}\n${record.message}`;
  }
  return String(error);
}

function boundedError(error: unknown): string {
  const normalized = processOutput(error).replace(/\s+/g, " ").trim();
  return normalized.length <= 300 ? normalized : `${normalized.slice(0, 297)}...`;
}

function isNodeError(error: unknown, code: string): boolean {
  return error instanceof Error && "code" in error && (error as NodeJS.ErrnoException).code === code;
}

const SKIPPED_CONTEXT_DIRS = new Set([
  ".git",
  ".hg",
  ".svn",
  ".devspace",
  "node_modules",
  "dist",
  "build",
  ".next",
  ".turbo",
  ".cache",
  ".agent-harness",
  ".tmp",
]);

export function contextPayloadCharacters(value: unknown): number {
  return JSON.stringify(value).length;
}

export function contextErrorCode(error: unknown): UniversalErrorCode | undefined {
  return error instanceof UniversalBrokerError ? error.code : undefined;
}
