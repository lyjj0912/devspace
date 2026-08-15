import { createHash, randomUUID } from "node:crypto";
import { execFile } from "node:child_process";
import {
  mkdir,
  readFile,
  readdir,
  realpath,
  rename,
  stat,
  writeFile,
} from "node:fs/promises";
import { homedir } from "node:os";
import {
  dirname,
  isAbsolute,
  join,
  parse,
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
import { UniversalBrokerError } from "./errors.js";
import {
  type TargetDefinition,
  type TargetRegistry,
} from "./targets.js";

const execFileAsync = promisify(execFile);
const CONTEXT_FILE_NAMES = ["AGENTS.md", "CLAUDE.md"] as const;
const MAX_SUGGESTED_SKILLS = 5;
const MAX_INITIAL_INSTRUCTION_REFERENCES = 10;
const MAX_SEARCH_RESULTS = 50;
const MAX_CONTEXTS = 256;
const MAX_NESTED_SEARCH_DEPTH = 6;
const MAX_NESTED_SEARCH_ENTRIES = 5_000;
const STORE_VERSION = 1;
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
  targetId: string;
  root: string;
  mode: ContextMode;
  instructionSetHash: string;
  instructions: InstructionReference[];
  git?: ContextGitSummary;
  createdAt: string;
  lastUsedAt: string;
}

interface ContextStoreFile {
  version: 1;
  contexts: ContextRecord[];
}

export interface ContextRegistryOptions {
  storePath: string;
  targets: TargetRegistry;
  serverConfig: ServerConfig;
  now?: () => number;
  maximumContexts?: number;
  execute?: typeof execFileAsync;
}

export class ContextRegistry {
  private readonly contexts = new Map<string, ContextRecord>();
  private readonly contextIdByKey = new Map<string, string>();
  private readonly pendingOpen = new Map<string, Promise<ContextOpenResult>>();
  private readonly skillCatalogCache = new Map<string, {
    loadedAt: number;
    skills: ReturnType<typeof loadWorkspaceSkills>["skills"];
  }>();
  private readonly now: () => number;
  private readonly maximumContexts: number;
  private readonly execute: typeof execFileAsync;
  private loaded = false;
  private loadPromise?: Promise<void>;
  private mutationQueue: Promise<void> = Promise.resolve();

  constructor(private readonly options: ContextRegistryOptions) {
    this.now = options.now ?? Date.now;
    this.maximumContexts = options.maximumContexts ?? MAX_CONTEXTS;
    this.execute = options.execute ?? execFileAsync;
  }

  async open(input: {
    target?: string;
    path?: string;
    mode?: ContextMode;
    task?: string;
  }): Promise<ContextOpenResult> {
    await this.ensureLoaded();
    const target = await this.options.targets.resolve(input.target);
    const mode = input.mode ?? "existing";
    if (mode === "worktree") {
      throw new UniversalBrokerError(
        "CAPABILITY_UNAVAILABLE",
        "Context worktree mode is reserved by the v2 contract and will be implemented after the filesystem and execution adapters.",
        { evidence: { phase: "phase-2", operation: "context.open", mode } },
      );
    }
    const requestedPath = input.path ?? target.defaultCwd;
    if (!requestedPath) {
      throw new UniversalBrokerError(
        "PRECONDITION_FAILED",
        `context.open requires path because target ${target.id} has no defaultCwd.`,
      );
    }
    const root = await this.resolveExistingDirectory(target, requestedPath);
    const key = contextKey(target.id, root, mode);
    const pending = this.pendingOpen.get(key);
    if (pending) return pending;

    const operation = this.openResolved(target, root, mode, input.task)
      .finally(() => this.pendingOpen.delete(key));
    this.pendingOpen.set(key, operation);
    return operation;
  }

  async search(input: {
    contextId?: string;
    query?: string;
    cursor?: string;
    limit?: number;
  }): Promise<Record<string, unknown>> {
    await this.ensureLoaded();
    const query = input.query?.trim();
    if (!query) {
      throw new UniversalBrokerError(
        "PRECONDITION_FAILED",
        "context.search requires a non-empty query.",
      );
    }
    const record = input.contextId ? this.requireContext(input.contextId) : undefined;
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

  async close(contextId: string): Promise<Record<string, unknown>> {
    await this.ensureLoaded();
    const record = this.requireContext(contextId);
    this.contexts.delete(contextId);
    this.contextIdByKey.delete(contextKey(record.targetId, record.root, record.mode));
    await this.persist();
    return {
      contextId,
      closed: true,
      targetId: record.targetId,
      root: record.root,
    };
  }

  async get(contextId: string): Promise<ContextRecord> {
    await this.ensureLoaded();
    const record = this.requireContext(contextId);
    await this.touch(record);
    return structuredClone(record);
  }

  private async openResolved(
    target: TargetDefinition,
    root: string,
    mode: ContextMode,
    task: string | undefined,
  ): Promise<ContextOpenResult> {
    const key = contextKey(target.id, root, mode);
    const existingId = this.contextIdByKey.get(key);
    const instructions = await this.discoverInitialInstructions(target, root);
    const instructionSetHash = hashInstructionSet(instructions);
    if (existingId) {
      const existing = this.requireContext(existingId);
      const changed = existing.instructionSetHash !== instructionSetHash;
      existing.instructions = instructions;
      existing.instructionSetHash = instructionSetHash;
      existing.lastUsedAt = new Date(this.now()).toISOString();
      await this.persist();
      const result: ContextOpenResult = {
        contextId: existing.contextId,
        targetId: existing.targetId,
        root: existing.root,
        mode: existing.mode,
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

    if (this.contexts.size >= this.maximumContexts) {
      throw new UniversalBrokerError(
        "RESOURCE_QUOTA_EXCEEDED",
        `Context limit reached: ${this.maximumContexts}`,
        { evidence: { maximumContexts: this.maximumContexts } },
      );
    }
    const timestamp = new Date(this.now()).toISOString();
    const record: ContextRecord = {
      contextId: `ctx_${randomUUID()}`,
      targetId: target.id,
      root,
      mode,
      instructionSetHash,
      instructions,
      git: target.transport === "local" ? await gitSummary(root) : undefined,
      createdAt: timestamp,
      lastUsedAt: timestamp,
    };
    this.contexts.set(record.contextId, record);
    this.contextIdByKey.set(key, record.contextId);
    await this.persist();
    const result = fitInitialContextPayload({
      contextId: record.contextId,
      targetId: record.targetId,
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
    return result;
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
    if (!target.sshHost || target.platform === "windows") return [];
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

  private requireContext(contextId: string): ContextRecord {
    const record = this.contexts.get(contextId);
    if (!record) {
      throw new UniversalBrokerError(
        "PATH_NOT_FOUND",
        `Unknown context: ${contextId}`,
        { evidence: { contextId } },
      );
    }
    return record;
  }

  private async touch(record: ContextRecord): Promise<void> {
    record.lastUsedAt = new Date(this.now()).toISOString();
    await this.persist();
  }

  private async ensureLoaded(): Promise<void> {
    if (this.loaded) return;
    this.loadPromise ??= this.loadFromStore();
    await this.loadPromise;
  }

  private async loadFromStore(): Promise<void> {
    let parsed: ContextStoreFile = { version: STORE_VERSION, contexts: [] };
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
    const keys = new Set<string>();
    for (const record of parsed.contexts) {
      validateContextRecord(record);
      const key = contextKey(record.targetId, record.root, record.mode);
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
      };
      await writeFile(temporary, `${JSON.stringify(payload, null, 2)}\n`, { mode: 0o600 });
      await rename(temporary, this.options.storePath);
    });
    this.mutationQueue = operation.catch(() => undefined);
    return operation;
  }
}

export interface ContextOpenResult extends Record<string, unknown> {
  contextId: string;
  targetId: string;
  root: string;
  mode: ContextMode;
  reused: boolean;
  changed?: boolean;
  instructionSetHash: string;
  instructions?: InstructionReference[];
  suggestedSkills?: SkillReference[];
  git?: ContextGitSummary;
  truncated?: boolean;
  omitted?: {
    instructions: number;
    skills: number;
    git: boolean;
  };
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

function contextKey(targetId: string, root: string, mode: ContextMode): string {
  return `${targetId}\0${root}\0${mode}`;
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

function parseContextStore(content: string): ContextStoreFile {
  const parsed = JSON.parse(content) as Partial<ContextStoreFile>;
  if (parsed.version !== STORE_VERSION || !Array.isArray(parsed.contexts)) {
    throw new Error("unsupported context store format");
  }
  return { version: STORE_VERSION, contexts: parsed.contexts };
}

function validateContextRecord(record: ContextRecord): void {
  const valid = Boolean(
    record
    && typeof record.contextId === "string"
    && record.contextId.startsWith("ctx_")
    && typeof record.targetId === "string"
    && record.targetId.length > 0
    && typeof record.root === "string"
    && record.root.length > 0
    && (record.mode === "existing" || record.mode === "worktree")
    && typeof record.instructionSetHash === "string"
    && Array.isArray(record.instructions)
    && Number.isFinite(Date.parse(record.createdAt))
    && Number.isFinite(Date.parse(record.lastUsedAt))
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
