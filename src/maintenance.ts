import { mkdir, readFile, readdir, realpath, rename, stat, writeFile } from "node:fs/promises";
import { dirname, isAbsolute, join, relative, resolve } from "node:path";
import type { ServerConfig } from "./config.js";
import { openDatabase } from "./db/client.js";
import { getGitEligibility, git } from "./git.js";

interface WorkspaceSessionRecord {
  id: string;
  root: string;
  status: string;
  mode: "checkout" | "worktree";
  sourceRoot?: string;
  baseSha?: string;
  managed: boolean;
  lastUsedAt: string;
}

export interface MaintenanceFailure {
  target: string;
  reason: string;
}

export interface MaintenanceSummary {
  enabled: boolean;
  dryRun: boolean;
  skippedReason?: "disabled" | "interval_not_elapsed";
  bindingsDeleted: number;
  sessionsDeleted: number;
  missingSessionRootsDeleted: number;
  worktreesRemoved: string[];
  worktreesRetainedDirty: string[];
  worktreesRetainedDiverged: string[];
  orphanWorktreesRetained: string[];
  reviewRefsDeleted: number;
  reviewRepositoriesInspected: number;
  failures: MaintenanceFailure[];
  remainingSessions: number;
  remainingBindings: number;
}

export interface MaintenanceOptions {
  now?: Date;
  dryRun?: boolean;
  scheduled?: boolean;
}

const REVIEW_REF_PREFIX = "refs/devspace/review";

export async function runMaintenance(
  config: ServerConfig,
  options: MaintenanceOptions = {},
): Promise<MaintenanceSummary> {
  const summary: MaintenanceSummary = {
    enabled: config.maintenance.enabled,
    dryRun: options.dryRun === true,
    bindingsDeleted: 0,
    sessionsDeleted: 0,
    missingSessionRootsDeleted: 0,
    worktreesRemoved: [],
    worktreesRetainedDirty: [],
    worktreesRetainedDiverged: [],
    orphanWorktreesRetained: [],
    reviewRefsDeleted: 0,
    reviewRepositoriesInspected: 0,
    failures: [],
    remainingSessions: 0,
    remainingBindings: 0,
  };
  if (!config.maintenance.enabled) {
    summary.skippedReason = "disabled";
    return summary;
  }

  const now = options.now ?? new Date();
  const nowMs = now.getTime();
  if (options.scheduled && !await maintenanceDue(config, nowMs)) {
    summary.skippedReason = "interval_not_elapsed";
    return summary;
  }
  const database = openDatabase(config.stateDir);
  const deletedSessionIds = new Set<string>();
  let sessionsBefore: WorkspaceSessionRecord[] = [];

  try {
    const bindingsBefore = readConversationBindings(database.sqlite);
    const bindingCutoff = new Date(
      nowMs - config.maintenance.conversationBindingRetentionMs,
    ).toISOString();
    const staleBindingCount = countRows(
      database.sqlite,
      "select count(*) as count from workspace_conversation_bindings where last_used_at < ?",
      bindingCutoff,
    );
    if (!summary.dryRun && staleBindingCount > 0) {
      database.sqlite
        .prepare("delete from workspace_conversation_bindings where last_used_at < ?")
        .run(bindingCutoff);
    }
    summary.bindingsDeleted = staleBindingCount;

    sessionsBefore = readWorkspaceSessions(database.sqlite);
    const activeBoundSessionIds = new Set(
      bindingsBefore
        .filter((binding) => binding.lastUsedAt >= bindingCutoff)
        .map((binding) => binding.workspaceSessionId),
    );
    const activeBoundRoots = new Set(await Promise.all(
      sessionsBefore
        .filter((session) => activeBoundSessionIds.has(session.id))
        .map((session) => canonicalDirectoryIdentity(session.root)),
    ));
    await pruneManagedWorktrees(
      database.sqlite,
      sessionsBefore,
      config,
      nowMs,
      summary,
      deletedSessionIds,
      activeBoundSessionIds,
      activeBoundRoots,
    );

    await pruneWorkspaceSessions(
      database.sqlite,
      config,
      nowMs,
      summary,
      deletedSessionIds,
      activeBoundSessionIds,
    );

    const retainedSessions = readWorkspaceSessions(database.sqlite).filter((session) =>
      !summary.dryRun || !deletedSessionIds.has(session.id)
    );
    await pruneReviewRefs(
      [...sessionsBefore, ...retainedSessions],
      retainedSessions,
      config,
      summary,
    );

    await inspectOrphanWorktrees(retainedSessions, config, summary);
    summary.remainingSessions = summary.dryRun
      ? Math.max(0, sessionsBefore.length - summary.sessionsDeleted)
      : countRows(database.sqlite, "select count(*) as count from workspace_sessions");
    if (summary.dryRun) {
      summary.remainingBindings = bindingsBefore.filter((binding) =>
        binding.lastUsedAt >= bindingCutoff
        && !deletedSessionIds.has(binding.workspaceSessionId)
      ).length;
    } else {
      summary.remainingBindings = countRows(
        database.sqlite,
        "select count(*) as count from workspace_conversation_bindings",
      );
    }
    summary.bindingsDeleted = bindingsBefore.length - summary.remainingBindings;
    if (!summary.dryRun && summary.failures.length === 0) {
      await writeMaintenanceMarker(config, now);
    }
    return summary;
  } finally {
    database.close();
  }
}

async function maintenanceDue(config: ServerConfig, nowMs: number): Promise<boolean> {
  try {
    const marker = JSON.parse(await readFile(maintenanceMarkerPath(config), "utf8")) as {
      completedAt?: string;
    };
    const completedAt = Date.parse(marker.completedAt ?? "");
    return !Number.isFinite(completedAt)
      || nowMs - completedAt >= config.maintenance.minimumIntervalMs;
  } catch {
    return true;
  }
}

async function writeMaintenanceMarker(config: ServerConfig, completedAt: Date): Promise<void> {
  await mkdir(config.stateDir, { recursive: true });
  const destination = maintenanceMarkerPath(config);
  const temporary = `${destination}.tmp-${process.pid}`;
  await writeFile(
    temporary,
    JSON.stringify({ completedAt: completedAt.toISOString() }, null, 2) + "\n",
    { mode: 0o600 },
  );
  await rename(temporary, destination);
}

function maintenanceMarkerPath(config: ServerConfig): string {
  return join(config.stateDir, "maintenance-state.json");
}

async function pruneManagedWorktrees(
  sqlite: ReturnType<typeof openDatabase>["sqlite"],
  sessions: WorkspaceSessionRecord[],
  config: ServerConfig,
  nowMs: number,
  summary: MaintenanceSummary,
  deletedSessionIds: Set<string>,
  activeBoundSessionIds: Set<string>,
  activeBoundRoots: Set<string>,
): Promise<void> {
  const worktrees = sessions.filter((session) =>
    session.mode === "worktree" && session.managed
  );
  const grouped = new Map<string, WorkspaceSessionRecord[]>();
  for (const session of worktrees) {
    const key = session.sourceRoot ?? `missing-source:${session.root}`;
    const entries = grouped.get(key) ?? [];
    entries.push(session);
    grouped.set(key, entries);
  }

  for (const entries of grouped.values()) {
    entries.sort((left, right) => right.lastUsedAt.localeCompare(left.lastUsedAt));
    for (const [index, session] of entries.entries()) {
      if (
        activeBoundSessionIds.has(session.id)
        || activeBoundRoots.has(await canonicalDirectoryIdentity(session.root))
      ) {
        continue;
      }
      const exists = await isDirectory(session.root);
      if (!exists) {
        deleteSession(sqlite, session.id, summary, true, deletedSessionIds);
        continue;
      }

      const ageMs = Math.max(0, nowMs - Date.parse(session.lastUsedAt));
      const expired = ageMs >= config.maintenance.managedWorktreeRetentionMs;
      const excess = index >= config.maintenance.managedWorktreePerSourceLimit
        && ageMs >= config.maintenance.managedWorktreeRecentProtectionMs;
      if (!expired && !excess) continue;

      if (
        !isInside(session.root, config.worktreeRoot)
        || !await isRealPathInside(session.root, config.worktreeRoot)
      ) {
        summary.failures.push({
          target: session.root,
          reason: "managed worktree real path is outside the configured worktree root",
        });
        continue;
      }

      try {
        const status = (await git(session.root, ["status", "--porcelain", "--untracked-files=all"]))
          .stdout
          .trim();
        if (status) {
          summary.worktreesRetainedDirty.push(session.root);
          continue;
        }
        const head = (await git(session.root, ["rev-parse", "HEAD"])).stdout.trim();
        const divergedFromRecordedBase = !session.baseSha || head !== session.baseSha;
        if (divergedFromRecordedBase && !await hasPermanentRefContaining(session.root, head)) {
          summary.worktreesRetainedDiverged.push(session.root);
          continue;
        }
        if (!summary.dryRun) {
          const commandRoot = session.sourceRoot && await isDirectory(session.sourceRoot)
            ? session.sourceRoot
            : session.root;
          await git(commandRoot, ["worktree", "remove", "--force", session.root]);
        }
        summary.worktreesRemoved.push(session.root);
        deleteSession(sqlite, session.id, summary, false, deletedSessionIds);
      } catch (error) {
        summary.failures.push({ target: session.root, reason: errorMessage(error) });
      }
    }
  }
}

async function hasPermanentRefContaining(root: string, commit: string): Promise<boolean> {
  const refs = (await git(root, [
    "for-each-ref",
    "--contains",
    commit,
    "--format=%(refname)",
    "refs/heads",
    "refs/remotes",
    "refs/tags",
  ])).stdout.trim();
  return refs.length > 0;
}

async function pruneWorkspaceSessions(
  sqlite: ReturnType<typeof openDatabase>["sqlite"],
  config: ServerConfig,
  nowMs: number,
  summary: MaintenanceSummary,
  deletedSessionIds: Set<string>,
  activeBoundSessionIds: Set<string>,
): Promise<void> {
  const sessions = readWorkspaceSessions(sqlite).filter((session) =>
    !deletedSessionIds.has(session.id)
  );
  const sessionCutoff = nowMs - config.maintenance.workspaceSessionRetentionMs;
  const candidates = new Map<string, { session: WorkspaceSessionRecord; missing: boolean }>();

  for (const session of sessions) {
    const missing = !(await isDirectory(session.root));
    if (missing) {
      candidates.set(session.id, { session, missing: true });
      continue;
    }
    if (activeBoundSessionIds.has(session.id)) continue;
    if (session.mode === "checkout" && Date.parse(session.lastUsedAt) <= sessionCutoff) {
      candidates.set(session.id, { session, missing });
    }
  }

  const retainedCountAfterAgePrune = sessions.length - candidates.size;
  let additionalNeeded = Math.max(
    0,
    retainedCountAfterAgePrune - config.maintenance.workspaceSessionLimit,
  );
  if (additionalNeeded > 0) {
    const eligible = sessions
      .filter((session) =>
        !activeBoundSessionIds.has(session.id)
        && session.mode === "checkout"
        && !candidates.has(session.id)
      )
      .sort((left, right) => left.lastUsedAt.localeCompare(right.lastUsedAt));
    for (const session of eligible) {
      if (additionalNeeded <= 0) break;
      candidates.set(session.id, { session, missing: false });
      additionalNeeded -= 1;
    }
  }

  for (const { session, missing } of candidates.values()) {
    deleteSession(sqlite, session.id, summary, missing, deletedSessionIds);
  }
}

function deleteSession(
  sqlite: ReturnType<typeof openDatabase>["sqlite"],
  sessionId: string,
  summary: MaintenanceSummary,
  missingRoot: boolean,
  deletedSessionIds: Set<string>,
): void {
  if (deletedSessionIds.has(sessionId)) return;
  deletedSessionIds.add(sessionId);
  summary.sessionsDeleted += 1;
  if (missingRoot) summary.missingSessionRootsDeleted += 1;
  if (!summary.dryRun) {
    sqlite.prepare("delete from workspace_sessions where id = ?").run(sessionId);
  }
}

async function pruneReviewRefs(
  repositoryCandidates: WorkspaceSessionRecord[],
  retainedSessions: WorkspaceSessionRecord[],
  config: ServerConfig,
  summary: MaintenanceSummary,
): Promise<void> {
  const retainedLastUsed = new Map(
    retainedSessions.map((session) => [session.id, Date.parse(session.lastUsedAt)]),
  );
  const repositories = new Map<string, string>();

  for (const session of repositoryCandidates) {
    const root = await firstExistingDirectory(session.root, session.sourceRoot);
    if (!root) continue;
    try {
      const eligibility = await getGitEligibility(root);
      if (!eligibility.ok || !eligibility.gitRoot) continue;
      const commonDirOutput = (await git(eligibility.gitRoot, ["rev-parse", "--git-common-dir"]))
        .stdout
        .trim();
      const commonDir = isAbsolute(commonDirOutput)
        ? commonDirOutput
        : resolve(eligibility.gitRoot, commonDirOutput);
      const identity = await realpath(commonDir).catch(() => commonDir);
      repositories.set(identity, eligibility.gitRoot);
    } catch {
      // A stale session can point at a path that stopped being a Git workspace.
    }
  }

  for (const gitRoot of repositories.values()) {
    summary.reviewRepositoriesInspected += 1;
    try {
      const refs = (await git(gitRoot, [
        "for-each-ref",
        "--format=%(refname)",
        REVIEW_REF_PREFIX,
      ])).stdout.split("\n").map((ref) => ref.trim()).filter(Boolean);
      const grouped = new Map<string, string[]>();
      for (const ref of refs) {
        const match = /^refs\/devspace\/review\/([^/]+)\/(?:open|baseline)$/.exec(ref);
        if (!match) continue;
        const workspaceId = match[1] ?? "";
        const group = grouped.get(workspaceId) ?? [];
        group.push(ref);
        grouped.set(workspaceId, group);
      }
      const retainedGroups = [...grouped.keys()]
        .filter((workspaceId) => retainedLastUsed.has(workspaceId))
        .sort((left, right) =>
          (retainedLastUsed.get(right) ?? 0) - (retainedLastUsed.get(left) ?? 0)
        );
      const keep = new Set(retainedGroups.slice(0, config.maintenance.reviewWorkspaceLimit));
      for (const [workspaceId, workspaceRefs] of grouped) {
        if (keep.has(workspaceId)) continue;
        for (const ref of workspaceRefs) {
          if (!summary.dryRun) await git(gitRoot, ["update-ref", "-d", ref]);
          summary.reviewRefsDeleted += 1;
        }
      }
    } catch (error) {
      summary.failures.push({ target: gitRoot, reason: errorMessage(error) });
    }
  }
}

async function inspectOrphanWorktrees(
  retainedSessions: WorkspaceSessionRecord[],
  config: ServerConfig,
  summary: MaintenanceSummary,
): Promise<void> {
  const retainedRoots = new Set(
    retainedSessions
      .filter((session) => session.mode === "worktree" && session.managed)
      .map((session) => resolve(session.root)),
  );
  let entries;
  try {
    entries = await readdir(config.worktreeRoot, { withFileTypes: true });
  } catch {
    return;
  }
  for (const entry of entries) {
    if (!entry.isDirectory()) continue;
    const path = resolve(config.worktreeRoot, entry.name);
    if (!retainedRoots.has(path) && !summary.worktreesRemoved.includes(path)) {
      summary.orphanWorktreesRetained.push(path);
    }
  }
}

function readWorkspaceSessions(
  sqlite: ReturnType<typeof openDatabase>["sqlite"],
): WorkspaceSessionRecord[] {
  const rows = sqlite.prepare(
    `select id, root, status, mode, source_root, base_sha, managed, last_used_at
       from workspace_sessions
      order by last_used_at desc`,
  ).all() as Array<{
    id: string;
    root: string;
    status: string;
    mode: string;
    source_root: string | null;
    base_sha: string | null;
    managed: string;
    last_used_at: string;
  }>;
  return rows.map((row) => ({
    id: row.id,
    root: row.root,
    status: row.status,
    mode: row.mode === "worktree" ? "worktree" : "checkout",
    sourceRoot: row.source_root ?? undefined,
    baseSha: row.base_sha ?? undefined,
    managed: row.managed === "true",
    lastUsedAt: row.last_used_at,
  }));
}

function readConversationBindings(
  sqlite: ReturnType<typeof openDatabase>["sqlite"],
): Array<{ workspaceSessionId: string; lastUsedAt: string }> {
  return (sqlite.prepare(
    `select workspace_session_id, last_used_at
       from workspace_conversation_bindings`,
  ).all() as Array<{ workspace_session_id: string; last_used_at: string }>).map((row) => ({
    workspaceSessionId: row.workspace_session_id,
    lastUsedAt: row.last_used_at,
  }));
}

function countRows(
  sqlite: ReturnType<typeof openDatabase>["sqlite"],
  sql: string,
  ...parameters: unknown[]
): number {
  return (sqlite.prepare(sql).get(...parameters) as { count: number }).count;
}

async function isDirectory(path: string): Promise<boolean> {
  try {
    return (await stat(path)).isDirectory();
  } catch {
    return false;
  }
}

async function firstExistingDirectory(
  ...paths: Array<string | undefined>
): Promise<string | undefined> {
  for (const path of paths) {
    if (path && await isDirectory(path)) return path;
  }
  return undefined;
}

function isInside(path: string, root: string): boolean {
  const relationship = relative(resolve(root), resolve(path));
  return relationship === "" || (!relationship.startsWith("..") && !isAbsolute(relationship));
}

async function isRealPathInside(path: string, root: string): Promise<boolean> {
  try {
    const [canonicalPath, canonicalRoot] = await Promise.all([
      realpath(path),
      realpath(root),
    ]);
    return isInside(canonicalPath, canonicalRoot);
  } catch {
    return false;
  }
}

async function canonicalDirectoryIdentity(path: string): Promise<string> {
  return realpath(path).catch(() => resolve(path));
}

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}
