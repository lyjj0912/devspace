import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { access, mkdir, mkdtemp, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test, { type TestContext } from "node:test";
import { promisify } from "node:util";
import { loadConfig, type ServerConfig } from "./config.js";
import { openDatabase } from "./db/client.js";
import { runMaintenance } from "./maintenance.js";

const execFileAsync = promisify(execFile);
const DAY_MS = 24 * 60 * 60 * 1_000;
const NOW = new Date("2026-08-14T13:00:00.000Z");
const TEST_CREDENTIAL = "x".repeat(32);

test("maintenance prunes stale unbound sessions and orphan review refs", async (t) => {
  const context = await fixture(t);
  const project = await committedRepository(context.root, "project");
  const recent = isoAgo(1);
  const old = isoAgo(10);

  seedSession(context.config, {
    id: "ws_bound",
    root: project,
    lastUsedAt: old,
  });
  seedSession(context.config, {
    id: "ws_recent",
    root: project,
    lastUsedAt: recent,
  });
  seedSession(context.config, {
    id: "ws_stale",
    root: project,
    lastUsedAt: old,
  });
  seedSession(context.config, {
    id: "ws_missing",
    root: join(context.root, "missing-project"),
    lastUsedAt: recent,
  });
  seedSession(context.config, {
    id: "ws_missing_bound",
    root: join(context.root, "missing-bound-project"),
    lastUsedAt: recent,
  });
  seedBinding(context.config, "conversation-1", "target-1", "ws_bound", recent);
  seedBinding(context.config, "conversation-2", "target-2", "ws_missing_bound", recent);

  const head = (await git(project, ["rev-parse", "HEAD"])).trim();
  for (const ref of [
    "refs/devspace/review/ws_bound/open",
    "refs/devspace/review/ws_bound/baseline",
    "refs/devspace/review/ws_stale/open",
    "refs/devspace/review/ws_stale/baseline",
    "refs/devspace/review/ws_unknown/open",
  ]) {
    await git(project, ["update-ref", ref, head]);
  }

  const result = await runMaintenance(context.config, { now: NOW });

  assert.equal(result.sessionsDeleted, 3);
  assert.equal(result.missingSessionRootsDeleted, 2);
  assert.equal(result.bindingsDeleted, 1);
  assert.equal(result.reviewRefsDeleted, 3);
  assert.deepEqual(sessionIds(context.config), ["ws_bound", "ws_recent"]);
  assert.equal(bindingCount(context.config), 1);
  assert.deepEqual(await reviewRefs(project), [
    "refs/devspace/review/ws_bound/baseline",
    "refs/devspace/review/ws_bound/open",
  ]);
});

test("maintenance removes expired clean worktrees but preserves dirty worktrees", async (t) => {
  const context = await fixture(t);
  const source = await committedRepository(context.root, "source");
  const clean = join(context.config.worktreeRoot, "clean-old");
  const dirty = join(context.config.worktreeRoot, "dirty-old");
  const diverged = join(context.config.worktreeRoot, "diverged-old");
  const referenced = join(context.config.worktreeRoot, "referenced-old");
  const bound = join(context.config.worktreeRoot, "bound-old");
  await mkdir(context.config.worktreeRoot, { recursive: true });
  const baseSha = (await git(source, ["rev-parse", "HEAD"])).trim();
  await git(source, ["worktree", "add", "--detach", clean, "HEAD"]);
  await git(source, ["worktree", "add", "--detach", dirty, "HEAD"]);
  await git(source, ["worktree", "add", "--detach", diverged, "HEAD"]);
  await git(source, ["worktree", "add", "-b", "preserved-worktree-branch", referenced, "HEAD"]);
  await git(source, ["worktree", "add", "--detach", bound, "HEAD"]);
  await writeFile(join(dirty, "uncommitted.txt"), "preserve me\n");
  await writeFile(join(diverged, "committed.txt"), "preserve commit\n");
  await git(diverged, ["add", "committed.txt"]);
  await git(diverged, ["commit", "-m", "Worktree-only commit"]);
  await writeFile(join(referenced, "branch-commit.txt"), "preserved by branch\n");
  await git(referenced, ["add", "branch-commit.txt"]);
  await git(referenced, ["commit", "-m", "Branch-preserved commit"]);

  seedSession(context.config, {
    id: "ws_clean_worktree",
    root: clean,
    mode: "worktree",
    sourceRoot: source,
    baseSha,
    managed: true,
    lastUsedAt: isoAgo(10),
  });
  seedSession(context.config, {
    id: "ws_bound_worktree",
    root: bound,
    mode: "worktree",
    sourceRoot: source,
    baseSha,
    managed: true,
    lastUsedAt: isoAgo(10),
  });
  seedBinding(context.config, "conversation-bound", "bound-worktree", "ws_bound_worktree", isoAgo(1));
  seedSession(context.config, {
    id: "ws_referenced_worktree",
    root: referenced,
    mode: "worktree",
    sourceRoot: source,
    baseSha,
    managed: true,
    lastUsedAt: isoAgo(10),
  });
  seedSession(context.config, {
    id: "ws_dirty_worktree",
    root: dirty,
    mode: "worktree",
    sourceRoot: source,
    baseSha,
    managed: true,
    lastUsedAt: isoAgo(10),
  });
  seedSession(context.config, {
    id: "ws_diverged_worktree",
    root: diverged,
    mode: "worktree",
    sourceRoot: source,
    baseSha,
    managed: true,
    lastUsedAt: isoAgo(10),
  });

  const result = await runMaintenance(context.config, { now: NOW });

  await assert.rejects(access(clean));
  await access(dirty);
  await access(diverged);
  await access(bound);
  await assert.rejects(access(referenced));
  assert.deepEqual(result.worktreesRemoved.sort(), [clean, referenced].sort());
  assert.deepEqual(result.worktreesRetainedDirty, [dirty]);
  assert.deepEqual(result.worktreesRetainedDiverged, [diverged]);
  assert.deepEqual(sessionIds(context.config), [
    "ws_bound_worktree",
    "ws_dirty_worktree",
    "ws_diverged_worktree",
  ]);
});

test("maintenance rejects a managed worktree symlink that escapes the configured root", async (t) => {
  const context = await fixture(t);
  const outside = await committedRepository(context.root, "outside-worktree");
  const link = join(context.config.worktreeRoot, "outside-link");
  await mkdir(context.config.worktreeRoot, { recursive: true });
  await symlink(outside, link, "dir");
  const baseSha = (await git(outside, ["rev-parse", "HEAD"])).trim();
  seedSession(context.config, {
    id: "ws_outside_link",
    root: link,
    mode: "worktree",
    sourceRoot: outside,
    baseSha,
    managed: true,
    lastUsedAt: isoAgo(10),
  });

  const result = await runMaintenance(context.config, { now: NOW });

  await access(link);
  assert.equal(result.worktreesRemoved.length, 0);
  assert.equal(result.failures.length, 1);
  assert.match(result.failures[0]?.reason ?? "", /real path is outside/);
  assert.deepEqual(sessionIds(context.config), ["ws_outside_link"]);
});

test("maintenance dry-run reports candidates without changing state", async (t) => {
  const context = await fixture(t);
  const project = await committedRepository(context.root, "dry-run-project");
  seedSession(context.config, {
    id: "ws_dry_run",
    root: project,
    lastUsedAt: isoAgo(10),
  });

  const result = await runMaintenance(context.config, { now: NOW, dryRun: true });

  assert.equal(result.dryRun, true);
  assert.equal(result.sessionsDeleted, 1);
  assert.deepEqual(sessionIds(context.config), ["ws_dry_run"]);
});

test("scheduled maintenance respects the persisted minimum interval", async (t) => {
  const context = await fixture(t);
  const first = await runMaintenance(context.config, { now: NOW });
  assert.equal(first.skippedReason, undefined);

  const scheduled = await runMaintenance(context.config, {
    now: new Date(NOW.getTime() + 60 * 60 * 1_000),
    scheduled: true,
  });
  assert.equal(scheduled.skippedReason, "interval_not_elapsed");
  assert.equal(scheduled.sessionsDeleted, 0);
});

interface Fixture {
  root: string;
  config: ServerConfig;
}

async function fixture(t: TestContext): Promise<Fixture> {
  const root = await mkdtemp(join(tmpdir(), "devspace-maintenance-test-"));
  t.after(() => rm(root, { recursive: true, force: true }));
  const config = loadConfig({
    DEVSPACE_CONFIG_DIR: join(root, ".config"),
    DEVSPACE_ALLOWED_ROOTS: root,
    DEVSPACE_STATE_DIR: join(root, ".state"),
    DEVSPACE_WORKTREE_ROOT: join(root, ".worktrees"),
    DEVSPACE_OAUTH_OWNER_TOKEN: TEST_CREDENTIAL,
  });
  config.maintenance = {
    enabled: true,
    minimumIntervalMs: DAY_MS,
    conversationBindingRetentionMs: 30 * DAY_MS,
    workspaceSessionRetentionMs: 7 * DAY_MS,
    workspaceSessionLimit: 10,
    managedWorktreeRetentionMs: 7 * DAY_MS,
    managedWorktreeRecentProtectionMs: DAY_MS,
    managedWorktreePerSourceLimit: 8,
    reviewWorkspaceLimit: 8,
  };
  return { root, config };
}

async function committedRepository(root: string, name: string): Promise<string> {
  const project = join(root, name);
  await mkdir(project, { recursive: true });
  await git(project, ["init"]);
  await git(project, ["config", "user.email", "devspace@example.com"]);
  await git(project, ["config", "user.name", "DevSpace Test"]);
  await writeFile(join(project, "README.md"), "hello\n");
  await git(project, ["add", "README.md"]);
  await git(project, ["commit", "-m", "Initial commit"]);
  return project;
}

function seedSession(
  config: ServerConfig,
  input: {
    id: string;
    root: string;
    mode?: "checkout" | "worktree";
    sourceRoot?: string;
    baseSha?: string;
    managed?: boolean;
    lastUsedAt: string;
  },
): void {
  const database = openDatabase(config.stateDir);
  try {
    database.sqlite.prepare(
      `insert into workspace_sessions (
         id, root, status, mode, source_root, base_ref, base_sha, managed, created_at, last_used_at
       ) values (?, ?, 'active', ?, ?, null, ?, ?, ?, ?)`,
    ).run(
      input.id,
      input.root,
      input.mode ?? "checkout",
      input.sourceRoot ?? null,
      input.baseSha ?? null,
      String(input.managed ?? false),
      input.lastUsedAt,
      input.lastUsedAt,
    );
  } finally {
    database.close();
  }
}

function seedBinding(
  config: ServerConfig,
  conversationScopeId: string,
  targetKey: string,
  workspaceSessionId: string,
  lastUsedAt: string,
): void {
  const database = openDatabase(config.stateDir);
  try {
    database.sqlite.prepare(
      `insert into workspace_conversation_bindings (
         conversation_scope_id, target_key, workspace_session_id, created_at, last_used_at
       ) values (?, ?, ?, ?, ?)`,
    ).run(conversationScopeId, targetKey, workspaceSessionId, lastUsedAt, lastUsedAt);
  } finally {
    database.close();
  }
}

function sessionIds(config: ServerConfig): string[] {
  const database = openDatabase(config.stateDir);
  try {
    return (database.sqlite
      .prepare("select id from workspace_sessions order by id")
      .all() as Array<{ id: string }>).map((row) => row.id);
  } finally {
    database.close();
  }
}

function bindingCount(config: ServerConfig): number {
  const database = openDatabase(config.stateDir);
  try {
    return (database.sqlite
      .prepare("select count(*) as count from workspace_conversation_bindings")
      .get() as { count: number }).count;
  } finally {
    database.close();
  }
}

async function reviewRefs(root: string): Promise<string[]> {
  return (await git(root, [
    "for-each-ref",
    "--format=%(refname)",
    "refs/devspace/review",
  ])).split("\n").map((line) => line.trim()).filter(Boolean).sort();
}

function isoAgo(days: number): string {
  return new Date(NOW.getTime() - days * DAY_MS).toISOString();
}

async function git(cwd: string, args: string[]): Promise<string> {
  const { stdout } = await execFileAsync("git", args, { cwd });
  return stdout;
}
