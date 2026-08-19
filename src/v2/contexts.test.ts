import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { access, mkdir, mkdtemp, readFile, rm, stat, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { loadConfig } from "../config.js";
import { UNIVERSAL_BROKER_BUDGETS } from "./contracts.js";
import { createCapabilityCallContextFromTrustedPrincipal } from "./capability-call-context.js";
import {
  ContextRegistry,
  contextErrorCode,
  contextPayloadCharacters,
} from "./contexts.js";
import { TargetRegistry } from "./targets.js";

const OWNER_A = createCapabilityCallContextFromTrustedPrincipal({
  principalKeyFingerprint: createHash("sha256").update("context-owner-a").digest("hex"),
});
const OWNER_B = createCapabilityCallContextFromTrustedPrincipal({
  principalKeyFingerprint: createHash("sha256").update("context-owner-b").digest("hex"),
});

test("context.open requires an existing directory and never creates a guessed path", async (t) => {
  const fixture = await createFixture(t);
  const missing = join(fixture.root, "missing");
  await assert.rejects(
    fixture.contexts.open({ path: missing }),
    (error: unknown) => contextErrorCode(error) === "PATH_NOT_FOUND",
  );
  await assert.rejects(stat(missing));

  const file = join(fixture.root, "file.txt");
  await writeFile(file, "not a directory\n");
  await assert.rejects(
    fixture.contexts.open({ path: file }),
    (error: unknown) => contextErrorCode(error) === "PATH_TYPE_MISMATCH",
  );
});

test("context.open returns only references and relevant Skills within payload budgets", async (t) => {
  const fixture = await createFixture(t);
  const project = join(fixture.root, "project");
  await mkdir(project);
  await writeFile(join(project, "AGENTS.md"), "# Project\n\nRun release checks.\n");
  await gitInit(project);

  const first = await fixture.contexts.open({
    path: project,
    task: "release verification",
  });
  assert.equal(first.reused, false);
  assert.equal(first.targetId, "local");
  assert.ok(first.instructions?.some((reference) => reference.path.endsWith("AGENTS.md")));
  assert.ok((first.suggestedSkills?.length ?? 0) <= 5);
  assert.ok(
    contextPayloadCharacters(first)
      <= UNIVERSAL_BROKER_BUDGETS.maximumInitialContextCharacters,
  );
  assert.equal("content" in (first.instructions?.[0] ?? {}), false);

  const second = await fixture.contexts.open({ path: project, task: "unrelated" });
  assert.equal(second.contextId, first.contextId);
  assert.equal(second.reused, true);
  assert.equal(second.root, undefined);
  assert.equal(second.mode, undefined);
  assert.ok(
    contextPayloadCharacters(second)
      <= UNIVERSAL_BROKER_BUDGETS.maximumReusedContextCharacters,
  );
  assert.equal(second.suggestedSkills, undefined);
});

test("context instruction hash changes without embedding instruction content", async (t) => {
  const fixture = await createFixture(t);
  const project = join(fixture.root, "project");
  await mkdir(project);
  const agents = join(project, "AGENTS.md");
  await writeFile(agents, "first\n");
  const first = await fixture.contexts.open({ path: project });
  await writeFile(agents, "second\n");
  const second = await fixture.contexts.open({ path: project });
  assert.equal(second.reused, true);
  assert.equal(second.changed, true);
  assert.notEqual(second.instructionSetHash, first.instructionSetHash);
});

test("context reuse is owner-aware and cross-owner rejection reaches zero target providers", async (t) => {
  const fixture = await createFixture(t);
  const project = join(fixture.root, "owned-project");
  await mkdir(project);
  const first = await fixture.contexts.open({ path: project }, OWNER_A);
  const reused = await fixture.contexts.open({ path: project }, OWNER_A);
  const otherOwner = await fixture.contexts.open({ path: project }, OWNER_B);
  assert.equal(reused.contextId, first.contextId);
  assert.equal(reused.reused, true);
  assert.notEqual(otherOwner.contextId, first.contextId);

  let targetProviderCalls = 0;
  const targets = fixture.targets as TargetRegistry & {
    resolveWithGeneration: TargetRegistry["resolveWithGeneration"];
  };
  const original = targets.resolveWithGeneration.bind(targets);
  targets.resolveWithGeneration = async (...args) => {
    targetProviderCalls += 1;
    return original(...args);
  };
  await assert.rejects(
    fixture.contexts.get(first.contextId, OWNER_B),
    (error: unknown) => contextErrorCode(error) === "AUTHORITY_PRINCIPAL_MISMATCH",
  );
  assert.equal(targetProviderCalls, 0);
});

test("the 129th context is rejected synchronously before context creation work", async (t) => {
  const fixture = await createFixture(t, { maximumContexts: 128 });
  let creationProviderCalls = 0;
  const internals = fixture.contexts as unknown as {
    discoverInitialInstructions: (...args: unknown[]) => Promise<unknown>;
  };
  const original = internals.discoverInitialInstructions.bind(fixture.contexts);
  internals.discoverInitialInstructions = async (...args) => {
    creationProviderCalls += 1;
    return original(...args);
  };
  for (let index = 0; index < 128; index += 1) {
    const project = join(fixture.root, `quota-project-${String(index).padStart(3, "0")}`);
    await mkdir(project);
    await fixture.contexts.open({ path: project }, OWNER_A);
  }
  assert.equal(creationProviderCalls, 128);
  const rejected = join(fixture.root, "quota-project-129");
  await mkdir(rejected);
  await assert.rejects(
    fixture.contexts.open({ path: rejected }, OWNER_A),
    (error: unknown) => contextErrorCode(error) === "RESOURCE_QUOTA_EXCEEDED",
  );
  assert.equal(creationProviderCalls, 128);
  assert.equal(fixture.contexts.stats().contexts, 128);
});

test("contexts retain unrelated-target stability and reject an exact-target generation change", async (t) => {
  const fixture = await createFixture(t);
  const project = join(fixture.root, "generation-project");
  await mkdir(project);
  const first = await fixture.contexts.open({ path: project }, OWNER_A);
  assert.match(first.targetGeneration, /^[a-f0-9]{64}$/u);

  const targetsPath = join(fixture.root, "targets.json");
  await writeFile(targetsPath, JSON.stringify({
    version: 1,
    targets: {
      unrelated: {
        displayName: "Unrelated",
        transport: "ssh",
        sshHost: "unrelated",
        platform: "linux",
      },
    },
  }));
  const reused = await fixture.contexts.open({ path: project }, OWNER_A);
  assert.equal(reused.contextId, first.contextId);

  await writeFile(targetsPath, JSON.stringify({
    version: 1,
    targets: {
      local: {
        displayName: "Changed local binding",
        transport: "local",
        platform: "unknown",
      },
    },
  }));
  await assert.rejects(
    fixture.contexts.get(first.contextId, OWNER_A),
    (error: unknown) => contextErrorCode(error) === "AUTHORITY_STALE",
  );
});

test("context records persist and close explicitly", async (t) => {
  const fixture = await createFixture(t);
  const project = join(fixture.root, "project");
  await mkdir(project);
  const opened = await fixture.contexts.open({ path: project });

  const restored = new ContextRegistry({
    storePath: fixture.storePath,
    targets: fixture.targets,
    serverConfig: fixture.serverConfig,
  });
  assert.equal((await restored.get(opened.contextId)).root, opened.root);
  const closed = await restored.close(opened.contextId);
  assert.equal(closed.closed, true);
  await assert.rejects(restored.get(opened.contextId));
  const stored = JSON.parse(await readFile(fixture.storePath, "utf8"));
  assert.deepEqual(stored.contexts, []);
});

test("context.search is explicit and bounded", async (t) => {
  const fixture = await createFixture(t);
  const project = join(fixture.root, "project");
  await mkdir(join(project, "nested"), { recursive: true });
  await writeFile(join(project, "nested", "AGENTS.md"), "nested instructions\n");
  const opened = await fixture.contexts.open({ path: project });
  const result = await fixture.contexts.search({
    contextId: opened.contextId,
    query: "nested",
    limit: 5,
  });
  const results = result.results as Array<{ type?: string; path?: string }>;
  assert.ok(results.some((entry) => entry.type === "instruction" && entry.path?.includes("nested")));
  await assert.rejects(
    fixture.contexts.search({ contextId: opened.contextId, query: "" }),
    (error: unknown) => contextErrorCode(error) === "PRECONDITION_FAILED",
  );
});

test("initial context trims references instead of exceeding the hard payload budget", async (t) => {
  const fixture = await createFixture(t);
  let project = fixture.root;
  for (let index = 0; index < 6; index += 1) {
    project = join(project, `very-long-project-directory-${index}-${"x".repeat(32)}`);
    await mkdir(project);
    await writeFile(join(project, "AGENTS.md"), `instructions ${index}\n`);
    await writeFile(join(project, "CLAUDE.md"), `claude ${index}\n`);
  }
  const skillRoot = join(fixture.root, "skills");
  await mkdir(skillRoot, { recursive: true });
  for (let index = 0; index < 8; index += 1) {
    const directory = join(skillRoot, `release-verification-${index}`);
    await mkdir(directory);
    await writeFile(join(directory, "SKILL.md"), [
      "---",
      `name: release-verification-${index}`,
      `description: ${"release verification deployment evidence ".repeat(20)}`,
      "---",
      "",
      "Run the release verification.",
      "",
    ].join("\n"));
  }

  const opened = await fixture.contexts.open({
    path: project,
    task: "release verification deployment evidence",
  });
  assert.ok(
    contextPayloadCharacters(opened)
      <= UNIVERSAL_BROKER_BUDGETS.maximumInitialContextCharacters,
  );
  assert.equal(opened.truncated, true);
  assert.ok((opened.omitted?.instructions ?? 0) + (opened.omitted?.skills ?? 0) > 0);
});

test("context worktree creates an isolated checkout, exposes a paged diff, and retains dirty work", async (t) => {
  const fixture = await createFixture(t);
  const project = join(fixture.root, "project");
  await mkdir(project);
  await gitInit(project);

  const opened = await fixture.contexts.open({
    path: project,
    mode: "worktree",
    task: "edit README",
  });
  assert.equal(opened.mode, "worktree");
  assert.equal(opened.managed, true);
  assert.notEqual(opened.root, project);
  const openedRoot = opened.root;
  assert.ok(openedRoot);
  await access(openedRoot);

  await writeFile(join(openedRoot, "README.md"), "hello\nchanged\n");
  const diff = await fixture.contexts.diff({
    contextId: opened.contextId,
    maxCharacters: 100,
  });
  assert.equal(typeof diff.resourceUri, "string");
  assert.equal((diff.summary as { files: number }).files, 1);
  const page = fixture.contexts.readDiffResource(String(diff.resourceUri));
  assert.match(String(page.text), /README\.md|changed/);

  const closed = await fixture.contexts.close(opened.contextId);
  assert.equal(closed.closed, false);
  assert.equal((closed.worktree as { retained: boolean }).retained, true);
  assert.equal((closed.worktree as { reason: string }).reason, "dirty");
  await access(openedRoot);
  assert.equal((await fixture.contexts.get(opened.contextId)).root, openedRoot);
});

test("context close removes a clean managed worktree and enforces the worktree quota", async (t) => {
  const fixture = await createFixture(t, { maximumWorktrees: 1 });
  const project = join(fixture.root, "project");
  await mkdir(project);
  await gitInit(project);

  const opened = await fixture.contexts.open({ path: project, mode: "worktree" });
  const openedRoot = opened.root;
  assert.ok(openedRoot);
  await assert.rejects(
    fixture.contexts.open({ path: project, mode: "worktree" }),
    (error: unknown) => contextErrorCode(error) === "RESOURCE_QUOTA_EXCEEDED",
  );
  const closed = await fixture.contexts.close(opened.contextId);
  assert.equal((closed.worktree as { removed: boolean }).removed, true);
  await assert.rejects(access(openedRoot));
});

test("context worktree byte quota removes the rejected checkout without recording it", async (t) => {
  const fixture = await createFixture(t, { maximumWorktreeBytes: 1 });
  const project = join(fixture.root, "byte-quota-project");
  await mkdir(project);
  await gitInit(project);

  await assert.rejects(
    fixture.contexts.open({ path: project, mode: "worktree" }),
    (error: unknown) => contextErrorCode(error) === "RESOURCE_QUOTA_EXCEEDED",
  );
  assert.equal(fixture.contexts.stats().contexts, 0);
  assert.equal(fixture.contexts.stats().managedWorktrees, 0);
  const worktreeList = await import("node:child_process").then(({ execFile }) =>
    import("node:util").then(({ promisify }) => promisify(execFile)(
      "git",
      ["worktree", "list", "--porcelain"],
      { cwd: project },
    )),
  );
  assert.equal(worktreeList.stdout.includes("v2-state/worktrees"), false);
});

test("context idle TTL removes ordinary contexts and clean managed worktrees", async (t) => {
  let now = 0;
  const fixture = await createFixture(t, {
    now: () => now,
    idleTtlMs: 1_000,
  });
  const project = join(fixture.root, "ttl-project");
  await mkdir(project);
  await gitInit(project);

  const ordinary = await fixture.contexts.open({ path: project });
  const worktree = await fixture.contexts.open({ path: project, mode: "worktree" });
  const worktreeRoot = worktree.root;
  assert.ok(worktreeRoot);
  now = 1_001;
  const cleanup = await fixture.contexts.cleanupExpired();

  assert.deepEqual(cleanup, {
    expired: 2,
    removed: 2,
    retained: 0,
    errors: 0,
    remaining: 0,
  });
  await assert.rejects(access(worktreeRoot));
  assert.equal(fixture.contexts.stats().contexts, 0);
  await assert.rejects(
    fixture.contexts.get(ordinary.contextId),
    (error: unknown) => error instanceof Error
      && "code" in error
      && error.code === "PRECONDITION_FAILED"
      && "evidence" in error
      && (error.evidence as { reasonCode?: string } | undefined)?.reasonCode === "RESOURCE_EXPIRED",
  );
  const stored = JSON.parse(await readFile(fixture.storePath, "utf8"));
  assert.deepEqual(stored.contexts, []);
});

test("context idle TTL retains dirty managed worktrees instead of evicting user work", async (t) => {
  let now = 0;
  const fixture = await createFixture(t, {
    now: () => now,
    idleTtlMs: 1_000,
  });
  const project = join(fixture.root, "ttl-dirty-project");
  await mkdir(project);
  await gitInit(project);
  const worktree = await fixture.contexts.open({ path: project, mode: "worktree" });
  const worktreeRoot = worktree.root;
  assert.ok(worktreeRoot);
  await writeFile(join(worktreeRoot, "README.md"), "dirty retained work\n");

  now = 1_001;
  const cleanup = await fixture.contexts.cleanupExpired();
  assert.deepEqual(cleanup, {
    expired: 1,
    removed: 0,
    retained: 1,
    errors: 0,
    remaining: 1,
  });
  await access(worktreeRoot);
  assert.equal(fixture.contexts.stats().managedWorktrees, 1);
});

interface Fixture {
  root: string;
  storePath: string;
  targets: TargetRegistry;
  contexts: ContextRegistry;
  serverConfig: ReturnType<typeof loadConfig>;
}

async function createFixture(
  t: test.TestContext,
  options: {
    maximumContexts?: number;
    maximumWorktrees?: number;
    maximumWorktreeBytes?: number;
    idleTtlMs?: number;
    now?: () => number;
  } = {},
): Promise<Fixture> {
  const root = await mkdtemp(join(tmpdir(), "devspace-v2-contexts-test-"));
  t.after(() => rm(root, { recursive: true, force: true }));
  const serverConfig = loadConfig({
    DEVSPACE_CONFIG_DIR: join(root, ".config"),
    DEVSPACE_ALLOWED_ROOTS: root,
    DEVSPACE_STATE_DIR: join(root, "legacy-state"),
    DEVSPACE_WORKTREE_ROOT: join(root, "worktrees"),
    DEVSPACE_OAUTH_OWNER_TOKEN: "v2-context-test-owner-credential-123456",
    DEVSPACE_PUBLIC_BASE_URL: "http://127.0.0.1:17676",
    DEVSPACE_LOG_LEVEL: "silent",
    DEVSPACE_SKILL_PATHS: join(root, "skills"),
  });
  const targets = new TargetRegistry({ configPath: join(root, "targets.json") });
  const storePath = join(root, "v2-state", "contexts.json");
  const contexts = new ContextRegistry({
    storePath,
    targets,
    serverConfig,
    now: options.now,
    maximumContexts: options.maximumContexts,
    idleTtlMs: options.idleTtlMs,
    worktreeRoot: join(root, "v2-state", "worktrees"),
    maximumWorktrees: options.maximumWorktrees,
    maximumWorktreeBytes: options.maximumWorktreeBytes,
  });
  return { root, storePath, targets, contexts, serverConfig };
}

async function gitInit(project: string): Promise<void> {
  const { execFile } = await import("node:child_process");
  const { promisify } = await import("node:util");
  const execute = promisify(execFile);
  await execute("git", ["init"], { cwd: project });
  await execute("git", ["config", "user.name", "DevSpace Test"], { cwd: project });
  await execute("git", ["config", "user.email", "devspace@example.com"], { cwd: project });
  await writeFile(join(project, "README.md"), "hello\n");
  await execute("git", ["add", "."], { cwd: project });
  await execute("git", ["commit", "-m", "Initial"], { cwd: project });
}
