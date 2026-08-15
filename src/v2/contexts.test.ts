import assert from "node:assert/strict";
import { mkdir, mkdtemp, readFile, rm, stat, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { loadConfig } from "../config.js";
import { UNIVERSAL_BROKER_BUDGETS } from "./contracts.js";
import {
  ContextRegistry,
  contextErrorCode,
  contextPayloadCharacters,
} from "./contexts.js";
import { TargetRegistry } from "./targets.js";

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

interface Fixture {
  root: string;
  storePath: string;
  targets: TargetRegistry;
  contexts: ContextRegistry;
  serverConfig: ReturnType<typeof loadConfig>;
}

async function createFixture(t: test.TestContext): Promise<Fixture> {
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
