import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import {
  copyFile,
  lstat,
  mkdir,
  mkdtemp,
  readFile,
  rm,
  symlink,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { promisify } from "node:util";
import { loadConfig } from "../config.js";
import { ContextRegistry } from "./contexts.js";
import type {
  UniversalExecutionPlane,
  UniversalProcessSnapshot,
} from "./execution.js";
import { UniversalFilesystemService } from "./filesystem.js";
import { TargetRegistry } from "./targets.js";

const execFileAsync = promisify(execFile);

test("fs performs a complete local lifecycle without a workspace boundary", async (t) => {
  const fixture = await createFixture(t);
  const directory = join(fixture.root, "storage");
  const source = join(directory, "source.txt");
  const copy = join(directory, "copy.txt");
  const moved = join(directory, "moved.txt");

  await fixture.filesystem.execute({
    operation: "mkdir",
    path: directory,
  });
  const written = await fixture.filesystem.execute({
    operation: "write",
    path: source,
    content: "alpha\nbeta\n",
  });
  assert.equal(written.path, source);
  assert.equal(typeof written.sha256, "string");

  const read = await fixture.filesystem.execute({ operation: "read", path: source });
  assert.equal(read.encoding, "utf8");
  assert.equal(read.content, "alpha\nbeta\n");

  const hash = await fixture.filesystem.execute({ operation: "hash", path: source });
  assert.equal(hash.sha256, written.sha256);
  await fixture.filesystem.execute({
    operation: "copy",
    path: source,
    destination: copy,
  });
  await fixture.filesystem.execute({
    operation: "move",
    path: copy,
    destination: moved,
  });
  assert.equal(await readFile(moved, "utf8"), "alpha\nbeta\n");

  const listed = await fixture.filesystem.execute({
    operation: "list",
    path: directory,
    limit: 1,
  });
  assert.equal((listed.entries as unknown[]).length, 1);
  assert.equal(typeof listed.nextCursor, "string");

  await fixture.filesystem.execute({
    operation: "remove",
    path: moved,
    disposition: "permanent",
  });
  await fixture.filesystem.execute({
    operation: "remove",
    path: source,
    disposition: "permanent",
  });
  await fixture.filesystem.execute({
    operation: "remove",
    path: directory,
    disposition: "permanent",
    recursive: true,
  });
  await assert.rejects(lstat(directory));
});

test("context supplies only target and relative path defaults", async (t) => {
  const fixture = await createFixture(t);
  const project = join(fixture.root, "project");
  await mkdir(project);
  const context = await fixture.contexts.open({ path: project });

  await fixture.filesystem.execute({
    operation: "write",
    contextId: context.contextId,
    path: "nested.txt",
    content: "context-relative\n",
  });
  assert.equal(await readFile(join(project, "nested.txt"), "utf8"), "context-relative\n");

  await fixture.filesystem.execute({
    operation: "write",
    contextId: context.contextId,
    path: join(fixture.root, "outside-context.txt"),
    content: "absolute-authority\n",
  });
  assert.equal(
    await readFile(join(fixture.root, "outside-context.txt"), "utf8"),
    "absolute-authority\n",
  );
});

test("fs patch uses the shared Codex patch engine with a hash precondition", async (t) => {
  const fixture = await createFixture(t);
  const path = join(fixture.root, "note.txt");
  const written = await fixture.filesystem.execute({
    operation: "write",
    path,
    content: "first\nsecond\n",
  });
  const patched = await fixture.filesystem.execute({
    operation: "patch",
    path,
    expectedSha256: String(written.sha256),
    patch: [
      "*** Begin Patch",
      "*** Update File: note.txt",
      "@@",
      " first",
      "-second",
      "+changed",
      "*** End Patch",
    ].join("\n"),
  });
  assert.equal(patched.patched, true);
  assert.equal(await readFile(path, "utf8"), "first\nchanged\n");

  await assert.rejects(
    fixture.filesystem.execute({
      operation: "patch",
      path,
      expectedSha256: "0".repeat(64),
      patch: [
        "*** Begin Patch",
        "*** Update File: note.txt",
        "@@",
        "-changed",
        "+wrong",
        "*** End Patch",
      ].join("\n"),
    }),
    hasCode("PRECONDITION_FAILED"),
  );
});

test("fs bounds read and search output and never publishes through a symlink", async (t) => {
  const fixture = await createFixture(t);
  const root = join(fixture.root, "search");
  await mkdir(root);
  await writeFile(join(root, "one.txt"), "needle one\nother\nneedle two\n");
  await writeFile(join(root, "two.txt"), "needle three\n");
  const target = join(root, "target.txt");
  const link = join(root, "link.txt");
  await writeFile(target, "preserve\n");
  await symlink(target, link);

  const read = await fixture.filesystem.execute({
    operation: "read",
    path: join(root, "one.txt"),
    limit: 6,
  });
  assert.equal(read.content, "needle");
  assert.equal(read.truncated, true);
  assert.equal(read.nextCursor, "6");

  const search = await fixture.filesystem.execute({
    operation: "search",
    path: root,
    query: "needle",
    limit: 2,
  });
  assert.equal((search.results as unknown[]).length, 2);
  assert.equal(search.truncated, true);

  await assert.rejects(
    fixture.filesystem.execute({
      operation: "write",
      path: link,
      content: "replace\n",
      overwrite: true,
    }),
    hasCode("PERMISSION_DENIED"),
  );
  assert.equal(await readFile(target, "utf8"), "preserve\n");
  await assert.rejects(
    fixture.filesystem.execute({ operation: "remove", path: target }),
    hasCode("PRECONDITION_FAILED"),
  );
});

test("remote POSIX fs uses framed helper execution and SFTP atomic publication", async (t) => {
  const fixture = await createRemoteFixture(t);
  const remoteRoot = join(fixture.root, "remote");
  await mkdir(remoteRoot);
  const path = join(remoteRoot, "remote.txt");
  const copy = join(remoteRoot, "copy.txt");
  const moved = join(remoteRoot, "moved.txt");
  const content = `${"large-content-".repeat(8_000)}\n`;

  const written = await fixture.filesystem.execute({
    operation: "write",
    target: "remote",
    path,
    content,
  });
  assert.equal(written.path, path);
  assert.equal(await readFile(path, "utf8"), content);
  assert.ok(fixture.sftpPuts > 0, "large remote content must use SFTP staging");

  const read = await fixture.filesystem.execute({
    operation: "read",
    target: "remote",
    path,
    limit: 32,
  });
  assert.equal(read.content, content.slice(0, 32));
  assert.equal(read.truncated, true);

  await fixture.filesystem.execute({
    operation: "copy",
    target: "remote",
    path,
    destination: copy,
  });
  await fixture.filesystem.execute({
    operation: "move",
    target: "remote",
    path: copy,
    destination: moved,
  });
  assert.equal(await readFile(moved, "utf8"), content);

  await fixture.filesystem.execute({
    operation: "remove",
    target: "remote",
    path: moved,
    disposition: "permanent",
  });
  await fixture.filesystem.execute({
    operation: "remove",
    target: "remote",
    path,
    disposition: "permanent",
  });
  assert.ok(fixture.executionCalls >= 7);
});

test("remote file patch rechecks the original hash before atomic publication", async (t) => {
  const fixture = await createRemoteFixture(t);
  const remoteRoot = join(fixture.root, "remote-patch");
  await mkdir(remoteRoot);
  const path = join(remoteRoot, "remote.txt");
  await writeFile(path, "before\n");
  const hash = await fixture.filesystem.execute({
    operation: "hash",
    target: "remote",
    path,
  });
  const result = await fixture.filesystem.execute({
    operation: "patch",
    target: "remote",
    path,
    expectedSha256: String(hash.sha256),
    patch: [
      "*** Begin Patch",
      "*** Update File: remote.txt",
      "@@",
      "-before",
      "+after",
      "*** End Patch",
    ].join("\n"),
  });
  assert.equal(result.patched, true);
  assert.equal(await readFile(path, "utf8"), "after\n");
  assert.ok(fixture.sftpGets > 0);
  assert.ok(fixture.sftpPuts > 0);
});

interface Fixture {
  root: string;
  targets: TargetRegistry;
  contexts: ContextRegistry;
  filesystem: UniversalFilesystemService;
}

interface RemoteFixture extends Fixture {
  executionCalls: number;
  sftpPuts: number;
  sftpGets: number;
}

async function createFixture(t: test.TestContext): Promise<Fixture> {
  const root = await mkdtemp(join(tmpdir(), "devspace-v2-fs-test-"));
  t.after(() => rm(root, { recursive: true, force: true }));
  const serverConfig = loadConfig({
    DEVSPACE_CONFIG_DIR: join(root, ".config"),
    DEVSPACE_ALLOWED_ROOTS: root,
    DEVSPACE_STATE_DIR: join(root, "legacy-state"),
    DEVSPACE_WORKTREE_ROOT: join(root, "worktrees"),
    DEVSPACE_OAUTH_OWNER_TOKEN: "v2-filesystem-test-owner-credential-123456",
    DEVSPACE_PUBLIC_BASE_URL: "http://127.0.0.1:17676",
    DEVSPACE_LOG_LEVEL: "silent",
    DEVSPACE_SKILL_PATHS: join(root, "skills"),
  });
  const targets = new TargetRegistry({ configPath: join(root, "targets.json") });
  const contexts = new ContextRegistry({
    storePath: join(root, "v2-state", "contexts.json"),
    targets,
    serverConfig,
  });
  const filesystem = new UniversalFilesystemService(
    targets,
    contexts,
    {} as UniversalExecutionPlane,
    { sshControlDir: join(root, "ssh-control") },
  );
  return { root, targets, contexts, filesystem };
}

async function createRemoteFixture(t: test.TestContext): Promise<RemoteFixture> {
  const root = await mkdtemp(join(tmpdir(), "devspace-v2-fs-remote-test-"));
  t.after(() => rm(root, { recursive: true, force: true }));
  const targetConfig = join(root, "targets.json");
  await writeFile(targetConfig, JSON.stringify({
    version: 1,
    targets: {
      remote: {
        displayName: "Remote fixture",
        aliases: ["remote"],
        transport: "ssh",
        sshHost: "fixture.invalid",
        platform: "linux",
        defaultCwd: root,
        privilege: { user: true, admin: { mode: "unavailable" } },
      },
    },
  }));
  const serverConfig = loadConfig({
    DEVSPACE_CONFIG_DIR: join(root, ".config"),
    DEVSPACE_ALLOWED_ROOTS: root,
    DEVSPACE_STATE_DIR: join(root, "legacy-state"),
    DEVSPACE_WORKTREE_ROOT: join(root, "worktrees"),
    DEVSPACE_OAUTH_OWNER_TOKEN: "v2-filesystem-remote-owner-credential-123456",
    DEVSPACE_PUBLIC_BASE_URL: "http://127.0.0.1:17676",
    DEVSPACE_LOG_LEVEL: "silent",
    DEVSPACE_SKILL_PATHS: join(root, "skills"),
  });
  const targets = new TargetRegistry({ configPath: targetConfig });
  const contexts = new ContextRegistry({
    storePath: join(root, "v2-state", "contexts.json"),
    targets,
    serverConfig,
  });
  let executionCalls = 0;
  const execution = {
    async execute(input: { command: string }): Promise<UniversalProcessSnapshot> {
      executionCalls += 1;
      const started = Date.now();
      try {
        const result = await execFileAsync("/bin/sh", ["-lc", input.command], {
          maxBuffer: 2 * 1024 * 1024,
        });
        return processSnapshot(result.stdout, 0, started);
      } catch (error) {
        const failure = error as Error & { stdout?: string; stderr?: string; code?: number };
        return processSnapshot(
          `${failure.stdout ?? ""}${failure.stderr ?? ""}`,
          typeof failure.code === "number" ? failure.code : 1,
          started,
        );
      }
    },
    async operate(): Promise<Record<string, unknown>> {
      throw new Error("The fixture helper completes synchronously.");
    },
  } as unknown as UniversalExecutionPlane;
  let sftpPuts = 0;
  let sftpGets = 0;
  const filesystem = new UniversalFilesystemService(
    targets,
    contexts,
    execution,
    {
      sshControlDir: join(root, "ssh-control"),
      sftpPut: async ({ localPath, remotePath }) => {
        sftpPuts += 1;
        await copyFile(localPath, remotePath);
      },
      sftpGet: async ({ localPath, remotePath }) => {
        sftpGets += 1;
        await copyFile(remotePath, localPath);
      },
    },
  );
  return {
    root,
    targets,
    contexts,
    filesystem,
    get executionCalls() { return executionCalls; },
    get sftpPuts() { return sftpPuts; },
    get sftpGets() { return sftpGets; },
  };
}

function processSnapshot(
  output: string,
  exitCode: number,
  startedAt: number,
): UniversalProcessSnapshot {
  return {
    processId: "proc_fixture",
    targetId: "remote",
    transport: "ssh",
    cwd: "/",
    privilege: "user",
    tty: false,
    state: "EXITED",
    startedAt: new Date(startedAt).toISOString(),
    endedAt: new Date().toISOString(),
    wallTimeMs: Date.now() - startedAt,
    output,
    outputTruncated: false,
    outputBytes: Buffer.byteLength(output),
    outputFileTruncated: false,
    resourceUri: "devspace://process/proc_fixture/output/0/1048576",
    exitCode,
  };
}

function hasCode(code: string): (error: unknown) => boolean {
  return (error: unknown) => error instanceof Error
    && "code" in error
    && error.code === code;
}
