import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { createHash } from "node:crypto";
import {
  copyFile,
  lstat,
  mkdir,
  mkdtemp,
  readdir,
  readFile,
  rename,
  rm,
  stat,
  symlink,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { promisify } from "node:util";
import { loadConfig } from "../config.js";
import { ContextRegistry } from "./contexts.js";
import {
  createCapabilityCallContextFromTrustedPrincipal,
  type CapabilityCallContext,
} from "./capability-call-context.js";
import type {
  UniversalExecutionPlane,
  UniversalProcessSnapshot,
} from "./execution.js";
import { UniversalBrokerError } from "./errors.js";
import {
  UniversalFilesystemService,
} from "./filesystem.js";
import {
  atomicCopyFile,
  atomicWriteBuffer,
  safeMoveFile,
} from "./filesystem-atomic.js";
import {
  REMOTE_WINDOWS_FILESYSTEM_RESULT_MARKER,
  windowsFilesystemCommand,
} from "./remote-windows-filesystem-helper.js";
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
  const trashed = await fixture.filesystem.execute({ operation: "remove", path: target });
  assert.equal(trashed.disposition, "trash");
  assert.equal(trashed.recoverable, true);
  await fixture.filesystem.execute({
    operation: "restore",
    trashId: String(trashed.trashId),
  });
  assert.equal(await readFile(target, "utf8"), "preserve\n");
});

test("atomic publication rejects a deterministic destination race and preserves the racer", async (t) => {
  const root = await mkdtemp(join(tmpdir(), "devspace-v2-fs-race-test-"));
  t.after(() => rm(root, { recursive: true, force: true }));
  const destination = join(root, "destination.txt");
  await writeFile(destination, "preimage\n");
  await assert.rejects(
    atomicWriteBuffer(destination, Buffer.from("ours\n"), {
      overwrite: true,
      hooks: {
        beforeDestinationRevalidation: async () => {
          await writeFile(destination, "racer\n");
        },
      },
    }),
    hasCode("PRECONDITION_FAILED"),
  );
  assert.equal(await readFile(destination, "utf8"), "racer\n");
  assert.equal(
    (await readdir(root)).some((name) => name.startsWith(".devspace-v2-")),
    false,
  );
});

test("verified EXDEV fallback never deletes the source after destination corruption", async (t) => {
  const root = await mkdtemp(join(tmpdir(), "devspace-v2-fs-exdev-test-"));
  t.after(() => rm(root, { recursive: true, force: true }));
  const source = join(root, "source.txt");
  const destination = join(root, "destination.txt");
  await writeFile(source, "source-must-survive\n");
  await assert.rejects(
    safeMoveFile(source, destination, {
      overwrite: false,
      hooks: {
        forceCrossDevice: true,
        afterCrossDevicePublication: async () => {
          await writeFile(destination, "corrupt-after-copy\n");
        },
      },
    }),
    hasCode("PRECONDITION_FAILED"),
  );
  assert.equal(await readFile(source, "utf8"), "source-must-survive\n");
  assert.equal(await readFile(destination, "utf8"), "corrupt-after-copy\n");
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
  assert.equal(fixture.forgottenProcesses, fixture.executionCalls);
});

test("remote filesystem helper processes preserve the authenticated owner context", async (t) => {
  const fixture = await createRemoteFixture(t);
  const path = join(fixture.root, "owner-context.txt");
  await writeFile(path, "owner-context\n");
  const callContext = createCapabilityCallContextFromTrustedPrincipal({
    principalKeyFingerprint: "a".repeat(64),
  });
  await fixture.filesystem.execute({
    operation: "hash",
    target: "remote",
    path,
  }, callContext);
  assert.ok(fixture.processCallContexts.length >= 2);
  assert.ok(fixture.processCallContexts.every((observed) => observed === callContext));
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

test("fresh cached SFTP denial fails before transfer dispatch", async (t) => {
  const fixture = await createRemoteFixture(t, { sftpAvailable: false });
  const path = join(fixture.root, "must-not-publish.txt");
  await assert.rejects(
    fixture.filesystem.execute({
      operation: "write",
      target: "remote",
      path,
      content: `${"blocked".repeat(12_000)}\n`,
      overwrite: false,
    }),
    (error: unknown) => error instanceof UniversalBrokerError
      && error.code === "CAPABILITY_UNAVAILABLE",
  );
  assert.equal(fixture.executionCalls, 0);
  assert.equal(fixture.sftpPuts, 0);
  await assert.rejects(readFile(path, "utf8"), { code: "ENOENT" });
});

test("remote Windows fs uses PowerShell framing and SFTP atomic publication", async (t) => {
  const fixture = await createWindowsRemoteFixture(t);
  const directory = "C:/Users/Test/DevSpace/storage";
  const path = `${directory}/remote.txt`;
  const copied = `${directory}/copied.txt`;
  const moved = `${directory}/moved.txt`;
  const content = `${"windows-large-content-".repeat(5_000)}\n`;

  await fixture.filesystem.execute({
    operation: "mkdir",
    target: "windows",
    path: directory,
    recursive: true,
  });
  const written = await fixture.filesystem.execute({
    operation: "write",
    target: "windows",
    path,
    content,
  });
  assert.equal(written.path, path);
  assert.equal(written.size, Buffer.byteLength(content));
  assert.ok(fixture.sftpPuts > 0, "large Windows content must use SFTP staging");

  const read = await fixture.filesystem.execute({
    operation: "read",
    target: "windows",
    path,
    limit: 32,
  });
  assert.equal(read.content, content.slice(0, 32));
  assert.equal(read.truncated, true);

  const largeHash = await fixture.filesystem.execute({
    operation: "hash",
    target: "windows",
    path,
  });
  await fixture.filesystem.execute({
    operation: "write",
    target: "windows",
    path,
    content: "before\n",
    overwrite: true,
    expectedSha256: String(largeHash.sha256),
  });
  const original = await fixture.filesystem.execute({
    operation: "hash",
    target: "windows",
    path,
  });
  const patched = await fixture.filesystem.execute({
    operation: "patch",
    target: "windows",
    path,
    expectedSha256: String(original.sha256),
    patch: [
      "*** Begin Patch",
      "*** Update File: remote.txt",
      "@@",
      "-before",
      "+windows-patched",
      "*** End Patch",
    ].join("\n"),
  });
  assert.equal(patched.patched, true);
  assert.ok(fixture.sftpGets > 0);

  await fixture.filesystem.execute({
    operation: "copy",
    target: "windows",
    path,
    destination: copied,
  });
  await fixture.filesystem.execute({
    operation: "move",
    target: "windows",
    path: copied,
    destination: moved,
  });
  const searched = await fixture.filesystem.execute({
    operation: "search",
    target: "windows",
    path: directory,
    query: "windows-patched",
  });
  assert.ok((searched.results as Array<{ path?: string }>).some(
    (entry) => entry.path === path || entry.path === moved,
  ));

  const listed = await fixture.filesystem.execute({
    operation: "list",
    target: "windows",
    path: directory,
  });
  assert.equal((listed.entries as unknown[]).length, 2);

  for (const targetPath of [moved, path]) {
    await fixture.filesystem.execute({
      operation: "remove",
      target: "windows",
      path: targetPath,
      disposition: "permanent",
    });
  }
  await fixture.filesystem.execute({
    operation: "remove",
    target: "windows",
    path: directory,
    disposition: "permanent",
    recursive: true,
  });
  assert.ok(fixture.executionCalls >= 10);
  assert.equal(fixture.forgottenProcesses, fixture.executionCalls);

  const command = windowsFilesystemCommand(
    { op: "stat", path },
  );
  assert.match(command, /powershell\.exe/u);
  assert.match(command, /-EncodedCommand/u);
  assert.doesNotMatch(command, /windows-large-content/u);
});

interface Fixture {
  root: string;
  targets: TargetRegistry;
  contexts: ContextRegistry;
  filesystem: UniversalFilesystemService;
}

interface RemoteFixture extends Fixture {
  executionCalls: number;
  forgottenProcesses: number;
  sftpPuts: number;
  sftpGets: number;
  processCallContexts: Array<CapabilityCallContext | undefined>;
}

interface WindowsRemoteFixture extends RemoteFixture {}

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

async function createRemoteFixture(
  t: test.TestContext,
  options: { sftpAvailable?: boolean } = {},
): Promise<RemoteFixture> {
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
  const targets = new TargetRegistry({
    configPath: targetConfig,
    execute: (async (executable: string, args: string[]) => {
      if (executable === "sftp") {
        if (options.sftpAvailable === false) throw new Error("SFTP subsystem unavailable");
        return { stdout: "", stderr: "" };
      }
      if (args.includes("-tt")) return { stdout: "__DEVSPACE_PTY_OK__\r\n", stderr: "" };
      return {
        stdout: [
          "__DEVSPACE_TARGET_V1__",
          "kernel=Linux",
          "architecture=x86_64",
          `home=${root}`,
          `temporary=${root}`,
          "git=1",
          "rsync=0",
          "setpriv_boundary=1",
          "sandbox_boundary=0",
          "",
        ].join("\n"),
        stderr: "",
      };
    }) as never,
  });
  await targets.probe("remote");
  const contexts = new ContextRegistry({
    storePath: join(root, "v2-state", "contexts.json"),
    targets,
    serverConfig,
  });
  let executionCalls = 0;
  let forgottenProcesses = 0;
  const processCallContexts: Array<CapabilityCallContext | undefined> = [];
  const execution = {
    async execute(
      input: { command: string },
      _binding?: unknown,
      _dispatch?: unknown,
      callContext?: CapabilityCallContext,
    ): Promise<UniversalProcessSnapshot> {
      executionCalls += 1;
      processCallContexts.push(callContext);
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
    async operate(
      input: { operation: string },
      _dispatch?: unknown,
      callContext?: CapabilityCallContext,
    ): Promise<Record<string, unknown>> {
      assert.equal(input.operation, "forget");
      forgottenProcesses += 1;
      processCallContexts.push(callContext);
      return { forgotten: true };
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
    get forgottenProcesses() { return forgottenProcesses; },
    get sftpPuts() { return sftpPuts; },
    get sftpGets() { return sftpGets; },
    get processCallContexts() { return processCallContexts; },
  };
}

async function createWindowsRemoteFixture(
  t: test.TestContext,
): Promise<WindowsRemoteFixture> {
  const root = await mkdtemp(join(tmpdir(), "devspace-v2-fs-windows-test-"));
  t.after(() => rm(root, { recursive: true, force: true }));
  const targetConfig = join(root, "targets.json");
  await writeFile(targetConfig, JSON.stringify({
    version: 1,
    targets: {
      windows: {
        displayName: "Windows fixture",
        aliases: ["windows"],
        transport: "ssh",
        sshHost: "windows.invalid",
        platform: "windows",
        shell: "powershell",
        defaultCwd: "C:/Users/Test",
      },
    },
  }));
  const serverConfig = loadConfig({
    DEVSPACE_CONFIG_DIR: join(root, ".config"),
    DEVSPACE_ALLOWED_ROOTS: root,
    DEVSPACE_STATE_DIR: join(root, "legacy-state"),
    DEVSPACE_WORKTREE_ROOT: join(root, "worktrees"),
    DEVSPACE_OAUTH_OWNER_TOKEN: "v2-windows-fs-owner-credential-123456",
    DEVSPACE_PUBLIC_BASE_URL: "http://127.0.0.1:17676",
    DEVSPACE_LOG_LEVEL: "silent",
    DEVSPACE_SKILL_PATHS: join(root, "skills"),
  });
  const targets = new TargetRegistry({
    configPath: targetConfig,
    execute: (async (executable: string, args: string[]) => {
      if (executable === "sftp") return { stdout: "", stderr: "" };
      if (args.includes("-tt")) return { stdout: "__DEVSPACE_PTY_OK__\r\n", stderr: "" };
      return {
        stdout: [
          "__DEVSPACE_TARGET_V1__",
          "architecture=AMD64",
          "home=C:\\Users\\Test",
          "temporary=C:\\Users\\Test\\AppData\\Local\\Temp\\",
          "git=1",
          "elevated=0",
          "",
        ].join("\n"),
        stderr: "",
      };
    }) as never,
  });
  const contexts = new ContextRegistry({
    storePath: join(root, "v2-state", "contexts.json"),
    targets,
    serverConfig,
  });
  const driveRoot = join(root, "drive-c");
  await mkdir(join(driveRoot, "Users", "Test", "AppData", "Local", "Temp"), { recursive: true });
  let executionCalls = 0;
  let forgottenProcesses = 0;
  const processCallContexts: Array<CapabilityCallContext | undefined> = [];
  const execution = {
    async execute(
      input: { command: string },
      _binding?: unknown,
      _dispatch?: unknown,
      callContext?: CapabilityCallContext,
    ): Promise<UniversalProcessSnapshot> {
      executionCalls += 1;
      processCallContexts.push(callContext);
      const started = Date.now();
      const cleanupPath = input.command.match(/Remove-Item\s+-LiteralPath\s+'((?:''|[^'])+)'/u)?.[1]
        ?.replaceAll("''", "'");
      if (cleanupPath) {
        await rm(mapWindowsFixturePath(cleanupPath, driveRoot), { force: true });
        return processSnapshot("", 0, started);
      }
      let response: Record<string, unknown>;
      try {
        const remoteScript = input.command.match(/-File\s+'((?:''|[^'])+)'/u)?.[1]
          ?.replaceAll("''", "'");
        if (!remoteScript) throw new Error("Windows filesystem command is missing its staged script.");
        const source = await readFile(mapWindowsFixturePath(remoteScript, driveRoot), "utf8");
        const request = decodeWindowsScript(source);
        response = {
          ok: true,
          data: await executeFakeWindowsFilesystemRequest(request, driveRoot),
        };
      } catch (error) {
        response = {
          ok: false,
          code: error instanceof UniversalBrokerError ? error.code : "TRANSPORT_INTERRUPTED",
          message: error instanceof Error ? error.message : String(error),
        };
      }
      return processSnapshot(
        `${REMOTE_WINDOWS_FILESYSTEM_RESULT_MARKER}${JSON.stringify(response)}\n`,
        0,
        started,
      );
    },
    async operate(
      input: { operation: string },
      _dispatch?: unknown,
      callContext?: CapabilityCallContext,
    ): Promise<Record<string, unknown>> {
      assert.equal(input.operation, "forget");
      forgottenProcesses += 1;
      processCallContexts.push(callContext);
      return { forgotten: true };
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
        const mapped = mapWindowsFixturePath(remotePath, driveRoot);
        await mkdir(join(mapped, ".."), { recursive: true });
        await copyFile(localPath, mapped);
      },
      sftpGet: async ({ localPath, remotePath }) => {
        sftpGets += 1;
        await copyFile(mapWindowsFixturePath(remotePath, driveRoot), localPath);
      },
    },
  );
  return {
    root,
    targets,
    contexts,
    filesystem,
    get executionCalls() { return executionCalls; },
    get forgottenProcesses() { return forgottenProcesses; },
    get sftpPuts() { return sftpPuts; },
    get sftpGets() { return sftpGets; },
    get processCallContexts() { return processCallContexts; },
  };
}

function decodeWindowsScript(source: string): Record<string, unknown> {
  const requestBase64 = source.match(/\$RequestBase64\s*=\s*'([A-Za-z0-9+/]+={0,2})'/u)?.[1];
  if (!requestBase64) throw new Error("Windows filesystem command is missing its framed request.");
  return JSON.parse(Buffer.from(requestBase64, "base64").toString("utf8")) as Record<string, unknown>;
}

async function executeFakeWindowsFilesystemRequest(
  request: Record<string, unknown>,
  driveRoot: string,
): Promise<Record<string, unknown>> {
  const operation = String(request.op ?? "");
  const options = (request.options && typeof request.options === "object")
    ? request.options as Record<string, unknown>
    : {};
  const remotePath = typeof request.path === "string" ? request.path : undefined;
  const remoteDestination = typeof request.destination === "string"
    ? request.destination
    : undefined;
  const path = remotePath ? mapWindowsFixturePath(remotePath, driveRoot) : undefined;
  const destination = remoteDestination
    ? mapWindowsFixturePath(remoteDestination, driveRoot)
    : undefined;

  switch (operation) {
    case "stat": {
      const required = requireFixturePath(path, remotePath);
      const metadata = await stat(required).catch(() => undefined);
      if (!metadata) throw fixtureError("PATH_NOT_FOUND", `Path not found: ${remotePath}`);
      return {
        path: remotePath,
        type: metadata.isDirectory() ? "directory" : "file",
        size: metadata.isFile() ? metadata.size : 0,
        mode: 0,
        mtimeMs: metadata.mtimeMs,
        birthtimeMs: metadata.birthtimeMs,
      };
    }
    case "list": {
      const required = requireFixturePath(path, remotePath);
      const entries = (await readdir(required, { withFileTypes: true }))
        .sort((left, right) => left.name.localeCompare(right.name));
      const offset = Number(options.offset ?? 0);
      const limit = Number(options.limit ?? 100);
      const page = entries.slice(offset, offset + limit).map((entry) => ({
        name: entry.name,
        type: entry.isDirectory() ? "directory" : "file",
      }));
      return {
        path: remotePath,
        entries: page,
        totalEntries: entries.length,
        offset,
        limit,
        ...(offset + page.length < entries.length ? { nextOffset: offset + page.length } : {}),
      };
    }
    case "read": {
      const required = requireFixturePath(path, remotePath);
      const content = await readFile(required);
      const offset = Number(options.offset ?? 0);
      const maximum = Number(options.maxBytes ?? 12_000);
      const selected = content.subarray(offset, offset + maximum);
      const nextOffset = offset + selected.byteLength;
      return {
        path: remotePath,
        contentBase64: selected.toString("base64"),
        offset,
        bytesRead: selected.byteLength,
        size: content.byteLength,
        truncated: nextOffset < content.byteLength,
        ...(nextOffset < content.byteLength ? { nextOffset } : {}),
      };
    }
    case "search": {
      const required = requireFixturePath(path, remotePath);
      const query = String(request.query ?? "");
      const limit = Number(options.limit ?? 50);
      const entries = (await stat(required)).isDirectory()
        ? await readdir(required, { withFileTypes: true })
        : [];
      const candidates = entries.filter((entry) => entry.isFile()).map((entry) => entry.name);
      const results: Array<Record<string, unknown>> = [];
      for (const name of candidates) {
        const lines = (await readFile(join(required, name), "utf8")).split(/\r?\n/u);
        for (let index = 0; index < lines.length && results.length < limit; index += 1) {
          if (!lines[index]!.includes(query)) continue;
          results.push({
            path: `${remotePath!.replace(/[\\/]$/u, "")}/${name}`,
            line: index + 1,
            text: lines[index],
          });
        }
      }
      return { path: remotePath, query, results, visitedFiles: candidates.length, truncated: false };
    }
    case "hash": {
      const required = requireFixturePath(path, remotePath);
      const content = await readFile(required);
      return {
        path: remotePath,
        algorithm: "sha256",
        sha256: createHash("sha256").update(content).digest("hex"),
        size: content.byteLength,
      };
    }
    case "mkdir": {
      await mkdir(requireFixturePath(path, remotePath), { recursive: options.recursive === true });
      return { path: remotePath, created: true, mode: 0 };
    }
    case "write_content": {
      const required = requireFixturePath(path, remotePath);
      const existing = await fixtureExistingHash(required);
      verifyFixtureWrite(existing, options, remotePath!);
      await mkdir(join(required, ".."), { recursive: true });
      const bytes = Buffer.from(String(request.contentBase64 ?? ""), "base64");
      await writeFile(required, bytes);
      return fixturePublishedResult(remotePath!, required, existing !== undefined);
    }
    case "prepare_write": {
      const required = requireFixturePath(path, remotePath);
      const existing = await fixtureExistingHash(required);
      verifyFixtureWrite(existing, options, remotePath!);
      await mkdir(join(required, ".."), { recursive: true });
      return {
        path: remotePath,
        preimage: existing === undefined
          ? { exists: false }
          : { exists: true, type: "file", sha256: existing },
        mode: 0,
      };
    }
    case "publish_write": {
      const required = requireFixturePath(path, remotePath);
      const temporaryRemote = String(request.temporary ?? "");
      const temporary = mapWindowsFixturePath(temporaryRemote, driveRoot);
      const existing = await fixtureExistingHash(required);
      verifyFixtureWrite(existing, options, remotePath!);
      const expectedPreimage = request.preimage as { exists?: boolean; sha256?: string } | undefined;
      if (
        expectedPreimage?.exists !== (existing !== undefined)
        || (existing !== undefined && expectedPreimage.sha256 !== existing)
      ) {
        throw fixtureError("PRECONDITION_FAILED", `Destination preimage changed: ${remotePath}`);
      }
      const published = await atomicCopyFile(temporary, required, {
        overwrite: options.overwrite === true,
        expectedSha256: typeof options.expectedSha256 === "string"
          ? options.expectedSha256
          : undefined,
      });
      await rm(temporary, { force: true });
      return { ...published, path: remotePath };
    }
    case "cleanup": {
      const temporaryRemote = String(request.temporary ?? "");
      await rm(mapWindowsFixturePath(temporaryRemote, driveRoot), { recursive: true, force: true });
      return { path: temporaryRemote, removed: true };
    }
    case "copy":
    case "sync": {
      const required = requireFixturePath(path, remotePath);
      const requiredDestination = requireFixturePath(destination, remoteDestination);
      const existing = await stat(requiredDestination).catch(() => undefined);
      if (existing && options.overwrite !== true) {
        throw fixtureError("PRECONDITION_FAILED", `Destination exists: ${remoteDestination}`);
      }
      await mkdir(join(requiredDestination, ".."), { recursive: true });
      const published = await atomicCopyFile(required, requiredDestination, {
        overwrite: options.overwrite === true,
      });
      return {
        source: remotePath,
        destination: remoteDestination,
        copied: true,
        overwritten: Boolean(existing),
        size: published.size,
        sha256: published.sha256,
        ...(operation === "sync" ? { synchronized: true } : {}),
      };
    }
    case "move": {
      const required = requireFixturePath(path, remotePath);
      const requiredDestination = requireFixturePath(destination, remoteDestination);
      const existing = await stat(requiredDestination).catch(() => undefined);
      if (existing && options.overwrite !== true) {
        throw fixtureError("PRECONDITION_FAILED", `Destination exists: ${remoteDestination}`);
      }
      await mkdir(join(requiredDestination, ".."), { recursive: true });
      const published = await safeMoveFile(required, requiredDestination, {
        overwrite: options.overwrite === true,
      });
      return {
        source: remotePath,
        destination: remoteDestination,
        moved: true,
        crossDevice: published.crossDevice,
      };
    }
    case "remove": {
      const required = requireFixturePath(path, remotePath);
      await rm(required, { recursive: options.recursive === true, force: false });
      return { path: remotePath, removed: true, disposition: "permanent" };
    }
    default:
      throw fixtureError("PRECONDITION_FAILED", `Unsupported fixture operation: ${operation}`);
  }
}

function mapWindowsFixturePath(remotePath: string, driveRoot: string): string {
  const normalized = remotePath.replaceAll("\\", "/").replace(/^\/(?=[a-zA-Z]:\/)/u, "");
  const expanded = normalized === "~"
    ? "C:/Users/Test"
    : normalized.startsWith("~/")
      ? `C:/Users/Test/${normalized.slice(2)}`
      : normalized;
  const match = expanded.match(/^C:\/(.*)$/iu);
  if (!match) throw fixtureError("PRECONDITION_FAILED", `Unexpected Windows fixture path: ${remotePath}`);
  const segments = (match[1] ?? "").split("/").filter(Boolean);
  if (segments.some((segment) => segment === "..")) {
    throw fixtureError("PERMISSION_DENIED", `Windows fixture path escaped its drive: ${remotePath}`);
  }
  return join(driveRoot, ...segments);
}

function requireFixturePath(
  value: string | undefined,
  remote: string | undefined,
): string {
  if (!value || !remote) throw fixtureError("PRECONDITION_FAILED", "Fixture path is required.");
  return value;
}

async function fixtureExistingHash(path: string): Promise<string | undefined> {
  const metadata = await stat(path).catch(() => undefined);
  if (!metadata) return undefined;
  if (!metadata.isFile()) throw fixtureError("PATH_TYPE_MISMATCH", `Expected file: ${path}`);
  return createHash("sha256").update(await readFile(path)).digest("hex");
}

function verifyFixtureWrite(
  existingHash: string | undefined,
  options: Record<string, unknown>,
  path: string,
): void {
  if (existingHash && options.overwrite !== true) {
    throw fixtureError("PRECONDITION_FAILED", `Destination exists: ${path}`);
  }
  if (
    typeof options.expectedSha256 === "string"
    && options.expectedSha256.toLowerCase() !== existingHash
  ) {
    throw fixtureError("PRECONDITION_FAILED", `SHA-256 precondition failed: ${path}`);
  }
}

async function fixturePublishedResult(
  remotePath: string,
  localPath: string,
  overwritten: boolean,
): Promise<Record<string, unknown>> {
  const content = await readFile(localPath);
  return {
    path: remotePath,
    size: content.byteLength,
    mode: 0,
    sha256: createHash("sha256").update(content).digest("hex"),
    overwritten,
  };
}

function fixtureError(
  code: ConstructorParameters<typeof UniversalBrokerError>[0],
  message: string,
): UniversalBrokerError {
  return new UniversalBrokerError(code, message);
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
    tty: false,
    state: "EXITED",
    startedAt: new Date(startedAt).toISOString(),
    endedAt: new Date().toISOString(),
    wallTimeMs: Date.now() - startedAt,
    output,
    outputTruncated: false,
    outputBytes: Buffer.byteLength(output),
    outputFileTruncated: false,
    outputOffsets: {
      global: Buffer.byteLength(output),
      stdout: Buffer.byteLength(output),
      stderr: 0,
      pty: 0,
    },
    resourceUri: "devspace://process/proc_fixture/output/0/1048576",
    durable: false,
    exitCode,
  };
}

function hasCode(code: string): (error: unknown) => boolean {
  return (error: unknown) => error instanceof Error
    && "code" in error
    && error.code === code;
}
