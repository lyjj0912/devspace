import assert from "node:assert/strict";
import { chmod, mkdir, mkdtemp, readdir, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test, { type TestContext } from "node:test";
import { loadConfig } from "../config.js";
import { createCapabilityCallContextFromTrustedPrincipal } from "./capability-call-context.js";
import { ContextRegistry } from "./contexts.js";
import { SignedSnapshotCursorStore } from "./cursor-capability.js";
import type {
  DurableProcessAdapter,
  DurableProcessEvents,
  DurableProcessHandle,
  DurableProcessIdentity,
} from "./durable-process-adapter.js";
import {
  BoundedInternalOneShotRunner,
  UniversalExecutionPlane,
} from "./execution.js";
import { UniversalBrokerError } from "./errors.js";
import { UniversalFilesystemService } from "./filesystem.js";
import {
  FileProcessStateStore,
  type PersistentProcessRecord,
  type ProcessStateStore,
  type WritableProcessRecord,
} from "./process-state.js";
import { TargetRegistry } from "./targets.js";

const owner = createCapabilityCallContextFromTrustedPrincipal({
  principalKeyFingerprint: "a".repeat(64),
});

test("personal recovery admits 1,000 terminal records, reattaches two running records, and permits cleanup plus new exec", async (t) => {
  const now = 1_800_000_000_000;
  const records = new Map<string, PersistentProcessRecord>();
  const fixture = await createRuntime(t, {
    now: () => now,
    maximumRetainedTerminalRecords: 1_000,
    maximumRunningTotal: 3,
    records,
    durableAdapter: new ReattachingAdapter(),
  });
  await mkdir(fixture.outputDir, { recursive: true });
  const retainedOutputPaths: string[] = [];
  for (let index = 0; index < 1_000; index += 1) {
    const record = processRecord(fixture.outputDir, `proc_terminal_${index}`, {
      state: "EXITED",
      startedAtMs: now - 20_000 + index,
      endedAtMs: now - 10_000 + index,
      exitCode: 0,
    });
    records.set(record.processId, record);
    retainedOutputPaths.push(record.outputPath);
  }
  await Promise.all(retainedOutputPaths.map((path) => writeFile(path, "", { mode: 0o600 })));
  for (let index = 0; index < 5; index += 1) {
    const record = processRecord(fixture.outputDir, `proc_expired_${index}`, {
      state: "EXITED",
      startedAtMs: now - 10_000_000 - index,
      endedAtMs: now - 9_000_000 - index,
      exitCode: 0,
    });
    records.set(record.processId, record);
  }
  for (let index = 0; index < 2; index += 1) {
    const identity = {
      managerHandle: `manager-${index}`,
      pid: 5_000 + index,
      startToken: `start-${index}`,
    };
    const record = processRecord(fixture.outputDir, `proc_running_${index}`, {
      state: "RUNNING",
      startedAtMs: now - 5_000,
      durable: true,
      durableIdentity: identity,
    });
    records.set(record.processId, record);
  }

  const listed = await fixture.execution.operate({ operation: "list", limit: 500 }, undefined, owner);
  assert.equal((listed.processes as unknown[]).length, 500);
  assert.equal(fixture.execution.stats().runningProcesses, 2);
  assert.equal(fixture.execution.stats().retainedTerminalRecords, 1_000);
  assert.deepEqual([...fixture.store.deleted].sort(), [
    "proc_expired_0",
    "proc_expired_1",
    "proc_expired_2",
    "proc_expired_3",
    "proc_expired_4",
  ]);

  await fixture.execution.operate({
    operation: "forget",
    processId: "proc_terminal_999",
  }, undefined, owner);
  const spawned = await fixture.execution.execute({
    target: "local",
    cwd: fixture.root,
    command: "printf personal-new-exec",
    mode: "foreground",
    yieldMs: 5_000,
  }, undefined, undefined, owner);
  assert.equal(spawned.state, "EXITED");
  assert.equal(spawned.output, "personal-new-exec");
});

test("a rejected recovery promise resets so a later recovery attempt can succeed", async (t) => {
  let attempts = 0;
  const stateStore: ProcessStateStore = {
    async loadAll() {
      attempts += 1;
      if (attempts === 1) throw new Error("first recovery failure");
      return [];
    },
    async save() {},
    async delete() {},
  };
  const fixture = await createRuntime(t, { processStateStore: stateStore });
  await assert.rejects(
    fixture.execution.operate({ operation: "list" }, undefined, owner),
    /first recovery failure/u,
  );
  const recovered = await fixture.execution.operate({ operation: "list" }, undefined, owner);
  assert.deepEqual(recovered.processes, []);
  assert.equal(attempts, 2);
});

test("internal one-shot helpers remain usable when user-process recovery is degraded and leave no managed record", async (t) => {
  const degradedStore: ProcessStateStore = {
    async loadAll() { throw new Error("user process registry unavailable"); },
    async save() { throw new Error("user process registry unavailable"); },
    async delete() { throw new Error("user process registry unavailable"); },
  };
  const fixture = await createRuntime(t, {
    maximumRunningTotal: 1,
    processStateStore: degradedStore,
  });
  const internal = new BoundedInternalOneShotRunner(fixture.execution, 2);
  const before = fixture.execution.stats();
  const result = await internal.run({
    target: "local",
    cwd: fixture.root,
    command: "printf internal-helper-ok",
    internalPolicy: "filesystem",
    timeoutMs: 5_000,
  }, owner);
  assert.equal(result.state, "EXITED");
  assert.equal(result.exitCode, 0);
  assert.equal(result.output, "internal-helper-ok");
  assert.deepEqual(fixture.execution.stats(), before);
  assert.deepEqual(internal.stats(), { active: 0, maximumConcurrent: 2, completed: 1 });
  const remoteFile = join(fixture.root, "remote-helper.txt");
  await writeFile(remoteFile, "remote-fs-ok", { mode: 0o600 });
  const filesystem = new UniversalFilesystemService(
    fixture.targets,
    fixture.contexts,
    internal,
    { sshControlDir: join(fixture.root, "fs-ssh-control") },
  );
  const remoteRead = await filesystem.execute({
    operation: "read",
    target: "fake-ssh",
    path: remoteFile,
  }, owner);
  assert.equal(remoteRead.content, "remote-fs-ok");
  assert.deepEqual(fixture.execution.stats(), before);
  await assert.rejects(
    fixture.execution.operate({ operation: "list" }, undefined, owner),
    /user process registry unavailable/u,
  );
});

test("file process-state recovery quarantines one malformed record and continues", async (t) => {
  const directory = await mkdtemp(join(tmpdir(), "devspace-process-quarantine-"));
  t.after(() => rm(directory, { recursive: true, force: true }));
  const store = new FileProcessStateStore(directory);
  await store.save(writableRecord(join(directory, "valid.log"), "proc_valid"));
  await writeFile(join(directory, "proc_corrupt.json"), "{not-json", { mode: 0o600 });
  const loaded = await store.loadAll();
  assert.deepEqual(loaded.map((record) => record.processId), ["proc_valid"]);
  const names = await readdir(directory);
  assert.equal(names.some((name) => name.startsWith("proc_corrupt.json.corrupt-")), true);
});

test("personal exec accepts composite local and SSH shell programs while retaining the no-elevation boundary", async (t) => {
  const fixture = await createRuntime(t);
  const composite = [
    "printf 'a\\nb\\n' | tail -n 1",
    "for value in one two; do printf '%s ' \"$value\"; done",
    "python3 - <<'PY'",
    "print('heredoc')",
    "PY",
    "sleep 0.01 & wait",
    "printf done",
  ].join("\n");
  for (const target of ["local", "fake-ssh"]) {
    const result = await fixture.execution.execute({
      target,
      cwd: fixture.root,
      command: composite,
      mode: "foreground",
      yieldMs: 5_000,
    }, undefined, undefined, owner);
    assert.equal(result.state, "EXITED");
    assert.equal(result.exitCode, 0);
    assert.match(result.output, /b\none two heredoc\ndone/u);
    await assert.rejects(
      fixture.execution.execute({
        target,
        cwd: fixture.root,
        command: "sudo -n true",
        mode: "foreground",
      }, undefined, undefined, owner),
      (error: unknown) => error instanceof UniversalBrokerError && error.code === "ELEVATION_BLOCKED",
    );
  }
});

interface RuntimeFixture {
  root: string;
  outputDir: string;
  execution: UniversalExecutionPlane;
  store: MemoryProcessStateStore;
  targets: TargetRegistry;
  contexts: ContextRegistry;
}

async function createRuntime(
  t: TestContext,
  options: {
    now?: () => number;
    maximumRetainedTerminalRecords?: number;
    maximumRunningTotal?: number;
    records?: Map<string, PersistentProcessRecord>;
    durableAdapter?: DurableProcessAdapter;
    processStateStore?: ProcessStateStore;
  } = {},
): Promise<RuntimeFixture> {
  const root = await mkdtemp(join(tmpdir(), "devspace-personal-process-"));
  const outputDir = join(root, "process-output");
  const targetConfigPath = join(root, "targets.json");
  const fakeBin = join(root, "fake-bin");
  const fakeSetpriv = join(fakeBin, "setpriv");
  await mkdir(fakeBin, { recursive: true });
  await writeFile(fakeSetpriv, [
    "#!/bin/sh",
    "[ \"$1\" = \"--no-new-privs\" ] || exit 64",
    "shift",
    "[ \"$1\" = \"--\" ] || exit 64",
    "shift",
    "exec \"$@\"",
    "",
  ].join("\n"));
  await chmod(fakeSetpriv, 0o700);
  const fakeSsh = join(root, "fake-ssh.sh");
  await writeFile(fakeSsh, [
    "#!/bin/sh",
    `PATH=${shellQuote(fakeBin)}:$PATH`,
    `DEVSPACE_TEST_SETPRIV=${shellQuote(fakeSetpriv)}`,
    "export PATH DEVSPACE_TEST_SETPRIV",
    "for last do :; done",
    "last=$(printf '%s' \"$last\" | sed \"s#/usr/bin/setpriv#$DEVSPACE_TEST_SETPRIV#g; s#/bin/setpriv#$DEVSPACE_TEST_SETPRIV#g\")",
    "exec /bin/sh -c \"$last\"",
    "",
  ].join("\n"));
  await chmod(fakeSsh, 0o700);
  await writeFile(targetConfigPath, JSON.stringify({
    version: 1,
    targets: {
      local: {
        displayName: "Local",
        aliases: ["local"],
        transport: "local",
        platform: "macos",
        shell: "zsh",
        defaultCwd: root,
        capabilities: { exec: true, durableProcess: true },
        durableProcess: { mode: "launchd" },
      },
      "fake-ssh": {
        displayName: "Fake SSH",
        aliases: ["fake-ssh"],
        transport: "ssh",
        sshHost: "fake-ssh",
        platform: "linux",
        shell: "sh",
        defaultCwd: root,
        capabilities: { exec: true },
      },
    },
  }));
  const base = loadConfig({
    DEVSPACE_CONFIG_DIR: join(root, "config"),
    DEVSPACE_ALLOWED_ROOTS: root,
    DEVSPACE_STATE_DIR: join(root, "legacy-state"),
    DEVSPACE_WORKTREE_ROOT: join(root, "worktrees"),
    DEVSPACE_OAUTH_OWNER_TOKEN: "personal-process-test-owner-token-123456789",
    DEVSPACE_PUBLIC_BASE_URL: "http://127.0.0.1:17676",
    DEVSPACE_LOG_LEVEL: "silent",
  });
  const targets = new TargetRegistry({
    configPath: targetConfigPath,
    sshExecutable: fakeSsh,
    sftpExecutable: "/usr/bin/true",
  });
  const contexts = new ContextRegistry({
    storePath: join(root, "contexts.json"),
    targets,
    serverConfig: base,
  });
  const store = new MemoryProcessStateStore(options.records);
  const execution = new UniversalExecutionPlane({
    targets,
    contexts,
    outputDir,
    sshControlDir: join(root, "ssh-control"),
    maxProcessRecords: options.maximumRetainedTerminalRecords ?? 10_000,
    maxRunningProcesses: options.maximumRunningTotal ?? 64,
    maxRunningProcessesPerTarget: options.maximumRunningTotal ?? 64,
    completedProcessTtlMs: 60 * 60_000,
    now: options.now,
    processStateStore: options.processStateStore ?? store,
    durableAdapter: options.durableAdapter,
    sshExecutable: fakeSsh,
    cursorStore: new SignedSnapshotCursorStore({
      currentKey: { keyId: "personal-process", secret: Buffer.alloc(32, 0x51) },
      ttlMs: 60_000,
      maximumSnapshotsPerPrincipal: 8,
    }),
  });
  t.after(async () => {
    await execution.close();
    await rm(root, { recursive: true, force: true });
  });
  return { root, outputDir, execution, store, targets, contexts };
}

class MemoryProcessStateStore implements ProcessStateStore {
  readonly records: Map<string, PersistentProcessRecord>;
  readonly deleted = new Set<string>();

  constructor(records = new Map<string, PersistentProcessRecord>()) {
    this.records = records;
  }

  async loadAll(): Promise<PersistentProcessRecord[]> {
    return [...this.records.values()];
  }

  async save(record: WritableProcessRecord): Promise<void> {
    this.records.set(record.processId, { schemaVersion: 1, ...record, checksum: "memory" });
  }

  async delete(processId: string): Promise<void> {
    this.records.delete(processId);
    this.deleted.add(processId);
  }
}

class ReattachingAdapter implements DurableProcessAdapter {
  async launch(): Promise<DurableProcessHandle> {
    throw new Error("fixture does not launch durable processes");
  }

  async reattach(
    identity: DurableProcessIdentity,
    _events: DurableProcessEvents,
  ): Promise<{ state: "RUNNING"; identity: DurableProcessIdentity; handle: DurableProcessHandle }> {
    return {
      state: "RUNNING",
      identity,
      handle: {
        identity,
        write() {},
        kill() {},
        close() {},
      },
    };
  }
}

function processRecord(
  outputDir: string,
  processId: string,
  overrides: Partial<PersistentProcessRecord>,
): PersistentProcessRecord {
  return {
    schemaVersion: 1,
    processId,
    principalKeyFingerprint: owner.principalKeyFingerprint,
    targetId: "local",
    targetGeneration: "sha256:" + "b".repeat(64),
    transport: "local",
    cwd: outputDir,
    tty: false,
    launchRisk: "R0",
    state: "EXITED",
    startedAtMs: 1_800_000_000_000,
    endedAtMs: 1_800_000_000_001,
    exitCode: 0,
    outputPath: join(outputDir, `${processId}.log`),
    durable: false,
    checksum: "memory",
    ...overrides,
  };
}

function writableRecord(outputPath: string, processId: string): WritableProcessRecord {
  return {
    processId,
    principalKeyFingerprint: owner.principalKeyFingerprint,
    targetId: "local",
    targetGeneration: "sha256:" + "c".repeat(64),
    transport: "local",
    cwd: tmpdir(),
    tty: false,
    launchRisk: "R0",
    state: "EXITED",
    startedAtMs: 1,
    endedAtMs: 2,
    exitCode: 0,
    outputPath,
    outputGeneration: "sha256:" + "d".repeat(64),
    outputIdentity: "sha256:" + "e".repeat(64),
    outputTruncated: false,
    outputBytes: 0,
    durable: false,
  };
}

function shellQuote(value: string): string {
  return `'${value.replaceAll("'", `'"'"'`)}'`;
}
