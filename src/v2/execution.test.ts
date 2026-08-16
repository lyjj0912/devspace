import assert from "node:assert/strict";
import {
  chmod,
  mkdir,
  mkdtemp,
  realpath,
  rm,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test, { type TestContext } from "node:test";
import { loadConfig } from "../config.js";
import { ContextRegistry } from "./contexts.js";
import {
  UniversalExecutionPlane,
  type UniversalProcessSnapshot,
} from "./execution.js";
import { UniversalBrokerError } from "./errors.js";
import { TargetRegistry } from "./targets.js";

test("exec auto returns a completed local result and preserves resource output", async (t) => {
  const fixture = await createFixture(t);
  const result = await fixture.execution.execute({
    target: "local",
    cwd: fixture.root,
    command: "printf 'hello-v2'",
    mode: "auto",
    yieldMs: 2_000,
  });

  assert.equal(result.state, "EXITED");
  assert.equal(result.exitCode, 0);
  assert.equal(result.output, "hello-v2");
  const resource = await fixture.execution.readOutput(result.processId, 0, 1_024);
  assert.equal(resource.text, "hello-v2");
  assert.equal(resource.nextOffset, undefined);
});

test("exec background converts to a managed process and process wait returns output", async (t) => {
  const fixture = await createFixture(t);
  const started = await fixture.execution.execute({
    cwd: fixture.root,
    command: "sleep 0.15; printf 'background-complete'",
    mode: "background",
  });
  assert.equal(started.state, "RUNNING");

  const completed = await fixture.execution.operate({
    operation: "wait",
    processId: started.processId,
    waitMs: 2_000,
  }) as UniversalProcessSnapshot;
  assert.equal(completed.state, "EXITED");
  assert.equal(completed.exitCode, 0);
  assert.match(completed.output, /background-complete/);
});

test("process write, resize validation, and signal use one generic lifecycle", async (t) => {
  const fixture = await createFixture(t);
  const input = await fixture.execution.execute({
    cwd: fixture.root,
    command: "IFS= read -r line; printf 'received:%s\\n' \"$line\"",
    mode: "background",
  });
  const written = await fixture.execution.operate({
    operation: "write",
    processId: input.processId,
    chars: "value-42\n",
    waitMs: 2_000,
  }) as UniversalProcessSnapshot;
  assert.equal(written.state, "EXITED");
  assert.match(written.output, /received:value-42/);

  const sleeping = await fixture.execution.execute({
    cwd: fixture.root,
    command: "sleep 30",
    mode: "background",
  });
  await assert.rejects(
    fixture.execution.operate({
      operation: "resize",
      processId: sleeping.processId,
      columns: 100,
      rows: 40,
    }),
    (error: unknown) => brokerCode(error) === "PRECONDITION_FAILED",
  );
  const signalled = await fixture.execution.operate({
    operation: "signal",
    processId: sleeping.processId,
    signal: "SIGTERM",
    waitMs: 2_000,
  }) as UniversalProcessSnapshot;
  assert.equal(signalled.state, "SIGNALED");
  assert.equal(signalled.signal, "SIGTERM");
});

test("PTY execution accepts stdin and resize", async (t) => {
  const fixture = await createFixture(t);
  const started = await fixture.execution.execute({
    cwd: fixture.root,
    command: "read line; printf 'pty:%s\\n' \"$line\"",
    tty: true,
    mode: "background",
  });
  const resized = await fixture.execution.operate({
    operation: "resize",
    processId: started.processId,
    columns: 100,
    rows: 40,
  }) as UniversalProcessSnapshot;
  assert.equal(resized.state, "RUNNING");
  const completed = await fixture.execution.operate({
    operation: "write",
    processId: started.processId,
    chars: "interactive\r",
    waitMs: 2_000,
  }) as UniversalProcessSnapshot;
  assert.equal(completed.state, "EXITED");
  assert.match(completed.output, /pty:interactive/);
});

test("context supplies target and cwd without becoming an authority boundary", async (t) => {
  const fixture = await createFixture(t);
  const project = join(fixture.root, "project");
  await mkdir(project);
  const context = await fixture.contexts.open({ path: project });
  const result = await fixture.execution.execute({
    contextId: context.contextId,
    command: "pwd -P",
    yieldMs: 2_000,
  });
  assert.equal(result.state, "EXITED");
  assert.equal(result.output.trim(), await realpath(project));

  await assert.rejects(
    fixture.execution.execute({
      contextId: context.contextId,
      target: "fake",
      command: "true",
    }),
    (error: unknown) => brokerCode(error) === "PRECONDITION_FAILED",
  );
});

test("running-process quotas fail before spawning another command", async (t) => {
  const fixture = await createFixture(t, { maxRunningProcesses: 1 });
  const first = await fixture.execution.execute({
    cwd: fixture.root,
    command: "sleep 30",
    mode: "background",
  });
  await assert.rejects(
    fixture.execution.execute({
      cwd: fixture.root,
      command: "sleep 30",
      mode: "background",
    }),
    (error: unknown) => brokerCode(error) === "RESOURCE_QUOTA_EXCEEDED",
  );
  await fixture.execution.operate({
    operation: "signal",
    processId: first.processId,
    signal: "SIGTERM",
    waitMs: 2_000,
  });
});

test("bounded model output retains full process output as a resource", async (t) => {
  const fixture = await createFixture(t, {
    processBufferCharacters: 100,
  });
  const result = await fixture.execution.execute({
    cwd: fixture.root,
    command: "python3 - <<'PY'\nprint('x' * 5000, end='')\nPY",
    yieldMs: 2_000,
    maxOutputChars: 80,
  });
  assert.equal(result.state, "EXITED");
  assert.equal(result.outputTruncated, true);
  assert.ok(result.output.length <= 200);
  const resource = await fixture.execution.readOutput(result.processId, 0, 6_000);
  assert.equal(resource.text.length, 5_000);
  assert.equal(resource.text, "x".repeat(5_000));
});

test("environment-profile requests fail explicitly when unavailable", async (t) => {
  const fixture = await createFixture(t);
  await assert.rejects(
    fixture.execution.execute({
      target: "local",
      cwd: fixture.root,
      command: "true",
      envProfile: "secret-profile",
    }),
    (error: unknown) => brokerCode(error) === "CAPABILITY_UNAVAILABLE",
  );
});

test("exec does not inherit service credentials into child processes", async (t) => {
  const fixture = await createFixture(t);
  const previousOwner = process.env.DEVSPACE_OAUTH_OWNER_TOKEN;
  const previousApiKey = process.env.OPENAI_API_KEY;
  process.env.DEVSPACE_OAUTH_OWNER_TOKEN = "must-not-reach-child";
  process.env.OPENAI_API_KEY = "must-not-reach-child";
  try {
    const result = await fixture.execution.execute({
      cwd: fixture.root,
      command: "printf 'owner=%s api=%s path=%s' \"${DEVSPACE_OAUTH_OWNER_TOKEN-unset}\" \"${OPENAI_API_KEY-unset}\" \"${PATH:+present}\"",
      yieldMs: 2_000,
    });
    assert.equal(result.state, "EXITED");
    assert.equal(result.output, "owner=unset api=unset path=present");
  } finally {
    restoreEnvironment("DEVSPACE_OAUTH_OWNER_TOKEN", previousOwner);
    restoreEnvironment("OPENAI_API_KEY", previousApiKey);
  }
});

test("SSH execution strips dispatch markers and preserves the remote exit code", async (t) => {
  const fixture = await createFixture(t);
  const result = await fixture.execution.execute({
    target: "fake",
    cwd: fixture.root,
    command: "printf 'remote-output'; exit 7",
    yieldMs: 2_000,
  });
  assert.equal(result.state, "EXITED");
  assert.equal(result.exitCode, 7);
  assert.equal(result.output, "remote-output");
});

test("SSH failures distinguish pre-dispatch failure from post-dispatch unknown state", async (t) => {
  const fixture = await createFixture(t);
  await assert.rejects(
    fixture.execution.execute({
      target: "offline",
      cwd: fixture.root,
      command: "true",
      yieldMs: 2_000,
    }),
    (error: unknown) => brokerCode(error) === "TRANSPORT_UNAVAILABLE",
  );
  await assert.rejects(
    fixture.execution.execute({
      target: "unknown",
      cwd: fixture.root,
      command: "touch must-not-be-retried",
      yieldMs: 2_000,
    }),
    (error: unknown) => brokerCode(error) === "EXECUTION_STATE_UNKNOWN",
  );
});

test("remote cwd failures are classified before dispatch", async (t) => {
  const fixture = await createFixture(t);
  await assert.rejects(
    fixture.execution.execute({
      target: "fake",
      cwd: join(fixture.root, "missing"),
      command: "true",
      yieldMs: 2_000,
    }),
    (error: unknown) => brokerCode(error) === "PATH_NOT_FOUND",
  );
});

interface Fixture {
  root: string;
  targets: TargetRegistry;
  contexts: ContextRegistry;
  execution: UniversalExecutionPlane;
}

async function createFixture(
  t: TestContext,
  overrides: Partial<{
    maxRunningProcesses: number;
    processBufferCharacters: number;
  }> = {},
): Promise<Fixture> {
  const root = await mkdtemp(join(tmpdir(), "devspace-v2-exec-test-"));
  t.after(async () => {
    await fixtureExecution?.close();
    await rm(root, { recursive: true, force: true });
  });
  const targetsPath = join(root, "targets.json");
  const fakeSsh = join(root, "fake-ssh.sh");
  await writeFile(fakeSsh, [
    "#!/bin/sh",
    "all=\" $* \"",
    "for last do :; done",
    "case \"$all\" in",
    "  *' offline '*) exit 255 ;;",
    "  *' unknown '*)",
    "    marker=$(printf '%s' \"$last\" | grep -o '__DEVSPACE_DISPATCHED_[A-Za-z0-9]*__' | head -1)",
    "    printf '%s\\n' \"$marker\" >&2",
    "    exit 255",
    "    ;;",
    "esac",
    "exec /bin/sh -c \"$last\"",
    "",
  ].join("\n"));
  await chmod(fakeSsh, 0o700);
  await writeFile(targetsPath, JSON.stringify({
    version: 1,
    targets: {
      local: {
        displayName: "Local",
        aliases: ["local"],
        transport: "local",
        platform: "macos",
        shell: "zsh",
      },
      fake: sshTarget("fake"),
      offline: sshTarget("offline"),
      unknown: sshTarget("unknown"),
    },
  }, null, 2));
  const serverConfig = loadConfig({
    DEVSPACE_CONFIG_DIR: join(root, ".config"),
    DEVSPACE_ALLOWED_ROOTS: root,
    DEVSPACE_STATE_DIR: join(root, "legacy-state"),
    DEVSPACE_WORKTREE_ROOT: join(root, "worktrees"),
    DEVSPACE_OAUTH_OWNER_TOKEN: "phase3-test-owner-credential-123456789",
    DEVSPACE_PUBLIC_BASE_URL: "http://127.0.0.1:17676",
    DEVSPACE_LOG_LEVEL: "silent",
  });
  const targets = new TargetRegistry({ configPath: targetsPath });
  const contexts = new ContextRegistry({
    storePath: join(root, "v2-state", "contexts.json"),
    targets,
    serverConfig,
  });
  let fixtureExecution: UniversalExecutionPlane | undefined;
  fixtureExecution = new UniversalExecutionPlane({
    targets,
    contexts,
    outputDir: join(root, "v2-state", "process-output"),
    sshControlDir: join(root, "v2-state", "ssh-control"),
    maxRunningProcesses: overrides.maxRunningProcesses ?? 32,
    maxRunningProcessesPerTarget: 16,
    processBufferCharacters: overrides.processBufferCharacters ?? 1_000_000,
    processOutputMaxBytes: 10_000_000,
    completedProcessTtlMs: 60_000,
    sshExecutable: fakeSsh,
  });
  return { root, targets, contexts, execution: fixtureExecution };
}

function sshTarget(sshHost: string) {
  return {
    displayName: sshHost,
    aliases: [sshHost],
    transport: "ssh",
    sshHost,
    platform: "linux",
    shell: "sh",
  };
}

function brokerCode(error: unknown): string | undefined {
  return error instanceof UniversalBrokerError ? error.code : undefined;
}

function restoreEnvironment(name: string, value: string | undefined): void {
  if (value === undefined) delete process.env[name];
  else process.env[name] = value;
}
