import assert from "node:assert/strict";
import { spawn, type ChildProcessWithoutNullStreams } from "node:child_process";
import { mkdtemp, readFile, readdir, realpath, rm, stat, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { loadConfig } from "../config.js";
import { createCapabilityCallContextFromTrustedPrincipal } from "./capability-call-context.js";
import type { RuntimeIdentity } from "./contracts.js";
import { ContextRegistry } from "./contexts.js";
import {
  type ExecuteCommandInput,
  UniversalExecutionPlane,
} from "./execution.js";
import { UniversalBrokerError } from "./errors.js";
import {
  createUserAuthorizationReceipt,
  type UserAuthorizationProvider,
  type UserAuthorizationProviderCapability,
  type UserAuthorizationProviderDecision,
  type UserAuthorizationProviderLaunchRequest,
  type UserAuthorizationProviderRequest,
} from "./user-authorization.js";
import { UserAuthorizationStore } from "./user-authorization-store.js";
import { TargetRegistry } from "./targets.js";

const PRINCIPAL = "1".repeat(64);
const PROVIDER_GENERATION = `sha256:${"2".repeat(64)}`;
const RUNTIME: RuntimeIdentity = {
  productVersion: "2.1.1",
  productProfile: "PERSONAL_DIRECT_OWNER",
  buildCapabilityDigest: `sha256:${"3".repeat(64)}`,
  resourceUriVersion: "v1",
  schemaGeneration: `sha256:${"4".repeat(64)}`,
  configDigest: `sha256:${"5".repeat(64)}`,
  sourceRevision: "6".repeat(40),
  runtimeRevision: "6".repeat(40),
  buildDigest: `sha256:${"7".repeat(64)}`,
  startedAt: "2030-01-01T00:00:00.000Z",
};

test("prompt execution uses the authorized provider child and never invokes the ordinary spawn seam", async (t) => {
  const fixture = await createFixture(t);
  const result = await executePrompt(fixture, {
    command: "/usr/bin/id",
    mode: "foreground",
    requestId: "authorized-exec-1",
  });

  assert.equal(result.state, "EXITED");
  assert.equal(result.exitCode, 0);
  assert.equal(result.elevationMode, "prompt");
  assert.equal(result.authorizationState, "APPROVED");
  assert.equal(result.authorizationOperationId, result.processId);
  assert.match(String(result.authorizationActionDigest), /^sha256:[a-f0-9]{64}$/u);
  assert.match(String(result.authorizationDescriptorDigest), /^sha256:[a-f0-9]{64}$/u);
  assert.match(String(result.authorizationReceiptDigest), /^sha256:[a-f0-9]{64}$/u);
  assert.equal(result.authorizationProviderId, "test-execution-approval-provider");
  assert.equal(result.authorizationProviderGeneration, PROVIDER_GENERATION);
  assert.match(result.output, /AUTHORIZED_EXECUTION_CLIENT_OK/u);
  assert.equal(fixture.provider.authorizeCalls, 1);
  assert.equal(fixture.provider.launchCalls, 1);
  assert.equal(fixture.ordinarySpawnCalls(), 0);
  const stored = fixture.store.get(result.processId);
  assert.equal(stored?.state, "APPROVED");
  assert.equal(typeof stored?.receiptConsumedAt, "number");
  const persisted = await findPersistedProcessRecord(fixture.root, result.processId);
  assert.equal(persisted.elevationMode, "prompt");
  assert.equal(persisted.authorizationState, "APPROVED");
  assert.equal(persisted.authorizationOperationId, result.processId);
  assert.equal(persisted.authorizationActionDigest, result.authorizationActionDigest);
  assert.equal(persisted.authorizationDescriptorDigest, result.authorizationDescriptorDigest);
  assert.equal(persisted.authorizationReceiptDigest, result.authorizationReceiptDigest);
  assert.equal(persisted.authorizationProviderId, result.authorizationProviderId);
  assert.equal(persisted.authorizationProviderGeneration, result.authorizationProviderGeneration);
  assert.doesNotMatch(JSON.stringify(persisted), /Run a protected task-owned fixture/u);
});

test("background prompt exposes WAITING_AUTHORIZATION and transitions to the tracked child", async (t) => {
  let release!: () => void;
  const gate = new Promise<void>((resolve) => { release = resolve; });
  const fixture = await createFixture(t, { authorizationGate: gate });
  const initial = await executePrompt(fixture, {
    command: "/usr/bin/id",
    mode: "background",
    requestId: "authorized-background-1",
  });
  assert.equal(initial.state, "WAITING_AUTHORIZATION");
  assert.equal(initial.authorizationState, "PENDING");
  assert.equal(initial.authorizationOperationId, initial.processId);
  assert.equal(fixture.provider.launchCalls, 0);
  const pendingRecord = await findPersistedProcessRecord(fixture.root, initial.processId);
  assert.equal(pendingRecord.state, "WAITING_AUTHORIZATION");
  assert.equal(pendingRecord.authorizationState, "PENDING");
  assert.equal(pendingRecord.authorizationOperationId, initial.processId);

  release();
  const terminal = await waitForTerminal(fixture.execution, initial.processId);
  assert.equal(terminal.state, "EXITED");
  assert.equal(terminal.authorizationState, "APPROVED");
  assert.match(terminal.output, /AUTHORIZED_EXECUTION_CLIENT_OK/u);
  assert.equal(fixture.provider.authorizeCalls, 1);
  assert.equal(fixture.provider.launchCalls, 1);
  assert.equal(fixture.ordinarySpawnCalls(), 0);
});

test("denied prompt is terminal without launching either provider or ordinary command", async (t) => {
  const fixture = await createFixture(t, { decision: "DENIED" });
  let result;
  try {
    result = await executePrompt(fixture, {
      command: "/usr/bin/id",
      mode: "foreground",
      requestId: "authorized-denied-1",
    });
  } catch (error) {
    assert.equal(error instanceof UniversalBrokerError && error.code, "ELEVATION_DENIED");
  }
  if (result) {
    assert.equal(result.state, "FAILED");
    assert.equal(result.authorizationState, "DENIED");
    assert.equal(result.authorizationOperationId, result.processId);
    assert.match(String(result.authorizationActionDigest), /^sha256:[a-f0-9]{64}$/u);
    assert.match(String(result.authorizationDescriptorDigest), /^sha256:[a-f0-9]{64}$/u);
    assert.match(String(result.authorizationReceiptDigest), /^sha256:[a-f0-9]{64}$/u);
    assert.equal(result.errorCode, "ELEVATION_DENIED");
  }
  assert.equal(fixture.provider.authorizeCalls, 1);
  assert.equal(fixture.provider.launchCalls, 0);
  assert.equal(fixture.ordinarySpawnCalls(), 0);
});

test("provider launch loss becomes UNKNOWN and is never retried", async (t) => {
  const fixture = await createFixture(t, { launchThrows: true });
  let result;
  try {
    result = await executePrompt(fixture, {
      command: "/usr/bin/id",
      mode: "foreground",
      requestId: "authorized-unknown-1",
    });
  } catch (error) {
    assert.equal(error instanceof UniversalBrokerError && error.code, "ELEVATION_RESULT_UNKNOWN");
  }
  if (result) {
    assert.equal(result.state, "UNKNOWN");
    assert.equal(result.authorizationState, "RESULT_UNKNOWN");
    assert.equal(result.authorizationOperationId, result.processId);
    assert.match(String(result.authorizationActionDigest), /^sha256:[a-f0-9]{64}$/u);
    assert.match(String(result.authorizationReceiptDigest), /^sha256:[a-f0-9]{64}$/u);
    assert.equal(result.errorCode, "ELEVATION_RESULT_UNKNOWN");
  }
  assert.equal(fixture.provider.authorizeCalls, 1);
  assert.equal(fixture.provider.launchCalls, 1);
  assert.equal(fixture.ordinarySpawnCalls(), 0);
});

interface FixtureOptions {
  decision?: "APPROVED" | "DENIED";
  authorizationGate?: Promise<void>;
  launchThrows?: boolean;
}

async function createFixture(t: test.TestContext, options: FixtureOptions = {}) {
  const root = await realpath(await mkdtemp(join(tmpdir(), "devspace-execution-authorized-")));
  const targetsPath = join(root, "targets.json");
  await writeFile(targetsPath, JSON.stringify({
    version: 1,
    targets: {
      local: {
        displayName: "Local",
        aliases: ["local"],
        transport: "local",
        platform: "macos",
        shell: "zsh",
        defaultCwd: root,
        elevationPolicy: "prompt",
      },
    },
  }));
  const base = loadConfig({
    DEVSPACE_CONFIG_DIR: join(root, "config"),
    DEVSPACE_ALLOWED_ROOTS: root,
    DEVSPACE_STATE_DIR: join(root, "legacy-state"),
    DEVSPACE_WORKTREE_ROOT: join(root, "worktrees"),
    DEVSPACE_OAUTH_OWNER_TOKEN: "authorized-execution-test-token-1234567890",
    DEVSPACE_PUBLIC_BASE_URL: "http://127.0.0.1:17676",
    DEVSPACE_LOG_LEVEL: "silent",
  });
  const targets = new TargetRegistry({ configPath: targetsPath });
  const contexts = new ContextRegistry({
    storePath: join(root, "contexts.json"),
    targets,
    serverConfig: base,
  });
  const store = new UserAuthorizationStore(join(root, "authorization.sqlite"));
  const provider = new ExecutionAuthorizationProvider(options);
  let ordinarySpawnCalls = 0;
  const execution = new UniversalExecutionPlane({
    targets,
    contexts,
    outputDir: join(root, "process-output"),
    sshControlDir: join(root, "ssh-control"),
    maxProcessRecords: 100,
    maxRunningProcesses: 8,
    maxRunningProcessesPerTarget: 8,
    completedProcessTtlMs: 60_000,
    runtimeIdentity: RUNTIME,
    userAuthorizationStore: store,
    userAuthorizationProvider: provider,
    spawnProcess: (() => {
      ordinarySpawnCalls += 1;
      throw new Error("ordinary spawn must not execute a prompt-authorized request");
    }) as never,
  });
  t.after(async () => {
    await execution.close();
    contexts.closeResources();
    store.close();
    await rm(root, { recursive: true, force: true });
  });
  return {
    root,
    targets,
    execution,
    store,
    provider,
    ordinarySpawnCalls: () => ordinarySpawnCalls,
  };
}

class ExecutionAuthorizationProvider implements UserAuthorizationProvider {
  authorizeCalls = 0;
  launchCalls = 0;

  constructor(private readonly options: FixtureOptions) {}

  capability(): UserAuthorizationProviderCapability {
    return {
      available: true,
      providerId: "test-execution-approval-provider",
      providerGeneration: PROVIDER_GENERATION,
      mechanism: "macos-authorization-services",
    };
  }

  async authorize(request: UserAuthorizationProviderRequest): Promise<UserAuthorizationProviderDecision> {
    this.authorizeCalls += 1;
    if (this.options.authorizationGate) await this.options.authorizationGate;
    return {
      receipt: createUserAuthorizationReceipt({
        descriptor: request.descriptor,
        decision: this.options.decision ?? "APPROVED",
        providerId: "test-execution-approval-provider",
        providerGeneration: PROVIDER_GENERATION,
        receiptId: `receipt-${request.descriptor.authorizationOperationId}`,
      }),
    };
  }

  async launch(_request: UserAuthorizationProviderLaunchRequest): Promise<ChildProcessWithoutNullStreams> {
    this.launchCalls += 1;
    if (this.options.launchThrows) throw new Error("simulated provider launch loss");
    return spawn(process.execPath, [
      "-e",
      "setTimeout(() => process.stdout.write('AUTHORIZED_EXECUTION_CLIENT_OK\\n'), 10)",
    ], { stdio: ["pipe", "pipe", "pipe"] });
  }
}

async function executePrompt(
  fixture: Awaited<ReturnType<typeof createFixture>>,
  options: { command: string; mode: "foreground" | "background"; requestId: string },
) {
  const input: ExecuteCommandInput = {
    target: "local",
    cwd: fixture.root,
    command: options.command,
    mode: options.mode,
    yieldMs: 30_000,
    elevation: {
      mode: "prompt",
      reason: "Run a protected task-owned fixture",
      scope: "operation",
      timeoutMs: 120_000,
    },
  };
  const resolved = await fixture.targets.resolveWithGeneration("local");
  const binding = await fixture.execution.prepareExecutionBinding(
    input,
    resolved.target,
    resolved.generation,
  );
  return fixture.execution.execute(
    input,
    binding,
    undefined,
    createCapabilityCallContextFromTrustedPrincipal({
      principalKeyFingerprint: PRINCIPAL,
      requestId: options.requestId,
      explicitRequestId: options.requestId,
      requestNamespace: `mcp-session:${options.requestId}`,
      receivedAt: new Date().toISOString(),
    }),
  );
}

async function findPersistedProcessRecord(
  root: string,
  processId: string,
): Promise<Record<string, unknown>> {
  const candidates: string[] = [];
  async function visit(directory: string): Promise<void> {
    for (const entry of await readdir(directory, { withFileTypes: true })) {
      const path = join(directory, entry.name);
      if (entry.isDirectory()) await visit(path);
      else if (entry.isFile() && entry.name.endsWith(".json") && (await stat(path)).size <= 1_000_000) {
        candidates.push(path);
      }
    }
  }
  await visit(root);
  for (const path of candidates) {
    try {
      const value = JSON.parse(await readFile(path, "utf8")) as Record<string, unknown>;
      if (value.processId === processId) return value;
    } catch {
      // Non-process JSON is ignored.
    }
  }
  assert.fail(`persisted process record not found: ${processId}`);
}

async function waitForTerminal(execution: UniversalExecutionPlane, processId: string) {
  let output = "";
  for (let attempt = 0; attempt < 200; attempt += 1) {
    const snapshot = await execution.operate(
      { operation: "poll", processId },
      undefined,
      createCapabilityCallContextFromTrustedPrincipal({
        principalKeyFingerprint: PRINCIPAL,
      }),
    ) as import("./execution.js").UniversalProcessSnapshot;
    output += snapshot.output;
    if (!["STARTING", "WAITING_AUTHORIZATION", "RUNNING"].includes(snapshot.state)) {
      return { ...snapshot, output };
    }
    await new Promise((resolve) => setTimeout(resolve, 10));
  }
  assert.fail(`authorized process did not become terminal: ${processId}`);
}
