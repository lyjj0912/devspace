import assert from "node:assert/strict";
import { spawn, type ChildProcessWithoutNullStreams } from "node:child_process";
import { once } from "node:events";
import { mkdtemp, realpath, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { createCapabilityCallContextFromTrustedPrincipal } from "./capability-call-context.js";
import type { RuntimeIdentity } from "./contracts.js";
import { normalizeExecutionElevation } from "./elevation.js";
import { UniversalBrokerError } from "./errors.js";
import {
  createUserAuthorizationReceipt,
  type UserAuthorizationProvider,
  type UserAuthorizationProviderCapability,
  type UserAuthorizationProviderLaunchRequest,
  type UserAuthorizationProviderRequest,
  type UserAuthorizationProviderDecision,
} from "./user-authorization.js";
import {
  type UserAuthorizationCoordinatorInput,
  UserAuthorizationCoordinator,
} from "./user-authorization-coordinator.js";
import { UserAuthorizationStore } from "./user-authorization-store.js";

const PRINCIPAL = "1".repeat(64);
const TARGET_GENERATION = `sha256:${"2".repeat(64)}`;
const PROVIDER_GENERATION = `sha256:${"3".repeat(64)}`;
const BASE_TIME = Date.parse("2030-01-01T00:00:00.000Z");

const RUNTIME: RuntimeIdentity = {
  productVersion: "2.1.1",
  productProfile: "PERSONAL_DIRECT_OWNER",
  buildCapabilityDigest: `sha256:${"4".repeat(64)}`,
  resourceUriVersion: "v1",
  schemaGeneration: `sha256:${"5".repeat(64)}`,
  configDigest: `sha256:${"6".repeat(64)}`,
  sourceRevision: "7".repeat(40),
  runtimeRevision: "7".repeat(40),
  buildDigest: `sha256:${"8".repeat(64)}`,
  startedAt: "2029-12-31T23:55:00.000Z",
};

const ELEVATION = normalizeExecutionElevation({
  mode: "prompt",
  reason: "Run a protected task-owned fixture",
  timeoutMs: 120_000,
}) as ReturnType<typeof normalizeExecutionElevation> & { mode: "prompt" };

test("coordinator prompts once, consumes one receipt, and refuses cross-transport replay after dispatch", async (t) => {
  const fixture = await createFixture(t);
  const firstInput = input({
    operationId: "coordinator_op_1",
    explicitRequestId: "coordinator-request-1",
    namespace: "mcp-session:first",
  });
  const first = await fixture.coordinator.authorizeAndLaunch(firstInput);
  assert.equal(first.reused, false);
  assert.equal(first.receipt.decision, "APPROVED");
  assert.equal(await childOutput(first.process), "AUTHORIZED_CLIENT_OK\n");
  assert.equal(fixture.provider.authorizeCalls, 1);
  assert.equal(fixture.provider.launchCalls, 1);
  assert.equal(fixture.store.get(firstInput.authorizationOperationId)?.receiptConsumedAt, BASE_TIME);

  await assert.rejects(
    fixture.coordinator.authorizeAndLaunch(input({
      operationId: "coordinator_op_retry",
      explicitRequestId: "coordinator-request-1",
      namespace: "mcp-session:second",
      runtimeIdentity: { ...RUNTIME, startedAt: "2030-01-01T00:00:30.000Z" },
    })),
    (error: unknown) => error instanceof UniversalBrokerError
      && error.code === "ELEVATION_RESULT_UNKNOWN"
      && error.evidence?.authorizationOperationId === firstInput.authorizationOperationId,
  );
  assert.equal(fixture.provider.authorizeCalls, 1);
  assert.equal(fixture.provider.launchCalls, 1);
});

test("coordinator coalesces a pending explicit request and rejects a changed action", async (t) => {
  let releaseAuthorization!: () => void;
  const authorizationGate = new Promise<void>((resolve) => { releaseAuthorization = resolve; });
  const fixture = await createFixture(t, { authorizationGate });
  const firstInput = input({
    operationId: "coordinator_pending_1",
    explicitRequestId: "pending-request-1",
    namespace: "mcp-session:pending-first",
  });
  const firstPromise = fixture.coordinator.authorizeAndLaunch(firstInput);
  await fixture.provider.authorizationStarted;

  await assert.rejects(
    fixture.coordinator.authorizeAndLaunch(input({
      operationId: "coordinator_pending_retry",
      explicitRequestId: "pending-request-1",
      namespace: "mcp-session:pending-second",
    })),
    (error: unknown) => error instanceof UniversalBrokerError
      && error.code === "RESOURCE_BUSY"
      && error.evidence?.authorizationOperationId === firstInput.authorizationOperationId,
  );
  await assert.rejects(
    fixture.coordinator.authorizeAndLaunch(input({
      operationId: "coordinator_pending_conflict",
      explicitRequestId: "pending-request-1",
      namespace: "mcp-session:pending-third",
      command: "/usr/bin/id -a",
    })),
    hasCode("PRECONDITION_FAILED"),
  );
  assert.equal(fixture.provider.authorizeCalls, 1);
  assert.equal(fixture.provider.launchCalls, 0);

  releaseAuthorization();
  const first = await firstPromise;
  assert.equal(await childOutput(first.process), "AUTHORIZED_CLIENT_OK\n");
  assert.equal(fixture.provider.launchCalls, 1);
});

test("implicit JSON-RPC IDs in separate sessions create independent authorization operations", async (t) => {
  const fixture = await createFixture(t);
  const first = await fixture.coordinator.authorizeAndLaunch(input({
    operationId: "coordinator_implicit_1",
    requestId: "1",
    namespace: "mcp-session:implicit-first",
  }));
  const firstOutput = childOutput(first.process);
  const second = await fixture.coordinator.authorizeAndLaunch(input({
    operationId: "coordinator_implicit_2",
    requestId: "1",
    namespace: "mcp-session:implicit-second",
  }));
  const secondOutput = childOutput(second.process);
  assert.equal(await firstOutput, "AUTHORIZED_CLIENT_OK\n");
  assert.equal(await secondOutput, "AUTHORIZED_CLIENT_OK\n");
  assert.equal(fixture.provider.authorizeCalls, 2);
  assert.equal(fixture.provider.launchCalls, 2);
  assert.equal(fixture.store.stats().APPROVED, 2);
});

test("denied authorization never launches a client", async (t) => {
  const fixture = await createFixture(t, { decision: "DENIED" });
  const request = input({
    operationId: "coordinator_denied_1",
    explicitRequestId: "denied-request-1",
    namespace: "mcp-session:denied",
  });
  await assert.rejects(
    fixture.coordinator.authorizeAndLaunch(request),
    hasCode("ELEVATION_DENIED"),
  );
  assert.equal(fixture.provider.authorizeCalls, 1);
  assert.equal(fixture.provider.launchCalls, 0);
  assert.equal(fixture.store.get(request.authorizationOperationId)?.state, "DENIED");
});

test("provider capability denial does not create a pending authorization record", async (t) => {
  const fixture = await createFixture(t, { available: false });
  const request = input({
    operationId: "coordinator_unavailable_1",
    explicitRequestId: "unavailable-request-1",
    namespace: "mcp-session:unavailable",
  });
  await assert.rejects(
    fixture.coordinator.authorizeAndLaunch(request),
    (error: unknown) => error instanceof UniversalBrokerError
      && error.code === "ELEVATION_UNAVAILABLE"
      && error.evidence?.providerDispatchCount === 0,
  );
  assert.equal(fixture.provider.authorizeCalls, 0);
  assert.equal(fixture.provider.launchCalls, 0);
  assert.equal(fixture.store.get(request.authorizationOperationId), undefined);
});

test("unknown provider decision and launch failure persist RESULT_UNKNOWN without retry", async (t) => {
  const decisionFixture = await createFixture(t, { authorizeThrows: true });
  const decisionRequest = input({
    operationId: "coordinator_decision_unknown",
    explicitRequestId: "decision-unknown-request",
    namespace: "mcp-session:decision-unknown",
  });
  await assert.rejects(
    decisionFixture.coordinator.authorizeAndLaunch(decisionRequest),
    hasCode("ELEVATION_RESULT_UNKNOWN"),
  );
  assert.equal(decisionFixture.store.get(decisionRequest.authorizationOperationId)?.state, "RESULT_UNKNOWN");
  assert.equal(decisionFixture.provider.launchCalls, 0);

  const launchFixture = await createFixture(t, { launchThrows: true });
  const launchRequest = input({
    operationId: "coordinator_launch_unknown",
    explicitRequestId: "launch-unknown-request",
    namespace: "mcp-session:launch-unknown",
  });
  await assert.rejects(
    launchFixture.coordinator.authorizeAndLaunch(launchRequest),
    (error: unknown) => error instanceof UniversalBrokerError
      && error.code === "ELEVATION_RESULT_UNKNOWN"
      && error.evidence?.providerDispatchCount === 1,
  );
  const unknown = launchFixture.store.get(launchRequest.authorizationOperationId);
  assert.equal(unknown?.state, "RESULT_UNKNOWN");
  assert.equal(typeof unknown?.receiptConsumedAt, "number");
  assert.equal(launchFixture.provider.launchCalls, 1);
});

async function createFixture(t: test.TestContext, options: FakeProviderOptions = {}) {
  const root = await realpath(await mkdtemp(join(tmpdir(), "devspace-user-authorization-coordinator-")));
  const store = new UserAuthorizationStore(join(root, "authorization.sqlite"), () => BASE_TIME);
  const provider = new FakeProvider(options);
  const coordinator = new UserAuthorizationCoordinator(store, provider);
  t.after(async () => {
    store.close();
    await rm(root, { recursive: true, force: true });
  });
  return { root, store, provider, coordinator };
}

interface FakeProviderOptions {
  available?: boolean;
  decision?: "APPROVED" | "DENIED" | "CANCELED" | "TIMED_OUT";
  authorizationGate?: Promise<void>;
  authorizeThrows?: boolean;
  launchThrows?: boolean;
}

class FakeProvider implements UserAuthorizationProvider {
  authorizeCalls = 0;
  launchCalls = 0;
  private authorizationStartedResolve!: () => void;
  readonly authorizationStarted = new Promise<void>((resolve) => {
    this.authorizationStartedResolve = resolve;
  });

  constructor(private readonly options: FakeProviderOptions) {}

  capability(): UserAuthorizationProviderCapability {
    return {
      available: this.options.available ?? true,
      providerId: "test-approval-provider",
      providerGeneration: PROVIDER_GENERATION,
      mechanism: "macos-authorization-services",
      ...((this.options.available ?? true) ? {} : { reason: "test provider unavailable" }),
    };
  }

  async authorize(request: UserAuthorizationProviderRequest): Promise<UserAuthorizationProviderDecision> {
    this.authorizeCalls += 1;
    this.authorizationStartedResolve();
    if (this.options.authorizationGate) await this.options.authorizationGate;
    if (this.options.authorizeThrows) throw new Error("simulated authorization transport loss");
    return {
      receipt: createUserAuthorizationReceipt({
        descriptor: request.descriptor,
        decision: this.options.decision ?? "APPROVED",
        providerId: "test-approval-provider",
        providerGeneration: PROVIDER_GENERATION,
        decidedAt: new Date(BASE_TIME).toISOString(),
        receiptId: `receipt-${request.descriptor.authorizationOperationId}`,
      }),
    };
  }

  async launch(_request: UserAuthorizationProviderLaunchRequest): Promise<ChildProcessWithoutNullStreams> {
    this.launchCalls += 1;
    if (this.options.launchThrows) throw new Error("simulated launch transport loss");
    return spawn(process.execPath, [
      "-e",
      "setTimeout(() => process.stdout.write('AUTHORIZED_CLIENT_OK\\n'), 10)",
    ], { stdio: ["pipe", "pipe", "pipe"] });
  }
}

function input(options: {
  operationId: string;
  requestId?: string;
  explicitRequestId?: string;
  namespace: string;
  command?: string;
  runtimeIdentity?: RuntimeIdentity;
}): UserAuthorizationCoordinatorInput {
  const requestId = options.explicitRequestId ?? options.requestId;
  return {
    authorizationOperationId: options.operationId,
    callContext: createCapabilityCallContextFromTrustedPrincipal({
      principalKeyFingerprint: PRINCIPAL,
      ...(requestId ? { requestId } : {}),
      ...(options.explicitRequestId ? { explicitRequestId: options.explicitRequestId } : {}),
      requestNamespace: options.namespace,
      receivedAt: new Date(BASE_TIME).toISOString(),
    }),
    target: {
      id: "local",
      generation: TARGET_GENERATION,
      transport: "local",
      platform: "macos",
    },
    runtimeIdentity: options.runtimeIdentity ?? RUNTIME,
    command: options.command ?? "/usr/bin/id",
    cwd: "/private/tmp/devspace-authorized-fixture",
    mode: "foreground",
    tty: false,
    elevation: ELEVATION,
    issuedAt: new Date(BASE_TIME).toISOString(),
    nonce: `nonce-${options.operationId}`,
  };
}

async function childOutput(child: ChildProcessWithoutNullStreams): Promise<string> {
  let output = "";
  child.stdout.setEncoding("utf8");
  child.stdout.on("data", (chunk: string) => { output += chunk; });
  const [code, signal] = await once(child, "exit") as [number | null, NodeJS.Signals | null];
  assert.equal(signal, null);
  assert.equal(code, 0);
  return output;
}

function hasCode(expected: string): (error: unknown) => boolean {
  return (error: unknown) => error instanceof UniversalBrokerError && error.code === expected;
}
