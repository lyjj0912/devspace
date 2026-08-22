import assert from "node:assert/strict";
import { mkdtemp, realpath, rm, stat } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import Database from "better-sqlite3";
import { createCapabilityCallContextFromTrustedPrincipal } from "./capability-call-context.js";
import type { RuntimeIdentity } from "./contracts.js";
import { normalizeExecutionElevation } from "./elevation.js";
import { UniversalBrokerError } from "./errors.js";
import {
  createUserAuthorizationDescriptor,
  createUserAuthorizationReceipt,
  verifyUserAuthorizationDescriptor,
  verifyUserAuthorizationReceipt,
} from "./user-authorization.js";
import { UserAuthorizationStore } from "./user-authorization-store.js";

const PRINCIPAL = "a".repeat(64);
const TARGET_GENERATION = `sha256:${"b".repeat(64)}`;
const PROVIDER_GENERATION = `sha256:${"c".repeat(64)}`;
const BASE_TIME = Date.parse("2026-08-22T08:00:00.000Z");

const RUNTIME: RuntimeIdentity = {
  productVersion: "2.1.1",
  productProfile: "PERSONAL_DIRECT_OWNER",
  buildCapabilityDigest: `sha256:${"d".repeat(64)}`,
  resourceUriVersion: "v1",
  schemaGeneration: `sha256:${"e".repeat(64)}`,
  configDigest: `sha256:${"f".repeat(64)}`,
  sourceRevision: "1".repeat(40),
  runtimeRevision: "1".repeat(40),
  buildDigest: `sha256:${"0".repeat(64)}`,
  startedAt: "2026-08-22T07:55:00.000Z",
};

const ELEVATION = normalizeExecutionElevation({
  mode: "prompt",
  reason: "Capture bounded loopback packets for a task-owned fixture",
  scope: "operation",
  timeoutMs: 120_000,
}) as ReturnType<typeof normalizeExecutionElevation> & { mode: "prompt" };

test("authorization descriptors persist only digests and explicit IDs define cross-transport action identity", () => {
  const first = descriptor({
    operationId: "auth_op_1",
    explicitRequestId: "explicit-request-1",
    requestNamespace: "mcp-session:first",
    issuedAt: "2026-08-22T08:00:00.000Z",
    nonce: "nonce-first",
  });
  verifyUserAuthorizationDescriptor(first);
  const serialized = JSON.stringify(first);
  assert.doesNotMatch(serialized, /tcpdump|private-task-root|Capture bounded loopback packets/u);
  assert.match(first.action.commandDigest, /^sha256:[a-f0-9]{64}$/u);
  assert.match(first.action.cwdDigest, /^sha256:[a-f0-9]{64}$/u);
  assert.match(first.action.reasonDigest, /^sha256:[a-f0-9]{64}$/u);
  assert.match(String(first.explicitRequestKey), /^sha256:[a-f0-9]{64}$/u);

  const retryRuntime = { ...RUNTIME, startedAt: "2026-08-22T08:01:00.000Z" };
  const second = descriptor({
    operationId: "auth_op_2",
    explicitRequestId: "explicit-request-1",
    requestNamespace: "mcp-session:second",
    issuedAt: "2026-08-22T08:00:10.000Z",
    nonce: "nonce-second",
    runtimeIdentity: retryRuntime,
  });
  assert.equal(second.explicitRequestKey, first.explicitRequestKey);
  assert.equal(second.actionDigest, first.actionDigest);
  assert.notEqual(second.descriptorDigest, first.descriptorDigest);

  const changed = descriptor({
    operationId: "auth_op_3",
    explicitRequestId: "explicit-request-1",
    requestNamespace: "mcp-session:third",
    issuedAt: "2026-08-22T08:00:20.000Z",
    nonce: "nonce-third",
    command: "/usr/bin/id -a",
  });
  assert.notEqual(changed.actionDigest, first.actionDigest);

  const implicitFirst = descriptor({
    operationId: "auth_implicit_1",
    requestId: "1",
    requestNamespace: "mcp-session:implicit-first",
    issuedAt: "2026-08-22T08:00:30.000Z",
    nonce: "nonce-implicit-first",
  });
  const implicitSecond = descriptor({
    operationId: "auth_implicit_2",
    requestId: "1",
    requestNamespace: "mcp-session:implicit-second",
    issuedAt: "2026-08-22T08:00:31.000Z",
    nonce: "nonce-implicit-second",
  });
  assert.equal(implicitFirst.explicitRequestIdDigest, undefined);
  assert.equal(implicitFirst.explicitRequestKey, undefined);
  assert.equal(implicitSecond.explicitRequestKey, undefined);
  assert.notEqual(implicitFirst.actionDigest, implicitSecond.actionDigest);
});

test("authorization receipt is secret-free and bound to one exact descriptor", () => {
  const action = descriptor({
    operationId: "auth_receipt_1",
    explicitRequestId: "receipt-request-1",
    requestNamespace: "mcp-session:receipt",
    issuedAt: "2026-08-22T08:00:00.000Z",
    nonce: "nonce-receipt",
  });
  const receipt = createUserAuthorizationReceipt({
    descriptor: action,
    decision: "APPROVED",
    providerId: "macos-approval-agent",
    providerGeneration: PROVIDER_GENERATION,
    decidedAt: "2026-08-22T08:00:05.000Z",
    receiptId: "receipt-1",
    helperIdentityDigest: `sha256:${"9".repeat(64)}`,
    evidence: { nativePrompt: true, authorizationRight: "task-owned-test" },
  });
  verifyUserAuthorizationReceipt(receipt);
  assert.equal(receipt.descriptorDigest, action.descriptorDigest);
  assert.equal(receipt.actionDigest, action.actionDigest);
  assert.doesNotMatch(JSON.stringify(receipt), /tcpdump|private-task-root|Capture bounded/u);

  const tampered = { ...receipt, actionDigest: `sha256:${"8".repeat(64)}` };
  assert.throws(
    () => verifyUserAuthorizationReceipt(tampered),
    hasCode("STATE_CORRUPTED"),
  );
});

test("authorization store coalesces only explicit same-action requests and consumes approval once", async (t) => {
  const root = await realpath(await mkdtemp(join(tmpdir(), "devspace-user-authorization-store-")));
  t.after(() => rm(root, { recursive: true, force: true }));
  const path = join(root, "authorization.sqlite");
  let now = BASE_TIME;
  const store = new UserAuthorizationStore(path, () => now);
  t.after(() => store.close());

  const firstDescriptor = descriptor({
    operationId: "auth_store_1",
    explicitRequestId: "store-request-1",
    requestNamespace: "mcp-session:store-first",
    issuedAt: new Date(now).toISOString(),
    nonce: "nonce-store-first",
  });
  const first = store.prepare(firstDescriptor);
  assert.equal(first.reused, false);
  assert.equal(first.operation.state, "PENDING");

  const retryDescriptor = descriptor({
    operationId: "auth_store_retry",
    explicitRequestId: "store-request-1",
    requestNamespace: "mcp-session:store-second",
    issuedAt: new Date(now + 1_000).toISOString(),
    nonce: "nonce-store-second",
    runtimeIdentity: { ...RUNTIME, startedAt: "2026-08-22T08:00:30.000Z" },
  });
  const retry = store.prepare(retryDescriptor);
  assert.equal(retry.reused, true);
  assert.equal(retry.operation.operationId, firstDescriptor.authorizationOperationId);
  assert.equal(retry.operation.actionDigest, firstDescriptor.actionDigest);

  assert.throws(
    () => store.prepare(descriptor({
      operationId: "auth_store_conflict",
      explicitRequestId: "store-request-1",
      requestNamespace: "mcp-session:store-third",
      issuedAt: new Date(now + 2_000).toISOString(),
      nonce: "nonce-store-third",
      command: "/usr/bin/id -a",
    })),
    (error: unknown) => error instanceof UniversalBrokerError
      && error.code === "PRECONDITION_FAILED"
      && error.evidence?.providerDispatchCount === 0,
  );

  const implicitOne = store.prepare(descriptor({
    operationId: "auth_store_implicit_1",
    requestId: "1",
    requestNamespace: "mcp-session:implicit-one",
    issuedAt: new Date(now + 3_000).toISOString(),
    nonce: "nonce-store-implicit-one",
  }));
  const implicitTwo = store.prepare(descriptor({
    operationId: "auth_store_implicit_2",
    requestId: "1",
    requestNamespace: "mcp-session:implicit-two",
    issuedAt: new Date(now + 4_000).toISOString(),
    nonce: "nonce-store-implicit-two",
  }));
  assert.equal(implicitOne.reused, false);
  assert.equal(implicitTwo.reused, false);
  assert.notEqual(implicitOne.operation.operationId, implicitTwo.operation.operationId);

  now += 5_000;
  const receipt = createUserAuthorizationReceipt({
    descriptor: firstDescriptor,
    decision: "APPROVED",
    providerId: "macos-approval-agent",
    providerGeneration: PROVIDER_GENERATION,
    decidedAt: new Date(now).toISOString(),
    receiptId: "receipt-store-approved",
  });
  const approved = store.recordDecision(receipt);
  assert.equal(approved.state, "APPROVED");
  assert.equal(approved.receipt?.receiptDigest, receipt.receiptDigest);
  const consumed = store.consumeApprovedReceipt({
    operationId: firstDescriptor.authorizationOperationId,
    descriptorDigest: firstDescriptor.descriptorDigest,
    receiptDigest: receipt.receiptDigest,
  });
  assert.equal(consumed.state, "APPROVED");
  assert.equal(Number(consumed.receiptConsumedAt), now);
  assert.throws(
    () => store.consumeApprovedReceipt({
      operationId: firstDescriptor.authorizationOperationId,
      descriptorDigest: firstDescriptor.descriptorDigest,
      receiptDigest: receipt.receiptDigest,
    }),
    hasCode("PRECONDITION_FAILED"),
  );

  const deniedReceipt = createUserAuthorizationReceipt({
    descriptor: implicitOne.operation.descriptor,
    decision: "DENIED",
    providerId: "macos-approval-agent",
    providerGeneration: PROVIDER_GENERATION,
    decidedAt: new Date(now).toISOString(),
    receiptId: "receipt-store-denied",
  });
  assert.equal(store.recordDecision(deniedReceipt).state, "DENIED");
  assert.throws(
    () => store.consumeApprovedReceipt({
      operationId: implicitOne.operation.operationId,
      descriptorDigest: implicitOne.operation.descriptorDigest,
      receiptDigest: deniedReceipt.receiptDigest,
    }),
    hasCode("ELEVATION_DENIED"),
  );

  store.checkpoint();
  assert.equal((await stat(path)).mode & 0o777, 0o600);
  const database = new Database(path, { readonly: true });
  try {
    assert.equal(database.pragma("quick_check", { simple: true }), "ok");
    assert.equal((database.prepare("SELECT COUNT(*) AS count FROM user_authorization_operations").get() as { count: number }).count, 3);
    const persisted = database.prepare("SELECT descriptor_json AS descriptorJson FROM user_authorization_operations WHERE operation_id = ?")
      .get(firstDescriptor.authorizationOperationId) as { descriptorJson: string };
    assert.doesNotMatch(persisted.descriptorJson, /tcpdump|private-task-root|Capture bounded/u);
  } finally {
    database.close();
  }
});

test("authorization store expires pending work and survives reopening", async (t) => {
  const root = await realpath(await mkdtemp(join(tmpdir(), "devspace-user-authorization-expiry-")));
  t.after(() => rm(root, { recursive: true, force: true }));
  const path = join(root, "authorization.sqlite");
  let now = BASE_TIME;
  const pendingDescriptor = descriptor({
    operationId: "auth_expiry_1",
    explicitRequestId: "expiry-request-1",
    requestNamespace: "mcp-session:expiry",
    issuedAt: new Date(now).toISOString(),
    nonce: "nonce-expiry",
    timeoutMs: 1_000,
  });
  const first = new UserAuthorizationStore(path, () => now);
  first.prepare(pendingDescriptor);
  now += 1_001;
  assert.deepEqual(first.reconcile(), { expired: 1 });
  assert.equal(first.get(pendingDescriptor.authorizationOperationId)?.state, "EXPIRED");
  first.close();

  const reopened = new UserAuthorizationStore(path, () => now);
  try {
    assert.equal(reopened.get(pendingDescriptor.authorizationOperationId)?.state, "EXPIRED");
    assert.equal(reopened.stats().EXPIRED, 1);
  } finally {
    reopened.close();
  }
});

function descriptor(input: {
  operationId: string;
  requestId?: string;
  explicitRequestId?: string;
  requestNamespace: string;
  issuedAt: string;
  nonce: string;
  command?: string;
  timeoutMs?: number;
  runtimeIdentity?: RuntimeIdentity;
}) {
  const requestId = input.explicitRequestId ?? input.requestId;
  const context = createCapabilityCallContextFromTrustedPrincipal({
    principalKeyFingerprint: PRINCIPAL,
    ...(requestId ? { requestId } : {}),
    ...(input.explicitRequestId ? { explicitRequestId: input.explicitRequestId } : {}),
    requestNamespace: input.requestNamespace,
    receivedAt: input.issuedAt,
  });
  const elevation = input.timeoutMs === undefined
    ? ELEVATION
    : normalizeExecutionElevation({
      mode: "prompt",
      reason: "Capture bounded loopback packets for a task-owned fixture",
      timeoutMs: input.timeoutMs,
    }) as typeof ELEVATION;
  return createUserAuthorizationDescriptor({
    authorizationOperationId: input.operationId,
    callContext: context,
    target: {
      id: "local",
      generation: TARGET_GENERATION,
      transport: "local",
      platform: "macos",
    },
    runtimeIdentity: input.runtimeIdentity ?? RUNTIME,
    command: input.command ?? "/usr/sbin/tcpdump -i lo0 -c 20 port 18993",
    cwd: "/private/tmp/private-task-root",
    mode: "foreground",
    tty: false,
    elevation,
    issuedAt: input.issuedAt,
    nonce: input.nonce,
  });
}

function hasCode(expected: string): (error: unknown) => boolean {
  return (error: unknown) => error instanceof UniversalBrokerError && error.code === expected;
}
