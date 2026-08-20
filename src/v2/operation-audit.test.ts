import assert from "node:assert/strict";
import { mkdtemp, mkdir, readFile, rm, stat, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import {
  OperationAuditSink,
  digestAuditIdentity,
  type OperationAuditInput,
} from "./operation-audit.js";

const PRINCIPAL = "a".repeat(64);
const RECEIPT = `sha256:${"b".repeat(64)}`;

test("operation audit appends owner-only hash-chained events with receipt linkage", async (t) => {
  const root = await temporaryRoot(t);
  const path = join(root, "audit", "operations.ndjson");
  const sink = new OperationAuditSink({ path });
  const first = auditInput("operation-1", {
    authorityId: "raw-authority-must-not-appear",
    taskInstanceId: "raw-task-must-not-appear",
    resourceKey: "/secret/path/must-not-appear",
    action: { command: "rm -rf /secret/path", token: "token-must-not-appear" },
    receiptDigest: RECEIPT,
  });
  const second = auditInput("operation-2");

  const firstAppend = sink.append(first);
  const secondAppend = sink.append(second);
  assert.deepEqual(sink.stats(), { pending: 2, initialized: false, failed: false });
  const [firstReceipt, secondReceipt] = await Promise.all([firstAppend, secondAppend]);
  assert.deepEqual(sink.stats(), { pending: 0, initialized: true, failed: false });
  await sink.close();

  assert.equal(firstReceipt.sequence, 1);
  assert.equal(firstReceipt.receiptDigest, RECEIPT);
  assert.match(firstReceipt.eventDigest, /^sha256:[a-f0-9]{64}$/u);
  assert.equal(secondReceipt.sequence, 2);
  const metadata = await stat(path);
  assert.equal(metadata.mode & 0o777, 0o600);

  const text = await readFile(path, "utf8");
  assert.equal(text.includes("raw-authority-must-not-appear"), false);
  assert.equal(text.includes("raw-task-must-not-appear"), false);
  assert.equal(text.includes("/secret/path/must-not-appear"), false);
  assert.equal(text.includes("token-must-not-appear"), false);
  const records = text.trim().split("\n").map((line) => JSON.parse(line)) as Array<Record<string, unknown>>;
  assert.equal(records.length, 2);
  assert.equal(records[0]?.principalFingerprintPrefix, PRINCIPAL.slice(0, 12));
  assert.equal(records[0]?.authorityIdDigest, digestAuditIdentity("raw-authority-must-not-appear"));
  assert.equal(records[0]?.receiptDigest, RECEIPT);
  assert.equal(records[1]?.previousEventDigest, records[0]?.eventDigest);
});

test("graceful close loses no accepted audit event", async (t) => {
  const root = await temporaryRoot(t);
  const path = join(root, "operations.ndjson");
  const sink = new OperationAuditSink({ path, maximumBatchSize: 64 });
  const writes = Array.from({ length: 50 }, (_, index) => sink.append(auditInput(`operation-${index}`)));
  await sink.close();
  const receipts = await Promise.all(writes);
  assert.equal(new Set(receipts.map((entry) => entry.eventDigest)).size, 50);
  assert.equal((await readFile(path, "utf8")).trim().split("\n").length, 50);
});

test("configured flush policy batches until its deterministic scheduler fires", async (t) => {
  const root = await temporaryRoot(t);
  const path = join(root, "operations.ndjson");
  let scheduled: (() => void) | undefined;
  let delayMs: number | undefined;
  const sink = new OperationAuditSink({
    path,
    flushIntervalMs: 250,
    scheduleFlush(callback, delay) {
      scheduled = callback;
      delayMs = delay;
      return () => { scheduled = undefined; };
    },
  });
  const append = sink.append(auditInput("operation-scheduled"));
  assert.equal(delayMs, 250);
  assert.equal(sink.stats().pending, 1);
  assert.equal(await fileExists(path), false);

  scheduled?.();
  const receipt = await append;
  assert.equal(receipt.sequence, 1);
  assert.deepEqual(sink.stats(), { pending: 0, initialized: true, failed: false });
  await sink.close();
});

test("reopen continues the durable chain and tampering fails closed", async (t) => {
  const root = await temporaryRoot(t);
  const path = join(root, "operations.ndjson");
  const first = new OperationAuditSink({ path });
  await first.append(auditInput("operation-before-reopen"));
  await first.close();

  const reopened = new OperationAuditSink({ path });
  const receipt = await reopened.append(auditInput("operation-after-reopen"));
  await reopened.close();
  assert.equal(receipt.sequence, 2);
  const records = (await readFile(path, "utf8")).trim().split("\n")
    .map((line) => JSON.parse(line)) as Array<Record<string, unknown>>;
  assert.equal(records[1]?.previousEventDigest, records[0]?.eventDigest);

  const tampered = (await readFile(path, "utf8")).replace('"result":"PASS"', '"result":"FAIL"');
  await writeFile(path, tampered, { mode: 0o600 });
  const rejected = await new OperationAuditSink({ path }).record(auditInput("operation-after-tamper"));
  assert.equal(rejected.status, "SINK_FAILED");
  assert.match(rejected.error ?? "", /digest is invalid/u);
});

test("record reports sink failure without replacing the mutation result", async (t) => {
  const root = await temporaryRoot(t);
  const invalidPath = join(root, "is-a-directory");
  await mkdir(invalidPath);
  const sink = new OperationAuditSink({ path: invalidPath });
  const mutationResult = { changed: true, value: 17 };

  const auditResult = await sink.record(auditInput("operation-failure"));
  assert.equal(auditResult.status, "SINK_FAILED");
  assert.match(auditResult.error ?? "", /directory|EISDIR|operation not permitted/iu);
  assert.deepEqual(sink.stats(), { pending: 0, initialized: false, failed: true });
  assert.deepEqual(mutationResult, { changed: true, value: 17 });
});

function auditInput(
  operationId: string,
  overrides: Partial<OperationAuditInput> = {},
): OperationAuditInput {
  return {
    timestamp: "2026-08-20T00:00:00.000Z",
    operationId,
    correlationId: `correlation-${operationId}`,
    principalFingerprint: PRINCIPAL,
    targetId: "local",
    targetGeneration: `sha256:${"1".repeat(64)}`,
    tool: "fs",
    operation: "write",
    risk: "R1",
    claimState: "CLAIMED",
    dispatchState: "COMPLETED",
    result: "PASS",
    ...overrides,
  };
}

async function temporaryRoot(t: test.TestContext): Promise<string> {
  const root = await mkdtemp(join(tmpdir(), "devspace-operation-audit-"));
  t.after(() => rm(root, { recursive: true, force: true }));
  return root;
}

async function fileExists(path: string): Promise<boolean> {
  try {
    await stat(path);
    return true;
  } catch (error) {
    return Boolean(error && typeof error === "object" && "code" in error && error.code !== "ENOENT");
  }
}
