import assert from "node:assert/strict";
import { mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import Database from "better-sqlite3";
import {
  OperationAuthorityRegistry,
  actionFingerprint,
} from "./authority.js";
import {
  assertNoElevationCommand,
  authorityActionFromToolCall,
  commandRisk,
  mcpRisk,
  minimumAuthorityRisk,
} from "./authority-policy.js";
import { UniversalBrokerError } from "./errors.js";

function registry(
  now: { value: number } = { value: Date.now() },
  storePath?: string,
  instanceId?: string,
) {
  return new OperationAuthorityRegistry({
    now: () => now.value,
    minimumRisk: minimumAuthorityRisk,
    ...(storePath ? { storePath } : {}),
    ...(instanceId ? { instanceId } : {}),
  });
}

test("exact R1 authority is scope-bound, receipted, and bounded by uses", () => {
  const authority = registry();
  const descriptor = authorityActionFromToolCall("fs", {
    operation: "write",
    target: "local",
    path: "/tmp/example.txt",
    overwrite: true,
  });
  const created = authority.create({
    taskId: "write-example",
    authorityText: "Create or replace the exact example file.",
    actions: [{ descriptor, uses: 2 }],
  }, "client-a:session-a");
  const authorityId = String(created.authorityId);

  const first = authority.require(authorityId, "client-a:session-a", descriptor, "R1");
  assert.ok(first);
  authority.record(first, "PASS", { verified: true });
  const second = authority.require(authorityId, "client-a:session-a", descriptor, "R1");
  assert.ok(second);
  authority.record(second, "FAIL", { verified: false });

  assert.throws(
    () => authority.require(authorityId, "client-a:session-a", descriptor, "R1"),
    (error: unknown) => code(error) === "AUTHORITY_CONSUMED",
  );
  assert.throws(
    () => authority.status(authorityId, "client-b:session-b"),
    (error: unknown) => code(error) === "AUTHORITY_EXPIRED",
  );
  const status = authority.status(authorityId, "client-a:session-a");
  assert.equal((status.receipts as unknown[]).length, 2);
});

test("re-authorizing a consumed exact action creates a fresh authority", () => {
  const authority = registry();
  const descriptor = authorityActionFromToolCall("fs", {
    operation: "write",
    target: "local",
    contextId: "context-a",
    path: "example.txt",
    content: "first\n",
  });
  const input = {
    taskId: "repeat-write",
    authorityText: "Write the exact file again after the first authority is consumed.",
    actions: [{ descriptor }],
  };
  const first = authority.create(input, "client:session");
  const firstId = String(first.authorityId);
  const reusedBeforeUse = authority.create(input, "client:session");
  assert.equal(reusedBeforeUse.authorityId, firstId);
  assert.equal(reusedBeforeUse.reused, true);
  const grant = authority.require(firstId, "client:session", descriptor, "R1");
  authority.record(grant, "PASS");
  const second = authority.create(input, "client:session");
  assert.notEqual(second.authorityId, firstId);
  assert.equal(second.reused, false);
});

test("filesystem authority binds context identity and payload hashes", () => {
  const a = authorityActionFromToolCall("fs", {
    operation: "write",
    target: "local",
    contextId: "context-a",
    path: "same.txt",
    content: "alpha\n",
  });
  const b = authorityActionFromToolCall("fs", {
    operation: "write",
    target: "local",
    contextId: "context-b",
    path: "same.txt",
    content: "alpha\n",
  });
  const c = authorityActionFromToolCall("fs", {
    operation: "write",
    target: "local",
    contextId: "context-a",
    path: "same.txt",
    content: "beta\n",
  });
  assert.notEqual(actionFingerprint(a), actionFingerprint(b));
  assert.notEqual(actionFingerprint(a), actionFingerprint(c));
});

test("exact action fingerprints bind every mutation dispatch dimension", () => {
  const fsBase = authorityActionFromToolCall("fs", {
    operation: "write",
    target: "local",
    path: "/tmp/exact-a.txt",
    content: "alpha\n",
  });
  for (const changed of [
    authorityActionFromToolCall("fs", {
      operation: "write",
      target: "company",
      path: "/tmp/exact-a.txt",
      content: "alpha\n",
    }),
    authorityActionFromToolCall("fs", {
      operation: "write",
      target: "local",
      path: "/tmp/exact-b.txt",
      content: "alpha\n",
    }),
    authorityActionFromToolCall("fs", {
      operation: "write",
      target: "local",
      path: "/tmp/exact-a.txt",
      content: "beta\n",
    }),
  ]) {
    assert.notEqual(actionFingerprint(fsBase), actionFingerprint(changed));
  }

  const execBase = authorityActionFromToolCall("exec", {
    target: "local",
    cwd: "/tmp",
    command: "git push origin main",
    mode: "foreground",
  });
  const execChanged = authorityActionFromToolCall("exec", {
    target: "local",
    cwd: "/tmp",
    command: "git push origin release",
    mode: "foreground",
  });
  assert.notEqual(actionFingerprint(execBase), actionFingerprint(execChanged));

  const mcpBase = authorityActionFromToolCall("mcp", {
    operation: "invoke",
    route: "jira",
    name: "create_issue",
    arguments: { project: "A", summary: "one" },
  });
  for (const changed of [
    authorityActionFromToolCall("mcp", {
      operation: "invoke",
      route: "computer-use",
      name: "create_issue",
      arguments: { project: "A", summary: "one" },
    }),
    authorityActionFromToolCall("mcp", {
      operation: "invoke",
      route: "jira",
      name: "update_issue",
      arguments: { project: "A", summary: "one" },
    }),
    authorityActionFromToolCall("mcp", {
      operation: "invoke",
      route: "jira",
      name: "create_issue",
      arguments: { project: "A", summary: "two" },
    }),
  ]) {
    assert.notEqual(actionFingerprint(mcpBase), actionFingerprint(changed));
  }

  const guiBase = authorityActionFromToolCall("gui", {
    operation: "act",
    target: "local",
    sessionId: "gui-1",
    generation: "generation-1",
    action: { type: "press", elementId: "confirm" },
  });
  for (const changed of [
    authorityActionFromToolCall("gui", {
      operation: "act",
      target: "local",
      sessionId: "gui-1",
      generation: "generation-2",
      action: { type: "press", elementId: "confirm" },
    }),
    authorityActionFromToolCall("gui", {
      operation: "act",
      target: "local",
      sessionId: "gui-1",
      generation: "generation-1",
      action: { type: "press", elementId: "cancel" },
    }),
  ]) {
    assert.notEqual(actionFingerprint(guiBase), actionFingerprint(changed));
  }
  assert.notEqual(actionFingerprint(fsBase), actionFingerprint(mcpBase));
});

test("PENDING reservation recovers as UNCERTAIN and consumed without persisting raw payload", async (t) => {
  const root = await mkdtemp(join(tmpdir(), "devspace-authority-recovery-"));
  t.after(async () => rm(root, { recursive: true, force: true }));
  const storePath = join(root, "authority.sqlite");
  const now = { value: 1_787_050_000_000 };
  const rawSecret = "RAW_AUTHORITY_SECRET_9f6b7b8e";
  const scopeId = `oauth-client:${rawSecret}`;
  const descriptor = authorityActionFromToolCall("exec", {
    target: "local",
    cwd: `/tmp/${rawSecret}`,
    command: `git push origin ${rawSecret}`,
    mode: "foreground",
  });
  const fileDescriptor = authorityActionFromToolCall("fs", {
    operation: "write",
    target: "local",
    path: `/tmp/${rawSecret}.txt`,
    content: `file-content-${rawSecret}\n`,
    overwrite: false,
  });
  const patchDescriptor = authorityActionFromToolCall("fs", {
    operation: "patch",
    target: "local",
    path: `/tmp/${rawSecret}.txt`,
    patch: `*** Begin Patch\n*** Update File: fixture.txt\n@@\n-old\n+${rawSecret}\n*** End Patch`,
  });
  const credentialDescriptor = authorityActionFromToolCall("mcp", {
    operation: "invoke",
    route: "jira",
    name: "read_only_fixture",
    arguments: { credential: rawSecret, query: `payload-${rawSecret}` },
  });
  const first = registry(now, storePath, "process-generation-a");
  const created = first.create({
    taskId: `task-${rawSecret}`,
    authorityText: `Dispatch exactly once using ${rawSecret}.`,
    actions: [
      { id: rawSecret, descriptor, risk: "R3", uses: 1 },
      { id: `file-${rawSecret}`, descriptor: fileDescriptor },
      { id: `patch-${rawSecret}`, descriptor: patchDescriptor },
      { id: `credential-${rawSecret}`, descriptor: credentialDescriptor },
    ],
  }, scopeId);
  const authorityId = String(created.authorityId);
  const grant = first.require(authorityId, scopeId, descriptor, "R3");
  assert.ok(grant);
  assert.equal(
    ((first.status(authorityId, scopeId).receipts as Array<{ result: string }>)[0]?.result),
    "PENDING",
  );
  first.close();

  now.value += 1_000;
  const recovered = registry(now, storePath, "process-generation-b");
  const status = recovered.status(authorityId, scopeId) as {
    actions: Array<{ consumedUses: number }>;
    receipts: Array<{ result: string; evidence?: { errorCode?: string; reasonCode?: string } }>;
  };
  assert.equal(status.actions[0]?.consumedUses, 1);
  assert.equal(status.receipts[0]?.result, "UNCERTAIN");
  assert.equal(status.receipts[0]?.evidence?.errorCode, "PROCESS_RESTARTED");
  assert.equal(status.receipts[0]?.evidence?.reasonCode, "PENDING_RESERVATION_RECOVERED");
  const stats = recovered.stats() as {
    pendingReservations: number;
    recoveredPendingUses: number;
  };
  assert.equal(stats.pendingReservations, 0);
  assert.equal(stats.recoveredPendingUses, 1);
  assert.throws(
    () => recovered.require(authorityId, scopeId, descriptor, "R3"),
    (error: unknown) => code(error) === "AUTHORITY_CONSUMED",
  );
  recovered.close();

  for (const path of [storePath, `${storePath}-wal`, `${storePath}-shm`]) {
    const bytes = await readFile(path).catch(() => undefined);
    if (!bytes) continue;
    assert.equal(bytes.includes(Buffer.from(rawSecret)), false, path);
    assert.equal(bytes.includes(Buffer.from(scopeId)), false, path);
  }
});

test("restart after authority expiry still preserves UNCERTAIN consumed evidence without replay", async (t) => {
  const root = await mkdtemp(join(tmpdir(), "devspace-authority-expired-recovery-"));
  t.after(async () => rm(root, { recursive: true, force: true }));
  const storePath = join(root, "authority.sqlite");
  const now = { value: 1_787_055_000_000 };
  const scopeId = "oauth-client:expired-recovery-client";
  const descriptor = authorityActionFromToolCall("exec", {
    target: "local",
    cwd: "/tmp",
    command: "git push origin expired-recovery-test",
    mode: "foreground",
  });
  const first = registry(now, storePath, "expired-process-a");
  const created = first.create({
    taskId: "expired-recovery",
    authorityText: "Dispatch this exact action once before expiry.",
    expiresInSeconds: 60,
    actions: [{ id: "one-shot", descriptor, risk: "R3", uses: 1 }],
  }, scopeId);
  const authorityId = String(created.authorityId);
  assert.ok(first.require(authorityId, scopeId, descriptor, "R3"));
  first.close();

  now.value += 61_000;
  const recovered = registry(now, storePath, "expired-process-b");
  const status = recovered.status(authorityId, scopeId) as {
    expired: boolean;
    actions: Array<{ consumedUses: number }>;
    receipts: Array<{ result: string }>;
  };
  assert.equal(status.expired, true);
  assert.equal(status.actions[0]?.consumedUses, 1);
  assert.deepEqual(status.receipts.map((receipt) => receipt.result), ["UNCERTAIN"]);
  assert.throws(
    () => recovered.require(authorityId, scopeId, descriptor, "R3"),
    (error: unknown) => code(error) === "AUTHORITY_EXPIRED",
  );
  recovered.close();
});

test("stale overlapping workers cannot reserve the same R3 action twice", async (t) => {
  const root = await mkdtemp(join(tmpdir(), "devspace-authority-overlap-"));
  t.after(async () => rm(root, { recursive: true, force: true }));
  const storePath = join(root, "authority.sqlite");
  const now = { value: 1_787_060_000_000 };
  const scopeId = "oauth-client:overlap-client";
  const descriptor = authorityActionFromToolCall("exec", {
    target: "local",
    cwd: "/tmp",
    command: "git push origin overlap-test",
    mode: "foreground",
  });
  const workerA = registry(now, storePath, "overlap-worker-a");
  const created = workerA.create({
    taskId: "overlap-one-shot",
    authorityText: "Dispatch the exact overlap test once.",
    actions: [{ id: "one-shot", descriptor, risk: "R3", uses: 1 }],
  }, scopeId);
  const authorityId = String(created.authorityId);
  const workerB = registry(now, storePath, "overlap-worker-b");

  const grant = workerA.require(authorityId, scopeId, descriptor, "R3");
  assert.ok(grant);
  assert.throws(
    () => workerB.require(authorityId, scopeId, descriptor, "R3"),
    (error: unknown) => code(error) === "AUTHORITY_CONSUMED",
  );
  assert.throws(
    () => workerB.release(authorityId, scopeId),
    (error: unknown) => code(error) === "PRECONDITION_FAILED",
  );
  workerA.record(grant, "PASS");
  workerA.close();
  workerB.close();

  const readback = registry(now, storePath, "overlap-worker-readback");
  const status = readback.status(authorityId, scopeId) as {
    actions: Array<{ consumedUses: number }>;
    receipts: Array<{ result: string }>;
  };
  assert.equal(status.actions[0]?.consumedUses, 1);
  assert.deepEqual(status.receipts.map((receipt) => receipt.result), ["PASS"]);
  readback.close();
});

test("correction preserves an in-flight receipt and epochs remain monotonic across workers", async (t) => {
  const root = await mkdtemp(join(tmpdir(), "devspace-authority-correction-"));
  t.after(async () => rm(root, { recursive: true, force: true }));
  const storePath = join(root, "authority.sqlite");
  const now = { value: 1_787_070_000_000 };
  const scopeId = "oauth-client:correction-client";
  const descriptor = authorityActionFromToolCall("exec", {
    target: "local",
    cwd: "/tmp",
    command: "git push origin correction-test",
    mode: "foreground",
  });
  const workerA = registry(now, storePath, "correction-worker-a");
  const created = workerA.create({
    taskId: "correction-one-shot",
    authorityText: "Dispatch this exact action before correction.",
    actions: [{ id: "one-shot", descriptor, risk: "R3", uses: 1 }],
  }, scopeId);
  const authorityId = String(created.authorityId);
  const workerB = registry(now, storePath, "correction-worker-b");
  const grant = workerA.require(authorityId, scopeId, descriptor, "R3");
  assert.ok(grant);

  const firstCorrection = workerA.invalidate(scopeId, "Stop authorizing the old action.");
  assert.equal(firstCorrection.correctionEpoch, 1);
  assert.deepEqual(firstCorrection.invalidatedAuthorityIds, [authorityId]);
  workerA.record(grant, "PASS", { reasonCode: "ACTION_COMPLETED_AFTER_CORRECTION" });
  assert.throws(
    () => workerB.status(authorityId, scopeId),
    (error: unknown) => code(error) === "AUTHORITY_EXPIRED",
  );
  const replacementFromStaleWorker = workerB.create({
    taskId: "correction-one-shot",
    authorityText: "Dispatch this exact action before correction.",
    actions: [{ id: "one-shot", descriptor, risk: "R3", uses: 1 }],
  }, scopeId);
  assert.equal(replacementFromStaleWorker.correctionEpoch, 1);
  assert.notEqual(replacementFromStaleWorker.authorityId, authorityId);
  const secondCorrection = workerB.invalidate(scopeId, "Apply a second correction from a stale worker.");
  assert.equal(secondCorrection.correctionEpoch, 2);
  assert.deepEqual(secondCorrection.invalidatedAuthorityIds, [replacementFromStaleWorker.authorityId]);
  workerA.close();
  workerB.close();

  const sqlite = new Database(storePath, { readonly: true, fileMustExist: true });
  const receipt = sqlite.prepare(
    "select result, reason_code from operation_authority_receipts where authority_id = ?",
  ).get(authorityId) as { result: string; reason_code: string | null } | undefined;
  const scope = sqlite.prepare(
    "select correction_epoch from operation_authority_scopes",
  ).get() as { correction_epoch: number } | undefined;
  sqlite.close();
  assert.deepEqual(receipt, {
    result: "PASS",
    reason_code: "ACTION_COMPLETED_AFTER_CORRECTION",
  });
  assert.equal(scope?.correction_epoch, 2);

  const readback = registry(now, storePath, "correction-worker-readback");
  assert.equal((readback.stats() as { authorities: number }).authorities, 0);
  assert.throws(
    () => readback.require(authorityId, scopeId, descriptor, "R3"),
    (error: unknown) => code(error) === "AUTHORITY_EXPIRED",
  );
  const replacement = readback.create({
    taskId: "correction-replacement",
    authorityText: "Create a replacement authority after both corrections.",
    actions: [{ id: "replacement", descriptor, risk: "R3", uses: 1 }],
  }, scopeId);
  assert.equal(replacement.correctionEpoch, 2);
  readback.close();
});

test("R3 authority is one-shot and cannot authorize a different exact action", () => {
  const authority = registry();
  const descriptor = authorityActionFromToolCall("exec", {
    target: "local",
    cwd: "/tmp",
    command: "git push origin main",
    mode: "foreground",
  });
  assert.equal(minimumAuthorityRisk(descriptor), "R3");
  const created = authority.create({
    taskId: "push-main",
    authorityText: "Push this exact branch once.",
    actions: [{ descriptor, risk: "R3", uses: 1 }],
  }, "client:session");
  const authorityId = String(created.authorityId);
  const grant = authority.require(authorityId, "client:session", descriptor, "R3");
  assert.ok(grant);
  assert.throws(
    () => authority.require(authorityId, "client:session", descriptor, "R3"),
    (error: unknown) => code(error) === "AUTHORITY_CONSUMED",
  );

  const changed = authorityActionFromToolCall("exec", {
    target: "local",
    cwd: "/tmp",
    command: "git push --force origin main",
    mode: "foreground",
  });
  assert.notEqual(actionFingerprint(changed), actionFingerprint(descriptor));
});

test("correction invalidates every authority in the same scope epoch", () => {
  const authority = registry();
  const descriptor = authorityActionFromToolCall("gui", {
    operation: "act",
    target: "local",
    sessionId: "gui-1",
    generation: "g1",
    action: { type: "press", elementId: "e1" },
  });
  const created = authority.create({
    taskId: "press-confirm",
    authorityText: "Press Confirm once.",
    actions: [{ descriptor, risk: "R3" }],
  }, "client:session");
  const authorityId = String(created.authorityId);
  const correction = authority.invalidate("client:session", "Do not press Confirm.");
  assert.deepEqual(correction.invalidatedAuthorityIds, [authorityId]);
  assert.throws(
    () => authority.require(authorityId, "client:session", descriptor, "R3"),
    (error: unknown) => code(error) === "AUTHORITY_EXPIRED",
  );
});

test("authority preview classifies exact actions without creating or consuming authority", () => {
  const authority = registry();
  const read = authorityActionFromToolCall("fs", {
    operation: "read",
    target: "local",
    path: "/tmp/example.txt",
  });
  const write = authorityActionFromToolCall("fs", {
    operation: "write",
    target: "local",
    path: "/tmp/example.txt",
    content: "value\n",
  });
  const push = authorityActionFromToolCall("exec", {
    target: "local",
    cwd: "/tmp",
    command: "git push origin main",
  });
  const first = authority.preview([
    { id: "read", descriptor: read },
    { id: "write", descriptor: write, uses: 2 },
    { id: "push", descriptor: push },
  ]);
  const second = authority.preview([
    { id: "read", descriptor: read },
    { id: "write", descriptor: write, uses: 2 },
    { id: "push", descriptor: push },
  ]);
  assert.equal(first.authorityRequired, true);
  assert.equal(first.actionCount, 3);
  assert.equal(first.authorityActionCount, 2);
  assert.equal(first.r0ActionCount, 1);
  assert.equal(first.planFingerprint, second.planFingerprint);
  assert.deepEqual(
    (first.actions as Array<{ id: string; minimumRisk: string; maximumUses: number }>).map(
      ({ id, minimumRisk, maximumUses }) => ({ id, minimumRisk, maximumUses }),
    ),
    [
      { id: "read", minimumRisk: "R0", maximumUses: 0 },
      { id: "write", minimumRisk: "R1", maximumUses: 2 },
      { id: "push", minimumRisk: "R3", maximumUses: 1 },
    ],
  );
  assert.deepEqual(authority.stats(), {
    authorities: 0,
    scopes: 0,
    pendingReservations: 0,
    recoveredPendingUses: 0,
    previews: 2,
  });
  assert.throws(
    () => authority.preview([{ descriptor: read, risk: "R1" }]),
    /is R0; omit risk and uses/u,
  );
  assert.throws(
    () => authority.preview([
      { id: "duplicate-one", descriptor: write },
      { id: "duplicate-two", descriptor: write },
    ]),
    /Duplicate exact authority actions.*combine repeated identical calls/u,
  );
  assert.throws(
    () => authority.create({
      taskId: "duplicate-create",
      authorityText: "Repeated exact actions must use one bounded action record.",
      actions: [
        { id: "duplicate-one", descriptor: write },
        { id: "duplicate-two", descriptor: write },
      ],
    }, "client:session"),
    /Duplicate exact authority actions.*combine repeated identical calls/u,
  );
});

test("R0 actions cannot be wrapped in authority and elevation commands fail closed", () => {
  const authority = registry();
  const read = authorityActionFromToolCall("fs", {
    operation: "read",
    target: "local",
    path: "/tmp/example.txt",
  });
  assert.equal(minimumAuthorityRisk(read), "R0");
  assert.throws(
    () => authority.create({
      taskId: "unnecessary-read",
      authorityText: "Read the file.",
      actions: [{ descriptor: read }],
    }, "client:session"),
    /must run without task authority/u,
  );

  for (const command of [
    "sudo -n id",
    "/usr/bin/env sudo id",
    "doas id",
    "pkexec sh",
    "osascript -e 'do shell script \"id\" with administrator privileges'",
    "powershell Start-Process cmd -Verb RunAs",
  ]) {
    assert.throws(
      () => assertNoElevationCommand(command),
      (error: unknown) => code(error) === "ELEVATION_BLOCKED",
      command,
    );
  }
  assert.equal(commandRisk("git status --short", "local"), "R0");
  assert.equal(commandRisk("npm run build", "local"), "R1");
  assert.equal(commandRisk("npm run build", "company"), "R2");
  assert.equal(commandRisk("git commit -m test", "local"), "R2");
  assert.equal(commandRisk("rm -rf /tmp/example", "local"), "R3");
  assert.equal(commandRisk("python3 -c 'import shutil; shutil.rmtree(\"/tmp/example\")'", "local"), "R3");
  assert.equal(commandRisk("find /tmp/example -delete", "local"), "R3");
  assert.equal(commandRisk("curl -d x=1 https://example.test", "local"), "R3");
  assert.equal(commandRisk("printf x | sh", "local"), "R3");
  assert.equal(commandRisk("env sh -c touch /tmp/x", "local"), "R3");
  assert.equal(commandRisk("find /tmp -fprint /tmp/index", "local"), "R3");
  assert.equal(commandRisk("printf x | xargs touch", "local"), "R2");
  assert.equal(mcpRisk("invoke", { readOnly: true }), "R0");
  assert.equal(mcpRisk("invoke", {}), "R2");
  assert.equal(mcpRisk("invoke", { destructive: true }), "R3");
  assert.equal(commandRisk("git branch --delete obsolete", "local"), "R3");
  assert.equal(commandRisk("git tag --delete obsolete", "local"), "R3");
  assert.equal(commandRisk("git stash clear", "local"), "R3");
});

function code(error: unknown): string | undefined {
  return error instanceof UniversalBrokerError ? error.code : undefined;
}
