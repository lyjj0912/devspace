import assert from "node:assert/strict";
import { spawn, type ChildProcess } from "node:child_process";
import { createHash } from "node:crypto";
import { once } from "node:events";
import {
  chmod,
  mkdir,
  mkdtemp,
  rm,
  stat,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { isAbsolute, join } from "node:path";
import { pathToFileURL } from "node:url";
import test from "node:test";
import Database from "better-sqlite3";
import type {
  ConnectorActivationRecoveryHandle,
  ConnectorActivationRecoveryIntent,
} from "./connector-activation-finalizer.js";
import {
  CONNECTOR_ACTIVATION_JOURNAL_MIGRATION_MANIFEST_DIGEST,
  CONNECTOR_ACTIVATION_JOURNAL_RECEIPT_REPLAY_POLICY,
  CONNECTOR_ACTIVATION_JOURNAL_SCHEMA_FINGERPRINT,
  CONNECTOR_ACTIVATION_JOURNAL_SCHEMA_VERSION,
  CONNECTOR_ACTIVATION_JOURNAL_SNAPSHOT_POLICY,
  ConnectorActivationJournalError,
  SqliteConnectorActivationRecoveryJournal,
  type ConnectorActivationJournalKey,
  type ConnectorActivationJournalTerminalState,
} from "./connector-activation-journal.js";

const FIXED_NOW_MS = 1_787_100_000_000;

test("journal requires an absolute owner-only path and persists its no-rollback identity", async (t) => {
  const root = await mkdtemp(join(tmpdir(), "devspace-connector-journal-permissions-"));
  t.after(() => rm(root, { recursive: true, force: true }));

  assert.throws(
    () => new SqliteConnectorActivationRecoveryJournal({ storePath: "relative.sqlite" }),
    hasJournalReason("INVALID_INPUT"),
  );

  const ownerDirectory = join(root, "owner-only");
  const storePath = join(ownerDirectory, "connector-activation-journal.sqlite");
  const journal = new SqliteConnectorActivationRecoveryJournal({
    storePath,
    now: () => FIXED_NOW_MS,
  });
  const identity = journal.identity();
  assert.equal(identity.schemaVersion, CONNECTOR_ACTIVATION_JOURNAL_SCHEMA_VERSION);
  assert.equal(identity.snapshotPolicy, CONNECTOR_ACTIVATION_JOURNAL_SNAPSHOT_POLICY);
  assert.equal(identity.receiptReplayPolicy, CONNECTOR_ACTIVATION_JOURNAL_RECEIPT_REPLAY_POLICY);
  assert.equal(identity.migrationManifestDigest, CONNECTOR_ACTIVATION_JOURNAL_MIGRATION_MANIFEST_DIGEST);
  assert.equal(identity.schemaFingerprint, CONNECTOR_ACTIVATION_JOURNAL_SCHEMA_FINGERPRINT);
  assert.match(identity.contentGeneration, /^sha256:[a-f0-9]{64}$/u);
  assert.equal(identity.storePath, storePath);
  assert.ok(isAbsolute(identity.storePath));
  assert.match(identity.storeId, /^[a-f0-9-]{36}$/u);
  journal.close();

  assert.equal((await stat(ownerDirectory)).mode & 0o777, 0o700);
  assert.equal((await stat(storePath)).mode & 0o777, 0o600);
  const database = new Database(storePath, { readonly: true, fileMustExist: true });
  try {
    assert.equal(database.pragma("journal_mode", { simple: true }), "wal");
    assert.equal(database.pragma("user_version", { simple: true }), 1);
    assert.equal(database.pragma("quick_check", { simple: true }), "ok");
  } finally {
    database.close();
  }

  await chmod(ownerDirectory, 0o755);
  assert.throws(
    () => new SqliteConnectorActivationRecoveryJournal({ storePath }),
    hasJournalReason("PERMISSION_DENIED"),
    "an already exposed parent must fail closed instead of being silently repaired",
  );
});

test("a PREPARED receipt is permanently one-shot across alternate evidence and reopen", async () => {
  const fixture = await journalFixture("receipt-one-shot");
  try {
    fixture.journal.reserve(fixture.intent);
    const alternate = {
      ...fixture.intent,
      approvalId: "approval-alternate",
      freshHostReceiptId: "host-alternate",
      evidenceDigest: digest("alternate-evidence"),
    } satisfies ConnectorActivationRecoveryIntent;
    assert.throws(
      () => fixture.journal.reserve(alternate),
      hasJournalReason("CONFLICT"),
      "approval, Host, or evidence rotation cannot bypass a consumed PREPARED receipt",
    );
    fixture.journal.close();

    const reopened = new SqliteConnectorActivationRecoveryJournal({ storePath: fixture.storePath });
    try {
      assert.throws(
        () => reopened.reserve({
          ...alternate,
          approvalId: "approval-other-principal",
          principalKeyFingerprint: rawDigest("other-principal"),
        }),
        hasJournalReason("CONFLICT"),
        "receipt identity is global and cannot move to another principal after restart",
      );
      assert.equal(reopened.listUnresolved(fixture.intent.principalKeyFingerprint).length, 1);
    } finally {
      reopened.close();
    }
  } finally {
    await fixture.cleanup();
  }
});

test("two concurrent processes cannot reserve alternate approvals for one PREPARED receipt", async (t) => {
  const root = await mkdtemp(join(tmpdir(), "devspace-connector-journal-reserve-race-"));
  t.after(() => rm(root, { recursive: true, force: true }));
  for (let round = 1; round <= 5; round += 1) {
    await t.test(`contention round ${round}`, async (t) => {
      const storePath = join(root, `owner-${round}`, "journal.sqlite");
      const bootstrap = new SqliteConnectorActivationRecoveryJournal({ storePath });
      bootstrap.close();
      const fixture = activationFixture(`receipt-race-${round}`);
      const alternate = {
        ...fixture.intent,
        approvalId: `approval-race-alternate-${round}`,
        freshHostReceiptId: `host-race-alternate-${round}`,
        evidenceDigest: digest(`race-alternate-evidence-${round}`),
      } satisfies ConnectorActivationRecoveryIntent;
      const first = spawnReservationRaceChild(storePath, fixture.intent);
      const second = spawnReservationRaceChild(storePath, alternate);
      t.after(() => {
        for (const child of [first.child, second.child]) {
          if (child.exitCode === null && child.signalCode === null) child.kill("SIGKILL");
        }
      });
      const firstExit = once(first.child, "exit");
      const secondExit = once(second.child, "exit");
      await Promise.all([first.ready, second.ready]);
      first.child.stdin?.end("GO\n");
      second.child.stdin?.end("GO\n");
      const [firstResult, secondResult, firstStatus, secondStatus] = await Promise.all([
        first.result,
        second.result,
        firstExit,
        secondExit,
      ]);
      assert.deepEqual([firstResult, secondResult].sort(), ["CONFLICT", "OK"]);
      assert.deepEqual(firstStatus, [0, null]);
      assert.deepEqual(secondStatus, [0, null]);

      const recovered = new SqliteConnectorActivationRecoveryJournal({ storePath });
      try {
        const unresolved = recovered.listUnresolved(fixture.intent.principalKeyFingerprint);
        assert.equal(unresolved.length, 1);
        assert.equal(unresolved[0]?.intent.receiptId, fixture.intent.receiptId);
        assert.ok([
          fixture.intent.approvalId,
          alternate.approvalId,
        ].includes(unresolved[0]!.intent.approvalId));
      } finally {
        recovered.close();
      }
    });
  }
});

test("reopen rejects same-name weakened triggers, indexes, and table constraints", async (t) => {
  await t.test("no-delete trigger", async () => {
    const fixture = await journalFixture("tampered-trigger");
    try {
      fixture.journal.reserve(fixture.intent);
      fixture.journal.close();
      const database = new Database(fixture.storePath);
      try {
        database.exec(`
          DROP TRIGGER connector_activation_journal_entries_no_delete;
          CREATE TRIGGER connector_activation_journal_entries_no_delete
            BEFORE DELETE ON connector_activation_journal_entries WHEN 0
            BEGIN SELECT RAISE(ABORT, 'disabled'); END;
          DELETE FROM connector_activation_journal_entries;
        `);
      } finally {
        database.close();
      }
      assert.throws(
        () => new SqliteConnectorActivationRecoveryJournal({ storePath: fixture.storePath }),
        hasJournalReason("CORRUPT"),
      );
    } finally {
      await fixture.cleanup();
    }
  });

  await t.test("non-unique partial wrong-column receipt index", async () => {
    const fixture = await journalFixture("tampered-index");
    try {
      fixture.journal.reserve(fixture.intent);
      fixture.journal.close();
      const database = new Database(fixture.storePath);
      try {
        database.exec(`
          DROP INDEX connector_activation_journal_entries_receipt_unique;
          CREATE INDEX connector_activation_journal_entries_receipt_unique
            ON connector_activation_journal_entries(approval_id)
            WHERE approval_id <> '';
        `);
      } finally {
        database.close();
      }
      assert.throws(
        () => new SqliteConnectorActivationRecoveryJournal({ storePath: fixture.storePath }),
        hasJournalReason("CORRUPT"),
      );
    } finally {
      await fixture.cleanup();
    }
  });

  await t.test("weakened table CHECK", async () => {
    const fixture = await journalFixture("tampered-table");
    try {
      fixture.journal.reserve(fixture.intent);
      fixture.journal.close();
      const database = new Database(fixture.storePath);
      try {
        database.unsafeMode(true);
        database.pragma("writable_schema = ON");
        const result = database.prepare(`
          UPDATE sqlite_master
             SET sql = replace(
               sql,
               'intent_json TEXT NOT NULL CHECK(json_valid(intent_json))',
               'intent_json TEXT NOT NULL'
             )
           WHERE type = 'table' AND name = 'connector_activation_journal_entries'
        `).run();
        assert.equal(result.changes, 1);
        database.pragma("writable_schema = OFF");
      } finally {
        database.close();
      }
      assert.throws(
        () => new SqliteConnectorActivationRecoveryJournal({ storePath: fixture.storePath }),
        hasJournalReason("CORRUPT"),
      );
    } finally {
      await fixture.cleanup();
    }
  });
});

test("reservation is one-shot while recovery handles are exact, monotonic, idempotent, and tombstoned", async (t) => {
  const fixture = await journalFixture("monotonic");
  t.after(fixture.cleanup);
  const { journal, intent, notClaimed, claimed, dispatched, key } = fixture;

  assert.throws(() => journal.record(notClaimed), hasJournalReason("CONFLICT"));
  journal.reserve(intent);
  assert.throws(
    () => journal.reserve(structuredClone(intent)),
    hasJournalReason("CONFLICT"),
    "even an exact second reservation would allow a crash retry to mint a second authority",
  );
  assert.deepEqual(journal.load(key), {
    intent,
    outcomes: [],
  });
  assert.throws(
    () => journal.reserve({ ...intent, evidenceDigest: digest("conflicting-reservation") }),
    hasJournalReason("CONFLICT"),
  );
  assert.throws(() => journal.record(claimed), hasJournalReason("CONFLICT"));

  journal.record(notClaimed);
  journal.record(structuredClone(notClaimed));
  assert.throws(
    () => journal.record({ ...notClaimed, authorityId: authorityId("replacement") }),
    hasJournalReason("CONFLICT"),
  );
  journal.record(claimed);
  journal.record(structuredClone(claimed));
  assert.throws(() => journal.record(notClaimed), hasJournalReason("CONFLICT"));
  journal.record(dispatched);
  journal.record(structuredClone(dispatched));

  assert.throws(() => journal.record(claimed), hasJournalReason("CONFLICT"));
  assert.throws(
    () => journal.record({
      ...dispatched,
      authorityId: authorityId("rollback-resurrection"),
      actionClaimId: actionClaimId("rollback-resurrection"),
      fencingToken: dispatched.fencingToken! + 1,
    }),
    hasJournalReason("CONFLICT"),
    "a restored mutable store cannot replace the preserved DISPATCHED tombstone",
  );
  assert.deepEqual(journal.load(key)?.recovery, dispatched);
  assert.deepEqual(journal.listUnresolved(intent.principalKeyFingerprint).map((entry) => entry.intent.receiptId), [
    intent.receiptId,
  ]);

  journal.close();
  const reopened = new SqliteConnectorActivationRecoveryJournal({ storePath: fixture.storePath });
  try {
    assert.deepEqual(reopened.load(key)?.recovery, dispatched);
    assert.throws(
      () => reopened.record({ ...notClaimed, authorityId: authorityId("after-reopen") }),
      hasJournalReason("CONFLICT"),
    );
  } finally {
    reopened.close();
  }
});

test("terminal and postcheck evidence advances only from DISPATCHED without deleting the tombstone", async (t) => {
  const fixture = await journalFixture("terminal");
  t.after(fixture.cleanup);
  const { journal, key, intent, notClaimed, claimed, dispatched } = fixture;
  const activationEvidence = digest("activation-pending-postcheck");
  const postcheckEvidence = digest("post-activation-verified");

  journal.reserve(intent);
  assert.throws(
    () => journal.markTerminal(key, {
      state: "ACTIVATED_PENDING_POSTCHECK",
      evidenceDigest: activationEvidence,
    }),
    hasJournalReason("CONFLICT"),
  );
  journal.record(notClaimed);
  journal.record(claimed);
  journal.record(dispatched);

  journal.markTerminal(key, {
    state: "ACTIVATED_PENDING_POSTCHECK",
    evidenceDigest: activationEvidence,
  });
  journal.markTerminal(key, {
    state: "ACTIVATED_PENDING_POSTCHECK",
    evidenceDigest: activationEvidence,
  });
  assert.throws(
    () => journal.markTerminal(key, {
      state: "ACTIVATED_PENDING_POSTCHECK",
      evidenceDigest: digest("conflicting-pending-evidence"),
    }),
    hasJournalReason("CONFLICT"),
  );
  assert.equal(journal.listUnresolved(intent.principalKeyFingerprint).length, 1);

  journal.markTerminal(key, {
    state: "POST_ACTIVATION_VERIFIED",
    evidenceDigest: postcheckEvidence,
  });
  journal.markTerminal(key, {
    state: "POST_ACTIVATION_VERIFIED",
    evidenceDigest: postcheckEvidence,
  });
  assert.throws(
    () => journal.markTerminal(key, {
      state: "FAILED",
      evidenceDigest: digest("late-failure"),
    }),
    hasJournalReason("CONFLICT"),
  );

  const loaded = journal.load(key);
  assert.deepEqual(loaded?.recovery, dispatched);
  assert.deepEqual(loaded?.outcomes.map(({ state, evidenceDigest }) => ({ state, evidenceDigest })), [
    { state: "ACTIVATED_PENDING_POSTCHECK", evidenceDigest: activationEvidence },
    { state: "POST_ACTIVATION_VERIFIED", evidenceDigest: postcheckEvidence },
  ]);
  assert.equal(journal.listUnresolved(intent.principalKeyFingerprint).length, 0);

  for (const state of ["FAILED", "UNKNOWN"] as const satisfies readonly ConnectorActivationJournalTerminalState[]) {
    const other = await journalFixture(`terminal-${state.toLowerCase()}`);
    try {
      other.journal.reserve(other.intent);
      other.journal.record(other.notClaimed);
      other.journal.record(other.claimed);
      other.journal.record(other.dispatched);
      const evidenceDigest = digest(`terminal-${state}`);
      other.journal.markTerminal(other.key, { state, evidenceDigest });
      other.journal.markTerminal(other.key, { state, evidenceDigest });
      assert.equal(other.journal.load(other.key)?.outcomes.at(-1)?.state, state);
      assert.equal(other.journal.listUnresolved(other.intent.principalKeyFingerprint).length, 1);
    } finally {
      await other.cleanup();
    }
  }
});

test("reopen rejects incomplete rows, byte corruption, and use after close", async (t) => {
  const incomplete = await journalFixture("incomplete");
  incomplete.journal.reserve(incomplete.intent);
  incomplete.journal.close();
  const database = new Database(incomplete.storePath);
  try {
    const other = activationFixture("malformed-row");
    database.prepare(`
      INSERT INTO connector_activation_journal_entries (
        principal_key_fingerprint, approval_id, receipt_id, fresh_host_receipt_id,
        canonical_name, tuple_digest, active_preimage_digest, finalization_plan_digest,
        action_fingerprint, resource_key_sha256, evidence_digest, intent_json, intent_checksum
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).run(
      other.intent.principalKeyFingerprint,
      other.intent.approvalId,
      other.intent.receiptId,
      other.intent.freshHostReceiptId,
      other.intent.canonicalName,
      other.intent.tupleDigest,
      other.intent.activePreimageDigest,
      other.intent.finalizationPlanDigest,
      other.intent.actionFingerprint,
      other.intent.resourceKeySha256,
      other.intent.evidenceDigest,
      "{}",
      digest("forged-incomplete-row"),
    );
  } finally {
    database.close();
  }
  assert.throws(
    () => new SqliteConnectorActivationRecoveryJournal({ storePath: incomplete.storePath }),
    hasJournalReason("CORRUPT"),
  );
  await incomplete.cleanup();

  const corrupt = await journalFixture("corrupt-bytes");
  corrupt.journal.reserve(corrupt.intent);
  corrupt.journal.close();
  await writeFile(corrupt.storePath, "not a sqlite database\n", { mode: 0o600 });
  assert.throws(
    () => new SqliteConnectorActivationRecoveryJournal({ storePath: corrupt.storePath }),
    hasJournalReason("CORRUPT"),
  );
  await corrupt.cleanup();

  const closed = await journalFixture("closed");
  closed.journal.close();
  closed.journal.close();
  assert.throws(() => closed.journal.load(closed.key), hasJournalReason("CLOSED"));
  await closed.cleanup();
  t.after(() => Promise.resolve());
});

test("a real child SIGKILL recovers reservation, CLAIMED, and DISPATCHED solely from disk", async (t) => {
  for (const stage of ["INTENT_RESERVED", "CLAIMED", "DISPATCHED"] as const) {
    await t.test(stage, async (t) => {
      const root = await mkdtemp(join(tmpdir(), `devspace-connector-journal-kill-${stage.toLowerCase()}-`));
      t.after(() => rm(root, { recursive: true, force: true }));
      const storePath = join(root, "owner", "journal.sqlite");
      const fixture = activationFixture(`child-${stage}`);
      const child = spawnDurabilityChild(storePath, stage, fixture);
      t.after(() => {
        if (child.exitCode === null && child.signalCode === null) child.kill("SIGKILL");
      });
      await waitForDurableMarker(child);
      const exited = once(child, "exit");
      assert.equal(child.kill("SIGKILL"), true);
      const [code, signal] = await exited as [number | null, NodeJS.Signals | null];
      assert.equal(code, null);
      assert.equal(signal, "SIGKILL");

      const recovered = new SqliteConnectorActivationRecoveryJournal({ storePath });
      try {
        const entry = recovered.load(fixture.key);
        assert.deepEqual(entry?.intent, fixture.intent);
        if (stage === "INTENT_RESERVED") {
          assert.equal(entry?.recovery, undefined);
          assert.throws(
            () => recovered.record(fixture.notClaimed),
            hasJournalReason("CONFLICT"),
            "an intent-only crash cannot attach a newly minted authority after restart",
          );
        } else if (stage === "CLAIMED") {
          assert.deepEqual(entry?.recovery, fixture.claimed);
        } else {
          assert.deepEqual(entry?.recovery, fixture.dispatched);
        }
      } finally {
        recovered.close();
      }
    });
  }
});

interface ActivationFixture {
  intent: ConnectorActivationRecoveryIntent;
  notClaimed: ConnectorActivationRecoveryHandle;
  claimed: ConnectorActivationRecoveryHandle;
  dispatched: ConnectorActivationRecoveryHandle;
  key: ConnectorActivationJournalKey;
}

async function journalFixture(label: string): Promise<ActivationFixture & {
  root: string;
  storePath: string;
  journal: SqliteConnectorActivationRecoveryJournal;
  cleanup(): Promise<void>;
}> {
  const root = await mkdtemp(join(tmpdir(), `devspace-connector-journal-${label}-`));
  const storePath = join(root, "owner", "journal.sqlite");
  const fixture = activationFixture(label);
  const journal = new SqliteConnectorActivationRecoveryJournal({
    storePath,
    now: () => FIXED_NOW_MS,
  });
  return {
    ...fixture,
    root,
    storePath,
    journal,
    async cleanup() {
      journal.close();
      await rm(root, { recursive: true, force: true });
    },
  };
}

function activationFixture(label: string): ActivationFixture {
  const suffix = rawDigest(label).slice(0, 12);
  const receiptId = `connector-activation-11111111-1111-4111-8111-${suffix}`;
  const binding = {
    receiptId,
    canonicalName: "myDevSpace",
    tupleDigest: digest(`tuple-${label}`),
    activePreimageDigest: digest(`preimage-${label}`),
    finalizationPlanDigest: digest(`plan-${label}`),
  };
  const common = {
    approvalId: `approval-${label}`,
    freshHostReceiptId: `host-${label}`,
    principalKeyFingerprint: rawDigest(`owner-${label}`),
    actionFingerprint: rawDigest(`action-${label}`),
    resourceKeySha256: rawDigest(`resource-${label}`),
    evidenceDigest: digest(`evidence-${label}`),
    ...binding,
  };
  const intent: ConnectorActivationRecoveryIntent = {
    schema: "devspace.connector_activation_recovery_intent",
    schemaVersion: 1,
    state: "INTENT_RESERVED",
    ...common,
  };
  const notClaimed: ConnectorActivationRecoveryHandle = {
    schema: "devspace.connector_activation_recovery",
    schemaVersion: 1,
    dispatchState: "NOT_CLAIMED",
    authorityId: authorityId(label),
    ...common,
  };
  const claimed: ConnectorActivationRecoveryHandle = {
    ...notClaimed,
    dispatchState: "CLAIMED",
    actionClaimId: actionClaimId(label),
    fencingToken: 7,
    claimedAtMs: FIXED_NOW_MS + 10,
  };
  const dispatched: ConnectorActivationRecoveryHandle = {
    ...claimed,
    dispatchState: "DISPATCHED",
    dispatchedAtMs: FIXED_NOW_MS + 20,
  };
  return {
    intent,
    notClaimed,
    claimed,
    dispatched,
    key: {
      principalKeyFingerprint: intent.principalKeyFingerprint,
      approvalId: intent.approvalId,
      receiptId: intent.receiptId,
    },
  };
}

function spawnDurabilityChild(
  storePath: string,
  stage: "INTENT_RESERVED" | "CLAIMED" | "DISPATCHED",
  fixture: ActivationFixture,
): ChildProcess {
  const moduleUrl = pathToFileURL(join(process.cwd(), "src/v2/connector-activation-journal.ts")).href;
  const source = `
    const { SqliteConnectorActivationRecoveryJournal } = await import(${JSON.stringify(moduleUrl)});
    const fixture = JSON.parse(process.env.DEVSPACE_JOURNAL_FIXTURE);
    const journal = new SqliteConnectorActivationRecoveryJournal({
      storePath: process.env.DEVSPACE_JOURNAL_PATH,
      now: () => ${FIXED_NOW_MS},
    });
    journal.reserve(fixture.intent);
    if (process.env.DEVSPACE_JOURNAL_STAGE !== "INTENT_RESERVED") {
      journal.record(fixture.notClaimed);
      journal.record(fixture.claimed);
    }
    if (process.env.DEVSPACE_JOURNAL_STAGE === "DISPATCHED") journal.record(fixture.dispatched);
    process.stdout.write("DURABLE\\n");
    setInterval(() => {}, 10_000);
  `;
  return spawn(process.execPath, ["--import", "tsx", "--input-type=module", "-e", source], {
    cwd: process.cwd(),
    env: {
      ...process.env,
      DEVSPACE_JOURNAL_PATH: storePath,
      DEVSPACE_JOURNAL_STAGE: stage,
      DEVSPACE_JOURNAL_FIXTURE: JSON.stringify(fixture),
    },
    stdio: ["ignore", "pipe", "pipe"],
  });
}

function spawnReservationRaceChild(
  storePath: string,
  intent: ConnectorActivationRecoveryIntent,
): {
  child: ChildProcess;
  ready: Promise<void>;
  result: Promise<string>;
} {
  const moduleUrl = pathToFileURL(join(process.cwd(), "src/v2/connector-activation-journal.ts")).href;
  const source = `
    const { SqliteConnectorActivationRecoveryJournal } = await import(${JSON.stringify(moduleUrl)});
    const intent = JSON.parse(process.env.DEVSPACE_JOURNAL_INTENT);
    const journal = new SqliteConnectorActivationRecoveryJournal({
      storePath: process.env.DEVSPACE_JOURNAL_PATH,
      now: () => ${FIXED_NOW_MS},
    });
    process.stdout.write("READY\\n");
    process.stdin.once("data", () => {
      let result;
      try {
        journal.reserve(intent);
        result = "OK";
      } catch (error) {
        result = error && typeof error === "object" && "reason" in error
          ? String(error.reason)
          : "UNEXPECTED";
      }
      try {
        journal.close();
      } catch {
        result = "CLOSE_FAILED";
      }
      process.stdout.write("RESULT:" + result + "\\n");
    });
  `;
  const child = spawn(process.execPath, ["--import", "tsx", "--input-type=module", "-e", source], {
    cwd: process.cwd(),
    env: {
      ...process.env,
      DEVSPACE_JOURNAL_PATH: storePath,
      DEVSPACE_JOURNAL_INTENT: JSON.stringify(intent),
    },
    stdio: ["pipe", "pipe", "pipe"],
  });
  let stdout = "";
  let stderr = "";
  let readyObserved = false;
  let resultObserved = false;
  let resolveReady!: () => void;
  let rejectReady!: (error: Error) => void;
  let resolveResult!: (result: string) => void;
  let rejectResult!: (error: Error) => void;
  const ready = new Promise<void>((resolve, reject) => {
    resolveReady = resolve;
    rejectReady = reject;
  });
  const result = new Promise<string>((resolve, reject) => {
    resolveResult = resolve;
    rejectResult = reject;
  });
  child.stdout?.on("data", (chunk: Buffer) => {
    stdout += chunk.toString("utf8");
    const lines = stdout.split("\n");
    stdout = lines.pop() ?? "";
    for (const line of lines) {
      if (line === "READY" && !readyObserved) {
        readyObserved = true;
        resolveReady();
      } else if (line.startsWith("RESULT:") && !resultObserved) {
        resultObserved = true;
        resolveResult(line.slice("RESULT:".length));
      }
    }
  });
  child.stderr?.on("data", (chunk: Buffer) => {
    stderr += chunk.toString("utf8");
  });
  child.once("exit", (code, signal) => {
    const error = new Error(
      `reservation race child exited before protocol completion: code=${code} signal=${signal} stderr=${stderr}`,
    );
    if (!readyObserved) rejectReady(error);
    if (!resultObserved) rejectResult(error);
  });
  return { child, ready, result };
}

async function waitForDurableMarker(child: ChildProcess): Promise<void> {
  await new Promise<void>((resolve, reject) => {
    let stdout = "";
    let stderr = "";
    const timeout = setTimeout(() => reject(new Error(`child durability marker timed out: ${stderr}`)), 10_000);
    child.stdout?.on("data", (chunk: Buffer) => {
      stdout += chunk.toString("utf8");
      if (!stdout.includes("DURABLE\n")) return;
      clearTimeout(timeout);
      resolve();
    });
    child.stderr?.on("data", (chunk: Buffer) => {
      stderr += chunk.toString("utf8");
    });
    child.once("exit", (code, signal) => {
      if (stdout.includes("DURABLE\n")) return;
      clearTimeout(timeout);
      reject(new Error(`child exited before durable marker: code=${code} signal=${signal} stderr=${stderr}`));
    });
  });
}

function authorityId(value: string): string {
  return `authority_22222222-2222-4222-8222-${rawDigest(value).slice(0, 12)}`;
}

function actionClaimId(value: string): string {
  return `authority_claim_33333333-3333-4333-8333-${rawDigest(value).slice(0, 12)}`;
}

function digest(value: string): string {
  return `sha256:${rawDigest(value)}`;
}

function rawDigest(value: string): string {
  return createHash("sha256").update(value).digest("hex");
}

function hasJournalReason(reason: ConnectorActivationJournalError["reason"]): (error: unknown) => boolean {
  return (error) => error instanceof ConnectorActivationJournalError && error.reason === reason;
}
