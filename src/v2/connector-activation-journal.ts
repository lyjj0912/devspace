import { createHash, randomUUID } from "node:crypto";
import {
  closeSync,
  constants,
  fchmodSync,
  fsyncSync,
  lstatSync,
  mkdirSync,
  openSync,
} from "node:fs";
import { dirname, isAbsolute, resolve } from "node:path";
import Database from "better-sqlite3";
import type {
  ConnectorActivationRecoveryHandle,
  ConnectorActivationRecoveryIntent,
  ConnectorActivationRecoveryJournal,
} from "./connector-activation-finalizer.js";

export const CONNECTOR_ACTIVATION_JOURNAL_SCHEMA_VERSION = 1;
export const CONNECTOR_ACTIVATION_JOURNAL_SNAPSHOT_POLICY =
  "PRESERVE_OUTSIDE_MUTABLE_ROLLBACK" as const;
export const CONNECTOR_ACTIVATION_JOURNAL_RECEIPT_REPLAY_POLICY =
  "PREPARED_RECEIPT_PERMANENTLY_ONE_SHOT" as const;

export type ConnectorActivationJournalFailureReason =
  | "INVALID_INPUT"
  | "PERMISSION_DENIED"
  | "CONFLICT"
  | "CORRUPT"
  | "UNAVAILABLE"
  | "CLOSED";

export type ConnectorActivationJournalTerminalState =
  | "ACTIVATED_PENDING_POSTCHECK"
  | "POST_ACTIVATION_VERIFIED"
  | "FAILED"
  | "UNKNOWN";

export interface ConnectorActivationJournalKey {
  readonly principalKeyFingerprint: string;
  readonly approvalId: string;
  readonly receiptId: string;
}

export interface ConnectorActivationJournalTerminalInput {
  readonly state: ConnectorActivationJournalTerminalState;
  readonly evidenceDigest: string;
}

export interface ConnectorActivationJournalOutcome
  extends ConnectorActivationJournalTerminalInput {
  readonly recordedAtMs: number;
}

export interface ConnectorActivationJournalEntry {
  readonly intent: Readonly<ConnectorActivationRecoveryIntent>;
  readonly recovery?: Readonly<ConnectorActivationRecoveryHandle>;
  readonly outcomes: readonly ConnectorActivationJournalOutcome[];
}

export interface ConnectorActivationJournalIdentity {
  storeId: string;
  storePath: string;
  schemaVersion: typeof CONNECTOR_ACTIVATION_JOURNAL_SCHEMA_VERSION;
  migrationManifestDigest: string;
  contentGeneration: string;
  snapshotPolicy: typeof CONNECTOR_ACTIVATION_JOURNAL_SNAPSHOT_POLICY;
  receiptReplayPolicy: typeof CONNECTOR_ACTIVATION_JOURNAL_RECEIPT_REPLAY_POLICY;
  schemaFingerprint: string;
  createdAtMs: number;
}

export interface SqliteConnectorActivationRecoveryJournalOptions {
  storePath: string;
  now?: () => number;
}

export class ConnectorActivationJournalError extends Error {
  readonly code = "CONNECTOR_ACTIVATION_JOURNAL_ERROR";

  constructor(
    readonly reason: ConnectorActivationJournalFailureReason,
    message: string,
    readonly evidence: Readonly<Record<string, unknown>> = {},
    options?: ErrorOptions,
  ) {
    super(message, options);
    this.name = "ConnectorActivationJournalError";
  }
}

const DIGEST_PATTERN = /^sha256:[a-f0-9]{64}$/u;
const RAW_DIGEST_PATTERN = /^[a-f0-9]{64}$/u;
const RECEIPT_ID_PATTERN =
  /^connector-activation-[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/u;
const AUTHORITY_ID_PATTERN =
  /^authority_[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/u;
const ACTION_CLAIM_ID_PATTERN =
  /^authority_claim_[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/u;
const CANONICAL_NAME_PATTERN = /^[A-Za-z][A-Za-z0-9._-]{0,127}$/u;
const CHECKPOINT_BUSY_TIMEOUT_NS = 5_000_000_000n;
const CHECKPOINT_RETRY_INTERVAL_MS = 2;
const CHECKPOINT_RETRY_SIGNAL = new Int32Array(new SharedArrayBuffer(4));
const DISPATCH_STATES = ["NOT_CLAIMED", "CLAIMED", "DISPATCHED"] as const;
const TERMINAL_STATES = [
  "ACTIVATED_PENDING_POSTCHECK",
  "POST_ACTIVATION_VERIFIED",
  "FAILED",
  "UNKNOWN",
] as const;

const INTENT_KEYS = [
  "schema",
  "schemaVersion",
  "state",
  "approvalId",
  "freshHostReceiptId",
  "principalKeyFingerprint",
  "actionFingerprint",
  "resourceKeySha256",
  "evidenceDigest",
  "receiptId",
  "canonicalName",
  "tupleDigest",
  "activePreimageDigest",
  "finalizationPlanDigest",
] as const;

const HANDLE_BASE_KEYS = [
  "schema",
  "schemaVersion",
  "dispatchState",
  "approvalId",
  "freshHostReceiptId",
  "authorityId",
  "principalKeyFingerprint",
  "actionFingerprint",
  "resourceKeySha256",
  "evidenceDigest",
  "receiptId",
  "canonicalName",
  "tupleDigest",
  "activePreimageDigest",
  "finalizationPlanDigest",
] as const;

const CLAIM_KEYS = ["actionClaimId", "fencingToken", "claimedAtMs"] as const;

const SCHEMA_SQL = `
  CREATE TABLE connector_activation_journal_metadata (
    singleton INTEGER NOT NULL PRIMARY KEY CHECK(singleton = 1),
    store_id TEXT NOT NULL UNIQUE,
    schema_version INTEGER NOT NULL CHECK(schema_version = 1),
    migration_manifest_digest TEXT NOT NULL,
    snapshot_policy TEXT NOT NULL,
    receipt_replay_policy TEXT NOT NULL,
    schema_fingerprint TEXT NOT NULL,
    created_at_ms INTEGER NOT NULL CHECK(created_at_ms >= 0),
    metadata_checksum TEXT NOT NULL
  ) STRICT;

  CREATE TABLE connector_activation_journal_entries (
    principal_key_fingerprint TEXT NOT NULL,
    approval_id TEXT NOT NULL,
    receipt_id TEXT NOT NULL,
    fresh_host_receipt_id TEXT NOT NULL,
    canonical_name TEXT NOT NULL,
    tuple_digest TEXT NOT NULL,
    active_preimage_digest TEXT NOT NULL,
    finalization_plan_digest TEXT NOT NULL,
    action_fingerprint TEXT NOT NULL,
    resource_key_sha256 TEXT NOT NULL,
    evidence_digest TEXT NOT NULL,
    intent_json TEXT NOT NULL CHECK(json_valid(intent_json)),
    intent_checksum TEXT NOT NULL,
    PRIMARY KEY(principal_key_fingerprint, approval_id, receipt_id)
  ) STRICT;

  CREATE INDEX connector_activation_journal_entries_principal_idx
    ON connector_activation_journal_entries(principal_key_fingerprint, receipt_id, approval_id);

  CREATE UNIQUE INDEX connector_activation_journal_entries_receipt_unique
    ON connector_activation_journal_entries(receipt_id);

  CREATE TABLE connector_activation_journal_transitions (
    principal_key_fingerprint TEXT NOT NULL,
    approval_id TEXT NOT NULL,
    receipt_id TEXT NOT NULL,
    sequence INTEGER NOT NULL CHECK(sequence BETWEEN 1 AND 3),
    dispatch_state TEXT NOT NULL CHECK(dispatch_state IN ('NOT_CLAIMED', 'CLAIMED', 'DISPATCHED')),
    authority_id TEXT NOT NULL,
    action_claim_id TEXT,
    fencing_token INTEGER,
    claimed_at_ms INTEGER,
    dispatched_at_ms INTEGER,
    handle_json TEXT NOT NULL CHECK(json_valid(handle_json)),
    previous_checksum TEXT NOT NULL,
    handle_checksum TEXT NOT NULL,
    PRIMARY KEY(principal_key_fingerprint, approval_id, receipt_id, sequence),
    UNIQUE(principal_key_fingerprint, approval_id, receipt_id, dispatch_state),
    FOREIGN KEY(principal_key_fingerprint, approval_id, receipt_id)
      REFERENCES connector_activation_journal_entries(
        principal_key_fingerprint, approval_id, receipt_id
      ) ON UPDATE RESTRICT ON DELETE RESTRICT
  ) STRICT;

  CREATE TABLE connector_activation_journal_outcomes (
    principal_key_fingerprint TEXT NOT NULL,
    approval_id TEXT NOT NULL,
    receipt_id TEXT NOT NULL,
    sequence INTEGER NOT NULL CHECK(sequence BETWEEN 1 AND 2),
    state TEXT NOT NULL CHECK(state IN (
      'ACTIVATED_PENDING_POSTCHECK', 'POST_ACTIVATION_VERIFIED', 'FAILED', 'UNKNOWN'
    )),
    evidence_digest TEXT NOT NULL,
    recorded_at_ms INTEGER NOT NULL CHECK(recorded_at_ms >= 0),
    previous_checksum TEXT NOT NULL,
    outcome_checksum TEXT NOT NULL,
    PRIMARY KEY(principal_key_fingerprint, approval_id, receipt_id, sequence),
    UNIQUE(principal_key_fingerprint, approval_id, receipt_id, state),
    FOREIGN KEY(principal_key_fingerprint, approval_id, receipt_id)
      REFERENCES connector_activation_journal_entries(
        principal_key_fingerprint, approval_id, receipt_id
      ) ON UPDATE RESTRICT ON DELETE RESTRICT
  ) STRICT;

  CREATE TRIGGER connector_activation_journal_metadata_no_update
    BEFORE UPDATE ON connector_activation_journal_metadata
    BEGIN SELECT RAISE(ABORT, 'connector activation journal metadata is immutable'); END;
  CREATE TRIGGER connector_activation_journal_metadata_no_delete
    BEFORE DELETE ON connector_activation_journal_metadata
    BEGIN SELECT RAISE(ABORT, 'connector activation journal metadata is immutable'); END;
  CREATE TRIGGER connector_activation_journal_entries_no_update
    BEFORE UPDATE ON connector_activation_journal_entries
    BEGIN SELECT RAISE(ABORT, 'connector activation reservations are immutable'); END;
  CREATE TRIGGER connector_activation_journal_entries_no_delete
    BEFORE DELETE ON connector_activation_journal_entries
    BEGIN SELECT RAISE(ABORT, 'connector activation reservations are permanent tombstones'); END;
  CREATE TRIGGER connector_activation_journal_transitions_no_update
    BEFORE UPDATE ON connector_activation_journal_transitions
    BEGIN SELECT RAISE(ABORT, 'connector activation transitions are immutable'); END;
  CREATE TRIGGER connector_activation_journal_transitions_no_delete
    BEFORE DELETE ON connector_activation_journal_transitions
    BEGIN SELECT RAISE(ABORT, 'connector activation transitions are permanent tombstones'); END;
  CREATE TRIGGER connector_activation_journal_outcomes_no_update
    BEFORE UPDATE ON connector_activation_journal_outcomes
    BEGIN SELECT RAISE(ABORT, 'connector activation outcomes are immutable'); END;
  CREATE TRIGGER connector_activation_journal_outcomes_no_delete
    BEFORE DELETE ON connector_activation_journal_outcomes
    BEGIN SELECT RAISE(ABORT, 'connector activation outcomes do not erase dispatch tombstones'); END;
`;

export const CONNECTOR_ACTIVATION_JOURNAL_MIGRATION_MANIFEST_DIGEST = sha256Digest(
  stableJson({
    schema: "devspace.connector_activation_journal",
    schemaVersion: CONNECTOR_ACTIVATION_JOURNAL_SCHEMA_VERSION,
    appendOnly: true,
    schemaSql: SCHEMA_SQL,
  }),
);

export const CONNECTOR_ACTIVATION_JOURNAL_SCHEMA_FINGERPRINT = expectedSchemaFingerprint();

interface MetadataRow {
  storeId: string;
  schemaVersion: number;
  migrationManifestDigest: string;
  snapshotPolicy: string;
  receiptReplayPolicy: string;
  schemaFingerprint: string;
  createdAtMs: number;
  metadataChecksum: string;
}

interface EntryRow {
  principalKeyFingerprint: string;
  approvalId: string;
  receiptId: string;
  freshHostReceiptId: string;
  canonicalName: string;
  tupleDigest: string;
  activePreimageDigest: string;
  finalizationPlanDigest: string;
  actionFingerprint: string;
  resourceKeySha256: string;
  evidenceDigest: string;
  intentJson: string;
  intentChecksum: string;
}

interface TransitionRow {
  principalKeyFingerprint: string;
  approvalId: string;
  receiptId: string;
  sequence: number;
  dispatchState: ConnectorActivationRecoveryHandle["dispatchState"];
  authorityId: string;
  actionClaimId: string | null;
  fencingToken: number | null;
  claimedAtMs: number | null;
  dispatchedAtMs: number | null;
  handleJson: string;
  previousChecksum: string;
  handleChecksum: string;
}

interface OutcomeRow {
  principalKeyFingerprint: string;
  approvalId: string;
  receiptId: string;
  sequence: number;
  state: ConnectorActivationJournalTerminalState;
  evidenceDigest: string;
  recordedAtMs: number;
  previousChecksum: string;
  outcomeChecksum: string;
}

interface TableInfoRow {
  name: string;
  type: string;
  notnull: number;
  pk: number;
}

interface CheckpointRow {
  busy: number;
  log: number;
  checkpointed: number;
}

const METADATA_SELECT = `
  SELECT store_id AS storeId, schema_version AS schemaVersion,
         migration_manifest_digest AS migrationManifestDigest,
         snapshot_policy AS snapshotPolicy, receipt_replay_policy AS receiptReplayPolicy,
         schema_fingerprint AS schemaFingerprint, created_at_ms AS createdAtMs,
         metadata_checksum AS metadataChecksum
    FROM connector_activation_journal_metadata
`;

const ENTRY_SELECT = `
  SELECT principal_key_fingerprint AS principalKeyFingerprint,
         approval_id AS approvalId, receipt_id AS receiptId,
         fresh_host_receipt_id AS freshHostReceiptId,
         canonical_name AS canonicalName, tuple_digest AS tupleDigest,
         active_preimage_digest AS activePreimageDigest,
         finalization_plan_digest AS finalizationPlanDigest,
         action_fingerprint AS actionFingerprint,
         resource_key_sha256 AS resourceKeySha256,
         evidence_digest AS evidenceDigest,
         intent_json AS intentJson, intent_checksum AS intentChecksum
    FROM connector_activation_journal_entries
`;

const TRANSITION_SELECT = `
  SELECT principal_key_fingerprint AS principalKeyFingerprint,
         approval_id AS approvalId, receipt_id AS receiptId,
         sequence, dispatch_state AS dispatchState,
         authority_id AS authorityId, action_claim_id AS actionClaimId,
         fencing_token AS fencingToken, claimed_at_ms AS claimedAtMs,
         dispatched_at_ms AS dispatchedAtMs, handle_json AS handleJson,
         previous_checksum AS previousChecksum, handle_checksum AS handleChecksum
    FROM connector_activation_journal_transitions
`;

const OUTCOME_SELECT = `
  SELECT principal_key_fingerprint AS principalKeyFingerprint,
         approval_id AS approvalId, receipt_id AS receiptId,
         sequence, state, evidence_digest AS evidenceDigest,
         recorded_at_ms AS recordedAtMs, previous_checksum AS previousChecksum,
         outcome_checksum AS outcomeChecksum
    FROM connector_activation_journal_outcomes
`;

/**
 * Append-only recovery journal for the connector activation destructive boundary.
 * Its path must be excluded from mutable rollback snapshots: restoring OAuth,
 * authority, or lifecycle stores must not resurrect a consumed approval.
 */
export class SqliteConnectorActivationRecoveryJournal
implements ConnectorActivationRecoveryJournal {
  private readonly storePath: string;
  private readonly parentPath: string;
  private readonly now: () => number;
  private readonly reservedThisInstance = new Set<string>();
  private sqlite!: Database.Database;
  private closed = false;
  private durabilityFailed = false;

  constructor(options: SqliteConnectorActivationRecoveryJournalOptions) {
    this.storePath = validateAbsolutePath(options?.storePath);
    this.parentPath = dirname(this.storePath);
    this.now = options.now ?? Date.now;

    let created = false;
    try {
      created = prepareOwnerOnlyPath(this.storePath, this.parentPath);
      const sqlite = new Database(this.storePath, { fileMustExist: true });
      this.sqlite = sqlite;
      configureSqlite(sqlite);
      if (created) this.initializeSchema();
      this.assertStoreIntegrity();
      this.durableCheckpoint("FULL");
      assertOwnerOnlyFile(this.storePath);
    } catch (error) {
      try {
        this.sqlite?.close();
      } catch {
        // Preserve the primary fail-closed error.
      }
      if (error instanceof ConnectorActivationJournalError) throw error;
      if (!created || isSqliteCorruption(error)) {
        throw journalError(
          "CORRUPT",
          "Connector activation journal could not be opened as a complete trusted store.",
          error,
          { storePath: this.storePath },
        );
      }
      throw journalError(
        "UNAVAILABLE",
        "Connector activation journal could not be initialized durably.",
        error,
        { storePath: this.storePath },
      );
    }
  }

  reserve(input: Readonly<ConnectorActivationRecoveryIntent>): void {
    this.assertOpen();
    const intent = canonicalIntent(input, "INVALID_INPUT");
    const key = keyFromIntent(intent);
    const keyText = stableJson(key);
    let changed = false;
    try {
      this.sqlite.transaction(() => {
        const existing = this.selectEntryRowByReceipt(intent.receiptId);
        if (existing) {
          throw conflict(
            "Connector activation approval reservation was already consumed; a second reserve is replay.",
            key,
          );
        }
        const intentJson = stableJson(intent);
        const intentChecksum = sha256Digest(intentJson);
        this.sqlite.prepare(`
          INSERT INTO connector_activation_journal_entries (
            principal_key_fingerprint, approval_id, receipt_id, fresh_host_receipt_id,
            canonical_name, tuple_digest, active_preimage_digest, finalization_plan_digest,
            action_fingerprint, resource_key_sha256, evidence_digest, intent_json, intent_checksum
          ) VALUES (
            @principalKeyFingerprint, @approvalId, @receiptId, @freshHostReceiptId,
            @canonicalName, @tupleDigest, @activePreimageDigest, @finalizationPlanDigest,
            @actionFingerprint, @resourceKeySha256, @evidenceDigest, @intentJson, @intentChecksum
          )
        `).run({ ...intent, intentJson, intentChecksum });
        changed = true;
      }).immediate();
      if (changed) {
        this.durableCheckpoint("FULL");
        this.reservedThisInstance.add(keyText);
      }
    } catch (error) {
      throw this.operationError("reserve connector activation intent", error, key);
    }
  }

  record(input: Readonly<ConnectorActivationRecoveryHandle>): void {
    this.assertOpen();
    const handle = canonicalHandle(input, "INVALID_INPUT");
    const key = keyFromHandle(handle);
    const keyText = stableJson(key);
    let changed = false;
    try {
      this.sqlite.transaction(() => {
        const entry = this.readEntryInternal(key);
        if (!entry) throw conflict("Connector activation recovery handle has no prior reservation.", key);
        assertHandleMatchesIntent(handle, entry.intent, "CONFLICT");
        const rows = this.selectTransitionRows(key);
        const latest = rows.at(-1);
        const expectedSequence = latest ? latest.sequence + 1 : 1;
        const requestedSequence = DISPATCH_STATES.indexOf(handle.dispatchState) + 1;

        if (latest?.dispatchState === handle.dispatchState) {
          if (latest.handleJson !== stableJson(handle)) {
            throw conflict("Connector activation recovery state cannot be replaced.", key);
          }
          return;
        }
        if (requestedSequence !== expectedSequence) {
          throw conflict("Connector activation recovery state must advance monotonically.", key);
        }
        if (!latest && !this.reservedThisInstance.has(keyText)) {
          throw conflict(
            "An intent-only reservation cannot acquire an authority after process restart.",
            key,
          );
        }
        if (latest) assertHandleContinues(handle, parseTransitionHandle(latest));

        const handleJson = stableJson(handle);
        const previousChecksum = latest?.handleChecksum ?? entryChecksum(entry.intent);
        const handleChecksum = transitionChecksum(
          key,
          requestedSequence,
          handle,
          previousChecksum,
        );
        this.sqlite.prepare(`
          INSERT INTO connector_activation_journal_transitions (
            principal_key_fingerprint, approval_id, receipt_id, sequence, dispatch_state,
            authority_id, action_claim_id, fencing_token, claimed_at_ms, dispatched_at_ms,
            handle_json, previous_checksum, handle_checksum
          ) VALUES (
            @principalKeyFingerprint, @approvalId, @receiptId, @sequence, @dispatchState,
            @authorityId, @actionClaimId, @fencingToken, @claimedAtMs, @dispatchedAtMs,
            @handleJson, @previousChecksum, @handleChecksum
          )
        `).run({
          ...key,
          sequence: requestedSequence,
          dispatchState: handle.dispatchState,
          authorityId: handle.authorityId,
          actionClaimId: handle.actionClaimId ?? null,
          fencingToken: handle.fencingToken ?? null,
          claimedAtMs: handle.claimedAtMs ?? null,
          dispatchedAtMs: handle.dispatchedAtMs ?? null,
          handleJson,
          previousChecksum,
          handleChecksum,
        });
        changed = true;
      }).immediate();
      if (changed) {
        this.durableCheckpoint("FULL");
        if (handle.dispatchState === "NOT_CLAIMED") this.reservedThisInstance.delete(keyText);
      }
    } catch (error) {
      throw this.operationError("record connector activation recovery state", error, key);
    }
  }

  load(input: Readonly<ConnectorActivationJournalKey>): ConnectorActivationJournalEntry | undefined {
    this.assertOpen();
    const key = canonicalKey(input, "INVALID_INPUT");
    try {
      return this.sqlite.transaction(() => this.readEntryInternal(key)).deferred();
    } catch (error) {
      throw this.operationError("load connector activation recovery state", error, key);
    }
  }

  listUnresolved(principalKeyFingerprint: string): readonly ConnectorActivationJournalEntry[] {
    this.assertOpen();
    requiredRawDigest(principalKeyFingerprint, "principalKeyFingerprint", "INVALID_INPUT");
    try {
      return this.sqlite.transaction(() => {
        const keys = this.sqlite.prepare(`
          SELECT principal_key_fingerprint AS principalKeyFingerprint,
                 approval_id AS approvalId, receipt_id AS receiptId
            FROM connector_activation_journal_entries
           WHERE principal_key_fingerprint = ?
           ORDER BY receipt_id, approval_id
        `).all(principalKeyFingerprint) as ConnectorActivationJournalKey[];
        const entries: ConnectorActivationJournalEntry[] = [];
        for (const key of keys) {
          const entry = this.readEntryInternal(key);
          if (!entry) throw corrupt("Connector activation journal lost an indexed reservation.");
          if (entry.outcomes.at(-1)?.state !== "POST_ACTIVATION_VERIFIED") entries.push(entry);
        }
        return Object.freeze(entries);
      }).deferred();
    } catch (error) {
      throw this.operationError("list unresolved connector activations", error, {
        principalKeyFingerprint,
      });
    }
  }

  markTerminal(
    keyInput: Readonly<ConnectorActivationJournalKey>,
    outcomeInput: Readonly<ConnectorActivationJournalTerminalInput>,
  ): void {
    this.assertOpen();
    const key = canonicalKey(keyInput, "INVALID_INPUT");
    const outcome = canonicalTerminalInput(outcomeInput, "INVALID_INPUT");
    let changed = false;
    try {
      this.sqlite.transaction(() => {
        const entry = this.readEntryInternal(key);
        if (!entry || entry.recovery?.dispatchState !== "DISPATCHED") {
          throw conflict("Terminal connector activation evidence requires a DISPATCHED tombstone.", key);
        }
        const rows = this.selectOutcomeRows(key);
        const latest = rows.at(-1);
        if (latest?.state === outcome.state) {
          if (latest.evidenceDigest !== outcome.evidenceDigest) {
            throw conflict("Terminal connector activation evidence cannot be replaced.", key);
          }
          return;
        }
        if (latest && latest.state !== "ACTIVATED_PENDING_POSTCHECK") {
          throw conflict("A terminal connector activation outcome cannot be changed.", key);
        }
        if (latest && outcome.state === "ACTIVATED_PENDING_POSTCHECK") {
          throw conflict("Pending postcheck evidence cannot be appended twice.", key);
        }
        const sequence = rows.length + 1;
        if (sequence > 2) throw conflict("Connector activation outcome chain is already terminal.", key);
        const recordedAtMs = monotonicTimestamp(this.now, latest?.recordedAtMs);
        const transitionRows = this.selectTransitionRows(key);
        const dispatched = transitionRows.at(-1);
        if (!dispatched || dispatched.dispatchState !== "DISPATCHED") {
          throw corrupt("Connector activation DISPATCHED checksum anchor is missing.");
        }
        const previousChecksum = latest?.outcomeChecksum ?? dispatched.handleChecksum;
        const outcomeChecksum = terminalOutcomeChecksum(
          key,
          sequence,
          outcome,
          recordedAtMs,
          previousChecksum,
        );
        this.sqlite.prepare(`
          INSERT INTO connector_activation_journal_outcomes (
            principal_key_fingerprint, approval_id, receipt_id, sequence, state,
            evidence_digest, recorded_at_ms, previous_checksum, outcome_checksum
          ) VALUES (
            @principalKeyFingerprint, @approvalId, @receiptId, @sequence, @state,
            @evidenceDigest, @recordedAtMs, @previousChecksum, @outcomeChecksum
          )
        `).run({
          ...key,
          sequence,
          state: outcome.state,
          evidenceDigest: outcome.evidenceDigest,
          recordedAtMs,
          previousChecksum,
          outcomeChecksum,
        });
        changed = true;
      }).immediate();
      if (changed) this.durableCheckpoint("FULL");
    } catch (error) {
      throw this.operationError("record connector activation terminal evidence", error, key);
    }
  }

  identity(): ConnectorActivationJournalIdentity {
    this.assertOpen();
    try {
      return this.sqlite.transaction(() => {
        const metadata = this.readMetadata();
        const checksums = [
          metadata.metadataChecksum,
          ...(this.sqlite.prepare(`
            SELECT intent_checksum AS checksum FROM connector_activation_journal_entries
            ORDER BY principal_key_fingerprint, approval_id, receipt_id
          `).all() as Array<{ checksum: string }>).map((row) => row.checksum),
          ...(this.sqlite.prepare(`
            SELECT handle_checksum AS checksum FROM connector_activation_journal_transitions
            ORDER BY principal_key_fingerprint, approval_id, receipt_id, sequence
          `).all() as Array<{ checksum: string }>).map((row) => row.checksum),
          ...(this.sqlite.prepare(`
            SELECT outcome_checksum AS checksum FROM connector_activation_journal_outcomes
            ORDER BY principal_key_fingerprint, approval_id, receipt_id, sequence
          `).all() as Array<{ checksum: string }>).map((row) => row.checksum),
        ];
        return Object.freeze({
          storeId: metadata.storeId,
          storePath: this.storePath,
          schemaVersion: CONNECTOR_ACTIVATION_JOURNAL_SCHEMA_VERSION,
          migrationManifestDigest: metadata.migrationManifestDigest,
          contentGeneration: sha256Digest(stableJson(checksums)),
          snapshotPolicy: CONNECTOR_ACTIVATION_JOURNAL_SNAPSHOT_POLICY,
          receiptReplayPolicy: CONNECTOR_ACTIVATION_JOURNAL_RECEIPT_REPLAY_POLICY,
          schemaFingerprint: metadata.schemaFingerprint,
          createdAtMs: metadata.createdAtMs,
        });
      }).deferred();
    } catch (error) {
      throw this.operationError("read connector activation journal identity", error, {});
    }
  }

  close(): void {
    if (this.closed) return;
    let failure: unknown;
    try {
      if (!this.durabilityFailed) this.durableCheckpoint("TRUNCATE");
    } catch (error) {
      failure = error;
    }
    try {
      this.sqlite.close();
    } catch (error) {
      failure ??= error;
    }
    this.closed = true;
    try {
      fsyncDirectory(this.parentPath);
    } catch (error) {
      failure ??= error;
    }
    if (failure) {
      throw this.operationError("close connector activation journal", failure, {});
    }
  }

  private initializeSchema(): void {
    const createdAtMs = monotonicTimestamp(this.now);
    const storeId = randomUUID();
    this.sqlite.transaction(() => {
      this.sqlite.exec(SCHEMA_SQL);
      const metadata = {
        storeId,
        schemaVersion: CONNECTOR_ACTIVATION_JOURNAL_SCHEMA_VERSION,
        migrationManifestDigest: CONNECTOR_ACTIVATION_JOURNAL_MIGRATION_MANIFEST_DIGEST,
        snapshotPolicy: CONNECTOR_ACTIVATION_JOURNAL_SNAPSHOT_POLICY,
        receiptReplayPolicy: CONNECTOR_ACTIVATION_JOURNAL_RECEIPT_REPLAY_POLICY,
        schemaFingerprint: sqliteSchemaFingerprint(this.sqlite),
        createdAtMs,
      };
      if (metadata.schemaFingerprint !== CONNECTOR_ACTIVATION_JOURNAL_SCHEMA_FINGERPRINT) {
        throw new Error("Created connector activation journal schema is not canonical.");
      }
      const metadataChecksum = sha256Digest(stableJson(metadata));
      this.sqlite.prepare(`
        INSERT INTO connector_activation_journal_metadata (
          singleton, store_id, schema_version, migration_manifest_digest,
          snapshot_policy, receipt_replay_policy, schema_fingerprint,
          created_at_ms, metadata_checksum
        ) VALUES (1, ?, ?, ?, ?, ?, ?, ?, ?)
      `).run(
        storeId,
        CONNECTOR_ACTIVATION_JOURNAL_SCHEMA_VERSION,
        CONNECTOR_ACTIVATION_JOURNAL_MIGRATION_MANIFEST_DIGEST,
        CONNECTOR_ACTIVATION_JOURNAL_SNAPSHOT_POLICY,
        CONNECTOR_ACTIVATION_JOURNAL_RECEIPT_REPLAY_POLICY,
        metadata.schemaFingerprint,
        createdAtMs,
        metadataChecksum,
      );
      this.sqlite.pragma(`user_version = ${CONNECTOR_ACTIVATION_JOURNAL_SCHEMA_VERSION}`);
    }).immediate();
  }

  private assertStoreIntegrity(): void {
    const quickCheck = this.sqlite.pragma("quick_check") as Array<Record<string, unknown>>;
    if (quickCheck.length !== 1 || Object.values(quickCheck[0] ?? {})[0] !== "ok") {
      throw corrupt("Connector activation journal SQLite quick_check failed.");
    }
    const foreignKeyFailures = this.sqlite.pragma("foreign_key_check") as unknown[];
    if (foreignKeyFailures.length !== 0) {
      throw corrupt("Connector activation journal contains broken foreign keys.");
    }
    if (this.sqlite.pragma("user_version", { simple: true }) !== CONNECTOR_ACTIVATION_JOURNAL_SCHEMA_VERSION) {
      throw corrupt("Connector activation journal schema version is unsupported.");
    }
    assertSchemaObjects(this.sqlite);
    assertTableShapes(this.sqlite);
    this.readMetadata();

    const keys = this.sqlite.prepare(`
      SELECT principal_key_fingerprint AS principalKeyFingerprint,
             approval_id AS approvalId, receipt_id AS receiptId
        FROM connector_activation_journal_entries
       ORDER BY principal_key_fingerprint, approval_id, receipt_id
    `).all() as ConnectorActivationJournalKey[];
    for (const key of keys) {
      if (!this.readEntryInternal(key)) {
        throw corrupt("Connector activation journal contains an unreadable reservation.");
      }
    }
    const transitionCount = Number((this.sqlite.prepare(
      "SELECT COUNT(*) AS count FROM connector_activation_journal_transitions",
    ).get() as { count: number }).count);
    const outcomeCount = Number((this.sqlite.prepare(
      "SELECT COUNT(*) AS count FROM connector_activation_journal_outcomes",
    ).get() as { count: number }).count);
    const countedTransitions = keys.reduce(
      (total, key) => total + this.selectTransitionRows(key).length,
      0,
    );
    const countedOutcomes = keys.reduce((total, key) => total + this.selectOutcomeRows(key).length, 0);
    if (transitionCount !== countedTransitions || outcomeCount !== countedOutcomes) {
      throw corrupt("Connector activation journal contains orphan recovery rows.");
    }
  }

  private readMetadata(): MetadataRow {
    const rows = this.sqlite.prepare(METADATA_SELECT).all() as MetadataRow[];
    if (rows.length !== 1) throw corrupt("Connector activation journal metadata is incomplete.");
    const row = rows[0]!;
    const unsigned = {
      storeId: row.storeId,
      schemaVersion: row.schemaVersion,
      migrationManifestDigest: row.migrationManifestDigest,
      snapshotPolicy: row.snapshotPolicy,
      receiptReplayPolicy: row.receiptReplayPolicy,
      schemaFingerprint: row.schemaFingerprint,
      createdAtMs: row.createdAtMs,
    };
    if (!/^[a-f0-9-]{36}$/u.test(row.storeId)
      || row.schemaVersion !== CONNECTOR_ACTIVATION_JOURNAL_SCHEMA_VERSION
      || row.migrationManifestDigest !== CONNECTOR_ACTIVATION_JOURNAL_MIGRATION_MANIFEST_DIGEST
      || row.snapshotPolicy !== CONNECTOR_ACTIVATION_JOURNAL_SNAPSHOT_POLICY
      || row.receiptReplayPolicy !== CONNECTOR_ACTIVATION_JOURNAL_RECEIPT_REPLAY_POLICY
      || row.schemaFingerprint !== CONNECTOR_ACTIVATION_JOURNAL_SCHEMA_FINGERPRINT
      || row.schemaFingerprint !== sqliteSchemaFingerprint(this.sqlite)
      || !Number.isSafeInteger(row.createdAtMs)
      || row.createdAtMs < 0
      || row.metadataChecksum !== sha256Digest(stableJson(unsigned))) {
      throw corrupt("Connector activation journal metadata identity is invalid.");
    }
    return row;
  }

  private readEntryInternal(key: ConnectorActivationJournalKey): ConnectorActivationJournalEntry | undefined {
    const row = this.selectEntryRow(key);
    if (!row) return undefined;
    const intent = parseEntryIntent(row);
    const transitions = this.selectTransitionRows(key);
    const outcomes = this.selectOutcomeRows(key);
    let previousChecksum = row.intentChecksum;
    let previousHandle: ConnectorActivationRecoveryHandle | undefined;
    for (let index = 0; index < transitions.length; index += 1) {
      const transition = transitions[index]!;
      const sequence = index + 1;
      if (transition.sequence !== sequence || transition.dispatchState !== DISPATCH_STATES[index]) {
        throw corrupt("Connector activation recovery transition sequence is incomplete.");
      }
      const handle = parseTransitionHandle(transition);
      assertHandleMatchesIntent(handle, intent, "CORRUPT");
      if (previousHandle) assertHandleContinues(handle, previousHandle, "CORRUPT");
      const expectedChecksum = transitionChecksum(key, sequence, handle, previousChecksum);
      if (transition.previousChecksum !== previousChecksum
        || transition.handleChecksum !== expectedChecksum) {
        throw corrupt("Connector activation recovery transition checksum chain is invalid.");
      }
      previousChecksum = transition.handleChecksum;
      previousHandle = handle;
    }

    if (outcomes.length > 0 && previousHandle?.dispatchState !== "DISPATCHED") {
      throw corrupt("Connector activation outcome exists without a DISPATCHED tombstone.");
    }
    let previousOutcome: ConnectorActivationJournalOutcome | undefined;
    const parsedOutcomes: ConnectorActivationJournalOutcome[] = [];
    for (let index = 0; index < outcomes.length; index += 1) {
      const rowOutcome = outcomes[index]!;
      const sequence = index + 1;
      if (rowOutcome.sequence !== sequence
        || !TERMINAL_STATES.includes(rowOutcome.state)
        || !DIGEST_PATTERN.test(rowOutcome.evidenceDigest)
        || !Number.isSafeInteger(rowOutcome.recordedAtMs)
        || rowOutcome.recordedAtMs < 0
        || (previousOutcome && rowOutcome.recordedAtMs < previousOutcome.recordedAtMs)) {
        throw corrupt("Connector activation outcome row is invalid.");
      }
      if (previousOutcome
        && (previousOutcome.state !== "ACTIVATED_PENDING_POSTCHECK"
          || rowOutcome.state === "ACTIVATED_PENDING_POSTCHECK")) {
        throw corrupt("Connector activation outcome state regressed or was replaced.");
      }
      const parsed = Object.freeze({
        state: rowOutcome.state,
        evidenceDigest: rowOutcome.evidenceDigest,
        recordedAtMs: rowOutcome.recordedAtMs,
      });
      const expectedChecksum = terminalOutcomeChecksum(
        key,
        sequence,
        parsed,
        rowOutcome.recordedAtMs,
        previousChecksum,
      );
      if (rowOutcome.previousChecksum !== previousChecksum
        || rowOutcome.outcomeChecksum !== expectedChecksum) {
        throw corrupt("Connector activation outcome checksum chain is invalid.");
      }
      previousChecksum = rowOutcome.outcomeChecksum;
      previousOutcome = parsed;
      parsedOutcomes.push(parsed);
    }

    return Object.freeze({
      intent,
      ...(previousHandle ? { recovery: previousHandle } : {}),
      outcomes: Object.freeze(parsedOutcomes),
    });
  }

  private selectEntryRow(key: ConnectorActivationJournalKey): EntryRow | undefined {
    return this.sqlite.prepare(`${ENTRY_SELECT}
      WHERE principal_key_fingerprint = ? AND approval_id = ? AND receipt_id = ?
    `).get(key.principalKeyFingerprint, key.approvalId, key.receiptId) as EntryRow | undefined;
  }

  private selectEntryRowByReceipt(receiptId: string): EntryRow | undefined {
    return this.sqlite.prepare(`${ENTRY_SELECT}
      WHERE receipt_id = ?
    `).get(receiptId) as EntryRow | undefined;
  }

  private selectTransitionRows(key: ConnectorActivationJournalKey): TransitionRow[] {
    return this.sqlite.prepare(`${TRANSITION_SELECT}
      WHERE principal_key_fingerprint = ? AND approval_id = ? AND receipt_id = ?
      ORDER BY sequence
    `).all(key.principalKeyFingerprint, key.approvalId, key.receiptId) as TransitionRow[];
  }

  private selectOutcomeRows(key: ConnectorActivationJournalKey): OutcomeRow[] {
    return this.sqlite.prepare(`${OUTCOME_SELECT}
      WHERE principal_key_fingerprint = ? AND approval_id = ? AND receipt_id = ?
      ORDER BY sequence
    `).all(key.principalKeyFingerprint, key.approvalId, key.receiptId) as OutcomeRow[];
  }

  private durableCheckpoint(mode: "FULL" | "TRUNCATE"): void {
    try {
      const deadline = process.hrtime.bigint() + CHECKPOINT_BUSY_TIMEOUT_NS;
      let checkpoint: CheckpointRow | undefined;
      for (;;) {
        const rows = this.sqlite.pragma(`wal_checkpoint(${mode})`) as CheckpointRow[];
        const row = rows[0];
        if (rows.length !== 1
          || !row
          || !Number.isSafeInteger(row.busy)
          || !Number.isSafeInteger(row.log)
          || !Number.isSafeInteger(row.checkpointed)) {
          throw new Error("SQLite WAL checkpoint returned an invalid result.");
        }
        if (row.busy === 0) {
          if (row.log !== row.checkpointed) {
            throw new Error("SQLite WAL checkpoint did not checkpoint every frame.");
          }
          checkpoint = row;
          break;
        }
        if (row.busy < 0 || process.hrtime.bigint() >= deadline) {
          throw new Error("SQLite WAL checkpoint remained busy beyond the bounded retry window.");
        }
        Atomics.wait(
          CHECKPOINT_RETRY_SIGNAL,
          0,
          0,
          CHECKPOINT_RETRY_INTERVAL_MS,
        );
      }
      if (!checkpoint) throw new Error("SQLite WAL checkpoint did not complete.");
      fsyncExistingFile(`${this.storePath}-wal`);
      fsyncExistingFile(this.storePath);
      fsyncDirectory(this.parentPath);
      assertOwnerOnlyDirectory(this.parentPath);
      assertOwnerOnlyFile(this.storePath);
    } catch (error) {
      this.durabilityFailed = true;
      if (error instanceof ConnectorActivationJournalError) throw error;
      throw journalError(
        "UNAVAILABLE",
        "Connector activation journal durability barrier failed.",
        error,
        { storePath: this.storePath, checkpointMode: mode },
      );
    }
  }

  private assertOpen(): void {
    if (this.closed) throw journalError("CLOSED", "Connector activation journal is closed.");
    if (this.durabilityFailed) {
      throw journalError(
        "UNAVAILABLE",
        "Connector activation journal is sealed after an uncertain durability barrier.",
      );
    }
    assertOwnerOnlyDirectory(this.parentPath);
    assertOwnerOnlyFile(this.storePath);
  }

  private operationError(
    operation: string,
    error: unknown,
    evidence: object,
  ): ConnectorActivationJournalError {
    if (error instanceof ConnectorActivationJournalError) return error;
    if (isSqliteCorruption(error)) {
      return journalError(
        "CORRUPT",
        `Unable to ${operation}: journal corruption detected.`,
        error,
        { ...evidence },
      );
    }
    return journalError("UNAVAILABLE", `Unable to ${operation}.`, error, { ...evidence });
  }
}

function configureSqlite(sqlite: Database.Database): void {
  const journalMode = sqlite.pragma("journal_mode = WAL", { simple: true });
  if (journalMode !== "wal") throw new Error("SQLite WAL mode is required.");
  sqlite.pragma("synchronous = FULL");
  sqlite.pragma("fullfsync = ON");
  sqlite.pragma("checkpoint_fullfsync = ON");
  sqlite.pragma("foreign_keys = ON");
  sqlite.pragma("busy_timeout = 5000");
  sqlite.pragma("wal_autocheckpoint = 0");
  sqlite.pragma("trusted_schema = OFF");
  if (sqlite.pragma("synchronous", { simple: true }) !== 2
    || sqlite.pragma("foreign_keys", { simple: true }) !== 1
    || sqlite.pragma("wal_autocheckpoint", { simple: true }) !== 0) {
    throw new Error("SQLite durability pragmas did not read back exactly.");
  }
}

function validateAbsolutePath(value: unknown): string {
  if (typeof value !== "string"
    || value.length === 0
    || value.includes("\0")
    || !isAbsolute(value)
    || resolve(value) !== value) {
    throw journalError(
      "INVALID_INPUT",
      "Connector activation journal storePath must be an absolute normalized path.",
    );
  }
  return value;
}

function prepareOwnerOnlyPath(storePath: string, parentPath: string): boolean {
  const uid = currentUid();
  try {
    mkdirSync(parentPath, { recursive: true, mode: 0o700 });
  } catch (error) {
    throw journalError(
      "PERMISSION_DENIED",
      "Connector activation journal parent could not be created owner-only.",
      error,
      { parentPath },
    );
  }
  assertOwnerOnlyDirectory(parentPath, uid);

  try {
    const metadata = lstatSync(storePath);
    if (!metadata.isFile()
      || metadata.isSymbolicLink()
      || metadata.uid !== uid
      || (metadata.mode & 0o777) !== 0o600
      || metadata.nlink !== 1) {
      throw journalError(
        "PERMISSION_DENIED",
        "Existing connector activation journal must be a single-link owner-only regular file.",
        undefined,
        { storePath },
      );
    }
    return false;
  } catch (error) {
    if (!isNodeError(error, "ENOENT")) {
      if (error instanceof ConnectorActivationJournalError) throw error;
      throw journalError(
        "PERMISSION_DENIED",
        "Connector activation journal path could not be verified.",
        error,
        { storePath },
      );
    }
  }

  const flags = constants.O_CREAT | constants.O_EXCL | constants.O_WRONLY
    | (constants.O_NOFOLLOW ?? 0);
  let descriptor: number | undefined;
  try {
    descriptor = openSync(storePath, flags, 0o600);
    fchmodSync(descriptor, 0o600);
    fsyncSync(descriptor);
  } catch (error) {
    throw journalError(
      "PERMISSION_DENIED",
      "Connector activation journal file could not be created owner-only.",
      error,
      { storePath },
    );
  } finally {
    if (descriptor !== undefined) closeSync(descriptor);
  }
  fsyncDirectory(parentPath);
  assertOwnerOnlyFile(storePath);
  return true;
}

function assertOwnerOnlyDirectory(path: string, expectedUid = currentUid()): void {
  let metadata: ReturnType<typeof lstatSync>;
  try {
    metadata = lstatSync(path);
  } catch (error) {
    throw journalError(
      "PERMISSION_DENIED",
      "Connector activation journal parent could not be verified.",
      error,
      { parentPath: path },
    );
  }
  if (!metadata.isDirectory()
    || metadata.isSymbolicLink()
    || metadata.uid !== expectedUid
    || (metadata.mode & 0o777) !== 0o700) {
    throw journalError(
      "PERMISSION_DENIED",
      "Connector activation journal parent must be an owner-only directory.",
      undefined,
      { parentPath: path },
    );
  }
}

function assertOwnerOnlyFile(path: string): void {
  let metadata: ReturnType<typeof lstatSync>;
  try {
    metadata = lstatSync(path);
  } catch (error) {
    throw journalError(
      "PERMISSION_DENIED",
      "Connector activation journal file could not be verified.",
      error,
      { storePath: path },
    );
  }
  if (!metadata.isFile()
    || metadata.isSymbolicLink()
    || metadata.uid !== currentUid()
    || (metadata.mode & 0o777) !== 0o600
    || metadata.nlink !== 1) {
    throw journalError(
      "PERMISSION_DENIED",
      "Connector activation journal file is no longer owner-only.",
      undefined,
      { storePath: path },
    );
  }
}

function currentUid(): number {
  if (typeof process.getuid !== "function") {
    throw journalError(
      "UNAVAILABLE",
      "Connector activation journal ownership cannot be verified on this platform.",
    );
  }
  return process.getuid();
}

function fsyncExistingFile(path: string): void {
  let descriptor: number | undefined;
  try {
    descriptor = openSync(path, constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0));
    fsyncSync(descriptor);
  } catch (error) {
    if (!isNodeError(error, "ENOENT")) throw error;
  } finally {
    if (descriptor !== undefined) closeSync(descriptor);
  }
}

function fsyncDirectory(path: string): void {
  const descriptor = openSync(path, constants.O_RDONLY | (constants.O_DIRECTORY ?? 0));
  try {
    fsyncSync(descriptor);
  } finally {
    closeSync(descriptor);
  }
}

function assertSchemaObjects(sqlite: Database.Database): void {
  const expected = new Map<string, { type: string; table: string }>([
    ["connector_activation_journal_metadata", { type: "table", table: "connector_activation_journal_metadata" }],
    ["connector_activation_journal_entries", { type: "table", table: "connector_activation_journal_entries" }],
    ["connector_activation_journal_transitions", { type: "table", table: "connector_activation_journal_transitions" }],
    ["connector_activation_journal_outcomes", { type: "table", table: "connector_activation_journal_outcomes" }],
    ["connector_activation_journal_entries_principal_idx", { type: "index", table: "connector_activation_journal_entries" }],
    ["connector_activation_journal_entries_receipt_unique", { type: "index", table: "connector_activation_journal_entries" }],
    ["connector_activation_journal_metadata_no_update", { type: "trigger", table: "connector_activation_journal_metadata" }],
    ["connector_activation_journal_metadata_no_delete", { type: "trigger", table: "connector_activation_journal_metadata" }],
    ["connector_activation_journal_entries_no_update", { type: "trigger", table: "connector_activation_journal_entries" }],
    ["connector_activation_journal_entries_no_delete", { type: "trigger", table: "connector_activation_journal_entries" }],
    ["connector_activation_journal_transitions_no_update", { type: "trigger", table: "connector_activation_journal_transitions" }],
    ["connector_activation_journal_transitions_no_delete", { type: "trigger", table: "connector_activation_journal_transitions" }],
    ["connector_activation_journal_outcomes_no_update", { type: "trigger", table: "connector_activation_journal_outcomes" }],
    ["connector_activation_journal_outcomes_no_delete", { type: "trigger", table: "connector_activation_journal_outcomes" }],
  ]);
  const rows = sqlite.prepare(`
    SELECT type, name, tbl_name AS tableName
      FROM sqlite_master
     WHERE name NOT LIKE 'sqlite_%'
     ORDER BY name
  `).all() as Array<{ type: string; name: string; tableName: string }>;
  if (rows.length !== expected.size) throw corrupt("Connector activation journal schema object set is incomplete.");
  for (const row of rows) {
    const object = expected.get(row.name);
    if (!object || object.type !== row.type || object.table !== row.tableName) {
      throw corrupt("Connector activation journal schema object identity is invalid.");
    }
  }
}

function assertTableShapes(sqlite: Database.Database): void {
  assertTableShape(sqlite, "connector_activation_journal_metadata", [
    ["singleton", "INTEGER", 1, 1], ["store_id", "TEXT", 1, 0],
    ["schema_version", "INTEGER", 1, 0], ["migration_manifest_digest", "TEXT", 1, 0],
    ["snapshot_policy", "TEXT", 1, 0], ["receipt_replay_policy", "TEXT", 1, 0],
    ["schema_fingerprint", "TEXT", 1, 0], ["created_at_ms", "INTEGER", 1, 0],
    ["metadata_checksum", "TEXT", 1, 0],
  ]);
  assertTableShape(sqlite, "connector_activation_journal_entries", [
    ["principal_key_fingerprint", "TEXT", 1, 1], ["approval_id", "TEXT", 1, 2],
    ["receipt_id", "TEXT", 1, 3], ["fresh_host_receipt_id", "TEXT", 1, 0],
    ["canonical_name", "TEXT", 1, 0], ["tuple_digest", "TEXT", 1, 0],
    ["active_preimage_digest", "TEXT", 1, 0], ["finalization_plan_digest", "TEXT", 1, 0],
    ["action_fingerprint", "TEXT", 1, 0], ["resource_key_sha256", "TEXT", 1, 0],
    ["evidence_digest", "TEXT", 1, 0], ["intent_json", "TEXT", 1, 0],
    ["intent_checksum", "TEXT", 1, 0],
  ]);
  assertTableShape(sqlite, "connector_activation_journal_transitions", [
    ["principal_key_fingerprint", "TEXT", 1, 1], ["approval_id", "TEXT", 1, 2],
    ["receipt_id", "TEXT", 1, 3], ["sequence", "INTEGER", 1, 4],
    ["dispatch_state", "TEXT", 1, 0], ["authority_id", "TEXT", 1, 0],
    ["action_claim_id", "TEXT", 0, 0], ["fencing_token", "INTEGER", 0, 0],
    ["claimed_at_ms", "INTEGER", 0, 0], ["dispatched_at_ms", "INTEGER", 0, 0],
    ["handle_json", "TEXT", 1, 0], ["previous_checksum", "TEXT", 1, 0],
    ["handle_checksum", "TEXT", 1, 0],
  ]);
  assertTableShape(sqlite, "connector_activation_journal_outcomes", [
    ["principal_key_fingerprint", "TEXT", 1, 1], ["approval_id", "TEXT", 1, 2],
    ["receipt_id", "TEXT", 1, 3], ["sequence", "INTEGER", 1, 4],
    ["state", "TEXT", 1, 0], ["evidence_digest", "TEXT", 1, 0],
    ["recorded_at_ms", "INTEGER", 1, 0], ["previous_checksum", "TEXT", 1, 0],
    ["outcome_checksum", "TEXT", 1, 0],
  ]);
  assertIndexShape(
    sqlite,
    "connector_activation_journal_entries_principal_idx",
    false,
    false,
    ["principal_key_fingerprint", "receipt_id", "approval_id"],
  );
  assertIndexShape(
    sqlite,
    "connector_activation_journal_entries_receipt_unique",
    true,
    false,
    ["receipt_id"],
  );
}

function assertTableShape(
  sqlite: Database.Database,
  table: string,
  expected: ReadonlyArray<readonly [string, string, number, number]>,
): void {
  const rows = sqlite.pragma(`table_info(${table})`) as TableInfoRow[];
  if (rows.length !== expected.length) throw corrupt(`Connector activation journal ${table} is incomplete.`);
  for (let index = 0; index < expected.length; index += 1) {
    const row = rows[index]!;
    const [name, type, notnull, pk] = expected[index]!;
    if (row.name !== name || row.type !== type || row.notnull !== notnull || row.pk !== pk) {
      throw corrupt(`Connector activation journal ${table} column identity is invalid.`);
    }
  }
}

function assertIndexShape(
  sqlite: Database.Database,
  indexName: string,
  unique: boolean,
  partial: boolean,
  columns: readonly string[],
): void {
  const indexes = sqlite.pragma("index_list(connector_activation_journal_entries)") as Array<{
    name: string;
    unique: number;
    partial: number;
  }>;
  const observed = indexes.find((index) => index.name === indexName);
  if (!observed
    || observed.unique !== Number(unique)
    || observed.partial !== Number(partial)) {
    throw corrupt(`Connector activation journal index ${indexName} semantics are invalid.`);
  }
  const indexColumns = (sqlite.pragma(`index_info(${indexName})`) as Array<{
    seqno: number;
    name: string;
  }>).sort((left, right) => left.seqno - right.seqno).map((column) => column.name);
  if (indexColumns.length !== columns.length
    || indexColumns.some((column, index) => column !== columns[index])) {
    throw corrupt(`Connector activation journal index ${indexName} columns are invalid.`);
  }
}

function expectedSchemaFingerprint(): string {
  const sqlite = new Database(":memory:");
  try {
    sqlite.exec(SCHEMA_SQL);
    return sqliteSchemaFingerprint(sqlite);
  } finally {
    sqlite.close();
  }
}

function sqliteSchemaFingerprint(sqlite: Database.Database): string {
  const rows = sqlite.prepare(`
    SELECT type, name, tbl_name AS tableName, sql
      FROM sqlite_master
     WHERE name NOT LIKE 'sqlite_%'
     ORDER BY type, name
  `).all() as Array<{
    type: string;
    name: string;
    tableName: string;
    sql: string;
  }>;
  if (rows.some((row) => typeof row.sql !== "string" || row.sql.length === 0)) {
    throw corrupt("Connector activation journal schema contains an unbound object.");
  }
  return sha256Digest(stableJson(rows));
}

function parseEntryIntent(row: EntryRow): ConnectorActivationRecoveryIntent {
  const intent = parseCanonicalJson(row.intentJson, "Connector activation reservation") as unknown;
  const canonical = canonicalIntent(intent, "CORRUPT");
  if (row.intentChecksum !== sha256Digest(row.intentJson)
    || row.intentChecksum !== entryChecksum(canonical)
    || row.principalKeyFingerprint !== canonical.principalKeyFingerprint
    || row.approvalId !== canonical.approvalId
    || row.receiptId !== canonical.receiptId
    || row.freshHostReceiptId !== canonical.freshHostReceiptId
    || row.canonicalName !== canonical.canonicalName
    || row.tupleDigest !== canonical.tupleDigest
    || row.activePreimageDigest !== canonical.activePreimageDigest
    || row.finalizationPlanDigest !== canonical.finalizationPlanDigest
    || row.actionFingerprint !== canonical.actionFingerprint
    || row.resourceKeySha256 !== canonical.resourceKeySha256
    || row.evidenceDigest !== canonical.evidenceDigest) {
    throw corrupt("Connector activation reservation columns or checksum do not match its canonical intent.");
  }
  return canonical;
}

function parseTransitionHandle(row: TransitionRow): ConnectorActivationRecoveryHandle {
  const handle = parseCanonicalJson(row.handleJson, "Connector activation recovery transition") as unknown;
  const canonical = canonicalHandle(handle, "CORRUPT");
  if (row.principalKeyFingerprint !== canonical.principalKeyFingerprint
    || row.approvalId !== canonical.approvalId
    || row.receiptId !== canonical.receiptId
    || row.dispatchState !== canonical.dispatchState
    || row.authorityId !== canonical.authorityId
    || row.actionClaimId !== (canonical.actionClaimId ?? null)
    || row.fencingToken !== (canonical.fencingToken ?? null)
    || row.claimedAtMs !== (canonical.claimedAtMs ?? null)
    || row.dispatchedAtMs !== (canonical.dispatchedAtMs ?? null)) {
    throw corrupt("Connector activation recovery transition columns do not match its canonical handle.");
  }
  return canonical;
}

function canonicalIntent(
  value: unknown,
  reason: "INVALID_INPUT" | "CORRUPT",
): ConnectorActivationRecoveryIntent {
  assertExactKeys(value, INTENT_KEYS, "Connector activation recovery intent", reason);
  const intent = value as unknown as ConnectorActivationRecoveryIntent;
  if (intent.schema !== "devspace.connector_activation_recovery_intent"
    || intent.schemaVersion !== 1
    || intent.state !== "INTENT_RESERVED") {
    throw validationFailure(reason, "Connector activation recovery intent identity is invalid.");
  }
  validateCommonBinding(intent, reason);
  requiredText(intent.approvalId, "approvalId", 256, reason);
  requiredText(intent.freshHostReceiptId, "freshHostReceiptId", 256, reason);
  const canonical = JSON.parse(stableJson(intent)) as ConnectorActivationRecoveryIntent;
  return Object.freeze(canonical);
}

function canonicalHandle(
  value: unknown,
  reason: "INVALID_INPUT" | "CORRUPT",
): ConnectorActivationRecoveryHandle {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw validationFailure(reason, "Connector activation recovery handle is invalid.");
  }
  const dispatchState = (value as { dispatchState?: unknown }).dispatchState;
  const expectedKeys = dispatchState === "NOT_CLAIMED"
    ? HANDLE_BASE_KEYS
    : dispatchState === "CLAIMED"
      ? [...HANDLE_BASE_KEYS, ...CLAIM_KEYS]
      : dispatchState === "DISPATCHED"
        ? [...HANDLE_BASE_KEYS, ...CLAIM_KEYS, "dispatchedAtMs"]
        : HANDLE_BASE_KEYS;
  assertExactKeys(value, expectedKeys, "Connector activation recovery handle", reason);
  const handle = value as unknown as ConnectorActivationRecoveryHandle;
  if (handle.schema !== "devspace.connector_activation_recovery"
    || handle.schemaVersion !== 1
    || !DISPATCH_STATES.includes(handle.dispatchState)
    || !AUTHORITY_ID_PATTERN.test(handle.authorityId)) {
    throw validationFailure(reason, "Connector activation recovery handle identity is invalid.");
  }
  validateCommonBinding(handle, reason);
  requiredText(handle.approvalId, "approvalId", 256, reason);
  requiredText(handle.freshHostReceiptId, "freshHostReceiptId", 256, reason);
  if (handle.dispatchState !== "NOT_CLAIMED") {
    if (!handle.actionClaimId
      || !ACTION_CLAIM_ID_PATTERN.test(handle.actionClaimId)
      || !Number.isSafeInteger(handle.fencingToken)
      || handle.fencingToken! < 1
      || !Number.isSafeInteger(handle.claimedAtMs)
      || handle.claimedAtMs! < 0) {
      throw validationFailure(reason, "Connector activation recovery claim evidence is invalid.");
    }
  }
  if (handle.dispatchState === "DISPATCHED"
    && (!Number.isSafeInteger(handle.dispatchedAtMs)
      || handle.dispatchedAtMs! < handle.claimedAtMs!)) {
    throw validationFailure(reason, "Connector activation DISPATCHED timing is invalid.");
  }
  const canonical = JSON.parse(stableJson(handle)) as ConnectorActivationRecoveryHandle;
  return Object.freeze(canonical);
}

function validateCommonBinding(
  value: ConnectorActivationRecoveryIntent | ConnectorActivationRecoveryHandle,
  reason: "INVALID_INPUT" | "CORRUPT",
): void {
  requiredRawDigest(value.principalKeyFingerprint, "principalKeyFingerprint", reason);
  requiredRawDigest(value.actionFingerprint, "actionFingerprint", reason);
  requiredRawDigest(value.resourceKeySha256, "resourceKeySha256", reason);
  requiredDigest(value.evidenceDigest, "evidenceDigest", reason);
  if (!RECEIPT_ID_PATTERN.test(value.receiptId)) {
    throw validationFailure(reason, "Connector activation receiptId is invalid.");
  }
  if (!CANONICAL_NAME_PATTERN.test(value.canonicalName)) {
    throw validationFailure(reason, "Connector activation canonicalName is invalid.");
  }
  requiredDigest(value.tupleDigest, "tupleDigest", reason);
  requiredDigest(value.activePreimageDigest, "activePreimageDigest", reason);
  requiredDigest(value.finalizationPlanDigest, "finalizationPlanDigest", reason);
}

function canonicalKey(
  value: unknown,
  reason: "INVALID_INPUT" | "CORRUPT",
): ConnectorActivationJournalKey {
  assertExactKeys(
    value,
    ["principalKeyFingerprint", "approvalId", "receiptId"],
    "Connector activation journal key",
    reason,
  );
  const key = value as unknown as ConnectorActivationJournalKey;
  requiredRawDigest(key.principalKeyFingerprint, "principalKeyFingerprint", reason);
  requiredText(key.approvalId, "approvalId", 256, reason);
  if (!RECEIPT_ID_PATTERN.test(key.receiptId)) {
    throw validationFailure(reason, "Connector activation journal receiptId is invalid.");
  }
  return Object.freeze({ ...key });
}

function canonicalTerminalInput(
  value: unknown,
  reason: "INVALID_INPUT" | "CORRUPT",
): ConnectorActivationJournalTerminalInput {
  assertExactKeys(value, ["state", "evidenceDigest"], "Connector activation terminal evidence", reason);
  const outcome = value as unknown as ConnectorActivationJournalTerminalInput;
  if (!TERMINAL_STATES.includes(outcome.state)) {
    throw validationFailure(reason, "Connector activation terminal state is invalid.");
  }
  requiredDigest(outcome.evidenceDigest, "terminal evidenceDigest", reason);
  return Object.freeze({ ...outcome });
}

function assertHandleMatchesIntent(
  handle: ConnectorActivationRecoveryHandle,
  intent: ConnectorActivationRecoveryIntent,
  reason: "CONFLICT" | "CORRUPT",
): void {
  for (const key of [
    "approvalId",
    "freshHostReceiptId",
    "principalKeyFingerprint",
    "actionFingerprint",
    "resourceKeySha256",
    "evidenceDigest",
    "receiptId",
    "canonicalName",
    "tupleDigest",
    "activePreimageDigest",
    "finalizationPlanDigest",
  ] as const) {
    if (handle[key] !== intent[key]) {
      if (reason === "CONFLICT") {
        throw conflict(`Connector activation recovery ${key} does not match its reservation.`, keyFromIntent(intent));
      }
      throw corrupt(`Connector activation recovery ${key} does not match its reservation.`);
    }
  }
}

function assertHandleContinues(
  next: ConnectorActivationRecoveryHandle,
  previous: ConnectorActivationRecoveryHandle,
  reason: "CONFLICT" | "CORRUPT" = "CONFLICT",
): void {
  const mismatch = next.authorityId !== previous.authorityId
    || (previous.actionClaimId !== undefined && next.actionClaimId !== previous.actionClaimId)
    || (previous.fencingToken !== undefined && next.fencingToken !== previous.fencingToken)
    || (previous.claimedAtMs !== undefined && next.claimedAtMs !== previous.claimedAtMs);
  if (!mismatch) return;
  if (reason === "CONFLICT") {
    throw conflict("Connector activation authority, claim, or fence cannot be replaced.", keyFromHandle(next));
  }
  throw corrupt("Connector activation authority, claim, or fence changed inside the recovery chain.");
}

function keyFromIntent(intent: ConnectorActivationRecoveryIntent): ConnectorActivationJournalKey {
  return Object.freeze({
    principalKeyFingerprint: intent.principalKeyFingerprint,
    approvalId: intent.approvalId,
    receiptId: intent.receiptId,
  });
}

function keyFromHandle(handle: ConnectorActivationRecoveryHandle): ConnectorActivationJournalKey {
  return Object.freeze({
    principalKeyFingerprint: handle.principalKeyFingerprint,
    approvalId: handle.approvalId,
    receiptId: handle.receiptId,
  });
}

function entryChecksum(intent: ConnectorActivationRecoveryIntent): string {
  return sha256Digest(stableJson(intent));
}

function transitionChecksum(
  key: ConnectorActivationJournalKey,
  sequence: number,
  handle: ConnectorActivationRecoveryHandle,
  previousChecksum: string,
): string {
  return sha256Digest(stableJson({
    schema: "devspace.connector_activation_journal_transition",
    schemaVersion: 1,
    key,
    sequence,
    handle,
    previousChecksum,
  }));
}

function terminalOutcomeChecksum(
  key: ConnectorActivationJournalKey,
  sequence: number,
  outcome: ConnectorActivationJournalTerminalInput,
  recordedAtMs: number,
  previousChecksum: string,
): string {
  return sha256Digest(stableJson({
    schema: "devspace.connector_activation_journal_outcome",
    schemaVersion: 1,
    key,
    sequence,
    state: outcome.state,
    evidenceDigest: outcome.evidenceDigest,
    recordedAtMs,
    previousChecksum,
  }));
}

function parseCanonicalJson(text: unknown, label: string): unknown {
  if (typeof text !== "string") throw corrupt(`${label} JSON is missing.`);
  let parsed: unknown;
  try {
    parsed = JSON.parse(text);
  } catch (error) {
    throw corrupt(`${label} JSON is invalid.`, error);
  }
  if (stableJson(parsed) !== text) throw corrupt(`${label} JSON is not canonical.`);
  return parsed;
}

function assertExactKeys(
  value: unknown,
  expected: readonly string[],
  label: string,
  reason: "INVALID_INPUT" | "CORRUPT",
): asserts value is Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw validationFailure(reason, `${label} is invalid.`);
  }
  const prototype = Object.getPrototypeOf(value);
  if (prototype !== Object.prototype && prototype !== null) {
    throw validationFailure(reason, `${label} must be a plain object.`);
  }
  const keys = Reflect.ownKeys(value).sort((left, right) => String(left).localeCompare(String(right)));
  const expectedKeys = [...expected].sort((left, right) => left.localeCompare(right));
  if (keys.length !== expectedKeys.length
    || keys.some((key, index) => typeof key !== "string" || key !== expectedKeys[index])) {
    throw validationFailure(reason, `${label} shape is invalid.`);
  }
}

function requiredText(
  value: unknown,
  label: string,
  maximumLength: number,
  reason: "INVALID_INPUT" | "CORRUPT",
): asserts value is string {
  if (typeof value !== "string"
    || value.trim().length === 0
    || value.length > maximumLength
    || /[\u0000-\u001f\u007f]/u.test(value)) {
    throw validationFailure(reason, `Connector activation ${label} is invalid.`);
  }
}

function requiredDigest(
  value: unknown,
  label: string,
  reason: "INVALID_INPUT" | "CORRUPT",
): asserts value is string {
  if (typeof value !== "string" || !DIGEST_PATTERN.test(value)) {
    throw validationFailure(reason, `Connector activation ${label} is invalid.`);
  }
}

function requiredRawDigest(
  value: unknown,
  label: string,
  reason: "INVALID_INPUT" | "CORRUPT",
): asserts value is string {
  if (typeof value !== "string" || !RAW_DIGEST_PATTERN.test(value)) {
    throw validationFailure(reason, `Connector activation ${label} is invalid.`);
  }
}

function monotonicTimestamp(now: () => number, minimum?: number): number {
  const value = now();
  if (!Number.isSafeInteger(value) || value < 0) {
    throw journalError("UNAVAILABLE", "Connector activation journal clock is invalid.");
  }
  return minimum === undefined ? value : Math.max(value, minimum);
}

function stableJson(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(stableJson).join(",")}]`;
  if (value && typeof value === "object") {
    const record = value as Record<string, unknown>;
    return `{${Object.keys(record)
      .filter((key) => record[key] !== undefined)
      .sort()
      .map((key) => `${JSON.stringify(key)}:${stableJson(record[key])}`)
      .join(",")}}`;
  }
  return JSON.stringify(value) ?? "null";
}

function sha256Digest(value: string): string {
  return `sha256:${createHash("sha256").update(value).digest("hex")}`;
}

function validationFailure(
  reason: "INVALID_INPUT" | "CORRUPT",
  message: string,
): ConnectorActivationJournalError {
  return reason === "CORRUPT" ? corrupt(message) : journalError("INVALID_INPUT", message);
}

function conflict(message: string, key: ConnectorActivationJournalKey): ConnectorActivationJournalError {
  return journalError("CONFLICT", message, undefined, {
    principalKeyFingerprint: key.principalKeyFingerprint,
    approvalId: key.approvalId,
    receiptId: key.receiptId,
  });
}

function corrupt(message: string, cause?: unknown): ConnectorActivationJournalError {
  return journalError("CORRUPT", message, cause);
}

function journalError(
  reason: ConnectorActivationJournalFailureReason,
  message: string,
  cause?: unknown,
  evidence: Readonly<Record<string, unknown>> = {},
): ConnectorActivationJournalError {
  return new ConnectorActivationJournalError(
    reason,
    message,
    evidence,
    cause === undefined ? undefined : { cause },
  );
}

function isSqliteCorruption(error: unknown): boolean {
  const code = isRecord(error) && typeof error.code === "string" ? error.code : "";
  const message = error instanceof Error ? error.message : String(error);
  return code === "SQLITE_CORRUPT"
    || code === "SQLITE_NOTADB"
    || /database disk image is malformed|file is not a database|malformed database schema/iu.test(message);
}

function isNodeError(error: unknown, code: string): boolean {
  return isRecord(error) && error.code === code;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return Boolean(value && typeof value === "object");
}
