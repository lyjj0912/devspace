import { createHash, createHmac, randomBytes, timingSafeEqual } from "node:crypto";
import {
  chmodSync,
  closeSync,
  constants,
  fstatSync,
  fsyncSync,
  linkSync,
  lstatSync,
  openSync,
  readFileSync,
  readdirSync,
  realpathSync,
  renameSync,
  unlinkSync,
  writeFileSync,
} from "node:fs";
import { basename, dirname, isAbsolute, join, relative, resolve, sep } from "node:path";
import { DatabaseSync } from "node:sqlite";

export const FINALIZATION_STORE_ID = "lifecycle-finalization-store";
export const FINALIZATION_STORE_SCHEMA_VERSION = 2;
export const FINALIZATION_STORE_MIGRATION_NAME = "lifecycle-finalization-authenticated-event-ledger";
export const FINALIZATION_STORE_MIGRATION_MODULE = "scripts/lib/finalization-store-contract.mjs";

export const FINALIZATION_STORE_TABLES = Object.freeze([
  "finalization_anchor",
  "finalization_events",
]);

export const FINALIZATION_STORE_INDEXES = Object.freeze([
  "finalization_events_transaction_idx",
]);

export const FINALIZATION_STORE_TRIGGERS = Object.freeze([
  "finalization_anchor_no_delete",
  "finalization_anchor_no_second_insert",
  "finalization_anchor_no_update",
  "finalization_events_insert_guard",
  "finalization_events_no_delete",
  "finalization_events_no_update",
]);

const FORWARD_FINALIZATION_STATES = Object.freeze([
  "DRAFT",
  "PREPARED",
  "PROFILE_GATES_EVALUATED",
  "ACTIVATION_PENDING",
  "POST_ACTIVATION_VERIFIED",
  "DRAINING",
  "SEALED",
  "BASE_PROFILE_FINAL_PASS",
]);
const ERROR_FINALIZATION_STATES = Object.freeze(["FAILED", "UNKNOWN"]);
const TERMINAL_FINALIZATION_STATES = Object.freeze([
  "BASE_PROFILE_FINAL_PASS",
  ...ERROR_FINALIZATION_STATES,
]);
const FINAL_STATES = Object.freeze(["SEALED", "BASE_PROFILE_FINAL_PASS"]);
const KEY_ID_PATTERN = /^management-[a-f0-9]{24}$/u;
const DIGEST_PATTERN = /^sha256:[a-f0-9]{64}$/u;
const TAG_PATTERN = /^hmac-sha256:[a-f0-9]{64}$/u;
const NONCE_PATTERN = /^[A-Za-z0-9_-]{43}$/u;
const CONTROL_FILE_NAME = "lifecycle-finalization-head.json";
const CONTROL_SCHEMA_VERSION = 1;
const CONTROL_KIND = "FINALIZATION_LEDGER_CONTROL";
const CONTROL_LOCK_SCHEMA_VERSION = 1;
const CONTROL_LOCK_KIND = "FINALIZATION_LEDGER_CONTROL_LOCK";
const BOOTSTRAP_AUTH_SCHEMA_VERSION = 2;
const BOOTSTRAP_AUTH_OPERATION = "OWNER_AUTHORIZED_R2_BOOTSTRAP";
const BOOTSTRAP_AUTH_TTL_MS = 15 * 60 * 1000;

export const FINALIZATION_STORE_DDL = Object.freeze([
  `create table finalization_anchor (
    singleton integer primary key check (singleton = 1),
    store_id text not null,
    schema_version integer not null,
    migration_name text not null,
    migration_checksum text not null,
    schema_fingerprint text not null,
    key_id text not null,
    anchor_nonce text not null,
    created_at text not null,
    anchor_tag text not null
  ) strict`,
  `create table finalization_events (
    sequence integer primary key check (sequence >= 1),
    transaction_id text not null,
    from_state text not null check (from_state in (
      'DRAFT', 'PREPARED', 'PROFILE_GATES_EVALUATED', 'ACTIVATION_PENDING',
      'POST_ACTIVATION_VERIFIED', 'DRAINING', 'SEALED', 'BASE_PROFILE_FINAL_PASS',
      'FAILED', 'UNKNOWN'
    )),
    to_state text not null check (to_state in (
      'PREPARED', 'PROFILE_GATES_EVALUATED', 'ACTIVATION_PENDING',
      'POST_ACTIVATION_VERIFIED', 'DRAINING', 'SEALED', 'BASE_PROFILE_FINAL_PASS',
      'FAILED', 'UNKNOWN'
    )),
    kind text not null,
    payload_json text not null,
    payload_digest text not null,
    occurred_at text not null,
    previous_transition_tag text not null,
    event_tag text not null unique,
    transition_tag text not null unique,
    final_tag text,
    check (
      (to_state in ('SEALED', 'BASE_PROFILE_FINAL_PASS') and final_tag is not null)
      or (to_state not in ('SEALED', 'BASE_PROFILE_FINAL_PASS') and final_tag is null)
    )
  ) strict`,
  "create index finalization_events_transaction_idx on finalization_events(transaction_id, sequence, transition_tag)",
  `create trigger finalization_anchor_no_update
    before update on finalization_anchor
    begin select raise(abort, 'finalization anchor is append-only'); end`,
  `create trigger finalization_anchor_no_delete
    before delete on finalization_anchor
    begin select raise(abort, 'finalization anchor is append-only'); end`,
  `create trigger finalization_anchor_no_second_insert
    before insert on finalization_anchor
    when exists (select 1 from finalization_anchor)
    begin select raise(abort, 'finalization anchor already exists'); end`,
  `create trigger finalization_events_no_update
    before update on finalization_events
    begin select raise(abort, 'finalization events are append-only'); end`,
  `create trigger finalization_events_no_delete
    before delete on finalization_events
    begin select raise(abort, 'finalization events are append-only'); end`,
  `create trigger finalization_events_insert_guard
    before insert on finalization_events
    begin
      select case when new.sequence != (select coalesce(max(sequence), 0) + 1 from finalization_events)
        then raise(abort, 'finalization event sequence is not contiguous') end;
      select case when new.previous_transition_tag != coalesce(
        (select transition_tag from finalization_events order by sequence desc limit 1),
        (select anchor_tag from finalization_anchor where singleton = 1)
      ) then raise(abort, 'finalization event chain predecessor differs') end;
      select case when new.from_state != coalesce(
        (select to_state from finalization_events order by sequence desc limit 1), 'DRAFT'
      ) then raise(abort, 'finalization event from_state differs') end;
      select case when exists (
        select 1 from finalization_events where transaction_id != new.transaction_id
      ) then raise(abort, 'finalization transaction identity differs') end;
      select case when not (
        (new.from_state = 'DRAFT' and new.to_state = 'PREPARED') or
        (new.from_state = 'PREPARED' and new.to_state = 'PROFILE_GATES_EVALUATED') or
        (new.from_state = 'PROFILE_GATES_EVALUATED' and new.to_state = 'ACTIVATION_PENDING') or
        (new.from_state = 'ACTIVATION_PENDING' and new.to_state = 'POST_ACTIVATION_VERIFIED') or
        (new.from_state = 'POST_ACTIVATION_VERIFIED' and new.to_state = 'DRAINING') or
        (new.from_state = 'DRAINING' and new.to_state = 'SEALED') or
        (new.from_state = 'SEALED' and new.to_state = 'BASE_PROFILE_FINAL_PASS') or
        (new.from_state not in ('DRAFT', 'FAILED', 'UNKNOWN', 'BASE_PROFILE_FINAL_PASS')
          and new.to_state in ('FAILED', 'UNKNOWN'))
      ) then raise(abort, 'finalization lifecycle step is invalid') end;
    end`,
]);

const CONTRACT_DESCRIPTOR = Object.freeze({
  storeId: FINALIZATION_STORE_ID,
  schemaVersion: FINALIZATION_STORE_SCHEMA_VERSION,
  migrationName: FINALIZATION_STORE_MIGRATION_NAME,
  migrationModule: FINALIZATION_STORE_MIGRATION_MODULE,
  tables: FINALIZATION_STORE_TABLES,
  indexes: FINALIZATION_STORE_INDEXES,
  triggers: FINALIZATION_STORE_TRIGGERS,
  ddl: FINALIZATION_STORE_DDL,
});

export const FINALIZATION_STORE_MIGRATION_CHECKSUM = domainDigest(
  "devspace.finalization-store.migration.v2",
  CONTRACT_DESCRIPTOR,
);

export const FINALIZATION_STORE_SCHEMA_FINGERPRINT = domainDigest(
  "devspace.finalization-store.schema.v2",
  CONTRACT_DESCRIPTOR,
);

export const FINALIZATION_STORE_MIGRATION = Object.freeze({
  storeId: FINALIZATION_STORE_ID,
  version: FINALIZATION_STORE_SCHEMA_VERSION,
  name: FINALIZATION_STORE_MIGRATION_NAME,
  checksum: FINALIZATION_STORE_MIGRATION_CHECKSUM,
  module: FINALIZATION_STORE_MIGRATION_MODULE,
});

export function createFinalizationStoreBootstrapAuthorization(options) {
  const configuration = requiredObject(options, "finalization bootstrap authorization options");
  const key = normalizeManagementKey(configuration.key);
  const storePath = canonicalLifecycleStorePath(configuration.storePath, true);
  const controlPath = canonicalControlPath(configuration.controlPath, storePath, true);
  const approvedAt = normalizedNow(configuration.approvedAt ? () => configuration.approvedAt : configuration.now);
  const expiresAt = configuration.expiresAt
    ? normalizedNow(() => configuration.expiresAt)
    : new Date(Date.parse(approvedAt) + BOOTSTRAP_AUTH_TTL_MS).toISOString();
  if (Date.parse(expiresAt) <= Date.parse(approvedAt)) {
    throw new Error("Finalization bootstrap authorization expiry must follow approval.");
  }
  const unsigned = bootstrapAuthorizationUnsigned({
    storePath,
    controlPath,
    keyId: key.keyId,
    approvedAt,
    expiresAt,
    authorizationId: randomBytes(32).toString("base64url"),
  });
  return Object.freeze({
    ...unsigned,
    authorizationTag: bootstrapAuthorizationTag(key, unsigned),
  });
}

export function bootstrapFinalizationStore(options) {
  return initializeFinalizationStore({ ...requiredObject(options, "finalization bootstrap options"), createOnly: true });
}

export function initializeFinalizationStore(options) {
  const configuration = requiredObject(options, "finalization store initialization options");
  const key = normalizeManagementKey(configuration.key);
  const storePath = canonicalLifecycleStorePath(configuration.storePath, true);
  const controlPath = canonicalControlPath(configuration.controlPath, storePath, true);
  const lockPath = controlLockPath(controlPath);
  let existingStore = lstatIfPresent(storePath);
  let existingControl = lstatIfPresent(controlPath);
  let lock = lstatIfPresent(lockPath) ? readAuthenticatedControlLock(lockPath, storePath, key) : null;
  let createdByThisCall = false;
  if (configuration.createOnly === true && existingControl) {
    throw new Error("Finalization store is already bootstrapped; exactly one owner-authorized bootstrap may create DRAFT.");
  }
  if (!existingControl && !lock) {
    if (existingStore) throw new Error("Finalization lifecycle.sqlite exists without external control/INIT lock; state is UNKNOWN and DRAFT resurrection is forbidden.");
    const consumedPath = bootstrapConsumedPath(controlPath);
    if (lstatIfPresent(consumedPath)) {
      readBootstrapConsumedTombstone(consumedPath, storePath, controlPath, key);
      throw new Error("Finalization bootstrap authorization was already consumed; DRAFT resurrection is forbidden.");
    }
    const createdAt = normalizedNow(configuration.now);
    const bootstrapAuthorization = validateBootstrapAuthorization(
      configuration.bootstrapAuthorization,
      storePath,
      controlPath,
      key,
      createdAt,
    );
    const anchorNonce = randomBytes(32).toString("base64url");
    const anchorPayload = {
      storeId: FINALIZATION_STORE_ID,
      schemaVersion: FINALIZATION_STORE_SCHEMA_VERSION,
      migrationName: FINALIZATION_STORE_MIGRATION_NAME,
      migrationChecksum: FINALIZATION_STORE_MIGRATION_CHECKSUM,
      schemaFingerprint: FINALIZATION_STORE_SCHEMA_FINGERPRINT,
      anchorNonce,
      createdAt,
    };
    const initialization = Object.freeze({ anchorPayload, anchorTag: authenticationTag("ANCHOR", key, anchorPayload) });
    lock = acquireControlLock({
      controlPath,
      storePath,
      key,
      lockKind: "INIT",
      intent: {
        authorizationId: bootstrapAuthorization.authorizationId,
        bootstrapAuthorization,
        initialization,
        bootstrapAuthorizationDigest: digestJson(bootstrapAuthorization),
        consumedPath,
        consumedAt: createdAt,
        controlPath,
        expectedStoreState: "ABSENT",
        stagingPath: initializationStagingPath(storePath, anchorNonce),
        storePath,
      },
      now: () => createdAt,
    });
    try {
      writeBootstrapConsumedTombstone({
        path: consumedPath,
        storePath,
        controlPath,
        key,
        authorization: bootstrapAuthorization,
        authorizationDigest: lock.intent.bootstrapAuthorizationDigest,
        consumedAt: createdAt,
      });
    } catch (error) {
      releaseControlLock(lockPath, lock);
      throw error;
    }
    createdByThisCall = true;
  }
  if (!existingControl) {
    if (!lock || lock.lockKind !== "INIT") throw new Error("Missing finalization control is not recoverable without its exact INIT lock.");
    if (lock.ownerPid !== process.pid) {
      throw new Error("Finalization INIT lock belongs to another process; use explicit verified-dead control recovery.");
    }
    completePendingInitialization({ storePath, controlPath, key, lock });
    existingControl = lstatIfPresent(controlPath);
    existingStore = lstatIfPresent(storePath);
  }
  if (!existingControl || !existingStore) throw new Error("Finalization INIT did not publish both store and committed control.");
  if (lstatIfPresent(lockPath)) {
    lock = readAuthenticatedControlLock(lockPath, storePath, key);
    if (lock.lockKind === "INIT") {
      if (lock.ownerPid !== process.pid) {
        throw new Error("Finalization INIT lock belongs to another process; use explicit verified-dead control recovery.");
      }
      validateInitializationLockIntent(lock.intent, storePath, key);
      const control = readAuthenticatedControl(controlPath, storePath, key, true);
      if (control.pending !== null) throw new Error("Finalization INIT lock overlaps a transition PENDING control.");
      cleanupPublishedInitializationResidue(storePath, lock.intent.stagingPath);
      releaseControlLock(lockPath, lock);
    }
  }
  const identity = readFinalizationStoreIdentity({ storePath, controlPath, key });
  if (configuration.createOnly === true && !createdByThisCall) {
    throw new Error("Finalization bootstrap lost the single-winner race before it could create DRAFT.");
  }
  if (configuration.requireDraft === true && identity.state !== "DRAFT") {
    throw new Error(`Finalization store is not DRAFT: ${identity.state}`);
  }
  return identity;
}

export function recoverFinalizationStoreControl(options) {
  const configuration = requiredObject(options, "finalization control recovery options");
  const key = normalizeManagementKey(configuration.key);
  const storePath = canonicalLifecycleStorePath(configuration.storePath, true);
  const controlPath = canonicalControlPath(configuration.controlPath, storePath, true);
  const lockPath = controlLockPath(controlPath);
  if (!lstatIfPresent(lockPath)) {
    throw new Error("Finalization control recovery requires an existing durable control lock.");
  }
  const abandoned = readAuthenticatedControlLock(lockPath, storePath, key);
  if (isProcessAlive(abandoned.ownerPid)) {
    throw new Error(`Finalization control lock owner PID ${abandoned.ownerPid} is still live; recovery is forbidden.`);
  }
  const recoveryPath = `${lockPath}.recovery`;
  const recovery = acquireRecoveryClaim({
    recoveryPath,
    storePath,
    key,
    abandoned,
    now: configuration.now,
  });
  let adopted;
  try {
    const current = readAuthenticatedControlLock(lockPath, storePath, key);
    if (canonicalJson(current) !== canonicalJson(abandoned) || isProcessAlive(current.ownerPid)) {
      throw new Error("Finalization control lock changed or its owner revived before verified-dead handoff.");
    }
    adopted = replaceAbandonedControlLock({ lockPath, recoveryPath, recovery, abandoned, key });
    if (adopted.lockKind === "INIT") {
      completePendingInitialization({ storePath, controlPath, key, lock: adopted });
    } else if (adopted.lockKind === "TRANSITION") {
      recoverAdoptedTransition({ storePath, controlPath, key, lock: adopted });
    } else if (adopted.lockKind === "ROLLBACK") {
      recoverAdoptedRollback({ storePath, controlPath, key, lock: adopted });
    } else {
      throw new Error(`Unsupported recovered finalization lock kind: ${adopted.lockKind}`);
    }
  } finally {
    if (lstatIfPresent(recoveryPath)) releaseControlLock(recoveryPath, recovery);
  }
  const identity = readFinalizationStoreIdentity({ storePath, controlPath, key });
  return Object.freeze({ recoveredLockKind: abandoned.lockKind, identity });
}

export function readFinalizationStoreIdentity(options) {
  return readFinalizationStoreLedger(options).identity;
}

export function readFinalizationStoreSnapshotIdentity(options) {
  const configuration = requiredObject(options, "finalization snapshot store read options");
  const key = normalizeManagementKey(configuration.key);
  const storePath = canonicalOwnerOnlyFile(
    resolve(requiredText(configuration.snapshotPath, "finalization snapshotPath")),
    "snapshotted finalization store",
  );
  const database = openReadOnlyDatabasePath(storePath);
  try {
    database.exec("pragma query_only = on");
    return readLedgerFromDatabase(database, storePath, key).identity;
  } finally {
    database.close();
  }
}

export function requestFinalizationStoreRollback(options) {
  const configuration = requiredObject(options, "finalization rollback request options");
  const key = normalizeManagementKey(configuration.key);
  const storePath = canonicalOwnerOnlyFile(canonicalLifecycleStorePath(configuration.storePath, false), "finalization store");
  const controlPath = canonicalControlPath(configuration.controlPath, storePath, false);
  const ledger = readFinalizationStoreLedger({ storePath, controlPath, key });
  if (ledger.control.rollbackAuthorization !== null) {
    const existing = ledger.control.rollbackAuthorization;
    const inspected = inspectRollbackRequest(configuration, key, ledger.control, false);
    if (canonicalJson(existing) !== canonicalJson(inspected.authorization)) {
      throw new Error("Existing finalization rollback authorization differs from this exact request.");
    }
    return Object.freeze({ resumed: true, controlEpoch: ledger.control.controlEpoch, authorization: existing });
  }
  const inspected = inspectRollbackRequest(configuration, key, ledger.control, false);
  if (inspected.authorization.from.revision <= inspected.authorization.target.revision) {
    throw new Error("Finalization rollback target must be an older authenticated lifecycle head.");
  }
  const next = authenticatedControlRecord({
    key,
    storePath,
    initialization: ledger.control.initialization,
    anchor: ledger.anchor,
    controlEpoch: ledger.control.controlEpoch + 1,
    previousControlTag: ledger.control.controlTag,
    storeFile: ledger.control.storeFile,
    databaseIdentity: ledger.control.databaseIdentity,
    current: ledger.control.current,
    pending: null,
    rollbackAuthorization: inspected.authorization,
  });
  const lock = acquireControlLock({
    controlPath, storePath, key, lockKind: "ROLLBACK",
    intent: { expectedControlDigest: digestJson(ledger.control), authorization: inspected.authorization },
    now: () => inspected.authorization.requestedAt,
  });
  const lockedControl = readAuthenticatedControl(controlPath, storePath, key);
  if (canonicalJson(lockedControl) !== canonicalJson(ledger.control)) {
    releaseControlLock(controlLockPath(controlPath), lock);
    throw new Error("Finalization rollback predecessor changed before REQUESTED publication; semantic conflict.");
  }
  replaceOwnerOnlyJsonCas(controlPath, ledger.control, next, "finalization rollback REQUESTED control", lock);
  releaseControlLock(controlLockPath(controlPath), lock);
  return Object.freeze({ resumed: false, controlEpoch: next.controlEpoch, authorization: next.rollbackAuthorization });
}

export function verifyFinalizationStoreRollback(options) {
  const configuration = requiredObject(options, "finalization rollback verification options");
  const key = normalizeManagementKey(configuration.key);
  const storePath = canonicalOwnerOnlyFile(canonicalLifecycleStorePath(configuration.storePath, false), "restored finalization store");
  const controlPath = canonicalControlPath(configuration.controlPath, storePath, false);
  if (lstatIfPresent(controlLockPath(controlPath))) {
    throw new Error("Finalization external control has an unresolved durable lock; state is UNKNOWN until exact recovery.");
  }
  const control = readAuthenticatedControl(controlPath, storePath, key);
  const existing = control.rollbackAuthorization;
  if (!existing || !["REQUESTED", "VERIFIED"].includes(existing.phase)) {
    throw new Error("A durable exact rollback REQUESTED control is required before accepting a lower lifecycle head.");
  }
  const inspected = inspectRollbackRequest(configuration, key, control, true);
  if (canonicalJson({ ...existing, phase: "REQUESTED", restore: null })
    !== canonicalJson({ ...inspected.authorization, phase: "REQUESTED", restore: null })) {
    throw new Error("Restored finalization store does not match its exact rollback REQUESTED authorization.");
  }
  if (existing.phase === "VERIFIED") {
    if (canonicalJson(existing) !== canonicalJson(inspected.authorization)) {
      throw new Error("Verified finalization rollback replay differs from durable control.");
    }
    const ledger = readFinalizationStoreLedger({ storePath, controlPath, key });
    return Object.freeze({ resumed: true, identity: ledger.identity, authorization: existing });
  }
  const restoredSha256 = digestBytes(stableReadFile(storePath, "restored finalization store"));
  if (restoredSha256 !== existing.snapshot.storeSnapshotSha256) {
    throw new Error("Restored lifecycle.sqlite bytes differ from the authorized snapshot entry.");
  }
  const database = openReadOnlyDatabasePath(storePath);
  let restored;
  try { database.exec("pragma query_only = on"); restored = readLedgerFromDatabase(database, storePath, key); }
  finally { database.close(); }
  if (canonicalJson(controlHeadFromLedger(restored)) !== canonicalJson(existing.target)) {
    throw new Error("Restored lifecycle SQLite head differs from the authorized lower target.");
  }
  const next = authenticatedControlRecord({
    key,
    storePath,
    initialization: control.initialization,
    anchor: restored.anchor,
    controlEpoch: control.controlEpoch + 1,
    previousControlTag: control.controlTag,
    storeFile: fileIdentity(storePath),
    databaseIdentity: databaseIdentityFromLedger(restored),
    current: existing.target,
    pending: null,
    rollbackAuthorization: inspected.authorization,
  });
  const lock = acquireControlLock({
    controlPath, storePath, key, lockKind: "ROLLBACK",
    intent: { expectedControlDigest: digestJson(control), authorization: inspected.authorization },
    now: () => inspected.authorization.restore.verifiedAt,
  });
  const lockedControl = readAuthenticatedControl(controlPath, storePath, key);
  if (canonicalJson(lockedControl) !== canonicalJson(control)) {
    releaseControlLock(controlLockPath(controlPath), lock);
    throw new Error("Finalization rollback predecessor changed before VERIFIED publication; semantic conflict.");
  }
  replaceOwnerOnlyJsonCas(controlPath, control, next, "finalization rollback VERIFIED control", lock);
  releaseControlLock(controlLockPath(controlPath), lock);
  const ledger = readFinalizationStoreLedger({ storePath, controlPath, key });
  return Object.freeze({ resumed: false, identity: ledger.identity, authorization: next.rollbackAuthorization });
}

export function assertImmutableFinalizationExecution(options) {
  const configuration = requiredObject(options, "immutable finalization execution options");
  const releaseRoot = canonicalRealDirectory(configuration.releaseRoot, "immutable release root");
  const modulePath = canonicalRealFile(configuration.modulePath, "finalization module");
  const moduleRelativePath = toPosix(relative(releaseRoot, modulePath));
  if (!isSameOrInside(releaseRoot, modulePath)
    || moduleRelativePath !== requiredText(configuration.expectedModulePath, "expected finalization module path")) {
    throw new Error("Finalization module is not executing from its exact immutable release root.");
  }
  const manifestPath = canonicalRealFile(join(releaseRoot, "BUILD-MANIFEST.json"), "release BUILD-MANIFEST");
  const checksumsPath = canonicalRealFile(join(releaseRoot, "SHA256SUMS"), "release SHA256SUMS");
  const manifestBytes = stableReadFile(manifestPath, "release BUILD-MANIFEST");
  const checksumsBytes = stableReadFile(checksumsPath, "release SHA256SUMS");
  const manifestSha256 = digestBytes(manifestBytes);
  const checksumsSha256 = digestBytes(checksumsBytes);
  if (manifestSha256 !== configuration.manifestSha256
    || checksumsSha256 !== configuration.checksumsSha256) {
    throw new Error("Immutable release manifest/checksum identity differs from the upgrade request.");
  }
  const manifest = parseJsonBytes(manifestBytes, "release BUILD-MANIFEST");
  if (manifest?.manifestVersion !== 2
    || !Array.isArray(manifest.payloadFiles)
    || !Array.isArray(manifest.runtimeFiles)) {
    throw new Error("Immutable release manifest shape is invalid.");
  }
  const checksums = parseChecksumManifest(checksumsBytes.toString("utf8"));
  const requiredModules = [...new Set([
    "scripts/lib/finalization-store-contract.mjs",
    "scripts/lib/finalization-store-contract.d.mts",
    "scripts/lib/finalization-state.mjs",
    "scripts/lib/finalization-state.d.mts",
    "scripts/lib/base-profile-gate-evidence.mjs",
    "scripts/lib/base-profile-gate-evidence.d.mts",
    "scripts/finalization-live-driver.mjs",
    "scripts/lib/release-artifacts.mjs",
    "dist/v2/connector-activation-evidence.js",
    ...manifest.runtimeFiles,
  ])].sort(compareCodeUnits);
  for (const path of requiredModules) {
    if (!manifest.payloadFiles.includes(path) || !checksums.has(path)) {
      throw new Error(`Immutable finalization module closure is incomplete: ${path}`);
    }
    const absolute = canonicalRealFile(resolveContained(releaseRoot, path), `immutable module closure ${path}`);
    const observed = createHash("sha256").update(stableReadFile(absolute, `immutable module closure ${path}`)).digest("hex");
    if (observed !== checksums.get(path)) {
      throw new Error(`Immutable finalization module closure digest changed: ${path}`);
    }
  }
  return Object.freeze({
    releaseRoot,
    modulePath,
    moduleRelativePath,
    manifestSha256,
    checksumsSha256,
    closureDigest: domainDigest("devspace.finalization-module-closure.v1", requiredModules.map((path) => ({
      path,
      sha256: `sha256:${checksums.get(path)}`,
    }))),
    manifest,
  });
}

export function commitPreparedFinalization(options) {
  const configuration = requiredObject(options, "prepared finalization commit options");
  const record = canonicalClone(requiredObject(configuration.record, "prepared finalization record"));
  validatePreparedRecordForCommit(record);
  const current = readFinalizationStoreIdentity({ storePath: configuration.storePath, controlPath: configuration.controlPath, key: configuration.key });
  if (canonicalJson(record.finalizationStore) !== canonicalJson(current)) {
    if (current.state === "PREPARED" && current.transactionId === record.transactionId) {
      const existing = preparedRecordFromLedger(readFinalizationStoreLedger({
        storePath: configuration.storePath,
        controlPath: configuration.controlPath,
        key: configuration.key,
      }));
      if (canonicalJson(existing) !== canonicalJson(record)) {
        throw new Error("Prepared finalization replay differs from the authenticated ledger.");
      }
      return Object.freeze({ resumed: true, identity: current, record: existing });
    }
    throw new Error("Prepared record is not bound to the current authenticated DRAFT identity.");
  }
  if (record.inputDigest !== digestJson(record.input)) {
    throw new Error("Prepared finalization inputDigest does not match its exact canonical input.");
  }
  const result = appendExactTransition({
    storePath: configuration.storePath,
    controlPath: configuration.controlPath,
    key: configuration.key,
    transactionId: record.transactionId,
    expectedState: "DRAFT",
    nextState: "PREPARED",
    kind: "FINALIZATION_PREPARED",
    payload: { record },
    now: configuration.now ?? (() => record.preparedAt),
  });
  return Object.freeze({ resumed: result.resumed, identity: result.identity, record });
}

export async function commitProfileGatesEvaluated(options) {
  const configuration = requiredObject(options, "profile gate evaluation commit options");
  const ledger = readFinalizationStoreLedger({ storePath: configuration.storePath, controlPath: configuration.controlPath, key: configuration.key });
  const prepared = preparedRecordFromLedger(ledger);
  assertTransaction(configuration.transactionId, prepared.transactionId);
  if (ledger.identity.state === "PROFILE_GATES_EVALUATED") {
    const event = requireEvent(ledger, "PROFILE_GATES_EVALUATED", "PROFILE_GATES_EVALUATED");
    validateProfileEvaluation(event.payload.evaluation);
    return Object.freeze({ resumed: true, identity: ledger.identity, evaluation: event.payload.evaluation });
  }
  if (ledger.identity.state !== "PREPARED") {
    throw new Error(`Profile gates require PREPARED, observed ${ledger.identity.state}.`);
  }
  let evaluation;
  if (configuration.evaluation) {
    evaluation = canonicalClone(configuration.evaluation);
  } else {
    const evaluator = await import("./base-profile-gate-evidence.mjs");
    evaluation = evaluator.evaluateBaseProfilePreCutoverEvidence({
      manifestPath: prepared.gateEvidence.manifestPath,
      manifestSha256: prepared.gateEvidence.manifestSha256,
      expectedBindings: prepared.gateEvidence.expectedBindings,
      releaseRoot: prepared.releasePackage,
      key: configuration.key,
      executables: prepared.productionSources.executables,
      environment: prepared.productionSources.environment,
      requirePostCutoverAbsent: true,
    });
  }
  validateProfileEvaluation(evaluation);
  const result = appendExactTransition({
    storePath: configuration.storePath,
    controlPath: configuration.controlPath,
    key: configuration.key,
    transactionId: prepared.transactionId,
    expectedState: "PREPARED",
    nextState: "PROFILE_GATES_EVALUATED",
    kind: "PROFILE_GATES_EVALUATED",
    payload: { evaluation },
    now: configuration.now,
  });
  return Object.freeze({ resumed: result.resumed, identity: result.identity, evaluation });
}

export function commitActivationPending(options) {
  const configuration = requiredObject(options, "activation pending commit options");
  const ledger = readFinalizationStoreLedger({ storePath: configuration.storePath, controlPath: configuration.controlPath, key: configuration.key });
  const prepared = preparedRecordFromLedger(ledger);
  assertTransaction(configuration.transactionId, prepared.transactionId);
  if (ledger.identity.state === "ACTIVATION_PENDING") {
    const event = requireEvent(ledger, "ACTIVATION_PENDING", "ACTIVATION_PENDING");
    validateActivationPendingPayload(event.payload, prepared, ledger, {
      approvalId: event.payload.activationApprovalId,
      receiptId: event.payload.activationReceiptId,
    });
    return Object.freeze({ resumed: true, identity: ledger.identity, binding: event.payload });
  }
  if (ledger.identity.state !== "PROFILE_GATES_EVALUATED") {
    throw new Error(`Activation pending requires PROFILE_GATES_EVALUATED, observed ${ledger.identity.state}.`);
  }
  const profile = requireEvent(ledger, "PROFILE_GATES_EVALUATED", "PROFILE_GATES_EVALUATED");
  validateProfileEvaluation(profile.payload.evaluation);
  const activation = configuration.activationBinding
    ? canonicalClone(requiredObject(configuration.activationBinding, "activation pending binding"))
    : prepared.productionSources.activation;
  const payload = {
    activationApprovalId: requiredText(activation.approvalId, "activation approvalId"),
    activationReceiptId: requiredText(activation.receiptId, "activation receiptId"),
    productionSourcesDigest: digestJson(prepared.productionSources),
    profileEvaluationDigest: digestJson(profile.payload.evaluation),
  };
  validateActivationPendingPayload(payload, prepared, ledger, activation);
  const result = appendExactTransition({
    storePath: configuration.storePath,
    controlPath: configuration.controlPath,
    key: configuration.key,
    transactionId: prepared.transactionId,
    expectedState: "PROFILE_GATES_EVALUATED",
    nextState: "ACTIVATION_PENDING",
    kind: "ACTIVATION_PENDING",
    payload,
    now: configuration.now,
  });
  return Object.freeze({ resumed: result.resumed, identity: result.identity, binding: payload });
}

export function commitPostActivationVerified(options) {
  const configuration = requiredObject(options, "post-activation verification commit options");
  const ledger = readFinalizationStoreLedger({ storePath: configuration.storePath, controlPath: configuration.controlPath, key: configuration.key });
  const prepared = preparedRecordFromLedger(ledger);
  assertTransaction(configuration.transactionId, prepared.transactionId);
  const proof = readExactPostActivationProof(configuration, prepared, ledger);
  const payload = {
    activatedAt: proof.activatedAt,
    activationReceiptId: proof.activationReceiptId,
    gateResult: proof.gateResult,
    postActivationEvidenceDigest: proof.postActivationEvidenceDigest,
  };
  if (ledger.identity.state === "POST_ACTIVATION_VERIFIED") {
    const event = requireEvent(ledger, "POST_ACTIVATION_VERIFIED", "POST_ACTIVATION_VERIFIED");
    validatePostActivationPayload(event, prepared, ledger);
    if (canonicalJson(event.payload) !== canonicalJson(payload)) {
      throw new Error("POST_ACTIVATION_VERIFIED replay proof differs from the authenticated event.");
    }
    return Object.freeze({ resumed: true, identity: ledger.identity, binding: event.payload });
  }
  if (ledger.identity.state !== "ACTIVATION_PENDING") {
    throw new Error(`Post-activation verification requires ACTIVATION_PENDING, observed ${ledger.identity.state}.`);
  }
  validatePostActivationPayload({ kind: "POST_ACTIVATION_VERIFIED", payload }, prepared, ledger);
  const result = appendExactTransition({
    storePath: configuration.storePath,
    controlPath: configuration.controlPath,
    key: configuration.key,
    transactionId: prepared.transactionId,
    expectedState: "ACTIVATION_PENDING",
    nextState: "POST_ACTIVATION_VERIFIED",
    kind: "POST_ACTIVATION_VERIFIED",
    payload,
    now: configuration.now ?? (() => proof.activatedAt),
  });
  return Object.freeze({ resumed: result.resumed, identity: result.identity, binding: payload });
}

export function commitDraining(options) {
  const configuration = requiredObject(options, "draining commit options");
  const ledger = readFinalizationStoreLedger({ storePath: configuration.storePath, controlPath: configuration.controlPath, key: configuration.key });
  const prepared = preparedRecordFromLedger(ledger);
  assertTransaction(configuration.transactionId, prepared.transactionId);
  if (ledger.identity.state === "DRAINING") {
    const event = requireEvent(ledger, "DRAINING", "DRAINING");
    validateDrainingPayload(event.payload, prepared, ledger);
    return Object.freeze({ resumed: true, identity: ledger.identity, binding: event.payload });
  }
  if (ledger.identity.state !== "POST_ACTIVATION_VERIFIED") {
    throw new Error(`Draining requires POST_ACTIVATION_VERIFIED, observed ${ledger.identity.state}.`);
  }
  const post = requireEvent(ledger, "POST_ACTIVATION_VERIFIED", "POST_ACTIVATION_VERIFIED");
  const activation = requireEvent(ledger, "ACTIVATION_PENDING", "ACTIVATION_PENDING");
  const payload = {
    activationReceiptId: activation.payload.activationReceiptId,
    postActivationGateEvidenceDigest: post.payload.gateResult.evidenceDigest,
    previousBindingId: prepared.productionSources.activation.previousBindingId ?? null,
  };
  validateDrainingPayload(payload, prepared, ledger);
  const result = appendExactTransition({
    storePath: configuration.storePath,
    controlPath: configuration.controlPath,
    key: configuration.key,
    transactionId: prepared.transactionId,
    expectedState: "POST_ACTIVATION_VERIFIED",
    nextState: "DRAINING",
    kind: "DRAINING",
    payload,
    now: configuration.now,
  });
  return Object.freeze({ resumed: result.resumed, identity: result.identity, binding: payload });
}

export function commitCanonicalFinalizationSeal(options) {
  const configuration = requiredObject(options, "canonical finalization seal commit options");
  const ledger = readFinalizationStoreLedger({ storePath: configuration.storePath, controlPath: configuration.controlPath, key: configuration.key });
  const prepared = preparedRecordFromLedger(ledger);
  assertTransaction(configuration.transactionId, prepared.transactionId);
  const proof = readProofArtifact(configuration.sealProofArtifact, "canonical finalization seal proof");
  validateCanonicalSealProof(proof);
  const payload = {
    finalArtifactsDigest: proof.finalArtifactsDigest,
    finalGateResultsDigest: proof.finalGateResultsDigest,
    residueEvidenceDigest: proof.residueEvidenceDigest,
    sealInputDigest: proof.sealInputDigest,
    sealedAt: proof.sealedAt,
  };
  if (ledger.identity.state === "SEALED") {
    const event = requireEvent(ledger, "FINALIZATION_SEALED", "SEALED");
    validateSealedPayload(event);
    if (canonicalJson(event.payload) !== canonicalJson(payload)) {
      throw new Error("SEALED replay proof differs from the authenticated event.");
    }
    return Object.freeze({ resumed: true, identity: ledger.identity, seal: event.payload });
  }
  if (ledger.identity.state !== "DRAINING") {
    throw new Error(`Canonical finalization seal requires DRAINING, observed ${ledger.identity.state}.`);
  }
  const result = appendExactTransition({
    storePath: configuration.storePath,
    controlPath: configuration.controlPath,
    key: configuration.key,
    transactionId: prepared.transactionId,
    expectedState: "DRAINING",
    nextState: "SEALED",
    kind: "FINALIZATION_SEALED",
    payload,
    now: configuration.now ?? (() => proof.sealedAt),
  });
  return Object.freeze({ resumed: result.resumed, identity: result.identity, seal: payload });
}

export function commitBaseProfileFinalPass(options) {
  const configuration = requiredObject(options, "Base profile final PASS commit options");
  const ledger = readFinalizationStoreLedger({ storePath: configuration.storePath, controlPath: configuration.controlPath, key: configuration.key });
  const prepared = preparedRecordFromLedger(ledger);
  assertTransaction(configuration.transactionId, prepared.transactionId);
  const proof = readProofArtifact(configuration.finalPassProofArtifact, "Base profile final PASS proof");
  validateBaseProfileFinalPassProof(proof, ledger);
  const payload = {
    completedAt: proof.completedAt,
    finalDigest: proof.finalDigest,
    finalManifestDigest: proof.finalManifestDigest,
    finalReportDigest: proof.finalReportDigest,
  };
  if (ledger.identity.state === "BASE_PROFILE_FINAL_PASS") {
    const event = requireEvent(ledger, "BASE_PROFILE_FINAL_PASS", "BASE_PROFILE_FINAL_PASS");
    validateBaseFinalPayload(event);
    if (canonicalJson(event.payload) !== canonicalJson(payload)) {
      throw new Error("BASE_PROFILE_FINAL_PASS replay proof differs from the authenticated event.");
    }
    return Object.freeze({ resumed: true, identity: ledger.identity, finalPass: event.payload });
  }
  if (ledger.identity.state !== "SEALED") {
    throw new Error(`Base profile final PASS requires SEALED, observed ${ledger.identity.state}.`);
  }
  const result = appendExactTransition({
    storePath: configuration.storePath,
    controlPath: configuration.controlPath,
    key: configuration.key,
    transactionId: prepared.transactionId,
    expectedState: "SEALED",
    nextState: "BASE_PROFILE_FINAL_PASS",
    kind: "BASE_PROFILE_FINAL_PASS",
    payload,
    now: configuration.now ?? (() => proof.completedAt),
  });
  return Object.freeze({ resumed: result.resumed, identity: result.identity, finalPass: payload });
}

export function commitFinalizationError(options) {
  const configuration = requiredObject(options, "finalization error commit options");
  const ledger = readFinalizationStoreLedger({ storePath: configuration.storePath, controlPath: configuration.controlPath, key: configuration.key });
  const prepared = preparedRecordFromLedger(ledger);
  assertTransaction(configuration.transactionId, prepared.transactionId);
  if (!ERROR_FINALIZATION_STATES.includes(configuration.terminalState)) {
    throw new Error("Finalization error terminal must be FAILED or UNKNOWN.");
  }
  const reasonCode = requiredReasonCode(configuration.reasonCode);
  const evidencePath = canonicalOwnerOnlyFile(resolve(requiredText(configuration.evidencePath, "error evidencePath")), "finalization error evidence");
  const evidenceSha256 = digestBytes(readFileSync(evidencePath));
  const payload = { evidencePath, evidenceSha256, reasonCode };
  const result = appendExactTransition({
    storePath: configuration.storePath,
    controlPath: configuration.controlPath,
    key: configuration.key,
    transactionId: prepared.transactionId,
    expectedState: ledger.identity.state,
    nextState: configuration.terminalState,
    kind: configuration.terminalState === "FAILED" ? "FINALIZATION_FAILED" : "FINALIZATION_UNKNOWN",
    payload,
    now: configuration.now,
  });
  return Object.freeze({ resumed: result.resumed, identity: result.identity });
}

export function readFinalizationStoreLedger(options) {
  const configuration = requiredObject(options, "finalization store read options");
  const key = normalizeManagementKey(configuration.key);
  const storePath = canonicalOwnerOnlyFile(
    canonicalLifecycleStorePath(configuration.storePath, false),
    "finalization store",
  );
  const controlPath = canonicalControlPath(configuration.controlPath, storePath, false);
  const lockPath = controlLockPath(controlPath);
  if (lstatIfPresent(lockPath) || lstatIfPresent(`${lockPath}.recovery`)) {
    throw new Error("Finalization external control has an unresolved durable lock; state is UNKNOWN until explicit recovery.");
  }
  assertNoUnboundSqliteMutationResidue(storePath, null);
  const control = readAuthenticatedControl(controlPath, storePath, key);
  if (control.pending !== null) {
    throw new Error("Finalization external control contains an unresolved PENDING intent; state is UNKNOWN until exact reconciliation.");
  }
  const database = openReadOnlyFinalizationStore(storePath, control);
  try {
    database.exec("pragma query_only = on");
    const queryOnly = database.prepare("pragma query_only").get();
    if (Number(firstColumn(queryOnly)) !== 1) {
      throw new Error("Finalization store readback is not query-only.");
    }
    const ledger = readLedgerFromDatabase(database, storePath, key);
    assertControlMatchesLedger(control, ledger, storePath);
    const preSnapshotIdentity = Object.freeze({
      storeId: ledger.identity.storeId,
      schemaVersion: ledger.identity.schemaVersion,
      state: ledger.identity.state,
      revision: ledger.identity.revision,
      transactionId: ledger.identity.transactionId,
      contentGeneration: ledger.identity.contentGeneration,
      keyId: ledger.identity.keyId,
      controlEpoch: control.controlEpoch,
      controlTag: control.controlTag,
    });
    const identity = Object.freeze({
      ...ledger.identity,
      controlEpoch: control.controlEpoch,
      controlTag: control.controlTag,
      preSnapshotIdentity,
      preSnapshotIdentityDigest: digestJson(preSnapshotIdentity),
    });
    return Object.freeze({ ...ledger, identity, control: Object.freeze(control), controlPath });
  } finally {
    database.close();
  }
}

function appendExactTransition(options) {
  const configuration = requiredObject(options, "exact finalization transition");
  const key = normalizeManagementKey(configuration.key);
  const storePath = canonicalOwnerOnlyFile(
    canonicalLifecycleStorePath(configuration.storePath, false),
    "finalization store",
  );
  const controlPath = canonicalControlPath(configuration.controlPath, storePath, false);
  const transactionId = requiredTransactionId(configuration.transactionId);
  const expectedState = requiredState(configuration.expectedState, true);
  const nextState = requiredState(configuration.nextState, false);
  assertAllowedFinalizationTransition(expectedState, nextState);
  const kind = requiredText(configuration.kind, "exact finalization event kind");
  const payload = canonicalClone(requiredObject(configuration.payload, "exact finalization event payload"));
  const payloadJson = canonicalJson(payload);
  const payloadDigest = digestText(payloadJson);
  const occurredAt = normalizedNow(configuration.now);
  if (lstatIfPresent(controlLockPath(controlPath))) {
    throw new Error("Finalization control lock conflict; ordinary append cannot adopt another process intent.");
  }
  const before = readFinalizationStoreLedger({ storePath, controlPath, key });
  if (before.identity.transactionId && before.identity.transactionId !== transactionId) {
    throw new Error("Finalization transaction identity differs from the authenticated ledger.");
  }
  if (before.identity.state === nextState) {
    const last = before.events.at(-1);
    if (!last || last.transactionId !== transactionId || last.fromState !== expectedState
      || last.toState !== nextState || last.kind !== kind || last.payloadJson !== payloadJson) {
      throw new Error("Exact finalization transition replay differs from the authenticated event.");
    }
    return Object.freeze({ resumed: true, identity: before.identity, event: last });
  }
  if (before.identity.state !== expectedState) {
    throw new Error(`Finalization lifecycle expected ${expectedState}, observed ${before.identity.state}.`);
  }
  if (Date.parse(occurredAt) < Date.parse(before.identity.updatedAt)) {
    throw new Error("Finalization transition timestamp precedes the authenticated ledger; no mutation performed.");
  }

  const event = buildAuthenticatedEvent({
    key,
    anchorNonce: before.anchor.anchorNonce,
    sequence: before.events.length + 1,
    transactionId,
    fromState: expectedState,
    toState: nextState,
    kind,
    payloadJson,
    payloadDigest,
    occurredAt,
    previousTransitionTag: before.events.at(-1)?.transitionTag ?? before.anchor.anchorTag,
  });
  const pendingPublication = writePendingControl({ controlPath, storePath, key, before, event });
  const pendingControl = pendingPublication.control;
  const writable = openWritableFinalizationStore(
    storePath,
    controlPath,
    pendingControl,
    pendingPublication.lock,
  );
  const { database } = writable;
  try {
    database.exec("begin immediate");
    try {
      const count = Number(firstColumn(database.prepare("select count(*) from finalization_events").get()));
      const last = database.prepare(`
        select to_state as toState, transition_tag as transitionTag
          from finalization_events order by sequence desc limit 1
      `).get();
      const observedState = last?.toState ?? "DRAFT";
      const observedTag = last?.transitionTag
        ?? database.prepare("select anchor_tag as anchorTag from finalization_anchor where singleton = 1").get()?.anchorTag;
      if (count !== before.events.length || observedState !== expectedState
        || observedTag !== (before.events.at(-1)?.transitionTag ?? before.anchor.anchorTag)) {
        throw new Error("Finalization ledger changed while acquiring the exact append lock.");
      }
      database.prepare(`
        insert into finalization_events
          (sequence, transaction_id, from_state, to_state, kind, payload_json,
           payload_digest, occurred_at, previous_transition_tag, event_tag,
           transition_tag, final_tag)
        values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      `).run(
        event.sequence, event.transactionId, event.fromState, event.toState, event.kind, event.payloadJson,
        event.payloadDigest, event.occurredAt, event.previousTransitionTag, event.eventTag,
        event.transitionTag, event.finalTag,
      );
      database.exec("commit");
      database.prepare("pragma wal_checkpoint(truncate)").all();
    } catch (error) {
      try { database.exec("rollback"); } catch { /* preserve the exact commit error */ }
      throw error;
    }
  } finally { database.close(); }
  writable.publish();
  fsyncFile(storePath);
  fsyncDirectory(dirname(storePath));
  commitPendingControl({ controlPath, storePath, key, expectedPending: pendingControl, event, lock: pendingPublication.lock });
  const after = readFinalizationStoreLedger({ storePath, controlPath, key });
  return Object.freeze({ resumed: false, identity: after.identity, event: after.events.at(-1) });
}

function validatePreparedRecordForCommit(record) {
  assertExactObjectKeys(record, [
    "destructivePlan", "finalizationStore", "gateEvidence", "immutableIdentity", "input",
    "inputDigest", "moduleClosureDigest", "preparedAt", "productionSources", "releaseChecksumsSha256",
    "releaseManifestSha256", "releasePackage", "runtimeIdentity", "schemaVersion", "snapshotGroup",
    "sourceRevision", "state", "transactionId",
  ], "prepared finalization record");
  if (record.schemaVersion !== 2 || record.state !== "PREPARED") {
    throw new Error("Prepared finalization record identity is invalid.");
  }
  requiredTransactionId(record.transactionId);
  requiredText(record.sourceRevision, "prepared sourceRevision");
  requiredText(record.releasePackage, "prepared releasePackage");
  for (const [value, label] of [
    [record.inputDigest, "prepared inputDigest"],
    [record.moduleClosureDigest, "prepared moduleClosureDigest"],
    [record.releaseManifestSha256, "prepared releaseManifestSha256"],
    [record.releaseChecksumsSha256, "prepared releaseChecksumsSha256"],
  ]) requireDigest(value, label);
  if (!isCanonicalTimestamp(record.preparedAt)) throw new Error("Prepared finalization timestamp is invalid.");
  requiredObject(record.input, "prepared exact input");
  requiredObject(record.runtimeIdentity, "prepared runtimeIdentity");
  requiredObject(record.immutableIdentity, "prepared immutableIdentity");
  requiredObject(record.snapshotGroup, "prepared snapshotGroup");
  requiredObject(record.gateEvidence, "prepared gateEvidence");
  requiredObject(record.productionSources, "prepared productionSources");
  if (!Array.isArray(record.destructivePlan)) throw new Error("Prepared destructivePlan is invalid.");
  requiredObject(record.finalizationStore, "prepared DRAFT store identity");
  const capturedAt = record.snapshotGroup?.manifest?.capturedAt;
  const groupDigest = record.snapshotGroup?.manifest?.groupDigest;
  if (!isCanonicalTimestamp(capturedAt) || !DIGEST_PATTERN.test(groupDigest ?? "")
    || Date.parse(record.preparedAt) <= Date.parse(capturedAt)
    || record.input?.requestBindingDigest !== record.snapshotGroup?.manifest?.barrier?.requestBindingDigest
    || record.input?.candidateIdentityDigest !== record.snapshotGroup?.manifest?.barrier?.candidateIdentityDigest
    || record.transactionId !== record.snapshotGroup?.manifest?.barrier?.transactionId) {
    throw new Error("PREPARED record is not causally bound after its exact snapshot/request/candidate barrier.");
  }
}

function validateProfileEvaluation(evaluation) {
  assertExactObjectKeys(evaluation, [
    "capabilities", "capabilitiesDigest", "gateResults", "gateResultsDigest",
    "manifestBindingDigest", "profileApplicability", "profileApplicabilityDigest", "thresholdDigest",
  ], "profile gate evaluation");
  for (const key of ["capabilitiesDigest", "gateResultsDigest", "manifestBindingDigest", "profileApplicabilityDigest", "thresholdDigest"]) {
    requireDigest(evaluation[key], `profile evaluation ${key}`);
  }
  if (!Array.isArray(evaluation.gateResults) || evaluation.gateResults.length !== 16
    || digestJson(evaluation.gateResults) !== evaluation.gateResultsDigest) {
    throw new Error("Profile gate evaluation result matrix is invalid.");
  }
  const expectedGates = [
    "G00 PROFILE", "G01 SOURCE", "G02 STATIC", "G03 UNIT", "G04 PROTOCOL", "G05 FUNCTIONAL",
    "G06 SECURITY", "G07 DURABILITY", "G08 LOAD", "G09 PACKAGE", "G10 STAGING", "G11 HOST",
    "G12 CONNECTOR", "G13 CUTOVER", "G16 CLEANUP", "G17 FINALIZATION",
  ];
  evaluation.gateResults.forEach((entry, index) => {
    const deferred = index >= 13;
    const expectedKeys = deferred
      ? ["applicability", "gate", "profile", "result"]
      : ["applicability", "evidenceDigest", "gate", "profile", "result"];
    assertExactObjectKeys(entry, expectedKeys, `profile gate ${expectedGates[index]}`);
    if (entry.gate !== expectedGates[index] || entry.profile !== "BASE_SINGLE_OWNER"
      || entry.applicability !== "REQUIRED" || entry.result !== (deferred ? "NOT_RUN" : "PASS")
      || (!deferred && !DIGEST_PATTERN.test(entry.evidenceDigest ?? ""))) {
      throw new Error("Profile gate evaluation temporal matrix is invalid.");
    }
  });
  if (!Array.isArray(evaluation.capabilities) || digestJson(evaluation.capabilities) !== evaluation.capabilitiesDigest) {
    throw new Error("Profile capability evaluation matrix is invalid.");
  }
  const noResidue = evaluation.capabilities.find((entry) => entry.capability === "no-residue");
  if (!noResidue || noResidue.result !== "NOT_RUN" || Object.hasOwn(noResidue, "evidenceDigest")) {
    throw new Error("Profile no-residue capability must remain exact NOT_RUN before canonical seal.");
  }
}

function validateActivationPendingPayload(payload, prepared, ledger, suppliedActivation = undefined) {
  assertExactObjectKeys(payload, [
    "activationApprovalId", "activationReceiptId", "productionSourcesDigest", "profileEvaluationDigest",
  ], "activation pending payload");
  const profile = requireEvent(ledger, "PROFILE_GATES_EVALUATED", "PROFILE_GATES_EVALUATED");
  const expectedActivation = suppliedActivation ?? prepared.productionSources.activation;
  if (payload.activationApprovalId !== expectedActivation.approvalId
    || payload.activationReceiptId !== expectedActivation.receiptId
    || payload.productionSourcesDigest !== digestJson(prepared.productionSources)
    || payload.profileEvaluationDigest !== digestJson(profile.payload.evaluation)) {
    throw new Error("Activation pending payload differs from prepared/profile-derived bindings.");
  }
}

function readExactPostActivationProof(configuration, prepared, ledger) {
  const proof = readProofArtifact(configuration.postActivationProofArtifact, "post-activation proof");
  validateExactPostActivationProof(proof, prepared, ledger);
  return proof;
}

function validateExactPostActivationProof(proof, prepared, ledger) {
  const activation = requireEvent(ledger, "ACTIVATION_PENDING", "ACTIVATION_PENDING");
  assertExactObjectKeys(proof, [
    "activatedAt", "activationReceiptId", "gateResult", "kind", "postActivationEvidenceDigest", "readback", "schemaVersion",
  ], "post-activation proof");
  if (proof.schemaVersion !== 1 || proof.kind !== "POST_ACTIVATION_VERIFIED_PROOF"
    || proof.activationReceiptId !== activation.payload.activationReceiptId
    || !isCanonicalTimestamp(proof.activatedAt)
    || !DIGEST_PATTERN.test(proof.postActivationEvidenceDigest ?? "")) {
    throw new Error("Post-activation proof is not bound to the prepared activation receipt.");
  }
  const readback = requiredObject(proof.readback, "post-activation canonical readback");
  assertExactObjectKeys(readback, ["installation", "postActivation", "runtimeEvidence"], "post-activation canonical readback");
  assertExactObjectKeys(readback.installation, [
    "activeBindingCount", "canonicalProcessCount", "legacyProcessCount", "residuePaths", "routeCount",
  ], "post-activation installation readback");
  if (readback.installation.activeBindingCount !== 1
    || readback.installation.canonicalProcessCount !== 1
    || readback.installation.legacyProcessCount !== 0
    || readback.installation.routeCount !== 1
    || !Array.isArray(readback.installation.residuePaths)
    || readback.installation.residuePaths.length !== 0
    || readback.postActivation?.receiptId !== proof.activationReceiptId
    || readback.postActivation?.state !== "POST_ACTIVATION_VERIFIED"
    || digestJson(readback) !== proof.postActivationEvidenceDigest) {
    throw new Error("Post-activation proof is not derived from the canonical runtime/route/connector readback.");
  }
  assertExactObjectKeys(proof.gateResult, ["applicability", "evidenceDigest", "gate", "profile", "result"], "post-activation G13 proof");
  if (proof.gateResult.profile !== "BASE_SINGLE_OWNER"
    || proof.gateResult.gate !== "G13 CUTOVER"
    || proof.gateResult.applicability !== "REQUIRED"
    || proof.gateResult.result !== "PASS"
    || proof.gateResult.evidenceDigest !== proof.postActivationEvidenceDigest) {
    throw new Error("Post-activation proof does not derive the exact G13 PASS evidence.");
  }
}

function validateDrainingPayload(payload, prepared, ledger) {
  assertExactObjectKeys(payload, ["activationReceiptId", "postActivationGateEvidenceDigest", "previousBindingId"], "draining payload");
  const post = requireEvent(ledger, "POST_ACTIVATION_VERIFIED", "POST_ACTIVATION_VERIFIED");
  const activation = requireEvent(ledger, "ACTIVATION_PENDING", "ACTIVATION_PENDING");
  if (payload.activationReceiptId !== activation.payload.activationReceiptId
    || payload.postActivationGateEvidenceDigest !== post.payload.gateResult.evidenceDigest
    || payload.previousBindingId !== (prepared.productionSources.activation.previousBindingId ?? null)) {
    throw new Error("Draining payload differs from prepared/POST-derived bindings.");
  }
}

function validateLedgerEventSemantics(ledger) {
  let prepared;
  for (const event of ledger.events) {
    if (event.toState === "PREPARED") {
      if (event.kind !== "FINALIZATION_PREPARED") throw new Error("PREPARED event kind is not canonical.");
      assertExactObjectKeys(event.payload, ["record"], "PREPARED event payload");
      validatePreparedRecordForCommit(event.payload.record);
      if (event.payload.record.transactionId !== event.transactionId
        || event.payload.record.inputDigest !== digestJson(event.payload.record.input)
        || event.payload.record.finalizationStore?.state !== "DRAFT") {
        throw new Error("PREPARED event payload is not derived from its exact input/DRAFT identity.");
      }
      prepared = event.payload.record;
      continue;
    }
    if (!prepared) throw new Error("Finalization event sequence lacks its canonical PREPARED predecessor.");
    if (event.toState === "PROFILE_GATES_EVALUATED") {
      if (event.kind !== "PROFILE_GATES_EVALUATED") throw new Error("PROFILE_GATES_EVALUATED event kind is not canonical.");
      assertExactObjectKeys(event.payload, ["evaluation"], "PROFILE_GATES_EVALUATED event payload");
      validateProfileEvaluation(event.payload.evaluation);
    } else if (event.toState === "ACTIVATION_PENDING") {
      if (event.kind !== "ACTIVATION_PENDING") throw new Error("ACTIVATION_PENDING event kind is not canonical.");
      validateActivationPendingPayload(event.payload, prepared, ledgerPrefix(ledger, event.sequence), {
        approvalId: event.payload.activationApprovalId,
        receiptId: event.payload.activationReceiptId,
      });
    } else if (event.toState === "POST_ACTIVATION_VERIFIED") {
      validatePostActivationPayload(event, prepared, ledgerPrefix(ledger, event.sequence));
    } else if (event.toState === "DRAINING") {
      if (event.kind !== "DRAINING") throw new Error("DRAINING event kind is not canonical.");
      validateDrainingPayload(event.payload, prepared, ledgerPrefix(ledger, event.sequence));
    } else if (event.toState === "SEALED") {
      validateSealedPayload(event);
    } else if (event.toState === "BASE_PROFILE_FINAL_PASS") {
      validateBaseFinalPayload(event);
    } else if (ERROR_FINALIZATION_STATES.includes(event.toState)) {
      const expectedKind = event.toState === "FAILED" ? "FINALIZATION_FAILED" : "FINALIZATION_UNKNOWN";
      if (event.kind !== expectedKind) throw new Error("Finalization error event kind is not canonical.");
      assertExactObjectKeys(event.payload, ["evidencePath", "evidenceSha256", "reasonCode"], "finalization error payload");
      requiredText(event.payload.evidencePath, "finalization error evidencePath");
      requireDigest(event.payload.evidenceSha256, "finalization error evidenceSha256");
      requiredReasonCode(event.payload.reasonCode);
    } else {
      throw new Error(`Unsupported authenticated lifecycle event: ${event.toState}`);
    }
  }
}

function ledgerPrefix(ledger, inclusiveSequence) {
  return Object.freeze({ ...ledger, events: Object.freeze(ledger.events.slice(0, inclusiveSequence)) });
}

function validatePostActivationPayload(event, prepared, ledger) {
  if (event.kind !== "POST_ACTIVATION_VERIFIED") throw new Error("POST_ACTIVATION_VERIFIED event kind is not canonical.");
  assertExactObjectKeys(event.payload, [
    "activatedAt", "activationReceiptId", "gateResult", "postActivationEvidenceDigest",
  ], "POST_ACTIVATION_VERIFIED event payload");
  const gate = event.payload.gateResult;
  assertExactObjectKeys(gate, ["applicability", "evidenceDigest", "gate", "profile", "result"], "G13 cutover result");
  const activation = requireEvent(ledger, "ACTIVATION_PENDING", "ACTIVATION_PENDING");
  if (event.payload.activationReceiptId !== activation.payload.activationReceiptId
    || !isCanonicalTimestamp(event.payload.activatedAt)
    || gate.profile !== "BASE_SINGLE_OWNER" || gate.gate !== "G13 CUTOVER"
    || gate.applicability !== "REQUIRED" || gate.result !== "PASS"
    || !DIGEST_PATTERN.test(gate.evidenceDigest ?? "")
    || event.payload.postActivationEvidenceDigest !== gate.evidenceDigest) {
    throw new Error("POST_ACTIVATION_VERIFIED payload is not the exact derived G13 binding.");
  }
}

function validateSealedPayload(event) {
  if (event.kind !== "FINALIZATION_SEALED") throw new Error("SEALED event kind is not canonical.");
  assertExactObjectKeys(event.payload, [
    "finalArtifactsDigest", "finalGateResultsDigest", "residueEvidenceDigest", "sealInputDigest", "sealedAt",
  ], "SEALED event payload");
  for (const key of ["finalArtifactsDigest", "finalGateResultsDigest", "residueEvidenceDigest", "sealInputDigest"]) {
    requireDigest(event.payload[key], `SEALED ${key}`);
  }
  if (!isCanonicalTimestamp(event.payload.sealedAt)) throw new Error("SEALED timestamp is invalid.");
}

function validateCanonicalSealProof(proof) {
  assertExactObjectKeys(proof, [
    "finalArtifactsDigest", "finalGateResults", "finalGateResultsDigest", "kind", "residueEvidence",
    "residueEvidenceDigest", "schemaVersion", "sealInputDigest", "sealedAt",
  ], "canonical finalization seal proof");
  if (proof.schemaVersion !== 1 || proof.kind !== "FINALIZATION_SEAL_PROOF"
    || !isCanonicalTimestamp(proof.sealedAt)) {
    throw new Error("Canonical finalization seal proof identity is invalid.");
  }
  for (const key of ["finalArtifactsDigest", "finalGateResultsDigest", "residueEvidenceDigest", "sealInputDigest"]) {
    requireDigest(proof[key], `canonical finalization seal proof ${key}`);
  }
  if (!Array.isArray(proof.finalGateResults) || proof.finalGateResults.length !== 16
    || digestJson(proof.finalGateResults) !== proof.finalGateResultsDigest) {
    throw new Error("Canonical finalization seal gate results are incomplete or changed.");
  }
  const expectedGates = [
    "G00 PROFILE", "G01 SOURCE", "G02 STATIC", "G03 UNIT", "G04 PROTOCOL", "G05 FUNCTIONAL",
    "G06 SECURITY", "G07 DURABILITY", "G08 LOAD", "G09 PACKAGE", "G10 STAGING", "G11 HOST",
    "G12 CONNECTOR", "G13 CUTOVER", "G16 CLEANUP", "G17 FINALIZATION",
  ];
  proof.finalGateResults.forEach((entry, index) => {
    assertExactObjectKeys(entry, ["applicability", "evidenceDigest", "gate", "profile", "result"], `sealed gate ${expectedGates[index]}`);
    if (entry.gate !== expectedGates[index] || entry.profile !== "BASE_SINGLE_OWNER"
      || entry.applicability !== "REQUIRED" || entry.result !== "PASS"
      || !DIGEST_PATTERN.test(entry.evidenceDigest ?? "")) {
      throw new Error("Canonical finalization seal does not contain the exact all-PASS Base gate matrix.");
    }
  });
  const residue = requiredObject(proof.residueEvidence, "canonical residue evidence");
  assertExactObjectKeys(residue, [
    "canonicalProcessCount", "currentAuditTarget", "legacyProcessNames", "residuePaths", "routeCount",
  ], "canonical residue evidence");
  if (residue.canonicalProcessCount !== 1 || residue.routeCount !== 1
    || !Array.isArray(residue.legacyProcessNames) || residue.legacyProcessNames.length !== 0
    || !Array.isArray(residue.residuePaths) || residue.residuePaths.length !== 0
    || typeof residue.currentAuditTarget !== "string" || residue.currentAuditTarget.length === 0
    || digestJson(residue) !== proof.residueEvidenceDigest) {
    throw new Error("Canonical finalization seal residue evidence is not exact zero-residue readback.");
  }
}

function validateBaseFinalPayload(event) {
  if (event.kind !== "BASE_PROFILE_FINAL_PASS") throw new Error("BASE_PROFILE_FINAL_PASS event kind is not canonical.");
  assertExactObjectKeys(event.payload, ["completedAt", "finalDigest", "finalManifestDigest", "finalReportDigest"], "BASE final payload");
  for (const key of ["finalDigest", "finalManifestDigest", "finalReportDigest"]) requireDigest(event.payload[key], `BASE final ${key}`);
  if (!isCanonicalTimestamp(event.payload.completedAt)) throw new Error("BASE final timestamp is invalid.");
}

function validateBaseProfileFinalPassProof(proof, ledger) {
  assertExactObjectKeys(proof, [
    "completedAt", "finalDigest", "finalManifest", "finalManifestDigest", "finalReport",
    "finalReportDigest", "kind", "schemaVersion",
  ], "Base profile final PASS proof");
  if (proof.schemaVersion !== 1 || proof.kind !== "BASE_PROFILE_FINAL_PASS_PROOF"
    || !isCanonicalTimestamp(proof.completedAt)) {
    throw new Error("Base profile final PASS proof identity is invalid.");
  }
  for (const key of ["finalDigest", "finalManifestDigest", "finalReportDigest"]) {
    requireDigest(proof[key], `Base profile final PASS proof ${key}`);
  }
  if (digestJson(proof.finalManifest) !== proof.finalManifestDigest
    || digestJson(proof.finalReport) !== proof.finalReportDigest) {
    throw new Error("Base profile final PASS proof report/manifest bytes are not digest-bound.");
  }
  const sealed = requireEvent(ledger, "FINALIZATION_SEALED", "SEALED");
  if (proof.finalReport?.status !== "BASE_PROFILE_FINAL_PASS"
    || proof.finalReport?.gateResultsDigest !== sealed.payload.finalGateResultsDigest
    || proof.finalManifest?.finalArtifactsDigest !== sealed.payload.finalArtifactsDigest
    || proof.finalManifest?.residueEvidenceDigest !== sealed.payload.residueEvidenceDigest
    || proof.finalDigest !== digestJson({
      finalManifestDigest: proof.finalManifestDigest,
      finalReportDigest: proof.finalReportDigest,
      sealInputDigest: sealed.payload.sealInputDigest,
    })) {
    throw new Error("Base profile final PASS proof is not derived from the authenticated seal and durable outputs.");
  }
}

function readProofArtifact(reference, label) {
  const artifact = requiredObject(reference, `${label} artifact reference`);
  assertExactObjectKeys(artifact, ["path", "sha256"], `${label} artifact reference`);
  const path = canonicalOwnerOnlyFile(resolve(requiredText(artifact.path, `${label} path`)), label);
  const bytes = stableReadFile(path, label);
  if (digestBytes(bytes) !== requireDigest(artifact.sha256, `${label} sha256`)) {
    throw new Error(`${label} bytes differ from their immutable artifact reference.`);
  }
  return parseJsonBytes(bytes, label);
}

function preparedRecordFromLedger(ledger) {
  const event = requireEvent(ledger, "FINALIZATION_PREPARED", "PREPARED");
  const record = event.payload?.record;
  validatePreparedRecordForCommit(record);
  if (record.inputDigest !== digestJson(record.input)
    || record.transactionId !== event.transactionId
    || record.finalizationStore?.state !== "DRAFT") {
    throw new Error("Authenticated PREPARED event record bindings are invalid.");
  }
  return record;
}

function requireEvent(ledger, kind, toState) {
  const matches = ledger.events.filter((event) => event.kind === kind && event.toState === toState);
  if (matches.length !== 1) throw new Error(`Authenticated lifecycle must contain exactly one ${kind} event.`);
  return matches[0];
}

function assertTransaction(actual, expected) {
  if (requiredTransactionId(actual) !== expected) throw new Error("Finalization transactionId differs from PREPARED.");
}

function requiredReasonCode(value) {
  const text = requiredText(value, "finalization reasonCode");
  if (!/^[A-Z][A-Z0-9_]{2,63}$/u.test(text)) throw new Error("Finalization reasonCode is not canonical.");
  return text;
}

function requireDigest(value, label) {
  if (!DIGEST_PATTERN.test(value ?? "")) throw new Error(`${label} is not a canonical SHA-256 digest.`);
  return value;
}

function assertExactObjectKeys(value, expected, label) {
  const actual = Object.keys(requiredObject(value, label)).sort(compareCodeUnits);
  const wanted = [...expected].sort(compareCodeUnits);
  if (canonicalJson(actual) !== canonicalJson(wanted)) {
    throw new Error(`${label} contains a missing or unsupported field.`);
  }
}

function readLedgerFromDatabase(database, storePath, key) {
  const integrityRows = database.prepare("pragma integrity_check").all();
  if (integrityRows.length !== 1 || firstColumn(integrityRows[0]) !== "ok") {
    throw new Error("Finalization store integrity check failed.");
  }
  const foreignKeyRows = database.prepare("pragma foreign_key_check").all();
  if (foreignKeyRows.length !== 0) {
    throw new Error("Finalization store foreign-key check failed.");
  }
  const userVersion = Number(firstColumn(database.prepare("pragma user_version").get()));
  if (userVersion !== FINALIZATION_STORE_SCHEMA_VERSION) {
    throw new Error(`Finalization store schema version mismatch: ${userVersion}`);
  }
  assertExactFinalizationSchema(database);
  const anchors = database.prepare("select * from finalization_anchor order by singleton").all();
  if (anchors.length !== 1) throw new Error("Finalization store must contain one authenticated anchor.");
  const anchorRow = anchors[0];
  if (anchorRow.singleton !== 1
    || anchorRow.store_id !== FINALIZATION_STORE_ID
    || anchorRow.schema_version !== FINALIZATION_STORE_SCHEMA_VERSION
    || anchorRow.migration_name !== FINALIZATION_STORE_MIGRATION_NAME
    || anchorRow.migration_checksum !== FINALIZATION_STORE_MIGRATION_CHECKSUM
    || anchorRow.schema_fingerprint !== FINALIZATION_STORE_SCHEMA_FINGERPRINT
    || anchorRow.key_id !== key.keyId
    || !NONCE_PATTERN.test(anchorRow.anchor_nonce)
    || !isCanonicalTimestamp(anchorRow.created_at)
    || !TAG_PATTERN.test(anchorRow.anchor_tag)) {
    throw new Error("Finalization store anchor identity is invalid or belongs to another key.");
  }
  const anchorPayload = {
    storeId: anchorRow.store_id,
    schemaVersion: anchorRow.schema_version,
    migrationName: anchorRow.migration_name,
    migrationChecksum: anchorRow.migration_checksum,
    schemaFingerprint: anchorRow.schema_fingerprint,
    anchorNonce: anchorRow.anchor_nonce,
    createdAt: anchorRow.created_at,
  };
  assertAuthenticationTag("ANCHOR", key, anchorPayload, anchorRow.anchor_tag);
  const anchor = Object.freeze({
    keyId: anchorRow.key_id,
    anchorNonce: anchorRow.anchor_nonce,
    createdAt: anchorRow.created_at,
    anchorTag: anchorRow.anchor_tag,
  });

  const rows = database.prepare(`
    select sequence, transaction_id as transactionId, from_state as fromState,
           to_state as toState, kind, payload_json as payloadJson,
           payload_digest as payloadDigest, occurred_at as occurredAt,
           previous_transition_tag as previousTransitionTag,
           event_tag as eventTag, transition_tag as transitionTag, final_tag as finalTag
      from finalization_events order by sequence
  `).all();
  const events = [];
  let state = "DRAFT";
  let transactionId = null;
  let previousTransitionTag = anchor.anchorTag;
  let previousOccurredAt = Date.parse(anchor.createdAt);
  for (let index = 0; index < rows.length; index += 1) {
    const row = rows[index];
    if (row.sequence !== index + 1
      || requiredTransactionId(row.transactionId) !== row.transactionId
      || row.fromState !== state
      || row.previousTransitionTag !== previousTransitionTag
      || !isCanonicalTimestamp(row.occurredAt)
      || Date.parse(row.occurredAt) < previousOccurredAt
      || !DIGEST_PATTERN.test(row.payloadDigest)
      || !TAG_PATTERN.test(row.eventTag)
      || !TAG_PATTERN.test(row.transitionTag)
      || (FINAL_STATES.includes(row.toState) ? !TAG_PATTERN.test(row.finalTag ?? "") : row.finalTag !== null)) {
      throw new Error("Finalization authenticated event chain is incomplete, foreign, or non-monotonic.");
    }
    assertAllowedFinalizationTransition(row.fromState, row.toState);
    if (transactionId !== null && transactionId !== row.transactionId) {
      throw new Error("Finalization authenticated event chain contains another transaction.");
    }
    transactionId = row.transactionId;
    let payload;
    try { payload = JSON.parse(row.payloadJson); } catch {
      throw new Error("Finalization event payload JSON is invalid.");
    }
    if (canonicalJson(payload) !== row.payloadJson || digestText(row.payloadJson) !== row.payloadDigest) {
      throw new Error("Finalization event payload canonical encoding or digest is invalid.");
    }
    const eventPayload = {
      sequence: row.sequence,
      transactionId: row.transactionId,
      fromState: row.fromState,
      toState: row.toState,
      kind: row.kind,
      payloadDigest: row.payloadDigest,
      payloadJson: row.payloadJson,
      occurredAt: row.occurredAt,
      previousTransitionTag: row.previousTransitionTag,
    };
    assertLifecycleAuthenticationTag("EVENT", key, anchor.anchorNonce, eventPayload, row.eventTag);
    const transitionPayload = {
      sequence: row.sequence,
      transactionId: row.transactionId,
      fromState: row.fromState,
      toState: row.toState,
      kind: row.kind,
      eventTag: row.eventTag,
      previousTransitionTag: row.previousTransitionTag,
    };
    assertLifecycleAuthenticationTag("TRANSITION", key, anchor.anchorNonce, transitionPayload, row.transitionTag);
    if (FINAL_STATES.includes(row.toState)) {
      assertLifecycleAuthenticationTag("FINAL", key, anchor.anchorNonce, {
        sequence: row.sequence,
        transactionId: row.transactionId,
        toState: row.toState,
        eventTag: row.eventTag,
        transitionTag: row.transitionTag,
        payloadDigest: row.payloadDigest,
      }, row.finalTag);
    }
    const event = Object.freeze({ ...row, payload: Object.freeze(payload) });
    events.push(event);
    state = row.toState;
    previousTransitionTag = row.transitionTag;
    previousOccurredAt = Date.parse(row.occurredAt);
  }

  const prepared = events.find((event) => event.toState === "PREPARED")?.payload?.record;
  const sealed = events.find((event) => event.toState === "SEALED")?.payload;
  const base = events.find((event) => event.toState === "BASE_PROFILE_FINAL_PASS")?.payload;
  const contentGeneration = digestJson({ anchor: anchorRow, events: rows });
  const identity = Object.freeze({
    storeId: FINALIZATION_STORE_ID,
    path: storePath,
    schemaVersion: FINALIZATION_STORE_SCHEMA_VERSION,
    schemaFingerprint: FINALIZATION_STORE_SCHEMA_FINGERPRINT,
    migration: FINALIZATION_STORE_MIGRATION,
    keyId: key.keyId,
    state,
    revision: events.length + 1,
    transactionId,
    inputDigest: prepared?.inputDigest ?? null,
    prepareDigest: prepared ? digestJson(prepared) : null,
    requestBindingDigest: prepared?.input?.requestBindingDigest ?? null,
    candidateIdentityDigest: prepared?.input?.candidateIdentityDigest ?? null,
    snapshotGroupDigest: prepared?.snapshotGroup?.manifest?.groupDigest ?? null,
    snapshotCapturedAt: prepared?.snapshotGroup?.manifest?.capturedAt ?? null,
    preparedAt: prepared?.preparedAt ?? null,
    sealInputDigest: sealed?.sealInputDigest ?? null,
    finalDigest: base?.finalDigest ?? null,
    contentGeneration,
    integrity: "ok",
    foreignKeyViolations: 0,
    createdAt: anchor.createdAt,
    updatedAt: events.at(-1)?.occurredAt ?? anchor.createdAt,
  });
  const ledger = Object.freeze({ identity, anchor, events: Object.freeze(events) });
  validateLedgerEventSemantics(ledger);
  return ledger;
}

function inspectRollbackRequest(configuration, key, control, requireVerifiedRestore) {
  const transactionId = requiredTransactionId(configuration.transactionId);
  const requestBindingDigest = requireDigest(configuration.requestBindingDigest, "rollback requestBindingDigest");
  const candidateIdentityDigest = requireDigest(configuration.candidateIdentityDigest, "rollback candidateIdentityDigest");
  const manifestPath = canonicalOwnerOnlyFile(resolve(requiredText(configuration.snapshotManifestPath, "rollback snapshot manifestPath")), "rollback snapshot manifest");
  const manifestBytes = stableReadFile(manifestPath, "rollback snapshot manifest");
  const manifestSha256 = digestBytes(manifestBytes);
  if (manifestSha256 !== requireDigest(configuration.snapshotManifestSha256, "rollback snapshot manifestSha256")) {
    throw new Error("Rollback snapshot manifest bytes differ from the exact authorization input.");
  }
  const manifest = parseJsonBytes(manifestBytes, "rollback snapshot manifest");
  assertExactObjectKeys(manifest, ["barrier", "capturedAt", "entries", "groupDigest", "schemaVersion", "snapshotRoot"], "rollback snapshot manifest");
  const unsignedManifest = {
    schemaVersion: manifest.schemaVersion,
    capturedAt: manifest.capturedAt,
    snapshotRoot: manifest.snapshotRoot,
    barrier: manifest.barrier,
    entries: manifest.entries,
  };
  if (manifest.schemaVersion !== 1 || manifest.groupDigest !== digestJson(unsignedManifest)
    || manifest.barrier?.transactionId !== transactionId
    || manifest.barrier?.requestBindingDigest !== requestBindingDigest
    || manifest.barrier?.candidateIdentityDigest !== candidateIdentityDigest) {
    throw new Error("Rollback snapshot manifest/group/barrier binding is invalid.");
  }
  const lifecycleEntries = Array.isArray(manifest.entries)
    ? manifest.entries.filter((entry) => entry?.id === FINALIZATION_STORE_ID)
    : [];
  if (lifecycleEntries.length !== 1) throw new Error("Rollback snapshot must contain exactly one lifecycle-finalization-store entry.");
  const lifecycle = lifecycleEntries[0];
  if (lifecycle.kind !== "sqlite" || lifecycle.state !== "captured" || lifecycle.path !== control.storePath
    || typeof lifecycle.snapshotPath !== "string" || !DIGEST_PATTERN.test(lifecycle.sha256 ?? "")) {
    throw new Error("Rollback lifecycle snapshot entry does not bind the exact mutable store.");
  }
  const storeSnapshotPath = canonicalOwnerOnlyFile(lifecycle.snapshotPath, "rollback lifecycle snapshot file");
  const storeSnapshotSha256 = digestBytes(stableReadFile(storeSnapshotPath, "rollback lifecycle snapshot file"));
  if (storeSnapshotSha256 !== lifecycle.sha256) throw new Error("Rollback lifecycle snapshot bytes differ from its manifest entry.");
  const snapshotDatabase = openReadOnlyDatabasePath(storeSnapshotPath);
  let snapshotLedger;
  try { snapshotDatabase.exec("pragma query_only = on"); snapshotLedger = readLedgerFromDatabase(snapshotDatabase, storeSnapshotPath, key); }
  finally { snapshotDatabase.close(); }
  if (snapshotLedger.anchor.anchorNonce !== control.initialization.anchorPayload.anchorNonce
    || snapshotLedger.anchor.anchorTag !== control.initialization.anchorTag
    || snapshotLedger.anchor.createdAt !== control.initialization.anchorPayload.createdAt
    || snapshotLedger.anchor.keyId !== control.keyId) {
    throw new Error("Rollback lifecycle snapshot is foreign to the current initialization lineage.");
  }

  const journalPath = canonicalOwnerOnlyFile(resolve(requiredText(configuration.rollbackJournalPath, "rollback journalPath")), "rollback control journal");
  const journalBytes = stableReadFile(journalPath, "rollback control journal");
  const journalSha256 = digestBytes(journalBytes);
  if (journalSha256 !== requireDigest(configuration.rollbackJournalSha256, "rollback journalSha256")) {
    throw new Error("Rollback control journal bytes differ from the current generation binding.");
  }
  const journalRecords = parseNdjson(journalBytes, "rollback control journal");
  const requested = journalRecords[0];
  if (requested?.event !== "ROLLBACK_REQUESTED" || requested.transactionId !== transactionId
    || requested.requestBindingDigest !== requestBindingDigest || requested.snapshotGroupDigest !== manifest.groupDigest) {
    throw new Error("Rollback control journal lacks the exact current ROLLBACK_REQUESTED tombstone.");
  }

  const claimPath = canonicalOwnerOnlyFile(resolve(requiredText(configuration.workerClaimPath, "rollback workerClaimPath")), "rollback worker claim");
  const claimBytes = stableReadFile(claimPath, "rollback worker claim");
  const claimSha256 = digestBytes(claimBytes);
  if (claimSha256 !== requireDigest(configuration.workerClaimSha256, "rollback workerClaimSha256")) {
    throw new Error("Rollback exclusive worker claim bytes differ from the current generation binding.");
  }
  const claim = parseJsonBytes(claimBytes, "rollback worker claim");
  if (claim.transactionId !== transactionId || claim.requestBindingDigest !== requestBindingDigest
    || typeof claim.claimId !== "string" || claim.claimId.length < 8) {
    throw new Error("Rollback exclusive worker claim is foreign or lacks a current generation.");
  }
  const requestedAt = requiredText(requested.requestedAt, "rollback requestedAt");
  if (!isCanonicalTimestamp(requestedAt)) throw new Error("Rollback requestedAt is invalid.");

  let restore = null;
  if (requireVerifiedRestore) {
    const existingRequestJournal = control.rollbackAuthorization?.requestJournal ?? null;
    const restorePath = canonicalOwnerOnlyFile(resolve(requiredText(configuration.restoreEvidencePath, "rollback restoreEvidencePath")), "rollback restore evidence");
    const restoreBytes = stableReadFile(restorePath, "rollback restore evidence");
    const restoreSha256 = digestBytes(restoreBytes);
    if (restoreSha256 !== requireDigest(configuration.restoreEvidenceSha256, "rollback restoreEvidenceSha256")) {
      throw new Error("Rollback restore evidence bytes differ from the exact authorization input.");
    }
    const restoreEvidence = parseJsonBytes(restoreBytes, "rollback restore evidence");
    if (restoreEvidence.groupDigest !== manifest.groupDigest || restoreEvidence.verified !== true
      || !Array.isArray(restoreEvidence.entries)
      || restoreEvidence.entries.filter((entry) => entry?.id === FINALIZATION_STORE_ID && entry.verified === true).length !== 1) {
      throw new Error("Rollback restore evidence does not verify the lifecycle snapshot entry/group.");
    }
    const terminal = journalRecords.at(-1);
    if (terminal?.event !== "ROLLBACK_RESTORE_VERIFIED" || terminal.transactionId !== transactionId
      || terminal.requestBindingDigest !== requestBindingDigest || terminal.snapshotGroupDigest !== manifest.groupDigest
      || terminal.evidenceDigest !== restoreSha256
      || (existingRequestJournal && terminal.requestJournalSha256 !== existingRequestJournal.sha256)) {
      throw new Error("Rollback control journal lacks the exact current ROLLBACK_RESTORE_VERIFIED generation.");
    }
    restore = {
      path: restorePath,
      sha256: restoreSha256,
      journalPath,
      journalSha256,
      generation: terminal.evidenceDigest,
      verifiedAt: normalizedNow(configuration.now),
    };
  }
  const authorization = Object.freeze({
    phase: requireVerifiedRestore ? "VERIFIED" : "REQUESTED",
    transactionId,
    requestBindingDigest,
    candidateIdentityDigest,
    requestedAt,
    from: control.current,
    target: controlHeadFromLedger(snapshotLedger),
    snapshot: {
      manifestPath,
      manifestSha256,
      groupDigest: manifest.groupDigest,
      storeSnapshotPath,
      storeSnapshotSha256,
    },
    requestJournal: {
      path: journalPath,
      sha256: requireVerifiedRestore && control.rollbackAuthorization?.requestJournal
        ? control.rollbackAuthorization.requestJournal.sha256
        : journalSha256,
      generation: digestJson(requested),
    },
    workerClaim: { path: claimPath, sha256: claimSha256, generation: claim.claimId },
    restore,
  });
  validateRollbackAuthorization(authorization);
  return Object.freeze({ authorization, manifest, snapshotLedger });
}

function parseNdjson(bytes, label) {
  const text = bytes.toString("utf8");
  const records = [];
  for (const line of text.split("\n")) {
    if (!line) continue;
    try { records.push(JSON.parse(line)); } catch { throw new Error(`${label} contains invalid NDJSON.`); }
  }
  if (records.length === 0) throw new Error(`${label} is empty.`);
  return records;
}

function completePendingInitialization({ storePath, controlPath, key, lock }) {
  assertControlLock(lock, "INIT", lock.intent);
  validateInitializationLockIntent(lock.intent, storePath, key);
  const initialization = lock.intent.initialization;
  const { anchorPayload, anchorTag } = initialization;
  const stagingPath = lock.intent.stagingPath;
  const journalPath = `${stagingPath}-journal`;
  assertNoUnboundInitializationResidue(storePath, stagingPath);
  let existing = lstatIfPresent(storePath);
  if (existing && (existing.isSymbolicLink() || !existing.isFile() || existing.size === 0)) {
    throw new Error("Existing lifecycle.sqlite is not a complete cryptographically recognizable INIT_PENDING publication.");
  }
  if (!existing) {
    quarantineRemoveInitializationPath(journalPath, stagingPath, "abandoned finalization INIT journal");
    quarantineRemoveInitializationPath(stagingPath, stagingPath, "abandoned finalization INIT staging");
    createInitializedStagingDatabase(stagingPath, initialization, key);
    assertControlLockStillCurrent(controlLockPath(controlPath), lock);
    if (lstatIfPresent(journalPath)) {
      throw new Error("Finalization INIT staging retained a SQLite journal; explicit recovery is required.");
    }
    validateInitializedDatabase(stagingPath, key, initialization);
    fsyncFile(stagingPath);
    publishNewFileNoReplace(stagingPath, storePath, "finalization store");
    fsyncDirectory(dirname(storePath));
    existing = lstatIfPresent(storePath);
  }
  if (!existing) throw new Error("Finalization INIT_PENDING database publication is missing.");
  const ledger = validateInitializedDatabase(storePath, key, initialization);
  cleanupPublishedInitializationResidue(storePath, stagingPath);
  const committed = authenticatedControlRecord({
    key,
    storePath,
    initialization,
    anchor: ledger.anchor,
    controlEpoch: 1,
    previousControlTag: null,
    storeFile: fileIdentity(storePath),
    databaseIdentity: databaseIdentityFromLedger(ledger),
    current: controlHeadFromLedger(ledger),
    pending: null,
    rollbackAuthorization: null,
  });
  if (lstatIfPresent(controlPath)) {
    const existingControl = readAuthenticatedControl(controlPath, storePath, key, true);
    if (canonicalJson(existingControl) !== canonicalJson(committed)) throw new Error("Existing INIT_COMMITTED control differs from exact INIT lock.");
  } else {
    assertControlLockStillCurrent(controlLockPath(controlPath), lock);
    writeOwnerOnlyJsonNew(controlPath, committed, "finalization INIT_COMMITTED control");
  }
  releaseControlLock(controlLockPath(controlPath), lock);
}

function initializationStagingPath(storePath, anchorNonce) {
  if (!NONCE_PATTERN.test(anchorNonce ?? "")) throw new Error("Finalization INIT anchor nonce is invalid.");
  return join(dirname(storePath), `.${basename(storePath)}.initialize-${anchorNonce}`);
}

function bootstrapAuthorizationUnsigned({ storePath, controlPath, keyId, approvedAt, expiresAt, authorizationId }) {
  return Object.freeze({
    schemaVersion: BOOTSTRAP_AUTH_SCHEMA_VERSION,
    operation: BOOTSTRAP_AUTH_OPERATION,
    storeId: FINALIZATION_STORE_ID,
    recoveryClass: "R2",
    storePath,
    controlPath,
    keyId,
    approvedAt,
    expiresAt,
    authorizationId,
  });
}

function validateBootstrapAuthorization(value, storePath, controlPath, key, observedAt) {
  const authorization = canonicalClone(requiredObject(value, "owner-authorized finalization bootstrap authorization"));
  assertExactObjectKeys(authorization, [
    "approvedAt", "authorizationId", "authorizationTag", "controlPath", "expiresAt", "keyId",
    "operation", "recoveryClass", "schemaVersion", "storeId", "storePath",
  ], "owner-authorized finalization bootstrap authorization");
  if (authorization.schemaVersion !== BOOTSTRAP_AUTH_SCHEMA_VERSION
    || authorization.operation !== BOOTSTRAP_AUTH_OPERATION
    || authorization.storeId !== FINALIZATION_STORE_ID
    || authorization.recoveryClass !== "R2"
    || authorization.storePath !== storePath
    || authorization.controlPath !== controlPath
    || authorization.keyId !== key.keyId
    || !isCanonicalTimestamp(authorization.approvedAt)
    || !isCanonicalTimestamp(authorization.expiresAt)
    || !NONCE_PATTERN.test(authorization.authorizationId ?? "")
    || Date.parse(authorization.expiresAt) <= Date.parse(authorization.approvedAt)
    || Date.parse(observedAt) < Date.parse(authorization.approvedAt)
    || Date.parse(observedAt) > Date.parse(authorization.expiresAt)
    || !TAG_PATTERN.test(authorization.authorizationTag ?? "")) {
    throw new Error("Owner-authorized finalization bootstrap proof is invalid or foreign.");
  }
  const unsigned = { ...authorization };
  delete unsigned.authorizationTag;
  assertSameTag(
    bootstrapAuthorizationTag(key, unsigned),
    authorization.authorizationTag,
    "Owner-authorized finalization bootstrap proof authentication failed.",
  );
  return Object.freeze(authorization);
}

function bootstrapAuthorizationTag(key, unsigned) {
  return `hmac-sha256:${createHmac("sha256", key.secret)
    .update("devspace.finalization-store.v2/BOOTSTRAP-AUTHORIZATION\0")
    .update(canonicalJson(unsigned))
    .digest("hex")}`;
}

function bootstrapConsumedPath(controlPath) {
  return `${controlPath}.bootstrap-consumed.json`;
}

function writeBootstrapConsumedTombstone({ path, storePath, controlPath, key, authorization, authorizationDigest, consumedAt }) {
  const unsigned = {
    schemaVersion: 1,
    kind: "FINALIZATION_BOOTSTRAP_CONSUMED",
    storeId: FINALIZATION_STORE_ID,
    storePath,
    controlPath,
    keyId: key.keyId,
    authorizationId: authorization.authorizationId,
    authorizationDigest,
    approvedAt: authorization.approvedAt,
    expiresAt: authorization.expiresAt,
    consumedAt,
  };
  const value = Object.freeze({
    ...unsigned,
    consumptionTag: `hmac-sha256:${createHmac("sha256", key.secret)
      .update("devspace.finalization-store.v2/BOOTSTRAP-CONSUMED\0")
      .update(canonicalJson(unsigned))
      .digest("hex")}`,
  });
  writeOwnerOnlyJsonNew(path, value, "finalization bootstrap consumption tombstone");
  fsyncDirectory(dirname(path));
  return value;
}

function readBootstrapConsumedTombstone(path, storePath, controlPath, key) {
  const canonicalPath = canonicalOwnerOnlyFile(path, "finalization bootstrap consumption tombstone");
  const value = parseJsonBytes(stableReadFile(canonicalPath, "finalization bootstrap consumption tombstone"),
    "finalization bootstrap consumption tombstone");
  assertExactObjectKeys(value, [
    "approvedAt", "authorizationDigest", "authorizationId", "consumedAt", "consumptionTag",
    "controlPath", "expiresAt", "keyId", "kind", "schemaVersion", "storeId", "storePath",
  ], "finalization bootstrap consumption tombstone");
  const { consumptionTag, ...unsigned } = value;
  if (value.schemaVersion !== 1 || value.kind !== "FINALIZATION_BOOTSTRAP_CONSUMED"
    || value.storeId !== FINALIZATION_STORE_ID || value.storePath !== storePath
    || value.controlPath !== controlPath || value.keyId !== key.keyId
    || !NONCE_PATTERN.test(value.authorizationId ?? "")
    || !DIGEST_PATTERN.test(value.authorizationDigest ?? "")
    || !isCanonicalTimestamp(value.approvedAt) || !isCanonicalTimestamp(value.expiresAt)
    || !isCanonicalTimestamp(value.consumedAt) || !TAG_PATTERN.test(consumptionTag ?? "")) {
    throw new Error("Finalization bootstrap consumption tombstone is invalid or foreign.");
  }
  const expected = `hmac-sha256:${createHmac("sha256", key.secret)
    .update("devspace.finalization-store.v2/BOOTSTRAP-CONSUMED\0")
    .update(canonicalJson(unsigned))
    .digest("hex")}`;
  assertSameTag(expected, consumptionTag, "Finalization bootstrap consumption tombstone authentication failed.");
  return Object.freeze(value);
}

function validateInitializationLockIntent(value, storePath, key) {
  assertExactObjectKeys(value, [
    "authorizationId", "bootstrapAuthorization", "bootstrapAuthorizationDigest", "consumedAt",
    "consumedPath", "controlPath", "expectedStoreState", "initialization", "stagingPath", "storePath",
  ], "finalization INIT lock intent");
  if (value.expectedStoreState !== "ABSENT" || value.storePath !== storePath) {
    throw new Error("Finalization INIT lock target state/path is invalid.");
  }
  requireDigest(value.bootstrapAuthorizationDigest, "finalization INIT bootstrap authorization digest");
  if (!NONCE_PATTERN.test(value.authorizationId ?? "")) {
    throw new Error("Finalization INIT bootstrap authorizationId is invalid.");
  }
  const controlPath = canonicalControlPath(value.controlPath, storePath, true);
  if (value.consumedPath !== bootstrapConsumedPath(controlPath)) {
    throw new Error("Finalization INIT bootstrap consumption path differs.");
  }
  if (digestJson(value.bootstrapAuthorization) !== value.bootstrapAuthorizationDigest
    || value.bootstrapAuthorization.authorizationId !== value.authorizationId
    || !isCanonicalTimestamp(value.consumedAt)) {
    throw new Error("Finalization INIT bootstrap authorization binding is invalid.");
  }
  if (!lstatIfPresent(value.consumedPath)) {
    writeBootstrapConsumedTombstone({
      path: value.consumedPath,
      storePath,
      controlPath,
      key,
      authorization: value.bootstrapAuthorization,
      authorizationDigest: value.bootstrapAuthorizationDigest,
      consumedAt: value.consumedAt,
    });
  }
  const consumed = readBootstrapConsumedTombstone(value.consumedPath, storePath, controlPath, key);
  if (consumed.authorizationId !== value.authorizationId
    || consumed.authorizationDigest !== value.bootstrapAuthorizationDigest) {
    throw new Error("Finalization INIT lock differs from its consumed bootstrap authorization.");
  }
  const initialization = requiredObject(value.initialization, "finalization INIT initialization");
  validateInitialization(initialization, key, initialization.anchorPayload?.anchorNonce);
  const expectedStagingPath = initializationStagingPath(storePath, initialization.anchorPayload.anchorNonce);
  if (value.stagingPath !== expectedStagingPath || !isAbsolute(value.stagingPath)
    || resolve(value.stagingPath) !== value.stagingPath || dirname(value.stagingPath) !== dirname(storePath)) {
    throw new Error("Finalization INIT staging path differs from the authenticated anchor binding.");
  }
}

function assertNoUnboundInitializationResidue(storePath, stagingPath) {
  const parent = canonicalRealDirectory(dirname(storePath), "finalization INIT parent");
  const prefix = `.${basename(storePath)}.initialize-`;
  const journalPath = `${stagingPath}-journal`;
  const allowed = new Set([
    stagingPath,
    journalPath,
    sqliteDiscardPath(stagingPath),
    sqliteDiscardPath(journalPath),
  ]);
  for (const entry of readdirSync(parent, { withFileTypes: true })) {
    if (!entry.name.startsWith(prefix)) continue;
    const path = join(parent, entry.name);
    if (!allowed.has(path)) {
      throw new Error(`Unbound finalization INIT residue makes state UNKNOWN: ${entry.name}`);
    }
    assertOwnerOnlyRegularEntry(path, "bound finalization INIT residue");
  }
}

function quarantineRemoveInitializationPath(path, stagingPath, label, expectedIdentity) {
  const allowed = new Set([stagingPath, `${stagingPath}-journal`]);
  if (!allowed.has(path)) throw new Error(`${label} path is not bound to the authenticated INIT lock.`);
  const discardPath = sqliteDiscardPath(path);
  const current = lstatIfPresent(path);
  const discarded = lstatIfPresent(discardPath);
  if (current && discarded) throw new Error(`${label} has both live and quarantined entries.`);
  if (!current && !discarded) return false;
  if (current) {
    assertOwnerOnlyRegularEntry(path, label);
    const before = fileIdentity(path);
    if (expectedIdentity && canonicalJson(before) !== canonicalJson(expectedIdentity)) {
      throw new Error(`${label} inode differs from the authenticated INIT publication.`);
    }
    renameSync(path, discardPath);
    fsyncDirectory(dirname(path));
    if (canonicalJson(fileIdentity(discardPath)) !== canonicalJson(before)) {
      throw new Error(`${label} inode changed during quarantine-first removal.`);
    }
  } else {
    assertOwnerOnlyRegularEntry(discardPath, `${label} quarantine`);
    if (expectedIdentity && canonicalJson(fileIdentity(discardPath)) !== canonicalJson(expectedIdentity)) {
      throw new Error(`${label} quarantined inode differs from the authenticated INIT publication.`);
    }
  }
  unlinkSync(discardPath);
  fsyncDirectory(dirname(path));
  return true;
}

function createInitializedStagingDatabase(stagingPath, initialization, key) {
  const descriptor = openSync(
    stagingPath,
    constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | (constants.O_NOFOLLOW ?? 0),
    0o600,
  );
  closeSync(descriptor);
  const database = openWritableDatabasePath(stagingPath);
  try {
    database.exec("begin immediate");
    try {
      for (const statement of FINALIZATION_STORE_DDL) database.exec(statement);
      database.exec(`pragma user_version = ${FINALIZATION_STORE_SCHEMA_VERSION}`);
      database.prepare(`
        insert into finalization_anchor
          (singleton, store_id, schema_version, migration_name, migration_checksum,
           schema_fingerprint, key_id, anchor_nonce, created_at, anchor_tag)
        values (1, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      `).run(
        FINALIZATION_STORE_ID,
        FINALIZATION_STORE_SCHEMA_VERSION,
        FINALIZATION_STORE_MIGRATION_NAME,
        FINALIZATION_STORE_MIGRATION_CHECKSUM,
        FINALIZATION_STORE_SCHEMA_FINGERPRINT,
        key.keyId,
        initialization.anchorPayload.anchorNonce,
        initialization.anchorPayload.createdAt,
        initialization.anchorTag,
      );
      database.exec("commit");
    } catch (error) {
      try { database.exec("rollback"); } catch { /* transaction may not have begun */ }
      throw error;
    }
  } finally { database.close(); }
  chmodSync(stagingPath, 0o600);
  if (lstatIfPresent(`${stagingPath}-journal`)) {
    throw new Error("Finalization INIT staging retained a SQLite journal.");
  }
  fsyncFile(stagingPath);
  fsyncDirectory(dirname(stagingPath));
}

function validateInitializedDatabase(path, key, initialization) {
  const database = openReadOnlyDatabasePath(path);
  let ledger;
  try {
    database.exec("pragma query_only = on");
    ledger = readLedgerFromDatabase(database, path, key);
  } finally { database.close(); }
  if (ledger.identity.state !== "DRAFT" || ledger.events.length !== 0
    || ledger.anchor.anchorNonce !== initialization.anchorPayload.anchorNonce
    || ledger.anchor.anchorTag !== initialization.anchorTag
    || ledger.anchor.createdAt !== initialization.anchorPayload.createdAt) {
    throw new Error("Lifecycle SQLite does not match its exact authenticated INIT_PENDING anchor.");
  }
  return ledger;
}

function cleanupPublishedInitializationResidue(storePath, stagingPath) {
  const journalPath = `${stagingPath}-journal`;
  assertNoUnboundInitializationResidue(storePath, stagingPath);
  if (lstatIfPresent(journalPath) || lstatIfPresent(sqliteDiscardPath(journalPath))) {
    throw new Error("Published finalization INIT retains an ambiguous SQLite journal.");
  }
  if (lstatIfPresent(stagingPath) || lstatIfPresent(sqliteDiscardPath(stagingPath))) {
    quarantineRemoveInitializationPath(
      stagingPath,
      stagingPath,
      "published finalization INIT staging alias",
      fileIdentity(storePath),
    );
  }
  assertNoUnboundInitializationResidue(storePath, stagingPath);
}

function readAuthenticatedControl(controlPath, storePath, key, allowInitializing = false) {
  const control = parseJsonBytes(stableReadFile(controlPath, "finalization external control"), "finalization external control");
  assertExactObjectKeys(control, [
    "anchorNonce", "controlEpoch", "controlTag", "current", "databaseIdentity", "initialization",
    "keyId", "kind", "pending", "previousControlTag", "rollbackAuthorization", "schemaVersion",
    "storeFile", "storeId", "storePath",
  ], "finalization external control");
  if (control.schemaVersion !== CONTROL_SCHEMA_VERSION || control.kind !== CONTROL_KIND
    || control.storeId !== FINALIZATION_STORE_ID || control.storePath !== storePath
    || control.keyId !== key.keyId || !NONCE_PATTERN.test(control.anchorNonce ?? "")
    || !Number.isSafeInteger(control.controlEpoch) || control.controlEpoch < 1
    || (control.previousControlTag !== null && !TAG_PATTERN.test(control.previousControlTag ?? ""))) {
    throw new Error("Finalization external control identity is invalid or foreign.");
  }
  validateInitialization(control.initialization, key, control.anchorNonce);
  validateFileIdentity(control.storeFile, "finalization external control storeFile");
  validateDatabaseIdentity(control.databaseIdentity);
  validateControlHead(control.current, "finalization external control current head");
  if (control.pending !== null) validatePendingControl(control.pending, control.current, storePath, control.storeFile);
  if (control.rollbackAuthorization !== null) validateRollbackAuthorization(control.rollbackAuthorization);
  const unsigned = { ...control };
  delete unsigned.controlTag;
  assertControlAuthenticationTag(key, unsigned, control.controlTag);
  return Object.freeze(control);
}

function validateInitialization(value, key, anchorNonce) {
  assertExactObjectKeys(value, ["anchorPayload", "anchorTag"], "finalization initialization binding");
  assertExactObjectKeys(value.anchorPayload, [
    "anchorNonce", "createdAt", "migrationChecksum", "migrationName", "schemaFingerprint",
    "schemaVersion", "storeId",
  ], "finalization initialization anchor payload");
  if (value.anchorPayload.storeId !== FINALIZATION_STORE_ID
    || value.anchorPayload.schemaVersion !== FINALIZATION_STORE_SCHEMA_VERSION
    || value.anchorPayload.migrationName !== FINALIZATION_STORE_MIGRATION_NAME
    || value.anchorPayload.migrationChecksum !== FINALIZATION_STORE_MIGRATION_CHECKSUM
    || value.anchorPayload.schemaFingerprint !== FINALIZATION_STORE_SCHEMA_FINGERPRINT
    || value.anchorPayload.anchorNonce !== anchorNonce
    || !isCanonicalTimestamp(value.anchorPayload.createdAt)) {
    throw new Error("Finalization initialization anchor identity is invalid.");
  }
  assertAuthenticationTag("ANCHOR", key, value.anchorPayload, value.anchorTag);
}

function controlLockPath(controlPath) {
  return `${controlPath}.lock`;
}

function acquireControlLock({ controlPath, storePath, key, lockKind, intent, now }) {
  if (!["INIT", "TRANSITION", "ROLLBACK"].includes(lockKind)) throw new Error("Finalization control lock kind is invalid.");
  const lockPath = controlLockPath(controlPath);
  const payload = canonicalClone(intent);
  const unsigned = {
    schemaVersion: CONTROL_LOCK_SCHEMA_VERSION,
    kind: CONTROL_LOCK_KIND,
    keyId: key.keyId,
    lockKind,
    storePath,
    ownerPid: process.pid,
    ownerNonce: randomBytes(32).toString("base64url"),
    createdAt: normalizedNow(now),
    intent: payload,
    intentDigest: digestJson(payload),
  };
  const candidate = Object.freeze({ ...unsigned, signature: controlLockSignature(key, unsigned) });
  try {
    writeOwnerOnlyJsonNew(lockPath, candidate, `finalization ${lockKind} control lock`);
    return candidate;
  } catch (error) {
    if (!lstatIfPresent(lockPath)) throw error;
    const existing = readAuthenticatedControlLock(lockPath, storePath, key);
    throw new Error(`Finalization control lock conflict: PID ${existing.ownerPid} owns ${existing.lockKind}; ordinary acquisition never adopts an existing intent.`);
  }
}

function acquireRecoveryClaim({ recoveryPath, storePath, key, abandoned, now }) {
  if (lstatIfPresent(recoveryPath)) {
    const existing = readAuthenticatedControlLock(recoveryPath, storePath, key);
    if (existing.lockKind !== "RECOVERY") throw new Error("Finalization recovery claim kind is invalid.");
    if (isProcessAlive(existing.ownerPid)) {
      throw new Error(`Finalization recovery claim owner PID ${existing.ownerPid} is still live.`);
    }
    releaseControlLock(recoveryPath, existing);
  }
  const intent = Object.freeze({
    abandonedLockDigest: digestJson(abandoned),
    abandonedOwnerNonce: abandoned.ownerNonce,
    abandonedOwnerPid: abandoned.ownerPid,
  });
  const unsigned = {
    schemaVersion: CONTROL_LOCK_SCHEMA_VERSION,
    kind: CONTROL_LOCK_KIND,
    keyId: key.keyId,
    lockKind: "RECOVERY",
    storePath,
    ownerPid: process.pid,
    ownerNonce: randomBytes(32).toString("base64url"),
    createdAt: normalizedNow(now),
    intent,
    intentDigest: digestJson(intent),
  };
  const claim = Object.freeze({ ...unsigned, signature: controlLockSignature(key, unsigned) });
  try {
    writeOwnerOnlyJsonNew(recoveryPath, claim, "finalization verified-dead recovery claim");
  } catch (error) {
    if (!lstatIfPresent(recoveryPath)) throw error;
    const winner = readAuthenticatedControlLock(recoveryPath, storePath, key);
    throw new Error(`Finalization recovery claim conflict: PID ${winner.ownerPid} won the verified-dead handoff.`);
  }
  return claim;
}

function replaceAbandonedControlLock({ lockPath, recoveryPath, recovery, abandoned, key }) {
  assertControlLockStillCurrent(recoveryPath, recovery);
  assertControlLockStillCurrent(lockPath, abandoned);
  const unsigned = {
    schemaVersion: CONTROL_LOCK_SCHEMA_VERSION,
    kind: CONTROL_LOCK_KIND,
    keyId: key.keyId,
    lockKind: abandoned.lockKind,
    storePath: abandoned.storePath,
    ownerPid: process.pid,
    ownerNonce: randomBytes(32).toString("base64url"),
    createdAt: normalizedNow(),
    intent: abandoned.intent,
    intentDigest: abandoned.intentDigest,
  };
  const adopted = Object.freeze({ ...unsigned, signature: controlLockSignature(key, unsigned) });
  replaceOwnerOnlyJsonUnderGuard(
    lockPath,
    abandoned,
    adopted,
    recoveryPath,
    recovery,
    "finalization verified-dead control lock handoff",
  );
  return adopted;
}

function recoverAdoptedTransition({ storePath, controlPath, key, lock }) {
  assertControlLock(lock, "TRANSITION", lock.intent);
  validateTransitionLockIntent(lock.intent, storePath);
  const event = lock.intent.event;
  const control = readAuthenticatedControl(controlPath, storePath, key);
  if (control.pending === null) {
    if (canonicalJson(control.current) === canonicalJson(lock.intent.proposedHead)) {
      cleanupCommittedSqliteCopyOnWrite(storePath, control, lock.intent.sqliteMutation, lock, controlPath);
      releaseControlLock(controlLockPath(controlPath), lock);
      return;
    }
    if (digestJson(control) !== lock.intent.expectedControlDigest) {
      throw new Error("Recovered finalization transition predecessor differs; state remains UNKNOWN.");
    }
    assertNoUnboundSqliteMutationResidue(storePath, null);
    const pending = Object.freeze({
      event,
      proposed: lock.intent.proposedHead,
      sqliteMutation: lock.intent.sqliteMutation,
    });
    validatePendingControl(pending, control.current, storePath, control.storeFile);
    const next = authenticatedControlRecord({
      key,
      storePath,
      initialization: control.initialization,
      anchor: { anchorNonce: control.anchorNonce },
      controlEpoch: control.controlEpoch + 1,
      previousControlTag: control.controlTag,
      storeFile: control.storeFile,
      databaseIdentity: control.databaseIdentity,
      current: control.current,
      pending,
      rollbackAuthorization: control.rollbackAuthorization,
    });
    replaceOwnerOnlyJsonCas(controlPath, control, next, "recovered finalization PENDING control", lock);
  }
  reconcilePendingTransition({
    storePath,
    controlPath,
    key,
    expected: {
      transactionId: event.transactionId,
      expectedState: event.fromState,
      nextState: event.toState,
      kind: event.kind,
      payloadJson: event.payloadJson,
      occurredAt: event.occurredAt,
    },
  });
}

function recoverAdoptedRollback({ storePath, controlPath, key, lock }) {
  assertControlLock(lock, "ROLLBACK", lock.intent);
  const control = readAuthenticatedControl(controlPath, storePath, key);
  const authorization = lock.intent.authorization;
  if (canonicalJson(control.rollbackAuthorization) === canonicalJson(authorization)) {
    releaseControlLock(controlLockPath(controlPath), lock);
    return;
  }
  if (digestJson(control) !== lock.intent.expectedControlDigest) {
    throw new Error("Recovered finalization rollback predecessor differs; state remains UNKNOWN.");
  }
  let anchor = { anchorNonce: control.anchorNonce };
  let storeFile = control.storeFile;
  let databaseIdentity = control.databaseIdentity;
  let current = control.current;
  if (authorization.phase === "VERIFIED") {
    const restoredSha256 = digestBytes(stableReadFile(storePath, "recovered rollback lifecycle store"));
    if (restoredSha256 !== authorization.snapshot.storeSnapshotSha256) {
      throw new Error("Recovered rollback lifecycle store differs from the authorized snapshot bytes.");
    }
    const database = openReadOnlyDatabasePath(storePath);
    let restored;
    try { database.exec("pragma query_only = on"); restored = readLedgerFromDatabase(database, storePath, key); }
    finally { database.close(); }
    if (canonicalJson(controlHeadFromLedger(restored)) !== canonicalJson(authorization.target)) {
      throw new Error("Recovered rollback lifecycle head differs from the authorized target.");
    }
    anchor = restored.anchor;
    storeFile = fileIdentity(storePath);
    databaseIdentity = databaseIdentityFromLedger(restored);
    current = authorization.target;
  }
  const next = authenticatedControlRecord({
    key,
    storePath,
    initialization: control.initialization,
    anchor,
    controlEpoch: control.controlEpoch + 1,
    previousControlTag: control.controlTag,
    storeFile,
    databaseIdentity,
    current,
    pending: null,
    rollbackAuthorization: authorization,
  });
  replaceOwnerOnlyJsonCas(controlPath, control, next, "recovered finalization rollback control", lock);
  releaseControlLock(controlLockPath(controlPath), lock);
}

function readAuthenticatedControlLock(lockPath, storePath, key) {
  const lock = parseJsonBytes(stableReadFile(lockPath, "finalization control lock"), "finalization control lock");
  assertExactObjectKeys(lock, [
    "createdAt", "intent", "intentDigest", "keyId", "kind", "lockKind", "schemaVersion",
    "ownerNonce", "ownerPid", "signature", "storePath",
  ], "finalization control lock");
  if (lock.schemaVersion !== CONTROL_LOCK_SCHEMA_VERSION || lock.kind !== CONTROL_LOCK_KIND
    || lock.keyId !== key.keyId || lock.storePath !== storePath
    || !["INIT", "TRANSITION", "ROLLBACK", "RECOVERY"].includes(lock.lockKind)
    || !Number.isSafeInteger(lock.ownerPid) || lock.ownerPid < 1
    || !NONCE_PATTERN.test(lock.ownerNonce ?? "")
    || !isCanonicalTimestamp(lock.createdAt) || lock.intentDigest !== digestJson(lock.intent)
    || !NONCE_PATTERN.test(lock.signature ?? "")) {
    throw new Error("Finalization control lock identity is invalid or foreign.");
  }
  const unsigned = { ...lock };
  delete unsigned.signature;
  const expected = controlLockSignature(key, unsigned);
  const left = Buffer.from(expected);
  const right = Buffer.from(lock.signature);
  if (left.length !== right.length || !timingSafeEqual(left, right)) {
    throw new Error("Finalization control lock authentication failed.");
  }
  return Object.freeze(lock);
}

function controlLockSignature(key, unsigned) {
  return createHmac("sha256", key.secret)
    .update("devspace.finalization-store.v2/CONTROL-LOCK\0")
    .update(canonicalJson(unsigned))
    .digest("base64url");
}

function assertControlLock(lock, expectedKind, expectedIntent) {
  if (lock.lockKind !== expectedKind || canonicalJson(lock.intent) !== canonicalJson(expectedIntent)) {
    throw new Error(`Finalization ${expectedKind} control lock intent differs.`);
  }
}

function assertControlLockStillCurrent(lockPath, expected) {
  const observed = parseJsonBytes(stableReadFile(lockPath, "finalization control lock"), "finalization control lock");
  if (canonicalJson(observed) !== canonicalJson(expected)) throw new Error("Finalization control lock changed before durable mutation.");
}

function releaseControlLock(lockPath, expected) {
  assertControlLockStillCurrent(lockPath, expected);
  const before = fileIdentity(lockPath);
  const quarantinePath = `${lockPath}.release-${randomBytes(16).toString("hex")}`;
  renameSync(lockPath, quarantinePath);
  fsyncDirectory(dirname(lockPath));
  const quarantined = parseJsonBytes(
    stableReadFile(quarantinePath, "quarantined finalization control lock"),
    "quarantined finalization control lock",
  );
  if (canonicalJson(quarantined) !== canonicalJson(expected)
    || canonicalJson(fileIdentity(quarantinePath)) !== canonicalJson(before)) {
    throw new Error("Finalization control lock changed during quarantine-first release; quarantine retained.");
  }
  unlinkSync(quarantinePath);
  fsyncDirectory(dirname(lockPath));
}

function authenticatedControlRecord({ key, storePath, initialization, anchor, controlEpoch, previousControlTag, storeFile, databaseIdentity, current, pending, rollbackAuthorization }) {
  const unsigned = {
    schemaVersion: CONTROL_SCHEMA_VERSION,
    kind: CONTROL_KIND,
    storeId: FINALIZATION_STORE_ID,
    storePath,
    keyId: key.keyId,
    anchorNonce: anchor.anchorNonce,
    controlEpoch,
    previousControlTag,
    initialization,
    storeFile,
    databaseIdentity,
    current,
    pending,
    rollbackAuthorization,
  };
  return Object.freeze({ ...unsigned, controlTag: controlAuthenticationTag(key, unsigned) });
}

function databaseIdentityFromLedger(ledger) {
  return Object.freeze({
    schemaVersion: FINALIZATION_STORE_SCHEMA_VERSION,
    schemaFingerprint: FINALIZATION_STORE_SCHEMA_FINGERPRINT,
    migrationChecksum: FINALIZATION_STORE_MIGRATION_CHECKSUM,
    anchorTag: ledger.anchor.anchorTag,
  });
}

function validateDatabaseIdentity(value) {
  assertExactObjectKeys(value, ["anchorTag", "migrationChecksum", "schemaFingerprint", "schemaVersion"], "finalization external database identity");
  if (value.schemaVersion !== FINALIZATION_STORE_SCHEMA_VERSION
    || value.schemaFingerprint !== FINALIZATION_STORE_SCHEMA_FINGERPRINT
    || value.migrationChecksum !== FINALIZATION_STORE_MIGRATION_CHECKSUM
    || !TAG_PATTERN.test(value.anchorTag ?? "")) {
    throw new Error("Finalization external database identity is invalid.");
  }
}

function controlHeadFromLedger(ledger) {
  return Object.freeze({
    revision: ledger.identity.revision,
    state: ledger.identity.state,
    transactionId: ledger.identity.transactionId,
    headTransitionTag: ledger.events.at(-1)?.transitionTag ?? ledger.anchor.anchorTag,
    updatedAt: ledger.identity.updatedAt,
  });
}

function validateControlHead(value, label) {
  assertExactObjectKeys(value, ["headTransitionTag", "revision", "state", "transactionId", "updatedAt"], label);
  if (!Number.isSafeInteger(value.revision) || value.revision < 1
    || !TAG_PATTERN.test(value.headTransitionTag ?? "") || !isCanonicalTimestamp(value.updatedAt)
    || (value.transactionId !== null && requiredTransactionId(value.transactionId) !== value.transactionId)) {
    throw new Error(`${label} is invalid.`);
  }
  requiredState(value.state, true);
  if ((value.revision === 1) !== (value.state === "DRAFT" && value.transactionId === null)) {
    throw new Error(`${label} revision/state/transaction tuple is invalid.`);
  }
}

function validatePendingControl(value, current, storePath, storeFile) {
  assertExactObjectKeys(value, ["event", "proposed", "sqliteMutation"], "finalization external PENDING intent");
  validateControlHead(value.proposed, "finalization external PENDING proposed head");
  validateAuthenticatedEventShape(value.event);
  validateSqliteCopyOnWriteBinding(value.sqliteMutation, storePath, storeFile, value.event);
  if (value.event.sequence !== current.revision
    || value.event.fromState !== current.state
    || value.event.previousTransitionTag !== current.headTransitionTag
    || value.proposed.revision !== current.revision + 1
    || value.proposed.state !== value.event.toState
    || value.proposed.transactionId !== value.event.transactionId
    || value.proposed.headTransitionTag !== value.event.transitionTag
    || value.proposed.updatedAt !== value.event.occurredAt) {
    throw new Error("Finalization external PENDING intent does not extend the exact committed head.");
  }
}

function validateRollbackAuthorization(value) {
  assertExactObjectKeys(value, [
    "candidateIdentityDigest", "from", "phase", "requestBindingDigest", "requestedAt",
    "requestJournal", "restore", "snapshot", "target", "transactionId", "workerClaim",
  ], "finalization rollback authorization");
  requiredTransactionId(value.transactionId);
  if (!['REQUESTED', 'VERIFIED'].includes(value.phase)) throw new Error("Finalization rollback authorization phase is invalid.");
  for (const key of ["requestBindingDigest", "candidateIdentityDigest"]) {
    requireDigest(value[key], `rollback authorization ${key}`);
  }
  if (!isCanonicalTimestamp(value.requestedAt)) throw new Error("Rollback authorization requestedAt is invalid.");
  validateControlHead(value.from, "rollback authorization source");
  validateControlHead(value.target, "rollback authorization target");
  validateBoundFile(value.snapshot, ["groupDigest", "manifestPath", "manifestSha256", "storeSnapshotPath", "storeSnapshotSha256"], "rollback snapshot binding");
  requireDigest(value.snapshot.groupDigest, "rollback snapshot groupDigest");
  validateBoundFile(value.requestJournal, ["generation", "path", "sha256"], "rollback request journal binding");
  requiredText(value.requestJournal.generation, "rollback request journal generation");
  validateBoundFile(value.workerClaim, ["generation", "path", "sha256"], "rollback worker claim binding");
  requiredText(value.workerClaim.generation, "rollback worker claim generation");
  if (value.phase === "REQUESTED") {
    if (value.restore !== null) throw new Error("Requested rollback authorization must not contain restore evidence.");
  } else {
    validateBoundFile(value.restore, ["generation", "journalPath", "journalSha256", "path", "sha256", "verifiedAt"], "rollback restore binding");
    requiredText(value.restore.generation, "rollback restore generation");
    if (!isCanonicalTimestamp(value.restore.verifiedAt)) throw new Error("Rollback restore verifiedAt is invalid.");
  }
}

function validateBoundFile(value, expectedKeys, label) {
  assertExactObjectKeys(value, expectedKeys, label);
  for (const key of expectedKeys.filter((key) => key.toLowerCase().endsWith("path"))) requiredText(value[key], `${label} ${key}`);
  for (const key of expectedKeys.filter((key) => key.toLowerCase().endsWith("sha256") || key.toLowerCase().endsWith("digest"))) requireDigest(value[key], `${label} ${key}`);
}

function assertControlMatchesLedger(control, ledger, storePath) {
  if (control.anchorNonce !== ledger.anchor.anchorNonce
    || canonicalJson(control.databaseIdentity) !== canonicalJson(databaseIdentityFromLedger(ledger))
    || canonicalJson(control.storeFile) !== canonicalJson(fileIdentity(storePath))
    || canonicalJson(control.current) !== canonicalJson(controlHeadFromLedger(ledger))) {
    throw new Error("Finalization SQLite head/inode differs from the rollback-preserved authenticated control anchor.");
  }
}

function buildAuthenticatedEvent(options) {
  const eventFields = {
    sequence: options.sequence,
    transactionId: options.transactionId,
    fromState: options.fromState,
    toState: options.toState,
    kind: options.kind,
    payloadDigest: options.payloadDigest,
    payloadJson: options.payloadJson,
    occurredAt: options.occurredAt,
    previousTransitionTag: options.previousTransitionTag,
  };
  const eventTag = lifecycleAuthenticationTag("EVENT", options.key, options.anchorNonce, eventFields);
  const transitionTag = lifecycleAuthenticationTag("TRANSITION", options.key, options.anchorNonce, {
    sequence: options.sequence,
    transactionId: options.transactionId,
    fromState: options.fromState,
    toState: options.toState,
    kind: options.kind,
    eventTag,
    previousTransitionTag: options.previousTransitionTag,
  });
  const finalTag = FINAL_STATES.includes(options.toState)
    ? lifecycleAuthenticationTag("FINAL", options.key, options.anchorNonce, {
      sequence: options.sequence,
      transactionId: options.transactionId,
      toState: options.toState,
      eventTag,
      transitionTag,
      payloadDigest: options.payloadDigest,
    })
    : null;
  return Object.freeze({ ...eventFields, eventTag, transitionTag, finalTag });
}

function validateAuthenticatedEventShape(value) {
  assertExactObjectKeys(value, [
    "eventTag", "finalTag", "fromState", "kind", "occurredAt", "payloadDigest", "payloadJson",
    "previousTransitionTag", "sequence", "toState", "transactionId", "transitionTag",
  ], "authenticated finalization event");
  if (!Number.isSafeInteger(value.sequence) || value.sequence < 1
    || !DIGEST_PATTERN.test(value.payloadDigest ?? "") || !TAG_PATTERN.test(value.eventTag ?? "")
    || !TAG_PATTERN.test(value.transitionTag ?? "") || !isCanonicalTimestamp(value.occurredAt)
    || (FINAL_STATES.includes(value.toState) ? !TAG_PATTERN.test(value.finalTag ?? "") : value.finalTag !== null)) {
    throw new Error("Authenticated finalization event shape is invalid.");
  }
  requiredTransactionId(value.transactionId);
  requiredState(value.fromState, true);
  requiredState(value.toState, false);
  requiredText(value.kind, "authenticated finalization event kind");
  requiredPayloadJson(value.payloadJson, "authenticated finalization event payloadJson");
  if (!TAG_PATTERN.test(value.previousTransitionTag ?? "")) throw new Error("Authenticated finalization event predecessor tag is invalid.");
}

function writePendingControl({ controlPath, storePath, key, before, event }) {
  const current = before.control;
  if (current.pending !== null) throw new Error("Cannot publish another finalization intent while PENDING exists.");
  const sqliteMutation = sqliteCopyOnWriteBinding(storePath, current, event);
  const pending = Object.freeze({
    event,
    proposed: Object.freeze({
      revision: current.current.revision + 1,
      state: event.toState,
      transactionId: event.transactionId,
      headTransitionTag: event.transitionTag,
      updatedAt: event.occurredAt,
    }),
    sqliteMutation,
  });
  const lock = acquireControlLock({
    controlPath,
    storePath,
    key,
    lockKind: "TRANSITION",
    intent: {
      expectedControlDigest: digestJson(current),
      event,
      proposedHead: pending.proposed,
      sqliteMutation,
    },
    now: () => event.occurredAt,
  });
  assertControlLock(lock, "TRANSITION", {
    expectedControlDigest: digestJson(current),
    event,
    proposedHead: pending.proposed,
    sqliteMutation,
  });
  const lockedCurrent = readAuthenticatedControl(controlPath, storePath, key);
  if (canonicalJson(lockedCurrent) !== canonicalJson(current)) {
    releaseControlLock(controlLockPath(controlPath), lock);
    throw new Error("Finalization transition predecessor changed before PENDING publication; semantic conflict.");
  }
  const next = authenticatedControlRecord({
    key,
    storePath,
    initialization: current.initialization,
    anchor: before.anchor,
    controlEpoch: current.controlEpoch + 1,
    previousControlTag: current.controlTag,
    storeFile: current.storeFile,
    databaseIdentity: current.databaseIdentity,
    current: current.current,
    pending,
    rollbackAuthorization: current.rollbackAuthorization,
  });
  replaceOwnerOnlyJsonCas(controlPath, current, next, "finalization PENDING control", lock);
  return Object.freeze({ control: next, lock });
}

function commitPendingControl({ controlPath, storePath, key, expectedPending, event, lock }) {
  const activeLock = lock ?? readAuthenticatedControlLock(controlLockPath(controlPath), storePath, key);
  assertControlLock(activeLock, "TRANSITION", {
    expectedControlDigest: activeLock.intent.expectedControlDigest,
    event,
    proposedHead: expectedPending.pending.proposed,
    sqliteMutation: expectedPending.pending.sqliteMutation,
  });
  const current = readAuthenticatedControl(controlPath, storePath, key);
  if (canonicalJson(current) !== canonicalJson(expectedPending)
    || canonicalJson(current.pending?.event) !== canonicalJson(event)) {
    throw new Error("Finalization external control changed before COMMITTED CAS; state is UNKNOWN.");
  }
  assertPublishedSqliteCopyOnWrite(storePath, current.pending.sqliteMutation);
  const database = openReadOnlyDatabasePath(storePath);
  let ledger;
  try { database.exec("pragma query_only = on"); ledger = readLedgerFromDatabase(database, storePath, key); }
  finally { database.close(); }
  if (canonicalJson(controlHeadFromLedger(ledger)) !== canonicalJson(current.pending.proposed)) {
    throw new Error("Finalization SQLite commit does not match its external PENDING intent.");
  }
  const next = authenticatedControlRecord({
    key,
    storePath,
    initialization: current.initialization,
    anchor: ledger.anchor,
    controlEpoch: current.controlEpoch + 1,
    previousControlTag: current.controlTag,
    storeFile: fileIdentity(storePath),
    databaseIdentity: current.databaseIdentity,
    current: current.pending.proposed,
    pending: null,
    rollbackAuthorization: current.rollbackAuthorization,
  });
  replaceOwnerOnlyJsonCas(controlPath, current, next, "finalization COMMITTED control", activeLock);
  removePublishedSqlitePreimage(storePath, current.pending.sqliteMutation, activeLock, controlPath);
  releaseControlLock(controlLockPath(controlPath), activeLock);
}

function reconcilePendingTransition({ storePath, controlPath, key, expected }) {
  const control = readAuthenticatedControl(controlPath, storePath, key);
  if (control.pending === null) return;
  const lock = readAuthenticatedControlLock(controlLockPath(controlPath), storePath, key);
  assertControlLock(lock, "TRANSITION", {
    expectedControlDigest: lock.intent.expectedControlDigest,
    event: control.pending.event,
    proposedHead: control.pending.proposed,
    sqliteMutation: control.pending.sqliteMutation,
  });
  const event = control.pending.event;
  if (event.transactionId !== expected.transactionId || event.fromState !== expected.expectedState
    || event.toState !== expected.nextState || event.kind !== expected.kind
    || event.payloadJson !== expected.payloadJson) {
    throw new Error("Existing finalization PENDING intent differs from the requested exact transition.");
  }
  recoverSqliteCopyOnWrite(storePath, control.pending.sqliteMutation, lock, controlPath);
  const database = openReadOnlyDatabasePath(storePath);
  let ledger;
  try { database.exec("pragma query_only = on"); ledger = readLedgerFromDatabase(database, storePath, key); }
  finally { database.close(); }
  const observed = controlHeadFromLedger(ledger);
  if (canonicalJson(observed) === canonicalJson(control.pending.proposed)) {
    commitPendingControl({ controlPath, storePath, key, expectedPending: control, event, lock });
    return;
  }
  if (canonicalJson(observed) !== canonicalJson(control.current)) {
    throw new Error("Finalization PENDING recovery found an ambiguous SQLite head; state remains UNKNOWN.");
  }
  const writable = openWritableFinalizationStore(storePath, controlPath, control, lock);
  const writableDatabase = writable.database;
  try {
    writableDatabase.exec("begin immediate");
    try {
      const head = writableDatabase.prepare("select sequence, transition_tag as transitionTag from finalization_events order by sequence desc limit 1").get();
      const count = Number(firstColumn(writableDatabase.prepare("select count(*) from finalization_events").get()));
      if (count !== event.sequence - 1
        || (head?.transitionTag ?? control.databaseIdentity.anchorTag) !== event.previousTransitionTag) {
        throw new Error("Finalization SQLite head changed while recovering PENDING.");
      }
      writableDatabase.prepare(`
        insert into finalization_events
          (sequence, transaction_id, from_state, to_state, kind, payload_json,
           payload_digest, occurred_at, previous_transition_tag, event_tag,
           transition_tag, final_tag)
        values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      `).run(
        event.sequence, event.transactionId, event.fromState, event.toState, event.kind,
        event.payloadJson, event.payloadDigest, event.occurredAt, event.previousTransitionTag,
        event.eventTag, event.transitionTag, event.finalTag,
      );
      writableDatabase.exec("commit");
      writableDatabase.prepare("pragma wal_checkpoint(truncate)").all();
    } catch (error) {
      try { writableDatabase.exec("rollback"); } catch { /* transaction may have committed */ }
      throw error;
    }
  } finally { writableDatabase.close(); }
  writable.publish();
  fsyncFile(storePath);
  fsyncDirectory(dirname(storePath));
  commitPendingControl({ controlPath, storePath, key, expectedPending: control, event, lock });
}

function sqliteCopyOnWriteBinding(storePath, control, event) {
  const token = event.transitionTag.slice("hmac-sha256:".length);
  const prefix = join(dirname(storePath), `.${basename(storePath)}.transition-${token}`);
  return Object.freeze({
    journalPath: `${prefix}.staging.sqlite-journal`,
    preimagePath: `${prefix}.preimage.sqlite`,
    sourceStoreFile: control.storeFile,
    stagingPath: `${prefix}.staging.sqlite`,
  });
}

function validateSqliteCopyOnWriteBinding(value, storePath, expectedStoreFile, event) {
  assertExactObjectKeys(value, ["journalPath", "preimagePath", "sourceStoreFile", "stagingPath"], "finalization SQLite copy-on-write binding");
  validateFileIdentity(value.sourceStoreFile, "finalization SQLite copy-on-write source inode");
  if (expectedStoreFile && canonicalJson(value.sourceStoreFile) !== canonicalJson(expectedStoreFile)) {
    throw new Error("Finalization SQLite copy-on-write source inode differs from authenticated control.");
  }
  validateAuthenticatedEventShape(event);
  const expected = sqliteCopyOnWriteBinding(storePath, { storeFile: value.sourceStoreFile }, event);
  if (canonicalJson(value) !== canonicalJson(expected)) {
    throw new Error("Finalization SQLite copy-on-write paths are not the exact event-derived binding.");
  }
  for (const [path, label] of [
    [value.stagingPath, "staging path"],
    [value.journalPath, "journal path"],
    [value.preimagePath, "preimage path"],
  ]) {
    if (!isAbsolute(path) || resolve(path) !== path || dirname(path) !== dirname(storePath)) {
      throw new Error(`Finalization SQLite copy-on-write ${label} is not canonical or colocated.`);
    }
  }
}

function validateTransitionLockIntent(value, storePath) {
  assertExactObjectKeys(value, [
    "event", "expectedControlDigest", "proposedHead", "sqliteMutation",
  ], "finalization TRANSITION lock intent");
  requireDigest(value.expectedControlDigest, "finalization transition expected control digest");
  validateAuthenticatedEventShape(value.event);
  validateControlHead(value.proposedHead, "finalization transition proposed head");
  validateSqliteCopyOnWriteBinding(
    value.sqliteMutation,
    storePath,
    value.sqliteMutation?.sourceStoreFile,
    value.event,
  );
}

function assertNoUnboundSqliteMutationResidue(storePath, allowedMutation) {
  const parent = canonicalRealDirectory(dirname(storePath), "finalization store parent");
  const base = basename(storePath);
  const allowed = new Set();
  if (allowedMutation) {
    for (const path of [allowedMutation.stagingPath, allowedMutation.journalPath, allowedMutation.preimagePath]) {
      allowed.add(path);
      allowed.add(sqliteDiscardPath(path));
    }
  }
  for (const entry of readdirSync(parent, { withFileTypes: true })) {
    const recognized = entry.name === `${base}-journal`
      || entry.name === `${base}-wal`
      || entry.name === `${base}-shm`
      || entry.name.startsWith(`.${base}.transition-`)
      || entry.name.startsWith(`.${base}.inode-`)
      || entry.name.startsWith(`.${base}.guard-`)
      || entry.name.startsWith(`.${base}.initialize-`);
    if (!recognized) continue;
    const path = join(parent, entry.name);
    if (!allowed.has(path)) {
      throw new Error(`Unbound finalization SQLite mutation residue makes state UNKNOWN: ${entry.name}`);
    }
    assertOwnerOnlyRegularEntry(path, "bound finalization SQLite mutation residue");
  }
}

function recoverSqliteCopyOnWrite(storePath, mutation, lock, controlPath) {
  validateSqliteCopyOnWriteBinding(mutation, storePath, mutation?.sourceStoreFile, lock.intent.event);
  assertControlLockStillCurrent(controlLockPath(controlPath), lock);
  assertNoUnboundSqliteMutationResidue(storePath, mutation);
  const current = fileIdentity(storePath);
  if (canonicalJson(current) === canonicalJson(mutation.sourceStoreFile)) {
    quarantineRemoveBoundPath(mutation.journalPath, mutation, "abandoned finalization SQLite journal");
    quarantineRemoveBoundPath(mutation.stagingPath, mutation, "abandoned finalization SQLite staging");
    quarantineRemoveBoundPath(
      mutation.preimagePath,
      mutation,
      "abandoned finalization SQLite preimage",
      mutation.sourceStoreFile,
    );
    assertNoUnboundSqliteMutationResidue(storePath, null);
    return "SOURCE";
  }
  assertPublishedSqliteCopyOnWrite(storePath, mutation);
  return "PUBLISHED";
}

function assertPublishedSqliteCopyOnWrite(storePath, mutation) {
  validateFileIdentity(mutation.sourceStoreFile, "published finalization SQLite source inode");
  assertNoUnboundSqliteMutationResidue(storePath, mutation);
  if (canonicalJson(fileIdentity(storePath)) === canonicalJson(mutation.sourceStoreFile)) {
    throw new Error("Finalization SQLite copy-on-write publication has not replaced the source inode.");
  }
  if (!lstatIfPresent(mutation.preimagePath)) {
    throw new Error("Finalization SQLite copy-on-write publication lacks its exact old-inode preimage.");
  }
  assertStoreFileIdentity(mutation.preimagePath, mutation.sourceStoreFile);
  for (const path of [
    mutation.stagingPath,
    mutation.journalPath,
    sqliteDiscardPath(mutation.stagingPath),
    sqliteDiscardPath(mutation.journalPath),
  ]) {
    if (lstatIfPresent(path)) throw new Error("Published finalization SQLite copy-on-write retains staging or journal residue.");
  }
}

function removePublishedSqlitePreimage(storePath, mutation, lock, controlPath) {
  assertControlLockStillCurrent(controlLockPath(controlPath), lock);
  assertPublishedSqliteCopyOnWrite(storePath, mutation);
  quarantineRemoveBoundPath(
    mutation.preimagePath,
    mutation,
    "committed finalization SQLite preimage",
    mutation.sourceStoreFile,
  );
  assertNoUnboundSqliteMutationResidue(storePath, null);
}

function cleanupCommittedSqliteCopyOnWrite(storePath, control, mutation, lock, controlPath) {
  validateSqliteCopyOnWriteBinding(mutation, storePath, mutation?.sourceStoreFile, lock.intent.event);
  assertStoreFileIdentity(storePath, control.storeFile);
  if (canonicalJson(control.storeFile) === canonicalJson(mutation.sourceStoreFile)) {
    throw new Error("Committed finalization control still identifies the pre-transition SQLite inode.");
  }
  assertNoUnboundSqliteMutationResidue(storePath, mutation);
  for (const path of [mutation.stagingPath, mutation.journalPath]) {
    if (lstatIfPresent(path) || lstatIfPresent(sqliteDiscardPath(path))) {
      throw new Error("Committed finalization transition retains ambiguous SQLite staging residue.");
    }
  }
  quarantineRemoveBoundPath(
    mutation.preimagePath,
    mutation,
    "recovered committed finalization SQLite preimage",
    mutation.sourceStoreFile,
  );
  assertNoUnboundSqliteMutationResidue(storePath, null);
}

function stableCopyFileNoReplace(sourcePath, targetPath, expectedSource, label) {
  if (lstatIfPresent(targetPath)) throw new Error(`${label} already exists.`);
  const parent = canonicalRealDirectory(dirname(sourcePath), `${label} parent`);
  const parentBefore = lstatSync(parent, { bigint: true });
  const source = openSync(sourcePath, constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0));
  let target;
  try {
    const before = fstatSync(source, { bigint: true });
    if (!before.isFile() || before.dev.toString() !== expectedSource.dev || before.ino.toString() !== expectedSource.ino) {
      throw new Error(`${label} source inode differs from authenticated control.`);
    }
    const bytes = readFileSync(source);
    const after = fstatSync(source, { bigint: true });
    if (before.dev !== after.dev || before.ino !== after.ino || before.size !== after.size
      || before.mtimeNs !== after.mtimeNs || BigInt(bytes.length) !== after.size) {
      throw new Error(`${label} source changed during stable descriptor copy.`);
    }
    target = openSync(
      targetPath,
      constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | (constants.O_NOFOLLOW ?? 0),
      0o600,
    );
    writeFileSync(target, bytes);
    fsyncSync(target);
  } finally {
    if (target !== undefined) closeSync(target);
    closeSync(source);
  }
  const parentAfter = lstatSync(parent, { bigint: true });
  if (parentBefore.dev !== parentAfter.dev || parentBefore.ino !== parentAfter.ino) {
    throw new Error(`${label} parent changed during publication.`);
  }
  assertStoreFileIdentity(sourcePath, expectedSource);
  assertOwnerOnlyRegularEntry(targetPath, label);
  fsyncDirectory(parent);
}

function quarantineRemoveBoundPath(path, mutation, label, expectedIdentity) {
  const discardPath = sqliteDiscardPath(path);
  const current = lstatIfPresent(path);
  const discarded = lstatIfPresent(discardPath);
  if (current && discarded) throw new Error(`${label} has both live and quarantined entries.`);
  if (!current && !discarded) return false;
  let target = discardPath;
  if (current) {
    assertOwnerOnlyRegularEntry(path, label);
    const before = fileIdentity(path);
    if (expectedIdentity && canonicalJson(before) !== canonicalJson(expectedIdentity)) {
      throw new Error(`${label} inode differs from its authenticated binding.`);
    }
    renameSync(path, discardPath);
    fsyncDirectory(dirname(path));
    if (canonicalJson(fileIdentity(discardPath)) !== canonicalJson(before)) {
      throw new Error(`${label} inode changed during quarantine-first removal.`);
    }
  } else {
    assertOwnerOnlyRegularEntry(discardPath, `${label} quarantine`);
    if (expectedIdentity && canonicalJson(fileIdentity(discardPath)) !== canonicalJson(expectedIdentity)) {
      throw new Error(`${label} quarantined inode differs from its authenticated binding.`);
    }
  }
  unlinkSync(target);
  fsyncDirectory(dirname(target));
  return true;
}

function sqliteDiscardPath(path) {
  return `${path}.discard`;
}

function assertOwnerOnlyRegularEntry(path, label) {
  const metadata = lstatSync(path);
  if (!metadata.isFile() || metadata.isSymbolicLink() || realpathSync(path) !== path
    || (metadata.mode & 0o077) !== 0
    || (typeof process.getuid === "function" && metadata.uid !== process.getuid())) {
    throw new Error(`${label} must be an owner-only no-follow regular file.`);
  }
}

function openWritableFinalizationStore(storePath, controlPath, control, lock) {
  canonicalOwnerOnlyFile(storePath, "finalization store");
  assertStoreFileIdentity(storePath, control.storeFile);
  const parent = canonicalRealDirectory(dirname(storePath), "finalization store parent");
  const mutation = control.pending?.sqliteMutation;
  validateSqliteCopyOnWriteBinding(mutation, storePath, control.storeFile, control.pending?.event);
  assertControlLockStillCurrent(controlLockPath(controlPath), lock);
  assertNoUnboundSqliteMutationResidue(storePath, mutation);
  if (lstatIfPresent(mutation.stagingPath) || lstatIfPresent(mutation.journalPath)
    || lstatIfPresent(mutation.preimagePath)) {
    throw new Error("Bound finalization SQLite copy-on-write residue already exists; explicit recovery is required.");
  }
  stableCopyFileNoReplace(
    storePath,
    mutation.stagingPath,
    mutation.sourceStoreFile,
    "finalization SQLite copy-on-write staging",
  );
  const database = new DatabaseSync(mutation.stagingPath);
  assertStoreFileIdentity(storePath, mutation.sourceStoreFile);
  database.exec("pragma journal_mode = delete");
  database.exec("pragma synchronous = full");
  database.exec("pragma busy_timeout = 5000");
  database.exec("pragma foreign_keys = on");
  let published = false;
  return Object.freeze({
    database,
    publish() {
      if (published) throw new Error("Finalization SQLite copy-on-write publication cannot repeat.");
      published = true;
      assertControlLockStillCurrent(controlLockPath(controlPath), lock);
      if (lstatIfPresent(mutation.journalPath)) {
        throw new Error("Finalization SQLite staging retained a journal; state is UNKNOWN until explicit recovery.");
      }
      fsyncFile(mutation.stagingPath);
      assertStoreFileIdentity(storePath, mutation.sourceStoreFile);
      if (lstatIfPresent(mutation.preimagePath)) {
        throw new Error("Finalization SQLite preimage appeared before copy-on-write publish.");
      }
      try {
        linkSync(storePath, mutation.preimagePath);
      } catch (error) {
        if (error?.code === "EEXIST") {
          throw new Error("Finalization SQLite preimage appeared before atomic no-replace publish.");
        }
        throw error;
      }
      fsyncDirectory(parent);
      assertStoreFileIdentity(mutation.preimagePath, mutation.sourceStoreFile);
      assertStoreFileIdentity(storePath, mutation.sourceStoreFile);
      assertControlLockStillCurrent(controlLockPath(controlPath), lock);
      renameSync(mutation.stagingPath, storePath);
      chmodSync(storePath, 0o600);
      fsyncFile(storePath);
      fsyncDirectory(parent);
      if (canonicalJson(fileIdentity(storePath)) === canonicalJson(mutation.sourceStoreFile)) {
        throw new Error("Finalization SQLite copy-on-write publish did not replace the canonical inode.");
      }
      assertStoreFileIdentity(mutation.preimagePath, mutation.sourceStoreFile);
      if (lstatIfPresent(mutation.stagingPath) || lstatIfPresent(mutation.journalPath)) {
        throw new Error("Finalization SQLite copy-on-write publish left staging residue.");
      }
    },
  });
}

function openWritableDatabasePath(path) {
  const database = new DatabaseSync(path);
  database.exec("pragma journal_mode = delete");
  database.exec("pragma synchronous = full");
  database.exec("pragma busy_timeout = 5000");
  database.exec("pragma foreign_keys = on");
  return database;
}

function openReadOnlyFinalizationStore(storePath, control) {
  assertStoreFileIdentity(storePath, control.storeFile);
  const descriptor = openSync(storePath, constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0));
  const before = fstatSync(descriptor, { bigint: true });
  const database = new DatabaseSync(`/dev/fd/${descriptor}`, { readOnly: true });
  try {
    const after = fstatSync(descriptor, { bigint: true });
    if (!before.isFile() || before.dev !== after.dev || before.ino !== after.ino
      || before.dev.toString() !== control.storeFile.dev || before.ino.toString() !== control.storeFile.ino) {
      throw new Error("Finalization store descriptor identity differs from authenticated external control.");
    }
    assertStoreFileIdentity(storePath, control.storeFile);
    wrapDatabaseClose(database, () => closeSync(descriptor));
    return database;
  } catch (error) {
    database.close();
    closeSync(descriptor);
    throw error;
  }
}

function openReadOnlyDatabasePath(storePath) {
  canonicalOwnerOnlyFile(storePath, "finalization store");
  const descriptor = openSync(storePath, constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0));
  const before = fstatSync(descriptor, { bigint: true });
  const database = new DatabaseSync(`/dev/fd/${descriptor}`, { readOnly: true });
  try {
    const after = fstatSync(descriptor, { bigint: true });
    if (!before.isFile() || before.dev !== after.dev || before.ino !== after.ino
      || before.dev.toString() !== fileIdentity(storePath).dev
      || before.ino.toString() !== fileIdentity(storePath).ino) {
      throw new Error("Finalization store inode changed while opening SQLite.");
    }
    wrapDatabaseClose(database, () => closeSync(descriptor));
    return database;
  } catch (error) {
    database.close();
    closeSync(descriptor);
    throw error;
  }
}

function wrapDatabaseClose(database, afterClose) {
  const closeDatabase = database.close.bind(database);
  let closed = false;
  Object.defineProperty(database, "close", {
    configurable: false,
    enumerable: false,
    writable: false,
    value() {
      if (closed) return;
      closed = true;
      let closeError;
      try { closeDatabase(); } catch (error) { closeError = error; }
      try { afterClose(); } catch (error) { if (!closeError) closeError = error; }
      if (closeError) throw closeError;
    },
  });
}

function assertExactFinalizationSchema(database) {
  const observed = database.prepare(`
    select type, name, sql from sqlite_master
     where name not like 'sqlite_%'
     order by type, name
  `).all().map((entry) => ({
    type: entry.type,
    name: entry.name,
    sql: normalizeSql(entry.sql),
  })).sort(compareSchemaObject);
  const expected = FINALIZATION_STORE_DDL.map((sql) => {
    const match = /^create\s+(table|index|trigger)\s+([a-z0-9_]+)/iu.exec(sql.trim());
    if (!match) throw new Error(`Finalization contract DDL has no canonical object identity: ${sql}`);
    return { type: match[1].toLowerCase(), name: match[2], sql: normalizeSql(sql) };
  }).sort(compareSchemaObject);
  if (canonicalJson(observed) !== canonicalJson(expected)) {
    throw new Error("Finalization database sqlite_master SQL differs from the exact authenticated append-only DDL contract.");
  }
}

function normalizeSql(value) {
  return String(value ?? "")
    .trim()
    .replaceAll(/\s+/gu, " ")
    .replace(/;$/u, "")
    .replace(/^CREATE (TABLE|INDEX|TRIGGER) /u, (_match, type) => `create ${type.toLowerCase()} `);
}

function assertAllowedFinalizationTransition(fromState, toState) {
  requiredState(fromState, true);
  requiredState(toState, false);
  if (TERMINAL_FINALIZATION_STATES.includes(fromState)) {
    throw new Error(`Finalization lifecycle state is terminal: ${fromState}`);
  }
  if (ERROR_FINALIZATION_STATES.includes(toState)) {
    if (fromState === "DRAFT") throw new Error("An unprepared DRAFT cannot transition to an error terminal.");
    return;
  }
  const fromIndex = FORWARD_FINALIZATION_STATES.indexOf(fromState);
  const toIndex = FORWARD_FINALIZATION_STATES.indexOf(toState);
  if (fromIndex < 0 || toIndex !== fromIndex + 1) {
    throw new Error(`Finalization lifecycle transition must be one exact forward step: ${fromState} -> ${toState}`);
  }
}

function normalizeManagementKey(value) {
  const key = requiredObject(value, "management authorization key");
  if (!KEY_ID_PATTERN.test(key.keyId ?? "")) {
    throw new Error("Management authorization keyId is not canonical.");
  }
  if (!(key.secret instanceof Uint8Array) || key.secret.byteLength !== 32) {
    throw new Error("Management authorization key secret must be exactly 32 bytes.");
  }
  const expectedKeyId = `management-${createHash("sha256").update(key.secret).digest("hex").slice(0, 24)}`;
  if (key.keyId !== expectedKeyId) {
    throw new Error("Management authorization keyId does not match the supplied key material.");
  }
  return Object.freeze({ keyId: key.keyId, secret: Uint8Array.from(key.secret) });
}

function authenticationTag(kind, key, payload) {
  const base = canonicalJson({
    schemaVersion: FINALIZATION_STORE_SCHEMA_VERSION,
    kind,
    keyId: key.keyId,
    payload,
  });
  const mac = createHmac("sha256", key.secret)
    .update(`devspace.finalization-store.v2/${kind}\0`)
    .update(base)
    .digest("hex");
  return `hmac-sha256:${mac}`;
}

function assertAuthenticationTag(kind, key, payload, observed) {
  if (!TAG_PATTERN.test(observed ?? "")) {
    throw new Error(`Finalization ${kind.toLowerCase()} authentication tag is invalid.`);
  }
  const expected = authenticationTag(kind, key, payload);
  const left = Buffer.from(expected);
  const right = Buffer.from(observed);
  if (left.length !== right.length || !timingSafeEqual(left, right)) {
    throw new Error(`Finalization ${kind.toLowerCase()} authentication failed.`);
  }
}

function lifecycleAuthenticationTag(kind, key, anchorNonce, payload) {
  if (!NONCE_PATTERN.test(anchorNonce ?? "")) throw new Error("Lifecycle commit anchor nonce is invalid.");
  const commitKey = createHmac("sha256", key.secret)
    .update("devspace.finalization-store.v2/LIFECYCLE-COMMIT-KEY\0")
    .update(anchorNonce)
    .digest();
  const base = canonicalJson({
    schemaVersion: FINALIZATION_STORE_SCHEMA_VERSION,
    kind,
    keyId: key.keyId,
    anchorNonce,
    payload,
  });
  return `hmac-sha256:${createHmac("sha256", commitKey)
    .update(`devspace.finalization-store.v2/LIFECYCLE-${kind}\0`)
    .update(base)
    .digest("hex")}`;
}

function assertLifecycleAuthenticationTag(kind, key, anchorNonce, payload, observed) {
  if (!TAG_PATTERN.test(observed ?? "")) throw new Error(`Finalization lifecycle ${kind} tag is invalid.`);
  assertSameTag(lifecycleAuthenticationTag(kind, key, anchorNonce, payload), observed,
    `Finalization lifecycle ${kind} authentication failed.`);
}

function controlAuthenticationTag(key, payload) {
  const base = canonicalJson({
    schemaVersion: CONTROL_SCHEMA_VERSION,
    kind: "CONTROL",
    keyId: key.keyId,
    payload,
  });
  return `hmac-sha256:${createHmac("sha256", key.secret)
    .update("devspace.finalization-store.v2/EXTERNAL-CONTROL\0")
    .update(base)
    .digest("hex")}`;
}

function assertControlAuthenticationTag(key, payload, observed) {
  if (!TAG_PATTERN.test(observed ?? "")) throw new Error("Finalization external control tag is invalid.");
  assertSameTag(controlAuthenticationTag(key, payload), observed, "Finalization external control authentication failed.");
}

function assertSameTag(expected, observed, message) {
  const left = Buffer.from(expected);
  const right = Buffer.from(observed);
  if (left.length !== right.length || !timingSafeEqual(left, right)) throw new Error(message);
}

function canonicalLifecycleStorePath(value, allowMissing) {
  const storePath = resolve(requiredText(value, "finalization storePath"));
  if (storePath !== value || basename(storePath) !== "lifecycle.sqlite") {
    throw new Error("Finalization storePath must be the absolute canonical <stateRoot>/lifecycle.sqlite path.");
  }
  const stateRoot = dirname(storePath);
  const rootMetadata = lstatSync(stateRoot);
  if (!rootMetadata.isDirectory()
    || rootMetadata.isSymbolicLink()
    || realpathSync(stateRoot) !== stateRoot
    || (rootMetadata.mode & 0o077) !== 0
    || (typeof process.getuid === "function" && rootMetadata.uid !== process.getuid())) {
    throw new Error("Finalization stateRoot must be an owner-only canonical real directory.");
  }
  const metadata = lstatIfPresent(storePath);
  if (!metadata && !allowMissing) throw missingPathError(storePath);
  if (metadata) canonicalOwnerOnlyFile(storePath, "finalization store");
  return storePath;
}

function canonicalControlPath(value, storePath, allowMissing) {
  const controlPath = resolve(requiredText(value, "finalization controlPath"));
  if (controlPath !== value || basename(controlPath) !== CONTROL_FILE_NAME) {
    throw new Error(`Finalization controlPath must be the absolute canonical rollback-preserved ${CONTROL_FILE_NAME} path.`);
  }
  const controlRoot = dirname(controlPath);
  const rootMetadata = lstatSync(controlRoot);
  if (!rootMetadata.isDirectory() || rootMetadata.isSymbolicLink() || realpathSync(controlRoot) !== controlRoot
    || (rootMetadata.mode & 0o077) !== 0
    || (typeof process.getuid === "function" && rootMetadata.uid !== process.getuid())) {
    throw new Error("Finalization control root must be an owner-only canonical real directory.");
  }
  if (isSameOrInside(dirname(storePath), controlPath) || isSameOrInside(controlRoot, storePath)) {
    throw new Error("Finalization rollback-preserved control must not overlap the mutable stateRoot/store path.");
  }
  const metadata = lstatIfPresent(controlPath);
  if (!metadata && !allowMissing) throw missingControlPathError(controlPath);
  if (metadata) canonicalOwnerOnlyFile(controlPath, "finalization external control");
  return controlPath;
}

function fileIdentity(path) {
  const metadata = lstatSync(path, { bigint: true });
  if (!metadata.isFile() || metadata.isSymbolicLink()) throw new Error(`Finalization file identity is not regular: ${path}`);
  return Object.freeze({ dev: metadata.dev.toString(), ino: metadata.ino.toString() });
}

function validateFileIdentity(value, label) {
  assertExactObjectKeys(value, ["dev", "ino"], label);
  if (!/^[0-9]+$/u.test(value.dev ?? "") || !/^[0-9]+$/u.test(value.ino ?? "")) throw new Error(`${label} is invalid.`);
}

function assertStoreFileIdentity(path, expected) {
  validateFileIdentity(expected, "expected finalization store file identity");
  if (canonicalJson(fileIdentity(path)) !== canonicalJson(expected)) {
    throw new Error("Finalization store inode changed; refusing path-based SQLite open.");
  }
}

function publishNewFileNoReplace(stagingPath, targetPath, label) {
  if (lstatIfPresent(targetPath)) throw new Error(`${label} already exists; refusing replacement.`);
  try {
    linkSync(stagingPath, targetPath);
  } catch (error) {
    if (error?.code === "EEXIST") throw new Error(`${label} appeared before atomic no-replace publish.`);
    throw error;
  }
  unlinkSync(stagingPath);
  chmodSync(targetPath, 0o600);
  fsyncFile(targetPath);
}

function stableReadFile(path, label) {
  const descriptor = openSync(path, constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0));
  try {
    const before = fstatSync(descriptor, { bigint: true });
    const bytes = readFileSync(descriptor);
    const after = fstatSync(descriptor, { bigint: true });
    if (!before.isFile() || before.dev !== after.dev || before.ino !== after.ino
      || before.size !== after.size || before.mtimeNs !== after.mtimeNs
      || BigInt(bytes.length) !== after.size) {
      throw new Error(`${label} changed during its single-descriptor no-follow read.`);
    }
    return bytes;
  } finally {
    closeSync(descriptor);
  }
}

function writeOwnerOnlyJsonNew(path, value, label) {
  if (lstatIfPresent(path)) throw new Error(`${label} already exists; refusing replacement.`);
  const parent = canonicalRealDirectory(dirname(path), `${label} parent`);
  const parentBefore = lstatSync(parent, { bigint: true });
  const stagingPath = join(parent, `.${basename(path)}.new-${randomBytes(16).toString("hex")}`);
  const descriptor = openSync(stagingPath, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | (constants.O_NOFOLLOW ?? 0), 0o600);
  try {
    writeFileSync(descriptor, `${canonicalJson(value)}\n`, "utf8");
    fsyncSync(descriptor);
  } finally {
    closeSync(descriptor);
  }
  try {
    const parentAfter = lstatSync(parent, { bigint: true });
    if (parentBefore.dev !== parentAfter.dev || parentBefore.ino !== parentAfter.ino) {
      throw new Error(`${label} parent changed before publish.`);
    }
    publishNewFileNoReplace(stagingPath, path, label);
    fsyncDirectory(parent);
  } finally {
    try { unlinkSync(stagingPath); } catch { /* staging may already be published */ }
  }
}

function replaceOwnerOnlyJsonCas(path, expected, replacement, label, lock) {
  if (replacement.controlEpoch !== expected.controlEpoch + 1
    || replacement.previousControlTag !== expected.controlTag) {
    throw new Error(`${label} does not extend the exact predecessor epoch/tag.`);
  }
  assertControlLockStillCurrent(controlLockPath(path), lock);
  const current = parseJsonBytes(stableReadFile(path, label), label);
  if (canonicalJson(current) !== canonicalJson(expected)) throw new Error(`${label} CAS predecessor differs.`);
  const parent = canonicalRealDirectory(dirname(path), `${label} parent`);
  const parentBefore = lstatSync(parent, { bigint: true });
  const pathBefore = lstatSync(path, { bigint: true });
  const stagingPath = join(parent, `.${basename(path)}.cas-${randomBytes(16).toString("hex")}`);
  const descriptor = openSync(stagingPath, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | (constants.O_NOFOLLOW ?? 0), 0o600);
  try {
    writeFileSync(descriptor, `${canonicalJson(replacement)}\n`, "utf8");
    fsyncSync(descriptor);
  } finally { closeSync(descriptor); }
  try {
    assertControlLockStillCurrent(controlLockPath(path), lock);
    const pathCurrent = lstatSync(path, { bigint: true });
    const parentCurrent = lstatSync(parent, { bigint: true });
    if (pathBefore.dev !== pathCurrent.dev || pathBefore.ino !== pathCurrent.ino
      || pathBefore.size !== pathCurrent.size || pathBefore.mtimeNs !== pathCurrent.mtimeNs
      || parentBefore.dev !== parentCurrent.dev || parentBefore.ino !== parentCurrent.ino
      || canonicalJson(parseJsonBytes(stableReadFile(path, label), label)) !== canonicalJson(expected)) {
      throw new Error(`${label} changed despite exclusive control lock.`);
    }
    renameSync(stagingPath, path);
    chmodSync(path, 0o600);
    fsyncFile(path);
    fsyncDirectory(parent);
  } finally {
    try { unlinkSync(stagingPath); } catch { /* renamed or absent */ }
  }
}

function replaceOwnerOnlyJsonUnderGuard(path, expected, replacement, guardPath, guard, label) {
  assertControlLockStillCurrent(guardPath, guard);
  const current = parseJsonBytes(stableReadFile(path, label), label);
  if (canonicalJson(current) !== canonicalJson(expected)) throw new Error(`${label} predecessor differs.`);
  const parent = canonicalRealDirectory(dirname(path), `${label} parent`);
  const parentBefore = lstatSync(parent, { bigint: true });
  const pathBefore = lstatSync(path, { bigint: true });
  const stagingPath = join(parent, `.${basename(path)}.handoff-${randomBytes(16).toString("hex")}`);
  const descriptor = openSync(
    stagingPath,
    constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | (constants.O_NOFOLLOW ?? 0),
    0o600,
  );
  try {
    writeFileSync(descriptor, `${canonicalJson(replacement)}\n`, "utf8");
    fsyncSync(descriptor);
  } finally { closeSync(descriptor); }
  try {
    assertControlLockStillCurrent(guardPath, guard);
    const pathCurrent = lstatSync(path, { bigint: true });
    const parentCurrent = lstatSync(parent, { bigint: true });
    if (pathBefore.dev !== pathCurrent.dev || pathBefore.ino !== pathCurrent.ino
      || pathBefore.size !== pathCurrent.size || pathBefore.mtimeNs !== pathCurrent.mtimeNs
      || parentBefore.dev !== parentCurrent.dev || parentBefore.ino !== parentCurrent.ino
      || canonicalJson(parseJsonBytes(stableReadFile(path, label), label)) !== canonicalJson(expected)) {
      throw new Error(`${label} changed despite its exclusive recovery guard.`);
    }
    renameSync(stagingPath, path);
    chmodSync(path, 0o600);
    fsyncFile(path);
    fsyncDirectory(parent);
  } finally {
    try { unlinkSync(stagingPath); } catch { /* renamed or absent */ }
  }
}

function canonicalOwnerOnlyFile(value, label) {
  const path = resolve(requiredText(value, label));
  if (path !== value) throw new Error(`${label} must be an absolute canonical path.`);
  const metadata = lstatSync(path);
  if (!metadata.isFile()
    || metadata.isSymbolicLink()
    || realpathSync(path) !== path
    || (metadata.mode & 0o077) !== 0
    || (typeof process.getuid === "function" && metadata.uid !== process.getuid())) {
    throw new Error(`${label} must be an owner-only canonical real file.`);
  }
  return path;
}

function canonicalRealFile(value, label) {
  const path = resolve(requiredText(value, label));
  const metadata = lstatSync(path);
  if (!metadata.isFile() || metadata.isSymbolicLink() || realpathSync(path) !== path) {
    throw new Error(`${label} must be a canonical real file.`);
  }
  return path;
}

function canonicalRealDirectory(value, label) {
  const path = resolve(requiredText(value, label));
  const metadata = lstatSync(path);
  if (!metadata.isDirectory() || metadata.isSymbolicLink() || realpathSync(path) !== path) {
    throw new Error(`${label} must be a canonical real directory.`);
  }
  return path;
}

function parseChecksumManifest(text) {
  const output = new Map();
  for (const line of String(text).split("\n")) {
    if (!line) continue;
    const match = /^([a-f0-9]{64})  ([^\0\r\n]+)$/u.exec(line);
    if (!match || output.has(match[2])) throw new Error("Immutable release SHA256SUMS is invalid or duplicated.");
    const path = match[2];
    if (isAbsolute(path) || path === ".." || path.startsWith(`..${sep}`) || path.includes("\\")) {
      throw new Error("Immutable release SHA256SUMS contains an unsafe path.");
    }
    output.set(path, match[1]);
  }
  if (output.size === 0) throw new Error("Immutable release SHA256SUMS is empty.");
  return output;
}

function resolveContained(root, path) {
  const absolute = resolve(root, path);
  if (!isSameOrInside(root, absolute)) throw new Error(`Immutable release path escapes package root: ${path}`);
  return absolute;
}

function isSameOrInside(root, path) {
  const relation = relative(root, path);
  return relation === "" || (relation !== ".." && !relation.startsWith(`..${sep}`) && !isAbsolute(relation));
}

function toPosix(value) {
  return value.split(sep).join("/");
}

function lstatIfPresent(path) {
  try { return lstatSync(path); } catch (error) {
    if (error?.code === "ENOENT") return undefined;
    throw error;
  }
}

function isProcessAlive(pid) {
  if (!Number.isSafeInteger(pid) || pid < 1) return false;
  try {
    process.kill(pid, 0);
    return true;
  } catch (error) {
    if (error?.code === "ESRCH") return false;
    if (error?.code === "EPERM") return true;
    throw error;
  }
}

function missingPathError(path) {
  const error = new Error(`ENOENT: finalization store is missing: ${path}`);
  error.code = "ENOENT";
  return error;
}

function missingControlPathError(path) {
  const error = new Error(`ENOENT: finalization external control is missing: ${path}`);
  error.code = "ENOENT";
  return error;
}

function parseJsonBytes(bytes, label) {
  try {
    return JSON.parse(bytes.toString("utf8"));
  } catch {
    throw new Error(`${label} is not valid JSON.`);
  }
}

function fsyncFile(path) {
  const descriptor = openSync(path, constants.O_RDONLY);
  try { fsyncSync(descriptor); } finally { closeSync(descriptor); }
}

function fsyncDirectory(path) {
  let descriptor;
  try {
    descriptor = openSync(path, constants.O_RDONLY);
    fsyncSync(descriptor);
  } catch (error) {
    if (!["EINVAL", "ENOTSUP", "EISDIR", "EPERM"].includes(error?.code)) throw error;
  } finally {
    if (descriptor !== undefined) closeSync(descriptor);
  }
}

function requiredObject(value, label) {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error(`${label} is missing or invalid.`);
  return value;
}

function requiredText(value, label) {
  if (typeof value !== "string" || value.length === 0 || value.length > 4096 || /[\0\r\n]/u.test(value)) {
    throw new Error(`${label} is missing or invalid.`);
  }
  return value;
}

function requiredPayloadJson(value, label) {
  if (typeof value !== "string" || value.length === 0 || value.length > 16 * 1024 * 1024
    || /[\0\r\n]/u.test(value)) {
    throw new Error(`${label} is missing, non-canonical, or exceeds the authenticated ledger limit.`);
  }
  return value;
}

function requiredTransactionId(value) {
  const text = requiredText(value, "finalization transactionId");
  if (text.length < 8 || text.length > 200 || !/^[A-Za-z0-9._:-]+$/u.test(text)) {
    throw new Error("Finalization transactionId is not canonical.");
  }
  return text;
}

function requiredState(value, allowDraft) {
  const states = allowDraft
    ? [...FORWARD_FINALIZATION_STATES, ...ERROR_FINALIZATION_STATES]
    : [...FORWARD_FINALIZATION_STATES.slice(1), ...ERROR_FINALIZATION_STATES];
  if (!states.includes(value)) throw new Error(`Finalization lifecycle state is invalid: ${String(value)}`);
  return value;
}

function normalizedNow(now) {
  const value = typeof now === "function" ? now() : new Date().toISOString();
  if (!isCanonicalTimestamp(value)) throw new Error("Finalization timestamp is not canonical UTC ISO-8601.");
  return value;
}

function isCanonicalTimestamp(value) {
  if (typeof value !== "string" || !Number.isFinite(Date.parse(value))) return false;
  return new Date(Date.parse(value)).toISOString() === value;
}

function canonicalClone(value) {
  const encoded = canonicalJson(value);
  if (encoded === undefined) throw new Error("Finalization payload is not canonically serializable.");
  return JSON.parse(encoded);
}

function canonicalJson(value) {
  if (value === null || typeof value !== "object") {
    const encoded = JSON.stringify(value);
    if (encoded === undefined) throw new Error("Value is not canonically serializable.");
    return encoded;
  }
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  const keys = Object.keys(value).sort(compareCodeUnits);
  return `{${keys.map((key) => `${JSON.stringify(key)}:${canonicalJson(value[key])}`).join(",")}}`;
}

function digestJson(value) {
  return digestText(canonicalJson(value));
}

function digestText(value) {
  return `sha256:${createHash("sha256").update(value).digest("hex")}`;
}

function digestBytes(value) {
  return `sha256:${createHash("sha256").update(value).digest("hex")}`;
}

function domainDigest(domain, value) {
  return digestText(`${domain}\0${canonicalJson(value)}`);
}

function compareSchemaObject(left, right) {
  return compareCodeUnits(`${left.type}\0${left.name}`, `${right.type}\0${right.name}`);
}

function compareCodeUnits(left, right) {
  return left < right ? -1 : left > right ? 1 : 0;
}

function escapeRegExp(value) {
  return String(value).replace(/[.*+?^${}()|[\]\\]/gu, "\\$&");
}

function firstColumn(row) {
  return row ? Object.values(row)[0] : undefined;
}
