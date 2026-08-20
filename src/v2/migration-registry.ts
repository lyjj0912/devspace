import { createHash } from "node:crypto";
import { chmodSync, mkdirSync } from "node:fs";
import { dirname } from "node:path";
import Database from "better-sqlite3";
import {
  FINALIZATION_STORE_ID,
  FINALIZATION_STORE_MIGRATION,
  FINALIZATION_STORE_SCHEMA_VERSION,
} from "../../scripts/lib/finalization-store-contract.mjs";
import {
  CONNECTOR_ACTIVATION_JOURNAL_MIGRATION_MANIFEST_DIGEST,
  CONNECTOR_ACTIVATION_JOURNAL_SCHEMA_VERSION,
} from "./connector-activation-journal.js";

export interface MigrationManifestEntry {
  storeId: string;
  version: number;
  name: string;
  checksum: string;
  module: string;
}

export interface AppliedMigrationRecord extends MigrationManifestEntry {
  appliedAt: string;
}

export interface MigrationExecutionAdapter {
  readApplied(): readonly AppliedMigrationRecord[];
  apply(entry: MigrationManifestEntry): void;
  recordApplied(entry: MigrationManifestEntry): void;
  verifyApplied(entry: MigrationManifestEntry): boolean;
}

export interface FilesystemSyncSchemaV1Representation {
  userVersion: 1;
  tables: readonly string[];
  indexes: readonly string[];
  triggers: readonly string[];
}

export interface FilesystemSyncSchemaReadback {
  userVersion: number;
  tables: readonly string[];
  indexes: readonly string[];
  triggers: readonly string[];
  complete: boolean;
  missing: readonly string[];
  integrity: string;
  foreignKeyViolations: number;
}

export interface BaseMutableSqliteStoreRequirement {
  storeId: string;
  expectedUserVersion: number;
  required: true;
  reason: string;
}

export interface BaseMutableStoreCapabilityInput {
  productProfile?: string;
  supportedOperations?: {
    fs?: readonly string[];
  };
}

export const FILESYSTEM_SYNC_STORE_ID = "filesystem-sync";
export const FILESYSTEM_SYNC_SCHEMA_VERSION = 1;
export const CONNECTOR_ACTIVATION_JOURNAL_STORE_ID = "connector-activation-journal";
export const FILESYSTEM_SYNC_SCHEMA_V1: FilesystemSyncSchemaV1Representation = Object.freeze({
  userVersion: FILESYSTEM_SYNC_SCHEMA_VERSION,
  tables: Object.freeze(["filesystem_sync_plans", "filesystem_sync_checkpoints"]),
  indexes: Object.freeze(["filesystem_sync_plans_owner_idx"]),
  triggers: Object.freeze([
    "filesystem_sync_plans_immutable",
    "filesystem_sync_checkpoint_operation_immutable",
  ]),
});

const RUNTIME_STORE_MIGRATIONS: readonly MigrationManifestEntry[] = Object.freeze([
  runtimeStoreMigration("authority", 7, "operation-authority-store", "v2/authority-store"),
  runtimeStoreMigration("contexts", 2, "context-store-file", "v2/contexts"),
  runtimeStoreMigration(
    FILESYSTEM_SYNC_STORE_ID,
    FILESYSTEM_SYNC_SCHEMA_VERSION,
    "filesystem-sync-sqlite",
    "v2/filesystem-sync",
  ),
  runtimeStoreMigration("process-metadata", 1, "process-state-files", "v2/process-state"),
  runtimeStoreMigration("process-output", 1, "process-output-spool", "v2/process-output-spool"),
  runtimeStoreMigration("artifact-catalog", 1, "artifact-catalog-sqlite", "v2/artifact-catalog"),
  runtimeStoreMigration("artifact-cas", 1, "artifact-content-addressed-objects", "v2/artifact-catalog"),
  runtimeStoreMigration("artifact-quarantine", 1, "artifact-quarantine", "v2/artifact-catalog"),
  runtimeStoreMigration("pagination", 1, "cursor-signing-key-files", "v2/cursor-capability"),
  Object.freeze({
    storeId: CONNECTOR_ACTIVATION_JOURNAL_STORE_ID,
    version: CONNECTOR_ACTIVATION_JOURNAL_SCHEMA_VERSION,
    name: "connector-activation-journal-sqlite",
    checksum: CONNECTOR_ACTIVATION_JOURNAL_MIGRATION_MANIFEST_DIGEST,
    module: "v2/connector-activation-journal",
  }),
  Object.freeze({ ...FINALIZATION_STORE_MIGRATION }),
]);

export class MigrationConflictError extends Error {
  readonly code = "MIGRATION_CONFLICT";

  constructor(message: string) {
    super(message);
    this.name = "MigrationConflictError";
  }
}

export class MigrationIncompleteError extends Error {
  readonly code = "STATE_CORRUPTED";

  constructor(message: string) {
    super(message);
    this.name = "MigrationIncompleteError";
  }
}

/**
 * Applies a single, globally ordered migration manifest through a store adapter.
 * The caller owns the encompassing transaction; this kernel guarantees that the
 * complete manifest and the existing registry are validated before `apply` is
 * invoked, then requires schema readback for every manifest entry.
 */
export function applyMigrationManifest(
  manifest: readonly MigrationManifestEntry[],
  adapter: MigrationExecutionAdapter,
): readonly MigrationManifestEntry[] {
  const ordered = validateMigrationManifest(manifest);
  const initiallyApplied = validateAppliedRegistry(adapter.readApplied());
  assertRegistryMatchesManifest(ordered, initiallyApplied);
  const appliedByKey = new Map(initiallyApplied.map((entry) => [migrationKey(entry), entry]));

  for (const migration of ordered) {
    if (!appliedByKey.has(migrationKey(migration))) {
      adapter.apply(migration);
      adapter.recordApplied(migration);
    }
    if (!adapter.verifyApplied(migration)) {
      throw new MigrationIncompleteError(
        `Migration ${migration.storeId}/${migration.version} (${migration.name}) is recorded but its schema readback is incomplete.`,
      );
    }
  }

  const finalApplied = validateAppliedRegistry(adapter.readApplied());
  assertRegistryMatchesManifest(ordered, finalApplied);
  const finalByKey = new Map(finalApplied.map((entry) => [migrationKey(entry), entry]));
  for (const migration of ordered) {
    if (!finalByKey.has(migrationKey(migration))) {
      throw new MigrationIncompleteError(
        `Migration ${migration.storeId}/${migration.version} (${migration.name}) was not durably recorded.`,
      );
    }
  }
  return ordered;
}

/** Verify a complete applied registry and every schema readback without applying migrations. */
export function verifyAppliedMigrationManifest(
  manifest: readonly MigrationManifestEntry[],
  applied: readonly AppliedMigrationRecord[],
  verifyApplied: (entry: MigrationManifestEntry) => boolean,
): readonly MigrationManifestEntry[] {
  const ordered = validateMigrationManifest(manifest);
  const validatedApplied = validateAppliedRegistry(applied);
  assertRegistryMatchesManifest(ordered, validatedApplied);
  const appliedByKey = new Map(validatedApplied.map((entry) => [migrationKey(entry), entry]));
  for (const migration of ordered) {
    if (!appliedByKey.has(migrationKey(migration))) {
      throw new MigrationIncompleteError(
        `Migration ${migration.storeId}/${migration.version} (${migration.name}) was not durably recorded.`,
      );
    }
    if (!verifyApplied(migration)) {
      throw new MigrationIncompleteError(
        `Migration ${migration.storeId}/${migration.version} (${migration.name}) is recorded but its schema readback is incomplete.`,
      );
    }
  }
  return ordered;
}

export function validateMigrationManifest(
  manifest: readonly MigrationManifestEntry[],
): readonly MigrationManifestEntry[] {
  const entries = manifest.map((entry) => ({
    storeId: entry.storeId,
    version: entry.version,
    name: entry.name,
    checksum: entry.checksum,
    module: entry.module,
  }));
  validateEntries(entries, "manifest");
  return entries.sort(compareMigrations);
}

export function canonicalMigrationManifest(manifest: readonly MigrationManifestEntry[]): string {
  return JSON.stringify(validateMigrationManifest(manifest));
}

export function migrationManifestDigest(manifest: readonly MigrationManifestEntry[]): string {
  return `sha256:${createHash("sha256").update(canonicalMigrationManifest(manifest)).digest("hex")}`;
}

export function universalBrokerStoreMigrationManifest(
  mainDatabaseManifest: readonly MigrationManifestEntry[] = [],
): readonly MigrationManifestEntry[] {
  return validateMigrationManifest([...mainDatabaseManifest, ...RUNTIME_STORE_MIGRATIONS]);
}

export function universalBrokerStoreMigrationManifestDigest(
  mainDatabaseManifest: readonly MigrationManifestEntry[] = [],
): string {
  return migrationManifestDigest(universalBrokerStoreMigrationManifest(mainDatabaseManifest));
}

export function baseMutableSqliteStoreRequirements(
  capabilities: BaseMutableStoreCapabilityInput,
): readonly BaseMutableSqliteStoreRequirement[] {
  const requirements: BaseMutableSqliteStoreRequirement[] = [
    {
      storeId: "authority",
      expectedUserVersion: 7,
      required: true,
      reason: "Durable operation authority claims, receipts, leases, and fencing.",
    },
    {
      storeId: "artifact-catalog",
      expectedUserVersion: 1,
      required: true,
      reason: "Durable artifact catalog, reservations, and CAS reference metadata.",
    },
    {
      storeId: CONNECTOR_ACTIVATION_JOURNAL_STORE_ID,
      expectedUserVersion: CONNECTOR_ACTIVATION_JOURNAL_SCHEMA_VERSION,
      required: true,
      reason: "Append-only connector activation intent, dispatch, postcheck, and rollback tombstones.",
    },
    {
      storeId: FINALIZATION_STORE_ID,
      expectedUserVersion: FINALIZATION_STORE_SCHEMA_VERSION,
      required: true,
      reason: "Durable finalization lifecycle, prepared transaction, transition, and evidence ledger.",
    },
  ];
  if (
    capabilities.productProfile === "BASE_SINGLE_OWNER"
    && capabilities.supportedOperations?.fs?.includes("sync")
  ) {
    requirements.push({
      storeId: FILESYSTEM_SYNC_STORE_ID,
      expectedUserVersion: FILESYSTEM_SYNC_SCHEMA_VERSION,
      required: true,
      reason: "Durable filesystem sync plans, immutable operation manifests, and checkpoints.",
    });
  }
  return Object.freeze(requirements);
}

export function ensureFilesystemSyncSqliteSchemaV1(path: string): FilesystemSyncSchemaReadback {
  mkdirSync(dirname(path), { recursive: true, mode: 0o700 });
  const database = new Database(path);
  try {
    chmodSync(path, 0o600);
    database.pragma("journal_mode = WAL");
    database.pragma("synchronous = FULL");
    database.pragma("busy_timeout = 5000");
    database.pragma("foreign_keys = ON");
    const version = Number(database.pragma("user_version", { simple: true }));
    if (version !== 0 && version !== FILESYSTEM_SYNC_SCHEMA_VERSION) {
      throw new MigrationIncompleteError(
        `Filesystem sync schema version ${version} is unsupported.`,
      );
    }
    if (version === 0) {
      database.exec(FILESYSTEM_SYNC_SCHEMA_V1_SQL);
      database.pragma(`user_version = ${FILESYSTEM_SYNC_SCHEMA_VERSION}`);
    }
    const readback = readFilesystemSyncSqliteSchemaV1FromDatabase(database);
    if (!readback.complete) {
      throw new MigrationIncompleteError(
        `Filesystem sync schema v1 readback is incomplete: ${readback.missing.join(", ")}.`,
      );
    }
    return readback;
  } finally {
    database.close();
  }
}

export function readFilesystemSyncSqliteSchemaV1(path: string): FilesystemSyncSchemaReadback {
  const database = new Database(path, { readonly: true, fileMustExist: true });
  try {
    database.pragma("query_only = ON");
    database.pragma("foreign_keys = ON");
    return readFilesystemSyncSqliteSchemaV1FromDatabase(database);
  } finally {
    database.close();
  }
}

function runtimeStoreMigration(
  storeId: string,
  version: number,
  name: string,
  module: string,
): MigrationManifestEntry {
  return {
    storeId,
    version,
    name,
    module,
    checksum: `sha256:${createHash("sha256")
      .update(`devspace/runtime-store/${storeId}/${version}/${name}/${module}`)
      .digest("hex")}`,
  };
}

const FILESYSTEM_SYNC_SCHEMA_V1_SQL = `
  create table if not exists filesystem_sync_plans (
    plan_id text primary key,
    owner_fingerprint text not null check (length(owner_fingerprint) = 64),
    target_id text not null,
    target_generation text not null,
    source_root text not null,
    destination_root text not null,
    source_snapshot_digest text not null check (length(source_snapshot_digest) = 64),
    destination_snapshot_digest text not null check (length(destination_snapshot_digest) = 64),
    expected_destination_snapshot_digest text not null
      check (length(expected_destination_snapshot_digest) = 64),
    plan_digest text not null check (length(plan_digest) = 64),
    plan_json text not null,
    selectors_json text not null,
    state text not null check (state in ('PLANNED', 'APPLYING', 'COMPLETE')),
    created_at_ms integer not null,
    expires_at_ms integer not null,
    completed_at_ms integer,
    result_json text
  );
  create index if not exists filesystem_sync_plans_owner_idx
    on filesystem_sync_plans(owner_fingerprint, created_at_ms desc);
  create table if not exists filesystem_sync_checkpoints (
    plan_id text not null,
    operation_id text not null,
    sequence integer not null,
    operation_json text not null,
    state text not null check (state in ('PENDING', 'APPLYING', 'APPLIED')),
    attempts integer not null check (attempts >= 0),
    applied_at_ms integer,
    postreadback_digest text,
    result_json text,
    primary key (plan_id, operation_id),
    unique (plan_id, sequence),
    foreign key (plan_id) references filesystem_sync_plans(plan_id) on delete cascade
  );
  create trigger if not exists filesystem_sync_plans_immutable
  before update of owner_fingerprint, target_id, target_generation,
                   source_root, destination_root, source_snapshot_digest,
                   destination_snapshot_digest, expected_destination_snapshot_digest,
                   plan_digest, plan_json, selectors_json, created_at_ms, expires_at_ms
    on filesystem_sync_plans
  begin
    select raise(abort, 'filesystem sync plan is immutable');
  end;
  create trigger if not exists filesystem_sync_checkpoint_operation_immutable
  before update of plan_id, operation_id, sequence, operation_json
    on filesystem_sync_checkpoints
  begin
    select raise(abort, 'filesystem sync checkpoint operation is immutable');
  end;
`;

function readFilesystemSyncSqliteSchemaV1FromDatabase(
  database: Database.Database,
): FilesystemSyncSchemaReadback {
  const userVersion = Number(database.pragma("user_version", { simple: true }));
  const integrity = String(database.pragma("quick_check", { simple: true }));
  const foreignKeyViolations = (database.pragma("foreign_key_check") as unknown[]).length;
  const rows = database.prepare(`
    select type, name from sqlite_schema
    where type in ('table', 'index', 'trigger')
      and name not like 'sqlite_%'
  `).all() as Array<{ type: string; name: string }>;
  const byType = (type: string) => rows
    .filter((row) => row.type === type)
    .map((row) => row.name)
    .sort(compareAscii);
  const tables = byType("table");
  const indexes = byType("index");
  const triggers = byType("trigger");
  const missing = [
    ...(userVersion === FILESYSTEM_SYNC_SCHEMA_VERSION ? [] : [`user_version:${FILESYSTEM_SYNC_SCHEMA_VERSION}`]),
    ...missingNames("table", FILESYSTEM_SYNC_SCHEMA_V1.tables, tables),
    ...missingNames("index", FILESYSTEM_SYNC_SCHEMA_V1.indexes, indexes),
    ...missingNames("trigger", FILESYSTEM_SYNC_SCHEMA_V1.triggers, triggers),
    ...(integrity === "ok" ? [] : ["integrity_check"]),
    ...(foreignKeyViolations === 0 ? [] : ["foreign_key_check"]),
  ];
  return {
    userVersion,
    tables,
    indexes,
    triggers,
    complete: missing.length === 0,
    missing,
    integrity,
    foreignKeyViolations,
  };
}

function missingNames(kind: string, required: readonly string[], observed: readonly string[]): string[] {
  return required
    .filter((name) => !observed.includes(name))
    .map((name) => `${kind}:${name}`);
}

function validateAppliedRegistry(
  applied: readonly AppliedMigrationRecord[],
): readonly AppliedMigrationRecord[] {
  const entries = applied.map((entry) => ({ ...entry }));
  validateEntries(entries, "registry");
  for (const entry of entries) {
    const parsed = entry.appliedAt ? new Date(entry.appliedAt) : undefined;
    if (!parsed || !Number.isFinite(parsed.getTime()) || parsed.toISOString() !== entry.appliedAt) {
      throw new MigrationConflictError(
        `Migration registry entry ${migrationKey(entry)} has an invalid appliedAt timestamp.`,
      );
    }
  }
  return entries.sort(compareMigrations);
}

function validateEntries(
  entries: readonly MigrationManifestEntry[],
  source: "manifest" | "registry",
): void {
  const byKey = new Map<string, MigrationManifestEntry>();
  const byName = new Map<string, MigrationManifestEntry>();
  for (const entry of entries) {
    validateEntry(entry, source);
    const key = migrationKey(entry);
    if (byKey.has(key)) {
      throw new MigrationConflictError(
        `Migration ${source} contains duplicate global key ${key}.`,
      );
    }
    byKey.set(key, entry);

    const nameKey = `${entry.storeId}\u0000${entry.name}`;
    const named = byName.get(nameKey);
    if (named && named.version !== entry.version) {
      throw new MigrationConflictError(
        `Migration ${source} assigns ${entry.storeId}/${entry.name} to both versions ${named.version} and ${entry.version}.`,
      );
    }
    byName.set(nameKey, entry);
  }
}

function validateEntry(entry: MigrationManifestEntry, source: string): void {
  if (!/^[A-Za-z][A-Za-z0-9._-]{0,127}$/u.test(entry.storeId)) {
    throw new MigrationConflictError(`Migration ${source} contains an invalid storeId.`);
  }
  if (!Number.isInteger(entry.version) || entry.version < 1) {
    throw new MigrationConflictError(`Migration ${source} contains an invalid version for store ${entry.storeId}.`);
  }
  if (!/^[A-Za-z][A-Za-z0-9._-]{0,255}$/u.test(entry.name)) {
    throw new MigrationConflictError(`Migration ${source} contains an invalid name for ${entry.storeId}/${entry.version}.`);
  }
  if (!/^sha256:[a-f0-9]{64}$/u.test(entry.checksum)) {
    throw new MigrationConflictError(`Migration ${source} contains an invalid checksum for ${entry.storeId}/${entry.version}.`);
  }
  if (!/^[A-Za-z][A-Za-z0-9._/-]{0,255}$/u.test(entry.module)) {
    throw new MigrationConflictError(`Migration ${source} contains an invalid module for ${entry.storeId}/${entry.version}.`);
  }
}

function assertRegistryMatchesManifest(
  manifest: readonly MigrationManifestEntry[],
  applied: readonly AppliedMigrationRecord[],
): void {
  const manifestByKey = new Map(manifest.map((entry) => [migrationKey(entry), entry]));
  const manifestByName = new Map(manifest.map((entry) => [`${entry.storeId}\u0000${entry.name}`, entry]));

  for (const record of applied) {
    const expected = manifestByKey.get(migrationKey(record));
    if (expected && !sameIdentity(expected, record)) {
      throw new MigrationConflictError(
        `Applied migration ${migrationKey(record)} conflicts with the current manifest.`,
      );
    }
    const expectedByName = manifestByName.get(`${record.storeId}\u0000${record.name}`);
    if (expectedByName && expectedByName.version !== record.version) {
      throw new MigrationConflictError(
        `Applied migration ${record.storeId}/${record.name} uses version ${record.version}; expected ${expectedByName.version}.`,
      );
    }
    if (!expected && !expectedByName) {
      throw new MigrationConflictError(
        `Applied migration ${migrationKey(record)} (${record.name}) is absent from the current manifest.`,
      );
    }
  }
}

function sameIdentity(left: MigrationManifestEntry, right: MigrationManifestEntry): boolean {
  return left.storeId === right.storeId
    && left.version === right.version
    && left.name === right.name
    && left.checksum === right.checksum
    && left.module === right.module;
}

function migrationKey(entry: Pick<MigrationManifestEntry, "storeId" | "version">): string {
  return `${entry.storeId}/${entry.version}`;
}

function compareMigrations(left: MigrationManifestEntry, right: MigrationManifestEntry): number {
  return compareAscii(left.storeId, right.storeId)
    || left.version - right.version
    || compareAscii(left.name, right.name)
    || compareAscii(left.module, right.module);
}

function compareAscii(left: string, right: string): number {
  return left < right ? -1 : left > right ? 1 : 0;
}
