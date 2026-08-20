import assert from "node:assert/strict";
import { mkdir, mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import Database from "better-sqlite3";
import { FINALIZATION_STORE_MIGRATION } from "../../scripts/lib/finalization-store-contract.mjs";
import {
  FILESYSTEM_SYNC_SCHEMA_V1,
  applyMigrationManifest,
  canonicalMigrationManifest,
  ensureFilesystemSyncSqliteSchemaV1,
  migrationManifestDigest,
  readFilesystemSyncSqliteSchemaV1,
  universalBrokerStoreMigrationManifest,
  type AppliedMigrationRecord,
  type MigrationExecutionAdapter,
  type MigrationManifestEntry,
} from "./migration-registry.js";

const checksumA = `sha256:${"a".repeat(64)}`;
const checksumB = `sha256:${"b".repeat(64)}`;
const checksumC = `sha256:${"c".repeat(64)}`;

test("Base runtime migration manifest includes every required SQLite store identity", () => {
  const manifest = universalBrokerStoreMigrationManifest();
  assert.deepEqual(
    manifest.filter((entry) => entry.storeId === "authority").map((entry) => entry.version),
    [7],
  );
  const filesystemSyncEntries = manifest.filter((migration) => migration.storeId === "filesystem-sync");
  assert.equal(filesystemSyncEntries.length, 1);
  assert.deepEqual(
    {
      storeId: filesystemSyncEntries[0]?.storeId,
      version: filesystemSyncEntries[0]?.version,
      name: filesystemSyncEntries[0]?.name,
      module: filesystemSyncEntries[0]?.module,
    },
    {
      storeId: "filesystem-sync",
      version: 1,
      name: "filesystem-sync-sqlite",
      module: "v2/filesystem-sync",
    },
  );
  assert.match(filesystemSyncEntries[0]?.checksum ?? "", /^sha256:[a-f0-9]{64}$/u);
  const connectorJournalEntries = manifest.filter(
    (migration) => migration.storeId === "connector-activation-journal",
  );
  assert.deepEqual(connectorJournalEntries.map(({ storeId, version, name, module }) => ({
    storeId,
    version,
    name,
    module,
  })), [{
    storeId: "connector-activation-journal",
    version: 1,
    name: "connector-activation-journal-sqlite",
    module: "v2/connector-activation-journal",
  }]);
  assert.match(connectorJournalEntries[0]?.checksum ?? "", /^sha256:[a-f0-9]{64}$/u);
  assert.deepEqual(
    manifest.find((migration) => migration.storeId === "lifecycle-finalization-store"),
    FINALIZATION_STORE_MIGRATION,
  );
});

test("filesystem-sync schema v1 readback is complete and fails on partial schema", async (t) => {
  const root = await mkdtemp(join(tmpdir(), "devspace-filesystem-sync-migration-"));
  t.after(() => rm(root, { recursive: true, force: true }));
  const storePath = join(root, "filesystem-sync", "sync.sqlite");
  const applied = ensureFilesystemSyncSqliteSchemaV1(storePath);
  assert.equal(applied.complete, true);
  assert.equal(applied.userVersion, 1);
  assert.deepEqual(applied.tables, [...FILESYSTEM_SYNC_SCHEMA_V1.tables].sort());
  assert.deepEqual(applied.indexes, [...FILESYSTEM_SYNC_SCHEMA_V1.indexes].sort());
  assert.deepEqual(applied.triggers, [...FILESYSTEM_SYNC_SCHEMA_V1.triggers].sort());
  assert.deepEqual(readFilesystemSyncSqliteSchemaV1(storePath), applied);

  const incompletePath = join(root, "incomplete", "sync.sqlite");
  await mkdir(join(root, "incomplete"), { recursive: true });
  const incomplete = new Database(incompletePath);
  try {
    incomplete.pragma("user_version = 1");
    incomplete.exec("create table filesystem_sync_plans (plan_id text primary key)");
  } finally {
    incomplete.close();
  }
  assert.throws(
    () => ensureFilesystemSyncSqliteSchemaV1(incompletePath),
    hasCode("STATE_CORRUPTED"),
  );
});

test("applies one globally sorted manifest and verifies every schema readback", () => {
  const manifest: MigrationManifestEntry[] = [
    entry("oauth", 2, "oauth-tokens", checksumB, "oauth"),
    entry("authority", 1, "authority-base", checksumC, "authority"),
    entry("oauth", 1, "oauth-clients", checksumA, "oauth"),
  ];
  const applied: AppliedMigrationRecord[] = [];
  const events: string[] = [];
  const adapter = memoryAdapter(applied, events);
  const reorderedProperties = manifest.map((migration) => ({
    module: migration.module,
    checksum: migration.checksum,
    name: migration.name,
    version: migration.version,
    storeId: migration.storeId,
  }));

  assert.equal(canonicalMigrationManifest(manifest), canonicalMigrationManifest([...manifest].reverse()));
  assert.equal(canonicalMigrationManifest(manifest), canonicalMigrationManifest(reorderedProperties));
  assert.equal(migrationManifestDigest(manifest), migrationManifestDigest([...manifest].reverse()));
  assert.match(migrationManifestDigest(manifest), /^sha256:[a-f0-9]{64}$/u);

  applyMigrationManifest(manifest, adapter);

  assert.deepEqual(events, [
    "apply:authority:1",
    "record:authority:1",
    "verify:authority:1",
    "apply:oauth:1",
    "record:oauth:1",
    "verify:oauth:1",
    "apply:oauth:2",
    "record:oauth:2",
    "verify:oauth:2",
  ]);
  events.length = 0;
  applyMigrationManifest([...manifest].reverse(), adapter);
  assert.deepEqual(events, [
    "verify:authority:1",
    "verify:oauth:1",
    "verify:oauth:2",
  ], "a complete registry is read back without replaying migrations");
});

test("rejects duplicate store/version identities before applying any migration", () => {
  const events: string[] = [];
  const adapter = memoryAdapter([], events);
  assert.throws(
    () => applyMigrationManifest([
      entry("main", 1, "workspace-state", checksumA, "workspace"),
      entry("main", 1, "oauth-state", checksumB, "oauth"),
    ], adapter),
    hasCode("MIGRATION_CONFLICT"),
  );
  assert.deepEqual(events, []);
});

test("rejects an applied checksum or name conflict before applying pending work", () => {
  const manifest = [
    entry("main", 1, "workspace-state", checksumA, "workspace"),
    entry("main", 2, "oauth-state", checksumB, "oauth"),
  ];
  const applied: AppliedMigrationRecord[] = [
    { ...manifest[0], checksum: checksumC, appliedAt: "2026-08-20T00:00:00.000Z" },
  ];
  const events: string[] = [];
  assert.throws(
    () => applyMigrationManifest(manifest, memoryAdapter(applied, events)),
    hasCode("MIGRATION_CONFLICT"),
  );
  assert.deepEqual(events, []);
});

test("rejects applied entries absent from the manifest", () => {
  const manifest = [entry("main", 1, "workspace-state", checksumA, "workspace")];
  const applied: AppliedMigrationRecord[] = [
    { ...entry("main", 9, "historical-branch", checksumC, "legacy"), appliedAt: "2026-08-20T00:00:00.000Z" },
  ];
  const events: string[] = [];
  assert.throws(
    () => applyMigrationManifest(manifest, memoryAdapter(applied, events)),
    hasCode("MIGRATION_CONFLICT"),
  );
  assert.deepEqual(events, []);
});

test("does not treat a module MAX(version) as migration completeness", () => {
  const manifest = [
    entry("main", 1, "oauth-base", checksumA, "oauth"),
    entry("main", 2, "oauth-tokens", checksumB, "oauth"),
  ];
  const applied: AppliedMigrationRecord[] = [
    { ...manifest[1], appliedAt: "2026-08-20T00:00:00.000Z" },
  ];
  const events: string[] = [];
  applyMigrationManifest(manifest, memoryAdapter(applied, events));
  assert.deepEqual(events, [
    "apply:main:1",
    "record:main:1",
    "verify:main:1",
    "verify:main:2",
  ]);
});

test("fails closed when table/index/schema completeness readback fails", () => {
  const manifest = [
    entry("main", 1, "workspace-state", checksumA, "workspace"),
    entry("main", 2, "oauth-state", checksumB, "oauth"),
  ];
  const applied: AppliedMigrationRecord[] = [];
  const events: string[] = [];
  const adapter = memoryAdapter(applied, events, (migration) => migration.version !== 1);
  assert.throws(
    () => applyMigrationManifest(manifest, adapter),
    hasCode("STATE_CORRUPTED"),
  );
  assert.deepEqual(events, [
    "apply:main:1",
    "record:main:1",
    "verify:main:1",
  ]);
});

function entry(
  storeId: string,
  version: number,
  name: string,
  checksum: string,
  module: string,
): MigrationManifestEntry {
  return { storeId, version, name, checksum, module };
}

function memoryAdapter(
  applied: AppliedMigrationRecord[],
  events: string[],
  verify: (entry: MigrationManifestEntry) => boolean = () => true,
): MigrationExecutionAdapter {
  return {
    readApplied: () => applied.map((record) => ({ ...record })),
    apply: (migration) => {
      events.push(`apply:${migration.storeId}:${migration.version}`);
    },
    recordApplied: (migration) => {
      events.push(`record:${migration.storeId}:${migration.version}`);
      applied.push({ ...migration, appliedAt: "2026-08-20T00:00:00.000Z" });
    },
    verifyApplied: (migration) => {
      events.push(`verify:${migration.storeId}:${migration.version}`);
      return verify(migration);
    },
  };
}

function hasCode(code: string): (error: unknown) => boolean {
  return (error) => error instanceof Error && "code" in error && error.code === code;
}
