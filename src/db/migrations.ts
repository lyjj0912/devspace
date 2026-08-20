import { createHash } from "node:crypto";
import { chmodSync, closeSync, existsSync, fsyncSync, openSync, readFileSync, renameSync, writeFileSync } from "node:fs";
import { basename, dirname } from "node:path";
import Database from "better-sqlite3";
import {
  applyMigrationManifest,
  migrationManifestDigest,
  MigrationConflictError,
  MigrationIncompleteError,
  verifyAppliedMigrationManifest,
  type AppliedMigrationRecord,
  type MigrationManifestEntry,
} from "../v2/migration-registry.js";

interface Migration extends MigrationManifestEntry {
  up(sqlite: Database.Database): void;
  verify(sqlite: Database.Database): boolean;
}

const MAIN_STORE_ID = "main";
const OAUTH_CONNECTOR_MIGRATION_VERSION = 6;
const OAUTH_CONNECTOR_MIGRATION_NAME = "oauth-token-families-and-connector-bindings";
const OAUTH_CONNECTOR_LIFECYCLE_MIGRATION_VERSION = 7;
const OAUTH_CONNECTOR_LIFECYCLE_MIGRATION_NAME = "oauth-connector-lifecycle-rev3";
const OAUTH_CONNECTOR_ACTIVATION_AUTHORITY_MIGRATION_VERSION = 8;
const OAUTH_CONNECTOR_ACTIVATION_AUTHORITY_MIGRATION_NAME = "oauth-connector-activation-authority-rev3";

const migrations: Migration[] = [
  defineMigration(1, "workspace-state", "workspace", "workspace-state/v1", migrateWorkspaceState, hasCompleteWorkspaceStateSchema),
  defineMigration(2, "oauth-state", "oauth", "oauth-state/v2", migrateOAuthState, hasCompleteOAuthStateSchema),
  defineMigration(3, "local-agent-sessions", "local-agent", "local-agent-sessions/v3", migrateLocalAgentSessions, hasCompleteLocalAgentSchema),
  defineMigration(4, "workspace-conversation-bindings", "workspace", "workspace-conversation-bindings/v4", migrateWorkspaceConversationBindings, hasCompleteConversationBindingSchema),
  defineMigration(
    5,
    "external-communications",
    "legacy-external-communications",
    "external-communications-compatibility/v5",
    migrateExternalCommunicationsCompatibility,
    hasCompleteExternalCommunicationsCompatibilitySchema,
  ),
  defineMigration(
    OAUTH_CONNECTOR_MIGRATION_VERSION,
    OAUTH_CONNECTOR_MIGRATION_NAME,
    "oauth",
    "oauth-token-families-and-connector-bindings/v6",
    migrateOAuthTokenFamiliesAndConnectorBindings,
    hasCompleteOAuthConnectorSchema,
  ),
  defineMigration(
    OAUTH_CONNECTOR_LIFECYCLE_MIGRATION_VERSION,
    OAUTH_CONNECTOR_LIFECYCLE_MIGRATION_NAME,
    "oauth",
    "oauth-connector-lifecycle-rev3/v7",
    migrateOAuthConnectorLifecycleRev3,
    hasCompleteOAuthConnectorLifecycleSchema,
  ),
  defineMigration(
    OAUTH_CONNECTOR_ACTIVATION_AUTHORITY_MIGRATION_VERSION,
    OAUTH_CONNECTOR_ACTIVATION_AUTHORITY_MIGRATION_NAME,
    "oauth",
    "oauth-connector-activation-authority-rev3/v8",
    migrateOAuthConnectorActivationAuthorityRev3,
    hasCompleteOAuthConnectorActivationAuthoritySchema,
  ),
];

export function migrateDatabase(sqlite: Database.Database): void {
  preservePendingOAuthMigrationPreimage(sqlite);
  const migrate = sqlite.transaction(() => {
    ensureGlobalMigrationRegistry(sqlite);
    const migrationsByKey = new Map(migrations.map((entry) => [`${entry.storeId}/${entry.version}`, entry]));
    applyMigrationManifest(migrations, {
      readApplied: () => readAppliedMigrations(sqlite),
      apply: (entry) => {
        const migration = migrationsByKey.get(`${entry.storeId}/${entry.version}`);
        if (!migration) throw new MigrationConflictError(`No executable migration exists for ${entry.storeId}/${entry.version}.`);
        migration.up(sqlite);
      },
      recordApplied: (entry) => {
        sqlite.prepare(`
          insert into devspace_schema_migrations
            (store_id, version, name, checksum, module, applied_at)
          values (?, ?, ?, ?, ?, ?)
        `).run(entry.storeId, entry.version, entry.name, entry.checksum, entry.module, new Date().toISOString());
      },
      verifyApplied: (entry) => {
        const migration = migrationsByKey.get(`${entry.storeId}/${entry.version}`);
        return Boolean(migration?.verify(sqlite));
      },
    });
    if (!hasCompleteGlobalMigrationRegistry(sqlite)) {
      throw new MigrationIncompleteError("The global migration registry schema is incomplete.");
    }
  });

  migrate.immediate();
}

export function mainDatabaseMigrationManifest(): readonly MigrationManifestEntry[] {
  return migrations.map(({ up: _up, verify: _verify, ...entry }) => ({ ...entry }));
}

export function mainDatabaseMigrationManifestDigest(): string {
  return migrationManifestDigest(mainDatabaseMigrationManifest());
}

export interface MainDatabaseMigrationReadback {
  storeId: "main";
  path: string;
  manifestDigest: string;
  appliedEntries: number;
  integrity: "ok";
  foreignKeyViolations: 0;
  complete: true;
}

/** Exact read-only main/OAuth migration and schema verification for private readiness. */
export function readMainDatabaseMigrationReadback(path: string): MainDatabaseMigrationReadback {
  const sqlite = new Database(path, { readonly: true, fileMustExist: true });
  try {
    sqlite.pragma("query_only = ON");
    sqlite.pragma("foreign_keys = ON");
    if (!hasCompleteGlobalMigrationRegistry(sqlite)) {
      throw new MigrationIncompleteError("The main database migration registry is incomplete.");
    }
    const applied = readAppliedMigrations(sqlite);
    const ordered = verifyAppliedMigrationManifest(
      migrations,
      applied,
      (entry) => migrations.find((migration) => (
        migration.storeId === entry.storeId && migration.version === entry.version
      ))?.verify(sqlite) === true,
    );
    const integrity = String(sqlite.pragma("quick_check", { simple: true }));
    const foreignKeyViolations = (sqlite.pragma("foreign_key_check") as unknown[]).length;
    if (integrity !== "ok" || foreignKeyViolations !== 0) {
      throw new MigrationIncompleteError(
        `The main database failed read-only integrity verification (${integrity}, fk=${foreignKeyViolations}).`,
      );
    }
    return {
      storeId: "main",
      path,
      manifestDigest: migrationManifestDigest(ordered),
      appliedEntries: applied.length,
      integrity: "ok",
      foreignKeyViolations: 0,
      complete: true,
    };
  } finally {
    sqlite.close();
  }
}

function defineMigration(
  version: number,
  name: string,
  module: string,
  checksumIdentity: string,
  up: Migration["up"],
  verify: Migration["verify"],
): Migration {
  return {
    storeId: MAIN_STORE_ID,
    version,
    name,
    checksum: `sha256:${createHash("sha256").update(`devspace/${MAIN_STORE_ID}/${checksumIdentity}`).digest("hex")}`,
    module,
    up,
    verify,
  };
}

function ensureGlobalMigrationRegistry(sqlite: Database.Database): void {
  const table = sqlite.prepare(
    "select 1 as present from sqlite_master where type = 'table' and name = 'devspace_schema_migrations'",
  ).get() as { present: number } | undefined;
  if (!table) {
    createGlobalMigrationRegistry(sqlite);
    return;
  }

  const columns = new Set(
    (sqlite.prepare("pragma table_info(devspace_schema_migrations)").all() as Array<{ name: string }>).map((row) => row.name),
  );
  const globalColumns = ["store_id", "version", "name", "checksum", "module", "applied_at"];
  if (globalColumns.every((column) => columns.has(column))) return;
  if (!["version", "name", "applied_at"].every((column) => columns.has(column))) {
    throw new MigrationConflictError("Legacy migration registry has an unrecognized schema.");
  }

  const legacyRows = sqlite.prepare(
    "select version, name, applied_at from devspace_schema_migrations order by version",
  ).all() as Array<{ version: number; name: string; applied_at: string }>;
  sqlite.exec("alter table devspace_schema_migrations rename to devspace_schema_migrations_legacy_rev3");
  createGlobalMigrationRegistry(sqlite);
  const insert = sqlite.prepare(`
    insert into devspace_schema_migrations
      (store_id, version, name, checksum, module, applied_at)
    values (?, ?, ?, ?, ?, ?)
  `);
  for (const row of legacyRows) {
    const known = migrations.find((migration) => migration.version === row.version && migration.name === row.name);
    const checksum = known?.checksum
      ?? `sha256:${createHash("sha256").update(`legacy/${MAIN_STORE_ID}/${row.version}/${row.name}`).digest("hex")}`;
    insert.run(MAIN_STORE_ID, row.version, row.name, checksum, known?.module ?? "legacy", row.applied_at);
  }
  sqlite.exec("drop table devspace_schema_migrations_legacy_rev3");
}

function createGlobalMigrationRegistry(sqlite: Database.Database): void {
  sqlite.exec(`
    create table devspace_schema_migrations (
      store_id text not null,
      version integer not null,
      name text not null,
      checksum text not null,
      module text not null,
      applied_at text not null,
      primary key (store_id, version),
      unique (store_id, name)
    );
    create index devspace_schema_migrations_module_idx
      on devspace_schema_migrations(module, store_id, version);
  `);
}

function readAppliedMigrations(sqlite: Database.Database): AppliedMigrationRecord[] {
  return sqlite.prepare(`
    select store_id as storeId, version, name, checksum, module, applied_at as appliedAt
      from devspace_schema_migrations
     order by store_id, version
  `).all() as AppliedMigrationRecord[];
}

function hasCompleteGlobalMigrationRegistry(sqlite: Database.Database): boolean {
  const registry = sqlite.prepare(
    "select sql from sqlite_master where type = 'table' and name = 'devspace_schema_migrations'",
  ).get() as { sql: string | null } | undefined;
  const definition = registry?.sql ?? "";
  return hasSchemaObjects(sqlite, ["devspace_schema_migrations"], ["devspace_schema_migrations_module_idx"])
    && hasColumns(sqlite, "devspace_schema_migrations", [
      "store_id",
      "version",
      "name",
      "checksum",
      "module",
      "applied_at",
    ])
    && /primary\s+key\s*\(\s*store_id\s*,\s*version\s*\)/iu.test(definition)
    && /unique\s*\(\s*store_id\s*,\s*name\s*\)/iu.test(definition);
}

function preservePendingOAuthMigrationPreimage(sqlite: Database.Database): void {
  const migrationTable = sqlite.prepare(
    "select 1 as present from sqlite_master where type = 'table' and name = 'devspace_schema_migrations'",
  ).get() as { present: number } | undefined;
  if (!migrationTable) return;
  const appliedRows = sqlite.prepare(
    "select version, name from devspace_schema_migrations",
  ).all() as Array<{ version: number; name: string }>;
  const versions = new Set(appliedRows.map((row) => row.version));
  const names = new Set(appliedRows.map((row) => row.name));
  if (!versions.has(2) || sqlite.name === ":memory:") return;
  const v6Complete = (versions.has(OAUTH_CONNECTOR_MIGRATION_VERSION) || names.has(OAUTH_CONNECTOR_MIGRATION_NAME))
    && hasCompleteOAuthConnectorSchema(sqlite);
  const v7Complete = (versions.has(OAUTH_CONNECTOR_LIFECYCLE_MIGRATION_VERSION)
      || names.has(OAUTH_CONNECTOR_LIFECYCLE_MIGRATION_NAME))
    && hasCompleteOAuthConnectorLifecycleSchema(sqlite);
  const v8Complete = (versions.has(OAUTH_CONNECTOR_ACTIVATION_AUTHORITY_MIGRATION_VERSION)
      || names.has(OAUTH_CONNECTOR_ACTIVATION_AUTHORITY_MIGRATION_NAME))
    && hasCompleteOAuthConnectorActivationAuthoritySchema(sqlite);
  const pendingVersion = !v6Complete
    ? OAUTH_CONNECTOR_MIGRATION_VERSION
    : !v7Complete
      ? OAUTH_CONNECTOR_LIFECYCLE_MIGRATION_VERSION
      : !v8Complete
        ? OAUTH_CONNECTOR_ACTIVATION_AUTHORITY_MIGRATION_VERSION
        : undefined;
  if (!pendingVersion) return;
  const image = sqlite.serialize();
  const digest = createHash("sha256").update(image).digest("hex");
  const backupPath = `${sqlite.name}.migration-v${pendingVersion}.${digest}.sqlite`;
  const checksumPath = `${backupPath}.sha256`;
  if (!existsSync(backupPath)) writeAtomic(backupPath, image);
  if (createHash("sha256").update(readFileSync(backupPath)).digest("hex") !== digest) {
    throw new Error(`OAuth migration backup checksum mismatch: ${backupPath}`);
  }
  const checksum = `${digest}  ${basename(backupPath)}\n`;
  if (!existsSync(checksumPath)) writeAtomic(checksumPath, Buffer.from(checksum, "utf8"));
  else if (readFileSync(checksumPath, "utf8") !== checksum) {
    throw new Error(`OAuth migration backup checksum receipt mismatch: ${checksumPath}`);
  }
}

function hasCompleteOAuthConnectorSchema(sqlite: Database.Database): boolean {
  const requiredTables = ["oauth_connector_bindings", "oauth_token_families"];
  const requiredIndexes = [
    "oauth_connector_bindings_one_active_name_idx",
    "oauth_connector_bindings_client_idx",
    "oauth_token_families_client_idx",
    "oauth_token_families_binding_idx",
    "oauth_access_tokens_family_idx",
    "oauth_refresh_tokens_family_idx",
  ];
  const objects = new Set(
    (sqlite.prepare(
      "select name from sqlite_master where type in ('table', 'index')",
    ).pluck().all() as string[]),
  );
  if ([...requiredTables, ...requiredIndexes].some((name) => !objects.has(name))) return false;
  const requiredColumns = [
    "family_id",
    "connector_binding_id",
    "connector_drain_epoch",
    "installation_epoch",
    "rotation_sequence",
  ];
  return ["oauth_access_tokens", "oauth_refresh_tokens"].every((table) => {
    const columns = new Set(
      (sqlite.prepare(`pragma table_info(${table})`).all() as Array<{ name: string }>).map((row) => row.name),
    );
    return requiredColumns.every((column) => columns.has(column));
  });
}

function hasCompleteOAuthConnectorLifecycleSchema(sqlite: Database.Database): boolean {
  const stateTable = sqlite.prepare(
    "select sql from sqlite_master where type = 'table' and name = 'oauth_connector_bindings'",
  ).get() as { sql: string | null } | undefined;
  const requiredStates = [
    "REGISTERED",
    "CANDIDATE",
    "VERIFIED",
    "ACTIVATION_PREPARED",
    "ACTIVE",
    "DRAINING",
    "RETIRED",
    "REJECTED",
    "FAILED",
  ];
  return hasCompleteOAuthConnectorSchema(sqlite)
    && hasSchemaObjects(
      sqlite,
      ["oauth_connector_activation_receipts", "oauth_connector_retirement_receipts"],
      [
        "oauth_connector_activation_receipts_one_prepared_idx",
        "oauth_connector_activation_receipts_candidate_idx",
        "oauth_connector_retirement_receipts_binding_idx",
      ],
    )
    && hasColumns(sqlite, "oauth_connector_bindings", [
      "authority_contract_generation",
      "redirect_uris_digest",
      "build_digest",
      "drain_deadline_at",
      "refresh_allowed_during_drain",
      "state_reason",
    ])
    && hasColumns(sqlite, "oauth_connector_activation_receipts", [
      "receipt_id",
      "canonical_name",
      "candidate_binding_id",
      "client_id",
      "installation_epoch",
      "schema_generation",
      "authority_contract_generation",
      "redirect_uris_digest",
      "build_digest",
      "tuple_digest",
      "preimage_json",
      "preimage_digest",
      "previous_active_binding_id",
      "owner_authority_id",
      "drain_deadline_at",
      "refresh_allowed_during_drain",
      "status",
      "failure_code",
      "prepared_at",
      "activated_at",
      "failed_at",
    ])
    && hasColumns(sqlite, "oauth_connector_retirement_receipts", [
      "receipt_id",
      "binding_id",
      "canonical_name",
      "drain_epoch",
      "reason",
      "revoked_family_count",
      "retired_at",
    ])
    && requiredStates.every((state) => stateTable?.sql?.includes(`'${state}'`))
    && /unique\s*\(\s*canonical_name\s*,\s*installation_epoch\s*\)/iu.test(stateTable?.sql ?? "");
}

function hasCompleteOAuthConnectorActivationAuthoritySchema(sqlite: Database.Database): boolean {
  const table = sqlite.prepare(
    "select sql from sqlite_master where type = 'table' and name = 'oauth_connector_activation_authorities'",
  ).get() as { sql: string | null } | undefined;
  const definition = table?.sql ?? "";
  const foreignKeys = sqlite.prepare(
    "pragma foreign_key_list(oauth_connector_activation_authorities)",
  ).all() as Array<{
    id: number;
    seq: number;
    table: string;
    from: string;
    to: string;
    on_update: string;
    on_delete: string;
    match: string;
  }>;
  return hasCompleteOAuthConnectorLifecycleSchema(sqlite)
    && hasSchemaObjects(
      sqlite,
      ["oauth_connector_activation_authorities"],
      [
        "oauth_connector_activation_authorities_canonical_idx",
        "oauth_connector_activation_authorities_authority_idx",
      ],
    )
    && hasExactColumns(sqlite, "oauth_connector_activation_authorities", [
      ["action_claim_id", "TEXT", 0, 1],
      ["receipt_id", "TEXT", 1, 0],
      ["authority_id", "TEXT", 1, 0],
      ["principal_key_fingerprint", "TEXT", 1, 0],
      ["action_fingerprint", "TEXT", 1, 0],
      ["resource_key_sha256", "TEXT", 1, 0],
      ["fencing_token", "INTEGER", 1, 0],
      ["risk", "TEXT", 1, 0],
      ["claim_state", "TEXT", 1, 0],
      ["approval_assurance", "TEXT", 1, 0],
      ["canonical_name", "TEXT", 1, 0],
      ["tuple_digest", "TEXT", 1, 0],
      ["active_preimage_digest", "TEXT", 1, 0],
      ["finalization_plan_digest", "TEXT", 1, 0],
      ["evidence_digest", "TEXT", 1, 0],
      ["claimed_at_ms", "INTEGER", 1, 0],
      ["dispatched_at_ms", "INTEGER", 1, 0],
      ["proof_digest", "TEXT", 1, 0],
      ["consumed_at", "TEXT", 1, 0],
    ])
    && hasExactIndex(sqlite, "oauth_connector_activation_authorities_canonical_idx", "oauth_connector_activation_authorities", [
      ["canonical_name", 0],
      ["consumed_at", 0],
    ])
    && hasExactIndex(sqlite, "oauth_connector_activation_authorities_authority_idx", "oauth_connector_activation_authorities", [
      ["authority_id", 0],
      ["action_claim_id", 0],
    ])
    && /unique\s*\(\s*receipt_id\s*\)/iu.test(definition)
    && /unique\s*\(\s*resource_key_sha256\s*,\s*fencing_token\s*\)/iu.test(definition)
    && /unique\s*\(\s*proof_digest\s*\)/iu.test(definition)
    && /check\s*\(\s*risk\s*=\s*'R3'\s*\)/iu.test(definition)
    && /check\s*\(\s*claim_state\s*=\s*'DISPATCHED'\s*\)/iu.test(definition)
    && /check\s*\(\s*approval_assurance\s*=\s*'cooperative'\s*\)/iu.test(definition)
    && /check\s*\(\s*fencing_token\s*>\s*0\s*\)/iu.test(definition)
    && /check\s*\(\s*claimed_at_ms\s*>\s*0\s+and\s+dispatched_at_ms\s*>=\s*claimed_at_ms\s*\)/iu.test(definition)
    && foreignKeys.length === 1
    && foreignKeys[0]?.id === 0
    && foreignKeys[0].seq === 0
    && foreignKeys[0].table === "oauth_connector_activation_receipts"
    && foreignKeys[0].from === "receipt_id"
    && foreignKeys[0].to === "receipt_id"
    && foreignKeys[0].on_update.toUpperCase() === "NO ACTION"
    && foreignKeys[0].on_delete.toUpperCase() === "RESTRICT"
    && foreignKeys[0].match.toUpperCase() === "NONE";
}

function hasCompleteWorkspaceStateSchema(sqlite: Database.Database): boolean {
  return hasSchemaObjects(
    sqlite,
    ["workspace_sessions", "loaded_agent_files"],
    ["workspace_sessions_root_idx", "workspace_sessions_status_idx", "loaded_agent_files_path_idx"],
  ) && hasColumns(sqlite, "workspace_sessions", [
    "id",
    "root",
    "status",
    "mode",
    "source_root",
    "base_ref",
    "base_sha",
    "managed",
    "created_at",
    "last_used_at",
  ]);
}

function hasCompleteOAuthStateSchema(sqlite: Database.Database): boolean {
  return hasSchemaObjects(
    sqlite,
    ["oauth_clients", "oauth_access_tokens", "oauth_refresh_tokens"],
    [
      "oauth_clients_issued_at_idx",
      "oauth_access_tokens_client_id_idx",
      "oauth_access_tokens_expires_at_idx",
      "oauth_refresh_tokens_client_id_idx",
      "oauth_refresh_tokens_expires_at_idx",
    ],
  ) && hasColumns(sqlite, "oauth_clients", ["client_id", "client_json", "issued_at"]);
}

function hasCompleteLocalAgentSchema(sqlite: Database.Database): boolean {
  return hasSchemaObjects(
    sqlite,
    ["local_agent_sessions"],
    [
      "local_agent_sessions_workspace_id_idx",
      "local_agent_sessions_workspace_root_idx",
      "local_agent_sessions_provider_session_id_idx",
    ],
  ) && hasColumns(sqlite, "local_agent_sessions", [
    "id",
    "workspace_id",
    "workspace_root",
    "profile_name",
    "provider",
    "model",
    "thinking",
    "provider_session_id",
    "status",
    "latest_response",
    "error",
    "created_at",
    "updated_at",
  ]);
}

function hasCompleteConversationBindingSchema(sqlite: Database.Database): boolean {
  return hasSchemaObjects(
    sqlite,
    ["workspace_conversation_bindings"],
    ["workspace_conversation_bindings_workspace_idx"],
  ) && hasColumns(sqlite, "workspace_conversation_bindings", [
    "conversation_scope_id",
    "target_key",
    "workspace_session_id",
    "created_at",
    "last_used_at",
  ]);
}

function migrateExternalCommunicationsCompatibility(sqlite: Database.Database): void {
  // Revision 3 no longer ships this provider-specific workflow. The manifest
  // still owns its historical identity so legacy stores can be verified and
  // migrated without silently accepting an unknown entry or recreating the
  // retired surface on fresh installations.
  const historicalObjectCount = Number(sqlite.prepare(`
    select count(*) from sqlite_master
     where name in (
       'external_communications',
       'external_communication_send_claims',
       'external_communications_scope_idx',
       'external_communications_draft_idx',
       'external_communication_send_claims_communication_idx'
     )
  `).pluck().get());
  if (historicalObjectCount > 0) return;
  sqlite.exec(`
    create table if not exists devspace_retired_migration_receipts (
      store_id text not null,
      version integer not null,
      name text not null,
      schema_state text not null check (schema_state = 'ABSENT_BY_DESIGN'),
      recorded_at text not null,
      primary key (store_id, version),
      unique (store_id, name)
    )
  `);
  sqlite.prepare(`
    insert into devspace_retired_migration_receipts
      (store_id, version, name, schema_state, recorded_at)
    values (?, 5, 'external-communications', 'ABSENT_BY_DESIGN', ?)
    on conflict (store_id, version) do nothing
  `).run(MAIN_STORE_ID, new Date().toISOString());
}

function hasCompleteExternalCommunicationsCompatibilitySchema(sqlite: Database.Database): boolean {
  const tables = ["external_communications", "external_communication_send_claims"];
  const indexes = [
    "external_communications_scope_idx",
    "external_communications_draft_idx",
    "external_communication_send_claims_communication_idx",
  ];
  const present = new Set(
    sqlite.prepare("select name from sqlite_master").pluck().all() as string[],
  );
  const requiredObjects = [...tables, ...indexes];
  if (requiredObjects.every((name) => !present.has(name))) {
    return hasRetiredExternalCommunicationsReceipt(sqlite);
  }
  if (requiredObjects.some((name) => !present.has(name))) return false;

  const communicationColumns: ExpectedColumn[] = [
    ["id", "TEXT", 0, 1],
    ["conversation_scope_id", "TEXT", 1, 0],
    ["provider", "TEXT", 1, 0],
    ["application", "TEXT", 1, 0],
    ["target_host", "TEXT", 1, 0],
    ["account_profile", "TEXT", 1, 0],
    ["sender_identity", "TEXT", 1, 0],
    ["to_json", "TEXT", 1, 0],
    ["cc_json", "TEXT", 1, 0],
    ["bcc_json", "TEXT", 1, 0],
    ["subject", "TEXT", 1, 0],
    ["body_sha256", "TEXT", 1, 0],
    ["attachments_json", "TEXT", 1, 0],
    ["draft_id", "TEXT", 0, 0],
    ["message_id", "TEXT", 0, 0],
    ["instruction_mode", "TEXT", 1, 0],
    ["assumption_epoch", "INTEGER", 1, 0],
    ["correction_epoch", "INTEGER", 1, 0],
    ["state", "TEXT", 1, 0],
    ["milestone", "TEXT", 1, 0],
    ["route_json", "TEXT", 1, 0],
    ["route_health_checked_at", "INTEGER", 1, 0],
    ["provider_call_count", "INTEGER", 1, 0],
    ["provider_call_budget", "INTEGER", 1, 0],
    ["state_history_json", "TEXT", 1, 0],
    ["authorities_json", "TEXT", 1, 0],
    ["stale_authority_ids_json", "TEXT", 1, 0],
    ["provider_operation_state", "TEXT", 1, 0],
    ["readback_result", "TEXT", 0, 0],
    ["last_readback_json", "TEXT", 0, 0],
    ["unresolved_draft_id", "TEXT", 0, 0],
    ["last_error_fingerprint", "TEXT", 0, 0],
    ["created_at", "TEXT", 1, 0],
    ["updated_at", "TEXT", 1, 0],
  ];
  const claimColumns: ExpectedColumn[] = [
    ["idempotency_key", "TEXT", 0, 1],
    ["communication_id", "TEXT", 1, 0],
    ["status", "TEXT", 1, 0],
    ["message_id", "TEXT", 0, 0],
    ["result", "TEXT", 0, 0],
    ["readback_json", "TEXT", 0, 0],
    ["created_at", "TEXT", 1, 0],
    ["updated_at", "TEXT", 1, 0],
  ];
  const foreignKeys = sqlite.prepare("pragma foreign_key_list(external_communication_send_claims)").all() as Array<{
    id: number;
    seq: number;
    table: string;
    from: string;
    to: string;
    on_update: string;
    on_delete: string;
    match: string;
  }>;
  return hasExactColumns(sqlite, "external_communications", communicationColumns)
    && hasExactColumns(sqlite, "external_communication_send_claims", claimColumns)
    && hasExactIndex(sqlite, "external_communications_scope_idx", "external_communications", [
      ["conversation_scope_id", 0],
      ["updated_at", 1],
    ])
    && hasExactIndex(sqlite, "external_communications_draft_idx", "external_communications", [["draft_id", 0]])
    && hasExactIndex(sqlite, "external_communication_send_claims_communication_idx", "external_communication_send_claims", [
      ["communication_id", 0],
      ["updated_at", 1],
    ])
    && !hasAnyRetiredExternalCommunicationsReceipt(sqlite)
    && foreignKeys.length === 1
    && foreignKeys[0]?.id === 0
    && foreignKeys[0].seq === 0
    && foreignKeys[0].table === "external_communications"
    && foreignKeys[0].from === "communication_id"
    && foreignKeys[0].to === "id"
    && foreignKeys[0].on_update.toUpperCase() === "NO ACTION"
    && foreignKeys[0].on_delete.toUpperCase() === "CASCADE"
    && foreignKeys[0].match.toUpperCase() === "NONE";
}

type ExpectedColumn = readonly [name: string, type: "TEXT" | "INTEGER", notNull: 0 | 1, primaryKey: number];

function hasRetiredExternalCommunicationsReceipt(sqlite: Database.Database): boolean {
  const table = sqlite.prepare(
    "select sql from sqlite_master where type = 'table' and name = 'devspace_retired_migration_receipts'",
  ).get() as { sql: string | null } | undefined;
  if (!table?.sql) return false;
  const columns: ExpectedColumn[] = [
    ["store_id", "TEXT", 1, 1],
    ["version", "INTEGER", 1, 2],
    ["name", "TEXT", 1, 0],
    ["schema_state", "TEXT", 1, 0],
    ["recorded_at", "TEXT", 1, 0],
  ];
  const row = sqlite.prepare(`
    select name, schema_state as schemaState
      from devspace_retired_migration_receipts
     where store_id = ? and version = 5
  `).get(MAIN_STORE_ID) as { name: string; schemaState: string } | undefined;
  return hasExactColumns(sqlite, "devspace_retired_migration_receipts", columns)
    && /primary\s+key\s*\(\s*store_id\s*,\s*version\s*\)/iu.test(table.sql)
    && /unique\s*\(\s*store_id\s*,\s*name\s*\)/iu.test(table.sql)
    && /check\s*\(\s*schema_state\s*=\s*'ABSENT_BY_DESIGN'\s*\)/iu.test(table.sql)
    && row?.name === "external-communications"
    && row.schemaState === "ABSENT_BY_DESIGN";
}

function hasAnyRetiredExternalCommunicationsReceipt(sqlite: Database.Database): boolean {
  const table = sqlite.prepare(
    "select 1 as present from sqlite_master where type = 'table' and name = 'devspace_retired_migration_receipts'",
  ).get() as { present: number } | undefined;
  if (!table) return false;
  try {
    return Number(sqlite.prepare(`
      select count(*) from devspace_retired_migration_receipts
       where store_id = ? and version = 5
    `).pluck().get(MAIN_STORE_ID)) > 0;
  } catch {
    return true;
  }
}

function hasSchemaObjects(
  sqlite: Database.Database,
  requiredTables: readonly string[],
  requiredIndexes: readonly string[],
): boolean {
  const objects = new Set(
    sqlite.prepare("select name from sqlite_master where type in ('table', 'index')").pluck().all() as string[],
  );
  return [...requiredTables, ...requiredIndexes].every((name) => objects.has(name));
}

function hasColumns(sqlite: Database.Database, table: string, requiredColumns: readonly string[]): boolean {
  const columns = new Set(
    (sqlite.prepare(`pragma table_info(${table})`).all() as Array<{ name: string }>).map((row) => row.name),
  );
  return requiredColumns.every((column) => columns.has(column));
}

function hasExactColumns(
  sqlite: Database.Database,
  table: string,
  expected: readonly ExpectedColumn[],
): boolean {
  const columns = sqlite.prepare(`pragma table_info(${table})`).all() as Array<{
    cid: number;
    name: string;
    type: string;
    notnull: number;
    dflt_value: string | null;
    pk: number;
  }>;
  return columns.length === expected.length && columns.every((column, position) => {
    const [name, type, notNull, primaryKey] = expected[position]!;
    return column.cid === position
      && column.name === name
      && column.type.toUpperCase() === type
      && column.notnull === notNull
      && column.dflt_value === null
      && column.pk === primaryKey;
  });
}

function hasExactIndex(
  sqlite: Database.Database,
  index: string,
  table: string,
  expected: readonly (readonly [name: string, descending: 0 | 1])[],
): boolean {
  const definition = sqlite.prepare(
    "select sql, tbl_name as tableName from sqlite_master where type = 'index' and name = ?",
  ).get(index) as { sql: string | null; tableName: string } | undefined;
  if (
    !definition?.sql
    || definition.tableName !== table
    || !/^create\s+index\b/iu.test(definition.sql.trim())
    || /\bwhere\b/iu.test(definition.sql)
  ) return false;
  const indexList = sqlite.prepare(`pragma index_list(${table})`).all() as Array<{
    name: string;
    unique: number;
    origin: string;
    partial: number;
  }>;
  const listed = indexList.find((candidate) => candidate.name === index);
  if (!listed || listed.unique !== 0 || listed.origin !== "c" || listed.partial !== 0) return false;
  const columns = (sqlite.prepare(`pragma index_xinfo(${index})`).all() as Array<{
    seqno: number;
    name: string | null;
    desc: number;
    coll: string;
    key: number;
  }>).filter((column) => column.key === 1).sort((left, right) => left.seqno - right.seqno);
  return columns.length === expected.length && columns.every((column, position) => {
    const [name, descending] = expected[position]!;
    return column.name === name && column.desc === descending && column.coll === "BINARY";
  });
}

function writeAtomic(path: string, value: Buffer): void {
  const temporary = `${path}.tmp-${process.pid}`;
  const descriptor = openSync(temporary, "wx", 0o600);
  try {
    writeFileSync(descriptor, value);
    fsyncSync(descriptor);
  } finally {
    closeSync(descriptor);
  }
  chmodSync(temporary, 0o600);
  renameSync(temporary, path);
  let directoryDescriptor: number | undefined;
  try {
    directoryDescriptor = openSync(dirname(path), "r");
    fsyncSync(directoryDescriptor);
  } catch (error) {
    if (!new Set(["EINVAL", "ENOTSUP", "EISDIR", "EPERM"]).has((error as NodeJS.ErrnoException).code ?? "")) throw error;
  } finally {
    if (directoryDescriptor !== undefined) closeSync(directoryDescriptor);
  }
}

function migrateWorkspaceState(sqlite: Database.Database): void {
  sqlite.exec(`
    create table if not exists workspace_sessions (
      id text primary key,
      root text not null,
      status text not null default 'active',
      mode text not null default 'checkout',
      source_root text,
      base_ref text,
      base_sha text,
      managed text not null default 'false',
      created_at text not null,
      last_used_at text not null
    );

    create index if not exists workspace_sessions_root_idx
      on workspace_sessions(root, last_used_at desc);

    create index if not exists workspace_sessions_status_idx
      on workspace_sessions(status, last_used_at desc);

    create table if not exists loaded_agent_files (
      workspace_session_id text not null,
      path text not null,
      content_hash text not null,
      content text not null,
      loaded_at text not null,
      last_seen_at text not null,
      primary key (workspace_session_id, path),
      foreign key (workspace_session_id)
        references workspace_sessions(id)
        on delete cascade
    );

    create index if not exists loaded_agent_files_path_idx
      on loaded_agent_files(path);
  `);

  addColumnIfMissing(sqlite, "workspace_sessions", "mode", "text not null default 'checkout'");
  addColumnIfMissing(sqlite, "workspace_sessions", "source_root", "text");
  addColumnIfMissing(sqlite, "workspace_sessions", "base_ref", "text");
  addColumnIfMissing(sqlite, "workspace_sessions", "base_sha", "text");
  addColumnIfMissing(sqlite, "workspace_sessions", "managed", "text not null default 'false'");
}

function migrateOAuthState(sqlite: Database.Database): void {
  sqlite.exec(`
    create table if not exists oauth_clients (
      client_id text primary key,
      client_json text not null,
      issued_at integer not null
    );

    create index if not exists oauth_clients_issued_at_idx
      on oauth_clients(issued_at desc);

    create table if not exists oauth_access_tokens (
      token_hash text primary key,
      client_id text not null,
      scopes_json text not null,
      expires_at integer not null,
      resource text,
      foreign key (client_id) references oauth_clients(client_id) on delete cascade
    );

    create index if not exists oauth_access_tokens_client_id_idx
      on oauth_access_tokens(client_id);

    create index if not exists oauth_access_tokens_expires_at_idx
      on oauth_access_tokens(expires_at);

    create table if not exists oauth_refresh_tokens (
      token_hash text primary key,
      client_id text not null,
      scopes_json text not null,
      expires_at integer not null,
      resource text,
      foreign key (client_id) references oauth_clients(client_id) on delete cascade
    );

    create index if not exists oauth_refresh_tokens_client_id_idx
      on oauth_refresh_tokens(client_id);

    create index if not exists oauth_refresh_tokens_expires_at_idx
      on oauth_refresh_tokens(expires_at);
  `);
}

function migrateLocalAgentSessions(sqlite: Database.Database): void {
  sqlite.exec(`
    create table if not exists local_agent_sessions (
      id text primary key,
      workspace_id text,
      workspace_root text not null,
      profile_name text not null,
      provider text not null,
      model text,
      thinking text,
      provider_session_id text,
      status text not null,
      latest_response text,
      error text,
      created_at text not null,
      updated_at text not null
    );

    create index if not exists local_agent_sessions_workspace_id_idx
      on local_agent_sessions(workspace_id, updated_at desc);

    create index if not exists local_agent_sessions_workspace_root_idx
      on local_agent_sessions(workspace_root, updated_at desc);

    create index if not exists local_agent_sessions_provider_session_id_idx
      on local_agent_sessions(provider_session_id);
  `);

  addColumnIfMissing(sqlite, "local_agent_sessions", "thinking", "text");
}

function migrateWorkspaceConversationBindings(sqlite: Database.Database): void {
  sqlite.exec(`
    create table if not exists workspace_conversation_bindings (
      conversation_scope_id text not null,
      target_key text not null,
      workspace_session_id text not null,
      created_at text not null,
      last_used_at text not null,
      primary key (conversation_scope_id, target_key),
      foreign key (workspace_session_id)
        references workspace_sessions(id)
        on delete cascade
    );

    create index if not exists workspace_conversation_bindings_workspace_idx
      on workspace_conversation_bindings(workspace_session_id);
  `);
}

function migrateOAuthTokenFamiliesAndConnectorBindings(sqlite: Database.Database): void {
  sqlite.exec(`
    create table if not exists oauth_connector_bindings (
      binding_id text primary key,
      canonical_name text not null,
      client_id text not null,
      installation_epoch integer not null,
      schema_generation text not null,
      drain_epoch integer not null default 0,
      state text not null check (state in ('ACTIVE', 'DEPRECATED', 'DRAINED')),
      ref_count integer not null default 0 check (ref_count >= 0),
      created_at text not null,
      updated_at text not null,
      foreign key (client_id) references oauth_clients(client_id) on delete cascade,
      unique (canonical_name, installation_epoch, schema_generation)
    );

    create unique index if not exists oauth_connector_bindings_one_active_name_idx
      on oauth_connector_bindings(canonical_name)
      where state = 'ACTIVE';

    create index if not exists oauth_connector_bindings_client_idx
      on oauth_connector_bindings(client_id, state);

    create table if not exists oauth_token_families (
      family_id text primary key,
      client_id text not null,
      connector_binding_id text,
      installation_epoch integer,
      drain_epoch integer,
      status text not null check (status in ('ACTIVE', 'ROTATING', 'REVOKED')),
      rotation_sequence integer not null default 0,
      created_at text not null,
      rotated_at text,
      revoked_at text,
      foreign key (client_id) references oauth_clients(client_id) on delete cascade,
      foreign key (connector_binding_id) references oauth_connector_bindings(binding_id) on delete restrict
    );

    create index if not exists oauth_token_families_client_idx
      on oauth_token_families(client_id, status);

    create index if not exists oauth_token_families_binding_idx
      on oauth_token_families(connector_binding_id, status);
  `);

  addColumnIfMissing(sqlite, "oauth_access_tokens", "family_id", "text");
  addColumnIfMissing(sqlite, "oauth_access_tokens", "connector_binding_id", "text");
  addColumnIfMissing(sqlite, "oauth_access_tokens", "connector_drain_epoch", "integer");
  addColumnIfMissing(sqlite, "oauth_access_tokens", "installation_epoch", "integer");
  addColumnIfMissing(sqlite, "oauth_access_tokens", "rotation_sequence", "integer not null default 0");
  addColumnIfMissing(sqlite, "oauth_refresh_tokens", "family_id", "text");
  addColumnIfMissing(sqlite, "oauth_refresh_tokens", "connector_binding_id", "text");
  addColumnIfMissing(sqlite, "oauth_refresh_tokens", "connector_drain_epoch", "integer");
  addColumnIfMissing(sqlite, "oauth_refresh_tokens", "installation_epoch", "integer");
  addColumnIfMissing(sqlite, "oauth_refresh_tokens", "rotation_sequence", "integer not null default 0");

  sqlite.exec(`
    create index if not exists oauth_access_tokens_family_idx
      on oauth_access_tokens(family_id);
    create index if not exists oauth_refresh_tokens_family_idx
      on oauth_refresh_tokens(family_id);
  `);

  const legacyClients = sqlite.prepare(`
    select distinct client_id from (
      select client_id from oauth_access_tokens where family_id is null
      union
      select client_id from oauth_refresh_tokens where family_id is null
    ) order by client_id
  `).pluck().all() as string[];
  const createdAt = new Date().toISOString();
  const insertFamily = sqlite.prepare(`
    insert or ignore into oauth_token_families
      (family_id, client_id, connector_binding_id, installation_epoch, drain_epoch,
       status, rotation_sequence, created_at)
    values (?, ?, null, null, null, 'ACTIVE', 0, ?)
  `);
  const bindAccess = sqlite.prepare(
    "update oauth_access_tokens set family_id = ?, rotation_sequence = 0 where client_id = ? and family_id is null",
  );
  const bindRefresh = sqlite.prepare(
    "update oauth_refresh_tokens set family_id = ?, rotation_sequence = 0 where client_id = ? and family_id is null",
  );
  for (const clientId of legacyClients) {
    const familyId = `family-legacy-${createHash("sha256").update(clientId).digest("hex").slice(0, 32)}`;
    insertFamily.run(familyId, clientId, createdAt);
    bindAccess.run(familyId, clientId);
    bindRefresh.run(familyId, clientId);
  }
}

function migrateOAuthConnectorLifecycleRev3(sqlite: Database.Database): void {
  sqlite.exec(`
    create table oauth_connector_bindings_rev3 (
      binding_id text primary key,
      canonical_name text not null,
      client_id text not null,
      installation_epoch integer not null check (installation_epoch > 0),
      schema_generation text not null,
      authority_contract_generation text,
      redirect_uris_digest text,
      build_digest text,
      drain_epoch integer not null default 0 check (drain_epoch >= 0),
      drain_deadline_at text,
      refresh_allowed_during_drain integer not null default 0
        check (refresh_allowed_during_drain in (0, 1)),
      state text not null check (state in (
        'REGISTERED', 'CANDIDATE', 'VERIFIED', 'ACTIVATION_PREPARED',
        'ACTIVE', 'DRAINING', 'RETIRED', 'REJECTED', 'FAILED'
      )),
      state_reason text,
      ref_count integer not null default 0 check (ref_count >= 0),
      created_at text not null,
      updated_at text not null,
      foreign key (client_id) references oauth_clients(client_id) on delete cascade,
      unique (canonical_name, installation_epoch)
    );

    insert into oauth_connector_bindings_rev3
      (binding_id, canonical_name, client_id, installation_epoch, schema_generation,
       authority_contract_generation, redirect_uris_digest, build_digest, drain_epoch,
       drain_deadline_at, refresh_allowed_during_drain, state, state_reason, ref_count,
       created_at, updated_at)
    select binding_id, canonical_name, client_id, installation_epoch, schema_generation,
           null, null, null, drain_epoch,
           case state when 'DEPRECATED' then updated_at else null end,
           0,
           case state
             when 'DEPRECATED' then 'DRAINING'
             when 'DRAINED' then 'RETIRED'
             else state
           end,
           case state
             when 'DEPRECATED' then 'MIGRATED_FROM_DEPRECATED'
             when 'DRAINED' then 'MIGRATED_FROM_DRAINED'
             else null
           end,
           ref_count, created_at, updated_at
      from oauth_connector_bindings;

    create table oauth_token_families_rev3 (
      family_id text primary key,
      client_id text not null,
      connector_binding_id text,
      installation_epoch integer,
      drain_epoch integer,
      status text not null check (status in ('ACTIVE', 'ROTATING', 'REVOKED')),
      rotation_sequence integer not null default 0,
      created_at text not null,
      rotated_at text,
      revoked_at text,
      foreign key (client_id) references oauth_clients(client_id) on delete cascade,
      foreign key (connector_binding_id) references oauth_connector_bindings_rev3(binding_id) on delete restrict
    );

    insert into oauth_token_families_rev3
      (family_id, client_id, connector_binding_id, installation_epoch, drain_epoch,
       status, rotation_sequence, created_at, rotated_at, revoked_at)
    select family_id, client_id, connector_binding_id, installation_epoch, drain_epoch,
           status, rotation_sequence, created_at, rotated_at, revoked_at
      from oauth_token_families;

    drop table oauth_token_families;
    drop table oauth_connector_bindings;
    alter table oauth_connector_bindings_rev3 rename to oauth_connector_bindings;
    alter table oauth_token_families_rev3 rename to oauth_token_families;

    create unique index oauth_connector_bindings_one_active_name_idx
      on oauth_connector_bindings(canonical_name) where state = 'ACTIVE';
    create index oauth_connector_bindings_client_idx
      on oauth_connector_bindings(client_id, state);
    create index oauth_token_families_client_idx
      on oauth_token_families(client_id, status);
    create index oauth_token_families_binding_idx
      on oauth_token_families(connector_binding_id, status);

    create table oauth_connector_activation_receipts (
      receipt_id text primary key,
      canonical_name text not null,
      candidate_binding_id text not null,
      client_id text not null,
      installation_epoch integer not null,
      schema_generation text not null,
      authority_contract_generation text not null,
      redirect_uris_digest text not null,
      build_digest text not null,
      tuple_digest text not null,
      preimage_json text not null,
      preimage_digest text not null,
      previous_active_binding_id text,
      owner_authority_id text,
      drain_deadline_at text not null,
      refresh_allowed_during_drain integer not null
        check (refresh_allowed_during_drain in (0, 1)),
      status text not null check (status in ('PREPARED', 'ACTIVATED', 'FAILED')),
      failure_code text,
      prepared_at text not null,
      activated_at text,
      failed_at text,
      check (
        (status = 'PREPARED' and owner_authority_id is null and activated_at is null and failure_code is null and failed_at is null)
        or (status = 'ACTIVATED' and owner_authority_id is not null and activated_at is not null and failure_code is null and failed_at is null)
        or (status = 'FAILED' and activated_at is null and failure_code is not null and failed_at is not null)
      ),
      foreign key (candidate_binding_id) references oauth_connector_bindings(binding_id) on delete restrict,
      foreign key (previous_active_binding_id) references oauth_connector_bindings(binding_id) on delete restrict
    );
    create unique index oauth_connector_activation_receipts_one_prepared_idx
      on oauth_connector_activation_receipts(canonical_name) where status = 'PREPARED';
    create index oauth_connector_activation_receipts_candidate_idx
      on oauth_connector_activation_receipts(candidate_binding_id, status);

    create table oauth_connector_retirement_receipts (
      receipt_id text primary key,
      binding_id text not null unique,
      canonical_name text not null,
      drain_epoch integer not null,
      reason text not null check (reason in ('REFERENCE_ZERO', 'DEADLINE_ELAPSED')),
      revoked_family_count integer not null check (revoked_family_count >= 0),
      retired_at text not null,
      foreign key (binding_id) references oauth_connector_bindings(binding_id) on delete restrict
    );
    create index oauth_connector_retirement_receipts_binding_idx
      on oauth_connector_retirement_receipts(binding_id, retired_at);
  `);
}

function migrateOAuthConnectorActivationAuthorityRev3(sqlite: Database.Database): void {
  sqlite.exec(`
    create table oauth_connector_activation_authorities (
      action_claim_id text primary key,
      receipt_id text not null,
      authority_id text not null check (length(authority_id) between 1 and 256),
      principal_key_fingerprint text not null
        check (length(principal_key_fingerprint) = 64 and principal_key_fingerprint not glob '*[^0-9a-f]*'),
      action_fingerprint text not null
        check (length(action_fingerprint) = 64 and action_fingerprint not glob '*[^0-9a-f]*'),
      resource_key_sha256 text not null
        check (length(resource_key_sha256) = 64 and resource_key_sha256 not glob '*[^0-9a-f]*'),
      fencing_token integer not null check (fencing_token > 0),
      risk text not null check (risk = 'R3'),
      claim_state text not null check (claim_state = 'DISPATCHED'),
      approval_assurance text not null check (approval_assurance = 'cooperative'),
      canonical_name text not null check (length(canonical_name) between 1 and 128),
      tuple_digest text not null
        check (length(tuple_digest) = 71 and tuple_digest glob 'sha256:[0-9a-f]*'),
      active_preimage_digest text not null
        check (length(active_preimage_digest) = 71 and active_preimage_digest glob 'sha256:[0-9a-f]*'),
      finalization_plan_digest text not null
        check (length(finalization_plan_digest) = 71 and finalization_plan_digest glob 'sha256:[0-9a-f]*'),
      evidence_digest text not null
        check (length(evidence_digest) = 71 and evidence_digest glob 'sha256:[0-9a-f]*'),
      claimed_at_ms integer not null,
      dispatched_at_ms integer not null,
      proof_digest text not null
        check (length(proof_digest) = 71 and proof_digest glob 'sha256:[0-9a-f]*'),
      consumed_at text not null check (length(consumed_at) between 20 and 64),
      unique (receipt_id),
      unique (resource_key_sha256, fencing_token),
      unique (proof_digest),
      check (claimed_at_ms > 0 and dispatched_at_ms >= claimed_at_ms),
      foreign key (receipt_id)
        references oauth_connector_activation_receipts(receipt_id) on delete restrict
    );
    create index oauth_connector_activation_authorities_canonical_idx
      on oauth_connector_activation_authorities(canonical_name, consumed_at);
    create index oauth_connector_activation_authorities_authority_idx
      on oauth_connector_activation_authorities(authority_id, action_claim_id);
  `);
}

function addColumnIfMissing(
  sqlite: Database.Database,
  table: "workspace_sessions" | "local_agent_sessions" | "oauth_access_tokens" | "oauth_refresh_tokens",
  column: string,
  definition: string,
): void {
  const columns = sqlite.prepare(`pragma table_info(${table})`).all() as Array<{ name: string }>;
  if (columns.some((existingColumn) => existingColumn.name === column)) return;

  sqlite.exec(`alter table ${table} add column ${column} ${definition}`);
}
