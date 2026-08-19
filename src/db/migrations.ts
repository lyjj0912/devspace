import { createHash } from "node:crypto";
import { chmodSync, closeSync, existsSync, fsyncSync, openSync, readFileSync, renameSync, writeFileSync } from "node:fs";
import { basename, dirname } from "node:path";
import type Database from "better-sqlite3";

interface Migration {
  version: number;
  name: string;
  up(sqlite: Database.Database): void;
}

const OAUTH_CONNECTOR_MIGRATION_VERSION = 6;
const OAUTH_CONNECTOR_MIGRATION_NAME = "oauth-token-families-and-connector-bindings";

const migrations: Migration[] = [
  {
    version: 1,
    name: "workspace-state",
    up: migrateWorkspaceState,
  },
  {
    version: 2,
    name: "oauth-state",
    up: migrateOAuthState,
  },
  {
    version: 3,
    name: "local-agent-sessions",
    up: migrateLocalAgentSessions,
  },
  {
    version: 4,
    name: "workspace-conversation-bindings",
    up: migrateWorkspaceConversationBindings,
  },
  {
    version: OAUTH_CONNECTOR_MIGRATION_VERSION,
    name: OAUTH_CONNECTOR_MIGRATION_NAME,
    up: migrateOAuthTokenFamiliesAndConnectorBindings,
  },
];

export function migrateDatabase(sqlite: Database.Database): void {
  preservePendingOAuthMigrationPreimage(sqlite);
  const migrate = sqlite.transaction(() => {
    sqlite.exec(`
      create table if not exists devspace_schema_migrations (
        version integer primary key,
        name text not null,
        applied_at text not null
      );
    `);

    const appliedRows = sqlite.prepare(
      "select version, name from devspace_schema_migrations",
    ).all() as Array<{ version: number; name: string }>;
    const appliedByVersion = new Map(appliedRows.map((row) => [row.version, row.name]));
    const appliedNames = new Set(appliedRows.map((row) => row.name));
    const recordMigration = sqlite.prepare(
      "insert into devspace_schema_migrations (version, name, applied_at) values (?, ?, ?)",
    );

    for (const migration of migrations) {
      const appliedName = appliedByVersion.get(migration.version);
      if (appliedName !== undefined && appliedName !== migration.name) {
        throw new Error(
          `Database migration version ${migration.version} is already assigned to ${appliedName}; expected ${migration.name}.`,
        );
      }
      if (appliedName === migration.name || appliedNames.has(migration.name)) {
        if (
          migration.name === OAUTH_CONNECTOR_MIGRATION_NAME
          && !hasCompleteOAuthConnectorSchema(sqlite)
        ) {
          throw new Error(
            `Database migration ${OAUTH_CONNECTOR_MIGRATION_NAME} is recorded but its schema is incomplete.`,
          );
        }
        continue;
      }
      migration.up(sqlite);
      recordMigration.run(migration.version, migration.name, new Date().toISOString());
    }
  });

  migrate.immediate();
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
  if (
    !versions.has(2)
    || ((versions.has(OAUTH_CONNECTOR_MIGRATION_VERSION) || names.has(OAUTH_CONNECTOR_MIGRATION_NAME))
      && hasCompleteOAuthConnectorSchema(sqlite))
    || sqlite.name === ":memory:"
  ) return;
  const image = sqlite.serialize();
  const digest = createHash("sha256").update(image).digest("hex");
  const backupPath = `${sqlite.name}.migration-v6.${digest}.sqlite`;
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
