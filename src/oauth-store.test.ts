import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { mkdtemp, readdir, readFile, rm, stat } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { InvalidGrantError, InvalidTokenError } from "@modelcontextprotocol/sdk/server/auth/errors.js";
import type { OAuthClientInformationFull } from "@modelcontextprotocol/sdk/shared/auth.js";
import Database from "better-sqlite3";
import { databasePath, openDatabase } from "./db/client.js";
import {
  mainDatabaseMigrationManifest,
  readMainDatabaseMigrationReadback,
} from "./db/migrations.js";
import { SingleUserOAuthProvider } from "./oauth-provider.js";
import {
  SqliteOAuthClientsStore,
  SqliteOAuthStore,
  connectorActivationAuthorityActionFingerprint,
  connectorActivationAuthorityDescriptor,
  connectorActivationAuthorityResourceKeySha256,
  type ConnectorActivationAuthorityProof,
  type ConnectorActivationReceipt,
  type ConnectorActivationTuple,
  type ConnectorBindingRecord,
  type ConnectorRegistrationInput,
} from "./oauth-store.js";
import {
  actionFingerprint as registryActionFingerprint,
  actionResourceKeySha256 as registryActionResourceKeySha256,
} from "./v2/authority.js";
import { UniversalBrokerMetrics } from "./v2/metrics.js";

const root = await mkdtemp(join(tmpdir(), "devspace-oauth-test-"));
const oauthConfig = {
  ownerToken: "test-owner-token-that-is-long-enough",
  accessTokenTtlSeconds: 3600,
  refreshTokenTtlSeconds: 2592000,
  scopes: ["devspace.read"],
  allowedRedirectHosts: ["chatgpt.com"],
};
const mcpUrl = new URL("https://agent.example.com/mcp");
const redirectUri = "https://chatgpt.com/connector_platform_oauth_redirect";

try {
  await testDatabaseConfiguration(join(root, "database-configuration"));
  testMainDatabaseReadbackFailsClosed(join(root, "migration-readback"));
  await testOAuthMigrationPreimageBackup(join(root, "migration-backup"));
  await testOAuthMigrationVersionCollisionFailsClosed(join(root, "migration-collision"));
  testOAuthMigrationChecksumCollisionFailsClosed(join(root, "migration-checksum-collision"));
  testUnknownAppliedMigrationFailsClosed(join(root, "migration-unknown"));
  testPartialHistoricalMigrationSchemaFailsClosed(join(root, "migration-partial-historical"));
  testWrongTypeHistoricalMigrationSchemaFailsClosed(join(root, "migration-wrong-type-historical"));
  testRecordedLifecycleCompletenessFailsClosed(join(root, "migration-incomplete"));
  await testMisversionedOAuthMigrationMarkerFailsClosed(join(root, "legacy-migration-marker"));
  await testProductionShapedConnectorLifecycleMigration(join(root, "connector-lifecycle-migration"));
  testPersistenceAndTokenHashing(join(root, "persistence"));
  testExpiredTokenCleanup(join(root, "expiration"));
  testTransactionalTokenRotation(join(root, "rotation"));
  testConnectorActivationRejectsArbitraryAuthorityLabel(join(root, "connector-activation-authority-red"));
  testConnectorLifecycleAndAtomicActivation(join(root, "connector-lifecycle"));
  testConcurrentConnectorActivationConsumesAuthorityOnce(join(root, "connector-activation-concurrent"));
  testConnectorActivationSwapFaultRollsBackAuthority(join(root, "connector-activation-swap-fault"));
  testConnectorTransitionMetrics(join(root, "connector-metrics"));
  testConnectorReadinessSummary(join(root, "connector-readiness"));
  testActivationPreimageConflictPreservesActive(join(root, "connector-preimage-conflict"));
  testReferenceAwareDrainAndRetirement(join(root, "connector-drain"));
  await testProviderRestartRotationAndRevocation(join(root, "provider"));
  await testProviderTokenIssuanceNeverActivatesConnector(join(root, "provider-connector-binding"));
} finally {
  await rm(root, { recursive: true, force: true });
}
console.log("OAuth store/provider tests: PASS");

function testConnectorActivationRejectsArbitraryAuthorityLabel(stateDir: string): void {
  const store = new SqliteOAuthStore(stateDir);
  try {
    const clients = new SqliteOAuthClientsStore(store, oauthConfig.allowedRedirectHosts);
    const client = clients.registerClient({
      redirect_uris: [redirectUri],
      client_name: "Arbitrary activation authority",
    });
    const candidate = createVerifiedCandidate(store, connectorInput(client.client_id, 1, "1"), "a");
    const prepared = store.prepareConnectorActivation(candidate.tuple, {
      drainDeadlineAt: new Date(Date.now() + 60_000).toISOString(),
      refreshAllowedDuringDrain: false,
    });

    assert.throws(
      () => store.activatePreparedConnector(
        prepared.receiptId,
        candidate.tuple,
        "arbitrary-nonempty-owner-label" as unknown as ConnectorActivationAuthorityProof,
      ),
      /activation authority proof/u,
    );
    assert.equal(store.getActiveConnectorBinding("myDevSpace"), undefined);
    assert.equal(store.getConnectorBinding(candidate.binding.bindingId)?.state, "ACTIVATION_PREPARED");
  } finally {
    store.close();
  }
}

function testMainDatabaseReadbackFailsClosed(stateDir: string): void {
  const initialized = openDatabase(stateDir);
  initialized.close();
  const path = databasePath(stateDir);
  const complete = readMainDatabaseMigrationReadback(path);
  assert.equal(complete.complete, true);
  assert.equal(complete.appliedEntries, mainDatabaseMigrationManifest().length);

  const expectedV8 = mainDatabaseMigrationManifest().find((entry) => entry.version === 8)!;
  const corrupt = new Database(path);
  corrupt.prepare(
    "update devspace_schema_migrations set checksum = ? where store_id = 'main' and version = 8",
  ).run(`sha256:${"f".repeat(64)}`);
  corrupt.close();
  assert.throws(
    () => readMainDatabaseMigrationReadback(path),
    /conflicts with the current manifest/u,
  );

  const incomplete = new Database(path);
  incomplete.prepare(
    "update devspace_schema_migrations set checksum = ? where store_id = 'main' and version = 8",
  ).run(expectedV8.checksum);
  incomplete.exec("drop index oauth_connector_activation_authorities_authority_idx");
  incomplete.close();
  assert.throws(
    () => readMainDatabaseMigrationReadback(path),
    /schema readback is incomplete/u,
  );
}

async function testOAuthMigrationPreimageBackup(stateDir: string): Promise<void> {
  const initial = openDatabase(stateDir);
  initial.sqlite.exec(`
    delete from devspace_schema_migrations where store_id = 'main' and version in (6, 7, 8);
    drop table oauth_connector_activation_authorities;
    drop table oauth_connector_activation_receipts;
    drop table oauth_connector_retirement_receipts;
    drop table oauth_token_families;
    drop table oauth_connector_bindings;
    drop table oauth_access_tokens;
    drop table oauth_refresh_tokens;
    create table oauth_access_tokens (
      token_hash text primary key,
      client_id text not null,
      scopes_json text not null,
      expires_at integer not null,
      resource text,
      foreign key (client_id) references oauth_clients(client_id) on delete cascade
    );
    create table oauth_refresh_tokens (
      token_hash text primary key,
      client_id text not null,
      scopes_json text not null,
      expires_at integer not null,
      resource text,
      foreign key (client_id) references oauth_clients(client_id) on delete cascade
    );
    create index oauth_access_tokens_client_id_idx on oauth_access_tokens(client_id);
    create index oauth_access_tokens_expires_at_idx on oauth_access_tokens(expires_at);
    create index oauth_refresh_tokens_client_id_idx on oauth_refresh_tokens(client_id);
    create index oauth_refresh_tokens_expires_at_idx on oauth_refresh_tokens(expires_at);
  `);
  const legacyClient = {
    client_id: "legacy-client",
    client_id_issued_at: 1,
    redirect_uris: [redirectUri],
  };
  initial.sqlite.prepare(
    "insert into oauth_clients (client_id, client_json, issued_at) values (?, ?, ?)",
  ).run(legacyClient.client_id, JSON.stringify(legacyClient), 1);
  const expiresAt = Math.floor(Date.now() / 1000) + 3_600;
  initial.sqlite.prepare(
    "insert into oauth_access_tokens (token_hash, client_id, scopes_json, expires_at) values (?, ?, ?, ?)",
  ).run("legacy-access", legacyClient.client_id, JSON.stringify(["devspace.read"]), expiresAt);
  initial.sqlite.prepare(
    "insert into oauth_refresh_tokens (token_hash, client_id, scopes_json, expires_at) values (?, ?, ?, ?)",
  ).run("legacy-refresh", legacyClient.client_id, JSON.stringify(["devspace.read"]), expiresAt);
  initial.close();
  const migrated = openDatabase(stateDir);
  const migratedAccess = migrated.sqlite.prepare(
    "select family_id, rotation_sequence from oauth_access_tokens where token_hash = ?",
  ).get("legacy-access") as { family_id: string | null; rotation_sequence: number };
  const migratedRefresh = migrated.sqlite.prepare(
    "select family_id, rotation_sequence from oauth_refresh_tokens where token_hash = ?",
  ).get("legacy-refresh") as { family_id: string | null; rotation_sequence: number };
  assert.match(migratedAccess.family_id ?? "", /^family-legacy-[a-f0-9]{32}$/u);
  assert.equal(migratedRefresh.family_id, migratedAccess.family_id);
  assert.equal(migratedAccess.rotation_sequence, 0);
  assert.equal(migratedRefresh.rotation_sequence, 0);
  assert.deepEqual(
    migrated.sqlite.prepare(
      "select version, name from devspace_schema_migrations where store_id = 'main' and version in (6, 7, 8) order by version",
    ).all(),
    [
      { version: 6, name: "oauth-token-families-and-connector-bindings" },
      { version: 7, name: "oauth-connector-lifecycle-rev3" },
      { version: 8, name: "oauth-connector-activation-authority-rev3" },
    ],
  );
  migrated.close();
  const names = await readdir(stateDir);
  const backupName = names.find((name) => /^devspace\.sqlite\.migration-v6\.[a-f0-9]{64}\.sqlite$/u.test(name));
  assert.ok(backupName, "pending OAuth migration must retain a byte-exact SQLite preimage");
  const checksum = (await readFile(join(stateDir, `${backupName}.sha256`), "utf8")).trim().split(/\s+/u)[0];
  const backup = await readFile(join(stateDir, backupName));
  assert.equal(createHash("sha256").update(backup).digest("hex"), checksum);
  const backupDatabase = new Database(join(stateDir, backupName), { readonly: true });
  try {
    assert.equal(
      backupDatabase.prepare("select count(*) from devspace_schema_migrations where store_id = 'main' and version = 6").pluck().get(),
      0,
    );
    assert.equal(
      backupDatabase.prepare(
        "select count(*) from sqlite_master where type = 'table' and name = 'oauth_token_families'",
      ).pluck().get(),
      0,
    );
  } finally {
    backupDatabase.close();
  }
}

async function testOAuthMigrationVersionCollisionFailsClosed(stateDir: string): Promise<void> {
  const initial = openDatabase(stateDir);
  initial.sqlite.prepare("delete from devspace_schema_migrations where store_id = 'main' and version = 6").run();
  initial.sqlite.prepare(
    `insert into devspace_schema_migrations
      (store_id, version, name, checksum, module, applied_at)
     values ('main', 6, 'unexpected-migration', ?, 'oauth', ?)`,
  ).run(`sha256:${"f".repeat(64)}`, new Date().toISOString());
  initial.close();

  assert.throws(
    () => openDatabase(stateDir),
    hasErrorCode("MIGRATION_CONFLICT"),
  );
}

function testOAuthMigrationChecksumCollisionFailsClosed(stateDir: string): void {
  const initial = openDatabase(stateDir);
  initial.sqlite.prepare(`
    update devspace_schema_migrations
       set checksum = ?
     where store_id = 'main' and version = 7
  `).run(`sha256:${"0".repeat(64)}`);
  initial.close();
  assert.throws(() => openDatabase(stateDir), hasErrorCode("MIGRATION_CONFLICT"));
}

function testUnknownAppliedMigrationFailsClosed(stateDir: string): void {
  const initial = openDatabase(stateDir);
  initial.sqlite.prepare(`
    insert into devspace_schema_migrations
      (store_id, version, name, checksum, module, applied_at)
    values ('main', 9, 'historical-branch', ?, 'legacy', ?)
  `).run(`sha256:${"5".repeat(64)}`, new Date().toISOString());
  initial.close();
  assert.throws(() => openDatabase(stateDir), hasErrorCode("MIGRATION_CONFLICT"));
}

function testPartialHistoricalMigrationSchemaFailsClosed(stateDir: string): void {
  const initial = openDatabase(stateDir);
  initial.sqlite.exec("create table external_communications (id text primary key)");
  initial.close();
  assert.throws(() => openDatabase(stateDir), hasErrorCode("STATE_CORRUPTED"));
}

function testWrongTypeHistoricalMigrationSchemaFailsClosed(stateDir: string): void {
  const initial = openDatabase(stateDir);
  initial.sqlite.exec("create view external_communications as select 'shadow' as id");
  initial.close();
  assert.throws(() => openDatabase(stateDir), hasErrorCode("STATE_CORRUPTED"));
}

function testRecordedLifecycleCompletenessFailsClosed(stateDir: string): void {
  const initial = openDatabase(stateDir);
  initial.sqlite.exec("drop index oauth_connector_activation_authorities_canonical_idx");
  initial.close();
  assert.throws(() => openDatabase(stateDir), hasErrorCode("STATE_CORRUPTED"));
}

async function testMisversionedOAuthMigrationMarkerFailsClosed(stateDir: string): Promise<void> {
  const initial = openDatabase(stateDir);
  initial.sqlite.prepare(
    "delete from devspace_schema_migrations where store_id = 'main' and version = 5",
  ).run();
  initial.sqlite.prepare(
    "update devspace_schema_migrations set version = 5 where store_id = 'main' and version = 6 and name = ?",
  ).run("oauth-token-families-and-connector-bindings");
  initial.close();

  assert.throws(
    () => openDatabase(stateDir),
    hasErrorCode("MIGRATION_CONFLICT"),
  );
}

async function testProductionShapedConnectorLifecycleMigration(stateDir: string): Promise<void> {
  const initial = openDatabase(stateDir);
  const now = "2026-08-20T00:00:00.000Z";
  const expiresAt = Math.floor(Date.now() / 1000) + 3_600;
  initial.sqlite.pragma("foreign_keys = OFF");
  initial.sqlite.exec(`
    drop table if exists devspace_retired_migration_receipts;
    drop table if exists oauth_connector_activation_authorities;
    drop table if exists oauth_connector_activation_receipts;
    drop table if exists oauth_connector_retirement_receipts;
    drop table oauth_token_families;
    drop table oauth_connector_bindings;

    create table oauth_connector_bindings (
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
    create unique index oauth_connector_bindings_one_active_name_idx
      on oauth_connector_bindings(canonical_name) where state = 'ACTIVE';
    create index oauth_connector_bindings_client_idx
      on oauth_connector_bindings(client_id, state);

    create table oauth_token_families (
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
    create index oauth_token_families_client_idx on oauth_token_families(client_id, status);
    create index oauth_token_families_binding_idx on oauth_token_families(connector_binding_id, status);

    create table external_communications (
      id text primary key,
      conversation_scope_id text not null,
      provider text not null,
      application text not null,
      target_host text not null,
      account_profile text not null,
      sender_identity text not null,
      to_json text not null,
      cc_json text not null,
      bcc_json text not null,
      subject text not null,
      body_sha256 text not null,
      attachments_json text not null,
      draft_id text,
      message_id text,
      instruction_mode text not null,
      assumption_epoch integer not null,
      correction_epoch integer not null,
      state text not null,
      milestone text not null,
      route_json text not null,
      route_health_checked_at integer not null,
      provider_call_count integer not null,
      provider_call_budget integer not null,
      state_history_json text not null,
      authorities_json text not null,
      stale_authority_ids_json text not null,
      provider_operation_state text not null,
      readback_result text,
      last_readback_json text,
      unresolved_draft_id text,
      last_error_fingerprint text,
      created_at text not null,
      updated_at text not null
    );
    create index external_communications_scope_idx
      on external_communications(conversation_scope_id, updated_at desc);
    create index external_communications_draft_idx on external_communications(draft_id);
    create table external_communication_send_claims (
      idempotency_key text primary key,
      communication_id text not null,
      status text not null,
      message_id text,
      result text,
      readback_json text,
      created_at text not null,
      updated_at text not null,
      foreign key (communication_id) references external_communications(id) on delete cascade
    );
    create index external_communication_send_claims_communication_idx
      on external_communication_send_claims(communication_id, updated_at desc);
    insert into external_communications (
      id, conversation_scope_id, provider, application, target_host, account_profile,
      sender_identity, to_json, cc_json, bcc_json, subject, body_sha256,
      attachments_json, instruction_mode, assumption_epoch, correction_epoch, state,
      milestone, route_json, route_health_checked_at, provider_call_count,
      provider_call_budget, state_history_json, authorities_json,
      stale_authority_ids_json, provider_operation_state, created_at, updated_at
    ) values (
      'legacy-communication', 'scope-legacy', 'gmail', 'mail', 'mail.example', 'owner',
      'owner@example.com', '[]', '[]', '[]', 'legacy subject',
      'sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
      '[]', 'prepare', 1, 0, 'DRAFT', 'prepared', '{}', 1, 0, 1, '[]', '[]',
      '[]', 'NOT_DISPATCHED', '2026-08-11T08:24:53.701Z', '2026-08-11T08:24:53.701Z'
    );
    insert into external_communication_send_claims (
      idempotency_key, communication_id, status, created_at, updated_at
    ) values (
      'legacy-claim', 'legacy-communication', 'PREPARED',
      '2026-08-11T08:24:53.701Z', '2026-08-11T08:24:53.701Z'
    );
  `);
  const insertClient = initial.sqlite.prepare(
    "insert into oauth_clients (client_id, client_json, issued_at) values (?, ?, ?)",
  );
  for (const clientId of ["legacy-active", "legacy-deprecated", "legacy-drained"]) {
    insertClient.run(clientId, JSON.stringify({ client_id: clientId, redirect_uris: [redirectUri] }), 1);
  }
  const insertBinding = initial.sqlite.prepare(`
    insert into oauth_connector_bindings
      (binding_id, canonical_name, client_id, installation_epoch, schema_generation,
       drain_epoch, state, ref_count, created_at, updated_at)
    values (?, 'myDevSpace', ?, ?, ?, ?, ?, ?, ?, ?)
  `);
  insertBinding.run("binding-active", "legacy-active", 3, `sha256:${"3".repeat(64)}`, 0, "ACTIVE", 0, now, now);
  insertBinding.run("binding-deprecated", "legacy-deprecated", 2, `sha256:${"2".repeat(64)}`, 1, "DEPRECATED", 1, now, now);
  insertBinding.run("binding-drained", "legacy-drained", 1, `sha256:${"1".repeat(64)}`, 2, "DRAINED", 0, now, now);
  initial.sqlite.prepare(`
    insert into oauth_token_families
      (family_id, client_id, connector_binding_id, installation_epoch, drain_epoch,
       status, rotation_sequence, created_at)
    values ('legacy-family', 'legacy-deprecated', 'binding-deprecated', 2, 1, 'ACTIVE', 0, ?)
  `).run(now);
  initial.sqlite.prepare(`
    insert into oauth_access_tokens
      (token_hash, client_id, scopes_json, expires_at, family_id, connector_binding_id,
       connector_drain_epoch, installation_epoch, rotation_sequence)
    values ('legacy-access', 'legacy-deprecated', '["devspace.read"]', ?, 'legacy-family',
            'binding-deprecated', 1, 2, 0)
  `).run(expiresAt);
  initial.sqlite.prepare(`
    insert into oauth_refresh_tokens
      (token_hash, client_id, scopes_json, expires_at, family_id, connector_binding_id,
       connector_drain_epoch, installation_epoch, rotation_sequence)
    values ('legacy-refresh', 'legacy-deprecated', '["devspace.read"]', ?, 'legacy-family',
            'binding-deprecated', 1, 2, 0)
  `).run(expiresAt);
  initial.sqlite.prepare(
    "delete from devspace_schema_migrations where store_id = 'main' and version in (7, 8)",
  ).run();
  initial.sqlite.exec(`
    create table devspace_schema_migrations_v2_shape (
      version integer primary key,
      name text not null,
      applied_at text not null
    );
    insert into devspace_schema_migrations_v2_shape (version, name, applied_at)
      select version, name, applied_at from devspace_schema_migrations order by version;
    drop table devspace_schema_migrations;
    alter table devspace_schema_migrations_v2_shape rename to devspace_schema_migrations;
  `);
  initial.close();

  const migrated = openDatabase(stateDir);
  try {
    assert.deepEqual(
      migrated.sqlite.prepare(`
        select binding_id, client_id, installation_epoch, schema_generation, drain_epoch, state, ref_count
          from oauth_connector_bindings order by installation_epoch desc
      `).all(),
      [
        { binding_id: "binding-active", client_id: "legacy-active", installation_epoch: 3, schema_generation: `sha256:${"3".repeat(64)}`, drain_epoch: 0, state: "ACTIVE", ref_count: 0 },
        { binding_id: "binding-deprecated", client_id: "legacy-deprecated", installation_epoch: 2, schema_generation: `sha256:${"2".repeat(64)}`, drain_epoch: 1, state: "DRAINING", ref_count: 1 },
        { binding_id: "binding-drained", client_id: "legacy-drained", installation_epoch: 1, schema_generation: `sha256:${"1".repeat(64)}`, drain_epoch: 2, state: "RETIRED", ref_count: 0 },
      ],
    );
    assert.equal(
      migrated.sqlite.prepare("select connector_binding_id from oauth_token_families where family_id = 'legacy-family'").pluck().get(),
      "binding-deprecated",
    );
    assert.equal(migrated.sqlite.prepare("select count(*) from oauth_access_tokens where token_hash = 'legacy-access'").pluck().get(), 1);
    assert.equal(migrated.sqlite.prepare("select count(*) from oauth_refresh_tokens where token_hash = 'legacy-refresh'").pluck().get(), 1);
    assert.equal(
      migrated.sqlite.prepare("select count(*) from devspace_schema_migrations where store_id = 'main' and version = 7").pluck().get(),
      1,
    );
    assert.equal(
      migrated.sqlite.prepare("select count(*) from devspace_schema_migrations where store_id = 'main' and version = 8").pluck().get(),
      1,
    );
    assert.deepEqual(
      migrated.sqlite.prepare(
        "select name, module from devspace_schema_migrations where store_id = 'main' and version = 5",
      ).get(),
      { name: "external-communications", module: "legacy-external-communications" },
    );
    assert.equal(
      migrated.sqlite.prepare("select subject from external_communications where id = 'legacy-communication'").pluck().get(),
      "legacy subject",
    );
    assert.equal(
      migrated.sqlite.prepare(
        "select communication_id from external_communication_send_claims where idempotency_key = 'legacy-claim'",
      ).pluck().get(),
      "legacy-communication",
    );
    assert.deepEqual(
      migrated.sqlite.prepare("pragma table_info(devspace_schema_migrations)").all()
        .map((column) => (column as { name: string }).name),
      ["store_id", "version", "name", "checksum", "module", "applied_at"],
    );
  } finally {
    migrated.close();
  }
  const readinessStore = new SqliteOAuthStore(stateDir);
  try {
    const readiness = readinessStore.connectorReadiness("myDevSpace", Date.parse(now) + 1);
    assert.equal(readiness.activeCount, 1);
    assert.deepEqual(readiness.invalidStates, [
      "VERIFICATION_IDENTITY_INCOMPLETE",
      "DRAINING_DEADLINE_ELAPSED",
    ], "legacy lifecycle rows remain preserved but cannot claim Rev3 readiness before identity reconciliation");
  } finally {
    readinessStore.close();
  }
  assert.ok(
    (await readdir(stateDir)).some((name) => /^devspace\.sqlite\.migration-v7\.[a-f0-9]{64}\.sqlite$/u.test(name)),
    "production-shaped lifecycle upgrade must retain a byte-exact v7 preimage",
  );
  const contradictoryReceipt = new Database(databasePath(stateDir));
  contradictoryReceipt.exec(`
    create table devspace_retired_migration_receipts (
      store_id text not null,
      version integer not null,
      name text not null,
      schema_state text not null check (schema_state = 'ABSENT_BY_DESIGN'),
      recorded_at text not null,
      primary key (store_id, version),
      unique (store_id, name)
    );
    insert into devspace_retired_migration_receipts
      (store_id, version, name, schema_state, recorded_at)
    values ('main', 5, 'external-communications', 'ABSENT_BY_DESIGN', '2026-08-20T00:00:00.000Z');
  `);
  contradictoryReceipt.close();
  assert.throws(
    () => openDatabase(stateDir),
    hasErrorCode("STATE_CORRUPTED"),
    "legacy schema presence and intentional-absence evidence are mutually exclusive",
  );
  const removeContradictoryReceipt = new Database(databasePath(stateDir));
  removeContradictoryReceipt.exec("drop table devspace_retired_migration_receipts");
  removeContradictoryReceipt.close();
  openDatabase(stateDir).close();

  const wrongIndex = new Database(databasePath(stateDir));
  wrongIndex.exec(`
    drop index external_communications_scope_idx;
    create index external_communications_scope_idx
      on external_communications(conversation_scope_id, updated_at asc);
  `);
  wrongIndex.close();
  assert.throws(
    () => openDatabase(stateDir),
    hasErrorCode("STATE_CORRUPTED"),
    "legacy v5 index direction is part of the verified historical schema",
  );

  const repairIndex = new Database(databasePath(stateDir));
  repairIndex.exec(`
    drop index external_communications_scope_idx;
    create index external_communications_scope_idx
      on external_communications(conversation_scope_id, updated_at desc);
  `);
  repairIndex.close();
  openDatabase(stateDir).close();

  const partialIndex = new Database(databasePath(stateDir));
  partialIndex.exec(`
    drop index external_communications_draft_idx;
    create index external_communications_draft_idx
      on external_communications(draft_id) where draft_id is not null;
  `);
  partialIndex.close();
  assert.throws(
    () => openDatabase(stateDir),
    hasErrorCode("STATE_CORRUPTED"),
    "a named partial index cannot stand in for the historical full index",
  );
  const repairPartialIndex = new Database(databasePath(stateDir));
  repairPartialIndex.exec(`
    drop index external_communications_draft_idx;
    create index external_communications_draft_idx on external_communications(draft_id);
  `);
  repairPartialIndex.close();
  openDatabase(stateDir).close();

  const malformedLegacySchema = new Database(databasePath(stateDir));
  malformedLegacySchema.pragma("foreign_keys = OFF");
  malformedLegacySchema.exec(`
    create table external_communications_malformed as
      select * from external_communications;
    create table external_communication_send_claims_malformed as
      select * from external_communication_send_claims;
    drop table external_communication_send_claims;
    drop table external_communications;
    alter table external_communications_malformed rename to external_communications;
    alter table external_communication_send_claims_malformed rename to external_communication_send_claims;
    create index external_communications_scope_idx
      on external_communications(conversation_scope_id, updated_at desc);
    create index external_communications_draft_idx on external_communications(draft_id);
    create index external_communication_send_claims_communication_idx
      on external_communication_send_claims(communication_id, updated_at desc);
  `);
  malformedLegacySchema.close();
  assert.throws(
    () => openDatabase(stateDir),
    hasErrorCode("STATE_CORRUPTED"),
    "matching object and column names cannot hide missing types, constraints, primary keys, or foreign keys",
  );

  const deletedLegacySchema = new Database(databasePath(stateDir));
  deletedLegacySchema.exec(`
    drop table external_communication_send_claims;
    drop table external_communications;
  `);
  deletedLegacySchema.close();
  assert.throws(
    () => openDatabase(stateDir),
    hasErrorCode("STATE_CORRUPTED"),
    "a recorded legacy v5 schema cannot be reinterpreted as a fresh intentional absence",
  );
}

async function testDatabaseConfiguration(stateDir: string): Promise<void> {
  const database = openDatabase(stateDir);
  try {
    assert.equal(database.sqlite.pragma("journal_mode", { simple: true }), "wal");
    assert.equal(database.sqlite.pragma("synchronous", { simple: true }), 1);
    assert.equal(database.sqlite.pragma("busy_timeout", { simple: true }), 5000);
    assert.equal(database.sqlite.pragma("foreign_keys", { simple: true }), 1);

    const migrations = database.sqlite
      .prepare("select store_id, version, name, checksum, module from devspace_schema_migrations order by store_id, version")
      .all();
    assert.equal(
      (migrations.find((migration) => (migration as { version: number }).version === 5) as { checksum: string }).checksum,
      "sha256:5c959ddb0bcc1a58d6d2a7f6dc4e2ebb844406f275f3cb6b6bbb72864f9572ea",
      "the globalized historical v5 checksum is a persistent store identity",
    );
    assert.deepEqual(
      migrations.map((migration) => ({
        ...(migration as Record<string, unknown>),
        checksum: String((migration as { checksum: string }).checksum).replace(/[a-f0-9]{64}$/u, "<digest>"),
      })),
      [
        { store_id: "main", version: 1, name: "workspace-state", checksum: "sha256:<digest>", module: "workspace" },
        { store_id: "main", version: 2, name: "oauth-state", checksum: "sha256:<digest>", module: "oauth" },
        { store_id: "main", version: 3, name: "local-agent-sessions", checksum: "sha256:<digest>", module: "local-agent" },
        { store_id: "main", version: 4, name: "workspace-conversation-bindings", checksum: "sha256:<digest>", module: "workspace" },
        { store_id: "main", version: 5, name: "external-communications", checksum: "sha256:<digest>", module: "legacy-external-communications" },
        { store_id: "main", version: 6, name: "oauth-token-families-and-connector-bindings", checksum: "sha256:<digest>", module: "oauth" },
        { store_id: "main", version: 7, name: "oauth-connector-lifecycle-rev3", checksum: "sha256:<digest>", module: "oauth" },
        { store_id: "main", version: 8, name: "oauth-connector-activation-authority-rev3", checksum: "sha256:<digest>", module: "oauth" },
      ],
    );
    assert.equal(
      database.sqlite.prepare(`
        select count(*) from sqlite_master
         where type = 'table'
           and name in ('external_communications', 'external_communication_send_claims')
      `).pluck().get(),
      0,
      "fresh Base stores must not recreate the retired provider-specific workflow",
    );
    assert.deepEqual(
      database.sqlite.prepare(`
        select name, schema_state
          from devspace_retired_migration_receipts
         where store_id = 'main' and version = 5
      `).get(),
      { name: "external-communications", schema_state: "ABSENT_BY_DESIGN" },
      "fresh Base stores must durably distinguish intentional absence from deleted legacy state",
    );
  } finally {
    database.close();
  }

  if (process.platform !== "win32") {
    assert.equal((await stat(stateDir)).mode & 0o777, 0o700);
    assert.equal((await stat(databasePath(stateDir))).mode & 0o777, 0o600);
  }
}

function testPersistenceAndTokenHashing(stateDir: string): void {
  const accessToken = "access-token-example";
  const refreshToken = "refresh-token-example";
  const firstStore = new SqliteOAuthStore(stateDir);
  const firstClients = new SqliteOAuthClientsStore(firstStore, oauthConfig.allowedRedirectHosts);
  const client = firstClients.registerClient({
    redirect_uris: [redirectUri],
    client_name: "ChatGPT",
  });

  firstStore.saveTokenPair({
    accessTokenHash: hashToken(accessToken),
    accessToken: {
      clientId: client.client_id,
      scopes: ["devspace.read"],
      expiresAt: Math.floor(Date.now() / 1000) + 3600,
      resource: mcpUrl.href,
    },
    refreshTokenHash: hashToken(refreshToken),
    refreshToken: {
      clientId: client.client_id,
      scopes: ["devspace.read"],
      expiresAt: Math.floor(Date.now() / 1000) + 2592000,
      resource: mcpUrl.href,
    },
  });
  firstStore.close();

  const database = openDatabase(stateDir);
  try {
    const accessHashes = database.sqlite
      .prepare("select token_hash from oauth_access_tokens")
      .pluck()
      .all() as string[];
    const refreshHashes = database.sqlite
      .prepare("select token_hash from oauth_refresh_tokens")
      .pluck()
      .all() as string[];
    assert.deepEqual(accessHashes, [hashToken(accessToken)]);
    assert.deepEqual(refreshHashes, [hashToken(refreshToken)]);
    assert.equal(accessHashes.includes(accessToken), false);
    assert.equal(refreshHashes.includes(refreshToken), false);
  } finally {
    database.close();
  }

  const restoredStore = new SqliteOAuthStore(stateDir);
  try {
    const restoredClient = restoredStore.getClient(client.client_id);
    assert.equal(restoredClient?.client_id, client.client_id);
    assert.equal(restoredStore.getAccessToken(hashToken(accessToken))?.resource, mcpUrl.href);
    assert.equal(restoredStore.getRefreshToken(hashToken(refreshToken))?.clientId, client.client_id);
  } finally {
    restoredStore.close();
  }
}

function testExpiredTokenCleanup(stateDir: string): void {
  const store = new SqliteOAuthStore(stateDir);
  const client = new SqliteOAuthClientsStore(store, oauthConfig.allowedRedirectHosts).registerClient({
    redirect_uris: [redirectUri],
  });
  const expiredAt = Math.floor(Date.now() / 1000) - 1;
  store.saveTokenPair({
    accessTokenHash: "expired-access-hash",
    accessToken: { clientId: client.client_id, scopes: ["devspace.read"], expiresAt: expiredAt },
    refreshTokenHash: "expired-refresh-hash",
    refreshToken: { clientId: client.client_id, scopes: ["devspace.read"], expiresAt: expiredAt },
  });
  store.close();

  const reopened = new SqliteOAuthStore(stateDir);
  try {
    assert.equal(reopened.getAccessToken("expired-access-hash"), undefined);
    assert.equal(reopened.getRefreshToken("expired-refresh-hash"), undefined);
  } finally {
    reopened.close();
  }
}

function testTransactionalTokenRotation(stateDir: string): void {
  const store = new SqliteOAuthStore(stateDir);
  try {
    const client = new SqliteOAuthClientsStore(store, oauthConfig.allowedRedirectHosts).registerClient({
      redirect_uris: [redirectUri],
    });
    const expiresAt = Math.floor(Date.now() / 1000) + 3600;
    store.saveRefreshToken("old-refresh-hash", {
      clientId: client.client_id,
      scopes: ["devspace.read"],
      expiresAt,
    });

    assert.equal(
      store.saveTokenPair(
        {
          accessTokenHash: "new-access-hash",
          accessToken: { clientId: client.client_id, scopes: ["devspace.read"], expiresAt },
          refreshTokenHash: "new-refresh-hash",
          refreshToken: { clientId: client.client_id, scopes: ["devspace.read"], expiresAt },
        },
        "old-refresh-hash",
      ),
      true,
    );
    assert.equal(store.getRefreshToken("old-refresh-hash"), undefined);
    assert.ok(store.getAccessToken("new-access-hash"));
    assert.ok(store.getRefreshToken("new-refresh-hash"));

    assert.equal(
      store.saveTokenPair(
        {
          accessTokenHash: "losing-access-hash",
          accessToken: { clientId: client.client_id, scopes: ["devspace.read"], expiresAt },
          refreshTokenHash: "losing-refresh-hash",
          refreshToken: { clientId: client.client_id, scopes: ["devspace.read"], expiresAt },
        },
        "old-refresh-hash",
      ),
      false,
    );
    assert.equal(store.getAccessToken("losing-access-hash"), undefined);
    assert.equal(store.getRefreshToken("losing-refresh-hash"), undefined);
  } finally {
    store.close();
  }
}

function testConnectorLifecycleAndAtomicActivation(stateDir: string): void {
  const store = new SqliteOAuthStore(stateDir);
  try {
    const clients = new SqliteOAuthClientsStore(store, oauthConfig.allowedRedirectHosts);
    const firstClient = clients.registerClient({ redirect_uris: [redirectUri], client_name: "Canonical v1" });
    const secondClient = clients.registerClient({ redirect_uris: [redirectUri], client_name: "Canonical v2" });
    const rejectedClient = clients.registerClient({ redirect_uris: [redirectUri], client_name: "Rejected candidate" });
    const failedClient = clients.registerClient({ redirect_uris: [redirectUri], client_name: "Failed candidate" });

    const firstInput = connectorInput(firstClient.client_id, 1, "1");
    const registered = store.registerConnectorBinding(firstInput);
    assert.equal(registered.state, "REGISTERED");
    assert.throws(
      () => store.registerConnectorBinding(connectorInput(secondClient.client_id, 1, "9")),
      hasErrorCode("CONNECTOR_STATE_CONFLICT"),
      "an installation epoch cannot be reused with another client or schema",
    );
    const candidate = store.ensureCandidateConnectorBinding(firstInput);
    assert.equal(candidate.state, "CANDIDATE");
    const firstTuple = verifyConnector(store, candidate.bindingId, firstInput, "a");
    assert.equal(store.getConnectorBinding(candidate.bindingId)?.state, "VERIFIED");
    const prepared = store.prepareConnectorActivation(firstTuple, {
      drainDeadlineAt: new Date(Date.now() + 60_000).toISOString(),
      refreshAllowedDuringDrain: true,
    });
    assert.equal(prepared.status, "PREPARED");
    assert.match(prepared.tupleDigest, /^sha256:[a-f0-9]{64}$/u);
    assert.match(prepared.preimageDigest, /^sha256:[a-f0-9]{64}$/u);
    assert.equal(prepared.ownerAuthorityId, undefined, "owner authority is sealed only at the activation boundary");
    assert.equal(store.getConnectorBinding(candidate.bindingId)?.state, "ACTIVATION_PREPARED");

    const competing = createVerifiedCandidate(store, connectorInput(secondClient.client_id, 2, "2"), "b");
    assert.throws(
      () => store.prepareConnectorActivation(competing.tuple, {
        drainDeadlineAt: new Date(Date.now() + 60_000).toISOString(),
        refreshAllowedDuringDrain: true,
      }),
      hasErrorCode("CONNECTOR_STATE_CONFLICT"),
      "only one exact activation tuple can be prepared per canonical connector",
    );

    const firstProof = activationAuthorityProof(prepared, "first-activation");
    assert.deepEqual(
      connectorActivationAuthorityDescriptor(firstProof),
      {
        tool: "context",
        operation: "connector_activation_finalize",
        target: "myDevSpace",
        resource: "connector:myDevSpace",
        parameters: {
          receiptId: prepared.receiptId,
          tupleDigest: prepared.tupleDigest,
          activePreimageDigest: prepared.preimageDigest,
          finalizationPlanDigest: firstProof.finalizationPlanDigest,
          canonicalName: "myDevSpace",
        },
      },
      "the internal authority action descriptor is an exact bounded five-field binding",
    );
    assert.equal(
      connectorActivationAuthorityActionFingerprint(firstProof),
      registryActionFingerprint(connectorActivationAuthorityDescriptor(firstProof)),
      "OAuth and the durable authority registry must canonicalize the action identically",
    );
    assert.equal(
      connectorActivationAuthorityResourceKeySha256(firstProof),
      registryActionResourceKeySha256(connectorActivationAuthorityDescriptor(firstProof)),
      "OAuth and the durable authority registry must fence the same canonical connector resource",
    );
    assert.throws(
      () => store.activatePreparedConnector(
        prepared.receiptId,
        { ...firstTuple, buildDigest: digest("f") },
        firstProof,
      ),
      hasErrorCode("CONNECTOR_STATE_CONFLICT"),
    );
    assert.equal(store.getActiveConnectorBinding("myDevSpace"), undefined);
    assert.equal(store.getConnectorBinding(candidate.bindingId)?.state, "ACTIVATION_PREPARED");

    assert.throws(
      () => store.activatePreparedConnector(
        prepared.receiptId,
        firstTuple,
        { ...firstProof, finalizationPlanDigest: digest("f") },
      ),
      hasErrorCode("CONNECTOR_STATE_CONFLICT"),
      "finalization plan drift must invalidate the already-claimed exact action fingerprint",
    );
    const firstReceipt = store.activatePreparedConnector(prepared.receiptId, firstTuple, firstProof);
    assert.equal(firstReceipt.status, "ACTIVATED");
    assert.equal(firstReceipt.ownerAuthorityId, firstProof.authorityId);
    assert.deepEqual(firstReceipt.activationAuthority, store.getActivationAuthorityReceipt(prepared.receiptId));
    assert.deepEqual(
      firstReceipt.activationAuthority,
      {
        ...firstProof,
        proofDigest: firstReceipt.activationAuthority?.proofDigest,
        consumedAt: firstReceipt.activatedAt,
      },
      "finalization readback must expose the exact secret-free owner/claim/tuple/plan/evidence receipt",
    );
    assert.match(firstReceipt.activationAuthority?.proofDigest ?? "", /^sha256:[a-f0-9]{64}$/u);
    assert.equal(store.getActiveConnectorBinding("myDevSpace")?.bindingId, candidate.bindingId);
    assert.throws(
      () => store.activatePreparedConnector(prepared.receiptId, firstTuple, firstProof),
      hasErrorCode("CONNECTOR_STATE_CONFLICT"),
      "the one-shot activation authority must reject replay; crash reconciliation uses readback",
    );

    const second = createVerifiedCandidate(store, connectorInput(secondClient.client_id, 2, "2"), "b");
    const secondPrepared = store.prepareConnectorActivation(second.tuple, {
      drainDeadlineAt: new Date(Date.now() + 60_000).toISOString(),
      refreshAllowedDuringDrain: true,
    });
    assert.equal(secondPrepared.previousActiveBindingId, candidate.bindingId);
    store.activatePreparedConnector(
      secondPrepared.receiptId,
      second.tuple,
      activationAuthorityProof(secondPrepared, "second-activation"),
    );
    assert.equal(store.getActiveConnectorBinding("myDevSpace")?.bindingId, second.binding.bindingId);
    assert.equal(store.getConnectorBinding(candidate.bindingId)?.state, "DRAINING");
    assert.equal(store.getConnectorBinding(candidate.bindingId)?.drainEpoch, 0, "activation must not invalidate bounded-grace references");

    const database = openDatabase(stateDir);
    try {
      assert.equal(
        database.sqlite.prepare("select count(*) from oauth_connector_bindings where canonical_name = 'myDevSpace' and state = 'ACTIVE'").pluck().get(),
        1,
      );
    } finally {
      database.close();
    }

    const rejected = store.ensureCandidateConnectorBinding(connectorInput(rejectedClient.client_id, 3, "3"));
    const rejectedToken = boundToken(
      rejectedClient.client_id,
      rejected,
      "family-rejected",
      Math.floor(Date.now() / 1000) + 3_600,
    );
    assert.equal(store.saveTokenPair({
      accessTokenHash: "access-rejected",
      accessToken: rejectedToken,
      refreshTokenHash: "refresh-rejected",
      refreshToken: rejectedToken,
    }), true);
    store.rejectConnectorBinding(rejected.bindingId, "CANDIDATE_CANARY_FAILED");
    assert.equal(store.getConnectorBinding(rejected.bindingId)?.state, "REJECTED");
    assert.equal(store.getConnectorBinding(rejected.bindingId)?.refCount, 0);
    assert.equal(store.getAccessToken("access-rejected"), undefined);
    assert.equal(store.getRefreshToken("refresh-rejected"), undefined);

    const failed = createVerifiedCandidate(store, connectorInput(failedClient.client_id, 4, "4"), "d");
    const failedPrepared = store.prepareConnectorActivation(failed.tuple, {
      drainDeadlineAt: new Date(Date.now() + 60_000).toISOString(),
      refreshAllowedDuringDrain: false,
    });
    store.failPreparedConnectorActivation(failedPrepared.receiptId, "POST_PREPARE_VALIDATION_FAILED");
    assert.equal(store.getConnectorBinding(failed.binding.bindingId)?.state, "FAILED");
    assert.equal(store.getActivationReceipt(failedPrepared.receiptId)?.status, "FAILED");
  } finally {
    store.close();
  }
}

function testConcurrentConnectorActivationConsumesAuthorityOnce(stateDir: string): void {
  const firstStore = new SqliteOAuthStore(stateDir);
  let secondStore: SqliteOAuthStore | undefined;
  try {
    const clients = new SqliteOAuthClientsStore(firstStore, oauthConfig.allowedRedirectHosts);
    const client = clients.registerClient({ redirect_uris: [redirectUri], client_name: "Concurrent activation" });
    const candidate = createVerifiedCandidate(firstStore, connectorInput(client.client_id, 1, "1"), "a");
    const prepared = firstStore.prepareConnectorActivation(candidate.tuple, {
      drainDeadlineAt: new Date(Date.now() + 60_000).toISOString(),
      refreshAllowedDuringDrain: false,
    });
    const proof = activationAuthorityProof(prepared, "concurrent");
    secondStore = new SqliteOAuthStore(stateDir);

    assert.equal(firstStore.activatePreparedConnector(prepared.receiptId, candidate.tuple, proof).status, "ACTIVATED");
    assert.throws(
      () => secondStore!.activatePreparedConnector(prepared.receiptId, candidate.tuple, proof),
      hasErrorCode("CONNECTOR_STATE_CONFLICT"),
    );
    assert.equal(
      firstStore["database"].sqlite.prepare(
        "select count(*) from oauth_connector_activation_authorities where action_claim_id = ?",
      ).pluck().get(proof.actionClaimId),
      1,
      "two independent store connections must persist exactly one authority consumption",
    );
    assert.equal(
      firstStore["database"].sqlite.prepare(
        "select count(*) from oauth_connector_bindings where canonical_name = 'myDevSpace' and state = 'ACTIVE'",
      ).pluck().get(),
      1,
    );
  } finally {
    secondStore?.close();
    firstStore.close();
  }
}

function testConnectorActivationSwapFaultRollsBackAuthority(stateDir: string): void {
  const store = new SqliteOAuthStore(stateDir);
  try {
    const clients = new SqliteOAuthClientsStore(store, oauthConfig.allowedRedirectHosts);
    const firstClient = clients.registerClient({ redirect_uris: [redirectUri], client_name: "Swap fault v1" });
    const secondClient = clients.registerClient({ redirect_uris: [redirectUri], client_name: "Swap fault v2" });
    const first = createVerifiedCandidate(store, connectorInput(firstClient.client_id, 1, "1"), "a");
    activateCandidate(store, first, Date.now() + 60_000, true, "swap-fault-first");
    const second = createVerifiedCandidate(store, connectorInput(secondClient.client_id, 2, "2"), "b");
    const prepared = store.prepareConnectorActivation(second.tuple, {
      drainDeadlineAt: new Date(Date.now() + 120_000).toISOString(),
      refreshAllowedDuringDrain: false,
    });
    const proof = activationAuthorityProof(prepared, "swap-fault-second");
    store["database"].sqlite.exec(`
      create trigger oauth_test_connector_activation_swap_fault
      before update of state on oauth_connector_bindings
      when old.binding_id = '${second.binding.bindingId}' and new.state = 'ACTIVE'
      begin
        select raise(abort, 'injected connector activation swap fault');
      end;
    `);

    assert.throws(
      () => store.activatePreparedConnector(prepared.receiptId, second.tuple, proof),
      /injected connector activation swap fault/u,
    );
    assert.equal(store.getActiveConnectorBinding("myDevSpace")?.bindingId, first.binding.bindingId);
    assert.equal(store.getConnectorBinding(first.binding.bindingId)?.state, "ACTIVE");
    assert.equal(store.getConnectorBinding(second.binding.bindingId)?.state, "ACTIVATION_PREPARED");
    assert.equal(store.getActivationReceipt(prepared.receiptId)?.status, "PREPARED");
    assert.equal(store.getActivationAuthorityReceipt(prepared.receiptId), undefined);
    assert.equal(
      store["database"].sqlite.prepare(
        "select count(*) from oauth_connector_activation_authorities where action_claim_id = ?",
      ).pluck().get(proof.actionClaimId),
      0,
      "the failed ACTIVE swap must roll back authority consumption in the same transaction",
    );
    store["database"].sqlite.exec("drop trigger oauth_test_connector_activation_swap_fault");
  } finally {
    store.close();
  }
}

function testConnectorReadinessSummary(stateDir: string): void {
  const store = new SqliteOAuthStore(stateDir);
  try {
    const empty = store.connectorReadiness("myDevSpace", Date.now());
    assert.deepEqual(empty, {
      state: "FAIL",
      activeCount: 0,
      bindingsByState: {
        REGISTERED: 0,
        CANDIDATE: 0,
        VERIFIED: 0,
        ACTIVATION_PREPARED: 0,
        ACTIVE: 0,
        DRAINING: 0,
        RETIRED: 0,
        REJECTED: 0,
        FAILED: 0,
      },
      invalidStates: ["ACTIVE_COUNT"],
    });

    const clients = new SqliteOAuthClientsStore(store, oauthConfig.allowedRedirectHosts);
    const firstClient = clients.registerClient({ redirect_uris: [redirectUri], client_name: "Readiness v1" });
    const first = createVerifiedCandidate(store, connectorInput(firstClient.client_id, 1, "1"), "a");
    const firstDeadline = Date.now() + 60_000;
    activateCandidate(store, first, firstDeadline, true, "authority:readiness-first");

    assert.deepEqual(store.connectorReadiness("myDevSpace", firstDeadline - 1), {
      state: "PASS",
      activeCount: 1,
      bindingsByState: {
        REGISTERED: 0,
        CANDIDATE: 0,
        VERIFIED: 0,
        ACTIVATION_PREPARED: 0,
        ACTIVE: 1,
        DRAINING: 0,
        RETIRED: 0,
        REJECTED: 0,
        FAILED: 0,
      },
      invalidStates: [],
    });

    const secondClient = clients.registerClient({ redirect_uris: [redirectUri], client_name: "Readiness v2" });
    const second = createVerifiedCandidate(store, connectorInput(secondClient.client_id, 2, "2"), "b");
    const secondDeadline = Date.now() + 120_000;
    const secondReceipt = store.prepareConnectorActivation(second.tuple, {
      drainDeadlineAt: new Date(secondDeadline).toISOString(),
      refreshAllowedDuringDrain: false,
    });
    assert.equal(store.connectorReadiness("myDevSpace", secondDeadline - 1).state, "PASS");
    store["database"].sqlite.prepare(
      "update oauth_connector_activation_receipts set tuple_digest = ? where receipt_id = ?",
    ).run(digest("0"), secondReceipt.receiptId);
    assert.deepEqual(
      store.connectorReadiness("myDevSpace", secondDeadline - 1).invalidStates,
      ["PREPARED_RECEIPT_MISMATCH"],
      "readiness must recompute the persisted exact activation tuple identity",
    );
    store["database"].sqlite.prepare(
      "update oauth_connector_activation_receipts set tuple_digest = ? where receipt_id = ?",
    ).run(secondReceipt.tupleDigest, secondReceipt.receiptId);
    store.activatePreparedConnector(
      secondReceipt.receiptId,
      second.tuple,
      activationAuthorityProof(secondReceipt, "readiness-second"),
    );
    const draining = store.connectorReadiness("myDevSpace", secondDeadline - 1);
    assert.equal(draining.state, "PASS");
    assert.equal(draining.activeCount, 1);
    assert.equal(draining.bindingsByState.ACTIVE, 1);
    assert.equal(draining.bindingsByState.DRAINING, 1);
    assert.deepEqual(draining.invalidStates, []);
    assert.equal(JSON.stringify(draining).includes(firstClient.client_id), false, "readiness must not expose client identity");
    assert.equal(JSON.stringify(draining).includes(first.binding.bindingId), false, "readiness must not expose binding identity");

    assert.deepEqual(
      store.connectorReadiness("myDevSpace", secondDeadline + 1).invalidStates,
      ["DRAINING_DEADLINE_ELAPSED"],
    );
  } finally {
    store.close();
  }
}

function testConnectorTransitionMetrics(stateDir: string): void {
  const metrics = new UniversalBrokerMetrics();
  const store = new SqliteOAuthStore(stateDir, metrics);
  try {
    const clients = new SqliteOAuthClientsStore(store, oauthConfig.allowedRedirectHosts);
    const firstClient = clients.registerClient({ redirect_uris: [redirectUri], client_name: "Metrics v1" });
    const secondClient = clients.registerClient({ redirect_uris: [redirectUri], client_name: "Metrics v2" });
    const first = createVerifiedCandidate(store, connectorInput(firstClient.client_id, 1, "1"), "a");
    activateCandidate(store, first, Date.now() + 60_000, true, "authority:metrics-first");
    const second = createVerifiedCandidate(store, connectorInput(secondClient.client_id, 2, "2"), "b");
    activateCandidate(store, second, Date.now() + 60_000, true, "authority:metrics-second");
    const draining = store.getConnectorBinding(first.binding.bindingId)!;
    assert.equal(store.retireConnectorBinding(draining.bindingId, draining.drainEpoch)?.reason, "REFERENCE_ZERO");

    const rendered = metrics.render({});
    assert.match(rendered, /devspace_connector_transitions_total\{from="NONE",result="pass",to="CANDIDATE"\} 2/u);
    assert.match(rendered, /devspace_connector_transitions_total\{from="CANDIDATE",result="pass",to="VERIFIED"\} 2/u);
    assert.match(rendered, /devspace_connector_transitions_total\{from="VERIFIED",result="pass",to="ACTIVATION_PREPARED"\} 2/u);
    assert.match(rendered, /devspace_connector_transitions_total\{from="ACTIVATION_PREPARED",result="pass",to="ACTIVE"\} 2/u);
    assert.match(rendered, /devspace_connector_transitions_total\{from="ACTIVE",result="pass",to="DRAINING"\} 1/u);
    assert.match(rendered, /devspace_connector_transitions_total\{from="DRAINING",result="pass",to="RETIRED"\} 1/u);
  } finally {
    store.close();
  }

  const throwingMetrics = {
    recordConnectorTransition: () => { throw new Error("metrics unavailable"); },
  } as unknown as UniversalBrokerMetrics;
  const resilient = new SqliteOAuthStore(join(stateDir, "resilient"), throwingMetrics);
  try {
    const clients = new SqliteOAuthClientsStore(resilient, oauthConfig.allowedRedirectHosts);
    const client = clients.registerClient({
      redirect_uris: [redirectUri],
      client_name: "Metrics resilient",
    });
    assert.equal(resilient.ensureCandidateConnectorBinding(
      connectorInput(client.client_id, 1, "3"),
    ).state, "CANDIDATE");
  } finally {
    resilient.close();
  }
}

function testActivationPreimageConflictPreservesActive(stateDir: string): void {
  const store = new SqliteOAuthStore(stateDir);
  try {
    const clients = new SqliteOAuthClientsStore(store, oauthConfig.allowedRedirectHosts);
    const firstClient = clients.registerClient({ redirect_uris: [redirectUri], client_name: "Preimage v1" });
    const secondClient = clients.registerClient({ redirect_uris: [redirectUri], client_name: "Preimage v2" });
    const first = createVerifiedCandidate(store, connectorInput(firstClient.client_id, 1, "1"), "a");
    activateCandidate(store, first, Date.now() + 60_000, true, "authority:preimage-first");
    const second = createVerifiedCandidate(store, connectorInput(secondClient.client_id, 2, "2"), "b");
    const prepared = store.prepareConnectorActivation(second.tuple, {
      drainDeadlineAt: new Date(Date.now() + 60_000).toISOString(),
      refreshAllowedDuringDrain: true,
    });

    assert.equal(store.acquireConnectorReference(first.binding.bindingId, first.binding.drainEpoch), true);
    assert.throws(
      () => store.activatePreparedConnector(
        prepared.receiptId,
        second.tuple,
        activationAuthorityProof(prepared, "preimage-second"),
      ),
      hasErrorCode("CONNECTOR_STATE_CONFLICT"),
    );
    assert.equal(store.getActiveConnectorBinding("myDevSpace")?.bindingId, first.binding.bindingId);
    assert.equal(store.getConnectorBinding(second.binding.bindingId)?.state, "ACTIVATION_PREPARED");
    assert.equal(store.releaseConnectorReference(first.binding.bindingId), true);
    store.failPreparedConnectorActivation(prepared.receiptId, "ACTIVE_PREIMAGE_CHANGED");
  } finally {
    store.close();
  }
}

function testReferenceAwareDrainAndRetirement(stateDir: string): void {
  const store = new SqliteOAuthStore(stateDir);
  try {
    const clients = new SqliteOAuthClientsStore(store, oauthConfig.allowedRedirectHosts);
    const firstClient = clients.registerClient({ redirect_uris: [redirectUri], client_name: "Drain v1" });
    const secondClient = clients.registerClient({ redirect_uris: [redirectUri], client_name: "Drain v2" });
    const thirdClient = clients.registerClient({ redirect_uris: [redirectUri], client_name: "Drain v3" });
    const first = createVerifiedCandidate(store, connectorInput(firstClient.client_id, 1, "1"), "a");
    activateCandidate(store, first, Date.now() + 60_000, true, "authority:drain-first");
    const expiresAt = Math.floor(Date.now() / 1000) + 3_600;
    const firstToken = boundToken(firstClient.client_id, first.binding, "family-drain-v1", expiresAt);
    assert.equal(store.saveTokenPair({
      accessTokenHash: "access-drain-v1",
      accessToken: firstToken,
      refreshTokenHash: "refresh-drain-v1",
      refreshToken: firstToken,
    }), true);

    const deadline = Date.now() + 60_000;
    const second = createVerifiedCandidate(store, connectorInput(secondClient.client_id, 2, "2"), "b");
    activateCandidate(store, second, deadline, false, "authority:drain-second");
    assert.equal(store.getConnectorBinding(first.binding.bindingId)?.state, "DRAINING");
    assert.equal(store.accessTokenBindingIsCurrent(firstToken, deadline - 1), true);
    assert.equal(store.refreshTokenBindingIsCurrent(firstToken, deadline - 1), false);
    assert.equal(store.retireConnectorBinding(first.binding.bindingId, first.binding.drainEpoch, deadline - 1), undefined);
    assert.equal(store.revokeTokenFamily("family-drain-v1"), true);
    const zeroReferenceReceipt = store.retireConnectorBinding(first.binding.bindingId, first.binding.drainEpoch, deadline - 1);
    assert.equal(zeroReferenceReceipt?.reason, "REFERENCE_ZERO");
    assert.equal(zeroReferenceReceipt?.revokedFamilyCount, 0);
    assert.equal(store.getConnectorBinding(first.binding.bindingId)?.state, "RETIRED");

    const secondToken = boundToken(secondClient.client_id, second.binding, "family-drain-v2", expiresAt);
    assert.equal(store.saveTokenPair({
      accessTokenHash: "access-drain-v2",
      accessToken: secondToken,
      refreshTokenHash: "refresh-drain-v2",
      refreshToken: secondToken,
    }), true);
    const forcedDeadline = Date.now() + 1_000;
    const third = createVerifiedCandidate(store, connectorInput(thirdClient.client_id, 3, "3"), "c");
    activateCandidate(store, third, forcedDeadline, true, "authority:drain-third");
    const forcedReceipt = store.retireConnectorBinding(second.binding.bindingId, second.binding.drainEpoch, forcedDeadline + 1);
    assert.equal(forcedReceipt?.reason, "DEADLINE_ELAPSED");
    assert.equal(forcedReceipt?.revokedFamilyCount, 1);
    assert.equal(store.getConnectorBinding(second.binding.bindingId)?.refCount, 0);
    assert.equal(store.getAccessToken("access-drain-v2"), undefined);
    assert.equal(store.getRefreshToken("refresh-drain-v2"), undefined);
    assert.equal(store.accessTokenBindingIsCurrent(secondToken, forcedDeadline + 1), false);
  } finally {
    store.close();
  }
}

async function testProviderRestartRotationAndRevocation(stateDir: string): Promise<void> {
  const firstProvider = new SingleUserOAuthProvider(oauthConfig, mcpUrl, stateDir);
  assert.deepEqual(firstProvider.connectorReadiness(), {
    state: "FAIL",
    activeCount: 0,
    bindingsByState: {
      REGISTERED: 0,
      CANDIDATE: 0,
      VERIFIED: 0,
      ACTIVATION_PREPARED: 0,
      ACTIVE: 0,
      DRAINING: 0,
      RETIRED: 0,
      REJECTED: 0,
      FAILED: 0,
    },
    invalidStates: ["CANONICAL_NAME_UNCONFIGURED"],
  });
  const client = await firstProvider.clientsStore.registerClient?.({
    redirect_uris: [redirectUri],
    client_name: "ChatGPT",
  });
  assert.ok(client);

  const code = "code-test-123";
  firstProvider["codes"].set(code, {
    clientId: client.client_id,
    params: {
      redirectUri,
      codeChallenge: "challenge",
      scopes: ["devspace.read"],
      resource: mcpUrl,
    },
    expiresAtMs: Date.now() + 60_000,
  });
  const issued = await firstProvider.exchangeAuthorizationCode(
    client,
    code,
    undefined,
    redirectUri,
    mcpUrl,
  );
  assert.ok(issued.refresh_token);
  firstProvider.close();

  const secondProvider = new SingleUserOAuthProvider(oauthConfig, mcpUrl, stateDir);
  try {
    const verified = await secondProvider.verifyAccessToken(issued.access_token);
    assert.equal(verified.clientId, client.client_id);

    const refreshed = await secondProvider.exchangeRefreshToken(
      client,
      issued.refresh_token,
      ["devspace.read"],
      mcpUrl,
    );
    assert.ok(refreshed.refresh_token);
    assert.notEqual(refreshed.access_token, issued.access_token);

    await assert.rejects(
      secondProvider.exchangeRefreshToken(client, issued.refresh_token, ["devspace.read"], mcpUrl),
      InvalidGrantError,
    );

    await secondProvider.revokeToken(client, { token: refreshed.access_token });
    await assert.rejects(secondProvider.verifyAccessToken(refreshed.access_token), InvalidTokenError);

    await secondProvider.revokeToken(client, { token: refreshed.refresh_token });
    await assert.rejects(
      secondProvider.exchangeRefreshToken(client, refreshed.refresh_token, ["devspace.read"], mcpUrl),
      InvalidGrantError,
    );
  } finally {
    secondProvider.close();
  }
}

async function testProviderTokenIssuanceNeverActivatesConnector(stateDir: string): Promise<void> {
  const firstProvider = new SingleUserOAuthProvider({
    ...oauthConfig,
    canonicalConnector: {
      name: "myDevSpace",
      installationEpoch: 1,
      schemaGeneration: `sha256:${"c".repeat(64)}`,
    },
  }, mcpUrl, stateDir);
  let firstClient: OAuthClientInformationFull;
  let firstAccessToken: string;
  try {
    const registered = await firstProvider.clientsStore.registerClient?.({
      redirect_uris: [redirectUri],
      client_name: "Canonical connector installation one",
    });
    assert.ok(registered);
    firstClient = registered;
    const registeredBinding = firstProvider["oauthStore"].getConnectorBindingForClient("myDevSpace", firstClient.client_id);
    assert.equal(registeredBinding?.state, "REGISTERED", "DCR records a non-canonical connector registration");

    const first = await issueProviderTokens(firstProvider, firstClient, "connector-code-one");
    firstAccessToken = first.access_token;
    const candidate = firstProvider["oauthStore"].getConnectorBindingForClient("myDevSpace", firstClient.client_id);
    assert.equal(candidate?.state, "CANDIDATE");
    assert.equal(firstProvider["oauthStore"].getActiveConnectorBinding("myDevSpace"), undefined);
    assert.deepEqual(firstProvider.connectorReadiness().invalidStates, ["ACTIVE_COUNT"]);
    assert.ok(candidate);
    const firstInput = connectorInput(firstClient.client_id, 1, "c");
    const tuple = verifyConnector(firstProvider["oauthStore"], candidate.bindingId, firstInput, "a");
    const receipt = firstProvider["oauthStore"].prepareConnectorActivation(tuple, {
      drainDeadlineAt: new Date(Date.now() + 60_000).toISOString(),
      refreshAllowedDuringDrain: true,
    });
    firstProvider["oauthStore"].activatePreparedConnector(
      receipt.receiptId,
      tuple,
      activationAuthorityProof(receipt, "provider-first"),
    );
    assert.equal(firstProvider.connectorReadiness().state, "PASS");
    assert.equal((await firstProvider.verifyAccessToken(firstAccessToken)).clientId, firstClient.client_id);
  } finally {
    firstProvider.close();
  }

  const secondProvider = new SingleUserOAuthProvider({
    ...oauthConfig,
    canonicalConnector: {
      name: "myDevSpace",
      installationEpoch: 2,
      schemaGeneration: `sha256:${"d".repeat(64)}`,
    },
  }, mcpUrl, stateDir);
  try {
    const secondClient = await secondProvider.clientsStore.registerClient?.({
      redirect_uris: [redirectUri],
      client_name: "Canonical connector installation two",
    });
    assert.ok(secondClient);
    assert.equal(
      secondProvider["oauthStore"].getConnectorBindingForClient("myDevSpace", secondClient.client_id)?.state,
      "REGISTERED",
    );
    const activeBeforeToken = secondProvider["oauthStore"].getActiveConnectorBinding("myDevSpace");
    assert.ok(activeBeforeToken);
    const second = await issueProviderTokens(secondProvider, secondClient, "connector-code-two");
    const candidateAuth = await secondProvider.verifyAccessToken(second.access_token);
    assert.equal(candidateAuth.clientId, secondClient.client_id);
    assert.deepEqual(candidateAuth.extra?.devspaceConnector, {
      bindingId: secondProvider["oauthStore"].getConnectorBindingForClient("myDevSpace", secondClient.client_id)?.bindingId,
      canonicalName: "myDevSpace",
      state: "CANDIDATE",
      installationEpoch: 2,
      schemaGeneration: digest("d"),
      buildDigest: undefined,
      drainDeadlineAt: undefined,
      activationRequired: true,
    });
    assert.equal((await secondProvider.verifyAccessToken(firstAccessToken)).clientId, firstClient.client_id);
    assert.deepEqual(
      secondProvider["oauthStore"].getActiveConnectorBinding("myDevSpace"),
      activeBeforeToken,
      "token issuance must not mutate or replace the canonical ACTIVE binding",
    );
    assert.equal(
      secondProvider["oauthStore"].getConnectorBindingForClient("myDevSpace", secondClient.client_id)?.state,
      "CANDIDATE",
    );
    assert.equal(secondProvider.connectorReadiness().state, "PASS", "a candidate does not make the canonical ACTIVE unready");
    const secondCandidate = secondProvider["oauthStore"].getConnectorBindingForClient("myDevSpace", secondClient.client_id);
    assert.ok(secondCandidate);
    const secondInput = connectorInput(secondClient.client_id, 2, "d");
    const secondTuple = verifyConnector(secondProvider["oauthStore"], secondCandidate.bindingId, secondInput, "b");
    const secondReceipt = secondProvider["oauthStore"].prepareConnectorActivation(secondTuple, {
      drainDeadlineAt: new Date(Date.now() + 60_000).toISOString(),
      refreshAllowedDuringDrain: true,
    });
    secondProvider["oauthStore"].activatePreparedConnector(
      secondReceipt.receiptId,
      secondTuple,
      activationAuthorityProof(secondReceipt, "provider-second"),
    );
    assert.equal(secondProvider.connectorReadiness().state, "PASS", "bounded DRAINING and one ACTIVE are consistent");
    assert.equal(
      secondProvider["oauthStore"].connectorCanIssueAuthorizationCode("myDevSpace", firstClient.client_id),
      false,
    );
    await assert.rejects(
      issueProviderTokens(secondProvider, firstClient, "draining-connector-code"),
      InvalidGrantError,
    );
    const drainingAuth = await secondProvider.verifyAccessToken(firstAccessToken);
    assert.equal(drainingAuth.clientId, firstClient.client_id, "existing access remains valid during the approved drain window");
    assert.equal((drainingAuth.extra?.devspaceConnector as { state?: string } | undefined)?.state, "DRAINING");
    assert.equal((drainingAuth.extra?.devspaceConnector as { activationRequired?: boolean } | undefined)?.activationRequired, false);
  } finally {
    secondProvider.close();
  }
}

async function issueProviderTokens(
  provider: SingleUserOAuthProvider,
  client: OAuthClientInformationFull,
  code: string,
) {
  provider["codes"].set(code, {
    clientId: client.client_id,
    params: {
      redirectUri,
      codeChallenge: "challenge",
      scopes: ["devspace.read"],
      resource: mcpUrl,
    },
    expiresAtMs: Date.now() + 60_000,
  });
  return provider.exchangeAuthorizationCode(client, code, undefined, redirectUri, mcpUrl);
}

function connectorInput(clientId: string, installationEpoch: number, schemaDigit: string): ConnectorRegistrationInput {
  return {
    canonicalName: "myDevSpace",
    clientId,
    installationEpoch,
    schemaGeneration: digest(schemaDigit),
  };
}

function verifyConnector(
  store: SqliteOAuthStore,
  bindingId: string,
  input: ConnectorRegistrationInput,
  identityDigit: string,
): ConnectorActivationTuple {
  const identities = {
    authorityContractGeneration: digest(identityDigit),
    redirectUrisDigest: digest(identityDigit),
    buildDigest: digest(identityDigit),
  };
  store.markConnectorBindingVerified(bindingId, identities);
  return {
    canonicalName: input.canonicalName,
    candidateBindingId: bindingId,
    clientId: input.clientId,
    installationEpoch: input.installationEpoch,
    schemaGeneration: input.schemaGeneration,
    ...identities,
  };
}

function createVerifiedCandidate(
  store: SqliteOAuthStore,
  input: ConnectorRegistrationInput,
  identityDigit: string,
): { binding: ConnectorBindingRecord; tuple: ConnectorActivationTuple } {
  const binding = store.ensureCandidateConnectorBinding(input);
  const tuple = verifyConnector(store, binding.bindingId, input, identityDigit);
  return { binding, tuple };
}

function activateCandidate(
  store: SqliteOAuthStore,
  candidate: { binding: ConnectorBindingRecord; tuple: ConnectorActivationTuple },
  deadlineMs: number,
  refreshAllowedDuringDrain: boolean,
  authorityLabel: string,
): void {
  const receipt = store.prepareConnectorActivation(candidate.tuple, {
    drainDeadlineAt: new Date(deadlineMs).toISOString(),
    refreshAllowedDuringDrain,
  });
  store.activatePreparedConnector(
    receipt.receiptId,
    candidate.tuple,
    activationAuthorityProof(receipt, authorityLabel),
  );
}

function activationAuthorityProof(
  receipt: ConnectorActivationReceipt,
  label: string,
): ConnectorActivationAuthorityProof {
  const binding = {
    receiptId: receipt.receiptId,
    tupleDigest: receipt.tupleDigest,
    activePreimageDigest: receipt.preimageDigest,
    finalizationPlanDigest: digestText(`finalization-plan\0${label}`),
    canonicalName: receipt.tuple.canonicalName,
  };
  const claimedAtMs = 1_700_000_000_000 + receipt.tuple.installationEpoch * 10;
  return {
    schemaVersion: 1,
    authorityId: `authority_${uuidText(`authority\0${receipt.receiptId}\0${label}`)}`,
    actionClaimId: `authority_claim_${uuidText(`claim\0${receipt.receiptId}\0${label}`)}`,
    actionFingerprint: connectorActivationAuthorityActionFingerprint(binding),
    resourceKeySha256: connectorActivationAuthorityResourceKeySha256(binding),
    fencingToken: receipt.tuple.installationEpoch,
    principalKeyFingerprint: createHash("sha256").update("stable-test-owner-principal").digest("hex"),
    risk: "R3",
    claimState: "DISPATCHED",
    approvalAssurance: "cooperative",
    ...binding,
    evidenceDigest: digestText(`owner-finalization-evidence\0${label}`),
    claimedAtMs,
    dispatchedAtMs: claimedAtMs + 1,
  };
}

function uuidText(value: string): string {
  const hex = createHash("sha256").update(value).digest("hex").slice(0, 32);
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
}

function digestText(value: string): string {
  return `sha256:${createHash("sha256").update(value).digest("hex")}`;
}

function boundToken(
  clientId: string,
  binding: ConnectorBindingRecord,
  familyId: string,
  expiresAt: number,
) {
  return {
    clientId,
    scopes: ["devspace.read"],
    expiresAt,
    familyId,
    connectorBindingId: binding.bindingId,
    connectorDrainEpoch: binding.drainEpoch,
    installationEpoch: binding.installationEpoch,
    rotationSequence: 0,
  };
}

function digest(character: string): string {
  return `sha256:${character.repeat(64)}`;
}

function hasErrorCode(code: string): (error: unknown) => boolean {
  return (error) => error instanceof Error && "code" in error && error.code === code;
}

function hashToken(token: string): string {
  return createHash("sha256").update(token).digest("base64url");
}
