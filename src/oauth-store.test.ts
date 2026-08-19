import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { mkdtemp, readdir, readFile, rm, stat } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { InvalidGrantError, InvalidTokenError } from "@modelcontextprotocol/sdk/server/auth/errors.js";
import type { OAuthClientInformationFull } from "@modelcontextprotocol/sdk/shared/auth.js";
import Database from "better-sqlite3";
import { databasePath, openDatabase } from "./db/client.js";
import { SingleUserOAuthProvider } from "./oauth-provider.js";
import { SqliteOAuthClientsStore, SqliteOAuthStore } from "./oauth-store.js";

const root = await mkdtemp(join(tmpdir(), "devspace-oauth-test-"));
const oauthConfig = {
  ownerToken: "test-owner-token-that-is-long-enough",
  accessTokenTtlSeconds: 3600,
  refreshTokenTtlSeconds: 2592000,
  scopes: ["devspace"],
  allowedRedirectHosts: ["chatgpt.com"],
};
const mcpUrl = new URL("https://agent.example.com/mcp");
const redirectUri = "https://chatgpt.com/connector_platform_oauth_redirect";

try {
  await testDatabaseConfiguration(join(root, "database-configuration"));
  await testOAuthMigrationPreimageBackup(join(root, "migration-backup"));
  await testOAuthMigrationVersionCollisionFailsClosed(join(root, "migration-collision"));
  await testLegacyOAuthMigrationMarkerCompatibility(join(root, "legacy-migration-marker"));
  testPersistenceAndTokenHashing(join(root, "persistence"));
  testExpiredTokenCleanup(join(root, "expiration"));
  testTransactionalTokenRotation(join(root, "rotation"));
  testConnectorTokenFamilyLifecycle(join(root, "connector-families"));
  await testProviderRestartRotationAndRevocation(join(root, "provider"));
  await testProviderRejectsStaleConnectorCredentials(join(root, "provider-connector-binding"));
} finally {
  await rm(root, { recursive: true, force: true });
}
console.log("OAuth store/provider tests: PASS");

async function testOAuthMigrationPreimageBackup(stateDir: string): Promise<void> {
  const initial = openDatabase(stateDir);
  initial.sqlite.exec(`
    delete from devspace_schema_migrations where version = 6;
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
  ).run("legacy-access", legacyClient.client_id, JSON.stringify(["devspace"]), expiresAt);
  initial.sqlite.prepare(
    "insert into oauth_refresh_tokens (token_hash, client_id, scopes_json, expires_at) values (?, ?, ?, ?)",
  ).run("legacy-refresh", legacyClient.client_id, JSON.stringify(["devspace"]), expiresAt);
  initial.sqlite.prepare(
    "insert into devspace_schema_migrations (version, name, applied_at) values (5, 'external-communications', ?)",
  ).run(new Date().toISOString());
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
      "select version, name from devspace_schema_migrations where version in (5, 6) order by version",
    ).all(),
    [
      { version: 5, name: "external-communications" },
      { version: 6, name: "oauth-token-families-and-connector-bindings" },
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
      backupDatabase.prepare(
        "select count(*) from devspace_schema_migrations where version = 5 and name = 'external-communications'",
      ).pluck().get(),
      1,
    );
    assert.equal(
      backupDatabase.prepare("select count(*) from devspace_schema_migrations where version = 6").pluck().get(),
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
  initial.sqlite.prepare("delete from devspace_schema_migrations where version = 6").run();
  initial.sqlite.prepare(
    "insert into devspace_schema_migrations (version, name, applied_at) values (6, 'unexpected-migration', ?)",
  ).run(new Date().toISOString());
  initial.close();

  assert.throws(
    () => openDatabase(stateDir),
    /migration version 6 is already assigned to unexpected-migration/u,
  );
}

async function testLegacyOAuthMigrationMarkerCompatibility(stateDir: string): Promise<void> {
  const initial = openDatabase(stateDir);
  initial.sqlite.prepare(
    "update devspace_schema_migrations set version = 5 where version = 6 and name = ?",
  ).run("oauth-token-families-and-connector-bindings");
  initial.close();

  const reopened = openDatabase(stateDir);
  try {
    assert.deepEqual(
      reopened.sqlite.prepare(
        "select version, name from devspace_schema_migrations where name = ?",
      ).get("oauth-token-families-and-connector-bindings"),
      { version: 5, name: "oauth-token-families-and-connector-bindings" },
    );
  } finally {
    reopened.close();
  }
}

async function testDatabaseConfiguration(stateDir: string): Promise<void> {
  const database = openDatabase(stateDir);
  try {
    assert.equal(database.sqlite.pragma("journal_mode", { simple: true }), "wal");
    assert.equal(database.sqlite.pragma("synchronous", { simple: true }), 1);
    assert.equal(database.sqlite.pragma("busy_timeout", { simple: true }), 5000);
    assert.equal(database.sqlite.pragma("foreign_keys", { simple: true }), 1);

    const migrations = database.sqlite
      .prepare("select version, name from devspace_schema_migrations order by version")
      .all();
    assert.deepEqual(migrations, [
      { version: 1, name: "workspace-state" },
      { version: 2, name: "oauth-state" },
      { version: 3, name: "local-agent-sessions" },
      { version: 4, name: "workspace-conversation-bindings" },
      { version: 6, name: "oauth-token-families-and-connector-bindings" },
    ]);
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
      scopes: ["devspace"],
      expiresAt: Math.floor(Date.now() / 1000) + 3600,
      resource: mcpUrl.href,
    },
    refreshTokenHash: hashToken(refreshToken),
    refreshToken: {
      clientId: client.client_id,
      scopes: ["devspace"],
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
    accessToken: { clientId: client.client_id, scopes: ["devspace"], expiresAt: expiredAt },
    refreshTokenHash: "expired-refresh-hash",
    refreshToken: { clientId: client.client_id, scopes: ["devspace"], expiresAt: expiredAt },
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
      scopes: ["devspace"],
      expiresAt,
    });

    assert.equal(
      store.saveTokenPair(
        {
          accessTokenHash: "new-access-hash",
          accessToken: { clientId: client.client_id, scopes: ["devspace"], expiresAt },
          refreshTokenHash: "new-refresh-hash",
          refreshToken: { clientId: client.client_id, scopes: ["devspace"], expiresAt },
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
          accessToken: { clientId: client.client_id, scopes: ["devspace"], expiresAt },
          refreshTokenHash: "losing-refresh-hash",
          refreshToken: { clientId: client.client_id, scopes: ["devspace"], expiresAt },
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

function testConnectorTokenFamilyLifecycle(stateDir: string): void {
  const store = new SqliteOAuthStore(stateDir);
  try {
    const clients = new SqliteOAuthClientsStore(store, oauthConfig.allowedRedirectHosts);
    const firstClient = clients.registerClient({ redirect_uris: [redirectUri], client_name: "ChatGPT canonical v1" });
    const secondClient = clients.registerClient({ redirect_uris: [redirectUri], client_name: "ChatGPT canonical v2" });
    const schemaV1 = `sha256:${"1".repeat(64)}`;
    const schemaV2 = `sha256:${"2".repeat(64)}`;
    const firstBinding = store.ensureCanonicalConnectorBinding({
      canonicalName: "myDevSpace",
      clientId: firstClient.client_id,
      installationEpoch: 1,
      schemaGeneration: schemaV1,
    });
    const expiresAt = Math.floor(Date.now() / 1000) + 3600;
    const firstToken = {
      clientId: firstClient.client_id,
      scopes: ["devspace"],
      expiresAt,
      familyId: "family-v1",
      connectorBindingId: firstBinding.bindingId,
      connectorDrainEpoch: firstBinding.drainEpoch,
      installationEpoch: firstBinding.installationEpoch,
      rotationSequence: 0,
    };
    assert.equal(store.saveTokenPair({
      accessTokenHash: "access-v1",
      accessToken: firstToken,
      refreshTokenHash: "refresh-v1",
      refreshToken: firstToken,
    }), true);
    assert.equal(store.getConnectorBinding(firstBinding.bindingId)?.refCount, 1);
    assert.equal(store.credentialBindingIsCurrent(firstToken), true);

    const secondBinding = store.ensureCanonicalConnectorBinding({
      canonicalName: "myDevSpace",
      clientId: secondClient.client_id,
      installationEpoch: 2,
      schemaGeneration: schemaV2,
    });
    assert.equal(store.getConnectorBinding(firstBinding.bindingId)?.state, "DEPRECATED");
    assert.equal(store.getConnectorBinding(firstBinding.bindingId)?.drainEpoch, 1);
    assert.equal(store.credentialBindingIsCurrent(firstToken), false);
    assert.equal(store.drainConnectorBinding(firstBinding.bindingId, 1), false);
    assert.equal(store.revokeTokenFamily("family-v1"), true);
    assert.equal(store.getConnectorBinding(firstBinding.bindingId)?.refCount, 0);
    assert.equal(store.drainConnectorBinding(firstBinding.bindingId, 1), true);
    assert.equal(store.getConnectorBinding(firstBinding.bindingId)?.state, "DRAINED");

    const secondToken = {
      clientId: secondClient.client_id,
      scopes: ["devspace"],
      expiresAt,
      familyId: "family-v2",
      connectorBindingId: secondBinding.bindingId,
      connectorDrainEpoch: secondBinding.drainEpoch,
      installationEpoch: secondBinding.installationEpoch,
      rotationSequence: 0,
    };
    assert.equal(store.saveTokenPair({
      accessTokenHash: "access-v2",
      accessToken: secondToken,
      refreshTokenHash: "refresh-v2",
      refreshToken: secondToken,
    }), true);
    const rotated = { ...secondToken, rotationSequence: 1 };
    assert.equal(store.saveTokenPair({
      accessTokenHash: "access-v2-rotated",
      accessToken: rotated,
      refreshTokenHash: "refresh-v2-rotated",
      refreshToken: rotated,
    }, "refresh-v2"), true);
    assert.equal(store.getRefreshToken("refresh-v2"), undefined);
    assert.equal(store.credentialBindingIsCurrent(rotated), true);
    const thirdBinding = store.ensureCanonicalConnectorBinding({
      canonicalName: "myDevSpace",
      clientId: firstClient.client_id,
      installationEpoch: 1,
      schemaGeneration: schemaV1,
    });
    assert.equal(thirdBinding.installationEpoch, 3, "re-registration must advance rather than reuse a retired epoch");
    assert.equal(store.credentialBindingIsCurrent(rotated), false);
  } finally {
    store.close();
  }
}

async function testProviderRestartRotationAndRevocation(stateDir: string): Promise<void> {
  const firstProvider = new SingleUserOAuthProvider(oauthConfig, mcpUrl, stateDir);
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
      scopes: ["devspace"],
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
      ["devspace"],
      mcpUrl,
    );
    assert.ok(refreshed.refresh_token);
    assert.notEqual(refreshed.access_token, issued.access_token);

    await assert.rejects(
      secondProvider.exchangeRefreshToken(client, issued.refresh_token, ["devspace"], mcpUrl),
      InvalidGrantError,
    );

    await secondProvider.revokeToken(client, { token: refreshed.access_token });
    await assert.rejects(secondProvider.verifyAccessToken(refreshed.access_token), InvalidTokenError);

    await secondProvider.revokeToken(client, { token: refreshed.refresh_token });
    await assert.rejects(
      secondProvider.exchangeRefreshToken(client, refreshed.refresh_token, ["devspace"], mcpUrl),
      InvalidGrantError,
    );
  } finally {
    secondProvider.close();
  }
}

async function testProviderRejectsStaleConnectorCredentials(stateDir: string): Promise<void> {
  const provider = new SingleUserOAuthProvider({
    ...oauthConfig,
    canonicalConnector: {
      name: "myDevSpace",
      installationEpoch: 1,
      schemaGeneration: `sha256:${"c".repeat(64)}`,
    },
  }, mcpUrl, stateDir);
  try {
    const firstClient = await provider.clientsStore.registerClient?.({
      redirect_uris: [redirectUri],
      client_name: "Canonical connector installation one",
    });
    const secondClient = await provider.clientsStore.registerClient?.({
      redirect_uris: [redirectUri],
      client_name: "Canonical connector installation two",
    });
    assert.ok(firstClient);
    assert.ok(secondClient);
    const first = await issueProviderTokens(provider, firstClient, "connector-code-one");
    assert.equal((await provider.verifyAccessToken(first.access_token)).clientId, firstClient.client_id);
    const second = await issueProviderTokens(provider, secondClient, "connector-code-two");
    assert.equal((await provider.verifyAccessToken(second.access_token)).clientId, secondClient.client_id);
    await assert.rejects(provider.verifyAccessToken(first.access_token), InvalidTokenError);
    await assert.rejects(
      provider.exchangeRefreshToken(firstClient, first.refresh_token!, ["devspace"], mcpUrl),
      InvalidGrantError,
    );
  } finally {
    provider.close();
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
      scopes: ["devspace"],
      resource: mcpUrl,
    },
    expiresAtMs: Date.now() + 60_000,
  });
  return provider.exchangeAuthorizationCode(client, code, undefined, redirectUri, mcpUrl);
}

function hashToken(token: string): string {
  return createHash("sha256").update(token).digest("base64url");
}
