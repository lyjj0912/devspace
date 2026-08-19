import { randomUUID } from "node:crypto";
import type { OAuthRegisteredClientsStore } from "@modelcontextprotocol/sdk/server/auth/clients.js";
import { InvalidRequestError } from "@modelcontextprotocol/sdk/server/auth/errors.js";
import type { OAuthClientInformationFull } from "@modelcontextprotocol/sdk/shared/auth.js";
import { openDatabase, type DatabaseHandle } from "./db/client.js";

export interface PersistedTokenBinding {
  familyId?: string;
  connectorBindingId?: string;
  connectorDrainEpoch?: number;
  installationEpoch?: number;
  rotationSequence?: number;
}

export interface PersistedAccessTokenRecord extends PersistedTokenBinding {
  clientId: string;
  scopes: string[];
  expiresAt: number;
  resource?: string;
}

export interface PersistedRefreshTokenRecord extends PersistedTokenBinding {
  clientId: string;
  scopes: string[];
  expiresAt: number;
  resource?: string;
}

export interface PersistedTokenPair {
  accessTokenHash: string;
  accessToken: PersistedAccessTokenRecord;
  refreshTokenHash: string;
  refreshToken: PersistedRefreshTokenRecord;
}

export type ConnectorBindingState = "ACTIVE" | "DEPRECATED" | "DRAINED";

export interface ConnectorBindingRecord {
  bindingId: string;
  canonicalName: string;
  clientId: string;
  installationEpoch: number;
  schemaGeneration: string;
  drainEpoch: number;
  state: ConnectorBindingState;
  refCount: number;
  createdAt: string;
  updatedAt: string;
}

export interface CanonicalConnectorBindingInput {
  canonicalName: string;
  clientId: string;
  installationEpoch: number;
  schemaGeneration: string;
}

function redirectHostAllowed(redirectUri: string, allowedHosts: string[]): boolean {
  let parsed: URL;
  try {
    parsed = new URL(redirectUri);
  } catch {
    return false;
  }

  if (["localhost", "127.0.0.1", "[::1]"].includes(parsed.hostname)) return true;
  return allowedHosts.includes(parsed.hostname);
}

export class SqliteOAuthStore {
  private readonly database: DatabaseHandle;

  constructor(stateDir: string) {
    this.database = openDatabase(stateDir);
    this.deleteExpiredTokens(Math.floor(Date.now() / 1000));
  }

  getClient(clientId: string): OAuthClientInformationFull | undefined {
    const row = this.database.sqlite
      .prepare("select client_json from oauth_clients where client_id = ?")
      .get(clientId) as { client_json: string } | undefined;

    return row ? (JSON.parse(row.client_json) as OAuthClientInformationFull) : undefined;
  }

  registerClient(
    client: Omit<OAuthClientInformationFull, "client_id" | "client_id_issued_at">,
    allowedRedirectHosts: string[],
  ): OAuthClientInformationFull {
    if (!client.redirect_uris.every((uri) => redirectHostAllowed(String(uri), allowedRedirectHosts))) {
      throw new InvalidRequestError("Client redirect_uri is not allowed for this DevSpace server");
    }

    const now = Math.floor(Date.now() / 1000);
    const registered: OAuthClientInformationFull = {
      ...client,
      client_id: `devspace-${randomUUID()}`,
      client_id_issued_at: now,
      token_endpoint_auth_method: client.token_endpoint_auth_method ?? "none",
      grant_types: client.grant_types ?? ["authorization_code", "refresh_token"],
      response_types: client.response_types ?? ["code"],
    };

    this.database.sqlite
      .prepare("insert into oauth_clients (client_id, client_json, issued_at) values (?, ?, ?)")
      .run(registered.client_id, JSON.stringify(registered), now);

    return registered;
  }

  ensureCanonicalConnectorBinding(input: CanonicalConnectorBindingInput): ConnectorBindingRecord {
    validateConnectorBindingInput(input);
    const ensure = this.database.sqlite.transaction(() => {
      const current = this.getActiveConnectorBinding(input.canonicalName);
      if (current
        && current.clientId === input.clientId
        && current.installationEpoch >= input.installationEpoch
        && current.schemaGeneration === input.schemaGeneration) return current;

      const now = new Date().toISOString();
      if (current) {
        const deprecated = this.database.sqlite.prepare(
          `update oauth_connector_bindings
             set state = 'DEPRECATED', drain_epoch = drain_epoch + 1, updated_at = ?
           where binding_id = ? and state = 'ACTIVE' and drain_epoch = ?`,
        ).run(now, current.bindingId, current.drainEpoch);
        if (deprecated.changes !== 1) throw new Error("Canonical connector binding changed concurrently.");
      }

      const installationEpoch = current
        ? Math.max(input.installationEpoch, current.installationEpoch + 1)
        : input.installationEpoch;
      const previous = this.database.sqlite.prepare(
        `select binding_id from oauth_connector_bindings
          where canonical_name = ? and installation_epoch = ? and schema_generation = ?`,
      ).get(input.canonicalName, installationEpoch, input.schemaGeneration) as { binding_id: string } | undefined;
      if (previous) {
        throw new Error("A retired connector installation/schema epoch cannot be reused.");
      }
      const bindingId = `connector-${randomUUID()}`;
      this.database.sqlite.prepare(
        `insert into oauth_connector_bindings
          (binding_id, canonical_name, client_id, installation_epoch, schema_generation,
           drain_epoch, state, ref_count, created_at, updated_at)
         values (?, ?, ?, ?, ?, 0, 'ACTIVE', 0, ?, ?)`,
      ).run(
        bindingId,
        input.canonicalName,
        input.clientId,
        installationEpoch,
        input.schemaGeneration,
        now,
        now,
      );
      return this.getConnectorBinding(bindingId)!;
    });
    return ensure.immediate();
  }

  getActiveConnectorBinding(canonicalName: string): ConnectorBindingRecord | undefined {
    const row = this.database.sqlite.prepare(
      `select binding_id, canonical_name, client_id, installation_epoch, schema_generation,
              drain_epoch, state, ref_count, created_at, updated_at
         from oauth_connector_bindings where canonical_name = ? and state = 'ACTIVE'`,
    ).get(canonicalName) as ConnectorBindingRow | undefined;
    return row ? rowToConnectorBinding(row) : undefined;
  }

  getConnectorBinding(bindingId: string): ConnectorBindingRecord | undefined {
    const row = this.database.sqlite.prepare(
      `select binding_id, canonical_name, client_id, installation_epoch, schema_generation,
              drain_epoch, state, ref_count, created_at, updated_at
         from oauth_connector_bindings where binding_id = ?`,
    ).get(bindingId) as ConnectorBindingRow | undefined;
    return row ? rowToConnectorBinding(row) : undefined;
  }

  acquireConnectorReference(bindingId: string, expectedDrainEpoch: number): boolean {
    const result = this.database.sqlite.prepare(
      `update oauth_connector_bindings set ref_count = ref_count + 1, updated_at = ?
        where binding_id = ? and state = 'ACTIVE' and drain_epoch = ?`,
    ).run(new Date().toISOString(), bindingId, expectedDrainEpoch);
    return result.changes === 1;
  }

  releaseConnectorReference(bindingId: string): boolean {
    const result = this.database.sqlite.prepare(
      `update oauth_connector_bindings set ref_count = ref_count - 1, updated_at = ?
        where binding_id = ? and ref_count > 0`,
    ).run(new Date().toISOString(), bindingId);
    return result.changes === 1;
  }

  drainConnectorBinding(bindingId: string, expectedDrainEpoch: number): boolean {
    const result = this.database.sqlite.prepare(
      `update oauth_connector_bindings
          set state = 'DRAINED', drain_epoch = drain_epoch + 1, updated_at = ?
        where binding_id = ? and state = 'DEPRECATED' and ref_count = 0 and drain_epoch = ?`,
    ).run(new Date().toISOString(), bindingId, expectedDrainEpoch);
    return result.changes === 1;
  }

  saveAccessToken(tokenHash: string, record: PersistedAccessTokenRecord): void {
    this.database.sqlite
      .prepare(
        `insert into oauth_access_tokens
          (token_hash, client_id, scopes_json, expires_at, resource, family_id,
           connector_binding_id, connector_drain_epoch, installation_epoch, rotation_sequence)
         values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
         on conflict(token_hash) do update set
           client_id = excluded.client_id,
           scopes_json = excluded.scopes_json,
           expires_at = excluded.expires_at,
           resource = excluded.resource,
           family_id = excluded.family_id,
           connector_binding_id = excluded.connector_binding_id,
           connector_drain_epoch = excluded.connector_drain_epoch,
           installation_epoch = excluded.installation_epoch,
           rotation_sequence = excluded.rotation_sequence`,
      )
      .run(
        tokenHash,
        record.clientId,
        JSON.stringify(record.scopes),
        record.expiresAt,
        record.resource ?? null,
        record.familyId ?? null,
        record.connectorBindingId ?? null,
        record.connectorDrainEpoch ?? null,
        record.installationEpoch ?? null,
        record.rotationSequence ?? 0,
      );
  }

  getAccessToken(tokenHash: string): PersistedAccessTokenRecord | undefined {
    const row = this.database.sqlite
      .prepare(
        `select client_id, scopes_json, expires_at, resource, family_id,
                connector_binding_id, connector_drain_epoch, installation_epoch, rotation_sequence
           from oauth_access_tokens where token_hash = ?`,
      )
      .get(tokenHash) as TokenRow | undefined;
    return row ? rowToAccessTokenRecord(row) : undefined;
  }

  deleteAccessToken(tokenHash: string): void {
    this.database.sqlite.prepare("delete from oauth_access_tokens where token_hash = ?").run(tokenHash);
  }

  saveRefreshToken(tokenHash: string, record: PersistedRefreshTokenRecord): void {
    this.database.sqlite
      .prepare(
        `insert into oauth_refresh_tokens
          (token_hash, client_id, scopes_json, expires_at, resource, family_id,
           connector_binding_id, connector_drain_epoch, installation_epoch, rotation_sequence)
         values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
         on conflict(token_hash) do update set
           client_id = excluded.client_id,
           scopes_json = excluded.scopes_json,
           expires_at = excluded.expires_at,
           resource = excluded.resource,
           family_id = excluded.family_id,
           connector_binding_id = excluded.connector_binding_id,
           connector_drain_epoch = excluded.connector_drain_epoch,
           installation_epoch = excluded.installation_epoch,
           rotation_sequence = excluded.rotation_sequence`,
      )
      .run(
        tokenHash,
        record.clientId,
        JSON.stringify(record.scopes),
        record.expiresAt,
        record.resource ?? null,
        record.familyId ?? null,
        record.connectorBindingId ?? null,
        record.connectorDrainEpoch ?? null,
        record.installationEpoch ?? null,
        record.rotationSequence ?? 0,
      );
  }

  saveTokenPair(pair: PersistedTokenPair, consumedRefreshTokenHash?: string): boolean {
    validateTokenPairBinding(pair);
    const save = this.database.sqlite.transaction(() => {
      const familyId = pair.refreshToken.familyId;
      if (consumedRefreshTokenHash) {
        const consumed = this.database.sqlite.prepare(
          `select client_id, family_id, connector_binding_id, connector_drain_epoch,
                  installation_epoch, rotation_sequence
             from oauth_refresh_tokens where token_hash = ?`,
        ).get(consumedRefreshTokenHash) as {
          client_id: string;
          family_id: string | null;
          connector_binding_id: string | null;
          connector_drain_epoch: number | null;
          installation_epoch: number | null;
          rotation_sequence: number;
        } | undefined;
        if (!consumed
          || consumed.client_id !== pair.refreshToken.clientId
          || (familyId && (
            consumed.family_id !== familyId
            || consumed.connector_binding_id !== (pair.refreshToken.connectorBindingId ?? null)
            || consumed.connector_drain_epoch !== (pair.refreshToken.connectorDrainEpoch ?? null)
            || consumed.installation_epoch !== (pair.refreshToken.installationEpoch ?? null)
            || consumed.rotation_sequence !== (pair.refreshToken.rotationSequence ?? 0) - 1
          ))) return false;
        if (familyId && !this.bindingAndFamilyAreCurrent({
          ...pair.refreshToken,
          rotationSequence: consumed.rotation_sequence,
        })) return false;
        const removed = this.database.sqlite.prepare("delete from oauth_refresh_tokens where token_hash = ?").run(consumedRefreshTokenHash);
        if (removed.changes !== 1) return false;
        if (familyId) {
          const advanced = this.database.sqlite.prepare(
            `update oauth_token_families
                set status = 'ACTIVE', rotation_sequence = ?, rotated_at = ?
              where family_id = ? and status in ('ACTIVE', 'ROTATING') and rotation_sequence = ?`,
          ).run(
            pair.refreshToken.rotationSequence ?? 0,
            new Date().toISOString(),
            familyId,
            consumed.rotation_sequence,
          );
          if (advanced.changes !== 1) return false;
        }
      } else if (familyId) {
        const bindingId = pair.refreshToken.connectorBindingId;
        if (bindingId && !this.acquireConnectorReference(bindingId, pair.refreshToken.connectorDrainEpoch ?? -1)) return false;
        const created = new Date().toISOString();
        try {
          this.database.sqlite.prepare(
            `insert into oauth_token_families
              (family_id, client_id, connector_binding_id, installation_epoch, drain_epoch,
               status, rotation_sequence, created_at)
             values (?, ?, ?, ?, ?, 'ACTIVE', ?, ?)`,
          ).run(
            familyId,
            pair.refreshToken.clientId,
            bindingId ?? null,
            pair.refreshToken.installationEpoch ?? null,
            pair.refreshToken.connectorDrainEpoch ?? null,
            pair.refreshToken.rotationSequence ?? 0,
            created,
          );
        } catch (error) {
          if (bindingId) this.releaseConnectorReference(bindingId);
          throw error;
        }
      }

      this.saveAccessToken(pair.accessTokenHash, pair.accessToken);
      this.saveRefreshToken(pair.refreshTokenHash, pair.refreshToken);
      return true;
    });

    return save.immediate();
  }

  getRefreshToken(tokenHash: string): PersistedRefreshTokenRecord | undefined {
    const row = this.database.sqlite
      .prepare(
        `select client_id, scopes_json, expires_at, resource, family_id,
                connector_binding_id, connector_drain_epoch, installation_epoch, rotation_sequence
           from oauth_refresh_tokens where token_hash = ?`,
      )
      .get(tokenHash) as TokenRow | undefined;
    return row ? rowToRefreshTokenRecord(row) : undefined;
  }

  credentialBindingIsCurrent(record: PersistedTokenBinding & { clientId: string }): boolean {
    if (!record.familyId && !record.connectorBindingId) return true;
    return this.bindingAndFamilyAreCurrent(record);
  }

  revokeTokenFamily(familyId: string): boolean {
    const revoke = this.database.sqlite.transaction(() => {
      const row = this.database.sqlite.prepare(
        "select status, connector_binding_id from oauth_token_families where family_id = ?",
      ).get(familyId) as { status: string; connector_binding_id: string | null } | undefined;
      if (!row) return false;
      if (row.status !== "REVOKED") {
        const updated = this.database.sqlite.prepare(
          "update oauth_token_families set status = 'REVOKED', revoked_at = ? where family_id = ? and status <> 'REVOKED'",
        ).run(new Date().toISOString(), familyId);
        if (updated.changes !== 1) return false;
        if (row.connector_binding_id && !this.releaseConnectorReference(row.connector_binding_id)) {
          throw new Error("Connector reference could not be released with token-family revocation.");
        }
      }
      this.database.sqlite.prepare("delete from oauth_access_tokens where family_id = ?").run(familyId);
      this.database.sqlite.prepare("delete from oauth_refresh_tokens where family_id = ?").run(familyId);
      return true;
    });
    return revoke.immediate();
  }

  deleteRefreshToken(tokenHash: string): void {
    const row = this.database.sqlite.prepare("select family_id from oauth_refresh_tokens where token_hash = ?")
      .get(tokenHash) as { family_id: string | null } | undefined;
    if (row?.family_id) this.revokeTokenFamily(row.family_id);
    else this.database.sqlite.prepare("delete from oauth_refresh_tokens where token_hash = ?").run(tokenHash);
  }

  close(): void {
    this.database.close();
  }

  private bindingAndFamilyAreCurrent(record: PersistedTokenBinding & { clientId: string }): boolean {
    if (!record.familyId) return false;
    const family = this.database.sqlite.prepare(
      `select client_id, connector_binding_id, installation_epoch, drain_epoch, status, rotation_sequence
         from oauth_token_families where family_id = ?`,
    ).get(record.familyId) as {
      client_id: string;
      connector_binding_id: string | null;
      installation_epoch: number | null;
      drain_epoch: number | null;
      status: string;
      rotation_sequence: number;
    } | undefined;
    if (!family || family.status !== "ACTIVE" || family.client_id !== record.clientId) return false;
    if (family.rotation_sequence !== (record.rotationSequence ?? 0)) return false;
    if (!record.connectorBindingId) return family.connector_binding_id === null;
    if (family.connector_binding_id !== record.connectorBindingId
      || family.installation_epoch !== record.installationEpoch
      || family.drain_epoch !== record.connectorDrainEpoch) return false;
    const binding = this.getConnectorBinding(record.connectorBindingId);
    return Boolean(binding
      && binding.state === "ACTIVE"
      && binding.clientId === record.clientId
      && binding.installationEpoch === record.installationEpoch
      && binding.drainEpoch === record.connectorDrainEpoch);
  }

  private deleteExpiredTokens(nowSeconds: number): void {
    this.database.sqlite.prepare("delete from oauth_access_tokens where expires_at < ?").run(nowSeconds);
    this.database.sqlite.prepare("delete from oauth_refresh_tokens where expires_at < ?").run(nowSeconds);
    const orphanedFamilies = this.database.sqlite.prepare(
      `select family_id from oauth_token_families
        where status <> 'REVOKED'
          and not exists (
            select 1 from oauth_refresh_tokens
             where oauth_refresh_tokens.family_id = oauth_token_families.family_id
          )`,
    ).pluck().all() as string[];
    for (const familyId of orphanedFamilies) this.revokeTokenFamily(familyId);
  }
}

export class SqliteOAuthClientsStore implements OAuthRegisteredClientsStore {
  constructor(
    private readonly store: SqliteOAuthStore,
    private readonly allowedRedirectHosts: string[],
  ) {}

  getClient(clientId: string): OAuthClientInformationFull | undefined {
    return this.store.getClient(clientId);
  }

  registerClient(
    client: Omit<OAuthClientInformationFull, "client_id" | "client_id_issued_at">,
  ): OAuthClientInformationFull {
    return this.store.registerClient(client, this.allowedRedirectHosts);
  }
}

interface TokenRow {
  client_id: string;
  scopes_json: string;
  expires_at: number;
  resource: string | null;
  family_id: string | null;
  connector_binding_id: string | null;
  connector_drain_epoch: number | null;
  installation_epoch: number | null;
  rotation_sequence: number;
}

interface ConnectorBindingRow {
  binding_id: string;
  canonical_name: string;
  client_id: string;
  installation_epoch: number;
  schema_generation: string;
  drain_epoch: number;
  state: ConnectorBindingState;
  ref_count: number;
  created_at: string;
  updated_at: string;
}

function rowToAccessTokenRecord(row: TokenRow): PersistedAccessTokenRecord {
  return tokenRow(row);
}

function rowToRefreshTokenRecord(row: TokenRow): PersistedRefreshTokenRecord {
  return tokenRow(row);
}

function tokenRow(row: TokenRow): PersistedAccessTokenRecord {
  return {
    clientId: row.client_id,
    scopes: JSON.parse(row.scopes_json) as string[],
    expiresAt: row.expires_at,
    resource: row.resource ?? undefined,
    familyId: row.family_id ?? undefined,
    connectorBindingId: row.connector_binding_id ?? undefined,
    connectorDrainEpoch: row.connector_drain_epoch ?? undefined,
    installationEpoch: row.installation_epoch ?? undefined,
    rotationSequence: row.rotation_sequence,
  };
}

function rowToConnectorBinding(row: ConnectorBindingRow): ConnectorBindingRecord {
  return {
    bindingId: row.binding_id,
    canonicalName: row.canonical_name,
    clientId: row.client_id,
    installationEpoch: row.installation_epoch,
    schemaGeneration: row.schema_generation,
    drainEpoch: row.drain_epoch,
    state: row.state,
    refCount: row.ref_count,
    createdAt: row.created_at,
    updatedAt: row.updated_at,
  };
}

function validateConnectorBindingInput(input: CanonicalConnectorBindingInput): void {
  if (!/^[A-Za-z][A-Za-z0-9._-]{0,127}$/u.test(input.canonicalName)) throw new Error("Canonical connector name is invalid.");
  if (!input.clientId) throw new Error("Canonical connector clientId is required.");
  if (!Number.isInteger(input.installationEpoch) || input.installationEpoch < 1) throw new Error("Connector installation epoch is invalid.");
  if (!/^sha256:[a-f0-9]{64}$/u.test(input.schemaGeneration)) throw new Error("Connector schema generation is invalid.");
}

function validateTokenPairBinding(pair: PersistedTokenPair): void {
  const fields: Array<keyof PersistedTokenBinding> = [
    "familyId",
    "connectorBindingId",
    "connectorDrainEpoch",
    "installationEpoch",
    "rotationSequence",
  ];
  if (pair.accessToken.clientId !== pair.refreshToken.clientId) throw new Error("OAuth token pair client identity mismatch.");
  for (const field of fields) {
    if (pair.accessToken[field] !== pair.refreshToken[field]) throw new Error(`OAuth token pair binding mismatch: ${field}`);
  }
  if (pair.refreshToken.connectorBindingId && !pair.refreshToken.familyId) throw new Error("Bound connector credentials require a token family.");
}
