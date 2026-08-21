import { timingSafeEqual, randomBytes, randomUUID, createHash } from "node:crypto";
import type { Response } from "express";
import type { OAuthRegisteredClientsStore } from "@modelcontextprotocol/sdk/server/auth/clients.js";
import type { OAuthServerProvider, AuthorizationParams } from "@modelcontextprotocol/sdk/server/auth/provider.js";
import { AccessDeniedError, InvalidGrantError, InvalidRequestError, InvalidTokenError } from "@modelcontextprotocol/sdk/server/auth/errors.js";
import type { AuthInfo } from "@modelcontextprotocol/sdk/server/auth/types.js";
import type {
  OAuthClientInformationFull,
  OAuthTokenRevocationRequest,
  OAuthTokens,
} from "@modelcontextprotocol/sdk/shared/auth.js";
import { checkResourceAllowed, resourceUrlFromServerUrl } from "@modelcontextprotocol/sdk/shared/auth-utils.js";
import {
  ConnectorStateConflictError,
  SqliteOAuthClientsStore,
  SqliteOAuthStore,
  type ConnectorAuthenticationContext,
  type ConnectorBindingRecord,
  type ConnectorReadinessSummary,
  type PersonalConnectorReadinessSummary,
  type PersistedRefreshTokenRecord,
} from "./oauth-store.js";
import type { UniversalBrokerMetrics } from "./v2/metrics.js";

export interface OAuthConfig {
  ownerToken: string;
  accessTokenTtlSeconds: number;
  refreshTokenTtlSeconds: number;
  scopes: string[];
  allowedRedirectHosts: string[];
  canonicalConnector?: {
    name: string;
    installationEpoch: number;
    schemaGeneration: string;
  };
}

interface AuthorizationCodeRecord {
  clientId: string;
  params: AuthorizationParams;
  expiresAtMs: number;
}

const CODE_TTL_MS = 5 * 60 * 1000;

function randomToken(): string {
  return randomBytes(32).toString("base64url");
}

function safeEquals(a: string, b: string): boolean {
  const left = Buffer.from(a);
  const right = Buffer.from(b);
  if (left.byteLength !== right.byteLength) return false;
  return timingSafeEqual(left, right);
}

function htmlEscape(value: string): string {
  return value
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}

function formHtml(params: {
  error?: string;
  clientName: string;
  scopes: string[];
  resource?: URL;
  fields: Record<string, string | undefined>;
}): string {
  const scopeText = params.scopes.length > 0 ? params.scopes.join(" ") : "No tool scope requested";
  const resourceText = params.resource?.href ?? "DevSpace MCP endpoint";
  const error = params.error
    ? `<p class="error">${htmlEscape(params.error)}</p>`
    : "";
  const hiddenFields = Object.entries(params.fields)
    .filter((entry): entry is [string, string] => entry[1] !== undefined)
    .map(([name, value]) => `        <input type="hidden" name="${htmlEscape(name)}" value="${htmlEscape(value)}" />`)
    .join("\n");

  return `<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <title>Connect DevSpace</title>
    <style>
      body { font-family: system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; margin: 0; background: #0f172a; color: #e2e8f0; }
      main { max-width: 440px; margin: 12vh auto; padding: 32px; background: #111827; border: 1px solid #334155; border-radius: 18px; box-shadow: 0 24px 80px rgba(0,0,0,.35); }
      h1 { margin: 0 0 12px; font-size: 28px; }
      p { line-height: 1.5; color: #cbd5e1; }
      dl { padding: 16px; background: #020617; border-radius: 12px; }
      dt { color: #94a3b8; font-size: 12px; text-transform: uppercase; letter-spacing: .06em; }
      dd { margin: 4px 0 12px; word-break: break-word; }
      label { display: block; margin: 18px 0 8px; font-weight: 600; }
      input { box-sizing: border-box; width: 100%; padding: 12px 14px; border-radius: 10px; border: 1px solid #475569; background: #020617; color: #e2e8f0; font-size: 16px; }
      button { margin-top: 18px; width: 100%; border: 0; border-radius: 10px; padding: 12px 14px; font-weight: 700; color: #020617; background: #38bdf8; cursor: pointer; }
      .error { color: #fecaca; background: #7f1d1d; border-radius: 10px; padding: 10px 12px; }
      .warning { color: #fde68a; }
    </style>
  </head>
  <body>
    <main>
      <h1>Connect DevSpace</h1>
      <p class="warning">Only approve this if you are intentionally connecting your own ChatGPT or MCP client to this local machine.</p>
      ${error}
      <dl>
        <dt>Client</dt><dd>${htmlEscape(params.clientName)}</dd>
        <dt>Scope</dt><dd>${htmlEscape(scopeText)}</dd>
        <dt>Resource</dt><dd>${htmlEscape(resourceText)}</dd>
      </dl>
      <form method="post">
${hiddenFields}
        <label for="owner_token">Owner password</label>
        <input id="owner_token" name="owner_token" type="password" autocomplete="current-password" autofocus required />
        <button type="submit">Authorize DevSpace</button>
      </form>
    </main>
  </body>
</html>`;
}

function requestedScopesAllowed(requested: string[], supported: string[]): boolean {
  return requested.every((scope) => supported.includes(scope));
}

export class SingleUserOAuthProvider implements OAuthServerProvider {
  readonly clientsStore: OAuthRegisteredClientsStore;
  private readonly codes = new Map<string, AuthorizationCodeRecord>();
  private readonly oauthStore: SqliteOAuthStore;
  private readonly resourceServerUrl: URL;
  private readonly canonicalConnector: OAuthConfig["canonicalConnector"];

  constructor(
    private readonly config: OAuthConfig,
    resourceServerUrl: URL,
    stateDir: string,
    metrics?: UniversalBrokerMetrics,
  ) {
    this.resourceServerUrl = resourceUrlFromServerUrl(resourceServerUrl);
    this.canonicalConnector = config.canonicalConnector ?? canonicalConnectorFromEnvironment(process.env);
    if (this.canonicalConnector) validateCanonicalConnector(this.canonicalConnector);
    this.oauthStore = new SqliteOAuthStore(stateDir, metrics);
    this.clientsStore = new SqliteOAuthClientsStore(
      this.oauthStore,
      config.allowedRedirectHosts,
      this.canonicalConnector
        ? {
            canonicalName: this.canonicalConnector.name,
            installationEpoch: this.canonicalConnector.installationEpoch,
            schemaGeneration: this.canonicalConnector.schemaGeneration,
          }
        : undefined,
    );
  }

  async authorize(
    client: OAuthClientInformationFull,
    params: AuthorizationParams,
    res: Response,
  ): Promise<void> {
    if (!params.resource || !checkResourceAllowed({ requestedResource: params.resource, configuredResource: this.resourceServerUrl })) {
      throw new InvalidRequestError("Invalid or missing OAuth resource");
    }
    if (!requestedScopesAllowed(params.scopes ?? [], this.config.scopes)) {
      throw new InvalidRequestError("Requested scope is not supported");
    }
    if (this.canonicalConnector
      && !this.oauthStore.connectorCanIssueAuthorizationCode(this.canonicalConnector.name, client.client_id)) {
      throw new AccessDeniedError("Connector binding cannot issue a new authorization code while draining or retired");
    }

    if (res.req.method !== "POST") {
      res.status(200).setHeader("Content-Type", "text/html; charset=utf-8");
      res.send(
        formHtml({
          clientName: client.client_name ?? client.client_id,
          scopes: params.scopes ?? this.config.scopes,
          resource: params.resource,
          fields: authorizationFormFields(client, params),
        }),
      );
      return;
    }

    const providedToken = String(res.req.body?.owner_token ?? "");
    if (!safeEquals(providedToken, this.config.ownerToken)) {
      res.status(401).setHeader("Content-Type", "text/html; charset=utf-8");
      res.send(
        formHtml({
          error: "The Owner password was not accepted.",
          clientName: client.client_name ?? client.client_id,
          scopes: params.scopes ?? this.config.scopes,
          resource: params.resource,
          fields: authorizationFormFields(client, params),
        }),
      );
      return;
    }

    const code = `code-${randomUUID()}`;
    this.codes.set(code, {
      clientId: client.client_id,
      params,
      expiresAtMs: Date.now() + CODE_TTL_MS,
    });

    const redirectUrl = new URL(params.redirectUri);
    redirectUrl.searchParams.set("code", code);
    if (params.state !== undefined) redirectUrl.searchParams.set("state", params.state);
    res.redirect(302, redirectUrl.href);
  }

  async challengeForAuthorizationCode(
    client: OAuthClientInformationFull,
    authorizationCode: string,
  ): Promise<string> {
    const record = this.validCodeRecord(client, authorizationCode);
    return record.params.codeChallenge;
  }

  async exchangeAuthorizationCode(
    client: OAuthClientInformationFull,
    authorizationCode: string,
    _codeVerifier?: string,
    redirectUri?: string,
    resource?: URL,
  ): Promise<OAuthTokens> {
    const record = this.validCodeRecord(client, authorizationCode);
    if (redirectUri && redirectUri !== record.params.redirectUri) {
      throw new InvalidGrantError("redirect_uri does not match the authorization request");
    }
    if (resource && !checkResourceAllowed({ requestedResource: resource, configuredResource: this.resourceServerUrl })) {
      throw new InvalidGrantError("Invalid resource");
    }

    this.codes.delete(authorizationCode);
    return this.issueTokens(client.client_id, record.params.scopes ?? this.config.scopes, record.params.resource);
  }

  async exchangeRefreshToken(
    client: OAuthClientInformationFull,
    refreshToken: string,
    scopes?: string[],
    resource?: URL,
  ): Promise<OAuthTokens> {
    const refreshTokenHash = hashToken(refreshToken);
    const record = this.oauthStore.getRefreshToken(refreshTokenHash);
    if (!record || record.clientId !== client.client_id || record.expiresAt < Math.floor(Date.now() / 1000)) {
      throw new InvalidGrantError("Invalid refresh token");
    }
    if (this.canonicalConnector && !record.connectorBindingId) {
      throw new InvalidGrantError("Refresh token is not bound to a connector candidate or ACTIVE binding");
    }
    if (!this.oauthStore.refreshTokenBindingIsCurrent(record)) {
      throw new InvalidGrantError("Refresh token belongs to a stale connector binding or token family");
    }
    if (resource && !checkResourceAllowed({ requestedResource: resource, configuredResource: this.resourceServerUrl })) {
      throw new InvalidGrantError("Invalid resource");
    }

    const requestedScopes = scopes ?? record.scopes;
    if (!requestedScopes.every((scope) => record.scopes.includes(scope))) {
      throw new AccessDeniedError("Refresh token cannot grant requested scopes");
    }

    return this.issueTokens(
      client.client_id,
      requestedScopes,
      resource ?? (record.resource ? new URL(record.resource) : undefined),
      { hash: refreshTokenHash, record },
    );
  }

  async verifyAccessToken(token: string): Promise<AuthInfo> {
    const record = this.oauthStore.getAccessToken(hashToken(token));
    if (!record || record.expiresAt < Math.floor(Date.now() / 1000)) {
      throw new InvalidTokenError("Invalid or expired access token");
    }
    if (this.canonicalConnector && !record.connectorBindingId) {
      throw new InvalidTokenError("Access token is not bound to a connector candidate or ACTIVE binding");
    }
    if (!this.oauthStore.accessTokenBindingIsCurrent(record)) {
      throw new InvalidTokenError("Access token belongs to a stale connector binding or token family");
    }
    const connectorBinding = record.connectorBindingId
      ? this.oauthStore.getConnectorBinding(record.connectorBindingId)
      : undefined;
    const connectorContext: ConnectorAuthenticationContext | undefined = connectorBinding
      ? {
          bindingId: connectorBinding.bindingId,
          canonicalName: connectorBinding.canonicalName,
          state: connectorBinding.state,
          installationEpoch: connectorBinding.installationEpoch,
          rotationSequence: record.rotationSequence ?? 0,
          schemaGeneration: connectorBinding.schemaGeneration,
          buildDigest: connectorBinding.buildDigest,
          drainDeadlineAt: connectorBinding.drainDeadlineAt,
          activationRequired: !["ACTIVE", "DRAINING"].includes(connectorBinding.state),
        }
      : undefined;

    return {
      token,
      clientId: record.clientId,
      scopes: record.scopes,
      expiresAt: record.expiresAt,
      resource: record.resource ? new URL(record.resource) : undefined,
      extra: connectorContext ? { devspaceConnector: connectorContext } : undefined,
    };
  }

  async revokeToken(_client: OAuthClientInformationFull, request: OAuthTokenRevocationRequest): Promise<void> {
    const hashed = hashToken(request.token);
    this.oauthStore.deleteAccessToken(hashed);
    this.oauthStore.deleteRefreshToken(hashed);
  }

  connectorReadiness(canonicalName = this.canonicalConnector?.name, nowMs = Date.now()): ConnectorReadinessSummary {
    return this.oauthStore.connectorReadiness(canonicalName, nowMs);
  }

  personalConnectorReadiness(nowMs = Date.now()): PersonalConnectorReadinessSummary {
    return this.oauthStore.personalConnectorReadiness(
      this.canonicalConnector
        ? {
            canonicalName: this.canonicalConnector.name,
            installationEpoch: this.canonicalConnector.installationEpoch,
            schemaGeneration: this.canonicalConnector.schemaGeneration,
            resource: this.resourceServerUrl.href,
          }
        : undefined,
      nowMs,
    );
  }

  activeConnectorBinding(canonicalName = this.canonicalConnector?.name): ConnectorBindingRecord | undefined {
    return canonicalName ? this.oauthStore.getActiveConnectorBinding(canonicalName) : undefined;
  }

  close(): void {
    this.oauthStore.close();
  }

  private validCodeRecord(
    client: OAuthClientInformationFull,
    authorizationCode: string,
  ): AuthorizationCodeRecord {
    const record = this.codes.get(authorizationCode);
    if (!record || record.clientId !== client.client_id || record.expiresAtMs < Date.now()) {
      throw new InvalidGrantError("Invalid authorization code");
    }
    return record;
  }

  private issueTokens(
    clientId: string,
    scopes: string[],
    resource?: URL,
    consumed?: { hash: string; record: PersistedRefreshTokenRecord },
  ): OAuthTokens {
    const now = Math.floor(Date.now() / 1000);
    const accessToken = randomToken();
    const refreshToken = randomToken();
    const accessExpiresAt = now + this.config.accessTokenTtlSeconds;
    const refreshExpiresAt = now + this.config.refreshTokenTtlSeconds;
    let connectorBinding: ConnectorBindingRecord | undefined;
    try {
      const registeredBinding = this.canonicalConnector
        ? this.oauthStore.getConnectorBindingForClient(this.canonicalConnector.name, clientId)
        : undefined;
      connectorBinding = consumed?.record.connectorBindingId
        ? undefined
        : this.canonicalConnector
          ? this.oauthStore.ensureCandidateConnectorBinding({
              canonicalName: this.canonicalConnector.name,
              clientId,
              installationEpoch: registeredBinding?.installationEpoch ?? this.canonicalConnector.installationEpoch,
              schemaGeneration: registeredBinding?.schemaGeneration ?? this.canonicalConnector.schemaGeneration,
            })
          : undefined;
    } catch (error) {
      if (error instanceof ConnectorStateConflictError) {
        throw new InvalidGrantError("Connector binding is not eligible for a new token family");
      }
      throw error;
    }
    const binding = {
      familyId: consumed?.record.familyId ?? `family-${randomUUID()}`,
      connectorBindingId: consumed?.record.connectorBindingId ?? connectorBinding?.bindingId,
      connectorDrainEpoch: consumed?.record.connectorDrainEpoch ?? connectorBinding?.drainEpoch,
      installationEpoch: consumed?.record.installationEpoch ?? connectorBinding?.installationEpoch,
      rotationSequence: (consumed?.record.rotationSequence ?? -1) + 1,
    };

    const saved = this.oauthStore.saveTokenPair(
      {
        accessTokenHash: hashToken(accessToken),
        accessToken: {
          clientId,
          scopes,
          expiresAt: accessExpiresAt,
          resource: resource?.href,
          ...binding,
        },
        refreshTokenHash: hashToken(refreshToken),
        refreshToken: {
          clientId,
          scopes,
          expiresAt: refreshExpiresAt,
          resource: resource?.href,
          ...binding,
        },
      },
      consumed?.hash,
    );
    if (!saved) {
      throw new InvalidGrantError("Invalid refresh token");
    }

    return {
      access_token: accessToken,
      token_type: "bearer",
      expires_in: this.config.accessTokenTtlSeconds,
      refresh_token: refreshToken,
      scope: scopes.join(" "),
    };
  }
}

function authorizationFormFields(
  client: OAuthClientInformationFull,
  params: AuthorizationParams,
): Record<string, string | undefined> {
  return {
    response_type: "code",
    client_id: client.client_id,
    redirect_uri: params.redirectUri,
    code_challenge: params.codeChallenge,
    code_challenge_method: "S256",
    scope: params.scopes?.join(" "),
    state: params.state,
    resource: params.resource?.href,
  };
}

function hashToken(token: string): string {
  return createHash("sha256").update(token).digest("base64url");
}

function canonicalConnectorFromEnvironment(env: NodeJS.ProcessEnv): OAuthConfig["canonicalConnector"] {
  const name = env.DEVSPACE_OAUTH_CANONICAL_CONNECTOR_NAME ?? env.DEVSPACE_NEXT_CANONICAL_CONNECTOR_NAME;
  const epoch = env.DEVSPACE_OAUTH_CONNECTOR_INSTALLATION_EPOCH;
  const schemaGeneration = env.DEVSPACE_EXPECTED_SCHEMA_GENERATION;
  if (!name) return undefined;
  if (!epoch || !schemaGeneration) {
    throw new Error("Canonical connector binding requires name, installation epoch, and schema generation together.");
  }
  const connector = { name, installationEpoch: Number(epoch), schemaGeneration };
  validateCanonicalConnector(connector);
  return connector;
}

function validateCanonicalConnector(connector: NonNullable<OAuthConfig["canonicalConnector"]>): void {
  if (!Number.isInteger(connector.installationEpoch) || connector.installationEpoch < 1) {
    throw new Error("DEVSPACE_OAUTH_CONNECTOR_INSTALLATION_EPOCH must be a positive integer.");
  }
  if (!/^[A-Za-z][A-Za-z0-9._-]{0,127}$/u.test(connector.name)) {
    throw new Error("DEVSPACE_OAUTH_CANONICAL_CONNECTOR_NAME is invalid.");
  }
  if (!/^sha256:[a-f0-9]{64}$/u.test(connector.schemaGeneration)) {
    throw new Error("DEVSPACE_EXPECTED_SCHEMA_GENERATION is invalid for OAuth connector binding.");
  }
}
