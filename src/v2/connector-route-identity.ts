import type { RuntimeIdentity } from "./contracts.js";
import { digest } from "./runtime-identity.js";

export const CONNECTOR_ROUTE_IDENTITY_SCHEMA_VERSION = 1;

export type ConnectorEnvironmentRole = "STAGING" | "PRODUCTION";

export interface ConnectorEnvironmentIdentityInput {
  environmentRole: ConnectorEnvironmentRole;
  runtimeIdentityDigest: string;
  oauthResource: string;
}

export interface ConnectorRouteIdentityInput {
  oauthResource: string;
  canonicalName: string;
  bindingId: string;
}

export interface ConnectorProductionRouteIdentityReadback {
  schemaVersion: typeof CONNECTOR_ROUTE_IDENTITY_SCHEMA_VERSION;
  state: "ACTIVE";
  routeCount: 1;
  canonicalName: string;
  bindingId: string;
  runtimeIdentityDigest: string;
  productionEnvironmentIdentityDigest: string;
  productionRouteIdentityDigest: string;
}

const DIGEST_PATTERN = /^sha256:[a-f0-9]{64}$/u;
const BOUNDED_IDENTITY_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._:@/-]{0,511}$/u;

/** Digest the complete runtime identity returned by private readiness. */
export function connectorRuntimeIdentityDigest(identity: RuntimeIdentity): string {
  return digest(identity);
}

/** Bind a release environment to one runtime identity and one OAuth resource. */
export function connectorEnvironmentIdentityDigest(input: ConnectorEnvironmentIdentityInput): string {
  const environmentRole = requiredEnvironmentRole(input.environmentRole);
  const runtimeIdentityDigest = requiredDigest(input.runtimeIdentityDigest, "runtime identity");
  const oauthResource = canonicalOAuthResource(input.oauthResource);
  return digest({
    schema: "devspace.connector_environment_identity",
    schemaVersion: CONNECTOR_ROUTE_IDENTITY_SCHEMA_VERSION,
    environmentRole,
    runtimeIdentityDigest,
    oauthResource,
  });
}

/** Bind the canonical connector to the exact externally configured OAuth route. */
export function connectorRouteIdentityDigest(input: ConnectorRouteIdentityInput): string {
  const oauthResource = canonicalOAuthResource(input.oauthResource);
  const canonicalName = requiredIdentity(input.canonicalName, "canonical connector name");
  const bindingId = requiredIdentity(input.bindingId, "connector binding id");
  return digest({
    schema: "devspace.connector_route_identity",
    schemaVersion: CONNECTOR_ROUTE_IDENTITY_SCHEMA_VERSION,
    oauthResource,
    canonicalName,
    bindingId,
  });
}

export function connectorProductionRouteIdentityReadback(input: {
  runtimeIdentity: RuntimeIdentity;
  oauthResource: string;
  canonicalName: string;
  bindingId: string;
}): ConnectorProductionRouteIdentityReadback {
  const runtimeIdentityDigest = connectorRuntimeIdentityDigest(input.runtimeIdentity);
  return Object.freeze({
    schemaVersion: CONNECTOR_ROUTE_IDENTITY_SCHEMA_VERSION,
    state: "ACTIVE",
    routeCount: 1,
    canonicalName: requiredIdentity(input.canonicalName, "canonical connector name"),
    bindingId: requiredIdentity(input.bindingId, "connector binding id"),
    runtimeIdentityDigest,
    productionEnvironmentIdentityDigest: connectorEnvironmentIdentityDigest({
      environmentRole: "PRODUCTION",
      runtimeIdentityDigest,
      oauthResource: input.oauthResource,
    }),
    productionRouteIdentityDigest: connectorRouteIdentityDigest({
      oauthResource: input.oauthResource,
      canonicalName: input.canonicalName,
      bindingId: input.bindingId,
    }),
  });
}

function requiredEnvironmentRole(value: unknown): ConnectorEnvironmentRole {
  if (value !== "STAGING" && value !== "PRODUCTION") {
    throw new Error("Connector environment role must be STAGING or PRODUCTION.");
  }
  return value;
}

function requiredDigest(value: unknown, label: string): string {
  if (typeof value !== "string" || !DIGEST_PATTERN.test(value)) {
    throw new Error(`Connector ${label} must be a SHA-256 digest.`);
  }
  return value;
}

function requiredIdentity(value: unknown, label: string): string {
  if (typeof value !== "string" || !BOUNDED_IDENTITY_PATTERN.test(value)) {
    throw new Error(`Connector ${label} is invalid.`);
  }
  return value;
}

function canonicalOAuthResource(value: unknown): string {
  if (typeof value !== "string" || value.length > 2_048) {
    throw new Error("Connector OAuth resource is invalid.");
  }
  const parsed = new URL(value);
  const loopback = parsed.hostname === "127.0.0.1"
    || parsed.hostname === "localhost"
    || parsed.hostname === "[::1]"
    || parsed.hostname === "::1";
  if ((parsed.protocol !== "https:" && !(parsed.protocol === "http:" && loopback))
    || parsed.username || parsed.password || parsed.hash) {
    throw new Error("Connector OAuth resource must use HTTPS or loopback HTTP without credentials or fragments.");
  }
  return parsed.href;
}
