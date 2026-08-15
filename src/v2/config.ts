import { dirname, join, resolve } from "node:path";
import type { ServerConfig } from "../config.js";
import type { LoggingConfig } from "../logger.js";
import type { OAuthConfig } from "../oauth-provider.js";
import { expandHomePath } from "../roots.js";
import { UNIVERSAL_OWNER_SCOPES } from "./contracts.js";

const DEFAULT_NEXT_ENDPOINT_PATH = "/mcp-next";
const DEFAULT_NEXT_SESSION_IDLE_TIMEOUT_MS = 90_000;
const DEFAULT_NEXT_SESSION_CLEANUP_INTERVAL_MS = 15_000;

export interface UniversalBrokerNextConfig {
  serverConfig: ServerConfig;
  host: string;
  port: number;
  publicBaseUrl: string;
  endpointPath: string;
  stateDir: string;
  targetConfigPath: string;
  mcpRouteConfigPath: string;
  contextStorePath: string;
  allowedHosts: string[];
  oauth: OAuthConfig;
  logging: LoggingConfig;
  mcpSessionIdleTimeoutMs: number;
  mcpSessionCleanupIntervalMs: number;
}

export function loadUniversalBrokerNextConfig(
  base: ServerConfig,
  env: NodeJS.ProcessEnv = process.env,
): UniversalBrokerNextConfig {
  const host = env.DEVSPACE_NEXT_HOST?.trim() || base.host;
  const port = parsePort(
    env.DEVSPACE_NEXT_PORT,
    base.port < 65_535 ? base.port + 1 : 7_677,
  );
  const publicBaseUrl = normalizePublicBaseUrl(
    env.DEVSPACE_NEXT_PUBLIC_BASE_URL ?? localBaseUrl(host, port),
  );
  const endpointPath = normalizeEndpointPath(
    env.DEVSPACE_NEXT_MCP_PATH ?? DEFAULT_NEXT_ENDPOINT_PATH,
  );
  const publicUrl = new URL(publicBaseUrl);
  const configuredAllowedHosts = parseStringList(env.DEVSPACE_NEXT_ALLOWED_HOSTS);
  const allowedHosts = configuredAllowedHosts.length > 0
    ? configuredAllowedHosts
    : Array.from(new Set([
        host,
        publicUrl.hostname,
        publicUrl.host,
        ...base.allowedHosts,
      ].filter(Boolean)));

  const stateDir = resolve(expandHomePath(
    env.DEVSPACE_NEXT_STATE_DIR
      ?? join(base.stateDir, "universal-broker-v2"),
  ));
  if (stateDir === resolve(base.stateDir)) {
    throw new Error("DEVSPACE_NEXT_STATE_DIR must be separate from the production state directory.");
  }
  if (publicBaseUrl === new URL(base.publicBaseUrl).origin) {
    throw new Error("DEVSPACE_NEXT_PUBLIC_BASE_URL must use a separate origin during parallel development.");
  }
  const configDir = env.DEVSPACE_CONFIG_DIR
    ? resolve(expandHomePath(env.DEVSPACE_CONFIG_DIR))
    : dirname(base.devspaceSkillsDir);

  return {
    serverConfig: base,
    host,
    port,
    publicBaseUrl,
    endpointPath,
    stateDir,
    targetConfigPath: resolve(expandHomePath(
      env.DEVSPACE_NEXT_TARGETS_FILE ?? join(configDir, "targets.v2.json"),
    )),
    mcpRouteConfigPath: resolve(expandHomePath(
      env.DEVSPACE_NEXT_MCP_ROUTES_FILE ?? join(configDir, "mcp-routes.v2.json"),
    )),
    contextStorePath: resolve(expandHomePath(
      env.DEVSPACE_NEXT_CONTEXT_STORE
        ?? join(stateDir, "contexts.json"),
    )),
    allowedHosts,
    oauth: {
      ownerToken: base.oauth.ownerToken,
      accessTokenTtlSeconds: base.oauth.accessTokenTtlSeconds,
      refreshTokenTtlSeconds: base.oauth.refreshTokenTtlSeconds,
      scopes: [...UNIVERSAL_OWNER_SCOPES],
      allowedRedirectHosts: base.oauth.allowedRedirectHosts,
    },
    logging: base.logging,
    mcpSessionIdleTimeoutMs: parsePositiveInteger(
      env.DEVSPACE_NEXT_MCP_SESSION_IDLE_TIMEOUT_MS,
      DEFAULT_NEXT_SESSION_IDLE_TIMEOUT_MS,
      "DEVSPACE_NEXT_MCP_SESSION_IDLE_TIMEOUT_MS",
    ),
    mcpSessionCleanupIntervalMs: parsePositiveInteger(
      env.DEVSPACE_NEXT_MCP_SESSION_CLEANUP_INTERVAL_MS,
      DEFAULT_NEXT_SESSION_CLEANUP_INTERVAL_MS,
      "DEVSPACE_NEXT_MCP_SESSION_CLEANUP_INTERVAL_MS",
    ),
  };
}

function parsePort(value: string | undefined, fallback: number): number {
  const parsed = value === undefined ? fallback : Number(value);
  if (!Number.isInteger(parsed) || parsed < 1 || parsed > 65_535) {
    throw new Error(`Invalid DEVSPACE_NEXT_PORT: ${value ?? String(fallback)}`);
  }
  return parsed;
}

function parsePositiveInteger(
  value: string | undefined,
  fallback: number,
  name: string,
): number {
  const parsed = value === undefined ? fallback : Number(value);
  if (!Number.isInteger(parsed) || parsed < 1) {
    throw new Error(`Invalid ${name}: ${value ?? String(fallback)}`);
  }
  return parsed;
}

function normalizePublicBaseUrl(value: string): string {
  const url = new URL(value);
  if (!["http:", "https:"].includes(url.protocol)) {
    throw new Error("DEVSPACE_NEXT_PUBLIC_BASE_URL must use HTTP or HTTPS.");
  }
  if (url.pathname !== "/" || url.search || url.hash) {
    throw new Error("DEVSPACE_NEXT_PUBLIC_BASE_URL must be an origin without a path, query, or fragment.");
  }
  return url.origin;
}

function normalizeEndpointPath(value: string): string {
  const trimmed = value.trim();
  if (!trimmed.startsWith("/") || trimmed.includes("?") || trimmed.includes("#")) {
    throw new Error(`Invalid DEVSPACE_NEXT_MCP_PATH: ${value}`);
  }
  const normalized = trimmed.length > 1 ? trimmed.replace(/\/+$/, "") : trimmed;
  const reserved = new Set([
    "/",
    "/mcp",
    "/authorize",
    "/token",
    "/register",
    "/revoke",
    "/healthz-next",
  ]);
  if (reserved.has(normalized) || normalized.startsWith("/.well-known/")) {
    throw new Error(`DEVSPACE_NEXT_MCP_PATH conflicts with a reserved endpoint: ${normalized}`);
  }
  return normalized;
}

function localBaseUrl(host: string, port: number): string {
  const publicHost = ["0.0.0.0", "::", "[::]"].includes(host) ? "127.0.0.1" : host;
  const formattedHost = publicHost.includes(":") && !publicHost.startsWith("[")
    ? `[${publicHost}]`
    : publicHost;
  return `http://${formattedHost}:${port}`;
}

function parseStringList(value: string | undefined): string[] {
  if (!value) return [];
  return Array.from(new Set(
    value
      .split(",")
      .map((entry) => entry.trim())
      .filter(Boolean),
  ));
}
