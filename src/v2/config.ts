import { homedir } from "node:os";
import { dirname, join, resolve } from "node:path";
import type { ServerConfig } from "../config.js";
import type { LoggingConfig } from "../logger.js";
import type { OAuthConfig } from "../oauth-provider.js";
import { expandHomePath } from "../roots.js";
import { UNIVERSAL_OWNER_SCOPES } from "./contracts.js";

const DEFAULT_NEXT_ENDPOINT_PATH = "/mcp-next";
const DEFAULT_NEXT_SESSION_IDLE_TIMEOUT_MS = 90_000;
const DEFAULT_NEXT_SESSION_CLEANUP_INTERVAL_MS = 15_000;
const DEFAULT_NEXT_MAXIMUM_MCP_SESSIONS = 128;
const DEFAULT_CONTEXT_MAXIMUM_ENTRIES = 256;
const DEFAULT_CONTEXT_IDLE_TTL_MS = 30 * 60_000;
const DEFAULT_CONTEXT_MAXIMUM_WORKTREES = 8;
const DEFAULT_CONTEXT_MAXIMUM_WORKTREE_BYTES = 8 * 1024 * 1024 * 1024;
const DEFAULT_CONTEXT_DIFF_MAXIMUM_ENTRIES = 64;
const DEFAULT_CONTEXT_DIFF_MAXIMUM_CHARACTERS = 50_000_000;
const DEFAULT_CONTEXT_DIFF_TTL_MS = 15 * 60_000;
const DEFAULT_MAX_RUNNING_PROCESSES = 32;
const DEFAULT_MAX_RUNNING_PROCESSES_PER_TARGET = 16;
const DEFAULT_PROCESS_BUFFER_CHARACTERS = 1_000_000;
const DEFAULT_PROCESS_OUTPUT_MAX_BYTES = 100 * 1024 * 1024;
const DEFAULT_COMPLETED_PROCESS_TTL_MS = 15 * 60 * 1_000;
const DEFAULT_ARTIFACT_MAXIMUM_ENTRIES = 64;
const DEFAULT_ARTIFACT_MAXIMUM_TOTAL_BYTES = 2 * 1024 * 1024 * 1024;
const DEFAULT_ARTIFACT_MAXIMUM_FILE_BYTES = 1024 * 1024 * 1024;
const DEFAULT_ARTIFACT_TTL_MS = 15 * 60 * 1_000;
const DEFAULT_GUI_MAXIMUM_SESSIONS = 32;
const DEFAULT_GUI_SESSION_TTL_MS = 5 * 60 * 1_000;
const DEFAULT_GUI_PAYLOAD_BUDGET_CHARACTERS = 12_000;
const DEFAULT_DOWNSTREAM_MCP_MAXIMUM_SESSIONS = 16;
const DEFAULT_DOWNSTREAM_MCP_SESSION_IDLE_TTL_MS = 5 * 60_000;
const DEFAULT_MCP_RESULT_MAXIMUM_ENTRIES = 64;
const DEFAULT_MCP_RESULT_MAXIMUM_CHARACTERS = 10_000_000;
const DEFAULT_MCP_RESULT_TTL_MS = 15 * 60_000;

export type UniversalBrokerDeploymentMode = "parallel" | "production";

export interface UniversalBrokerNextConfig {
  serverConfig: ServerConfig;
  deploymentMode: UniversalBrokerDeploymentMode;
  host: string;
  port: number;
  publicBaseUrl: string;
  publicMcpUrl: string;
  endpointPath: string;
  healthPath: string;
  metricsPath: string;
  artifactPathPrefix: string;
  stateDir: string;
  oauthStateDir: string;
  legacyScopeCompatibility: boolean;
  targetConfigPath: string;
  mcpRouteConfigPath: string;
  contextStorePath: string;
  envProfileConfigPath: string;
  contextIdleTtlMs: number;
  contextWorktreeRoot: string;
  contextMaximumEntries: number;
  contextMaximumWorktrees: number;
  contextMaximumWorktreeBytes: number;
  contextDiffMaximumEntries: number;
  contextDiffMaximumCharacters: number;
  contextDiffTtlMs: number;
  processOutputDir: string;
  sshControlDir: string;
  maxRunningProcesses: number;
  maxRunningProcessesPerTarget: number;
  processBufferCharacters: number;
  processOutputMaxBytes: number;
  completedProcessTtlMs: number;
  artifactStagingDir: string;
  artifactMaximumEntries: number;
  artifactMaximumTotalBytes: number;
  artifactMaximumFileBytes: number;
  artifactTtlMs: number;
  guiMaximumSessions: number;
  guiSessionTtlMs: number;
  guiPayloadBudgetCharacters: number;
  downstreamMcpMaximumSessions: number;
  downstreamMcpSessionIdleTtlMs: number;
  mcpResultMaximumEntries: number;
  mcpResultMaximumCharacters: number;
  mcpResultTtlMs: number;
  allowedHosts: string[];
  oauth: OAuthConfig;
  logging: LoggingConfig;
  mcpSessionIdleTimeoutMs: number;
  mcpSessionCleanupIntervalMs: number;
  maximumMcpSessions: number;
}

export function loadUniversalBrokerNextConfig(
  base: ServerConfig,
  env: NodeJS.ProcessEnv = process.env,
): UniversalBrokerNextConfig {
  const deploymentMode = parseDeploymentMode(env.DEVSPACE_V2_DEPLOYMENT_MODE);
  const host = env.DEVSPACE_NEXT_HOST?.trim() || base.host;
  const port = parsePort(
    env.DEVSPACE_NEXT_PORT,
    deploymentMode === "production"
      ? base.port
      : base.port < 65_535 ? base.port + 1 : 7_677,
  );
  const publicBaseUrl = normalizePublicBaseUrl(
    env.DEVSPACE_NEXT_PUBLIC_BASE_URL
      ?? (deploymentMode === "production" ? base.publicBaseUrl : localBaseUrl(host, port)),
  );
  const endpointPath = normalizeEndpointPath(
    env.DEVSPACE_NEXT_MCP_PATH
      ?? (deploymentMode === "production" ? "/mcp" : DEFAULT_NEXT_ENDPOINT_PATH),
    deploymentMode,
  );
  const healthPath = deploymentMode === "production" ? "/healthz" : "/healthz-next";
  const metricsPath = deploymentMode === "production" ? "/metrics" : "/metrics-next";
  const artifactPathPrefix = deploymentMode === "production" ? "/artifacts" : "/artifacts-next";
  const publicMcpUrl = joinPublicUrl(publicBaseUrl, endpointPath);
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
      ?? join(
        base.stateDir,
        deploymentMode === "production"
          ? "universal-broker-v2-production"
          : "universal-broker-v2",
      ),
  ));
  if (stateDir === resolve(base.stateDir)) {
    throw new Error("DEVSPACE_NEXT_STATE_DIR must be separate from the production state directory.");
  }
  const oauthStateDir = deploymentMode === "production"
    ? resolve(base.stateDir)
    : stateDir;
  const legacyScopeCompatibility = parseBoolean(
    env.DEVSPACE_V2_LEGACY_SCOPE_COMPATIBILITY,
    deploymentMode === "production",
    "DEVSPACE_V2_LEGACY_SCOPE_COMPATIBILITY",
  );
  if (deploymentMode !== "production" && legacyScopeCompatibility) {
    throw new Error("Legacy devspace scope compatibility is available only in production deployment mode.");
  }
  const productionMcpUrl = new URL("/mcp", base.publicBaseUrl).href;
  if (deploymentMode === "parallel" && publicMcpUrl === productionMcpUrl) {
    throw new Error("Universal Broker v2 public MCP URL must differ from production /mcp during parallel development.");
  }
  if (deploymentMode === "production" && publicMcpUrl !== productionMcpUrl) {
    throw new Error("Universal Broker v2 production mode must use the canonical production /mcp URL.");
  }
  const configDir = env.DEVSPACE_CONFIG_DIR
    ? resolve(expandHomePath(env.DEVSPACE_CONFIG_DIR))
    : dirname(base.devspaceSkillsDir);

  return {
    serverConfig: base,
    deploymentMode,
    host,
    port,
    publicBaseUrl,
    publicMcpUrl,
    endpointPath,
    healthPath,
    metricsPath,
    artifactPathPrefix,
    stateDir,
    oauthStateDir,
    legacyScopeCompatibility,
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
    envProfileConfigPath: resolve(expandHomePath(
      env.DEVSPACE_NEXT_ENV_PROFILE_CONFIG
        ?? `${homedir()}/.devspace/env-profiles.v2.json`,
    )),
    contextIdleTtlMs: parseBoundedPositiveInteger(
      env.DEVSPACE_NEXT_CONTEXT_IDLE_TTL_MS,
      DEFAULT_CONTEXT_IDLE_TTL_MS,
      "DEVSPACE_NEXT_CONTEXT_IDLE_TTL_MS",
      24 * 60 * 60_000,
    ),
    contextWorktreeRoot: resolve(expandHomePath(
      env.DEVSPACE_NEXT_CONTEXT_WORKTREE_ROOT
        ?? join(stateDir, "worktrees"),
    )),
    contextMaximumEntries: parseBoundedPositiveInteger(
      env.DEVSPACE_NEXT_CONTEXT_MAXIMUM_ENTRIES,
      DEFAULT_CONTEXT_MAXIMUM_ENTRIES,
      "DEVSPACE_NEXT_CONTEXT_MAXIMUM_ENTRIES",
      10_000,
    ),
    contextMaximumWorktrees: parseBoundedPositiveInteger(
      env.DEVSPACE_NEXT_CONTEXT_MAXIMUM_WORKTREES,
      DEFAULT_CONTEXT_MAXIMUM_WORKTREES,
      "DEVSPACE_NEXT_CONTEXT_MAXIMUM_WORKTREES",
      1_000,
    ),
    contextMaximumWorktreeBytes: parseBoundedPositiveInteger(
      env.DEVSPACE_NEXT_CONTEXT_MAXIMUM_WORKTREE_BYTES,
      DEFAULT_CONTEXT_MAXIMUM_WORKTREE_BYTES,
      "DEVSPACE_NEXT_CONTEXT_MAXIMUM_WORKTREE_BYTES",
      1024 * 1024 * 1024 * 1024,
    ),
    contextDiffMaximumEntries: parseBoundedPositiveInteger(
      env.DEVSPACE_NEXT_CONTEXT_DIFF_MAXIMUM_ENTRIES,
      DEFAULT_CONTEXT_DIFF_MAXIMUM_ENTRIES,
      "DEVSPACE_NEXT_CONTEXT_DIFF_MAXIMUM_ENTRIES",
      10_000,
    ),
    contextDiffMaximumCharacters: parseBoundedPositiveInteger(
      env.DEVSPACE_NEXT_CONTEXT_DIFF_MAXIMUM_CHARACTERS,
      DEFAULT_CONTEXT_DIFF_MAXIMUM_CHARACTERS,
      "DEVSPACE_NEXT_CONTEXT_DIFF_MAXIMUM_CHARACTERS",
      1_000_000_000,
    ),
    contextDiffTtlMs: parseBoundedPositiveInteger(
      env.DEVSPACE_NEXT_CONTEXT_DIFF_TTL_MS,
      DEFAULT_CONTEXT_DIFF_TTL_MS,
      "DEVSPACE_NEXT_CONTEXT_DIFF_TTL_MS",
      24 * 60 * 60_000,
    ),
    processOutputDir: resolve(expandHomePath(
      env.DEVSPACE_NEXT_PROCESS_OUTPUT_DIR
        ?? join(stateDir, "process-output"),
    )),
    sshControlDir: resolve(expandHomePath(
      env.DEVSPACE_NEXT_SSH_CONTROL_DIR
        ?? join(process.env.HOME ?? "~", ".devspace", "run", "v2-ssh"),
    )),
    maxRunningProcesses: parseBoundedPositiveInteger(
      env.DEVSPACE_NEXT_MAX_RUNNING_PROCESSES,
      DEFAULT_MAX_RUNNING_PROCESSES,
      "DEVSPACE_NEXT_MAX_RUNNING_PROCESSES",
      1_024,
    ),
    maxRunningProcessesPerTarget: parseBoundedPositiveInteger(
      env.DEVSPACE_NEXT_MAX_RUNNING_PROCESSES_PER_TARGET,
      DEFAULT_MAX_RUNNING_PROCESSES_PER_TARGET,
      "DEVSPACE_NEXT_MAX_RUNNING_PROCESSES_PER_TARGET",
      1_024,
    ),
    processBufferCharacters: parseBoundedPositiveInteger(
      env.DEVSPACE_NEXT_PROCESS_BUFFER_CHARACTERS,
      DEFAULT_PROCESS_BUFFER_CHARACTERS,
      "DEVSPACE_NEXT_PROCESS_BUFFER_CHARACTERS",
      100_000_000,
    ),
    processOutputMaxBytes: parseBoundedPositiveInteger(
      env.DEVSPACE_NEXT_PROCESS_OUTPUT_MAX_BYTES,
      DEFAULT_PROCESS_OUTPUT_MAX_BYTES,
      "DEVSPACE_NEXT_PROCESS_OUTPUT_MAX_BYTES",
      10 * 1024 * 1024 * 1024,
    ),
    completedProcessTtlMs: parseBoundedPositiveInteger(
      env.DEVSPACE_NEXT_COMPLETED_PROCESS_TTL_MS,
      DEFAULT_COMPLETED_PROCESS_TTL_MS,
      "DEVSPACE_NEXT_COMPLETED_PROCESS_TTL_MS",
      24 * 60 * 60 * 1_000,
    ),
    artifactStagingDir: resolve(expandHomePath(
      env.DEVSPACE_NEXT_ARTIFACT_STAGING_DIR
        ?? join(stateDir, "artifacts"),
    )),
    artifactMaximumEntries: parseBoundedPositiveInteger(
      env.DEVSPACE_NEXT_ARTIFACT_MAXIMUM_ENTRIES,
      DEFAULT_ARTIFACT_MAXIMUM_ENTRIES,
      "DEVSPACE_NEXT_ARTIFACT_MAXIMUM_ENTRIES",
      10_000,
    ),
    artifactMaximumTotalBytes: parseBoundedPositiveInteger(
      env.DEVSPACE_NEXT_ARTIFACT_MAXIMUM_TOTAL_BYTES,
      DEFAULT_ARTIFACT_MAXIMUM_TOTAL_BYTES,
      "DEVSPACE_NEXT_ARTIFACT_MAXIMUM_TOTAL_BYTES",
      100 * 1024 * 1024 * 1024,
    ),
    artifactMaximumFileBytes: parseBoundedPositiveInteger(
      env.DEVSPACE_NEXT_ARTIFACT_MAXIMUM_FILE_BYTES,
      DEFAULT_ARTIFACT_MAXIMUM_FILE_BYTES,
      "DEVSPACE_NEXT_ARTIFACT_MAXIMUM_FILE_BYTES",
      10 * 1024 * 1024 * 1024,
    ),
    artifactTtlMs: parseBoundedPositiveInteger(
      env.DEVSPACE_NEXT_ARTIFACT_TTL_MS,
      DEFAULT_ARTIFACT_TTL_MS,
      "DEVSPACE_NEXT_ARTIFACT_TTL_MS",
      24 * 60 * 60 * 1_000,
    ),
    guiMaximumSessions: parseBoundedPositiveInteger(
      env.DEVSPACE_NEXT_GUI_MAXIMUM_SESSIONS,
      DEFAULT_GUI_MAXIMUM_SESSIONS,
      "DEVSPACE_NEXT_GUI_MAXIMUM_SESSIONS",
      1_000,
    ),
    guiSessionTtlMs: parseBoundedPositiveInteger(
      env.DEVSPACE_NEXT_GUI_SESSION_TTL_MS,
      DEFAULT_GUI_SESSION_TTL_MS,
      "DEVSPACE_NEXT_GUI_SESSION_TTL_MS",
      24 * 60 * 60 * 1_000,
    ),
    guiPayloadBudgetCharacters: parseBoundedPositiveInteger(
      env.DEVSPACE_NEXT_GUI_PAYLOAD_BUDGET_CHARACTERS,
      DEFAULT_GUI_PAYLOAD_BUDGET_CHARACTERS,
      "DEVSPACE_NEXT_GUI_PAYLOAD_BUDGET_CHARACTERS",
      100_000,
    ),
    downstreamMcpMaximumSessions: parseBoundedPositiveInteger(
      env.DEVSPACE_NEXT_DOWNSTREAM_MCP_MAXIMUM_SESSIONS,
      DEFAULT_DOWNSTREAM_MCP_MAXIMUM_SESSIONS,
      "DEVSPACE_NEXT_DOWNSTREAM_MCP_MAXIMUM_SESSIONS",
      256,
    ),
    downstreamMcpSessionIdleTtlMs: parseBoundedPositiveInteger(
      env.DEVSPACE_NEXT_DOWNSTREAM_MCP_SESSION_IDLE_TTL_MS,
      DEFAULT_DOWNSTREAM_MCP_SESSION_IDLE_TTL_MS,
      "DEVSPACE_NEXT_DOWNSTREAM_MCP_SESSION_IDLE_TTL_MS",
      60 * 60_000,
    ),
    mcpResultMaximumEntries: parseBoundedPositiveInteger(
      env.DEVSPACE_NEXT_MCP_RESULT_MAXIMUM_ENTRIES,
      DEFAULT_MCP_RESULT_MAXIMUM_ENTRIES,
      "DEVSPACE_NEXT_MCP_RESULT_MAXIMUM_ENTRIES",
      10_000,
    ),
    mcpResultMaximumCharacters: parseBoundedPositiveInteger(
      env.DEVSPACE_NEXT_MCP_RESULT_MAXIMUM_CHARACTERS,
      DEFAULT_MCP_RESULT_MAXIMUM_CHARACTERS,
      "DEVSPACE_NEXT_MCP_RESULT_MAXIMUM_CHARACTERS",
      1_000_000_000,
    ),
    mcpResultTtlMs: parseBoundedPositiveInteger(
      env.DEVSPACE_NEXT_MCP_RESULT_TTL_MS,
      DEFAULT_MCP_RESULT_TTL_MS,
      "DEVSPACE_NEXT_MCP_RESULT_TTL_MS",
      24 * 60 * 60_000,
    ),
    allowedHosts,
    oauth: {
      ownerToken: base.oauth.ownerToken,
      accessTokenTtlSeconds: base.oauth.accessTokenTtlSeconds,
      refreshTokenTtlSeconds: base.oauth.refreshTokenTtlSeconds,
      scopes: [...UNIVERSAL_OWNER_SCOPES],
      allowedRedirectHosts: base.oauth.allowedRedirectHosts,
    },
    logging: base.logging,
    mcpSessionIdleTimeoutMs: parseBoundedPositiveInteger(
      env.DEVSPACE_NEXT_MCP_SESSION_IDLE_TIMEOUT_MS,
      DEFAULT_NEXT_SESSION_IDLE_TIMEOUT_MS,
      "DEVSPACE_NEXT_MCP_SESSION_IDLE_TIMEOUT_MS",
      24 * 60 * 60_000,
    ),
    mcpSessionCleanupIntervalMs: parseBoundedPositiveInteger(
      env.DEVSPACE_NEXT_MCP_SESSION_CLEANUP_INTERVAL_MS,
      DEFAULT_NEXT_SESSION_CLEANUP_INTERVAL_MS,
      "DEVSPACE_NEXT_MCP_SESSION_CLEANUP_INTERVAL_MS",
      60 * 60_000,
    ),
    maximumMcpSessions: parseBoundedPositiveInteger(
      env.DEVSPACE_NEXT_MAXIMUM_MCP_SESSIONS,
      DEFAULT_NEXT_MAXIMUM_MCP_SESSIONS,
      "DEVSPACE_NEXT_MAXIMUM_MCP_SESSIONS",
      10_000,
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

function parseBoundedPositiveInteger(
  value: string | undefined,
  fallback: number,
  name: string,
  maximum: number,
): number {
  const parsed = parsePositiveInteger(value, fallback, name);
  if (parsed > maximum) {
    throw new Error(`Invalid ${name}: ${parsed} exceeds ${maximum}`);
  }
  return parsed;
}

function parseBoolean(
  value: string | undefined,
  fallback: boolean,
  name: string,
): boolean {
  if (value === undefined) return fallback;
  const normalized = value.trim().toLowerCase();
  if (normalized === "true") return true;
  if (normalized === "false") return false;
  throw new Error(`Invalid ${name}: expected true or false`);
}

function normalizePublicBaseUrl(value: string): string {
  const url = new URL(value);
  if (!["http:", "https:"].includes(url.protocol)) {
    throw new Error("DEVSPACE_NEXT_PUBLIC_BASE_URL must use HTTP or HTTPS.");
  }
  if (url.search || url.hash || url.username || url.password) {
    throw new Error("DEVSPACE_NEXT_PUBLIC_BASE_URL must not contain credentials, a query, or a fragment.");
  }
  const pathname = url.pathname === "/"
    ? ""
    : url.pathname.replace(/\/+$/u, "");
  return `${url.origin}${pathname}`;
}

export function joinPublicUrl(baseUrl: string, path: string): string {
  const normalizedBase = baseUrl.replace(/\/+$/u, "");
  const normalizedPath = path.startsWith("/") ? path : `/${path}`;
  return `${normalizedBase}${normalizedPath}`;
}

function normalizeEndpointPath(
  value: string,
  deploymentMode: UniversalBrokerDeploymentMode,
): string {
  const trimmed = value.trim();
  if (!trimmed.startsWith("/") || trimmed.includes("?") || trimmed.includes("#")) {
    throw new Error(`Invalid DEVSPACE_NEXT_MCP_PATH: ${value}`);
  }
  const normalized = trimmed.length > 1 ? trimmed.replace(/\/+$/, "") : trimmed;
  const reserved = new Set([
    "/",
    "/authorize",
    "/token",
    "/register",
    "/revoke",
    "/healthz-next",
  ]);
  if (deploymentMode === "parallel") reserved.add("/mcp");
  if (deploymentMode === "production" && normalized !== "/mcp") {
    throw new Error("Universal Broker v2 production endpoint must be /mcp; this is the canonical /mcp endpoint.");
  }
  if (reserved.has(normalized) || normalized.startsWith("/.well-known/")) {
    throw new Error(`DEVSPACE_NEXT_MCP_PATH conflicts with a reserved endpoint: ${normalized}`);
  }
  return normalized;
}

function parseDeploymentMode(
  value: string | undefined,
): UniversalBrokerDeploymentMode {
  const normalized = value?.trim() || "parallel";
  if (normalized === "parallel" || normalized === "production") return normalized;
  throw new Error(`Invalid DEVSPACE_V2_DEPLOYMENT_MODE: ${normalized}`);
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
