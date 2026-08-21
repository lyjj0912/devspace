import { homedir } from "node:os";
import { basename, dirname, isAbsolute, join, relative, resolve, sep } from "node:path";
import type { ServerConfig } from "../config.js";
import type { LoggingConfig } from "../logger.js";
import type { OAuthConfig } from "../oauth-provider.js";
import { expandHomePath } from "../roots.js";
import type { PrincipalMode } from "./authority-principal.js";
import { BASE_PRODUCT_PROFILE } from "./build-capabilities.js";
import { UNIVERSAL_OWNER_SCOPES } from "./contracts.js";
import {
  RESOURCE_DEFAULT_ARTIFACTS,
  RESOURCE_DEFAULT_ARTIFACT_MAX_BYTES,
  RESOURCE_DEFAULT_ARTIFACT_TTL_MS,
  RESOURCE_DEFAULT_COMPLETED_PROCESS_TTL_MS,
  RESOURCE_DEFAULT_CONCURRENT_PROCESSES,
  RESOURCE_DEFAULT_CONTEXTS,
  RESOURCE_DEFAULT_CONTEXT_TTL_MS,
  RESOURCE_DEFAULT_GUI_SESSIONS,
  RESOURCE_DEFAULT_GUI_TTL_MS,
  RESOURCE_DEFAULT_INLINE_OUTPUT_BYTES,
  RESOURCE_DEFAULT_MCP_CONNECTIONS,
  RESOURCE_DEFAULT_MCP_IDLE_TTL_MS,
  RESOURCE_DEFAULT_MCP_RESULT_MAX_BYTES,
  RESOURCE_DEFAULT_PROCESS_OUTPUT_BYTES,
  RESOURCE_DEFAULT_PROCESSES,
} from "./resource-defaults.js";
import { RUNTIME_SCHEMA_GENERATION } from "./runtime-contract-identity.js";
import {
  canonicalConfigDigest,
  loadUnifiedConfigSource,
  materializeUnifiedRegistries,
  unifiedConfigEnvironment,
  UNIFIED_CAPABILITY_SCOPES,
  UNIFIED_EXPECTED_TOOL_NAMES,
  type UnifiedConfigDocument,
  type UnifiedConfigSource,
  type UnifiedMcpRouteConfig,
  type UnifiedTargetConfig,
} from "./unified-config.js";

const DEFAULT_NEXT_ENDPOINT_PATH = "/mcp-next";
const DEFAULT_NEXT_SESSION_IDLE_TIMEOUT_MS = 90_000;
const DEFAULT_NEXT_SESSION_CLEANUP_INTERVAL_MS = 15_000;
const DEFAULT_NEXT_MAXIMUM_MCP_SESSIONS = 128;
const DEFAULT_CONTEXT_MAXIMUM_ENTRIES = RESOURCE_DEFAULT_CONTEXTS;
const DEFAULT_CONTEXT_IDLE_TTL_MS = RESOURCE_DEFAULT_CONTEXT_TTL_MS;
const DEFAULT_CONTEXT_MAXIMUM_WORKTREES = 8;
const DEFAULT_CONTEXT_MAXIMUM_WORKTREE_BYTES = 8 * 1024 * 1024 * 1024;
const DEFAULT_CONTEXT_DIFF_MAXIMUM_ENTRIES = 64;
const DEFAULT_CONTEXT_DIFF_MAXIMUM_CHARACTERS = 50_000_000;
const DEFAULT_CONTEXT_DIFF_TTL_MS = 15 * 60_000;
const DEFAULT_MAX_RUNNING_PROCESSES = RESOURCE_DEFAULT_CONCURRENT_PROCESSES;
const DEFAULT_MAX_RUNNING_PROCESSES_PER_TARGET = 32;
const DEFAULT_PROCESS_BUFFER_CHARACTERS = RESOURCE_DEFAULT_INLINE_OUTPUT_BYTES;
const DEFAULT_PROCESS_OUTPUT_MAX_BYTES = RESOURCE_DEFAULT_PROCESS_OUTPUT_BYTES;
const DEFAULT_COMPLETED_PROCESS_TTL_MS = RESOURCE_DEFAULT_COMPLETED_PROCESS_TTL_MS;
const DEFAULT_SELF_RESTART_TIMEOUT_MS = 120_000;
const DEFAULT_ARTIFACT_MAXIMUM_ENTRIES = RESOURCE_DEFAULT_ARTIFACTS;
const DEFAULT_ARTIFACT_MAXIMUM_TOTAL_BYTES = 2 * 1024 * 1024 * 1024;
const DEFAULT_ARTIFACT_MAXIMUM_FILE_BYTES = RESOURCE_DEFAULT_ARTIFACT_MAX_BYTES;
const DEFAULT_ARTIFACT_TTL_MS = RESOURCE_DEFAULT_ARTIFACT_TTL_MS;
const DEFAULT_GUI_MAXIMUM_SESSIONS = RESOURCE_DEFAULT_GUI_SESSIONS;
const DEFAULT_GUI_SESSION_TTL_MS = RESOURCE_DEFAULT_GUI_TTL_MS;
const DEFAULT_GUI_PAYLOAD_BUDGET_CHARACTERS = 12_000;
const DEFAULT_DOWNSTREAM_MCP_MAXIMUM_SESSIONS = RESOURCE_DEFAULT_MCP_CONNECTIONS;
const DEFAULT_DOWNSTREAM_MCP_SESSION_IDLE_TTL_MS = RESOURCE_DEFAULT_MCP_IDLE_TTL_MS;
const DEFAULT_MCP_RESULT_MAXIMUM_ENTRIES = 64;
const DEFAULT_MCP_RESULT_MAXIMUM_BYTES = RESOURCE_DEFAULT_MCP_RESULT_MAX_BYTES;
const DEFAULT_MCP_RESULT_TTL_MS = 15 * 60_000;
export const OAUTH_OFFLINE_ACCESS_SCOPE = "offline_access";

export type UniversalBrokerDeploymentMode = "parallel" | "production";

export interface UniversalBrokerNextConfig {
  productProfile: typeof BASE_PRODUCT_PROFILE;
  serverConfig: ServerConfig;
  deploymentMode: UniversalBrokerDeploymentMode;
  host: string;
  port: number;
  managementHost: string;
  managementPort: number;
  managementAuthorizationKeyRef: string;
  readyPath: string;
  publicBaseUrl: string;
  publicMcpUrl: string;
  endpointPath: string;
  healthPath: string;
  metricsPath: string;
  artifactPathPrefix: string;
  stateDir: string;
  authorityStorePath: string;
  connectorActivationJournalPath: string;
  lifecycleFinalizationStorePath: string;
  lifecycleFinalizationControlPath: string;
  authorityPrincipalMode: PrincipalMode;
  authorityOwnerInstanceId?: string;
  oauthStateDir: string;
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
  selfManagementDir: string;
  selfRestartPm2ProcessName: string;
  selfRestartExpectedScript?: string;
  selfRestartTimeoutMs: number;
  maxRunningProcesses: number;
  maximumProcessRecords: number;
  maxRunningProcessesPerTarget: number;
  internalRunnerMaximumConcurrent: number;
  processBufferCharacters: number;
  processOutputMaxBytes: number;
  completedProcessTtlMs: number;
  artifactStagingDir: string;
  artifactCatalogPath: string;
  artifactObjectRoot: string;
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
  mcpResultMaximumBytes: number;
  mcpResultTtlMs: number;
  allowedHosts: string[];
  oauth: OAuthConfig;
  logging: LoggingConfig;
  mcpSessionIdleTimeoutMs: number;
  mcpSessionCleanupIntervalMs: number;
  maximumMcpSessions: number;
  canonicalConnectorName: string;
  authorityDeployment: "in-process";
  authorityApprovalAssurance: "cooperative";
  authorityMode: "enforced" | "audit" | "disabled";
  authorityStateDirectory: string;
  authorityR0FastPath: boolean;
  authorityTtlSeconds: Readonly<{ R1: number; R2: number; R3: number }>;
  authorityResourceLeaseTtlSeconds: number;
  authorityResourceLeaseHeartbeatSeconds: number;
  authorityResourceLeaseRecoveryGraceSeconds: number;
  authorityMaximumActionsPerPlan: number;
  authorityMaximumUses: Readonly<{ R1: number; R2: number; R3: number }>;
  oauthIssuer: string;
  oauthResource: string;
  oauthAllowOfflineAccess: boolean;
  allowAnonymousSessionFallback: boolean;
  legacyBlanketScopeCompatibility: boolean;
  adminScopeEnabled: boolean;
  supervisorEndpoint: string;
  supervisorProcessManager: "pm2";
  supervisorRestartMaximumAttempts: number;
  supervisorRestartMaximumDelayMs: number;
  cursorTtlMs: number;
  cursorMaximumSnapshotsPerPrincipal: number;
  cursorSigningKeyRef: string;
  cursorPreviousSigningKeyRef?: string;
  connectorDrainGraceSeconds: number;
  rateLimit: Readonly<{
    mode: "internal";
    preAuth: Readonly<{ refillPerMinute: number; burst: number }>;
    postAuth: Readonly<{ refillPerMinute: number; burst: number }>;
    initialize: Readonly<{ refillPerMinute: number; burst: number }>;
  }>;
  auditSinkPath: string;
  auditFlushIntervalMs: number;
  publicMetrics: boolean;
  publicHealth: boolean;
  redactSecrets: boolean;
  stateFileMode: "0600";
  directoryMode: "0700";
  unifiedTargets: readonly UnifiedTargetConfig[];
  unifiedMcpRoutes: readonly UnifiedMcpRouteConfig[];
  configProfile: "development" | "production";
  configSourcePath?: string;
  canonicalConfig: Readonly<Record<string, unknown>>;
  configDigest: string;
  sourceRevision: string;
  runtimeRevision: string;
  buildDigest?: string;
}

export function loadUniversalBrokerNextConfig(
  base: ServerConfig,
  env: NodeJS.ProcessEnv = process.env,
): UniversalBrokerNextConfig {
  const configDirectory = env.DEVSPACE_CONFIG_DIR
    ? resolve(expandHomePath(env.DEVSPACE_CONFIG_DIR))
    : dirname(base.devspaceSkillsDir);
  const unifiedSource = loadUnifiedConfigSource(env, configDirectory);
  const effectiveEnvironment = unifiedSource
    ? mergeDefinedEnvironment(unifiedConfigEnvironment(unifiedSource), env)
    : env;
  const environmentConfig = loadUniversalBrokerEnvironmentConfig(
    base,
    effectiveEnvironment,
    unifiedSource !== undefined,
  );
  return finalizeUniversalBrokerConfig(
    environmentConfig,
    effectiveEnvironment,
    unifiedSource,
    env,
  );
}

type EnvironmentUniversalBrokerNextConfig = Omit<UniversalBrokerNextConfig,
  | "authorityMode"
  | "authorityApprovalAssurance"
  | "authorityStateDirectory"
  | "authorityR0FastPath"
  | "authorityTtlSeconds"
  | "authorityResourceLeaseTtlSeconds"
  | "authorityResourceLeaseHeartbeatSeconds"
  | "authorityResourceLeaseRecoveryGraceSeconds"
  | "authorityMaximumActionsPerPlan"
  | "authorityMaximumUses"
  | "oauthIssuer"
  | "oauthResource"
  | "oauthAllowOfflineAccess"
  | "allowAnonymousSessionFallback"
  | "legacyBlanketScopeCompatibility"
  | "adminScopeEnabled"
  | "supervisorEndpoint"
  | "supervisorProcessManager"
  | "supervisorRestartMaximumAttempts"
  | "supervisorRestartMaximumDelayMs"
  | "publicMetrics"
  | "publicHealth"
  | "redactSecrets"
  | "stateFileMode"
  | "directoryMode"
  | "unifiedTargets"
  | "unifiedMcpRoutes"
  | "configProfile"
  | "configSourcePath"
  | "canonicalConfig"
  | "configDigest"
>;

function loadUniversalBrokerEnvironmentConfig(
  base: ServerConfig,
  env: NodeJS.ProcessEnv,
  unifiedConfigurationActive: boolean,
): EnvironmentUniversalBrokerNextConfig {
  const deploymentMode = parseDeploymentMode(env.DEVSPACE_V2_DEPLOYMENT_MODE);
  const host = env.DEVSPACE_NEXT_HOST?.trim() || base.host;
  const port = parsePort(
    env.DEVSPACE_NEXT_PORT,
    deploymentMode === "production"
      ? base.port
      : base.port < 65_535 ? base.port + 1 : 7_677,
  );
  const managementHost = env.DEVSPACE_NEXT_MANAGEMENT_HOST?.trim() || "127.0.0.1";
  if (!["127.0.0.1", "::1", "localhost"].includes(managementHost)) {
    throw new Error("DEVSPACE_NEXT_MANAGEMENT_HOST must be loopback-only.");
  }
  const managementPort = parsePort(
    env.DEVSPACE_NEXT_MANAGEMENT_PORT,
    port <= 64_535 ? port + 1_000 : port - 1_000,
  );
  if (managementPort === port) {
    throw new Error("The management listener must use a different port from the public data plane.");
  }
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
  const metricsPath = "/metrics";
  const readyPath = "/readyz";
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
  if (
    stateDir === resolve(base.stateDir)
    && !(unifiedConfigurationActive && deploymentMode === "production")
  ) {
    throw new Error("DEVSPACE_NEXT_STATE_DIR must be separate from the production state directory.");
  }
  const oauthStateDir = resolve(expandHomePath(
    env.DEVSPACE_NEXT_OAUTH_STATE_DIR
      ?? (deploymentMode === "production" ? base.stateDir : stateDir),
  ));
  // Retained only as inert source-compatibility fields for legacy modules that
  // are not registered by PERSONAL_DIRECT_OWNER. They are not configurable,
  // opened, migrated, or readiness-gating in the personal runtime.
  const authorityStorePath = join(stateDir, "legacy-unused-authority.sqlite");
  const connectorActivationJournalPath = join(stateDir, "legacy-unused-connector-journal.sqlite");
  const lifecycleFinalizationStorePath = join(stateDir, "legacy-unused-lifecycle.sqlite");
  const lifecycleFinalizationControlPath = join(stateDir, "legacy-unused-lifecycle-control.json");
  const authorityPrincipalMode = "single-owner" as const;
  const authorityOwnerInstanceId = parseOptionalBoundedText(
    env.DEVSPACE_OAUTH_OWNER_INSTANCE_ID ?? env.DEVSPACE_NEXT_AUTHORITY_OWNER_INSTANCE_ID,
    "DEVSPACE_OAUTH_OWNER_INSTANCE_ID",
    512,
  );
  if (authorityPrincipalMode === "single-owner" && !authorityOwnerInstanceId) {
    throw new Error(
      "Personal Direct Owner requires DEVSPACE_OAUTH_OWNER_INSTANCE_ID.",
    );
  }
  const legacyScopeCompatibility = env.DEVSPACE_V2_LEGACY_SCOPE_COMPATIBILITY;
  if (legacyScopeCompatibility !== undefined && parseBoolean(
    legacyScopeCompatibility,
    false,
    "DEVSPACE_V2_LEGACY_SCOPE_COMPATIBILITY",
  )) {
    throw new Error(
      "DEVSPACE_V2_LEGACY_SCOPE_COMPATIBILITY was removed in Universal Broker v2.1; issue granular scopes instead.",
    );
  }
  const productionMcpUrl = new URL("/mcp", base.publicBaseUrl).href;
  if (deploymentMode === "parallel" && publicMcpUrl === productionMcpUrl) {
    throw new Error("Universal Broker v2 public MCP URL must differ from production /mcp during parallel development.");
  }
  if (
    deploymentMode === "production"
    && !unifiedConfigurationActive
    && publicMcpUrl !== productionMcpUrl
  ) {
    throw new Error("Universal Broker v2 production mode must use the canonical production /mcp URL.");
  }
  if (
    deploymentMode === "production"
    && unifiedConfigurationActive
    && new URL(publicMcpUrl).pathname !== "/mcp"
  ) {
    throw new Error("Universal Broker v2 production mode must use the canonical production /mcp URL.");
  }
  const configDir = env.DEVSPACE_CONFIG_DIR
    ? resolve(expandHomePath(env.DEVSPACE_CONFIG_DIR))
    : dirname(base.devspaceSkillsDir);
  const buildDigest = parseOptionalDigest(env.DEVSPACE_BUILD_DIGEST);

  const config: EnvironmentUniversalBrokerNextConfig = {
    productProfile: BASE_PRODUCT_PROFILE,
    serverConfig: base,
    deploymentMode,
    host,
    port,
    managementHost,
    managementPort,
    readyPath,
    publicBaseUrl,
    publicMcpUrl,
    endpointPath,
    healthPath,
    metricsPath,
    artifactPathPrefix,
    stateDir,
    authorityStorePath,
    connectorActivationJournalPath,
    lifecycleFinalizationStorePath,
    lifecycleFinalizationControlPath,
    authorityPrincipalMode,
    authorityOwnerInstanceId,
    oauthStateDir,
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
    selfManagementDir: resolve(expandHomePath(
      env.DEVSPACE_NEXT_SELF_MANAGEMENT_DIR
        ?? join(stateDir, "self-management"),
    )),
    selfRestartPm2ProcessName: parseBoundedText(
      env.DEVSPACE_NEXT_PM2_PROCESS_NAME,
      deploymentMode === "production" ? "devspace-v2-production" : "devspace-next",
      "DEVSPACE_NEXT_PM2_PROCESS_NAME",
      128,
    ),
    selfRestartExpectedScript: env.DEVSPACE_NEXT_PM2_EXPECTED_SCRIPT?.trim()
      ? resolve(expandHomePath(env.DEVSPACE_NEXT_PM2_EXPECTED_SCRIPT))
      : undefined,
    selfRestartTimeoutMs: parseBoundedPositiveInteger(
      env.DEVSPACE_NEXT_SELF_RESTART_TIMEOUT_MS,
      DEFAULT_SELF_RESTART_TIMEOUT_MS,
      "DEVSPACE_NEXT_SELF_RESTART_TIMEOUT_MS",
      10 * 60_000,
    ),
    maxRunningProcesses: parseBoundedPositiveInteger(
      env.DEVSPACE_NEXT_MAX_RUNNING_PROCESSES,
      DEFAULT_MAX_RUNNING_PROCESSES,
      "DEVSPACE_NEXT_MAX_RUNNING_PROCESSES",
      1_024,
    ),
    maximumProcessRecords: parseBoundedPositiveInteger(
      env.DEVSPACE_NEXT_MAXIMUM_PROCESS_RECORDS,
      RESOURCE_DEFAULT_PROCESSES,
      "DEVSPACE_NEXT_MAXIMUM_PROCESS_RECORDS",
      10_000,
    ),
    maxRunningProcessesPerTarget: parseBoundedPositiveInteger(
      env.DEVSPACE_NEXT_MAX_RUNNING_PROCESSES_PER_TARGET,
      DEFAULT_MAX_RUNNING_PROCESSES_PER_TARGET,
      "DEVSPACE_NEXT_MAX_RUNNING_PROCESSES_PER_TARGET",
      1_024,
    ),
    internalRunnerMaximumConcurrent: parseBoundedPositiveInteger(
      env.DEVSPACE_NEXT_INTERNAL_RUNNER_MAXIMUM_CONCURRENT,
      32,
      "DEVSPACE_NEXT_INTERNAL_RUNNER_MAXIMUM_CONCURRENT",
      1_000,
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
    artifactCatalogPath: resolve(expandHomePath(
      env.DEVSPACE_NEXT_ARTIFACT_CATALOG ?? join(stateDir, "artifacts.sqlite"),
    )),
    artifactObjectRoot: resolve(expandHomePath(
      env.DEVSPACE_NEXT_ARTIFACT_OBJECT_ROOT ?? join(stateDir, "artifact-objects"),
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
    mcpResultMaximumBytes: parseBoundedPositiveInteger(
      env.DEVSPACE_NEXT_MCP_RESULT_MAXIMUM_BYTES,
      DEFAULT_MCP_RESULT_MAXIMUM_BYTES,
      "DEVSPACE_NEXT_MCP_RESULT_MAXIMUM_BYTES",
      10 * 1024 * 1024 * 1024,
    ),
    mcpResultTtlMs: parseBoundedPositiveInteger(
      env.DEVSPACE_NEXT_MCP_RESULT_TTL_MS,
      DEFAULT_MCP_RESULT_TTL_MS,
      "DEVSPACE_NEXT_MCP_RESULT_TTL_MS",
      24 * 60 * 60_000,
    ),
    cursorTtlMs: parseBoundedPositiveInteger(
      env.DEVSPACE_NEXT_CURSOR_TTL_MS,
      10 * 60_000,
      "DEVSPACE_NEXT_CURSOR_TTL_MS",
      24 * 60 * 60_000,
    ),
    cursorMaximumSnapshotsPerPrincipal: parseBoundedPositiveInteger(
      env.DEVSPACE_NEXT_CURSOR_MAXIMUM_SNAPSHOTS_PER_PRINCIPAL,
      128,
      "DEVSPACE_NEXT_CURSOR_MAXIMUM_SNAPSHOTS_PER_PRINCIPAL",
      10_000,
    ),
    cursorSigningKeyRef: parseBoundedText(
      env.DEVSPACE_NEXT_CURSOR_SIGNING_KEY_REF,
      join(stateDir, "cursor-hmac-current.key"),
      "DEVSPACE_NEXT_CURSOR_SIGNING_KEY_REF",
      4_096,
    ),
    cursorPreviousSigningKeyRef: parseOptionalBoundedText(
      env.DEVSPACE_NEXT_CURSOR_PREVIOUS_SIGNING_KEY_REF,
      "DEVSPACE_NEXT_CURSOR_PREVIOUS_SIGNING_KEY_REF",
      4_096,
    ),
    managementAuthorizationKeyRef: parseBoundedText(
      env.DEVSPACE_NEXT_MANAGEMENT_AUTHORIZATION_KEY_REF,
      join(stateDir, "management-authorization.key"),
      "DEVSPACE_NEXT_MANAGEMENT_AUTHORIZATION_KEY_REF",
      4_096,
    ),
    connectorDrainGraceSeconds: parseBoundedPositiveInteger(
      env.DEVSPACE_NEXT_CONNECTOR_DRAIN_GRACE_SECONDS,
      3_600,
      "DEVSPACE_NEXT_CONNECTOR_DRAIN_GRACE_SECONDS",
      86_400,
    ),
    rateLimit: Object.freeze({
      mode: parseInternalRateLimitMode(env.DEVSPACE_NEXT_RATE_LIMIT_MODE),
      preAuth: Object.freeze({
        refillPerMinute: parseBoundedPositiveInteger(
          env.DEVSPACE_NEXT_RATE_LIMIT_PRE_AUTH_REFILL_PER_MINUTE,
          120,
          "DEVSPACE_NEXT_RATE_LIMIT_PRE_AUTH_REFILL_PER_MINUTE",
          1_000_000,
        ),
        burst: parseBoundedPositiveInteger(
          env.DEVSPACE_NEXT_RATE_LIMIT_PRE_AUTH_BURST,
          30,
          "DEVSPACE_NEXT_RATE_LIMIT_PRE_AUTH_BURST",
          1_000_000,
        ),
      }),
      postAuth: Object.freeze({
        refillPerMinute: parseBoundedPositiveInteger(
          env.DEVSPACE_NEXT_RATE_LIMIT_POST_AUTH_REFILL_PER_MINUTE,
          600,
          "DEVSPACE_NEXT_RATE_LIMIT_POST_AUTH_REFILL_PER_MINUTE",
          1_000_000,
        ),
        burst: parseBoundedPositiveInteger(
          env.DEVSPACE_NEXT_RATE_LIMIT_POST_AUTH_BURST,
          100,
          "DEVSPACE_NEXT_RATE_LIMIT_POST_AUTH_BURST",
          1_000_000,
        ),
      }),
      initialize: Object.freeze({
        refillPerMinute: parseBoundedPositiveInteger(
          env.DEVSPACE_NEXT_RATE_LIMIT_INITIALIZE_REFILL_PER_MINUTE,
          30,
          "DEVSPACE_NEXT_RATE_LIMIT_INITIALIZE_REFILL_PER_MINUTE",
          1_000_000,
        ),
        burst: parseBoundedPositiveInteger(
          env.DEVSPACE_NEXT_RATE_LIMIT_INITIALIZE_BURST,
          10,
          "DEVSPACE_NEXT_RATE_LIMIT_INITIALIZE_BURST",
          1_000_000,
        ),
      }),
    }),
    auditSinkPath: resolve(expandHomePath(
      env.DEVSPACE_NEXT_AUDIT_SINK ?? join(stateDir, "audit", "operations.jsonl"),
    )),
    auditFlushIntervalMs: parseBoundedPositiveInteger(
      env.DEVSPACE_NEXT_AUDIT_FLUSH_INTERVAL_MS,
      250,
      "DEVSPACE_NEXT_AUDIT_FLUSH_INTERVAL_MS",
      60_000,
    ),
    allowedHosts,
    oauth: {
      ownerToken: base.oauth.ownerToken,
      accessTokenTtlSeconds: base.oauth.accessTokenTtlSeconds,
      refreshTokenTtlSeconds: base.oauth.refreshTokenTtlSeconds,
      scopes: [...UNIVERSAL_OWNER_SCOPES, OAUTH_OFFLINE_ACCESS_SCOPE],
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
    canonicalConnectorName: parseBoundedText(
      env.DEVSPACE_NEXT_CANONICAL_CONNECTOR_NAME,
      "myDevSpace",
      "DEVSPACE_NEXT_CANONICAL_CONNECTOR_NAME",
      128,
    ),
    authorityDeployment: parseAuthorityDeployment(env.DEVSPACE_NEXT_AUTHORITY_DEPLOYMENT),
    sourceRevision: parseBoundedText(
      env.DEVSPACE_SOURCE_REVISION,
      "unknown-source",
      "DEVSPACE_SOURCE_REVISION",
      256,
    ),
    runtimeRevision: parseBoundedText(
      env.DEVSPACE_RUNTIME_REVISION,
      "development-runtime",
      "DEVSPACE_RUNTIME_REVISION",
      256,
    ),
    ...(buildDigest ? { buildDigest } : {}),
  };
  if (config.maxRunningProcessesPerTarget > config.maxRunningProcesses) {
    throw new Error("Per-target process concurrency cannot exceed global concurrency.");
  }
  if (config.artifactMaximumFileBytes > config.artifactMaximumTotalBytes) {
    throw new Error("Per-artifact maximum cannot exceed the total artifact byte quota.");
  }
  return config;
}

function finalizeUniversalBrokerConfig(
  config: EnvironmentUniversalBrokerNextConfig,
  env: NodeJS.ProcessEnv,
  source: UnifiedConfigSource | undefined,
  explicitEnvironment: NodeJS.ProcessEnv,
): UniversalBrokerNextConfig {
  const document = source?.document;
  const production = config.deploymentMode === "production";
  const profile = production ? "production" : "development";

  if (document?.server?.managementPlane?.unixSocket) {
    throw new Error(
      "server.managementPlane.unixSocket is not supported by this build; refusing to expose a fallback TCP management listener.",
    );
  }
  const stagingPort = document?.server?.stagingPlane?.port;
  if (stagingPort !== undefined && stagingPort === config.port) {
    throw new Error("The staging listener must use a different port from the public data plane.");
  }
  if (source && production && env.DEVSPACE_NEXT_CANONICAL_CONNECTOR_NAME === undefined) {
    throw new Error("Production unified configuration requires server.canonicalConnectorName.");
  }

  const oauthIssuer = normalizeConfiguredUrl(
    env.DEVSPACE_NEXT_OAUTH_ISSUER ?? document?.oauth?.issuer ?? config.publicBaseUrl,
    "OAuth issuer",
  );
  const oauthResource = normalizeConfiguredUrl(
    env.DEVSPACE_NEXT_OAUTH_RESOURCE ?? document?.oauth?.resource ?? config.publicMcpUrl,
    "OAuth resource",
  );
  if (production && oauthResource !== config.publicMcpUrl) {
    throw new Error("Production OAuth resource must equal the canonical public MCP URL.");
  }
  const capabilityScopes = parseCapabilityScopes(
    env.DEVSPACE_NEXT_CAPABILITY_SCOPES,
    document?.oauth?.capabilityScopes,
  );
  const oauthAllowOfflineAccess = parseBoolean(
    env.DEVSPACE_NEXT_ALLOW_OFFLINE_ACCESS,
    document?.oauth?.allowOfflineAccess ?? true,
    "DEVSPACE_NEXT_ALLOW_OFFLINE_ACCESS",
  );
  const legacyBlanketScopeCompatibility = parseBoolean(
    env.DEVSPACE_V2_LEGACY_SCOPE_COMPATIBILITY,
    document?.oauth?.legacyBlanketScopeCompatibility ?? false,
    "DEVSPACE_V2_LEGACY_SCOPE_COMPATIBILITY",
  );
  const adminScopeEnabled = parseBoolean(
    env.DEVSPACE_NEXT_ADMIN_SCOPE_ENABLED,
    document?.oauth?.adminScopeEnabled ?? false,
    "DEVSPACE_NEXT_ADMIN_SCOPE_ENABLED",
  );
  const allowAnonymousSessionFallback = parseBoolean(
    env.DEVSPACE_NEXT_ALLOW_ANONYMOUS_SESSION_FALLBACK,
    document?.oauth?.allowAnonymousSessionFallback ?? false,
    "DEVSPACE_NEXT_ALLOW_ANONYMOUS_SESSION_FALLBACK",
  );
  if (legacyBlanketScopeCompatibility) {
    throw new Error("Legacy blanket OAuth scope compatibility is forbidden.");
  }
  if (adminScopeEnabled) {
    throw new Error("Administrative OAuth scope is forbidden.");
  }
  if (production && allowAnonymousSessionFallback) {
    throw new Error("Production configuration forbids anonymous or MCP-session principal fallback.");
  }

  if (env.DEVSPACE_NEXT_OAUTH_SUBJECT_CLAIM !== undefined) {
    throw new Error("OAuth subject claim policy is unsupported by this PERSONAL_DIRECT_OWNER build.");
  }

  const authorityMode = "disabled" as const;
  const authorityApprovalAssurance = "cooperative" as const;
  const authorityR0FastPath = true;
  if (env.DEVSPACE_NEXT_SELF_RESTART_DELAY_MS !== undefined) {
    throw new Error("Self-restart delay is unsupported; restart requires transport ACK_FLUSHED evidence.");
  }
  const authorityTtlSeconds = Object.freeze({ R1: 1, R2: 1, R3: 1 });
  const authorityResourceLeaseTtlSeconds = 1;
  const authorityResourceLeaseHeartbeatSeconds = 1;
  const authorityResourceLeaseRecoveryGraceSeconds = 1;
  const authorityMaximumActionsPerPlan = 1;
  const authorityMaximumUses = Object.freeze({ R1: 1, R2: 1, R3: 1 });
  const supervisorEndpoint = parseOptionalBoundedText(
    env.DEVSPACE_NEXT_SUPERVISOR_ENDPOINT ?? document?.supervisor?.endpoint,
    "supervisor.endpoint",
    4_096,
  ) ?? (source ? undefined : "internal://pm2");
  if (!supervisorEndpoint) {
    throw new Error("Supervisor endpoint is required.");
  }
  if (source && production && document?.supervisor?.endpoint === undefined
      && env.DEVSPACE_NEXT_SUPERVISOR_ENDPOINT === undefined) {
    throw new Error("Production unified configuration requires supervisor.endpoint.");
  }
  assertPrivateEndpoint(supervisorEndpoint, "supervisor endpoint");
  const supervisorProcessManager = parseSupervisorProcessManager(
    env.DEVSPACE_NEXT_SUPERVISOR_PROCESS_MANAGER ?? document?.supervisor?.processManager,
  );
  const supervisorRestartMaximumAttempts = parseBoundedPositiveInteger(
    env.DEVSPACE_NEXT_SUPERVISOR_MAXIMUM_RESTART_ATTEMPTS,
    document?.supervisor?.restartPolicy?.maximumAttempts ?? 3,
    "DEVSPACE_NEXT_SUPERVISOR_MAXIMUM_RESTART_ATTEMPTS",
    100,
  );
  const supervisorRestartMaximumDelayMs = parseBoundedPositiveInteger(
    env.DEVSPACE_NEXT_SUPERVISOR_MAXIMUM_RESTART_DELAY_MS,
    document?.supervisor?.restartPolicy?.maximumDelayMs ?? 60_000,
    "DEVSPACE_NEXT_SUPERVISOR_MAXIMUM_RESTART_DELAY_MS",
    600_000,
  );

  const publicMetrics = parseBoolean(
    env.DEVSPACE_NEXT_PUBLIC_METRICS,
    document?.observability?.publicMetrics ?? false,
    "DEVSPACE_NEXT_PUBLIC_METRICS",
  );
  if (publicMetrics) throw new Error("Public metrics are forbidden; metrics must remain management-only.");
  const publicHealth = parseBoolean(
    env.DEVSPACE_NEXT_PUBLIC_HEALTH,
    document?.observability?.publicHealth ?? true,
    "DEVSPACE_NEXT_PUBLIC_HEALTH",
  );
  const redactSecrets = parseBoolean(
    env.DEVSPACE_NEXT_REDACT_SECRETS,
    document?.observability?.redactSecrets ?? true,
    "DEVSPACE_NEXT_REDACT_SECRETS",
  );
  const logging = {
    ...config.logging,
    level: parseLogLevel(env.DEVSPACE_LOG_LEVEL, config.logging.level),
  };
  const stateFileMode = document?.storage?.stateFileMode ?? "0600";
  const directoryMode = document?.storage?.directoryMode ?? "0700";
  const authorityStateDirectory = dirname(config.authorityStorePath);
  const unifiedTargets = Object.freeze([...(document?.targets ?? [])]);
  const unifiedMcpRoutes = Object.freeze([...(document?.mcpRoutes ?? [])]);
  const expectedToolNames = document?.release?.expectedToolNames
    ?? [...UNIFIED_EXPECTED_TOOL_NAMES];
  assertExpectedToolNames(expectedToolNames);
  const materializedRegistries = source
    ? materializeUnifiedRegistries(source, config.stateDir)
    : {};
  const targetConfigPath = explicitEnvironment.DEVSPACE_NEXT_TARGETS_FILE !== undefined
    ? config.targetConfigPath
    : materializedRegistries.targetConfigPath ?? config.targetConfigPath;
  const mcpRouteConfigPath = explicitEnvironment.DEVSPACE_NEXT_MCP_ROUTES_FILE !== undefined
    ? config.mcpRouteConfigPath
    : materializedRegistries.mcpRouteConfigPath ?? config.mcpRouteConfigPath;

  const oauth: OAuthConfig = {
    ...config.oauth,
    scopes: [
      ...capabilityScopes,
      ...(oauthAllowOfflineAccess ? [OAUTH_OFFLINE_ACCESS_SCOPE] : []),
    ],
    canonicalConnector: {
      name: config.canonicalConnectorName,
      installationEpoch: parseBoundedPositiveInteger(
        explicitEnvironment.DEVSPACE_OAUTH_CONNECTOR_INSTALLATION_EPOCH
          ?? (document?.connector?.installationEpoch === undefined
            ? undefined
            : String(document.connector.installationEpoch)),
        1,
        "DEVSPACE_OAUTH_CONNECTOR_INSTALLATION_EPOCH",
        Number.MAX_SAFE_INTEGER,
      ),
      schemaGeneration: RUNTIME_SCHEMA_GENERATION,
    },
  };
  const canonicalConfig = freezeDeep({
    version: 2,
    productProfile: BASE_PRODUCT_PROFILE,
    profile,
    server: {
      publicBaseUrl: config.publicBaseUrl,
      mcpPath: config.endpointPath,
      dataPlane: { host: config.host, port: config.port },
      managementPlane: { host: config.managementHost, port: config.managementPort },
      ...(stagingPort === undefined ? {} : { stagingPlane: {
        host: document?.server?.stagingPlane?.host ?? "127.0.0.1",
        port: stagingPort,
      } }),
      canonicalConnectorName: config.canonicalConnectorName,
      allowedHosts: [...config.allowedHosts],
    },
    oauth: {
      issuer: oauthIssuer,
      resource: oauthResource,
      principalMode: config.authorityPrincipalMode,
      ownerInstanceId: config.authorityOwnerInstanceId,
      capabilityScopes: [...capabilityScopes],
      allowOfflineAccess: oauthAllowOfflineAccess,
      legacyBlanketScopeCompatibility,
      adminScopeEnabled,
      allowAnonymousSessionFallback,
    },
    supervisor: {
      endpoint: supervisorEndpoint,
      processManager: supervisorProcessManager,
      processName: config.selfRestartPm2ProcessName,
      expectedScript: config.selfRestartExpectedScript,
      transactionDirectory: config.selfManagementDir,
      healthTimeoutMs: config.selfRestartTimeoutMs,
      responseFlushRequired: true,
      restartPolicy: {
        maximumAttempts: supervisorRestartMaximumAttempts,
        maximumDelayMs: supervisorRestartMaximumDelayMs,
      },
    },
    pagination: {
      cursorTtlSeconds: config.cursorTtlMs / 1_000,
      maximumSnapshotsPerPrincipal: config.cursorMaximumSnapshotsPerPrincipal,
      signingKeyRef: config.cursorSigningKeyRef,
      previousSigningKeyRef: config.cursorPreviousSigningKeyRef,
    },
    artifact: {
      catalogPath: config.artifactCatalogPath,
      objectRoot: config.artifactObjectRoot,
      defaultTtlSeconds: config.artifactTtlMs / 1_000,
      maximumArtifactBytes: config.artifactMaximumFileBytes,
      maximumTotalBytes: config.artifactMaximumTotalBytes,
    },
    connector: {
      canonicalName: config.canonicalConnectorName,
      installationEpoch: oauth.canonicalConnector!.installationEpoch,
      drainGraceSeconds: config.connectorDrainGraceSeconds,
    },
    rateLimit: config.rateLimit,
    management: {
      bind: config.managementHost,
      port: config.managementPort,
      publicExposure: "deny",
      authorizationKeyRef: config.managementAuthorizationKeyRef,
    },
    audit: {
      sink: config.auditSinkPath,
      flushIntervalMs: config.auditFlushIntervalMs,
      rawArguments: false,
    },
    storage: {
      stateDirectory: config.stateDir,
      oauthStateDirectory: config.oauthStateDir,
      artifactRoot: config.artifactStagingDir,
      processOutputRoot: config.processOutputDir,
      sshControlDirectory: config.sshControlDir,
      contextStore: config.contextStorePath,
      contextWorktreeRoot: config.contextWorktreeRoot,
      envProfileConfig: config.envProfileConfigPath,
      targetConfig: targetConfigPath,
      mcpRouteConfig: mcpRouteConfigPath,
      stateFileMode,
      directoryMode,
    },
    process: {
      maximumRunningTotal: config.maxRunningProcesses,
      maximumRunningPerTarget: config.maxRunningProcessesPerTarget,
      terminalRetentionTtlSeconds: config.completedProcessTtlMs / 1_000,
      maximumRetainedTerminalRecords: config.maximumProcessRecords,
      maximumOutputBytesPerProcess: config.processOutputMaxBytes,
      terminalOverflowPolicy: "prune-oldest",
      internalRunnerMaximumConcurrent: config.internalRunnerMaximumConcurrent,
    },
    quotas: {
      contexts: config.contextMaximumEntries,
      mcpConnections: config.downstreamMcpMaximumSessions,
      mcpRetainedResultBytes: config.mcpResultMaximumBytes,
      guiSessions: config.guiMaximumSessions,
      artifacts: config.artifactMaximumEntries,
      inlineOutputBytes: config.processBufferCharacters,
      artifactMaxBytes: config.artifactMaximumFileBytes,
    },
    ttls: {
      contextSeconds: config.contextIdleTtlMs / 1_000,
      mcpIdleSeconds: config.downstreamMcpSessionIdleTtlMs / 1_000,
      guiSeconds: config.guiSessionTtlMs / 1_000,
      artifactSeconds: config.artifactTtlMs / 1_000,
      cursorSnapshotSeconds: config.cursorTtlMs / 1_000,
      mcpRetainedResultSeconds: config.mcpResultTtlMs / 1_000,
    },
    targets: unifiedTargets,
    mcpRoutes: unifiedMcpRoutes,
    observability: {
      publicHealth,
      publicMetrics,
      logLevel: logging.level,
      redactSecrets,
    },
    release: {
      expectedToolNames: [...expectedToolNames],
      expectedTargetIdsFile: document?.release?.expectedTargetIdsFile,
      requireCleanSource: document?.release?.requireCleanSource ?? true,
      requireRuntimeBuildDigestMatch:
        document?.release?.requireRuntimeBuildDigestMatch ?? true,
      requireHostSessionChurnCanary:
        document?.release?.requireHostSessionChurnCanary ?? true,
      forbidParallelRuntime: document?.release?.forbidParallelRuntime ?? true,
      forbidLegacyScopes: document?.release?.forbidLegacyScopes ?? true,
      forbidPrivilegedArtifacts:
        document?.release?.forbidPrivilegedArtifacts ?? true,
    },
  }) as Readonly<Record<string, unknown>>;

  return {
    ...config,
    targetConfigPath,
    mcpRouteConfigPath,
    oauth,
    logging,
    authorityMode,
    authorityApprovalAssurance,
    authorityStateDirectory,
    authorityR0FastPath,
    authorityTtlSeconds,
    authorityResourceLeaseTtlSeconds,
    authorityResourceLeaseHeartbeatSeconds,
    authorityResourceLeaseRecoveryGraceSeconds,
    authorityMaximumActionsPerPlan,
    authorityMaximumUses,
    oauthIssuer,
    oauthResource,
    oauthAllowOfflineAccess,
    allowAnonymousSessionFallback,
    legacyBlanketScopeCompatibility,
    adminScopeEnabled,
    supervisorEndpoint,
    supervisorProcessManager,
    supervisorRestartMaximumAttempts,
    supervisorRestartMaximumDelayMs,
    publicMetrics,
    publicHealth,
    redactSecrets,
    stateFileMode,
    directoryMode,
    unifiedTargets,
    unifiedMcpRoutes,
    configProfile: profile,
    ...(source ? { configSourcePath: source.path } : {}),
    canonicalConfig,
    configDigest: canonicalConfigDigest(canonicalConfig),
  };
}

function parseCapabilityScopes(
  environmentValue: string | undefined,
  configured: readonly string[] | undefined,
): string[] {
  const scopes = environmentValue === undefined
    ? [...(configured ?? UNIFIED_CAPABILITY_SCOPES)]
    : parseStringList(environmentValue);
  const expected = new Set<string>(UNIFIED_CAPABILITY_SCOPES);
  const actual = new Set(scopes);
  if (actual.size !== expected.size || scopes.length !== expected.size
      || [...expected].some((scope) => !actual.has(scope))) {
    throw new Error(
      `OAuth capabilityScopes must be exactly: ${UNIFIED_CAPABILITY_SCOPES.join(", ")}`,
    );
  }
  return [...UNIFIED_CAPABILITY_SCOPES];
}

function assertExpectedToolNames(names: readonly string[]): void {
  const expected = new Set<string>(UNIFIED_EXPECTED_TOOL_NAMES);
  const actual = new Set(names);
  if (actual.size !== expected.size || names.length !== expected.size
      || [...expected].some((name) => !actual.has(name))) {
    throw new Error(`release.expectedToolNames must be the exact eight universal tools.`);
  }
}

function parseAuthorityMode(
  value: string | undefined,
): "enforced" | "audit" | "disabled" {
  const normalized = value?.trim() || "enforced";
  if (normalized === "enforced" || normalized === "audit" || normalized === "disabled") {
    return normalized;
  }
  throw new Error("authority.mode must be enforced, audit, or disabled.");
}

function parseSupervisorProcessManager(value: string | undefined): "pm2" {
  const normalized = value?.trim() || "pm2";
  if (normalized === "pm2") return normalized;
  throw new Error("supervisor.processManager must be pm2 in this build.");
}

function parseLogLevel(
  value: string | undefined,
  fallback: LoggingConfig["level"],
): LoggingConfig["level"] {
  const normalized = value?.trim() || fallback;
  if (["silent", "error", "warn", "info", "debug"].includes(normalized)) {
    return normalized as LoggingConfig["level"];
  }
  throw new Error(`Invalid DEVSPACE_LOG_LEVEL: ${normalized}`);
}

function normalizeConfiguredUrl(value: string, name: string): string {
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    throw new Error(`${name} must be an absolute HTTP or HTTPS URL.`);
  }
  if (!new Set(["http:", "https:"]).has(url.protocol)) {
    throw new Error(`${name} must use HTTP or HTTPS.`);
  }
  if (url.username || url.password || url.search || url.hash) {
    throw new Error(`${name} must not contain credentials, a query, or a fragment.`);
  }
  const pathname = url.pathname === "/" ? "" : url.pathname.replace(/\/+$/u, "");
  return `${url.origin}${pathname}`;
}

function assertPrivateEndpoint(value: string, name: string): void {
  if (value === "internal://pm2" || value.startsWith("unix://")) return;
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    throw new Error(`${name} must be a private HTTP(S), unix://, or internal endpoint.`);
  }
  const host = url.hostname.toLowerCase();
  if (host === "localhost" || host === "::1" || host === "[::1]" || host === "127.0.0.1"
      || host.startsWith("10.") || host.startsWith("192.168.") || isPrivate172(host)) return;
  throw new Error(`${name} must not be publicly reachable.`);
}

function isPrivate172(host: string): boolean {
  const match = /^172\.(\d{1,3})\./u.exec(host);
  if (!match) return false;
  const secondOctet = Number(match[1]);
  return secondOctet >= 16 && secondOctet <= 31;
}

function mergeDefinedEnvironment(
  base: NodeJS.ProcessEnv,
  overrides: NodeJS.ProcessEnv,
): NodeJS.ProcessEnv {
  const merged: NodeJS.ProcessEnv = { ...base };
  for (const [key, value] of Object.entries(overrides)) {
    if (value !== undefined) merged[key] = value;
  }
  return merged;
}

function freezeDeep<T>(value: T): T {
  if (value && typeof value === "object" && !Object.isFrozen(value)) {
    for (const child of Object.values(value as Record<string, unknown>)) freezeDeep(child);
    Object.freeze(value);
  }
  return value;
}

function parseAuthorityDeployment(value: string | undefined): "in-process" {
  const normalized = value?.trim() || "in-process";
  if (normalized === "in-process") return normalized;
  throw new Error("This BASE_SINGLE_OWNER build supports only in-process authority deployment.");
}

function parseCooperativeApprovalAssurance(value: string | undefined): "cooperative" {
  const normalized = value?.trim() || "cooperative";
  if (normalized === "cooperative") return normalized;
  throw new Error("This BASE_SINGLE_OWNER build supports only cooperative approval assurance.");
}

function parseInternalRateLimitMode(value: string | undefined): "internal" {
  const normalized = value?.trim() || "internal";
  if (normalized === "internal") return normalized;
  throw new Error("This BASE_SINGLE_OWNER build requires the internal rate limiter.");
}

function parseOptionalDigest(value: string | undefined): string | undefined {
  if (value === undefined) return undefined;
  const normalized = value.trim();
  if (!/^sha256:[a-f0-9]{64}$/u.test(normalized)) {
    throw new Error("DEVSPACE_BUILD_DIGEST must be a sha256: digest.");
  }
  return normalized;
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

function parseBoundedText(
  value: string | undefined,
  fallback: string,
  name: string,
  maximum: number,
): string {
  const normalized = value?.trim() || fallback;
  if (!normalized || normalized.length > maximum || /[\r\n\0]/u.test(normalized)) {
    throw new Error(`Invalid ${name}: expected 1 through ${maximum} single-line characters.`);
  }
  return normalized;
}

function parseOptionalBoundedText(
  value: string | undefined,
  name: string,
  maximum: number,
): string | undefined {
  if (value === undefined) return undefined;
  const normalized = value.trim();
  if (!normalized || normalized.length > maximum || /[\r\n\0]/u.test(normalized)) {
    throw new Error(`Invalid ${name}: expected 1 through ${maximum} single-line characters.`);
  }
  return normalized;
}

function parsePrincipalMode(value: string | undefined): PrincipalMode {
  const normalized = value?.trim() || "single-owner";
  if (normalized === "single-owner") return normalized;
  throw new Error(
    `Invalid DEVSPACE_NEXT_AUTHORITY_PRINCIPAL_MODE: ${normalized}; this build supports single-owner only`,
  );
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
