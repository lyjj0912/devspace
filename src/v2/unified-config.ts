import { createHash, randomBytes } from "node:crypto";
import {
  chmodSync,
  closeSync,
  existsSync,
  fsyncSync,
  mkdirSync,
  openSync,
  readFileSync,
  renameSync,
  unlinkSync,
  writeFileSync,
} from "node:fs";
import { dirname, extname, isAbsolute, join, resolve } from "node:path";
import { parse as parseYaml } from "yaml";
import * as z from "zod/v4";
import { expandHomePath } from "../roots.js";
import { BASE_PRODUCT_PROFILE } from "./build-capabilities.js";

const IDENTIFIER_PATTERN = /^[a-z][a-z0-9._-]{0,63}$/u;
const CONNECTOR_PATTERN = /^[A-Za-z][A-Za-z0-9._-]{0,127}$/u;

export const UNIFIED_CAPABILITY_SCOPES = [
  "devspace.read",
  "devspace.write",
  "devspace.exec",
  "devspace.mcp",
  "devspace.artifact",
  "devspace.gui",
] as const;

export const UNIFIED_EXPECTED_TOOL_NAMES = [
  "target",
  "context",
  "fs",
  "exec",
  "process",
  "mcp",
  "artifact",
  "gui",
] as const;

const positiveInteger = (maximum: number) => z.number().int().min(1).max(maximum);
const singleLine = (maximum: number) => z.string().trim().min(1).max(maximum).refine(
  (value) => !/[\r\n\0]/u.test(value),
  "must be a single-line value",
);
const pathText = singleLine(4_096);
const identifier = z.string().regex(IDENTIFIER_PATTERN);

const dataPlaneSchema = z.strictObject({
  host: singleLine(256).optional(),
  port: positiveInteger(65_535).optional(),
});

const managementPlaneSchema = z.strictObject({
  host: singleLine(256).optional(),
  port: positiveInteger(65_535).optional(),
  unixSocket: pathText.optional(),
}).superRefine((listener, context) => {
  const hasTcp = listener.host !== undefined || listener.port !== undefined;
  const hasUnix = listener.unixSocket !== undefined;
  if (hasTcp && hasUnix) {
    context.addIssue({ code: "custom", message: "managementPlane must select TCP or unixSocket, not both" });
  }
  if (listener.host !== undefined && listener.port === undefined) {
    context.addIssue({ code: "custom", path: ["port"], message: "port is required with host" });
  }
  if (listener.port !== undefined && listener.host === undefined) {
    context.addIssue({ code: "custom", path: ["host"], message: "host is required with port" });
  }
});

const serverSchema = z.strictObject({
  publicBaseUrl: z.url().optional(),
  mcpPath: z.string().startsWith("/").max(512).optional(),
  dataPlane: dataPlaneSchema.optional(),
  managementPlane: managementPlaneSchema.optional(),
  stagingPlane: dataPlaneSchema.optional(),
  canonicalConnectorName: z.string().regex(CONNECTOR_PATTERN).optional(),
  allowedHosts: z.array(singleLine(256)).max(256).optional(),
});

const oauthSchema = z.strictObject({
  issuer: z.url().optional(),
  resource: z.url().optional(),
  principalMode: z.literal("single-owner").optional(),
  ownerInstanceId: singleLine(512).optional(),
  capabilityScopes: z.array(singleLine(128)).max(32).optional(),
  allowOfflineAccess: z.boolean().optional(),
  legacyBlanketScopeCompatibility: z.literal(false).optional(),
  adminScopeEnabled: z.literal(false).optional(),
  allowAnonymousSessionFallback: z.literal(false).optional(),
});

const restartPolicySchema = z.strictObject({
  maximumAttempts: positiveInteger(100).optional(),
  maximumDelayMs: positiveInteger(600_000).optional(),
});

const supervisorSchema = z.strictObject({
  endpoint: z.union([z.url(), z.string().startsWith("unix://"), z.literal("internal://pm2")]).optional(),
  processManager: z.literal("pm2").optional(),
  processName: singleLine(128).optional(),
  expectedScript: pathText.optional(),
  transactionDirectory: pathText.optional(),
  healthTimeoutMs: positiveInteger(600_000).optional(),
  responseFlushRequired: z.literal(true).optional(),
  restartPolicy: restartPolicySchema.optional(),
});

const paginationSchema = z.strictObject({
  cursorTtlSeconds: positiveInteger(86_400).optional(),
  maximumSnapshotsPerPrincipal: positiveInteger(10_000).optional(),
  signingKeyRef: singleLine(512),
  previousSigningKeyRef: singleLine(512).optional(),
});

const artifactSchema = z.strictObject({
  catalogPath: pathText,
  objectRoot: pathText,
  defaultTtlSeconds: positiveInteger(86_400).optional(),
  maximumArtifactBytes: positiveInteger(10 * 1_024 * 1_024 * 1_024).optional(),
  maximumTotalBytes: positiveInteger(10 * 1_024 * 1_024 * 1_024).optional(),
});

const connectorSchema = z.strictObject({
  canonicalName: z.string().regex(CONNECTOR_PATTERN),
  installationEpoch: positiveInteger(Number.MAX_SAFE_INTEGER).optional(),
  drainGraceSeconds: positiveInteger(86_400).optional(),
});

const tokenBucketSchema = z.strictObject({
  refillPerMinute: positiveInteger(1_000_000),
  burst: positiveInteger(1_000_000),
});

const rateLimitSchema = z.strictObject({
  mode: z.literal("internal"),
  preAuth: tokenBucketSchema,
  postAuth: tokenBucketSchema,
  initialize: tokenBucketSchema,
});

const managementSchema = z.strictObject({
  bind: singleLine(256),
  port: positiveInteger(65_535),
  publicExposure: z.literal("deny"),
  authorizationKeyRef: pathText.optional(),
});

const auditSchema = z.strictObject({
  sink: pathText,
  flushIntervalMs: positiveInteger(60_000).optional(),
  rawArguments: z.literal(false).optional(),
});

const storageSchema = z.strictObject({
  root: pathText.optional(),
  stateDirectory: pathText.optional(),
  oauthStateDirectory: pathText.optional(),
  artifactRoot: pathText.optional(),
  processOutputRoot: pathText.optional(),
  sshControlDirectory: pathText.optional(),
  contextStore: pathText.optional(),
  contextWorktreeRoot: pathText.optional(),
  envProfileConfig: pathText.optional(),
  targetConfig: pathText.optional(),
  mcpRouteConfig: pathText.optional(),
  stateFileMode: z.literal("0600").optional(),
  directoryMode: z.literal("0700").optional(),
});

const quotasSchema = z.strictObject({
  contexts: positiveInteger(10_000).optional(),
  mcpConnections: positiveInteger(256).optional(),
  mcpRetainedResultBytes: positiveInteger(10 * 1_024 * 1_024 * 1_024).optional(),
  guiSessions: positiveInteger(1_000).optional(),
  artifacts: positiveInteger(10_000).optional(),
  inlineOutputBytes: positiveInteger(100_000_000).optional(),
  artifactMaxBytes: positiveInteger(10 * 1_024 * 1_024 * 1_024).optional(),
});

const processSchema = z.strictObject({
  maximumRunningTotal: positiveInteger(10_000).optional(),
  maximumRunningPerTarget: positiveInteger(10_000).optional(),
  terminalRetentionTtlSeconds: positiveInteger(7 * 24 * 60 * 60).optional(),
  maximumRetainedTerminalRecords: positiveInteger(100_000).optional(),
  maximumOutputBytesPerProcess: positiveInteger(10 * 1_024 * 1_024 * 1_024).optional(),
  terminalOverflowPolicy: z.literal("prune-oldest").optional(),
  internalRunnerMaximumConcurrent: positiveInteger(1_000).optional(),
});

const ttlSchema = z.strictObject({
  contextSeconds: positiveInteger(86_400).optional(),
  completedProcessSeconds: positiveInteger(86_400).optional(),
  mcpIdleSeconds: positiveInteger(3_600).optional(),
  mcpRetainedResultSeconds: positiveInteger(86_400).optional(),
  guiSeconds: positiveInteger(86_400).optional(),
  artifactSeconds: positiveInteger(86_400).optional(),
  cursorSnapshotSeconds: positiveInteger(86_400).optional(),
});

const capabilitiesSchema = z.strictObject({
  fs: z.boolean().optional(),
  exec: z.boolean().optional(),
  pty: z.boolean().optional(),
  mcp: z.boolean().optional(),
  artifact: z.boolean().optional(),
  gui: z.boolean().optional(),
  durableProcess: z.boolean().optional(),
});

const targetSchema = z.strictObject({
  targetId: identifier,
  displayName: singleLine(128),
  aliases: z.array(identifier).max(64).optional(),
  aliasOf: identifier.optional(),
  endpointId: singleLine(128).optional(),
  transport: z.enum(["local", "ssh"]),
  host: singleLine(512).optional(),
  user: singleLine(256).optional(),
  platform: z.enum(["macos", "linux", "windows", "unknown"]),
  defaultCwd: pathText.optional(),
  elevationPolicy: singleLine(32),
  capabilities: capabilitiesSchema.optional(),
}).superRefine((target, context) => {
  if (target.transport === "ssh" && !target.host) {
    context.addIssue({ code: "custom", path: ["host"], message: "host is required for SSH targets" });
  }
});

const routeTransportSchema = z.strictObject({
  type: z.enum(["local-stdio", "ssh-stdio", "streamable-http"]),
  targetId: identifier.optional(),
  command: singleLine(4_096).optional(),
  args: z.array(z.string().max(4_096)).max(256).optional(),
  url: z.url().optional(),
}).superRefine((transport, context) => {
  if ((transport.type === "local-stdio" || transport.type === "ssh-stdio") && !transport.command) {
    context.addIssue({ code: "custom", path: ["command"], message: "command is required for stdio transports" });
  }
  if (transport.type === "local-stdio" && transport.command && !isAbsolute(transport.command)) {
    context.addIssue({ code: "custom", path: ["command"], message: "local-stdio command must be absolute" });
  }
  if (transport.type === "ssh-stdio" && transport.command && !transport.command.startsWith("/")) {
    context.addIssue({ code: "custom", path: ["command"], message: "ssh-stdio command must be an absolute remote path" });
  }
  if (transport.type === "ssh-stdio" && !transport.targetId) {
    context.addIssue({ code: "custom", path: ["targetId"], message: "targetId is required for ssh-stdio" });
  }
  if (transport.type === "streamable-http" && !transport.url) {
    context.addIssue({ code: "custom", path: ["url"], message: "url is required for streamable-http" });
  }
});

const routeRiskPolicySchema = z.strictObject({
  mode: z.literal("broker-owned"),
  policyFile: pathText,
});

const routeSchema = z.strictObject({
  routeId: identifier,
  displayName: singleLine(128),
  aliases: z.array(identifier).max(64).optional(),
  enabled: z.boolean().optional(),
  targetId: identifier.optional(),
  transport: routeTransportSchema,
  riskPolicy: routeRiskPolicySchema.optional(),
  idleTtlSeconds: positiveInteger(3_600).optional(),
  connectTimeoutMs: positiveInteger(300_000).optional(),
  invokeTimeoutMs: positiveInteger(300_000).optional(),
});

const observabilitySchema = z.strictObject({
  publicHealth: z.boolean().optional(),
  publicMetrics: z.literal(false).optional(),
  logLevel: z.enum(["silent", "error", "warn", "info", "debug"]).optional(),
  redactSecrets: z.boolean().optional(),
});

const releaseSchema = z.strictObject({
  expectedToolNames: z.array(singleLine(128)).max(64).optional(),
  expectedTargetIdsFile: pathText.optional(),
  requireCleanSource: z.boolean().optional(),
  requireRuntimeBuildDigestMatch: z.boolean().optional(),
  requireHostSessionChurnCanary: z.boolean().optional(),
  forbidParallelRuntime: z.boolean().optional(),
  forbidLegacyScopes: z.boolean().optional(),
  forbidPrivilegedArtifacts: z.boolean().optional(),
});

export const unifiedConfigSchema = z.strictObject({
  version: z.literal(2),
  productProfile: z.literal(BASE_PRODUCT_PROFILE),
  profile: z.enum(["development", "production"]).optional(),
  deploymentMode: z.enum(["parallel", "production"]).optional(),
  server: serverSchema.optional(),
  oauth: oauthSchema.optional(),
  supervisor: supervisorSchema.optional(),
  pagination: paginationSchema.optional(),
  artifact: artifactSchema.optional(),
  connector: connectorSchema.optional(),
  rateLimit: rateLimitSchema.optional(),
  management: managementSchema.optional(),
  audit: auditSchema.optional(),
  storage: storageSchema.optional(),
  process: processSchema.optional(),
  quotas: quotasSchema.optional(),
  ttls: ttlSchema.optional(),
  targets: z.array(targetSchema).max(10_000).optional(),
  mcpRoutes: z.array(routeSchema).max(10_000).optional(),
  observability: observabilitySchema.optional(),
  release: releaseSchema.optional(),
}).superRefine((config, context) => {
  if (
    config.profile !== undefined
    && config.deploymentMode !== undefined
    && (config.profile === "production") !== (config.deploymentMode === "production")
  ) {
    context.addIssue({
      code: "custom",
      path: ["deploymentMode"],
      message: "deploymentMode conflicts with profile",
    });
  }
});

export type UnifiedConfigDocument = z.infer<typeof unifiedConfigSchema>;
export type UnifiedTargetConfig = NonNullable<UnifiedConfigDocument["targets"]>[number];
export type UnifiedMcpRouteConfig = NonNullable<UnifiedConfigDocument["mcpRoutes"]>[number];

export interface UnifiedConfigSource {
  path: string;
  document: UnifiedConfigDocument;
}

export interface MaterializedUnifiedRegistries {
  targetConfigPath?: string;
  mcpRouteConfigPath?: string;
}

export function loadUnifiedConfigSource(
  env: NodeJS.ProcessEnv,
  configDirectory: string,
): UnifiedConfigSource | undefined {
  const explicit = firstDefined(
    env.DEVSPACE_V2_CONFIG_FILE,
    env.DEVSPACE_NEXT_CONFIG_FILE,
    env.DEVSPACE_UNIFIED_CONFIG_FILE,
  );
  let configPath: string | undefined;
  if (explicit) {
    configPath = resolve(expandHomePath(explicit));
    if (!existsSync(configPath)) {
      throw new Error(`Unified configuration file does not exist: ${configPath}`);
    }
  } else {
    const candidates = [
      join(configDirectory, "config.yaml"),
      join(configDirectory, "config.yml"),
      join(configDirectory, "config.v2.json"),
    ].filter((candidate) => existsSync(candidate));
    if (candidates.length > 1) {
      throw new Error(`Multiple unified configuration files found: ${candidates.join(", ")}`);
    }
    configPath = candidates[0];
  }
  if (!configPath) return undefined;

  const content = readFileSync(configPath, "utf8");
  let input: unknown;
  try {
    input = extname(configPath).toLowerCase() === ".json"
      ? JSON.parse(content)
      : parseYaml(content, { uniqueKeys: true });
  } catch (error) {
    throw new Error(`Unable to parse unified configuration ${configPath}: ${errorMessage(error)}`);
  }
  const parsed = unifiedConfigSchema.safeParse(input);
  if (!parsed.success) {
    const issues = parsed.error.issues
      .slice(0, 20)
      .map((issue) => `${issue.path.join(".") || "config"}: ${issue.message}`)
      .join("; ");
    throw new Error(`Invalid unified configuration ${configPath}: ${issues}`);
  }
  validateUnifiedReferences(parsed.data, configPath);
  return {
    path: configPath,
    document: deepFreeze(parsed.data),
  };
}

export function unifiedConfigEnvironment(
  source: UnifiedConfigSource,
): NodeJS.ProcessEnv {
  const config = source.document;
  const storageRoot = config.storage?.root
    ? resolve(expandHomePath(config.storage.root))
    : dirname(source.path);
  const stateDirectory = config.storage?.stateDirectory
    ?? (config.storage?.root ? join(storageRoot, "state") : undefined);
  const profileMode = config.profile === "production" ? "production" : "parallel";
  const deploymentMode = config.deploymentMode ?? profileMode;
  const values: NodeJS.ProcessEnv = {
    DEVSPACE_CONFIG_DIR: dirname(source.path),
    DEVSPACE_V2_DEPLOYMENT_MODE: deploymentMode,
    DEVSPACE_NEXT_HOST: config.server?.dataPlane?.host,
    DEVSPACE_NEXT_PORT: numberText(config.server?.dataPlane?.port),
    DEVSPACE_NEXT_MANAGEMENT_HOST: config.management?.bind ?? config.server?.managementPlane?.host,
    DEVSPACE_NEXT_MANAGEMENT_PORT: numberText(config.management?.port ?? config.server?.managementPlane?.port),
    DEVSPACE_NEXT_MANAGEMENT_AUTHORIZATION_KEY_REF: config.management?.authorizationKeyRef,
    DEVSPACE_NEXT_PUBLIC_BASE_URL: config.server?.publicBaseUrl,
    DEVSPACE_NEXT_MCP_PATH: config.server?.mcpPath,
    DEVSPACE_NEXT_ALLOWED_HOSTS: config.server?.allowedHosts?.join(","),
    DEVSPACE_NEXT_CANONICAL_CONNECTOR_NAME:
      config.connector?.canonicalName ?? config.server?.canonicalConnectorName,
    DEVSPACE_OAUTH_OWNER_INSTANCE_ID: config.oauth?.ownerInstanceId,
    DEVSPACE_V2_LEGACY_SCOPE_COMPATIBILITY: booleanText(config.oauth?.legacyBlanketScopeCompatibility),
    DEVSPACE_NEXT_STATE_DIR: stateDirectory,
    DEVSPACE_NEXT_OAUTH_STATE_DIR: config.storage?.oauthStateDirectory,
    DEVSPACE_NEXT_TARGETS_FILE: config.storage?.targetConfig,
    DEVSPACE_NEXT_MCP_ROUTES_FILE: config.storage?.mcpRouteConfig,
    DEVSPACE_NEXT_CONTEXT_STORE: config.storage?.contextStore,
    DEVSPACE_NEXT_ENV_PROFILE_CONFIG: config.storage?.envProfileConfig,
    DEVSPACE_NEXT_CONTEXT_WORKTREE_ROOT: config.storage?.contextWorktreeRoot,
    DEVSPACE_NEXT_PROCESS_OUTPUT_DIR: config.storage?.processOutputRoot,
    DEVSPACE_NEXT_SSH_CONTROL_DIR: config.storage?.sshControlDirectory,
    DEVSPACE_NEXT_ARTIFACT_STAGING_DIR: config.storage?.artifactRoot,
    DEVSPACE_NEXT_ARTIFACT_CATALOG: config.artifact?.catalogPath,
    DEVSPACE_NEXT_ARTIFACT_OBJECT_ROOT: config.artifact?.objectRoot,
    DEVSPACE_NEXT_SELF_MANAGEMENT_DIR: config.supervisor?.transactionDirectory,
    DEVSPACE_NEXT_PM2_PROCESS_NAME: config.supervisor?.processName,
    DEVSPACE_NEXT_PM2_EXPECTED_SCRIPT: config.supervisor?.expectedScript,
    DEVSPACE_NEXT_SELF_RESTART_TIMEOUT_MS: numberText(config.supervisor?.healthTimeoutMs),
    DEVSPACE_NEXT_CURSOR_TTL_MS: secondsAsMilliseconds(config.pagination?.cursorTtlSeconds),
    DEVSPACE_NEXT_CURSOR_MAXIMUM_SNAPSHOTS_PER_PRINCIPAL:
      numberText(config.pagination?.maximumSnapshotsPerPrincipal),
    DEVSPACE_NEXT_CURSOR_SIGNING_KEY_REF: config.pagination?.signingKeyRef,
    DEVSPACE_NEXT_CURSOR_PREVIOUS_SIGNING_KEY_REF: config.pagination?.previousSigningKeyRef,
    DEVSPACE_NEXT_CONTEXT_MAXIMUM_ENTRIES: numberText(config.quotas?.contexts),
    DEVSPACE_NEXT_MAXIMUM_PROCESS_RECORDS: numberText(config.process?.maximumRetainedTerminalRecords),
    DEVSPACE_NEXT_MAX_RUNNING_PROCESSES: numberText(config.process?.maximumRunningTotal),
    DEVSPACE_NEXT_MAX_RUNNING_PROCESSES_PER_TARGET: numberText(config.process?.maximumRunningPerTarget),
    DEVSPACE_NEXT_INTERNAL_RUNNER_MAXIMUM_CONCURRENT:
      numberText(config.process?.internalRunnerMaximumConcurrent),
    DEVSPACE_NEXT_PROCESS_BUFFER_CHARACTERS: numberText(config.quotas?.inlineOutputBytes),
    DEVSPACE_NEXT_PROCESS_OUTPUT_MAX_BYTES: numberText(config.process?.maximumOutputBytesPerProcess),
    DEVSPACE_NEXT_DOWNSTREAM_MCP_MAXIMUM_SESSIONS: numberText(config.quotas?.mcpConnections),
    DEVSPACE_NEXT_MCP_RESULT_MAXIMUM_BYTES: numberText(config.quotas?.mcpRetainedResultBytes),
    DEVSPACE_NEXT_GUI_MAXIMUM_SESSIONS: numberText(config.quotas?.guiSessions),
    DEVSPACE_NEXT_ARTIFACT_MAXIMUM_ENTRIES: numberText(config.quotas?.artifacts),
    DEVSPACE_NEXT_ARTIFACT_MAXIMUM_TOTAL_BYTES:
      numberText(config.artifact?.maximumTotalBytes ?? config.quotas?.artifactMaxBytes),
    DEVSPACE_NEXT_ARTIFACT_MAXIMUM_FILE_BYTES:
      numberText(config.artifact?.maximumArtifactBytes ?? config.quotas?.artifactMaxBytes),
    DEVSPACE_NEXT_CONTEXT_IDLE_TTL_MS: secondsAsMilliseconds(config.ttls?.contextSeconds),
    DEVSPACE_NEXT_COMPLETED_PROCESS_TTL_MS: secondsAsMilliseconds(
      config.process?.terminalRetentionTtlSeconds ?? config.ttls?.completedProcessSeconds,
    ),
    DEVSPACE_NEXT_DOWNSTREAM_MCP_SESSION_IDLE_TTL_MS: secondsAsMilliseconds(config.ttls?.mcpIdleSeconds),
    DEVSPACE_NEXT_GUI_SESSION_TTL_MS: secondsAsMilliseconds(config.ttls?.guiSeconds),
    DEVSPACE_NEXT_ARTIFACT_TTL_MS:
      secondsAsMilliseconds(config.artifact?.defaultTtlSeconds ?? config.ttls?.artifactSeconds),
    DEVSPACE_NEXT_CONTEXT_DIFF_TTL_MS: secondsAsMilliseconds(config.ttls?.cursorSnapshotSeconds),
    DEVSPACE_NEXT_MCP_RESULT_TTL_MS: secondsAsMilliseconds(config.ttls?.mcpRetainedResultSeconds),
    DEVSPACE_LOG_LEVEL: config.observability?.logLevel,
    DEVSPACE_OAUTH_CONNECTOR_INSTALLATION_EPOCH:
      numberText(config.connector?.installationEpoch),
    DEVSPACE_NEXT_CONNECTOR_DRAIN_GRACE_SECONDS: numberText(config.connector?.drainGraceSeconds),
    DEVSPACE_NEXT_RATE_LIMIT_MODE: config.rateLimit?.mode,
    DEVSPACE_NEXT_RATE_LIMIT_PRE_AUTH_REFILL_PER_MINUTE:
      numberText(config.rateLimit?.preAuth.refillPerMinute),
    DEVSPACE_NEXT_RATE_LIMIT_PRE_AUTH_BURST: numberText(config.rateLimit?.preAuth.burst),
    DEVSPACE_NEXT_RATE_LIMIT_POST_AUTH_REFILL_PER_MINUTE:
      numberText(config.rateLimit?.postAuth.refillPerMinute),
    DEVSPACE_NEXT_RATE_LIMIT_POST_AUTH_BURST: numberText(config.rateLimit?.postAuth.burst),
    DEVSPACE_NEXT_RATE_LIMIT_INITIALIZE_REFILL_PER_MINUTE:
      numberText(config.rateLimit?.initialize.refillPerMinute),
    DEVSPACE_NEXT_RATE_LIMIT_INITIALIZE_BURST: numberText(config.rateLimit?.initialize.burst),
    DEVSPACE_NEXT_AUDIT_SINK: config.audit?.sink,
    DEVSPACE_NEXT_AUDIT_FLUSH_INTERVAL_MS: numberText(config.audit?.flushIntervalMs),
  };
  return Object.fromEntries(Object.entries(values).filter((entry): entry is [string, string] => entry[1] !== undefined));
}

export function canonicalConfigDigest(value: unknown): string {
  return `sha256:${createHash("sha256").update(canonicalJson(value)).digest("hex")}`;
}

/**
 * Bridges the v2 unified arrays to the existing strict registry readers without
 * creating a second user-authored source of truth. Generated files are private,
 * fsynced, and atomically replaced in the v2 state directory.
 */
export function materializeUnifiedRegistries(
  source: UnifiedConfigSource,
  stateDirectory: string,
): MaterializedUnifiedRegistries {
  if (source.document.targets === undefined && source.document.mcpRoutes === undefined) return {};
  const directory = resolve(stateDirectory, "generated-config");
  mkdirSync(directory, { recursive: true, mode: 0o700 });
  chmodSync(directory, 0o700);
  const result: MaterializedUnifiedRegistries = {};
  if (source.document.targets !== undefined) {
    const targetConfigPath = join(directory, "targets.v1.json");
    atomicWriteOwnerOnly(targetConfigPath, `${canonicalJson(materializedTargetFile(source.document.targets))}\n`);
    result.targetConfigPath = targetConfigPath;
  }
  if (source.document.mcpRoutes !== undefined) {
    const mcpRouteConfigPath = join(directory, "mcp-routes.v1.json");
    atomicWriteOwnerOnly(
      mcpRouteConfigPath,
      `${canonicalJson(materializedRouteFile(source.document.mcpRoutes))}\n`,
    );
    result.mcpRouteConfigPath = mcpRouteConfigPath;
  }
  fsyncDirectory(directory);
  return result;
}

export function canonicalJson(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  if (value && typeof value === "object") {
    return `{${Object.entries(value as Record<string, unknown>)
      .filter(([, child]) => child !== undefined)
      .sort(([left], [right]) => left < right ? -1 : left > right ? 1 : 0)
      .map(([key, child]) => `${JSON.stringify(key)}:${canonicalJson(child)}`)
      .join(",")}}`;
  }
  return JSON.stringify(value) ?? "null";
}

function validateUnifiedReferences(config: UnifiedConfigDocument, configPath: string): void {
  const targets = config.targets ?? [];
  const targetIds = new Set<string>();
  const targetSelectors = new Map<string, string>();
  for (const target of targets) {
    if (targetIds.has(target.targetId)) {
      throw new Error(`Invalid unified configuration ${configPath}: duplicate targetId ${target.targetId}`);
    }
    targetIds.add(target.targetId);
    registerSelector(targetSelectors, target.targetId, target.targetId, "target", configPath);
    for (const alias of target.aliases ?? []) {
      registerSelector(targetSelectors, alias, target.targetId, "target", configPath);
    }
    if (target.elevationPolicy !== "deny") {
      throw new Error(
        `Invalid unified configuration ${configPath}: target ${target.targetId} elevationPolicy must be deny`,
      );
    }
  }
  for (const target of targets) {
    if (target.aliasOf && !targetIds.has(target.aliasOf)) {
      throw new Error(
        `Invalid unified configuration ${configPath}: target ${target.targetId} references unknown target ${target.aliasOf}`,
      );
    }
  }
  assertNoAliasCycle(targets, configPath);
  const targetById = new Map(targets.map((target) => [target.targetId, target]));
  for (const target of targets) {
    if (!target.aliasOf) continue;
    const parent = targetById.get(target.aliasOf)!;
    const parentEndpointId = effectiveEndpointId(parent, targetById);
    if (target.endpointId !== undefined && target.endpointId !== parentEndpointId) {
      throw new Error(
        `Invalid unified configuration ${configPath}: alias target ${target.targetId} must share endpointId ${parentEndpointId}`,
      );
    }
    const endpointParent = effectiveEndpointTarget(parent, targetById);
    if (target.transport !== endpointParent.transport
        || target.platform !== endpointParent.platform
        || (target.host !== undefined && target.host !== endpointParent.host)) {
      throw new Error(
        `Invalid unified configuration ${configPath}: alias target ${target.targetId} must inherit transport, host, and platform from ${target.aliasOf}`,
      );
    }
  }

  const routeIds = new Set<string>();
  const routeSelectors = new Map<string, string>();
  for (const route of config.mcpRoutes ?? []) {
    if (routeIds.has(route.routeId)) {
      throw new Error(`Invalid unified configuration ${configPath}: duplicate routeId ${route.routeId}`);
    }
    routeIds.add(route.routeId);
    registerSelector(routeSelectors, route.routeId, route.routeId, "route", configPath);
    for (const alias of route.aliases ?? []) {
      registerSelector(routeSelectors, alias, route.routeId, "route", configPath);
    }
    const routeTarget = route.targetId;
    const transportTarget = route.transport.targetId;
    if (routeTarget && transportTarget && routeTarget !== transportTarget) {
      throw new Error(
        `Invalid unified configuration ${configPath}: route ${route.routeId} has conflicting target references`,
      );
    }
    const targetReference = routeTarget ?? transportTarget;
    if (targetReference && !targetIds.has(targetReference)) {
      throw new Error(
        `Invalid unified configuration ${configPath}: route ${route.routeId} references unknown target ${targetReference}`,
      );
    }
  }
}

function materializedTargetFile(targets: readonly UnifiedTargetConfig[]): Record<string, unknown> {
  const targetById = new Map(targets.map((target) => [target.targetId, target]));
  const entries = [...targets]
    .sort((left, right) => left.targetId.localeCompare(right.targetId))
    .map((target) => {
      const endpointTarget = effectiveEndpointTarget(target, targetById);
      const capabilities = target.capabilities ?? endpointTarget.capabilities;
      const guiEnabled = capabilities?.gui === true;
      const durableEnabled = capabilities?.durableProcess === true;
      const value = {
        displayName: target.displayName,
        aliases: [...(target.aliases ?? [])],
        endpointId: effectiveEndpointId(target, targetById),
        transport: endpointTarget.transport,
        ...(endpointTarget.transport === "ssh" ? { sshHost: endpointTarget.host } : {}),
        ...(target.user ?? endpointTarget.user ? { user: target.user ?? endpointTarget.user } : {}),
        platform: endpointTarget.platform,
        ...(target.defaultCwd ?? endpointTarget.defaultCwd
          ? { defaultCwd: target.defaultCwd ?? endpointTarget.defaultCwd }
          : {}),
        ...(capabilities ? { capabilities: { ...capabilities } } : {}),
        gui: {
          mode: guiEnabled
            ? endpointTarget.transport === "local" ? "local-ipc" : "ssh-stdio"
            : "none",
        },
        durableProcess: {
          mode: durableEnabled
            ? endpointTarget.platform === "windows"
              ? "task-scheduler"
              : endpointTarget.platform === "macos"
                ? "launchd"
                : "systemd-run"
            : "none",
        },
      };
      return [target.targetId, value] as const;
    });
  return { version: 1, targets: Object.fromEntries(entries) };
}

function materializedRouteFile(routes: readonly UnifiedMcpRouteConfig[]): Record<string, unknown> {
  const entries = routes
    .filter((route) => route.enabled !== false)
    .sort((left, right) => left.routeId.localeCompare(right.routeId))
    .map((route) => {
      const target = route.targetId ?? route.transport.targetId;
      return [route.routeId, {
        displayName: route.displayName,
        aliases: [...(route.aliases ?? [])],
        transport: route.transport.type,
        ...(target ? { target } : {}),
        ...(route.transport.command ? { command: route.transport.command } : {}),
        args: [...(route.transport.args ?? [])],
        ...(route.transport.url ? { url: route.transport.url } : {}),
        ...(route.riskPolicy ? { riskPolicy: { ...route.riskPolicy } } : {}),
        startupTimeoutMs: route.connectTimeoutMs ?? 15_000,
        callTimeoutMs: route.invokeTimeoutMs ?? 120_000,
        idleTimeoutMs: (route.idleTtlSeconds ?? 900) * 1_000,
      }] as const;
    });
  return { version: 1, routes: Object.fromEntries(entries) };
}

function effectiveEndpointTarget(
  target: UnifiedTargetConfig,
  targets: ReadonlyMap<string, UnifiedTargetConfig>,
): UnifiedTargetConfig {
  let current = target;
  while (current.aliasOf) current = targets.get(current.aliasOf)!;
  return current;
}

function effectiveEndpointId(
  target: UnifiedTargetConfig,
  targets: ReadonlyMap<string, UnifiedTargetConfig>,
): string {
  const endpointTarget = effectiveEndpointTarget(target, targets);
  return endpointTarget.endpointId ?? endpointTarget.targetId;
}

function atomicWriteOwnerOnly(destination: string, content: string): void {
  if (existsSync(destination)) {
    const current = readFileSync(destination, "utf8");
    if (current === content) {
      chmodSync(destination, 0o600);
      return;
    }
  }
  const stagingPath = `${destination}.stage-${process.pid}-${randomBytes(8).toString("hex")}`;
  let descriptor: number | undefined;
  try {
    descriptor = openSync(stagingPath, "wx", 0o600);
    writeFileSync(descriptor, content, "utf8");
    fsyncSync(descriptor);
    closeSync(descriptor);
    descriptor = undefined;
    renameSync(stagingPath, destination);
    chmodSync(destination, 0o600);
  } catch (error) {
    if (descriptor !== undefined) closeSync(descriptor);
    try {
      unlinkSync(stagingPath);
    } catch {
      // The staging path may already have been atomically published.
    }
    throw error;
  }
}

function fsyncDirectory(directory: string): void {
  const descriptor = openSync(directory, "r");
  try {
    fsyncSync(descriptor);
  } finally {
    closeSync(descriptor);
  }
}

function registerSelector(
  selectors: Map<string, string>,
  selector: string,
  owner: string,
  kind: "target" | "route",
  configPath: string,
): void {
  const normalized = selector.toLowerCase();
  const existing = selectors.get(normalized);
  if (existing !== undefined) {
    throw new Error(
      `Invalid unified configuration ${configPath}: duplicate ${kind} selector ${selector} (${existing}, ${owner})`,
    );
  }
  selectors.set(normalized, owner);
}

function assertNoAliasCycle(targets: readonly UnifiedTargetConfig[], configPath: string): void {
  const parents = new Map(targets.map((target) => [target.targetId, target.aliasOf]));
  const complete = new Set<string>();
  for (const target of targets) {
    const active = new Set<string>();
    let current: string | undefined = target.targetId;
    while (current && !complete.has(current)) {
      if (active.has(current)) {
        throw new Error(`Invalid unified configuration ${configPath}: target alias cycle includes ${current}`);
      }
      active.add(current);
      current = parents.get(current);
    }
    for (const visited of active) complete.add(visited);
  }
}

function firstDefined(...values: Array<string | undefined>): string | undefined {
  for (const value of values) {
    const normalized = value?.trim();
    if (normalized) return normalized;
  }
  return undefined;
}

function numberText(value: number | undefined): string | undefined {
  return value === undefined ? undefined : String(value);
}

function booleanText(value: boolean | undefined): string | undefined {
  return value === undefined ? undefined : String(value);
}

function secondsAsMilliseconds(value: number | undefined): string | undefined {
  return value === undefined ? undefined : String(value * 1_000);
}

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

function deepFreeze<T>(value: T): T {
  if (value && typeof value === "object" && !Object.isFrozen(value)) {
    for (const child of Object.values(value as Record<string, unknown>)) deepFreeze(child);
    Object.freeze(value);
  }
  return value;
}
