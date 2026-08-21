import { execFile } from "node:child_process";
import { createHash, randomBytes, randomUUID, timingSafeEqual } from "node:crypto";
import { chmodSync, mkdirSync } from "node:fs";
import { mkdir, rm, writeFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import { promisify } from "node:util";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { hostHeaderValidation } from "@modelcontextprotocol/sdk/server/middleware/hostHeaderValidation.js";
import { mcpAuthRouter, getOAuthProtectedResourceMetadataUrl } from "@modelcontextprotocol/sdk/server/auth/router.js";
import { requireBearerAuth } from "@modelcontextprotocol/sdk/server/auth/middleware/bearerAuth.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import { isInitializeRequest } from "@modelcontextprotocol/sdk/types.js";
import { checkResourceAllowed, resourceUrlFromServerUrl } from "@modelcontextprotocol/sdk/shared/auth-utils.js";
import express, { type Express, type Request, type Response } from "express";
import { loadConfig, type ServerConfig } from "../config.js";
import { databasePath } from "../db/client.js";
import {
  mainDatabaseMigrationManifest,
  readMainDatabaseMigrationReadback,
} from "../db/migrations.js";
import type { IncomingArtifactAdapter } from "../incoming-artifacts.js";
import {
  logEvent,
  requestIp,
  requestPath,
  sessionIdPrefix,
} from "../logger.js";
import {
  McpSessionRegistry,
  type McpSessionCloseResult,
} from "../mcp-sessions.js";
import { SingleUserOAuthProvider } from "../oauth-provider.js";
import { UniversalArtifactService } from "./artifact-service.js";
import { OperationAuthorityRegistry } from "./authority.js";
import { resolveAuthorityPrincipal } from "./authority-principal.js";
import {
  authorityActionFromToolCall,
  minimumAuthorityRisk,
} from "./authority-policy.js";
import { buildCapabilityContract } from "./build-capabilities.js";
import { ContextRegistry } from "./contexts.js";
import { SignedSnapshotCursorStore } from "./cursor-capability.js";
import { loadCursorSigningKeyRing } from "./cursor-signing-key.js";
import { UniversalExecutionPlane } from "./execution.js";
import { UniversalEnvProfileRegistry } from "./env-profiles.js";
import { UniversalFilesystemService } from "./filesystem.js";
import {
  type GuiNodeRunner,
  UniversalGuiService,
} from "./gui.js";
import { UniversalMcpProxy } from "./mcp-proxy.js";
import { UniversalMcpResultStore } from "./mcp-result-store.js";
import { SignedResourceContinuation } from "./resource-continuation.js";
import {
  isManagementAuthorized,
  loadOrCreateManagementAuthorizationKey,
} from "./management-authorization.js";
import { assertServiceAccountBoundary } from "./no-elevation.js";
import { UniversalMcpRouteRegistry } from "./mcp-routes.js";
import { UniversalBrokerMetrics } from "./metrics.js";
import { OperationAuditSink } from "./operation-audit.js";
import {
  BrokerRateLimiter,
  trustedLoopbackProxyHopCount,
  type BrokerRateLimitPolicy,
  type RateLimitDecision,
} from "./rate-limit.js";
import {
  ReadinessRegistry,
  baseMutableSqliteStoreReadiness,
  canonicalConnectorReadinessObservation,
  readablePathReadiness,
  runtimeCapabilityIdentityReadiness,
  type ReadinessCheckObservation,
} from "./readiness.js";
import {
  BoundedDeepDoctor,
  type DeepDoctorCheck,
  type DeepDoctorCheckObservation,
} from "./doctor.js";
import { createUniversalBrokerMcpServer } from "./server.js";
import { UniversalSelfManagementService } from "./self-management.js";
import { captureSnapshotGroup } from "./snapshot-group.js";
import { TargetRegistry } from "./targets.js";
import { UniversalTextResourceStore } from "./text-resource-store.js";
import { SqliteConnectorActivationRecoveryJournal } from "./connector-activation-journal.js";
import {
  createFinalizationStoreBootstrapAuthorization,
  initializeFinalizationStore,
} from "../../scripts/lib/finalization-store-contract.mjs";
import { connectorProductionRouteIdentityReadback } from "./connector-route-identity.js";
import { configureResultEnvelopeIdentity } from "./errors.js";
import {
  createRuntimeIdentity,
  publicRuntimeHealth,
} from "./runtime-identity.js";
import type { RuntimeIdentity } from "./contracts.js";
import {
  baseMutableSqliteStoreRequirements,
  ensureFilesystemSyncSqliteSchemaV1,
  universalBrokerStoreMigrationManifest,
  universalBrokerStoreMigrationManifestDigest,
} from "./migration-registry.js";
import {
  joinPublicUrl,
  loadUniversalBrokerNextConfig,
  type UniversalBrokerNextConfig,
} from "./config.js";

type NextTransport = StreamableHTTPServerTransport;
const MAXIMUM_HTTP_JSON_BYTES = 2 * 1024 * 1024;
const SAFE_SESSIONLESS_DISCOVERY_METHODS = new Set([
  "notifications/initialized",
  "tools/list",
]);
const DEEP_DOCTOR_RATE_CANARY_CLEANUP_BINDING = "deep-doctor-rate-canary-v1";
const DEEP_DOCTOR_PUBLIC_PROBE_HEADER = "x-devspace-internal-doctor-probe";
const BASE64URL_256_BIT_VALUE = /^[A-Za-z0-9_-]{43}$/u;
const execFileAsync = promisify(execFile);

function jsonRpcMethods(body: unknown): string[] {
  const messages = Array.isArray(body) ? body : [body];
  return messages.flatMap((message) => {
    if (!message || typeof message !== "object") return [];
    const method = (message as { method?: unknown }).method;
    return typeof method === "string" ? [method] : [];
  });
}

function jsonRpcRequestIds(body: unknown): Array<string | number> {
  const messages = Array.isArray(body) ? body : [body];
  return messages.flatMap((message) => {
    if (!message || typeof message !== "object") return [];
    const id = (message as { id?: unknown }).id;
    return typeof id === "string" || typeof id === "number" ? [id] : [];
  });
}

function isSafeSessionlessDiscoveryRequest(methods: readonly string[]): boolean {
  return methods.length > 0
    && methods.every((method) => SAFE_SESSIONLESS_DISCOVERY_METHODS.has(method));
}

export interface RunningUniversalBrokerNextServer {
  app: Express;
  managementApp: Express;
  config: UniversalBrokerNextConfig;
  runtimeIdentity: RuntimeIdentity;
  targets: TargetRegistry;
  contexts: ContextRegistry;
  execution: UniversalExecutionPlane;
  filesystem: UniversalFilesystemService;
  mcpRoutes: UniversalMcpRouteRegistry;
  mcpProxy: UniversalMcpProxy;
  artifacts: UniversalArtifactService;
  gui: UniversalGuiService;
  authority: OperationAuthorityRegistry;
  selfManagement: UniversalSelfManagementService;
  close(): Promise<void>;
}

export interface CreateUniversalBrokerNextServerOptions {
  incomingArtifactAdapters?: readonly IncomingArtifactAdapter[];
  guiRunner?: GuiNodeRunner;
  selfManagement?: UniversalSelfManagementService;
}

export function createUniversalBrokerNextServer(
  config = loadUniversalBrokerNextConfig(loadConfig()),
  options: CreateUniversalBrokerNextServerOptions = {},
): RunningUniversalBrokerNextServer {
  assertServiceAccountBoundary();
  const allowedHosts = config.allowedHosts.includes("*")
    ? undefined
    : Array.from(new Set([config.host, ...config.allowedHosts]));
  const app = express();
  const managementApp = express();
  const deepDoctorPublicProbeSecret = randomBytes(32);
  managementApp.disable("x-powered-by");
  if (allowedHosts) app.use(hostHeaderValidation(allowedHosts));
  const transports = new McpSessionRegistry<NextTransport>({
    maximumSessions: config.maximumMcpSessions,
  });
  const metrics = new UniversalBrokerMetrics();
  const trustedProxyPolicy = trustedLoopbackProxyHopCount(config.logging.trustProxy);
  const rateLimitIdentity = Object.freeze({
    mode: config.rateLimit.mode,
    sourcePolicy: "loopback-direct-peer-plus-bounded-hop-count",
    trustedProxyHops: config.logging.trustProxy,
    preAuth: config.rateLimit.preAuth,
    postAuth: config.rateLimit.postAuth,
    initialize: config.rateLimit.initialize,
  });
  const rateLimitPolicyDigest = `sha256:${createHash("sha256")
    .update(JSON.stringify(rateLimitIdentity))
    .digest("hex")}`;
  const rateLimitPolicy: BrokerRateLimitPolicy = Object.freeze({
    preAuth: Object.freeze(ratePolicy(config.rateLimit.preAuth)),
    postAuth: Object.freeze(ratePolicy(config.rateLimit.postAuth)),
    initialize: Object.freeze(ratePolicy(config.rateLimit.initialize)),
  });
  const rateLimiter = new BrokerRateLimiter(rateLimitPolicy, {
    trustedProxy: trustedProxyPolicy,
  });
  const operationAudit = new OperationAuditSink({
    path: config.auditSinkPath,
    flushIntervalMs: config.auditFlushIntervalMs,
  });
  const filesystemSyncStorePath = join(config.stateDir, "filesystem-sync", "sync.sqlite");
  ensureFilesystemSyncSqliteSchemaV1(filesystemSyncStorePath);
  const runtimeIdentity = createRuntimeIdentity({
    config,
    sourceRevision: config.sourceRevision,
    runtimeRevision: config.runtimeRevision,
    ...(config.buildDigest ? { buildDigest: config.buildDigest } : {}),
  });
  const auditStartupProof = operationAudit.record({
    operationId: "broker-startup",
    correlationId: `startup-${createHash("sha256")
      .update(runtimeIdentity.startedAt)
      .digest("hex")
      .slice(0, 16)}`,
    principalFingerprint: createHash("sha256")
      .update("devspace-broker-startup-audit")
      .update("\0")
      .update(runtimeIdentity.configDigest)
      .digest("hex"),
    tool: "management",
    operation: "startup-audit-probe",
    risk: "R0",
    dispatchState: "ACKNOWLEDGED",
    result: "PASS",
    receiptDigest: runtimeIdentity.buildDigest,
  });
  void operationAudit.flush().catch(() => undefined);
  const cursorKeys = loadCursorSigningKeyRing({
    currentKeyRef: config.cursorSigningKeyRef,
    ...(config.cursorPreviousSigningKeyRef
      ? { previousKeyRef: config.cursorPreviousSigningKeyRef }
      : {}),
    stateDir: config.stateDir,
  });
  const managementAuthorization = loadOrCreateManagementAuthorizationKey({
    keyRef: config.managementAuthorizationKeyRef,
    stateDir: config.stateDir,
  });
  const finalizationControlRoot = dirname(config.lifecycleFinalizationControlPath);
  mkdirSync(finalizationControlRoot, { recursive: true, mode: 0o700 });
  chmodSync(finalizationControlRoot, 0o700);
  const finalizationBootstrapAuthorization = createFinalizationStoreBootstrapAuthorization({
    storePath: config.lifecycleFinalizationStorePath,
    controlPath: config.lifecycleFinalizationControlPath,
    key: managementAuthorization,
  });
  initializeFinalizationStore({
    storePath: config.lifecycleFinalizationStorePath,
    controlPath: config.lifecycleFinalizationControlPath,
    key: managementAuthorization,
    bootstrapAuthorization: finalizationBootstrapAuthorization,
  });
  const connectorActivationJournal = new SqliteConnectorActivationRecoveryJournal({
    storePath: config.connectorActivationJournalPath,
  });
  const connectorActivationJournalIdentity = connectorActivationJournal.identity();
  const cursors = new SignedSnapshotCursorStore({
    currentKey: cursorKeys.currentKey,
    ...(cursorKeys.previousKey ? { previousKey: cursorKeys.previousKey } : {}),
    ttlMs: config.cursorTtlMs,
    maximumSnapshotsPerPrincipal: config.cursorMaximumSnapshotsPerPrincipal,
    metrics,
  });
  const resourceContinuation = new SignedResourceContinuation({
    currentKey: cursorKeys.currentKey,
    ...(cursorKeys.previousKey ? { previousKey: cursorKeys.previousKey } : {}),
  });
  configureResultEnvelopeIdentity(runtimeIdentity);
  const authority = new OperationAuthorityRegistry({
    minimumRisk: minimumAuthorityRisk,
    storePath: config.authorityStorePath,
    resourceLeaseTtlMs: config.authorityResourceLeaseTtlSeconds * 1_000,
    resourceLeaseHeartbeatMs: config.authorityResourceLeaseHeartbeatSeconds * 1_000,
    resourceLeaseRecoveryGraceMs: config.authorityResourceLeaseRecoveryGraceSeconds * 1_000,
    metrics,
  });
  const envProfiles = new UniversalEnvProfileRegistry({
    configPath: config.envProfileConfigPath,
  });
  const targets = new TargetRegistry({
    configPath: config.targetConfigPath,
    cursorStore: cursors,
  });
  const contexts = new ContextRegistry({
    storePath: config.contextStorePath,
    targets,
    serverConfig: config.serverConfig,
    maximumContexts: config.contextMaximumEntries,
    idleTtlMs: config.contextIdleTtlMs,
    worktreeRoot: config.contextWorktreeRoot,
    maximumWorktrees: config.contextMaximumWorktrees,
    maximumWorktreeBytes: config.contextMaximumWorktreeBytes,
    diffStore: new UniversalTextResourceStore({
      authority: "context-diff",
      maximumEntries: config.contextDiffMaximumEntries,
      maximumTotalCharacters: config.contextDiffMaximumCharacters,
      ttlMs: config.contextDiffTtlMs,
      continuation: resourceContinuation,
    }),
    cursorStore: cursors,
    metrics,
  });
  const execution = new UniversalExecutionPlane({
    targets,
    contexts,
    outputDir: config.processOutputDir,
    sshControlDir: config.sshControlDir,
    maxProcessRecords: config.maximumProcessRecords,
    maxRunningProcesses: config.maxRunningProcesses,
    maxRunningProcessesPerTarget: config.maxRunningProcessesPerTarget,
    processBufferCharacters: config.processBufferCharacters,
    processOutputMaxBytes: config.processOutputMaxBytes,
    completedProcessTtlMs: config.completedProcessTtlMs,
    processStateDir: join(config.stateDir, "processes"),
    envProfiles,
    cursorStore: cursors,
    resourceContinuation,
    metrics,
  });
  const filesystem = new UniversalFilesystemService(
    targets,
    contexts,
    execution,
    {
      sshControlDir: config.sshControlDir,
      syncStatePath: filesystemSyncStorePath,
      cursorStore: cursors,
    },
  );
  const mcpRoutes = new UniversalMcpRouteRegistry(config.mcpRouteConfigPath);
  const mcpProxy = new UniversalMcpProxy(
    mcpRoutes,
    targets,
    {
      sshControlDir: config.sshControlDir,
      maximumSessions: config.downstreamMcpMaximumSessions,
      defaultSessionIdleTtlMs: config.downstreamMcpSessionIdleTtlMs,
      resultStore: new UniversalMcpResultStore({
        maximumEntries: config.mcpResultMaximumEntries,
        maximumTotalBytes: config.mcpResultMaximumBytes,
        ttlMs: config.mcpResultTtlMs,
        metrics,
        continuation: resourceContinuation,
      }),
      envProfiles,
      cursorStore: cursors,
      metrics,
    },
  );
  const artifacts = new UniversalArtifactService(filesystem, {
    baseUrl: config.publicBaseUrl,
    httpPathPrefix: config.artifactPathPrefix,
    stagingRoot: config.artifactStagingDir,
    catalogPath: config.artifactCatalogPath,
    objectRoot: config.artifactObjectRoot,
    quarantineRoot: join(config.stateDir, "quarantine", "artifacts"),
    incomingAdapters: options.incomingArtifactAdapters ?? [],
    maximumEntries: config.artifactMaximumEntries,
    maximumTotalBytes: config.artifactMaximumTotalBytes,
    maximumArtifactBytes: config.artifactMaximumFileBytes,
    ttlMs: config.artifactTtlMs,
    metrics,
  });
  const gui = new UniversalGuiService(
    targets,
    filesystem,
    execution,
    {
      runner: options.guiRunner,
      maximumSessions: config.guiMaximumSessions,
      sessionTtlMs: config.guiSessionTtlMs,
      payloadBudgetCharacters: config.guiPayloadBudgetCharacters,
    },
  );
  const selfManagement = options.selfManagement ?? new UniversalSelfManagementService({
    stateDir: config.selfManagementDir,
    pm2ProcessName: config.selfRestartPm2ProcessName,
    localHealthUrl: `http://${config.managementHost}:${config.managementPort}${config.readyPath}`,
    publicHealthUrl: joinPublicUrl(config.publicBaseUrl, config.healthPath),
    expectedCwd: process.cwd(),
    expectedScript: config.selfRestartExpectedScript,
    timeoutMs: config.selfRestartTimeoutMs,
    runtimeIdentity,
    metrics,
  });
  const mcpUrl = new URL(config.publicMcpUrl);
  const resourceServerUrl = resourceUrlFromServerUrl(mcpUrl);
  const authorityPrincipal = {
    environment: config.deploymentMode === "production" ? "production" as const : "development" as const,
    mode: config.authorityPrincipalMode,
    issuer: new URL(`${config.publicBaseUrl}/`).href,
    resource: resourceServerUrl.href,
    ownerInstanceId: config.authorityOwnerInstanceId,
  };
  const resourceMetadataUrl = prefixedResourceMetadataUrl(
    config.publicBaseUrl,
    resourceServerUrl,
  );
  const oauthProvider = new SingleUserOAuthProvider(
    config.oauth,
    mcpUrl,
    config.oauthStateDir,
    metrics,
  );
  const readiness = new ReadinessRegistry([
    {
      id: "config_build_capabilities",
      sideEffectFree: true,
      check: () => runtimeCapabilityIdentityReadiness(runtimeIdentity),
    },
    {
      id: "non_root",
      sideEffectFree: true,
      check: () => ({
        state: typeof process.getuid !== "function" || process.getuid() !== 0 ? "PASS" : "FAIL",
      }),
    },
    {
      id: "required_store_migrations",
      sideEffectFree: true,
      check: async () => {
        const sqliteReadiness = baseMutableSqliteStoreReadiness({
          authorityStorePath: config.authorityStorePath,
          artifactCatalogPath: config.artifactCatalogPath,
          filesystemSyncStorePath,
          connectorActivationJournalPath: config.connectorActivationJournalPath,
          lifecycleFinalizationStorePath: config.lifecycleFinalizationStorePath,
          lifecycleFinalizationControlPath: config.lifecycleFinalizationControlPath,
          finalizationManagementKey: managementAuthorization,
        });
        let mainDatabaseReadiness: ReadinessCheckObservation;
        try {
          const readback = readMainDatabaseMigrationReadback(databasePath(config.oauthStateDir));
          mainDatabaseReadiness = { state: "PASS", evidence: { ...readback } };
        } catch (error) {
          mainDatabaseReadiness = {
            state: "FAIL",
            summary: "The main/OAuth migration registry or schema readback failed.",
            evidence: {
              storeId: "main",
              path: databasePath(config.oauthStateDir),
              error: errorMessage(error),
            },
          };
        }
        return aggregateReadiness("required stores", [
          ...readinessObservationChildren(sqliteReadiness),
          mainDatabaseReadiness,
          await readablePathReadiness(cursorKeys.currentPath, {
            id: "pagination-current-signing-key",
            required: true,
          }),
          await readablePathReadiness(managementAuthorization.path, {
            id: "management-authorization-key",
            required: true,
          }),
          {
            state: connectorActivationJournalIdentity.storePath
                === config.connectorActivationJournalPath
              && connectorActivationJournalIdentity.schemaVersion === 1
              ? "PASS"
              : "FAIL",
            evidence: {
              id: "connector-activation-journal-identity",
              ...connectorActivationJournalIdentity,
            },
          },
        ]);
      },
    },
    {
      id: "authority_artifact_readability",
      sideEffectFree: true,
      check: () => {
        const authorityStats = authority.readOnlyStats();
        const artifactStats = artifacts.stats();
        return {
          state: numeric(authorityStats.authorities) >= 0 && numeric(artifactStats.artifacts) >= 0
            ? "PASS"
            : "FAIL",
          evidence: { authority: authorityStats, artifacts: artifactStats },
        };
      },
    },
    {
      id: "target_route_generation",
      sideEffectFree: true,
      check: async () => {
        const [targetSnapshot, routeSnapshot] = await Promise.all([
          targets.inspect(),
          mcpRoutes.inspect(),
        ]);
        return {
          state: "PASS",
          evidence: {
            targetGeneration: targetSnapshot.generation,
            targetCount: targetSnapshot.targets.length,
            routeGeneration: routeSnapshot.generation,
            routeCount: routeSnapshot.routes.length,
          },
        };
      },
    },
    {
      id: "cursor_signing",
      sideEffectFree: true,
      check: () => ({
        state: "PASS",
        evidence: {
          currentKeyId: cursorKeys.currentKey.keyId,
          previousKeyConfigured: Boolean(cursorKeys.previousKey),
          ttlMs: config.cursorTtlMs,
          maximumSnapshotsPerPrincipal: config.cursorMaximumSnapshotsPerPrincipal,
        },
      }),
    },
    {
      id: "canonical_connector",
      sideEffectFree: true,
      check: () => canonicalConnectorReadinessObservation(
        config.deploymentMode,
        oauthProvider.connectorReadiness(),
      ),
    },
    {
      id: "supervisor_control",
      sideEffectFree: true,
      check: async () => {
        const internal = config.supervisorEndpoint === "internal://pm2";
        if (!internal || config.supervisorProcessManager !== "pm2") {
          return {
            state: "FAIL" as const,
            summary: "The Base build requires the internal PM2 supervisor control channel.",
            evidence: { endpoint: config.supervisorEndpoint },
          };
        }
        const observed = await selfManagement.supervisorReadiness();
        return {
          ...observed,
          evidence: {
            ...observed.evidence,
            processManager: config.supervisorProcessManager,
            transactionModel: "response-bound-ack-flushed-supervisor",
          },
        };
      },
    },
    {
      id: "rate_limit_identity",
      sideEffectFree: true,
      check: () => ({
        state: rateLimiter.stats().maximumBuckets > 0 ? "PASS" : "FAIL",
        evidence: {
          ...rateLimitIdentity,
          policyDigest: rateLimitPolicyDigest,
        },
      }),
    },
    {
      id: "management_isolation",
      sideEffectFree: true,
      check: () => {
        const isolated = ["127.0.0.1", "::1", "localhost"].includes(config.managementHost)
          && config.managementPort !== config.port;
        return {
          state: isolated ? "PASS" : "FAIL",
          evidence: {
            publicHost: config.host,
            publicPort: config.port,
            managementHost: config.managementHost,
            managementPort: config.managementPort,
            metricsPath: config.metricsPath,
            readyPath: config.readyPath,
          },
        };
      },
    },
    {
      id: "audit_sink",
      sideEffectFree: true,
      check: async () => {
        const proof = await auditStartupProof;
        const stats = operationAudit.stats();
        if (proof.status !== "RECORDED") {
          return { state: "FAIL", summary: proof.error, evidence: { ...stats } };
        }
        return {
          state: stats.initialized && !stats.failed ? "PASS" : "FAIL",
          evidence: {
            ...stats,
            sequence: proof.sequence,
            eventDigest: proof.eventDigest,
            startupProof: "RECORDED",
          },
        };
      },
    },
    {
      id: "runtime_contract_identity",
      sideEffectFree: true,
      check: () => runtimeCapabilityIdentityReadiness(runtimeIdentity),
    },
  ]);
  const deepDoctor = new BoundedDeepDoctor({
    maximumDurationMs: 30_000,
    cleanupReserveMs: 5_000,
    createIsolation: async (context) => {
      const namespace = `doctor_${randomUUID()}`;
      const namespaceRoot = doctorNamespacePath(config, namespace);
      await mkdir(join(config.stateDir, "doctor"), { recursive: true, mode: 0o700 });
      await mkdir(namespaceRoot, { recursive: false, mode: 0o700 });
      await writeFile(join(namespaceRoot, "created.json"), JSON.stringify({
        correlationId: context.correlationId,
        createdAt: new Date().toISOString(),
      }, null, 2), { flag: "wx", mode: 0o600 });
      return {
        namespace,
        async cleanup(cleanupContext) {
          const receiptDigest = sha256Digest({
            namespace,
            correlationId: cleanupContext.correlationId,
            cleanedAt: new Date().toISOString(),
            rateCanaryCleanupBinding: DEEP_DOCTOR_RATE_CANARY_CLEANUP_BINDING,
          });
          await rm(namespaceRoot, { recursive: true, force: true });
          return { state: "CLEANED", receiptDigest };
        },
      };
    },
    checks: createDeepDoctorChecks({
      config,
      runtimeIdentity,
      oauthProvider,
      authority,
      artifacts,
      selfManagement,
      rateLimitPolicy,
      rateLimitPolicyDigest,
      deepDoctorPublicProbeSecret,
    }),
  });
  const bearerAuth = requireBearerAuth({
    verifier: oauthProvider,
    requiredScopes: [],
    resourceMetadataUrl,
  });

  const logSessionCloseResults = (
    reason: "idle_timeout" | "server_shutdown",
    results: McpSessionCloseResult[],
  ) => {
    for (const result of results) {
      metrics.increment(
        result.error ? "devspace_mcp_session_close_failures_total" : "devspace_mcp_sessions_closed_total",
        result.error ? "MCP session close failures" : "Closed MCP sessions",
      );
      logEvent(
        config.logging,
        result.error ? "warn" : "info",
        result.error ? "v2_mcp_session_close_failed" : "v2_mcp_session_closed",
        {
          reason,
          sessionIdPrefix: sessionIdPrefix(result.sessionId),
          error: result.error instanceof Error
            ? result.error.message
            : result.error === undefined
              ? undefined
              : String(result.error),
        },
      );
    }
  };

  let cleanupRunning = false;
  const cleanupTimer = setInterval(() => {
    if (cleanupRunning) return;
    cleanupRunning = true;
    void Promise.allSettled([
      transports.closeIdle(config.mcpSessionIdleTimeoutMs)
        .then((results) => logSessionCloseResults("idle_timeout", results)),
      contexts.cleanupExpired(),
      artifacts.cleanupExpired(),
      mcpProxy.stats(),
      Promise.resolve(gui.stats()),
    ]).then((results) => {
      for (const result of results) {
        if (result.status !== "rejected") continue;
        logEvent(config.logging, "warn", "v2_lifecycle_cleanup_failed", {
          error: result.reason instanceof Error
            ? result.reason.message
            : String(result.reason),
        });
      }
    }).finally(() => {
      cleanupRunning = false;
    });
  }, config.mcpSessionCleanupIntervalMs);
  cleanupTimer.unref();
  let pendingInitializations = 0;

  if (config.logging.trustProxy !== false) {
    app.set("trust proxy", trustedProxyPolicy);
  }

  app.use((req, res, next) => {
    const requestId = randomUUID();
    const startedAt = performance.now();
    res.locals.requestId = requestId;
    res.on("finish", () => {
      metrics.increment("devspace_http_requests_total", "HTTP requests");
      metrics.observeMilliseconds(
        "devspace_http_request_duration_seconds",
        "HTTP request duration in seconds",
        performance.now() - startedAt,
      );
      if (!config.logging.requests) return;
      logEvent(config.logging, "info", "v2_http_request", {
        requestId,
        method: req.method,
        path: requestPath(req),
        status: res.statusCode,
        durationMs: Math.round(performance.now() - startedAt),
        ip: requestIp(req),
        host: req.header("host"),
        userAgent: req.header("user-agent"),
        contentLength: req.header("content-length"),
      });
    });
    next();
  });

  app.use((req, res, next) => {
    // The management-authorized self-probe crosses the real public stack without spending a
    // production admission token. Keep this exception exact: one method, one path, and one
    // process-local secret presented over a loopback socket.
    if (
      req.method === "GET"
      && req.path === config.metricsPath
      && isAuthorizedDeepDoctorPublicProbe(req, deepDoctorPublicProbeSecret)
    ) {
      next();
      return;
    }
    try {
      const decision = rateLimiter.preAuth({
        remoteAddress: req.socket.remoteAddress ?? "0.0.0.0",
        forwardedFor: req.headers["x-forwarded-for"],
      });
      if (applyRateLimitDecision(res, decision, metrics)) return;
      next();
    } catch (error) {
      logEvent(config.logging, "warn", "v2_rate_limit_source_rejected", {
        requestId: res.locals.requestId,
        error: error instanceof Error ? error.message : String(error),
      });
      sendJsonRpcError(res, 400, -32600, "Invalid request source metadata");
    }
  });

  // Reject abusive sources before allocating up to the bounded JSON body limit.
  app.use(express.json({ limit: MAXIMUM_HTTP_JSON_BYTES }));

  const authorizationMetadata = universalAuthorizationMetadata(config);
  app.get("/.well-known/oauth-authorization-server", (_req, res) => {
    res.json(authorizationMetadata);
  });
  app.get("/.well-known/openid-configuration", (_req, res) => {
    res.json(authorizationMetadata);
  });

  app.use(
    mcpAuthRouter({
      provider: oauthProvider,
      issuerUrl: new URL(`${config.publicBaseUrl}/`),
      baseUrl: new URL(`${config.publicBaseUrl}/`),
      resourceServerUrl,
      scopesSupported: config.oauth.scopes,
      resourceName: "DevSpace Universal Broker v2",
    }),
  );

  app.get(config.healthPath, (_req, res) => {
    res.json({
      ...publicRuntimeHealth(runtimeIdentity),
      buildDigest: runtimeIdentity.buildDigest,
    });
  });

  managementApp.get("/healthz", (_req, res) => {
    res.json({ ...publicRuntimeHealth(runtimeIdentity), buildDigest: runtimeIdentity.buildDigest });
  });

  managementApp.get("/route-identityz", (req, res) => {
    if (!isManagementAuthorized(req.get("authorization"), managementAuthorization)) {
      res.setHeader(
        "WWW-Authenticate",
        'Bearer realm="devspace-management", error="invalid_token"',
      );
      res.status(401).json({ error: "management_authorization_required" });
      return;
    }
    const connector = oauthProvider.connectorReadiness();
    const activeBinding = oauthProvider.activeConnectorBinding();
    if (config.deploymentMode !== "production"
      || connector.state !== "PASS"
      || connector.activeCount !== 1
      || !activeBinding
      || activeBinding.schemaGeneration !== runtimeIdentity.schemaGeneration
      || activeBinding.authorityContractGeneration !== runtimeIdentity.authorityContractGeneration
      || activeBinding.buildDigest !== runtimeIdentity.buildDigest) {
      res.status(503).json({
        schemaVersion: 1,
        state: "UNAVAILABLE",
        routeCount: connector.activeCount,
      });
      return;
    }
    res.json(connectorProductionRouteIdentityReadback({
      runtimeIdentity,
      oauthResource: resourceServerUrl.href,
      canonicalName: activeBinding.canonicalName,
      bindingId: activeBinding.bindingId,
    }));
  });

  managementApp.get(config.readyPath, async (_req, res) => {
    const report = await readiness.evaluate();
    try {
      for (const check of report.checks) {
        metrics.increment(
          "devspace_readiness_checks_total",
          "Private readiness check results",
          1,
          { check: check.id, result: check.state.toLowerCase() },
        );
      }
      metrics.observeMilliseconds(
        "devspace_readiness_duration_seconds",
        "Private readiness duration",
        report.durationMs,
        { result: report.status },
      );
    } catch {
      // Readiness evidence is authoritative even when metrics instrumentation is unavailable.
    }
    res.status(report.httpStatus).json({ ...report, identity: runtimeIdentity });
  });

  managementApp.get("/doctorz", (_req, res) => {
    res.setHeader("Allow", "POST");
    res.status(405).json({ error: "method_not_allowed", allowed: ["POST"] });
  });

  managementApp.post("/doctorz", async (req, res) => {
    if (!isManagementAuthorized(req.get("authorization"), managementAuthorization)) {
      res.setHeader(
        "WWW-Authenticate",
        'Bearer realm="devspace-management", error="invalid_token"',
      );
      res.status(401).json({ error: "management_authorization_required" });
      return;
    }
    const report = await deepDoctor.run({
      authorized: true,
      correlationId: `doctor-${randomUUID()}`,
    });
    try {
      for (const check of report.checks) {
        metrics.increment(
          "devspace_doctor_checks_total",
          "Private deep doctor check results",
          1,
          { check: check.id, result: check.state.toLowerCase() },
        );
      }
      metrics.observeMilliseconds(
        "devspace_doctor_duration_seconds",
        "Private deep doctor duration",
        report.durationMs,
        { result: report.status },
      );
    } catch {
      // Doctor evidence remains authoritative even when metrics instrumentation is unavailable.
    }
    res.status(report.status === "PASS" ? 200 : 503).json({
      ...report,
      releasePassClaimed: false,
    });
  });

  managementApp.get(config.metricsPath, async (_req, res) => {
    const [contextStats, executionStats, mcpStats, selfManagementStats] = await Promise.all([
      Promise.resolve(contexts.stats()),
      Promise.resolve(execution.stats()),
      mcpProxy.stats(),
      selfManagement.stats(),
    ]);
    const targetProbeStats = targets.stats();
    const authorityStats = authority.stats();
    res.type("text/plain; version=0.0.4").send(metrics.render({
      devspace_open_http_sessions: gauge("Open MCP HTTP sessions", transports.size),
      devspace_pending_mcp_initializations: gauge("Pending MCP initialize requests", pendingInitializations),
      devspace_contexts: gauge("Open Universal Broker contexts", numeric(contextStats.contexts)),
      devspace_managed_worktrees: gauge("Managed Universal Broker worktrees", numeric(contextStats.managedWorktrees)),
      devspace_running_processes: gauge("Running ordinary processes", numeric(executionStats.runningProcesses)),
      devspace_process_output_bytes: gauge("Retained ordinary process output bytes", numeric(executionStats.outputBytes)),
      devspace_downstream_mcp_sessions: gauge("Open downstream MCP sessions", numeric(mcpStats.sessions)),
      devspace_downstream_mcp_active_calls: gauge("Active downstream MCP calls", numeric(mcpStats.activeCalls)),
      devspace_artifacts: gauge("Published artifacts", numeric(artifacts.stats().artifacts)),
      devspace_artifact_bytes: gauge("Published artifact bytes", numeric(artifacts.stats().totalBytes)),
      devspace_gui_sessions: gauge("Open GUI sessions", numeric(gui.stats().sessions)),
      devspace_operation_authorities: gauge("Active operation authority records", numeric(authorityStats.authorities)),
      devspace_authority_previews: gauge("Operation authority previews since process start", numeric(authorityStats.previews)),
      devspace_target_probe_cache_entries: gauge("Cached target probe observations", numeric(targetProbeStats.probeCacheEntries)),
      devspace_target_probe_in_flight: gauge("Target probes currently in flight", numeric(targetProbeStats.probeInFlight)),
      devspace_target_probe_cache_hits: gauge("Target probe cache hits since process start", numeric(targetProbeStats.probeCacheHits)),
      devspace_target_probe_cache_misses: gauge("Target probe cache misses since process start", numeric(targetProbeStats.probeCacheMisses)),
      devspace_target_probe_coalesced: gauge("Target probe calls coalesced onto in-flight work", numeric(targetProbeStats.probeCoalesced)),
      devspace_target_probe_online: gauge("Successful online target probes since process start", numeric(targetProbeStats.probeOnline)),
      devspace_target_probe_degraded: gauge("Degraded target probes since process start", numeric(targetProbeStats.probeDegraded)),
      devspace_target_probe_offline: gauge("Offline target probes since process start", numeric(targetProbeStats.probeOffline)),
      devspace_target_probe_average_duration_ms: gauge("Average uncached target probe duration in milliseconds", numeric(targetProbeStats.averageProbeDurationMs)),
      devspace_target_probe_last_duration_ms: gauge("Most recent uncached target probe duration in milliseconds", numeric(targetProbeStats.lastProbeDurationMs)),
      devspace_restart_transactions: gauge("Retained broker restart transactions", numeric(selfManagementStats.restartTransactions)),
      devspace_active_restart_transactions: gauge("Active broker restart transactions", numeric(selfManagementStats.activeRestartTransactions)),
      devspace_rate_limit_buckets: gauge("Broker-owned rate limit buckets", rateLimiter.stats().buckets),
      devspace_operation_audit_pending: gauge("Operation audit events awaiting durable flush", operationAudit.stats().pending),
    }));
  });

  app.head(`${config.artifactPathPrefix}/:artifactId`, (req, res) => {
    void artifacts.handleHttp(req, res);
  });
  app.get(`${config.artifactPathPrefix}/:artifactId`, (req, res) => {
    void artifacts.handleHttp(req, res);
  });

  app.all(config.endpointPath, async (req, res) => {
    const requestId = res.locals.requestId as string;
    const currentSessionId = req.header("mcp-session-id");
    const initializeRequest = req.method === "POST" && isInitializeRequest(req.body);
    const messageMethods = req.method === "POST" ? jsonRpcMethods(req.body) : [];
    const responseRequestIds = req.method === "POST" ? jsonRpcRequestIds(req.body) : [];
    bindRestartResponseLifecycle(
      req,
      res,
      responseRequestIds,
      selfManagement,
      config,
      requestId,
    );

    await applyBearerAuth(bearerAuth, req, res);
    if (res.headersSent) return;

    if (
      !req.auth?.resource
      || !checkResourceAllowed({
        requestedResource: req.auth.resource,
        configuredResource: resourceServerUrl,
      })
    ) {
      logEvent(config.logging, "warn", "v2_auth_denied", {
        requestId,
        reason: "invalid_oauth_resource",
        path: requestPath(req),
      });
      sendJsonRpcError(res, 401, -32001, "Unauthorized");
      return;
    }

    const authorizedScopes = authenticatedBrokerScopes(req.auth?.scopes, config);
    if (!authorizedScopes || !req.auth) {
      logEvent(config.logging, "warn", "v2_auth_denied", {
        requestId,
        reason: "unsupported_oauth_scope",
        path: requestPath(req),
      });
      sendJsonRpcError(res, 403, -32003, "Insufficient OAuth scope");
      return;
    }
    req.auth = { ...req.auth, scopes: authorizedScopes };

    const principalFingerprint = resolveAuthorityPrincipal(
      { authInfo: req.auth },
      authorityPrincipal,
    ).fingerprint;
    const clientId = req.auth.clientId;
    if (!clientId) {
      sendJsonRpcError(res, 401, -32001, "Unauthorized");
      return;
    }
    if (applyRateLimitDecision(
      res,
      rateLimiter.postAuth({ principalFingerprint, clientId }),
      metrics,
    )) return;
    if (initializeRequest && applyRateLimitDecision(
      res,
      rateLimiter.initialize({ principalFingerprint, clientId }),
      metrics,
    )) return;

    let acquiredSessionId: string | undefined;
    let initializationReserved = false;
    let ephemeralServer: McpServer | undefined;
    try {
      let transport: NextTransport | undefined;
      if (currentSessionId) {
        transport = transports.acquire(currentSessionId);
        if (!transport) {
          sendJsonRpcError(res, 404, -32000, "Unknown MCP session");
          return;
        }
        acquiredSessionId = currentSessionId;
      } else if (initializeRequest) {
        if (transports.size + pendingInitializations >= config.maximumMcpSessions) {
          const evicted = await transports.closeLeastRecentlyUsed(1);
          logSessionCloseResults("idle_timeout", evicted);
        }
        if (transports.size + pendingInitializations >= config.maximumMcpSessions) {
          try {
            metrics.recordQuotaRejection("mcp_session");
          } catch {
            // MCP session rejection remains enforced if metrics are unavailable.
          }
          sendJsonRpcError(res, 503, -32002, "MCP session quota is full");
          return;
        }
        pendingInitializations += 1;
        initializationReserved = true;
        transport = new StreamableHTTPServerTransport({
          sessionIdGenerator: () => randomUUID(),
          onsessioninitialized: (newSessionId) => {
            if (transport) transports.register(newSessionId, transport);
            metrics.increment("devspace_mcp_sessions_created_total", "Created MCP sessions");
            logEvent(config.logging, "info", "v2_mcp_session_created", {
              requestId,
              sessionIdPrefix: sessionIdPrefix(newSessionId),
            });
          },
        });
        transport.onclose = () => {
          const closedSessionId = transport?.sessionId;
          if (closedSessionId && transports.remove(closedSessionId)) {
            logEvent(config.logging, "info", "v2_mcp_session_closed", {
              reason: "transport_close",
              sessionIdPrefix: sessionIdPrefix(closedSessionId),
            });
          }
        };
        const server: McpServer = createUniversalBrokerMcpServer({
          targets,
          contexts,
          execution,
          filesystem,
          mcpProxy,
          artifacts,
          gui,
          authority,
          authorityPrincipal,
          selfManagement,
          runtimeIdentity,
          metrics,
          operationAudit,
        });
        await server.connect(transport);
      } else if (isSafeSessionlessDiscoveryRequest(messageMethods)) {
        logEvent(config.logging, "info", "v2_mcp_sessionless_discovery", {
          requestId,
          methods: messageMethods,
          batch: Array.isArray(req.body),
        });
        transport = new StreamableHTTPServerTransport({
          sessionIdGenerator: undefined,
          enableJsonResponse: true,
        });
        ephemeralServer = createUniversalBrokerMcpServer({
          targets,
          contexts,
          execution,
          filesystem,
          mcpProxy,
          artifacts,
          gui,
          authority,
          authorityPrincipal,
          selfManagement,
          runtimeIdentity,
          metrics,
          operationAudit,
        });
        await ephemeralServer.connect(transport);
      } else {
        logEvent(config.logging, "warn", "v2_mcp_sessionless_rejected", {
          requestId,
          methods: messageMethods,
          batch: Array.isArray(req.body),
        });
        sendJsonRpcError(res, 400, -32000, "No valid MCP session");
        return;
      }

      await selfManagement.withResponseTransport(
        requestId,
        () => transport.handleRequest(req, res, req.body),
      );
    } catch (error) {
      logEvent(config.logging, "error", "v2_mcp_request_error", {
        requestId,
        error: error instanceof Error ? error.message : String(error),
      });
      metrics.increment("devspace_mcp_request_errors_total", "MCP request errors");
      if (!res.headersSent) {
        sendJsonRpcError(res, 500, -32603, "Internal server error");
      }
    } finally {
      if (acquiredSessionId) transports.release(acquiredSessionId);
      if (initializationReserved) {
        pendingInitializations = Math.max(0, pendingInitializations - 1);
      }
      if (ephemeralServer) await ephemeralServer.close();
    }
  });

  let closePromise: Promise<void> | undefined;
  return {
    app,
    managementApp,
    config,
    runtimeIdentity,
    targets,
    contexts,
    execution,
    filesystem,
    mcpRoutes,
    mcpProxy,
    artifacts,
    gui,
    authority,
    selfManagement,
    close: () => {
      closePromise ??= (async () => {
        clearInterval(cleanupTimer);
        const results = await transports.closeAll();
        logSessionCloseResults("server_shutdown", results);
        gui.close();
        contexts.closeResources();
        await artifacts.close();
        await mcpProxy.close();
        await execution.close();
        authority.close();
        connectorActivationJournal.close();
        oauthProvider.close();
        await operationAudit.close();
      })();
      return closePromise;
    },
  };
}

function bindRestartResponseLifecycle(
  req: Request,
  res: Response,
  responseRequestIds: readonly (string | number)[],
  selfManagement: UniversalSelfManagementService,
  config: Pick<UniversalBrokerNextConfig, "logging">,
  httpRequestId: string,
): void {
  if (responseRequestIds.length === 0) return;
  const reportFailure = (event: string, error: unknown): void => {
    logEvent(config.logging, "error", "v2_restart_response_ack_failed", {
      requestId: httpRequestId,
      event,
      error: error instanceof Error ? error.message : String(error),
    });
  };
  const flushed = (): void => {
    void Promise.all(responseRequestIds.map((id) => (
      selfManagement.responseFlushedForRequest(httpRequestId, id)
    )))
      .catch((error) => reportFailure("finish", error));
  };
  const aborted = (event: string): void => {
    if (res.writableFinished) return;
    void Promise.all(responseRequestIds.map((id) => (
      selfManagement.responseAbortedForRequest(httpRequestId, id, event)
    )))
      .catch((error) => reportFailure(event, error));
  };
  res.once("finish", flushed);
  req.once("aborted", () => aborted("request aborted before response flush"));
  res.once("error", (error) => {
    reportFailure("response error before flush", error);
    aborted("response error before flush");
  });
  res.once("close", () => aborted("response closed before flush"));
}

export function authenticatedBrokerScopes(
  scopes: readonly string[] | undefined,
  config: Pick<UniversalBrokerNextConfig, "oauth">,
): string[] | undefined {
  if (!scopes) return undefined;
  const granted = [...new Set(scopes)];
  if (granted.length === 0) return undefined;
  return granted.every((scope) => config.oauth.scopes.includes(scope))
    ? granted
    : undefined;
}

function universalAuthorizationMetadata(
  config: UniversalBrokerNextConfig,
): Record<string, unknown> {
  return {
    issuer: `${config.publicBaseUrl}/`,
    authorization_endpoint: joinPublicUrl(config.publicBaseUrl, "/authorize"),
    response_types_supported: ["code"],
    code_challenge_methods_supported: ["S256"],
    token_endpoint: joinPublicUrl(config.publicBaseUrl, "/token"),
    token_endpoint_auth_methods_supported: ["client_secret_post", "none"],
    grant_types_supported: ["authorization_code", "refresh_token"],
    scopes_supported: config.oauth.scopes,
    revocation_endpoint: joinPublicUrl(config.publicBaseUrl, "/revoke"),
    revocation_endpoint_auth_methods_supported: ["client_secret_post"],
    registration_endpoint: joinPublicUrl(config.publicBaseUrl, "/register"),
  };
}

function prefixedResourceMetadataUrl(
  publicBaseUrl: string,
  resourceServerUrl: URL,
): string {
  const standard = new URL(getOAuthProtectedResourceMetadataUrl(resourceServerUrl));
  const base = new URL(`${publicBaseUrl}/`);
  const prefix = base.pathname === "/"
    ? ""
    : base.pathname.replace(/\/+$/u, "");
  return new URL(`${prefix}${standard.pathname}`, base.origin).href;
}

export function createUniversalBrokerNextConfig(
  base: ServerConfig,
  env: NodeJS.ProcessEnv = process.env,
): UniversalBrokerNextConfig {
  return loadUniversalBrokerNextConfig(base, env);
}

async function applyBearerAuth(
  bearerAuth: ReturnType<typeof requireBearerAuth>,
  req: Request,
  res: Response,
): Promise<void> {
  await new Promise<void>((resolve, reject) => {
    bearerAuth(req, res, (error?: unknown) => {
      if (error) reject(error);
      else resolve();
    });
  });
}

function sendJsonRpcError(
  res: Response,
  status: number,
  code: number,
  message: string,
): void {
  res.status(status).json({
    jsonrpc: "2.0",
    error: { code, message },
    id: null,
  });
}

function gauge(help: string, value: number): { help: string; value: number } {
  return { help, value };
}

function isAuthorizedDeepDoctorPublicProbe(
  request: Request,
  authorizationSecret: Uint8Array,
): boolean {
  if (!isLoopbackSocketAddress(request.socket.remoteAddress)) return false;
  const encoded = request.get(DEEP_DOCTOR_PUBLIC_PROBE_HEADER);
  if (!encoded || !BASE64URL_256_BIT_VALUE.test(encoded)) return false;
  const candidate = Buffer.from(encoded, "base64url");
  const expected = Buffer.from(authorizationSecret);
  return candidate.length === expected.length
    && candidate.toString("base64url") === encoded
    && timingSafeEqual(candidate, expected);
}

function deepDoctorPublicProbeHost(configuredHost: string): string | undefined {
  const host = configuredHost.trim().toLowerCase();
  if (host === "127.0.0.1" || host === "localhost") return host;
  if (host === "::1") return "[::1]";
  if (host === "0.0.0.0") return "127.0.0.1";
  if (host === "::") return "[::1]";
  return undefined;
}

function isLoopbackSocketAddress(address: string | undefined): boolean {
  const normalized = address?.toLowerCase();
  return normalized === "127.0.0.1"
    || normalized === "::1"
    || normalized === "::ffff:127.0.0.1";
}

function ratePolicy(input: Readonly<{ refillPerMinute: number; burst: number }>) {
  return {
    capacity: input.burst,
    refillTokens: input.refillPerMinute,
    refillIntervalMs: 60_000,
  };
}

function applyRateLimitDecision(
  res: Response,
  decision: RateLimitDecision,
  metrics: UniversalBrokerMetrics,
): boolean {
  res.setHeader("X-RateLimit-Limit", String(decision.limit));
  res.setHeader("X-RateLimit-Remaining", String(decision.remaining));
  if (decision.allowed) return false;
  try {
    metrics.recordRateLimitRejection(decision.stage);
  } catch {
    // Rate limiting remains enforced even if metrics are unavailable.
  }
  res.setHeader("Retry-After", String(decision.retryAfterSeconds));
  res.status(429).json({
    error: "rate_limited",
    stage: decision.stage,
    retryAfterSeconds: decision.retryAfterSeconds,
  });
  return true;
}

function aggregateReadiness(
  label: string,
  observations: readonly ReadinessCheckObservation[],
): ReadinessCheckObservation {
  const state = observations.some((observation) => observation.state === "FAIL")
    ? "FAIL"
    : observations.some((observation) => observation.state === "UNKNOWN")
      ? "UNKNOWN"
      : "PASS";
  return {
    state,
    ...(state === "PASS" ? {} : { summary: `${label} are not fully ready.` }),
    evidence: { observations },
  };
}

function readinessObservationChildren(
  observation: ReadinessCheckObservation,
): ReadinessCheckObservation[] {
  const children = observation.evidence?.observations;
  if (!Array.isArray(children)) return [observation];
  return children.filter((child): child is ReadinessCheckObservation => (
    Boolean(child)
    && typeof child === "object"
    && ["PASS", "FAIL", "UNKNOWN"].includes((child as ReadinessCheckObservation).state)
  ));
}

function createDeepDoctorChecks(input: {
  config: UniversalBrokerNextConfig;
  runtimeIdentity: RuntimeIdentity;
  oauthProvider: SingleUserOAuthProvider;
  authority: OperationAuthorityRegistry;
  artifacts: UniversalArtifactService;
  selfManagement: UniversalSelfManagementService;
  rateLimitPolicy: BrokerRateLimitPolicy;
  rateLimitPolicyDigest: string;
  deepDoctorPublicProbeSecret: Uint8Array;
}): DeepDoctorCheck[] {
  return [
    {
      id: "authority_claim_receipt",
      timeoutMs: 2_000,
      check: (context) => isolatedAuthorityClaimReceipt(input.config, context.namespace),
    },
    {
      id: "connector_consistency",
      check: () => {
        const connector = input.oauthProvider.connectorReadiness();
        return {
          state: connector.state,
          ...(connector.state === "PASS" ? {} : { summary: "Canonical connector consistency failed." }),
          evidence: { ...connector },
        };
      },
    },
    {
      id: "pm2_uniqueness",
      timeoutMs: 3_000,
      check: () => processManagerProductionUniqueness(input.config),
    },
    {
      id: "public_metrics_negative_probe",
      timeoutMs: 2_000,
      check: (context) => publicMetricsNegativeProbe(
        input.config,
        context.signal,
        input.deepDoctorPublicProbeSecret,
      ),
    },
    {
      id: "artifact_reconciliation",
      check: async () => {
        try {
          const report = await input.artifacts.reconciliationReport();
          return {
            state: "PASS",
            evidence: { ...report },
          };
        } catch (error) {
          return {
            state: "FAIL",
            summary: `Artifact reconciliation failed: ${errorMessage(error)}`,
            evidence: input.artifacts.stats(),
          };
        }
      },
    },
    {
      id: "migration_manifest_scan",
      check: () => {
        const mainManifest = mainDatabaseMigrationManifest();
        const manifest = universalBrokerStoreMigrationManifest(mainManifest);
        const requiredStores = baseMutableSqliteStoreRequirements(buildCapabilityContract());
        const manifestStores = new Set(manifest.map((entry) => entry.storeId));
        const missingRequiredStores = requiredStores
          .map((requirement) => requirement.storeId)
          .filter((storeId) => !manifestStores.has(storeId));
        return {
          state: missingRequiredStores.length === 0 ? "PASS" : "FAIL",
          ...(missingRequiredStores.length === 0
            ? {}
            : { summary: `Required store migrations are missing: ${missingRequiredStores.join(", ")}` }),
          evidence: {
            digest: universalBrokerStoreMigrationManifestDigest(mainManifest),
            entries: manifest.length,
            stores: [...new Set(manifest.map((entry) => entry.storeId))],
            requiredStores,
            missingRequiredStores,
          },
        };
      },
    },
    {
      id: "mutable_snapshot_capability",
      timeoutMs: 5_000,
      check: (context) => mutableSnapshotCapability(input.config, context.namespace),
    },
    {
      id: "rate_canary",
      check: (context) => {
        // A doctor canary validates the production policy, but its bucket state is disposable
        // and must never enter the production limiter's cardinality or token accounting.
        const isolatedRateLimiter = new BrokerRateLimiter(input.rateLimitPolicy, {
          maximumBuckets: 1,
        });
        const before = isolatedRateLimiter.stats();
        const decision = isolatedRateLimiter.postAuth({
          principalFingerprint: createHash("sha256")
            .update("doctor-rate-canary")
            .update("\0")
            .update(context.namespace)
            .digest("hex"),
          clientId: `doctor:${context.namespace}`,
        });
        const after = isolatedRateLimiter.stats();
        return {
          state: decision.allowed ? "PASS" : "FAIL",
          evidence: {
            stage: decision.stage,
            allowed: decision.allowed,
            limit: decision.limit,
            remaining: decision.remaining,
            isolation: "PER_RUN_DISPOSABLE_RATE_LIMITER",
            cleanupBinding: DEEP_DOCTOR_RATE_CANARY_CLEANUP_BINDING,
            policyDigest: input.rateLimitPolicyDigest,
            isolatedBucketCountBefore: before.buckets,
            isolatedBucketCountAfter: after.buckets,
            isolatedMaximumBuckets: after.maximumBuckets,
          },
        };
      },
    },
    {
      id: "stale_lease_nonterminal_report",
      timeoutMs: 2_000,
      check: async () => {
        const authorityStats = input.authority.stats();
        const selfManagementStats = await input.selfManagement.stats();
        const pendingReservations = numeric(authorityStats.pendingReservations);
        const activeRestartTransactions = numeric(selfManagementStats.activeRestartTransactions);
        return {
          state: pendingReservations === 0 && activeRestartTransactions === 0 ? "PASS" : "UNKNOWN",
          ...(pendingReservations === 0 && activeRestartTransactions === 0
            ? {}
            : { summary: "Nonterminal authority or restart state requires operator readback." }),
          evidence: { authority: authorityStats, selfManagement: selfManagementStats },
        };
      },
    },
    {
      id: "runtime_identity_readback",
      check: () => exactRuntimeIdentityReadback(input.config, input.runtimeIdentity),
    },
  ];
}

async function isolatedAuthorityClaimReceipt(
  config: UniversalBrokerNextConfig,
  namespace: string,
): Promise<DeepDoctorCheckObservation> {
  const namespaceRoot = doctorNamespacePath(config, namespace);
  const registry = new OperationAuthorityRegistry({
    minimumRisk: minimumAuthorityRisk,
    storePath: join(namespaceRoot, "authority.sqlite"),
    instanceId: `${namespace}_authority`,
    resourceLeaseTtlMs: 1_000,
  });
  try {
    const descriptor = authorityActionFromToolCall("fs", {
      operation: "write",
      target: "local",
      path: join(namespaceRoot, "authority-canary.txt"),
      content: "deep doctor isolated authority canary\n",
    });
    const principalFingerprint = createHash("sha256")
      .update("doctor-isolated-authority")
      .update("\0")
      .update(namespace)
      .digest("hex");
    const created = registry.create({
      taskId: "deep-doctor-isolated-authority",
      authorityText: "Authorize only the isolated deep doctor authority canary.",
      expiresInSeconds: 60,
      actions: [{ descriptor, risk: "R1", uses: 1 }],
    }, principalFingerprint) as { authorityId?: unknown };
    const authorityId = String(created.authorityId ?? "");
    const dispatch = registry.prepareDispatch(authorityId, principalFingerprint, descriptor, "R1");
    const grant = dispatch.claim();
    dispatch.cancelNotDispatched({
      providerCallCount: 0,
      proof: "DEEP_DOCTOR_ISOLATED_PROVIDER_CALL_ZERO",
    });
    const status = registry.status(authorityId, principalFingerprint) as {
      receipts?: Array<{ result?: string; leaseState?: string }>;
    };
    return {
      state: status.receipts?.some((receipt) => receipt.result === "CANCELLED_NOT_DISPATCHED")
        ? "PASS"
        : "FAIL",
      evidence: {
        authorityIdDigest: sha256Digest(authorityId),
        actionClaimIdDigest: sha256Digest(grant.actionClaimId),
        receiptResults: status.receipts?.map((receipt) => ({
          result: receipt.result,
          leaseState: receipt.leaseState,
        })),
      },
    };
  } finally {
    registry.close();
  }
}

async function processManagerProductionUniqueness(
  config: UniversalBrokerNextConfig,
): Promise<DeepDoctorCheckObservation> {
  if (config.deploymentMode !== "production") {
    return {
      state: "UNKNOWN",
      summary: "PM2 production uniqueness is a live-only check outside production mode.",
      evidence: {
        deploymentMode: config.deploymentMode,
        pm2ProcessName: config.selfRestartPm2ProcessName,
      },
    };
  }
  try {
    const { stdout } = await execFileAsync("pm2", ["jlist"], {
      encoding: "utf8",
      maxBuffer: 2 * 1024 * 1024,
      timeout: 2_000,
    });
    const processes = JSON.parse(stdout) as Array<{
      name?: string;
      pm2_env?: { status?: string; pm_cwd?: string; pm_exec_path?: string };
    }>;
    const matches = processes.filter((processInfo) => processInfo.name === config.selfRestartPm2ProcessName);
    return {
      state: matches.length === 1 ? "PASS" : "FAIL",
      evidence: {
        pm2ProcessName: config.selfRestartPm2ProcessName,
        matches: matches.length,
        statuses: matches.map((processInfo) => processInfo.pm2_env?.status ?? "unknown"),
      },
    };
  } catch (error) {
    return {
      state: "UNKNOWN",
      summary: `PM2 uniqueness could not be read: ${errorMessage(error)}`,
      evidence: { pm2ProcessName: config.selfRestartPm2ProcessName },
    };
  }
}

async function publicMetricsNegativeProbe(
  config: UniversalBrokerNextConfig,
  signal: AbortSignal,
  authorizationSecret: Uint8Array,
): Promise<DeepDoctorCheckObservation> {
  const probeHost = deepDoctorPublicProbeHost(config.host);
  if (!probeHost) {
    return {
      state: "UNKNOWN",
      summary: "Public metrics negative probe requires a broker-local data-plane listener.",
      evidence: { configuredHost: config.host },
    };
  }
  const url = `http://${probeHost}:${config.port}${config.metricsPath}`;
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(new Error("public metrics probe timed out")), 1_000);
  timeout.unref();
  const abortFromParent = () => controller.abort(signal.reason);
  signal.addEventListener("abort", abortFromParent, { once: true });
  try {
    const response = await fetch(url, {
      method: "GET",
      signal: controller.signal,
      headers: {
        [DEEP_DOCTOR_PUBLIC_PROBE_HEADER]: Buffer.from(authorizationSecret).toString("base64url"),
      },
    });
    return {
      state: response.status === 200 ? "FAIL" : "PASS",
      ...(response.status === 200 ? { summary: "Metrics are exposed on the public data plane." } : {}),
      evidence: { url, status: response.status },
    };
  } catch (error) {
    return {
      state: "UNKNOWN",
      summary: `Public metrics negative probe was not proven: ${errorMessage(error)}`,
      evidence: { url },
    };
  } finally {
    clearTimeout(timeout);
    signal.removeEventListener("abort", abortFromParent);
  }
}

async function mutableSnapshotCapability(
  config: UniversalBrokerNextConfig,
  namespace: string,
): Promise<DeepDoctorCheckObservation> {
  const namespaceRoot = doctorNamespacePath(config, namespace);
  const sourcePath = join(namespaceRoot, "snapshot-source.txt");
  await writeFile(sourcePath, "deep doctor snapshot canary\n", { flag: "wx", mode: 0o600 });
  const capture = await captureSnapshotGroup({
    snapshotRoot: join(namespaceRoot, "snapshot"),
    barrier: { kind: "DEEP_DOCTOR_ISOLATED" },
    entries: [{
      id: "snapshot-source",
      kind: "file",
      path: sourcePath,
      required: true,
      purpose: "deep doctor mutable snapshot capability canary",
    }],
  });
  return {
    state: "PASS",
    evidence: {
      manifestPath: capture.manifestPath,
      groupDigest: capture.manifest.groupDigest,
      entries: capture.manifest.entries.length,
    },
  };
}

function exactRuntimeIdentityReadback(
  config: UniversalBrokerNextConfig,
  runtimeIdentity: RuntimeIdentity,
): DeepDoctorCheckObservation {
  const expected = createRuntimeIdentity({
    config,
    sourceRevision: config.sourceRevision,
    runtimeRevision: config.runtimeRevision,
    ...(config.buildDigest ? { buildDigest: config.buildDigest } : {}),
    startedAt: runtimeIdentity.startedAt,
  });
  const mismatches = Object.entries(expected)
    .filter(([key, value]) => runtimeIdentity[key as keyof RuntimeIdentity] !== value)
    .map(([key]) => key);
  return {
    state: mismatches.length === 0 ? "PASS" : "FAIL",
    ...(mismatches.length > 0 ? { summary: `Runtime identity drift: ${mismatches.join(", ")}` } : {}),
    evidence: { expected, actual: runtimeIdentity },
  };
}

function doctorNamespacePath(
  config: Pick<UniversalBrokerNextConfig, "stateDir">,
  namespace: string,
): string {
  if (!/^doctor_[0-9a-f-]{36}$/u.test(namespace)) {
    throw new Error("Invalid doctor namespace.");
  }
  return join(config.stateDir, "doctor", namespace);
}

function sha256Digest(value: unknown): string {
  return `sha256:${createHash("sha256").update(stableJson(value)).digest("hex")}`;
}

function stableJson(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(stableJson).join(",")}]`;
  if (value && typeof value === "object") {
    return `{${Object.entries(value as Record<string, unknown>)
      .filter(([, child]) => child !== undefined)
      .sort(([left], [right]) => left < right ? -1 : left > right ? 1 : 0)
      .map(([key, child]) => `${JSON.stringify(key)}:${stableJson(child)}`)
      .join(",")}}`;
  }
  return JSON.stringify(value) ?? "null";
}

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

function numeric(value: unknown): number {
  return typeof value === "number" && Number.isFinite(value) ? value : 0;
}
