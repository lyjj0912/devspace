import { randomUUID } from "node:crypto";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { hostHeaderValidation } from "@modelcontextprotocol/sdk/server/middleware/hostHeaderValidation.js";
import { mcpAuthRouter, getOAuthProtectedResourceMetadataUrl } from "@modelcontextprotocol/sdk/server/auth/router.js";
import { requireBearerAuth } from "@modelcontextprotocol/sdk/server/auth/middleware/bearerAuth.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import { isInitializeRequest } from "@modelcontextprotocol/sdk/types.js";
import { checkResourceAllowed, resourceUrlFromServerUrl } from "@modelcontextprotocol/sdk/shared/auth-utils.js";
import express, { type Express, type Request, type Response } from "express";
import { loadConfig, type ServerConfig } from "../config.js";
import {
  createOpenAIIncomingArtifactAdapter,
  type IncomingArtifactAdapter,
} from "../incoming-artifacts.js";
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
import { minimumAuthorityRisk } from "./authority-policy.js";
import { ContextRegistry } from "./contexts.js";
import { UniversalExecutionPlane } from "./execution.js";
import { UniversalEnvProfileRegistry } from "./env-profiles.js";
import { UniversalFilesystemService } from "./filesystem.js";
import {
  type GuiNodeRunner,
  UniversalGuiService,
} from "./gui.js";
import { UniversalMcpProxy } from "./mcp-proxy.js";
import { UniversalMcpResultStore } from "./mcp-result-store.js";
import { assertServiceAccountBoundary } from "./no-elevation.js";
import { UniversalMcpRouteRegistry } from "./mcp-routes.js";
import { UniversalBrokerMetrics } from "./metrics.js";
import { createUniversalBrokerMcpServer } from "./server.js";
import { UniversalSelfManagementService } from "./self-management.js";
import { TargetRegistry } from "./targets.js";
import { UniversalTextResourceStore } from "./text-resource-store.js";
import {
  joinPublicUrl,
  loadUniversalBrokerNextConfig,
  type UniversalBrokerNextConfig,
} from "./config.js";

type NextTransport = StreamableHTTPServerTransport;
const MAXIMUM_HTTP_JSON_BYTES = 2 * 1024 * 1024;
const OPENAI_MCP_USER_AGENT = /^openai-mcp\//u;
const OPENAI_SESSIONLESS_DISCOVERY_METHODS = new Set([
  "notifications/initialized",
  "tools/list",
]);

function jsonRpcMethods(body: unknown): string[] {
  const messages = Array.isArray(body) ? body : [body];
  return messages.flatMap((message) => {
    if (!message || typeof message !== "object") return [];
    const method = (message as { method?: unknown }).method;
    return typeof method === "string" ? [method] : [];
  });
}

function isOpenAiSessionlessDiscoveryRequest(
  userAgent: string | undefined,
  methods: readonly string[],
): boolean {
  return Boolean(
    userAgent
    && OPENAI_MCP_USER_AGENT.test(userAgent)
    && methods.length > 0
    && methods.every((method) => OPENAI_SESSIONLESS_DISCOVERY_METHODS.has(method)),
  );
}

export interface RunningUniversalBrokerNextServer {
  app: Express;
  config: UniversalBrokerNextConfig;
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
  app.use(express.json({ limit: MAXIMUM_HTTP_JSON_BYTES }));
  if (allowedHosts) app.use(hostHeaderValidation(allowedHosts));
  const transports = new McpSessionRegistry<NextTransport>({
    maximumSessions: config.maximumMcpSessions,
  });
  const metrics = new UniversalBrokerMetrics();
  const authority = new OperationAuthorityRegistry({
    minimumRisk: minimumAuthorityRisk,
    storePath: config.authorityStorePath,
  });
  const envProfiles = new UniversalEnvProfileRegistry({
    configPath: config.envProfileConfigPath,
  });
  const targets = new TargetRegistry({
    configPath: config.targetConfigPath,
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
    }),
  });
  const execution = new UniversalExecutionPlane({
    targets,
    contexts,
    outputDir: config.processOutputDir,
    sshControlDir: config.sshControlDir,
    maxRunningProcesses: config.maxRunningProcesses,
    maxRunningProcessesPerTarget: config.maxRunningProcessesPerTarget,
    processBufferCharacters: config.processBufferCharacters,
    processOutputMaxBytes: config.processOutputMaxBytes,
    completedProcessTtlMs: config.completedProcessTtlMs,
    envProfiles,
  });
  const filesystem = new UniversalFilesystemService(
    targets,
    contexts,
    execution,
    { sshControlDir: config.sshControlDir },
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
        maximumTotalCharacters: config.mcpResultMaximumCharacters,
        ttlMs: config.mcpResultTtlMs,
      }),
      envProfiles,
    },
  );
  const artifacts = new UniversalArtifactService(filesystem, {
    baseUrl: config.publicBaseUrl,
    httpPathPrefix: config.artifactPathPrefix,
    stagingRoot: config.artifactStagingDir,
    incomingAdapters: options.incomingArtifactAdapters
      ?? [createOpenAIIncomingArtifactAdapter()],
    maximumEntries: config.artifactMaximumEntries,
    maximumTotalBytes: config.artifactMaximumTotalBytes,
    maximumArtifactBytes: config.artifactMaximumFileBytes,
    ttlMs: config.artifactTtlMs,
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
    localHealthUrl: `http://${managementHost(config.host)}:${config.port}${config.healthPath}`,
    publicHealthUrl: joinPublicUrl(config.publicBaseUrl, config.healthPath),
    expectedCwd: process.cwd(),
    expectedScript: config.selfRestartExpectedScript,
    defaultDelayMs: config.selfRestartDelayMs,
    timeoutMs: config.selfRestartTimeoutMs,
  });
  const mcpUrl = new URL(config.publicMcpUrl);
  const resourceServerUrl = resourceUrlFromServerUrl(mcpUrl);
  const resourceMetadataUrl = prefixedResourceMetadataUrl(
    config.publicBaseUrl,
    resourceServerUrl,
  );
  const oauthProvider = new SingleUserOAuthProvider(
    config.oauth,
    mcpUrl,
    config.oauthStateDir,
  );
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
    app.set("trust proxy", config.logging.trustProxy);
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

  app.get(config.healthPath, async (_req, res) => {
    try {
      const snapshot = await targets.inspect();
      const routeSnapshot = await mcpRoutes.inspect();
      res.json({
        ok: true,
        name: "devspace-universal-broker",
        phase: "universal-broker-v2",
        targetGeneration: snapshot.generation,
        targetCount: snapshot.targets.length,
        mcpRouteGeneration: routeSnapshot.generation,
        mcpRouteCount: routeSnapshot.routes.length,
      });
    } catch (error) {
      res.status(503).json({
        ok: false,
        name: "devspace-universal-broker",
        phase: "universal-broker-v2",
        error: error instanceof Error ? error.message : String(error),
      });
    }
  });

  app.get(config.metricsPath, async (req, res) => {
    if (!isLoopbackRequest(req)) {
      res.status(403).type("text/plain").send("metrics are loopback-only\n");
      return;
    }
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
    }));
  });

  app.head(`${config.artifactPathPrefix}/:artifactId`, (req, res) => {
    void artifacts.handleHttp(req, res);
  });
  app.get(`${config.artifactPathPrefix}/:artifactId`, (req, res) => {
    void artifacts.handleHttp(req, res);
  });

  app.all(config.endpointPath, async (req, res) => {
    const requestId = res.locals.requestId as string | undefined;
    const currentSessionId = req.header("mcp-session-id");
    const initializeRequest = req.method === "POST" && isInitializeRequest(req.body);
    const messageMethods = req.method === "POST" ? jsonRpcMethods(req.body) : [];

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
          selfManagement,
        });
        await server.connect(transport);
      } else if (isOpenAiSessionlessDiscoveryRequest(req.header("user-agent"), messageMethods)) {
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
          selfManagement,
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

      await transport.handleRequest(req, res, req.body);
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
    config,
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
        oauthProvider.close();
      })();
      return closePromise;
    },
  };
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

function managementHost(host: string): string {
  if (host === "0.0.0.0" || host === "::" || host === "[::]") return "127.0.0.1";
  return host.includes(":") && !host.startsWith("[") ? `[${host}]` : host;
}

function isLoopbackRequest(req: Request): boolean {
  const address = req.socket.remoteAddress ?? "";
  const socketIsLoopback = address === "127.0.0.1"
    || address === "::1"
    || address === "::ffff:127.0.0.1";
  if (!socketIsLoopback) return false;
  const host = req.header("host")?.trim();
  if (!host) return false;
  try {
    const hostname = new URL(`http://${host}`).hostname;
    return hostname === "localhost" || hostname === "127.0.0.1" || hostname === "[::1]" || hostname === "::1";
  } catch {
    return false;
  }
}

function gauge(help: string, value: number): { help: string; value: number } {
  return { help, value };
}

function numeric(value: unknown): number {
  return typeof value === "number" && Number.isFinite(value) ? value : 0;
}
