import { randomUUID } from "node:crypto";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { createMcpExpressApp } from "@modelcontextprotocol/sdk/server/express.js";
import { mcpAuthRouter, getOAuthProtectedResourceMetadataUrl } from "@modelcontextprotocol/sdk/server/auth/router.js";
import { requireBearerAuth } from "@modelcontextprotocol/sdk/server/auth/middleware/bearerAuth.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import { isInitializeRequest } from "@modelcontextprotocol/sdk/types.js";
import { checkResourceAllowed, resourceUrlFromServerUrl } from "@modelcontextprotocol/sdk/shared/auth-utils.js";
import type { Request, Response } from "express";
import { loadConfig, type ServerConfig } from "../config.js";
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
import { ContextRegistry } from "./contexts.js";
import { UniversalExecutionPlane } from "./execution.js";
import { createUniversalBrokerMcpServer } from "./server.js";
import { TargetRegistry } from "./targets.js";
import {
  loadUniversalBrokerNextConfig,
  type UniversalBrokerNextConfig,
} from "./config.js";

type NextTransport = StreamableHTTPServerTransport;

export interface RunningUniversalBrokerNextServer {
  app: ReturnType<typeof createMcpExpressApp>;
  config: UniversalBrokerNextConfig;
  targets: TargetRegistry;
  contexts: ContextRegistry;
  execution: UniversalExecutionPlane;
  close(): Promise<void>;
}

export function createUniversalBrokerNextServer(
  config = loadUniversalBrokerNextConfig(loadConfig()),
): RunningUniversalBrokerNextServer {
  const allowedHosts = config.allowedHosts.includes("*")
    ? undefined
    : Array.from(new Set([config.host, ...config.allowedHosts]));
  const app = createMcpExpressApp({
    host: config.host,
    ...(allowedHosts ? { allowedHosts } : {}),
  });
  const transports = new McpSessionRegistry<NextTransport>();
  const targets = new TargetRegistry({ configPath: config.targetConfigPath });
  const contexts = new ContextRegistry({
    storePath: config.contextStorePath,
    targets,
    serverConfig: config.serverConfig,
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
  });
  const mcpUrl = new URL(config.endpointPath, config.publicBaseUrl);
  const resourceServerUrl = resourceUrlFromServerUrl(mcpUrl);
  const oauthProvider = new SingleUserOAuthProvider(
    config.oauth,
    mcpUrl,
    config.stateDir,
  );
  const bearerAuth = requireBearerAuth({
    verifier: oauthProvider,
    requiredScopes: [config.oauth.scopes[0] ?? "devspace.read"],
    resourceMetadataUrl: getOAuthProtectedResourceMetadataUrl(resourceServerUrl),
  });

  const logSessionCloseResults = (
    reason: "idle_timeout" | "server_shutdown",
    results: McpSessionCloseResult[],
  ) => {
    for (const result of results) {
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

  const cleanupTimer = setInterval(() => {
    void transports
      .closeIdle(config.mcpSessionIdleTimeoutMs)
      .then((results) => logSessionCloseResults("idle_timeout", results));
  }, config.mcpSessionCleanupIntervalMs);
  cleanupTimer.unref();

  if (config.logging.trustProxy !== false) {
    app.set("trust proxy", config.logging.trustProxy);
  }

  app.use((req, res, next) => {
    const requestId = randomUUID();
    const startedAt = performance.now();
    res.locals.requestId = requestId;
    res.on("finish", () => {
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

  app.use(
    mcpAuthRouter({
      provider: oauthProvider,
      issuerUrl: new URL(config.publicBaseUrl),
      baseUrl: new URL(config.publicBaseUrl),
      resourceServerUrl,
      scopesSupported: config.oauth.scopes,
      resourceName: "DevSpace Universal Broker v2",
    }),
  );

  app.get("/healthz-next", async (_req, res) => {
    try {
      const snapshot = await targets.inspect();
      res.json({
        ok: true,
        name: "devspace-universal-broker",
        phase: "phase-2-target-context",
        targetGeneration: snapshot.generation,
        targetCount: snapshot.targets.length,
      });
    } catch (error) {
      res.status(503).json({
        ok: false,
        name: "devspace-universal-broker",
        phase: "phase-2-target-context",
        error: error instanceof Error ? error.message : String(error),
      });
    }
  });

  app.all(config.endpointPath, async (req, res) => {
    const requestId = res.locals.requestId as string | undefined;
    const currentSessionId = req.header("mcp-session-id");
    const initializeRequest = req.method === "POST" && isInitializeRequest(req.body);

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

    try {
      let transport: NextTransport | undefined;
      if (currentSessionId) {
        transport = transports.get(currentSessionId);
        if (!transport) {
          sendJsonRpcError(res, 404, -32000, "Unknown MCP session");
          return;
        }
      } else if (initializeRequest) {
        transport = new StreamableHTTPServerTransport({
          sessionIdGenerator: () => randomUUID(),
          onsessioninitialized: (newSessionId) => {
            if (transport) transports.register(newSessionId, transport);
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
        });
        await server.connect(transport);
      } else {
        sendJsonRpcError(res, 400, -32000, "No valid MCP session");
        return;
      }

      await transport.handleRequest(req, res, req.body);
    } catch (error) {
      logEvent(config.logging, "error", "v2_mcp_request_error", {
        requestId,
        error: error instanceof Error ? error.message : String(error),
      });
      if (!res.headersSent) {
        sendJsonRpcError(res, 500, -32603, "Internal server error");
      }
    }
  });

  let closePromise: Promise<void> | undefined;
  return {
    app,
    config,
    targets,
    contexts,
    execution,
    close: () => {
      closePromise ??= (async () => {
        clearInterval(cleanupTimer);
        const results = await transports.closeAll();
        logSessionCloseResults("server_shutdown", results);
        await execution.close();
        oauthProvider.close();
      })();
      return closePromise;
    },
  };
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
