import { createHash, randomUUID } from "node:crypto";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import {
  getDefaultEnvironment,
  StdioClientTransport,
} from "@modelcontextprotocol/sdk/client/stdio.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";
import { McpError } from "@modelcontextprotocol/sdk/types.js";
import { UniversalBrokerError } from "./errors.js";
import {
  resolvedEnvProfileExecutionGeneration,
  type ResolvedEnvProfile,
  type UniversalEnvProfileRegistry,
} from "./env-profiles.js";
import {
  routeSummary,
  type UniversalMcpRoute,
  type UniversalMcpRouteRegistry,
} from "./mcp-routes.js";
import { UniversalMcpResultStore } from "./mcp-result-store.js";
import { prepareSshControlPath } from "./ssh-control.js";
import { posixRemoteUserOnlyRunner, wrapLocalUserOnlyExecution } from "./no-elevation.js";
import { assertTargetCapability, type TargetRegistry } from "./targets.js";
import type { AuthorityRiskClass, UniversalRequestMeta } from "./contracts.js";
import type { OperationAuthorityDispatchController } from "./authority.js";
import {
  createCapabilityCallContextFromTrustedPrincipal,
  requireCapabilityCallContext,
  type CapabilityCallContext,
  type CapabilityCallContextProvider,
} from "./capability-call-context.js";
import { SynchronousQuotaReservations } from "./quota-reservations.js";
import {
  RESOURCE_DEFAULT_MCP_CONNECTIONS,
  RESOURCE_DEFAULT_MCP_IDLE_TTL_MS,
} from "./resource-defaults.js";

export type UniversalMcpOperation =
  | "routes"
  | "search_tools"
  | "describe_tool"
  | "invoke"
  | "list_resources"
  | "read_resource"
  | "list_prompts"
  | "get_prompt"
  | "close";

export interface UniversalMcpInput {
  operation: UniversalMcpOperation;
  route?: string;
  query?: string;
  name?: string;
  arguments?: Record<string, unknown>;
  uri?: string;
  cursor?: string;
  limit?: number;
  responsePolicy?: Record<string, unknown>;
  authorityId?: string;
}

type DownstreamTransport = StdioClientTransport | StreamableHTTPClientTransport;

export interface DownstreamMcpSession {
  route: UniversalMcpRoute;
  routeFingerprint: string;
  client: Client;
  transport: DownstreamTransport;
  connectedAt: number;
  lastUsedAt: number;
  activeCalls: number;
  principalKeyFingerprint?: string;
  cacheKey?: string;
  connectionGeneration?: string;
  livenessVerified?: boolean;
}

export interface McpInvocationAuthorityBinding {
  routeId: string;
  routeGeneration: string;
  toolName: string;
  toolContractSha256: string;
  riskPolicyGeneration: string;
  risk: AuthorityRiskClass;
}

export interface PreparedMcpInvocation {
  binding: McpInvocationAuthorityBinding;
  execute(dispatch?: OperationAuthorityDispatchController): Promise<Record<string, unknown>>;
  release(): void;
}

export interface UniversalMcpOperationalObserver {
  reconnect(event: {
    routeId: string;
    operation: string;
    result: "pass" | "fail";
  }): void;
  connection(event: {
    routeId: string;
    state: "connected" | "disconnected";
  }): void;
}

export interface UniversalMcpProxyOptions {
  sshControlDir: string;
  maximumSessions?: number;
  defaultSessionIdleTtlMs?: number;
  resultStore?: UniversalMcpResultStore;
  envProfiles?: UniversalEnvProfileRegistry;
  /** Compatibility injection for deterministic tests and embedders. */
  resolveEnvironmentProfile?: (
    name: string,
    targetId?: string,
  ) => Promise<Record<string, string>> | Record<string, string>;
  /** Compatibility injection for HTTP-header profiles. */
  resolveHeadersProfile?: (
    name: string,
    targetId?: string,
  ) => Promise<Record<string, string>> | Record<string, string>;
  clientFactory?: (route: UniversalMcpRoute) => Promise<DownstreamMcpSession>;
  now?: () => number;
  ownerProvider?: CapabilityCallContextProvider;
}

export class UniversalMcpProxy {
  private readonly sessions = new Map<string, Promise<DownstreamMcpSession>>();
  private readonly maximumSessions: number;
  private readonly defaultSessionIdleTtlMs: number;
  private readonly results: UniversalMcpResultStore;
  private readonly now: () => number;
  private readonly ownerProvider: CapabilityCallContextProvider;
  private readonly reservations: SynchronousQuotaReservations;
  private readonly observedConnections = new WeakSet<object>();
  private operationalObserver?: UniversalMcpOperationalObserver;
  private closed = false;

  constructor(
    private readonly routes: UniversalMcpRouteRegistry,
    private readonly targets: TargetRegistry,
    private readonly options: UniversalMcpProxyOptions,
  ) {
    this.maximumSessions = boundedInteger(
      options.maximumSessions,
      RESOURCE_DEFAULT_MCP_CONNECTIONS,
      1,
      256,
      "maximumSessions",
    );
    this.defaultSessionIdleTtlMs = boundedInteger(
      options.defaultSessionIdleTtlMs,
      RESOURCE_DEFAULT_MCP_IDLE_TTL_MS,
      1_000,
      3_600_000,
      "defaultSessionIdleTtlMs",
    );
    this.results = options.resultStore ?? new UniversalMcpResultStore();
    this.now = options.now ?? Date.now;
    const compatibilityOwner = createCapabilityCallContextFromTrustedPrincipal({
      principalKeyFingerprint: createHash("sha256")
        .update(JSON.stringify({
          authority: "legacy-single-owner-mcp-proxy",
          sshControlDir: options.sshControlDir,
        }))
        .digest("hex"),
    });
    this.ownerProvider = options.ownerProvider ?? (() => compatibilityOwner);
    this.reservations = new SynchronousQuotaReservations("downstream-mcp-session", {
      entries: this.maximumSessions,
    });
  }

  setOperationalObserver(observer: UniversalMcpOperationalObserver | undefined): void {
    this.operationalObserver = observer;
  }

  async execute(
    input: UniversalMcpInput,
    callContext?: CapabilityCallContext,
    requestMeta: UniversalRequestMeta = {},
  ): Promise<Record<string, unknown>> {
    this.assertOpen();
    const owner = this.owner(callContext);
    await this.pruneIdle();
    switch (input.operation) {
      case "routes":
        rejectUnrelatedRouteGeneration(requestMeta, "routes");
        return this.routes.list();
      case "close":
        return this.closeRoute(input.route, owner, requestMeta.expectedRouteGeneration);
      case "search_tools":
        return this.withSession(
          input.route,
          "search_tools",
          owner,
          requestMeta.expectedRouteGeneration,
          async (session) => {
          const query = requireText(input.query, "mcp.search_tools requires query.");
          const listed = await timed(
            session.client.listTools(),
            session.route.callTimeoutMs,
            `${session.route.id} tools/list`,
          );
          const limit = boundedInteger(input.limit, 5, 1, 5, "limit");
          return {
            route: routeSummary(session.route),
            tools: listed.tools
              .map((tool) => ({
                name: tool.name,
                title: tool.title,
                description: tool.description,
                annotations: tool.annotations,
                score: scoreTool(tool, query),
              }))
              .filter((tool) => tool.score > 0)
              .sort((left, right) => right.score - left.score || left.name.localeCompare(right.name))
              .slice(0, limit),
          };
          },
        );
      case "describe_tool":
        return this.withSession(
          input.route,
          "describe_tool",
          owner,
          requestMeta.expectedRouteGeneration,
          async (session) => {
          const name = requireText(input.name, "mcp.describe_tool requires name.");
          const listed = await timed(
            session.client.listTools(),
            session.route.callTimeoutMs,
            `${session.route.id} tools/list`,
          );
          const tool = listed.tools.find((candidate) => candidate.name === name);
          if (!tool) {
            throw new UniversalBrokerError(
              "MCP_TOOL_NOT_FOUND",
              `MCP tool ${name} is not exposed by route ${session.route.id}.`,
              {
                suggestions: listed.tools
                  .map((candidate) => ({ name: candidate.name }))
                  .sort((left, right) => left.name.localeCompare(right.name)),
              },
            );
          }
          return {
            route: routeSummary(session.route),
            result: this.project({ tool }, input.responsePolicy, session.route.id, owner),
          };
          },
        );
      case "invoke":
        return (await this.prepareInvocation(input, owner, requestMeta)).execute();
      case "list_resources":
        return this.withSession(
          input.route,
          "list_resources",
          owner,
          requestMeta.expectedRouteGeneration,
          async (session) => {
          const [resources, templates] = await timed(
            Promise.all([
              session.client.listResources(input.cursor ? { cursor: input.cursor } : undefined),
              session.client.listResourceTemplates(),
            ]),
            session.route.callTimeoutMs,
            `${session.route.id} resources/list`,
          );
          return {
            route: routeSummary(session.route),
            result: this.project(
              { resources, resourceTemplates: templates },
              withLimit(input.responsePolicy, input.limit),
              session.route.id,
              owner,
            ),
          };
          },
        );
      case "read_resource":
        const requestedUri = input.uri;
        if (requestedUri !== undefined && (
          requestedUri.startsWith("devspace://mcp-result/")
          || /^devspace:\/\/mcp\/[^/]+\/result\//u.test(requestedUri)
        )) {
          if (requestMeta.expectedRouteGeneration !== undefined) {
            const routeId = canonicalResultRouteId(requestedUri);
            if (!routeId) {
              rejectUnrelatedRouteGeneration(requestMeta, "legacy stored-result read");
            }
            const route = await this.routes.resolve(routeId);
            assertExpectedProxyRouteGeneration(
              requestMeta.expectedRouteGeneration,
              await this.routeExecutionGeneration(route),
              route.id,
            );
          }
          return this.results.readByUri(requestedUri, owner);
        }
        return this.withSession(
          input.route,
          "read_resource",
          owner,
          requestMeta.expectedRouteGeneration,
          async (session) => {
          const uri = requireText(input.uri, "mcp.read_resource requires uri.");
          const response = await timed(
            session.client.readResource({ uri }),
            session.route.callTimeoutMs,
            `${session.route.id} resources/read`,
          );
          return {
            route: routeSummary(session.route),
            result: this.project(response, input.responsePolicy, session.route.id, owner),
          };
          },
        );
      case "list_prompts":
        return this.withSession(
          input.route,
          "list_prompts",
          owner,
          requestMeta.expectedRouteGeneration,
          async (session) => {
          const response = await timed(
            session.client.listPrompts(input.cursor ? { cursor: input.cursor } : undefined),
            session.route.callTimeoutMs,
            `${session.route.id} prompts/list`,
          );
          return {
            route: routeSummary(session.route),
            result: this.project(
              response,
              withLimit(input.responsePolicy, input.limit),
              session.route.id,
              owner,
            ),
          };
          },
        );
      case "get_prompt":
        return this.withSession(
          input.route,
          "get_prompt",
          owner,
          requestMeta.expectedRouteGeneration,
          async (session) => {
          const name = requireText(input.name, "mcp.get_prompt requires name.");
          const response = await timed(
            session.client.getPrompt({
              name,
              arguments: promptArguments(input.arguments),
            }),
            session.route.callTimeoutMs,
            `${session.route.id} prompts/get`,
          );
          return {
            route: routeSummary(session.route),
            prompt: name,
            result: this.project(response, input.responsePolicy, session.route.id, owner),
          };
          },
        );
    }
  }

  async prepareInvocation(
    input: UniversalMcpInput,
    callContext?: CapabilityCallContext,
    requestMeta: UniversalRequestMeta = {},
  ): Promise<PreparedMcpInvocation> {
    this.assertOpen();
    const owner = this.owner(callContext);
    if (input.operation !== "invoke") {
      throw new UniversalBrokerError(
        "PRECONDITION_FAILED",
        "Only mcp.invoke can be prepared for exact downstream dispatch.",
      );
    }
    await this.pruneIdle();
    let session = await this.acquireSession(
      input.route,
      "prepare_invocation",
      owner,
      requestMeta.expectedRouteGeneration,
    );
    let released = false;
    let executed = false;
    let reconnects = 0;
    const release = () => {
      if (released) return;
      released = true;
      this.releaseSession(session);
    };
    try {
      const name = requireText(input.name, "mcp.invoke requires name.");
      let listed;
      try {
        listed = await timed(
          session.client.listTools(),
          session.route.callTimeoutMs,
          `${session.route.id} tools/list`,
        );
      } catch (error) {
        if (!isExactNotConnected(error)) throw error;
        const previous = session;
        const routeId = previous.route.id;
        this.releaseSession(previous);
        await this.evict(previous.cacheKey!, previous);
        reconnects += 1;
        try {
          session = await this.acquireSession(
            input.route,
            "prepare_invocation_reconnect",
            owner,
            requestMeta.expectedRouteGeneration,
          );
          listed = await timed(
            session.client.listTools(),
            session.route.callTimeoutMs,
            `${session.route.id} tools/list after reconnect`,
          );
          this.observeReconnect(routeId, "prepare_invocation", "pass");
        } catch (reconnectError) {
          this.observeReconnect(routeId, "prepare_invocation", "fail");
          throw reconnectError;
        }
      }
      session.livenessVerified = true;
      const tool = requireDownstreamTool(session.route.id, name, listed.tools);
      const toolContractSha256 = downstreamMcpToolContractSha256(tool);
      const binding: McpInvocationAuthorityBinding = {
        routeId: session.route.id,
        routeGeneration: session.routeFingerprint,
        toolName: name,
        toolContractSha256,
        riskPolicyGeneration: session.route.riskPolicy?.policyDigest ?? "none",
        risk: downstreamInvocationRisk(session.route, tool, toolContractSha256),
      };
      const invocation = {
        name,
        arguments: structuredClone(input.arguments ?? {}),
        responsePolicy: input.responsePolicy
          ? structuredClone(input.responsePolicy)
          : undefined,
      };
      return {
        binding,
        execute: async (dispatch) => {
          if (executed) {
            throw new UniversalBrokerError(
              "PRECONDITION_FAILED",
              `Prepared MCP invocation ${binding.routeId}.${binding.toolName} can execute only once.`,
            );
          }
          if (released) {
            throw new UniversalBrokerError(
              "PRECONDITION_FAILED",
              `Prepared MCP invocation ${binding.routeId}.${binding.toolName} was released.`,
            );
          }
          executed = true;
          try {
            dispatch?.claim();
            const beforeRevalidation = session;
            session = await this.assertPreparedToolContract(
              session,
              binding,
              owner,
              reconnects === 0,
            );
            if (session !== beforeRevalidation) reconnects += 1;
            return await this.invokePreparedSession(
              session,
              invocation,
              binding,
              owner,
              dispatch,
            );
          } finally {
            release();
          }
        },
        release,
      };
    } catch (error) {
      release();
      if (error instanceof UniversalBrokerError) throw error;
      if (error instanceof McpError && !isExactNotConnected(error)) {
        throw new UniversalBrokerError(
          "MCP_PROVIDER_ERROR",
          `MCP route ${session.route.id} rejected tool inspection: ${error.message}`,
          { evidence: { routeId: session.route.id, providerCode: error.code } },
        );
      }
      await this.evict(session.cacheKey!, session);
      throw new UniversalBrokerError(
        "TRANSPORT_INTERRUPTED",
        `MCP route ${session.route.id} transport failed while preparing an invocation.`,
        { evidence: { routeId: session.route.id, cause: errorMessage(error) } },
      );
    }
  }

  async inspectInvocation(
    input: Pick<UniversalMcpInput, "route" | "name">,
    callContext?: CapabilityCallContext,
  ): Promise<McpInvocationAuthorityBinding> {
    const prepared = await this.prepareInvocation({ ...input, operation: "invoke" }, callContext);
    try {
      return prepared.binding;
    } finally {
      prepared.release();
    }
  }

  async inspectRoute(selector: string | undefined): Promise<{
    routeId: string;
    routeGeneration: string;
  }> {
    const route = await this.routes.resolve(selector);
    return {
      routeId: route.id,
      routeGeneration: await this.routeExecutionGeneration(route),
    };
  }

  readStoredResult(uri: string, callContext?: CapabilityCallContext): Record<string, unknown> {
    return this.results.readByUri(uri, this.owner(callContext));
  }

  async close(): Promise<void> {
    if (this.closed) return;
    this.closed = true;
    const pending = [...this.sessions.values()];
    this.sessions.clear();
    this.results.clear();
    await Promise.allSettled(pending.map(async (sessionPromise) => {
      const session = await sessionPromise.catch(() => undefined);
      if (session) await this.closeObservedSession(session);
    }));
  }

  async stats(): Promise<Record<string, unknown>> {
    await this.pruneIdle();
    const resolved = await Promise.all([...this.sessions.entries()].map(async ([cacheKey, pending]) => {
      const session = await pending.catch(() => undefined);
      return session
        ? {
            routeId: session.route.id,
            connectionGeneration: session.connectionGeneration,
            livenessVerified: session.livenessVerified === true,
            activeCalls: session.activeCalls,
            lastUsedAt: session.lastUsedAt,
          }
        : { routeId: cacheKey.split("\0").at(-1), activeCalls: 0, lastUsedAt: 0 };
    }));
    return {
      sessions: this.sessions.size,
      maximumSessions: this.maximumSessions,
      activeCalls: resolved.reduce((total, entry) => total + entry.activeCalls, 0),
      routes: resolved.sort((left, right) => (left.routeId ?? "").localeCompare(right.routeId ?? "")),
      results: this.results.stats(),
    };
  }

  private async withSession<T extends Record<string, unknown>>(
    selector: string | undefined,
    operation: string,
    owner: CapabilityCallContext,
    expectedRouteGeneration: string | undefined,
    callback: (session: DownstreamMcpSession) => Promise<T>,
  ): Promise<T> {
    let session = await this.acquireSession(
      selector,
      operation,
      owner,
      expectedRouteGeneration,
    );
    try {
      try {
        const result = await callback(session);
        session.livenessVerified = true;
        return {
          ...result,
          livenessVerified: true,
          connectionGeneration: session.connectionGeneration,
        };
      } catch (error) {
        if (!isExactNotConnected(error)) throw error;
        const previous = session;
        const routeId = previous.route.id;
        this.releaseSession(previous);
        await this.evict(previous.cacheKey!, previous);
        try {
          session = await this.acquireSession(
            selector,
            `${operation}_reconnect`,
            owner,
            expectedRouteGeneration,
          );
          const result = await callback(session);
          session.livenessVerified = true;
          this.observeReconnect(routeId, operation, "pass");
          return {
            ...result,
            livenessVerified: true,
            connectionGeneration: session.connectionGeneration,
          };
        } catch (reconnectError) {
          this.observeReconnect(routeId, operation, "fail");
          throw reconnectError;
        }
      }
    } catch (error) {
      if (error instanceof UniversalBrokerError) throw error;
      if (error instanceof McpError && !isExactNotConnected(error)) {
        throw new UniversalBrokerError(
          "MCP_PROVIDER_ERROR",
          `MCP route ${session.route.id} failed during ${operation}: ${error.message}`,
          { evidence: { routeId: session.route.id, providerCode: error.code } },
        );
      }
      await this.evict(session.cacheKey!, session);
      throw new UniversalBrokerError(
        "TRANSPORT_INTERRUPTED",
        `MCP route ${session.route.id} transport failed during ${operation}.`,
        { evidence: { routeId: session.route.id, cause: errorMessage(error) } },
      );
    } finally {
      this.releaseSession(session);
    }
  }

  private async acquireSession(
    selector: string | undefined,
    operation: string,
    owner: CapabilityCallContext,
    expectedRouteGeneration?: string,
  ): Promise<DownstreamMcpSession> {
    const route = await this.routes.resolve(selector);
    const routeFingerprint = await this.routeExecutionGeneration(route);
    assertExpectedProxyRouteGeneration(
      expectedRouteGeneration,
      routeFingerprint,
      route.id,
    );
    const cacheKey = sessionCacheKey(owner.principalKeyFingerprint, route.id);
    let session: DownstreamMcpSession;
    try {
      session = await this.session(route, routeFingerprint, cacheKey, owner);
    } catch (error) {
      if (error instanceof UniversalBrokerError) throw error;
      throw new UniversalBrokerError(
        "TRANSPORT_UNAVAILABLE",
        `MCP route ${route.id} could not connect for ${operation}.`,
        { evidence: { routeId: route.id, cause: errorMessage(error) } },
      );
    }
    session.lastUsedAt = this.now();
    this.touchSession(cacheKey);
    session.activeCalls += 1;
    return session;
  }

  private releaseSession(session: DownstreamMcpSession): void {
    session.activeCalls = Math.max(0, session.activeCalls - 1);
    session.lastUsedAt = this.now();
  }

  private async assertPreparedToolContract(
    session: DownstreamMcpSession,
    binding: McpInvocationAuthorityBinding,
    owner: CapabilityCallContext,
    allowReconnect: boolean,
  ): Promise<DownstreamMcpSession> {
    let listed;
    try {
      listed = await timed(
        session.client.listTools(),
        session.route.callTimeoutMs,
        `${session.route.id} tools/list pre-dispatch check`,
      );
    } catch (error) {
      if (isExactNotConnected(error) && allowReconnect) {
        const previous = session;
        const routeId = previous.route.id;
        this.releaseSession(previous);
        await this.evict(previous.cacheKey!, previous);
        let replacement: DownstreamMcpSession | undefined;
        try {
          replacement = await this.acquireSession(
            binding.routeId,
            "prepared_invocation_reconnect",
            owner,
            binding.routeGeneration,
          );
          listed = await timed(
            replacement.client.listTools(),
            replacement.route.callTimeoutMs,
            `${replacement.route.id} tools/list after reconnect`,
          );
          replacement.livenessVerified = true;
          session = replacement;
          this.observeReconnect(routeId, "prepared_invocation_revalidation", "pass");
        } catch (replacementError) {
          this.observeReconnect(routeId, "prepared_invocation_revalidation", "fail");
          if (replacement) {
            this.releaseSession(replacement);
            await this.evict(replacement.cacheKey!, replacement);
          }
          throw new UniversalBrokerError(
            "TRANSPORT_INTERRUPTED",
            `MCP route ${routeId} remained disconnected before provider dispatch.`,
            { evidence: { routeId, cause: errorMessage(replacementError) } },
          );
        }
      } else {
        await this.evict(session.cacheKey!, session);
        throw new UniversalBrokerError(
          "TRANSPORT_INTERRUPTED",
          `MCP route ${session.route.id} could not revalidate the prepared tool before dispatch.`,
          { evidence: { routeId: session.route.id, cause: errorMessage(error) } },
        );
      }
    }
    const tool = requireDownstreamTool(session.route.id, binding.toolName, listed.tools);
    if (downstreamMcpToolContractSha256(tool) !== binding.toolContractSha256) {
      throw new UniversalBrokerError(
        "AUTHORITY_STALE",
        `MCP tool contract changed after ${binding.routeId}.${binding.toolName} was prepared; provider dispatch was not attempted.`,
        {
          evidence: {
            routeId: binding.routeId,
            tool: binding.toolName,
            routeGeneration: binding.routeGeneration,
          },
        },
      );
    }
    session.livenessVerified = true;
    return session;
  }

  private async invokePreparedSession(
    session: DownstreamMcpSession,
    invocation: {
      name: string;
      arguments: Record<string, unknown>;
      responsePolicy?: Record<string, unknown>;
    },
    binding: McpInvocationAuthorityBinding,
    owner: CapabilityCallContext,
    dispatch?: OperationAuthorityDispatchController,
  ): Promise<Record<string, unknown>> {
    await this.assertCurrentPreparedRoute(binding);
    dispatch?.markDispatched();
    let response;
    try {
      response = await timed(
        session.client.callTool({
          name: invocation.name,
          arguments: invocation.arguments,
        }),
        session.route.callTimeoutMs,
        `${session.route.id}.${invocation.name}`,
      );
    } catch (error) {
      await this.evict(session.cacheKey!, session);
      if (error instanceof McpError && !isExactNotConnected(error)) {
        throw new UniversalBrokerError(
          "MCP_PROVIDER_ERROR",
          `MCP provider rejected ${session.route.id}.${invocation.name}: ${error.message}`,
          {
            evidence: {
              routeId: session.route.id,
              tool: invocation.name,
              providerCode: error.code,
            },
          },
        );
      }
      throw new UniversalBrokerError(
        "MCP_RESULT_UNKNOWN",
        `MCP route ${session.route.id} failed after dispatching ${invocation.name}; the result is unknown and was not retried.`,
        {
          evidence: {
            routeId: session.route.id,
            tool: invocation.name,
            cause: errorMessage(error),
          },
        },
      );
    }
    if (response.isError === true) {
      throw new UniversalBrokerError(
        "MCP_PROVIDER_ERROR",
        `MCP provider returned an error for ${session.route.id}.${invocation.name}.`,
        {
          evidence: {
            routeId: session.route.id,
            tool: invocation.name,
            responsePreview: boundedJson(response, 2_000),
          },
        },
      );
    }
    session.livenessVerified = true;
    return {
      route: routeSummary(session.route),
      tool: invocation.name,
      livenessVerified: true,
      connectionGeneration: session.connectionGeneration,
      result: this.project(response, invocation.responsePolicy, session.route.id, owner),
    };
  }

  private async assertCurrentPreparedRoute(
    binding: McpInvocationAuthorityBinding,
  ): Promise<void> {
    let current: UniversalMcpRoute;
    try {
      current = await this.routes.resolve(binding.routeId);
    } catch (error) {
      throw new UniversalBrokerError(
        "AUTHORITY_STALE",
        `MCP route ${binding.routeId} could not be revalidated immediately before provider dispatch.`,
        {
          evidence: {
            routeId: binding.routeId,
            preparedRouteGeneration: binding.routeGeneration,
            causeCode: error instanceof UniversalBrokerError ? error.code : "UNEXPECTED_ERROR",
          },
        },
      );
    }
    let currentRouteGeneration: string;
    try {
      currentRouteGeneration = await this.routeExecutionGeneration(current);
    } catch (error) {
      throw new UniversalBrokerError(
        "AUTHORITY_STALE",
        `MCP route ${binding.routeId} runtime dependencies could not be revalidated before provider dispatch.`,
        {
          evidence: {
            routeId: binding.routeId,
            preparedRouteGeneration: binding.routeGeneration,
            causeCode: error instanceof UniversalBrokerError ? error.code : "UNEXPECTED_ERROR",
          },
        },
      );
    }
    const currentPolicyGeneration = current.riskPolicy?.policyDigest ?? "none";
    if (
      currentRouteGeneration === binding.routeGeneration
      && currentPolicyGeneration === binding.riskPolicyGeneration
    ) return;
    throw new UniversalBrokerError(
      "AUTHORITY_STALE",
      `MCP route or broker-owned risk policy changed after ${binding.routeId}.${binding.toolName} was prepared; provider dispatch was not attempted.`,
      {
        evidence: {
          routeId: binding.routeId,
          tool: binding.toolName,
          preparedRouteGeneration: binding.routeGeneration,
          observedRouteGeneration: currentRouteGeneration,
          preparedRiskPolicyGeneration: binding.riskPolicyGeneration,
          observedRiskPolicyGeneration: currentPolicyGeneration,
        },
      },
    );
  }

  private async session(
    route: UniversalMcpRoute,
    fingerprint: string,
    cacheKey: string,
    owner: CapabilityCallContext,
  ): Promise<DownstreamMcpSession> {
    const existing = this.sessions.get(cacheKey);
    if (existing) {
      const resolved = await existing.catch(() => undefined);
      if (resolved?.routeFingerprint === fingerprint) return existing;
      if (resolved?.activeCalls) {
        throw new UniversalBrokerError(
          "PRECONDITION_FAILED",
          `MCP route ${route.id} changed generation while an earlier generation is in flight.`,
          {
            evidence: {
              routeId: route.id,
              activeCalls: resolved.activeCalls,
              activeGeneration: resolved.routeFingerprint,
              requestedGeneration: fingerprint,
            },
          },
        );
      }
      if (resolved) await this.closeObservedSession(resolved);
      this.sessions.delete(cacheKey);
    }
    const reservation = this.reservations.reserve(
      { entries: this.sessions.size },
      { entries: 1 },
    );
    const connectionGeneration = `mcpconn_${randomUUID()}`;
    let pending!: Promise<DownstreamMcpSession>;
    try {
      const creation = this.options.clientFactory
        ? this.options.clientFactory(route).then((session) => ({
            ...session,
            route,
            routeFingerprint: fingerprint,
            principalKeyFingerprint: owner.principalKeyFingerprint,
            cacheKey,
            connectionGeneration,
            livenessVerified: false,
          }))
        : this.connect(route, fingerprint, cacheKey, owner, connectionGeneration);
      pending = creation.then((session) => {
        this.installGenerationClose(session);
        this.observeConnection(session, "connected");
        return session;
      }).catch((error) => {
        if (this.sessions.get(cacheKey) === pending) this.sessions.delete(cacheKey);
        throw error;
      });
      reservation.commit(() => this.sessions.set(cacheKey, pending));
      return pending;
    } finally {
      reservation.release();
    }
  }

  private async routeExecutionGeneration(route: UniversalMcpRoute): Promise<string> {
    let targetId: string | undefined;
    let targetGeneration: string | undefined;
    if (route.transport === "local-stdio" || route.transport === "ssh-stdio") {
      const targetBinding = await this.targets.resolveWithGeneration(
        route.transport === "local-stdio" ? "local" : route.target,
      );
      assertTargetCapability(targetBinding.target, "mcp");
      targetId = targetBinding.target.id;
      targetGeneration = targetBinding.generation;
    }
    let envProfileGeneration: string | undefined;
    if (route.envProfile) {
      const profile = await this.requireEnvProfiles().resolve(route.envProfile, targetId ?? "local");
      assertRouteEnvironmentProfile(route, profile);
      envProfileGeneration = await resolvedEnvProfileExecutionGeneration(
        profile,
        route.transport === "ssh-stdio" ? "remote" : "local",
      );
    }
    return createHash("sha256").update(stableJson({
      routeGeneration: route.generation,
      targetId,
      targetGeneration,
      envProfileId: route.envProfile,
      envProfileGeneration,
    })).digest("hex");
  }

  private async connect(
    route: UniversalMcpRoute,
    fingerprint: string,
    cacheKey: string,
    owner: CapabilityCallContext,
    connectionGeneration: string,
  ): Promise<DownstreamMcpSession> {
    const transport = await this.transport(route);
    const client = new Client({
      name: `devspace-universal-proxy-${route.id}`,
      version: "2.0.0",
    });
    try {
      await timed(
        client.connect(transport),
        route.startupTimeoutMs,
        `${route.id} startup`,
      );
      const now = this.now();
      return {
        route,
        routeFingerprint: fingerprint,
        client,
        transport,
        connectedAt: now,
        lastUsedAt: now,
        activeCalls: 0,
        principalKeyFingerprint: owner.principalKeyFingerprint,
        cacheKey,
        connectionGeneration,
        livenessVerified: false,
      };
    } catch (error) {
      await Promise.allSettled([client.close(), transport.close()]);
      throw error;
    }
  }

  private async transport(route: UniversalMcpRoute): Promise<DownstreamTransport> {
    const target = route.transport === "ssh-stdio"
      ? await this.targets.resolve(route.target)
      : undefined;
    const localTarget = route.transport === "local-stdio"
      ? await this.targets.resolve("local")
      : undefined;
    const profile = route.envProfile
      ? await this.requireEnvProfiles().resolve(route.envProfile, target?.id ?? "local")
      : undefined;
    if (profile) assertRouteEnvironmentProfile(route, profile);
    if (route.transport === "streamable-http") {
      return new StreamableHTTPClientTransport(new URL(route.url!), {
        ...(profile && Object.keys(profile.headers).length > 0
          ? { requestInit: { headers: profile.headers } }
          : {}),
      });
    }
    let environment = getDefaultEnvironment();
    if (profile) {
      environment = {
        ...environment,
        ...profile.environment,
      };
    }
    if (route.transport === "local-stdio") {
      if (!localTarget) {
        throw new UniversalBrokerError(
          "CAPABILITY_UNAVAILABLE",
          `Local target is unavailable for MCP route ${route.id}.`,
        );
      }
      const direct = profile?.sourceFile
        ? {
            executable: "/bin/sh",
            args: [
              "-lc",
              `set -a; . ${shellQuote(profile.sourceFile)}; set +a; exec ${[route.command!, ...route.args].map(shellQuote).join(" ")}`,
            ],
          }
        : { executable: route.command!, args: route.args };
      const wrapped = wrapLocalUserOnlyExecution(localTarget.platform, direct, "mcp");
      return new StdioClientTransport({
        command: wrapped.executable,
        args: wrapped.args,
        env: environment,
        stderr: "pipe",
      });
    }
    if (!target || target.transport !== "ssh" || !target.sshHost) {
      throw new UniversalBrokerError(
        "TRANSPORT_UNAVAILABLE",
        `MCP route ${route.id} requires an SSH target with sshHost.`,
      );
    }
    const controlPath = await prepareSshControlPath(this.options.sshControlDir);
    const command = [route.command!, ...route.args]
      .map(shellQuote)
      .join(" ");
    const remoteCommand = profile?.sourceFile
      ? `set -a; . ${shellQuote(profile.sourceFile)}; set +a; exec ${command}`
      : `exec ${command}`;
    if (target.platform === "windows") {
      throw new UniversalBrokerError(
        "CAPABILITY_UNAVAILABLE",
        `SSH stdio MCP route ${route.id} requires a POSIX target.`,
      );
    }
    const userOnlyCommand = posixRemoteUserOnlyRunner(
      target.platform,
      "sh",
      remoteCommand,
      "mcp",
    );
    return new StdioClientTransport({
      command: "/usr/bin/ssh",
      args: [
        "-o", "BatchMode=yes",
        "-o", "ConnectTimeout=7",
        "-o", "ConnectionAttempts=1",
        "-o", "ControlMaster=auto",
        "-o", "ControlPersist=90",
        "-o", `ControlPath=${controlPath}`,
        "-T",
        target.sshHost,
        userOnlyCommand,
      ],
      env: environment,
      stderr: "pipe",
    });
  }

  private requireEnvProfiles(): UniversalEnvProfileRegistry {
    if (!this.options.envProfiles) {
      throw new UniversalBrokerError(
        "CAPABILITY_UNAVAILABLE",
        "Environment profile registry is not configured.",
      );
    }
    return this.options.envProfiles;
  }

  private project(
    value: unknown,
    policy: Record<string, unknown> | undefined,
    routeId: string,
    owner: CapabilityCallContext,
  ): Record<string, unknown> {
    const maximumCharacters = policyInteger(policy, "maxCharacters", 12_000, 100, 100_000);
    const maximumItems = policyInteger(policy, "maxItems", 50, 1, 1_000);
    const preserve = policyBoolean(policy, "preserveFullResult", true);
    const pointers = policyStringArray(policy, "jsonPointers");
    const selected = pointers.length > 0 ? selectPointers(value, pointers) : value;
    const bounded = boundArrays(selected, maximumItems);
    const serialized = JSON.stringify(bounded.value) ?? "null";
    if (serialized.length <= maximumCharacters && !bounded.truncated) {
      return { truncated: false, value: bounded.value };
    }
    const stored = preserve ? this.results.put(value, routeId, owner) : undefined;
    return {
      truncated: true,
      preview: headTail(serialized, maximumCharacters),
      projectedValue: serialized.length <= maximumCharacters ? bounded.value : undefined,
      totalCharacters: (JSON.stringify(value) ?? "null").length,
      itemLimitApplied: bounded.truncated,
      ...(stored ?? {}),
    };
  }

  private async closeRoute(
    selector: string | undefined,
    owner: CapabilityCallContext,
    expectedRouteGeneration?: string,
  ): Promise<Record<string, unknown>> {
    if (!selector) {
      rejectUnrelatedRouteGeneration(
        { expectedRouteGeneration },
        "close without a route selector",
      );
      const owned = (await Promise.all([...this.sessions.entries()].map(async ([cacheKey, pending]) => ({
        cacheKey,
        session: await pending.catch(() => undefined),
      })))).filter((entry) =>
        entry.session?.principalKeyFingerprint === owner.principalKeyFingerprint
      );
      await Promise.all(owned.map((entry) => this.closeSessionByKey(entry.cacheKey)));
      return { closedRoutes: owned.map((entry) => entry.session!.route.id).sort() };
    }
    const route = await this.routes.resolve(selector);
    assertExpectedProxyRouteGeneration(
      expectedRouteGeneration,
      await this.routeExecutionGeneration(route),
      route.id,
    );
    const closed = await this.closeSessionByKey(
      sessionCacheKey(owner.principalKeyFingerprint, route.id),
    );
    return { routeId: route.id, closed };
  }

  private async closeSessionByKey(cacheKey: string): Promise<boolean> {
    const pending = this.sessions.get(cacheKey);
    this.sessions.delete(cacheKey);
    const session = await pending?.catch(() => undefined);
    if (session) await this.closeObservedSession(session);
    return Boolean(pending);
  }

  private async evict(cacheKey: string, session: DownstreamMcpSession): Promise<void> {
    const pending = this.sessions.get(cacheKey);
    if (!pending) return;
    const candidate = await pending.catch(() => undefined);
    if (candidate !== session || this.sessions.get(cacheKey) !== pending) return;
    this.sessions.delete(cacheKey);
    await this.closeObservedSession(session);
  }

  private async pruneIdle(): Promise<void> {
    const now = this.now();
    for (const [cacheKey, pending] of [...this.sessions]) {
      const session = await pending.catch(() => undefined);
      if (!session) continue;
      const ttl = session.route.idleTimeoutMs || this.defaultSessionIdleTtlMs;
      if (session.activeCalls === 0 && session.lastUsedAt + ttl <= now) {
        await this.closeSessionByKey(cacheKey);
      }
    }
  }

  private touchSession(cacheKey: string): void {
    const pending = this.sessions.get(cacheKey);
    if (!pending) return;
    this.sessions.delete(cacheKey);
    this.sessions.set(cacheKey, pending);
  }

  private installGenerationClose(session: DownstreamMcpSession): void {
    const transport = session.transport as unknown as { onclose?: () => void };
    const previous = transport.onclose;
    transport.onclose = () => {
      previous?.();
      void this.handleTransportClose(session);
    };
  }

  private async handleTransportClose(session: DownstreamMcpSession): Promise<void> {
    this.observeConnection(session, "disconnected");
    const cacheKey = session.cacheKey!;
    const pending = this.sessions.get(cacheKey);
    if (!pending) return;
    const current = await pending.catch(() => undefined);
    if (
      current?.connectionGeneration !== session.connectionGeneration
      || this.sessions.get(cacheKey) !== pending
    ) return;
    this.sessions.delete(cacheKey);
  }

  private async closeObservedSession(session: DownstreamMcpSession): Promise<void> {
    try {
      await closeSession(session);
    } finally {
      this.observeConnection(session, "disconnected");
    }
  }

  private observeConnection(
    session: DownstreamMcpSession,
    state: "connected" | "disconnected",
  ): void {
    if (state === "connected") {
      if (this.observedConnections.has(session)) return;
      this.observedConnections.add(session);
    } else {
      if (!this.observedConnections.has(session)) return;
      this.observedConnections.delete(session);
    }
    try {
      this.operationalObserver?.connection({ routeId: session.route.id, state });
    } catch {
      // Observability cannot change downstream transport state.
    }
  }

  private observeReconnect(
    routeId: string,
    operation: string,
    result: "pass" | "fail",
  ): void {
    try {
      this.operationalObserver?.reconnect({ routeId, operation, result });
    } catch {
      // Observability cannot replace the reconnect result.
    }
  }

  private assertOpen(): void {
    if (this.closed) {
      throw new UniversalBrokerError("TRANSPORT_UNAVAILABLE", "The generic MCP proxy is closed.");
    }
  }

  private owner(callContext?: CapabilityCallContext): CapabilityCallContext {
    return requireCapabilityCallContext(callContext, this.ownerProvider);
  }
}

function assertRouteEnvironmentProfile(
  route: UniversalMcpRoute,
  profile: ResolvedEnvProfile,
): void {
  if (
    route.transport === "streamable-http"
    && (Object.keys(profile.environment).length > 0 || profile.sourceFile)
  ) {
    throw new UniversalBrokerError(
      "PRECONDITION_FAILED",
      `HTTP MCP route ${route.id} environment profile may contain headers only.`,
    );
  }
  if (route.transport === "local-stdio" && Object.keys(profile.headers).length > 0) {
    throw new UniversalBrokerError(
      "PRECONDITION_FAILED",
      `Local stdio MCP route ${route.id} environment profile may not contain HTTP headers.`,
    );
  }
  if (
    route.transport === "ssh-stdio"
    && (Object.keys(profile.environment).length > 0 || Object.keys(profile.headers).length > 0)
  ) {
    throw new UniversalBrokerError(
      "PRECONDITION_FAILED",
      `SSH stdio MCP route ${route.id} environment profile must use sourceFile only.`,
    );
  }
}

function assertExpectedProxyRouteGeneration(
  expected: string | undefined,
  observed: string,
  routeId: string,
): void {
  if (expected === undefined || expected === observed) return;
  throw new UniversalBrokerError(
    "AUTHORITY_STALE",
    `MCP route ${routeId} does not match the expected route generation.`,
    {
      evidence: {
        routeId,
        expectedRouteGeneration: expected,
        observedRouteGeneration: observed,
        routeGeneration: observed,
        providerDispatchCount: 0,
        durableClaimCount: 0,
      },
    },
  );
}

function rejectUnrelatedRouteGeneration(
  requestMeta: Pick<UniversalRequestMeta, "expectedRouteGeneration">,
  operation: string,
): void {
  if (requestMeta.expectedRouteGeneration === undefined) return;
  throw new UniversalBrokerError(
    "INVALID_ARGUMENT",
    `expectedRouteGeneration does not apply to MCP ${operation}.`,
    { evidence: { operation, providerDispatchCount: 0, durableClaimCount: 0 } },
  );
}

function canonicalResultRouteId(uri: string): string | undefined {
  if (!uri.startsWith("devspace://mcp/")) return undefined;
  try {
    const parsed = new URL(uri);
    const [routeId, marker] = parsed.pathname.split("/").filter(Boolean);
    return marker === "result" && routeId ? decodeURIComponent(routeId) : undefined;
  } catch {
    return undefined;
  }
}

async function closeSession(session: DownstreamMcpSession): Promise<void> {
  await Promise.allSettled([
    session.client.close(),
    session.transport.close(),
  ]);
}

function scoreTool(
  tool: { name: string; title?: string; description?: string },
  query: string,
): number {
  const normalized = normalize(query);
  const name = normalize(tool.name);
  const title = normalize(tool.title ?? "");
  const description = normalize(tool.description ?? "");
  let score = 0;
  if (name === normalized) score += 200;
  else if (name.includes(normalized)) score += 100;
  if (title.includes(normalized)) score += 80;
  if (description.includes(normalized)) score += 50;
  for (const token of tokens(normalized)) {
    if (name.includes(token)) score += 25;
    if (title.includes(token)) score += 15;
    if (description.includes(token)) score += 5;
  }
  return score;
}

function tokens(value: string): string[] {
  return [...new Set(value.match(/[\p{L}\p{N}]+/gu) ?? [])]
    .filter((token) => token.length > 1);
}

function normalize(value: string): string {
  return value.normalize("NFKC").trim().toLocaleLowerCase("en-US");
}

function requireText(value: string | undefined, message: string): string {
  if (!value?.trim()) throw new UniversalBrokerError("PRECONDITION_FAILED", message);
  return value;
}

function promptArguments(
  input: Record<string, unknown> | undefined,
): Record<string, string> | undefined {
  if (!input) return undefined;
  const result: Record<string, string> = {};
  for (const [key, value] of Object.entries(input)) {
    if (typeof value !== "string") {
      throw new UniversalBrokerError(
        "PRECONDITION_FAILED",
        `Prompt argument ${key} must be a string.`,
      );
    }
    result[key] = value;
  }
  return result;
}

function withLimit(
  policy: Record<string, unknown> | undefined,
  limit: number | undefined,
): Record<string, unknown> | undefined {
  return limit === undefined ? policy : { ...(policy ?? {}), maxItems: limit };
}

function policyInteger(
  policy: Record<string, unknown> | undefined,
  key: string,
  fallback: number,
  minimum: number,
  maximum: number,
): number {
  const value = policy?.[key];
  return boundedInteger(
    typeof value === "number" ? value : value === undefined ? undefined : Number.NaN,
    fallback,
    minimum,
    maximum,
    `responsePolicy.${key}`,
  );
}

function policyBoolean(
  policy: Record<string, unknown> | undefined,
  key: string,
  fallback: boolean,
): boolean {
  const value = policy?.[key];
  if (value === undefined) return fallback;
  if (typeof value !== "boolean") {
    throw new UniversalBrokerError(
      "PRECONDITION_FAILED",
      `responsePolicy.${key} must be boolean.`,
    );
  }
  return value;
}

function policyStringArray(
  policy: Record<string, unknown> | undefined,
  key: string,
): string[] {
  const value = policy?.[key];
  if (value === undefined) return [];
  if (!Array.isArray(value) || value.some((entry) => typeof entry !== "string")) {
    throw new UniversalBrokerError(
      "PRECONDITION_FAILED",
      `responsePolicy.${key} must be an array of strings.`,
    );
  }
  return value as string[];
}

function selectPointers(value: unknown, pointers: string[]): Record<string, unknown> {
  const result: Record<string, unknown> = {};
  for (const pointer of pointers) {
    if (!pointer.startsWith("/")) {
      throw new UniversalBrokerError(
        "PRECONDITION_FAILED",
        `JSON pointer must start with /: ${pointer}`,
      );
    }
    let current = value;
    for (const raw of pointer.slice(1).split("/")) {
      const key = raw.replaceAll("~1", "/").replaceAll("~0", "~");
      if (Array.isArray(current)) {
        const index = Number(key);
        current = Number.isSafeInteger(index) ? current[index] : undefined;
      } else if (current && typeof current === "object") {
        current = (current as Record<string, unknown>)[key];
      } else {
        current = undefined;
      }
    }
    result[pointer] = current;
  }
  return result;
}

function boundArrays(
  value: unknown,
  maximumItems: number,
): { value: unknown; truncated: boolean } {
  let truncated = false;
  const visit = (entry: unknown, depth: number): unknown => {
    if (depth > 8) return entry;
    if (Array.isArray(entry)) {
      if (entry.length > maximumItems) truncated = true;
      return entry.slice(0, maximumItems).map((item) => visit(item, depth + 1));
    }
    if (entry && typeof entry === "object") {
      return Object.fromEntries(
        Object.entries(entry).map(([key, item]) => [key, visit(item, depth + 1)]),
      );
    }
    return entry;
  };
  return { value: visit(value, 0), truncated };
}

function boundedInteger(
  value: number | undefined,
  fallback: number,
  minimum: number,
  maximum: number,
  field: string,
): number {
  const parsed = value ?? fallback;
  if (!Number.isInteger(parsed) || parsed < minimum || parsed > maximum) {
    throw new UniversalBrokerError(
      "PRECONDITION_FAILED",
      `${field} must be an integer from ${minimum} through ${maximum}.`,
    );
  }
  return parsed;
}

function timed<T>(promise: Promise<T>, timeoutMs: number, label: string): Promise<T> {
  let timer: NodeJS.Timeout | undefined;
  return Promise.race([
    promise,
    new Promise<never>((_resolve, reject) => {
      timer = setTimeout(
        () => reject(new Error(`${label} timed out after ${timeoutMs}ms.`)),
        timeoutMs,
      );
      timer.unref();
    }),
  ]).finally(() => {
    if (timer) clearTimeout(timer);
  });
}

function headTail(value: string, maximum: number): string {
  const marker = "\n... truncated ...\n";
  if (value.length <= maximum) return value;
  const available = Math.max(0, maximum - marker.length);
  const head = Math.ceil(available / 2);
  const tail = Math.floor(available / 2);
  return value.slice(0, head) + marker + value.slice(value.length - tail);
}

export function downstreamMcpToolContractSha256(tool: unknown): string {
  return createHash("sha256").update(stableJson(tool)).digest("hex");
}

function downstreamInvocationRisk(
  route: UniversalMcpRoute,
  tool: Record<string, unknown>,
  toolContractSha256: string,
): AuthorityRiskClass {
  const annotations = isRecord(tool.annotations) ? tool.annotations : undefined;
  const destructive = annotations?.destructiveHint === true;
  const readOnly = annotations?.readOnlyHint === true;
  const policy = route.riskPolicy?.tools[String(tool.name)];
  if (destructive || policy?.risk === "R3") return "R3";
  if (
    policy?.risk === "R0"
    && policy.toolContractSha256 === toolContractSha256
    && readOnly
    && !destructive
  ) {
    return "R0";
  }
  return "R2";
}

function requireDownstreamTool<T extends { name: string }>(
  routeId: string,
  name: string,
  tools: T[],
): T & Record<string, unknown> {
  const tool = tools.find((candidate) => candidate.name === name);
  if (!tool) {
    throw new UniversalBrokerError(
      "MCP_TOOL_NOT_FOUND",
      `MCP tool ${name} is not exposed by route ${routeId}.`,
      {
        suggestions: tools
          .map((candidate) => ({ name: candidate.name }))
          .sort((left, right) => left.name.localeCompare(right.name)),
      },
    );
  }
  return tool as T & Record<string, unknown>;
}

function stableJson(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(stableJson).join(",")}]`;
  if (value && typeof value === "object") {
    const record = value as Record<string, unknown>;
    return `{${Object.keys(record).sort().map((key) => `${JSON.stringify(key)}:${stableJson(record[key])}`).join(",")}}`;
  }
  return JSON.stringify(value) ?? "null";
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return Boolean(value) && typeof value === "object" && !Array.isArray(value);
}

function shellQuote(value: string): string {
  return `'${value.replaceAll("'", `'"'"'`)}'`;
}

function boundedJson(value: unknown, maximum: number): string {
  return headTail(JSON.stringify(value) ?? "null", maximum);
}

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

function sessionCacheKey(principalKeyFingerprint: string, routeId: string): string {
  return `${principalKeyFingerprint}\0${routeId}`;
}

function isExactNotConnected(error: unknown): boolean {
  return error instanceof Error && error.message.trim() === "Not connected";
}
