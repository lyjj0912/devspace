import { randomUUID } from "node:crypto";
import {
  McpServer,
  ResourceTemplate,
} from "@modelcontextprotocol/sdk/server/mcp.js";
import type { CallToolResult } from "@modelcontextprotocol/sdk/types.js";
import { registerAppTool } from "@modelcontextprotocol/ext-apps/server";
import type {
  UniversalArtifactInput,
  UniversalArtifactService,
} from "./artifact-service.js";
import {
  OperationAuthorityRegistry,
  type AuthorityActionDescriptor,
  type CreateOperationAuthorityInput,
  type OperationAuthorityDispatchController,
  type RequestedAuthorityAction,
} from "./authority.js";
import {
  resolveAuthorityPrincipal,
  type AuthorityAuthenticationInfo,
  type AuthorityPrincipalConfiguration,
  type AuthorityRequestIdentity,
} from "./authority-principal.js";
import {
  createCapabilityCallContextFromTrustedPrincipal,
  type CapabilityCallContext,
} from "./capability-call-context.js";
import {
  artifactAction,
  artifactRisk,
  authorityActionFromToolCall,
  commandRisk,
  contextAction,
  execAction,
  filesystemAction,
  filesystemRisk,
  guiAction,
  mcpAction,
  mcpRisk,
  minimumAuthorityRisk,
  processAction,
  processRisk,
} from "./authority-policy.js";
import type { ContextRegistry } from "./contexts.js";
import type { UniversalSelfManagementService } from "./self-management.js";
import {
  type PreparedExecExecutionBinding,
  type ExecuteCommandInput,
  type ProcessOperationInput,
  type UniversalExecutionPlane,
} from "./execution.js";
import type {
  UniversalFilesystemInput,
  UniversalFilesystemService,
} from "./filesystem.js";
import type {
  McpInvocationAuthorityBinding,
  PreparedMcpInvocation,
  UniversalMcpInput,
  UniversalMcpProxy,
} from "./mcp-proxy.js";
import type {
  UniversalGuiInput,
  UniversalGuiService,
} from "./gui.js";
import {
  UNIVERSAL_BROKER_INSTRUCTIONS,
  UNIVERSAL_BROKER_VERSION,
  UNIVERSAL_TOOL_CONTRACTS,
  UNIVERSAL_TOOL_NAMES,
  universalRequestMetaSchema,
  type AuthorityRiskClass,
  type RuntimeIdentity,
  type UniversalRequestMeta,
  type UniversalToolContract,
  type UniversalToolName,
} from "./contracts.js";
import {
  executeUniversalTool,
  failedToolResult,
  successfulToolResult,
  UniversalBrokerError,
} from "./errors.js";
import {
  assertTargetCapability,
  type TargetRegistry,
  targetSummary,
} from "./targets.js";
import type { UniversalBrokerMetrics } from "./metrics.js";
import type { OperationAuditSink } from "./operation-audit.js";

export interface UniversalBrokerServices {
  targets?: TargetRegistry;
  contexts?: ContextRegistry;
  execution?: UniversalExecutionPlane;
  filesystem?: UniversalFilesystemService;
  mcpProxy?: UniversalMcpProxy;
  artifacts?: UniversalArtifactService;
  gui?: UniversalGuiService;
  authority?: OperationAuthorityRegistry;
  authorityPrincipal?: AuthorityPrincipalConfiguration;
  selfManagement?: UniversalSelfManagementService;
  runtimeIdentity?: RuntimeIdentity;
  metrics?: UniversalBrokerMetrics;
  operationAudit?: OperationAuditSink;
}

interface UniversalBrokerRequestBoundary {
  runtimeIdentity?: RuntimeIdentity;
  metrics?: UniversalBrokerMetrics;
  operationAudit?: OperationAuditSink;
  authority?: OperationAuthorityRegistry;
  authorityPrincipal?: AuthorityPrincipalResolver;
}

export function createUniversalBrokerMcpServer(
  services: UniversalBrokerServices = {},
): McpServer {
  const server = new McpServer(
    {
      name: "devspace-universal-broker",
      title: "DevSpace Universal Broker",
      version: UNIVERSAL_BROKER_VERSION,
      description:
        "Generic broker for local and remote targets, files, commands, MCP routes, artifacts, and optional GUI sessions.",
    },
    { instructions: UNIVERSAL_BROKER_INSTRUCTIONS },
  );
  const authority = services.authority ?? new OperationAuthorityRegistry({
    minimumRisk: minimumAuthorityRisk,
    metrics: services.metrics,
  });
  const principalConfiguration = services.authorityPrincipal ?? {
    environment: "production",
    mode: "single-owner",
  };
  const authorityPrincipal: AuthorityPrincipalResolver = (extra) => (
    resolveAuthorityPrincipal(extra, principalConfiguration).fingerprint
  );
  const requestBoundary: UniversalBrokerRequestBoundary = {
    runtimeIdentity: services.runtimeIdentity,
    metrics: services.metrics,
    operationAudit: services.operationAudit,
    authority,
    authorityPrincipal,
  };

  if (services.mcpProxy && services.metrics) {
    services.mcpProxy.setOperationalObserver?.({
      reconnect: ({ transport, result }) => services.metrics!.recordMcpReconnect(transport, result),
      connection: ({ transport, state }) => services.metrics!.recordMcpConnection(transport, state),
    });
  }

  if (services.execution) {
    registerProcessOutputResource(server, services.execution, authorityPrincipal);
  }
  if (services.mcpProxy) {
    registerMcpResourceProxy(server, services.mcpProxy, authorityPrincipal);
    registerMcpResultResource(server, services.mcpProxy, authorityPrincipal);
  }
  if (services.contexts) registerContextDiffResource(server, services.contexts, authorityPrincipal);
  if (services.artifacts) registerArtifactResource(server, services.artifacts, authorityPrincipal);

  for (const name of UNIVERSAL_TOOL_NAMES) {
    if (name === "target" && services.targets) {
      registerTargetTool(server, services.targets, authorityPrincipal, requestBoundary);
    } else if (name === "context" && services.contexts && services.targets) {
      registerContextTool(
        server,
        services.contexts,
        services.targets,
        services.execution,
        services.filesystem,
        services.mcpProxy,
        services.gui,
        authority,
        authorityPrincipal,
        requestBoundary,
      );
    } else if (name === "exec" && services.execution && services.targets && services.contexts) {
      registerExecTool(
        server,
        services.execution,
        services.targets,
        services.contexts,
        authority,
        authorityPrincipal,
        requestBoundary,
      );
    } else if (name === "process" && services.execution) {
      registerProcessTool(
        server,
        services.execution,
        authority,
        authorityPrincipal,
        services.selfManagement,
        requestBoundary,
      );
    } else if (name === "fs" && services.filesystem && services.targets && services.contexts) {
      registerFilesystemTool(
        server,
        services.filesystem,
        services.targets,
        services.contexts,
        authority,
        authorityPrincipal,
        requestBoundary,
      );
    } else if (name === "mcp" && services.mcpProxy) {
      registerMcpTool(
        server,
        services.mcpProxy,
        authority,
        authorityPrincipal,
        requestBoundary,
      );
    } else if (
      name === "artifact"
      && services.artifacts
      && services.targets
      && services.contexts
    ) {
      registerArtifactTool(
        server,
        services.artifacts,
        services.targets,
        services.contexts,
        authority,
        authorityPrincipal,
        requestBoundary,
      );
    } else if (name === "gui" && services.gui && services.targets) {
      registerGuiTool(server, services.gui, authority, authorityPrincipal, requestBoundary);
    } else {
      registerUnavailableTool(
        server,
        name,
        UNIVERSAL_TOOL_CONTRACTS[name] as UniversalToolContract,
        requestBoundary,
      );
    }
  }

  return server;
}

function registerGuiTool(
  server: McpServer,
  gui: UniversalGuiService,
  authority: OperationAuthorityRegistry,
  authorityPrincipal: AuthorityPrincipalResolver,
  requestBoundary: UniversalBrokerRequestBoundary,
): void {
  const contract = UNIVERSAL_TOOL_CONTRACTS.gui;
  registerAppTool(
    server,
    "gui",
    {
      title: contract.title,
      description: contract.description,
      inputSchema: contract.inputSchema,
      annotations: contract.annotations,
      _meta: {},
    },
    async (input, extra) => executeMeasuredUniversalTool(
      requestBoundary,
      "gui",
      input.operation,
      extra,
      async (requestMeta, observation) => {
      const authenticated = requireAuthenticatedPrincipal(extra, authorityPrincipal);
      requireScope(authenticated.authInfo, "devspace.gui");
      const typed = mergeOperationRequestMeta(input, requestMeta) as UniversalGuiInput;
      assertGenerationApplicability(requestMeta, "gui", typed.operation, {
        target: true,
        route: false,
      });
      const targetBinding = await gui.authorityTarget(typed, authenticated.callContext);
      assertTargetGeneration(requestMeta, targetBinding.generation, observation);
      const action = bindTargetAuthority(
        guiAction(typed, targetBinding.target.id),
        targetBinding,
      );
      const risk: AuthorityRiskClass = typed.operation === "act" ? "R3" : "R0";
      const data = await withOperationAuthority(
        authority,
        typed.authorityId,
        () => authenticated.principalKeyFingerprint,
        action,
        risk,
        () => gui.execute(typed, authenticated.callContext),
        { auditObservation: observation, authInfo: authenticated.authInfo },
      );
      return successfulToolResult(data, undefined, guiSummaryText(typed.operation, data));
      },
    ),
  );
}

function registerArtifactTool(
  server: McpServer,
  artifacts: UniversalArtifactService,
  targets: TargetRegistry,
  contexts: ContextRegistry,
  authority: OperationAuthorityRegistry,
  authorityPrincipal: AuthorityPrincipalResolver,
  requestBoundary: UniversalBrokerRequestBoundary,
): void {
  const contract = UNIVERSAL_TOOL_CONTRACTS.artifact;
  registerAppTool(
    server,
    "artifact",
    {
      title: contract.title,
      description: contract.description,
      inputSchema: contract.inputSchema,
      annotations: contract.annotations,
      _meta: {},
    },
    async (input, extra) => executeMeasuredUniversalTool(
      requestBoundary,
      "artifact",
      input.operation,
      extra,
      async (requestMeta, observation) => {
      const authenticated = requireAuthenticatedPrincipal(extra, authorityPrincipal);
      requireScope(authenticated.authInfo, "devspace.artifact");
      requireScope(
        authenticated.authInfo,
        input.operation === "publish" ? "devspace.read" : "devspace.write",
      );
      const typed = mergeOperationRequestMeta(input, requestMeta) as UniversalArtifactInput;
      assertGenerationApplicability(requestMeta, "artifact", typed.operation, {
        target: true,
        route: false,
      });
      const normalized = await normalizeArtifactAuthority(
        typed,
        targets,
        contexts,
        authenticated.callContext,
      );
      for (const binding of normalized.bindings) {
        assertTargetCapability(binding.target, "artifact");
      }
      const targetGenerations = [...new Set(
        normalized.bindings.map((binding) => binding.generation),
      )];
      if (requestMeta.expectedTargetGeneration !== undefined && targetGenerations.length !== 1) {
        assertGenerationApplicability(requestMeta, "artifact", typed.operation, {
          target: false,
          route: false,
        });
      }
      if (targetGenerations.length === 1) {
        assertTargetGeneration(requestMeta, targetGenerations[0]!, observation);
      }
      const data = await withOperationAuthority(
        authority,
        typed.authorityId,
        () => authenticated.principalKeyFingerprint,
        normalized.action,
        normalized.risk,
        () => artifacts.execute(typed, authenticated.callContext),
        { auditObservation: observation, authInfo: authenticated.authInfo },
      );
      const result = successfulToolResult(
        data,
        undefined,
        artifactSummaryText(typed.operation, data),
      );
      if (
        typed.operation === "publish"
        && typeof data.resourceUri === "string"
        && typeof data.resourceName === "string"
      ) {
        result.content.push({
          type: "resource_link",
          uri: data.resourceUri,
          name: data.resourceName,
          title: data.resourceName,
          ...(typeof data.mimeType === "string" ? { mimeType: data.mimeType } : {}),
          ...(typeof data.size === "number" ? { size: data.size } : {}),
        });
      }
      return result;
      },
    ),
  );
}

function registerMcpTool(
  server: McpServer,
  proxy: UniversalMcpProxy,
  authority: OperationAuthorityRegistry,
  authorityPrincipal: AuthorityPrincipalResolver,
  requestBoundary: UniversalBrokerRequestBoundary,
): void {
  const contract = UNIVERSAL_TOOL_CONTRACTS.mcp;
  registerAppTool(
    server,
    "mcp",
    {
      title: contract.title,
      description: contract.description,
      inputSchema: contract.inputSchema,
      annotations: contract.annotations,
      _meta: {},
    },
    async (input, extra) => executeMeasuredUniversalTool(
      requestBoundary,
      "mcp",
      input.operation,
      extra,
      async (requestMeta, observation) => {
      const authenticated = requireAuthenticatedPrincipal(extra, authorityPrincipal);
      requireScope(authenticated.authInfo, "devspace.mcp");
      const typed = mergeOperationRequestMeta(input, requestMeta) as UniversalMcpInput;
      const routeSelector = typed.route ?? mcpResultRouteSelector(typed.uri);
      const routeApplicable = typed.operation !== "routes"
        && !(typed.operation === "close" && routeSelector === undefined);
      assertGenerationApplicability(requestMeta, "mcp", typed.operation, {
        target: false,
        route: routeApplicable,
      });
      let routeBinding: RouteAuthorityBinding | undefined;
      let preparedInvocation: PreparedMcpInvocation | undefined;
      if (routeApplicable) {
        routeBinding = await proxy.inspectRoute(routeSelector);
        assertRouteGeneration(requestMeta, routeBinding.routeGeneration, observation);
      }
      if (typed.operation === "invoke") {
        preparedInvocation = await proxy.prepareInvocation(
          typed,
          authenticated.callContext,
          requestMeta,
        );
        assertRouteGeneration(
          requestMeta,
          preparedInvocation.binding.routeGeneration,
          observation,
        );
      }
      const invocationBinding = preparedInvocation?.binding;
      const action = invocationBinding
        ? mcpAction(typed, invocationBinding)
        : bindRouteAuthority(mcpAction(typed, routeBinding?.routeId), routeBinding);
      const risk = invocationBinding?.risk ?? minimumAuthorityRisk(action);
      let data: Record<string, unknown>;
      try {
        data = await withOperationAuthority(
          authority,
          typed.authorityId,
          () => authenticated.principalKeyFingerprint,
          action,
          risk,
          (dispatch) => preparedInvocation
            ? preparedInvocation.execute(dispatch)
            : proxy.execute(typed, authenticated.callContext, requestMeta),
          {
            adapterBoundary: Boolean(preparedInvocation),
            auditObservation: observation,
            authInfo: authenticated.authInfo,
          },
        );
      } finally {
        preparedInvocation?.release();
      }
      return successfulToolResult(
        data,
        undefined,
        mcpSummaryText(typed.operation, data),
      );
      },
    ),
  );
}

function registerFilesystemTool(
  server: McpServer,
  filesystem: UniversalFilesystemService,
  targets: TargetRegistry,
  contexts: ContextRegistry,
  authority: OperationAuthorityRegistry,
  authorityPrincipal: AuthorityPrincipalResolver,
  requestBoundary: UniversalBrokerRequestBoundary,
): void {
  const contract = UNIVERSAL_TOOL_CONTRACTS.fs;
  registerAppTool(
    server,
    "fs",
    {
      title: contract.title,
      description: contract.description,
      inputSchema: contract.inputSchema,
      annotations: contract.annotations,
      _meta: {},
    },
    async (input, extra) => executeMeasuredUniversalTool(
      requestBoundary,
      "fs",
      input.operation,
      extra,
      async (requestMeta, observation) => {
      const authenticated = requireAuthenticatedPrincipal(extra, authorityPrincipal);
      requireScope(
        authenticated.authInfo,
        isFilesystemMutation(input.operation, input.sync?.phase) ? "devspace.write" : "devspace.read",
      );
      const typed = mergeOperationRequestMeta(input, requestMeta) as UniversalFilesystemInput;
      assertGenerationApplicability(requestMeta, "fs", typed.operation, {
        target: true,
        route: false,
      });
      const targetBinding = await resolveSelectedTargetBinding(
        targets,
        contexts,
        typed.target,
        typed.contextId,
        authenticated.callContext,
      );
      assertTargetGeneration(requestMeta, targetBinding.generation, observation);
      const syncBinding = typed.operation === "sync" && typed.sync?.phase === "apply"
        ? await filesystem.prepareSyncAuthorityBinding(typed, authenticated.callContext)
        : undefined;
      if (
        syncBinding
        && (
          syncBinding.targetId !== targetBinding.target.id
          || syncBinding.targetGeneration !== targetBinding.generation
        )
      ) {
        throw new UniversalBrokerError(
          "SYNC_PLAN_STALE",
          "The immutable filesystem sync plan no longer matches the selected target generation.",
          { evidence: { planId: syncBinding.planId, targetId: syncBinding.targetId } },
        );
      }
      const action = bindTargetAuthority(
        filesystemAction(typed, targetBinding.target.id, syncBinding ? {
          syncPlanDigest: syncBinding.planDigest,
          syncDeleteMode: syncBinding.deleteMode,
        } : undefined),
        targetBinding,
      );
      const risk = filesystemRisk(
        typed.operation,
        targetBinding.target.id,
        action.parameters,
      );
      const data = await withOperationAuthority(
        authority,
        typed.authorityId,
        () => authenticated.principalKeyFingerprint,
        action,
        risk,
        () => filesystem.execute(typed, authenticated.callContext),
        { auditObservation: observation, authInfo: authenticated.authInfo },
      );
      return successfulToolResult(
        data,
        undefined,
        filesystemSummaryText(typed.operation, data),
      );
      },
    ),
  );
}

function registerExecTool(
  server: McpServer,
  execution: UniversalExecutionPlane,
  targets: TargetRegistry,
  contexts: ContextRegistry,
  authority: OperationAuthorityRegistry,
  authorityPrincipal: AuthorityPrincipalResolver,
  requestBoundary: UniversalBrokerRequestBoundary,
): void {
  const contract = UNIVERSAL_TOOL_CONTRACTS.exec;
  registerAppTool(
    server,
    "exec",
    {
      title: contract.title,
      description: contract.description,
      inputSchema: contract.inputSchema,
      annotations: contract.annotations,
      _meta: {},
    },
    async (input, extra) => executeMeasuredUniversalTool(
      requestBoundary,
      "exec",
      "run",
      extra,
      async (requestMeta, observation) => {
      const authenticated = requireAuthenticatedPrincipal(extra, authorityPrincipal);
      requireScope(authenticated.authInfo, "devspace.exec");
      const typed = mergeOperationRequestMeta(input, requestMeta) as ExecuteCommandInput;
      assertGenerationApplicability(requestMeta, "exec", "run", {
        target: true,
        route: false,
      });
      const targetBinding = await resolveSelectedTargetBinding(
        targets,
        contexts,
        typed.target,
        typed.contextId,
        authenticated.callContext,
      );
      assertTargetGeneration(requestMeta, targetBinding.generation, observation);
      const executionBinding = await execution.prepareAuthorityBinding(
        typed,
        targetBinding.target,
        targetBinding.generation,
        authenticated.callContext,
      );
      const action = execAction(typed, targetBinding.target.id, executionBinding.effectiveCwd, {
        targetGeneration: targetBinding.generation,
        targetTransport: targetBinding.target.transport,
        targetPlatform: targetBinding.target.platform,
        shellDialect: targetBinding.target.shell,
        effectiveEnvProfile: typed.envProfile ?? targetBinding.target.envProfile,
        effectiveEnvProfileGeneration: executionBinding.effectiveEnvProfileGeneration,
      });
      const risk = minimumAuthorityRisk(action);
      assertExecBindingRisk(risk, executionBinding);
      const data = await withOperationAuthority(
        authority,
        typed.authorityId,
        () => authenticated.principalKeyFingerprint,
        action,
        risk,
        (dispatch) => execution.execute(
          typed,
          executionBinding,
          dispatch,
          authenticated.callContext,
        ),
        {
          adapterBoundary: true,
          auditObservation: observation,
          authInfo: authenticated.authInfo,
        },
      );
      return successfulToolResult(
        data,
        undefined,
        processSummaryText(data),
      );
      },
    ),
  );
}

function assertExecBindingRisk(
  actionRisk: AuthorityRiskClass,
  executionBinding: PreparedExecExecutionBinding,
): void {
  if (actionRisk === executionBinding.launchRisk) return;
  throw new UniversalBrokerError(
    "PRECONDITION_FAILED",
    "Exec action and execution-plane classifier bindings disagree; process dispatch was not attempted.",
    {
      evidence: {
        actionRisk,
        executionRisk: executionBinding.launchRisk,
        classifierGeneration: executionBinding.classifierGeneration,
      },
    },
  );
}

function registerProcessTool(
  server: McpServer,
  execution: UniversalExecutionPlane,
  authority: OperationAuthorityRegistry,
  authorityPrincipal: AuthorityPrincipalResolver,
  selfManagement?: UniversalSelfManagementService,
  requestBoundary: UniversalBrokerRequestBoundary = {},
): void {
  const contract = UNIVERSAL_TOOL_CONTRACTS.process;
  registerAppTool(
    server,
    "process",
    {
      title: contract.title,
      description: contract.description,
      inputSchema: contract.inputSchema,
      annotations: contract.annotations,
      _meta: {},
    },
    async (input, extra) => executeMeasuredUniversalTool(
      requestBoundary,
      "process",
      input.operation,
      extra,
      async (requestMeta, observation) => {
      const authenticated = requireAuthenticatedPrincipal(extra, authorityPrincipal);
      requireScope(authenticated.authInfo, "devspace.exec");
      const typed = mergeOperationRequestMeta(input, requestMeta) as ProcessOperationInput;
      const targetApplicable = processOperationTargetsRecord(typed.operation);
      assertGenerationApplicability(requestMeta, "process", typed.operation, {
        target: targetApplicable,
        route: false,
      });
      const observedProcessBinding = targetApplicable
        ? execution.authorityBinding(
            typed.processId,
            typed.operation,
            authenticated.callContext,
          )
        : undefined;
      if (observedProcessBinding?.targetGeneration) {
        assertTargetGeneration(
          requestMeta,
          observedProcessBinding.targetGeneration,
          observation,
        );
      }
      const processBinding = processOperationNeedsBinding(typed.operation)
        ? observedProcessBinding
        : undefined;
      const action = processAction(typed, processBinding);
      const data = await withOperationAuthority(
        authority,
        typed.authorityId,
        () => authenticated.principalKeyFingerprint,
        action,
        processRisk(typed.operation, action.parameters),
        async (dispatch) => {
          if (typed.operation === "restart_broker") {
            if (!selfManagement) return unavailableSelfManagement("restart_broker");
            if (extra.requestId === undefined) {
              throw new UniversalBrokerError(
                "RESTART_ACK_NOT_FLUSHED",
                "Broker restart requires an exact response request identifier.",
              );
            }
            const prepared = await selfManagement.requestRestart({
              reason: typed.reason,
              ownerFingerprint: authenticated.principalKeyFingerprint,
              authorityId: typed.authorityId!,
            });
            return selfManagement.bindResponse(prepared.transactionId, extra.requestId);
          }
          if (typed.operation === "restart_status") {
            if (!selfManagement) return unavailableSelfManagement("restart_status");
            if (!typed.transactionId) {
              throw new UniversalBrokerError(
                "PRECONDITION_FAILED",
                "process.restart_status requires transactionId.",
              );
            }
            return selfManagement.status(typed.transactionId);
          }
          return execution.operate(typed, dispatch, authenticated.callContext);
        },
        {
          adapterBoundary: processOperationNeedsBinding(typed.operation),
          auditObservation: observation,
          authInfo: authenticated.authInfo,
        },
      );
      const text = typed.operation === "list"
        ? `Managed processes: ${Array.isArray(data.processes) ? data.processes.length : 0}`
        : typed.operation === "restart_broker"
          ? `Broker restart transaction requested: ${String(data.transactionId)}`
          : typed.operation === "restart_status"
            ? `Broker restart ${String(data.transactionId)}: ${String(data.state)}`
            : processSummaryText(data);
      return successfulToolResult(data, undefined, text);
      },
    ),
  );
}

function unavailableSelfManagement(operation: string): never {
  throw new UniversalBrokerError(
    "CAPABILITY_UNAVAILABLE",
    `Broker self-management is unavailable for process.${operation}.`,
  );
}

function processOperationNeedsBinding(operation: ProcessOperationInput["operation"]): boolean {
  return ["write", "resize", "signal", "forget"].includes(operation);
}

function processOperationTargetsRecord(operation: ProcessOperationInput["operation"]): boolean {
  return ["poll", "write", "resize", "signal", "wait", "forget"].includes(operation);
}

function registerProcessOutputResource(
  server: McpServer,
  execution: UniversalExecutionPlane,
  authorityPrincipal: AuthorityPrincipalResolver,
): void {
  server.registerResource(
    "Universal Broker process output",
    new ResourceTemplate(
      "devspace://v1/process/{processId}/output",
      { list: undefined },
    ),
    {
      title: "Managed process output",
      description: "Bounded UTF-8 chunk from the full output retained for a managed process.",
      mimeType: "text/plain",
    },
    async (uri, _variables, extra) => {
      const authenticated = requireAuthenticatedPrincipal(extra, authorityPrincipal);
      requireScope(authenticated.authInfo, "devspace.exec");
      const page = await execution.readOutputResource(uri.href, authenticated.callContext);
      return {
        contents: [{
          uri: String(page.uri ?? uri.href),
          mimeType: "text/plain",
          text: String(page.text ?? ""),
          _meta: Object.fromEntries(
            Object.entries(page).filter(([key]) => !["uri", "mimeType", "text"].includes(key)),
          ),
        }],
      };
    },
  );
}

function registerMcpResultResource(
  server: McpServer,
  proxy: UniversalMcpProxy,
  authorityPrincipal: AuthorityPrincipalResolver,
): void {
  server.registerResource(
    "Universal Broker MCP result",
    new ResourceTemplate(
      "devspace://v1/mcp-result/{resultId}",
      { list: undefined },
    ),
    {
      title: "Paged downstream MCP result",
      description: "Bounded JSON chunk from a downstream MCP result retained in the v2 result store.",
      mimeType: "application/json",
    },
    async (uri, _variables, extra) => {
      const authenticated = requireAuthenticatedPrincipal(extra, authorityPrincipal);
      requireScope(authenticated.authInfo, "devspace.mcp");
      const page = proxy.readStoredResult(uri.href, authenticated.callContext);
      return {
        contents: [{
          uri: uri.href,
          mimeType: "application/json",
          text: String(page.text ?? ""),
          _meta: Object.fromEntries(
            Object.entries(page).filter(([key]) => !["uri", "mimeType", "text"].includes(key)),
          ),
        }],
      };
    },
  );
}

function registerMcpResourceProxy(
  server: McpServer,
  proxy: UniversalMcpProxy,
  authorityPrincipal: AuthorityPrincipalResolver,
): void {
  server.registerResource(
    "Universal Broker downstream MCP resource",
    new ResourceTemplate(
      "devspace://v1/mcp/{routeId}/resource/{opaque}",
      { list: undefined },
    ),
    {
      title: "Owner-bound downstream MCP resource",
      description: "Broker-proxied downstream MCP content bound to its owner, route generation, and expiry.",
    },
    async (uri, _variables, extra) => {
      const authenticated = requireAuthenticatedPrincipal(extra, authorityPrincipal);
      requireScope(authenticated.authInfo, "devspace.mcp");
      const response = await proxy.execute(
        { operation: "read_resource", uri: uri.href },
        authenticated.callContext,
      );
      const projected = recordValue(response.result);
      const value = recordValue(projected?.value);
      if (!value || !Array.isArray(value.contents)) {
        throw new UniversalBrokerError(
          "STATE_CORRUPTED",
          "Downstream MCP resource proxy returned an invalid content envelope.",
        );
      }
      return {
        contents: value.contents.map(resourceContentFromProxy),
      };
    },
  );
}

function resourceContentFromProxy(value: unknown): {
  uri: string;
  mimeType?: string;
  text: string;
  _meta?: Record<string, unknown>;
} | {
  uri: string;
  mimeType?: string;
  blob: string;
  _meta?: Record<string, unknown>;
} {
  const record = recordValue(value);
  if (!record || typeof record.uri !== "string") {
    throw new UniversalBrokerError(
      "STATE_CORRUPTED",
      "Downstream MCP resource content is invalid.",
    );
  }
  const metadata = Object.fromEntries(
    Object.entries(record).filter(([key]) => !["uri", "mimeType", "text", "blob"].includes(key)),
  );
  if (typeof record.text === "string") {
    return {
      uri: record.uri,
      ...(typeof record.mimeType === "string" ? { mimeType: record.mimeType } : {}),
      text: record.text,
      ...(Object.keys(metadata).length > 0 ? { _meta: metadata } : {}),
    };
  }
  if (typeof record.blob === "string") {
    return {
      uri: record.uri,
      ...(typeof record.mimeType === "string" ? { mimeType: record.mimeType } : {}),
      blob: record.blob,
      ...(Object.keys(metadata).length > 0 ? { _meta: metadata } : {}),
    };
  }
  throw new UniversalBrokerError(
    "STATE_CORRUPTED",
    "Downstream MCP resource content has neither text nor blob data.",
  );
}

function registerArtifactResource(
  server: McpServer,
  artifacts: UniversalArtifactService,
  authorityPrincipal: AuthorityPrincipalResolver,
): void {
  server.registerResource(
    "Universal Broker artifact",
    new ResourceTemplate("devspace://v1/artifact/{artifactId}", { list: undefined }),
    {
      title: "Immutable artifact content",
      description: "Owner-bound bytes from an immutable Universal Broker CAS artifact.",
      mimeType: "application/octet-stream",
    },
    async (uri, _variables, extra) => {
      const authenticated = requireAuthenticatedPrincipal(extra, authorityPrincipal);
      requireScope(authenticated.authInfo, "devspace.artifact");
      requireScope(authenticated.authInfo, "devspace.read");
      const page = await artifacts.readResource(uri.href, authenticated.callContext);
      return {
        contents: [{
          uri: uri.href,
          mimeType: String(page.mimeType ?? "application/octet-stream"),
          blob: String(page.blobBase64 ?? ""),
          _meta: Object.fromEntries(
            Object.entries(page).filter(([key]) => ![
              "uri",
              "mimeType",
              "blobBase64",
            ].includes(key)),
          ),
        }],
      };
    },
  );
}

function registerTargetTool(
  server: McpServer,
  targets: TargetRegistry,
  authorityPrincipal: AuthorityPrincipalResolver,
  requestBoundary: UniversalBrokerRequestBoundary,
): void {
  const contract = UNIVERSAL_TOOL_CONTRACTS.target;
  registerAppTool(
    server,
    "target",
    {
      title: contract.title,
      description: contract.description,
      inputSchema: contract.inputSchema,
      annotations: contract.annotations,
      _meta: {},
    },
    async (input, extra) => executeMeasuredUniversalTool(
      requestBoundary,
      "target",
      input.operation,
      extra,
      async (requestMeta, observation) => {
      const authenticated = requireAuthenticatedPrincipal(extra, authorityPrincipal);
      requireScope(authenticated.authInfo, "devspace.read");
      const { operation, selector, targetId, refresh, cursor, limit } =
        mergeOperationRequestMeta(input, requestMeta);
      assertGenerationApplicability(requestMeta, "target", operation, {
        target: operation !== "list",
        route: false,
      });
      switch (operation) {
        case "list": {
          const data = await targets.list({ cursor, limit }, authenticated.callContext);
          return successfulToolResult(data, undefined, targetListText(data.targets));
        }
        case "resolve": {
          const { generation, target: resolved } = await targets.resolveWithGeneration(
            selector ?? targetId,
          );
          assertTargetGeneration(requestMeta, generation, observation);
          const data = {
            generation,
            target: targetSummary(resolved),
          };
          return successfulToolResult(data, undefined, `Resolved target: ${resolved.id}`);
        }
        case "probe": {
          const binding = await targets.resolveWithGeneration(targetId ?? selector);
          assertTargetGeneration(requestMeta, binding.generation, observation);
          const targetObservation = await targets.probe(binding.target.id, { refresh });
          return successfulToolResult(
            { observation: targetObservation },
            undefined,
            `${targetObservation.targetId}: ${targetObservation.status}`,
          );
        }
      }
      },
    ),
  );
}

function registerContextTool(
  server: McpServer,
  contexts: ContextRegistry,
  targets: TargetRegistry,
  execution: UniversalExecutionPlane | undefined,
  filesystem: UniversalFilesystemService | undefined,
  mcpProxy: UniversalMcpProxy | undefined,
  gui: UniversalGuiService | undefined,
  authority: OperationAuthorityRegistry,
  authorityPrincipal: AuthorityPrincipalResolver,
  requestBoundary: UniversalBrokerRequestBoundary,
): void {
  const contract = UNIVERSAL_TOOL_CONTRACTS.context;
  registerAppTool(
    server,
    "context",
    {
      title: contract.title,
      description: contract.description,
      inputSchema: contract.inputSchema,
      annotations: contract.annotations,
      _meta: {},
    },
    async (input, extra) => executeMeasuredUniversalTool(
      requestBoundary,
      "context",
      input.operation,
      extra,
      async (requestMeta, observation) => {
      const authenticated = requireAuthenticatedPrincipal(extra, authorityPrincipal);
      requireScope(authenticated.authInfo, "devspace.read");
      const {
        operation,
        contextId,
        target,
        path,
        mode,
        baseRef,
        task,
        query,
        cursor,
        limit,
        maxCharacters,
        authorityId,
        taskInstanceId,
        taskLabel,
        taskId,
        authorityText,
        actions,
        correctionText,
        expiresInSeconds,
      } = mergeOperationRequestMeta(input, requestMeta);
      const targetApplicable = ["open", "search", "diff", "close"].includes(operation);
      assertGenerationApplicability(requestMeta, "context", operation, {
        target: targetApplicable,
        route: false,
      });
      let openTargetBinding: ResolvedTargetAuthorityBinding | undefined;
      if (operation === "open") {
        openTargetBinding = await targets.resolveWithGeneration(target);
        assertTargetGeneration(requestMeta, openTargetBinding.generation, observation);
      } else if (operation === "search" && !contextId) {
        const localBinding = await targets.resolveWithGeneration("local");
        assertTargetGeneration(requestMeta, localBinding.generation, observation);
      } else if (targetApplicable && contextId) {
        const context = await contexts.get(contextId, authenticated.callContext);
        assertTargetGeneration(requestMeta, context.targetGeneration, observation);
      }
      const principal = () => authenticated.principalKeyFingerprint;
      if (operation === "close" || (operation === "open" && mode === "worktree")) {
        requireScope(authenticated.authInfo, "devspace.write");
      }
      switch (operation) {
        case "authority_preview": {
          requireAuthorityPlanningInputScopes(authenticated.authInfo, actions);
          const normalizedActions = await normalizeRequestedAuthorityActions(
            actions,
            targets,
            contexts,
            execution,
            filesystem,
            mcpProxy,
            gui,
            authenticated.callContext,
          );
          requireAuthorityPlanningScopes(authenticated.authInfo, normalizedActions);
          const data = authority.preview(normalizedActions);
          return successfulToolResult(
            data,
            undefined,
            `Authority preview: ${String(data.authorityActionCount)} of ${String(data.actionCount)} action(s) require authority.`,
          );
        }
        case "authorize": {
          requireActivatedConnectorForRisk(authenticated.authInfo, "R1");
          requireAuthorityPlanningInputScopes(authenticated.authInfo, actions);
          const normalizedActions = await normalizeRequestedAuthorityActions(
            actions,
            targets,
            contexts,
            execution,
            filesystem,
            mcpProxy,
            gui,
            authenticated.callContext,
          );
          requireAuthorityPlanningScopes(authenticated.authInfo, normalizedActions);
          const data = authority.create({
            taskInstanceId,
            taskLabel: taskLabel ?? taskId,
            authorityText: authorityText ?? "",
            actions: normalizedActions,
            expiresInSeconds,
          } satisfies CreateOperationAuthorityInput, principal());
          return successfulToolResult(
            data,
            undefined,
            `Prepared exact task authority ${String(data.authorityId)} for ${normalizedActions.length} action(s).`,
          );
        }
        case "authority_status": {
          if (!authorityId) {
            throw new UniversalBrokerError(
              "PRECONDITION_FAILED",
              "context.authority_status requires authorityId.",
            );
          }
          const data = authority.status(authorityId, principal());
          return successfulToolResult(data, undefined, `Task authority status: ${authorityId}`);
        }
        case "invalidate_authority": {
          requireActivatedConnectorForRisk(authenticated.authInfo, "R1");
          const data = authority.invalidate(
            principal(),
            taskInstanceId ?? "",
            correctionText ?? "",
          );
          return successfulToolResult(
            data,
            undefined,
            `Invalidated ${String((data.invalidatedAuthorityIds as unknown[]).length)} task authority record(s).`,
          );
        }
        case "release_authority": {
          requireActivatedConnectorForRisk(authenticated.authInfo, "R1");
          if (!authorityId) {
            throw new UniversalBrokerError(
              "PRECONDITION_FAILED",
              "context.release_authority requires authorityId.",
            );
          }
          const data = authority.release(authorityId, principal());
          return successfulToolResult(data, undefined, `Released task authority ${authorityId}.`);
        }
        case "open": {
          const rawAction = contextAction(operation, { target, path, contextId, mode, baseRef });
          const action = bindTargetAuthority(rawAction, openTargetBinding);
          const data = await withOperationAuthority(
            authority,
            authorityId,
            principal,
            action,
            minimumAuthorityRisk(action),
            () => contexts.open(
              { target, path, mode, baseRef, task },
              authenticated.callContext,
            ),
            { auditObservation: observation, authInfo: authenticated.authInfo },
          );
          return successfulToolResult(
            data,
            undefined,
            data.reused
              ? `Reused context ${data.contextId} (${data.targetId}@${
                data.targetGeneration.slice(0, 12)
              })`
              : `Opened context ${data.contextId} at ${data.root}`,
          );
        }
        case "search": {
          const data = await contexts.search(
            { contextId, query, cursor, limit },
            authenticated.callContext,
          );
          const count = Array.isArray(data.results) ? data.results.length : 0;
          return successfulToolResult(data, undefined, `Context search returned ${count} result(s).`);
        }
        case "close": {
          if (!contextId) {
            throw new UniversalBrokerError(
              "PRECONDITION_FAILED",
              "context.close requires contextId.",
            );
          }
          const action = contextAction(operation, { contextId });
          const data = await withOperationAuthority(
            authority,
            authorityId,
            principal,
            action,
            minimumAuthorityRisk(action),
            () => contexts.close(contextId, authenticated.callContext),
            { auditObservation: observation, authInfo: authenticated.authInfo },
          );
          return successfulToolResult(data, undefined, `Closed context ${contextId}.`);
        }
        case "diff": {
          if (!contextId) {
            throw new UniversalBrokerError(
              "PRECONDITION_FAILED",
              "context.diff requires contextId.",
            );
          }
          const data = await contexts.diff(
            { contextId, maxCharacters },
            authenticated.callContext,
          );
          return successfulToolResult(
            data,
            undefined,
            `Context diff: ${String((data.summary as Record<string, unknown> | undefined)?.files ?? 0)} file(s).`,
          );
        }
      }
      },
    ),
  );
}

function registerContextDiffResource(
  server: McpServer,
  contexts: ContextRegistry,
  authorityPrincipal: AuthorityPrincipalResolver,
): void {
  server.registerResource(
    "Universal Broker context diff",
    new ResourceTemplate(
      "devspace://v1/context-diff/{diffId}",
      { list: undefined },
    ),
    {
      title: "Paged context diff",
      description: "Bounded text chunk from a context diff retained by the Universal Broker.",
      mimeType: "text/x-diff",
    },
    async (uri, _variables, extra) => {
      const authenticated = requireAuthenticatedPrincipal(extra, authorityPrincipal);
      requireScope(authenticated.authInfo, "devspace.read");
      const page = contexts.readDiffResource(uri.href, authenticated.callContext);
      return {
        contents: [{
          uri: uri.href,
          mimeType: String(page.mimeType ?? "text/x-diff"),
          text: String(page.text ?? ""),
          _meta: Object.fromEntries(
            Object.entries(page).filter(([key]) => !["uri", "mimeType", "text"].includes(key)),
          ),
        }],
      };
    },
  );
}

type AuthorityRequestExtra = AuthorityRequestIdentity & {
  _meta?: Record<string, unknown>;
  requestId?: string | number;
};
type AuthorityPrincipalResolver = (extra: AuthorityRequestExtra) => string;

interface AuthenticatedAuthorityRequest {
  authInfo: AuthorityAuthenticationInfo;
  principalKeyFingerprint: string;
  callContext: CapabilityCallContext;
}

interface GenerationObservation {
  targetGeneration?: string;
  routeGeneration?: string;
  audit?: {
    principalFingerprint: string;
    authorityId?: string;
    action: AuthorityActionDescriptor;
    risk: AuthorityRiskClass;
    claimState?: string;
    dispatchState: "NOT_DISPATCHED" | "CLAIMED" | "DISPATCHED" | "ACKNOWLEDGED" | "UNKNOWN";
    actionClaimId?: string;
    receiptDigest?: string;
  };
}

async function executeMeasuredUniversalTool(
  boundary: UniversalBrokerRequestBoundary,
  tool: UniversalToolName,
  operation: string,
  extra: AuthorityRequestExtra,
  callback: (
    requestMeta: UniversalRequestMeta,
    observation: GenerationObservation,
  ) => Promise<CallToolResult>,
): Promise<CallToolResult> {
  const startedAt = performance.now();
  const observation: GenerationObservation = {};
  let requestMeta: UniversalRequestMeta = {};
  const result = await executeUniversalTool(async () => {
    requestMeta = requestMetaFromExtra(extra);
    assertSchemaGeneration(requestMeta, boundary.runtimeIdentity);
    assertAuthorityContractGeneration(requestMeta, boundary.runtimeIdentity);
    return callback(requestMeta, observation);
  });
  applyObservedGenerations(result, boundary.runtimeIdentity, observation);
  const measured = measuredToolResult(result, tool);
  const metrics = boundary.metrics;
  if (metrics) {
    try {
      metrics.recordToolRequest(
        tool,
        operation,
        measured.result,
        performance.now() - startedAt,
        measured.errorCode,
      );
      if (measured.result === "unknown") {
        metrics.recordDispatchUnknown(measured.transport);
      }
    } catch {
      // Instrumentation must never replace the bounded tool result.
    }
  }
  await recordOperationAudit(
    boundary,
    tool,
    operation,
    extra,
    requestMeta,
    observation,
    result,
    measured.result,
  );
  return result;
}

async function recordOperationAudit(
  boundary: UniversalBrokerRequestBoundary,
  tool: UniversalToolName,
  operation: string,
  extra: AuthorityRequestExtra,
  requestMeta: UniversalRequestMeta,
  observation: GenerationObservation,
  result: CallToolResult,
  measuredResult: "pass" | "fail" | "unknown",
): Promise<void> {
  const sink = boundary.operationAudit;
  if (!sink) return;
  let receiptDigest = observation.audit?.receiptDigest;
  let actionClaimId = observation.audit?.actionClaimId;
  try {
    const envelope = recordValue(result.structuredContent);
    const error = recordValue(envelope?.error);
    const operationId = typeof envelope?.operationId === "string"
      ? envelope.operationId
      : `op_${String(extra.requestId ?? "unknown")}`;
    const principalFingerprint = observation.audit?.principalFingerprint
      ?? boundary.authorityPrincipal?.(extra);
    if (!principalFingerprint) return;
    const action = observation.audit?.action;
    const routeId = tool === "mcp" && typeof action?.resource === "string"
      ? action.resource
      : undefined;
    const outcomePromise = sink.record({
      operationId,
      correlationId: requestMeta.requestId ?? String(extra.requestId ?? operationId),
      principalFingerprint,
      ...(requestMeta.taskInstanceId ? { taskInstanceId: requestMeta.taskInstanceId } : {}),
      ...(observation.audit?.authorityId ?? requestMeta.authorityId
        ? { authorityId: observation.audit?.authorityId ?? requestMeta.authorityId }
        : {}),
      ...(action ? { action } : {}),
      ...(typeof action?.target === "string" ? { targetId: action.target } : {}),
      ...(observation.targetGeneration
        ? { targetGeneration: auditDigest(observation.targetGeneration) }
        : {}),
      ...(routeId ? { routeId } : {}),
      ...(observation.routeGeneration ? { routeGeneration: auditDigest(observation.routeGeneration) } : {}),
      tool,
      operation,
      risk: observation.audit?.risk ?? "R0",
      ...(observation.audit?.claimState ? { claimState: observation.audit.claimState } : {}),
      dispatchState: typeof error?.dispatchState === "string"
        ? error.dispatchState
        : observation.audit?.dispatchState ?? "NOT_DISPATCHED",
      result: measuredResult,
      ...(typeof error?.code === "string" ? { errorCode: error.code } : {}),
      ...(observation.audit?.receiptDigest
        ? { receiptDigest: observation.audit.receiptDigest }
        : {}),
    });
    if (!receiptDigest || !actionClaimId || !observation.audit?.authorityId || !boundary.authority) {
      void outcomePromise.then((outcome) => {
        recordAuditMetric(boundary, outcome.status === "RECORDED" ? "recorded" : "sink_failed");
      }).catch(() => recordAuditMetric(boundary, "sink_failed"));
      return;
    }
    // A provider mutation may return only after its audit event is durable. R0
    // observations retain the configured batching policy and are drained on
    // graceful shutdown, but an authority receipt forces this exact batch now.
    await sink.flush().catch(() => undefined);
    const outcome = await outcomePromise;
    recordAuditMetric(boundary, outcome.status === "RECORDED" ? "recorded" : "sink_failed");
    const linked = attachReceiptAuditResult(
      boundary,
      observation,
      outcome.status === "RECORDED"
        ? {
            status: "RECORDED",
            receiptDigest,
            actionClaimId,
            eventDigest: outcome.eventDigest,
          }
        : {
            status: "SINK_FAILED",
            receiptDigest,
            actionClaimId,
            errorCode: "AUDIT_SINK_FAILED",
          },
    );
    attachAuditMetadata(result, {
      status: outcome.status,
      ...(outcome.status === "RECORDED" ? { eventDigest: outcome.eventDigest } : {}),
      ...(receiptDigest ? { receiptDigest } : {}),
      ...(linked.authorityReceiptAuditState
        ? { authorityReceiptAuditState: linked.authorityReceiptAuditState }
        : {}),
      ...(linked.authorityReceiptAuditEventDigest
        ? { authorityReceiptAuditEventDigest: linked.authorityReceiptAuditEventDigest }
        : {}),
      ...(linked.errorCode ? { authorityReceiptAuditErrorCode: linked.errorCode } : {}),
    });
  } catch {
    recordAuditMetric(boundary, "sink_failed");
    const linked = attachReceiptAuditResult(boundary, observation, {
      status: "SINK_FAILED",
      receiptDigest,
      actionClaimId,
      errorCode: "AUDIT_RECORD_FAILED",
    });
    attachAuditMetadata(result, {
      status: "SINK_FAILED",
      ...(receiptDigest ? { receiptDigest } : {}),
      ...(linked.authorityReceiptAuditState
        ? { authorityReceiptAuditState: linked.authorityReceiptAuditState }
        : {}),
      ...(linked.errorCode ? { authorityReceiptAuditErrorCode: linked.errorCode } : {}),
    });
  }
}

function recordAuditMetric(
  boundary: UniversalBrokerRequestBoundary,
  result: "recorded" | "sink_failed",
): void {
  try {
    boundary.metrics?.recordAuditResult(result);
  } catch {
    // Audit/metrics failure must never replace a provider result.
  }
}

function attachReceiptAuditResult(
  boundary: UniversalBrokerRequestBoundary,
  observation: GenerationObservation,
  input: {
    status: "RECORDED" | "SINK_FAILED";
    receiptDigest?: string;
    actionClaimId?: string;
    eventDigest?: string;
    errorCode?: string;
  },
): {
  authorityReceiptAuditState?: string;
  authorityReceiptAuditEventDigest?: string;
  errorCode?: string;
} {
  const audit = observation.audit;
  if (
    !boundary.authority
    || !audit?.authorityId
    || !input.actionClaimId
    || !input.receiptDigest
  ) return {};
  try {
    const receipt = boundary.authority.recordReceiptAuditResult({
      authorityId: audit.authorityId,
      actionClaimId: input.actionClaimId,
      receiptDigest: input.receiptDigest,
      status: input.status,
      ...(input.eventDigest ? { auditEventDigest: input.eventDigest } : {}),
      ...(input.errorCode ? { errorCode: input.errorCode } : {}),
    });
    return {
      authorityReceiptAuditState: receipt?.auditState ?? input.status,
      ...(receipt?.auditEventDigest
        ? { authorityReceiptAuditEventDigest: receipt.auditEventDigest }
        : {}),
    };
  } catch (error) {
    return {
      errorCode: error instanceof UniversalBrokerError
        ? error.code
        : "AUTHORITY_STATE_UNCERTAIN",
    };
  }
}

function attachAuditMetadata(
  result: CallToolResult,
  audit: Record<string, unknown>,
): void {
  const envelope = recordValue(result.structuredContent);
  if (!envelope) return;
  envelope.audit = {
    ...(recordValue(envelope.audit) ?? {}),
    ...audit,
  };
}

function requestMetaFromExtra(extra: AuthorityRequestExtra): UniversalRequestMeta {
  const candidate = extra._meta?.devspace;
  if (candidate === undefined) return { requestId: `request_${randomUUID()}` };
  const parsed = universalRequestMetaSchema.safeParse(candidate);
  if (parsed.success) {
    return {
      ...parsed.data,
      requestId: parsed.data.requestId ?? `request_${randomUUID()}`,
    };
  }
  throw new UniversalBrokerError(
    "INVALID_ARGUMENT",
    "MCP request metadata at params._meta.devspace is invalid.",
    {
      evidence: {
        providerDispatchCount: 0,
        issues: parsed.error.issues.slice(0, 20).map((issue) => ({
          path: issue.path.join("."),
          message: issue.message,
        })),
      },
    },
  );
}

function assertSchemaGeneration(
  requestMeta: UniversalRequestMeta,
  runtimeIdentity: RuntimeIdentity | undefined,
): void {
  const expected = requestMeta.expectedSchemaGeneration;
  if (expected === undefined) return;
  const observed = runtimeIdentity?.schemaGeneration ?? `sha256:${"0".repeat(64)}`;
  if (expected === observed) return;
  throw new UniversalBrokerError(
    "SCHEMA_STALE",
    "The request schema generation does not match this broker runtime.",
    {
      evidence: {
        expectedSchemaGeneration: expected,
        observedSchemaGeneration: observed,
        providerDispatchCount: 0,
        durableClaimCount: 0,
      },
    },
  );
}

function assertAuthorityContractGeneration(
  requestMeta: UniversalRequestMeta,
  runtimeIdentity: RuntimeIdentity | undefined,
): void {
  const expected = requestMeta.expectedAuthorityContractGeneration;
  if (expected === undefined) return;
  const observed = runtimeIdentity?.authorityContractGeneration ?? `sha256:${"0".repeat(64)}`;
  if (expected === observed) return;
  throw new UniversalBrokerError(
    "SCHEMA_STALE",
    "The request authority contract generation does not match this broker runtime.",
    {
      evidence: {
        expectedAuthorityContractGeneration: expected,
        observedAuthorityContractGeneration: observed,
        providerDispatchCount: 0,
        durableClaimCount: 0,
      },
    },
  );
}

function mergeOperationRequestMeta<T extends Record<string, unknown>>(
  input: T,
  requestMeta: UniversalRequestMeta,
): T & Pick<UniversalRequestMeta, "authorityId" | "taskInstanceId" | "transactionId"> {
  const merged: Record<string, unknown> = { ...input };
  for (const field of ["authorityId", "taskInstanceId", "transactionId"] as const) {
    const argumentValue = merged[field];
    const metadataValue = requestMeta[field];
    if (argumentValue !== undefined) {
      throw new UniversalBrokerError(
        "INVALID_ARGUMENT",
        `Common request metadata ${field} is accepted only at params._meta.devspace.${field}.`,
        { evidence: { field, providerDispatchCount: 0, durableClaimCount: 0 } },
      );
    }
    if (metadataValue !== undefined) {
      merged[field] = metadataValue;
    }
  }
  return merged as T & Pick<
    UniversalRequestMeta,
    "authorityId" | "taskInstanceId" | "transactionId"
  >;
}

function assertGenerationApplicability(
  requestMeta: UniversalRequestMeta,
  tool: UniversalToolName,
  operation: string,
  applicable: { target: boolean; route: boolean },
): void {
  const invalidField = requestMeta.expectedTargetGeneration !== undefined && !applicable.target
    ? "expectedTargetGeneration"
    : requestMeta.expectedRouteGeneration !== undefined && !applicable.route
      ? "expectedRouteGeneration"
      : undefined;
  if (!invalidField) return;
  throw new UniversalBrokerError(
    "INVALID_ARGUMENT",
    `${invalidField} does not apply to ${tool}.${operation}.`,
    {
      evidence: {
        field: invalidField,
        tool,
        operation,
        providerDispatchCount: 0,
        durableClaimCount: 0,
      },
    },
  );
}

function assertTargetGeneration(
  requestMeta: UniversalRequestMeta,
  observed: string,
  observation: GenerationObservation,
): void {
  observation.targetGeneration = observed;
  const expected = requestMeta.expectedTargetGeneration;
  if (expected === undefined || expected === observed) return;
  throw new UniversalBrokerError(
    "AUTHORITY_STALE",
    "The expected target generation is stale; provider dispatch was not attempted.",
    {
      evidence: {
        expectedTargetGeneration: expected,
        observedTargetGeneration: observed,
        targetGeneration: observed,
        providerDispatchCount: 0,
        durableClaimCount: 0,
      },
    },
  );
}

function assertRouteGeneration(
  requestMeta: UniversalRequestMeta,
  observed: string,
  observation: GenerationObservation,
): void {
  observation.routeGeneration = observed;
  const expected = requestMeta.expectedRouteGeneration;
  if (expected === undefined || expected === observed) return;
  throw new UniversalBrokerError(
    "AUTHORITY_STALE",
    "The expected MCP route generation is stale; provider dispatch was not attempted.",
    {
      evidence: {
        expectedRouteGeneration: expected,
        observedRouteGeneration: observed,
        routeGeneration: observed,
        providerDispatchCount: 0,
        durableClaimCount: 0,
      },
    },
  );
}

function applyObservedGenerations(
  result: CallToolResult,
  runtimeIdentity: RuntimeIdentity | undefined,
  observation: GenerationObservation,
): void {
  const envelope = result.structuredContent;
  if (!envelope || typeof envelope !== "object") return;
  if (runtimeIdentity) {
    envelope.observedSchemaGeneration = runtimeIdentity.schemaGeneration;
    envelope.observedAuthorityContractGeneration = runtimeIdentity.authorityContractGeneration;
  }
  if (observation.targetGeneration) {
    envelope.observedTargetGeneration = observation.targetGeneration;
  }
  if (observation.routeGeneration) {
    envelope.observedRouteGeneration = observation.routeGeneration;
  }
}

function measuredToolResult(
  result: CallToolResult,
  tool: UniversalToolName,
): { result: "pass" | "fail" | "unknown"; transport: string; errorCode: string } {
  const envelope = result.structuredContent;
  if (!envelope || typeof envelope !== "object") {
    return {
      result: result.isError === true ? "fail" : "pass",
      transport: tool,
      errorCode: result.isError === true ? "MCP_ERROR" : "none",
    };
  }
  if (envelope.ok === true) {
    const data = recordValue(envelope.data);
    return {
      result: data?.state === "UNKNOWN" ? "unknown" : "pass",
      transport: measuredTransport(data, tool),
      errorCode: "none",
    };
  }
  const error = recordValue(envelope.error);
  const evidence = recordValue(error?.evidence);
  const unknown = error?.dispatchState === "UNKNOWN"
    || [
      "AUTHORITY_STATE_UNCERTAIN",
      "MCP_RESULT_UNKNOWN",
      "EXECUTION_STATE_UNKNOWN",
      "TRANSPORT_INTERRUPTED",
    ].includes(String(error?.code ?? ""));
  return {
    result: unknown ? "unknown" : "fail",
    transport: measuredTransport(evidence, tool),
    errorCode: typeof error?.code === "string" ? error.code : "UNEXPECTED_ERROR",
  };
}

function auditDigest(value: string): string {
  const normalized = value.trim().toLowerCase();
  return /^[a-f0-9]{64}$/u.test(normalized) ? `sha256:${normalized}` : normalized;
}

function measuredTransport(
  value: Record<string, unknown> | undefined,
  fallback: UniversalToolName,
): string {
  for (const field of ["targetTransport", "transport"] as const) {
    const candidate = value?.[field];
    if (typeof candidate === "string" && candidate.trim()) return candidate;
  }
  return fallback === "mcp" ? "mcp" : fallback;
}

function recordValue(value: unknown): Record<string, unknown> | undefined {
  return value && typeof value === "object" && !Array.isArray(value)
    ? value as Record<string, unknown>
    : undefined;
}

function requireAuthenticatedPrincipal(
  extra: AuthorityRequestExtra,
  authorityPrincipal: AuthorityPrincipalResolver,
): AuthenticatedAuthorityRequest {
  const authInfo = extra.authInfo;
  if (!authInfo) {
    throw new UniversalBrokerError(
      "AUTHENTICATION_FAILED",
      "Validated authentication information is required for configured broker capabilities.",
    );
  }
  const principalKeyFingerprint = authorityPrincipal(extra);
  return {
    authInfo,
    principalKeyFingerprint,
    callContext: createCapabilityCallContextFromTrustedPrincipal({
      principalKeyFingerprint,
    }),
  };
}

async function withOperationAuthority<T extends Record<string, unknown>>(
  authority: OperationAuthorityRegistry,
  authorityId: string | undefined,
  principalKeyFingerprint: () => string,
  action: AuthorityActionDescriptor,
  risk: AuthorityRiskClass,
  execute: (dispatch?: OperationAuthorityDispatchController) => Promise<T>,
  options: {
    adapterBoundary?: boolean;
    auditObservation?: GenerationObservation;
    authInfo?: AuthorityAuthenticationInfo;
  } = {},
): Promise<T> {
  requireActivatedConnectorForRisk(options.authInfo, risk);
  const principal = principalKeyFingerprint();
  const audit = options.auditObservation;
  if (audit) {
    audit.audit = {
      principalFingerprint: principal,
      ...(authorityId ? { authorityId } : {}),
      action,
      risk,
      dispatchState: "NOT_DISPATCHED",
    };
  }
  if (risk === "R0") return execute(undefined);
  const dispatch = authority.prepareDispatch(
    authorityId,
    principal,
    action,
    risk,
  );
  if (!options.adapterBoundary) {
    try {
      dispatch.claim();
      if (audit?.audit) {
        audit.audit.claimState = "CLAIMED";
        audit.audit.dispatchState = "CLAIMED";
      }
      dispatch.markDispatched();
      if (audit?.audit) audit.audit.dispatchState = "DISPATCHED";
    } catch (error) {
      if (dispatch.phase === "CLAIMED") {
        const receipt = dispatch.cancelNotDispatched({
          providerCallCount: 0,
          proof: "COARSE_BOUNDARY_PROVIDER_CALL_ZERO",
        });
        if (audit?.audit) {
          audit.audit.claimState = "CANCELLED_NOT_DISPATCHED";
          audit.audit.dispatchState = "NOT_DISPATCHED";
          audit.audit.actionClaimId = receipt.actionClaimId;
          audit.audit.receiptDigest = receipt.receiptDigest;
        }
      }
      throw error;
    }
  }
  let value: T;
  try {
    value = await execute(dispatch);
  } catch (error) {
    if (dispatch.phase === "CLAIMED") {
      try {
        const receipt = dispatch.cancelNotDispatched({
          providerCallCount: 0,
          proof: "ADAPTER_BOUNDARY_PROVIDER_CALL_ZERO",
        });
        if (audit?.audit) {
          audit.audit.claimState = "CANCELLED_NOT_DISPATCHED";
          audit.audit.dispatchState = "NOT_DISPATCHED";
          audit.audit.actionClaimId = receipt.actionClaimId;
          audit.audit.receiptDigest = receipt.receiptDigest;
        }
      } catch (cancellationError) {
        throw cancellationError;
      }
      throw error;
    }
    if (dispatch.phase !== "DISPATCHED") throw error;
    const uncertain = error instanceof UniversalBrokerError
      && ["MCP_RESULT_UNKNOWN", "EXECUTION_STATE_UNKNOWN", "TRANSPORT_INTERRUPTED"].includes(error.code);
    const receipt = dispatch.complete(uncertain ? "UNCERTAIN" : "FAIL", {
      tool: action.tool,
      operation: action.operation,
      errorCode: error instanceof UniversalBrokerError ? error.code : "UNEXPECTED_ERROR",
    });
    if (audit?.audit) {
      audit.audit.claimState = uncertain ? "UNCERTAIN" : "FAIL";
      audit.audit.dispatchState = uncertain ? "UNKNOWN" : "ACKNOWLEDGED";
      audit.audit.actionClaimId = receipt.actionClaimId;
      audit.audit.receiptDigest = receipt.receiptDigest;
    }
    throw error;
  }
  if (dispatch.phase === "CLAIMED") {
    const receipt = dispatch.cancelNotDispatched({
      providerCallCount: 0,
      proof: "ADAPTER_BOUNDARY_PROVIDER_CALL_ZERO",
    });
    if (audit?.audit) {
      audit.audit.claimState = "CANCELLED_NOT_DISPATCHED";
      audit.audit.dispatchState = "NOT_DISPATCHED";
      audit.audit.actionClaimId = receipt.actionClaimId;
      audit.audit.receiptDigest = receipt.receiptDigest;
    }
    return value;
  }
  if (dispatch.phase === "READY") return value;
  const terminalState = successfulDispatchTerminalState(value);
  const receipt = dispatch.complete(terminalState, {
    tool: action.tool,
    operation: action.operation,
  });
  if (audit?.audit) {
    audit.audit.claimState = terminalState;
    audit.audit.dispatchState = terminalState === "UNCERTAIN" ? "UNKNOWN" : "ACKNOWLEDGED";
    audit.audit.actionClaimId = receipt.actionClaimId;
    audit.audit.receiptDigest = receipt.receiptDigest;
  }
  return value;
}

function requireActivatedConnectorForRisk(
  authInfo: AuthorityAuthenticationInfo | undefined,
  risk: AuthorityRiskClass,
): void {
  if (risk === "R0") return;
  const connector = recordValue(authInfo?.extra?.devspaceConnector);
  if (connector?.activationRequired !== true) return;
  throw new UniversalBrokerError(
    "CONNECTOR_ACTIVATION_REQUIRED",
    "This connector must complete owner-approved canonical activation before mutation authority can be used.",
    {
      evidence: {
        ...(typeof connector.bindingId === "string" ? { connectorBindingId: connector.bindingId } : {}),
        ...(typeof connector.state === "string" ? { connectorState: connector.state } : {}),
        providerDispatchCount: 0,
        durableClaimCount: 0,
      },
    },
  );
}

function successfulDispatchTerminalState(
  value: Record<string, unknown>,
): "PASS" | "FAIL" | "UNCERTAIN" {
  if (value.state === "UNKNOWN") return "UNCERTAIN";
  if (value.state === "FAILED") return "FAIL";
  return "PASS";
}

type ResolvedTargetAuthorityBinding = Awaited<ReturnType<TargetRegistry["resolveWithGeneration"]>>;

async function resolveSelectedTargetBinding(
  targets: TargetRegistry,
  contexts: ContextRegistry,
  selector: string | undefined,
  contextId: string | undefined,
  callContext?: CapabilityCallContext,
): Promise<ResolvedTargetAuthorityBinding> {
  const context = contextId ? await contexts.get(contextId, callContext) : undefined;
  const binding = await targets.resolveWithGeneration(selector ?? context?.targetId);
  if (context && context.targetId !== binding.target.id) {
    throw new UniversalBrokerError(
      "PRECONDITION_FAILED",
      `Context ${context.contextId} belongs to target ${context.targetId}, not ${binding.target.id}.`,
    );
  }
  return binding;
}

function bindTargetAuthority(
  action: AuthorityActionDescriptor,
  binding: ResolvedTargetAuthorityBinding | undefined,
): AuthorityActionDescriptor {
  if (!binding) return action;
  return {
    ...action,
    target: binding.target.id,
    parameters: {
      ...(action.parameters ?? {}),
      targetGeneration: binding.generation,
    },
  };
}

interface RouteAuthorityBinding {
  routeId: string;
  routeGeneration: string;
}

function mcpResultRouteSelector(uri: string | undefined): string | undefined {
  if (!uri?.startsWith("devspace://mcp/")) return undefined;
  try {
    const parsed = new URL(uri);
    const [routeId, marker] = parsed.pathname.split("/").filter(Boolean);
    return marker === "result" && routeId ? decodeURIComponent(routeId) : undefined;
  } catch {
    return undefined;
  }
}

function bindRouteAuthority(
  action: AuthorityActionDescriptor,
  binding: RouteAuthorityBinding | undefined,
): AuthorityActionDescriptor {
  if (!binding) return action;
  return {
    ...action,
    resource: binding.routeId,
    parameters: {
      ...(action.parameters ?? {}),
      routeGeneration: binding.routeGeneration,
    },
  };
}

async function normalizeRequestedAuthorityActions(
  actions: Array<{
    id?: string;
    tool: UniversalToolName;
    arguments: Record<string, unknown>;
    risk?: AuthorityRiskClass;
    uses?: number;
  }> | undefined,
  targets: TargetRegistry,
  contexts: ContextRegistry,
  execution: UniversalExecutionPlane | undefined,
  filesystem: UniversalFilesystemService | undefined,
  mcpProxy: UniversalMcpProxy | undefined,
  gui: UniversalGuiService | undefined,
  callContext: CapabilityCallContext,
): Promise<RequestedAuthorityAction[]> {
  return Promise.all((actions ?? []).map(async (action) => ({
    ...(action.id ? { id: action.id } : {}),
    descriptor: await normalizeAuthorityAction(
      action.tool,
      action.arguments,
      targets,
      contexts,
      execution,
      filesystem,
      mcpProxy,
      gui,
      callContext,
    ),
    ...(action.risk ? { risk: action.risk } : {}),
    ...(action.uses ? { uses: action.uses } : {}),
  })));
}

function requireAuthorityPlanningInputScopes(
  authInfo: AuthorityAuthenticationInfo,
  actions: Array<{
    tool: UniversalToolName;
    arguments: Record<string, unknown>;
  }> | undefined,
): void {
  requireAuthorityPlanningScopes(
    authInfo,
    (actions ?? []).map((action) => ({
      descriptor: authorityActionFromToolCall(action.tool, action.arguments),
    })),
  );
}

function requireAuthorityPlanningScopes(
  authInfo: AuthorityAuthenticationInfo,
  actions: RequestedAuthorityAction[],
): void {
  const required = new Set<string>();
  for (const action of actions) {
    const descriptor = action.descriptor;
    const risk = minimumAuthorityRisk(descriptor);
    switch (descriptor.tool) {
      case "target":
        required.add("devspace.read");
        break;
      case "context":
      case "fs":
        required.add(risk === "R0" ? "devspace.read" : "devspace.write");
        break;
      case "exec":
      case "process":
        required.add("devspace.exec");
        break;
      case "mcp":
        required.add("devspace.mcp");
        break;
      case "artifact":
        required.add("devspace.artifact");
        required.add(descriptor.operation === "publish" ? "devspace.read" : "devspace.write");
        break;
      case "gui":
        required.add("devspace.gui");
        break;
    }
  }
  for (const scope of [...required].sort()) requireScope(authInfo, scope);
}

async function normalizeAuthorityAction(
  tool: UniversalToolName,
  argumentsValue: Record<string, unknown>,
  targets: TargetRegistry,
  contexts: ContextRegistry,
  execution: UniversalExecutionPlane | undefined,
  filesystem: UniversalFilesystemService | undefined,
  mcpProxy: UniversalMcpProxy | undefined,
  gui: UniversalGuiService | undefined,
  callContext: CapabilityCallContext,
): Promise<AuthorityActionDescriptor> {
  const action = authorityActionFromToolCall(tool, argumentsValue);
  switch (tool) {
    case "target":
      return action;
    case "process": {
      const input = argumentsValue as unknown as ProcessOperationInput;
      if (!processOperationNeedsBinding(input.operation)) return action;
      if (!execution) {
        throw new UniversalBrokerError(
          "CAPABILITY_UNAVAILABLE",
          "Process authority cannot be prepared because the execution plane is unavailable.",
        );
      }
      return processAction(
        input,
        execution.authorityBinding(input.processId, input.operation, callContext),
      );
    }
    case "context": {
      if (action.operation !== "open") return action;
      return bindTargetAuthority(
        action,
        await targets.resolveWithGeneration(
          typeof argumentsValue.target === "string" ? argumentsValue.target : undefined,
        ),
      );
    }
    case "fs": {
      const input = argumentsValue as unknown as UniversalFilesystemInput;
      const binding = await resolveSelectedTargetBinding(
        targets,
        contexts,
        input.target,
        input.contextId,
        callContext,
      );
      if (input.operation !== "sync" || input.sync?.phase !== "apply") {
        return bindTargetAuthority(filesystemAction(input, binding.target.id), binding);
      }
      if (!filesystem) {
        throw new UniversalBrokerError(
          "CAPABILITY_UNAVAILABLE",
          "Filesystem sync apply authority cannot be prepared because the filesystem service is unavailable.",
        );
      }
      const syncBinding = await filesystem.prepareSyncAuthorityBinding(input, callContext);
      if (
        syncBinding.targetId !== binding.target.id
        || syncBinding.targetGeneration !== binding.generation
      ) {
        throw new UniversalBrokerError(
          "SYNC_PLAN_STALE",
          "The immutable filesystem sync plan no longer matches the selected target generation.",
          { evidence: { planId: syncBinding.planId, targetId: syncBinding.targetId } },
        );
      }
      return bindTargetAuthority(filesystemAction(input, binding.target.id, {
        syncPlanDigest: syncBinding.planDigest,
        syncDeleteMode: syncBinding.deleteMode,
      }), binding);
    }
    case "exec": {
      const input = argumentsValue as unknown as ExecuteCommandInput;
      const binding = await resolveSelectedTargetBinding(
        targets,
        contexts,
        input.target,
        input.contextId,
        callContext,
      );
      if (!execution) {
        throw new UniversalBrokerError(
          "CAPABILITY_UNAVAILABLE",
          "Exec authority cannot be prepared because the execution plane is unavailable.",
        );
      }
      const executionBinding = await execution.prepareAuthorityBinding(
        input,
        binding.target,
        binding.generation,
        callContext,
      );
      return execAction(
        input,
        binding.target.id,
        executionBinding.effectiveCwd,
        {
          targetGeneration: binding.generation,
          targetTransport: binding.target.transport,
          targetPlatform: binding.target.platform,
          shellDialect: binding.target.shell,
          effectiveEnvProfile: input.envProfile ?? binding.target.envProfile,
          effectiveEnvProfileGeneration: executionBinding.effectiveEnvProfileGeneration,
        },
      );
    }
    case "mcp": {
      if (!mcpProxy) {
        throw new UniversalBrokerError(
          "CAPABILITY_UNAVAILABLE",
          "MCP authority cannot be prepared because the generic MCP proxy is unavailable.",
        );
      }
      const input = argumentsValue as unknown as UniversalMcpInput;
      if (input.operation === "routes") return action;
      const binding = input.operation === "invoke"
        ? await mcpProxy.inspectInvocation(input, callContext)
        : await mcpProxy.inspectRoute(input.route);
      return "risk" in binding
        ? mcpAction(input, binding as McpInvocationAuthorityBinding)
        : bindRouteAuthority(mcpAction(input, binding.routeId), binding);
    }
    case "artifact": {
      const normalized = await normalizeArtifactAuthority(
        argumentsValue as unknown as UniversalArtifactInput,
        targets,
        contexts,
        callContext,
      );
      return normalized.action;
    }
    case "gui": {
      if (!gui) {
        throw new UniversalBrokerError(
          "CAPABILITY_UNAVAILABLE",
          "GUI authority cannot be prepared because the GUI service is unavailable.",
        );
      }
      const input = argumentsValue as unknown as UniversalGuiInput;
      const binding = await gui.authorityTarget(input, callContext);
      return bindTargetAuthority(guiAction(input, binding.target.id), binding);
    }
  }
}

async function normalizeArtifactAuthority(
  input: UniversalArtifactInput,
  targets: TargetRegistry,
  contexts: ContextRegistry,
  callContext?: CapabilityCallContext,
): Promise<{
  action: AuthorityActionDescriptor;
  risk: AuthorityRiskClass;
  bindings: ResolvedTargetAuthorityBinding[];
}> {
  const source = await normalizeArtifactEndpoint(input.source, targets, contexts, callContext);
  const destination = await normalizeArtifactEndpoint(
    input.destination,
    targets,
    contexts,
    callContext,
  );
  const normalizedInput: UniversalArtifactInput = {
    ...input,
    source: source.endpoint ?? input.source,
    ...(input.destination
      ? { destination: destination.endpoint ?? input.destination }
      : {}),
  };
  const bindings = [source.binding, destination.binding]
    .filter((value): value is ResolvedTargetAuthorityBinding => Boolean(value));
  const action = bindMultipleTargetAuthority(artifactAction(normalizedInput), bindings);
  return {
    action,
    risk: artifactRisk(input.operation, {
      remote: bindings.some((binding) => binding.target.id !== "local"),
    }),
    bindings,
  };
}

async function normalizeArtifactEndpoint(
  endpoint: Record<string, unknown> | undefined,
  targets: TargetRegistry,
  contexts: ContextRegistry,
  callContext?: CapabilityCallContext,
): Promise<{
  endpoint?: Record<string, unknown>;
  binding?: ResolvedTargetAuthorityBinding;
}> {
  if (!endpoint) return {};
  const target = typeof endpoint.target === "string" ? endpoint.target : undefined;
  const contextId = typeof endpoint.contextId === "string" ? endpoint.contextId : undefined;
  const path = typeof endpoint.path === "string" ? endpoint.path : undefined;
  if (!target && !contextId && !path) return { endpoint };
  const binding = await resolveSelectedTargetBinding(
    targets,
    contexts,
    target,
    contextId,
    callContext,
  );
  return {
    endpoint: { ...endpoint, target: binding.target.id },
    binding,
  };
}

function bindMultipleTargetAuthority(
  action: AuthorityActionDescriptor,
  bindings: ResolvedTargetAuthorityBinding[],
): AuthorityActionDescriptor {
  if (bindings.length === 0) return action;
  const unique = [...new Map(bindings.map((binding) => [
    `${binding.generation}:${binding.target.id}`,
    binding,
  ])).values()]
    .map((binding) => ({
      targetId: binding.target.id,
      targetGeneration: binding.generation,
    }))
    .sort((left, right) => left.targetId.localeCompare(right.targetId));
  return {
    ...action,
    parameters: {
      ...(action.parameters ?? {}),
      targetBindings: unique,
    },
  };
}

function registerUnavailableTool(
  server: McpServer,
  name: UniversalToolName,
  contract: UniversalToolContract,
  requestBoundary: UniversalBrokerRequestBoundary,
): void {
  registerAppTool(
    server,
    name,
    {
      title: contract.title,
      description: contract.description,
      inputSchema: contract.inputSchema,
      annotations: contract.annotations,
      _meta: {},
    },
    async (input, extra) => executeMeasuredUniversalTool(
      requestBoundary,
      name,
      name === "exec" ? "run" : String((input as { operation?: unknown }).operation ?? "unknown"),
      extra,
      async () => failedToolResult(new UniversalBrokerError(
        "CAPABILITY_UNAVAILABLE",
        `${name} is registered in the Universal Broker contract but its backing service is not configured.`,
        {
          evidence: {
            phase: "service-not-configured",
            tool: name,
            providerDispatchCount: 0,
          },
        },
      )),
    ),
  );
}

function targetListText(targets: Array<Record<string, unknown>>): string {
  if (targets.length === 0) return "No targets are configured.";
  return targets
    .map((target) => `${String(target.targetId)}: ${String(target.displayName)} (${String(target.transport)})`)
    .join("\n");
}

function requireScope(authInfo: AuthorityAuthenticationInfo, required: string): void {
  const scopes = authInfo.scopes;
  if (Array.isArray(scopes) && scopes.includes(required)) return;
  throw new UniversalBrokerError(
    "SCOPE_INSUFFICIENT",
    `OAuth scope is required: ${required}`,
    {
      evidence: {
        requiredScope: required,
        grantedScopes: Array.isArray(scopes) ? scopes : [],
      },
    },
  );
}

function processSummaryText(data: Record<string, unknown>): string {
  const processId = typeof data.processId === "string" ? data.processId : "process";
  const state = typeof data.state === "string" ? data.state : "updated";
  const exitCode = typeof data.exitCode === "number" ? `, exit ${data.exitCode}` : "";
  const output = typeof data.output === "string" && data.output
    ? `\n${data.output}`
    : "";
  return `${processId}: ${state}${exitCode}${output}`;
}

function isFilesystemMutation(
  operation: UniversalFilesystemInput["operation"],
  syncPhase?: "plan" | "apply",
): boolean {
  if (operation === "sync") return syncPhase !== "plan";
  return !["stat", "list", "read", "search", "hash"].includes(operation);
}

function filesystemSummaryText(
  operation: UniversalFilesystemInput["operation"],
  data: Record<string, unknown>,
): string {
  const path = typeof data.path === "string"
    ? data.path
    : typeof data.destination === "string"
      ? data.destination
      : undefined;
  return path ? `${operation}: ${path}` : `Filesystem operation completed: ${operation}`;
}

function mcpSummaryText(
  operation: UniversalMcpInput["operation"],
  data: Record<string, unknown>,
): string {
  const route = data.route;
  const routeId = route && typeof route === "object"
    ? (route as Record<string, unknown>).routeId
    : undefined;
  const count = Array.isArray(data.routes)
    ? data.routes.length
    : Array.isArray(data.tools)
      ? data.tools.length
      : undefined;
  if (typeof routeId === "string") return `${operation}: ${routeId}`;
  if (typeof count === "number") return `${operation}: ${count} result(s)`;
  return `MCP operation completed: ${operation}`;
}

function artifactSummaryText(
  operation: UniversalArtifactInput["operation"],
  data: Record<string, unknown>,
): string {
  if (operation === "publish" && typeof data.resourceName === "string") {
    return `Published artifact: ${data.resourceName}`;
  }
  const path = typeof data.path === "string"
    ? data.path
    : data.destination && typeof data.destination === "object"
      ? (data.destination as Record<string, unknown>).path
      : undefined;
  return typeof path === "string"
    ? `${operation}: ${path}`
    : `Artifact operation completed: ${operation}`;
}

function guiSummaryText(
  operation: UniversalGuiInput["operation"],
  data: Record<string, unknown>,
): string {
  if (operation === "capabilities") {
    return `GUI capabilities: ${String(data.targetId ?? "target")} ${data.available === true ? "available" : "unavailable"}`;
  }
  if (operation === "observe") {
    return `Observed GUI session ${String(data.sessionId ?? "unknown")}.`;
  }
  if (operation === "wait") {
    return data.changed === true ? "GUI state changed." : "GUI wait timed out without change.";
  }
  return "GUI action completed.";
}

function templateVariable(value: string | string[] | undefined, name: string): string {
  if (typeof value === "string" && value.length > 0) return value;
  throw new UniversalBrokerError(
    "PRECONDITION_FAILED",
    `Missing resource template variable: ${name}`,
  );
}
