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
  type AuthorityGrant,
  type CreateOperationAuthorityInput,
  type RequestedAuthorityAction,
} from "./authority.js";
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
import type {
  ExecuteCommandInput,
  ProcessOperationInput,
  UniversalExecutionPlane,
} from "./execution.js";
import type {
  UniversalFilesystemInput,
  UniversalFilesystemService,
} from "./filesystem.js";
import type {
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
  type AuthorityRiskClass,
  type UniversalToolContract,
  type UniversalToolName,
} from "./contracts.js";
import {
  executeUniversalTool,
  successfulToolResult,
  UniversalBrokerError,
} from "./errors.js";
import {
  type TargetRegistry,
  targetSummary,
} from "./targets.js";

export interface UniversalBrokerServices {
  targets?: TargetRegistry;
  contexts?: ContextRegistry;
  execution?: UniversalExecutionPlane;
  filesystem?: UniversalFilesystemService;
  mcpProxy?: UniversalMcpProxy;
  artifacts?: UniversalArtifactService;
  gui?: UniversalGuiService;
  authority?: OperationAuthorityRegistry;
  selfManagement?: UniversalSelfManagementService;
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
  });

  if (services.execution) registerProcessOutputResource(server, services.execution);
  if (services.mcpProxy) registerMcpResultResource(server, services.mcpProxy);
  if (services.contexts) registerContextDiffResource(server, services.contexts);

  for (const name of UNIVERSAL_TOOL_NAMES) {
    if (name === "target" && services.targets) {
      registerTargetTool(server, services.targets);
    } else if (name === "context" && services.contexts && services.targets) {
      registerContextTool(
        server,
        services.contexts,
        services.targets,
        services.mcpProxy,
        services.gui,
        authority,
      );
    } else if (name === "exec" && services.execution && services.targets && services.contexts) {
      registerExecTool(server, services.execution, services.targets, services.contexts, authority);
    } else if (name === "process" && services.execution) {
      registerProcessTool(server, services.execution, authority, services.selfManagement);
    } else if (name === "fs" && services.filesystem && services.targets && services.contexts) {
      registerFilesystemTool(server, services.filesystem, services.targets, services.contexts, authority);
    } else if (name === "mcp" && services.mcpProxy) {
      registerMcpTool(server, services.mcpProxy, authority);
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
      );
    } else if (name === "gui" && services.gui && services.targets) {
      registerGuiTool(server, services.gui, authority);
    } else {
      registerUnavailableTool(
        server,
        name,
        UNIVERSAL_TOOL_CONTRACTS[name] as UniversalToolContract,
      );
    }
  }

  return server;
}

function registerGuiTool(
  server: McpServer,
  gui: UniversalGuiService,
  authority: OperationAuthorityRegistry,
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
    async (input, extra) => executeUniversalTool(async () => {
      requireScope(extra.authInfo?.scopes, "devspace.gui");
      const typed = input as UniversalGuiInput;
      const targetBinding = typed.operation === "act"
        ? await gui.authorityTarget(typed)
        : undefined;
      const action = bindTargetAuthority(
        guiAction(typed, targetBinding?.target.id),
        targetBinding,
      );
      const risk: AuthorityRiskClass = typed.operation === "act" ? "R3" : "R0";
      const data = await withOperationAuthority(
        authority,
        typed.authorityId,
        authorityScope(extra),
        action,
        risk,
        () => gui.execute(typed),
      );
      return successfulToolResult(data, undefined, guiSummaryText(typed.operation, data));
    }),
  );
}

function registerArtifactTool(
  server: McpServer,
  artifacts: UniversalArtifactService,
  targets: TargetRegistry,
  contexts: ContextRegistry,
  authority: OperationAuthorityRegistry,
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
    async (input, extra) => executeUniversalTool(async () => {
      requireScope(extra.authInfo?.scopes, "devspace.artifact");
      requireScope(
        extra.authInfo?.scopes,
        input.operation === "publish" ? "devspace.read" : "devspace.write",
      );
      const typed = input as UniversalArtifactInput;
      const normalized = await normalizeArtifactAuthority(
        typed,
        targets,
        contexts,
      );
      const data = await withOperationAuthority(
        authority,
        typed.authorityId,
        authorityScope(extra),
        normalized.action,
        normalized.risk,
        () => artifacts.execute(typed),
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
    }),
  );
}

function registerMcpTool(
  server: McpServer,
  proxy: UniversalMcpProxy,
  authority: OperationAuthorityRegistry,
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
    async (input, extra) => executeUniversalTool(async () => {
      requireScope(extra.authInfo?.scopes, "devspace.mcp");
      const typed = input as UniversalMcpInput;
      let routeBinding: RouteAuthorityBinding | undefined;
      if (typed.operation === "invoke") {
        routeBinding = await proxy.inspectInvocation(typed);
      } else if (typed.operation === "close") {
        routeBinding = await proxy.inspectRoute(typed.route);
      }
      const action = bindRouteAuthority(
        mcpAction(typed, routeBinding?.routeId),
        routeBinding,
      );
      const risk = minimumAuthorityRisk(action);
      const data = await withOperationAuthority(
        authority,
        typed.authorityId,
        authorityScope(extra),
        action,
        risk,
        () => proxy.execute(typed),
      );
      return successfulToolResult(
        data,
        undefined,
        mcpSummaryText(typed.operation, data),
      );
    }),
  );
}

function registerFilesystemTool(
  server: McpServer,
  filesystem: UniversalFilesystemService,
  targets: TargetRegistry,
  contexts: ContextRegistry,
  authority: OperationAuthorityRegistry,
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
    async (input, extra) => executeUniversalTool(async () => {
      requireScope(
        extra.authInfo?.scopes,
        isFilesystemMutation(input.operation) ? "devspace.write" : "devspace.read",
      );
      const typed = input as UniversalFilesystemInput;
      const targetBinding = await resolveSelectedTargetBinding(
        targets,
        contexts,
        typed.target,
        typed.contextId,
      );
      const action = bindTargetAuthority(
        filesystemAction(typed, targetBinding.target.id),
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
        authorityScope(extra),
        action,
        risk,
        () => filesystem.execute(typed),
      );
      return successfulToolResult(
        data,
        undefined,
        filesystemSummaryText(typed.operation, data),
      );
    }),
  );
}

function registerExecTool(
  server: McpServer,
  execution: UniversalExecutionPlane,
  targets: TargetRegistry,
  contexts: ContextRegistry,
  authority: OperationAuthorityRegistry,
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
    async (input, extra) => executeUniversalTool(async () => {
      requireScope(extra.authInfo?.scopes, "devspace.exec");
      const typed = input as ExecuteCommandInput;
      const targetBinding = await resolveSelectedTargetBinding(
        targets,
        contexts,
        typed.target,
        typed.contextId,
      );
      const resource = typed.cwd ?? typed.contextId ?? "default";
      const action = bindTargetAuthority(
        execAction(typed, targetBinding.target.id, resource),
        targetBinding,
      );
      const risk = minimumAuthorityRisk(action);
      const data = await withOperationAuthority(
        authority,
        typed.authorityId,
        authorityScope(extra),
        action,
        risk,
        () => execution.execute(typed),
      );
      return successfulToolResult(
        data,
        undefined,
        processSummaryText(data),
      );
    }),
  );
}

function registerProcessTool(
  server: McpServer,
  execution: UniversalExecutionPlane,
  authority: OperationAuthorityRegistry,
  selfManagement?: UniversalSelfManagementService,
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
    async (input, extra) => executeUniversalTool(async () => {
      requireScope(extra.authInfo?.scopes, "devspace.exec");
      const typed = input as ProcessOperationInput;
      const data = await withOperationAuthority(
        authority,
        typed.authorityId,
        authorityScope(extra),
        processAction(typed),
        processRisk(typed.operation),
        async () => {
          if (typed.operation === "restart_broker") {
            if (!selfManagement) return unavailableSelfManagement("restart_broker");
            return selfManagement.requestRestart({
              reason: typed.reason,
              delayMs: typed.delayMs,
            });
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
          return execution.operate(typed);
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
    }),
  );
}

function unavailableSelfManagement(operation: string): never {
  throw new UniversalBrokerError(
    "CAPABILITY_UNAVAILABLE",
    `Broker self-management is unavailable for process.${operation}.`,
  );
}

function registerProcessOutputResource(
  server: McpServer,
  execution: UniversalExecutionPlane,
): void {
  server.registerResource(
    "Universal Broker process output",
    new ResourceTemplate(
      "devspace://process/{processId}/output/{offset}/{limit}",
      { list: undefined },
    ),
    {
      title: "Managed process output",
      description: "Bounded UTF-8 chunk from the full output retained for a managed process.",
      mimeType: "text/plain",
    },
    async (uri, variables, extra) => {
      requireScope(extra.authInfo?.scopes, "devspace.exec");
      const processId = templateVariable(variables.processId, "processId");
      const offset = numericTemplateVariable(variables.offset, "offset", 0, Number.MAX_SAFE_INTEGER);
      const limit = numericTemplateVariable(variables.limit, "limit", 1, 1_048_576);
      const chunk = await execution.readOutput(processId, offset, limit);
      return {
        contents: [{
          uri: uri.href,
          mimeType: "text/plain",
          text: chunk.text,
          _meta: {
            processId,
            offset,
            nextOffset: chunk.nextOffset,
            totalBytes: chunk.totalBytes,
            truncated: chunk.truncated,
          },
        }],
      };
    },
  );
}

function registerMcpResultResource(
  server: McpServer,
  proxy: UniversalMcpProxy,
): void {
  server.registerResource(
    "Universal Broker MCP result",
    new ResourceTemplate(
      "devspace://mcp-result/{resultId}/{offset}/{limit}",
      { list: undefined },
    ),
    {
      title: "Paged downstream MCP result",
      description: "Bounded JSON chunk from a downstream MCP result retained in the v2 result store.",
      mimeType: "application/json",
    },
    async (uri, _variables, extra) => {
      requireScope(extra.authInfo?.scopes, "devspace.mcp");
      const page = proxy.readStoredResult(uri.href);
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

function registerTargetTool(server: McpServer, targets: TargetRegistry): void {
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
    async ({ operation, selector, targetId, refresh, cursor, limit }, extra) => executeUniversalTool(async () => {
      requireScope(extra.authInfo?.scopes, "devspace.read");
      switch (operation) {
        case "list": {
          const data = await targets.list({ cursor, limit });
          return successfulToolResult(data, undefined, targetListText(data.targets));
        }
        case "resolve": {
          const { generation, target: resolved } = await targets.resolveWithGeneration(
            selector ?? targetId,
          );
          const data = {
            generation,
            target: targetSummary(resolved),
          };
          return successfulToolResult(data, undefined, `Resolved target: ${resolved.id}`);
        }
        case "probe": {
          const observation = await targets.probe(targetId ?? selector, { refresh });
          return successfulToolResult(
            { observation },
            undefined,
            `${observation.targetId}: ${observation.status}`,
          );
        }
      }
    }),
  );
}

function registerContextTool(
  server: McpServer,
  contexts: ContextRegistry,
  targets: TargetRegistry,
  mcpProxy: UniversalMcpProxy | undefined,
  gui: UniversalGuiService | undefined,
  authority: OperationAuthorityRegistry,
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
    async ({
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
      taskId,
      authorityText,
      actions,
      correctionText,
      expiresInSeconds,
    }, extra) => executeUniversalTool(async () => {
      requireScope(extra.authInfo?.scopes, "devspace.read");
      const scopeId = authorityScope(extra);
      if (operation === "close" || (operation === "open" && mode === "worktree")) {
        requireScope(extra.authInfo?.scopes, "devspace.write");
      }
      switch (operation) {
        case "authority_preview": {
          requireAuthorityPlanningInputScopes(extra.authInfo?.scopes, actions);
          const normalizedActions = await normalizeRequestedAuthorityActions(
            actions,
            targets,
            contexts,
            mcpProxy,
            gui,
          );
          requireAuthorityPlanningScopes(extra.authInfo?.scopes, normalizedActions);
          const data = authority.preview(normalizedActions);
          return successfulToolResult(
            data,
            undefined,
            `Authority preview: ${String(data.authorityActionCount)} of ${String(data.actionCount)} action(s) require authority.`,
          );
        }
        case "authorize": {
          requireAuthorityPlanningInputScopes(extra.authInfo?.scopes, actions);
          const normalizedActions = await normalizeRequestedAuthorityActions(
            actions,
            targets,
            contexts,
            mcpProxy,
            gui,
          );
          requireAuthorityPlanningScopes(extra.authInfo?.scopes, normalizedActions);
          const data = authority.create({
            taskId: taskId ?? "",
            authorityText: authorityText ?? "",
            actions: normalizedActions,
            expiresInSeconds,
          } satisfies CreateOperationAuthorityInput, scopeId);
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
          const data = authority.status(authorityId, scopeId);
          return successfulToolResult(data, undefined, `Task authority status: ${authorityId}`);
        }
        case "invalidate_authority": {
          const data = authority.invalidate(scopeId, correctionText ?? "");
          return successfulToolResult(
            data,
            undefined,
            `Invalidated ${String((data.invalidatedAuthorityIds as unknown[]).length)} task authority record(s).`,
          );
        }
        case "release_authority": {
          if (!authorityId) {
            throw new UniversalBrokerError(
              "PRECONDITION_FAILED",
              "context.release_authority requires authorityId.",
            );
          }
          const data = authority.release(authorityId, scopeId);
          return successfulToolResult(data, undefined, `Released task authority ${authorityId}.`);
        }
        case "open": {
          const rawAction = contextAction(operation, { target, path, contextId, mode, baseRef });
          const targetBinding = mode === "worktree"
            ? await targets.resolveWithGeneration(target)
            : undefined;
          const action = bindTargetAuthority(rawAction, targetBinding);
          const data = await withOperationAuthority(
            authority,
            authorityId,
            scopeId,
            action,
            minimumAuthorityRisk(action),
            () => contexts.open({ target, path, mode, baseRef, task }),
          );
          return successfulToolResult(
            data,
            undefined,
            data.reused
              ? `Reused context ${data.contextId} at ${data.root}`
              : `Opened context ${data.contextId} at ${data.root}`,
          );
        }
        case "search": {
          const data = await contexts.search({ contextId, query, cursor, limit });
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
            scopeId,
            action,
            minimumAuthorityRisk(action),
            () => contexts.close(contextId),
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
          const data = await contexts.diff({ contextId, maxCharacters });
          return successfulToolResult(
            data,
            undefined,
            `Context diff: ${String((data.summary as Record<string, unknown> | undefined)?.files ?? 0)} file(s).`,
          );
        }
      }
    }),
  );
}

function registerContextDiffResource(
  server: McpServer,
  contexts: ContextRegistry,
): void {
  server.registerResource(
    "Universal Broker context diff",
    new ResourceTemplate(
      "devspace://context-diff/{diffId}/{offset}/{limit}",
      { list: undefined },
    ),
    {
      title: "Paged context diff",
      description: "Bounded text chunk from a context diff retained by the Universal Broker.",
      mimeType: "text/x-diff",
    },
    async (uri, _variables, extra) => {
      requireScope(extra.authInfo?.scopes, "devspace.read");
      const page = contexts.readDiffResource(uri.href);
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

interface AuthorityRequestExtra {
  authInfo?: { clientId?: string };
  sessionId?: string;
}

async function withOperationAuthority<T extends Record<string, unknown>>(
  authority: OperationAuthorityRegistry,
  authorityId: string | undefined,
  scopeId: string,
  action: AuthorityActionDescriptor,
  risk: AuthorityRiskClass,
  execute: () => Promise<T>,
): Promise<T> {
  let grant: AuthorityGrant | undefined;
  grant = authority.require(authorityId, scopeId, action, risk);
  try {
    const value = await execute();
    authority.record(grant, "PASS", {
      tool: action.tool,
      operation: action.operation,
    });
    return value;
  } catch (error) {
    const uncertain = error instanceof UniversalBrokerError
      && ["MCP_RESULT_UNKNOWN", "EXECUTION_STATE_UNKNOWN", "TRANSPORT_INTERRUPTED"].includes(error.code);
    authority.record(grant, uncertain ? "UNCERTAIN" : "FAIL", {
      tool: action.tool,
      operation: action.operation,
      errorCode: error instanceof UniversalBrokerError ? error.code : "UNEXPECTED_ERROR",
    });
    throw error;
  }
}

function authorityScope(extra: AuthorityRequestExtra): string {
  const clientId = extra.authInfo?.clientId?.trim() || "anonymous";
  const sessionId = extra.sessionId?.trim() || "sessionless";
  return `${clientId}:${sessionId}`;
}

type ResolvedTargetAuthorityBinding = Awaited<ReturnType<TargetRegistry["resolveWithGeneration"]>>;

async function resolveSelectedTargetBinding(
  targets: TargetRegistry,
  contexts: ContextRegistry,
  selector: string | undefined,
  contextId: string | undefined,
): Promise<ResolvedTargetAuthorityBinding> {
  const context = contextId ? await contexts.get(contextId) : undefined;
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
  routeFingerprint: string;
  annotations?: Record<string, unknown>;
}

function bindRouteAuthority(
  action: AuthorityActionDescriptor,
  binding: RouteAuthorityBinding | undefined,
): AuthorityActionDescriptor {
  if (!binding) return action;
  const readOnly = binding.annotations?.readOnlyHint === true;
  const destructive = binding.annotations?.destructiveHint === true;
  return {
    ...action,
    resource: binding.routeId,
    parameters: {
      ...(action.parameters ?? {}),
      routeFingerprint: binding.routeFingerprint,
      ...(readOnly ? { readOnly: true } : {}),
      ...(destructive ? { destructive: true } : {}),
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
  mcpProxy: UniversalMcpProxy | undefined,
  gui: UniversalGuiService | undefined,
): Promise<RequestedAuthorityAction[]> {
  return Promise.all((actions ?? []).map(async (action) => ({
    ...(action.id ? { id: action.id } : {}),
    descriptor: await normalizeAuthorityAction(
      action.tool,
      action.arguments,
      targets,
      contexts,
      mcpProxy,
      gui,
    ),
    ...(action.risk ? { risk: action.risk } : {}),
    ...(action.uses ? { uses: action.uses } : {}),
  })));
}

function requireAuthorityPlanningInputScopes(
  scopes: string[] | undefined,
  actions: Array<{
    tool: UniversalToolName;
    arguments: Record<string, unknown>;
  }> | undefined,
): void {
  requireAuthorityPlanningScopes(
    scopes,
    (actions ?? []).map((action) => ({
      descriptor: authorityActionFromToolCall(action.tool, action.arguments),
    })),
  );
}

function requireAuthorityPlanningScopes(
  scopes: string[] | undefined,
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
  for (const scope of [...required].sort()) requireScope(scopes, scope);
}

async function normalizeAuthorityAction(
  tool: UniversalToolName,
  argumentsValue: Record<string, unknown>,
  targets: TargetRegistry,
  contexts: ContextRegistry,
  mcpProxy: UniversalMcpProxy | undefined,
  gui: UniversalGuiService | undefined,
): Promise<AuthorityActionDescriptor> {
  const action = authorityActionFromToolCall(tool, argumentsValue);
  switch (tool) {
    case "target":
    case "process":
      return action;
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
      );
      return bindTargetAuthority(filesystemAction(input, binding.target.id), binding);
    }
    case "exec": {
      const input = argumentsValue as unknown as ExecuteCommandInput;
      const binding = await resolveSelectedTargetBinding(
        targets,
        contexts,
        input.target,
        input.contextId,
      );
      return bindTargetAuthority(
        execAction(input, binding.target.id, input.cwd ?? input.contextId ?? "default"),
        binding,
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
        ? await mcpProxy.inspectInvocation(input)
        : await mcpProxy.inspectRoute(input.route);
      return bindRouteAuthority(mcpAction(input, binding.routeId), binding);
    }
    case "artifact": {
      const normalized = await normalizeArtifactAuthority(
        argumentsValue as unknown as UniversalArtifactInput,
        targets,
        contexts,
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
      const binding = await gui.authorityTarget(input);
      return bindTargetAuthority(guiAction(input, binding.target.id), binding);
    }
  }
}

async function normalizeArtifactAuthority(
  input: UniversalArtifactInput,
  targets: TargetRegistry,
  contexts: ContextRegistry,
): Promise<{ action: AuthorityActionDescriptor; risk: AuthorityRiskClass }> {
  const source = await normalizeArtifactEndpoint(input.source, targets, contexts);
  const destination = await normalizeArtifactEndpoint(input.destination, targets, contexts);
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
  };
}

async function normalizeArtifactEndpoint(
  endpoint: Record<string, unknown> | undefined,
  targets: TargetRegistry,
  contexts: ContextRegistry,
): Promise<{
  endpoint?: Record<string, unknown>;
  binding?: ResolvedTargetAuthorityBinding;
}> {
  if (!endpoint) return {};
  const target = typeof endpoint.target === "string" ? endpoint.target : undefined;
  const contextId = typeof endpoint.contextId === "string" ? endpoint.contextId : undefined;
  const path = typeof endpoint.path === "string" ? endpoint.path : undefined;
  if (!target && !contextId && !path) return { endpoint };
  const binding = await resolveSelectedTargetBinding(targets, contexts, target, contextId);
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
    async () => unavailableResult(name),
  );
}

function unavailableResult(
  name: UniversalToolName,
  evidence: Record<string, unknown> = {
    phase: "service-not-configured",
    tool: name,
  },
): CallToolResult {
  const operationId = `op_${randomUUID()}`;
  const message = `${name} is registered in the Universal Broker contract but its backing service is not configured.`;
  const structuredContent = {
    ok: false,
    operationId,
    error: {
      code: "CAPABILITY_UNAVAILABLE" as const,
      message,
      retryable: false,
      evidence,
    },
  };

  return {
    isError: true,
    content: [{ type: "text" as const, text: message }],
    structuredContent,
  };
}

function targetListText(targets: Array<Record<string, unknown>>): string {
  if (targets.length === 0) return "No targets are configured.";
  return targets
    .map((target) => `${String(target.targetId)}: ${String(target.displayName)} (${String(target.transport)})`)
    .join("\n");
}

function requireScope(scopes: string[] | undefined, required: string): void {
  if (
    scopes === undefined
    || scopes.includes(required)
  ) return;
  throw new UniversalBrokerError(
    "PERMISSION_DENIED",
    `OAuth scope is required: ${required}`,
    {
      evidence: {
        requiredScope: required,
        grantedScopes: scopes,
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
): boolean {
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

function numericTemplateVariable(
  value: string | string[] | undefined,
  name: string,
  minimum: number,
  maximum: number,
): number {
  const raw = templateVariable(value, name);
  const parsed = Number(raw);
  if (!Number.isInteger(parsed) || parsed < minimum || parsed > maximum) {
    throw new UniversalBrokerError(
      "PRECONDITION_FAILED",
      `Invalid resource template variable ${name}: ${raw}`,
    );
  }
  return parsed;
}
