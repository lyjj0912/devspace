import { randomUUID } from "node:crypto";
import {
  McpServer,
  ResourceTemplate,
} from "@modelcontextprotocol/sdk/server/mcp.js";
import type { CallToolResult } from "@modelcontextprotocol/sdk/types.js";
import { registerAppTool } from "@modelcontextprotocol/ext-apps/server";
import type { ContextRegistry } from "./contexts.js";
import type { UniversalExecutionPlane } from "./execution.js";
import {
  UNIVERSAL_BROKER_INSTRUCTIONS,
  UNIVERSAL_BROKER_VERSION,
  UNIVERSAL_TOOL_CONTRACTS,
  UNIVERSAL_TOOL_NAMES,
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

  if (services.execution) registerProcessOutputResource(server, services.execution);

  for (const name of UNIVERSAL_TOOL_NAMES) {
    if (name === "target" && services.targets) {
      registerTargetTool(server, services.targets);
    } else if (name === "context" && services.contexts) {
      registerContextTool(server, services.contexts);
    } else if (name === "exec" && services.execution) {
      registerExecTool(server, services.execution);
    } else if (name === "process" && services.execution) {
      registerProcessTool(server, services.execution);
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

function registerExecTool(server: McpServer, execution: UniversalExecutionPlane): void {
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
      if (input.privilege === "admin") {
        requireScope(extra.authInfo?.scopes, "devspace.admin");
      }
      const data = await execution.execute(input);
      return successfulToolResult(
        data,
        undefined,
        processSummaryText(data),
      );
    }),
  );
}

function registerProcessTool(server: McpServer, execution: UniversalExecutionPlane): void {
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
      const data = await execution.operate(input);
      const text = input.operation === "list"
        ? `Managed processes: ${Array.isArray(data.processes) ? data.processes.length : 0}`
        : processSummaryText(data);
      return successfulToolResult(data, undefined, text);
    }),
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
    async ({ operation, selector, targetId, cursor, limit }, extra) => executeUniversalTool(async () => {
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
          const observation = await targets.probe(targetId ?? selector);
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

function registerContextTool(server: McpServer, contexts: ContextRegistry): void {
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
    async ({ operation, contextId, target, path, mode, task, query, cursor, limit }, extra) => executeUniversalTool(async () => {
      requireScope(extra.authInfo?.scopes, "devspace.read");
      switch (operation) {
        case "open": {
          const data = await contexts.open({ target, path, mode, task });
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
          const data = await contexts.close(contextId);
          return successfulToolResult(data, undefined, `Closed context ${contextId}.`);
        }
        case "diff":
          return unavailableResult("context", {
            operation: "diff",
            phase: "phase-2",
          });
      }
    }),
  );
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
    phase: "phase-1-skeleton",
    tool: name,
  },
): CallToolResult {
  const operationId = `op_${randomUUID()}`;
  const message = `${name} is registered in the Universal Broker v2 contract but is not implemented in the Phase 1 skeleton.`;
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
  if (scopes === undefined || scopes.includes(required)) return;
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
