import { randomUUID } from "node:crypto";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import type { CallToolResult } from "@modelcontextprotocol/sdk/types.js";
import { registerAppTool } from "@modelcontextprotocol/ext-apps/server";
import {
  UNIVERSAL_BROKER_INSTRUCTIONS,
  UNIVERSAL_BROKER_VERSION,
  UNIVERSAL_TOOL_CONTRACTS,
  UNIVERSAL_TOOL_NAMES,
  type UniversalToolContract,
  type UniversalToolName,
} from "./contracts.js";

export function createUniversalBrokerMcpServer(): McpServer {
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

  for (const name of UNIVERSAL_TOOL_NAMES) {
    registerUnavailableTool(
      server,
      name,
      UNIVERSAL_TOOL_CONTRACTS[name] as UniversalToolContract,
    );
  }

  return server;
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

function unavailableResult(name: UniversalToolName): CallToolResult {
  const operationId = `op_${randomUUID()}`;
  const message = `${name} is registered in the Universal Broker v2 contract but is not implemented in the Phase 1 skeleton.`;
  const structuredContent = {
    ok: false,
    operationId,
    error: {
      code: "CAPABILITY_UNAVAILABLE" as const,
      message,
      retryable: false,
      evidence: {
        phase: "phase-1-skeleton",
        tool: name,
      },
    },
  };

  return {
    isError: true,
    content: [{ type: "text" as const, text: message }],
    structuredContent,
  };
}
