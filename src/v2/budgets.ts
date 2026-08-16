import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import type { Tool } from "@modelcontextprotocol/sdk/types.js";
import {
  UNIVERSAL_BROKER_BUDGETS,
  UNIVERSAL_BROKER_INSTRUCTIONS,
  UNIVERSAL_TOOL_NAMES,
} from "./contracts.js";
import { createUniversalBrokerMcpServer } from "./server.js";

export interface UniversalBrokerBudgetReport {
  toolCount: number;
  toolNames: string[];
  descriptorCharacters: number;
  instructionCharacters: number;
  perToolDescriptorCharacters: Record<string, number>;
  passed: boolean;
  failures: string[];
}

export async function inspectUniversalBrokerBudgets(): Promise<UniversalBrokerBudgetReport> {
  const server = createUniversalBrokerMcpServer();
  const client = new Client({
    name: "devspace-universal-broker-budget-check",
    version: "1.0.0",
  });
  const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();

  try {
    await Promise.all([
      client.connect(clientTransport),
      server.connect(serverTransport),
    ]);
    const listed = await client.listTools();
    return budgetReport(listed.tools);
  } finally {
    await Promise.allSettled([
      client.close(),
      server.close(),
    ]);
  }
}

export function assertUniversalBrokerBudgets(
  report: UniversalBrokerBudgetReport,
): void {
  if (report.passed) return;
  throw new Error(
    `Universal Broker v2 budget gate failed:\n${report.failures.map((failure) => `- ${failure}`).join("\n")}`,
  );
}

function budgetReport(tools: Tool[]): UniversalBrokerBudgetReport {
  const toolNames = tools.map((tool) => tool.name);
  const descriptorCharacters = JSON.stringify(tools).length;
  const instructionCharacters = UNIVERSAL_BROKER_INSTRUCTIONS.length;
  const perToolDescriptorCharacters = Object.fromEntries(
    tools.map((tool) => [tool.name, JSON.stringify(tool).length]),
  );
  const failures: string[] = [];

  if (tools.length !== UNIVERSAL_TOOL_NAMES.length) {
    failures.push(
      `expected exactly ${UNIVERSAL_TOOL_NAMES.length} tools, received ${tools.length}`,
    );
  }
  if (tools.length > UNIVERSAL_BROKER_BUDGETS.maximumTools) {
    failures.push(
      `tool count ${tools.length} exceeds ${UNIVERSAL_BROKER_BUDGETS.maximumTools}`,
    );
  }
  if (JSON.stringify(toolNames) !== JSON.stringify(UNIVERSAL_TOOL_NAMES)) {
    failures.push(
      `tool names/order differ: ${toolNames.join(", ")}`,
    );
  }
  if (
    descriptorCharacters
    > UNIVERSAL_BROKER_BUDGETS.maximumToolDescriptorCharacters
  ) {
    failures.push(
      `tool descriptors use ${descriptorCharacters} characters, limit ${UNIVERSAL_BROKER_BUDGETS.maximumToolDescriptorCharacters}`,
    );
  }
  if (
    instructionCharacters
    > UNIVERSAL_BROKER_BUDGETS.maximumServerInstructionCharacters
  ) {
    failures.push(
      `server instructions use ${instructionCharacters} characters, limit ${UNIVERSAL_BROKER_BUDGETS.maximumServerInstructionCharacters}`,
    );
  }

  return {
    toolCount: tools.length,
    toolNames,
    descriptorCharacters,
    instructionCharacters,
    perToolDescriptorCharacters,
    passed: failures.length === 0,
    failures,
  };
}
