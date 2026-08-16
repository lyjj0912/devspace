import assert from "node:assert/strict";
import test from "node:test";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import {
  assertUniversalBrokerBudgets,
  inspectUniversalBrokerBudgets,
} from "./budgets.js";
import {
  UNIVERSAL_TOOL_NAMES,
  type UniversalToolName,
} from "./contracts.js";
import { createUniversalBrokerMcpServer } from "./server.js";

test("Universal Broker v2 exposes exactly the fixed eight-tool surface within budget", async () => {
  const report = await inspectUniversalBrokerBudgets();
  assertUniversalBrokerBudgets(report);
  assert.deepEqual(report.toolNames, [...UNIVERSAL_TOOL_NAMES]);
});

test("tools without an injected implementation fail explicitly without changing the registered schema", async () => {
  const server = createUniversalBrokerMcpServer();
  const client = new Client({ name: "v2-skeleton-test", version: "1.0.0" });
  const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
  await Promise.all([
    client.connect(clientTransport),
    server.connect(serverTransport),
  ]);

  try {
    for (const name of UNIVERSAL_TOOL_NAMES) {
      const result = await client.callTool({
        name,
        arguments: minimalArguments(name),
      });
      const structured = result.structuredContent as {
        ok?: unknown;
        error?: unknown;
      } | undefined;
      assert.equal(result.isError, true, name);
      assert.equal(structured?.ok, false, name);
      const error = structured?.error;
      assert.equal(typeof error, "object", name);
      assert.equal(
        (error as { code?: unknown }).code,
        "CAPABILITY_UNAVAILABLE",
        name,
      );
    }
  } finally {
    await Promise.allSettled([client.close(), server.close()]);
  }
});

function minimalArguments(name: UniversalToolName): Record<string, unknown> {
  switch (name) {
    case "target":
      return { operation: "list" };
    case "context":
      return { operation: "search", query: "release" };
    case "fs":
      return { operation: "stat", path: "/tmp" };
    case "exec":
      return { command: "true" };
    case "process":
      return { operation: "list" };
    case "mcp":
      return { operation: "routes" };
    case "artifact":
      return { operation: "publish", source: {} };
    case "gui":
      return { operation: "capabilities" };
  }
}
