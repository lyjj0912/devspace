import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import * as z from "zod/v4";

export function createFixtureMcpServer(): McpServer {
  const state = new Map<string, string>();
  const server = new McpServer({
    name: "devspace-universal-broker-v2-fixture",
    version: "1.0.0",
  });

  server.registerTool(
    "read_value",
    {
      title: "Read fixture value",
      description: "Read one value from fixture state.",
      inputSchema: { key: z.string() },
      annotations: { readOnlyHint: true, destructiveHint: false },
    },
    async ({ key }) => ({
      content: [{ type: "text", text: state.get(key) ?? "" }],
      structuredContent: { key, value: state.get(key) ?? null },
    }),
  );

  server.registerTool(
    "write_value",
    {
      title: "Write fixture value",
      description: "Mutate fixture state through the generic MCP proxy.",
      inputSchema: { key: z.string(), value: z.string() },
      annotations: { readOnlyHint: false, destructiveHint: false },
    },
    async ({ key, value }) => {
      state.set(key, value);
      return {
        content: [{ type: "text", text: `stored:${key}` }],
        structuredContent: { key, value, stored: true },
      };
    },
  );

  server.registerTool(
    "delete_value",
    {
      title: "Delete fixture value",
      description: "Destructively delete fixture state.",
      inputSchema: { key: z.string() },
      annotations: { readOnlyHint: false, destructiveHint: true },
    },
    async ({ key }) => ({
      content: [{ type: "text", text: `deleted:${key}:${state.delete(key)}` }],
    }),
  );

  server.registerTool(
    "large_result",
    {
      title: "Large fixture result",
      description: "Return a result large enough to require resource-backed paging.",
      inputSchema: { characters: z.number().int().min(1).max(100_000) },
      annotations: { readOnlyHint: true, destructiveHint: false },
    },
    async ({ characters }) => ({
      content: [{ type: "text", text: "x".repeat(characters) }],
      structuredContent: { payload: "x".repeat(characters) },
    }),
  );

  server.registerTool(
    "provider_error",
    {
      title: "Provider error",
      description: "Return a provider-declared tool error.",
      inputSchema: {},
      annotations: { readOnlyHint: false, destructiveHint: true },
    },
    async () => ({
      content: [{ type: "text", text: "fixture provider rejected the call" }],
      isError: true,
    }),
  );

  server.registerResource(
    "fixture-state",
    "fixture://state",
    { title: "Fixture state", mimeType: "application/json" },
    async (uri) => ({
      contents: [{
        uri: uri.href,
        mimeType: "application/json",
        text: JSON.stringify(Object.fromEntries(state), null, 2),
      }],
    }),
  );

  server.registerPrompt(
    "fixture_prompt",
    {
      title: "Fixture prompt",
      description: "Return a deterministic fixture prompt.",
      argsSchema: { subject: z.string().optional() },
    },
    ({ subject }) => ({
      messages: [{
        role: "user",
        content: { type: "text", text: `Inspect ${subject ?? "fixture"}.` },
      }],
    }),
  );

  return server;
}
