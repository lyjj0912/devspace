import assert from "node:assert/strict";
import test from "node:test";
import { ErrorCode, McpError } from "@modelcontextprotocol/sdk/types.js";
import type { RemoteMcpShortcutRouteConfig } from "./config.js";
import {
  buildSshRemoteCommand,
  isReadOnlyRemoteToolDefinition,
  RemoteMcpReader,
  type RemoteMcpSession,
} from "./remote-mcp-read.js";

const route: RemoteMcpShortcutRouteConfig = {
  transport: "ssh-stdio",
  host: "company",
  command: "/Users/example/.nvm/node",
  args: ["/Volumes/extStorage/atlassian-oauth-mcp.js", "value with spaces"],
  env: { PATH: "/usr/local/bin:/usr/bin:/bin", LABEL: "team's jira" },
  allowedTools: ["searchJiraIssuesUsingJql", "getJiraIssue"],
  toolDefaults: { getJiraIssue: { cloudId: "example.atlassian.net" } },
  startupTimeoutSeconds: 45,
  callTimeoutSeconds: 60,
};

test("remote MCP shortcut shell-quotes route-owned command data", () => {
  const command = buildSshRemoteCommand(route);
  assert.match(command, /^'env' /);
  assert.match(command, /'LABEL=team'"'"'s jira'/);
  assert.match(command, /'value with spaces'$/);
});

test("remote MCP shortcut requires explicit read-only annotations", () => {
  assert.equal(isReadOnlyRemoteToolDefinition({
    annotations: { readOnlyHint: true, destructiveHint: false },
  }), true);
  assert.equal(isReadOnlyRemoteToolDefinition({
    annotations: { readOnlyHint: true, destructiveHint: true },
  }), false);
  assert.equal(isReadOnlyRemoteToolDefinition({}), false);
});

function fakeSession(
  callTool: (input: unknown) => Promise<unknown>,
  closed: { count: number },
): RemoteMcpSession {
  return {
    client: {
      callTool,
      close: async () => { closed.count += 1; },
    } as never,
    transport: {
      close: async () => { closed.count += 1; },
    } as never,
    toolNames: new Set(route.allowedTools),
  };
}

test("remote MCP shortcut reuses a route session and merges defaults", async () => {
  let factoryCalls = 0;
  const inputs: unknown[] = [];
  const closed = { count: 0 };
  const reader = new RemoteMcpReader({ jira: route }, async () => {
    factoryCalls += 1;
    return fakeSession(async (input) => {
      inputs.push(input);
      return { content: [{ type: "text", text: "ok" }], isError: false };
    }, closed);
  });
  const first = await reader.invoke("jira", "getJiraIssue", { issueIdOrKey: "A-1" });
  const second = await reader.invoke("jira", "getJiraIssue", {
    issueIdOrKey: "A-2",
    cloudId: "override",
  });
  assert.equal(factoryCalls, 1);
  assert.equal(first.connectionReused, false);
  assert.equal(second.connectionReused, true);
  assert.deepEqual((inputs[1] as { arguments: unknown }).arguments, {
    cloudId: "override",
    issueIdOrKey: "A-2",
  });
  await reader.close();
  await reader.close();
  assert.equal(closed.count, 2);
});

test("remote MCP shortcut treats provider isError as terminal", async () => {
  let factoryCalls = 0;
  const reader = new RemoteMcpReader({ jira: route }, async () => {
    factoryCalls += 1;
    return fakeSession(async () => ({
      content: [{ type: "text", text: "provider rejected read" }],
      isError: true,
    }), { count: 0 });
  });
  await assert.rejects(
    reader.invoke("jira", "getJiraIssue", { issueIdOrKey: "A-1" }),
    /returned isError/,
  );
  assert.equal(factoryCalls, 1);
  await reader.close();
});

test("remote MCP shortcut reconnects exactly once after transport failure", async () => {
  let factoryCalls = 0;
  const reader = new RemoteMcpReader({ jira: route }, async () => {
    factoryCalls += 1;
    const attempt = factoryCalls;
    return fakeSession(async () => {
      if (attempt === 1) throw new McpError(ErrorCode.ConnectionClosed, "transport closed");
      return { content: [{ type: "text", text: "recovered" }], isError: false };
    }, { count: 0 });
  });
  const result = await reader.invoke("jira", "getJiraIssue", { issueIdOrKey: "A-1" });
  assert.equal(result.retried, true);
  assert.equal(result.providerCalls, 2);
  assert.equal(factoryCalls, 2);
  await reader.close();
});

test("remote MCP shortcut does not retry provider JSON-RPC errors", async () => {
  let factoryCalls = 0;
  let toolCalls = 0;
  const reader = new RemoteMcpReader({ jira: route }, async () => {
    factoryCalls += 1;
    return fakeSession(async () => {
      toolCalls += 1;
      throw new McpError(ErrorCode.InvalidParams, "provider validation failed");
    }, { count: 0 });
  });
  await assert.rejects(
    reader.invoke("jira", "getJiraIssue", { issueIdOrKey: "A-1" }),
    /provider validation failed/,
  );
  assert.equal(factoryCalls, 1);
  assert.equal(toolCalls, 1);
  await reader.close();
});
