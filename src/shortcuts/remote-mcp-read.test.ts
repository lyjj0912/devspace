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
  const client = {
    callTool,
    onclose: undefined as (() => void) | undefined,
    close: async () => {
      closed.count += 1;
      client.onclose?.();
    },
  };
  return {
    client: client as never,
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
  assert.equal(first.livenessVerified, true);
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
  assert.equal(result.livenessVerified, true);
  assert.equal(result.recoveryReason, "mcp_connection_closed");
  await reader.close();
});

test("remote MCP shortcut reconnects after SDK bare Not connected error", async () => {
  let factoryCalls = 0;
  const reader = new RemoteMcpReader({ jira: route }, async () => {
    factoryCalls += 1;
    const attempt = factoryCalls;
    return fakeSession(async () => {
      if (attempt === 1) throw new Error("Not connected");
      return { content: [{ type: "text", text: "recovered" }], isError: false };
    }, { count: 0 });
  });

  const result = await reader.invoke("jira", "getJiraIssue", { issueIdOrKey: "A-1" });

  assert.equal(result.retried, true);
  assert.equal(result.providerCalls, 2);
  assert.equal(factoryCalls, 2);
  assert.equal(result.recoveryReason, "sdk_not_connected");
  await reader.close();
});

test("remote MCP shortcut list_tools is explicitly capability-only, not a liveness check", async () => {
  const reader = new RemoteMcpReader({ jira: route }, async () =>
    fakeSession(async () => ({ content: [], isError: false }), { count: 0 }));

  const result = await reader.invoke("jira");

  assert.equal(result.providerCalls, 0);
  assert.equal(result.livenessVerified, false);
  assert.deepEqual(result.availableTools, route.allowedTools);
  await reader.close();
});

test("remote MCP shortcut shares one replacement session across concurrent disconnects", async () => {
  let factoryCalls = 0;
  let firstCalls = 0;
  let releaseFirstCalls: (() => void) | undefined;
  const firstCallsReady = new Promise<void>((resolve) => {
    releaseFirstCalls = resolve;
  });
  const reader = new RemoteMcpReader({ jira: route }, async () => {
    factoryCalls += 1;
    const attempt = factoryCalls;
    return fakeSession(async () => {
      if (attempt === 1) {
        firstCalls += 1;
        if (firstCalls === 2) releaseFirstCalls?.();
        await firstCallsReady;
        throw new Error("Not connected");
      }
      return { content: [{ type: "text", text: "recovered" }], isError: false };
    }, { count: 0 });
  });

  const results = await Promise.all([
    reader.invoke("jira", "getJiraIssue", { issueIdOrKey: "A-1" }),
    reader.invoke("jira", "getJiraIssue", { issueIdOrKey: "A-2" }),
  ]);

  assert.equal(factoryCalls, 2);
  assert.deepEqual(results.map((result) => result.retried), [true, true]);
  await reader.close();
});

test("remote MCP shortcut ignores a stale generation close after replacement", async () => {
  let factoryCalls = 0;
  const sessions: RemoteMcpSession[] = [];
  const reader = new RemoteMcpReader({ jira: route }, async () => {
    factoryCalls += 1;
    const session = fakeSession(async () => ({
      content: [{ type: "text", text: "ok" }],
      isError: false,
    }), { count: 0 });
    sessions.push(session);
    return session;
  });

  await reader.invoke("jira", "getJiraIssue", { issueIdOrKey: "A-1" });
  const staleOnClose = sessions[0].client.onclose;
  sessions[0].client.onclose?.();
  await reader.invoke("jira", "getJiraIssue", { issueIdOrKey: "A-2" });
  assert.equal(factoryCalls, 2);

  staleOnClose?.();
  await reader.invoke("jira", "getJiraIssue", { issueIdOrKey: "A-3" });
  assert.equal(factoryCalls, 2);
  const listing = await reader.invoke("jira");
  assert.equal(listing.lastDisconnectReason, undefined);
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
