import assert from "node:assert/strict";
import test from "node:test";
import type { RemoteMcpShortcutRouteConfig, ShortcutConfig } from "./config.js";
import { createShortcutRuntime } from "./runtime.js";
import type { RemoteMcpSession } from "./remote-mcp-read.js";

const route: RemoteMcpShortcutRouteConfig = {
  transport: "ssh-stdio",
  host: "company",
  command: "/usr/bin/node",
  args: ["/opt/read-mcp.js"],
  env: {},
  allowedTools: ["getJiraIssue", "searchJiraIssuesUsingJql"],
  toolDefaults: {},
  startupTimeoutSeconds: 45,
  callTimeoutSeconds: 60,
};

const config: ShortcutConfig = {
  browserRead: { enabled: false },
  remoteMcpRead: { enabled: true, routes: { jira: route } },
  jiraLookup: { enabled: true, route: "jira" },
};

test("shortcut runtime reuses one remote route session and closes idempotently", async () => {
  let factoryCalls = 0;
  let closeCalls = 0;
  const runtime = createShortcutRuntime(config, {
    remoteSessionFactory: async (): Promise<RemoteMcpSession> => {
      factoryCalls += 1;
      return {
        client: {
          callTool: async () => ({ content: [{ type: "text", text: "{}" }], isError: false }),
          close: async () => { closeCalls += 1; },
        } as never,
        transport: {
          close: async () => { closeCalls += 1; },
        } as never,
        toolNames: new Set(route.allowedTools),
      };
    },
  });

  await runtime.remoteMcp.invoke("jira", "getJiraIssue", { issueIdOrKey: "A-1" });
  await runtime.remoteMcp.invoke("jira", "getJiraIssue", { issueIdOrKey: "A-2" });
  assert.equal(factoryCalls, 1);
  await Promise.all([runtime.close(), runtime.close()]);
  assert.equal(closeCalls, 2);
});
