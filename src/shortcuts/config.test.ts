import assert from "node:assert/strict";
import test from "node:test";
import { parseShortcutConfig } from "./config.js";

const route = {
  transport: "ssh-stdio" as const,
  host: "company",
  command: "/usr/local/bin/node",
  args: ["/opt/atlassian-oauth-mcp.js"],
  env: { PATH: "/usr/local/bin:/usr/bin:/bin" },
  allowedTools: ["searchJiraIssuesUsingJql", "getJiraIssue"],
  toolDefaults: {
    searchJiraIssuesUsingJql: { cloudId: "example.atlassian.net" },
    getJiraIssue: { cloudId: "example.atlassian.net" },
  },
};

test("shortcut config is disabled by default and normalizes an explicit route", () => {
  assert.deepEqual(parseShortcutConfig(undefined, {}), {
    browserRead: { enabled: false },
    remoteMcpRead: { enabled: false, routes: {} },
    jiraLookup: { enabled: false },
  });

  assert.deepEqual(parseShortcutConfig({
    browserRead: { enabled: true },
    remoteMcpRead: { enabled: true, routes: { "company-jira": route } },
    jiraLookup: { enabled: true, route: "company-jira" },
  }, {}).remoteMcpRead.routes["company-jira"], {
    ...route,
    startupTimeoutSeconds: 45,
    callTimeoutSeconds: 60,
  });
});

test("shortcut environment toggles override file toggles", () => {
  const config = parseShortcutConfig({
    browserRead: { enabled: false },
    remoteMcpRead: { enabled: false, routes: { jira: route } },
    jiraLookup: { enabled: false, route: "jira" },
  }, {
    DEVSPACE_SHORTCUT_BROWSER_READ_ENABLED: "1",
    DEVSPACE_SHORTCUT_REMOTE_MCP_READ_ENABLED: "true",
    DEVSPACE_SHORTCUT_JIRA_LOOKUP_ENABLED: "yes",
  });
  assert.equal(config.browserRead.enabled, true);
  assert.equal(config.remoteMcpRead.enabled, true);
  assert.equal(config.jiraLookup.enabled, true);
  assert.equal(config.jiraLookup.route, "jira");
  assert.throws(
    () => parseShortcutConfig(undefined, { DEVSPACE_SHORTCUT_BROWSER_READ_ENABLED: "maybe" }),
    /Invalid DEVSPACE_SHORTCUT_BROWSER_READ_ENABLED/,
  );
});

test("shortcut config rejects unsafe routes and invalid Jira prerequisites", () => {
  assert.throws(() => parseShortcutConfig({
    remoteMcpRead: {
      enabled: true,
      routes: { bad: { ...route, host: "-oProxyCommand=bad" } },
    },
  }, {}), /unsafe SSH host/);
  assert.throws(() => parseShortcutConfig({
    remoteMcpRead: {
      enabled: true,
      routes: { bad: { ...route, allowedTools: ["createJiraIssue"] } },
    },
  }, {}), /mutation-shaped tool/);
  assert.throws(() => parseShortcutConfig({
    remoteMcpRead: {
      routes: {
        jira: {
          ...route,
          allowedTools: ["getJiraIssue"],
          toolDefaults: { getJiraIssue: route.toolDefaults.getJiraIssue },
        },
      },
    },
    jiraLookup: { enabled: true, route: "jira" },
  }, {}), /must allow searchJiraIssuesUsingJql/);
  assert.throws(() => parseShortcutConfig({
    remoteMcpRead: { enabled: true },
  }, {}), /requires at least one route/);
});
