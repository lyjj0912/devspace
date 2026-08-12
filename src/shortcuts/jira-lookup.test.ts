import assert from "node:assert/strict";
import test from "node:test";
import { JiraLookupService } from "./jira-lookup.js";
import type { RemoteMcpReadResult } from "./remote-mcp-read.js";

function mcpJson(value: unknown, retried = false): RemoteMcpReadResult {
  return {
    route: "company-jira",
    availableTools: ["searchJiraIssuesUsingJql", "getJiraIssue"],
    providerCalls: 1,
    connectionReused: true,
    retried,
    response: { content: [{ type: "text", text: JSON.stringify(value) }], isError: false },
  };
}

test("Jira shortcut searches and fetches one unique detail", async () => {
  const calls: string[] = [];
  const responses = [
    mcpJson({ issues: [{ key: "OMNIBESU-547", fields: { summary: "search" } }] }),
    mcpJson({
      key: "OMNIBESU-547",
      fields: { summary: "detail", status: { name: "진행중" }, description: "details" },
    }, true),
  ];
  const service = new JiraLookupService("company-jira", {
    invoke: async (_route, tool) => {
      calls.push(tool ?? "");
      return responses.shift()!;
    },
  });
  const result = await service.lookup({
    jql: "key = OMNIBESU-547",
    fields: ["summary", "status", "description"],
  });
  assert.deepEqual(calls, ["searchJiraIssuesUsingJql", "getJiraIssue"]);
  assert.equal(result.issues[0]?.summary, "detail");
  assert.equal(result.issues[0]?.description, "details");
  assert.equal(result.retried, true);
});

test("Jira shortcut direct lookup calls once and multiple search results do not fan out", async () => {
  let directCalls = 0;
  const direct = new JiraLookupService("company-jira", {
    invoke: async () => {
      directCalls += 1;
      return mcpJson({
        key: "A-1",
        fields: { summary: "One", description: "unrequested" },
      });
    },
  });
  const directResult = await direct.lookup({ issueKey: "A-1" });
  assert.equal(directCalls, 1);
  assert.equal(directResult.issues[0]?.description, undefined);

  let searchCalls = 0;
  const multiple = new JiraLookupService("company-jira", {
    invoke: async () => {
      searchCalls += 1;
      return mcpJson({ issues: [{ key: "A-1", fields: {} }, { key: "A-2", fields: {} }] });
    },
  });
  assert.equal((await multiple.lookup({ jql: "project = A" })).issues.length, 2);
  assert.equal(searchCalls, 1);
});

test("Jira shortcut requires exactly one selector", async () => {
  const service = new JiraLookupService("company-jira", {
    invoke: async () => { throw new Error("should not call"); },
  });
  await assert.rejects(service.lookup({}), /exactly one of jql or issueKey/);
  await assert.rejects(service.lookup({ jql: "A", issueKey: "A-1" }), /exactly one/);
});

test("Jira shortcut returns bounded compact requested fields", async () => {
  const service = new JiraLookupService("company-jira", {
    invoke: async () => mcpJson({
      key: "A-1",
      fields: {
        summary: "One",
        description: "x".repeat(25_000),
        customfield_1: { value: "bounded" },
      },
    }),
  });
  const result = await service.lookup({
    issueKey: "A-1",
    fields: ["summary", "description", "customfield_1"],
  });
  assert.equal(result.issues[0]?.description?.length, 20_001);
  assert.equal(result.truncated, true);
  assert.deepEqual(Object.keys(result).sort(), [
    "connectionReused",
    "issues",
    "mode",
    "providerCalls",
    "retried",
    "route",
    "truncated",
  ]);
});
