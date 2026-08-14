import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { registerAppTool } from "@modelcontextprotocol/ext-apps/server";
import * as z from "zod/v4";
import type { LoggingConfig } from "../logger.js";
import { logEvent } from "../logger.js";
import type { BrowserReadResult } from "./browser-read.js";
import type { JiraIssueSummary, JiraLookupResult } from "./jira-lookup.js";
import { remoteToolText, type RemoteMcpReadResult } from "./remote-mcp-read.js";
import type { ShortcutRuntime } from "./runtime.js";

export const shortcutToolNames = {
  browserRead: "browser_read_shortcut",
  remoteMcpRead: "remote_mcp_read_shortcut",
  jiraLookup: "jira_lookup_shortcut",
} as const;

const NO_WIDGET_META = { _meta: {} };
const READ_ONLY_ANNOTATIONS = {
  readOnlyHint: true,
  destructiveHint: false,
  idempotentHint: true,
  openWorldHint: true,
};
const BROWSER_ANNOTATIONS = {
  readOnlyHint: false,
  destructiveHint: false,
  idempotentHint: false,
  openWorldHint: true,
};

export interface ShortcutToolRegistrationOptions {
  runtime: ShortcutRuntime;
  logging: LoggingConfig;
}

export function registerShortcutTools(
  server: McpServer,
  options: ShortcutToolRegistrationOptions,
): void {
  const { runtime, logging } = options;
  if (runtime.config.browserRead.enabled) registerBrowserRead(server, runtime, logging);
  if (runtime.config.remoteMcpRead.enabled) registerRemoteMcpRead(server, runtime, logging);
  if (runtime.config.jiraLookup.enabled) registerJiraLookup(server, runtime, logging);
}

function registerBrowserRead(
  server: McpServer,
  runtime: ShortcutRuntime,
  logging: LoggingConfig,
): void {
  registerAppTool(
    server,
    shortcutToolNames.browserRead,
    {
      title: "Read Chrome pages (personal shortcut)",
      description:
        "Personal DevSpace shortcut for listing Chrome tabs, opening one HTTP(S) URL, and reading bounded page text. It cannot click, type, submit, upload, download, or accept model-supplied JavaScript. open_url changes browser navigation state.",
      inputSchema: {
        operation: z.enum(["list_tabs", "read_page", "open_url"]),
        windowIndex: z.number().int().positive().optional(),
        tabIndex: z.number().int().positive().optional(),
        url: z.string().url().optional(),
        selector: z.string().min(1).optional(),
        maxCharacters: z.number().int().min(1).max(100_000).optional(),
        matchText: z.string().min(1).optional(),
        waitMs: z.number().int().min(0).max(5_000).optional(),
      },
      outputSchema: shortcutOutputSchema(),
      ...NO_WIDGET_META,
      annotations: BROWSER_ANNOTATIONS,
    },
    async (input) => executeShortcut(
      logging,
      shortcutToolNames.browserRead,
      { operation: input.operation },
      async () => {
        const data = await runtime.browser.execute(input);
        return {
          data,
          text: browserResultText(data),
          meta: {
            providerCalls: 0,
            connectionReused: false,
            retried: false,
            truncated: data.truncated,
          },
        };
      },
    ),
  );
}

function registerRemoteMcpRead(
  server: McpServer,
  runtime: ShortcutRuntime,
  logging: LoggingConfig,
): void {
  registerAppTool(
    server,
    shortcutToolNames.remoteMcpRead,
    {
      title: "Read a configured remote MCP (personal shortcut)",
      description:
        [
          "Personal DevSpace shortcut for a preconfigured allowlisted remote MCP route.",
          runtime.config.jiraLookup.enabled
            ? "Prefer jira_lookup_shortcut for ordinary Jira issue or JQL reads because it returns compact summaries and requested fields without raw provider payloads. Use this generic route for capability discovery or read operations the compact Jira shortcut cannot express."
            : undefined,
          "list_tools reports approved read tools; call invokes one approved tool. SSH host, command, environment, and credentials are local configuration only. A process-wide route session is reused and transport failures reconnect at most once.",
        ].filter(Boolean).join(" "),
      inputSchema: {
        operation: z.enum(["list_tools", "call"]),
        route: z.string().min(1),
        tool: z.string().min(1).optional(),
        arguments: z.record(z.string(), z.unknown()).optional(),
        maxCharacters: z.number().int().min(1).max(100_000).optional(),
      },
      outputSchema: shortcutOutputSchema(),
      ...NO_WIDGET_META,
      annotations: READ_ONLY_ANNOTATIONS,
    },
    async ({ operation, route, tool, arguments: args, maxCharacters }) => executeShortcut(
      logging,
      shortcutToolNames.remoteMcpRead,
      { operation, route, remoteTool: tool },
      async () => {
        if (operation === "list_tools" && tool !== undefined) {
          throw new ShortcutToolError("list_tools does not accept tool.", "INVALID_SHORTCUT_INPUT");
        }
        if (operation === "call" && !tool) {
          throw new ShortcutToolError("call requires tool.", "INVALID_SHORTCUT_INPUT");
        }
        const result = await runtime.remoteMcp.invoke(
          route,
          operation === "call" ? tool : undefined,
          args ?? {},
        );
        const bounded = remoteToolText(result.response, maxCharacters ?? 10_000);
        const data = remoteResultData(result, bounded.text);
        return {
          data,
          text: remoteResultText(result, bounded.text),
          meta: {
            providerCalls: result.providerCalls,
            connectionReused: result.connectionReused,
            retried: result.retried,
            truncated: bounded.truncated,
            livenessVerified: result.livenessVerified,
            ...(result.recoveryReason ? { recoveryReason: result.recoveryReason } : {}),
          },
        };
      },
    ),
  );
}

function registerJiraLookup(
  server: McpServer,
  runtime: ShortcutRuntime,
  logging: LoggingConfig,
): void {
  registerAppTool(
    server,
    shortcutToolNames.jiraLookup,
    {
      title: "Look up Jira issues (personal shortcut)",
      description:
        "Preferred shortcut for ordinary Jira issue and JQL reads. It returns compact summaries plus explicitly requested fields, avoiding large raw provider payloads. Direct issue lookup calls the provider once. JQL calls search once and fetches detail only for one unique result when requested. It does not fan out or perform Jira mutations.",
      inputSchema: {
        jql: z.string().min(1).optional(),
        issueKey: z.string().min(1).optional(),
        cloudId: z.string().min(1).optional(),
        fields: z.array(z.string().min(1)).optional(),
        maxResults: z.number().int().min(1).max(100).optional(),
        includeDetails: z.boolean().optional(),
      },
      outputSchema: shortcutOutputSchema(),
      ...NO_WIDGET_META,
      annotations: READ_ONLY_ANNOTATIONS,
    },
    async (input) => executeShortcut(
      logging,
      shortcutToolNames.jiraLookup,
      {},
      async () => {
        if (!runtime.jira) {
          throw new ShortcutToolError("Jira shortcut route is not configured.", "JIRA_ROUTE_NOT_CONFIGURED");
        }
        const result = await runtime.jira.lookup(input);
        return {
          data: {
            route: result.route,
            mode: result.mode,
            issues: result.issues,
          },
          text: jiraResultText(result),
          meta: {
            providerCalls: result.providerCalls,
            connectionReused: result.connectionReused,
            retried: result.retried,
            truncated: result.truncated,
          },
        };
      },
    ),
  );
}

interface ShortcutSuccess {
  data: unknown;
  text: string;
  meta: {
    providerCalls: number;
    connectionReused: boolean;
    retried: boolean;
    truncated: boolean;
    livenessVerified?: boolean;
    recoveryReason?: string;
  };
}

async function executeShortcut(
  logging: LoggingConfig,
  shortcut: string,
  logFields: Record<string, unknown>,
  run: () => Promise<ShortcutSuccess>,
): Promise<{
  content: Array<{ type: "text"; text: string }>;
  isError?: boolean;
  structuredContent: Record<string, unknown>;
}> {
  const startedAt = performance.now();
  try {
    const result = await run();
    const durationMs = Math.round(performance.now() - startedAt);
    logEvent(logging, "info", "shortcut_call", {
      shortcut,
      ...logFields,
      durationMs,
      ...result.meta,
    });
    return {
      content: [{ type: "text", text: result.text }],
      structuredContent: {
        result: result.text,
        data: result.data,
        meta: { durationMs, ...result.meta },
      },
    };
  } catch (error) {
    const durationMs = Math.round(performance.now() - startedAt);
    const message = error instanceof Error ? error.message : String(error);
    const code = errorCode(error);
    logEvent(logging, "warn", "shortcut_error", {
      shortcut,
      ...logFields,
      durationMs,
      errorCode: code,
    });
    const text = `ERROR: ${message}`;
    return {
      content: [{ type: "text", text }],
      isError: true,
      structuredContent: {
        result: text,
        error: { code, message },
        meta: {
          durationMs,
          providerCalls: 0,
          connectionReused: false,
          retried: false,
          truncated: false,
        },
      },
    };
  }
}

class ShortcutToolError extends Error {
  constructor(message: string, readonly code: string) {
    super(message);
    this.name = "ShortcutToolError";
  }
}

function shortcutOutputSchema(): z.ZodRawShape {
  return {
    result: z.string(),
    data: z.unknown().optional(),
    error: z.object({ code: z.string(), message: z.string() }).optional(),
    meta: z.object({
      durationMs: z.number(),
      providerCalls: z.number().int().nonnegative(),
      connectionReused: z.boolean(),
      retried: z.boolean(),
      truncated: z.boolean(),
      livenessVerified: z.boolean().optional(),
      recoveryReason: z.string().optional(),
    }),
  };
}

function browserResultText(result: BrowserReadResult): string {
  if (result.operation === "list_tabs") {
    return result.tabs.length === 0
      ? "Google Chrome has no open tabs."
      : result.tabs.map((tab) =>
          `${tab.active ? "*" : "-"} ${tab.windowIndex}:${tab.tabIndex} ${tab.title} | ${tab.url}`
        ).join("\n");
  }
  return [
    `${result.page.title} | ${result.page.url}`,
    result.page.matchedLines
      ? `Matched lines: ${result.page.matchedLines.length}`
      : `Characters: ${result.page.text.length}${result.page.truncated ? " (truncated)" : ""}`,
    result.page.text,
  ].filter(Boolean).join("\n");
}

function remoteResultData(result: RemoteMcpReadResult, content: string): Record<string, unknown> {
  return {
    route: result.route,
    availableTools: result.availableTools,
    livenessVerified: result.livenessVerified,
    ...(result.recoveryReason ? { recoveryReason: result.recoveryReason } : {}),
    ...(result.lastDisconnectReason ? { lastDisconnectReason: result.lastDisconnectReason } : {}),
    ...(result.tool ? { tool: result.tool } : {}),
    ...(content ? { content } : {}),
  };
}

function remoteResultText(result: RemoteMcpReadResult, content: string): string {
  return [
    `Remote MCP route: ${result.route}`,
    `Available read tools: ${result.availableTools.join(", ") || "none"}`,
    result.tool ? `Called: ${result.tool}` : "Route inspection only",
    result.livenessVerified
      ? "Provider liveness verified by this tool call."
      : "Provider liveness not verified; list_tools reports cached/approved capabilities only.",
    result.connectionReused ? "Connection reused." : "Connection opened.",
    result.retried ? "Transport reconnected once." : "No reconnect.",
    result.recoveryReason ? `Recovery reason: ${result.recoveryReason}.` : "",
    result.lastDisconnectReason ? `Last disconnect reason: ${result.lastDisconnectReason}.` : "",
    content,
  ].filter(Boolean).join("\n");
}

function jiraResultText(result: JiraLookupResult): string {
  return [
    `Jira route: ${result.route}`,
    `Mode: ${result.mode}`,
    `Issues: ${result.issues.length}`,
    ...result.issues.map(issueLine),
  ].join("\n");
}

function issueLine(issue: JiraIssueSummary): string {
  return [issue.key ?? issue.id ?? "unknown", issue.status, issue.updated, issue.summary]
    .filter(Boolean)
    .join(" | ");
}

function errorCode(error: unknown): string {
  return typeof error === "object" && error !== null && "code" in error
    ? String((error as { code: unknown }).code)
    : "SHORTCUT_FAILED";
}
