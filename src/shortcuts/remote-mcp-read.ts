import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
import { ErrorCode, McpError } from "@modelcontextprotocol/sdk/types.js";
import type { RemoteMcpShortcutRouteConfig } from "./config.js";
import { isReadOnlyRemoteToolName } from "./config.js";

export interface RemoteMcpSession {
  client: Client;
  transport: StdioClientTransport;
  toolNames: Set<string>;
}

export type RemoteMcpSessionFactory = (routeName: string) => Promise<RemoteMcpSession>;

export interface RemoteMcpReadResult {
  route: string;
  availableTools: string[];
  tool?: string;
  response?: unknown;
  providerCalls: number;
  connectionReused: boolean;
  retried: boolean;
}

export class RemoteMcpReadError extends Error {
  constructor(message: string, readonly code = "REMOTE_MCP_READ_FAILED") {
    super(message);
    this.name = "RemoteMcpReadError";
  }
}

export class RemoteMcpReader {
  private readonly sessions = new Map<string, Promise<RemoteMcpSession>>();
  private closePromise?: Promise<void>;

  constructor(
    private readonly routes: Record<string, RemoteMcpShortcutRouteConfig>,
    private readonly sessionFactory?: RemoteMcpSessionFactory,
  ) {}

  routeNames(): string[] {
    return Object.keys(this.routes).sort();
  }

  async invoke(
    routeName: string,
    toolName?: string,
    args: Record<string, unknown> = {},
  ): Promise<RemoteMcpReadResult> {
    const route = this.route(routeName);
    this.assertAllowedTool(routeName, route, toolName);

    const initial = this.session(routeName);
    let session = await initial.session;
    if (!toolName) {
      return {
        route: routeName,
        availableTools: exposedTools(route, session),
        providerCalls: 0,
        connectionReused: initial.reused,
        retried: false,
      };
    }
    this.assertExposed(routeName, toolName, session);
    const toolArguments = { ...(route.toolDefaults[toolName] ?? {}), ...args };

    try {
      const response = requireSuccessfulToolResult(await callRemoteTool(
        session,
        routeName,
        toolName,
        toolArguments,
        route.callTimeoutSeconds,
      ), routeName, toolName);
      return {
        route: routeName,
        availableTools: exposedTools(route, session),
        tool: toolName,
        response,
        providerCalls: 1,
        connectionReused: initial.reused,
        retried: false,
      };
    } catch (error) {
      if (!isTransportFailure(error)) throw error;
      await this.reset(routeName);
      const retry = this.session(routeName);
      session = await retry.session;
      this.assertExposed(routeName, toolName, session);
      try {
        const response = requireSuccessfulToolResult(await callRemoteTool(
          session,
          routeName,
          toolName,
          toolArguments,
          route.callTimeoutSeconds,
        ), routeName, toolName);
        return {
          route: routeName,
          availableTools: exposedTools(route, session),
          tool: toolName,
          response,
          providerCalls: 2,
          connectionReused: initial.reused,
          retried: true,
        };
      } catch (retryError) {
        if (isTransportFailure(retryError)) await this.reset(routeName);
        throw new RemoteMcpReadError(
          `Remote MCP route ${routeName} failed before and after one reconnect: ${errorMessage(error)}; retry: ${errorMessage(retryError)}`,
        );
      }
    }
  }

  close(): Promise<void> {
    this.closePromise ??= (async () => {
      const sessions = [...this.sessions.values()];
      this.sessions.clear();
      await Promise.allSettled(sessions.map(async (pending) => {
        const session = await pending.catch(() => undefined);
        await session?.client.close().catch(() => undefined);
        await session?.transport.close().catch(() => undefined);
      }));
    })();
    return this.closePromise;
  }

  private route(name: string): RemoteMcpShortcutRouteConfig {
    const route = this.routes[name];
    if (route) return route;
    const available = this.routeNames();
    throw new RemoteMcpReadError(
      available.length > 0
        ? `Unknown shortcut remote MCP route ${name}. Available routes: ${available.join(", ")}.`
        : "No shortcut remote MCP routes are configured.",
      "REMOTE_MCP_ROUTE_NOT_FOUND",
    );
  }

  private session(name: string): { session: Promise<RemoteMcpSession>; reused: boolean } {
    const existing = this.sessions.get(name);
    if (existing) return { session: existing, reused: true };
    const pending = (this.sessionFactory ? this.sessionFactory(name) : this.connect(name)).catch((error) => {
      this.sessions.delete(name);
      throw error;
    });
    this.sessions.set(name, pending);
    return { session: pending, reused: false };
  }

  private async connect(name: string): Promise<RemoteMcpSession> {
    const route = this.route(name);
    const transport = new StdioClientTransport({
      command: "ssh",
      args: [route.host, buildSshRemoteCommand(route)],
      stderr: "ignore",
    });
    const client = new Client({ name: `devspace-shortcut-${name}`, version: "1.0.0" });
    try {
      await withTimeout(
        client.connect(transport),
        route.startupTimeoutSeconds * 1_000,
        `Remote MCP route ${name} startup`,
      );
      const listed = await withTimeout(
        client.listTools(),
        route.startupTimeoutSeconds * 1_000,
        `Remote MCP route ${name} tools/list`,
      );
      for (const tool of listed.tools) {
        if (!route.allowedTools.includes(tool.name)) continue;
        if (!isReadOnlyRemoteToolDefinition(tool)) {
          throw new RemoteMcpReadError(
            `Remote MCP route ${name} tool ${tool.name} is not explicitly read-only and non-destructive.`,
            "REMOTE_MCP_TOOL_NOT_READ_ONLY",
          );
        }
      }
      return { client, transport, toolNames: new Set(listed.tools.map((tool) => tool.name)) };
    } catch (error) {
      await client.close().catch(() => undefined);
      await transport.close().catch(() => undefined);
      if (error instanceof RemoteMcpReadError) throw error;
      throw new RemoteMcpReadError(`Unable to connect remote MCP route ${name}: ${errorMessage(error)}`);
    }
  }

  private async reset(name: string): Promise<void> {
    const pending = this.sessions.get(name);
    this.sessions.delete(name);
    if (!pending) return;
    const session = await pending.catch(() => undefined);
    await session?.client.close().catch(() => undefined);
    await session?.transport.close().catch(() => undefined);
  }

  private assertAllowedTool(
    routeName: string,
    route: RemoteMcpShortcutRouteConfig,
    toolName?: string,
  ): void {
    if (!toolName) return;
    if (!route.allowedTools.includes(toolName)) {
      throw new RemoteMcpReadError(
        `Remote MCP route ${routeName} does not allow tool ${toolName}.`,
        "REMOTE_MCP_TOOL_NOT_ALLOWED",
      );
    }
    if (!isReadOnlyRemoteToolName(toolName)) {
      throw new RemoteMcpReadError(
        `Remote MCP read shortcuts reject mutation-shaped tool names: ${toolName}.`,
        "REMOTE_MCP_TOOL_NOT_READ_ONLY",
      );
    }
  }

  private assertExposed(route: string, tool: string, session: RemoteMcpSession): void {
    if (!session.toolNames.has(tool)) {
      throw new RemoteMcpReadError(
        `Remote MCP route ${route} did not expose configured tool ${tool}.`,
        "REMOTE_MCP_TOOL_NOT_EXPOSED",
      );
    }
  }
}

class RemoteMcpToolResultError extends RemoteMcpReadError {}
class RemoteMcpTransportError extends RemoteMcpReadError {}

export function isReadOnlyRemoteToolDefinition(tool: {
  annotations?: { readOnlyHint?: boolean; destructiveHint?: boolean };
}): boolean {
  return tool.annotations?.readOnlyHint === true && tool.annotations?.destructiveHint !== true;
}

export function buildSshRemoteCommand(route: RemoteMcpShortcutRouteConfig): string {
  return [
    "env",
    ...Object.entries(route.env).map(([key, value]) => `${key}=${value}`),
    route.command,
    ...route.args,
  ].map(shellQuote).join(" ");
}

export function remoteToolText(response: unknown, maxCharacters = 100_000): {
  text: string;
  truncated: boolean;
} {
  const content = typeof response === "object" && response !== null
    ? (response as { content?: unknown }).content
    : undefined;
  const fullText = Array.isArray(content)
    ? content.map((entry) => {
        if (typeof entry !== "object" || entry === null) return "";
        const record = entry as { type?: unknown; text?: unknown };
        return record.type === "text" && typeof record.text === "string" ? record.text : "";
      }).filter(Boolean).join("\n")
    : "";
  const limit = Math.min(Math.max(Math.trunc(maxCharacters), 1), 100_000);
  return { text: fullText.slice(0, limit), truncated: fullText.length > limit };
}

function exposedTools(route: RemoteMcpShortcutRouteConfig, session: RemoteMcpSession): string[] {
  return route.allowedTools.filter((tool) => session.toolNames.has(tool));
}

async function callRemoteTool(
  session: RemoteMcpSession,
  route: string,
  tool: string,
  args: Record<string, unknown>,
  timeoutSeconds: number,
): Promise<unknown> {
  try {
    return await withTimeout(
      session.client.callTool({ name: tool, arguments: args }),
      timeoutSeconds * 1_000,
      `Remote MCP tool ${route}/${tool}`,
    );
  } catch (error) {
    if (error instanceof RemoteMcpReadError) throw error;
    if (isMcpTransportFailure(error) || isNodeTransportFailure(error)) {
      throw new RemoteMcpTransportError(errorMessage(error));
    }
    throw error;
  }
}

function requireSuccessfulToolResult<T>(response: T, route: string, tool: string): T {
  if (typeof response !== "object" || response === null || (response as { isError?: boolean }).isError !== true) {
    return response;
  }
  throw new RemoteMcpToolResultError(
    `Remote MCP tool ${route}/${tool} returned isError.`,
    "REMOTE_MCP_TOOL_ERROR",
  );
}

async function withTimeout<T>(promise: Promise<T>, timeoutMs: number, label: string): Promise<T> {
  let timer: NodeJS.Timeout | undefined;
  try {
    return await Promise.race([
      promise,
      new Promise<never>((_, reject) => {
        timer = setTimeout(
          () => reject(new RemoteMcpTransportError(`${label} timed out after ${timeoutMs}ms.`)),
          timeoutMs,
        );
      }),
    ]);
  } finally {
    if (timer) clearTimeout(timer);
  }
}

function isTransportFailure(error: unknown): boolean {
  return error instanceof RemoteMcpTransportError;
}

function isMcpTransportFailure(error: unknown): boolean {
  return error instanceof McpError
    && (error.code === ErrorCode.ConnectionClosed || error.code === ErrorCode.RequestTimeout);
}

function isNodeTransportFailure(error: unknown): boolean {
  if (typeof error !== "object" || error === null || !("code" in error)) return false;
  return new Set(["EPIPE", "ECONNRESET", "ECONNREFUSED", "ETIMEDOUT"])
    .has(String((error as { code: unknown }).code));
}

function shellQuote(value: string): string {
  return `'${value.replaceAll("'", `'"'"'`)}'`;
}

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}
