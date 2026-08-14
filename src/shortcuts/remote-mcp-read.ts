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
  livenessVerified: boolean;
  recoveryReason?: string;
  lastDisconnectReason?: string;
}

export class RemoteMcpReadError extends Error {
  constructor(message: string, readonly code = "REMOTE_MCP_READ_FAILED") {
    super(message);
    this.name = "RemoteMcpReadError";
  }
}

export class RemoteMcpReader {
  private readonly sessions = new Map<string, {
    generation: number;
    session: Promise<RemoteMcpSession>;
  }>();
  private closePromise?: Promise<void>;
  private nextGeneration = 1;
  private readonly lastDisconnectReasons = new Map<string, string>();

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
        livenessVerified: false,
        ...(this.lastDisconnectReasons.get(routeName)
          ? { lastDisconnectReason: this.lastDisconnectReasons.get(routeName) }
          : {}),
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
      this.lastDisconnectReasons.delete(routeName);
      return {
        route: routeName,
        availableTools: exposedTools(route, session),
        tool: toolName,
        response,
        providerCalls: 1,
        connectionReused: initial.reused,
        retried: false,
        livenessVerified: true,
      };
    } catch (error) {
      if (!isTransportFailure(error)) throw error;
      const recoveryReason = transportFailureReason(error);
      this.lastDisconnectReasons.set(routeName, recoveryReason);
      await this.reset(routeName, initial.generation);
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
        this.lastDisconnectReasons.delete(routeName);
        return {
          route: routeName,
          availableTools: exposedTools(route, session),
          tool: toolName,
          response,
          providerCalls: 2,
          connectionReused: initial.reused,
          retried: true,
          livenessVerified: true,
          recoveryReason,
        };
      } catch (retryError) {
        if (isTransportFailure(retryError)) {
          this.lastDisconnectReasons.set(routeName, transportFailureReason(retryError));
          await this.reset(routeName, retry.generation);
        }
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
      await Promise.allSettled(sessions.map(async (entry) => {
        const session = await entry.session.catch(() => undefined);
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

  private session(name: string): {
    session: Promise<RemoteMcpSession>;
    reused: boolean;
    generation: number;
  } {
    const existing = this.sessions.get(name);
    if (existing) {
      return {
        session: existing.session,
        reused: true,
        generation: existing.generation,
      };
    }

    const generation = this.nextGeneration++;
    const pending = (this.sessionFactory ? this.sessionFactory(name) : this.connect(name))
      .then((session) => {
        this.attachDisconnectEviction(name, generation, session);
        return session;
      })
      .catch((error) => {
        this.evictGeneration(name, generation);
        throw error;
      });
    this.sessions.set(name, { generation, session: pending });
    return { session: pending, reused: false, generation };
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

  private async reset(name: string, generation: number): Promise<void> {
    const entry = this.sessions.get(name);
    if (!entry || entry.generation !== generation) return;
    this.sessions.delete(name);
    const session = await entry.session.catch(() => undefined);
    await session?.client.close().catch(() => undefined);
    await session?.transport.close().catch(() => undefined);
  }

  private attachDisconnectEviction(
    name: string,
    generation: number,
    session: RemoteMcpSession,
  ): void {
    const previousOnClose = session.client.onclose;
    session.client.onclose = () => {
      previousOnClose?.();
      if (this.sessions.get(name)?.generation !== generation) return;
      if (!this.lastDisconnectReasons.has(name)) {
        this.lastDisconnectReasons.set(name, "transport_closed");
      }
      this.evictGeneration(name, generation);
    };
  }

  private evictGeneration(name: string, generation: number): void {
    const entry = this.sessions.get(name);
    if (entry?.generation === generation) this.sessions.delete(name);
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
class RemoteMcpTransportError extends RemoteMcpReadError {
  constructor(message: string, readonly reason = "transport_error") {
    super(message);
  }
}

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
    if (
      isMcpTransportFailure(error)
      || isMcpDisconnectedError(error)
      || isNodeTransportFailure(error)
    ) {
      throw new RemoteMcpTransportError(errorMessage(error), rawTransportFailureReason(error));
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

function transportFailureReason(error: unknown): string {
  return error instanceof RemoteMcpTransportError ? error.reason : "transport_error";
}

function rawTransportFailureReason(error: unknown): string {
  if (error instanceof McpError) {
    if (error.code === ErrorCode.ConnectionClosed) return "mcp_connection_closed";
    if (error.code === ErrorCode.RequestTimeout) return "mcp_request_timeout";
  }
  if (isMcpDisconnectedError(error)) return "sdk_not_connected";
  if (typeof error === "object" && error !== null && "code" in error) {
    const code = String((error as { code: unknown }).code).toLowerCase();
    if (["epipe", "econnreset", "econnrefused", "etimedout"].includes(code)) {
      return `node_${code}`;
    }
  }
  return "transport_error";
}

function isMcpTransportFailure(error: unknown): boolean {
  return error instanceof McpError
    && (error.code === ErrorCode.ConnectionClosed || error.code === ErrorCode.RequestTimeout);
}

function isMcpDisconnectedError(error: unknown): boolean {
  return error instanceof Error && error.message === "Not connected";
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
