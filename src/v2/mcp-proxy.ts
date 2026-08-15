import { mkdir } from "node:fs/promises";
import { join } from "node:path";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import {
  getDefaultEnvironment,
  StdioClientTransport,
} from "@modelcontextprotocol/sdk/client/stdio.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";
import { McpError } from "@modelcontextprotocol/sdk/types.js";
import { UniversalBrokerError } from "./errors.js";
import {
  routeSummary,
  type UniversalMcpRoute,
  type UniversalMcpRouteRegistry,
} from "./mcp-routes.js";
import { UniversalMcpResultStore } from "./mcp-result-store.js";
import type { TargetRegistry } from "./targets.js";

export type UniversalMcpOperation =
  | "routes"
  | "search_tools"
  | "describe_tool"
  | "invoke"
  | "list_resources"
  | "read_resource"
  | "list_prompts"
  | "get_prompt"
  | "close";

export interface UniversalMcpInput {
  operation: UniversalMcpOperation;
  route?: string;
  query?: string;
  name?: string;
  arguments?: Record<string, unknown>;
  uri?: string;
  cursor?: string;
  limit?: number;
  responsePolicy?: Record<string, unknown>;
}

type DownstreamTransport = StdioClientTransport | StreamableHTTPClientTransport;

export interface DownstreamMcpSession {
  route: UniversalMcpRoute;
  routeFingerprint: string;
  client: Client;
  transport: DownstreamTransport;
  connectedAt: number;
  lastUsedAt: number;
}

export interface UniversalMcpProxyOptions {
  sshControlDir: string;
  maximumSessions?: number;
  defaultSessionIdleTtlMs?: number;
  resultStore?: UniversalMcpResultStore;
  resolveEnvironmentProfile?: (
    name: string,
  ) => Promise<Record<string, string>> | Record<string, string>;
  clientFactory?: (route: UniversalMcpRoute) => Promise<DownstreamMcpSession>;
  now?: () => number;
}

export class UniversalMcpProxy {
  private readonly sessions = new Map<string, Promise<DownstreamMcpSession>>();
  private readonly maximumSessions: number;
  private readonly defaultSessionIdleTtlMs: number;
  private readonly results: UniversalMcpResultStore;
  private readonly now: () => number;
  private closed = false;

  constructor(
    private readonly routes: UniversalMcpRouteRegistry,
    private readonly targets: TargetRegistry,
    private readonly options: UniversalMcpProxyOptions,
  ) {
    this.maximumSessions = boundedInteger(options.maximumSessions, 16, 1, 256, "maximumSessions");
    this.defaultSessionIdleTtlMs = boundedInteger(
      options.defaultSessionIdleTtlMs,
      5 * 60_000,
      1_000,
      3_600_000,
      "defaultSessionIdleTtlMs",
    );
    this.results = options.resultStore ?? new UniversalMcpResultStore();
    this.now = options.now ?? Date.now;
  }

  async execute(input: UniversalMcpInput): Promise<Record<string, unknown>> {
    this.assertOpen();
    await this.pruneIdle();
    switch (input.operation) {
      case "routes":
        return this.routes.list();
      case "close":
        return this.closeRoute(input.route);
      case "search_tools":
        return this.withSession(input.route, "search_tools", async (session) => {
          const query = requireText(input.query, "mcp.search_tools requires query.");
          const listed = await timed(
            session.client.listTools(),
            session.route.callTimeoutMs,
            `${session.route.id} tools/list`,
          );
          const limit = boundedInteger(input.limit, 5, 1, 5, "limit");
          return {
            route: routeSummary(session.route),
            tools: listed.tools
              .map((tool) => ({
                name: tool.name,
                title: tool.title,
                description: tool.description,
                annotations: tool.annotations,
                score: scoreTool(tool, query),
              }))
              .filter((tool) => tool.score > 0)
              .sort((left, right) => right.score - left.score || left.name.localeCompare(right.name))
              .slice(0, limit),
          };
        });
      case "describe_tool":
        return this.withSession(input.route, "describe_tool", async (session) => {
          const name = requireText(input.name, "mcp.describe_tool requires name.");
          const listed = await timed(
            session.client.listTools(),
            session.route.callTimeoutMs,
            `${session.route.id} tools/list`,
          );
          const tool = listed.tools.find((candidate) => candidate.name === name);
          if (!tool) {
            throw new UniversalBrokerError(
              "MCP_TOOL_NOT_FOUND",
              `MCP tool ${name} is not exposed by route ${session.route.id}.`,
              {
                suggestions: listed.tools
                  .map((candidate) => ({ name: candidate.name }))
                  .sort((left, right) => left.name.localeCompare(right.name)),
              },
            );
          }
          return {
            route: routeSummary(session.route),
            result: this.project({ tool }, input.responsePolicy),
          };
        });
      case "invoke":
        return this.withSession(input.route, "invoke", async (session) => {
          const name = requireText(input.name, "mcp.invoke requires name.");
          let response;
          try {
            response = await timed(
              session.client.callTool({ name, arguments: input.arguments ?? {} }),
              session.route.callTimeoutMs,
              `${session.route.id}.${name}`,
            );
          } catch (error) {
            await this.evict(session.route.id, session);
            if (error instanceof McpError) {
              throw new UniversalBrokerError(
                "MCP_PROVIDER_ERROR",
                `MCP provider rejected ${session.route.id}.${name}: ${error.message}`,
                {
                  evidence: {
                    routeId: session.route.id,
                    tool: name,
                    providerCode: error.code,
                  },
                },
              );
            }
            throw new UniversalBrokerError(
              "MCP_RESULT_UNKNOWN",
              `MCP route ${session.route.id} failed after dispatching ${name}; the result is unknown and was not retried.`,
              {
                evidence: {
                  routeId: session.route.id,
                  tool: name,
                  cause: errorMessage(error),
                },
              },
            );
          }
          if (response.isError === true) {
            throw new UniversalBrokerError(
              "MCP_PROVIDER_ERROR",
              `MCP provider returned an error for ${session.route.id}.${name}.`,
              {
                evidence: {
                  routeId: session.route.id,
                  tool: name,
                  responsePreview: boundedJson(response, 2_000),
                },
              },
            );
          }
          return {
            route: routeSummary(session.route),
            tool: name,
            result: this.project(response, input.responsePolicy),
          };
        });
      case "list_resources":
        return this.withSession(input.route, "list_resources", async (session) => {
          const [resources, templates] = await timed(
            Promise.all([
              session.client.listResources(input.cursor ? { cursor: input.cursor } : undefined),
              session.client.listResourceTemplates(),
            ]),
            session.route.callTimeoutMs,
            `${session.route.id} resources/list`,
          );
          return {
            route: routeSummary(session.route),
            result: this.project(
              { resources, resourceTemplates: templates },
              withLimit(input.responsePolicy, input.limit),
            ),
          };
        });
      case "read_resource":
        if (input.uri?.startsWith("devspace://mcp-result/")) {
          return this.results.readByUri(input.uri);
        }
        return this.withSession(input.route, "read_resource", async (session) => {
          const uri = requireText(input.uri, "mcp.read_resource requires uri.");
          const response = await timed(
            session.client.readResource({ uri }),
            session.route.callTimeoutMs,
            `${session.route.id} resources/read`,
          );
          return {
            route: routeSummary(session.route),
            result: this.project(response, input.responsePolicy),
          };
        });
      case "list_prompts":
        return this.withSession(input.route, "list_prompts", async (session) => {
          const response = await timed(
            session.client.listPrompts(input.cursor ? { cursor: input.cursor } : undefined),
            session.route.callTimeoutMs,
            `${session.route.id} prompts/list`,
          );
          return {
            route: routeSummary(session.route),
            result: this.project(response, withLimit(input.responsePolicy, input.limit)),
          };
        });
      case "get_prompt":
        return this.withSession(input.route, "get_prompt", async (session) => {
          const name = requireText(input.name, "mcp.get_prompt requires name.");
          const response = await timed(
            session.client.getPrompt({
              name,
              arguments: promptArguments(input.arguments),
            }),
            session.route.callTimeoutMs,
            `${session.route.id} prompts/get`,
          );
          return {
            route: routeSummary(session.route),
            prompt: name,
            result: this.project(response, input.responsePolicy),
          };
        });
    }
  }

  readStoredResult(uri: string): Record<string, unknown> {
    return this.results.readByUri(uri);
  }

  async close(): Promise<void> {
    if (this.closed) return;
    this.closed = true;
    const pending = [...this.sessions.values()];
    this.sessions.clear();
    this.results.clear();
    await Promise.allSettled(pending.map(async (sessionPromise) => {
      const session = await sessionPromise.catch(() => undefined);
      if (session) await closeSession(session);
    }));
  }

  private async withSession<T extends Record<string, unknown>>(
    selector: string | undefined,
    operation: string,
    callback: (session: DownstreamMcpSession) => Promise<T>,
  ): Promise<T> {
    const route = await this.routes.resolve(selector);
    let session: DownstreamMcpSession;
    try {
      session = await this.session(route);
    } catch (error) {
      if (error instanceof UniversalBrokerError) throw error;
      throw new UniversalBrokerError(
        "TRANSPORT_UNAVAILABLE",
        `MCP route ${route.id} could not connect for ${operation}.`,
        { evidence: { routeId: route.id, cause: errorMessage(error) } },
      );
    }
    session.lastUsedAt = this.now();
    this.touchSession(route.id);
    try {
      return await callback(session);
    } catch (error) {
      if (error instanceof UniversalBrokerError) throw error;
      if (error instanceof McpError) {
        throw new UniversalBrokerError(
          "MCP_PROVIDER_ERROR",
          `MCP route ${route.id} failed during ${operation}: ${error.message}`,
          { evidence: { routeId: route.id, providerCode: error.code } },
        );
      }
      await this.evict(route.id, session);
      throw new UniversalBrokerError(
        "TRANSPORT_INTERRUPTED",
        `MCP route ${route.id} transport failed during ${operation}.`,
        { evidence: { routeId: route.id, cause: errorMessage(error) } },
      );
    }
  }

  private async session(route: UniversalMcpRoute): Promise<DownstreamMcpSession> {
    const fingerprint = routeFingerprint(route);
    const existing = this.sessions.get(route.id);
    if (existing) {
      const resolved = await existing.catch(() => undefined);
      if (resolved?.routeFingerprint === fingerprint) return existing;
      if (resolved) await closeSession(resolved);
      this.sessions.delete(route.id);
    }
    if (this.sessions.size >= this.maximumSessions) {
      const oldest = this.sessions.keys().next().value as string | undefined;
      if (oldest) await this.closeSessionById(oldest);
    }
    const pending = (this.options.clientFactory
      ? this.options.clientFactory(route)
      : this.connect(route, fingerprint))
      .catch((error) => {
        if (this.sessions.get(route.id) === pending) this.sessions.delete(route.id);
        throw error;
      });
    this.sessions.set(route.id, pending);
    return pending;
  }

  private async connect(
    route: UniversalMcpRoute,
    fingerprint: string,
  ): Promise<DownstreamMcpSession> {
    const transport = await this.transport(route);
    const client = new Client({
      name: `devspace-universal-proxy-${route.id}`,
      version: "2.0.0",
    });
    try {
      await timed(
        client.connect(transport),
        route.startupTimeoutMs,
        `${route.id} startup`,
      );
      const now = this.now();
      return {
        route,
        routeFingerprint: fingerprint,
        client,
        transport,
        connectedAt: now,
        lastUsedAt: now,
      };
    } catch (error) {
      await Promise.allSettled([client.close(), transport.close()]);
      throw error;
    }
  }

  private async transport(route: UniversalMcpRoute): Promise<DownstreamTransport> {
    if (route.transport === "streamable-http") {
      if (route.envProfile) {
        throw new UniversalBrokerError(
          "CAPABILITY_UNAVAILABLE",
          `HTTP MCP route ${route.id} cannot map an environment profile to headers yet.`,
        );
      }
      return new StreamableHTTPClientTransport(new URL(route.url!));
    }
    let environment = getDefaultEnvironment();
    if (route.envProfile) {
      if (!this.options.resolveEnvironmentProfile) {
        throw new UniversalBrokerError(
          "CAPABILITY_UNAVAILABLE",
          `MCP route ${route.id} requires unavailable environment profile ${route.envProfile}.`,
        );
      }
      if (route.transport === "ssh-stdio") {
        throw new UniversalBrokerError(
          "CAPABILITY_UNAVAILABLE",
          "SSH route secrets are not serialized into command arguments; use a remote credential source or a local stdio SSH wrapper.",
        );
      }
      environment = {
        ...environment,
        ...await this.options.resolveEnvironmentProfile(route.envProfile),
      };
    }
    if (route.transport === "local-stdio") {
      return new StdioClientTransport({
        command: route.command!,
        args: route.args,
        env: environment,
        stderr: "pipe",
      });
    }
    const target = await this.targets.resolve(route.target);
    if (target.transport !== "ssh" || !target.sshHost) {
      throw new UniversalBrokerError(
        "TRANSPORT_UNAVAILABLE",
        `MCP route ${route.id} requires an SSH target with sshHost.`,
      );
    }
    await mkdir(this.options.sshControlDir, { recursive: true, mode: 0o700 });
    const remoteCommand = [route.command!, ...route.args]
      .map(shellQuote)
      .join(" ");
    return new StdioClientTransport({
      command: "/usr/bin/ssh",
      args: [
        "-o", "BatchMode=yes",
        "-o", "ConnectTimeout=7",
        "-o", "ConnectionAttempts=1",
        "-o", "ControlMaster=auto",
        "-o", "ControlPersist=90",
        "-o", `ControlPath=${join(this.options.sshControlDir, "%C")}`,
        "-T",
        target.sshHost,
        remoteCommand,
      ],
      env: environment,
      stderr: "pipe",
    });
  }

  private project(
    value: unknown,
    policy: Record<string, unknown> | undefined,
  ): Record<string, unknown> {
    const maximumCharacters = policyInteger(policy, "maxCharacters", 12_000, 100, 100_000);
    const maximumItems = policyInteger(policy, "maxItems", 50, 1, 1_000);
    const preserve = policyBoolean(policy, "preserveFullResult", true);
    const pointers = policyStringArray(policy, "jsonPointers");
    const selected = pointers.length > 0 ? selectPointers(value, pointers) : value;
    const bounded = boundArrays(selected, maximumItems);
    const serialized = JSON.stringify(bounded.value) ?? "null";
    if (serialized.length <= maximumCharacters && !bounded.truncated) {
      return { truncated: false, value: bounded.value };
    }
    const stored = preserve ? this.results.put(value) : undefined;
    return {
      truncated: true,
      preview: headTail(serialized, maximumCharacters),
      projectedValue: serialized.length <= maximumCharacters ? bounded.value : undefined,
      totalCharacters: (JSON.stringify(value) ?? "null").length,
      itemLimitApplied: bounded.truncated,
      ...(stored ?? {}),
    };
  }

  private async closeRoute(selector: string | undefined): Promise<Record<string, unknown>> {
    if (!selector) {
      const ids = [...this.sessions.keys()];
      await Promise.all(ids.map((id) => this.closeSessionById(id)));
      return { closedRoutes: ids.sort() };
    }
    const route = await this.routes.resolve(selector);
    const closed = await this.closeSessionById(route.id);
    return { routeId: route.id, closed };
  }

  private async closeSessionById(routeId: string): Promise<boolean> {
    const pending = this.sessions.get(routeId);
    this.sessions.delete(routeId);
    const session = await pending?.catch(() => undefined);
    if (session) await closeSession(session);
    return Boolean(pending);
  }

  private async evict(routeId: string, session: DownstreamMcpSession): Promise<void> {
    const pending = this.sessions.get(routeId);
    if (!pending) return;
    const candidate = await pending.catch(() => undefined);
    if (candidate !== session || this.sessions.get(routeId) !== pending) return;
    this.sessions.delete(routeId);
    await closeSession(session);
  }

  private async pruneIdle(): Promise<void> {
    const now = this.now();
    for (const [routeId, pending] of [...this.sessions]) {
      const session = await pending.catch(() => undefined);
      if (!session) continue;
      const ttl = session.route.idleTimeoutMs || this.defaultSessionIdleTtlMs;
      if (session.lastUsedAt + ttl <= now) await this.closeSessionById(routeId);
    }
  }

  private touchSession(routeId: string): void {
    const pending = this.sessions.get(routeId);
    if (!pending) return;
    this.sessions.delete(routeId);
    this.sessions.set(routeId, pending);
  }

  private assertOpen(): void {
    if (this.closed) {
      throw new UniversalBrokerError("TRANSPORT_UNAVAILABLE", "The generic MCP proxy is closed.");
    }
  }
}

async function closeSession(session: DownstreamMcpSession): Promise<void> {
  await Promise.allSettled([
    session.client.close(),
    session.transport.close(),
  ]);
}

function scoreTool(
  tool: { name: string; title?: string; description?: string },
  query: string,
): number {
  const normalized = normalize(query);
  const name = normalize(tool.name);
  const title = normalize(tool.title ?? "");
  const description = normalize(tool.description ?? "");
  let score = 0;
  if (name === normalized) score += 200;
  else if (name.includes(normalized)) score += 100;
  if (title.includes(normalized)) score += 80;
  if (description.includes(normalized)) score += 50;
  for (const token of tokens(normalized)) {
    if (name.includes(token)) score += 25;
    if (title.includes(token)) score += 15;
    if (description.includes(token)) score += 5;
  }
  return score;
}

function tokens(value: string): string[] {
  return [...new Set(value.match(/[\p{L}\p{N}]+/gu) ?? [])]
    .filter((token) => token.length > 1);
}

function normalize(value: string): string {
  return value.normalize("NFKC").trim().toLocaleLowerCase("en-US");
}

function requireText(value: string | undefined, message: string): string {
  if (!value?.trim()) throw new UniversalBrokerError("PRECONDITION_FAILED", message);
  return value;
}

function promptArguments(
  input: Record<string, unknown> | undefined,
): Record<string, string> | undefined {
  if (!input) return undefined;
  const result: Record<string, string> = {};
  for (const [key, value] of Object.entries(input)) {
    if (typeof value !== "string") {
      throw new UniversalBrokerError(
        "PRECONDITION_FAILED",
        `Prompt argument ${key} must be a string.`,
      );
    }
    result[key] = value;
  }
  return result;
}

function withLimit(
  policy: Record<string, unknown> | undefined,
  limit: number | undefined,
): Record<string, unknown> | undefined {
  return limit === undefined ? policy : { ...(policy ?? {}), maxItems: limit };
}

function policyInteger(
  policy: Record<string, unknown> | undefined,
  key: string,
  fallback: number,
  minimum: number,
  maximum: number,
): number {
  const value = policy?.[key];
  return boundedInteger(
    typeof value === "number" ? value : value === undefined ? undefined : Number.NaN,
    fallback,
    minimum,
    maximum,
    `responsePolicy.${key}`,
  );
}

function policyBoolean(
  policy: Record<string, unknown> | undefined,
  key: string,
  fallback: boolean,
): boolean {
  const value = policy?.[key];
  if (value === undefined) return fallback;
  if (typeof value !== "boolean") {
    throw new UniversalBrokerError(
      "PRECONDITION_FAILED",
      `responsePolicy.${key} must be boolean.`,
    );
  }
  return value;
}

function policyStringArray(
  policy: Record<string, unknown> | undefined,
  key: string,
): string[] {
  const value = policy?.[key];
  if (value === undefined) return [];
  if (!Array.isArray(value) || value.some((entry) => typeof entry !== "string")) {
    throw new UniversalBrokerError(
      "PRECONDITION_FAILED",
      `responsePolicy.${key} must be an array of strings.`,
    );
  }
  return value as string[];
}

function selectPointers(value: unknown, pointers: string[]): Record<string, unknown> {
  const result: Record<string, unknown> = {};
  for (const pointer of pointers) {
    if (!pointer.startsWith("/")) {
      throw new UniversalBrokerError(
        "PRECONDITION_FAILED",
        `JSON pointer must start with /: ${pointer}`,
      );
    }
    let current = value;
    for (const raw of pointer.slice(1).split("/")) {
      const key = raw.replaceAll("~1", "/").replaceAll("~0", "~");
      if (Array.isArray(current)) {
        const index = Number(key);
        current = Number.isSafeInteger(index) ? current[index] : undefined;
      } else if (current && typeof current === "object") {
        current = (current as Record<string, unknown>)[key];
      } else {
        current = undefined;
      }
    }
    result[pointer] = current;
  }
  return result;
}

function boundArrays(
  value: unknown,
  maximumItems: number,
): { value: unknown; truncated: boolean } {
  let truncated = false;
  const visit = (entry: unknown, depth: number): unknown => {
    if (depth > 8) return entry;
    if (Array.isArray(entry)) {
      if (entry.length > maximumItems) truncated = true;
      return entry.slice(0, maximumItems).map((item) => visit(item, depth + 1));
    }
    if (entry && typeof entry === "object") {
      return Object.fromEntries(
        Object.entries(entry).map(([key, item]) => [key, visit(item, depth + 1)]),
      );
    }
    return entry;
  };
  return { value: visit(value, 0), truncated };
}

function boundedInteger(
  value: number | undefined,
  fallback: number,
  minimum: number,
  maximum: number,
  field: string,
): number {
  const parsed = value ?? fallback;
  if (!Number.isInteger(parsed) || parsed < minimum || parsed > maximum) {
    throw new UniversalBrokerError(
      "PRECONDITION_FAILED",
      `${field} must be an integer from ${minimum} through ${maximum}.`,
    );
  }
  return parsed;
}

function timed<T>(promise: Promise<T>, timeoutMs: number, label: string): Promise<T> {
  let timer: NodeJS.Timeout | undefined;
  return Promise.race([
    promise,
    new Promise<never>((_resolve, reject) => {
      timer = setTimeout(
        () => reject(new Error(`${label} timed out after ${timeoutMs}ms.`)),
        timeoutMs,
      );
      timer.unref();
    }),
  ]).finally(() => {
    if (timer) clearTimeout(timer);
  });
}

function headTail(value: string, maximum: number): string {
  const marker = "\n... truncated ...\n";
  if (value.length <= maximum) return value;
  const available = Math.max(0, maximum - marker.length);
  const head = Math.ceil(available / 2);
  const tail = Math.floor(available / 2);
  return value.slice(0, head) + marker + value.slice(value.length - tail);
}

function routeFingerprint(route: UniversalMcpRoute): string {
  return JSON.stringify(route);
}

function shellQuote(value: string): string {
  return `'${value.replaceAll("'", `'"'"'`)}'`;
}

function boundedJson(value: unknown, maximum: number): string {
  return headTail(JSON.stringify(value) ?? "null", maximum);
}

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}
