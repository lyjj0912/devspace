import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import { isAbsolute } from "node:path";
import * as z from "zod/v4";
import { UniversalBrokerError } from "./errors.js";

const ROUTE_ID_PATTERN = /^[a-z][a-z0-9._-]{0,63}$/;

export type UniversalMcpTransport =
  | "local-stdio"
  | "ssh-stdio"
  | "streamable-http";

export interface UniversalMcpRoute {
  id: string;
  displayName: string;
  aliases: string[];
  transport: UniversalMcpTransport;
  target?: string;
  command?: string;
  args: string[];
  url?: string;
  envProfile?: string;
  startupTimeoutMs: number;
  callTimeoutMs: number;
  idleTimeoutMs: number;
}

export interface UniversalMcpRouteSnapshot {
  generation: string;
  routes: UniversalMcpRoute[];
}

const routeSchema = z.strictObject({
  displayName: z.string().min(1).max(128),
  aliases: z.array(z.string().min(1).max(128)).optional(),
  transport: z.enum(["local-stdio", "ssh-stdio", "streamable-http"]),
  target: z.string().min(1).optional(),
  command: z.string().min(1).optional(),
  args: z.array(z.string()).optional(),
  url: z.string().min(1).optional(),
  envProfile: z.string().min(1).optional(),
  startupTimeoutMs: z.number().int().min(100).max(300_000).optional(),
  callTimeoutMs: z.number().int().min(100).max(300_000).optional(),
  idleTimeoutMs: z.number().int().min(1_000).max(3_600_000).optional(),
}).superRefine((route, context) => {
  if ((route.transport === "local-stdio" || route.transport === "ssh-stdio") && !route.command) {
    context.addIssue({ code: "custom", path: ["command"], message: "command is required" });
  }
  if (route.transport === "ssh-stdio" && !route.target) {
    context.addIssue({ code: "custom", path: ["target"], message: "target is required" });
  }
  if (route.transport === "streamable-http" && !route.url) {
    context.addIssue({ code: "custom", path: ["url"], message: "url is required" });
  }
});

const routeFileSchema = z.strictObject({
  version: z.literal(1),
  routes: z.record(z.string(), routeSchema),
});

export class UniversalMcpRouteRegistry {
  private snapshot?: UniversalMcpRouteSnapshot;
  private contentHash?: string;

  constructor(private readonly configPath: string) {}

  async inspect(): Promise<UniversalMcpRouteSnapshot> {
    const content = await this.readConfig();
    const hash = sha256(content ?? "<missing>");
    if (this.snapshot && this.contentHash === hash) return this.snapshot;
    const parsed = content === undefined
      ? { version: 1 as const, routes: {} }
      : parseRouteFile(content, this.configPath);
    const routes = Object.entries(parsed.routes).map(([id, input]) => normalizeRoute(id, input));
    assertUniqueSelectors(routes);
    routes.sort((left, right) => left.id.localeCompare(right.id));
    this.snapshot = {
      generation: sha256(JSON.stringify(routes)).slice(0, 16),
      routes,
    };
    this.contentHash = hash;
    return this.snapshot;
  }

  async list(): Promise<{ generation: string; routes: Array<Record<string, unknown>> }> {
    const snapshot = await this.inspect();
    return {
      generation: snapshot.generation,
      routes: snapshot.routes.map(routeSummary),
    };
  }

  async resolve(selector: string | undefined): Promise<UniversalMcpRoute> {
    const snapshot = await this.inspect();
    if (!selector?.trim()) {
      if (snapshot.routes.length === 1) return snapshot.routes[0]!;
      throw new UniversalBrokerError(
        snapshot.routes.length === 0 ? "MCP_ROUTE_NOT_FOUND" : "PRECONDITION_FAILED",
        snapshot.routes.length === 0
          ? "No MCP routes are configured."
          : "Multiple MCP routes are configured; specify route.",
        { suggestions: snapshot.routes.map(routeSummary) },
      );
    }
    const normalized = normalizeSelector(selector);
    const matches = snapshot.routes.filter((route) =>
      normalizeSelector(route.id) === normalized
      || normalizeSelector(route.displayName) === normalized
      || route.aliases.some((alias) => normalizeSelector(alias) === normalized)
    );
    if (matches.length === 1) return matches[0]!;
    if (matches.length > 1) {
      throw new UniversalBrokerError(
        "PRECONDITION_FAILED",
        `MCP route selector is ambiguous: ${selector}`,
        { suggestions: matches.map(routeSummary) },
      );
    }
    throw new UniversalBrokerError(
      "MCP_ROUTE_NOT_FOUND",
      `Unknown MCP route: ${selector}`,
      { suggestions: snapshot.routes.map(routeSummary) },
    );
  }

  private async readConfig(): Promise<string | undefined> {
    try {
      return await readFile(this.configPath, "utf8");
    } catch (error) {
      if (isNodeError(error, "ENOENT")) return undefined;
      throw new UniversalBrokerError(
        "PRECONDITION_FAILED",
        `Unable to read MCP route registry: ${this.configPath}`,
        { evidence: { error: errorMessage(error) } },
      );
    }
  }
}

export function routeSummary(route: UniversalMcpRoute): Record<string, unknown> {
  return {
    routeId: route.id,
    displayName: route.displayName,
    aliases: route.aliases,
    transport: route.transport,
    ...(route.target ? { target: route.target } : {}),
    startupTimeoutMs: route.startupTimeoutMs,
    callTimeoutMs: route.callTimeoutMs,
    idleTimeoutMs: route.idleTimeoutMs,
    envProfileConfigured: Boolean(route.envProfile),
  };
}

function parseRouteFile(content: string, path: string) {
  let value: unknown;
  try {
    value = JSON.parse(content);
  } catch (error) {
    throw new UniversalBrokerError(
      "PRECONDITION_FAILED",
      `MCP route registry is not valid JSON: ${path}`,
      { evidence: { error: errorMessage(error) } },
    );
  }
  const result = routeFileSchema.safeParse(value);
  if (!result.success) {
    throw new UniversalBrokerError(
      "PRECONDITION_FAILED",
      `Invalid MCP route registry: ${path}`,
      { evidence: { issues: result.error.issues.slice(0, 20) } },
    );
  }
  return result.data;
}

function normalizeRoute(id: string, input: z.infer<typeof routeSchema>): UniversalMcpRoute {
  if (!ROUTE_ID_PATTERN.test(id)) {
    throw new UniversalBrokerError("PRECONDITION_FAILED", `Invalid MCP route id: ${id}`);
  }
  if (input.transport === "local-stdio" && input.command && !isAbsolute(input.command)) {
    throw new UniversalBrokerError(
      "PRECONDITION_FAILED",
      `Local stdio MCP route ${id} requires an absolute command path.`,
    );
  }
  if (input.transport === "ssh-stdio" && input.command && !input.command.startsWith("/")) {
    throw new UniversalBrokerError(
      "PRECONDITION_FAILED",
      `SSH stdio MCP route ${id} requires an absolute remote command path.`,
    );
  }
  if (input.transport === "streamable-http" && input.url) validateHttpRouteUrl(id, input.url);
  return {
    id,
    displayName: input.displayName.trim(),
    aliases: [...new Set((input.aliases ?? []).map((alias) => alias.trim()))],
    transport: input.transport,
    ...(input.target ? { target: input.target } : {}),
    ...(input.command ? { command: input.command } : {}),
    args: [...(input.args ?? [])],
    ...(input.url ? { url: input.url } : {}),
    ...(input.envProfile ? { envProfile: input.envProfile } : {}),
    startupTimeoutMs: input.startupTimeoutMs ?? 15_000,
    callTimeoutMs: input.callTimeoutMs ?? 120_000,
    idleTimeoutMs: input.idleTimeoutMs ?? 5 * 60_000,
  };
}

function validateHttpRouteUrl(id: string, value: string): void {
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    throw new UniversalBrokerError("PRECONDITION_FAILED", `MCP route ${id} has an invalid URL.`);
  }
  const loopback = ["localhost", "127.0.0.1", "::1", "[::1]"].includes(url.hostname);
  if (url.protocol !== "https:" && !(url.protocol === "http:" && loopback)) {
    throw new UniversalBrokerError(
      "PRECONDITION_FAILED",
      `MCP route ${id} must use HTTPS or loopback HTTP.`,
    );
  }
  if (url.username || url.password) {
    throw new UniversalBrokerError(
      "PRECONDITION_FAILED",
      `MCP route ${id} must not embed credentials in its URL.`,
    );
  }
}

function assertUniqueSelectors(routes: UniversalMcpRoute[]): void {
  const selectors = new Map<string, string[]>();
  for (const route of routes) {
    for (const value of [route.id, route.displayName, ...route.aliases]) {
      const key = normalizeSelector(value);
      const owners = selectors.get(key) ?? [];
      owners.push(route.id);
      selectors.set(key, owners);
    }
  }
  const collision = [...selectors.entries()].find(([, owners]) => new Set(owners).size > 1);
  if (collision) {
    throw new UniversalBrokerError(
      "PRECONDITION_FAILED",
      `MCP route selector is duplicated: ${collision[0]}`,
      { evidence: { routeIds: [...new Set(collision[1])] } },
    );
  }
}

function normalizeSelector(value: string): string {
  return value.normalize("NFKC").trim().toLocaleLowerCase("en-US");
}

function sha256(value: string): string {
  return createHash("sha256").update(value).digest("hex");
}

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

function isNodeError(error: unknown, code: string): error is NodeJS.ErrnoException {
  return error instanceof Error && (error as NodeJS.ErrnoException).code === code;
}
