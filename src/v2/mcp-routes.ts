import { createHash } from "node:crypto";
import { constants as fsConstants, type Stats } from "node:fs";
import { lstat, open, readFile } from "node:fs/promises";
import { isAbsolute, resolve } from "node:path";
import * as z from "zod/v4";
import { expandHomePath } from "../roots.js";
import { UniversalBrokerError } from "./errors.js";

const ROUTE_ID_PATTERN = /^[a-z][a-z0-9._-]{0,63}$/;

export type UniversalMcpTransport =
  | "local-stdio"
  | "ssh-stdio"
  | "streamable-http";

export interface UniversalMcpRiskPolicyEntry {
  risk: "R0" | "R2" | "R3";
  toolContractSha256: string;
}

export interface UniversalMcpRiskPolicy {
  mode: "broker-owned";
  policyFile: string;
  policyDigest: string;
  tools: Record<string, UniversalMcpRiskPolicyEntry>;
}

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
  riskPolicy?: UniversalMcpRiskPolicy;
  generation: string;
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
  riskPolicy: z.strictObject({
    mode: z.literal("broker-owned"),
    policyFile: z.string().min(1).max(4_096),
  }).optional(),
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

const riskPolicyEntrySchema = z.strictObject({
  risk: z.enum(["R0", "R2", "R3"]),
  toolContractSha256: z.string().regex(/^[a-f0-9]{64}$/u),
});

const riskPolicyFileSchema = z.strictObject({
  version: z.literal(1),
  routeId: z.string().regex(ROUTE_ID_PATTERN),
  tools: z.record(z.string().min(1).max(256), riskPolicyEntrySchema),
});

export class UniversalMcpRouteRegistry {
  private snapshot?: UniversalMcpRouteSnapshot;

  constructor(private readonly configPath: string) {}

  async inspect(): Promise<UniversalMcpRouteSnapshot> {
    const content = await this.readConfig();
    const parsed = content === undefined
      ? { version: 1 as const, routes: {} }
      : parseRouteFile(content, this.configPath);
    const routes = await Promise.all(
      Object.entries(parsed.routes).map(([id, input]) => normalizeRoute(id, input)),
    );
    assertUniqueSelectors(routes);
    routes.sort((left, right) => left.id.localeCompare(right.id));
    const generation = sha256(stableJson(routes));
    if (this.snapshot?.generation === generation) return this.snapshot;
    this.snapshot = {
      generation,
      routes,
    };
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
    riskPolicyConfigured: Boolean(route.riskPolicy),
    ...(route.riskPolicy ? { riskPolicyGeneration: route.riskPolicy.policyDigest } : {}),
    generation: route.generation,
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

async function normalizeRoute(
  id: string,
  input: z.infer<typeof routeSchema>,
): Promise<UniversalMcpRoute> {
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
  const riskPolicy = input.riskPolicy
    ? await loadBrokerOwnedRiskPolicy(id, input.riskPolicy.policyFile)
    : undefined;
  const route = {
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
    ...(riskPolicy ? { riskPolicy } : {}),
  };
  return {
    ...route,
    generation: sha256(stableJson(route)),
  };
}

async function loadBrokerOwnedRiskPolicy(
  routeId: string,
  configuredPath: string,
): Promise<UniversalMcpRiskPolicy> {
  const policyFile = resolvePolicyPath(configuredPath);
  let before: Stats;
  try {
    before = await lstat(policyFile);
  } catch (error) {
    throw invalidRiskPolicy(routeId, policyFile, "cannot be inspected", error);
  }
  assertOwnerOnlyPolicyFile(routeId, policyFile, before);
  if (typeof fsConstants.O_NOFOLLOW !== "number") {
    throw invalidRiskPolicy(routeId, policyFile, "cannot be opened without following symlinks");
  }

  let handle;
  try {
    handle = await open(policyFile, fsConstants.O_RDONLY | fsConstants.O_NOFOLLOW);
  } catch (error) {
    throw invalidRiskPolicy(routeId, policyFile, "cannot be opened safely", error);
  }
  let content: string;
  try {
    const opened = await handle.stat();
    assertOwnerOnlyPolicyFile(routeId, policyFile, opened);
    assertSameFileSnapshot(routeId, policyFile, before, opened);
    content = await handle.readFile({ encoding: "utf8" });
    const after = await handle.stat();
    assertSameFileSnapshot(routeId, policyFile, opened, after, true);
  } catch (error) {
    if (error instanceof UniversalBrokerError) throw error;
    throw invalidRiskPolicy(routeId, policyFile, "could not be read safely", error);
  } finally {
    await handle.close().catch(() => undefined);
  }

  let value: unknown;
  try {
    value = JSON.parse(content);
  } catch (error) {
    throw invalidRiskPolicy(routeId, policyFile, "is not valid JSON", error);
  }
  const parsed = riskPolicyFileSchema.safeParse(value);
  if (!parsed.success) {
    throw new UniversalBrokerError(
      "PRECONDITION_FAILED",
      `Invalid broker-owned MCP risk policy for route ${routeId}.`,
      { evidence: { routeId, issues: parsed.error.issues.slice(0, 20) } },
    );
  }
  if (parsed.data.routeId !== routeId) {
    throw invalidRiskPolicy(
      routeId,
      policyFile,
      `is bound to route ${parsed.data.routeId} instead of ${routeId}`,
    );
  }
  return {
    mode: "broker-owned",
    policyFile,
    policyDigest: sha256(content),
    tools: Object.fromEntries(
      Object.entries(parsed.data.tools)
        .sort(([left], [right]) => left.localeCompare(right))
        .map(([name, entry]) => [name, { ...entry }]),
    ),
  };
}

function resolvePolicyPath(configuredPath: string): string {
  const expanded = expandHomePath(configuredPath.trim());
  if (!isAbsolute(expanded)) {
    throw new UniversalBrokerError(
      "PRECONDITION_FAILED",
      "Broker-owned MCP risk policy paths must be absolute or start with ~/.",
    );
  }
  return resolve(expanded);
}

function assertOwnerOnlyPolicyFile(routeId: string, path: string, metadata: Stats): void {
  if (metadata.isSymbolicLink() || !metadata.isFile()) {
    throw invalidRiskPolicy(routeId, path, "must be a regular non-symlink file");
  }
  const getuid = process.getuid;
  if (typeof getuid !== "function") {
    throw invalidRiskPolicy(routeId, path, "cannot verify broker-user ownership on this platform");
  }
  if (metadata.uid !== getuid.call(process)) {
    throw invalidRiskPolicy(routeId, path, "is not owned by the broker user");
  }
  if ((metadata.mode & 0o022) !== 0) {
    throw invalidRiskPolicy(routeId, path, "must not be group- or other-writable");
  }
}

function assertSameFileSnapshot(
  routeId: string,
  path: string,
  expected: Stats,
  observed: Stats,
  compareMutationMetadata = false,
): void {
  if (
    expected.dev !== observed.dev
    || expected.ino !== observed.ino
    || (compareMutationMetadata && (
      expected.size !== observed.size
      || expected.mtimeMs !== observed.mtimeMs
      || expected.ctimeMs !== observed.ctimeMs
    ))
  ) {
    throw invalidRiskPolicy(routeId, path, "changed while it was being inspected");
  }
}

function invalidRiskPolicy(
  routeId: string,
  path: string,
  reason: string,
  error?: unknown,
): UniversalBrokerError {
  return new UniversalBrokerError(
    "PRECONDITION_FAILED",
    `Broker-owned MCP risk policy for route ${routeId} ${reason}.`,
    {
      evidence: {
        routeId,
        policyFileSha256: sha256(path),
        ...(error ? { error: errorMessage(error) } : {}),
      },
    },
  );
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

function stableJson(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(stableJson).join(",")}]`;
  if (value && typeof value === "object") {
    const record = value as Record<string, unknown>;
    return `{${Object.keys(record).sort().map((key) => `${JSON.stringify(key)}:${stableJson(record[key])}`).join(",")}}`;
  }
  return JSON.stringify(value) ?? "null";
}

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

function isNodeError(error: unknown, code: string): error is NodeJS.ErrnoException {
  return error instanceof Error && (error as NodeJS.ErrnoException).code === code;
}
