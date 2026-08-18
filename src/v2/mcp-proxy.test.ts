import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import type { AddressInfo } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { createMcpExpressApp } from "@modelcontextprotocol/sdk/server/express.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import { isInitializeRequest } from "@modelcontextprotocol/sdk/types.js";
import { createFixtureMcpServer } from "./fixtures/mcp-fixture-core.js";
import { UniversalEnvProfileRegistry } from "./env-profiles.js";
import {
  type DownstreamMcpSession,
  UniversalMcpProxy,
} from "./mcp-proxy.js";
import { UniversalMcpRouteRegistry } from "./mcp-routes.js";
import { TargetRegistry } from "./targets.js";

test("generic local-stdio proxy discovers, invokes, mutates, and pages downstream MCP", async (t) => {
  const root = await mkdtemp(join(tmpdir(), "devspace-v2-mcp-proxy-"));
  t.after(() => rm(root, { recursive: true, force: true }));
  const routePath = join(root, "routes.json");
  await writeRouteFile(routePath, {
    fixture: {
      displayName: "Fixture",
      aliases: ["테스트 MCP"],
      transport: "local-stdio",
      command: process.execPath,
      args: ["--import", "tsx", "src/v2/fixtures/mcp-fixture.ts"],
    },
  });
  const proxy = new UniversalMcpProxy(
    new UniversalMcpRouteRegistry(routePath),
    new TargetRegistry({ configPath: join(root, "targets.json") }),
    { sshControlDir: join(root, "ssh") },
  );
  t.after(() => proxy.close());

  const routes = await proxy.execute({ operation: "routes" });
  assert.equal((routes.routes as unknown[]).length, 1);
  const searched = await proxy.execute({
    operation: "search_tools",
    route: "테스트 MCP",
    query: "write value",
  });
  assert.equal((searched.tools as Array<{ name: string }>)[0]?.name, "write_value");
  const described = await proxy.execute({
    operation: "describe_tool",
    route: "fixture",
    name: "write_value",
  });
  assert.match(JSON.stringify(described), /inputSchema/);

  const write = await proxy.execute({
    operation: "invoke",
    route: "fixture",
    name: "write_value",
    arguments: { key: "alpha", value: "stored" },
  });
  assert.equal(write.tool, "write_value");
  const read = await proxy.execute({
    operation: "invoke",
    route: "fixture",
    name: "read_value",
    arguments: { key: "alpha" },
  });
  assert.match(JSON.stringify(read), /stored/);

  const resources = await proxy.execute({ operation: "list_resources", route: "fixture" });
  assert.match(JSON.stringify(resources), /fixture:\/\/state/);
  const resource = await proxy.execute({
    operation: "read_resource",
    route: "fixture",
    uri: "fixture://state",
  });
  assert.match(JSON.stringify(resource), /alpha/);
  const prompts = await proxy.execute({ operation: "list_prompts", route: "fixture" });
  assert.match(JSON.stringify(prompts), /fixture_prompt/);
  const prompt = await proxy.execute({
    operation: "get_prompt",
    route: "fixture",
    name: "fixture_prompt",
    arguments: { subject: "broker" },
  });
  assert.match(JSON.stringify(prompt), /Inspect broker/);

  const large = await proxy.execute({
    operation: "invoke",
    route: "fixture",
    name: "large_result",
    arguments: { characters: 20_000 },
    responsePolicy: { maxCharacters: 500, preserveFullResult: true },
  });
  const projected = large.result as { resourceUri?: string; truncated?: boolean };
  assert.equal(projected.truncated, true);
  assert.equal(typeof projected.resourceUri, "string");
  const page = await proxy.execute({
    operation: "read_resource",
    uri: projected.resourceUri,
  });
  assert.equal(page.mimeType, "application/json");
  assert.equal(typeof page.text, "string");

  await assert.rejects(
    proxy.execute({ operation: "invoke", route: "fixture", name: "provider_error" }),
    hasCode("MCP_PROVIDER_ERROR"),
  );
  await proxy.execute({
    operation: "invoke",
    route: "fixture",
    name: "delete_value",
    arguments: { key: "alpha" },
  });
  const closed = await proxy.execute({ operation: "close", route: "fixture" });
  assert.equal(closed.closed, true);
});

test("local stdio MCP routes inherit the runtime no-elevation boundary", { skip: process.platform !== "darwin" }, async (t) => {
  const root = await mkdtemp(join(tmpdir(), "devspace-v2-mcp-no-elevation-"));
  t.after(() => rm(root, { recursive: true, force: true }));
  const routePath = join(root, "routes.json");
  await writeRouteFile(routePath, {
    blocked: {
      displayName: "Blocked elevation fixture",
      transport: "local-stdio",
      command: "/usr/bin/sudo",
      args: ["-n", "true"],
      startupTimeoutMs: 1_000,
      callTimeoutMs: 1_000,
    },
  });
  const proxy = new UniversalMcpProxy(
    new UniversalMcpRouteRegistry(routePath),
    new TargetRegistry({ configPath: join(root, "targets.json") }),
    { sshControlDir: join(root, "ssh") },
  );
  t.after(() => proxy.close());
  await assert.rejects(
    proxy.execute({ operation: "search_tools", route: "blocked", query: "anything" }),
    hasCode("TRANSPORT_UNAVAILABLE"),
  );
});

test("generic Streamable HTTP route uses the same proxy contract", async (t) => {
  const fixture = await startHttpFixture(t);
  const root = await mkdtemp(join(tmpdir(), "devspace-v2-mcp-http-"));
  t.after(() => rm(root, { recursive: true, force: true }));
  const routePath = join(root, "routes.json");
  await writeRouteFile(routePath, {
    http: {
      displayName: "HTTP Fixture",
      transport: "streamable-http",
      url: fixture.url,
    },
  });
  const proxy = new UniversalMcpProxy(
    new UniversalMcpRouteRegistry(routePath),
    new TargetRegistry({ configPath: join(root, "targets.json") }),
    { sshControlDir: join(root, "ssh") },
  );
  t.after(() => proxy.close());

  const search = await proxy.execute({
    operation: "search_tools",
    route: "http",
    query: "read value",
  });
  assert.equal((search.tools as Array<{ name: string }>)[0]?.name, "read_value");
  const write = await proxy.execute({
    operation: "invoke",
    route: "http",
    name: "write_value",
    arguments: { key: "http", value: "ok" },
  });
  assert.match(JSON.stringify(write), /stored/);
});

test("MCP routes consume owner-only environment and HTTP-header profiles without exposing values", async (t) => {
  const root = await mkdtemp(join(tmpdir(), "devspace-v2-mcp-profile-"));
  t.after(() => rm(root, { recursive: true, force: true }));
  const profilePath = join(root, "profiles.json");
  await writeFile(profilePath, JSON.stringify({
    version: 1,
    profiles: {
      stdio: {
        targets: ["local"],
        environment: { DEVSPACE_FIXTURE_PROFILE: "stdio-secret" },
      },
      http: {
        targets: ["local"],
        headers: { "x-devspace-profile": "http-secret" },
      },
    },
  }), { mode: 0o600 });
  const profiles = new UniversalEnvProfileRegistry({ configPath: profilePath });
  const routePath = join(root, "routes.json");
  const fixture = await startHttpFixture(t, { headerName: "x-devspace-profile", headerValue: "http-secret" });
  await writeRouteFile(routePath, {
    stdio: {
      displayName: "Profile stdio",
      transport: "local-stdio",
      command: process.execPath,
      args: ["--import", "tsx", "src/v2/fixtures/mcp-fixture.ts"],
      envProfile: "stdio",
    },
    http: {
      displayName: "Profile HTTP",
      transport: "streamable-http",
      url: fixture.url,
      envProfile: "http",
    },
  });
  const proxy = new UniversalMcpProxy(
    new UniversalMcpRouteRegistry(routePath),
    new TargetRegistry({ configPath: join(root, "targets.json") }),
    { sshControlDir: join(root, "ssh"), envProfiles: profiles },
  );
  t.after(() => proxy.close());
  const stdio = await proxy.execute({
    operation: "invoke",
    route: "stdio",
    name: "read_environment",
    arguments: { name: "DEVSPACE_FIXTURE_PROFILE" },
  });
  assert.match(JSON.stringify(stdio), /stdio-secret/);
  const http = await proxy.execute({
    operation: "search_tools",
    route: "http",
    query: "read value",
  });
  assert.equal((http.tools as Array<{ name: string }>)[0]?.name, "read_value");
  assert.equal(JSON.stringify(await profiles.list()).includes("stdio-secret"), false);
  assert.equal(JSON.stringify(await profiles.list()).includes("http-secret"), false);
});

test("post-dispatch transport failure is never retried", async (t) => {
  const root = await mkdtemp(join(tmpdir(), "devspace-v2-mcp-unknown-"));
  t.after(() => rm(root, { recursive: true, force: true }));
  const routePath = join(root, "routes.json");
  await writeRouteFile(routePath, {
    fixture: {
      displayName: "Fixture",
      transport: "local-stdio",
      command: process.execPath,
      args: ["--version"],
    },
  });
  let calls = 0;
  const proxy = new UniversalMcpProxy(
    new UniversalMcpRouteRegistry(routePath),
    new TargetRegistry({ configPath: join(root, "targets.json") }),
    {
      sshControlDir: join(root, "ssh"),
      clientFactory: async (route) => ({
        route,
        routeFingerprint: JSON.stringify(route),
        client: {
          callTool: async () => {
            calls += 1;
            throw new Error("connection lost after dispatch");
          },
          close: async () => undefined,
        } as unknown as Client,
        transport: {
          close: async () => undefined,
        } as DownstreamMcpSession["transport"],
        connectedAt: Date.now(),
        lastUsedAt: Date.now(),
        activeCalls: 0,
      }),
    },
  );
  t.after(() => proxy.close());
  await assert.rejects(
    proxy.execute({ operation: "invoke", route: "fixture", name: "write_value" }),
    hasCode("MCP_RESULT_UNKNOWN"),
  );
  assert.equal(calls, 1);
});

test("downstream MCP LRU never evicts an in-flight session", async (t) => {
  const root = await mkdtemp(join(tmpdir(), "devspace-v2-mcp-lru-"));
  t.after(() => rm(root, { recursive: true, force: true }));
  const routePath = join(root, "routes.json");
  await writeRouteFile(routePath, Object.fromEntries(["a", "b", "c"].map((id) => [id, {
    displayName: `Route ${id}`,
    transport: "local-stdio",
    command: process.execPath,
    args: ["--version"],
  }])));
  let now = 0;
  let releaseA: (() => void) | undefined;
  const aGate = new Promise<void>((resolve) => { releaseA = resolve; });
  const closed: string[] = [];
  const proxy = new UniversalMcpProxy(
    new UniversalMcpRouteRegistry(routePath),
    new TargetRegistry({ configPath: join(root, "targets.json") }),
    {
      sshControlDir: join(root, "ssh"),
      maximumSessions: 2,
      now: () => now,
      clientFactory: async (route) => ({
        route,
        routeFingerprint: JSON.stringify(route),
        client: {
          listTools: async () => {
            if (route.id === "a") await aGate;
            return { tools: [{ name: `read_${route.id}`, description: "read value" }] };
          },
          close: async () => { closed.push(`client:${route.id}`); },
        } as unknown as Client,
        transport: {
          close: async () => { closed.push(`transport:${route.id}`); },
        } as DownstreamMcpSession["transport"],
        connectedAt: now,
        lastUsedAt: now,
        activeCalls: 0,
      }),
    },
  );
  t.after(() => proxy.close());

  const inFlight = proxy.execute({ operation: "search_tools", route: "a", query: "read" });
  for (let attempt = 0; attempt < 10 && (await proxy.stats()).activeCalls !== 1; attempt += 1) {
    await new Promise<void>((resolve) => setImmediate(resolve));
  }
  assert.equal((await proxy.stats()).activeCalls, 1);
  now = 1;
  await proxy.execute({ operation: "search_tools", route: "b", query: "read" });
  now = 2;
  await proxy.execute({ operation: "search_tools", route: "c", query: "read" });
  assert.equal(closed.includes("client:b"), true);
  assert.equal(closed.includes("client:a"), false);
  releaseA?.();
  await inFlight;
});

async function startHttpFixture(
  t: test.TestContext,
  expectedHeader?: { headerName: string; headerValue: string },
): Promise<{ url: string }> {
  const app = createMcpExpressApp({ host: "127.0.0.1" });
  const transports = new Map<string, StreamableHTTPServerTransport>();
  const mcpServers = new Set<ReturnType<typeof createFixtureMcpServer>>();
  app.all("/mcp", async (req, res) => {
    if (expectedHeader && req.header(expectedHeader.headerName) !== expectedHeader.headerValue) {
      return void res.status(401).end();
    }
    let transport: StreamableHTTPServerTransport | undefined;
    const sessionId = req.header("mcp-session-id");
    if (sessionId) {
      transport = transports.get(sessionId);
      if (!transport) return void res.status(404).end();
    } else if (req.method === "POST" && isInitializeRequest(req.body)) {
      transport = new StreamableHTTPServerTransport({
        sessionIdGenerator: () => randomUUID(),
        onsessioninitialized: (id) => {
          if (transport) transports.set(id, transport);
        },
      });
      const server = createFixtureMcpServer();
      mcpServers.add(server);
      transport.onclose = () => {
        const id = transport?.sessionId;
        if (id) transports.delete(id);
      };
      await server.connect(transport);
    } else {
      return void res.status(400).end();
    }
    await transport.handleRequest(req, res, req.body);
  });
  const server = app.listen(0, "127.0.0.1");
  await new Promise<void>((resolve, reject) => {
    server.once("listening", resolve);
    server.once("error", reject);
  });
  t.after(async () => {
    await Promise.allSettled([...transports.values()].map((transport) => transport.close()));
    await Promise.allSettled([...mcpServers].map((mcpServer) => mcpServer.close()));
    await new Promise<void>((resolve) => server.close(() => resolve()));
  });
  const address = server.address() as AddressInfo;
  return { url: `http://127.0.0.1:${address.port}/mcp` };
}

async function writeRouteFile(path: string, routes: Record<string, unknown>): Promise<void> {
  await writeFile(path, JSON.stringify({ version: 1, routes }, null, 2));
}

function hasCode(code: string) {
  return (error: unknown) => error instanceof Error && "code" in error && error.code === code;
}
