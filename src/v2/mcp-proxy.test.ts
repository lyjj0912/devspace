import assert from "node:assert/strict";
import { createHash, randomUUID } from "node:crypto";
import { chmod, mkdtemp, rm, symlink, writeFile } from "node:fs/promises";
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
  downstreamMcpToolContractSha256,
  type DownstreamMcpSession,
  UniversalMcpProxy,
} from "./mcp-proxy.js";
import { UniversalMcpRouteRegistry } from "./mcp-routes.js";
import { OperationAuthorityRegistry, actionFingerprint } from "./authority.js";
import { mcpAction, minimumAuthorityRisk } from "./authority-policy.js";
import { TargetRegistry } from "./targets.js";
import { createCapabilityCallContextFromTrustedPrincipal } from "./capability-call-context.js";

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
          listTools: async () => ({
            tools: [{
              name: "write_value",
              description: "Mutate the fixture value.",
              inputSchema: { type: "object" },
            }],
          }),
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

test("downstream MCP quota never evicts an unexpired or in-flight session", async (t) => {
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
  await assert.rejects(
    proxy.execute({ operation: "search_tools", route: "c", query: "read" }),
    hasCode("RESOURCE_QUOTA_EXCEEDED"),
  );
  assert.equal(closed.includes("client:b"), false);
  assert.equal(closed.includes("client:a"), false);
  releaseA?.();
  await inFlight;
});

test("MCP connections key by stable principal and exact not-connected reconnect is single-flight", async (t) => {
  const root = await mkdtemp(join(tmpdir(), "devspace-v2-mcp-principal-reconnect-"));
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
  let constructions = 0;
  const transports: Array<{ close(): Promise<void>; onclose?: () => void }> = [];
  const proxy = new UniversalMcpProxy(
    new UniversalMcpRouteRegistry(routePath),
    new TargetRegistry({ configPath: join(root, "targets.json") }),
    {
      sshControlDir: join(root, "ssh"),
      clientFactory: async (route) => {
        constructions += 1;
        const construction = constructions;
        const transport = { close: async () => undefined };
        transports.push(transport);
        return {
          route,
          routeFingerprint: route.generation,
          client: {
            listTools: async () => {
              if (construction === 1) throw new Error("Not connected");
              return { tools: [{ name: "read_value", description: "read value" }] };
            },
            close: async () => undefined,
          } as unknown as Client,
          transport: transport as DownstreamMcpSession["transport"],
          connectedAt: Date.now(),
          lastUsedAt: Date.now(),
          activeCalls: 0,
        };
      },
    },
  );
  t.after(() => proxy.close());
  const ownerA1 = owner("mcp-owner-a");
  const ownerA2 = owner("mcp-owner-a");
  const ownerB = owner("mcp-owner-b");
  const calls = await Promise.all(Array.from({ length: 20 }, () => proxy.execute({
    operation: "search_tools",
    route: "fixture",
    query: "read",
  }, ownerA1)));
  assert.equal(constructions, 2);
  assert.equal(calls.every((result) => result.livenessVerified === true), true);
  await proxy.execute({ operation: "search_tools", route: "fixture", query: "read" }, ownerA2);
  assert.equal(constructions, 2);
  await proxy.execute({ operation: "search_tools", route: "fixture", query: "read" }, ownerB);
  assert.equal(constructions, 3);

  transports[0]?.onclose?.();
  await new Promise<void>((resolve) => setImmediate(resolve));
  assert.equal((await proxy.stats()).sessions, 2);
});

test("broker-owned exact tool policy is the only provider-corroborated R0 downgrade", async (t) => {
  const root = await mkdtemp(join(tmpdir(), "devspace-v2-mcp-risk-"));
  t.after(() => rm(root, { recursive: true, force: true }));
  const routePath = join(root, "routes.json");
  const policyPath = join(root, "policy.json");
  const baseTool = {
    name: "read_exact",
    title: "Read exact fixture",
    description: "A deterministic downstream tool contract.",
    inputSchema: {
      type: "object",
      additionalProperties: false,
      properties: { key: { type: "string" } },
      required: ["key"],
    },
    annotations: { readOnlyHint: true, destructiveHint: false },
  };
  let providerTool: Record<string, unknown> = structuredClone(baseTool);
  let providerDispatches = 0;
  let providerConstructions = 0;
  await writePolicyRoute(routePath, policyPath);
  await writeRiskPolicy(
    policyPath,
    "R0",
    downstreamMcpToolContractSha256(baseTool),
  );
  const proxy = new UniversalMcpProxy(
    new UniversalMcpRouteRegistry(routePath),
    new TargetRegistry({ configPath: join(root, "targets.json") }),
    {
      sshControlDir: join(root, "ssh"),
      clientFactory: async (route) => {
        providerConstructions += 1;
        return {
          route,
          routeFingerprint: route.generation,
          client: {
            listTools: async () => ({ tools: [structuredClone(providerTool)] }),
            callTool: async () => {
              providerDispatches += 1;
              return { content: [{ type: "text", text: "ok" }] };
            },
            close: async () => undefined,
          } as unknown as Client,
          transport: { close: async () => undefined } as DownstreamMcpSession["transport"],
          connectedAt: Date.now(),
          lastUsedAt: Date.now(),
          activeCalls: 0,
        };
      },
    },
  );
  t.after(() => proxy.close());

  const exact = await proxy.prepareInvocation({
    operation: "invoke",
    route: "fixture",
    name: "read_exact",
    arguments: { key: "one" },
  });
  assert.equal(exact.binding.risk, "R0");
  assert.equal(exact.binding.toolContractSha256, downstreamMcpToolContractSha256(baseTool));
  assert.equal(providerDispatches, 0);
  const exactGeneration = exact.binding.routeGeneration;
  const exactAction = mcpAction(
    { operation: "invoke", route: "fixture", name: "read_exact", arguments: { key: "one" } },
    exact.binding,
  );
  await exact.execute();
  assert.equal(providerDispatches, 1);

  const policyStale = await proxy.prepareInvocation({
    operation: "invoke",
    route: "fixture",
    name: "read_exact",
  });
  assert.equal(policyStale.binding.risk, "R0");
  await writeRiskPolicy(policyPath, "R3", downstreamMcpToolContractSha256(baseTool));
  await assert.rejects(policyStale.execute(), hasCode("AUTHORITY_STALE"));
  assert.equal(providerDispatches, 1);
  await writeRiskPolicy(policyPath, "R0", downstreamMcpToolContractSha256(baseTool));

  const contractStale = await proxy.prepareInvocation({
    operation: "invoke",
    route: "fixture",
    name: "read_exact",
  });
  providerTool = { ...structuredClone(baseTool), title: "Changed after preparation" };
  await assert.rejects(contractStale.execute(), hasCode("AUTHORITY_STALE"));
  assert.equal(providerDispatches, 1);
  providerTool = structuredClone(baseTool);

  await writeRiskPolicy(policyPath, "R2", downstreamMcpToolContractSha256(baseTool));
  const policyChanged = await proxy.prepareInvocation({
    operation: "invoke",
    route: "fixture",
    name: "read_exact",
    arguments: { key: "one" },
  });
  assert.equal(policyChanged.binding.risk, "R2");
  assert.notEqual(policyChanged.binding.routeGeneration, exactGeneration);
  assert.notEqual(
    actionFingerprint(mcpAction(
      { operation: "invoke", route: "fixture", name: "read_exact", arguments: { key: "one" } },
      policyChanged.binding,
    )),
    actionFingerprint(exactAction),
  );
  policyChanged.release();

  await writeRiskPolicy(policyPath, "R3", "e".repeat(64));
  const brokerHighRisk = await proxy.prepareInvocation({
    operation: "invoke",
    route: "fixture",
    name: "read_exact",
  });
  assert.equal(brokerHighRisk.binding.risk, "R3");
  brokerHighRisk.release();

  await writeRiskPolicy(policyPath, "R0", "f".repeat(64));
  const mismatched = await proxy.prepareInvocation({ operation: "invoke", route: "fixture", name: "read_exact" });
  assert.equal(mismatched.binding.risk, "R2");
  mismatched.release();

  await writeRouteFile(routePath, {
    fixture: {
      displayName: "Fixture",
      transport: "local-stdio",
      command: process.execPath,
      args: ["--version"],
    },
  });
  const omitted = await proxy.prepareInvocation({ operation: "invoke", route: "fixture", name: "read_exact" });
  assert.equal(omitted.binding.risk, "R2");
  omitted.release();

  await writePolicyRoute(routePath, policyPath);
  await writeRiskPolicy(policyPath, "R0", downstreamMcpToolContractSha256(baseTool));
  providerTool = { ...structuredClone(baseTool), annotations: { destructiveHint: false } };
  const uncorroborated = await proxy.prepareInvocation({ operation: "invoke", route: "fixture", name: "read_exact" });
  assert.equal(uncorroborated.binding.risk, "R2");
  uncorroborated.release();

  providerTool = {
    ...structuredClone(baseTool),
    annotations: { readOnlyHint: true, destructiveHint: true },
  };
  const destructive = await proxy.prepareInvocation({ operation: "invoke", route: "fixture", name: "read_exact" });
  assert.equal(destructive.binding.risk, "R3");
  destructive.release();
  assert.equal(providerDispatches, 1);
  assert.ok(providerConstructions >= 1);
});

test("prepared MCP invocation persists DISPATCHED immediately before callTool and cancels stale contracts", async (t) => {
  const root = await mkdtemp(join(tmpdir(), "devspace-v2-mcp-dispatch-barrier-"));
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
  const baseTool = {
    name: "mutate_exact",
    title: "Mutate exact fixture",
    description: "A deterministic mutation contract.",
    inputSchema: { type: "object", additionalProperties: false },
    annotations: { readOnlyHint: false, destructiveHint: false },
  };
  let providerTool: Record<string, unknown> = structuredClone(baseTool);
  let providerCalls = 0;
  let boundaryAuthorityId: string | undefined;
  const principal = "mcp-dispatch-boundary-principal";
  const authority = new OperationAuthorityRegistry({
    minimumRisk: minimumAuthorityRisk,
    storePath: join(root, "authority.sqlite"),
    instanceId: "mcp-dispatch-boundary-owner",
  });
  t.after(() => authority.close());
  const proxy = new UniversalMcpProxy(
    new UniversalMcpRouteRegistry(routePath),
    new TargetRegistry({ configPath: join(root, "targets.json") }),
    {
      sshControlDir: join(root, "ssh"),
      clientFactory: async (route) => ({
        route,
        routeFingerprint: route.generation,
        client: {
          listTools: async () => ({ tools: [structuredClone(providerTool)] }),
          callTool: async () => {
            assert.ok(boundaryAuthorityId);
            const status = authority.status(boundaryAuthorityId, principal) as {
              receipts: Array<{ state: string; leaseState: string }>;
            };
            assert.equal(status.receipts.at(-1)?.state, "DISPATCHED");
            assert.equal(status.receipts.at(-1)?.leaseState, "ACTIVE");
            providerCalls += 1;
            return { content: [{ type: "text", text: "mutated" }] };
          },
          close: async () => undefined,
        } as unknown as Client,
        transport: { close: async () => undefined } as DownstreamMcpSession["transport"],
        connectedAt: Date.now(),
        lastUsedAt: Date.now(),
        activeCalls: 0,
      }),
    },
  );
  t.after(() => proxy.close());

  const input = {
    operation: "invoke" as const,
    route: "fixture",
    name: "mutate_exact",
    arguments: { key: "one" },
  };
  const prepared = await proxy.prepareInvocation(input);
  assert.equal(prepared.binding.risk, "R2");
  const descriptor = mcpAction(input, prepared.binding);
  const created = authority.create({
    taskId: "mcp-dispatch-boundary-pass",
    authorityText: "Dispatch the exact downstream mutation once.",
    actions: [{ descriptor, risk: prepared.binding.risk, uses: 1 }],
  }, principal);
  boundaryAuthorityId = String(created.authorityId);
  const dispatch = authority.prepareDispatch(
    boundaryAuthorityId,
    principal,
    descriptor,
    prepared.binding.risk,
  );
  await prepared.execute(dispatch);
  assert.equal(providerCalls, 1);
  dispatch.complete("PASS");

  providerTool = structuredClone(baseTool);
  const stale = await proxy.prepareInvocation(input);
  const staleDescriptor = mcpAction(input, stale.binding);
  const staleCreated = authority.create({
    taskId: "mcp-dispatch-boundary-stale",
    authorityText: "Do not dispatch if the provider contract changes.",
    actions: [{ descriptor: staleDescriptor, risk: stale.binding.risk, uses: 1 }],
  }, principal);
  const staleAuthorityId = String(staleCreated.authorityId);
  const staleDispatch = authority.prepareDispatch(
    staleAuthorityId,
    principal,
    staleDescriptor,
    stale.binding.risk,
  );
  providerTool = { ...structuredClone(baseTool), title: "Changed after preparation" };
  await assert.rejects(stale.execute(staleDispatch), hasCode("AUTHORITY_STALE"));
  assert.equal(providerCalls, 1);
  assert.equal(staleDispatch.phase, "CLAIMED");
  staleDispatch.cancelNotDispatched({
    providerCallCount: 0,
    proof: "MCP_CONTRACT_REVALIDATION_PROVIDER_CALL_ZERO",
  });
  const cancelled = authority.status(staleAuthorityId, principal) as {
    actions: Array<{ consumedUses: number }>;
    receipts: Array<{ state: string; leaseState: string }>;
  };
  assert.equal(cancelled.actions[0]?.consumedUses, 0);
  assert.equal(cancelled.receipts[0]?.state, "CANCELLED_NOT_DISPATCHED");
  assert.equal(cancelled.receipts[0]?.leaseState, "RELEASED");
});

test("unsafe configured MCP policy rejects before provider construction or dispatch", async (t) => {
  const root = await mkdtemp(join(tmpdir(), "devspace-v2-mcp-policy-predispatch-"));
  t.after(() => rm(root, { recursive: true, force: true }));
  const routePath = join(root, "routes.json");
  const policyPath = join(root, "policy.json");
  await writePolicyRoute(routePath, policyPath);
  await writeRiskPolicy(policyPath, "R0", "a".repeat(64));
  await chmod(policyPath, 0o622);
  let constructions = 0;
  let dispatches = 0;
  const proxy = new UniversalMcpProxy(
    new UniversalMcpRouteRegistry(routePath),
    new TargetRegistry({ configPath: join(root, "targets.json") }),
    {
      sshControlDir: join(root, "ssh"),
      clientFactory: async () => {
        constructions += 1;
        dispatches += 1;
        throw new Error("unsafe policy must fail before provider construction");
      },
    },
  );
  t.after(() => proxy.close());
  await assert.rejects(
    proxy.prepareInvocation({ operation: "invoke", route: "fixture", name: "read_exact" }),
    hasCode("PRECONDITION_FAILED"),
  );
  await chmod(policyPath, 0o600);
  await writeFile(policyPath, "{not-json", { mode: 0o600 });
  await assert.rejects(
    proxy.prepareInvocation({ operation: "invoke", route: "fixture", name: "read_exact" }),
    hasCode("PRECONDITION_FAILED"),
  );
  const realPolicyPath = join(root, "real-policy.json");
  await writeRiskPolicy(realPolicyPath, "R0", "a".repeat(64));
  await rm(policyPath);
  await symlink(realPolicyPath, policyPath);
  await assert.rejects(
    proxy.prepareInvocation({ operation: "invoke", route: "fixture", name: "read_exact" }),
    hasCode("PRECONDITION_FAILED"),
  );
  assert.equal(constructions, 0);
  assert.equal(dispatches, 0);
});

test("prepared MCP invocation fences target and environment-profile generations", async (t) => {
  const root = await mkdtemp(join(tmpdir(), "devspace-v2-mcp-runtime-generation-"));
  t.after(() => rm(root, { recursive: true, force: true }));
  const routePath = join(root, "routes.json");
  const targetPath = join(root, "targets.json");
  const profilePath = join(root, "profiles.json");
  const writeTarget = async (platform: "macos" | "linux", shell: "zsh" | "sh") => {
    await writeFile(targetPath, JSON.stringify({
      version: 1,
      targets: {
        local: {
          displayName: "Local",
          aliases: ["local"],
          transport: "local",
          platform,
          shell,
        },
      },
    }, null, 2));
  };
  const writeProfile = async (value: string) => {
    await writeFile(profilePath, JSON.stringify({
      version: 1,
      profiles: {
        developer: {
          targets: ["local"],
          environment: { DEVSPACE_PROFILE_VALUE: value },
        },
      },
    }, null, 2), { mode: 0o600 });
    await chmod(profilePath, 0o600);
  };
  await writeTarget("macos", "zsh");
  await writeProfile("one");
  await writeRouteFile(routePath, {
    fixture: {
      displayName: "Fixture",
      transport: "local-stdio",
      command: process.execPath,
      args: ["--version"],
      envProfile: "developer",
    },
  });
  let providerDispatches = 0;
  const proxy = new UniversalMcpProxy(
    new UniversalMcpRouteRegistry(routePath),
    new TargetRegistry({ configPath: targetPath }),
    {
      sshControlDir: join(root, "ssh"),
      envProfiles: new UniversalEnvProfileRegistry({ configPath: profilePath }),
      clientFactory: async (route) => ({
        route,
        routeFingerprint: route.generation,
        client: {
          listTools: async () => ({ tools: [{ name: "read_exact", inputSchema: { type: "object" } }] }),
          callTool: async () => {
            providerDispatches += 1;
            return { content: [{ type: "text", text: "ok" }] };
          },
          close: async () => undefined,
        } as unknown as Client,
        transport: { close: async () => undefined } as DownstreamMcpSession["transport"],
        connectedAt: Date.now(),
        lastUsedAt: Date.now(),
        activeCalls: 0,
      }),
    },
  );
  t.after(() => proxy.close());

  const targetStale = await proxy.prepareInvocation({
    operation: "invoke",
    route: "fixture",
    name: "read_exact",
  });
  await writeTarget("linux", "sh");
  await assert.rejects(targetStale.execute(), hasCode("AUTHORITY_STALE"));
  assert.equal(providerDispatches, 0);

  const profileStale = await proxy.prepareInvocation({
    operation: "invoke",
    route: "fixture",
    name: "read_exact",
  });
  await writeProfile("two");
  await assert.rejects(profileStale.execute(), hasCode("AUTHORITY_STALE"));
  assert.equal(providerDispatches, 0);
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

async function writePolicyRoute(routePath: string, policyPath: string): Promise<void> {
  await writeRouteFile(routePath, {
    fixture: {
      displayName: "Fixture",
      transport: "local-stdio",
      command: process.execPath,
      args: ["--version"],
      riskPolicy: { mode: "broker-owned", policyFile: policyPath },
    },
  });
}

async function writeRiskPolicy(
  path: string,
  risk: "R0" | "R2" | "R3",
  toolContractSha256: string,
): Promise<void> {
  await writeFile(path, JSON.stringify({
    version: 1,
    routeId: "fixture",
    tools: { read_exact: { risk, toolContractSha256 } },
  }, null, 2), { mode: 0o600 });
  await chmod(path, 0o600);
}

function hasCode(code: string) {
  return (error: unknown) => error instanceof Error && "code" in error && error.code === code;
}

function owner(label: string) {
  return createCapabilityCallContextFromTrustedPrincipal({
    principalKeyFingerprint: createHash("sha256").update(label).digest("hex"),
  });
}
