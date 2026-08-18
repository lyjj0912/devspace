import assert from "node:assert/strict";
import { createHash, randomUUID } from "node:crypto";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { request as httpRequest } from "node:http";
import type { AddressInfo } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Readable } from "node:stream";
import test from "node:test";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";
import { loadConfig } from "../config.js";
import type { IncomingArtifactAdapter } from "../incoming-artifacts.js";
import { SqliteOAuthStore } from "../oauth-store.js";
import { UNIVERSAL_OWNER_SCOPES, UNIVERSAL_TOOL_NAMES } from "./contracts.js";
import type { GuiNodeRunner } from "./gui.js";
import {
  authenticatedBrokerScopes,
  createUniversalBrokerNextServer,
} from "./http-server.js";
import { loadUniversalBrokerNextConfig, OAUTH_OFFLINE_ACCESS_SCOPE } from "./config.js";
import { UniversalSelfManagementService } from "./self-management.js";

function guiObservation(applicationName: string) {
  return {
    application: {
      name: applicationName,
      bundleIdentifier: "com.example.http-gui",
      pid: 4321,
    },
    window: {
      title: "HTTP GUI Fixture",
      role: "AXWindow",
      subrole: "AXStandardWindow",
      position: [0, 0],
      size: [800, 600],
    },
    elements: [
      {
        elementId: "e0",
        index: 0,
        role: "AXWindow",
        subrole: "AXStandardWindow",
        name: "HTTP GUI Fixture",
        description: "",
        value: "",
        enabled: true,
        focused: true,
        position: [0, 0],
        size: [800, 600],
        actions: [],
      },
      {
        elementId: "e1",
        index: 1,
        role: "AXButton",
        subrole: "",
        name: "Confirm",
        description: "confirm",
        value: "",
        enabled: true,
        focused: false,
        position: [100, 100],
        size: [80, 24],
        actions: ["AXPress"],
      },
    ],
    totalElements: 2,
    omittedElements: 0,
    truncated: false,
  };
}


async function requestStatus(url: string, host: string): Promise<number> {
  return new Promise<number>((resolve, reject) => {
    const request = httpRequest(url, { headers: { Host: host } }, (response) => {
      response.resume();
      response.once("end", () => resolve(response.statusCode ?? 0));
    });
    request.once("error", reject);
    request.end();
  });
}

interface AuthorizedCall {
  taskId: string;
  authorityText: string;
  tool: "context" | "fs" | "exec" | "process" | "mcp" | "artifact" | "gui";
  arguments: Record<string, unknown>;
  risk?: "R1" | "R2" | "R3";
  uses?: number;
}

async function prepareAuthority(client: Client, input: AuthorizedCall): Promise<string> {
  const prepared = await client.callTool({
    name: "context",
    arguments: {
      operation: "authorize",
      taskId: input.taskId,
      authorityText: input.authorityText,
      actions: [{
        tool: input.tool,
        arguments: input.arguments,
        ...(input.risk ? { risk: input.risk } : {}),
        ...(input.uses ? { uses: input.uses } : {}),
      }],
    },
  });
  assert.notEqual(prepared.isError, true, JSON.stringify(prepared.structuredContent));
  const authorityId = (prepared.structuredContent as {
    data?: { authorityId?: string };
  } | undefined)?.data?.authorityId;
  assert.equal(typeof authorityId, "string");
  return authorityId!;
}

async function callAuthorized(client: Client, input: AuthorizedCall) {
  const authorityId = await prepareAuthority(client, input);
  return client.callTool({
    name: input.tool,
    arguments: { ...input.arguments, authorityId },
  });
}

test("granular scopes are mandatory and legacy compatibility cannot be re-enabled", async (t) => {
  const root = await mkdtemp(join(tmpdir(), "devspace-v2-granular-scope-test-"));
  t.after(() => rm(root, { recursive: true, force: true }));
  const base = loadConfig({
    DEVSPACE_CONFIG_DIR: join(root, "config"),
    DEVSPACE_ALLOWED_ROOTS: root,
    DEVSPACE_STATE_DIR: join(root, "state"),
    DEVSPACE_WORKTREE_ROOT: join(root, "worktrees"),
    DEVSPACE_OAUTH_OWNER_TOKEN: "v2-granular-scope-test-owner-token-not-a-real-secret",
    DEVSPACE_HOST: "127.0.0.1",
    DEVSPACE_PORT: "7676",
    DEVSPACE_PUBLIC_BASE_URL: "http://127.0.0.1:7676",
    DEVSPACE_LOG_LEVEL: "silent",
  });
  const production = loadUniversalBrokerNextConfig(base, {
    DEVSPACE_V2_DEPLOYMENT_MODE: "production",
  });
  assert.equal(authenticatedBrokerScopes(["devspace"], production), undefined);
  assert.equal(
    authenticatedBrokerScopes(["devspace.read", "unrecognized"], production),
    undefined,
  );
  assert.deepEqual(
    authenticatedBrokerScopes(["devspace.read", "devspace.read"], production),
    ["devspace.read"],
  );
  assert.throws(
    () => loadUniversalBrokerNextConfig(base, {
      DEVSPACE_V2_DEPLOYMENT_MODE: "production",
      DEVSPACE_V2_LEGACY_SCOPE_COMPATIBILITY: "true",
    }),
    /removed in Universal Broker v2\.1/u,
  );
});

test("production HTTP rejects legacy-scope tokens and accepts granular tokens", async (t) => {
  const root = await mkdtemp(join(tmpdir(), "devspace-v2-production-oauth-test-"));
  t.after(() => rm(root, { recursive: true, force: true }));
  const base = loadConfig({
    DEVSPACE_CONFIG_DIR: join(root, "config"),
    DEVSPACE_ALLOWED_ROOTS: root,
    DEVSPACE_STATE_DIR: join(root, "legacy-oauth-state"),
    DEVSPACE_WORKTREE_ROOT: join(root, "legacy-worktrees"),
    DEVSPACE_OAUTH_OWNER_TOKEN: "v2-production-oauth-test-owner-not-a-real-secret",
    DEVSPACE_HOST: "127.0.0.1",
    DEVSPACE_PORT: "7676",
    DEVSPACE_PUBLIC_BASE_URL: "http://127.0.0.1:7676",
    DEVSPACE_LOG_LEVEL: "silent",
  });
  const config = loadUniversalBrokerNextConfig(base, {
    DEVSPACE_V2_DEPLOYMENT_MODE: "production",
    DEVSPACE_NEXT_STATE_DIR: join(root, "v2-production-state"),
  });
  const legacyToken = `legacy-${randomUUID()}`;
  const granularToken = `granular-${randomUUID()}`;
  const store = new SqliteOAuthStore(config.oauthStateDir);
  const registered = store.registerClient({
    redirect_uris: ["http://127.0.0.1/callback"],
    client_name: "Granular scope enforcement test",
    token_endpoint_auth_method: "none",
    grant_types: ["authorization_code", "refresh_token"],
    response_types: ["code"],
  }, config.oauth.allowedRedirectHosts);
  for (const [token, scopes] of [
    [legacyToken, ["devspace"]],
    [granularToken, [...config.oauth.scopes]],
  ] as const) {
    store.saveAccessToken(createHash("sha256").update(token).digest("base64url"), {
      clientId: registered.client_id,
      scopes: [...scopes],
      expiresAt: Math.floor(Date.now() / 1000) + 300,
      resource: config.publicMcpUrl,
    });
  }
  store.close();

  const running = createUniversalBrokerNextServer(config, { incomingArtifactAdapters: [] });
  const http = running.app.listen(0, "127.0.0.1");
  await new Promise<void>((resolve, reject) => {
    http.once("listening", resolve);
    http.once("error", reject);
  });
  const address = http.address() as AddressInfo;
  const endpoint = new URL(`http://127.0.0.1:${address.port}/mcp`);
  try {
    const rejectedTransport = new StreamableHTTPClientTransport(endpoint, {
      requestInit: { headers: { Authorization: `Bearer ${legacyToken}` } },
    });
    const rejectedClient = new Client({ name: "legacy-scope-rejected-test", version: "1" });
    await assert.rejects(rejectedClient.connect(rejectedTransport));
    await Promise.allSettled([rejectedClient.close(), rejectedTransport.close()]);

    const acceptedTransport = new StreamableHTTPClientTransport(endpoint, {
      requestInit: { headers: { Authorization: `Bearer ${granularToken}` } },
    });
    const acceptedClient = new Client({ name: "granular-scope-accepted-test", version: "1" });
    await acceptedClient.connect(acceptedTransport);
    const listed = await acceptedClient.listTools();
    assert.deepEqual(listed.tools.map((tool) => tool.name), [...UNIVERSAL_TOOL_NAMES]);
    const targets = await acceptedClient.callTool({ name: "target", arguments: { operation: "list" } });
    assert.notEqual(targets.isError, true);
    await acceptedClient.close();
  } finally {
    await new Promise<void>((resolve) => http.close(() => resolve()));
    await running.close();
  }
});

test("parallel v2 HTTP skeleton has an independent health endpoint and protected MCP endpoint", async (t) => {
  const root = await mkdtemp(join(tmpdir(), "devspace-v2-http-test-"));
  t.after(() => rm(root, { recursive: true, force: true }));
  const mcpRoutes = join(root, "mcp-routes.json");
  const targetsFile = join(root, "targets.json");
  await writeFile(mcpRoutes, JSON.stringify({
    version: 1,
    routes: {
      fixture: {
        displayName: "Fixture MCP",
        aliases: ["fixture"],
        transport: "local-stdio",
        command: process.execPath,
        args: ["--import", "tsx", "src/v2/fixtures/mcp-fixture.ts"],
      },
    },
  }, null, 2));
  await writeFile(targetsFile, JSON.stringify({
    version: 1,
    targets: {
      local: {
        displayName: "Local",
        aliases: ["local"],
        transport: "local",
        platform: "macos",
        gui: { mode: "local-ipc" },
      },
    },
  }, null, 2));
  const base = loadConfig({
    DEVSPACE_CONFIG_DIR: join(root, "config"),
    DEVSPACE_ALLOWED_ROOTS: root,
    DEVSPACE_STATE_DIR: join(root, "state"),
    DEVSPACE_WORKTREE_ROOT: join(root, "worktrees"),
    DEVSPACE_OAUTH_OWNER_TOKEN: "v2-test-owner-token-not-a-real-secret-123456",
    DEVSPACE_HOST: "127.0.0.1",
    DEVSPACE_PORT: "7676",
    DEVSPACE_PUBLIC_BASE_URL: "http://127.0.0.1:7676",
    DEVSPACE_LOG_LEVEL: "silent",
  });
  const config = loadUniversalBrokerNextConfig(base, {
    DEVSPACE_NEXT_PUBLIC_BASE_URL: "http://127.0.0.1:17677/v2",
    DEVSPACE_NEXT_MCP_ROUTES_FILE: mcpRoutes,
    DEVSPACE_NEXT_TARGETS_FILE: targetsFile,
  });
  const nativeArtifactAdapter: IncomingArtifactAdapter = {
    id: "http-fixture",
    canHandle(value) {
      return Boolean(
        value
        && typeof value === "object"
        && (value as { httpFixture?: boolean }).httpFixture === true
      );
    },
    async open() {
      const content = Buffer.from("native-http-artifact\n");
      return {
        name: "native-http.txt",
        mimeType: "text/plain",
        size: content.length,
        stream: Readable.from(content),
      };
    },
  };
  let guiState = guiObservation("Before GUI action");
  const guiRunner: GuiNodeRunner = {
    async call(_target, request) {
      if (request.operation === "capabilities") {
        return {
          platform: "macos",
          accessibility: true,
          screenCapture: "not_probed",
          frontmostProcess: {
            name: guiState.application.name,
            pid: guiState.application.pid,
          },
        };
      }
      if (request.operation === "observe") return structuredClone(guiState);
      guiState = guiObservation("After GUI action");
      return { performed: true, actionType: request.actionType };
    },
  };
  const restartLaunches: string[] = [];
  const selfManagement = new UniversalSelfManagementService({
    stateDir: join(root, "self-management"),
    pm2ProcessName: "devspace-http-test",
    pm2Executable: "/usr/bin/true",
    localHealthUrl: "http://127.0.0.1:17691/healthz",
    expectedCwd: root,
    defaultDelayMs: 750,
    timeoutMs: 10_000,
    launchWorker(request) {
      restartLaunches.push(request.transactionId);
    },
  });
  const running = createUniversalBrokerNextServer(config, {
    incomingArtifactAdapters: [nativeArtifactAdapter],
    guiRunner,
    selfManagement,
  });
  const httpServer = running.app.listen(0, "127.0.0.1");
  await new Promise<void>((resolve, reject) => {
    httpServer.once("listening", resolve);
    httpServer.once("error", reject);
  });
  t.after(async () => {
    await new Promise<void>((resolve) => httpServer.close(() => resolve()));
    await running.close();
  });

  const address = httpServer.address() as AddressInfo;
  const origin = `http://127.0.0.1:${address.port}`;
  assert.equal(
    await requestStatus(`${origin}${config.metricsPath}`, `127.0.0.1:${address.port}`),
    200,
  );
  assert.equal(
    await requestStatus(`${origin}${config.metricsPath}`, "home-ai.example.test"),
    403,
  );
  const health = await fetch(`${origin}/healthz-next`);
  assert.equal(health.status, 200);
  const healthBody = await health.json() as {
    ok: boolean;
    name: string;
    phase: string;
    targetGeneration: string;
    targetCount: number;
    mcpRouteGeneration: string;
    mcpRouteCount: number;
  };
  assert.equal(healthBody.ok, true);
  assert.equal(healthBody.name, "devspace-universal-broker");
  assert.equal(healthBody.phase, "universal-broker-v2");
  assert.equal(healthBody.targetCount, 1);
  assert.equal(healthBody.mcpRouteCount, 1);
  assert.equal(typeof healthBody.targetGeneration, "string");
  assert.equal(typeof healthBody.mcpRouteGeneration, "string");
  assert.deepEqual({ ok: healthBody.ok, name: healthBody.name }, {
    ok: true,
    name: "devspace-universal-broker",
  });

  const authorizationMetadata = await fetch(
    `${origin}/.well-known/oauth-authorization-server`,
  );
  assert.equal(authorizationMetadata.status, 200);
  const authorizationMetadataBody = await authorizationMetadata.json() as {
    issuer?: string;
    authorization_endpoint?: string;
    token_endpoint?: string;
    registration_endpoint?: string;
    scopes_supported?: string[];
  };
  assert.equal(authorizationMetadataBody.issuer, "http://127.0.0.1:17677/v2/");
  assert.equal(
    authorizationMetadataBody.authorization_endpoint,
    "http://127.0.0.1:17677/v2/authorize",
  );
  assert.equal(
    authorizationMetadataBody.token_endpoint,
    "http://127.0.0.1:17677/v2/token",
  );
  assert.equal(
    authorizationMetadataBody.registration_endpoint,
    "http://127.0.0.1:17677/v2/register",
  );
  assert.deepEqual(
    authorizationMetadataBody.scopes_supported,
    [...UNIVERSAL_OWNER_SCOPES, OAUTH_OFFLINE_ACCESS_SCOPE],
  );

  const unauthenticated = await fetch(`${origin}${config.endpointPath}`);
  assert.equal(unauthenticated.status, 401);
  assert.match(
    unauthenticated.headers.get("www-authenticate") ?? "",
    /resource_metadata="http:\/\/127\.0\.0\.1:17677\/v2\/\.well-known\/oauth-protected-resource\/v2\/mcp-next"/u,
  );

  const token = `v2-test-${randomUUID()}`;
  const oauthStore = new SqliteOAuthStore(config.stateDir);
  const registered = oauthStore.registerClient({
    redirect_uris: ["http://127.0.0.1/callback"],
    client_name: "Universal Broker v2 HTTP test",
    token_endpoint_auth_method: "none",
    grant_types: ["authorization_code", "refresh_token"],
    response_types: ["code"],
  }, config.oauth.allowedRedirectHosts);
  oauthStore.saveAccessToken(createHash("sha256").update(token).digest("base64url"), {
    clientId: registered.client_id,
    scopes: config.oauth.scopes,
    expiresAt: Math.floor(Date.now() / 1000) + 300,
    resource: config.publicMcpUrl,
  });
  oauthStore.close();

  const transport = new StreamableHTTPClientTransport(
    new URL(`${origin}${config.endpointPath}`),
    {
      requestInit: {
        headers: { Authorization: `Bearer ${token}` },
      },
    },
  );
  const client = new Client({ name: "v2-http-test", version: "1.0.0" });
  await client.connect(transport);
  try {
    const tools = await client.listTools();
    assert.deepEqual(tools.tools.map((tool) => tool.name), [...UNIVERSAL_TOOL_NAMES]);
    const target = await client.callTool({
      name: "target",
      arguments: { operation: "list" },
    });
    assert.notEqual(target.isError, true);
    const targetStructured = target.structuredContent as {
      data?: {
        targets?: Array<{ targetId?: string }>;
      };
    } | undefined;
    const targetData = targetStructured?.data as {
      targets?: Array<{ targetId?: string }>;
    } | undefined;
    assert.equal(targetData?.targets?.[0]?.targetId, "local");

    const generationBoundPath = join(root, "generation-bound.txt");
    const generationBoundArguments = {
      operation: "write",
      target: "local",
      path: generationBoundPath,
      content: "must-not-write-after-registry-change\n",
    };
    const generationAuthorityId = await prepareAuthority(client, {
      taskId: "target-generation-bound-write",
      authorityText: "Write only while the exact target registry generation remains unchanged.",
      tool: "fs",
      arguments: generationBoundArguments,
      risk: "R1",
    });
    await writeFile(targetsFile, JSON.stringify({
      version: 1,
      targets: {
        local: {
          displayName: "Local changed after authorization",
          aliases: ["local"],
          transport: "local",
          platform: "macos",
          gui: { mode: "local-ipc" },
        },
      },
    }, null, 2));
    const staleGeneration = await client.callTool({
      name: "fs",
      arguments: { ...generationBoundArguments, authorityId: generationAuthorityId },
    });
    assert.equal(staleGeneration.isError, true);
    assert.equal(
      (staleGeneration.structuredContent as { error?: { code?: string } } | undefined)?.error?.code,
      "AUTHORITY_MISMATCH",
    );
    await assert.rejects(readFile(generationBoundPath, "utf8"), { code: "ENOENT" });
    await writeFile(targetsFile, JSON.stringify({
      version: 1,
      targets: {
        local: {
          displayName: "Local",
          aliases: ["local"],
          transport: "local",
          platform: "macos",
          gui: { mode: "local-ipc" },
        },
      },
    }, null, 2));

    const missing = join(root, "does-not-exist");
    const context = await client.callTool({
      name: "context",
      arguments: { operation: "open", path: missing },
    });
    assert.equal(context.isError, true);
    const contextStructured = context.structuredContent as {
      error?: { code?: string };
    } | undefined;
    const contextError = contextStructured?.error;
    assert.equal(contextError?.code, "PATH_NOT_FOUND");

    const filePath = join(root, "http-fs-v2.txt");
    const fileWrite = await callAuthorized(client, {
      taskId: "http-fs-write",
      authorityText: "Write this exact local fixture file.",
      tool: "fs",
      arguments: {
        operation: "write",
        path: filePath,
        content: "http-filesystem-v2\n",
      },
    });
    assert.notEqual(fileWrite.isError, true);
    const fileRead = await client.callTool({
      name: "fs",
      arguments: {
        operation: "read",
        path: filePath,
      },
    });
    const fileReadData = (fileRead.structuredContent as {
      data?: { content?: string; encoding?: string };
    } | undefined)?.data;
    assert.equal(fileReadData?.encoding, "utf8");
    assert.equal(fileReadData?.content, "http-filesystem-v2\n");
    const fileRemove = await callAuthorized(client, {
      taskId: "http-fs-remove",
      authorityText: "Permanently remove this exact fixture file once.",
      tool: "fs",
      arguments: {
        operation: "remove",
        path: filePath,
        disposition: "permanent",
      },
      risk: "R3",
    });
    assert.notEqual(fileRemove.isError, true);

    const mcpRoutesResult = await client.callTool({
      name: "mcp",
      arguments: { operation: "routes" },
    });
    const mcpRoutesData = (mcpRoutesResult.structuredContent as {
      data?: { routes?: Array<{ routeId?: string }> };
    } | undefined)?.data;
    assert.equal(mcpRoutesData?.routes?.[0]?.routeId, "fixture");

    const mcpWrite = await callAuthorized(client, {
      taskId: "http-mcp-write",
      authorityText: "Set this exact fixture key and value.",
      tool: "mcp",
      arguments: {
        operation: "invoke",
        route: "fixture",
        name: "write_value",
        arguments: { key: "http", value: "proxied" },
      },
      risk: "R2",
    });
    assert.notEqual(mcpWrite.isError, true);
    const mcpRead = await callAuthorized(client, {
      taskId: "http-mcp-read-invocation",
      authorityText: "Invoke this exact downstream MCP tool and read this exact fixture key.",
      tool: "mcp",
      arguments: {
        operation: "invoke",
        route: "fixture",
        name: "read_value",
        arguments: { key: "http" },
      },
      risk: "R2",
    });
    assert.match(JSON.stringify(mcpRead.structuredContent), /proxied/);

    const routeArgs = {
      operation: "invoke",
      route: "fixture",
      name: "write_value",
      arguments: { key: "route-change", value: "blocked" },
    };
    const routeAuthority = await prepareAuthority(client, {
      taskId: "mcp-route-version-bound",
      authorityText: "Invoke only while this configured route version is unchanged.",
      tool: "mcp",
      arguments: routeArgs,
      risk: "R2",
    });
    await writeFile(mcpRoutes, JSON.stringify({
      version: 1,
      routes: {
        fixture: {
          displayName: "Fixture MCP updated",
          aliases: ["fixture"],
          transport: "local-stdio",
          command: process.execPath,
          args: ["--import", "tsx", "src/v2/fixtures/mcp-fixture.ts"],
        },
      },
    }, null, 2));
    const changedRouteResult = await client.callTool({
      name: "mcp",
      arguments: { ...routeArgs, authorityId: routeAuthority },
    });
    assert.equal(changedRouteResult.isError, true);
    assert.equal(
      (changedRouteResult.structuredContent as { error?: { code?: string } } | undefined)?.error?.code,
      "AUTHORITY_MISMATCH",
    );
    await writeFile(mcpRoutes, JSON.stringify({
      version: 1,
      routes: {
        fixture: {
          displayName: "Fixture MCP",
          aliases: ["fixture"],
          transport: "local-stdio",
          command: process.execPath,
          args: ["--import", "tsx", "src/v2/fixtures/mcp-fixture.ts"],
        },
      },
    }, null, 2));
    const restoredMcpWrite = await callAuthorized(client, {
      taskId: "http-mcp-write-after-route-reload",
      authorityText: "Restore the exact fixture state after the route reload regression check.",
      tool: "mcp",
      arguments: {
        operation: "invoke",
        route: "fixture",
        name: "write_value",
        arguments: { key: "http", value: "proxied" },
      },
      risk: "R2",
    });
    assert.notEqual(restoredMcpWrite.isError, true);

    const mcpResource = await client.callTool({
      name: "mcp",
      arguments: {
        operation: "read_resource",
        route: "fixture",
        uri: "fixture://state",
      },
    });
    assert.match(JSON.stringify(mcpResource.structuredContent), /http/);

    const mcpPrompt = await client.callTool({
      name: "mcp",
      arguments: {
        operation: "get_prompt",
        route: "fixture",
        name: "fixture_prompt",
        arguments: { subject: "HTTP proxy" },
      },
    });
    assert.match(JSON.stringify(mcpPrompt.structuredContent), /Inspect HTTP proxy/);

    const mcpLarge = await callAuthorized(client, {
      taskId: "http-mcp-large-result",
      authorityText: "Invoke this exact downstream MCP large-result canary.",
      tool: "mcp",
      arguments: {
        operation: "invoke",
        route: "fixture",
        name: "large_result",
        arguments: { characters: 20_000 },
        responsePolicy: { maxCharacters: 500, preserveFullResult: true },
      },
      risk: "R2",
    });
    const largeData = (mcpLarge.structuredContent as {
      data?: { result?: { resourceUri?: string; truncated?: boolean } };
    } | undefined)?.data?.result;
    assert.equal(largeData?.truncated, true);
    assert.equal(typeof largeData?.resourceUri, "string");
    const mcpResultResource = await client.readResource({ uri: largeData!.resourceUri! });
    const mcpResultContent = mcpResultResource.contents[0];
    assert.ok(mcpResultContent && "text" in mcpResultContent);
    assert.match(mcpResultContent.text, /^\{"content"/);
    assert.equal(mcpResultContent.text.length, 12_000);
    const mcpResultMeta = mcpResultContent._meta as {
      truncated?: boolean;
      nextResourceUri?: string;
    } | undefined;
    assert.equal(mcpResultMeta?.truncated, true);
    assert.equal(typeof mcpResultMeta?.nextResourceUri, "string");

    const mcpDelete = await callAuthorized(client, {
      taskId: "http-mcp-delete",
      authorityText: "Delete this exact fixture key once.",
      tool: "mcp",
      arguments: {
        operation: "invoke",
        route: "fixture",
        name: "delete_value",
        arguments: { key: "http" },
      },
      risk: "R3",
    });
    assert.notEqual(mcpDelete.isError, true);

    const receivedPath = join(root, "http-artifact-received.txt");
    const copiedPath = join(root, "http-artifact-copied.txt");
    const artifactReceive = await callAuthorized(client, {
      taskId: "http-artifact-receive",
      authorityText: "Receive this exact fixture artifact at the exact local path.",
      tool: "artifact",
      arguments: {
        operation: "receive",
        source: { file: { httpFixture: true } },
        destination: { path: receivedPath },
      },
    });
    assert.notEqual(artifactReceive.isError, true);
    const artifactReceiveData = (artifactReceive.structuredContent as {
      data?: { sourceKind?: string; size?: number };
    } | undefined)?.data;
    assert.equal(artifactReceiveData?.sourceKind, "native:http-fixture");
    assert.equal(artifactReceiveData?.size, 21);

    const receivedRead = await client.callTool({
      name: "fs",
      arguments: { operation: "read", path: receivedPath },
    });
    const receivedReadData = (receivedRead.structuredContent as {
      data?: { content?: string };
    } | undefined)?.data;
    assert.equal(receivedReadData?.content, "native-http-artifact\n");

    const artifactCopy = await callAuthorized(client, {
      taskId: "http-artifact-copy",
      authorityText: "Copy this exact local artifact to the exact destination.",
      tool: "artifact",
      arguments: {
        operation: "copy",
        source: { path: receivedPath },
        destination: { path: copiedPath },
      },
    });
    assert.notEqual(artifactCopy.isError, true);
    const copiedRead = await client.callTool({
      name: "fs",
      arguments: { operation: "read", path: copiedPath },
    });
    const copiedReadData = (copiedRead.structuredContent as {
      data?: { content?: string };
    } | undefined)?.data;
    assert.equal(copiedReadData?.content, "native-http-artifact\n");

    const artifactPublish = await callAuthorized(client, {
      taskId: "http-artifact-publish",
      authorityText: "Publish this exact artifact for sixty seconds.",
      tool: "artifact",
      arguments: {
        operation: "publish",
        source: {
          path: copiedPath,
          name: "published-http-artifact.txt",
          mimeType: "text/plain",
        },
        ttlSeconds: 60,
      },
      risk: "R2",
    });
    assert.notEqual(artifactPublish.isError, true);
    const publishedData = (artifactPublish.structuredContent as {
      data?: { resourceUri?: string; oneTime?: boolean };
    } | undefined)?.data;
    assert.equal(publishedData?.oneTime, true);
    assert.equal(typeof publishedData?.resourceUri, "string");
    const artifactPublishContent = artifactPublish.content as Array<{
      type?: string;
      name?: string;
      uri?: string;
    }>;
    const resourceLink = artifactPublishContent.find(
      (entry) => entry.type === "resource_link",
    );
    assert.ok(resourceLink && resourceLink.type === "resource_link");
    assert.equal(resourceLink.name, "published-http-artifact.txt");

    for (const path of [receivedPath, copiedPath]) {
      const removed = await callAuthorized(client, {
        taskId: `http-artifact-cleanup-${path}`,
        authorityText: "Permanently remove this exact fixture artifact once.",
        tool: "fs",
        arguments: {
          operation: "remove",
          path,
          disposition: "permanent",
        },
        risk: "R3",
      });
      assert.notEqual(removed.isError, true);
    }

    const guiCapabilities = await client.callTool({
      name: "gui",
      arguments: { operation: "capabilities", target: "local" },
    });
    const guiCapabilitiesData = (guiCapabilities.structuredContent as {
      data?: { available?: boolean; accessibility?: boolean };
    } | undefined)?.data;
    assert.equal(guiCapabilitiesData?.available, true);
    assert.equal(guiCapabilitiesData?.accessibility, true);

    const guiObserved = await client.callTool({
      name: "gui",
      arguments: { operation: "observe", target: "local", maxElements: 50 },
    });
    const guiObservedData = (guiObserved.structuredContent as {
      data?: {
        sessionId?: string;
        generation?: string;
        elements?: Array<{ elementId?: string; name?: string }>;
      };
    } | undefined)?.data;
    const confirmElement = guiObservedData?.elements?.find(
      (element) => element.name === "Confirm",
    );
    assert.equal(typeof guiObservedData?.sessionId, "string");
    assert.equal(typeof guiObservedData?.generation, "string");
    assert.equal(confirmElement?.elementId, "e1");

    const guiActed = await callAuthorized(client, {
      taskId: "http-gui-act",
      authorityText: "Press the exact observed Confirm element once.",
      tool: "gui",
      arguments: {
        operation: "act",
        target: "local",
        sessionId: guiObservedData!.sessionId!,
        generation: guiObservedData!.generation!,
        action: {
          type: "perform",
          elementId: confirmElement!.elementId!,
          actionName: "AXPress",
        },
      },
      risk: "R3",
    });
    assert.notEqual(guiActed.isError, true);
    const guiActedData = (guiActed.structuredContent as {
      data?: {
        performed?: Record<string, unknown>;
        observation?: { application?: { name?: string } };
      };
    } | undefined)?.data;
    assert.equal(guiActedData?.observation?.application?.name, "After GUI action");

    const executed = await client.callTool({
      name: "exec",
      arguments: {
        target: "local",
        cwd: root,
        command: "printf 'http-exec-v2'",
        mode: "auto",
        yieldMs: 2_000,
      },
    });
    assert.notEqual(executed.isError, true);
    const executedData = (executed.structuredContent as {
      data?: { state?: string; output?: string; resourceUri?: string };
    } | undefined)?.data;
    assert.equal(executedData?.state, "EXITED");
    assert.equal(executedData?.output, "http-exec-v2");
    assert.equal(typeof executedData?.resourceUri, "string");
    const resource = await client.readResource({ uri: executedData!.resourceUri! });
    const resourceContent = resource.contents[0];
    assert.ok(resourceContent && "text" in resourceContent);
    assert.equal(resourceContent.text, "http-exec-v2");

    const background = await callAuthorized(client, {
      taskId: "http-background-exec",
      authorityText: "Start this exact short-lived local background command.",
      tool: "exec",
      arguments: {
        target: "local",
        cwd: root,
        command: "sleep 0.1; printf 'http-background-v2'",
        mode: "background",
      },
      risk: "R1",
    });
    const backgroundData = (background.structuredContent as {
      data?: { processId?: string; state?: string };
    } | undefined)?.data;
    assert.equal(backgroundData?.state, "RUNNING");
    const waited = await client.callTool({
      name: "process",
      arguments: {
        operation: "wait",
        processId: backgroundData!.processId!,
        waitMs: 2_000,
      },
    });
    const waitedData = (waited.structuredContent as {
      data?: { state?: string; output?: string };
    } | undefined)?.data;
    assert.equal(waitedData?.state, "EXITED");
    assert.match(waitedData?.output ?? "", /http-background-v2/);

    const restartRequested = await callAuthorized(client, {
      taskId: "http-self-restart",
      authorityText: "Restart the broker through one durable transaction.",
      tool: "process",
      arguments: {
        operation: "restart_broker",
        reason: "HTTP integration restart",
        delayMs: 750,
      },
      risk: "R3",
    });
    assert.notEqual(restartRequested.isError, true);
    const restartData = (restartRequested.structuredContent as {
      data?: { transactionId?: string; state?: string; expectedDisconnect?: boolean };
    } | undefined)?.data;
    assert.equal(restartData?.state, "REQUESTED");
    assert.equal(restartData?.expectedDisconnect, true);
    assert.deepEqual(restartLaunches, [restartData!.transactionId!]);
    const restartStatus = await client.callTool({
      name: "process",
      arguments: {
        operation: "restart_status",
        transactionId: restartData!.transactionId!,
      },
    });
    const restartStatusData = (restartStatus.structuredContent as {
      data?: { state?: string; transactionId?: string };
    } | undefined)?.data;
    assert.equal(restartStatusData?.state, "REQUESTED");
    assert.equal(restartStatusData?.transactionId, restartData?.transactionId);
  } finally {
    await client.close();
  }
});
