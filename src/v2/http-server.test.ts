import assert from "node:assert/strict";
import { createHash, randomUUID } from "node:crypto";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
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
import { UNIVERSAL_TOOL_NAMES } from "./contracts.js";
import type { GuiNodeRunner } from "./gui.js";
import {
  authenticatedBrokerScopes,
  createUniversalBrokerNextServer,
} from "./http-server.js";
import { loadUniversalBrokerNextConfig } from "./config.js";

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

test("legacy devspace scope expands only in temporary production compatibility mode", async (t) => {
  const root = await mkdtemp(join(tmpdir(), "devspace-v2-legacy-scope-test-"));
  t.after(() => rm(root, { recursive: true, force: true }));
  const base = loadConfig({
    DEVSPACE_CONFIG_DIR: join(root, "config"),
    DEVSPACE_ALLOWED_ROOTS: root,
    DEVSPACE_STATE_DIR: join(root, "state"),
    DEVSPACE_WORKTREE_ROOT: join(root, "worktrees"),
    DEVSPACE_OAUTH_OWNER_TOKEN: "v2-legacy-scope-test-owner-token-not-a-real-secret",
    DEVSPACE_HOST: "127.0.0.1",
    DEVSPACE_PORT: "7676",
    DEVSPACE_PUBLIC_BASE_URL: "http://127.0.0.1:7676",
    DEVSPACE_LOG_LEVEL: "silent",
  });
  const parallel = loadUniversalBrokerNextConfig(base, {});
  assert.equal(authenticatedBrokerScopes(["devspace"], parallel), undefined);

  const production = loadUniversalBrokerNextConfig(base, {
    DEVSPACE_V2_DEPLOYMENT_MODE: "production",
  });
  assert.deepEqual(
    authenticatedBrokerScopes(["devspace"], production),
    ["devspace", ...production.oauth.scopes],
  );

  const granularOnly = loadUniversalBrokerNextConfig(base, {
    DEVSPACE_V2_DEPLOYMENT_MODE: "production",
    DEVSPACE_V2_LEGACY_SCOPE_COMPATIBILITY: "false",
  });
  assert.equal(authenticatedBrokerScopes(["devspace"], granularOnly), undefined);
  assert.deepEqual(
    authenticatedBrokerScopes(["devspace.read"], granularOnly),
    ["devspace.read"],
  );
});
test("production HTTP accepts existing legacy-scope tokens only while compatibility is enabled", async (t) => {
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
  const token = `legacy-${randomUUID()}`;
  const store = new SqliteOAuthStore(config.oauthStateDir);
  const registered = store.registerClient({
    redirect_uris: ["http://127.0.0.1/callback"],
    client_name: "Legacy scope migration test",
    token_endpoint_auth_method: "none",
    grant_types: ["authorization_code", "refresh_token"],
    response_types: ["code"],
  }, config.oauth.allowedRedirectHosts);
  store.saveAccessToken(createHash("sha256").update(token).digest("base64url"), {
    clientId: registered.client_id,
    scopes: ["devspace"],
    expiresAt: Math.floor(Date.now() / 1000) + 300,
    resource: config.publicMcpUrl,
  });
  store.close();

  const compatible = createUniversalBrokerNextServer(config, { incomingArtifactAdapters: [] });
  const compatibleHttp = compatible.app.listen(0, "127.0.0.1");
  await new Promise<void>((resolve, reject) => {
    compatibleHttp.once("listening", resolve);
    compatibleHttp.once("error", reject);
  });
  const compatibleAddress = compatibleHttp.address() as AddressInfo;
  const transport = new StreamableHTTPClientTransport(
    new URL(`http://127.0.0.1:${compatibleAddress.port}/mcp`),
    { requestInit: { headers: { Authorization: `Bearer ${token}` } } },
  );
  const client = new Client({ name: "legacy-scope-production-test", version: "1" });
  await client.connect(transport);
  const listed = await client.listTools();
  assert.deepEqual(listed.tools.map((tool) => tool.name), [...UNIVERSAL_TOOL_NAMES]);
  const targets = await client.callTool({ name: "target", arguments: { operation: "list" } });
  assert.notEqual(targets.isError, true);
  await client.close();
  await new Promise<void>((resolve) => compatibleHttp.close(() => resolve()));
  await compatible.close();

  const granularOnlyConfig = loadUniversalBrokerNextConfig(base, {
    DEVSPACE_V2_DEPLOYMENT_MODE: "production",
    DEVSPACE_V2_LEGACY_SCOPE_COMPATIBILITY: "false",
    DEVSPACE_NEXT_STATE_DIR: join(root, "v2-production-granular-state"),
  });
  const granularOnly = createUniversalBrokerNextServer(granularOnlyConfig, { incomingArtifactAdapters: [] });
  const granularOnlyHttp = granularOnly.app.listen(0, "127.0.0.1");
  await new Promise<void>((resolve, reject) => {
    granularOnlyHttp.once("listening", resolve);
    granularOnlyHttp.once("error", reject);
  });
  const granularAddress = granularOnlyHttp.address() as AddressInfo;
  const rejectedTransport = new StreamableHTTPClientTransport(
    new URL(`http://127.0.0.1:${granularAddress.port}/mcp`),
    { requestInit: { headers: { Authorization: `Bearer ${token}` } } },
  );
  const rejectedClient = new Client({ name: "legacy-scope-rejected-test", version: "1" });
  await assert.rejects(rejectedClient.connect(rejectedTransport));
  await Promise.allSettled([rejectedClient.close(), rejectedTransport.close()]);
  await new Promise<void>((resolve) => granularOnlyHttp.close(() => resolve()));
  await granularOnly.close();
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
  const running = createUniversalBrokerNextServer(config, {
    incomingArtifactAdapters: [nativeArtifactAdapter],
    guiRunner,
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
    const fileWrite = await client.callTool({
      name: "fs",
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
    const fileRemove = await client.callTool({
      name: "fs",
      arguments: {
        operation: "remove",
        path: filePath,
        disposition: "permanent",
      },
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

    const mcpWrite = await client.callTool({
      name: "mcp",
      arguments: {
        operation: "invoke",
        route: "fixture",
        name: "write_value",
        arguments: { key: "http", value: "proxied" },
      },
    });
    assert.notEqual(mcpWrite.isError, true);
    const mcpRead = await client.callTool({
      name: "mcp",
      arguments: {
        operation: "invoke",
        route: "fixture",
        name: "read_value",
        arguments: { key: "http" },
      },
    });
    assert.match(JSON.stringify(mcpRead.structuredContent), /proxied/);

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

    const mcpLarge = await client.callTool({
      name: "mcp",
      arguments: {
        operation: "invoke",
        route: "fixture",
        name: "large_result",
        arguments: { characters: 20_000 },
        responsePolicy: { maxCharacters: 500, preserveFullResult: true },
      },
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

    const mcpDelete = await client.callTool({
      name: "mcp",
      arguments: {
        operation: "invoke",
        route: "fixture",
        name: "delete_value",
        arguments: { key: "http" },
      },
    });
    assert.notEqual(mcpDelete.isError, true);

    const receivedPath = join(root, "http-artifact-received.txt");
    const copiedPath = join(root, "http-artifact-copied.txt");
    const artifactReceive = await client.callTool({
      name: "artifact",
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

    const artifactCopy = await client.callTool({
      name: "artifact",
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

    const artifactPublish = await client.callTool({
      name: "artifact",
      arguments: {
        operation: "publish",
        source: {
          path: copiedPath,
          name: "published-http-artifact.txt",
          mimeType: "text/plain",
        },
        ttlSeconds: 60,
      },
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
      const removed = await client.callTool({
        name: "fs",
        arguments: {
          operation: "remove",
          path,
          disposition: "permanent",
        },
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

    const guiActed = await client.callTool({
      name: "gui",
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

    const background = await client.callTool({
      name: "exec",
      arguments: {
        target: "local",
        cwd: root,
        command: "sleep 0.1; printf 'http-background-v2'",
        mode: "background",
      },
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
  } finally {
    await client.close();
  }
});
