import assert from "node:assert/strict";
import { createHash, randomUUID } from "node:crypto";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
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
import { createUniversalBrokerNextServer } from "./http-server.js";
import { loadUniversalBrokerNextConfig } from "./config.js";

test("parallel v2 HTTP skeleton has an independent health endpoint and protected MCP endpoint", async (t) => {
  const root = await mkdtemp(join(tmpdir(), "devspace-v2-http-test-"));
  t.after(() => rm(root, { recursive: true, force: true }));
  const mcpRoutes = join(root, "mcp-routes.json");
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
    DEVSPACE_NEXT_PUBLIC_BASE_URL: "http://127.0.0.1:17677",
    DEVSPACE_NEXT_MCP_ROUTES_FILE: mcpRoutes,
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
  const running = createUniversalBrokerNextServer(config, {
    incomingArtifactAdapters: [nativeArtifactAdapter],
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
  assert.equal(healthBody.phase, "phase-7-artifact");
  assert.equal(healthBody.targetCount, 1);
  assert.equal(healthBody.mcpRouteCount, 1);
  assert.equal(typeof healthBody.targetGeneration, "string");
  assert.equal(typeof healthBody.mcpRouteGeneration, "string");
  assert.deepEqual({ ok: healthBody.ok, name: healthBody.name }, {
    ok: true,
    name: "devspace-universal-broker",
  });

  const unauthenticated = await fetch(`${origin}${config.endpointPath}`);
  assert.equal(unauthenticated.status, 401);

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
    resource: new URL(config.endpointPath, config.publicBaseUrl).href,
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
