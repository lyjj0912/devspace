import assert from "node:assert/strict";
import { createHash, randomUUID } from "node:crypto";
import { mkdtemp, rm } from "node:fs/promises";
import type { AddressInfo } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";
import { loadConfig } from "../config.js";
import { SqliteOAuthStore } from "../oauth-store.js";
import { UNIVERSAL_TOOL_NAMES } from "./contracts.js";
import { createUniversalBrokerNextServer } from "./http-server.js";
import { loadUniversalBrokerNextConfig } from "./config.js";

test("parallel v2 HTTP skeleton has an independent health endpoint and protected MCP endpoint", async (t) => {
  const root = await mkdtemp(join(tmpdir(), "devspace-v2-http-test-"));
  t.after(() => rm(root, { recursive: true, force: true }));
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
  });
  const running = createUniversalBrokerNextServer(config);
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
  assert.deepEqual(await health.json(), {
    ok: true,
    name: "devspace-universal-broker",
    phase: "phase-1-skeleton",
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
    assert.equal(target.isError, true);
  } finally {
    await client.close();
  }
});
