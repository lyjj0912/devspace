import assert from "node:assert/strict";
import { createHash, randomUUID } from "node:crypto";
import { mkdtemp, readFile, realpath, rm, writeFile } from "node:fs/promises";
import { request as httpRequest } from "node:http";
import { createServer, type AddressInfo } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Readable } from "node:stream";
import test from "node:test";
import { FINALIZATION_STORE_SCHEMA_FINGERPRINT } from "../../scripts/lib/finalization-store-contract.mjs";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";
import { loadConfig } from "../config.js";
import type { IncomingArtifactAdapter } from "../incoming-artifacts.js";
import {
  type ConnectorActivationAuthorityProof,
  type ConnectorActivationReceipt,
  SqliteOAuthStore,
  connectorActivationAuthorityActionFingerprint,
  connectorActivationAuthorityResourceKeySha256,
} from "../oauth-store.js";
import { UNIVERSAL_OWNER_SCOPES, UNIVERSAL_TOOL_NAMES } from "./contracts.js";
import type { GuiNodeRunner } from "./gui.js";
import {
  authenticatedBrokerScopes,
  createUniversalBrokerNextServer,
} from "./http-server.js";
import { loadUniversalBrokerNextConfig, OAUTH_OFFLINE_ACCESS_SCOPE } from "./config.js";
import {
  loadExistingManagementAuthorizationKey,
  managementAuthorizationHeader,
} from "./management-authorization.js";
import { UniversalSelfManagementService } from "./self-management.js";
import { createRuntimeIdentity } from "./runtime-identity.js";
import { connectorProductionRouteIdentityReadback } from "./connector-route-identity.js";

function connectorActivationProofFixture(
  receipt: ConnectorActivationReceipt,
  label: string,
): ConnectorActivationAuthorityProof {
  const binding = {
    receiptId: receipt.receiptId,
    tupleDigest: receipt.tupleDigest,
    activePreimageDigest: receipt.preimageDigest,
    finalizationPlanDigest: `sha256:${createHash("sha256")
      .update(`http-fixture-finalization-plan\0${label}`)
      .digest("hex")}`,
    canonicalName: receipt.tuple.canonicalName,
  };
  const claimedAtMs = Date.now();
  return {
    schemaVersion: 1,
    authorityId: `authority_${randomUUID()}`,
    actionClaimId: `authority_claim_${randomUUID()}`,
    actionFingerprint: connectorActivationAuthorityActionFingerprint(binding),
    resourceKeySha256: connectorActivationAuthorityResourceKeySha256(binding),
    fencingToken: 1,
    principalKeyFingerprint: createHash("sha256")
      .update(`http-fixture-principal\0${label}`)
      .digest("hex"),
    risk: "R3",
    claimState: "DISPATCHED",
    approvalAssurance: "cooperative",
    ...binding,
    evidenceDigest: `sha256:${createHash("sha256")
      .update(`http-fixture-owner-evidence\0${label}`)
      .digest("hex")}`,
    claimedAtMs,
    dispatchedAtMs: claimedAtMs + 1,
  };
}

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
    arguments: input.arguments,
    _meta: { devspace: { authorityId } },
  });
}

test("granular scopes are mandatory and legacy compatibility cannot be re-enabled", async (t) => {
  const root = await realpath(await mkdtemp(join(tmpdir(), "devspace-v2-granular-scope-test-")));
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
    DEVSPACE_NEXT_AUTHORITY_OWNER_INSTANCE_ID: "granular-scope-owner",
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
      DEVSPACE_NEXT_AUTHORITY_OWNER_INSTANCE_ID: "legacy-compatibility-owner",
    }),
    /removed in Universal Broker v2\.1/u,
  );
});

test("HTTP Core has no provider-specific incoming artifact adapter unless one is edge-injected", async (t) => {
  const root = await realpath(await mkdtemp(join(tmpdir(), "devspace-v2-http-artifact-adapter-test-")));
  const base = loadConfig({
    DEVSPACE_CONFIG_DIR: join(root, "config"),
    DEVSPACE_ALLOWED_ROOTS: root,
    DEVSPACE_STATE_DIR: join(root, "legacy-state"),
    DEVSPACE_WORKTREE_ROOT: join(root, "legacy-worktrees"),
    DEVSPACE_OAUTH_OWNER_TOKEN: "v2-artifact-adapter-owner-not-a-real-secret",
    DEVSPACE_HOST: "127.0.0.1",
    DEVSPACE_PORT: "7676",
    DEVSPACE_PUBLIC_BASE_URL: "http://127.0.0.1:7676",
    DEVSPACE_LOG_LEVEL: "silent",
  });
  const config = loadUniversalBrokerNextConfig(base, {
    DEVSPACE_NEXT_STATE_DIR: join(root, "state"),
    DEVSPACE_NEXT_AUTHORITY_OWNER_INSTANCE_ID: "http-artifact-adapter-owner",
  });
  const running = createUniversalBrokerNextServer(config);
  t.after(async () => {
    await running.close();
    await rm(root, { recursive: true, force: true });
  });

  await assert.rejects(
    running.artifacts.execute({
      operation: "receive",
      source: {
        file: {
          download_url: "https://example.com/provider-owned-file",
          file_id: "file_provider_edge_fixture",
        },
      },
    }),
    (error: unknown) => {
      assert.equal((error as { code?: string }).code, "PRECONDITION_FAILED");
      assert.match(
        error instanceof Error ? error.message : String(error),
        /requires a trusted native file reference or URL/u,
      );
      return true;
    },
  );
});

test("HTTP OAuth registration uses the shared metrics registry for connector transitions", async (t) => {
  const root = await realpath(await mkdtemp(join(tmpdir(), "devspace-v2-http-oauth-metrics-")));
  const base = loadConfig({
    DEVSPACE_CONFIG_DIR: join(root, "config"),
    DEVSPACE_ALLOWED_ROOTS: root,
    DEVSPACE_STATE_DIR: join(root, "legacy-state"),
    DEVSPACE_WORKTREE_ROOT: join(root, "legacy-worktrees"),
    DEVSPACE_OAUTH_OWNER_TOKEN: "v2-oauth-metrics-owner-not-a-real-secret",
    DEVSPACE_HOST: "127.0.0.1",
    DEVSPACE_PORT: "7676",
    DEVSPACE_PUBLIC_BASE_URL: "http://127.0.0.1:7676",
    DEVSPACE_LOG_LEVEL: "silent",
  });
  const config = loadUniversalBrokerNextConfig(base, {
    DEVSPACE_NEXT_STATE_DIR: join(root, "state"),
    DEVSPACE_NEXT_AUTHORITY_OWNER_INSTANCE_ID: "http-oauth-metrics-owner",
    DEVSPACE_NEXT_PUBLIC_BASE_URL: "http://127.0.0.1:17677/v2",
  });
  const running = createUniversalBrokerNextServer(config, { incomingArtifactAdapters: [] });
  const httpServer = running.app.listen(0, "127.0.0.1");
  const managementServer = running.managementApp.listen(0, "127.0.0.1");
  await Promise.all([httpServer, managementServer].map((server) => (
    new Promise<void>((resolve, reject) => {
      server.once("listening", resolve);
      server.once("error", reject);
    })
  )));
  t.after(async () => {
    await new Promise<void>((resolve) => httpServer.close(() => resolve()));
    await new Promise<void>((resolve) => managementServer.close(() => resolve()));
    await running.close();
    await rm(root, { recursive: true, force: true });
  });

  const address = httpServer.address() as AddressInfo;
  const managementAddress = managementServer.address() as AddressInfo;
  const origin = `http://127.0.0.1:${address.port}`;
  const managementOrigin = `http://127.0.0.1:${managementAddress.port}`;
  const registered = await fetch(`${origin}/register`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      redirect_uris: ["http://127.0.0.1/callback"],
      client_name: "Metrics connector registration",
      token_endpoint_auth_method: "none",
      grant_types: ["authorization_code", "refresh_token"],
      response_types: ["code"],
    }),
  });
  assert.equal(registered.status, 201, await registered.text());
  const metrics = await fetch(`${managementOrigin}${config.metricsPath}`);
  assert.equal(metrics.status, 200);
  assert.match(
    await metrics.text(),
    /devspace_connector_transitions_total\{from="NONE",result="pass",to="REGISTERED"\} 1/u,
  );
});

test("production HTTP rejects legacy-scope tokens and accepts granular tokens", async (t) => {
  const root = await realpath(await mkdtemp(join(tmpdir(), "devspace-v2-production-oauth-test-")));
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
    DEVSPACE_NEXT_AUTHORITY_OWNER_INSTANCE_ID: "http-production-test-owner",
  });
  const legacyToken = `legacy-${randomUUID()}`;
  const granularToken = `granular-${randomUUID()}`;
  const refreshedToken = `refreshed-${randomUUID()}`;
  const readOnlyToken = `read-only-${randomUUID()}`;
  const otherClientToken = `other-client-${randomUUID()}`;
  const store = new SqliteOAuthStore(config.oauthStateDir);
  const registered = store.registerClient({
    redirect_uris: ["http://127.0.0.1/callback"],
    client_name: "Granular scope enforcement test",
    token_endpoint_auth_method: "none",
    grant_types: ["authorization_code", "refresh_token"],
    response_types: ["code"],
  }, config.oauth.allowedRedirectHosts);
  const otherRegistered = store.registerClient({
    redirect_uris: ["http://127.0.0.1/other-callback"],
    client_name: "Cross-client authority rejection test",
    token_endpoint_auth_method: "none",
    grant_types: ["authorization_code", "refresh_token"],
    response_types: ["code"],
  }, config.oauth.allowedRedirectHosts);
  const fixtureRuntimeIdentity = createRuntimeIdentity({
    config,
    sourceRevision: config.sourceRevision,
    runtimeRevision: config.runtimeRevision,
    ...(config.buildDigest ? { buildDigest: config.buildDigest } : {}),
  });
  const activateConnector = (clientId: string, label: string, installationEpoch: number) => {
    const connectorInput = {
      canonicalName: config.oauth.canonicalConnector!.name,
      clientId,
      installationEpoch,
      schemaGeneration: config.oauth.canonicalConnector!.schemaGeneration,
    };
    const connector = store.ensureCandidateConnectorBinding(connectorInput);
    const connectorTuple = {
      ...connectorInput,
      candidateBindingId: connector.bindingId,
      authorityContractGeneration: fixtureRuntimeIdentity.authorityContractGeneration,
      redirectUrisDigest: `sha256:${createHash("sha256").update(label).digest("hex")}`,
      buildDigest: fixtureRuntimeIdentity.buildDigest,
    };
    store.markConnectorBindingVerified(connector.bindingId, {
      authorityContractGeneration: connectorTuple.authorityContractGeneration,
      redirectUrisDigest: connectorTuple.redirectUrisDigest,
      buildDigest: connectorTuple.buildDigest,
    });
    const connectorReceipt = store.prepareConnectorActivation(connectorTuple, {
      drainDeadlineAt: new Date(Date.now() + 60_000).toISOString(),
      refreshAllowedDuringDrain: false,
    });
    store.activatePreparedConnector(
      connectorReceipt.receiptId,
      connectorTuple,
      connectorActivationProofFixture(connectorReceipt, label),
    );
    return connector.bindingId;
  };
  const activeInstallationEpoch = config.oauth.canonicalConnector!.installationEpoch;
  const activeBindingId = activateConnector(
    registered.client_id,
    "active-client-fixture",
    activeInstallationEpoch,
  );
  const activeConnector = store.getConnectorBinding(activeBindingId)!;
  const saveBoundAccessToken = (
    token: string,
    scopes: string[],
    clientId: string,
    binding: typeof activeConnector,
  ) => {
    const familyId = `family-${randomUUID()}`;
    const expiresAt = Math.floor(Date.now() / 1000) + 300;
    const connectorBinding = {
      familyId,
      connectorBindingId: binding.bindingId,
      connectorDrainEpoch: binding.drainEpoch,
      installationEpoch: binding.installationEpoch,
      rotationSequence: 0,
    };
    store.saveTokenPair({
      accessTokenHash: createHash("sha256").update(token).digest("base64url"),
      accessToken: {
        clientId,
        scopes,
        expiresAt,
        resource: config.publicMcpUrl,
        ...connectorBinding,
      },
      refreshTokenHash: createHash("sha256").update(`refresh-${token}`).digest("base64url"),
      refreshToken: {
        clientId,
        scopes,
        expiresAt,
        resource: config.publicMcpUrl,
        ...connectorBinding,
      },
    });
  };
  for (const [token, scopes] of [
    [legacyToken, ["devspace"]],
    [granularToken, [...config.oauth.scopes]],
    [refreshedToken, [...config.oauth.scopes]],
    [readOnlyToken, ["devspace.read"]],
  ] as const) {
    saveBoundAccessToken(token, [...scopes], registered.client_id, activeConnector);
  }
  store.saveAccessToken(createHash("sha256").update(otherClientToken).digest("base64url"), {
    clientId: otherRegistered.client_id,
    scopes: [...config.oauth.scopes],
    expiresAt: Math.floor(Date.now() / 1000) + 300,
    resource: config.publicMcpUrl,
  });
  store.close();

  const running = createUniversalBrokerNextServer(config, { incomingArtifactAdapters: [] });
  const http = running.app.listen(0, "127.0.0.1");
  const management = running.managementApp.listen(0, "127.0.0.1");
  await Promise.all([http, management].map((server) => new Promise<void>((resolve, reject) => {
    server.once("listening", resolve);
    server.once("error", reject);
  })));
  const address = http.address() as AddressInfo;
  const managementAddress = management.address() as AddressInfo;
  const endpoint = new URL(`http://127.0.0.1:${address.port}/mcp`);
  try {
    const routeIdentityUrl = `http://127.0.0.1:${managementAddress.port}/route-identityz`;
    const unauthorizedRouteIdentity = await fetch(routeIdentityUrl);
    assert.equal(unauthorizedRouteIdentity.status, 401);
    const managementKey = loadExistingManagementAuthorizationKey({
      keyRef: config.managementAuthorizationKeyRef,
      stateDir: config.stateDir,
    });
    const routeIdentity = await fetch(routeIdentityUrl, {
      headers: { Authorization: managementAuthorizationHeader(managementKey) },
    });
    const routeIdentityBody = await routeIdentity.json();
    assert.equal(routeIdentity.status, 200, JSON.stringify(routeIdentityBody));
    assert.deepEqual(
      routeIdentityBody,
      connectorProductionRouteIdentityReadback({
        runtimeIdentity: running.runtimeIdentity,
        oauthResource: config.publicMcpUrl,
        canonicalName: activeConnector.canonicalName,
        bindingId: activeConnector.bindingId,
      }),
    );

    const rejectedTransport = new StreamableHTTPClientTransport(endpoint, {
      requestInit: { headers: { Authorization: `Bearer ${legacyToken}` } },
    });
    const rejectedClient = new Client({ name: "legacy-scope-rejected-test", version: "1" });
    await assert.rejects(rejectedClient.connect(rejectedTransport));
    await Promise.allSettled([rejectedClient.close(), rejectedTransport.close()]);

    const sessionlessHeaders = {
      Accept: "application/json, text/event-stream",
      Authorization: `Bearer ${granularToken}`,
      "Content-Type": "application/json",
      "User-Agent": "openai-mcp/1.0.0",
    };
    const sessionlessToolsList = await fetch(endpoint, {
      method: "POST",
      headers: sessionlessHeaders,
      body: JSON.stringify({
        jsonrpc: "2.0",
        id: "chatgpt-action-refresh",
        method: "tools/list",
        params: {},
      }),
    });
    assert.equal(sessionlessToolsList.status, 200);
    const sessionlessToolsListBody = await sessionlessToolsList.json() as {
      result?: { tools?: Array<{ name?: string }> };
    };
    assert.deepEqual(
      sessionlessToolsListBody.result?.tools?.map((tool) => tool.name),
      [...UNIVERSAL_TOOL_NAMES],
    );

    const sessionlessInitialized = await fetch(endpoint, {
      method: "POST",
      headers: sessionlessHeaders,
      body: JSON.stringify({
        jsonrpc: "2.0",
        method: "notifications/initialized",
      }),
    });
    assert.equal(sessionlessInitialized.status, 202);

    const sessionlessDiscoveryBatch = await fetch(endpoint, {
      method: "POST",
      headers: sessionlessHeaders,
      body: JSON.stringify([
        {
          jsonrpc: "2.0",
          method: "notifications/initialized",
        },
        {
          jsonrpc: "2.0",
          id: "chatgpt-batched-action-refresh",
          method: "tools/list",
          params: {},
        },
      ]),
    });
    assert.equal(sessionlessDiscoveryBatch.status, 200);
    const sessionlessDiscoveryBatchBody = await sessionlessDiscoveryBatch.json() as {
      result?: { tools?: Array<{ name?: string }> };
    } | Array<{
      result?: { tools?: Array<{ name?: string }> };
    }>;
    const sessionlessDiscoveryBatchResponses = Array.isArray(sessionlessDiscoveryBatchBody)
      ? sessionlessDiscoveryBatchBody
      : [sessionlessDiscoveryBatchBody];
    assert.deepEqual(
      sessionlessDiscoveryBatchResponses[0]?.result?.tools?.map((tool) => tool.name),
      [...UNIVERSAL_TOOL_NAMES],
    );

    const sessionlessExecution = await fetch(endpoint, {
      method: "POST",
      headers: sessionlessHeaders,
      body: JSON.stringify({
        jsonrpc: "2.0",
        id: "must-remain-session-bound",
        method: "tools/call",
        params: { name: "target", arguments: { operation: "list" } },
      }),
    });
    assert.equal(sessionlessExecution.status, 400);

    const genericSessionlessToolsList = await fetch(endpoint, {
      method: "POST",
      headers: { ...sessionlessHeaders, "User-Agent": "generic-mcp-client/1.0.0" },
      body: JSON.stringify({
        jsonrpc: "2.0",
        id: "generic-client-sessionless-discovery",
        method: "tools/list",
        params: {},
      }),
    });
    assert.equal(genericSessionlessToolsList.status, 200);
    const genericSessionlessToolsListBody = await genericSessionlessToolsList.json() as {
      result?: { tools?: Array<{ name?: string }> };
    };
    assert.deepEqual(
      genericSessionlessToolsListBody.result?.tools?.map((tool) => tool.name),
      [...UNIVERSAL_TOOL_NAMES],
    );
    const genericSessionlessExecution = await fetch(endpoint, {
      method: "POST",
      headers: { ...sessionlessHeaders, "User-Agent": "generic-mcp-client/1.0.0" },
      body: JSON.stringify({
        jsonrpc: "2.0",
        id: "generic-execution-must-remain-session-bound",
        method: "tools/call",
        params: { name: "target", arguments: { operation: "list" } },
      }),
    });
    assert.equal(genericSessionlessExecution.status, 400);
    const genericMixedSessionlessBatch = await fetch(endpoint, {
      method: "POST",
      headers: { ...sessionlessHeaders, "User-Agent": "generic-mcp-client/1.0.0" },
      body: JSON.stringify([
        {
          jsonrpc: "2.0",
          id: "generic-discovery-part",
          method: "tools/list",
          params: {},
        },
        {
          jsonrpc: "2.0",
          id: "generic-execution-part",
          method: "tools/call",
          params: { name: "target", arguments: { operation: "list" } },
        },
      ]),
    });
    assert.equal(genericMixedSessionlessBatch.status, 400);

    const acceptedTransport = new StreamableHTTPClientTransport(endpoint, {
      requestInit: { headers: { Authorization: `Bearer ${granularToken}` } },
    });
    const acceptedClient = new Client({ name: "granular-scope-accepted-test", version: "1" });
    await acceptedClient.connect(acceptedTransport);
    const listed = await acceptedClient.listTools();
    assert.deepEqual(listed.tools.map((tool) => tool.name), [...UNIVERSAL_TOOL_NAMES]);
    const targets = await acceptedClient.callTool({ name: "target", arguments: { operation: "list" } });
    assert.notEqual(targets.isError, true);
    const crossSessionPath = join(root, "cross-session-authority.txt");
    const crossSessionArguments = {
      operation: "write",
      target: "local",
      path: crossSessionPath,
      content: "same OAuth client, new MCP session\n",
    };
    const crossSessionAuthorityId = await prepareAuthority(acceptedClient, {
      taskId: "cross-session-first-write",
      authorityText: "Write the exact fixture once through a fresh MCP session.",
      tool: "fs",
      arguments: crossSessionArguments,
      uses: 2,
    });
    await acceptedClient.close();

    const nextSessionTransport = new StreamableHTTPClientTransport(endpoint, {
      requestInit: { headers: { Authorization: `Bearer ${refreshedToken}` } },
    });
    const nextSessionClient = new Client({ name: "same-oauth-new-session-test", version: "1" });
    await nextSessionClient.connect(nextSessionTransport);
    const crossSessionWrite = await nextSessionClient.callTool({
      name: "fs",
      arguments: crossSessionArguments,
      _meta: { devspace: { authorityId: crossSessionAuthorityId } },
    });
    assert.notEqual(crossSessionWrite.isError, true, JSON.stringify(crossSessionWrite.structuredContent));
    assert.equal(await readFile(crossSessionPath, "utf8"), crossSessionArguments.content);
    await nextSessionClient.close();

    const otherClientTransport = new StreamableHTTPClientTransport(endpoint, {
      requestInit: { headers: { Authorization: `Bearer ${otherClientToken}` } },
    });
    const otherClient = new Client({ name: "different-oauth-authority-test", version: "1" });
    await assert.rejects(otherClient.connect(otherClientTransport));
    await Promise.allSettled([otherClient.close(), otherClientTransport.close()]);

    const readOnlyTransport = new StreamableHTTPClientTransport(endpoint, {
      requestInit: { headers: { Authorization: `Bearer ${readOnlyToken}` } },
    });
    const readOnlyClient = new Client({ name: "authority-preview-scope-test", version: "1" });
    await readOnlyClient.connect(readOnlyTransport);
    const authorityStatusBeforeScopeFailure = await readOnlyClient.callTool({
      name: "context",
      arguments: { operation: "authority_status" },
      _meta: { devspace: { authorityId: crossSessionAuthorityId } },
    });
    assert.notEqual(
      authorityStatusBeforeScopeFailure.isError,
      true,
      JSON.stringify(authorityStatusBeforeScopeFailure.structuredContent),
    );
    assert.equal(
      ((authorityStatusBeforeScopeFailure.structuredContent as {
        data?: { actions?: Array<{ consumedUses?: number }> };
      } | undefined)?.data?.actions?.[0]?.consumedUses),
      1,
    );
    const scopeReducedWrite = await readOnlyClient.callTool({
      name: "fs",
      arguments: crossSessionArguments,
      _meta: { devspace: { authorityId: crossSessionAuthorityId } },
    });
    assert.equal(scopeReducedWrite.isError, true);
    assert.equal(
      (scopeReducedWrite.structuredContent as {
        error?: { code?: string; evidence?: { requiredScope?: string } };
      } | undefined)?.error?.code,
      "SCOPE_INSUFFICIENT",
    );
    const authorityStatusAfterScopeFailure = await readOnlyClient.callTool({
      name: "context",
      arguments: { operation: "authority_status" },
      _meta: { devspace: { authorityId: crossSessionAuthorityId } },
    });
    assert.equal(
      ((authorityStatusAfterScopeFailure.structuredContent as {
        data?: { actions?: Array<{ consumedUses?: number }> };
      } | undefined)?.data?.actions?.[0]?.consumedUses),
      1,
    );
    const readPreview = await readOnlyClient.callTool({
      name: "context",
      arguments: {
        operation: "authority_preview",
        actions: [{
          tool: "fs",
          arguments: { operation: "read", target: "local", path: "/tmp/example.txt" },
        }],
      },
    });
    assert.notEqual(readPreview.isError, true, JSON.stringify(readPreview.structuredContent));
    const execPreview = await readOnlyClient.callTool({
      name: "context",
      arguments: {
        operation: "authority_preview",
        actions: [{
          tool: "exec",
          arguments: { target: "local", cwd: "/tmp", command: "git status --short" },
        }],
      },
    });
    assert.equal(execPreview.isError, true);
    assert.equal(
      (execPreview.structuredContent as { error?: { code?: string; evidence?: { requiredScope?: string } } } | undefined)?.error?.code,
      "SCOPE_INSUFFICIENT",
    );
    assert.equal(
      (execPreview.structuredContent as { error?: { evidence?: { requiredScope?: string } } } | undefined)?.error?.evidence?.requiredScope,
      "devspace.exec",
    );
    await readOnlyClient.close();
  } finally {
    await new Promise<void>((resolve) => http.close(() => resolve()));
    await new Promise<void>((resolve) => management.close(() => resolve()));
    await running.close();
  }
});

test("parallel v2 HTTP service has an independent health endpoint and protected MCP endpoint", async (t) => {
  const root = await realpath(await mkdtemp(join(tmpdir(), "devspace-v2-http-test-")));
  const publicPort = await availableLoopbackPort();
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
    DEVSPACE_NEXT_PORT: String(publicPort),
    DEVSPACE_NEXT_PUBLIC_BASE_URL: "http://127.0.0.1:17677/v2",
    DEVSPACE_NEXT_AUTHORITY_OWNER_INSTANCE_ID: "http-parallel-test-owner",
    DEVSPACE_NEXT_MCP_ROUTES_FILE: mcpRoutes,
    DEVSPACE_NEXT_TARGETS_FILE: targetsFile,
    DEVSPACE_NEXT_RATE_LIMIT_PRE_AUTH_BURST: "1000",
    DEVSPACE_NEXT_RATE_LIMIT_POST_AUTH_BURST: "1000",
    DEVSPACE_NEXT_RATE_LIMIT_INITIALIZE_BURST: "100",
  });
  const fixtureRuntimeIdentity = createRuntimeIdentity({
    config,
    sourceRevision: config.sourceRevision,
    runtimeRevision: config.runtimeRevision,
    ...(config.buildDigest ? { buildDigest: config.buildDigest } : {}),
  });
  const connectorStore = new SqliteOAuthStore(config.oauthStateDir);
  const connectorClient = connectorStore.registerClient({
    redirect_uris: ["http://127.0.0.1/connector-callback"],
    client_name: "Universal Broker v3 active connector fixture",
    token_endpoint_auth_method: "none",
    grant_types: ["authorization_code", "refresh_token"],
    response_types: ["code"],
  }, config.oauth.allowedRedirectHosts);
  const connectorInput = {
    canonicalName: config.oauth.canonicalConnector!.name,
    clientId: connectorClient.client_id,
    installationEpoch: config.oauth.canonicalConnector!.installationEpoch,
    schemaGeneration: config.oauth.canonicalConnector!.schemaGeneration,
  };
  const connector = connectorStore.ensureCandidateConnectorBinding(connectorInput);
  const connectorTuple = {
    ...connectorInput,
    candidateBindingId: connector.bindingId,
    authorityContractGeneration: fixtureRuntimeIdentity.authorityContractGeneration,
    redirectUrisDigest: `sha256:${createHash("sha256").update("http-fixture-redirects").digest("hex")}`,
    buildDigest: fixtureRuntimeIdentity.buildDigest,
  };
  connectorStore.markConnectorBindingVerified(connector.bindingId, {
    authorityContractGeneration: connectorTuple.authorityContractGeneration,
    redirectUrisDigest: connectorTuple.redirectUrisDigest,
    buildDigest: connectorTuple.buildDigest,
  });
  const connectorReceipt = connectorStore.prepareConnectorActivation(connectorTuple, {
    drainDeadlineAt: new Date(Date.now() + 60_000).toISOString(),
    refreshAllowedDuringDrain: false,
  });
  connectorStore.activatePreparedConnector(
    connectorReceipt.receiptId,
    connectorTuple,
    connectorActivationProofFixture(connectorReceipt, "http-fixture-activation"),
  );
  connectorStore.close();
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
          screenCapture: false,
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
    timeoutMs: 10_000,
    runtimeIdentity: fixtureRuntimeIdentity,
    launchWorker(request) {
      restartLaunches.push(request.transactionId);
    },
    supervisorReadinessProbe: () => ({
      state: "PASS",
      evidence: {
        controlChannel: "fixture-pm2-rpc",
        processMatches: 1,
        online: true,
        cwdMatches: true,
        scriptMatches: true,
      },
    }),
  });
  const running = createUniversalBrokerNextServer(config, {
    incomingArtifactAdapters: [nativeArtifactAdapter],
    guiRunner,
    selfManagement,
  });
  const httpServer = running.app.listen(config.port, "127.0.0.1");
  const managementServer = running.managementApp.listen(0, "127.0.0.1");
  await Promise.all([httpServer, managementServer].map((server) => (
    new Promise<void>((resolve, reject) => {
      server.once("listening", resolve);
      server.once("error", reject);
    })
  )));
  t.after(async () => {
    await new Promise<void>((resolve) => httpServer.close(() => resolve()));
    await new Promise<void>((resolve) => managementServer.close(() => resolve()));
    await running.close();
    await rm(root, { recursive: true, force: true });
  });

  const address = httpServer.address() as AddressInfo;
  const managementAddress = managementServer.address() as AddressInfo;
  const origin = `http://127.0.0.1:${address.port}`;
  const managementOrigin = `http://127.0.0.1:${managementAddress.port}`;
  assert.equal(
    await requestStatus(`${origin}${config.metricsPath}`, `127.0.0.1:${address.port}`),
    404,
  );
  const localMetrics = await fetch(`${managementOrigin}${config.metricsPath}`);
  assert.equal(localMetrics.status, 200);
  const localMetricsText = await localMetrics.text();
  assert.match(localMetricsText, /devspace_authority_previews 0/u);
  assert.match(localMetricsText, /devspace_target_probe_in_flight 0/u);
  assert.match(localMetricsText, /devspace_target_probe_cache_hits 0/u);
  assert.match(localMetricsText, /devspace_target_probe_cache_misses 0/u);
  assert.match(localMetricsText, /devspace_target_probe_coalesced 0/u);
  assert.match(localMetricsText, /devspace_target_probe_average_duration_ms 0/u);
  const productionRateLimitBucketsBeforeDoctor = Number(
    /^devspace_rate_limit_buckets ([0-9]+)$/mu.exec(localMetricsText)?.[1],
  );
  assert.equal(Number.isSafeInteger(productionRateLimitBucketsBeforeDoctor), true);
  assert.ok(productionRateLimitBucketsBeforeDoctor >= 0);
  const health = await fetch(`${origin}/healthz-next`);
  assert.equal(health.status, 200);
  const healthBody = await health.json() as {
    status: string;
    productVersion: string;
    schemaGeneration: string;
    authorityContractGeneration: string;
    buildDigest: string;
    runtimeRevision: string;
    startedAt: string;
  };
  assert.equal(healthBody.status, "ok");
  assert.match(healthBody.schemaGeneration, /^sha256:/u);
  assert.match(healthBody.authorityContractGeneration, /^sha256:/u);
  assert.equal(healthBody.buildDigest, fixtureRuntimeIdentity.buildDigest);
  assert.equal("configDigest" in healthBody, false);
  assert.equal("targetGeneration" in healthBody, false);
  assert.equal("mcpRouteGeneration" in healthBody, false);
  const readiness = await fetch(`${managementOrigin}${config.readyPath}`);
  const readinessBody = await readiness.json() as {
    checks?: Array<{ id?: string; state?: string; evidence?: Record<string, unknown> }>;
    identity?: { productProfile?: string; buildCapabilityDigest?: string };
  };
  assert.equal(readiness.status, 200, JSON.stringify(readinessBody));
  assert.equal(readinessBody.identity?.productProfile, "BASE_SINGLE_OWNER");
  const readinessChecks = new Map(readinessBody.checks?.map((check) => [check.id, check]));
  for (const id of [
    "config_build_capabilities",
    "required_store_migrations",
    "authority_artifact_readability",
    "target_route_generation",
    "canonical_connector",
    "supervisor_control",
    "rate_limit_identity",
    "management_isolation",
    "audit_sink",
    "runtime_contract_identity",
  ]) {
    assert.equal(readinessChecks.has(id), true, id);
    assert.equal(readinessChecks.get(id)?.state, "PASS", id);
  }
  const storeObservations = readinessChecks.get("required_store_migrations")?.evidence?.observations as
    | Array<{ evidence?: Record<string, unknown> }>
    | undefined;
  assert.equal(
    storeObservations?.some((observation) => (
      observation.evidence?.storeId === "filesystem-sync"
      && observation.evidence.path === join(config.stateDir, "filesystem-sync", "sync.sqlite")
      && observation.evidence.exists === true
      && observation.evidence.userVersion === 1
      && observation.evidence.expectedUserVersion === 1
    )),
    true,
  );
  assert.equal(
    storeObservations?.some((observation) => (
      observation.evidence?.storeId === "connector-activation-journal"
      && observation.evidence.path === config.connectorActivationJournalPath
      && observation.evidence.exists === true
      && observation.evidence.userVersion === 1
      && observation.evidence.expectedUserVersion === 1
    )),
    true,
  );
  assert.equal(
    storeObservations?.some((observation) => (
      observation.evidence?.storeId === "lifecycle-finalization-store"
      && observation.evidence.path === config.lifecycleFinalizationStorePath
      && observation.evidence.controlPath === config.lifecycleFinalizationControlPath
      && observation.evidence.schemaVersion === 2
      && observation.evidence.schemaFingerprint === FINALIZATION_STORE_SCHEMA_FINGERPRINT
      && observation.evidence.state === "DRAFT"
      && observation.evidence.revision === 1
      && observation.evidence.integrity === "ok"
      && observation.evidence.foreignKeyViolations === 0
    )),
    true,
  );
  assert.equal(
    storeObservations?.some((observation) => (
      observation.evidence?.id === "connector-activation-journal-identity"
      && observation.evidence.storePath === config.connectorActivationJournalPath
      && observation.evidence.schemaVersion === 1
      && typeof observation.evidence.schemaFingerprint === "string"
      && typeof observation.evidence.migrationManifestDigest === "string"
      && observation.evidence.snapshotPolicy === "PRESERVE_OUTSIDE_MUTABLE_ROLLBACK"
      && observation.evidence.receiptReplayPolicy === "PREPARED_RECEIPT_PERMANENTLY_ONE_SHOT"
    )),
    true,
  );
  assert.equal(
    storeObservations?.some((observation) => (
      observation.evidence?.storeId === "main"
      && observation.evidence.path === join(config.oauthStateDir, "devspace.sqlite")
      && observation.evidence.complete === true
      && observation.evidence.integrity === "ok"
      && observation.evidence.foreignKeyViolations === 0
    )),
    true,
  );
  assert.equal(
    (readinessChecks.get("audit_sink")?.evidence as { startupProof?: string } | undefined)?.startupProof,
    "RECORDED",
  );
  assert.equal(
    readinessChecks.get("rate_limit_identity")?.evidence?.sourcePolicy,
    "loopback-direct-peer-plus-bounded-hop-count",
  );
  const expectedRateLimitPolicyDigest = String(
    readinessChecks.get("rate_limit_identity")?.evidence?.policyDigest ?? "",
  );
  assert.match(expectedRateLimitPolicyDigest, /^sha256:[a-f0-9]{64}$/u);
  const publicDoctor = await fetch(`${origin}/doctorz`, { method: "POST" });
  assert.equal(publicDoctor.status, 404);
  const forgedDoctorProbe = await fetch(`${origin}/healthz-next`, {
    headers: { "x-devspace-internal-doctor-probe": "A".repeat(43) },
  });
  assert.equal(forgedDoctorProbe.status, 200);
  assert.equal(
    Number.isSafeInteger(Number(forgedDoctorProbe.headers.get("x-ratelimit-remaining"))),
    true,
  );
  const rateStateBeforeDoctor = await fetch(`${origin}/healthz-next`);
  assert.equal(rateStateBeforeDoctor.status, 200);
  const rateLimitBeforeDoctor = Number(rateStateBeforeDoctor.headers.get("x-ratelimit-limit"));
  const rateRemainingBeforeDoctor = Number(rateStateBeforeDoctor.headers.get("x-ratelimit-remaining"));
  assert.equal(Number.isSafeInteger(rateRemainingBeforeDoctor), true);
  const doctorGet = await fetch(`${managementOrigin}/doctorz`);
  assert.equal(doctorGet.status, 405);
  const unauthorizedDoctor = await fetch(`${managementOrigin}/doctorz`, { method: "POST" });
  assert.equal(unauthorizedDoctor.status, 401);
  const managementKey = loadExistingManagementAuthorizationKey({
    keyRef: config.managementAuthorizationKeyRef,
    stateDir: config.stateDir,
  });
  const parallelRouteIdentity = await fetch(`${managementOrigin}/route-identityz`, {
    headers: { Authorization: managementAuthorizationHeader(managementKey) },
  });
  assert.equal(parallelRouteIdentity.status, 503);
  assert.deepEqual(await parallelRouteIdentity.json(), {
    schemaVersion: 1,
    state: "UNAVAILABLE",
    routeCount: 1,
  });
  const doctor = await fetch(`${managementOrigin}/doctorz`, {
    method: "POST",
    headers: { Authorization: managementAuthorizationHeader(managementKey) },
  });
  const doctorBody = await doctor.json() as {
    status?: string;
    releasePassClaimed?: boolean;
    cleanup?: { state?: string; receiptDigest?: string };
    checks?: Array<{
      id?: string;
      state?: string;
      evidence?: Record<string, unknown> & { stores?: string[] };
    }>;
  };
  assert.equal(doctor.status, 503, JSON.stringify(doctorBody));
  assert.equal(doctorBody.releasePassClaimed, false);
  assert.equal(doctorBody.cleanup?.state, "CLEANED");
  assert.match(doctorBody.cleanup?.receiptDigest ?? "", /^sha256:[a-f0-9]{64}$/u);
  const doctorChecks = new Map(doctorBody.checks?.map((check) => [check.id, check.state]));
  for (const id of [
    "authority_claim_receipt",
    "connector_consistency",
    "pm2_uniqueness",
    "public_metrics_negative_probe",
    "artifact_reconciliation",
    "migration_manifest_scan",
    "mutable_snapshot_capability",
    "rate_canary",
    "stale_lease_nonterminal_report",
    "runtime_identity_readback",
  ]) {
    assert.equal(doctorChecks.has(id), true, id);
  }
  assert.equal(doctorChecks.get("authority_claim_receipt"), "PASS");
  assert.equal(
    doctorChecks.get("mutable_snapshot_capability"),
    "PASS",
    JSON.stringify(doctorBody.checks?.find((check) => check.id === "mutable_snapshot_capability")),
  );
  assert.equal(doctorChecks.get("rate_canary"), "PASS");
  assert.equal(doctorChecks.get("public_metrics_negative_probe"), "PASS");
  assert.equal(doctorChecks.get("artifact_reconciliation"), "PASS");
  const migrationScan = doctorBody.checks?.find((check) => check.id === "migration_manifest_scan");
  assert.equal(migrationScan?.state, "PASS");
  assert.equal(migrationScan?.evidence?.stores?.includes("main"), true);
  const secondDoctor = await fetch(`${managementOrigin}/doctorz`, {
    method: "POST",
    headers: { Authorization: managementAuthorizationHeader(managementKey) },
  });
  const secondDoctorBody = await secondDoctor.json() as typeof doctorBody;
  assert.equal(secondDoctor.status, 503, JSON.stringify(secondDoctorBody));
  assert.equal(secondDoctorBody.cleanup?.state, "CLEANED");
  assert.match(secondDoctorBody.cleanup?.receiptDigest ?? "", /^sha256:[a-f0-9]{64}$/u);
  assert.equal(
    secondDoctorBody.checks?.find((check) => check.id === "rate_canary")?.state,
    "PASS",
  );
  assert.equal(
    secondDoctorBody.checks?.find((check) => check.id === "public_metrics_negative_probe")?.state,
    "PASS",
  );
  const rateStateAfterDoctor = await fetch(`${origin}/healthz-next`);
  assert.equal(rateStateAfterDoctor.status, 200);
  assert.equal(
    Number(rateStateAfterDoctor.headers.get("x-ratelimit-limit")),
    rateLimitBeforeDoctor,
  );
  assert.equal(
    Number(rateStateAfterDoctor.headers.get("x-ratelimit-remaining")),
    rateRemainingBeforeDoctor - 1,
    "deep-doctor self-probes must not consume production admission tokens",
  );
  const metricsAfterDoctor = await fetch(`${managementOrigin}${config.metricsPath}`);
  assert.equal(metricsAfterDoctor.status, 200);
  const metricsAfterDoctorText = await metricsAfterDoctor.text();
  const productionRateLimitBucketsAfterDoctor = Number(
    /^devspace_rate_limit_buckets ([0-9]+)$/mu.exec(metricsAfterDoctorText)?.[1],
  );
  assert.equal(
    productionRateLimitBucketsAfterDoctor,
    productionRateLimitBucketsBeforeDoctor,
    "authorized deep-doctor runs must not retain production rate-limit buckets",
  );
  for (const report of [doctorBody, secondDoctorBody]) {
    const evidence = report.checks?.find((check) => check.id === "rate_canary")?.evidence;
    assert.equal(evidence?.isolation, "PER_RUN_DISPOSABLE_RATE_LIMITER");
    assert.equal(evidence?.cleanupBinding, "deep-doctor-rate-canary-v1");
    assert.equal(evidence?.policyDigest, expectedRateLimitPolicyDigest);
    assert.equal(evidence?.isolatedBucketCountBefore, 0);
    assert.equal(evidence?.isolatedBucketCountAfter, 1);
  }
  assert.match(
    metricsAfterDoctorText,
    /devspace_doctor_checks_total\{check="authority_claim_receipt",result="pass"\} 2/u,
  );
  assert.match(
    metricsAfterDoctorText,
    /devspace_doctor_duration_seconds_count\{result="UNKNOWN"\} 2/u,
  );

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
  const readOnlyPlanningToken = `v2-read-only-${randomUUID()}`;
  const oauthStore = new SqliteOAuthStore(config.stateDir);
  const registered = connectorClient;
  const activeConnector = oauthStore.getActiveConnectorBinding(config.canonicalConnectorName)!;
  const saveBoundAccessToken = (accessToken: string, scopes: string[]) => {
    const familyId = `family-${randomUUID()}`;
    const expiresAt = Math.floor(Date.now() / 1000) + 300;
    const binding = {
      familyId,
      connectorBindingId: activeConnector.bindingId,
      connectorDrainEpoch: activeConnector.drainEpoch,
      installationEpoch: activeConnector.installationEpoch,
      rotationSequence: 0,
    };
    oauthStore.saveTokenPair({
      accessTokenHash: createHash("sha256").update(accessToken).digest("base64url"),
      accessToken: {
        clientId: registered.client_id,
        scopes,
        expiresAt,
        resource: config.publicMcpUrl,
        ...binding,
      },
      refreshTokenHash: createHash("sha256").update(`refresh-${accessToken}`).digest("base64url"),
      refreshToken: {
        clientId: registered.client_id,
        scopes,
        expiresAt,
        resource: config.publicMcpUrl,
        ...binding,
      },
    });
  };
  saveBoundAccessToken(token, config.oauth.scopes);
  saveBoundAccessToken(readOnlyPlanningToken, ["devspace.read"]);
  oauthStore.close();

  const readOnlyPlanningTransport = new StreamableHTTPClientTransport(
    new URL(`${origin}${config.endpointPath}`),
    {
      requestInit: {
        headers: { Authorization: `Bearer ${readOnlyPlanningToken}` },
      },
    },
  );
  const readOnlyPlanningClient = new Client({
    name: "v2-authority-preview-preflight-scope-test",
    version: "1.0.0",
  });
  await readOnlyPlanningClient.connect(readOnlyPlanningTransport);
  try {
    assert.equal((await running.mcpProxy.stats()).sessions, 0);
    const deniedMcpPreview = await readOnlyPlanningClient.callTool({
      name: "context",
      arguments: {
        operation: "authority_preview",
        actions: [{
          tool: "mcp",
          arguments: {
            operation: "invoke",
            route: "fixture",
            name: "read_value",
            arguments: { key: "must-not-inspect-provider" },
          },
        }],
      },
    });
    assert.equal(deniedMcpPreview.isError, true);
    assert.equal(
      (deniedMcpPreview.structuredContent as {
        error?: { code?: string; evidence?: { requiredScope?: string } };
      } | undefined)?.error?.code,
      "SCOPE_INSUFFICIENT",
    );
    assert.equal(
      (deniedMcpPreview.structuredContent as {
        error?: { evidence?: { requiredScope?: string } };
      } | undefined)?.error?.evidence?.requiredScope,
      "devspace.mcp",
    );
    assert.equal((await running.mcpProxy.stats()).sessions, 0);
  } finally {
    await readOnlyPlanningClient.close();
  }

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
      arguments: generationBoundArguments,
      _meta: { devspace: { authorityId: generationAuthorityId } },
    });
    assert.equal(staleGeneration.isError, true);
    assert.equal(
      (staleGeneration.structuredContent as { error?: { code?: string } } | undefined)?.error?.code,
      "AUTHORITY_ACTION_MISMATCH",
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
    const previewSecretContent = "preview-secret-content-must-not-echo";
    const previewSecretMcpValue = "preview-secret-mcp-value-must-not-echo";
    const authorityPreview = await client.callTool({
      name: "context",
      arguments: {
        operation: "authority_preview",
        actions: [
          {
            id: "local-write",
            tool: "fs",
            arguments: {
              operation: "write",
              path: filePath,
              content: previewSecretContent,
            },
          },
          {
            id: "provider-read",
            tool: "mcp",
            arguments: {
              operation: "invoke",
              route: "fixture",
              name: "read_value",
              arguments: { key: "http" },
            },
          },
          {
            id: "provider-write",
            tool: "mcp",
            arguments: {
              operation: "invoke",
              route: "fixture",
              name: "write_value",
              arguments: { key: "http", value: previewSecretMcpValue },
            },
          },
        ],
      },
    });
    assert.notEqual(authorityPreview.isError, true, JSON.stringify(authorityPreview.structuredContent));
    const serializedPreview = JSON.stringify(authorityPreview.structuredContent);
    assert.doesNotMatch(serializedPreview, new RegExp(previewSecretContent, "u"));
    assert.doesNotMatch(serializedPreview, new RegExp(previewSecretMcpValue, "u"));
    const previewData = (authorityPreview.structuredContent as {
      data?: {
        planFingerprint?: string;
        authorityActionCount?: number;
        r0ActionCount?: number;
        actions?: Array<{
          id?: string;
          minimumRisk?: string;
          authorityRequired?: boolean;
          target?: string;
          resource?: string;
          parameterKeys?: string[];
        }>;
      };
    } | undefined)?.data;
    assert.equal(typeof previewData?.planFingerprint, "string");
    assert.equal(previewData?.authorityActionCount, 3);
    assert.equal(previewData?.r0ActionCount, 0);
    assert.deepEqual(
      previewData?.actions?.map(({ id, minimumRisk, authorityRequired }) => ({ id, minimumRisk, authorityRequired })),
      [
        { id: "local-write", minimumRisk: "R1", authorityRequired: true },
        { id: "provider-read", minimumRisk: "R2", authorityRequired: true },
        { id: "provider-write", minimumRisk: "R2", authorityRequired: true },
      ],
    );
    assert.equal(previewData?.actions?.[0]?.target, "local");
    assert.deepEqual(
      previewData?.actions?.[0]?.parameterKeys,
      ["contentSha256", "path", "targetGeneration"],
    );
    assert.equal(previewData?.actions?.[1]?.resource, "fixture");
    assert.deepEqual(
      previewData?.actions?.[1]?.parameterKeys,
      ["arguments", "name", "riskDecision", "riskPolicyGeneration", "routeGeneration", "toolContractSha256"],
    );
    assert.deepEqual(
      previewData?.actions?.[2]?.parameterKeys,
      ["arguments", "name", "riskDecision", "riskPolicyGeneration", "routeGeneration", "toolContractSha256"],
    );
    const unapprovedWrite = await client.callTool({
      name: "fs",
      arguments: {
        operation: "write",
        path: filePath,
        content: "must-not-dispatch\n",
      },
    });
    assert.equal(unapprovedWrite.isError, true);
    assert.equal(
      (unapprovedWrite.structuredContent as { error?: { code?: string } } | undefined)?.error?.code,
      "AUTHORITY_REQUIRED",
    );
    await assert.rejects(readFile(filePath, "utf8"), { code: "ENOENT" });

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
    const metricsAfterAuthority = await fetch(`${managementOrigin}${config.metricsPath}`);
    assert.equal(metricsAfterAuthority.status, 200);
    assert.match(
      await metricsAfterAuthority.text(),
      /devspace_authority_checks_total\{result="pass",risk="R1"\} 1/u,
    );
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
    const unapprovedMcpRead = await client.callTool({
      name: "mcp",
      arguments: {
        operation: "invoke",
        route: "fixture",
        name: "read_value",
        arguments: { key: "http" },
      },
    });
    assert.equal(unapprovedMcpRead.isError, true);
    assert.equal(
      (unapprovedMcpRead.structuredContent as { error?: { code?: string } } | undefined)?.error?.code,
      "AUTHORITY_REQUIRED",
    );
    const mcpRead = await callAuthorized(client, {
      taskId: "http-mcp-read-without-owner-policy",
      authorityText: "Read this exact fixture key under the conservative generic-invoke policy.",
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
      arguments: routeArgs,
      _meta: { devspace: { authorityId: routeAuthority } },
    });
    assert.equal(changedRouteResult.isError, true);
    assert.equal(
      (changedRouteResult.structuredContent as { error?: { code?: string } } | undefined)?.error?.code,
      "AUTHORITY_ACTION_MISMATCH",
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

    const mcpResources = await client.callTool({
      name: "mcp",
      arguments: {
        operation: "list_resources",
        route: "fixture",
      },
    });
    const mcpResourcesStructured = mcpResources.structuredContent as {
      data?: { result?: { value?: { resources?: Array<{ uri?: string }> } } };
    } | undefined;
    const mcpResourceUri = mcpResourcesStructured?.data?.result?.value?.resources?.[0]?.uri;
    assert.match(mcpResourceUri ?? "", /^devspace:\/\/v1\/mcp\/fixture\/resource\//u);
    const mcpResource = await client.callTool({
      name: "mcp",
      arguments: {
        operation: "read_resource",
        route: "fixture",
        uri: mcpResourceUri,
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
      taskId: "http-mcp-large-without-owner-policy",
      authorityText: "Return this exact bounded large fixture result under the conservative generic-invoke policy.",
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
    const mcpResultPages: string[] = [];
    let nextMcpResultUri: string | undefined = largeData!.resourceUri!;
    let mcpResultPageCount = 0;
    while (nextMcpResultUri) {
      const page = await client.readResource({ uri: nextMcpResultUri });
      const content = page.contents[0];
      assert.ok(content && "text" in content);
      mcpResultPages.push(content.text);
      const meta = content._meta as {
        truncated?: boolean;
        nextResourceUri?: string;
        nextOffset?: number;
      } | undefined;
      assert.equal(meta?.nextOffset, undefined);
      nextMcpResultUri = meta?.nextResourceUri;
      mcpResultPageCount += 1;
      assert.ok(mcpResultPageCount <= 8, "retained MCP result paging must terminate");
    }
    const completeMcpResult = mcpResultPages.join("");
    assert.match(completeMcpResult, /^\{"content"/);
    assert.ok(completeMcpResult.length > 20_000);
    assert.ok(mcpResultPageCount > 1);

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
      data?: { resourceUri?: string; downloadUrl?: string; immutable?: boolean };
    } | undefined)?.data;
    assert.equal(publishedData?.immutable, true);
    assert.match(publishedData?.resourceUri ?? "", /^devspace:\/\/v1\/artifact\/[0-9a-f-]{36}$/u);
    assert.match(publishedData?.downloadUrl ?? "", /^http:\/\/127\.0\.0\.1:17677\/v2\/artifacts-next\//u);
    const artifactResource = await client.readResource({ uri: publishedData!.resourceUri! });
    const artifactContent = artifactResource.contents[0];
    assert.ok(artifactContent && "blob" in artifactContent);
    assert.equal(
      Buffer.from(artifactContent.blob, "base64").toString("utf8"),
      "native-http-artifact\n",
    );
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
    assert.equal(resourceLink.uri, publishedData?.resourceUri);

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
      risk: "R2",
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

    const writableProcess = await callAuthorized(client, {
      taskId: "http-writable-process",
      authorityText: "Start this exact bounded local stdin echo process.",
      tool: "exec",
      arguments: {
        target: "local",
        cwd: root,
        command: "cat",
        mode: "background",
      },
      risk: "R1",
    });
    const writableProcessId = (writableProcess.structuredContent as {
      data?: { processId?: string };
    } | undefined)?.data?.processId;
    assert.equal(typeof writableProcessId, "string");
    const processWritten = await callAuthorized(client, {
      taskId: "http-process-write-binding",
      authorityText: "Write this exact text to the exact managed local process.",
      tool: "process",
      arguments: {
        operation: "write",
        processId: writableProcessId,
        chars: "process-binding-v2\n",
        waitMs: 100,
      },
      risk: "R2",
    });
    assert.match(JSON.stringify(processWritten.structuredContent), /process-binding-v2/u);
    const processSignalled = await callAuthorized(client, {
      taskId: "http-process-signal-binding",
      authorityText: "Terminate this exact managed local process once.",
      tool: "process",
      arguments: {
        operation: "signal",
        processId: writableProcessId,
        signal: "SIGTERM",
        waitMs: 2_000,
      },
      risk: "R3",
    });
    assert.match(JSON.stringify(processSignalled.structuredContent), /SIGNALED/u);

    const restartRequested = await callAuthorized(client, {
      taskId: "http-self-restart",
      authorityText: "Restart the broker through one durable transaction.",
      tool: "process",
      arguments: {
        operation: "restart_broker",
        reason: "HTTP integration restart",
      },
      risk: "R3",
    });
    assert.notEqual(
      restartRequested.isError,
      true,
      JSON.stringify(restartRequested.structuredContent),
    );
    const restartData = (restartRequested.structuredContent as {
      data?: { transactionId?: string; state?: string; expectedDisconnect?: boolean };
    } | undefined)?.data;
    assert.equal(restartData?.state, "RESPONSE_BOUND");
    assert.equal(restartData?.expectedDisconnect, true);
    await waitFor(() => restartLaunches.length === 1, 2_000);
    assert.deepEqual(restartLaunches, [restartData!.transactionId!]);
    const restartStatus = await client.callTool({
      name: "process",
      arguments: { operation: "restart_status" },
      _meta: { devspace: { transactionId: restartData!.transactionId! } },
    });
    const restartStatusData = (restartStatus.structuredContent as {
      data?: { state?: string; transactionId?: string };
    } | undefined)?.data;
    assert.equal(restartStatusData?.state, "ACK_FLUSHED");
    assert.equal(restartStatusData?.transactionId, restartData?.transactionId);
  } finally {
    await client.close();
  }
});

async function waitFor(predicate: () => boolean, timeoutMs: number): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  while (!predicate()) {
    if (Date.now() >= deadline) throw new Error("Timed out waiting for the expected HTTP lifecycle state.");
    await new Promise<void>((resolve) => setTimeout(resolve, 10));
  }
}

async function availableLoopbackPort(): Promise<number> {
  const server = createServer();
  await new Promise<void>((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", resolve);
  });
  const address = server.address() as AddressInfo;
  await new Promise<void>((resolve, reject) => {
    server.close((error) => error ? reject(error) : resolve());
  });
  return address.port;
}
