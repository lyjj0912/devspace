import assert from "node:assert/strict";
import { createHash, randomUUID } from "node:crypto";
import { mkdtemp, readFile, realpath, rm } from "node:fs/promises";
import type { AddressInfo } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { loadConfig } from "../config.js";
import {
  type ConnectorActivationAuthorityProof,
  type ConnectorActivationReceipt,
  SqliteOAuthStore,
  connectorActivationAuthorityActionFingerprint,
  connectorActivationAuthorityResourceKeySha256,
} from "../oauth-store.js";
import { UNIVERSAL_TOOL_NAMES } from "./contracts.js";
import { loadUniversalBrokerNextConfig } from "./config.js";
import { createUniversalBrokerNextServer } from "./http-server.js";
import { UniversalToolRequestReplayGuard } from "./request-replay-guard.js";
import { createRuntimeIdentity } from "./runtime-identity.js";
import { RUNTIME_AUTHORITY_CONTRACT_GENERATION } from "./runtime-contract-identity.js";

interface JsonRpcToolResponse {
  jsonrpc?: string;
  id?: string | number;
  result?: {
    structuredContent?: {
      ok?: boolean;
      operationId?: string;
      data?: Record<string, unknown>;
      error?: {
        code?: string;
        dispatchState?: string;
        evidence?: Record<string, unknown>;
      };
    };
  };
  error?: Record<string, unknown>;
}

interface AuditRecord {
  operationId?: string;
  tool?: string;
  operation?: string;
  risk?: string;
  dispatchState?: string;
  result?: string;
  productProfile?: string;
  sourceRevision?: string;
  runtimeRevision?: string;
  buildDigest?: string;
  schemaGeneration?: string;
  runtimeStartedAt?: string;
  connectorInstallationEpoch?: number;
  acceptanceRunId?: string;
}

test("Personal HTTP accepts authenticated sessionless tools/call without regressing stateful sessions", {
  timeout: 20_000,
}, async (t) => {
  const fixture = await createPersonalHttpFixture(t);
  const sessionlessHeaders = {
    Accept: "application/json, text/event-stream",
    Authorization: `Bearer ${fixture.accessToken}`,
    "Content-Type": "application/json",
    "User-Agent": "openai-mcp/1.0.0",
  };

  const initialized = await postJsonRpc(fixture.endpoint, sessionlessHeaders, {
    jsonrpc: "2.0",
    id: "personal-stateful-initialize",
    method: "initialize",
    params: {
      protocolVersion: "2025-06-18",
      capabilities: {},
      clientInfo: { name: "personal-stateful-regression", version: "1" },
    },
  });
  assert.equal(initialized.response.status, 200, JSON.stringify(initialized.body));
  const sessionId = initialized.response.headers.get("mcp-session-id");
  assert.equal(typeof sessionId, "string");
  assert.ok(sessionId);
  const statefulHeaders = { ...sessionlessHeaders, "mcp-session-id": sessionId };
  const statefulReady = await postJsonRpc(fixture.endpoint, statefulHeaders, {
    jsonrpc: "2.0",
    method: "notifications/initialized",
  });
  assert.equal(statefulReady.response.status, 202, JSON.stringify(statefulReady.body));
  const statefulList = await postJsonRpc(fixture.endpoint, statefulHeaders, {
    jsonrpc: "2.0",
    id: "personal-stateful-target-list",
    method: "tools/call",
    params: { name: "target", arguments: { operation: "list" } },
  });
  assert.equal(statefulList.response.status, 200, JSON.stringify(statefulList.body));
  assert.equal(statefulList.body.result?.structuredContent?.ok, true);

  const sessionlessList = await postJsonRpc(fixture.endpoint, sessionlessHeaders, {
    jsonrpc: "2.0",
    id: "chatgpt-sessionless-target-list",
    method: "tools/call",
    params: { name: "target", arguments: { operation: "list" } },
  });
  assert.equal(sessionlessList.response.status, 200, JSON.stringify(sessionlessList.body));
  assert.equal(sessionlessList.body.result?.structuredContent?.ok, true);
  assert.deepEqual(
    (sessionlessList.body.result?.structuredContent?.data?.targets as Array<{ targetId?: string }>)
      .map((target) => target.targetId),
    ["local"],
  );

  const writePath = join(fixture.root, "sessionless-write.txt");
  const sessionlessWrite = await postJsonRpc(fixture.endpoint, sessionlessHeaders, {
    jsonrpc: "2.0",
    id: "chatgpt-sessionless-fs-write",
    method: "tools/call",
    params: {
      name: "fs",
      arguments: {
        operation: "write",
        target: "local",
        path: writePath,
        content: "authenticated sessionless mutation\n",
      },
    },
  });
  assert.equal(sessionlessWrite.response.status, 200, JSON.stringify(sessionlessWrite.body));
  assert.equal(sessionlessWrite.body.result?.structuredContent?.ok, true);
  assert.match(
    sessionlessWrite.body.result?.structuredContent?.operationId ?? "",
    /^op_[0-9a-f-]{36}$/u,
  );
  assert.equal(await readFile(writePath, "utf8"), "authenticated sessionless mutation\n");
  const writeOperationId = sessionlessWrite.body.result?.structuredContent?.operationId!;
  const writeAudit = await waitForAuditRecord(fixture.auditPath, writeOperationId);
  assert.deepEqual(
    {
      tool: writeAudit.tool,
      operation: writeAudit.operation,
      risk: writeAudit.risk,
      dispatchState: writeAudit.dispatchState,
      result: writeAudit.result,
      productProfile: writeAudit.productProfile,
      sourceRevision: writeAudit.sourceRevision,
      runtimeRevision: writeAudit.runtimeRevision,
      buildDigest: writeAudit.buildDigest,
      schemaGeneration: writeAudit.schemaGeneration,
      runtimeStartedAt: writeAudit.runtimeStartedAt,
      connectorInstallationEpoch: writeAudit.connectorInstallationEpoch,
      acceptanceRunId: writeAudit.acceptanceRunId,
    },
    {
      tool: "fs",
      operation: "write",
      risk: "R1",
      dispatchState: "ACKNOWLEDGED",
      result: "pass",
      productProfile: fixture.runtimeIdentity.productProfile,
      sourceRevision: fixture.runtimeIdentity.sourceRevision,
      runtimeRevision: fixture.runtimeIdentity.runtimeRevision,
      buildDigest: fixture.runtimeIdentity.buildDigest,
      schemaGeneration: fixture.runtimeIdentity.schemaGeneration,
      runtimeStartedAt: fixture.runtimeIdentity.startedAt,
      connectorInstallationEpoch: fixture.connectorInstallationEpoch,
      acceptanceRunId: fixture.acceptanceRunId,
    },
  );

  const closed = await fetch(fixture.endpoint, {
    method: "DELETE",
    headers: statefulHeaders,
  });
  assert.equal(closed.status, 200);
});

test("Personal sessionless tools/call preserves authentication and scope boundaries", {
  timeout: 20_000,
}, async (t) => {
  const fixture = await createPersonalHttpFixture(t);
  const writePath = join(fixture.root, "scope-must-not-dispatch.txt");
  const body = {
    jsonrpc: "2.0",
    id: "chatgpt-sessionless-scope-negative",
    method: "tools/call",
    params: {
      name: "fs",
      arguments: {
        operation: "write",
        target: "local",
        path: writePath,
        content: "must not exist\n",
      },
    },
  };

  const unauthenticated = await postJsonRpc(fixture.endpoint, {
    Accept: "application/json, text/event-stream",
    "Content-Type": "application/json",
  }, body);
  assert.equal(unauthenticated.response.status, 401);

  const scopeReduced = await postJsonRpc(fixture.endpoint, {
    Accept: "application/json, text/event-stream",
    Authorization: `Bearer ${fixture.readOnlyAccessToken}`,
    "Content-Type": "application/json",
    "User-Agent": "openai-mcp/1.0.0",
  }, body);
  assert.equal(scopeReduced.response.status, 200, JSON.stringify(scopeReduced.body));
  assert.equal(scopeReduced.body.result?.structuredContent?.ok, false);
  assert.equal(scopeReduced.body.result?.structuredContent?.error?.code, "SCOPE_INSUFFICIENT");
  assert.equal(
    scopeReduced.body.result?.structuredContent?.error?.dispatchState,
    "NOT_DISPATCHED",
  );
  await assert.rejects(readFile(writePath, "utf8"), /ENOENT/u);
});

test("mixed stateful and sessionless retries share one mutation result", {
  timeout: 20_000,
}, async (t) => {
  const fixture = await createPersonalHttpFixture(t);
  const sessionlessHeaders = authenticatedHeaders(fixture.accessToken);
  const statefulHeaders = await initializeStatefulSession(
    fixture.endpoint,
    sessionlessHeaders,
    "personal-mixed-replay",
  );
  const markerPath = join(fixture.root, "mixed-replay-marker.txt");
  const requestBody = {
    jsonrpc: "2.0",
    id: "chatgpt-mixed-stateful-sessionless-retry",
    method: "tools/call",
    params: {
      name: "exec",
      arguments: {
        target: "local",
        cwd: fixture.root,
        command: `sleep 0.25; printf 'once\\n' >> ${shellQuote(markerPath)}`,
        mode: "foreground",
        yieldMs: 5_000,
      },
    },
  };

  const [stateful, sessionless] = await Promise.all([
    postJsonRpc(fixture.endpoint, statefulHeaders, requestBody),
    postJsonRpc(fixture.endpoint, sessionlessHeaders, requestBody),
  ]);
  for (const result of [stateful, sessionless]) {
    assert.equal(result.response.status, 200, JSON.stringify(result.body));
    assert.equal(result.body.result?.structuredContent?.ok, true);
  }
  assert.equal(
    stateful.body.result?.structuredContent?.operationId,
    sessionless.body.result?.structuredContent?.operationId,
  );
  assert.equal(await readFile(markerPath, "utf8"), "once\n");
  const operationId = stateful.body.result?.structuredContent?.operationId!;
  await waitForAuditRecord(fixture.auditPath, operationId);
  assert.equal(
    (await readAuditRecords(fixture.auditPath))
      .filter((record) => record.operationId === operationId).length,
    1,
  );
  const replayStats = fixture.requestReplayGuard.stats();
  assert.equal(replayStats.executed, 1);
  assert.equal(replayStats.coalesced + replayStats.replayed, 1);

  const closed = await fetch(fixture.endpoint, {
    method: "DELETE",
    headers: statefulHeaders,
  });
  assert.equal(closed.status, 200);
});

async function createPersonalHttpFixture(t: test.TestContext) {
  const root = await realpath(await mkdtemp(join(tmpdir(), "devspace-personal-http-sessionless-")));
  const base = loadConfig({
    DEVSPACE_CONFIG_DIR: join(root, "config"),
    DEVSPACE_ALLOWED_ROOTS: root,
    DEVSPACE_STATE_DIR: join(root, "legacy-state"),
    DEVSPACE_WORKTREE_ROOT: join(root, "legacy-worktrees"),
    DEVSPACE_OAUTH_OWNER_TOKEN: "personal-http-owner-token-not-a-secret-123456789",
    DEVSPACE_HOST: "127.0.0.1",
    DEVSPACE_PORT: "7676",
    DEVSPACE_PUBLIC_BASE_URL: "http://127.0.0.1:7676",
    DEVSPACE_LOG_LEVEL: "silent",
  });
  const config = loadUniversalBrokerNextConfig(base, {
    DEVSPACE_V2_DEPLOYMENT_MODE: "production",
    DEVSPACE_NEXT_STATE_DIR: join(root, "state"),
    DEVSPACE_NEXT_AUTHORITY_OWNER_INSTANCE_ID: "personal-http-sessionless-owner",
  });
  const accessToken = `personal-http-full-${randomUUID()}`;
  const readOnlyAccessToken = `personal-http-read-${randomUUID()}`;
  const store = new SqliteOAuthStore(config.oauthStateDir);
  const registered = store.registerClient({
    redirect_uris: ["http://127.0.0.1/callback"],
    client_name: "Personal HTTP sessionless fixture",
    token_endpoint_auth_method: "none",
    grant_types: ["authorization_code", "refresh_token"],
    response_types: ["code"],
  }, config.oauth.allowedRedirectHosts);
  const runtimeIdentity = createRuntimeIdentity({
    config,
    sourceRevision: config.sourceRevision,
    runtimeRevision: config.runtimeRevision,
    ...(config.buildDigest ? { buildDigest: config.buildDigest } : {}),
  });
  const connectorInput = {
    canonicalName: config.oauth.canonicalConnector!.name,
    clientId: registered.client_id,
    installationEpoch: config.oauth.canonicalConnector!.installationEpoch,
    schemaGeneration: config.oauth.canonicalConnector!.schemaGeneration,
  };
  const connector = store.ensureCandidateConnectorBinding(connectorInput);
  const tuple = {
    ...connectorInput,
    candidateBindingId: connector.bindingId,
    authorityContractGeneration: RUNTIME_AUTHORITY_CONTRACT_GENERATION,
    redirectUrisDigest: `sha256:${createHash("sha256").update("personal-http-redirects").digest("hex")}`,
    buildDigest: runtimeIdentity.buildDigest,
  };
  store.markConnectorBindingVerified(connector.bindingId, {
    authorityContractGeneration: tuple.authorityContractGeneration,
    redirectUrisDigest: tuple.redirectUrisDigest,
    buildDigest: tuple.buildDigest,
  });
  const receipt = store.prepareConnectorActivation(tuple, {
    drainDeadlineAt: new Date(Date.now() + 60_000).toISOString(),
    refreshAllowedDuringDrain: false,
  });
  store.activatePreparedConnector(
    receipt.receiptId,
    tuple,
    connectorActivationProof(receipt),
  );
  const active = store.getConnectorBinding(connector.bindingId)!;
  saveBoundTokenPair(
    store,
    accessToken,
    [...config.oauth.scopes],
    registered.client_id,
    active,
    config.publicMcpUrl,
  );
  saveBoundTokenPair(
    store,
    readOnlyAccessToken,
    ["devspace.read"],
    registered.client_id,
    active,
    config.publicMcpUrl,
  );
  store.close();

  const requestReplayGuard = new UniversalToolRequestReplayGuard();
  const acceptanceRunId = `pdo-e2e-${randomUUID()}`;
  const running = createUniversalBrokerNextServer(config, {
    incomingArtifactAdapters: [],
    requestReplayGuard,
    acceptanceRunId,
  });
  const http = running.app.listen(0, "127.0.0.1");
  await new Promise<void>((resolve, reject) => {
    http.once("listening", resolve);
    http.once("error", reject);
  });
  const address = http.address() as AddressInfo;
  const endpoint = new URL(`http://127.0.0.1:${address.port}/mcp`);
  t.after(async () => {
    await new Promise<void>((resolve) => http.close(() => resolve()));
    await running.close();
    await rm(root, { recursive: true, force: true });
  });
  return {
    root,
    endpoint,
    accessToken,
    readOnlyAccessToken,
    requestReplayGuard,
    acceptanceRunId,
    auditPath: config.auditSinkPath,
    runtimeIdentity: running.runtimeIdentity,
    connectorInstallationEpoch: active.installationEpoch,
  };
}

function authenticatedHeaders(accessToken: string): Record<string, string> {
  return {
    Accept: "application/json, text/event-stream",
    Authorization: `Bearer ${accessToken}`,
    "Content-Type": "application/json",
    "User-Agent": "openai-mcp/1.0.0",
  };
}

async function initializeStatefulSession(
  endpoint: URL,
  headers: Record<string, string>,
  clientName: string,
): Promise<Record<string, string>> {
  const initialized = await postJsonRpc(endpoint, headers, {
    jsonrpc: "2.0",
    id: `${clientName}-initialize`,
    method: "initialize",
    params: {
      protocolVersion: "2025-06-18",
      capabilities: {},
      clientInfo: { name: clientName, version: "1" },
    },
  });
  assert.equal(initialized.response.status, 200, JSON.stringify(initialized.body));
  const sessionId = initialized.response.headers.get("mcp-session-id");
  assert.ok(sessionId);
  const statefulHeaders = { ...headers, "mcp-session-id": sessionId };
  const ready = await postJsonRpc(endpoint, statefulHeaders, {
    jsonrpc: "2.0",
    method: "notifications/initialized",
  });
  assert.equal(ready.response.status, 202, JSON.stringify(ready.body));
  return statefulHeaders;
}

function saveBoundTokenPair(
  store: SqliteOAuthStore,
  token: string,
  scopes: string[],
  clientId: string,
  binding: NonNullable<ReturnType<SqliteOAuthStore["getConnectorBinding"]>>,
  resource: string,
): void {
  const familyId = `family-${randomUUID()}`;
  const expiresAt = Math.floor(Date.now() / 1000) + 300;
  const connectorBinding = {
    familyId,
    connectorBindingId: binding.bindingId,
    connectorDrainEpoch: binding.drainEpoch,
    installationEpoch: binding.installationEpoch,
    rotationSequence: 0,
  };
  assert.equal(store.saveTokenPair({
    accessTokenHash: createHash("sha256").update(token).digest("base64url"),
    accessToken: {
      clientId,
      scopes,
      expiresAt,
      resource,
      ...connectorBinding,
    },
    refreshTokenHash: createHash("sha256").update(`refresh-${token}`).digest("base64url"),
    refreshToken: {
      clientId,
      scopes,
      expiresAt,
      resource,
      ...connectorBinding,
    },
  }), true);
}

function connectorActivationProof(
  receipt: ConnectorActivationReceipt,
): ConnectorActivationAuthorityProof {
  const binding = {
    receiptId: receipt.receiptId,
    tupleDigest: receipt.tupleDigest,
    activePreimageDigest: receipt.preimageDigest,
    finalizationPlanDigest: `sha256:${createHash("sha256")
      .update("personal-http-finalization-plan")
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
      .update("personal-http-principal")
      .digest("hex"),
    risk: "R3",
    claimState: "DISPATCHED",
    approvalAssurance: "cooperative",
    ...binding,
    evidenceDigest: `sha256:${createHash("sha256")
      .update("personal-http-owner-evidence")
      .digest("hex")}`,
    claimedAtMs,
    dispatchedAtMs: claimedAtMs + 1,
  };
}

async function postJsonRpc(
  endpoint: URL,
  headers: Record<string, string>,
  body: Record<string, unknown>,
): Promise<{ response: Response; body: JsonRpcToolResponse }> {
  const response = await fetch(endpoint, {
    method: "POST",
    headers,
    body: JSON.stringify(body),
  });
  const text = await response.text();
  let parsed: JsonRpcToolResponse = {};
  if (text) parsed = parseJsonRpcText(text);
  return { response, body: parsed };
}

function parseJsonRpcText(text: string): JsonRpcToolResponse {
  const trimmed = text.trim();
  if (!trimmed) return {};
  if (trimmed.startsWith("{")) return JSON.parse(trimmed) as JsonRpcToolResponse;
  const payload = trimmed
    .split(/\r?\n/u)
    .find((line) => line.startsWith("data:"))
    ?.slice("data:".length)
    .trim();
  if (!payload) throw new Error(`MCP response contains no JSON payload: ${trimmed.slice(0, 500)}`);
  return JSON.parse(payload) as JsonRpcToolResponse;
}

function shellQuote(value: string): string {
  return `'${value.replaceAll("'", `'"'"'`)}'`;
}

async function waitForAuditRecord(path: string, operationId: string): Promise<AuditRecord> {
  const deadline = Date.now() + 5_000;
  do {
    const record = (await readAuditRecords(path))
      .find((candidate) => candidate.operationId === operationId);
    if (record) return record;
    await new Promise((resolve) => setTimeout(resolve, 10));
  } while (Date.now() < deadline);
  throw new Error(`Audit record did not appear for ${operationId}`);
}

async function readAuditRecords(path: string): Promise<AuditRecord[]> {
  try {
    return (await readFile(path, "utf8"))
      .trim()
      .split("\n")
      .filter(Boolean)
      .map((line) => JSON.parse(line) as AuditRecord);
  } catch (error) {
    if (error && typeof error === "object" && "code" in error && error.code === "ENOENT") return [];
    throw error;
  }
}

assert.deepEqual([...UNIVERSAL_TOOL_NAMES], [
  "target",
  "context",
  "fs",
  "exec",
  "process",
  "mcp",
  "artifact",
  "gui",
]);
