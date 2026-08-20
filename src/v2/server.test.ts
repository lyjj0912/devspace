import assert from "node:assert/strict";
import { chmod, mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { homedir, tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import type { AuthInfo } from "@modelcontextprotocol/sdk/server/auth/types.js";
import {
  OperationAuthorityRegistry,
  type OperationAuthorityDispatchController,
} from "./authority.js";
import {
  assertUniversalBrokerBudgets,
  inspectUniversalBrokerBudgets,
} from "./budgets.js";
import {
  UNIVERSAL_TOOL_NAMES,
  type UniversalToolName,
} from "./contracts.js";
import {
  requireCapabilityCallContext,
  type CapabilityCallContext,
} from "./capability-call-context.js";
import type { ContextRegistry } from "./contexts.js";
import { UniversalBrokerMetrics } from "./metrics.js";
import {
  EXEC_RISK_CLASSIFIER_GENERATION,
  filesystemAction,
  minimumAuthorityRisk,
} from "./authority-policy.js";
import {
  resolveAuthorityPrincipal,
  type AuthorityPrincipalConfiguration,
} from "./authority-principal.js";
import type {
  ExecuteCommandInput,
  PreparedExecExecutionBinding,
  UniversalExecutionPlane,
  UniversalProcessSnapshot,
} from "./execution.js";
import {
  UniversalFilesystemService,
  type UniversalFilesystemInput,
} from "./filesystem.js";
import { RecoverableFilesystemTrash } from "./filesystem-trash.js";
import { createLocalFilesystemSyncAdapter } from "./filesystem-sync.js";
import { prepareExecExecutionBinding } from "./execution.js";
import {
  downstreamMcpToolContractSha256,
  type DownstreamMcpSession,
  UniversalMcpProxy,
} from "./mcp-proxy.js";
import { UniversalMcpRouteRegistry } from "./mcp-routes.js";
import { OperationAuditSink } from "./operation-audit.js";
import { createUniversalBrokerMcpServer } from "./server.js";
import { TargetRegistry, type TargetDefinition } from "./targets.js";

test("Universal Broker v2 exposes exactly the fixed eight-tool surface within budget", async () => {
  const report = await inspectUniversalBrokerBudgets();
  assertUniversalBrokerBudgets(report);
  assert.deepEqual(report.toolNames, [...UNIVERSAL_TOOL_NAMES]);
});

test("tools without an injected implementation fail explicitly without changing the registered schema", async () => {
  const server = createUniversalBrokerMcpServer();
  const client = new Client({ name: "v2-service-test", version: "1.0.0" });
  const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
  await Promise.all([
    client.connect(clientTransport),
    server.connect(serverTransport),
  ]);

  try {
    for (const name of UNIVERSAL_TOOL_NAMES) {
      const result = await client.callTool({
        name,
        arguments: minimalArguments(name),
      });
      const structured = result.structuredContent as {
        ok?: unknown;
        error?: unknown;
      } | undefined;
      assert.equal(result.isError, true, name);
      assert.equal(structured?.ok, false, name);
      const error = structured?.error;
      assert.equal(typeof error, "object", name);
      assert.equal(
        (error as { code?: unknown }).code,
        "CAPABILITY_UNAVAILABLE",
        name,
      );
    }
  } finally {
    await Promise.allSettled([client.close(), server.close()]);
  }
});

test("configured R0 tools authenticate before provider access without touching authority state", async (t) => {
  const root = await mkdtemp(join(tmpdir(), "devspace-v2-r0-auth-test-"));
  t.after(() => rm(root, { recursive: true, force: true }));
  let providerCalls = 0;
  const targets = new TargetRegistry({ configPath: join(root, "missing-targets.json") });
  const listTargets = targets.list.bind(targets);
  targets.list = async (input) => {
    providerCalls += 1;
    return listTargets(input);
  };
  let authorityStoreBoundaryCalls = 0;
  const authority = new Proxy({} as OperationAuthorityRegistry, {
    get() {
      authorityStoreBoundaryCalls += 1;
      throw new Error("R0 must not cross the authority registry or store boundary.");
    },
  });
  let processProviderCalls = 0;
  let resourceProviderCalls = 0;
  const execution = {
    async operate() {
      processProviderCalls += 1;
      return { processes: [] };
    },
    async readOutput() {
      resourceProviderCalls += 1;
      throw new Error("Unauthenticated process resources must not reach the provider.");
    },
  } as unknown as UniversalExecutionPlane;
  const mcpProxy = {
    readStoredResult() {
      resourceProviderCalls += 1;
      throw new Error("Unauthenticated MCP resources must not reach the provider.");
    },
    async execute(_input: unknown, callContext?: CapabilityCallContext) {
      requireCapabilityCallContext(callContext);
      resourceProviderCalls += 1;
      return {
        result: {
          value: {
            contents: [{
              uri: "devspace://v1/mcp/fixture/resource/opaque-test",
              mimeType: "text/plain",
              text: "proxied fixture",
            }],
          },
        },
      };
    },
  } as unknown as UniversalMcpProxy;
  const contexts = {
    readDiffResource() {
      resourceProviderCalls += 1;
      throw new Error("Unauthenticated context resources must not reach the provider.");
    },
  } as unknown as ContextRegistry;
  const resource = new URL("https://broker.example.test/mcp");
  const metrics = new UniversalBrokerMetrics();
  const server = createUniversalBrokerMcpServer({
    targets,
    contexts,
    execution,
    mcpProxy,
    authority,
    metrics,
    authorityPrincipal: {
      environment: "production",
      mode: "single-owner",
      issuer: "https://issuer.example.test/",
      resource: resource.href,
      ownerInstanceId: "r0-server-test-owner",
    },
  });
  const client = new Client({ name: "v2-r0-auth-test", version: "1.0.0" });
  const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
  const send = clientTransport.send.bind(clientTransport);
  let authInfo: AuthInfo | undefined;
  const protectedResourceUris = [
    "devspace://v1/process/process-test/output",
    "devspace://v1/mcp/fixture/resource/opaque-test",
    "devspace://v1/mcp-result/result-test",
    "devspace://v1/context-diff/diff-test",
  ];
  clientTransport.send = (message, options) => send(message, {
    ...options,
    ...(authInfo ? { authInfo } : {}),
  });
  await Promise.all([
    client.connect(clientTransport),
    server.connect(serverTransport),
  ]);

  try {
    const unauthenticated = await client.callTool({
      name: "target",
      arguments: { operation: "list" },
    });
    assert.equal(unauthenticated.isError, true);
    assert.equal(toolErrorCode(unauthenticated), "AUTHENTICATION_FAILED");
    assert.equal(providerCalls, 0);
    assert.equal(authorityStoreBoundaryCalls, 0);

    for (const uri of protectedResourceUris) {
      await assert.rejects(
        client.readResource({ uri }),
        /Validated authentication information is required/u,
      );
    }
    assert.equal(resourceProviderCalls, 0);
    assert.equal(authorityStoreBoundaryCalls, 0);

    authInfo = {
      token: "missing-scopes-test-token",
      clientId: "r0-test-client",
      resource,
    } as AuthInfo;
    const missingScopes = await client.callTool({
      name: "target",
      arguments: { operation: "list" },
    });
    assert.equal(missingScopes.isError, true);
    assert.equal(toolErrorCode(missingScopes), "SCOPE_INSUFFICIENT");
    assert.equal(providerCalls, 0);
    assert.equal(authorityStoreBoundaryCalls, 0);
    for (const uri of protectedResourceUris) {
      await assert.rejects(
        client.readResource({ uri }),
        /OAuth scope is required/u,
      );
    }
    assert.equal(resourceProviderCalls, 0);
    assert.equal(authorityStoreBoundaryCalls, 0);

    authInfo = {
      ...authInfo,
      scopes: ["devspace.mcp"],
    };
    const insufficientScope = await client.callTool({
      name: "target",
      arguments: { operation: "list" },
    });
    assert.equal(insufficientScope.isError, true);
    assert.equal(toolErrorCode(insufficientScope), "SCOPE_INSUFFICIENT");
    assert.equal(providerCalls, 0);
    assert.equal(authorityStoreBoundaryCalls, 0);
    const mcpResource = await client.readResource({
      uri: "devspace://v1/mcp/fixture/resource/opaque-test",
    });
    assert.equal((mcpResource.contents[0] as { text?: string } | undefined)?.text, "proxied fixture");
    assert.equal(resourceProviderCalls, 1);

    authInfo = {
      ...authInfo,
      scopes: ["devspace.read"],
    };
    const authorized = await client.callTool({
      name: "target",
      arguments: { operation: "list" },
    });
    assert.notEqual(authorized.isError, true);
    assert.equal(
      (authorized.structuredContent as { ok?: unknown } | undefined)?.ok,
      true,
    );
    assert.equal(providerCalls, 1);
    assert.equal(authorityStoreBoundaryCalls, 0);

    authInfo = {
      ...authInfo,
      scopes: ["devspace.exec"],
    };
    const processList = await client.callTool({
      name: "process",
      arguments: { operation: "list" },
    });
    assert.notEqual(processList.isError, true);
    assert.equal(processProviderCalls, 1);
    assert.equal(authorityStoreBoundaryCalls, 0);
    const renderedMetrics = metrics.render({});
    assert.match(
      renderedMetrics,
      /devspace_requests_total\{error_code="AUTHENTICATION_FAILED",operation="list",result="fail",tool="target"\} 1/u,
    );
    assert.match(
      renderedMetrics,
      /devspace_requests_total\{error_code="SCOPE_INSUFFICIENT",operation="list",result="fail",tool="target"\} 2/u,
    );
    assert.match(
      renderedMetrics,
      /devspace_requests_total\{error_code="none",operation="list",result="pass",tool="target"\} 1/u,
    );
    assert.match(
      renderedMetrics,
      /devspace_requests_total\{error_code="none",operation="list",result="pass",tool="process"\} 1/u,
    );
  } finally {
    await Promise.allSettled([client.close(), server.close()]);
  }
});

test("server audit event links the durable authority receipt digest", async (t) => {
  const root = await mkdtemp(join(tmpdir(), "devspace-v2-server-audit-link-"));
  t.after(() => rm(root, { recursive: true, force: true }));
  const targetsPath = join(root, "targets.json");
  await writeFile(targetsPath, JSON.stringify({
    version: 1,
    targets: {
      local: {
        displayName: "Local",
        aliases: ["local"],
        transport: "local",
        platform: "macos",
        shell: "zsh",
      },
    },
  }, null, 2));
  const targets = new TargetRegistry({ configPath: targetsPath });
  const contexts = {} as ContextRegistry;
  let providerDispatches = 0;
  const filesystem = {
    async execute(_input: UniversalFilesystemInput, callContext?: CapabilityCallContext) {
      requireCapabilityCallContext(callContext);
      providerDispatches += 1;
      return {
        state: "UPDATED",
        targetId: "local",
        bytesWritten: 11,
      };
    },
  } as unknown as UniversalFilesystemService;
  const metrics = new UniversalBrokerMetrics();
  const operationAudit = new OperationAuditSink({
    path: join(root, "audit", "operations.ndjson"),
    flushIntervalMs: 60_000,
  });
  t.after(() => operationAudit.close());
  const authorityStorePath = join(root, "authority.sqlite");
  const authority = new OperationAuthorityRegistry({
    minimumRisk: minimumAuthorityRisk,
    storePath: authorityStorePath,
    instanceId: "server-audit-link-owner",
    metrics,
  });
  t.after(() => authority.close());
  const resource = new URL("https://broker.example.test/mcp");
  const authorityPrincipal: AuthorityPrincipalConfiguration = {
    environment: "production",
    mode: "single-owner",
    issuer: "https://issuer.example.test/",
    resource: resource.href,
    ownerInstanceId: "server-audit-link-principal",
  };
  const authInfo: AuthInfo = {
    token: "server-audit-link-token",
    clientId: "server-audit-link-client",
    resource,
    scopes: ["devspace.read", "devspace.write"],
  };
  const principal = resolveAuthorityPrincipal({ authInfo }, authorityPrincipal).fingerprint;
  const input: UniversalFilesystemInput = {
    operation: "write",
    target: "local",
    path: "/tmp/raw-audit-link-path-must-not-leak.txt",
    content: "hello audit",
    overwrite: true,
  };
  const targetBinding = await targets.resolveWithGeneration("local");
  const descriptor = filesystemAction(input, targetBinding.target.id);
  const boundDescriptor = {
    ...descriptor,
    parameters: {
      ...(descriptor.parameters ?? {}),
      targetGeneration: targetBinding.generation,
    },
  };
  const created = authority.create({
    authorityText: "Allow exactly one fake filesystem write for audit linkage.",
    actions: [{ descriptor: boundDescriptor }],
  }, principal);
  const server = createUniversalBrokerMcpServer({
    targets,
    contexts,
    filesystem,
    authority,
    authorityPrincipal,
    metrics,
    operationAudit,
  });
  const client = new Client({ name: "server-audit-link-test", version: "1.0.0" });
  const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
  const send = clientTransport.send.bind(clientTransport);
  clientTransport.send = (message, options) => send(message, { ...options, authInfo });
  await Promise.all([client.connect(clientTransport), server.connect(serverTransport)]);

  try {
    const result = await client.callTool({
      name: "fs",
      arguments: { ...input },
      _meta: { devspace: { authorityId: String(created.authorityId) } },
    });
    assert.notEqual(result.isError, true, JSON.stringify(result.structuredContent));
    assert.equal(providerDispatches, 1);
    await operationAudit.close();
    const status = authority.status(String(created.authorityId), principal) as {
      receipts: Array<{
        receiptDigest: string;
        state: string;
        auditState?: string;
        auditEventDigest?: string;
      }>;
    };
    const receiptDigest = status.receipts[0]?.receiptDigest;
    assert.match(receiptDigest ?? "", /^sha256:[a-f0-9]{64}$/u);
    assert.equal(status.receipts[0]?.state, "PASS");

    const auditText = await readFile(join(root, "audit", "operations.ndjson"), "utf8");
    assert.equal(auditText.includes("raw-audit-link-path-must-not-leak"), false);
    assert.equal(auditText.includes("hello audit"), false);
    assert.equal(auditText.includes("Allow exactly one fake"), false);
    const auditRecords = auditText.trim().split("\n")
      .map((line) => JSON.parse(line)) as Array<Record<string, unknown>>;
    const auditRecord = auditRecords.find((record) => record.receiptDigest === receiptDigest);
    assert.ok(auditRecord);
    assert.match(String(auditRecord.eventDigest), /^sha256:[a-f0-9]{64}$/u);
    assert.equal(status.receipts[0]?.auditState, "RECORDED");
    assert.equal(status.receipts[0]?.auditEventDigest, auditRecord.eventDigest);
    authority.close();
    const reopened = new OperationAuthorityRegistry({
      minimumRisk: minimumAuthorityRisk,
      storePath: authorityStorePath,
      instanceId: "server-audit-link-readback",
    });
    const reopenedStatus = reopened.status(String(created.authorityId), principal) as {
      receipts: Array<{ auditState?: string; auditEventDigest?: string }>;
    };
    assert.equal(reopenedStatus.receipts[0]?.auditState, "RECORDED");
    assert.equal(reopenedStatus.receipts[0]?.auditEventDigest, auditRecord.eventDigest);
    reopened.close();
    assert.match(
      metrics.render({}),
      /devspace_authority_claims_total\{risk="R1",state="PASS"\} 1/u,
    );
  } finally {
    await Promise.allSettled([client.close(), server.close()]);
  }
});

test("permanent fs.sync apply is bound to exact R3 authority before deletion dispatch", async (t) => {
  const root = await mkdtemp(join(tmpdir(), "devspace-v3-sync-r3-server-"));
  t.after(() => rm(root, { recursive: true, force: true }));
  const source = join(root, "source");
  const destination = join(root, "destination");
  await mkdir(source, { recursive: true });
  await mkdir(destination, { recursive: true });
  await writeFile(join(destination, "delete.txt"), "delete\n");
  const targets = new TargetRegistry({ configPath: join(root, "missing-targets.json") });
  const contexts = {} as ContextRegistry;
  let deleteDispatches = 0;
  const trashRoot = join(root, "filesystem-trash");
  const trash = new RecoverableFilesystemTrash(trashRoot);
  const baseSyncAdapter = createLocalFilesystemSyncAdapter("local", trash);
  const filesystem = new UniversalFilesystemService(
    targets,
    contexts,
    {} as UniversalExecutionPlane,
    {
      sshControlDir: join(root, "ssh"),
      trashRoot,
      syncAdapter: {
        ...baseSyncAdapter,
        applyOperation: async (input) => {
          if (input.operation.kind === "DELETE_ENTRY") deleteDispatches += 1;
          return baseSyncAdapter.applyOperation(input);
        },
      },
    },
  );
  const authority = new OperationAuthorityRegistry({
    minimumRisk: minimumAuthorityRisk,
    storePath: join(root, "authority.sqlite"),
    instanceId: "sync-r3-server-authority",
  });
  t.after(() => authority.close());
  const resource = new URL("https://broker.example.test/mcp");
  const authorityPrincipal: AuthorityPrincipalConfiguration = {
    environment: "production",
    mode: "single-owner",
    issuer: "https://issuer.example.test/",
    resource: resource.href,
    ownerInstanceId: "sync-r3-server-owner",
  };
  const server = createUniversalBrokerMcpServer({
    targets,
    contexts,
    filesystem,
    authority,
    authorityPrincipal,
  });
  const client = new Client({ name: "sync-r3-server-test", version: "1.0.0" });
  const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
  const send = clientTransport.send.bind(clientTransport);
  const authInfo: AuthInfo = {
    token: "sync-r3-server-token",
    clientId: "sync-r3-server-client",
    resource,
    scopes: ["devspace.read", "devspace.write"],
  };
  clientTransport.send = (message, options) => send(message, { ...options, authInfo });
  await Promise.all([client.connect(clientTransport), server.connect(serverTransport)]);

  try {
    const planned = await client.callTool({
      name: "fs",
      arguments: {
        operation: "sync",
        target: "local",
        path: source,
        destination,
        sync: { phase: "plan", deleteMode: "permanent" },
      },
    });
    assert.notEqual(planned.isError, true, JSON.stringify(planned.structuredContent));
    const plan = (planned.structuredContent as {
      data?: { planId?: string; planDigest?: string };
    } | undefined)?.data;
    assert.match(plan?.planId ?? "", /^sync_plan_/u);
    assert.match(plan?.planDigest ?? "", /^[a-f0-9]{64}$/u);
    const applyArguments = {
      operation: "sync",
      target: "local",
      path: source,
      destination,
      sync: {
        phase: "apply",
        planId: plan!.planId!,
        planDigest: plan!.planDigest!,
      },
    };
    assert.deepEqual(Object.keys(applyArguments.sync), ["phase", "planId", "planDigest"]);

    const blocked = await client.callTool({ name: "fs", arguments: applyArguments });
    assert.equal(toolErrorCode(blocked), "AUTHORITY_REQUIRED");
    assert.equal(deleteDispatches, 0);
    assert.equal(await readFile(join(destination, "delete.txt"), "utf8"), "delete\n");

    const prepared = await client.callTool({
      name: "context",
      arguments: {
        operation: "authorize",
        taskId: "sync-r3-server-task",
        authorityText: "Permanently delete only the entries in this exact immutable sync plan.",
        actions: [{ tool: "fs", arguments: applyArguments }],
      },
    });
    assert.notEqual(prepared.isError, true, JSON.stringify(prepared.structuredContent));
    const preparedData = (prepared.structuredContent as {
      data?: {
        authorityId?: string;
        actions?: Array<{ risk?: string; maximumUses?: number }>;
      };
    } | undefined)?.data;
    assert.equal(preparedData?.actions?.[0]?.risk, "R3");
    assert.equal(preparedData?.actions?.[0]?.maximumUses, 1);

    const applied = await client.callTool({
      name: "fs",
      arguments: applyArguments,
      _meta: { devspace: { authorityId: preparedData!.authorityId! } },
    });
    assert.notEqual(applied.isError, true, JSON.stringify(applied.structuredContent));
    assert.equal(deleteDispatches, 1);
    await assert.rejects(readFile(join(destination, "delete.txt"), "utf8"), { code: "ENOENT" });
  } finally {
    await Promise.allSettled([client.close(), server.close()]);
  }
});

test("audit sink failure preserves successful mutation result and marks receipt audit state", async (t) => {
  const root = await mkdtemp(join(tmpdir(), "devspace-v2-audit-failure-boundary-"));
  t.after(() => rm(root, { recursive: true, force: true }));
  const targetsPath = join(root, "targets.json");
  await writeFile(targetsPath, JSON.stringify({
    version: 1,
    targets: {
      local: {
        displayName: "Local",
        aliases: ["local"],
        transport: "local",
        platform: "macos",
        shell: "zsh",
      },
    },
  }, null, 2));
  const targets = new TargetRegistry({ configPath: targetsPath });
  const contexts = {} as ContextRegistry;
  let providerDispatches = 0;
  const filesystem = {
    async execute(_input: UniversalFilesystemInput, callContext?: CapabilityCallContext) {
      requireCapabilityCallContext(callContext);
      providerDispatches += 1;
      return {
        state: "UPDATED",
        targetId: "local",
        bytesWritten: 12,
      };
    },
  } as unknown as UniversalFilesystemService;
  const auditDirectory = join(root, "audit-as-directory");
  await mkdir(auditDirectory);
  const operationAudit = new OperationAuditSink({ path: auditDirectory });
  const authority = new OperationAuthorityRegistry({
    minimumRisk: minimumAuthorityRisk,
    storePath: join(root, "authority.sqlite"),
    instanceId: "server-audit-failure-owner",
  });
  t.after(() => authority.close());
  const resource = new URL("https://broker.example.test/mcp");
  const authorityPrincipal: AuthorityPrincipalConfiguration = {
    environment: "production",
    mode: "single-owner",
    issuer: "https://issuer.example.test/",
    resource: resource.href,
    ownerInstanceId: "server-audit-failure-principal",
  };
  const authInfo: AuthInfo = {
    token: "server-audit-failure-token",
    clientId: "server-audit-failure-client",
    resource,
    scopes: ["devspace.read", "devspace.write"],
  };
  const principal = resolveAuthorityPrincipal({ authInfo }, authorityPrincipal).fingerprint;
  const input: UniversalFilesystemInput = {
    operation: "write",
    target: "local",
    path: "/tmp/raw-audit-failure-path-must-not-leak.txt",
    content: "hello failure",
    overwrite: true,
  };
  const targetBinding = await targets.resolveWithGeneration("local");
  const descriptor = filesystemAction(input, targetBinding.target.id);
  const boundDescriptor = {
    ...descriptor,
    parameters: {
      ...(descriptor.parameters ?? {}),
      targetGeneration: targetBinding.generation,
    },
  };
  const created = authority.create({
    authorityText: "Allow exactly one fake filesystem write even if audit recording fails.",
    actions: [{ descriptor: boundDescriptor }],
  }, principal);
  const server = createUniversalBrokerMcpServer({
    targets,
    contexts,
    filesystem,
    authority,
    authorityPrincipal,
    operationAudit,
  });
  const client = new Client({ name: "server-audit-failure-test", version: "1.0.0" });
  const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
  const send = clientTransport.send.bind(clientTransport);
  clientTransport.send = (message, options) => send(message, { ...options, authInfo });
  await Promise.all([client.connect(clientTransport), server.connect(serverTransport)]);

  try {
    const result = await client.callTool({
      name: "fs",
      arguments: { ...input },
      _meta: { devspace: { authorityId: String(created.authorityId) } },
    });
    assert.notEqual(result.isError, true, JSON.stringify(result.structuredContent));
    assert.equal(providerDispatches, 1);
    const structured = result.structuredContent as {
      audit?: { status?: string; authorityReceiptAuditState?: string };
    };
    assert.equal(structured.audit?.status, "SINK_FAILED");
    assert.equal(structured.audit?.authorityReceiptAuditState, "SINK_FAILED");
    const status = authority.status(String(created.authorityId), principal) as {
      receipts: Array<{
        state: string;
        auditState?: string;
        auditEventDigest?: string;
      }>;
    };
    assert.equal(status.receipts[0]?.state, "PASS");
    assert.equal(status.receipts[0]?.auditState, "SINK_FAILED");
    assert.equal(status.receipts[0]?.auditEventDigest, undefined);
  } finally {
    await Promise.allSettled([client.close(), server.close(), operationAudit.close()]);
  }
});

test("real corrupt authority store does not block authenticated R0 server traffic", async (t) => {
  const root = await mkdtemp(join(tmpdir(), "devspace-v2-corrupt-authority-r0-"));
  t.after(() => rm(root, { recursive: true, force: true }));
  const storePath = join(root, "authority.sqlite");
  await writeFile(storePath, Buffer.from("this is not a sqlite database\n"), { mode: 0o600 });
  const authority = new OperationAuthorityRegistry({
    minimumRisk: minimumAuthorityRisk,
    storePath,
    instanceId: "corrupt-authority-r0-owner",
  });
  t.after(() => authority.close());
  let providerCalls = 0;
  const targets = new TargetRegistry({ configPath: join(root, "missing-targets.json") });
  const list = targets.list.bind(targets);
  targets.list = async (input) => {
    providerCalls += 1;
    return list(input);
  };
  const resource = new URL("https://broker.example.test/mcp");
  const server = createUniversalBrokerMcpServer({
    targets,
    authority,
    authorityPrincipal: {
      environment: "production",
      mode: "single-owner",
      issuer: "https://issuer.example.test/",
      resource: resource.href,
      ownerInstanceId: "corrupt-authority-r0-server-owner",
    },
  });
  const client = new Client({ name: "v2-corrupt-authority-r0-test", version: "1.0.0" });
  const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
  const send = clientTransport.send.bind(clientTransport);
  const authInfo: AuthInfo = {
    token: "corrupt-authority-r0-test-token",
    clientId: "corrupt-authority-r0-test-client",
    resource,
    scopes: ["devspace.read"],
  };
  clientTransport.send = (message, options) => send(message, { ...options, authInfo });
  await Promise.all([client.connect(clientTransport), server.connect(serverTransport)]);
  try {
    const result = await client.callTool({
      name: "target",
      arguments: { operation: "list" },
    });
    assert.notEqual(result.isError, true, JSON.stringify(result.structuredContent));
    assert.equal(providerCalls, 1);
    assert.throws(
      () => authority.create({
        taskId: "corrupt-store-r1",
        authorityText: "This mutation must fail closed while the store is corrupt.",
        actions: [{
          descriptor: {
            tool: "fs",
            operation: "write",
            target: "local",
            resource: "/tmp/corrupt-store-r1.txt",
          },
        }],
      }, "corrupt-store-r1-principal"),
      (error: unknown) => error instanceof Error
        && "code" in error
        && ["AUTHORITY_STORE_UNAVAILABLE", "STATE_CORRUPTED"].includes(String(error.code)),
    );
    assert.equal(providerCalls, 1);
  } finally {
    await Promise.allSettled([client.close(), server.close()]);
  }
});

test("MCP invoke trusts only exact broker policy and blocks a lying readOnly provider before dispatch", async (t) => {
  const root = await mkdtemp(join(tmpdir(), "devspace-v2-mcp-policy-server-"));
  t.after(() => rm(root, { recursive: true, force: true }));
  const routesPath = join(root, "routes.json");
  const policyPath = join(root, "risk-policy.json");
  const exactReadTool = {
    name: "owner_read",
    title: "Owner-approved read",
    description: "Read-only only when exact owner policy and provider contract agree.",
    inputSchema: { type: "object", additionalProperties: false },
    annotations: { readOnlyHint: true, destructiveHint: false },
  };
  const lyingMutationTool = {
    name: "lying_mutation",
    title: "Lying mutation",
    description: "Claims read-only without any broker-owned downgrade policy.",
    inputSchema: { type: "object", additionalProperties: false },
    annotations: { readOnlyHint: true, destructiveHint: false },
  };
  await writeFile(policyPath, JSON.stringify({
    version: 1,
    routeId: "fixture",
    tools: {
      owner_read: {
        risk: "R0",
        toolContractSha256: downstreamMcpToolContractSha256(exactReadTool),
      },
    },
  }, null, 2), { mode: 0o600 });
  await chmod(policyPath, 0o600);
  await writeFile(routesPath, JSON.stringify({
    version: 1,
    routes: {
      fixture: {
        displayName: "Fixture",
        transport: "local-stdio",
        command: process.execPath,
        args: ["--version"],
        riskPolicy: { mode: "broker-owned", policyFile: policyPath },
      },
    },
  }, null, 2));
  let providerDispatches = 0;
  const targets = new TargetRegistry({ configPath: join(root, "missing-targets.json") });
  const proxy = new UniversalMcpProxy(
    new UniversalMcpRouteRegistry(routesPath),
    targets,
    {
      sshControlDir: join(root, "ssh"),
      clientFactory: async (route) => ({
        route,
        routeFingerprint: route.generation,
        client: {
          listTools: async () => ({ tools: [exactReadTool, lyingMutationTool] }),
          callTool: async ({ name }: { name: string }) => {
            providerDispatches += 1;
            return { content: [{ type: "text", text: `called:${name}` }] };
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
  const resource = new URL("https://broker.example.test/mcp");
  const server = createUniversalBrokerMcpServer({
    targets,
    mcpProxy: proxy,
    authorityPrincipal: {
      environment: "production",
      mode: "single-owner",
      issuer: "https://issuer.example.test/",
      resource: resource.href,
      ownerInstanceId: "mcp-risk-server-test-owner",
    },
  });
  const client = new Client({ name: "v2-mcp-risk-test", version: "1.0.0" });
  const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
  const send = clientTransport.send.bind(clientTransport);
  const authInfo: AuthInfo = {
    token: "mcp-risk-test-token",
    clientId: "mcp-risk-test-client",
    resource,
    scopes: ["devspace.mcp"],
  };
  clientTransport.send = (message, options) => send(message, { ...options, authInfo });
  await Promise.all([client.connect(clientTransport), server.connect(serverTransport)]);
  try {
    const blocked = await client.callTool({
      name: "mcp",
      arguments: { operation: "invoke", route: "fixture", name: "lying_mutation" },
    });
    assert.equal(blocked.isError, true);
    assert.equal(toolErrorCode(blocked), "AUTHORITY_REQUIRED");
    assert.equal(providerDispatches, 0);

    const exactRead = await client.callTool({
      name: "mcp",
      arguments: { operation: "invoke", route: "fixture", name: "owner_read" },
    });
    assert.notEqual(exactRead.isError, true);
    assert.equal(providerDispatches, 1);
  } finally {
    await Promise.allSettled([client.close(), server.close()]);
  }
});

test("public exec passes its exact target and classifier binding into the execution plane", async (t) => {
  const root = await mkdtemp(join(tmpdir(), "devspace-v2-exec-binding-server-"));
  t.after(() => rm(root, { recursive: true, force: true }));
  const targetsPath = join(root, "targets.json");
  await writeFile(targetsPath, JSON.stringify({
    version: 1,
    targets: {
      local: {
        displayName: "Local",
        aliases: ["local"],
        transport: "local",
        platform: "macos",
        shell: "zsh",
      },
    },
  }, null, 2));
  const targets = new TargetRegistry({ configPath: targetsPath });
  const contexts = {
    async get() {
      throw new Error("context lookup was not expected");
    },
  } as unknown as ContextRegistry;
  let observedBinding: PreparedExecExecutionBinding | undefined;
  let preparedOwner: CapabilityCallContext | undefined;
  let dispatchedOwner: CapabilityCallContext | undefined;
  const execution = {
    async prepareAuthorityBinding(
      input: ExecuteCommandInput,
      target: TargetDefinition,
      generation: string,
      callContext?: CapabilityCallContext,
    ) {
      preparedOwner = requireCapabilityCallContext(callContext);
      return prepareExecExecutionBinding(input, target, generation);
    },
    async execute(
      _input: ExecuteCommandInput,
      binding?: PreparedExecExecutionBinding,
      _dispatch?: OperationAuthorityDispatchController,
      callContext?: CapabilityCallContext,
    ): Promise<UniversalProcessSnapshot> {
      dispatchedOwner = requireCapabilityCallContext(callContext);
      observedBinding = binding;
      return {
        processId: "proc_binding",
        targetId: "local",
        transport: "local",
        cwd: root,
        tty: false,
        state: "EXITED",
        startedAt: new Date(0).toISOString(),
        wallTimeMs: 0,
        output: "",
        outputTruncated: false,
        outputBytes: 0,
        outputFileTruncated: false,
        resourceUri: "devspace://v1/process/proc_binding/output",
        exitCode: 0,
      };
    },
    async operate() {
      return { processes: [] };
    },
    async readOutput() {
      return { text: "", totalBytes: 0, truncated: false };
    },
  } as unknown as UniversalExecutionPlane;
  const resource = new URL("https://broker.example.test/mcp");
  const server = createUniversalBrokerMcpServer({
    targets,
    contexts,
    execution,
    authorityPrincipal: {
      environment: "production",
      mode: "single-owner",
      issuer: "https://issuer.example.test/",
      resource: resource.href,
      ownerInstanceId: "exec-binding-server-test-owner",
    },
  });
  const client = new Client({ name: "v2-exec-binding-test", version: "1.0.0" });
  const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
  const send = clientTransport.send.bind(clientTransport);
  const authInfo: AuthInfo = {
    token: "exec-binding-test-token",
    clientId: "exec-binding-test-client",
    resource,
    scopes: ["devspace.exec"],
  };
  clientTransport.send = (message, options) => send(message, { ...options, authInfo });
  await Promise.all([client.connect(clientTransport), server.connect(serverTransport)]);
  try {
    const result = await client.callTool({
      name: "exec",
      arguments: { target: "local", command: "git status --short" },
    });
    assert.notEqual(result.isError, true);
    const current = await targets.resolveWithGeneration("local");
    assert.deepEqual(observedBinding, {
      targetId: "local",
      targetGeneration: current.generation,
      targetTransport: "local",
      targetPlatform: "macos",
      shellDialect: "zsh",
      effectiveEnvProfile: undefined,
      effectiveEnvProfileGeneration: undefined,
      effectiveCwd: homedir(),
      mode: "auto",
      tty: false,
      classifierGeneration: EXEC_RISK_CLASSIFIER_GENERATION,
      launchRisk: "R0",
    });
    assert.ok(preparedOwner);
    assert.equal(dispatchedOwner, preparedOwner);
    assert.match(preparedOwner.principalKeyFingerprint, /^[a-f0-9]{64}$/u);
  } finally {
    await Promise.allSettled([client.close(), server.close()]);
  }
});

test("candidate connector permits R0 canaries but rejects authority and mutation before dispatch", async (t) => {
  const root = await mkdtemp(join(tmpdir(), "devspace-v3-candidate-gate-"));
  t.after(() => rm(root, { recursive: true, force: true }));
  const targets = new TargetRegistry({ configPath: join(root, "missing-targets.json") });
  let providerCalls = 0;
  const execution = {
    async prepareAuthorityBinding(input: ExecuteCommandInput, target: TargetDefinition, generation: string) {
      return prepareExecExecutionBinding(input, target, generation);
    },
    async execute() {
      providerCalls += 1;
      throw new Error("Candidate connector mutation must not reach execution.");
    },
    async operate() {
      return { processes: [] };
    },
    async readOutput() {
      return { text: "", totalBytes: 0, truncated: false };
    },
  } as unknown as UniversalExecutionPlane;
  const contexts = {
    async get() {
      throw new Error("Candidate authority rejection must precede context lookup.");
    },
  } as unknown as ContextRegistry;
  const resource = new URL("https://broker.example.test/mcp");
  const server = createUniversalBrokerMcpServer({
    targets,
    contexts,
    execution,
    authorityPrincipal: {
      environment: "production",
      mode: "single-owner",
      issuer: "https://issuer.example.test/",
      resource: resource.href,
      ownerInstanceId: "candidate-gate-owner",
    },
  });
  const client = new Client({ name: "candidate-gate-test", version: "1.0.0" });
  const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
  const send = clientTransport.send.bind(clientTransport);
  const authInfo: AuthInfo = {
    token: "candidate-gate-token",
    clientId: "candidate-gate-client",
    resource,
    scopes: ["devspace.read", "devspace.write", "devspace.exec"],
    extra: {
      devspaceConnector: {
        bindingId: "connector-candidate-fixture",
        state: "CANDIDATE",
        activationRequired: true,
      },
    },
  };
  clientTransport.send = (message, options) => send(message, { ...options, authInfo });
  await Promise.all([client.connect(clientTransport), server.connect(serverTransport)]);
  try {
    const listed = await client.callTool({ name: "target", arguments: { operation: "list" } });
    assert.notEqual(listed.isError, true, JSON.stringify(listed.structuredContent));

    const authorize = await client.callTool({
      name: "context",
      arguments: {
        operation: "authorize",
        authorityText: "Attempt candidate mutation authority.",
        actions: [{
          tool: "exec",
          arguments: { target: "local", cwd: root, command: "touch candidate-blocked" },
        }],
      },
    });
    assert.equal(toolErrorCode(authorize), "CONNECTOR_ACTIVATION_REQUIRED");

    const mutation = await client.callTool({
      name: "exec",
      arguments: { target: "local", cwd: root, command: "touch candidate-blocked" },
    });
    assert.equal(toolErrorCode(mutation), "CONNECTOR_ACTIVATION_REQUIRED");
    assert.equal(providerCalls, 0);
  } finally {
    await Promise.allSettled([client.close(), server.close()]);
  }
});

test("public stopped signal cancels and reclaims while authority mismatch keeps provider calls at zero", async (t) => {
  const root = await mkdtemp(join(tmpdir(), "devspace-v2-process-cancel-server-"));
  t.after(() => rm(root, { recursive: true, force: true }));
  const resource = new URL("https://broker.example.test/mcp");
  const authority = new OperationAuthorityRegistry({
    minimumRisk: minimumAuthorityRisk,
    storePath: join(root, "authority.sqlite"),
    instanceId: "process-cancel-server-authority-owner",
  });
  t.after(() => authority.close());
  let providerCalls = 0;
  const stoppedSnapshot: UniversalProcessSnapshot = {
    processId: "proc_stopped",
    targetId: "local",
    transport: "local",
    cwd: root,
    tty: false,
    state: "EXITED",
    startedAt: new Date(0).toISOString(),
    endedAt: new Date(1).toISOString(),
    wallTimeMs: 1,
    output: "",
    outputTruncated: false,
    outputBytes: 0,
    outputFileTruncated: false,
    resourceUri: "devspace://v1/process/proc_stopped/output",
    exitCode: 0,
  };
  const execution = {
    authorityBinding() {
      return {
        targetId: "local",
        targetGeneration: "process-generation-1",
        targetTransport: "local" as const,
        tty: false,
        launchRisk: "R1" as const,
      };
    },
    async operate(
      input: { operation: string },
      dispatch?: OperationAuthorityDispatchController,
    ) {
      if (input.operation === "signal") {
        dispatch?.claim();
        return stoppedSnapshot;
      }
      providerCalls += 1;
      return { processes: [] };
    },
    async readOutput() {
      return { text: "", totalBytes: 0, truncated: false };
    },
  } as unknown as UniversalExecutionPlane;
  const server = createUniversalBrokerMcpServer({
    targets: new TargetRegistry({ configPath: join(root, "missing-targets.json") }),
    contexts: {} as ContextRegistry,
    execution,
    authority,
    authorityPrincipal: {
      environment: "production",
      mode: "single-owner",
      issuer: "https://issuer.example.test/",
      resource: resource.href,
      ownerInstanceId: "process-cancel-server-owner",
    },
  });
  const client = new Client({ name: "v2-process-cancel-test", version: "1.0.0" });
  const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
  const send = clientTransport.send.bind(clientTransport);
  const authInfo: AuthInfo = {
    token: "process-cancel-test-token",
    clientId: "process-cancel-test-client",
    resource,
    scopes: ["devspace.read", "devspace.exec"],
  };
  clientTransport.send = (message, options) => send(message, { ...options, authInfo });
  await Promise.all([client.connect(clientTransport), server.connect(serverTransport)]);
  try {
    const prepared = await client.callTool({
      name: "context",
      arguments: {
        operation: "authorize",
        taskId: "stopped-signal-cancel",
        authorityText: "Signal the exact process only if it is still running.",
        actions: [{
          tool: "process",
          arguments: {
            operation: "signal",
            processId: "proc_stopped",
            signal: "SIGTERM",
          },
        }],
      },
    });
    assert.notEqual(prepared.isError, true, JSON.stringify(prepared.structuredContent));
    const authorityId = (prepared.structuredContent as {
      data?: { authorityId?: string };
    } | undefined)?.data?.authorityId;
    assert.equal(typeof authorityId, "string");

    const stopped = await client.callTool({
      name: "process",
      arguments: {
        operation: "signal",
        processId: "proc_stopped",
        signal: "SIGTERM",
      },
      _meta: { devspace: { authorityId } },
    });
    assert.notEqual(stopped.isError, true, JSON.stringify(stopped.structuredContent));
    assert.equal(providerCalls, 0);
    const status = await client.callTool({
      name: "context",
      arguments: { operation: "authority_status" },
      _meta: { devspace: { authorityId } },
    });
    const statusData = (status.structuredContent as {
      data?: {
        actions?: Array<{ consumedUses: number }>;
        receipts?: Array<{ state: string; leaseState: string }>;
      };
    } | undefined)?.data;
    assert.equal(statusData?.actions?.[0]?.consumedUses, 0);
    assert.equal(statusData?.receipts?.[0]?.state, "CANCELLED_NOT_DISPATCHED");
    assert.equal(statusData?.receipts?.[0]?.leaseState, "RELEASED");

    const mismatch = await client.callTool({
      name: "process",
      arguments: {
        operation: "signal",
        processId: "proc_stopped",
        signal: "SIGKILL",
      },
      _meta: { devspace: { authorityId } },
    });
    assert.equal(mismatch.isError, true);
    assert.equal(toolErrorCode(mismatch), "AUTHORITY_ACTION_MISMATCH");
    assert.equal(providerCalls, 0);
  } finally {
    await Promise.allSettled([client.close(), server.close()]);
  }
});

function toolErrorCode(result: unknown): unknown {
  return (
    (result as { structuredContent?: unknown }).structuredContent as
      | { error?: { code?: unknown } }
      | undefined
  )?.error?.code;
}

function minimalArguments(name: UniversalToolName): Record<string, unknown> {
  switch (name) {
    case "target":
      return { operation: "list" };
    case "context":
      return { operation: "search", query: "release" };
    case "fs":
      return { operation: "stat", path: "/tmp" };
    case "exec":
      return { command: "true" };
    case "process":
      return { operation: "list" };
    case "mcp":
      return { operation: "routes" };
    case "artifact":
      return { operation: "publish", source: {} };
    case "gui":
      return { operation: "capabilities" };
  }
}
