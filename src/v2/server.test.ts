import assert from "node:assert/strict";
import { chmod, mkdtemp, rm, writeFile } from "node:fs/promises";
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
  minimumAuthorityRisk,
} from "./authority-policy.js";
import type {
  ExecuteCommandInput,
  PreparedExecExecutionBinding,
  UniversalExecutionPlane,
  UniversalProcessSnapshot,
} from "./execution.js";
import { prepareExecExecutionBinding } from "./execution.js";
import {
  downstreamMcpToolContractSha256,
  type DownstreamMcpSession,
  UniversalMcpProxy,
} from "./mcp-proxy.js";
import { UniversalMcpRouteRegistry } from "./mcp-routes.js";
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
    "devspace://process/process-test/output/0/10",
    "devspace://mcp/fixture/result/result-test/0/10",
    "devspace://context-diff/diff-test/0/10",
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
      /devspace_requests_total\{operation="list",result="fail",tool="target"\} 3/u,
    );
    assert.match(
      renderedMetrics,
      /devspace_requests_total\{operation="list",result="pass",tool="target"\} 1/u,
    );
    assert.match(
      renderedMetrics,
      /devspace_requests_total\{operation="list",result="pass",tool="process"\} 1/u,
    );
  } finally {
    await Promise.allSettled([client.close(), server.close()]);
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
        resourceUri: "devspace://process/proc_binding/output/0/0",
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
    resourceUri: "devspace://process/proc_stopped/output/0/0",
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
        authorityId,
      },
    });
    assert.notEqual(stopped.isError, true, JSON.stringify(stopped.structuredContent));
    assert.equal(providerCalls, 0);
    const status = await client.callTool({
      name: "context",
      arguments: { operation: "authority_status", authorityId },
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
        authorityId,
      },
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
