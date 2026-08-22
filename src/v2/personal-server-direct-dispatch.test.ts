import assert from "node:assert/strict";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import type { AuthInfo } from "@modelcontextprotocol/sdk/server/auth/types.js";
import type { CapabilityCallContext } from "./capability-call-context.js";
import type { ContextRegistry } from "./contexts.js";
import type {
  PreparedExecExecutionBinding,
  UniversalExecutionPlane,
} from "./execution.js";
import type { UniversalFilesystemService } from "./filesystem.js";
import type { UniversalSelfManagementService } from "./self-management.js";
import { createUniversalBrokerMcpServer } from "./server.js";
import { TargetRegistry } from "./targets.js";

test("personal OAuth-scoped fs, exec, and process mutations dispatch directly without hidden authority metadata or store access", async (t) => {
  const root = await mkdtemp(join(tmpdir(), "devspace-personal-direct-server-"));
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
        defaultCwd: root,
      },
    },
  }));
  const targets = new TargetRegistry({ configPath: targetsPath });
  const contexts = {} as ContextRegistry;
  const calls: string[] = [];
  const filesystem = {
    async execute(_input: unknown, callContext?: CapabilityCallContext) {
      assert.ok(callContext?.principalKeyFingerprint);
      calls.push("fs.write");
      return { state: "UPDATED", targetId: "local", bytesWritten: 2 };
    },
  } as unknown as UniversalFilesystemService;
  const prepared: PreparedExecExecutionBinding = {
    targetId: "local",
    targetGeneration: (await targets.resolveWithGeneration("local")).generation,
    targetTransport: "local",
    targetPlatform: "macos",
    shellDialect: "zsh",
    effectiveCwd: root,
    mode: "foreground",
    tty: false,
    elevationMode: "none",
    elevationPolicy: "deny",
    classifierGeneration: "sha256:" + "1".repeat(64),
    launchRisk: "R3",
  };
  const execution = {
    async prepareExecutionBinding(_input: unknown, _target: unknown, generation: string) {
      assert.equal(generation, prepared.targetGeneration);
      return prepared;
    },
    async execute(_input: unknown, binding: PreparedExecExecutionBinding | undefined, _dispatch: unknown, callContext?: CapabilityCallContext) {
      assert.equal(binding, prepared);
      assert.ok(callContext?.principalKeyFingerprint);
      calls.push("exec.run");
      return { processId: "proc_direct", state: "EXITED", exitCode: 0, output: "direct" };
    },
    async operate(input: { operation: string }, _dispatch: unknown, callContext?: CapabilityCallContext) {
      assert.ok(callContext?.principalKeyFingerprint);
      calls.push(`process.${input.operation}`);
      return { processId: "proc_direct", forgotten: true };
    },
    authorityBinding() {
      return { targetId: "local", targetGeneration: prepared.targetGeneration };
    },
  } as unknown as UniversalExecutionPlane;
  const restartTransactionId = "restart_11111111-1111-4111-8111-111111111111";
  const selfManagement = {
    async status(transactionId: string) {
      assert.equal(transactionId, restartTransactionId);
      calls.push("process.restart_status");
      return { transactionId, state: "PASS", expectedDisconnect: true, history: [] };
    },
  } as unknown as UniversalSelfManagementService;
  let legacyStoreTouches = 0;
  const ignoredLegacyService = new Proxy({}, {
    get() {
      legacyStoreTouches += 1;
      throw new Error("personal request crossed a legacy store boundary");
    },
  });
  const resource = new URL("https://broker.example.test/mcp");
  const authInfo: AuthInfo = {
    token: "personal-direct-test-token",
    clientId: "existing-client",
    resource,
    scopes: ["devspace.read", "devspace.write", "devspace.exec"],
  };
  const server = createUniversalBrokerMcpServer({
    targets,
    contexts,
    filesystem,
    execution,
    selfManagement,
    authority: ignoredLegacyService,
    authorityPrincipal: {
      environment: "production",
      mode: "single-owner",
      issuer: "https://issuer.example.test/",
      resource: resource.href,
      ownerInstanceId: "personal-owner",
    },
  });
  const client = new Client({ name: "personal-direct-test", version: "1.0.0" });
  const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
  const send = clientTransport.send.bind(clientTransport);
  clientTransport.send = (message, options) => send(message, { ...options, authInfo });
  await Promise.all([client.connect(clientTransport), server.connect(serverTransport)]);
  t.after(async () => Promise.allSettled([client.close(), server.close()]));

  for (const request of [
    { name: "fs", arguments: { operation: "write", target: "local", path: join(root, "file.txt"), content: "ok" } },
    { name: "exec", arguments: { target: "local", cwd: root, command: "printf direct", mode: "foreground" } },
    { name: "process", arguments: { operation: "forget", processId: "proc_direct" } },
  ]) {
    const result = await client.callTool(request);
    assert.notEqual(result.isError, true, JSON.stringify(result.structuredContent));
    assert.equal((result.structuredContent as { ok?: unknown })?.ok, true);
  }
  const restartStatus = await client.callTool({
    name: "process",
    arguments: { operation: "restart_status", transactionId: restartTransactionId },
  });
  assert.notEqual(restartStatus.isError, true, JSON.stringify(restartStatus.structuredContent));
  assert.equal(
    (restartStatus.structuredContent as { data?: { transactionId?: string } })?.data?.transactionId,
    restartTransactionId,
  );
  assert.deepEqual(calls, ["fs.write", "exec.run", "process.forget", "process.restart_status"]);
  assert.equal(legacyStoreTouches, 0);
});
