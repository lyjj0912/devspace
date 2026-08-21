import assert from "node:assert/strict";
import {
  mkdtemp,
  mkdir,
  realpath,
  readdir,
  readFile,
  rm,
  stat,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import type { RuntimeIdentity } from "./contracts.js";
import { UniversalBrokerError } from "./errors.js";
import {
  UniversalSelfManagementService,
  atomicRestartStatusWrite,
  restartWorkerLaunchDescriptor,
  restartWorkerLaunchctlCommand,
  type RestartTransactionStatus,
  type RestartWorkerRequest,
} from "./self-management.js";
import {
  runRestartWorker,
  type RestartWorkerRuntime,
} from "./self-management-worker.js";
import { UniversalBrokerMetrics } from "./metrics.js";

const OWNER = "a".repeat(64);
const TRANSPORT = "http-request-test-1";
const TEST_RUNTIME_IDENTITY: RuntimeIdentity = {
  productVersion: "3.0.0",
  productProfile: "PERSONAL_DIRECT_OWNER",
  buildCapabilityDigest: `sha256:${"5".repeat(64)}`,
  resourceUriVersion: "v1",
  schemaGeneration: `sha256:${"1".repeat(64)}`,
  configDigest: `sha256:${"3".repeat(64)}`,
  sourceRevision: "source-test",
  runtimeRevision: "runtime-test",
  buildDigest: `sha256:${"4".repeat(64)}`,
  startedAt: "2026-08-20T00:00:00.000Z",
};

test("self-management requires the complete personal runtime identity tuple", async (t) => {
  const root = await temporaryRoot(t, "devspace-self-management-runtime-identity-");
  const {
    productProfile: _productProfile,
    buildCapabilityDigest: _buildCapabilityDigest,
    resourceUriVersion: _resourceUriVersion,
    ...legacyIdentity
  } = TEST_RUNTIME_IDENTITY;
  assert.throws(
    () => serviceFixture(root, { runtimeIdentity: legacyIdentity as RuntimeIdentity }),
    /runtimeIdentity is missing or invalid/u,
  );
});

test("supervisor readiness performs a real PM2 RPC readback without starting a daemon", async (t) => {
  const root = await temporaryRoot(t, "devspace-self-management-pm2-readiness-");
  const pm2Root = join(root, "pm2");
  const pm2Executable = join(pm2Root, "bin", "pm2");
  await mkdir(join(pm2Root, "bin"), { recursive: true });
  await Promise.all([
    writeFile(pm2Executable, "#!/bin/sh\n", { mode: 0o700 }),
    writeFile(join(pm2Root, "package.json"), `${JSON.stringify({ main: "index.cjs" })}\n`),
    writeFile(join(pm2Root, "index.cjs"), `
module.exports = {
  Client: {
    launchRPC(callback) { callback(null); },
    executeRemote(method, _input, callback) {
      if (method !== "getMonitorData") return callback(new Error("unexpected RPC method"));
      callback(null, [{
        name: "devspace-test",
        pid: 12345,
        pm2_env: {
          status: "online",
          pm_cwd: ${JSON.stringify(root)},
          pm_exec_path: ${JSON.stringify(join(root, "start.js"))},
        },
      }]);
    },
  },
};
`),
  ]);

  const service = serviceFixture(root, { pm2Executable });
  const observed = await service.supervisorReadiness();
  assert.equal(observed.state, "PASS", JSON.stringify(observed));
  assert.deepEqual(observed.evidence, {
    controlChannel: "pm2-rpc",
    processMatches: 1,
    online: true,
    cwdMatches: true,
    scriptMatches: true,
    pid: 12345,
  });
});

test("packaged restart worker uses the runtime dependency loader without inheriting secrets", async (t) => {
  const root = await temporaryRoot(t, "devspace-self-management-packaged-worker-");
  const workerPath = join(root, "dist", "v2", "self-management-worker.js");
  const loaderPath = join(root, "scripts", "lib", "runtime-dependency-loader.mjs");
  const dependencyRoot = join(root, "dependencies");
  const requestPath = join(root, "request.json");
  await Promise.all([
    mkdir(join(root, "dist", "v2"), { recursive: true }),
    mkdir(join(root, "scripts", "lib"), { recursive: true }),
    mkdir(dependencyRoot, { recursive: true }),
  ]);
  await Promise.all([
    writeFile(workerPath, "export {};\n"),
    writeFile(loaderPath, "export {};\n"),
    writeFile(join(dependencyRoot, "package.json"), "{}\n"),
    writeFile(requestPath, "{}\n"),
  ]);
  const request: RestartWorkerRequest = {
    version: 2,
    transactionId: "restart_11111111-1111-4111-8111-111111111111",
    requestedAt: "2026-08-21T00:00:00.000Z",
    ownerFingerprint: OWNER,
    timeoutMs: 10_000,
    pm2ProcessName: "devspace-test",
    pm2Executable: "/usr/bin/true",
    expectedCwd: root,
    localHealthUrl: "http://127.0.0.1:17690/healthz",
    expectedRuntimeIdentity: TEST_RUNTIME_IDENTITY,
    statusPath: join(root, "status.json"),
    requestPath,
    workerLogPath: join(root, "worker.log"),
  };
  const descriptor = restartWorkerLaunchDescriptor(request, workerPath, {
    HOME: root,
    PATH: "/usr/bin:/bin",
    DEVSPACE_RUNTIME_DEPENDENCY_ROOT: dependencyRoot,
    DEVSPACE_RUNTIME_SECRET: "must-not-leak",
    OAUTH_CLIENT_SECRET: "must-not-leak",
  });
  const [realRoot, realDependencyRoot, realWorkerPath, realLoaderPath] = await Promise.all([
    realpath(root),
    realpath(dependencyRoot),
    realpath(workerPath),
    realpath(loaderPath),
  ]);
  assert.deepEqual(descriptor.arguments, [
    "--import",
    realLoaderPath,
    realWorkerPath,
    requestPath,
  ]);
  assert.equal(descriptor.dependencyLoaderPath, realLoaderPath);
  assert.equal(descriptor.environment.DEVSPACE_RUNTIME_PACKAGE_ROOT, realRoot);
  assert.equal(descriptor.environment.DEVSPACE_RUNTIME_DEPENDENCY_ROOT, realDependencyRoot);
  assert.equal(descriptor.environment.DEVSPACE_RUNTIME_SECRET, undefined);
  assert.equal(descriptor.environment.OAUTH_CLIENT_SECRET, undefined);
  const launchctlCommand = restartWorkerLaunchctlCommand(descriptor);
  assert.equal(launchctlCommand.executable, "/usr/bin/env");
  assert.deepEqual(launchctlCommand.arguments.slice(0, 3), [
    "-i",
    `HOME=${root}`,
    "PATH=/usr/bin:/bin",
  ]);
  assert.ok(launchctlCommand.arguments.includes(`DEVSPACE_RUNTIME_PACKAGE_ROOT=${realRoot}`));
  assert.ok(launchctlCommand.arguments.includes(`DEVSPACE_RUNTIME_DEPENDENCY_ROOT=${realDependencyRoot}`));
  assert.deepEqual(launchctlCommand.arguments.slice(-5), [
    process.execPath,
    "--import",
    realLoaderPath,
    realWorkerPath,
    requestPath,
  ]);
  assert.equal(launchctlCommand.arguments.some((value) => value.includes("must-not-leak")), false);
});

test("restart handoff occurs only after the exact response is durably ACK_FLUSHED", async (t) => {
  const root = await temporaryRoot(t, "devspace-self-management-ack-");
  const launches: RestartWorkerRequest[] = [];
  const service = serviceFixture(root, {
    launchWorker(request) {
      launches.push(request);
    },
  });

  const prepared = await service.requestRestart({
    reason: "test restart",
    ownerFingerprint: OWNER,
  });
  assert.equal(prepared.state, "PREPARED");
  assert.equal(launches.length, 0);

  const bound = await service.withResponseTransport(
    TRANSPORT,
    () => service.bindResponse(prepared.transactionId, "rpc-request-17"),
  );
  assert.equal(bound.state, "RESPONSE_BOUND");
  assert.equal(bound.responseTransportId, TRANSPORT);
  assert.equal(bound.responseRequestId, "rpc-request-17");
  assert.equal(launches.length, 0);

  assert.equal(
    await service.boundTransactionId(TRANSPORT, "rpc-request-17"),
    prepared.transactionId,
  );
  const flushed = await service.responseFlushedForRequest(TRANSPORT, "rpc-request-17");
  assert.equal(flushed?.state, "ACK_FLUSHED");
  assert.equal(launches.length, 1);
  assert.equal(launches[0]?.transactionId, prepared.transactionId);

  const duplicate = await service.responseFlushed(
    prepared.transactionId,
    TRANSPORT,
    "rpc-request-17",
  );
  assert.equal(duplicate.state, "ACK_FLUSHED");
  assert.equal(launches.length, 1);

  const lateAbort = await service.responseAbortedForRequest(TRANSPORT, "rpc-request-17", "close");
  assert.equal(lateAbort?.state, "ACK_FLUSHED");
  assert.equal(launches.length, 1);

  const persisted = await service.status(prepared.transactionId);
  assert.equal(persisted.ackFlushedAt, flushed?.ackFlushedAt);
  assert.deepEqual(persisted.history?.map((entry) => entry.state), [
    "PREPARED",
    "RESPONSE_BOUND",
    "ACK_FLUSHED",
  ]);
  const transactionRoot = join(root, "state", "restart-transactions");
  assert.equal((await stat(transactionRoot)).mode & 0o777, 0o700);
  assert.equal((await stat(join(transactionRoot, prepared.transactionId, "status.json"))).mode & 0o777, 0o600);
});

test("response abort is terminal, idempotent, and never launches the supervisor", async (t) => {
  const root = await temporaryRoot(t, "devspace-self-management-abort-");
  const launches: RestartWorkerRequest[] = [];
  const service = serviceFixture(root, { launchWorker: (request) => launches.push(request) });
  const prepared = await service.requestRestart({
    ownerFingerprint: OWNER,
  });
  await service.bindResponse(prepared.transactionId, "rpc-request-abort", TRANSPORT);

  const aborted = await service.responseAbortedForRequest(
    TRANSPORT,
    "rpc-request-abort",
    "request aborted",
  );
  assert.equal(aborted?.state, "FAIL");
  assert.equal(aborted?.abortReason, "request aborted");
  assert.equal(launches.length, 0);

  assert.deepEqual(aborted?.history.map((entry) => entry.state), [
    "PREPARED",
    "RESPONSE_BOUND",
    "ACK_ABORTED",
    "FAIL",
  ]);
  assert.equal((await service.responseAborted(
    prepared.transactionId,
    TRANSPORT,
    "rpc-request-abort",
    "duplicate",
  )).state, "FAIL");
  assert.equal(
    (await service.responseFlushedForRequest(TRANSPORT, "rpc-request-abort"))?.state,
    "FAIL",
  );
  assert.equal(launches.length, 0);

  const replacement = await service.requestRestart({
    ownerFingerprint: OWNER,
  });
  assert.equal(replacement.state, "PREPARED");
});

test("restart metrics derive from durable states, deduplicate callbacks, and never mask results", async (t) => {
  const metrics = new UniversalBrokerMetrics();
  const flushedRoot = await temporaryRoot(t, "devspace-self-management-metrics-flush-");
  const flushedService = serviceFixture(flushedRoot, {
    metrics,
    launchWorker() {},
  });
  const prepared = await flushedService.requestRestart({
    ownerFingerprint: OWNER,
  });
  await flushedService.bindResponse(prepared.transactionId, "rpc-metrics-flush", TRANSPORT);
  await flushedService.responseFlushedForRequest(TRANSPORT, "rpc-metrics-flush");
  await flushedService.responseFlushedForRequest(TRANSPORT, "rpc-metrics-flush");

  const abortedRoot = await temporaryRoot(t, "devspace-self-management-metrics-abort-");
  const abortedService = serviceFixture(abortedRoot, { metrics });
  const aborted = await abortedService.requestRestart({
    ownerFingerprint: OWNER,
  });
  await abortedService.bindResponse(aborted.transactionId, "rpc-metrics-abort", TRANSPORT);
  await abortedService.responseAbortedForRequest(TRANSPORT, "rpc-metrics-abort", "closed");
  const rendered = metrics.render({});
  assert.match(rendered, /devspace_restart_transactions_total\{result="requested"\} 2/u);
  assert.match(rendered, /devspace_restart_transactions_total\{result="ack_flushed"\} 1/u);
  assert.match(rendered, /devspace_restart_transactions_total\{result="fail"\} 1/u);

  const throwingMetrics = {
    recordRestartTransaction: () => { throw new Error("metrics unavailable"); },
  } as unknown as UniversalBrokerMetrics;
  const resilientRoot = await temporaryRoot(t, "devspace-self-management-metrics-resilient-");
  const resilientService = serviceFixture(resilientRoot, { metrics: throwingMetrics });
  assert.equal((await resilientService.requestRestart({
    ownerFingerprint: OWNER,
  })).state, "PREPARED");
});

test("ACK persistence failure prevents supervisor launch", async (t) => {
  const root = await temporaryRoot(t, "devspace-self-management-write-failure-");
  const launches: RestartWorkerRequest[] = [];
  const service = serviceFixture(root, {
    launchWorker: (request) => launches.push(request),
    async writeStatus(path, status) {
      if (status.state === "ACK_FLUSHED") throw new Error("injected durable ACK failure");
      await atomicRestartStatusWrite(path, status);
    },
  });
  const prepared = await service.requestRestart({ ownerFingerprint: OWNER });
  await service.bindResponse(prepared.transactionId, "rpc-request-write-failure", TRANSPORT);

  await assert.rejects(
    service.responseFlushedForRequest(TRANSPORT, "rpc-request-write-failure"),
    /injected durable ACK failure/u,
  );
  assert.equal(launches.length, 0);
  assert.equal((await service.status(prepared.transactionId)).state, "RESPONSE_BOUND");
});

test("ACK_ABORTED is durable before FAIL and a failed terminal write is safely retryable", async (t) => {
  const root = await temporaryRoot(t, "devspace-self-management-abort-write-failure-");
  let failTerminalWrite = true;
  const service = serviceFixture(root, {
    async writeStatus(path, status) {
      if (status.state === "FAIL" && failTerminalWrite) {
        failTerminalWrite = false;
        throw new Error("injected terminal abort write failure");
      }
      await atomicRestartStatusWrite(path, status);
    },
  });
  const prepared = await service.requestRestart({ ownerFingerprint: OWNER });
  await service.bindResponse(
    prepared.transactionId,
    "rpc-request-abort-write-failure",
    TRANSPORT,
  );

  await assert.rejects(
    service.responseAbortedForRequest(
      TRANSPORT,
      "rpc-request-abort-write-failure",
      "transport closed",
    ),
    /injected terminal abort write failure/u,
  );
  assert.equal((await service.status(prepared.transactionId)).state, "ACK_ABORTED");

  const retried = await service.responseAborted(
    prepared.transactionId,
    TRANSPORT,
    "rpc-request-abort-write-failure",
    "transport closed",
  );
  assert.equal(retried.state, "FAIL");
  assert.deepEqual(retried.history.map((entry) => entry.state), [
    "PREPARED",
    "RESPONSE_BOUND",
    "ACK_ABORTED",
    "FAIL",
  ]);
});

test("reused JSON-RPC IDs cannot acknowledge a restart bound to another HTTP response", async (t) => {
  const root = await temporaryRoot(t, "devspace-self-management-transport-binding-");
  const launches: RestartWorkerRequest[] = [];
  const service = serviceFixture(root, { launchWorker: (request) => launches.push(request) });
  const sharedRequestId = "rpc-reused-across-transports";

  const first = await service.requestRestart({ ownerFingerprint: OWNER });
  await service.bindResponse(first.transactionId, sharedRequestId, "http-response-old");
  await service.responseAbortedForRequest(
    "http-response-old",
    sharedRequestId,
    "old response aborted",
  );

  const second = await service.requestRestart({
    ownerFingerprint: OWNER,
  });
  await service.bindResponse(second.transactionId, sharedRequestId, "http-response-current");
  assert.equal(
    await service.responseFlushedForRequest("http-response-unrelated", sharedRequestId),
    undefined,
  );
  assert.equal(
    (await service.responseFlushedForRequest("http-response-old", sharedRequestId))?.state,
    "FAIL",
  );
  assert.equal(launches.length, 0);

  const flushed = await service.responseFlushedForRequest(
    "http-response-current",
    sharedRequestId,
  );
  assert.equal(flushed?.transactionId, second.transactionId);
  assert.equal(flushed?.state, "ACK_FLUSHED");
  assert.deepEqual(launches.map((request) => request.transactionId), [second.transactionId]);
});

test("duplicate durable transport bindings fail closed even when only one match is active", async (t) => {
  const root = await temporaryRoot(t, "devspace-self-management-ambiguous-binding-");
  const service = serviceFixture(root);
  const requestId = "rpc-ambiguous-binding";
  const transportId = "http-response-reused";

  const first = await service.requestRestart({ ownerFingerprint: OWNER });
  await service.bindResponse(first.transactionId, requestId, transportId);
  await service.responseAbortedForRequest(transportId, requestId, "first response aborted");
  const second = await service.requestRestart({
    ownerFingerprint: OWNER,
  });
  await service.bindResponse(second.transactionId, requestId, transportId);

  await assert.rejects(
    service.boundTransactionId(transportId, requestId),
    (error: unknown) => brokerCode(error) === "PRECONDITION_FAILED",
  );
  await assert.rejects(
    service.responseFlushedForRequest(transportId, requestId),
    (error: unknown) => brokerCode(error) === "PRECONDITION_FAILED",
  );
  assert.equal((await service.status(second.transactionId)).state, "RESPONSE_BOUND");
});

test("an uncertain supervisor launch is durable UNKNOWN and is never auto-retried", async (t) => {
  const root = await temporaryRoot(t, "devspace-self-management-launch-unknown-");
  let launchCalls = 0;
  const service = serviceFixture(root, {
    launchWorker() {
      launchCalls += 1;
      throw new Error("supervisor handoff result unavailable");
    },
  });
  const prepared = await service.requestRestart({ ownerFingerprint: OWNER });
  await service.bindResponse(prepared.transactionId, "rpc-launch-unknown", TRANSPORT);

  await assert.rejects(
    service.responseFlushedForRequest(TRANSPORT, "rpc-launch-unknown"),
    (error: unknown) => brokerCode(error) === "SUPERVISOR_UNAVAILABLE",
  );
  const status = await service.status(prepared.transactionId);
  assert.equal(status.state, "UNKNOWN");
  assert.equal(status.evidence?.automaticRetry, false);
  assert.equal(launchCalls, 1);
});

test("binding is exact and stale nonterminal transactions become UNKNOWN without retry", async (t) => {
  const root = await temporaryRoot(t, "devspace-self-management-unknown-");
  let now = Date.now();
  const launches: RestartWorkerRequest[] = [];
  const service = serviceFixture(root, {
    now: () => now,
    timeoutMs: 10_000,
    launchWorker: (request) => launches.push(request),
  });
  const prepared = await service.requestRestart({ ownerFingerprint: OWNER });
  await service.bindResponse(prepared.transactionId, "rpc-request-stale", TRANSPORT);
  await assert.rejects(
    service.bindResponse(prepared.transactionId, "different-request", TRANSPORT),
    (error: unknown) => brokerCode(error) === "PRECONDITION_FAILED",
  );
  await assert.rejects(
    service.responseFlushed(prepared.transactionId, TRANSPORT, "different-request"),
    (error: unknown) => brokerCode(error) === "PRECONDITION_FAILED",
  );

  now += 10_000 + 30_000 + 1;
  const stale = await service.status(prepared.transactionId);
  assert.equal(stale.state, "UNKNOWN");
  assert.match(stale.error ?? "", /verification deadline/u);
  assert.equal(launches.length, 0);
});

test("a malformed durable transaction blocks a second restart instead of being skipped", async (t) => {
  const root = await temporaryRoot(t, "devspace-self-management-corrupt-state-");
  const service = serviceFixture(root);
  const prepared = await service.requestRestart({ ownerFingerprint: OWNER });
  const statusPath = join(
    root,
    "state",
    "restart-transactions",
    prepared.transactionId,
    "status.json",
  );
  await writeFile(statusPath, "{\"version\":2}\n", { mode: 0o600 });

  await assert.rejects(
    service.requestRestart({
      ownerFingerprint: OWNER,
    }),
    (error: unknown) => brokerCode(error) === "TRANSPORT_INTERRUPTED",
  );
  assert.equal(
    (await readdir(join(root, "state", "restart-transactions"))).length,
    1,
  );
});

test("stale broker polling does not overwrite a restart still owned by the supervisor", async (t) => {
  const root = await temporaryRoot(t, "devspace-self-management-supervisor-owner-");
  let now = Date.now();
  const service = serviceFixture(root, {
    now: () => now,
    timeoutMs: 10_000,
    launchWorker() {},
  });
  const prepared = await service.requestRestart({ ownerFingerprint: OWNER });
  await service.bindResponse(prepared.transactionId, "rpc-supervisor-owner", TRANSPORT);
  const acknowledged = await service.responseFlushedForRequest(
    TRANSPORT,
    "rpc-supervisor-owner",
  );
  assert.equal(acknowledged?.state, "ACK_FLUSHED");

  const acceptedAt = new Date(now).toISOString();
  const accepted: RestartTransactionStatus = {
    ...acknowledged!,
    state: "HANDOFF_ACCEPTED",
    updatedAt: acceptedAt,
    handoffAcceptedAt: acceptedAt,
    workerPid: process.pid,
    history: [
      ...acknowledged!.history,
      { state: "HANDOFF_ACCEPTED", at: acceptedAt },
    ],
  };
  const statusPath = join(
    root,
    "state",
    "restart-transactions",
    prepared.transactionId,
    "status.json",
  );
  await atomicRestartStatusWrite(statusPath, accepted);

  now += 10_000 + 30_000 + 1;
  assert.equal((await service.status(prepared.transactionId)).state, "HANDOFF_ACCEPTED");

  await atomicRestartStatusWrite(statusPath, {
    ...accepted,
    workerPid: 2_147_483_647,
  });
  const recovered = await service.status(prepared.transactionId);
  assert.equal(recovered.state, "UNKNOWN");
  assert.equal(recovered.evidence?.automaticRetry, false);
});

test("supervisor rejects every state except ACK_FLUSHED", async (t) => {
  const root = await temporaryRoot(t, "devspace-restart-worker-reject-");
  const fixture = await workerFixture(root, "PREPARED");
  let restartCalls = 0;
  const runtime: RestartWorkerRuntime = {
    restartPm2() {
      restartCalls += 1;
    },
  };

  await assert.rejects(runRestartWorker(fixture.requestPath, runtime), /ACK_FLUSHED/u);
  assert.equal(restartCalls, 0);
  assert.equal(JSON.parse(await readFile(fixture.statusPath, "utf8")).state, "PREPARED");
});

test("supervisor rejects an ACK_FLUSHED label without a valid durable transition history", async (t) => {
  const root = await temporaryRoot(t, "devspace-restart-worker-invalid-history-");
  const fixture = await workerFixture(root, "ACK_FLUSHED");
  const status = JSON.parse(await readFile(fixture.statusPath, "utf8")) as RestartTransactionStatus;
  status.history = [
    { state: "PREPARED", at: status.requestedAt },
    { state: "ACK_FLUSHED", at: status.requestedAt },
  ];
  await writeFile(fixture.statusPath, `${JSON.stringify(status, null, 2)}\n`, { mode: 0o600 });
  let restartCalls = 0;

  await assert.rejects(runRestartWorker(fixture.requestPath, {
    restartPm2() {
      restartCalls += 1;
    },
  }), /Malformed broker restart status/u);
  assert.equal(restartCalls, 0);
});

test("failure after supervisor acceptance but before restart dispatch is durable UNKNOWN", async (t) => {
  const root = await temporaryRoot(t, "devspace-restart-worker-pre-dispatch-unknown-");
  const fixture = await workerFixture(root, "ACK_FLUSHED");
  let restartCalls = 0;

  await assert.rejects(runRestartWorker(fixture.requestPath, {
    inspectPm2() {
      throw new Error("process-manager readback unavailable");
    },
    restartPm2() {
      restartCalls += 1;
    },
  }), /readback unavailable/u);
  const status = JSON.parse(await readFile(fixture.statusPath, "utf8")) as RestartTransactionStatus;
  assert.equal(status.state, "UNKNOWN");
  assert.equal(status.evidence?.restartAttempted, false);
  assert.equal(status.evidence?.automaticRetry, false);
  assert.equal(restartCalls, 0);
});

test("supervisor durably accepts ACK_FLUSHED then verifies the replacement runtime", async (t) => {
  const root = await temporaryRoot(t, "devspace-restart-worker-pass-");
  const fixture = await workerFixture(root, "ACK_FLUSHED");
  let restarted = false;
  let saved = false;
  const runtime: RestartWorkerRuntime = {
    inspectPm2() {
      return {
        name: "devspace-test",
        pid: restarted ? 222 : 111,
        status: "online",
        cwd: root,
        script: fixture.expectedScript,
      };
    },
    async restartPm2() {
      const status = JSON.parse(await readFile(fixture.statusPath, "utf8")) as RestartTransactionStatus;
      assert.equal(status.state, "RESTARTING");
      assert.deepEqual(status.history?.map((entry) => entry.state), [
        "PREPARED",
        "RESPONSE_BOUND",
        "ACK_FLUSHED",
        "HANDOFF_ACCEPTED",
        "RESTARTING",
      ]);
      restarted = true;
    },
    savePm2() {
      saved = true;
    },
    healthStatus(url) {
      if (url.includes("local")) return Promise.resolve({ status: 200, body: fixture.healthBody });
      return Promise.resolve({ status: 200 });
    },
    sleep: async () => undefined,
  };

  await runRestartWorker(fixture.requestPath, runtime);
  const status = JSON.parse(await readFile(fixture.statusPath, "utf8")) as RestartTransactionStatus;
  assert.equal(status.state, "PASS");
  assert.equal(status.pidBefore, 111);
  assert.equal(status.pidAfter, 222);
  assert.equal(status.localHealthStatus, 200);
  assert.equal(status.publicHealthStatus, 200);
  assert.equal(restarted, true);
  assert.equal(saved, true);
});

test("supervisor retries transient replacement health until the bounded deadline", async (t) => {
  const root = await temporaryRoot(t, "devspace-restart-worker-transient-health-");
  const fixture = await workerFixture(root, "ACK_FLUSHED");
  let now = 0;
  let restarted = false;
  let localHealthCalls = 0;
  await runRestartWorker(fixture.requestPath, {
    now: () => now,
    inspectPm2() {
      return {
        name: "devspace-test",
        pid: restarted ? 222 : 111,
        status: "online",
        cwd: root,
        script: fixture.expectedScript,
      };
    },
    restartPm2() {
      restarted = true;
    },
    savePm2() {},
    healthStatus(url) {
      if (url.includes("local")) {
        localHealthCalls += 1;
        return Promise.resolve(localHealthCalls === 1
          ? { status: 503 }
          : { status: 200, body: fixture.healthBody });
      }
      return Promise.resolve({ status: 200 });
    },
    async sleep(milliseconds) {
      now += milliseconds;
    },
  });

  const status = JSON.parse(await readFile(fixture.statusPath, "utf8")) as RestartTransactionStatus;
  assert.equal(status.state, "PASS");
  assert.equal(localHealthCalls, 2);
  assert.equal(now, 500);
});

test("an ambiguous supervisor result is durable UNKNOWN and is not retried", async (t) => {
  const root = await temporaryRoot(t, "devspace-restart-worker-unknown-");
  const fixture = await workerFixture(root, "ACK_FLUSHED");
  let restartCalls = 0;
  await assert.rejects(runRestartWorker(fixture.requestPath, {
    inspectPm2() {
      return {
        name: "devspace-test",
        pid: 111,
        status: "online",
        cwd: root,
        script: fixture.expectedScript,
      };
    },
    restartPm2() {
      restartCalls += 1;
      throw new Error("supervisor connection closed after dispatch");
    },
  }), /supervisor connection closed/u);

  const status = JSON.parse(await readFile(fixture.statusPath, "utf8")) as RestartTransactionStatus;
  assert.equal(status.state, "UNKNOWN");
  assert.equal(restartCalls, 1);
});

test("post-dispatch runtime identity mismatch is durable UNKNOWN", async (t) => {
  const root = await temporaryRoot(t, "devspace-restart-worker-identity-unknown-");
  const fixture = await workerFixture(root, "ACK_FLUSHED");
  let restarted = false;
  await assert.rejects(runRestartWorker(fixture.requestPath, {
    inspectPm2() {
      return {
        name: "devspace-test",
        pid: restarted ? 222 : 111,
        status: "online",
        cwd: root,
        script: fixture.expectedScript,
      };
    },
    restartPm2() {
      restarted = true;
    },
    savePm2() {},
    healthStatus() {
      return Promise.resolve({
        status: 200,
        body: {
          identity: {
            ...(fixture.healthBody.identity as Record<string, unknown>),
            runtimeRevision: "unexpected-runtime",
          },
        },
      });
    },
  }), /runtime identity mismatch/u);

  const status = JSON.parse(await readFile(fixture.statusPath, "utf8")) as RestartTransactionStatus;
  assert.equal(status.state, "UNKNOWN");
  assert.equal(status.evidence?.automaticRetry, false);
});

test("replacement verification requires positive before and after PID evidence", async (t) => {
  const beforeRoot = await temporaryRoot(t, "devspace-restart-worker-before-pid-");
  const beforeFixture = await workerFixture(beforeRoot, "ACK_FLUSHED");
  let preDispatchRestartCalls = 0;
  await assert.rejects(runRestartWorker(beforeFixture.requestPath, {
    inspectPm2() {
      return {
        name: "devspace-test",
        status: "online",
        cwd: beforeRoot,
        script: beforeFixture.expectedScript,
      };
    },
    restartPm2() {
      preDispatchRestartCalls += 1;
    },
  }), /PID is missing or invalid before restart dispatch/u);
  assert.equal(preDispatchRestartCalls, 0);
  assert.equal(
    (JSON.parse(await readFile(beforeFixture.statusPath, "utf8")) as RestartTransactionStatus).state,
    "UNKNOWN",
  );

  const afterRoot = await temporaryRoot(t, "devspace-restart-worker-after-pid-");
  const afterFixture = await workerFixture(afterRoot, "ACK_FLUSHED");
  let restarted = false;
  await assert.rejects(runRestartWorker(afterFixture.requestPath, {
    inspectPm2() {
      return {
        name: "devspace-test",
        pid: restarted ? undefined : 111,
        status: "online",
        cwd: afterRoot,
        script: afterFixture.expectedScript,
      };
    },
    restartPm2() {
      restarted = true;
    },
    savePm2() {},
    healthStatus() {
      return Promise.resolve({ status: 200, body: afterFixture.healthBody });
    },
  }), /PID is missing or invalid after restart dispatch/u);

  const status = JSON.parse(await readFile(afterFixture.statusPath, "utf8")) as RestartTransactionStatus;
  assert.equal(status.state, "UNKNOWN");
  assert.equal(status.evidence?.automaticRetry, false);
});

function serviceFixture(
  root: string,
  overrides: Partial<ConstructorParameters<typeof UniversalSelfManagementService>[0]> = {},
): UniversalSelfManagementService {
  return new UniversalSelfManagementService({
    stateDir: join(root, "state"),
    pm2ProcessName: "devspace-test",
    pm2Executable: "/usr/bin/true",
    localHealthUrl: "http://127.0.0.1:17690/healthz",
    expectedCwd: root,
    timeoutMs: 10_000,
    runtimeIdentity: TEST_RUNTIME_IDENTITY,
    ...overrides,
  });
}

async function workerFixture(
  root: string,
  state: RestartTransactionStatus["state"],
): Promise<{
  requestPath: string;
  statusPath: string;
  expectedScript: string;
  healthBody: Record<string, unknown>;
}> {
  const transactionId = "restart_11111111-1111-4111-8111-111111111111";
  const transactionDir = join(root, transactionId);
  await mkdir(transactionDir, { recursive: true });
  const requestPath = join(transactionDir, "request.json");
  const statusPath = join(transactionDir, "status.json");
  const expectedScript = join(root, "start.sh");
  await writeFile(expectedScript, "#!/bin/sh\n", { mode: 0o700 });
  const requestedAt = "2026-08-20T00:00:00.000Z";
  const historyStates: RestartTransactionStatus["state"][] = state === "ACK_FLUSHED"
    ? ["PREPARED", "RESPONSE_BOUND", "ACK_FLUSHED"]
    : [state];
  const status: RestartTransactionStatus = {
    version: 2,
    transactionId,
    state,
    requestedAt,
    updatedAt: requestedAt,
    expectedDisconnect: true,
    ownerFingerprint: OWNER,
    expectedRuntimeIdentity: TEST_RUNTIME_IDENTITY,
    responseTransportId: state === "PREPARED" ? undefined : TRANSPORT,
    responseRequestId: state === "PREPARED" ? undefined : "rpc-worker",
    history: historyStates.map((entry) => ({ state: entry, at: requestedAt })),
  };
  const request: RestartWorkerRequest = {
    version: 2,
    transactionId,
    requestedAt,
    ownerFingerprint: OWNER,
    timeoutMs: 2_000,
    pm2ProcessName: "devspace-test",
    pm2Executable: "/usr/bin/true",
    expectedCwd: root,
    expectedScript,
    localHealthUrl: "http://local.test/healthz",
    publicHealthUrl: "http://public.test/healthz",
    expectedRuntimeIdentity: TEST_RUNTIME_IDENTITY,
    statusPath,
    requestPath,
    workerLogPath: join(transactionDir, "worker.log"),
  };
  await Promise.all([
    writeFile(requestPath, `${JSON.stringify(request, null, 2)}\n`, { mode: 0o600 }),
    atomicRestartStatusWrite(statusPath, status),
  ]);
  return {
    requestPath,
    statusPath,
    expectedScript,
    healthBody: { identity: TEST_RUNTIME_IDENTITY },
  };
}

async function temporaryRoot(t: test.TestContext, prefix: string): Promise<string> {
  const root = await mkdtemp(join(tmpdir(), prefix));
  t.after(() => rm(root, { recursive: true, force: true }));
  return root;
}

function brokerCode(error: unknown): string | undefined {
  return error instanceof UniversalBrokerError ? error.code : undefined;
}
