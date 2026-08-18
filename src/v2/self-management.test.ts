import assert from "node:assert/strict";
import { createServer } from "node:http";
import {
  chmod,
  mkdtemp,
  mkdir,
  readFile,
  rm,
  writeFile,
} from "node:fs/promises";
import type { AddressInfo } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { UniversalBrokerError } from "./errors.js";
import {
  UniversalSelfManagementService,
  type RestartWorkerRequest,
} from "./self-management.js";
import { runRestartWorker } from "./self-management-worker.js";

test("restart requests are durable, exclusive, and stale transactions fail closed", async (t) => {
  const root = await mkdtemp(join(tmpdir(), "devspace-self-management-test-"));
  t.after(() => rm(root, { recursive: true, force: true }));
  let now = Date.now();
  const launches: RestartWorkerRequest[] = [];
  const service = new UniversalSelfManagementService({
    stateDir: join(root, "state"),
    pm2ProcessName: "devspace-test",
    pm2Executable: "/usr/bin/true",
    localHealthUrl: "http://127.0.0.1:17690/healthz",
    expectedCwd: root,
    defaultDelayMs: 750,
    timeoutMs: 10_000,
    now: () => now,
    launchWorker(request) {
      launches.push(request);
    },
  });

  const requested = await service.requestRestart({ reason: "test restart", delayMs: 750 });
  assert.equal(requested.state, "REQUESTED");
  assert.equal(requested.expectedDisconnect, true);
  assert.equal(launches.at(-1)?.transactionId, requested.transactionId);
  assert.equal((await service.status(requested.transactionId)).state, "REQUESTED");
  await assert.rejects(
    service.requestRestart({ reason: "duplicate" }),
    (error: unknown) => brokerCode(error) === "PRECONDITION_FAILED",
  );

  now += 10_000 + 15_000 + 30_000 + 1;
  const stale = await service.status(requested.transactionId);
  assert.equal(stale.state, "FAIL");
  assert.match(stale.error ?? "", /durable verification deadline/u);
  assert.equal((stale.evidence as { staleRecovered?: boolean }).staleRecovered, true);

  const replacement = await service.requestRestart({ reason: "replacement" });
  assert.equal(replacement.state, "REQUESTED");
  assert.equal(launches.at(-1)?.transactionId, replacement.transactionId);
});

test("restart worker changes PM2 PID and persists independently verifiable PASS evidence", async (t) => {
  const root = await mkdtemp(join(tmpdir(), "devspace-restart-worker-test-"));
  t.after(() => rm(root, { recursive: true, force: true }));
  const transactionId = "restart_11111111-1111-4111-8111-111111111111";
  const transactionDir = join(root, transactionId);
  await mkdir(transactionDir, { recursive: true });
  const pidState = join(root, "pid.txt");
  const expectedScript = join(root, "start.sh");
  const fakePm2 = join(root, "pm2-fixture.sh");
  await writeFile(pidState, "111\n");
  await writeFile(expectedScript, "#!/bin/sh\n", { mode: 0o700 });
  await writeFile(fakePm2, [
    "#!/bin/sh",
    `pid_state=${shellQuote(pidState)}`,
    `expected_cwd=${shellQuote(root)}`,
    `expected_script=${shellQuote(expectedScript)}`,
    "case \"$1\" in",
    "  jlist)",
    "    pid=$(cat \"$pid_state\")",
    "    printf '[{\"name\":\"devspace-test\",\"pid\":%s,\"pm2_env\":{\"status\":\"online\",\"pm_cwd\":\"%s\",\"pm_exec_path\":\"%s\"}}]\\n' \"$pid\" \"$expected_cwd\" \"$expected_script\"",
    "    ;;",
    "  restart)",
    "    printf '222\\n' > \"$pid_state\"",
    "    ;;",
    "  save)",
    "    :",
    "    ;;",
    "  *) exit 64 ;;",
    "esac",
    "",
  ].join("\n"));
  await chmod(fakePm2, 0o700);

  const local = createServer((_req, res) => {
    res.statusCode = 200;
    res.end("ok");
  });
  const publicServer = createServer((_req, res) => {
    res.statusCode = 200;
    res.end("ok");
  });
  await Promise.all([listen(local), listen(publicServer)]);
  t.after(() => Promise.all([close(local), close(publicServer)]));
  const localAddress = local.address() as AddressInfo;
  const publicAddress = publicServer.address() as AddressInfo;

  const requestPath = join(transactionDir, "request.json");
  const statusPath = join(transactionDir, "status.json");
  const request: RestartWorkerRequest = {
    version: 1,
    transactionId,
    requestedAt: new Date().toISOString(),
    delayMs: 1,
    timeoutMs: 2_000,
    pm2ProcessName: "devspace-test",
    pm2Executable: fakePm2,
    expectedCwd: root,
    expectedScript,
    localHealthUrl: `http://127.0.0.1:${localAddress.port}/healthz`,
    publicHealthUrl: `http://127.0.0.1:${publicAddress.port}/healthz`,
    statusPath,
    requestPath,
    workerLogPath: join(transactionDir, "worker.log"),
  };
  await writeFile(requestPath, `${JSON.stringify(request, null, 2)}\n`, { mode: 0o600 });
  await runRestartWorker(requestPath);

  const status = JSON.parse(await readFile(statusPath, "utf8")) as {
    state: string;
    pidBefore?: number;
    pidAfter?: number;
    localHealthStatus?: number;
    publicHealthStatus?: number;
    expectedDisconnect?: boolean;
  };
  assert.deepEqual(status, {
    ...status,
    state: "PASS",
    pidBefore: 111,
    pidAfter: 222,
    localHealthStatus: 200,
    publicHealthStatus: 200,
    expectedDisconnect: true,
  });
});

function brokerCode(error: unknown): string | undefined {
  return error instanceof UniversalBrokerError ? error.code : undefined;
}

function shellQuote(value: string): string {
  return `'${value.replaceAll("'", `'"'"'`)}'`;
}

async function listen(server: ReturnType<typeof createServer>): Promise<void> {
  await new Promise<void>((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", resolve);
  });
}

async function close(server: ReturnType<typeof createServer>): Promise<void> {
  if (!server.listening) return;
  await new Promise<void>((resolve) => server.close(() => resolve()));
}
