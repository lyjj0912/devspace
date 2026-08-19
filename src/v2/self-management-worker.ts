import { spawnSync } from "node:child_process";
import { readFile } from "node:fs/promises";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";
import {
  atomicRestartStatusWrite,
  type RestartTransactionStatus,
  type RestartWorkerRequest,
} from "./self-management.js";

interface Pm2ProcessSnapshot {
  name?: string;
  pid?: number;
  pm2_env?: {
    status?: string;
    pm_cwd?: string;
    pm_exec_path?: string;
  };
}

export async function runRestartWorker(requestPath: string): Promise<void> {
  const request = await readRequest(requestPath);
  let status: RestartTransactionStatus = {
    version: 1,
    transactionId: request.transactionId,
    state: "WAITING_FOR_RESPONSE",
    requestedAt: request.requestedAt,
    updatedAt: new Date().toISOString(),
    expectedDisconnect: true,
    ...(request.reason ? { reason: request.reason } : {}),
    workerPid: process.pid,
    handoffAcknowledgedAt: new Date().toISOString(),
  };
  await atomicRestartStatusWrite(request.statusPath, status);
  try {
    const before = pm2Process(request);
    status = {
      ...status,
      pidBefore: before?.pid,
      pm2Status: before?.pm2_env?.status,
      cwd: before?.pm2_env?.pm_cwd,
      script: before?.pm2_env?.pm_exec_path,
    };
    await sleep(request.delayMs);
    status = await transition(request, status, "RESTARTING");
    runPm2(request, ["restart", request.pm2ProcessName, "--update-env"], 60_000);
    runPm2(request, ["save"], 30_000);
    status = await transition(request, status, "VERIFYING");

    const deadline = Date.now() + request.timeoutMs;
    let lastError = "Restart verification did not run.";
    while (Date.now() < deadline) {
      try {
        const after = pm2Process(request);
        if (!after) throw new Error(`PM2 process is missing: ${request.pm2ProcessName}`);
        if (after.pm2_env?.status !== "online") {
          throw new Error(`PM2 status is ${after.pm2_env?.status ?? "unknown"}.`);
        }
        if (resolve(after.pm2_env?.pm_cwd ?? "/") !== resolve(request.expectedCwd)) {
          throw new Error(`PM2 cwd mismatch: ${after.pm2_env?.pm_cwd ?? "missing"}`);
        }
        if (
          request.expectedScript
          && resolve(after.pm2_env?.pm_exec_path ?? "/") !== resolve(request.expectedScript)
        ) {
          throw new Error(`PM2 script mismatch: ${after.pm2_env?.pm_exec_path ?? "missing"}`);
        }
        if (before?.pid && after.pid === before.pid) {
          throw new Error(`PM2 PID did not change: ${after.pid}`);
        }
        const localHealth = await healthStatus(request.localHealthUrl);
        const localHealthStatus = localHealth.status;
        if (localHealthStatus !== 200) throw new Error(`Local health returned ${localHealthStatus}.`);
        if (request.expectedIdentity) assertRuntimeIdentity(localHealth.body, request.expectedIdentity);
        const publicHealthStatus = request.publicHealthUrl
          ? (await healthStatus(request.publicHealthUrl)).status
          : undefined;
        if (request.publicHealthUrl && publicHealthStatus !== 200) {
          throw new Error(`Public health returned ${publicHealthStatus}.`);
        }
        status = {
          ...status,
          state: "PASS",
          updatedAt: new Date().toISOString(),
          pidAfter: after.pid,
          pm2Status: after.pm2_env?.status,
          cwd: after.pm2_env?.pm_cwd,
          script: after.pm2_env?.pm_exec_path,
          localHealthStatus,
          ...(publicHealthStatus !== undefined ? { publicHealthStatus } : {}),
          evidence: {
            responseGraceMs: request.delayMs,
            pm2Restarted: true,
            pm2Saved: true,
            expectedCwd: request.expectedCwd,
            expectedScript: request.expectedScript,
            expectedIdentity: request.expectedIdentity,
          },
        };
        await atomicRestartStatusWrite(request.statusPath, status);
        return;
      } catch (error) {
        lastError = error instanceof Error ? error.message : String(error);
        await sleep(500);
      }
    }
    throw new Error(lastError);
  } catch (error) {
    status = {
      ...status,
      state: "FAIL",
      updatedAt: new Date().toISOString(),
      error: error instanceof Error ? error.message : String(error),
    };
    await atomicRestartStatusWrite(request.statusPath, status);
    throw error;
  } finally {
    removeLaunchdJob(request.launchdLabel);
  }
}

async function transition(
  request: RestartWorkerRequest,
  status: RestartTransactionStatus,
  state: RestartTransactionStatus["state"],
): Promise<RestartTransactionStatus> {
  const next = { ...status, state, updatedAt: new Date().toISOString() };
  await atomicRestartStatusWrite(request.statusPath, next);
  return next;
}

function pm2Process(request: RestartWorkerRequest): Pm2ProcessSnapshot | undefined {
  const result = runPm2(request, ["jlist"], 30_000);
  const output = result.stdout.trim();
  const start = output.indexOf("[");
  if (start < 0) throw new Error(`PM2 jlist did not return JSON: ${bounded(output)}`);
  const processes = JSON.parse(output.slice(start)) as Pm2ProcessSnapshot[];
  return processes.find((candidate) => candidate.name === request.pm2ProcessName);
}

function runPm2(
  request: RestartWorkerRequest,
  args: string[],
  timeout: number,
): { stdout: string; stderr: string } {
  const result = spawnSync(request.pm2Executable, args, {
    encoding: "utf8",
    timeout,
    env: process.env,
    cwd: request.expectedCwd,
  });
  if (result.error) throw result.error;
  if (result.status !== 0) {
    throw new Error(`pm2 ${args.join(" ")} failed: ${bounded(result.stderr || result.stdout)}`);
  }
  return { stdout: result.stdout ?? "", stderr: result.stderr ?? "" };
}

async function healthStatus(url: string): Promise<{ status: number; body?: unknown }> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 5_000);
  timer.unref?.();
  try {
    const response = await fetch(url, {
      method: "GET",
      redirect: "error",
      cache: "no-store",
      signal: controller.signal,
    });
    const contentType = response.headers.get("content-type") ?? "";
    const body = contentType.includes("application/json")
      ? await response.json().catch(() => undefined)
      : undefined;
    if (body === undefined) await response.body?.cancel();
    return { status: response.status, body };
  } finally {
    clearTimeout(timer);
  }
}

function assertRuntimeIdentity(
  value: unknown,
  expected: NonNullable<RestartWorkerRequest["expectedIdentity"]>,
): void {
  const record = value && typeof value === "object" ? value as Record<string, unknown> : {};
  const identity = record.identity && typeof record.identity === "object"
    ? record.identity as Record<string, unknown>
    : record;
  for (const key of [
    "productVersion",
    "schemaGeneration",
    "authorityContractGeneration",
    "configDigest",
    "sourceRevision",
    "runtimeRevision",
    "buildDigest",
  ] as const) {
    if (identity[key] !== expected[key]) {
      throw new Error(`Restart runtime identity mismatch for ${key}.`);
    }
  }
}

async function readRequest(path: string): Promise<RestartWorkerRequest> {
  const value = JSON.parse(await readFile(resolve(path), "utf8")) as RestartWorkerRequest;
  if (
    value?.version !== 1
    || typeof value.transactionId !== "string"
    || typeof value.statusPath !== "string"
    || typeof value.pm2Executable !== "string"
    || typeof value.pm2ProcessName !== "string"
  ) {
    throw new Error(`Malformed restart worker request: ${path}`);
  }
  return value;
}

function removeLaunchdJob(label: string | undefined): void {
  if (!label || process.platform !== "darwin") return;
  spawnSync("/bin/launchctl", ["remove", label], {
    encoding: "utf8",
    timeout: 5_000,
  });
}

function sleep(milliseconds: number): Promise<void> {
  return new Promise((resolvePromise) => setTimeout(resolvePromise, milliseconds));
}

function bounded(value: string, maximum = 2_000): string {
  return value.length <= maximum ? value : `${value.slice(0, maximum)}…`;
}

const invokedPath = process.argv[1] ? resolve(process.argv[1]) : undefined;
if (invokedPath && invokedPath === fileURLToPath(import.meta.url)) {
  const requestPath = process.argv[2];
  if (!requestPath) {
    console.error("Restart worker requires a request path.");
    process.exitCode = 2;
  } else {
    void runRestartWorker(requestPath).catch((error) => {
      console.error(error instanceof Error ? error.stack ?? error.message : String(error));
      process.exitCode = 1;
    });
  }
}
