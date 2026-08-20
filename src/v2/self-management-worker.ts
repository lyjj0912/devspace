import { spawnSync } from "node:child_process";
import { readFile } from "node:fs/promises";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";
import {
  assertRestartWorkerRequest,
  atomicRestartStatusWrite,
  readRestartStatus,
  type RestartTransactionState,
  type RestartTransactionStatus,
  type RestartWorkerRequest,
} from "./self-management.js";

export interface RestartPm2Snapshot {
  name?: string;
  pid?: number;
  status?: string;
  cwd?: string;
  script?: string;
}

interface HealthObservation {
  status: number;
  body?: unknown;
}

type MaybePromise<T> = T | Promise<T>;

export interface RestartWorkerRuntime {
  now?: () => number;
  sleep?: (milliseconds: number) => Promise<void>;
  inspectPm2?: (request: RestartWorkerRequest) => MaybePromise<RestartPm2Snapshot | undefined>;
  restartPm2?: (request: RestartWorkerRequest) => MaybePromise<void>;
  savePm2?: (request: RestartWorkerRequest) => MaybePromise<void>;
  healthStatus?: (url: string) => Promise<HealthObservation>;
  removeLaunchdJob?: (label: string | undefined) => void;
}

class ConclusiveVerificationMismatch extends Error {}

export async function runRestartWorker(
  requestPath: string,
  runtime: RestartWorkerRuntime = {},
): Promise<void> {
  const request = await readRequest(requestPath);
  let status = await readRestartStatus(request.statusPath);
  assertRequestMatchesStatus(request, status);
  if (status.state !== "ACK_FLUSHED") {
    throw new Error(
      `Restart supervisor requires durable ACK_FLUSHED; observed ${status.state}.`,
    );
  }

  const now = runtime.now ?? Date.now;
  const sleepFor = runtime.sleep ?? sleep;
  const inspectPm2 = runtime.inspectPm2 ?? defaultInspectPm2;
  const restartPm2 = runtime.restartPm2 ?? defaultRestartPm2;
  const savePm2 = runtime.savePm2 ?? defaultSavePm2;
  const observeHealth = runtime.healthStatus ?? healthStatus;
  let restartAttempted = false;
  try {
    const acceptedAt = timestamp(now);
    status = await transition(request, status, "HANDOFF_ACCEPTED", acceptedAt, {
      workerPid: process.pid,
      handoffAcceptedAt: acceptedAt,
    });

    const before = await inspectPm2(request);
    if (!positivePid(before?.pid)) {
      throw new Error("PM2 PID is missing or invalid before restart dispatch.");
    }
    status = {
      ...status,
      updatedAt: timestamp(now),
      pidBefore: before?.pid,
      pm2Status: before?.status,
      cwd: before?.cwd,
      script: before?.script,
    };
    await atomicRestartStatusWrite(request.statusPath, status);

    const restartingAt = timestamp(now);
    status = await transition(request, status, "RESTARTING", restartingAt, {
      restartStartedAt: restartingAt,
    });
    restartAttempted = true;
    await restartPm2(request);
    await savePm2(request);

    const verifyingAt = timestamp(now);
    status = await transition(request, status, "VERIFYING", verifyingAt, { verifyingAt });
    const deadline = now() + request.timeoutMs;
    let lastError: unknown = new Error("Restart verification did not run.");
    while (now() <= deadline) {
      try {
        const evidence = await verifyReplacementRuntime(
          request,
          before,
          inspectPm2,
          observeHealth,
        );
        const completedAt = timestamp(now);
        status = await transition(request, status, "PASS", completedAt, {
          completedAt,
          ...evidence,
          evidence: {
            ...(status.evidence ?? {}),
            pm2Restarted: true,
            pm2Saved: true,
            expectedCwd: request.expectedCwd,
            expectedScript: request.expectedScript,
            expectedRuntimeIdentity: request.expectedRuntimeIdentity,
          },
        });
        return;
      } catch (error) {
        lastError = error;
        if (error instanceof ConclusiveVerificationMismatch) throw error;
        const remaining = deadline - now();
        if (remaining <= 0) break;
        await sleepFor(Math.min(500, remaining));
      }
    }
    throw lastError;
  } catch (error) {
    const completedAt = timestamp(now);
    // Once the process-manager dispatch boundary has been crossed, even a conclusive-looking
    // verification mismatch is operationally ambiguous until independent readback/rollback.
    const terminal = transitionValue(status, "UNKNOWN", completedAt, {
      completedAt,
      error: errorMessage(error),
      evidence: {
        ...(status.evidence ?? {}),
        restartAttempted,
        automaticRetry: false,
      },
    });
    await atomicRestartStatusWrite(request.statusPath, terminal);
    throw error;
  } finally {
    (runtime.removeLaunchdJob ?? removeLaunchdJob)(request.launchdLabel);
  }
}

async function verifyReplacementRuntime(
  request: RestartWorkerRequest,
  before: RestartPm2Snapshot | undefined,
  inspectPm2: NonNullable<RestartWorkerRuntime["inspectPm2"]>,
  observeHealth: NonNullable<RestartWorkerRuntime["healthStatus"]>,
): Promise<Partial<RestartTransactionStatus>> {
  const after = await inspectPm2(request);
  if (!after) throw new Error(`PM2 process is missing: ${request.pm2ProcessName}`);
  if (!positivePid(after.pid)) throw new ConclusiveVerificationMismatch("PM2 PID is missing or invalid after restart dispatch.");
  if (after.status !== "online") {
    throw new Error(`PM2 status is ${after.status ?? "unknown"}.`);
  }
  if (resolve(after.cwd ?? "/") !== resolve(request.expectedCwd)) {
    throw new ConclusiveVerificationMismatch(`PM2 cwd mismatch: ${after.cwd ?? "missing"}`);
  }
  if (request.expectedScript && resolve(after.script ?? "/") !== resolve(request.expectedScript)) {
    throw new ConclusiveVerificationMismatch(`PM2 script mismatch: ${after.script ?? "missing"}`);
  }
  if (before?.pid && after.pid === before.pid) {
    throw new Error(`PM2 PID did not change: ${after.pid}`);
  }

  const localHealth = await observeHealth(request.localHealthUrl);
  if (localHealth.status !== 200) {
    throw new Error(`Local health returned ${localHealth.status}.`);
  }
  assertRuntimeIdentity(localHealth.body, request.expectedRuntimeIdentity);
  const publicHealth = request.publicHealthUrl
    ? await observeHealth(request.publicHealthUrl)
    : undefined;
  if (publicHealth && publicHealth.status !== 200) {
    throw new Error(`Public health returned ${publicHealth.status}.`);
  }
  return {
    pidAfter: after.pid,
    pm2Status: after.status,
    cwd: after.cwd,
    script: after.script,
    localHealthStatus: localHealth.status,
    ...(publicHealth ? { publicHealthStatus: publicHealth.status } : {}),
  };
}

async function transition(
  request: RestartWorkerRequest,
  status: RestartTransactionStatus,
  state: RestartTransactionState,
  at: string,
  fields: Partial<RestartTransactionStatus> = {},
): Promise<RestartTransactionStatus> {
  const next = transitionValue(status, state, at, fields);
  await atomicRestartStatusWrite(request.statusPath, next);
  return next;
}

function transitionValue(
  status: RestartTransactionStatus,
  state: RestartTransactionState,
  at: string,
  fields: Partial<RestartTransactionStatus>,
): RestartTransactionStatus {
  return {
    ...status,
    ...fields,
    state,
    updatedAt: at,
    history: [...status.history, { state, at }],
  };
}

function defaultInspectPm2(request: RestartWorkerRequest): RestartPm2Snapshot | undefined {
  const result = runPm2(request, ["jlist"], 30_000);
  const output = result.stdout.trim();
  const start = output.indexOf("[");
  if (start < 0) throw new Error(`PM2 jlist did not return JSON: ${bounded(output)}`);
  const processes = JSON.parse(output.slice(start)) as Array<{
    name?: string;
    pid?: number;
    pm2_env?: { status?: string; pm_cwd?: string; pm_exec_path?: string };
  }>;
  const process = processes.find((candidate) => candidate.name === request.pm2ProcessName);
  return process
    ? {
        name: process.name,
        pid: process.pid,
        status: process.pm2_env?.status,
        cwd: process.pm2_env?.pm_cwd,
        script: process.pm2_env?.pm_exec_path,
      }
    : undefined;
}

function defaultRestartPm2(request: RestartWorkerRequest): void {
  runPm2(request, ["restart", request.pm2ProcessName, "--update-env"], 60_000);
}

function defaultSavePm2(request: RestartWorkerRequest): void {
  runPm2(request, ["save"], 30_000);
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

async function healthStatus(url: string): Promise<HealthObservation> {
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
  expected: RestartWorkerRequest["expectedRuntimeIdentity"],
): void {
  const record = value && typeof value === "object" ? value as Record<string, unknown> : {};
  const identity = record.identity && typeof record.identity === "object"
    ? record.identity as Record<string, unknown>
    : record;
  for (const key of [
    "productVersion",
    "productProfile",
    "buildCapabilityDigest",
    "resourceUriVersion",
    "schemaGeneration",
    "authorityContractGeneration",
    "configDigest",
    "sourceRevision",
    "runtimeRevision",
    "buildDigest",
  ] as const) {
    if (identity[key] !== expected[key]) {
      throw new ConclusiveVerificationMismatch(`Restart runtime identity mismatch for ${key}.`);
    }
  }
}

async function readRequest(path: string): Promise<RestartWorkerRequest> {
  const value = JSON.parse(await readFile(resolve(path), "utf8")) as RestartWorkerRequest;
  assertRestartWorkerRequest(value);
  return value;
}

function assertRequestMatchesStatus(
  request: RestartWorkerRequest,
  status: RestartTransactionStatus,
): void {
  if (
    status.transactionId !== request.transactionId
    || status.ownerFingerprint !== request.ownerFingerprint
    || status.authorityId !== request.authorityId
    || !sameRuntimeIdentity(status.expectedRuntimeIdentity, request.expectedRuntimeIdentity)
  ) {
    throw new Error(
      "Restart worker request does not match the durable transaction owner, authority, or runtime identity.",
    );
  }
}

function sameRuntimeIdentity(
  left: RestartWorkerRequest["expectedRuntimeIdentity"],
  right: RestartWorkerRequest["expectedRuntimeIdentity"],
): boolean {
  return [
    "productVersion",
    "productProfile",
    "buildCapabilityDigest",
    "resourceUriVersion",
    "schemaGeneration",
    "authorityContractGeneration",
    "configDigest",
    "sourceRevision",
    "runtimeRevision",
    "buildDigest",
    "startedAt",
  ].every((key) => left[key as keyof typeof left] === right[key as keyof typeof right]);
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

function positivePid(value: unknown): value is number {
  return Number.isInteger(value) && Number(value) > 0;
}

function timestamp(now: () => number): string {
  return new Date(now()).toISOString();
}

function bounded(value: string, maximum = 2_000): string {
  return value.length <= maximum ? value : `${value.slice(0, maximum)}…`;
}

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
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
