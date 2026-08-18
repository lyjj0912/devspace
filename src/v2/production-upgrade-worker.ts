import { spawnSync } from "node:child_process";
import {
  chmod,
  copyFile,
  lstat,
  mkdir,
  readFile,
  readlink,
  rename,
  rm,
  symlink,
  writeFile,
} from "node:fs/promises";
import { basename, dirname, isAbsolute, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { randomUUID } from "node:crypto";

export const PRODUCTION_UPGRADE_STATES = [
  "PREPARED",
  "WAITING_FOR_RESPONSE",
  "SWITCHING",
  "VERIFYING",
  "PASS",
  "ROLLING_BACK",
  "FAIL",
] as const;

export type ProductionUpgradeState = (typeof PRODUCTION_UPGRADE_STATES)[number];

export interface ProductionUpgradeRequest {
  version: 1;
  transactionId: string;
  requestedAt: string;
  delayMs: number;
  timeoutMs: number;
  pm2ProcessName: string;
  pm2Executable: string;
  previous: {
    pid: number;
    cwd: string;
    script: string;
    auditTarget?: string;
  };
  next: {
    commit: string;
    release: string;
    script: string;
  };
  productionEnvPath: string;
  productionEnvBackupPath: string;
  nextEnvPath: string;
  startScriptPath: string;
  startScriptBackupPath: string;
  auditDirectory: string;
  currentAuditLink: string;
  statusPath: string;
  workerLogPath: string;
  localHealthUrl: string;
  publicHealthUrl: string;
  publicMetricsUrl: string;
  publicMcpUrl: string;
  oauthMetadataUrl: string;
  expectedScopes: string[];
  launchdLabel?: string;
}

export interface ProductionUpgradeStatus extends Record<string, unknown> {
  version: 1;
  transactionId: string;
  state: ProductionUpgradeState;
  requestedAt: string;
  updatedAt: string;
  expectedDisconnect: true;
  previous: ProductionUpgradeRequest["previous"];
  next: ProductionUpgradeRequest["next"];
  workerPid?: number;
  pidAfter?: number;
  pm2Status?: string;
  cwd?: string;
  script?: string;
  localHealthStatus?: number;
  publicHealthStatus?: number;
  publicMetricsStatus?: number;
  unauthenticatedMcpStatus?: number;
  oauthScopes?: string[];
  rollback?: Record<string, unknown>;
  error?: string;
}

interface Pm2ProcessSnapshot {
  name?: string;
  pid?: number;
  pm2_env?: {
    status?: string;
    pm_cwd?: string;
    pm_exec_path?: string;
  };
}

const TRANSACTION_PATTERN = /^upgrade_[0-9a-f-]{36}$/u;

export async function runProductionUpgradeWorker(requestPath: string): Promise<void> {
  const request = await readRequest(requestPath);
  let status: ProductionUpgradeStatus = {
    version: 1,
    transactionId: request.transactionId,
    state: "WAITING_FOR_RESPONSE",
    requestedAt: request.requestedAt,
    updatedAt: new Date().toISOString(),
    expectedDisconnect: true,
    previous: request.previous,
    next: request.next,
    workerPid: process.pid,
  };
  await writeStatus(request.statusPath, status);
  try {
    await sleep(request.delayMs);
    status = await transition(request, status, "SWITCHING");
    await installFile(request.nextEnvPath, request.productionEnvPath, 0o600);
    replacePm2Process(request, request.next.script, request.next.release);
    status = await transition(request, status, "VERIFYING");
    const evidence = await verifyNextRuntime(request);

    await installStartScript(request);
    await replaceSymlink(request.currentAuditLink, request.auditDirectory);
    status = {
      ...status,
      state: "PASS",
      updatedAt: new Date().toISOString(),
      ...evidence,
    };
    await writeStatus(request.statusPath, status);
  } catch (error) {
    const failure = error instanceof Error ? error.message : String(error);
    status = await transition(request, { ...status, error: failure }, "ROLLING_BACK");
    const rollback = await rollbackRuntime(request);
    status = {
      ...status,
      state: "FAIL",
      updatedAt: new Date().toISOString(),
      error: failure,
      rollback,
    };
    await writeStatus(request.statusPath, status);
    throw error;
  } finally {
    removeLaunchdJob(request.launchdLabel);
  }
}

async function verifyNextRuntime(
  request: ProductionUpgradeRequest,
): Promise<Pick<ProductionUpgradeStatus,
  | "pidAfter"
  | "pm2Status"
  | "cwd"
  | "script"
  | "localHealthStatus"
  | "publicHealthStatus"
  | "publicMetricsStatus"
  | "unauthenticatedMcpStatus"
  | "oauthScopes"
>> {
  const deadline = Date.now() + request.timeoutMs;
  let lastError = "Production upgrade verification did not run.";
  while (Date.now() < deadline) {
    try {
      const process = pm2Process(request);
      if (!process) throw new Error(`PM2 process is missing: ${request.pm2ProcessName}`);
      if (process.pm2_env?.status !== "online") {
        throw new Error(`PM2 status is ${process.pm2_env?.status ?? "unknown"}.`);
      }
      if (resolve(process.pm2_env?.pm_cwd ?? "/") !== resolve(request.next.release)) {
        throw new Error(`PM2 cwd mismatch: ${process.pm2_env?.pm_cwd ?? "missing"}`);
      }
      if (resolve(process.pm2_env?.pm_exec_path ?? "/") !== resolve(request.next.script)) {
        throw new Error(`PM2 script mismatch: ${process.pm2_env?.pm_exec_path ?? "missing"}`);
      }
      if (process.pid === request.previous.pid) {
        throw new Error(`PM2 PID did not change: ${process.pid}`);
      }
      const localHealthStatus = await httpStatus(request.localHealthUrl);
      const publicHealthStatus = await httpStatus(request.publicHealthUrl);
      const publicMetricsStatus = await httpStatus(request.publicMetricsUrl);
      const unauthenticatedMcpStatus = await httpStatus(request.publicMcpUrl, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          jsonrpc: "2.0",
          id: 1,
          method: "initialize",
          params: {
            protocolVersion: "2025-06-18",
            capabilities: {},
            clientInfo: { name: "production-upgrade-worker", version: "1" },
          },
        }),
      });
      const metadataResponse = await fetchWithTimeout(request.oauthMetadataUrl);
      const metadata = await metadataResponse.json() as { scopes_supported?: unknown };
      const oauthScopes = Array.isArray(metadata.scopes_supported)
        ? metadata.scopes_supported.filter((scope): scope is string => typeof scope === "string")
        : [];
      if (localHealthStatus !== 200) throw new Error(`Local health returned ${localHealthStatus}.`);
      if (publicHealthStatus !== 200) throw new Error(`Public health returned ${publicHealthStatus}.`);
      if (publicMetricsStatus !== 403) throw new Error(`Public metrics returned ${publicMetricsStatus}.`);
      if (unauthenticatedMcpStatus !== 401) {
        throw new Error(`Unauthenticated public MCP returned ${unauthenticatedMcpStatus}.`);
      }
      if (JSON.stringify(oauthScopes) !== JSON.stringify(request.expectedScopes)) {
        throw new Error(`OAuth scopes mismatch: ${JSON.stringify(oauthScopes)}`);
      }
      if (oauthScopes.includes("devspace")) {
        throw new Error("Legacy blanket OAuth scope remains advertised.");
      }
      return {
        pidAfter: process.pid,
        pm2Status: process.pm2_env?.status,
        cwd: process.pm2_env?.pm_cwd,
        script: process.pm2_env?.pm_exec_path,
        localHealthStatus,
        publicHealthStatus,
        publicMetricsStatus,
        unauthenticatedMcpStatus,
        oauthScopes,
      };
    } catch (error) {
      lastError = error instanceof Error ? error.message : String(error);
      await sleep(500);
    }
  }
  throw new Error(lastError);
}

function replacePm2Process(
  request: ProductionUpgradeRequest,
  script: string,
  cwd: string,
): void {
  runPm2(request, ["delete", request.pm2ProcessName], 30_000, true);
  runPm2(request, [
    "start",
    script,
    "--name",
    request.pm2ProcessName,
    "--interpreter",
    "/bin/bash",
    "--cwd",
    cwd,
    "--time",
  ], 60_000, false, productionPm2Environment(
    process.env,
    request.productionEnvPath,
  ));
  runPm2(request, ["save"], 30_000);
}

export function productionPm2Environment(
  inherited: NodeJS.ProcessEnv,
  productionEnvPath: string,
): NodeJS.ProcessEnv {
  const sanitized: NodeJS.ProcessEnv = {};
  for (const [key, value] of Object.entries(inherited)) {
    if (!key.startsWith("DEVSPACE_")) sanitized[key] = value;
  }
  sanitized.DEVSPACE_PRODUCTION_ENV_FILE = productionEnvPath;
  return sanitized;
}

async function rollbackRuntime(request: ProductionUpgradeRequest): Promise<Record<string, unknown>> {
  let restored = false;
  let healthStatus: number | undefined;
  let error: string | undefined;
  try {
    await installFile(request.productionEnvBackupPath, request.productionEnvPath, 0o600);
    replacePm2Process(request, request.previous.script, request.previous.cwd);
    await installFile(request.startScriptBackupPath, request.startScriptPath, 0o700);
    if (request.previous.auditTarget) {
      await replaceSymlink(request.currentAuditLink, request.previous.auditTarget);
    }
    const deadline = Date.now() + Math.min(request.timeoutMs, 60_000);
    while (Date.now() < deadline) {
      const process = pm2Process(request);
      if (
        process?.pm2_env?.status === "online"
        && resolve(process.pm2_env?.pm_cwd ?? "/") === resolve(request.previous.cwd)
        && resolve(process.pm2_env?.pm_exec_path ?? "/") === resolve(request.previous.script)
      ) {
        healthStatus = await httpStatus(request.localHealthUrl);
        if (healthStatus === 200) {
          restored = true;
          break;
        }
      }
      await sleep(500);
    }
    if (!restored) throw new Error("Previous production runtime did not recover before rollback timeout.");
  } catch (rollbackError) {
    error = rollbackError instanceof Error ? rollbackError.message : String(rollbackError);
  }
  return {
    attempted: true,
    restored,
    healthStatus,
    ...(error ? { error } : {}),
  };
}

async function installStartScript(request: ProductionUpgradeRequest): Promise<void> {
  const content = [
    "#!/bin/bash",
    "set -euo pipefail",
    `export DEVSPACE_PRODUCTION_ENV_FILE=${shellQuote(request.productionEnvPath)}`,
    `exec ${shellQuote(request.next.script)}`,
    "",
  ].join("\n");
  const temporary = temporaryPath(request.startScriptPath);
  await writeFile(temporary, content, { mode: 0o700 });
  await rename(temporary, request.startScriptPath);
  await chmod(request.startScriptPath, 0o700);
}

function pm2Process(request: ProductionUpgradeRequest): Pm2ProcessSnapshot | undefined {
  const result = runPm2(request, ["jlist"], 30_000);
  const start = result.stdout.indexOf("[");
  if (start < 0) throw new Error(`PM2 jlist did not return JSON: ${bounded(result.stdout)}`);
  const processes = JSON.parse(result.stdout.slice(start)) as Pm2ProcessSnapshot[];
  return processes.find((candidate) => candidate.name === request.pm2ProcessName);
}

function runPm2(
  request: ProductionUpgradeRequest,
  args: string[],
  timeout: number,
  allowFailure = false,
  env: NodeJS.ProcessEnv = process.env,
): { stdout: string; stderr: string; status: number | null } {
  const result = spawnSync(request.pm2Executable, args, {
    encoding: "utf8",
    timeout,
    env,
    cwd: request.auditDirectory,
  });
  if (result.error) throw result.error;
  if (!allowFailure && result.status !== 0) {
    throw new Error(`pm2 ${args.join(" ")} failed: ${bounded(result.stderr || result.stdout)}`);
  }
  return { stdout: result.stdout ?? "", stderr: result.stderr ?? "", status: result.status };
}

async function readRequest(path: string): Promise<ProductionUpgradeRequest> {
  const request = JSON.parse(await readFile(resolve(path), "utf8")) as ProductionUpgradeRequest;
  if (
    request?.version !== 1
    || !TRANSACTION_PATTERN.test(request.transactionId)
    || !request.pm2ProcessName
    || !request.pm2Executable
    || !request.previous?.cwd
    || !request.previous?.script
    || !request.next?.release
    || !request.next?.script
  ) {
    throw new Error(`Malformed production upgrade request: ${path}`);
  }
  for (const absolutePath of [
    request.pm2Executable,
    request.previous.cwd,
    request.previous.script,
    request.next.release,
    request.next.script,
    request.productionEnvPath,
    request.productionEnvBackupPath,
    request.nextEnvPath,
    request.startScriptPath,
    request.startScriptBackupPath,
    request.auditDirectory,
    request.currentAuditLink,
    request.statusPath,
  ]) {
    if (!isAbsolute(absolutePath)) throw new Error(`Upgrade request path is not absolute: ${absolutePath}`);
  }
  return request;
}

async function transition(
  request: ProductionUpgradeRequest,
  status: ProductionUpgradeStatus,
  state: ProductionUpgradeState,
): Promise<ProductionUpgradeStatus> {
  const next = { ...status, state, updatedAt: new Date().toISOString() };
  await writeStatus(request.statusPath, next);
  return next;
}

async function writeStatus(path: string, value: ProductionUpgradeStatus): Promise<void> {
  await mkdir(dirname(path), { recursive: true, mode: 0o700 });
  const temporary = temporaryPath(path);
  await writeFile(temporary, `${JSON.stringify(value, null, 2)}\n`, { mode: 0o600 });
  await rename(temporary, path);
}

async function installFile(source: string, destination: string, mode: number): Promise<void> {
  const temporary = temporaryPath(destination);
  await copyFile(source, temporary);
  await chmod(temporary, mode);
  await rename(temporary, destination);
}

async function replaceSymlink(path: string, target: string): Promise<void> {
  await mkdir(dirname(path), { recursive: true, mode: 0o700 });
  const temporary = temporaryPath(path);
  await rm(temporary, { force: true, recursive: true });
  await symlink(target, temporary);
  await rename(temporary, path);
}

async function httpStatus(url: string, init?: RequestInit): Promise<number> {
  const response = await fetchWithTimeout(url, init);
  await response.body?.cancel();
  return response.status;
}

async function fetchWithTimeout(url: string, init?: RequestInit): Promise<Response> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 10_000);
  timer.unref?.();
  try {
    return await fetch(url, { ...init, redirect: "error", cache: "no-store", signal: controller.signal });
  } finally {
    clearTimeout(timer);
  }
}

function removeLaunchdJob(label: string | undefined): void {
  if (!label || process.platform !== "darwin") return;
  spawnSync("/bin/launchctl", ["remove", label], { encoding: "utf8", timeout: 5_000 });
}

function temporaryPath(path: string): string {
  return join(dirname(path), `.${basename(path)}.${process.pid}.${randomUUID()}.tmp`);
}

function shellQuote(value: string): string {
  return `'${value.replaceAll("'", `'"'"'`)}'`;
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
    console.error("Production upgrade worker requires a request path.");
    process.exitCode = 2;
  } else {
    void runProductionUpgradeWorker(requestPath).catch((error) => {
      console.error(error instanceof Error ? error.stack ?? error.message : String(error));
      process.exitCode = 1;
    });
  }
}
