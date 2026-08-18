import { spawnSync } from "node:child_process";
import { chmod, readFile, rename, writeFile } from "node:fs/promises";
import { dirname, isAbsolute, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const TERMINAL_STATES = new Set(["PASS", "FAIL", "UNKNOWN"]);

export interface Pm2UpgradeCleanupOptions {
  statusPath: string;
  pm2Executable: string;
  workerName: string;
  auditDirectory: string;
  timeoutMs?: number;
  pollMs?: number;
  graceMs?: number;
  env?: NodeJS.ProcessEnv;
}

export interface Pm2UpgradeCleanupEvidence {
  version: 1;
  ok: boolean;
  transactionId?: string;
  terminalState?: string;
  workerName: string;
  workerPresentBefore?: boolean;
  deleteAttempted?: boolean;
  deleteStatus?: number | null;
  dumpSaved?: boolean;
  saveStatus?: number | null;
  workerPresentAfter?: boolean;
  dumpWorkerResidue?: boolean;
  completedAt: string;
  error?: string;
}

interface UpgradeStatus {
  transactionId?: unknown;
  state?: unknown;
}

interface Pm2Process {
  name?: string;
}

export async function runPm2UpgradeCleanupMonitor(
  options: Pm2UpgradeCleanupOptions,
): Promise<Pm2UpgradeCleanupEvidence> {
  validateOptions(options);
  const timeoutMs = options.timeoutMs ?? 10 * 60_000;
  const pollMs = options.pollMs ?? 250;
  const graceMs = options.graceMs ?? 1_500;
  const env = options.env ?? process.env;
  const evidencePath = join(options.auditDirectory, "scheduler-cleanup.json");
  let transactionId: string | undefined;
  let terminalState: string | undefined;
  try {
    const deadline = Date.now() + timeoutMs;
    while (Date.now() < deadline) {
      const status = JSON.parse(await readFile(options.statusPath, "utf8")) as UpgradeStatus;
      transactionId = typeof status.transactionId === "string" ? status.transactionId : transactionId;
      terminalState = typeof status.state === "string" ? status.state : undefined;
      if (terminalState && TERMINAL_STATES.has(terminalState)) break;
      await sleep(pollMs);
    }
    if (!terminalState || !TERMINAL_STATES.has(terminalState)) {
      throw new Error(`Upgrade transaction did not reach a terminal state within ${timeoutMs}ms.`);
    }
    await sleep(graceMs);

    const workerPresentBefore = pm2HasWorker(options, env);
    let deleteStatus: number | null = null;
    if (workerPresentBefore) {
      deleteStatus = runPm2(options, ["delete", options.workerName], env).status;
      if (deleteStatus !== 0) {
        throw new Error(`PM2 worker delete failed with status ${String(deleteStatus)}.`);
      }
    }
    const saveStatus = runPm2(options, ["save"], env).status;
    if (saveStatus !== 0) {
      throw new Error(`PM2 dump save failed with status ${String(saveStatus)}.`);
    }
    const workerPresentAfter = pm2HasWorker(options, env);
    const dumpWorkerResidue = await dumpHasWorker(options, env);
    if (workerPresentAfter || dumpWorkerResidue) {
      throw new Error("Temporary PM2 upgrade worker remains after cleanup.");
    }

    const evidence: Pm2UpgradeCleanupEvidence = {
      version: 1,
      ok: true,
      ...(transactionId ? { transactionId } : {}),
      terminalState,
      workerName: options.workerName,
      workerPresentBefore,
      deleteAttempted: workerPresentBefore,
      deleteStatus,
      dumpSaved: true,
      saveStatus,
      workerPresentAfter,
      dumpWorkerResidue,
      completedAt: new Date().toISOString(),
    };
    await writeEvidence(evidencePath, evidence);
    return evidence;
  } catch (error) {
    const evidence: Pm2UpgradeCleanupEvidence = {
      version: 1,
      ok: false,
      ...(transactionId ? { transactionId } : {}),
      ...(terminalState ? { terminalState } : {}),
      workerName: options.workerName,
      completedAt: new Date().toISOString(),
      error: sanitizeError(error),
    };
    await writeEvidence(evidencePath, evidence).catch(() => undefined);
    throw error;
  }
}

function validateOptions(options: Pm2UpgradeCleanupOptions): void {
  for (const [label, path] of [
    ["statusPath", options.statusPath],
    ["pm2Executable", options.pm2Executable],
    ["auditDirectory", options.auditDirectory],
  ] as const) {
    if (!isAbsolute(path)) throw new Error(`${label} must be absolute: ${path}`);
  }
  if (!/^[A-Za-z0-9_.-]{1,128}$/u.test(options.workerName)) {
    throw new Error(`Invalid PM2 worker name: ${options.workerName}`);
  }
  for (const [label, value, maximum] of [
    ["timeoutMs", options.timeoutMs ?? 10 * 60_000, 30 * 60_000],
    ["pollMs", options.pollMs ?? 250, 10_000],
    ["graceMs", options.graceMs ?? 1_500, 30_000],
  ] as const) {
    if (!Number.isInteger(value) || value < 0 || value > maximum) {
      throw new Error(`Invalid ${label}: ${value}`);
    }
  }
}

function pm2HasWorker(options: Pm2UpgradeCleanupOptions, env: NodeJS.ProcessEnv): boolean {
  const result = runPm2(options, ["jlist"], env);
  if (result.status !== 0) throw new Error(`PM2 jlist failed with status ${String(result.status)}.`);
  const start = result.stdout.indexOf("[");
  if (start < 0) throw new Error("PM2 jlist did not return JSON.");
  const processes = JSON.parse(result.stdout.slice(start)) as Pm2Process[];
  return processes.some((process) => process.name === options.workerName);
}

async function dumpHasWorker(
  options: Pm2UpgradeCleanupOptions,
  env: NodeJS.ProcessEnv,
): Promise<boolean> {
  const pm2Home = env.PM2_HOME ?? (env.HOME ? join(env.HOME, ".pm2") : undefined);
  if (!pm2Home || !isAbsolute(pm2Home)) {
    throw new Error("PM2_HOME or HOME is required to verify the PM2 dump.");
  }
  const processes = JSON.parse(await readFile(join(pm2Home, "dump.pm2"), "utf8")) as Pm2Process[];
  return processes.some((process) => process.name === options.workerName);
}

function runPm2(
  options: Pm2UpgradeCleanupOptions,
  args: string[],
  env: NodeJS.ProcessEnv,
): { status: number | null; stdout: string; stderr: string } {
  const result = spawnSync(options.pm2Executable, args, {
    cwd: options.auditDirectory,
    env,
    encoding: "utf8",
    timeout: 30_000,
  });
  if (result.error) throw result.error;
  return {
    status: result.status,
    stdout: result.stdout ?? "",
    stderr: result.stderr ?? "",
  };
}

async function writeEvidence(path: string, evidence: Pm2UpgradeCleanupEvidence): Promise<void> {
  const temporary = join(dirname(path), `.${resolve(path).split("/").at(-1)}.${process.pid}.tmp`);
  await writeFile(temporary, `${JSON.stringify(evidence, null, 2)}\n`, { mode: 0o600 });
  await chmod(temporary, 0o600);
  await rename(temporary, path);
  await chmod(path, 0o600);
}

function sanitizeError(error: unknown): string {
  return (error instanceof Error ? error.message : String(error))
    .replace(/\bBearer\s+\S+/giu, "Bearer <redacted>")
    .replace(/\b[A-Za-z0-9_-]{40,}\b/gu, "<redacted>")
    .replace(/\s+/gu, " ")
    .trim()
    .slice(0, 500);
}

function sleep(milliseconds: number): Promise<void> {
  return new Promise((resolvePromise) => setTimeout(resolvePromise, milliseconds));
}

const invokedPath = process.argv[1] ? resolve(process.argv[1]) : undefined;
if (invokedPath === fileURLToPath(import.meta.url)) {
  const [statusPath, pm2Executable, workerName, auditDirectory, timeoutText] = process.argv.slice(2);
  if (!statusPath || !pm2Executable || !workerName || !auditDirectory) {
    console.error("Usage: production-upgrade-cleanup-monitor <status> <pm2> <worker> <audit> [timeoutMs]");
    process.exitCode = 2;
  } else {
    runPm2UpgradeCleanupMonitor({
      statusPath,
      pm2Executable,
      workerName,
      auditDirectory,
      ...(timeoutText ? { timeoutMs: Number(timeoutText) } : {}),
    }).catch((error) => {
      console.error(error instanceof Error ? error.stack ?? error.message : String(error));
      process.exitCode = 1;
    });
  }
}
