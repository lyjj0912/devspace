import { randomUUID } from "node:crypto";
import {
  closeSync,
  existsSync,
  openSync,
} from "node:fs";
import {
  mkdir,
  open as openFile,
  readFile,
  readdir,
  rename,
  rm,
  stat,
} from "node:fs/promises";
import { homedir } from "node:os";
import { basename, dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { spawn, spawnSync, type SpawnOptions } from "node:child_process";
import { UniversalBrokerError } from "./errors.js";
import type { RuntimeIdentity } from "./contracts.js";

export const RESTART_TRANSACTION_STATES = [
  "REQUESTED",
  "WAITING_FOR_RESPONSE",
  "RESTARTING",
  "VERIFYING",
  "PASS",
  "FAIL",
] as const;

export type RestartTransactionState = (typeof RESTART_TRANSACTION_STATES)[number];

export interface RestartBrokerInput {
  reason?: string;
  delayMs?: number;
}

export interface RestartStatusInput {
  transactionId?: string;
}

export interface RestartWorkerRequest {
  version: 1;
  transactionId: string;
  requestedAt: string;
  reason?: string;
  delayMs: number;
  timeoutMs: number;
  pm2ProcessName: string;
  pm2Executable: string;
  expectedCwd: string;
  expectedScript?: string;
  localHealthUrl: string;
  publicHealthUrl?: string;
  expectedIdentity?: RuntimeIdentity;
  statusPath: string;
  requestPath: string;
  workerLogPath: string;
  launchdLabel?: string;
}

export interface RestartTransactionStatus extends Record<string, unknown> {
  version: 1;
  transactionId: string;
  state: RestartTransactionState;
  requestedAt: string;
  updatedAt: string;
  expectedDisconnect: boolean;
  reason?: string;
  workerPid?: number;
  pidBefore?: number;
  pidAfter?: number;
  pm2Status?: string;
  cwd?: string;
  script?: string;
  localHealthStatus?: number;
  publicHealthStatus?: number;
  error?: string;
  evidence?: Record<string, unknown>;
  handoffAcknowledgedAt?: string;
}

export interface UniversalSelfManagementOptions {
  stateDir: string;
  pm2ProcessName: string;
  localHealthUrl: string;
  publicHealthUrl?: string;
  expectedCwd?: string;
  expectedScript?: string;
  defaultDelayMs?: number;
  timeoutMs?: number;
  now?: () => number;
  workerPath?: string;
  pm2Executable?: string;
  launchWorker?: (request: RestartWorkerRequest) => void;
  platform?: NodeJS.Platform;
  runtimeIdentity?: RuntimeIdentity;
}

const TRANSACTION_ID_PATTERN = /^restart_[0-9a-f-]{36}$/u;
const DEFAULT_DELAY_MS = 2_000;
const MINIMUM_DELAY_MS = 750;
const MAXIMUM_DELAY_MS = 15_000;
const DEFAULT_TIMEOUT_MS = 120_000;
const MAXIMUM_REASON_CHARACTERS = 2_000;
const MAXIMUM_RETAINED_TRANSACTIONS = 64;
const RETENTION_MS = 7 * 24 * 60 * 60_000;
const STALE_TRANSACTION_MARGIN_MS = 30_000;

export class UniversalSelfManagementService {
  private readonly stateDir: string;
  private readonly transactionsDir: string;
  private readonly pm2ProcessName: string;
  private readonly localHealthUrl: string;
  private readonly publicHealthUrl?: string;
  private readonly expectedCwd: string;
  private readonly expectedScript?: string;
  private readonly defaultDelayMs: number;
  private readonly timeoutMs: number;
  private readonly now: () => number;
  private readonly workerPath: string;
  private readonly pm2Executable?: string;
  private readonly launchWorker: (request: RestartWorkerRequest) => void;
  private readonly runtimeIdentity?: RuntimeIdentity;

  constructor(options: UniversalSelfManagementOptions) {
    this.stateDir = resolve(options.stateDir);
    this.transactionsDir = join(this.stateDir, "restart-transactions");
    this.pm2ProcessName = requiredText(options.pm2ProcessName, "pm2ProcessName", 256);
    this.localHealthUrl = validHttpUrl(options.localHealthUrl, "localHealthUrl");
    this.publicHealthUrl = options.publicHealthUrl
      ? validHttpUrl(options.publicHealthUrl, "publicHealthUrl")
      : undefined;
    this.expectedCwd = resolve(options.expectedCwd ?? process.cwd());
    this.expectedScript = options.expectedScript ? resolve(options.expectedScript) : undefined;
    this.defaultDelayMs = boundedInteger(
      options.defaultDelayMs,
      DEFAULT_DELAY_MS,
      MINIMUM_DELAY_MS,
      MAXIMUM_DELAY_MS,
      "defaultDelayMs",
    );
    this.timeoutMs = boundedInteger(
      options.timeoutMs,
      DEFAULT_TIMEOUT_MS,
      10_000,
      10 * 60_000,
      "timeoutMs",
    );
    this.now = options.now ?? Date.now;
    this.workerPath = resolve(
      options.workerPath
        ?? fileURLToPath(new URL("./self-management-worker.js", import.meta.url)),
    );
    this.pm2Executable = options.pm2Executable;
    this.runtimeIdentity = options.runtimeIdentity;
    this.launchWorker = options.launchWorker
      ?? ((request) => launchDetachedRestartWorker(
        request,
        options.platform ?? process.platform,
        this.workerPath,
      ));
  }

  async requestRestart(input: RestartBrokerInput = {}): Promise<RestartTransactionStatus> {
    await this.prepareState();
    const active = await this.activeTransaction();
    if (active) {
      throw new UniversalBrokerError(
        "PRECONDITION_FAILED",
        `A broker restart transaction is already active: ${active.transactionId}`,
        { evidence: { transactionId: active.transactionId, state: active.state } },
      );
    }
    const reason = optionalText(input.reason, MAXIMUM_REASON_CHARACTERS, "reason");
    const delayMs = boundedInteger(
      input.delayMs,
      this.defaultDelayMs,
      MINIMUM_DELAY_MS,
      MAXIMUM_DELAY_MS,
      "delayMs",
    );
    const transactionId = `restart_${randomUUID()}`;
    const directory = this.transactionDirectory(transactionId);
    await mkdir(directory, { recursive: false, mode: 0o700 });
    const requestPath = join(directory, "request.json");
    const statusPath = join(directory, "status.json");
    const workerLogPath = join(directory, "worker.log");
    const requestedAt = new Date(this.now()).toISOString();
    const launchdLabel = `com.devspace.restart.${transactionId.replaceAll(/[^A-Za-z0-9.-]/gu, "-")}`;
    const request: RestartWorkerRequest = {
      version: 1,
      transactionId,
      requestedAt,
      ...(reason ? { reason } : {}),
      delayMs,
      timeoutMs: this.timeoutMs,
      pm2ProcessName: this.pm2ProcessName,
      pm2Executable: resolvePm2Executable(this.pm2Executable),
      expectedCwd: this.expectedCwd,
      ...(this.expectedScript ? { expectedScript: this.expectedScript } : {}),
      localHealthUrl: this.localHealthUrl,
      ...(this.publicHealthUrl ? { publicHealthUrl: this.publicHealthUrl } : {}),
      ...(this.runtimeIdentity ? { expectedIdentity: this.runtimeIdentity } : {}),
      statusPath,
      requestPath,
      workerLogPath,
      ...(process.platform === "darwin" ? { launchdLabel } : {}),
    };
    const status: RestartTransactionStatus = {
      version: 1,
      transactionId,
      state: "REQUESTED",
      requestedAt,
      updatedAt: requestedAt,
      expectedDisconnect: true,
      ...(reason ? { reason } : {}),
      evidence: {
        expectedCwd: this.expectedCwd,
        expectedScript: this.expectedScript,
        pm2ProcessName: this.pm2ProcessName,
        localHealthUrl: this.localHealthUrl,
        publicHealthUrl: this.publicHealthUrl,
        responseGraceMs: delayMs,
        expectedIdentity: this.runtimeIdentity,
      },
    };
    await atomicJsonWrite(requestPath, request);
    await atomicJsonWrite(statusPath, status);
    try {
      this.launchWorker(request);
    } catch (error) {
      const failed: RestartTransactionStatus = {
        ...status,
        state: "FAIL",
        updatedAt: new Date(this.now()).toISOString(),
        error: error instanceof Error ? error.message : String(error),
      };
      await atomicJsonWrite(statusPath, failed);
      throw new UniversalBrokerError(
        "SUPERVISOR_UNAVAILABLE",
        "Unable to launch the independent broker restart worker.",
        { evidence: { transactionId, error: failed.error } },
      );
    }
    return status;
  }

  async status(transactionId: string): Promise<RestartTransactionStatus> {
    validateTransactionId(transactionId);
    try {
      const parsed = JSON.parse(
        await readFile(join(this.transactionDirectory(transactionId), "status.json"), "utf8"),
      ) as RestartTransactionStatus;
      assertStatus(parsed, transactionId);
      if (!isTerminal(parsed.state) && this.isStale(parsed)) {
        const failed: RestartTransactionStatus = {
          ...parsed,
          state: "FAIL",
          updatedAt: new Date(this.now()).toISOString(),
          error: "Restart transaction exceeded its durable verification deadline.",
          evidence: {
            ...(parsed.evidence ?? {}),
            staleRecovered: true,
            timeoutMs: this.timeoutMs,
          },
        };
        await atomicJsonWrite(
          join(this.transactionDirectory(transactionId), "status.json"),
          failed,
        );
        return failed;
      }
      return parsed;
    } catch (error) {
      if (isNodeError(error, "ENOENT")) {
        throw new UniversalBrokerError(
          "PROCESS_NOT_FOUND",
          `Unknown broker restart transaction: ${transactionId}`,
        );
      }
      if (error instanceof UniversalBrokerError) throw error;
      throw new UniversalBrokerError(
        "TRANSPORT_INTERRUPTED",
        `Unable to read broker restart transaction: ${transactionId}`,
        { evidence: { error: error instanceof Error ? error.message : String(error) } },
      );
    }
  }

  async stats(): Promise<Record<string, unknown>> {
    await this.prepareState();
    const statuses = await this.listStatuses();
    return {
      restartTransactions: statuses.length,
      activeRestartTransactions: statuses.filter((status) => !isTerminal(status.state)).length,
    };
  }

  private async prepareState(): Promise<void> {
    await mkdir(this.transactionsDir, { recursive: true, mode: 0o700 });
    await this.prune();
  }

  private async activeTransaction(): Promise<RestartTransactionStatus | undefined> {
    const statuses = await this.listStatuses();
    return statuses.find((status) => !isTerminal(status.state));
  }

  private async listStatuses(): Promise<RestartTransactionStatus[]> {
    const statuses: RestartTransactionStatus[] = [];
    for (const entry of await readdir(this.transactionsDir, { withFileTypes: true })) {
      if (!entry.isDirectory() || !TRANSACTION_ID_PATTERN.test(entry.name)) continue;
      try {
        statuses.push(await this.status(entry.name));
      } catch {
        // Corrupt transaction directories are retained for manual inspection and ignored here.
      }
    }
    return statuses.sort((left, right) => right.requestedAt.localeCompare(left.requestedAt));
  }

  private async prune(): Promise<void> {
    const now = this.now();
    const entries = await readdir(this.transactionsDir, { withFileTypes: true });
    const candidates: Array<{ path: string; mtimeMs: number }> = [];
    for (const entry of entries) {
      if (!entry.isDirectory() || !TRANSACTION_ID_PATTERN.test(entry.name)) continue;
      const path = join(this.transactionsDir, entry.name);
      const metadata = await stat(path);
      candidates.push({ path, mtimeMs: metadata.mtimeMs });
    }
    candidates.sort((left, right) => right.mtimeMs - left.mtimeMs);
    for (const [index, candidate] of candidates.entries()) {
      if (index < MAXIMUM_RETAINED_TRANSACTIONS && candidate.mtimeMs + RETENTION_MS > now) continue;
      try {
        const status = JSON.parse(
          await readFile(join(candidate.path, "status.json"), "utf8"),
        ) as RestartTransactionStatus;
        if (!isTerminal(status.state)) continue;
      } catch {
        continue;
      }
      await rm(candidate.path, { recursive: true, force: true });
    }
  }

  private isStale(status: RestartTransactionStatus): boolean {
    const updatedAtMs = Date.parse(status.updatedAt);
    if (!Number.isFinite(updatedAtMs)) return true;
    return updatedAtMs
      + this.timeoutMs
      + MAXIMUM_DELAY_MS
      + STALE_TRANSACTION_MARGIN_MS
      <= this.now();
  }

  private transactionDirectory(transactionId: string): string {
    validateTransactionId(transactionId);
    return join(this.transactionsDir, transactionId);
  }
}

export async function atomicRestartStatusWrite(
  path: string,
  status: RestartTransactionStatus,
): Promise<void> {
  await atomicJsonWrite(path, status);
}

function launchDetachedRestartWorker(
  request: RestartWorkerRequest,
  platform: NodeJS.Platform,
  workerPath: string,
): void {
  if (!existsSync(workerPath)) {
    throw new Error(`Restart worker is missing: ${workerPath}`);
  }
  if (platform === "darwin") {
    const result = spawnSync(
      "/bin/launchctl",
      [
        "submit",
        "-l",
        request.launchdLabel!,
        "-o",
        request.workerLogPath,
        "-e",
        request.workerLogPath,
        "--",
        process.execPath,
        workerPath,
        request.requestPath,
      ],
      {
        encoding: "utf8",
        timeout: 10_000,
        env: workerEnvironment(),
      },
    );
    if (result.status !== 0) {
      throw new Error(`launchctl submit failed: ${bounded(result.stderr || result.stdout)}`);
    }
    return;
  }

  const logFd = openSync(request.workerLogPath, "a", 0o600);
  try {
    const options: SpawnOptions = {
      detached: true,
      stdio: ["ignore", logFd, logFd],
      env: workerEnvironment(),
      windowsHide: true,
    };
    const child = spawn(process.execPath, [workerPath, request.requestPath], options);
    child.once("error", () => undefined);
    child.unref();
  } finally {
    closeSync(logFd);
  }
}

function workerEnvironment(): NodeJS.ProcessEnv {
  return {
    HOME: process.env.HOME ?? homedir(),
    USER: process.env.USER,
    LOGNAME: process.env.LOGNAME,
    PATH: process.env.PATH ?? "/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin",
    TMPDIR: process.env.TMPDIR,
    LANG: process.env.LANG,
    LC_ALL: process.env.LC_ALL,
  };
}

async function atomicJsonWrite(path: string, value: unknown): Promise<void> {
  await mkdir(dirname(path), { recursive: true, mode: 0o700 });
  const temporary = join(dirname(path), `.${basename(path)}.${process.pid}.${randomUUID()}.tmp`);
  const file = await openFile(temporary, "wx", 0o600);
  try {
    await file.writeFile(`${JSON.stringify(value, null, 2)}\n`, "utf8");
    await file.sync();
  } finally {
    await file.close();
  }
  await rename(temporary, path);
  const directory = await openFile(dirname(path), "r");
  try {
    await directory.sync();
  } finally {
    await directory.close();
  }
}

function resolvePm2Executable(configured?: string): string {
  if (configured) {
    const absolute = resolve(configured);
    if (!existsSync(absolute)) throw new Error(`Configured PM2 executable is missing: ${absolute}`);
    return absolute;
  }
  for (const directory of (process.env.PATH ?? "").split(":")) {
    if (!directory) continue;
    const candidate = join(directory, "pm2");
    if (existsSync(candidate)) return candidate;
  }
  throw new Error("Unable to resolve the pm2 executable for broker self-management.");
}

function assertStatus(value: RestartTransactionStatus, transactionId: string): void {
  if (
    value?.version !== 1
    || value.transactionId !== transactionId
    || !RESTART_TRANSACTION_STATES.includes(value.state)
  ) {
    throw new UniversalBrokerError(
      "TRANSPORT_INTERRUPTED",
      `Malformed broker restart status: ${transactionId}`,
    );
  }
}

function validateTransactionId(value: string): void {
  if (!TRANSACTION_ID_PATTERN.test(value)) {
    throw new UniversalBrokerError(
      "PRECONDITION_FAILED",
      `Invalid broker restart transaction ID: ${value}`,
    );
  }
}

function isTerminal(state: RestartTransactionState): boolean {
  return state === "PASS" || state === "FAIL";
}

function requiredText(value: string, name: string, maximum: number): string {
  const normalized = value.trim();
  if (!normalized || normalized.length > maximum) {
    throw new Error(`${name} must use 1 through ${maximum} characters.`);
  }
  return normalized;
}

function optionalText(value: string | undefined, maximum: number, name: string): string | undefined {
  if (value === undefined) return undefined;
  return requiredText(value, name, maximum);
}

function boundedInteger(
  value: number | undefined,
  fallback: number,
  minimum: number,
  maximum: number,
  name: string,
): number {
  const parsed = value ?? fallback;
  if (!Number.isInteger(parsed) || parsed < minimum || parsed > maximum) {
    throw new Error(`${name} must be an integer from ${minimum} through ${maximum}.`);
  }
  return parsed;
}

function validHttpUrl(value: string, name: string): string {
  const url = new URL(value);
  if (!['http:', 'https:'].includes(url.protocol) || url.username || url.password) {
    throw new Error(`${name} must be an HTTP(S) URL without credentials.`);
  }
  return url.href;
}

function bounded(value: string, maximum = 2_000): string {
  return value.length <= maximum ? value : `${value.slice(0, maximum)}…`;
}

function isNodeError(error: unknown, code: string): boolean {
  return Boolean(error && typeof error === "object" && "code" in error && error.code === code);
}
