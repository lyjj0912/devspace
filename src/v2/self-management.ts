import { randomUUID } from "node:crypto";
import { AsyncLocalStorage } from "node:async_hooks";
import {
  closeSync,
  existsSync,
  openSync,
  realpathSync,
} from "node:fs";
import {
  chmod,
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
import type { UniversalBrokerMetrics } from "./metrics.js";

export const RESTART_TRANSACTION_STATES = [
  "PREPARED",
  "RESPONSE_BOUND",
  "ACK_FLUSHED",
  "ACK_ABORTED",
  "HANDOFF_ACCEPTED",
  "RESTARTING",
  "VERIFYING",
  "PASS",
  "FAIL",
  "UNKNOWN",
] as const;

export type RestartTransactionState = (typeof RESTART_TRANSACTION_STATES)[number];

export interface RestartBrokerInput {
  reason?: string;
  ownerFingerprint: string;
  /** Ignored legacy caller field. */
  authorityId?: string;
}

export interface RestartStatusInput {
  transactionId?: string;
}

export interface RestartTransitionRecord {
  state: RestartTransactionState;
  at: string;
}

export interface RestartWorkerRequest {
  version: 2;
  transactionId: string;
  requestedAt: string;
  ownerFingerprint: string;
  /** Ignored legacy persisted field. */
  authorityId?: string;
  reason?: string;
  timeoutMs: number;
  pm2ProcessName: string;
  pm2Executable: string;
  expectedCwd: string;
  expectedScript?: string;
  localHealthUrl: string;
  publicHealthUrl?: string;
  expectedRuntimeIdentity: RuntimeIdentity;
  statusPath: string;
  requestPath: string;
  workerLogPath: string;
  launchdLabel?: string;
}

export interface RestartTransactionStatus extends Record<string, unknown> {
  version: 2;
  transactionId: string;
  state: RestartTransactionState;
  requestedAt: string;
  updatedAt: string;
  expectedDisconnect: boolean;
  ownerFingerprint: string;
  expectedRuntimeIdentity: RuntimeIdentity;
  reason?: string;
  responseTransportId?: string;
  responseRequestId?: string;
  responseBoundAt?: string;
  ackFlushedAt?: string;
  ackAbortedAt?: string;
  abortReason?: string;
  handoffAcceptedAt?: string;
  restartStartedAt?: string;
  verifyingAt?: string;
  completedAt?: string;
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
  history: RestartTransitionRecord[];
}

type RestartStatusWriter = (
  path: string,
  status: RestartTransactionStatus,
) => Promise<void>;

export interface UniversalSelfManagementOptions {
  stateDir: string;
  pm2ProcessName: string;
  localHealthUrl: string;
  publicHealthUrl?: string;
  expectedCwd?: string;
  expectedScript?: string;
  timeoutMs?: number;
  now?: () => number;
  workerPath?: string;
  pm2Executable?: string;
  launchWorker?: (request: RestartWorkerRequest) => void;
  writeStatus?: RestartStatusWriter;
  platform?: NodeJS.Platform;
  runtimeIdentity: RuntimeIdentity;
  metrics?: UniversalBrokerMetrics;
  supervisorReadinessProbe?: () => SupervisorControlReadiness | Promise<SupervisorControlReadiness>;
}

export interface SupervisorControlReadiness {
  state: "PASS" | "FAIL" | "UNKNOWN";
  summary?: string;
  evidence: Record<string, unknown>;
}

const TRANSACTION_ID_PATTERN = /^restart_[0-9a-f-]{36}$/u;
const OWNER_FINGERPRINT_PATTERN = /^[a-f0-9]{64}$/u;
const SHA256_DIGEST_PATTERN = /^sha256:[a-f0-9]{64}$/u;
const RESTART_TRANSITIONS: Readonly<Record<RestartTransactionState, readonly RestartTransactionState[]>> = {
  PREPARED: ["RESPONSE_BOUND", "UNKNOWN"],
  RESPONSE_BOUND: ["ACK_FLUSHED", "ACK_ABORTED", "UNKNOWN"],
  ACK_FLUSHED: ["HANDOFF_ACCEPTED", "UNKNOWN"],
  ACK_ABORTED: ["FAIL", "UNKNOWN"],
  HANDOFF_ACCEPTED: ["RESTARTING", "UNKNOWN"],
  RESTARTING: ["VERIFYING", "UNKNOWN"],
  VERIFYING: ["PASS", "FAIL", "UNKNOWN"],
  PASS: [],
  FAIL: [],
  UNKNOWN: [],
};
const DEFAULT_TIMEOUT_MS = 120_000;
const MAXIMUM_REASON_CHARACTERS = 2_000;
const MAXIMUM_IDENTIFIER_CHARACTERS = 256;
const MAXIMUM_RESPONSE_TRANSPORT_ID_CHARACTERS = 256;
const MAXIMUM_RESPONSE_REQUEST_ID_CHARACTERS = 512;
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
  private readonly timeoutMs: number;
  private readonly now: () => number;
  private readonly workerPath: string;
  private readonly pm2Executable?: string;
  private readonly launchWorker: (request: RestartWorkerRequest) => void;
  private readonly writeStatus: RestartStatusWriter;
  private readonly runtimeIdentity: RuntimeIdentity;
  private readonly metrics?: UniversalBrokerMetrics;
  private readonly supervisorReadinessProbe: () => SupervisorControlReadiness | Promise<SupervisorControlReadiness>;
  private readonly recordedMetricStates = new Set<string>();
  private readonly locks = new Map<string, Promise<void>>();
  private readonly responseTransportContext = new AsyncLocalStorage<string>();

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
    if (!validRuntimeIdentity(options.runtimeIdentity)) {
      throw new Error("runtimeIdentity is missing or invalid for broker self-management.");
    }
    this.runtimeIdentity = Object.freeze({ ...options.runtimeIdentity });
    this.metrics = options.metrics;
    this.supervisorReadinessProbe = options.supervisorReadinessProbe
      ?? (() => probePm2SupervisorControl({
        pm2Executable: resolvePm2Executable(this.pm2Executable),
        processName: this.pm2ProcessName,
        expectedCwd: this.expectedCwd,
        expectedScript: this.expectedScript,
      }));
    this.writeStatus = options.writeStatus ?? atomicRestartStatusWrite;
    this.launchWorker = options.launchWorker
      ?? ((request) => launchDetachedRestartWorker(
        request,
        options.platform ?? process.platform,
        this.workerPath,
      ));
  }

  /**
   * Durably prepares a restart. This method never launches a worker. The caller must bind the
   * transaction to the exact response and only an actual transport finish may acknowledge it.
   */
  async requestRestart(input: RestartBrokerInput): Promise<RestartTransactionStatus> {
    return this.withLock("active-restart", async () => {
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
      const ownerFingerprint = requiredOwnerFingerprint(input.ownerFingerprint);
      const transactionId = `restart_${randomUUID()}`;
      const directory = this.transactionDirectory(transactionId);
      await mkdir(directory, { recursive: false, mode: 0o700 });
      const requestPath = join(directory, "request.json");
      const statusPath = join(directory, "status.json");
      const workerLogPath = join(directory, "worker.log");
      const requestedAt = this.timestamp();
      const launchdLabel = `com.devspace.restart.${transactionId.replaceAll(/[^A-Za-z0-9.-]/gu, "-")}`;
      const request: RestartWorkerRequest = {
        version: 2,
        transactionId,
        requestedAt,
        ownerFingerprint,
        ...(reason ? { reason } : {}),
        timeoutMs: this.timeoutMs,
        pm2ProcessName: this.pm2ProcessName,
        pm2Executable: resolvePm2Executable(this.pm2Executable),
        expectedCwd: this.expectedCwd,
        ...(this.expectedScript ? { expectedScript: this.expectedScript } : {}),
        localHealthUrl: this.localHealthUrl,
        ...(this.publicHealthUrl ? { publicHealthUrl: this.publicHealthUrl } : {}),
        expectedRuntimeIdentity: this.runtimeIdentity,
        statusPath,
        requestPath,
        workerLogPath,
        ...(process.platform === "darwin" ? { launchdLabel } : {}),
      };
      const status: RestartTransactionStatus = {
        version: 2,
        transactionId,
        state: "PREPARED",
        requestedAt,
        updatedAt: requestedAt,
        expectedDisconnect: true,
        ownerFingerprint,
        expectedRuntimeIdentity: this.runtimeIdentity,
        ...(reason ? { reason } : {}),
        history: [{ state: "PREPARED", at: requestedAt }],
        evidence: {
          expectedCwd: this.expectedCwd,
          expectedScript: this.expectedScript,
          pm2ProcessName: this.pm2ProcessName,
          localHealthUrl: this.localHealthUrl,
          publicHealthUrl: this.publicHealthUrl,
          expectedRuntimeIdentity: this.runtimeIdentity,
          handoffPolicy: "ACK_FLUSHED_ONLY",
        },
      };
      try {
        await atomicJsonWrite(requestPath, request);
        await this.writeStatus(statusPath, status);
      } catch (error) {
        await rm(directory, { recursive: true, force: true });
        throw error;
      }
      this.recordRestartMetric(status);
      return status;
    });
  }

  /** Bind a prepared transaction to the precise JSON-RPC/transport response identifier. */
  async bindResponse(
    transactionId: string,
    responseRequestId: string | number,
    responseTransportId = this.responseTransportContext.getStore(),
  ): Promise<RestartTransactionStatus> {
    validateTransactionId(transactionId);
    const normalizedRequestId = normalizeResponseRequestId(responseRequestId);
    const normalizedTransportId = normalizeResponseTransportId(responseTransportId);
    return this.withLock(transactionId, async () => {
      const status = await this.loadStatus(transactionId);
      if (
        (status.responseRequestId && status.responseRequestId !== normalizedRequestId)
        || (status.responseTransportId && status.responseTransportId !== normalizedTransportId)
      ) {
        throw new UniversalBrokerError(
          "PRECONDITION_FAILED",
          "Restart transaction is already bound to another transport response.",
          { evidence: { transactionId, state: status.state } },
        );
      }
      if (status.state === "PREPARED") {
        const at = this.timestamp();
        const next = transitionStatus(status, "RESPONSE_BOUND", at, {
          responseTransportId: normalizedTransportId,
          responseRequestId: normalizedRequestId,
          responseBoundAt: at,
        });
        await this.writeStatus(this.statusPath(transactionId), next);
        return next;
      }
      if (
        status.responseRequestId === normalizedRequestId
        && status.responseTransportId === normalizedTransportId
      ) return status;
      throw invalidTransition(status, "RESPONSE_BOUND");
    });
  }

  /** Propagate an unspoofable HTTP-response identity into the MCP tool handler async chain. */
  withResponseTransport<T>(responseTransportId: string, action: () => T): T {
    const normalizedTransportId = normalizeResponseTransportId(responseTransportId);
    return this.responseTransportContext.run(normalizedTransportId, action);
  }

  /**
   * HTTP integration seam: invoke from the actual response `finish` callback. A durable
   * ACK_FLUSHED write happens before the independent supervisor is launched.
   */
  async responseFlushedForRequest(
    responseTransportId: string,
    responseRequestId: string | number,
  ): Promise<RestartTransactionStatus | undefined> {
    const normalizedTransportId = normalizeResponseTransportId(responseTransportId);
    const normalizedRequestId = normalizeResponseRequestId(responseRequestId);
    const transactionId = await this.boundTransactionId(normalizedTransportId, normalizedRequestId);
    if (!transactionId) return undefined;
    return this.responseFlushed(transactionId, normalizedTransportId, normalizedRequestId);
  }

  /** Exact durable compare-and-set used by the request-only HTTP integration seam. */
  async responseFlushed(
    transactionId: string,
    responseTransportId: string,
    responseRequestId: string | number,
  ): Promise<RestartTransactionStatus> {
    validateTransactionId(transactionId);
    const normalizedTransportId = normalizeResponseTransportId(responseTransportId);
    const normalizedRequestId = normalizeResponseRequestId(responseRequestId);
    return this.withLock(transactionId, async () => {
      const status = await this.loadStatus(transactionId);
      assertResponseBinding(status, normalizedTransportId, normalizedRequestId);
      if (status.state !== "RESPONSE_BOUND") return status;

      const at = this.timestamp();
      const acknowledged = transitionStatus(status, "ACK_FLUSHED", at, {
        ackFlushedAt: at,
      });
      // This write is the safety boundary. Never move launchWorker before it.
      await this.writeStatus(this.statusPath(status.transactionId), acknowledged);
      this.recordRestartMetric(acknowledged);
      try {
        this.launchWorker(await this.loadWorkerRequest(status.transactionId));
      } catch (error) {
        const unknownAt = this.timestamp();
        const unknown = transitionStatus(acknowledged, "UNKNOWN", unknownAt, {
          completedAt: unknownAt,
          error: errorMessage(error),
          evidence: {
            ...(acknowledged.evidence ?? {}),
            handoffAttempted: true,
            automaticRetry: false,
          },
        });
        await this.writeStatus(this.statusPath(status.transactionId), unknown);
        this.recordRestartMetric(unknown);
        throw new UniversalBrokerError(
          "SUPERVISOR_UNAVAILABLE",
          "Unable to confirm the independent broker restart supervisor handoff.",
          { evidence: { transactionId: status.transactionId, error: unknown.error } },
        );
      }
      return acknowledged;
    });
  }

  /** HTTP integration seam for response `close`, request `aborted`, or response `error`. */
  async responseAbortedForRequest(
    responseTransportId: string,
    responseRequestId: string | number,
    reason = "response transport aborted before flush",
  ): Promise<RestartTransactionStatus | undefined> {
    const normalizedTransportId = normalizeResponseTransportId(responseTransportId);
    const normalizedRequestId = normalizeResponseRequestId(responseRequestId);
    const transactionId = await this.boundTransactionId(normalizedTransportId, normalizedRequestId);
    if (!transactionId) return undefined;
    return this.responseAborted(
      transactionId,
      normalizedTransportId,
      normalizedRequestId,
      reason,
    );
  }

  /** Exact durable compare-and-set for transport abort, followed by terminal FAIL. */
  async responseAborted(
    transactionId: string,
    responseTransportId: string,
    responseRequestId: string | number,
    reason = "response transport aborted before flush",
  ): Promise<RestartTransactionStatus> {
    validateTransactionId(transactionId);
    const normalizedTransportId = normalizeResponseTransportId(responseTransportId);
    const normalizedRequestId = normalizeResponseRequestId(responseRequestId);
    const normalizedReason = requiredText(reason, "abort reason", MAXIMUM_REASON_CHARACTERS);
    return this.withLock(transactionId, async () => {
      let status = await this.loadStatus(transactionId);
      assertResponseBinding(status, normalizedTransportId, normalizedRequestId);
      if (status.state === "RESPONSE_BOUND") {
        const acknowledgedAt = this.timestamp();
        status = transitionStatus(status, "ACK_ABORTED", acknowledgedAt, {
          ackAbortedAt: acknowledgedAt,
          abortReason: normalizedReason,
        });
        await this.writeStatus(this.statusPath(status.transactionId), status);
      }
      if (status.state !== "ACK_ABORTED") return status;
      const failedAt = this.timestamp();
      const failed = transitionStatus(status, "FAIL", failedAt, {
        completedAt: failedAt,
        error: status.abortReason ?? normalizedReason,
      });
      await this.writeStatus(this.statusPath(status.transactionId), failed);
      this.recordRestartMetric(failed);
      return failed;
    });
  }

  /** Resolve only a unique durable transaction/request binding; ambiguity fails closed. */
  async boundTransactionId(
    responseTransportId: string,
    responseRequestId: string | number,
  ): Promise<string | undefined> {
    const normalizedTransportId = normalizeResponseTransportId(responseTransportId);
    const normalizedRequestId = normalizeResponseRequestId(responseRequestId);
    await this.prepareState();
    const matches = (await this.listStatuses())
      .filter((status) => (
        status.responseTransportId === normalizedTransportId
        && status.responseRequestId === normalizedRequestId
      ));
    if (matches.length > 1) {
      throw new UniversalBrokerError(
        "PRECONDITION_FAILED",
        "Restart response binding is ambiguous; no acknowledgement was recorded.",
        {
          evidence: {
            responseTransportId: normalizedTransportId,
            responseRequestId: normalizedRequestId,
            matches: matches.length,
          },
        },
      );
    }
    return matches[0]?.transactionId;
  }

  async status(transactionId: string): Promise<RestartTransactionStatus> {
    validateTransactionId(transactionId);
    try {
      const status = await this.loadStatus(transactionId);
      if (
        isTerminal(status.state)
        || !this.isStale(status)
        || supervisorStillOwns(status)
      ) {
        this.recordRestartMetric(status);
        return status;
      }
      return this.withLock(transactionId, async () => {
        const current = await this.loadStatus(transactionId);
        if (
          isTerminal(current.state)
          || !this.isStale(current)
          || supervisorStillOwns(current)
        ) {
          this.recordRestartMetric(current);
          return current;
        }
        const at = this.timestamp();
        const unknown = transitionStatus(current, "UNKNOWN", at, {
          completedAt: at,
          error: "Restart transaction exceeded its durable verification deadline; outcome is unknown.",
          evidence: {
            ...(current.evidence ?? {}),
            staleRecovered: true,
            timeoutMs: this.timeoutMs,
            automaticRetry: false,
          },
        });
        await this.writeStatus(this.statusPath(transactionId), unknown);
        this.recordRestartMetric(unknown);
        return unknown;
      });
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
        { evidence: { error: errorMessage(error) } },
      );
    }
  }

  async stats(): Promise<Record<string, unknown>> {
    await this.prepareState();
    const statuses = await this.listStatuses();
    return {
      restartTransactions: statuses.length,
      activeRestartTransactions: statuses.filter((status) => !isTerminal(status.state)).length,
      restartOutcomes: Object.fromEntries(RESTART_TRANSACTION_STATES.map((state) => [
        state,
        statuses.filter((status) => status.state === state).length,
      ])),
    };
  }

  /** Read-only PM2 RPC/control-channel probe used by private readiness. */
  async supervisorReadiness(): Promise<SupervisorControlReadiness> {
    try {
      const observation = await this.supervisorReadinessProbe();
      if (
        !observation
        || !["PASS", "FAIL", "UNKNOWN"].includes(observation.state)
        || !observation.evidence
        || typeof observation.evidence !== "object"
      ) {
        throw new Error("Supervisor readiness probe returned malformed evidence.");
      }
      return observation;
    } catch (error) {
      return {
        state: "FAIL",
        summary: "The PM2 supervisor control channel could not be verified.",
        evidence: { controlChannel: "pm2-rpc", error: errorMessage(error) },
      };
    }
  }

  private async prepareState(): Promise<void> {
    await mkdir(this.transactionsDir, { recursive: true, mode: 0o700 });
    await chmod(this.transactionsDir, 0o700);
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
        statuses.push(await this.loadStatus(entry.name));
      } catch (error) {
        if (error instanceof UniversalBrokerError) throw error;
        throw new UniversalBrokerError(
          "TRANSPORT_INTERRUPTED",
          `Unable to validate durable broker restart transaction: ${entry.name}`,
          { evidence: { transactionId: entry.name, error: errorMessage(error) } },
        );
      }
    }
    return statuses.sort((left, right) => right.requestedAt.localeCompare(left.requestedAt));
  }

  private async loadStatus(transactionId: string): Promise<RestartTransactionStatus> {
    const parsed = JSON.parse(await readFile(this.statusPath(transactionId), "utf8")) as RestartTransactionStatus;
    assertRestartStatus(parsed, transactionId);
    return parsed;
  }

  private async loadWorkerRequest(transactionId: string): Promise<RestartWorkerRequest> {
    const value = JSON.parse(
      await readFile(join(this.transactionDirectory(transactionId), "request.json"), "utf8"),
    ) as RestartWorkerRequest;
    assertRestartWorkerRequest(value, transactionId);
    return value;
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
    return updatedAtMs + this.timeoutMs + STALE_TRANSACTION_MARGIN_MS <= this.now();
  }

  private statusPath(transactionId: string): string {
    return join(this.transactionDirectory(transactionId), "status.json");
  }

  private transactionDirectory(transactionId: string): string {
    validateTransactionId(transactionId);
    return join(this.transactionsDir, transactionId);
  }

  private timestamp(): string {
    return new Date(this.now()).toISOString();
  }

  private recordRestartMetric(status: RestartTransactionStatus): void {
    const result = status.state === "PREPARED"
      ? "requested"
      : status.state === "ACK_FLUSHED"
        ? "ack_flushed"
        : status.state === "PASS"
          ? "pass"
          : status.state === "FAIL"
            ? "fail"
            : status.state === "UNKNOWN"
              ? "unknown"
              : undefined;
    if (!result) return;
    const key = `${status.transactionId}:${result}`;
    if (this.recordedMetricStates.has(key)) return;
    try {
      this.metrics?.recordRestartTransaction(result);
      this.recordedMetricStates.add(key);
    } catch {
      // Observability must never replace restart state-machine evidence.
    }
  }

  private async withLock<T>(key: string, action: () => Promise<T>): Promise<T> {
    const previous = this.locks.get(key) ?? Promise.resolve();
    let release!: () => void;
    const turn = new Promise<void>((resolvePromise) => { release = resolvePromise; });
    const tail = previous.then(() => turn, () => turn);
    this.locks.set(key, tail);
    await previous.catch(() => undefined);
    try {
      return await action();
    } finally {
      release();
      if (this.locks.get(key) === tail) this.locks.delete(key);
    }
  }
}

function probePm2SupervisorControl(input: {
  pm2Executable: string;
  processName: string;
  expectedCwd: string;
  expectedScript?: string;
}): SupervisorControlReadiness {
  const pm2Root = dirname(dirname(realpathSync(input.pm2Executable)));
  if (!existsSync(join(pm2Root, "package.json"))) {
    throw new Error("Unable to resolve the PM2 programmatic control module.");
  }
  const source = String.raw`
const [pm2Root, processName] = process.argv.slice(1);
const pm2 = require(pm2Root);
const finish = (value, code = 0) => {
  process.stdout.write(JSON.stringify(value));
  process.exit(code);
};
pm2.Client.launchRPC((connectionError) => {
  if (connectionError) return finish({ ok: false, error: String(connectionError.message || connectionError) }, 2);
  pm2.Client.executeRemote("getMonitorData", {}, (queryError, list) => {
    if (queryError || !Array.isArray(list)) {
      return finish({ ok: false, error: String(queryError?.message || queryError || "invalid PM2 response") }, 3);
    }
    const matches = list.filter((item) => item?.name === processName).map((item) => ({
      pid: item.pid,
      status: item.pm2_env?.status,
      cwd: item.pm2_env?.pm_cwd,
      script: item.pm2_env?.pm_exec_path,
    }));
    return finish({ ok: true, matches });
  });
});`;
  const result = spawnSync(process.execPath, [
    "--input-type=commonjs",
    "--eval",
    source,
    pm2Root,
    input.processName,
  ], {
    encoding: "utf8",
    timeout: 3_000,
    maxBuffer: 64 * 1024,
    env: { ...process.env, PM2_SILENT: "true" },
  });
  if (result.error) throw result.error;
  if (result.status !== 0) {
    throw new Error(`PM2 RPC probe exited ${String(result.status)}: ${result.stderr.trim()}`);
  }
  const parsed = JSON.parse(result.stdout) as {
    ok?: boolean;
    matches?: Array<{ pid?: unknown; status?: unknown; cwd?: unknown; script?: unknown }>;
  };
  const matches = parsed.ok && Array.isArray(parsed.matches) ? parsed.matches : [];
  const exact = matches.length === 1 ? matches[0]! : undefined;
  const online = exact?.status === "online";
  const cwdMatches = typeof exact?.cwd === "string" && resolve(exact.cwd) === input.expectedCwd;
  const scriptMatches = input.expectedScript === undefined
    || (typeof exact?.script === "string" && resolve(exact.script) === input.expectedScript);
  const passed = Boolean(exact && online && cwdMatches && scriptMatches);
  return {
    state: passed ? "PASS" : "FAIL",
    ...(passed ? {} : { summary: "PM2 does not expose exactly one matching online broker process." }),
    evidence: {
      controlChannel: "pm2-rpc",
      processMatches: matches.length,
      online,
      cwdMatches,
      scriptMatches,
      pid: typeof exact?.pid === "number" && exact.pid > 0 ? exact.pid : undefined,
    },
  };
}

export async function atomicRestartStatusWrite(
  path: string,
  status: RestartTransactionStatus,
): Promise<void> {
  assertRestartStatus(status, status.transactionId);
  await atomicJsonWrite(path, status);
}

export async function readRestartStatus(path: string): Promise<RestartTransactionStatus> {
  const value = JSON.parse(await readFile(resolve(path), "utf8")) as RestartTransactionStatus;
  assertRestartStatus(value, value?.transactionId);
  return value;
}

export function assertRestartStatus(
  value: RestartTransactionStatus,
  transactionId: string | undefined,
): void {
  if (
    value?.version !== 2
    || typeof transactionId !== "string"
    || value.transactionId !== transactionId
    || !RESTART_TRANSACTION_STATES.includes(value.state)
    || value.expectedDisconnect !== true
    || !Number.isFinite(Date.parse(value.requestedAt))
    || !Number.isFinite(Date.parse(value.updatedAt))
    || !OWNER_FINGERPRINT_PATTERN.test(value.ownerFingerprint)
    || !validRuntimeIdentity(value.expectedRuntimeIdentity)
    || !validRestartHistory(value)
  ) {
    throw new UniversalBrokerError(
      "TRANSPORT_INTERRUPTED",
      `Malformed broker restart status: ${transactionId ?? "unknown"}`,
    );
  }
}

export function assertRestartWorkerRequest(
  value: RestartWorkerRequest,
  transactionId = value?.transactionId,
): void {
  if (
    value?.version !== 2
    || value.transactionId !== transactionId
    || !TRANSACTION_ID_PATTERN.test(value.transactionId)
    || !OWNER_FINGERPRINT_PATTERN.test(value.ownerFingerprint)
    || !validRuntimeIdentity(value.expectedRuntimeIdentity)
    || !value.statusPath
    || !value.requestPath
    || !value.pm2Executable
    || !value.pm2ProcessName
  ) {
    throw new Error(`Malformed restart worker request: ${value?.requestPath ?? "unknown"}`);
  }
}

function transitionStatus(
  status: RestartTransactionStatus,
  state: RestartTransactionState,
  at: string,
  fields: Partial<RestartTransactionStatus> = {},
): RestartTransactionStatus {
  return {
    ...status,
    ...fields,
    state,
    updatedAt: at,
    history: [...status.history, { state, at }],
  };
}

function invalidTransition(
  status: RestartTransactionStatus,
  target: RestartTransactionState,
): UniversalBrokerError {
  return new UniversalBrokerError(
    "PRECONDITION_FAILED",
    `Invalid restart transaction transition ${status.state} -> ${target}.`,
    { evidence: { transactionId: status.transactionId, state: status.state, target } },
  );
}

function assertResponseBinding(
  status: RestartTransactionStatus,
  responseTransportId: string,
  responseRequestId: string,
): void {
  if (
    status.responseTransportId === responseTransportId
    && status.responseRequestId === responseRequestId
  ) return;
  throw new UniversalBrokerError(
    "PRECONDITION_FAILED",
    "Restart transaction is not bound to this response request.",
    {
      evidence: {
        transactionId: status.transactionId,
        state: status.state,
        responseTransportId,
        responseRequestId,
      },
    },
  );
}

function launchDetachedRestartWorker(
  request: RestartWorkerRequest,
  platform: NodeJS.Platform,
  workerPath: string,
): void {
  if (!existsSync(workerPath)) throw new Error(`Restart worker is missing: ${workerPath}`);
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
  let published = false;
  try {
    const file = await openFile(temporary, "wx", 0o600);
    try {
      await file.writeFile(`${JSON.stringify(value, null, 2)}\n`, "utf8");
      await file.sync();
    } finally {
      await file.close();
    }
    await rename(temporary, path);
    published = true;
    const directory = await openFile(dirname(path), "r");
    try {
      await directory.sync();
    } finally {
      await directory.close();
    }
  } finally {
    if (!published) await rm(temporary, { force: true });
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

function normalizeResponseRequestId(value: string | number): string {
  const normalized = typeof value === "number" ? String(value) : value.trim();
  if (
    !normalized
    || normalized.length > MAXIMUM_RESPONSE_REQUEST_ID_CHARACTERS
    || /[\r\n\0]/u.test(normalized)
  ) {
    throw new UniversalBrokerError(
      "PRECONDITION_FAILED",
      "responseRequestId is missing or invalid.",
    );
  }
  return normalized;
}

function normalizeResponseTransportId(value: string | undefined): string {
  if (value === undefined) {
    throw new UniversalBrokerError(
      "PRECONDITION_FAILED",
      "responseTransportId is unavailable; restart response binding is unsafe.",
    );
  }
  try {
    return requiredText(
      value,
      "responseTransportId",
      MAXIMUM_RESPONSE_TRANSPORT_ID_CHARACTERS,
    );
  } catch (error) {
    throw new UniversalBrokerError(
      "PRECONDITION_FAILED",
      errorMessage(error),
    );
  }
}

function validRuntimeIdentity(value: RuntimeIdentity | undefined): value is RuntimeIdentity {
  if (!value || typeof value !== "object") return false;
  if (
    !safeRuntimeIdentityText(value.productVersion)
    || !SHA256_DIGEST_PATTERN.test(value.schemaGeneration)
    || !SHA256_DIGEST_PATTERN.test(value.configDigest)
    || !safeRuntimeIdentityText(value.sourceRevision)
    || !safeRuntimeIdentityText(value.runtimeRevision)
    || !SHA256_DIGEST_PATTERN.test(value.buildDigest)
    || typeof value.startedAt !== "string"
    || value.productProfile !== "PERSONAL_DIRECT_OWNER"
    || !SHA256_DIGEST_PATTERN.test(value.buildCapabilityDigest ?? "")
    || value.resourceUriVersion !== "v1"
  ) return false;
  return Number.isFinite(Date.parse(value.startedAt));
}

function validRestartHistory(status: RestartTransactionStatus): boolean {
  if (!Array.isArray(status.history) || status.history.length === 0) return false;
  if (status.history[0]?.state !== "PREPARED") return false;
  if (status.history.at(-1)?.state !== status.state) return false;
  for (const [index, entry] of status.history.entries()) {
    if (
      !entry
      || !RESTART_TRANSACTION_STATES.includes(entry.state)
      || !Number.isFinite(Date.parse(entry.at))
    ) return false;
    if (index === 0) continue;
    const previous = status.history[index - 1]!.state;
    if (!RESTART_TRANSITIONS[previous].includes(entry.state)) return false;
  }
  if (
    status.history.some((entry) => entry.state === "RESPONSE_BOUND")
    && (
      !safeStatusText(status.responseTransportId, MAXIMUM_RESPONSE_TRANSPORT_ID_CHARACTERS)
      || !safeStatusText(status.responseRequestId, MAXIMUM_RESPONSE_REQUEST_ID_CHARACTERS)
    )
  ) return false;
  return true;
}

function safeStatusText(value: unknown, maximum: number): value is string {
  return typeof value === "string"
    && value.trim().length > 0
    && value.length <= maximum
    && !/[\r\n\0]/u.test(value);
}

function safeRuntimeIdentityText(value: string): boolean {
  return typeof value === "string"
    && value.trim().length > 0
    && value.length <= 256
    && !/[\r\n\0]/u.test(value);
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
  return ["PASS", "FAIL", "UNKNOWN"].includes(state);
}

function supervisorStillOwns(status: RestartTransactionStatus): boolean {
  if (!["HANDOFF_ACCEPTED", "RESTARTING", "VERIFYING"].includes(status.state)) return false;
  if (!Number.isInteger(status.workerPid) || status.workerPid! <= 0) return false;
  try {
    process.kill(status.workerPid!, 0);
    return true;
  } catch (error) {
    return !isNodeError(error, "ESRCH");
  }
}

function requiredOwnerFingerprint(value: string): string {
  const normalized = value.trim().toLowerCase();
  if (!OWNER_FINGERPRINT_PATTERN.test(normalized)) {
    throw new UniversalBrokerError(
      "PRECONDITION_FAILED",
      "ownerFingerprint must be a SHA-256 fingerprint.",
    );
  }
  return normalized;
}

function requiredText(value: string, name: string, maximum: number): string {
  const normalized = value.trim();
  if (!normalized || normalized.length > maximum || /[\r\n\0]/u.test(normalized)) {
    throw new Error(`${name} must use 1 through ${maximum} safe characters.`);
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
  if (!["http:", "https:"].includes(url.protocol) || url.username || url.password) {
    throw new Error(`${name} must be an HTTP(S) URL without credentials.`);
  }
  return url.href;
}

function bounded(value: string, maximum = 2_000): string {
  return value.length <= maximum ? value : `${value.slice(0, maximum)}…`;
}

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

function isNodeError(error: unknown, code: string): boolean {
  return Boolean(error && typeof error === "object" && "code" in error && error.code === code);
}
