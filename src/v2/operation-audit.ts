import { createHash } from "node:crypto";
import { constants } from "node:fs";
import {
  chmod,
  lstat,
  mkdir,
  open,
  readFile,
} from "node:fs/promises";
import { dirname, resolve } from "node:path";

export interface OperationAuditEvent {
  timestamp: string;
  operationId: string;
  correlationId: string;
  principalFingerprintPrefix: string;
  taskInstanceDigest?: string;
  authorityIdDigest?: string;
  actionDigest?: string;
  resourceKeyDigest?: string;
  targetId?: string;
  targetGeneration?: string;
  routeId?: string;
  routeGeneration?: string;
  tool: string;
  operation: string;
  risk: string;
  claimState?: string;
  dispatchState: string;
  result: string;
  errorCode?: string;
}

export interface OperationAuditInput {
  timestamp?: string;
  operationId: string;
  correlationId: string;
  principalFingerprint: string;
  taskInstanceId?: string;
  authorityId?: string;
  action?: unknown;
  resourceKey?: string;
  targetId?: string;
  targetGeneration?: string;
  routeId?: string;
  routeGeneration?: string;
  tool: string;
  operation: string;
  risk: string;
  claimState?: string;
  dispatchState: string;
  result: string;
  errorCode?: string;
  receiptDigest?: string;
}

export interface OperationAuditAppendReceipt {
  sequence: number;
  eventDigest: string;
  receiptDigest?: string;
}

export type OperationAuditRecordResult =
  | ({ status: "RECORDED" } & OperationAuditAppendReceipt)
  | { status: "SINK_FAILED"; error: string };

export interface OperationAuditSinkOptions {
  path: string;
  now?: () => number;
  maximumBatchSize?: number;
  flushIntervalMs?: number;
  scheduleFlush?: (callback: () => void, delayMs: number) => () => void;
}

export interface OperationAuditSinkStats {
  pending: number;
  initialized: boolean;
  failed: boolean;
}

interface StoredOperationAuditEvent extends OperationAuditEvent {
  schemaVersion: 1;
  sequence: number;
  previousEventDigest?: string;
  receiptDigest?: string;
  eventDigest: string;
}

interface PendingAuditEvent {
  event: OperationAuditEvent;
  receiptDigest?: string;
  resolve: (receipt: OperationAuditAppendReceipt) => void;
  reject: (error: Error) => void;
}

const SHA256_PATTERN = /^sha256:[a-f0-9]{64}$/u;
const PRINCIPAL_PATTERN = /^[a-f0-9]{64}$/u;
const SAFE_IDENTIFIER_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._:@/-]{0,255}$/u;
const DEFAULT_MAXIMUM_BATCH_SIZE = 32;
const DEFAULT_FLUSH_INTERVAL_MS = 0;

/**
 * Append-only operation audit sink. Concurrent appends in the same turn are written and fsynced
 * as one hash-chained batch. `record` converts sink failure into data so mutation results remain
 * independently reportable by the caller.
 */
export class OperationAuditSink {
  private readonly path: string;
  private readonly now: () => number;
  private readonly maximumBatchSize: number;
  private readonly flushIntervalMs: number;
  private readonly scheduleFlush: NonNullable<OperationAuditSinkOptions["scheduleFlush"]>;
  private readonly pending: PendingAuditEvent[] = [];
  private flushTail: Promise<void> = Promise.resolve();
  private initialized = false;
  private cancelScheduledFlush?: () => void;
  private closing = false;
  private closed = false;
  private permanentFailure?: Error;
  private inFlight = 0;
  private sequence = 0;
  private previousEventDigest?: string;

  constructor(options: OperationAuditSinkOptions) {
    this.path = resolve(options.path);
    this.now = options.now ?? Date.now;
    this.maximumBatchSize = boundedInteger(
      options.maximumBatchSize,
      DEFAULT_MAXIMUM_BATCH_SIZE,
      1,
      1_000,
      "maximumBatchSize",
    );
    this.flushIntervalMs = boundedInteger(
      options.flushIntervalMs,
      DEFAULT_FLUSH_INTERVAL_MS,
      0,
      60_000,
      "flushIntervalMs",
    );
    this.scheduleFlush = options.scheduleFlush ?? defaultScheduleFlush;
  }

  append(input: OperationAuditInput): Promise<OperationAuditAppendReceipt> {
    if (this.closing || this.closed) return Promise.reject(new Error("Operation audit sink is closed."));
    if (this.permanentFailure) return Promise.reject(this.permanentFailure);
    const event = operationAuditEvent(input, this.now);
    const receiptDigest = input.receiptDigest === undefined
      ? undefined
      : requiredDigest(input.receiptDigest, "receiptDigest");
    const promise = new Promise<OperationAuditAppendReceipt>((resolvePromise, rejectPromise) => {
      this.pending.push({ event, receiptDigest, resolve: resolvePromise, reject: rejectPromise });
    });
    if (this.pending.length >= this.maximumBatchSize) {
      this.cancelFlushTimer();
      void this.flush().catch(() => undefined);
    } else if (!this.cancelScheduledFlush) {
      this.cancelScheduledFlush = this.scheduleFlush(() => {
        this.cancelScheduledFlush = undefined;
        void this.flush().catch(() => undefined);
      }, this.flushIntervalMs);
    }
    return promise;
  }

  async record(input: OperationAuditInput): Promise<OperationAuditRecordResult> {
    try {
      return { status: "RECORDED", ...await this.append(input) };
    } catch (error) {
      return { status: "SINK_FAILED", error: bounded(errorMessage(error), 2_000) };
    }
  }

  stats(): OperationAuditSinkStats {
    return {
      pending: this.pending.length + this.inFlight,
      initialized: this.initialized,
      failed: this.permanentFailure !== undefined,
    };
  }

  flush(): Promise<void> {
    const run = this.flushTail
      .catch(() => undefined)
      .then(() => this.flushOnce());
    this.flushTail = run;
    return run;
  }

  async close(): Promise<void> {
    if (this.closed) return;
    this.closing = true;
    this.cancelFlushTimer();
    try {
      while (this.pending.length > 0) await this.flush();
      await this.flushTail;
    } finally {
      this.closed = true;
    }
  }

  private cancelFlushTimer(): void {
    this.cancelScheduledFlush?.();
    this.cancelScheduledFlush = undefined;
  }

  private async flushOnce(): Promise<void> {
    if (this.permanentFailure) throw this.permanentFailure;
    if (this.pending.length === 0) return;
    const batch = this.pending.splice(0, this.maximumBatchSize);
    this.inFlight += batch.length;
    try {
      await this.initialize();
      let sequence = this.sequence;
      let previousEventDigest = this.previousEventDigest;
      const records: StoredOperationAuditEvent[] = batch.map((pending) => {
        sequence += 1;
        const unsigned = {
          schemaVersion: 1 as const,
          sequence,
          ...(previousEventDigest ? { previousEventDigest } : {}),
          ...pending.event,
          ...(pending.receiptDigest ? { receiptDigest: pending.receiptDigest } : {}),
        };
        const eventDigest = digestCanonical(unsigned);
        previousEventDigest = eventDigest;
        return { ...unsigned, eventDigest };
      });
      await appendOwnerOnlyBatch(this.path, records.map((record) => JSON.stringify(record)).join("\n") + "\n");
      this.sequence = sequence;
      this.previousEventDigest = previousEventDigest;
      for (const [index, pending] of batch.entries()) {
        const record = records[index]!;
        pending.resolve({
          sequence: record.sequence,
          eventDigest: record.eventDigest,
          ...(record.receiptDigest ? { receiptDigest: record.receiptDigest } : {}),
        });
      }
    } catch (error) {
      const failure = error instanceof Error ? error : new Error(String(error));
      this.permanentFailure = failure;
      for (const pending of batch) pending.reject(failure);
      for (const pending of this.pending.splice(0)) pending.reject(failure);
      throw failure;
    } finally {
      this.inFlight -= batch.length;
    }
  }

  private async initialize(): Promise<void> {
    if (this.initialized) return;
    await mkdir(dirname(this.path), { recursive: true, mode: 0o700 });
    await chmod(dirname(this.path), 0o700);
    let text = "";
    try {
      const metadata = await lstat(this.path);
      if (metadata.isSymbolicLink() || !metadata.isFile()) {
        throw new Error("Operation audit path must be an owner-only regular file, not a directory or symlink.");
      }
      await chmod(this.path, 0o600);
      text = await readFile(this.path, "utf8");
    } catch (error) {
      if (!isNodeError(error, "ENOENT")) throw error;
    }
    if (text && !text.endsWith("\n")) {
      throw new Error("Operation audit sink has an incomplete trailing record.");
    }
    let sequence = 0;
    let previousEventDigest: string | undefined;
    for (const line of text.split("\n")) {
      if (!line) continue;
      const record = JSON.parse(line) as StoredOperationAuditEvent;
      verifyStoredRecord(record, sequence + 1, previousEventDigest);
      sequence = record.sequence;
      previousEventDigest = record.eventDigest;
    }
    this.sequence = sequence;
    this.previousEventDigest = previousEventDigest;
    this.initialized = true;
  }
}

export function digestAuditIdentity(value: string): string {
  return `sha256:${createHash("sha256").update(value).digest("hex")}`;
}

function operationAuditEvent(
  input: OperationAuditInput,
  now: () => number,
): OperationAuditEvent {
  const principal = input.principalFingerprint.trim().toLowerCase();
  if (!PRINCIPAL_PATTERN.test(principal)) {
    throw new Error("principalFingerprint must be a SHA-256 fingerprint.");
  }
  const timestamp = input.timestamp ?? new Date(now()).toISOString();
  if (!Number.isFinite(Date.parse(timestamp))) throw new Error("Audit timestamp is invalid.");
  return {
    timestamp,
    operationId: safeIdentifier(input.operationId, "operationId"),
    correlationId: safeIdentifier(input.correlationId, "correlationId"),
    principalFingerprintPrefix: principal.slice(0, 12),
    ...(input.taskInstanceId ? { taskInstanceDigest: digestAuditIdentity(input.taskInstanceId) } : {}),
    ...(input.authorityId ? { authorityIdDigest: digestAuditIdentity(input.authorityId) } : {}),
    ...(input.action !== undefined ? { actionDigest: digestCanonical(input.action) } : {}),
    ...(input.resourceKey ? { resourceKeyDigest: digestAuditIdentity(input.resourceKey) } : {}),
    ...(input.targetId ? { targetId: safeIdentifier(input.targetId, "targetId") } : {}),
    ...(input.targetGeneration
      ? { targetGeneration: requiredDigest(input.targetGeneration, "targetGeneration") }
      : {}),
    ...(input.routeId ? { routeId: safeIdentifier(input.routeId, "routeId") } : {}),
    ...(input.routeGeneration
      ? { routeGeneration: requiredDigest(input.routeGeneration, "routeGeneration") }
      : {}),
    tool: safeIdentifier(input.tool, "tool"),
    operation: safeIdentifier(input.operation, "operation"),
    risk: safeIdentifier(input.risk, "risk"),
    ...(input.claimState ? { claimState: safeIdentifier(input.claimState, "claimState") } : {}),
    dispatchState: safeIdentifier(input.dispatchState, "dispatchState"),
    result: safeIdentifier(input.result, "result"),
    ...(input.errorCode ? { errorCode: safeIdentifier(input.errorCode, "errorCode") } : {}),
  };
}

async function appendOwnerOnlyBatch(path: string, content: string): Promise<void> {
  const noFollow = typeof constants.O_NOFOLLOW === "number" ? constants.O_NOFOLLOW : 0;
  const file = await open(
    path,
    constants.O_APPEND | constants.O_CREAT | constants.O_WRONLY | noFollow,
    0o600,
  );
  try {
    await file.writeFile(content, "utf8");
    await file.sync();
    await file.chmod(0o600);
  } finally {
    await file.close();
  }
  const directory = await open(dirname(path), "r");
  try {
    await directory.sync();
  } finally {
    await directory.close();
  }
}

function verifyStoredRecord(
  record: StoredOperationAuditEvent,
  expectedSequence: number,
  expectedPrevious: string | undefined,
): void {
  if (record.schemaVersion !== 1 || record.sequence !== expectedSequence) {
    throw new Error(`Operation audit sequence is invalid at ${expectedSequence}.`);
  }
  if (record.previousEventDigest !== expectedPrevious) {
    throw new Error(`Operation audit chain is invalid at ${expectedSequence}.`);
  }
  const { eventDigest, ...unsigned } = record;
  if (!SHA256_PATTERN.test(eventDigest) || digestCanonical(unsigned) !== eventDigest) {
    throw new Error(`Operation audit digest is invalid at ${expectedSequence}.`);
  }
}

function digestCanonical(value: unknown): string {
  return `sha256:${createHash("sha256").update(canonicalJson(value)).digest("hex")}`;
}

function canonicalJson(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  if (value && typeof value === "object") {
    return `{${Object.entries(value as Record<string, unknown>)
      .filter(([, child]) => child !== undefined)
      .sort(([left], [right]) => left < right ? -1 : left > right ? 1 : 0)
      .map(([key, child]) => `${JSON.stringify(key)}:${canonicalJson(child)}`)
      .join(",")}}`;
  }
  return JSON.stringify(value) ?? "null";
}

function requiredDigest(value: string, field: string): string {
  const normalized = value.trim().toLowerCase();
  if (!SHA256_PATTERN.test(normalized)) throw new Error(`${field} must be a SHA-256 digest.`);
  return normalized;
}

function safeIdentifier(value: string, field: string): string {
  const normalized = value.trim();
  if (!SAFE_IDENTIFIER_PATTERN.test(normalized)) {
    throw new Error(`${field} is missing or contains unsafe characters.`);
  }
  return normalized;
}

function boundedInteger(
  value: number | undefined,
  fallback: number,
  minimum: number,
  maximum: number,
  field: string,
): number {
  const parsed = value ?? fallback;
  if (!Number.isInteger(parsed) || parsed < minimum || parsed > maximum) {
    throw new Error(`${field} must be an integer from ${minimum} through ${maximum}.`);
  }
  return parsed;
}

function defaultScheduleFlush(callback: () => void, delayMs: number): () => void {
  if (delayMs === 0) {
    let active = true;
    queueMicrotask(() => {
      if (active) callback();
    });
    return () => { active = false; };
  }
  const timer = setTimeout(callback, delayMs);
  return () => clearTimeout(timer);
}

function bounded(value: string, maximum: number): string {
  const normalized = value.replace(/[\r\n\0]+/gu, " ").trim();
  return normalized.length <= maximum ? normalized : `${normalized.slice(0, maximum)}…`;
}

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

function isNodeError(error: unknown, code: string): boolean {
  return Boolean(error && typeof error === "object" && "code" in error && error.code === code);
}
