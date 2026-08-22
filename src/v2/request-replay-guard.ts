import { createHash } from "node:crypto";
import { UniversalBrokerError } from "./errors.js";

export interface ToolRequestReplayIdentity {
  principalFingerprint: string;
  scopes: readonly string[];
  requestNamespace: string;
  requestId: string | number;
  tool: string;
  arguments: unknown;
  meta?: unknown;
}

export type ToolRequestReplayDisposition = "EXECUTED" | "COALESCED" | "REPLAYED";

export interface ToolRequestReplayResult<T> {
  value: T;
  disposition: ToolRequestReplayDisposition;
}

export interface ToolRequestReplayGuardOptions {
  maximumEntries?: number;
  terminalTtlMs?: number;
  unknownTtlMs?: number;
  now?: () => number;
}

export interface ToolRequestReplayGuardStats {
  entries: number;
  inFlight: number;
  executed: number;
  coalesced: number;
  replayed: number;
  conflicts: number;
  evicted: number;
}

interface ReplayEntry<T> {
  requestDigest: string;
  createdAt: number;
  expiresAt: number;
  promise?: Promise<T>;
  value?: T;
}

const DEFAULT_MAXIMUM_ENTRIES = 1_024;
const DEFAULT_TERMINAL_TTL_MS = 30_000;
const DEFAULT_UNKNOWN_TTL_MS = 10 * 60_000;

/**
 * Bounded, process-local replay protection for one logical MCP tool request arriving through
 * both stateful and stateless HTTP transports. OAuth authentication and scope validation still
 * run on every HTTP request; this guard only coalesces the provider dispatch/result boundary.
 */
export class UniversalToolRequestReplayGuard {
  private readonly maximumEntries: number;
  private readonly terminalTtlMs: number;
  private readonly unknownTtlMs: number;
  private readonly now: () => number;
  private readonly entries = new Map<string, ReplayEntry<unknown>>();
  private executed = 0;
  private coalesced = 0;
  private replayed = 0;
  private conflicts = 0;
  private evicted = 0;

  constructor(options: ToolRequestReplayGuardOptions = {}) {
    this.maximumEntries = boundedInteger(
      options.maximumEntries,
      DEFAULT_MAXIMUM_ENTRIES,
      1,
      100_000,
      "maximumEntries",
    );
    this.terminalTtlMs = boundedInteger(
      options.terminalTtlMs,
      DEFAULT_TERMINAL_TTL_MS,
      1,
      60 * 60_000,
      "terminalTtlMs",
    );
    this.unknownTtlMs = boundedInteger(
      options.unknownTtlMs,
      DEFAULT_UNKNOWN_TTL_MS,
      this.terminalTtlMs,
      24 * 60 * 60_000,
      "unknownTtlMs",
    );
    this.now = options.now ?? Date.now;
  }

  async execute<T>(
    identity: ToolRequestReplayIdentity,
    dispatch: () => Promise<T>,
    isUnknown: (value: T) => boolean = () => false,
  ): Promise<ToolRequestReplayResult<T>> {
    const now = this.now();
    this.cleanupExpired(now);
    const key = replayKey(identity);
    const requestDigest = replayRequestDigest(identity);
    const existing = this.entries.get(key) as ReplayEntry<T> | undefined;
    if (existing) {
      if (existing.requestDigest !== requestDigest) {
        this.conflicts += 1;
        throw new UniversalBrokerError(
          "PRECONDITION_FAILED",
          existing.promise
            ? "The JSON-RPC request identifier is already in flight with different tool arguments."
            : "The JSON-RPC request identifier was recently used with different tool arguments.",
          {
            evidence: {
              providerDispatchCount: 0,
              requestIdDigest: digestCanonical(identity.requestId),
              existingRequestDigest: existing.requestDigest,
              receivedRequestDigest: requestDigest,
            },
          },
        );
      } else if (existing.promise) {
        this.coalesced += 1;
        return {
          value: clone(await existing.promise),
          disposition: "COALESCED",
        };
      } else if (existing.value !== undefined && existing.expiresAt > now) {
        this.replayed += 1;
        return {
          value: clone(existing.value),
          disposition: "REPLAYED",
        };
      } else {
        this.entries.delete(key);
      }
    }

    this.ensureCapacity(now);
    const entry: ReplayEntry<T> = {
      requestDigest,
      createdAt: now,
      expiresAt: Number.POSITIVE_INFINITY,
    };
    const promise = Promise.resolve()
      .then(dispatch)
      .then((value) => {
        entry.value = clone(value);
        entry.promise = undefined;
        entry.expiresAt = this.now() + (isUnknown(value) ? this.unknownTtlMs : this.terminalTtlMs);
        return value;
      })
      .catch((error) => {
        if (this.entries.get(key) === entry) this.entries.delete(key);
        throw error;
      });
    entry.promise = promise;
    this.entries.set(key, entry as ReplayEntry<unknown>);
    this.executed += 1;
    return {
      value: clone(await promise),
      disposition: "EXECUTED",
    };
  }

  stats(): ToolRequestReplayGuardStats {
    this.cleanupExpired(this.now());
    return {
      entries: this.entries.size,
      inFlight: [...this.entries.values()].filter((entry) => entry.promise !== undefined).length,
      executed: this.executed,
      coalesced: this.coalesced,
      replayed: this.replayed,
      conflicts: this.conflicts,
      evicted: this.evicted,
    };
  }

  private cleanupExpired(now: number): void {
    for (const [key, entry] of this.entries) {
      if (!entry.promise && entry.expiresAt <= now) this.entries.delete(key);
    }
  }

  private ensureCapacity(now: number): void {
    this.cleanupExpired(now);
    while (this.entries.size >= this.maximumEntries) {
      const terminal = [...this.entries.entries()].find(([, entry]) => !entry.promise);
      if (!terminal) {
        throw new UniversalBrokerError(
          "RESOURCE_QUOTA_EXCEEDED",
          "The bounded MCP request replay guard is full of in-flight operations.",
          { evidence: { providerDispatchCount: 0, maximumEntries: this.maximumEntries } },
        );
      }
      this.entries.delete(terminal[0]);
      this.evicted += 1;
    }
  }
}

function replayKey(identity: ToolRequestReplayIdentity): string {
  return digestCanonical({
    principalFingerprint: identity.principalFingerprint,
    scopes: [...new Set(identity.scopes)].sort(),
    requestNamespace: identity.requestNamespace,
    requestId: identity.requestId,
  });
}

function replayRequestDigest(identity: ToolRequestReplayIdentity): string {
  return digestCanonical({
    tool: identity.tool,
    arguments: identity.arguments,
    ...(identity.meta === undefined ? {} : { meta: identity.meta }),
  });
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

function clone<T>(value: T): T {
  try {
    return structuredClone(value);
  } catch {
    // MCP tool results are JSON-compatible, but replay protection must never turn a completed
    // provider dispatch into a synthetic failure if a future extension adds a non-cloneable field.
    return value;
  }
}

function boundedInteger(
  value: number | undefined,
  fallback: number,
  minimum: number,
  maximum: number,
  field: string,
): number {
  const resolved = value ?? fallback;
  if (!Number.isInteger(resolved) || resolved < minimum || resolved > maximum) {
    throw new Error(`${field} must be an integer from ${minimum} through ${maximum}.`);
  }
  return resolved;
}
