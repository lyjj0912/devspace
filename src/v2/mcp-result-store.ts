import { createHash, randomUUID } from "node:crypto";
import {
  createCapabilityCallContextFromTrustedPrincipal,
  requireCapabilityCallContext,
  type CapabilityCallContext,
  type CapabilityCallContextProvider,
} from "./capability-call-context.js";
import { UniversalBrokerError } from "./errors.js";
import type { UniversalBrokerMetrics } from "./metrics.js";
import {
  SynchronousQuotaReservations,
  type QuotaReservation,
} from "./quota-reservations.js";
import {
  RESOURCE_DEFAULT_MCP_CONNECTIONS,
  RESOURCE_DEFAULT_MCP_IDLE_TTL_MS,
  RESOURCE_DEFAULT_MCP_RESULT_MAX_BYTES,
} from "./resource-defaults.js";
import {
  createEphemeralResourceContinuation,
  isResourceContinuationToken,
  SignedResourceContinuation,
} from "./resource-continuation.js";
import { formatResourceUri, parseResourceUri, ResourceUriError } from "./resource-uri.js";

interface ResultRecord {
  id: string;
  generation: string;
  routeId: string;
  principalKeyFingerprint: string;
  serialized: string;
  bytes: number;
  createdAt: number;
  expiresAt: number;
  lastUsedAt: number;
}

export interface UniversalMcpResultStoreOptions {
  maximumEntries?: number;
  maximumTotalBytes?: number;
  ttlMs?: number;
  now?: () => number;
  ownerProvider?: CapabilityCallContextProvider;
  compatibilityAuthority?: string;
  metrics?: UniversalBrokerMetrics;
  continuation?: SignedResourceContinuation;
}

export interface ParsedMcpResultUri {
  id: string;
  routeId?: string;
  offset: number;
  limit: number;
  legacy: boolean;
}

export class UniversalMcpResultStore {
  private readonly records = new Map<string, ResultRecord>();
  private readonly maximumEntries: number;
  private readonly maximumTotalBytes: number;
  private readonly ttlMs: number;
  private readonly now: () => number;
  private readonly continuation: SignedResourceContinuation;
  private readonly ownerProvider: CapabilityCallContextProvider;
  private readonly metrics?: UniversalBrokerMetrics;
  private readonly reservationsByPrincipal = new Map<string, SynchronousQuotaReservations>();
  private readonly usageByPrincipal = new Map<string, { entries: number; bytes: number }>();
  private totalBytes = 0;

  constructor(options: UniversalMcpResultStoreOptions = {}) {
    this.maximumEntries = boundedInteger(
      options.maximumEntries,
      RESOURCE_DEFAULT_MCP_CONNECTIONS,
      1,
      10_000,
    );
    this.maximumTotalBytes = boundedInteger(
      options.maximumTotalBytes,
      RESOURCE_DEFAULT_MCP_RESULT_MAX_BYTES,
      1,
      10 * 1024 * 1024 * 1024,
    );
    this.ttlMs = boundedInteger(
      options.ttlMs,
      RESOURCE_DEFAULT_MCP_IDLE_TTL_MS,
      1_000,
      86_400_000,
    );
    this.now = options.now ?? Date.now;
    this.continuation = options.continuation
      ?? createEphemeralResourceContinuation({ now: this.now });
    const compatibilityOwner = createCapabilityCallContextFromTrustedPrincipal({
      principalKeyFingerprint: createHash("sha256")
        .update(options.compatibilityAuthority ?? "legacy-single-owner-mcp-result-store")
        .digest("hex"),
    });
    this.ownerProvider = options.ownerProvider ?? (() => compatibilityOwner);
    this.metrics = options.metrics;
  }

  put(
    value: unknown,
    routeId = "legacy",
    callContext?: CapabilityCallContext,
  ): {
    resultId: string;
    resourceUri: string;
    characters: number;
    bytes: number;
    expiresAt: string;
  } {
    const owner = this.owner(callContext);
    const canonicalRouteId = requireRouteId(routeId);
    const serialized = JSON.stringify(value) ?? "null";
    const bytes = Buffer.byteLength(serialized, "utf8");
    this.pruneExpired();
    const usage = this.usage(owner.principalKeyFingerprint);
    let reservation: QuotaReservation;
    try {
      reservation = this.reservations(owner.principalKeyFingerprint).reserve(
        usage,
        { entries: 1, bytes },
      );
    } catch (error) {
      this.recordQuotaRejection();
      throw error;
    }
    try {
      const now = this.now();
      const id = randomUUID();
      const record: ResultRecord = {
        id,
        generation: randomUUID(),
        routeId: canonicalRouteId,
        principalKeyFingerprint: owner.principalKeyFingerprint,
        serialized,
        bytes,
        createdAt: now,
        expiresAt: now + this.ttlMs,
        lastUsedAt: now,
      };
      reservation.commit(() => {
        this.records.set(id, record);
        usage.entries += 1;
        usage.bytes += bytes;
        this.totalBytes += bytes;
      });
      return {
        resultId: id,
        resourceUri: resultUri(id),
        characters: serialized.length,
        bytes,
        expiresAt: new Date(record.expiresAt).toISOString(),
      };
    } finally {
      reservation.release();
    }
  }

  readByUri(uri: string, callContext?: CapabilityCallContext): Record<string, unknown> {
    const owner = this.owner(callContext);
    const parsed = parseResultUri(uri);
    if (!parsed.legacy && isResourceContinuationToken(parsed.id)) {
      const verified = this.continuation.verify({
        token: parsed.id,
        principalKeyFingerprint: owner.principalKeyFingerprint,
        resourceKind: "mcp-result",
        resolveResource: (id) => {
          const record = this.records.get(id);
          return record
            ? { generation: record.generation, expiresAtMs: record.expiresAt }
            : undefined;
        },
      });
      return this.read(
        verified.resourceIdentity,
        verified.offset,
        verified.limit,
        uri,
        owner,
      );
    }
    return this.read(
      parsed.id,
      parsed.offset,
      parsed.limit,
      parsed.legacy ? resultUri(parsed.id) : uri,
      owner,
      parsed.routeId,
    );
  }

  read(
    id: string,
    offset = 0,
    maximumCharacters = 12_000,
    uri?: string,
    callContext?: CapabilityCallContext,
    expectedRouteId?: string,
  ): Record<string, unknown> {
    const owner = this.owner(callContext);
    this.pruneExpired();
    const record = this.records.get(id);
    if (!record) {
      throw new UniversalBrokerError(
        "PATH_NOT_FOUND",
        `MCP result resource is unknown or expired: ${id}`,
      );
    }
    this.assertOwner(record, owner);
    if (expectedRouteId !== undefined && expectedRouteId !== record.routeId) {
      throw new UniversalBrokerError(
        "PRECONDITION_FAILED",
        "MCP result URI route does not match the stored route binding.",
        { evidence: { routeId: expectedRouteId, providerDispatchCount: 0 } },
      );
    }
    if (!Number.isSafeInteger(offset) || offset < 0 || offset > record.serialized.length) {
      throw new UniversalBrokerError("PRECONDITION_FAILED", "MCP result offset is invalid.");
    }
    const limit = boundedInteger(maximumCharacters, 12_000, 1, 100_000);
    record.lastUsedAt = this.now();
    const text = record.serialized.slice(offset, offset + limit);
    const nextOffset = offset + text.length;
    const canonicalUri = uri ?? resultUri(id);
    return {
      uri: canonicalUri,
      mimeType: "application/json",
      routeId: record.routeId,
      text,
      offset,
      charactersRead: text.length,
      totalCharacters: record.serialized.length,
      totalBytes: record.bytes,
      truncated: nextOffset < record.serialized.length,
      ...(nextOffset < record.serialized.length ? {
        nextResourceUri: this.continuationUri(record, nextOffset, limit),
      } : {}),
      expiresAt: new Date(record.expiresAt).toISOString(),
    };
  }

  clear(): void {
    this.records.clear();
    this.totalBytes = 0;
    this.usageByPrincipal.clear();
    this.reservationsByPrincipal.clear();
  }

  stats(): { entries: number; totalBytes: number } {
    this.pruneExpired();
    return { entries: this.records.size, totalBytes: this.totalBytes };
  }

  private owner(callContext?: CapabilityCallContext): CapabilityCallContext {
    return requireCapabilityCallContext(callContext, this.ownerProvider);
  }

  private continuationUri(record: ResultRecord, offset: number, limit: number): string {
    const token = this.continuation.issue({
      binding: {
        principalKeyFingerprint: record.principalKeyFingerprint,
        resourceKind: "mcp-result",
        resourceIdentity: record.id,
        resourceGeneration: record.generation,
      },
      offset,
      limit,
      expiresAtMs: record.expiresAt,
    });
    return resultUri(token);
  }

  private assertOwner(record: ResultRecord, owner: CapabilityCallContext): void {
    if (record.principalKeyFingerprint === owner.principalKeyFingerprint) return;
    throw new UniversalBrokerError(
      "AUTHORITY_PRINCIPAL_MISMATCH",
      "MCP result belongs to a different authenticated principal.",
      { evidence: { resultId: record.id, routeId: record.routeId, providerDispatchCount: 0 } },
    );
  }

  private pruneExpired(): void {
    const now = this.now();
    for (const record of this.records.values()) {
      if (record.expiresAt <= now) this.delete(record.id);
    }
  }

  private delete(id: string): void {
    const record = this.records.get(id);
    if (!record) return;
    this.records.delete(id);
    this.totalBytes -= record.bytes;
    const usage = this.usageByPrincipal.get(record.principalKeyFingerprint);
    if (!usage) return;
    usage.entries -= 1;
    usage.bytes -= record.bytes;
    if (usage.entries === 0 && usage.bytes === 0) {
      const reservations = this.reservationsByPrincipal.get(record.principalKeyFingerprint);
      if (!reservations || Object.values(reservations.pending()).every((value) => value === 0)) {
        this.usageByPrincipal.delete(record.principalKeyFingerprint);
        this.reservationsByPrincipal.delete(record.principalKeyFingerprint);
      }
    }
  }

  private usage(principalKeyFingerprint: string): { entries: number; bytes: number } {
    let usage = this.usageByPrincipal.get(principalKeyFingerprint);
    if (!usage) {
      usage = { entries: 0, bytes: 0 };
      this.usageByPrincipal.set(principalKeyFingerprint, usage);
    }
    return usage;
  }

  private reservations(principalKeyFingerprint: string): SynchronousQuotaReservations {
    let reservations = this.reservationsByPrincipal.get(principalKeyFingerprint);
    if (!reservations) {
      reservations = new SynchronousQuotaReservations("mcp-result", {
        entries: this.maximumEntries,
        bytes: this.maximumTotalBytes,
      });
      this.reservationsByPrincipal.set(principalKeyFingerprint, reservations);
    }
    return reservations;
  }

  private recordQuotaRejection(): void {
    try {
      this.metrics?.recordQuotaRejection("mcp_result");
    } catch {
      // Retained-result quota rejection must not be masked by instrumentation failure.
    }
  }
}

export function parseResultUri(uri: string): ParsedMcpResultUri {
  try {
    const parsed = parseResourceUri(uri, { allowLegacyRead: true });
    if (parsed.kind !== "mcp-result") {
      throw new UniversalBrokerError("PRECONDITION_FAILED", `Not an MCP result URI: ${uri}`);
    }
    const legacyRouteId = parsed.legacy ? legacyResultRouteId(uri) : undefined;
    return {
      id: parsed.resultId,
      ...(legacyRouteId === undefined ? {} : { routeId: legacyRouteId }),
      offset: parsed.legacy ? parsed.offset ?? 0 : 0,
      limit: parsed.legacy
        ? boundedInteger(parsed.limit, 12_000, 1, 100_000)
        : 12_000,
      legacy: parsed.legacy,
    };
  } catch (error) {
    if (error instanceof UniversalBrokerError) throw error;
    if (error instanceof ResourceUriError) {
      throw new UniversalBrokerError(
        "PRECONDITION_FAILED",
        `Invalid MCP result URI: ${uri}`,
        { evidence: { reason: error.reason } },
      );
    }
    throw error;
  }
}

function legacyResultRouteId(uri: string): string | undefined {
  const parsed = new URL(uri);
  if (parsed.hostname !== "mcp") return undefined;
  const [routeId, marker] = parsed.pathname.split("/").filter(Boolean);
  if (marker !== "result" || !routeId) return undefined;
  return requireRouteId(decodeURIComponent(routeId));
}

function resultUri(id: string): string {
  return formatResourceUri({ kind: "mcp-result", resultId: id });
}

function requireRouteId(value: string): string {
  const routeId = value.trim();
  if (!routeId || routeId.length > 256 || routeId.includes("\0")) {
    throw new UniversalBrokerError("PRECONDITION_FAILED", "MCP result route ID is invalid.");
  }
  return routeId;
}

function boundedInteger(
  value: number | undefined,
  fallback: number,
  minimum: number,
  maximum: number,
): number {
  const parsed = value ?? fallback;
  if (!Number.isInteger(parsed) || parsed < minimum || parsed > maximum) {
    throw new UniversalBrokerError(
      "PRECONDITION_FAILED",
      `Expected an integer from ${minimum} through ${maximum}.`,
    );
  }
  return parsed;
}
