import { createHash, randomUUID } from "node:crypto";
import {
  createCapabilityCallContextFromTrustedPrincipal,
  requireCapabilityCallContext,
  type CapabilityCallContext,
  type CapabilityCallContextProvider,
} from "./capability-call-context.js";
import { UniversalBrokerError } from "./errors.js";
import { SynchronousQuotaReservations } from "./quota-reservations.js";
import {
  RESOURCE_DEFAULT_MCP_CONNECTIONS,
  RESOURCE_DEFAULT_MCP_IDLE_TTL_MS,
} from "./resource-defaults.js";

interface ResultRecord {
  id: string;
  routeId: string;
  principalKeyFingerprint: string;
  serialized: string;
  createdAt: number;
  expiresAt: number;
  lastUsedAt: number;
}

export interface UniversalMcpResultStoreOptions {
  maximumEntries?: number;
  maximumTotalCharacters?: number;
  ttlMs?: number;
  now?: () => number;
  ownerProvider?: CapabilityCallContextProvider;
  compatibilityAuthority?: string;
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
  private readonly maximumTotalCharacters: number;
  private readonly ttlMs: number;
  private readonly now: () => number;
  private readonly ownerProvider: CapabilityCallContextProvider;
  private readonly reservations: SynchronousQuotaReservations;
  private totalCharacters = 0;

  constructor(options: UniversalMcpResultStoreOptions = {}) {
    this.maximumEntries = boundedInteger(
      options.maximumEntries,
      RESOURCE_DEFAULT_MCP_CONNECTIONS,
      1,
      10_000,
    );
    this.maximumTotalCharacters = boundedInteger(
      options.maximumTotalCharacters,
      10_000_000,
      1_000,
      1_000_000_000,
    );
    this.ttlMs = boundedInteger(
      options.ttlMs,
      RESOURCE_DEFAULT_MCP_IDLE_TTL_MS,
      1_000,
      86_400_000,
    );
    this.now = options.now ?? Date.now;
    const compatibilityOwner = createCapabilityCallContextFromTrustedPrincipal({
      principalKeyFingerprint: createHash("sha256")
        .update(options.compatibilityAuthority ?? "legacy-single-owner-mcp-result-store")
        .digest("hex"),
    });
    this.ownerProvider = options.ownerProvider ?? (() => compatibilityOwner);
    this.reservations = new SynchronousQuotaReservations("mcp-result", {
      entries: this.maximumEntries,
      characters: this.maximumTotalCharacters,
    });
  }

  put(
    value: unknown,
    routeId = "legacy",
    callContext?: CapabilityCallContext,
  ): {
    resultId: string;
    resourceUri: string;
    characters: number;
    expiresAt: string;
  } {
    const owner = this.owner(callContext);
    const canonicalRouteId = requireRouteId(routeId);
    const serialized = JSON.stringify(value) ?? "null";
    this.pruneExpired();
    const reservation = this.reservations.reserve(
      { entries: this.records.size, characters: this.totalCharacters },
      { entries: 1, characters: serialized.length },
    );
    try {
      const now = this.now();
      const id = randomUUID();
      const record: ResultRecord = {
        id,
        routeId: canonicalRouteId,
        principalKeyFingerprint: owner.principalKeyFingerprint,
        serialized,
        createdAt: now,
        expiresAt: now + this.ttlMs,
        lastUsedAt: now,
      };
      reservation.commit(() => {
        this.records.set(id, record);
        this.totalCharacters += serialized.length;
      });
      return {
        resultId: id,
        resourceUri: resultUri(canonicalRouteId, id, 0, 12_000),
        characters: serialized.length,
        expiresAt: new Date(record.expiresAt).toISOString(),
      };
    } finally {
      reservation.release();
    }
  }

  readByUri(uri: string, callContext?: CapabilityCallContext): Record<string, unknown> {
    const parsed = parseResultUri(uri);
    return this.read(parsed.id, parsed.offset, parsed.limit, uri, callContext, parsed.routeId);
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
    const canonicalUri = uri ?? resultUri(record.routeId, id, offset, limit);
    return {
      uri: canonicalUri,
      mimeType: "application/json",
      routeId: record.routeId,
      text,
      offset,
      charactersRead: text.length,
      totalCharacters: record.serialized.length,
      truncated: nextOffset < record.serialized.length,
      ...(nextOffset < record.serialized.length ? {
        nextOffset,
        nextResourceUri: resultUri(record.routeId, id, nextOffset, limit),
      } : {}),
      expiresAt: new Date(record.expiresAt).toISOString(),
    };
  }

  clear(): void {
    this.records.clear();
    this.totalCharacters = 0;
  }

  stats(): { entries: number; totalCharacters: number } {
    this.pruneExpired();
    return { entries: this.records.size, totalCharacters: this.totalCharacters };
  }

  private owner(callContext?: CapabilityCallContext): CapabilityCallContext {
    return requireCapabilityCallContext(callContext, this.ownerProvider);
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
    this.totalCharacters -= record.serialized.length;
  }
}

export function parseResultUri(uri: string): ParsedMcpResultUri {
  let parsed: URL;
  try {
    parsed = new URL(uri);
  } catch {
    throw new UniversalBrokerError("PRECONDITION_FAILED", `Invalid MCP result URI: ${uri}`);
  }
  if (parsed.protocol !== "devspace:") {
    throw new UniversalBrokerError("PRECONDITION_FAILED", `Not an MCP result URI: ${uri}`);
  }
  const parts = parsed.pathname.replace(/^\/+/, "").split("/");
  if (parsed.hostname === "mcp-result") {
    const [id, rawOffset = "0", rawLimit = "12000"] = parts;
    return parsedParts(uri, id, rawOffset, rawLimit, undefined, true);
  }
  if (parsed.hostname === "mcp" && parts[1] === "result") {
    const [rawRouteId, _result, id, rawOffset = "0", rawLimit = "12000"] = parts;
    return parsedParts(uri, id, rawOffset, rawLimit, decodeURIComponent(rawRouteId ?? ""), false);
  }
  throw new UniversalBrokerError("PRECONDITION_FAILED", `Not an MCP result URI: ${uri}`);
}

function parsedParts(
  uri: string,
  id: string | undefined,
  rawOffset: string,
  rawLimit: string,
  routeId: string | undefined,
  legacy: boolean,
): ParsedMcpResultUri {
  if (!id) throw new UniversalBrokerError("PRECONDITION_FAILED", `Missing result ID: ${uri}`);
  if (!legacy) requireRouteId(routeId ?? "");
  const offset = Number(rawOffset);
  const limit = Number(rawLimit);
  if (!Number.isSafeInteger(offset) || offset < 0) {
    throw new UniversalBrokerError("PRECONDITION_FAILED", `Invalid result offset: ${uri}`);
  }
  return {
    id,
    ...(routeId === undefined ? {} : { routeId }),
    offset,
    limit: boundedInteger(limit, 12_000, 1, 100_000),
    legacy,
  };
}

function resultUri(routeId: string, id: string, offset: number, limit: number): string {
  return `devspace://mcp/${encodeURIComponent(routeId)}/result/${encodeURIComponent(id)}/${offset}/${limit}`;
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
