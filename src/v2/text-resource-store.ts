import { randomUUID } from "node:crypto";
import {
  requireCapabilityCallContext,
  type CapabilityCallContext,
  type CapabilityCallContextProvider,
} from "./capability-call-context.js";
import { UniversalBrokerError } from "./errors.js";
import { SynchronousQuotaReservations } from "./quota-reservations.js";
import { RESOURCE_DEFAULT_CONTEXT_TTL_MS } from "./resource-defaults.js";
import {
  createEphemeralResourceContinuation,
  isResourceContinuationToken,
  SignedResourceContinuation,
} from "./resource-continuation.js";
import { formatResourceUri, parseResourceUri, ResourceUriError } from "./resource-uri.js";

interface TextResourceRecord {
  id: string;
  generation: string;
  text: string;
  mimeType: string;
  createdAt: number;
  expiresAt: number;
  lastUsedAt: number;
  principalKeyFingerprint: string;
}

interface TextResourceTombstone {
  id: string;
  principalKeyFingerprint: string;
  expiredAt: number;
  tombstonedAt: number;
  removeAfter: number;
}

export interface UniversalTextResourceStoreOptions {
  authority: string;
  maximumEntries?: number;
  maximumTotalCharacters?: number;
  ttlMs?: number;
  defaultPageCharacters?: number;
  tombstoneTtlMs?: number;
  ownerProvider?: CapabilityCallContextProvider;
  now?: () => number;
  continuation?: SignedResourceContinuation;
}

export class UniversalTextResourceStore {
  private readonly records = new Map<string, TextResourceRecord>();
  private readonly tombstones = new Map<string, TextResourceTombstone>();
  private readonly authority: string;
  private readonly maximumEntries: number;
  private readonly maximumTotalCharacters: number;
  private readonly ttlMs: number;
  private readonly defaultPageCharacters: number;
  private readonly tombstoneTtlMs: number;
  private readonly ownerProvider?: CapabilityCallContextProvider;
  private readonly now: () => number;
  private readonly continuation: SignedResourceContinuation;
  private readonly reservations: SynchronousQuotaReservations;
  private totalCharacters = 0;

  constructor(options: UniversalTextResourceStoreOptions) {
    this.authority = requireAuthority(options.authority);
    this.maximumEntries = boundedInteger(options.maximumEntries, 64, 1, 10_000);
    this.maximumTotalCharacters = boundedInteger(
      options.maximumTotalCharacters,
      10_000_000,
      1_000,
      1_000_000_000,
    );
    this.ttlMs = boundedInteger(options.ttlMs, 15 * 60_000, 1_000, 86_400_000);
    this.defaultPageCharacters = boundedInteger(
      options.defaultPageCharacters,
      12_000,
      1,
      100_000,
    );
    this.tombstoneTtlMs = boundedInteger(
      options.tombstoneTtlMs,
      RESOURCE_DEFAULT_CONTEXT_TTL_MS,
      1_000,
      7 * 86_400_000,
    );
    this.ownerProvider = options.ownerProvider;
    this.now = options.now ?? Date.now;
    this.continuation = options.continuation
      ?? createEphemeralResourceContinuation({ now: this.now });
    this.reservations = new SynchronousQuotaReservations(this.authority, {
      entries: this.maximumEntries,
      characters: this.maximumTotalCharacters,
    });
  }

  put(
    text: string,
    mimeType = "text/plain",
    callContext?: CapabilityCallContext,
  ): {
    resourceId: string;
    resourceUri: string;
    characters: number;
    expiresAt: string;
  } {
    const owner = this.owner(callContext);
    this.pruneExpired();
    const reservation = this.reservations.reserve(
      { entries: this.records.size, characters: this.totalCharacters },
      { entries: 1, characters: text.length },
    );
    const now = this.now();
    const id = randomUUID();
    const record: TextResourceRecord = {
      id,
      generation: randomUUID(),
      text,
      mimeType,
      createdAt: now,
      expiresAt: now + this.ttlMs,
      lastUsedAt: now,
      principalKeyFingerprint: owner.principalKeyFingerprint,
    };
    reservation.commit(() => {
      this.records.set(id, record);
      this.totalCharacters += text.length;
    });
    return {
      resourceId: id,
      resourceUri: this.uri(id),
      characters: text.length,
      expiresAt: new Date(record.expiresAt).toISOString(),
    };
  }

  readByUri(uri: string, callContext?: CapabilityCallContext): Record<string, unknown> {
    const owner = this.owner(callContext);
    const { id, offset, limit, legacy } = this.parseUri(uri, owner);
    return this.read(id, offset, limit, legacy ? this.uri(id) : uri, owner);
  }

  read(
    id: string,
    offset = 0,
    maximumCharacters = this.defaultPageCharacters,
    uri = this.uri(id),
    callContext?: CapabilityCallContext,
  ): Record<string, unknown> {
    const owner = this.owner(callContext);
    this.pruneExpired();
    const record = this.records.get(id);
    if (!record) {
      const tombstone = this.tombstones.get(id);
      if (tombstone) {
        this.assertOwner(tombstone.principalKeyFingerprint, owner, id);
        throw new UniversalBrokerError(
          "PRECONDITION_FAILED",
          `${this.authority} resource expired: ${id}`,
          {
            evidence: {
              reasonCode: "RESOURCE_EXPIRED",
              resourceId: id,
              expiredAt: new Date(tombstone.expiredAt).toISOString(),
            },
          },
        );
      }
      throw new UniversalBrokerError(
        "PATH_NOT_FOUND",
        `${this.authority} resource is unknown or expired: ${id}`,
      );
    }
    this.assertOwner(record.principalKeyFingerprint, owner, id);
    if (!Number.isSafeInteger(offset) || offset < 0 || offset > record.text.length) {
      throw new UniversalBrokerError("PRECONDITION_FAILED", `${this.authority} offset is invalid.`);
    }
    const limit = boundedInteger(maximumCharacters, this.defaultPageCharacters, 1, 100_000);
    record.lastUsedAt = this.now();
    const text = record.text.slice(offset, offset + limit);
    const nextOffset = offset + text.length;
    return {
      uri,
      mimeType: record.mimeType,
      text,
      offset,
      charactersRead: text.length,
      totalCharacters: record.text.length,
      truncated: nextOffset < record.text.length,
      ...(nextOffset < record.text.length ? {
        nextResourceUri: this.continuationUri(record, nextOffset, limit),
      } : {}),
      expiresAt: new Date(record.expiresAt).toISOString(),
    };
  }

  clear(): void {
    this.records.clear();
    this.tombstones.clear();
    this.totalCharacters = 0;
  }

  stats(): { entries: number; totalCharacters: number; tombstones: number } {
    this.pruneExpired();
    return {
      entries: this.records.size,
      totalCharacters: this.totalCharacters,
      tombstones: this.tombstones.size,
    };
  }

  private uri(id: string): string {
    return formatResourceUri({ kind: "context-diff", diffId: id });
  }

  private continuationUri(record: TextResourceRecord, offset: number, limit: number): string {
    const token = this.continuation.issue({
      binding: {
        principalKeyFingerprint: record.principalKeyFingerprint,
        resourceKind: this.authority,
        resourceIdentity: record.id,
        resourceGeneration: record.generation,
      },
      offset,
      limit,
      expiresAtMs: record.expiresAt,
    });
    return this.uri(token);
  }

  private parseUri(
    uri: string,
    owner: CapabilityCallContext,
  ): { id: string; offset: number; limit: number; legacy: boolean } {
    try {
      const parsed = parseResourceUri(uri, { allowLegacyRead: true });
      if (parsed.kind !== "context-diff") {
        throw new UniversalBrokerError("PRECONDITION_FAILED", `Not a ${this.authority} URI: ${uri}`);
      }
      if (!parsed.legacy && isResourceContinuationToken(parsed.diffId)) {
        const verified = this.continuation.verify({
          token: parsed.diffId,
          principalKeyFingerprint: owner.principalKeyFingerprint,
          resourceKind: this.authority,
          resolveResource: (id) => {
            const record = this.records.get(id);
            return record
              ? { generation: record.generation, expiresAtMs: record.expiresAt }
              : undefined;
          },
        });
        return {
          id: verified.resourceIdentity,
          offset: verified.offset,
          limit: verified.limit,
          legacy: false,
        };
      }
      return {
        id: parsed.diffId,
        offset: parsed.legacy ? parsed.offset ?? 0 : 0,
        limit: parsed.legacy
          ? boundedInteger(parsed.limit, this.defaultPageCharacters, 1, 100_000)
          : this.defaultPageCharacters,
        legacy: parsed.legacy,
      };
    } catch (error) {
      if (error instanceof UniversalBrokerError) throw error;
      if (error instanceof ResourceUriError) {
        throw new UniversalBrokerError(
          "PRECONDITION_FAILED",
          `Invalid ${this.authority} URI: ${uri}`,
          { evidence: { reason: error.reason } },
        );
      }
      throw error;
    }
  }

  private pruneExpired(): void {
    const now = this.now();
    for (const tombstone of this.tombstones.values()) {
      if (tombstone.removeAfter <= now) this.tombstones.delete(tombstone.id);
    }
    for (const record of this.records.values()) {
      if (record.expiresAt <= now) this.expire(record, now);
    }
  }

  private expire(record: TextResourceRecord, now: number): void {
    this.records.delete(record.id);
    this.totalCharacters -= record.text.length;
    this.tombstones.set(record.id, {
      id: record.id,
      principalKeyFingerprint: record.principalKeyFingerprint,
      expiredAt: record.expiresAt,
      tombstonedAt: now,
      removeAfter: now + this.tombstoneTtlMs,
    });
    const maximumTombstones = Math.max(64, this.maximumEntries * 4);
    if (this.tombstones.size > maximumTombstones) {
      const oldest = [...this.tombstones.values()]
        .sort((left, right) => left.tombstonedAt - right.tombstonedAt || left.id.localeCompare(right.id))[0];
      if (oldest) this.tombstones.delete(oldest.id);
    }
  }

  private owner(explicit?: CapabilityCallContext): CapabilityCallContext {
    return requireCapabilityCallContext(explicit, this.ownerProvider);
  }

  private assertOwner(
    expected: string,
    actual: CapabilityCallContext,
    resourceId: string,
  ): void {
    if (expected === actual.principalKeyFingerprint) return;
    throw new UniversalBrokerError(
      "AUTHORITY_PRINCIPAL_MISMATCH",
      `${this.authority} resource belongs to a different stable principal.`,
      { evidence: { reasonCode: "RESOURCE_OWNER_MISMATCH", resourceId } },
    );
  }
}

function requireAuthority(value: string): string {
  if (!/^[a-z][a-z0-9-]{0,63}$/.test(value)) {
    throw new UniversalBrokerError("PRECONDITION_FAILED", `Invalid resource authority: ${value}`);
  }
  return value;
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
