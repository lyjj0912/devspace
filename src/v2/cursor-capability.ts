import {
  createHash,
  createHmac,
  randomBytes,
  randomUUID,
  timingSafeEqual,
} from "node:crypto";
import type { UniversalBrokerMetrics } from "./metrics.js";

export type CursorFailureReason =
  | "CURSOR_INVALID"
  | "CURSOR_EXPIRED"
  | "CURSOR_STALE"
  | "CURSOR_QUOTA_EXCEEDED";

export interface CursorBinding {
  principalKeyFingerprint: string;
  resourceKind: string;
  resourceIdentityDigest: string;
  queryDigest: string;
  snapshotGeneration: string;
}

export interface CursorSigningKey {
  keyId: string;
  secret: Uint8Array;
}

export interface CursorPayload extends CursorBinding {
  version: 1;
  keyId: string;
  snapshotId: string;
  snapshotDigest: string;
  offset: number;
  limit: number;
  issuedAt: string;
  expiresAt: string;
  nonce: string;
}

export interface SnapshotPage {
  snapshotId: string;
  snapshotDigest: string;
  itemIdentities: readonly string[];
  nextCursor?: string;
  expiresAt: string;
}

export interface SignedSnapshotCursorStoreOptions {
  currentKey: CursorSigningKey;
  previousKey?: CursorSigningKey;
  ttlMs: number;
  maximumSnapshotsPerPrincipal: number;
  now?: () => number;
  metrics?: UniversalBrokerMetrics;
}

interface SnapshotRecord extends CursorBinding {
  snapshotId: string;
  snapshotDigest: string;
  itemIdentities: readonly string[];
  issuedAtMs: number;
  expiresAtMs: number;
}

export class CursorCapabilityError extends Error {
  readonly code = "CURSOR_CAPABILITY_ERROR";

  constructor(
    readonly reason: CursorFailureReason,
    message: string,
    readonly evidence: Readonly<Record<string, unknown>> = {},
  ) {
    super(message);
    this.name = "CursorCapabilityError";
  }
}

export function cursorFailure(error: unknown): {
  reason: CursorFailureReason;
  retryable: false;
  evidence: Readonly<Record<string, unknown>>;
} | undefined {
  if (!(error instanceof CursorCapabilityError)) return undefined;
  return { reason: error.reason, retryable: false, evidence: error.evidence };
}

/**
 * Ephemeral ordered-snapshot store with authenticated, owner-bound continuation
 * capabilities. Signing keys may survive a restart; snapshots deliberately do
 * not need to, so a valid pre-restart cursor deterministically becomes stale.
 */
export class SignedSnapshotCursorStore {
  private readonly currentKey: CursorSigningKey;
  private readonly previousKey?: CursorSigningKey;
  private readonly ttlMs: number;
  private readonly maximumSnapshotsPerPrincipal: number;
  private readonly now: () => number;
  private readonly metrics?: UniversalBrokerMetrics;
  private readonly snapshots = new Map<string, SnapshotRecord>();

  constructor(options: SignedSnapshotCursorStoreOptions) {
    this.currentKey = validateSigningKey(options.currentKey, "currentKey");
    this.previousKey = options.previousKey
      ? validateSigningKey(options.previousKey, "previousKey")
      : undefined;
    if (this.previousKey?.keyId === this.currentKey.keyId) {
      throw new TypeError("Cursor current and previous key IDs must differ.");
    }
    this.ttlMs = positiveSafeInteger(options.ttlMs, "ttlMs");
    this.maximumSnapshotsPerPrincipal = positiveSafeInteger(
      options.maximumSnapshotsPerPrincipal,
      "maximumSnapshotsPerPrincipal",
    );
    this.now = options.now ?? Date.now;
    this.metrics = options.metrics;
  }

  createSnapshot(input: {
    binding: CursorBinding;
    orderedItemIdentities: readonly string[];
    limit: number;
  }): SnapshotPage {
    const binding = validateBinding(input.binding);
    const limit = positiveSafeInteger(input.limit, "limit");
    const now = this.checkedNow();
    this.pruneExpired(now);
    const identities = Object.freeze(input.orderedItemIdentities.map((identity) => {
      if (typeof identity !== "string" || identity.length === 0) {
        throw new TypeError("Snapshot item identities must be non-empty strings.");
      }
      return identity;
    }));
    const snapshotId = randomUUID();
    const snapshotDigest = sha256(canonicalStringArray(identities));
    const expiresAtMs = now + this.ttlMs;
    const record: SnapshotRecord = Object.freeze({
      ...binding,
      snapshotId,
      snapshotDigest,
      itemIdentities: identities,
      issuedAtMs: now,
      expiresAtMs,
    });

    if (identities.length > limit) {
      const liveForPrincipal = [...this.snapshots.values()].filter(
        (snapshot) => snapshot.principalKeyFingerprint === binding.principalKeyFingerprint,
      ).length;
      if (liveForPrincipal >= this.maximumSnapshotsPerPrincipal) {
        this.recordCursorEvent(binding.resourceKind, "rejected");
        this.recordQuotaRejection();
        throw new CursorCapabilityError(
          "CURSOR_QUOTA_EXCEEDED",
          "Pagination snapshot quota is full; live snapshots are never evicted.",
          {
            resourceKind: binding.resourceKind,
            maximumSnapshotsPerPrincipal: this.maximumSnapshotsPerPrincipal,
          },
        );
      }
      this.snapshots.set(snapshotId, record);
    }
    const page = this.page(record, 0, limit);
    if (page.nextCursor) this.recordCursorEvent(binding.resourceKind, "issued");
    return page;
  }

  continueSnapshot(input: {
    cursor: string;
    binding: CursorBinding;
    limit?: number;
  }): SnapshotPage {
    let resourceKind = input.binding.resourceKind;
    try {
      const binding = validateBinding(input.binding);
      resourceKind = binding.resourceKind;
      const payload = this.decodeAndVerify(input.cursor);
      resourceKind = payload.resourceKind;
      assertPayloadBinding(payload, binding);
      const now = this.checkedNow();
      const expiresAtMs = Date.parse(payload.expiresAt);
      if (!Number.isFinite(expiresAtMs) || expiresAtMs <= now) {
        this.snapshots.delete(payload.snapshotId);
        throw new CursorCapabilityError("CURSOR_EXPIRED", "Pagination cursor has expired.", {
          resourceKind: payload.resourceKind,
        });
      }
      const requestedLimit = input.limit === undefined
        ? payload.limit
        : positiveSafeInteger(input.limit, "limit");
      if (requestedLimit > payload.limit) {
        throw new CursorCapabilityError(
          "CURSOR_INVALID",
          "Pagination limit cannot exceed the cursor-bound limit.",
          { resourceKind: payload.resourceKind, cursorLimit: payload.limit },
        );
      }
      const snapshot = this.snapshots.get(payload.snapshotId);
      if (!snapshot) {
        throw new CursorCapabilityError("CURSOR_STALE", "Pagination snapshot is no longer available.", {
          resourceKind: payload.resourceKind,
        });
      }
      if (
        snapshot.snapshotDigest !== payload.snapshotDigest
        || snapshot.snapshotGeneration !== payload.snapshotGeneration
        || snapshot.expiresAtMs !== expiresAtMs
      ) {
        throw new CursorCapabilityError("CURSOR_STALE", "Pagination snapshot generation changed.", {
          resourceKind: payload.resourceKind,
        });
      }
      if (payload.offset > snapshot.itemIdentities.length) {
        throw new CursorCapabilityError("CURSOR_INVALID", "Pagination offset is outside the snapshot.", {
          resourceKind: payload.resourceKind,
        });
      }
      const page = this.page(snapshot, payload.offset, requestedLimit);
      this.recordCursorEvent(resourceKind, "accepted");
      if (page.nextCursor) this.recordCursorEvent(resourceKind, "issued");
      return page;
    } catch (error) {
      const failure = cursorFailure(error);
      this.recordCursorEvent(
        resourceKind,
        failure?.reason === "CURSOR_EXPIRED"
          ? "expired"
          : failure?.reason === "CURSOR_STALE"
            ? "stale"
            : "rejected",
      );
      throw error;
    }
  }

  private recordCursorEvent(resourceKind: string, result: string): void {
    try {
      this.metrics?.recordCursorEvent(resourceKind, result);
    } catch {
      // Observability must never replace the cursor contract result.
    }
  }

  private recordQuotaRejection(): void {
    try {
      this.metrics?.recordQuotaRejection("cursor");
    } catch {
      // Observability must never replace the cursor quota result.
    }
  }

  private page(snapshot: SnapshotRecord, offset: number, limit: number): SnapshotPage {
    const end = Math.min(offset + limit, snapshot.itemIdentities.length);
    const itemIdentities = Object.freeze(snapshot.itemIdentities.slice(offset, end));
    return {
      snapshotId: snapshot.snapshotId,
      snapshotDigest: snapshot.snapshotDigest,
      itemIdentities,
      ...(end < snapshot.itemIdentities.length
        ? { nextCursor: this.encode(snapshot, end, limit) }
        : {}),
      expiresAt: new Date(snapshot.expiresAtMs).toISOString(),
    };
  }

  private encode(snapshot: SnapshotRecord, offset: number, limit: number): string {
    const payload: CursorPayload = {
      version: 1,
      keyId: this.currentKey.keyId,
      principalKeyFingerprint: snapshot.principalKeyFingerprint,
      resourceKind: snapshot.resourceKind,
      resourceIdentityDigest: snapshot.resourceIdentityDigest,
      queryDigest: snapshot.queryDigest,
      snapshotId: snapshot.snapshotId,
      snapshotDigest: snapshot.snapshotDigest,
      snapshotGeneration: snapshot.snapshotGeneration,
      offset,
      limit,
      issuedAt: new Date(snapshot.issuedAtMs).toISOString(),
      expiresAt: new Date(snapshot.expiresAtMs).toISOString(),
      nonce: randomBytes(16).toString("base64url"),
    };
    const encodedPayload = Buffer.from(canonicalCursorPayload(payload)).toString("base64url");
    const signature = hmac(this.currentKey.secret, encodedPayload).toString("base64url");
    return `${encodedPayload}.${signature}`;
  }

  private decodeAndVerify(cursor: string): CursorPayload {
    if (typeof cursor !== "string" || cursor.length < 32 || cursor.length > 8_192) {
      throw invalidCursor();
    }
    const segments = cursor.split(".");
    if (segments.length !== 2 || segments.some((segment) => !BASE64URL.test(segment))) {
      throw invalidCursor();
    }
    const [encodedPayload, encodedSignature] = segments as [string, string];
    let rawPayload: Buffer;
    let suppliedSignature: Buffer;
    try {
      rawPayload = Buffer.from(encodedPayload, "base64url");
      suppliedSignature = Buffer.from(encodedSignature, "base64url");
    } catch {
      throw invalidCursor();
    }
    if (
      rawPayload.toString("base64url") !== encodedPayload
      || suppliedSignature.toString("base64url") !== encodedSignature
    ) {
      throw invalidCursor();
    }
    let value: unknown;
    try {
      value = JSON.parse(rawPayload.toString("utf8"));
    } catch {
      throw invalidCursor();
    }
    const payload = validatePayload(value);
    if (canonicalCursorPayload(payload) !== rawPayload.toString("utf8")) throw invalidCursor();
    const key = payload.keyId === this.currentKey.keyId
      ? this.currentKey
      : payload.keyId === this.previousKey?.keyId
        ? this.previousKey
        : undefined;
    if (!key) throw invalidCursor();
    const expected = hmac(key.secret, encodedPayload);
    if (suppliedSignature.length !== expected.length || !timingSafeEqual(suppliedSignature, expected)) {
      throw invalidCursor();
    }
    return payload;
  }

  private pruneExpired(now: number): void {
    for (const [snapshotId, snapshot] of this.snapshots) {
      if (snapshot.expiresAtMs <= now) this.snapshots.delete(snapshotId);
    }
  }

  private checkedNow(): number {
    const value = this.now();
    if (!Number.isSafeInteger(value) || value < 0) throw new TypeError("Cursor clock returned an invalid timestamp.");
    return value;
  }
}

const BASE64URL = /^[A-Za-z0-9_-]+$/u;

function canonicalCursorPayload(payload: CursorPayload): string {
  return JSON.stringify({
    version: payload.version,
    keyId: payload.keyId,
    principalKeyFingerprint: payload.principalKeyFingerprint,
    resourceKind: payload.resourceKind,
    resourceIdentityDigest: payload.resourceIdentityDigest,
    queryDigest: payload.queryDigest,
    snapshotId: payload.snapshotId,
    snapshotDigest: payload.snapshotDigest,
    snapshotGeneration: payload.snapshotGeneration,
    offset: payload.offset,
    limit: payload.limit,
    issuedAt: payload.issuedAt,
    expiresAt: payload.expiresAt,
    nonce: payload.nonce,
  });
}

function canonicalStringArray(values: readonly string[]): string {
  return JSON.stringify(values);
}

function validatePayload(value: unknown): CursorPayload {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw invalidCursor();
  const payload = value as Record<string, unknown>;
  const expectedKeys = [
    "version", "keyId", "principalKeyFingerprint", "resourceKind", "resourceIdentityDigest",
    "queryDigest", "snapshotId", "snapshotDigest", "snapshotGeneration", "offset", "limit",
    "issuedAt", "expiresAt", "nonce",
  ];
  if (Object.keys(payload).length !== expectedKeys.length || expectedKeys.some((key) => !(key in payload))) {
    throw invalidCursor();
  }
  if (payload.version !== 1) throw invalidCursor();
  for (const key of expectedKeys.filter((key) => !["version", "offset", "limit"].includes(key))) {
    if (typeof payload[key] !== "string" || (payload[key] as string).length === 0) throw invalidCursor();
  }
  if (!Number.isSafeInteger(payload.offset) || (payload.offset as number) < 0) throw invalidCursor();
  if (!Number.isSafeInteger(payload.limit) || (payload.limit as number) < 1) throw invalidCursor();
  if (!Number.isFinite(Date.parse(payload.issuedAt as string)) || !Number.isFinite(Date.parse(payload.expiresAt as string))) {
    throw invalidCursor();
  }
  return payload as unknown as CursorPayload;
}

function assertPayloadBinding(payload: CursorPayload, binding: CursorBinding): void {
  if (
    payload.principalKeyFingerprint !== binding.principalKeyFingerprint
    || payload.resourceKind !== binding.resourceKind
    || payload.resourceIdentityDigest !== binding.resourceIdentityDigest
    || payload.queryDigest !== binding.queryDigest
  ) {
    throw new CursorCapabilityError("CURSOR_INVALID", "Pagination cursor binding does not match.", {
      resourceKind: binding.resourceKind,
    });
  }
  if (payload.snapshotGeneration !== binding.snapshotGeneration) {
    throw new CursorCapabilityError("CURSOR_STALE", "Pagination resource generation changed.", {
      resourceKind: binding.resourceKind,
    });
  }
}

function validateBinding(binding: CursorBinding): CursorBinding {
  const copy = { ...binding };
  for (const [key, value] of Object.entries(copy)) {
    if (typeof value !== "string" || value.length === 0 || value.length > 1_024) {
      throw new TypeError(`Cursor binding ${key} must be a bounded non-empty string.`);
    }
  }
  return Object.freeze(copy);
}

function validateSigningKey(key: CursorSigningKey, name: string): CursorSigningKey {
  if (!key || typeof key.keyId !== "string" || !/^[A-Za-z0-9._-]{1,128}$/u.test(key.keyId)) {
    throw new TypeError(`${name}.keyId is invalid.`);
  }
  const secret = Buffer.from(key.secret);
  if (secret.length < 32) throw new TypeError(`${name}.secret must contain at least 32 bytes.`);
  return Object.freeze({ keyId: key.keyId, secret });
}

function positiveSafeInteger(value: number, field: string): number {
  if (!Number.isSafeInteger(value) || value < 1) throw new TypeError(`${field} must be a positive safe integer.`);
  return value;
}

function invalidCursor(): CursorCapabilityError {
  return new CursorCapabilityError("CURSOR_INVALID", "Pagination cursor is invalid.");
}

function sha256(value: string): string {
  return createHash("sha256").update(value).digest("hex");
}

function hmac(secret: Uint8Array, value: string): Buffer {
  return createHmac("sha256", secret).update(value).digest();
}
