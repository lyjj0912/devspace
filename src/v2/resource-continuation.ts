import {
  createHash,
  createHmac,
  randomBytes,
  timingSafeEqual,
} from "node:crypto";
import { CursorCapabilityError } from "./cursor-capability.js";

export interface ResourceContinuationSigningKey {
  keyId: string;
  secret: Uint8Array;
}

export interface ResourceContinuationBinding {
  principalKeyFingerprint: string;
  resourceKind: string;
  resourceIdentity: string;
  resourceGeneration: string;
}

export interface ResourceContinuationPayload extends ResourceContinuationBinding {
  version: 1;
  keyId: string;
  offset: number;
  limit: number;
  issuedAt: string;
  expiresAt: string;
  nonce: string;
}

export interface ResourceContinuationState {
  generation: string;
  expiresAtMs: number;
}

export interface SignedResourceContinuationOptions {
  currentKey: ResourceContinuationSigningKey;
  previousKey?: ResourceContinuationSigningKey;
  now?: () => number;
}

export interface VerifiedResourceContinuation extends ResourceContinuationPayload {
  expiresAtMs: number;
}

const TOKEN_PREFIX = "rc1";
const MAXIMUM_TOKEN_CHARACTERS = 4_096;
const HMAC_DOMAIN = "devspace-resource-continuation-v1\0";
const BASE64URL = /^[A-Za-z0-9_-]+$/u;
const NONCE = /^[A-Za-z0-9_-]{22}$/u;

/**
 * Stateless HMAC capability for paging one retained resource. Unlike the
 * ordered-list cursor store, immutable resource paging needs no snapshot
 * record: the caller supplies the current resource generation through the
 * resolver and a mismatch becomes a typed stale continuation.
 */
export class SignedResourceContinuation {
  private readonly currentKey: ResourceContinuationSigningKey;
  private readonly previousKey?: ResourceContinuationSigningKey;
  private readonly now: () => number;

  constructor(options: SignedResourceContinuationOptions) {
    this.currentKey = validateSigningKey(options.currentKey, "currentKey");
    this.previousKey = options.previousKey
      ? validateSigningKey(options.previousKey, "previousKey")
      : undefined;
    if (this.previousKey?.keyId === this.currentKey.keyId) {
      throw new TypeError("Resource continuation current and previous key IDs must differ.");
    }
    this.now = options.now ?? Date.now;
  }

  issue(input: {
    binding: ResourceContinuationBinding;
    offset: number;
    limit: number;
    expiresAtMs: number;
  }): string {
    const binding = validateBinding(input.binding);
    const offset = nonnegativeSafeInteger(input.offset, "offset");
    const limit = positiveSafeInteger(input.limit, "limit");
    const now = this.checkedNow();
    const expiresAtMs = positiveSafeInteger(input.expiresAtMs, "expiresAtMs");
    if (expiresAtMs <= now) {
      throw new CursorCapabilityError(
        "CURSOR_EXPIRED",
        "Resource continuation cannot be issued for an expired resource.",
        { resourceKind: binding.resourceKind },
      );
    }
    const payload: ResourceContinuationPayload = {
      version: 1,
      keyId: this.currentKey.keyId,
      ...binding,
      offset,
      limit,
      issuedAt: new Date(now).toISOString(),
      expiresAt: new Date(expiresAtMs).toISOString(),
      nonce: randomBytes(16).toString("base64url"),
    };
    const encodedPayload = Buffer.from(canonicalPayload(payload), "utf8").toString("base64url");
    const signature = hmac(this.currentKey.secret, encodedPayload).toString("base64url");
    const token = `${TOKEN_PREFIX}.${encodedPayload}.${signature}`;
    if (token.length > MAXIMUM_TOKEN_CHARACTERS) {
      throw new TypeError("Resource continuation exceeds the canonical URI component budget.");
    }
    return token;
  }

  verify(input: {
    token: string;
    principalKeyFingerprint: string;
    resourceKind: string;
    expectedResourceIdentity?: string;
    requestedLimit?: number;
    resolveResource: (resourceIdentity: string) => ResourceContinuationState | undefined;
  }): VerifiedResourceContinuation {
    const principalKeyFingerprint = boundedString(
      input.principalKeyFingerprint,
      "principalKeyFingerprint",
      1_024,
    );
    const resourceKind = boundedString(input.resourceKind, "resourceKind", 128);
    if (typeof input.resolveResource !== "function") {
      throw new TypeError("resolveResource must be a function.");
    }
    const payload = this.decodeAndVerify(input.token);
    if (
      payload.principalKeyFingerprint !== principalKeyFingerprint
      || payload.resourceKind !== resourceKind
    ) {
      throw invalidContinuation(resourceKind, "Resource continuation owner or kind does not match.");
    }
    if (
      input.expectedResourceIdentity !== undefined
      && payload.resourceIdentity !== input.expectedResourceIdentity
    ) {
      throw invalidContinuation(resourceKind, "Resource continuation identity does not match.");
    }
    if (
      input.requestedLimit !== undefined
      && (
        !Number.isSafeInteger(input.requestedLimit)
        || input.requestedLimit < 1
        || input.requestedLimit > payload.limit
      )
    ) {
      throw invalidContinuation(resourceKind, "Resource continuation limit cannot be increased.");
    }

    const now = this.checkedNow();
    const expiresAtMs = Date.parse(payload.expiresAt);
    if (expiresAtMs <= now) {
      throw new CursorCapabilityError(
        "CURSOR_EXPIRED",
        "Resource continuation has expired.",
        { resourceKind },
      );
    }
    const resource = input.resolveResource(payload.resourceIdentity);
    if (!resource) {
      throw staleContinuation(resourceKind, "Resource continuation state is no longer available.");
    }
    const generation = boundedString(resource.generation, "resource generation", 1_024);
    const resourceExpiresAtMs = positiveSafeInteger(resource.expiresAtMs, "resource expiresAtMs");
    if (resourceExpiresAtMs <= now) {
      throw new CursorCapabilityError(
        "CURSOR_EXPIRED",
        "Resource continuation resource has expired.",
        { resourceKind },
      );
    }
    if (
      generation !== payload.resourceGeneration
      || resourceExpiresAtMs < expiresAtMs
    ) {
      throw staleContinuation(
        resourceKind,
        "Resource continuation generation or retention boundary changed.",
      );
    }
    return Object.freeze({ ...payload, expiresAtMs });
  }

  private decodeAndVerify(token: string): ResourceContinuationPayload {
    if (
      !isResourceContinuationToken(token)
      || token.length > MAXIMUM_TOKEN_CHARACTERS
    ) {
      throw invalidContinuation();
    }
    const segments = token.split(".");
    if (
      segments.length !== 3
      || segments[0] !== TOKEN_PREFIX
      || !BASE64URL.test(segments[1]!)
      || !BASE64URL.test(segments[2]!)
    ) {
      throw invalidContinuation();
    }
    const encodedPayload = segments[1]!;
    const encodedSignature = segments[2]!;
    let rawPayload: Buffer;
    let suppliedSignature: Buffer;
    try {
      rawPayload = Buffer.from(encodedPayload, "base64url");
      suppliedSignature = Buffer.from(encodedSignature, "base64url");
    } catch {
      throw invalidContinuation();
    }
    if (
      rawPayload.toString("base64url") !== encodedPayload
      || suppliedSignature.toString("base64url") !== encodedSignature
    ) {
      throw invalidContinuation();
    }
    let parsed: unknown;
    try {
      parsed = JSON.parse(rawPayload.toString("utf8"));
    } catch {
      throw invalidContinuation();
    }
    let payload: ResourceContinuationPayload;
    try {
      payload = validatePayload(parsed);
    } catch {
      throw invalidContinuation();
    }
    if (canonicalPayload(payload) !== rawPayload.toString("utf8")) {
      throw invalidContinuation(payload.resourceKind);
    }
    const key = payload.keyId === this.currentKey.keyId
      ? this.currentKey
      : payload.keyId === this.previousKey?.keyId
        ? this.previousKey
        : undefined;
    if (!key) throw invalidContinuation(payload.resourceKind);
    const expected = hmac(key.secret, encodedPayload);
    if (
      suppliedSignature.length !== expected.length
      || !timingSafeEqual(suppliedSignature, expected)
    ) {
      throw invalidContinuation(payload.resourceKind);
    }
    return payload;
  }

  private checkedNow(): number {
    const value = this.now();
    if (!Number.isSafeInteger(value) || value < 0) {
      throw new TypeError("Resource continuation clock returned an invalid timestamp.");
    }
    return value;
  }
}

export function createEphemeralResourceContinuation(
  options: { now?: () => number } = {},
): SignedResourceContinuation {
  const secret = randomBytes(32);
  const keyId = `resource-${createHash("sha256").update(secret).digest("hex").slice(0, 24)}`;
  return new SignedResourceContinuation({
    currentKey: { keyId, secret },
    ...(options.now ? { now: options.now } : {}),
  });
}

export function isResourceContinuationToken(value: string): boolean {
  return typeof value === "string"
    && value.startsWith(`${TOKEN_PREFIX}.`);
}

function validatePayload(value: unknown): ResourceContinuationPayload {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw invalidContinuation();
  const payload = value as Record<string, unknown>;
  const expectedKeys = [
    "version",
    "keyId",
    "principalKeyFingerprint",
    "resourceKind",
    "resourceIdentity",
    "resourceGeneration",
    "offset",
    "limit",
    "issuedAt",
    "expiresAt",
    "nonce",
  ];
  if (
    Object.keys(payload).length !== expectedKeys.length
    || expectedKeys.some((key) => !(key in payload))
    || payload.version !== 1
  ) {
    throw invalidContinuation();
  }
  const result: ResourceContinuationPayload = {
    version: 1,
    keyId: signingKeyId(payload.keyId, "keyId"),
    principalKeyFingerprint: boundedString(
      payload.principalKeyFingerprint,
      "principalKeyFingerprint",
      1_024,
    ),
    resourceKind: boundedString(payload.resourceKind, "resourceKind", 128),
    resourceIdentity: boundedString(payload.resourceIdentity, "resourceIdentity", 4_096),
    resourceGeneration: boundedString(payload.resourceGeneration, "resourceGeneration", 1_024),
    offset: continuationInteger(payload.offset, false),
    limit: continuationInteger(payload.limit, true),
    issuedAt: canonicalDate(payload.issuedAt),
    expiresAt: canonicalDate(payload.expiresAt),
    nonce: boundedString(payload.nonce, "nonce", 64),
  };
  if (!NONCE.test(result.nonce) || Date.parse(result.issuedAt) > Date.parse(result.expiresAt)) {
    throw invalidContinuation(result.resourceKind);
  }
  return result;
}

function canonicalPayload(payload: ResourceContinuationPayload): string {
  return JSON.stringify({
    version: payload.version,
    keyId: payload.keyId,
    principalKeyFingerprint: payload.principalKeyFingerprint,
    resourceKind: payload.resourceKind,
    resourceIdentity: payload.resourceIdentity,
    resourceGeneration: payload.resourceGeneration,
    offset: payload.offset,
    limit: payload.limit,
    issuedAt: payload.issuedAt,
    expiresAt: payload.expiresAt,
    nonce: payload.nonce,
  });
}

function validateBinding(binding: ResourceContinuationBinding): ResourceContinuationBinding {
  return Object.freeze({
    principalKeyFingerprint: boundedString(
      binding.principalKeyFingerprint,
      "principalKeyFingerprint",
      1_024,
    ),
    resourceKind: boundedString(binding.resourceKind, "resourceKind", 128),
    resourceIdentity: boundedString(binding.resourceIdentity, "resourceIdentity", 4_096),
    resourceGeneration: boundedString(binding.resourceGeneration, "resourceGeneration", 1_024),
  });
}

function validateSigningKey(
  key: ResourceContinuationSigningKey,
  field: string,
): ResourceContinuationSigningKey {
  if (!key || typeof key !== "object") throw new TypeError(`${field} is invalid.`);
  const keyId = signingKeyId(key.keyId, `${field}.keyId`);
  const secret = Buffer.from(key.secret);
  if (secret.length < 32) throw new TypeError(`${field}.secret must contain at least 32 bytes.`);
  return { keyId, secret };
}

function signingKeyId(value: unknown, field: string): string {
  if (typeof value !== "string" || !/^[A-Za-z0-9._-]{1,128}$/u.test(value)) {
    throw new TypeError(`${field} is invalid.`);
  }
  return value;
}

function boundedString(value: unknown, field: string, maximum: number): string {
  if (typeof value !== "string" || value.length === 0 || value.length > maximum) {
    throw new TypeError(`${field} must be a bounded non-empty string.`);
  }
  return value;
}

function canonicalDate(value: unknown): string {
  if (typeof value !== "string") throw invalidContinuation();
  const parsed = Date.parse(value);
  if (!Number.isSafeInteger(parsed) || new Date(parsed).toISOString() !== value) {
    throw invalidContinuation();
  }
  return value;
}

function continuationInteger(value: unknown, positive: boolean): number {
  if (!Number.isSafeInteger(value) || (positive ? Number(value) < 1 : Number(value) < 0)) {
    throw invalidContinuation();
  }
  return value as number;
}

function nonnegativeSafeInteger(value: number, field: string): number {
  if (!Number.isSafeInteger(value) || value < 0) {
    throw new TypeError(`${field} must be a nonnegative safe integer.`);
  }
  return value;
}

function positiveSafeInteger(value: number, field: string): number {
  if (!Number.isSafeInteger(value) || value < 1) {
    throw new TypeError(`${field} must be a positive safe integer.`);
  }
  return value;
}

function invalidContinuation(
  resourceKind?: string,
  message = "Resource continuation is invalid.",
): CursorCapabilityError {
  return new CursorCapabilityError(
    "CURSOR_INVALID",
    message,
    resourceKind ? { resourceKind } : {},
  );
}

function staleContinuation(resourceKind: string, message: string): CursorCapabilityError {
  return new CursorCapabilityError("CURSOR_STALE", message, { resourceKind });
}

function hmac(secret: Uint8Array, value: string): Buffer {
  return createHmac("sha256", secret).update(HMAC_DOMAIN).update(value).digest();
}
