import { createHash } from "node:crypto";
import { isIP } from "node:net";

export type RateLimitStage = "pre_auth" | "post_auth" | "initialize";

export interface TokenBucketPolicy {
  capacity: number;
  refillTokens: number;
  refillIntervalMs: number;
}

export interface BrokerRateLimitPolicy {
  preAuth: TokenBucketPolicy;
  postAuth: TokenBucketPolicy;
  initialize: TokenBucketPolicy;
}

export interface RateLimitSourceInput {
  remoteAddress: string;
  forwardedFor?: string | readonly string[];
}

export interface AuthenticatedRateLimitInput {
  principalFingerprint: string;
  clientId: string;
}

export type RateLimitDecision =
  | {
      allowed: true;
      stage: RateLimitStage;
      limit: number;
      remaining: number;
    }
  | {
      allowed: false;
      stage: RateLimitStage;
      limit: number;
      remaining: 0;
      httpStatus: 429;
      retryAfterSeconds: number;
      resetAt: number;
      reason?: "BUCKET_CAPACITY_EXHAUSTED";
    };

export interface BrokerRateLimiterOptions {
  now?: () => number;
  trustedProxy?: (address: string, hopIndexFromBroker: number) => boolean;
  maximumBuckets?: number;
  bucketIdleTtlMs?: number;
}

interface BucketState {
  tokens: number;
  refilledAt: number;
  lastSeenAt: number;
  policy: TokenBucketPolicy;
}

const PRINCIPAL_PATTERN = /^[a-f0-9]{64}$/u;
const DEFAULT_MAXIMUM_BUCKETS = 10_000;
const DEFAULT_BUCKET_IDLE_TTL_MS = 15 * 60_000;
const MAXIMUM_IDENTITY_CHARACTERS = 512;

/**
 * Broker-owned, in-process token buckets. Keys are SHA-256 digests so raw IP, principal, and
 * client identities never become metrics or diagnostic state.
 */
export class BrokerRateLimiter {
  private readonly policy: BrokerRateLimitPolicy;
  private readonly now: () => number;
  private readonly trustedProxy: (address: string, hopIndexFromBroker: number) => boolean;
  private readonly maximumBuckets: number;
  private readonly bucketIdleTtlMs: number;
  private readonly buckets = new Map<string, BucketState>();

  constructor(policy: BrokerRateLimitPolicy, options: BrokerRateLimiterOptions = {}) {
    this.policy = {
      preAuth: validatePolicy(policy.preAuth, "preAuth"),
      postAuth: validatePolicy(policy.postAuth, "postAuth"),
      initialize: validatePolicy(policy.initialize, "initialize"),
    };
    this.now = options.now ?? Date.now;
    this.trustedProxy = options.trustedProxy ?? (() => false);
    this.maximumBuckets = boundedInteger(
      options.maximumBuckets,
      DEFAULT_MAXIMUM_BUCKETS,
      1,
      1_000_000,
      "maximumBuckets",
    );
    this.bucketIdleTtlMs = boundedInteger(
      options.bucketIdleTtlMs,
      DEFAULT_BUCKET_IDLE_TTL_MS,
      1_000,
      24 * 60 * 60_000,
      "bucketIdleTtlMs",
    );
  }

  preAuth(input: RateLimitSourceInput): RateLimitDecision {
    const source = resolveRateLimitSourceAddress(input, this.trustedProxy);
    return this.consume("pre_auth", digestKey("pre_auth", source), this.policy.preAuth);
  }

  postAuth(input: AuthenticatedRateLimitInput): RateLimitDecision {
    const identity = authenticatedIdentity(input);
    return this.consume("post_auth", digestKey("post_auth", identity), this.policy.postAuth);
  }

  initialize(input: AuthenticatedRateLimitInput): RateLimitDecision {
    const identity = authenticatedIdentity(input);
    return this.consume("initialize", digestKey("initialize", identity), this.policy.initialize);
  }

  stats(): { buckets: number; maximumBuckets: number } {
    this.pruneExpired(this.now());
    return { buckets: this.buckets.size, maximumBuckets: this.maximumBuckets };
  }

  private consume(
    stage: RateLimitStage,
    key: string,
    policy: TokenBucketPolicy,
  ): RateLimitDecision {
    const now = this.now();
    if (!Number.isFinite(now) || now < 0) throw new Error("Rate limiter clock returned an invalid time.");
    let bucket = this.buckets.get(key);
    if (!bucket) {
      this.pruneExpired(now);
      if (this.buckets.size >= this.maximumBuckets) {
        const resetAt = this.nextBucketAvailability(now);
        return {
          allowed: false,
          stage,
          limit: policy.capacity,
          remaining: 0,
          httpStatus: 429,
          retryAfterSeconds: Math.max(1, Math.ceil((resetAt - now) / 1_000)),
          resetAt,
          reason: "BUCKET_CAPACITY_EXHAUSTED",
        };
      }
      bucket = { tokens: policy.capacity, refilledAt: now, lastSeenAt: now, policy };
      this.buckets.set(key, bucket);
    }

    refill(bucket, policy, now);
    bucket.lastSeenAt = now;
    if (bucket.tokens >= 1) {
      bucket.tokens -= 1;
      return {
        allowed: true,
        stage,
        limit: policy.capacity,
        remaining: Math.max(0, Math.floor(bucket.tokens)),
      };
    }

    const millisecondsPerToken = policy.refillIntervalMs / policy.refillTokens;
    const waitMs = Math.max(1, Math.ceil((1 - bucket.tokens) * millisecondsPerToken));
    return {
      allowed: false,
      stage,
      limit: policy.capacity,
      remaining: 0,
      httpStatus: 429,
      retryAfterSeconds: Math.max(1, Math.ceil(waitMs / 1_000)),
      resetAt: now + waitMs,
    };
  }

  private pruneExpired(now: number): void {
    for (const [key, bucket] of this.buckets) {
      if (bucket.lastSeenAt + this.bucketIdleTtlMs > now) continue;
      refill(bucket, bucket.policy, now);
      // Never let cache pruning become a rate-limit reset. A bucket is evictable only after its
      // idle interval and after it has naturally refilled to capacity.
      if (bucket.tokens >= bucket.policy.capacity) this.buckets.delete(key);
    }
  }

  private nextBucketAvailability(now: number): number {
    let earliest = Number.POSITIVE_INFINITY;
    for (const bucket of this.buckets.values()) {
      refill(bucket, bucket.policy, now);
      const tokensNeeded = Math.max(0, bucket.policy.capacity - bucket.tokens);
      const refillWaitMs = Math.ceil(
        tokensNeeded * (bucket.policy.refillIntervalMs / bucket.policy.refillTokens),
      );
      earliest = Math.min(
        earliest,
        Math.max(bucket.lastSeenAt + this.bucketIdleTtlMs, now + refillWaitMs),
      );
    }
    return Number.isFinite(earliest) ? Math.max(now + 1, earliest) : now + this.bucketIdleTtlMs;
  }
}

/** Resolve the client hop only when the directly connected peer is explicitly trusted. */
export function resolveRateLimitSourceAddress(
  input: RateLimitSourceInput,
  trustedProxy: (address: string, hopIndexFromBroker: number) => boolean,
): string {
  const direct = validIpAddress(input.remoteAddress, "remoteAddress");
  // Forwarding metadata from an untrusted peer is attacker-controlled and must be ignored,
  // including malformed values that otherwise could turn spoofed headers into availability loss.
  if (!trustedProxy(direct, 0)) return direct;
  const forwarded = forwardedAddresses(input.forwardedFor);
  if (forwarded.length === 0) return direct;

  for (let index = forwarded.length - 1; index >= 0; index -= 1) {
    const address = forwarded[index]!;
    const hopIndexFromBroker = forwarded.length - index;
    if (!trustedProxy(address, hopIndexFromBroker)) return address;
  }
  return forwarded[0] ?? direct;
}

/** Convert the existing Express-style trusted hop count into the exact chain predicate. */
export function trustedProxyHopCount(
  maximumTrustedHops: false | number,
): (address: string, hopIndexFromBroker: number) => boolean {
  if (maximumTrustedHops === false) return () => false;
  const hops = boundedInteger(maximumTrustedHops, undefined, 1, 32, "maximumTrustedHops");
  return (_address, hopIndexFromBroker) => (
    Number.isInteger(hopIndexFromBroker)
    && hopIndexFromBroker >= 0
    && hopIndexFromBroker < hops
  );
}

/**
 * Trust forwarding metadata only when the directly connected peer is a local management proxy.
 * A hop count alone is not a source trust policy: without this guard any remote client could
 * choose its own bucket by sending X-Forwarded-For.
 */
export function trustedLoopbackProxyHopCount(
  maximumTrustedHops: false | number,
): (address: string, hopIndexFromBroker: number) => boolean {
  if (maximumTrustedHops === false) return () => false;
  const hopPolicy = trustedProxyHopCount(maximumTrustedHops);
  return (address, hopIndexFromBroker) => {
    if (hopIndexFromBroker === 0 && !isLoopbackAddress(address)) return false;
    return hopPolicy(address, hopIndexFromBroker);
  };
}

function isLoopbackAddress(address: string): boolean {
  const normalized = address.toLowerCase();
  return normalized === "127.0.0.1"
    || normalized === "::1"
    || normalized === "::ffff:127.0.0.1";
}

function forwardedAddresses(value: string | readonly string[] | undefined): string[] {
  if (value === undefined) return [];
  const joined = typeof value === "string" ? value : value.join(",");
  const entries = joined.split(",").map((entry: string) => entry.trim()).filter(Boolean);
  if (entries.length > 32) throw new Error("Forwarded address chain exceeds 32 hops.");
  return entries.map((entry: string) => validIpAddress(entry, "forwardedFor"));
}

function validIpAddress(value: string, field: string): string {
  const normalized = value.trim();
  if (isIP(normalized) === 0) throw new Error(`${field} must contain a valid IP address.`);
  return normalized.toLowerCase();
}

function authenticatedIdentity(input: AuthenticatedRateLimitInput): string {
  const principal = input.principalFingerprint.trim().toLowerCase();
  if (!PRINCIPAL_PATTERN.test(principal)) {
    throw new Error("principalFingerprint must be a SHA-256 fingerprint.");
  }
  const clientId = input.clientId.trim();
  if (!clientId || clientId.length > MAXIMUM_IDENTITY_CHARACTERS || /[\r\n\0]/u.test(clientId)) {
    throw new Error("clientId is missing or invalid.");
  }
  return `${principal}\0${clientId}`;
}

function validatePolicy(value: TokenBucketPolicy, name: string): TokenBucketPolicy {
  return Object.freeze({
    capacity: boundedInteger(value?.capacity, undefined, 1, 1_000_000, `${name}.capacity`),
    refillTokens: boundedInteger(value?.refillTokens, undefined, 1, 1_000_000, `${name}.refillTokens`),
    refillIntervalMs: boundedInteger(
      value?.refillIntervalMs,
      undefined,
      1,
      24 * 60 * 60_000,
      `${name}.refillIntervalMs`,
    ),
  });
}

function refill(bucket: BucketState, policy: TokenBucketPolicy, now: number): void {
  const elapsed = Math.max(0, now - bucket.refilledAt);
  if (elapsed === 0) return;
  const replenished = elapsed * (policy.refillTokens / policy.refillIntervalMs);
  bucket.tokens = Math.min(policy.capacity, bucket.tokens + replenished);
  bucket.refilledAt = now;
}

function digestKey(stage: RateLimitStage, value: string): string {
  return createHash("sha256").update(stage).update("\0").update(value).digest("hex");
}

function boundedInteger(
  value: number | undefined,
  fallback: number | undefined,
  minimum: number,
  maximum: number,
  name: string,
): number {
  const parsed = value ?? fallback;
  if (parsed === undefined || !Number.isInteger(parsed) || parsed < minimum || parsed > maximum) {
    throw new Error(`${name} must be an integer from ${minimum} through ${maximum}.`);
  }
  return parsed;
}
