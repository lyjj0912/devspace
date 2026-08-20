import assert from "node:assert/strict";
import test from "node:test";
import {
  BrokerRateLimiter,
  resolveRateLimitSourceAddress,
  trustedLoopbackProxyHopCount,
  trustedProxyHopCount,
  type BrokerRateLimitPolicy,
} from "./rate-limit.js";

const PRINCIPAL = "a".repeat(64);
const POLICY: BrokerRateLimitPolicy = {
  preAuth: { capacity: 2, refillTokens: 1, refillIntervalMs: 1_000 },
  postAuth: { capacity: 2, refillTokens: 1, refillIntervalMs: 1_000 },
  initialize: { capacity: 1, refillTokens: 1, refillIntervalMs: 5_000 },
};

test("pre-auth buckets fail at the exact threshold and return deterministic Retry-After", () => {
  let now = 10_000;
  const limiter = new BrokerRateLimiter(POLICY, { now: () => now });
  const request = { remoteAddress: "203.0.113.10" };

  assert.equal(limiter.preAuth(request).allowed, true);
  assert.equal(limiter.preAuth(request).allowed, true);
  const rejected = limiter.preAuth(request);
  assert.deepEqual(rejected, {
    allowed: false,
    stage: "pre_auth",
    limit: 2,
    remaining: 0,
    httpStatus: 429,
    retryAfterSeconds: 1,
    resetAt: 11_000,
  });

  now = 10_999;
  assert.equal(limiter.preAuth(request).allowed, false);
  now = 11_000;
  assert.equal(limiter.preAuth(request).allowed, true);
});

test("production loopback proxy policy ignores spoofed forwarding from a remote peer", () => {
  const policy = trustedLoopbackProxyHopCount(1);
  assert.equal(resolveRateLimitSourceAddress({
    remoteAddress: "203.0.113.9",
    forwardedFor: "198.51.100.7",
  }, policy), "203.0.113.9");
  assert.equal(resolveRateLimitSourceAddress({
    remoteAddress: "127.0.0.1",
    forwardedFor: "198.51.100.7",
  }, policy), "198.51.100.7");
  assert.equal(resolveRateLimitSourceAddress({
    remoteAddress: "::ffff:127.0.0.1",
    forwardedFor: "198.51.100.8",
  }, policy), "198.51.100.8");
});

test("pre-auth, post-auth, and initialize buckets are independent and identity scoped", () => {
  const limiter = new BrokerRateLimiter(POLICY, { now: () => 50_000 });
  const authenticated = { principalFingerprint: PRINCIPAL, clientId: "client-a" };

  assert.equal(limiter.postAuth(authenticated).allowed, true);
  assert.equal(limiter.postAuth(authenticated).allowed, true);
  assert.equal(limiter.postAuth(authenticated).allowed, false);
  assert.equal(limiter.postAuth({ ...authenticated, clientId: "client-b" }).allowed, true);

  assert.equal(limiter.initialize(authenticated).allowed, true);
  const initializeRejected = limiter.initialize(authenticated);
  assert.equal(initializeRejected.allowed, false);
  assert.equal(initializeRejected.stage, "initialize");
  assert.equal(initializeRejected.retryAfterSeconds, 5);

  assert.equal(limiter.preAuth({ remoteAddress: "203.0.113.20" }).allowed, true);
});

test("forwarded addresses are used only across an explicitly trusted proxy chain", () => {
  const untrusted = resolveRateLimitSourceAddress({
    remoteAddress: "198.51.100.9",
    forwardedFor: "203.0.113.8, 10.0.0.8",
  }, () => false);
  assert.equal(untrusted, "198.51.100.9");
  assert.equal(resolveRateLimitSourceAddress({
    remoteAddress: "198.51.100.9",
    forwardedFor: "attacker-controlled-invalid-value",
  }, () => false), "198.51.100.9");

  const trusted = resolveRateLimitSourceAddress({
    remoteAddress: "10.0.0.9",
    forwardedFor: "203.0.113.8, 10.0.0.8",
  }, (address) => address.startsWith("10."));
  assert.equal(trusted, "203.0.113.8");

  const oneTrustedHop = resolveRateLimitSourceAddress({
    remoteAddress: "10.0.0.9",
    forwardedFor: "192.0.2.66, 203.0.113.8",
  }, trustedProxyHopCount(1));
  assert.equal(oneTrustedHop, "203.0.113.8");
  assert.equal(resolveRateLimitSourceAddress({
    remoteAddress: "10.0.0.9",
    forwardedFor: "192.0.2.66, 203.0.113.8",
  }, trustedProxyHopCount(2)), "192.0.2.66");

  assert.throws(
    () => resolveRateLimitSourceAddress({ remoteAddress: "not-an-ip" }, () => true),
    /valid IP address/u,
  );
});

test("bucket cardinality exhaustion fails closed for a new identity", () => {
  const limiter = new BrokerRateLimiter(POLICY, {
    now: () => 0,
    maximumBuckets: 2,
    bucketIdleTtlMs: 60_000,
  });
  assert.equal(limiter.preAuth({ remoteAddress: "203.0.113.1" }).allowed, true);
  assert.equal(limiter.preAuth({ remoteAddress: "203.0.113.2" }).allowed, true);
  const saturated = limiter.preAuth({ remoteAddress: "203.0.113.3" });
  assert.equal(saturated.allowed, false);
  assert.equal(saturated.reason, "BUCKET_CAPACITY_EXHAUSTED");
  assert.equal(saturated.httpStatus, 429);
});

test("idle pruning never resets a bucket before its tokens naturally refill", () => {
  let now = 0;
  const limiter = new BrokerRateLimiter({
    ...POLICY,
    preAuth: { capacity: 2, refillTokens: 1, refillIntervalMs: 10_000 },
  }, {
    now: () => now,
    bucketIdleTtlMs: 1_000,
    maximumBuckets: 1,
  });
  const request = { remoteAddress: "203.0.113.44" };
  assert.equal(limiter.preAuth(request).allowed, true);
  assert.equal(limiter.preAuth(request).allowed, true);

  now = 2_000;
  assert.equal(limiter.stats().buckets, 1);
  const stillLimited = limiter.preAuth(request);
  assert.equal(stillLimited.allowed, false);
  assert.equal(stillLimited.retryAfterSeconds, 8);
  const capacityLimited = limiter.preAuth({ remoteAddress: "203.0.113.45" });
  assert.equal(capacityLimited.allowed, false);
  assert.equal(capacityLimited.retryAfterSeconds, 18);
  assert.equal(capacityLimited.resetAt, 20_000);

  now = 20_000;
  assert.equal(limiter.stats().buckets, 0);
  assert.equal(limiter.preAuth(request).allowed, true);
});
