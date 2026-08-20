import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { performance } from "node:perf_hooks";
import test from "node:test";
import { CursorCapabilityError } from "./cursor-capability.js";
import {
  SignedResourceContinuation,
  type ResourceContinuationBinding,
} from "./resource-continuation.js";

const OWNER_A = digest("owner-a");
const OWNER_B = digest("owner-b");
const RESOURCE_A = "resource-a";
const GENERATION_A = digest("generation-a");

test("resource continuation binds owner, resource, generation, offset, limit, expiry, and nonce", () => {
  const clock = { value: 1_787_200_000_000 };
  const continuation = codec(clock);
  const token = continuation.issue({
    binding: binding(),
    offset: 37,
    limit: 64,
    expiresAtMs: clock.value + 60_000,
  });

  assert.match(token, /^rc1\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/u);
  assert.equal(token.includes('"offset"'), false);
  const verified = continuation.verify({
    token,
    principalKeyFingerprint: OWNER_A,
    resourceKind: "context-diff",
    expectedResourceIdentity: RESOURCE_A,
    resolveResource: (identity) => identity === RESOURCE_A
      ? { generation: GENERATION_A, expiresAtMs: clock.value + 60_000 }
      : undefined,
  });
  assert.equal(verified.resourceIdentity, RESOURCE_A);
  assert.equal(verified.resourceGeneration, GENERATION_A);
  assert.equal(verified.offset, 37);
  assert.equal(verified.limit, 64);
  assert.match(verified.nonce, /^[A-Za-z0-9_-]{22}$/u);

  const extended = continuation.verify({
    token,
    principalKeyFingerprint: OWNER_A,
    resourceKind: "context-diff",
    resolveResource: () => ({
      generation: GENERATION_A,
      expiresAtMs: clock.value + 120_000,
    }),
  });
  assert.equal(extended.expiresAtMs, clock.value + 60_000);
});

test("resource continuation rejects tamper, owner/resource mismatch, limit escalation, stale state, and expiry", () => {
  const clock = { value: 1_787_200_100_000 };
  const continuation = codec(clock);
  const expiresAtMs = clock.value + 1_000;
  const token = continuation.issue({
    binding: binding(),
    offset: 8,
    limit: 16,
    expiresAtMs,
  });
  const live = (identity: string) => identity === RESOURCE_A
    ? { generation: GENERATION_A, expiresAtMs }
    : undefined;

  assert.throws(
    () => continuation.verify({
      token: tamper(token),
      principalKeyFingerprint: OWNER_A,
      resourceKind: "context-diff",
      resolveResource: live,
    }),
    hasReason("CURSOR_INVALID"),
  );
  assert.throws(
    () => continuation.verify({
      token: malformedPayload(token),
      principalKeyFingerprint: OWNER_A,
      resourceKind: "context-diff",
      resolveResource: live,
    }),
    hasReason("CURSOR_INVALID"),
  );
  assert.throws(
    () => continuation.verify({
      token,
      principalKeyFingerprint: OWNER_B,
      resourceKind: "context-diff",
      resolveResource: () => assert.fail("owner mismatch must reject before resource lookup"),
    }),
    hasReason("CURSOR_INVALID"),
  );
  assert.throws(
    () => continuation.verify({
      token,
      principalKeyFingerprint: OWNER_A,
      resourceKind: "context-diff",
      expectedResourceIdentity: "resource-b",
      resolveResource: live,
    }),
    hasReason("CURSOR_INVALID"),
  );
  assert.throws(
    () => continuation.verify({
      token,
      principalKeyFingerprint: OWNER_A,
      resourceKind: "context-diff",
      requestedLimit: 17,
      resolveResource: live,
    }),
    hasReason("CURSOR_INVALID"),
  );
  assert.throws(
    () => continuation.verify({
      token,
      principalKeyFingerprint: OWNER_A,
      resourceKind: "context-diff",
      resolveResource: () => ({ generation: digest("generation-b"), expiresAtMs }),
    }),
    hasReason("CURSOR_STALE"),
  );
  assert.throws(
    () => continuation.verify({
      token,
      principalKeyFingerprint: OWNER_A,
      resourceKind: "context-diff",
      resolveResource: () => ({ generation: GENERATION_A, expiresAtMs: expiresAtMs - 1 }),
    }),
    hasReason("CURSOR_STALE"),
  );
  assert.throws(
    () => continuation.verify({
      token,
      principalKeyFingerprint: OWNER_A,
      resourceKind: "context-diff",
      resolveResource: () => undefined,
    }),
    hasReason("CURSOR_STALE"),
  );

  clock.value = expiresAtMs;
  assert.throws(
    () => continuation.verify({
      token,
      principalKeyFingerprint: OWNER_A,
      resourceKind: "context-diff",
      resolveResource: live,
    }),
    hasReason("CURSOR_EXPIRED"),
  );
});

test("every single-character continuation tamper is typed invalid before resource lookup", () => {
  const clock = { value: 1_787_200_150_000 };
  const continuation = codec(clock);
  const token = continuation.issue({
    binding: binding(),
    offset: 8,
    limit: 16,
    expiresAtMs: clock.value + 60_000,
  });
  let resourceLookups = 0;
  for (let index = 0; index < token.length; index += 1) {
    const replacement = token[index] === "A" ? "B" : "A";
    const changed = `${token.slice(0, index)}${replacement}${token.slice(index + 1)}`;
    assert.throws(
      () => continuation.verify({
        token: changed,
        principalKeyFingerprint: OWNER_A,
        resourceKind: "context-diff",
        resolveResource: () => {
          resourceLookups += 1;
          return { generation: GENERATION_A, expiresAtMs: clock.value + 60_000 };
        },
      }),
      hasReason("CURSOR_INVALID"),
      `tamper at continuation character ${index} must reject`,
    );
  }
  assert.equal(resourceLookups, 0);
});

test("resource continuation accepts only current or bounded previous HMAC keys", () => {
  const clock = { value: 1_787_200_200_000 };
  const oldKey = { keyId: "resource-old", secret: Buffer.alloc(32, 0x11) };
  const newKey = { keyId: "resource-new", secret: Buffer.alloc(32, 0x22) };
  const oldIssuer = new SignedResourceContinuation({ currentKey: oldKey, now: () => clock.value });
  const token = oldIssuer.issue({
    binding: binding(),
    offset: 1,
    limit: 2,
    expiresAtMs: clock.value + 60_000,
  });
  const resolver = () => ({ generation: GENERATION_A, expiresAtMs: clock.value + 60_000 });

  const rotated = new SignedResourceContinuation({
    currentKey: newKey,
    previousKey: oldKey,
    now: () => clock.value,
  });
  assert.equal(rotated.verify({
    token,
    principalKeyFingerprint: OWNER_A,
    resourceKind: "context-diff",
    resolveResource: resolver,
  }).offset, 1);

  const expiredRotation = new SignedResourceContinuation({ currentKey: newKey, now: () => clock.value });
  assert.throws(
    () => expiredRotation.verify({
      token,
      principalKeyFingerprint: OWNER_A,
      resourceKind: "context-diff",
      resolveResource: resolver,
    }),
    hasReason("CURSOR_INVALID"),
  );
});

test("resource continuation verification remains within the 5ms p95 cursor NFR", () => {
  const clock = { value: 1_787_200_300_000 };
  const continuation = codec(clock);
  const expiresAtMs = clock.value + 60_000;
  const token = continuation.issue({
    binding: binding(),
    offset: 12_000,
    limit: 12_000,
    expiresAtMs,
  });
  const samples: number[] = [];
  for (let index = 0; index < 500; index += 1) {
    const started = performance.now();
    const verified = continuation.verify({
      token,
      principalKeyFingerprint: OWNER_A,
      resourceKind: "context-diff",
      resolveResource: () => ({ generation: GENERATION_A, expiresAtMs }),
    });
    samples.push(performance.now() - started);
    assert.equal(verified.offset, 12_000);
  }
  samples.sort((left, right) => left - right);
  const p95 = samples[Math.ceil(samples.length * 0.95) - 1]!;
  assert.equal(p95 <= 5, true, `resource continuation verification p95 was ${p95.toFixed(3)}ms`);
});

function codec(clock: { value: number }): SignedResourceContinuation {
  return new SignedResourceContinuation({
    currentKey: { keyId: "resource-current", secret: Buffer.alloc(32, 0x44) },
    now: () => clock.value,
  });
}

function binding(overrides: Partial<ResourceContinuationBinding> = {}): ResourceContinuationBinding {
  return {
    principalKeyFingerprint: OWNER_A,
    resourceKind: "context-diff",
    resourceIdentity: RESOURCE_A,
    resourceGeneration: GENERATION_A,
    ...overrides,
  };
}

function tamper(token: string): string {
  const replacement = token.endsWith("A") ? "B" : "A";
  return `${token.slice(0, -1)}${replacement}`;
}

function malformedPayload(token: string): string {
  const [prefix, encodedPayload, signature] = token.split(".") as [string, string, string];
  const payload = JSON.parse(Buffer.from(encodedPayload, "base64url").toString("utf8")) as {
    principalKeyFingerprint: string;
  };
  payload.principalKeyFingerprint = "";
  return `${prefix}.${Buffer.from(JSON.stringify(payload), "utf8").toString("base64url")}.${signature}`;
}

function digest(value: string): string {
  return createHash("sha256").update(value).digest("hex");
}

function hasReason(reason: string) {
  return (error: unknown) => error instanceof CursorCapabilityError && error.reason === reason;
}
