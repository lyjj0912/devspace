import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import test from "node:test";
import { createCapabilityCallContextFromTrustedPrincipal } from "./capability-call-context.js";
import { UniversalTextResourceStore } from "./text-resource-store.js";

const OWNER_A = createCapabilityCallContextFromTrustedPrincipal({
  principalKeyFingerprint: createHash("sha256").update("owner-a").digest("hex"),
});
const OWNER_B = createCapabilityCallContextFromTrustedPrincipal({
  principalKeyFingerprint: createHash("sha256").update("owner-b").digest("hex"),
});

test("text resource store pages and expires resources", () => {
  let now = 1_000;
  const store = new UniversalTextResourceStore({
    authority: "context-diff",
    ttlMs: 1_000,
    defaultPageCharacters: 4,
    now: () => now,
  });
  const stored = store.put("abcdefgh", "text/x-diff", OWNER_A);
  const first = store.readByUri(stored.resourceUri, OWNER_A);
  assert.equal(first.text, "abcd");
  assert.equal(first.nextResourceUri, `devspace://context-diff/${stored.resourceId}/4/4`);
  now = 2_001;
  assert.throws(
    () => store.readByUri(stored.resourceUri, OWNER_A),
    hasReason("PRECONDITION_FAILED", "RESOURCE_EXPIRED"),
  );
  assert.equal(store.stats().tombstones, 1);
});

test("text resource store rejects quota excess without evicting unexpired resources", () => {
  let now = 1_000;
  const store = new UniversalTextResourceStore({
    authority: "context-diff",
    maximumEntries: 1,
    maximumTotalCharacters: 1_000,
    now: () => now,
  });
  const first = store.put("first", "text/plain", OWNER_A);
  now += 1;
  assert.throws(
    () => store.put("second", "text/plain", OWNER_A),
    hasCode("RESOURCE_QUOTA_EXCEEDED"),
  );
  assert.equal(store.readByUri(first.resourceUri, OWNER_A).text, "first");
});

test("text resource ownership rejects cross-owner reads and missing trusted context", () => {
  const store = new UniversalTextResourceStore({ authority: "context-diff" });
  const stored = store.put("principal-owned", "text/plain", OWNER_A);
  assert.throws(
    () => store.readByUri(stored.resourceUri, OWNER_B),
    hasCode("AUTHORITY_PRINCIPAL_MISMATCH"),
  );
  assert.throws(
    () => store.readByUri(stored.resourceUri),
    hasCode("AUTHENTICATION_FAILED"),
  );
});

function hasCode(code: string) {
  return (error: unknown) => error instanceof Error
    && "code" in error
    && error.code === code;
}

function hasReason(code: string, reasonCode: string) {
  return (error: unknown) => error instanceof Error
    && "code" in error
    && error.code === code
    && "evidence" in error
    && (error.evidence as { reasonCode?: string } | undefined)?.reasonCode === reasonCode;
}
