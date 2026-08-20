import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import test from "node:test";
import { createCapabilityCallContextFromTrustedPrincipal } from "./capability-call-context.js";
import { CursorCapabilityError } from "./cursor-capability.js";
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
  assert.match(stored.resourceUri, /^devspace:\/\/v1\/context-diff\//u);
  let nextResourceUri: string | undefined = stored.resourceUri;
  let combined = "";
  let pages = 0;
  while (nextResourceUri) {
    const page = store.readByUri(nextResourceUri, OWNER_A);
    combined += String(page.text);
    pages += 1;
    assert.equal("nextOffset" in page, false);
    nextResourceUri = typeof page.nextResourceUri === "string"
      ? page.nextResourceUri
      : undefined;
    if (nextResourceUri) {
      assert.match(nextResourceUri, /^devspace:\/\/v1\/context-diff\/rc1\./u);
      assert.doesNotMatch(nextResourceUri, /\/\d+\/\d+$/u);
    }
  }
  assert.equal(combined, "abcdefgh");
  assert.equal(pages, 2);
  now = 2_001;
  assert.throws(
    () => store.readByUri(stored.resourceUri, OWNER_A),
    hasReason("PRECONDITION_FAILED", "RESOURCE_EXPIRED"),
  );
  assert.equal(store.stats().tombstones, 1);
});

test("text resource continuation rejects tamper, cross-owner use, missing generation, and expiry", () => {
  let now = 1_000;
  const store = new UniversalTextResourceStore({
    authority: "context-diff",
    ttlMs: 1_000,
    defaultPageCharacters: 4,
    now: () => now,
  });
  const stored = store.put("abcdefgh", "text/plain", OWNER_A);
  const first = store.readByUri(stored.resourceUri, OWNER_A);
  const nextResourceUri = String(first.nextResourceUri);

  assert.throws(
    () => store.readByUri(tamper(nextResourceUri), OWNER_A),
    hasCursorReason("CURSOR_INVALID"),
  );
  assert.throws(
    () => store.readByUri(nextResourceUri, OWNER_B),
    hasCursorReason("CURSOR_INVALID"),
  );
  store.clear();
  assert.throws(
    () => store.readByUri(nextResourceUri, OWNER_A),
    hasCursorReason("CURSOR_STALE"),
  );
  now = 2_000;
  assert.throws(
    () => store.readByUri(nextResourceUri, OWNER_A),
    hasCursorReason("CURSOR_EXPIRED"),
  );
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

function hasCursorReason(reason: string) {
  return (error: unknown) => error instanceof CursorCapabilityError && error.reason === reason;
}

function tamper(token: string): string {
  const replacement = token.endsWith("A") ? "B" : "A";
  return `${token.slice(0, -1)}${replacement}`;
}
