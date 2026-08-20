import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import test from "node:test";
import { UniversalMcpResultStore } from "./mcp-result-store.js";
import { createCapabilityCallContextFromTrustedPrincipal } from "./capability-call-context.js";
import { CursorCapabilityError } from "./cursor-capability.js";
import { UniversalBrokerMetrics } from "./metrics.js";

test("MCP result store pages bounded resources and expires them", () => {
  let now = 1_000;
  const store = new UniversalMcpResultStore({
    maximumEntries: 2,
    maximumTotalBytes: 100_000,
    ttlMs: 1_000,
    now: () => now,
  });
  const expected = { payload: "x".repeat(25_000) };
  const stored = store.put(expected, "fixture");
  assert.match(stored.resourceUri, /^devspace:\/\/v1\/mcp-result\//u);
  let nextResourceUri: string | undefined = stored.resourceUri;
  let combined = "";
  let pages = 0;
  while (nextResourceUri) {
    const page = store.readByUri(nextResourceUri);
    combined += String(page.text);
    pages += 1;
    assert.equal("nextOffset" in page, false);
    nextResourceUri = typeof page.nextResourceUri === "string"
      ? page.nextResourceUri
      : undefined;
    if (nextResourceUri) {
      assert.match(nextResourceUri, /^devspace:\/\/v1\/mcp-result\/rc1\./u);
      assert.doesNotMatch(nextResourceUri, /\/\d+\/\d+$/u);
    }
  }
  assert.deepEqual(JSON.parse(combined), expected);
  assert.equal(pages, 3);
  now = 2_001;
  assert.throws(() => store.readByUri(stored.resourceUri), hasCode("PATH_NOT_FOUND"));
});

test("MCP result continuation rejects tamper, cross-owner use, missing generation, and expiry", () => {
  let now = 1_000;
  const store = new UniversalMcpResultStore({
    maximumEntries: 2,
    maximumTotalBytes: 100_000,
    ttlMs: 1_000,
    now: () => now,
  });
  const ownerA = owner("continuation-owner-a");
  const ownerB = owner("continuation-owner-b");
  const stored = store.put({ payload: "x".repeat(25_000) }, "fixture", ownerA);
  const first = store.readByUri(stored.resourceUri, ownerA);
  const nextResourceUri = String(first.nextResourceUri);

  assert.throws(
    () => store.readByUri(tamper(nextResourceUri), ownerA),
    hasCursorReason("CURSOR_INVALID"),
  );
  assert.throws(
    () => store.readByUri(nextResourceUri, ownerB),
    hasCursorReason("CURSOR_INVALID"),
  );
  store.clear();
  assert.throws(
    () => store.readByUri(nextResourceUri, ownerA),
    hasCursorReason("CURSOR_STALE"),
  );
  now = 2_000;
  assert.throws(
    () => store.readByUri(nextResourceUri, ownerA),
    hasCursorReason("CURSOR_EXPIRED"),
  );
});

test("MCP result store rejects quota before creation without evicting live results", () => {
  const metrics = new UniversalBrokerMetrics();
  const store = new UniversalMcpResultStore({
    maximumEntries: 1,
    maximumTotalBytes: 1_000,
    ttlMs: 10_000,
    metrics,
  });
  const first = store.put({ first: "a".repeat(100) });
  assert.throws(
    () => store.put({ second: "b".repeat(100) }),
    hasCode("RESOURCE_QUOTA_EXCEEDED"),
  );
  assert.doesNotThrow(() => store.readByUri(first.resourceUri));
  assert.match(
    metrics.render({}),
    /devspace_quota_rejections_total\{resource_kind="mcp_result"\} 1/u,
  );
});

test("MCP result quota metrics cannot mask the original rejection", () => {
  const throwingMetrics = {
    recordQuotaRejection() {
      throw new Error("metrics sink unavailable");
    },
  } as unknown as UniversalBrokerMetrics;
  const store = new UniversalMcpResultStore({
    maximumEntries: 1,
    maximumTotalBytes: 1_000,
    ttlMs: 10_000,
    metrics: throwingMetrics,
  });
  store.put({ first: "ok" });
  assert.throws(
    () => store.put({ second: "rejected" }),
    hasCode("RESOURCE_QUOTA_EXCEEDED"),
  );
});

test("MCP retained-result quota is UTF-8 bytes and isolated per principal", () => {
  const store = new UniversalMcpResultStore({
    maximumEntries: 2,
    maximumTotalBytes: 20,
    ttlMs: 10_000,
  });
  const ownerA = owner("byte-owner-a");
  const ownerB = owner("byte-owner-b");

  const first = store.put("한글", "fixture", ownerA);
  assert.equal(first.bytes, Buffer.byteLength(JSON.stringify("한글"), "utf8"));
  assert.throws(
    () => store.put("한글한글한글", "fixture", ownerA),
    hasCode("RESOURCE_QUOTA_EXCEEDED"),
  );
  assert.doesNotThrow(() => store.put("한글", "fixture", ownerB));
});

test("MCP result URIs bind route and stable principal", () => {
  const store = new UniversalMcpResultStore();
  const ownerA1 = owner("result-owner-a");
  const ownerA2 = owner("result-owner-a");
  const ownerB = owner("result-owner-b");
  const stored = store.put({ secret: "owned" }, "route-a", ownerA1);
  assert.match(String(store.readByUri(stored.resourceUri, ownerA2).text), /owned/u);
  assert.throws(
    () => store.readByUri(stored.resourceUri, ownerB),
    hasCode("AUTHORITY_PRINCIPAL_MISMATCH"),
  );
  const wrongRoute = `devspace://mcp/route-b/result/${stored.resultId}/0/12000`;
  assert.throws(() => store.readByUri(wrongRoute, ownerA2), hasCode("PRECONDITION_FAILED"));
  const legacyRoute = `devspace://mcp/route-a/result/${stored.resultId}/0/12000`;
  assert.match(String(store.readByUri(legacyRoute, ownerA2).uri), /^devspace:\/\/v1\/mcp-result\//u);
});

function hasCode(code: string) {
  return (error: unknown) => error instanceof Error && "code" in error && error.code === code;
}

function owner(label: string) {
  return createCapabilityCallContextFromTrustedPrincipal({
    principalKeyFingerprint: createHash("sha256").update(label).digest("hex"),
  });
}

function hasCursorReason(reason: string) {
  return (error: unknown) => error instanceof CursorCapabilityError && error.reason === reason;
}

function tamper(token: string): string {
  const replacement = token.endsWith("A") ? "B" : "A";
  return `${token.slice(0, -1)}${replacement}`;
}
