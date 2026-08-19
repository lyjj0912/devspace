import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import test from "node:test";
import { UniversalMcpResultStore } from "./mcp-result-store.js";
import { createCapabilityCallContextFromTrustedPrincipal } from "./capability-call-context.js";

test("MCP result store pages bounded resources and expires them", () => {
  let now = 1_000;
  const store = new UniversalMcpResultStore({
    maximumEntries: 2,
    maximumTotalCharacters: 10_000,
    ttlMs: 1_000,
    now: () => now,
  });
  const stored = store.put({ payload: "x".repeat(200) }, "fixture");
  assert.match(stored.resourceUri, /^devspace:\/\/mcp\/fixture\/result\//u);
  const first = store.readByUri(stored.resourceUri);
  assert.equal(first.truncated, false);
  assert.match(String(first.text), /payload/);

  const paged = store.read(stored.resultId, 0, 50);
  assert.equal(paged.truncated, true);
  assert.equal(typeof paged.nextResourceUri, "string");
  now = 2_001;
  assert.throws(() => store.readByUri(stored.resourceUri), hasCode("PATH_NOT_FOUND"));
});

test("MCP result store rejects quota before creation without evicting live results", () => {
  const store = new UniversalMcpResultStore({
    maximumEntries: 1,
    maximumTotalCharacters: 1_000,
    ttlMs: 10_000,
  });
  const first = store.put({ first: "a".repeat(100) });
  assert.throws(
    () => store.put({ second: "b".repeat(100) }),
    hasCode("RESOURCE_QUOTA_EXCEEDED"),
  );
  assert.doesNotThrow(() => store.readByUri(first.resourceUri));
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
  const wrongRoute = stored.resourceUri.replace("/route-a/", "/route-b/");
  assert.throws(() => store.readByUri(wrongRoute, ownerA2), hasCode("PRECONDITION_FAILED"));
});

function hasCode(code: string) {
  return (error: unknown) => error instanceof Error && "code" in error && error.code === code;
}

function owner(label: string) {
  return createCapabilityCallContextFromTrustedPrincipal({
    principalKeyFingerprint: createHash("sha256").update(label).digest("hex"),
  });
}
