import assert from "node:assert/strict";
import test from "node:test";
import { UniversalMcpResultStore } from "./mcp-result-store.js";

test("MCP result store pages bounded resources and expires them", () => {
  let now = 1_000;
  const store = new UniversalMcpResultStore({
    maximumEntries: 2,
    maximumTotalCharacters: 10_000,
    ttlMs: 1_000,
    now: () => now,
  });
  const stored = store.put({ payload: "x".repeat(200) });
  const first = store.readByUri(stored.resourceUri);
  assert.equal(first.truncated, false);
  assert.match(String(first.text), /payload/);

  const paged = store.read(stored.resultId, 0, 50);
  assert.equal(paged.truncated, true);
  assert.equal(typeof paged.nextResourceUri, "string");
  now = 2_001;
  assert.throws(() => store.readByUri(stored.resourceUri), hasCode("PATH_NOT_FOUND"));
});

test("MCP result store enforces total quotas with LRU eviction", () => {
  const store = new UniversalMcpResultStore({
    maximumEntries: 1,
    maximumTotalCharacters: 1_000,
    ttlMs: 10_000,
  });
  const first = store.put({ first: "a".repeat(100) });
  const second = store.put({ second: "b".repeat(100) });
  assert.throws(() => store.readByUri(first.resourceUri), hasCode("PATH_NOT_FOUND"));
  assert.doesNotThrow(() => store.readByUri(second.resourceUri));
});

function hasCode(code: string) {
  return (error: unknown) => error instanceof Error && "code" in error && error.code === code;
}
