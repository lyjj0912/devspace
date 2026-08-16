import assert from "node:assert/strict";
import test from "node:test";
import { UniversalTextResourceStore } from "./text-resource-store.js";

test("text resource store pages and expires resources", () => {
  let now = 1_000;
  const store = new UniversalTextResourceStore({
    authority: "context-diff",
    ttlMs: 1_000,
    defaultPageCharacters: 4,
    now: () => now,
  });
  const stored = store.put("abcdefgh", "text/x-diff");
  const first = store.readByUri(stored.resourceUri);
  assert.equal(first.text, "abcd");
  assert.equal(first.nextResourceUri, `devspace://context-diff/${stored.resourceId}/4/4`);
  now = 2_001;
  assert.throws(() => store.readByUri(stored.resourceUri), hasCode("PATH_NOT_FOUND"));
});

test("text resource store enforces LRU quotas", () => {
  let now = 1_000;
  const store = new UniversalTextResourceStore({
    authority: "context-diff",
    maximumEntries: 1,
    maximumTotalCharacters: 1_000,
    now: () => now,
  });
  const first = store.put("first");
  now += 1;
  const second = store.put("second");
  assert.throws(() => store.readByUri(first.resourceUri), hasCode("PATH_NOT_FOUND"));
  assert.doesNotThrow(() => store.readByUri(second.resourceUri));
});

function hasCode(code: string) {
  return (error: unknown) => error instanceof Error
    && "code" in error
    && error.code === code;
}
