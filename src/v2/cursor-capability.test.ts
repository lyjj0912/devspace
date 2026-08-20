import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { performance } from "node:perf_hooks";
import test from "node:test";
import {
  CursorCapabilityError,
  SignedSnapshotCursorStore,
  cursorFailure,
  type CursorBinding,
} from "./cursor-capability.js";
import { UniversalBrokerMetrics } from "./metrics.js";

const OWNER_A = digest("owner-a");
const OWNER_B = digest("owner-b");
const RESOURCE = digest("target-registry");
const QUERY = digest("all-targets");

test("signed snapshots retain stable ordering and reject tamper or binding drift", () => {
  const clock = { value: 1_787_200_000_000 };
  const store = cursorStore(clock);
  const identities = ["target-a", "target-b", "target-c"];
  const first = store.createSnapshot({
    binding: binding(),
    orderedItemIdentities: identities,
    limit: 2,
  });

  identities.splice(0, identities.length, "replacement");
  assert.deepEqual(first.itemIdentities, ["target-a", "target-b"]);
  assert.equal(typeof first.nextCursor, "string");
  assert.equal(first.nextCursor?.includes("target-c"), false);

  const next = store.continueSnapshot({
    cursor: first.nextCursor!,
    binding: binding(),
  });
  assert.deepEqual(next.itemIdentities, ["target-c"]);
  assert.equal(next.nextCursor, undefined);

  assert.throws(
    () => store.continueSnapshot({
      cursor: `${first.nextCursor!.slice(0, -1)}x`,
      binding: binding(),
    }),
    hasReason("CURSOR_INVALID"),
  );
  assert.throws(
    () => store.continueSnapshot({
      cursor: first.nextCursor!,
      binding: binding({ resourceIdentityDigest: digest("another-resource") }),
    }),
    hasReason("CURSOR_INVALID"),
  );
  assert.throws(
    () => store.continueSnapshot({
      cursor: first.nextCursor!,
      binding: binding({ queryDigest: digest("another-query") }),
    }),
    hasReason("CURSOR_INVALID"),
  );
  assert.throws(
    () => store.continueSnapshot({
      cursor: first.nextCursor!,
      binding: binding({ principalKeyFingerprint: OWNER_B }),
    }),
    hasReason("CURSOR_INVALID"),
  );
  assert.throws(
    () => store.continueSnapshot({
      cursor: first.nextCursor!,
      binding: binding({ snapshotGeneration: digest("generation-b") }),
    }),
    hasReason("CURSOR_STALE"),
  );
});

test("cursor limit may shrink but never increase", () => {
  const store = cursorStore({ value: 1_787_200_100_000 });
  const first = store.createSnapshot({
    binding: binding(),
    orderedItemIdentities: ["a", "b", "c", "d"],
    limit: 3,
  });
  const shrunk = store.continueSnapshot({
    cursor: first.nextCursor!,
    binding: binding(),
    limit: 1,
  });
  assert.deepEqual(shrunk.itemIdentities, ["d"]);

  const another = store.createSnapshot({
    binding: binding(),
    orderedItemIdentities: ["a", "b", "c"],
    limit: 1,
  });
  assert.throws(
    () => store.continueSnapshot({
      cursor: another.nextCursor!,
      binding: binding(),
      limit: 2,
    }),
    hasReason("CURSOR_INVALID"),
  );
});

test("current and previous keys verify, but a restarted ephemeral store returns stale", () => {
  const clock = { value: 1_787_200_200_000 };
  const oldKey = { keyId: "cursor-old", secret: Buffer.alloc(32, 0x11) };
  const newKey = { keyId: "cursor-new", secret: Buffer.alloc(32, 0x22) };
  const original = new SignedSnapshotCursorStore({
    currentKey: oldKey,
    ttlMs: 60_000,
    maximumSnapshotsPerPrincipal: 4,
    now: () => clock.value,
  });
  const first = original.createSnapshot({
    binding: binding(),
    orderedItemIdentities: ["a", "b"],
    limit: 1,
  });

  const restarted = new SignedSnapshotCursorStore({
    currentKey: newKey,
    previousKey: oldKey,
    ttlMs: 60_000,
    maximumSnapshotsPerPrincipal: 4,
    now: () => clock.value,
  });
  assert.throws(
    () => restarted.continueSnapshot({
      cursor: first.nextCursor!,
      binding: binding(),
    }),
    hasReason("CURSOR_STALE"),
  );
});

test("snapshot quota never evicts a live capability and expired cursors are typed", () => {
  const clock = { value: 1_787_200_300_000 };
  const store = new SignedSnapshotCursorStore({
    currentKey: { keyId: "cursor-current", secret: Buffer.alloc(32, 0x33) },
    ttlMs: 1_000,
    maximumSnapshotsPerPrincipal: 1,
    now: () => clock.value,
  });
  const first = store.createSnapshot({
    binding: binding(),
    orderedItemIdentities: ["a", "b"],
    limit: 1,
  });
  assert.throws(
    () => store.createSnapshot({
      binding: binding(),
      orderedItemIdentities: ["c", "d"],
      limit: 1,
    }),
    hasReason("CURSOR_QUOTA_EXCEEDED"),
  );
  assert.deepEqual(
    store.continueSnapshot({ cursor: first.nextCursor!, binding: binding() }).itemIdentities,
    ["b"],
  );

  clock.value += 1_001;
  assert.throws(
    () => store.continueSnapshot({ cursor: first.nextCursor!, binding: binding() }),
    hasReason("CURSOR_EXPIRED"),
  );
  assert.doesNotThrow(() => store.createSnapshot({
    binding: binding(),
    orderedItemIdentities: ["c"],
    limit: 1,
  }));
});

test("typed cursor errors expose a contract adapter without leaking the cursor", () => {
  const error = new CursorCapabilityError("CURSOR_STALE", "snapshot missing", {
    resourceKind: "target",
  });
  assert.deepEqual(cursorFailure(error), {
    reason: "CURSOR_STALE",
    retryable: false,
    evidence: { resourceKind: "target" },
  });
  assert.equal(cursorFailure(new Error("other")), undefined);
});

test("cursor metrics use bounded resource labels and never replace cursor outcomes", () => {
  const metrics = new UniversalBrokerMetrics();
  const clock = { value: 1_787_200_350_000 };
  const store = new SignedSnapshotCursorStore({
    currentKey: { keyId: "cursor-current", secret: Buffer.alloc(32, 0x55) },
    ttlMs: 1_000,
    maximumSnapshotsPerPrincipal: 1,
    now: () => clock.value,
    metrics,
  });
  const first = store.createSnapshot({
    binding: binding(),
    orderedItemIdentities: ["a", "b"],
    limit: 1,
  });
  assert.deepEqual(
    store.continueSnapshot({ cursor: first.nextCursor!, binding: binding() }).itemIdentities,
    ["b"],
  );
  assert.throws(
    () => store.createSnapshot({
      binding: binding(),
      orderedItemIdentities: ["c", "d"],
      limit: 1,
    }),
    hasReason("CURSOR_QUOTA_EXCEEDED"),
  );
  assert.throws(
    () => store.continueSnapshot({
      cursor: `${first.nextCursor!.slice(0, -1)}x`,
      binding: binding(),
    }),
    hasReason("CURSOR_INVALID"),
  );
  const rendered = metrics.render({});
  assert.match(rendered, /devspace_cursor_events_total\{resource_kind="target",result="issued"\} 1/u);
  assert.match(rendered, /devspace_cursor_events_total\{resource_kind="target",result="accepted"\} 1/u);
  assert.match(rendered, /devspace_cursor_events_total\{resource_kind="target",result="rejected"\} 2/u);
  assert.match(rendered, /devspace_quota_rejections_total\{resource_kind="cursor"\} 1/u);

  const throwingMetrics = {
    recordCursorEvent: () => { throw new Error("metrics unavailable"); },
    recordQuotaRejection: () => { throw new Error("metrics unavailable"); },
  } as unknown as UniversalBrokerMetrics;
  const resilient = new SignedSnapshotCursorStore({
    currentKey: { keyId: "cursor-resilient", secret: Buffer.alloc(32, 0x66) },
    ttlMs: 1_000,
    maximumSnapshotsPerPrincipal: 1,
    now: () => clock.value,
    metrics: throwingMetrics,
  });
  assert.equal(resilient.createSnapshot({
    binding: binding(),
    orderedItemIdentities: ["a", "b"],
    limit: 1,
  }).itemIdentities[0], "a");
});

test("100,000-entry snapshot cursor verification remains within the 5ms p95 NFR", () => {
  const store = cursorStore({ value: 1_787_200_400_000 });
  const first = store.createSnapshot({
    binding: binding(),
    orderedItemIdentities: Array.from({ length: 100_000 }, (_, index) => `item-${index}`),
    limit: 100,
  });
  const samples: number[] = [];
  for (let index = 0; index < 250; index += 1) {
    const started = performance.now();
    const page = store.continueSnapshot({ cursor: first.nextCursor!, binding: binding() });
    samples.push(performance.now() - started);
    assert.equal(page.itemIdentities[0], "item-100");
  }
  samples.sort((left, right) => left - right);
  const p95 = samples[Math.ceil(samples.length * 0.95) - 1]!;
  assert.equal(p95 <= 5, true, `cursor verification p95 was ${p95.toFixed(3)}ms`);
});

function cursorStore(clock: { value: number }): SignedSnapshotCursorStore {
  return new SignedSnapshotCursorStore({
    currentKey: { keyId: "cursor-current", secret: Buffer.alloc(32, 0x44) },
    ttlMs: 60_000,
    maximumSnapshotsPerPrincipal: 4,
    now: () => clock.value,
  });
}

function binding(overrides: Partial<CursorBinding> = {}): CursorBinding {
  return {
    principalKeyFingerprint: OWNER_A,
    resourceKind: "target",
    resourceIdentityDigest: RESOURCE,
    queryDigest: QUERY,
    snapshotGeneration: digest("generation-a"),
    ...overrides,
  };
}

function digest(value: string): string {
  return createHash("sha256").update(value).digest("hex");
}

function hasReason(reason: string) {
  return (error: unknown) => error instanceof CursorCapabilityError && error.reason === reason;
}
