import assert from "node:assert/strict";
import test from "node:test";
import { UniversalBrokerError } from "./errors.js";
import { UniversalToolRequestReplayGuard } from "./request-replay-guard.js";

const base = {
  principalFingerprint: "a".repeat(64),
  scopes: ["devspace.read", "devspace.write"],
  requestId: "rpc-1",
  tool: "fs",
  arguments: { operation: "write", path: "/tmp/example", content: "one" },
};

test("identical in-flight requests coalesce and terminal retries replay", async () => {
  const guard = new UniversalToolRequestReplayGuard();
  let dispatches = 0;
  let release!: () => void;
  const gate = new Promise<void>((resolve) => { release = resolve; });
  const dispatch = async () => {
    dispatches += 1;
    await gate;
    return { ok: true, operationId: "op-one" };
  };
  const first = guard.execute(base, dispatch);
  const second = guard.execute(base, dispatch);
  release();
  const [firstResult, secondResult] = await Promise.all([first, second]);
  assert.equal(dispatches, 1);
  assert.deepEqual(
    new Set([firstResult.disposition, secondResult.disposition]),
    new Set(["EXECUTED", "COALESCED"]),
  );
  const replayed = await guard.execute(base, dispatch);
  assert.equal(replayed.disposition, "REPLAYED");
  assert.equal(dispatches, 1);
  assert.deepEqual(guard.stats(), {
    entries: 1,
    inFlight: 0,
    executed: 1,
    coalesced: 1,
    replayed: 1,
    conflicts: 0,
    evicted: 0,
  });
});

test("an in-flight JSON-RPC id collision with different arguments fails before dispatch", async () => {
  const guard = new UniversalToolRequestReplayGuard();
  let dispatches = 0;
  let release!: () => void;
  const gate = new Promise<void>((resolve) => { release = resolve; });
  const first = guard.execute(base, async () => {
    dispatches += 1;
    await gate;
    return { ok: true };
  });
  await assert.rejects(
    guard.execute({
      ...base,
      arguments: { ...base.arguments, content: "two" },
    }, async () => {
      dispatches += 1;
      return { ok: true };
    }),
    (error: unknown) => error instanceof UniversalBrokerError
      && error.code === "PRECONDITION_FAILED"
      && error.evidence?.providerDispatchCount === 0,
  );
  release();
  await first;
  assert.equal(dispatches, 1);
  assert.equal(guard.stats().conflicts, 1);
});

test("a recently completed JSON-RPC id cannot be rebound to different arguments", async () => {
  const guard = new UniversalToolRequestReplayGuard();
  let dispatches = 0;
  await guard.execute(base, async () => ({ ok: true, count: ++dispatches }));
  await assert.rejects(
    guard.execute({
      ...base,
      arguments: { ...base.arguments, content: "different-after-completion" },
    }, async () => ({ ok: true, count: ++dispatches })),
    (error: unknown) => error instanceof UniversalBrokerError
      && error.code === "PRECONDITION_FAILED"
      && error.evidence?.providerDispatchCount === 0,
  );
  assert.equal(dispatches, 1);
});

test("principal and scope identities never share replay state", async () => {
  const guard = new UniversalToolRequestReplayGuard();
  let dispatches = 0;
  const dispatch = async () => ({ sequence: ++dispatches });
  const first = await guard.execute(base, dispatch);
  const differentPrincipal = await guard.execute({
    ...base,
    principalFingerprint: "b".repeat(64),
  }, dispatch);
  const differentScopes = await guard.execute({
    ...base,
    scopes: ["devspace.read"],
  }, dispatch);
  assert.deepEqual(
    [first.value.sequence, differentPrincipal.value.sequence, differentScopes.value.sequence],
    [1, 2, 3],
  );
});

test("normal terminal entries expire while UNKNOWN results retain a longer no-replay tombstone", async () => {
  let now = 1_000;
  const guard = new UniversalToolRequestReplayGuard({
    now: () => now,
    terminalTtlMs: 10,
    unknownTtlMs: 100,
  });
  let normalDispatches = 0;
  await guard.execute(base, async () => ({ state: "PASS", count: ++normalDispatches }));
  now += 11;
  const normalAgain = await guard.execute(base, async () => ({
    state: "PASS",
    count: ++normalDispatches,
  }));
  assert.equal(normalAgain.disposition, "EXECUTED");
  assert.equal(normalDispatches, 2);

  const unknownIdentity = { ...base, requestId: "rpc-unknown" };
  let unknownDispatches = 0;
  await guard.execute(
    unknownIdentity,
    async () => ({ state: "UNKNOWN", count: ++unknownDispatches }),
    (value) => value.state === "UNKNOWN",
  );
  now += 11;
  const unknownAgain = await guard.execute(
    unknownIdentity,
    async () => ({ state: "UNKNOWN", count: ++unknownDispatches }),
    (value) => value.state === "UNKNOWN",
  );
  assert.equal(unknownAgain.disposition, "REPLAYED");
  assert.equal(unknownDispatches, 1);
});
