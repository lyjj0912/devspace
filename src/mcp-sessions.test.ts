import assert from "node:assert/strict";
import { McpSessionRegistry } from "./mcp-sessions.js";

interface FakeTransport {
  closeCalls: number;
  close(): Promise<void>;
}

function createTransport(closeError?: Error): FakeTransport {
  return {
    closeCalls: 0,
    async close() {
      this.closeCalls += 1;
      if (closeError) throw closeError;
    },
  };
}

{
  let churnNow = 0;
  const churnRegistry = new McpSessionRegistry<FakeTransport>({ now: () => churnNow });
  const abandoned = Array.from({ length: 100 }, () => createTransport());
  abandoned.forEach((transport, index) => churnRegistry.register(`abandoned-${index}`, transport));
  const reused = createTransport();
  churnRegistry.register("reused", reused);

  churnNow = 9 * 60 * 1_000;
  assert.equal(churnRegistry.get("reused"), reused);
  churnNow = 11 * 60 * 1_000;
  const churnResults = await churnRegistry.closeIdle(10 * 60 * 1_000);
  assert.equal(churnResults.length, 100);
  assert.equal(abandoned.every((transport) => transport.closeCalls === 1), true);
  assert.equal(reused.closeCalls, 0);
  assert.equal(churnRegistry.size, 1);
}

let now = 0;
const registry = new McpSessionRegistry<FakeTransport>({ now: () => now });
const staleTransport = createTransport();
const activeTransport = createTransport();

registry.register("stale", staleTransport);
now = 1_000;
registry.register("active", activeTransport);
now = 1_500;
assert.equal(registry.get("active"), activeTransport);
now = 2_000;

const idleResults = await registry.closeIdle(1_500);
assert.deepEqual(idleResults, [{ sessionId: "stale" }]);
assert.equal(staleTransport.closeCalls, 1);
assert.equal(activeTransport.closeCalls, 0);
assert.equal(registry.size, 1);
assert.equal(registry.get("stale"), undefined);
assert.equal(registry.get("active"), activeTransport);

const closeError = new Error("close failed");
const failingTransport = createTransport(closeError);
registry.register("failing", failingTransport);
now = 10_000;

const failingResults = await registry.closeIdle(1);
assert.equal(failingResults.length, 2);
assert.deepEqual(failingResults.map((result) => result.sessionId).sort(), ["active", "failing"]);
assert.equal(failingResults.find((result) => result.sessionId === "failing")?.error, closeError);
assert.equal(failingTransport.closeCalls, 1);
assert.equal(registry.size, 0);

const first = createTransport();
const second = createTransport();
registry.register("first", first);
registry.register("second", second);
registry.remove("first");

const shutdownResults = await registry.closeAll();
assert.deepEqual(shutdownResults, [{ sessionId: "second" }]);
assert.equal(first.closeCalls, 0);
assert.equal(second.closeCalls, 1);
assert.equal(registry.size, 0);

let finishDelayedClose: (() => void) | undefined;
let delayedCloseResolved = false;
const delayedTransport: FakeTransport = {
  closeCalls: 0,
  close() {
    this.closeCalls += 1;
    return new Promise<void>((resolve) => {
      finishDelayedClose = resolve;
    });
  },
};
registry.register("delayed", delayedTransport);
const delayedClose = registry.closeAll();
void delayedClose.then(() => {
  delayedCloseResolved = true;
});

await Promise.resolve();
assert.equal(delayedCloseResolved, false);
assert.equal(delayedTransport.closeCalls, 1);
finishDelayedClose?.();
await delayedClose;
assert.equal(delayedCloseResolved, true);
assert.equal(registry.size, 0);

{
  let quotaNow = 0;
  const quota = new McpSessionRegistry<FakeTransport>({
    now: () => quotaNow,
    maximumSessions: 2,
  });
  const firstQuota = createTransport();
  const secondQuota = createTransport();
  quota.register("first", firstQuota);
  quotaNow = 1;
  quota.register("second", secondQuota);
  assert.throws(() => quota.register("third", createTransport()), /quota is full/);
  const closed = await quota.closeLeastRecentlyUsed(1);
  assert.deepEqual(closed, [{ sessionId: "first" }]);
  assert.equal(firstQuota.closeCalls, 1);
  assert.equal(secondQuota.closeCalls, 0);
  quota.register("third", createTransport());
  assert.equal(quota.size, 2);
}

{
  let activeNow = 0;
  const activeRegistry = new McpSessionRegistry<FakeTransport>({
    now: () => activeNow,
    maximumSessions: 2,
  });
  const activeRequest = createTransport();
  const idle = createTransport();
  activeRegistry.register("active-request", activeRequest);
  activeNow = 1;
  activeRegistry.register("idle", idle);
  activeRegistry.acquire("active-request");
  activeNow = 10_000;
  const closed = await activeRegistry.closeIdle(1);
  assert.deepEqual(closed, [{ sessionId: "idle" }]);
  assert.equal(activeRequest.closeCalls, 0);
  assert.equal((await activeRegistry.closeLeastRecentlyUsed(1)).length, 0);
  activeRegistry.release("active-request");
  assert.deepEqual(await activeRegistry.closeLeastRecentlyUsed(1), [{ sessionId: "active-request" }]);
}
