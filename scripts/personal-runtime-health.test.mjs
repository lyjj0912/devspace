import assert from "node:assert/strict";
import { createServer } from "node:http";
import { test } from "node:test";
import { waitForHealthyPersonalRuntime } from "./lib/personal-runtime-health.mjs";

const REVISION = "a".repeat(40);

test("personal deployment health waits for a delayed listener instead of rolling back immediately", async (t) => {
  const port = await unusedPort();
  const server = createServer((_request, response) => {
    response.setHeader("Content-Type", "application/json");
    response.end(JSON.stringify({ productProfile: "PERSONAL_DIRECT_OWNER", runtimeRevision: REVISION }));
  });
  t.after(() => server.close());
  const startedAt = Date.now();
  const delayedListen = new Promise((resolve, reject) => {
    setTimeout(() => server.listen(port, "127.0.0.1", resolve), 150);
    server.once("error", reject);
  });
  const health = await waitForHealthyPersonalRuntime(`http://127.0.0.1:${port}/healthz`, REVISION, {
    timeoutMs: 2_000,
    requestTimeoutMs: 100,
    intervalMs: 25,
  });
  await delayedListen;
  assert.equal(health.productProfile, "PERSONAL_DIRECT_OWNER");
  assert.ok(Date.now() - startedAt >= 100);
});

test("personal deployment health remains fail-closed after the bounded deadline", async (t) => {
  const server = createServer((_request, response) => {
    response.setHeader("Content-Type", "application/json");
    response.end(JSON.stringify({ productProfile: "BASE_SINGLE_OWNER", runtimeRevision: REVISION }));
  });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  t.after(() => server.close());
  const address = server.address();
  await assert.rejects(
    waitForHealthyPersonalRuntime(`http://127.0.0.1:${address.port}/healthz`, REVISION, {
      timeoutMs: 150,
      requestTimeoutMs: 50,
      intervalMs: 20,
    }),
    /did not converge within 150ms/u,
  );
});

async function unusedPort() {
  const server = createServer();
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  const address = server.address();
  await new Promise((resolve, reject) => server.close((error) => error ? reject(error) : resolve()));
  return address.port;
}
