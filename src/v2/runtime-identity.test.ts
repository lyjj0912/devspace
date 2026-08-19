import assert from "node:assert/strict";
import test from "node:test";
import { createRuntimeIdentity, publicRuntimeHealth } from "./runtime-identity.js";

test("runtime identity is canonical, secret-free, and public health is minimal", () => {
  const left = createRuntimeIdentity({
    config: { port: 7677, oauth: { clientSecret: "alpha", scopes: ["read"] } },
    sourceRevision: "abc123",
    runtimeRevision: "runtime-a",
    startedAt: "2026-08-19T00:00:00.000Z",
  });
  const right = createRuntimeIdentity({
    config: { oauth: { scopes: ["read"], clientSecret: "beta" }, port: 7677 },
    sourceRevision: "abc123",
    runtimeRevision: "runtime-a",
    startedAt: "2026-08-19T00:00:00.000Z",
  });
  assert.equal(left.configDigest, right.configDigest);
  assert.match(left.schemaGeneration, /^sha256:[a-f0-9]{64}$/u);
  assert.match(left.authorityContractGeneration, /^sha256:[a-f0-9]{64}$/u);
  assert.deepEqual(Object.keys(publicRuntimeHealth(left)), [
    "status",
    "productVersion",
    "schemaGeneration",
    "authorityContractGeneration",
    "runtimeRevision",
    "startedAt",
  ]);
  assert.doesNotMatch(JSON.stringify(publicRuntimeHealth(left)), /alpha|beta|target|route/iu);
});
