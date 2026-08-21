import assert from "node:assert/strict";
import test from "node:test";
import type { RuntimeIdentity } from "./contracts.js";
import {
  connectorEnvironmentIdentityDigest,
  connectorProductionRouteIdentityReadback,
  connectorRouteIdentityDigest,
  connectorRuntimeIdentityDigest,
} from "./connector-route-identity.js";

const runtimeIdentity: RuntimeIdentity = Object.freeze({
  productVersion: "2.1.1",
  productProfile: "PERSONAL_DIRECT_OWNER",
  buildCapabilityDigest: `sha256:${"1".repeat(64)}`,
  resourceUriVersion: "v1",
  schemaGeneration: `sha256:${"2".repeat(64)}`,
  authorityContractGeneration: `sha256:${"3".repeat(64)}`,
  configDigest: `sha256:${"4".repeat(64)}`,
  sourceRevision: "source-revision",
  runtimeRevision: "runtime-revision",
  buildDigest: `sha256:${"5".repeat(64)}`,
  startedAt: "2026-08-20T00:00:00.000Z",
});

test("connector route readback derives every digest from runtime, route, and ACTIVE binding", () => {
  const readback = connectorProductionRouteIdentityReadback({
    runtimeIdentity,
    oauthResource: "https://broker.example/mcp",
    canonicalName: "myDevSpace",
    bindingId: "binding-active-1",
  });
  assert.deepEqual(readback, {
    schemaVersion: 1,
    state: "ACTIVE",
    routeCount: 1,
    canonicalName: "myDevSpace",
    bindingId: "binding-active-1",
    runtimeIdentityDigest: connectorRuntimeIdentityDigest(runtimeIdentity),
    productionEnvironmentIdentityDigest: connectorEnvironmentIdentityDigest({
      environmentRole: "PRODUCTION",
      runtimeIdentityDigest: connectorRuntimeIdentityDigest(runtimeIdentity),
      oauthResource: "https://broker.example/mcp",
    }),
    productionRouteIdentityDigest: connectorRouteIdentityDigest({
      oauthResource: "https://broker.example/mcp",
      canonicalName: "myDevSpace",
      bindingId: "binding-active-1",
    }),
  });
  assert.notEqual(
    readback.productionRouteIdentityDigest,
    connectorRouteIdentityDigest({
      oauthResource: "https://broker.example/mcp",
      canonicalName: "myDevSpace",
      bindingId: "binding-active-2",
    }),
  );
});

test("connector route identity is canonical and rejects unsafe resources or malformed identities", () => {
  assert.equal(
    connectorRouteIdentityDigest({
      oauthResource: "https://broker.example:443/mcp",
      canonicalName: "myDevSpace",
      bindingId: "binding-active-1",
    }),
    connectorRouteIdentityDigest({
      oauthResource: "https://broker.example/mcp",
      canonicalName: "myDevSpace",
      bindingId: "binding-active-1",
    }),
  );
  assert.doesNotThrow(() => connectorEnvironmentIdentityDigest({
    environmentRole: "STAGING",
    runtimeIdentityDigest: connectorRuntimeIdentityDigest(runtimeIdentity),
    oauthResource: "http://127.0.0.1:7678/mcp",
  }));
  assert.throws(() => connectorRouteIdentityDigest({
    oauthResource: "http://broker.example/mcp",
    canonicalName: "myDevSpace",
    bindingId: "binding-active-1",
  }), /HTTPS or loopback HTTP/u);
  assert.throws(() => connectorRouteIdentityDigest({
    oauthResource: "https://broker.example/mcp#forged",
    canonicalName: "myDevSpace",
    bindingId: "binding-active-1",
  }), /without credentials or fragments/u);
  assert.throws(() => connectorRouteIdentityDigest({
    oauthResource: "https://broker.example/mcp",
    canonicalName: "myDevSpace",
    bindingId: "bad binding with spaces",
  }), /binding id is invalid/u);
});
