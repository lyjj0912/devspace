import assert from "node:assert/strict";
import test from "node:test";
import {
  assertPersonalProductionReadback,
  createPersonalUpgradePlan,
  type PersonalRuntimeCandidate,
  type PersonalUpgradeInput,
} from "./personal-upgrade.js";

const candidate: PersonalRuntimeCandidate = {
  productProfile: "PERSONAL_DIRECT_OWNER",
  publicOrigin: "https://devspace.example.test",
  oauthClientId: "existing-client",
  oauthResource: "https://devspace.example.test/mcp",
  ownerInstanceId: "existing-owner",
  connectorName: "myDevSpace",
  connectorInstallationEpoch: 7,
  runtimePath: "/releases/candidate",
  sourceRevision: "source-2",
  runtimeRevision: "runtime-2",
  buildDigest: "sha256:" + "a".repeat(64),
};

function input(overrides: Partial<PersonalUpgradeInput> = {}): PersonalUpgradeInput {
  return {
    existing: { ...candidate, runtimePath: "/releases/current-runtime" },
    candidate,
    stores: [],
    currentRuntimePointer: "/releases/current",
    ...overrides,
  };
}

test("runtime-only personal upgrade preserves connector/client/origin and creates no store snapshot", () => {
  const plan = createPersonalUpgradePlan(input());
  assert.equal(plan.productProfile, "PERSONAL_DIRECT_OWNER");
  assert.equal(plan.identityAction, "PRESERVE_EXISTING_BINDING");
  assert.equal(plan.migrationRequired, false);
  assert.deepEqual(plan.backupSet, []);
  assert.equal(plan.phases.includes("ATOMIC_CURRENT_POINTER_SWITCH"), true);
  assert.equal(JSON.stringify(plan).match(/authority|activation|finalization|drain/giu), null);
});

test("store backup set contains only changed stores and their actual dependencies", () => {
  const plan = createPersonalUpgradePlan(input({
    stores: [
      { id: "artifact-objects", path: "/state/artifact-objects", kind: "directory", changed: false },
      {
        id: "artifact-catalog",
        path: "/state/artifacts.sqlite",
        kind: "sqlite",
        changed: true,
        dependsOn: ["artifact-objects"],
      },
      { id: "contexts", path: "/state/contexts.json", kind: "file", changed: false },
    ],
  }));
  assert.equal(plan.migrationRequired, true);
  assert.deepEqual(plan.backupSet.map((store) => store.id), ["artifact-catalog", "artifact-objects"]);
  assert.deepEqual(plan.rollback.restoreStores, ["artifact-catalog", "artifact-objects"]);
});

test("runtime-only plan rejects connector, client, resource, owner, or origin drift", () => {
  for (const drift of [
    { connectorName: "replacement" },
    { oauthClientId: "new-client" },
    { oauthResource: "https://other.example.test/mcp" },
    { ownerInstanceId: "other-owner" },
    { publicOrigin: "https://other.example.test" },
  ]) {
    assert.throws(
      () => createPersonalUpgradePlan(input({ candidate: { ...candidate, ...drift } })),
      /cannot change/u,
    );
  }
});

test("production readback requires the candidate runtime, one production, and zero candidates", () => {
  assert.doesNotThrow(() => assertPersonalProductionReadback(candidate, {
    ...candidate,
    productionInstances: 1,
    candidateInstances: 0,
  }));
  assert.throws(() => assertPersonalProductionReadback(candidate, {
    ...candidate,
    productionInstances: 1,
    candidateInstances: 1,
  }), /one production runtime and zero candidates/u);
});
