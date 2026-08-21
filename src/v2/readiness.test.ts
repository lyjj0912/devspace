import assert from "node:assert/strict";
import { mkdir, mkdtemp, realpath, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import Database from "better-sqlite3";
import {
  ReadinessRegistry,
  baseMutableSqliteStoreReadiness,
  canonicalConnectorReadinessObservation,
  personalConnectorReadinessObservation,
  type ReadinessCheck,
} from "./readiness.js";
import { loadOrCreateManagementAuthorizationKey } from "./management-authorization.js";
import {
  createFinalizationStoreBootstrapAuthorization,
  initializeFinalizationStore,
} from "../../scripts/lib/finalization-store-contract.mjs";

test("readiness executes only declared read-only checks and is ready only when all PASS", async () => {
  let mutationCalls = 0;
  const checks: ReadinessCheck[] = [
    {
      id: "manifest",
      sideEffectFree: true,
      check(context) {
        assert.equal(context.mode, "READ_ONLY");
        assert.equal(Object.isFrozen(context), true);
        return Promise.resolve({ state: "PASS", evidence: { generation: "manifest-1" } });
      },
    },
    {
      id: "authority_store",
      sideEffectFree: true,
      check() {
        return Promise.resolve({ state: "PASS" });
      },
    },
  ];
  const report = await new ReadinessRegistry(checks).evaluate();
  assert.equal(report.status, "ready");
  assert.equal(report.httpStatus, 200);
  assert.equal(report.checks.length, 2);
  assert.equal(mutationCalls, 0);
});

test("FAIL, throw, and timeout are fail-closed and never promoted to ready", async () => {
  const failing = await new ReadinessRegistry([
    check("non_root", { state: "FAIL", summary: "running as root" }),
  ]).evaluate();
  assert.equal(failing.status, "not_ready");
  assert.equal(failing.httpStatus, 503);

  const thrown = await new ReadinessRegistry([{
    id: "store",
    sideEffectFree: true,
    check() {
      throw new Error("store unavailable");
    },
  }]).evaluate();
  assert.equal(thrown.checks[0]?.state, "UNKNOWN");
  assert.match(thrown.checks[0]?.summary ?? "", /store unavailable/u);

  const timedOut = await new ReadinessRegistry([{
    id: "supervisor",
    sideEffectFree: true,
    timeoutMs: 5,
    check: () => new Promise(() => undefined),
  }], { maximumDurationMs: 50, defaultCheckTimeoutMs: 5 }).evaluate();
  assert.equal(timedOut.status, "not_ready");
  assert.equal(timedOut.checks[0]?.state, "UNKNOWN");
  assert.match(timedOut.checks[0]?.summary ?? "", /timed out/u);
});

test("registration rejects mutation canaries and duplicate check identities", () => {
  assert.throws(() => new ReadinessRegistry([]), /at least one/u);
  assert.throws(() => new ReadinessRegistry([{
    id: "mutation_canary",
    sideEffectFree: false,
    check: async () => ({ state: "PASS" }),
  }]), /side-effect-free/u);
  assert.throws(() => new ReadinessRegistry([
    check("store", { state: "PASS" }),
    check("store", { state: "PASS" }),
  ]), /duplicate readiness check/iu);
});

test("parallel readiness accepts only the consistent pre-activation connector state", () => {
  const emptyConnector = {
    state: "FAIL" as const,
    activeCount: 0,
    bindingsByState: { ACTIVE: 0 },
    invalidStates: ["ACTIVE_COUNT"],
  };
  const parallel = canonicalConnectorReadinessObservation("parallel", emptyConnector);
  assert.equal(parallel.state, "PASS");
  assert.equal(parallel.evidence?.activationState, "PENDING");

  const production = canonicalConnectorReadinessObservation("production", emptyConnector);
  assert.equal(production.state, "FAIL");

  assert.equal(canonicalConnectorReadinessObservation("production", {
    state: "FAIL",
    activeCount: 1,
    bindingsByState: { ACTIVE: 1 },
    invalidStates: ["PREPARED_RECEIPT_MISMATCH"],
  }).state, "FAIL");

  const inconsistentParallel = canonicalConnectorReadinessObservation("parallel", {
    ...emptyConnector,
    invalidStates: ["ACTIVE_COUNT", "PREPARED_RECEIPT_MISMATCH"],
  });
  assert.equal(inconsistentParallel.state, "FAIL");

  const activeParallel = canonicalConnectorReadinessObservation("parallel", {
    state: "PASS",
    activeCount: 1,
    bindingsByState: { ACTIVE: 1 },
    invalidStates: [],
  });
  assert.equal(activeParallel.state, "PASS");
  assert.equal(activeParallel.evidence?.activationState, "ACTIVE");
});

test("Personal readiness has no production legacy-fixture bypass", () => {
  const empty = {
    state: "FAIL" as const,
    activeCount: 0,
    bindingsByState: {
      REGISTERED: 0,
      CANDIDATE: 0,
      VERIFIED: 0,
      ACTIVATION_PREPARED: 0,
      ACTIVE: 0,
      DRAINING: 0,
      RETIRED: 0,
      REJECTED: 0,
      FAILED: 0,
    },
    invalidStates: ["ACTIVE_COUNT"],
    expectedInstallationEpoch: 3,
    activeFamilyCount: 0,
    activeRefreshTokenCount: 0,
    activePersistedTokenCount: 0,
    overdueDrainingCount: 0,
    unboundActiveFamilyCount: 0,
    nonActiveTokenFamilyCount: 0,
    preparedReceiptCount: 0,
  };
  assert.equal(personalConnectorReadinessObservation("parallel", empty).state, "PASS");
  assert.equal(
    personalConnectorReadinessObservation("parallel", empty).evidence?.activationState,
    "PENDING",
  );
  assert.equal(personalConnectorReadinessObservation("production", empty).state, "FAIL");

  const active = {
    ...empty,
    state: "PASS" as const,
    activeCount: 1,
    bindingsByState: { ...empty.bindingsByState, ACTIVE: 1 },
    invalidStates: [],
    activeInstallationEpoch: 3,
    activeSchemaGeneration: `sha256:${"1".repeat(64)}`,
    activeBindingIdDigest: `sha256:${"2".repeat(64)}`,
    activeClientIdDigest: `sha256:${"3".repeat(64)}`,
    activeFamilyCount: 1,
    activeRefreshTokenCount: 1,
    activePersistedTokenCount: 2,
  };
  assert.equal(personalConnectorReadinessObservation("production", active).state, "PASS");
  assert.equal(
    personalConnectorReadinessObservation("production", active).evidence?.activationState,
    "ACTIVE",
  );
  const legacyInvalid = {
    ...active,
    state: "FAIL" as const,
    bindingsByState: { ...active.bindingsByState, DRAINING: 2 },
    invalidStates: ["DRAINING_DEADLINE_ELAPSED"],
    overdueDrainingCount: 2,
  };
  assert.equal(personalConnectorReadinessObservation("production", legacyInvalid).state, "FAIL");
  assert.equal(
    personalConnectorReadinessObservation("production", legacyInvalid).evidence?.activationState,
    "INVALID",
  );
});

test("personal readiness is gated only by the mutable stores used by the request path", async (t) => {
  const root = await realpath(await mkdtemp(join(tmpdir(), "devspace-base-store-readiness-")));
  t.after(() => rm(root, { recursive: true, force: true }));
  const artifactCatalogPath = join(root, "artifacts.sqlite");
  const filesystemSyncStorePath = join(root, "filesystem-sync", "sync.sqlite");
  const input = {
    artifactCatalogPath,
    filesystemSyncStorePath,
  };
  createSqliteStore(artifactCatalogPath, 1);

  const missingSync = baseMutableSqliteStoreReadiness(input);
  assert.equal(missingSync.state, "FAIL");
  assert.equal(syncObservation(missingSync)?.state, "FAIL");

  await mkdir(join(root, "filesystem-sync"), { recursive: true });
  createSqliteStore(filesystemSyncStorePath, 0);
  const incompleteSync = baseMutableSqliteStoreReadiness(input);
  assert.equal(incompleteSync.state, "FAIL");
  assert.match(syncObservation(incompleteSync)?.summary ?? "", /schema version is 0/u);

  createSqliteStore(filesystemSyncStorePath, 1);
  const complete = baseMutableSqliteStoreReadiness(input);
  assert.equal(complete.state, "PASS");
  assert.equal(storeObservation(complete, "connector-activation-journal"), undefined);
  assert.equal(storeObservation(complete, "lifecycle-finalization-store"), undefined);
  assert.equal(syncObservation(complete)?.state, "PASS");
});

function check(id: string, result: Awaited<ReturnType<ReadinessCheck["check"]>>): ReadinessCheck {
  return {
    id,
    sideEffectFree: true,
    check: async () => result,
  };
}

function createSqliteStore(path: string, userVersion: number): void {
  const database = new Database(path);
  try {
    database.pragma(`user_version = ${userVersion}`);
    database.exec("create table if not exists sentinel (value text)");
  } finally {
    database.close();
  }
}

function syncObservation(observation: { evidence?: Record<string, unknown> }) {
  return storeObservation(observation, "filesystem-sync");
}

function storeObservation(observation: { evidence?: Record<string, unknown> }, storeId: string) {
  const observations = observation.evidence?.observations;
  assert.equal(Array.isArray(observations), true);
  return (observations as Array<{ evidence?: Record<string, unknown> & { storeId?: string }; state?: string; summary?: string }>)
    .find((entry) => entry.evidence?.storeId === storeId);
}
