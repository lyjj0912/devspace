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

  const legacyPersonal = canonicalConnectorReadinessObservation("production", {
    state: "FAIL",
    activeCount: 1,
    bindingsByState: { ACTIVE: 1, DRAINING: 2 },
    invalidStates: ["VERIFICATION_IDENTITY_INCOMPLETE", "DRAINING_DEADLINE_ELAPSED"],
  }, true);
  assert.equal(legacyPersonal.state, "PASS");
  assert.equal(legacyPersonal.evidence?.activationState, "LEGACY_ACTIVE");
  assert.equal(canonicalConnectorReadinessObservation("production", {
    state: "FAIL",
    activeCount: 1,
    bindingsByState: { ACTIVE: 1 },
    invalidStates: ["PREPARED_RECEIPT_MISMATCH"],
  }, true).state, "FAIL");

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

test("Base readiness uses the keyed finalization store and external control readback", async (t) => {
  const root = await realpath(await mkdtemp(join(tmpdir(), "devspace-base-store-readiness-")));
  t.after(() => rm(root, { recursive: true, force: true }));
  const authorityStorePath = join(root, "authority.sqlite");
  const artifactCatalogPath = join(root, "artifacts.sqlite");
  const filesystemSyncStorePath = join(root, "filesystem-sync", "sync.sqlite");
  const connectorActivationJournalPath = join(root, "connector-activation-journal.sqlite");
  const finalizationStateRoot = join(root, "finalization-state");
  const finalizationControlRoot = join(root, "finalization-control");
  const managementStateRoot = join(root, "management-state");
  await mkdir(finalizationStateRoot, { mode: 0o700 });
  await mkdir(finalizationControlRoot, { mode: 0o700 });
  await mkdir(managementStateRoot, { mode: 0o700 });
  const lifecycleFinalizationStorePath = join(finalizationStateRoot, "lifecycle.sqlite");
  const lifecycleFinalizationControlPath = join(
    finalizationControlRoot,
    "lifecycle-finalization-head.json",
  );
  const finalizationManagementKey = loadOrCreateManagementAuthorizationKey({
    keyRef: "readiness-test",
    stateDir: managementStateRoot,
  });
  const input = {
    authorityStorePath,
    artifactCatalogPath,
    filesystemSyncStorePath,
    connectorActivationJournalPath,
    lifecycleFinalizationStorePath,
    lifecycleFinalizationControlPath,
    finalizationManagementKey,
  };
  createSqliteStore(authorityStorePath, 7);
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
  const missingJournal = baseMutableSqliteStoreReadiness(input);
  assert.equal(missingJournal.state, "FAIL");
  assert.equal(storeObservation(missingJournal, "connector-activation-journal")?.state, "FAIL");

  createSqliteStore(connectorActivationJournalPath, 1);
  const ready = baseMutableSqliteStoreReadiness(input);
  assert.equal(ready.state, "FAIL");
  assert.equal(storeObservation(ready, "lifecycle-finalization-store")?.state, "FAIL");

  const bootstrapAuthorization = createFinalizationStoreBootstrapAuthorization({
    storePath: lifecycleFinalizationStorePath,
    controlPath: lifecycleFinalizationControlPath,
    key: finalizationManagementKey,
  });
  initializeFinalizationStore({
    storePath: lifecycleFinalizationStorePath,
    controlPath: lifecycleFinalizationControlPath,
    key: finalizationManagementKey,
    bootstrapAuthorization,
  });
  const complete = baseMutableSqliteStoreReadiness(input);
  assert.equal(complete.state, "PASS");
  assert.equal(storeObservation(complete, "lifecycle-finalization-store")?.state, "PASS");
  assert.equal(
    storeObservation(complete, "lifecycle-finalization-store")?.evidence?.schemaVersion,
    2,
  );
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
