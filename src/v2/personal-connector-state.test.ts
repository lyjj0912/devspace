import assert from "node:assert/strict";
import { createHash, randomUUID } from "node:crypto";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import {
  type ConnectorActivationAuthorityProof,
  type ConnectorActivationReceipt,
  type ConnectorBindingRecord,
  SqliteOAuthClientsStore,
  SqliteOAuthStore,
  connectorActivationAuthorityActionFingerprint,
  connectorActivationAuthorityResourceKeySha256,
  type PersonalConnectorExpectation,
} from "../oauth-store.js";
import { RUNTIME_AUTHORITY_CONTRACT_GENERATION } from "./runtime-contract-identity.js";

const RESOURCE = "http://127.0.0.1:17676/mcp";
const CANONICAL_NAME = "myDevSpace";
const SCHEMA_GENERATION = `sha256:${"7".repeat(64)}`;

test("Personal readiness accepts a migrated ACTIVE connector without enterprise verification identity", async (t) => {
  const fixture = await createFixture(t);
  const active = activate(fixture.store, fixture.clients, 3, SCHEMA_GENERATION, Date.now() + 60_000);
  saveBoundTokenPair(fixture.store, active, RESOURCE, "active-family");
  clearEnterpriseVerificationIdentity(fixture.store, active.bindingId);

  const readiness = fixture.store.personalConnectorReadiness(expectation(3), Date.now());
  assert.equal(readiness.state, "PASS", JSON.stringify(readiness));
  assert.deepEqual(readiness.invalidStates, []);
  assert.equal(readiness.activeCount, 1);
  assert.equal(readiness.activeInstallationEpoch, 3);
  assert.equal(readiness.activeFamilyCount, 1);
  assert.equal(readiness.activeRefreshTokenCount, 1);
  assert.equal(readiness.activePersistedTokenCount, 2);
  assert.match(readiness.activeBindingIdDigest ?? "", /^sha256:[a-f0-9]{64}$/u);
  assert.match(readiness.activeClientIdDigest ?? "", /^sha256:[a-f0-9]{64}$/u);
  assert.equal(JSON.stringify(readiness).includes(active.bindingId), false);
  assert.equal(JSON.stringify(readiness).includes(active.clientId), false);
});

test("Personal readiness rejects overdue DRAINING and unbound active token families", async (t) => {
  const fixture = await createFixture(t);
  const first = activate(fixture.store, fixture.clients, 1, digest("1"), Date.now() + 60_000);
  saveBoundTokenPair(fixture.store, first, RESOURCE, "first-family");
  const second = activate(fixture.store, fixture.clients, 3, SCHEMA_GENERATION, Date.now() - 1_000);
  saveBoundTokenPair(fixture.store, second, RESOURCE, "second-family");
  saveUnboundTokenPair(fixture.store, second.clientId, RESOURCE, "unbound-family");
  clearEnterpriseVerificationIdentity(fixture.store, first.bindingId);
  clearEnterpriseVerificationIdentity(fixture.store, second.bindingId);

  const readiness = fixture.store.personalConnectorReadiness(expectation(3), Date.now());
  assert.equal(readiness.state, "FAIL");
  assert.equal(readiness.overdueDrainingCount, 1);
  assert.equal(readiness.unboundActiveFamilyCount, 1);
  assert.deepEqual(readiness.invalidStates, [
    "DRAINING_DEADLINE_ELAPSED",
    "UNBOUND_ACTIVE_FAMILY",
  ]);
});

test("Personal readiness rejects active identity, resource, refresh-token, and reference drift", async (t) => {
  const fixture = await createFixture(t);
  const active = activate(fixture.store, fixture.clients, 3, SCHEMA_GENERATION, Date.now() + 60_000);
  saveBoundTokenPair(fixture.store, active, RESOURCE, "drift-family");
  clearEnterpriseVerificationIdentity(fixture.store, active.bindingId);
  const sqlite = database(fixture.store);
  sqlite.prepare("update oauth_access_tokens set resource = ? where connector_binding_id = ?")
    .run("https://wrong.example/mcp", active.bindingId);
  sqlite.prepare("delete from oauth_refresh_tokens where connector_binding_id = ?")
    .run(active.bindingId);
  sqlite.prepare("update oauth_connector_bindings set ref_count = 2 where binding_id = ?")
    .run(active.bindingId);

  const readiness = fixture.store.personalConnectorReadiness(expectation(4), Date.now());
  assert.equal(readiness.state, "FAIL");
  assert.deepEqual(readiness.invalidStates, [
    "ACTIVE_EPOCH_MISMATCH",
    "ACTIVE_REFRESH_TOKEN_MISSING",
    "ACTIVE_TOKEN_RESOURCE_MISMATCH",
    "REFERENCE_COUNT_MISMATCH",
  ]);
});

test("Personal reconciliation updates only a stale ACTIVE schema generation", async (t) => {
  const fixture = await createFixture(t);
  const oldSchema = digest("old-personal-schema");
  const active = activate(
    fixture.store,
    fixture.clients,
    3,
    oldSchema,
    Date.now() + 60_000,
  );
  saveBoundTokenPair(fixture.store, active, RESOURCE, "schema-migration-family");
  clearEnterpriseVerificationIdentity(fixture.store, active.bindingId);
  const before = fixture.store.personalConnectorReadiness(expectation(3), Date.now());
  assert.deepEqual(before.invalidStates, ["ACTIVE_SCHEMA_STALE"]);
  const clientId = active.clientId;
  const bindingId = active.bindingId;

  const plan = fixture.store.planPersonalConnectorReconciliation(expectation(3), Date.now());
  assert.deepEqual(plan.blockers, []);
  assert.deepEqual(plan.actions, [{
    kind: "UPDATE_ACTIVE_SCHEMA",
    bindingId,
    expectedInstallationEpoch: 3,
    expectedSchemaGeneration: oldSchema,
    nextSchemaGeneration: SCHEMA_GENERATION,
  }]);
  const result = fixture.store.applyPersonalConnectorReconciliation(plan, Date.now());
  assert.equal(result.readinessAfter.state, "PASS");
  const migrated = fixture.store.getConnectorBinding(bindingId)!;
  assert.equal(migrated.bindingId, bindingId);
  assert.equal(migrated.clientId, clientId);
  assert.equal(migrated.installationEpoch, 3);
  assert.equal(migrated.schemaGeneration, SCHEMA_GENERATION);
  assert.equal(migrated.refCount, 1);
  assert.ok(fixture.store.getRefreshToken("refresh-schema-migration-family"));
  assert.ok(fixture.store.getAccessToken("access-schema-migration-family"));
});

test("Personal readiness rejects prepared activation residue and non-active token families", async (t) => {
  const fixture = await createFixture(t);
  const active = activate(fixture.store, fixture.clients, 3, SCHEMA_GENERATION, Date.now() + 60_000);
  saveBoundTokenPair(fixture.store, active, RESOURCE, "active-family");
  clearEnterpriseVerificationIdentity(fixture.store, active.bindingId);
  const candidate = verifiedCandidate(fixture.store, fixture.clients, 4, digest("4"));
  fixture.store.prepareConnectorActivation(candidate.tuple, {
    drainDeadlineAt: new Date(Date.now() + 60_000).toISOString(),
    refreshAllowedDuringDrain: false,
  });
  saveBoundTokenPair(fixture.store, candidate.binding, RESOURCE, "candidate-family");

  const readiness = fixture.store.personalConnectorReadiness(expectation(3), Date.now());
  assert.equal(readiness.state, "FAIL");
  assert.equal(readiness.preparedReceiptCount, 1);
  assert.equal(readiness.nonActiveTokenFamilyCount, 1);
  assert.deepEqual(readiness.invalidStates, [
    "PREPARED_RECEIPT_RESIDUE",
    "NON_ACTIVE_TOKEN_FAMILY",
  ]);
});

test("Personal reconciliation atomically retires overdue DRAINING and revokes unbound families", async (t) => {
  const fixture = await createFixture(t);
  const now = Date.now();
  const first = activate(fixture.store, fixture.clients, 1, digest("1"), now + 60_000);
  saveBoundTokenPair(fixture.store, first, RESOURCE, "reconcile-first-family");
  const active = activate(fixture.store, fixture.clients, 3, SCHEMA_GENERATION, now - 1_000);
  saveBoundTokenPair(fixture.store, active, RESOURCE, "reconcile-active-family");
  saveUnboundTokenPair(
    fixture.store,
    active.clientId,
    RESOURCE,
    "reconcile-unbound-family",
  );
  clearEnterpriseVerificationIdentity(fixture.store, first.bindingId);
  clearEnterpriseVerificationIdentity(fixture.store, active.bindingId);

  const plan = fixture.store.planPersonalConnectorReconciliation(expectation(3), now);
  assert.deepEqual(plan.blockers, []);
  assert.deepEqual(plan.actions.map((action) => action.kind), [
    "RETIRE_DRAINING_BINDING",
    "REVOKE_UNBOUND_FAMILY",
  ]);
  assert.match(plan.planDigest, /^sha256:[a-f0-9]{64}$/u);
  assert.deepEqual(plan.readinessBefore.invalidStates, [
    "DRAINING_DEADLINE_ELAPSED",
    "UNBOUND_ACTIVE_FAMILY",
  ]);

  const result = fixture.store.applyPersonalConnectorReconciliation(plan, now);
  assert.equal(result.status, "APPLIED");
  assert.equal(result.readinessAfter.state, "PASS", JSON.stringify(result.readinessAfter));
  assert.notEqual(result.preimageDigest, result.postimageDigest);
  assert.equal(result.retirementReceipts.length, 1);
  assert.equal(result.retirementReceipts[0]?.reason, "DEADLINE_ELAPSED");
  assert.equal(result.retirementReceipts[0]?.revokedFamilyCount, 1);
  assert.equal(fixture.store.getConnectorBinding(first.bindingId)?.state, "RETIRED");
  assert.equal(fixture.store.getAccessToken("access-reconcile-first-family"), undefined);
  assert.equal(fixture.store.getRefreshToken("refresh-reconcile-first-family"), undefined);
  const unbound = database(fixture.store).prepare(`
    select status from oauth_token_families where family_id = ?
  `).get("reconcile-unbound-family") as { status: string };
  assert.equal(unbound.status, "REVOKED");
});

test("Personal reconciliation is no-op when readiness is already exact", async (t) => {
  const fixture = await createFixture(t);
  const active = activate(
    fixture.store,
    fixture.clients,
    3,
    SCHEMA_GENERATION,
    Date.now() + 60_000,
  );
  saveBoundTokenPair(fixture.store, active, RESOURCE, "exact-family");
  clearEnterpriseVerificationIdentity(fixture.store, active.bindingId);
  const plan = fixture.store.planPersonalConnectorReconciliation(expectation(3), Date.now());
  assert.deepEqual(plan.actions, []);
  assert.deepEqual(plan.blockers, []);
  const result = fixture.store.applyPersonalConnectorReconciliation(plan, Date.now());
  assert.equal(result.status, "NO_CHANGES");
  assert.equal(result.preimageDigest, result.postimageDigest);
  assert.equal(result.readinessAfter.state, "PASS");
});

test("Personal reconciliation rejects stale preimages and tampered plans", async (t) => {
  const fixture = await createFixture(t);
  const active = activate(
    fixture.store,
    fixture.clients,
    3,
    SCHEMA_GENERATION,
    Date.now() + 60_000,
  );
  saveBoundTokenPair(fixture.store, active, RESOURCE, "stale-family");
  clearEnterpriseVerificationIdentity(fixture.store, active.bindingId);
  const plan = fixture.store.planPersonalConnectorReconciliation(expectation(3), Date.now());
  database(fixture.store).prepare(`
    update oauth_token_families set rotation_sequence = 1 where family_id = ?
  `).run("stale-family");
  assert.throws(
    () => fixture.store.applyPersonalConnectorReconciliation(plan, Date.now()),
    /preimage changed/u,
  );

  const freshPlan = fixture.store.planPersonalConnectorReconciliation(expectation(3), Date.now());
  const tampered = {
    ...freshPlan,
    actions: [{ kind: "REVOKE_UNBOUND_FAMILY" as const, familyId: "fabricated-family" }],
  };
  assert.throws(
    () => fixture.store.applyPersonalConnectorReconciliation(tampered, Date.now()),
    /plan digest mismatch/u,
  );
});

test("Personal reconciliation refuses active identity and prepared-candidate blockers", async (t) => {
  const fixture = await createFixture(t);
  const active = activate(
    fixture.store,
    fixture.clients,
    3,
    SCHEMA_GENERATION,
    Date.now() + 60_000,
  );
  saveBoundTokenPair(fixture.store, active, RESOURCE, "blocked-active-family");
  clearEnterpriseVerificationIdentity(fixture.store, active.bindingId);
  const candidate = verifiedCandidate(fixture.store, fixture.clients, 4, digest("4"));
  fixture.store.prepareConnectorActivation(candidate.tuple, {
    drainDeadlineAt: new Date(Date.now() + 60_000).toISOString(),
    refreshAllowedDuringDrain: false,
  });
  saveBoundTokenPair(fixture.store, candidate.binding, RESOURCE, "blocked-candidate-family");
  const plan = fixture.store.planPersonalConnectorReconciliation(expectation(3), Date.now());
  assert.deepEqual(plan.blockers, [
    "PREPARED_RECEIPT_RESIDUE",
    "NON_ACTIVE_TOKEN_FAMILY",
  ]);
  assert.throws(
    () => fixture.store.applyPersonalConnectorReconciliation(plan, Date.now()),
    /reconciliation is blocked/u,
  );
  assert.equal(fixture.store.getConnectorBinding(candidate.binding.bindingId)?.state, "ACTIVATION_PREPARED");
  assert.ok(fixture.store.getRefreshToken("refresh-blocked-candidate-family"));
});

async function createFixture(t: test.TestContext) {
  const root = await mkdtemp(join(tmpdir(), "devspace-personal-connector-state-"));
  const store = new SqliteOAuthStore(root);
  const clients = new SqliteOAuthClientsStore(store, ["127.0.0.1", "localhost"]);
  t.after(() => {
    store.close();
    return rm(root, { recursive: true, force: true });
  });
  return { root, store, clients };
}

function expectation(installationEpoch: number): PersonalConnectorExpectation {
  return {
    canonicalName: CANONICAL_NAME,
    installationEpoch,
    schemaGeneration: SCHEMA_GENERATION,
    resource: RESOURCE,
  };
}

function activate(
  store: SqliteOAuthStore,
  clients: SqliteOAuthClientsStore,
  installationEpoch: number,
  schemaGeneration: string,
  drainDeadlineMs: number,
): ConnectorBindingRecord {
  const candidate = verifiedCandidate(store, clients, installationEpoch, schemaGeneration);
  const receipt = store.prepareConnectorActivation(candidate.tuple, {
    drainDeadlineAt: new Date(drainDeadlineMs).toISOString(),
    refreshAllowedDuringDrain: false,
  });
  store.activatePreparedConnector(receipt.receiptId, candidate.tuple, activationProof(receipt));
  return store.getConnectorBinding(candidate.binding.bindingId)!;
}

function verifiedCandidate(
  store: SqliteOAuthStore,
  clients: SqliteOAuthClientsStore,
  installationEpoch: number,
  schemaGeneration: string,
) {
  const client = clients.registerClient({
    redirect_uris: ["http://127.0.0.1/callback"],
    client_name: `Personal connector ${installationEpoch}`,
    token_endpoint_auth_method: "none",
    grant_types: ["authorization_code", "refresh_token"],
    response_types: ["code"],
  });
  const input = {
    canonicalName: CANONICAL_NAME,
    clientId: client.client_id,
    installationEpoch,
    schemaGeneration,
  };
  const binding = store.ensureCandidateConnectorBinding(input);
  const tuple = {
    ...input,
    candidateBindingId: binding.bindingId,
    authorityContractGeneration: RUNTIME_AUTHORITY_CONTRACT_GENERATION,
    redirectUrisDigest: digest(`redirect-${installationEpoch}`),
    buildDigest: digest(`build-${installationEpoch}`),
  };
  store.markConnectorBindingVerified(binding.bindingId, {
    authorityContractGeneration: tuple.authorityContractGeneration,
    redirectUrisDigest: tuple.redirectUrisDigest,
    buildDigest: tuple.buildDigest,
  });
  return { binding: store.getConnectorBinding(binding.bindingId)!, tuple };
}

function saveBoundTokenPair(
  store: SqliteOAuthStore,
  binding: ConnectorBindingRecord,
  resource: string,
  familyId: string,
): void {
  const token = {
    clientId: binding.clientId,
    scopes: ["devspace.read", "devspace.write"],
    expiresAt: Math.floor(Date.now() / 1_000) + 3_600,
    resource,
    familyId,
    connectorBindingId: binding.bindingId,
    connectorDrainEpoch: binding.drainEpoch,
    installationEpoch: binding.installationEpoch,
    rotationSequence: 0,
  };
  assert.equal(store.saveTokenPair({
    accessTokenHash: `access-${familyId}`,
    accessToken: token,
    refreshTokenHash: `refresh-${familyId}`,
    refreshToken: token,
  }), true);
}

function saveUnboundTokenPair(
  store: SqliteOAuthStore,
  clientId: string,
  resource: string,
  familyId: string,
): void {
  const token = {
    clientId,
    scopes: ["devspace.read"],
    expiresAt: Math.floor(Date.now() / 1_000) + 3_600,
    resource,
    familyId,
    rotationSequence: 0,
  };
  assert.equal(store.saveTokenPair({
    accessTokenHash: `access-${familyId}`,
    accessToken: token,
    refreshTokenHash: `refresh-${familyId}`,
    refreshToken: token,
  }), true);
}

function clearEnterpriseVerificationIdentity(store: SqliteOAuthStore, bindingId: string): void {
  database(store).prepare(`
    update oauth_connector_bindings
       set authority_contract_generation = null,
           redirect_uris_digest = null,
           build_digest = null
     where binding_id = ?
  `).run(bindingId);
}

function database(store: SqliteOAuthStore) {
  return store["database"].sqlite;
}

function activationProof(receipt: ConnectorActivationReceipt): ConnectorActivationAuthorityProof {
  const binding = {
    receiptId: receipt.receiptId,
    tupleDigest: receipt.tupleDigest,
    activePreimageDigest: receipt.preimageDigest,
    finalizationPlanDigest: digest("personal-finalization-plan"),
    canonicalName: receipt.tuple.canonicalName,
  };
  const claimedAtMs = Date.now();
  return {
    schemaVersion: 1,
    authorityId: `authority_${randomUUID()}`,
    actionClaimId: `authority_claim_${randomUUID()}`,
    actionFingerprint: connectorActivationAuthorityActionFingerprint(binding),
    resourceKeySha256: connectorActivationAuthorityResourceKeySha256(binding),
    fencingToken: receipt.tuple.installationEpoch,
    principalKeyFingerprint: createHash("sha256").update("personal-owner").digest("hex"),
    risk: "R3",
    claimState: "DISPATCHED",
    approvalAssurance: "cooperative",
    ...binding,
    evidenceDigest: digest("personal-owner-evidence"),
    claimedAtMs,
    dispatchedAtMs: claimedAtMs + 1,
  };
}

function digest(value: string): string {
  return `sha256:${createHash("sha256").update(value).digest("hex")}`;
}
