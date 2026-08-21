import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { createHash, randomUUID } from "node:crypto";
import { chmod, mkdtemp, readFile, rm, stat } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import test from "node:test";
import Database from "better-sqlite3";
import {
  SqliteOAuthClientsStore,
  SqliteOAuthStore,
  connectorActivationAuthorityActionFingerprint,
  connectorActivationAuthorityResourceKeySha256,
} from "../dist/oauth-store.js";
import { RUNTIME_AUTHORITY_CONTRACT_GENERATION } from "../dist/v2/runtime-contract-identity.js";

const script = resolve("scripts/personal-connector-reconcile.mjs");
const resource = "http://127.0.0.1:17676/mcp";
const schemaGeneration = `sha256:${"9".repeat(64)}`;

test("Personal connector CLI requires a verified backup and preserves the stale preimage", async (t) => {
  const root = await mkdtemp(join(tmpdir(), "devspace-personal-connector-cli-"));
  const stateDir = join(root, "state");
  const planPath = join(root, "plan.json");
  const backupDir = join(root, "backup");
  const resultPath = join(root, "result.json");
  t.after(() => rm(root, { recursive: true, force: true }));
  createStaleFixture(stateDir);

  const planRun = run([
    "plan",
    "--state-dir", stateDir,
    "--canonical-name", "myDevSpace",
    "--installation-epoch", "3",
    "--schema-generation", schemaGeneration,
    "--resource", resource,
    "--output", planPath,
  ]);
  assert.equal(planRun.status, 0, planRun.stderr);
  const planSummary = JSON.parse(planRun.stdout);
  assert.equal(planSummary.status, "PLANNED");
  assert.equal(planSummary.actionCount, 2);
  assert.deepEqual(planSummary.blockers, []);
  assert.equal(await mode(planPath), "600");

  const applyRun = run([
    "apply",
    "--state-dir", stateDir,
    "--plan", planPath,
    "--backup-dir", backupDir,
    "--output", resultPath,
  ]);
  assert.equal(applyRun.status, 0, applyRun.stderr);
  const applySummary = JSON.parse(applyRun.stdout);
  assert.equal(applySummary.status, "APPLIED");
  assert.equal(applySummary.readinessAfter.state, "PASS");

  const result = JSON.parse(await readFile(resultPath, "utf8"));
  const manifest = JSON.parse(await readFile(result.backupManifestPath, "utf8"));
  assert.equal(result.readinessAfter.state, "PASS");
  assert.equal(result.backupVerification.quickCheck, "ok");
  assert.equal(result.backupVerification.foreignKeyViolations, 0);
  assert.equal(manifest.planDigest, result.planDigest);
  assert.equal(manifest.preimageDigest, result.preimageDigest);
  assert.equal(await mode(resultPath), "600");
  assert.equal(await mode(result.backupPath), "600");
  assert.equal(await mode(result.backupManifestPath), "600");
  assert.equal(await mode(backupDir), "700");

  const backup = new Database(result.backupPath, { readonly: true, fileMustExist: true });
  try {
    assert.equal(backup.pragma("quick_check", { simple: true }), "ok");
    assert.equal(backup.prepare(
      "select count(*) from oauth_connector_bindings where state = 'DRAINING'",
    ).pluck().get(), 1);
    assert.equal(backup.prepare(
      "select count(*) from oauth_token_families where connector_binding_id is null and status <> 'REVOKED'",
    ).pluck().get(), 1);
  } finally {
    backup.close();
  }

  const current = new SqliteOAuthStore(stateDir);
  try {
    const readiness = current.personalConnectorReadiness(expectation());
    assert.equal(readiness.state, "PASS", JSON.stringify(readiness));
    assert.equal(readiness.bindingsByState.DRAINING, 0);
    assert.equal(readiness.bindingsByState.RETIRED, 1);
    assert.equal(readiness.unboundActiveFamilyCount, 0);
  } finally {
    current.close();
  }

  const duplicateApply = run([
    "apply",
    "--state-dir", stateDir,
    "--plan", planPath,
    "--backup-dir", backupDir,
    "--output", resultPath,
  ]);
  assert.notEqual(duplicateApply.status, 0);
  assert.match(duplicateApply.stderr, /already exists/u);
});

test("Personal connector CLI keeps the backup when a stale plan is rejected", async (t) => {
  const root = await mkdtemp(join(tmpdir(), "devspace-personal-connector-cli-stale-"));
  const stateDir = join(root, "state");
  const planPath = join(root, "plan.json");
  const backupDir = join(root, "backup");
  const resultPath = join(root, "result.json");
  t.after(() => rm(root, { recursive: true, force: true }));
  createStaleFixture(stateDir);
  assert.equal(run([
    "plan",
    "--state-dir", stateDir,
    "--canonical-name", "myDevSpace",
    "--installation-epoch", "3",
    "--schema-generation", schemaGeneration,
    "--resource", resource,
    "--output", planPath,
  ]).status, 0);
  const sqlite = new Database(join(stateDir, "devspace.sqlite"));
  try {
    sqlite.prepare(`
      update oauth_token_families set rotation_sequence = rotation_sequence + 1
       where family_id = 'active-family'
    `).run();
  } finally {
    sqlite.close();
  }

  const applyRun = run([
    "apply",
    "--state-dir", stateDir,
    "--plan", planPath,
    "--backup-dir", backupDir,
    "--output", resultPath,
  ]);
  assert.notEqual(applyRun.status, 0);
  assert.match(applyRun.stderr, /preimage changed/u);
  assert.equal(await mode(join(
    backupDir,
    "devspace.sqlite.before-personal-connector-reconciliation.sqlite",
  )), "600");
  assert.equal(await mode(join(backupDir, "BACKUP-MANIFEST.json")), "600");
  await assert.rejects(readFile(resultPath, "utf8"), /ENOENT/u);
});

function createStaleFixture(stateDir) {
  const store = new SqliteOAuthStore(stateDir);
  try {
    const clients = new SqliteOAuthClientsStore(store, ["127.0.0.1", "localhost"]);
    const now = Date.now();
    const first = activate(store, clients, 1, digest("schema-1"), now + 60_000);
    saveBoundPair(store, first, "first-family");
    const active = activate(store, clients, 3, schemaGeneration, now - 1_000);
    saveBoundPair(store, active, "active-family");
    saveUnboundPair(store, active.clientId, "unbound-family");
    const sqlite = store["database"].sqlite;
    sqlite.prepare(`
      update oauth_connector_bindings
         set authority_contract_generation = null,
             redirect_uris_digest = null,
             build_digest = null
    `).run();
  } finally {
    store.close();
  }
}

function activate(store, clients, installationEpoch, schema, drainDeadlineMs) {
  const client = clients.registerClient({
    redirect_uris: ["http://127.0.0.1/callback"],
    client_name: `CLI connector ${installationEpoch}`,
    token_endpoint_auth_method: "none",
    grant_types: ["authorization_code", "refresh_token"],
    response_types: ["code"],
  });
  const input = {
    canonicalName: "myDevSpace",
    clientId: client.client_id,
    installationEpoch,
    schemaGeneration: schema,
  };
  const candidate = store.ensureCandidateConnectorBinding(input);
  const tuple = {
    ...input,
    candidateBindingId: candidate.bindingId,
    authorityContractGeneration: RUNTIME_AUTHORITY_CONTRACT_GENERATION,
    redirectUrisDigest: digest(`redirect-${installationEpoch}`),
    buildDigest: digest(`build-${installationEpoch}`),
  };
  store.markConnectorBindingVerified(candidate.bindingId, {
    authorityContractGeneration: tuple.authorityContractGeneration,
    redirectUrisDigest: tuple.redirectUrisDigest,
    buildDigest: tuple.buildDigest,
  });
  const receipt = store.prepareConnectorActivation(tuple, {
    drainDeadlineAt: new Date(drainDeadlineMs).toISOString(),
    refreshAllowedDuringDrain: false,
  });
  store.activatePreparedConnector(receipt.receiptId, tuple, activationProof(receipt));
  return store.getConnectorBinding(candidate.bindingId);
}

function activationProof(receipt) {
  const binding = {
    receiptId: receipt.receiptId,
    tupleDigest: receipt.tupleDigest,
    activePreimageDigest: receipt.preimageDigest,
    finalizationPlanDigest: digest("cli-finalization"),
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
    principalKeyFingerprint: createHash("sha256").update("cli-owner").digest("hex"),
    risk: "R3",
    claimState: "DISPATCHED",
    approvalAssurance: "cooperative",
    ...binding,
    evidenceDigest: digest("cli-evidence"),
    claimedAtMs,
    dispatchedAtMs: claimedAtMs + 1,
  };
}

function saveBoundPair(store, binding, familyId) {
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

function saveUnboundPair(store, clientId, familyId) {
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

function expectation() {
  return {
    canonicalName: "myDevSpace",
    installationEpoch: 3,
    schemaGeneration,
    resource,
  };
}

function run(args) {
  return spawnSync(process.execPath, [script, ...args], {
    cwd: process.cwd(),
    env: process.env,
    encoding: "utf8",
    stdio: "pipe",
  });
}

async function mode(path) {
  return ((await stat(path)).mode & 0o777).toString(8).padStart(3, "0");
}

function digest(value) {
  return `sha256:${createHash("sha256").update(value).digest("hex")}`;
}
