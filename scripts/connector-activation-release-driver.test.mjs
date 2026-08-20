import test, { after } from "node:test";
import assert from "node:assert/strict";
import { createHash, createHmac, randomUUID } from "node:crypto";
import {
  chmodSync,
  copyFileSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  statSync,
  writeFileSync,
} from "node:fs";
import { join } from "node:path";
import { spawn, spawnSync } from "node:child_process";
import Database from "better-sqlite3";

import * as oauth from "../src/oauth-store.ts";
import * as authority from "../src/v2/authority.ts";
import * as evidence from "../src/v2/connector-activation-evidence.ts";
import * as finalizer from "../src/v2/connector-activation-finalizer.ts";
import * as journal from "../src/v2/connector-activation-journal.ts";
import * as management from "../src/v2/management-authorization.ts";
import * as routeIdentity from "../src/v2/connector-route-identity.ts";
import * as snapshotGroup from "../src/v2/snapshot-group.ts";
import * as staging from "../src/v2/connector-staging-activation.ts";
import * as productionUpgradeWorker from "../src/v2/production-upgrade-worker.ts";
import * as productionUpgradeContract from "../src/v2/production-upgrade-contract.ts";
import {
  commitPreparedFinalization,
  createFinalizationStoreBootstrapAuthorization,
  initializeFinalizationStore,
  readFinalizationStoreIdentity,
} from "./lib/finalization-store-contract.mjs";
import {
  ConnectorActivationReleaseDriver,
  createEvidenceLedgerRecord,
  writeOwnerOnlyArtifactAtomic,
  writeProductionApprovalDirectoryAtomic,
} from "./lib/connector-activation-release-driver.mjs";
import {
  canonicalizeConnectorRollbackEvidence,
  connectorRollbackHealthReadbackDigest,
  connectorRollbackReadyReadbackDigest,
  connectorRollbackRuntimeReadbackDigest,
  signConnectorRollbackHostChallenge,
  signConnectorRollbackHostReceipt,
  verifyConnectorRollbackHostChallenge,
  verifyConnectorRollbackHostReceipt,
} from "./lib/connector-rollback-evidence.mjs";

const NODE_VERSION = "22.23.2";
const TOOLS = ["target", "context", "fs", "exec", "process", "mcp", "artifact", "gui"];
const SCOPES = [
  "devspace.read", "devspace.write", "devspace.exec", "devspace.mcp",
  "devspace.artifact", "devspace.gui",
];
const GENERATED_SCHEMA_FILES = [
  "config.schema.json",
  "config/config.schema.json",
  "contracts/tools-v2.schema.json",
  "contracts/build-capabilities.schema.json",
];
const PRODUCTION_PREDECISION_DOMAIN =
  "devspace.connector-activation-release-driver.v1/PRODUCTION_ACTIVATION_PREDECISION\0";
const runtime = Object.freeze({
  ...oauth,
  ...authority,
  ...evidence,
  ...finalizer,
  ...journal,
  ...management,
  ...routeIdentity,
  ...snapshotGroup,
  ...staging,
  ...productionUpgradeWorker,
  ...productionUpgradeContract,
});
const CREATED_TEMP_ROOTS = new Set();
after(() => {
  for (const root of CREATED_TEMP_ROOTS) rmSync(root, { recursive: true, force: true });
});

test("release driver tests run under the exact release Node", () => {
  assert.equal(process.versions.node, NODE_VERSION);
  const usage = spawnSync(process.execPath, ["scripts/connector-activation-release-driver.mjs"], {
    cwd: process.cwd(),
    encoding: "utf8",
  });
  assert.equal(usage.status, 64, usage.stderr);
  const usageEnvelope = usage.stderr
    .split("\n")
    .map((line) => line.trim())
    .find((line) => line.startsWith("{"));
  assert.equal(JSON.parse(usageEnvelope).code, "USAGE");
});

test("production activation exposes a split predecision and post-snapshot preparation boundary", () => {
  const driver = new ConnectorActivationReleaseDriver({ runtime });
  assert.equal(typeof driver.createProductionActivationPredecision, "function");
  assert.equal(typeof driver.createProductionActivationApproval, "function");
});

test("rollback evidence is domain-separated, exact-shape, and challenge-bound", () => {
  const now = 1_800_000_000_000;
  const key = { keyId: "management-test", secret: Buffer.alloc(32, 7) };
  const expected = {
    transactionId: "upgrade-transaction-1",
    previousRuntimeIdentityDigest: digest("previous-runtime"),
    previousMainMigrationIdentityDigest: digest("previous-migration"),
    receiptPath: "/private/rollback/receipt.json",
  };
  const challenge = signConnectorRollbackHostChallenge({
    challengeId: "rollback-challenge-1",
    transactionId: expected.transactionId,
    nonce: Buffer.alloc(32, 9).toString("base64url"),
    managementCorrelationId: "rollback-correlation-1",
    hostProvider: "chatgpt",
    actualHostRequired: true,
    previousRuntimeIdentityDigest: expected.previousRuntimeIdentityDigest,
    previousMainMigrationIdentityDigest: expected.previousMainMigrationIdentityDigest,
    issuedAtMs: now,
    expiresAtMs: now + 300_000,
    receiptPath: expected.receiptPath,
  }, key, now);
  const verifiedChallenge = verifyConnectorRollbackHostChallenge(challenge, key, expected, now);
  assert.equal(verifiedChallenge.signedPayloadDigest, challenge.payloadDigest);
  assert.equal(
    canonicalizeConnectorRollbackEvidence({ "ä": 1, z: 2, a: 3 }),
    '{"a":3,"z":2,"ä":1}',
  );
  const canonicalChallengeBase = canonicalJson({
    schemaVersion: 1,
    kind: challenge.kind,
    keyId: challenge.keyId,
    payload: challenge.payload,
  });
  assert.equal(
    canonicalizeConnectorRollbackEvidence({
      schemaVersion: 1,
      kind: challenge.kind,
      keyId: challenge.keyId,
      payload: challenge.payload,
    }),
    canonicalChallengeBase,
  );
  assert.equal(
    challenge.payloadDigest,
    digest(canonicalChallengeBase),
  );
  assert.equal(
    challenge.signature,
    createHmac("sha256", key.secret)
      .update("devspace.connector-rollback-evidence.v1/ROLLBACK_HOST_CHALLENGE\0")
      .update(canonicalChallengeBase)
      .digest("base64url"),
  );

  const receiptExpected = {
    ...expected,
    healthReadbackDigest: connectorRollbackHealthReadbackDigest({
      challengeId: challenge.payload.challengeId,
      transactionId: challenge.payload.transactionId,
      nonce: challenge.payload.nonce,
      managementCorrelationId: challenge.payload.managementCorrelationId,
      httpStatus: 200,
    }),
    readyReadbackDigest: connectorRollbackReadyReadbackDigest({
      challengeId: challenge.payload.challengeId,
      transactionId: challenge.payload.transactionId,
      nonce: challenge.payload.nonce,
      managementCorrelationId: challenge.payload.managementCorrelationId,
      httpStatus: 200,
      runtimeIdentityDigest: expected.previousRuntimeIdentityDigest,
    }),
    runtimeReadbackDigest: connectorRollbackRuntimeReadbackDigest({
      challengeId: challenge.payload.challengeId,
      transactionId: challenge.payload.transactionId,
      nonce: challenge.payload.nonce,
      managementCorrelationId: challenge.payload.managementCorrelationId,
      processName: "devspace-previous",
      processStatus: "online",
      cwd: "/private/rollback/previous-runtime",
      script: "/private/rollback/previous-runtime/dist/cli.js",
      runtimeIdentityDigest: expected.previousRuntimeIdentityDigest,
      mainMigrationIdentityDigest: expected.previousMainMigrationIdentityDigest,
    }),
  };
  assert.equal(receiptExpected.healthReadbackDigest, digest(canonicalJson({
    schemaVersion: 1,
    kind: "ROLLBACK_HEALTH_READBACK_BINDING",
    challengeId: challenge.payload.challengeId,
    transactionId: challenge.payload.transactionId,
    nonce: challenge.payload.nonce,
    managementCorrelationId: challenge.payload.managementCorrelationId,
    httpStatus: 200,
  })));
  assert.equal(receiptExpected.readyReadbackDigest, digest(canonicalJson({
    schemaVersion: 1,
    kind: "ROLLBACK_READY_READBACK_BINDING",
    challengeId: challenge.payload.challengeId,
    transactionId: challenge.payload.transactionId,
    nonce: challenge.payload.nonce,
    managementCorrelationId: challenge.payload.managementCorrelationId,
    httpStatus: 200,
    runtimeIdentityDigest: expected.previousRuntimeIdentityDigest,
  })));
  assert.equal(receiptExpected.runtimeReadbackDigest, digest(canonicalJson({
    schemaVersion: 1,
    kind: "ROLLBACK_RUNTIME_READBACK_BINDING",
    challengeId: challenge.payload.challengeId,
    transactionId: challenge.payload.transactionId,
    nonce: challenge.payload.nonce,
    managementCorrelationId: challenge.payload.managementCorrelationId,
    processName: "devspace-previous",
    processStatus: "online",
    cwd: "/private/rollback/previous-runtime",
    script: "/private/rollback/previous-runtime/dist/cli.js",
    runtimeIdentityDigest: expected.previousRuntimeIdentityDigest,
    mainMigrationIdentityDigest: expected.previousMainMigrationIdentityDigest,
  })));

  const receipt = signConnectorRollbackHostReceipt({
    challengeId: challenge.payload.challengeId,
    challengePayloadDigest: challenge.payloadDigest,
    transactionId: challenge.payload.transactionId,
    nonce: challenge.payload.nonce,
    managementCorrelationId: challenge.payload.managementCorrelationId,
    hostProvider: "chatgpt",
    actualHost: true,
    previousRuntimeIdentityDigest: challenge.payload.previousRuntimeIdentityDigest,
    previousMainMigrationIdentityDigest: challenge.payload.previousMainMigrationIdentityDigest,
    runtimeReadbackDigest: receiptExpected.runtimeReadbackDigest,
    healthReadbackDigest: receiptExpected.healthReadbackDigest,
    readyReadbackDigest: receiptExpected.readyReadbackDigest,
    sessionAIdDigest: digest("session-a"),
    sessionBIdDigest: digest("session-b"),
    observedAtMs: now + 1,
    expiresAtMs: now + 120_001,
  }, key, challenge, receiptExpected, now + 1);
  const canonicalReceiptBase = canonicalJson({
    schemaVersion: 1,
    kind: receipt.kind,
    keyId: receipt.keyId,
    payload: receipt.payload,
  });
  assert.equal(receipt.payloadDigest, digest(canonicalReceiptBase));
  assert.equal(
    receipt.signature,
    createHmac("sha256", key.secret)
      .update("devspace.connector-rollback-evidence.v1/ROLLBACK_HOST_RECEIPT\0")
      .update(canonicalReceiptBase)
      .digest("base64url"),
  );
  assert.equal(
    verifyConnectorRollbackHostReceipt(receipt, key, challenge, receiptExpected, now + 1).transactionId,
    expected.transactionId,
  );
  assert.throws(
    () => signConnectorRollbackHostReceipt({
      ...receipt.payload,
      sessionBIdDigest: receipt.payload.sessionAIdDigest,
    }, key, challenge, receiptExpected, now + 1),
    /two distinct ChatGPT sessions/u,
  );
  assert.throws(
    () => verifyConnectorRollbackHostReceipt({
      ...receipt,
      signature: `${receipt.signature.slice(0, -1)}A`,
    }, key, challenge, receiptExpected, now + 1),
    /signature verification failed/u,
  );
  assert.throws(
    () => verifyConnectorRollbackHostReceipt(receipt, key, challenge, {
      ...receiptExpected,
      healthReadbackDigest: digest("caller-invented-health"),
    }, now + 1),
    /trusted runtime, health, and ready readback bindings/u,
  );
  assert.throws(
    () => verifyConnectorRollbackHostChallenge(challenge, key, {
      ...expected,
      transactionId: "wrong-transaction",
    }, now),
    /trusted transaction preimage binding/u,
  );
  assert.throws(
    () => verifyConnectorRollbackHostChallenge({
      ...challenge,
      payload: { ...challenge.payload, pass: true },
    }, key, expected, now),
    /signature verification failed|unexpected or missing fields/u,
  );
});

test("actual-Host rollback collection derives health, ready, and runtime receipt from trusted ledgers", (t) => {
  const fixture = createRollbackFixture();
  t.after(() => fixture.cleanup());
  const driver = new ConnectorActivationReleaseDriver({ runtime, now: () => fixture.now });
  const challenge = driver.createRollbackHostChallenge(fixture.challengeRequest);
  writeOwnerOnlyArtifactAtomic(fixture.challengePath, challenge);
  fixture.appendObservation(challenge);
  const receipt = driver.createRollbackHostReceipt(fixture.hostRequest);
  writeOwnerOnlyArtifactAtomic(fixture.receiptPath, receipt);
  const verified = driver.verifyPersistedRollbackHostReceipt(fixture.verifyRequest);
  assert.equal(verified.actualHost, true);
  assert.equal(verified.transactionId, fixture.transactionId);
  assert.equal(verified.runtimeReadbackDigest, fixture.expectedReadbacks.runtimeReadbackDigest);
  assert.equal(verified.healthReadbackDigest, fixture.expectedReadbacks.healthReadbackDigest);
  assert.equal(verified.readyReadbackDigest, fixture.expectedReadbacks.readyReadbackDigest);

  assert.throws(
    () => driver.createRollbackHostReceipt({
      ...fixture.hostRequest,
      selection: { ...fixture.hostRequest.selection, pass: true },
    }),
    /unexpected or missing fields/u,
  );
  const forged = clone(receipt);
  forged.signature = `${forged.signature.slice(0, -1)}${forged.signature.endsWith("A") ? "B" : "A"}`;
  writeText(fixture.receiptPath, `${JSON.stringify(forged)}\n`, 0o600);
  assert.throws(
    () => driver.verifyPersistedRollbackHostReceipt(fixture.verifyRequest),
    /signature verification failed/u,
  );
  rmSync(fixture.receiptPath);
  assert.throws(
    () => driver.verifyPersistedRollbackHostReceipt({
      ...fixture.verifyRequest,
      selection: {
        ...fixture.verifyRequest.selection,
        healthReadbackRecordId: fixture.runtimeReadback.recordDigest,
      },
    }),
    /ROLLBACK_HEALTH_READBACK is missing/u,
  );
  fixture.rewriteHostSessionsSame();
  assert.throws(() => driver.createRollbackHostReceipt(fixture.hostRequest), /two distinct session identities/u);
});

test("rollback-challenge CLI publishes an owner-only challenge and no future receipt digest", (t) => {
  const fixture = createRollbackFixture({ now: Date.now() });
  t.after(() => fixture.cleanup());
  const requestPath = join(fixture.root, "rollback-challenge-request.json");
  writeText(requestPath, `${JSON.stringify(fixture.challengeRequest)}\n`, 0o600);
  const result = spawnSync(process.execPath, [
    "scripts/connector-activation-release-driver.mjs",
    "rollback-challenge",
    "--request",
    requestPath,
    "--output",
    fixture.challengePath,
  ], { cwd: process.cwd(), encoding: "utf8" });
  assert.equal(result.status, 0, result.stderr);
  const summary = JSON.parse(result.stdout);
  assert.equal(summary.path, fixture.challengePath);
  assert.equal(summary.receiptPath, fixture.receiptPath);
  assert.equal(Object.hasOwn(summary, "receiptSha256"), false);
  assert.equal(statSync(fixture.challengePath).mode & 0o777, 0o600);
  assert.equal(statSync(fixture.root).mode & 0o777, 0o700);
  assert.equal(readFileSync(fixture.challengePath).includes(Buffer.from(fixture.key.secret)), false);
  assert.throws(() => statSync(fixture.receiptPath), /ENOENT/u);
  assert.equal(summary.sha256, digest(readFileSync(fixture.challengePath)));
});

test("staging precheck derives actual ChatGPT R0, audit, dispatch, readback, OAuth, and immutable package identity", (t) => {
  const fixture = createStagingFixture();
  t.after(() => fixture.cleanup());
  const driver = new ConnectorActivationReleaseDriver({ runtime, now: () => fixture.now });
  const signed = driver.createStagingActivationPrecheck(fixture.precheckRequest);
  assert.equal(signed.kind, "STAGING_ACTIVATION_PRECHECK");
  assert.equal(signed.payload.actualHost, true);
  assert.deepEqual(signed.payload.discoveredToolNames, TOOLS);
  assert.equal(signed.payload.r0Canary.providerDispatchCount, 1);
  assert.equal(signed.payload.candidateIdentity.packageSha256, fixture.candidateIdentity.packageSha256);

  assert.throws(
    () => driver.createStagingActivationPrecheck({
      ...fixture.precheckRequest,
      selection: { ...fixture.precheckRequest.selection, principalKeyFingerprint: fixture.principal },
    }),
    /unexpected or missing fields/u,
  );
  assert.throws(
    () => driver.createStagingActivationPrecheck({
      ...fixture.precheckRequest,
      selection: { ...fixture.precheckRequest.selection, pass: true },
    }),
    /unexpected or missing fields/u,
    "a caller-supplied synthetic PASS cannot replace trusted dispatch/readback evidence",
  );
  assert.throws(
    () => driver.createStagingActivationPrecheck({
      ...fixture.precheckRequest,
      management: { ...fixture.precheckRequest.management, rawSecret: "Bearer fixture-secret" },
    }),
    /unexpected or missing fields/u,
  );
  assert.throws(
    () => driver.createStagingActivationPrecheck({
      ...fixture.precheckRequest,
      selection: {
        ...fixture.precheckRequest.selection,
        expectedResourceDigest: digest("wrong-resource"),
      },
    }),
    /R0 resource/u,
  );
});

test("real staging coordinator activation and PRE canary derive authority, token-family, cleanup, and foreign-zero evidence", (t) => {
  const fixture = createStagingFixture();
  t.after(() => fixture.cleanup());
  const driver = new ConnectorActivationReleaseDriver({ runtime, now: () => fixture.now });
  const precheck = driver.createStagingActivationPrecheck(fixture.precheckRequest);
  const precheckPath = join(fixture.root, "staging-precheck.json");
  writeOwnerOnlyArtifactAtomic(precheckPath, precheck);
  const authorityDatabasePath = join(fixture.root, "authority.sqlite");
  const authorityRegistry = new authority.OperationAuthorityRegistry({
    storePath: authorityDatabasePath,
    instanceId: "staging-fixture-bootstrap",
  });
  authorityRegistry.close();
  chmodSync(authorityDatabasePath, 0o600);
  const journalPath = join(fixture.root, "connector-journal.sqlite");
  const verified = evidence.verifyConnectorActivationStagingPrecheck(
    precheck,
    fixture.key,
    {
      principalKeyFingerprint: fixture.principal,
      managementNonce: precheck.payload.managementNonce,
      managementCorrelationId: precheck.payload.managementCorrelationId,
      candidateIdentity: fixture.candidateIdentity,
      stagingRouteIdentityDigest: fixture.routeIdentityDigest,
      stagingCandidateBinding: precheck.payload.stagingCandidateBinding,
    },
    fixture.now,
  );
  const approvalBinding = staging.connectorStagingActivationOwnerApprovalBinding(
    fixture.receipt,
    verified,
    fixture.principal,
  );
  const conditionsDigest = digestJson({
    schemaVersion: 1,
    stage: "STAGING_ACTIVATION",
    stagingActivationPrecheckDigest: verified.signedPayloadDigest,
    ...approvalBinding,
  });
  const decision = appendLedger(
    fixture.broker,
    "DEVSPACE_BROKER",
    "OWNER_APPROVAL_DECISION",
    fixture.now,
    {
      stage: "STAGING_ACTIVATION",
      approvalId: "staging-owner-approval-fixture",
      authorityText: "Activate this exact isolated staging connector after its signed actual-Host R0 precheck.",
      managementCorrelationId: fixture.managementCorrelationId,
      conditionsDigest,
      approvedAtMs: fixture.now,
      expiresAtMs: fixture.now + 60_000,
    },
  );
  writeLedger(fixture.brokerLedgerPath, fixture.broker);
  const activationRequest = {
    ...fixture.precheckRequest,
    operation: "STAGING_ACTIVATE",
    stores: {
      ...fixture.precheckRequest.stores,
      authorityDatabasePath,
      journalPath,
      oauthStateDir: fixture.oauthStateDir,
    },
    selection: {
      ...fixture.precheckRequest.selection,
      ownerApprovalDecisionRecordId: decision.recordDigest,
    },
    artifacts: { stagingPrecheckPath: precheckPath },
  };
  const activated = driver.activateStagingConnector(activationRequest);
  assert.equal(activated.kind, "STAGING_ACTIVATION");
  assert.equal(activated.payload.state, "STAGING_ACTIVATED_PENDING_PRE_CANARY");
  assert.equal(activated.payload.activationReceipt.status, "ACTIVATED");

  fixture.now = Date.now() + 10;
  const canary = appendCanaryEvidence(fixture, {
    stage: "PRE_CUTOVER_HOST_CANARY",
    authorityDatabasePath,
  });
  const preRequest = {
    schemaVersion: 1,
    operation: "PRE_CUTOVER",
    management: fixture.precheckRequest.management,
    stores: {
      ...fixture.precheckRequest.stores,
      authorityDatabasePath,
    },
    selection: {
      stagingPrecheck: fixture.precheckRequest.selection,
      canary: canary.selector,
    },
    artifacts: { stagingPrecheckPath: precheckPath },
  };
  const pre = driver.createPreCutoverHostCanary(preRequest);
  assert.equal(pre.kind, "PRE_CUTOVER_HOST_CANARY");
  assert.equal(pre.payload.actualHost, true);
  assert.equal(pre.payload.mutation.providerDispatchCount, 1);
  assert.equal(pre.payload.mutation.cleanupPerformed, true);
  assert.equal(pre.payload.foreignClientIsolation.providerDispatchCount, 0);
  assert.notEqual(pre.payload.mutation.sessionAIdDigest, pre.payload.mutation.sessionBIdDigest);

  const wrongBinding = clone(preRequest);
  wrongBinding.selection.canary.expectedResourceDigest = digest("wrong-canary-resource");
  assert.throws(() => driver.createPreCutoverHostCanary(wrongBinding), /canary resource/u);
});

test("PRE canary fails closed on session, dispatch, readback, cleanup, authority, client, and token drift", async (t) => {
  const mutationAction = {
    tool: "fs",
    operation: "write",
    target: "fixture-target",
    resource: "/fixture/harmless-canary",
    parameters: { targetGeneration: digest("PRE_CUTOVER_HOST_CANARY-target-generation") },
  };
  const cases = [
    ["same ChatGPT session A/B", { sameSessions: true }, /distinct session A and session B/u],
    ["synthetic PASS with no provider dispatch", { omitProviderDispatch: true }, /provider dispatch count/u],
    ["provider dispatch count is two", { extraProviderDispatch: true }, /provider dispatch count/u],
    ["missing broker readback", { omitReadback: true }, /missing one exact post-readback/u],
    ["missing cleanup and absence readback", { omitCleanup: true }, /cleanup dispatch is missing/u],
    ["foreign client reaches provider", { foreignDispatch: true }, /Foreign client reached the provider boundary/u],
    ["discovery uses the wrong client", { discoveryClientId: "wrong-client" }, /stable client principal/u],
    ["authorization uses the wrong client", { authorizationClientId: "wrong-client" }, /stable client principal/u],
    ["durable claim uses the wrong principal", { authorityPrincipal: rawDigest("wrong-principal") }, /one exact authority claim/u],
    ["durable claim uses the wrong action", {
      authorityAction: { ...mutationAction, operation: "remove" },
    }, /one exact authority claim/u],
    ["durable claim uses the wrong resource", {
      authorityAction: { ...mutationAction, resource: "/fixture/different-resource" },
    }, /one exact authority claim/u],
    ["token family binds another connector generation", { wrongTokenBinding: true }, /exact new connector generation/u],
  ];
  for (const [name, canaryOptions, expected] of cases) {
    await t.test(name, () => {
      const ready = createReadyPreFixture({ canaryOptions, createPre: false });
      try {
        assert.throws(() => ready.driver.createPreCutoverHostCanary(ready.preRequest), expected);
      } finally {
        ready.cleanup();
      }
    });
  }

  await t.test("expired Host evidence", () => {
    const ready = createReadyPreFixture({ createPre: false });
    try {
      const expiredDriver = new ConnectorActivationReleaseDriver({
        runtime,
        now: () => ready.canary.hostObservation.occurredAtMs + 120_001,
      });
      assert.throws(
        () => expiredDriver.createPreCutoverHostCanary(ready.preRequest),
        /expired|currently valid|lifetime|stale/iu,
      );
    } finally {
      ready.cleanup();
    }
  });

  await t.test("staging OAuth receipt was never activated", () => {
    const ready = createReadyPreFixture({ createPre: false });
    try {
      const sqlite = new Database(ready.fixture.oauthDatabasePath);
      sqlite.prepare("update oauth_connector_bindings set state = 'ACTIVATION_PREPARED' where binding_id = ?")
        .run(ready.fixture.binding.bindingId);
      sqlite.close();
      assert.throws(
        () => ready.driver.createPreCutoverHostCanary(ready.preRequest),
        /OAuth connector binding does not match|not ACTIVATED/u,
      );
    } finally {
      ready.cleanup();
    }
  });
});

test("ledger tamper and foreign content-addressed record selection are rejected", (t) => {
  const fixture = createStagingFixture();
  const foreign = createStagingFixture();
  t.after(() => {
    fixture.cleanup();
    foreign.cleanup();
  });
  const driver = new ConnectorActivationReleaseDriver({ runtime, now: () => fixture.now });
  assert.throws(
    () => driver.createStagingActivationPrecheck({
      ...fixture.precheckRequest,
      selection: {
        ...fixture.precheckRequest.selection,
        candidateReadbackRecordId: foreign.candidate.recordDigest,
      },
    }),
    /trusted evidence record CANDIDATE_READBACK is missing/iu,
  );
  const lines = readFileSync(fixture.brokerLedgerPath, "utf8").trimEnd().split("\n").map(JSON.parse);
  lines[1].recordDigest = digest("forged-ledger-record");
  writeText(fixture.brokerLedgerPath, `${lines.map(JSON.stringify).join("\n")}\n`, 0o600);
  assert.throws(
    () => driver.createStagingActivationPrecheck(fixture.precheckRequest),
    /record digest is invalid|hash chain is invalid/u,
  );
});

test("candidate environment and route identities are derived for staging and production", async (t) => {
  const cases = [
    ["staging invented environment identity", "STAGING", "environment"],
    ["staging invented route identity", "STAGING", "route"],
    ["production invented environment identity", "PRODUCTION", "environment"],
    ["production invented route identity", "PRODUCTION", "route"],
  ];
  for (const [name, environmentRole, drift] of cases) {
    await t.test(name, () => {
      const ready = environmentRole === "STAGING"
        ? createStagingFixture({ candidateIdentityDrift: drift })
        : createProductionFixture({ candidateIdentityDrift: drift, autoPredecision: false });
      try {
        assert.throws(
          () => environmentRole === "STAGING"
            ? new ConnectorActivationReleaseDriver({ runtime, now: () => ready.now })
              .createStagingActivationPrecheck(ready.precheckRequest)
            : ready.driver.createProductionActivationPredecision(ready.predecisionRequest),
          drift === "environment"
            ? /candidate environment identity does not match the derived runtime\/resource binding/iu
            : /candidate route identity does not match the derived OAuth\/binding route/iu,
        );
      } finally {
        ready.cleanup();
      }
    });
  }
});

test("production predecision is canonical, authenticated, replay-bound, and OAuth read-only", async (t) => {
  await t.test("canonical code-unit bytes and domain-separated HMAC are independently reproducible", () => {
    const ready = createProductionFixture({ autoPredecision: false });
    try {
      const oauthBefore = readFileSync(ready.oauthDatabasePath);
      const envelope = ready.driver.createProductionActivationPredecision(ready.predecisionRequest);
      assert.deepEqual(readFileSync(ready.oauthDatabasePath), oauthBefore);
      assertProductionCandidateNotPrepared(ready);
      const base = {
        schemaVersion: 1,
        kind: "PRODUCTION_ACTIVATION_PREDECISION",
        keyId: ready.fixture.key.keyId,
        payload: envelope.payload,
      };
      const canonical = canonicalJson(base);
      assert.equal(envelope.payloadDigest, digest(canonical));
      assert.equal(
        envelope.signature,
        createHmac("sha256", ready.fixture.key.secret)
          .update(PRODUCTION_PREDECISION_DOMAIN)
          .update(canonical)
          .digest("base64url"),
      );
      assert.equal(
        canonicalJson(reverseObjectKeys({
          ...base,
          payload: reverseObjectKeys(base.payload),
        })),
        canonical,
        "insertion order must not change the signed canonical bytes",
      );
    } finally {
      ready.cleanup();
    }
  });

  await t.test("wrong management key cannot authenticate the persisted predecision", () => {
    const ready = createProductionFixture();
    try {
      const wrongKeyRuntime = Object.freeze({
        ...runtime,
        loadExistingManagementAuthorizationKey: () => Object.freeze({
          ...ready.fixture.key,
          secret: Uint8Array.from(Buffer.alloc(32, 0x5a)),
        }),
      });
      const driver = new ConnectorActivationReleaseDriver({
        runtime: wrongKeyRuntime,
        now: () => ready.fixture.now,
      });
      assert.throws(
        () => driver.createProductionActivationApproval(ready.request),
        /predecision signature is invalid/iu,
      );
      assertProductionCandidateNotPrepared(ready);
    } finally {
      ready.cleanup();
    }
  });

  await t.test("altered signed field and unexpected PASS are rejected before OAuth mutation", () => {
    const ready = createProductionFixture();
    try {
      const oauthBefore = readFileSync(ready.oauthDatabasePath);
      const altered = clone(ready.predecision);
      altered.payload.plan.refreshAllowedDuringDrain = !altered.payload.plan.refreshAllowedDuringDrain;
      altered.payload.PASS = true;
      writeText(ready.predecisionPath, `${JSON.stringify(altered)}\n`, 0o600);
      assert.throws(
        () => ready.driver.createProductionActivationApproval(ready.request),
        /unexpected or missing fields|payload digest|signature/iu,
      );
      assertProductionCandidateNotPrepared(ready);
      assert.deepEqual(readFileSync(ready.oauthDatabasePath), oauthBefore);
    } finally {
      ready.cleanup();
    }
  });

  await t.test("future-issued and expired predecisions are rejected", () => {
    const future = createProductionFixture();
    try {
      const altered = clone(future.predecision);
      altered.payload.issuedAtMs = future.fixture.now + 1;
      altered.payload.expiresAtMs = Math.min(
        altered.payload.issuedAtMs + 1_000,
        altered.payload.ownerDecision.expiresAtMs,
      );
      writeText(
        future.predecisionPath,
        `${JSON.stringify(resignProductionPredecision(altered, future.fixture.key))}\n`,
        0o600,
      );
      assert.throws(
        () => future.driver.createProductionActivationApproval(future.request),
        /future-issued|bounded lifetime/iu,
      );
      assertProductionCandidateNotPrepared(future);
    } finally {
      future.cleanup();
    }

    const expired = createProductionFixture();
    try {
      const staleDriver = new ConnectorActivationReleaseDriver({
        runtime,
        now: () => expired.predecision.payload.expiresAtMs + 1,
      });
      assert.throws(
        () => staleDriver.createProductionActivationApproval(expired.request),
        /expired|bounded lifetime/iu,
      );
      assertProductionCandidateNotPrepared(expired);
    } finally {
      expired.cleanup();
    }
  });

  await t.test("transaction replay and alternate output/control paths are rejected", () => {
    for (const kind of ["transaction", "output", "predecisionPath"]) {
      const ready = createProductionFixture();
      try {
        const changed = clone(ready.request);
        if (kind === "transaction") {
          changed.selection.transactionId = `upgrade_${randomUUID()}`;
        } else if (kind === "output") {
          changed.artifacts.productionApprovalOutputDirectory = join(
            ready.fixture.root,
            "alternate-production-approval-output",
          );
        } else {
          const alternate = join(ready.fixture.root, "alternate-production-predecision.json");
          copyFileSync(ready.predecisionPath, alternate);
          chmodSync(alternate, 0o600);
          changed.artifacts.predecisionPath = alternate;
        }
        writeText(
          ready.productionPreparationRequestPath,
          `${JSON.stringify(changed)}\n`,
          0o600,
        );
        assert.throws(
          () => ready.driver.createProductionActivationApproval(changed),
          /predecision.*transaction|transaction and output paths|signed predecision store or control path/iu,
        );
        assertProductionCandidateNotPrepared(ready);
      } finally {
        ready.cleanup();
      }
    }
  });
});

test("production-predecision CLI publishes only the signed owner decision and leaves OAuth unchanged", (t) => {
  const ready = createProductionFixture({ autoPredecision: false });
  t.after(() => ready.cleanup());
  const oauthBefore = readFileSync(ready.oauthDatabasePath);
  const command = [
    "scripts/connector-activation-release-driver.mjs",
    "production-predecision",
    "--request",
    ready.predecisionRequestPath,
    "--output",
    ready.predecisionPath,
  ];
  const wrongOutput = spawnSync(
    process.execPath,
    command.with(command.length - 1, join(ready.fixture.root, "alternate-predecision.json")),
    { cwd: process.cwd(), encoding: "utf8" },
  );
  assert.equal(wrongOutput.status, 64, wrongOutput.stderr);
  assert.deepEqual(readFileSync(ready.oauthDatabasePath), oauthBefore);
  assertProductionCandidateNotPrepared(ready);
  const executed = spawnSync(process.execPath, command, { cwd: process.cwd(), encoding: "utf8" });
  assert.equal(executed.status, 0, executed.stderr);
  const summary = JSON.parse(executed.stdout);
  assert.equal(summary.path, ready.predecisionPath);
  assert.equal(summary.kind, "PRODUCTION_ACTIVATION_PREDECISION");
  assert.equal(statSync(ready.predecisionPath).mode & 0o777, 0o600);
  assert.equal(JSON.parse(readFileSync(ready.predecisionPath, "utf8")).kind, summary.kind);
  assert.deepEqual(readFileSync(ready.oauthDatabasePath), oauthBefore);
  assertProductionCandidateNotPrepared(ready);
  assert.equal(executed.stdout.includes(Buffer.from(ready.fixture.key.secret).toString("base64url")), false);
  assert.equal(executed.stderr, "");
});

test("production approval creates the real PREPARED receipt and atomically publishes separate signed envelopes", (t) => {
  const ready = createProductionFixture();
  t.after(() => ready.cleanup());
  const bundle = ready.driver.createProductionActivationApproval(ready.request);
  assert.equal(bundle.productionActivationPrecheck.kind, "PRODUCTION_ACTIVATION_PRECHECK");
  assert.equal(bundle.ownerManagementApproval.kind, "OWNER_MANAGEMENT_APPROVAL");
  assert.equal(bundle.manifest.receiptId, bundle.productionActivationPrecheck.payload.receiptId);
  assert.equal(bundle.manifest.tupleDigest, ready.tupleDigest);
  assert.equal(bundle.manifest.activePreimageDigest, ready.activePreimageDigest);
  assert.equal(bundle.manifest.migrationManifestDigest, ready.fixture.packageFixture.migrationManifestDigest);
  const serialized = JSON.stringify(bundle);
  for (const secret of ready.rawClientSecrets) assert.equal(serialized.includes(secret), false);
  assert.equal(serialized.includes(Buffer.from(ready.fixture.key.secret).toString("base64url")), false);
  const readback = new oauth.SqliteOAuthStore(ready.oauthStateDir);
  const receipt = readback.getActivationReceipt(bundle.manifest.receiptId);
  assert.equal(receipt?.status, "PREPARED");
  assert.equal(readback.getConnectorBinding(ready.candidateBindingId)?.state, "ACTIVATION_PREPARED");
  readback.close();

  const oauthAfterPrepare = readFileSync(ready.oauthDatabasePath);
  const reconstructedAfterCrash = ready.driver.createProductionActivationApproval(ready.request);
  assert.deepEqual(
    reconstructedAfterCrash,
    bundle,
    "PREPARED with absent output must reconstruct without preparing again",
  );
  assert.deepEqual(readFileSync(ready.oauthDatabasePath), oauthAfterPrepare);
  assert.equal(productionReceiptCount(ready), 1);

  const outputDirectory = ready.productionApprovalOutputDirectory;
  const published = writeProductionApprovalDirectoryAtomic(outputDirectory, bundle);
  assert.equal(
    JSON.parse(readFileSync(published.productionActivationPrecheckPath, "utf8")).kind,
    "PRODUCTION_ACTIVATION_PRECHECK",
  );
  assert.equal(
    JSON.parse(readFileSync(published.ownerManagementApprovalPath, "utf8")).kind,
    "OWNER_MANAGEMENT_APPROVAL",
  );
  assert.equal(JSON.parse(readFileSync(published.manifestPath, "utf8")).receiptId, receipt.receiptId);

  const completeBytes = {
    oauth: readFileSync(ready.oauthDatabasePath),
    precheck: readFileSync(published.productionActivationPrecheckPath),
    approval: readFileSync(published.ownerManagementApprovalPath),
    manifest: readFileSync(published.manifestPath),
  };
  const resumedBundle = ready.driver.createProductionActivationApproval(ready.request);
  assert.deepEqual(resumedBundle, bundle, "exact PREPARED reconciliation must reconstruct identical artifacts");
  assert.deepEqual(
    writeProductionApprovalDirectoryAtomic(outputDirectory, resumedBundle),
    published,
    "complete output resume must verify exact bytes without overwriting them",
  );
  assert.deepEqual(readFileSync(ready.oauthDatabasePath), completeBytes.oauth);
  assert.deepEqual(readFileSync(published.productionActivationPrecheckPath), completeBytes.precheck);
  assert.deepEqual(readFileSync(published.ownerManagementApprovalPath), completeBytes.approval);
  assert.deepEqual(readFileSync(published.manifestPath), completeBytes.manifest);

  rmSync(published.ownerManagementApprovalPath);
  const partialResume = ready.driver.createProductionActivationApproval(ready.request);
  assert.deepEqual(partialResume, bundle);
  assert.deepEqual(
    writeProductionApprovalDirectoryAtomic(outputDirectory, partialResume),
    published,
    "partial exact output must restore only the missing deterministic artifact",
  );
  assert.deepEqual(readFileSync(published.productionActivationPrecheckPath), completeBytes.precheck);
  assert.deepEqual(readFileSync(published.ownerManagementApprovalPath), completeBytes.approval);
  assert.deepEqual(readFileSync(published.manifestPath), completeBytes.manifest);
  assert.deepEqual(readFileSync(ready.oauthDatabasePath), completeBytes.oauth);
  assert.equal(productionReceiptCount(ready), 1);
});

test("production-approve CLI preflights output and publishes owner-only split artifacts", (t) => {
  const ready = createProductionFixture();
  t.after(() => ready.cleanup());
  const requestPath = ready.productionPreparationRequestPath;
  const outputDirectory = ready.productionApprovalOutputDirectory;
  const command = [
    "scripts/connector-activation-release-driver.mjs",
    "production-approve",
    "--request",
    requestPath,
    "--output",
    outputDirectory,
  ];
  const executed = spawnSync(process.execPath, command, {
    cwd: process.cwd(),
    encoding: "utf8",
  });
  assert.equal(executed.status, 0, executed.stderr);
  const summary = JSON.parse(executed.stdout);
  assert.equal(summary.directoryPath, outputDirectory);
  assert.equal(summary.candidateIdentity.packageSha256, ready.fixture.candidateIdentity.packageSha256);
  assert.equal(summary.migrationManifestDigest, ready.fixture.packageFixture.migrationManifestDigest);
  assert.equal(summary.productionEnvironmentIdentityDigest, ready.candidate.payload.environmentIdentityDigest);
  assert.equal(summary.productionRouteIdentityDigest, ready.candidate.payload.routeIdentityDigest);
  assert.equal(summary.oauthResource, ready.candidate.payload.oauthResource);
  assert.equal(statSync(outputDirectory).mode & 0o777, 0o700);
  for (const path of [
    summary.manifestPath,
    summary.productionActivationPrecheckPath,
    summary.ownerManagementApprovalPath,
  ]) assert.equal(statSync(path).mode & 0o777, 0o600);
  const persistedManifest = JSON.parse(readFileSync(summary.manifestPath, "utf8"));
  assert.equal(
    persistedManifest.productionActivationPrecheck.sha256,
    digest(readFileSync(summary.productionActivationPrecheckPath)),
  );
  assert.equal(
    persistedManifest.ownerManagementApproval.sha256,
    digest(readFileSync(summary.ownerManagementApprovalPath)),
  );
  assert.equal(JSON.parse(readFileSync(summary.productionActivationPrecheckPath, "utf8")).kind, "PRODUCTION_ACTIVATION_PRECHECK");
  assert.equal(JSON.parse(readFileSync(summary.ownerManagementApprovalPath, "utf8")).kind, "OWNER_MANAGEMENT_APPROVAL");
  assert.equal(executed.stdout.includes(Buffer.from(ready.fixture.key.secret).toString("base64url")), false);
  assert.equal(executed.stderr, "");

  const second = spawnSync(process.execPath, command, { cwd: process.cwd(), encoding: "utf8" });
  assert.equal(second.status, 0, second.stderr);
  assert.deepEqual(JSON.parse(second.stdout), summary);
  assert.equal(productionReceiptCount(ready), 1);
});

test("concurrent post-snapshot approval processes create one PREPARED receipt", async (t) => {
  const ready = createProductionFixture();
  t.after(() => ready.cleanup());
  const command = [
    "scripts/connector-activation-release-driver.mjs",
    "production-approve",
    "--request",
    ready.productionPreparationRequestPath,
    "--output",
    ready.productionApprovalOutputDirectory,
  ];
  const results = await Promise.all([
    runChild(process.execPath, command),
    runChild(process.execPath, command),
  ]);
  const successes = results.filter((result) => result.status === 0);
  assert.ok(successes.length >= 1, results.map((result) => result.stderr).join("\n"));
  for (const result of results) {
    assert.ok([0, 65].includes(result.status), result.stderr);
    assert.equal(result.stdout.includes(Buffer.from(ready.fixture.key.secret).toString("base64url")), false);
    assert.equal(result.stderr.includes(Buffer.from(ready.fixture.key.secret).toString("base64url")), false);
  }
  const summaries = successes.map((result) => JSON.parse(result.stdout));
  for (const summary of summaries.slice(1)) assert.deepEqual(summary, summaries[0]);
  assert.equal(productionReceiptCount(ready), 1);
  assert.equal(
    JSON.parse(readFileSync(join(ready.productionApprovalOutputDirectory, "manifest.json"), "utf8")).receiptId,
    summaries[0].receiptId,
  );
});

test("production preparation rejects stale, concurrent, invented, and drifted bindings before signing", async (t) => {
  await t.test("caller authority, proof, tuple, and candidate identity are not wire-authoritative", () => {
    const ready = createProductionFixture();
    try {
      const invented = clone(ready.request);
      Object.assign(invented.selection, {
        authorityId: `authority_${randomUUID()}`,
        proof: { pass: true },
        tuple: ready.tuple,
        candidateIdentity: ready.fixture.candidateIdentity,
      });
      assert.throws(
        () => ready.driver.createProductionActivationApproval(invented),
        /unexpected or missing fields/u,
      );
      assertProductionCandidateNotPrepared(ready);
    } finally {
      ready.cleanup();
    }
  });

  await t.test("expired PRE evidence", () => {
    const ready = createProductionFixture();
    try {
      const staleDriver = new ConnectorActivationReleaseDriver({
        runtime,
        now: () => ready.pre.payload.expiresAtMs + 1,
      });
      assert.throws(
        () => staleDriver.createProductionActivationApproval(ready.request),
        /expired|currently valid|lifetime|fresh|stale/iu,
      );
      assertProductionCandidateNotPrepared(ready);
    } finally {
      ready.cleanup();
    }
  });

  await t.test("stale production candidate readback", () => {
    const ready = createProductionFixture({ productionCandidateAgeMs: 120_001, autoPredecision: false });
    try {
      assert.throws(
        () => ready.driver.createProductionActivationPredecision(ready.predecisionRequest),
        /production candidate readback is stale/u,
      );
      assertProductionCandidateNotPrepared(ready);
    } finally {
      ready.cleanup();
    }
  });

  await t.test("expired conditional owner decision", () => {
    const ready = createProductionFixture({ autoPredecision: false });
    try {
      const expiredDecisionDriver = new ConnectorActivationReleaseDriver({
        runtime,
        now: () => ready.decision.payload.expiresAtMs + 1,
      });
      assert.throws(
        () => expiredDecisionDriver.createProductionActivationPredecision(ready.predecisionRequest),
        /owner approval decision.*stale|owner approval decision.*lifetime/iu,
      );
      assertProductionCandidateNotPrepared(ready);
    } finally {
      ready.cleanup();
    }
  });

  await t.test("candidate changes concurrently after read-only tuple reconstruction", () => {
    const ready = createProductionFixture();
    let mutated = false;
    class ConcurrentOAuthStore extends oauth.SqliteOAuthStore {
      constructor(stateDir) {
        if (!mutated) {
          const concurrent = new oauth.SqliteOAuthStore(stateDir);
          concurrent.rejectConnectorBinding(ready.candidateBindingId, "CONCURRENT_RELEASE_REJECTION");
          concurrent.close();
          mutated = true;
        }
        super(stateDir);
      }
    }
    const concurrentRuntime = Object.freeze({ ...runtime, SqliteOAuthStore: ConcurrentOAuthStore });
    try {
      const driver = new ConnectorActivationReleaseDriver({ runtime: concurrentRuntime });
      assert.throws(
        () => driver.createProductionActivationApproval(ready.request),
        /changed before activation preparation/u,
      );
      assertProductionCandidateNotPrepared(ready, "REJECTED");
    } finally {
      ready.cleanup();
    }
  });

  for (const [name, column, value, expected] of [
    ["tuple client drift", "client_id", "ACTIVE_CLIENT", /tuple drifted|does not match/u],
    ["tuple schema drift", "schema_generation", digest("drifted-schema"), /tuple drifted|does not match/u],
    ["tuple authority drift", "authority_contract_generation", digest("drifted-authority"), /tuple drifted|does not match/u],
    ["tuple redirect drift", "redirect_uris_digest", digest("drifted-redirect"), /tuple drifted|does not match/u],
    ["tuple build drift", "build_digest", digest("drifted-build"), /tuple drifted|does not match/u],
  ]) {
    await t.test(name, () => {
      const ready = createProductionFixture();
      try {
        const sqlite = new Database(ready.oauthDatabasePath);
        const replacement = value === "ACTIVE_CLIENT"
          ? sqlite.prepare("select client_id from oauth_connector_bindings where state = 'ACTIVE'").pluck().get()
          : value;
        sqlite.prepare(`update oauth_connector_bindings set ${column} = ? where binding_id = ?`)
          .run(replacement, ready.candidateBindingId);
        sqlite.close();
        assert.throws(() => ready.driver.createProductionActivationApproval(ready.request), expected);
        assertProductionCandidateNotPrepared(ready);
      } finally {
        ready.cleanup();
      }
    });
  }

  await t.test("canonical ACTIVE preimage drift", () => {
    const ready = createProductionFixture();
    try {
      const sqlite = new Database(ready.oauthDatabasePath);
      sqlite.prepare("update oauth_connector_bindings set ref_count = ref_count + 1 where state = 'ACTIVE'")
        .run();
      sqlite.close();
      assert.throws(
        () => ready.driver.createProductionActivationApproval(ready.request),
        /ACTIVE preimage drifted/u,
      );
      assertProductionCandidateNotPrepared(ready);
    } finally {
      ready.cleanup();
    }
  });

  await t.test("foreign already-PREPARED candidate state", () => {
    const ready = createProductionFixture();
    try {
      const sqlite = new Database(ready.oauthDatabasePath);
      sqlite.prepare(`
        update oauth_connector_bindings
           set state = 'ACTIVATION_PREPARED', state_reason = ?
         where binding_id = ?
      `).run("foreign-prepared-receipt", ready.candidateBindingId);
      sqlite.close();
      assert.throws(
        () => ready.driver.createProductionActivationApproval(ready.request),
        /neither exact VERIFIED nor exact reconciled PREPARED|foreign PREPARED/iu,
      );
      assert.equal(productionReceiptCount(ready), 0);
    } finally {
      ready.cleanup();
    }
  });

  await t.test("snapshot bytes, worker status, and claim drift", () => {
    for (const kind of ["snapshot", "status", "claim"]) {
      const ready = createProductionFixture();
      try {
        if (kind === "snapshot") {
          const sqlite = new Database(ready.oauthSnapshotPath);
          sqlite.prepare("update oauth_connector_bindings set ref_count = ref_count + 1 where state = 'ACTIVE'")
            .run();
          sqlite.close();
        } else if (kind === "status") {
          const status = JSON.parse(readFileSync(ready.statusPath, "utf8"));
          status.state = "PREFLIGHT_VERIFIED";
          writeText(ready.statusPath, `${JSON.stringify(status)}\n`, 0o600);
        } else {
          const claim = JSON.parse(readFileSync(ready.workerClaimPath, "utf8"));
          claim.acquiredAt = new Date(ready.fixture.now + 1).toISOString();
          const status = JSON.parse(readFileSync(ready.statusPath, "utf8"));
          status.workerClaim = claim;
          writeText(ready.workerClaimPath, `${JSON.stringify(claim)}\n`, 0o600);
          writeText(ready.statusPath, `${JSON.stringify(status)}\n`, 0o600);
        }
        assert.throws(
          () => ready.driver.createProductionActivationApproval(ready.request),
          /snapshot|STATE_SNAPSHOTTED|future-issued|worker claim/iu,
        );
        assertProductionCandidateNotPrepared(ready);
      } finally {
        ready.cleanup();
      }
    }
  });

  await t.test("finalization PREPARED identity drift immediately before OAuth CAS", () => {
    const ready = createProductionFixture();
    let reads = 0;
    const driver = new ConnectorActivationReleaseDriver({
      runtime,
      now: () => ready.fixture.now,
      finalizationIdentityReader: (options) => {
        const identity = readFinalizationStoreIdentity(options);
        reads += 1;
        return reads === 1 ? identity : { ...identity, contentGeneration: digest("drifted-finalization") };
      },
    });
    try {
      assert.throws(
        () => driver.createProductionActivationApproval(ready.request),
        /finalization PREPARED identity drifted/iu,
      );
      assert.equal(reads, 2);
      assertProductionCandidateNotPrepared(ready);
    } finally {
      ready.cleanup();
    }
  });

  await t.test("immutable build-capability manifest drift", () => {
    const ready = createProductionFixture();
    try {
      const path = join(ready.fixture.packageFixture.packageRoot, "BUILD-MANIFEST.json");
      const manifest = JSON.parse(readFileSync(path, "utf8"));
      manifest.buildCapabilities.capabilityDigest = digest("drifted-build-capability");
      writeText(path, `${JSON.stringify(manifest)}\n`, 0o644);
      assert.throws(
        () => ready.driver.createProductionActivationApproval(ready.request),
        /immutable release identity|candidate identity does not match/iu,
      );
      assertProductionCandidateNotPrepared(ready);
    } finally {
      ready.cleanup();
    }
  });

  await t.test("generated schema tree drift", () => {
    const ready = createProductionFixture();
    try {
      writeText(
        join(ready.fixture.packageFixture.packageRoot, GENERATED_SCHEMA_FILES[0]),
        `${JSON.stringify({ drifted: true })}\n`,
        0o644,
      );
      assert.throws(
        () => ready.driver.createProductionActivationApproval(ready.request),
        /payload tree does not match/u,
      );
      assertProductionCandidateNotPrepared(ready);
    } finally {
      ready.cleanup();
    }
  });

  await t.test("migration-manifest identity drift", () => {
    const ready = createProductionFixture();
    try {
      const path = join(ready.fixture.packageFixture.packageRoot, "BUILD-MANIFEST.json");
      const manifest = JSON.parse(readFileSync(path, "utf8"));
      manifest.migrationManifestDigest = digest("drifted-migration-manifest");
      writeText(path, `${JSON.stringify(manifest)}\n`, 0o644);
      assert.throws(
        () => ready.driver.createProductionActivationApproval(ready.request),
        /immutable release identity|migration identity does not match/iu,
      );
      assertProductionCandidateNotPrepared(ready);
    } finally {
      ready.cleanup();
    }
  });

  await t.test("drain plan differs from conditional owner approval", () => {
    const ready = createProductionFixture({ autoPredecision: false });
    try {
      const changed = clone(ready.predecisionRequest);
      changed.selection.refreshAllowedDuringDrain = !changed.selection.refreshAllowedDuringDrain;
      assert.throws(
        () => ready.driver.createProductionActivationPredecision(changed),
        /owner approval decision.*conditions/iu,
      );
      assertProductionCandidateNotPrepared(ready);
    } finally {
      ready.cleanup();
    }
  });
});

test("POST canary derives the activated production tuple, token family, prior DRAINING binding, and actual Host evidence", (t) => {
  const ready = createPostFixture();
  t.after(() => ready.cleanup());
  const post = ready.driver.createPostActivationHostCanary(ready.request);
  assert.equal(post.kind, "POST_ACTIVATION_HOST_CANARY");
  assert.equal(post.payload.actualHost, true);
  assert.equal(post.payload.activationReceiptId, ready.activationReceipt.receiptId);
  assert.equal(post.payload.newActiveBindingState, "ACTIVE");
  assert.equal(post.payload.previousActiveBindingId, ready.activationReceipt.previousActiveBindingId);
  assert.equal(post.payload.previousBindingState, "DRAINING");
  assert.equal(post.payload.tokenFamilyBindingId, ready.candidateBindingId);
  assert.equal(post.payload.mutation.providerDispatchCount, 1);
  assert.equal(post.payload.mutation.cleanupPerformed, true);
  assert.equal(post.payload.foreignClientIsolation.providerDispatchCount, 0);
  assert.notEqual(post.payload.mutation.sessionAIdDigest, post.payload.mutation.sessionBIdDigest);

  const store = new oauth.SqliteOAuthStore(ready.oauthStateDir);
  assert.equal(store.getConnectorBinding(ready.candidateBindingId)?.state, "ACTIVE");
  assert.equal(store.getConnectorBinding(ready.activationReceipt.previousActiveBindingId)?.state, "DRAINING");
  store.close();
});

test("POST canary rejects PREPARED-only production, OAuth-resource drift, and missing prior DRAINING state", async (t) => {
  await t.test("production receipt is still PREPARED", () => {
    const ready = createProductionFixture();
    try {
      const bundle = ready.driver.createProductionActivationApproval(ready.request);
      const output = writeProductionApprovalDirectoryAtomic(
        join(ready.fixture.root, "prepared-only-production-approval"),
        bundle,
      );
      const request = {
        schemaVersion: 1,
        operation: "POST_ACTIVATION",
        management: ready.fixture.precheckRequest.management,
        stores: {
          auditLogPath: ready.fixture.auditLogPath,
          brokerLedgerPath: ready.fixture.brokerLedgerPath,
          hostLedgerPath: ready.fixture.hostLedgerPath,
          oauthDatabasePath: ready.oauthDatabasePath,
          authorityDatabasePath: ready.authorityDatabasePath,
        },
        selection: {
          activeStagingCandidateReadbackRecordId: ready.canary.candidate.recordDigest,
          stagingPrecheck: ready.fixture.precheckRequest.selection,
          canary: ready.canary.selector,
        },
        artifacts: {
          stagingPrecheckPath: ready.precheckPath,
          preCutoverPath: ready.prePath,
          productionPrecheckPath: output.productionActivationPrecheckPath,
          ownerApprovalPath: output.ownerManagementApprovalPath,
        },
      };
      assert.throws(
        () => ready.driver.createPostActivationHostCanary(request),
        /activation receipt is not ACTIVATED/u,
      );
    } finally {
      ready.cleanup();
    }
  });

  await t.test("production OAuth resource changes after signed precheck", () => {
    const ready = createPostFixture({ oauthResource: "https://drifted-production.example.test/mcp" });
    try {
      assert.throws(
        () => ready.driver.createPostActivationHostCanary(ready.request),
        /trusted OAuth resource|exact production precheck/u,
      );
    } finally {
      ready.cleanup();
    }
  });

  await t.test("prior production binding is no longer DRAINING", () => {
    const ready = createPostFixture();
    try {
      const sqlite = new Database(ready.oauthDatabasePath);
      sqlite.prepare("update oauth_connector_bindings set state = 'RETIRED' where binding_id = ?")
        .run(ready.activationReceipt.previousActiveBindingId);
      sqlite.close();
      assert.throws(
        () => ready.driver.createPostActivationHostCanary(ready.request),
        /Prior production connector is not DRAINING/u,
      );
    } finally {
      ready.cleanup();
    }
  });
});

function createRollbackFixture({ now = 1_800_100_000_000 } = {}) {
  const root = secureTemp("connector-rollback-");
  const managementState = secureDirectory(join(root, "management"));
  const key = management.loadOrCreateManagementAuthorizationKey({ keyRef: "release", stateDir: managementState });
  const hostLedgerPath = join(root, "host.ndjson");
  const brokerLedgerPath = join(root, "broker.ndjson");
  const challengePath = join(root, "rollback-challenge.json");
  const receiptPath = join(root, "rollback-receipt.json");
  const transactionId = "transaction-rollback-fixture";
  const broker = [];
  const host = [];
  const preimage = appendLedger(broker, "DEVSPACE_BROKER", "ROLLBACK_PREIMAGE_READBACK", now - 10, {
    transactionId,
    managementCorrelationId: "rollback-correlation-fixture",
    previousRuntimeIdentityDigest: digest("rollback-runtime"),
    previousMainMigrationIdentityDigest: digest("rollback-migration"),
  });
  writeLedger(brokerLedgerPath, broker);
  writeLedger(hostLedgerPath, host);
  const base = {
    schemaVersion: 1,
    management: { stateDir: managementState, keyRef: key.path },
  };
  const challengeRequest = {
    ...base,
    operation: "ROLLBACK_CHALLENGE",
    stores: { brokerLedgerPath },
    selection: { rollbackPreimageRecordId: preimage.recordDigest },
    artifacts: { receiptPath },
  };
  let healthReadback;
  let readyReadback;
  let runtimeReadback;
  let expectedReadbacks;
  const fixture = {
    root,
    now,
    key,
    transactionId,
    challengePath,
    receiptPath,
    challengeRequest,
    hostRequest: undefined,
    verifyRequest: undefined,
    get expectedReadbacks() { return expectedReadbacks; },
    get runtimeReadback() { return runtimeReadback; },
    appendObservation(challenge) {
      const sessionA = digest("rollback-session-a");
      const sessionB = digest("rollback-session-b");
      const common = {
        challengeId: challenge.payload.challengeId,
        transactionId,
        nonce: challenge.payload.nonce,
        correlationId: challenge.payload.managementCorrelationId,
      };
      healthReadback = appendLedger(broker, "DEVSPACE_BROKER", "ROLLBACK_HEALTH_READBACK", now + 1, {
        ...common,
        sessionIdentityDigest: sessionA,
        httpStatus: 200,
        responseDigest: digest("rollback-health-response"),
      });
      readyReadback = appendLedger(broker, "DEVSPACE_BROKER", "ROLLBACK_READY_READBACK", now + 2, {
        ...common,
        sessionIdentityDigest: sessionB,
        httpStatus: 200,
        runtimeIdentityDigest: preimage.payload.previousRuntimeIdentityDigest,
        responseDigest: digest("rollback-ready-response"),
      });
      runtimeReadback = appendLedger(broker, "DEVSPACE_BROKER", "ROLLBACK_RUNTIME_READBACK", now + 3, {
        ...common,
        sessionIdentityDigest: sessionB,
        processName: "devspace-previous",
        processStatus: "online",
        cwd: join(root, "previous-runtime"),
        script: join(root, "previous-runtime", "dist", "cli.js"),
        runtimeIdentityDigest: preimage.payload.previousRuntimeIdentityDigest,
        mainMigrationIdentityDigest: preimage.payload.previousMainMigrationIdentityDigest,
        responseDigest: digest("rollback-runtime-response"),
      });
      const observation = appendLedger(host, "CHATGPT_HOST", "CHATGPT_ROLLBACK_HOST", now + 4, {
        challengeId: challenge.payload.challengeId,
        transactionId,
        managementCorrelationId: challenge.payload.managementCorrelationId,
        sessionA: {
          sessionIdentityDigest: sessionA,
          transcriptDigest: digest("rollback-transcript-a"),
          healthReadbackRecordId: healthReadback.recordDigest,
        },
        sessionB: {
          sessionIdentityDigest: sessionB,
          transcriptDigest: digest("rollback-transcript-b"),
          readyReadbackRecordId: readyReadback.recordDigest,
          runtimeReadbackRecordId: runtimeReadback.recordDigest,
        },
      });
      writeLedger(brokerLedgerPath, broker);
      writeLedger(hostLedgerPath, host);
      expectedReadbacks = {
        healthReadbackDigest: connectorRollbackHealthReadbackDigest({
          challengeId: challenge.payload.challengeId,
          transactionId,
          nonce: challenge.payload.nonce,
          managementCorrelationId: challenge.payload.managementCorrelationId,
          httpStatus: 200,
        }),
        readyReadbackDigest: connectorRollbackReadyReadbackDigest({
          challengeId: challenge.payload.challengeId,
          transactionId,
          nonce: challenge.payload.nonce,
          managementCorrelationId: challenge.payload.managementCorrelationId,
          httpStatus: 200,
          runtimeIdentityDigest: preimage.payload.previousRuntimeIdentityDigest,
        }),
        runtimeReadbackDigest: connectorRollbackRuntimeReadbackDigest({
          challengeId: challenge.payload.challengeId,
          transactionId,
          nonce: challenge.payload.nonce,
          managementCorrelationId: challenge.payload.managementCorrelationId,
          processName: runtimeReadback.payload.processName,
          processStatus: runtimeReadback.payload.processStatus,
          cwd: runtimeReadback.payload.cwd,
          script: runtimeReadback.payload.script,
          runtimeIdentityDigest: preimage.payload.previousRuntimeIdentityDigest,
          mainMigrationIdentityDigest: preimage.payload.previousMainMigrationIdentityDigest,
        }),
      };
      this.now = now + 5;
      this.hostRequest = {
        ...base,
        operation: "ROLLBACK_HOST",
        stores: { brokerLedgerPath, hostLedgerPath },
        selection: {
          rollbackPreimageRecordId: preimage.recordDigest,
          hostObservationRecordId: observation.recordDigest,
          expectedSessionATranscriptDigest: digest("rollback-transcript-a"),
          expectedSessionBTranscriptDigest: digest("rollback-transcript-b"),
        },
        artifacts: { challengePath, receiptPath },
      };
      this.verifyRequest = {
        ...base,
        operation: "ROLLBACK_VERIFY",
        stores: { brokerLedgerPath },
        selection: {
          rollbackPreimageRecordId: preimage.recordDigest,
          healthReadbackRecordId: healthReadback.recordDigest,
          readyReadbackRecordId: readyReadback.recordDigest,
          runtimeReadbackRecordId: runtimeReadback.recordDigest,
        },
        artifacts: { challengePath, receiptPath },
      };
    },
    rewriteHostSessionsSame() {
      const last = host.at(-1);
      last.payload.sessionB.sessionIdentityDigest = last.payload.sessionA.sessionIdentityDigest;
      rewriteLedgerRecord(host, host.length - 1);
      this.hostRequest.selection.hostObservationRecordId = host.at(-1).recordDigest;
      writeLedger(hostLedgerPath, host);
    },
    cleanup: () => rmSync(root, { recursive: true, force: true }),
  };
  return fixture;
}

function createStagingFixture({ candidateIdentityDrift } = {}) {
  const root = secureTemp("connector-staging-");
  const now = Date.now() - 100;
  const packageFixture = createPackageFixture(root);
  const managementState = secureDirectory(join(root, "management"));
  const oauthStateDir = secureDirectory(join(root, "oauth"));
  const key = management.loadOrCreateManagementAuthorizationKey({ keyRef: "release", stateDir: managementState });
  const store = new oauth.SqliteOAuthStore(oauthStateDir);
  const clients = new oauth.SqliteOAuthClientsStore(store, ["chatgpt.com"]);
  const client = clients.registerClient({
    redirect_uris: ["https://chatgpt.com/aip/g-test/oauth/callback"],
    client_name: "fixture staging candidate",
  });
  const initial = store.ensureCandidateConnectorBinding({
    canonicalName: "myDevSpace",
    clientId: client.client_id,
    installationEpoch: 1,
    schemaGeneration: packageFixture.candidateIdentity.schemaGeneration,
  });
  const binding = store.markConnectorBindingVerified(initial.bindingId, {
    authorityContractGeneration: packageFixture.candidateIdentity.authorityContractGeneration,
    redirectUrisDigest: digest("redirect-uris"),
    buildDigest: packageFixture.candidateIdentity.buildDigest,
  });
  const receipt = store.prepareConnectorActivation(activationTuple(binding), {
    drainDeadlineAt: new Date(now + 600_000).toISOString(),
    refreshAllowedDuringDrain: false,
  });
  store.close();
  chmodSync(join(oauthStateDir, "devspace.sqlite"), 0o600);

  const hostLedgerPath = join(root, "host.ndjson");
  const brokerLedgerPath = join(root, "broker.ndjson");
  const auditLogPath = join(root, "audit.ndjson");
  const oauthResource = "https://staging.example.test/mcp";
  const environmentIdentityDigest = routeIdentity.connectorEnvironmentIdentityDigest({
    environmentRole: "STAGING",
    runtimeIdentityDigest: packageFixture.candidateIdentity.runtimeIdentityDigest,
    oauthResource,
  });
  const routeIdentityDigest = routeIdentity.connectorRouteIdentityDigest({
    oauthResource,
    canonicalName: binding.canonicalName,
    bindingId: binding.bindingId,
  });
  const principal = rawDigest("stable-owner-principal");
  const managementCorrelationId = "staging-management-correlation";
  const broker = [];
  const candidatePayload = {
    environmentRole: "STAGING",
    environmentIdentityDigest: candidateIdentityDrift === "environment"
      ? digest("invented-staging-environment")
      : environmentIdentityDigest,
    routeIdentityDigest: candidateIdentityDrift === "route"
      ? digest("invented-staging-route")
      : routeIdentityDigest,
    oauthResource,
    migrationManifestDigest: packageFixture.migrationManifestDigest,
    packageRoot: packageFixture.packageRoot,
    candidateIdentity: packageFixture.candidateIdentity,
    canonicalName: binding.canonicalName,
    clientId: binding.clientId,
    bindingId: binding.bindingId,
    installationEpoch: binding.installationEpoch,
    redirectUrisDigest: binding.redirectUrisDigest,
    bindingState: "ACTIVATION_PREPARED",
    receiptId: receipt.receiptId,
    activePreimageDigest: null,
  };
  const candidate = candidateIdentityDrift
    ? appendLedgerUnchecked(broker, "DEVSPACE_BROKER", "CANDIDATE_READBACK", now - 20, candidatePayload)
    : appendLedger(broker, "DEVSPACE_BROKER", "CANDIDATE_READBACK", now - 20, candidatePayload);
  const discoverySession = digest("staging-discovery-session");
  const r0Session = digest("staging-r0-session");
  const discovery = appendLedger(broker, "DEVSPACE_BROKER", "TOOL_DISCOVERY", now - 15, {
    requestId: "staging-discovery-request",
    correlationId: "staging-discovery-correlation",
    managementCorrelationId,
    sessionIdentityDigest: discoverySession,
    clientId: binding.clientId,
    principalKeyFingerprint: principal,
    environmentIdentityDigest,
    routeIdentityDigest,
    responseDigest: digest("staging-discovery-response"),
    toolNames: TOOLS,
  });
  const r0Action = {
    tool: "fs",
    operation: "read",
    target: "fixture-target",
    resource: "/fixture/canary",
    parameters: {},
  };
  const r0 = appendLedger(broker, "DEVSPACE_BROKER", "TOOL_REQUEST", now - 14, {
    requestId: "staging-r0-request",
    correlationId: "staging-r0-correlation",
    managementCorrelationId,
    sessionIdentityDigest: r0Session,
    clientId: binding.clientId,
    principalKeyFingerprint: principal,
    environmentIdentityDigest,
    routeIdentityDigest,
    operationId: "staging-r0-operation",
    tool: "fs",
    operation: "read",
    argumentsDigest: digest("staging-r0-arguments"),
    resourceDigest: digest("staging-r0-resource"),
    responseDigest: digest("staging-r0-response"),
    outcome: "PASS",
    action: r0Action,
  });
  const dispatch = appendLedger(broker, "DEVSPACE_BROKER", "PROVIDER_DISPATCH", now - 13, {
    requestRecordId: r0.recordDigest,
    correlationId: r0.payload.correlationId,
    operationId: r0.payload.operationId,
    tool: r0.payload.tool,
    operation: r0.payload.operation,
    resourceDigest: r0.payload.resourceDigest,
    resultDigest: r0.payload.responseDigest,
  });
  const readback = appendLedger(broker, "DEVSPACE_BROKER", "RESOURCE_READBACK", now - 12, {
    requestRecordId: r0.recordDigest,
    correlationId: r0.payload.correlationId,
    resourceDigest: r0.payload.resourceDigest,
    readbackDigest: digest("staging-r0-readback"),
  });
  const host = [];
  const observation = appendLedger(host, "CHATGPT_HOST", "CHATGPT_STAGING_DISCOVERY_R0", now - 10, {
    stagingActivationPrecheckId: "staging-precheck-fixture",
    managementNonce: "staging-management-nonce",
    managementCorrelationId,
    environmentIdentityDigest,
    routeIdentityDigest,
    discovery: {
      sessionIdentityDigest: discoverySession,
      transcriptDigest: digest("staging-discovery-transcript"),
      brokerRequestRecordId: discovery.recordDigest,
      toolNames: TOOLS,
    },
    r0Canary: {
      sessionIdentityDigest: r0Session,
      transcriptDigest: digest("staging-r0-transcript"),
      brokerRequestRecordId: r0.recordDigest,
    },
  });
  const audit = [auditRecord(1, undefined, {
    timestamp: new Date(now - 14).toISOString(),
    operationId: r0.payload.operationId,
    correlationId: r0.payload.correlationId,
    principalFingerprintPrefix: principal.slice(0, 12),
    actionDigest: digestJson(r0Action),
    targetId: r0Action.target,
    tool: r0.payload.tool,
    operation: r0.payload.operation,
    risk: "R0",
    dispatchState: "NOT_DISPATCHED",
    result: "pass",
  })];
  writeLedger(brokerLedgerPath, broker);
  writeLedger(hostLedgerPath, host);
  writeLedger(auditLogPath, audit);
  const precheckRequest = {
    schemaVersion: 1,
    operation: "STAGING_PRECHECK",
    management: { stateDir: managementState, keyRef: key.path },
    stores: {
      auditLogPath,
      brokerLedgerPath,
      hostLedgerPath,
      oauthDatabasePath: join(oauthStateDir, "devspace.sqlite"),
    },
    selection: {
      candidateReadbackRecordId: candidate.recordDigest,
      hostObservationRecordId: observation.recordDigest,
      expectedDiscoveryTranscriptDigest: observation.payload.discovery.transcriptDigest,
      expectedR0TranscriptDigest: observation.payload.r0Canary.transcriptDigest,
      expectedResourceDigest: r0.payload.resourceDigest,
    },
    artifacts: {},
  };
  return {
    root,
    now,
    principal,
    key,
    managementState,
    oauthStateDir,
    oauthDatabasePath: join(oauthStateDir, "devspace.sqlite"),
    hostLedgerPath,
    brokerLedgerPath,
    auditLogPath,
    host,
    broker,
    audit,
    packageFixture,
    binding,
    receipt,
    candidate,
    observation,
    environmentIdentityDigest,
    routeIdentityDigest,
    managementCorrelationId,
    candidateIdentity: packageFixture.candidateIdentity,
    precheckRequest,
    dispatch,
    readback,
    cleanup: () => rmSync(root, { recursive: true, force: true }),
  };
}

function createReadyPreFixture({ canaryOptions = {}, createPre = true } = {}) {
  const fixture = createStagingFixture();
  const driver = new ConnectorActivationReleaseDriver({ runtime, now: () => fixture.now });
  const precheck = driver.createStagingActivationPrecheck(fixture.precheckRequest);
  const precheckPath = join(fixture.root, "staging-precheck.json");
  writeOwnerOnlyArtifactAtomic(precheckPath, precheck);
  const authorityDatabasePath = join(fixture.root, "authority.sqlite");
  const bootstrap = new authority.OperationAuthorityRegistry({
    storePath: authorityDatabasePath,
    instanceId: "ready-pre-bootstrap",
  });
  bootstrap.close();
  chmodSync(authorityDatabasePath, 0o600);
  const journalPath = join(fixture.root, "staging-connector-journal.sqlite");
  const verified = evidence.verifyConnectorActivationStagingPrecheck(
    precheck,
    fixture.key,
    {
      principalKeyFingerprint: fixture.principal,
      managementNonce: precheck.payload.managementNonce,
      managementCorrelationId: precheck.payload.managementCorrelationId,
      candidateIdentity: fixture.candidateIdentity,
      stagingRouteIdentityDigest: fixture.routeIdentityDigest,
      stagingCandidateBinding: precheck.payload.stagingCandidateBinding,
    },
    fixture.now,
  );
  const approvalBinding = staging.connectorStagingActivationOwnerApprovalBinding(
    fixture.receipt,
    verified,
    fixture.principal,
  );
  const decision = appendLedger(fixture.broker, "DEVSPACE_BROKER", "OWNER_APPROVAL_DECISION", fixture.now, {
    stage: "STAGING_ACTIVATION",
    approvalId: "ready-pre-owner-approval",
    authorityText: "Activate this exact isolated staging candidate for the PRE Host canary.",
    managementCorrelationId: fixture.managementCorrelationId,
    conditionsDigest: digestJson({
      schemaVersion: 1,
      stage: "STAGING_ACTIVATION",
      stagingActivationPrecheckDigest: verified.signedPayloadDigest,
      ...approvalBinding,
    }),
    approvedAtMs: fixture.now,
    expiresAtMs: fixture.now + 60_000,
  });
  writeLedger(fixture.brokerLedgerPath, fixture.broker);
  driver.activateStagingConnector({
    ...fixture.precheckRequest,
    operation: "STAGING_ACTIVATE",
    stores: {
      ...fixture.precheckRequest.stores,
      authorityDatabasePath,
      journalPath,
      oauthStateDir: fixture.oauthStateDir,
    },
    selection: {
      ...fixture.precheckRequest.selection,
      ownerApprovalDecisionRecordId: decision.recordDigest,
    },
    artifacts: { stagingPrecheckPath: precheckPath },
  });
  fixture.now = Date.now() + 10;
  const canary = appendCanaryEvidence(fixture, {
    stage: "PRE_CUTOVER_HOST_CANARY",
    authorityDatabasePath,
    ...canaryOptions,
  });
  const preRequest = {
    schemaVersion: 1,
    operation: "PRE_CUTOVER",
    management: fixture.precheckRequest.management,
    stores: { ...fixture.precheckRequest.stores, authorityDatabasePath },
    selection: {
      stagingPrecheck: fixture.precheckRequest.selection,
      canary: canary.selector,
    },
    artifacts: { stagingPrecheckPath: precheckPath },
  };
  const pre = createPre ? driver.createPreCutoverHostCanary(preRequest) : undefined;
  const prePath = join(fixture.root, "pre-cutover-host-canary.json");
  if (pre) writeOwnerOnlyArtifactAtomic(prePath, pre);
  return {
    fixture,
    driver,
    authorityDatabasePath,
    precheck,
    precheckPath,
    pre,
    prePath,
    preRequest,
    canary,
    cleanup: fixture.cleanup,
  };
}

function createProductionFixture({
  productionCandidateAgeMs = 0,
  candidateIdentityDrift,
  autoPredecision = true,
} = {}) {
  const ready = createReadyPreFixture();
  const fixture = ready.fixture;
  const oauthStateDir = secureDirectory(join(fixture.root, "production-oauth"));
  const store = new oauth.SqliteOAuthStore(oauthStateDir);
  const clients = new oauth.SqliteOAuthClientsStore(store, ["chatgpt.com"]);
  const oldClient = clients.registerClient({
    redirect_uris: ["https://chatgpt.com/aip/g-production-old/oauth/callback"],
    client_name: "fixture production old active",
  });
  const oldInitial = store.ensureCandidateConnectorBinding({
    canonicalName: "myDevSpace",
    clientId: oldClient.client_id,
    installationEpoch: 1,
    schemaGeneration: fixture.candidateIdentity.schemaGeneration,
  });
  const oldBinding = store.markConnectorBindingVerified(oldInitial.bindingId, {
    authorityContractGeneration: fixture.candidateIdentity.authorityContractGeneration,
    redirectUrisDigest: digest("production-old-redirect"),
    buildDigest: fixture.candidateIdentity.buildDigest,
  });
  const oldPrepared = store.prepareConnectorActivation(activationTuple(oldBinding), {
    drainDeadlineAt: new Date(Date.now() + 300_000).toISOString(),
    refreshAllowedDuringDrain: true,
  });
  store.activatePreparedConnector(
    oldPrepared.receiptId,
    oldPrepared.tuple,
    activationProof(oldPrepared, "production-old", fixture.principal),
  );
  const candidateClient = clients.registerClient({
    redirect_uris: ["https://chatgpt.com/aip/g-production-new/oauth/callback"],
    client_name: "fixture production candidate",
  });
  const candidateInitial = store.ensureCandidateConnectorBinding({
    canonicalName: "myDevSpace",
    clientId: candidateClient.client_id,
    installationEpoch: 2,
    schemaGeneration: fixture.candidateIdentity.schemaGeneration,
  });
  const candidateBinding = store.markConnectorBindingVerified(candidateInitial.bindingId, {
    authorityContractGeneration: fixture.candidateIdentity.authorityContractGeneration,
    redirectUrisDigest: digest("production-new-redirect"),
    buildDigest: fixture.candidateIdentity.buildDigest,
  });
  const active = store.getActiveConnectorBinding("myDevSpace");
  const activePreimageDigest = connectorPreimageDigest(active);
  const tuple = activationTuple(candidateBinding);
  const tupleDigest = oauth.connectorActivationTupleDigest(tuple);
  store.close();
  chmodSync(join(oauthStateDir, "devspace.sqlite"), 0o600);
  fixture.now += 1;
  const oauthResource = "https://production.example.test/mcp";
  const environmentIdentityDigest = routeIdentity.connectorEnvironmentIdentityDigest({
    environmentRole: "PRODUCTION",
    runtimeIdentityDigest: fixture.candidateIdentity.runtimeIdentityDigest,
    oauthResource,
  });
  const routeIdentityDigest = routeIdentity.connectorRouteIdentityDigest({
    oauthResource,
    canonicalName: candidateBinding.canonicalName,
    bindingId: candidateBinding.bindingId,
  });
  const candidatePayload = {
    environmentRole: "PRODUCTION",
    environmentIdentityDigest: candidateIdentityDrift === "environment"
      ? digest("invented-production-environment")
      : environmentIdentityDigest,
    routeIdentityDigest: candidateIdentityDrift === "route"
      ? digest("invented-production-route")
      : routeIdentityDigest,
    oauthResource,
    migrationManifestDigest: fixture.packageFixture.migrationManifestDigest,
    packageRoot: fixture.packageFixture.packageRoot,
    candidateIdentity: fixture.candidateIdentity,
    canonicalName: candidateBinding.canonicalName,
    clientId: candidateBinding.clientId,
    bindingId: candidateBinding.bindingId,
    installationEpoch: candidateBinding.installationEpoch,
    redirectUrisDigest: candidateBinding.redirectUrisDigest,
    bindingState: "VERIFIED",
    receiptId: null,
    activePreimageDigest,
  };
  const candidate = (candidateIdentityDrift ? appendLedgerUnchecked : appendLedger)(
    fixture.broker,
    "DEVSPACE_BROKER",
    "CANDIDATE_READBACK",
    fixture.now - productionCandidateAgeMs,
    candidatePayload,
  );
  const productionJournalPath = join(fixture.root, "production-connector-journal.sqlite");
  const productionJournal = new journal.SqliteConnectorActivationRecoveryJournal({
    storePath: productionJournalPath,
  });
  const journalIdentity = productionJournal.identity();
  productionJournal.close();
  const transactionId = `upgrade_${randomUUID()}`;
  const finalizationStateDir = secureDirectory(join(fixture.root, "finalization-state"));
  const finalizationStorePath = join(finalizationStateDir, "lifecycle.sqlite");
  const finalizationControlDir = secureDirectory(join(fixture.root, "finalization-control"));
  const finalizationControlPath = join(finalizationControlDir, "lifecycle-finalization-head.json");
  const finalizationDraftIdentity = initializeFinalizationStore({
    storePath: finalizationStorePath,
    controlPath: finalizationControlPath,
    key: fixture.key,
    bootstrapAuthorization: createFinalizationStoreBootstrapAuthorization({
      storePath: finalizationStorePath,
      controlPath: finalizationControlPath,
      key: fixture.key,
      approvedAt: new Date(fixture.now - 100).toISOString(),
    }),
    requireDraft: true,
    now: () => new Date(fixture.now - 100).toISOString(),
  });
  const plan = {
    drainDeadlineAt: new Date(Date.now() + 600_000).toISOString(),
    refreshAllowedDuringDrain: false,
  };
  const predecisionRequestPath = join(fixture.root, "production-predecision-request.json");
  const predecisionPath = join(fixture.root, "production-predecision.json");
  const productionPreparationRequestPath = join(fixture.root, "production-preparation-request.json");
  const upgradeRequestPath = join(fixture.root, "production-upgrade-request.json");
  const productionApprovalOutputDirectory = join(fixture.root, "production-approval-output");
  fixture.now += 1;
  const decision = appendLedger(fixture.broker, "DEVSPACE_BROKER", "OWNER_APPROVAL_DECISION", fixture.now, {
    stage: "PRODUCTION_ACTIVATION",
    approvalId: "production-owner-approval-fixture",
    authorityText: "Prepare and approve exactly this production connector tuple and bounded drain plan.",
    managementCorrelationId: fixture.managementCorrelationId,
    conditionsDigest: digestJson({
      schemaVersion: 1,
      stage: "PRODUCTION_ACTIVATION",
      transactionId,
      preCutoverHostCanaryDigest: ready.pre.payloadDigest,
      productionCandidateRecordId: candidate.recordDigest,
      canonicalName: tuple.canonicalName,
      candidateBindingId: tuple.candidateBindingId,
      tuple,
      tupleDigest,
      activePreimageDigest,
      plan,
      oauthResource: candidate.payload.oauthResource,
      productionEnvironmentIdentityDigest: environmentIdentityDigest,
      productionRouteIdentityDigest: routeIdentityDigest,
      migrationManifestDigest: fixture.packageFixture.migrationManifestDigest,
      journalIdentity,
      finalizationDraftIdentity,
      productionApprovalOutputDirectory,
    }),
    approvedAtMs: fixture.now,
    expiresAtMs: fixture.now + 60_000,
  });
  writeLedger(fixture.brokerLedgerPath, fixture.broker);
  const predecisionRequest = {
    schemaVersion: 1,
    operation: "PRODUCTION_PREDECISION",
    management: fixture.precheckRequest.management,
    stores: {
      auditLogPath: fixture.auditLogPath,
      brokerLedgerPath: fixture.brokerLedgerPath,
      hostLedgerPath: fixture.hostLedgerPath,
      oauthDatabasePath: join(oauthStateDir, "devspace.sqlite"),
      oauthStateDir,
      journalPath: productionJournalPath,
      finalizationStorePath,
      finalizationControlPath,
    },
    selection: {
      stagingPrecheck: fixture.precheckRequest.selection,
      activeStagingCandidateReadbackRecordId: ready.canary.candidate.recordDigest,
      productionCandidateReadbackRecordId: candidate.recordDigest,
      ownerApprovalDecisionRecordId: decision.recordDigest,
      canonicalName: tuple.canonicalName,
      candidateBindingId: tuple.candidateBindingId,
      drainDeadlineAt: plan.drainDeadlineAt,
      refreshAllowedDuringDrain: plan.refreshAllowedDuringDrain,
      transactionId,
    },
    artifacts: {
      stagingPrecheckPath: ready.precheckPath,
      preCutoverPath: ready.prePath,
      predecisionPath,
      productionPreparationRequestPath,
      upgradeRequestPath,
      productionApprovalOutputDirectory,
    },
  };
  writeText(predecisionRequestPath, `${JSON.stringify(predecisionRequest)}\n`, 0o600);
  const driver = new ConnectorActivationReleaseDriver({ runtime, now: () => fixture.now });
  const base = {
    ...ready,
    driver,
    oauthStateDir,
    oauthDatabasePath: join(oauthStateDir, "devspace.sqlite"),
    candidateBindingId: candidateBinding.bindingId,
    candidate,
    tuple,
    tupleDigest,
    activePreimageDigest,
    plan,
    productionJournalPath,
    journalIdentity,
    decision,
    transactionId,
    finalizationStorePath,
    finalizationControlPath,
    finalizationDraftIdentity,
    predecisionRequest,
    predecisionRequestPath,
    predecisionPath,
    productionPreparationRequestPath,
    upgradeRequestPath,
    productionApprovalOutputDirectory,
    rawClientSecrets: [oldClient.client_secret, candidateClient.client_secret].filter(Boolean),
    request: predecisionRequest,
  };
  if (!autoPredecision) return base;

  const oauthBeforePredecision = readFileSync(base.oauthDatabasePath);
  const predecision = driver.createProductionActivationPredecision(predecisionRequest);
  assert.deepEqual(readFileSync(base.oauthDatabasePath), oauthBeforePredecision);
  writeOwnerOnlyArtifactAtomic(predecisionPath, predecision);

  const auditDirectory = secureDirectory(join(fixture.root, "upgrade-audit"));
  const snapshotRoot = secureDirectory(join(auditDirectory, "snapshot"));
  const snapshotManifestPath = join(snapshotRoot, "SNAPSHOT-GROUP.json");
  const oauthSnapshotPath = join(snapshotRoot, "oauth-main-and-connector-state.sqlite");
  const finalizationSnapshotPath = join(snapshotRoot, "lifecycle-finalization-store.sqlite");
  copyFileSync(base.oauthDatabasePath, oauthSnapshotPath);
  chmodSync(oauthSnapshotPath, 0o600);
  copyFileSync(finalizationStorePath, finalizationSnapshotPath);
  chmodSync(finalizationSnapshotPath, 0o600);
  const statusPath = join(auditDirectory, "status.json");
  const workerClaimPath = `${statusPath}.worker-claim.json`;
  const preparationRequest = {
    schemaVersion: 1,
    operation: "PRODUCTION_APPROVE",
    management: fixture.precheckRequest.management,
    stores: { finalizationStorePath, finalizationControlPath },
    selection: { transactionId },
    artifacts: {
      predecisionPath,
      productionApprovalOutputDirectory,
      productionPreparationRequestPath,
      snapshotManifestPath,
      statusPath,
      upgradeRequestPath,
      workerClaimPath,
    },
  };
  writeText(productionPreparationRequestPath, `${JSON.stringify(preparationRequest)}\n`, 0o600);
  const stagingPrecheckRequestPath = join(fixture.root, "driver-staging-precheck-request.json");
  const stagingActivationRequestPath = join(fixture.root, "driver-staging-activation-request.json");
  const stagingActivationReadbackPath = join(fixture.root, "driver-staging-activation-readback.json");
  const preCutoverRequestPath = join(fixture.root, "driver-pre-cutover-request.json");
  for (const path of [
    stagingPrecheckRequestPath,
    stagingActivationRequestPath,
    stagingActivationReadbackPath,
    preCutoverRequestPath,
  ]) writeText(path, "{}\n", 0o600);
  const artifactReference = (path) => ({ path, sha256: digest(readFileSync(path)) });
  const releaseDriver = {
    stagingPrecheckRequest: artifactReference(stagingPrecheckRequestPath),
    stagingActivationRequest: artifactReference(stagingActivationRequestPath),
    stagingActivationReadback: artifactReference(stagingActivationReadbackPath),
    preCutoverRequest: artifactReference(preCutoverRequestPath),
    productionPredecisionRequest: {
      path: predecisionRequestPath,
      sha256: digest(readFileSync(predecisionRequestPath)),
    },
    productionPredecisionEnvelope: {
      path: predecisionPath,
      sha256: digest(readFileSync(predecisionPath)),
    },
    productionPreparationRequest: {
      path: productionPreparationRequestPath,
      sha256: digest(readFileSync(productionPreparationRequestPath)),
    },
    productionApprovalOutputDirectory,
  };
  const upgradeRequest = createCanonicalProductionUpgradeRequest({
    fixture,
    base,
    transactionId,
    finalizationStorePath,
    finalizationControlPath,
    finalizationDraftIdentity,
    productionJournalPath,
    journalIdentity,
    releaseDriver,
    snapshotRoot,
    snapshotManifestPath,
    statusPath,
    workerClaimPath,
  });
  const snapshotEntries = upgradeRequest.snapshotGroup.entries;
  writeText(upgradeRequestPath, `${JSON.stringify(upgradeRequest)}\n`, 0o600);
  const requestBindingDigest = productionUpgradeWorker.productionUpgradeRequestBindingDigest(upgradeRequest);
  const claimAt = new Date(fixture.now + 1).toISOString();
  const stoppedAt = new Date(fixture.now + 2).toISOString();
  const capturedAt = new Date(fixture.now + 3).toISOString();
  const snappedAt = new Date(fixture.now + 4).toISOString();
  const workerClaim = {
    schemaVersion: 1,
    claimId: randomUUID(),
    claimPath: workerClaimPath,
    transactionId,
    requestBindingDigest,
    pid: process.pid,
    acquiredAt: claimAt,
  };
  const manifestUnsigned = {
    schemaVersion: 1,
    capturedAt,
    snapshotRoot,
    barrier: {
      kind: "PM2_STOPPED",
      processName: upgradeRequest.pm2ProcessName,
      previousPid: upgradeRequest.previous.pid,
      previousRuntimeIdentityDigest: upgradeRequest.previous.runtimeIdentityDigest,
      previousMigrationManifestDigest: upgradeRequest.previous.migrationManifestDigest,
      transactionId,
      requestBindingDigest,
      cutoverProcessNames: [...upgradeRequest.cutoverProcessNames].sort(),
      establishedAt: stoppedAt,
    },
    entries: [
      snapshotManifestEntry(
        snapshotEntries.find((entry) => entry.id === "oauth-main-and-connector-state"),
        oauthSnapshotPath,
      ),
      snapshotManifestEntry(
        snapshotEntries.find((entry) => entry.id === "lifecycle-finalization-store"),
        finalizationSnapshotPath,
      ),
    ],
  };
  const snapshotManifest = {
    ...manifestUnsigned,
    groupDigest: digestJson(manifestUnsigned),
  };
  writeText(snapshotManifestPath, `${JSON.stringify(snapshotManifest)}\n`, 0o600);
  prepareFinalizationStoreFixture(
    finalizationStorePath,
    finalizationControlPath,
    fixture.key,
    transactionId,
    snapshotManifest,
    requestBindingDigest,
    upgradeRequest.snapshotGroup.barrier.candidateIdentityDigest,
    new Date(fixture.now + 5).toISOString(),
  );
  const finalizationPreparedIdentity = readFinalizationStoreIdentity({
    storePath: finalizationStorePath,
    controlPath: finalizationControlPath,
    key: fixture.key,
  });
  fixture.now = Math.max(fixture.now + 6, Date.now() + 1_000);
  const status = {
    version: 2,
    transactionId,
    requestBindingDigest,
    state: "STATE_SNAPSHOTTED",
    requestedAt: upgradeRequest.requestedAt,
    updatedAt: snappedAt,
    expectedDisconnect: true,
    previous: upgradeRequest.previous,
    next: upgradeRequest.next,
    workerPid: process.pid,
    workerClaim,
    acceptedAt: claimAt,
    history: [
      { state: "PREPARED", at: upgradeRequest.requestedAt },
      { state: "ACCEPTED", at: claimAt },
      { state: "PREFLIGHT_VERIFIED", at: claimAt },
      { state: "CUTOVER_STOP_REQUESTED", at: claimAt },
      { state: "CUTOVER_PROCESSES_STOPPED", at: stoppedAt },
      { state: "STATE_SNAPSHOTTED", at: snappedAt },
    ],
    snapshotGroupPreimage: snapshotManifest,
  };
  writeText(workerClaimPath, `${JSON.stringify(workerClaim)}\n`, 0o600);
  writeText(statusPath, `${JSON.stringify(status)}\n`, 0o600);
  return {
    ...base,
    predecision,
    preparationRequest,
    request: preparationRequest,
    upgradeRequest,
    requestBindingDigest,
    statusPath,
    workerClaimPath,
    workerClaim,
    snapshotRoot,
    auditDirectory,
    snapshotManifestPath,
    snapshotManifest,
    oauthSnapshotPath,
    finalizationSnapshotPath,
    finalizationPreparedIdentity,
  };
}

function createCanonicalProductionUpgradeRequest({
  fixture,
  base,
  transactionId,
  finalizationStorePath,
  finalizationControlPath,
  finalizationDraftIdentity,
  productionJournalPath,
  journalIdentity,
  releaseDriver,
  snapshotRoot,
  snapshotManifestPath,
  statusPath,
  workerClaimPath,
}) {
  const root = fixture.root;
  const stateRoot = secureDirectory(join(root, "upgrade-mutable"));
  const auditDirectory = join(root, "upgrade-audit");
  const controlRoot = secureDirectory(join(root, "upgrade-control"));
  const immutableSourceRoot = secureDirectory(join(root, "immutable-source-evidence"));
  const immutableDependencyRoot = secureDirectory(join(root, "immutable-runtime-dependencies"));
  const candidateIdentity = fixture.candidateIdentity;
  fixture.now = Math.max(fixture.now, journalIdentity.createdAtMs + 1);
  const requestedAt = new Date(fixture.now).toISOString();
  const timeoutMs = 300_000;
  const captureDeadlineAt = new Date(fixture.now + timeoutMs).toISOString();
  const previousRuntimeIdentityDigest = digest("previous-production-runtime");
  const previousMigrationManifestDigest = digest("previous-production-migration");
  const processName = "devspace-universal-broker";
  const previousPid = 4242;
  const productionEnvPath = join(stateRoot, "production.env");
  const startScriptPath = join(stateRoot, "canonical-start.sh");
  const previousCursorPath = join(stateRoot, "pagination-previous.key");
  const snapshotPathById = {
    "oauth-main-and-connector-state": base.oauthDatabasePath,
    "authority-store": join(root, "authority.sqlite"),
    "contexts-store": join(stateRoot, "contexts.json"),
    "process-metadata": join(stateRoot, "process-metadata"),
    "process-output": join(stateRoot, "process-output"),
    "filesystem-sync": join(stateRoot, "filesystem-sync.sqlite"),
    "artifact-catalog": join(stateRoot, "artifact-catalog.sqlite"),
    "artifact-cas": join(stateRoot, "artifact-cas"),
    "artifact-quarantine": join(stateRoot, "artifact-quarantine"),
    "pagination-current-signing-key": join(stateRoot, "pagination-current.key"),
    "lifecycle-finalization-store": finalizationStorePath,
    "runtime-environment": productionEnvPath,
    "process-manager-definition": startScriptPath,
    "public-route": join(stateRoot, "public-route.json"),
    "target-route-generation-config": join(stateRoot, "targets.json"),
  };
  const entries = productionUpgradeContract.PRODUCTION_UPGRADE_REQUIRED_SNAPSHOT_ENTRIES.map(
    ({ id, kind }) => ({ id, kind, path: snapshotPathById[id], required: true }),
  );
  entries.push({
    ...productionUpgradeContract.PRODUCTION_UPGRADE_PREVIOUS_CURSOR_SNAPSHOT_ENTRY,
    path: previousCursorPath,
    required: false,
  });
  const rollbackChallengeRequestPath = join(controlRoot, "rollback-challenge-request.json");
  const rollbackChallengePath = join(controlRoot, "rollback-challenge.json");
  const rollbackReceiptPath = join(controlRoot, "rollback-receipt.json");
  const postChallengePath = join(controlRoot, "post-activation-challenge.json");
  const postReceiptPath = join(controlRoot, "post-activation-receipt.json");
  const trustAnchorPath = join(controlRoot, "gate-producer-trust-anchor.json");
  const producerSha = rawDigest("fixture-gate-producer-spki");
  const finalizationPreSnapshot = finalizationDraftIdentity.preSnapshotIdentity;
  const request = {
    version: 4,
    transactionId,
    requestedAt,
    delayMs: 0,
    timeoutMs,
    pm2ProcessName: processName,
    pm2Executable: "/usr/local/bin/pm2",
    gitExecutable: "/usr/bin/git",
    previous: {
      pid: previousPid,
      cwd: join(root, "previous-release"),
      script: join(root, "previous-release", "start.sh"),
      runtimeIdentityDigest: previousRuntimeIdentityDigest,
      migrationManifestDigest: previousMigrationManifestDigest,
      localHealthUrl: "http://127.0.0.1:43110/healthz",
      localReadyUrl: "http://127.0.0.1:43111/readyz",
      rollbackHostChallenge: {
        rollbackChallengeRequest: {
          path: rollbackChallengeRequestPath,
          sha256: digest("rollback-challenge-request"),
        },
        challengePath: rollbackChallengePath,
        challengeSha256: digest("rollback-challenge"),
        receiptPath: rollbackReceiptPath,
        deadlineAt: new Date(fixture.now + 240_000).toISOString(),
        pollIntervalMs: 250,
      },
    },
    next: {
      commit: "1".repeat(40),
      sourceTree: "2".repeat(40),
      sourceEvidenceRoot: immutableSourceRoot,
      immutableRuntimeRoot: fixture.packageFixture.packageRoot,
      immutableRuntimeEntrypoint: join(fixture.packageFixture.packageRoot, "start.sh"),
      runtimeDependencies: {
        root: immutableDependencyRoot,
        evidencePath: join(immutableDependencyRoot, "RUNTIME-DEPENDENCIES.json"),
        evidenceSha256: digest("runtime-dependencies"),
      },
      dist: { files: 1, sha256: "3".repeat(64) },
      manifest: {
        path: join(fixture.packageFixture.packageRoot, "BUILD-MANIFEST.json"),
        sha256: digest(readFileSync(join(fixture.packageFixture.packageRoot, "BUILD-MANIFEST.json"))),
        buildDigest: candidateIdentity.buildDigest,
        runtimeRevision: "fixture-runtime-revision",
        schemaGeneration: candidateIdentity.schemaGeneration,
        authorityContractGeneration: candidateIdentity.authorityContractGeneration,
        configSchemaIdentity: digest("fixture-config-schema"),
        migrationManifestDigest: fixture.packageFixture.migrationManifestDigest,
        buildCapabilityManifestDigest: candidateIdentity.buildCapabilityManifestDigest,
        generatedSchemaDigest: candidateIdentity.generatedSchemaDigest,
        packageSha256: candidateIdentity.packageSha256,
        runtimeIdentityDigest: candidateIdentity.runtimeIdentityDigest,
      },
    },
    oauthStateDirectory: base.oauthStateDir,
    productionEnvPath,
    productionEnvBackupPath: join(auditDirectory, "preimage-production.env"),
    oauthDatabasePath: base.oauthDatabasePath,
    oauthDatabaseBackupPath: join(auditDirectory, "preimage-oauth.sqlite"),
    authorityDatabasePath: join(root, "authority.sqlite"),
    authorityDatabaseBackupPath: join(auditDirectory, "preimage-authority.sqlite"),
    snapshotGroup: {
      snapshotRoot,
      manifestPath: snapshotManifestPath,
      paginationPreviousSigningKey: { state: "ABSENT", path: previousCursorPath },
      barrier: {
        kind: "PM2_STOPPED",
        transactionId,
        processName,
        previousPid,
        previousRuntimeIdentityDigest,
        previousMigrationManifestDigest,
        candidateIdentityDigest:
          productionUpgradeContract.productionUpgradeCandidateIdentityDigest(candidateIdentity),
        cutoverProcessNames: [processName],
        captureDeadlineAt,
      },
      entries,
    },
    cutoverProcessNames: [processName],
    connectorLifecycle: {
      bindingDigest: digest("placeholder-lifecycle-binding"),
      stagingActivationPrecheck: {
        path: base.precheckPath,
        sha256: digest(readFileSync(base.precheckPath)),
      },
      preCutoverHostCanary: {
        path: base.prePath,
        sha256: digest(readFileSync(base.prePath)),
      },
      releaseDriver,
      journal: { path: productionJournalPath, identity: journalIdentity },
      postActivation: {
        challengePath: postChallengePath,
        challengeSha256: digest("post-activation-challenge"),
        receiptPath: postReceiptPath,
        deadlineAt: new Date(fixture.now + 240_000).toISOString(),
        pollIntervalMs: 250,
        runtimeIdentityUrl: "http://127.0.0.1:43111/readyz",
        routeIdentityUrl: "http://127.0.0.1:43111/route-identityz",
      },
      managementAuthorizationKeyRef: fixture.key.path,
      managementNonce: base.pre.payload.managementNonce,
      managementCorrelationId: base.pre.payload.managementCorrelationId,
      candidateIdentity,
      oauthResource: base.candidate.payload.oauthResource,
      productionEnvironmentIdentityDigest: base.candidate.payload.environmentIdentityDigest,
      productionRouteIdentityDigest: base.candidate.payload.routeIdentityDigest,
      finalization: {
        storePath: finalizationStorePath,
        controlPath: finalizationControlPath,
        keyId: fixture.key.keyId,
        gateProducer: {
          keyId: `gate-producer-ed25519-sha256:${producerSha}`,
          publicKeySha256: `sha256:${producerSha}`,
        },
        gateProducerTrustAnchor: {
          path: trustAnchorPath,
          sha256: digest("gate-producer-trust-anchor"),
        },
        preSnapshotIdentity: {
          storeId: "lifecycle-finalization-store",
          schemaVersion: 2,
          state: "DRAFT",
          revision: 1,
          transactionId: null,
          contentGeneration: finalizationPreSnapshot.contentGeneration,
          controlEpoch: finalizationPreSnapshot.controlEpoch,
          controlTag: finalizationPreSnapshot.controlTag,
          identityDigest: finalizationDraftIdentity.preSnapshotIdentityDigest,
        },
      },
    },
    rollbackJournalPath: join(controlRoot, "rollback.jsonl"),
    nextEnvPath: join(auditDirectory, "production.env.next"),
    startScriptPath,
    startScriptBackupPath: join(auditDirectory, "preimage-start.sh"),
    auditDirectory,
    currentAuditLink: join(root, "current-audit"),
    statusPath,
    workerClaimPath,
    workerLogPath: join(auditDirectory, "worker.log"),
    localHealthUrl: "http://127.0.0.1:43110/healthz",
    localDoctorUrl: "http://127.0.0.1:43111/doctorz",
    publicHealthUrl: "https://production.example.test/healthz",
    publicMetricsUrl: "https://production.example.test/metrics",
    publicMcpUrl: base.candidate.payload.oauthResource,
    oauthMetadataUrl: "https://production.example.test/.well-known/oauth-protected-resource/mcp",
    expectedScopes: [
      "devspace.read", "devspace.write", "devspace.exec", "devspace.mcp",
      "devspace.artifact", "devspace.gui", "offline_access",
    ],
  };
  request.connectorLifecycle.bindingDigest =
    productionUpgradeContract.productionUpgradeLifecycleBindingDigest(request);
  return productionUpgradeContract.validateProductionUpgradeRequestV4(request);
}

function createPostFixture({ oauthResource } = {}) {
  const production = createProductionFixture();
  const bundle = production.driver.createProductionActivationApproval(production.request);
  const published = writeProductionApprovalDirectoryAtomic(
    join(production.fixture.root, "production-approval-for-post"),
    bundle,
  );
  const activationReceipt = activatePreparedProductionFixture(production, bundle);
  const postOauthResource = oauthResource ?? production.candidate.payload.oauthResource;
  const postFixture = {
    ...production.fixture,
    now: Math.max(production.fixture.now + 100, Date.now() + 100),
    oauthStateDir: production.oauthStateDir,
    oauthDatabasePath: production.oauthDatabasePath,
    binding: { bindingId: production.candidateBindingId },
    receipt: activationReceipt,
    environmentIdentityDigest: routeIdentity.connectorEnvironmentIdentityDigest({
      environmentRole: "PRODUCTION",
      runtimeIdentityDigest: production.fixture.candidateIdentity.runtimeIdentityDigest,
      oauthResource: postOauthResource,
    }),
    routeIdentityDigest: routeIdentity.connectorRouteIdentityDigest({
      oauthResource: postOauthResource,
      canonicalName: production.candidate.payload.canonicalName,
      bindingId: production.candidateBindingId,
    }),
    oauthResource: postOauthResource,
  };
  const canary = appendCanaryEvidence(postFixture, {
    stage: "POST_ACTIVATION_HOST_CANARY",
    authorityDatabasePath: production.authorityDatabasePath,
  });
  production.fixture.now = postFixture.now;
  const request = {
    schemaVersion: 1,
    operation: "POST_ACTIVATION",
    management: production.fixture.precheckRequest.management,
    stores: {
      auditLogPath: production.fixture.auditLogPath,
      brokerLedgerPath: production.fixture.brokerLedgerPath,
      hostLedgerPath: production.fixture.hostLedgerPath,
      oauthDatabasePath: production.oauthDatabasePath,
      authorityDatabasePath: production.authorityDatabasePath,
    },
    selection: {
      activeStagingCandidateReadbackRecordId: production.canary.candidate.recordDigest,
      stagingPrecheck: production.fixture.precheckRequest.selection,
      canary: canary.selector,
    },
    artifacts: {
      stagingPrecheckPath: production.precheckPath,
      preCutoverPath: production.prePath,
      productionPrecheckPath: published.productionActivationPrecheckPath,
      ownerApprovalPath: published.ownerManagementApprovalPath,
    },
  };
  return {
    ...production,
    driver: new ConnectorActivationReleaseDriver({ runtime, now: () => production.fixture.now }),
    activationReceipt,
    bundle,
    canary,
    published,
    request,
  };
}

function activatePreparedProductionFixture(fixture, bundle) {
  const store = new oauth.SqliteOAuthStore(fixture.oauthStateDir);
  const receipt = store.getActivationReceipt(bundle.manifest.receiptId);
  assert.equal(receipt?.status, "PREPARED");
  const binding = {
    receiptId: receipt.receiptId,
    tupleDigest: receipt.tupleDigest,
    activePreimageDigest: receipt.preimageDigest,
    finalizationPlanDigest: bundle.manifest.finalizationPlanDigest,
    canonicalName: receipt.tuple.canonicalName,
  };
  const descriptor = oauth.connectorActivationAuthorityDescriptor(binding);
  const registry = new authority.OperationAuthorityRegistry({
    storePath: fixture.authorityDatabasePath,
    instanceId: "production-post-activation-authority",
  });
  const created = registry.createConnectorActivationAuthority({
    authorityText: "Finalize exactly the signed production connector receipt for the POST fixture.",
    descriptor,
  }, fixture.fixture.principal);
  const controller = registry.prepareDispatch(
    created.authorityId,
    fixture.fixture.principal,
    descriptor,
    "R3",
  );
  controller.claim();
  const grant = controller.markDispatched();
  const proof = {
    schemaVersion: 1,
    authorityId: grant.authorityId,
    actionClaimId: grant.actionClaimId,
    actionFingerprint: grant.fingerprint,
    resourceKeySha256: grant.resourceKeySha256,
    fencingToken: grant.fencingToken,
    principalKeyFingerprint: fixture.fixture.principal,
    risk: "R3",
    claimState: "DISPATCHED",
    approvalAssurance: "cooperative",
    ...binding,
    evidenceDigest: digestJson({
      productionActivationPrecheckDigest: bundle.productionActivationPrecheck.payloadDigest,
      ownerManagementApprovalDigest: bundle.ownerManagementApproval.payloadDigest,
    }),
    claimedAtMs: grant.claimedAtMs,
    dispatchedAtMs: grant.dispatchedAtMs,
  };
  const activated = store.activatePreparedConnector(receipt.receiptId, receipt.tuple, proof);
  controller.complete("PASS", {
    reasonCode: "CONNECTOR_ACTIVATION_COMMITTED",
    receiptId: activated.receiptId,
    oauthProofDigest: activated.activationAuthority.proofDigest,
    evidenceDigest: proof.evidenceDigest,
  });
  const exact = store.getActivationReceipt(receipt.receiptId);
  store.close();
  registry.close();
  return exact;
}

function appendCanaryEvidence(fixture, {
  stage,
  authorityDatabasePath,
  authorizationClientId,
  discoveryClientId,
  authorityAction,
  authorityPrincipal = fixture.principal,
  extraProviderDispatch = false,
  foreignDispatch = false,
  omitCleanup = false,
  omitProviderDispatch = false,
  omitReadback = false,
  sameSessions = false,
  wrongTokenBinding = false,
}) {
  const base = fixture.now;
  const oauthResource = fixture.oauthResource ?? "https://staging.example.test/mcp";
  const store = new oauth.SqliteOAuthStore(fixture.oauthStateDir);
  const active = store.getConnectorBinding(fixture.binding.bindingId);
  assert.equal(active?.state, "ACTIVE");
  const activationReceipt = store.getActivationReceipt(fixture.receipt.receiptId);
  assert.equal(activationReceipt?.status, "ACTIVATED");
  const familyId = `family-${stage.toLowerCase()}`;
  let tokenBinding = active;
  if (wrongTokenBinding) {
    tokenBinding = store.ensureCandidateConnectorBinding({
      canonicalName: active.canonicalName,
      clientId: active.clientId,
      installationEpoch: active.installationEpoch + 100,
      schemaGeneration: active.schemaGeneration,
    });
  }
  const token = {
    clientId: active.clientId,
    scopes: SCOPES,
    expiresAt: Math.floor(Date.now() / 1_000) + 3_600,
    familyId,
    connectorBindingId: tokenBinding.bindingId,
    connectorDrainEpoch: tokenBinding.drainEpoch,
    installationEpoch: tokenBinding.installationEpoch,
    rotationSequence: 0,
  };
  assert.equal(store.saveTokenPair({
    accessTokenHash: `access-${familyId}`,
    accessToken: token,
    refreshTokenHash: `refresh-${familyId}`,
    refreshToken: token,
  }), true);
  store.close();

  const candidate = appendLedger(fixture.broker, "DEVSPACE_BROKER", "CANDIDATE_READBACK", base, {
    environmentRole: stage === "PRE_CUTOVER_HOST_CANARY" ? "STAGING" : "PRODUCTION",
    environmentIdentityDigest: fixture.environmentIdentityDigest,
    routeIdentityDigest: fixture.routeIdentityDigest,
    oauthResource,
    migrationManifestDigest: fixture.packageFixture.migrationManifestDigest,
    packageRoot: fixture.packageFixture.packageRoot,
    candidateIdentity: fixture.candidateIdentity,
    canonicalName: active.canonicalName,
    clientId: active.clientId,
    bindingId: active.bindingId,
    installationEpoch: active.installationEpoch,
    redirectUrisDigest: active.redirectUrisDigest,
    bindingState: "ACTIVE",
    receiptId: activationReceipt.receiptId,
    activePreimageDigest: null,
  });
  const sessionA = digest(`${stage}-session-a`);
  const sessionB = sameSessions ? sessionA : digest(`${stage}-session-b`);
  const foreignSession = digest(`${stage}-foreign-session`);
  const discovery = appendLedger(fixture.broker, "DEVSPACE_BROKER", "TOOL_DISCOVERY", base + 1, {
    requestId: `${stage}-discovery-request`,
    correlationId: `${stage}-discovery-correlation`,
    managementCorrelationId: fixture.managementCorrelationId,
    sessionIdentityDigest: sessionA,
    clientId: discoveryClientId ?? active.clientId,
    principalKeyFingerprint: fixture.principal,
    environmentIdentityDigest: fixture.environmentIdentityDigest,
    routeIdentityDigest: fixture.routeIdentityDigest,
    responseDigest: digest(`${stage}-discovery-response`),
    toolNames: TOOLS,
  });
  const authorizationRecord = appendLedger(fixture.broker, "DEVSPACE_BROKER", "OAUTH_AUTHORIZATION", base + 2, {
    requestId: `${stage}-authorization-request`,
    correlationId: `${stage}-authorization-correlation`,
    managementCorrelationId: fixture.managementCorrelationId,
    sessionIdentityDigest: sessionA,
    clientId: authorizationClientId ?? active.clientId,
    principalKeyFingerprint: fixture.principal,
    environmentIdentityDigest: fixture.environmentIdentityDigest,
    routeIdentityDigest: fixture.routeIdentityDigest,
    oauthResource,
    tokenFamilyIdDigest: digest(familyId),
    authorizationEvidenceDigest: digest(`${stage}-authorization-evidence`),
  });
  const close = appendLedger(fixture.broker, "DEVSPACE_BROKER", "SESSION_CLOSE", base + 3, {
    requestId: `${stage}-close-request`,
    correlationId: `${stage}-close-correlation`,
    managementCorrelationId: fixture.managementCorrelationId,
    sessionIdentityDigest: sessionA,
    closeEvidenceDigest: digest(`${stage}-close-evidence`),
  });
  const mutationAction = {
    tool: "fs",
    operation: "write",
    target: "fixture-target",
    resource: "/fixture/harmless-canary",
    parameters: { targetGeneration: digest(`${stage}-target-generation`) },
  };
  const registry = new authority.OperationAuthorityRegistry({
    storePath: authorityDatabasePath,
    instanceId: `${stage.toLowerCase()}-mutation-authority`,
  });
  const durableMutationAction = authorityAction ?? mutationAction;
  const created = registry.create({
    taskLabel: `${stage.toLowerCase()}-mutation-task`,
    authorityText: "Perform exactly one harmless canary mutation and then clean it up.",
    actions: [{
      id: `${stage.toLowerCase()}-mutation`,
      descriptor: durableMutationAction,
      risk: "R2",
      uses: 1,
    }],
    expiresInSeconds: 300,
  }, authorityPrincipal);
  const controller = registry.prepareDispatch(created.authorityId, authorityPrincipal, durableMutationAction, "R2");
  controller.claim();
  const grant = controller.markDispatched();
  const completion = controller.complete("PASS", { reasonCode: "CANARY_MUTATION_COMMITTED" });
  const mutation = appendLedger(fixture.broker, "DEVSPACE_BROKER", "TOOL_REQUEST", base + 4, {
    requestId: `${stage}-mutation-request`,
    correlationId: `${stage}-mutation-correlation`,
    managementCorrelationId: fixture.managementCorrelationId,
    sessionIdentityDigest: sessionB,
    clientId: active.clientId,
    principalKeyFingerprint: fixture.principal,
    environmentIdentityDigest: fixture.environmentIdentityDigest,
    routeIdentityDigest: fixture.routeIdentityDigest,
    operationId: `${stage}-mutation-operation`,
    tool: mutationAction.tool,
    operation: mutationAction.operation,
    argumentsDigest: digest(`${stage}-mutation-arguments`),
    resourceDigest: digest(`${stage}-mutation-resource`),
    responseDigest: digest(`${stage}-mutation-response`),
    outcome: "PASS",
    action: mutationAction,
  });
  const appendProviderDispatch = () => appendLedger(
    fixture.broker,
    "DEVSPACE_BROKER",
    "PROVIDER_DISPATCH",
    base + 5,
    {
      requestRecordId: mutation.recordDigest,
      correlationId: mutation.payload.correlationId,
      operationId: mutation.payload.operationId,
      tool: mutation.payload.tool,
      operation: mutation.payload.operation,
      resourceDigest: mutation.payload.resourceDigest,
      resultDigest: mutation.payload.responseDigest,
    },
  );
  const dispatch = omitProviderDispatch ? undefined : appendProviderDispatch();
  const duplicateDispatch = extraProviderDispatch ? appendProviderDispatch() : undefined;
  const readback = omitReadback ? undefined : appendLedger(
    fixture.broker,
    "DEVSPACE_BROKER",
    "RESOURCE_READBACK",
    base + 6,
    {
      requestRecordId: mutation.recordDigest,
      correlationId: mutation.payload.correlationId,
      resourceDigest: mutation.payload.resourceDigest,
      readbackDigest: digest(`${stage}-mutation-readback`),
    },
  );
  const cleanup = omitCleanup ? undefined : appendLedger(
    fixture.broker,
    "DEVSPACE_BROKER",
    "CLEANUP_DISPATCH",
    base + 7,
    {
      requestRecordId: mutation.recordDigest,
      correlationId: mutation.payload.correlationId,
      resourceDigest: mutation.payload.resourceDigest,
      cleanupOperation: "remove",
      cleanupArgumentsDigest: digest(`${stage}-cleanup-arguments`),
      resultDigest: digest(`${stage}-cleanup-result`),
    },
  );
  const absence = cleanup ? appendLedger(
    fixture.broker,
    "DEVSPACE_BROKER",
    "RESOURCE_ABSENCE_READBACK",
    base + 8,
    {
      cleanupRecordId: cleanup.recordDigest,
      resourceDigest: mutation.payload.resourceDigest,
      absenceEvidenceDigest: digest(`${stage}-absence-evidence`),
    },
  ) : undefined;
  const foreignPrincipal = rawDigest(`${stage}-foreign-principal`);
  const foreign = appendLedger(fixture.broker, "DEVSPACE_BROKER", "TOOL_REQUEST", base + 9, {
    requestId: `${stage}-foreign-request`,
    correlationId: `${stage}-foreign-correlation`,
    managementCorrelationId: fixture.managementCorrelationId,
    sessionIdentityDigest: foreignSession,
    clientId: `${active.clientId}-foreign`,
    principalKeyFingerprint: foreignPrincipal,
    environmentIdentityDigest: fixture.environmentIdentityDigest,
    routeIdentityDigest: fixture.routeIdentityDigest,
    operationId: `${stage}-foreign-operation`,
    tool: mutationAction.tool,
    operation: mutationAction.operation,
    argumentsDigest: mutation.payload.argumentsDigest,
    resourceDigest: mutation.payload.resourceDigest,
    responseDigest: digest(`${stage}-foreign-response`),
    outcome: "AUTHORITY_PRINCIPAL_MISMATCH",
    action: mutationAction,
  });
  const foreignProviderDispatch = foreignDispatch ? appendLedger(
    fixture.broker,
    "DEVSPACE_BROKER",
    "PROVIDER_DISPATCH",
    base + 10,
    {
      requestRecordId: foreign.recordDigest,
      correlationId: foreign.payload.correlationId,
      operationId: foreign.payload.operationId,
      tool: foreign.payload.tool,
      operation: foreign.payload.operation,
      resourceDigest: foreign.payload.resourceDigest,
      resultDigest: foreign.payload.responseDigest,
    },
  ) : undefined;
  const mutationAudit = auditRecord(
    fixture.audit.length + 1,
    fixture.audit.at(-1)?.eventDigest,
    {
      timestamp: new Date(base + 4).toISOString(),
      operationId: mutation.payload.operationId,
      correlationId: mutation.payload.correlationId,
      principalFingerprintPrefix: fixture.principal.slice(0, 12),
      authorityIdDigest: digest(created.authorityId),
      actionDigest: digestJson(mutationAction),
      targetId: mutationAction.target,
      tool: mutationAction.tool,
      operation: mutationAction.operation,
      risk: "R2",
      claimState: "PASS",
      dispatchState: "ACKNOWLEDGED",
      result: "pass",
      receiptDigest: completion.receiptDigest,
    },
  );
  fixture.audit.push(mutationAudit);
  registry.recordReceiptAuditResult({
    authorityId: created.authorityId,
    actionClaimId: grant.actionClaimId,
    receiptDigest: completion.receiptDigest,
    status: "RECORDED",
    auditEventDigest: mutationAudit.eventDigest,
  });
  const foreignAudit = auditRecord(
    fixture.audit.length + 1,
    mutationAudit.eventDigest,
    {
      timestamp: new Date(base + 9).toISOString(),
      operationId: foreign.payload.operationId,
      correlationId: foreign.payload.correlationId,
      principalFingerprintPrefix: foreignPrincipal.slice(0, 12),
      authorityIdDigest: digest(created.authorityId),
      actionDigest: digestJson(mutationAction),
      targetId: mutationAction.target,
      tool: mutationAction.tool,
      operation: mutationAction.operation,
      risk: "R2",
      dispatchState: "NOT_DISPATCHED",
      result: "fail",
      errorCode: "AUTHORITY_PRINCIPAL_MISMATCH",
    },
  );
  fixture.audit.push(foreignAudit);
  registry.close();
  const hostObservation = appendLedger(
    fixture.host,
    "CHATGPT_HOST",
    "CHATGPT_A_TO_B_CANARY",
    base + (foreignDispatch ? 11 : 10),
    {
    stage,
    hostCanaryId: `${stage}-fixture-host-canary`,
    managementNonce: "staging-management-nonce",
    managementCorrelationId: fixture.managementCorrelationId,
    environmentIdentityDigest: fixture.environmentIdentityDigest,
    routeIdentityDigest: fixture.routeIdentityDigest,
    discovery: {
      sessionIdentityDigest: sessionA,
      transcriptDigest: digest(`${stage}-discovery-transcript`),
      brokerRequestRecordId: discovery.recordDigest,
      toolNames: TOOLS,
    },
    sessionA: {
      sessionIdentityDigest: sessionA,
      authorizationTranscriptDigest: digest(`${stage}-authorization-transcript`),
      authorizationRequestRecordId: authorizationRecord.recordDigest,
      authorizedAtMs: authorizationRecord.occurredAtMs,
      closeTranscriptDigest: digest(`${stage}-close-transcript`),
      closeRequestRecordId: close.recordDigest,
      closedAtMs: close.occurredAtMs,
    },
    sessionB: {
      sessionIdentityDigest: sessionB,
      mutationTranscriptDigest: digest(`${stage}-mutation-transcript`),
      mutationRequestRecordId: mutation.recordDigest,
      mutationAtMs: mutation.occurredAtMs,
    },
    foreignClient: {
      sessionIdentityDigest: foreignSession,
      rejectionTranscriptDigest: digest(`${stage}-foreign-transcript`),
      rejectionRequestRecordId: foreign.recordDigest,
      observedAtMs: foreign.occurredAtMs,
    },
    },
  );
  writeLedger(fixture.brokerLedgerPath, fixture.broker);
  writeLedger(fixture.hostLedgerPath, fixture.host);
  writeLedger(fixture.auditLogPath, fixture.audit);
  fixture.now = hostObservation.occurredAtMs + 1;
  return {
    absence,
    activationReceipt,
    authorizationRecord,
    candidate,
    cleanup,
    dispatch,
    duplicateDispatch,
    familyId,
    foreign,
    foreignProviderDispatch,
    hostObservation,
    mutation,
    readback,
    tokenBinding,
    selector: {
      candidateReadbackRecordId: candidate.recordDigest,
      hostObservationRecordId: hostObservation.recordDigest,
      expectedDiscoveryTranscriptDigest: hostObservation.payload.discovery.transcriptDigest,
      expectedAuthorizationTranscriptDigest: hostObservation.payload.sessionA.authorizationTranscriptDigest,
      expectedCloseTranscriptDigest: hostObservation.payload.sessionA.closeTranscriptDigest,
      expectedMutationTranscriptDigest: hostObservation.payload.sessionB.mutationTranscriptDigest,
      expectedForeignTranscriptDigest: hostObservation.payload.foreignClient.rejectionTranscriptDigest,
      expectedResourceDigest: mutation.payload.resourceDigest,
    },
  };
}

function createPackageFixture(root) {
  const packageRoot = secureDirectory(join(root, "immutable-package"));
  secureDirectory(join(packageRoot, "config"));
  secureDirectory(join(packageRoot, "contracts"));
  secureDirectory(join(packageRoot, "dist"));
  for (const [index, path] of GENERATED_SCHEMA_FILES.entries()) {
    writeText(join(packageRoot, path), `${JSON.stringify({ schema: path, index })}\n`, 0o644);
  }
  writeText(join(packageRoot, "dist/cli.js"), "export const fixture = true;\n", 0o644);
  const payloadFiles = [...GENERATED_SCHEMA_FILES, "dist/cli.js"].sort();
  const runtimeFiles = ["dist/cli.js"];
  const buildDigest = treeDigest(packageRoot, runtimeFiles);
  const payloadDigest = treeDigest(packageRoot, payloadFiles);
  const schemaGeneration = digest("fixture-schema-generation");
  const authorityContractGeneration = digest("fixture-authority-generation");
  const capabilityDigest = digest("fixture-build-capability");
  const migrationManifestDigest = digest("fixture-migration-manifest");
  const manifest = {
    manifestVersion: 2,
    buildDigest,
    payloadDigest,
    schemaGeneration,
    authorityContractGeneration,
    migrationManifestDigest,
    buildCapabilities: { capabilityDigest },
    payloadFiles,
    runtimeFiles,
  };
  writeText(join(packageRoot, "BUILD-MANIFEST.json"), `${JSON.stringify(manifest)}\n`, 0o644);
  return {
    packageRoot,
    migrationManifestDigest,
    candidateIdentity: {
      runtimeIdentityDigest: digest("fixture-runtime-identity"),
      buildDigest,
      schemaGeneration,
      authorityContractGeneration,
      buildCapabilityManifestDigest: capabilityDigest,
      generatedSchemaDigest: treeDigest(packageRoot, GENERATED_SCHEMA_FILES),
      packageSha256: payloadDigest,
    },
  };
}

function activationTuple(binding) {
  return {
    canonicalName: binding.canonicalName,
    candidateBindingId: binding.bindingId,
    clientId: binding.clientId,
    installationEpoch: binding.installationEpoch,
    schemaGeneration: binding.schemaGeneration,
    authorityContractGeneration: binding.authorityContractGeneration,
    redirectUrisDigest: binding.redirectUrisDigest,
    buildDigest: binding.buildDigest,
  };
}

function connectorPreimageDigest(binding) {
  return digest(JSON.stringify(binding ? {
    bindingId: binding.bindingId,
    canonicalName: binding.canonicalName,
    clientId: binding.clientId,
    installationEpoch: binding.installationEpoch,
    schemaGeneration: binding.schemaGeneration,
    authorityContractGeneration: binding.authorityContractGeneration ?? null,
    redirectUrisDigest: binding.redirectUrisDigest ?? null,
    buildDigest: binding.buildDigest ?? null,
    drainEpoch: binding.drainEpoch,
    drainDeadlineAt: binding.drainDeadlineAt ?? null,
    refreshAllowedDuringDrain: binding.refreshAllowedDuringDrain,
    state: binding.state,
    stateReason: binding.stateReason ?? null,
    refCount: binding.refCount,
    createdAt: binding.createdAt,
    updatedAt: binding.updatedAt,
  } : null));
}

function activationProof(receipt, label, principalKeyFingerprint) {
  const binding = {
    receiptId: receipt.receiptId,
    tupleDigest: receipt.tupleDigest,
    activePreimageDigest: receipt.preimageDigest,
    finalizationPlanDigest: finalizer.connectorActivationFinalizationPlanDigest(receipt),
    canonicalName: receipt.tuple.canonicalName,
  };
  const claimedAtMs = Date.now() - 2;
  return {
    schemaVersion: 1,
    authorityId: `authority_${randomUUID()}`,
    actionClaimId: `authority_claim_${randomUUID()}`,
    actionFingerprint: oauth.connectorActivationAuthorityActionFingerprint(binding),
    resourceKeySha256: oauth.connectorActivationAuthorityResourceKeySha256(binding),
    fencingToken: 1,
    principalKeyFingerprint,
    risk: "R3",
    claimState: "DISPATCHED",
    approvalAssurance: "cooperative",
    ...binding,
    evidenceDigest: digest(`${label}-activation-authority-evidence`),
    claimedAtMs,
    dispatchedAtMs: claimedAtMs + 1,
  };
}

function assertProductionCandidateNotPrepared(fixture, expectedState = "VERIFIED") {
  const sqlite = new Database(fixture.oauthDatabasePath, { readonly: true, fileMustExist: true });
  const binding = sqlite.prepare(
    "select state from oauth_connector_bindings where binding_id = ?",
  ).get(fixture.candidateBindingId);
  const receiptCount = sqlite.prepare(
    "select count(*) as count from oauth_connector_activation_receipts where candidate_binding_id = ?",
  ).get(fixture.candidateBindingId).count;
  sqlite.close();
  assert.equal(binding.state, expectedState);
  assert.equal(receiptCount, 0);
}

function productionReceiptCount(fixture) {
  const sqlite = new Database(fixture.oauthDatabasePath, { readonly: true, fileMustExist: true });
  try {
    return sqlite.prepare(
      "select count(*) as count from oauth_connector_activation_receipts where candidate_binding_id = ?",
    ).get(fixture.candidateBindingId).count;
  } finally {
    sqlite.close();
  }
}

function snapshotManifestEntry(request, snapshotPath) {
  const metadata = statSync(snapshotPath);
  return {
    id: request.id,
    kind: request.kind,
    path: request.path,
    required: request.required,
    state: "captured",
    snapshotPath,
    sha256: digest(readFileSync(snapshotPath)),
    bytes: metadata.size,
    mode: metadata.mode & 0o777,
  };
}

function prepareFinalizationStoreFixture(
  storePath,
  controlPath,
  key,
  transactionId,
  snapshotManifest,
  requestBindingDigest,
  candidateIdentityDigest,
  preparedAt,
) {
  const draft = readFinalizationStoreIdentity({ storePath, controlPath, key });
  const input = {
    requestBindingDigest,
    candidateIdentityDigest,
    purpose: "connector-release-driver-fixture",
  };
  const record = {
    schemaVersion: 2,
    state: "PREPARED",
    transactionId,
    preparedAt,
    input,
    inputDigest: digestJson(input),
    sourceRevision: "connector-release-driver-fixture",
    runtimeIdentity: { digest: digestJson({ runtime: transactionId }) },
    immutableIdentity: { digest: digestJson({ immutable: transactionId }) },
    releasePackage: process.cwd(),
    releaseManifestSha256: digestJson({ manifest: transactionId }),
    releaseChecksumsSha256: digestJson({ checksums: transactionId }),
    moduleClosureDigest: digestJson({ closure: transactionId }),
    snapshotGroup: {
      manifest: {
        capturedAt: snapshotManifest.capturedAt,
        groupDigest: snapshotManifest.groupDigest,
        barrier: { transactionId, requestBindingDigest, candidateIdentityDigest },
      },
    },
    gateEvidence: {
      manifestPath: "/non-release-fixture/gates.json",
      manifestSha256: digestJson({ gates: transactionId }),
    },
    productionSources: {
      activation: {
        approvalId: `approval-${transactionId}`,
        receiptId: `receipt-${transactionId}`,
        previousBindingId: null,
      },
    },
    destructivePlan: [],
    finalizationStore: draft,
  };
  const prepared = commitPreparedFinalization({
    storePath,
    controlPath,
    key,
    record,
    now: () => preparedAt,
  }).identity;
  assert.equal(prepared.state, "PREPARED");
  assert.equal(prepared.transactionId, transactionId);
  return prepared;
}

function auditRecord(sequence, previousEventDigest, payload) {
  const unsigned = {
    schemaVersion: 1,
    sequence,
    ...(previousEventDigest ? { previousEventDigest } : {}),
    ...payload,
  };
  return { ...unsigned, eventDigest: digestJson(unsigned) };
}

function appendLedger(records, source, kind, occurredAtMs, payload) {
  const record = createEvidenceLedgerRecord({
    sequence: records.length + 1,
    previousRecordDigest: records.at(-1)?.recordDigest,
    source,
    kind,
    occurredAtMs,
    payload,
  }, runtime);
  records.push(record);
  return record;
}

function appendLedgerUnchecked(records, source, kind, occurredAtMs, payload) {
  const unsigned = {
    schemaVersion: 1,
    sequence: records.length + 1,
    ...(records.at(-1)?.recordDigest
      ? { previousRecordDigest: records.at(-1).recordDigest }
      : {}),
    source,
    kind,
    occurredAtMs,
    payload,
  };
  const record = { ...unsigned, recordDigest: digestJson(unsigned) };
  records.push(record);
  return record;
}

function rewriteLedgerRecord(records, index) {
  for (let position = index; position < records.length; position += 1) {
    const prior = records[position - 1];
    const current = records[position];
    records[position] = createEvidenceLedgerRecord({
      sequence: position + 1,
      previousRecordDigest: prior?.recordDigest,
      source: current.source,
      kind: current.kind,
      occurredAtMs: current.occurredAtMs,
      payload: current.payload,
    }, runtime);
  }
}

function writeLedger(path, records) {
  writeText(path, records.length ? `${records.map((record) => JSON.stringify(record)).join("\n")}\n` : "", 0o600);
}

function secureTemp(prefix) {
  const root = mkdtempSync(join(process.cwd(), `.${prefix}`));
  chmodSync(root, 0o700);
  CREATED_TEMP_ROOTS.add(root);
  return root;
}

function secureDirectory(path) {
  mkdirSync(path, { recursive: true, mode: 0o700 });
  chmodSync(path, 0o700);
  return path;
}

function writeText(path, value, mode = 0o600) {
  writeFileSync(path, value, { mode });
  chmodSync(path, mode);
}

function treeDigest(root, files) {
  const hash = createHash("sha256");
  for (const path of [...files].sort()) {
    const fileHash = createHash("sha256").update(readFileSync(join(root, path))).digest("hex");
    hash.update(path);
    hash.update("\0");
    hash.update(fileHash);
    hash.update("\n");
  }
  return `sha256:${hash.digest("hex")}`;
}

function runChild(executable, arguments_) {
  return new Promise((resolvePromise, rejectPromise) => {
    const child = spawn(executable, arguments_, {
      cwd: process.cwd(),
      stdio: ["ignore", "pipe", "pipe"],
    });
    let stdout = "";
    let stderr = "";
    child.stdout.setEncoding("utf8");
    child.stderr.setEncoding("utf8");
    child.stdout.on("data", (chunk) => { stdout += chunk; });
    child.stderr.on("data", (chunk) => { stderr += chunk; });
    child.once("error", rejectPromise);
    child.once("close", (status, signal) => {
      resolvePromise({ status, signal, stdout, stderr });
    });
  });
}

function digest(value) {
  return `sha256:${createHash("sha256").update(value).digest("hex")}`;
}

function rawDigest(value) {
  return createHash("sha256").update(value).digest("hex");
}

function digestJson(value) {
  return digest(canonicalJson(value));
}

function canonicalJson(value) {
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  if (value && typeof value === "object") {
    return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonicalJson(value[key])}`).join(",")}}`;
  }
  return JSON.stringify(value);
}

function resignProductionPredecision(envelope, key) {
  const base = {
    schemaVersion: envelope.schemaVersion,
    kind: envelope.kind,
    keyId: envelope.keyId,
    payload: envelope.payload,
  };
  const canonical = canonicalJson(base);
  return {
    ...base,
    payloadDigest: digest(canonical),
    signature: createHmac("sha256", key.secret)
      .update(PRODUCTION_PREDECISION_DOMAIN)
      .update(canonical)
      .digest("base64url"),
  };
}

function reverseObjectKeys(value) {
  return Object.fromEntries(Object.entries(value).reverse());
}

function clone(value) {
  return JSON.parse(JSON.stringify(value));
}
