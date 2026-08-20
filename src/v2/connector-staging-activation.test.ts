import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import Database from "better-sqlite3";
import {
  SqliteOAuthClientsStore,
  SqliteOAuthStore,
  connectorActivationTupleDigest,
  type ConnectorActivationAuthorityProof,
  type ConnectorActivationAuthorityReceipt,
  type ConnectorActivationReceipt,
  type ConnectorActivationTuple,
  type ConnectorBindingRecord,
} from "../oauth-store.js";
import { OperationAuthorityRegistry } from "./authority.js";
import {
  signConnectorActivationStagingPrecheck,
  verifyConnectorActivationStagingPrecheck,
  type ConnectorActivationImmutableCandidateIdentity,
  type ConnectorActivationStagingCandidateBindingIdentity,
  type ConnectorActivationStagingPrecheckPayload,
  type VerifiedConnectorActivationStagingPrecheck,
} from "./connector-activation-evidence.js";
import { SqliteConnectorActivationRecoveryJournal } from "./connector-activation-journal.js";
import {
  CONNECTOR_STAGING_ACTIVATION_OUTWARD_STATE,
  ConnectorStagingActivationCoordinator,
  ConnectorStagingActivationUnknownError,
  connectorStagingActivationOwnerApprovalBinding,
  signConnectorStagingActivationOwnerApproval,
  verifyConnectorStagingActivationOwnerApproval,
  type ConnectorStagingActivationInput,
  type ConnectorStagingActivationOwnerApprovalPayload,
  type SignedConnectorStagingActivationOwnerApproval,
  type VerifiedConnectorStagingActivationOwnerApproval,
} from "./connector-staging-activation.js";
import { UNIVERSAL_OWNER_SCOPES, UNIVERSAL_TOOL_NAMES } from "./contracts.js";
import {
  loadOrCreateManagementAuthorizationKey,
  type ManagementAuthorizationKey,
} from "./management-authorization.js";

const REDIRECT_URI = "https://chatgpt.com/connector_platform_oauth_redirect";
const CANONICAL_NAME = "myDevSpace";
const OWNER_PRINCIPAL = rawDigest("staging-activation-owner");
const MANAGEMENT_NONCE = "staging-activation-management-nonce";
const MANAGEMENT_CORRELATION_ID = "staging-activation-management-correlation";
const OAUTH_RESOURCE = "https://staging.example.test/mcp";
const STAGING_ENVIRONMENT_IDENTITY = digest("staging-activation-environment");
const STAGING_ROUTE_IDENTITY = digest("staging-activation-route");

type ActivationInput = Parameters<ConnectorStagingActivationCoordinator["activateOrReconcile"]>[0];
type HasForbiddenCallerTuple = "tuple" extends keyof ActivationInput ? true : false;
type HasForbiddenCallerProof = "authorityProof" extends keyof ActivationInput ? true : false;
type HasForbiddenCallerPass = "pass" extends keyof ActivationInput ? true : false;
const NO_CALLER_TUPLE_OR_PROOF_OR_PASS: [
  HasForbiddenCallerTuple,
  HasForbiddenCallerProof,
  HasForbiddenCallerPass,
] = [false, false, false];

interface StagingFixture {
  root: string;
  oauthPath: string;
  authorityPath: string;
  journalPath: string;
  key: ManagementAuthorizationKey;
  oauthStore: SqliteOAuthStore;
  authorityRegistry: OperationAuthorityRegistry;
  journal: SqliteConnectorActivationRecoveryJournal;
  prepared: ConnectorActivationReceipt;
  preparedBinding: ConnectorBindingRecord;
  candidateIdentity: ConnectorActivationImmutableCandidateIdentity;
  stagingPrecheck: VerifiedConnectorActivationStagingPrecheck;
  ownerApproval: VerifiedConnectorStagingActivationOwnerApproval;
  ownerEnvelope: SignedConnectorStagingActivationOwnerApproval;
}

class CountingOAuthStore {
  activationCalls = 0;

  constructor(readonly delegate: SqliteOAuthStore) {}

  getConnectorBinding(bindingId: string): ConnectorBindingRecord | undefined {
    return this.delegate.getConnectorBinding(bindingId);
  }

  getActivationReceipt(receiptId: string): ConnectorActivationReceipt | undefined {
    return this.delegate.getActivationReceipt(receiptId);
  }

  getActivationAuthorityReceipt(receiptId: string): ConnectorActivationAuthorityReceipt | undefined {
    return this.delegate.getActivationAuthorityReceipt(receiptId);
  }

  activatePreparedConnector(
    receiptId: string,
    tuple: ConnectorActivationTuple,
    proof: ConnectorActivationAuthorityProof,
  ): ConnectorActivationReceipt {
    this.activationCalls += 1;
    return this.delegate.activatePreparedConnector(receiptId, tuple, proof);
  }
}

class ThrowBeforeOAuthCommitStore extends CountingOAuthStore {
  override activatePreparedConnector(
    _receiptId: string,
    _tuple: ConnectorActivationTuple,
    _proof: ConnectorActivationAuthorityProof,
  ): ConnectorActivationReceipt {
    this.activationCalls += 1;
    throw new Error("simulated loss before OAuth CAS");
  }
}

class CommitThenThrowOAuthStore extends CountingOAuthStore {
  override activatePreparedConnector(
    receiptId: string,
    tuple: ConnectorActivationTuple,
    proof: ConnectorActivationAuthorityProof,
  ): ConnectorActivationReceipt {
    this.activationCalls += 1;
    this.delegate.activatePreparedConnector(receiptId, tuple, proof);
    throw new Error("simulated loss after OAuth CAS");
  }
}

test("staging activation API accepts no caller tuple, authority proof, or PASS", () => {
  assert.deepEqual(NO_CALLER_TUPLE_OR_PROOF_OR_PASS, [false, false, false]);
  assert.equal(ConnectorStagingActivationCoordinator.prototype.activateOrReconcile.length, 1);
});

test("real SQLite staging activation reaches ACTIVE once and returns pending PRE canary state", async (t) => {
  const fixture = await createFixture("positive");
  t.after(async () => cleanupFixture(fixture));
  assertCandidateProgression(fixture, "ACTIVATION_PREPARED");

  saveBoundTokenFamily(fixture.oauthStore, fixture.preparedBinding, "pre-activation-family");
  assert.equal(
    fixture.oauthStore.getActivationReceipt(fixture.prepared.receiptId)?.status,
    "PREPARED",
    "token issuance must not activate the prepared connector",
  );

  const first = coordinator(fixture).activateOrReconcile(input(fixture));
  assert.equal(first.state, CONNECTOR_STAGING_ACTIVATION_OUTWARD_STATE);
  assert.equal(first.activationReceipt.status, "ACTIVATED");
  assert.equal(first.stagingBinding.state, "ACTIVE");
  assert.equal(first.activationAuthorityReceipt.authorityId, first.recovery.authorityId);
  assert.equal(first.activationAuthorityReceipt.actionClaimId, first.recovery.actionClaimId);
  assert.equal(first.activationAuthorityReceipt.finalizationPlanDigest, first.finalizationPlanDigest);
  assert.equal(first.authorityCompletionReceipt.state, "PASS");
  assert.equal(first.authorityCompletionReceipt.result, "PASS");
  assert.equal(first.authorityCompletionReceipt.leaseState, "RELEASED");

  const beforeReplay = activationCounts(fixture);
  const replay = coordinator(fixture).activateOrReconcile(input(fixture));
  assert.equal(replay.state, CONNECTOR_STAGING_ACTIVATION_OUTWARD_STATE);
  assert.deepEqual(activationCounts(fixture), beforeReplay, "replay must only read back the one committed activation");
});

test("staging activation rejects unverified, stale, and mismatched evidence before dispatch", async (t) => {
  const cases: Array<[
    string,
    (fixture: StagingFixture) => ConnectorStagingActivationInput,
    (fixture: StagingFixture) => ConnectorStagingActivationCoordinator,
  ]> = [
    ["arbitrary-owner", (fixture) => ({
      ...input(fixture),
      ownerApproval: fixture.ownerEnvelope as unknown as VerifiedConnectorStagingActivationOwnerApproval,
    }), coordinator],
    ["json-owner", (fixture) => ({
      ...input(fixture),
      ownerApproval: JSON.parse(JSON.stringify(fixture.ownerApproval)) as VerifiedConnectorStagingActivationOwnerApproval,
    }), coordinator],
    ["expired-owner", input, (fixture) => coordinator(fixture, { now: () => fixture.ownerApproval.expiresAtMs })],
    ["wrong-principal", (fixture) => ({
      ...input(fixture),
      authenticatedOwnerPrincipalKeyFingerprint: rawDigest("wrong-staging-principal"),
    }), coordinator],
    ["unverified-precheck", (fixture) => ({
      ...input(fixture),
      stagingActivationPrecheck:
        JSON.parse(JSON.stringify(fixture.stagingPrecheck)) as VerifiedConnectorActivationStagingPrecheck,
    }), coordinator],
    ["tuple-drift", (fixture) => {
      tamperReceiptTuple(fixture, { installationEpoch: fixture.prepared.tuple.installationEpoch + 1 });
      return input(fixture);
    }, coordinator],
    ["build-drift", (fixture) => {
      tamperBindingBuild(fixture, digest("wrong-build"));
      return input(fixture);
    }, coordinator],
    ["redirect-drift", (fixture) => {
      tamperReceiptTuple(fixture, { redirectUrisDigest: digest("wrong-redirect") });
      return input(fixture);
    }, coordinator],
    ["route-drift", (fixture) => ({
      ...input(fixture),
      ownerApproval: ownerApprovalForBinding(fixture, {
        stagingRouteIdentityDigest: digest("wrong-route"),
      }),
    }), coordinator],
    ["plan-drift", (fixture) => ({
      ...input(fixture),
      ownerApproval: ownerApprovalForBinding(fixture, {
        finalizationPlanDigest: digest("wrong-plan"),
      }),
    }), coordinator],
  ];

  for (const [label, makeInput, makeCoordinator] of cases) {
    await t.test(label, async (t) => {
      const fixture = await createFixture(label);
      t.after(async () => cleanupFixture(fixture));
      assert.throws(() => makeCoordinator(fixture).activateOrReconcile(makeInput(fixture)));
      assertNoActivationDispatch(fixture);
    });
  }
});

test("staging activation rejects persisted binding redirect drift before journal reserve", async (t) => {
  const fixture = await createFixture("binding-redirect-drift");
  t.after(async () => cleanupFixture(fixture));

  tamperBindingRedirect(fixture, digest("wrong-current-binding-redirect"));
  const error = captureThrown(() => coordinator(fixture).activateOrReconcile(input(fixture)));
  assert.equal(error.code, "PRECONDITION_FAILED");
  assertNoActivationDispatch(fixture);
});

test("staging owner approval verifier rejects wrong expected precheck bindings", async (t) => {
  const fixture = await createFixture("approval-verifier");
  t.after(async () => cleanupFixture(fixture));
  const expected = connectorStagingActivationOwnerApprovalBinding(
    fixture.prepared,
    fixture.stagingPrecheck,
    OWNER_PRINCIPAL,
  );
  assert.throws(
    () => verifyConnectorStagingActivationOwnerApproval(
      fixture.ownerEnvelope,
      fixture.key,
      { ...expected, stagingActivationPrecheckDigest: digest("wrong-precheck") },
    ),
    /precheck|mismatch/iu,
  );
  assertNoActivationDispatch(fixture);
});

test("DISPATCHED recovery recovers PASS only from exact OAuth readback", async (t) => {
  const fixture = await createFixture("recover-pass");
  const crashingStore = new CommitThenThrowOAuthStore(fixture.oauthStore);
  t.after(async () => cleanupFixture(fixture));

  assert.throws(
    () => coordinator(fixture, { oauthStore: crashingStore }).activateOrReconcile(input(fixture)),
    ConnectorStagingActivationUnknownError,
  );
  assert.equal(crashingStore.activationCalls, 1);
  assert.equal(
    fixture.oauthStore.getActivationReceipt(fixture.prepared.receiptId)?.status,
    "ACTIVATED",
  );
  closeFixtureStores(fixture);

  const reopened = reopenFixture(fixture, "recover-pass-reopen");
  const recovered = coordinator(reopened).reconcile(input(reopened));
  assert.equal(recovered.state, CONNECTOR_STAGING_ACTIVATION_OUTWARD_STATE);
  assert.equal(recovered.activationReceipt.status, "ACTIVATED");
  assert.equal(recovered.authorityCompletionReceipt.state, "PASS");
  assert.equal(recovered.authorityCompletionReceipt.result, "PASS");
  closeFixtureStores(reopened);
});

test("DISPATCHED recovery without OAuth readback returns UNKNOWN and does not replay", async (t) => {
  const fixture = await createFixture("recover-unknown");
  const crashingStore = new ThrowBeforeOAuthCommitStore(fixture.oauthStore);
  t.after(async () => cleanupFixture(fixture));

  assert.throws(
    () => coordinator(fixture, { oauthStore: crashingStore }).activateOrReconcile(input(fixture)),
    ConnectorStagingActivationUnknownError,
  );
  assert.equal(crashingStore.activationCalls, 1);
  assert.equal(
    fixture.oauthStore.getActivationReceipt(fixture.prepared.receiptId)?.status,
    "PREPARED",
  );
  closeFixtureStores(fixture);

  const reopened = reopenFixture(fixture, "recover-unknown-reopen");
  const recovered = coordinator(reopened).reconcile(input(reopened));
  assert.equal(recovered.state, "UNKNOWN");
  assert.equal(recovered.oauthCommitted, false);
  assert.equal(recovered.retryAllowed, false);
  assert.equal(recovered.reason, "DISPATCHED_OUTCOME_NOT_PROVEN");
  assert.equal(activationCounts(reopened).oauthAuthorities, 0);
  closeFixtureStores(reopened);
});

async function createFixture(label: string): Promise<StagingFixture> {
  const root = await mkdtemp(join(tmpdir(), `devspace-staging-activation-${label}-`));
  const key = loadOrCreateManagementAuthorizationKey({
    keyRef: join(root, "management.key"),
    stateDir: root,
  });
  const oauthDir = join(root, "oauth");
  const oauthStore = new SqliteOAuthStore(oauthDir);
  const client = new SqliteOAuthClientsStore(oauthStore, ["chatgpt.com"]).registerClient({
    redirect_uris: [REDIRECT_URI],
    client_name: `Staging ${label}`,
  });
  const candidateIdentity: ConnectorActivationImmutableCandidateIdentity = {
    runtimeIdentityDigest: digest(`runtime-${label}`),
    buildDigest: digest(`build-${label}`),
    schemaGeneration: digest(`schema-${label}`),
    authorityContractGeneration: digest(`authority-${label}`),
    buildCapabilityManifestDigest: digest(`capability-${label}`),
    generatedSchemaDigest: digest(`generated-schema-${label}`),
    packageSha256: digest(`package-${label}`),
  };
  const { binding, tuple } = verifiedCandidateWithIdentity(
    oauthStore,
    client.client_id,
    candidateIdentity,
    label,
  );
  const prepared = oauthStore.prepareConnectorActivation(tuple, {
    drainDeadlineAt: new Date(Date.now() + 300_000).toISOString(),
    refreshAllowedDuringDrain: false,
  });
  const preparedBinding = oauthStore.getConnectorBinding(binding.bindingId)!;
  const observedAtMs = Date.now();
  const stagingCandidateBinding: ConnectorActivationStagingCandidateBindingIdentity = {
    environmentIdentityDigest: STAGING_ENVIRONMENT_IDENTITY,
    canonicalName: preparedBinding.canonicalName,
    clientId: preparedBinding.clientId,
    bindingId: preparedBinding.bindingId,
    installationEpoch: preparedBinding.installationEpoch,
    state: "ACTIVATION_PREPARED",
  };
  const stagingPrecheckPayload: ConnectorActivationStagingPrecheckPayload = {
    stage: "STAGING_ACTIVATION_PRECHECK",
    stagingActivationPrecheckId: `staging-precheck-${label}`,
    managementNonce: MANAGEMENT_NONCE,
    managementCorrelationId: MANAGEMENT_CORRELATION_ID,
    principalKeyFingerprint: OWNER_PRINCIPAL,
    hostProvider: "chatgpt",
    actualHost: true,
    candidateIdentity,
    stagingRouteIdentityDigest: STAGING_ROUTE_IDENTITY,
    stagingCandidateBinding,
    discoveredToolNames: UNIVERSAL_TOOL_NAMES,
    toolDiscoveryEvidenceDigest: digest(`tools-${label}`),
    r0Canary: {
      tool: "target",
      operation: "list",
      argumentsDigest: digest(`r0-args-${label}`),
      resourceDigest: digest(`r0-resource-${label}`),
      providerDispatchCount: 1,
      readbackDigest: digest(`r0-readback-${label}`),
    },
    observedAtMs,
    expiresAtMs: observedAtMs + 110_000,
  };
  const stagingEnvelope = signConnectorActivationStagingPrecheck(
    stagingPrecheckPayload,
    key,
    observedAtMs,
  );
  const stagingPrecheck = verifyConnectorActivationStagingPrecheck(
    stagingEnvelope,
    key,
    {
      principalKeyFingerprint: OWNER_PRINCIPAL,
      managementNonce: MANAGEMENT_NONCE,
      managementCorrelationId: MANAGEMENT_CORRELATION_ID,
      candidateIdentity,
      stagingRouteIdentityDigest: STAGING_ROUTE_IDENTITY,
      stagingCandidateBinding,
    },
    observedAtMs,
  );
  const ownerEnvelope = signOwnerApproval(
    prepared,
    stagingPrecheck,
    key,
    `owner-approval-${label}`,
    "Activate this exact isolated staging connector before PRE canary.",
  );
  const ownerApproval = verifyConnectorStagingActivationOwnerApproval(
    ownerEnvelope,
    key,
    connectorStagingActivationOwnerApprovalBinding(prepared, stagingPrecheck, OWNER_PRINCIPAL),
  );
  const authorityPath = join(root, "authority.sqlite");
  const journalPath = join(root, "journal.sqlite");
  return {
    root,
    oauthPath: join(oauthDir, "devspace.sqlite"),
    authorityPath,
    journalPath,
    key,
    oauthStore,
    authorityRegistry: new OperationAuthorityRegistry({
      storePath: authorityPath,
      instanceId: `staging-activation-${label}`,
    }),
    journal: new SqliteConnectorActivationRecoveryJournal({ storePath: journalPath }),
    prepared,
    preparedBinding,
    candidateIdentity,
    stagingPrecheck,
    ownerApproval,
    ownerEnvelope,
  };
}

function reopenFixture(fixture: StagingFixture, instanceId: string): StagingFixture {
  return {
    ...fixture,
    oauthStore: new SqliteOAuthStore(join(fixture.root, "oauth")),
    authorityRegistry: new OperationAuthorityRegistry({
      storePath: fixture.authorityPath,
      instanceId,
    }),
    journal: new SqliteConnectorActivationRecoveryJournal({ storePath: fixture.journalPath }),
  };
}

function coordinator(
  fixture: StagingFixture,
  overrides: {
    oauthStore?: CountingOAuthStore | SqliteOAuthStore;
    now?: () => number;
  } = {},
): ConnectorStagingActivationCoordinator {
  return new ConnectorStagingActivationCoordinator({
    oauthStore: overrides.oauthStore ?? fixture.oauthStore,
    authorityRegistry: fixture.authorityRegistry,
    recoveryJournal: fixture.journal,
    ...(overrides.now ? { now: overrides.now } : {}),
  });
}

function input(fixture: StagingFixture): ConnectorStagingActivationInput {
  return {
    stagingActivationPrecheck: fixture.stagingPrecheck,
    authenticatedOwnerPrincipalKeyFingerprint: OWNER_PRINCIPAL,
    ownerApproval: fixture.ownerApproval,
  };
}

function verifiedCandidateWithIdentity(
  store: SqliteOAuthStore,
  clientId: string,
  identity: ConnectorActivationImmutableCandidateIdentity,
  label: string,
): { binding: ConnectorBindingRecord; tuple: ConnectorActivationTuple } {
  const registration = {
    canonicalName: CANONICAL_NAME,
    clientId,
    installationEpoch: 1,
    schemaGeneration: identity.schemaGeneration,
  };
  const binding = store.ensureCandidateConnectorBinding(registration);
  const evidence = {
    authorityContractGeneration: identity.authorityContractGeneration,
    redirectUrisDigest: digest(`redirect-${label}`),
    buildDigest: identity.buildDigest,
  };
  const verified = store.markConnectorBindingVerified(binding.bindingId, evidence);
  return { binding: verified, tuple: { ...registration, candidateBindingId: binding.bindingId, ...evidence } };
}

function signOwnerApproval(
  receipt: ConnectorActivationReceipt,
  precheck: VerifiedConnectorActivationStagingPrecheck,
  key: ManagementAuthorizationKey,
  approvalId: string,
  authorityText: string,
): SignedConnectorStagingActivationOwnerApproval {
  const approvedAtMs = Math.max(Date.now(), precheck.observedAtMs);
  const payload: ConnectorStagingActivationOwnerApprovalPayload = {
    ...connectorStagingActivationOwnerApprovalBinding(receipt, precheck, OWNER_PRINCIPAL),
    approvalId,
    authorityText,
    evidenceDigest: digest(`owner-evidence-${approvalId}`),
    approvedAtMs,
    expiresAtMs: approvedAtMs + 110_000,
  };
  return signConnectorStagingActivationOwnerApproval(payload, key, approvedAtMs);
}

function ownerApprovalForBinding(
  fixture: StagingFixture,
  overrides: Partial<ReturnType<typeof connectorStagingActivationOwnerApprovalBinding>>,
): VerifiedConnectorStagingActivationOwnerApproval {
  const binding = {
    ...connectorStagingActivationOwnerApprovalBinding(
      fixture.prepared,
      fixture.stagingPrecheck,
      OWNER_PRINCIPAL,
    ),
    ...overrides,
  };
  const approvedAtMs = Math.max(Date.now(), fixture.stagingPrecheck.observedAtMs);
  const envelope = signConnectorStagingActivationOwnerApproval({
    ...binding,
    approvalId: `owner-approval-${String(overrides.finalizationPlanDigest ?? overrides.stagingRouteIdentityDigest)}`,
    authorityText: "Activate this exact isolated staging connector with tampered test binding.",
    evidenceDigest: digest(`owner-evidence-${String(overrides.finalizationPlanDigest ?? overrides.stagingRouteIdentityDigest)}`),
    approvedAtMs,
    expiresAtMs: approvedAtMs + 110_000,
  }, fixture.key, approvedAtMs);
  return verifyConnectorStagingActivationOwnerApproval(envelope, fixture.key, binding, approvedAtMs);
}

function saveBoundTokenFamily(
  store: SqliteOAuthStore,
  binding: ConnectorBindingRecord,
  familyId: string,
): void {
  const expiresAt = Math.floor(Date.now() / 1_000) + 3_600;
  const token = {
    clientId: binding.clientId,
    scopes: [...UNIVERSAL_OWNER_SCOPES],
    expiresAt,
    resource: OAUTH_RESOURCE,
    familyId,
    connectorBindingId: binding.bindingId,
    connectorDrainEpoch: binding.drainEpoch,
    installationEpoch: binding.installationEpoch,
    rotationSequence: 0,
  };
  assert.equal(store.saveTokenPair({
    accessTokenHash: rawDigest(`access-${familyId}`),
    accessToken: token,
    refreshTokenHash: rawDigest(`refresh-${familyId}`),
    refreshToken: token,
  }), true);
}

function tamperBindingBuild(fixture: StagingFixture, buildDigest: string): void {
  const sqlite = new Database(fixture.oauthPath);
  sqlite.prepare("update oauth_connector_bindings set build_digest = ? where binding_id = ?")
    .run(buildDigest, fixture.prepared.tuple.candidateBindingId);
  sqlite.close();
}

function tamperBindingRedirect(fixture: StagingFixture, redirectUrisDigest: string): void {
  const sqlite = new Database(fixture.oauthPath);
  sqlite.prepare("update oauth_connector_bindings set redirect_uris_digest = ? where binding_id = ?")
    .run(redirectUrisDigest, fixture.prepared.tuple.candidateBindingId);
  sqlite.close();
}

function tamperReceiptTuple(
  fixture: StagingFixture,
  overrides: Partial<ConnectorActivationTuple>,
): void {
  const tuple = { ...fixture.prepared.tuple, ...overrides };
  const tupleDigest = connectorActivationTupleDigest(tuple);
  const sqlite = new Database(fixture.oauthPath);
  sqlite.prepare(`
    update oauth_connector_activation_receipts
       set installation_epoch = ?, schema_generation = ?, authority_contract_generation = ?,
           redirect_uris_digest = ?, build_digest = ?, tuple_digest = ?
     where receipt_id = ?
  `).run(
    tuple.installationEpoch,
    tuple.schemaGeneration,
    tuple.authorityContractGeneration,
    tuple.redirectUrisDigest,
    tuple.buildDigest,
    tupleDigest,
    fixture.prepared.receiptId,
  );
  sqlite.close();
}

function captureThrown(callback: () => unknown): { code?: string } {
  try {
    callback();
  } catch (error) {
    return error as { code?: string };
  }
  assert.fail("Expected staging activation to throw.");
}

function assertCandidateProgression(
  fixture: StagingFixture,
  expectedState: ConnectorBindingRecord["state"],
): void {
  const binding = fixture.oauthStore.getConnectorBinding(fixture.prepared.tuple.candidateBindingId);
  assert.equal(binding?.state, expectedState);
  assert.equal(fixture.oauthStore.getActivationReceipt(fixture.prepared.receiptId)?.status, "PREPARED");
}

function assertNoActivationDispatch(fixture: StagingFixture): void {
  const counts = activationCounts(fixture);
  assert.equal(counts.oauthAuthorities, 0);
  assert.equal(counts.journalEntries, 0);
  assert.equal(
    fixture.oauthStore.getActivationReceipt(fixture.prepared.receiptId)?.status,
    "PREPARED",
  );
}

function activationCounts(fixture: Pick<StagingFixture, "oauthPath" | "journalPath" | "prepared">): {
  oauthAuthorities: number;
  journalEntries: number;
  journalTransitions: number;
} {
  const oauth = new Database(fixture.oauthPath, { readonly: true });
  const oauthAuthorities = oauth.prepare(
    "select count(*) as count from oauth_connector_activation_authorities where receipt_id = ?",
  ).get(fixture.prepared.receiptId) as { count: number };
  oauth.close();
  const journal = new Database(fixture.journalPath, { readonly: true });
  const journalEntries = journal.prepare(
    "select count(*) as count from connector_activation_journal_entries where receipt_id = ?",
  ).get(fixture.prepared.receiptId) as { count: number };
  const journalTransitions = journal.prepare(
    "select count(*) as count from connector_activation_journal_transitions where receipt_id = ?",
  ).get(fixture.prepared.receiptId) as { count: number };
  journal.close();
  return {
    oauthAuthorities: oauthAuthorities.count,
    journalEntries: journalEntries.count,
    journalTransitions: journalTransitions.count,
  };
}

function closeFixtureStores(fixture: StagingFixture): void {
  for (const close of [
    () => fixture.journal.close(),
    () => fixture.authorityRegistry.close(),
    () => fixture.oauthStore.close(),
  ]) {
    try {
      close();
    } catch {
      // Tests close stores explicitly around reopen boundaries.
    }
  }
}

async function cleanupFixture(fixture: StagingFixture): Promise<void> {
  closeFixtureStores(fixture);
  await rm(fixture.root, { recursive: true, force: true });
}

function digest(value: string | Uint8Array): string {
  return `sha256:${createHash("sha256").update(value).digest("hex")}`;
}

function rawDigest(value: string): string {
  return createHash("sha256").update(value).digest("hex");
}
