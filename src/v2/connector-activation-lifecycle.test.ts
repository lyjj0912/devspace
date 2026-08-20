import assert from "node:assert/strict";
import { createHash, createHmac } from "node:crypto";
import { createServer, type Server } from "node:http";
import { chmod, mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import Database from "better-sqlite3";
import {
  SqliteOAuthClientsStore,
  SqliteOAuthStore,
  connectorActivationAuthorityActionFingerprint,
  connectorActivationAuthorityResourceKeySha256,
  connectorActivationTupleDigest,
  type ConnectorActivationAuthorityProof,
  type ConnectorActivationAuthorityReceipt,
  type ConnectorActivationReceipt,
  type ConnectorActivationTuple,
  type ConnectorBindingRecord,
} from "../oauth-store.js";
import {
  OperationAuthorityRegistry,
  actionFingerprint,
  actionResourceKeySha256,
} from "./authority.js";
import { authorityActionFromToolCall, minimumAuthorityRisk } from "./authority-policy.js";
import {
  connectorActivationAuthorityReceiptDigest,
  connectorActivationReceiptDigest,
  signConnectorActivationOwnerApproval,
  signConnectorActivationPostActivationHostCanary,
  signConnectorActivationPreCutoverHostCanary,
  signConnectorActivationProductionPrecheck,
  signConnectorActivationStagingPrecheck,
  verifyConnectorActivationStagingPrecheck,
  type ConnectorActivationCanaryMutationEvidence,
  type ConnectorActivationForeignClientIsolationEvidence,
  type ConnectorActivationImmutableCandidateIdentity,
  type ConnectorActivationOwnerApprovalPayload,
  type ConnectorActivationPostActivationHostCanaryPayload,
  type ConnectorActivationPreCutoverHostCanaryPayload,
  type ConnectorActivationProductionPrecheckPayload,
  type ConnectorActivationStagingBindingIdentity,
  type ConnectorActivationStagingPrecheckPayload,
  type SignedConnectorActivationEvidence,
} from "./connector-activation-evidence.js";
import { connectorActivationFinalizationPlanDigest } from "./connector-activation-finalizer.js";
import { connectorStagingActivationPlanDigest } from "./connector-staging-activation-contract.js";
import {
  ConnectorActivationLifecycleManager,
  type ConnectorActivationLifecycleConfiguration,
  type ConnectorActivationLifecyclePrepared,
} from "./connector-activation-lifecycle.js";
import { SqliteConnectorActivationRecoveryJournal } from "./connector-activation-journal.js";
import { UNIVERSAL_OWNER_SCOPES, UNIVERSAL_TOOL_NAMES } from "./contracts.js";
import {
  loadOrCreateManagementAuthorizationKey,
  managementAuthorizationHeader,
  type ManagementAuthorizationKey,
} from "./management-authorization.js";

const REDIRECT_URI = "https://chatgpt.com/connector_platform_oauth_redirect";
const CANONICAL_NAME = "myDevSpace";
const OWNER_PRINCIPAL = rawDigest("lifecycle-owner-principal");
const MANAGEMENT_NONCE = "lifecycle-management-nonce";
const MANAGEMENT_CORRELATION_ID = "lifecycle-management-correlation";
const OAUTH_RESOURCE = "https://production.example.test/mcp";
const STAGING_ENVIRONMENT_IDENTITY = digest("lifecycle-staging-environment");
const STAGING_ROUTE_IDENTITY = digest("lifecycle-staging-route");
const PRODUCTION_ENVIRONMENT_IDENTITY = digest("lifecycle-production-environment");
const PRODUCTION_ROUTE_IDENTITY = digest("lifecycle-production-route");

type NoCallerActivationEvidence = Parameters<
  ConnectorActivationLifecycleManager["activateOrReconcile"]
> extends [] ? true : false;
const NO_CALLER_ACTIVATION_EVIDENCE: NoCallerActivationEvidence = true;

// @ts-expect-error Lifecycle state is intentionally branded and cannot be caller-fabricated.
const FORGED_PREPARED_STATE: ConnectorActivationLifecyclePrepared = {
  state: "CONNECTOR_ACTIVATION_PREPARED",
  receiptId: "forged",
  tupleDigest: digest("forged"),
  journalContentGeneration: digest("forged-journal"),
};
void FORGED_PREPARED_STATE;

interface LifecycleFixture {
  root: string;
  configuration: ConnectorActivationLifecycleConfiguration;
  key: ManagementAuthorizationKey;
  prepared: ConnectorActivationReceipt;
  candidateIdentity: ConnectorActivationImmutableCandidateIdentity;
  stagingPrecheckEnvelope: SignedConnectorActivationEvidence<ConnectorActivationStagingPrecheckPayload>;
  preEnvelope: SignedConnectorActivationEvidence<ConnectorActivationPreCutoverHostCanaryPayload>;
  productionPrecheckEnvelope: SignedConnectorActivationEvidence<ConnectorActivationProductionPrecheckPayload>;
  ownerEnvelope: SignedConnectorActivationEvidence<ConnectorActivationOwnerApprovalPayload>;
  oldTokenFamilyId?: string;
  server: Server;
}

test("lifecycle API is branded and contains no caller tuple/proof/PASS input", () => {
  assert.equal(NO_CALLER_ACTIVATION_EVIDENCE, true);
  assert.equal(ConnectorActivationLifecycleManager.prototype.activateOrReconcile.length, 0);
  assert.equal(ConnectorActivationLifecycleManager.prototype.verifyPostActivation.length, 0);
});

test("lifecycle accepts only exact same-origin loopback management readback endpoints", async (t) => {
  const fixture = await createFixture("readback-url-boundary");
  t.after(async () => cleanupFixture(fixture));

  for (const postActivation of [
    {
      ...fixture.configuration.postActivation,
      runtimeIdentityUrl: "https://127.0.0.1:9443/readyz",
    },
    {
      ...fixture.configuration.postActivation,
      routeIdentityUrl: "http://127.0.0.1:9443/route-identityz",
    },
    {
      ...fixture.configuration.postActivation,
      routeIdentityUrl: fixture.configuration.postActivation.routeIdentityUrl.replace(
        "/route-identityz",
        "/route",
      ),
    },
  ]) {
    assert.throws(
      () => new ConnectorActivationLifecycleManager({
        ...fixture.configuration,
        postActivation,
      }),
      /exact loopback management|same loopback management origin/u,
    );
  }
});

test("real-store lifecycle activates once, reconstructs after restart, and verifies exact POST", async (t) => {
  const fixture = await createFixture("positive", { withOldActive: true });
  t.after(async () => cleanupFixture(fixture));

  const first = new ConnectorActivationLifecycleManager(fixture.configuration);
  assert.equal((await first.prepare()).state, "CONNECTOR_ACTIVATION_PREPARED");
  const pending = await first.activateOrReconcile();
  assert.equal(pending.state, "ACTIVATED_PENDING_POSTCHECK");
  first.close();

  const post = await installPostReadback(fixture);
  const before = activationCounts(fixture);
  const restarted = new ConnectorActivationLifecycleManager(fixture.configuration);
  assert.equal((await restarted.prepare()).state, "CONNECTOR_ACTIVATION_PREPARED");
  assert.equal((await restarted.activateOrReconcile()).state, "ACTIVATED_PENDING_POSTCHECK");
  const verified = await restarted.verifyPostActivation();
  assert.equal(verified.state, "POST_ACTIVATION_VERIFIED");
  assert.equal(verified.postActivationEvidenceDigest, post.payloadDigest);
  restarted.close();
  assert.deepEqual(activationCounts(fixture), before, "restart must not replay DISPATCHED activation");

  const terminalBefore = activationCounts(fixture);
  const terminalRestart = new ConnectorActivationLifecycleManager(fixture.configuration);
  assert.equal((await terminalRestart.prepare()).state, "CONNECTOR_ACTIVATION_PREPARED");
  const terminalVerified = await terminalRestart.activateOrReconcile();
  assert.equal(terminalVerified.state, "POST_ACTIVATION_VERIFIED");
  if (terminalVerified.state !== "POST_ACTIVATION_VERIFIED") assert.fail("terminal restart regressed");
  assert.equal(terminalVerified.postActivationEvidenceDigest, post.payloadDigest);
  assert.equal((await terminalRestart.verifyPostActivation()).postActivationEvidenceDigest, post.payloadDigest);
  terminalRestart.close();
  assert.deepEqual(
    activationCounts(fixture),
    terminalBefore,
    "terminal restart must not re-finalize or append a backward lifecycle transition",
  );

  const journal = new SqliteConnectorActivationRecoveryJournal({
    storePath: fixture.configuration.journal.path,
  });
  const entries = journal.listUnresolved(OWNER_PRINCIPAL);
  journal.close();
  assert.equal(entries.length, 0, "POST verification terminalizes the append-only journal entry");
  const sqlite = new Database(fixture.configuration.journal.path, { readonly: true });
  const states = sqlite.prepare(
    "select state from connector_activation_journal_outcomes order by sequence",
  ).all() as Array<{ state: string }>;
  sqlite.close();
  assert.deepEqual(states.map((row) => row.state), [
    "ACTIVATED_PENDING_POSTCHECK",
    "POST_ACTIVATION_VERIFIED",
  ]);
});

test("stale tuple/build/redirect/principal/PRE/journal bindings fail before activation dispatch", async (t) => {
  const cases = ["tuple", "build", "redirect", "principal", "pre", "journal"] as const;
  for (const kind of cases) {
    await t.test(kind, async (t) => {
      const fixture = await createFixture(`stale-${kind}`);
      t.after(async () => cleanupFixture(fixture));
      if (kind === "tuple") {
        fixture.configuration = {
          ...fixture.configuration,
          activation: { ...fixture.configuration.activation, tupleDigest: digest("wrong-tuple") },
        };
      } else if (kind === "build") {
        fixture.configuration = {
          ...fixture.configuration,
          candidateIdentity: {
            ...fixture.configuration.candidateIdentity,
            buildDigest: digest("wrong-build"),
          },
        };
      } else if (kind === "redirect") {
        const changedTuple = {
          ...fixture.productionPrecheckEnvelope.payload.tuple,
          redirectUrisDigest: digest("wrong-redirect"),
        };
        const payload = {
          ...fixture.productionPrecheckEnvelope.payload,
          tuple: changedTuple,
          tupleDigest: tupleDigest(changedTuple),
        };
        await replaceArtifact(
          fixture.configuration.productionActivationPrecheck.path,
          rawSign("PRODUCTION_ACTIVATION_PRECHECK", payload, fixture.key),
          fixture.configuration.productionActivationPrecheck,
        );
      } else if (kind === "principal") {
        const payload = {
          ...fixture.ownerEnvelope.payload,
          principalKeyFingerprint: rawDigest("wrong-owner-principal"),
        };
        await replaceArtifact(
          fixture.configuration.ownerApproval.path,
          rawSign("OWNER_MANAGEMENT_APPROVAL", payload, fixture.key),
          fixture.configuration.ownerApproval,
        );
      } else if (kind === "pre") {
        const bytes = await readFile(fixture.configuration.preCutoverHostCanary.path);
        const parsed = JSON.parse(bytes.toString("utf8")) as SignedConnectorActivationEvidence<
          ConnectorActivationPreCutoverHostCanaryPayload
        >;
        parsed.signature = `${parsed.signature.slice(0, -1)}${parsed.signature.endsWith("A") ? "B" : "A"}`;
        await replaceArtifact(
          fixture.configuration.preCutoverHostCanary.path,
          parsed,
          fixture.configuration.preCutoverHostCanary,
        );
      } else {
        fixture.configuration = {
          ...fixture.configuration,
          journal: {
            ...fixture.configuration.journal,
            identity: {
              ...fixture.configuration.journal.identity,
              contentGeneration: digest("tampered-journal-content-generation"),
            },
          },
        };
      }

      const manager = new ConnectorActivationLifecycleManager(fixture.configuration);
      await assert.rejects(() => manager.prepare());
      manager.close();
      assertNoActivationDispatch(fixture);
    });
  }
});

test("a PRE envelope cannot substitute an unactivated production binding for staging readback", async (t) => {
  const fixture = await createFixture("unactivated-staging-substitution");
  t.after(async () => cleanupFixture(fixture));
  const payload = structuredClone(fixture.preEnvelope.payload);
  payload.stagingActivationReceipt = structuredClone(fixture.prepared);
  await replaceArtifact(
    fixture.configuration.preCutoverHostCanary.path,
    rawSign("PRE_CUTOVER_HOST_CANARY", payload, fixture.key),
    fixture.configuration.preCutoverHostCanary,
  );
  const manager = new ConnectorActivationLifecycleManager(fixture.configuration);
  await assert.rejects(
    () => manager.prepare(),
    /staging|ACTIVATED|receipt|evidence signature verification failed/iu,
  );
  manager.close();
  assertNoActivationDispatch(fixture);
});

test("POST rejects an old DRAINING token family before journal verification", async (t) => {
  const fixture = await createFixture("old-token-family", { withOldActive: true });
  t.after(async () => cleanupFixture(fixture));
  const first = new ConnectorActivationLifecycleManager(fixture.configuration);
  await first.prepare();
  const pending = await first.activateOrReconcile();
  first.close();
  assert.ok(fixture.oldTokenFamilyId);

  const valid = await installPostReadback(fixture);
  const oldFamilyPayload: ConnectorActivationPostActivationHostCanaryPayload = {
    ...valid.payload,
    tokenFamilyIdDigest: digest(fixture.oldTokenFamilyId!),
  };
  const oldFamily = signConnectorActivationPostActivationHostCanary(
    oldFamilyPayload,
    fixture.key,
    oldFamilyPayload.observedAtMs,
  );
  await writeOwnerJson(fixture.configuration.postActivation.receiptPath, oldFamily);

  const restarted = new ConnectorActivationLifecycleManager(fixture.configuration);
  await restarted.prepare();
  assert.equal((await restarted.activateOrReconcile()).activationReceiptDigest, pending.activationReceiptDigest);
  await assert.rejects(() => restarted.verifyPostActivation(), /token family.*new ACTIVE/iu);
  restarted.close();
  assertPostNotVerified(fixture);
});

test("POST rejects stale timing and missing readback, cleanup, or foreign-zero fields", async (t) => {
  const fixture = await createFixture("post-negative");
  t.after(async () => cleanupFixture(fixture));
  const first = new ConnectorActivationLifecycleManager(fixture.configuration);
  await first.prepare();
  await first.activateOrReconcile();
  first.close();
  const valid = await installPostReadback(fixture);

  const invalidPayloads: Array<[string, Record<string, unknown>]> = [
    ["timestamp", {
      ...valid.payload,
      observedAtMs: valid.payload.activatedAtMs,
      mutation: {
        ...valid.payload.mutation,
        sessionAAuthorizedAtMs: valid.payload.activatedAtMs,
      },
    }],
    ["readback", omitNested(valid.payload, "mutation", "postReadbackDigest")],
    ["cleanup", omitNested(valid.payload, "mutation", "cleanupPerformed")],
    ["foreign-zero", {
      ...valid.payload,
      foreignClientIsolation: {
        ...valid.payload.foreignClientIsolation,
        providerDispatchCount: 1,
      },
    }],
  ];
  const restarted = new ConnectorActivationLifecycleManager(fixture.configuration);
  await restarted.prepare();
  await restarted.activateOrReconcile();
  for (const [label, payload] of invalidPayloads) {
    await writeOwnerJson(
      fixture.configuration.postActivation.receiptPath,
      rawSign("POST_ACTIVATION_HOST_CANARY", payload, fixture.key),
    );
    await assert.rejects(
      () => restarted.verifyPostActivation(),
      `${label} POST must fail closed`,
    );
    assertPostNotVerified(fixture);
  }
  restarted.close();
});

async function createFixture(
  label: string,
  options: { withOldActive?: boolean } = {},
): Promise<LifecycleFixture> {
  const root = await mkdtemp(join(tmpdir(), `devspace-lifecycle-${label}-`));
  const key = loadOrCreateManagementAuthorizationKey({
    keyRef: join(root, "management.key"),
    stateDir: root,
  });
  const oauthDir = join(root, "oauth");
  const oauthStore = new SqliteOAuthStore(oauthDir);
  const clients = new SqliteOAuthClientsStore(oauthStore, ["chatgpt.com"]);
  let oldTokenFamilyId: string | undefined;
  if (options.withOldActive) {
    const oldClient = clients.registerClient({
      redirect_uris: [REDIRECT_URI],
      client_name: `Lifecycle ${label} old`,
    });
    const old = verifiedCandidate(oauthStore, oldClient.client_id, 1, `old-${label}`);
    const oldPrepared = oauthStore.prepareConnectorActivation(old.tuple, {
      drainDeadlineAt: new Date(Date.now() + 300_000).toISOString(),
      refreshAllowedDuringDrain: true,
    });
    oauthStore.activatePreparedConnector(
      oldPrepared.receiptId,
      old.tuple,
      directActivationProof(oldPrepared, OWNER_PRINCIPAL, `old-${label}`),
    );
    const active = oauthStore.getConnectorBinding(old.binding.bindingId)!;
    oldTokenFamilyId = `old-family-${label}`;
    saveBoundTokenFamily(oauthStore, active, oldTokenFamilyId);
  }
  const productionClient = clients.registerClient({
    redirect_uris: [REDIRECT_URI],
    client_name: `Lifecycle ${label} production`,
  });
  const installationEpoch = options.withOldActive ? 2 : 1;
  const production = verifiedCandidate(
    oauthStore,
    productionClient.client_id,
    installationEpoch,
    `production-${label}`,
  );
  const prepared = oauthStore.prepareConnectorActivation(production.tuple, {
    drainDeadlineAt: new Date(Date.now() + 300_000).toISOString(),
    refreshAllowedDuringDrain: false,
  });
  const runtimeIdentity = {
    schemaVersion: 1,
    releaseId: `release-${label}`,
    buildDigest: prepared.tuple.buildDigest,
  };
  const candidateIdentity: ConnectorActivationImmutableCandidateIdentity = {
    runtimeIdentityDigest: digestJson(runtimeIdentity),
    buildDigest: prepared.tuple.buildDigest,
    schemaGeneration: prepared.tuple.schemaGeneration,
    authorityContractGeneration: prepared.tuple.authorityContractGeneration,
    buildCapabilityManifestDigest: digest(`capability-${label}`),
    generatedSchemaDigest: digest(`generated-schema-${label}`),
    packageSha256: digest(`package-${label}`),
  };
  oauthStore.close();

  const stagingStore = new SqliteOAuthStore(join(root, "staging-oauth"));
  const stagingClient = new SqliteOAuthClientsStore(stagingStore, ["chatgpt.com"]).registerClient({
    redirect_uris: [REDIRECT_URI],
    client_name: `Lifecycle ${label} staging`,
  });
  const staging = verifiedCandidateWithIdentity(
    stagingStore,
    stagingClient.client_id,
    1,
    candidateIdentity,
    `staging-${label}`,
  );
  const stagingPrepared = stagingStore.prepareConnectorActivation(staging.tuple, {
    drainDeadlineAt: new Date(Date.now() + 300_000).toISOString(),
    refreshAllowedDuringDrain: false,
  });
  const bootstrapObservedAt = Date.now() - 25;
  const stagingCandidateBinding = {
    environmentIdentityDigest: STAGING_ENVIRONMENT_IDENTITY,
    canonicalName: CANONICAL_NAME,
    clientId: stagingClient.client_id,
    bindingId: staging.binding.bindingId,
    installationEpoch: 1,
    state: "ACTIVATION_PREPARED" as const,
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
    toolDiscoveryEvidenceDigest: digest(`staging-tools-${label}`),
    r0Canary: {
      tool: "target",
      operation: "list",
      argumentsDigest: digest(`staging-r0-args-${label}`),
      resourceDigest: digest(`staging-r0-resource-${label}`),
      providerDispatchCount: 1,
      readbackDigest: digest(`staging-r0-readback-${label}`),
    },
    observedAtMs: bootstrapObservedAt,
    expiresAtMs: bootstrapObservedAt + 110_000,
  };
  const stagingPrecheckEnvelope = signConnectorActivationStagingPrecheck(
    stagingPrecheckPayload,
    key,
    bootstrapObservedAt,
  );
  const verifiedStagingPrecheck = verifyConnectorActivationStagingPrecheck(
    stagingPrecheckEnvelope,
    key,
    {
      principalKeyFingerprint: OWNER_PRINCIPAL,
      managementNonce: MANAGEMENT_NONCE,
      managementCorrelationId: MANAGEMENT_CORRELATION_ID,
      candidateIdentity,
      stagingRouteIdentityDigest: STAGING_ROUTE_IDENTITY,
      stagingCandidateBinding,
    },
    bootstrapObservedAt,
  );
  const stagingActivated = stagingStore.activatePreparedConnector(
    stagingPrepared.receiptId,
    staging.tuple,
    directActivationProof(
      stagingPrepared,
      OWNER_PRINCIPAL,
      `staging-${label}`,
      connectorStagingActivationPlanDigest(stagingPrepared, verifiedStagingPrecheck),
    ),
  );
  const stagingAuthority = stagingStore.getActivationAuthorityReceipt(stagingPrepared.receiptId)!;
  const stagingActive = stagingStore.getConnectorBinding(staging.binding.bindingId)!;
  const embeddedStagingReceipt: ConnectorActivationReceipt = {
    receiptId: stagingActivated.receiptId,
    tuple: stagingActivated.tuple,
    tupleDigest: stagingActivated.tupleDigest,
    preimageDigest: stagingActivated.preimageDigest,
    activationAuthority: stagingAuthority,
    ownerAuthorityId: stagingAuthority.authorityId,
    drainDeadlineAt: stagingActivated.drainDeadlineAt,
    refreshAllowedDuringDrain: stagingActivated.refreshAllowedDuringDrain,
    status: "ACTIVATED",
    preparedAt: stagingActivated.preparedAt,
    activatedAt: stagingActivated.activatedAt!,
    ...(stagingActivated.previousActiveBindingId
      ? { previousActiveBindingId: stagingActivated.previousActiveBindingId }
      : {}),
  };
  const stagingTokenFamilyId = `staging-family-${label}`;
  saveBoundTokenFamily(stagingStore, stagingActive, stagingTokenFamilyId);
  stagingStore.close();

  const stagingActivatedAtMs = Date.parse(stagingActivated.activatedAt!);
  await delayUntil(stagingActivatedAtMs + 5);
  const preObservedAt = Date.now();
  const stagingBinding: ConnectorActivationStagingBindingIdentity = {
    ...stagingCandidateBinding,
    state: "ACTIVE",
  };
  const preEnvelope = signConnectorActivationPreCutoverHostCanary({
    stage: "PRE_CUTOVER_HOST_CANARY",
    preCutoverHostCanaryId: `pre-cutover-${label}`,
    managementNonce: MANAGEMENT_NONCE,
    managementCorrelationId: MANAGEMENT_CORRELATION_ID,
    principalKeyFingerprint: OWNER_PRINCIPAL,
    hostProvider: "chatgpt",
    actualHost: true,
    candidateIdentity,
    stagingRouteIdentityDigest: STAGING_ROUTE_IDENTITY,
    stagingBinding,
    stagingActivationPrecheckDigest: stagingPrecheckEnvelope.payloadDigest,
    stagingActivationReceipt: embeddedStagingReceipt,
    stagingActivationAuthorityReceipt: stagingAuthority,
    stagingActivationReceiptId: embeddedStagingReceipt.receiptId,
    stagingActivationReceiptDigest: connectorActivationReceiptDigest(embeddedStagingReceipt),
    stagingActivationProofDigest: stagingAuthority.proofDigest,
    stagingActivationAuthorityReceiptDigest: connectorActivationAuthorityReceiptDigest(stagingAuthority),
    stagingActivatedAtMs,
    stagingActiveTuple: stagingActivated.tuple,
    stagingTokenFamilyIdDigest: digest(stagingTokenFamilyId),
    stagingTokenFamilyBindingId: stagingActive.bindingId,
    discoveredToolNames: UNIVERSAL_TOOL_NAMES,
    toolDiscoveryEvidenceDigest: digest(`pre-tools-${label}`),
    mutation: mutationEvidence(`pre-${label}`, stagingActivatedAtMs + 1, preObservedAt),
    foreignClientIsolation: foreignIsolation(`pre-${label}`, stagingClient.client_id),
    observedAtMs: preObservedAt,
    expiresAtMs: preObservedAt + 110_000,
  }, key, preObservedAt);

  const productionObservedAt = Date.now();
  const evidenceBinding = {
    principalKeyFingerprint: OWNER_PRINCIPAL,
    receiptId: prepared.receiptId,
    canonicalName: prepared.tuple.canonicalName,
    tupleDigest: prepared.tupleDigest,
    activePreimageDigest: prepared.preimageDigest,
    finalizationPlanDigest: connectorActivationFinalizationPlanDigest(prepared),
  };
  const productionPrecheckPayload: ConnectorActivationProductionPrecheckPayload = {
    ...evidenceBinding,
    stage: "PRODUCTION_ACTIVATION_PRECHECK",
    productionActivationPrecheckId: `production-precheck-${label}`,
    managementCorrelationId: MANAGEMENT_CORRELATION_ID,
    tuple: prepared.tuple,
    oauthResource: OAUTH_RESOURCE,
    oauthScopes: UNIVERSAL_OWNER_SCOPES,
    candidateIdentity,
    preCutoverHostCanaryDigest: preEnvelope.payloadDigest,
    stagingBinding,
    stagingRouteIdentityDigest: STAGING_ROUTE_IDENTITY,
    productionEnvironmentIdentityDigest: PRODUCTION_ENVIRONMENT_IDENTITY,
    productionRouteIdentityDigest: PRODUCTION_ROUTE_IDENTITY,
    stagingProductionBindingRelation: "DISTINCT_STAGING_BINDING",
    observedAtMs: productionObservedAt,
    expiresAtMs: productionObservedAt + 110_000,
  };
  const productionPrecheckEnvelope = signConnectorActivationProductionPrecheck(
    productionPrecheckPayload,
    key,
    productionObservedAt,
  );
  const approvedAtMs = Date.now();
  const ownerPayload: ConnectorActivationOwnerApprovalPayload = {
    ...evidenceBinding,
    approvalId: `owner-approval-${label}`,
    authorityText: "Activate this exact production candidate after both signed Host stages pass.",
    preCutoverHostCanaryDigest: preEnvelope.payloadDigest,
    productionActivationPrecheckDigest: productionPrecheckEnvelope.payloadDigest,
    evidenceDigest: digest(`owner-evidence-${label}`),
    approvedAtMs,
    expiresAtMs: approvedAtMs + 110_000,
  };
  const ownerEnvelope = signConnectorActivationOwnerApproval(ownerPayload, key, approvedAtMs);

  const artifactDir = join(root, "artifacts");
  const stagingPrecheckArtifact = await artifact(
    join(artifactDir, "staging-precheck.json"),
    stagingPrecheckEnvelope,
  );
  const preArtifact = await artifact(join(artifactDir, "pre.json"), preEnvelope);
  const productionPrecheckArtifact = await artifact(
    join(artifactDir, "production-precheck.json"),
    productionPrecheckEnvelope,
  );
  const ownerArtifact = await artifact(join(artifactDir, "owner.json"), ownerEnvelope);
  const journalPath = join(root, "control-plane", "connector-journal.sqlite");
  const journal = new SqliteConnectorActivationRecoveryJournal({ storePath: journalPath });
  const journalIdentity = journal.identity();
  journal.close();

  const challengePath = join(artifactDir, "post-challenge.json");
  const challenge = {
    schemaVersion: 1,
    kind: "POST_ACTIVATION_CHALLENGE",
    managementNonce: MANAGEMENT_NONCE,
    managementCorrelationId: MANAGEMENT_CORRELATION_ID,
    productionEnvironmentIdentityDigest: PRODUCTION_ENVIRONMENT_IDENTITY,
    productionRouteIdentityDigest: PRODUCTION_ROUTE_IDENTITY,
    candidateIdentity,
  };
  const challengeArtifact = await artifact(challengePath, challenge);
  const server = createReadbackServer(
    runtimeIdentity,
    prepared.tuple.candidateBindingId,
    candidateIdentity,
    managementAuthorizationHeader(key),
  );
  await listen(server);
  const address = server.address();
  assert.ok(address && typeof address === "object");
  const baseUrl = `http://127.0.0.1:${address.port}`;

  return {
    root,
    key,
    prepared,
    candidateIdentity,
    stagingPrecheckEnvelope,
    preEnvelope,
    productionPrecheckEnvelope,
    ownerEnvelope,
    ...(oldTokenFamilyId ? { oldTokenFamilyId } : {}),
    server,
    configuration: {
      oauthDatabasePath: join(oauthDir, "devspace.sqlite"),
      authorityDatabasePath: join(root, "authority.sqlite"),
      managementAuthorizationKeyRef: key.path,
      managementNonce: MANAGEMENT_NONCE,
      managementCorrelationId: MANAGEMENT_CORRELATION_ID,
      candidateIdentity,
      productionEnvironmentIdentityDigest: PRODUCTION_ENVIRONMENT_IDENTITY,
      productionRouteIdentityDigest: PRODUCTION_ROUTE_IDENTITY,
      oauthResource: OAUTH_RESOURCE,
      activation: {
        receiptId: prepared.receiptId,
        tupleDigest: prepared.tupleDigest,
        activePreimageDigest: prepared.preimageDigest,
        finalizationPlanDigest: connectorActivationFinalizationPlanDigest(prepared),
      },
      stagingActivationPrecheck: stagingPrecheckArtifact,
      preCutoverHostCanary: preArtifact,
      productionActivationPrecheck: productionPrecheckArtifact,
      ownerApproval: ownerArtifact,
      journal: { path: journalPath, identity: journalIdentity },
      postActivation: {
        challengePath,
        challengeSha256: challengeArtifact.sha256,
        receiptPath: join(artifactDir, "post-receipt.json"),
        deadlineAt: new Date(Date.now() + 110_000).toISOString(),
        pollIntervalMs: 10,
        runtimeIdentityUrl: `${baseUrl}/readyz`,
        routeIdentityUrl: `${baseUrl}/route-identityz`,
      },
    },
  };
}

async function installPostReadback(
  fixture: LifecycleFixture,
): Promise<SignedConnectorActivationEvidence<ConnectorActivationPostActivationHostCanaryPayload>> {
  const oauthStore = new SqliteOAuthStore(join(fixture.root, "oauth"));
  const receipt = oauthStore.getActivationReceipt(fixture.prepared.receiptId)!;
  const authorityReceipt = oauthStore.getActivationAuthorityReceipt(fixture.prepared.receiptId)!;
  const active = oauthStore.getConnectorBinding(receipt.tuple.candidateBindingId)!;
  const familyId = `new-family-${fixture.prepared.receiptId}`;
  saveBoundTokenFamily(oauthStore, active, familyId);
  oauthStore.close();

  const activatedAtMs = Date.parse(receipt.activatedAt!);
  await delayUntil(activatedAtMs + 5);
  const registry = new OperationAuthorityRegistry({
    storePath: fixture.configuration.authorityDatabasePath,
    instanceId: `post-evidence-${process.pid}-${Date.now()}`,
  });
  const descriptor = authorityActionFromToolCall("fs", {
    operation: "write",
    target: "local",
    path: `/tmp/lifecycle-post-${fixture.prepared.receiptId}`,
    content: "post-canary\n",
  });
  const created = registry.create({
    taskId: `post-host-${fixture.prepared.receiptId}`,
    authorityText: "Authorize this exact harmless production POST canary mutation.",
    actions: [{ descriptor }],
  }, OWNER_PRINCIPAL);
  const authorityId = String(created.authorityId);
  const dispatch = registry.prepareDispatch(
    authorityId,
    OWNER_PRINCIPAL,
    descriptor,
    minimumAuthorityRisk(descriptor),
  );
  const grant = dispatch.claim();
  dispatch.markDispatched();
  const completion = dispatch.complete("PASS", { reasonCode: "POST_HOST_CANARY" });
  registry.close();

  const observedAtMs = Math.max(Date.now(), activatedAtMs + 5);
  const sessionAAuthorizedAtMs = activatedAtMs + 1;
  const sessionAClosedAtMs = activatedAtMs + 2;
  const sessionBMutationAtMs = Math.max(sessionAClosedAtMs + 1, grant.dispatchedAtMs ?? grant.claimedAtMs);
  const previousActiveBindingId = receipt.previousActiveBindingId ?? null;
  const payload: ConnectorActivationPostActivationHostCanaryPayload = {
    stage: "POST_ACTIVATION_HOST_CANARY",
    postActivationHostCanaryId: `post-host-${fixture.prepared.receiptId}`,
    managementNonce: MANAGEMENT_NONCE,
    managementCorrelationId: MANAGEMENT_CORRELATION_ID,
    principalKeyFingerprint: OWNER_PRINCIPAL,
    hostProvider: "chatgpt",
    actualHost: true,
    precheckDigest: fixture.productionPrecheckEnvelope.payloadDigest,
    activationReceiptId: receipt.receiptId,
    activationReceiptDigest: connectorActivationReceiptDigest(receipt),
    activationProofDigest: authorityReceipt.proofDigest,
    activationAuthorityReceiptDigest: connectorActivationAuthorityReceiptDigest(authorityReceipt),
    activatedAtMs,
    newActiveTuple: receipt.tuple,
    newActiveBindingState: "ACTIVE",
    tokenFamilyIdDigest: digest(familyId),
    tokenFamilyBindingId: active.bindingId,
    previousActiveBindingId,
    previousBindingState: previousActiveBindingId ? "DRAINING" : "ABSENT",
    productionIdentity: fixture.candidateIdentity,
    productionEnvironmentIdentityDigest: PRODUCTION_ENVIRONMENT_IDENTITY,
    productionRouteIdentityDigest: PRODUCTION_ROUTE_IDENTITY,
    discoveredToolNames: UNIVERSAL_TOOL_NAMES,
    toolDiscoveryEvidenceDigest: digest(`post-tools-${fixture.prepared.receiptId}`),
    mutation: {
      tool: "fs",
      operation: "write",
      argumentsDigest: digest(`post-arguments-${fixture.prepared.receiptId}`),
      resourceDigest: digest(`post-resource-${fixture.prepared.receiptId}`),
      sessionAIdDigest: digest(`post-session-a-${fixture.prepared.receiptId}`),
      sessionAAuthorizationEvidenceDigest: digest(`post-session-a-authority-${fixture.prepared.receiptId}`),
      sessionAAuthorizedAtMs,
      sessionACloseEvidenceDigest: digest(`post-session-a-close-${fixture.prepared.receiptId}`),
      sessionAClosedAtMs,
      sessionBIdDigest: digest(`post-session-b-${fixture.prepared.receiptId}`),
      sessionBMutationEvidenceDigest: digest(`post-session-b-mutation-${fixture.prepared.receiptId}`),
      sessionBMutationAtMs,
      actionFingerprint: actionFingerprint(descriptor),
      resourceKeySha256: actionResourceKeySha256(descriptor),
      authorityId,
      actionClaimId: completion.actionClaimId,
      fencingToken: grant.fencingToken,
      authorityReceiptDigest: completion.receiptDigest,
      providerDispatchCount: 1,
      postReadbackDigest: digest(`post-readback-${fixture.prepared.receiptId}`),
      cleanupPerformed: true,
      cleanupEvidenceDigest: digest(`post-cleanup-${fixture.prepared.receiptId}`),
    },
    foreignClientIsolation: foreignIsolation(
      `post-${fixture.prepared.receiptId}`,
      receipt.tuple.clientId,
    ),
    observedAtMs: Math.max(observedAtMs, sessionBMutationAtMs),
    expiresAtMs: Math.max(observedAtMs, sessionBMutationAtMs) + 110_000,
  };
  const envelope = signConnectorActivationPostActivationHostCanary(
    payload,
    fixture.key,
    payload.observedAtMs,
  );
  await writeOwnerJson(fixture.configuration.postActivation.receiptPath, envelope);
  return envelope;
}

function verifiedCandidate(
  store: SqliteOAuthStore,
  clientId: string,
  installationEpoch: number,
  label: string,
): { binding: ConnectorBindingRecord; tuple: ConnectorActivationTuple } {
  const identity: ConnectorActivationImmutableCandidateIdentity = {
    runtimeIdentityDigest: digest(`unused-runtime-${label}`),
    buildDigest: digest(`build-${label}`),
    schemaGeneration: digest(`schema-${label}`),
    authorityContractGeneration: digest(`authority-${label}`),
    buildCapabilityManifestDigest: digest(`unused-capability-${label}`),
    generatedSchemaDigest: digest(`unused-generated-${label}`),
    packageSha256: digest(`unused-package-${label}`),
  };
  return verifiedCandidateWithIdentity(store, clientId, installationEpoch, identity, label);
}

function verifiedCandidateWithIdentity(
  store: SqliteOAuthStore,
  clientId: string,
  installationEpoch: number,
  identity: ConnectorActivationImmutableCandidateIdentity,
  label: string,
): { binding: ConnectorBindingRecord; tuple: ConnectorActivationTuple } {
  const input = {
    canonicalName: CANONICAL_NAME,
    clientId,
    installationEpoch,
    schemaGeneration: identity.schemaGeneration,
  };
  const binding = store.ensureCandidateConnectorBinding(input);
  const evidence = {
    authorityContractGeneration: identity.authorityContractGeneration,
    redirectUrisDigest: digest(`redirect-${label}`),
    buildDigest: identity.buildDigest,
  };
  store.markConnectorBindingVerified(binding.bindingId, evidence);
  return { binding, tuple: { ...input, candidateBindingId: binding.bindingId, ...evidence } };
}

function directActivationProof(
  receipt: ConnectorActivationReceipt,
  principalKeyFingerprint: string,
  label: string,
  finalizationPlanDigest = digest(`direct-plan-${label}`),
): ConnectorActivationAuthorityProof {
  const binding = {
    receiptId: receipt.receiptId,
    tupleDigest: receipt.tupleDigest,
    activePreimageDigest: receipt.preimageDigest,
    finalizationPlanDigest,
    canonicalName: receipt.tuple.canonicalName,
  };
  const claimedAtMs = Date.now() - 2;
  return {
    schemaVersion: 1,
    authorityId: `authority_${uuid(label, "authority")}`,
    actionClaimId: `authority_claim_${uuid(label, "claim")}`,
    actionFingerprint: connectorActivationAuthorityActionFingerprint(binding),
    resourceKeySha256: connectorActivationAuthorityResourceKeySha256(binding),
    fencingToken: label.startsWith("old-") ? 999 : 1,
    principalKeyFingerprint,
    risk: "R3",
    claimState: "DISPATCHED",
    approvalAssurance: "cooperative",
    ...binding,
    evidenceDigest: digest(`direct-evidence-${label}`),
    claimedAtMs,
    dispatchedAtMs: claimedAtMs + 1,
  };
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

function mutationEvidence(
  label: string,
  sessionAAuthorizedAtMs: number,
  observedAtMs: number,
): ConnectorActivationCanaryMutationEvidence {
  const sessionAClosedAtMs = sessionAAuthorizedAtMs + 1;
  return {
    tool: "context",
    operation: "create",
    argumentsDigest: digest(`${label}-arguments`),
    resourceDigest: digest(`${label}-resource`),
    sessionAIdDigest: digest(`${label}-session-a`),
    sessionAAuthorizationEvidenceDigest: digest(`${label}-session-a-authority`),
    sessionAAuthorizedAtMs,
    sessionACloseEvidenceDigest: digest(`${label}-session-a-close`),
    sessionAClosedAtMs,
    sessionBIdDigest: digest(`${label}-session-b`),
    sessionBMutationEvidenceDigest: digest(`${label}-session-b-mutation`),
    sessionBMutationAtMs: Math.min(observedAtMs, sessionAClosedAtMs + 1),
    actionFingerprint: rawDigest(`${label}-action`),
    resourceKeySha256: rawDigest(`${label}-resource-key`),
    authorityId: `authority_${uuid(label, "canary-authority")}`,
    actionClaimId: `authority_claim_${uuid(label, "canary-claim")}`,
    fencingToken: 1,
    authorityReceiptDigest: digest(`${label}-authority-receipt`),
    providerDispatchCount: 1,
    postReadbackDigest: digest(`${label}-readback`),
    cleanupPerformed: true,
    cleanupEvidenceDigest: digest(`${label}-cleanup`),
  };
}

function foreignIsolation(
  label: string,
  activeClientId: string,
): ConnectorActivationForeignClientIsolationEvidence {
  return {
    clientId: `${activeClientId}-foreign-${label}`,
    principalKeyFingerprint: rawDigest(`foreign-principal-${label}`),
    errorCode: "AUTHORITY_PRINCIPAL_MISMATCH",
    providerDispatchCount: 0,
    evidenceDigest: digest(`foreign-evidence-${label}`),
  };
}

function createReadbackServer(
  runtimeIdentity: Record<string, unknown>,
  bindingId: string,
  candidateIdentity: ConnectorActivationImmutableCandidateIdentity,
  expectedAuthorizationHeader: string,
): Server {
  return createServer((request, response) => {
    response.setHeader("content-type", "application/json");
    if (request.headers.authorization !== expectedAuthorizationHeader) {
      response.statusCode = 401;
      response.end("{}");
      return;
    }
    if (request.url === "/readyz") {
      response.end(JSON.stringify(runtimeIdentity));
      return;
    }
    if (request.url === "/route-identityz") {
      response.end(JSON.stringify({
        schemaVersion: 1,
        state: "ACTIVE",
        routeCount: 1,
        canonicalName: CANONICAL_NAME,
        bindingId,
        runtimeIdentityDigest: candidateIdentity.runtimeIdentityDigest,
        productionEnvironmentIdentityDigest: PRODUCTION_ENVIRONMENT_IDENTITY,
        productionRouteIdentityDigest: PRODUCTION_ROUTE_IDENTITY,
      }));
      return;
    }
    response.statusCode = 404;
    response.end("{}");
  });
}

async function listen(server: Server): Promise<void> {
  await new Promise<void>((resolvePromise, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", () => resolvePromise());
  });
}

async function artifact(path: string, value: unknown): Promise<{ path: string; sha256: string }> {
  await writeOwnerJson(path, value);
  return { path, sha256: digest(await readFile(path)) };
}

async function writeOwnerJson(path: string, value: unknown): Promise<void> {
  await mkdir(join(path, ".."), { recursive: true, mode: 0o700 });
  await writeFile(path, `${JSON.stringify(value)}\n`, { mode: 0o600, flag: "w" });
  await chmod(path, 0o600);
}

async function replaceArtifact(
  path: string,
  value: unknown,
  binding: { sha256: string },
): Promise<void> {
  await writeOwnerJson(path, value);
  binding.sha256 = digest(await readFile(path));
}

function rawSign<T>(
  kind: SignedConnectorActivationEvidence<T>["kind"],
  payload: T,
  key: ManagementAuthorizationKey,
): SignedConnectorActivationEvidence<T> {
  const canonicalPayload = JSON.parse(JSON.stringify(payload)) as T;
  const envelopeIdentity = {
    schemaVersion: 2 as const,
    kind,
    keyId: key.keyId,
    payload: canonicalPayload,
  };
  const canonical = stableJson(envelopeIdentity);
  return {
    ...envelopeIdentity,
    payloadDigest: digest(canonical),
    signature: createHmac("sha256", key.secret)
      .update(`devspace.connector-activation-evidence.v2/${kind}\0`)
      .update(canonical)
      .digest("base64url"),
  };
}

function omitNested(
  value: ConnectorActivationPostActivationHostCanaryPayload,
  outer: "mutation",
  key: keyof ConnectorActivationPostActivationHostCanaryPayload["mutation"],
): Record<string, unknown> {
  const clone = structuredClone(value) as unknown as Record<string, unknown>;
  delete (clone[outer] as Record<string, unknown>)[key];
  return clone;
}

function assertNoActivationDispatch(fixture: LifecycleFixture): void {
  const oauth = new SqliteOAuthStore(join(fixture.root, "oauth"));
  assert.equal(oauth.getActivationReceipt(fixture.prepared.receiptId)?.status, "PREPARED");
  assert.equal(oauth.getActivationAuthorityReceipt(fixture.prepared.receiptId), undefined);
  oauth.close();
  const journal = new Database(fixture.configuration.journal.path, { readonly: true });
  const count = journal.prepare("select count(*) as count from connector_activation_journal_entries")
    .get() as { count: number };
  journal.close();
  assert.equal(count.count, 0);
}

function assertPostNotVerified(fixture: LifecycleFixture): void {
  const journal = new Database(fixture.configuration.journal.path, { readonly: true });
  const count = journal.prepare(
    "select count(*) as count from connector_activation_journal_outcomes where state = 'POST_ACTIVATION_VERIFIED'",
  ).get() as { count: number };
  journal.close();
  assert.equal(count.count, 0);
}

function activationCounts(fixture: LifecycleFixture): Record<string, number> {
  const oauth = new Database(fixture.configuration.oauthDatabasePath, { readonly: true });
  const oauthCount = oauth.prepare(
    "select count(*) as count from oauth_connector_activation_authorities where receipt_id = ?",
  ).get(fixture.prepared.receiptId) as { count: number };
  oauth.close();
  const journal = new Database(fixture.configuration.journal.path, { readonly: true });
  const transitions = journal.prepare(
    "select count(*) as count from connector_activation_journal_transitions where receipt_id = ?",
  ).get(fixture.prepared.receiptId) as { count: number };
  journal.close();
  return { oauth: oauthCount.count, transitions: transitions.count };
}

async function cleanupFixture(fixture: LifecycleFixture): Promise<void> {
  await new Promise<void>((resolvePromise) => fixture.server.close(() => resolvePromise()));
  await rm(fixture.root, { recursive: true, force: true });
}

async function delayUntil(timestampMs: number): Promise<void> {
  const remaining = timestampMs - Date.now();
  if (remaining > 0) await new Promise((resolvePromise) => setTimeout(resolvePromise, remaining));
}

function uuid(...parts: string[]): string {
  const hex = rawDigest(parts.join("\0")).slice(0, 32);
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-4${hex.slice(13, 16)}-8${hex.slice(17, 20)}-${hex.slice(20)}`;
}

function tupleDigest(tuple: ConnectorActivationTuple): string {
  return connectorActivationTupleDigest(tuple);
}

function digestJson(value: unknown): string {
  return digest(stableJson(value));
}

function digest(value: string | Uint8Array): string {
  return `sha256:${createHash("sha256").update(value).digest("hex")}`;
}

function rawDigest(value: string): string {
  return createHash("sha256").update(value).digest("hex");
}

function stableJson(value: unknown): string {
  return JSON.stringify(canonical(value));
}

function canonical(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(canonical);
  if (!value || typeof value !== "object") return value;
  return Object.fromEntries(
    Object.entries(value as Record<string, unknown>)
      .sort(([left], [right]) => left < right ? -1 : left > right ? 1 : 0)
      .map(([key, item]) => [key, canonical(item)]),
  );
}
