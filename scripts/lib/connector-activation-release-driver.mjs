import {
  createHash,
  createHmac,
  randomBytes,
  randomUUID,
  timingSafeEqual,
} from "node:crypto";
import {
  constants,
  closeSync,
  existsSync,
  fstatSync,
  fsyncSync,
  linkSync,
  lstatSync,
  mkdirSync,
  openSync,
  readdirSync,
  readFileSync,
  realpathSync,
  renameSync,
  rmdirSync,
  unlinkSync,
  writeFileSync,
} from "node:fs";
import { dirname, isAbsolute, join, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import Database from "better-sqlite3";
import { treeEvidence } from "./release-artifacts.mjs";
import { readFinalizationStoreIdentity } from "./finalization-store-contract.mjs";
import {
  connectorRollbackHealthReadbackDigest,
  connectorRollbackReadyReadbackDigest,
  connectorRollbackRuntimeReadbackDigest,
  signConnectorRollbackHostChallenge,
  signConnectorRollbackHostReceipt,
  verifyConnectorRollbackHostChallenge,
  verifyConnectorRollbackHostReceipt,
} from "./connector-rollback-evidence.mjs";

const SHA256 = /^sha256:[a-f0-9]{64}$/u;
const RAW_SHA256 = /^[a-f0-9]{64}$/u;
const SAFE_ID = /^[A-Za-z0-9][A-Za-z0-9._:@/-]{0,511}$/u;
const MAX_LEDGER_BYTES = 64 * 1024 * 1024;
const MAX_JSON_BYTES = 16 * 1024 * 1024;
const HOST_SOURCE = "CHATGPT_HOST";
const BROKER_SOURCE = "DEVSPACE_BROKER";
const EXPECTED_TOOLS = Object.freeze([
  "target", "context", "fs", "exec", "process", "mcp", "artifact", "gui",
]);
const EXPECTED_SCOPES = Object.freeze([
  "devspace.read", "devspace.write", "devspace.exec", "devspace.mcp",
  "devspace.artifact", "devspace.gui",
]);
const EVIDENCE_LIFETIME_MS = 120_000;
const PREDECISION_DOMAIN =
  "devspace.connector-activation-release-driver.v1/PRODUCTION_ACTIVATION_PREDECISION\0";
const ROLLBACK_CHALLENGE_LIFETIME_MS = 30 * 60_000;
const GENERATED_SCHEMA_FILES = Object.freeze([
  "config.schema.json",
  "config/config.schema.json",
  "contracts/tools-v2.schema.json",
  "contracts/build-capabilities.schema.json",
]);

const COMMON_REQUEST_KEYS = ["artifacts", "management", "operation", "schemaVersion", "selection", "stores"];
const MANAGEMENT_KEYS = ["keyRef", "stateDir"];
const COMMON_STORE_KEYS = ["auditLogPath", "brokerLedgerPath", "hostLedgerPath", "oauthDatabasePath"];
const STAGING_SELECTOR_KEYS = [
  "candidateReadbackRecordId",
  "expectedDiscoveryTranscriptDigest",
  "expectedResourceDigest",
  "expectedR0TranscriptDigest",
  "hostObservationRecordId",
];
const CANARY_SELECTOR_KEYS = [
  "candidateReadbackRecordId",
  "expectedAuthorizationTranscriptDigest",
  "expectedCloseTranscriptDigest",
  "expectedDiscoveryTranscriptDigest",
  "expectedForeignTranscriptDigest",
  "expectedMutationTranscriptDigest",
  "expectedResourceDigest",
  "hostObservationRecordId",
];

export class ConnectorActivationReleaseDriver {
  constructor({
    runtime,
    now = Date.now,
    finalizationIdentityReader = readFinalizationStoreIdentity,
  } = {}) {
    this.runtime = assertRuntime(runtime);
    this.now = now;
    if (typeof finalizationIdentityReader !== "function") {
      throw new Error("Finalization identity reader is required.");
    }
    this.finalizationIdentityReader = finalizationIdentityReader;
  }

  createStagingActivationPrecheck(request) {
    validateRequestEnvelope(request, "STAGING_PRECHECK", COMMON_STORE_KEYS, STAGING_SELECTOR_KEYS, []);
    const key = loadManagementAuthorizationKey(this.runtime, request.management);
    const context = this.#deriveStagingPrecheckContext(request);
    const observedAtMs = context.host.occurredAtMs;
    const payload = {
      stage: "STAGING_ACTIVATION_PRECHECK",
      stagingActivationPrecheckId: context.host.payload.stagingActivationPrecheckId,
      managementNonce: context.host.payload.managementNonce,
      managementCorrelationId: context.host.payload.managementCorrelationId,
      principalKeyFingerprint: context.principalKeyFingerprint,
      hostProvider: "chatgpt",
      actualHost: true,
      candidateIdentity: context.candidate.payload.candidateIdentity,
      stagingRouteIdentityDigest: context.candidate.payload.routeIdentityDigest,
      stagingCandidateBinding: stagingBindingIdentity(context.candidate.payload, "ACTIVATION_PREPARED"),
      discoveredToolNames: [...EXPECTED_TOOLS],
      toolDiscoveryEvidenceDigest: context.toolDiscoveryEvidenceDigest,
      r0Canary: context.r0Canary,
      observedAtMs,
      expiresAtMs: observedAtMs + EVIDENCE_LIFETIME_MS,
    };
    const evidence = this.runtime.signConnectorActivationStagingPrecheck(payload, key, this.now());
    this.runtime.verifyConnectorActivationStagingPrecheck(evidence, key, {
      principalKeyFingerprint: context.principalKeyFingerprint,
      managementNonce: payload.managementNonce,
      managementCorrelationId: payload.managementCorrelationId,
      candidateIdentity: payload.candidateIdentity,
      stagingRouteIdentityDigest: payload.stagingRouteIdentityDigest,
      stagingCandidateBinding: payload.stagingCandidateBinding,
    }, this.now());
    return evidence;
  }

  activateStagingConnector(request) {
    validateRequestEnvelope(
      request,
      "STAGING_ACTIVATE",
      [...COMMON_STORE_KEYS, "authorityDatabasePath", "journalPath", "oauthStateDir"],
      [...STAGING_SELECTOR_KEYS, "ownerApprovalDecisionRecordId"],
      ["stagingPrecheckPath"],
    );
    assertOAuthStateDirectory(request.stores.oauthStateDir, request.stores.oauthDatabasePath);
    const key = loadManagementAuthorizationKey(this.runtime, request.management);
    const context = this.#deriveStagingPrecheckContext(request);
    const precheckArtifact = readSignedEvidence(
      request.artifacts.stagingPrecheckPath,
      "STAGING_ACTIVATION_PRECHECK",
    );
    const stagingPrecheck = this.runtime.verifyConnectorActivationStagingPrecheck(
      precheckArtifact,
      key,
      stagingPrecheckExpected(context),
      this.now(),
    );
    const oauthReader = new OAuthActivationReadAdapter(request.stores.oauthDatabasePath, this.runtime);
    let receipt;
    try {
      const binding = oauthReader.requireBinding(context.candidate.payload.bindingId);
      assertBindingMatchesCandidateRecord(binding, context.candidate.payload, "ACTIVATION_PREPARED");
      receipt = oauthReader.requireActivationReceipt(context.candidate.payload.receiptId);
      assertPreparedReceiptMatchesBinding(receipt, binding, this.runtime);
    } finally {
      oauthReader.close();
    }
    const approvalBinding = this.runtime.connectorStagingActivationOwnerApprovalBinding(
      receipt,
      stagingPrecheck,
      context.principalKeyFingerprint,
    );
    const conditionsDigest = digestJson({
      schemaVersion: 1,
      stage: "STAGING_ACTIVATION",
      stagingActivationPrecheckDigest: stagingPrecheck.signedPayloadDigest,
      ...approvalBinding,
    });
    const broker = new EvidenceLedger(request.stores.brokerLedgerPath, BROKER_SOURCE, this.runtime);
    const decision = broker.require(request.selection.ownerApprovalDecisionRecordId, "OWNER_APPROVAL_DECISION");
    assertOwnerDecision(decision, "STAGING_ACTIVATION", context.host.payload.managementCorrelationId, conditionsDigest, this.now());
    const ownerEnvelope = this.runtime.signConnectorStagingActivationOwnerApproval({
      ...approvalBinding,
      approvalId: decision.payload.approvalId,
      authorityText: decision.payload.authorityText,
      evidenceDigest: digestJson({ decisionRecordId: decision.recordDigest, conditionsDigest }),
      approvedAtMs: decision.payload.approvedAtMs,
      expiresAtMs: decision.payload.expiresAtMs,
    }, key, this.now());
    const ownerApproval = this.runtime.verifyConnectorStagingActivationOwnerApproval(
      ownerEnvelope,
      key,
      approvalBinding,
      this.now(),
    );

    let oauthStore;
    let authorityRegistry;
    let journal;
    try {
      oauthStore = new this.runtime.SqliteOAuthStore(request.stores.oauthStateDir);
      authorityRegistry = new this.runtime.OperationAuthorityRegistry({
        storePath: ownerOnlyExistingPath(request.stores.authorityDatabasePath, "authority database"),
        instanceId: `connector-release-${decision.recordDigest.slice(7, 31)}`,
      });
      journal = new this.runtime.SqliteConnectorActivationRecoveryJournal({
        storePath: ownerOnlyExistingOrNewPath(request.stores.journalPath, "connector journal"),
      });
      const coordinator = new this.runtime.ConnectorStagingActivationCoordinator({
        oauthStore,
        authorityRegistry,
        recoveryJournal: journal,
        now: this.now,
      });
      const result = coordinator.activateOrReconcile({
        stagingActivationPrecheck: stagingPrecheck,
        authenticatedOwnerPrincipalKeyFingerprint: context.principalKeyFingerprint,
        ownerApproval,
      });
      if (result.state !== this.runtime.CONNECTOR_STAGING_ACTIVATION_OUTWARD_STATE) {
        throw new Error(`Staging activation did not reach ${this.runtime.CONNECTOR_STAGING_ACTIVATION_OUTWARD_STATE}.`);
      }
      return sealArtifact("STAGING_ACTIVATION", {
        stagingActivationPrecheckDigest: stagingPrecheck.signedPayloadDigest,
        ownerApproval: ownerEnvelope,
        state: result.state,
        finalizationPlanDigest: result.finalizationPlanDigest,
        evidenceDigest: result.evidenceDigest,
        activationReceipt: result.activationReceipt,
        activationAuthorityReceipt: result.activationAuthorityReceipt,
        authorityCompletionReceipt: result.authorityCompletionReceipt,
        stagingBinding: result.stagingBinding,
        recovery: result.recovery,
      });
    } finally {
      closeQuietly(journal);
      closeQuietly(authorityRegistry);
      closeQuietly(oauthStore);
    }
  }

  createPreCutoverHostCanary(request) {
    validateRequestEnvelope(
      request,
      "PRE_CUTOVER",
      [...COMMON_STORE_KEYS, "authorityDatabasePath"],
      ["canary", "stagingPrecheck"],
      ["stagingPrecheckPath"],
      { stagingPrecheck: STAGING_SELECTOR_KEYS, canary: CANARY_SELECTOR_KEYS },
    );
    const key = loadManagementAuthorizationKey(this.runtime, request.management);
    const stagingRequest = nestedSelectionRequest(request, "stagingPrecheck");
    const stagingContext = this.#deriveStagingPrecheckContext(stagingRequest, false);
    const stagingArtifact = readSignedEvidence(
      request.artifacts.stagingPrecheckPath,
      "STAGING_ACTIVATION_PRECHECK",
    );
    const stagingPrecheck = this.runtime.verifyConnectorActivationStagingPrecheck(
      stagingArtifact,
      key,
      stagingPrecheckExpected(stagingContext),
      this.now(),
    );
    const canary = this.#deriveHostCanaryContext(request, "PRE_CUTOVER_HOST_CANARY", stagingPrecheck);
    const payload = {
      stage: "PRE_CUTOVER_HOST_CANARY",
      preCutoverHostCanaryId: canary.host.payload.hostCanaryId,
      managementNonce: canary.host.payload.managementNonce,
      managementCorrelationId: canary.host.payload.managementCorrelationId,
      principalKeyFingerprint: canary.principalKeyFingerprint,
      hostProvider: "chatgpt",
      actualHost: true,
      candidateIdentity: canary.candidate.payload.candidateIdentity,
      stagingRouteIdentityDigest: canary.candidate.payload.routeIdentityDigest,
      stagingBinding: stagingBindingIdentity(canary.candidate.payload, "ACTIVE"),
      stagingActivationPrecheckDigest: stagingPrecheck.signedPayloadDigest,
      stagingActivationReceipt: canary.activationReceipt,
      stagingActivationAuthorityReceipt: canary.activationAuthorityReceipt,
      stagingActivationReceiptId: canary.activationReceipt.receiptId,
      stagingActivationReceiptDigest: this.runtime.connectorActivationReceiptDigest(canary.activationReceipt),
      stagingActivationProofDigest: canary.activationAuthorityReceipt.proofDigest,
      stagingActivationAuthorityReceiptDigest:
        this.runtime.connectorActivationAuthorityReceiptDigest(canary.activationAuthorityReceipt),
      stagingActivatedAtMs: Date.parse(canary.activationReceipt.activatedAt),
      stagingActiveTuple: canary.activationReceipt.tuple,
      stagingTokenFamilyIdDigest: canary.tokenFamilyIdDigest,
      stagingTokenFamilyBindingId: canary.tokenFamily.connectorBindingId,
      discoveredToolNames: [...EXPECTED_TOOLS],
      toolDiscoveryEvidenceDigest: canary.toolDiscoveryEvidenceDigest,
      mutation: canary.mutation,
      foreignClientIsolation: canary.foreignClientIsolation,
      observedAtMs: canary.host.occurredAtMs,
      expiresAtMs: canary.host.occurredAtMs + EVIDENCE_LIFETIME_MS,
    };
    const evidence = this.runtime.signConnectorActivationPreCutoverHostCanary(payload, key, this.now());
    this.runtime.verifyConnectorActivationPreCutoverHostCanary(evidence, key, {
      principalKeyFingerprint: canary.principalKeyFingerprint,
      managementNonce: payload.managementNonce,
      managementCorrelationId: payload.managementCorrelationId,
      candidateIdentity: payload.candidateIdentity,
      stagingRouteIdentityDigest: payload.stagingRouteIdentityDigest,
      stagingBinding: payload.stagingBinding,
      stagingActivationPrecheck: stagingPrecheck,
      stagingActivationReceipt: canary.activationReceipt,
      stagingActivationAuthorityReceipt: canary.activationAuthorityReceipt,
      stagingTokenFamilyIdDigest: canary.tokenFamilyIdDigest,
      stagingTokenFamilyBindingId: canary.tokenFamily.connectorBindingId,
    }, this.now());
    return evidence;
  }

  createProductionActivationPredecision(request) {
    validateRequestEnvelope(
      request,
      "PRODUCTION_PREDECISION",
      [...COMMON_STORE_KEYS, "finalizationControlPath", "finalizationStorePath", "journalPath", "oauthStateDir"],
      [
        "activeStagingCandidateReadbackRecordId", "candidateBindingId", "canonicalName",
        "drainDeadlineAt", "ownerApprovalDecisionRecordId", "productionCandidateReadbackRecordId",
        "refreshAllowedDuringDrain", "stagingPrecheck", "transactionId",
      ],
      [
        "preCutoverPath", "predecisionPath", "productionApprovalOutputDirectory",
        "productionPreparationRequestPath", "stagingPrecheckPath", "upgradeRequestPath",
      ],
      { stagingPrecheck: STAGING_SELECTOR_KEYS },
    );
    assertOAuthStateDirectory(request.stores.oauthStateDir, request.stores.oauthDatabasePath);
    assertProductionTransactionId(request.selection.transactionId);
    requiredText(request.selection.canonicalName, "production canonicalName", 128);
    requiredText(request.selection.candidateBindingId, "production candidateBindingId", 256);
    requiredIsoTimestamp(request.selection.drainDeadlineAt, "production drainDeadlineAt");
    if (typeof request.selection.refreshAllowedDuringDrain !== "boolean") {
      throw new Error("Production refreshAllowedDuringDrain must be boolean.");
    }
    const key = loadManagementAuthorizationKey(this.runtime, request.management);
    const stagingRequest = nestedSelectionRequest(request, "stagingPrecheck");
    const stagingContext = this.#deriveStagingPrecheckContext(stagingRequest, false);
    const stagingArtifact = readSignedEvidence(
      request.artifacts.stagingPrecheckPath,
      "STAGING_ACTIVATION_PRECHECK",
    );
    const stagingPrecheck = this.runtime.verifyConnectorActivationStagingPrecheck(
      stagingArtifact,
      key,
      stagingPrecheckExpected(stagingContext),
      this.now(),
    );
    const broker = new EvidenceLedger(request.stores.brokerLedgerPath, BROKER_SOURCE, this.runtime);
    const activeStaging = broker.require(
      request.selection.activeStagingCandidateReadbackRecordId,
      "CANDIDATE_READBACK",
    );
    assertEvidenceFresh(activeStaging, this.now(), EVIDENCE_LIFETIME_MS, "ACTIVE staging candidate readback");
    assertCandidateReadback(activeStaging.payload, "STAGING", "ACTIVE");
    const preArtifact = readSignedEvidence(
      request.artifacts.preCutoverPath,
      "PRE_CUTOVER_HOST_CANARY",
    );
    const preCutover = this.runtime.verifyPersistedConnectorActivationPreCutoverHostCanary(
      preArtifact,
      key,
      {
        principalKeyFingerprint: stagingPrecheck.principalKeyFingerprint,
        managementNonce: stagingPrecheck.managementNonce,
        managementCorrelationId: stagingPrecheck.managementCorrelationId,
        candidateIdentity: activeStaging.payload.candidateIdentity,
        stagingRouteIdentityDigest: activeStaging.payload.routeIdentityDigest,
        stagingBinding: stagingBindingIdentity(activeStaging.payload, "ACTIVE"),
        stagingActivationPrecheck: stagingPrecheck,
      },
      this.now(),
    );
    const productionCandidate = broker.require(
      request.selection.productionCandidateReadbackRecordId,
      "CANDIDATE_READBACK",
    );
    assertEvidenceFresh(productionCandidate, this.now(), EVIDENCE_LIFETIME_MS, "production candidate readback");
    assertCandidateReadback(productionCandidate.payload, "PRODUCTION", "VERIFIED");
    if (productionCandidate.payload.receiptId !== null) {
      throw new Error("Production VERIFIED candidate readback must not name an activation receipt.");
    }
    if (!objectsEqual(productionCandidate.payload.candidateIdentity, preCutover.candidateIdentity)) {
      throw new Error("Production immutable candidate identity does not match the verified staging canary.");
    }
    if (productionCandidate.payload.canonicalName !== request.selection.canonicalName
      || productionCandidate.payload.bindingId !== request.selection.candidateBindingId) {
      throw new Error("Production selection does not name the trusted candidate readback.");
    }

    const readonlyOAuth = new OAuthActivationReadAdapter(request.stores.oauthDatabasePath, this.runtime);
    let tuple;
    let expectedActivePreimageDigest;
    try {
      const binding = readonlyOAuth.requireBinding(productionCandidate.payload.bindingId);
      assertBindingMatchesCandidateRecord(binding, productionCandidate.payload, "VERIFIED");
      tuple = activationTupleFromBinding(binding);
      if (this.runtime.connectorActivationTupleDigest(tuple) !== digestActivationTuple(tuple)) {
        throw new Error("Production activation tuple canonical digest disagrees with the OAuth runtime.");
      }
      const active = readonlyOAuth.requireActiveBinding(request.selection.canonicalName);
      expectedActivePreimageDigest = oauthConnectorPreimageDigest(active);
      if (productionCandidate.payload.activePreimageDigest !== expectedActivePreimageDigest) {
        throw new Error("Production broker readback does not match the current canonical ACTIVE preimage.");
      }
    } finally {
      readonlyOAuth.close();
    }
    const tupleDigest = this.runtime.connectorActivationTupleDigest(tuple);
    const plan = {
      drainDeadlineAt: request.selection.drainDeadlineAt,
      refreshAllowedDuringDrain: request.selection.refreshAllowedDuringDrain,
    };
    const journalIdentity = readConnectorJournalIdentityReadonly(
      request.stores.journalPath,
      this.runtime,
    );
    const finalizationDraftIdentity = this.finalizationIdentityReader({
      storePath: ownerOnlyExistingPath(request.stores.finalizationStorePath, "finalization store"),
      controlPath: ownerOnlyExistingPath(request.stores.finalizationControlPath, "finalization control"),
      key,
    });
    assertFinalizationDraftIdentity(finalizationDraftIdentity, request.stores.finalizationStorePath);
    const artifactBindings = validateProductionPredecisionArtifactBindings(request.artifacts);
    const storeBindings = {
      oauthStateDir: ownerOnlyDirectory(request.stores.oauthStateDir, "OAuth state directory"),
      oauthDatabasePath: ownerOnlyExistingPath(request.stores.oauthDatabasePath, "OAuth database"),
      journalPath: ownerOnlyExistingPath(request.stores.journalPath, "connector journal"),
      finalizationStorePath: ownerOnlyExistingPath(
        request.stores.finalizationStorePath,
        "finalization store",
      ),
      finalizationControlPath: ownerOnlyExistingPath(
        request.stores.finalizationControlPath,
        "finalization control",
      ),
    };
    const approvalConditionsDigest = digestJson({
      schemaVersion: 1,
      stage: "PRODUCTION_ACTIVATION",
      transactionId: request.selection.transactionId,
      preCutoverHostCanaryDigest: preCutover.signedPayloadDigest,
      productionCandidateRecordId: productionCandidate.recordDigest,
      canonicalName: tuple.canonicalName,
      candidateBindingId: tuple.candidateBindingId,
      tuple,
      tupleDigest,
      activePreimageDigest: expectedActivePreimageDigest,
      plan,
      oauthResource: productionCandidate.payload.oauthResource,
      productionEnvironmentIdentityDigest: productionCandidate.payload.environmentIdentityDigest,
      productionRouteIdentityDigest: productionCandidate.payload.routeIdentityDigest,
      migrationManifestDigest: productionCandidate.payload.migrationManifestDigest,
      journalIdentity,
      finalizationDraftIdentity,
      productionApprovalOutputDirectory: artifactBindings.productionApprovalOutputDirectory,
    });
    const decision = broker.require(request.selection.ownerApprovalDecisionRecordId, "OWNER_APPROVAL_DECISION");
    assertOwnerDecision(
      decision,
      "PRODUCTION_ACTIVATION",
      preCutover.managementCorrelationId,
      approvalConditionsDigest,
      this.now(),
    );
    const relation = activeStaging.payload.bindingId === tuple.candidateBindingId
      && activeStaging.payload.clientId === tuple.clientId
      ? "IDENTICAL_BINDING_IDENTIFIERS_ISOLATED_STAGING"
      : "DISTINCT_STAGING_BINDING";
    const issuedAtMs = this.now();
    const expiresAtMs = Math.min(
      issuedAtMs + EVIDENCE_LIFETIME_MS,
      decision.payload.expiresAtMs,
      preCutover.expiresAtMs,
    );
    if (expiresAtMs <= issuedAtMs) {
      throw new Error("Production activation predecision has no remaining bounded validity window.");
    }
    const payload = {
      stage: "PRODUCTION_ACTIVATION_PREDECISION",
      predecisionId: `production-predecision-${randomUUID()}`,
      productionActivationPrecheckId: `production-precheck-${randomUUID()}`,
      transactionId: request.selection.transactionId,
      managementNonce: stagingPrecheck.managementNonce,
      managementCorrelationId: preCutover.managementCorrelationId,
      principalKeyFingerprint: preCutover.principalKeyFingerprint,
      canonicalName: tuple.canonicalName,
      candidateBindingId: tuple.candidateBindingId,
      clientId: tuple.clientId,
      tuple,
      tupleDigest,
      activePreimageDigest: expectedActivePreimageDigest,
      plan,
      oauthResource: productionCandidate.payload.oauthResource,
      oauthScopes: [...EXPECTED_SCOPES],
      candidateIdentity: productionCandidate.payload.candidateIdentity,
      immutablePackageRoot: immutablePackageDirectory(productionCandidate.payload.packageRoot),
      migrationManifestDigest: productionCandidate.payload.migrationManifestDigest,
      preCutoverHostCanaryDigest: preCutover.signedPayloadDigest,
      stagingActivationPrecheckDigest: stagingPrecheck.signedPayloadDigest,
      stagingCandidateBinding: stagingPrecheck.stagingCandidateBinding,
      stagingBinding: preCutover.stagingBinding,
      stagingRouteIdentityDigest: preCutover.stagingRouteIdentityDigest,
      productionEnvironmentIdentityDigest: productionCandidate.payload.environmentIdentityDigest,
      productionRouteIdentityDigest: productionCandidate.payload.routeIdentityDigest,
      stagingProductionBindingRelation: relation,
      productionCandidateRecordId: productionCandidate.recordDigest,
      ownerDecisionRecordId: decision.recordDigest,
      approvalConditionsDigest,
      ownerDecision: {
        approvalId: decision.payload.approvalId,
        authorityText: decision.payload.authorityText,
        approvedAtMs: decision.payload.approvedAtMs,
        expiresAtMs: decision.payload.expiresAtMs,
      },
      journalIdentity,
      finalizationDraftIdentity,
      storeBindings,
      artifactBindings,
      issuedAtMs,
      expiresAtMs,
    };
    const envelope = signProductionActivationPredecision(payload, key, issuedAtMs);
    verifyProductionActivationPredecision(envelope, key, {
      transactionId: request.selection.transactionId,
      predecisionPath: artifactBindings.predecisionPath,
      productionApprovalOutputDirectory: artifactBindings.productionApprovalOutputDirectory,
    }, issuedAtMs);
    return envelope;
  }

  createProductionActivationApproval(request) {
    validateRequestEnvelope(
      request,
      "PRODUCTION_APPROVE",
      ["finalizationControlPath", "finalizationStorePath"],
      ["transactionId"],
      [
        "predecisionPath", "productionApprovalOutputDirectory",
        "productionPreparationRequestPath", "snapshotManifestPath", "statusPath",
        "upgradeRequestPath", "workerClaimPath",
      ],
    );
    assertProductionTransactionId(request.selection.transactionId);
    const key = loadManagementAuthorizationKey(this.runtime, request.management);
    const context = validatePostSnapshotProductionPreparation(
      request,
      key,
      this.runtime,
      this.finalizationIdentityReader,
      this.now(),
    );
    const preCutover = readVerifiedPreCutoverFromPredecision(
      context,
      key,
      this.runtime,
      this.now(),
    );
    let receipt = reconcileOrPrepareProductionActivation(context, this.runtime, this.finalizationIdentityReader);
    receipt = readPreparedProductionReceipt(context, receipt.receiptId, this.runtime);
    const finalizationPlanDigest = this.runtime.connectorActivationFinalizationPlanDigest(receipt);
    const observedAtMs = Date.parse(receipt.preparedAt);
    const productionPayload = {
      stage: "PRODUCTION_ACTIVATION_PRECHECK",
      productionActivationPrecheckId: context.predecision.productionActivationPrecheckId,
      managementCorrelationId: context.predecision.managementCorrelationId,
      principalKeyFingerprint: context.predecision.principalKeyFingerprint,
      receiptId: receipt.receiptId,
      canonicalName: receipt.tuple.canonicalName,
      tupleDigest: receipt.tupleDigest,
      activePreimageDigest: receipt.preimageDigest,
      finalizationPlanDigest,
      tuple: receipt.tuple,
      oauthResource: context.predecision.oauthResource,
      oauthScopes: [...EXPECTED_SCOPES],
      candidateIdentity: context.predecision.candidateIdentity,
      preCutoverHostCanaryDigest: context.predecision.preCutoverHostCanaryDigest,
      stagingBinding: context.predecision.stagingBinding,
      stagingRouteIdentityDigest: context.predecision.stagingRouteIdentityDigest,
      productionEnvironmentIdentityDigest: context.predecision.productionEnvironmentIdentityDigest,
      productionRouteIdentityDigest: context.predecision.productionRouteIdentityDigest,
      stagingProductionBindingRelation: context.predecision.stagingProductionBindingRelation,
      observedAtMs,
      expiresAtMs: observedAtMs + EVIDENCE_LIFETIME_MS,
    };
    const productionEnvelope = this.runtime.signConnectorActivationProductionPrecheck(
      productionPayload,
      key,
      this.now(),
    );
    const productionPrecheck = this.runtime.verifyConnectorActivationProductionPrecheck(
      productionEnvelope,
      key,
      {
        principalKeyFingerprint: context.predecision.principalKeyFingerprint,
        receiptId: receipt.receiptId,
        canonicalName: receipt.tuple.canonicalName,
        tupleDigest: receipt.tupleDigest,
        activePreimageDigest: receipt.preimageDigest,
        finalizationPlanDigest,
        tuple: receipt.tuple,
        preCutoverHostCanary: preCutover,
        oauthResource: context.predecision.oauthResource,
        productionEnvironmentIdentityDigest: context.predecision.productionEnvironmentIdentityDigest,
        productionRouteIdentityDigest: context.predecision.productionRouteIdentityDigest,
      },
      this.now(),
    );
    const ownerBinding = {
      principalKeyFingerprint: productionPrecheck.principalKeyFingerprint,
      receiptId: productionPrecheck.receiptId,
      canonicalName: productionPrecheck.canonicalName,
      tupleDigest: productionPrecheck.tupleDigest,
      activePreimageDigest: productionPrecheck.activePreimageDigest,
      finalizationPlanDigest: productionPrecheck.finalizationPlanDigest,
      preCutoverHostCanaryDigest: preCutover.signedPayloadDigest,
      productionActivationPrecheckDigest: productionPrecheck.signedPayloadDigest,
    };
    const ownerEnvelope = this.runtime.signConnectorActivationOwnerApproval({
      ...ownerBinding,
      approvalId: context.predecision.ownerDecision.approvalId,
      authorityText: context.predecision.ownerDecision.authorityText,
      evidenceDigest: digestJson({
        predecisionDigest: context.predecisionDigest,
        decisionRecordId: context.predecision.ownerDecisionRecordId,
        approvalConditionsDigest: context.predecision.approvalConditionsDigest,
        receiptId: receipt.receiptId,
        finalizationPlanDigest,
        snapshotGroupDigest: context.snapshotManifest.groupDigest,
        finalizationPrepareDigest: context.finalizationPreparedIdentity.prepareDigest,
      }),
      approvedAtMs: context.predecision.ownerDecision.approvedAtMs,
      expiresAtMs: context.predecision.ownerDecision.expiresAtMs,
    }, key, this.now());
    this.runtime.verifyConnectorActivationOwnerApproval(ownerEnvelope, key, ownerBinding, this.now());
    return Object.freeze({
      productionActivationPrecheck: productionEnvelope,
      ownerManagementApproval: ownerEnvelope,
      manifest: Object.freeze({
        schemaVersion: 1,
        kind: "PRODUCTION_ACTIVATION_APPROVAL_MANIFEST",
        transactionId: context.predecision.transactionId,
        predecisionDigest: context.predecisionDigest,
        requestBindingDigest: context.requestBindingDigest,
        snapshotGroupDigest: context.snapshotManifest.groupDigest,
        snapshotManifestSha256: context.snapshotManifestSha256,
        finalizationStorePath: context.finalizationPreparedIdentity.path,
        finalizationPrepareDigest: context.finalizationPreparedIdentity.prepareDigest,
        finalizationContentGeneration: context.finalizationPreparedIdentity.contentGeneration,
        receiptId: receipt.receiptId,
        tupleDigest: receipt.tupleDigest,
        activePreimageDigest: receipt.preimageDigest,
        finalizationPlanDigest,
        tuple: receipt.tuple,
        candidateIdentity: context.predecision.candidateIdentity,
        productionEnvironmentIdentityDigest: context.predecision.productionEnvironmentIdentityDigest,
        productionRouteIdentityDigest: context.predecision.productionRouteIdentityDigest,
        migrationManifestDigest: context.predecision.migrationManifestDigest,
        oauthResource: context.predecision.oauthResource,
        journalIdentity: context.predecision.journalIdentity,
        provenanceDigest: digestJson({
          predecisionDigest: context.predecisionDigest,
          preCutoverArtifactDigest: context.predecision.preCutoverHostCanaryDigest,
          productionCandidateRecordId: context.predecision.productionCandidateRecordId,
          ownerDecisionRecordId: context.predecision.ownerDecisionRecordId,
          approvalConditionsDigest: context.predecision.approvalConditionsDigest,
          requestBindingDigest: context.requestBindingDigest,
          snapshotGroupDigest: context.snapshotManifest.groupDigest,
          finalizationPrepareDigest: context.finalizationPreparedIdentity.prepareDigest,
        }),
      }),
    });
  }

  createPostActivationHostCanary(request) {
    validateRequestEnvelope(
      request,
      "POST_ACTIVATION",
      [...COMMON_STORE_KEYS, "authorityDatabasePath"],
      ["activeStagingCandidateReadbackRecordId", "canary", "stagingPrecheck"],
      ["ownerApprovalPath", "preCutoverPath", "productionPrecheckPath", "stagingPrecheckPath"],
      { stagingPrecheck: STAGING_SELECTOR_KEYS, canary: CANARY_SELECTOR_KEYS },
    );
    const key = loadManagementAuthorizationKey(this.runtime, request.management);
    const stagingRequest = nestedSelectionRequest(request, "stagingPrecheck");
    const stagingContext = this.#deriveStagingPrecheckContext(stagingRequest, false);
    const stagingArtifact = readSignedEvidence(
      request.artifacts.stagingPrecheckPath,
      "STAGING_ACTIVATION_PRECHECK",
    );
    const stagingPrecheck = this.runtime.verifyConnectorActivationStagingPrecheck(
      stagingArtifact,
      key,
      stagingPrecheckExpected(stagingContext),
      this.now(),
    );
    const broker = new EvidenceLedger(request.stores.brokerLedgerPath, BROKER_SOURCE, this.runtime);
    const activeStaging = broker.require(
      request.selection.activeStagingCandidateReadbackRecordId,
      "CANDIDATE_READBACK",
    );
    assertEvidenceFresh(activeStaging, this.now(), EVIDENCE_LIFETIME_MS, "ACTIVE staging candidate readback");
    assertCandidateReadback(activeStaging.payload, "STAGING", "ACTIVE");
    const preArtifact = readSignedEvidence(
      request.artifacts.preCutoverPath,
      "PRE_CUTOVER_HOST_CANARY",
    );
    const preCutover = this.runtime.verifyPersistedConnectorActivationPreCutoverHostCanary(
      preArtifact,
      key,
      {
        principalKeyFingerprint: stagingPrecheck.principalKeyFingerprint,
        managementNonce: stagingPrecheck.managementNonce,
        managementCorrelationId: stagingPrecheck.managementCorrelationId,
        candidateIdentity: activeStaging.payload.candidateIdentity,
        stagingRouteIdentityDigest: activeStaging.payload.routeIdentityDigest,
        stagingBinding: stagingBindingIdentity(activeStaging.payload, "ACTIVE"),
        stagingActivationPrecheck: stagingPrecheck,
      },
      this.now(),
    );
    const productionEnvelope = readSignedEvidence(
      request.artifacts.productionPrecheckPath,
      "PRODUCTION_ACTIVATION_PRECHECK",
    );
    const ownerEnvelope = readSignedEvidence(
      request.artifacts.ownerApprovalPath,
      "OWNER_MANAGEMENT_APPROVAL",
    );
    const oauth = new OAuthActivationReadAdapter(request.stores.oauthDatabasePath, this.runtime);
    let activatedReceipt;
    try {
      const receiptId = productionEnvelope.payload.receiptId;
      activatedReceipt = oauth.requireActivationReceipt(receiptId);
      if (activatedReceipt.status !== "ACTIVATED") {
        throw new Error("Production connector activation receipt is not ACTIVATED.");
      }
    } finally {
      oauth.close();
    }
    const productionPrecheck = this.runtime.verifyConnectorActivationProductionPrecheck(
      productionEnvelope,
      key,
      {
        principalKeyFingerprint: preCutover.principalKeyFingerprint,
        receiptId: activatedReceipt.receiptId,
        canonicalName: activatedReceipt.tuple.canonicalName,
        tupleDigest: activatedReceipt.tupleDigest,
        activePreimageDigest: activatedReceipt.preimageDigest,
        finalizationPlanDigest: this.runtime.connectorActivationFinalizationPlanDigest(activatedReceipt),
        tuple: activatedReceipt.tuple,
        preCutoverHostCanary: preCutover,
        oauthResource: productionEnvelope.payload.oauthResource,
        productionEnvironmentIdentityDigest: productionEnvelope.payload.productionEnvironmentIdentityDigest,
        productionRouteIdentityDigest: productionEnvelope.payload.productionRouteIdentityDigest,
      },
      this.now(),
    );
    const ownerBinding = {
      principalKeyFingerprint: productionPrecheck.principalKeyFingerprint,
      receiptId: productionPrecheck.receiptId,
      canonicalName: productionPrecheck.canonicalName,
      tupleDigest: productionPrecheck.tupleDigest,
      activePreimageDigest: productionPrecheck.activePreimageDigest,
      finalizationPlanDigest: productionPrecheck.finalizationPlanDigest,
      preCutoverHostCanaryDigest: preCutover.signedPayloadDigest,
      productionActivationPrecheckDigest: productionPrecheck.signedPayloadDigest,
    };
    this.runtime.verifyConnectorActivationOwnerApproval(
      ownerEnvelope,
      key,
      ownerBinding,
      this.now(),
    );
    const canary = this.#deriveHostCanaryContext(request, "POST_ACTIVATION_HOST_CANARY", productionPrecheck);
    if (canary.activationReceipt.receiptId !== activatedReceipt.receiptId) {
      throw new Error("POST canary OAuth activation receipt changed during readback.");
    }
    const previousBindingState = canary.activationReceipt.previousActiveBindingId ? "DRAINING" : "ABSENT";
    const payload = {
      stage: "POST_ACTIVATION_HOST_CANARY",
      postActivationHostCanaryId: canary.host.payload.hostCanaryId,
      managementNonce: canary.host.payload.managementNonce,
      managementCorrelationId: canary.host.payload.managementCorrelationId,
      principalKeyFingerprint: canary.principalKeyFingerprint,
      hostProvider: "chatgpt",
      actualHost: true,
      precheckDigest: productionPrecheck.signedPayloadDigest,
      activationReceiptId: canary.activationReceipt.receiptId,
      activationReceiptDigest: this.runtime.connectorActivationReceiptDigest(canary.activationReceipt),
      activationProofDigest: canary.activationAuthorityReceipt.proofDigest,
      activationAuthorityReceiptDigest:
        this.runtime.connectorActivationAuthorityReceiptDigest(canary.activationAuthorityReceipt),
      activatedAtMs: Date.parse(canary.activationReceipt.activatedAt),
      newActiveTuple: canary.activationReceipt.tuple,
      newActiveBindingState: "ACTIVE",
      tokenFamilyIdDigest: canary.tokenFamilyIdDigest,
      tokenFamilyBindingId: canary.tokenFamily.connectorBindingId,
      previousActiveBindingId: canary.activationReceipt.previousActiveBindingId ?? null,
      previousBindingState,
      productionIdentity: canary.candidate.payload.candidateIdentity,
      productionEnvironmentIdentityDigest: canary.candidate.payload.environmentIdentityDigest,
      productionRouteIdentityDigest: canary.candidate.payload.routeIdentityDigest,
      discoveredToolNames: [...EXPECTED_TOOLS],
      toolDiscoveryEvidenceDigest: canary.toolDiscoveryEvidenceDigest,
      mutation: canary.mutation,
      foreignClientIsolation: canary.foreignClientIsolation,
      observedAtMs: canary.host.occurredAtMs,
      expiresAtMs: canary.host.occurredAtMs + EVIDENCE_LIFETIME_MS,
    };
    const evidence = this.runtime.signConnectorActivationPostActivationHostCanary(payload, key, this.now());
    this.runtime.verifyConnectorActivationPostActivationHostCanary(evidence, key, {
      principalKeyFingerprint: canary.principalKeyFingerprint,
      managementNonce: payload.managementNonce,
      managementCorrelationId: payload.managementCorrelationId,
      productionActivationPrecheckDigest: productionPrecheck.signedPayloadDigest,
      activationReceipt: canary.activationReceipt,
      activationAuthorityReceipt: canary.activationAuthorityReceipt,
      newActiveBindingState: "ACTIVE",
      tokenFamilyIdDigest: canary.tokenFamilyIdDigest,
      tokenFamilyBindingId: canary.tokenFamily.connectorBindingId,
      previousBindingState,
      productionIdentity: payload.productionIdentity,
      productionEnvironmentIdentityDigest: payload.productionEnvironmentIdentityDigest,
      productionRouteIdentityDigest: payload.productionRouteIdentityDigest,
    }, this.now());
    return evidence;
  }

  createRollbackHostChallenge(request) {
    validateRequestEnvelope(
      request,
      "ROLLBACK_CHALLENGE",
      ["brokerLedgerPath"],
      ["rollbackPreimageRecordId"],
      ["receiptPath"],
    );
    const key = loadManagementAuthorizationKey(this.runtime, request.management);
    const broker = new EvidenceLedger(request.stores.brokerLedgerPath, BROKER_SOURCE, this.runtime);
    const preimage = broker.require(
      request.selection.rollbackPreimageRecordId,
      "ROLLBACK_PREIMAGE_READBACK",
    );
    assertEvidenceFresh(preimage, this.now(), EVIDENCE_LIFETIME_MS, "rollback preimage readback");
    const receiptPath = ownerOnlyFuturePath(request.artifacts.receiptPath, "rollback receipt");
    const issuedAtMs = this.now();
    return signConnectorRollbackHostChallenge({
      challengeId: `rollback-challenge-${randomUUID()}`,
      transactionId: preimage.payload.transactionId,
      nonce: randomBytes(32).toString("base64url"),
      managementCorrelationId: preimage.payload.managementCorrelationId,
      hostProvider: "chatgpt",
      actualHostRequired: true,
      previousRuntimeIdentityDigest: preimage.payload.previousRuntimeIdentityDigest,
      previousMainMigrationIdentityDigest: preimage.payload.previousMainMigrationIdentityDigest,
      issuedAtMs,
      expiresAtMs: issuedAtMs + ROLLBACK_CHALLENGE_LIFETIME_MS,
      receiptPath,
    }, key, issuedAtMs);
  }

  createRollbackHostReceipt(request) {
    validateRequestEnvelope(
      request,
      "ROLLBACK_HOST",
      ["brokerLedgerPath", "hostLedgerPath"],
      [
        "expectedSessionATranscriptDigest", "expectedSessionBTranscriptDigest",
        "hostObservationRecordId", "rollbackPreimageRecordId",
      ],
      ["challengePath", "receiptPath"],
    );
    const key = loadManagementAuthorizationKey(this.runtime, request.management);
    const challengeEnvelope = readSignedRollbackEvidence(
      request.artifacts.challengePath,
      "ROLLBACK_HOST_CHALLENGE",
    );
    const broker = new EvidenceLedger(request.stores.brokerLedgerPath, BROKER_SOURCE, this.runtime);
    const preimage = broker.require(
      request.selection.rollbackPreimageRecordId,
      "ROLLBACK_PREIMAGE_READBACK",
    );
    const challengeExpected = rollbackExpectedBinding(preimage, request.artifacts.receiptPath);
    const challenge = verifyConnectorRollbackHostChallenge(
      challengeEnvelope,
      key,
      challengeExpected,
      this.now(),
    );
    ownerOnlyFuturePath(challengeExpected.receiptPath, "rollback receipt");
    const hostLedger = new EvidenceLedger(request.stores.hostLedgerPath, HOST_SOURCE, this.runtime);
    const host = hostLedger.require(
      request.selection.hostObservationRecordId,
      "CHATGPT_ROLLBACK_HOST",
    );
    assertDigestEquals(
      host.payload.sessionA.transcriptDigest,
      request.selection.expectedSessionATranscriptDigest,
      "rollback Host session A transcript",
    );
    assertDigestEquals(
      host.payload.sessionB.transcriptDigest,
      request.selection.expectedSessionBTranscriptDigest,
      "rollback Host session B transcript",
    );
    if (host.payload.sessionA.sessionIdentityDigest === host.payload.sessionB.sessionIdentityDigest) {
      throw new Error("Actual ChatGPT rollback provenance requires two distinct session identities.");
    }
    if (host.payload.challengeId !== challenge.challengeId
      || host.payload.transactionId !== challenge.transactionId
      || host.payload.managementCorrelationId !== challenge.managementCorrelationId) {
      throw new Error("Rollback Host observation does not bind the signed challenge transaction.");
    }
    const health = broker.require(
      host.payload.sessionA.healthReadbackRecordId,
      "ROLLBACK_HEALTH_READBACK",
    );
    const ready = broker.require(
      host.payload.sessionB.readyReadbackRecordId,
      "ROLLBACK_READY_READBACK",
    );
    const runtime = broker.require(
      host.payload.sessionB.runtimeReadbackRecordId,
      "ROLLBACK_RUNTIME_READBACK",
    );
    assertRollbackReadbackBinding(health, challenge, host.payload.sessionA.sessionIdentityDigest);
    assertRollbackReadbackBinding(ready, challenge, host.payload.sessionB.sessionIdentityDigest);
    assertRollbackReadbackBinding(runtime, challenge, host.payload.sessionB.sessionIdentityDigest);
    if (health.payload.httpStatus !== 200 || ready.payload.httpStatus !== 200) {
      throw new Error("Rollback broker health and ready readbacks must both be HTTP 200.");
    }
    if (ready.payload.runtimeIdentityDigest !== challenge.previousRuntimeIdentityDigest
      || runtime.payload.runtimeIdentityDigest !== challenge.previousRuntimeIdentityDigest
      || runtime.payload.mainMigrationIdentityDigest !== challenge.previousMainMigrationIdentityDigest) {
      throw new Error("Rollback ready/runtime readback does not match the signed previous runtime and migration identity.");
    }
    if (health.occurredAtMs < challenge.issuedAtMs
      || health.occurredAtMs > host.occurredAtMs
      || ready.occurredAtMs < challenge.issuedAtMs
      || ready.occurredAtMs > host.occurredAtMs
      || runtime.occurredAtMs < challenge.issuedAtMs
      || runtime.occurredAtMs > host.occurredAtMs) {
      throw new Error("Rollback Host observation timing does not reconcile to post-challenge broker readbacks.");
    }
    const receiptExpected = rollbackReceiptExpectedBinding(
      challengeExpected,
      challenge,
      health,
      ready,
      runtime,
    );
    const expiresAtMs = Math.min(
      host.occurredAtMs + EVIDENCE_LIFETIME_MS,
      challenge.expiresAtMs,
    );
    const envelope = signConnectorRollbackHostReceipt({
      challengeId: challenge.challengeId,
      challengePayloadDigest: challenge.signedPayloadDigest,
      transactionId: challenge.transactionId,
      nonce: challenge.nonce,
      managementCorrelationId: challenge.managementCorrelationId,
      hostProvider: "chatgpt",
      actualHost: true,
      previousRuntimeIdentityDigest: challenge.previousRuntimeIdentityDigest,
      previousMainMigrationIdentityDigest: challenge.previousMainMigrationIdentityDigest,
      runtimeReadbackDigest: receiptExpected.runtimeReadbackDigest,
      healthReadbackDigest: receiptExpected.healthReadbackDigest,
      readyReadbackDigest: receiptExpected.readyReadbackDigest,
      sessionAIdDigest: host.payload.sessionA.sessionIdentityDigest,
      sessionBIdDigest: host.payload.sessionB.sessionIdentityDigest,
      observedAtMs: host.occurredAtMs,
      expiresAtMs,
    }, key, challengeEnvelope, receiptExpected, this.now());
    verifyConnectorRollbackHostReceipt(
      envelope,
      key,
      challengeEnvelope,
      receiptExpected,
      this.now(),
    );
    return envelope;
  }

  verifyPersistedRollbackHostReceipt(request) {
    validateRequestEnvelope(
      request,
      "ROLLBACK_VERIFY",
      ["brokerLedgerPath"],
      [
        "healthReadbackRecordId", "readyReadbackRecordId", "rollbackPreimageRecordId",
        "runtimeReadbackRecordId",
      ],
      ["challengePath", "receiptPath"],
    );
    const key = loadManagementAuthorizationKey(this.runtime, request.management);
    const broker = new EvidenceLedger(request.stores.brokerLedgerPath, BROKER_SOURCE, this.runtime);
    const preimage = broker.require(
      request.selection.rollbackPreimageRecordId,
      "ROLLBACK_PREIMAGE_READBACK",
    );
    const challengeExpected = rollbackExpectedBinding(preimage, request.artifacts.receiptPath);
    const challengeEnvelope = readSignedRollbackEvidence(
      request.artifacts.challengePath,
      "ROLLBACK_HOST_CHALLENGE",
    );
    const challenge = verifyConnectorRollbackHostChallenge(
      challengeEnvelope,
      key,
      challengeExpected,
      this.now(),
    );
    const health = broker.require(
      request.selection.healthReadbackRecordId,
      "ROLLBACK_HEALTH_READBACK",
    );
    const ready = broker.require(
      request.selection.readyReadbackRecordId,
      "ROLLBACK_READY_READBACK",
    );
    const runtime = broker.require(
      request.selection.runtimeReadbackRecordId,
      "ROLLBACK_RUNTIME_READBACK",
    );
    assertRollbackReadbackBinding(health, challenge);
    assertRollbackReadbackBinding(ready, challenge);
    assertRollbackReadbackBinding(runtime, challenge);
    if (health.payload.httpStatus !== 200 || ready.payload.httpStatus !== 200) {
      throw new Error("Persisted rollback health and ready readbacks must both be HTTP 200.");
    }
    if (ready.payload.runtimeIdentityDigest !== challenge.previousRuntimeIdentityDigest
      || runtime.payload.runtimeIdentityDigest !== challenge.previousRuntimeIdentityDigest
      || runtime.payload.mainMigrationIdentityDigest !== challenge.previousMainMigrationIdentityDigest) {
      throw new Error("Persisted rollback ready/runtime readback does not match the signed previous identities.");
    }
    const receiptExpected = rollbackReceiptExpectedBinding(
      challengeExpected,
      challenge,
      health,
      ready,
      runtime,
    );
    const receiptEnvelope = readSignedRollbackEvidence(
      request.artifacts.receiptPath,
      "ROLLBACK_HOST_RECEIPT",
    );
    const receipt = verifyConnectorRollbackHostReceipt(
      receiptEnvelope,
      key,
      challengeEnvelope,
      receiptExpected,
      this.now(),
    );
    if (health.payload.sessionIdentityDigest !== receipt.sessionAIdDigest
      || ready.payload.sessionIdentityDigest !== receipt.sessionBIdDigest
      || runtime.payload.sessionIdentityDigest !== receipt.sessionBIdDigest) {
      throw new Error("Persisted rollback readbacks do not bind the signed Host session identities.");
    }
    for (const readback of [health, ready, runtime]) {
      if (readback.occurredAtMs < challenge.issuedAtMs
        || readback.occurredAtMs > receipt.observedAtMs) {
        throw new Error("Persisted rollback readback timing is outside the signed Host observation.");
      }
    }
    return receipt;
  }

  #deriveStagingPrecheckContext(request, requirePreparedOAuth = true) {
    const hostLedger = new EvidenceLedger(request.stores.hostLedgerPath, HOST_SOURCE, this.runtime);
    const brokerLedger = new EvidenceLedger(request.stores.brokerLedgerPath, BROKER_SOURCE, this.runtime);
    const audit = new OperationAuditReader(request.stores.auditLogPath);
    const host = hostLedger.require(request.selection.hostObservationRecordId, "CHATGPT_STAGING_DISCOVERY_R0");
    const candidate = brokerLedger.require(request.selection.candidateReadbackRecordId, "CANDIDATE_READBACK");
    assertEvidenceFresh(host, this.now(), EVIDENCE_LIFETIME_MS, "staging Host observation");
    assertEvidenceFresh(candidate, this.now(), EVIDENCE_LIFETIME_MS, "staging candidate readback");
    assertCandidateReadback(candidate.payload, "STAGING", "ACTIVATION_PREPARED");
    assertDigestEquals(host.payload.discovery.transcriptDigest, request.selection.expectedDiscoveryTranscriptDigest, "discovery transcript");
    assertDigestEquals(host.payload.r0Canary.transcriptDigest, request.selection.expectedR0TranscriptDigest, "R0 transcript");
    if (host.payload.discovery.sessionIdentityDigest === host.payload.r0Canary.sessionIdentityDigest) {
      throw new Error("Actual ChatGPT staging provenance requires two distinct session identities.");
    }
    if (host.payload.environmentIdentityDigest !== candidate.payload.environmentIdentityDigest
      || host.payload.routeIdentityDigest !== candidate.payload.routeIdentityDigest) {
      throw new Error("Host staging observation does not match the trusted staging environment and route.");
    }
    const discovery = brokerLedger.require(host.payload.discovery.brokerRequestRecordId, "TOOL_DISCOVERY");
    const r0 = brokerLedger.require(host.payload.r0Canary.brokerRequestRecordId, "TOOL_REQUEST");
    assertBrokerRequestBinding(discovery, host, candidate, host.payload.discovery.sessionIdentityDigest);
    assertBrokerRequestBinding(r0, host, candidate, host.payload.r0Canary.sessionIdentityDigest);
    if (!objectsEqual(host.payload.discovery.toolNames, EXPECTED_TOOLS)
      || !objectsEqual(discovery.payload.toolNames, EXPECTED_TOOLS)) {
      throw new Error("Actual Host and broker discovery must both contain exactly the canonical eight tools.");
    }
    if (r0.payload.outcome !== "PASS") throw new Error("Staging R0 canary did not return PASS.");
    assertDigestEquals(r0.payload.resourceDigest, request.selection.expectedResourceDigest, "R0 resource");
    if (discovery.payload.principalKeyFingerprint !== r0.payload.principalKeyFingerprint
      || discovery.payload.clientId !== r0.payload.clientId
      || candidate.payload.clientId !== r0.payload.clientId) {
      throw new Error("Staging discovery, R0 canary, and candidate do not share one stable client principal.");
    }
    const auditEvent = audit.requireOperation(r0.payload.operationId, r0.payload.correlationId);
    assertAuditMatchesRequest(auditEvent, r0, {
      result: "pass", risk: "R0", dispatchState: "NOT_DISPATCHED",
    });
    const dispatches = brokerLedger.find("PROVIDER_DISPATCH", (record) => (
      record.payload.requestRecordId === r0.recordDigest
    ));
    if (dispatches.length !== 1) throw new Error("Staging R0 provider dispatch count is not exactly one.");
    assertProviderDispatchMatchesRequest(dispatches[0], r0);
    const readbacks = brokerLedger.find("RESOURCE_READBACK", (record) => (
      record.payload.requestRecordId === r0.recordDigest
    ));
    if (readbacks.length !== 1) throw new Error("Staging R0 has no one exact broker readback.");
    assertReadbackAfterDispatch(readbacks[0], dispatches[0], r0);
    if (readbacks[0].occurredAtMs > host.occurredAtMs) {
      throw new Error("Staging R0 Host observation predates its broker readback.");
    }
    if (requirePreparedOAuth) {
      const oauth = new OAuthActivationReadAdapter(request.stores.oauthDatabasePath, this.runtime);
      try {
        const binding = oauth.requireBinding(candidate.payload.bindingId);
        assertBindingMatchesCandidateRecord(binding, candidate.payload, "ACTIVATION_PREPARED");
        const receipt = oauth.requireActivationReceipt(candidate.payload.receiptId);
        assertPreparedReceiptMatchesBinding(receipt, binding, this.runtime);
      } finally {
        oauth.close();
      }
    }
    const toolDiscoveryEvidenceDigest = digestJson({
      hostRecordId: host.recordDigest,
      brokerRequestRecordId: discovery.recordDigest,
      transcriptDigest: host.payload.discovery.transcriptDigest,
      responseDigest: discovery.payload.responseDigest,
      toolNames: [...EXPECTED_TOOLS],
    });
    const r0Canary = {
      tool: r0.payload.tool,
      operation: r0.payload.operation,
      argumentsDigest: r0.payload.argumentsDigest,
      resourceDigest: r0.payload.resourceDigest,
      providerDispatchCount: 1,
      readbackDigest: readbacks[0].payload.readbackDigest,
    };
    return {
      host,
      candidate,
      principalKeyFingerprint: r0.payload.principalKeyFingerprint,
      toolDiscoveryEvidenceDigest,
      r0Canary,
      provenanceDigest: digestJson({
        hostRecordId: host.recordDigest,
        candidateRecordId: candidate.recordDigest,
        discoveryRecordId: discovery.recordDigest,
        r0RecordId: r0.recordDigest,
        auditEventDigest: auditEvent.eventDigest,
        providerDispatchRecordId: dispatches[0].recordDigest,
        readbackRecordId: readbacks[0].recordDigest,
      }),
    };
  }

  #deriveHostCanaryContext(request, expectedStage, priorEvidence) {
    const selector = request.selection.canary;
    const hostLedger = new EvidenceLedger(request.stores.hostLedgerPath, HOST_SOURCE, this.runtime);
    const brokerLedger = new EvidenceLedger(request.stores.brokerLedgerPath, BROKER_SOURCE, this.runtime);
    const audit = new OperationAuditReader(request.stores.auditLogPath);
    const host = hostLedger.require(selector.hostObservationRecordId, "CHATGPT_A_TO_B_CANARY");
    assertEvidenceFresh(host, this.now(), EVIDENCE_LIFETIME_MS, `${expectedStage} Host observation`);
    if (host.payload.stage !== expectedStage) throw new Error(`Host canary is not ${expectedStage}.`);
    const environmentRole = expectedStage === "PRE_CUTOVER_HOST_CANARY" ? "STAGING" : "PRODUCTION";
    const candidate = brokerLedger.require(selector.candidateReadbackRecordId, "CANDIDATE_READBACK");
    assertEvidenceFresh(candidate, this.now(), EVIDENCE_LIFETIME_MS, `${expectedStage} candidate readback`);
    assertCandidateReadback(candidate.payload, environmentRole, "ACTIVE");
    if (host.payload.environmentIdentityDigest !== candidate.payload.environmentIdentityDigest
      || host.payload.routeIdentityDigest !== candidate.payload.routeIdentityDigest) {
      throw new Error("Host canary does not match the trusted ACTIVE environment and route.");
    }
    assertCanaryExpectedDigests(host, selector);
    if (host.payload.sessionA.sessionIdentityDigest === host.payload.sessionB.sessionIdentityDigest) {
      throw new Error("Actual ChatGPT Host canary requires distinct session A and session B identities.");
    }
    const discovery = brokerLedger.require(host.payload.discovery.brokerRequestRecordId, "TOOL_DISCOVERY");
    const authorization = brokerLedger.require(
      host.payload.sessionA.authorizationRequestRecordId,
      "OAUTH_AUTHORIZATION",
    );
    const close = brokerLedger.require(host.payload.sessionA.closeRequestRecordId, "SESSION_CLOSE");
    const mutationRequest = brokerLedger.require(host.payload.sessionB.mutationRequestRecordId, "TOOL_REQUEST");
    const foreignRequest = brokerLedger.require(
      host.payload.foreignClient.rejectionRequestRecordId,
      "TOOL_REQUEST",
    );
    for (const [record, session] of [
      [discovery, host.payload.discovery.sessionIdentityDigest],
      [authorization, host.payload.sessionA.sessionIdentityDigest],
      [mutationRequest, host.payload.sessionB.sessionIdentityDigest],
      [foreignRequest, host.payload.foreignClient.sessionIdentityDigest],
    ]) assertBrokerRequestBinding(record, host, candidate, session);
    assertSessionCloseBinding(close, host);
    if (!objectsEqual(host.payload.discovery.toolNames, EXPECTED_TOOLS)
      || !objectsEqual(discovery.payload.toolNames, EXPECTED_TOOLS)) {
      throw new Error("Host canary discovery is not exactly the canonical eight-tool surface.");
    }
    if (host.payload.sessionA.authorizedAtMs !== authorization.occurredAtMs
      || host.payload.sessionA.closedAtMs !== close.occurredAtMs
      || host.payload.sessionB.mutationAtMs !== mutationRequest.occurredAtMs
      || host.payload.foreignClient.observedAtMs !== foreignRequest.occurredAtMs
      || authorization.occurredAtMs >= close.occurredAtMs
      || close.occurredAtMs >= mutationRequest.occurredAtMs
      || foreignRequest.occurredAtMs > host.occurredAtMs) {
      throw new Error("Host A authorize/close to B mutation timing does not reconcile to broker records.");
    }
    if (discovery.payload.clientId !== mutationRequest.payload.clientId
      || discovery.payload.principalKeyFingerprint !== mutationRequest.payload.principalKeyFingerprint
      || authorization.payload.clientId !== mutationRequest.payload.clientId
      || authorization.payload.principalKeyFingerprint !== mutationRequest.payload.principalKeyFingerprint
      || candidate.payload.clientId !== mutationRequest.payload.clientId) {
      throw new Error("Host discovery, authorization, and mutation do not use the ACTIVE connector's stable client principal.");
    }
    if (authorization.payload.oauthResource !== candidate.payload.oauthResource) {
      throw new Error("Host authorization does not bind the ACTIVE connector's trusted OAuth resource.");
    }
    if (mutationRequest.payload.outcome !== "PASS") throw new Error("Host session B mutation did not PASS.");
    assertDigestEquals(mutationRequest.payload.resourceDigest, selector.expectedResourceDigest, "canary resource");
    const mutationAudit = audit.requireOperation(
      mutationRequest.payload.operationId,
      mutationRequest.payload.correlationId,
    );
    const actionFingerprint = this.runtime.actionFingerprint(mutationRequest.payload.action);
    const resourceKeySha256 = this.runtime.actionResourceKeySha256(mutationRequest.payload.action);
    const authority = new AuthorityReadAdapter(request.stores.authorityDatabasePath);
    let mutationClaim;
    try {
      mutationClaim = authority.requireMutationPass({
        principalKeyFingerprint: mutationRequest.payload.principalKeyFingerprint,
        actionFingerprint,
        resourceKeySha256,
        auditEventDigest: mutationAudit.eventDigest,
        tool: mutationRequest.payload.tool,
        operation: mutationRequest.payload.operation,
      });
      assertAuditMatchesRequest(mutationAudit, mutationRequest, {
        result: "pass",
        risk: mutationClaim.risk,
        claimState: "PASS",
        dispatchState: "ACKNOWLEDGED",
        authorityId: mutationClaim.authorityId,
        resourceKeySha256,
        receiptDigest: mutationClaim.receiptDigest,
      });
    } finally {
      authority.close();
    }
    const providerDispatches = brokerLedger.find("PROVIDER_DISPATCH", (record) => (
      record.payload.requestRecordId === mutationRequest.recordDigest
    ));
    if (providerDispatches.length !== 1) throw new Error("Host mutation provider dispatch count is not exactly one.");
    assertProviderDispatchMatchesRequest(providerDispatches[0], mutationRequest);
    const readbacks = brokerLedger.find("RESOURCE_READBACK", (record) => (
      record.payload.requestRecordId === mutationRequest.recordDigest
    ));
    if (readbacks.length !== 1) throw new Error("Host mutation is missing one exact post-readback.");
    assertReadbackAfterDispatch(readbacks[0], providerDispatches[0], mutationRequest);
    const cleanups = brokerLedger.find("CLEANUP_DISPATCH", (record) => (
      record.payload.requestRecordId === mutationRequest.recordDigest
    ));
    if (cleanups.length !== 1) throw new Error("Host mutation cleanup dispatch is missing or ambiguous.");
    assertCleanupAfterReadback(cleanups[0], readbacks[0], mutationRequest);
    const absenceReadbacks = brokerLedger.find("RESOURCE_ABSENCE_READBACK", (record) => (
      record.payload.cleanupRecordId === cleanups[0].recordDigest
    ));
    if (absenceReadbacks.length !== 1) throw new Error("Host mutation cleanup absence readback is missing or ambiguous.");
    assertAbsenceAfterCleanup(absenceReadbacks[0], cleanups[0], mutationRequest);
    if (absenceReadbacks[0].occurredAtMs > host.occurredAtMs) {
      throw new Error("Host observation predates mutation cleanup readback.");
    }
    if (foreignRequest.payload.outcome !== "AUTHORITY_PRINCIPAL_MISMATCH"
      || foreignRequest.payload.clientId === mutationRequest.payload.clientId
      || foreignRequest.payload.principalKeyFingerprint === mutationRequest.payload.principalKeyFingerprint
      || this.runtime.actionFingerprint(foreignRequest.payload.action) !== actionFingerprint
      || this.runtime.actionResourceKeySha256(foreignRequest.payload.action) !== resourceKeySha256) {
      throw new Error("Foreign-client request is not the same action from a distinct principal.");
    }
    const foreignDispatches = brokerLedger.find("PROVIDER_DISPATCH", (record) => (
      record.payload.requestRecordId === foreignRequest.recordDigest
    ));
    if (foreignDispatches.length !== 0) throw new Error("Foreign client reached the provider boundary.");
    const foreignAudit = audit.requireOperation(
      foreignRequest.payload.operationId,
      foreignRequest.payload.correlationId,
    );
    assertAuditMatchesRequest(foreignAudit, foreignRequest, {
      result: "fail",
      risk: mutationClaim.risk,
      dispatchState: "NOT_DISPATCHED",
      authorityId: mutationClaim.authorityId,
      errorCode: "AUTHORITY_PRINCIPAL_MISMATCH",
    });

    const oauth = new OAuthActivationReadAdapter(request.stores.oauthDatabasePath, this.runtime);
    let activationReceipt;
    let activationAuthorityReceipt;
    let tokenFamily;
    try {
      const active = oauth.requireBinding(candidate.payload.bindingId);
      assertBindingMatchesCandidateRecord(active, candidate.payload, "ACTIVE");
      if (oauth.countActiveCanonical(candidate.payload.canonicalName) !== 1) {
        throw new Error("OAuth readback does not contain exactly one canonical ACTIVE connector.");
      }
      activationReceipt = oauth.requireActivationReceipt(candidate.payload.receiptId);
      if (activationReceipt.status !== "ACTIVATED" || !activationReceipt.activationAuthority) {
        throw new Error("Exact OAuth connector activation receipt is not ACTIVATED.");
      }
      activationAuthorityReceipt = activationReceipt.activationAuthority;
      tokenFamily = oauth.requireTokenFamilyByDigest(authorization.payload.tokenFamilyIdDigest);
      if (tokenFamily.status !== "ACTIVE"
        || tokenFamily.clientId !== active.clientId
        || tokenFamily.connectorBindingId !== active.bindingId
        || tokenFamily.installationEpoch !== active.installationEpoch
        || tokenFamily.drainEpoch !== active.drainEpoch) {
        throw new Error("OAuth token family is not ACTIVE on the exact new connector generation.");
      }
      const activatedAtMs = Date.parse(activationReceipt.activatedAt);
      if (!Number.isSafeInteger(activatedAtMs) || activatedAtMs >= authorization.occurredAtMs) {
        throw new Error("Host authorization did not occur strictly after connector activation.");
      }
      if (activationReceipt.previousActiveBindingId) {
        const previous = oauth.requireBinding(activationReceipt.previousActiveBindingId);
        if (previous.state !== "DRAINING") {
          throw new Error("Prior production connector is not DRAINING at POST evidence time.");
        }
      }
    } finally {
      oauth.close();
    }
    const activationAuthority = new AuthorityReadAdapter(request.stores.authorityDatabasePath);
    try {
      activationAuthority.requireActivationPass(activationAuthorityReceipt);
    } finally {
      activationAuthority.close();
    }
    if (activationAuthorityReceipt.principalKeyFingerprint !== mutationRequest.payload.principalKeyFingerprint) {
      throw new Error("Activation and Host mutation authority principals differ.");
    }
    if (expectedStage === "PRE_CUTOVER_HOST_CANARY") {
      if (priorEvidence.principalKeyFingerprint !== mutationRequest.payload.principalKeyFingerprint
        || priorEvidence.managementNonce !== host.payload.managementNonce
        || priorEvidence.managementCorrelationId !== host.payload.managementCorrelationId
        || !objectsEqual(priorEvidence.candidateIdentity, candidate.payload.candidateIdentity)) {
        throw new Error("PRE Host canary does not continue the exact staging precheck.");
      }
    } else if (priorEvidence.principalKeyFingerprint !== mutationRequest.payload.principalKeyFingerprint
      || priorEvidence.managementCorrelationId !== host.payload.managementCorrelationId
      || priorEvidence.oauthResource !== candidate.payload.oauthResource
      || priorEvidence.productionEnvironmentIdentityDigest !== candidate.payload.environmentIdentityDigest
      || priorEvidence.productionRouteIdentityDigest !== candidate.payload.routeIdentityDigest) {
      throw new Error("POST Host canary does not continue the exact production precheck.");
    }

    const toolDiscoveryEvidenceDigest = digestJson({
      hostRecordId: host.recordDigest,
      brokerRequestRecordId: discovery.recordDigest,
      transcriptDigest: host.payload.discovery.transcriptDigest,
      responseDigest: discovery.payload.responseDigest,
      toolNames: [...EXPECTED_TOOLS],
    });
    const cleanupEvidenceDigest = digestJson({
      cleanupRecordId: cleanups[0].recordDigest,
      absenceReadbackRecordId: absenceReadbacks[0].recordDigest,
      absenceEvidenceDigest: absenceReadbacks[0].payload.absenceEvidenceDigest,
    });
    const mutation = {
      tool: mutationRequest.payload.tool,
      operation: mutationRequest.payload.operation,
      argumentsDigest: mutationRequest.payload.argumentsDigest,
      resourceDigest: mutationRequest.payload.resourceDigest,
      sessionAIdDigest: host.payload.sessionA.sessionIdentityDigest,
      sessionAAuthorizationEvidenceDigest: digestJson({
        hostTranscriptDigest: host.payload.sessionA.authorizationTranscriptDigest,
        brokerAuthorizationRecordId: authorization.recordDigest,
        authorizationEvidenceDigest: authorization.payload.authorizationEvidenceDigest,
      }),
      sessionAAuthorizedAtMs: authorization.occurredAtMs,
      sessionACloseEvidenceDigest: digestJson({
        hostTranscriptDigest: host.payload.sessionA.closeTranscriptDigest,
        brokerCloseRecordId: close.recordDigest,
        closeEvidenceDigest: close.payload.closeEvidenceDigest,
      }),
      sessionAClosedAtMs: close.occurredAtMs,
      sessionBIdDigest: host.payload.sessionB.sessionIdentityDigest,
      sessionBMutationEvidenceDigest: digestJson({
        hostTranscriptDigest: host.payload.sessionB.mutationTranscriptDigest,
        brokerRequestRecordId: mutationRequest.recordDigest,
        brokerResponseDigest: mutationRequest.payload.responseDigest,
        auditEventDigest: mutationAudit.eventDigest,
      }),
      sessionBMutationAtMs: mutationRequest.occurredAtMs,
      actionFingerprint,
      resourceKeySha256,
      authorityId: mutationClaim.authorityId,
      actionClaimId: mutationClaim.actionClaimId,
      fencingToken: mutationClaim.fencingToken,
      authorityReceiptDigest: mutationClaim.receiptDigest,
      providerDispatchCount: 1,
      postReadbackDigest: readbacks[0].payload.readbackDigest,
      cleanupPerformed: true,
      cleanupEvidenceDigest,
    };
    const foreignClientIsolation = {
      clientId: foreignRequest.payload.clientId,
      principalKeyFingerprint: foreignRequest.payload.principalKeyFingerprint,
      errorCode: "AUTHORITY_PRINCIPAL_MISMATCH",
      providerDispatchCount: 0,
      evidenceDigest: digestJson({
        hostTranscriptDigest: host.payload.foreignClient.rejectionTranscriptDigest,
        brokerRequestRecordId: foreignRequest.recordDigest,
        auditEventDigest: foreignAudit.eventDigest,
      }),
    };
    return {
      host,
      candidate,
      principalKeyFingerprint: mutationRequest.payload.principalKeyFingerprint,
      activationReceipt,
      activationAuthorityReceipt,
      tokenFamily,
      tokenFamilyIdDigest: authorization.payload.tokenFamilyIdDigest,
      toolDiscoveryEvidenceDigest,
      mutation,
      foreignClientIsolation,
      provenanceDigest: digestJson({
        hostRecordId: host.recordDigest,
        candidateRecordId: candidate.recordDigest,
        discoveryRecordId: discovery.recordDigest,
        authorizationRecordId: authorization.recordDigest,
        closeRecordId: close.recordDigest,
        mutationRecordId: mutationRequest.recordDigest,
        mutationAuditEventDigest: mutationAudit.eventDigest,
        providerDispatchRecordId: providerDispatches[0].recordDigest,
        readbackRecordId: readbacks[0].recordDigest,
        cleanupRecordId: cleanups[0].recordDigest,
        absenceReadbackRecordId: absenceReadbacks[0].recordDigest,
        foreignRequestRecordId: foreignRequest.recordDigest,
        foreignAuditEventDigest: foreignAudit.eventDigest,
      }),
    };
  }
}

function validatePostSnapshotProductionPreparation(
  request,
  key,
  runtime,
  finalizationIdentityReader,
  nowMs,
) {
  const preparationRequestPath = ownerOnlyExistingPath(
    request.artifacts.productionPreparationRequestPath,
    "production preparation request",
  );
  const persistedPreparationRequest = readOwnerOnlyJson(
    preparationRequestPath,
    "production preparation request",
  );
  if (!objectsEqual(persistedPreparationRequest, request)) {
    throw new Error("Production preparation request differs from its owner-only persisted bytes.");
  }
  const predecisionPath = ownerOnlyExistingPath(
    request.artifacts.predecisionPath,
    "production activation predecision",
  );
  const predecisionEnvelope = readOwnerOnlyJson(
    predecisionPath,
    "PRODUCTION_ACTIVATION_PREDECISION artifact",
  );
  const outputDirectory = preflightProductionApprovalDirectoryForReconcile(
    request.artifacts.productionApprovalOutputDirectory,
  );
  const predecision = verifyProductionActivationPredecision(
    predecisionEnvelope,
    key,
    {
      transactionId: request.selection.transactionId,
      predecisionPath,
      productionApprovalOutputDirectory: outputDirectory,
    },
    nowMs,
  );
  if (request.stores.finalizationStorePath !== predecision.storeBindings.finalizationStorePath
    || request.stores.finalizationControlPath !== predecision.storeBindings.finalizationControlPath
    || preparationRequestPath !== predecision.artifactBindings.productionPreparationRequestPath
    || request.artifacts.upgradeRequestPath !== predecision.artifactBindings.upgradeRequestPath) {
    throw new Error("Production preparation request changed a signed predecision store or control path.");
  }
  assertImmutablePredecisionBindings(predecision, runtime);
  const currentJournalIdentity = readConnectorJournalIdentityReadonly(
    predecision.storeBindings.journalPath,
    runtime,
  );
  if (!objectsEqual(currentJournalIdentity, predecision.journalIdentity)) {
    throw new Error("Connector activation journal identity changed after owner predecision.");
  }

  const upgradeRequestPath = ownerOnlyExistingPath(
    request.artifacts.upgradeRequestPath,
    "production upgrade request",
  );
  const upgradeRequest = readOwnerOnlyJson(upgradeRequestPath, "production upgrade request");
  if (upgradeRequest.version !== 4 || upgradeRequest.transactionId !== predecision.transactionId) {
    throw new Error("Production upgrade request does not bind the signed predecision transaction.");
  }
  const requestBindingDigest = runtime.productionUpgradeRequestBindingDigest(upgradeRequest);
  requiredDigest(requestBindingDigest, "production upgrade request binding digest");
  const releaseDriver = upgradeRequest.connectorLifecycle?.releaseDriver;
  if (!isPlainObject(releaseDriver)) {
    throw new Error("Production upgrade request omits the release-driver provenance binding.");
  }
  assertArtifactReference(
    releaseDriver.productionPredecisionRequest,
    undefined,
    "production predecision request",
  );
  const persistedPredecisionRequest = readOwnerOnlyJson(
    releaseDriver.productionPredecisionRequest.path,
    "production predecision request",
  );
  if (persistedPredecisionRequest.operation !== "PRODUCTION_PREDECISION"
    || persistedPredecisionRequest.selection?.transactionId !== predecision.transactionId
    || persistedPredecisionRequest.artifacts?.predecisionPath !== predecisionPath
    || persistedPredecisionRequest.artifacts?.productionPreparationRequestPath !== preparationRequestPath
    || persistedPredecisionRequest.artifacts?.upgradeRequestPath !== upgradeRequestPath
    || persistedPredecisionRequest.artifacts?.productionApprovalOutputDirectory !== outputDirectory) {
    throw new Error("Production predecision request provenance does not match its signed outputs.");
  }
  assertArtifactReference(
    releaseDriver.productionPredecisionEnvelope,
    predecisionPath,
    "production predecision envelope",
  );
  assertArtifactReference(
    releaseDriver.productionPreparationRequest,
    preparationRequestPath,
    "production preparation request",
  );
  if (releaseDriver.productionApprovalOutputDirectory !== outputDirectory) {
    throw new Error("Production upgrade request changed the signed approval output directory.");
  }

  const statusPath = ownerOnlyExistingPath(request.artifacts.statusPath, "production upgrade status");
  const workerClaimPath = ownerOnlyExistingPath(
    request.artifacts.workerClaimPath,
    "production upgrade worker claim",
  );
  const snapshotManifestPath = ownerOnlyExistingPath(
    request.artifacts.snapshotManifestPath,
    "production snapshot manifest",
  );
  if (statusPath !== upgradeRequest.statusPath
    || workerClaimPath !== `${statusPath}.worker-claim.json`
    || !isPlainObject(upgradeRequest.snapshotGroup)
    || snapshotManifestPath !== join(upgradeRequest.snapshotGroup.snapshotRoot, "SNAPSHOT-GROUP.json")) {
    throw new Error("Production preparation control paths do not match the exact worker request.");
  }
  const sequencing = readAndValidateWorkerSnapshotSequencing({
    statusPath,
    workerClaimPath,
    snapshotManifestPath,
    upgradeRequest,
    requestBindingDigest,
    transactionId: predecision.transactionId,
    runtime,
    nowMs,
  });
  assertSnapshotPreMutationOAuth(
    sequencing.snapshotManifest,
    predecision,
    runtime,
  );
  assertSnapshotFinalizationEntry(
    sequencing.snapshotManifest,
    predecision.storeBindings.finalizationStorePath,
  );
  const finalizationPreparedIdentity = finalizationIdentityReader({
    storePath: ownerOnlyExistingPath(
      request.stores.finalizationStorePath,
      "prepared finalization store",
    ),
    controlPath: ownerOnlyExistingPath(
      request.stores.finalizationControlPath,
      "prepared finalization control",
    ),
    key,
  });
  assertFinalizationPreparedIdentity(
    finalizationPreparedIdentity,
    predecision.finalizationDraftIdentity,
    predecision.transactionId,
    {
      requestBindingDigest,
      candidateIdentityDigest: upgradeRequest.snapshotGroup.barrier.candidateIdentityDigest,
      snapshotGroupDigest: sequencing.snapshotManifest.groupDigest,
      snapshotCapturedAt: sequencing.snapshotManifest.capturedAt,
    },
  );
  return Object.freeze({
    request,
    key,
    predecision,
    predecisionDigest: predecision.signedPayloadDigest,
    predecisionEnvelope,
    requestBindingDigest,
    upgradeRequest,
    workerClaim: sequencing.workerClaim,
    snapshotManifest: sequencing.snapshotManifest,
    snapshotManifestSha256: sequencing.snapshotManifestSha256,
    finalizationPreparedIdentity,
    finalizationIdentityReader,
    nowMs,
  });
}

function assertImmutablePredecisionBindings(predecision, runtime) {
  const derived = deriveCandidateIdentityFromImmutablePackage({
    packageRoot: predecision.immutablePackageRoot,
    candidateIdentity: predecision.candidateIdentity,
  });
  if (!objectsEqual(derived.candidateIdentity, predecision.candidateIdentity)
    || derived.migrationManifestDigest !== predecision.migrationManifestDigest) {
    throw new Error("Immutable release identity changed after production predecision.");
  }
  const environmentIdentityDigest = runtime.connectorEnvironmentIdentityDigest({
    environmentRole: "PRODUCTION",
    runtimeIdentityDigest: predecision.candidateIdentity.runtimeIdentityDigest,
    oauthResource: predecision.oauthResource,
  });
  const routeIdentityDigest = runtime.connectorRouteIdentityDigest({
    oauthResource: predecision.oauthResource,
    canonicalName: predecision.canonicalName,
    bindingId: predecision.candidateBindingId,
  });
  if (environmentIdentityDigest !== predecision.productionEnvironmentIdentityDigest
    || routeIdentityDigest !== predecision.productionRouteIdentityDigest) {
    throw new Error("Production environment or route identity changed after owner predecision.");
  }
  if (predecision.tupleDigest !== runtime.connectorActivationTupleDigest(predecision.tuple)) {
    throw new Error("Production tuple digest disagrees with the connector runtime.");
  }
}

function assertArtifactReference(reference, expectedPath, label) {
  assertExactKeys(reference, ["path", "sha256"], `${label} reference`);
  const path = ownerOnlyExistingPath(reference.path, label);
  requiredDigest(reference.sha256, `${label} sha256`);
  if ((expectedPath !== undefined && path !== expectedPath)
    || fileSha256(path) !== reference.sha256) {
    throw new Error(`${label} path or byte digest changed from the worker request.`);
  }
}

function readAndValidateWorkerSnapshotSequencing({
  statusPath,
  workerClaimPath,
  snapshotManifestPath,
  upgradeRequest,
  requestBindingDigest,
  transactionId,
  runtime,
  nowMs,
}) {
  const workerClaim = readOwnerOnlyJson(workerClaimPath, "production upgrade worker claim");
  assertExactKeys(workerClaim, [
    "acquiredAt", "claimId", "claimPath", "pid", "requestBindingDigest", "schemaVersion",
    "transactionId",
  ], "production upgrade worker claim");
  if (workerClaim.schemaVersion !== 1
    || workerClaim.claimPath !== workerClaimPath
    || workerClaim.transactionId !== transactionId
    || workerClaim.requestBindingDigest !== requestBindingDigest
    || !/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/u.test(workerClaim.claimId)
    || !Number.isSafeInteger(workerClaim.pid) || workerClaim.pid < 1) {
    throw new Error("Production upgrade worker claim is not bound to the exact transaction request.");
  }
  requiredIsoTimestamp(workerClaim.acquiredAt, "worker claim acquiredAt");
  if (Date.parse(workerClaim.acquiredAt) > nowMs) {
    throw new Error("Production upgrade worker claim is future-issued.");
  }
  const status = readOwnerOnlyJson(statusPath, "production upgrade status");
  if (status.version !== 2
    || status.transactionId !== transactionId
    || status.requestBindingDigest !== requestBindingDigest
    || status.state !== "STATE_SNAPSHOTTED"
    || status.workerPid !== workerClaim.pid
    || !objectsEqual(status.workerClaim, workerClaim)) {
    throw new Error("Production upgrade status is not the exact claimed STATE_SNAPSHOTTED barrier.");
  }
  requiredIsoTimestamp(status.updatedAt, "production upgrade status updatedAt");
  if (!Array.isArray(status.history)) {
    throw new Error("Production upgrade status history is missing.");
  }
  const stopped = status.history.filter((entry) => entry?.state === "CUTOVER_PROCESSES_STOPPED");
  const snapped = status.history.filter((entry) => entry?.state === "STATE_SNAPSHOTTED");
  if (stopped.length !== 1 || snapped.length !== 1
    || status.history.at(-1)?.state !== "STATE_SNAPSHOTTED"
    || status.history.at(-1)?.at !== status.updatedAt) {
    throw new Error("Production upgrade status has no unique durable stopped/snapshotted sequence.");
  }
  requiredIsoTimestamp(stopped[0].at, "CUTOVER_PROCESSES_STOPPED transition");
  requiredIsoTimestamp(snapped[0].at, "STATE_SNAPSHOTTED transition");
  const snapshotManifestRaw = readOwnerOnlyText(
    snapshotManifestPath,
    "production snapshot manifest",
    MAX_JSON_BYTES,
  );
  const snapshotManifest = runtime.validateSnapshotGroupManifest(
    parseJson(snapshotManifestRaw, "production snapshot manifest"),
  );
  if (!objectsEqual(status.snapshotGroupPreimage, snapshotManifest)
    || snapshotManifest.snapshotRoot !== upgradeRequest.snapshotGroup.snapshotRoot) {
    throw new Error("Production snapshot manifest differs from durable worker status/request state.");
  }
  const barrier = snapshotManifest.barrier;
  assertExactKeys(barrier, [
    "cutoverProcessNames", "establishedAt", "kind", "previousMigrationManifestDigest",
    "previousPid", "previousRuntimeIdentityDigest", "processName", "requestBindingDigest",
    "transactionId",
  ], "production snapshot barrier");
  const expectedProcessNames = [...upgradeRequest.cutoverProcessNames]
    .sort((left, right) => (left < right ? -1 : left > right ? 1 : 0));
  if (barrier.kind !== "PM2_STOPPED"
    || barrier.transactionId !== transactionId
    || barrier.requestBindingDigest !== requestBindingDigest
    || barrier.processName !== upgradeRequest.pm2ProcessName
    || barrier.previousPid !== upgradeRequest.previous?.pid
    || barrier.previousRuntimeIdentityDigest !== upgradeRequest.previous?.runtimeIdentityDigest
    || barrier.previousMigrationManifestDigest !== upgradeRequest.previous?.migrationManifestDigest
    || !objectsEqual(barrier.cutoverProcessNames, expectedProcessNames)
    || barrier.establishedAt !== stopped[0].at) {
    throw new Error("Production snapshot barrier is not bound to the exact stopped worker transaction.");
  }
  requiredIsoTimestamp(snapshotManifest.capturedAt, "snapshot capturedAt");
  if (Date.parse(snapshotManifest.capturedAt) < Date.parse(barrier.establishedAt)
    || Date.parse(snapshotManifest.capturedAt) > Date.parse(snapped[0].at)) {
    throw new Error("Production snapshot capture is outside the durable stopped/snapshotted interval.");
  }
  return {
    workerClaim,
    status,
    snapshotManifest,
    snapshotManifestSha256: digestText(snapshotManifestRaw),
  };
}

function requireSnapshotSqliteEntry(manifest, id, expectedLivePath) {
  const matches = manifest.entries.filter((entry) => entry.id === id);
  if (matches.length !== 1) throw new Error(`Snapshot group does not contain one exact ${id} entry.`);
  const entry = matches[0];
  if (entry.kind !== "sqlite" || entry.required !== true || entry.state !== "captured"
    || entry.path !== expectedLivePath || typeof entry.snapshotPath !== "string") {
    throw new Error(`Snapshot group ${id} entry is not one required captured SQLite preimage.`);
  }
  const snapshotPath = ownerOnlyExistingPath(entry.snapshotPath, `${id} snapshot`);
  const metadata = lstatSync(snapshotPath);
  if (entry.sha256 !== fileSha256(snapshotPath)
    || entry.bytes !== metadata.size
    || entry.mode !== (metadata.mode & 0o777)) {
    throw new Error(`Snapshot group ${id} bytes, size, or mode differ from its manifest.`);
  }
  return { entry, snapshotPath };
}

function assertSnapshotPreMutationOAuth(manifest, predecision, runtime) {
  const { snapshotPath } = requireSnapshotSqliteEntry(
    manifest,
    "oauth-main-and-connector-state",
    predecision.storeBindings.oauthDatabasePath,
  );
  const oauth = new OAuthActivationReadAdapter(snapshotPath, runtime);
  try {
    const candidate = oauth.requireBinding(predecision.candidateBindingId);
    if (candidate.state !== "VERIFIED"
      || candidate.stateReason !== undefined
      || !objectsEqual(activationTupleFromBinding(candidate), predecision.tuple)) {
      throw new Error("Captured OAuth preimage is not the exact pre-mutation VERIFIED candidate.");
    }
    const active = oauth.requireActiveBinding(predecision.canonicalName);
    if (oauthConnectorPreimageDigest(active) !== predecision.activePreimageDigest
      || oauth.getPreparedActivationReceipt(predecision.canonicalName) !== undefined) {
      throw new Error("Captured OAuth preimage does not match the signed ACTIVE preimage or is already prepared.");
    }
  } finally {
    oauth.close();
  }
}

function assertSnapshotFinalizationEntry(manifest, finalizationStorePath) {
  requireSnapshotSqliteEntry(
    manifest,
    "lifecycle-finalization-store",
    finalizationStorePath,
  );
}

function assertFinalizationPreparedIdentity(identity, draft, transactionId, expected) {
  assertExactKeys(identity, [
    "contentGeneration", "createdAt", "finalDigest", "foreignKeyViolations", "inputDigest",
    "integrity", "keyId", "migration", "path", "prepareDigest", "revision", "schemaFingerprint",
    "schemaVersion", "sealInputDigest", "state", "storeId", "transactionId", "updatedAt",
    "controlEpoch", "controlTag", "candidateIdentityDigest", "preSnapshotIdentity",
    "preSnapshotIdentityDigest", "preparedAt", "requestBindingDigest", "snapshotCapturedAt",
    "snapshotGroupDigest",
  ], "prepared finalization identity");
  if (identity.storeId !== draft.storeId
    || identity.path !== draft.path
    || identity.schemaVersion !== draft.schemaVersion
    || identity.schemaFingerprint !== draft.schemaFingerprint
    || !objectsEqual(identity.migration, draft.migration)
    || identity.keyId !== draft.keyId
    || identity.createdAt !== draft.createdAt
    || identity.state !== "PREPARED"
    || identity.revision !== draft.revision + 1
    || identity.transactionId !== transactionId
    || identity.requestBindingDigest !== expected.requestBindingDigest
    || identity.candidateIdentityDigest !== expected.candidateIdentityDigest
    || identity.snapshotGroupDigest !== expected.snapshotGroupDigest
    || identity.snapshotCapturedAt !== expected.snapshotCapturedAt
    || identity.preparedAt !== identity.updatedAt
    || identity.sealInputDigest !== null
    || identity.finalDigest !== null
    || identity.integrity !== "ok"
    || identity.foreignKeyViolations !== 0) {
    throw new Error("Finalization store is not the exact PREPARED transaction derived from the DRAFT preimage.");
  }
  requiredDigest(identity.inputDigest, "prepared finalization inputDigest");
  requiredDigest(identity.prepareDigest, "prepared finalization prepareDigest");
  requiredDigest(identity.contentGeneration, "prepared finalization contentGeneration");
  requiredDigest(identity.preSnapshotIdentityDigest, "prepared finalization preSnapshotIdentityDigest");
  if (!isPlainObject(identity.preSnapshotIdentity)
    || !Number.isSafeInteger(identity.controlEpoch)
    || identity.controlEpoch <= draft.controlEpoch
    || !/^hmac-sha256:[a-f0-9]{64}$/u.test(identity.controlTag ?? "")) {
    throw new Error("Prepared finalization external control identity is invalid.");
  }
  requiredIsoTimestamp(identity.preparedAt, "prepared finalization preparedAt");
  requiredIsoTimestamp(identity.updatedAt, "prepared finalization updatedAt");
  if (Date.parse(identity.updatedAt) < Date.parse(draft.updatedAt)) {
    throw new Error("Prepared finalization identity predates its signed DRAFT preimage.");
  }
}

function reconcileOrPrepareProductionActivation(context, runtime, finalizationIdentityReader) {
  let state = readCurrentProductionActivationState(context.predecision, runtime);
  if (state.kind === "VERIFIED" && existsSync(context.predecision.artifactBindings.productionApprovalOutputDirectory)) {
    throw new Error("Production approval output exists before an exact PREPARED OAuth receipt.");
  }
  const finalizationReadback = finalizationIdentityReader({
    storePath: context.predecision.storeBindings.finalizationStorePath,
    controlPath: context.predecision.storeBindings.finalizationControlPath,
    key: context.key,
  });
  assertFinalizationPreparedIdentity(
    finalizationReadback,
    context.predecision.finalizationDraftIdentity,
    context.predecision.transactionId,
    {
      requestBindingDigest: context.requestBindingDigest,
      candidateIdentityDigest: context.upgradeRequest.snapshotGroup.barrier.candidateIdentityDigest,
      snapshotGroupDigest: context.snapshotManifest.groupDigest,
      snapshotCapturedAt: context.snapshotManifest.capturedAt,
    },
  );
  if (!objectsEqual(finalizationReadback, context.finalizationPreparedIdentity)) {
    throw new Error("Finalization PREPARED identity drifted immediately before OAuth preparation.");
  }
  assertWorkerClaimStillHeld(context);
  if (state.kind === "PREPARED") return state.receipt;

  let store;
  let receipt;
  try {
    store = new runtime.SqliteOAuthStore(context.predecision.storeBindings.oauthStateDir);
    const candidate = store.getConnectorBinding(context.predecision.candidateBindingId);
    const active = store.getActiveConnectorBinding(context.predecision.canonicalName);
    if (!candidate || !active
      || !objectsEqual(activationTupleFromBinding(candidate), context.predecision.tuple)
      || oauthConnectorPreimageDigest(active) !== context.predecision.activePreimageDigest) {
      throw new Error("Production OAuth tuple or ACTIVE preimage drifted before activation preparation.");
    }
    if (candidate.state === "VERIFIED") {
      receipt = store.prepareConnectorActivation(
        context.predecision.tuple,
        context.predecision.plan,
      );
    } else if (candidate.state === "ACTIVATION_PREPARED" && typeof candidate.stateReason === "string") {
      receipt = store.getActivationReceipt(candidate.stateReason);
    } else {
      throw new Error("Production candidate changed before activation preparation.");
    }
  } finally {
    closeQuietly(store);
  }
  assertPreparedReceiptMatchesPredecision(receipt, context.predecision, runtime);
  state = readCurrentProductionActivationState(context.predecision, runtime);
  if (state.kind !== "PREPARED" || state.receipt.receiptId !== receipt.receiptId) {
    throw new Error("Production OAuth PREPARED receipt did not survive exact readback.");
  }
  return state.receipt;
}

function assertWorkerClaimStillHeld(context) {
  const claim = readOwnerOnlyJson(
    context.request.artifacts.workerClaimPath,
    "production upgrade worker claim",
  );
  const status = readOwnerOnlyJson(
    context.request.artifacts.statusPath,
    "production upgrade status",
  );
  if (!objectsEqual(claim, context.workerClaim)
    || status.state !== "STATE_SNAPSHOTTED"
    || status.transactionId !== context.predecision.transactionId
    || status.requestBindingDigest !== context.requestBindingDigest
    || !objectsEqual(status.workerClaim, context.workerClaim)
    || !objectsEqual(status.snapshotGroupPreimage, context.snapshotManifest)) {
    throw new Error("Production worker claim or durable snapshot status drifted before OAuth preparation.");
  }
}

function readCurrentProductionActivationState(predecision, runtime) {
  const oauth = new OAuthActivationReadAdapter(predecision.storeBindings.oauthDatabasePath, runtime);
  try {
    const binding = oauth.requireBinding(predecision.candidateBindingId);
    if (!objectsEqual(activationTupleFromBinding(binding), predecision.tuple)) {
      throw new Error("Production candidate activation tuple drifted after owner predecision.");
    }
    const active = oauth.requireActiveBinding(predecision.canonicalName);
    if (oauthConnectorPreimageDigest(active) !== predecision.activePreimageDigest) {
      throw new Error("Production canonical ACTIVE preimage drifted after owner predecision.");
    }
    const prepared = oauth.getPreparedActivationReceipt(predecision.canonicalName);
    if (binding.state === "VERIFIED") {
      if (binding.stateReason !== undefined || prepared !== undefined) {
        throw new Error("A concurrent or foreign PREPARED receipt exists for the production connector.");
      }
      return { kind: "VERIFIED", binding };
    }
    if (binding.state !== "ACTIVATION_PREPARED"
      || typeof binding.stateReason !== "string"
      || prepared?.receiptId !== binding.stateReason) {
      throw new Error("Production candidate is neither exact VERIFIED nor exact reconciled PREPARED state.");
    }
    assertPreparedReceiptMatchesPredecision(prepared, predecision, runtime);
    return { kind: "PREPARED", binding, receipt: prepared };
  } finally {
    oauth.close();
  }
}

function assertPreparedReceiptMatchesPredecision(receipt, predecision, runtime) {
  if (!receipt || receipt.status !== "PREPARED" || receipt.activationAuthority !== undefined
    || !objectsEqual(receipt.tuple, predecision.tuple)
    || receipt.tupleDigest !== predecision.tupleDigest
    || receipt.tupleDigest !== runtime.connectorActivationTupleDigest(receipt.tuple)
    || receipt.preimageDigest !== predecision.activePreimageDigest
    || receipt.drainDeadlineAt !== predecision.plan.drainDeadlineAt
    || receipt.refreshAllowedDuringDrain !== predecision.plan.refreshAllowedDuringDrain) {
    throw new Error("Persisted PREPARED receipt does not match the exact signed production predecision.");
  }
  requiredText(receipt.receiptId, "prepared receiptId", 256);
  requiredIsoTimestamp(receipt.preparedAt, "prepared receipt preparedAt");
}

function readPreparedProductionReceipt(context, receiptId, runtime) {
  const oauth = new OAuthActivationReadAdapter(
    context.predecision.storeBindings.oauthDatabasePath,
    runtime,
  );
  try {
    const binding = oauth.requireBinding(context.predecision.candidateBindingId);
    const receipt = oauth.requireActivationReceipt(receiptId);
    assertPreparedReceiptMatchesBinding(receipt, binding, runtime);
    assertPreparedReceiptMatchesPredecision(receipt, context.predecision, runtime);
    return receipt;
  } finally {
    oauth.close();
  }
}

function readVerifiedPreCutoverFromPredecision(context, key, runtime, nowMs) {
  const stagingEnvelope = readSignedEvidence(
    context.predecision.artifactBindings.stagingPrecheckPath,
    "STAGING_ACTIVATION_PRECHECK",
  );
  const stagingPrecheck = runtime.verifyConnectorActivationStagingPrecheck(
    stagingEnvelope,
    key,
    {
      principalKeyFingerprint: context.predecision.principalKeyFingerprint,
      managementNonce: context.predecision.managementNonce,
      managementCorrelationId: context.predecision.managementCorrelationId,
      candidateIdentity: context.predecision.candidateIdentity,
      stagingRouteIdentityDigest: context.predecision.stagingRouteIdentityDigest,
      stagingCandidateBinding: context.predecision.stagingCandidateBinding,
    },
    nowMs,
  );
  if (stagingPrecheck.signedPayloadDigest !== context.predecision.stagingActivationPrecheckDigest) {
    throw new Error("Staging precheck artifact changed after production predecision.");
  }
  const preEnvelope = readSignedEvidence(
    context.predecision.artifactBindings.preCutoverPath,
    "PRE_CUTOVER_HOST_CANARY",
  );
  const preCutover = runtime.verifyPersistedConnectorActivationPreCutoverHostCanary(
    preEnvelope,
    key,
    {
      principalKeyFingerprint: context.predecision.principalKeyFingerprint,
      managementNonce: context.predecision.managementNonce,
      managementCorrelationId: context.predecision.managementCorrelationId,
      candidateIdentity: context.predecision.candidateIdentity,
      stagingRouteIdentityDigest: context.predecision.stagingRouteIdentityDigest,
      stagingBinding: context.predecision.stagingBinding,
      stagingActivationPrecheck: stagingPrecheck,
    },
    nowMs,
  );
  if (preCutover.signedPayloadDigest !== context.predecision.preCutoverHostCanaryDigest) {
    throw new Error("PRE cutover Host canary changed after production predecision.");
  }
  return preCutover;
}

function fileSha256(path) {
  return digestText(readFileSync(ownerOnlyExistingPath(path, "digest-bound owner-only file")));
}

function signProductionActivationPredecision(payload, key, nowMs) {
  validateProductionActivationPredecisionPayload(payload, nowMs);
  const base = {
    schemaVersion: 1,
    kind: "PRODUCTION_ACTIVATION_PREDECISION",
    keyId: requiredText(key.keyId, "predecision keyId", 256),
    payload,
  };
  const canonical = canonicalJson(base);
  return Object.freeze({
    ...base,
    payloadDigest: digestText(canonical),
    signature: createHmac("sha256", key.secret)
      .update(PREDECISION_DOMAIN)
      .update(canonical)
      .digest("base64url"),
  });
}

function verifyProductionActivationPredecision(envelope, key, expected, nowMs) {
  assertExactKeys(
    envelope,
    ["keyId", "kind", "payload", "payloadDigest", "schemaVersion", "signature"],
    "PRODUCTION_ACTIVATION_PREDECISION signed envelope",
  );
  assertExactKeys(
    expected,
    ["predecisionPath", "productionApprovalOutputDirectory", "transactionId"],
    "PRODUCTION_ACTIVATION_PREDECISION expected binding",
  );
  if (envelope.schemaVersion !== 1
    || envelope.kind !== "PRODUCTION_ACTIVATION_PREDECISION"
    || envelope.keyId !== key.keyId) {
    throw new Error("PRODUCTION_ACTIVATION_PREDECISION envelope identity is invalid.");
  }
  validateProductionActivationPredecisionPayload(envelope.payload, nowMs);
  const base = {
    schemaVersion: envelope.schemaVersion,
    kind: envelope.kind,
    keyId: envelope.keyId,
    payload: envelope.payload,
  };
  const canonical = canonicalJson(base);
  if (envelope.payloadDigest !== digestText(canonical)) {
    throw new Error("PRODUCTION_ACTIVATION_PREDECISION payload digest is invalid.");
  }
  if (typeof envelope.signature !== "string" || !/^[A-Za-z0-9_-]{43}$/u.test(envelope.signature)) {
    throw new Error("PRODUCTION_ACTIVATION_PREDECISION signature encoding is invalid.");
  }
  const expectedSignature = createHmac("sha256", key.secret)
    .update(PREDECISION_DOMAIN)
    .update(canonical)
    .digest();
  const observedSignature = Buffer.from(envelope.signature, "base64url");
  if (observedSignature.byteLength !== expectedSignature.byteLength
    || !timingSafeEqual(observedSignature, expectedSignature)) {
    throw new Error("PRODUCTION_ACTIVATION_PREDECISION signature is invalid.");
  }
  if (envelope.payload.transactionId !== expected.transactionId
    || envelope.payload.artifactBindings.predecisionPath !== expected.predecisionPath
    || envelope.payload.artifactBindings.productionApprovalOutputDirectory
      !== expected.productionApprovalOutputDirectory) {
    throw new Error("PRODUCTION_ACTIVATION_PREDECISION does not match the exact transaction and output paths.");
  }
  return Object.freeze({
    ...envelope.payload,
    signedPayloadDigest: envelope.payloadDigest,
  });
}

function validateProductionActivationPredecisionPayload(payload, nowMs) {
  assertExactKeys(payload, [
    "activePreimageDigest", "approvalConditionsDigest", "artifactBindings", "candidateBindingId",
    "candidateIdentity", "canonicalName", "clientId", "expiresAtMs", "finalizationDraftIdentity",
    "immutablePackageRoot", "issuedAtMs", "journalIdentity", "managementCorrelationId",
    "managementNonce", "migrationManifestDigest", "oauthResource", "oauthScopes", "ownerDecision",
    "ownerDecisionRecordId", "plan", "preCutoverHostCanaryDigest", "predecisionId",
    "principalKeyFingerprint", "productionActivationPrecheckId", "productionCandidateRecordId",
    "productionEnvironmentIdentityDigest", "productionRouteIdentityDigest", "stage",
    "stagingActivationPrecheckDigest", "stagingBinding", "stagingCandidateBinding",
    "stagingProductionBindingRelation", "stagingRouteIdentityDigest", "storeBindings",
    "transactionId", "tuple", "tupleDigest",
  ], "PRODUCTION_ACTIVATION_PREDECISION payload");
  if (payload.stage !== "PRODUCTION_ACTIVATION_PREDECISION") {
    throw new Error("Production activation predecision stage is invalid.");
  }
  requiredText(payload.predecisionId, "predecisionId", 256);
  requiredText(payload.productionActivationPrecheckId, "productionActivationPrecheckId", 256);
  assertProductionTransactionId(payload.transactionId);
  requiredText(payload.managementNonce, "managementNonce", 512);
  requiredText(payload.managementCorrelationId, "managementCorrelationId", 256);
  requiredRawDigest(payload.principalKeyFingerprint, "principalKeyFingerprint");
  assertActivationTupleShape(payload.tuple);
  if (payload.tupleDigest !== digestActivationTuple(payload.tuple)
    || payload.canonicalName !== payload.tuple.canonicalName
    || payload.candidateBindingId !== payload.tuple.candidateBindingId
    || payload.clientId !== payload.tuple.clientId) {
    throw new Error("Production activation predecision tuple binding is not exact.");
  }
  requiredDigest(payload.activePreimageDigest, "activePreimageDigest");
  assertExactKeys(payload.plan, ["drainDeadlineAt", "refreshAllowedDuringDrain"], "activation drain plan");
  requiredIsoTimestamp(payload.plan.drainDeadlineAt, "activation drain deadline");
  if (typeof payload.plan.refreshAllowedDuringDrain !== "boolean") {
    throw new Error("Activation refresh-during-drain policy is invalid.");
  }
  requiredHttpsUrl(payload.oauthResource, "production OAuth resource");
  if (!objectsEqual(payload.oauthScopes, EXPECTED_SCOPES)) {
    throw new Error("Production OAuth scopes are not the exact six Base scopes.");
  }
  assertCandidateIdentityShape(payload.candidateIdentity);
  if (payload.tuple.schemaGeneration !== payload.candidateIdentity.schemaGeneration
    || payload.tuple.authorityContractGeneration !== payload.candidateIdentity.authorityContractGeneration
    || payload.tuple.buildDigest !== payload.candidateIdentity.buildDigest) {
    throw new Error("Production tuple does not match the immutable candidate identity.");
  }
  absolutePath(payload.immutablePackageRoot, "immutable package root");
  requiredDigest(payload.migrationManifestDigest, "migrationManifestDigest");
  for (const [name, value] of [
    ["preCutoverHostCanaryDigest", payload.preCutoverHostCanaryDigest],
    ["stagingActivationPrecheckDigest", payload.stagingActivationPrecheckDigest],
    ["stagingRouteIdentityDigest", payload.stagingRouteIdentityDigest],
    ["productionEnvironmentIdentityDigest", payload.productionEnvironmentIdentityDigest],
    ["productionRouteIdentityDigest", payload.productionRouteIdentityDigest],
    ["productionCandidateRecordId", payload.productionCandidateRecordId],
    ["ownerDecisionRecordId", payload.ownerDecisionRecordId],
    ["approvalConditionsDigest", payload.approvalConditionsDigest],
  ]) requiredDigest(value, name);
  assertStagingBindingShape(payload.stagingCandidateBinding, "ACTIVATION_PREPARED");
  assertStagingBindingShape(payload.stagingBinding, "ACTIVE");
  const identifiersEqual = payload.stagingBinding.bindingId === payload.tuple.candidateBindingId
    && payload.stagingBinding.clientId === payload.tuple.clientId;
  if ((payload.stagingProductionBindingRelation === "DISTINCT_STAGING_BINDING" && identifiersEqual)
    || (payload.stagingProductionBindingRelation
      === "IDENTICAL_BINDING_IDENTIFIERS_ISOLATED_STAGING" && !identifiersEqual)
    || !["DISTINCT_STAGING_BINDING", "IDENTICAL_BINDING_IDENTIFIERS_ISOLATED_STAGING"]
      .includes(payload.stagingProductionBindingRelation)) {
    throw new Error("Staging versus production binding relation is invalid.");
  }
  assertExactKeys(
    payload.ownerDecision,
    ["approvalId", "approvedAtMs", "authorityText", "expiresAtMs"],
    "predecision owner decision",
  );
  requiredText(payload.ownerDecision.approvalId, "approvalId", 256);
  requiredText(payload.ownerDecision.authorityText, "authorityText", 2_000);
  requiredTimestamp(payload.ownerDecision.approvedAtMs, "approvedAtMs");
  requiredTimestamp(payload.ownerDecision.expiresAtMs, "owner decision expiresAtMs");
  assertConnectorJournalIdentity(payload.journalIdentity);
  assertFinalizationDraftIdentity(
    payload.finalizationDraftIdentity,
    payload.finalizationDraftIdentity.path,
  );
  assertProductionStoreBindings(payload.storeBindings);
  assertProductionArtifactBindings(payload.artifactBindings, false);
  requiredTimestamp(payload.issuedAtMs, "predecision issuedAtMs");
  requiredTimestamp(payload.expiresAtMs, "predecision expiresAtMs");
  if (payload.issuedAtMs > nowMs
    || payload.expiresAtMs <= payload.issuedAtMs
    || payload.expiresAtMs - payload.issuedAtMs > EVIDENCE_LIFETIME_MS
    || payload.expiresAtMs > payload.ownerDecision.expiresAtMs
    || nowMs > payload.expiresAtMs) {
    throw new Error("Production activation predecision is future-issued, expired, or exceeds its bounded lifetime.");
  }
}

function assertActivationTupleShape(tuple) {
  assertExactKeys(tuple, [
    "authorityContractGeneration", "buildDigest", "candidateBindingId", "canonicalName", "clientId",
    "installationEpoch", "redirectUrisDigest", "schemaGeneration",
  ], "production activation tuple");
  requiredText(tuple.canonicalName, "tuple canonicalName", 128);
  requiredText(tuple.candidateBindingId, "tuple candidateBindingId", 256);
  requiredText(tuple.clientId, "tuple clientId", 256);
  if (!Number.isSafeInteger(tuple.installationEpoch) || tuple.installationEpoch < 1) {
    throw new Error("Tuple installationEpoch is invalid.");
  }
  for (const name of [
    "schemaGeneration", "authorityContractGeneration", "redirectUrisDigest", "buildDigest",
  ]) requiredDigest(tuple[name], `tuple ${name}`);
}

function assertCandidateIdentityShape(identity) {
  assertExactKeys(identity, [
    "authorityContractGeneration", "buildCapabilityManifestDigest", "buildDigest",
    "generatedSchemaDigest", "packageSha256", "runtimeIdentityDigest", "schemaGeneration",
  ], "immutable candidate identity");
  for (const [name, value] of Object.entries(identity)) requiredDigest(value, name);
}

function assertStagingBindingShape(binding, expectedState) {
  assertExactKeys(binding, [
    "bindingId", "canonicalName", "clientId", "environmentIdentityDigest", "installationEpoch", "state",
  ], "staging binding identity");
  requiredDigest(binding.environmentIdentityDigest, "staging environmentIdentityDigest");
  requiredText(binding.canonicalName, "staging canonicalName", 128);
  requiredText(binding.clientId, "staging clientId", 256);
  requiredText(binding.bindingId, "staging bindingId", 256);
  if (!Number.isSafeInteger(binding.installationEpoch) || binding.installationEpoch < 1
    || binding.state !== expectedState) {
    throw new Error(`Staging binding identity must be ${expectedState}.`);
  }
}

function assertProductionTransactionId(value) {
  requiredText(value, "production transactionId", 256);
  if (!/^upgrade_[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/u.test(value)) {
    throw new Error("Production transactionId is invalid.");
  }
}

function validateProductionPredecisionArtifactBindings(artifacts) {
  const bindings = {
    stagingPrecheckPath: ownerOnlyExistingPath(
      artifacts.stagingPrecheckPath,
      "staging activation precheck",
    ),
    preCutoverPath: ownerOnlyExistingPath(artifacts.preCutoverPath, "PRE cutover canary"),
    predecisionPath: ownerOnlyFuturePath(artifacts.predecisionPath, "production predecision"),
    productionPreparationRequestPath: ownerOnlyFuturePath(
      artifacts.productionPreparationRequestPath,
      "production preparation request",
    ),
    upgradeRequestPath: ownerOnlyFuturePath(artifacts.upgradeRequestPath, "production upgrade request"),
    productionApprovalOutputDirectory: preflightProductionApprovalDirectory(
      artifacts.productionApprovalOutputDirectory,
    ),
  };
  assertProductionArtifactBindings(bindings, true);
  return bindings;
}

function assertProductionArtifactBindings(bindings, requireSharedControlDirectory) {
  assertExactKeys(bindings, [
    "preCutoverPath", "predecisionPath", "productionApprovalOutputDirectory",
    "productionPreparationRequestPath", "stagingPrecheckPath", "upgradeRequestPath",
  ], "production predecision artifact bindings");
  for (const [name, value] of Object.entries(bindings)) absolutePath(value, name);
  if (requireSharedControlDirectory) {
    const controlDirectory = dirname(bindings.predecisionPath);
    for (const path of [
      bindings.productionPreparationRequestPath,
      bindings.upgradeRequestPath,
      bindings.productionApprovalOutputDirectory,
    ]) {
      if (dirname(path) !== controlDirectory) {
        throw new Error("Production control artifacts must share one canonical owner-only transaction directory.");
      }
    }
  }
}

function assertProductionStoreBindings(bindings) {
  assertExactKeys(bindings, [
    "finalizationControlPath", "finalizationStorePath", "journalPath", "oauthDatabasePath", "oauthStateDir",
  ], "production store bindings");
  for (const [name, value] of Object.entries(bindings)) absolutePath(value, name);
  if (bindings.oauthDatabasePath !== join(bindings.oauthStateDir, "devspace.sqlite")) {
    throw new Error("Production OAuth database binding is not the exact state-directory database.");
  }
}

function assertFinalizationDraftIdentity(identity, expectedPath) {
  assertExactKeys(identity, [
    "contentGeneration", "createdAt", "finalDigest", "foreignKeyViolations", "inputDigest",
    "integrity", "keyId", "migration", "path", "prepareDigest", "revision", "schemaFingerprint",
    "schemaVersion", "sealInputDigest", "state", "storeId", "transactionId", "updatedAt",
    "controlEpoch", "controlTag",
    "candidateIdentityDigest", "preSnapshotIdentity", "preSnapshotIdentityDigest", "preparedAt",
    "requestBindingDigest", "snapshotCapturedAt", "snapshotGroupDigest",
  ], "finalization DRAFT identity");
  if (identity.path !== absolutePath(expectedPath, "finalization store path")
    || identity.storeId !== "lifecycle-finalization-store"
    || identity.schemaVersion !== 2
    || identity.state !== "DRAFT"
    || identity.revision !== 1
    || identity.transactionId !== null
    || identity.candidateIdentityDigest !== null
    || !isPlainObject(identity.preSnapshotIdentity)
    || identity.preparedAt !== null
    || identity.requestBindingDigest !== null
    || identity.snapshotCapturedAt !== null
    || identity.snapshotGroupDigest !== null
    || identity.inputDigest !== null
    || identity.prepareDigest !== null
    || identity.sealInputDigest !== null
    || identity.finalDigest !== null
    || identity.integrity !== "ok"
    || identity.foreignKeyViolations !== 0) {
    throw new Error("Finalization store is not the exact unbound DRAFT preimage.");
  }
  requiredDigest(identity.schemaFingerprint, "finalization schemaFingerprint");
  requiredDigest(identity.contentGeneration, "finalization contentGeneration");
  requiredDigest(identity.preSnapshotIdentityDigest, "finalization preSnapshotIdentityDigest");
  requiredText(identity.keyId, "finalization keyId", 256);
  if (!Number.isSafeInteger(identity.controlEpoch) || identity.controlEpoch < 1
    || !/^hmac-sha256:[a-f0-9]{64}$/u.test(identity.controlTag ?? "")) {
    throw new Error("Finalization DRAFT external control identity is invalid.");
  }
  requiredIsoTimestamp(identity.createdAt, "finalization createdAt");
  requiredIsoTimestamp(identity.updatedAt, "finalization updatedAt");
  if (!isPlainObject(identity.migration)) throw new Error("Finalization migration identity is invalid.");
}

function assertConnectorJournalIdentity(identity) {
  assertExactKeys(identity, [
    "contentGeneration", "createdAtMs", "migrationManifestDigest", "receiptReplayPolicy",
    "schemaFingerprint", "schemaVersion", "snapshotPolicy", "storeId", "storePath",
  ], "connector activation journal identity");
  requiredText(identity.storeId, "connector journal storeId", 256);
  absolutePath(identity.storePath, "connector journal storePath");
  if (identity.schemaVersion !== 1
    || identity.snapshotPolicy !== "PRESERVE_OUTSIDE_MUTABLE_ROLLBACK"
    || identity.receiptReplayPolicy !== "PREPARED_RECEIPT_PERMANENTLY_ONE_SHOT"
    || !Number.isSafeInteger(identity.createdAtMs) || identity.createdAtMs < 0) {
    throw new Error("Connector activation journal identity is invalid.");
  }
  requiredDigest(identity.migrationManifestDigest, "journal migrationManifestDigest");
  requiredDigest(identity.contentGeneration, "journal contentGeneration");
  requiredDigest(identity.schemaFingerprint, "journal schemaFingerprint");
}

function readConnectorJournalIdentityReadonly(path, runtime) {
  const storePath = ownerOnlyExistingPath(path, "connector activation journal");
  const sqlite = new Database(storePath, { readonly: true, fileMustExist: true });
  try {
    sqlite.pragma("query_only = ON");
    sqlite.pragma("foreign_keys = ON");
    if (sqlite.pragma("quick_check", { simple: true }) !== "ok"
      || sqlite.pragma("foreign_key_check").length !== 0
      || sqlite.pragma("user_version", { simple: true })
        !== runtime.CONNECTOR_ACTIVATION_JOURNAL_SCHEMA_VERSION) {
      throw new Error("Connector activation journal read-only integrity check failed.");
    }
    const rows = sqlite.prepare(`
      select store_id as storeId, schema_version as schemaVersion,
             migration_manifest_digest as migrationManifestDigest,
             snapshot_policy as snapshotPolicy, receipt_replay_policy as receiptReplayPolicy,
             schema_fingerprint as schemaFingerprint, created_at_ms as createdAtMs,
             metadata_checksum as metadataChecksum
        from connector_activation_journal_metadata
    `).all();
    if (rows.length !== 1) throw new Error("Connector activation journal metadata is missing or ambiguous.");
    const metadata = rows[0];
    const metadataIdentity = {
      storeId: metadata.storeId,
      schemaVersion: metadata.schemaVersion,
      migrationManifestDigest: metadata.migrationManifestDigest,
      snapshotPolicy: metadata.snapshotPolicy,
      receiptReplayPolicy: metadata.receiptReplayPolicy,
      schemaFingerprint: metadata.schemaFingerprint,
      createdAtMs: metadata.createdAtMs,
    };
    if (metadata.metadataChecksum !== digestJson(metadataIdentity)
      || metadata.schemaVersion !== runtime.CONNECTOR_ACTIVATION_JOURNAL_SCHEMA_VERSION
      || metadata.migrationManifestDigest
        !== runtime.CONNECTOR_ACTIVATION_JOURNAL_MIGRATION_MANIFEST_DIGEST
      || metadata.snapshotPolicy !== runtime.CONNECTOR_ACTIVATION_JOURNAL_SNAPSHOT_POLICY
      || metadata.receiptReplayPolicy !== runtime.CONNECTOR_ACTIVATION_JOURNAL_RECEIPT_REPLAY_POLICY
      || metadata.schemaFingerprint !== runtime.CONNECTOR_ACTIVATION_JOURNAL_SCHEMA_FINGERPRINT) {
      throw new Error("Connector activation journal metadata identity is invalid.");
    }
    const checksums = [
      metadata.metadataChecksum,
      ...sqlite.prepare(`
        select intent_checksum as checksum from connector_activation_journal_entries
        order by principal_key_fingerprint, approval_id, receipt_id
      `).all().map((row) => row.checksum),
      ...sqlite.prepare(`
        select handle_checksum as checksum from connector_activation_journal_transitions
        order by principal_key_fingerprint, approval_id, receipt_id, sequence
      `).all().map((row) => row.checksum),
      ...sqlite.prepare(`
        select outcome_checksum as checksum from connector_activation_journal_outcomes
        order by principal_key_fingerprint, approval_id, receipt_id, sequence
      `).all().map((row) => row.checksum),
    ];
    for (const checksum of checksums) requiredDigest(checksum, "connector journal row checksum");
    const identity = {
      storeId: metadata.storeId,
      storePath,
      schemaVersion: metadata.schemaVersion,
      migrationManifestDigest: metadata.migrationManifestDigest,
      contentGeneration: digestJson(checksums),
      snapshotPolicy: metadata.snapshotPolicy,
      receiptReplayPolicy: metadata.receiptReplayPolicy,
      schemaFingerprint: metadata.schemaFingerprint,
      createdAtMs: metadata.createdAtMs,
    };
    assertConnectorJournalIdentity(identity);
    return Object.freeze(identity);
  } finally {
    sqlite.close();
  }
}

export function loadManagementAuthorizationKey(runtime, input) {
  assertExactKeys(input, MANAGEMENT_KEYS, "management key reference");
  const stateDir = ownerOnlyDirectory(input.stateDir, "management state directory");
  const keyRef = ownerOnlyExistingPath(input.keyRef, "management authorization key");
  const key = runtime.loadExistingManagementAuthorizationKey({ stateDir, keyRef });
  if (!key || typeof key.keyId !== "string"
    || !(key.secret instanceof Uint8Array) || key.secret.byteLength !== 32) {
    throw new Error("Management authorization key readback is invalid.");
  }
  return key;
}

export async function loadCompiledConnectorActivationRuntime() {
  const repositoryRoot = resolve(dirname(fileURLToPath(import.meta.url)), "../..");
  const module = (path) => import(pathToFileURL(join(repositoryRoot, "dist", path)).href);
  const [
    oauth, authority, evidence, finalizer, staging, journal, management, contracts,
    routeIdentity, snapshotGroup, productionUpgradeWorker,
  ] = await Promise.all([
    module("oauth-store.js"),
    module("v2/authority.js"),
    module("v2/connector-activation-evidence.js"),
    module("v2/connector-activation-finalizer.js"),
    module("v2/connector-staging-activation.js"),
    module("v2/connector-activation-journal.js"),
    module("v2/management-authorization.js"),
    module("v2/contracts.js"),
    module("v2/connector-route-identity.js"),
    module("v2/snapshot-group.js"),
    module("v2/production-upgrade-worker.js"),
  ]);
  return Object.freeze({
    ...oauth,
    ...authority,
    ...evidence,
    ...finalizer,
    ...staging,
    ...journal,
    ...management,
    ...contracts,
    ...routeIdentity,
    ...snapshotGroup,
    ...productionUpgradeWorker,
  });
}

export function writeOwnerOnlyArtifactAtomic(path, artifact) {
  const target = absolutePath(path, "output artifact");
  const parent = ownerOnlyDirectory(dirname(target), "output artifact directory");
  if (existsSync(target)) throw new Error("Output artifact already exists; immutable evidence is never overwritten.");
  const text = `${JSON.stringify(artifact, null, 2)}\n`;
  if (Buffer.byteLength(text) > MAX_JSON_BYTES) throw new Error("Output artifact exceeds the bounded size.");
  const temporary = join(parent, `.${target.split("/").at(-1)}.tmp-${process.pid}-${randomUUID()}`);
  let descriptor;
  try {
    descriptor = openSync(
      temporary,
      constants.O_CREAT | constants.O_EXCL | constants.O_WRONLY | noFollowFlag(),
      0o600,
    );
    writeFileSync(descriptor, text, "utf8");
    fsyncSync(descriptor);
    closeSync(descriptor);
    descriptor = undefined;
    linkSync(temporary, target);
    fsyncDirectory(parent);
    unlinkSync(temporary);
    fsyncDirectory(parent);
  } catch (error) {
    if (descriptor !== undefined) closeSync(descriptor);
    try { unlinkSync(temporary); } catch { /* preserve primary error */ }
    throw error;
  }
  ownerOnlyExistingPath(target, "output artifact");
  return {
    path: target,
    sha256: serializedArtifactSha256(artifact),
    ...(typeof artifact.payloadDigest === "string" ? { payloadDigest: artifact.payloadDigest } : {}),
    ...(typeof artifact.artifactDigest === "string" ? { artifactDigest: artifact.artifactDigest } : {}),
    kind: artifact.kind,
  };
}

export function preflightOwnerOnlyArtifactPath(path) {
  return ownerOnlyFuturePath(path, "output artifact");
}

export function readOwnerOnlyJson(path, label = "owner-only JSON") {
  return parseJson(readOwnerOnlyText(path, label, MAX_JSON_BYTES), label);
}

export function writeProductionApprovalDirectoryAtomic(path, bundle) {
  assertExactKeys(
    bundle,
    ["manifest", "ownerManagementApproval", "productionActivationPrecheck"],
    "production approval bundle",
  );
  if (bundle.productionActivationPrecheck?.kind !== "PRODUCTION_ACTIVATION_PRECHECK"
    || bundle.ownerManagementApproval?.kind !== "OWNER_MANAGEMENT_APPROVAL"
    || bundle.manifest?.kind !== "PRODUCTION_ACTIVATION_APPROVAL_MANIFEST") {
    throw new Error("Production approval bundle contains the wrong signed evidence kinds.");
  }
  const target = preflightProductionApprovalDirectoryForReconcile(path);
  const parent = dirname(target);
  const material = productionApprovalPublicationMaterial(target, bundle);
  if (existsSync(target)) {
    reconcileProductionApprovalDirectory(target, material);
    return productionApprovalPublicationSummary(target, material.manifest);
  }
  const temporary = join(parent, `.${target.split("/").at(-1)}.tmp-${process.pid}-${randomUUID()}`);
  mkdirSync(temporary, { mode: 0o700 });
  const precheckPath = join(temporary, "production-activation-precheck.json");
  const approvalPath = join(temporary, "owner-management-approval.json");
  const manifestPath = join(temporary, "manifest.json");
  try {
    writeOwnerOnlyArtifactAtomic(precheckPath, bundle.productionActivationPrecheck);
    writeOwnerOnlyArtifactAtomic(approvalPath, bundle.ownerManagementApproval);
    writeOwnerOnlyArtifactAtomic(manifestPath, material.manifest);
    fsyncDirectory(temporary);
    try {
      renameSync(temporary, target);
    } catch (error) {
      if (!existsSync(target)) throw error;
      for (const child of [precheckPath, approvalPath, manifestPath]) {
        try { unlinkSync(child); } catch { /* another publisher won; private temp cleanup only */ }
      }
      try { rmdirSync(temporary); } catch { /* preserve exact winner verification below */ }
      reconcileProductionApprovalDirectory(target, material);
    }
    fsyncDirectory(parent);
    ownerOnlyDirectory(target, "production approval output directory");
    return productionApprovalPublicationSummary(target, material.manifest);
  } catch (error) {
    for (const child of [precheckPath, approvalPath, manifestPath]) {
      try { unlinkSync(child); } catch { /* only the private temporary directory is cleaned */ }
    }
    try { rmdirSync(temporary); } catch { /* preserve the primary error */ }
    throw error;
  }
}

function productionApprovalPublicationMaterial(target, bundle) {
  const finalPrecheckPath = join(target, "production-activation-precheck.json");
  const finalApprovalPath = join(target, "owner-management-approval.json");
  const manifest = Object.freeze({
    ...bundle.manifest,
    productionActivationPrecheck: {
      path: finalPrecheckPath,
      sha256: serializedArtifactSha256(bundle.productionActivationPrecheck),
      payloadDigest: bundle.productionActivationPrecheck.payloadDigest,
    },
    ownerManagementApproval: {
      path: finalApprovalPath,
      sha256: serializedArtifactSha256(bundle.ownerManagementApproval),
      payloadDigest: bundle.ownerManagementApproval.payloadDigest,
    },
  });
  return Object.freeze({
    productionActivationPrecheck: bundle.productionActivationPrecheck,
    ownerManagementApproval: bundle.ownerManagementApproval,
    manifest,
  });
}

function reconcileProductionApprovalDirectory(target, material) {
  ownerOnlyDirectory(target, "production approval output directory");
  const expected = new Map([
    ["production-activation-precheck.json", material.productionActivationPrecheck],
    ["owner-management-approval.json", material.ownerManagementApproval],
    ["manifest.json", material.manifest],
  ]);
  const observed = readdirSync(target).sort();
  for (const name of observed) {
    if (!expected.has(name)) {
      throw new Error(`Production approval output contains unexpected file ${name}.`);
    }
    const path = join(target, name);
    const exact = `${JSON.stringify(expected.get(name), null, 2)}\n`;
    if (readOwnerOnlyText(path, `production approval ${name}`, MAX_JSON_BYTES) !== exact) {
      throw new Error(`Production approval output file ${name} differs from the reconstructed receipt.`);
    }
  }
  for (const [name, artifact] of expected) {
    const path = join(target, name);
    if (existsSync(path)) continue;
    try {
      writeOwnerOnlyArtifactAtomic(path, artifact);
    } catch (error) {
      if (!existsSync(path)
        || readOwnerOnlyText(path, `production approval ${name}`, MAX_JSON_BYTES)
          !== `${JSON.stringify(artifact, null, 2)}\n`) {
        throw error;
      }
    }
  }
  fsyncDirectory(target);
}

function productionApprovalPublicationSummary(target, manifest) {
  return Object.freeze({
    directoryPath: target,
    manifestPath: join(target, "manifest.json"),
    productionActivationPrecheckPath: join(target, "production-activation-precheck.json"),
    ownerManagementApprovalPath: join(target, "owner-management-approval.json"),
    transactionId: manifest.transactionId,
    predecisionDigest: manifest.predecisionDigest,
    requestBindingDigest: manifest.requestBindingDigest,
    snapshotGroupDigest: manifest.snapshotGroupDigest,
    snapshotManifestSha256: manifest.snapshotManifestSha256,
    finalizationStorePath: manifest.finalizationStorePath,
    finalizationPrepareDigest: manifest.finalizationPrepareDigest,
    finalizationContentGeneration: manifest.finalizationContentGeneration,
    receiptId: manifest.receiptId,
    tupleDigest: manifest.tupleDigest,
    activePreimageDigest: manifest.activePreimageDigest,
    finalizationPlanDigest: manifest.finalizationPlanDigest,
    tuple: manifest.tuple,
    candidateIdentity: manifest.candidateIdentity,
    migrationManifestDigest: manifest.migrationManifestDigest,
    productionEnvironmentIdentityDigest: manifest.productionEnvironmentIdentityDigest,
    productionRouteIdentityDigest: manifest.productionRouteIdentityDigest,
    oauthResource: manifest.oauthResource,
    journalIdentity: manifest.journalIdentity,
  });
}

export function preflightProductionApprovalDirectory(path) {
  const target = absolutePath(path, "production approval output directory");
  const parent = ownerOnlyDirectory(dirname(target), "production approval parent directory");
  if (existsSync(target)) throw new Error("Production approval output already exists.");
  const base = target.slice(parent.length + 1);
  if (!base || base === "." || base === ".." || base.includes("/")) {
    throw new Error("Production approval output directory name is invalid.");
  }
  return target;
}

export function preflightProductionApprovalDirectoryForReconcile(path) {
  const target = absolutePath(path, "production approval output directory");
  const parent = ownerOnlyDirectory(dirname(target), "production approval parent directory");
  const base = target.slice(parent.length + 1);
  if (!base || base === "." || base === ".." || base.includes("/")) {
    throw new Error("Production approval output directory name is invalid.");
  }
  if (existsSync(target)) ownerOnlyDirectory(target, "production approval output directory");
  return target;
}

export function createEvidenceLedgerRecord(
  { sequence, previousRecordDigest, source, kind, occurredAtMs, payload },
  runtime,
) {
  const unsigned = {
    schemaVersion: 1,
    sequence,
    ...(previousRecordDigest ? { previousRecordDigest } : {}),
    source,
    kind,
    occurredAtMs,
    payload,
  };
  const record = { ...unsigned, recordDigest: digestJson(unsigned) };
  validateLedgerRecord(record, sequence, previousRecordDigest, source, runtime);
  return record;
}

export function sealArtifact(kind, payload) {
  const unsigned = { schemaVersion: 1, kind, payload };
  return Object.freeze({ ...unsigned, artifactDigest: digestJson(unsigned) });
}

class EvidenceLedger {
  constructor(path, expectedSource, runtime) {
    const text = readOwnerOnlyText(path, "evidence ledger", MAX_LEDGER_BYTES);
    if (text && !text.endsWith("\n")) throw new Error("Evidence ledger has an incomplete trailing record.");
    this.records = [];
    this.byDigest = new Map();
    let previous;
    for (const line of text.split("\n")) {
      if (!line) continue;
      const record = parseJson(line, "evidence ledger record");
      validateLedgerRecord(record, this.records.length + 1, previous, expectedSource, runtime);
      if (this.byDigest.has(record.recordDigest)) throw new Error("Evidence ledger record digest is duplicated.");
      this.records.push(Object.freeze(record));
      this.byDigest.set(record.recordDigest, Object.freeze(record));
      previous = record.recordDigest;
    }
  }

  require(recordId, expectedKind) {
    requiredDigest(recordId, "recordId");
    const record = this.byDigest.get(recordId);
    if (!record || record.kind !== expectedKind) {
      throw new Error(`Trusted evidence record ${expectedKind} is missing.`);
    }
    return record;
  }

  find(kind, predicate) {
    return this.records.filter((record) => record.kind === kind && predicate(record));
  }
}

class OperationAuditReader {
  constructor(path) {
    const text = readOwnerOnlyText(path, "operation audit log", MAX_LEDGER_BYTES);
    if (text && !text.endsWith("\n")) throw new Error("Operation audit log has an incomplete trailing record.");
    this.records = [];
    let previous;
    for (const line of text.split("\n")) {
      if (!line) continue;
      const record = parseJson(line, "operation audit record");
      validateAuditRecord(record, this.records.length + 1, previous);
      this.records.push(Object.freeze(record));
      previous = record.eventDigest;
    }
  }

  requireOperation(operationId, correlationId) {
    const matches = this.records.filter((record) => (
      record.operationId === operationId && record.correlationId === correlationId
    ));
    if (matches.length !== 1) throw new Error("Broker request does not select one exact operation audit record.");
    return matches[0];
  }
}

class OAuthActivationReadAdapter {
  constructor(path, runtime) {
    this.path = ownerOnlyExistingPath(path, "OAuth database");
    this.runtime = runtime;
    this.sqlite = new Database(this.path, { readonly: true, fileMustExist: true });
    this.sqlite.pragma("query_only = ON");
    this.sqlite.pragma("foreign_keys = ON");
    const integrity = this.sqlite.pragma("quick_check", { simple: true });
    if (integrity !== "ok") {
      this.sqlite.close();
      throw new Error("OAuth database integrity readback failed.");
    }
  }

  close() {
    this.sqlite.close();
  }

  requireBinding(bindingId) {
    requiredText(bindingId, "bindingId", 256);
    const rows = this.sqlite.prepare(`
      select binding_id, canonical_name, client_id, installation_epoch, schema_generation,
             authority_contract_generation, redirect_uris_digest, build_digest, drain_epoch,
             drain_deadline_at, refresh_allowed_during_drain, state, state_reason, ref_count,
             created_at, updated_at
        from oauth_connector_bindings where binding_id = ?
    `).all(bindingId);
    if (rows.length !== 1) throw new Error("OAuth connector binding readback is missing or ambiguous.");
    const row = rows[0];
    return {
      bindingId: row.binding_id,
      canonicalName: row.canonical_name,
      clientId: row.client_id,
      installationEpoch: row.installation_epoch,
      schemaGeneration: row.schema_generation,
      ...(row.authority_contract_generation === null ? {} : { authorityContractGeneration: row.authority_contract_generation }),
      ...(row.redirect_uris_digest === null ? {} : { redirectUrisDigest: row.redirect_uris_digest }),
      ...(row.build_digest === null ? {} : { buildDigest: row.build_digest }),
      drainEpoch: row.drain_epoch,
      ...(row.drain_deadline_at === null ? {} : { drainDeadlineAt: row.drain_deadline_at }),
      refreshAllowedDuringDrain: row.refresh_allowed_during_drain === 1,
      state: row.state,
      ...(row.state_reason === null ? {} : { stateReason: row.state_reason }),
      refCount: row.ref_count,
      createdAt: row.created_at,
      updatedAt: row.updated_at,
    };
  }

  requireActiveBinding(canonicalName) {
    requiredText(canonicalName, "canonicalName", 128);
    const rows = this.sqlite.prepare(
      "select binding_id from oauth_connector_bindings where canonical_name = ? and state = 'ACTIVE'",
    ).all(canonicalName);
    if (rows.length !== 1) {
      throw new Error("OAuth readback does not contain one exact canonical ACTIVE connector.");
    }
    return this.requireBinding(rows[0].binding_id);
  }

  getPreparedActivationReceipt(canonicalName) {
    requiredText(canonicalName, "canonicalName", 128);
    const rows = this.sqlite.prepare(`
      select receipt_id from oauth_connector_activation_receipts
       where canonical_name = ? and status = 'PREPARED'
       order by receipt_id
    `).all(canonicalName);
    if (rows.length > 1) {
      throw new Error("OAuth readback contains multiple PREPARED receipts for one canonical connector.");
    }
    return rows.length === 0 ? undefined : this.requireActivationReceipt(rows[0].receipt_id);
  }

  requireActivationReceipt(receiptId) {
    requiredText(receiptId, "activation receiptId", 256);
    const rows = this.sqlite.prepare(`
      select receipt_id, canonical_name, candidate_binding_id, client_id, installation_epoch,
             schema_generation, authority_contract_generation, redirect_uris_digest, build_digest,
             tuple_digest, preimage_digest, previous_active_binding_id, owner_authority_id,
             drain_deadline_at, refresh_allowed_during_drain, status, failure_code,
             prepared_at, activated_at, failed_at
        from oauth_connector_activation_receipts where receipt_id = ?
    `).all(receiptId);
    if (rows.length !== 1) throw new Error("OAuth connector activation receipt is missing or ambiguous.");
    const row = rows[0];
    const tuple = {
      canonicalName: row.canonical_name,
      candidateBindingId: row.candidate_binding_id,
      clientId: row.client_id,
      installationEpoch: row.installation_epoch,
      schemaGeneration: row.schema_generation,
      authorityContractGeneration: row.authority_contract_generation,
      redirectUrisDigest: row.redirect_uris_digest,
      buildDigest: row.build_digest,
    };
    if (row.tuple_digest !== this.runtime.connectorActivationTupleDigest(tuple)) {
      throw new Error("OAuth activation receipt tuple digest is not canonical.");
    }
    const receipt = {
      receiptId: row.receipt_id,
      tuple,
      tupleDigest: row.tuple_digest,
      ...(row.previous_active_binding_id === null ? {} : { previousActiveBindingId: row.previous_active_binding_id }),
      preimageDigest: row.preimage_digest,
      ...(row.owner_authority_id === null ? {} : { ownerAuthorityId: row.owner_authority_id }),
      drainDeadlineAt: row.drain_deadline_at,
      refreshAllowedDuringDrain: row.refresh_allowed_during_drain === 1,
      status: row.status,
      ...(row.failure_code === null ? {} : { failureCode: row.failure_code }),
      preparedAt: row.prepared_at,
      ...(row.activated_at === null ? {} : { activatedAt: row.activated_at }),
      ...(row.failed_at === null ? {} : { failedAt: row.failed_at }),
    };
    const authority = this.getActivationAuthorityReceipt(receiptId);
    return authority ? { ...receipt, activationAuthority: authority } : receipt;
  }

  getActivationAuthorityReceipt(receiptId) {
    const rows = this.sqlite.prepare(`
      select action_claim_id, receipt_id, authority_id, principal_key_fingerprint,
             action_fingerprint, resource_key_sha256, fencing_token, risk, claim_state,
             approval_assurance, canonical_name, tuple_digest, active_preimage_digest,
             finalization_plan_digest, evidence_digest, claimed_at_ms, dispatched_at_ms,
             proof_digest, consumed_at
        from oauth_connector_activation_authorities where receipt_id = ?
    `).all(receiptId);
    if (rows.length > 1) throw new Error("OAuth activation authority receipt is ambiguous.");
    if (rows.length === 0) return undefined;
    const row = rows[0];
    return {
      schemaVersion: 1,
      authorityId: row.authority_id,
      actionClaimId: row.action_claim_id,
      actionFingerprint: row.action_fingerprint,
      resourceKeySha256: row.resource_key_sha256,
      fencingToken: row.fencing_token,
      principalKeyFingerprint: row.principal_key_fingerprint,
      risk: row.risk,
      claimState: row.claim_state,
      approvalAssurance: row.approval_assurance,
      receiptId: row.receipt_id,
      canonicalName: row.canonical_name,
      tupleDigest: row.tuple_digest,
      activePreimageDigest: row.active_preimage_digest,
      finalizationPlanDigest: row.finalization_plan_digest,
      evidenceDigest: row.evidence_digest,
      claimedAtMs: row.claimed_at_ms,
      dispatchedAtMs: row.dispatched_at_ms,
      proofDigest: row.proof_digest,
      consumedAt: row.consumed_at,
    };
  }

  requireTokenFamilyByDigest(familyIdDigest) {
    requiredDigest(familyIdDigest, "token family digest");
    const rows = this.sqlite.prepare(`
      select family_id, client_id, connector_binding_id, installation_epoch, drain_epoch,
             status, rotation_sequence, created_at, rotated_at, revoked_at
        from oauth_token_families order by family_id
    `).all().filter((row) => digestText(row.family_id) === familyIdDigest);
    if (rows.length !== 1) throw new Error("Token-family digest does not select one exact OAuth family.");
    const row = rows[0];
    return {
      clientId: row.client_id,
      connectorBindingId: row.connector_binding_id,
      installationEpoch: row.installation_epoch,
      drainEpoch: row.drain_epoch,
      status: row.status,
      rotationSequence: row.rotation_sequence,
      createdAt: row.created_at,
      ...(row.rotated_at === null ? {} : { rotatedAt: row.rotated_at }),
      ...(row.revoked_at === null ? {} : { revokedAt: row.revoked_at }),
    };
  }

  countActiveCanonical(canonicalName) {
    const row = this.sqlite.prepare(
      "select count(*) as count from oauth_connector_bindings where canonical_name = ? and state = 'ACTIVE'",
    ).get(canonicalName);
    return row.count;
  }
}

class AuthorityReadAdapter {
  constructor(path) {
    this.path = ownerOnlyExistingPath(path, "authority database");
    this.sqlite = new Database(this.path, { readonly: true, fileMustExist: true });
    this.sqlite.pragma("query_only = ON");
    this.sqlite.pragma("foreign_keys = ON");
    const integrity = this.sqlite.pragma("quick_check", { simple: true });
    if (integrity !== "ok") {
      this.sqlite.close();
      throw new Error("Authority database integrity readback failed.");
    }
  }

  close() {
    this.sqlite.close();
  }

  requireMutationPass(expected) {
    const rows = this.#claims().filter((row) => (
      row.principalKeyFingerprint === expected.principalKeyFingerprint
      && row.actionFingerprint === expected.actionFingerprint
      && row.resourceKeySha256 === expected.resourceKeySha256
      && row.auditEventDigest === expected.auditEventDigest
      && row.tool === expected.tool
      && row.operation === expected.operation
    ));
    if (rows.length !== 1) throw new Error("Mutation evidence does not select one exact authority claim.");
    const row = rows[0];
    assertAuthorityPassRow(row);
    return { ...row, receiptDigest: authorityReceiptDigest(row) };
  }

  requireActivationPass(receipt) {
    const rows = this.#claims().filter((row) => (
      row.authorityId === receipt.authorityId
      && row.actionClaimId === receipt.actionClaimId
      && row.principalKeyFingerprint === receipt.principalKeyFingerprint
      && row.actionFingerprint === receipt.actionFingerprint
      && row.resourceKeySha256 === receipt.resourceKeySha256
      && row.fencingToken === receipt.fencingToken
      && row.tool === "context"
      && row.operation === "connector_activation_finalize"
    ));
    if (rows.length !== 1) throw new Error("OAuth activation authority does not select one exact durable claim.");
    const row = rows[0];
    assertAuthorityPassRow(row, false);
    if (row.risk !== "R3" || row.maximumUses !== 1 || row.consumedUses !== 1
      || row.dispatchedAtMs !== receipt.dispatchedAtMs || row.claimedAtMs !== receipt.claimedAtMs) {
      throw new Error("Durable activation authority is not the exact R3 one-shot OAuth proof.");
    }
    return { ...row, receiptDigest: authorityReceiptDigest(row) };
  }

  #claims() {
    return this.sqlite.prepare(`
      select c.authority_id as authorityId, c.action_claim_id as actionClaimId,
             c.action_id as actionId, c.task_instance_id as taskInstanceId,
             c.principal_key_fingerprint as principalKeyFingerprint,
             c.action_fingerprint as actionFingerprint,
             c.resource_key_sha256 as resourceKeySha256,
             c.fencing_token as fencingToken, c.claimed_at_ms as claimedAtMs,
             c.dispatched_at_ms as dispatchedAtMs, c.completed_at_ms as completedAtMs,
             c.state, c.provider_call_count as providerCallCount,
             c.error_code as errorCode, c.reason_code as reasonCode,
             c.audit_state as auditState, c.audit_event_digest as auditEventDigest,
             c.audit_receipt_digest as auditReceiptDigest,
             c.audit_recorded_at_ms as auditRecordedAtMs,
             a.tool, a.operation, a.risk, a.maximum_uses as maximumUses,
             a.consumed_uses as consumedUses,
             a.fingerprint as durableActionFingerprint,
             a.resource_key_sha256 as durableResourceKeySha256,
             coalesce(l.lease_state, case when c.state = 'UNCERTAIN' then 'RECOVERY_REQUIRED' else 'RELEASED' end)
               as leaseState
        from operation_authority_claims c
        join operation_authority_actions a
          on a.authority_id = c.authority_id and a.action_id = c.action_id
        left join operation_authority_resource_leases l
          on l.resource_key_sha256 = c.resource_key_sha256
         and l.action_claim_id = c.action_claim_id and l.fencing_token = c.fencing_token
    `).all();
  }
}

function validateLedgerRecord(record, expectedSequence, expectedPrevious, expectedSource, runtime) {
  const keys = expectedPrevious
    ? ["kind", "occurredAtMs", "payload", "previousRecordDigest", "recordDigest", "schemaVersion", "sequence", "source"]
    : ["kind", "occurredAtMs", "payload", "recordDigest", "schemaVersion", "sequence", "source"];
  assertExactKeys(record, keys, "evidence ledger record");
  if (record.schemaVersion !== 1 || record.sequence !== expectedSequence || record.source !== expectedSource) {
    throw new Error("Evidence ledger sequence or source is invalid.");
  }
  if (record.previousRecordDigest !== expectedPrevious) throw new Error("Evidence ledger hash chain is invalid.");
  requiredTimestamp(record.occurredAtMs, "evidence occurredAtMs");
  requiredText(record.kind, "evidence kind", 128);
  requiredDigest(record.recordDigest, "evidence recordDigest");
  const { recordDigest, ...unsigned } = record;
  if (recordDigest !== digestJson(unsigned)) throw new Error("Evidence ledger record digest is invalid.");
  validateLedgerPayload(record.source, record.kind, record.payload, runtime);
}

function validateLedgerPayload(source, kind, payload, runtime) {
  if (source === HOST_SOURCE && kind === "CHATGPT_STAGING_DISCOVERY_R0") {
    assertExactKeys(payload, [
      "discovery", "environmentIdentityDigest", "managementCorrelationId", "managementNonce",
      "r0Canary", "routeIdentityDigest", "stagingActivationPrecheckId",
    ], kind);
    requiredText(payload.stagingActivationPrecheckId, "stagingActivationPrecheckId", 256);
    requiredText(payload.managementNonce, "managementNonce", 512);
    requiredText(payload.managementCorrelationId, "managementCorrelationId", 256);
    requiredDigest(payload.environmentIdentityDigest, "environmentIdentityDigest");
    requiredDigest(payload.routeIdentityDigest, "routeIdentityDigest");
    validateHostDiscovery(payload.discovery);
    assertExactKeys(payload.r0Canary, ["brokerRequestRecordId", "sessionIdentityDigest", "transcriptDigest"], "Host R0 canary");
    requiredDigest(payload.r0Canary.brokerRequestRecordId, "R0 broker request recordId");
    requiredDigest(payload.r0Canary.sessionIdentityDigest, "R0 session identity");
    requiredDigest(payload.r0Canary.transcriptDigest, "R0 transcript");
    return;
  }
  if (source === HOST_SOURCE && kind === "CHATGPT_A_TO_B_CANARY") {
    assertExactKeys(payload, [
      "discovery", "environmentIdentityDigest", "foreignClient", "hostCanaryId",
      "managementCorrelationId", "managementNonce", "routeIdentityDigest", "sessionA", "sessionB", "stage",
    ], kind);
    if (!["PRE_CUTOVER_HOST_CANARY", "POST_ACTIVATION_HOST_CANARY"].includes(payload.stage)) {
      throw new Error("Host A/B canary stage is invalid.");
    }
    requiredText(payload.hostCanaryId, "hostCanaryId", 256);
    requiredText(payload.managementNonce, "managementNonce", 512);
    requiredText(payload.managementCorrelationId, "managementCorrelationId", 256);
    requiredDigest(payload.environmentIdentityDigest, "environmentIdentityDigest");
    requiredDigest(payload.routeIdentityDigest, "routeIdentityDigest");
    validateHostDiscovery(payload.discovery);
    assertExactKeys(payload.sessionA, [
      "authorizationRequestRecordId", "authorizationTranscriptDigest", "authorizedAtMs",
      "closeRequestRecordId", "closeTranscriptDigest", "closedAtMs", "sessionIdentityDigest",
    ], "Host session A");
    requiredDigest(payload.sessionA.authorizationRequestRecordId, "authorization request recordId");
    requiredDigest(payload.sessionA.authorizationTranscriptDigest, "authorization transcript");
    requiredTimestamp(payload.sessionA.authorizedAtMs, "session A authorizedAtMs");
    requiredDigest(payload.sessionA.closeRequestRecordId, "close request recordId");
    requiredDigest(payload.sessionA.closeTranscriptDigest, "close transcript");
    requiredTimestamp(payload.sessionA.closedAtMs, "session A closedAtMs");
    requiredDigest(payload.sessionA.sessionIdentityDigest, "session A identity");
    assertExactKeys(payload.sessionB, [
      "mutationAtMs", "mutationRequestRecordId", "mutationTranscriptDigest", "sessionIdentityDigest",
    ], "Host session B");
    requiredTimestamp(payload.sessionB.mutationAtMs, "session B mutationAtMs");
    requiredDigest(payload.sessionB.mutationRequestRecordId, "mutation request recordId");
    requiredDigest(payload.sessionB.mutationTranscriptDigest, "mutation transcript");
    requiredDigest(payload.sessionB.sessionIdentityDigest, "session B identity");
    assertExactKeys(payload.foreignClient, [
      "observedAtMs", "rejectionRequestRecordId", "rejectionTranscriptDigest", "sessionIdentityDigest",
    ], "Host foreign client");
    requiredTimestamp(payload.foreignClient.observedAtMs, "foreign observedAtMs");
    requiredDigest(payload.foreignClient.rejectionRequestRecordId, "foreign request recordId");
    requiredDigest(payload.foreignClient.rejectionTranscriptDigest, "foreign transcript");
    requiredDigest(payload.foreignClient.sessionIdentityDigest, "foreign session identity");
    return;
  }
  if (source === HOST_SOURCE && kind === "CHATGPT_ROLLBACK_HOST") {
    assertExactKeys(payload, [
      "challengeId", "managementCorrelationId", "sessionA", "sessionB", "transactionId",
    ], kind);
    requiredText(payload.challengeId, "rollback Host challengeId", 256);
    requiredText(payload.transactionId, "rollback Host transactionId", 512);
    requiredText(payload.managementCorrelationId, "rollback Host managementCorrelationId", 256);
    assertExactKeys(payload.sessionA, [
      "healthReadbackRecordId", "sessionIdentityDigest", "transcriptDigest",
    ], "rollback Host session A");
    requiredDigest(payload.sessionA.healthReadbackRecordId, "rollback health recordId");
    requiredDigest(payload.sessionA.sessionIdentityDigest, "rollback session A identity");
    requiredDigest(payload.sessionA.transcriptDigest, "rollback session A transcript");
    assertExactKeys(payload.sessionB, [
      "readyReadbackRecordId", "runtimeReadbackRecordId", "sessionIdentityDigest", "transcriptDigest",
    ], "rollback Host session B");
    requiredDigest(payload.sessionB.readyReadbackRecordId, "rollback ready recordId");
    requiredDigest(payload.sessionB.runtimeReadbackRecordId, "rollback runtime recordId");
    requiredDigest(payload.sessionB.sessionIdentityDigest, "rollback session B identity");
    requiredDigest(payload.sessionB.transcriptDigest, "rollback session B transcript");
    return;
  }
  if (source !== BROKER_SOURCE) throw new Error("Evidence ledger contains an unsupported source/kind pair.");
  if (kind === "CANDIDATE_READBACK") {
    assertExactKeys(payload, [
      "activePreimageDigest", "bindingId", "bindingState", "candidateIdentity", "canonicalName", "clientId",
      "environmentIdentityDigest", "environmentRole", "installationEpoch", "oauthResource",
      "migrationManifestDigest", "packageRoot", "receiptId", "redirectUrisDigest", "routeIdentityDigest",
    ], kind);
    if (!["STAGING", "PRODUCTION"].includes(payload.environmentRole)
      || !["VERIFIED", "ACTIVATION_PREPARED", "ACTIVE"].includes(payload.bindingState)) {
      throw new Error("Candidate readback environment role or binding state is invalid.");
    }
    requiredDigest(payload.environmentIdentityDigest, "candidate environment identity");
    requiredDigest(payload.routeIdentityDigest, "candidate route identity");
    requiredHttpsUrl(payload.oauthResource, "candidate OAuth resource");
    requiredDigest(payload.migrationManifestDigest, "candidate migrationManifestDigest");
    absolutePath(payload.packageRoot, "candidate immutable package root");
    validateCandidateIdentity(payload.candidateIdentity);
    requiredText(payload.canonicalName, "candidate canonicalName", 128);
    requiredText(payload.clientId, "candidate clientId", 256);
    requiredText(payload.bindingId, "candidate bindingId", 256);
    requiredDigest(payload.redirectUrisDigest, "candidate redirectUrisDigest");
    if (!runtime
      || typeof runtime.connectorEnvironmentIdentityDigest !== "function"
      || typeof runtime.connectorRouteIdentityDigest !== "function") {
      throw new Error("Candidate readback validation requires the connector route identity runtime.");
    }
    const derivedEnvironmentIdentityDigest = runtime.connectorEnvironmentIdentityDigest({
      environmentRole: payload.environmentRole,
      runtimeIdentityDigest: payload.candidateIdentity.runtimeIdentityDigest,
      oauthResource: payload.oauthResource,
    });
    if (payload.environmentIdentityDigest !== derivedEnvironmentIdentityDigest) {
      throw new Error("Candidate environment identity does not match the derived runtime/resource binding.");
    }
    const derivedRouteIdentityDigest = runtime.connectorRouteIdentityDigest({
      oauthResource: payload.oauthResource,
      canonicalName: payload.canonicalName,
      bindingId: payload.bindingId,
    });
    if (payload.routeIdentityDigest !== derivedRouteIdentityDigest) {
      throw new Error("Candidate route identity does not match the derived OAuth/binding route.");
    }
    if (!Number.isSafeInteger(payload.installationEpoch) || payload.installationEpoch < 1) {
      throw new Error("Candidate installationEpoch is invalid.");
    }
    if (payload.receiptId !== null) requiredText(payload.receiptId, "candidate receiptId", 256);
    if (payload.activePreimageDigest !== null) {
      requiredDigest(payload.activePreimageDigest, "candidate activePreimageDigest");
    }
    if (payload.environmentRole === "PRODUCTION" && payload.bindingState === "VERIFIED"
      && payload.activePreimageDigest === null) {
      throw new Error("Production VERIFIED candidate readback requires the canonical ACTIVE preimage digest.");
    }
    return;
  }
  if (kind === "ROLLBACK_PREIMAGE_READBACK") {
    assertExactKeys(payload, [
      "managementCorrelationId", "previousMainMigrationIdentityDigest",
      "previousRuntimeIdentityDigest", "transactionId",
    ], kind);
    requiredText(payload.transactionId, "rollback transactionId", 512);
    requiredText(payload.managementCorrelationId, "rollback managementCorrelationId", 256);
    requiredDigest(payload.previousRuntimeIdentityDigest, "rollback previous runtime identity");
    requiredDigest(payload.previousMainMigrationIdentityDigest, "rollback previous main migration identity");
    return;
  }
  if (kind === "ROLLBACK_HEALTH_READBACK") {
    assertExactKeys(payload, [
      "challengeId", "correlationId", "httpStatus", "nonce", "responseDigest",
      "sessionIdentityDigest", "transactionId",
    ], kind);
    validateRollbackReadbackCommon(payload);
    if (!Number.isSafeInteger(payload.httpStatus) || payload.httpStatus < 100 || payload.httpStatus > 599) {
      throw new Error(`${kind} httpStatus is invalid.`);
    }
    return;
  }
  if (kind === "ROLLBACK_READY_READBACK") {
    assertExactKeys(payload, [
      "challengeId", "correlationId", "httpStatus", "nonce", "responseDigest",
      "runtimeIdentityDigest", "sessionIdentityDigest", "transactionId",
    ], kind);
    validateRollbackReadbackCommon(payload);
    if (!Number.isSafeInteger(payload.httpStatus) || payload.httpStatus < 100 || payload.httpStatus > 599) {
      throw new Error(`${kind} httpStatus is invalid.`);
    }
    requiredDigest(payload.runtimeIdentityDigest, "rollback ready runtime identity");
    return;
  }
  if (kind === "ROLLBACK_RUNTIME_READBACK") {
    assertExactKeys(payload, [
      "challengeId", "correlationId", "cwd", "mainMigrationIdentityDigest", "nonce", "processName",
      "processStatus", "responseDigest", "runtimeIdentityDigest", "script", "sessionIdentityDigest",
      "transactionId",
    ], kind);
    validateRollbackReadbackCommon(payload);
    if (typeof payload.processName !== "string" || !SAFE_ID.test(payload.processName)) {
      throw new Error("rollback runtime processName is invalid.");
    }
    if (payload.processStatus !== "online") throw new Error("rollback runtime processStatus must be online.");
    if (absolutePath(payload.cwd, "rollback runtime cwd") !== payload.cwd
      || absolutePath(payload.script, "rollback runtime script") !== payload.script) {
      throw new Error("Rollback runtime cwd and script must be normalized absolute paths.");
    }
    requiredDigest(payload.runtimeIdentityDigest, "rollback runtime identity");
    requiredDigest(payload.mainMigrationIdentityDigest, "rollback main migration identity");
    return;
  }
  if (kind === "TOOL_DISCOVERY") {
    assertExactKeys(payload, [
      "clientId", "correlationId", "environmentIdentityDigest", "managementCorrelationId",
      "principalKeyFingerprint", "requestId", "responseDigest", "routeIdentityDigest",
      "sessionIdentityDigest", "toolNames",
    ], kind);
    validateBrokerCommon(payload);
    requiredDigest(payload.responseDigest, "discovery responseDigest");
    validateTools(payload.toolNames);
    return;
  }
  if (kind === "TOOL_REQUEST") {
    assertExactKeys(payload, [
      "action", "argumentsDigest", "clientId", "correlationId", "environmentIdentityDigest",
      "managementCorrelationId", "operation", "operationId", "outcome", "principalKeyFingerprint",
      "requestId", "resourceDigest", "responseDigest", "routeIdentityDigest", "sessionIdentityDigest", "tool",
    ], kind);
    validateBrokerCommon(payload);
    requiredText(payload.operationId, "operationId", 256);
    requiredText(payload.tool, "tool", 64);
    requiredText(payload.operation, "operation", 128);
    requiredDigest(payload.argumentsDigest, "argumentsDigest");
    requiredDigest(payload.resourceDigest, "resourceDigest");
    requiredDigest(payload.responseDigest, "responseDigest");
    if (!["PASS", "AUTHORITY_PRINCIPAL_MISMATCH"].includes(payload.outcome)) {
      throw new Error("Broker tool request outcome is invalid.");
    }
    validateAction(payload.action, payload.tool, payload.operation);
    return;
  }
  if (kind === "OAUTH_AUTHORIZATION") {
    assertExactKeys(payload, [
      "authorizationEvidenceDigest", "clientId", "correlationId", "environmentIdentityDigest",
      "managementCorrelationId", "oauthResource", "principalKeyFingerprint", "requestId",
      "routeIdentityDigest", "sessionIdentityDigest", "tokenFamilyIdDigest",
    ], kind);
    validateBrokerCommon(payload);
    requiredHttpsUrl(payload.oauthResource, "authorization OAuth resource");
    requiredDigest(payload.tokenFamilyIdDigest, "authorization token family digest");
    requiredDigest(payload.authorizationEvidenceDigest, "authorization evidence digest");
    return;
  }
  if (kind === "SESSION_CLOSE") {
    assertExactKeys(payload, [
      "closeEvidenceDigest", "correlationId", "managementCorrelationId", "requestId", "sessionIdentityDigest",
    ], kind);
    requiredText(payload.requestId, "close requestId", 256);
    requiredText(payload.correlationId, "close correlationId", 256);
    requiredText(payload.managementCorrelationId, "close managementCorrelationId", 256);
    requiredDigest(payload.sessionIdentityDigest, "close session identity");
    requiredDigest(payload.closeEvidenceDigest, "close evidence digest");
    return;
  }
  if (kind === "PROVIDER_DISPATCH") {
    assertExactKeys(payload, [
      "correlationId", "operation", "operationId", "requestRecordId", "resourceDigest", "resultDigest", "tool",
    ], kind);
    requiredDigest(payload.requestRecordId, "dispatch requestRecordId");
    requiredText(payload.correlationId, "dispatch correlationId", 256);
    requiredText(payload.operationId, "dispatch operationId", 256);
    requiredText(payload.tool, "dispatch tool", 64);
    requiredText(payload.operation, "dispatch operation", 128);
    requiredDigest(payload.resourceDigest, "dispatch resourceDigest");
    requiredDigest(payload.resultDigest, "dispatch resultDigest");
    return;
  }
  if (kind === "RESOURCE_READBACK") {
    assertExactKeys(payload, ["correlationId", "readbackDigest", "requestRecordId", "resourceDigest"], kind);
    requiredDigest(payload.requestRecordId, "readback requestRecordId");
    requiredText(payload.correlationId, "readback correlationId", 256);
    requiredDigest(payload.resourceDigest, "readback resourceDigest");
    requiredDigest(payload.readbackDigest, "readbackDigest");
    return;
  }
  if (kind === "CLEANUP_DISPATCH") {
    assertExactKeys(payload, [
      "cleanupArgumentsDigest", "cleanupOperation", "correlationId", "requestRecordId", "resourceDigest", "resultDigest",
    ], kind);
    requiredDigest(payload.requestRecordId, "cleanup requestRecordId");
    requiredText(payload.correlationId, "cleanup correlationId", 256);
    requiredDigest(payload.resourceDigest, "cleanup resourceDigest");
    requiredText(payload.cleanupOperation, "cleanupOperation", 128);
    requiredDigest(payload.cleanupArgumentsDigest, "cleanupArgumentsDigest");
    requiredDigest(payload.resultDigest, "cleanup resultDigest");
    return;
  }
  if (kind === "RESOURCE_ABSENCE_READBACK") {
    assertExactKeys(payload, ["absenceEvidenceDigest", "cleanupRecordId", "resourceDigest"], kind);
    requiredDigest(payload.cleanupRecordId, "absence cleanupRecordId");
    requiredDigest(payload.resourceDigest, "absence resourceDigest");
    requiredDigest(payload.absenceEvidenceDigest, "absenceEvidenceDigest");
    return;
  }
  if (kind === "OWNER_APPROVAL_DECISION") {
    assertExactKeys(payload, [
      "approvalId", "approvedAtMs", "authorityText", "conditionsDigest", "expiresAtMs",
      "managementCorrelationId", "stage",
    ], kind);
    if (!["STAGING_ACTIVATION", "PRODUCTION_ACTIVATION"].includes(payload.stage)) {
      throw new Error("Owner approval decision stage is invalid.");
    }
    requiredText(payload.approvalId, "approvalId", 256);
    requiredText(payload.authorityText, "authorityText", 8_000);
    requiredText(payload.managementCorrelationId, "approval managementCorrelationId", 256);
    requiredDigest(payload.conditionsDigest, "approval conditionsDigest");
    requiredTimestamp(payload.approvedAtMs, "approvedAtMs");
    requiredTimestamp(payload.expiresAtMs, "expiresAtMs");
    return;
  }
  throw new Error(`Evidence ledger kind is unsupported: ${kind}`);
}

function validateHostDiscovery(value) {
  assertExactKeys(value, ["brokerRequestRecordId", "sessionIdentityDigest", "toolNames", "transcriptDigest"], "Host discovery");
  requiredDigest(value.brokerRequestRecordId, "discovery broker request recordId");
  requiredDigest(value.sessionIdentityDigest, "discovery session identity");
  requiredDigest(value.transcriptDigest, "discovery transcript");
  validateTools(value.toolNames);
}

function validateBrokerCommon(payload) {
  requiredText(payload.requestId, "broker requestId", 256);
  requiredText(payload.correlationId, "broker correlationId", 256);
  requiredText(payload.managementCorrelationId, "broker managementCorrelationId", 256);
  requiredDigest(payload.sessionIdentityDigest, "broker session identity");
  requiredText(payload.clientId, "broker clientId", 256);
  requiredRawDigest(payload.principalKeyFingerprint, "broker principal fingerprint");
  requiredDigest(payload.environmentIdentityDigest, "broker environment identity");
  requiredDigest(payload.routeIdentityDigest, "broker route identity");
}

function validateCandidateIdentity(value) {
  assertExactKeys(value, [
    "authorityContractGeneration", "buildCapabilityManifestDigest", "buildDigest", "generatedSchemaDigest",
    "packageSha256", "runtimeIdentityDigest", "schemaGeneration",
  ], "candidate identity");
  for (const [key, child] of Object.entries(value)) requiredDigest(child, `candidate ${key}`);
}

function validateAction(value, expectedTool, expectedOperation) {
  assertExactKeys(value, ["operation", "parameters", "resource", "target", "tool"], "broker authority action");
  if (value.tool !== expectedTool || value.operation !== expectedOperation) {
    throw new Error("Broker authority action does not match the tool request.");
  }
  requiredText(value.tool, "action tool", 64);
  requiredText(value.operation, "action operation", 128);
  if (value.target !== null) requiredText(value.target, "action target", 512);
  if (value.resource !== null) requiredText(value.resource, "action resource", 2_048);
  if (!isPlainObject(value.parameters)) throw new Error("Broker authority action parameters are invalid.");
  assertSecretFreeJson(value.parameters, "action.parameters");
}

function validateTools(value) {
  if (!Array.isArray(value) || !objectsEqual(value, EXPECTED_TOOLS)) {
    throw new Error("Tool discovery is not exactly the canonical eight tools.");
  }
}

function validateRollbackReadbackCommon(payload) {
  requiredText(payload.challengeId, "rollback readback challengeId", 256);
  requiredText(payload.transactionId, "rollback readback transactionId", 512);
  requiredText(payload.nonce, "rollback readback nonce", 512);
  requiredText(payload.correlationId, "rollback readback correlationId", 256);
  requiredDigest(payload.sessionIdentityDigest, "rollback readback session identity");
  requiredDigest(payload.responseDigest, "rollback readback response digest");
}

function assertRuntime(runtime) {
  if (!runtime || typeof runtime !== "object") throw new Error("Connector activation runtime is required.");
  for (const symbol of [
    "actionFingerprint",
    "actionResourceKeySha256",
    "connectorActivationAuthorityReceiptDigest",
    "connectorActivationFinalizationPlanDigest",
    "connectorActivationReceiptDigest",
    "connectorActivationTupleDigest",
    "connectorEnvironmentIdentityDigest",
    "connectorRouteIdentityDigest",
    "connectorStagingActivationOwnerApprovalBinding",
    "loadExistingManagementAuthorizationKey",
    "productionUpgradeRequestBindingDigest",
    "signConnectorActivationOwnerApproval",
    "signConnectorActivationPostActivationHostCanary",
    "signConnectorActivationPreCutoverHostCanary",
    "signConnectorActivationProductionPrecheck",
    "signConnectorActivationStagingPrecheck",
    "signConnectorStagingActivationOwnerApproval",
    "verifyConnectorActivationOwnerApproval",
    "verifyConnectorActivationPostActivationHostCanary",
    "verifyConnectorActivationPreCutoverHostCanary",
    "verifyConnectorActivationProductionPrecheck",
    "verifyConnectorActivationStagingPrecheck",
    "verifyConnectorStagingActivationOwnerApproval",
    "verifyPersistedConnectorActivationPreCutoverHostCanary",
    "validateSnapshotGroupManifest",
  ]) {
    if (typeof runtime[symbol] !== "function") throw new Error(`Connector activation runtime is missing ${symbol}.`);
  }
  for (const symbol of [
    "ConnectorStagingActivationCoordinator",
    "OperationAuthorityRegistry",
    "SqliteConnectorActivationRecoveryJournal",
    "SqliteOAuthStore",
  ]) {
    if (typeof runtime[symbol] !== "function") throw new Error(`Connector activation runtime is missing ${symbol}.`);
  }
  if (runtime.CONNECTOR_STAGING_ACTIVATION_OUTWARD_STATE
    !== "STAGING_ACTIVATED_PENDING_PRE_CANARY") {
    throw new Error("Connector staging activation outward state is not the required pending-PRE contract.");
  }
  if (runtime.CONNECTOR_ACTIVATION_JOURNAL_SCHEMA_VERSION !== 1
    || typeof runtime.CONNECTOR_ACTIVATION_JOURNAL_MIGRATION_MANIFEST_DIGEST !== "string"
    || typeof runtime.CONNECTOR_ACTIVATION_JOURNAL_SCHEMA_FINGERPRINT !== "string") {
    throw new Error("Connector activation journal runtime identity is unavailable.");
  }
  return runtime;
}

function validateRequestEnvelope(
  request,
  operation,
  storeKeys,
  selectionKeys,
  artifactKeys,
  nestedSelections = {},
) {
  assertExactKeys(request, COMMON_REQUEST_KEYS, `${operation} request`);
  if (request.schemaVersion !== 1 || request.operation !== operation) {
    throw new Error(`${operation} request identity is invalid.`);
  }
  assertExactKeys(request.management, MANAGEMENT_KEYS, `${operation} management reference`);
  assertExactKeys(request.stores, storeKeys, `${operation} stores`);
  assertExactKeys(request.selection, selectionKeys, `${operation} selection`);
  assertExactKeys(request.artifacts, artifactKeys, `${operation} artifacts`);
  for (const [name, keys] of Object.entries(nestedSelections)) {
    assertExactKeys(request.selection[name], keys, `${operation} ${name} selection`);
  }
  for (const [name, value] of Object.entries(request.stores)) {
    absolutePath(value, `${operation} store ${name}`);
  }
  for (const [name, value] of Object.entries(request.artifacts)) {
    absolutePath(value, `${operation} artifact ${name}`);
  }
  assertSecretFreeJson(request, `${operation} request`);
}

function nestedSelectionRequest(request, selectionName) {
  return { ...request, selection: request.selection[selectionName] };
}

function stagingPrecheckExpected(context) {
  return {
    principalKeyFingerprint: context.principalKeyFingerprint,
    managementNonce: context.host.payload.managementNonce,
    managementCorrelationId: context.host.payload.managementCorrelationId,
    candidateIdentity: context.candidate.payload.candidateIdentity,
    stagingRouteIdentityDigest: context.candidate.payload.routeIdentityDigest,
    stagingCandidateBinding: stagingBindingIdentity(context.candidate.payload, "ACTIVATION_PREPARED"),
  };
}

function stagingBindingIdentity(candidate, state) {
  if (!["ACTIVATION_PREPARED", "ACTIVE"].includes(state)) {
    throw new Error("Staging binding evidence state is invalid.");
  }
  return {
    environmentIdentityDigest: candidate.environmentIdentityDigest,
    canonicalName: candidate.canonicalName,
    clientId: candidate.clientId,
    bindingId: candidate.bindingId,
    installationEpoch: candidate.installationEpoch,
    state,
  };
}

function assertCandidateReadback(payload, environmentRole, bindingState) {
  if (payload.environmentRole !== environmentRole || payload.bindingState !== bindingState) {
    throw new Error(`Candidate readback is not ${environmentRole}/${bindingState}.`);
  }
  if (bindingState === "VERIFIED" && payload.receiptId !== null) {
    throw new Error("VERIFIED candidate readback cannot contain a prepared receipt.");
  }
  if (["ACTIVATION_PREPARED", "ACTIVE"].includes(bindingState) && payload.receiptId === null) {
    throw new Error(`${bindingState} candidate readback requires an activation receipt.`);
  }
  const derived = deriveCandidateIdentityFromImmutablePackage(payload);
  if (!objectsEqual(derived.candidateIdentity, payload.candidateIdentity)) {
    throw new Error("Candidate identity does not match the verified immutable release package.");
  }
  if (derived.migrationManifestDigest !== payload.migrationManifestDigest) {
    throw new Error("Candidate migration identity does not match the verified immutable release package.");
  }
}

function deriveCandidateIdentityFromImmutablePackage(payload) {
  const packageRoot = immutablePackageDirectory(payload.packageRoot);
  const manifestPath = join(packageRoot, "BUILD-MANIFEST.json");
  const manifestMetadata = lstatSync(manifestPath);
  if (!manifestMetadata.isFile() || manifestMetadata.isSymbolicLink()) {
    throw new Error("Immutable package BUILD-MANIFEST.json is not a regular file.");
  }
  const manifest = parseJson(readFileSync(manifestPath, "utf8"), "BUILD-MANIFEST.json");
  if (manifest.manifestVersion !== 2 || !isPlainObject(manifest.buildCapabilities)
    || !Array.isArray(manifest.payloadFiles) || !Array.isArray(manifest.runtimeFiles)) {
    throw new Error("Immutable package BUILD-MANIFEST.json shape is invalid.");
  }
  for (const key of [
    "buildDigest", "payloadDigest", "schemaGeneration", "authorityContractGeneration",
    "migrationManifestDigest",
  ]) requiredDigest(manifest[key], `BUILD-MANIFEST ${key}`);
  requiredDigest(manifest.buildCapabilities.capabilityDigest, "BUILD-MANIFEST capabilityDigest");
  for (const path of GENERATED_SCHEMA_FILES) {
    if (!manifest.payloadFiles.includes(path)) {
      throw new Error(`Immutable package manifest does not bind generated schema ${path}.`);
    }
  }
  const payloadTree = treeEvidence(packageRoot, manifest.payloadFiles);
  if (payloadTree.sha256 !== manifest.payloadDigest) {
    throw new Error("Immutable package payload tree does not match BUILD-MANIFEST payloadDigest.");
  }
  const runtimeTree = treeEvidence(packageRoot, manifest.runtimeFiles);
  if (runtimeTree.sha256 !== manifest.buildDigest) {
    throw new Error("Immutable package runtime tree does not match BUILD-MANIFEST buildDigest.");
  }
  const generatedSchemaDigest = treeEvidence(packageRoot, GENERATED_SCHEMA_FILES).sha256;
  return {
    candidateIdentity: {
      runtimeIdentityDigest: payload.candidateIdentity.runtimeIdentityDigest,
      buildDigest: manifest.buildDigest,
      schemaGeneration: manifest.schemaGeneration,
      authorityContractGeneration: manifest.authorityContractGeneration,
      buildCapabilityManifestDigest: manifest.buildCapabilities.capabilityDigest,
      generatedSchemaDigest,
      packageSha256: manifest.payloadDigest,
    },
    migrationManifestDigest: manifest.migrationManifestDigest,
  };
}

function assertBindingMatchesCandidateRecord(binding, candidate, expectedState) {
  if (binding.state !== expectedState
    || binding.bindingId !== candidate.bindingId
    || binding.canonicalName !== candidate.canonicalName
    || binding.clientId !== candidate.clientId
    || binding.installationEpoch !== candidate.installationEpoch
    || binding.schemaGeneration !== candidate.candidateIdentity.schemaGeneration
    || binding.authorityContractGeneration !== candidate.candidateIdentity.authorityContractGeneration
    || binding.redirectUrisDigest !== candidate.redirectUrisDigest
    || binding.buildDigest !== candidate.candidateIdentity.buildDigest) {
    throw new Error("OAuth connector binding does not match the trusted candidate readback.");
  }
  if (candidate.bindingState !== expectedState) {
    throw new Error("Candidate readback state does not match the exact OAuth binding state.");
  }
  if (["ACTIVATION_PREPARED", "ACTIVE"].includes(expectedState)
    && binding.stateReason !== candidate.receiptId) {
    throw new Error("OAuth connector state does not name the trusted activation receipt.");
  }
}

function assertPreparedReceiptMatchesBinding(receipt, binding, runtime) {
  if (receipt.status !== "PREPARED" || receipt.activationAuthority !== undefined
    || receipt.tuple.candidateBindingId !== binding.bindingId
    || receipt.tuple.canonicalName !== binding.canonicalName
    || receipt.tuple.clientId !== binding.clientId
    || receipt.tuple.installationEpoch !== binding.installationEpoch
    || receipt.tuple.schemaGeneration !== binding.schemaGeneration
    || receipt.tuple.authorityContractGeneration !== binding.authorityContractGeneration
    || receipt.tuple.redirectUrisDigest !== binding.redirectUrisDigest
    || receipt.tuple.buildDigest !== binding.buildDigest
    || receipt.tupleDigest !== runtime.connectorActivationTupleDigest(receipt.tuple)
    || binding.state !== "ACTIVATION_PREPARED"
    || binding.stateReason !== receipt.receiptId) {
    throw new Error("Prepared OAuth activation receipt does not match its exact connector binding.");
  }
  requiredDigest(receipt.preimageDigest, "activation receipt preimageDigest");
  requiredIsoTimestamp(receipt.preparedAt, "activation receipt preparedAt");
  requiredIsoTimestamp(receipt.drainDeadlineAt, "activation receipt drainDeadlineAt");
}

function assertOwnerDecision(decision, stage, correlationId, conditionsDigest, nowMs) {
  if (decision.payload.stage !== stage
    || decision.payload.managementCorrelationId !== correlationId
    || decision.payload.conditionsDigest !== conditionsDigest) {
    throw new Error("Owner approval decision does not bind the exact activation conditions.");
  }
  if (decision.payload.approvedAtMs > decision.occurredAtMs
    || decision.occurredAtMs > nowMs
    || decision.payload.expiresAtMs <= decision.payload.approvedAtMs
    || decision.payload.expiresAtMs - decision.payload.approvedAtMs > 5 * 60_000
    || nowMs > decision.payload.expiresAtMs) {
    throw new Error("Owner approval decision is stale, premature, or exceeds its bounded lifetime.");
  }
}

function activationTupleFromBinding(binding) {
  for (const key of ["authorityContractGeneration", "redirectUrisDigest", "buildDigest"]) {
    requiredDigest(binding[key], `verified OAuth binding ${key}`);
  }
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

function digestActivationTuple(tuple) {
  return digestText(JSON.stringify({
    canonicalName: tuple.canonicalName,
    candidateBindingId: tuple.candidateBindingId,
    clientId: tuple.clientId,
    installationEpoch: tuple.installationEpoch,
    schemaGeneration: tuple.schemaGeneration,
    authorityContractGeneration: tuple.authorityContractGeneration,
    redirectUrisDigest: tuple.redirectUrisDigest,
    buildDigest: tuple.buildDigest,
  }));
}

function oauthConnectorPreimageDigest(binding) {
  return digestText(JSON.stringify(binding ? {
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

function assertBrokerRequestBinding(record, host, candidate, sessionIdentityDigest) {
  if (record.payload.managementCorrelationId !== host.payload.managementCorrelationId
    || record.payload.sessionIdentityDigest !== sessionIdentityDigest
    || record.payload.environmentIdentityDigest !== candidate.payload.environmentIdentityDigest
    || record.payload.routeIdentityDigest !== candidate.payload.routeIdentityDigest
    || record.occurredAtMs > host.occurredAtMs) {
    throw new Error("Broker request does not bind the exact Host session, environment, route, and correlation.");
  }
}

function assertAuditMatchesRequest(audit, request, expected) {
  if (audit.operationId !== request.payload.operationId
    || audit.correlationId !== request.payload.correlationId
    || audit.principalFingerprintPrefix !== request.payload.principalKeyFingerprint.slice(0, 12)
    || audit.tool !== request.payload.tool
    || audit.operation !== request.payload.operation
    || audit.risk !== expected.risk
    || audit.dispatchState !== expected.dispatchState
    || audit.result !== expected.result
    || audit.actionDigest !== digestJson(request.payload.action)) {
    throw new Error("Operation audit does not match the exact broker request and outcome.");
  }
  if ((expected.claimState === undefined && audit.claimState !== undefined)
    || (expected.claimState !== undefined && audit.claimState !== expected.claimState)) {
    throw new Error("Operation audit claim state does not match trusted authority readback.");
  }
  if (expected.authorityId !== undefined
    && audit.authorityIdDigest !== digestText(expected.authorityId)) {
    throw new Error("Operation audit authority identity does not match trusted authority readback.");
  }
  if (expected.receiptDigest !== undefined && audit.receiptDigest !== expected.receiptDigest) {
    throw new Error("Operation audit receipt does not match the durable authority receipt.");
  }
  if ((expected.errorCode ?? undefined) !== (audit.errorCode ?? undefined)) {
    throw new Error("Operation audit error code does not match the expected dispatch outcome.");
  }
  if (request.payload.action.target !== null && audit.targetId !== request.payload.action.target) {
    throw new Error("Operation audit target does not match the broker authority action.");
  }
}

function assertProviderDispatchMatchesRequest(dispatch, request) {
  if (dispatch.payload.requestRecordId !== request.recordDigest
    || dispatch.payload.correlationId !== request.payload.correlationId
    || dispatch.payload.operationId !== request.payload.operationId
    || dispatch.payload.tool !== request.payload.tool
    || dispatch.payload.operation !== request.payload.operation
    || dispatch.payload.resourceDigest !== request.payload.resourceDigest
    || dispatch.payload.resultDigest !== request.payload.responseDigest
    || dispatch.occurredAtMs < request.occurredAtMs) {
    throw new Error("Provider dispatch does not match the exact broker request.");
  }
}

function assertReadbackAfterDispatch(readback, dispatch, request) {
  if (readback.payload.requestRecordId !== request.recordDigest
    || readback.payload.correlationId !== request.payload.correlationId
    || readback.payload.resourceDigest !== request.payload.resourceDigest
    || readback.occurredAtMs < dispatch.occurredAtMs) {
    throw new Error("Broker resource readback does not follow the exact provider dispatch.");
  }
}

function assertCleanupAfterReadback(cleanup, readback, request) {
  if (cleanup.payload.requestRecordId !== request.recordDigest
    || cleanup.payload.correlationId !== request.payload.correlationId
    || cleanup.payload.resourceDigest !== request.payload.resourceDigest
    || cleanup.occurredAtMs < readback.occurredAtMs) {
    throw new Error("Broker cleanup does not follow the exact resource readback.");
  }
}

function assertAbsenceAfterCleanup(absence, cleanup, request) {
  if (absence.payload.cleanupRecordId !== cleanup.recordDigest
    || absence.payload.resourceDigest !== request.payload.resourceDigest
    || absence.occurredAtMs < cleanup.occurredAtMs) {
    throw new Error("Broker absence readback does not follow the exact cleanup dispatch.");
  }
}

function assertSessionCloseBinding(close, host) {
  if (close.payload.sessionIdentityDigest !== host.payload.sessionA.sessionIdentityDigest
    || close.payload.managementCorrelationId !== host.payload.managementCorrelationId) {
    throw new Error("Session A close readback does not bind the exact Host session.");
  }
}

function assertCanaryExpectedDigests(host, selector) {
  for (const [observed, expected, label] of [
    [host.payload.discovery.transcriptDigest, selector.expectedDiscoveryTranscriptDigest, "discovery transcript"],
    [host.payload.sessionA.authorizationTranscriptDigest, selector.expectedAuthorizationTranscriptDigest, "authorization transcript"],
    [host.payload.sessionA.closeTranscriptDigest, selector.expectedCloseTranscriptDigest, "close transcript"],
    [host.payload.sessionB.mutationTranscriptDigest, selector.expectedMutationTranscriptDigest, "mutation transcript"],
    [host.payload.foreignClient.rejectionTranscriptDigest, selector.expectedForeignTranscriptDigest, "foreign-client transcript"],
  ]) assertDigestEquals(observed, expected, label);
}

function assertRollbackReadbackBinding(readback, challenge, sessionIdentityDigest) {
  if (readback.payload.challengeId !== challenge.challengeId
    || readback.payload.transactionId !== challenge.transactionId
    || readback.payload.nonce !== challenge.nonce
    || readback.payload.correlationId !== challenge.managementCorrelationId
    || (sessionIdentityDigest !== undefined
      && readback.payload.sessionIdentityDigest !== sessionIdentityDigest)) {
    throw new Error("Rollback broker readback does not bind the exact challenge and Host session.");
  }
}

function rollbackExpectedBinding(preimage, receiptPathInput) {
  return {
    transactionId: preimage.payload.transactionId,
    previousRuntimeIdentityDigest: preimage.payload.previousRuntimeIdentityDigest,
    previousMainMigrationIdentityDigest: preimage.payload.previousMainMigrationIdentityDigest,
    receiptPath: absolutePath(receiptPathInput, "rollback receiptPath"),
  };
}

function rollbackReceiptExpectedBinding(challengeExpected, challenge, health, ready, runtime) {
  const common = {
    challengeId: challenge.challengeId,
    transactionId: challenge.transactionId,
    nonce: challenge.nonce,
    managementCorrelationId: challenge.managementCorrelationId,
  };
  return {
    ...challengeExpected,
    healthReadbackDigest: connectorRollbackHealthReadbackDigest({
      ...common,
      httpStatus: health.payload.httpStatus,
    }),
    readyReadbackDigest: connectorRollbackReadyReadbackDigest({
      ...common,
      httpStatus: ready.payload.httpStatus,
      runtimeIdentityDigest: ready.payload.runtimeIdentityDigest,
    }),
    runtimeReadbackDigest: connectorRollbackRuntimeReadbackDigest({
      ...common,
      processName: runtime.payload.processName,
      processStatus: runtime.payload.processStatus,
      cwd: runtime.payload.cwd,
      script: runtime.payload.script,
      runtimeIdentityDigest: runtime.payload.runtimeIdentityDigest,
      mainMigrationIdentityDigest: runtime.payload.mainMigrationIdentityDigest,
    }),
  };
}

function assertEvidenceFresh(record, nowMs, lifetimeMs, label) {
  if (record.occurredAtMs > nowMs || nowMs - record.occurredAtMs > lifetimeMs) {
    throw new Error(`${label} is stale or from the future.`);
  }
}

function validateAuditRecord(record, expectedSequence, expectedPrevious) {
  if (!isPlainObject(record)) throw new Error("Operation audit record is invalid.");
  const required = [
    "actionDigest", "correlationId", "dispatchState", "eventDigest", "operation", "operationId",
    "principalFingerprintPrefix", "result", "risk", "schemaVersion", "sequence", "timestamp", "tool",
  ];
  const optional = [
    "authorityIdDigest", "claimState", "errorCode", "previousEventDigest", "receiptDigest", "resourceKeyDigest",
    "routeGeneration", "routeId", "targetGeneration", "targetId", "taskInstanceDigest",
  ];
  for (const key of Object.keys(record)) {
    if (![...required, ...optional].includes(key)) throw new Error("Operation audit record has unexpected fields.");
  }
  for (const key of required) {
    if (!Object.prototype.hasOwnProperty.call(record, key)) throw new Error(`Operation audit record is missing ${key}.`);
  }
  if (record.schemaVersion !== 1 || record.sequence !== expectedSequence
    || record.previousEventDigest !== expectedPrevious) {
    throw new Error("Operation audit sequence or hash chain is invalid.");
  }
  requiredIsoTimestamp(record.timestamp, "operation audit timestamp");
  for (const key of ["operationId", "correlationId", "tool", "operation", "risk", "dispatchState", "result"]) {
    requiredText(record[key], `operation audit ${key}`, 256);
  }
  if (typeof record.principalFingerprintPrefix !== "string"
    || !/^[a-f0-9]{12}$/u.test(record.principalFingerprintPrefix)) {
    throw new Error("Operation audit principal prefix is invalid.");
  }
  for (const key of [
    "actionDigest", "authorityIdDigest", "receiptDigest", "resourceKeyDigest", "routeGeneration",
    "targetGeneration", "taskInstanceDigest",
  ]) {
    if (record[key] !== undefined) requiredDigest(record[key], `operation audit ${key}`);
  }
  for (const key of ["claimState", "errorCode", "routeId", "targetId"]) {
    if (record[key] !== undefined) requiredText(record[key], `operation audit ${key}`, 256);
  }
  requiredDigest(record.eventDigest, "operation audit eventDigest");
  const { eventDigest, ...unsigned } = record;
  if (eventDigest !== digestJson(unsigned)) throw new Error("Operation audit event digest is invalid.");
}

function assertAuthorityPassRow(row, requireAudit = true) {
  if (row.state !== "PASS" || row.providerCallCount !== 1
    || !Number.isSafeInteger(row.claimedAtMs) || !Number.isSafeInteger(row.dispatchedAtMs)
    || !Number.isSafeInteger(row.completedAtMs)
    || row.claimedAtMs > row.dispatchedAtMs || row.dispatchedAtMs > row.completedAtMs
    || row.leaseState !== "RELEASED"
    || row.errorCode !== null
    || row.actionFingerprint !== row.durableActionFingerprint
    || row.resourceKeySha256 !== row.durableResourceKeySha256
    || row.consumedUses < 1 || row.consumedUses > row.maximumUses) {
    throw new Error("Durable authority claim is not one completed PASS with exactly one provider call.");
  }
  const receiptDigest = authorityReceiptDigest(row);
  if (requireAudit && (row.auditState !== "RECORDED"
    || !SHA256.test(row.auditEventDigest)
    || row.auditReceiptDigest !== receiptDigest
    || !Number.isSafeInteger(row.auditRecordedAtMs))) {
    throw new Error("Durable authority PASS is not linked to one recorded operation audit receipt.");
  }
}

function authorityReceiptDigest(row) {
  return digestJson({
    schemaVersion: 1,
    authorityId: row.authorityId,
    actionClaimId: row.actionClaimId,
    useId: row.actionClaimId,
    actionId: `action_${row.actionFingerprint}`,
    taskInstanceId: row.taskInstanceId,
    principalKeyFingerprint: row.principalKeyFingerprint,
    actionFingerprint: row.actionFingerprint,
    resourceKeySha256: row.resourceKeySha256,
    fencingToken: row.fencingToken,
    claimedAtMs: row.claimedAtMs,
    reservedAtMs: row.claimedAtMs,
    dispatchedAtMs: row.dispatchedAtMs,
    completedAtMs: row.completedAtMs,
    state: row.state,
    result: row.state,
    leaseState: row.leaseState,
    providerCallCount: row.providerCallCount,
    ...(row.errorCode === null ? {} : { errorCode: row.errorCode }),
    ...(row.reasonCode === null ? {} : { reasonCode: row.reasonCode }),
  });
}

function readSignedEvidence(path, expectedKind) {
  const value = parseJson(readOwnerOnlyText(path, `${expectedKind} artifact`, MAX_JSON_BYTES), expectedKind);
  assertExactKeys(
    value,
    ["keyId", "kind", "payload", "payloadDigest", "schemaVersion", "signature"],
    `${expectedKind} signed envelope`,
  );
  if (value.schemaVersion !== 2 || value.kind !== expectedKind) {
    throw new Error(`${expectedKind} signed artifact identity is invalid.`);
  }
  requiredDigest(value.payloadDigest, `${expectedKind} payloadDigest`);
  if (typeof value.signature !== "string" || !/^[A-Za-z0-9_-]{43}$/u.test(value.signature)) {
    throw new Error(`${expectedKind} signature encoding is invalid.`);
  }
  return value;
}

function readSignedRollbackEvidence(path, expectedKind) {
  const value = parseJson(readOwnerOnlyText(path, `${expectedKind} artifact`, MAX_JSON_BYTES), expectedKind);
  assertExactKeys(
    value,
    ["keyId", "kind", "payload", "payloadDigest", "schemaVersion", "signature"],
    `${expectedKind} signed envelope`,
  );
  if (value.schemaVersion !== 1 || value.kind !== expectedKind) {
    throw new Error(`${expectedKind} signed artifact identity is invalid.`);
  }
  return value;
}

function absolutePath(value, label) {
  if (typeof value !== "string" || value.length < 2 || value.length > 4_096
    || /[\0\r\n]/u.test(value) || !isAbsolute(value)) {
    throw new Error(`${label} must be one absolute path.`);
  }
  return resolve(value);
}

function ownerOnlyDirectory(path, label) {
  const target = absolutePath(path, label);
  const metadata = lstatSync(target);
  if (!metadata.isDirectory() || metadata.isSymbolicLink()
    || (metadata.mode & 0o077) !== 0 || (metadata.mode & 0o700) !== 0o700) {
    throw new Error(`${label} must be an owner-only directory, not a symlink.`);
  }
  assertOwnedByCurrentUser(metadata, label);
  if (realpathSync(target) !== target) throw new Error(`${label} may not traverse symbolic links.`);
  return target;
}

function immutablePackageDirectory(path) {
  const target = absolutePath(path, "immutable package root");
  const metadata = lstatSync(target);
  if (!metadata.isDirectory() || metadata.isSymbolicLink()) {
    throw new Error("Immutable package root must be one regular directory, not a symlink.");
  }
  if (realpathSync(target) !== target) throw new Error("Immutable package root may not traverse symbolic links.");
  return target;
}

function ownerOnlyExistingPath(path, label) {
  const target = absolutePath(path, label);
  const metadata = lstatSync(target);
  if (!metadata.isFile() || metadata.isSymbolicLink()
    || (metadata.mode & 0o077) !== 0 || (metadata.mode & 0o400) === 0) {
    throw new Error(`${label} must be an owner-only regular file, not a symlink.`);
  }
  assertOwnedByCurrentUser(metadata, label);
  if (realpathSync(target) !== target) throw new Error(`${label} may not traverse symbolic links.`);
  return target;
}

function ownerOnlyFuturePath(path, label) {
  const target = absolutePath(path, label);
  if (existsSync(target)) throw new Error(`${label} output already exists and cannot be overwritten.`);
  ownerOnlyDirectory(dirname(target), `${label} parent directory`);
  const base = target.slice(dirname(target).length + 1);
  if (!base || base === "." || base === ".." || base.includes("/")) {
    throw new Error(`${label} output filename is invalid.`);
  }
  return target;
}

function ownerOnlyExistingOrNewPath(path, label) {
  const target = absolutePath(path, label);
  if (existsSync(target)) return ownerOnlyExistingPath(target, label);
  ownerOnlyDirectory(dirname(target), `${label} parent directory`);
  return target;
}

function assertOAuthStateDirectory(stateDirInput, databasePathInput) {
  const stateDir = ownerOnlyDirectory(stateDirInput, "OAuth state directory");
  const databasePath = ownerOnlyExistingPath(databasePathInput, "OAuth database");
  if (databasePath !== join(stateDir, "devspace.sqlite")) {
    throw new Error("OAuth database path does not belong to the exact OAuth state directory.");
  }
}

function assertOwnedByCurrentUser(metadata, label) {
  if (typeof process.getuid === "function" && metadata.uid !== process.getuid()) {
    throw new Error(`${label} must be owned by the broker service user.`);
  }
}

function readOwnerOnlyText(path, label, maximumBytes) {
  const target = ownerOnlyExistingPath(path, label);
  const descriptor = openSync(target, constants.O_RDONLY | noFollowFlag());
  try {
    const metadata = fstatSync(descriptor);
    if (!metadata.isFile() || metadata.size > maximumBytes) {
      throw new Error(`${label} is not a bounded regular file.`);
    }
    return readFileSync(descriptor, "utf8");
  } finally {
    closeSync(descriptor);
  }
}

function noFollowFlag() {
  return typeof constants.O_NOFOLLOW === "number" ? constants.O_NOFOLLOW : 0;
}

function fsyncDirectory(path) {
  const descriptor = openSync(path, constants.O_RDONLY | noFollowFlag());
  try { fsyncSync(descriptor); } finally { closeSync(descriptor); }
}

function closeQuietly(value) {
  if (value && typeof value.close === "function") {
    try { value.close(); } catch { /* a close failure cannot replace the primary evidence result */ }
  }
}

function parseJson(text, label) {
  if (typeof text !== "string" || text.length === 0) throw new Error(`${label} is empty.`);
  try {
    const value = JSON.parse(text);
    assertSecretFreeJson(value, label);
    return value;
  } catch (error) {
    if (error instanceof SyntaxError) throw new Error(`${label} is not valid JSON.`, { cause: error });
    throw error;
  }
}

function assertExactKeys(value, expectedKeys, label) {
  if (!isPlainObject(value)) throw new Error(`${label} must be one plain object.`);
  const observed = Object.keys(value).sort();
  const expected = [...expectedKeys].sort();
  if (observed.length !== expected.length
    || observed.some((key, index) => key !== expected[index])) {
    throw new Error(
      `${label} has unexpected or missing fields: observed=${observed.join(",")}; expected=${expected.join(",")}.`,
    );
  }
}

function isPlainObject(value) {
  if (!value || typeof value !== "object" || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function assertSecretFreeJson(value, label, seen = new Set()) {
  if (value === null || typeof value === "boolean") return;
  if (typeof value === "number") {
    if (!Number.isFinite(value)) throw new Error(`${label} contains a non-finite number.`);
    return;
  }
  if (typeof value === "string") {
    if (/\bBearer\s+[A-Za-z0-9._~-]/iu.test(value)
      || /-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----/u.test(value)) {
      throw new Error(`${label} contains raw secret material.`);
    }
    return;
  }
  if (!value || typeof value !== "object") throw new Error(`${label} contains a non-JSON value.`);
  if (seen.has(value)) throw new Error(`${label} contains a cyclic value.`);
  seen.add(value);
  const entries = Array.isArray(value) ? value.entries() : Object.entries(value);
  for (const [key, child] of entries) {
    if (typeof key === "string" && /^(?:accessToken|authorizationHeader|bearerToken|clientSecret|password|rawSecret|rawToken|refreshToken)$/iu.test(key)) {
      throw new Error(`${label} contains forbidden raw-secret field ${key}.`);
    }
    assertSecretFreeJson(child, `${label}.${key}`, seen);
  }
  seen.delete(value);
}

function requiredText(value, label, maximumLength) {
  if (typeof value !== "string" || value.length < 1 || value.length > maximumLength
    || /[\0\r\n]/u.test(value)) {
    throw new Error(`${label} is invalid.`);
  }
  return value;
}

function requiredDigest(value, label) {
  if (typeof value !== "string" || !SHA256.test(value)) throw new Error(`${label} is invalid.`);
  return value;
}

function requiredRawDigest(value, label) {
  if (typeof value !== "string" || !RAW_SHA256.test(value)) throw new Error(`${label} is invalid.`);
  return value;
}

function requiredTimestamp(value, label) {
  if (!Number.isSafeInteger(value) || value < 0) throw new Error(`${label} is invalid.`);
  return value;
}

function requiredIsoTimestamp(value, label) {
  requiredText(value, label, 128);
  const parsed = Date.parse(value);
  if (!Number.isFinite(parsed) || new Date(parsed).toISOString() !== value) {
    throw new Error(`${label} must be one canonical ISO-8601 timestamp.`);
  }
  return value;
}

function requiredHttpsUrl(value, label) {
  requiredText(value, label, 2_048);
  let parsed;
  try { parsed = new URL(value); } catch (error) {
    throw new Error(`${label} is not a valid URL.`, { cause: error });
  }
  if (parsed.protocol !== "https:" || parsed.username || parsed.password || parsed.hash) {
    throw new Error(`${label} must be one secret-free HTTPS resource URL.`);
  }
  return value;
}

function assertDigestEquals(observed, expected, label) {
  requiredDigest(expected, `expected ${label}`);
  if (observed !== expected) throw new Error(`${label} does not match the selected immutable evidence.`);
}

function objectsEqual(left, right) {
  return canonicalJson(left) === canonicalJson(right);
}

function digestJson(value) {
  return digestText(canonicalJson(value));
}

function digestText(value) {
  return `sha256:${createHash("sha256").update(value).digest("hex")}`;
}

function canonicalJson(value) {
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  if (isPlainObject(value)) {
    return `{${Object.keys(value)
      .filter((key) => value[key] !== undefined)
      .sort((left, right) => (left < right ? -1 : left > right ? 1 : 0))
      .map((key) => `${JSON.stringify(key)}:${canonicalJson(value[key])}`)
      .join(",")}}`;
  }
  if (value === null || typeof value === "string" || typeof value === "boolean") {
    return JSON.stringify(value);
  }
  if (typeof value === "number" && Number.isFinite(value)) return JSON.stringify(value);
  throw new Error("Canonical evidence contains a non-JSON value.");
}

function serializedArtifactSha256(artifact) {
  return digestText(`${JSON.stringify(artifact, null, 2)}\n`);
}
