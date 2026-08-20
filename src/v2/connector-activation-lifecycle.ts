import { createHash } from "node:crypto";
import { lstat, readFile } from "node:fs/promises";
import { basename, dirname, isAbsolute, resolve } from "node:path";
import Database from "better-sqlite3";
import {
  SqliteOAuthStore,
  type ConnectorActivationAuthorityReceipt,
  type ConnectorActivationReceipt,
  type ConnectorBindingRecord,
} from "../oauth-store.js";
import { OperationAuthorityRegistry } from "./authority.js";
import {
  connectorActivationAuthorityReceiptDigest,
  connectorActivationReceiptDigest,
  verifyConnectorActivationOwnerApproval,
  verifyConnectorActivationPostActivationHostCanary,
  verifyPersistedConnectorActivationPreCutoverHostCanary,
  verifyConnectorActivationProductionPrecheck,
  verifyConnectorActivationStagingPrecheck,
  type ConnectorActivationImmutableCandidateIdentity,
  type ConnectorActivationOwnerApprovalPayload,
  type ConnectorActivationPostActivationHostCanaryPayload,
  type ConnectorActivationPreCutoverHostCanaryPayload,
  type ConnectorActivationProductionPrecheckPayload,
  type ConnectorActivationStagingPrecheckPayload,
  type SignedConnectorActivationEvidence,
  type VerifiedConnectorActivationOwnerApproval,
  type VerifiedConnectorActivationPreCutoverHostCanary,
  type VerifiedConnectorActivationProductionPrecheck,
  type VerifiedConnectorActivationStagingPrecheck,
} from "./connector-activation-evidence.js";
import {
  ConnectorActivationFinalizer,
  connectorActivationFinalizationPlanDigest,
  type ConnectorActivationFinalizationResult,
  type ConnectorActivationPendingPostcheckReconciliation,
  type ConnectorActivationRecoveryHandle,
} from "./connector-activation-finalizer.js";
import {
  SqliteConnectorActivationRecoveryJournal,
  type ConnectorActivationJournalEntry,
  type ConnectorActivationJournalIdentity,
  type ConnectorActivationJournalKey,
} from "./connector-activation-journal.js";
import {
  loadExistingManagementAuthorizationKey,
  managementAuthorizationHeader,
} from "./management-authorization.js";

const SHA256_DIGEST_PATTERN = /^sha256:[a-f0-9]{64}$/u;
const RAW_SHA256_PATTERN = /^[a-f0-9]{64}$/u;
const PREPARED_BRAND: unique symbol = Symbol("connector-activation-lifecycle-prepared");
const PENDING_BRAND: unique symbol = Symbol("connector-activation-lifecycle-pending");
const VERIFIED_BRAND: unique symbol = Symbol("connector-activation-lifecycle-post-verified");

export interface ConnectorActivationLifecycleArtifact {
  readonly path: string;
  readonly sha256: string;
}

export interface ConnectorActivationLifecycleConfiguration {
  readonly oauthDatabasePath: string;
  readonly authorityDatabasePath: string;
  readonly managementAuthorizationKeyRef: string;
  readonly managementNonce: string;
  readonly managementCorrelationId: string;
  readonly candidateIdentity: ConnectorActivationImmutableCandidateIdentity;
  readonly productionEnvironmentIdentityDigest: string;
  readonly productionRouteIdentityDigest: string;
  readonly oauthResource: string;
  readonly activation: {
    readonly receiptId: string;
    readonly tupleDigest: string;
    readonly activePreimageDigest: string;
    readonly finalizationPlanDigest: string;
  };
  readonly preCutoverHostCanary: ConnectorActivationLifecycleArtifact;
  readonly stagingActivationPrecheck: ConnectorActivationLifecycleArtifact;
  readonly productionActivationPrecheck: ConnectorActivationLifecycleArtifact;
  readonly ownerApproval: ConnectorActivationLifecycleArtifact;
  readonly journal: {
    readonly path: string;
    readonly identity: ConnectorActivationJournalIdentity;
  };
  readonly postActivation: {
    readonly challengePath: string;
    readonly challengeSha256: string;
    readonly receiptPath: string;
    readonly deadlineAt: string;
    readonly pollIntervalMs: number;
    readonly runtimeIdentityUrl: string;
    readonly routeIdentityUrl: string;
  };
}

export interface ConnectorActivationLifecyclePrepared {
  readonly state: "CONNECTOR_ACTIVATION_PREPARED";
  readonly receiptId: string;
  readonly tupleDigest: string;
  readonly journalContentGeneration: string;
  readonly [PREPARED_BRAND]: true;
}

export interface ConnectorActivationLifecyclePending {
  readonly state: "ACTIVATED_PENDING_POSTCHECK";
  readonly receiptId: string;
  readonly tupleDigest: string;
  readonly activationReceiptDigest: string;
  readonly activationProofDigest: string;
  readonly authorityReceiptDigest: string;
  readonly journalContentGeneration: string;
  readonly [PENDING_BRAND]: true;
}

export interface ConnectorActivationLifecycleVerified {
  readonly state: "POST_ACTIVATION_VERIFIED";
  readonly receiptId: string;
  readonly tupleDigest: string;
  readonly activationReceiptDigest: string;
  readonly activationProofDigest: string;
  readonly authorityReceiptDigest: string;
  readonly postActivationEvidenceDigest: string;
  readonly journalContentGeneration: string;
  readonly [VERIFIED_BRAND]: true;
}

interface VerifiedPreparation {
  receipt: ConnectorActivationReceipt;
  principalKeyFingerprint: string;
  ownerApproval: VerifiedConnectorActivationOwnerApproval;
  preCutoverHostCanary: VerifiedConnectorActivationPreCutoverHostCanary;
  productionActivationPrecheck: VerifiedConnectorActivationProductionPrecheck;
  stagingActivationPrecheck: VerifiedConnectorActivationStagingPrecheck;
  journalKey: ConnectorActivationJournalKey;
  journalEntry?: ConnectorActivationJournalEntry;
}

interface PendingReadback {
  activationReceipt: ConnectorActivationReceipt;
  activationAuthorityReceipt: ConnectorActivationAuthorityReceipt;
  recovery: ConnectorActivationRecoveryHandle;
  authorityReceiptDigest: string;
}

interface ActiveTokenFamilyReadback {
  tokenFamilyIdDigest: string;
  tokenFamilyBindingId: string;
}

/**
 * Internal production connector lifecycle. All identity-bearing evidence is
 * loaded from owner-only, request-bound files or durable stores. Public methods
 * intentionally accept no caller tuple, principal, authority proof, receipt,
 * or PASS value.
 */
export class ConnectorActivationLifecycleManager {
  private readonly configuration: ConnectorActivationLifecycleConfiguration;
  private readonly oauthStore: SqliteOAuthStore;
  private readonly authorityRegistry: OperationAuthorityRegistry;
  private readonly journal: SqliteConnectorActivationRecoveryJournal;
  private readonly finalizer: ConnectorActivationFinalizer;
  private readonly managementKey: ReturnType<typeof loadExistingManagementAuthorizationKey>;
  private preparation?: VerifiedPreparation;
  private pending?: PendingReadback;
  private closed = false;

  constructor(configuration: ConnectorActivationLifecycleConfiguration) {
    this.configuration = validateConfiguration(configuration);
    const oauthPath = resolve(configuration.oauthDatabasePath);
    if (basename(oauthPath) !== "devspace.sqlite") {
      throw new Error("Connector lifecycle OAuth database must be the canonical devspace.sqlite path.");
    }
    this.managementKey = loadExistingManagementAuthorizationKey({
      keyRef: configuration.managementAuthorizationKeyRef,
      stateDir: dirname(configuration.managementAuthorizationKeyRef),
    });
    this.oauthStore = new SqliteOAuthStore(dirname(oauthPath));
    this.authorityRegistry = new OperationAuthorityRegistry({
      storePath: resolve(configuration.authorityDatabasePath),
      instanceId: `connector-lifecycle-${process.pid}`,
    });
    this.journal = new SqliteConnectorActivationRecoveryJournal({
      storePath: resolve(configuration.journal.path),
    });
    this.finalizer = new ConnectorActivationFinalizer({
      oauthStore: this.oauthStore,
      authorityRegistry: this.authorityRegistry,
      recoveryJournal: this.journal,
    });
  }

  async prepare(): Promise<ConnectorActivationLifecyclePrepared> {
    this.assertOpen();
    const preEnvelope = await readSignedArtifact<ConnectorActivationPreCutoverHostCanaryPayload>(
      this.configuration.preCutoverHostCanary,
      "PRE_CUTOVER_HOST_CANARY",
    );
    const stagingEnvelope = await readSignedArtifact<ConnectorActivationStagingPrecheckPayload>(
      this.configuration.stagingActivationPrecheck,
      "STAGING_ACTIVATION_PRECHECK",
    );
    const precheckEnvelope = await readSignedArtifact<ConnectorActivationProductionPrecheckPayload>(
      this.configuration.productionActivationPrecheck,
      "PRODUCTION_ACTIVATION_PRECHECK",
    );
    const ownerEnvelope = await readSignedArtifact<ConnectorActivationOwnerApprovalPayload>(
      this.configuration.ownerApproval,
      "OWNER_MANAGEMENT_APPROVAL",
    );
    await validatePostChallenge(this.configuration);

    const receipt = this.oauthStore.getActivationReceipt(this.configuration.activation.receiptId);
    if (!receipt || (receipt.status !== "PREPARED" && receipt.status !== "ACTIVATED")) {
      throw new Error("Request-bound connector activation receipt is not PREPARED or ACTIVATED.");
    }
    assertReceiptBinding(receipt, this.configuration);

    const selector = ownerEnvelope.payload;
    const selectorPrincipal = requiredRawDigest(selector?.principalKeyFingerprint, "owner principal selector");
    const selectorApprovalId = requiredText(selector?.approvalId, "owner approval selector", 256);
    const journalKey: ConnectorActivationJournalKey = {
      principalKeyFingerprint: selectorPrincipal,
      approvalId: selectorApprovalId,
      receiptId: receipt.receiptId,
    };
    const journalEntry = this.journal.load(journalKey);
    assertJournalIdentity(
      this.journal.identity(),
      this.configuration.journal.identity,
      journalEntry !== undefined,
    );
    if (receipt.status === "ACTIVATED" && !journalEntry?.recovery) {
      throw new Error("Activated OAuth state has no exact durable connector recovery handle.");
    }
    if (journalEntry && !journalEntry.recovery) {
      throw new Error("Reserved connector activation intent cannot be replayed after restart.");
    }
    const referenceTime = journalEntry?.recovery?.dispatchedAtMs
      ?? journalEntry?.recovery?.claimedAtMs
      ?? Date.now();

    const stagingPayload = stagingEnvelope.payload;
    const stagingActivationPrecheck = verifyConnectorActivationStagingPrecheck(
      stagingEnvelope,
      this.managementKey,
      {
        principalKeyFingerprint: selectorPrincipal,
        managementNonce: this.configuration.managementNonce,
        managementCorrelationId: this.configuration.managementCorrelationId,
        candidateIdentity: this.configuration.candidateIdentity,
        stagingRouteIdentityDigest: requiredDigest(
          stagingPayload?.stagingRouteIdentityDigest,
          "staging bootstrap route identity",
        ),
        stagingCandidateBinding: stagingPayload.stagingCandidateBinding,
      },
      stagingPayload.observedAtMs,
    );
    const prePayload = preEnvelope.payload;
    const preCutoverHostCanary = verifyPersistedConnectorActivationPreCutoverHostCanary(
      preEnvelope,
      this.managementKey,
      {
        principalKeyFingerprint: selectorPrincipal,
        managementNonce: this.configuration.managementNonce,
        managementCorrelationId: this.configuration.managementCorrelationId,
        candidateIdentity: this.configuration.candidateIdentity,
        stagingRouteIdentityDigest: requiredDigest(
          prePayload?.stagingRouteIdentityDigest,
          "PRE staging route identity",
        ),
        stagingBinding: prePayload.stagingBinding,
        stagingActivationPrecheck,
      },
      referenceTime,
    );
    if (preCutoverHostCanary.stagingBinding.state !== "ACTIVE"
      || preCutoverHostCanary.stagingBinding.environmentIdentityDigest
        === this.configuration.productionEnvironmentIdentityDigest
      || preCutoverHostCanary.stagingRouteIdentityDigest
        === this.configuration.productionRouteIdentityDigest) {
      throw new Error("Production PRE evidence did not come from an activated isolated staging binding.");
    }

    const binding = receiptBinding(receipt, selectorPrincipal);
    const productionActivationPrecheck = verifyConnectorActivationProductionPrecheck(
      precheckEnvelope,
      this.managementKey,
      {
        ...binding,
        tuple: receipt.tuple,
        preCutoverHostCanary,
        oauthResource: this.configuration.oauthResource,
        productionEnvironmentIdentityDigest: this.configuration.productionEnvironmentIdentityDigest,
        productionRouteIdentityDigest: this.configuration.productionRouteIdentityDigest,
      },
      referenceTime,
    );
    const ownerApproval = verifyConnectorActivationOwnerApproval(
      ownerEnvelope,
      this.managementKey,
      {
        ...binding,
        preCutoverHostCanaryDigest: preCutoverHostCanary.signedPayloadDigest,
        productionActivationPrecheckDigest: productionActivationPrecheck.signedPayloadDigest,
      },
      referenceTime,
    );
    if (ownerApproval.principalKeyFingerprint !== preCutoverHostCanary.principalKeyFingerprint
      || ownerApproval.principalKeyFingerprint !== productionActivationPrecheck.principalKeyFingerprint) {
      throw new Error("Connector lifecycle staged evidence does not share one verified owner principal.");
    }
    if (journalEntry) {
      assertJournalEntryBinding(
        journalEntry,
        ownerApproval,
        preCutoverHostCanary,
        receipt,
      );
    }

    this.preparation = {
      receipt,
      principalKeyFingerprint: ownerApproval.principalKeyFingerprint,
      ownerApproval,
      preCutoverHostCanary,
      productionActivationPrecheck,
      stagingActivationPrecheck,
      journalKey,
      ...(journalEntry ? { journalEntry } : {}),
    };
    return branded({
      state: "CONNECTOR_ACTIVATION_PREPARED",
      receiptId: receipt.receiptId,
      tupleDigest: receipt.tupleDigest,
      journalContentGeneration: this.journal.identity().contentGeneration,
    }, PREPARED_BRAND) as ConnectorActivationLifecyclePrepared;
  }

  async activateOrReconcile(): Promise<
    ConnectorActivationLifecyclePending | ConnectorActivationLifecycleVerified
  > {
    this.assertOpen();
    const preparation = this.preparation ?? await this.prepareThenRead();
    let readback: PendingReadback;
    const input = {
      receiptId: preparation.receipt.receiptId,
      tuple: preparation.receipt.tuple,
      authenticatedOwnerPrincipalKeyFingerprint: preparation.principalKeyFingerprint,
      ownerApproval: preparation.ownerApproval,
      preCutoverHostCanary: preparation.preCutoverHostCanary,
      productionActivationPrecheck: preparation.productionActivationPrecheck,
    };
    const currentEntry = this.journal.load(preparation.journalKey);
    if (currentEntry?.outcomes.at(-1)?.state === "POST_ACTIVATION_VERIFIED") {
      const terminalReadback = this.reconstructPending(preparation);
      assertExactPendingReadback(terminalReadback, this.oauthStore, this.authorityRegistry);
      this.pending = terminalReadback;
      return this.verifyPostActivation();
    }
    if (currentEntry) {
      if (!currentEntry.recovery) {
        throw new Error("Connector activation intent was consumed without a recoverable authority locator.");
      }
      const reconciled = this.finalizer.reconcile({ ...input, recovery: currentEntry.recovery });
      if (reconciled.state !== "ACTIVATED_PENDING_POSTCHECK") {
        if (reconciled.state === "UNKNOWN" && reconciled.recovery.dispatchState === "DISPATCHED") {
          this.journal.markTerminal(preparation.journalKey, {
            state: "UNKNOWN",
            evidenceDigest: digestJson(reconciled),
          });
        }
        throw new Error(`Connector activation recovery is ${reconciled.state}; replay is forbidden.`);
      }
      readback = pendingReadbackFromReconciliation(
        reconciled,
        this.authorityRegistry,
        preparation.principalKeyFingerprint,
      );
    } else {
      const finalized = this.finalizer.finalize(input);
      readback = pendingReadbackFromFinalization(finalized);
    }
    assertExactPendingReadback(readback, this.oauthStore, this.authorityRegistry);
    const latestEntry = this.journal.load(preparation.journalKey);
    if (!latestEntry?.recovery || latestEntry.recovery.dispatchState !== "DISPATCHED") {
      throw new Error("Connector activation committed without its durable DISPATCHED journal tombstone.");
    }
    this.journal.markTerminal(preparation.journalKey, {
      state: "ACTIVATED_PENDING_POSTCHECK",
      evidenceDigest: latestEntry.intent.evidenceDigest,
    });
    this.pending = readback;
    return this.pendingResult(readback);
  }

  async waitForPostActivationReceipt(): Promise<void> {
    this.assertOpen();
    const deadline = Date.parse(this.configuration.postActivation.deadlineAt);
    while (Date.now() <= deadline) {
      try {
        await assertOwnerOnlyRegularFile(
          this.configuration.postActivation.receiptPath,
          "POST activation Host receipt",
        );
        return;
      } catch (error) {
        if (!isNodeError(error, "ENOENT")) throw error;
      }
      await sleep(this.configuration.postActivation.pollIntervalMs);
    }
    throw new Error("POST activation Host receipt did not arrive before the request-bound deadline.");
  }

  async verifyPostActivation(): Promise<ConnectorActivationLifecycleVerified> {
    this.assertOpen();
    const preparation = this.preparation ?? await this.prepareThenRead();
    const pending = this.pending ?? this.reconstructPending(preparation);
    assertExactPendingReadback(pending, this.oauthStore, this.authorityRegistry);

    const activeBinding = assertExactActiveBinding(pending.activationReceipt, this.oauthStore);
    const postEnvelope = await readSignedArtifact<ConnectorActivationPostActivationHostCanaryPayload>(
      { path: this.configuration.postActivation.receiptPath, sha256: undefined },
      "POST_ACTIVATION_HOST_CANARY",
    );
    const tokenFamily = readActiveTokenFamily(
      this.configuration.oauthDatabasePath,
      activeBinding,
      requiredDigest(postEnvelope.payload?.tokenFamilyIdDigest, "POST token family selector"),
    );
    const previousBindingState = assertPreviousBindingDisposition(
      pending.activationReceipt,
      this.oauthStore,
    );
    await this.assertRuntimeAndRouteReadback(activeBinding);

    const entryBefore = this.journal.load(preparation.journalKey);
    const alreadyVerified = entryBefore?.outcomes.find(
      (outcome) => outcome.state === "POST_ACTIVATION_VERIFIED",
    );
    const verifiedPost = verifyConnectorActivationPostActivationHostCanary(
      postEnvelope,
      this.managementKey,
      {
        principalKeyFingerprint: preparation.principalKeyFingerprint,
        managementNonce: this.configuration.managementNonce,
        managementCorrelationId: this.configuration.managementCorrelationId,
        productionActivationPrecheckDigest:
          preparation.productionActivationPrecheck.signedPayloadDigest,
        activationReceipt: pending.activationReceipt,
        activationAuthorityReceipt: pending.activationAuthorityReceipt,
        newActiveBindingState: "ACTIVE",
        tokenFamilyIdDigest: tokenFamily.tokenFamilyIdDigest,
        tokenFamilyBindingId: tokenFamily.tokenFamilyBindingId,
        previousBindingState,
        productionIdentity: this.configuration.candidateIdentity,
        productionEnvironmentIdentityDigest: this.configuration.productionEnvironmentIdentityDigest,
        productionRouteIdentityDigest: this.configuration.productionRouteIdentityDigest,
      },
      alreadyVerified?.recordedAtMs ?? Date.now(),
    );
    if (verifiedPost.observedAtMs <= Number(new Date(pending.activationReceipt.activatedAt!).getTime())) {
      throw new Error("POST activation evidence must be observed strictly after OAuth activation.");
    }
    assertCanaryAuthorityReadback(
      this.authorityRegistry,
      verifiedPost.mutation,
      preparation.principalKeyFingerprint,
    );
    this.journal.markTerminal(preparation.journalKey, {
      state: "POST_ACTIVATION_VERIFIED",
      evidenceDigest: verifiedPost.signedPayloadDigest,
    });
    return branded({
      state: "POST_ACTIVATION_VERIFIED",
      receiptId: pending.activationReceipt.receiptId,
      tupleDigest: pending.activationReceipt.tupleDigest,
      activationReceiptDigest: connectorActivationReceiptDigest(pending.activationReceipt),
      activationProofDigest: pending.activationAuthorityReceipt.proofDigest,
      authorityReceiptDigest: pending.authorityReceiptDigest,
      postActivationEvidenceDigest: verifiedPost.signedPayloadDigest,
      journalContentGeneration: this.journal.identity().contentGeneration,
    }, VERIFIED_BRAND) as ConnectorActivationLifecycleVerified;
  }

  close(): void {
    if (this.closed) return;
    this.closed = true;
    let first: unknown;
    for (const close of [
      () => this.journal.close(),
      () => this.authorityRegistry.close(),
      () => this.oauthStore.close(),
    ]) {
      try {
        close();
      } catch (error) {
        first ??= error;
      }
    }
    if (first) throw first;
  }

  private async prepareThenRead(): Promise<VerifiedPreparation> {
    await this.prepare();
    return this.preparation!;
  }

  private reconstructPending(preparation: VerifiedPreparation): PendingReadback {
    const entry = this.journal.load(preparation.journalKey);
    if (!entry?.recovery || entry.recovery.dispatchState !== "DISPATCHED"
      || !entry.outcomes.some((outcome) => outcome.state === "ACTIVATED_PENDING_POSTCHECK")) {
      throw new Error("POST verification requires durable ACTIVATED_PENDING_POSTCHECK evidence.");
    }
    const activationReceipt = this.oauthStore.getActivationReceipt(preparation.receipt.receiptId);
    const activationAuthorityReceipt = this.oauthStore.getActivationAuthorityReceipt(
      preparation.receipt.receiptId,
    );
    if (!activationReceipt || !activationAuthorityReceipt) {
      throw new Error("Activated OAuth receipt and authority proof are missing during recovery.");
    }
    return {
      activationReceipt,
      activationAuthorityReceipt,
      recovery: entry.recovery,
      authorityReceiptDigest: activationAuthorityCompletionDigest(
        this.authorityRegistry,
        entry.recovery,
        preparation.principalKeyFingerprint,
      ),
    };
  }

  private pendingResult(readback: PendingReadback): ConnectorActivationLifecyclePending {
    return branded({
      state: "ACTIVATED_PENDING_POSTCHECK",
      receiptId: readback.activationReceipt.receiptId,
      tupleDigest: readback.activationReceipt.tupleDigest,
      activationReceiptDigest: connectorActivationReceiptDigest(readback.activationReceipt),
      activationProofDigest: readback.activationAuthorityReceipt.proofDigest,
      authorityReceiptDigest: readback.authorityReceiptDigest,
      journalContentGeneration: this.journal.identity().contentGeneration,
    }, PENDING_BRAND) as ConnectorActivationLifecyclePending;
  }

  private async assertRuntimeAndRouteReadback(activeBinding: ConnectorBindingRecord): Promise<void> {
    const authorizationHeader = managementAuthorizationHeader(this.managementKey);
    const runtime = await readJsonUrl(
      this.configuration.postActivation.runtimeIdentityUrl,
      authorizationHeader,
    );
    const runtimeIdentity = isRecord(runtime) && isRecord(runtime.identity) ? runtime.identity : runtime;
    if (digestJson(runtimeIdentity) !== this.configuration.candidateIdentity.runtimeIdentityDigest) {
      throw new Error("POST runtime identity readback does not match the immutable candidate.");
    }
    const route = await readJsonUrl(
      this.configuration.postActivation.routeIdentityUrl,
      authorizationHeader,
    );
    if (!isRecord(route)
      || route.schemaVersion !== 1
      || route.state !== "ACTIVE"
      || route.routeCount !== 1
      || route.canonicalName !== activeBinding.canonicalName
      || route.bindingId !== activeBinding.bindingId
      || route.runtimeIdentityDigest !== this.configuration.candidateIdentity.runtimeIdentityDigest
      || route.productionEnvironmentIdentityDigest
        !== this.configuration.productionEnvironmentIdentityDigest
      || route.productionRouteIdentityDigest !== this.configuration.productionRouteIdentityDigest) {
      throw new Error("POST route identity readback is not the exact canonical production route.");
    }
  }

  private assertOpen(): void {
    if (this.closed) throw new Error("Connector activation lifecycle manager is closed.");
  }
}

function pendingReadbackFromFinalization(
  result: ConnectorActivationFinalizationResult,
): PendingReadback {
  return {
    activationReceipt: result.activationReceipt,
    activationAuthorityReceipt: result.activationAuthorityReceipt,
    recovery: result.recovery,
    authorityReceiptDigest: result.authorityCompletionReceipt.receiptDigest,
  };
}

function pendingReadbackFromReconciliation(
  result: ConnectorActivationPendingPostcheckReconciliation,
  authorityRegistry: OperationAuthorityRegistry,
  principalKeyFingerprint: string,
): PendingReadback {
  return {
    activationReceipt: result.activationReceipt,
    activationAuthorityReceipt: result.activationAuthorityReceipt,
    recovery: result.recovery,
    authorityReceiptDigest: result.recoveredAuthorityReceipt?.receiptDigest
      ?? activationAuthorityCompletionDigest(
        authorityRegistry,
        result.recovery,
        principalKeyFingerprint,
      ),
  };
}

function activationAuthorityCompletionDigest(
  authorityRegistry: OperationAuthorityRegistry,
  recovery: ConnectorActivationRecoveryHandle,
  principalKeyFingerprint: string,
): string {
  const status = authorityRegistry.status(recovery.authorityId, principalKeyFingerprint);
  const receipt = presentedReceipt(status, recovery.actionClaimId);
  assertPassReceipt(receipt, recovery);
  return requiredDigest(receipt.receiptDigest, "activation authority completion receipt");
}

function assertExactPendingReadback(
  pending: PendingReadback,
  oauthStore: SqliteOAuthStore,
  authorityRegistry: OperationAuthorityRegistry,
): void {
  const receipt = oauthStore.getActivationReceipt(pending.activationReceipt.receiptId);
  const proof = oauthStore.getActivationAuthorityReceipt(pending.activationReceipt.receiptId);
  if (!receipt || receipt.status !== "ACTIVATED" || !receipt.activatedAt
    || !proof
    || connectorActivationReceiptDigest(receipt)
      !== connectorActivationReceiptDigest(pending.activationReceipt)
    || connectorActivationAuthorityReceiptDigest(proof)
      !== connectorActivationAuthorityReceiptDigest(pending.activationAuthorityReceipt)
    || receipt.ownerAuthorityId !== pending.recovery.authorityId
    || proof.authorityId !== pending.recovery.authorityId
    || proof.actionClaimId !== pending.recovery.actionClaimId
    || proof.principalKeyFingerprint !== pending.recovery.principalKeyFingerprint) {
    throw new Error("OAuth activation readback does not match the durable DISPATCHED authority proof.");
  }
  const status = authorityRegistry.status(
    pending.recovery.authorityId,
    pending.recovery.principalKeyFingerprint,
  );
  const authorityReceipt = presentedReceipt(status, pending.recovery.actionClaimId);
  assertPassReceipt(authorityReceipt, pending.recovery);
  if (authorityReceipt.receiptDigest !== pending.authorityReceiptDigest) {
    throw new Error("Activation authority completion digest changed after the durable boundary.");
  }
}

function assertExactActiveBinding(
  receipt: ConnectorActivationReceipt,
  oauthStore: SqliteOAuthStore,
): ConnectorBindingRecord {
  const readiness = oauthStore.connectorReadiness(receipt.tuple.canonicalName);
  const active = oauthStore.getActiveConnectorBinding(receipt.tuple.canonicalName);
  const exact = oauthStore.getConnectorBinding(receipt.tuple.candidateBindingId);
  if (readiness.activeCount !== 1 || !active || !exact
    || active.bindingId !== exact.bindingId
    || exact.state !== "ACTIVE"
    || exact.canonicalName !== receipt.tuple.canonicalName
    || exact.clientId !== receipt.tuple.clientId
    || exact.installationEpoch !== receipt.tuple.installationEpoch
    || exact.schemaGeneration !== receipt.tuple.schemaGeneration
    || exact.authorityContractGeneration !== receipt.tuple.authorityContractGeneration
    || exact.redirectUrisDigest !== receipt.tuple.redirectUrisDigest
    || exact.buildDigest !== receipt.tuple.buildDigest) {
    throw new Error("OAuth readback does not contain exactly one exact new ACTIVE candidate binding.");
  }
  return exact;
}

function assertPreviousBindingDisposition(
  receipt: ConnectorActivationReceipt,
  oauthStore: SqliteOAuthStore,
): "DRAINING" | "ABSENT" {
  if (!receipt.previousActiveBindingId) return "ABSENT";
  const previous = oauthStore.getConnectorBinding(receipt.previousActiveBindingId);
  if (!previous || previous.state !== "DRAINING" || previous.bindingId === receipt.tuple.candidateBindingId) {
    throw new Error("Prior ACTIVE binding is not the exact allowed DRAINING preimage.");
  }
  return "DRAINING";
}

function readActiveTokenFamily(
  oauthDatabasePath: string,
  binding: ConnectorBindingRecord,
  expectedDigest: string,
): ActiveTokenFamilyReadback {
  const sqlite = new Database(resolve(oauthDatabasePath), { readonly: true, fileMustExist: true });
  try {
    const rows = sqlite.prepare(`
      SELECT family_id AS familyId, client_id AS clientId,
             connector_binding_id AS connectorBindingId,
             installation_epoch AS installationEpoch, drain_epoch AS drainEpoch,
             status
        FROM oauth_token_families
       WHERE status = 'ACTIVE'
       ORDER BY family_id
    `).all() as Array<{
      familyId: string;
      clientId: string;
      connectorBindingId: string | null;
      installationEpoch: number | null;
      drainEpoch: number | null;
      status: string;
    }>;
    const matching = rows.filter((row) => sha256Digest(row.familyId) === expectedDigest);
    if (matching.length !== 1) {
      throw new Error("POST token family digest does not select exactly one ACTIVE family.");
    }
    const row = matching[0]!;
    if (row.status !== "ACTIVE"
      || row.clientId !== binding.clientId
      || row.connectorBindingId !== binding.bindingId
      || row.installationEpoch !== binding.installationEpoch
      || row.drainEpoch !== binding.drainEpoch) {
      throw new Error("POST token family does not belong to the exact new ACTIVE binding.");
    }
    return {
      tokenFamilyIdDigest: expectedDigest,
      tokenFamilyBindingId: binding.bindingId,
    };
  } finally {
    sqlite.close();
  }
}

function assertCanaryAuthorityReadback(
  authorityRegistry: OperationAuthorityRegistry,
  mutation: ConnectorActivationPostActivationHostCanaryPayload["mutation"],
  principalKeyFingerprint: string,
): void {
  const status = authorityRegistry.status(mutation.authorityId, principalKeyFingerprint);
  const receipt = presentedReceipt(status, mutation.actionClaimId);
  if (receipt.state !== "PASS" || receipt.result !== "PASS" || receipt.leaseState !== "RELEASED"
    || receipt.providerCallCount !== 1
    || receipt.receiptDigest !== mutation.authorityReceiptDigest
    || receipt.resourceKeySha256 !== mutation.resourceKeySha256
    || receipt.fencingToken !== mutation.fencingToken) {
    throw new Error("POST session-B mutation authority readback is not exact PASS/dispatch-one/released.");
  }
  const actions = isRecord(status) && Array.isArray(status.actions) ? status.actions : [];
  const action = actions.find((candidate) => isRecord(candidate)
    && candidate.id === `action_${mutation.actionFingerprint}`);
  if (!isRecord(action) || action.resourceKeySha256 !== mutation.resourceKeySha256) {
    throw new Error("POST mutation action fingerprint/resource readback does not match signed evidence.");
  }
}

function presentedReceipt(status: unknown, actionClaimId: string | undefined): Record<string, unknown> {
  if (!isRecord(status) || !Array.isArray(status.receipts) || !actionClaimId) {
    throw new Error("Authority PASS receipt readback is missing.");
  }
  const matches = status.receipts.filter(
    (candidate) => isRecord(candidate) && candidate.actionClaimId === actionClaimId,
  );
  if (matches.length !== 1) throw new Error("Authority PASS receipt readback is not unique.");
  return matches[0] as Record<string, unknown>;
}

function assertPassReceipt(
  receipt: Record<string, unknown>,
  recovery: ConnectorActivationRecoveryHandle,
): void {
  if (receipt.state !== "PASS" || receipt.result !== "PASS" || receipt.leaseState !== "RELEASED"
    || receipt.providerCallCount !== 1
    || receipt.actionClaimId !== recovery.actionClaimId
    || receipt.resourceKeySha256 !== recovery.resourceKeySha256
    || receipt.fencingToken !== recovery.fencingToken
    || !SHA256_DIGEST_PATTERN.test(String(receipt.receiptDigest ?? ""))) {
    throw new Error("Activation authority receipt is not exact PASS/dispatch-one/released readback.");
  }
}

function assertJournalEntryBinding(
  entry: ConnectorActivationJournalEntry,
  ownerApproval: VerifiedConnectorActivationOwnerApproval,
  preCutoverHostCanary: VerifiedConnectorActivationPreCutoverHostCanary,
  receipt: ConnectorActivationReceipt,
): void {
  if (entry.intent.principalKeyFingerprint !== ownerApproval.principalKeyFingerprint
    || entry.intent.approvalId !== ownerApproval.approvalId
    || entry.intent.receiptId !== receipt.receiptId
    || entry.intent.tupleDigest !== receipt.tupleDigest
    || entry.intent.activePreimageDigest !== receipt.preimageDigest
    || entry.intent.finalizationPlanDigest !== connectorActivationFinalizationPlanDigest(receipt)
    || entry.intent.freshHostReceiptId !== preCutoverHostCanary.preCutoverHostCanaryId) {
    throw new Error("Connector journal entry does not match verified request-bound evidence.");
  }
}

function assertJournalIdentity(
  observed: ConnectorActivationJournalIdentity,
  expected: ConnectorActivationJournalIdentity,
  mutableContentExpected: boolean,
): void {
  for (const field of [
    "storeId",
    "storePath",
    "schemaVersion",
    "migrationManifestDigest",
    "snapshotPolicy",
    "receiptReplayPolicy",
    "schemaFingerprint",
    "createdAtMs",
  ] as const) {
    const left = field === "storePath" ? resolve(String(observed[field])) : observed[field];
    const right = field === "storePath" ? resolve(String(expected[field])) : expected[field];
    if (left !== right) throw new Error(`Connector journal immutable identity mismatch: ${field}.`);
  }
  if (!mutableContentExpected && observed.contentGeneration !== expected.contentGeneration) {
    throw new Error("Connector journal content generation changed before activation preparation.");
  }
  requiredDigest(observed.contentGeneration, "connector journal content generation");
}

function assertReceiptBinding(
  receipt: ConnectorActivationReceipt,
  configuration: ConnectorActivationLifecycleConfiguration,
): void {
  if (receipt.receiptId !== configuration.activation.receiptId
    || receipt.tupleDigest !== configuration.activation.tupleDigest
    || receipt.preimageDigest !== configuration.activation.activePreimageDigest
    || connectorActivationFinalizationPlanDigest(receipt)
      !== configuration.activation.finalizationPlanDigest
    || receipt.tuple.buildDigest !== configuration.candidateIdentity.buildDigest
    || receipt.tuple.schemaGeneration !== configuration.candidateIdentity.schemaGeneration
    || receipt.tuple.authorityContractGeneration
      !== configuration.candidateIdentity.authorityContractGeneration) {
    throw new Error("Persisted activation receipt/tuple/preimage/plan drifted from immutable request identity.");
  }
}

function receiptBinding(receipt: ConnectorActivationReceipt, principalKeyFingerprint: string) {
  return {
    principalKeyFingerprint,
    receiptId: receipt.receiptId,
    canonicalName: receipt.tuple.canonicalName,
    tupleDigest: receipt.tupleDigest,
    activePreimageDigest: receipt.preimageDigest,
    finalizationPlanDigest: connectorActivationFinalizationPlanDigest(receipt),
  };
}

async function readSignedArtifact<T>(
  artifact: { path: string; sha256?: string },
  expectedKind: SignedConnectorActivationEvidence<T>["kind"],
): Promise<SignedConnectorActivationEvidence<T>> {
  await assertOwnerOnlyRegularFile(artifact.path, expectedKind);
  const content = await readFile(artifact.path);
  if (artifact.sha256 !== undefined && sha256Digest(content) !== artifact.sha256) {
    throw new Error(`${expectedKind} file digest does not match the immutable request.`);
  }
  let value: unknown;
  try {
    value = JSON.parse(content.toString("utf8"));
  } catch {
    throw new Error(`${expectedKind} file is not canonical JSON evidence.`);
  }
  if (!isRecord(value) || value.schemaVersion !== 2 || value.kind !== expectedKind
    || !isRecord(value.payload)) {
    throw new Error(`${expectedKind} evidence envelope identity is invalid.`);
  }
  return value as unknown as SignedConnectorActivationEvidence<T>;
}

async function validatePostChallenge(
  configuration: ConnectorActivationLifecycleConfiguration,
): Promise<void> {
  const artifact = configuration.postActivation;
  await assertOwnerOnlyRegularFile(artifact.challengePath, "POST activation challenge");
  const content = await readFile(artifact.challengePath);
  if (sha256Digest(content) !== artifact.challengeSha256) {
    throw new Error("POST activation challenge digest does not match the immutable request.");
  }
  const value = JSON.parse(content.toString("utf8")) as unknown;
  if (!isRecord(value)
    || value.schemaVersion !== 1
    || value.kind !== "POST_ACTIVATION_CHALLENGE"
    || value.managementNonce !== configuration.managementNonce
    || value.managementCorrelationId !== configuration.managementCorrelationId
    || value.productionEnvironmentIdentityDigest
      !== configuration.productionEnvironmentIdentityDigest
    || value.productionRouteIdentityDigest !== configuration.productionRouteIdentityDigest
    || stableJson(value.candidateIdentity) !== stableJson(configuration.candidateIdentity)) {
    throw new Error("POST activation challenge does not bind the immutable production identity.");
  }
}

function validateConfiguration(
  configuration: ConnectorActivationLifecycleConfiguration,
): ConnectorActivationLifecycleConfiguration {
  if (!configuration || typeof configuration !== "object") {
    throw new Error("Connector lifecycle configuration is required.");
  }
  for (const path of [
    configuration.oauthDatabasePath,
    configuration.authorityDatabasePath,
    configuration.managementAuthorizationKeyRef,
    configuration.preCutoverHostCanary.path,
    configuration.stagingActivationPrecheck.path,
    configuration.productionActivationPrecheck.path,
    configuration.ownerApproval.path,
    configuration.journal.path,
    configuration.postActivation.challengePath,
    configuration.postActivation.receiptPath,
  ]) {
    if (!isAbsolute(path)) throw new Error(`Connector lifecycle path must be absolute: ${path}`);
  }
  for (const digest of [
    configuration.preCutoverHostCanary.sha256,
    configuration.stagingActivationPrecheck.sha256,
    configuration.productionActivationPrecheck.sha256,
    configuration.ownerApproval.sha256,
    configuration.postActivation.challengeSha256,
    configuration.activation.tupleDigest,
    configuration.activation.activePreimageDigest,
    configuration.activation.finalizationPlanDigest,
    configuration.productionEnvironmentIdentityDigest,
    configuration.productionRouteIdentityDigest,
    ...Object.values(configuration.candidateIdentity),
  ]) requiredDigest(digest, "connector lifecycle digest");
  requiredText(configuration.managementNonce, "management nonce", 512);
  requiredText(configuration.managementCorrelationId, "management correlation", 256);
  requiredText(configuration.oauthResource, "OAuth resource", 2_048);
  if (!Number.isFinite(Date.parse(configuration.postActivation.deadlineAt))) {
    throw new Error("POST activation deadline is invalid.");
  }
  if (!Number.isInteger(configuration.postActivation.pollIntervalMs)
    || configuration.postActivation.pollIntervalMs < 10
    || configuration.postActivation.pollIntervalMs > 5_000) {
    throw new Error("POST activation poll interval must be 10 through 5000 milliseconds.");
  }
  const runtimeIdentityUrl = new URL(configuration.postActivation.runtimeIdentityUrl);
  const routeIdentityUrl = new URL(configuration.postActivation.routeIdentityUrl);
  for (const [label, parsed, expectedPath] of [
    ["runtime", runtimeIdentityUrl, "/readyz"],
    ["route", routeIdentityUrl, "/route-identityz"],
  ] as const) {
    if (parsed.protocol !== "http:"
      || !isLoopbackHostname(parsed.hostname)
      || parsed.username !== ""
      || parsed.password !== ""
      || parsed.search !== ""
      || parsed.hash !== ""
      || parsed.pathname !== expectedPath) {
      throw new Error(
        `POST ${label} readback URL must be the exact loopback management ${expectedPath} endpoint.`,
      );
    }
  }
  if (runtimeIdentityUrl.origin !== routeIdentityUrl.origin) {
    throw new Error("POST runtime and route readbacks must use the same loopback management origin.");
  }
  return configuration;
}

function isLoopbackHostname(hostname: string): boolean {
  return hostname === "127.0.0.1" || hostname === "localhost" || hostname === "[::1]";
}

async function assertOwnerOnlyRegularFile(path: string, label: string): Promise<void> {
  const metadata = await lstat(resolve(path));
  if (!metadata.isFile() || metadata.isSymbolicLink() || (metadata.mode & 0o077) !== 0
    || (typeof process.getuid === "function" && metadata.uid !== process.getuid())) {
    throw new Error(`${label} must be an owner-only regular file owned by the broker user.`);
  }
}

async function readJsonUrl(url: string, authorizationHeader: string): Promise<unknown> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 5_000);
  try {
    const response = await fetch(url, {
      headers: { authorization: authorizationHeader },
      signal: controller.signal,
    });
    const body = await response.text();
    if (response.status !== 200 || body.length > 64 * 1024) {
      throw new Error(`POST readback failed at ${url}: HTTP ${response.status}.`);
    }
    return JSON.parse(body) as unknown;
  } finally {
    clearTimeout(timer);
  }
}

function branded<T extends object>(value: T, brand: symbol): Readonly<T> {
  Object.defineProperty(value, brand, {
    value: true,
    enumerable: false,
    configurable: false,
    writable: false,
  });
  return Object.freeze(value);
}

function sha256Digest(value: string | Uint8Array): string {
  return `sha256:${createHash("sha256").update(value).digest("hex")}`;
}

function digestJson(value: unknown): string {
  return sha256Digest(stableJson(value));
}

function stableJson(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(stableJson).join(",")}]`;
  if (value && typeof value === "object") {
    const record = value as Record<string, unknown>;
    return `{${Object.keys(record).sort().map(
      (key) => `${JSON.stringify(key)}:${stableJson(record[key])}`,
    ).join(",")}}`;
  }
  return JSON.stringify(value) ?? "null";
}

function requiredDigest(value: unknown, name: string): string {
  if (typeof value !== "string" || !SHA256_DIGEST_PATTERN.test(value)) {
    throw new Error(`${name} must be a SHA-256 digest.`);
  }
  return value;
}

function requiredRawDigest(value: unknown, name: string): string {
  if (typeof value !== "string" || !RAW_SHA256_PATTERN.test(value)) {
    throw new Error(`${name} must be a raw SHA-256 fingerprint.`);
  }
  return value;
}

function requiredText(value: unknown, name: string, maximum: number): string {
  if (typeof value !== "string" || value.trim().length === 0 || value.length > maximum
    || /[\r\n\0]/u.test(value)) {
    throw new Error(`${name} is missing or invalid.`);
  }
  return value;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return Boolean(value) && typeof value === "object" && !Array.isArray(value);
}

function isNodeError(error: unknown, code: string): boolean {
  return error instanceof Error && "code" in error && (error as NodeJS.ErrnoException).code === code;
}

function sleep(milliseconds: number): Promise<void> {
  return new Promise((resolvePromise) => setTimeout(resolvePromise, milliseconds));
}
