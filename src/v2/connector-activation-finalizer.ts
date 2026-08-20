import { createHash } from "node:crypto";
import {
  connectorActivationAuthorityActionFingerprint,
  connectorActivationAuthorityDescriptor,
  connectorActivationAuthorityResourceKeySha256,
  type ConnectorActivationAuthorityBinding,
  type ConnectorActivationAuthorityProof,
  type ConnectorActivationAuthorityReceipt,
  type ConnectorActivationReceipt,
  type ConnectorActivationTuple,
  type SqliteOAuthStore,
} from "../oauth-store.js";
import {
  type AuthorityCompletionReceipt,
  type AuthorityGrant,
  type OperationAuthorityDispatchController,
  type OperationAuthorityRegistry,
  type RecoveredConnectorActivationAuthorityReceipt,
} from "./authority.js";
import {
  assertVerifiedConnectorActivationOwnerApproval,
  assertVerifiedConnectorActivationPreCutoverHostCanary,
  assertVerifiedConnectorActivationProductionPrecheck,
  type VerifiedConnectorActivationOwnerApproval,
  type VerifiedConnectorActivationPreCutoverHostCanary,
  type VerifiedConnectorActivationProductionPrecheck,
} from "./connector-activation-evidence.js";
import { UniversalBrokerError } from "./errors.js";

const SHA256_DIGEST_PATTERN = /^sha256:[a-f0-9]{64}$/u;
const RAW_SHA256_PATTERN = /^[a-f0-9]{64}$/u;
const RECEIPT_ID_PATTERN = /^connector-activation-[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/u;
const AUTHORITY_ID_PATTERN = /^authority_[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/u;
const ACTION_CLAIM_ID_PATTERN = /^authority_claim_[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/u;
const CANONICAL_NAME_PATTERN = /^[A-Za-z][A-Za-z0-9._-]{0,127}$/u;
export interface ConnectorActivationFinalizationInput {
  receiptId: string;
  tuple: ConnectorActivationTuple;
  authenticatedOwnerPrincipalKeyFingerprint: string;
  ownerApproval: VerifiedConnectorActivationOwnerApproval;
  preCutoverHostCanary: VerifiedConnectorActivationPreCutoverHostCanary;
  productionActivationPrecheck: VerifiedConnectorActivationProductionPrecheck;
}

export type ConnectorActivationRecoveryDispatchState =
  | "NOT_CLAIMED"
  | "CLAIMED"
  | "DISPATCHED";

export interface ConnectorActivationRecoveryIntent extends ConnectorActivationAuthorityBinding {
  schema: "devspace.connector_activation_recovery_intent";
  schemaVersion: 1;
  state: "INTENT_RESERVED";
  approvalId: string;
  freshHostReceiptId: string;
  principalKeyFingerprint: string;
  actionFingerprint: string;
  resourceKeySha256: string;
  evidenceDigest: string;
}

export interface ConnectorActivationRecoveryHandle extends ConnectorActivationAuthorityBinding {
  schema: "devspace.connector_activation_recovery";
  schemaVersion: 1;
  approvalId: string;
  freshHostReceiptId: string;
  dispatchState: ConnectorActivationRecoveryDispatchState;
  authorityId: string;
  principalKeyFingerprint: string;
  actionFingerprint: string;
  resourceKeySha256: string;
  evidenceDigest: string;
  actionClaimId?: string;
  fencingToken?: number;
  claimedAtMs?: number;
  dispatchedAtMs?: number;
}

export interface ConnectorActivationFinalizationResult {
  state: "ACTIVATED_PENDING_POSTCHECK";
  finalizationPlanDigest: string;
  evidenceDigest: string;
  activationReceipt: ConnectorActivationReceipt;
  activationAuthorityReceipt: ConnectorActivationAuthorityReceipt;
  authorityCompletionReceipt: AuthorityCompletionReceipt;
  recovery: ConnectorActivationRecoveryHandle;
}

export interface ConnectorActivationReconciliationInput
  extends ConnectorActivationFinalizationInput {
  recovery: ConnectorActivationRecoveryHandle;
}

export interface ConnectorActivationNotDispatchedReconciliation {
  state: "NOT_DISPATCHED";
  retryAllowed: true;
  oauthCommitted: false;
  authorityState: "NOT_CLAIMED" | "CANCELLED_NOT_DISPATCHED";
  recovery: ConnectorActivationRecoveryHandle;
}

export interface ConnectorActivationPendingPostcheckReconciliation {
  state: "ACTIVATED_PENDING_POSTCHECK";
  retryAllowed: false;
  oauthCommitted: true;
  authorityState: "PASS";
  activationReceipt: ConnectorActivationReceipt;
  activationAuthorityReceipt: ConnectorActivationAuthorityReceipt;
  recoveredAuthorityReceipt?: RecoveredConnectorActivationAuthorityReceipt;
  recovery: ConnectorActivationRecoveryHandle;
}

export interface ConnectorActivationUnknownReconciliation {
  state: "UNKNOWN";
  retryAllowed: false;
  oauthCommitted: boolean;
  authorityState: string;
  leaseState?: string;
  leaseReconciled: boolean;
  reason:
    | "DISPATCHED_OUTCOME_NOT_PROVEN"
    | "OAUTH_ACTIVATION_RECEIPT_MISMATCH";
  recovery: ConnectorActivationRecoveryHandle;
}

export type ConnectorActivationReconciliationResult =
  | ConnectorActivationNotDispatchedReconciliation
  | ConnectorActivationPendingPostcheckReconciliation
  | ConnectorActivationUnknownReconciliation;

export class ConnectorActivationUnknownError extends UniversalBrokerError {
  constructor(
    message: string,
    readonly recovery: ConnectorActivationRecoveryHandle,
    cause: unknown,
  ) {
    super("AUTHORITY_STATE_UNCERTAIN", message, {
      retryable: false,
      evidence: {
        dispatchState: "UNKNOWN",
        receiptId: recovery.receiptId,
        approvalId: recovery.approvalId,
        canonicalName: recovery.canonicalName,
        authorityId: recovery.authorityId,
        actionClaimId: recovery.actionClaimId,
        finalizationPlanDigest: recovery.finalizationPlanDigest,
        causeType: cause instanceof Error ? cause.name : typeof cause,
      },
    });
    this.name = "ConnectorActivationUnknownError";
  }
}

/**
 * Owner-only durable finalization journal. reserve() must atomically persist and
 * fsync the secret-free approval intent before any authority is created. record()
 * then durably advances the same CAS key through NOT_CLAIMED, CLAIMED, and
 * DISPATCHED. Throwing prevents the coordinator from crossing the next boundary.
 * The exclusivity key is (principalKeyFingerprint, receiptId); approvalId and
 * evidence fields are immutable attempt provenance. A stored intent is already
 * a one-shot receipt tombstone, so every second reserve must fail, including an
 * alternate approval or byte-identical retry. A stored DISPATCHED entry
 * must never regress or be replaced by another authority/action claim before
 * explicit terminal reconciliation.
 */
export interface ConnectorActivationRecoveryJournal {
  reserve(intent: Readonly<ConnectorActivationRecoveryIntent>): void;
  record(handle: Readonly<ConnectorActivationRecoveryHandle>): void;
}

interface ConnectorActivationStore {
  getActivationReceipt(receiptId: string): ConnectorActivationReceipt | undefined;
  getActivationAuthorityReceipt(receiptId: string): ConnectorActivationAuthorityReceipt | undefined;
  activatePreparedConnector(
    receiptId: string,
    tuple: ConnectorActivationTuple,
    proof: ConnectorActivationAuthorityProof,
  ): ConnectorActivationReceipt;
}

type ConnectorActivationAuthorityRegistry = Pick<
  OperationAuthorityRegistry,
  | "createConnectorActivationAuthority"
  | "prepareDispatch"
  | "status"
  | "terminalizeRecoveredConnectorActivationClaimPass"
>;

export interface ConnectorActivationFinalizerDependencies {
  oauthStore: ConnectorActivationStore | SqliteOAuthStore;
  authorityRegistry: ConnectorActivationAuthorityRegistry;
  recoveryJournal: ConnectorActivationRecoveryJournal;
  now?: () => number;
}

interface ValidatedFinalizationContext {
  receipt: ConnectorActivationReceipt;
  binding: ConnectorActivationAuthorityBinding;
  descriptor: ReturnType<typeof connectorActivationAuthorityDescriptor>;
  principalKeyFingerprint: string;
  authorityText: string;
  approvalId: string;
  freshHostReceiptId: string;
  evidenceDigest: string;
}

interface PresentedAuthorityReceipt {
  actionClaimId: string;
  resourceKeySha256: string;
  fencingToken: number;
  claimedAtMs: number;
  dispatchedAtMs?: number;
  state: string;
  result: string;
  leaseState: string;
}

interface ActivationAuthorityReadbackIdentity extends ConnectorActivationAuthorityBinding {
  authorityId: string;
  actionClaimId?: string;
  actionFingerprint: string;
  resourceKeySha256: string;
  fencingToken?: number;
  principalKeyFingerprint: string;
  evidenceDigest: string;
  claimedAtMs?: number;
  dispatchedAtMs?: number;
}

export function connectorActivationFinalizationPlanDigest(
  receipt: ConnectorActivationReceipt,
): string {
  validateReceiptIdentity(receipt);
  const previousActiveBindingId = receipt.previousActiveBindingId ?? null;
  return sha256Digest(stableJson({
    schemaVersion: 1,
    operation: "context.connector_activation_finalize",
    authority: { maximumUses: 1, risk: "R3" },
    canonicalName: receipt.tuple.canonicalName,
    receiptId: receipt.receiptId,
    candidateBindingId: receipt.tuple.candidateBindingId,
    tupleDigest: receipt.tupleDigest,
    activePreimageDigest: receipt.preimageDigest,
    previousActiveBindingId,
    drainDeadlineAt: receipt.drainDeadlineAt,
    refreshAllowedDuringDrain: receipt.refreshAllowedDuringDrain,
    transitions: {
      candidate: ["ACTIVATION_PREPARED", "ACTIVE"],
      previousActive: previousActiveBindingId === null ? null : ["ACTIVE", "DRAINING"],
    },
  }));
}

export class ConnectorActivationFinalizer {
  private readonly oauthStore: ConnectorActivationStore;
  private readonly authorityRegistry: ConnectorActivationAuthorityRegistry;
  private readonly recoveryJournal: ConnectorActivationRecoveryJournal;
  private readonly now: () => number;

  constructor(dependencies: ConnectorActivationFinalizerDependencies) {
    this.oauthStore = dependencies.oauthStore;
    this.authorityRegistry = dependencies.authorityRegistry;
    this.recoveryJournal = dependencies.recoveryJournal;
    this.now = dependencies.now ?? Date.now;
  }

  finalize(input: ConnectorActivationFinalizationInput): ConnectorActivationFinalizationResult {
    const context = this.validateFinalizationInput(input, this.now(), true);
    const intent = recoveryIntent(context);
    this.reserveRecovery(intent);
    this.assertEvidenceCurrent(input, context);
    const created = this.authorityRegistry.createConnectorActivationAuthority({
      authorityText: context.authorityText,
      descriptor: context.descriptor,
    }, context.principalKeyFingerprint);
    const authorityId = validateCreatedAuthority(created, context);
    this.recordRecovery(recoveryHandle(context, authorityId, undefined));
    const controller = this.authorityRegistry.prepareDispatch(
      authorityId,
      context.principalKeyFingerprint,
      context.descriptor,
      "R3",
    );
    let grant: AuthorityGrant | undefined;
    let crossedDispatchBarrier = false;
    try {
      this.assertEvidenceCurrent(input, context);
      grant = controller.claim();
      this.recordRecovery(recoveryHandle(context, authorityId, grant));
      this.assertEvidenceCurrent(input, context);
      grant = controller.markDispatched();
      crossedDispatchBarrier = true;
      this.recordRecovery(recoveryHandle(context, authorityId, grant));
      this.assertEvidenceCurrent(input, context);

      const proof = activationProofFromLiveGrant(context, grant);
      this.oauthStore.activatePreparedConnector(input.receiptId, input.tuple, proof);

      const exact = this.readExactCommittedActivation(context, proof);
      const completion = controller.complete("PASS", {
        reasonCode: "CONNECTOR_ACTIVATION_COMMITTED",
        receiptId: exact.activationReceipt.receiptId,
        oauthProofDigest: exact.activationAuthorityReceipt.proofDigest,
        evidenceDigest: context.evidenceDigest,
      });
      assertPassCompletion(completion);
      assertAuthorityPassReadback(
        this.authorityRegistry.status(authorityId, context.principalKeyFingerprint),
        grant,
      );
      const recovery = recoveryHandle(context, authorityId, grant);
      return {
        state: "ACTIVATED_PENDING_POSTCHECK",
        finalizationPlanDigest: context.binding.finalizationPlanDigest,
        evidenceDigest: context.evidenceDigest,
        activationReceipt: exact.activationReceipt,
        activationAuthorityReceipt: exact.activationAuthorityReceipt,
        authorityCompletionReceipt: completion,
        recovery,
      };
    } catch (error) {
      const recovery = recoveryHandle(context, authorityId, grant);
      if (!crossedDispatchBarrier) {
        cancelClaimBeforeDispatch(controller, error);
        throw error;
      }
      sealLiveDispatchUncertain(controller, recovery, error);
      throw new ConnectorActivationUnknownError(
        "Connector activation crossed DISPATCHED, but exact PASS could not be proven. Do not replay it.",
        recovery,
        error,
      );
    }
  }

  private reserveRecovery(intent: ConnectorActivationRecoveryIntent): void {
    try {
      this.recoveryJournal.reserve(Object.freeze({ ...intent }));
    } catch (error) {
      throw new UniversalBrokerError(
        "AUTHORITY_STATE_UNCERTAIN",
        "Connector activation recovery journal did not durably reserve the approval intent; this attempt did not create an authority.",
        {
          retryable: false,
          evidence: {
            dispatchState: "NOT_DISPATCHED",
            journalState: intent.state,
            receiptId: intent.receiptId,
            approvalId: intent.approvalId,
            providerDispatchCount: 0,
            journalErrorType: error instanceof Error ? error.name : typeof error,
          },
        },
      );
    }
  }

  private recordRecovery(handle: ConnectorActivationRecoveryHandle): void {
    try {
      this.recoveryJournal.record(Object.freeze({ ...handle }));
    } catch (error) {
      throw new UniversalBrokerError(
        "AUTHORITY_STATE_UNCERTAIN",
        "Connector activation recovery journal did not durably accept the next state; finalization stopped.",
        {
          retryable: false,
          evidence: {
            dispatchState: handle.dispatchState === "NOT_CLAIMED"
              ? "NOT_DISPATCHED"
              : handle.dispatchState,
            receiptId: handle.receiptId,
            approvalId: handle.approvalId,
            authorityId: handle.authorityId,
            actionClaimId: handle.actionClaimId,
            providerDispatchCount: 0,
            journalErrorType: error instanceof Error ? error.name : typeof error,
          },
        },
      );
    }
  }

  private assertEvidenceCurrent(
    input: ConnectorActivationFinalizationInput,
    context: ValidatedFinalizationContext,
  ): void {
    const nowMs = this.now();
    validateVerifiedApproval(
      input.ownerApproval,
      context.principalKeyFingerprint,
      context.binding,
      input.preCutoverHostCanary,
      input.productionActivationPrecheck,
      nowMs,
    );
    validateVerifiedPreCutoverHostCanary(
      input.preCutoverHostCanary,
      context.principalKeyFingerprint,
      context.receipt.tuple,
      nowMs,
    );
    validateVerifiedProductionPrecheck(
      input.productionActivationPrecheck,
      input.preCutoverHostCanary,
      context.principalKeyFingerprint,
      context.binding,
      context.receipt.tuple,
      nowMs,
    );
  }

  reconcile(input: ConnectorActivationReconciliationInput): ConnectorActivationReconciliationResult {
    const receipt = this.oauthStore.getActivationReceipt(input.receiptId);
    if (!receipt) {
      throw precondition("Connector activation receipt does not exist for reconciliation.");
    }
    const referenceTime = input.recovery.dispatchedAtMs
      ?? input.recovery.claimedAtMs
      ?? this.now();
    const context = this.validateFinalizationInput(input, referenceTime, false);
    validateRecoveryHandle(input.recovery, context);
    const status = this.authorityRegistry.status(
      input.recovery.authorityId,
      context.principalKeyFingerprint,
    );
    let recovery = input.recovery;
    assertAuthorityActionReadback(status, recovery);
    let authorityReceipt = findPresentedAuthorityReceipt(status, recovery.actionClaimId);
    const activationAuthorityReceipt = this.oauthStore.getActivationAuthorityReceipt(input.receiptId);

    if (!recovery.actionClaimId) {
      const discovered = solePresentedAuthorityReceipt(status);
      if (discovered) {
        recovery = recoveryFromDiscoveredAuthorityReceipt(recovery, discovered);
        authorityReceipt = discovered;
      }
    }

    if (!recovery.actionClaimId) {
      if (authorityReceipt || activationAuthorityReceipt || receipt.status !== "PREPARED") {
        return unknownReconciliation(
          recovery,
          Boolean(activationAuthorityReceipt),
          authorityReceipt?.state ?? "NOT_CLAIMED",
          authorityReceipt?.leaseState,
          false,
          "DISPATCHED_OUTCOME_NOT_PROVEN",
        );
      }
      assertUnusedAuthorityReadback(status, recovery);
      return {
        state: "NOT_DISPATCHED",
        retryAllowed: true,
        oauthCommitted: false,
        authorityState: "NOT_CLAIMED",
        recovery,
      };
    }

    if (!authorityReceipt) {
      return unknownReconciliation(
        recovery,
        Boolean(activationAuthorityReceipt),
        "MISSING_ACTION_CLAIM",
        undefined,
        false,
        "DISPATCHED_OUTCOME_NOT_PROVEN",
      );
    }
    recovery = recoveryFromAuthorityReceipt(recovery, authorityReceipt);

    if (authorityReceipt.state === "CANCELLED_NOT_DISPATCHED") {
      if (activationAuthorityReceipt || receipt.status !== "PREPARED") {
        return unknownReconciliation(
          recovery,
          Boolean(activationAuthorityReceipt),
          authorityReceipt.state,
          authorityReceipt.leaseState,
          false,
          "OAUTH_ACTIVATION_RECEIPT_MISMATCH",
        );
      }
      return {
        state: "NOT_DISPATCHED",
        retryAllowed: true,
        oauthCommitted: false,
        authorityState: "CANCELLED_NOT_DISPATCHED",
        recovery,
      };
    }

    const exactOAuthReceipt = activationAuthorityReceipt
      && receipt.status === "ACTIVATED"
      && receipt.ownerAuthorityId === recovery.authorityId
      && activationAuthorityReceipt.consumedAt === receipt.activatedAt
      && activationAuthorityReceiptMatchesRecovery(activationAuthorityReceipt, recovery)
      ? activationAuthorityReceipt
      : undefined;

    if (authorityReceipt.state === "PASS" && exactOAuthReceipt) {
      return {
        state: "ACTIVATED_PENDING_POSTCHECK",
        retryAllowed: false,
        oauthCommitted: true,
        authorityState: "PASS",
        activationReceipt: receipt,
        activationAuthorityReceipt: exactOAuthReceipt,
        recovery,
      };
    }

    if (activationAuthorityReceipt && !exactOAuthReceipt) {
      return unknownReconciliation(
        recovery,
        true,
        authorityReceipt.state,
        authorityReceipt.leaseState,
        false,
        "OAUTH_ACTIVATION_RECEIPT_MISMATCH",
      );
    }

    if (authorityReceipt.state === "UNCERTAIN" && exactOAuthReceipt) {
      const recoveredAuthorityReceipt =
        this.authorityRegistry.terminalizeRecoveredConnectorActivationClaimPass({
          principalKeyFingerprint: context.principalKeyFingerprint,
          authorityId: recovery.authorityId,
          actionClaimId: recovery.actionClaimId!,
          actionFingerprint: recovery.actionFingerprint,
          resourceKeySha256: recovery.resourceKeySha256,
          fencingToken: recovery.fencingToken!,
          oauthProofDigest: exactOAuthReceipt.proofDigest,
          evidenceDigest: recovery.evidenceDigest,
        });
      assertRecoveredAuthorityPass(
        recoveredAuthorityReceipt,
        recovery,
        exactOAuthReceipt.proofDigest,
      );
      assertRecoveredAuthorityPassReadback(
        this.authorityRegistry.status(recovery.authorityId, context.principalKeyFingerprint),
        recovery,
      );
      return {
        state: "ACTIVATED_PENDING_POSTCHECK",
        retryAllowed: false,
        oauthCommitted: true,
        authorityState: "PASS",
        activationReceipt: receipt,
        activationAuthorityReceipt: exactOAuthReceipt,
        recoveredAuthorityReceipt,
        recovery,
      };
    }

    // No OAuth receipt after DISPATCHED is not proof of absence. Keep the
    // RECOVERY_REQUIRED lease frozen so another grant cannot replay the CAS.
    return unknownReconciliation(
      recovery,
      false,
      authorityReceipt.state,
      authorityReceipt.leaseState,
      false,
      "DISPATCHED_OUTCOME_NOT_PROVEN",
    );
  }

  private validateFinalizationInput(
    input: ConnectorActivationFinalizationInput,
    referenceTimeMs: number,
    requirePrepared: boolean,
  ): ValidatedFinalizationContext {
    if (!input || typeof input !== "object") throw precondition("Connector activation input is required.");
    const principalKeyFingerprint = requiredPrincipal(input.authenticatedOwnerPrincipalKeyFingerprint);
    const receipt = this.oauthStore.getActivationReceipt(requiredReceiptId(input.receiptId));
    if (!receipt) throw precondition("Connector activation receipt does not exist.");
    if (requirePrepared && receipt.status !== "PREPARED") {
      throw precondition(`Connector activation receipt is ${receipt.status}; it cannot be replayed.`);
    }
    if (!activationTuplesEqual(receipt.tuple, input.tuple)) {
      throw precondition("Connector activation tuple does not exactly match its persisted PREPARED receipt.");
    }
    const finalizationPlanDigest = connectorActivationFinalizationPlanDigest(receipt);
    const binding: ConnectorActivationAuthorityBinding = {
      receiptId: receipt.receiptId,
      tupleDigest: receipt.tupleDigest,
      activePreimageDigest: receipt.preimageDigest,
      finalizationPlanDigest,
      canonicalName: receipt.tuple.canonicalName,
    };
    validateVerifiedApproval(
      input.ownerApproval,
      principalKeyFingerprint,
      binding,
      input.preCutoverHostCanary,
      input.productionActivationPrecheck,
      referenceTimeMs,
    );
    validateVerifiedPreCutoverHostCanary(
      input.preCutoverHostCanary,
      principalKeyFingerprint,
      receipt.tuple,
      referenceTimeMs,
    );
    validateVerifiedProductionPrecheck(
      input.productionActivationPrecheck,
      input.preCutoverHostCanary,
      principalKeyFingerprint,
      binding,
      receipt.tuple,
      referenceTimeMs,
    );
    const evidenceDigest = connectorActivationEvidenceDigest(
      binding,
      input.ownerApproval,
      input.preCutoverHostCanary,
      input.productionActivationPrecheck,
    );
    return {
      receipt,
      binding,
      descriptor: connectorActivationAuthorityDescriptor(binding),
      principalKeyFingerprint,
      authorityText: input.ownerApproval.authorityText,
      approvalId: input.ownerApproval.approvalId,
      freshHostReceiptId: input.preCutoverHostCanary.preCutoverHostCanaryId,
      evidenceDigest,
    };
  }

  private readExactCommittedActivation(
    context: ValidatedFinalizationContext,
    proof: ConnectorActivationAuthorityProof,
  ): {
    activationReceipt: ConnectorActivationReceipt;
    activationAuthorityReceipt: ConnectorActivationAuthorityReceipt;
  } {
    const activationReceipt = this.oauthStore.getActivationReceipt(context.receipt.receiptId);
    const activationAuthorityReceipt = this.oauthStore.getActivationAuthorityReceipt(
      context.receipt.receiptId,
    );
    if (
      !activationReceipt
      || activationReceipt.status !== "ACTIVATED"
      || activationReceipt.ownerAuthorityId !== proof.authorityId
      || !activationTuplesEqual(activationReceipt.tuple, context.receipt.tuple)
      || activationReceipt.tupleDigest !== context.binding.tupleDigest
      || activationReceipt.preimageDigest !== context.binding.activePreimageDigest
      || activationReceipt.previousActiveBindingId !== context.receipt.previousActiveBindingId
      || activationReceipt.drainDeadlineAt !== context.receipt.drainDeadlineAt
      || activationReceipt.refreshAllowedDuringDrain !== context.receipt.refreshAllowedDuringDrain
      || !activationAuthorityReceipt
      || activationAuthorityReceipt.consumedAt !== activationReceipt.activatedAt
      || !activationAuthorityReceiptMatchesProof(activationAuthorityReceipt, proof)
    ) {
      throw new Error("Committed connector activation readback did not match the exact grant and tuple.");
    }
    return { activationReceipt, activationAuthorityReceipt };
  }
}

function validateVerifiedApproval(
  approval: VerifiedConnectorActivationOwnerApproval,
  principalKeyFingerprint: string,
  binding: ConnectorActivationAuthorityBinding,
  preCutoverHostCanary: VerifiedConnectorActivationPreCutoverHostCanary,
  productionActivationPrecheck: VerifiedConnectorActivationProductionPrecheck,
  referenceTimeMs: number,
): void {
  try {
    assertVerifiedConnectorActivationOwnerApproval(approval);
  } catch {
    throw precondition("Owner management approval is not verified signed evidence.");
  }
  if (approval.assurance !== "cooperative") throw precondition("Owner approval assurance is invalid.");
  if (approval.principalKeyFingerprint !== principalKeyFingerprint) {
    throw new UniversalBrokerError(
      "AUTHORITY_PRINCIPAL_MISMATCH",
      "Owner management approval belongs to a different stable principal.",
    );
  }
  assertBindingMatches(approval, binding, "Owner management approval");
  if (approval.preCutoverHostCanaryDigest !== preCutoverHostCanary.signedPayloadDigest
    || approval.productionActivationPrecheckDigest !== productionActivationPrecheck.signedPayloadDigest) {
    throw precondition("Owner management approval does not bind both verified staged evidence receipts.");
  }
  if (approval.approvedAtMs < preCutoverHostCanary.observedAtMs
    || approval.approvedAtMs < productionActivationPrecheck.observedAtMs) {
    throw precondition("Owner management approval predates its signed staged evidence receipts.");
  }
  assertValidAt(approval.approvedAtMs, approval.expiresAtMs, referenceTimeMs, "Owner management approval");
}

function validateVerifiedPreCutoverHostCanary(
  host: VerifiedConnectorActivationPreCutoverHostCanary,
  principalKeyFingerprint: string,
  tuple: ConnectorActivationTuple,
  referenceTimeMs: number,
): void {
  try {
    assertVerifiedConnectorActivationPreCutoverHostCanary(host);
  } catch {
    throw precondition("PRE_CUTOVER_HOST_CANARY is not verified signed evidence.");
  }
  if (host.stage !== "PRE_CUTOVER_HOST_CANARY"
    || host.hostProvider !== "chatgpt"
    || host.actualHost !== true
    || host.stagingBinding.state !== "ACTIVE") {
    throw precondition("PRE_CUTOVER_HOST_CANARY provenance is invalid.");
  }
  if (host.principalKeyFingerprint !== principalKeyFingerprint) {
    throw new UniversalBrokerError(
      "AUTHORITY_PRINCIPAL_MISMATCH",
      "PRE_CUTOVER_HOST_CANARY belongs to a different stable principal.",
    );
  }
  if (host.stagingBinding.canonicalName !== tuple.canonicalName
    || host.candidateIdentity.schemaGeneration !== tuple.schemaGeneration
    || host.candidateIdentity.authorityContractGeneration !== tuple.authorityContractGeneration
    || host.candidateIdentity.buildDigest !== tuple.buildDigest) {
    throw precondition("PRE_CUTOVER_HOST_CANARY immutable build, schema, or authority identity drifted.");
  }
  assertValidAt(host.observedAtMs, host.expiresAtMs, referenceTimeMs, "PRE_CUTOVER_HOST_CANARY");
}

function validateVerifiedProductionPrecheck(
  precheck: VerifiedConnectorActivationProductionPrecheck,
  preCutoverHostCanary: VerifiedConnectorActivationPreCutoverHostCanary,
  principalKeyFingerprint: string,
  binding: ConnectorActivationAuthorityBinding,
  tuple: ConnectorActivationTuple,
  referenceTimeMs: number,
): void {
  try {
    assertVerifiedConnectorActivationProductionPrecheck(precheck);
  } catch {
    throw precondition("PRODUCTION_ACTIVATION_PRECHECK is not verified signed evidence.");
  }
  if (precheck.stage !== "PRODUCTION_ACTIVATION_PRECHECK") {
    throw precondition("PRODUCTION_ACTIVATION_PRECHECK provenance is invalid.");
  }
  if (precheck.principalKeyFingerprint !== principalKeyFingerprint) {
    throw new UniversalBrokerError(
      "AUTHORITY_PRINCIPAL_MISMATCH",
      "PRODUCTION_ACTIVATION_PRECHECK belongs to a different stable principal.",
    );
  }
  assertBindingMatches(precheck, binding, "PRODUCTION_ACTIVATION_PRECHECK");
  if (!activationTuplesEqual(precheck.tuple, tuple)
    || precheck.preCutoverHostCanaryDigest !== preCutoverHostCanary.signedPayloadDigest
    || precheck.managementCorrelationId !== preCutoverHostCanary.managementCorrelationId
    || precheck.stagingRouteIdentityDigest !== preCutoverHostCanary.stagingRouteIdentityDigest
    || stableJson(precheck.stagingBinding) !== stableJson(preCutoverHostCanary.stagingBinding)
    || stableJson(precheck.candidateIdentity) !== stableJson(preCutoverHostCanary.candidateIdentity)
    || precheck.candidateIdentity.schemaGeneration !== tuple.schemaGeneration
    || precheck.candidateIdentity.authorityContractGeneration !== tuple.authorityContractGeneration
    || precheck.candidateIdentity.buildDigest !== tuple.buildDigest) {
    throw precondition(
      "PRODUCTION_ACTIVATION_PRECHECK does not match the exact PRE canary, tuple, or immutable release identity.",
    );
  }
  assertValidAt(
    precheck.observedAtMs,
    precheck.expiresAtMs,
    referenceTimeMs,
    "PRODUCTION_ACTIVATION_PRECHECK",
  );
}

function connectorActivationEvidenceDigest(
  binding: ConnectorActivationAuthorityBinding,
  approval: VerifiedConnectorActivationOwnerApproval,
  preCutoverHostCanary: VerifiedConnectorActivationPreCutoverHostCanary,
  productionActivationPrecheck: VerifiedConnectorActivationProductionPrecheck,
): string {
  return sha256Digest(stableJson({
    schemaVersion: 2,
    operation: "context.connector_activation_finalize",
    binding,
    ownerApproval: { ...approval },
    preCutoverHostCanary: { ...preCutoverHostCanary },
    productionActivationPrecheck: { ...productionActivationPrecheck },
  }));
}

function validateCreatedAuthority(
  created: Record<string, unknown>,
  context: ValidatedFinalizationContext,
): string {
  const authorityId = typeof created.authorityId === "string" ? created.authorityId : "";
  if (!AUTHORITY_ID_PATTERN.test(authorityId)
    || created.principalKeyFingerprint !== context.principalKeyFingerprint
    || created.approvalAssurance !== "cooperative"
    || created.expired !== false
    || !Array.isArray(created.actions)
    || created.actions.length !== 1
    || !Array.isArray(created.receipts)
    || created.receipts.length !== 0) {
    throw new UniversalBrokerError(
      "AUTHORITY_STATE_UNCERTAIN",
      "Internal connector activation authority readback is incomplete.",
    );
  }
  const action = created.actions[0] as Record<string, unknown>;
  const expectedActionFingerprint = connectorActivationAuthorityActionFingerprint(context.binding);
  if (action.id !== `action_${expectedActionFingerprint}`
    || action.tool !== "context"
    || action.operation !== "connector_activation_finalize"
    || action.risk !== "R3"
    || action.maximumUses !== 1
    || action.consumedUses !== 0
    || action.resourceKeySha256 !== connectorActivationAuthorityResourceKeySha256(context.binding)) {
    throw new UniversalBrokerError(
      "AUTHORITY_STATE_UNCERTAIN",
      "Internal connector activation authority is not the exact R3 one-shot action.",
    );
  }
  return authorityId;
}

function activationProofFromLiveGrant(
  context: ValidatedFinalizationContext,
  grant: AuthorityGrant,
): ConnectorActivationAuthorityProof {
  const expectedActionFingerprint = connectorActivationAuthorityActionFingerprint(context.binding);
  const expectedResourceKey = connectorActivationAuthorityResourceKeySha256(context.binding);
  if (
    grant.actionId !== `action_${expectedActionFingerprint}`
    || grant.risk !== "R3"
    || grant.fingerprint !== expectedActionFingerprint
    || grant.resourceKeySha256 !== expectedResourceKey
    || !ACTION_CLAIM_ID_PATTERN.test(grant.actionClaimId)
    || !Number.isSafeInteger(grant.fencingToken)
    || grant.fencingToken < 1
    || !Number.isSafeInteger(grant.dispatchedAtMs)
    || grant.dispatchedAtMs! < grant.claimedAtMs
  ) {
    throw new UniversalBrokerError(
      "AUTHORITY_STATE_UNCERTAIN",
      "Live connector activation grant does not match the exact dispatched R3 action.",
    );
  }
  return {
    schemaVersion: 1,
    authorityId: grant.authorityId,
    actionClaimId: grant.actionClaimId,
    actionFingerprint: grant.fingerprint,
    resourceKeySha256: grant.resourceKeySha256,
    fencingToken: grant.fencingToken,
    principalKeyFingerprint: context.principalKeyFingerprint,
    risk: "R3",
    claimState: "DISPATCHED",
    approvalAssurance: "cooperative",
    ...context.binding,
    evidenceDigest: context.evidenceDigest,
    claimedAtMs: grant.claimedAtMs,
    dispatchedAtMs: grant.dispatchedAtMs!,
  };
}

function recoveryIntent(
  context: ValidatedFinalizationContext,
): ConnectorActivationRecoveryIntent {
  return {
    schema: "devspace.connector_activation_recovery_intent",
    schemaVersion: 1,
    state: "INTENT_RESERVED",
    approvalId: context.approvalId,
    freshHostReceiptId: context.freshHostReceiptId,
    principalKeyFingerprint: context.principalKeyFingerprint,
    actionFingerprint: connectorActivationAuthorityActionFingerprint(context.binding),
    resourceKeySha256: connectorActivationAuthorityResourceKeySha256(context.binding),
    evidenceDigest: context.evidenceDigest,
    ...context.binding,
  };
}

function recoveryHandle(
  context: ValidatedFinalizationContext,
  authorityId: string,
  grant: AuthorityGrant | undefined,
): ConnectorActivationRecoveryHandle {
  return {
    schema: "devspace.connector_activation_recovery",
    schemaVersion: 1,
    approvalId: context.approvalId,
    freshHostReceiptId: context.freshHostReceiptId,
    dispatchState: grant?.dispatchedAtMs === undefined
      ? grant ? "CLAIMED" : "NOT_CLAIMED"
      : "DISPATCHED",
    authorityId,
    principalKeyFingerprint: context.principalKeyFingerprint,
    actionFingerprint: connectorActivationAuthorityActionFingerprint(context.binding),
    resourceKeySha256: connectorActivationAuthorityResourceKeySha256(context.binding),
    evidenceDigest: context.evidenceDigest,
    ...context.binding,
    ...(grant ? {
      actionClaimId: grant.actionClaimId,
      fencingToken: grant.fencingToken,
      claimedAtMs: grant.claimedAtMs,
    } : {}),
    ...(grant?.dispatchedAtMs === undefined ? {} : { dispatchedAtMs: grant.dispatchedAtMs }),
  };
}

function validateRecoveryHandle(
  recovery: ConnectorActivationRecoveryHandle,
  context: ValidatedFinalizationContext,
): void {
  if (!recovery || typeof recovery !== "object"
    || recovery.schema !== "devspace.connector_activation_recovery"
    || recovery.schemaVersion !== 1
    || recovery.approvalId !== context.approvalId
    || recovery.freshHostReceiptId !== context.freshHostReceiptId
    || !AUTHORITY_ID_PATTERN.test(recovery.authorityId)
    || recovery.principalKeyFingerprint !== context.principalKeyFingerprint
    || recovery.actionFingerprint !== connectorActivationAuthorityActionFingerprint(context.binding)
    || recovery.resourceKeySha256 !== connectorActivationAuthorityResourceKeySha256(context.binding)
    || recovery.evidenceDigest !== context.evidenceDigest) {
    throw precondition("Connector activation recovery handle does not match trusted finalization evidence.");
  }
  assertBindingMatches(recovery, context.binding, "Connector activation recovery handle");
  if (recovery.dispatchState === "NOT_CLAIMED") {
    if (recovery.actionClaimId !== undefined
      || recovery.fencingToken !== undefined
      || recovery.claimedAtMs !== undefined
      || recovery.dispatchedAtMs !== undefined) {
      throw precondition("NOT_CLAIMED recovery handle contains claim evidence.");
    }
    return;
  }
  if (!recovery.actionClaimId
    || !ACTION_CLAIM_ID_PATTERN.test(recovery.actionClaimId)
    || !Number.isSafeInteger(recovery.fencingToken)
    || recovery.fencingToken! < 1
    || !Number.isSafeInteger(recovery.claimedAtMs)
    || recovery.claimedAtMs! < 1) {
    throw precondition("Connector activation recovery claim evidence is invalid.");
  }
  if (recovery.dispatchState === "CLAIMED" && recovery.dispatchedAtMs !== undefined) {
    throw precondition("CLAIMED recovery handle contains DISPATCHED evidence.");
  }
  if (recovery.dispatchState === "DISPATCHED"
    && (!Number.isSafeInteger(recovery.dispatchedAtMs)
      || recovery.dispatchedAtMs! < recovery.claimedAtMs!)) {
    throw precondition("DISPATCHED recovery handle timing is invalid.");
  }
}

function cancelClaimBeforeDispatch(
  controller: OperationAuthorityDispatchController,
  originalError: unknown,
): void {
  if (controller.phase !== "CLAIMED") return;
  try {
    controller.cancelNotDispatched({
      providerCallCount: 0,
      proof: "CONNECTOR_FINALIZER_PRE_DISPATCH_PROVIDER_ZERO",
    });
  } catch (cancellationError) {
    throw new UniversalBrokerError(
      "AUTHORITY_STATE_UNCERTAIN",
      "Connector activation remained pre-dispatch, but its zero-provider cancellation could not be persisted.",
      {
        retryable: false,
        evidence: {
          dispatchState: "CLAIMED",
          providerCallCount: 0,
          originalErrorType: originalError instanceof Error ? originalError.name : typeof originalError,
          cancellationErrorType: cancellationError instanceof Error
            ? cancellationError.name
            : typeof cancellationError,
        },
      },
    );
  }
}

function sealLiveDispatchUncertain(
  controller: OperationAuthorityDispatchController,
  recovery: ConnectorActivationRecoveryHandle,
  error: unknown,
): void {
  if (controller.phase !== "DISPATCHED") return;
  try {
    controller.complete("UNCERTAIN", {
      errorCode: "AUTHORITY_STATE_UNCERTAIN",
      reasonCode: "CONNECTOR_ACTIVATION_DISPATCHED_OUTCOME_UNKNOWN",
      receiptId: recovery.receiptId,
      evidenceDigest: recovery.evidenceDigest,
      causeType: error instanceof Error ? error.name : typeof error,
    });
  } catch {
    // The caller still receives UNKNOWN. Reconstructing a grant or replaying the
    // OAuth CAS would be less safe than retaining the durable dispatch barrier.
  }
}

function assertPassCompletion(completion: AuthorityCompletionReceipt): void {
  if (completion.state !== "PASS"
    || completion.result !== "PASS"
    || completion.leaseState !== "RELEASED") {
    throw new Error("Connector activation authority did not durably read back PASS.");
  }
}

function assertAuthorityPassReadback(status: Record<string, unknown>, grant: AuthorityGrant): void {
  const receipt = findPresentedAuthorityReceipt(status, grant.actionClaimId);
  if (!receipt
    || receipt.state !== "PASS"
    || receipt.result !== "PASS"
    || receipt.leaseState !== "RELEASED"
    || receipt.resourceKeySha256 !== grant.resourceKeySha256
    || receipt.fencingToken !== grant.fencingToken) {
    throw new Error("Connector activation authority PASS readback is not exact.");
  }
}

function assertRecoveredAuthorityPass(
  completion: RecoveredConnectorActivationAuthorityReceipt,
  recovery: ConnectorActivationRecoveryHandle,
  oauthProofDigest: string,
): void {
  if (completion.state !== "PASS"
    || completion.result !== "PASS"
    || completion.leaseState !== "RELEASED"
    || completion.recovered !== true
    || completion.actionClaimId !== recovery.actionClaimId
    || completion.oauthProofDigest !== oauthProofDigest
    || !SHA256_DIGEST_PATTERN.test(completion.reconciliationEvidenceDigest)) {
    throw new Error("Recovered connector activation authority PASS receipt is not exact.");
  }
}

function assertRecoveredAuthorityPassReadback(
  status: Record<string, unknown>,
  recovery: ConnectorActivationRecoveryHandle,
): void {
  assertAuthorityActionReadback(status, recovery);
  const receipt = findPresentedAuthorityReceipt(status, recovery.actionClaimId);
  if (!receipt
    || receipt.state !== "PASS"
    || receipt.result !== "PASS"
    || receipt.leaseState !== "RELEASED"
    || receipt.resourceKeySha256 !== recovery.resourceKeySha256
    || receipt.fencingToken !== recovery.fencingToken) {
    throw new Error("Recovered connector activation authority PASS readback is not exact.");
  }
}

function assertUnusedAuthorityReadback(
  status: Record<string, unknown>,
  recovery: ConnectorActivationRecoveryHandle,
): void {
  const receipts = Array.isArray(status.receipts) ? status.receipts : [];
  assertAuthorityActionReadback(status, recovery);
  const actions = status.actions as Array<Record<string, unknown>>;
  if (receipts.length !== 0 || actions[0]?.consumedUses !== 0) {
    throw precondition("Pre-claim authority readback does not prove provider dispatch zero.");
  }
}

function assertAuthorityActionReadback(
  status: Record<string, unknown>,
  recovery: ConnectorActivationRecoveryHandle,
): void {
  const actions = Array.isArray(status.actions) ? status.actions : [];
  const action = actions[0] as Record<string, unknown> | undefined;
  if (actions.length !== 1
    || action?.id !== `action_${recovery.actionFingerprint}`
    || action.tool !== "context"
    || action.operation !== "connector_activation_finalize"
    || action.resourceKeySha256 !== recovery.resourceKeySha256
    || action.risk !== "R3"
    || action.maximumUses !== 1
    || !Number.isSafeInteger(action.consumedUses)
    || Number(action.consumedUses) < 0
    || Number(action.consumedUses) > 1) {
    throw precondition("Authority action readback does not match the exact connector activation grant.");
  }
}

function findPresentedAuthorityReceipt(
  status: Record<string, unknown>,
  actionClaimId: string | undefined,
): PresentedAuthorityReceipt | undefined {
  if (!actionClaimId) return undefined;
  const receipts = Array.isArray(status.receipts) ? status.receipts : [];
  const matches = receipts.filter((value) => (
    value
    && typeof value === "object"
    && (value as Record<string, unknown>).actionClaimId === actionClaimId
  ));
  if (matches.length !== 1) return undefined;
  return presentedAuthorityReceipt(matches[0]);
}

function solePresentedAuthorityReceipt(
  status: Record<string, unknown>,
): PresentedAuthorityReceipt | undefined {
  const receipts = Array.isArray(status.receipts) ? status.receipts : [];
  return receipts.length === 1 ? presentedAuthorityReceipt(receipts[0]) : undefined;
}

function presentedAuthorityReceipt(value: unknown): PresentedAuthorityReceipt | undefined {
  if (!value || typeof value !== "object") return undefined;
  const receipt = value as Record<string, unknown>;
  const claimedAtMs = typeof receipt.claimedAt === "string" ? Date.parse(receipt.claimedAt) : Number.NaN;
  const dispatchedAtMs = typeof receipt.dispatchedAt === "string"
    ? Date.parse(receipt.dispatchedAt)
    : undefined;
  if (typeof receipt.actionClaimId !== "string"
    || typeof receipt.resourceKeySha256 !== "string"
    || !Number.isSafeInteger(receipt.fencingToken)
    || !Number.isSafeInteger(claimedAtMs)
    || (dispatchedAtMs !== undefined && !Number.isSafeInteger(dispatchedAtMs))
    || typeof receipt.state !== "string"
    || typeof receipt.result !== "string"
    || typeof receipt.leaseState !== "string") return undefined;
  return {
    actionClaimId: receipt.actionClaimId,
    resourceKeySha256: receipt.resourceKeySha256,
    fencingToken: Number(receipt.fencingToken),
    claimedAtMs,
    ...(dispatchedAtMs === undefined ? {} : { dispatchedAtMs }),
    state: receipt.state,
    result: receipt.result,
    leaseState: receipt.leaseState,
  };
}

function recoveryFromDiscoveredAuthorityReceipt(
  recovery: ConnectorActivationRecoveryHandle,
  receipt: PresentedAuthorityReceipt,
): ConnectorActivationRecoveryHandle {
  if (recovery.dispatchState !== "NOT_CLAIMED"
    || recovery.actionClaimId !== undefined
    || receipt.resourceKeySha256 !== recovery.resourceKeySha256) {
    throw precondition("Journal and sole authority claim readback do not identify the same activation action.");
  }
  return Object.freeze({
    ...recovery,
    dispatchState: receipt.dispatchedAtMs === undefined ? "CLAIMED" as const : "DISPATCHED" as const,
    actionClaimId: receipt.actionClaimId,
    fencingToken: receipt.fencingToken,
    claimedAtMs: receipt.claimedAtMs,
    ...(receipt.dispatchedAtMs === undefined ? {} : { dispatchedAtMs: receipt.dispatchedAtMs }),
  });
}

function recoveryFromAuthorityReceipt(
  recovery: ConnectorActivationRecoveryHandle,
  receipt: PresentedAuthorityReceipt,
): ConnectorActivationRecoveryHandle {
  if (receipt.actionClaimId !== recovery.actionClaimId
    || receipt.resourceKeySha256 !== recovery.resourceKeySha256
    || receipt.fencingToken !== recovery.fencingToken
    || receipt.claimedAtMs !== recovery.claimedAtMs
    || (recovery.dispatchedAtMs !== undefined
      && receipt.dispatchedAtMs !== recovery.dispatchedAtMs)
    || (recovery.dispatchState === "DISPATCHED" && receipt.dispatchedAtMs === undefined)) {
    throw precondition("Authority action claim readback does not match the connector recovery handle.");
  }
  if (receipt.dispatchedAtMs === undefined) return recovery;
  return Object.freeze({
    ...recovery,
    dispatchState: "DISPATCHED" as const,
    dispatchedAtMs: receipt.dispatchedAtMs,
  });
}

function activationAuthorityReceiptMatchesProof(
  receipt: ConnectorActivationAuthorityReceipt,
  proof: ConnectorActivationAuthorityProof,
): boolean {
  return activationAuthorityReceiptMatchesRecovery(receipt, proof);
}

function activationAuthorityReceiptMatchesRecovery(
  receipt: ConnectorActivationAuthorityReceipt,
  recovery: ActivationAuthorityReadbackIdentity,
): boolean {
  const proofRecord: Record<string, unknown> = { ...receipt };
  delete proofRecord.proofDigest;
  delete proofRecord.consumedAt;
  return receipt.proofDigest === sha256Digest(stableJson(proofRecord))
    && receipt.schemaVersion === 1
    && receipt.authorityId === recovery.authorityId
    && receipt.actionClaimId === recovery.actionClaimId
    && receipt.actionFingerprint === recovery.actionFingerprint
    && receipt.resourceKeySha256 === recovery.resourceKeySha256
    && receipt.fencingToken === recovery.fencingToken
    && receipt.principalKeyFingerprint === recovery.principalKeyFingerprint
    && receipt.risk === "R3"
    && receipt.claimState === "DISPATCHED"
    && receipt.approvalAssurance === "cooperative"
    && receipt.receiptId === recovery.receiptId
    && receipt.canonicalName === recovery.canonicalName
    && receipt.tupleDigest === recovery.tupleDigest
    && receipt.activePreimageDigest === recovery.activePreimageDigest
    && receipt.finalizationPlanDigest === recovery.finalizationPlanDigest
    && receipt.evidenceDigest === recovery.evidenceDigest
    && receipt.claimedAtMs === recovery.claimedAtMs
    && receipt.dispatchedAtMs === recovery.dispatchedAtMs;
}

function unknownReconciliation(
  recovery: ConnectorActivationRecoveryHandle,
  oauthCommitted: boolean,
  authorityState: string,
  leaseState: string | undefined,
  leaseReconciled: boolean,
  reason: ConnectorActivationUnknownReconciliation["reason"],
): ConnectorActivationUnknownReconciliation {
  return {
    state: "UNKNOWN",
    retryAllowed: false,
    oauthCommitted,
    authorityState,
    ...(leaseState ? { leaseState } : {}),
    leaseReconciled,
    reason,
    recovery,
  };
}

function validateReceiptIdentity(receipt: ConnectorActivationReceipt): void {
  if (!receipt || typeof receipt !== "object"
    || !RECEIPT_ID_PATTERN.test(receipt.receiptId)
    || !CANONICAL_NAME_PATTERN.test(receipt.tuple?.canonicalName ?? "")
    || !SHA256_DIGEST_PATTERN.test(receipt.tupleDigest)
    || !SHA256_DIGEST_PATTERN.test(receipt.preimageDigest)
    || !Number.isFinite(Date.parse(receipt.drainDeadlineAt))) {
    throw precondition("Connector activation receipt identity or plan is invalid.");
  }
}

function assertBindingMatches(
  actual: ConnectorActivationAuthorityBinding,
  expected: ConnectorActivationAuthorityBinding,
  label: string,
): void {
  if (actual.receiptId !== expected.receiptId
    || actual.canonicalName !== expected.canonicalName
    || actual.tupleDigest !== expected.tupleDigest
    || actual.activePreimageDigest !== expected.activePreimageDigest
    || actual.finalizationPlanDigest !== expected.finalizationPlanDigest) {
    throw precondition(`${label} does not match the exact prepared tuple, preimage, and plan.`);
  }
}

function activationTuplesEqual(left: ConnectorActivationTuple, right: ConnectorActivationTuple): boolean {
  return Boolean(left && right) && stableJson({
    canonicalName: left.canonicalName,
    candidateBindingId: left.candidateBindingId,
    clientId: left.clientId,
    installationEpoch: left.installationEpoch,
    schemaGeneration: left.schemaGeneration,
    authorityContractGeneration: left.authorityContractGeneration,
    redirectUrisDigest: left.redirectUrisDigest,
    buildDigest: left.buildDigest,
  }) === stableJson({
    canonicalName: right.canonicalName,
    candidateBindingId: right.candidateBindingId,
    clientId: right.clientId,
    installationEpoch: right.installationEpoch,
    schemaGeneration: right.schemaGeneration,
    authorityContractGeneration: right.authorityContractGeneration,
    redirectUrisDigest: right.redirectUrisDigest,
    buildDigest: right.buildDigest,
  });
}

function assertValidAt(
  issuedAtMs: number,
  expiresAtMs: number,
  referenceTimeMs: number,
  label: string,
): void {
  if (!Number.isSafeInteger(referenceTimeMs)
    || issuedAtMs > referenceTimeMs
    || expiresAtMs <= referenceTimeMs) {
    throw precondition(`${label} is not valid at the finalization boundary.`);
  }
}

function requiredReceiptId(value: string): string {
  if (!RECEIPT_ID_PATTERN.test(value)) throw precondition("Connector activation receiptId is invalid.");
  return value;
}

function requiredPrincipal(value: string): string {
  if (!RAW_SHA256_PATTERN.test(value) || /^0{64}$/u.test(value)) {
    throw precondition("Stable owner principal fingerprint is invalid.");
  }
  return value;
}

function precondition(message: string): UniversalBrokerError {
  return new UniversalBrokerError("PRECONDITION_FAILED", message, {
    retryable: false,
    evidence: { dispatchState: "NOT_DISPATCHED", providerDispatchCount: 0 },
  });
}

function sha256Digest(value: string): string {
  return `sha256:${sha256Hex(value)}`;
}

function sha256Hex(value: string): string {
  return createHash("sha256").update(value).digest("hex");
}

function stableJson(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(stableJson).join(",")}]`;
  if (value && typeof value === "object") {
    const record = value as Record<string, unknown>;
    return `{${Object.keys(record).sort().map((key) => `${JSON.stringify(key)}:${stableJson(record[key])}`).join(",")}}`;
  }
  return JSON.stringify(value) ?? "null";
}
