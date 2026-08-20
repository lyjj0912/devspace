import { createHash, createHmac, timingSafeEqual } from "node:crypto";
import {
  connectorActivationAuthorityActionFingerprint,
  connectorActivationAuthorityDescriptor,
  connectorActivationAuthorityResourceKeySha256,
  connectorActivationTupleDigest,
  type ConnectorActivationAuthorityBinding,
  type ConnectorActivationAuthorityProof,
  type ConnectorActivationAuthorityReceipt,
  type ConnectorActivationReceipt,
  type ConnectorActivationTuple,
  type ConnectorBindingRecord,
} from "../oauth-store.js";
import {
  type AuthorityCompletionReceipt,
  type AuthorityGrant,
  type OperationAuthorityDispatchController,
  type OperationAuthorityRegistry,
  type RecoveredConnectorActivationAuthorityReceipt,
} from "./authority.js";
import {
  assertVerifiedConnectorActivationStagingPrecheck,
  type VerifiedConnectorActivationStagingPrecheck,
} from "./connector-activation-evidence.js";
import {
  CONNECTOR_STAGING_ACTIVATION_OUTWARD_STATE,
  connectorStagingActivationAuthorityBinding,
  connectorStagingActivationCandidateIdentityDigest,
  connectorStagingActivationPlanDigest,
} from "./connector-staging-activation-contract.js";
import {
  type ConnectorActivationJournalEntry,
  type ConnectorActivationJournalKey,
} from "./connector-activation-journal.js";
import {
  type ConnectorActivationRecoveryHandle,
  type ConnectorActivationRecoveryIntent,
  type ConnectorActivationRecoveryJournal,
} from "./connector-activation-finalizer.js";
import { UniversalBrokerError } from "./errors.js";
import type { ManagementAuthorizationKey } from "./management-authorization.js";

const STAGING_OWNER_APPROVAL_BRAND: unique symbol = Symbol(
  "verified-connector-staging-owner-approval",
);

const SHA256_DIGEST_PATTERN = /^sha256:[a-f0-9]{64}$/u;
const RAW_SHA256_PATTERN = /^[a-f0-9]{64}$/u;
const SIGNATURE_PATTERN = /^[A-Za-z0-9_-]{43}$/u;
const RECEIPT_ID_PATTERN =
  /^connector-activation-[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/u;
const AUTHORITY_ID_PATTERN =
  /^authority_[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/u;
const ACTION_CLAIM_ID_PATTERN =
  /^authority_claim_[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/u;
const CANONICAL_NAME_PATTERN = /^[A-Za-z][A-Za-z0-9._-]{0,127}$/u;
const MAXIMUM_STAGING_APPROVAL_LIFETIME_MS = 5 * 60_000;
const MAXIMUM_STAGING_PRECHECK_LIFETIME_MS = 2 * 60_000;

const ENVELOPE_KEYS = ["keyId", "kind", "payload", "payloadDigest", "schemaVersion", "signature"] as const;
const STAGING_OWNER_APPROVAL_KEYS = [
  "activePreimageDigest",
  "approvalId",
  "approvedAtMs",
  "authorityText",
  "candidateIdentityDigest",
  "canonicalName",
  "evidenceDigest",
  "expiresAtMs",
  "finalizationPlanDigest",
  "managementCorrelationId",
  "principalKeyFingerprint",
  "receiptId",
  "stagingActivationPrecheckDigest",
  "stagingRouteIdentityDigest",
  "tupleDigest",
] as const;

export {
  CONNECTOR_STAGING_ACTIVATION_OUTWARD_STATE,
  connectorStagingActivationCandidateIdentityDigest,
  connectorStagingActivationPlanDigest,
} from "./connector-staging-activation-contract.js";
export const CONNECTOR_STAGING_OWNER_APPROVAL_KIND =
  "STAGING_OWNER_MANAGEMENT_APPROVAL" as const;

export interface ConnectorStagingActivationOwnerApprovalBinding
  extends ConnectorActivationAuthorityBinding {
  principalKeyFingerprint: string;
  stagingActivationPrecheckDigest: string;
  managementCorrelationId: string;
  stagingRouteIdentityDigest: string;
  candidateIdentityDigest: string;
}

export interface ConnectorStagingActivationOwnerApprovalPayload
  extends ConnectorStagingActivationOwnerApprovalBinding {
  approvalId: string;
  authorityText: string;
  evidenceDigest: string;
  approvedAtMs: number;
  expiresAtMs: number;
}

export interface VerifiedConnectorStagingActivationOwnerApproval
  extends Readonly<ConnectorStagingActivationOwnerApprovalPayload> {
  readonly assurance: "cooperative";
  readonly signedPayloadDigest: string;
  readonly [STAGING_OWNER_APPROVAL_BRAND]: true;
}

export interface SignedConnectorStagingActivationOwnerApproval {
  readonly schemaVersion: 1;
  readonly kind: typeof CONNECTOR_STAGING_OWNER_APPROVAL_KIND;
  readonly keyId: string;
  readonly payload: ConnectorStagingActivationOwnerApprovalPayload;
  readonly payloadDigest: string;
  readonly signature: string;
}

export interface ConnectorStagingActivationInput {
  stagingActivationPrecheck: VerifiedConnectorActivationStagingPrecheck;
  authenticatedOwnerPrincipalKeyFingerprint: string;
  ownerApproval: VerifiedConnectorStagingActivationOwnerApproval;
}

export interface ConnectorStagingActivationResult {
  state: typeof CONNECTOR_STAGING_ACTIVATION_OUTWARD_STATE;
  finalizationPlanDigest: string;
  evidenceDigest: string;
  activationReceipt: ConnectorActivationReceipt;
  activationAuthorityReceipt: ConnectorActivationAuthorityReceipt;
  authorityCompletionReceipt: AuthorityCompletionReceipt;
  stagingBinding: ConnectorBindingRecord;
  recovery: ConnectorActivationRecoveryHandle;
}

export interface ConnectorStagingActivationUnknownReconciliation {
  state: "UNKNOWN";
  retryAllowed: false;
  oauthCommitted: boolean;
  authorityState: string;
  leaseState?: string;
  leaseReconciled: false;
  reason:
    | "DISPATCHED_OUTCOME_NOT_PROVEN"
    | "OAUTH_ACTIVATION_RECEIPT_MISMATCH";
  recovery: ConnectorActivationRecoveryHandle;
}

export interface ConnectorStagingActivationNotDispatchedReconciliation {
  state: "STAGING_ACTIVATION_NOT_DISPATCHED";
  retryAllowed: false;
  oauthCommitted: false;
  authorityState: "INTENT_RESERVED" | "NOT_CLAIMED" | "CLAIMED" | "CANCELLED_NOT_DISPATCHED";
  recovery?: ConnectorActivationRecoveryHandle;
}

export type ConnectorStagingActivationReconciliationResult =
  | ConnectorStagingActivationResult
  | ConnectorStagingActivationUnknownReconciliation
  | ConnectorStagingActivationNotDispatchedReconciliation;

export class ConnectorStagingActivationUnknownError extends UniversalBrokerError {
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
    this.name = "ConnectorStagingActivationUnknownError";
  }
}

interface ConnectorStagingActivationStore {
  getConnectorBinding(bindingId: string): ConnectorBindingRecord | undefined;
  getActivationReceipt(receiptId: string): ConnectorActivationReceipt | undefined;
  getActivationAuthorityReceipt(receiptId: string): ConnectorActivationAuthorityReceipt | undefined;
  activatePreparedConnector(
    receiptId: string,
    tuple: ConnectorActivationTuple,
    proof: ConnectorActivationAuthorityProof,
  ): ConnectorActivationReceipt;
}

type ConnectorStagingAuthorityRegistry = Pick<
  OperationAuthorityRegistry,
  | "createConnectorActivationAuthority"
  | "prepareDispatch"
  | "status"
  | "terminalizeRecoveredConnectorActivationClaimPass"
>;

interface ConnectorStagingActivationRecoveryJournal
  extends ConnectorActivationRecoveryJournal {
  load(input: Readonly<ConnectorActivationJournalKey>): ConnectorActivationJournalEntry | undefined;
}

export interface ConnectorStagingActivationCoordinatorDependencies {
  oauthStore: ConnectorStagingActivationStore;
  authorityRegistry: ConnectorStagingAuthorityRegistry;
  recoveryJournal: ConnectorStagingActivationRecoveryJournal;
  now?: () => number;
}

interface ValidatedStagingActivationContext {
  receipt: ConnectorActivationReceipt;
  binding: ConnectorActivationAuthorityBinding;
  ownerApprovalBinding: ConnectorStagingActivationOwnerApprovalBinding;
  descriptor: ReturnType<typeof connectorActivationAuthorityDescriptor>;
  principalKeyFingerprint: string;
  authorityText: string;
  approvalId: string;
  stagingActivationPrecheckId: string;
  evidenceDigest: string;
  journalKey: ConnectorActivationJournalKey;
}

interface PresentedAuthorityReceipt {
  actionClaimId: string;
  receiptDigest: string;
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

export function connectorStagingActivationOwnerApprovalBinding(
  receipt: ConnectorActivationReceipt,
  stagingActivationPrecheck: VerifiedConnectorActivationStagingPrecheck,
  principalKeyFingerprint: string,
): ConnectorStagingActivationOwnerApprovalBinding {
  validateReceiptIdentity(receipt);
  validateStagingPrecheckBrand(stagingActivationPrecheck);
  const principal = requiredPrincipal(principalKeyFingerprint);
  const authorityBinding = connectorStagingActivationAuthorityBinding(
    receipt,
    stagingActivationPrecheck,
  );
  return {
    principalKeyFingerprint: principal,
    ...authorityBinding,
    stagingActivationPrecheckDigest: stagingActivationPrecheck.signedPayloadDigest,
    managementCorrelationId: stagingActivationPrecheck.managementCorrelationId,
    stagingRouteIdentityDigest: stagingActivationPrecheck.stagingRouteIdentityDigest,
    candidateIdentityDigest: connectorStagingActivationCandidateIdentityDigest(
      stagingActivationPrecheck.candidateIdentity,
    ),
  };
}

export function signConnectorStagingActivationOwnerApproval(
  input: ConnectorStagingActivationOwnerApprovalPayload,
  key: ManagementAuthorizationKey,
  nowMs = Date.now(),
): SignedConnectorStagingActivationOwnerApproval {
  const payload = clonePlain(input);
  validateStagingOwnerApproval(payload, nowMs);
  return signStagingOwnerApproval(payload, key);
}

export function verifyConnectorStagingActivationOwnerApproval(
  envelope: SignedConnectorStagingActivationOwnerApproval,
  key: ManagementAuthorizationKey,
  expected: ConnectorStagingActivationOwnerApprovalBinding,
  nowMs = Date.now(),
): VerifiedConnectorStagingActivationOwnerApproval {
  const payload = verifyStagingOwnerApprovalEnvelope(envelope, key);
  validateStagingOwnerApproval(payload, nowMs);
  assertStagingOwnerApprovalBinding(payload, expected);
  const value = {
    ...payload,
    assurance: "cooperative" as const,
    signedPayloadDigest: envelope.payloadDigest,
  };
  Object.defineProperty(value, "authorityText", {
    value: payload.authorityText,
    enumerable: false,
    configurable: false,
    writable: false,
  });
  return brandedFrozen(value, STAGING_OWNER_APPROVAL_BRAND);
}

export function assertVerifiedConnectorStagingActivationOwnerApproval(
  value: unknown,
): asserts value is VerifiedConnectorStagingActivationOwnerApproval {
  if (!hasOwnBrand(value, STAGING_OWNER_APPROVAL_BRAND)) {
    throw new Error("Staging owner management approval is not verified signed evidence.");
  }
}

export class ConnectorStagingActivationCoordinator {
  private readonly oauthStore: ConnectorStagingActivationStore;
  private readonly authorityRegistry: ConnectorStagingAuthorityRegistry;
  private readonly recoveryJournal: ConnectorStagingActivationRecoveryJournal;
  private readonly now: () => number;

  constructor(dependencies: ConnectorStagingActivationCoordinatorDependencies) {
    this.oauthStore = dependencies.oauthStore;
    this.authorityRegistry = dependencies.authorityRegistry;
    this.recoveryJournal = dependencies.recoveryJournal;
    this.now = dependencies.now ?? Date.now;
  }

  activateOrReconcile(
    input: ConnectorStagingActivationInput,
  ): ConnectorStagingActivationReconciliationResult {
    const context = this.validateActivationInput(input, this.now(), false);
    const existing = this.recoveryJournal.load(context.journalKey);
    if (existing) return this.reconcileValidated(context, existing);
    if (context.receipt.status !== "PREPARED") {
      throw precondition(`Staging connector activation receipt is ${context.receipt.status}; it cannot be replayed.`);
    }
    return this.activateValidated(input, context);
  }

  reconcile(
    input: ConnectorStagingActivationInput,
  ): ConnectorStagingActivationReconciliationResult {
    const context = this.validateActivationInput(input, this.now(), false);
    const existing = this.recoveryJournal.load(context.journalKey);
    if (!existing) {
      throw precondition("Staging activation has no durable recovery journal entry.");
    }
    return this.reconcileValidated(context, existing);
  }

  private activateValidated(
    input: ConnectorStagingActivationInput,
    context: ValidatedStagingActivationContext,
  ): ConnectorStagingActivationResult {
    const currentBinding = this.oauthStore.getConnectorBinding(context.receipt.tuple.candidateBindingId);
    if (!currentBinding || currentBinding.state !== "ACTIVATION_PREPARED") {
      throw precondition("Fresh staging activation requires the persisted candidate to remain ACTIVATION_PREPARED.");
    }
    assertBindingMatchesReceiptTuple(currentBinding, context.receipt.tuple);
    this.recoveryJournal.reserve(Object.freeze(recoveryIntent(context)));
    this.assertEvidenceCurrent(input, context);
    const created = this.authorityRegistry.createConnectorActivationAuthority({
      authorityText: context.authorityText,
      descriptor: context.descriptor,
    }, context.principalKeyFingerprint);
    const authorityId = validateCreatedAuthority(created, context);
    this.recoveryJournal.record(Object.freeze(recoveryHandle(context, authorityId, undefined)));
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
      this.recoveryJournal.record(Object.freeze(recoveryHandle(context, authorityId, grant)));
      this.assertEvidenceCurrent(input, context);
      grant = controller.markDispatched();
      crossedDispatchBarrier = true;
      this.recoveryJournal.record(Object.freeze(recoveryHandle(context, authorityId, grant)));
      this.assertEvidenceCurrent(input, context);

      const proof = activationProofFromLiveGrant(context, grant);
      this.oauthStore.activatePreparedConnector(context.receipt.receiptId, context.receipt.tuple, proof);

      const exact = this.readExactCommittedActivation(context, proof);
      const completion = controller.complete("PASS", {
        reasonCode: "STAGING_CONNECTOR_ACTIVATION_COMMITTED",
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
      return this.resultFromExactReadback(context, exact, completion, recovery);
    } catch (error) {
      const recovery = recoveryHandle(context, authorityId, grant);
      if (!crossedDispatchBarrier) {
        cancelClaimBeforeDispatch(controller, error);
        throw error;
      }
      sealLiveDispatchUncertain(controller, recovery, error);
      throw new ConnectorStagingActivationUnknownError(
        "Staging connector activation crossed DISPATCHED, but exact PASS could not be proven. Do not replay it.",
        recovery,
        error,
      );
    }
  }

  private reconcileValidated(
    context: ValidatedStagingActivationContext,
    entry: ConnectorActivationJournalEntry,
  ): ConnectorStagingActivationReconciliationResult {
    if (!entry.recovery) {
      return {
        state: "STAGING_ACTIVATION_NOT_DISPATCHED",
        retryAllowed: false,
        oauthCommitted: false,
        authorityState: "INTENT_RESERVED",
      };
    }
    validateRecoveryHandle(entry.recovery, context);
    const status = this.authorityRegistry.status(
      entry.recovery.authorityId,
      context.principalKeyFingerprint,
    );
    assertAuthorityActionReadback(status, entry.recovery);
    let recovery = entry.recovery;
    let authorityReceipt = findPresentedAuthorityReceipt(status, recovery.actionClaimId);
    const activationReceipt = this.oauthStore.getActivationReceipt(context.receipt.receiptId);
    const activationAuthorityReceipt = this.oauthStore.getActivationAuthorityReceipt(
      context.receipt.receiptId,
    );

    if (!recovery.actionClaimId) {
      const discovered = solePresentedAuthorityReceipt(status);
      if (discovered) {
        recovery = recoveryFromDiscoveredAuthorityReceipt(recovery, discovered);
        authorityReceipt = discovered;
      }
    }

    if (!recovery.actionClaimId) {
      return {
        state: "STAGING_ACTIVATION_NOT_DISPATCHED",
        retryAllowed: false,
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
        "DISPATCHED_OUTCOME_NOT_PROVEN",
      );
    }
    recovery = recoveryFromAuthorityReceipt(recovery, authorityReceipt);

    if (authorityReceipt.state === "CANCELLED_NOT_DISPATCHED") {
      return {
        state: "STAGING_ACTIVATION_NOT_DISPATCHED",
        retryAllowed: false,
        oauthCommitted: false,
        authorityState: "CANCELLED_NOT_DISPATCHED",
        recovery,
      };
    }

    const exactOAuthReceipt = activationReceipt
      && activationAuthorityReceipt
      && activationReceipt.status === "ACTIVATED"
      && activationReceipt.ownerAuthorityId === recovery.authorityId
      && activationAuthorityReceipt.consumedAt === activationReceipt.activatedAt
      && activationAuthorityReceiptMatchesRecovery(activationAuthorityReceipt, recovery)
      && activationReceiptMatchesContext(activationReceipt, context)
      ? activationAuthorityReceipt
      : undefined;

    if (authorityReceipt.state === "PASS" && exactOAuthReceipt) {
      const completion = authorityCompletionFromPresented(authorityReceipt);
      return this.resultFromExactReadback(
        context,
        { activationReceipt: activationReceipt!, activationAuthorityReceipt: exactOAuthReceipt },
        completion,
        recovery,
      );
    }

    if (activationAuthorityReceipt && !exactOAuthReceipt) {
      return unknownReconciliation(
        recovery,
        true,
        authorityReceipt.state,
        authorityReceipt.leaseState,
        "OAUTH_ACTIVATION_RECEIPT_MISMATCH",
      );
    }

    if (authorityReceipt.state === "UNCERTAIN" && exactOAuthReceipt) {
      const recovered = this.authorityRegistry.terminalizeRecoveredConnectorActivationClaimPass({
        principalKeyFingerprint: context.principalKeyFingerprint,
        authorityId: recovery.authorityId,
        actionClaimId: recovery.actionClaimId!,
        actionFingerprint: recovery.actionFingerprint,
        resourceKeySha256: recovery.resourceKeySha256,
        fencingToken: recovery.fencingToken!,
        oauthProofDigest: exactOAuthReceipt.proofDigest,
        evidenceDigest: recovery.evidenceDigest,
      });
      assertRecoveredAuthorityPass(recovered, recovery, exactOAuthReceipt.proofDigest);
      assertRecoveredAuthorityPassReadback(
        this.authorityRegistry.status(recovery.authorityId, context.principalKeyFingerprint),
        recovery,
      );
      return this.resultFromExactReadback(
        context,
        { activationReceipt: activationReceipt!, activationAuthorityReceipt: exactOAuthReceipt },
        recovered,
        recovery,
      );
    }

    return unknownReconciliation(
      recovery,
      false,
      authorityReceipt.state,
      authorityReceipt.leaseState,
      "DISPATCHED_OUTCOME_NOT_PROVEN",
    );
  }

  private validateActivationInput(
    input: ConnectorStagingActivationInput,
    referenceTimeMs: number,
    requirePrepared: boolean,
  ): ValidatedStagingActivationContext {
    if (!input || typeof input !== "object") {
      throw precondition("Staging connector activation input is required.");
    }
    const principalKeyFingerprint = requiredPrincipal(
      input.authenticatedOwnerPrincipalKeyFingerprint,
    );
    validateStagingPrecheckBrand(input.stagingActivationPrecheck);
    assertValidAt(
      input.stagingActivationPrecheck.observedAtMs,
      input.stagingActivationPrecheck.expiresAtMs,
      referenceTimeMs,
      MAXIMUM_STAGING_PRECHECK_LIFETIME_MS,
      "STAGING_ACTIVATION_PRECHECK",
    );
    if (input.stagingActivationPrecheck.principalKeyFingerprint !== principalKeyFingerprint) {
      throw new UniversalBrokerError(
        "AUTHORITY_PRINCIPAL_MISMATCH",
        "STAGING_ACTIVATION_PRECHECK belongs to a different stable principal.",
      );
    }
    const storedBinding = this.oauthStore.getConnectorBinding(
      input.stagingActivationPrecheck.stagingCandidateBinding.bindingId,
    );
    if (!storedBinding) throw precondition("Staging connector candidate binding does not exist.");
    assertBindingMatchesStagingPrecheck(storedBinding, input.stagingActivationPrecheck, requirePrepared);
    if (requirePrepared && storedBinding.state !== "ACTIVATION_PREPARED") {
      throw precondition(`Staging connector binding is ${storedBinding.state}; it cannot be activated.`);
    }
    if (!storedBinding.stateReason || !RECEIPT_ID_PATTERN.test(storedBinding.stateReason)) {
      throw precondition("Staging connector candidate does not reference an exact PREPARED receipt.");
    }
    const receipt = this.oauthStore.getActivationReceipt(storedBinding.stateReason);
    if (!receipt) throw precondition("Staging connector activation receipt does not exist.");
    if (requirePrepared && receipt.status !== "PREPARED") {
      throw precondition(`Staging connector activation receipt is ${receipt.status}; it cannot be replayed.`);
    }
    assertReceiptMatchesStagingPrecheck(receipt, input.stagingActivationPrecheck);
    assertBindingMatchesReceiptTuple(storedBinding, receipt.tuple);
    const binding = connectorStagingActivationOwnerApprovalBinding(
      receipt,
      input.stagingActivationPrecheck,
      principalKeyFingerprint,
    );
    validateVerifiedStagingOwnerApproval(
      input.ownerApproval,
      binding,
      input.stagingActivationPrecheck,
      referenceTimeMs,
    );
    const evidenceDigest = connectorStagingActivationEvidenceDigest(
      binding,
      input.ownerApproval,
      input.stagingActivationPrecheck,
    );
    const authorityBinding = connectorStagingActivationAuthorityBinding(
      receipt,
      input.stagingActivationPrecheck,
    );
    assertAuthorityBindingMatches(authorityBinding, binding, "Staging activation owner approval binding");
    return {
      receipt,
      binding: authorityBinding,
      ownerApprovalBinding: binding,
      descriptor: connectorActivationAuthorityDescriptor(authorityBinding),
      principalKeyFingerprint,
      authorityText: input.ownerApproval.authorityText,
      approvalId: input.ownerApproval.approvalId,
      stagingActivationPrecheckId: input.stagingActivationPrecheck.stagingActivationPrecheckId,
      evidenceDigest,
      journalKey: {
        principalKeyFingerprint,
        approvalId: input.ownerApproval.approvalId,
        receiptId: receipt.receiptId,
      },
    };
  }

  private assertEvidenceCurrent(
    input: ConnectorStagingActivationInput,
    context: ValidatedStagingActivationContext,
  ): void {
    const nowMs = this.now();
    const currentBinding = this.oauthStore.getConnectorBinding(context.receipt.tuple.candidateBindingId);
    if (!currentBinding) throw precondition("Staging connector candidate binding does not exist.");
    assertBindingMatchesStagingPrecheck(currentBinding, input.stagingActivationPrecheck, false);
    assertBindingMatchesReceiptTuple(currentBinding, context.receipt.tuple);
    assertValidAt(
      input.stagingActivationPrecheck.observedAtMs,
      input.stagingActivationPrecheck.expiresAtMs,
      nowMs,
      MAXIMUM_STAGING_PRECHECK_LIFETIME_MS,
      "STAGING_ACTIVATION_PRECHECK",
    );
    validateVerifiedStagingOwnerApproval(
      input.ownerApproval,
      connectorStagingActivationOwnerApprovalBinding(
        context.receipt,
        input.stagingActivationPrecheck,
        context.principalKeyFingerprint,
      ),
      input.stagingActivationPrecheck,
      nowMs,
    );
  }

  private readExactCommittedActivation(
    context: ValidatedStagingActivationContext,
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
      || !activationReceiptMatchesContext(activationReceipt, context)
      || activationReceipt.status !== "ACTIVATED"
      || activationReceipt.ownerAuthorityId !== proof.authorityId
      || !activationAuthorityReceipt
      || activationAuthorityReceipt.consumedAt !== activationReceipt.activatedAt
      || !activationAuthorityReceiptMatchesRecovery(activationAuthorityReceipt, proof)
    ) {
      throw new Error("Committed staging activation readback did not match the exact grant and tuple.");
    }
    return { activationReceipt, activationAuthorityReceipt };
  }

  private resultFromExactReadback(
    context: ValidatedStagingActivationContext,
    exact: {
      activationReceipt: ConnectorActivationReceipt;
      activationAuthorityReceipt: ConnectorActivationAuthorityReceipt;
    },
    completion: AuthorityCompletionReceipt,
    recovery: ConnectorActivationRecoveryHandle,
  ): ConnectorStagingActivationResult {
    const binding = this.oauthStore.getConnectorBinding(
      exact.activationReceipt.tuple.candidateBindingId,
    );
    if (!binding || binding.state !== "ACTIVE" || !bindingMatchesTuple(binding, exact.activationReceipt.tuple)) {
      throw new Error("Staging activation readback did not expose the exact ACTIVE staging binding.");
    }
    if (completion.state !== "PASS"
      || completion.result !== "PASS"
      || completion.leaseState !== "RELEASED") {
      throw new Error("Staging activation authority completion is not exact PASS.");
    }
    if (recovery.dispatchState !== "DISPATCHED"
      || recovery.receiptId !== context.receipt.receiptId
      || recovery.finalizationPlanDigest !== context.binding.finalizationPlanDigest) {
      throw new Error("Staging activation recovery handle does not match the committed readback.");
    }
    return {
      state: CONNECTOR_STAGING_ACTIVATION_OUTWARD_STATE,
      finalizationPlanDigest: context.binding.finalizationPlanDigest,
      evidenceDigest: context.evidenceDigest,
      activationReceipt: exact.activationReceipt,
      activationAuthorityReceipt: exact.activationAuthorityReceipt,
      authorityCompletionReceipt: completion,
      stagingBinding: binding,
      recovery,
    };
  }
}

function signStagingOwnerApproval(
  payload: ConnectorStagingActivationOwnerApprovalPayload,
  key: ManagementAuthorizationKey,
): SignedConnectorStagingActivationOwnerApproval {
  const frozenPayload = deepFreeze(payload);
  const base = {
    schemaVersion: 1 as const,
    kind: CONNECTOR_STAGING_OWNER_APPROVAL_KIND,
    keyId: key.keyId,
    payload: frozenPayload,
  };
  const canonical = stableJson(base);
  return Object.freeze({
    ...base,
    payloadDigest: sha256Digest(canonical),
    signature: createHmac("sha256", key.secret)
      .update(stagingOwnerApprovalSignatureDomain())
      .update(canonical)
      .digest("base64url"),
  });
}

function verifyStagingOwnerApprovalEnvelope(
  envelope: SignedConnectorStagingActivationOwnerApproval,
  key: ManagementAuthorizationKey,
): ConnectorStagingActivationOwnerApprovalPayload {
  assertExactObjectKeys(envelope, ENVELOPE_KEYS, "Staging owner approval envelope");
  if (envelope.schemaVersion !== 1
    || envelope.kind !== CONNECTOR_STAGING_OWNER_APPROVAL_KIND
    || envelope.keyId !== key.keyId) {
    throw new Error("Staging owner approval envelope identity is invalid.");
  }
  if (!SHA256_DIGEST_PATTERN.test(envelope.payloadDigest)
    || !SIGNATURE_PATTERN.test(envelope.signature)) {
    throw new Error("Staging owner approval signature fields are invalid.");
  }
  const canonical = stableJson({
    schemaVersion: envelope.schemaVersion,
    kind: envelope.kind,
    keyId: envelope.keyId,
    payload: envelope.payload,
  });
  const expectedSignature = createHmac("sha256", key.secret)
    .update(stagingOwnerApprovalSignatureDomain())
    .update(canonical)
    .digest();
  const observedSignature = Buffer.from(envelope.signature, "base64url");
  if (observedSignature.toString("base64url") !== envelope.signature
    || envelope.payloadDigest !== sha256Digest(canonical)
    || observedSignature.length !== expectedSignature.length
    || !timingSafeEqual(observedSignature, expectedSignature)) {
    throw new Error("Staging owner approval signature verification failed.");
  }
  return clonePlain(envelope.payload);
}

function stagingOwnerApprovalSignatureDomain(): string {
  return "devspace.connector-staging-activation.v1/STAGING_OWNER_MANAGEMENT_APPROVAL\0";
}

function validateStagingOwnerApproval(
  input: ConnectorStagingActivationOwnerApprovalPayload,
  nowMs: number,
): void {
  assertExactObjectKeys(input, STAGING_OWNER_APPROVAL_KEYS, "Staging owner approval payload");
  validateStagingOwnerApprovalBinding(input);
  requiredText(input.approvalId, "approvalId", 256);
  requiredText(input.authorityText, "authorityText", 8_000);
  requiredDigest(input.evidenceDigest, "staging owner approval evidenceDigest");
  assertValidAt(
    input.approvedAtMs,
    input.expiresAtMs,
    nowMs,
    MAXIMUM_STAGING_APPROVAL_LIFETIME_MS,
    "Staging owner approval",
  );
}

function validateStagingOwnerApprovalBinding(
  input: ConnectorStagingActivationOwnerApprovalBinding,
): void {
  requiredPrincipal(input.principalKeyFingerprint);
  requiredReceiptId(input.receiptId);
  requiredCanonicalName(input.canonicalName);
  requiredDigest(input.tupleDigest, "tupleDigest");
  requiredDigest(input.activePreimageDigest, "activePreimageDigest");
  requiredDigest(input.finalizationPlanDigest, "finalizationPlanDigest");
  requiredDigest(input.stagingActivationPrecheckDigest, "stagingActivationPrecheckDigest");
  requiredText(input.managementCorrelationId, "managementCorrelationId", 256);
  requiredDigest(input.stagingRouteIdentityDigest, "stagingRouteIdentityDigest");
  requiredDigest(input.candidateIdentityDigest, "candidateIdentityDigest");
}

function assertStagingOwnerApprovalBinding(
  observed: ConnectorStagingActivationOwnerApprovalBinding,
  expected: ConnectorStagingActivationOwnerApprovalBinding,
): void {
  for (const key of [
    "activePreimageDigest",
    "candidateIdentityDigest",
    "canonicalName",
    "finalizationPlanDigest",
    "managementCorrelationId",
    "principalKeyFingerprint",
    "receiptId",
    "stagingActivationPrecheckDigest",
    "stagingRouteIdentityDigest",
    "tupleDigest",
  ] as const) {
    if (observed[key] !== expected[key]) {
      throw new Error(`Staging owner approval ${key} mismatch.`);
    }
  }
}

function validateVerifiedStagingOwnerApproval(
  approval: VerifiedConnectorStagingActivationOwnerApproval,
  binding: ConnectorStagingActivationOwnerApprovalBinding,
  stagingActivationPrecheck: VerifiedConnectorActivationStagingPrecheck,
  referenceTimeMs: number,
): void {
  try {
    assertVerifiedConnectorStagingActivationOwnerApproval(approval);
  } catch {
    throw precondition("Staging owner management approval is not verified signed evidence.");
  }
  if (approval.assurance !== "cooperative") {
    throw precondition("Staging owner approval assurance is invalid.");
  }
  try {
    assertStagingOwnerApprovalBinding(approval, binding);
  } catch {
    throw precondition("Staging owner approval does not match the exact prepared tuple, preimage, and plan.");
  }
  if (approval.stagingActivationPrecheckDigest !== stagingActivationPrecheck.signedPayloadDigest
    || approval.managementCorrelationId !== stagingActivationPrecheck.managementCorrelationId
    || approval.stagingRouteIdentityDigest !== stagingActivationPrecheck.stagingRouteIdentityDigest
    || approval.candidateIdentityDigest
      !== connectorStagingActivationCandidateIdentityDigest(stagingActivationPrecheck.candidateIdentity)) {
    throw precondition("Staging owner approval does not bind the exact signed staging precheck.");
  }
  if (approval.approvedAtMs < stagingActivationPrecheck.observedAtMs) {
    throw precondition("Staging owner approval predates the signed staging precheck.");
  }
  assertValidAt(
    approval.approvedAtMs,
    approval.expiresAtMs,
    referenceTimeMs,
    MAXIMUM_STAGING_APPROVAL_LIFETIME_MS,
    "Staging owner approval",
  );
}

function connectorStagingActivationEvidenceDigest(
  binding: ConnectorStagingActivationOwnerApprovalBinding,
  approval: VerifiedConnectorStagingActivationOwnerApproval,
  precheck: VerifiedConnectorActivationStagingPrecheck,
): string {
  return sha256Digest(stableJson({
    schemaVersion: 1,
    operation: "context.connector_staging_activation_finalize",
    outwardState: CONNECTOR_STAGING_ACTIVATION_OUTWARD_STATE,
    binding,
    ownerApproval: {
      approvalId: approval.approvalId,
      signedPayloadDigest: approval.signedPayloadDigest,
      evidenceDigest: approval.evidenceDigest,
      approvedAtMs: approval.approvedAtMs,
      expiresAtMs: approval.expiresAtMs,
    },
    stagingActivationPrecheck: {
      stagingActivationPrecheckId: precheck.stagingActivationPrecheckId,
      signedPayloadDigest: precheck.signedPayloadDigest,
      observedAtMs: precheck.observedAtMs,
      expiresAtMs: precheck.expiresAtMs,
    },
  }));
}

function recoveryIntent(
  context: ValidatedStagingActivationContext,
): ConnectorActivationRecoveryIntent {
  return {
    schema: "devspace.connector_activation_recovery_intent",
    schemaVersion: 1,
    state: "INTENT_RESERVED",
    approvalId: context.approvalId,
    freshHostReceiptId: context.stagingActivationPrecheckId,
    principalKeyFingerprint: context.principalKeyFingerprint,
    actionFingerprint: connectorActivationAuthorityActionFingerprint(context.binding),
    resourceKeySha256: connectorActivationAuthorityResourceKeySha256(context.binding),
    evidenceDigest: context.evidenceDigest,
    ...context.binding,
  };
}

function recoveryHandle(
  context: ValidatedStagingActivationContext,
  authorityId: string,
  grant: AuthorityGrant | undefined,
): ConnectorActivationRecoveryHandle {
  return {
    schema: "devspace.connector_activation_recovery",
    schemaVersion: 1,
    approvalId: context.approvalId,
    freshHostReceiptId: context.stagingActivationPrecheckId,
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

function validateCreatedAuthority(
  created: Record<string, unknown>,
  context: ValidatedStagingActivationContext,
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
      "Internal staging activation authority readback is incomplete.",
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
      "Internal staging activation authority is not the exact R3 one-shot action.",
    );
  }
  return authorityId;
}

function activationProofFromLiveGrant(
  context: ValidatedStagingActivationContext,
  grant: AuthorityGrant,
): ConnectorActivationAuthorityProof {
  const expectedActionFingerprint = connectorActivationAuthorityActionFingerprint(context.binding);
  const expectedResourceKey = connectorActivationAuthorityResourceKeySha256(context.binding);
  if (grant.actionId !== `action_${expectedActionFingerprint}`
    || grant.risk !== "R3"
    || grant.fingerprint !== expectedActionFingerprint
    || grant.resourceKeySha256 !== expectedResourceKey
    || !ACTION_CLAIM_ID_PATTERN.test(grant.actionClaimId)
    || !Number.isSafeInteger(grant.fencingToken)
    || grant.fencingToken < 1
    || !Number.isSafeInteger(grant.dispatchedAtMs)
    || grant.dispatchedAtMs! < grant.claimedAtMs) {
    throw new UniversalBrokerError(
      "AUTHORITY_STATE_UNCERTAIN",
      "Live staging activation grant does not match the exact dispatched R3 action.",
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

function validateRecoveryHandle(
  recovery: ConnectorActivationRecoveryHandle,
  context: ValidatedStagingActivationContext,
): void {
  if (!recovery || typeof recovery !== "object"
    || recovery.schema !== "devspace.connector_activation_recovery"
    || recovery.schemaVersion !== 1
    || recovery.approvalId !== context.approvalId
    || recovery.freshHostReceiptId !== context.stagingActivationPrecheckId
    || !AUTHORITY_ID_PATTERN.test(recovery.authorityId)
    || recovery.principalKeyFingerprint !== context.principalKeyFingerprint
    || recovery.actionFingerprint !== connectorActivationAuthorityActionFingerprint(context.binding)
    || recovery.resourceKeySha256 !== connectorActivationAuthorityResourceKeySha256(context.binding)
    || recovery.evidenceDigest !== context.evidenceDigest) {
    throw precondition("Staging activation recovery handle does not match trusted evidence.");
  }
  assertAuthorityBindingMatches(recovery, context.binding, "Staging activation recovery handle");
  if (recovery.dispatchState === "NOT_CLAIMED") {
    if (recovery.actionClaimId !== undefined
      || recovery.fencingToken !== undefined
      || recovery.claimedAtMs !== undefined
      || recovery.dispatchedAtMs !== undefined) {
      throw precondition("NOT_CLAIMED staging recovery handle contains claim evidence.");
    }
    return;
  }
  if (!recovery.actionClaimId
    || !ACTION_CLAIM_ID_PATTERN.test(recovery.actionClaimId)
    || !Number.isSafeInteger(recovery.fencingToken)
    || recovery.fencingToken! < 1
    || !Number.isSafeInteger(recovery.claimedAtMs)
    || recovery.claimedAtMs! < 1) {
    throw precondition("Staging activation recovery claim evidence is invalid.");
  }
  if (recovery.dispatchState === "CLAIMED" && recovery.dispatchedAtMs !== undefined) {
    throw precondition("CLAIMED staging recovery handle contains DISPATCHED evidence.");
  }
  if (recovery.dispatchState === "DISPATCHED"
    && (!Number.isSafeInteger(recovery.dispatchedAtMs)
      || recovery.dispatchedAtMs! < recovery.claimedAtMs!)) {
    throw precondition("DISPATCHED staging recovery handle timing is invalid.");
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
      proof: "STAGING_CONNECTOR_ACTIVATION_PRE_DISPATCH_PROVIDER_ZERO",
    });
  } catch (cancellationError) {
    throw new UniversalBrokerError(
      "AUTHORITY_STATE_UNCERTAIN",
      "Staging activation remained pre-dispatch, but its zero-provider cancellation could not be persisted.",
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
      reasonCode: "STAGING_CONNECTOR_ACTIVATION_DISPATCHED_OUTCOME_UNKNOWN",
      receiptId: recovery.receiptId,
      evidenceDigest: recovery.evidenceDigest,
      causeType: error instanceof Error ? error.name : typeof error,
    });
  } catch {
    // Keep the durable DISPATCHED tombstone as the recovery boundary.
  }
}

function assertPassCompletion(completion: AuthorityCompletionReceipt): void {
  if (completion.state !== "PASS"
    || completion.result !== "PASS"
    || completion.leaseState !== "RELEASED") {
    throw new Error("Staging activation authority did not durably read back PASS.");
  }
}

function assertAuthorityPassReadback(status: Record<string, unknown>, grant: AuthorityGrant): void {
  const receipt = findPresentedAuthorityReceipt(status, grant.actionClaimId);
  if (!receipt
    || receipt.state !== "PASS"
    || receipt.result !== "PASS"
    || receipt.leaseState !== "RELEASED"
    || !SHA256_DIGEST_PATTERN.test(receipt.receiptDigest)
    || receipt.resourceKeySha256 !== grant.resourceKeySha256
    || receipt.fencingToken !== grant.fencingToken) {
    throw new Error("Staging activation authority PASS readback is not exact.");
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
    throw new Error("Recovered staging activation authority PASS receipt is not exact.");
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
    || !SHA256_DIGEST_PATTERN.test(receipt.receiptDigest)
    || receipt.resourceKeySha256 !== recovery.resourceKeySha256
    || receipt.fencingToken !== recovery.fencingToken) {
    throw new Error("Recovered staging activation authority PASS readback is not exact.");
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
    throw precondition("Authority action readback does not match the exact staging activation grant.");
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
    || typeof receipt.receiptDigest !== "string"
    || !SHA256_DIGEST_PATTERN.test(receipt.receiptDigest)
    || typeof receipt.resourceKeySha256 !== "string"
    || !Number.isSafeInteger(receipt.fencingToken)
    || !Number.isSafeInteger(claimedAtMs)
    || (dispatchedAtMs !== undefined && !Number.isSafeInteger(dispatchedAtMs))
    || typeof receipt.state !== "string"
    || typeof receipt.result !== "string"
    || typeof receipt.leaseState !== "string") return undefined;
  return {
    actionClaimId: receipt.actionClaimId,
    receiptDigest: receipt.receiptDigest,
    resourceKeySha256: receipt.resourceKeySha256,
    fencingToken: Number(receipt.fencingToken),
    claimedAtMs,
    ...(dispatchedAtMs === undefined ? {} : { dispatchedAtMs }),
    state: receipt.state,
    result: receipt.result,
    leaseState: receipt.leaseState,
  };
}

function authorityCompletionFromPresented(
  receipt: PresentedAuthorityReceipt,
): AuthorityCompletionReceipt {
  return {
    actionClaimId: receipt.actionClaimId,
    useId: receipt.actionClaimId,
    receiptDigest: receipt.receiptDigest,
    state: "PASS",
    result: "PASS",
    leaseState: "RELEASED",
  };
}

function recoveryFromDiscoveredAuthorityReceipt(
  recovery: ConnectorActivationRecoveryHandle,
  receipt: PresentedAuthorityReceipt,
): ConnectorActivationRecoveryHandle {
  if (recovery.dispatchState !== "NOT_CLAIMED"
    || recovery.actionClaimId !== undefined
    || receipt.resourceKeySha256 !== recovery.resourceKeySha256) {
    throw precondition("Journal and sole authority claim readback do not identify the same staging action.");
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
    throw precondition("Authority action claim readback does not match the staging recovery handle.");
  }
  if (receipt.dispatchedAtMs === undefined) return recovery;
  return Object.freeze({
    ...recovery,
    dispatchState: "DISPATCHED" as const,
    dispatchedAtMs: receipt.dispatchedAtMs,
  });
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
  reason: ConnectorStagingActivationUnknownReconciliation["reason"],
): ConnectorStagingActivationUnknownReconciliation {
  return {
    state: "UNKNOWN",
    retryAllowed: false,
    oauthCommitted,
    authorityState,
    ...(leaseState ? { leaseState } : {}),
    leaseReconciled: false,
    reason,
    recovery,
  };
}

function validateStagingPrecheckBrand(
  value: VerifiedConnectorActivationStagingPrecheck,
): void {
  try {
    assertVerifiedConnectorActivationStagingPrecheck(value);
  } catch {
    throw precondition("STAGING_ACTIVATION_PRECHECK is not verified signed evidence.");
  }
}

function assertBindingMatchesStagingPrecheck(
  binding: ConnectorBindingRecord,
  precheck: VerifiedConnectorActivationStagingPrecheck,
  requirePrepared: boolean,
): void {
  const expected = precheck.stagingCandidateBinding;
  const identity = precheck.candidateIdentity;
  const allowedState = requirePrepared
    ? binding.state === "ACTIVATION_PREPARED"
    : binding.state === "ACTIVATION_PREPARED" || binding.state === "ACTIVE";
  if (binding.bindingId !== expected.bindingId
    || binding.canonicalName !== expected.canonicalName
    || binding.clientId !== expected.clientId
    || binding.installationEpoch !== expected.installationEpoch
    || !allowedState
    || binding.schemaGeneration !== identity.schemaGeneration
    || binding.authorityContractGeneration !== identity.authorityContractGeneration
    || binding.buildDigest !== identity.buildDigest) {
    throw precondition("Persisted staging candidate binding does not match STAGING_ACTIVATION_PRECHECK.");
  }
}

function assertReceiptMatchesStagingPrecheck(
  receipt: ConnectorActivationReceipt,
  precheck: VerifiedConnectorActivationStagingPrecheck,
): void {
  validateReceiptIdentity(receipt);
  if (receipt.tupleDigest !== connectorActivationTupleDigest(receipt.tuple)) {
    throw precondition("Persisted staging activation tuple digest is not exact.");
  }
  const expected = precheck.stagingCandidateBinding;
  const identity = precheck.candidateIdentity;
  if (receipt.tuple.canonicalName !== expected.canonicalName
    || receipt.tuple.candidateBindingId !== expected.bindingId
    || receipt.tuple.clientId !== expected.clientId
    || receipt.tuple.installationEpoch !== expected.installationEpoch
    || receipt.tuple.schemaGeneration !== identity.schemaGeneration
    || receipt.tuple.authorityContractGeneration !== identity.authorityContractGeneration
    || receipt.tuple.buildDigest !== identity.buildDigest) {
    throw precondition("Persisted staging activation receipt does not match STAGING_ACTIVATION_PRECHECK.");
  }
}

function activationReceiptMatchesContext(
  receipt: ConnectorActivationReceipt,
  context: ValidatedStagingActivationContext,
): boolean {
  return receipt.receiptId === context.receipt.receiptId
    && receipt.tupleDigest === context.binding.tupleDigest
    && receipt.preimageDigest === context.binding.activePreimageDigest
    && receipt.previousActiveBindingId === context.receipt.previousActiveBindingId
    && receipt.drainDeadlineAt === context.receipt.drainDeadlineAt
    && receipt.refreshAllowedDuringDrain === context.receipt.refreshAllowedDuringDrain
    && activationTuplesEqual(receipt.tuple, context.receipt.tuple);
}

function assertBindingMatchesReceiptTuple(
  binding: ConnectorBindingRecord,
  tuple: ConnectorActivationTuple,
): void {
  if (!bindingMatchesTuple(binding, tuple)) {
    throw precondition("Persisted staging candidate binding does not match the exact prepared activation tuple.");
  }
}

function bindingMatchesTuple(binding: ConnectorBindingRecord, tuple: ConnectorActivationTuple): boolean {
  return binding.bindingId === tuple.candidateBindingId
    && binding.canonicalName === tuple.canonicalName
    && binding.clientId === tuple.clientId
    && binding.installationEpoch === tuple.installationEpoch
    && binding.schemaGeneration === tuple.schemaGeneration
    && binding.authorityContractGeneration === tuple.authorityContractGeneration
    && binding.redirectUrisDigest === tuple.redirectUrisDigest
    && binding.buildDigest === tuple.buildDigest;
}

function validateReceiptIdentity(receipt: ConnectorActivationReceipt): void {
  if (!receipt || typeof receipt !== "object"
    || !RECEIPT_ID_PATTERN.test(receipt.receiptId)
    || !receipt.tuple
    || !CANONICAL_NAME_PATTERN.test(receipt.tuple.canonicalName)
    || !SHA256_DIGEST_PATTERN.test(receipt.tupleDigest)
    || !SHA256_DIGEST_PATTERN.test(receipt.preimageDigest)
    || !Number.isFinite(Date.parse(receipt.drainDeadlineAt))) {
    throw precondition("Staging activation receipt identity or plan is invalid.");
  }
}

function assertAuthorityBindingMatches(
  actual: ConnectorActivationAuthorityBinding,
  expected: ConnectorActivationAuthorityBinding,
  label: string,
): void {
  if (actual.receiptId !== expected.receiptId
    || actual.canonicalName !== expected.canonicalName
    || actual.tupleDigest !== expected.tupleDigest
    || actual.activePreimageDigest !== expected.activePreimageDigest
    || actual.finalizationPlanDigest !== expected.finalizationPlanDigest) {
    throw precondition(`${label} does not match the exact prepared tuple, preimage, and staging plan.`);
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
  maximumLifetimeMs: number,
  label: string,
): void {
  if (!Number.isSafeInteger(issuedAtMs)
    || !Number.isSafeInteger(expiresAtMs)
    || !Number.isSafeInteger(referenceTimeMs)
    || issuedAtMs < 0
    || expiresAtMs <= issuedAtMs
    || expiresAtMs - issuedAtMs > maximumLifetimeMs) {
    throw precondition(`${label} lifetime is invalid.`);
  }
  if (issuedAtMs > referenceTimeMs || expiresAtMs <= referenceTimeMs) {
    throw precondition(`${label} is not valid at the staging activation boundary.`);
  }
}

function requiredReceiptId(value: string): string {
  if (!RECEIPT_ID_PATTERN.test(value)) throw precondition("Staging activation receiptId is invalid.");
  return value;
}

function requiredPrincipal(value: string): string {
  if (!RAW_SHA256_PATTERN.test(value) || /^0{64}$/u.test(value)) {
    throw precondition("Stable owner principal fingerprint is invalid.");
  }
  return value;
}

function requiredCanonicalName(value: string): string {
  if (!CANONICAL_NAME_PATTERN.test(value)) throw precondition("Canonical connector name is invalid.");
  return value;
}

function requiredDigest(value: string, label: string): string {
  if (!SHA256_DIGEST_PATTERN.test(value)) throw precondition(`${label} is invalid.`);
  return value;
}

function requiredText(value: string, label: string, maximum: number): string {
  if (typeof value !== "string"
    || value.length < 1
    || value.length > maximum
    || /[\0\r\n]/u.test(value)) {
    throw precondition(`${label} is invalid.`);
  }
  return value;
}

function precondition(message: string): UniversalBrokerError {
  return new UniversalBrokerError("PRECONDITION_FAILED", message, {
    retryable: false,
    evidence: { dispatchState: "NOT_DISPATCHED", providerDispatchCount: 0 },
  });
}

function assertExactObjectKeys(
  value: unknown,
  expectedKeys: readonly string[],
  label: string,
): asserts value is Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error(`${label} is invalid.`);
  const keys = Object.keys(value).sort();
  const expected = [...expectedKeys].sort();
  if (keys.length !== expected.length || keys.some((key, index) => key !== expected[index])) {
    throw new Error(`${label} shape is invalid.`);
  }
}

function brandedFrozen<T extends object, K extends symbol>(value: T, brand: K): T & { readonly [P in K]: true } {
  Object.defineProperty(value, brand, {
    value: true,
    enumerable: false,
    configurable: false,
    writable: false,
  });
  return deepFreeze(value) as T & { readonly [P in K]: true };
}

function hasOwnBrand<K extends symbol>(value: unknown, brand: K): value is { readonly [P in K]: true } {
  return Boolean(value && typeof value === "object"
    && Object.prototype.hasOwnProperty.call(value, brand)
    && (value as Record<K, unknown>)[brand] === true);
}

function clonePlain<T>(value: T): T {
  return JSON.parse(JSON.stringify(value)) as T;
}

function deepFreeze<T>(value: T): T {
  if (!value || typeof value !== "object" || Object.isFrozen(value)) return value;
  Object.freeze(value);
  for (const nested of Object.values(value as Record<string, unknown>)) deepFreeze(nested);
  return value;
}

function sha256Digest(value: string): string {
  return `sha256:${createHash("sha256").update(value).digest("hex")}`;
}

function stableJson(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(stableJson).join(",")}]`;
  if (value && typeof value === "object") {
    const record = value as Record<string, unknown>;
    return `{${Object.keys(record).sort().map((key) => `${JSON.stringify(key)}:${stableJson(record[key])}`).join(",")}}`;
  }
  return JSON.stringify(value) ?? "null";
}
