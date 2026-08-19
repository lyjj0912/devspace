import { createHash, randomUUID } from "node:crypto";
import {
  DurableAuthorityStore,
  type DurableActionClaimState,
  type DurableAuthorityRecord,
  type DurableAuthorityTaskRecord,
  type DurableResourceLeaseState,
} from "./authority-store.js";
import {
  UNIVERSAL_AUTHORITY_RISKS,
  UNIVERSAL_TOOL_OPERATIONS,
  type AuthorityRiskClass,
  type UniversalToolName,
} from "./contracts.js";
import { UniversalBrokerError } from "./errors.js";

export { UNIVERSAL_AUTHORITY_RISKS as AUTHORITY_RISK_CLASSES };
export type { AuthorityRiskClass };

export interface AuthorityActionDescriptor {
  tool: UniversalToolName;
  operation: string;
  target?: string;
  resource?: string;
  parameters?: Record<string, unknown>;
}

export interface RequestedAuthorityAction {
  id?: string;
  descriptor: AuthorityActionDescriptor;
  risk?: AuthorityRiskClass;
  uses?: number;
}

export interface CreateOperationAuthorityInput {
  taskInstanceId?: string;
  taskLabel?: string;
  /** Deprecated compatibility label. It is hashed and never used as an authority boundary. */
  taskId?: string;
  authorityText: string;
  actions: RequestedAuthorityAction[];
  expiresInSeconds?: number;
}

export interface AuthorityGrant {
  authorityId: string;
  actionId: string;
  actionClaimId: string;
  useId: string;
  risk: AuthorityRiskClass;
  fingerprint: string;
  resourceKeySha256: string;
  fencingToken: number;
}

interface StoredAuthorityAction {
  id: string;
  descriptor: AuthorityActionDescriptor;
  fingerprint: string;
  resourceKeySha256: string;
  minimumRisk: AuthorityRiskClass;
  risk: AuthorityRiskClass;
  maximumUses: number;
  consumedUses: number;
}

interface StoredOperationAuthority {
  authorityId: string;
  taskInstanceId: string;
  taskLabelSha256?: string;
  authorityTextSha256: string;
  principalKeyFingerprint: string;
  approvalAssurance: "cooperative";
  correctionEpoch: number;
  createdAtMs: number;
  expiresAtMs: number;
  fingerprint: string;
  actions: StoredAuthorityAction[];
  receipts: AuthorityReceipt[];
}

interface AuthorityReceipt {
  actionClaimId: string;
  useId: string;
  actionId: string;
  taskInstanceId: string;
  principalKeyFingerprint: string;
  actionFingerprint: string;
  resourceKeySha256: string;
  fencingToken: number;
  claimedAtMs: number;
  reservedAtMs: number;
  dispatchedAtMs?: number;
  completedAtMs?: number;
  state: DurableActionClaimState;
  result: DurableActionClaimState;
  leaseState: DurableResourceLeaseState;
  providerCallCount?: number;
  evidence?: Record<string, unknown>;
}

export interface OperationAuthorityRegistryOptions {
  now?: () => number;
  minimumRisk?: (action: AuthorityActionDescriptor) => AuthorityRiskClass;
  storePath?: string;
  instanceId?: string;
}

const DEFAULT_AUTHORITY_TTL_SECONDS = 15 * 60;
const MAXIMUM_AUTHORITY_TTL_SECONDS = 8 * 60 * 60;
const MAXIMUM_ACTIONS = 64;
const MAXIMUM_AUTHORITY_TEXT_CHARACTERS = 8_000;
const MAXIMUM_ACTION_PARAMETERS_CHARACTERS = 16_000;
const MAXIMUM_RECEIPTS = 256;
const MAXIMUM_ACTIVE_AUTHORITIES = 4_096;
const MAXIMUM_ACTIVE_AUTHORITIES_PER_SCOPE = 512;
const AUTHORITY_RECEIPT_RETENTION_MS = 24 * 60 * 60_000;
const ACTIVE_AUTHORITY_INSTANCE_COUNTS = new Map<string, number>();

export interface ProvenNotDispatched {
  providerCallCount: 0;
  proof: string;
}

export type OperationDispatchPhase =
  | "READY"
  | "CLAIMED"
  | "DISPATCHED"
  | "PASS"
  | "FAIL"
  | "UNCERTAIN"
  | "CANCELLED_NOT_DISPATCHED";

/**
 * One exact mutation lifecycle. Adapters call claim() after preflight and
 * markDispatched() immediately before the real side-effecting provider call.
 */
export class OperationAuthorityDispatchController {
  private grantValue: AuthorityGrant | undefined;
  private phaseValue: OperationDispatchPhase = "READY";

  constructor(
    private readonly registry: OperationAuthorityRegistry,
    private readonly authorityId: string | undefined,
    private readonly principalKeyFingerprint: string,
    private readonly action: AuthorityActionDescriptor,
    private readonly risk: AuthorityRiskClass,
  ) {}

  get phase(): OperationDispatchPhase {
    return this.phaseValue;
  }

  get grant(): AuthorityGrant | undefined {
    return this.grantValue;
  }

  claim(): AuthorityGrant {
    if (this.grantValue) return this.grantValue;
    if (this.phaseValue !== "READY") {
      throw new UniversalBrokerError(
        "AUTHORITY_STATE_UNCERTAIN",
        `Authority dispatch cannot claim from ${this.phaseValue}.`,
      );
    }
    const grant = this.registry.claim(
      this.authorityId,
      this.principalKeyFingerprint,
      this.action,
      this.risk,
    );
    if (!grant) {
      throw new UniversalBrokerError(
        "AUTHORITY_STATE_UNCERTAIN",
        "A mutation dispatch controller cannot use the R0 fast path.",
      );
    }
    this.grantValue = grant;
    this.phaseValue = "CLAIMED";
    return grant;
  }

  markDispatched(): AuthorityGrant {
    const grant = this.claim();
    if (this.phaseValue === "DISPATCHED") return grant;
    if (this.phaseValue !== "CLAIMED") {
      throw new UniversalBrokerError(
        "AUTHORITY_STATE_UNCERTAIN",
        `Authority dispatch cannot cross the provider boundary from ${this.phaseValue}.`,
      );
    }
    this.registry.markDispatched(grant);
    this.phaseValue = "DISPATCHED";
    return grant;
  }

  cancelNotDispatched(proof: ProvenNotDispatched): void {
    if (proof.providerCallCount !== 0 || this.phaseValue !== "CLAIMED" || !this.grantValue) {
      throw new UniversalBrokerError(
        "AUTHORITY_STATE_UNCERTAIN",
        "A claim can be cancelled only before DISPATCHED with independently proven provider call count zero.",
      );
    }
    this.registry.cancelNotDispatched(this.grantValue, proof);
    this.phaseValue = "CANCELLED_NOT_DISPATCHED";
  }

  complete(
    state: "PASS" | "FAIL" | "UNCERTAIN",
    evidence?: Record<string, unknown>,
  ): void {
    if (this.phaseValue !== "DISPATCHED" || !this.grantValue) {
      throw new UniversalBrokerError(
        "AUTHORITY_STATE_UNCERTAIN",
        `A claim cannot terminalize as ${state} before the durable DISPATCHED barrier.`,
      );
    }
    this.registry.completeClaim(this.grantValue, state, evidence);
    this.phaseValue = state;
  }
}

export class OperationAuthorityRegistry {
  private readonly now: () => number;
  private readonly minimumRisk: (action: AuthorityActionDescriptor) => AuthorityRiskClass;
  private readonly store: DurableAuthorityStore | undefined;
  private readonly storeFailure: UniversalBrokerError | undefined;
  private readonly tasks = new Map<string, DurableAuthorityTaskRecord>();
  private readonly authorities = new Map<string, StoredOperationAuthority>();
  private readonly staleAuthorityIds = new Set<string>();
  private readonly authorityIdsByFingerprint = new Map<string, string>();
  private readonly recoveredPendingUses: number;
  private readonly instanceId: string;
  private closed = false;
  private previews = 0;

  constructor(options: OperationAuthorityRegistryOptions = {}) {
    this.now = options.now ?? Date.now;
    this.minimumRisk = options.minimumRisk ?? (() => "R1");
    this.instanceId = options.instanceId ?? `authority_run_${randomUUID()}`;
    retainAuthorityInstance(this.instanceId);
    try {
      this.store = new DurableAuthorityStore(
        options.storePath,
        this.now(),
        this.instanceId,
        [...ACTIVE_AUTHORITY_INSTANCE_COUNTS.keys()],
      );
    } catch (error) {
      this.store = undefined;
      this.storeFailure = authorityStoreFailure(error);
      this.recoveredPendingUses = 0;
      return;
    }
    this.storeFailure = undefined;
    const snapshot = this.store.load();
    this.recoveredPendingUses = snapshot.recoveredPendingUses;
    for (const task of snapshot.tasks) this.tasks.set(task.taskInstanceId, task);
    for (const record of snapshot.authorities) {
      const task = this.tasks.get(record.taskInstanceId);
      if (
        !task
        || record.principalKeyFingerprint !== task.principalKeyFingerprint
        || record.correctionEpoch !== task.correctionEpoch
      ) {
        this.staleAuthorityIds.add(record.authorityId);
        continue;
      }
      const authority = this.fromDurable(record);
      this.authorities.set(authority.authorityId, authority);
      this.authorityIdsByFingerprint.set(authority.fingerprint, authority.authorityId);
    }
    this.pruneExpired();
  }

  create(
    input: CreateOperationAuthorityInput,
    principalKeyFingerprint: string,
  ): Record<string, unknown> {
    this.pruneExpired();
    const principal = requiredPrincipalFingerprint(principalKeyFingerprint);
    const taskLabel = optionalText(input.taskLabel ?? input.taskId, 256, "taskLabel");
    const authorityText = requiredText(
      input.authorityText,
      "context.authorize requires the controlling user instruction in authorityText.",
      MAXIMUM_AUTHORITY_TEXT_CHARACTERS,
    );
    if (!Array.isArray(input.actions) || input.actions.length < 1 || input.actions.length > MAXIMUM_ACTIONS) {
      throw new UniversalBrokerError(
        "PRECONDITION_FAILED",
        `context.authorize requires 1 through ${MAXIMUM_ACTIONS} exact actions.`,
      );
    }
    const actions = input.actions.map((action, index) => this.prepareAction(action, index, false));
    assertUniqueActionIds(actions);
    assertUniqueActionFingerprints(actions);
    const expiresInSeconds = boundedInteger(
      input.expiresInSeconds,
      DEFAULT_AUTHORITY_TTL_SECONDS,
      60,
      MAXIMUM_AUTHORITY_TTL_SECONDS,
      "expiresInSeconds",
    );
    const task = this.resolveOrIssueTask(input.taskInstanceId, principal, taskLabel);
    const correctionEpoch = task.correctionEpoch;
    this.dropStaleTaskAuthorities(task.taskInstanceId, correctionEpoch);
    const authorityTextSha256 = sha256(authorityText);
    const fingerprint = sha256(stableJson({
      principalKeyFingerprint: principal,
      taskInstanceId: task.taskInstanceId,
      correctionEpoch,
      authorityTextSha256,
      actions: actions.map((action) => ({
        id: action.id,
        fingerprint: action.fingerprint,
        minimumRisk: action.minimumRisk,
        risk: action.risk,
        maximumUses: action.maximumUses,
      })),
      expiresInSeconds,
    }));
    const existingId = this.authorityIdsByFingerprint.get(fingerprint);
    const existing = existingId ? this.authorities.get(existingId) : undefined;
    if (
      existing
      && existing.expiresAtMs > this.now()
      && existing.receipts.length === 0
      && existing.actions.every((action) => action.consumedUses === 0)
    ) {
      return this.present(existing, true);
    }
    if (existingId) this.authorityIdsByFingerprint.delete(fingerprint);
    this.assertAuthorityCapacity(principal);

    const createdAtMs = this.now();
    const authority: StoredOperationAuthority = {
      authorityId: `authority_${randomUUID()}`,
      taskInstanceId: task.taskInstanceId,
      ...(task.taskLabelSha256 ? { taskLabelSha256: task.taskLabelSha256 } : {}),
      authorityTextSha256,
      principalKeyFingerprint: principal,
      approvalAssurance: "cooperative",
      correctionEpoch,
      createdAtMs,
      expiresAtMs: createdAtMs + expiresInSeconds * 1_000,
      fingerprint,
      actions,
      receipts: [],
    };
    let selected: ReturnType<DurableAuthorityStore["getOrCreateAuthority"]>;
    try {
      selected = this.requireStore().getOrCreateAuthority(
        this.toDurable(authority),
        createdAtMs,
      );
    } catch (error) {
      if (error instanceof UniversalBrokerError) throw error;
      throw new UniversalBrokerError(
        "AUTHORITY_STORE_UNAVAILABLE",
        "The task authority could not be durably persisted.",
        { evidence: { persistenceError: error instanceof Error ? error.name : "UNKNOWN_ERROR" } },
      );
    }
    const durableAuthority = this.fromDurable(selected.authority);
    this.authorities.set(durableAuthority.authorityId, durableAuthority);
    this.authorityIdsByFingerprint.set(fingerprint, durableAuthority.authorityId);
    return this.present(durableAuthority, !selected.created);
  }

  preview(actionsInput: RequestedAuthorityAction[]): Record<string, unknown> {
    if (!Array.isArray(actionsInput) || actionsInput.length < 1 || actionsInput.length > MAXIMUM_ACTIONS) {
      throw new UniversalBrokerError(
        "PRECONDITION_FAILED",
        `context.authority_preview requires 1 through ${MAXIMUM_ACTIONS} exact actions.`,
      );
    }
    const actions = actionsInput.map((action, index) => this.prepareAction(action, index, true));
    assertUniqueActionIds(actions);
    assertUniqueActionFingerprints(actions);
    this.previews += 1;
    const planFingerprint = sha256(stableJson(actions.map((action) => ({
      id: action.id,
      descriptor: action.descriptor,
      minimumRisk: action.minimumRisk,
      risk: action.risk,
      maximumUses: action.maximumUses,
    }))));
    const authorityActions = actions.filter((action) => action.minimumRisk !== "R0");
    return {
      planFingerprint,
      actionCount: actions.length,
      authorityActionCount: authorityActions.length,
      r0ActionCount: actions.length - authorityActions.length,
      authorityRequired: authorityActions.length > 0,
      actions: actions.map((action) => ({
        id: action.id,
        tool: action.descriptor.tool,
        operation: action.descriptor.operation,
        target: action.descriptor.target,
        resource: action.descriptor.resource,
        fingerprint: action.fingerprint,
        minimumRisk: action.minimumRisk,
        effectiveRisk: action.risk,
        authorityRequired: action.minimumRisk !== "R0",
        maximumUses: action.maximumUses,
        parameterKeys: Object.keys(action.descriptor.parameters ?? {}).sort(),
      })),
    };
  }

  prepareDispatch(
    authorityId: string | undefined,
    principalKeyFingerprint: string,
    action: AuthorityActionDescriptor,
    requiredRisk: AuthorityRiskClass,
  ): OperationAuthorityDispatchController {
    if (requiredRisk === "R0") {
      throw new UniversalBrokerError(
        "PRECONDITION_FAILED",
        "R0 operations must use the zero-authority fast path without a dispatch controller.",
      );
    }
    return new OperationAuthorityDispatchController(
      this,
      authorityId,
      requiredPrincipalFingerprint(principalKeyFingerprint),
      action,
      requiredRisk,
    );
  }

  require(
    authorityId: string | undefined,
    principalKeyFingerprint: string,
    action: AuthorityActionDescriptor,
    requiredRisk: AuthorityRiskClass,
  ): AuthorityGrant | undefined {
    return this.claim(authorityId, principalKeyFingerprint, action, requiredRisk);
  }

  claim(
    authorityId: string | undefined,
    principalKeyFingerprint: string,
    action: AuthorityActionDescriptor,
    requiredRisk: AuthorityRiskClass,
  ): AuthorityGrant | undefined {
    if (requiredRisk === "R0") return undefined;
    this.pruneExpired();
    if (!authorityId) {
      throw new UniversalBrokerError(
        "AUTHORITY_REQUIRED",
        `${action.tool}.${action.operation} requires ${requiredRisk} task authority. Prepare it with context.authorize and pass authorityId.`,
        { evidence: { requiredRisk, action: boundedAction(action) } },
      );
    }
    const authority = this.authorities.get(authorityId);
    if (!authority) {
      if (this.staleAuthorityIds.has(authorityId)) {
        throw new UniversalBrokerError(
          "AUTHORITY_STALE",
          `Task authority is stale after a correction: ${authorityId}`,
        );
      }
      throw new UniversalBrokerError(
        "AUTHORITY_EXPIRED",
        `Task authority is unknown, released, stale, or expired: ${authorityId}`,
      );
    }
    const principal = requiredPrincipalFingerprint(principalKeyFingerprint);
    if (authority.principalKeyFingerprint !== principal) {
      throw new UniversalBrokerError(
        "AUTHORITY_PRINCIPAL_MISMATCH",
        "Task authority belongs to a different stable authenticated principal.",
      );
    }
    const task = this.currentTask(authority.taskInstanceId);
    if (
      !task
      || task.principalKeyFingerprint !== principal
      || authority.correctionEpoch !== task.correctionEpoch
    ) {
      this.staleAuthorityIds.add(authority.authorityId);
      this.remove(authority, false);
      throw new UniversalBrokerError(
        "AUTHORITY_STALE",
        `Task authority is stale after a correction: ${authorityId}`,
      );
    }
    if (authority.expiresAtMs <= this.now()) {
      if (this.authorityIdsByFingerprint.get(authority.fingerprint) === authority.authorityId) {
        this.authorityIdsByFingerprint.delete(authority.fingerprint);
      }
      throw new UniversalBrokerError(
        "AUTHORITY_EXPIRED",
        `Task authority expired: ${authorityId}`,
      );
    }
    const fingerprint = actionFingerprint(action);
    const candidates = authority.actions.filter((candidate) => candidate.fingerprint === fingerprint);
    if (candidates.length !== 1) {
      throw new UniversalBrokerError(
        "AUTHORITY_ACTION_MISMATCH",
        `Task authority does not contain exactly one matching ${action.tool}.${action.operation} action.`,
        {
          evidence: {
            authorityId,
            requiredRisk,
            action: boundedAction(action),
            matchingActions: candidates.length,
          },
        },
      );
    }
    const selected = candidates[0]!;
    if (riskRank(selected.risk) < riskRank(requiredRisk)) {
      throw new UniversalBrokerError(
        "AUTHORITY_ACTION_MISMATCH",
        `Task authority action ${selected.id} is ${selected.risk}, but ${requiredRisk} is required.`,
      );
    }
    if (selected.consumedUses >= selected.maximumUses) {
      throw new UniversalBrokerError(
        "AUTHORITY_CONSUMED",
        `Task authority action is fully consumed: ${selected.id}`,
        {
          evidence: {
            authorityId,
            actionId: selected.id,
            maximumUses: selected.maximumUses,
          },
        },
      );
    }
    const actionClaimId = `authority_claim_${randomUUID()}`;
    const claimedAtMs = this.now();
    let reservation: ReturnType<DurableAuthorityStore["claimAction"]>;
    try {
      reservation = this.requireStore().claimAction({
        authorityId,
        principalKeyFingerprint: principal,
        taskInstanceId: authority.taskInstanceId,
        correctionEpoch: authority.correctionEpoch,
        actionId: persistentActionKey(fingerprint),
        actionFingerprint: fingerprint,
        resourceKeySha256: selected.resourceKeySha256,
        actionClaimId,
        claimedAtMs,
        maximumReceipts: MAXIMUM_RECEIPTS,
      });
    } catch (error) {
      if (error instanceof UniversalBrokerError) throw error;
      throw new UniversalBrokerError(
        "AUTHORITY_STATE_UNCERTAIN",
        "Task authority reservation outcome could not be confirmed; the action was not dispatched.",
        {
          evidence: {
            authorityId,
            actionId: selected.id,
            persistenceError: error instanceof Error ? error.name : "UNKNOWN_ERROR",
          },
        },
      );
    }
    if (!reservation.ok) {
      switch (reservation.code) {
        case "AUTHORITY_EXPIRED":
          this.remove(authority, false);
          throw new UniversalBrokerError(
            "AUTHORITY_EXPIRED",
            `Task authority is stale or expired: ${authorityId}`,
          );
        case "AUTHORITY_PRINCIPAL_MISMATCH":
          throw new UniversalBrokerError(
            "AUTHORITY_PRINCIPAL_MISMATCH",
            "Task authority belongs to a different stable authenticated principal.",
          );
        case "AUTHORITY_ACTION_MISMATCH":
          throw new UniversalBrokerError(
            "AUTHORITY_ACTION_MISMATCH",
            "Task authority no longer matches the exact persisted action.",
          );
        case "AUTHORITY_STALE":
          this.staleAuthorityIds.add(authority.authorityId);
          this.remove(authority, false);
          throw new UniversalBrokerError(
            "AUTHORITY_STALE",
            `Task authority is stale after a correction: ${authorityId}`,
          );
        case "AUTHORITY_CONSUMED":
          selected.consumedUses = reservation.consumedUses ?? selected.maximumUses;
          throw new UniversalBrokerError(
            "AUTHORITY_CONSUMED",
            `Task authority action is fully consumed: ${selected.id}`,
            {
              evidence: {
                authorityId,
                actionId: selected.id,
                maximumUses: selected.maximumUses,
              },
            },
          );
        case "RESOURCE_QUOTA_EXCEEDED":
          throw new UniversalBrokerError(
            "RESOURCE_QUOTA_EXCEEDED",
            "Task authority has too many in-flight reservations; wait for terminal receipts.",
            {
              evidence: {
                authorityId,
                maximumReceipts: MAXIMUM_RECEIPTS,
              },
            },
          );
        case "RESOURCE_BUSY":
          throw new UniversalBrokerError(
            "RESOURCE_BUSY",
            "Another writer holds or froze the exact resource lease.",
            {
              retryable: true,
              evidence: {
                resourceKeySha256: selected.resourceKeySha256,
                activeClaimIdSha256: reservation.activeClaimId
                  ? sha256(reservation.activeClaimId)
                  : undefined,
              },
            },
          );
      }
    }
    selected.consumedUses = reservation.consumedUses;
    const grant: AuthorityGrant = {
      authorityId,
      actionId: selected.id,
      actionClaimId: reservation.actionClaimId,
      useId: reservation.actionClaimId,
      risk: requiredRisk,
      fingerprint,
      resourceKeySha256: reservation.resourceKeySha256,
      fencingToken: reservation.fencingToken,
    };
    const receipt: AuthorityReceipt = {
      actionClaimId: grant.actionClaimId,
      useId: grant.useId,
      actionId: grant.actionId,
      taskInstanceId: authority.taskInstanceId,
      principalKeyFingerprint: principal,
      actionFingerprint: fingerprint,
      resourceKeySha256: grant.resourceKeySha256,
      fencingToken: grant.fencingToken,
      claimedAtMs,
      reservedAtMs: claimedAtMs,
      state: "CLAIMED",
      result: "CLAIMED",
      leaseState: "ACTIVE",
    };
    authority.receipts = trimReceipts([...authority.receipts, receipt]);
    return grant;
  }

  markDispatched(grant: AuthorityGrant): void {
    const dispatchedAtMs = this.now();
    let marked: boolean;
    try {
      marked = this.requireStore().markClaimDispatched({
        authorityId: grant.authorityId,
        actionClaimId: grant.actionClaimId,
        resourceKeySha256: grant.resourceKeySha256,
        fencingToken: grant.fencingToken,
        dispatchedAtMs,
      });
    } catch (error) {
      if (error instanceof UniversalBrokerError) throw error;
      throw new UniversalBrokerError(
        "AUTHORITY_STORE_UNAVAILABLE",
        "The durable DISPATCHED barrier could not be written; provider dispatch was not attempted.",
        { evidence: { persistenceError: error instanceof Error ? error.name : "UNKNOWN_ERROR" } },
      );
    }
    if (!marked) {
      throw new UniversalBrokerError(
        "AUTHORITY_STATE_UNCERTAIN",
        "The claim could not cross the durable DISPATCHED barrier with its current fencing token.",
      );
    }
    this.updateReceipt(grant, (receipt) => ({
      ...receipt,
      dispatchedAtMs,
      state: "DISPATCHED",
      result: "DISPATCHED",
    }));
  }

  cancelNotDispatched(grant: AuthorityGrant, proof: ProvenNotDispatched): void {
    const completedAtMs = this.now();
    let cancelled: boolean;
    try {
      cancelled = this.requireStore().cancelClaimNotDispatched({
        authorityId: grant.authorityId,
        actionClaimId: grant.actionClaimId,
        resourceKeySha256: grant.resourceKeySha256,
        fencingToken: grant.fencingToken,
        completedAtMs,
        providerCallCount: 0,
        proofCode: proof.proof,
        maximumReceipts: MAXIMUM_RECEIPTS,
      });
    } catch (error) {
      if (error instanceof UniversalBrokerError) throw error;
      throw new UniversalBrokerError(
        "AUTHORITY_STATE_UNCERTAIN",
        "The proven-not-dispatched claim could not be atomically cancelled and reclaimed.",
        { evidence: { persistenceError: error instanceof Error ? error.name : "UNKNOWN_ERROR" } },
      );
    }
    if (!cancelled) {
      throw new UniversalBrokerError(
        "AUTHORITY_STATE_UNCERTAIN",
        "The claim is no longer eligible for CANCELLED_NOT_DISPATCHED.",
      );
    }
    const authority = this.authorities.get(grant.authorityId);
    const action = authority?.actions.find((candidate) => candidate.fingerprint === grant.fingerprint);
    if (action) action.consumedUses = Math.max(0, action.consumedUses - 1);
    this.updateReceipt(grant, (receipt) => ({
      ...receipt,
      completedAtMs,
      state: "CANCELLED_NOT_DISPATCHED",
      result: "CANCELLED_NOT_DISPATCHED",
      leaseState: "RELEASED",
      providerCallCount: 0,
      evidence: {
        reasonCode: "PROVIDER_CALL_ZERO_PROVEN",
        cancellationProofCode: proof.proof,
      },
    }));
  }

  record(
    grant: AuthorityGrant | undefined,
    result: "PASS" | "FAIL" | "UNCERTAIN",
    evidence?: Record<string, unknown>,
  ): void {
    if (!grant) return;
    const receipt = this.findReceipt(grant);
    if (!receipt || receipt.state === "CLAIMED") this.markDispatched(grant);
    this.completeClaim(grant, result, evidence);
  }

  completeClaim(
    grant: AuthorityGrant,
    result: "PASS" | "FAIL" | "UNCERTAIN",
    evidence?: Record<string, unknown>,
  ): void {
    const completedAtMs = this.now();
    const boundedEvidence = evidence ? boundedRecord(evidence, 4_000) : undefined;
    let finalized: boolean;
    try {
      finalized = this.requireStore().terminalizeClaim({
        authorityId: grant.authorityId,
        actionClaimId: grant.actionClaimId,
        resourceKeySha256: grant.resourceKeySha256,
        fencingToken: grant.fencingToken,
        completedAtMs,
        state: result,
        ...(typeof boundedEvidence?.errorCode === "string"
          ? { errorCode: boundedEvidence.errorCode }
          : {}),
        ...(typeof boundedEvidence?.reasonCode === "string"
          ? { reasonCode: boundedEvidence.reasonCode }
          : {}),
        maximumReceipts: MAXIMUM_RECEIPTS,
      });
    } catch (error) {
      const sealed = this.trySealUncertain(grant, completedAtMs, "RECEIPT_WRITE_FAILED");
      if (sealed) {
        this.updateReceipt(grant, (receipt) => ({
          ...receipt,
          completedAtMs,
          state: "UNCERTAIN",
          result: "UNCERTAIN",
          leaseState: "FROZEN",
          providerCallCount: 1,
          evidence: { errorCode: "AUTHORITY_STATE_UNCERTAIN", reasonCode: "RECEIPT_WRITE_FAILED" },
        }));
      }
      throw new UniversalBrokerError(
        "AUTHORITY_STATE_UNCERTAIN",
        "The action completed, but its authority receipt could not be durably finalized.",
        {
          evidence: {
            authorityId: grant.authorityId,
            actionId: grant.actionId,
            persistenceError: error instanceof Error ? error.name : "UNKNOWN_ERROR",
          },
        },
      );
    }
    if (!finalized) {
      throw new UniversalBrokerError(
        "AUTHORITY_STATE_UNCERTAIN",
        "The authority claim was no longer current DISPATCHED state for its fencing token.",
        {
          evidence: {
            authorityId: grant.authorityId,
            actionId: grant.actionId,
          },
        },
      );
    }
    this.updateReceipt(grant, (receipt) => ({
      ...receipt,
      completedAtMs,
      state: result,
      result,
      leaseState: result === "UNCERTAIN" ? "FROZEN" : "RELEASED",
      providerCallCount: 1,
      ...(boundedEvidence ? { evidence: boundedEvidence } : {}),
    }));
  }

  status(authorityId: string, principalKeyFingerprint: string): Record<string, unknown> {
    this.pruneExpired();
    const normalizedAuthorityId = requiredText(authorityId, "authorityId is required.", 256);
    const durable = this.requireStore().load().authorities.find(
      (candidate) => candidate.authorityId === normalizedAuthorityId,
    );
    if (durable) {
      const refreshed = this.fromDurable(durable);
      this.authorities.set(normalizedAuthorityId, refreshed);
    }
    const authority = this.authorities.get(normalizedAuthorityId);
    if (!authority) {
      if (this.staleAuthorityIds.has(authorityId)) {
        throw new UniversalBrokerError("AUTHORITY_STALE", "Task authority was invalidated by a user correction.");
      }
      throw new UniversalBrokerError("AUTHORITY_EXPIRED", `Unknown task authority: ${authorityId}`);
    }
    const principal = requiredPrincipalFingerprint(principalKeyFingerprint);
    if (authority.principalKeyFingerprint !== principal) {
      throw new UniversalBrokerError(
        "AUTHORITY_PRINCIPAL_MISMATCH",
        "Task authority belongs to a different stable authenticated principal.",
      );
    }
    const task = this.currentTask(authority.taskInstanceId);
    if (
      !task
      || task.principalKeyFingerprint !== principal
      || authority.correctionEpoch !== task.correctionEpoch
    ) {
      this.staleAuthorityIds.add(authority.authorityId);
      this.remove(authority, false);
      throw new UniversalBrokerError("AUTHORITY_STALE", "Task authority was invalidated by a user correction.");
    }
    return this.present(authority, false);
  }

  invalidate(
    principalKeyFingerprint: string,
    taskInstanceId: string,
    correctionText: string,
  ): Record<string, unknown> {
    requiredText(correctionText, "context.invalidate_authority requires correctionText.", 8_000);
    const principal = requiredPrincipalFingerprint(principalKeyFingerprint);
    const taskId = requiredText(
      taskInstanceId,
      "context.invalidate_authority requires a broker-issued taskInstanceId.",
      128,
    );
    let correction: ReturnType<DurableAuthorityStore["incrementTaskCorrectionEpoch"]>;
    try {
      correction = this.requireStore().incrementTaskCorrectionEpoch(taskId, principal, this.now());
    } catch (error) {
      if (error instanceof UniversalBrokerError) throw error;
      throw new UniversalBrokerError(
        "AUTHORITY_STORE_UNAVAILABLE",
        "The task correction could not be durably persisted.",
        { evidence: { persistenceError: error instanceof Error ? error.name : "UNKNOWN_ERROR" } },
      );
    }
    if (!correction.ok) {
      throw new UniversalBrokerError(
        correction.code,
        correction.code === "AUTHORITY_PRINCIPAL_MISMATCH"
          ? "The task belongs to a different stable authenticated principal."
          : `Unknown or stale broker-issued task: ${taskId}`,
      );
    }
    const previous = this.tasks.get(taskId);
    if (previous) {
      this.tasks.set(taskId, {
        ...previous,
        correctionEpoch: correction.correctionEpoch,
        updatedAtMs: this.now(),
      });
    }
    for (const authorityId of correction.authorityIds) {
      const authority = this.authorities.get(authorityId);
      this.staleAuthorityIds.add(authorityId);
      if (authority) this.remove(authority, false);
    }
    return {
      taskInstanceId: taskId,
      correctionEpoch: correction.correctionEpoch,
      invalidatedAuthorityIds: correction.authorityIds,
      correctionTextSha256: sha256(correctionText),
    };
  }

  release(authorityId: string, principalKeyFingerprint: string): Record<string, unknown> {
    const authority = this.authorities.get(requiredText(authorityId, "authorityId is required.", 256));
    if (!authority) {
      if (this.staleAuthorityIds.has(authorityId)) {
        throw new UniversalBrokerError(
          "AUTHORITY_STALE",
          `Task authority is stale after a correction: ${authorityId}`,
        );
      }
      throw new UniversalBrokerError("AUTHORITY_EXPIRED", `Unknown task authority: ${authorityId}`);
    }
    const principal = requiredPrincipalFingerprint(principalKeyFingerprint);
    if (authority.principalKeyFingerprint !== principal) {
      throw new UniversalBrokerError(
        "AUTHORITY_PRINCIPAL_MISMATCH",
        "Task authority belongs to a different stable authenticated principal.",
      );
    }
    let released: ReturnType<DurableAuthorityStore["releaseAuthority"]>;
    try {
      released = this.requireStore().releaseAuthority({
        authorityId: authority.authorityId,
        principalKeyFingerprint: principal,
        taskInstanceId: authority.taskInstanceId,
        correctionEpoch: authority.correctionEpoch,
      });
    } catch (error) {
      if (error instanceof UniversalBrokerError) throw error;
      throw new UniversalBrokerError(
        "AUTHORITY_STATE_UNCERTAIN",
        "Task authority release outcome could not be confirmed.",
        {
          evidence: {
            authorityId,
            persistenceError: error instanceof Error ? error.name : "UNKNOWN_ERROR",
          },
        },
      );
    }
    if (!released.ok) {
      if (released.code === "PRECONDITION_FAILED") {
        throw new UniversalBrokerError(
          "PRECONDITION_FAILED",
          "A task authority with active or frozen claims cannot be released.",
          { evidence: { authorityId, pendingReceipts: released.pendingReceipts ?? 1 } },
        );
      }
      if (released.code === "AUTHORITY_PRINCIPAL_MISMATCH") {
        throw new UniversalBrokerError(
          "AUTHORITY_PRINCIPAL_MISMATCH",
          "Task authority belongs to a different stable authenticated principal.",
        );
      }
      if (released.code === "AUTHORITY_STALE") {
        this.staleAuthorityIds.add(authority.authorityId);
        this.remove(authority, false);
        throw new UniversalBrokerError(
          "AUTHORITY_STALE",
          `Task authority is stale after a correction: ${authorityId}`,
        );
      }
      this.remove(authority, false);
      throw new UniversalBrokerError(
        "AUTHORITY_EXPIRED",
        `Task authority is stale, released, or expired: ${authorityId}`,
      );
    }
    this.remove(authority, false);
    return {
      authorityId,
      taskInstanceId: authority.taskInstanceId,
      released: true,
      receipts: authority.receipts.length,
      unconsumedActions: authority.actions.filter((action) => action.consumedUses < action.maximumUses).length,
    };
  }

  stats(): Record<string, unknown> {
    this.pruneExpired();
    return {
      authorities: this.authorities.size,
      tasks: this.requireStore().taskCount(),
      principals: new Set(
        [...this.authorities.values()].map((authority) => authority.principalKeyFingerprint),
      ).size,
      scopes: new Set(
        [...this.authorities.values()].map((authority) => authority.principalKeyFingerprint),
      ).size,
      pendingReservations: [...this.authorities.values()].reduce(
        (total, authority) => total + authority.receipts.filter(
          (receipt) => receipt.state === "CLAIMED" || receipt.state === "DISPATCHED",
        ).length,
        0,
      ),
      recoveredPendingUses: this.recoveredPendingUses,
      previews: this.previews,
    };
  }

  close(): void {
    if (this.closed) return;
    this.closed = true;
    this.store?.close(this.now());
    releaseAuthorityInstance(this.instanceId);
  }

  private requireStore(): DurableAuthorityStore {
    if (this.store) return this.store;
    throw this.storeFailure ?? new UniversalBrokerError(
      "AUTHORITY_STORE_UNAVAILABLE",
      "The durable authority store is unavailable.",
    );
  }

  private findReceipt(grant: AuthorityGrant): AuthorityReceipt | undefined {
    return this.authorities.get(grant.authorityId)?.receipts.find(
      (receipt) => receipt.actionClaimId === grant.actionClaimId,
    );
  }

  private updateReceipt(
    grant: AuthorityGrant,
    update: (receipt: AuthorityReceipt) => AuthorityReceipt,
  ): void {
    const authority = this.authorities.get(grant.authorityId);
    if (!authority) return;
    const index = authority.receipts.findIndex(
      (receipt) => receipt.actionClaimId === grant.actionClaimId,
    );
    if (index < 0) return;
    authority.receipts = trimReceipts([
      ...authority.receipts.slice(0, index),
      update(authority.receipts[index]!),
      ...authority.receipts.slice(index + 1),
    ]);
  }

  private trySealUncertain(
    grant: AuthorityGrant,
    completedAtMs: number,
    reasonCode: string,
  ): boolean {
    try {
      return this.requireStore().terminalizeClaim({
        authorityId: grant.authorityId,
        actionClaimId: grant.actionClaimId,
        resourceKeySha256: grant.resourceKeySha256,
        fencingToken: grant.fencingToken,
        completedAtMs,
        state: "UNCERTAIN",
        errorCode: "AUTHORITY_STATE_UNCERTAIN",
        reasonCode,
        maximumReceipts: MAXIMUM_RECEIPTS,
      });
    } catch {
      return false;
    }
  }

  private prepareAction(
    action: RequestedAuthorityAction,
    index: number,
    allowR0: boolean,
  ): StoredAuthorityAction {
    if (!action || typeof action !== "object") {
      throw new UniversalBrokerError("PRECONDITION_FAILED", `Invalid authority action at index ${index}.`);
    }
    const source = action.descriptor;
    const descriptor: AuthorityActionDescriptor = {
      tool: source.tool,
      operation: requiredText(source.operation, `Authority action ${index} requires operation.`, 128),
      ...(source.target ? { target: requiredText(source.target, `Authority action ${index} target is invalid.`, 256) } : {}),
      ...(source.resource ? { resource: requiredText(source.resource, `Authority action ${index} resource is invalid.`, 2_048) } : {}),
      ...(source.parameters ? { parameters: boundedParameters(source.parameters, index) } : {}),
    };
    const operations = UNIVERSAL_TOOL_OPERATIONS[descriptor.tool] as readonly string[];
    if (!operations.includes(descriptor.operation)) {
      throw new UniversalBrokerError(
        "PRECONDITION_FAILED",
        `Authority action ${index} uses unsupported operation ${descriptor.tool}.${descriptor.operation}.`,
      );
    }
    const minimumRisk = this.minimumRisk(descriptor);
    if (minimumRisk === "R0" && !allowR0) {
      throw new UniversalBrokerError(
        "PRECONDITION_FAILED",
        `Authority action ${index} is R0 and must run without task authority: ${descriptor.tool}.${descriptor.operation}.`,
      );
    }
    const requestedRisk = action.risk ?? minimumRisk;
    if (!UNIVERSAL_AUTHORITY_RISKS.includes(requestedRisk)) {
      throw new UniversalBrokerError("PRECONDITION_FAILED", `Invalid authority risk at index ${index}.`);
    }
    if (minimumRisk === "R0" && (action.risk !== undefined || action.uses !== undefined)) {
      throw new UniversalBrokerError(
        "PRECONDITION_FAILED",
        `Authority preview action ${index} is R0; omit risk and uses because no authority is required.`,
      );
    }
    if (riskRank(requestedRisk) < riskRank(minimumRisk)) {
      throw new UniversalBrokerError(
        "PRECONDITION_FAILED",
        `Authority action ${index} requests ${requestedRisk}, but ${minimumRisk} is the minimum risk.`,
      );
    }
    const maximumForRisk = requestedRisk === "R3" ? 1 : requestedRisk === "R2" ? 10 : 50;
    const maximumUses = minimumRisk === "R0"
      ? 0
      : boundedInteger(action.uses, 1, 1, maximumForRisk, `actions[${index}].uses`);
    return {
      id: action.id === undefined
        ? `action-${index + 1}`
        : requiredText(action.id, `Authority action ${index} ID is invalid.`, 128),
      descriptor,
      fingerprint: actionFingerprint(descriptor),
      resourceKeySha256: actionResourceKeySha256(descriptor),
      minimumRisk,
      risk: requestedRisk,
      maximumUses,
      consumedUses: 0,
    };
  }

  private present(authority: StoredOperationAuthority, reused: boolean): Record<string, unknown> {
    return {
      authorityId: authority.authorityId,
      taskInstanceId: authority.taskInstanceId,
      ...(authority.taskLabelSha256 ? { taskLabelSha256: authority.taskLabelSha256 } : {}),
      principalKeyFingerprint: authority.principalKeyFingerprint,
      approvalAssurance: authority.approvalAssurance,
      correctionEpoch: authority.correctionEpoch,
      createdAt: new Date(authority.createdAtMs).toISOString(),
      expiresAt: new Date(authority.expiresAtMs).toISOString(),
      expired: authority.expiresAtMs <= this.now(),
      authorityTextSha256: authority.authorityTextSha256,
      reused,
      actions: authority.actions.map((action) => ({
        id: action.id,
        tool: action.descriptor.tool,
        operation: action.descriptor.operation,
        resourceKeySha256: action.resourceKeySha256,
        risk: action.risk,
        maximumUses: action.maximumUses,
        consumedUses: action.consumedUses,
      })),
      receipts: authority.receipts.map((receipt) => ({
        actionClaimId: receipt.actionClaimId,
        useId: receipt.useId,
        actionId: receipt.actionId,
        resourceKeySha256: receipt.resourceKeySha256,
        fencingToken: receipt.fencingToken,
        claimedAt: new Date(receipt.claimedAtMs).toISOString(),
        ...(receipt.dispatchedAtMs === undefined
          ? {}
          : { dispatchedAt: new Date(receipt.dispatchedAtMs).toISOString() }),
        ...(receipt.completedAtMs === undefined
          ? {}
          : {
              completedAt: new Date(receipt.completedAtMs).toISOString(),
              recordedAt: new Date(receipt.completedAtMs).toISOString(),
            }),
        state: receipt.state,
        result: receipt.result,
        leaseState: receipt.leaseState,
        ...(receipt.providerCallCount === undefined
          ? {}
          : { providerCallCount: receipt.providerCallCount }),
        ...(receipt.evidence ? { evidence: receipt.evidence } : {}),
      })),
    };
  }

  private resolveOrIssueTask(
    requestedTaskInstanceId: string | undefined,
    principalKeyFingerprint: string,
    taskLabel: string | undefined,
  ): DurableAuthorityTaskRecord {
    if (requestedTaskInstanceId) {
      const taskInstanceId = requiredText(
        requestedTaskInstanceId,
        "taskInstanceId is invalid.",
        128,
      );
      const task = this.currentTask(taskInstanceId);
      if (!task) {
        throw new UniversalBrokerError(
          "AUTHORITY_STALE",
          `Unknown broker-issued taskInstanceId: ${taskInstanceId}`,
        );
      }
      if (task.principalKeyFingerprint !== principalKeyFingerprint) {
        throw new UniversalBrokerError(
          "AUTHORITY_PRINCIPAL_MISMATCH",
          "The broker-issued task belongs to a different stable authenticated principal.",
        );
      }
      return task;
    }
    const now = this.now();
    const task: DurableAuthorityTaskRecord = {
      taskInstanceId: `task_${randomUUID()}`,
      principalKeyFingerprint,
      ...(taskLabel ? { taskLabelSha256: sha256(taskLabel) } : {}),
      correctionEpoch: 0,
      createdAtMs: now,
      updatedAtMs: now,
    };
    try {
      this.requireStore().saveTask(task);
    } catch (error) {
      if (error instanceof UniversalBrokerError) throw error;
      throw new UniversalBrokerError(
        "AUTHORITY_STORE_UNAVAILABLE",
        "The broker-issued task could not be durably persisted.",
        { evidence: { persistenceError: error instanceof Error ? error.name : "UNKNOWN_ERROR" } },
      );
    }
    this.tasks.set(task.taskInstanceId, task);
    return task;
  }

  private currentTask(taskInstanceId: string): DurableAuthorityTaskRecord | undefined {
    const task = this.requireStore().getTask(taskInstanceId);
    if (task) this.tasks.set(taskInstanceId, task);
    else this.tasks.delete(taskInstanceId);
    return task;
  }

  private dropStaleTaskAuthorities(taskInstanceId: string, correctionEpoch: number): void {
    for (const authority of [...this.authorities.values()]) {
      if (
        authority.taskInstanceId === taskInstanceId
        && authority.correctionEpoch !== correctionEpoch
      ) {
        this.staleAuthorityIds.add(authority.authorityId);
        this.remove(authority, false);
      }
    }
  }

  private pruneExpired(): void {
    const now = this.now();
    const purgedAuthorityIds = this.requireStore().deleteAuthoritiesExpiredBefore(
      now - AUTHORITY_RECEIPT_RETENTION_MS,
    );
    for (const authorityId of purgedAuthorityIds) {
      const authority = this.authorities.get(authorityId);
      if (authority) this.remove(authority, false);
    }
    for (const authority of this.authorities.values()) {
      if (
        authority.expiresAtMs <= now
        && this.authorityIdsByFingerprint.get(authority.fingerprint) === authority.authorityId
      ) {
        this.authorityIdsByFingerprint.delete(authority.fingerprint);
      }
    }
  }

  private remove(authority: StoredOperationAuthority, persist = true): void {
    if (persist) this.requireStore().deleteAuthorities([authority.authorityId]);
    this.authorities.delete(authority.authorityId);
    if (this.authorityIdsByFingerprint.get(authority.fingerprint) === authority.authorityId) {
      this.authorityIdsByFingerprint.delete(authority.fingerprint);
    }
  }

  private assertAuthorityCapacity(principalKeyFingerprint: string): void {
    const now = this.now();
    const activeAuthorities = [...this.authorities.values()].filter(
      (authority) => authority.expiresAtMs > now,
    );
    const principalAuthorities = activeAuthorities.filter(
      (authority) => authority.principalKeyFingerprint === principalKeyFingerprint,
    ).length;
    if (
      activeAuthorities.length >= MAXIMUM_ACTIVE_AUTHORITIES
      || principalAuthorities >= MAXIMUM_ACTIVE_AUTHORITIES_PER_SCOPE
    ) {
      throw new UniversalBrokerError(
        "RESOURCE_QUOTA_EXCEEDED",
        "Operation authority quota is full; release or wait for existing authorities to expire.",
        {
          evidence: {
            authorities: activeAuthorities.length,
            maximumAuthorities: MAXIMUM_ACTIVE_AUTHORITIES,
            principalAuthorities,
            maximumAuthoritiesPerPrincipal: MAXIMUM_ACTIVE_AUTHORITIES_PER_SCOPE,
          },
        },
      );
    }
  }

  private toDurable(authority: StoredOperationAuthority): DurableAuthorityRecord {
    const persistentActionIds = new Map(
      authority.actions.map((action) => [action.id, persistentActionKey(action.fingerprint)]),
    );
    return {
      authorityId: authority.authorityId,
      taskInstanceId: authority.taskInstanceId,
      ...(authority.taskLabelSha256 ? { taskLabelSha256: authority.taskLabelSha256 } : {}),
      authorityTextSha256: authority.authorityTextSha256,
      principalKeyFingerprint: authority.principalKeyFingerprint,
      approvalAssurance: authority.approvalAssurance,
      correctionEpoch: authority.correctionEpoch,
      createdAtMs: authority.createdAtMs,
      expiresAtMs: authority.expiresAtMs,
      fingerprint: authority.fingerprint,
      actions: authority.actions.map((action) => ({
        id: persistentActionKey(action.fingerprint),
        tool: action.descriptor.tool,
        operation: action.descriptor.operation,
        fingerprint: action.fingerprint,
        resourceKeySha256: action.resourceKeySha256,
        minimumRisk: action.minimumRisk,
        risk: action.risk,
        maximumUses: action.maximumUses,
        consumedUses: action.consumedUses,
      })),
      receipts: authority.receipts.map((receipt) => {
        const actionId = persistentActionIds.get(receipt.actionId);
        if (!actionId) {
          throw new Error(`Authority receipt references an unknown in-memory action: ${receipt.actionId}`);
        }
        return {
          actionClaimId: receipt.actionClaimId,
          useId: receipt.useId,
          actionId,
          taskInstanceId: receipt.taskInstanceId,
          principalKeyFingerprint: receipt.principalKeyFingerprint,
          actionFingerprint: receipt.actionFingerprint,
          resourceKeySha256: receipt.resourceKeySha256,
          fencingToken: receipt.fencingToken,
          claimedAtMs: receipt.claimedAtMs,
          reservedAtMs: receipt.reservedAtMs,
          ...(receipt.dispatchedAtMs === undefined ? {} : { dispatchedAtMs: receipt.dispatchedAtMs }),
          ...(receipt.completedAtMs === undefined ? {} : { completedAtMs: receipt.completedAtMs }),
          state: receipt.state,
          result: receipt.result,
          leaseState: receipt.leaseState,
          ...(receipt.providerCallCount === undefined
            ? {}
            : { providerCallCount: receipt.providerCallCount }),
          ...(typeof receipt.evidence?.errorCode === "string"
            ? { errorCode: receipt.evidence.errorCode }
            : {}),
          ...(typeof receipt.evidence?.reasonCode === "string"
            ? { reasonCode: receipt.evidence.reasonCode }
            : {}),
        };
      }),
    };
  }

  private fromDurable(record: DurableAuthorityRecord): StoredOperationAuthority {
    return {
      authorityId: record.authorityId,
      taskInstanceId: record.taskInstanceId,
      ...(record.taskLabelSha256 ? { taskLabelSha256: record.taskLabelSha256 } : {}),
      authorityTextSha256: record.authorityTextSha256,
      principalKeyFingerprint: record.principalKeyFingerprint,
      approvalAssurance: record.approvalAssurance,
      correctionEpoch: record.correctionEpoch,
      createdAtMs: record.createdAtMs,
      expiresAtMs: record.expiresAtMs,
      fingerprint: record.fingerprint,
      actions: record.actions.map((action) => ({
        id: action.id,
        descriptor: {
          tool: persistedTool(action.tool),
          operation: action.operation,
        },
        fingerprint: action.fingerprint,
        resourceKeySha256: action.resourceKeySha256,
        minimumRisk: persistedRisk(action.minimumRisk),
        risk: persistedRisk(action.risk),
        maximumUses: action.maximumUses,
        consumedUses: action.consumedUses,
      })),
      receipts: record.receipts.map((receipt) => ({
        actionClaimId: receipt.actionClaimId,
        useId: receipt.useId,
        actionId: receipt.actionId,
        taskInstanceId: receipt.taskInstanceId,
        principalKeyFingerprint: receipt.principalKeyFingerprint,
        actionFingerprint: receipt.actionFingerprint,
        resourceKeySha256: receipt.resourceKeySha256,
        fencingToken: receipt.fencingToken,
        claimedAtMs: receipt.claimedAtMs,
        reservedAtMs: receipt.reservedAtMs,
        ...(receipt.dispatchedAtMs === undefined ? {} : { dispatchedAtMs: receipt.dispatchedAtMs }),
        ...(receipt.completedAtMs === undefined ? {} : { completedAtMs: receipt.completedAtMs }),
        state: receipt.state,
        result: receipt.result,
        leaseState: receipt.leaseState,
        ...(receipt.providerCallCount === undefined
          ? {}
          : { providerCallCount: receipt.providerCallCount }),
        ...(receipt.errorCode || receipt.reasonCode
          ? {
              evidence: {
                ...(receipt.errorCode ? { errorCode: receipt.errorCode } : {}),
                ...(receipt.reasonCode ? { reasonCode: receipt.reasonCode } : {}),
              },
            }
          : {}),
      })),
    };
  }
}

export function actionFingerprint(action: AuthorityActionDescriptor): string {
  return sha256(stableJson(normalizeAction(action)));
}

/** Hashes only the stable mutation domain, never command/path/secret payload bytes. */
export function actionResourceKeySha256(action: AuthorityActionDescriptor): string {
  const endpointGeneration = typeof action.parameters?.targetGeneration === "string"
    ? action.parameters.targetGeneration
    : typeof action.parameters?.routeGeneration === "string"
      ? action.parameters.routeGeneration
      : "unversioned-endpoint";
  return sha256(stableJson({
    tool: action.tool,
    target: action.target?.trim() || "default-target",
    resource: action.resource?.trim() || `operation:${action.operation.trim()}`,
    endpointGeneration,
  }));
}

export function authorityRiskAtLeast(actual: AuthorityRiskClass, required: AuthorityRiskClass): boolean {
  return riskRank(actual) >= riskRank(required);
}

function normalizeAction(action: AuthorityActionDescriptor): Record<string, unknown> {
  return {
    tool: action.tool,
    operation: action.operation.trim(),
    ...(action.target?.trim() ? { target: action.target.trim() } : {}),
    ...(action.resource?.trim() ? { resource: action.resource.trim() } : {}),
    ...(action.parameters ? { parameters: normalizeValue(action.parameters) } : {}),
  };
}

function normalizeValue(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(normalizeValue);
  if (value && typeof value === "object") {
    return Object.fromEntries(
      Object.entries(value as Record<string, unknown>)
        .filter(([, child]) => child !== undefined)
        .sort(([left], [right]) => left.localeCompare(right))
        .map(([key, child]) => [key, normalizeValue(child)]),
    );
  }
  return value;
}

function boundedParameters(value: Record<string, unknown>, index: number): Record<string, unknown> {
  const normalized = normalizeValue(value) as Record<string, unknown>;
  const characters = JSON.stringify(normalized).length;
  if (characters > MAXIMUM_ACTION_PARAMETERS_CHARACTERS) {
    throw new UniversalBrokerError(
      "PRECONDITION_FAILED",
      `Authority action ${index} parameters use ${characters} characters; limit is ${MAXIMUM_ACTION_PARAMETERS_CHARACTERS}.`,
    );
  }
  return normalized;
}

function boundedAction(action: AuthorityActionDescriptor): Record<string, unknown> {
  const normalized = normalizeAction(action);
  const serialized = JSON.stringify(normalized);
  return serialized.length <= 4_000
    ? normalized
    : { tool: action.tool, operation: action.operation, fingerprint: actionFingerprint(action) };
}

function boundedRecord(value: Record<string, unknown>, maximumCharacters: number): Record<string, unknown> {
  const normalized = normalizeValue(value) as Record<string, unknown>;
  const serialized = JSON.stringify(normalized);
  return serialized.length <= maximumCharacters
    ? normalized
    : { truncated: true, sha256: sha256(serialized), characters: serialized.length };
}

function assertUniqueActionIds(actions: StoredAuthorityAction[]): void {
  const ids = new Set<string>();
  for (const action of actions) {
    if (ids.has(action.id)) {
      throw new UniversalBrokerError("PRECONDITION_FAILED", `Duplicate authority action ID: ${action.id}`);
    }
    ids.add(action.id);
  }
}

function assertUniqueActionFingerprints(actions: StoredAuthorityAction[]): void {
  const fingerprints = new Map<string, string>();
  for (const action of actions) {
    const previous = fingerprints.get(action.fingerprint);
    if (previous) {
      throw new UniversalBrokerError(
        "PRECONDITION_FAILED",
        `Duplicate exact authority actions ${previous} and ${action.id}; combine repeated identical calls with one action and uses.`,
      );
    }
    fingerprints.set(action.fingerprint, action.id);
  }
}

function trimReceipts(receipts: AuthorityReceipt[]): AuthorityReceipt[] {
  if (receipts.length <= MAXIMUM_RECEIPTS) return receipts;
  const retained = receipts.filter(
    (receipt) => ["CLAIMED", "DISPATCHED", "UNCERTAIN"].includes(receipt.state),
  );
  const terminalCapacity = Math.max(0, MAXIMUM_RECEIPTS - retained.length);
  const terminal = receipts.filter(
    (receipt) => !["CLAIMED", "DISPATCHED", "UNCERTAIN"].includes(receipt.state),
  );
  const retainedTerminalIds = new Set(
    terminal.slice(Math.max(0, terminal.length - terminalCapacity))
      .map((receipt) => receipt.actionClaimId),
  );
  return receipts.filter(
    (receipt) => ["CLAIMED", "DISPATCHED", "UNCERTAIN"].includes(receipt.state)
      || retainedTerminalIds.has(receipt.actionClaimId),
  );
}

function retainAuthorityInstance(instanceId: string): void {
  ACTIVE_AUTHORITY_INSTANCE_COUNTS.set(
    instanceId,
    (ACTIVE_AUTHORITY_INSTANCE_COUNTS.get(instanceId) ?? 0) + 1,
  );
}

function releaseAuthorityInstance(instanceId: string): void {
  const remaining = (ACTIVE_AUTHORITY_INSTANCE_COUNTS.get(instanceId) ?? 1) - 1;
  if (remaining <= 0) ACTIVE_AUTHORITY_INSTANCE_COUNTS.delete(instanceId);
  else ACTIVE_AUTHORITY_INSTANCE_COUNTS.set(instanceId, remaining);
}

function requiredPrincipalFingerprint(value: string): string {
  const normalized = requiredText(
    value,
    "A stable authenticated principal fingerprint is required.",
    2_048,
  );
  return /^[a-f0-9]{64}$/u.test(normalized) ? normalized : sha256(normalized);
}

function authorityStoreFailure(error: unknown): UniversalBrokerError {
  if (error instanceof UniversalBrokerError) return error;
  const sqliteCode = error && typeof error === "object" && "code" in error
    ? String(error.code)
    : undefined;
  const corrupted = sqliteCode === "SQLITE_CORRUPT"
    || sqliteCode === "SQLITE_NOTADB"
    || sqliteCode === "SQLITE_FORMAT";
  return new UniversalBrokerError(
    corrupted ? "STATE_CORRUPTED" : "AUTHORITY_STORE_UNAVAILABLE",
    corrupted
      ? "The durable authority store is corrupted; mutation authority is fail-closed."
      : "The durable authority store is unavailable; mutation authority is fail-closed.",
    {
      evidence: {
        persistenceError: error instanceof Error ? error.name : "UNKNOWN_ERROR",
        ...(sqliteCode ? { sqliteCode } : {}),
      },
    },
  );
}

function persistentActionKey(fingerprint: string): string {
  return `action_${fingerprint}`;
}

function persistedTool(value: string): UniversalToolName {
  if (!Object.prototype.hasOwnProperty.call(UNIVERSAL_TOOL_OPERATIONS, value)) {
    throw new Error(`Invalid persisted authority tool: ${value}`);
  }
  return value as UniversalToolName;
}

function persistedRisk(value: string): AuthorityRiskClass {
  if (!UNIVERSAL_AUTHORITY_RISKS.includes(value as AuthorityRiskClass)) {
    throw new Error(`Invalid persisted authority risk: ${value}`);
  }
  return value as AuthorityRiskClass;
}

function riskRank(risk: AuthorityRiskClass): number {
  return UNIVERSAL_AUTHORITY_RISKS.indexOf(risk);
}

function sha256(value: string): string {
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

function requiredText(value: string | undefined, message: string, maximum: number): string {
  const normalized = value?.trim();
  if (!normalized) throw new UniversalBrokerError("PRECONDITION_FAILED", message);
  if (normalized.length > maximum) {
    throw new UniversalBrokerError(
      "PRECONDITION_FAILED",
      `${message} Maximum characters: ${maximum}.`,
    );
  }
  return normalized;
}

function optionalText(
  value: string | undefined,
  maximum: number,
  name: string,
): string | undefined {
  const normalized = value?.trim();
  if (!normalized) return undefined;
  if (normalized.length > maximum || /[\r\n\0]/u.test(normalized)) {
    throw new UniversalBrokerError(
      "PRECONDITION_FAILED",
      `${name} must use 1 through ${maximum} single-line characters.`,
    );
  }
  return normalized;
}

function boundedInteger(
  value: number | undefined,
  fallback: number,
  minimum: number,
  maximum: number,
  name: string,
): number {
  const parsed = value ?? fallback;
  if (!Number.isInteger(parsed) || parsed < minimum || parsed > maximum) {
    throw new UniversalBrokerError(
      "PRECONDITION_FAILED",
      `${name} must be an integer from ${minimum} through ${maximum}.`,
    );
  }
  return parsed;
}
