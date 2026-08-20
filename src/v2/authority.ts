import { createHash, randomUUID } from "node:crypto";
import {
  DurableAuthorityStore,
  type DurableActionClaimState,
  type DurableAuthorityRecord,
  type DurableAuthorityReceiptAuditState,
  type DurableAuthorityTaskRecord,
  type DurableResourceLeaseHeartbeat,
  type DurableResourceReconciliationOutcome,
  type DurableResourceLeaseState,
} from "./authority-store.js";
import {
  UNIVERSAL_AUTHORITY_RISKS,
  UNIVERSAL_TOOL_OPERATIONS,
  type AuthorityRiskClass,
  type UniversalToolName,
} from "./contracts.js";
import { UniversalBrokerError } from "./errors.js";
import type { UniversalBrokerMetrics } from "./metrics.js";

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

export interface CreateConnectorActivationAuthorityInput {
  authorityText: string;
  descriptor: AuthorityActionDescriptor;
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
  leaseExpiresAtMs: number;
  claimedAtMs: number;
  dispatchedAtMs?: number;
}

export interface AuthorityCompletionReceipt {
  actionClaimId: string;
  useId: string;
  receiptDigest: string;
  state: DurableActionClaimState;
  result: DurableActionClaimState;
  leaseState: DurableResourceLeaseState;
  completedAt?: string;
  auditState?: DurableAuthorityReceiptAuditState;
  auditEventDigest?: string;
  auditRecordedAt?: string;
  auditErrorCode?: string;
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
  auditState?: DurableAuthorityReceiptAuditState;
  auditEventDigest?: string;
  auditReceiptDigest?: string;
  auditRecordedAtMs?: number;
  auditErrorCode?: string;
}

export interface AuthorityReceiptAuditResultInput {
  authorityId: string;
  actionClaimId: string;
  receiptDigest: string;
  status: DurableAuthorityReceiptAuditState;
  auditEventDigest?: string;
  errorCode?: string;
}

export interface OperationAuthorityRegistryOptions {
  now?: () => number;
  minimumRisk?: (action: AuthorityActionDescriptor) => AuthorityRiskClass;
  storePath?: string;
  instanceId?: string;
  resourceLeaseTtlMs?: number;
  resourceLeaseHeartbeatMs?: number;
  resourceLeaseRecoveryGraceMs?: number;
  leaseHeartbeatScheduler?: AuthorityLeaseHeartbeatScheduler;
  metrics?: UniversalBrokerMetrics;
}

export type AuthorityLeaseHeartbeatScheduler = (
  callback: () => void,
  intervalMs: number,
) => () => void;

const DEFAULT_AUTHORITY_TTL_SECONDS = 15 * 60;
const MAXIMUM_AUTHORITY_TTL_SECONDS = 8 * 60 * 60;
const MAXIMUM_ACTIONS = 64;
const MAXIMUM_AUTHORITY_TEXT_CHARACTERS = 8_000;
const MAXIMUM_ACTION_PARAMETERS_CHARACTERS = 16_000;
const MAXIMUM_RECEIPTS = 256;
const MAXIMUM_ACTIVE_AUTHORITIES = 4_096;
const MAXIMUM_ACTIVE_AUTHORITIES_PER_SCOPE = 512;
const AUTHORITY_RECEIPT_RETENTION_MS = 24 * 60 * 60_000;
const DEFAULT_RESOURCE_LEASE_TTL_MS = 15 * 60_000;
const DEFAULT_RESOURCE_LEASE_HEARTBEAT_MS = 30_000;
const DEFAULT_RESOURCE_LEASE_RECOVERY_GRACE_MS = 60_000;
const MAXIMUM_RESOURCE_LEASE_INTERVAL_MS = 24 * 60 * 60_000;
const ACTIVE_AUTHORITY_INSTANCE_COUNTS = new Map<string, number>();

export interface ProvenNotDispatched {
  providerCallCount: 0;
  proof: string;
}

export interface ResourceLeaseReconciliationInput {
  principalKeyFingerprint: string;
  resourceKeySha256: string;
  actionClaimId: string;
  fencingToken: number;
  outcome: DurableResourceReconciliationOutcome;
  evidenceDigest: string;
}

export interface RecoveredConnectorActivationPassInput {
  principalKeyFingerprint: string;
  authorityId: string;
  actionClaimId: string;
  actionFingerprint: string;
  resourceKeySha256: string;
  fencingToken: number;
  oauthProofDigest: string;
  evidenceDigest: string;
}

export interface RecoveredConnectorActivationAuthorityReceipt
  extends AuthorityCompletionReceipt {
  recovered: true;
  oauthProofDigest: string;
  reconciliationEvidenceDigest: string;
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
  private stopLeaseHeartbeat: (() => void) | undefined;

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
    const stopLeaseHeartbeat = this.registry.startAutomaticLeaseHeartbeat(() => this.heartbeat());
    try {
      this.registry.markDispatched(grant);
    } catch (error) {
      stopLeaseHeartbeat();
      throw error;
    }
    this.stopLeaseHeartbeat = stopLeaseHeartbeat;
    this.phaseValue = "DISPATCHED";
    return grant;
  }

  heartbeat(): DurableResourceLeaseHeartbeat {
    const grant = this.grantValue;
    if (!grant || (this.phaseValue !== "CLAIMED" && this.phaseValue !== "DISPATCHED")) {
      throw new UniversalBrokerError(
        "AUTHORITY_STATE_UNCERTAIN",
        `A resource lease cannot heartbeat from ${this.phaseValue}.`,
      );
    }
    return this.registry.heartbeatResourceLease(grant);
  }

  cancelNotDispatched(proof: ProvenNotDispatched): AuthorityCompletionReceipt {
    if (proof.providerCallCount !== 0 || this.phaseValue !== "CLAIMED" || !this.grantValue) {
      throw new UniversalBrokerError(
        "AUTHORITY_STATE_UNCERTAIN",
        "A claim can be cancelled only before DISPATCHED with independently proven provider call count zero.",
      );
    }
    const receipt = this.registry.cancelNotDispatched(this.grantValue, proof);
    this.phaseValue = "CANCELLED_NOT_DISPATCHED";
    this.stopAutomaticLeaseHeartbeat();
    return receipt;
  }

  complete(
    state: "PASS" | "FAIL" | "UNCERTAIN",
    evidence?: Record<string, unknown>,
  ): AuthorityCompletionReceipt {
    if (this.phaseValue !== "DISPATCHED" || !this.grantValue) {
      throw new UniversalBrokerError(
        "AUTHORITY_STATE_UNCERTAIN",
        `A claim cannot terminalize as ${state} before the durable DISPATCHED barrier.`,
      );
    }
    try {
      const receipt = this.registry.completeClaim(this.grantValue, state, evidence);
      this.phaseValue = state;
      return receipt;
    } finally {
      this.stopAutomaticLeaseHeartbeat();
    }
  }

  private stopAutomaticLeaseHeartbeat(): void {
    this.stopLeaseHeartbeat?.();
    this.stopLeaseHeartbeat = undefined;
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
  private readonly resourceLeaseHeartbeatMs: number;
  private readonly leaseHeartbeatScheduler: AuthorityLeaseHeartbeatScheduler;
  private readonly activeLeaseHeartbeatStops = new Set<() => void>();
  private metrics: UniversalBrokerMetrics | undefined;
  private closed = false;
  private previews = 0;

  constructor(options: OperationAuthorityRegistryOptions = {}) {
    this.now = options.now ?? Date.now;
    this.minimumRisk = options.minimumRisk ?? (() => "R1");
    this.instanceId = options.instanceId ?? `authority_run_${randomUUID()}`;
    const resourceLeaseTtlMs = options.resourceLeaseTtlMs ?? DEFAULT_RESOURCE_LEASE_TTL_MS;
    this.resourceLeaseHeartbeatMs = boundedLeaseInterval(
      options.resourceLeaseHeartbeatMs
        ?? Math.min(DEFAULT_RESOURCE_LEASE_HEARTBEAT_MS, Math.max(1, Math.floor(resourceLeaseTtlMs / 3))),
      "resourceLeaseHeartbeatMs",
    );
    const resourceLeaseRecoveryGraceMs = boundedLeaseInterval(
      options.resourceLeaseRecoveryGraceMs ?? DEFAULT_RESOURCE_LEASE_RECOVERY_GRACE_MS,
      "resourceLeaseRecoveryGraceMs",
      true,
    );
    if (this.resourceLeaseHeartbeatMs >= resourceLeaseTtlMs) {
      throw new Error("resourceLeaseHeartbeatMs must be shorter than resourceLeaseTtlMs.");
    }
    this.leaseHeartbeatScheduler = options.leaseHeartbeatScheduler
      ?? defaultAuthorityLeaseHeartbeatScheduler;
    this.metrics = options.metrics;
    retainAuthorityInstance(this.instanceId);
    try {
      this.store = new DurableAuthorityStore(
        options.storePath,
        this.now(),
        this.instanceId,
        [...ACTIVE_AUTHORITY_INSTANCE_COUNTS.keys()],
        resourceLeaseTtlMs,
        resourceLeaseRecoveryGraceMs,
        Math.min(
          MAXIMUM_RESOURCE_LEASE_INTERVAL_MS,
          this.resourceLeaseHeartbeatMs * 2,
        ),
      );
    } catch (error) {
      this.store = undefined;
      this.storeFailure = authorityStoreFailure(error);
      this.recoveredPendingUses = 0;
      this.recordAuthorityStoreFailure("create");
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

  setOperationalMetrics(metrics: UniversalBrokerMetrics | undefined): void {
    this.metrics = metrics;
  }

  create(
    input: CreateOperationAuthorityInput,
    principalKeyFingerprint: string,
  ): Record<string, unknown> {
    return this.createAuthority(input, principalKeyFingerprint, false);
  }

  /**
   * Mints the one internal R3 grant used by the owner-authenticated connector
   * finalization boundary. This operation is intentionally absent from the
   * public eight-tool contract and cannot be requested through context.authorize.
   */
  createConnectorActivationAuthority(
    input: CreateConnectorActivationAuthorityInput,
    principalKeyFingerprint: string,
  ): Record<string, unknown> {
    assertConnectorActivationAuthorityDescriptor(input.descriptor);
    return this.createAuthority({
      authorityText: input.authorityText,
      actions: [{
        id: "connector-activation-finalize",
        descriptor: input.descriptor,
        risk: "R3",
        uses: 1,
      }],
      expiresInSeconds: 5 * 60,
    }, principalKeyFingerprint, true);
  }

  private createAuthority(
    input: CreateOperationAuthorityInput,
    principalKeyFingerprint: string,
    allowConnectorActivation: boolean,
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
    const actions = input.actions.map((action, index) => (
      this.prepareAction(action, index, false, allowConnectorActivation)
    ));
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
      this.recordAuthorityStoreFailure("create");
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
      this.recordAuthorityCheckMetric(requiredRisk, "fail");
      throw new UniversalBrokerError(
        "AUTHORITY_REQUIRED",
        `${action.tool}.${action.operation} requires ${requiredRisk} task authority. Prepare it with context.authorize and pass authorityId.`,
        { evidence: { requiredRisk, action: boundedAction(action) } },
      );
    }
    const authority = this.authorities.get(authorityId);
    if (!authority) {
      if (this.staleAuthorityIds.has(authorityId)) {
        this.recordAuthorityCheckMetric(requiredRisk, "fail");
        throw new UniversalBrokerError(
          "AUTHORITY_STALE",
          `Task authority is stale after a correction: ${authorityId}`,
        );
      }
      this.recordAuthorityCheckMetric(requiredRisk, "fail");
      throw new UniversalBrokerError(
        "AUTHORITY_EXPIRED",
        `Task authority is unknown, released, stale, or expired: ${authorityId}`,
      );
    }
    const principal = requiredPrincipalFingerprint(principalKeyFingerprint);
    if (authority.principalKeyFingerprint !== principal) {
      this.recordAuthorityCheckMetric(requiredRisk, "fail");
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
      this.recordAuthorityCheckMetric(requiredRisk, "fail");
      throw new UniversalBrokerError(
        "AUTHORITY_STALE",
        `Task authority is stale after a correction: ${authorityId}`,
      );
    }
    if (authority.expiresAtMs <= this.now()) {
      if (this.authorityIdsByFingerprint.get(authority.fingerprint) === authority.authorityId) {
        this.authorityIdsByFingerprint.delete(authority.fingerprint);
      }
      this.recordAuthorityCheckMetric(requiredRisk, "fail");
      throw new UniversalBrokerError(
        "AUTHORITY_EXPIRED",
        `Task authority expired: ${authorityId}`,
      );
    }
    const fingerprint = actionFingerprint(action);
    const candidates = authority.actions.filter((candidate) => candidate.fingerprint === fingerprint);
    if (candidates.length !== 1) {
      this.recordAuthorityCheckMetric(requiredRisk, "fail");
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
      this.recordAuthorityCheckMetric(requiredRisk, "fail");
      throw new UniversalBrokerError(
        "AUTHORITY_ACTION_MISMATCH",
        `Task authority action ${selected.id} is ${selected.risk}, but ${requiredRisk} is required.`,
      );
    }
    if (selected.consumedUses >= selected.maximumUses) {
      this.recordAuthorityCheckMetric(requiredRisk, "fail");
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
      this.recordAuthorityCheckMetric(requiredRisk, "fail");
      this.recordAuthorityStoreFailure("claim");
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
      this.recordAuthorityCheckMetric(requiredRisk, "fail");
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
          this.recordQuotaRejection("authority_receipt");
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
          this.recordResourceLeaseEvent("busy");
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
      leaseExpiresAtMs: reservation.leaseExpiresAtMs,
      claimedAtMs,
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
    this.recordAuthorityCheckMetric(requiredRisk, "pass");
    this.recordAuthorityClaimMetric(requiredRisk, "CLAIMED");
    this.recordResourceLeaseEvent("acquired");
    return grant;
  }

  markDispatched(grant: AuthorityGrant): void {
    const dispatchedAtMs = this.now();
    let dispatchedLease: DurableResourceLeaseHeartbeat | undefined;
    try {
      dispatchedLease = this.requireStore().markClaimDispatched({
        authorityId: grant.authorityId,
        actionClaimId: grant.actionClaimId,
        resourceKeySha256: grant.resourceKeySha256,
        fencingToken: grant.fencingToken,
        dispatchedAtMs,
      });
    } catch (error) {
      this.recordAuthorityStoreFailure("dispatch");
      if (error instanceof UniversalBrokerError) throw error;
      throw new UniversalBrokerError(
        "AUTHORITY_STORE_UNAVAILABLE",
        "The durable DISPATCHED barrier could not be written; provider dispatch was not attempted.",
        { evidence: { persistenceError: error instanceof Error ? error.name : "UNKNOWN_ERROR" } },
      );
    }
    if (!dispatchedLease) {
      throw new UniversalBrokerError(
        "AUTHORITY_STATE_UNCERTAIN",
        "The claim could not cross the durable DISPATCHED barrier with its current fencing token.",
      );
    }
    grant.leaseExpiresAtMs = dispatchedLease.expiresAtMs;
    grant.dispatchedAtMs = dispatchedAtMs;
    this.updateReceipt(grant, (receipt) => ({
      ...receipt,
      dispatchedAtMs,
      state: "DISPATCHED",
      result: "DISPATCHED",
    }));
    this.recordAuthorityClaimMetric(grant.risk, "DISPATCHED");
    this.recordResourceLeaseEvent("dispatched");
  }

  heartbeatResourceLease(grant: AuthorityGrant): DurableResourceLeaseHeartbeat {
    const heartbeatAtMs = this.now();
    let heartbeat: DurableResourceLeaseHeartbeat | undefined;
    try {
      heartbeat = this.requireStore().heartbeatResourceLease({
        authorityId: grant.authorityId,
        actionClaimId: grant.actionClaimId,
        resourceKeySha256: grant.resourceKeySha256,
        fencingToken: grant.fencingToken,
        heartbeatAtMs,
      });
    } catch (error) {
      this.recordAuthorityStoreFailure("heartbeat");
      throw new UniversalBrokerError(
        "AUTHORITY_STORE_UNAVAILABLE",
        "The durable resource lease heartbeat could not be written.",
        { evidence: { persistenceError: error instanceof Error ? error.name : "UNKNOWN_ERROR" } },
      );
    }
    if (!heartbeat) {
      throw new UniversalBrokerError(
        "AUTHORITY_STATE_UNCERTAIN",
        "The resource lease is no longer ACTIVE for this owner and fencing token.",
      );
    }
    grant.leaseExpiresAtMs = heartbeat.expiresAtMs;
    this.recordResourceLeaseEvent("heartbeat");
    return heartbeat;
  }

  cancelNotDispatched(grant: AuthorityGrant, proof: ProvenNotDispatched): AuthorityCompletionReceipt {
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
      this.recordAuthorityStoreFailure("cancel");
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
    this.recordAuthorityClaimMetric(grant.risk, "CANCELLED_NOT_DISPATCHED");
    this.recordResourceLeaseEvent("released");
    return this.completionReceipt(grant);
  }

  record(
    grant: AuthorityGrant | undefined,
    result: "PASS" | "FAIL" | "UNCERTAIN",
    evidence?: Record<string, unknown>,
  ): AuthorityCompletionReceipt | undefined {
    if (!grant) return undefined;
    const receipt = this.findReceipt(grant);
    if (!receipt || receipt.state === "CLAIMED") this.markDispatched(grant);
    return this.completeClaim(grant, result, evidence);
  }

  completeClaim(
    grant: AuthorityGrant,
    result: "PASS" | "FAIL" | "UNCERTAIN",
    evidence?: Record<string, unknown>,
  ): AuthorityCompletionReceipt {
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
      this.recordAuthorityStoreFailure("complete");
      const sealed = this.trySealUncertain(grant, completedAtMs, "RECEIPT_WRITE_FAILED");
      if (sealed) {
        this.updateReceipt(grant, (receipt) => ({
          ...receipt,
          completedAtMs,
          state: "UNCERTAIN",
          result: "UNCERTAIN",
          leaseState: "RECOVERY_REQUIRED",
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
      leaseState: result === "UNCERTAIN" ? "RECOVERY_REQUIRED" : "RELEASED",
      providerCallCount: 1,
      ...(boundedEvidence ? { evidence: boundedEvidence } : {}),
    }));
    this.recordAuthorityClaimMetric(grant.risk, result);
    this.recordResourceLeaseEvent(result === "UNCERTAIN" ? "recovery_required" : "released");
    return this.completionReceipt(grant);
  }

  recordReceiptAuditResult(input: AuthorityReceiptAuditResultInput): AuthorityCompletionReceipt | undefined {
    const authorityId = requiredText(input.authorityId, "authorityId is required.", 256);
    const actionClaimId = requiredText(input.actionClaimId, "actionClaimId is required.", 256);
    const receiptDigest = requiredSha256Digest(input.receiptDigest, "receiptDigest");
    if (input.status !== "RECORDED" && input.status !== "SINK_FAILED") {
      throw new UniversalBrokerError("PRECONDITION_FAILED", "Receipt audit status is invalid.");
    }
    const auditEventDigest = input.status === "RECORDED"
      ? requiredSha256Digest(input.auditEventDigest, "auditEventDigest")
      : undefined;
    const errorCode = input.status === "SINK_FAILED"
      ? safeAuthorityCode(input.errorCode) ?? "AUDIT_SINK_FAILED"
      : undefined;
    let recorded: ReturnType<DurableAuthorityStore["recordClaimAuditResult"]>;
    try {
      recorded = this.requireStore().recordClaimAuditResult({
        authorityId,
        actionClaimId,
        receiptDigest,
        status: input.status,
        ...(auditEventDigest ? { auditEventDigest } : {}),
        ...(errorCode ? { errorCode } : {}),
        recordedAtMs: this.now(),
      });
    } catch (error) {
      this.recordAuthorityStoreFailure("audit");
      throw new UniversalBrokerError(
        "AUTHORITY_STATE_UNCERTAIN",
        "The audit cross-reference could not be durably attached to the authority receipt.",
        {
          evidence: {
            authorityId,
            persistenceError: error instanceof Error ? error.name : "UNKNOWN_ERROR",
          },
        },
      );
    }
    if (!recorded.ok) {
      throw new UniversalBrokerError(
        recorded.code,
        recorded.code === "PRECONDITION_FAILED"
          ? "The audit cross-reference request is invalid."
          : "The authority receipt already has a different audit cross-reference.",
        { evidence: { authorityId, actionClaimId } },
      );
    }
    this.updateReceiptByClaim(authorityId, actionClaimId, (receipt) => ({
      ...receipt,
      auditState: recorded.auditState,
      ...(recorded.auditEventDigest ? { auditEventDigest: recorded.auditEventDigest } : {}),
      auditReceiptDigest: receiptDigest,
      auditRecordedAtMs: recorded.auditRecordedAtMs,
      ...(errorCode ? { auditErrorCode: errorCode } : {}),
    }));
    const authority = this.authorities.get(authorityId);
    const receipt = authority?.receipts.find((candidate) => candidate.actionClaimId === actionClaimId);
    return authority && receipt
      ? this.presentCompletionReceipt(authority, receipt)
      : undefined;
  }

  reconcileResourceLease(input: ResourceLeaseReconciliationInput): Record<string, unknown> {
    const principalKeyFingerprint = requiredPrincipalFingerprint(input.principalKeyFingerprint);
    if (!/^[a-f0-9]{64}$/u.test(input.resourceKeySha256)) {
      throw new UniversalBrokerError("PRECONDITION_FAILED", "resourceKeySha256 is invalid.");
    }
    if (!/^[a-f0-9]{64}$/u.test(input.evidenceDigest) || /^0{64}$/u.test(input.evidenceDigest)) {
      throw new UniversalBrokerError("PRECONDITION_FAILED", "A non-zero reconciliation evidence digest is required.");
    }
    if (!Number.isSafeInteger(input.fencingToken) || input.fencingToken < 1) {
      throw new UniversalBrokerError("PRECONDITION_FAILED", "fencingToken is invalid.");
    }
    const reconciledAtMs = this.now();
    let result: ReturnType<DurableAuthorityStore["reconcileResourceLease"]>;
    try {
      result = this.requireStore().reconcileResourceLease({
        principalKeyFingerprint,
        resourceKeySha256: input.resourceKeySha256,
        actionClaimId: requiredText(input.actionClaimId, "actionClaimId is required.", 256),
        fencingToken: input.fencingToken,
        outcome: input.outcome,
        evidenceDigest: input.evidenceDigest,
        reconciledAtMs,
      });
    } catch (error) {
      this.recordAuthorityStoreFailure("reconcile");
      throw new UniversalBrokerError(
        "AUTHORITY_STORE_UNAVAILABLE",
        "The resource reconciliation receipt could not be committed.",
        { evidence: { persistenceError: error instanceof Error ? error.name : "UNKNOWN_ERROR" } },
      );
    }
    if (!result.ok) {
      if (result.code === "AUTHORITY_PRINCIPAL_MISMATCH") {
        throw new UniversalBrokerError(
          "AUTHORITY_PRINCIPAL_MISMATCH",
          "The resource lease belongs to a different stable principal.",
        );
      }
      throw new UniversalBrokerError(
        result.code === "PRECONDITION_FAILED" ? "PRECONDITION_FAILED" : "AUTHORITY_STATE_UNCERTAIN",
        result.code === "PRECONDITION_FAILED"
          ? "Resource reconciliation evidence is invalid."
          : "The resource lease is not awaiting reconciliation for this fencing token.",
      );
    }
    for (const authority of this.authorities.values()) {
      const receipt = authority.receipts.find((candidate) => (
        candidate.actionClaimId === input.actionClaimId
        && candidate.resourceKeySha256 === input.resourceKeySha256
        && candidate.fencingToken === input.fencingToken
      ));
      if (receipt) receipt.leaseState = "RELEASED";
    }
    this.recordResourceLeaseEvent("reconciled");
    return {
      released: true,
      resourceKeySha256: input.resourceKeySha256,
      fencingToken: result.fencingToken,
      outcome: input.outcome,
      evidenceDigest: input.evidenceDigest,
      reconciledAt: new Date(result.releasedAtMs).toISOString(),
    };
  }

  /**
   * Specialized cross-store recovery for connector activation only. The caller
   * must first prove the exact OAuth activation-authority receipt; this method
   * atomically changes the matching UNCERTAIN claim and frozen lease to PASS.
   */
  terminalizeRecoveredConnectorActivationClaimPass(
    input: RecoveredConnectorActivationPassInput,
  ): RecoveredConnectorActivationAuthorityReceipt {
    const principalKeyFingerprint = requiredPrincipalFingerprint(input.principalKeyFingerprint);
    const authorityId = requiredText(input.authorityId, "authorityId is required.", 256);
    const actionClaimId = requiredText(input.actionClaimId, "actionClaimId is required.", 256);
    if (!/^[a-f0-9]{64}$/u.test(input.actionFingerprint)) {
      throw new UniversalBrokerError("PRECONDITION_FAILED", "actionFingerprint is invalid.");
    }
    if (!/^[a-f0-9]{64}$/u.test(input.resourceKeySha256)) {
      throw new UniversalBrokerError("PRECONDITION_FAILED", "resourceKeySha256 is invalid.");
    }
    if (!Number.isSafeInteger(input.fencingToken) || input.fencingToken < 1) {
      throw new UniversalBrokerError("PRECONDITION_FAILED", "fencingToken is invalid.");
    }
    const oauthProofDigest = requiredSha256Digest(input.oauthProofDigest, "oauthProofDigest");
    const evidenceDigest = requiredSha256Digest(input.evidenceDigest, "evidenceDigest");
    const recoveredAtMs = this.now();
    const reconciliationEvidenceSha256 = sha256(stableJson({
      schemaVersion: 1,
      operation: CONNECTOR_ACTIVATION_OPERATION,
      principalKeyFingerprint,
      authorityId,
      actionClaimId,
      actionFingerprint: input.actionFingerprint,
      resourceKeySha256: input.resourceKeySha256,
      fencingToken: input.fencingToken,
      oauthProofDigest,
      evidenceDigest,
      outcome: "PASS",
    }));
    let result: ReturnType<DurableAuthorityStore["terminalizeRecoveredConnectorActivationPass"]>;
    try {
      result = this.requireStore().terminalizeRecoveredConnectorActivationPass({
        principalKeyFingerprint,
        authorityId,
        actionClaimId,
        actionFingerprint: input.actionFingerprint,
        resourceKeySha256: input.resourceKeySha256,
        fencingToken: input.fencingToken,
        oauthProofDigest,
        reconciliationEvidenceSha256,
        recoveredAtMs,
      });
    } catch (error) {
      this.recordAuthorityStoreFailure("reconcile");
      throw new UniversalBrokerError(
        "AUTHORITY_STORE_UNAVAILABLE",
        "The recovered connector activation receipt could not be atomically terminalized.",
        { evidence: { persistenceError: error instanceof Error ? error.name : "UNKNOWN_ERROR" } },
      );
    }
    if (!result.ok) {
      const code = result.code === "AUTHORITY_PRINCIPAL_MISMATCH"
        ? "AUTHORITY_PRINCIPAL_MISMATCH"
        : result.code === "AUTHORITY_ACTION_MISMATCH"
          ? "AUTHORITY_ACTION_MISMATCH"
          : result.code === "PRECONDITION_FAILED"
            ? "PRECONDITION_FAILED"
            : "AUTHORITY_STATE_UNCERTAIN";
      throw new UniversalBrokerError(
        code,
        code === "AUTHORITY_PRINCIPAL_MISMATCH"
          ? "The recovered connector activation belongs to a different stable principal."
          : code === "AUTHORITY_ACTION_MISMATCH"
            ? "The recovered claim is not the exact internal connector activation action."
            : code === "PRECONDITION_FAILED"
              ? "Recovered connector activation evidence is invalid."
              : "The connector activation claim is not awaiting exact OAuth receipt recovery.",
      );
    }
    const durable = this.requireStore().load().authorities.find(
      (candidate) => candidate.authorityId === authorityId,
    );
    if (!durable) {
      throw new UniversalBrokerError(
        "AUTHORITY_STATE_UNCERTAIN",
        "The recovered connector activation authority could not be read back.",
      );
    }
    const refreshed = this.fromDurable(durable);
    this.authorities.set(authorityId, refreshed);
    const receipt = refreshed.receipts.find((candidate) => candidate.actionClaimId === actionClaimId);
    if (!receipt
      || receipt.state !== "PASS"
      || receipt.result !== "PASS"
      || receipt.leaseState !== "RELEASED"
      || receipt.actionFingerprint !== input.actionFingerprint
      || receipt.resourceKeySha256 !== input.resourceKeySha256
      || receipt.fencingToken !== input.fencingToken) {
      throw new UniversalBrokerError(
        "AUTHORITY_STATE_UNCERTAIN",
        "Recovered connector activation PASS readback is incomplete.",
      );
    }
    this.recordAuthorityClaimMetric("R3", "PASS");
    this.recordResourceLeaseEvent("reconciled");
    return {
      ...this.presentCompletionReceipt(refreshed, receipt),
      recovered: true,
      oauthProofDigest,
      reconciliationEvidenceDigest: `sha256:${result.reconciliationEvidenceSha256}`,
    };
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
      this.recordAuthorityStoreFailure("invalidate");
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
      this.recordAuthorityStoreFailure("release");
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
    return this.statsSnapshot();
  }

  /** Side-effect-free observation for readiness and other pure management probes. */
  readOnlyStats(): Record<string, unknown> {
    return this.statsSnapshot();
  }

  private statsSnapshot(): Record<string, unknown> {
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
    for (const stop of [...this.activeLeaseHeartbeatStops]) stop();
    this.store?.close(this.now());
    releaseAuthorityInstance(this.instanceId);
  }

  startAutomaticLeaseHeartbeat(heartbeat: () => void): () => void {
    if (this.closed) {
      throw new UniversalBrokerError(
        "AUTHORITY_STORE_UNAVAILABLE",
        "The authority registry is closed; a resource lease heartbeat cannot be scheduled.",
      );
    }
    let stopped = false;
    let cancelScheduled: (() => void) | undefined;
    const stop = () => {
      if (stopped) return;
      stopped = true;
      cancelScheduled?.();
      this.activeLeaseHeartbeatStops.delete(stop);
    };
    cancelScheduled = this.leaseHeartbeatScheduler(() => {
      if (stopped || this.closed) return;
      try {
        heartbeat();
      } catch {
        // The synchronous heartbeat path records the bounded store failure metric.
        // A later tick may recover; owner death + expiry + grace still prevents takeover.
      }
    }, this.resourceLeaseHeartbeatMs);
    this.activeLeaseHeartbeatStops.add(stop);
    return stop;
  }

  private requireStore(): DurableAuthorityStore {
    if (this.store) return this.store;
    throw this.storeFailure ?? new UniversalBrokerError(
      "AUTHORITY_STORE_UNAVAILABLE",
      "The durable authority store is unavailable.",
    );
  }

  private recordAuthorityCheckMetric(risk: AuthorityRiskClass, result: "pass" | "fail"): void {
    this.recordMetric((metrics) => metrics.recordAuthorityCheck(risk, result));
  }

  private recordAuthorityClaimMetric(risk: AuthorityRiskClass, state: DurableActionClaimState): void {
    this.recordMetric((metrics) => metrics.recordAuthorityClaim(risk, state));
  }

  private recordAuthorityStoreFailure(operation: string): void {
    this.recordMetric((metrics) => metrics.recordAuthorityStoreFailure(operation));
  }

  private recordResourceLeaseEvent(event: string): void {
    this.recordMetric((metrics) => metrics.recordResourceLeaseEvent(event));
  }

  private recordQuotaRejection(resourceKind: string): void {
    this.recordMetric((metrics) => metrics.recordQuotaRejection(resourceKind));
  }

  private recordMetric(update: (metrics: UniversalBrokerMetrics) => void): void {
    if (!this.metrics) return;
    try {
      update(this.metrics);
    } catch {
      // Observability must never replace authority semantics.
    }
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

  private updateReceiptByClaim(
    authorityId: string,
    actionClaimId: string,
    update: (receipt: AuthorityReceipt) => AuthorityReceipt,
  ): void {
    const authority = this.authorities.get(authorityId);
    if (!authority) return;
    const index = authority.receipts.findIndex(
      (receipt) => receipt.actionClaimId === actionClaimId,
    );
    if (index < 0) return;
    authority.receipts = trimReceipts([
      ...authority.receipts.slice(0, index),
      update(authority.receipts[index]!),
      ...authority.receipts.slice(index + 1),
    ]);
  }

  private completionReceipt(grant: AuthorityGrant): AuthorityCompletionReceipt {
    let authority = this.authorities.get(grant.authorityId);
    if (!authority) {
      const durable = this.requireStore().load().authorities.find(
        (candidate) => candidate.authorityId === grant.authorityId,
      );
      authority = durable ? this.fromDurable(durable) : undefined;
    }
    const receipt = authority?.receipts.find(
      (candidate) => candidate.actionClaimId === grant.actionClaimId,
    );
    if (!authority || !receipt) {
      throw new UniversalBrokerError(
        "AUTHORITY_STATE_UNCERTAIN",
        "The authority receipt could not be read back after completion.",
      );
    }
    return this.presentCompletionReceipt(authority, receipt);
  }

  private presentCompletionReceipt(
    authority: StoredOperationAuthority,
    receipt: AuthorityReceipt,
  ): AuthorityCompletionReceipt {
    return {
      actionClaimId: receipt.actionClaimId,
      useId: receipt.useId,
      receiptDigest: authorityReceiptDigest(authority, receipt),
      state: receipt.state,
      result: receipt.result,
      leaseState: receipt.leaseState,
      ...(receipt.completedAtMs === undefined
        ? {}
        : { completedAt: new Date(receipt.completedAtMs).toISOString() }),
      ...(receipt.auditState ? { auditState: receipt.auditState } : {}),
      ...(receipt.auditEventDigest ? { auditEventDigest: receipt.auditEventDigest } : {}),
      ...(receipt.auditRecordedAtMs === undefined
        ? {}
        : { auditRecordedAt: new Date(receipt.auditRecordedAtMs).toISOString() }),
      ...(receipt.auditErrorCode ? { auditErrorCode: receipt.auditErrorCode } : {}),
    };
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
    allowConnectorActivation = false,
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
    const connectorActivation = allowConnectorActivation
      && isConnectorActivationAuthorityDescriptor(descriptor);
    if (!operations.includes(descriptor.operation) && !connectorActivation) {
      throw new UniversalBrokerError(
        "PRECONDITION_FAILED",
        `Authority action ${index} uses unsupported operation ${descriptor.tool}.${descriptor.operation}.`,
      );
    }
    const minimumRisk = connectorActivation ? "R3" : this.minimumRisk(descriptor);
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
        receiptDigest: authorityReceiptDigest(authority, receipt),
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
        ...(receipt.auditState ? { auditState: receipt.auditState } : {}),
        ...(receipt.auditEventDigest ? { auditEventDigest: receipt.auditEventDigest } : {}),
        ...(receipt.auditRecordedAtMs === undefined
          ? {}
          : { auditRecordedAt: new Date(receipt.auditRecordedAtMs).toISOString() }),
        ...(receipt.auditErrorCode ? { auditErrorCode: receipt.auditErrorCode } : {}),
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
      this.recordAuthorityStoreFailure("task");
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
          ...(receipt.auditState ? { auditState: receipt.auditState } : {}),
          ...(receipt.auditEventDigest ? { auditEventDigest: receipt.auditEventDigest } : {}),
          ...(receipt.auditReceiptDigest ? { auditReceiptDigest: receipt.auditReceiptDigest } : {}),
          ...(receipt.auditRecordedAtMs === undefined ? {} : { auditRecordedAtMs: receipt.auditRecordedAtMs }),
          ...(receipt.auditErrorCode ? { auditErrorCode: receipt.auditErrorCode } : {}),
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
        ...(receipt.auditState ? { auditState: receipt.auditState } : {}),
        ...(receipt.auditEventDigest ? { auditEventDigest: receipt.auditEventDigest } : {}),
        ...(receipt.auditReceiptDigest ? { auditReceiptDigest: receipt.auditReceiptDigest } : {}),
        ...(receipt.auditRecordedAtMs === undefined ? {} : { auditRecordedAtMs: receipt.auditRecordedAtMs }),
        ...(receipt.auditErrorCode ? { auditErrorCode: receipt.auditErrorCode } : {}),
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

function authorityReceiptDigest(
  authority: StoredOperationAuthority,
  receipt: AuthorityReceipt,
): string {
  return `sha256:${sha256(stableJson({
    schemaVersion: 1,
    authorityId: authority.authorityId,
    actionClaimId: receipt.actionClaimId,
    useId: receipt.useId,
    actionId: persistentActionKey(receipt.actionFingerprint),
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
    ...(receipt.providerCallCount === undefined ? {} : { providerCallCount: receipt.providerCallCount }),
    ...(typeof receipt.evidence?.errorCode === "string"
      ? { errorCode: receipt.evidence.errorCode }
      : {}),
    ...(typeof receipt.evidence?.reasonCode === "string"
      ? { reasonCode: receipt.evidence.reasonCode }
      : {}),
  }))}`;
}

export function authorityRiskAtLeast(actual: AuthorityRiskClass, required: AuthorityRiskClass): boolean {
  return riskRank(actual) >= riskRank(required);
}

const CONNECTOR_ACTIVATION_OPERATION = "connector_activation_finalize";
const CONNECTOR_ACTIVATION_PARAMETER_KEYS = [
  "activePreimageDigest",
  "canonicalName",
  "finalizationPlanDigest",
  "receiptId",
  "tupleDigest",
] as const;
const SHA256_DIGEST_PATTERN = /^sha256:[a-f0-9]{64}$/u;
const CONNECTOR_CANONICAL_NAME_PATTERN = /^[A-Za-z][A-Za-z0-9._-]{0,127}$/u;

function assertConnectorActivationAuthorityDescriptor(action: AuthorityActionDescriptor): void {
  if (!isConnectorActivationAuthorityDescriptor(action)) {
    throw new UniversalBrokerError(
      "PRECONDITION_FAILED",
      "Connector activation authority requires the exact internal R3 activation descriptor.",
    );
  }
}

function isConnectorActivationAuthorityDescriptor(action: AuthorityActionDescriptor): boolean {
  if (
    action.tool !== "context"
    || action.operation !== CONNECTOR_ACTIVATION_OPERATION
    || typeof action.target !== "string"
    || !CONNECTOR_CANONICAL_NAME_PATTERN.test(action.target)
    || action.resource !== `connector:${action.target}`
    || !action.parameters
  ) {
    return false;
  }
  const keys = Object.keys(action.parameters).sort();
  if (
    keys.length !== CONNECTOR_ACTIVATION_PARAMETER_KEYS.length
    || keys.some((key, index) => key !== CONNECTOR_ACTIVATION_PARAMETER_KEYS[index])
    || action.parameters.canonicalName !== action.target
    || typeof action.parameters.receiptId !== "string"
    || action.parameters.receiptId.length < 1
    || action.parameters.receiptId.length > 256
  ) {
    return false;
  }
  return [
    action.parameters.tupleDigest,
    action.parameters.activePreimageDigest,
    action.parameters.finalizationPlanDigest,
  ].every((value) => typeof value === "string" && SHA256_DIGEST_PATTERN.test(value));
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
        .sort(([left], [right]) => left < right ? -1 : left > right ? 1 : 0)
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

function boundedLeaseInterval(
  value: number,
  name: string,
  allowZero = false,
): number {
  if (
    !Number.isSafeInteger(value)
    || value < (allowZero ? 0 : 1)
    || value > MAXIMUM_RESOURCE_LEASE_INTERVAL_MS
  ) {
    throw new Error(`${name} must be a bounded ${allowZero ? "non-negative" : "positive"} safe integer.`);
  }
  return value;
}

function defaultAuthorityLeaseHeartbeatScheduler(
  callback: () => void,
  intervalMs: number,
): () => void {
  const timer = setInterval(callback, intervalMs);
  timer.unref();
  return () => clearInterval(timer);
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

function requiredSha256Digest(value: string | undefined, name: string): string {
  const normalized = value?.trim().toLowerCase();
  if (!normalized || !/^sha256:[a-f0-9]{64}$/u.test(normalized)) {
    throw new UniversalBrokerError("PRECONDITION_FAILED", `${name} must be a SHA-256 digest.`);
  }
  return normalized;
}

function safeAuthorityCode(value: string | undefined): string | undefined {
  if (!value) return undefined;
  return /^[A-Z][A-Z0-9_.:-]{0,127}$/u.test(value) ? value : undefined;
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
