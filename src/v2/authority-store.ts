import { createHash, randomUUID } from "node:crypto";
import { execFileSync } from "node:child_process";
import { chmodSync, mkdirSync, readFileSync } from "node:fs";
import { hostname, platform } from "node:os";
import { dirname } from "node:path";
import Database from "better-sqlite3";

export type DurableActionClaimState =
  | "CLAIMED"
  | "DISPATCHED"
  | "PASS"
  | "FAIL"
  | "UNCERTAIN"
  | "CANCELLED_NOT_DISPATCHED";

export type DurableAuthorityReceiptAuditState =
  | "RECORDED"
  | "SINK_FAILED";

export type DurableResourceLeaseState =
  | "ACTIVE"
  | "RELEASED"
  | "EXPIRED"
  | "RECOVERY_REQUIRED";

export type DurableResourceReconciliationOutcome =
  | "RESOURCE_VERIFIED"
  | "RESOURCE_QUARANTINED";

export interface DurableResourceLeaseHeartbeat {
  resourceKeySha256: string;
  actionClaimId: string;
  fencingToken: number;
  heartbeatAtMs: number;
  expiresAtMs: number;
}

export type DurableResourceLeaseReconciliationResult =
  | { ok: true; fencingToken: number; releasedAtMs: number }
  | {
      ok: false;
      code:
        | "AUTHORITY_PRINCIPAL_MISMATCH"
        | "AUTHORITY_STATE_UNCERTAIN"
        | "PRECONDITION_FAILED";
    };

export type DurableRecoveredConnectorActivationResult =
  | {
      ok: true;
      fencingToken: number;
      recoveredAtMs: number;
      reconciliationEvidenceSha256: string;
    }
  | {
      ok: false;
      code:
        | "AUTHORITY_PRINCIPAL_MISMATCH"
        | "AUTHORITY_ACTION_MISMATCH"
        | "AUTHORITY_STATE_UNCERTAIN"
        | "PRECONDITION_FAILED";
    };

export interface DurableAuthorityTaskRecord {
  taskInstanceId: string;
  principalKeyFingerprint: string;
  taskLabelSha256?: string;
  correctionEpoch: number;
  createdAtMs: number;
  updatedAtMs: number;
}

export interface DurableAuthorityActionRecord {
  id: string;
  tool: string;
  operation: string;
  fingerprint: string;
  resourceKeySha256: string;
  minimumRisk: string;
  risk: string;
  maximumUses: number;
  consumedUses: number;
}

export interface DurableAuthorityReceiptRecord {
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
  errorCode?: string;
  reasonCode?: string;
  cancellationProofCode?: string;
  auditState?: DurableAuthorityReceiptAuditState;
  auditEventDigest?: string;
  auditReceiptDigest?: string;
  auditRecordedAtMs?: number;
  auditErrorCode?: string;
}

export interface DurableAuthorityRecord {
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
  actions: DurableAuthorityActionRecord[];
  receipts: DurableAuthorityReceiptRecord[];
}

export interface DurableAuthoritySnapshot {
  tasks: DurableAuthorityTaskRecord[];
  authorities: DurableAuthorityRecord[];
  recoveredPendingUses: number;
}

export type DurableAuthorityClaimResult =
  | {
      ok: true;
      consumedUses: number;
      actionClaimId: string;
      resourceKeySha256: string;
      fencingToken: number;
      leaseExpiresAtMs: number;
    }
  | {
      ok: false;
      code:
        | "AUTHORITY_EXPIRED"
        | "AUTHORITY_PRINCIPAL_MISMATCH"
        | "AUTHORITY_ACTION_MISMATCH"
        | "AUTHORITY_STALE"
        | "AUTHORITY_CONSUMED"
        | "RESOURCE_BUSY"
        | "RESOURCE_QUOTA_EXCEEDED";
      consumedUses?: number;
      activeClaimId?: string;
    };

export type DurableAuthorityReservationResult = DurableAuthorityClaimResult;

export type DurableAuthorityReleaseResult =
  | { ok: true }
  | {
      ok: false;
      code:
        | "AUTHORITY_EXPIRED"
        | "AUTHORITY_PRINCIPAL_MISMATCH"
        | "AUTHORITY_STALE"
        | "PRECONDITION_FAILED";
      pendingReceipts?: number;
    };

export type DurableAuthorityReceiptAuditResult =
  | {
      ok: true;
      auditState: DurableAuthorityReceiptAuditState;
      auditEventDigest?: string;
      auditRecordedAtMs: number;
    }
  | { ok: false; code: "AUTHORITY_STATE_UNCERTAIN" | "PRECONDITION_FAILED" };

export type DurableTaskCorrectionResult =
  | { ok: true; correctionEpoch: number; authorityIds: string[] }
  | { ok: false; code: "AUTHORITY_PRINCIPAL_MISMATCH" | "AUTHORITY_STALE" };

interface TaskRow {
  task_instance_id: string;
  principal_key_fingerprint: string;
  task_label_sha256: string | null;
  correction_epoch: number;
  created_at_ms: number;
  updated_at_ms: number;
}

interface AuthorityRow {
  authority_id: string;
  task_instance_id: string;
  task_label_sha256: string | null;
  authority_text_sha256: string;
  principal_key_fingerprint: string;
  approval_assurance: "cooperative";
  correction_epoch: number;
  created_at_ms: number;
  expires_at_ms: number;
  fingerprint: string;
}

interface ActionRow {
  authority_id: string;
  action_id: string;
  tool: string;
  operation: string;
  fingerprint: string;
  resource_key_sha256: string;
  minimum_risk: string;
  risk: string;
  maximum_uses: number;
  consumed_uses: number;
}

interface ClaimRow {
  authority_id: string;
  action_claim_id: string;
  action_id: string;
  task_instance_id: string;
  principal_key_fingerprint: string;
  action_fingerprint: string;
  resource_key_sha256: string;
  fencing_token: number;
  claimed_at_ms: number;
  dispatched_at_ms: number | null;
  completed_at_ms: number | null;
  state: DurableActionClaimState;
  owner_instance_id: string;
  provider_call_count: number | null;
  error_code: string | null;
  reason_code: string | null;
  cancellation_proof_code: string | null;
  audit_state: DurableAuthorityReceiptAuditState | null;
  audit_event_digest: string | null;
  audit_receipt_digest: string | null;
  audit_recorded_at_ms: number | null;
  audit_error_code: string | null;
}

interface LeaseRow {
  resource_key_sha256: string;
  action_claim_id: string;
  fencing_token: number;
  lease_state: DurableResourceLeaseState;
  owner_instance_id: string;
  acquired_at_ms: number;
  heartbeat_at_ms: number;
  expires_at_ms: number;
  updated_at_ms: number;
  reconciliation_state: "NOT_REQUIRED" | "PENDING" | "VERIFIED" | "FAILED";
  reconciliation_outcome: DurableResourceReconciliationOutcome | null;
  reconciliation_evidence_sha256: string | null;
  reconciled_at_ms: number | null;
  recovery_reason: string | null;
}

interface OwnerRunRow {
  owner_run_id: string;
  host_identity_sha256: string;
  process_id: number;
  process_start_key_sha256: string;
  run_state: "ACTIVE" | "CLOSED";
  registered_at_ms: number;
  heartbeat_at_ms: number;
  lease_deadline_ms: number;
  closed_at_ms: number | null;
}

interface MigrationBackup {
  path: string;
  sha256: string;
  sourceIntegrityCheck: string;
  backupIntegrityCheck: string;
}

interface LegacyV3ActionRow {
  authority_id: string;
  action_id: string;
  ordinal: number;
  tool: string;
  operation: string;
  fingerprint: string;
  minimum_risk: string;
  risk: string;
  maximum_uses: number;
  consumed_uses: number;
}

interface LegacyV3ReceiptRow {
  authority_id: string;
  use_id: string;
  action_id: string;
  reserved_at_ms: number;
  completed_at_ms: number | null;
  result: "PENDING" | "PASS" | "FAIL" | "UNCERTAIN";
  error_code: string | null;
  reason_code: string | null;
  owner_instance_id: string;
  task_instance_id: string;
  principal_key_fingerprint: string;
  action_fingerprint: string;
}

const SCHEMA_VERSION = 7;
const HASH_PATTERN = /^[a-f0-9]{64}$/u;
const SHA256_DIGEST_PATTERN = /^sha256:[a-f0-9]{64}$/u;
const DEFAULT_RESOURCE_LEASE_TTL_MS = 15 * 60_000;
const DEFAULT_RESOURCE_LEASE_RECOVERY_GRACE_MS = 60_000;
const DEFAULT_OWNER_RUN_LEASE_MS = 90_000;
const MAXIMUM_RESOURCE_LEASE_TTL_MS = 8 * 60 * 60_000;
const MAXIMUM_RESOURCE_LEASE_RECOVERY_GRACE_MS = 24 * 60 * 60_000;
const MAXIMUM_OWNER_RUN_LEASE_MS = 24 * 60 * 60_000;
const HOST_IDENTITY_SHA256 = createHash("sha256")
  .update(`${platform()}\0${hostname()}`)
  .digest("hex");

export class DurableAuthorityStore {
  private readonly sqlite: Database.Database;
  private readonly instanceId: string;
  private readonly resourceLeaseTtlMs: number;
  private readonly resourceLeaseRecoveryGraceMs: number;
  private readonly ownerRunLeaseMs: number;
  private recoveredPendingUses: number;

  constructor(
    path: string | undefined,
    nowMs: number,
    instanceId = `authority_run_${randomUUID()}`,
    _activeOwnerInstanceIds: readonly string[] = [instanceId],
    resourceLeaseTtlMs = DEFAULT_RESOURCE_LEASE_TTL_MS,
    resourceLeaseRecoveryGraceMs = DEFAULT_RESOURCE_LEASE_RECOVERY_GRACE_MS,
    ownerRunLeaseMs = DEFAULT_OWNER_RUN_LEASE_MS,
  ) {
    this.instanceId = instanceId;
    if (
      !Number.isSafeInteger(resourceLeaseTtlMs)
      || resourceLeaseTtlMs < 1
      || resourceLeaseTtlMs > MAXIMUM_RESOURCE_LEASE_TTL_MS
    ) {
      throw new Error("resourceLeaseTtlMs must be a positive bounded safe integer.");
    }
    this.resourceLeaseTtlMs = resourceLeaseTtlMs;
    if (
      !Number.isSafeInteger(resourceLeaseRecoveryGraceMs)
      || resourceLeaseRecoveryGraceMs < 0
      || resourceLeaseRecoveryGraceMs > MAXIMUM_RESOURCE_LEASE_RECOVERY_GRACE_MS
    ) {
      throw new Error("resourceLeaseRecoveryGraceMs must be a bounded non-negative safe integer.");
    }
    this.resourceLeaseRecoveryGraceMs = resourceLeaseRecoveryGraceMs;
    if (
      !Number.isSafeInteger(ownerRunLeaseMs)
      || ownerRunLeaseMs < 1
      || ownerRunLeaseMs > MAXIMUM_OWNER_RUN_LEASE_MS
    ) {
      throw new Error("ownerRunLeaseMs must be a positive bounded safe integer.");
    }
    this.ownerRunLeaseMs = ownerRunLeaseMs;
    if (path) mkdirSync(dirname(path), { recursive: true, mode: 0o700 });
    this.sqlite = new Database(path ?? ":memory:");
    if (path) chmodSync(path, 0o600);
    try {
      this.sqlite.pragma("journal_mode = WAL");
      this.sqlite.pragma("synchronous = FULL");
      this.sqlite.pragma("busy_timeout = 5000");
      this.sqlite.pragma("foreign_keys = ON");
      this.initializeSchema(path, nowMs);
      this.registerOwnerRun(nowMs);
      this.recoveredPendingUses = this.recoverNonterminalClaims(nowMs);
    } catch (error) {
      this.sqlite.close();
      throw error;
    }
  }

  load(): DurableAuthoritySnapshot {
    const tasks = (this.sqlite.prepare(
      `select task_instance_id, principal_key_fingerprint, task_label_sha256,
              correction_epoch, created_at_ms, updated_at_ms
         from operation_authority_tasks
        order by created_at_ms, task_instance_id`,
    ).all() as TaskRow[]).map(taskFromRow);
    const authorities = new Map<string, DurableAuthorityRecord>();
    for (const row of this.sqlite.prepare(
      `select authority_id, task_instance_id, task_label_sha256,
              authority_text_sha256, principal_key_fingerprint,
              approval_assurance, correction_epoch, created_at_ms,
              expires_at_ms, fingerprint
         from operation_authorities
        order by created_at_ms, authority_id`,
    ).all() as AuthorityRow[]) {
      authorities.set(row.authority_id, {
        authorityId: row.authority_id,
        taskInstanceId: row.task_instance_id,
        ...(row.task_label_sha256 ? { taskLabelSha256: row.task_label_sha256 } : {}),
        authorityTextSha256: row.authority_text_sha256,
        principalKeyFingerprint: row.principal_key_fingerprint,
        approvalAssurance: row.approval_assurance,
        correctionEpoch: row.correction_epoch,
        createdAtMs: row.created_at_ms,
        expiresAtMs: row.expires_at_ms,
        fingerprint: row.fingerprint,
        actions: [],
        receipts: [],
      });
    }
    for (const row of this.sqlite.prepare(
      `select authority_id, action_id, tool, operation, fingerprint,
              resource_key_sha256, minimum_risk, risk, maximum_uses,
              consumed_uses
         from operation_authority_actions
        order by authority_id, ordinal`,
    ).all() as ActionRow[]) {
      const authority = authorities.get(row.authority_id);
      if (!authority) continue;
      authority.actions.push({
        id: row.action_id,
        tool: row.tool,
        operation: row.operation,
        fingerprint: row.fingerprint,
        resourceKeySha256: row.resource_key_sha256,
        minimumRisk: row.minimum_risk,
        risk: row.risk,
        maximumUses: row.maximum_uses,
        consumedUses: row.consumed_uses,
      });
    }
    const leases = new Map(
      (this.sqlite.prepare(
        `select resource_key_sha256, action_claim_id, fencing_token, lease_state
           from operation_authority_resource_leases`,
      ).all() as LeaseRow[]).map((row) => [row.resource_key_sha256, row]),
    );
    for (const row of this.sqlite.prepare(
      `select authority_id, action_claim_id, action_id, task_instance_id,
              principal_key_fingerprint, action_fingerprint,
              resource_key_sha256, fencing_token, claimed_at_ms,
              dispatched_at_ms, completed_at_ms, state, owner_instance_id,
              provider_call_count, error_code, reason_code,
              cancellation_proof_code, audit_state, audit_event_digest,
              audit_receipt_digest, audit_recorded_at_ms, audit_error_code
         from operation_authority_claims
        order by authority_id, claimed_at_ms, action_claim_id`,
    ).all() as ClaimRow[]) {
      const authority = authorities.get(row.authority_id);
      if (!authority) continue;
      const lease = leases.get(row.resource_key_sha256);
      const leaseState = lease?.action_claim_id === row.action_claim_id
        && lease.fencing_token === row.fencing_token
        ? lease.lease_state
        : row.state === "UNCERTAIN" ? "RECOVERY_REQUIRED" : "RELEASED";
      authority.receipts.push({
        actionClaimId: row.action_claim_id,
        useId: row.action_claim_id,
        actionId: row.action_id,
        taskInstanceId: row.task_instance_id,
        principalKeyFingerprint: row.principal_key_fingerprint,
        actionFingerprint: row.action_fingerprint,
        resourceKeySha256: row.resource_key_sha256,
        fencingToken: row.fencing_token,
        claimedAtMs: row.claimed_at_ms,
        reservedAtMs: row.claimed_at_ms,
        ...(row.dispatched_at_ms === null ? {} : { dispatchedAtMs: row.dispatched_at_ms }),
        ...(row.completed_at_ms === null ? {} : { completedAtMs: row.completed_at_ms }),
        state: row.state,
        result: row.state,
        leaseState,
        ...(row.provider_call_count === null ? {} : { providerCallCount: row.provider_call_count }),
        ...(row.error_code ? { errorCode: row.error_code } : {}),
        ...(row.reason_code ? { reasonCode: row.reason_code } : {}),
        ...(row.cancellation_proof_code
          ? { cancellationProofCode: row.cancellation_proof_code }
          : {}),
        ...(row.audit_state ? { auditState: row.audit_state } : {}),
        ...(row.audit_event_digest ? { auditEventDigest: row.audit_event_digest } : {}),
        ...(row.audit_receipt_digest ? { auditReceiptDigest: row.audit_receipt_digest } : {}),
        ...(row.audit_recorded_at_ms === null ? {} : { auditRecordedAtMs: row.audit_recorded_at_ms }),
        ...(row.audit_error_code ? { auditErrorCode: row.audit_error_code } : {}),
      });
    }
    return {
      tasks,
      authorities: [...authorities.values()],
      recoveredPendingUses: this.recoveredPendingUses,
    };
  }

  saveTask(task: DurableAuthorityTaskRecord): void {
    const persist = this.sqlite.transaction(() => {
      this.sqlite.prepare(
        `insert into operation_authority_tasks (
           task_instance_id, principal_key_fingerprint, task_label_sha256,
           correction_epoch, created_at_ms, updated_at_ms
         ) values (?, ?, ?, ?, ?, ?)
         on conflict(task_instance_id) do nothing`,
      ).run(
        task.taskInstanceId,
        task.principalKeyFingerprint,
        task.taskLabelSha256 ?? null,
        task.correctionEpoch,
        task.createdAtMs,
        task.updatedAtMs,
      );
      const current = this.taskRow(task.taskInstanceId);
      if (
        !current
        || current.principal_key_fingerprint !== task.principalKeyFingerprint
        || current.correction_epoch !== task.correctionEpoch
      ) {
        throw new Error("Refusing to persist a task with mismatched principal or correction epoch.");
      }
    });
    persist.immediate();
  }

  getTask(taskInstanceId: string): DurableAuthorityTaskRecord | undefined {
    const row = this.taskRow(taskInstanceId);
    return row ? taskFromRow(row) : undefined;
  }

  saveAuthority(authority: DurableAuthorityRecord): void {
    const persist = this.sqlite.transaction(() => this.persistAuthority(authority));
    persist.immediate();
  }

  getOrCreateAuthority(
    authority: DurableAuthorityRecord,
    nowMs: number,
  ): { authority: DurableAuthorityRecord; created: boolean } {
    const select = this.sqlite.transaction(() => {
      const existing = this.sqlite.prepare(
        `select authority_id, expires_at_ms
           from operation_authorities
          where principal_key_fingerprint = ? and task_instance_id = ?
            and correction_epoch = ? and fingerprint = ? and grant_active = 1`,
      ).get(
        authority.principalKeyFingerprint,
        authority.taskInstanceId,
        authority.correctionEpoch,
        authority.fingerprint,
      ) as { authority_id: string; expires_at_ms: number } | undefined;
      if (existing) {
        const blocking = (this.sqlite.prepare(
          `select count(*) as count from operation_authority_claims
            where authority_id = ? and state in ('CLAIMED', 'DISPATCHED', 'UNCERTAIN')`,
        ).get(existing.authority_id) as { count: number }).count;
        const remaining = (this.sqlite.prepare(
          `select count(*) as count from operation_authority_actions
            where authority_id = ? and consumed_uses < maximum_uses`,
        ).get(existing.authority_id) as { count: number }).count;
        if (blocking > 0 || (existing.expires_at_ms > nowMs && remaining > 0)) {
          return { authorityId: existing.authority_id, created: false };
        }
        this.sqlite.prepare(
          "update operation_authorities set grant_active = 0 where authority_id = ? and grant_active = 1",
        ).run(existing.authority_id);
      }
      this.persistAuthority(authority);
      return { authorityId: authority.authorityId, created: true };
    });
    const selected = select.immediate();
    const durable = this.load().authorities.find(
      (candidate) => candidate.authorityId === selected.authorityId,
    );
    if (!durable) throw new Error("Atomic authority get-or-create lost its durable grant.");
    return { authority: durable, created: selected.created };
  }

  claimAction(input: {
    authorityId: string;
    principalKeyFingerprint: string;
    taskInstanceId: string;
    correctionEpoch: number;
    actionId: string;
    actionFingerprint: string;
    resourceKeySha256: string;
    actionClaimId: string;
    claimedAtMs: number;
    maximumReceipts: number;
  }): DurableAuthorityClaimResult {
    assertSha256(input.resourceKeySha256, "resourceKeySha256");
    this.recoveredPendingUses += this.recoverNonterminalClaims(input.claimedAtMs);
    const claim = this.sqlite.transaction((): DurableAuthorityClaimResult => {
      this.touchOwnerRun(input.claimedAtMs);
      const authority = this.sqlite.prepare(
        `select task_instance_id, principal_key_fingerprint,
                correction_epoch, expires_at_ms, grant_active
           from operation_authorities where authority_id = ?`,
      ).get(input.authorityId) as {
        task_instance_id: string;
        principal_key_fingerprint: string;
        correction_epoch: number;
        expires_at_ms: number;
        grant_active: number;
      } | undefined;
      if (!authority || authority.grant_active !== 1) {
        return { ok: false, code: "AUTHORITY_EXPIRED" };
      }
      if (authority.principal_key_fingerprint !== input.principalKeyFingerprint) {
        return { ok: false, code: "AUTHORITY_PRINCIPAL_MISMATCH" };
      }
      if (authority.task_instance_id !== input.taskInstanceId) {
        return { ok: false, code: "AUTHORITY_STALE" };
      }
      const task = this.taskRow(input.taskInstanceId);
      if (
        !task
        || task.principal_key_fingerprint !== input.principalKeyFingerprint
        || task.correction_epoch !== input.correctionEpoch
        || authority.correction_epoch !== input.correctionEpoch
      ) {
        return { ok: false, code: "AUTHORITY_STALE" };
      }
      if (authority.expires_at_ms <= input.claimedAtMs) {
        return { ok: false, code: "AUTHORITY_EXPIRED" };
      }
      const nonterminal = this.sqlite.prepare(
        `select count(*) as count from operation_authority_claims
          where authority_id = ? and state in ('CLAIMED', 'DISPATCHED')`,
      ).get(input.authorityId) as { count: number };
      if (nonterminal.count >= input.maximumReceipts) {
        return { ok: false, code: "RESOURCE_QUOTA_EXCEEDED" };
      }
      const action = this.sqlite.prepare(
        `select fingerprint, resource_key_sha256, maximum_uses, consumed_uses
           from operation_authority_actions
          where authority_id = ? and action_id = ?`,
      ).get(input.authorityId, input.actionId) as {
        fingerprint: string;
        resource_key_sha256: string;
        maximum_uses: number;
        consumed_uses: number;
      } | undefined;
      if (
        !action
        || action.fingerprint !== input.actionFingerprint
        || action.resource_key_sha256 !== input.resourceKeySha256
      ) {
        return { ok: false, code: "AUTHORITY_ACTION_MISMATCH" };
      }
      if (action.consumed_uses >= action.maximum_uses) {
        return {
          ok: false,
          code: "AUTHORITY_CONSUMED",
          consumedUses: action.consumed_uses,
        };
      }
      const lease = this.sqlite.prepare(
        `select action_claim_id, lease_state
           from operation_authority_resource_leases
          where resource_key_sha256 = ?`,
      ).get(input.resourceKeySha256) as {
        action_claim_id: string;
        lease_state: DurableResourceLeaseState;
      } | undefined;
      if (lease && lease.lease_state !== "RELEASED") {
        return { ok: false, code: "RESOURCE_BUSY", activeClaimId: lease.action_claim_id };
      }
      const updated = this.sqlite.prepare(
        `update operation_authority_actions
            set consumed_uses = consumed_uses + 1
          where authority_id = ? and action_id = ? and fingerprint = ?
            and resource_key_sha256 = ? and consumed_uses = ?
            and consumed_uses < maximum_uses`,
      ).run(
        input.authorityId,
        input.actionId,
        input.actionFingerprint,
        input.resourceKeySha256,
        action.consumed_uses,
      );
      if (updated.changes !== 1) {
        const current = this.sqlite.prepare(
          `select consumed_uses from operation_authority_actions
            where authority_id = ? and action_id = ?`,
        ).get(input.authorityId, input.actionId) as { consumed_uses: number } | undefined;
        return {
          ok: false,
          code: "AUTHORITY_CONSUMED",
          ...(current ? { consumedUses: current.consumed_uses } : {}),
        };
      }
      const currentFence = this.sqlite.prepare(
        `select last_fencing_token from operation_authority_resource_fences
          where resource_key_sha256 = ?`,
      ).get(input.resourceKeySha256) as { last_fencing_token: number } | undefined;
      const fencingToken = (currentFence?.last_fencing_token ?? 0) + 1;
      this.sqlite.prepare(
        `insert into operation_authority_resource_fences (
           resource_key_sha256, last_fencing_token, updated_at_ms
         ) values (?, ?, ?)
         on conflict(resource_key_sha256) do update set
           last_fencing_token = excluded.last_fencing_token,
           updated_at_ms = excluded.updated_at_ms`,
      ).run(input.resourceKeySha256, fencingToken, input.claimedAtMs);
      this.sqlite.prepare(
        `insert into operation_authority_claims (
           action_claim_id, authority_id, action_id, task_instance_id,
           principal_key_fingerprint, action_fingerprint,
           resource_key_sha256, fencing_token, state, owner_instance_id,
           claimed_at_ms, dispatched_at_ms, completed_at_ms,
           provider_call_count, error_code, reason_code,
           cancellation_proof_code
         ) values (?, ?, ?, ?, ?, ?, ?, ?, 'CLAIMED', ?, ?, null, null,
                   null, null, null, null)`,
      ).run(
        input.actionClaimId,
        input.authorityId,
        input.actionId,
        input.taskInstanceId,
        input.principalKeyFingerprint,
        input.actionFingerprint,
        input.resourceKeySha256,
        fencingToken,
        this.instanceId,
        input.claimedAtMs,
      );
      this.sqlite.prepare(
        `insert into operation_authority_resource_leases (
           resource_key_sha256, task_instance_id,
           principal_key_fingerprint, authority_id, action_id,
           action_claim_id, fencing_token, lease_state, owner_instance_id,
           acquired_at_ms, heartbeat_at_ms, expires_at_ms, updated_at_ms,
           reconciliation_state, reconciliation_outcome,
           reconciliation_evidence_sha256, reconciled_at_ms, recovery_reason
         ) values (?, ?, ?, ?, ?, ?, ?, 'ACTIVE', ?, ?, ?, ?, ?,
                   'NOT_REQUIRED', null, null, null, null)
         on conflict(resource_key_sha256) do update set
           task_instance_id = excluded.task_instance_id,
           principal_key_fingerprint = excluded.principal_key_fingerprint,
           authority_id = excluded.authority_id,
           action_id = excluded.action_id,
           action_claim_id = excluded.action_claim_id,
           fencing_token = excluded.fencing_token,
           lease_state = 'ACTIVE',
           owner_instance_id = excluded.owner_instance_id,
           acquired_at_ms = excluded.acquired_at_ms,
           heartbeat_at_ms = excluded.heartbeat_at_ms,
           expires_at_ms = excluded.expires_at_ms,
           updated_at_ms = excluded.updated_at_ms,
           reconciliation_state = 'NOT_REQUIRED',
           reconciliation_outcome = null,
           reconciliation_evidence_sha256 = null,
           reconciled_at_ms = null,
           recovery_reason = null`,
      ).run(
        input.resourceKeySha256,
        input.taskInstanceId,
        input.principalKeyFingerprint,
        input.authorityId,
        input.actionId,
        input.actionClaimId,
        fencingToken,
        this.instanceId,
        input.claimedAtMs,
        input.claimedAtMs,
        input.claimedAtMs + this.resourceLeaseTtlMs,
        input.claimedAtMs,
      );
      this.pruneTerminalClaims(input.authorityId, input.maximumReceipts);
      return {
        ok: true,
        consumedUses: action.consumed_uses + 1,
        actionClaimId: input.actionClaimId,
        resourceKeySha256: input.resourceKeySha256,
        fencingToken,
        leaseExpiresAtMs: input.claimedAtMs + this.resourceLeaseTtlMs,
      };
    });
    return claim.immediate();
  }

  markClaimDispatched(input: {
    authorityId: string;
    actionClaimId: string;
    resourceKeySha256: string;
    fencingToken: number;
    dispatchedAtMs: number;
  }): DurableResourceLeaseHeartbeat | undefined {
    const mark = this.sqlite.transaction(() => {
      this.touchOwnerRun(input.dispatchedAtMs);
      if (!this.currentLeaseMatches(input, "ACTIVE", this.instanceId)) return undefined;
      const updated = this.sqlite.prepare(
        `update operation_authority_claims
            set state = 'DISPATCHED', dispatched_at_ms = ?
          where authority_id = ? and action_claim_id = ?
            and resource_key_sha256 = ? and fencing_token = ?
            and state = 'CLAIMED'`,
      ).run(
        input.dispatchedAtMs,
        input.authorityId,
        input.actionClaimId,
        input.resourceKeySha256,
        input.fencingToken,
      );
      if (updated.changes !== 1) return undefined;
      const expiresAtMs = input.dispatchedAtMs + this.resourceLeaseTtlMs;
      const lease = this.sqlite.prepare(
        `update operation_authority_resource_leases
            set heartbeat_at_ms = ?, expires_at_ms = ?, updated_at_ms = ?
          where resource_key_sha256 = ? and action_claim_id = ?
            and fencing_token = ? and lease_state = 'ACTIVE'
            and owner_instance_id = ?`,
      ).run(
        input.dispatchedAtMs,
        expiresAtMs,
        input.dispatchedAtMs,
        input.resourceKeySha256,
        input.actionClaimId,
        input.fencingToken,
        this.instanceId,
      );
      if (lease.changes !== 1) {
        throw new Error("DISPATCHED barrier could not atomically renew its resource lease.");
      }
      return {
        resourceKeySha256: input.resourceKeySha256,
        actionClaimId: input.actionClaimId,
        fencingToken: input.fencingToken,
        heartbeatAtMs: input.dispatchedAtMs,
        expiresAtMs,
      };
    });
    return mark.immediate();
  }

  heartbeatResourceLease(input: {
    authorityId: string;
    actionClaimId: string;
    resourceKeySha256: string;
    fencingToken: number;
    heartbeatAtMs: number;
  }): DurableResourceLeaseHeartbeat | undefined {
    assertSha256(input.resourceKeySha256, "resourceKeySha256");
    const heartbeat = this.sqlite.transaction(() => {
      this.touchOwnerRun(input.heartbeatAtMs);
      if (!this.currentLeaseMatches(input, "ACTIVE", this.instanceId)) return undefined;
      const expiresAtMs = input.heartbeatAtMs + this.resourceLeaseTtlMs;
      const updated = this.sqlite.prepare(
        `update operation_authority_resource_leases
            set heartbeat_at_ms = ?, expires_at_ms = ?, updated_at_ms = ?
          where resource_key_sha256 = ? and authority_id = ?
            and action_claim_id = ? and fencing_token = ?
            and lease_state = 'ACTIVE' and owner_instance_id = ?`,
      ).run(
        input.heartbeatAtMs,
        expiresAtMs,
        input.heartbeatAtMs,
        input.resourceKeySha256,
        input.authorityId,
        input.actionClaimId,
        input.fencingToken,
        this.instanceId,
      );
      if (updated.changes !== 1) return undefined;
      return {
        resourceKeySha256: input.resourceKeySha256,
        actionClaimId: input.actionClaimId,
        fencingToken: input.fencingToken,
        heartbeatAtMs: input.heartbeatAtMs,
        expiresAtMs,
      };
    });
    return heartbeat.immediate();
  }

  cancelClaimNotDispatched(input: {
    authorityId: string;
    actionClaimId: string;
    resourceKeySha256: string;
    fencingToken: number;
    completedAtMs: number;
    providerCallCount: 0;
    proofCode: string;
    maximumReceipts: number;
  }): boolean {
    const proofCode = safeCode(input.proofCode);
    if (!proofCode) return false;
    const cancel = this.sqlite.transaction(() => {
      this.touchOwnerRun(input.completedAtMs);
      if (!this.currentLeaseMatches(input, "ACTIVE", this.instanceId)) return false;
      const claim = this.sqlite.prepare(
        `select action_id from operation_authority_claims
          where authority_id = ? and action_claim_id = ?
            and resource_key_sha256 = ? and fencing_token = ?
            and state = 'CLAIMED'`,
      ).get(
        input.authorityId,
        input.actionClaimId,
        input.resourceKeySha256,
        input.fencingToken,
      ) as { action_id: string } | undefined;
      if (!claim) return false;
      const terminal = this.sqlite.prepare(
        `update operation_authority_claims
            set state = 'CANCELLED_NOT_DISPATCHED', completed_at_ms = ?,
                provider_call_count = 0,
                reason_code = 'PROVIDER_CALL_ZERO_PROVEN',
                cancellation_proof_code = ?
          where authority_id = ? and action_claim_id = ?
            and resource_key_sha256 = ? and fencing_token = ?
            and state = 'CLAIMED'`,
      ).run(
        input.completedAtMs,
        proofCode,
        input.authorityId,
        input.actionClaimId,
        input.resourceKeySha256,
        input.fencingToken,
      );
      if (terminal.changes !== 1) return false;
      const reclaimed = this.sqlite.prepare(
        `update operation_authority_actions set consumed_uses = consumed_uses - 1
          where authority_id = ? and action_id = ? and consumed_uses > 0`,
      ).run(input.authorityId, claim.action_id);
      if (reclaimed.changes !== 1) {
        throw new Error("Claim cancellation could not atomically reclaim its authority use.");
      }
      const released = this.sqlite.prepare(
        `update operation_authority_resource_leases
            set lease_state = 'RELEASED', updated_at_ms = ?,
                reconciliation_state = 'NOT_REQUIRED', recovery_reason = null
          where resource_key_sha256 = ? and action_claim_id = ?
            and fencing_token = ? and lease_state = 'ACTIVE'`,
      ).run(
        input.completedAtMs,
        input.resourceKeySha256,
        input.actionClaimId,
        input.fencingToken,
      );
      if (released.changes !== 1) {
        throw new Error("Claim cancellation could not atomically release its writer lease.");
      }
      this.pruneTerminalClaims(input.authorityId, input.maximumReceipts);
      return true;
    });
    return cancel.immediate();
  }

  terminalizeClaim(input: {
    authorityId: string;
    actionClaimId: string;
    resourceKeySha256: string;
    fencingToken: number;
    completedAtMs: number;
    state: "PASS" | "FAIL" | "UNCERTAIN";
    errorCode?: string;
    reasonCode?: string;
    maximumReceipts: number;
  }): boolean {
    const terminalize = this.sqlite.transaction(() => {
      this.touchOwnerRun(input.completedAtMs);
      if (!this.currentLeaseMatches(input, "ACTIVE", this.instanceId)) return false;
      const updated = this.sqlite.prepare(
        `update operation_authority_claims
            set state = ?, completed_at_ms = ?, provider_call_count = 1,
                error_code = ?, reason_code = ?
          where authority_id = ? and action_claim_id = ?
            and resource_key_sha256 = ? and fencing_token = ?
            and state = 'DISPATCHED'`,
      ).run(
        input.state,
        input.completedAtMs,
        safeCode(input.errorCode),
        safeCode(input.reasonCode),
        input.authorityId,
        input.actionClaimId,
        input.resourceKeySha256,
        input.fencingToken,
      );
      if (updated.changes !== 1) return false;
      const released = input.state === "UNCERTAIN"
        ? this.sqlite.prepare(
          `update operation_authority_resource_leases
              set lease_state = 'RECOVERY_REQUIRED', updated_at_ms = ?,
                  reconciliation_state = 'PENDING',
                  recovery_reason = coalesce(?, 'ACTION_RESULT_UNCERTAIN')
            where resource_key_sha256 = ? and action_claim_id = ?
              and fencing_token = ? and lease_state = 'ACTIVE'`,
        ).run(
          input.completedAtMs,
          safeCode(input.reasonCode),
          input.resourceKeySha256,
          input.actionClaimId,
          input.fencingToken,
        )
        : this.sqlite.prepare(
          `update operation_authority_resource_leases
              set lease_state = 'RELEASED', updated_at_ms = ?,
                  reconciliation_state = 'NOT_REQUIRED', recovery_reason = null
            where resource_key_sha256 = ? and action_claim_id = ?
              and fencing_token = ? and lease_state = 'ACTIVE'`,
        ).run(
          input.completedAtMs,
          input.resourceKeySha256,
          input.actionClaimId,
          input.fencingToken,
        );
      if (released.changes !== 1) {
        throw new Error("Terminal claim transition could not atomically update its writer lease.");
      }
      this.pruneTerminalClaims(input.authorityId, input.maximumReceipts);
      return true;
    });
    return terminalize.immediate();
  }

  recordClaimAuditResult(input: {
    authorityId: string;
    actionClaimId: string;
    receiptDigest: string;
    status: DurableAuthorityReceiptAuditState;
    auditEventDigest?: string;
    errorCode?: string;
    recordedAtMs: number;
  }): DurableAuthorityReceiptAuditResult {
    if (input.status !== "RECORDED" && input.status !== "SINK_FAILED") {
      return { ok: false, code: "PRECONDITION_FAILED" };
    }
    const receiptDigest = assertSha256Digest(input.receiptDigest, "receiptDigest");
    const auditEventDigest = input.status === "RECORDED"
      ? assertSha256Digest(input.auditEventDigest, "auditEventDigest")
      : null;
    if (input.status === "SINK_FAILED" && input.auditEventDigest !== undefined) {
      return { ok: false, code: "PRECONDITION_FAILED" };
    }
    if (!Number.isSafeInteger(input.recordedAtMs) || input.recordedAtMs < 0) {
      return { ok: false, code: "PRECONDITION_FAILED" };
    }
    const errorCode = input.status === "SINK_FAILED"
      ? (safeCode(input.errorCode) ?? "AUDIT_SINK_FAILED")
      : null;
    const record = this.sqlite.transaction((): DurableAuthorityReceiptAuditResult => {
      this.touchOwnerRun(input.recordedAtMs);
      const current = this.sqlite.prepare(
        `select state, audit_state, audit_event_digest, audit_receipt_digest,
                audit_recorded_at_ms
           from operation_authority_claims
          where authority_id = ? and action_claim_id = ?`,
      ).get(input.authorityId, input.actionClaimId) as {
        state: DurableActionClaimState;
        audit_state: DurableAuthorityReceiptAuditState | null;
        audit_event_digest: string | null;
        audit_receipt_digest: string | null;
        audit_recorded_at_ms: number | null;
      } | undefined;
      if (!current || current.state === "CLAIMED" || current.state === "DISPATCHED") {
        return { ok: false, code: "AUTHORITY_STATE_UNCERTAIN" };
      }
      if (current.audit_state !== null) {
        const sameRecorded = current.audit_state === input.status
          && current.audit_receipt_digest === receiptDigest
          && (current.audit_event_digest ?? null) === auditEventDigest;
        return sameRecorded
          ? {
              ok: true,
              auditState: input.status,
              ...(auditEventDigest ? { auditEventDigest } : {}),
              auditRecordedAtMs: current.audit_recorded_at_ms ?? input.recordedAtMs,
            }
          : { ok: false, code: "AUTHORITY_STATE_UNCERTAIN" };
      }
      const updated = this.sqlite.prepare(
        `update operation_authority_claims
            set audit_state = ?, audit_event_digest = ?,
                audit_receipt_digest = ?, audit_recorded_at_ms = ?,
                audit_error_code = ?
          where authority_id = ? and action_claim_id = ?
            and audit_state is null`,
      ).run(
        input.status,
        auditEventDigest,
        receiptDigest,
        input.recordedAtMs,
        errorCode,
        input.authorityId,
        input.actionClaimId,
      );
      return updated.changes === 1
        ? {
            ok: true,
            auditState: input.status,
            ...(auditEventDigest ? { auditEventDigest } : {}),
            auditRecordedAtMs: input.recordedAtMs,
          }
        : { ok: false, code: "AUTHORITY_STATE_UNCERTAIN" };
    });
    return record.immediate();
  }

  reconcileResourceLease(input: {
    principalKeyFingerprint: string;
    resourceKeySha256: string;
    actionClaimId: string;
    fencingToken: number;
    outcome: DurableResourceReconciliationOutcome;
    evidenceDigest: string;
    reconciledAtMs: number;
  }): DurableResourceLeaseReconciliationResult {
    assertSha256(input.resourceKeySha256, "resourceKeySha256");
    assertSha256(input.evidenceDigest, "evidenceDigest");
    if (/^0{64}$/u.test(input.evidenceDigest)) {
      return { ok: false, code: "PRECONDITION_FAILED" };
    }
    if (!(["RESOURCE_VERIFIED", "RESOURCE_QUARANTINED"] as const).includes(input.outcome)) {
      return { ok: false, code: "PRECONDITION_FAILED" };
    }
    const reconcile = this.sqlite.transaction((): DurableResourceLeaseReconciliationResult => {
      this.touchOwnerRun(input.reconciledAtMs);
      const lease = this.sqlite.prepare(
        `select principal_key_fingerprint, action_claim_id, fencing_token,
                lease_state, reconciliation_state
           from operation_authority_resource_leases
          where resource_key_sha256 = ?`,
      ).get(input.resourceKeySha256) as {
        principal_key_fingerprint: string;
        action_claim_id: string;
        fencing_token: number;
        lease_state: DurableResourceLeaseState;
        reconciliation_state: string;
      } | undefined;
      if (!lease) return { ok: false, code: "AUTHORITY_STATE_UNCERTAIN" };
      if (lease.principal_key_fingerprint !== input.principalKeyFingerprint) {
        return { ok: false, code: "AUTHORITY_PRINCIPAL_MISMATCH" };
      }
      if (
        lease.action_claim_id !== input.actionClaimId
        || lease.fencing_token !== input.fencingToken
        || lease.lease_state !== "RECOVERY_REQUIRED"
        || lease.reconciliation_state !== "PENDING"
      ) {
        return { ok: false, code: "AUTHORITY_STATE_UNCERTAIN" };
      }
      const claim = this.sqlite.prepare(
        `select state from operation_authority_claims
          where action_claim_id = ? and resource_key_sha256 = ? and fencing_token = ?`,
      ).get(
        input.actionClaimId,
        input.resourceKeySha256,
        input.fencingToken,
      ) as { state: DurableActionClaimState } | undefined;
      if (claim?.state !== "UNCERTAIN") {
        return { ok: false, code: "AUTHORITY_STATE_UNCERTAIN" };
      }
      const updated = this.sqlite.prepare(
        `update operation_authority_resource_leases
            set lease_state = 'RELEASED', reconciliation_state = 'VERIFIED',
                reconciliation_outcome = ?, reconciliation_evidence_sha256 = ?,
                reconciled_at_ms = ?, updated_at_ms = ?
          where resource_key_sha256 = ? and action_claim_id = ?
            and fencing_token = ? and lease_state = 'RECOVERY_REQUIRED'
            and reconciliation_state = 'PENDING'`,
      ).run(
        input.outcome,
        input.evidenceDigest,
        input.reconciledAtMs,
        input.reconciledAtMs,
        input.resourceKeySha256,
        input.actionClaimId,
        input.fencingToken,
      );
      return updated.changes === 1
        ? { ok: true, fencingToken: input.fencingToken, releasedAtMs: input.reconciledAtMs }
        : { ok: false, code: "AUTHORITY_STATE_UNCERTAIN" };
    });
    return reconcile.immediate();
  }

  /**
   * Atomically closes the only supported cross-store recovery case: an exact
   * connector activation proof exists in OAuth after this claim was recovered
   * as UNCERTAIN. Generic callers cannot use this to bless an unknown result.
   */
  terminalizeRecoveredConnectorActivationPass(input: {
    principalKeyFingerprint: string;
    authorityId: string;
    actionClaimId: string;
    actionFingerprint: string;
    resourceKeySha256: string;
    fencingToken: number;
    oauthProofDigest: string;
    reconciliationEvidenceSha256: string;
    recoveredAtMs: number;
  }): DurableRecoveredConnectorActivationResult {
    if (!HASH_PATTERN.test(input.principalKeyFingerprint)
      || !HASH_PATTERN.test(input.actionFingerprint)
      || !HASH_PATTERN.test(input.resourceKeySha256)
      || !SHA256_DIGEST_PATTERN.test(input.oauthProofDigest)
      || !HASH_PATTERN.test(input.reconciliationEvidenceSha256)
      || /^0{64}$/u.test(input.reconciliationEvidenceSha256)
      || !Number.isSafeInteger(input.fencingToken)
      || input.fencingToken < 1
      || !Number.isSafeInteger(input.recoveredAtMs)
      || input.recoveredAtMs < 0) {
      return { ok: false, code: "PRECONDITION_FAILED" };
    }
    const recover = this.sqlite.transaction((): DurableRecoveredConnectorActivationResult => {
      this.touchOwnerRun(input.recoveredAtMs);
      const row = this.sqlite.prepare(
        `select c.state, c.completed_at_ms, c.provider_call_count, c.principal_key_fingerprint,
                c.action_fingerprint, c.resource_key_sha256, c.fencing_token,
                c.reason_code, a.action_id, a.tool, a.operation,
                a.fingerprint as durable_action_fingerprint,
                a.resource_key_sha256 as action_resource_key_sha256,
                l.principal_key_fingerprint as lease_principal_key_fingerprint,
                l.action_claim_id as lease_action_claim_id,
                l.fencing_token as lease_fencing_token,
                l.lease_state, l.reconciliation_state,
                l.reconciliation_outcome, l.reconciliation_evidence_sha256
           from operation_authority_claims c
           join operation_authority_actions a
             on a.authority_id = c.authority_id and a.action_id = c.action_id
           left join operation_authority_resource_leases l
             on l.resource_key_sha256 = c.resource_key_sha256
          where c.authority_id = ? and c.action_claim_id = ?`,
      ).get(input.authorityId, input.actionClaimId) as {
        state: DurableActionClaimState;
        completed_at_ms: number | null;
        provider_call_count: number | null;
        principal_key_fingerprint: string;
        action_fingerprint: string;
        resource_key_sha256: string;
        fencing_token: number;
        reason_code: string | null;
        action_id: string;
        tool: string;
        operation: string;
        durable_action_fingerprint: string;
        action_resource_key_sha256: string;
        lease_principal_key_fingerprint: string | null;
        lease_action_claim_id: string | null;
        lease_fencing_token: number | null;
        lease_state: DurableResourceLeaseState | null;
        reconciliation_state: string | null;
        reconciliation_outcome: string | null;
        reconciliation_evidence_sha256: string | null;
      } | undefined;
      if (!row) return { ok: false, code: "AUTHORITY_STATE_UNCERTAIN" };
      if (row.principal_key_fingerprint !== input.principalKeyFingerprint
        || row.lease_principal_key_fingerprint !== input.principalKeyFingerprint) {
        return { ok: false, code: "AUTHORITY_PRINCIPAL_MISMATCH" };
      }
      if (row.action_fingerprint !== input.actionFingerprint
        || row.durable_action_fingerprint !== input.actionFingerprint
        || row.action_id !== `action_${input.actionFingerprint}`
        || row.tool !== "context"
        || row.operation !== "connector_activation_finalize"
        || row.resource_key_sha256 !== input.resourceKeySha256
        || row.action_resource_key_sha256 !== input.resourceKeySha256
        || row.fencing_token !== input.fencingToken
        || row.lease_action_claim_id !== input.actionClaimId
        || row.lease_fencing_token !== input.fencingToken) {
        return { ok: false, code: "AUTHORITY_ACTION_MISMATCH" };
      }
      if (row.state === "PASS") {
        const sameRecovery = row.provider_call_count === 1
          && row.reason_code === "CONNECTOR_ACTIVATION_RECOVERED_EXACT_OAUTH_RECEIPT"
          && row.lease_state === "RELEASED"
          && row.reconciliation_state === "VERIFIED"
          && row.reconciliation_outcome === "RESOURCE_VERIFIED"
          && row.reconciliation_evidence_sha256 === input.reconciliationEvidenceSha256;
        return sameRecovery
          ? {
              ok: true,
              fencingToken: input.fencingToken,
              recoveredAtMs: row.completed_at_ms ?? input.recoveredAtMs,
              reconciliationEvidenceSha256: input.reconciliationEvidenceSha256,
            }
          : { ok: false, code: "AUTHORITY_STATE_UNCERTAIN" };
      }
      if (row.state !== "UNCERTAIN"
        || row.provider_call_count !== 1
        || row.lease_state !== "RECOVERY_REQUIRED"
        || row.reconciliation_state !== "PENDING") {
        return { ok: false, code: "AUTHORITY_STATE_UNCERTAIN" };
      }
      const claim = this.sqlite.prepare(
        `update operation_authority_claims
            set state = 'PASS', completed_at_ms = ?, provider_call_count = 1,
                error_code = null,
                reason_code = 'CONNECTOR_ACTIVATION_RECOVERED_EXACT_OAUTH_RECEIPT'
          where authority_id = ? and action_claim_id = ?
            and action_fingerprint = ? and resource_key_sha256 = ?
            and fencing_token = ? and state = 'UNCERTAIN'
            and provider_call_count = 1`,
      ).run(
        input.recoveredAtMs,
        input.authorityId,
        input.actionClaimId,
        input.actionFingerprint,
        input.resourceKeySha256,
        input.fencingToken,
      );
      const lease = this.sqlite.prepare(
        `update operation_authority_resource_leases
            set lease_state = 'RELEASED', updated_at_ms = ?,
                reconciliation_state = 'VERIFIED',
                reconciliation_outcome = 'RESOURCE_VERIFIED',
                reconciliation_evidence_sha256 = ?, reconciled_at_ms = ?,
                recovery_reason = 'CONNECTOR_ACTIVATION_EXACT_OAUTH_RECEIPT'
          where resource_key_sha256 = ? and authority_id = ?
            and action_claim_id = ? and fencing_token = ?
            and principal_key_fingerprint = ?
            and lease_state = 'RECOVERY_REQUIRED'
            and reconciliation_state = 'PENDING'`,
      ).run(
        input.recoveredAtMs,
        input.reconciliationEvidenceSha256,
        input.recoveredAtMs,
        input.resourceKeySha256,
        input.authorityId,
        input.actionClaimId,
        input.fencingToken,
        input.principalKeyFingerprint,
      );
      if (claim.changes !== 1 || lease.changes !== 1) {
        throw new Error("Recovered connector activation could not atomically terminalize its claim and lease.");
      }
      return {
        ok: true,
        fencingToken: input.fencingToken,
        recoveredAtMs: input.recoveredAtMs,
        reconciliationEvidenceSha256: input.reconciliationEvidenceSha256,
      };
    });
    return recover.immediate();
  }

  incrementTaskCorrectionEpoch(
    taskInstanceId: string,
    principalKeyFingerprint: string,
    nowMs: number,
  ): DurableTaskCorrectionResult {
    const increment = this.sqlite.transaction((): DurableTaskCorrectionResult => {
      const task = this.taskRow(taskInstanceId);
      if (!task) return { ok: false, code: "AUTHORITY_STALE" };
      if (task.principal_key_fingerprint !== principalKeyFingerprint) {
        return { ok: false, code: "AUTHORITY_PRINCIPAL_MISMATCH" };
      }
      const correctionEpoch = task.correction_epoch + 1;
      const updated = this.sqlite.prepare(
        `update operation_authority_tasks set correction_epoch = ?, updated_at_ms = ?
          where task_instance_id = ? and principal_key_fingerprint = ?
            and correction_epoch = ?`,
      ).run(
        correctionEpoch,
        nowMs,
        taskInstanceId,
        principalKeyFingerprint,
        task.correction_epoch,
      );
      if (updated.changes !== 1) return { ok: false, code: "AUTHORITY_STALE" };
      const authorityIds = (this.sqlite.prepare(
        `select authority_id from operation_authorities
          where task_instance_id = ? and principal_key_fingerprint = ?
            and correction_epoch = ? order by authority_id`,
      ).all(
        taskInstanceId,
        principalKeyFingerprint,
        task.correction_epoch,
      ) as Array<{ authority_id: string }>).map((row) => row.authority_id);
      this.sqlite.prepare(
        `update operation_authorities set grant_active = 0
          where task_instance_id = ? and principal_key_fingerprint = ?
            and correction_epoch = ? and grant_active = 1`,
      ).run(taskInstanceId, principalKeyFingerprint, task.correction_epoch);
      return { ok: true, correctionEpoch, authorityIds };
    });
    return increment.immediate();
  }

  releaseAuthority(input: {
    authorityId: string;
    principalKeyFingerprint: string;
    taskInstanceId: string;
    correctionEpoch: number;
  }): DurableAuthorityReleaseResult {
    const release = this.sqlite.transaction((): DurableAuthorityReleaseResult => {
      const authority = this.sqlite.prepare(
        `select task_instance_id, principal_key_fingerprint, correction_epoch
           from operation_authorities where authority_id = ?`,
      ).get(input.authorityId) as {
        task_instance_id: string;
        principal_key_fingerprint: string;
        correction_epoch: number;
      } | undefined;
      if (!authority) return { ok: false, code: "AUTHORITY_EXPIRED" };
      if (authority.principal_key_fingerprint !== input.principalKeyFingerprint) {
        return { ok: false, code: "AUTHORITY_PRINCIPAL_MISMATCH" };
      }
      if (authority.task_instance_id !== input.taskInstanceId) {
        return { ok: false, code: "AUTHORITY_STALE" };
      }
      const task = this.taskRow(input.taskInstanceId);
      if (
        !task
        || task.principal_key_fingerprint !== input.principalKeyFingerprint
        || task.correction_epoch !== input.correctionEpoch
        || authority.correction_epoch !== input.correctionEpoch
      ) {
        return { ok: false, code: "AUTHORITY_STALE" };
      }
      const pending = this.sqlite.prepare(
        `select count(*) as count from operation_authority_claims
          where authority_id = ? and state in ('CLAIMED', 'DISPATCHED', 'UNCERTAIN')`,
      ).get(input.authorityId) as { count: number };
      if (pending.count > 0) {
        return { ok: false, code: "PRECONDITION_FAILED", pendingReceipts: pending.count };
      }
      const deleted = this.sqlite.prepare(
        "delete from operation_authorities where authority_id = ?",
      ).run(input.authorityId);
      return deleted.changes === 1
        ? { ok: true }
        : { ok: false, code: "AUTHORITY_EXPIRED" };
    });
    return release.immediate();
  }

  deleteAuthorities(authorityIds: readonly string[]): void {
    if (authorityIds.length === 0) return;
    const remove = this.sqlite.transaction(() => {
      const statement = this.sqlite.prepare(
        `delete from operation_authorities where authority_id = ?
          and not exists (
            select 1 from operation_authority_claims
             where operation_authority_claims.authority_id = operation_authorities.authority_id
          )`,
      );
      for (const authorityId of authorityIds) statement.run(authorityId);
    });
    remove.immediate();
  }

  deleteAuthoritiesExpiredBefore(expiresAtCutoffMs: number): string[] {
    const rows = this.sqlite.prepare(
      `select authority_id from operation_authorities where expires_at_ms <= ?
        and not exists (
          select 1 from operation_authority_claims
           where operation_authority_claims.authority_id = operation_authorities.authority_id
             and operation_authority_claims.state in ('CLAIMED', 'DISPATCHED', 'UNCERTAIN')
        ) order by authority_id`,
    ).all(expiresAtCutoffMs) as Array<{ authority_id: string }>;
    if (rows.length === 0) return [];
    const purge = this.sqlite.transaction(() => {
      const remove = this.sqlite.prepare(
        `delete from operation_authorities where authority_id = ? and expires_at_ms <= ?
          and not exists (
            select 1 from operation_authority_claims
             where operation_authority_claims.authority_id = operation_authorities.authority_id
               and operation_authority_claims.state in ('CLAIMED', 'DISPATCHED', 'UNCERTAIN')
          )`,
      );
      const removed: string[] = [];
      for (const row of rows) {
        if (remove.run(row.authority_id, expiresAtCutoffMs).changes === 1) {
          removed.push(row.authority_id);
        }
      }
      return removed;
    });
    return purge.immediate();
  }

  taskCount(): number {
    return (this.sqlite.prepare(
      "select count(*) as count from operation_authority_tasks",
    ).get() as { count: number }).count;
  }

  close(nowMs = Date.now()): void {
    this.sqlite.prepare(
      `update operation_authority_owner_runs
          set run_state = 'CLOSED', heartbeat_at_ms = ?,
              lease_deadline_ms = ?, closed_at_ms = ?
        where owner_run_id = ? and run_state = 'ACTIVE'`,
    ).run(nowMs, nowMs, nowMs, this.instanceId);
    this.sqlite.close();
  }

  private initializeSchema(path: string | undefined, nowMs: number): void {
    const currentVersion = Number(this.sqlite.pragma("user_version", { simple: true }));
    if (currentVersion > SCHEMA_VERSION) {
      throw new Error(
        `Authority store schema ${currentVersion} is newer than supported schema ${SCHEMA_VERSION}.`,
      );
    }
    const hasLegacyTables = this.tableExists("operation_authorities")
      && !this.tableExists("operation_authority_tasks");
    if (currentVersion < 3 && hasLegacyTables) {
      const backup = path ? this.createMigrationBackup(path) : undefined;
      this.migrateLegacySchema(currentVersion, nowMs, backup);
      this.validateDatabase("post-v2-migration");
      return;
    }
    if (currentVersion === 3) {
      const backup = path ? this.createMigrationBackup(path) : undefined;
      this.migrateV3Schema(nowMs, backup);
      this.validateDatabase("post-v3-migration");
      return;
    }
    if (currentVersion === 4) {
      const backup = path ? this.createMigrationBackup(path) : undefined;
      this.migrateV4Schema(nowMs, backup);
      this.validateDatabase("post-v4-migration");
      return;
    }
    if (currentVersion === 5) {
      const backup = path ? this.createMigrationBackup(path) : undefined;
      this.migrateV5Schema(nowMs, backup);
      this.validateDatabase("post-v5-migration");
      return;
    }
    if (currentVersion === 6) {
      const backup = path ? this.createMigrationBackup(path) : undefined;
      this.migrateV6Schema(nowMs, backup);
      this.validateDatabase("post-v6-migration");
      return;
    }
    if (currentVersion === 0 && !hasLegacyTables) {
      this.createSchema();
      this.sqlite.pragma(`user_version = ${SCHEMA_VERSION}`);
      this.validateDatabase("new-v7-store");
      return;
    }
    if (currentVersion < SCHEMA_VERSION) {
      throw new Error(
        `Authority store schema ${currentVersion} cannot be migrated because its legacy tables are incomplete.`,
      );
    }
    this.validateDatabase("existing-v7-store");
  }

  private createSchema(): void {
    this.sqlite.exec(`
      create table if not exists operation_authority_tasks (
        task_instance_id text primary key,
        principal_key_fingerprint text not null,
        task_label_sha256 text,
        correction_epoch integer not null check (correction_epoch >= 0),
        created_at_ms integer not null,
        updated_at_ms integer not null
      );
      create index if not exists operation_authority_tasks_principal_idx
        on operation_authority_tasks(principal_key_fingerprint, updated_at_ms desc);
      create table if not exists operation_authorities (
        authority_id text primary key,
        task_instance_id text not null,
        task_label_sha256 text,
        authority_text_sha256 text not null,
        principal_key_fingerprint text not null,
        approval_assurance text not null check (approval_assurance in ('cooperative')),
        correction_epoch integer not null check (correction_epoch >= 0),
        created_at_ms integer not null,
        expires_at_ms integer not null,
        fingerprint text not null,
        grant_active integer not null default 1 check (grant_active in (0, 1)),
        foreign key (task_instance_id) references operation_authority_tasks(task_instance_id)
      );
      create index if not exists operation_authorities_principal_fingerprint_idx
        on operation_authorities(principal_key_fingerprint, fingerprint, created_at_ms desc);
      create index if not exists operation_authorities_task_idx
        on operation_authorities(task_instance_id, correction_epoch, created_at_ms desc);
      create index if not exists operation_authorities_expiry_idx
        on operation_authorities(expires_at_ms);
      create unique index if not exists operation_authorities_open_grant_idx
        on operation_authorities(
          principal_key_fingerprint, task_instance_id, correction_epoch, fingerprint
        ) where grant_active = 1;
      create table if not exists operation_authority_actions (
        authority_id text not null,
        action_id text not null,
        ordinal integer not null,
        tool text not null,
        operation text not null,
        fingerprint text not null,
        resource_key_sha256 text not null check (length(resource_key_sha256) = 64),
        minimum_risk text not null,
        risk text not null,
        maximum_uses integer not null check (maximum_uses >= 1),
        consumed_uses integer not null check (consumed_uses >= 0),
        primary key (authority_id, action_id),
        unique (authority_id, fingerprint),
        foreign key (authority_id) references operation_authorities(authority_id) on delete cascade
      );
      create table if not exists operation_authority_resource_fences (
        resource_key_sha256 text primary key check (length(resource_key_sha256) = 64),
        last_fencing_token integer not null check (last_fencing_token >= 1),
        updated_at_ms integer not null
      );
      create table if not exists operation_authority_owner_runs (
        owner_run_id text primary key,
        host_identity_sha256 text not null check (length(host_identity_sha256) = 64),
        process_id integer not null check (process_id >= 0),
        process_start_key_sha256 text not null check (length(process_start_key_sha256) = 64),
        run_state text not null check (run_state in ('ACTIVE', 'CLOSED')),
        registered_at_ms integer not null,
        heartbeat_at_ms integer not null,
        lease_deadline_ms integer not null,
        closed_at_ms integer
      );
      create index if not exists operation_authority_owner_runs_state_idx
        on operation_authority_owner_runs(run_state, lease_deadline_ms);
      create table if not exists operation_authority_claims (
        action_claim_id text primary key,
        authority_id text not null,
        action_id text not null,
        task_instance_id text not null,
        principal_key_fingerprint text not null,
        action_fingerprint text not null,
        resource_key_sha256 text not null check (length(resource_key_sha256) = 64),
        fencing_token integer not null check (fencing_token >= 1),
        state text not null check (state in (
          'CLAIMED', 'DISPATCHED', 'PASS', 'FAIL', 'UNCERTAIN',
          'CANCELLED_NOT_DISPATCHED'
        )),
        owner_instance_id text not null,
        claimed_at_ms integer not null,
        dispatched_at_ms integer,
        completed_at_ms integer,
        provider_call_count integer check (provider_call_count in (0, 1)),
        error_code text,
        reason_code text,
        cancellation_proof_code text,
        audit_state text check (audit_state is null or audit_state in ('RECORDED', 'SINK_FAILED')),
        audit_event_digest text check (
          audit_event_digest is null
          or (length(audit_event_digest) = 71 and substr(audit_event_digest, 1, 7) = 'sha256:')
        ),
        audit_receipt_digest text check (
          audit_receipt_digest is null
          or (length(audit_receipt_digest) = 71 and substr(audit_receipt_digest, 1, 7) = 'sha256:')
        ),
        audit_recorded_at_ms integer,
        audit_error_code text,
        unique (resource_key_sha256, fencing_token),
        foreign key (authority_id, action_id)
          references operation_authority_actions(authority_id, action_id) on delete cascade,
        foreign key (task_instance_id) references operation_authority_tasks(task_instance_id)
      );
      create index if not exists operation_authority_claims_authority_idx
        on operation_authority_claims(authority_id, claimed_at_ms);
      create index if not exists operation_authority_claims_state_idx
        on operation_authority_claims(state, owner_instance_id, claimed_at_ms);
      create table if not exists operation_authority_resource_leases (
        resource_key_sha256 text primary key check (length(resource_key_sha256) = 64),
        task_instance_id text not null,
        principal_key_fingerprint text not null,
        authority_id text not null,
        action_id text not null,
        action_claim_id text not null,
        fencing_token integer not null check (fencing_token >= 1),
        lease_state text not null check (lease_state in (
          'ACTIVE', 'RELEASED', 'EXPIRED', 'RECOVERY_REQUIRED'
        )),
        owner_instance_id text not null,
        acquired_at_ms integer not null,
        heartbeat_at_ms integer not null,
        expires_at_ms integer not null,
        updated_at_ms integer not null,
        reconciliation_state text not null check (reconciliation_state in (
          'NOT_REQUIRED', 'PENDING', 'VERIFIED', 'FAILED'
        )),
        reconciliation_outcome text check (reconciliation_outcome in (
          'RESOURCE_VERIFIED', 'RESOURCE_QUARANTINED'
        )),
        reconciliation_evidence_sha256 text
          check (reconciliation_evidence_sha256 is null or length(reconciliation_evidence_sha256) = 64),
        reconciled_at_ms integer,
        recovery_reason text,
        foreign key (task_instance_id)
          references operation_authority_tasks(task_instance_id),
        foreign key (authority_id, action_id)
          references operation_authority_actions(authority_id, action_id),
        foreign key (action_claim_id)
          references operation_authority_claims(action_claim_id) on delete cascade
      );
      create index if not exists operation_authority_resource_leases_task_idx
        on operation_authority_resource_leases(task_instance_id, lease_state);
      create index if not exists operation_authority_resource_leases_expiry_idx
        on operation_authority_resource_leases(lease_state, expires_at_ms);
      create trigger if not exists operation_authority_resource_leases_exact_insert
      before insert on operation_authority_resource_leases
      begin
        select case when not exists (
          select 1 from operation_authority_claims c
           where c.action_claim_id = new.action_claim_id
             and c.authority_id = new.authority_id
             and c.action_id = new.action_id
             and c.task_instance_id = new.task_instance_id
             and c.principal_key_fingerprint = new.principal_key_fingerprint
             and c.resource_key_sha256 = new.resource_key_sha256
             and c.fencing_token = new.fencing_token
        ) then raise(abort, 'resource lease does not exactly match its claim') end;
      end;
      create trigger if not exists operation_authority_resource_leases_exact_update
      before update on operation_authority_resource_leases
      begin
        select case when not exists (
          select 1 from operation_authority_claims c
           where c.action_claim_id = new.action_claim_id
             and c.authority_id = new.authority_id
             and c.action_id = new.action_id
             and c.task_instance_id = new.task_instance_id
             and c.principal_key_fingerprint = new.principal_key_fingerprint
             and c.resource_key_sha256 = new.resource_key_sha256
             and c.fencing_token = new.fencing_token
        ) then raise(abort, 'resource lease does not exactly match its claim') end;
      end;
      create table if not exists operation_authority_legacy_quarantine (
        authority_id text primary key,
        legacy_scope_key text not null,
        legacy_task_id_sha256 text not null,
        legacy_fingerprint text not null,
        quarantined_at_ms integer not null,
        reason text not null,
        backup_sha256 text
      );
      create table if not exists operation_authority_v3_action_quarantine (
        authority_id text not null,
        action_id text not null,
        legacy_fingerprint text not null,
        quarantined_at_ms integer not null,
        reason text not null,
        backup_sha256 text,
        primary key (authority_id, action_id)
      );
      create table if not exists operation_authority_v4_lease_quarantine (
        resource_key_sha256 text not null,
        action_claim_id text not null,
        quarantined_at_ms integer not null,
        reason text not null,
        backup_sha256 text,
        primary key (resource_key_sha256, action_claim_id)
      );
      create table if not exists operation_authority_migrations (
        migration_id text primary key,
        from_schema_version integer not null,
        to_schema_version integer not null,
        migrated_at_ms integer not null,
        backup_path text,
        backup_sha256 text,
        quarantined_authorities integer not null,
        source_integrity_check text not null default 'ok',
        backup_integrity_check text not null default 'ok',
        post_integrity_check text not null default 'ok',
        foreign_key_violations integer not null default 0
      );
    `);
  }

  private migrateLegacySchema(
    currentVersion: number,
    nowMs: number,
    backup: MigrationBackup | undefined,
  ): void {
    this.sqlite.pragma("foreign_keys = OFF");
    try {
      const migrate = this.sqlite.transaction(() => {
        for (const table of [
          "operation_authority_receipts",
          "operation_authority_actions",
          "operation_authorities",
          "operation_authority_scopes",
        ]) {
          if (this.tableExists(table)) {
            this.sqlite.exec(`alter table ${table} rename to legacy_v2_${table}`);
          }
        }
        this.createSchema();
        let quarantinedAuthorities = 0;
        if (this.tableExists("legacy_v2_operation_authorities")) {
          const inserted = this.sqlite.prepare(
            `insert into operation_authority_legacy_quarantine (
               authority_id, legacy_scope_key, legacy_task_id_sha256,
               legacy_fingerprint, quarantined_at_ms, reason, backup_sha256
             ) select authority_id, scope_key, task_id_sha256, fingerprint, ?, ?, ?
                 from legacy_v2_operation_authorities`,
          ).run(
            nowMs,
            "AMBIGUOUS_LEGACY_CLIENT_SESSION_SCOPE",
            backup?.sha256 ?? null,
          );
          quarantinedAuthorities = inserted.changes;
        }
        this.insertMigrationRecord(currentVersion, nowMs, backup, quarantinedAuthorities);
        this.sqlite.pragma(`user_version = ${SCHEMA_VERSION}`);
      });
      migrate.immediate();
    } finally {
      this.sqlite.pragma("foreign_keys = ON");
    }
    this.finishMigrationRecord();
  }

  private migrateV3Schema(nowMs: number, backup: MigrationBackup | undefined): void {
    this.sqlite.pragma("foreign_keys = OFF");
    try {
      const migrate = this.sqlite.transaction(() => {
        this.sqlite.exec(
          "alter table operation_authority_actions rename to legacy_v3_operation_authority_actions",
        );
        this.sqlite.exec(
          "alter table operation_authority_receipts rename to legacy_v3_operation_authority_receipts",
        );
        this.sqlite.exec(
          "alter table operation_authorities add column grant_active integer not null default 0 check (grant_active in (0, 1))",
        );
        this.sqlite.exec(`
          with ranked as (
            select authority_id,
                   row_number() over (
                     partition by principal_key_fingerprint, task_instance_id,
                                  correction_epoch, fingerprint
                     order by created_at_ms desc, authority_id desc
                   ) as rank
              from operation_authorities
          )
          update operation_authorities
             set grant_active = case when authority_id in (
               select authority_id from ranked where rank = 1
             ) then 1 else 0 end;
        `);
        this.ensureMigrationColumns();
        this.createSchema();
        this.ensureClaimAuditColumns();
        const legacyActions = this.sqlite.prepare(
          `select authority_id, action_id, ordinal, tool, operation, fingerprint,
                  minimum_risk, risk, maximum_uses, consumed_uses
             from legacy_v3_operation_authority_actions
            order by authority_id, ordinal`,
        ).all() as LegacyV3ActionRow[];
        const insertAction = this.sqlite.prepare(
          `insert into operation_authority_actions (
             authority_id, action_id, ordinal, tool, operation, fingerprint,
             resource_key_sha256, minimum_risk, risk, maximum_uses, consumed_uses
           ) values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
        );
        const quarantinedAuthorities = new Set<string>();
        for (const action of legacyActions) {
          const resourceKey = legacyV3ResourceKey(action.fingerprint);
          insertAction.run(
            action.authority_id,
            action.action_id,
            action.ordinal,
            action.tool,
            action.operation,
            action.fingerprint,
            resourceKey,
            action.minimum_risk,
            action.risk,
            action.maximum_uses,
            action.consumed_uses,
          );
          this.sqlite.prepare(
            `insert into operation_authority_v3_action_quarantine (
               authority_id, action_id, legacy_fingerprint,
               quarantined_at_ms, reason, backup_sha256
             ) values (?, ?, ?, ?, ?, ?)`,
          ).run(
            action.authority_id,
            action.action_id,
            action.fingerprint,
            nowMs,
            "LEGACY_ACTION_RESOURCE_BINDING_UNRECOVERABLE",
            backup?.sha256 ?? null,
          );
          quarantinedAuthorities.add(action.authority_id);
        }
        const legacyReceipts = this.sqlite.prepare(
          `select r.authority_id, r.use_id, r.action_id, r.reserved_at_ms,
                  r.completed_at_ms, r.result, r.error_code, r.reason_code,
                  r.owner_instance_id, a.task_instance_id,
                  a.principal_key_fingerprint, x.fingerprint as action_fingerprint
             from legacy_v3_operation_authority_receipts r
             join operation_authorities a on a.authority_id = r.authority_id
             join legacy_v3_operation_authority_actions x
               on x.authority_id = r.authority_id and x.action_id = r.action_id
            order by r.reserved_at_ms, r.use_id`,
        ).all() as LegacyV3ReceiptRow[];
        const fences = new Map<string, number>();
        for (const receipt of legacyReceipts) {
          const resourceKey = legacyV3ResourceKey(receipt.action_fingerprint);
          const fencingToken = (fences.get(resourceKey) ?? 0) + 1;
          fences.set(resourceKey, fencingToken);
          const state: DurableActionClaimState = receipt.result === "PENDING"
            ? "UNCERTAIN"
            : receipt.result;
          const completedAtMs = receipt.completed_at_ms
            ?? (state === "UNCERTAIN" ? nowMs : null);
          this.sqlite.prepare(
            `insert into operation_authority_claims (
               action_claim_id, authority_id, action_id, task_instance_id,
               principal_key_fingerprint, action_fingerprint,
               resource_key_sha256, fencing_token, state, owner_instance_id,
               claimed_at_ms, dispatched_at_ms, completed_at_ms,
               provider_call_count, error_code, reason_code,
               cancellation_proof_code
             ) values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, null, ?, ?, ?, ?, null)`,
          ).run(
            receipt.use_id,
            receipt.authority_id,
            receipt.action_id,
            receipt.task_instance_id,
            receipt.principal_key_fingerprint,
            receipt.action_fingerprint,
            resourceKey,
            fencingToken,
            state,
            receipt.owner_instance_id,
            receipt.reserved_at_ms,
            completedAtMs,
            state === "UNCERTAIN" ? null : 1,
            receipt.result === "PENDING" ? "PROCESS_RESTARTED" : receipt.error_code,
            receipt.result === "PENDING"
              ? "LEGACY_PENDING_CLAIM_MIGRATED"
              : receipt.reason_code,
          );
          if (state === "UNCERTAIN") {
            this.upsertMigratedFrozenLease({
              resourceKey,
              actionClaimId: receipt.use_id,
              authorityId: receipt.authority_id,
              actionId: receipt.action_id,
              taskInstanceId: receipt.task_instance_id,
              principalKeyFingerprint: receipt.principal_key_fingerprint,
              ownerInstanceId: receipt.owner_instance_id,
              fencingToken,
              nowMs,
            });
          }
        }
        for (const [resourceKey, fencingToken] of fences) {
          this.sqlite.prepare(
            `insert into operation_authority_resource_fences (
               resource_key_sha256, last_fencing_token, updated_at_ms
             ) values (?, ?, ?)`,
          ).run(resourceKey, fencingToken, nowMs);
        }
        this.insertMigrationRecord(3, nowMs, backup, quarantinedAuthorities.size);
        this.sqlite.pragma(`user_version = ${SCHEMA_VERSION}`);
      });
      migrate.immediate();
    } finally {
      this.sqlite.pragma("foreign_keys = ON");
    }
    this.finishMigrationRecord();
  }

  private migrateV4Schema(nowMs: number, backup: MigrationBackup | undefined): void {
    this.sqlite.pragma("foreign_keys = OFF");
    try {
      const migrate = this.sqlite.transaction(() => {
        this.sqlite.exec(
          "alter table operation_authority_resource_leases rename to legacy_v4_operation_authority_resource_leases",
        );
        this.sqlite.exec("drop index if exists operation_authority_resource_leases_task_idx");
        this.sqlite.exec(
          "alter table operation_authorities add column grant_active integer not null default 0 check (grant_active in (0, 1))",
        );
        this.ensureMigrationColumns();
        this.sqlite.exec(`
          with ranked as (
            select a.authority_id,
                   row_number() over (
                     partition by a.principal_key_fingerprint, a.task_instance_id,
                                  a.correction_epoch, a.fingerprint
                     order by exists (
                       select 1 from operation_authority_claims c
                        where c.authority_id = a.authority_id
                          and c.state in ('CLAIMED', 'DISPATCHED', 'UNCERTAIN')
                     ) desc, a.created_at_ms desc, a.authority_id desc
                   ) as rank
              from operation_authorities a
          )
          update operation_authorities
             set grant_active = case when authority_id in (
               select authority_id from ranked where rank = 1
             ) then 1 else 0 end;
          update operation_authority_claims
             set state = 'UNCERTAIN', completed_at_ms = ${Number(nowMs)},
                 provider_call_count = case when state = 'DISPATCHED' then 1 else 0 end,
                 error_code = 'PROCESS_RESTARTED',
                 reason_code = 'V4_NONTERMINAL_CLAIM_MIGRATED'
           where state in ('CLAIMED', 'DISPATCHED');
        `);
        this.createSchema();
        this.ensureClaimAuditColumns();
        this.sqlite.prepare(
          `insert into operation_authority_v4_lease_quarantine (
             resource_key_sha256, action_claim_id, quarantined_at_ms,
             reason, backup_sha256
           )
           select l.resource_key_sha256, l.action_claim_id, ?, ?, ?
             from legacy_v4_operation_authority_resource_leases l
            where l.lease_state != 'RELEASED'
              and not exists (
                select 1 from operation_authority_claims c
                 where c.action_claim_id = l.action_claim_id
                   and c.authority_id = l.authority_id
                   and c.action_id = l.action_id
                   and c.task_instance_id = l.task_instance_id
                   and c.principal_key_fingerprint = l.principal_key_fingerprint
                   and c.resource_key_sha256 = l.resource_key_sha256
                   and c.fencing_token = l.fencing_token
              )`,
        ).run(
          nowMs,
          "LEGACY_V4_LEASE_CLAIM_MISMATCH",
          backup?.sha256 ?? null,
        );
        this.sqlite.exec(`
          insert into operation_authority_resource_leases (
            resource_key_sha256, task_instance_id, principal_key_fingerprint,
            authority_id, action_id, action_claim_id, fencing_token,
            lease_state, owner_instance_id, acquired_at_ms, heartbeat_at_ms,
            expires_at_ms, updated_at_ms, reconciliation_state,
            reconciliation_outcome, reconciliation_evidence_sha256,
            reconciled_at_ms, recovery_reason
          )
          select l.resource_key_sha256, l.task_instance_id,
                 l.principal_key_fingerprint, l.authority_id, l.action_id,
                 l.action_claim_id, l.fencing_token, 'RECOVERY_REQUIRED',
                 c.owner_instance_id, l.acquired_at_ms, ${Number(nowMs)},
                 ${Number(nowMs)}, ${Number(nowMs)}, 'PENDING',
                 null, null, null, 'V4_NONTERMINAL_LEASE_MIGRATED'
            from legacy_v4_operation_authority_resource_leases l
            join operation_authority_claims c
              on c.action_claim_id = l.action_claim_id
             and c.authority_id = l.authority_id
             and c.action_id = l.action_id
             and c.task_instance_id = l.task_instance_id
             and c.principal_key_fingerprint = l.principal_key_fingerprint
             and c.resource_key_sha256 = l.resource_key_sha256
             and c.fencing_token = l.fencing_token
           where l.lease_state != 'RELEASED'
             and c.state = 'UNCERTAIN';
        `);
        const quarantined = (this.sqlite.prepare(
          "select count(distinct action_claim_id) as count from operation_authority_v4_lease_quarantine",
        ).get() as { count: number }).count;
        this.insertMigrationRecord(4, nowMs, backup, quarantined);
        this.sqlite.pragma(`user_version = ${SCHEMA_VERSION}`);
      });
      migrate.immediate();
    } finally {
      this.sqlite.pragma("foreign_keys = ON");
    }
    this.finishMigrationRecord();
  }

  private migrateV5Schema(nowMs: number, backup: MigrationBackup | undefined): void {
    this.sqlite.pragma("foreign_keys = OFF");
    try {
      const migrate = this.sqlite.transaction(() => {
        this.sqlite.exec(`
          drop trigger if exists operation_authority_resource_leases_exact_insert;
          drop trigger if exists operation_authority_resource_leases_exact_update;
          drop index if exists operation_authority_resource_leases_task_idx;
          alter table operation_authority_resource_leases
            rename to legacy_v5_operation_authority_resource_leases;
        `);
        this.createSchema();
        this.ensureClaimAuditColumns();
        this.sqlite.prepare(`
          insert into operation_authority_resource_leases (
            resource_key_sha256, task_instance_id, principal_key_fingerprint,
            authority_id, action_id, action_claim_id, fencing_token,
            lease_state, owner_instance_id, acquired_at_ms, heartbeat_at_ms,
            expires_at_ms, updated_at_ms, reconciliation_state,
            reconciliation_outcome, reconciliation_evidence_sha256,
            reconciled_at_ms, recovery_reason
          )
          select l.resource_key_sha256, l.task_instance_id,
                 l.principal_key_fingerprint, l.authority_id, l.action_id,
                 l.action_claim_id, l.fencing_token,
                 case when l.lease_state = 'FROZEN'
                      then 'RECOVERY_REQUIRED' else 'ACTIVE' end,
                 c.owner_instance_id, l.acquired_at_ms, l.updated_at_ms,
                 l.updated_at_ms + ?, l.updated_at_ms,
                 case when l.lease_state = 'FROZEN'
                      then 'PENDING' else 'NOT_REQUIRED' end,
                 null, null, null,
                 case when l.lease_state = 'FROZEN'
                      then 'V5_FROZEN_LEASE_MIGRATED' else null end
            from legacy_v5_operation_authority_resource_leases l
            join operation_authority_claims c
              on c.action_claim_id = l.action_claim_id
             and c.authority_id = l.authority_id
             and c.action_id = l.action_id
             and c.task_instance_id = l.task_instance_id
             and c.principal_key_fingerprint = l.principal_key_fingerprint
             and c.resource_key_sha256 = l.resource_key_sha256
             and c.fencing_token = l.fencing_token
        `).run(this.resourceLeaseTtlMs);
        const recoveryRequired = (this.sqlite.prepare(
          `select count(*) as count
             from operation_authority_resource_leases
            where lease_state = 'RECOVERY_REQUIRED'`,
        ).get() as { count: number }).count;
        this.sqlite.exec("drop table legacy_v5_operation_authority_resource_leases");
        this.insertMigrationRecord(5, nowMs, backup, recoveryRequired);
        this.sqlite.pragma(`user_version = ${SCHEMA_VERSION}`);
      });
      migrate.immediate();
    } finally {
      this.sqlite.pragma("foreign_keys = ON");
    }
    this.finishMigrationRecord();
  }

  private migrateV6Schema(nowMs: number, backup: MigrationBackup | undefined): void {
    const migrate = this.sqlite.transaction(() => {
      this.ensureClaimAuditColumns();
      this.insertMigrationRecord(6, nowMs, backup, 0);
      this.sqlite.pragma(`user_version = ${SCHEMA_VERSION}`);
    });
    migrate.immediate();
    this.finishMigrationRecord();
  }

  private createMigrationBackup(path: string): MigrationBackup {
    const sourceIntegrityCheck = String(this.sqlite.pragma("integrity_check", { simple: true }));
    const sourceForeignKeys = this.sqlite.pragma("foreign_key_check") as unknown[];
    if (sourceIntegrityCheck !== "ok" || sourceForeignKeys.length > 0) {
      throw new Error("Authority store failed pre-migration integrity validation.");
    }
    this.sqlite.pragma("wal_checkpoint(FULL)");
    const backupPath = `${path}.pre-v${SCHEMA_VERSION}-${randomUUID()}.sqlite`;
    this.sqlite.exec(`vacuum into ${sqlLiteral(backupPath)}`);
    chmodSync(backupPath, 0o600);
    const backup = new Database(backupPath, { readonly: true, fileMustExist: true });
    let backupIntegrityCheck: string;
    let foreignKeyViolations: number;
    try {
      backupIntegrityCheck = String(backup.pragma("integrity_check", { simple: true }));
      foreignKeyViolations = (backup.pragma("foreign_key_check") as unknown[]).length;
    } finally {
      backup.close();
    }
    if (backupIntegrityCheck !== "ok" || foreignKeyViolations > 0) {
      throw new Error("Authority store migration backup failed integrity validation.");
    }
    return {
      path: backupPath,
      sha256: createHash("sha256").update(readFileSync(backupPath)).digest("hex"),
      sourceIntegrityCheck,
      backupIntegrityCheck,
    };
  }

  private registerOwnerRun(nowMs: number): void {
    const processStartKeySha256 = currentProcessStartKeySha256();
    const register = this.sqlite.transaction(() => {
      this.sqlite.prepare(
        `insert into operation_authority_owner_runs (
           owner_run_id, host_identity_sha256, process_id,
           process_start_key_sha256, run_state, registered_at_ms,
           heartbeat_at_ms, lease_deadline_ms, closed_at_ms
         ) values (?, ?, ?, ?, 'ACTIVE', ?, ?, ?, null)
         on conflict(owner_run_id) do update set
           host_identity_sha256 = excluded.host_identity_sha256,
           process_id = excluded.process_id,
           process_start_key_sha256 = excluded.process_start_key_sha256,
           run_state = 'ACTIVE', registered_at_ms = excluded.registered_at_ms,
           heartbeat_at_ms = excluded.heartbeat_at_ms,
           lease_deadline_ms = excluded.lease_deadline_ms,
           closed_at_ms = null
         where operation_authority_owner_runs.run_state = 'CLOSED'`,
      ).run(
        this.instanceId,
        HOST_IDENTITY_SHA256,
        process.pid,
        processStartKeySha256,
        nowMs,
        nowMs,
        nowMs + this.ownerRunLeaseMs,
      );
      const row = this.ownerRun(this.instanceId);
      if (
        !row
        || row.run_state !== "ACTIVE"
        || row.host_identity_sha256 !== HOST_IDENTITY_SHA256
        || row.process_id !== process.pid
        || row.process_start_key_sha256 !== processStartKeySha256
      ) {
        throw new Error("Authority owner run identity is already active in another process.");
      }
    });
    register.immediate();
  }

  private touchOwnerRun(nowMs: number): void {
    const touched = this.sqlite.prepare(
      `update operation_authority_owner_runs
          set heartbeat_at_ms = ?, lease_deadline_ms = ?
        where owner_run_id = ? and run_state = 'ACTIVE'`,
    ).run(nowMs, nowMs + this.ownerRunLeaseMs, this.instanceId);
    if (touched.changes !== 1) {
      throw new Error("Authority owner run is no longer active.");
    }
  }

  private recoverNonterminalClaims(nowMs: number): number {
    const recoveryCutoffMs = nowMs - this.resourceLeaseRecoveryGraceMs;
    const rows = this.sqlite.prepare(
      `select c.authority_id, c.action_claim_id, c.action_id,
              c.resource_key_sha256, c.fencing_token,
              c.owner_instance_id, c.state,
              l.owner_instance_id as lease_owner_instance_id,
              l.lease_state, l.expires_at_ms as resource_expires_at_ms,
              o.host_identity_sha256, o.process_id,
              o.process_start_key_sha256, o.run_state,
              o.registered_at_ms, o.heartbeat_at_ms,
              o.lease_deadline_ms, o.closed_at_ms
         from operation_authority_claims c
         left join operation_authority_owner_runs o
           on o.owner_run_id = c.owner_instance_id
         left join operation_authority_resource_leases l
           on l.resource_key_sha256 = c.resource_key_sha256
          and l.action_claim_id = c.action_claim_id
          and l.fencing_token = c.fencing_token
        where c.state in ('CLAIMED', 'DISPATCHED')
        order by c.claimed_at_ms, c.action_claim_id`,
    ).all() as Array<{
      authority_id: string;
      action_claim_id: string;
      action_id: string;
      resource_key_sha256: string;
      fencing_token: number;
      owner_instance_id: string;
      state: "CLAIMED" | "DISPATCHED";
      lease_owner_instance_id: string | null;
      lease_state: DurableResourceLeaseState | null;
      resource_expires_at_ms: number | null;
      host_identity_sha256: string | null;
      process_id: number | null;
      process_start_key_sha256: string | null;
      run_state: "ACTIVE" | "CLOSED" | null;
      registered_at_ms: number | null;
      heartbeat_at_ms: number | null;
      lease_deadline_ms: number | null;
      closed_at_ms: number | null;
    }>;
    const recoverable = rows.filter((row) => (
      row.lease_state === "ACTIVE"
      && row.lease_owner_instance_id === row.owner_instance_id
      && row.resource_expires_at_ms !== null
      && row.resource_expires_at_ms <= recoveryCutoffMs
      && ownerRunIsVerifiedDead(row, nowMs)
    ));
    if (recoverable.length === 0) return 0;
    const recover = this.sqlite.transaction(() => {
      let recovered = 0;
      for (const row of recoverable) {
        const currentOwner = this.ownerRun(row.owner_instance_id);
        if (!currentOwner || !ownerRunIsVerifiedDead(currentOwner, nowMs)) continue;
        if (!this.currentLeaseMatches({
          authorityId: row.authority_id,
          actionClaimId: row.action_claim_id,
          resourceKeySha256: row.resource_key_sha256,
          fencingToken: row.fencing_token,
        }, "ACTIVE", row.owner_instance_id)) continue;
        if (row.state === "CLAIMED") {
          const claim = this.sqlite.prepare(
            `update operation_authority_claims
                set state = 'CANCELLED_NOT_DISPATCHED', completed_at_ms = ?,
                    provider_call_count = 0, error_code = null,
                    reason_code = 'OWNER_RUN_DEAD_BEFORE_DISPATCH',
                    cancellation_proof_code = 'DURABLE_DISPATCH_BARRIER_ZERO'
              where authority_id = ? and action_claim_id = ?
                and resource_key_sha256 = ? and fencing_token = ?
                and owner_instance_id = ? and state = 'CLAIMED'`,
          ).run(
            nowMs,
            row.authority_id,
            row.action_claim_id,
            row.resource_key_sha256,
            row.fencing_token,
            row.owner_instance_id,
          );
          if (claim.changes !== 1) continue;
          const reclaimed = this.sqlite.prepare(
            `update operation_authority_actions
                set consumed_uses = consumed_uses - 1
              where authority_id = ? and action_id = ? and consumed_uses > 0`,
          ).run(row.authority_id, row.action_id);
          const reconciliationDigest = createHash("sha256")
            .update(`dispatch-barrier-zero\0${row.action_claim_id}\0${row.fencing_token}`)
            .digest("hex");
          const released = this.sqlite.prepare(
            `update operation_authority_resource_leases
                set lease_state = 'RELEASED', updated_at_ms = ?,
                    reconciliation_state = 'VERIFIED',
                    reconciliation_outcome = 'RESOURCE_VERIFIED',
                    reconciliation_evidence_sha256 = ?, reconciled_at_ms = ?,
                    recovery_reason = 'OWNER_RUN_DEAD_BEFORE_DISPATCH'
              where resource_key_sha256 = ? and action_claim_id = ?
                and fencing_token = ? and lease_state = 'ACTIVE'
                and owner_instance_id = ? and expires_at_ms <= ?`,
          ).run(
            nowMs,
            reconciliationDigest,
            nowMs,
            row.resource_key_sha256,
            row.action_claim_id,
            row.fencing_token,
            row.owner_instance_id,
            recoveryCutoffMs,
          );
          if (reclaimed.changes !== 1 || released.changes !== 1) {
            throw new Error("Dead CLAIMED owner could not atomically reclaim its use and lease.");
          }
        } else {
          const claim = this.sqlite.prepare(
            `update operation_authority_claims
                set state = 'UNCERTAIN', completed_at_ms = ?,
                    provider_call_count = 1,
                    error_code = 'PROCESS_RESTARTED',
                    reason_code = 'NONTERMINAL_CLAIM_RECOVERED'
              where authority_id = ? and action_claim_id = ?
                and resource_key_sha256 = ? and fencing_token = ?
                and owner_instance_id = ? and state = 'DISPATCHED'`,
          ).run(
            nowMs,
            row.authority_id,
            row.action_claim_id,
            row.resource_key_sha256,
            row.fencing_token,
            row.owner_instance_id,
          );
          if (claim.changes !== 1) continue;
          const lease = this.sqlite.prepare(
            `update operation_authority_resource_leases
                set lease_state = 'RECOVERY_REQUIRED', updated_at_ms = ?,
                    reconciliation_state = 'PENDING',
                    recovery_reason = 'NONTERMINAL_CLAIM_RECOVERED'
              where resource_key_sha256 = ? and action_claim_id = ?
                and fencing_token = ? and lease_state = 'ACTIVE'
                and owner_instance_id = ? and expires_at_ms <= ?`,
          ).run(
            nowMs,
            row.resource_key_sha256,
            row.action_claim_id,
            row.fencing_token,
            row.owner_instance_id,
            recoveryCutoffMs,
          );
          if (lease.changes !== 1) {
            throw new Error("Recovered DISPATCHED claim could not enter resource reconciliation.");
          }
        }
        recovered += 1;
      }
      return recovered;
    });
    return recover.immediate();
  }

  private ownerRun(ownerRunId: string): OwnerRunRow | undefined {
    return this.sqlite.prepare(
      `select owner_run_id, host_identity_sha256, process_id,
              process_start_key_sha256, run_state, registered_at_ms,
              heartbeat_at_ms, lease_deadline_ms, closed_at_ms
         from operation_authority_owner_runs where owner_run_id = ?`,
    ).get(ownerRunId) as OwnerRunRow | undefined;
  }

  private currentLeaseMatches(
    input: {
      authorityId: string;
      actionClaimId: string;
      resourceKeySha256: string;
      fencingToken: number;
    },
    expectedState: DurableResourceLeaseState,
    expectedOwnerInstanceId?: string,
  ): boolean {
    const lease = this.sqlite.prepare(
      `select authority_id, action_claim_id, fencing_token, lease_state, owner_instance_id
         from operation_authority_resource_leases where resource_key_sha256 = ?`,
    ).get(input.resourceKeySha256) as {
      authority_id: string;
      action_claim_id: string;
      fencing_token: number;
      lease_state: DurableResourceLeaseState;
      owner_instance_id: string;
    } | undefined;
    return Boolean(
      lease
      && lease.authority_id === input.authorityId
      && lease.action_claim_id === input.actionClaimId
      && lease.fencing_token === input.fencingToken
      && lease.lease_state === expectedState
      && (expectedOwnerInstanceId === undefined || lease.owner_instance_id === expectedOwnerInstanceId)
    );
  }

  private pruneTerminalClaims(authorityId: string, maximumReceipts: number): void {
    const nonterminal = this.sqlite.prepare(
      `select count(*) as count from operation_authority_claims
        where authority_id = ? and state in ('CLAIMED', 'DISPATCHED')`,
    ).get(authorityId) as { count: number };
    const terminalCapacity = Math.max(0, maximumReceipts - nonterminal.count);
    this.sqlite.prepare(
      `delete from operation_authority_claims where action_claim_id in (
        select c.action_claim_id from operation_authority_claims c
         where c.authority_id = ?
           and c.state in ('PASS', 'FAIL', 'CANCELLED_NOT_DISPATCHED')
           and not exists (
             select 1 from operation_authority_resource_leases l
              where l.action_claim_id = c.action_claim_id
                and l.resource_key_sha256 = c.resource_key_sha256
                and l.fencing_token = c.fencing_token
                and l.lease_state != 'RELEASED'
           )
         order by coalesce(c.completed_at_ms, c.claimed_at_ms) desc,
                  c.action_claim_id desc limit -1 offset ?
      )`,
    ).run(authorityId, terminalCapacity);
  }

  private upsertMigratedFrozenLease(input: {
    resourceKey: string;
    actionClaimId: string;
    authorityId: string;
    actionId: string;
    taskInstanceId: string;
    principalKeyFingerprint: string;
    ownerInstanceId: string;
    fencingToken: number;
    nowMs: number;
  }): void {
    this.sqlite.prepare(
      `insert into operation_authority_resource_leases (
         resource_key_sha256, task_instance_id, principal_key_fingerprint,
         authority_id, action_id, action_claim_id, fencing_token,
         lease_state, owner_instance_id, acquired_at_ms, heartbeat_at_ms,
         expires_at_ms, updated_at_ms, reconciliation_state,
         reconciliation_outcome, reconciliation_evidence_sha256,
         reconciled_at_ms, recovery_reason
       ) values (?, ?, ?, ?, ?, ?, ?, 'RECOVERY_REQUIRED', ?, ?, ?, ?, ?,
                 'PENDING', null, null, null, 'LEGACY_NONTERMINAL_LEASE_MIGRATED')
       on conflict(resource_key_sha256) do update set
         task_instance_id = excluded.task_instance_id,
         principal_key_fingerprint = excluded.principal_key_fingerprint,
         authority_id = excluded.authority_id,
         action_id = excluded.action_id,
         action_claim_id = excluded.action_claim_id,
         fencing_token = excluded.fencing_token,
         lease_state = 'RECOVERY_REQUIRED',
         owner_instance_id = excluded.owner_instance_id,
         acquired_at_ms = excluded.acquired_at_ms,
         heartbeat_at_ms = excluded.heartbeat_at_ms,
         expires_at_ms = excluded.expires_at_ms,
         updated_at_ms = excluded.updated_at_ms,
         reconciliation_state = 'PENDING',
         reconciliation_outcome = null,
         reconciliation_evidence_sha256 = null,
         reconciled_at_ms = null,
         recovery_reason = excluded.recovery_reason
       where excluded.fencing_token > operation_authority_resource_leases.fencing_token`,
    ).run(
      input.resourceKey,
      input.taskInstanceId,
      input.principalKeyFingerprint,
      input.authorityId,
      input.actionId,
      input.actionClaimId,
      input.fencingToken,
      input.ownerInstanceId,
      input.nowMs,
      input.nowMs,
      input.nowMs,
      input.nowMs,
    );
  }

  private insertMigrationRecord(
    fromVersion: number,
    nowMs: number,
    backup: MigrationBackup | undefined,
    quarantinedAuthorities: number,
  ): void {
    this.sqlite.prepare(
      `insert into operation_authority_migrations (
         migration_id, from_schema_version, to_schema_version,
         migrated_at_ms, backup_path, backup_sha256,
         quarantined_authorities, source_integrity_check,
         backup_integrity_check, post_integrity_check,
         foreign_key_violations
       ) values (?, ?, ?, ?, ?, ?, ?, ?, ?, 'pending', 0)`,
    ).run(
      `authority_migration_${randomUUID()}`,
      fromVersion,
      SCHEMA_VERSION,
      nowMs,
      backup?.path ?? null,
      backup?.sha256 ?? null,
      quarantinedAuthorities,
      backup?.sourceIntegrityCheck ?? "ok",
      backup?.backupIntegrityCheck ?? "ok",
    );
  }

  private finishMigrationRecord(): void {
    const postIntegrityCheck = String(this.sqlite.pragma("integrity_check", { simple: true }));
    const foreignKeyViolations = (this.sqlite.pragma("foreign_key_check") as unknown[]).length;
    this.sqlite.prepare(
      `update operation_authority_migrations
          set post_integrity_check = ?, foreign_key_violations = ?
        where rowid = (select max(rowid) from operation_authority_migrations)`,
    ).run(postIntegrityCheck, foreignKeyViolations);
    if (postIntegrityCheck !== "ok" || foreignKeyViolations > 0) {
      throw new Error("Authority store failed post-migration integrity validation.");
    }
  }

  private ensureClaimAuditColumns(): void {
    for (const [name, definition] of [
      [
        "audit_state",
        "text check (audit_state is null or audit_state in ('RECORDED', 'SINK_FAILED'))",
      ],
      [
        "audit_event_digest",
        `text check (
          audit_event_digest is null
          or (length(audit_event_digest) = 71 and substr(audit_event_digest, 1, 7) = 'sha256:')
        )`,
      ],
      [
        "audit_receipt_digest",
        `text check (
          audit_receipt_digest is null
          or (length(audit_receipt_digest) = 71 and substr(audit_receipt_digest, 1, 7) = 'sha256:')
        )`,
      ],
      ["audit_recorded_at_ms", "integer"],
      ["audit_error_code", "text"],
    ] as const) {
      if (!this.columnExists("operation_authority_claims", name)) {
        this.sqlite.exec(
          `alter table operation_authority_claims add column ${name} ${definition}`,
        );
      }
    }
  }

  private ensureMigrationColumns(): void {
    for (const [name, definition] of [
      ["source_integrity_check", "text not null default 'ok'"],
      ["backup_integrity_check", "text not null default 'ok'"],
      ["post_integrity_check", "text not null default 'ok'"],
      ["foreign_key_violations", "integer not null default 0"],
    ] as const) {
      if (!this.columnExists("operation_authority_migrations", name)) {
        this.sqlite.exec(
          `alter table operation_authority_migrations add column ${name} ${definition}`,
        );
      }
    }
  }

  private validateRequiredSchema(): void {
    const requiredColumns: Record<string, readonly string[]> = {
      operation_authority_tasks: ["task_instance_id", "principal_key_fingerprint", "correction_epoch"],
      operation_authorities: ["authority_id", "task_instance_id", "principal_key_fingerprint"],
      operation_authority_actions: ["authority_id", "action_id", "resource_key_sha256", "consumed_uses"],
      operation_authority_claims: [
        "action_claim_id",
        "resource_key_sha256",
        "fencing_token",
        "state",
        "audit_state",
        "audit_event_digest",
        "audit_receipt_digest",
      ],
      operation_authority_resource_fences: ["resource_key_sha256", "last_fencing_token"],
      operation_authority_resource_leases: [
        "resource_key_sha256",
        "action_claim_id",
        "lease_state",
        "owner_instance_id",
        "heartbeat_at_ms",
        "expires_at_ms",
        "reconciliation_state",
      ],
    };
    for (const [table, columns] of Object.entries(requiredColumns)) {
      if (!this.tableExists(table)) {
        throw new Error(`Authority store schema ${SCHEMA_VERSION} is missing required table ${table}.`);
      }
      for (const column of columns) {
        if (!this.columnExists(table, column)) {
          throw new Error(
            `Authority store schema ${SCHEMA_VERSION} table ${table} is missing ${column}.`,
          );
        }
      }
    }
  }

  private validateDatabase(label: string): void {
    this.validateRequiredSchema();
    const integrity = String(this.sqlite.pragma("integrity_check", { simple: true }));
    const foreignKeys = this.sqlite.pragma("foreign_key_check") as unknown[];
    if (integrity !== "ok" || foreignKeys.length > 0) {
      throw new Error(`Authority store ${label} integrity validation failed.`);
    }
  }

  private persistAuthority(authority: DurableAuthorityRecord): void {
    const task = this.taskRow(authority.taskInstanceId);
    if (
      !task
      || task.principal_key_fingerprint !== authority.principalKeyFingerprint
      || task.correction_epoch !== authority.correctionEpoch
    ) {
      throw new Error("Refusing to persist an authority from a stale or mismatched task.");
    }
    this.sqlite.prepare(
      `insert into operation_authorities (
         authority_id, task_instance_id, task_label_sha256,
         authority_text_sha256, principal_key_fingerprint,
         approval_assurance, correction_epoch, created_at_ms,
         expires_at_ms, fingerprint, grant_active
       ) values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1)
       on conflict(authority_id) do nothing`,
    ).run(
      authority.authorityId,
      authority.taskInstanceId,
      authority.taskLabelSha256 ?? null,
      authority.authorityTextSha256,
      authority.principalKeyFingerprint,
      authority.approvalAssurance,
      authority.correctionEpoch,
      authority.createdAtMs,
      authority.expiresAtMs,
      authority.fingerprint,
    );
    const persisted = this.sqlite.prepare(
      `select task_instance_id, principal_key_fingerprint,
              correction_epoch, fingerprint
         from operation_authorities where authority_id = ?`,
    ).get(authority.authorityId) as {
      task_instance_id: string;
      principal_key_fingerprint: string;
      correction_epoch: number;
      fingerprint: string;
    } | undefined;
    if (
      !persisted
      || persisted.task_instance_id !== authority.taskInstanceId
      || persisted.principal_key_fingerprint !== authority.principalKeyFingerprint
      || persisted.correction_epoch !== authority.correctionEpoch
      || persisted.fingerprint !== authority.fingerprint
    ) {
      throw new Error("Refusing to overwrite a different durable authority grant.");
    }
    const insertAction = this.sqlite.prepare(
      `insert into operation_authority_actions (
         authority_id, action_id, ordinal, tool, operation, fingerprint,
         resource_key_sha256, minimum_risk, risk, maximum_uses,
         consumed_uses
       ) values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
       on conflict(authority_id, action_id) do nothing`,
    );
    authority.actions.forEach((action, ordinal) => {
      assertSha256(action.resourceKeySha256, "resourceKeySha256");
      insertAction.run(
        authority.authorityId,
        action.id,
        ordinal,
        action.tool,
        action.operation,
        action.fingerprint,
        action.resourceKeySha256,
        action.minimumRisk,
        action.risk,
        action.maximumUses,
        action.consumedUses,
      );
      const current = this.sqlite.prepare(
        `select fingerprint, resource_key_sha256, maximum_uses
           from operation_authority_actions
          where authority_id = ? and action_id = ?`,
      ).get(authority.authorityId, action.id) as {
        fingerprint: string;
        resource_key_sha256: string;
        maximum_uses: number;
      } | undefined;
      if (
        !current
        || current.fingerprint !== action.fingerprint
        || current.resource_key_sha256 !== action.resourceKeySha256
        || current.maximum_uses !== action.maximumUses
      ) {
        throw new Error("Refusing to overwrite a different durable authority action.");
      }
    });
  }

  private taskRow(taskInstanceId: string): TaskRow | undefined {
    return this.sqlite.prepare(
      `select task_instance_id, principal_key_fingerprint, task_label_sha256,
              correction_epoch, created_at_ms, updated_at_ms
         from operation_authority_tasks where task_instance_id = ?`,
    ).get(taskInstanceId) as TaskRow | undefined;
  }

  private tableExists(name: string): boolean {
    return Boolean(this.sqlite.prepare(
      "select 1 from sqlite_master where type = 'table' and name = ?",
    ).get(name));
  }

  private columnExists(table: string, column: string): boolean {
    return (this.sqlite.pragma(`table_info(${table})`) as Array<{ name: string }>)
      .some((candidate) => candidate.name === column);
  }
}

function taskFromRow(row: TaskRow): DurableAuthorityTaskRecord {
  return {
    taskInstanceId: row.task_instance_id,
    principalKeyFingerprint: row.principal_key_fingerprint,
    ...(row.task_label_sha256 ? { taskLabelSha256: row.task_label_sha256 } : {}),
    correctionEpoch: row.correction_epoch,
    createdAtMs: row.created_at_ms,
    updatedAtMs: row.updated_at_ms,
  };
}

function legacyV3ResourceKey(actionFingerprint: string): string {
  return createHash("sha256")
    .update(`quarantined-v3-resource:${actionFingerprint}`)
    .digest("hex");
}

function currentProcessStartKeySha256(): string {
  const observed = observeProcessIdentity(process.pid);
  if (observed.state === "ALIVE" && observed.startKeySha256) {
    return observed.startKeySha256;
  }
  return createHash("sha256")
    .update(`unverifiable-process-start\0${process.pid}\0${randomUUID()}`)
    .digest("hex");
}

function ownerRunIsVerifiedDead(
  row: {
    host_identity_sha256: string | null;
    process_id: number | null;
    process_start_key_sha256: string | null;
    run_state: "ACTIVE" | "CLOSED" | null;
    lease_deadline_ms: number | null;
  },
  nowMs: number,
): boolean {
  if (row.run_state === "CLOSED") return true;
  if (
    row.run_state !== "ACTIVE"
    || row.host_identity_sha256 !== HOST_IDENTITY_SHA256
    || row.process_id === null
    || row.process_start_key_sha256 === null
    || row.lease_deadline_ms === null
    || row.lease_deadline_ms > nowMs
  ) return false;
  const observed = observeProcessIdentity(row.process_id);
  if (observed.state === "DEAD") return true;
  if (observed.state !== "ALIVE" || !observed.startKeySha256) return false;
  return observed.startKeySha256 !== row.process_start_key_sha256;
}

function observeProcessIdentity(processId: number): {
  state: "ALIVE" | "DEAD" | "UNKNOWN";
  startKeySha256?: string;
} {
  try {
    process.kill(processId, 0);
  } catch (error) {
    const code = error && typeof error === "object" && "code" in error
      ? String(error.code)
      : undefined;
    if (code === "ESRCH") return { state: "DEAD" };
    if (code !== "EPERM") return { state: "UNKNOWN" };
  }
  try {
    let startKey: string;
    if (platform() === "linux") {
      const stat = readFileSync(`/proc/${processId}/stat`, "utf8");
      const tail = stat.slice(stat.lastIndexOf(")") + 2).trim().split(/\s+/u);
      const kernelStartTicks = tail[19];
      if (!kernelStartTicks) return { state: "UNKNOWN" };
      startKey = `linux-start-ticks:${kernelStartTicks}`;
    } else {
      const started = execFileSync(
        "/bin/ps",
        ["-o", "lstart=", "-p", String(processId)],
        { encoding: "utf8", stdio: ["ignore", "pipe", "ignore"] },
      ).trim();
      if (!started) return { state: "UNKNOWN" };
      startKey = `${platform()}-ps-lstart:${started}`;
    }
    return {
      state: "ALIVE",
      startKeySha256: createHash("sha256").update(startKey).digest("hex"),
    };
  } catch {
    try {
      process.kill(processId, 0);
      return { state: "UNKNOWN" };
    } catch (error) {
      const code = error && typeof error === "object" && "code" in error
        ? String(error.code)
        : undefined;
      return code === "ESRCH" ? { state: "DEAD" } : { state: "UNKNOWN" };
    }
  }
}

function assertSha256(value: string, name: string): void {
  if (!HASH_PATTERN.test(value)) throw new Error(`${name} must be a SHA-256 hex digest.`);
}

function assertSha256Digest(value: string | undefined, name: string): string {
  if (!value || !SHA256_DIGEST_PATTERN.test(value)) {
    throw new Error(`${name} must be a SHA-256 digest.`);
  }
  return value;
}

function safeCode(value: string | undefined): string | null {
  if (!value) return null;
  return /^[A-Z][A-Z0-9_.:-]{0,127}$/u.test(value) ? value : null;
}

function sqlLiteral(value: string): string {
  return `'${value.replaceAll("'", "''")}'`;
}
