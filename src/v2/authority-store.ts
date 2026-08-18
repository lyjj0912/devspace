import { randomUUID } from "node:crypto";
import { chmodSync, mkdirSync } from "node:fs";
import { dirname } from "node:path";
import Database from "better-sqlite3";

export interface DurableAuthorityActionRecord {
  id: string;
  tool: string;
  operation: string;
  fingerprint: string;
  minimumRisk: string;
  risk: string;
  maximumUses: number;
  consumedUses: number;
}

export interface DurableAuthorityReceiptRecord {
  useId: string;
  actionId: string;
  reservedAtMs: number;
  completedAtMs?: number;
  result: "PENDING" | "PASS" | "FAIL" | "UNCERTAIN";
  errorCode?: string;
  reasonCode?: string;
}

export interface DurableAuthorityRecord {
  authorityId: string;
  taskIdSha256: string;
  authorityTextSha256: string;
  scopeKey: string;
  correctionEpoch: number;
  createdAtMs: number;
  expiresAtMs: number;
  fingerprint: string;
  actions: DurableAuthorityActionRecord[];
  receipts: DurableAuthorityReceiptRecord[];
}

export interface DurableAuthoritySnapshot {
  authorities: DurableAuthorityRecord[];
  correctionEpochs: Map<string, number>;
  recoveredPendingUses: number;
}

export type DurableAuthorityReservationResult =
  | { ok: true; consumedUses: number }
  | {
      ok: false;
      code: "AUTHORITY_EXPIRED" | "AUTHORITY_MISMATCH" | "AUTHORITY_CONSUMED" | "RESOURCE_QUOTA_EXCEEDED";
      consumedUses?: number;
    };

export type DurableAuthorityReleaseResult =
  | { ok: true }
  | {
      ok: false;
      code: "AUTHORITY_EXPIRED" | "AUTHORITY_MISMATCH" | "PRECONDITION_FAILED";
      pendingReceipts?: number;
    };

interface AuthorityRow {
  authority_id: string;
  task_id_sha256: string;
  authority_text_sha256: string;
  scope_key: string;
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
  minimum_risk: string;
  risk: string;
  maximum_uses: number;
  consumed_uses: number;
}

interface ReceiptRow {
  authority_id: string;
  use_id: string;
  action_id: string;
  reserved_at_ms: number;
  completed_at_ms: number | null;
  result: "PENDING" | "PASS" | "FAIL" | "UNCERTAIN";
  error_code: string | null;
  reason_code: string | null;
}

interface ScopeRow {
  scope_key: string;
  correction_epoch: number;
}

const SCHEMA_VERSION = 2;
const PROCESS_INSTANCE_ID = `authority_process_${randomUUID()}`;

export class DurableAuthorityStore {
  private readonly sqlite: Database.Database;
  private readonly instanceId: string;
  private readonly recoveredPendingUses: number;

  constructor(path: string | undefined, nowMs: number, instanceId = PROCESS_INSTANCE_ID) {
    this.instanceId = instanceId;
    if (path) {
      mkdirSync(dirname(path), { recursive: true, mode: 0o700 });
    }
    this.sqlite = new Database(path ?? ":memory:");
    if (path) chmodSync(path, 0o600);
    this.sqlite.pragma("journal_mode = WAL");
    this.sqlite.pragma("synchronous = FULL");
    this.sqlite.pragma("busy_timeout = 5000");
    this.sqlite.pragma("foreign_keys = ON");
    this.initializeSchema();
    this.recoveredPendingUses = this.recoverPendingReservations(nowMs);
  }

  load(): DurableAuthoritySnapshot {
    const authorities = new Map<string, DurableAuthorityRecord>();
    for (const row of this.sqlite.prepare(
      `select authority_id, task_id_sha256, authority_text_sha256, scope_key,
              correction_epoch, created_at_ms, expires_at_ms, fingerprint
         from operation_authorities
        order by created_at_ms, authority_id`,
    ).all() as AuthorityRow[]) {
      authorities.set(row.authority_id, {
        authorityId: row.authority_id,
        taskIdSha256: row.task_id_sha256,
        authorityTextSha256: row.authority_text_sha256,
        scopeKey: row.scope_key,
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
              minimum_risk, risk, maximum_uses, consumed_uses
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
        minimumRisk: row.minimum_risk,
        risk: row.risk,
        maximumUses: row.maximum_uses,
        consumedUses: row.consumed_uses,
      });
    }
    for (const row of this.sqlite.prepare(
      `select authority_id, use_id, action_id, reserved_at_ms, completed_at_ms,
              result, error_code, reason_code
         from operation_authority_receipts
        order by authority_id, reserved_at_ms, use_id`,
    ).all() as ReceiptRow[]) {
      const authority = authorities.get(row.authority_id);
      if (!authority) continue;
      authority.receipts.push({
        useId: row.use_id,
        actionId: row.action_id,
        reservedAtMs: row.reserved_at_ms,
        ...(row.completed_at_ms === null ? {} : { completedAtMs: row.completed_at_ms }),
        result: row.result,
        ...(row.error_code ? { errorCode: row.error_code } : {}),
        ...(row.reason_code ? { reasonCode: row.reason_code } : {}),
      });
    }
    const correctionEpochs = new Map<string, number>();
    for (const row of this.sqlite.prepare(
      "select scope_key, correction_epoch from operation_authority_scopes",
    ).all() as ScopeRow[]) {
      correctionEpochs.set(row.scope_key, row.correction_epoch);
    }
    return {
      authorities: [...authorities.values()],
      correctionEpochs,
      recoveredPendingUses: this.recoveredPendingUses,
    };
  }

  saveAuthority(authority: DurableAuthorityRecord): void {
    const persist = this.sqlite.transaction(() => {
      const currentScope = this.sqlite.prepare(
        "select correction_epoch from operation_authority_scopes where scope_key = ?",
      ).get(authority.scopeKey) as { correction_epoch: number } | undefined;
      if (currentScope && currentScope.correction_epoch !== authority.correctionEpoch) {
        throw new Error("Refusing to persist an authority from a stale correction epoch.");
      }
      this.sqlite.prepare(
        `insert into operation_authority_scopes (scope_key, correction_epoch, updated_at_ms)
         values (?, ?, ?)
         on conflict(scope_key) do update set updated_at_ms = excluded.updated_at_ms`,
      ).run(authority.scopeKey, authority.correctionEpoch, authority.createdAtMs);
      this.sqlite.prepare(
        `insert into operation_authorities (
           authority_id, task_id_sha256, authority_text_sha256, scope_key,
           correction_epoch, created_at_ms, expires_at_ms, fingerprint
         ) values (?, ?, ?, ?, ?, ?, ?, ?)
         on conflict(authority_id) do update set
           task_id_sha256 = excluded.task_id_sha256,
           authority_text_sha256 = excluded.authority_text_sha256,
           scope_key = excluded.scope_key,
           correction_epoch = excluded.correction_epoch,
           created_at_ms = excluded.created_at_ms,
           expires_at_ms = excluded.expires_at_ms,
           fingerprint = excluded.fingerprint`,
      ).run(
        authority.authorityId,
        authority.taskIdSha256,
        authority.authorityTextSha256,
        authority.scopeKey,
        authority.correctionEpoch,
        authority.createdAtMs,
        authority.expiresAtMs,
        authority.fingerprint,
      );
      this.sqlite.prepare(
        "delete from operation_authority_receipts where authority_id = ?",
      ).run(authority.authorityId);
      this.sqlite.prepare(
        "delete from operation_authority_actions where authority_id = ?",
      ).run(authority.authorityId);
      const insertAction = this.sqlite.prepare(
        `insert into operation_authority_actions (
           authority_id, action_id, ordinal, tool, operation, fingerprint,
           minimum_risk, risk, maximum_uses, consumed_uses
         ) values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      );
      authority.actions.forEach((action, ordinal) => {
        insertAction.run(
          authority.authorityId,
          action.id,
          ordinal,
          action.tool,
          action.operation,
          action.fingerprint,
          action.minimumRisk,
          action.risk,
          action.maximumUses,
          action.consumedUses,
        );
      });
      const insertReceipt = this.sqlite.prepare(
        `insert into operation_authority_receipts (
           authority_id, use_id, action_id, reserved_at_ms, completed_at_ms,
           result, error_code, reason_code, owner_instance_id
         ) values (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      );
      for (const receipt of authority.receipts) {
        insertReceipt.run(
          authority.authorityId,
          receipt.useId,
          receipt.actionId,
          receipt.reservedAtMs,
          receipt.completedAtMs ?? null,
          receipt.result,
          safeCode(receipt.errorCode),
          safeCode(receipt.reasonCode),
          this.instanceId,
        );
      }
    });
    persist.immediate();
  }

  reserveUse(input: {
    authorityId: string;
    scopeKey: string;
    correctionEpoch: number;
    actionId: string;
    actionFingerprint: string;
    useId: string;
    reservedAtMs: number;
    maximumReceipts: number;
  }): DurableAuthorityReservationResult {
    const reserve = this.sqlite.transaction((): DurableAuthorityReservationResult => {
      const authority = this.sqlite.prepare(
        `select scope_key, correction_epoch, expires_at_ms
           from operation_authorities
          where authority_id = ?`,
      ).get(input.authorityId) as {
        scope_key: string;
        correction_epoch: number;
        expires_at_ms: number;
      } | undefined;
      if (!authority) return { ok: false, code: "AUTHORITY_EXPIRED" };
      if (authority.scope_key !== input.scopeKey) {
        return { ok: false, code: "AUTHORITY_MISMATCH" };
      }
      const scope = this.sqlite.prepare(
        "select correction_epoch from operation_authority_scopes where scope_key = ?",
      ).get(input.scopeKey) as { correction_epoch: number } | undefined;
      if (
        !scope
        || scope.correction_epoch !== input.correctionEpoch
        || authority.correction_epoch !== input.correctionEpoch
      ) {
        return { ok: false, code: "AUTHORITY_EXPIRED" };
      }
      if (authority.expires_at_ms <= input.reservedAtMs) {
        return { ok: false, code: "AUTHORITY_EXPIRED" };
      }
      const pending = this.sqlite.prepare(
        `select count(*) as count
           from operation_authority_receipts
          where authority_id = ? and result = 'PENDING'`,
      ).get(input.authorityId) as { count: number };
      if (pending.count >= input.maximumReceipts) {
        return { ok: false, code: "RESOURCE_QUOTA_EXCEEDED" };
      }
      const action = this.sqlite.prepare(
        `select fingerprint, maximum_uses, consumed_uses
           from operation_authority_actions
          where authority_id = ? and action_id = ?`,
      ).get(input.authorityId, input.actionId) as {
        fingerprint: string;
        maximum_uses: number;
        consumed_uses: number;
      } | undefined;
      if (!action || action.fingerprint !== input.actionFingerprint) {
        return { ok: false, code: "AUTHORITY_MISMATCH" };
      }
      if (action.consumed_uses >= action.maximum_uses) {
        return {
          ok: false,
          code: "AUTHORITY_CONSUMED",
          consumedUses: action.consumed_uses,
        };
      }
      const updated = this.sqlite.prepare(
        `update operation_authority_actions
            set consumed_uses = consumed_uses + 1
          where authority_id = ?
            and action_id = ?
            and fingerprint = ?
            and consumed_uses = ?
            and consumed_uses < maximum_uses`,
      ).run(
        input.authorityId,
        input.actionId,
        input.actionFingerprint,
        action.consumed_uses,
      );
      if (updated.changes !== 1) {
        const current = this.sqlite.prepare(
          `select consumed_uses
             from operation_authority_actions
            where authority_id = ? and action_id = ?`,
        ).get(input.authorityId, input.actionId) as { consumed_uses: number } | undefined;
        return {
          ok: false,
          code: "AUTHORITY_CONSUMED",
          ...(current ? { consumedUses: current.consumed_uses } : {}),
        };
      }
      this.sqlite.prepare(
        `insert into operation_authority_receipts (
           authority_id, use_id, action_id, reserved_at_ms, completed_at_ms,
           result, error_code, reason_code, owner_instance_id
         ) values (?, ?, ?, ?, null, 'PENDING', null, null, ?)`,
      ).run(
        input.authorityId,
        input.useId,
        input.actionId,
        input.reservedAtMs,
        this.instanceId,
      );
      const terminalCapacity = Math.max(0, input.maximumReceipts - pending.count - 1);
      this.sqlite.prepare(
        `delete from operation_authority_receipts
          where use_id in (
            select use_id
              from operation_authority_receipts
             where authority_id = ? and result != 'PENDING'
             order by coalesce(completed_at_ms, reserved_at_ms) desc, use_id desc
             limit -1 offset ?
          )`,
      ).run(input.authorityId, terminalCapacity);
      return { ok: true, consumedUses: action.consumed_uses + 1 };
    });
    return reserve.immediate();
  }

  finalizeUse(input: {
    authorityId: string;
    useId: string;
    completedAtMs: number;
    result: "PASS" | "FAIL" | "UNCERTAIN";
    errorCode?: string;
    reasonCode?: string;
    maximumReceipts: number;
  }): boolean {
    const finalize = this.sqlite.transaction(() => {
      const updated = this.sqlite.prepare(
        `update operation_authority_receipts
            set completed_at_ms = ?, result = ?, error_code = ?, reason_code = ?
          where authority_id = ? and use_id = ? and result = 'PENDING'`,
      ).run(
        input.completedAtMs,
        input.result,
        safeCode(input.errorCode),
        safeCode(input.reasonCode),
        input.authorityId,
        input.useId,
      );
      if (updated.changes !== 1) return false;
      const pending = this.sqlite.prepare(
        `select count(*) as count
           from operation_authority_receipts
          where authority_id = ? and result = 'PENDING'`,
      ).get(input.authorityId) as { count: number };
      const terminalCapacity = Math.max(0, input.maximumReceipts - pending.count);
      this.sqlite.prepare(
        `delete from operation_authority_receipts
          where use_id in (
            select use_id
              from operation_authority_receipts
             where authority_id = ? and result != 'PENDING'
             order by coalesce(completed_at_ms, reserved_at_ms) desc, use_id desc
             limit -1 offset ?
          )`,
      ).run(input.authorityId, terminalCapacity);
      return true;
    });
    return finalize.immediate();
  }

  incrementCorrectionEpoch(scopeKey: string, nowMs: number): number {
    const increment = this.sqlite.transaction(() => {
      const current = this.sqlite.prepare(
        "select correction_epoch from operation_authority_scopes where scope_key = ?",
      ).get(scopeKey) as { correction_epoch: number } | undefined;
      const correctionEpoch = (current?.correction_epoch ?? 0) + 1;
      this.sqlite.prepare(
        `insert into operation_authority_scopes (scope_key, correction_epoch, updated_at_ms)
         values (?, ?, ?)
         on conflict(scope_key) do update set
           correction_epoch = excluded.correction_epoch,
           updated_at_ms = excluded.updated_at_ms`,
      ).run(scopeKey, correctionEpoch, nowMs);
      return correctionEpoch;
    });
    return increment.immediate();
  }

  currentCorrectionEpoch(scopeKey: string): number {
    const row = this.sqlite.prepare(
      "select correction_epoch from operation_authority_scopes where scope_key = ?",
    ).get(scopeKey) as { correction_epoch: number } | undefined;
    return row?.correction_epoch ?? 0;
  }

  releaseAuthority(input: {
    authorityId: string;
    scopeKey: string;
    correctionEpoch: number;
  }): DurableAuthorityReleaseResult {
    const release = this.sqlite.transaction((): DurableAuthorityReleaseResult => {
      const authority = this.sqlite.prepare(
        `select scope_key, correction_epoch
           from operation_authorities
          where authority_id = ?`,
      ).get(input.authorityId) as {
        scope_key: string;
        correction_epoch: number;
      } | undefined;
      if (!authority) return { ok: false, code: "AUTHORITY_EXPIRED" };
      if (authority.scope_key !== input.scopeKey) {
        return { ok: false, code: "AUTHORITY_MISMATCH" };
      }
      const scope = this.sqlite.prepare(
        "select correction_epoch from operation_authority_scopes where scope_key = ?",
      ).get(input.scopeKey) as { correction_epoch: number } | undefined;
      if (
        !scope
        || scope.correction_epoch !== input.correctionEpoch
        || authority.correction_epoch !== input.correctionEpoch
      ) {
        return { ok: false, code: "AUTHORITY_EXPIRED" };
      }
      const pending = this.sqlite.prepare(
        `select count(*) as count
           from operation_authority_receipts
          where authority_id = ? and result = 'PENDING'`,
      ).get(input.authorityId) as { count: number };
      if (pending.count > 0) {
        return {
          ok: false,
          code: "PRECONDITION_FAILED",
          pendingReceipts: pending.count,
        };
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
        "delete from operation_authorities where authority_id = ?",
      );
      for (const authorityId of authorityIds) statement.run(authorityId);
    });
    remove.immediate();
  }

  deleteAuthoritiesExpiredBefore(expiresAtCutoffMs: number): string[] {
    const rows = this.sqlite.prepare(
      `select authority_id
         from operation_authorities
        where expires_at_ms <= ?
          and not exists (
            select 1
              from operation_authority_receipts
             where operation_authority_receipts.authority_id = operation_authorities.authority_id
               and operation_authority_receipts.result = 'PENDING'
          )
        order by authority_id`,
    ).all(expiresAtCutoffMs) as Array<{ authority_id: string }>;
    if (rows.length === 0) return [];
    const purge = this.sqlite.transaction(() => {
      const remove = this.sqlite.prepare(
        `delete from operation_authorities
          where authority_id = ?
            and expires_at_ms <= ?
            and not exists (
              select 1
                from operation_authority_receipts
               where operation_authority_receipts.authority_id = operation_authorities.authority_id
                 and operation_authority_receipts.result = 'PENDING'
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

  close(): void {
    this.sqlite.close();
  }

  private initializeSchema(): void {
    this.sqlite.exec(`
      create table if not exists operation_authority_scopes (
        scope_key text primary key,
        correction_epoch integer not null check (correction_epoch >= 0),
        updated_at_ms integer not null
      );
      create table if not exists operation_authorities (
        authority_id text primary key,
        task_id_sha256 text not null,
        authority_text_sha256 text not null,
        scope_key text not null,
        correction_epoch integer not null check (correction_epoch >= 0),
        created_at_ms integer not null,
        expires_at_ms integer not null,
        fingerprint text not null,
        foreign key (scope_key) references operation_authority_scopes(scope_key)
      );
      create index if not exists operation_authorities_scope_fingerprint_idx
        on operation_authorities(scope_key, fingerprint, created_at_ms desc);
      create index if not exists operation_authorities_expiry_idx
        on operation_authorities(expires_at_ms);
      create table if not exists operation_authority_actions (
        authority_id text not null,
        action_id text not null,
        ordinal integer not null,
        tool text not null,
        operation text not null,
        fingerprint text not null,
        minimum_risk text not null,
        risk text not null,
        maximum_uses integer not null check (maximum_uses >= 1),
        consumed_uses integer not null check (consumed_uses >= 0),
        primary key (authority_id, action_id),
        unique (authority_id, fingerprint),
        foreign key (authority_id) references operation_authorities(authority_id) on delete cascade
      );
      create table if not exists operation_authority_receipts (
        authority_id text not null,
        use_id text primary key,
        action_id text not null,
        reserved_at_ms integer not null,
        completed_at_ms integer,
        result text not null check (result in ('PENDING', 'PASS', 'FAIL', 'UNCERTAIN')),
        error_code text,
        reason_code text,
        owner_instance_id text not null,
        foreign key (authority_id, action_id)
          references operation_authority_actions(authority_id, action_id)
          on delete cascade
      );
      create index if not exists operation_authority_receipts_authority_idx
        on operation_authority_receipts(authority_id, reserved_at_ms);
      pragma user_version = ${SCHEMA_VERSION};
    `);
    const receiptColumns = this.sqlite.pragma(
      "table_info(operation_authority_receipts)",
    ) as Array<{ name: string }>;
    if (!receiptColumns.some((column) => column.name === "owner_instance_id")) {
      this.sqlite.exec(
        "alter table operation_authority_receipts add column owner_instance_id text not null default 'legacy_process'",
      );
    }
  }

  private recoverPendingReservations(nowMs: number): number {
    const result = this.sqlite.prepare(
      `update operation_authority_receipts
          set result = 'UNCERTAIN',
              completed_at_ms = ?,
              error_code = 'PROCESS_RESTARTED',
              reason_code = 'PENDING_RESERVATION_RECOVERED'
        where result = 'PENDING' and owner_instance_id != ?`,
    ).run(nowMs, this.instanceId);
    return result.changes;
  }
}

function safeCode(value: string | undefined): string | null {
  if (!value) return null;
  return /^[A-Z][A-Z0-9_.:-]{0,127}$/u.test(value) ? value : null;
}
