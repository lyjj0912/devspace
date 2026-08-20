import { createHash, randomUUID } from "node:crypto";
import { chmodSync, mkdirSync } from "node:fs";
import {
  lstat,
  mkdir,
  readdir,
  readlink,
  rm,
  symlink,
} from "node:fs/promises";
import { dirname, isAbsolute, join, posix, relative, resolve, sep, win32 } from "node:path";
import Database from "better-sqlite3";
import { UniversalBrokerError } from "./errors.js";
import { atomicCopyFile, sha256File } from "./filesystem-atomic.js";
import { RecoverableFilesystemTrash } from "./filesystem-trash.js";

const SYNC_SCHEMA_VERSION = 1;
const DEFAULT_PLAN_TTL_MS = 15 * 60_000;
const MAXIMUM_PLAN_TTL_MS = 8 * 60 * 60_000;
const MAXIMUM_SYNC_ENTRIES = 100_000;
const MAXIMUM_ACTIVE_SYNC_PLANS = 4_096;
const MAXIMUM_ACTIVE_SYNC_PLANS_PER_OWNER = 512;
const MAXIMUM_PATTERN_COUNT = 1_024;
const MAXIMUM_PATTERN_CHARACTERS = 65_536;
const SHA256_PATTERN = /^[a-f0-9]{64}$/u;

export type FilesystemSyncDeleteMode = "none" | "trash" | "permanent";
export type FilesystemSyncConflictStrategy = "fail" | "source-wins";
export type FilesystemSyncEntryType = "file" | "directory" | "symlink";

export interface FilesystemSyncEntry {
  path: string;
  type: FilesystemSyncEntryType;
  size?: number;
  sha256?: string;
  linkTarget?: string;
}

export interface FilesystemSyncConflict {
  path: string;
  sourceType: FilesystemSyncEntryType;
  destinationType: FilesystemSyncEntryType;
  reason: "TYPE_MISMATCH";
}

export interface FilesystemSyncRequest {
  phase: "plan" | "apply";
  planId?: string;
  planDigest?: string;
  include?: string[];
  exclude?: string[];
  deleteMode?: FilesystemSyncDeleteMode;
  conflictStrategy?: FilesystemSyncConflictStrategy;
}

export interface DurableFilesystemSyncOptions {
  storePath: string;
  trash: RecoverableFilesystemTrash;
  now?: () => number;
  planTtlMs?: number;
  adapter?: FilesystemSyncAdapter;
}

export interface FilesystemSyncScope {
  ownerFingerprint: string;
  targetId: string;
  targetGeneration: string;
  sourceRoot: string;
  destinationRoot: string;
  pathStyle?: FilesystemSyncPathStyle;
}

export interface FilesystemSyncAuthorityBinding {
  planId: string;
  planDigest: string;
  deleteMode: FilesystemSyncDeleteMode;
  ownerFingerprint: string;
  targetId: string;
  targetGeneration: string;
  sourceRoot: string;
  destinationRoot: string;
}

export interface FilesystemSyncPlan {
  phase: "plan";
  planId: string;
  ownerFingerprint: string;
  targetId: string;
  targetGeneration: string;
  sourceRoot: string;
  destinationRoot: string;
  sourceSnapshotDigest: string;
  destinationSnapshotDigest: string;
  expectedDestinationSnapshotDigest: string;
  includeDigest: string;
  excludeDigest: string;
  operationManifestDigest: string;
  copySet: FilesystemSyncEntry[];
  updateSet: FilesystemSyncEntry[];
  deleteSet: FilesystemSyncEntry[];
  conflictSet: FilesystemSyncConflict[];
  deleteMode: FilesystemSyncDeleteMode;
  conflictStrategy: FilesystemSyncConflictStrategy;
  createdAt: string;
  expiresAt: string;
  planDigest: string;
}

export type FilesystemSyncPathStyle = "local" | "posix" | "windows";

export type SyncOperationKind =
  | "CREATE_ROOT"
  | "COPY_DIRECTORY"
  | "COPY_FILE"
  | "COPY_SYMLINK"
  | "UPDATE_FILE"
  | "UPDATE_SYMLINK"
  | "REPLACE_CONFLICT"
  | "DELETE_ENTRY";

export interface SyncOperation {
  operationId: string;
  sequence: number;
  kind: SyncOperationKind;
  path: string;
  source?: FilesystemSyncEntry;
  destination?: FilesystemSyncEntry;
  deleteMode: FilesystemSyncDeleteMode;
}

export interface TreeSnapshot {
  rootType: FilesystemSyncEntryType | "absent" | "other";
  entries: FilesystemSyncEntry[];
  digest: string;
}

export interface StoredSelectors {
  include: string[];
  exclude: string[];
  destinationSnapshot?: TreeSnapshot;
}

export interface FilesystemSyncAdapter {
  pathStyle: FilesystemSyncPathStyle;
  snapshotTree(
    root: string,
    selectors: StoredSelectors,
    sourceRequired: boolean,
  ): Promise<TreeSnapshot>;
  applyOperation(input: {
    planId: string;
    sourceRoot: string;
    destinationRoot: string;
    operation: SyncOperation;
    persistPartialResult?: (result: Record<string, unknown>) => void;
  }): Promise<Record<string, unknown>>;
  operationPostcondition(destinationRoot: string, operation: SyncOperation): Promise<boolean>;
  operationPostreadbackDigest(destinationRoot: string, operation: SyncOperation): Promise<string>;
  assertSourceEntry(sourceRoot: string, operation: SyncOperation): Promise<void>;
}

interface PlanRow {
  plan_id: string;
  owner_fingerprint: string;
  target_id: string;
  target_generation: string;
  source_root: string;
  destination_root: string;
  source_snapshot_digest: string;
  destination_snapshot_digest: string;
  expected_destination_snapshot_digest: string;
  plan_digest: string;
  plan_json: string;
  selectors_json: string;
  state: "PLANNED" | "APPLYING" | "COMPLETE";
  created_at_ms: number;
  expires_at_ms: number;
  completed_at_ms: number | null;
  result_json: string | null;
}

interface CheckpointRow {
  operation_id: string;
  sequence: number;
  operation_json: string;
  state: "PENDING" | "APPLYING" | "APPLIED";
  attempts: number;
  applied_at_ms: number | null;
  postreadback_digest: string | null;
  result_json: string | null;
}

export class DurableFilesystemSync {
  private readonly now: () => number;
  private readonly planTtlMs: number;

  constructor(private readonly options: DurableFilesystemSyncOptions) {
    this.now = options.now ?? Date.now;
    this.planTtlMs = options.planTtlMs ?? DEFAULT_PLAN_TTL_MS;
    if (
      !Number.isSafeInteger(this.planTtlMs)
      || this.planTtlMs < 1
      || this.planTtlMs > MAXIMUM_PLAN_TTL_MS
    ) {
      throw new Error("Filesystem sync planTtlMs must be a positive bounded safe integer.");
    }
  }

  private adapter(scope: FilesystemSyncScope): FilesystemSyncAdapter {
    return this.options.adapter ?? createLocalFilesystemSyncAdapter(
      scope.pathStyle ?? "local",
      this.options.trash,
    );
  }

  async execute(
    request: FilesystemSyncRequest,
    scope: FilesystemSyncScope,
  ): Promise<Record<string, unknown>> {
    validateScope(scope, this.adapter(scope).pathStyle);
    if (request.phase !== "plan" && request.phase !== "apply") {
      throw new UniversalBrokerError(
        "PRECONDITION_FAILED",
        "fs.sync requires phase=plan or phase=apply.",
      );
    }
    return request.phase === "plan"
      ? { ...await this.plan(request, scope) }
      : this.apply(request, scope);
  }

  /**
   * Resolve the immutable apply-plan fields needed by authority policy without
   * probing a provider or reading/mutating either filesystem tree.
   */
  inspectApplyAuthorityBinding(
    request: FilesystemSyncRequest,
    scope: FilesystemSyncScope,
  ): FilesystemSyncAuthorityBinding {
    const { planId, planDigest } = validateApplyRequest(request);
    const adapter = this.adapter(scope);
    validateScope(scope, adapter.pathStyle);
    assertDisjointRoots(scope.sourceRoot, scope.destinationRoot, adapter.pathStyle);
    const database = this.openReadOnlyStore(planId);
    try {
      const row = selectPlan(database, planId);
      assertPlanBinding(row, planDigest, scope);
      const plan = parsePlan(row.plan_json);
      assertParsedPlanBinding(plan, row, scope);
      if (row.state === "PLANNED" && row.expires_at_ms <= this.now()) {
        throw stalePlan(planId, "PLAN_EXPIRED");
      }
      return {
        planId,
        planDigest,
        deleteMode: plan.deleteMode,
        ownerFingerprint: scope.ownerFingerprint,
        targetId: scope.targetId,
        targetGeneration: scope.targetGeneration,
        sourceRoot: scope.sourceRoot,
        destinationRoot: scope.destinationRoot,
      };
    } finally {
      database.close();
    }
  }

  private async plan(
    request: FilesystemSyncRequest,
    scope: FilesystemSyncScope,
  ): Promise<FilesystemSyncPlan> {
    if (request.planId !== undefined || request.planDigest !== undefined) {
      throw new UniversalBrokerError(
        "PRECONDITION_FAILED",
        "fs.sync phase=plan does not accept planId or planDigest.",
      );
    }
    const adapter = this.adapter(scope);
    assertDisjointRoots(scope.sourceRoot, scope.destinationRoot, adapter.pathStyle);
    const selectors = normalizeSelectors(request.include, request.exclude);
    const deleteMode = validatedDeleteMode(request.deleteMode);
    const conflictStrategy = validatedConflictStrategy(request.conflictStrategy);
    const [source, destination] = await Promise.all([
      adapter.snapshotTree(scope.sourceRoot, selectors, true),
      adapter.snapshotTree(scope.destinationRoot, selectors, false),
    ]);
    if (source.rootType !== "directory") {
      throw new UniversalBrokerError(
        "PATH_TYPE_MISMATCH",
        `fs.sync source root must be a directory: ${scope.sourceRoot}`,
      );
    }
    const diff = buildDiff(source, destination, deleteMode);
    const planId = `sync_plan_${randomUUID()}`;
    const operations = buildOperations(planId, source, destination, diff, deleteMode);
    const expected = applyOperationsToSnapshot(destination, operations);
    const createdAtMs = this.now();
    const expiresAtMs = createdAtMs + this.planTtlMs;
    const unsigned = {
      phase: "plan" as const,
      planId,
      ownerFingerprint: scope.ownerFingerprint,
      targetId: scope.targetId,
      targetGeneration: scope.targetGeneration,
      sourceRoot: scope.sourceRoot,
      destinationRoot: scope.destinationRoot,
      sourceSnapshotDigest: source.digest,
      destinationSnapshotDigest: destination.digest,
      expectedDestinationSnapshotDigest: expected.digest,
      includeDigest: sha256(stableJson(selectors.include)),
      excludeDigest: sha256(stableJson(selectors.exclude)),
      operationManifestDigest: sha256(stableJson(operations)),
      copySet: diff.copySet,
      updateSet: diff.updateSet,
      deleteSet: diff.deleteSet,
      conflictSet: diff.conflictSet,
      deleteMode,
      conflictStrategy,
      createdAt: new Date(createdAtMs).toISOString(),
      expiresAt: new Date(expiresAtMs).toISOString(),
    };
    const plan: FilesystemSyncPlan = {
      ...unsigned,
      planDigest: sha256(stableJson(unsigned)),
    };
    const database = this.openStore();
    try {
      const insert = database.transaction(() => {
        database.prepare(
          `delete from filesystem_sync_plans
            where expires_at_ms <= ? and state in ('PLANNED', 'COMPLETE')`,
        ).run(createdAtMs);
        const counts = database.prepare(
          `select count(*) as total,
                  sum(case when owner_fingerprint = ? then 1 else 0 end) as owner
             from filesystem_sync_plans`,
        ).get(plan.ownerFingerprint) as { total: number; owner: number | null };
        if (
          counts.total >= MAXIMUM_ACTIVE_SYNC_PLANS
          || (counts.owner ?? 0) >= MAXIMUM_ACTIVE_SYNC_PLANS_PER_OWNER
        ) {
          throw new UniversalBrokerError(
            "RESOURCE_QUOTA_EXCEEDED",
            "Filesystem sync plan quota is exhausted; live plans are never evicted.",
            {
              evidence: {
                maximumPlans: MAXIMUM_ACTIVE_SYNC_PLANS,
                maximumPlansPerOwner: MAXIMUM_ACTIVE_SYNC_PLANS_PER_OWNER,
              },
            },
          );
        }
        database.prepare(
          `insert into filesystem_sync_plans (
             plan_id, owner_fingerprint, target_id, target_generation,
             source_root, destination_root, source_snapshot_digest,
             destination_snapshot_digest, expected_destination_snapshot_digest,
             plan_digest, plan_json, selectors_json, state,
             created_at_ms, expires_at_ms, completed_at_ms, result_json
           ) values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'PLANNED', ?, ?, null, null)`,
        ).run(
          plan.planId,
          plan.ownerFingerprint,
          plan.targetId,
          plan.targetGeneration,
          plan.sourceRoot,
          plan.destinationRoot,
          plan.sourceSnapshotDigest,
          plan.destinationSnapshotDigest,
          plan.expectedDestinationSnapshotDigest,
          plan.planDigest,
          stableJson(plan),
          stableJson({ ...selectors, destinationSnapshot: destination }),
          createdAtMs,
          expiresAtMs,
        );
        const statement = database.prepare(
          `insert into filesystem_sync_checkpoints (
             plan_id, operation_id, sequence, operation_json, state,
             attempts, applied_at_ms, postreadback_digest, result_json
           ) values (?, ?, ?, ?, 'PENDING', 0, null, null, null)`,
        );
        for (const operation of operations) {
          statement.run(plan.planId, operation.operationId, operation.sequence, stableJson(operation));
        }
      });
      insert.immediate();
    } finally {
      database.close();
    }
    return plan;
  }

  private async apply(
    request: FilesystemSyncRequest,
    scope: FilesystemSyncScope,
  ): Promise<Record<string, unknown>> {
    const { planId, planDigest } = validateApplyRequest(request);
    const adapter = this.adapter(scope);
    assertDisjointRoots(scope.sourceRoot, scope.destinationRoot, adapter.pathStyle);
    const database = this.openStore();
    try {
      const row = selectPlan(database, planId);
      assertPlanBinding(row, planDigest, scope);
      const plan = parsePlan(row.plan_json);
      assertParsedPlanBinding(plan, row, scope);
      if (row.state === "COMPLETE") {
        const result = parseRecord(row.result_json, "completed sync result");
        return { ...result, replayed: true };
      }
      const nowMs = this.now();
      if (row.state === "PLANNED" && row.expires_at_ms <= nowMs) {
        throw stalePlan(planId, "PLAN_EXPIRED");
      }
      if (plan.conflictSet.length > 0 && plan.conflictStrategy === "fail") {
        throw new UniversalBrokerError(
          "SYNC_CONFLICT",
          "The immutable sync plan contains unresolved conflicts.",
          { evidence: { planId, conflictCount: plan.conflictSet.length } },
        );
      }
      const selectors = parseSelectors(row.selectors_json);
      const operations = loadCheckpoints(database, planId);
      const operationManifest = operations.map((checkpoint) => parseOperation(checkpoint.operation_json));
      if (sha256(stableJson(operationManifest)) !== plan.operationManifestDigest) {
        throw new UniversalBrokerError(
          "STATE_CORRUPTED",
          "Stored filesystem sync operation manifest does not match its immutable digest.",
          { evidence: { planId } },
        );
      }
      const currentSource = await adapter.snapshotTree(scope.sourceRoot, selectors, true);
      if (currentSource.digest !== row!.source_snapshot_digest) {
        throw stalePlan(planId, "SOURCE_SNAPSHOT_CHANGED", {
          expected: row!.source_snapshot_digest,
          actual: currentSource.digest,
        });
      }

      let resumedEntries = 0;
      if (row!.state === "APPLYING") {
        for (const checkpoint of operations) {
          if (checkpoint.state === "APPLIED") continue;
          const operation = parseOperation(checkpoint.operation_json);
          if (!await adapter.operationPostcondition(scope.destinationRoot, operation)) continue;
          const postreadbackDigest = await adapter.operationPostreadbackDigest(scope.destinationRoot, operation);
          database.prepare(
            `update filesystem_sync_checkpoints
                set state = 'APPLIED', applied_at_ms = ?, postreadback_digest = ?,
                    result_json = ?
              where plan_id = ? and operation_id = ? and state != 'APPLIED'`,
          ).run(
            nowMs,
            postreadbackDigest,
            stableJson({
              ...parseOptionalRecord(checkpoint.result_json, "partial sync checkpoint result"),
              reconciledFromPostreadback: true,
            }),
            planId,
            operation.operationId,
          );
          checkpoint.state = "APPLIED";
          checkpoint.postreadback_digest = postreadbackDigest;
          checkpoint.result_json = stableJson({
            ...parseOptionalRecord(checkpoint.result_json, "partial sync checkpoint result"),
            reconciledFromPostreadback: true,
          });
          resumedEntries += 1;
        }
      }

      await this.assertCheckpointSnapshot(database, plan, selectors, operations, adapter);
      database.prepare(
        `update filesystem_sync_plans set state = 'APPLYING'
          where plan_id = ? and state in ('PLANNED', 'APPLYING')`,
      ).run(planId);

      let appliedEntries = 0;
      for (const checkpoint of operations) {
        if (checkpoint.state === "APPLIED") continue;
        const operation = parseOperation(checkpoint.operation_json);
        await this.assertCheckpointSnapshot(database, plan, selectors, operations, adapter);
        await adapter.assertSourceEntry(scope.sourceRoot, operation);
        database.prepare(
          `update filesystem_sync_checkpoints
              set state = 'APPLYING', attempts = attempts + 1
            where plan_id = ? and operation_id = ? and state != 'APPLIED'`,
        ).run(planId, operation.operationId);
        const result = await adapter.applyOperation({
          planId,
          sourceRoot: scope.sourceRoot,
          destinationRoot: scope.destinationRoot,
          operation,
          persistPartialResult: (partialResult) => {
            const resultJson = stableJson({
              ...parseOptionalRecord(checkpoint.result_json, "partial sync checkpoint result"),
              ...partialResult,
            });
            const persisted = database.prepare(
              `update filesystem_sync_checkpoints set result_json = ?
                where plan_id = ? and operation_id = ? and state = 'APPLYING'`,
            ).run(resultJson, planId, operation.operationId);
            if (persisted.changes !== 1) {
              throw stalePlan(planId, "CHECKPOINT_STATE_CHANGED", {
                operationId: operation.operationId,
              });
            }
            checkpoint.result_json = resultJson;
          },
        });
        const durableResult = {
          ...parseOptionalRecord(checkpoint.result_json, "partial sync checkpoint result"),
          ...result,
        };
        checkpoint.result_json = stableJson(durableResult);
        database.prepare(
          `update filesystem_sync_checkpoints set result_json = ?
            where plan_id = ? and operation_id = ? and state = 'APPLYING'`,
        ).run(checkpoint.result_json, planId, operation.operationId);
        if (!await adapter.operationPostcondition(scope.destinationRoot, operation)) {
          throw new UniversalBrokerError(
            "SYNC_PLAN_STALE",
            "A sync entry failed its post-readback verification.",
            { evidence: { planId, operationId: operation.operationId, path: operation.path } },
          );
        }
        const postreadbackDigest = await adapter.operationPostreadbackDigest(scope.destinationRoot, operation);
        database.prepare(
          `update filesystem_sync_checkpoints
              set state = 'APPLIED', applied_at_ms = ?, postreadback_digest = ?,
                  result_json = ?
            where plan_id = ? and operation_id = ? and state = 'APPLYING'`,
        ).run(
          this.now(),
          postreadbackDigest,
          checkpoint.result_json,
          planId,
          operation.operationId,
        );
        checkpoint.state = "APPLIED";
        checkpoint.postreadback_digest = postreadbackDigest;
        appliedEntries += 1;
      }

      const finalSnapshot = await adapter.snapshotTree(scope.destinationRoot, selectors, false);
      if (finalSnapshot.digest !== row!.expected_destination_snapshot_digest) {
        throw stalePlan(planId, "FINAL_POSTREADBACK_MISMATCH", {
          expected: row!.expected_destination_snapshot_digest,
          actual: finalSnapshot.digest,
        });
      }
      const completedAtMs = this.now();
      const receipts = operations.flatMap((checkpoint) => {
        const result = parseOptionalRecord(checkpoint.result_json, "sync checkpoint result");
        return Object.keys(result).length === 0
          ? []
          : [{ operationId: checkpoint.operation_id, ...result }];
      });
      const result = {
        phase: "apply",
        synchronized: true,
        planId,
        planDigest,
        sourceSnapshotDigest: row!.source_snapshot_digest,
        destinationSnapshotDigest: finalSnapshot.digest,
        checkpoint: {
          completed: operations.length,
          total: operations.length,
        },
        appliedEntries,
        resumedEntries,
        receipts,
        completedAt: new Date(completedAtMs).toISOString(),
      };
      const completed = database.prepare(
        `update filesystem_sync_plans
            set state = 'COMPLETE', completed_at_ms = ?, result_json = ?
          where plan_id = ? and state = 'APPLYING'
            and not exists (
              select 1 from filesystem_sync_checkpoints
               where plan_id = ? and state != 'APPLIED'
            )`,
      ).run(completedAtMs, stableJson(result), planId, planId);
      if (completed.changes !== 1) {
        throw new UniversalBrokerError(
          "SYNC_PLAN_STALE",
          "The sync checkpoint could not be atomically completed.",
          { evidence: { planId } },
        );
      }
      return result;
    } finally {
      database.close();
    }
  }

  private async assertCheckpointSnapshot(
    database: Database.Database,
    plan: FilesystemSyncPlan,
    selectors: StoredSelectors,
    checkpoints: CheckpointRow[],
    adapter: FilesystemSyncAdapter,
  ): Promise<void> {
    refreshCheckpointStates(database, plan.planId, checkpoints);
    const operations = checkpoints
      .filter((checkpoint) => checkpoint.state === "APPLIED")
      .map((checkpoint) => parseOperation(checkpoint.operation_json));
    for (const checkpoint of checkpoints) {
      if (checkpoint.state !== "APPLYING") continue;
      const operation = parseOperation(checkpoint.operation_json);
      if (operation.kind !== "REPLACE_CONFLICT" && operation.kind !== "UPDATE_SYMLINK") continue;
      const destination = operation.path === "."
        ? plan.destinationRoot
        : treePath(plan.destinationRoot, operation.path);
      if (await optionalLstat(destination)) continue;
      operations.push({
        ...operation,
        kind: "DELETE_ENTRY",
        source: undefined,
      });
    }
    const baseline = selectors.destinationSnapshot;
    if (!baseline || baseline.digest !== plan.destinationSnapshotDigest) {
      throw new UniversalBrokerError(
        "STATE_CORRUPTED",
        "Stored filesystem sync destination snapshot is missing or invalid.",
      );
    }
    const expected = applyOperationsToSnapshot(baseline, operations);
    const actual = await adapter.snapshotTree(plan.destinationRoot, selectors, false);
    if (actual.digest !== expected.digest) {
      throw stalePlan(plan.planId, "DESTINATION_CHECKPOINT_CHANGED", {
        expected: expected.digest,
        actual: actual.digest,
      });
    }
  }

  private openStore(): Database.Database {
    try {
      mkdirSync(dirname(this.options.storePath), { recursive: true, mode: 0o700 });
      const database = new Database(this.options.storePath);
      chmodSync(this.options.storePath, 0o600);
      database.pragma("journal_mode = WAL");
      database.pragma("synchronous = FULL");
      database.pragma("busy_timeout = 5000");
      database.pragma("foreign_keys = ON");
      const version = Number(database.pragma("user_version", { simple: true }));
      if (version !== 0 && version !== SYNC_SCHEMA_VERSION) {
        database.close();
        throw new UniversalBrokerError(
          "STATE_CORRUPTED",
          `Filesystem sync store schema ${version} is unsupported.`,
        );
      }
      database.exec(`
        create table if not exists filesystem_sync_plans (
          plan_id text primary key,
          owner_fingerprint text not null check (length(owner_fingerprint) = 64),
          target_id text not null,
          target_generation text not null,
          source_root text not null,
          destination_root text not null,
          source_snapshot_digest text not null check (length(source_snapshot_digest) = 64),
          destination_snapshot_digest text not null check (length(destination_snapshot_digest) = 64),
          expected_destination_snapshot_digest text not null
            check (length(expected_destination_snapshot_digest) = 64),
          plan_digest text not null check (length(plan_digest) = 64),
          plan_json text not null,
          selectors_json text not null,
          state text not null check (state in ('PLANNED', 'APPLYING', 'COMPLETE')),
          created_at_ms integer not null,
          expires_at_ms integer not null,
          completed_at_ms integer,
          result_json text
        );
        create index if not exists filesystem_sync_plans_owner_idx
          on filesystem_sync_plans(owner_fingerprint, created_at_ms desc);
        create table if not exists filesystem_sync_checkpoints (
          plan_id text not null,
          operation_id text not null,
          sequence integer not null,
          operation_json text not null,
          state text not null check (state in ('PENDING', 'APPLYING', 'APPLIED')),
          attempts integer not null check (attempts >= 0),
          applied_at_ms integer,
          postreadback_digest text,
          result_json text,
          primary key (plan_id, operation_id),
          unique (plan_id, sequence),
          foreign key (plan_id) references filesystem_sync_plans(plan_id) on delete cascade
        );
        create trigger if not exists filesystem_sync_plans_immutable
        before update of owner_fingerprint, target_id, target_generation,
                         source_root, destination_root, source_snapshot_digest,
                         destination_snapshot_digest, expected_destination_snapshot_digest,
                         plan_digest, plan_json, selectors_json, created_at_ms, expires_at_ms
          on filesystem_sync_plans
        begin
          select raise(abort, 'filesystem sync plan is immutable');
        end;
        create trigger if not exists filesystem_sync_checkpoint_operation_immutable
        before update of plan_id, operation_id, sequence, operation_json
          on filesystem_sync_checkpoints
        begin
          select raise(abort, 'filesystem sync checkpoint operation is immutable');
        end;
      `);
      database.pragma(`user_version = ${SYNC_SCHEMA_VERSION}`);
      const integrity = String(database.pragma("quick_check", { simple: true }));
      const foreignKeyViolations = (database.pragma("foreign_key_check") as unknown[]).length;
      if (integrity !== "ok" || foreignKeyViolations > 0) {
        database.close();
        throw new UniversalBrokerError("STATE_CORRUPTED", "Filesystem sync store integrity failed.");
      }
      return database;
    } catch (error) {
      if (error instanceof UniversalBrokerError) throw error;
      throw new UniversalBrokerError(
        "STATE_CORRUPTED",
        "Filesystem sync store is unavailable or corrupt.",
        { evidence: { errorType: error instanceof Error ? error.name : typeof error } },
      );
    }
  }

  private openReadOnlyStore(planId: string): Database.Database {
    try {
      const database = new Database(this.options.storePath, {
        readonly: true,
        fileMustExist: true,
      });
      database.pragma("query_only = ON");
      const version = Number(database.pragma("user_version", { simple: true }));
      if (version !== SYNC_SCHEMA_VERSION) {
        database.close();
        throw new UniversalBrokerError(
          "STATE_CORRUPTED",
          `Filesystem sync store schema ${version} is unsupported.`,
        );
      }
      const integrity = String(database.pragma("quick_check", { simple: true }));
      const foreignKeyViolations = (database.pragma("foreign_key_check") as unknown[]).length;
      const requiredTables = database.prepare(
        `select count(*) as count from sqlite_master
          where type = 'table'
            and name in ('filesystem_sync_plans', 'filesystem_sync_checkpoints')`,
      ).get() as { count: number };
      const immutableTriggers = database.prepare(
        `select count(*) as count from sqlite_master
          where type = 'trigger'
            and name in (
              'filesystem_sync_plans_immutable',
              'filesystem_sync_checkpoint_operation_immutable'
            )`,
      ).get() as { count: number };
      if (
        integrity !== "ok"
        || foreignKeyViolations > 0
        || requiredTables.count !== 2
        || immutableTriggers.count !== 2
      ) {
        database.close();
        throw new UniversalBrokerError("STATE_CORRUPTED", "Filesystem sync store integrity failed.");
      }
      return database;
    } catch (error) {
      if (error instanceof UniversalBrokerError) throw error;
      throw stalePlan(planId, "PLAN_STORE_UNAVAILABLE", {
        errorType: error instanceof Error ? error.name : typeof error,
      });
    }
  }
}

export function createLocalFilesystemSyncAdapter(
  pathStyle: FilesystemSyncPathStyle,
  trash: RecoverableFilesystemTrash,
): FilesystemSyncAdapter {
  return {
    pathStyle,
    snapshotTree: (root, selectors, sourceRequired) => snapshotTree(
      root,
      selectors,
      sourceRequired,
      pathStyle,
    ),
    applyOperation: (input) => applyOperation(
      input.planId,
      input.sourceRoot,
      input.destinationRoot,
      input.operation,
      trash,
      input.persistPartialResult,
      pathStyle,
    ),
    operationPostcondition: (destinationRoot, operation) => operationPostcondition(
      destinationRoot,
      operation,
      pathStyle,
    ),
    operationPostreadbackDigest: (destinationRoot, operation) => operationPostreadbackDigest(
      destinationRoot,
      operation,
      pathStyle,
    ),
    assertSourceEntry: (sourceRoot, operation) => assertSourceEntry(sourceRoot, operation, pathStyle),
  };
}

function buildDiff(
  source: TreeSnapshot,
  destination: TreeSnapshot,
  deleteMode: FilesystemSyncDeleteMode,
): {
  copySet: FilesystemSyncEntry[];
  updateSet: FilesystemSyncEntry[];
  deleteSet: FilesystemSyncEntry[];
  conflictSet: FilesystemSyncConflict[];
} {
  const copySet: FilesystemSyncEntry[] = [];
  const updateSet: FilesystemSyncEntry[] = [];
  const conflictSet: FilesystemSyncConflict[] = [];
  const sourceMap = entryMap(source.entries);
  const destinationMap = entryMap(destination.entries);
  if (destination.rootType !== "directory" && destination.rootType !== "absent") {
    conflictSet.push({
      path: ".",
      sourceType: "directory",
      destinationType: destination.rootType === "other" ? "file" : destination.rootType,
      reason: "TYPE_MISMATCH",
    });
  }
  for (const entry of source.entries) {
    const existing = destinationMap.get(entry.path);
    if (!existing) {
      copySet.push(entry);
    } else if (existing.type !== entry.type) {
      conflictSet.push({
        path: entry.path,
        sourceType: entry.type,
        destinationType: existing.type,
        reason: "TYPE_MISMATCH",
      });
    } else if (!entriesEqual(entry, existing)) {
      updateSet.push(entry);
    }
  }
  const conflictRoots = conflictSet.map((conflict) => conflict.path);
  const destinationOnly = destination.entries.filter((entry) => (
    !sourceMap.has(entry.path)
    && !conflictRoots.some((root) => isSameOrDescendant(entry.path, root))
  ));
  const deleteSet = deleteMode === "none" ? [] : collapseToRoots(destinationOnly);
  return {
    copySet: sortEntries(copySet),
    updateSet: sortEntries(updateSet),
    deleteSet: sortEntries(deleteSet),
    conflictSet: [...conflictSet].sort((left, right) => comparePaths(left.path, right.path)),
  };
}

function buildOperations(
  planId: string,
  source: TreeSnapshot,
  destination: TreeSnapshot,
  diff: ReturnType<typeof buildDiff>,
  deleteMode: FilesystemSyncDeleteMode,
): SyncOperation[] {
  const operations: Omit<SyncOperation, "operationId" | "sequence">[] = [];
  if (destination.rootType === "absent") {
    operations.push({ kind: "CREATE_ROOT", path: ".", deleteMode });
  }
  const sourceMap = entryMap(source.entries);
  const destinationMap = entryMap(destination.entries);
  for (const conflict of diff.conflictSet) {
    operations.push({
      kind: "REPLACE_CONFLICT",
      path: conflict.path,
      source: conflict.path === "."
        ? { path: ".", type: "directory" }
        : sourceMap.get(conflict.path),
      destination: conflict.path === "."
        ? rootEntry(destination)
        : destinationMap.get(conflict.path),
      deleteMode,
    });
  }
  const copies = [...diff.copySet].sort(compareCopyEntries);
  for (const entry of copies) {
    operations.push({
      kind: entry.type === "directory"
        ? "COPY_DIRECTORY"
        : entry.type === "file" ? "COPY_FILE" : "COPY_SYMLINK",
      path: entry.path,
      source: entry,
      deleteMode,
    });
  }
  for (const entry of diff.updateSet) {
    operations.push({
      kind: entry.type === "file" ? "UPDATE_FILE" : "UPDATE_SYMLINK",
      path: entry.path,
      source: entry,
      destination: destinationMap.get(entry.path),
      deleteMode,
    });
  }
  for (const entry of [...diff.deleteSet].sort((left, right) => depth(right.path) - depth(left.path))) {
    operations.push({
      kind: "DELETE_ENTRY",
      path: entry.path,
      destination: entry,
      deleteMode,
    });
  }
  return operations.map((operation, sequence) => ({
    ...operation,
    sequence,
    operationId: `sync_op_${sha256(`${planId}\0${sequence}\0${stableJson(operation)}`).slice(0, 32)}`,
  }));
}

function applyOperationsToSnapshot(
  initial: TreeSnapshot,
  operations: SyncOperation[],
): TreeSnapshot {
  let rootType = initial.rootType;
  const entries = entryMap(initial.entries);
  for (const operation of [...operations].sort((left, right) => left.sequence - right.sequence)) {
    switch (operation.kind) {
      case "CREATE_ROOT":
        rootType = "directory";
        break;
      case "DELETE_ENTRY":
        if (operation.path === ".") {
          entries.clear();
          rootType = "absent";
        } else removeEntryTree(entries, operation.path);
        break;
      case "REPLACE_CONFLICT":
        if (operation.path === ".") {
          entries.clear();
          rootType = operation.source?.type ?? "directory";
        } else {
          removeEntryTree(entries, operation.path);
          if (operation.source) entries.set(operation.path, operation.source);
        }
        break;
      case "COPY_DIRECTORY":
      case "COPY_FILE":
      case "COPY_SYMLINK":
      case "UPDATE_FILE":
      case "UPDATE_SYMLINK":
        if (operation.source) entries.set(operation.path, operation.source);
        break;
    }
  }
  return makeSnapshot(rootType, [...entries.values()]);
}

async function applyOperation(
  planId: string,
  sourceRoot: string,
  destinationRoot: string,
  operation: SyncOperation,
  trash: RecoverableFilesystemTrash,
  persistPartialResult?: (result: Record<string, unknown>) => void,
  pathStyle: FilesystemSyncPathStyle = "local",
): Promise<Record<string, unknown>> {
  const sourcePath = operation.path === "." ? sourceRoot : treePath(sourceRoot, operation.path, pathStyle);
  const destinationPath = operation.path === "."
    ? destinationRoot
    : treePath(destinationRoot, operation.path, pathStyle);
  switch (operation.kind) {
    case "CREATE_ROOT":
      await mkdir(destinationRoot, { recursive: true, mode: 0o700 });
      return { createdRoot: true };
    case "COPY_DIRECTORY":
      await mkdir(destinationPath, { recursive: false, mode: 0o700 });
      return { createdDirectory: operation.path };
    case "COPY_FILE": {
      await mkdir(dirname(destinationPath), { recursive: true, mode: 0o700 });
      const published = await atomicCopyFile(sourcePath, destinationPath, { overwrite: false });
      return { copied: operation.path, sha256: published.sha256 };
    }
    case "UPDATE_FILE": {
      const expectedSha256 = operation.destination?.sha256;
      if (!expectedSha256) throw stalePlan("unknown", "UPDATE_PREIMAGE_MISSING");
      const published = await atomicCopyFile(sourcePath, destinationPath, {
        overwrite: true,
        expectedSha256,
      });
      return { updated: operation.path, sha256: published.sha256 };
    }
    case "COPY_SYMLINK":
      await mkdir(dirname(destinationPath), { recursive: true, mode: 0o700 });
      await symlink(String(operation.source?.linkTarget ?? ""), destinationPath);
      return { copiedSymlink: operation.path };
    case "UPDATE_SYMLINK": {
      const receipt = await trash.trash(destinationPath, true);
      persistPartialResult?.({ recovery: receipt });
      await symlink(String(operation.source?.linkTarget ?? ""), destinationPath);
      return { updatedSymlink: operation.path, recovery: receipt };
    }
    case "REPLACE_CONFLICT": {
      const existing = await optionalLstat(destinationPath);
      const recovery = existing ? await trash.trash(destinationPath, true) : undefined;
      if (existing) {
        persistPartialResult?.({ recovery });
      }
      if (operation.source?.type === "directory") {
        await mkdir(destinationPath, { recursive: true, mode: 0o700 });
      } else if (operation.source?.type === "file") {
        await mkdir(dirname(destinationPath), { recursive: true, mode: 0o700 });
        await atomicCopyFile(sourcePath, destinationPath, { overwrite: false });
      } else if (operation.source?.type === "symlink") {
        await mkdir(dirname(destinationPath), { recursive: true, mode: 0o700 });
        await symlink(String(operation.source.linkTarget ?? ""), destinationPath);
      } else {
        throw new UniversalBrokerError("SYNC_CONFLICT", "A conflict has no source entry.");
      }
      return { replacedConflict: operation.path, ...(recovery ? { recovery } : {}) };
    }
    case "DELETE_ENTRY": {
      if (!await optionalLstat(destinationPath)) return { reconciledAbsent: operation.path };
      if (operation.deleteMode === "permanent") {
        await rm(destinationPath, { recursive: true, force: false });
        return { deleted: operation.path, disposition: "permanent" };
      }
      if (operation.deleteMode !== "trash") throw stalePlan(planId, "INVALID_DELETE_OPERATION");
      const recovery = await trash.trash(destinationPath, true);
      persistPartialResult?.({ recovery });
      return { deleted: operation.path, recovery };
    }
  }
}

async function operationPostcondition(
  destinationRoot: string,
  operation: SyncOperation,
  pathStyle: FilesystemSyncPathStyle = "local",
): Promise<boolean> {
  const path = operation.path === "." ? destinationRoot : treePath(destinationRoot, operation.path, pathStyle);
  if (operation.kind === "DELETE_ENTRY") return !(await optionalLstat(path));
  const expected = operation.source;
  if (operation.kind === "CREATE_ROOT") {
    const observed = await optionalLstat(path);
    return Boolean(observed?.isDirectory() && !observed.isSymbolicLink());
  }
  if (!expected) return false;
  const observed = await optionalLstat(path);
  if (!observed) return false;
  if (expected.type === "directory") return observed.isDirectory() && !observed.isSymbolicLink();
  if (expected.type === "file") {
    return observed.isFile()
      && observed.size === expected.size
      && await sha256File(path) === expected.sha256;
  }
  return observed.isSymbolicLink() && await readlink(path) === expected.linkTarget;
}

async function operationPostreadbackDigest(
  destinationRoot: string,
  operation: SyncOperation,
  pathStyle: FilesystemSyncPathStyle = "local",
): Promise<string> {
  const path = operation.path === "." ? destinationRoot : treePath(destinationRoot, operation.path, pathStyle);
  if (operation.kind === "DELETE_ENTRY") return sha256("absent");
  const observed = await optionalLstat(path);
  if (!observed) return sha256("absent");
  if (observed.isFile()) return sha256(`file\0${observed.size}\0${await sha256File(path)}`);
  if (observed.isSymbolicLink()) return sha256(`symlink\0${await readlink(path)}`);
  return sha256("directory");
}

async function assertSourceEntry(
  sourceRoot: string,
  operation: SyncOperation,
  pathStyle: FilesystemSyncPathStyle = "local",
): Promise<void> {
  if (!operation.source || operation.kind === "CREATE_ROOT" || operation.kind === "DELETE_ENTRY") return;
  if (operation.path === "." && operation.source.type === "directory") return;
  const sourcePath = treePath(sourceRoot, operation.path, pathStyle);
  const observed = await optionalLstat(sourcePath);
  const expected = operation.source;
  const matches = expected.type === "directory"
    ? Boolean(observed?.isDirectory() && !observed.isSymbolicLink())
    : expected.type === "file"
      ? Boolean(
          observed?.isFile()
          && observed.size === expected.size
          && await sha256File(sourcePath) === expected.sha256
        )
      : Boolean(observed?.isSymbolicLink() && await readlink(sourcePath) === expected.linkTarget);
  if (!matches) throw stalePlan("unknown", "SOURCE_ENTRY_CHANGED", { path: operation.path });
}

async function snapshotTree(
  root: string,
  selectors: StoredSelectors,
  sourceRequired: boolean,
  pathStyle: FilesystemSyncPathStyle = "local",
): Promise<TreeSnapshot> {
  const rootMetadata = await optionalLstat(root);
  if (!rootMetadata) {
    if (sourceRequired) {
      throw new UniversalBrokerError("PATH_NOT_FOUND", `Filesystem sync source was not found: ${root}`);
    }
    return makeSnapshot("absent", []);
  }
  const rootType = metadataType(rootMetadata);
  if (rootType === "file") {
    return makeSnapshot(rootType, [await fileEntry(root, ".", rootMetadata)]);
  }
  if (rootType === "symlink") {
    return makeSnapshot(rootType, [{ path: ".", type: rootType, linkTarget: await readlink(root) }]);
  }
  if (rootType !== "directory") return makeSnapshot("other", []);
  const entries: FilesystemSyncEntry[] = [];
  const walk = async (directory: string, relativeDirectory: string): Promise<void> => {
    const children = (await readdir(directory, { withFileTypes: true }))
      .sort((left, right) => left.name.localeCompare(right.name));
    for (const child of children) {
      const relativePath = relativeDirectory ? `${relativeDirectory}/${child.name}` : child.name;
      if (matchesAny(relativePath, selectors.exclude, child.isDirectory())) continue;
      const absolutePath = syncJoin(pathStyle, directory, child.name);
      const metadata = await lstat(absolutePath);
      const type = metadataType(metadata);
      if (!type) {
        throw new UniversalBrokerError(
          "CAPABILITY_UNAVAILABLE",
          `fs.sync does not support special filesystem entry: ${absolutePath}`,
          { evidence: { path: absolutePath } },
        );
      }
      if (type === "directory") {
        entries.push({ path: relativePath, type });
        if (entries.length > MAXIMUM_SYNC_ENTRIES) throw syncEntryQuota(root);
        await walk(absolutePath, relativePath);
        continue;
      }
      if (selectors.include.length > 0 && !matchesAny(relativePath, selectors.include, false)) continue;
      if (type === "file") {
        entries.push(await fileEntry(absolutePath, relativePath, metadata));
      } else {
        entries.push({ path: relativePath, type, linkTarget: await readlink(absolutePath) });
      }
      if (entries.length > MAXIMUM_SYNC_ENTRIES) throw syncEntryQuota(root);
    }
  };
  await walk(root, "");
  const selected = selectors.include.length === 0
    ? entries
    : retainIncludedAncestors(entries);
  return makeSnapshot("directory", selected);
}

function makeSnapshot(
  rootType: TreeSnapshot["rootType"],
  entries: FilesystemSyncEntry[],
): TreeSnapshot {
  const sorted = sortEntries(entries);
  return {
    rootType,
    entries: sorted,
    digest: sha256(stableJson({ rootType, entries: sorted })),
  };
}

function selectPlan(database: Database.Database, planId: string): PlanRow | undefined {
  return database.prepare(
    `select plan_id, owner_fingerprint, target_id, target_generation,
            source_root, destination_root, source_snapshot_digest,
            destination_snapshot_digest, expected_destination_snapshot_digest,
            plan_digest, plan_json, selectors_json, state,
            created_at_ms, expires_at_ms, completed_at_ms, result_json
       from filesystem_sync_plans where plan_id = ?`,
  ).get(planId) as PlanRow | undefined;
}

function loadCheckpoints(database: Database.Database, planId: string): CheckpointRow[] {
  return database.prepare(
    `select operation_id, sequence, operation_json, state, attempts,
            applied_at_ms, postreadback_digest, result_json
       from filesystem_sync_checkpoints where plan_id = ? order by sequence`,
  ).all(planId) as CheckpointRow[];
}

function refreshCheckpointStates(
  database: Database.Database,
  planId: string,
  checkpoints: CheckpointRow[],
): void {
  const states = new Map(
    (database.prepare(
      `select operation_id, state, postreadback_digest, result_json
         from filesystem_sync_checkpoints where plan_id = ?`,
    ).all(planId) as Array<{
      operation_id: string;
      state: CheckpointRow["state"];
      postreadback_digest: string | null;
      result_json: string | null;
    }>).map((row) => [row.operation_id, row]),
  );
  for (const checkpoint of checkpoints) {
    const state = states.get(checkpoint.operation_id);
    if (!state) throw stalePlan(planId, "CHECKPOINT_MISSING");
    checkpoint.state = state.state;
    checkpoint.postreadback_digest = state.postreadback_digest;
    checkpoint.result_json = state.result_json;
  }
}

function assertPlanBinding(
  row: PlanRow | undefined,
  planDigest: string,
  scope: FilesystemSyncScope,
): asserts row is PlanRow {
  if (
    !row
    || row.plan_digest !== planDigest
    || row.owner_fingerprint !== scope.ownerFingerprint
    || row.target_id !== scope.targetId
    || row.target_generation !== scope.targetGeneration
    || row.source_root !== scope.sourceRoot
    || row.destination_root !== scope.destinationRoot
  ) {
    throw stalePlan(row?.plan_id ?? "unknown", "PLAN_BINDING_MISMATCH");
  }
}

function assertParsedPlanBinding(
  plan: FilesystemSyncPlan,
  row: PlanRow,
  scope: FilesystemSyncScope,
): void {
  if (
    plan.planId !== row.plan_id
    || plan.planDigest !== row.plan_digest
    || plan.ownerFingerprint !== scope.ownerFingerprint
    || plan.targetId !== scope.targetId
    || plan.targetGeneration !== scope.targetGeneration
    || plan.sourceRoot !== scope.sourceRoot
    || plan.destinationRoot !== scope.destinationRoot
    || plan.sourceSnapshotDigest !== row.source_snapshot_digest
    || plan.destinationSnapshotDigest !== row.destination_snapshot_digest
    || plan.expectedDestinationSnapshotDigest !== row.expected_destination_snapshot_digest
  ) {
    throw new UniversalBrokerError(
      "STATE_CORRUPTED",
      "Stored filesystem sync plan fields do not match their immutable row binding.",
      { evidence: { planId: row.plan_id } },
    );
  }
}

function parsePlan(value: string): FilesystemSyncPlan {
  const parsed = JSON.parse(value) as FilesystemSyncPlan;
  const { planDigest, ...unsigned } = parsed;
  if (!SHA256_PATTERN.test(planDigest) || sha256(stableJson(unsigned)) !== planDigest) {
    throw new UniversalBrokerError("STATE_CORRUPTED", "Stored filesystem sync plan digest is invalid.");
  }
  return parsed;
}

function parseSelectors(value: string): StoredSelectors {
  const parsed = JSON.parse(value) as StoredSelectors;
  if (!Array.isArray(parsed.include) || !Array.isArray(parsed.exclude)) {
    throw new UniversalBrokerError("STATE_CORRUPTED", "Stored filesystem sync selectors are invalid.");
  }
  const normalized = normalizeSelectors(parsed.include, parsed.exclude);
  const destinationSnapshot = parsed.destinationSnapshot;
  if (
    !destinationSnapshot
    || !Array.isArray(destinationSnapshot.entries)
    || !SHA256_PATTERN.test(destinationSnapshot.digest)
    || makeSnapshot(destinationSnapshot.rootType, destinationSnapshot.entries).digest
      !== destinationSnapshot.digest
  ) {
    throw new UniversalBrokerError(
      "STATE_CORRUPTED",
      "Stored filesystem sync destination snapshot is invalid.",
    );
  }
  return { ...normalized, destinationSnapshot };
}

function parseOperation(value: string): SyncOperation {
  const parsed = JSON.parse(value) as SyncOperation;
  if (!parsed.operationId || !Number.isSafeInteger(parsed.sequence) || !parsed.kind || !parsed.path) {
    throw new UniversalBrokerError("STATE_CORRUPTED", "Stored filesystem sync operation is invalid.");
  }
  return parsed;
}

function parseRecord(value: string | null, label: string): Record<string, unknown> {
  if (!value) throw new UniversalBrokerError("STATE_CORRUPTED", `Missing ${label}.`);
  const parsed = JSON.parse(value) as unknown;
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
    throw new UniversalBrokerError("STATE_CORRUPTED", `Invalid ${label}.`);
  }
  return parsed as Record<string, unknown>;
}

function parseOptionalRecord(value: string | null, label: string): Record<string, unknown> {
  return value ? parseRecord(value, label) : {};
}

function normalizeSelectors(
  include: readonly string[] | undefined,
  exclude: readonly string[] | undefined,
): StoredSelectors {
  const normalize = (values: readonly string[] | undefined, name: string): string[] => {
    if (!values) return [];
    if (values.length > MAXIMUM_PATTERN_COUNT) {
      throw new UniversalBrokerError("RESOURCE_QUOTA_EXCEEDED", `Too many fs.sync ${name} patterns.`);
    }
    const normalized = [...new Set(values.map((value) => {
      const pattern = value.trim().replaceAll("\\", "/").replace(/^\.\//u, "");
      if (!pattern || pattern.includes("\0") || pattern.startsWith("/") || pattern.includes("../")) {
        throw new UniversalBrokerError("PRECONDITION_FAILED", `Invalid fs.sync ${name} pattern.`);
      }
      return pattern;
    }))].sort();
    if (normalized.join("").length > MAXIMUM_PATTERN_CHARACTERS) {
      throw new UniversalBrokerError("RESOURCE_QUOTA_EXCEEDED", `fs.sync ${name} patterns are too large.`);
    }
    return normalized;
  };
  return { include: normalize(include, "include"), exclude: normalize(exclude, "exclude") };
}

function matchesAny(path: string, patterns: readonly string[], directory: boolean): boolean {
  return patterns.some((pattern) => {
    const expression = globExpression(pattern);
    return expression.test(path) || (directory && expression.test(`${path}/`));
  });
}

function globExpression(pattern: string): RegExp {
  let expression = pattern.includes("/") ? "^" : "(?:^|/)";
  for (let index = 0; index < pattern.length; index += 1) {
    const character = pattern[index]!;
    if (character === "*") {
      if (pattern[index + 1] === "*") {
        expression += ".*";
        index += 1;
      } else expression += "[^/]*";
    } else if (character === "?") expression += "[^/]";
    else expression += character.replace(/[|\\{}()[\]^$+?.]/gu, "\\$&");
  }
  return new RegExp(`${expression}$`, "u");
}

function retainIncludedAncestors(entries: FilesystemSyncEntry[]): FilesystemSyncEntry[] {
  const selectedPaths = new Set(entries.filter((entry) => entry.type !== "directory").map((entry) => entry.path));
  for (const path of [...selectedPaths]) {
    let parent = path.includes("/") ? path.slice(0, path.lastIndexOf("/")) : "";
    while (parent) {
      selectedPaths.add(parent);
      parent = parent.includes("/") ? parent.slice(0, parent.lastIndexOf("/")) : "";
    }
  }
  return entries.filter((entry) => selectedPaths.has(entry.path));
}

function metadataType(metadata: Awaited<ReturnType<typeof lstat>>): FilesystemSyncEntryType | undefined {
  if (metadata.isSymbolicLink()) return "symlink";
  if (metadata.isFile()) return "file";
  if (metadata.isDirectory()) return "directory";
  return undefined;
}

async function fileEntry(
  path: string,
  relativePath: string,
  before: Awaited<ReturnType<typeof lstat>>,
): Promise<FilesystemSyncEntry> {
  const digest = await sha256File(path);
  const after = await lstat(path);
  if (
    !after.isFile()
    || before.dev !== after.dev
    || before.ino !== after.ino
    || before.size !== after.size
    || before.mtimeMs !== after.mtimeMs
  ) {
    throw stalePlan("snapshot", "FILE_CHANGED_DURING_SNAPSHOT", { path });
  }
  return { path: relativePath, type: "file", size: after.size, sha256: digest };
}

function entriesEqual(left: FilesystemSyncEntry, right: FilesystemSyncEntry): boolean {
  return left.type === right.type
    && left.size === right.size
    && left.sha256 === right.sha256
    && left.linkTarget === right.linkTarget;
}

function collapseToRoots(entries: FilesystemSyncEntry[]): FilesystemSyncEntry[] {
  const sorted = [...entries].sort((left, right) => depth(left.path) - depth(right.path)
    || comparePaths(left.path, right.path));
  const roots: FilesystemSyncEntry[] = [];
  for (const entry of sorted) {
    if (roots.some((root) => isSameOrDescendant(entry.path, root.path))) continue;
    roots.push(entry);
  }
  return roots;
}

function removeEntryTree(entries: Map<string, FilesystemSyncEntry>, root: string): void {
  for (const path of entries.keys()) {
    if (isSameOrDescendant(path, root)) entries.delete(path);
  }
}

function isSameOrDescendant(path: string, root: string): boolean {
  return root === "." || path === root || path.startsWith(`${root}/`);
}

function treePath(
  root: string,
  relativePath: string,
  pathStyle: FilesystemSyncPathStyle = "local",
): string {
  if (!relativePath || relativePath === "." || relativePath.startsWith("/") || relativePath.includes("\0")) {
    throw new UniversalBrokerError("STATE_CORRUPTED", "Stored filesystem sync path is invalid.");
  }
  const toolkit = syncPathToolkit(pathStyle);
  const resolvedRoot = toolkit.resolve(root);
  const resolvedPath = toolkit.resolve(resolvedRoot, ...relativePath.split("/"));
  const child = toolkit.relative(resolvedRoot, resolvedPath);
  if (!child || child === ".." || child.startsWith(`..${toolkit.sep}`) || toolkit.isAbsolute(child)) {
    throw new UniversalBrokerError("STATE_CORRUPTED", "Stored filesystem sync path escaped its root.");
  }
  return toolkit.normalizeOutput(resolvedPath);
}

function assertDisjointRoots(
  source: string,
  destination: string,
  pathStyle: FilesystemSyncPathStyle = "local",
): void {
  const toolkit = syncPathToolkit(pathStyle);
  const sourceRoot = toolkit.resolve(source);
  const destinationRoot = toolkit.resolve(destination);
  const sourceToDestination = toolkit.relative(sourceRoot, destinationRoot);
  const destinationToSource = toolkit.relative(destinationRoot, sourceRoot);
  const nested = (value: string): boolean => !value
    || (!value.startsWith(`..${toolkit.sep}`) && value !== ".." && !toolkit.isAbsolute(value));
  if (nested(sourceToDestination) || nested(destinationToSource)) {
    throw new UniversalBrokerError(
      "PRECONDITION_FAILED",
      "fs.sync source and destination roots must be disjoint.",
      { evidence: { sourceRoot, destinationRoot } },
    );
  }
}

function validateScope(scope: FilesystemSyncScope, pathStyle: FilesystemSyncPathStyle): void {
  if (!SHA256_PATTERN.test(scope.ownerFingerprint)) {
    throw new UniversalBrokerError("AUTHENTICATION_FAILED", "fs.sync requires a stable owner fingerprint.");
  }
  const toolkit = syncPathToolkit(pathStyle);
  if (
    !scope.targetId
    || !scope.targetGeneration
    || !toolkit.isAbsolute(scope.sourceRoot)
    || !toolkit.isAbsolute(scope.destinationRoot)
  ) {
    throw new UniversalBrokerError("PRECONDITION_FAILED", "fs.sync scope is incomplete.");
  }
}

function syncJoin(pathStyle: FilesystemSyncPathStyle, root: string, child: string): string {
  if (pathStyle === "windows") {
    return win32.join(root.replaceAll("/", "\\"), child).replaceAll("\\", "/");
  }
  if (pathStyle === "posix") return posix.join(root, child);
  return join(root, child);
}

function syncPathToolkit(pathStyle: FilesystemSyncPathStyle): {
  sep: string;
  resolve: (...paths: string[]) => string;
  relative: (from: string, to: string) => string;
  isAbsolute: (path: string) => boolean;
  normalizeOutput: (path: string) => string;
} {
  if (pathStyle === "windows") {
    return {
      sep: "\\",
      resolve: (...paths) => win32.resolve(...paths.map((path) => path.replaceAll("/", "\\"))),
      relative: (from, to) => win32.relative(from.replaceAll("/", "\\"), to.replaceAll("/", "\\")),
      isAbsolute: (path) => win32.isAbsolute(path.replaceAll("/", "\\")),
      normalizeOutput: (path) => path.replaceAll("\\", "/"),
    };
  }
  if (pathStyle === "posix") {
    return {
      sep: "/",
      resolve: (...paths) => posix.resolve(...paths),
      relative: (from, to) => posix.relative(from, to),
      isAbsolute: (path) => posix.isAbsolute(path),
      normalizeOutput: (path) => path,
    };
  }
  return {
    sep,
    resolve: (...paths) => resolve(...paths),
    relative: (from, to) => relative(from, to),
    isAbsolute,
    normalizeOutput: (path) => path,
  };
}

function rootEntry(snapshot: TreeSnapshot): FilesystemSyncEntry | undefined {
  return snapshot.rootType === "file" || snapshot.rootType === "directory" || snapshot.rootType === "symlink"
    ? { path: ".", type: snapshot.rootType }
    : undefined;
}

function entryMap(entries: readonly FilesystemSyncEntry[]): Map<string, FilesystemSyncEntry> {
  return new Map(entries.map((entry) => [entry.path, entry]));
}

function sortEntries(entries: readonly FilesystemSyncEntry[]): FilesystemSyncEntry[] {
  return [...entries].sort((left, right) => comparePaths(left.path, right.path));
}

function compareCopyEntries(left: FilesystemSyncEntry, right: FilesystemSyncEntry): number {
  if (left.type === "directory" && right.type !== "directory") return -1;
  if (left.type !== "directory" && right.type === "directory") return 1;
  return depth(left.path) - depth(right.path) || comparePaths(left.path, right.path);
}

function comparePaths(left: string, right: string): number {
  return Buffer.from(left).compare(Buffer.from(right));
}

function depth(path: string): number {
  return path === "." ? 0 : path.split("/").length;
}

function requiredPlanId(value: string | undefined): string {
  if (!value || !/^sync_plan_[0-9a-f-]{36}$/u.test(value)) {
    throw new UniversalBrokerError("SYNC_PLAN_STALE", "A valid fs.sync planId is required.");
  }
  return value;
}

function validateApplyRequest(request: FilesystemSyncRequest): {
  planId: string;
  planDigest: string;
} {
  const planId = requiredPlanId(request.planId);
  const planDigest = requiredDigest(request.planDigest, "planDigest");
  if (
    request.phase !== "apply"
    || request.include !== undefined
    || request.exclude !== undefined
    || request.deleteMode !== undefined
    || request.conflictStrategy !== undefined
  ) {
    throw new UniversalBrokerError(
      "PRECONDITION_FAILED",
      "fs.sync phase=apply accepts only the immutable planId and planDigest.",
    );
  }
  return { planId, planDigest };
}

function validatedDeleteMode(
  value: FilesystemSyncDeleteMode | undefined,
): FilesystemSyncDeleteMode {
  const normalized = value ?? "none";
  if (normalized !== "none" && normalized !== "trash" && normalized !== "permanent") {
    throw new UniversalBrokerError("PRECONDITION_FAILED", "Invalid fs.sync deleteMode.");
  }
  return normalized;
}

function validatedConflictStrategy(
  value: FilesystemSyncConflictStrategy | undefined,
): FilesystemSyncConflictStrategy {
  const normalized = value ?? "fail";
  if (normalized !== "fail" && normalized !== "source-wins") {
    throw new UniversalBrokerError("PRECONDITION_FAILED", "Invalid fs.sync conflictStrategy.");
  }
  return normalized;
}

function requiredDigest(value: string | undefined, name: string): string {
  const normalized = value?.trim().toLowerCase();
  if (!normalized || !SHA256_PATTERN.test(normalized)) {
    throw new UniversalBrokerError("SYNC_PLAN_STALE", `A valid fs.sync ${name} is required.`);
  }
  return normalized;
}

function stalePlan(
  planId: string,
  reason: string,
  evidence: Record<string, unknown> = {},
): UniversalBrokerError {
  return new UniversalBrokerError(
    "SYNC_PLAN_STALE",
    "The immutable filesystem sync plan is stale or no longer matches its bound state.",
    { evidence: { planId, reason, ...evidence } },
  );
}

function syncEntryQuota(root: string): UniversalBrokerError {
  return new UniversalBrokerError(
    "RESOURCE_QUOTA_EXCEEDED",
    `Filesystem sync snapshot exceeds ${MAXIMUM_SYNC_ENTRIES} entries.`,
    { evidence: { root, maximumEntries: MAXIMUM_SYNC_ENTRIES } },
  );
}

async function optionalLstat(path: string) {
  try {
    return await lstat(path);
  } catch (error) {
    if (isNodeError(error, "ENOENT")) return undefined;
    throw error;
  }
}

function isNodeError(error: unknown, code: string): error is NodeJS.ErrnoException {
  return error instanceof Error && "code" in error && error.code === code;
}

function stableJson(value: unknown): string {
  return JSON.stringify(canonicalize(value));
}

function canonicalize(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(canonicalize);
  if (value && typeof value === "object") {
    return Object.fromEntries(
      Object.entries(value as Record<string, unknown>)
        .filter(([, item]) => item !== undefined)
        .sort(([left], [right]) => left < right ? -1 : left > right ? 1 : 0)
        .map(([key, item]) => [key, canonicalize(item)]),
    );
  }
  return value;
}

function sha256(value: string): string {
  return createHash("sha256").update(value).digest("hex");
}
