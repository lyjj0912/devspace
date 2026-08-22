import { chmodSync, lstatSync, mkdirSync, realpathSync } from "node:fs";
import { dirname, isAbsolute, resolve } from "node:path";
import Database from "better-sqlite3";
import type { AuthorizationState } from "./contracts.js";
import { UniversalBrokerError } from "./errors.js";
import {
  type UserAuthorizationDescriptor,
  type UserAuthorizationReceipt,
  verifyUserAuthorizationDescriptor,
  verifyUserAuthorizationReceipt,
} from "./user-authorization.js";

interface AuthorizationRow {
  operationId: string;
  principalFingerprint: string;
  explicitRequestKey: string | null;
  actionDigest: string;
  descriptorDigest: string;
  descriptorJson: string;
  state: AuthorizationState;
  receiptDigest: string | null;
  receiptJson: string | null;
  receiptConsumedAt: number | null;
  createdAt: number;
  updatedAt: number;
  expiresAt: number;
}

export interface UserAuthorizationOperation {
  operationId: string;
  principalFingerprint: string;
  explicitRequestKey?: string;
  actionDigest: string;
  descriptorDigest: string;
  descriptor: UserAuthorizationDescriptor;
  state: AuthorizationState;
  receipt?: UserAuthorizationReceipt;
  receiptConsumedAt?: number;
  createdAt: number;
  updatedAt: number;
  expiresAt: number;
}

export interface PreparedUserAuthorizationOperation {
  operation: UserAuthorizationOperation;
  reused: boolean;
}

export class UserAuthorizationStore {
  private readonly sqlite: Database.Database;
  private closed = false;

  constructor(
    readonly path: string,
    private readonly now: () => number = Date.now,
  ) {
    if (!isAbsolute(path) || resolve(path) !== path || /[\0\r\n]/u.test(path)) {
      throw unavailable("User authorization store path must be canonical and absolute.");
    }
    const parent = dirname(path);
    mkdirSync(parent, { recursive: true, mode: 0o700 });
    chmodSync(parent, 0o700);
    try {
      const parentState = lstatSync(parent);
      if (!parentState.isDirectory() || parentState.isSymbolicLink() || realpathSync(parent) !== parent) {
        throw new Error("parent is not a canonical directory");
      }
      try {
        const existing = lstatSync(path);
        if (!existing.isFile() || existing.isSymbolicLink()) {
          throw new Error("store is not an owner-only regular file");
        }
      } catch (error) {
        if (!isNodeError(error, "ENOENT")) throw error;
      }
      this.sqlite = new Database(path);
      chmodSync(path, 0o600);
      this.sqlite.pragma("journal_mode = WAL");
      this.sqlite.pragma("synchronous = FULL");
      this.sqlite.pragma("foreign_keys = ON");
      this.sqlite.pragma("busy_timeout = 5000");
      this.migrate();
      this.assertIntegrity();
    } catch (error) {
      throw unavailable("User authorization store could not be opened or migrated.", error);
    }
  }

  prepare(descriptor: UserAuthorizationDescriptor): PreparedUserAuthorizationOperation {
    this.assertOpen();
    verifyUserAuthorizationDescriptor(descriptor);
    const now = checkedNow(this.now());
    const expiresAt = Date.parse(descriptor.expiresAt);
    if (!Number.isSafeInteger(expiresAt) || expiresAt <= now) {
      throw new UniversalBrokerError("ELEVATION_TIMED_OUT", "Authorization request expired before it was prepared.", {
        evidence: { authorizationOperationId: descriptor.authorizationOperationId, providerDispatchCount: 0 },
      });
    }
    try {
      return this.sqlite.transaction(() => {
        this.expirePendingLocked(now);
        if (descriptor.explicitRequestKey) {
          const existing = this.byExplicitRequestKey(descriptor.explicitRequestKey);
          if (existing) {
            if (existing.actionDigest !== descriptor.actionDigest) {
              throw new UniversalBrokerError(
                "PRECONDITION_FAILED",
                "The explicit DevSpace request ID was already bound to a different authorization action.",
                {
                  evidence: {
                    authorizationOperationId: existing.operationId,
                    existingActionDigest: existing.actionDigest,
                    receivedActionDigest: descriptor.actionDigest,
                    providerDispatchCount: 0,
                  },
                },
              );
            }
            return { operation: operationFromRow(existing), reused: true };
          }
        }
        this.sqlite.prepare(`
          INSERT INTO user_authorization_operations (
            operation_id, principal_fingerprint, explicit_request_key,
            action_digest, descriptor_digest, descriptor_json, state,
            receipt_digest, receipt_json, receipt_consumed_at,
            created_at, updated_at, expires_at
          ) VALUES (?, ?, ?, ?, ?, ?, 'PENDING', NULL, NULL, NULL, ?, ?, ?)
        `).run(
          descriptor.authorizationOperationId,
          descriptor.principalFingerprint,
          descriptor.explicitRequestKey ?? null,
          descriptor.actionDigest,
          descriptor.descriptorDigest,
          JSON.stringify(descriptor),
          now,
          now,
          expiresAt,
        );
        const inserted = this.requiredRow(descriptor.authorizationOperationId);
        return { operation: operationFromRow(inserted), reused: false };
      })();
    } catch (error) {
      if (error instanceof UniversalBrokerError) throw error;
      throw unavailable("User authorization request could not be prepared.", error);
    }
  }

  recordDecision(receipt: UserAuthorizationReceipt): UserAuthorizationOperation {
    this.assertOpen();
    verifyUserAuthorizationReceipt(receipt);
    const now = checkedNow(this.now());
    try {
      return this.sqlite.transaction(() => {
        const row = this.requiredRow(receipt.authorizationOperationId);
        if (
          row.descriptorDigest !== receipt.descriptorDigest
          || row.actionDigest !== receipt.actionDigest
        ) {
          throw stateCorrupted("Authorization receipt is not bound to the stored action descriptor.");
        }
        if (row.receiptDigest) {
          if (row.receiptDigest !== receipt.receiptDigest) {
            throw stateCorrupted("A conflicting authorization receipt already exists.");
          }
          return operationFromRow(row);
        }
        if (row.state !== "PENDING") {
          throw stateCorrupted(`Authorization decision cannot transition from ${row.state}.`);
        }
        const decision = receipt.decision;
        this.sqlite.prepare(`
          UPDATE user_authorization_operations
          SET state = ?, receipt_digest = ?, receipt_json = ?, updated_at = ?
          WHERE operation_id = ? AND state = 'PENDING' AND receipt_digest IS NULL
        `).run(
          decision,
          receipt.receiptDigest,
          JSON.stringify(receipt),
          now,
          receipt.authorizationOperationId,
        );
        return operationFromRow(this.requiredRow(receipt.authorizationOperationId));
      })();
    } catch (error) {
      if (error instanceof UniversalBrokerError) throw error;
      throw unavailable("User authorization decision could not be recorded.", error);
    }
  }

  consumeApprovedReceipt(input: {
    operationId: string;
    descriptorDigest: string;
    receiptDigest: string;
  }): UserAuthorizationOperation {
    this.assertOpen();
    const now = checkedNow(this.now());
    try {
      return this.sqlite.transaction(() => {
        const row = this.requiredRow(input.operationId);
        if (
          row.state !== "APPROVED"
          || row.descriptorDigest !== input.descriptorDigest
          || row.receiptDigest !== input.receiptDigest
          || !row.receiptJson
        ) {
          throw new UniversalBrokerError(
            "ELEVATION_DENIED",
            "Authorization receipt is not approved for this exact operation.",
            { evidence: { authorizationOperationId: input.operationId, providerDispatchCount: 0 } },
          );
        }
        const receipt = JSON.parse(row.receiptJson) as UserAuthorizationReceipt;
        verifyUserAuthorizationReceipt(receipt);
        if (Date.parse(receipt.expiresAt) <= now || row.expiresAt <= now) {
          this.sqlite.prepare(`
            UPDATE user_authorization_operations SET state = 'EXPIRED', updated_at = ?
            WHERE operation_id = ? AND state = 'APPROVED'
          `).run(now, input.operationId);
          throw new UniversalBrokerError(
            "ELEVATION_TIMED_OUT",
            "Approved authorization receipt expired before dispatch.",
            { evidence: { authorizationOperationId: input.operationId, providerDispatchCount: 0 } },
          );
        }
        if (row.receiptConsumedAt !== null) {
          throw new UniversalBrokerError(
            "PRECONDITION_FAILED",
            "Authorization receipt was already consumed.",
            { evidence: { authorizationOperationId: input.operationId, providerDispatchCount: 0 } },
          );
        }
        const updated = this.sqlite.prepare(`
          UPDATE user_authorization_operations
          SET receipt_consumed_at = ?, updated_at = ?
          WHERE operation_id = ? AND state = 'APPROVED' AND receipt_consumed_at IS NULL
        `).run(now, now, input.operationId);
        if (updated.changes !== 1) {
          throw new UniversalBrokerError(
            "PRECONDITION_FAILED",
            "Authorization receipt consumption raced with another dispatcher.",
            { evidence: { authorizationOperationId: input.operationId, providerDispatchCount: 0 } },
          );
        }
        return operationFromRow(this.requiredRow(input.operationId));
      })();
    } catch (error) {
      if (error instanceof UniversalBrokerError) throw error;
      throw unavailable("User authorization receipt could not be consumed.", error);
    }
  }

  markDecisionUnknown(input: {
    operationId: string;
    descriptorDigest: string;
  }): UserAuthorizationOperation {
    this.assertOpen();
    const now = checkedNow(this.now());
    try {
      return this.sqlite.transaction(() => {
        const row = this.requiredRow(input.operationId);
        if (row.descriptorDigest !== input.descriptorDigest || row.state !== "PENDING") {
          throw stateCorrupted("Authorization decision-unknown transition is not bound to a pending descriptor.");
        }
        this.sqlite.prepare(`
          UPDATE user_authorization_operations
          SET state = 'RESULT_UNKNOWN', updated_at = ?
          WHERE operation_id = ? AND state = 'PENDING'
        `).run(now, input.operationId);
        return operationFromRow(this.requiredRow(input.operationId));
      })();
    } catch (error) {
      if (error instanceof UniversalBrokerError) throw error;
      throw unavailable("User authorization decision could not be marked unknown.", error);
    }
  }

  markResultUnknown(input: {
    operationId: string;
    descriptorDigest: string;
    receiptDigest: string;
  }): UserAuthorizationOperation {
    this.assertOpen();
    const now = checkedNow(this.now());
    try {
      return this.sqlite.transaction(() => {
        const row = this.requiredRow(input.operationId);
        if (
          row.descriptorDigest !== input.descriptorDigest
          || row.receiptDigest !== input.receiptDigest
          || row.state !== "APPROVED"
          || row.receiptConsumedAt === null
        ) {
          throw stateCorrupted("Authorization result-unknown transition is not bound to a consumed approval.");
        }
        this.sqlite.prepare(`
          UPDATE user_authorization_operations
          SET state = 'RESULT_UNKNOWN', updated_at = ?
          WHERE operation_id = ? AND state = 'APPROVED' AND receipt_consumed_at IS NOT NULL
        `).run(now, input.operationId);
        return operationFromRow(this.requiredRow(input.operationId));
      })();
    } catch (error) {
      if (error instanceof UniversalBrokerError) throw error;
      throw unavailable("User authorization result could not be marked unknown.", error);
    }
  }

  get(operationId: string): UserAuthorizationOperation | undefined {
    this.assertOpen();
    const row = this.sqlite.prepare(ROW_SELECT + " WHERE operation_id = ?").get(operationId) as AuthorizationRow | undefined;
    return row ? operationFromRow(row) : undefined;
  }

  reconcile(): { expired: number } {
    this.assertOpen();
    try {
      return this.sqlite.transaction(() => ({ expired: this.expirePendingLocked(checkedNow(this.now())) }))();
    } catch (error) {
      throw unavailable("User authorization store reconciliation failed.", error);
    }
  }

  stats(): Record<AuthorizationState, number> {
    this.assertOpen();
    const counts = Object.fromEntries(AUTHORIZATION_STATES.map((state) => [state, 0])) as Record<AuthorizationState, number>;
    const rows = this.sqlite.prepare(`
      SELECT state, COUNT(*) AS count FROM user_authorization_operations GROUP BY state
    `).all() as Array<{ state: AuthorizationState; count: number }>;
    for (const row of rows) counts[row.state] = row.count;
    return counts;
  }

  checkpoint(): void {
    this.assertOpen();
    this.sqlite.pragma("wal_checkpoint(FULL)");
  }

  close(): void {
    if (this.closed) return;
    this.sqlite.pragma("wal_checkpoint(TRUNCATE)");
    this.sqlite.close();
    this.closed = true;
  }

  private migrate(): void {
    this.sqlite.exec(`
      CREATE TABLE IF NOT EXISTS user_authorization_metadata (
        key TEXT PRIMARY KEY,
        value TEXT NOT NULL
      ) STRICT;
      CREATE TABLE IF NOT EXISTS user_authorization_operations (
        operation_id TEXT PRIMARY KEY,
        principal_fingerprint TEXT NOT NULL,
        explicit_request_key TEXT UNIQUE,
        action_digest TEXT NOT NULL,
        descriptor_digest TEXT NOT NULL,
        descriptor_json TEXT NOT NULL,
        state TEXT NOT NULL CHECK(state IN (
          'PENDING', 'APPROVED', 'DENIED', 'CANCELED',
          'TIMED_OUT', 'EXPIRED', 'RESULT_UNKNOWN'
        )),
        receipt_digest TEXT,
        receipt_json TEXT,
        receipt_consumed_at INTEGER,
        created_at INTEGER NOT NULL,
        updated_at INTEGER NOT NULL,
        expires_at INTEGER NOT NULL
      ) STRICT;
      CREATE INDEX IF NOT EXISTS user_authorization_state_expiry_idx
        ON user_authorization_operations(state, expires_at);
    `);
    const version = this.sqlite.prepare(`
      SELECT value FROM user_authorization_metadata WHERE key = 'schema_version'
    `).get() as { value?: string } | undefined;
    if (!version) {
      this.sqlite.prepare(`
        INSERT INTO user_authorization_metadata(key, value) VALUES('schema_version', '1')
      `).run();
    } else if (version.value !== "1") {
      throw new Error(`Unsupported user authorization schema version: ${version.value}`);
    }
  }

  private assertIntegrity(): void {
    const quick = this.sqlite.pragma("quick_check") as Array<{ quick_check?: string }>;
    if (quick.length !== 1 || quick[0]?.quick_check !== "ok") {
      throw new Error("User authorization store quick_check failed.");
    }
    const foreignKeys = this.sqlite.pragma("foreign_key_check") as unknown[];
    if (foreignKeys.length !== 0) throw new Error("User authorization store foreign-key check failed.");
  }

  private expirePendingLocked(now: number): number {
    return this.sqlite.prepare(`
      UPDATE user_authorization_operations
      SET state = 'EXPIRED', updated_at = ?
      WHERE state = 'PENDING' AND expires_at <= ?
    `).run(now, now).changes;
  }

  private byExplicitRequestKey(key: string): AuthorizationRow | undefined {
    return this.sqlite.prepare(ROW_SELECT + " WHERE explicit_request_key = ?").get(key) as AuthorizationRow | undefined;
  }

  private requiredRow(operationId: string): AuthorizationRow {
    const row = this.sqlite.prepare(ROW_SELECT + " WHERE operation_id = ?").get(operationId) as AuthorizationRow | undefined;
    if (!row) throw stateCorrupted(`Authorization operation does not exist: ${operationId}`);
    return row;
  }

  private assertOpen(): void {
    if (this.closed) throw unavailable("User authorization store is closed.");
  }
}

const AUTHORIZATION_STATES = [
  "NOT_REQUIRED",
  "PENDING",
  "APPROVED",
  "DENIED",
  "CANCELED",
  "TIMED_OUT",
  "EXPIRED",
  "RESULT_UNKNOWN",
] as const satisfies readonly AuthorizationState[];

const ROW_SELECT = `
  SELECT
    operation_id AS operationId,
    principal_fingerprint AS principalFingerprint,
    explicit_request_key AS explicitRequestKey,
    action_digest AS actionDigest,
    descriptor_digest AS descriptorDigest,
    descriptor_json AS descriptorJson,
    state,
    receipt_digest AS receiptDigest,
    receipt_json AS receiptJson,
    receipt_consumed_at AS receiptConsumedAt,
    created_at AS createdAt,
    updated_at AS updatedAt,
    expires_at AS expiresAt
  FROM user_authorization_operations
`;

function operationFromRow(row: AuthorizationRow): UserAuthorizationOperation {
  const descriptor = JSON.parse(row.descriptorJson) as UserAuthorizationDescriptor;
  verifyUserAuthorizationDescriptor(descriptor);
  if (
    descriptor.authorizationOperationId !== row.operationId
    || descriptor.principalFingerprint !== row.principalFingerprint
    || descriptor.actionDigest !== row.actionDigest
    || descriptor.descriptorDigest !== row.descriptorDigest
    || (descriptor.explicitRequestKey ?? null) !== row.explicitRequestKey
  ) throw stateCorrupted("Stored authorization descriptor columns do not match its canonical JSON.");
  const receipt = row.receiptJson
    ? JSON.parse(row.receiptJson) as UserAuthorizationReceipt
    : undefined;
  if (receipt) {
    verifyUserAuthorizationReceipt(receipt);
    if (receipt.receiptDigest !== row.receiptDigest) {
      throw stateCorrupted("Stored authorization receipt columns do not match its canonical JSON.");
    }
  } else if (row.receiptDigest) {
    throw stateCorrupted("Stored authorization receipt digest has no receipt JSON.");
  }
  return Object.freeze({
    operationId: row.operationId,
    principalFingerprint: row.principalFingerprint,
    ...(row.explicitRequestKey ? { explicitRequestKey: row.explicitRequestKey } : {}),
    actionDigest: row.actionDigest,
    descriptorDigest: row.descriptorDigest,
    descriptor,
    state: row.state,
    ...(receipt ? { receipt } : {}),
    ...(row.receiptConsumedAt === null ? {} : { receiptConsumedAt: row.receiptConsumedAt }),
    createdAt: row.createdAt,
    updatedAt: row.updatedAt,
    expiresAt: row.expiresAt,
  });
}

function checkedNow(value: number): number {
  if (!Number.isSafeInteger(value) || value < 0) {
    throw unavailable("User authorization store clock is invalid.");
  }
  return value;
}

function stateCorrupted(message: string): UniversalBrokerError {
  return new UniversalBrokerError("STATE_CORRUPTED", message, {
    evidence: { providerDispatchCount: 0 },
  });
}

function unavailable(message: string, error?: unknown): UniversalBrokerError {
  return new UniversalBrokerError("ELEVATION_UNAVAILABLE", message, {
    evidence: {
      providerDispatchCount: 0,
      ...(error === undefined ? {} : {
        errorType: error instanceof Error ? error.name : typeof error,
        cause: boundedErrorMessage(error),
      }),
    },
  });
}

function boundedErrorMessage(error: unknown): string {
  const value = error instanceof Error ? error.message : String(error);
  const normalized = value.replace(/[\0\r\n]+/gu, " ").trim();
  return normalized.length <= 500 ? normalized : `${normalized.slice(0, 497)}...`;
}

function isNodeError(error: unknown, code: string): boolean {
  return Boolean(error && typeof error === "object" && "code" in error && error.code === code);
}
