import { createHash, randomUUID, timingSafeEqual } from "node:crypto";
import { createReadStream, mkdirSync, chmodSync } from "node:fs";
import {
  copyFile,
  lstat,
  mkdir,
  readdir,
  rename,
  unlink,
} from "node:fs/promises";
import { dirname, join, resolve } from "node:path";
import { pipeline } from "node:stream/promises";
import Database from "better-sqlite3";
import { formatResourceUri } from "./resource-uri.js";

export type ArtifactCatalogFailureReason =
  | "ARTIFACT_CATALOG_UNAVAILABLE"
  | "ARTIFACT_CATALOG_STATE_INVALID"
  | "ARTIFACT_QUOTA_EXCEEDED";

export type ArtifactState =
  | "AVAILABLE"
  | "EXPIRED"
  | "QUARANTINED";

export interface ArtifactCatalogRecord {
  artifactId: string;
  ownerFingerprint: string;
  objectSha256: string;
  objectPath: string;
  name: string;
  mimeType: string;
  size: number;
  sha256: string;
  tokenHash: string;
  source: string;
  destination?: string;
  state: ArtifactState;
  createdAt: number;
  expiresAt: number;
  resourceUri: string;
  cleanupStatus: string;
  reconciliationStatus: string;
}

export interface ArtifactCatalogObject {
  path: string;
  sha256: string;
  size: number;
  references: number;
  state: "AVAILABLE" | "CLEANUP_PENDING" | "QUARANTINED" | "DELETED";
}

export interface ArtifactCatalogReservation {
  reservationId: string;
  ownerFingerprint: string;
  entryReserved: boolean;
  bytesReserved: number;
  bytesCommitted: boolean;
  objectSha256?: string;
  state: "ACTIVE" | "COMMITTED" | "ABORTED";
}

export interface ArtifactCleanupReceipt {
  receiptId: string;
  artifactId?: string;
  objectSha256?: string;
  reason: string;
  status: "PLANNED" | "COMPLETED" | "FAILED";
  detail?: string;
  createdAt: number;
  completedAt?: number;
}

export interface ArtifactCatalogOptions {
  catalogPath: string;
  objectRoot: string;
  quarantineRoot: string;
  maximumEntries: number;
  maximumTotalBytes: number;
  now?: () => number;
}

export interface ArtifactReconciliationReport {
  abortedReservations: number;
  quarantinedObjects: number;
  quarantinedRecords: number;
  receipts: number;
}

export interface ArtifactCleanupPlan {
  receiptId: string;
  object: ArtifactCatalogObject;
}

interface ArtifactRecordRow {
  artifactId: string;
  ownerFingerprint: string;
  objectSha256: string;
  objectPath: string;
  name: string;
  mimeType: string;
  size: number;
  sha256: string;
  tokenHash: string;
  source: string;
  destination: string | null;
  state: ArtifactState;
  createdAt: number;
  expiresAt: number;
  resourceUri: string;
  cleanupStatus: string;
  reconciliationStatus: string;
}

interface ArtifactObjectRow {
  path: string;
  sha256: string;
  size: number;
  references: number;
  state: ArtifactCatalogObject["state"];
}

interface ReservationRow {
  reservationId: string;
  ownerFingerprint: string;
  entryReserved: number;
  bytesReserved: number;
  bytesCommitted: number;
  objectSha256: string | null;
  state: ArtifactCatalogReservation["state"];
}

interface CleanupReceiptRow {
  receiptId: string;
  artifactId: string | null;
  objectSha256: string | null;
  reason: string;
  status: ArtifactCleanupReceipt["status"];
  detail: string | null;
  createdAt: number;
  completedAt: number | null;
}

export class ArtifactCatalogError extends Error {
  readonly code = "ARTIFACT_CATALOG_ERROR";

  constructor(
    readonly reason: ArtifactCatalogFailureReason,
    message: string,
    readonly evidence: Readonly<Record<string, unknown>> = {},
    options?: ErrorOptions,
  ) {
    super(message, options);
    this.name = "ArtifactCatalogError";
  }
}

export class ArtifactCatalog {
  private readonly sqlite: Database.Database;
  private readonly now: () => number;
  private readonly objectRoot: string;
  private readonly quarantineRoot: string;
  private readonly maximumEntries: number;
  private readonly maximumTotalBytes: number;
  private closed = false;

  constructor(options: ArtifactCatalogOptions) {
    this.now = options.now ?? Date.now;
    this.objectRoot = resolve(options.objectRoot);
    this.quarantineRoot = resolve(options.quarantineRoot);
    this.maximumEntries = positiveSafeInteger(options.maximumEntries, "maximumEntries");
    this.maximumTotalBytes = positiveSafeInteger(options.maximumTotalBytes, "maximumTotalBytes");
    try {
      mkdirSync(dirname(options.catalogPath), { recursive: true, mode: 0o700 });
      mkdirSync(this.objectRoot, { recursive: true, mode: 0o700 });
      mkdirSync(this.quarantineRoot, { recursive: true, mode: 0o700 });
      this.sqlite = new Database(options.catalogPath);
      chmodSync(options.catalogPath, 0o600);
      this.sqlite.pragma("journal_mode = WAL");
      this.sqlite.pragma("synchronous = FULL");
      this.sqlite.pragma("foreign_keys = ON");
      this.sqlite.pragma("busy_timeout = 5000");
      this.migrate();
      this.assertIntegrity();
    } catch (error) {
      throw unavailable("Artifact catalog could not be opened or migrated.", error);
    }
  }

  async reconcile(): Promise<ArtifactReconciliationReport> {
    this.assertOpen();
    this.assertIntegrity();
    await mkdir(this.objectRoot, { recursive: true, mode: 0o700 });
    await mkdir(this.quarantineRoot, { recursive: true, mode: 0o700 });
    const report: ArtifactReconciliationReport = {
      abortedReservations: 0,
      quarantinedObjects: 0,
      quarantinedRecords: 0,
      receipts: 0,
    };
    try {
      const active = this.allReservations("ACTIVE");
      const recover = this.sqlite.transaction(() => {
        for (const reservation of active) {
          this.sqlite.prepare(`
            UPDATE artifact_reservations
            SET state = 'ABORTED', updated_at = ?
            WHERE reservation_id = ? AND state = 'ACTIVE'
          `).run(this.checkedNow(), reservation.reservationId);
          this.insertReceipt({
            objectSha256: reservation.objectSha256,
            reason: "RESERVATION_RECOVERED",
            status: "COMPLETED",
            detail: "Startup reconciliation aborted a nonterminal reservation.",
          });
          report.abortedReservations += 1;
          report.receipts += 1;
        }
      });
      recover();

      const objects = this.allObjects().filter((object) => object.state === "AVAILABLE" || object.state === "CLEANUP_PENDING");
      for (const object of objects) {
        const expectedReferences = this.availableReferenceCount(object.sha256);
        let reason: string | undefined;
        if (expectedReferences !== object.references) reason = "CAS_REFCOUNT_MISMATCH";
        else if (expectedReferences === 0) reason = "CAS_OBJECT_ORPHAN";
        else if (!(await validObjectFile(object))) reason = "CAS_OBJECT_CORRUPT";
        if (!reason) continue;
        const moved = await this.quarantinePathIfPresent(object.path, object.sha256, reason);
        const counts = this.quarantineCatalogObject(object.sha256, reason, moved);
        report.quarantinedObjects += 1;
        report.quarantinedRecords += counts.records;
        report.receipts += 1;
      }

      const dangling = this.sqlite.prepare(`
        SELECT r.artifact_id AS artifactId
        FROM artifact_records r
        LEFT JOIN artifact_objects o ON o.sha256 = r.object_sha256
        WHERE r.state = 'AVAILABLE' AND (o.sha256 IS NULL OR o.state != 'AVAILABLE')
      `).all() as Array<{ artifactId: string }>;
      const quarantineDangling = this.sqlite.transaction(() => {
        for (const { artifactId } of dangling) {
          this.sqlite.prepare(`
            UPDATE artifact_records
            SET state = 'QUARANTINED', cleanup_status = 'QUARANTINED',
                reconciliation_status = 'OBJECT_UNAVAILABLE'
            WHERE artifact_id = ? AND state = 'AVAILABLE'
          `).run(artifactId);
          this.insertReceipt({
            artifactId,
            reason: "CATALOG_OBJECT_MISSING",
            status: "COMPLETED",
            detail: "Available artifact referenced a missing or unavailable catalog object.",
          });
          report.quarantinedRecords += 1;
          report.receipts += 1;
        }
      });
      quarantineDangling();

      const catalogPaths = new Set(
        this.allObjects()
          .filter((object) => object.state === "AVAILABLE")
          .map((object) => resolve(object.path)),
      );
      for (const path of await listFilesRecursively(this.objectRoot)) {
        if (catalogPaths.has(resolve(path))) continue;
        const digest = await sha256File(path).catch(() => "unknown");
        const moved = await this.quarantinePathIfPresent(path, digest, "CAS_OBJECT_ORPHAN");
        this.insertReceipt({
          objectSha256: /^[0-9a-f]{64}$/u.test(digest) ? digest : undefined,
          reason: "CAS_OBJECT_ORPHAN",
          status: "COMPLETED",
          detail: moved ? `Quarantined orphan CAS file as ${moved}.` : "Orphan CAS file was already absent.",
        });
        report.quarantinedObjects += 1;
        report.receipts += 1;
      }
      this.assertIntegrity();
      return report;
    } catch (error) {
      if (error instanceof ArtifactCatalogError) throw error;
      throw unavailable("Artifact catalog reconciliation failed closed.", error);
    }
  }

  reserveCapacity(input: {
    ownerFingerprint: string;
    requestedMaximumBytes: number;
    declaredSize?: number;
    provisionalMaximumBytes?: number;
    reserveEntry: boolean;
  }): ArtifactCatalogReservation {
    this.assertOpen();
    const requestedMaximumBytes = positiveSafeInteger(input.requestedMaximumBytes, "requestedMaximumBytes");
    if (input.declaredSize !== undefined && (!Number.isSafeInteger(input.declaredSize) || input.declaredSize < 0)) {
      throw stateInvalid("declaredSize must be a non-negative safe integer.");
    }
    if (input.declaredSize !== undefined && input.declaredSize > requestedMaximumBytes) {
      throw quotaExceeded("Artifact exceeds maxBytes before source open.", {
        declaredSize: input.declaredSize,
        requestedMaximumBytes,
      });
    }
    if (
      input.provisionalMaximumBytes !== undefined
      && (
        !Number.isSafeInteger(input.provisionalMaximumBytes)
        || input.provisionalMaximumBytes < 0
        || input.provisionalMaximumBytes > requestedMaximumBytes
      )
    ) {
      throw stateInvalid("provisionalMaximumBytes must fit within requestedMaximumBytes.");
    }
    if (input.declaredSize !== undefined && input.provisionalMaximumBytes !== undefined) {
      throw stateInvalid("declaredSize and provisionalMaximumBytes are mutually exclusive.");
    }
    return this.catalogOperation("reserve capacity", () => {
      const stats = this.stats();
      if (input.reserveEntry && stats.artifacts + stats.reservedEntries >= this.maximumEntries) {
        throw quotaExceeded("Artifact record quota is full; live records are never evicted.", {
          maximumEntries: this.maximumEntries,
        });
      }
      const available = this.maximumTotalBytes - stats.totalBytes - stats.reservedBytes;
      const bytesReserved = input.declaredSize
        ?? (input.provisionalMaximumBytes !== undefined
          ? Math.min(input.provisionalMaximumBytes, Math.max(available, 0))
          : Math.min(requestedMaximumBytes, Math.max(available, 0)));
      if (
        bytesReserved > available
        || (bytesReserved === 0 && input.declaredSize !== 0 && input.provisionalMaximumBytes === undefined)
      ) {
        throw quotaExceeded("Artifact byte quota is full before source open.", {
          availableBytes: Math.max(available, 0),
          requestedMaximumBytes,
          declaredSize: input.declaredSize,
        });
      }
      const now = this.checkedNow();
      const reservation: ArtifactCatalogReservation = {
        reservationId: randomUUID(),
        ownerFingerprint: requiredText(input.ownerFingerprint, "ownerFingerprint", 512),
        entryReserved: input.reserveEntry,
        bytesReserved,
        bytesCommitted: false,
        state: "ACTIVE",
      };
      this.sqlite.prepare(`
        INSERT INTO artifact_reservations (
          reservation_id, owner_fingerprint, entry_reserved, bytes_reserved,
          bytes_committed, object_sha256, state, created_at, updated_at
        ) VALUES (?, ?, ?, ?, 0, NULL, 'ACTIVE', ?, ?)
      `).run(
        reservation.reservationId,
        reservation.ownerFingerprint,
        reservation.entryReserved ? 1 : 0,
        reservation.bytesReserved,
        now,
        now,
      );
      return reservation;
    });
  }

  reserveArtifactEntry(reservationId: string): ArtifactCatalogReservation {
    this.assertOpen();
    return this.catalogOperation("reserve artifact entry", () => this.sqlite.transaction(() => {
      const reservation = this.requiredActiveReservation(reservationId);
      if (reservation.entryReserved) return reservation;
      const stats = this.stats();
      if (stats.artifacts + stats.reservedEntries >= this.maximumEntries) {
        throw quotaExceeded("Artifact record quota is full; live records are never evicted.", {
          maximumEntries: this.maximumEntries,
        });
      }
      this.sqlite.prepare(`
        UPDATE artifact_reservations SET entry_reserved = 1, updated_at = ?
        WHERE reservation_id = ? AND state = 'ACTIVE' AND entry_reserved = 0
      `).run(this.checkedNow(), reservationId);
      return this.requiredActiveReservation(reservationId);
    })());
  }

  resizeCapacityReservation(
    reservationId: string,
    requiredBytes: number,
  ): ArtifactCatalogReservation {
    this.assertOpen();
    if (!Number.isSafeInteger(requiredBytes) || requiredBytes < 0) {
      throw stateInvalid("requiredBytes must be a non-negative safe integer.");
    }
    return this.catalogOperation("resize capacity reservation", () => this.sqlite.transaction(() => {
      const reservation = this.requiredActiveReservation(reservationId);
      if (reservation.bytesCommitted || reservation.objectSha256) {
        throw stateInvalid("Committed artifact capacity cannot be resized.");
      }
      const stats = this.stats();
      const availableIncludingReservation = this.maximumTotalBytes
        - stats.totalBytes
        - stats.reservedBytes
        + reservation.bytesReserved;
      if (requiredBytes > availableIncludingReservation) {
        throw quotaExceeded("Artifact byte quota is full before destination mutation.", {
          availableBytes: Math.max(availableIncludingReservation, 0),
          requiredBytes,
        });
      }
      this.sqlite.prepare(`
        UPDATE artifact_reservations SET bytes_reserved = ?, updated_at = ?
        WHERE reservation_id = ? AND state = 'ACTIVE' AND bytes_committed = 0
      `).run(requiredBytes, this.checkedNow(), reservationId);
      return this.requiredActiveReservation(reservationId);
    })());
  }

  maximizeCapacityReservation(
    reservationId: string,
    requestedMaximumBytes: number,
  ): ArtifactCatalogReservation {
    this.assertOpen();
    const maximumBytes = positiveSafeInteger(requestedMaximumBytes, "requestedMaximumBytes");
    return this.catalogOperation("maximize capacity reservation", () => this.sqlite.transaction(() => {
      const reservation = this.requiredActiveReservation(reservationId);
      if (reservation.bytesCommitted || reservation.objectSha256) {
        throw stateInvalid("Committed artifact capacity cannot be resized.");
      }
      const stats = this.stats();
      const availableIncludingReservation = this.maximumTotalBytes
        - stats.totalBytes
        - stats.reservedBytes
        + reservation.bytesReserved;
      const requiredBytes = Math.min(maximumBytes, Math.max(availableIncludingReservation, 0));
      if (requiredBytes === 0) {
        throw quotaExceeded("Artifact byte quota is full before source open.", {
          availableBytes: Math.max(availableIncludingReservation, 0),
          requestedMaximumBytes: maximumBytes,
        });
      }
      this.sqlite.prepare(`
        UPDATE artifact_reservations SET bytes_reserved = ?, updated_at = ?
        WHERE reservation_id = ? AND state = 'ACTIVE' AND bytes_committed = 0
      `).run(requiredBytes, this.checkedNow(), reservationId);
      return this.requiredActiveReservation(reservationId);
    })());
  }

  attachObject(
    reservationId: string,
    input: { path: string; sha256: string; size: number },
  ): ArtifactCatalogObject {
    this.assertOpen();
    validateDigest(input.sha256);
    if (!Number.isSafeInteger(input.size) || input.size < 0) throw stateInvalid("Object size is invalid.");
    const objectPath = resolve(input.path);
    if (!isInside(this.objectRoot, objectPath)) {
      throw stateInvalid("CAS object path must remain under the configured object root.");
    }
    return this.catalogOperation("attach CAS object", () => this.sqlite.transaction(() => {
      const reservation = this.requiredActiveReservation(reservationId);
      if (reservation.objectSha256) {
        if (reservation.objectSha256 !== input.sha256) throw stateInvalid("Reservation is attached to another object.");
        return this.requiredObject(input.sha256);
      }
      const existing = this.getObject(input.sha256);
      if (
        existing
        && existing.state !== "DELETED"
        && (existing.path !== objectPath || existing.size !== input.size || existing.state !== "AVAILABLE")
      ) {
        throw stateInvalid("CAS digest metadata conflicts with the durable catalog.", { sha256: input.sha256 });
      }
      const reusable = existing?.state === "AVAILABLE"
        && existing.path === objectPath
        && existing.size === input.size;
      if (input.size > reservation.bytesReserved && !reusable) {
        throw quotaExceeded("Artifact bytes exceeded the synchronously reserved capacity.", {
          size: input.size,
          reservedBytes: reservation.bytesReserved,
        });
      }
      if (existing?.state === "DELETED") {
        this.sqlite.prepare(`
          UPDATE artifact_objects
          SET object_path = ?, size = ?, ref_count = 0, state = 'AVAILABLE',
              reconciliation_status = 'PENDING', updated_at = ?
          WHERE sha256 = ?
        `).run(objectPath, input.size, this.checkedNow(), input.sha256);
      } else if (!existing) {
        const now = this.checkedNow();
        this.sqlite.prepare(`
          INSERT INTO artifact_objects (
            sha256, object_path, size, ref_count, state, reconciliation_status, created_at, updated_at
          ) VALUES (?, ?, ?, 0, 'AVAILABLE', 'PENDING', ?, ?)
        `).run(input.sha256, objectPath, input.size, now, now);
      }
      this.sqlite.prepare(`
        UPDATE artifact_reservations
        SET bytes_committed = 1, object_sha256 = ?, updated_at = ?
        WHERE reservation_id = ? AND state = 'ACTIVE'
      `).run(input.sha256, this.checkedNow(), reservationId);
      return this.requiredObject(input.sha256);
    })());
  }

  commitArtifact(
    reservationId: string,
    objectSha256: string,
    input: {
      artifactId: string;
      ownerFingerprint: string;
      tokenHash: string;
      name: string;
      mimeType: string;
      source: string;
      destination?: string;
      createdAt: number;
      expiresAt: number;
    },
  ): ArtifactCatalogRecord {
    this.assertOpen();
    validateDigest(objectSha256);
    validateDigest(input.tokenHash);
    return this.catalogOperation("commit artifact", () => this.sqlite.transaction(() => {
      const reservation = this.requiredActiveReservation(reservationId);
      if (!reservation.bytesCommitted || reservation.objectSha256 !== objectSha256) {
        throw stateInvalid("Artifact reservation cannot commit this object.");
      }
      if (reservation.ownerFingerprint !== input.ownerFingerprint) {
        throw stateInvalid("Artifact owner does not match its capacity reservation.");
      }
      if (!Number.isSafeInteger(input.createdAt) || !Number.isSafeInteger(input.expiresAt) || input.expiresAt <= input.createdAt) {
        throw stateInvalid("Artifact timestamps are invalid.");
      }
      const object = this.requiredObject(objectSha256);
      if (object.state !== "AVAILABLE") throw stateInvalid("CAS object is unavailable.");
      const artifactId = requiredText(input.artifactId, "artifactId", 512);
      const ownerFingerprint = requiredText(input.ownerFingerprint, "ownerFingerprint", 512);
      const name = requiredText(input.name, "name", 4_096);
      const mimeType = requiredText(input.mimeType, "mimeType", 1_024);
      const source = requiredText(input.source, "source", 16_384);
      const resourceUri = formatResourceUri({ kind: "artifact", artifactId });
      const existing = this.getArtifact(artifactId);
      if (existing) {
        if (
          existing.state !== "AVAILABLE"
          || existing.objectSha256 !== objectSha256
          || existing.ownerFingerprint !== ownerFingerprint
          || existing.name !== name
          || existing.mimeType !== mimeType
          || existing.source !== source
          || existing.destination !== input.destination
          || existing.resourceUri !== resourceUri
          || existing.size !== object.size
          || existing.sha256 !== object.sha256
          || existing.cleanupStatus !== "NONE"
          || existing.reconciliationStatus !== "VERIFIED"
        ) {
          throw stateInvalid("Idempotent artifact commit conflicts with an existing record.", {
            artifactId,
            objectSha256,
          });
        }
        this.sqlite.prepare(`
          UPDATE artifact_reservations SET state = 'COMMITTED', entry_reserved = 0, updated_at = ?
          WHERE reservation_id = ? AND state = 'ACTIVE'
        `).run(this.checkedNow(), reservationId);
        return existing;
      }
      if (!reservation.entryReserved) {
        throw stateInvalid("A new artifact record requires a reserved entry.");
      }
      this.sqlite.prepare(`
        INSERT INTO artifact_records (
          artifact_id, owner_fingerprint, object_sha256, name, mime_type, size, sha256,
          token_hash, source, destination, state, created_at, expires_at, resource_uri,
          cleanup_status, reconciliation_status
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'AVAILABLE', ?, ?, ?, 'NONE', 'VERIFIED')
      `).run(
        artifactId,
        ownerFingerprint,
        objectSha256,
        name,
        mimeType,
        object.size,
        object.sha256,
        input.tokenHash,
        source,
        input.destination ?? null,
        input.createdAt,
        input.expiresAt,
        resourceUri,
      );
      this.sqlite.prepare(`
        UPDATE artifact_objects
        SET ref_count = ref_count + 1, reconciliation_status = 'VERIFIED', updated_at = ?
        WHERE sha256 = ? AND state = 'AVAILABLE'
      `).run(this.checkedNow(), objectSha256);
      this.sqlite.prepare(`
        UPDATE artifact_reservations SET state = 'COMMITTED', entry_reserved = 0, updated_at = ?
        WHERE reservation_id = ? AND state = 'ACTIVE'
      `).run(this.checkedNow(), reservationId);
      return this.requiredArtifact(artifactId);
    })());
  }

  abortReservation(reservationId: string): ArtifactCleanupPlan[] {
    this.assertOpen();
    return this.catalogOperation("abort reservation", () => this.sqlite.transaction(() => {
      const row = this.reservation(reservationId);
      if (!row || row.state !== "ACTIVE") return [];
      this.sqlite.prepare(`
        UPDATE artifact_reservations SET state = 'ABORTED', entry_reserved = 0, updated_at = ?
        WHERE reservation_id = ? AND state = 'ACTIVE'
      `).run(this.checkedNow(), reservationId);
      if (!row.objectSha256 || this.availableReferenceCount(row.objectSha256) > 0 || this.activeReservationCount(row.objectSha256) > 0) {
        return [];
      }
      const object = this.getObject(row.objectSha256);
      if (!object || object.state !== "AVAILABLE") return [];
      this.sqlite.prepare(`
        UPDATE artifact_objects SET state = 'CLEANUP_PENDING', updated_at = ? WHERE sha256 = ?
      `).run(this.checkedNow(), object.sha256);
      const receiptId = this.insertReceipt({
        objectSha256: object.sha256,
        reason: "RESERVATION_ABORTED",
        status: "PLANNED",
      });
      return [{ receiptId, object: { ...object, state: "CLEANUP_PENDING" as const } }];
    })());
  }

  expireDue(now = this.checkedNow()): { expiredRecords: number; cleanup: ArtifactCleanupPlan[] } {
    this.assertOpen();
    if (!Number.isSafeInteger(now) || now < 0) throw stateInvalid("Expiry timestamp is invalid.");
    return this.catalogOperation("expire artifacts", () => this.sqlite.transaction(() => {
      const expired = this.sqlite.prepare(`
        SELECT artifact_id AS artifactId, object_sha256 AS objectSha256
        FROM artifact_records WHERE state = 'AVAILABLE' AND expires_at <= ?
        ORDER BY artifact_id
      `).all(now) as Array<{ artifactId: string; objectSha256: string }>;
      const touched = new Set<string>();
      for (const record of expired) {
        this.sqlite.prepare(`
          UPDATE artifact_records
          SET state = 'EXPIRED', cleanup_status = 'EXPIRED'
          WHERE artifact_id = ? AND state = 'AVAILABLE'
        `).run(record.artifactId);
        this.sqlite.prepare(`
          UPDATE artifact_objects SET ref_count = MAX(ref_count - 1, 0), updated_at = ? WHERE sha256 = ?
        `).run(now, record.objectSha256);
        this.insertReceipt({
          artifactId: record.artifactId,
          objectSha256: record.objectSha256,
          reason: "ARTIFACT_EXPIRED",
          status: "COMPLETED",
        });
        touched.add(record.objectSha256);
      }
      const cleanup: ArtifactCleanupPlan[] = [];
      for (const sha256 of touched) {
        const object = this.getObject(sha256);
        if (!object || object.references > 0 || this.activeReservationCount(sha256) > 0 || object.state !== "AVAILABLE") continue;
        this.sqlite.prepare(`UPDATE artifact_objects SET state = 'CLEANUP_PENDING', updated_at = ? WHERE sha256 = ?`).run(now, sha256);
        const receiptId = this.insertReceipt({
          objectSha256: sha256,
          reason: "CAS_REFCOUNT_ZERO",
          status: "PLANNED",
        });
        cleanup.push({ receiptId, object: { ...object, state: "CLEANUP_PENDING" } });
      }
      return { expiredRecords: expired.length, cleanup };
    })());
  }

  completeObjectCleanup(receiptId: string, sha256: string, succeeded: boolean, detail?: string): void {
    this.assertOpen();
    validateDigest(sha256);
    this.catalogOperation("complete object cleanup", () => this.sqlite.transaction(() => {
      const now = this.checkedNow();
      this.sqlite.prepare(`
        UPDATE artifact_cleanup_receipts
        SET status = ?, detail = ?, completed_at = ?
        WHERE receipt_id = ? AND object_sha256 = ? AND status = 'PLANNED'
      `).run(succeeded ? "COMPLETED" : "FAILED", detail ?? null, now, receiptId, sha256);
      this.sqlite.prepare(`
        UPDATE artifact_objects
        SET state = ?, reconciliation_status = ?, updated_at = ?
        WHERE sha256 = ? AND state = 'CLEANUP_PENDING'
      `).run(succeeded ? "DELETED" : "CLEANUP_PENDING", succeeded ? "CLEANED" : "CLEANUP_FAILED", now, sha256);
    })());
  }

  getArtifact(artifactId: string): ArtifactCatalogRecord | undefined {
    this.assertOpen();
    return this.catalogOperation("read artifact", () => {
      const row = this.sqlite.prepare(RECORD_SELECT + " WHERE r.artifact_id = ?").get(artifactId) as ArtifactRecordRow | undefined;
      return row ? recordFromRow(row) : undefined;
    });
  }

  getAvailableArtifact(artifactId: string, now = this.checkedNow()): ArtifactCatalogRecord | undefined {
    const record = this.getArtifact(artifactId);
    return record?.state === "AVAILABLE" && record.expiresAt > now ? record : undefined;
  }

  getObject(sha256: string): ArtifactCatalogObject | undefined {
    this.assertOpen();
    const row = this.sqlite.prepare(OBJECT_SELECT + " WHERE sha256 = ?").get(sha256) as ArtifactObjectRow | undefined;
    return row ? objectFromRow(row) : undefined;
  }

  matchesCapabilityToken(record: Pick<ArtifactCatalogRecord, "tokenHash">, rawToken: string): boolean {
    if (typeof rawToken !== "string" || rawToken.length === 0 || rawToken.length > 4_096) return false;
    const expected = Buffer.from(record.tokenHash, "hex");
    const actual = Buffer.from(artifactCapabilityTokenHash(rawToken), "hex");
    return expected.length === actual.length && timingSafeEqual(expected, actual);
  }

  stats(): {
    artifacts: number;
    objects: number;
    totalBytes: number;
    reservations: number;
    reservedEntries: number;
    reservedBytes: number;
  } {
    this.assertOpen();
    return this.catalogOperation("read catalog statistics", () => {
      const row = this.sqlite.prepare(`
        SELECT
          (SELECT COUNT(*) FROM artifact_records WHERE state = 'AVAILABLE') AS artifacts,
          (SELECT COUNT(*) FROM artifact_objects WHERE state IN ('AVAILABLE', 'CLEANUP_PENDING')) AS objects,
          (SELECT COALESCE(SUM(size), 0) FROM artifact_objects WHERE state IN ('AVAILABLE', 'CLEANUP_PENDING')) AS totalBytes,
          (SELECT COUNT(*) FROM artifact_reservations WHERE state = 'ACTIVE') AS reservations,
          (SELECT COALESCE(SUM(entry_reserved), 0) FROM artifact_reservations WHERE state = 'ACTIVE') AS reservedEntries,
          (SELECT COALESCE(SUM(CASE WHEN bytes_committed = 0 THEN bytes_reserved ELSE 0 END), 0)
             FROM artifact_reservations WHERE state = 'ACTIVE') AS reservedBytes
      `).get() as {
        artifacts: number;
        objects: number;
        totalBytes: number;
        reservations: number;
        reservedEntries: number;
        reservedBytes: number;
      };
      return row;
    });
  }

  listCleanupReceipts(): ArtifactCleanupReceipt[] {
    this.assertOpen();
    const rows = this.sqlite.prepare(`
      SELECT receipt_id AS receiptId, artifact_id AS artifactId, object_sha256 AS objectSha256,
             reason, status, detail, created_at AS createdAt, completed_at AS completedAt
      FROM artifact_cleanup_receipts ORDER BY created_at, receipt_id
    `).all() as CleanupReceiptRow[];
    return rows.map((row) => ({
      receiptId: row.receiptId,
      ...(row.artifactId ? { artifactId: row.artifactId } : {}),
      ...(row.objectSha256 ? { objectSha256: row.objectSha256 } : {}),
      reason: row.reason,
      status: row.status,
      ...(row.detail ? { detail: row.detail } : {}),
      createdAt: row.createdAt,
      ...(row.completedAt === null ? {} : { completedAt: row.completedAt }),
    }));
  }

  checkpoint(): void {
    this.assertOpen();
    this.catalogOperation("checkpoint catalog", () => {
      this.sqlite.pragma("wal_checkpoint(FULL)");
    });
  }

  close(): void {
    if (this.closed) return;
    try {
      this.sqlite.pragma("wal_checkpoint(TRUNCATE)");
      this.sqlite.close();
      this.closed = true;
    } catch (error) {
      throw unavailable("Artifact catalog could not be closed cleanly.", error);
    }
  }

  private migrate(): void {
    this.sqlite.exec(`
      CREATE TABLE IF NOT EXISTS artifact_objects (
        sha256 TEXT PRIMARY KEY CHECK(length(sha256) = 64),
        object_path TEXT NOT NULL UNIQUE,
        size INTEGER NOT NULL CHECK(size >= 0),
        ref_count INTEGER NOT NULL DEFAULT 0 CHECK(ref_count >= 0),
        state TEXT NOT NULL CHECK(state IN ('AVAILABLE', 'CLEANUP_PENDING', 'QUARANTINED', 'DELETED')),
        reconciliation_status TEXT NOT NULL,
        created_at INTEGER NOT NULL,
        updated_at INTEGER NOT NULL
      ) STRICT;

      CREATE TABLE IF NOT EXISTS artifact_records (
        artifact_id TEXT PRIMARY KEY,
        owner_fingerprint TEXT NOT NULL,
        object_sha256 TEXT NOT NULL,
        name TEXT NOT NULL,
        mime_type TEXT NOT NULL,
        size INTEGER NOT NULL CHECK(size >= 0),
        sha256 TEXT NOT NULL CHECK(length(sha256) = 64),
        token_hash TEXT NOT NULL CHECK(length(token_hash) = 64),
        source TEXT NOT NULL,
        destination TEXT,
        state TEXT NOT NULL CHECK(state IN ('AVAILABLE', 'EXPIRED', 'QUARANTINED')),
        created_at INTEGER NOT NULL,
        expires_at INTEGER NOT NULL,
        resource_uri TEXT NOT NULL,
        cleanup_status TEXT NOT NULL,
        reconciliation_status TEXT NOT NULL,
        FOREIGN KEY(object_sha256) REFERENCES artifact_objects(sha256)
      ) STRICT;

      CREATE INDEX IF NOT EXISTS artifact_records_expiry_idx
        ON artifact_records(state, expires_at);
      CREATE INDEX IF NOT EXISTS artifact_records_object_idx
        ON artifact_records(object_sha256, state);

      CREATE TABLE IF NOT EXISTS artifact_reservations (
        reservation_id TEXT PRIMARY KEY,
        owner_fingerprint TEXT NOT NULL,
        entry_reserved INTEGER NOT NULL CHECK(entry_reserved IN (0, 1)),
        bytes_reserved INTEGER NOT NULL CHECK(bytes_reserved >= 0),
        bytes_committed INTEGER NOT NULL CHECK(bytes_committed IN (0, 1)),
        object_sha256 TEXT,
        state TEXT NOT NULL CHECK(state IN ('ACTIVE', 'COMMITTED', 'ABORTED')),
        created_at INTEGER NOT NULL,
        updated_at INTEGER NOT NULL
      ) STRICT;

      CREATE INDEX IF NOT EXISTS artifact_reservations_active_idx
        ON artifact_reservations(state, object_sha256);

      CREATE TABLE IF NOT EXISTS artifact_cleanup_receipts (
        receipt_id TEXT PRIMARY KEY,
        artifact_id TEXT,
        object_sha256 TEXT,
        reason TEXT NOT NULL,
        status TEXT NOT NULL CHECK(status IN ('PLANNED', 'COMPLETED', 'FAILED')),
        detail TEXT,
        created_at INTEGER NOT NULL,
        completed_at INTEGER
      ) STRICT;

      CREATE TABLE IF NOT EXISTS artifact_catalog_metadata (
        key TEXT PRIMARY KEY,
        value TEXT NOT NULL
      ) STRICT;
    `);
    const initialize = this.sqlite.transaction(() => {
      this.sqlite.prepare(`INSERT OR IGNORE INTO artifact_catalog_metadata(key, value) VALUES ('store_id', ?)`).run(randomUUID());
      this.sqlite.prepare(`INSERT OR IGNORE INTO artifact_catalog_metadata(key, value) VALUES ('schema_version', '1')`).run();
      this.sqlite.pragma("user_version = 1");
    });
    initialize();
  }

  private assertIntegrity(): void {
    this.assertOpen();
    const result = this.sqlite.pragma("quick_check", { simple: true });
    if (result !== "ok") throw unavailable("Artifact catalog integrity check failed.", undefined, { result });
    const foreignKeys = this.sqlite.pragma("foreign_key_check") as unknown[];
    if (foreignKeys.length > 0) {
      throw unavailable("Artifact catalog foreign-key check failed.", undefined, { violations: foreignKeys.length });
    }
  }

  private quarantineCatalogObject(sha256: string, reason: string, movedPath?: string): { records: number } {
    return this.catalogOperation("quarantine catalog object", () => this.sqlite.transaction(() => {
      const records = this.sqlite.prepare(`
        UPDATE artifact_records
        SET state = 'QUARANTINED', cleanup_status = 'QUARANTINED', reconciliation_status = ?
        WHERE object_sha256 = ? AND state = 'AVAILABLE'
      `).run(reason, sha256).changes;
      this.sqlite.prepare(`
        UPDATE artifact_objects
        SET ref_count = 0, state = 'QUARANTINED', reconciliation_status = ?, updated_at = ?
        WHERE sha256 = ?
      `).run(reason, this.checkedNow(), sha256);
      this.insertReceipt({
        objectSha256: sha256,
        reason,
        status: "COMPLETED",
        detail: movedPath ? `Quarantined CAS object as ${movedPath}.` : "CAS object was unavailable during quarantine.",
      });
      return { records };
    })());
  }

  private async quarantinePathIfPresent(path: string, sha256: string, reason: string): Promise<string | undefined> {
    const source = resolve(path);
    if (!isInside(this.objectRoot, source)) throw stateInvalid("Catalog object path escaped the object root.");
    try {
      await lstat(source);
    } catch (error) {
      if (isNodeError(error, "ENOENT")) return undefined;
      throw error;
    }
    const safeDigest = /^[0-9a-f]{64}$/u.test(sha256) ? sha256 : "unknown";
    const destination = join(
      this.quarantineRoot,
      `${this.checkedNow()}-${safeDigest}-${reason.toLowerCase()}-${randomUUID()}`,
    );
    try {
      await rename(source, destination);
    } catch (error) {
      if (!isNodeError(error, "EXDEV")) throw error;
      await copyFile(source, destination);
      await unlink(source);
    }
    return destination;
  }

  private insertReceipt(input: {
    artifactId?: string;
    objectSha256?: string;
    reason: string;
    status: ArtifactCleanupReceipt["status"];
    detail?: string;
  }): string {
    const receiptId = randomUUID();
    const now = this.checkedNow();
    this.sqlite.prepare(`
      INSERT INTO artifact_cleanup_receipts (
        receipt_id, artifact_id, object_sha256, reason, status, detail, created_at, completed_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    `).run(
      receiptId,
      input.artifactId ?? null,
      input.objectSha256 ?? null,
      input.reason,
      input.status,
      input.detail ?? null,
      now,
      input.status === "PLANNED" ? null : now,
    );
    return receiptId;
  }

  private reservation(reservationId: string): ArtifactCatalogReservation | undefined {
    const row = this.sqlite.prepare(RESERVATION_SELECT + " WHERE reservation_id = ?").get(reservationId) as ReservationRow | undefined;
    return row ? reservationFromRow(row) : undefined;
  }

  private requiredActiveReservation(reservationId: string): ArtifactCatalogReservation {
    const reservation = this.reservation(reservationId);
    if (!reservation || reservation.state !== "ACTIVE") throw stateInvalid("Artifact reservation is no longer active.");
    return reservation;
  }

  private requiredObject(sha256: string): ArtifactCatalogObject {
    const object = this.getObject(sha256);
    if (!object) throw stateInvalid("CAS object is missing from the catalog.", { sha256 });
    return object;
  }

  private requiredArtifact(artifactId: string): ArtifactCatalogRecord {
    const record = this.getArtifact(artifactId);
    if (!record) throw stateInvalid("Committed artifact record could not be read back.", { artifactId });
    return record;
  }

  private allObjects(): ArtifactCatalogObject[] {
    const rows = this.sqlite.prepare(OBJECT_SELECT + " ORDER BY sha256").all() as ArtifactObjectRow[];
    return rows.map(objectFromRow);
  }

  private allReservations(state: ArtifactCatalogReservation["state"]): ArtifactCatalogReservation[] {
    const rows = this.sqlite.prepare(RESERVATION_SELECT + " WHERE state = ? ORDER BY reservation_id").all(state) as ReservationRow[];
    return rows.map(reservationFromRow);
  }

  private availableReferenceCount(sha256: string): number {
    const row = this.sqlite.prepare(`
      SELECT COUNT(*) AS count FROM artifact_records WHERE object_sha256 = ? AND state = 'AVAILABLE'
    `).get(sha256) as { count: number };
    return row.count;
  }

  private activeReservationCount(sha256: string): number {
    const row = this.sqlite.prepare(`
      SELECT COUNT(*) AS count FROM artifact_reservations WHERE object_sha256 = ? AND state = 'ACTIVE'
    `).get(sha256) as { count: number };
    return row.count;
  }

  private checkedNow(): number {
    const value = this.now();
    if (!Number.isSafeInteger(value) || value < 0) throw stateInvalid("Artifact catalog clock is invalid.");
    return value;
  }

  private catalogOperation<T>(operation: string, action: () => T): T {
    try {
      return action();
    } catch (error) {
      if (error instanceof ArtifactCatalogError) throw error;
      throw unavailable(`Artifact catalog failed to ${operation}.`, error);
    }
  }

  private assertOpen(): void {
    if (this.closed) throw unavailable("Artifact catalog is closed.");
  }
}

export function artifactCapabilityTokenHash(rawToken: string): string {
  if (typeof rawToken !== "string" || rawToken.length === 0 || rawToken.length > 4_096) {
    throw stateInvalid("Artifact capability token is invalid.");
  }
  return createHash("sha256").update(rawToken).digest("hex");
}

const RECORD_SELECT = `
  SELECT r.artifact_id AS artifactId, r.owner_fingerprint AS ownerFingerprint,
         r.object_sha256 AS objectSha256, o.object_path AS objectPath,
         r.name, r.mime_type AS mimeType, r.size, r.sha256, r.token_hash AS tokenHash,
         r.source, r.destination, r.state, r.created_at AS createdAt, r.expires_at AS expiresAt,
         r.resource_uri AS resourceUri, r.cleanup_status AS cleanupStatus,
         r.reconciliation_status AS reconciliationStatus
  FROM artifact_records r
  JOIN artifact_objects o ON o.sha256 = r.object_sha256
`;

const OBJECT_SELECT = `
  SELECT object_path AS path, sha256, size, ref_count AS "references", state FROM artifact_objects
`;

const RESERVATION_SELECT = `
  SELECT reservation_id AS reservationId, owner_fingerprint AS ownerFingerprint,
         entry_reserved AS entryReserved, bytes_reserved AS bytesReserved,
         bytes_committed AS bytesCommitted, object_sha256 AS objectSha256, state
  FROM artifact_reservations
`;

function recordFromRow(row: ArtifactRecordRow): ArtifactCatalogRecord {
  return {
    artifactId: row.artifactId,
    ownerFingerprint: row.ownerFingerprint,
    objectSha256: row.objectSha256,
    objectPath: row.objectPath,
    name: row.name,
    mimeType: row.mimeType,
    size: row.size,
    sha256: row.sha256,
    tokenHash: row.tokenHash,
    source: row.source,
    ...(row.destination === null ? {} : { destination: row.destination }),
    state: row.state,
    createdAt: row.createdAt,
    expiresAt: row.expiresAt,
    resourceUri: row.resourceUri,
    cleanupStatus: row.cleanupStatus,
    reconciliationStatus: row.reconciliationStatus,
  };
}

function objectFromRow(row: ArtifactObjectRow): ArtifactCatalogObject {
  return { path: row.path, sha256: row.sha256, size: row.size, references: row.references, state: row.state };
}

function reservationFromRow(row: ReservationRow): ArtifactCatalogReservation {
  return {
    reservationId: row.reservationId,
    ownerFingerprint: row.ownerFingerprint,
    entryReserved: row.entryReserved === 1,
    bytesReserved: row.bytesReserved,
    bytesCommitted: row.bytesCommitted === 1,
    ...(row.objectSha256 ? { objectSha256: row.objectSha256 } : {}),
    state: row.state,
  };
}

async function validObjectFile(object: ArtifactCatalogObject): Promise<boolean> {
  try {
    const value = await lstat(object.path);
    if (!value.isFile() || value.isSymbolicLink() || value.size !== object.size) return false;
    return await sha256File(object.path) === object.sha256;
  } catch {
    return false;
  }
}

async function sha256File(path: string): Promise<string> {
  const digest = createHash("sha256");
  await pipeline(createReadStream(path), digest);
  return digest.digest("hex");
}

async function listFilesRecursively(root: string): Promise<string[]> {
  const files: string[] = [];
  const visit = async (directory: string): Promise<void> => {
    const entries = await readdir(directory, { withFileTypes: true });
    for (const entry of entries) {
      const path = join(directory, entry.name);
      if (entry.isDirectory()) await visit(path);
      else files.push(path);
    }
  };
  await visit(root);
  return files;
}

function positiveSafeInteger(value: number, field: string): number {
  if (!Number.isSafeInteger(value) || value < 1) throw stateInvalid(`${field} must be a positive safe integer.`);
  return value;
}

function requiredText(value: string, field: string, maximumLength: number): string {
  if (typeof value !== "string" || value.length === 0 || value.length > maximumLength) {
    throw stateInvalid(`${field} must be a bounded non-empty string.`);
  }
  return value;
}

function validateDigest(value: string): void {
  if (!/^[0-9a-f]{64}$/u.test(value)) throw stateInvalid("SHA-256 digest must be lowercase hexadecimal.");
}

function isInside(root: string, path: string): boolean {
  return path === root || path.startsWith(`${root}/`);
}

function quotaExceeded(message: string, evidence: Record<string, unknown> = {}): ArtifactCatalogError {
  return new ArtifactCatalogError("ARTIFACT_QUOTA_EXCEEDED", message, evidence);
}

function stateInvalid(message: string, evidence: Record<string, unknown> = {}): ArtifactCatalogError {
  return new ArtifactCatalogError("ARTIFACT_CATALOG_STATE_INVALID", message, evidence);
}

function unavailable(
  message: string,
  cause?: unknown,
  evidence: Record<string, unknown> = {},
): ArtifactCatalogError {
  return new ArtifactCatalogError(
    "ARTIFACT_CATALOG_UNAVAILABLE",
    message,
    evidence,
    cause === undefined ? undefined : { cause },
  );
}

function isNodeError(error: unknown, code: string): error is NodeJS.ErrnoException {
  return error instanceof Error && (error as NodeJS.ErrnoException).code === code;
}
