import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { mkdir, mkdtemp, readdir, rm, unlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import {
  ArtifactCatalog,
  ArtifactCatalogError,
  artifactCapabilityTokenHash,
} from "./artifact-catalog.js";

test("catalog durably preserves records, hash-only tokens, CAS refcounts, and reservations", async (t) => {
  const fixture = await catalogFixture(t);
  const content = Buffer.from("durable artifact\n");
  const digest = createHash("sha256").update(content).digest("hex");
  const objectPath = join(fixture.objectRoot, "sha256", digest.slice(0, 2), digest);
  const catalog = new ArtifactCatalog(fixture.options);
  await catalog.reconcile();
  await mkdir(join(fixture.objectRoot, "sha256", digest.slice(0, 2)), { recursive: true });
  await writeFile(objectPath, content);
  for (const artifactId of ["artifact-one", "artifact-two"]) {
    const reservation = catalog.reserveCapacity({
      ownerFingerprint: "owner-a",
      requestedMaximumBytes: content.length,
      declaredSize: content.length,
      reserveEntry: true,
    });
    const object = catalog.attachObject(reservation.reservationId, {
      path: objectPath,
      sha256: digest,
      size: content.length,
    });
    catalog.commitArtifact(reservation.reservationId, object.sha256, {
      artifactId,
      ownerFingerprint: "owner-a",
      tokenHash: artifactCapabilityTokenHash(`token-${artifactId}`),
      name: `${artifactId}.txt`,
      mimeType: "text/plain",
      source: "fixture",
      createdAt: fixture.clock.value,
      expiresAt: fixture.clock.value + 60_000,
    });
  }
  assert.deepEqual(catalog.stats(), {
    artifacts: 2,
    objects: 1,
    totalBytes: content.length,
    reservations: 0,
    reservedEntries: 0,
    reservedBytes: 0,
  });
  assert.equal(catalog.getObject(digest)?.references, 2);
  catalog.close();

  const reopened = new ArtifactCatalog(fixture.options);
  const report = await reopened.reconcile();
  assert.equal(report.quarantinedObjects, 0);
  const record = reopened.getAvailableArtifact("artifact-one", fixture.clock.value);
  assert.equal(record?.tokenHash, artifactCapabilityTokenHash("token-artifact-one"));
  assert.equal(reopened.matchesCapabilityToken(record!, "token-artifact-one"), true);
  assert.equal(reopened.matchesCapabilityToken(record!, "wrong-token"), false);
  assert.equal(reopened.getObject(digest)?.references, 2);
  reopened.close();
});

test("catalog idempotently commits a retried artifact without duplicating records or CAS references", async (t) => {
  const fixture = await catalogFixture(t);
  const content = Buffer.from("idempotent artifact\n");
  const digest = createHash("sha256").update(content).digest("hex");
  const objectPath = join(fixture.objectRoot, "sha256", digest.slice(0, 2), digest);
  await mkdir(join(fixture.objectRoot, "sha256", digest.slice(0, 2)), { recursive: true });
  await writeFile(objectPath, content);
  const catalog = new ArtifactCatalog(fixture.options);
  await catalog.reconcile();

  const commit = (reservationId: string, token: string, createdAt: number) =>
    catalog.commitArtifact(reservationId, digest, {
      artifactId: "artifact-idempotent",
      ownerFingerprint: "owner-a",
      tokenHash: artifactCapabilityTokenHash(token),
      name: "idempotent.txt",
      mimeType: "text/plain",
      source: "fixture-source",
      destination: "fixture-destination",
      createdAt,
      expiresAt: createdAt + 60_000,
    });

  const firstReservation = catalog.reserveCapacity({
    ownerFingerprint: "owner-a",
    requestedMaximumBytes: content.length,
    declaredSize: content.length,
    reserveEntry: true,
  });
  catalog.attachObject(firstReservation.reservationId, {
    path: objectPath,
    sha256: digest,
    size: content.length,
  });
  const first = commit(firstReservation.reservationId, "first-token", fixture.clock.value);

  const retryReservation = catalog.reserveCapacity({
    ownerFingerprint: "owner-a",
    requestedMaximumBytes: 1_000,
    provisionalMaximumBytes: 1,
    reserveEntry: false,
  });
  assert.equal(retryReservation.bytesReserved, 1);
  assert.equal(retryReservation.entryReserved, false);
  const expanded = catalog.maximizeCapacityReservation(retryReservation.reservationId, 1_000);
  assert.equal(expanded.bytesReserved, 1_000);
  catalog.attachObject(retryReservation.reservationId, {
    path: objectPath,
    sha256: digest,
    size: content.length,
  });
  const retried = commit(retryReservation.reservationId, "retry-token", fixture.clock.value + 1);

  assert.equal(retried.artifactId, first.artifactId);
  assert.equal(retried.tokenHash, first.tokenHash);
  assert.equal(catalog.getObject(digest)?.references, 1);
  assert.deepEqual(catalog.stats(), {
    artifacts: 1,
    objects: 1,
    totalBytes: content.length,
    reservations: 0,
    reservedEntries: 0,
    reservedBytes: 0,
  });
  catalog.close();
});

test("startup reconciliation quarantines orphan and corrupt CAS bytes with receipts", async (t) => {
  const fixture = await catalogFixture(t);
  const catalog = new ArtifactCatalog(fixture.options);
  await catalog.reconcile();
  const content = Buffer.from("catalogued\n");
  const digest = createHash("sha256").update(content).digest("hex");
  const objectPath = join(fixture.objectRoot, "sha256", digest.slice(0, 2), digest);
  await mkdir(join(fixture.objectRoot, "sha256", digest.slice(0, 2)), { recursive: true });
  await writeFile(objectPath, content);
  const reservation = catalog.reserveCapacity({
    ownerFingerprint: "owner-a",
    requestedMaximumBytes: content.length,
    declaredSize: content.length,
    reserveEntry: true,
  });
  catalog.attachObject(reservation.reservationId, { path: objectPath, sha256: digest, size: content.length });
  catalog.commitArtifact(reservation.reservationId, digest, {
    artifactId: "artifact-corrupt",
    ownerFingerprint: "owner-a",
    tokenHash: artifactCapabilityTokenHash("capability"),
    name: "corrupt.txt",
    mimeType: "text/plain",
    source: "fixture",
    createdAt: fixture.clock.value,
    expiresAt: fixture.clock.value + 60_000,
  });
  catalog.close();
  await writeFile(objectPath, "tampered!!\n");

  const orphanBytes = Buffer.from("orphan\n");
  const orphanDigest = createHash("sha256").update(orphanBytes).digest("hex");
  const orphanPath = join(fixture.objectRoot, "sha256", orphanDigest.slice(0, 2), orphanDigest);
  await mkdir(join(fixture.objectRoot, "sha256", orphanDigest.slice(0, 2)), { recursive: true });
  await writeFile(orphanPath, orphanBytes);

  const reopened = new ArtifactCatalog(fixture.options);
  const report = await reopened.reconcile();
  assert.equal(report.quarantinedObjects, 2);
  assert.equal(reopened.getArtifact("artifact-corrupt")?.state, "QUARANTINED");
  assert.equal(reopened.getAvailableArtifact("artifact-corrupt", fixture.clock.value), undefined);
  const receipts = reopened.listCleanupReceipts();
  assert.equal(receipts.some((receipt) => receipt.reason === "CAS_OBJECT_CORRUPT"), true);
  assert.equal(receipts.some((receipt) => receipt.reason === "CAS_OBJECT_ORPHAN"), true);
  assert.equal((await readdir(fixture.quarantineRoot)).length >= 2, true);
  reopened.close();
});

test("startup aborts a crash-left reservation without evicting live records", async (t) => {
  const fixture = await catalogFixture(t);
  const catalog = new ArtifactCatalog(fixture.options);
  await catalog.reconcile();
  catalog.reserveCapacity({
    ownerFingerprint: "owner-a",
    requestedMaximumBytes: 50,
    declaredSize: 50,
    reserveEntry: true,
  });
  catalog.close();

  const reopened = new ArtifactCatalog(fixture.options);
  const report = await reopened.reconcile();
  assert.equal(report.abortedReservations, 1);
  assert.equal(reopened.stats().reservations, 0);
  assert.equal(reopened.listCleanupReceipts().some((receipt) => receipt.reason === "RESERVATION_RECOVERED"), true);
  reopened.close();
});

test("expiry decrements durable refcounts and cleans bytes only after the last live reference", async (t) => {
  const fixture = await catalogFixture(t);
  const catalog = new ArtifactCatalog(fixture.options);
  await catalog.reconcile();
  const content = Buffer.from("shared-expiry\n");
  const digest = createHash("sha256").update(content).digest("hex");
  const objectPath = join(fixture.objectRoot, "sha256", digest.slice(0, 2), digest);
  await mkdir(join(fixture.objectRoot, "sha256", digest.slice(0, 2)), { recursive: true });
  await writeFile(objectPath, content);
  for (const [artifactId, expiresAt] of [["expires-first", 100], ["expires-last", 200]] as const) {
    const reservation = catalog.reserveCapacity({
      ownerFingerprint: "owner-a",
      requestedMaximumBytes: content.length,
      declaredSize: content.length,
      reserveEntry: true,
    });
    catalog.attachObject(reservation.reservationId, { path: objectPath, sha256: digest, size: content.length });
    catalog.commitArtifact(reservation.reservationId, digest, {
      artifactId,
      ownerFingerprint: "owner-a",
      tokenHash: artifactCapabilityTokenHash(`token-${artifactId}`),
      name: "expiry.txt",
      mimeType: "text/plain",
      source: "fixture",
      createdAt: fixture.clock.value,
      expiresAt: fixture.clock.value + expiresAt,
    });
  }

  fixture.clock.value += 101;
  const first = catalog.expireDue();
  assert.equal(first.expiredRecords, 1);
  assert.equal(first.cleanup.length, 0);
  assert.equal(catalog.getObject(digest)?.references, 1);

  fixture.clock.value += 100;
  const last = catalog.expireDue();
  assert.equal(last.expiredRecords, 1);
  assert.equal(last.cleanup.length, 1);
  assert.equal(catalog.getObject(digest)?.references, 0);
  await unlink(last.cleanup[0]!.object.path);
  catalog.completeObjectCleanup(last.cleanup[0]!.receiptId, digest, true);
  assert.equal(catalog.stats().objects, 0);
  assert.equal(catalog.stats().totalBytes, 0);
  assert.equal(catalog.listCleanupReceipts().some((receipt) => (
    receipt.reason === "CAS_REFCOUNT_ZERO" && receipt.status === "COMPLETED"
  )), true);
  catalog.close();
});

test("catalog corruption fails closed with a typed unavailable reason", async (t) => {
  const fixture = await catalogFixture(t);
  const catalog = new ArtifactCatalog(fixture.options);
  await catalog.reconcile();
  catalog.close();
  await writeFile(fixture.options.catalogPath, "not-a-sqlite-database");
  assert.throws(
    () => new ArtifactCatalog(fixture.options),
    (error: unknown) => error instanceof ArtifactCatalogError
      && error.reason === "ARTIFACT_CATALOG_UNAVAILABLE",
  );
});

async function catalogFixture(t: test.TestContext) {
  const root = await mkdtemp(join(tmpdir(), "devspace-artifact-catalog-"));
  t.after(() => rm(root, { recursive: true, force: true }));
  const clock = { value: 1_787_200_000_000 };
  const objectRoot = join(root, "objects");
  const quarantineRoot = join(root, "quarantine");
  return {
    root,
    objectRoot,
    quarantineRoot,
    clock,
    options: {
      catalogPath: join(root, "artifacts.sqlite"),
      objectRoot,
      quarantineRoot,
      maximumEntries: 8,
      maximumTotalBytes: 10_000,
      now: () => clock.value,
    },
  };
}
