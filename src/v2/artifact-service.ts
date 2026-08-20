import {
  createHash,
  randomBytes,
  randomUUID,
} from "node:crypto";
import { spawn } from "node:child_process";
import { constants as fsConstants, createReadStream, createWriteStream, type Stats } from "node:fs";
import {
  access,
  chmod,
  copyFile,
  link,
  lstat,
  mkdir,
  mkdtemp,
  open,
  readdir,
  readFile,
  rename,
  rm,
  stat,
  unlink,
  writeFile,
} from "node:fs/promises";
import { homedir } from "node:os";
import { basename, dirname, isAbsolute, join, parse, relative, resolve, sep } from "node:path";
import { createInterface } from "node:readline";
import { Readable } from "node:stream";
import { pipeline } from "node:stream/promises";
import type { Request, Response as ExpressResponse } from "express";
import { ArtifactError } from "../artifact-error.js";
import {
  IncomingArtifactAdapterRegistry,
  type IncomingArtifactAdapter,
} from "../incoming-artifacts.js";
import { expandHomePath } from "../roots.js";
import { UniversalBrokerError } from "./errors.js";
import type { UniversalFilesystemService } from "./filesystem.js";
import type { CapabilityCallContext } from "./capability-call-context.js";
import {
  ArtifactCatalog,
  ArtifactCatalogError,
  artifactCapabilityTokenHash,
  type ArtifactCatalogObject,
  type ArtifactCatalogRecord,
  type ArtifactCatalogReservation,
  type ArtifactCleanupPlan,
  type ArtifactReconciliationReport,
} from "./artifact-catalog.js";
import { formatResourceUri, parseResourceUri, ResourceUriError } from "./resource-uri.js";
import type { UniversalBrokerMetrics } from "./metrics.js";

const DEFAULT_MAXIMUM_ENTRIES = 256;
const DEFAULT_MAXIMUM_TOTAL_BYTES = 2 * 1024 * 1024 * 1024;
const DEFAULT_MAXIMUM_ARTIFACT_BYTES = 2 * 1024 * 1024 * 1024;
const DEFAULT_TTL_MS = 24 * 60 * 60_000;
const MAXIMUM_TTL_MS = 24 * 60 * 60_000;
const DOWNLOAD_REDIRECT_LIMIT = 5;
const DOWNLOAD_TIMEOUT_MS = 60_000;
const DEFAULT_RESOURCE_READ_BYTES = 1024 * 1024;
const DEFAULT_OWNER_FINGERPRINT = "devspace-single-owner";
const DIRECTORY_COPY_LIST_PAGE_LIMIT = 1_000;
const COPY_PROVISIONAL_BYTES = 1;

export type UniversalArtifactOperation = "receive" | "publish" | "copy";

export interface UniversalArtifactInput {
  operation: UniversalArtifactOperation;
  source: Record<string, unknown>;
  destination?: Record<string, unknown>;
  overwrite?: boolean;
  maxBytes?: number;
  ttlSeconds?: number;
  authorityId?: string;
}

/** Compatible with the capability call-context being wired by the broker. */
export interface ArtifactCallContext {
  ownerFingerprint?: string;
  principalKeyFingerprint?: string;
}

export type ArtifactOwnerContext = string | ArtifactCallContext | CapabilityCallContext;

type ArtifactRecord = ArtifactCatalogRecord;
type ContentObject = ArtifactCatalogObject;
type CapacityReservation = ArtifactCatalogReservation;

export interface ArtifactCopyCheckpointEvent {
  copyId: string;
  ownerFingerprint: string;
  manifestDigest: string;
  checkpointPath: string;
  relativePath: string;
  completedEntries: number;
  totalEntries: number;
}

export interface ArtifactCopyHooks {
  afterEntryCheckpointed?: (event: ArtifactCopyCheckpointEvent) => void | Promise<void>;
}

interface ArtifactCopyTargetBinding {
  targetId: string;
  targetGeneration: string;
  endpointFingerprint: string;
  transport: "local" | "ssh";
  path: string;
  contextId?: string;
}

interface DirectoryManifestEntry {
  relativePath: string;
  size: number;
  sha256: string;
}

interface DirectoryManifestListEntry {
  name: string;
  type: "directory" | "file" | "symlink" | "other";
}

interface DirectoryManifestSnapshot {
  directories: string[];
  entries: DirectoryManifestEntry[];
  totalBytes: number;
  sourceIdentity: Record<string, unknown>;
}

interface DirectoryCopyCheckpoint {
  version: 1;
  copyId: string;
  ownerFingerprint: string;
  manifestDigest: string;
  source: ArtifactCopyTargetBinding;
  destination: ArtifactCopyTargetBinding;
  completedEntries: string[];
  status: "RUNNING" | "COMPLETED";
  createdAt: number;
  updatedAt: number;
  artifactId: string;
  resourceUri: string;
}

export interface UniversalArtifactServiceOptions {
  baseUrl?: string | (() => string);
  httpPathPrefix?: string;
  stagingRoot: string;
  catalogPath?: string;
  objectRoot?: string;
  quarantineRoot?: string;
  incomingAdapters?: readonly IncomingArtifactAdapter[];
  maximumEntries?: number;
  maximumTotalBytes?: number;
  maximumArtifactBytes?: number;
  ttlMs?: number;
  fetch?: typeof fetch;
  now?: () => number;
  defaultOwnerFingerprint?: string;
  copyHooks?: ArtifactCopyHooks;
  metrics?: UniversalBrokerMetrics;
}

export class UniversalArtifactService {
  private readonly incoming: IncomingArtifactAdapterRegistry;
  private readonly maximumEntries: number;
  private readonly maximumTotalBytes: number;
  private readonly maximumArtifactBytes: number;
  private readonly ttlMs: number;
  private readonly httpPathPrefix: string;
  private readonly fetcher: typeof fetch;
  private readonly now: () => number;
  private readonly defaultOwnerFingerprint: string;
  private readonly catalog: ArtifactCatalog;
  private readonly initialization: Promise<void>;
  private latestReconciliation?: Readonly<ArtifactReconciliationReport>;
  private inFlight = 0;
  private readonly idleWaiters = new Set<() => void>();
  private closed = false;

  constructor(
    private readonly filesystem: UniversalFilesystemService,
    private readonly options: UniversalArtifactServiceOptions,
  ) {
    this.incoming = new IncomingArtifactAdapterRegistry(options.incomingAdapters ?? []);
    this.maximumEntries = boundedInteger(options.maximumEntries, DEFAULT_MAXIMUM_ENTRIES, 1, 10_000, "maximumEntries");
    this.maximumTotalBytes = boundedInteger(options.maximumTotalBytes, DEFAULT_MAXIMUM_TOTAL_BYTES, 1, Number.MAX_SAFE_INTEGER, "maximumTotalBytes");
    this.maximumArtifactBytes = boundedInteger(options.maximumArtifactBytes, DEFAULT_MAXIMUM_ARTIFACT_BYTES, 1, Number.MAX_SAFE_INTEGER, "maximumArtifactBytes");
    this.ttlMs = boundedInteger(options.ttlMs, DEFAULT_TTL_MS, 1_000, MAXIMUM_TTL_MS, "ttlMs");
    this.httpPathPrefix = normalizeArtifactPathPrefix(options.httpPathPrefix);
    this.fetcher = options.fetch ?? globalThis.fetch;
    this.now = options.now ?? Date.now;
    this.defaultOwnerFingerprint = requiredOwnerFingerprint(
      options.defaultOwnerFingerprint ?? DEFAULT_OWNER_FINGERPRINT,
    );
    this.catalog = new ArtifactCatalog({
      catalogPath: options.catalogPath ?? join(options.stagingRoot, "artifacts.sqlite"),
      objectRoot: options.objectRoot ?? join(options.stagingRoot, "objects"),
      quarantineRoot: options.quarantineRoot ?? join(options.stagingRoot, "quarantine"),
      maximumEntries: this.maximumEntries,
      maximumTotalBytes: this.maximumTotalBytes,
      now: this.now,
    });
    this.initialization = this.catalog.reconcile().then((report) => {
      this.latestReconciliation = Object.freeze({ ...report });
    });
  }

  async execute(
    input: UniversalArtifactInput,
    context?: ArtifactOwnerContext,
  ): Promise<Record<string, unknown>> {
    try {
      const result = await this.runOperation(async () => {
        await this.pruneExpired();
        const ownerFingerprint = this.resolveOwner(context);
        const callContext = artifactCapabilityContext(context);
        switch (input.operation) {
          case "receive":
            return this.receive(input, ownerFingerprint, callContext);
          case "publish":
            return this.publish(input, ownerFingerprint, callContext);
          case "copy":
            return this.copy(input, ownerFingerprint, callContext);
        }
      });
      this.recordArtifactEvent("published", "pass");
      return result;
    } catch (error) {
      this.recordArtifactEvent("published", "fail");
      throw error;
    }
  }

  /** Resolve a canonical owner-bound resource handle for MCP resource wiring. */
  async readResource(
    resourceUri: string,
    context: ArtifactOwnerContext,
    offset = 0,
    maximumBytes = DEFAULT_RESOURCE_READ_BYTES,
  ): Promise<Record<string, unknown>> {
    try {
      const result = await this.runOperation(async () => {
      const artifactId = parseArtifactResourceUri(resourceUri);
      const record = await this.resolveRecord(
        artifactId,
        this.resolveOwner(context),
      );
      if (!Number.isSafeInteger(offset) || offset < 0) {
        throw new UniversalBrokerError("PRECONDITION_FAILED", "Artifact offset is invalid.");
      }
      const limit = boundedInteger(maximumBytes, DEFAULT_RESOURCE_READ_BYTES, 1, DEFAULT_RESOURCE_READ_BYTES, "maximumBytes");
      const handle = await open(record.objectPath, "r");
      try {
        const buffer = Buffer.alloc(Math.min(limit, Math.max(record.size - offset, 0)));
        const { bytesRead } = await handle.read(buffer, 0, buffer.length, offset);
        const nextOffset = offset + bytesRead;
        return {
          uri: canonicalArtifactResourceUri(record.artifactId),
          artifactId: record.artifactId,
          mimeType: record.mimeType,
          name: record.name,
          offset,
          bytesRead,
          size: record.size,
          sha256: record.sha256,
          blobBase64: buffer.subarray(0, bytesRead).toString("base64"),
          truncated: nextOffset < record.size,
          ...(nextOffset < record.size ? { nextOffset } : {}),
        };
      } finally {
        await handle.close();
      }
      });
      this.recordArtifactEvent("read", "pass");
      return result;
    } catch (error) {
      this.recordArtifactEvent("read", "fail");
      throw error;
    }
  }

  async handleHttp(
    req: Request,
    res: ExpressResponse,
    context?: ArtifactOwnerContext,
  ): Promise<void> {
    try {
      await this.runOperation(async () => {
        const artifactId = typeof req.params.artifactId === "string"
          ? req.params.artifactId
          : req.params.artifactId?.[0];
        const token = typeof req.query.token === "string" ? req.query.token : undefined;
        if (!artifactId || !token) {
          res.status(400).send("Missing artifact capability.");
          return;
        }
        const record = await this.resolveRecord(
          artifactId,
          context === undefined ? undefined : this.resolveOwner(context),
          token,
        );
        res.setHeader("Content-Type", record.mimeType);
        res.setHeader("Content-Length", String(record.size));
        res.setHeader("Content-Disposition", `attachment; filename*=UTF-8''${encodeURIComponent(record.name)}`);
        res.setHeader("Cache-Control", "private, no-store");
        res.setHeader("X-Content-Type-Options", "nosniff");
        res.setHeader("Content-Security-Policy", "default-src 'none'; sandbox");
        if (req.method === "HEAD") {
          res.status(200).end();
          return;
        }
        const stream = createReadStream(record.objectPath);
        stream.once("error", (error) => {
          if (!res.headersSent) res.status(500).end();
          else res.destroy(error);
        });
        stream.pipe(res);
      });
    } catch (error) {
      const status = error instanceof UniversalBrokerError
        && error.code === "PATH_NOT_FOUND"
        ? 404
        : 403;
      res.status(status).send("Artifact capability is invalid, unauthorized, or expired.");
    }
  }

  async close(): Promise<void> {
    if (this.closed) return;
    this.closed = true;
    await this.initialization;
    if (this.inFlight > 0) {
      await new Promise<void>((resolve) => this.idleWaiters.add(resolve));
    }
    this.catalog.checkpoint();
    this.catalog.close();
  }

  async cleanupExpired(): Promise<Record<string, unknown>> {
    this.recordArtifactEvent("cleanup_planned", "pass");
    try {
      const result = await this.runOperation(async () => {
        const before = this.catalog.stats().artifacts;
        await this.pruneExpired();
        const after = this.catalog.stats();
        return {
          removed: before - after.artifacts,
          remaining: after.artifacts,
          objects: after.objects,
          totalBytes: after.totalBytes,
        };
      });
      this.recordArtifactEvent("cleanup_completed", "pass");
      return result;
    } catch (error) {
      this.recordArtifactEvent("cleanup_failed", "fail");
      throw error;
    }
  }

  stats(): Record<string, unknown> {
    const stats = this.catalog.stats();
    return {
      artifacts: stats.artifacts,
      objects: stats.objects,
      totalBytes: stats.totalBytes,
      reservations: stats.reservations,
      reservedEntries: stats.reservedEntries,
      reservedBytes: stats.reservedBytes,
      maximumEntries: this.maximumEntries,
      maximumTotalBytes: this.maximumTotalBytes,
      maximumArtifactBytes: this.maximumArtifactBytes,
      ttlMs: this.ttlMs,
    };
  }

  async reconciliationReport(): Promise<Readonly<ArtifactReconciliationReport>> {
    await this.initialization;
    if (!this.latestReconciliation) {
      throw new UniversalBrokerError(
        "STATE_CORRUPTED",
        "Artifact startup reconciliation completed without a durable report.",
      );
    }
    return Object.freeze({ ...this.latestReconciliation });
  }

  private async receive(
    input: UniversalArtifactInput,
    ownerFingerprint: string,
    callContext?: CapabilityCallContext,
  ): Promise<Record<string, unknown>> {
    const maximumBytes = this.requestMaximumBytes(input.maxBytes);
    const expectedSize = optionalNumber(input.source, "size");
    const reservation = this.reserveCapacity(ownerFingerprint, maximumBytes, expectedSize, true);
    let object: ContentObject | undefined;
    let stagedDirectory: string | undefined;
    try {
      const staged = await this.stageIncoming(input.source, reservation.bytesReserved);
      stagedDirectory = staged.directory;
      object = await this.commitContentObject(staged.path, staged.size, staged.sha256, reservation);
      let published: Record<string, unknown> | undefined;
      const destinationPath = optionalString(input.destination, "path");
      if (destinationPath) {
        published = await this.filesystem.importLocalFile({
          target: optionalString(input.destination, "target"),
          contextId: optionalString(input.destination, "contextId"),
          path: destinationPath,
          localPath: object.path,
          overwrite: input.overwrite === true,
          expectedSha256: optionalString(input.destination, "expectedSha256"),
        }, callContext);
      }
      const committed = this.commitRecord(reservation, object, {
        name: staged.name,
        mimeType: staged.mimeType,
        source: staged.sourceKind,
        destination: destinationPath,
        ttlMs: this.requestTtlMs(input.ttlSeconds),
      });
      return {
        operation: "receive",
        ...(destinationPath ? { target: optionalString(input.destination, "target") ?? "local", path: destinationPath } : {}),
        artifactId: committed.record.artifactId,
        resourceUri: canonicalArtifactResourceUri(committed.record.artifactId),
        ...(this.downloadUrl(committed.record, committed.token)
          ? { downloadUrl: this.downloadUrl(committed.record, committed.token) }
          : {}),
        resourceName: committed.record.name,
        mimeType: committed.record.mimeType,
        size: committed.record.size,
        sha256: committed.record.sha256,
        sourceKind: staged.sourceKind,
        deduplicated: object.references > 0,
        ...(published ? { published } : {}),
        expiresAt: new Date(committed.record.expiresAt).toISOString(),
      };
    } catch (error) {
      await this.abortReservation(reservation);
      throw error;
    } finally {
      if (stagedDirectory) await rm(stagedDirectory, { recursive: true, force: true });
    }
  }

  private async publish(
    input: UniversalArtifactInput,
    ownerFingerprint: string,
    callContext?: CapabilityCallContext,
  ): Promise<Record<string, unknown>> {
    const source = input.source;
    const path = requiredString(source, "path", "artifact.publish source.path is required.");
    const maximumBytes = this.requestMaximumBytes(input.maxBytes);
    const reservation = this.reserveCapacity(
      ownerFingerprint,
      maximumBytes,
      optionalNumber(source, "size"),
      true,
    );
    let directory: string | undefined;
    try {
      directory = await this.createStagingDirectory("publish");
      const stagedPath = join(directory, "payload");
      const exported = await this.filesystem.exportToLocalFile({
        target: optionalString(source, "target"),
        contextId: optionalString(source, "contextId"),
        path,
        localPath: stagedPath,
      }, callContext);
      this.assertExpectedContent(source, exported.size, exported.sha256, reservation.bytesReserved);
      const object = await this.commitContentObject(stagedPath, exported.size, exported.sha256, reservation);
      const committed = this.commitRecord(reservation, object, {
        name: optionalString(source, "name") ?? (basename(path) || "artifact.bin"),
        mimeType: optionalString(source, "mimeType") ?? "application/octet-stream",
        source: `${optionalString(source, "target") ?? "local"}:${path}`,
        ttlMs: this.requestTtlMs(input.ttlSeconds),
      });
      return {
        operation: "publish",
        source: { target: optionalString(source, "target") ?? "local", path },
        artifactId: committed.record.artifactId,
        resourceUri: canonicalArtifactResourceUri(committed.record.artifactId),
        ...(this.downloadUrl(committed.record, committed.token)
          ? { downloadUrl: this.downloadUrl(committed.record, committed.token) }
          : {}),
        resourceName: committed.record.name,
        mimeType: committed.record.mimeType,
        size: committed.record.size,
        sha256: committed.record.sha256,
        expiresAt: new Date(committed.record.expiresAt).toISOString(),
        immutable: true,
      };
    } catch (error) {
      await this.abortReservation(reservation);
      throw error;
    } finally {
      if (directory) await rm(directory, { recursive: true, force: true });
    }
  }

  private async copy(
    input: UniversalArtifactInput,
    ownerFingerprint: string,
    callContext?: CapabilityCallContext,
  ): Promise<Record<string, unknown>> {
    const sourcePath = requiredString(input.source, "path", "artifact.copy source.path is required.");
    const destinationPath = requiredString(input.destination, "path", "artifact.copy destination.path is required.");
    const maximumBytes = this.requestMaximumBytes(input.maxBytes);
    const declaredSourceSize = optionalNumber(input.source, "size");
    const reservation = this.reserveCapacity(
      ownerFingerprint,
      maximumBytes,
      undefined,
      false,
      COPY_PROVISIONAL_BYTES,
    );
    let directory: string | undefined;
    try {
      const sourceBinding = await this.resolveCopyTargetBinding(input.source, sourcePath, callContext);
      const destinationBinding = await this.resolveCopyTargetBinding(input.destination, destinationPath, callContext);
      if (sourceBinding.transport === "local") {
        const sourceMetadata = await optionalLstat(sourceBinding.path);
        if (sourceMetadata?.isDirectory()) {
          return await this.copyDirectory(
            input,
            ownerFingerprint,
            sourceBinding,
            destinationBinding,
            reservation,
            maximumBytes,
            callContext,
          );
        }
      } else if (await this.sourceIsRemoteDirectory(sourceBinding, callContext)) {
        return await this.copyDirectory(
          input,
          ownerFingerprint,
          sourceBinding,
          destinationBinding,
          reservation,
          maximumBytes,
          callContext,
        );
      }
      this.reserveArtifactEntry(reservation);
      this.expandFileCopyReservation(
        reservation,
        maximumBytes,
        declaredSourceSize,
      );
      directory = await this.createStagingDirectory("copy");
      const stagedPath = join(directory, "payload");
      const exported = await this.filesystem.exportToLocalFile({
        target: optionalString(input.source, "target"),
        contextId: optionalString(input.source, "contextId"),
        path: sourcePath,
        localPath: stagedPath,
      }, callContext);
      this.assertExpectedContent(input.source, exported.size, exported.sha256, reservation.bytesReserved);
      const object = await this.commitContentObject(stagedPath, exported.size, exported.sha256, reservation);
      const published = await this.filesystem.importLocalFile({
        target: optionalString(input.destination, "target"),
        contextId: optionalString(input.destination, "contextId"),
        path: destinationPath,
        localPath: object.path,
        overwrite: input.overwrite === true,
        expectedSha256: optionalString(input.destination, "expectedSha256"),
      }, callContext);
      const committed = this.commitRecord(reservation, object, {
        name: optionalString(input.destination, "name") ?? basename(destinationPath) ?? "artifact.bin",
        mimeType: optionalString(input.source, "mimeType") ?? "application/octet-stream",
        source: `${optionalString(input.source, "target") ?? "local"}:${sourcePath}`,
        destination: `${optionalString(input.destination, "target") ?? "local"}:${destinationPath}`,
        ttlMs: this.requestTtlMs(input.ttlSeconds),
      });
      return {
        operation: "copy",
        source: {
          target: optionalString(input.source, "target") ?? "local",
          targetId: sourceBinding.targetId,
          targetGeneration: sourceBinding.targetGeneration,
          path: sourcePath,
        },
        destination: {
          target: optionalString(input.destination, "target") ?? "local",
          targetId: destinationBinding.targetId,
          targetGeneration: destinationBinding.targetGeneration,
          path: destinationPath,
        },
        artifactId: committed.record.artifactId,
        resourceUri: canonicalArtifactResourceUri(committed.record.artifactId),
        size: object.size,
        sha256: object.sha256,
        immutableCas: true,
        published,
      };
    } catch (error) {
      await this.abortReservation(reservation);
      throw error;
    } finally {
      if (directory) await rm(directory, { recursive: true, force: true });
    }
  }

  private async copyDirectory(
    input: UniversalArtifactInput,
    ownerFingerprint: string,
    source: ArtifactCopyTargetBinding,
    destination: ArtifactCopyTargetBinding,
    reservation: CapacityReservation,
    maximumBytes: number,
    callContext?: CapabilityCallContext,
  ): Promise<Record<string, unknown>> {
    if (
      source.targetId === destination.targetId
      && (source.path === destination.path || isCopyTargetPathInside(source, destination.path))
    ) {
      throw new UniversalBrokerError(
        "PRECONDITION_FAILED",
        "Directory artifact.copy destination cannot be inside the source tree.",
        { evidence: { sourcePath: source.path, destinationPath: destination.path } },
      );
    }
    await Promise.all([
      this.assertCopyTargetCurrent(source),
      this.assertCopyTargetCurrent(destination),
    ]);
    const checkpointId = digestJson({
      version: 1,
      ownerFingerprint,
      source,
      destination,
    });
    const checkpointPath = directoryCopyCheckpointPath(this.options.stagingRoot, checkpointId);
    const checkpoint = await this.loadDirectoryCopyCheckpoint(checkpointPath);
    if (!checkpoint) this.reserveArtifactEntry(reservation);
    const snapshot = source.transport === "local"
      ? await snapshotLocalDirectory(source.path)
      : await this.snapshotRemoteDirectory(source, callContext);
    if (snapshot.totalBytes > maximumBytes) {
      throw new UniversalBrokerError(
        "RESOURCE_QUOTA_EXCEEDED",
        "Directory artifact.copy source exceeds maxBytes.",
        { evidence: { totalBytes: snapshot.totalBytes, maximumBytes } },
      );
    }
    const declaredSize = optionalNumber(input.source, "size");
    if (declaredSize !== undefined && declaredSize !== snapshot.totalBytes) {
      throw new UniversalBrokerError(
        "PRECONDITION_FAILED",
        "Directory artifact.copy source size precondition failed.",
        { evidence: { declaredSize, actualSize: snapshot.totalBytes } },
      );
    }

    const manifestBase = {
      version: 1,
      kind: "devspace.artifact.copy.directory-manifest",
      ownerFingerprint,
      source,
      destination,
      sourceIdentity: snapshot.sourceIdentity,
      directories: snapshot.directories,
      entries: snapshot.entries,
      totalEntries: snapshot.entries.length,
      totalBytes: snapshot.totalBytes,
    };
    const manifestDigest = digestJson(manifestBase);
    const copyId = digestJson({
      version: 1,
      checkpointId,
      ownerFingerprint,
      source,
      destination,
      manifestDigest,
    });
    const artifactId = deterministicDirectoryCopyArtifactId(copyId);
    const resourceUri = canonicalArtifactResourceUri(artifactId);
    const manifest = {
      ...manifestBase,
      copyId,
      manifestDigest,
      completedEntries: snapshot.entries.length,
    };
    const manifestBytes = Buffer.from(`${JSON.stringify(manifest, null, 2)}\n`, "utf8");
    const manifestSha256 = createHash("sha256").update(manifestBytes).digest("hex");
    const resumed = Boolean(checkpoint && checkpoint.status === "RUNNING");
    if (checkpoint) {
      assertCompatibleDirectoryCheckpoint(checkpoint, {
        copyId,
        ownerFingerprint,
        manifestDigest,
        source,
        destination,
        artifactId,
        resourceUri,
      });
      if (checkpoint.status === "COMPLETED") {
        const existing = await this.verifyCompletedDirectoryCopy({
          artifactId,
          ownerFingerprint,
          source,
          destination,
          directories: snapshot.directories,
          entries: snapshot.entries,
          manifestBytes,
          manifestSha256,
          callContext,
        });
        await this.abortReservation(reservation);
        return this.directoryCopyResult({
          source,
          destination,
          copyId,
          manifestDigest,
          artifactId: existing.artifactId,
          resourceUri: existing.resourceUri,
          size: existing.size,
          sha256: existing.sha256,
          totalEntries: snapshot.entries.length,
          completedEntries: snapshot.entries.length,
          totalBytes: snapshot.totalBytes,
          resumed: true,
        });
      }
    }

    if (!reservation.entryReserved) {
      const existing = this.catalog.getArtifact(artifactId);
      if (existing) {
        await this.verifyDirectoryManifestArtifact({
          artifactId,
          ownerFingerprint,
          source,
          destination,
          manifestBytes,
          manifestSha256,
        });
      } else {
        this.reserveArtifactEntry(reservation);
      }
    }

    const reusableManifest = await this.reusableContentObject(
      manifestSha256,
      manifestBytes.byteLength,
      "STATE_CORRUPTED",
    );
    this.resizeCapacityReservation(
      reservation,
      reusableManifest ? 0 : manifestBytes.byteLength,
      this.maximumArtifactBytes,
    );
    if (destination.transport === "local") {
      await runBoundLocalDirectoryHelper({
        mode: "preflight",
        destinationRoot: destination.path,
        directories: snapshot.directories,
        entries: snapshot.entries,
        overwrite: input.overwrite === true,
      });
    }

    const completed = new Set(checkpoint?.completedEntries ?? []);
    const baseCheckpoint: Omit<DirectoryCopyCheckpoint, "completedEntries" | "status" | "updatedAt"> = {
      version: 1,
      copyId,
      ownerFingerprint,
      manifestDigest,
      source,
      destination,
      createdAt: checkpoint?.createdAt ?? this.now(),
      artifactId,
      resourceUri,
    };
    await this.persistDirectoryCopyCheckpoint(checkpointPath, {
      ...baseCheckpoint,
      completedEntries: [...completed].sort(compareText),
      status: "RUNNING",
      updatedAt: this.now(),
    });

    if (destination.transport === "local") {
      await runBoundLocalDirectoryHelper({
        mode: "prepare",
        destinationRoot: destination.path,
        directories: snapshot.directories,
      });
    } else {
      await this.ensureCopyTargetDirectory(destination, destination.path, callContext);
      for (const directoryPath of snapshot.directories) {
        await this.ensureCopyTargetDirectory(
          destination,
          copyTargetPath(destination, directoryPath),
          callContext,
        );
      }
    }

    for (const entry of snapshot.entries) {
      if (await this.copyTargetFileMatches(destination, entry, callContext)) {
        completed.add(entry.relativePath);
      } else {
        if (completed.has(entry.relativePath)) completed.delete(entry.relativePath);
        await this.copyDirectoryEntryBetweenTargets(
          source,
          destination,
          entry,
          input.overwrite === true,
          callContext,
        );
        completed.add(entry.relativePath);
      }
      await this.persistDirectoryCopyCheckpoint(checkpointPath, {
        ...baseCheckpoint,
        completedEntries: [...completed].sort(compareText),
        status: "RUNNING",
        updatedAt: this.now(),
      });
      await this.options.copyHooks?.afterEntryCheckpointed?.({
        copyId,
        ownerFingerprint,
        manifestDigest,
        checkpointPath,
        relativePath: entry.relativePath,
        completedEntries: completed.size,
        totalEntries: snapshot.entries.length,
      });
    }

    for (const entry of snapshot.entries) {
      if (!(await this.copyTargetFileMatches(destination, entry, callContext))) {
        throw new UniversalBrokerError(
          "TRANSPORT_INTERRUPTED",
          "Directory artifact.copy post-readback failed.",
          { evidence: { copyId, relativePath: entry.relativePath } },
        );
      }
    }

    const stagingDirectory = await this.createStagingDirectory("copy-manifest");
    try {
      const manifestPath = join(stagingDirectory, "manifest.json");
      await writeFile(manifestPath, manifestBytes, { flag: "wx", mode: 0o600 });
      await syncFile(manifestPath);
      const object = await this.commitContentObject(
        manifestPath,
        manifestBytes.byteLength,
        manifestSha256,
        reservation,
      );
      const committed = this.commitRecord(reservation, object, {
        artifactId,
        name: `${sanitizeFilename(basename(destination.path) || "directory")}.manifest.json`,
        mimeType: "application/vnd.devspace.artifact-copy-manifest+json",
        source: `${source.targetId}:${source.path}`,
        destination: `${destination.targetId}:${destination.path}`,
        ttlMs: this.requestTtlMs(input.ttlSeconds),
      });
      await this.persistDirectoryCopyCheckpoint(checkpointPath, {
        ...baseCheckpoint,
        completedEntries: [...completed].sort(compareText),
        status: "COMPLETED",
        updatedAt: this.now(),
        artifactId: committed.record.artifactId,
        resourceUri,
      });
      const verified = await this.verifyCompletedDirectoryCopy({
        artifactId,
        ownerFingerprint,
        source,
        destination,
        directories: snapshot.directories,
        entries: snapshot.entries,
        manifestBytes,
        manifestSha256,
        callContext,
      });
      return this.directoryCopyResult({
        source,
        destination,
        copyId,
        manifestDigest,
        artifactId: verified.artifactId,
        resourceUri: verified.resourceUri,
        size: verified.size,
        sha256: verified.sha256,
        totalEntries: snapshot.entries.length,
        completedEntries: completed.size,
        totalBytes: snapshot.totalBytes,
        resumed,
      });
    } finally {
      await rm(stagingDirectory, { recursive: true, force: true });
    }
  }

  private async verifyCompletedDirectoryCopy(input: {
    artifactId: string;
    ownerFingerprint: string;
    source: ArtifactCopyTargetBinding;
    destination: ArtifactCopyTargetBinding;
    directories: readonly string[];
    entries: readonly DirectoryManifestEntry[];
    manifestBytes: Buffer;
    manifestSha256: string;
    callContext?: CapabilityCallContext;
  }): Promise<ArtifactRecord> {
    const record = await this.verifyDirectoryManifestArtifact(input);
    if (!(await this.copyTargetDirectoriesMatch(input.destination, input.directories, input.callContext))) {
      throw new UniversalBrokerError(
        "TRANSPORT_INTERRUPTED",
        "Completed directory artifact.copy destination directories failed post-readback.",
        { evidence: { artifactId: input.artifactId } },
      );
    }
    for (const entry of input.entries) {
      if (!(await this.copyTargetFileMatches(input.destination, entry, input.callContext))) {
        throw new UniversalBrokerError(
          "TRANSPORT_INTERRUPTED",
          "Completed directory artifact.copy destination failed post-readback.",
          { evidence: { artifactId: input.artifactId, relativePath: entry.relativePath } },
        );
      }
    }
    return record;
  }

  private async verifyDirectoryManifestArtifact(input: {
    artifactId: string;
    ownerFingerprint: string;
    source: ArtifactCopyTargetBinding;
    destination: ArtifactCopyTargetBinding;
    manifestBytes: Buffer;
    manifestSha256: string;
  }): Promise<ArtifactRecord> {
    const record = this.catalog.getAvailableArtifact(input.artifactId, this.now());
    const expectedSource = `${input.source.targetId}:${input.source.path}`;
    const expectedDestination = `${input.destination.targetId}:${input.destination.path}`;
    if (
      !record
      || record.ownerFingerprint !== input.ownerFingerprint
      || record.sha256 !== input.manifestSha256
      || record.objectSha256 !== input.manifestSha256
      || record.size !== input.manifestBytes.byteLength
      || record.source !== expectedSource
      || record.destination !== expectedDestination
      || record.resourceUri !== canonicalArtifactResourceUri(input.artifactId)
      || record.cleanupStatus !== "NONE"
      || record.reconciliationStatus !== "VERIFIED"
    ) {
      throw new UniversalBrokerError(
        "STATE_CORRUPTED",
        "Completed directory artifact.copy catalog record failed readback.",
        { evidence: { artifactId: input.artifactId } },
      );
    }
    const object = this.catalog.getObject(input.manifestSha256);
    if (
      !object
      || object.state !== "AVAILABLE"
      || object.references < 1
      || object.path !== record.objectPath
      || object.size !== input.manifestBytes.byteLength
    ) {
      throw new UniversalBrokerError(
        "STATE_CORRUPTED",
        "Completed directory artifact.copy CAS metadata failed readback.",
        { evidence: { artifactId: input.artifactId, sha256: input.manifestSha256 } },
      );
    }
    try {
      await verifyFile(object.path, input.manifestBytes.byteLength, input.manifestSha256);
    } catch (error) {
      throw new UniversalBrokerError(
        "STATE_CORRUPTED",
        "Completed directory artifact.copy manifest CAS failed readback.",
        {
          evidence: {
            artifactId: input.artifactId,
            sha256: input.manifestSha256,
            filesystemError: errorMessage(error),
          },
        },
      );
    }
    return record;
  }

  private async resolveCopyTargetBinding(
    descriptor: Record<string, unknown> | undefined,
    path: string,
    callContext?: CapabilityCallContext,
  ): Promise<ArtifactCopyTargetBinding> {
    const runtime = filesystemRuntimeAccess(this.filesystem);
    const contextId = optionalString(descriptor, "contextId");
    const context = contextId
      ? await runtime.contexts.get(contextId, callContext)
      : undefined;
    const targetSelector = optionalString(descriptor, "target") ?? context?.targetId ?? "local";
    const { target } = await runtime.targets.resolveWithGeneration(targetSelector);
    const expectedGeneration = optionalString(descriptor, "targetGeneration");
    if (expectedGeneration && expectedGeneration !== target.generation) {
      throw new UniversalBrokerError(
        "PRECONDITION_FAILED",
        "Artifact copy target generation precondition failed.",
        { evidence: { targetId: target.id, expectedGeneration, actualGeneration: target.generation } },
      );
    }
    if (context && context.targetId !== target.id) {
      throw new UniversalBrokerError(
        "PRECONDITION_FAILED",
        `Context ${context.contextId} belongs to target ${context.targetId}, not ${target.id}.`,
        { evidence: { contextId: context.contextId, contextTarget: context.targetId, targetId: target.id } },
      );
    }
    return {
      targetId: target.id,
      targetGeneration: target.generation,
      endpointFingerprint: target.endpointFingerprint,
      transport: target.transport,
      path: target.transport === "local"
        ? resolveArtifactLocalPath(path, context?.root ?? target.defaultCwd ?? homedir())
        : path,
      ...(contextId ? { contextId } : {}),
    };
  }

  private async sourceIsRemoteDirectory(
    source: ArtifactCopyTargetBinding,
    callContext?: CapabilityCallContext,
  ): Promise<boolean> {
    const result = await this.filesystem.execute({
      operation: "stat",
      target: source.targetId,
      contextId: source.contextId,
      path: source.path,
    }, callContext);
    return result.type === "directory";
  }

  private async snapshotRemoteDirectory(
    source: ArtifactCopyTargetBinding,
    callContext?: CapabilityCallContext,
  ): Promise<DirectoryManifestSnapshot> {
    const rootMetadata = await this.copyTargetStat(source, source.path, callContext);
    if (rootMetadata.type !== "directory") throw pathTypeError(source.path, "directory");
    const directories = new Set<string>();
    const entries: DirectoryManifestEntry[] = [];
    let totalBytes = 0;

    const visit = async (directory: string, relativeDirectory: string): Promise<void> => {
      await this.assertCopyTargetCurrent(source);
      const before = await this.copyTargetStat(source, directory, callContext);
      if (before.type !== "directory") throw pathTypeError(directory, "directory");
      const children = await this.listCopyTargetDirectory(source, directory, callContext);
      for (const child of children) {
        const relativePath = manifestChildRelativePath(relativeDirectory, child.name);
        const childPath = remoteChildPath(directory, child.name);
        if (child.type === "directory") {
          directories.add(relativePath);
          await visit(childPath, relativePath);
          continue;
        }
        if (child.type !== "file") {
          throw new UniversalBrokerError(
            "CAPABILITY_UNAVAILABLE",
            "Directory artifact.copy manifest mode supports regular files and directories only.",
            { evidence: { path: childPath, entryType: child.type, targetId: source.targetId } },
          );
        }
        const beforeFile = await this.copyTargetStat(source, childPath, callContext);
        if (beforeFile.type !== "file") throw pathTypeError(childPath, "file");
        const hash = await this.hashCopyTargetFile(source, childPath, callContext);
        const afterFile = await this.copyTargetStat(source, childPath, callContext);
        if (digestJson(beforeFile.identity) !== digestJson(afterFile.identity)) {
          throw new UniversalBrokerError(
            "PRECONDITION_FAILED",
            "Directory artifact.copy source changed while its immutable manifest was captured.",
            { evidence: { path: childPath, targetId: source.targetId } },
          );
        }
        if (hash.size !== afterFile.size) {
          throw new UniversalBrokerError(
            "PRECONDITION_FAILED",
            "Directory artifact.copy source hash size changed while its immutable manifest was captured.",
            { evidence: { path: childPath, targetId: source.targetId } },
          );
        }
        totalBytes += hash.size;
        entries.push({ relativePath, size: hash.size, sha256: hash.sha256 });
      }
      const after = await this.copyTargetStat(source, directory, callContext);
      if (digestJson(before.identity) !== digestJson(after.identity)) {
        throw new UniversalBrokerError(
          "PRECONDITION_FAILED",
          "Directory artifact.copy source changed while its immutable manifest was captured.",
          { evidence: { path: directory, targetId: source.targetId } },
        );
      }
    };

    await visit(source.path, "");
    entries.sort((left, right) => compareText(left.relativePath, right.relativePath));
    return {
      directories: [...directories].sort(compareText),
      entries,
      totalBytes,
      sourceIdentity: rootMetadata.identity,
    };
  }

  private async listCopyTargetDirectory(
    target: ArtifactCopyTargetBinding,
    path: string,
    callContext?: CapabilityCallContext,
  ): Promise<DirectoryManifestListEntry[]> {
    const entries: DirectoryManifestListEntry[] = [];
    let cursor: string | undefined;
    do {
      const page = await this.filesystem.execute({
        operation: "list",
        target: target.targetId,
        contextId: target.contextId,
        path,
        limit: DIRECTORY_COPY_LIST_PAGE_LIMIT,
        ...(cursor ? { cursor } : {}),
      }, callContext);
      entries.push(...directoryManifestListEntries(page.entries));
      cursor = optionalString(page, "nextCursor");
    } while (cursor);
    entries.sort((left, right) => compareText(left.name, right.name));
    return entries;
  }

  private async ensureCopyTargetDirectory(
    target: ArtifactCopyTargetBinding,
    path: string,
    callContext?: CapabilityCallContext,
  ): Promise<void> {
    await this.assertCopyTargetCurrent(target);
    if (target.transport === "local") {
      const relativePath = localDirectoryCopyRelativePath(target.path, path);
      await runBoundLocalDirectoryHelper({
        mode: "prepare",
        destinationRoot: target.path,
        directories: relativePath ? [relativePath] : [],
      });
      return;
    }
    await this.filesystem.execute({
      operation: "mkdir",
      target: target.targetId,
      contextId: target.contextId,
      path,
      recursive: true,
    }, callContext);
  }

  private async copyTargetFileMatches(
    target: ArtifactCopyTargetBinding,
    entry: DirectoryManifestEntry,
    callContext?: CapabilityCallContext,
  ): Promise<boolean> {
    await this.assertCopyTargetCurrent(target);
    const path = copyTargetPath(target, entry.relativePath);
    if (target.transport === "local") {
      const result = await runBoundLocalDirectoryHelper({
        mode: "verify",
        destinationRoot: target.path,
        relativePath: entry.relativePath,
        expectedSize: entry.size,
        expectedSha256: entry.sha256,
      });
      return result.matches === true;
    }
    try {
      const hash = await this.hashCopyTargetFile(target, path, callContext);
      return hash.size === entry.size && hash.sha256 === entry.sha256;
    } catch (error) {
      if (error instanceof UniversalBrokerError && ["PATH_NOT_FOUND", "PRECONDITION_FAILED"].includes(error.code)) {
        return false;
      }
      throw error;
    }
  }

  private async copyTargetDirectoriesMatch(
    target: ArtifactCopyTargetBinding,
    directories: readonly string[],
    callContext?: CapabilityCallContext,
  ): Promise<boolean> {
    await this.assertCopyTargetCurrent(target);
    if (target.transport === "local") {
      const result = await runBoundLocalDirectoryHelper({
        mode: "verify-directories",
        destinationRoot: target.path,
        directories,
      });
      return result.matches === true;
    }
    try {
      for (const path of [target.path, ...directories.map((entry) => copyTargetPath(target, entry))]) {
        if ((await this.copyTargetStat(target, path, callContext)).type !== "directory") return false;
      }
      return true;
    } catch (error) {
      if (error instanceof UniversalBrokerError && ["PATH_NOT_FOUND", "PRECONDITION_FAILED"].includes(error.code)) {
        return false;
      }
      throw error;
    }
  }

  private async copyDirectoryEntryBetweenTargets(
    source: ArtifactCopyTargetBinding,
    destination: ArtifactCopyTargetBinding,
    entry: DirectoryManifestEntry,
    overwrite: boolean,
    callContext?: CapabilityCallContext,
  ): Promise<void> {
    await Promise.all([
      this.assertCopyTargetCurrent(source),
      this.assertCopyTargetCurrent(destination),
    ]);
    if (source.transport === "local" && destination.transport === "local") {
      await runBoundLocalDirectoryHelper({
        mode: "publish",
        sourcePath: copyTargetPath(source, entry.relativePath),
        destinationRoot: destination.path,
        relativePath: entry.relativePath,
        expectedSize: entry.size,
        expectedSha256: entry.sha256,
        overwrite,
      });
      return;
    }

    const stagingDirectory = await this.createStagingDirectory("copy-entry");
    const stagedPath = join(stagingDirectory, "payload");
    try {
      const exported = await this.filesystem.exportToLocalFile({
        target: copyTargetSelector(source),
        contextId: source.contextId,
        path: copyTargetPath(source, entry.relativePath),
        localPath: stagedPath,
      }, callContext);
      if (exported.size !== entry.size || exported.sha256 !== entry.sha256) {
        throw new UniversalBrokerError(
          "PRECONDITION_FAILED",
          "Directory artifact.copy source entry no longer matches its immutable manifest.",
          { evidence: { relativePath: entry.relativePath, targetId: source.targetId } },
        );
      }
      if (destination.transport === "local") {
        await runBoundLocalDirectoryHelper({
          mode: "publish",
          sourcePath: stagedPath,
          destinationRoot: destination.path,
          relativePath: entry.relativePath,
          expectedSize: entry.size,
          expectedSha256: entry.sha256,
          overwrite,
        });
      } else {
        await this.filesystem.importLocalFile({
          target: copyTargetSelector(destination),
          contextId: destination.contextId,
          path: copyTargetPath(destination, entry.relativePath),
          localPath: stagedPath,
          overwrite,
        }, callContext);
      }
      if (!(await this.copyTargetFileMatches(destination, entry, callContext))) {
        throw new UniversalBrokerError(
          "TRANSPORT_INTERRUPTED",
          "Directory artifact.copy entry post-readback failed.",
          { evidence: { relativePath: entry.relativePath, targetId: destination.targetId } },
        );
      }
    } finally {
      await rm(stagingDirectory, { recursive: true, force: true });
    }
  }

  private async hashCopyTargetFile(
    target: ArtifactCopyTargetBinding,
    path: string,
    callContext?: CapabilityCallContext,
  ): Promise<{ size: number; sha256: string }> {
    const result = await this.filesystem.execute({
      operation: "hash",
      target: copyTargetSelector(target),
      contextId: target.contextId,
      path,
    }, callContext);
    return {
      size: requiredNumberField(result, "size"),
      sha256: requiredSha256Field(result, "sha256"),
    };
  }

  private async copyTargetStat(
    target: ArtifactCopyTargetBinding,
    path: string,
    callContext?: CapabilityCallContext,
  ): Promise<{ type: string; size: number; identity: Record<string, unknown> }> {
    const result = await this.filesystem.execute({
      operation: "stat",
      target: copyTargetSelector(target),
      contextId: target.contextId,
      path,
    }, callContext);
    const type = requiredString(result, "type", "Filesystem stat result is missing type.");
    const size = requiredNumberField(result, "size");
    return {
      type,
      size,
      identity: copyTargetStatIdentity(result),
    };
  }

  private async assertCopyTargetCurrent(binding: ArtifactCopyTargetBinding): Promise<void> {
    const runtime = filesystemRuntimeAccess(this.filesystem);
    const { target } = await runtime.targets.resolveWithGeneration(binding.targetId);
    if (
      target.id !== binding.targetId
      || target.generation !== binding.targetGeneration
      || target.endpointFingerprint !== binding.endpointFingerprint
      || target.transport !== binding.transport
    ) {
      throw new UniversalBrokerError(
        "PRECONDITION_FAILED",
        "Artifact copy target binding is stale.",
        {
          evidence: {
            targetId: binding.targetId,
            expectedGeneration: binding.targetGeneration,
            actualGeneration: target.generation,
          },
        },
      );
    }
  }

  private async loadDirectoryCopyCheckpoint(path: string): Promise<DirectoryCopyCheckpoint | undefined> {
    try {
      const value = JSON.parse(await readFile(path, "utf8")) as unknown;
      if (!isDirectoryCopyCheckpoint(value)) {
        throw new UniversalBrokerError(
          "STATE_CORRUPTED",
          "Directory artifact.copy checkpoint is invalid.",
          { evidence: { checkpointPath: path } },
        );
      }
      return value;
    } catch (error) {
      if (isNodeError(error, "ENOENT")) return undefined;
      throw error;
    }
  }

  private async persistDirectoryCopyCheckpoint(
    path: string,
    checkpoint: DirectoryCopyCheckpoint,
  ): Promise<void> {
    await atomicWriteJson(path, checkpoint);
  }

  private directoryCopyResult(input: {
    source: ArtifactCopyTargetBinding;
    destination: ArtifactCopyTargetBinding;
    copyId: string;
    manifestDigest: string;
    artifactId: string;
    resourceUri: string;
    size: number;
    sha256: string;
    totalEntries: number;
    completedEntries: number;
    totalBytes: number;
    resumed: boolean;
  }): Record<string, unknown> {
    return {
      operation: "copy",
      manifestMode: true,
      immutableManifest: true,
      copyId: input.copyId,
      manifestDigest: input.manifestDigest,
      source: input.source,
      destination: input.destination,
      artifactId: input.artifactId,
      resourceUri: input.resourceUri,
      size: input.size,
      sha256: input.sha256,
      totalEntries: input.totalEntries,
      completedEntries: input.completedEntries,
      totalBytes: input.totalBytes,
      resumed: input.resumed,
      postReadback: true,
    };
  }

  /** Synchronous capacity fencing happens before any adapter open, fetch, or source file open. */
  private reserveCapacity(
    ownerFingerprint: string,
    requestedMaximumBytes: number,
    declaredSize: number | undefined,
    reserveEntry: boolean,
    provisionalMaximumBytes?: number,
  ): CapacityReservation {
    try {
      const reservation = this.catalog.reserveCapacity({
        ownerFingerprint,
        requestedMaximumBytes,
        declaredSize,
        reserveEntry,
        provisionalMaximumBytes,
      });
      this.recordArtifactEvent("reserved", "pass");
      return reservation;
    } catch (error) {
      const mapped = mapCatalogError(error);
      this.recordArtifactEvent("reserved", "fail");
      if (mapped instanceof UniversalBrokerError && mapped.code === "RESOURCE_QUOTA_EXCEEDED") {
        this.recordQuotaRejection();
      }
      throw mapped;
    }
  }

  private resizeCapacityReservation(
    reservation: CapacityReservation,
    requiredBytes: number,
    maximumObjectBytes: number,
  ): void {
    try {
      if (requiredBytes > maximumObjectBytes) {
        throw new UniversalBrokerError(
          "RESOURCE_QUOTA_EXCEEDED",
          "Directory artifact.copy manifest exceeds the per-artifact byte limit.",
          { evidence: { requiredBytes, maximumArtifactBytes: maximumObjectBytes } },
        );
      }
      const resized = this.catalog.resizeCapacityReservation(
        reservation.reservationId,
        requiredBytes,
      );
      reservation.bytesReserved = resized.bytesReserved;
    } catch (error) {
      const mapped = error instanceof ArtifactCatalogError ? mapCatalogError(error) : error;
      this.recordArtifactEvent("reserved", "fail");
      if (mapped instanceof UniversalBrokerError && mapped.code === "RESOURCE_QUOTA_EXCEEDED") {
        this.recordQuotaRejection();
      }
      throw mapped;
    }
  }

  private reserveArtifactEntry(reservation: CapacityReservation): void {
    try {
      const updated = this.catalog.reserveArtifactEntry(reservation.reservationId);
      reservation.entryReserved = updated.entryReserved;
    } catch (error) {
      const mapped = error instanceof ArtifactCatalogError ? mapCatalogError(error) : error;
      this.recordArtifactEvent("reserved", "fail");
      if (mapped instanceof UniversalBrokerError && mapped.code === "RESOURCE_QUOTA_EXCEEDED") {
        this.recordQuotaRejection();
      }
      throw mapped;
    }
  }

  private expandFileCopyReservation(
    reservation: CapacityReservation,
    maximumBytes: number,
    declaredSize: number | undefined,
  ): void {
    if (declaredSize !== undefined) {
      this.resizeCapacityReservation(reservation, declaredSize, maximumBytes);
      return;
    }
    try {
      const resized = this.catalog.maximizeCapacityReservation(
        reservation.reservationId,
        maximumBytes,
      );
      reservation.bytesReserved = resized.bytesReserved;
    } catch (error) {
      const mapped = error instanceof ArtifactCatalogError ? mapCatalogError(error) : error;
      this.recordArtifactEvent("reserved", "fail");
      if (mapped instanceof UniversalBrokerError && mapped.code === "RESOURCE_QUOTA_EXCEEDED") {
        this.recordQuotaRejection();
      }
      throw mapped;
    }
  }

  private recordArtifactEvent(event: string, result: "pass" | "fail"): void {
    try {
      this.options.metrics?.recordArtifactEvent(event, result);
    } catch {
      // Observability must never replace the artifact operation result.
    }
  }

  private recordQuotaRejection(): void {
    try {
      this.options.metrics?.recordQuotaRejection("artifact");
    } catch {
      // Observability must never replace the quota result.
    }
  }

  private async commitContentObject(
    stagedPath: string,
    size: number,
    sha256: string,
    reservation: CapacityReservation,
  ): Promise<ContentObject> {
    this.assertReservation(reservation);
    const reusable = await this.reusableContentObject(sha256, size);
    if (size > reservation.bytesReserved && !reusable) {
      throw new UniversalBrokerError(
        "RESOURCE_QUOTA_EXCEEDED",
        "Artifact bytes exceeded the synchronously reserved capacity.",
        { evidence: { size, reservedBytes: reservation.bytesReserved } },
      );
    }
    await verifyFile(stagedPath, size, sha256);
    const objectRoot = this.options.objectRoot ?? join(this.options.stagingRoot, "objects");
    const objectDirectory = join(objectRoot, "sha256", sha256.slice(0, 2));
    const objectPath = join(objectDirectory, sha256);
    await mkdir(objectDirectory, { recursive: true, mode: 0o700 });
    const object = reusable ?? this.catalog.getObject(sha256);
    if (reusable) {
      // The immutable CAS bytes were verified before incremental capacity was calculated.
    } else {
      if (object && object.state !== "DELETED") {
        throw new UniversalBrokerError("STATE_CORRUPTED", "Artifact CAS object is not available for reuse.");
      }
      const existing = await optionalLstat(objectPath);
      if (existing) {
        await verifyFile(objectPath, size, sha256);
      } else {
        await this.publishCasObject(stagedPath, objectPath, size, sha256);
      }
    }
    try {
      const attached = this.catalog.attachObject(reservation.reservationId, {
        path: objectPath,
        sha256,
        size,
      });
      reservation.bytesCommitted = true;
      reservation.objectSha256 = sha256;
      return attached;
    } catch (error) {
      throw mapCatalogError(error);
    }
  }

  private async reusableContentObject(
    sha256: string,
    size: number,
    verificationFailureCode: "PRECONDITION_FAILED" | "STATE_CORRUPTED" = "PRECONDITION_FAILED",
  ): Promise<ContentObject | undefined> {
    const object = this.catalog.getObject(sha256);
    if (!object || object.state === "DELETED") return undefined;
    if (object.state !== "AVAILABLE") {
      throw new UniversalBrokerError(
        "STATE_CORRUPTED",
        "Artifact CAS object is not available for reuse.",
        { evidence: { sha256, state: object.state } },
      );
    }
    const objectRoot = this.options.objectRoot ?? join(this.options.stagingRoot, "objects");
    const expectedPath = resolve(objectRoot, "sha256", sha256.slice(0, 2), sha256);
    if (resolve(object.path) !== expectedPath || object.size !== size) {
      throw new UniversalBrokerError(
        "STATE_CORRUPTED",
        "Artifact CAS metadata conflicts with the expected immutable object.",
        { evidence: { sha256, expectedPath, objectPath: object.path, expectedSize: size, objectSize: object.size } },
      );
    }
    try {
      await verifyFile(object.path, size, sha256);
    } catch (error) {
      if (verificationFailureCode === "PRECONDITION_FAILED" && error instanceof UniversalBrokerError) {
        throw error;
      }
      throw new UniversalBrokerError(
        verificationFailureCode,
        "Artifact CAS object failed immutable readback.",
        { evidence: { sha256, filesystemError: errorMessage(error) } },
      );
    }
    return object;
  }

  private async publishCasObject(
    stagedPath: string,
    objectPath: string,
    size: number,
    sha256: string,
  ): Promise<void> {
    try {
      await link(stagedPath, objectPath);
    } catch (error) {
      if (isNodeError(error, "EEXIST")) {
        await verifyFile(objectPath, size, sha256);
        return;
      }
      if (!isNodeError(error, "EXDEV")) throw error;
      const temporary = join(dirname(objectPath), `.cas-${randomUUID()}.tmp`);
      try {
        await copyFile(stagedPath, temporary, fsConstants.COPYFILE_EXCL);
        await syncFile(temporary);
        await verifyFile(temporary, size, sha256);
        try {
          await link(temporary, objectPath);
        } catch (linkError) {
          if (!isNodeError(linkError, "EEXIST")) throw linkError;
        }
      } finally {
        await rm(temporary, { force: true }).catch(() => undefined);
      }
    }
    await chmod(objectPath, 0o400);
    await syncFile(objectPath);
    await syncDirectory(dirname(objectPath));
    await verifyFile(objectPath, size, sha256);
  }

  private commitRecord(
    reservation: CapacityReservation,
    object: ContentObject,
    input: {
      artifactId?: string;
      name: string;
      mimeType: string;
      source: string;
      destination?: string;
      ttlMs: number;
    },
  ): { record: ArtifactRecord; token: string } {
    this.assertReservation(reservation);
    if ((!reservation.entryReserved && !input.artifactId) || reservation.objectSha256 !== object.sha256) {
      throw new UniversalBrokerError("STATE_CORRUPTED", "Artifact reservation cannot commit this object.");
    }
    const now = this.now();
    const token = randomBytes(32).toString("base64url");
    try {
      const record = this.catalog.commitArtifact(reservation.reservationId, object.sha256, {
        artifactId: input.artifactId ?? randomUUID(),
        ownerFingerprint: reservation.ownerFingerprint,
        tokenHash: artifactCapabilityTokenHash(token),
        name: sanitizeFilename(input.name),
        mimeType: input.mimeType,
        source: input.source,
        destination: input.destination,
        createdAt: now,
        expiresAt: now + input.ttlMs,
      });
      reservation.state = "COMMITTED";
      reservation.entryReserved = false;
      return { record, token };
    } catch (error) {
      throw mapCatalogError(error);
    }
  }

  private async abortReservation(reservation: CapacityReservation): Promise<void> {
    try {
      await this.performCleanupPlans(this.catalog.abortReservation(reservation.reservationId));
    } catch (error) {
      throw mapCatalogError(error);
    }
  }

  private async stageIncoming(
    source: Record<string, unknown>,
    reservedBytes: number,
  ): Promise<{
    directory: string;
    path: string;
    name: string;
    mimeType: string;
    size: number;
    sha256: string;
    sourceKind: string;
  }> {
    const directory = await this.createStagingDirectory("receive");
    const path = join(directory, "payload");
    try {
      const nativeValue = source.file ?? source;
      let name: string;
      let mimeType: string;
      let declaredSize: number | undefined;
      let stream: Readable;
      let sourceKind: string;
      try {
        const opened = await this.incoming.open(nativeValue);
        name = opened.name;
        mimeType = opened.mimeType ?? "application/octet-stream";
        declaredSize = opened.size;
        stream = opened.stream;
        sourceKind = `native:${opened.adapterId}`;
      } catch (error) {
        if (!isUnsupportedIncomingArtifact(error)) throw mapArtifactError(error);
        const url = sourceUrl(source);
        const response = await fetchWithValidatedRedirects(this.fetcher, url, DOWNLOAD_TIMEOUT_MS);
        if (!response.ok || !response.body) {
          throw new UniversalBrokerError(
            "TRANSPORT_UNAVAILABLE",
            `Artifact download failed with HTTP ${response.status}.`,
            { evidence: { status: response.status, origin: url.origin } },
          );
        }
        declaredSize = contentLength(response);
        name = optionalString(source, "name")
          ?? (basename(new URL(response.url || url.href).pathname) || "artifact.bin");
        mimeType = optionalString(source, "mimeType")
          ?? response.headers.get("content-type")?.split(";", 1)[0]?.trim()
          ?? "application/octet-stream";
        stream = Readable.fromWeb(response.body as never);
        sourceKind = "url";
      }
      if (declaredSize !== undefined && declaredSize > reservedBytes) {
        stream.destroy();
        throw new UniversalBrokerError("RESOURCE_QUOTA_EXCEEDED", "Artifact declared size exceeds reserved bytes.");
      }
      const output = createWriteStream(path, { flags: "wx", mode: 0o600 });
      let bytes = 0;
      const digest = createHash("sha256");
      stream.on("data", (chunk: Buffer | string) => {
        const buffer = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
        bytes += buffer.byteLength;
        digest.update(buffer);
        if (bytes > reservedBytes) stream.destroy(new Error("artifact-size-limit"));
      });
      try {
        await pipeline(stream, output);
      } catch (error) {
        if (error instanceof Error && error.message === "artifact-size-limit") {
          throw new UniversalBrokerError(
            "RESOURCE_QUOTA_EXCEEDED",
            "Artifact stream exceeded synchronously reserved bytes.",
            { evidence: { reservedBytes } },
          );
        }
        throw error;
      }
      await syncFile(path);
      if (declaredSize !== undefined && declaredSize !== bytes) {
        throw new UniversalBrokerError(
          "PRECONDITION_FAILED",
          "Artifact declared size did not match received bytes.",
          { evidence: { declaredSize, actualSize: bytes } },
        );
      }
      const sha256 = digest.digest("hex");
      this.assertExpectedContent(source, bytes, sha256, reservedBytes);
      return { directory, path, name, mimeType, size: bytes, sha256, sourceKind };
    } catch (error) {
      await rm(directory, { recursive: true, force: true });
      throw error;
    }
  }

  private assertExpectedContent(
    source: Record<string, unknown>,
    size: number,
    sha256: string,
    reservedBytes: number,
  ): void {
    if (size > reservedBytes) {
      throw new UniversalBrokerError("RESOURCE_QUOTA_EXCEEDED", "Artifact exceeds reserved bytes.");
    }
    const expectedSize = optionalNumber(source, "size");
    if (expectedSize !== undefined && expectedSize !== size) {
      throw new UniversalBrokerError(
        "PRECONDITION_FAILED",
        "Artifact size precondition failed.",
        { evidence: { expectedSize, actualSize: size } },
      );
    }
    const expectedSha256 = optionalString(source, "sha256");
    if (expectedSha256 && expectedSha256.toLowerCase() !== sha256) {
      throw new UniversalBrokerError(
        "PRECONDITION_FAILED",
        "Artifact SHA-256 precondition failed.",
        { evidence: { expectedSha256, actualSha256: sha256 } },
      );
    }
  }

  private async resolveRecord(
    artifactId: string,
    ownerFingerprint?: string,
    token?: string,
  ): Promise<ArtifactRecord> {
    await this.pruneExpired();
    const record = this.catalog.getAvailableArtifact(artifactId, this.now());
    if (!record) {
      throw new UniversalBrokerError("PATH_NOT_FOUND", "Artifact is unknown or expired.");
    }
    if (ownerFingerprint && record.ownerFingerprint !== ownerFingerprint) {
      throw new UniversalBrokerError(
        "AUTHORITY_PRINCIPAL_MISMATCH",
        "Artifact belongs to a different authenticated principal.",
      );
    }
    if (token && !this.catalog.matchesCapabilityToken(record, token)) {
      throw new UniversalBrokerError("PATH_NOT_FOUND", "Artifact capability is invalid.");
    }
    await verifyFile(record.objectPath, record.size, record.sha256);
    return record;
  }

  private async pruneExpired(): Promise<void> {
    try {
      const expired = this.catalog.expireDue(this.now());
      await this.performCleanupPlans(expired.cleanup);
    } catch (error) {
      throw mapCatalogError(error);
    }
  }

  private async createStagingDirectory(kind: string): Promise<string> {
    await mkdir(this.options.stagingRoot, { recursive: true, mode: 0o700 });
    return mkdtemp(join(this.options.stagingRoot, `${kind}-`));
  }

  private requestMaximumBytes(requested: number | undefined): number {
    if (requested === undefined) return this.maximumArtifactBytes;
    return boundedInteger(requested, requested, 1, this.maximumArtifactBytes, "maxBytes");
  }

  private requestTtlMs(ttlSeconds: number | undefined): number {
    if (ttlSeconds === undefined) return this.ttlMs;
    return boundedInteger(ttlSeconds * 1_000, this.ttlMs, 1_000, MAXIMUM_TTL_MS, "ttlSeconds");
  }

  private downloadUrl(record: ArtifactRecord, token: string): string | undefined {
    const configured = typeof this.options.baseUrl === "function"
      ? this.options.baseUrl()
      : this.options.baseUrl;
    if (!configured) return undefined;
    return `${configured.replace(/\/+$/, "")}${this.httpPathPrefix}/${record.artifactId}?token=${encodeURIComponent(token)}`;
  }

  private resolveOwner(context: ArtifactOwnerContext | undefined): string {
    if (typeof context === "string") return requiredOwnerFingerprint(context);
    const record = context as ArtifactCallContext | undefined;
    return requiredOwnerFingerprint(
      record?.ownerFingerprint
      ?? record?.principalKeyFingerprint
      ?? this.defaultOwnerFingerprint,
    );
  }

  private assertReservation(reservation: CapacityReservation): void {
    if (reservation.state !== "ACTIVE") {
      throw new UniversalBrokerError("STATE_CORRUPTED", "Artifact reservation is no longer active.");
    }
  }

  private async performCleanupPlans(plans: readonly ArtifactCleanupPlan[]): Promise<void> {
    for (const plan of plans) {
      try {
        await unlink(plan.object.path).catch((error: unknown) => {
          if (!isNodeError(error, "ENOENT")) throw error;
        });
        this.catalog.completeObjectCleanup(plan.receiptId, plan.object.sha256, true);
      } catch (error) {
        this.catalog.completeObjectCleanup(
          plan.receiptId,
          plan.object.sha256,
          false,
          errorMessage(error),
        );
        throw new UniversalBrokerError(
          "TRANSPORT_UNAVAILABLE",
          "Artifact CAS cleanup could not be completed.",
          { evidence: { sha256: plan.object.sha256, error: errorMessage(error) } },
        );
      }
    }
  }

  private async runOperation<T>(operation: () => Promise<T>): Promise<T> {
    this.assertOpen();
    this.inFlight += 1;
    try {
      await this.initialization;
      return await operation();
    } catch (error) {
      if (error instanceof ArtifactCatalogError) throw mapCatalogError(error);
      throw error;
    } finally {
      this.inFlight -= 1;
      if (this.inFlight === 0) {
        for (const resolve of this.idleWaiters) resolve();
        this.idleWaiters.clear();
      }
    }
  }

  private assertOpen(): void {
    if (this.closed) throw new UniversalBrokerError("TRANSPORT_UNAVAILABLE", "Artifact service is closed.");
  }
}

interface FilesystemRuntimeTarget {
  id: string;
  generation: string;
  endpointFingerprint: string;
  transport: "local" | "ssh";
  defaultCwd?: string;
}

interface FilesystemRuntimeContext {
  contextId: string;
  targetId: string;
  root: string;
}

interface FilesystemRuntimeAccess {
  targets: {
    resolveWithGeneration(selector: string | undefined): Promise<{ target: FilesystemRuntimeTarget }>;
  };
  contexts: {
    get(contextId: string, callContext?: CapabilityCallContext): Promise<FilesystemRuntimeContext>;
  };
}

function filesystemRuntimeAccess(filesystem: UniversalFilesystemService): FilesystemRuntimeAccess {
  const runtime = filesystem as unknown as Partial<FilesystemRuntimeAccess>;
  if (!runtime.targets || !runtime.contexts) {
    throw new UniversalBrokerError(
      "STATE_CORRUPTED",
      "Artifact copy cannot resolve filesystem target identity.",
    );
  }
  return runtime as FilesystemRuntimeAccess;
}

async function snapshotLocalDirectory(root: string): Promise<DirectoryManifestSnapshot> {
  const rootMetadata = await stat(root);
  if (!rootMetadata.isDirectory()) throw pathTypeError(root, "directory");
  const directories = new Set<string>();
  const entries: DirectoryManifestEntry[] = [];
  let totalBytes = 0;

  const visit = async (directory: string): Promise<void> => {
    const before = await stat(directory);
    if (!before.isDirectory()) throw pathTypeError(directory, "directory");
    const children = (await readdir(directory, { withFileTypes: true }))
      .sort((left, right) => compareText(left.name, right.name));
    for (const child of children) {
      const path = join(directory, child.name);
      const relativePath = safeManifestRelativePath(root, path);
      if (child.isDirectory()) {
        directories.add(relativePath);
        await visit(path);
        continue;
      }
      if (!child.isFile()) {
        throw new UniversalBrokerError(
          "CAPABILITY_UNAVAILABLE",
          "Directory artifact.copy manifest mode supports regular files and directories only.",
          { evidence: { path, entryType: child.isSymbolicLink() ? "symlink" : "other" } },
        );
      }
      const beforeFile = await stat(path);
      const sha256 = await sha256File(path);
      const afterFile = await stat(path);
      if (!sameFileIdentity(beforeFile, afterFile)) {
        throw new UniversalBrokerError(
          "PRECONDITION_FAILED",
          "Directory artifact.copy source changed while its immutable manifest was captured.",
          { evidence: { path } },
        );
      }
      totalBytes += afterFile.size;
      entries.push({ relativePath, size: afterFile.size, sha256 });
    }
    const after = await stat(directory);
    if (!sameFileIdentity(before, after)) {
      throw new UniversalBrokerError(
        "PRECONDITION_FAILED",
        "Directory artifact.copy source changed while its immutable manifest was captured.",
        { evidence: { path: directory } },
      );
    }
  };

  await visit(root);
  entries.sort((left, right) => compareText(left.relativePath, right.relativePath));
  const directoryEntries = [...directories].sort(compareText);
  return {
    directories: directoryEntries,
    entries,
    totalBytes,
    sourceIdentity: {
      path: root,
      mode: rootMetadata.mode & 0o7777,
      size: rootMetadata.size,
      mtimeMs: rootMetadata.mtimeMs,
      ctimeMs: rootMetadata.ctimeMs,
      birthtimeMs: rootMetadata.birthtimeMs,
    },
  };
}

type BoundLocalDirectoryHelperInput =
  | {
    mode: "preflight";
    destinationRoot: string;
    directories: readonly string[];
    entries: readonly DirectoryManifestEntry[];
    overwrite: boolean;
  }
  | {
    mode: "prepare";
    destinationRoot: string;
    directories: readonly string[];
  }
  | {
    mode: "verify-directories";
    destinationRoot: string;
    directories: readonly string[];
  }
  | {
    mode: "verify";
    destinationRoot: string;
    relativePath: string;
    expectedSize: number;
    expectedSha256: string;
  }
  | {
    mode: "publish";
    sourcePath: string;
    destinationRoot: string;
    relativePath: string;
    expectedSize: number;
    expectedSha256: string;
    overwrite: boolean;
  };

interface BoundLocalDirectoryHelperMessage {
  marker: "DEVSPACE_BOUND_LOCAL_PUBLICATION_HELPER";
  status: "READY" | "OK" | "ERROR";
  result?: { matches?: boolean };
  error?: {
    reason?: string;
    code?: string;
    message?: string;
    path?: string;
    recoveryError?: string;
  };
}

async function runBoundLocalDirectoryHelper(
  input: BoundLocalDirectoryHelperInput,
): Promise<{ matches?: boolean }> {
  const destinationRoot = resolve(input.destinationRoot);
  const filesystemRoot = parse(destinationRoot).root;
  const payload = JSON.stringify({ ...input, destinationRoot });
  const child = spawn(
    process.execPath,
    ["--input-type=commonjs", "-e", BOUND_LOCAL_DIRECTORY_HELPER_SOURCE],
    {
      cwd: filesystemRoot,
      stdio: ["pipe", "pipe", "pipe", "pipe"],
      windowsHide: true,
    },
  );
  let spawnError: Error | undefined;
  child.once("error", (error) => {
    spawnError = error;
  });
  child.stdin.on("error", (error) => {
    spawnError ??= error;
  });
  const payloadInput = child.stdio[3];
  if (!payloadInput || !("end" in payloadInput)) {
    child.kill();
    throw new UniversalBrokerError(
      "STATE_CORRUPTED",
      "Bound local Artifact publication helper payload pipe is unavailable.",
    );
  }
  payloadInput.on("error", (error) => {
    spawnError ??= error;
  });
  payloadInput.end(payload);
  const stderr: Buffer[] = [];
  child.stderr.on("data", (chunk: Buffer) => stderr.push(chunk));
  const close = new Promise<{ code: number | null; signal: NodeJS.Signals | null }>((resolveClose) => {
    child.once("close", (code, signal) => resolveClose({ code, signal }));
  });
  const lines = createInterface({ input: child.stdout, crlfDelay: Infinity });
  const iterator = lines[Symbol.asyncIterator]();
  const nextMessage = async (): Promise<BoundLocalDirectoryHelperMessage> => {
    const line = await iterator.next();
    if (line.done) {
      const exit = await close;
      throw new UniversalBrokerError(
        "STATE_CORRUPTED",
        "Bound local Artifact publication helper exited without a protocol result.",
        {
          evidence: {
            exitCode: exit.code,
            signal: exit.signal,
            spawnError: spawnError?.message,
            stderr: Buffer.concat(stderr).toString("utf8").slice(0, 2_048),
          },
        },
      );
    }
    try {
      const message = JSON.parse(line.value) as BoundLocalDirectoryHelperMessage;
      if (message.marker !== "DEVSPACE_BOUND_LOCAL_PUBLICATION_HELPER") throw new Error("marker");
      return message;
    } catch {
      throw new UniversalBrokerError(
        "STATE_CORRUPTED",
        "Bound local Artifact publication helper returned an invalid protocol message.",
      );
    }
  };

  try {
    let message = await nextMessage();
    if (message.status === "READY") {
      if (input.mode !== "publish") {
        child.stdin.end("abort\n");
        throw new UniversalBrokerError(
          "STATE_CORRUPTED",
          "Bound local Artifact helper requested publication for a read-only operation.",
        );
      }
      child.stdin.end("publish\n");
      message = await nextMessage();
    } else {
      child.stdin.end();
    }
    const exit = await close;
    if (message.status === "ERROR") throw mapBoundLocalDirectoryHelperError(message);
    if (message.status !== "OK" || exit.code !== 0 || exit.signal !== null) {
      throw new UniversalBrokerError(
        "STATE_CORRUPTED",
        "Bound local Artifact publication helper did not complete cleanly.",
        {
          evidence: {
            exitCode: exit.code,
            signal: exit.signal,
            spawnError: spawnError?.message,
            stderr: Buffer.concat(stderr).toString("utf8").slice(0, 2_048),
          },
        },
      );
    }
    return message.result ?? {};
  } finally {
    lines.close();
    if (child.exitCode === null && child.signalCode === null) child.kill();
  }
}

function mapBoundLocalDirectoryHelperError(
  message: BoundLocalDirectoryHelperMessage,
): UniversalBrokerError {
  const reason = message.error?.reason ?? message.error?.code ?? "UNKNOWN";
  const evidence = {
    helperReason: reason,
    filesystemError: message.error?.message,
    path: message.error?.path,
    recoveryError: message.error?.recoveryError,
  };
  if (message.error?.recoveryError) {
    return new UniversalBrokerError(
      "ROLLBACK_STATE_UNKNOWN",
      "Local directory Artifact publication rollback could not be verified.",
      { evidence: { ...evidence, dispatchState: "UNKNOWN" } },
    );
  }
  if (["SYMLINK", "BINDING_CHANGED"].includes(reason)) {
    return new UniversalBrokerError(
      "PERMISSION_DENIED",
      "Local directory Artifact publication path changed or contains a symlink.",
      { evidence },
    );
  }
  if (reason === "NO_REPLACE_CAPABILITY") {
    return new UniversalBrokerError(
      "CAPABILITY_UNAVAILABLE",
      "Destination filesystem lacks descriptor-bound atomic no-replace publication.",
      { evidence },
    );
  }
  if (reason === "SOURCE_MISSING") {
    return new UniversalBrokerError("PATH_NOT_FOUND", "Directory Artifact source entry is missing.", { evidence });
  }
  return new UniversalBrokerError(
    "PRECONDITION_FAILED",
    "Descriptor-bound local directory Artifact publication precondition failed.",
    { evidence },
  );
}

const BOUND_LOCAL_DIRECTORY_HELPER_SOURCE = String.raw`
"use strict";
const fs = require("node:fs");
const crypto = require("node:crypto");
const path = require("node:path");
const MARKER = "DEVSPACE_BOUND_LOCAL_PUBLICATION_HELPER";
const input = JSON.parse(fs.readFileSync(3, "utf8"));

function emit(status, value) {
  process.stdout.write(JSON.stringify(Object.assign({ marker: MARKER, status }, value || {})) + "\n");
}
function failure(reason, message, target) {
  const error = new Error(message);
  error.reason = reason;
  if (target) error.path = target;
  throw error;
}
function sameIdentity(left, right) {
  return String(left.dev) === String(right.dev) && String(left.ino) === String(right.ino);
}
function directoryIdentity(value) {
  return { dev: String(value.dev), ino: String(value.ino) };
}
function isMissing(error) {
  return error && (error.code === "ENOENT" || error.code === "ENOTDIR");
}
function hashFile(target) {
  const digest = crypto.createHash("sha256");
  const descriptor = fs.openSync(target, "r");
  const buffer = Buffer.allocUnsafe(1024 * 1024);
  try {
    for (;;) {
      const count = fs.readSync(descriptor, buffer, 0, buffer.length, null);
      if (count === 0) break;
      digest.update(buffer.subarray(0, count));
    }
  } finally {
    fs.closeSync(descriptor);
  }
  return digest.digest("hex");
}
function fsyncFile(target) {
  const descriptor = fs.openSync(target, "r");
  try { fs.fsyncSync(descriptor); } finally { fs.closeSync(descriptor); }
}
function fsyncCurrentDirectory() {
  try { fsyncFile("."); } catch (_) { }
}
function validateRelative(value) {
  if (typeof value !== "string" || value.length === 0 || value.includes("\\") || path.isAbsolute(value)) {
    failure("UNSAFE_PATH", "unsafe relative path", String(value));
  }
  const segments = value.split("/");
  if (segments.some((segment) => !segment || segment === "." || segment === "..")) {
    failure("UNSAFE_PATH", "unsafe relative path", value);
  }
  return segments;
}
function childPath(root, relativePath) {
  const segments = validateRelative(relativePath);
  const candidate = path.resolve(root, ...segments);
  if (candidate !== root && !candidate.startsWith(root + path.sep)) {
    failure("UNSAFE_PATH", "relative path escaped destination root", relativePath);
  }
  return candidate;
}
function bindDirectory(target, create) {
  const absolute = path.resolve(target);
  const filesystemRoot = path.parse(absolute).root;
  process.chdir(filesystemRoot);
  const relative = path.relative(filesystemRoot, absolute);
  const segments = relative ? relative.split(path.sep) : [];
  for (const segment of segments) {
    if (!segment || segment === "." || segment === "..") failure("UNSAFE_PATH", "unsafe absolute path", absolute);
    let observed;
    try {
      observed = fs.lstatSync(segment);
    } catch (error) {
      if (!isMissing(error) || !create) {
        if (isMissing(error)) failure("MISSING_DIRECTORY", "directory does not exist", absolute);
        throw error;
      }
      try { fs.mkdirSync(segment, { mode: 0o700 }); }
      catch (mkdirError) { if (!mkdirError || mkdirError.code !== "EEXIST") throw mkdirError; }
      observed = fs.lstatSync(segment);
    }
    if (observed.isSymbolicLink()) {
      const parent = fs.statSync(".");
      let parentWritable = true;
      try { fs.accessSync(".", fs.constants.W_OK); }
      catch (_) { parentWritable = false; }
      const ownedByProcess = typeof process.getuid === "function" && parent.uid === process.getuid();
      if (parentWritable || ownedByProcess) failure("SYMLINK", "mutable symlink directory component", absolute);
      observed = fs.statSync(segment);
    }
    if (!observed.isDirectory()) failure("PATH_TYPE", "path component is not a directory", absolute);
    process.chdir(segment);
    const bound = fs.statSync(".");
    if (!sameIdentity(observed, bound)) failure("BINDING_CHANGED", "directory changed while binding cwd", absolute);
  }
  return directoryIdentity(fs.statSync("."));
}
function assertPublicDirectoryIdentity(target, expected) {
  let observed;
  try { observed = fs.lstatSync(target); }
  catch (error) { failure("BINDING_CHANGED", error.message, target); }
  if (observed.isSymbolicLink() || !observed.isDirectory() || !sameIdentity(observed, expected)) {
    failure("BINDING_CHANGED", "public directory identity changed", target);
  }
}
function inspectPath(target) {
  try { bindDirectory(path.dirname(target), false); }
  catch (error) {
    if (error && error.reason === "MISSING_DIRECTORY") return { exists: false };
    throw error;
  }
  const leaf = path.basename(target);
  let observed;
  try { observed = fs.lstatSync(leaf); }
  catch (error) {
    if (isMissing(error)) return { exists: false };
    throw error;
  }
  if (observed.isSymbolicLink()) failure("SYMLINK", "symlink destination", target);
  return { exists: true, observed };
}
function filePreimage(leaf, target) {
  let observed;
  try { observed = fs.lstatSync(leaf); }
  catch (error) {
    if (isMissing(error)) return { exists: false };
    throw error;
  }
  if (observed.isSymbolicLink()) failure("SYMLINK", "symlink destination", target);
  if (!observed.isFile()) failure("PATH_TYPE", "destination is not a regular file", target);
  return {
    exists: true,
    dev: String(observed.dev),
    ino: String(observed.ino),
    size: observed.size,
    mtimeMs: observed.mtimeMs,
    ctimeMs: observed.ctimeMs,
    sha256: hashFile(leaf),
  };
}
function samePreimage(left, right) {
  return left.exists === right.exists
    && left.dev === right.dev
    && left.ino === right.ino
    && left.size === right.size
    && left.mtimeMs === right.mtimeMs
    && left.ctimeMs === right.ctimeMs
    && left.sha256 === right.sha256;
}
function verifyExpectedFile(target, expectedSize, expectedSha256) {
  const observed = fs.lstatSync(target);
  if (observed.isSymbolicLink() || !observed.isFile() || observed.size !== expectedSize) {
    failure("CONTENT_MISMATCH", "file type or size mismatch", target);
  }
  const actualSha256 = hashFile(target);
  if (actualSha256 !== expectedSha256) failure("CONTENT_MISMATCH", "file hash mismatch", target);
}
function preflight() {
  const root = path.resolve(input.destinationRoot);
  const rootValue = inspectPath(root);
  if (rootValue.exists && !rootValue.observed.isDirectory()) failure("PATH_TYPE", "destination root is not a directory", root);
  for (const relativePath of input.directories || []) {
    const target = childPath(root, relativePath);
    const value = inspectPath(target);
    if (value.exists && !value.observed.isDirectory()) failure("PATH_TYPE", "manifest directory has wrong type", target);
  }
  for (const entry of input.entries || []) {
    const target = childPath(root, entry.relativePath);
    const value = inspectPath(target);
    if (!value.exists) continue;
    if (!value.observed.isFile()) failure("PATH_TYPE", "manifest file has wrong type", target);
    if (!input.overwrite && (value.observed.size !== entry.size || hashFile(path.basename(target)) !== entry.sha256)) {
      failure("DESTINATION_EXISTS", "destination file exists with different content", target);
    }
  }
  return {};
}
function prepare() {
  const root = path.resolve(input.destinationRoot);
  const rootIdentity = bindDirectory(root, true);
  assertPublicDirectoryIdentity(root, rootIdentity);
  for (const relativePath of input.directories || []) {
    const target = childPath(root, relativePath);
    const identity = bindDirectory(target, true);
    assertPublicDirectoryIdentity(root, rootIdentity);
    assertPublicDirectoryIdentity(target, identity);
  }
  return {};
}
function verifyDirectories() {
  const root = path.resolve(input.destinationRoot);
  let rootIdentity;
  try { rootIdentity = bindDirectory(root, false); }
  catch (error) {
    if (error && (error.reason === "MISSING_DIRECTORY" || error.reason === "PATH_TYPE")) return { matches: false };
    throw error;
  }
  assertPublicDirectoryIdentity(root, rootIdentity);
  for (const relativePath of input.directories || []) {
    const target = childPath(root, relativePath);
    let identity;
    try { identity = bindDirectory(target, false); }
    catch (error) {
      if (error && (error.reason === "MISSING_DIRECTORY" || error.reason === "PATH_TYPE")) return { matches: false };
      throw error;
    }
    assertPublicDirectoryIdentity(root, rootIdentity);
    assertPublicDirectoryIdentity(target, identity);
  }
  assertPublicDirectoryIdentity(root, rootIdentity);
  return { matches: true };
}
function verify() {
  const root = path.resolve(input.destinationRoot);
  let rootIdentity;
  try { rootIdentity = bindDirectory(root, false); }
  catch (error) { if (error && error.reason === "MISSING_DIRECTORY") return { matches: false }; throw error; }
  const target = childPath(root, input.relativePath);
  let parentIdentity;
  try { parentIdentity = bindDirectory(path.dirname(target), false); }
  catch (error) { if (error && error.reason === "MISSING_DIRECTORY") return { matches: false }; throw error; }
  assertPublicDirectoryIdentity(root, rootIdentity);
  assertPublicDirectoryIdentity(path.dirname(target), parentIdentity);
  let observed;
  try { observed = fs.lstatSync(path.basename(target)); }
  catch (error) { if (isMissing(error)) return { matches: false }; throw error; }
  if (observed.isSymbolicLink()) failure("SYMLINK", "symlink destination", target);
  if (!observed.isFile()) failure("PATH_TYPE", "destination is not a regular file", target);
  const matches = observed.size === input.expectedSize && hashFile(path.basename(target)) === input.expectedSha256;
  assertPublicDirectoryIdentity(root, rootIdentity);
  assertPublicDirectoryIdentity(path.dirname(target), parentIdentity);
  return { matches };
}
function publish() {
  const root = path.resolve(input.destinationRoot);
  const target = childPath(root, input.relativePath);
  const source = path.resolve(input.sourcePath);
  let sourceValue;
  try { sourceValue = fs.lstatSync(source); }
  catch (error) { if (isMissing(error)) failure("SOURCE_MISSING", "source entry is missing", source); throw error; }
  if (sourceValue.isSymbolicLink() || !sourceValue.isFile()) failure("PATH_TYPE", "source is not a regular file", source);
  if (sourceValue.size !== input.expectedSize || hashFile(source) !== input.expectedSha256) {
    failure("CONTENT_MISMATCH", "source no longer matches manifest", source);
  }
  const rootIdentity = bindDirectory(root, false);
  const parent = path.dirname(target);
  const parentIdentity = bindDirectory(parent, true);
  assertPublicDirectoryIdentity(root, rootIdentity);
  assertPublicDirectoryIdentity(parent, parentIdentity);
  const leaf = path.basename(target);
  const preimage = filePreimage(leaf, target);
  if (preimage.exists && !input.overwrite) failure("DESTINATION_EXISTS", "destination exists", target);
  const temporary = ".devspace-artifact-copy-" + crypto.randomUUID() + ".tmp";
  const backup = ".devspace-artifact-preimage-" + crypto.randomUUID() + ".tmp";
  let temporaryExists = false;
  let backupExists = false;
  let published = false;
  try {
    fs.copyFileSync(source, temporary, fs.constants.COPYFILE_EXCL);
    temporaryExists = true;
    fsyncFile(temporary);
    verifyExpectedFile(temporary, input.expectedSize, input.expectedSha256);
    assertPublicDirectoryIdentity(root, rootIdentity);
    assertPublicDirectoryIdentity(parent, parentIdentity);
    emit("READY");
    const command = fs.readFileSync(0, "utf8").trim();
    if (command !== "publish") failure("ABORTED", "publication was not authorized", target);
    assertPublicDirectoryIdentity(root, rootIdentity);
    assertPublicDirectoryIdentity(parent, parentIdentity);
    if (!samePreimage(preimage, filePreimage(leaf, target))) {
      failure("DESTINATION_CHANGED", "destination changed before publication", target);
    }
    if (!preimage.exists) {
      try {
        fs.linkSync(temporary, leaf);
        fs.unlinkSync(temporary);
        temporaryExists = false;
      } catch (error) {
        if (!input.overwrite || !error || !["ENOTSUP", "EOPNOTSUPP", "ENOSYS", "EPERM"].includes(error.code)) {
          if (error && ["ENOTSUP", "EOPNOTSUPP", "ENOSYS", "EPERM"].includes(error.code)) {
            failure("NO_REPLACE_CAPABILITY", error.message, target);
          }
          throw error;
        }
        fs.renameSync(temporary, leaf);
        temporaryExists = false;
      }
    } else {
      try { fs.linkSync(leaf, backup); }
      catch (_) { fs.copyFileSync(leaf, backup, fs.constants.COPYFILE_EXCL); }
      backupExists = true;
      fsyncFile(backup);
      verifyExpectedFile(backup, preimage.size, preimage.sha256);
      fs.renameSync(temporary, leaf);
      temporaryExists = false;
    }
    published = true;
    fsyncCurrentDirectory();
    verifyExpectedFile(leaf, input.expectedSize, input.expectedSha256);
    assertPublicDirectoryIdentity(root, rootIdentity);
    assertPublicDirectoryIdentity(parent, parentIdentity);
    if (backupExists) { fs.unlinkSync(backup); backupExists = false; }
    fsyncCurrentDirectory();
    return {};
  } catch (error) {
    if (published) {
      try {
        if (preimage.exists && backupExists) {
          fs.renameSync(backup, leaf);
          backupExists = false;
        } else if (!preimage.exists) {
          try { fs.unlinkSync(leaf); } catch (unlinkError) { if (!isMissing(unlinkError)) throw unlinkError; }
        }
        fsyncCurrentDirectory();
      } catch (recoveryError) {
        error.recoveryError = recoveryError.message;
      }
    }
    throw error;
  } finally {
    if (temporaryExists) { try { fs.unlinkSync(temporary); } catch (_) { } }
    if (backupExists) { try { fs.unlinkSync(backup); } catch (_) { } }
  }
}

try {
  let result;
  if (input.mode === "preflight") result = preflight();
  else if (input.mode === "prepare") result = prepare();
  else if (input.mode === "verify-directories") result = verifyDirectories();
  else if (input.mode === "verify") result = verify();
  else if (input.mode === "publish") result = publish();
  else failure("INVALID_MODE", "unsupported helper mode");
  emit("OK", { result });
} catch (error) {
  emit("ERROR", { error: {
    reason: error && error.reason,
    code: error && error.code,
    message: error && error.message,
    path: error && error.path,
    recoveryError: error && error.recoveryError,
  } });
  process.exitCode = 1;
}
`;

function localDirectoryCopyRelativePath(root: string, path: string): string {
  const normalizedRoot = resolve(root);
  const normalizedPath = resolve(path);
  if (normalizedPath === normalizedRoot) return "";
  if (!isPathInside(normalizedRoot, normalizedPath)) {
    throw new UniversalBrokerError(
      "PRECONDITION_FAILED",
      "Directory artifact.copy destination path escaped its root.",
      { evidence: { root: normalizedRoot, path: normalizedPath } },
    );
  }
  const relativePath = relative(normalizedRoot, normalizedPath).split(sep).join("/");
  assertSafeManifestRelativePath(relativePath);
  return relativePath;
}

async function atomicWriteJson(path: string, value: unknown): Promise<void> {
  await mkdir(dirname(path), { recursive: true, mode: 0o700 });
  const temporary = join(dirname(path), `.${basename(path)}.${randomUUID()}.tmp`);
  try {
    await writeFile(temporary, `${JSON.stringify(value, null, 2)}\n`, { flag: "wx", mode: 0o600 });
    await syncFile(temporary);
    await rename(temporary, path);
    await syncDirectory(dirname(path));
  } finally {
    await rm(temporary, { force: true }).catch(() => undefined);
  }
}

function directoryCopyCheckpointPath(stagingRoot: string, copyId: string): string {
  return join(stagingRoot, "copy-checkpoints", `${copyId}.json`);
}

function assertCompatibleDirectoryCheckpoint(
  checkpoint: DirectoryCopyCheckpoint,
  expected: {
    copyId: string;
    ownerFingerprint: string;
    manifestDigest: string;
    source: ArtifactCopyTargetBinding;
    destination: ArtifactCopyTargetBinding;
    artifactId: string;
    resourceUri: string;
  },
): void {
  if (
    checkpoint.copyId !== expected.copyId
    || checkpoint.ownerFingerprint !== expected.ownerFingerprint
    || checkpoint.manifestDigest !== expected.manifestDigest
    || digestJson(checkpoint.source) !== digestJson(expected.source)
    || digestJson(checkpoint.destination) !== digestJson(expected.destination)
    || checkpoint.artifactId !== expected.artifactId
    || checkpoint.resourceUri !== expected.resourceUri
  ) {
    throw new UniversalBrokerError(
      "PRECONDITION_FAILED",
      "Directory artifact.copy checkpoint does not match the requested transfer.",
      { evidence: { copyId: expected.copyId } },
    );
  }
}

function isDirectoryCopyCheckpoint(value: unknown): value is DirectoryCopyCheckpoint {
  if (!value || typeof value !== "object" || Array.isArray(value)) return false;
  const checkpoint = value as DirectoryCopyCheckpoint;
  return checkpoint.version === 1
    && typeof checkpoint.copyId === "string"
    && /^[0-9a-f]{64}$/u.test(checkpoint.copyId)
    && typeof checkpoint.ownerFingerprint === "string"
    && typeof checkpoint.manifestDigest === "string"
    && /^[0-9a-f]{64}$/u.test(checkpoint.manifestDigest)
    && isCopyTargetBinding(checkpoint.source)
    && isCopyTargetBinding(checkpoint.destination)
    && typeof checkpoint.artifactId === "string"
    && /^[0-9a-f-]{36}$/u.test(checkpoint.artifactId)
    && checkpoint.resourceUri === canonicalArtifactResourceUri(checkpoint.artifactId)
    && Array.isArray(checkpoint.completedEntries)
    && checkpoint.completedEntries.every((entry) => typeof entry === "string")
    && (checkpoint.status === "RUNNING" || checkpoint.status === "COMPLETED")
    && Number.isSafeInteger(checkpoint.createdAt)
    && Number.isSafeInteger(checkpoint.updatedAt);
}

function isCopyTargetBinding(value: unknown): value is ArtifactCopyTargetBinding {
  if (!value || typeof value !== "object" || Array.isArray(value)) return false;
  const binding = value as ArtifactCopyTargetBinding;
  return typeof binding.targetId === "string"
    && typeof binding.targetGeneration === "string"
    && /^[0-9a-f]{64}$/u.test(binding.targetGeneration)
    && typeof binding.endpointFingerprint === "string"
    && (binding.transport === "local" || binding.transport === "ssh")
    && typeof binding.path === "string";
}

function copyTargetSelector(binding: ArtifactCopyTargetBinding): string | undefined {
  return binding.transport === "local" ? undefined : binding.targetId;
}

function copyTargetPath(binding: ArtifactCopyTargetBinding, relativePath: string): string {
  return binding.transport === "local"
    ? joinSafeRelative(binding.path, relativePath)
    : remoteJoinSafeRelative(binding.path, relativePath);
}

function manifestChildRelativePath(parent: string, name: string): string {
  assertSafeRemoteEntryName(name);
  const relativePath = parent ? `${parent}/${name}` : name;
  assertSafeManifestRelativePath(relativePath);
  return relativePath;
}

function remoteChildPath(parent: string, name: string): string {
  assertSafeRemoteEntryName(name);
  if (parent === "/") return `/${name}`;
  return `${parent.replace(/\/+$/u, "")}/${name}`;
}

function remoteJoinSafeRelative(root: string, relativePath: string): string {
  assertSafeManifestRelativePath(relativePath);
  const normalizedRoot = root === "/" ? "/" : root.replace(/\/+$/u, "");
  return normalizedRoot === "/" ? `/${relativePath}` : `${normalizedRoot}/${relativePath}`;
}

function isCopyTargetPathInside(source: ArtifactCopyTargetBinding, candidate: string): boolean {
  if (source.transport === "local") return isPathInside(source.path, candidate);
  const normalizedRoot = source.path === "/" ? "/" : source.path.replace(/\/+$/u, "");
  if (normalizedRoot === "/") return candidate !== "/" && candidate.startsWith("/");
  return candidate.startsWith(`${normalizedRoot}/`);
}

function directoryManifestListEntries(value: unknown): DirectoryManifestListEntry[] {
  if (!Array.isArray(value)) {
    throw new UniversalBrokerError(
      "STATE_CORRUPTED",
      "Directory artifact.copy list result is invalid.",
    );
  }
  return value.map((entry): DirectoryManifestListEntry => {
    if (!entry || typeof entry !== "object" || Array.isArray(entry)) {
      throw new UniversalBrokerError(
        "STATE_CORRUPTED",
        "Directory artifact.copy list entry is invalid.",
      );
    }
    const record = entry as Record<string, unknown>;
    const name = requiredString(record, "name", "Directory artifact.copy list entry is missing name.");
    assertSafeRemoteEntryName(name);
    const type = requiredString(record, "type", "Directory artifact.copy list entry is missing type.");
    if (type !== "directory" && type !== "file" && type !== "symlink" && type !== "other") {
      throw new UniversalBrokerError(
        "STATE_CORRUPTED",
        "Directory artifact.copy list entry type is invalid.",
        { evidence: { type } },
      );
    }
    return { name, type };
  });
}

function copyTargetStatIdentity(record: Record<string, unknown>): Record<string, unknown> {
  return {
    path: record.path,
    type: record.type,
    size: record.size,
    mode: record.mode,
    mtimeMs: record.mtimeMs,
    birthtimeMs: record.birthtimeMs,
    uid: record.uid,
    gid: record.gid,
    linkTarget: record.linkTarget,
  };
}

function requiredNumberField(record: Record<string, unknown>, key: string): number {
  const value = record[key];
  if (typeof value !== "number" || !Number.isSafeInteger(value) || value < 0) {
    throw new UniversalBrokerError("STATE_CORRUPTED", `${key} must be a non-negative integer.`);
  }
  return value;
}

function requiredSha256Field(record: Record<string, unknown>, key: string): string {
  const value = record[key];
  if (typeof value !== "string" || !/^[0-9a-f]{64}$/u.test(value)) {
    throw new UniversalBrokerError("STATE_CORRUPTED", `${key} must be a SHA-256 digest.`);
  }
  return value;
}

function assertSafeRemoteEntryName(name: string): void {
  if (!name || name === "." || name === ".." || name.includes("/") || name.includes("\0")) {
    throw new UniversalBrokerError(
      "PRECONDITION_FAILED",
      "Directory artifact.copy manifest contains an unsafe entry name.",
      { evidence: { name } },
    );
  }
}

function resolveArtifactLocalPath(value: string, base: string): string {
  const expanded = expandHomePath(value);
  return resolve(isAbsolute(expanded) ? expanded : join(base, expanded));
}

function safeManifestRelativePath(root: string, path: string): string {
  const relativePath = relative(root, path).split(sep).join("/");
  if (!relativePath || relativePath === "." || relativePath.startsWith("../") || relativePath.includes("/../")) {
    throw new UniversalBrokerError(
      "PRECONDITION_FAILED",
      "Directory artifact.copy source path escaped its root.",
      { evidence: { root, path } },
    );
  }
  return relativePath;
}

function joinSafeRelative(root: string, relativePath: string): string {
  assertSafeManifestRelativePath(relativePath);
  return join(root, ...relativePath.split("/"));
}

function assertSafeManifestRelativePath(relativePath: string): void {
  if (
    !relativePath
    || relativePath === "."
    || relativePath.startsWith("/")
    || relativePath.startsWith("../")
    || relativePath.includes("/../")
    || relativePath.includes("\0")
  ) {
    throw new UniversalBrokerError(
      "PRECONDITION_FAILED",
      "Directory artifact.copy manifest contains an unsafe relative path.",
      { evidence: { relativePath } },
    );
  }
}

function sameFileIdentity(left: Stats, right: Stats): boolean {
  return left.dev === right.dev
    && left.ino === right.ino
    && left.size === right.size
    && left.mtimeMs === right.mtimeMs
    && left.ctimeMs === right.ctimeMs;
}

function isPathInside(root: string, path: string): boolean {
  const normalizedRoot = resolve(root);
  const normalizedPath = resolve(path);
  return normalizedPath.startsWith(`${normalizedRoot}${sep}`);
}

function digestJson(value: unknown): string {
  return createHash("sha256").update(JSON.stringify(value)).digest("hex");
}

function deterministicDirectoryCopyArtifactId(copyId: string): string {
  const hex = createHash("sha256")
    .update("devspace-directory-copy-artifact\0")
    .update(copyId)
    .digest("hex")
    .slice(0, 32)
    .split("");
  hex[12] = "5";
  hex[16] = ((Number.parseInt(hex[16]!, 16) & 0x3) | 0x8).toString(16);
  const value = hex.join("");
  return `${value.slice(0, 8)}-${value.slice(8, 12)}-${value.slice(12, 16)}-${value.slice(16, 20)}-${value.slice(20)}`;
}

function compareText(left: string, right: string): number {
  return left < right ? -1 : left > right ? 1 : 0;
}

function pathTypeError(path: string, expected: string): UniversalBrokerError {
  return new UniversalBrokerError(
    "PRECONDITION_FAILED",
    `Expected ${expected}: ${path}`,
    { evidence: { path, expected } },
  );
}

export function canonicalArtifactResourceUri(artifactId: string): string {
  if (!/^[0-9a-f-]{36}$/iu.test(artifactId)) {
    throw new UniversalBrokerError("PRECONDITION_FAILED", "Artifact ID is invalid.");
  }
  return formatResourceUri({ kind: "artifact", artifactId });
}

function parseArtifactResourceUri(resourceUri: string): string {
  try {
    const parsed = parseResourceUri(resourceUri, { allowLegacyRead: true });
    if (parsed.kind !== "artifact") {
      throw new UniversalBrokerError("PRECONDITION_FAILED", "Resource URI does not identify an artifact.");
    }
    canonicalArtifactResourceUri(parsed.artifactId);
    return parsed.artifactId;
  } catch (error) {
    if (error instanceof UniversalBrokerError) throw error;
    if (!(error instanceof ResourceUriError)) throw error;
    throw new UniversalBrokerError("PRECONDITION_FAILED", "Artifact resource URI is invalid.");
  }
}

function artifactCapabilityContext(
  context: ArtifactOwnerContext | undefined,
): CapabilityCallContext | undefined {
  if (!context || typeof context === "string") return undefined;
  return "principalKeyFingerprint" in context
    ? context as CapabilityCallContext
    : undefined;
}

async function verifyFile(path: string, expectedSize: number, expectedSha256: string): Promise<void> {
  const value = await lstat(path);
  if (!value.isFile() || value.isSymbolicLink() || value.size !== expectedSize) {
    throw new UniversalBrokerError(
      "PRECONDITION_FAILED",
      "Artifact CAS object size/type verification failed.",
      { evidence: { expectedSize, actualSize: value.size, path } },
    );
  }
  const actualSha256 = await sha256File(path);
  if (actualSha256 !== expectedSha256) {
    throw new UniversalBrokerError(
      "PRECONDITION_FAILED",
      "Artifact CAS object hash verification failed.",
      { evidence: { expectedSha256, actualSha256, path } },
    );
  }
}

async function sha256File(path: string): Promise<string> {
  const digest = createHash("sha256");
  await pipeline(createReadStream(path), digest);
  return digest.digest("hex");
}

async function syncFile(path: string): Promise<void> {
  const handle = await open(path, "r");
  try {
    await handle.sync();
  } finally {
    await handle.close();
  }
}

async function syncDirectory(path: string): Promise<void> {
  try {
    await syncFile(path);
  } catch {
    // Directory fsync is not exposed on every supported filesystem.
  }
}

async function optionalLstat(path: string) {
  try {
    return await lstat(path);
  } catch (error) {
    if (isNodeError(error, "ENOENT")) return undefined;
    throw error;
  }
}

function sourceUrl(source: Record<string, unknown>): URL {
  const raw = optionalString(source, "url") ?? optionalString(source, "download_url");
  if (!raw) {
    throw new UniversalBrokerError(
      "PRECONDITION_FAILED",
      "artifact.receive source requires a trusted native file reference or URL.",
    );
  }
  let url: URL;
  try {
    url = new URL(raw);
  } catch {
    throw new UniversalBrokerError("PRECONDITION_FAILED", "Artifact source URL is invalid.");
  }
  validateDownloadUrl(url);
  return url;
}

async function fetchWithValidatedRedirects(
  fetcher: typeof fetch,
  initial: URL,
  timeoutMs: number,
): Promise<Response> {
  let current = initial;
  for (let redirect = 0; redirect <= DOWNLOAD_REDIRECT_LIMIT; redirect++) {
    validateDownloadUrl(current);
    let response: Response;
    try {
      response = await fetcher(current, { redirect: "manual", signal: AbortSignal.timeout(timeoutMs) });
    } catch (error) {
      throw new UniversalBrokerError(
        "TRANSPORT_UNAVAILABLE",
        "Artifact URL could not be downloaded.",
        { evidence: { origin: current.origin, error: errorMessage(error) } },
      );
    }
    if (![301, 302, 303, 307, 308].includes(response.status)) return response;
    const location = response.headers.get("location");
    await response.body?.cancel().catch(() => undefined);
    if (!location || redirect === DOWNLOAD_REDIRECT_LIMIT) {
      throw new UniversalBrokerError("TRANSPORT_UNAVAILABLE", "Artifact redirect chain is invalid or too long.");
    }
    current = new URL(location, current);
  }
  throw new UniversalBrokerError("TRANSPORT_UNAVAILABLE", "Artifact redirect limit exceeded.");
}

function validateDownloadUrl(url: URL): void {
  const loopback = ["localhost", "127.0.0.1", "::1", "[::1]"].includes(url.hostname);
  if (url.protocol !== "https:" && !(url.protocol === "http:" && loopback)) {
    throw new UniversalBrokerError("PRECONDITION_FAILED", "Artifact URL must use HTTPS, except for loopback test sources.");
  }
  if (url.username || url.password) {
    throw new UniversalBrokerError("PRECONDITION_FAILED", "Artifact URL must not contain credentials.");
  }
}

function isUnsupportedIncomingArtifact(error: unknown): boolean {
  return error instanceof ArtifactError && error.code === "unsupported_incoming_artifact";
}

function mapArtifactError(error: unknown): UniversalBrokerError {
  if (error instanceof UniversalBrokerError) return error;
  if (error instanceof ArtifactError) {
    return new UniversalBrokerError(
      error.code.includes("size") ? "PRECONDITION_FAILED" : "TRANSPORT_UNAVAILABLE",
      error.message,
      { evidence: { adapterCode: error.code } },
    );
  }
  return new UniversalBrokerError("TRANSPORT_UNAVAILABLE", errorMessage(error));
}

function requiredString(record: Record<string, unknown> | undefined, key: string, message: string): string {
  const value = optionalString(record, key);
  if (!value) throw new UniversalBrokerError("PRECONDITION_FAILED", message);
  return value;
}

function optionalString(record: Record<string, unknown> | undefined, key: string): string | undefined {
  const value = record?.[key];
  if (value === undefined || value === null) return undefined;
  if (typeof value !== "string" || value.length === 0) {
    throw new UniversalBrokerError("PRECONDITION_FAILED", `${key} must be a non-empty string.`);
  }
  return value;
}

function optionalNumber(record: Record<string, unknown> | undefined, key: string): number | undefined {
  const value = record?.[key];
  if (value === undefined || value === null) return undefined;
  if (typeof value !== "number" || !Number.isSafeInteger(value) || value < 0) {
    throw new UniversalBrokerError("PRECONDITION_FAILED", `${key} must be a non-negative integer.`);
  }
  return value;
}

function boundedInteger(
  value: number | undefined,
  fallback: number,
  minimum: number,
  maximum: number,
  field: string,
): number {
  const parsed = value ?? fallback;
  if (!Number.isSafeInteger(parsed) || parsed < minimum || parsed > maximum) {
    throw new UniversalBrokerError("PRECONDITION_FAILED", `${field} must be an integer from ${minimum} through ${maximum}.`);
  }
  return parsed;
}

function requiredOwnerFingerprint(value: string): string {
  const normalized = value.trim();
  if (!normalized || normalized.length > 512) {
    throw new UniversalBrokerError("AUTHENTICATION_FAILED", "A stable artifact owner fingerprint is required.");
  }
  return normalized;
}

function sanitizeFilename(value: string): string {
  const sanitized = basename(value).replace(/[\u0000-\u001f\u007f]/g, "_");
  return sanitized || "artifact.bin";
}

function contentLength(response: Response): number | undefined {
  const raw = response.headers.get("content-length");
  if (!raw) return undefined;
  const parsed = Number(raw);
  return Number.isSafeInteger(parsed) && parsed >= 0 ? parsed : undefined;
}

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

function isNodeError(error: unknown, code: string): error is NodeJS.ErrnoException {
  return error instanceof Error && (error as NodeJS.ErrnoException).code === code;
}

function normalizeArtifactPathPrefix(value: string | undefined): string {
  const prefix = value?.trim() || "/artifacts-next";
  if (!prefix.startsWith("/") || prefix.includes("?") || prefix.includes("#")) {
    throw new UniversalBrokerError("PRECONDITION_FAILED", `Invalid artifact HTTP path prefix: ${prefix}`);
  }
  return prefix.length > 1 ? prefix.replace(/\/+$/, "") : prefix;
}

function mapCatalogError(error: unknown): UniversalBrokerError {
  if (!(error instanceof ArtifactCatalogError)) {
    return new UniversalBrokerError("STATE_CORRUPTED", "Artifact catalog operation failed.", {
      evidence: { error: errorMessage(error) },
    });
  }
  if (error.reason === "ARTIFACT_QUOTA_EXCEEDED") {
    return new UniversalBrokerError("RESOURCE_QUOTA_EXCEEDED", error.message, {
      evidence: error.evidence,
    });
  }
  return new UniversalBrokerError("STATE_CORRUPTED", "Artifact catalog is unavailable or inconsistent.", {
    evidence: { catalogReason: error.reason, ...error.evidence },
  });
}
