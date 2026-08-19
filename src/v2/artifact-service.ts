import {
  createHash,
  randomBytes,
  randomUUID,
  timingSafeEqual,
} from "node:crypto";
import { constants as fsConstants, createReadStream, createWriteStream } from "node:fs";
import {
  access,
  chmod,
  copyFile,
  link,
  lstat,
  mkdir,
  mkdtemp,
  open,
  readFile,
  rm,
  stat,
  unlink,
} from "node:fs/promises";
import { basename, dirname, join } from "node:path";
import { Readable } from "node:stream";
import { pipeline } from "node:stream/promises";
import type { Request, Response as ExpressResponse } from "express";
import { ArtifactError } from "../artifact-error.js";
import {
  IncomingArtifactAdapterRegistry,
  type IncomingArtifactAdapter,
} from "../incoming-artifacts.js";
import { UniversalBrokerError } from "./errors.js";
import type { UniversalFilesystemService } from "./filesystem.js";
import type { CapabilityCallContext } from "./capability-call-context.js";

const DEFAULT_MAXIMUM_ENTRIES = 256;
const DEFAULT_MAXIMUM_TOTAL_BYTES = 2 * 1024 * 1024 * 1024;
const DEFAULT_MAXIMUM_ARTIFACT_BYTES = 2 * 1024 * 1024 * 1024;
const DEFAULT_TTL_MS = 24 * 60 * 60_000;
const MAXIMUM_TTL_MS = 24 * 60 * 60_000;
const DOWNLOAD_REDIRECT_LIMIT = 5;
const DOWNLOAD_TIMEOUT_MS = 60_000;
const DEFAULT_RESOURCE_READ_BYTES = 1024 * 1024;
const DEFAULT_OWNER_FINGERPRINT = "devspace-single-owner";

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

interface ArtifactRecord {
  artifactId: string;
  token: string;
  ownerFingerprint: string;
  objectSha256: string;
  objectPath: string;
  name: string;
  mimeType: string;
  size: number;
  sha256: string;
  source: string;
  destination?: string;
  state: "AVAILABLE" | "EXPIRED";
  createdAt: number;
  expiresAt: number;
}

interface ContentObject {
  path: string;
  sha256: string;
  size: number;
  references: number;
}

interface CapacityReservation {
  reservationId: string;
  ownerFingerprint: string;
  entryReserved: boolean;
  bytesReserved: number;
  active: boolean;
  bytesCommitted: boolean;
  objectSha256?: string;
}

export interface UniversalArtifactServiceOptions {
  baseUrl?: string | (() => string);
  httpPathPrefix?: string;
  stagingRoot: string;
  incomingAdapters?: readonly IncomingArtifactAdapter[];
  maximumEntries?: number;
  maximumTotalBytes?: number;
  maximumArtifactBytes?: number;
  ttlMs?: number;
  fetch?: typeof fetch;
  now?: () => number;
  defaultOwnerFingerprint?: string;
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
  private readonly records = new Map<string, ArtifactRecord>();
  private readonly objects = new Map<string, ContentObject>();
  private readonly reservations = new Map<string, CapacityReservation>();
  private totalBytes = 0;
  private reservedBytes = 0;
  private reservedEntries = 0;
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
  }

  async execute(
    input: UniversalArtifactInput,
    context?: ArtifactOwnerContext,
  ): Promise<Record<string, unknown>> {
    this.assertOpen();
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
  }

  /** Resolve a canonical owner-bound resource handle for MCP resource wiring. */
  async readResource(
    resourceUri: string,
    context: ArtifactOwnerContext,
    offset = 0,
    maximumBytes = DEFAULT_RESOURCE_READ_BYTES,
  ): Promise<Record<string, unknown>> {
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
  }

  async handleHttp(
    req: Request,
    res: ExpressResponse,
    context?: ArtifactOwnerContext,
  ): Promise<void> {
    try {
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
    for (const reservation of [...this.reservations.values()]) {
      await this.abortReservation(reservation);
    }
    for (const id of [...this.records.keys()]) await this.deleteRecord(id);
  }

  async cleanupExpired(): Promise<Record<string, unknown>> {
    const before = this.records.size;
    await this.pruneExpired();
    return {
      removed: before - this.records.size,
      remaining: this.records.size,
      objects: this.objects.size,
      totalBytes: this.totalBytes,
    };
  }

  stats(): Record<string, unknown> {
    return {
      artifacts: this.records.size,
      objects: this.objects.size,
      totalBytes: this.totalBytes,
      reservations: this.reservations.size,
      reservedEntries: this.reservedEntries,
      reservedBytes: this.reservedBytes,
      maximumEntries: this.maximumEntries,
      maximumTotalBytes: this.maximumTotalBytes,
      maximumArtifactBytes: this.maximumArtifactBytes,
      ttlMs: this.ttlMs,
    };
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
      const record = this.commitRecord(reservation, object, {
        name: staged.name,
        mimeType: staged.mimeType,
        source: staged.sourceKind,
        destination: destinationPath,
        ttlMs: this.requestTtlMs(input.ttlSeconds),
      });
      return {
        operation: "receive",
        ...(destinationPath ? { target: optionalString(input.destination, "target") ?? "local", path: destinationPath } : {}),
        artifactId: record.artifactId,
        resourceUri: canonicalArtifactResourceUri(record.artifactId),
        ...(this.downloadUrl(record) ? { downloadUrl: this.downloadUrl(record) } : {}),
        resourceName: record.name,
        mimeType: record.mimeType,
        size: record.size,
        sha256: record.sha256,
        sourceKind: staged.sourceKind,
        deduplicated: object.references > 1,
        ...(published ? { published } : {}),
        expiresAt: new Date(record.expiresAt).toISOString(),
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
      const record = this.commitRecord(reservation, object, {
        name: optionalString(source, "name") ?? (basename(path) || "artifact.bin"),
        mimeType: optionalString(source, "mimeType") ?? "application/octet-stream",
        source: `${optionalString(source, "target") ?? "local"}:${path}`,
        ttlMs: this.requestTtlMs(input.ttlSeconds),
      });
      return {
        operation: "publish",
        source: { target: optionalString(source, "target") ?? "local", path },
        artifactId: record.artifactId,
        resourceUri: canonicalArtifactResourceUri(record.artifactId),
        ...(this.downloadUrl(record) ? { downloadUrl: this.downloadUrl(record) } : {}),
        resourceName: record.name,
        mimeType: record.mimeType,
        size: record.size,
        sha256: record.sha256,
        expiresAt: new Date(record.expiresAt).toISOString(),
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
    const reservation = this.reserveCapacity(
      ownerFingerprint,
      maximumBytes,
      optionalNumber(input.source, "size"),
      true,
    );
    let directory: string | undefined;
    try {
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
      const record = this.commitRecord(reservation, object, {
        name: optionalString(input.destination, "name") ?? basename(destinationPath) ?? "artifact.bin",
        mimeType: optionalString(input.source, "mimeType") ?? "application/octet-stream",
        source: `${optionalString(input.source, "target") ?? "local"}:${sourcePath}`,
        destination: `${optionalString(input.destination, "target") ?? "local"}:${destinationPath}`,
        ttlMs: this.requestTtlMs(input.ttlSeconds),
      });
      return {
        operation: "copy",
        source: { target: optionalString(input.source, "target") ?? "local", path: sourcePath },
        destination: { target: optionalString(input.destination, "target") ?? "local", path: destinationPath },
        artifactId: record.artifactId,
        resourceUri: canonicalArtifactResourceUri(record.artifactId),
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

  /** Synchronous capacity fencing happens before any adapter open, fetch, or source file open. */
  private reserveCapacity(
    ownerFingerprint: string,
    requestedMaximumBytes: number,
    declaredSize: number | undefined,
    reserveEntry: boolean,
  ): CapacityReservation {
    if (reserveEntry && this.records.size + this.reservedEntries >= this.maximumEntries) {
      throw new UniversalBrokerError(
        "RESOURCE_QUOTA_EXCEEDED",
        "Artifact record quota is full; live records are never evicted.",
        { evidence: { maximumEntries: this.maximumEntries } },
      );
    }
    if (declaredSize !== undefined && declaredSize > requestedMaximumBytes) {
      throw new UniversalBrokerError("RESOURCE_QUOTA_EXCEEDED", "Artifact exceeds maxBytes before source open.");
    }
    const available = this.maximumTotalBytes - this.totalBytes - this.reservedBytes;
    const bytesReserved = declaredSize ?? Math.min(requestedMaximumBytes, Math.max(available, 0));
    if (bytesReserved > available || (bytesReserved === 0 && declaredSize !== 0)) {
      throw new UniversalBrokerError(
        "RESOURCE_QUOTA_EXCEEDED",
        "Artifact byte quota is full before source open.",
        { evidence: { availableBytes: Math.max(available, 0), requestedMaximumBytes, declaredSize } },
      );
    }
    const reservation: CapacityReservation = {
      reservationId: randomUUID(),
      ownerFingerprint,
      entryReserved: reserveEntry,
      bytesReserved,
      active: true,
      bytesCommitted: false,
    };
    this.reservations.set(reservation.reservationId, reservation);
    this.reservedBytes += bytesReserved;
    if (reserveEntry) this.reservedEntries += 1;
    return reservation;
  }

  private async commitContentObject(
    stagedPath: string,
    size: number,
    sha256: string,
    reservation: CapacityReservation,
  ): Promise<ContentObject> {
    this.assertReservation(reservation);
    if (size > reservation.bytesReserved) {
      throw new UniversalBrokerError(
        "RESOURCE_QUOTA_EXCEEDED",
        "Artifact bytes exceeded the synchronously reserved capacity.",
        { evidence: { size, reservedBytes: reservation.bytesReserved } },
      );
    }
    await verifyFile(stagedPath, size, sha256);
    const objectDirectory = join(this.options.stagingRoot, "objects", "sha256", sha256.slice(0, 2));
    const objectPath = join(objectDirectory, sha256);
    await mkdir(objectDirectory, { recursive: true, mode: 0o700 });
    let object = this.objects.get(sha256);
    if (object) {
      await verifyFile(object.path, size, sha256);
    } else {
      const existing = await optionalLstat(objectPath);
      if (existing) {
        await verifyFile(objectPath, size, sha256);
      } else {
        await this.publishCasObject(stagedPath, objectPath, size, sha256);
      }
      object = { path: objectPath, sha256, size, references: 0 };
      this.objects.set(sha256, object);
      this.totalBytes += size;
    }
    this.reservedBytes -= reservation.bytesReserved;
    reservation.bytesCommitted = true;
    reservation.objectSha256 = sha256;
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
      name: string;
      mimeType: string;
      source: string;
      destination?: string;
      ttlMs: number;
    },
  ): ArtifactRecord {
    this.assertReservation(reservation);
    if (!reservation.entryReserved || reservation.objectSha256 !== object.sha256) {
      throw new UniversalBrokerError("STATE_CORRUPTED", "Artifact reservation cannot commit this object.");
    }
    const now = this.now();
    const record: ArtifactRecord = {
      artifactId: randomUUID(),
      token: randomBytes(32).toString("base64url"),
      ownerFingerprint: reservation.ownerFingerprint,
      objectSha256: object.sha256,
      objectPath: object.path,
      name: sanitizeFilename(input.name),
      mimeType: input.mimeType,
      size: object.size,
      sha256: object.sha256,
      source: input.source,
      destination: input.destination,
      state: "AVAILABLE",
      createdAt: now,
      expiresAt: now + input.ttlMs,
    };
    object.references += 1;
    this.records.set(record.artifactId, record);
    this.reservedEntries -= 1;
    reservation.entryReserved = false;
    reservation.active = false;
    this.reservations.delete(reservation.reservationId);
    return record;
  }

  private async abortReservation(reservation: CapacityReservation): Promise<void> {
    if (!reservation.active) return;
    if (!reservation.bytesCommitted) this.reservedBytes -= reservation.bytesReserved;
    if (reservation.entryReserved) this.reservedEntries -= 1;
    reservation.active = false;
    this.reservations.delete(reservation.reservationId);
    if (reservation.objectSha256) await this.deleteObjectIfUnreferenced(reservation.objectSha256);
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
    const record = this.records.get(artifactId);
    if (!record || record.state !== "AVAILABLE") {
      throw new UniversalBrokerError("PATH_NOT_FOUND", "Artifact is unknown or expired.");
    }
    if (ownerFingerprint && record.ownerFingerprint !== ownerFingerprint) {
      throw new UniversalBrokerError(
        "AUTHORITY_PRINCIPAL_MISMATCH",
        "Artifact belongs to a different authenticated principal.",
      );
    }
    if (token && !sameToken(record.token, token)) {
      throw new UniversalBrokerError("PATH_NOT_FOUND", "Artifact capability is invalid.");
    }
    await verifyFile(record.objectPath, record.size, record.sha256);
    return record;
  }

  private async pruneExpired(): Promise<void> {
    const now = this.now();
    const expired = [...this.records.values()]
      .filter((record) => record.expiresAt <= now)
      .map((record) => record.artifactId);
    for (const artifactId of expired) await this.deleteRecord(artifactId);
  }

  private async deleteRecord(artifactId: string): Promise<void> {
    const record = this.records.get(artifactId);
    if (!record) return;
    record.state = "EXPIRED";
    this.records.delete(artifactId);
    const object = this.objects.get(record.objectSha256);
    if (object) object.references = Math.max(0, object.references - 1);
    await this.deleteObjectIfUnreferenced(record.objectSha256);
  }

  private async deleteObjectIfUnreferenced(sha256: string): Promise<void> {
    const object = this.objects.get(sha256);
    if (!object || object.references > 0) return;
    this.objects.delete(sha256);
    this.totalBytes -= object.size;
    await unlink(object.path).catch(() => undefined);
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

  private downloadUrl(record: ArtifactRecord): string | undefined {
    const configured = typeof this.options.baseUrl === "function"
      ? this.options.baseUrl()
      : this.options.baseUrl;
    if (!configured) return undefined;
    return `${configured.replace(/\/+$/, "")}${this.httpPathPrefix}/${record.artifactId}?token=${encodeURIComponent(record.token)}`;
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
    if (!reservation.active || this.reservations.get(reservation.reservationId) !== reservation) {
      throw new UniversalBrokerError("STATE_CORRUPTED", "Artifact reservation is no longer active.");
    }
  }

  private assertOpen(): void {
    if (this.closed) throw new UniversalBrokerError("TRANSPORT_UNAVAILABLE", "Artifact service is closed.");
  }
}

export function canonicalArtifactResourceUri(artifactId: string): string {
  if (!/^[0-9a-f-]{36}$/iu.test(artifactId)) {
    throw new UniversalBrokerError("PRECONDITION_FAILED", "Artifact ID is invalid.");
  }
  return `devspace://artifact/${artifactId}`;
}

function parseArtifactResourceUri(resourceUri: string): string {
  let parsed: URL;
  try {
    parsed = new URL(resourceUri);
  } catch {
    throw new UniversalBrokerError("PRECONDITION_FAILED", "Artifact resource URI is invalid.");
  }
  const artifactId = parsed.pathname.replace(/^\//u, "");
  if (parsed.protocol !== "devspace:" || parsed.hostname !== "artifact" || parsed.search || parsed.hash) {
    throw new UniversalBrokerError("PRECONDITION_FAILED", "Artifact resource URI is not canonical.");
  }
  canonicalArtifactResourceUri(artifactId);
  return artifactId;
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

function sameToken(left: string, right: string): boolean {
  const leftBuffer = Buffer.from(left);
  const rightBuffer = Buffer.from(right);
  return leftBuffer.length === rightBuffer.length && timingSafeEqual(leftBuffer, rightBuffer);
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
