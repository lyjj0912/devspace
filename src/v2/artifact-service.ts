import {
  createHash,
  randomBytes,
  randomUUID,
  timingSafeEqual,
} from "node:crypto";
import { createReadStream, createWriteStream } from "node:fs";
import {
  access,
  mkdir,
  mkdtemp,
  rm,
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

const DEFAULT_MAXIMUM_ENTRIES = 64;
const DEFAULT_MAXIMUM_TOTAL_BYTES = 2 * 1024 * 1024 * 1024;
const DEFAULT_MAXIMUM_ARTIFACT_BYTES = 1024 * 1024 * 1024;
const DEFAULT_TTL_MS = 15 * 60_000;
const MAXIMUM_TTL_MS = 24 * 60 * 60_000;
const DOWNLOAD_REDIRECT_LIMIT = 5;
const DOWNLOAD_TIMEOUT_MS = 60_000;

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

interface ArtifactRecord {
  artifactId: string;
  token: string;
  path: string;
  name: string;
  mimeType: string;
  size: number;
  sha256: string;
  createdAt: number;
  expiresAt: number;
  lastUsedAt: number;
  claimed: boolean;
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
  private readonly records = new Map<string, ArtifactRecord>();
  private totalBytes = 0;
  private closed = false;

  constructor(
    private readonly filesystem: UniversalFilesystemService,
    private readonly options: UniversalArtifactServiceOptions,
  ) {
    this.incoming = new IncomingArtifactAdapterRegistry(options.incomingAdapters ?? []);
    this.maximumEntries = boundedInteger(
      options.maximumEntries,
      DEFAULT_MAXIMUM_ENTRIES,
      1,
      10_000,
      "maximumEntries",
    );
    this.maximumTotalBytes = boundedInteger(
      options.maximumTotalBytes,
      DEFAULT_MAXIMUM_TOTAL_BYTES,
      1,
      Number.MAX_SAFE_INTEGER,
      "maximumTotalBytes",
    );
    this.maximumArtifactBytes = boundedInteger(
      options.maximumArtifactBytes,
      DEFAULT_MAXIMUM_ARTIFACT_BYTES,
      1,
      Number.MAX_SAFE_INTEGER,
      "maximumArtifactBytes",
    );
    this.ttlMs = boundedInteger(
      options.ttlMs,
      DEFAULT_TTL_MS,
      1_000,
      MAXIMUM_TTL_MS,
      "ttlMs",
    );
    this.httpPathPrefix = normalizeArtifactPathPrefix(options.httpPathPrefix);
    this.fetcher = options.fetch ?? globalThis.fetch;
    this.now = options.now ?? Date.now;
  }

  async execute(input: UniversalArtifactInput): Promise<Record<string, unknown>> {
    this.assertOpen();
    await this.pruneExpired();
    switch (input.operation) {
      case "receive":
        return this.receive(input);
      case "publish":
        return this.publish(input);
      case "copy":
        return this.copy(input);
    }
  }

  async handleHttp(req: Request, res: ExpressResponse): Promise<void> {
    let record: ArtifactRecord | undefined;
    let finalized = false;
    const finalize = async () => {
      if (finalized || !record || req.method === "HEAD") return;
      finalized = true;
      await this.deleteRecord(record.artifactId);
    };
    try {
      const artifactId = typeof req.params.artifactId === "string"
        ? req.params.artifactId
        : req.params.artifactId?.[0];
      const token = typeof req.query.token === "string" ? req.query.token : undefined;
      if (!artifactId || !token) {
        res.status(400).send("Missing artifact capability.");
        return;
      }
      record = await this.resolveRecord(artifactId, token, req.method !== "HEAD");
      res.setHeader("Content-Type", record.mimeType);
      res.setHeader("Content-Length", String(record.size));
      res.setHeader(
        "Content-Disposition",
        `attachment; filename*=UTF-8''${encodeURIComponent(record.name)}`,
      );
      res.setHeader("Cache-Control", "private, no-store");
      res.setHeader("X-Content-Type-Options", "nosniff");
      res.setHeader("Content-Security-Policy", "default-src 'none'; sandbox");
      if (req.method === "HEAD") {
        res.status(200).end();
        return;
      }
      res.once("finish", () => void finalize());
      res.once("close", () => void finalize());
      const stream = createReadStream(record.path);
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
      res.status(status).send("Artifact capability is invalid, consumed, or expired.");
    }
  }

  async close(): Promise<void> {
    if (this.closed) return;
    this.closed = true;
    const ids = [...this.records.keys()];
    await Promise.all(ids.map((id) => this.deleteRecord(id)));
  }

  async cleanupExpired(): Promise<Record<string, unknown>> {
    const before = this.records.size;
    await this.pruneExpired();
    return {
      removed: before - this.records.size,
      remaining: this.records.size,
      totalBytes: this.totalBytes,
    };
  }

  stats(): Record<string, unknown> {
    return {
      artifacts: this.records.size,
      totalBytes: this.totalBytes,
      maximumEntries: this.maximumEntries,
      maximumTotalBytes: this.maximumTotalBytes,
      maximumArtifactBytes: this.maximumArtifactBytes,
      ttlMs: this.ttlMs,
    };
  }

  private async receive(input: UniversalArtifactInput): Promise<Record<string, unknown>> {
    const destination = input.destination;
    const path = requiredString(destination, "path", "artifact.receive destination.path is required.");
    const target = optionalString(destination, "target");
    const contextId = optionalString(destination, "contextId");
    const maximumBytes = this.requestMaximumBytes(input.maxBytes);
    const staged = await this.stageIncoming(input.source, maximumBytes);
    try {
      const published = await this.filesystem.importLocalFile({
        target,
        contextId,
        path,
        localPath: staged.path,
        overwrite: input.overwrite === true,
        expectedSha256: optionalString(input.source, "destinationExpectedSha256"),
      });
      return {
        operation: "receive",
        target: target ?? "local",
        path,
        name: staged.name,
        mimeType: staged.mimeType,
        size: staged.size,
        sha256: staged.sha256,
        sourceKind: staged.sourceKind,
        published,
      };
    } finally {
      await rm(staged.directory, { recursive: true, force: true });
    }
  }

  private async publish(input: UniversalArtifactInput): Promise<Record<string, unknown>> {
    const source = input.source;
    const path = requiredString(source, "path", "artifact.publish source.path is required.");
    const target = optionalString(source, "target");
    const contextId = optionalString(source, "contextId");
    const directory = await this.createStagingDirectory("publish");
    const stagedPath = join(directory, "payload");
    try {
      const exported = await this.filesystem.exportToLocalFile({
        target,
        contextId,
        path,
        localPath: stagedPath,
      });
      this.assertSize(exported.size, this.requestMaximumBytes(input.maxBytes));
      const record = await this.registerRecord({
        path: stagedPath,
        name: optionalString(source, "name") ?? (basename(path) || "artifact.bin"),
        mimeType: optionalString(source, "mimeType") ?? "application/octet-stream",
        size: exported.size,
        sha256: exported.sha256,
        ttlMs: this.requestTtlMs(input.ttlSeconds),
      });
      return {
        operation: "publish",
        source: { target: target ?? "local", path },
        artifactId: record.artifactId,
        resourceUri: this.resourceUri(record),
        resourceName: record.name,
        mimeType: record.mimeType,
        size: record.size,
        sha256: record.sha256,
        expiresAt: new Date(record.expiresAt).toISOString(),
        oneTime: true,
      };
    } catch (error) {
      await rm(directory, { recursive: true, force: true });
      throw error;
    }
  }

  private async copy(input: UniversalArtifactInput): Promise<Record<string, unknown>> {
    const sourcePath = requiredString(input.source, "path", "artifact.copy source.path is required.");
    const sourceTarget = optionalString(input.source, "target");
    const sourceContextId = optionalString(input.source, "contextId");
    const destinationPath = requiredString(
      input.destination,
      "path",
      "artifact.copy destination.path is required.",
    );
    const destinationTarget = optionalString(input.destination, "target");
    const destinationContextId = optionalString(input.destination, "contextId");
    const directory = await this.createStagingDirectory("copy");
    const stagedPath = join(directory, "payload");
    try {
      const exported = await this.filesystem.exportToLocalFile({
        target: sourceTarget,
        contextId: sourceContextId,
        path: sourcePath,
        localPath: stagedPath,
      });
      this.assertSize(exported.size, this.requestMaximumBytes(input.maxBytes));
      const published = await this.filesystem.importLocalFile({
        target: destinationTarget,
        contextId: destinationContextId,
        path: destinationPath,
        localPath: stagedPath,
        overwrite: input.overwrite === true,
        expectedSha256: optionalString(input.destination, "expectedSha256"),
      });
      return {
        operation: "copy",
        source: {
          target: sourceTarget ?? "local",
          path: sourcePath,
        },
        destination: {
          target: destinationTarget ?? "local",
          path: destinationPath,
        },
        size: exported.size,
        sha256: exported.sha256,
        published,
      };
    } finally {
      await rm(directory, { recursive: true, force: true });
    }
  }

  private async stageIncoming(
    source: Record<string, unknown>,
    maximumBytes: number,
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
        const response = await fetchWithValidatedRedirects(
          this.fetcher,
          url,
          DOWNLOAD_TIMEOUT_MS,
        );
        if (!response.ok || !response.body) {
          throw new UniversalBrokerError(
            "TRANSPORT_UNAVAILABLE",
            `Artifact download failed with HTTP ${response.status}.`,
            { evidence: { status: response.status, origin: url.origin } },
          );
        }
        const responseLength = contentLength(response);
        name = optionalString(source, "name")
          ?? (basename(new URL(response.url || url.href).pathname) || "artifact.bin");
        mimeType = optionalString(source, "mimeType")
          ?? response.headers.get("content-type")?.split(";", 1)[0]?.trim()
          ?? "application/octet-stream";
        declaredSize = responseLength;
        stream = Readable.fromWeb(response.body as never);
        sourceKind = "url";
      }

      if (declaredSize !== undefined) this.assertSize(declaredSize, maximumBytes);
      const output = createWriteStream(path, { flags: "wx", mode: 0o600 });
      let bytes = 0;
      const digest = createHash("sha256");
      stream.on("data", (chunk: Buffer | string) => {
        const buffer = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
        bytes += buffer.byteLength;
        digest.update(buffer);
        if (bytes > maximumBytes) stream.destroy(new Error("artifact-size-limit"));
      });
      try {
        await pipeline(stream, output);
      } catch (error) {
        if (error instanceof Error && error.message === "artifact-size-limit") {
          throw new UniversalBrokerError(
            "RESOURCE_QUOTA_EXCEEDED",
            "Artifact stream exceeded the requested byte limit.",
            { evidence: { maximumBytes } },
          );
        }
        throw error;
      }
      if (declaredSize !== undefined && declaredSize !== bytes) {
        throw new UniversalBrokerError(
          "PRECONDITION_FAILED",
          "Artifact declared size did not match downloaded bytes.",
          { evidence: { declaredSize, actualSize: bytes } },
        );
      }
      const expectedSize = optionalNumber(source, "size");
      if (expectedSize !== undefined && expectedSize !== bytes) {
        throw new UniversalBrokerError("PRECONDITION_FAILED", "Artifact size precondition failed.");
      }
      const sha256 = digest.digest("hex");
      const expectedSha256 = optionalString(source, "sha256");
      if (expectedSha256 && expectedSha256.toLowerCase() !== sha256) {
        throw new UniversalBrokerError("PRECONDITION_FAILED", "Artifact SHA-256 precondition failed.");
      }
      return { directory, path, name, mimeType, size: bytes, sha256, sourceKind };
    } catch (error) {
      await rm(directory, { recursive: true, force: true });
      throw error;
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

  private assertSize(size: number, maximumBytes: number): void {
    if (size > maximumBytes) {
      throw new UniversalBrokerError(
        "RESOURCE_QUOTA_EXCEEDED",
        "Artifact exceeds the requested byte limit.",
        { evidence: { size, maximumBytes } },
      );
    }
  }

  private async registerRecord(input: {
    path: string;
    name: string;
    mimeType: string;
    size: number;
    sha256: string;
    ttlMs: number;
  }): Promise<ArtifactRecord> {
    await this.pruneExpired();
    while (
      this.records.size >= this.maximumEntries
      || this.totalBytes + input.size > this.maximumTotalBytes
    ) {
      const oldest = [...this.records.values()]
        .sort((left, right) => left.lastUsedAt - right.lastUsedAt)[0];
      if (!oldest) break;
      await this.deleteRecord(oldest.artifactId);
    }
    if (this.totalBytes + input.size > this.maximumTotalBytes) {
      throw new UniversalBrokerError(
        "RESOURCE_QUOTA_EXCEEDED",
        "Artifact store is at its total byte quota.",
      );
    }
    const now = this.now();
    const record: ArtifactRecord = {
      artifactId: randomUUID(),
      token: randomBytes(32).toString("base64url"),
      path: input.path,
      name: sanitizeFilename(input.name),
      mimeType: input.mimeType,
      size: input.size,
      sha256: input.sha256,
      createdAt: now,
      expiresAt: now + input.ttlMs,
      lastUsedAt: now,
      claimed: false,
    };
    this.records.set(record.artifactId, record);
    this.totalBytes += record.size;
    return record;
  }

  private async resolveRecord(
    artifactId: string,
    token: string,
    claim: boolean,
  ): Promise<ArtifactRecord> {
    await this.pruneExpired();
    const record = this.records.get(artifactId);
    if (!record || !sameToken(record.token, token) || (claim && record.claimed)) {
      throw new UniversalBrokerError(
        "PATH_NOT_FOUND",
        "Artifact capability is unknown, consumed, or expired.",
      );
    }
    await access(record.path);
    if (claim) record.claimed = true;
    record.lastUsedAt = this.now();
    return record;
  }

  private resourceUri(record: ArtifactRecord): string {
    const configured = typeof this.options.baseUrl === "function"
      ? this.options.baseUrl()
      : this.options.baseUrl;
    const query = `token=${encodeURIComponent(record.token)}`;
    return configured
      ? `${configured.replace(/\/+$/, "")}${this.httpPathPrefix}/${record.artifactId}?${query}`
      : `devspace://artifact/${record.artifactId}?${query}`;
  }

  private async pruneExpired(): Promise<void> {
    const now = this.now();
    const expired = [...this.records.values()]
      .filter((record) => record.expiresAt <= now)
      .map((record) => record.artifactId);
    await Promise.all(expired.map((id) => this.deleteRecord(id)));
  }

  private async deleteRecord(artifactId: string): Promise<void> {
    const record = this.records.get(artifactId);
    if (!record) return;
    this.records.delete(artifactId);
    this.totalBytes -= record.size;
    await rm(dirname(record.path), { recursive: true, force: true }).catch(() => undefined);
  }

  private assertOpen(): void {
    if (this.closed) {
      throw new UniversalBrokerError("TRANSPORT_UNAVAILABLE", "Artifact service is closed.");
    }
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
      response = await fetcher(current, {
        redirect: "manual",
        signal: AbortSignal.timeout(timeoutMs),
      });
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
      throw new UniversalBrokerError(
        "TRANSPORT_UNAVAILABLE",
        "Artifact redirect chain is invalid or too long.",
      );
    }
    current = new URL(location, current);
  }
  throw new UniversalBrokerError("TRANSPORT_UNAVAILABLE", "Artifact redirect limit exceeded.");
}

function validateDownloadUrl(url: URL): void {
  const loopback = ["localhost", "127.0.0.1", "::1", "[::1]"].includes(url.hostname);
  if (url.protocol !== "https:" && !(url.protocol === "http:" && loopback)) {
    throw new UniversalBrokerError(
      "PRECONDITION_FAILED",
      "Artifact URL must use HTTPS, except for loopback test sources.",
    );
  }
  if (url.username || url.password) {
    throw new UniversalBrokerError(
      "PRECONDITION_FAILED",
      "Artifact URL must not contain credentials.",
    );
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

function requiredString(
  record: Record<string, unknown> | undefined,
  key: string,
  message: string,
): string {
  const value = optionalString(record, key);
  if (!value) throw new UniversalBrokerError("PRECONDITION_FAILED", message);
  return value;
}

function optionalString(
  record: Record<string, unknown> | undefined,
  key: string,
): string | undefined {
  const value = record?.[key];
  if (value === undefined || value === null) return undefined;
  if (typeof value !== "string" || value.length === 0) {
    throw new UniversalBrokerError("PRECONDITION_FAILED", `${key} must be a non-empty string.`);
  }
  return value;
}

function optionalNumber(
  record: Record<string, unknown> | undefined,
  key: string,
): number | undefined {
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
    throw new UniversalBrokerError(
      "PRECONDITION_FAILED",
      `${field} must be an integer from ${minimum} through ${maximum}.`,
    );
  }
  return parsed;
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
  return leftBuffer.length === rightBuffer.length
    && timingSafeEqual(leftBuffer, rightBuffer);
}

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

function normalizeArtifactPathPrefix(value: string | undefined): string {
  const prefix = value?.trim() || "/artifacts-next";
  if (!prefix.startsWith("/") || prefix.includes("?") || prefix.includes("#")) {
    throw new UniversalBrokerError(
      "PRECONDITION_FAILED",
      `Invalid artifact HTTP path prefix: ${prefix}`,
    );
  }
  return prefix.length > 1 ? prefix.replace(/\/+$/, "") : prefix;
}
