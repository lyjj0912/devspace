import { spawn } from "node:child_process";
import { createHash, randomUUID } from "node:crypto";
import { constants as fsConstants, type Stats } from "node:fs";
import {
  copyFile,
  cp,
  lstat,
  mkdir,
  mkdtemp,
  open,
  readdir,
  readFile,
  readlink,
  realpath,
  rename,
  rm,
  stat,
  writeFile,
} from "node:fs/promises";
import { homedir, tmpdir } from "node:os";
import {
  basename,
  dirname,
  isAbsolute,
  join,
  posix,
  resolve,
  win32,
} from "node:path";
import { applyPatch, parsePatch } from "../apply-patch.js";
import { expandHomePath } from "../roots.js";
import {
  requireCapabilityCallContext,
  type CapabilityCallContext,
} from "./capability-call-context.js";
import type { ContextRegistry } from "./contexts.js";
import {
  CursorCapabilityError,
  cursorFailure,
  type CursorBinding,
  type SignedSnapshotCursorStore,
} from "./cursor-capability.js";
import type {
  UniversalExecutionPlane,
  UniversalProcessSnapshot,
} from "./execution.js";
import { UniversalBrokerError } from "./errors.js";
import {
  atomicCopyFile,
  atomicWriteBuffer,
  nodeAtomicFilesystemOperations,
  safeMoveFile,
  sha256File,
  type AtomicFilesystemOperations,
} from "./filesystem-atomic.js";
import { RecoverableFilesystemTrash } from "./filesystem-trash.js";
import {
  DurableFilesystemSync,
  type FilesystemSyncAuthorityBinding,
  type FilesystemSyncAdapter,
  type FilesystemSyncEntry,
  type FilesystemSyncRequest,
  type StoredSelectors,
  type SyncOperation,
  type TreeSnapshot,
} from "./filesystem-sync.js";
import { prepareSshControlPath } from "./ssh-control.js";
import {
  REMOTE_FILESYSTEM_HELPER_SOURCE,
  REMOTE_FILESYSTEM_RESULT_MARKER,
} from "./remote-filesystem-helper.js";
import {
  REMOTE_WINDOWS_FILESYSTEM_RESULT_MARKER,
  windowsFilesystemScript as buildWindowsFilesystemScript,
} from "./remote-windows-filesystem-helper.js";
import {
  assertTargetCapability,
  type TargetDefinition,
  type TargetRegistry,
} from "./targets.js";

const DEFAULT_READ_BYTES = 12_000;
const MAX_READ_BYTES = 1_000_000;
const DEFAULT_LIST_LIMIT = 100;
const MAX_LIST_LIMIT = 1_000;
const DEFAULT_SEARCH_LIMIT = 50;
const MAX_SEARCH_LIMIT = 500;
const MAX_SEARCH_FILE_BYTES = 2 * 1024 * 1024;
const MAX_SEARCH_FILES = 20_000;
const MAX_LIST_SNAPSHOT_ENTRIES = 100_000;
const REMOTE_LIST_PAGE_LIMIT = 1_000;
const MAX_DIRECT_REMOTE_WRITE_BYTES = 64 * 1024;
const DEFAULT_REMOTE_TIMEOUT_MS = 60_000;

const SEARCH_SKIPPED_DIRECTORIES = new Set([
  ".git",
  ".hg",
  ".svn",
  "node_modules",
  "dist",
  "build",
  ".next",
  ".cache",
]);

export type UniversalFilesystemOperation =
  | "stat"
  | "list"
  | "read"
  | "search"
  | "write"
  | "patch"
  | "mkdir"
  | "copy"
  | "move"
  | "remove"
  | "restore"
  | "hash"
  | "sync";

export interface UniversalFilesystemInput {
  operation: UniversalFilesystemOperation;
  target?: string;
  contextId?: string;
  path?: string;
  destination?: string;
  content?: string;
  patch?: string;
  query?: string;
  recursive?: boolean;
  overwrite?: boolean;
  expectedSha256?: string;
  disposition?: "trash" | "permanent";
  trashId?: string;
  /** Final-component behavior. Mutations default to reject; reads default to follow. */
  finalSymlink?: "follow" | "preserve" | "replace" | "reject";
  authorityId?: string;
  cursor?: string;
  /** Byte range offset for fs.read; never a pagination cursor. */
  offset?: number;
  limit?: number;
  sync?: FilesystemSyncRequest;
}

export interface UniversalFilesystemOptions {
  sshControlDir: string;
  sftpExecutable?: string;
  remoteTimeoutMs?: number;
  trashRoot?: string;
  atomicFilesystem?: AtomicFilesystemOperations;
  syncStatePath?: string;
  syncPlanTtlMs?: number;
  syncNow?: () => number;
  syncAdapter?: FilesystemSyncAdapter;
  cursorStore?: SignedSnapshotCursorStore;
  sftpPut?: (input: SftpTransferInput) => Promise<void>;
  sftpGet?: (input: SftpTransferInput) => Promise<void>;
}

interface SftpTransferInput {
  target: TargetDefinition;
  localPath: string;
  remotePath: string;
}

interface ResolvedFilesystemRequest {
  target: TargetDefinition;
  path?: string;
  destination?: string;
}

interface RemoteResponse {
  ok?: boolean;
  data?: unknown;
  code?: string;
  message?: string;
}

interface FilesystemListEntry {
  name: string;
  type: "directory" | "file" | "symlink" | "other";
}

interface FilesystemListSnapshot {
  resolvedPath: string;
  entries: FilesystemListEntry[];
  generation: string;
}

interface FilesystemSearchResult {
  path: string;
  line: number;
  text: string;
}

interface FilesystemSearchSnapshot {
  resolvedPath: string;
  results: FilesystemSearchResult[];
  visitedFiles: number;
  truncated: boolean;
  generation: string;
}

export class UniversalFilesystemService {
  private readonly trash: RecoverableFilesystemTrash;
  private syncService: DurableFilesystemSync | undefined;

  constructor(
    private readonly targets: TargetRegistry,
    private readonly contexts: ContextRegistry,
    private readonly execution: UniversalExecutionPlane,
    private readonly options: UniversalFilesystemOptions,
  ) {
    this.trash = new RecoverableFilesystemTrash(
      options.trashRoot ?? join(dirname(options.sshControlDir), "filesystem-trash"),
      options.atomicFilesystem ?? nodeAtomicFilesystemOperations,
    );
  }

  async execute(
    input: UniversalFilesystemInput,
    callContext?: CapabilityCallContext,
  ): Promise<Record<string, unknown>> {
    try {
      const resolved = await this.resolveRequest(input, callContext);
      if (resolved.target.transport === "ssh") {
        return await this.executeRemote(input, resolved, callContext);
      }
      return await this.executeLocal(input, resolved, callContext);
    } catch (error) {
      if (cursorFailure(error)) throw error;
      throw normalizeFilesystemError(error, input);
    }
  }

  async prepareSyncAuthorityBinding(
    input: UniversalFilesystemInput,
    callContext?: CapabilityCallContext,
  ): Promise<FilesystemSyncAuthorityBinding> {
    if (input.operation !== "sync" || input.sync?.phase !== "apply") {
      throw new UniversalBrokerError(
        "PRECONDITION_FAILED",
        "Filesystem sync authority binding requires fs.sync phase=apply.",
      );
    }
    const resolved = await this.resolveRequest(input, callContext);
    const owner = requireCapabilityCallContext(callContext);
    const requestedSource = requirePath(resolved.path, "fs.sync");
    const requestedDestination = requirePath(resolved.destination, "fs.sync destination");
    const sourceRoot = resolved.target.transport === "local"
      ? await resolveLocalFinalPath(requestedSource, "sync", input.finalSymlink)
      : requestedSource;
    const destinationRoot = resolved.target.transport === "local"
      ? await resolveLocalFinalPath(requestedDestination, "write", input.finalSymlink)
      : requestedDestination;
    const sync = resolved.target.transport === "local"
      ? this.localSyncService()
      : this.remoteSyncService(resolved.target, callContext);
    return sync.inspectApplyAuthorityBinding(input.sync, {
      ownerFingerprint: owner.principalKeyFingerprint,
      targetId: resolved.target.id,
      targetGeneration: resolved.target.generation,
      sourceRoot,
      destinationRoot,
      ...(resolved.target.transport === "ssh"
        ? { pathStyle: resolved.target.platform === "windows" ? "windows" : "posix" }
        : {}),
    });
  }

  /** Stage a local file into any configured filesystem target without putting it in tool text. */
  async importLocalFile(input: {
    target?: string;
    contextId?: string;
    path: string;
    localPath: string;
    overwrite?: boolean;
    expectedSha256?: string;
  }, callContext?: CapabilityCallContext): Promise<Record<string, unknown>> {
    const source = await requiredLstat(input.localPath);
    if (!source.isFile()) throw pathTypeError(input.localPath, "file");
    const resolved = await this.resolveRequest({
      operation: "write",
      target: input.target,
      contextId: input.contextId,
      path: input.path,
      overwrite: input.overwrite,
      expectedSha256: input.expectedSha256,
    }, callContext);
    if (resolved.target.transport === "local") {
      return publishLocalFile(
        requirePath(resolved.path, "artifact destination"),
        input.localPath,
        {
          overwrite: input.overwrite === true,
          expectedSha256: input.expectedSha256,
          filesystem: this.options.atomicFilesystem,
        },
      );
    }
    await assertCachedSftpCapability(this.targets, resolved.target);
    return this.publishRemoteFile(
      resolved.target,
      requirePath(resolved.path, "artifact destination"),
      input.localPath,
      {
        overwrite: input.overwrite === true,
        expectedSha256: input.expectedSha256,
      },
      callContext,
    );
  }

  /** Export a target file into an owner-only local staging path for artifact publication. */
  async exportToLocalFile(input: {
    target?: string;
    contextId?: string;
    path: string;
    localPath: string;
  }, callContext?: CapabilityCallContext): Promise<{ localPath: string; size: number; sha256: string }> {
    const resolved = await this.resolveRequest({
      operation: "read",
      target: input.target,
      contextId: input.contextId,
      path: input.path,
    }, callContext);
    await mkdir(dirname(input.localPath), { recursive: true, mode: 0o700 });
    if (resolved.target.transport === "local") {
      const sourcePath = requirePath(resolved.path, "artifact source");
      const source = await requiredLstat(sourcePath);
      if (!source.isFile()) throw pathTypeError(sourcePath, "file");
      await copyFile(sourcePath, input.localPath, fsConstants.COPYFILE_EXCL);
    } else {
      const remotePath = requirePath(resolved.path, "artifact source");
      await assertCachedSftpCapability(this.targets, resolved.target);
      const metadata = await this.remoteRequest(
        resolved.target,
        { op: "stat", path: remotePath },
        callContext,
      ) as { type?: string };
      if (metadata.type !== "file") throw pathTypeError(remotePath, "file");
      await this.sftpGet({
        target: resolved.target,
        localPath: input.localPath,
        remotePath,
      });
    }
    const metadata = await stat(input.localPath);
    return {
      localPath: input.localPath,
      size: metadata.size,
      sha256: await sha256File(input.localPath),
    };
  }

  private async executeLocal(
    input: UniversalFilesystemInput,
    resolved: ResolvedFilesystemRequest,
    callContext?: CapabilityCallContext,
  ): Promise<Record<string, unknown>> {
    const requestedPath = resolved.path;
    const path = requestedPath === undefined
      ? undefined
      : await resolveLocalFinalPath(requestedPath, input.operation, input.finalSymlink);
    const requestedDestination = resolved.destination;
    const destinationPath = requestedDestination === undefined
      ? undefined
      : await resolveLocalFinalPath(requestedDestination, "write", input.finalSymlink);
    const withPathIdentity = (result: Record<string, unknown>): Record<string, unknown> => ({
      ...result,
      ...(requestedPath ? {
        requestedPath,
        resolvedPath: path,
      } : {}),
    });
    switch (input.operation) {
      case "stat":
        return withPathIdentity(await localStat(requirePath(path, "fs.stat")));
      case "list":
        return withPathIdentity(await this.paginateLocalList(
          resolved.target,
          requirePath(path, "fs.list"),
          input,
          callContext,
        ));
      case "read":
        return withPathIdentity(await localRead(
          requirePath(path, "fs.read"),
          readOffset(input),
          boundedLimit(input.limit, DEFAULT_READ_BYTES, MAX_READ_BYTES),
        ));
      case "search":
        return withPathIdentity(await this.paginateLocalSearch(
          resolved.target,
          requirePath(path, "fs.search"),
          input,
          callContext,
        ));
      case "write":
        if (input.content === undefined) {
          throw new UniversalBrokerError("PRECONDITION_FAILED", "fs.write requires content.");
        }
        return withPathIdentity(await atomicLocalWrite(
          requirePath(path, "fs.write"),
          Buffer.from(input.content, "utf8"),
          {
            overwrite: input.overwrite === true,
            expectedSha256: input.expectedSha256,
            allowReplaceSymlink: input.finalSymlink === "replace",
            filesystem: this.options.atomicFilesystem,
          },
        ));
      case "patch":
        return localPatch(
          requirePath(path, "fs.patch"),
          requireText(input.patch, "fs.patch requires patch."),
          input.expectedSha256,
          this.options.atomicFilesystem,
        );
      case "mkdir":
        return localMkdir(requirePath(path, "fs.mkdir"), input.recursive === true);
      case "copy":
        return withPathIdentity(await localCopy(
          requirePath(path, "fs.copy"),
          requirePath(destinationPath, "fs.copy destination"),
          input.overwrite === true,
          input.recursive === true,
          this.options.atomicFilesystem,
          input.finalSymlink === "replace",
        ));
      case "move":
        return withPathIdentity(await localMove(
          requirePath(path, "fs.move"),
          requirePath(destinationPath, "fs.move destination"),
          input.overwrite === true,
          this.options.atomicFilesystem,
          input.finalSymlink === "replace",
        ));
      case "remove":
        return withPathIdentity(await localRemove(
          requirePath(path, "fs.remove"),
          input.disposition,
          input.recursive === true,
          this.trash,
        ));
      case "restore":
        return this.trash.restore({
          trashId: requireText(input.trashId, "fs.restore requires trashId."),
          destination: destinationPath ?? path,
          overwrite: input.overwrite === true,
        });
      case "hash":
        return withPathIdentity(await localHash(requirePath(path, "fs.hash")));
      case "sync":
        return withPathIdentity(await this.executeLocalSync(
          input,
          resolved.target,
          requirePath(path, "fs.sync"),
          requirePath(destinationPath, "fs.sync destination"),
          callContext,
        ));
    }
  }

  private async executeRemote(
    input: UniversalFilesystemInput,
    resolved: ResolvedFilesystemRequest,
    callContext?: CapabilityCallContext,
  ): Promise<Record<string, unknown>> {
    const target = resolved.target;
    const path = resolved.path;
    switch (input.operation) {
      case "stat":
        return asRecord(await this.remoteRequest(target, {
          op: "stat",
          path: requirePath(path, "fs.stat"),
        }, callContext));
      case "list":
        return this.paginateRemoteList(
          target,
          requirePath(path, "fs.list"),
          input,
          callContext,
        );
      case "read": {
        const result = asRecord(await this.remoteRequest(target, {
          op: "read",
          path: requirePath(path, "fs.read"),
          options: {
            offset: readOffset(input),
            maxBytes: boundedLimit(input.limit, DEFAULT_READ_BYTES, MAX_READ_BYTES),
          },
        }, callContext));
        const encoded = typeof result.contentBase64 === "string" ? result.contentBase64 : "";
        delete result.contentBase64;
        return presentBytes(result, Buffer.from(encoded, "base64"));
      }
      case "search":
        return this.paginateRemoteSearch(
          target,
          requirePath(path, "fs.search"),
          input,
          callContext,
        );
      case "write": {
        if (input.content === undefined) {
          throw new UniversalBrokerError("PRECONDITION_FAILED", "fs.write requires content.");
        }
        const content = Buffer.from(input.content, "utf8");
        const destination = requirePath(path, "fs.write");
        const options = {
          overwrite: input.overwrite === true,
          expectedSha256: input.expectedSha256,
          finalSymlink: input.finalSymlink ?? "reject",
        };
        if (content.byteLength <= MAX_DIRECT_REMOTE_WRITE_BYTES) {
          return asRecord(await this.remoteRequest(target, {
            op: "write_content",
            path: destination,
            contentBase64: content.toString("base64"),
            options,
          }, callContext));
        }
        await assertCachedSftpCapability(this.targets, target);
        const directory = await mkdtemp(join(tmpdir(), "devspace-v2-fs-write-"));
        const staged = join(directory, "payload");
        try {
          await writeFile(staged, content, { mode: 0o600 });
          return await this.publishRemoteFile(target, destination, staged, options, callContext);
        } finally {
          await rm(directory, { recursive: true, force: true });
        }
      }
      case "patch":
        await assertCachedSftpCapability(this.targets, target);
        return this.remotePatch(
          target,
          requirePath(path, "fs.patch"),
          requireText(input.patch, "fs.patch requires patch."),
          input.expectedSha256,
          callContext,
        );
      case "mkdir":
        return asRecord(await this.remoteRequest(target, {
          op: "mkdir",
          path: requirePath(path, "fs.mkdir"),
          options: { recursive: input.recursive === true },
        }, callContext));
      case "copy":
        return asRecord(await this.remoteRequest(target, {
          op: "copy",
          path: requirePath(path, "fs.copy"),
          destination: requirePath(resolved.destination, "fs.copy destination"),
          options: {
            overwrite: input.overwrite === true,
            recursive: input.recursive === true,
            finalSymlink: input.finalSymlink ?? "reject",
          },
        }, callContext));
      case "sync":
        return this.executeRemoteSync(
          input,
          target,
          requirePath(path, "fs.sync"),
          requirePath(resolved.destination, "fs.sync destination"),
          callContext,
        );
      case "move":
        return asRecord(await this.remoteRequest(target, {
          op: "move",
          path: requirePath(path, "fs.move"),
          destination: requirePath(resolved.destination, "fs.move destination"),
          options: {
            overwrite: input.overwrite === true,
            finalSymlink: input.finalSymlink ?? "reject",
            allowCrossDevice: true,
          },
        }, callContext));
      case "remove":
        return asRecord(await this.remoteRequest(target, {
          op: "remove",
          path: requirePath(path, "fs.remove"),
          options: {
            disposition: input.disposition ?? "trash",
            recursive: input.recursive === true,
            finalSymlink: input.finalSymlink ?? "preserve",
          },
        }, callContext));
      case "restore":
        return asRecord(await this.remoteRequest(target, {
          op: "restore",
          path: resolved.destination ?? resolved.path,
          trashId: requireText(input.trashId, "fs.restore requires trashId."),
          options: { overwrite: input.overwrite === true },
        }, callContext));
      case "hash":
        return asRecord(await this.remoteRequest(target, {
          op: "hash",
          path: requirePath(path, "fs.hash"),
        }, callContext));
    }
  }

  private async paginateLocalList(
    target: TargetDefinition,
    path: string,
    input: UniversalFilesystemInput,
    callContext?: CapabilityCallContext,
  ): Promise<Record<string, unknown>> {
    const owner = requireCapabilityCallContext(callContext);
    const store = this.requireCursorStore();
    const limit = paginationLimit(input.limit, DEFAULT_LIST_LIMIT, MAX_LIST_LIMIT);
    const snapshot = await localListSnapshot(path);
    const page = paginateSnapshotItems({
      store,
      cursor: input.cursor,
      limit,
      binding: filesystemCursorBinding({
        principalKeyFingerprint: owner.principalKeyFingerprint,
        target,
        resourceKind: "filesystem.list",
        resolvedPath: snapshot.resolvedPath,
        queryDigest: digestJson({ version: 1, operation: "list" }),
        snapshotGeneration: snapshot.generation,
      }),
      items: snapshot.entries,
    });
    return {
      path: snapshot.resolvedPath,
      entries: page.items,
      totalEntries: snapshot.entries.length,
      offset: page.offset,
      limit: page.limit,
      snapshotGeneration: snapshot.generation,
      snapshotDigest: page.snapshotDigest,
      snapshotExpiresAt: page.expiresAt,
      targetGeneration: target.generation,
      ...(page.nextCursor ? { nextCursor: page.nextCursor } : {}),
    };
  }

  private async paginateLocalSearch(
    target: TargetDefinition,
    path: string,
    input: UniversalFilesystemInput,
    callContext?: CapabilityCallContext,
  ): Promise<Record<string, unknown>> {
    const owner = requireCapabilityCallContext(callContext);
    const store = this.requireCursorStore();
    const query = requireText(input.query, "fs.search requires query.");
    const recursive = input.recursive !== false;
    const limit = paginationLimit(input.limit, DEFAULT_SEARCH_LIMIT, MAX_SEARCH_LIMIT);
    const snapshot = await localSearchSnapshot(path, query, recursive);
    const page = paginateSnapshotItems({
      store,
      cursor: input.cursor,
      limit,
      binding: filesystemCursorBinding({
        principalKeyFingerprint: owner.principalKeyFingerprint,
        target,
        resourceKind: "filesystem.search",
        resolvedPath: snapshot.resolvedPath,
        queryDigest: digestJson({
          version: 1,
          operation: "search",
          query,
          recursive,
          maximumFileBytes: MAX_SEARCH_FILE_BYTES,
          maximumFiles: MAX_SEARCH_FILES,
          maximumResults: MAX_SEARCH_LIMIT,
        }),
        snapshotGeneration: snapshot.generation,
      }),
      items: snapshot.results,
    });
    return {
      path: snapshot.resolvedPath,
      query,
      results: page.items,
      visitedFiles: snapshot.visitedFiles,
      offset: page.offset,
      limit: page.limit,
      truncated: snapshot.truncated || Boolean(page.nextCursor),
      boundedSnapshotTruncated: snapshot.truncated,
      snapshotGeneration: snapshot.generation,
      snapshotDigest: page.snapshotDigest,
      snapshotExpiresAt: page.expiresAt,
      targetGeneration: target.generation,
      ...(page.nextCursor ? { nextCursor: page.nextCursor } : {}),
    };
  }

  private async paginateRemoteList(
    target: TargetDefinition,
    path: string,
    input: UniversalFilesystemInput,
    callContext?: CapabilityCallContext,
  ): Promise<Record<string, unknown>> {
    const owner = requireCapabilityCallContext(callContext);
    const store = this.requireCursorStore();
    const limit = paginationLimit(input.limit, DEFAULT_LIST_LIMIT, MAX_LIST_LIMIT);
    const snapshot = await this.remoteListSnapshot(target, path, callContext);
    const page = paginateSnapshotItems({
      store,
      cursor: input.cursor,
      limit,
      binding: filesystemCursorBinding({
        principalKeyFingerprint: owner.principalKeyFingerprint,
        target,
        resourceKind: "filesystem.list",
        resolvedPath: snapshot.resolvedPath,
        queryDigest: digestJson({ version: 1, operation: "list" }),
        snapshotGeneration: snapshot.generation,
      }),
      items: snapshot.entries,
    });
    return {
      path: snapshot.resolvedPath,
      entries: page.items,
      totalEntries: snapshot.entries.length,
      offset: page.offset,
      limit: page.limit,
      snapshotGeneration: snapshot.generation,
      snapshotDigest: page.snapshotDigest,
      snapshotExpiresAt: page.expiresAt,
      targetGeneration: target.generation,
      ...(page.nextCursor ? { nextCursor: page.nextCursor } : {}),
    };
  }

  private async paginateRemoteSearch(
    target: TargetDefinition,
    path: string,
    input: UniversalFilesystemInput,
    callContext?: CapabilityCallContext,
  ): Promise<Record<string, unknown>> {
    const owner = requireCapabilityCallContext(callContext);
    const store = this.requireCursorStore();
    const query = requireText(input.query, "fs.search requires query.");
    const recursive = input.recursive !== false;
    const limit = paginationLimit(input.limit, DEFAULT_SEARCH_LIMIT, MAX_SEARCH_LIMIT);
    const snapshot = await this.remoteSearchSnapshot(
      target,
      path,
      query,
      recursive,
      callContext,
    );
    const page = paginateSnapshotItems({
      store,
      cursor: input.cursor,
      limit,
      binding: filesystemCursorBinding({
        principalKeyFingerprint: owner.principalKeyFingerprint,
        target,
        resourceKind: "filesystem.search",
        resolvedPath: snapshot.resolvedPath,
        queryDigest: digestJson({
          version: 1,
          operation: "search",
          query,
          recursive,
          maximumFileBytes: MAX_SEARCH_FILE_BYTES,
          maximumFiles: MAX_SEARCH_FILES,
          maximumResults: MAX_SEARCH_LIMIT,
        }),
        snapshotGeneration: snapshot.generation,
      }),
      items: snapshot.results,
    });
    return {
      path: snapshot.resolvedPath,
      query,
      results: page.items,
      visitedFiles: snapshot.visitedFiles,
      offset: page.offset,
      limit: page.limit,
      truncated: snapshot.truncated || Boolean(page.nextCursor),
      boundedSnapshotTruncated: snapshot.truncated,
      snapshotGeneration: snapshot.generation,
      snapshotDigest: page.snapshotDigest,
      snapshotExpiresAt: page.expiresAt,
      targetGeneration: target.generation,
      ...(page.nextCursor ? { nextCursor: page.nextCursor } : {}),
    };
  }

  private async remoteListSnapshot(
    target: TargetDefinition,
    path: string,
    callContext?: CapabilityCallContext,
  ): Promise<FilesystemListSnapshot> {
    const first = await this.remoteListSnapshotPass(target, path, callContext);
    const second = await this.remoteListSnapshotPass(target, path, callContext);
    if (first.generation !== second.generation || first.resolvedPath !== second.resolvedPath) {
      throw new CursorCapabilityError(
        "CURSOR_STALE",
        "Remote directory changed while its ordered pagination snapshot was captured.",
        { resourceKind: "filesystem.list", targetId: target.id },
      );
    }
    return second;
  }

  private async remoteListSnapshotPass(
    target: TargetDefinition,
    path: string,
    callContext?: CapabilityCallContext,
  ): Promise<FilesystemListSnapshot> {
    const entries: FilesystemListEntry[] = [];
    let expectedTotal: number | undefined;
    let resolvedPath: string | undefined;
    while (expectedTotal === undefined || entries.length < expectedTotal) {
      const result = asRecord(await this.remoteRequest(target, {
        op: "list",
        path,
        options: { offset: entries.length, limit: REMOTE_LIST_PAGE_LIMIT },
      }, callContext));
      const observedPath = requireTextField(result.path, "remote list path");
      if (resolvedPath !== undefined && resolvedPath !== observedPath) {
        throw remoteSnapshotChanged("Remote directory resolved path changed during capture.", target);
      }
      resolvedPath = observedPath;
      const total = requireBoundedCount(
        result.totalEntries,
        "remote list totalEntries",
        MAX_LIST_SNAPSHOT_ENTRIES,
        "RESOURCE_QUOTA_EXCEEDED",
      );
      if (expectedTotal !== undefined && expectedTotal !== total) {
        throw remoteSnapshotChanged("Remote directory entry count changed during capture.", target);
      }
      expectedTotal = total;
      const offset = requireBoundedCount(
        result.offset,
        "remote list offset",
        MAX_LIST_SNAPSHOT_ENTRIES,
      );
      if (offset !== entries.length) {
        throw remoteSnapshotChanged("Remote directory page offset changed during capture.", target);
      }
      const page = normalizeListEntries(result.entries, REMOTE_LIST_PAGE_LIMIT);
      if (page.length === 0 && entries.length < total) {
        throw remoteSnapshotChanged("Remote directory pagination stopped before the snapshot ended.", target);
      }
      entries.push(...page);
      if (entries.length > total || entries.length > MAX_LIST_SNAPSHOT_ENTRIES) {
        throw remoteSnapshotChanged("Remote directory pagination exceeded its declared size.", target);
      }
    }
    entries.sort((left, right) => compareText(left.name, right.name));
    for (let index = 1; index < entries.length; index++) {
      if (entries[index - 1]!.name === entries[index]!.name) {
        throw new UniversalBrokerError(
          "STATE_CORRUPTED",
          "Remote directory snapshot contains a duplicate entry name.",
          { evidence: { targetId: target.id } },
        );
      }
    }
    const normalizedPath = resolvedPath ?? path;
    return {
      resolvedPath: normalizedPath,
      entries,
      generation: digestJson({ version: 1, resolvedPath: normalizedPath, entries }),
    };
  }

  private async remoteSearchSnapshot(
    target: TargetDefinition,
    path: string,
    query: string,
    recursive: boolean,
    callContext?: CapabilityCallContext,
  ): Promise<FilesystemSearchSnapshot> {
    const scan = async (): Promise<FilesystemSearchSnapshot> => {
      const result = asRecord(await this.remoteRequest(target, {
        op: "search",
        path,
        query,
        options: {
          recursive,
          limit: MAX_SEARCH_LIMIT,
          maxFileBytes: MAX_SEARCH_FILE_BYTES,
        },
      }, callContext));
      const resolvedPath = requireTextField(result.path, "remote search path");
      const results = normalizeSearchResults(result.results, MAX_SEARCH_LIMIT)
        .sort(compareSearchResults);
      const visitedFiles = requireBoundedCount(
        result.visitedFiles,
        "remote search visitedFiles",
        MAX_SEARCH_FILES,
      );
      const truncated = result.truncated === true;
      return {
        resolvedPath,
        results,
        visitedFiles,
        truncated,
        generation: digestJson({
          version: 1,
          resolvedPath,
          query,
          recursive,
          results,
          visitedFiles,
          truncated,
        }),
      };
    };
    const first = await scan();
    const second = await scan();
    if (first.generation !== second.generation || first.resolvedPath !== second.resolvedPath) {
      throw new CursorCapabilityError(
        "CURSOR_STALE",
        "Remote search changed while its ordered pagination snapshot was captured.",
        { resourceKind: "filesystem.search", targetId: target.id },
      );
    }
    return second;
  }

  private requireCursorStore(): SignedSnapshotCursorStore {
    if (!this.options.cursorStore) {
      throw new UniversalBrokerError(
        "CAPABILITY_UNAVAILABLE",
        "Signed filesystem pagination is unavailable because no cursor store was configured.",
        { evidence: { providerDispatch: false } },
      );
    }
    return this.options.cursorStore;
  }

  private async executeLocalSync(
    input: UniversalFilesystemInput,
    target: TargetDefinition,
    sourceRoot: string,
    destinationRoot: string,
    callContext?: CapabilityCallContext,
  ): Promise<Record<string, unknown>> {
    const request = input.sync;
    if (!request) {
      throw new UniversalBrokerError(
        "PRECONDITION_FAILED",
        "fs.sync requires sync.phase=plan or sync.phase=apply.",
      );
    }
    const owner = requireCapabilityCallContext(callContext);
    return this.localSyncService().execute(request, {
      ownerFingerprint: owner.principalKeyFingerprint,
      targetId: target.id,
      targetGeneration: target.generation,
      sourceRoot,
      destinationRoot,
    });
  }

  private async executeRemoteSync(
    input: UniversalFilesystemInput,
    target: TargetDefinition,
    sourceRoot: string,
    destinationRoot: string,
    callContext?: CapabilityCallContext,
  ): Promise<Record<string, unknown>> {
    const request = input.sync;
    if (!request) {
      throw new UniversalBrokerError(
        "PRECONDITION_FAILED",
        "fs.sync requires sync.phase=plan or sync.phase=apply.",
      );
    }
    const owner = requireCapabilityCallContext(callContext);
    return this.remoteSyncService(target, callContext).execute(request, {
      ownerFingerprint: owner.principalKeyFingerprint,
      targetId: target.id,
      targetGeneration: target.generation,
      sourceRoot,
      destinationRoot,
      pathStyle: target.platform === "windows" ? "windows" : "posix",
    });
  }

  private localSyncService(): DurableFilesystemSync {
    this.syncService ??= new DurableFilesystemSync({
      storePath: this.options.syncStatePath
        ?? join(dirname(this.options.sshControlDir), "filesystem-sync", "sync.sqlite"),
      trash: this.trash,
      ...(this.options.syncPlanTtlMs === undefined
        ? {}
        : { planTtlMs: this.options.syncPlanTtlMs }),
      ...(this.options.syncNow ? { now: this.options.syncNow } : {}),
      ...(this.options.syncAdapter ? { adapter: this.options.syncAdapter } : {}),
    });
    return this.syncService;
  }

  private remoteSyncService(
    target: TargetDefinition,
    callContext?: CapabilityCallContext,
  ): DurableFilesystemSync {
    return new DurableFilesystemSync({
      storePath: this.options.syncStatePath
        ?? join(dirname(this.options.sshControlDir), "filesystem-sync", "sync.sqlite"),
      trash: this.trash,
      ...(this.options.syncPlanTtlMs === undefined
        ? {}
        : { planTtlMs: this.options.syncPlanTtlMs }),
      ...(this.options.syncNow ? { now: this.options.syncNow } : {}),
      adapter: this.remoteSyncAdapter(target, callContext),
    });
  }

  private remoteSyncAdapter(
    target: TargetDefinition,
    callContext?: CapabilityCallContext,
  ): FilesystemSyncAdapter {
    return {
      pathStyle: target.platform === "windows" ? "windows" : "posix",
      snapshotTree: (root, selectors, sourceRequired) => this.remoteSyncSnapshotTree(
        target,
        root,
        selectors,
        sourceRequired,
        callContext,
      ),
      applyOperation: (input) => this.remoteSyncApplyOperation(target, input, callContext),
      operationPostcondition: (destinationRoot, operation) => this.remoteSyncOperationPostcondition(
        target,
        destinationRoot,
        operation,
        callContext,
      ),
      operationPostreadbackDigest: (destinationRoot, operation) => this.remoteSyncOperationPostreadbackDigest(
        target,
        destinationRoot,
        operation,
        callContext,
      ),
      assertSourceEntry: (sourceRoot, operation) => this.remoteSyncAssertSourceEntry(
        target,
        sourceRoot,
        operation,
        callContext,
      ),
    };
  }

  private async remoteSyncSnapshotTree(
    target: TargetDefinition,
    root: string,
    selectors: StoredSelectors,
    sourceRequired: boolean,
    callContext?: CapabilityCallContext,
  ): Promise<TreeSnapshot> {
    const rootMetadata = await this.remoteSyncOptionalStat(target, root, callContext);
    if (!rootMetadata) {
      if (sourceRequired) {
        throw new UniversalBrokerError("PATH_NOT_FOUND", `Filesystem sync source was not found: ${root}`);
      }
      return syncTreeSnapshot("absent", []);
    }
    const rootType = remoteSyncEntryType(rootMetadata);
    if (rootType === "file") return syncTreeSnapshot(rootType, [await this.remoteSyncFileEntry(
      target,
      root,
      ".",
      rootMetadata,
      callContext,
    )]);
    if (rootType === "symlink") {
      const linkTarget = typeof rootMetadata.linkTarget === "string" ? rootMetadata.linkTarget : undefined;
      if (linkTarget === undefined) throw remoteSyncUnsupported(target, root, "symlink");
      return syncTreeSnapshot(rootType, [{ path: ".", type: rootType, linkTarget }]);
    }
    if (rootType !== "directory") return syncTreeSnapshot("other", []);

    const entries: FilesystemSyncEntry[] = [];
    const walk = async (directory: string, relativeDirectory: string): Promise<void> => {
      const children = await this.remoteSyncListAll(target, directory, callContext);
      for (const child of children) {
        const relativePath = relativeDirectory ? `${relativeDirectory}/${child.name}` : child.name;
        if (syncMatchesAny(relativePath, selectors.exclude, child.type === "directory")) continue;
        const absolutePath = remoteTreePath(target, directory, child.name);
        if (child.type === "directory") {
          entries.push({ path: relativePath, type: "directory" });
          if (entries.length > MAX_LIST_SNAPSHOT_ENTRIES) throw remoteSyncEntryQuota(target, root);
          await walk(absolutePath, relativePath);
          continue;
        }
        if (selectors.include.length > 0 && !syncMatchesAny(relativePath, selectors.include, false)) continue;
        if (child.type === "file") {
          const metadata = await this.remoteSyncRequiredStat(target, absolutePath, callContext);
          entries.push(await this.remoteSyncFileEntry(target, absolutePath, relativePath, metadata, callContext));
        } else if (child.type === "symlink") {
          const metadata = await this.remoteSyncRequiredStat(target, absolutePath, callContext);
          const linkTarget = typeof metadata.linkTarget === "string" ? metadata.linkTarget : undefined;
          if (linkTarget === undefined) throw remoteSyncUnsupported(target, absolutePath, "symlink");
          entries.push({ path: relativePath, type: "symlink", linkTarget });
        } else {
          throw remoteSyncUnsupported(target, absolutePath, child.type);
        }
        if (entries.length > MAX_LIST_SNAPSHOT_ENTRIES) throw remoteSyncEntryQuota(target, root);
      }
    };
    await walk(root, "");
    return syncTreeSnapshot(
      "directory",
      selectors.include.length === 0 ? entries : retainSyncIncludedAncestors(entries),
    );
  }

  private async remoteSyncApplyOperation(
    target: TargetDefinition,
    input: {
      planId: string;
      sourceRoot: string;
      destinationRoot: string;
    operation: SyncOperation;
    persistPartialResult?: (result: Record<string, unknown>) => void;
  },
    callContext?: CapabilityCallContext,
  ): Promise<Record<string, unknown>> {
    const { planId, sourceRoot, destinationRoot, operation } = input;
    const sourcePath = operation.path === "." ? sourceRoot : remoteTreePath(target, sourceRoot, operation.path);
    const destinationPath = operation.path === "."
      ? destinationRoot
      : remoteTreePath(target, destinationRoot, operation.path);
    switch (operation.kind) {
      case "CREATE_ROOT":
        await this.remoteRequest(target, {
          op: "mkdir",
          path: destinationRoot,
          options: { recursive: true },
        }, callContext);
        return { createdRoot: true };
      case "COPY_DIRECTORY":
        await this.remoteRequest(target, {
          op: "mkdir",
          path: destinationPath,
          options: { recursive: false },
        }, callContext);
        return { createdDirectory: operation.path };
      case "COPY_FILE": {
        const copied = asRecord(await this.remoteRequest(target, {
          op: "copy",
          path: sourcePath,
          destination: destinationPath,
          options: { overwrite: false, createParents: true, finalSymlink: "reject" },
        }, callContext));
        return { copied: operation.path, sha256: copied.sha256 ?? operation.source?.sha256 };
      }
      case "UPDATE_FILE": {
        const expectedSha256 = operation.destination?.sha256;
        if (!expectedSha256) throw remoteSyncStale(input.planId, "UPDATE_PREIMAGE_MISSING", operation.path);
        const updated = asRecord(await this.remoteRequest(target, {
          op: "copy",
          path: sourcePath,
          destination: destinationPath,
          options: {
            overwrite: true,
            expectedSha256,
            createParents: true,
            finalSymlink: "reject",
          },
        }, callContext));
        return { updated: operation.path, sha256: updated.sha256 ?? operation.source?.sha256 };
      }
      case "COPY_SYMLINK":
        if (target.platform === "windows") throw remoteSyncUnsupported(target, destinationPath, operation.kind);
        if (typeof operation.source?.linkTarget !== "string") {
          throw remoteSyncStale(input.planId, "SYMLINK_TARGET_MISSING", operation.path);
        }
        await this.remoteRequest(target, {
          op: "symlink",
          path: destinationPath,
          linkTarget: operation.source.linkTarget,
          options: { createParents: true },
        }, callContext);
        return { copiedSymlink: operation.path };
      case "UPDATE_SYMLINK": {
        if (target.platform === "windows") throw remoteSyncUnsupported(target, destinationPath, operation.kind);
        if (typeof operation.source?.linkTarget !== "string") {
          throw remoteSyncStale(input.planId, "SYMLINK_TARGET_MISSING", operation.path);
        }
        const recovery = await this.remoteSyncTrash(target, destinationPath, operation.path, callContext);
        input.persistPartialResult?.({ recovery });
        await this.remoteRequest(target, {
          op: "symlink",
          path: destinationPath,
          linkTarget: operation.source.linkTarget,
          options: { createParents: true },
        }, callContext);
        return { updatedSymlink: operation.path, recovery };
      }
      case "REPLACE_CONFLICT": {
        const existing = await this.remoteSyncOptionalStat(target, destinationPath, callContext);
        const recovery = existing
          ? await this.remoteSyncTrash(target, destinationPath, operation.path, callContext)
          : undefined;
        if (recovery) {
          input.persistPartialResult?.({ recovery });
        }
        if (operation.source?.type === "directory") {
          await this.remoteRequest(target, {
            op: "mkdir",
            path: destinationPath,
            options: { recursive: true },
          }, callContext);
        } else if (operation.source?.type === "file") {
          await this.remoteRequest(target, {
            op: "copy",
            path: sourcePath,
            destination: destinationPath,
            options: { overwrite: false, createParents: true, finalSymlink: "reject" },
          }, callContext);
        } else if (operation.source?.type === "symlink") {
          throw remoteSyncUnsupported(target, destinationPath, "REPLACE_SYMLINK_CONFLICT");
        } else {
          throw new UniversalBrokerError("SYNC_CONFLICT", "A conflict has no source entry.");
        }
        return { replacedConflict: operation.path, ...(recovery ? { recovery } : {}) };
      }
      case "DELETE_ENTRY": {
        if (!await this.remoteSyncOptionalStat(target, destinationPath, callContext)) {
          return { reconciledAbsent: operation.path };
        }
        if (operation.deleteMode === "permanent") {
          const result = asRecord(await this.remoteRequest(target, {
            op: "remove",
            path: destinationPath,
            options: {
              disposition: "permanent",
              recursive: true,
              finalSymlink: "preserve",
            },
          }, callContext));
          if (result.removed !== true || result.disposition !== "permanent") {
            throw new UniversalBrokerError(
              "SYNC_PLAN_STALE",
              "Remote permanent sync deletion did not return its exact post-readback receipt.",
              { evidence: { targetId: target.id, path: operation.path } },
            );
          }
          return { deleted: operation.path, disposition: "permanent" };
        }
        if (operation.deleteMode !== "trash") {
          throw new UniversalBrokerError(
            "SYNC_PLAN_STALE",
            "Stored remote sync deletion has an invalid immutable delete mode.",
            { evidence: { targetId: target.id, path: operation.path, deleteMode: operation.deleteMode } },
          );
        }
        const recovery = await this.remoteSyncTrash(target, destinationPath, operation.path, callContext);
        input.persistPartialResult?.({ recovery });
        return { deleted: operation.path, recovery };
      }
    }
  }

  private async remoteSyncOperationPostcondition(
    target: TargetDefinition,
    destinationRoot: string,
    operation: SyncOperation,
    callContext?: CapabilityCallContext,
  ): Promise<boolean> {
    const path = operation.path === "." ? destinationRoot : remoteTreePath(target, destinationRoot, operation.path);
    if (operation.kind === "DELETE_ENTRY") return !(await this.remoteSyncOptionalStat(target, path, callContext));
    const expected = operation.source;
    if (operation.kind === "CREATE_ROOT") {
      return remoteSyncEntryType(await this.remoteSyncOptionalStat(target, path, callContext)) === "directory";
    }
    if (!expected) return false;
    const observed = await this.remoteSyncOptionalStat(target, path, callContext);
    if (!observed) return false;
    const observedType = remoteSyncEntryType(observed);
    if (expected.type === "directory") return observedType === "directory";
    if (expected.type === "file") {
      if (observedType !== "file" || Number(observed.size) !== expected.size) return false;
      const hash = await this.remoteSyncHash(target, path, callContext);
      return hash.sha256 === expected.sha256;
    }
    return observedType === "symlink" && observed.linkTarget === expected.linkTarget;
  }

  private async remoteSyncOperationPostreadbackDigest(
    target: TargetDefinition,
    destinationRoot: string,
    operation: SyncOperation,
    callContext?: CapabilityCallContext,
  ): Promise<string> {
    const path = operation.path === "." ? destinationRoot : remoteTreePath(target, destinationRoot, operation.path);
    const observed = await this.remoteSyncOptionalStat(target, path, callContext);
    if (!observed) return sha256Text("absent");
    const observedType = remoteSyncEntryType(observed);
    if (observedType === "file") {
      const hash = await this.remoteSyncHash(target, path, callContext);
      return sha256Text(`file\0${hash.size}\0${hash.sha256}`);
    }
    if (observedType === "symlink") return sha256Text(`symlink\0${String(observed.linkTarget ?? "")}`);
    return sha256Text("directory");
  }

  private async remoteSyncAssertSourceEntry(
    target: TargetDefinition,
    sourceRoot: string,
    operation: SyncOperation,
    callContext?: CapabilityCallContext,
  ): Promise<void> {
    if (!operation.source || operation.kind === "CREATE_ROOT" || operation.kind === "DELETE_ENTRY") return;
    if (operation.path === "." && operation.source.type === "directory") return;
    const sourcePath = remoteTreePath(target, sourceRoot, operation.path);
    const observed = await this.remoteSyncOptionalStat(target, sourcePath, callContext);
    const expected = operation.source;
    const observedType = remoteSyncEntryType(observed);
    const matches = expected.type === "directory"
      ? observedType === "directory"
      : expected.type === "file"
        ? Boolean(
            observedType === "file"
            && Number(observed?.size) === expected.size
            && (await this.remoteSyncHash(target, sourcePath, callContext)).sha256 === expected.sha256
          )
        : Boolean(observedType === "symlink" && observed?.linkTarget === expected.linkTarget);
    if (!matches) throw remoteSyncStale("unknown", "SOURCE_ENTRY_CHANGED", operation.path);
  }

  private async remoteSyncFileEntry(
    target: TargetDefinition,
    path: string,
    relativePath: string,
    before: Record<string, unknown>,
    callContext?: CapabilityCallContext,
  ): Promise<FilesystemSyncEntry> {
    const beforeIdentity = remoteSyncStatIdentity(before);
    const hash = await this.remoteSyncHash(target, path, callContext);
    const after = await this.remoteSyncRequiredStat(target, path, callContext);
    if (
      remoteSyncEntryType(after) !== "file"
      || stableJson(remoteSyncStatIdentity(after)) !== stableJson(beforeIdentity)
      || hash.size !== Number(after.size)
    ) {
      throw remoteSyncStale("snapshot", "FILE_CHANGED_DURING_SNAPSHOT", relativePath);
    }
    return { path: relativePath, type: "file", size: hash.size, sha256: hash.sha256 };
  }

  private async remoteSyncListAll(
    target: TargetDefinition,
    path: string,
    callContext?: CapabilityCallContext,
  ): Promise<FilesystemListEntry[]> {
    const entries: FilesystemListEntry[] = [];
    let expectedTotal: number | undefined;
    while (expectedTotal === undefined || entries.length < expectedTotal) {
      const result = asRecord(await this.remoteRequest(target, {
        op: "list",
        path,
        options: { offset: entries.length, limit: REMOTE_LIST_PAGE_LIMIT },
      }, callContext));
      const total = requireBoundedCount(
        result.totalEntries,
        "remote sync list totalEntries",
        MAX_LIST_SNAPSHOT_ENTRIES,
        "RESOURCE_QUOTA_EXCEEDED",
      );
      if (expectedTotal !== undefined && total !== expectedTotal) {
        throw remoteSyncStale("snapshot", "DIRECTORY_ENTRY_COUNT_CHANGED", path);
      }
      expectedTotal = total;
      const offset = requireBoundedCount(result.offset, "remote sync list offset", MAX_LIST_SNAPSHOT_ENTRIES);
      if (offset !== entries.length) throw remoteSyncStale("snapshot", "DIRECTORY_PAGE_OFFSET_CHANGED", path);
      const page = normalizeListEntries(result.entries, REMOTE_LIST_PAGE_LIMIT);
      if (page.length === 0 && entries.length < total) {
        throw remoteSyncStale("snapshot", "DIRECTORY_PAGE_TRUNCATED", path);
      }
      entries.push(...page);
      if (entries.length > total || entries.length > MAX_LIST_SNAPSHOT_ENTRIES) {
        throw remoteSyncEntryQuota(target, path);
      }
    }
    entries.sort((left, right) => compareText(left.name, right.name));
    return entries;
  }

  private async remoteSyncHash(
    target: TargetDefinition,
    path: string,
    callContext?: CapabilityCallContext,
  ): Promise<{ sha256: string; size: number }> {
    const result = asRecord(await this.remoteRequest(target, {
      op: "hash",
      path,
    }, callContext));
    const sha256 = typeof result.sha256 === "string" ? result.sha256.toLowerCase() : "";
    const size = Number(result.size);
    if (!/^[a-f0-9]{64}$/u.test(sha256) || !Number.isSafeInteger(size) || size < 0) {
      throw new UniversalBrokerError(
        "STATE_CORRUPTED",
        "Remote filesystem hash result is invalid.",
        { evidence: { targetId: target.id, path } },
      );
    }
    return { sha256, size };
  }

  private async remoteSyncOptionalStat(
    target: TargetDefinition,
    path: string,
    callContext?: CapabilityCallContext,
  ): Promise<Record<string, unknown> | undefined> {
    try {
      return await this.remoteSyncRequiredStat(target, path, callContext);
    } catch (error) {
      if (error instanceof UniversalBrokerError && error.code === "PATH_NOT_FOUND") return undefined;
      throw error;
    }
  }

  private async remoteSyncRequiredStat(
    target: TargetDefinition,
    path: string,
    callContext?: CapabilityCallContext,
  ): Promise<Record<string, unknown>> {
    return asRecord(await this.remoteRequest(target, {
      op: "stat",
      path,
    }, callContext));
  }

  private async remoteSyncTrash(
    target: TargetDefinition,
    path: string,
    relativePath: string,
    callContext?: CapabilityCallContext,
  ): Promise<Record<string, unknown>> {
    const recovery = asRecord(await this.remoteRequest(target, {
      op: "remove",
      path,
      options: {
        disposition: "trash",
        recursive: true,
        finalSymlink: "preserve",
      },
    }, callContext));
    if (recovery.disposition !== "trash" || recovery.recoverable !== true) {
      throw new UniversalBrokerError(
        "CAPABILITY_UNAVAILABLE",
        "Remote fs.sync delete did not return a recoverable trash receipt.",
        { evidence: { targetId: target.id, path: relativePath, deleteMode: "trash" } },
      );
    }
    return recovery;
  }

  private async resolveRequest(
    input: UniversalFilesystemInput,
    callContext?: CapabilityCallContext,
  ): Promise<ResolvedFilesystemRequest> {
    const context = input.contextId
      ? await this.contexts.get(input.contextId, callContext)
      : undefined;
    const target = await this.targets.resolve(input.target ?? context?.targetId ?? "local");
    assertTargetCapability(target, "fs");
    if (context && context.targetId !== target.id) {
      throw new UniversalBrokerError(
        "PRECONDITION_FAILED",
        `Context ${context.contextId} belongs to target ${context.targetId}, not ${target.id}.`,
        { evidence: { contextId: context.contextId, contextTarget: context.targetId, targetId: target.id } },
      );
    }
    const resolvePath = (value: string): string => target.transport === "local"
      ? resolveLocalPath(value, context?.root ?? target.defaultCwd ?? homedir())
      : resolveRemotePath(
          value,
          context?.root ?? target.defaultCwd ?? "~",
          target.platform,
        );
    return {
      target,
      ...(input.path !== undefined ? { path: resolvePath(input.path) } : {}),
      ...(input.destination !== undefined ? { destination: resolvePath(input.destination) } : {}),
    };
  }

  private async remoteRequest(
    target: TargetDefinition,
    request: Record<string, unknown>,
    callContext?: CapabilityCallContext,
  ): Promise<unknown> {
    if (target.platform === "windows") {
      return this.windowsRemoteRequest(target, request, callContext);
    }
    const command = `python3 -c ${shellQuote(REMOTE_FILESYSTEM_HELPER_SOURCE)} ${shellQuote(
      Buffer.from(JSON.stringify(request), "utf8").toString("base64"),
    )}`;
    return this.executeRemoteFilesystemCommand(
      target,
      command,
      REMOTE_FILESYSTEM_RESULT_MARKER,
      callContext,
    );
  }

  private async windowsRemoteRequest(
    target: TargetDefinition,
    request: Record<string, unknown>,
    callContext?: CapabilityCallContext,
  ): Promise<unknown> {
    await assertCachedSftpCapability(this.targets, target);
    const observation = await this.targets.probe(target.id);
    const temporaryDirectory = observation.temporaryDirectory;
    if (!temporaryDirectory) {
      throw new UniversalBrokerError(
        "CAPABILITY_UNAVAILABLE",
        `Windows target ${target.id} did not report a temporary directory.`,
      );
    }
    const directory = await mkdtemp(join(tmpdir(), "devspace-v2-windows-fs-"));
    const localScript = join(directory, "filesystem.ps1");
    const remoteScript = normalizeWindowsPath(win32.join(
      temporaryDirectory.replaceAll("/", "\\"),
      `.devspace-v2-fs-${randomUUID()}.ps1`,
    ));
    try {
      await writeFile(localScript, buildWindowsFilesystemScript(request), { mode: 0o600 });
      await this.sftpPut({ target, localPath: localScript, remotePath: remoteScript });
      return await this.executeRemoteFilesystemCommand(
        target,
        `& powershell.exe -NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -File ${powershellLiteral(remoteScript)}`,
        REMOTE_WINDOWS_FILESYSTEM_RESULT_MARKER,
        callContext,
      );
    } finally {
      await this.removeWindowsRemoteScript(target, remoteScript, callContext);
      await rm(directory, { recursive: true, force: true });
    }
  }

  private async removeWindowsRemoteScript(
    target: TargetDefinition,
    remoteScript: string,
    callContext?: CapabilityCallContext,
  ): Promise<void> {
    let result: UniversalProcessSnapshot | undefined;
    try {
      result = await this.execution.execute({
        internalPolicy: "filesystem",
        target: target.id,
        cwd: target.defaultCwd ?? "~",
        command: `Remove-Item -LiteralPath ${powershellLiteral(remoteScript)} -Force -ErrorAction SilentlyContinue`,
        mode: "foreground",
        yieldMs: 30_000,
        maxOutputChars: 8_000,
      }, undefined, undefined, callContext);
      if (result.state === "RUNNING" || result.state === "STARTING") {
        result = await this.execution.operate({
          operation: "wait",
          processId: result.processId,
          waitMs: 30_000,
          maxOutputChars: 8_000,
        }, undefined, callContext) as typeof result;
      }
    } catch {
      // The staged script is random, owner-level, and short-lived. The caller's
      // original filesystem error remains authoritative if cleanup also fails.
    } finally {
      if (result) {
        await this.forgetRemoteFilesystemProcess(result, callContext).catch(() => undefined);
      }
    }
  }

  private async executeRemoteFilesystemCommand(
    target: TargetDefinition,
    command: string,
    responseMarker: string,
    callContext?: CapabilityCallContext,
  ): Promise<unknown> {
    let result = await this.execution.execute({
      internalPolicy: "filesystem",
      target: target.id,
      cwd: target.defaultCwd ?? "~",
      command,
      mode: "foreground",
      yieldMs: 30_000,
      maxOutputChars: 1_000_000,
    }, undefined, undefined, callContext);
    try {
      if (result.state === "RUNNING" || result.state === "STARTING") {
        result = await this.execution.operate({
          operation: "wait",
          processId: result.processId,
          waitMs: 60_000,
          maxOutputChars: 1_000_000,
        }, undefined, callContext) as typeof result;
      }
      if (result.state !== "EXITED" || result.exitCode !== 0) {
        throw new UniversalBrokerError(
          result.state === "UNKNOWN" ? "EXECUTION_STATE_UNKNOWN" : "TRANSPORT_INTERRUPTED",
          `Remote filesystem helper did not complete on target ${target.id}.`,
          {
            evidence: {
              targetId: target.id,
              processId: result.processId,
              state: result.state,
              exitCode: result.exitCode,
              outputPreview: result.output.slice(0, 500),
            },
          },
        );
      }
      const marker = result.output.lastIndexOf(responseMarker);
      if (marker < 0) {
        throw new UniversalBrokerError(
          "TRANSPORT_INTERRUPTED",
          `Remote filesystem helper returned no framed result on target ${target.id}.`,
          { evidence: { targetId: target.id, outputPreview: result.output.slice(0, 500) } },
        );
      }
      const framed = result.output
        .slice(marker + responseMarker.length)
        .trim()
        .split(/\r?\n/, 1)[0] ?? "";
      let response: RemoteResponse;
      try {
        response = JSON.parse(framed) as RemoteResponse;
      } catch (error) {
        throw new UniversalBrokerError(
          "TRANSPORT_INTERRUPTED",
          `Remote filesystem helper returned malformed JSON on target ${target.id}.`,
          { evidence: { targetId: target.id, error: errorMessage(error) } },
        );
      }
      if (response.ok === true) return response.data;
      throw new UniversalBrokerError(
        remoteErrorCode(response.code),
        response.message ?? `Remote filesystem operation failed on target ${target.id}.`,
        { evidence: { targetId: target.id, remoteCode: response.code } },
      );
    } finally {
      await this.forgetRemoteFilesystemProcess(result, callContext);
    }
  }

  private async forgetRemoteFilesystemProcess(
    result: UniversalProcessSnapshot,
    callContext?: CapabilityCallContext,
  ): Promise<void> {
    if (result.state === "RUNNING" || result.state === "STARTING") {
      result = await this.execution.operate({
        operation: "signal",
        processId: result.processId,
        signal: "SIGTERM",
        waitMs: 2_000,
        maxOutputChars: 1_000,
      }, undefined, callContext) as UniversalProcessSnapshot;
    }
    await this.execution.operate({
      operation: "forget",
      processId: result.processId,
    }, undefined, callContext);
  }

  private async publishRemoteFile(
    target: TargetDefinition,
    path: string,
    localPath: string,
    options: {
      overwrite: boolean;
      expectedSha256?: string;
      mode?: number;
      uid?: number;
      gid?: number;
      confinedRoot?: string;
      createParents?: boolean;
    },
    callContext?: CapabilityCallContext,
  ): Promise<Record<string, unknown>> {
    await assertCachedSftpCapability(this.targets, target);
    const sourceMetadata = await stat(localPath);
    if (!sourceMetadata.isFile()) throw pathTypeError(localPath, "file");
    const sourceSha256 = await sha256File(localPath);
    const prepared = asRecord(await this.remoteRequest(target, {
      op: "prepare_write",
      path,
      options,
    }, callContext));
    const resolvedPath = typeof prepared.path === "string" ? prepared.path : path;
    const temporary = remoteSiblingTemporaryPath(target, resolvedPath);
    try {
      await this.sftpPut({ target, localPath, remotePath: temporary });
      return asRecord(await this.remoteRequest(target, {
        op: "publish_write",
        path,
        temporary,
        preimage: prepared.preimage,
        expectedContent: {
          size: sourceMetadata.size,
          sha256: sourceSha256,
        },
        options,
      }, callContext));
    } catch (error) {
      await this.remoteRequest(target, {
        op: "cleanup",
        path,
        temporary,
      }, callContext).catch(() => undefined);
      throw error;
    }
  }

  private async remotePatch(
    target: TargetDefinition,
    path: string,
    patch: string,
    expectedSha256: string | undefined,
    callContext?: CapabilityCallContext,
  ): Promise<Record<string, unknown>> {
    await assertCachedSftpCapability(this.targets, target);
    const metadata = asRecord(await this.remoteRequest(target, {
      op: "stat",
      path,
    }, callContext));
    if (metadata.type === "directory") {
      if (expectedSha256) {
        throw new UniversalBrokerError(
          "PRECONDITION_FAILED",
          "expectedSha256 is valid only when fs.patch targets one file.",
        );
      }
      throw new UniversalBrokerError(
        "CAPABILITY_UNAVAILABLE",
        `Remote directory patch is not supported; patch individual files on target ${target.id}.`,
      );
    }
    if (metadata.type !== "file") throw pathTypeError(path, "file or directory");
    const remoteBaseName = remotePathBaseName(target, path);
    validateSingleFilePatch(patch, remoteBaseName);
    const directory = await mkdtemp(join(tmpdir(), "devspace-v2-fs-patch-"));
    const staged = join(directory, remoteBaseName);
    try {
      await this.sftpGet({ target, remotePath: path, localPath: staged });
      const originalSha256 = await sha256File(staged);
      if (expectedSha256 && expectedSha256.toLowerCase() !== originalSha256) {
        throw new UniversalBrokerError(
          "PRECONDITION_FAILED",
          `SHA-256 precondition failed for ${path}.`,
          { evidence: { expectedSha256, actualSha256: originalSha256, path } },
        );
      }
      const applied = await applyPatch(directory, patch);
      await this.publishRemoteFile(
        target,
        path,
        staged,
        { overwrite: true, expectedSha256: originalSha256 },
        callContext,
      );
      return {
        path,
        patched: true,
        files: applied.files,
        additions: applied.additions,
        removals: applied.removals,
        previousSha256: originalSha256,
        sha256: await sha256File(staged),
      };
    } finally {
      await rm(directory, { recursive: true, force: true });
    }
  }

  private async sftpPut(input: SftpTransferInput): Promise<void> {
    await assertCachedSftpCapability(this.targets, input.target);
    await (this.options.sftpPut?.(input)
      ?? runSftpTransfer("put", input, this.options));
  }

  private async sftpGet(input: SftpTransferInput): Promise<void> {
    await assertCachedSftpCapability(this.targets, input.target);
    await (this.options.sftpGet?.(input)
      ?? runSftpTransfer("get", input, this.options));
  }
}

async function localStat(path: string): Promise<Record<string, unknown>> {
  const metadata = await requiredLstat(path);
  const type = fileType(metadata);
  return {
    path,
    type,
    size: metadata.size,
    mode: metadata.mode & 0o7777,
    mtimeMs: metadata.mtimeMs,
    birthtimeMs: metadata.birthtimeMs,
    uid: metadata.uid,
    gid: metadata.gid,
    ...(type === "symlink" ? { linkTarget: await readlink(path) } : {}),
  };
}

async function localListSnapshot(path: string): Promise<FilesystemListSnapshot> {
  const before = await requiredStat(path);
  if (!before.isDirectory()) throw pathTypeError(path, "directory");
  const entries = normalizeListEntries(
    (await readdir(path, { withFileTypes: true }))
      .sort((left, right) => compareText(left.name, right.name))
      .map((entry) => ({
        name: entry.name,
        type: entry.isDirectory()
          ? "directory"
          : entry.isFile()
            ? "file"
            : entry.isSymbolicLink()
              ? "symlink"
              : "other",
      })),
    MAX_LIST_SNAPSHOT_ENTRIES,
  );
  const after = await requiredStat(path);
  const beforeIdentity = filesystemStatIdentity(before);
  const afterIdentity = filesystemStatIdentity(after);
  if (!after.isDirectory() || digestJson(beforeIdentity) !== digestJson(afterIdentity)) {
    throw new CursorCapabilityError(
      "CURSOR_STALE",
      "Directory changed while its ordered pagination snapshot was captured.",
      { resourceKind: "filesystem.list" },
    );
  }
  return {
    resolvedPath: path,
    entries,
    generation: digestJson({
      version: 1,
      resolvedPath: path,
      directoryIdentity: afterIdentity,
      entries,
    }),
  };
}

async function localRead(
  path: string,
  offset: number,
  maximumBytes: number,
): Promise<Record<string, unknown>> {
  const metadata = await requiredStat(path);
  if (!metadata.isFile()) throw pathTypeError(path, "file");
  const handle = await open(path, "r");
  try {
    const buffer = Buffer.alloc(Math.min(maximumBytes, Math.max(metadata.size - offset, 0)));
    const { bytesRead } = await handle.read(buffer, 0, buffer.length, offset);
    const nextOffset = offset + bytesRead;
    return presentBytes({
      path,
      offset,
      bytesRead,
      size: metadata.size,
      truncated: nextOffset < metadata.size,
      ...(nextOffset < metadata.size ? { nextOffset } : {}),
    }, buffer.subarray(0, bytesRead));
  } finally {
    await handle.close();
  }
}

async function localSearchSnapshot(
  root: string,
  query: string,
  recursive: boolean,
): Promise<FilesystemSearchSnapshot> {
  const metadata = await requiredStat(root);
  const candidates: string[] = [];
  const directoryObservations: Array<Record<string, unknown>> = [];
  let candidateLimitReached = false;
  if (metadata.isFile()) {
    candidates.push(root);
  } else if (metadata.isDirectory()) {
    const walk = async (directory: string): Promise<void> => {
      if (candidateLimitReached) return;
      const before = await stat(directory);
      let entries;
      try {
        entries = (await readdir(directory, { withFileTypes: true }))
          .sort((left, right) => compareText(left.name, right.name));
      } catch (error) {
        if (isPermissionError(error)) {
          directoryObservations.push({ path: directory, unreadable: true });
          return;
        }
        throw error;
      }
      for (const entry of entries) {
        if (candidates.length >= MAX_SEARCH_FILES) {
          candidateLimitReached = true;
          break;
        }
        const candidatePath = join(directory, entry.name);
        if (entry.isDirectory()) {
          if (recursive && !SEARCH_SKIPPED_DIRECTORIES.has(entry.name)) {
            await walk(candidatePath);
          }
        } else if (entry.isFile()) {
          candidates.push(candidatePath);
        }
      }
      const after = await stat(directory);
      const beforeIdentity = filesystemStatIdentity(before);
      const afterIdentity = filesystemStatIdentity(after);
      if (digestJson(beforeIdentity) !== digestJson(afterIdentity)) {
        throw new CursorCapabilityError(
          "CURSOR_STALE",
          "Search directory changed while its pagination snapshot was captured.",
          { resourceKind: "filesystem.search" },
        );
      }
      directoryObservations.push({ path: directory, identity: afterIdentity });
    };
    await walk(root);
  } else {
    throw pathTypeError(root, "file or directory");
  }

  const results: FilesystemSearchResult[] = [];
  const fileObservations: Array<Record<string, unknown>> = [];
  let visitedFiles = 0;
  for (const candidatePath of candidates) {
    if (results.length > MAX_SEARCH_LIMIT) break;
    try {
      const before = await stat(candidatePath);
      const beforeIdentity = filesystemStatIdentity(before);
      if (before.size > MAX_SEARCH_FILE_BYTES) {
        fileObservations.push({ path: candidatePath, identity: beforeIdentity, skipped: "size" });
        continue;
      }
      const content = await readFile(candidatePath);
      const after = await stat(candidatePath);
      const afterIdentity = filesystemStatIdentity(after);
      if (digestJson(beforeIdentity) !== digestJson(afterIdentity)) {
        throw new CursorCapabilityError(
          "CURSOR_STALE",
          "A searched file changed while its pagination snapshot was captured.",
          { resourceKind: "filesystem.search" },
        );
      }
      const contentDigest = createHash("sha256").update(content).digest("hex");
      if (content.includes(0)) {
        fileObservations.push({
          path: candidatePath,
          identity: afterIdentity,
          contentDigest,
          skipped: "binary",
        });
        continue;
      }
      visitedFiles++;
      const lines = content.toString("utf8").split(/\r?\n/);
      for (let index = 0; index < lines.length; index++) {
        if (!lines[index]!.includes(query)) continue;
        results.push({
          path: candidatePath,
          line: index + 1,
          text: lines[index]!.slice(0, 500),
        });
        if (results.length > MAX_SEARCH_LIMIT) break;
      }
      fileObservations.push({ path: candidatePath, identity: afterIdentity, contentDigest });
    } catch (error) {
      if (error instanceof CursorCapabilityError) throw error;
      if (isNodeError(error, "ENOENT")) {
        throw new CursorCapabilityError(
          "CURSOR_STALE",
          "A search candidate disappeared while its pagination snapshot was captured.",
          { resourceKind: "filesystem.search" },
        );
      }
      if (isPermissionError(error)) {
        fileObservations.push({ path: candidatePath, unreadable: true });
        continue;
      }
      throw error;
    }
  }
  const boundedResults = results.slice(0, MAX_SEARCH_LIMIT).sort(compareSearchResults);
  const truncated = candidateLimitReached || results.length > MAX_SEARCH_LIMIT;
  return {
    resolvedPath: root,
    results: boundedResults,
    visitedFiles,
    truncated,
    generation: digestJson({
      version: 1,
      resolvedPath: root,
      query,
      recursive,
      directoryObservations: directoryObservations.sort(comparePathRecords),
      fileObservations,
      candidateLimitReached,
      results: boundedResults,
      visitedFiles,
      truncated,
    }),
  };
}

async function atomicLocalWrite(
  path: string,
  content: Buffer,
  options: {
    overwrite: boolean;
    expectedSha256?: string;
    allowReplaceSymlink?: boolean;
    filesystem?: AtomicFilesystemOperations;
  },
): Promise<Record<string, unknown>> {
  return { ...await atomicWriteBuffer(path, content, options) };
}

async function publishLocalFile(
  path: string,
  localPath: string,
  options: {
    overwrite: boolean;
    expectedSha256?: string;
    allowReplaceSymlink?: boolean;
    filesystem?: AtomicFilesystemOperations;
  },
): Promise<Record<string, unknown>> {
  return { ...await atomicCopyFile(localPath, path, options) };
}

async function localPatch(
  path: string,
  patch: string,
  expectedSha256: string | undefined,
  filesystem?: AtomicFilesystemOperations,
): Promise<Record<string, unknown>> {
  const metadata = await requiredStat(path);
  if (metadata.isDirectory()) {
    throw new UniversalBrokerError(
      "CAPABILITY_UNAVAILABLE",
      "Atomic directory patch is unavailable; patch one file per exact action.",
      { evidence: { path, sourcePreserved: true } },
    );
  }
  if (!metadata.isFile()) {
    throw pathTypeError(path, "file or directory");
  }
  validateSingleFilePatch(patch, basename(path));
  const originalSha256 = await sha256File(path);
  if (expectedSha256 && originalSha256 !== expectedSha256.toLowerCase()) {
    throw new UniversalBrokerError(
      "PRECONDITION_FAILED",
      `SHA-256 precondition failed for ${path}.`,
      { evidence: { path, expectedSha256, actualSha256: originalSha256 } },
    );
  }
  const directory = await mkdtemp(join(tmpdir(), "devspace-v2-local-patch-"));
  const staged = join(directory, basename(path));
  try {
    await copyFile(path, staged, fsConstants.COPYFILE_EXCL);
    const applied = await applyPatch(directory, patch);
    const published = await atomicCopyFile(staged, path, {
      overwrite: true,
      expectedSha256: originalSha256,
      filesystem,
    });
    return {
      root: dirname(path),
      path,
      patched: true,
      files: applied.files,
      additions: applied.additions,
      removals: applied.removals,
      previousSha256: originalSha256,
      sha256: published.sha256,
    };
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
}

async function localMkdir(path: string, recursive: boolean): Promise<Record<string, unknown>> {
  await mkdir(path, { recursive, mode: 0o700 });
  const metadata = await stat(path);
  return { path, created: true, mode: metadata.mode & 0o7777 };
}

async function localCopy(
  source: string,
  destination: string,
  overwrite: boolean,
  recursive: boolean,
  filesystem?: AtomicFilesystemOperations,
  allowReplaceSymlink = false,
): Promise<Record<string, unknown>> {
  const io = filesystem ?? nodeAtomicFilesystemOperations;
  const sourceMetadata = await requiredLstat(source);
  const existing = await optionalLstat(destination);
  if (existing && !overwrite) {
    throw new UniversalBrokerError("PRECONDITION_FAILED", `Destination exists: ${destination}`);
  }
  if (existing?.isSymbolicLink() && !allowReplaceSymlink) {
    throw new UniversalBrokerError("PERMISSION_DENIED", `Refusing symlink destination: ${destination}`);
  }
  if (sourceMetadata.isDirectory()) {
    if (!recursive) {
      throw new UniversalBrokerError(
        "PRECONDITION_FAILED",
        `Directory copy requires recursive=true: ${source}`,
      );
    }
    if (existing) {
      throw new UniversalBrokerError(
        "CAPABILITY_UNAVAILABLE",
        "Atomic overwrite of an existing directory is unavailable; trash or move it first.",
        { evidence: { source, destination, sourceType: "directory" } },
      );
    }
    const temporary = join(
      dirname(destination),
      `.devspace-v2-${basename(destination)}-${randomUUID()}.tmp`,
    );
    try {
      await io.cp(source, temporary, {
        recursive: true,
        force: false,
        errorOnExist: true,
        dereference: false,
        preserveTimestamps: true,
      });
      if (await optionalLstat(destination)) {
        throw new UniversalBrokerError(
          "PRECONDITION_FAILED",
          `Destination changed while the directory was staged: ${destination}`,
        );
      }
      await io.rename(temporary, destination);
      await syncDirectory(dirname(destination));
    } finally {
      await io.rm(temporary, { recursive: true, force: true }).catch(() => undefined);
    }
  } else if (sourceMetadata.isFile()) {
    const published = await atomicCopyFile(source, destination, {
      overwrite,
      allowReplaceSymlink,
      filesystem,
    });
    return {
      source,
      destination,
      copied: true,
      overwritten: published.overwritten,
      size: published.size,
      sha256: published.sha256,
    };
  } else {
    throw pathTypeError(source, "file or directory");
  }
  return {
    source,
    destination,
    copied: true,
    overwritten: Boolean(existing),
  };
}

async function localMove(
  source: string,
  destination: string,
  overwrite: boolean,
  filesystem?: AtomicFilesystemOperations,
  allowReplaceSymlink = false,
): Promise<Record<string, unknown>> {
  const sourceMetadata = await requiredLstat(source);
  if (sourceMetadata.isFile()) {
    const moved = await safeMoveFile(source, destination, {
      overwrite,
      allowReplaceSymlink,
      filesystem,
    });
    return {
      source,
      destination,
      moved: true,
      overwritten: moved.overwritten,
      crossDevice: moved.crossDevice,
      size: moved.size,
      sha256: moved.sha256,
    };
  }
  const existing = await optionalLstat(destination);
  if (existing && !overwrite) {
    throw new UniversalBrokerError("PRECONDITION_FAILED", `Destination exists: ${destination}`);
  }
  if (existing?.isSymbolicLink() && !allowReplaceSymlink) {
    throw new UniversalBrokerError("PERMISSION_DENIED", `Refusing symlink destination: ${destination}`);
  }
  if (existing) {
    throw new UniversalBrokerError(
      "CAPABILITY_UNAVAILABLE",
      "Atomic overwrite move is supported only for regular files.",
      { evidence: { source, destination } },
    );
  }
  try {
    await rename(source, destination);
  } catch (error) {
    if (!isNodeError(error, "EXDEV")) throw error;
    throw new UniversalBrokerError(
      "CAPABILITY_UNAVAILABLE",
      "Cross-device directory/symlink moves require recoverable trash or artifact copy.",
      { evidence: { source, destination, sourcePreserved: true } },
    );
  }
  return { source, destination, moved: true, overwritten: Boolean(existing) };
}

async function localRemove(
  path: string,
  disposition: "trash" | "permanent" | undefined,
  recursive: boolean,
  trash: RecoverableFilesystemTrash,
): Promise<Record<string, unknown>> {
  if ((disposition ?? "trash") === "trash") return trash.trash(path, recursive);
  const metadata = await requiredLstat(path);
  if (metadata.isDirectory() && !metadata.isSymbolicLink() && !recursive) {
    throw new UniversalBrokerError(
      "PRECONDITION_FAILED",
      `Directory removal requires recursive=true: ${path}`,
    );
  }
  await rm(path, { recursive, force: false });
  if (await optionalLstat(path)) {
    throw new UniversalBrokerError(
      "PRECONDITION_FAILED",
      `Filesystem removal post-readback found the path still present: ${path}`,
    );
  }
  return { path, removed: true, disposition: "permanent" };
}

async function localHash(path: string): Promise<Record<string, unknown>> {
  const metadata = await requiredStat(path);
  if (!metadata.isFile()) throw pathTypeError(path, "file");
  return { path, algorithm: "sha256", sha256: await sha256File(path), size: metadata.size };
}

function validateSingleFilePatch(patch: string, expectedName: string): void {
  let actions: ReturnType<typeof parsePatch>;
  try {
    actions = parsePatch(patch);
  } catch (error) {
    throw new UniversalBrokerError(
      "PRECONDITION_FAILED",
      errorMessage(error),
      { evidence: { operation: "fs.patch" } },
    );
  }
  if (actions.length !== 1) {
    throw new UniversalBrokerError(
      "PRECONDITION_FAILED",
      "A file-targeted patch must contain exactly one action.",
    );
  }
  const action = actions[0]!;
  if (action.kind !== "update" || action.path !== expectedName || action.moveTo) {
    throw new UniversalBrokerError(
      "PRECONDITION_FAILED",
      `A file-targeted patch must update exactly ${expectedName} without moving it.`,
    );
  }
}

async function assertCachedSftpCapability(
  targets: TargetRegistry,
  target: TargetDefinition,
): Promise<void> {
  const observation = await targets.cachedObservation(target.id);
  if (!observation || observation.capabilities.sftp) return;
  throw new UniversalBrokerError(
    observation.status === "OFFLINE" ? "TARGET_OFFLINE" : "CAPABILITY_UNAVAILABLE",
    `A fresh target probe reports SFTP unavailable on ${target.id}. Refresh the target probe after external SSH configuration changes.`,
    {
      evidence: {
        targetId: target.id,
        status: observation.status,
        capability: "sftp",
        expiresAt: observation.expiresAt,
      },
    },
  );
}

async function runSftpTransfer(
  operation: "put" | "get",
  input: SftpTransferInput,
  options: UniversalFilesystemOptions,
): Promise<void> {
  if (!input.target.sshHost) {
    throw new UniversalBrokerError(
      "TRANSPORT_UNAVAILABLE",
      `SSH target ${input.target.id} has no sshHost.`,
    );
  }
  validateSftpPath(input.localPath, "localPath");
  validateSftpPath(input.remotePath, "remotePath");
  const controlPath = await prepareSshControlPath(options.sshControlDir);
  const executable = options.sftpExecutable ?? "sftp";
  const args = [
    "-q",
    "-b", "-",
    "-o", "BatchMode=yes",
    "-o", "ConnectTimeout=7",
    "-o", "ConnectionAttempts=1",
    "-o", "ControlMaster=auto",
    "-o", "ControlPersist=90",
    "-o", `ControlPath=${controlPath}`,
    input.target.sshHost,
  ];
  const command = operation === "put"
    ? `put ${sftpQuote(input.localPath)} ${sftpQuote(sftpRemotePath(input.target, input.remotePath))}\n`
    : `get ${sftpQuote(sftpRemotePath(input.target, input.remotePath))} ${sftpQuote(input.localPath)}\n`;
  await new Promise<void>((resolvePromise, rejectPromise) => {
    const child = spawn(executable, args, {
      stdio: ["pipe", "pipe", "pipe"],
      env: sanitizedChildEnvironment(),
    });
    let output = "";
    const timer = setTimeout(() => {
      child.kill("SIGKILL");
      rejectPromise(new UniversalBrokerError(
        "TRANSPORT_INTERRUPTED",
        `SFTP ${operation} timed out for target ${input.target.id}.`,
      ));
    }, options.remoteTimeoutMs ?? DEFAULT_REMOTE_TIMEOUT_MS);
    timer.unref();
    child.stdout.on("data", (chunk: Buffer) => {
      output = boundedAppend(output, chunk.toString("utf8"), 8_000);
    });
    child.stderr.on("data", (chunk: Buffer) => {
      output = boundedAppend(output, chunk.toString("utf8"), 8_000);
    });
    child.once("error", (error) => {
      clearTimeout(timer);
      rejectPromise(new UniversalBrokerError(
        "TRANSPORT_UNAVAILABLE",
        `Unable to start SFTP for target ${input.target.id}: ${error.message}`,
      ));
    });
    child.once("close", (code) => {
      clearTimeout(timer);
      if (code === 0) resolvePromise();
      else rejectPromise(new UniversalBrokerError(
        "TRANSPORT_INTERRUPTED",
        `SFTP ${operation} failed for target ${input.target.id}.`,
        { evidence: { targetId: input.target.id, exitCode: code, outputPreview: output } },
      ));
    });
    child.stdin.end(command);
  });
}

function resolveLocalPath(value: string, base: string): string {
  const expanded = expandHomePath(value);
  return resolve(isAbsolute(expanded) ? expanded : join(base, expanded));
}

function resolveRemotePath(
  value: string,
  base: string,
  platform: TargetDefinition["platform"],
): string {
  if (value.includes("\0") || value.includes("\n") || value.includes("\r")) {
    throw new UniversalBrokerError("PRECONDITION_FAILED", "Remote paths cannot contain NUL or newlines.");
  }
  if (platform === "windows") return resolveWindowsRemotePath(value, base);
  if (value.startsWith("/") || value === "~" || value.startsWith("~/")) {
    return posix.normalize(value);
  }
  return base === "~"
    ? `~/${posix.normalize(value)}`
    : posix.normalize(posix.join(base, value));
}

function resolveWindowsRemotePath(value: string, base: string): string {
  const normalizedValue = value.replaceAll("\\", "/");
  if (normalizedValue === "~") return "~";
  if (normalizedValue.startsWith("~/")) {
    return `~/${normalizeWindowsRelativePath(normalizedValue.slice(2))}`;
  }
  if (isWindowsRemoteAbsolute(normalizedValue)) {
    return normalizeWindowsPath(normalizedValue);
  }
  const normalizedBase = base.replaceAll("\\", "/");
  if (normalizedBase === "~") {
    return `~/${normalizeWindowsRelativePath(normalizedValue)}`;
  }
  if (normalizedBase.startsWith("~/")) {
    return `~/${normalizeWindowsRelativePath(`${normalizedBase.slice(2)}/${normalizedValue}`)}`;
  }
  if (!isWindowsRemoteAbsolute(normalizedBase)) {
    throw new UniversalBrokerError(
      "PRECONDITION_FAILED",
      `Windows remote base path must be absolute or use a leading tilde: ${base}`,
    );
  }
  return normalizeWindowsPath(`${normalizedBase}/${normalizedValue}`);
}

function normalizeWindowsRelativePath(value: string): string {
  const normalized = win32.normalize(value.replaceAll("/", "\\")).replaceAll("\\", "/");
  if (
    normalized === ".."
    || normalized.startsWith("../")
    || isWindowsRemoteAbsolute(normalized)
  ) {
    throw new UniversalBrokerError(
      "PRECONDITION_FAILED",
      `Windows relative path escapes its base: ${value}`,
    );
  }
  return normalized === "." ? "" : normalized;
}

function normalizeWindowsPath(value: string): string {
  return win32.normalize(value.replaceAll("/", "\\")).replaceAll("\\", "/");
}

function isWindowsRemoteAbsolute(value: string): boolean {
  return /^[a-zA-Z]:[\\/]/u.test(value) || value.startsWith("//") || value.startsWith("\\\\");
}

function remotePathBaseName(target: TargetDefinition, path: string): string {
  return target.platform === "windows"
    ? win32.basename(path.replaceAll("/", "\\"))
    : posix.basename(posix.normalize(path));
}

function remoteSiblingTemporaryPath(target: TargetDefinition, path: string): string {
  const name = `.devspace-v2-${remotePathBaseName(target, path)}-${randomUUID()}.tmp`;
  if (target.platform === "windows") {
    const directory = win32.dirname(path.replaceAll("/", "\\"));
    return normalizeWindowsPath(win32.join(directory, name));
  }
  return posix.join(posix.dirname(path), name);
}

function remoteTreePath(target: TargetDefinition, root: string, relativePath: string): string {
  if (!relativePath || relativePath === "." || relativePath.startsWith("/") || relativePath.includes("\0")) {
    throw new UniversalBrokerError("STATE_CORRUPTED", "Stored remote filesystem sync path is invalid.");
  }
  if (target.platform === "windows") {
    const rootNative = root.replaceAll("/", "\\");
    const resolvedRoot = win32.resolve(rootNative);
    const resolved = win32.resolve(resolvedRoot, ...relativePath.split("/"));
    const child = win32.relative(resolvedRoot, resolved);
    if (!child || child === ".." || child.startsWith("..\\") || win32.isAbsolute(child)) {
      throw new UniversalBrokerError("STATE_CORRUPTED", "Stored remote filesystem sync path escaped its root.");
    }
    return normalizeWindowsPath(resolved);
  }
  const resolvedRoot = posix.resolve(root);
  const resolved = posix.resolve(resolvedRoot, ...relativePath.split("/"));
  const child = posix.relative(resolvedRoot, resolved);
  if (!child || child === ".." || child.startsWith("../") || posix.isAbsolute(child)) {
    throw new UniversalBrokerError("STATE_CORRUPTED", "Stored remote filesystem sync path escaped its root.");
  }
  return posix.normalize(resolved);
}

function syncTreeSnapshot(
  rootType: TreeSnapshot["rootType"],
  entries: FilesystemSyncEntry[],
): TreeSnapshot {
  const sorted = [...entries].sort((left, right) => Buffer.from(left.path).compare(Buffer.from(right.path)));
  return {
    rootType,
    entries: sorted,
    digest: sha256Text(stableJson({ rootType, entries: sorted })),
  };
}

function syncMatchesAny(path: string, patterns: readonly string[], directory: boolean): boolean {
  return patterns.some((pattern) => {
    const expression = syncGlobExpression(pattern);
    return expression.test(path) || (directory && expression.test(`${path}/`));
  });
}

function syncGlobExpression(pattern: string): RegExp {
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

function retainSyncIncludedAncestors(entries: FilesystemSyncEntry[]): FilesystemSyncEntry[] {
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

function remoteSyncEntryType(
  metadata: Record<string, unknown> | undefined,
): FilesystemSyncEntry["type"] | "other" | undefined {
  if (!metadata) return undefined;
  if (metadata.type === "file" || metadata.type === "directory" || metadata.type === "symlink") {
    return metadata.type;
  }
  return "other";
}

function remoteSyncStatIdentity(metadata: Record<string, unknown>): Record<string, unknown> {
  return {
    type: metadata.type,
    size: metadata.size,
    mode: metadata.mode ?? null,
    mtimeMs: metadata.mtimeMs ?? null,
    birthtimeMs: metadata.birthtimeMs ?? null,
    linkTarget: metadata.linkTarget ?? null,
  };
}

function remoteSyncUnsupported(
  target: TargetDefinition,
  path: string,
  entryType: string,
): UniversalBrokerError {
  return new UniversalBrokerError(
    "CAPABILITY_UNAVAILABLE",
    `Remote fs.sync does not support ${entryType} entries on target ${target.id}.`,
    { evidence: { targetId: target.id, path, entryType } },
  );
}

function remoteSyncEntryQuota(target: TargetDefinition, root: string): UniversalBrokerError {
  return new UniversalBrokerError(
    "RESOURCE_QUOTA_EXCEEDED",
    `Remote filesystem sync snapshot exceeds ${MAX_LIST_SNAPSHOT_ENTRIES} entries.`,
    { evidence: { targetId: target.id, root, maximumEntries: MAX_LIST_SNAPSHOT_ENTRIES } },
  );
}

function remoteSyncStale(planId: string, reason: string, path: string): UniversalBrokerError {
  return new UniversalBrokerError(
    "SYNC_PLAN_STALE",
    "The immutable remote filesystem sync plan is stale or no longer matches its bound state.",
    { evidence: { planId, reason, path } },
  );
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

function sha256Text(value: string): string {
  return createHash("sha256").update(value).digest("hex");
}

async function resolveLocalFinalPath(
  requestedPath: string,
  operation: UniversalFilesystemOperation,
  requestedBehavior: UniversalFilesystemInput["finalSymlink"],
): Promise<string> {
  const value = await optionalLstat(requestedPath);
  if (!value?.isSymbolicLink()) return requestedPath;
  const behavior = requestedBehavior ?? defaultFinalSymlinkBehavior(operation);
  switch (behavior) {
    case "follow":
      return realpath(requestedPath);
    case "preserve":
    case "replace":
      return requestedPath;
    case "reject":
      throw new UniversalBrokerError(
        "PERMISSION_DENIED",
        `Final symlink semantics reject this operation: ${requestedPath}`,
        { evidence: { requestedPath, operation, finalSymlink: behavior } },
      );
  }
}

function defaultFinalSymlinkBehavior(
  operation: UniversalFilesystemOperation,
): NonNullable<UniversalFilesystemInput["finalSymlink"]> {
  if (["stat", "move", "remove", "restore"].includes(operation)) return "preserve";
  if (["write", "mkdir", "sync"].includes(operation)) return "reject";
  return "follow";
}

function presentBytes(
  data: Record<string, unknown>,
  content: Buffer,
): Record<string, unknown> {
  const binary = content.includes(0);
  return binary
    ? { ...data, encoding: "base64", contentBase64: content.toString("base64") }
    : { ...data, encoding: "utf8", content: content.toString("utf8") };
}

async function requiredLstat(path: string) {
  try {
    return await lstat(path);
  } catch (error) {
    throw normalizeFilesystemError(error, { operation: "stat", path });
  }
}

async function requiredStat(path: string) {
  try {
    return await stat(path);
  } catch (error) {
    throw normalizeFilesystemError(error, { operation: "stat", path });
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

async function syncDirectory(path: string): Promise<void> {
  try {
    const handle = await open(path, "r");
    await handle.sync();
    await handle.close();
  } catch {
    // Some filesystems do not support directory fsync. The file itself was synced.
  }
}

function fileType(metadata: Awaited<ReturnType<typeof lstat>>): string {
  if (metadata.isFile()) return "file";
  if (metadata.isDirectory()) return "directory";
  if (metadata.isSymbolicLink()) return "symlink";
  if (metadata.isSocket()) return "socket";
  if (metadata.isFIFO()) return "fifo";
  if (metadata.isCharacterDevice()) return "character-device";
  if (metadata.isBlockDevice()) return "block-device";
  return "other";
}

function requirePath(value: string | undefined, operation: string): string {
  if (!value) {
    throw new UniversalBrokerError("PRECONDITION_FAILED", `${operation} requires path.`);
  }
  return value;
}

function requireText(value: string | undefined, message: string): string {
  if (!value?.trim()) throw new UniversalBrokerError("PRECONDITION_FAILED", message);
  return value;
}

function readOffset(input: UniversalFilesystemInput): number {
  if (input.cursor !== undefined) {
    throw new UniversalBrokerError(
      "PRECONDITION_FAILED",
      "fs.read byte ranges use offset; cursor is reserved for signed list/search pagination.",
      { evidence: { operation: "read", cursorAccepted: false } },
    );
  }
  const offset = input.offset ?? 0;
  if (!Number.isSafeInteger(offset) || offset < 0) {
    throw new UniversalBrokerError(
      "PRECONDITION_FAILED",
      "offset must be a non-negative safe integer.",
      { evidence: { operation: "read", offset } },
    );
  }
  return offset;
}

function boundedLimit(value: number | undefined, fallback: number, maximum: number): number {
  const parsed = value ?? fallback;
  if (!Number.isInteger(parsed) || parsed < 1 || parsed > maximum) {
    throw new UniversalBrokerError(
      "PRECONDITION_FAILED",
      `limit must be an integer from 1 through ${maximum}.`,
      { evidence: { limit: parsed, maximum } },
    );
  }
  return parsed;
}

interface PaginationLimit {
  creationLimit: number;
  continuationLimit?: number;
}

function paginationLimit(
  value: number | undefined,
  fallback: number,
  maximum: number,
): PaginationLimit {
  return {
    creationLimit: boundedLimit(value, fallback, maximum),
    ...(value === undefined ? {} : { continuationLimit: boundedLimit(value, fallback, maximum) }),
  };
}

function paginateSnapshotItems<T>(input: {
  store: SignedSnapshotCursorStore;
  cursor?: string;
  limit: PaginationLimit;
  binding: CursorBinding;
  items: readonly T[];
}): {
  items: T[];
  offset: number;
  limit: number;
  snapshotDigest: string;
  expiresAt: string;
  nextCursor?: string;
} {
  const page = input.cursor === undefined
    ? input.store.createSnapshot({
        binding: input.binding,
        orderedItemIdentities: input.items.map((value, index) => JSON.stringify({
          version: 1,
          index,
          initialLimit: input.limit.creationLimit,
          value,
        })),
        limit: input.limit.creationLimit,
      })
    : input.store.continueSnapshot({
        cursor: input.cursor,
        binding: input.binding,
        ...(input.limit.continuationLimit === undefined
          ? {}
          : { limit: input.limit.continuationLimit }),
      });
  const decoded = page.itemIdentities.map((identity) => decodeSnapshotItem<T>(identity));
  for (let index = 1; index < decoded.length; index++) {
    if (
      decoded[index]!.index !== decoded[index - 1]!.index + 1
      || decoded[index]!.initialLimit !== decoded[0]!.initialLimit
    ) {
      throw new UniversalBrokerError(
        "STATE_CORRUPTED",
        "Filesystem pagination snapshot item order is invalid.",
      );
    }
  }
  return {
    items: decoded.map((item) => item.value),
    offset: decoded[0]?.index ?? 0,
    limit: input.limit.continuationLimit
      ?? decoded[0]?.initialLimit
      ?? input.limit.creationLimit,
    snapshotDigest: page.snapshotDigest,
    expiresAt: page.expiresAt,
    ...(page.nextCursor ? { nextCursor: page.nextCursor } : {}),
  };
}

function decodeSnapshotItem<T>(identity: string): {
  index: number;
  initialLimit: number;
  value: T;
} {
  let parsed: unknown;
  try {
    parsed = JSON.parse(identity);
  } catch {
    throw new UniversalBrokerError(
      "STATE_CORRUPTED",
      "Filesystem pagination snapshot item is not valid JSON.",
    );
  }
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
    throw new UniversalBrokerError(
      "STATE_CORRUPTED",
      "Filesystem pagination snapshot item is invalid.",
    );
  }
  const value = parsed as Record<string, unknown>;
  if (
    value.version !== 1
    || !Number.isSafeInteger(value.index)
    || (value.index as number) < 0
    || !Number.isSafeInteger(value.initialLimit)
    || (value.initialLimit as number) < 1
    || !("value" in value)
  ) {
    throw new UniversalBrokerError(
      "STATE_CORRUPTED",
      "Filesystem pagination snapshot item fields are invalid.",
    );
  }
  return {
    index: value.index as number,
    initialLimit: value.initialLimit as number,
    value: value.value as T,
  };
}

function filesystemCursorBinding(input: {
  principalKeyFingerprint: string;
  target: TargetDefinition;
  resourceKind: "filesystem.list" | "filesystem.search";
  resolvedPath: string;
  queryDigest: string;
  snapshotGeneration: string;
}): CursorBinding {
  return {
    principalKeyFingerprint: input.principalKeyFingerprint,
    resourceKind: input.resourceKind,
    resourceIdentityDigest: digestJson({
      version: 1,
      targetId: input.target.id,
      targetGeneration: input.target.generation,
      endpointFingerprint: input.target.endpointFingerprint,
      resolvedPath: input.resolvedPath,
    }),
    queryDigest: input.queryDigest,
    snapshotGeneration: input.snapshotGeneration,
  };
}

function normalizeListEntries(value: unknown, maximum: number): FilesystemListEntry[] {
  if (!Array.isArray(value) || value.length > maximum) {
    throw new UniversalBrokerError(
      value instanceof Array ? "RESOURCE_QUOTA_EXCEEDED" : "STATE_CORRUPTED",
      "Filesystem directory snapshot entry count is invalid.",
      { evidence: { maximumEntries: maximum } },
    );
  }
  return value.map((entry) => {
    if (!entry || typeof entry !== "object" || Array.isArray(entry)) {
      throw new UniversalBrokerError("STATE_CORRUPTED", "Filesystem list entry is invalid.");
    }
    const record = entry as Record<string, unknown>;
    const name = requireTextField(record.name, "filesystem list entry name");
    if (name.length > 4_096 || name.includes("\0")) {
      throw new UniversalBrokerError("STATE_CORRUPTED", "Filesystem list entry name is invalid.");
    }
    const type = record.type;
    if (type !== "directory" && type !== "file" && type !== "symlink" && type !== "other") {
      throw new UniversalBrokerError("STATE_CORRUPTED", "Filesystem list entry type is invalid.");
    }
    return { name, type };
  });
}

function normalizeSearchResults(value: unknown, maximum: number): FilesystemSearchResult[] {
  if (!Array.isArray(value) || value.length > maximum) {
    throw new UniversalBrokerError("STATE_CORRUPTED", "Filesystem search result count is invalid.");
  }
  return value.map((entry) => {
    if (!entry || typeof entry !== "object" || Array.isArray(entry)) {
      throw new UniversalBrokerError("STATE_CORRUPTED", "Filesystem search result is invalid.");
    }
    const record = entry as Record<string, unknown>;
    const path = requireTextField(record.path, "filesystem search result path");
    const text = typeof record.text === "string" ? record.text.slice(0, 500) : undefined;
    const line = record.line;
    if (text === undefined || !Number.isSafeInteger(line) || (line as number) < 1) {
      throw new UniversalBrokerError("STATE_CORRUPTED", "Filesystem search result fields are invalid.");
    }
    return { path, line: line as number, text };
  });
}

function requireTextField(value: unknown, label: string): string {
  if (typeof value !== "string" || value.length === 0 || value.length > 32_768) {
    throw new UniversalBrokerError("STATE_CORRUPTED", `${label} is invalid.`);
  }
  return value;
}

function requireBoundedCount(
  value: unknown,
  label: string,
  maximum: number,
  overflowCode: "STATE_CORRUPTED" | "RESOURCE_QUOTA_EXCEEDED" = "STATE_CORRUPTED",
): number {
  if (!Number.isSafeInteger(value) || (value as number) < 0) {
    throw new UniversalBrokerError("STATE_CORRUPTED", `${label} is invalid.`);
  }
  if ((value as number) > maximum) {
    throw new UniversalBrokerError(
      overflowCode,
      `${label} exceeds the supported bound.`,
      { evidence: { maximum, actual: value } },
    );
  }
  return value as number;
}

function remoteSnapshotChanged(message: string, target: TargetDefinition): CursorCapabilityError {
  return new CursorCapabilityError(
    "CURSOR_STALE",
    message,
    { resourceKind: "filesystem.list", targetId: target.id },
  );
}

function filesystemStatIdentity(metadata: Stats): Record<string, unknown> {
  return {
    dev: String(metadata.dev),
    ino: String(metadata.ino),
    mode: metadata.mode,
    size: metadata.size,
    mtimeMs: metadata.mtimeMs,
    ctimeMs: metadata.ctimeMs,
  };
}

function compareSearchResults(left: FilesystemSearchResult, right: FilesystemSearchResult): number {
  return compareText(left.path, right.path)
    || left.line - right.line
    || compareText(left.text, right.text);
}

function comparePathRecords(left: Record<string, unknown>, right: Record<string, unknown>): number {
  return compareText(String(left.path ?? ""), String(right.path ?? ""));
}

function compareText(left: string, right: string): number {
  return left < right ? -1 : left > right ? 1 : 0;
}

function digestJson(value: unknown): string {
  return createHash("sha256").update(JSON.stringify(value)).digest("hex");
}

function pathTypeError(path: string, expected: string): UniversalBrokerError {
  return new UniversalBrokerError(
    "PATH_TYPE_MISMATCH",
    `Expected ${expected}: ${path}`,
    { evidence: { path, expected } },
  );
}

function normalizeFilesystemError(
  error: unknown,
  input: Pick<UniversalFilesystemInput, "operation" | "path" | "destination">,
): UniversalBrokerError {
  if (error instanceof UniversalBrokerError) return error;
  const evidence = {
    operation: input.operation,
    path: input.path,
    destination: input.destination,
    error: errorMessage(error),
  };
  if (isNodeError(error, "ENOENT")) {
    return new UniversalBrokerError("PATH_NOT_FOUND", error.message, { evidence });
  }
  if (isNodeError(error, "ENOTDIR") || isNodeError(error, "EISDIR")) {
    return new UniversalBrokerError("PATH_TYPE_MISMATCH", error.message, { evidence });
  }
  if (isPermissionError(error)) {
    return new UniversalBrokerError("PERMISSION_DENIED", errorMessage(error), { evidence });
  }
  if (isNodeError(error, "EEXIST") || isNodeError(error, "ENOTEMPTY")) {
    return new UniversalBrokerError("PRECONDITION_FAILED", error.message, { evidence });
  }
  return new UniversalBrokerError(
    "MCP_PROVIDER_ERROR",
    errorMessage(error),
    { evidence },
  );
}

function remoteErrorCode(code: string | undefined):
  | "PATH_NOT_FOUND"
  | "PATH_TYPE_MISMATCH"
  | "PERMISSION_DENIED"
  | "PRECONDITION_FAILED"
  | "TRANSPORT_INTERRUPTED" {
  switch (code) {
    case "PATH_NOT_FOUND":
    case "PATH_TYPE_MISMATCH":
    case "PERMISSION_DENIED":
    case "PRECONDITION_FAILED":
      return code;
    default:
      return "TRANSPORT_INTERRUPTED";
  }
}

function asRecord(value: unknown): Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new UniversalBrokerError(
      "TRANSPORT_INTERRUPTED",
      "Filesystem adapter returned a non-object result.",
    );
  }
  return { ...(value as Record<string, unknown>) };
}

function shellQuote(value: string): string {
  return `'${value.replaceAll("'", `'"'"'`)}'`;
}

function powershellLiteral(value: string): string {
  return `'${value.replaceAll("'", "''")}'`;
}

function sftpQuote(value: string): string {
  return `"${value.replaceAll("\\", "\\\\").replaceAll('"', '\\"')}"`;
}

function sftpRemotePath(target: TargetDefinition, value: string): string {
  if (target.platform !== "windows") return value;
  const normalized = value.replaceAll("\\", "/");
  if (/^[a-zA-Z]:\//u.test(normalized)) return `/${normalized}`;
  return normalized;
}

function validateSftpPath(value: string, field: string): void {
  if (!value || value.includes("\0") || value.includes("\n") || value.includes("\r")) {
    throw new UniversalBrokerError(
      "PRECONDITION_FAILED",
      `${field} is not safe for SFTP batch mode.`,
    );
  }
}

function sanitizedChildEnvironment(): NodeJS.ProcessEnv {
  const blocked = /(TOKEN|SECRET|PASSWORD|CREDENTIAL|PRIVATE_KEY|AUTH|COOKIE|SESSION)/i;
  return Object.fromEntries(
    Object.entries(process.env).filter(([name]) => !blocked.test(name)),
  );
}

function boundedAppend(current: string, addition: string, maximum: number): string {
  const combined = current + addition;
  return combined.length <= maximum ? combined : combined.slice(-maximum);
}

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

function isNodeError(error: unknown, code: string): error is NodeJS.ErrnoException {
  return error instanceof Error && (error as NodeJS.ErrnoException).code === code;
}

function isPermissionError(error: unknown): boolean {
  return isNodeError(error, "EACCES") || isNodeError(error, "EPERM");
}
