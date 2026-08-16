import { spawn } from "node:child_process";
import { createHash, randomUUID } from "node:crypto";
import { constants as fsConstants, createReadStream } from "node:fs";
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
import { pipeline } from "node:stream/promises";
import { applyPatch, parsePatch } from "../apply-patch.js";
import { expandHomePath } from "../roots.js";
import type { ContextRegistry } from "./contexts.js";
import type {
  UniversalExecutionPlane,
  UniversalProcessSnapshot,
} from "./execution.js";
import { UniversalBrokerError } from "./errors.js";
import { prepareSshControlPath } from "./ssh-control.js";
import {
  REMOTE_FILESYSTEM_HELPER_SOURCE,
  REMOTE_FILESYSTEM_RESULT_MARKER,
} from "./remote-filesystem-helper.js";
import {
  REMOTE_WINDOWS_FILESYSTEM_RESULT_MARKER,
  windowsFilesystemScript as buildWindowsFilesystemScript,
} from "./remote-windows-filesystem-helper.js";
import type { TargetDefinition, TargetRegistry } from "./targets.js";

const DEFAULT_READ_BYTES = 12_000;
const MAX_READ_BYTES = 1_000_000;
const DEFAULT_LIST_LIMIT = 100;
const MAX_LIST_LIMIT = 1_000;
const DEFAULT_SEARCH_LIMIT = 50;
const MAX_SEARCH_LIMIT = 500;
const MAX_SEARCH_FILE_BYTES = 2 * 1024 * 1024;
const MAX_SEARCH_FILES = 20_000;
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
  cursor?: string;
  limit?: number;
}

export interface UniversalFilesystemOptions {
  sshControlDir: string;
  sftpExecutable?: string;
  remoteTimeoutMs?: number;
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

export class UniversalFilesystemService {
  constructor(
    private readonly targets: TargetRegistry,
    private readonly contexts: ContextRegistry,
    private readonly execution: UniversalExecutionPlane,
    private readonly options: UniversalFilesystemOptions,
  ) {}

  async execute(input: UniversalFilesystemInput): Promise<Record<string, unknown>> {
    try {
      const resolved = await this.resolveRequest(input);
      if (resolved.target.transport === "ssh") {
        return await this.executeRemote(input, resolved);
      }
      return await this.executeLocal(input, resolved);
    } catch (error) {
      throw normalizeFilesystemError(error, input);
    }
  }

  /** Stage a local file into any configured filesystem target without putting it in tool text. */
  async importLocalFile(input: {
    target?: string;
    contextId?: string;
    path: string;
    localPath: string;
    overwrite?: boolean;
    expectedSha256?: string;
  }): Promise<Record<string, unknown>> {
    const source = await requiredLstat(input.localPath);
    if (!source.isFile()) throw pathTypeError(input.localPath, "file");
    const resolved = await this.resolveRequest({
      operation: "write",
      target: input.target,
      contextId: input.contextId,
      path: input.path,
      overwrite: input.overwrite,
      expectedSha256: input.expectedSha256,
    });
    if (resolved.target.transport === "local") {
      return publishLocalFile(
        requirePath(resolved.path, "artifact destination"),
        input.localPath,
        {
          overwrite: input.overwrite === true,
          expectedSha256: input.expectedSha256,
        },
      );
    }
    return this.publishRemoteFile(
      resolved.target,
      requirePath(resolved.path, "artifact destination"),
      input.localPath,
      {
        overwrite: input.overwrite === true,
        expectedSha256: input.expectedSha256,
      },
    );
  }

  /** Export a target file into an owner-only local staging path for artifact publication. */
  async exportToLocalFile(input: {
    target?: string;
    contextId?: string;
    path: string;
    localPath: string;
  }): Promise<{ localPath: string; size: number; sha256: string }> {
    const resolved = await this.resolveRequest({
      operation: "read",
      target: input.target,
      contextId: input.contextId,
      path: input.path,
    });
    await mkdir(dirname(input.localPath), { recursive: true, mode: 0o700 });
    if (resolved.target.transport === "local") {
      const sourcePath = requirePath(resolved.path, "artifact source");
      const source = await requiredLstat(sourcePath);
      if (!source.isFile()) throw pathTypeError(sourcePath, "file");
      await copyFile(sourcePath, input.localPath, fsConstants.COPYFILE_EXCL);
    } else {
      const remotePath = requirePath(resolved.path, "artifact source");
      const metadata = await this.remoteRequest(
        resolved.target,
        { op: "stat", path: remotePath },
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
  ): Promise<Record<string, unknown>> {
    const path = resolved.path;
    switch (input.operation) {
      case "stat":
        return localStat(requirePath(path, "fs.stat"));
      case "list":
        return localList(
          requirePath(path, "fs.list"),
          parseCursor(input.cursor),
          boundedLimit(input.limit, DEFAULT_LIST_LIMIT, MAX_LIST_LIMIT),
        );
      case "read":
        return localRead(
          requirePath(path, "fs.read"),
          parseCursor(input.cursor),
          boundedLimit(input.limit, DEFAULT_READ_BYTES, MAX_READ_BYTES),
        );
      case "search":
        return localSearch(
          requirePath(path, "fs.search"),
          requireText(input.query, "fs.search requires query."),
          input.recursive !== false,
          boundedLimit(input.limit, DEFAULT_SEARCH_LIMIT, MAX_SEARCH_LIMIT),
        );
      case "write":
        if (input.content === undefined) {
          throw new UniversalBrokerError("PRECONDITION_FAILED", "fs.write requires content.");
        }
        return atomicLocalWrite(
          requirePath(path, "fs.write"),
          Buffer.from(input.content, "utf8"),
          {
            overwrite: input.overwrite === true,
            expectedSha256: input.expectedSha256,
          },
        );
      case "patch":
        return localPatch(
          requirePath(path, "fs.patch"),
          requireText(input.patch, "fs.patch requires patch."),
          input.expectedSha256,
        );
      case "mkdir":
        return localMkdir(requirePath(path, "fs.mkdir"), input.recursive === true);
      case "copy":
        return localCopy(
          requirePath(path, "fs.copy"),
          requirePath(resolved.destination, "fs.copy destination"),
          input.overwrite === true,
          input.recursive === true,
        );
      case "move":
        return localMove(
          requirePath(path, "fs.move"),
          requirePath(resolved.destination, "fs.move destination"),
          input.overwrite === true,
        );
      case "remove":
        return localRemove(
          requirePath(path, "fs.remove"),
          input.disposition,
          input.recursive === true,
        );
      case "hash":
        return localHash(requirePath(path, "fs.hash"));
      case "sync":
        return localCopy(
          requirePath(path, "fs.sync"),
          requirePath(resolved.destination, "fs.sync destination"),
          input.overwrite === true,
          input.recursive === true,
          true,
        );
    }
  }

  private async executeRemote(
    input: UniversalFilesystemInput,
    resolved: ResolvedFilesystemRequest,
  ): Promise<Record<string, unknown>> {
    const target = resolved.target;
    const path = resolved.path;
    switch (input.operation) {
      case "stat":
        return asRecord(await this.remoteRequest(target, {
          op: "stat",
          path: requirePath(path, "fs.stat"),
        }));
      case "list":
        return asRecord(await this.remoteRequest(target, {
          op: "list",
          path: requirePath(path, "fs.list"),
          options: {
            offset: parseCursor(input.cursor),
            limit: boundedLimit(input.limit, DEFAULT_LIST_LIMIT, MAX_LIST_LIMIT),
          },
        }));
      case "read": {
        const result = asRecord(await this.remoteRequest(target, {
          op: "read",
          path: requirePath(path, "fs.read"),
          options: {
            offset: parseCursor(input.cursor),
            maxBytes: boundedLimit(input.limit, DEFAULT_READ_BYTES, MAX_READ_BYTES),
          },
        }));
        const encoded = typeof result.contentBase64 === "string" ? result.contentBase64 : "";
        delete result.contentBase64;
        return presentBytes(result, Buffer.from(encoded, "base64"));
      }
      case "search":
        return asRecord(await this.remoteRequest(target, {
          op: "search",
          path: requirePath(path, "fs.search"),
          query: requireText(input.query, "fs.search requires query."),
          options: {
            recursive: input.recursive !== false,
            limit: boundedLimit(input.limit, DEFAULT_SEARCH_LIMIT, MAX_SEARCH_LIMIT),
            maxFileBytes: MAX_SEARCH_FILE_BYTES,
          },
        }));
      case "write": {
        if (input.content === undefined) {
          throw new UniversalBrokerError("PRECONDITION_FAILED", "fs.write requires content.");
        }
        const content = Buffer.from(input.content, "utf8");
        const destination = requirePath(path, "fs.write");
        const options = {
          overwrite: input.overwrite === true,
          expectedSha256: input.expectedSha256,
        };
        if (content.byteLength <= MAX_DIRECT_REMOTE_WRITE_BYTES) {
          return asRecord(await this.remoteRequest(target, {
            op: "write_content",
            path: destination,
            contentBase64: content.toString("base64"),
            options,
          }));
        }
        const directory = await mkdtemp(join(tmpdir(), "devspace-v2-fs-write-"));
        const staged = join(directory, "payload");
        try {
          await writeFile(staged, content, { mode: 0o600 });
          return await this.publishRemoteFile(target, destination, staged, options);
        } finally {
          await rm(directory, { recursive: true, force: true });
        }
      }
      case "patch":
        return this.remotePatch(
          target,
          requirePath(path, "fs.patch"),
          requireText(input.patch, "fs.patch requires patch."),
          input.expectedSha256,
        );
      case "mkdir":
        return asRecord(await this.remoteRequest(target, {
          op: "mkdir",
          path: requirePath(path, "fs.mkdir"),
          options: { recursive: input.recursive === true },
        }));
      case "copy":
      case "sync":
        return asRecord(await this.remoteRequest(target, {
          op: input.operation,
          path: requirePath(path, `fs.${input.operation}`),
          destination: requirePath(resolved.destination, `fs.${input.operation} destination`),
          options: {
            overwrite: input.overwrite === true,
            recursive: input.recursive === true,
          },
        }));
      case "move":
        return asRecord(await this.remoteRequest(target, {
          op: "move",
          path: requirePath(path, "fs.move"),
          destination: requirePath(resolved.destination, "fs.move destination"),
          options: { overwrite: input.overwrite === true },
        }));
      case "remove":
        return asRecord(await this.remoteRequest(target, {
          op: "remove",
          path: requirePath(path, "fs.remove"),
          options: {
            disposition: requirePermanentDisposition(input.disposition),
            recursive: input.recursive === true,
          },
        }));
      case "hash":
        return asRecord(await this.remoteRequest(target, {
          op: "hash",
          path: requirePath(path, "fs.hash"),
        }));
    }
  }

  private async resolveRequest(
    input: UniversalFilesystemInput,
  ): Promise<ResolvedFilesystemRequest> {
    const context = input.contextId ? await this.contexts.get(input.contextId) : undefined;
    const target = await this.targets.resolve(input.target ?? context?.targetId ?? "local");
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
  ): Promise<unknown> {
    if (target.platform === "windows") {
      return this.windowsRemoteRequest(target, request);
    }
    const command = `python3 -c ${shellQuote(REMOTE_FILESYSTEM_HELPER_SOURCE)} ${shellQuote(
      Buffer.from(JSON.stringify(request), "utf8").toString("base64"),
    )}`;
    return this.executeRemoteFilesystemCommand(
      target,
      command,
      REMOTE_FILESYSTEM_RESULT_MARKER,
    );
  }

  private async windowsRemoteRequest(
    target: TargetDefinition,
    request: Record<string, unknown>,
  ): Promise<unknown> {
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
      );
    } finally {
      await this.removeWindowsRemoteScript(target, remoteScript);
      await rm(directory, { recursive: true, force: true });
    }
  }

  private async removeWindowsRemoteScript(
    target: TargetDefinition,
    remoteScript: string,
  ): Promise<void> {
    let result: UniversalProcessSnapshot | undefined;
    try {
      result = await this.execution.execute({
        target: target.id,
        cwd: target.defaultCwd ?? "~",
        command: `Remove-Item -LiteralPath ${powershellLiteral(remoteScript)} -Force -ErrorAction SilentlyContinue`,
        mode: "foreground",
        yieldMs: 30_000,
        maxOutputChars: 8_000,
      });
      if (result.state === "RUNNING" || result.state === "STARTING") {
        result = await this.execution.operate({
          operation: "wait",
          processId: result.processId,
          waitMs: 30_000,
          maxOutputChars: 8_000,
        }) as typeof result;
      }
    } catch {
      // The staged script is random, owner-level, and short-lived. The caller's
      // original filesystem error remains authoritative if cleanup also fails.
    } finally {
      if (result) await this.forgetRemoteFilesystemProcess(result).catch(() => undefined);
    }
  }

  private async executeRemoteFilesystemCommand(
    target: TargetDefinition,
    command: string,
    responseMarker: string,
  ): Promise<unknown> {
    let result = await this.execution.execute({
      target: target.id,
      cwd: target.defaultCwd ?? "~",
      command,
      mode: "foreground",
      yieldMs: 30_000,
      maxOutputChars: 1_000_000,
    });
    try {
      if (result.state === "RUNNING" || result.state === "STARTING") {
        result = await this.execution.operate({
          operation: "wait",
          processId: result.processId,
          waitMs: 60_000,
          maxOutputChars: 1_000_000,
        }) as typeof result;
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
      await this.forgetRemoteFilesystemProcess(result);
    }
  }

  private async forgetRemoteFilesystemProcess(
    result: UniversalProcessSnapshot,
  ): Promise<void> {
    if (result.state === "RUNNING" || result.state === "STARTING") {
      result = await this.execution.operate({
        operation: "signal",
        processId: result.processId,
        signal: "SIGTERM",
        waitMs: 2_000,
        maxOutputChars: 1_000,
      }) as UniversalProcessSnapshot;
    }
    await this.execution.operate({
      operation: "forget",
      processId: result.processId,
    });
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
  ): Promise<Record<string, unknown>> {
    const prepared = asRecord(await this.remoteRequest(target, {
      op: "prepare_write",
      path,
      options,
    }));
    const resolvedPath = typeof prepared.path === "string" ? prepared.path : path;
    const temporary = remoteSiblingTemporaryPath(target, resolvedPath);
    try {
      await this.sftpPut({ target, localPath, remotePath: temporary });
      return asRecord(await this.remoteRequest(target, {
        op: "publish_write",
        path,
        temporary,
        options,
      }));
    } catch (error) {
      await this.remoteRequest(target, {
        op: "cleanup",
        path,
        temporary,
      }).catch(() => undefined);
      throw error;
    }
  }

  private async remotePatch(
    target: TargetDefinition,
    path: string,
    patch: string,
    expectedSha256: string | undefined,
  ): Promise<Record<string, unknown>> {
    const metadata = asRecord(await this.remoteRequest(target, {
      op: "stat",
      path,
    }));
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

  private sftpPut(input: SftpTransferInput): Promise<void> {
    return this.options.sftpPut?.(input)
      ?? runSftpTransfer("put", input, this.options);
  }

  private sftpGet(input: SftpTransferInput): Promise<void> {
    return this.options.sftpGet?.(input)
      ?? runSftpTransfer("get", input, this.options);
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

async function localList(
  path: string,
  offset: number,
  limit: number,
): Promise<Record<string, unknown>> {
  const metadata = await requiredStat(path);
  if (!metadata.isDirectory()) throw pathTypeError(path, "directory");
  const entries = (await readdir(path, { withFileTypes: true }))
    .sort((left, right) => left.name.localeCompare(right.name));
  const page = entries.slice(offset, offset + limit).map((entry) => ({
    name: entry.name,
    type: entry.isDirectory()
      ? "directory"
      : entry.isFile()
        ? "file"
        : entry.isSymbolicLink()
          ? "symlink"
          : "other",
  }));
  const nextOffset = offset + page.length;
  return {
    path,
    entries: page,
    totalEntries: entries.length,
    offset,
    limit,
    ...(nextOffset < entries.length ? { nextCursor: String(nextOffset) } : {}),
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
      ...(nextOffset < metadata.size ? { nextCursor: String(nextOffset) } : {}),
    }, buffer.subarray(0, bytesRead));
  } finally {
    await handle.close();
  }
}

async function localSearch(
  root: string,
  query: string,
  recursive: boolean,
  limit: number,
): Promise<Record<string, unknown>> {
  const metadata = await requiredStat(root);
  const candidates: string[] = [];
  if (metadata.isFile()) {
    candidates.push(root);
  } else if (metadata.isDirectory()) {
    const walk = async (directory: string): Promise<void> => {
      if (candidates.length >= MAX_SEARCH_FILES) return;
      let entries;
      try {
        entries = await readdir(directory, { withFileTypes: true });
      } catch (error) {
        if (isPermissionError(error)) return;
        throw error;
      }
      for (const entry of entries) {
        if (candidates.length >= MAX_SEARCH_FILES) return;
        const path = join(directory, entry.name);
        if (entry.isDirectory()) {
          if (recursive && !SEARCH_SKIPPED_DIRECTORIES.has(entry.name)) await walk(path);
        } else if (entry.isFile()) {
          candidates.push(path);
        }
      }
    };
    await walk(root);
  } else {
    throw pathTypeError(root, "file or directory");
  }

  const results: Array<Record<string, unknown>> = [];
  let visitedFiles = 0;
  for (const path of candidates) {
    if (results.length >= limit) break;
    let file;
    try {
      file = await stat(path);
      if (file.size > MAX_SEARCH_FILE_BYTES) continue;
      const content = await readFile(path);
      if (content.includes(0)) continue;
      visitedFiles++;
      const lines = content.toString("utf8").split(/\r?\n/);
      for (let index = 0; index < lines.length; index++) {
        if (!lines[index]!.includes(query)) continue;
        results.push({ path, line: index + 1, text: lines[index]!.slice(0, 500) });
        if (results.length >= limit) break;
      }
    } catch (error) {
      if (isPermissionError(error) || isNodeError(error, "ENOENT")) continue;
      throw error;
    }
  }
  return {
    path: root,
    query,
    results,
    visitedFiles,
    truncated: results.length >= limit || candidates.length >= MAX_SEARCH_FILES,
  };
}

async function atomicLocalWrite(
  path: string,
  content: Buffer,
  options: { overwrite: boolean; expectedSha256?: string },
): Promise<Record<string, unknown>> {
  const parent = dirname(path);
  const parentMetadata = await requiredStat(parent);
  if (!parentMetadata.isDirectory()) throw pathTypeError(parent, "directory");
  const existing = await optionalLstat(path);
  if (existing?.isSymbolicLink()) {
    throw new UniversalBrokerError(
      "PERMISSION_DENIED",
      `Refusing to publish through a symlink destination: ${path}`,
    );
  }
  if (existing && !existing.isFile()) throw pathTypeError(path, "file");
  if (existing && !options.overwrite) {
    throw new UniversalBrokerError(
      "PRECONDITION_FAILED",
      `Destination already exists and overwrite is false: ${path}`,
    );
  }
  if (options.expectedSha256) {
    const actual = existing?.isFile() ? await sha256File(path) : undefined;
    if (!actual || actual.toLowerCase() !== options.expectedSha256.toLowerCase()) {
      throw new UniversalBrokerError(
        "PRECONDITION_FAILED",
        `SHA-256 precondition failed for ${path}.`,
        { evidence: { path, expectedSha256: options.expectedSha256, actualSha256: actual } },
      );
    }
  }
  const temporary = join(parent, `.devspace-v2-${basename(path)}-${randomUUID()}.tmp`);
  let handle;
  try {
    handle = await open(temporary, "wx", existing ? existing.mode & 0o777 : 0o600);
    await handle.writeFile(content);
    await handle.sync();
    await handle.close();
    handle = undefined;
    await rename(temporary, path);
    await syncDirectory(parent);
  } finally {
    await handle?.close().catch(() => undefined);
    await rm(temporary, { force: true }).catch(() => undefined);
  }
  return {
    path,
    size: content.byteLength,
    sha256: sha256(content),
    overwritten: Boolean(existing),
  };
}

async function publishLocalFile(
  path: string,
  localPath: string,
  options: { overwrite: boolean; expectedSha256?: string },
): Promise<Record<string, unknown>> {
  const parent = dirname(path);
  const existing = await optionalLstat(path);
  if (existing?.isSymbolicLink()) {
    throw new UniversalBrokerError("PERMISSION_DENIED", `Refusing symlink destination: ${path}`);
  }
  if (existing && !existing.isFile()) throw pathTypeError(path, "file");
  if (existing && !options.overwrite) {
    throw new UniversalBrokerError("PRECONDITION_FAILED", `Destination exists: ${path}`);
  }
  if (options.expectedSha256) {
    const actual = existing?.isFile() ? await sha256File(path) : undefined;
    if (!actual || actual.toLowerCase() !== options.expectedSha256.toLowerCase()) {
      throw new UniversalBrokerError("PRECONDITION_FAILED", `SHA-256 precondition failed: ${path}`);
    }
  }
  const temporary = join(parent, `.devspace-v2-${basename(path)}-${randomUUID()}.tmp`);
  try {
    await copyFile(localPath, temporary, fsConstants.COPYFILE_EXCL);
    const handle = await open(temporary, "r");
    await handle.sync();
    await handle.close();
    await rename(temporary, path);
    await syncDirectory(parent);
  } finally {
    await rm(temporary, { force: true }).catch(() => undefined);
  }
  const metadata = await stat(path);
  return {
    path,
    size: metadata.size,
    sha256: await sha256File(path),
    overwritten: Boolean(existing),
  };
}

async function localPatch(
  path: string,
  patch: string,
  expectedSha256: string | undefined,
): Promise<Record<string, unknown>> {
  const metadata = await requiredStat(path);
  let root: string;
  if (metadata.isDirectory()) {
    if (expectedSha256) {
      throw new UniversalBrokerError(
        "PRECONDITION_FAILED",
        "expectedSha256 is valid only when fs.patch targets one file.",
      );
    }
    root = path;
  } else if (metadata.isFile()) {
    root = dirname(path);
    validateSingleFilePatch(patch, basename(path));
    if (expectedSha256) {
      const actual = await sha256File(path);
      if (actual.toLowerCase() !== expectedSha256.toLowerCase()) {
        throw new UniversalBrokerError(
          "PRECONDITION_FAILED",
          `SHA-256 precondition failed for ${path}.`,
          { evidence: { path, expectedSha256, actualSha256: actual } },
        );
      }
    }
  } else {
    throw pathTypeError(path, "file or directory");
  }
  const applied = await applyPatch(root, patch);
  return {
    root,
    patched: true,
    files: applied.files,
    additions: applied.additions,
    removals: applied.removals,
  };
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
  synchronized = false,
): Promise<Record<string, unknown>> {
  const sourceMetadata = await requiredLstat(source);
  const existing = await optionalLstat(destination);
  if (existing && !overwrite) {
    throw new UniversalBrokerError("PRECONDITION_FAILED", `Destination exists: ${destination}`);
  }
  if (existing?.isSymbolicLink()) {
    throw new UniversalBrokerError("PERMISSION_DENIED", `Refusing symlink destination: ${destination}`);
  }
  if (sourceMetadata.isDirectory()) {
    if (!recursive) {
      throw new UniversalBrokerError(
        "PRECONDITION_FAILED",
        `Directory copy requires recursive=true: ${source}`,
      );
    }
    await cp(source, destination, {
      recursive: true,
      force: overwrite,
      errorOnExist: !overwrite,
      dereference: false,
      preserveTimestamps: true,
    });
  } else if (sourceMetadata.isFile()) {
    await copyFile(source, destination, overwrite ? 0 : fsConstants.COPYFILE_EXCL);
  } else {
    throw pathTypeError(source, "file or directory");
  }
  return {
    source,
    destination,
    copied: true,
    synchronized,
    overwritten: Boolean(existing),
  };
}

async function localMove(
  source: string,
  destination: string,
  overwrite: boolean,
): Promise<Record<string, unknown>> {
  await requiredLstat(source);
  const existing = await optionalLstat(destination);
  if (existing && !overwrite) {
    throw new UniversalBrokerError("PRECONDITION_FAILED", `Destination exists: ${destination}`);
  }
  if (existing?.isSymbolicLink()) {
    throw new UniversalBrokerError("PERMISSION_DENIED", `Refusing symlink destination: ${destination}`);
  }
  if (existing) await rm(destination, { recursive: true, force: true });
  try {
    await rename(source, destination);
  } catch (error) {
    if (!isNodeError(error, "EXDEV")) throw error;
    throw new UniversalBrokerError(
      "PRECONDITION_FAILED",
      "Cross-device move is not implicit; use fs.sync followed by explicit fs.remove.",
      { evidence: { source, destination } },
    );
  }
  return { source, destination, moved: true, overwritten: Boolean(existing) };
}

async function localRemove(
  path: string,
  disposition: "trash" | "permanent" | undefined,
  recursive: boolean,
): Promise<Record<string, unknown>> {
  requirePermanentDisposition(disposition);
  const metadata = await requiredLstat(path);
  if (metadata.isDirectory() && !metadata.isSymbolicLink() && !recursive) {
    throw new UniversalBrokerError(
      "PRECONDITION_FAILED",
      `Directory removal requires recursive=true: ${path}`,
    );
  }
  await rm(path, { recursive, force: false });
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

function presentBytes(
  data: Record<string, unknown>,
  content: Buffer,
): Record<string, unknown> {
  const binary = content.includes(0);
  return binary
    ? { ...data, encoding: "base64", contentBase64: content.toString("base64") }
    : { ...data, encoding: "utf8", content: content.toString("utf8") };
}

async function sha256File(path: string): Promise<string> {
  const digest = createHash("sha256");
  await pipeline(createReadStream(path), digest);
  return digest.digest("hex");
}

function sha256(value: Buffer): string {
  return createHash("sha256").update(value).digest("hex");
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

function requirePermanentDisposition(
  disposition: "trash" | "permanent" | undefined,
): "permanent" {
  if (disposition !== "permanent") {
    throw new UniversalBrokerError(
      "PRECONDITION_FAILED",
      "fs.remove requires disposition=permanent; trash support is not implicit.",
      { evidence: { disposition: disposition ?? "missing" } },
    );
  }
  return disposition;
}

function parseCursor(cursor: string | undefined): number {
  if (cursor === undefined) return 0;
  const parsed = Number(cursor);
  if (!Number.isSafeInteger(parsed) || parsed < 0) {
    throw new UniversalBrokerError("PRECONDITION_FAILED", `Invalid cursor: ${cursor}`);
  }
  return parsed;
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
