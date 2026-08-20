import { createHash, randomUUID } from "node:crypto";
import { lstatSync, realpathSync } from "node:fs";
import {
  chmod,
  copyFile,
  lstat,
  mkdir,
  open,
  readFile,
  readdir,
  rename,
  rm,
  writeFile,
} from "node:fs/promises";
import { basename, dirname, isAbsolute, join, relative, resolve, sep } from "node:path";
import Database from "better-sqlite3";

export const SNAPSHOT_GROUP_SCHEMA_VERSION = 1;

export type SnapshotEntryKind = "sqlite" | "file" | "directory";
export type SnapshotEntryState = "captured" | "absent";

export interface SnapshotGroupEntryRequest {
  id: string;
  kind: SnapshotEntryKind;
  path: string;
  required?: boolean;
  purpose?: string;
}

export interface SnapshotGroupBarrier extends Record<string, unknown> {
  kind: string;
  establishedAt?: string;
}

export interface SnapshotTreeEvidence {
  files: number;
  directories: number;
  bytes: number;
  sha256: string;
}

export interface SnapshotGroupManifestEntry {
  id: string;
  kind: SnapshotEntryKind;
  path: string;
  required: boolean;
  state: SnapshotEntryState;
  purpose?: string;
  snapshotPath?: string;
  sha256?: string;
  tree?: SnapshotTreeEvidence;
  bytes?: number;
  mode?: number;
}

export interface SnapshotGroupManifest {
  schemaVersion: typeof SNAPSHOT_GROUP_SCHEMA_VERSION;
  capturedAt: string;
  snapshotRoot: string;
  barrier: SnapshotGroupBarrier;
  entries: readonly SnapshotGroupManifestEntry[];
  groupDigest: string;
}

export interface SnapshotGroupCapture {
  manifest: SnapshotGroupManifest;
  manifestPath: string;
}

export interface SnapshotGroupRestoreEntry {
  id: string;
  kind: SnapshotEntryKind;
  path: string;
  state: SnapshotEntryState;
  restored: boolean;
  verified: boolean;
  sha256?: string;
  tree?: SnapshotTreeEvidence;
  staleSidecarsRemoved?: true;
}

export interface SnapshotGroupRestoreEvidence {
  groupDigest: string;
  restoredAt: string;
  verified: true;
  entries: readonly SnapshotGroupRestoreEntry[];
}

interface NormalizedSnapshotEntry extends SnapshotGroupEntryRequest {
  required: boolean;
  path: string;
}

interface UnsignedSnapshotGroupManifest {
  schemaVersion: typeof SNAPSHOT_GROUP_SCHEMA_VERSION;
  capturedAt: string;
  snapshotRoot: string;
  barrier: SnapshotGroupBarrier;
  entries: readonly SnapshotGroupManifestEntry[];
}

export async function captureSnapshotGroup(options: {
  snapshotRoot: string;
  barrier: SnapshotGroupBarrier;
  entries: readonly SnapshotGroupEntryRequest[];
  now?: () => string;
}): Promise<SnapshotGroupCapture> {
  const snapshotRoot = canonicalNoFollowPath(
    resolveAbsoluteDirectory(options.snapshotRoot, "snapshotRoot"),
    "snapshotRoot",
  );
  const entries = normalizeEntries(options.entries);
  assertSnapshotRootDoesNotOverlapStores(snapshotRoot, entries);
  const existingRoot = await lstat(snapshotRoot).catch((error: unknown) => {
    if (isNodeError(error, "ENOENT")) return undefined;
    throw error;
  });
  if (existingRoot) {
    throw new Error(`Snapshot root must be a new transaction-specific path: ${snapshotRoot}`);
  }
  const parent = dirname(snapshotRoot);
  const stagingRoot = canonicalNoFollowPath(
    join(parent, `.${basename(snapshotRoot)}.capture-${randomUUID()}`),
    "snapshot staging root",
  );
  try {
    await mkdir(stagingRoot, { recursive: false, mode: 0o700 });
    await chmod(stagingRoot, 0o700);
    const stagingEntriesRoot = join(stagingRoot, "entries");
    await mkdir(stagingEntriesRoot, { recursive: false, mode: 0o700 });
    const capturedEntries: SnapshotGroupManifestEntry[] = [];
    for (const entry of entries) {
      const captured = await captureEntry(stagingEntriesRoot, entry);
      capturedEntries.push(captured.snapshotPath
        ? {
            ...captured,
            snapshotPath: join(snapshotRoot, "entries", `${captured.id}.${captured.kind}`),
          }
        : captured);
    }
    const capturedAt = normalizeTimestamp(options.now?.() ?? new Date().toISOString());
    const barrier = normalizeBarrier(options.barrier, capturedAt);
    const unsigned: UnsignedSnapshotGroupManifest = {
      schemaVersion: SNAPSHOT_GROUP_SCHEMA_VERSION,
      capturedAt,
      snapshotRoot,
      barrier,
      entries: capturedEntries,
    };
    const manifest: SnapshotGroupManifest = {
      ...unsigned,
      groupDigest: digestJson(unsigned),
    };
    await writeJsonAtomic(join(stagingRoot, "SNAPSHOT-GROUP.json"), manifest, 0o600);
    await fsyncDirectory(stagingRoot);
    await rename(stagingRoot, snapshotRoot);
    await fsyncDirectory(parent);
    return { manifest, manifestPath: join(snapshotRoot, "SNAPSHOT-GROUP.json") };
  } catch (error) {
    await rm(stagingRoot, { recursive: true, force: true }).catch(() => undefined);
    await fsyncDirectory(parent).catch(() => undefined);
    throw error;
  }
}

export async function restoreSnapshotGroup(
  manifest: SnapshotGroupManifest,
  options: { now?: () => string } = {},
): Promise<SnapshotGroupRestoreEvidence> {
  const normalized = validateSnapshotGroupManifest(manifest);
  const entries: SnapshotGroupRestoreEntry[] = [];
  for (const entry of normalized.entries) {
    entries.push(await restoreEntry(entry));
  }
  if (entries.some((entry) => !entry.verified)) {
    throw new Error("Snapshot group restore did not verify every entry.");
  }
  return {
    groupDigest: normalized.groupDigest,
    restoredAt: normalizeTimestamp(options.now?.() ?? new Date().toISOString()),
    verified: true,
    entries,
  };
}

export function validateSnapshotGroupManifest(value: SnapshotGroupManifest): SnapshotGroupManifest {
  if (!value || value.schemaVersion !== SNAPSHOT_GROUP_SCHEMA_VERSION) {
    throw new Error("Unsupported snapshot group manifest version.");
  }
  const snapshotRoot = canonicalNoFollowPath(
    resolveAbsoluteDirectory(value.snapshotRoot, "snapshotRoot"),
    "snapshotRoot",
  );
  normalizeTimestamp(value.capturedAt);
  normalizeBarrier(value.barrier, value.capturedAt);
  if (!Array.isArray(value.entries) || value.entries.length < 1) {
    throw new Error("Snapshot group manifest must contain at least one entry.");
  }
  const entries = value.entries.map((entry) => validateManifestEntry(entry, snapshotRoot));
  const unsigned: UnsignedSnapshotGroupManifest = {
    schemaVersion: SNAPSHOT_GROUP_SCHEMA_VERSION,
    capturedAt: value.capturedAt,
    snapshotRoot,
    barrier: value.barrier,
    entries,
  };
  const expectedDigest = digestJson(unsigned);
  if (value.groupDigest !== expectedDigest) {
    throw new Error(`Snapshot group digest mismatch: expected ${expectedDigest}, observed ${value.groupDigest}`);
  }
  return {
    ...unsigned,
    groupDigest: value.groupDigest,
  };
}

async function captureEntry(
  entriesRoot: string,
  entry: NormalizedSnapshotEntry,
): Promise<SnapshotGroupManifestEntry> {
  const canonicalPath = canonicalNoFollowPath(entry.path, `snapshot store ${entry.id}`);
  if (canonicalPath !== entry.path) {
    throw new Error(`Snapshot store identity changed before capture: ${entry.id}.`);
  }
  const sourceState = await lstat(entry.path).catch((error: unknown) => {
    if (isNodeError(error, "ENOENT")) return undefined;
    throw error;
  });
  if (!sourceState) {
    if (entry.required) throw new Error(`Required snapshot store is missing: ${entry.id}: ${entry.path}`);
    return {
      id: entry.id,
      kind: entry.kind,
      path: entry.path,
      required: entry.required,
      state: "absent",
      ...(entry.purpose ? { purpose: entry.purpose } : {}),
    };
  }
  if (sourceState.isSymbolicLink()) throw new Error(`Snapshot store may not be a symlink: ${entry.path}`);
  const snapshotPath = join(entriesRoot, `${entry.id}.${entry.kind}`);
  switch (entry.kind) {
    case "sqlite": {
      if (!sourceState.isFile()) throw new Error(`SQLite snapshot store is not a file: ${entry.path}`);
      await backupSqlite(entry.path, snapshotPath);
      const sha256 = await fileSha256(snapshotPath);
      return {
        ...capturedBase(entry, snapshotPath),
        sha256,
        bytes: sourceState.size,
        mode: sourceState.mode & 0o777,
      };
    }
    case "file": {
      if (!sourceState.isFile()) throw new Error(`Snapshot file store is not a file: ${entry.path}`);
      await copyFile(entry.path, snapshotPath);
      await chmod(snapshotPath, sourceState.mode & 0o777);
      await fsyncFile(snapshotPath);
      const sha256 = await fileSha256(snapshotPath);
      return {
        ...capturedBase(entry, snapshotPath),
        sha256,
        bytes: sourceState.size,
        mode: sourceState.mode & 0o777,
      };
    }
    case "directory": {
      if (!sourceState.isDirectory()) throw new Error(`Snapshot directory store is not a directory: ${entry.path}`);
      await copyDirectory(entry.path, snapshotPath);
      const tree = await treeEvidence(snapshotPath);
      return {
        ...capturedBase(entry, snapshotPath),
        tree,
        mode: sourceState.mode & 0o777,
      };
    }
  }
}

function capturedBase(
  entry: NormalizedSnapshotEntry,
  snapshotPath: string,
): Omit<SnapshotGroupManifestEntry, "sha256" | "tree" | "bytes" | "mode"> {
  return {
    id: entry.id,
    kind: entry.kind,
    path: entry.path,
    required: entry.required,
    state: "captured",
    snapshotPath,
    ...(entry.purpose ? { purpose: entry.purpose } : {}),
  };
}

async function restoreEntry(entry: SnapshotGroupManifestEntry): Promise<SnapshotGroupRestoreEntry> {
  if (entry.state === "absent") {
    await removeDestination(entry);
    return {
      id: entry.id,
      kind: entry.kind,
      path: entry.path,
      state: "absent",
      restored: true,
      verified: true,
      ...(entry.kind === "sqlite" ? { staleSidecarsRemoved: true as const } : {}),
    };
  }
  if (!entry.snapshotPath) throw new Error(`Captured snapshot entry has no snapshot path: ${entry.id}`);
  switch (entry.kind) {
    case "sqlite":
      return restoreSqlite(entry);
    case "file":
      return restoreFile(entry);
    case "directory":
      return restoreDirectory(entry);
  }
}

async function restoreSqlite(entry: SnapshotGroupManifestEntry): Promise<SnapshotGroupRestoreEntry> {
  if (!entry.snapshotPath || !entry.sha256) throw new Error(`SQLite snapshot entry is incomplete: ${entry.id}`);
  await verifySqliteDatabase(entry.snapshotPath);
  if (await fileSha256(entry.snapshotPath) !== entry.sha256) {
    throw new Error(`SQLite snapshot digest mismatch before restore: ${entry.id}`);
  }
  const temporary = temporaryPath(entry.path);
  try {
    await copyFile(entry.snapshotPath, temporary);
    await chmod(temporary, 0o600);
    await fsyncFile(temporary);
    if (await fileSha256(temporary) !== entry.sha256) {
      throw new Error(`Staged SQLite restore digest mismatch: ${entry.id}`);
    }
    await removeSqliteSidecars(entry.path);
    await rename(temporary, entry.path);
    await chmod(entry.path, 0o600);
    await verifySqliteDatabase(entry.path);
    const restoredSha256 = await fileSha256(entry.path);
    if (restoredSha256 !== entry.sha256) {
      throw new Error(`Restored SQLite digest mismatch: ${entry.id}`);
    }
    await removeSqliteSidecars(entry.path);
    return {
      id: entry.id,
      kind: entry.kind,
      path: entry.path,
      state: entry.state,
      restored: true,
      verified: true,
      sha256: restoredSha256,
      staleSidecarsRemoved: true,
    };
  } catch (error) {
    await rm(temporary, { force: true }).catch(() => undefined);
    throw error;
  }
}

async function restoreFile(entry: SnapshotGroupManifestEntry): Promise<SnapshotGroupRestoreEntry> {
  if (!entry.snapshotPath || !entry.sha256) throw new Error(`File snapshot entry is incomplete: ${entry.id}`);
  if (await fileSha256(entry.snapshotPath) !== entry.sha256) {
    throw new Error(`File snapshot digest mismatch before restore: ${entry.id}`);
  }
  const temporary = temporaryPath(entry.path);
  try {
    await mkdir(dirname(entry.path), { recursive: true, mode: 0o700 });
    await copyFile(entry.snapshotPath, temporary);
    await chmod(temporary, entry.mode ?? 0o600);
    await fsyncFile(temporary);
    await rename(temporary, entry.path);
    const restoredSha256 = await fileSha256(entry.path);
    if (restoredSha256 !== entry.sha256) throw new Error(`Restored file digest mismatch: ${entry.id}`);
    return {
      id: entry.id,
      kind: entry.kind,
      path: entry.path,
      state: entry.state,
      restored: true,
      verified: true,
      sha256: restoredSha256,
    };
  } catch (error) {
    await rm(temporary, { force: true }).catch(() => undefined);
    throw error;
  }
}

async function restoreDirectory(entry: SnapshotGroupManifestEntry): Promise<SnapshotGroupRestoreEntry> {
  if (!entry.snapshotPath || !entry.tree) throw new Error(`Directory snapshot entry is incomplete: ${entry.id}`);
  const snapshotTree = await treeEvidence(entry.snapshotPath);
  if (snapshotTree.sha256 !== entry.tree.sha256) {
    throw new Error(`Directory snapshot digest mismatch before restore: ${entry.id}`);
  }
  const temporary = temporaryPath(entry.path);
  try {
    await rm(temporary, { recursive: true, force: true });
    await copyDirectory(entry.snapshotPath, temporary);
    await rm(entry.path, { recursive: true, force: true });
    await mkdir(dirname(entry.path), { recursive: true, mode: 0o700 });
    await rename(temporary, entry.path);
    if (entry.mode !== undefined) await chmod(entry.path, entry.mode);
    const restoredTree = await treeEvidence(entry.path);
    if (restoredTree.sha256 !== entry.tree.sha256) {
      throw new Error(`Restored directory digest mismatch: ${entry.id}`);
    }
    return {
      id: entry.id,
      kind: entry.kind,
      path: entry.path,
      state: entry.state,
      restored: true,
      verified: true,
      tree: restoredTree,
    };
  } catch (error) {
    await rm(temporary, { recursive: true, force: true }).catch(() => undefined);
    throw error;
  }
}

async function removeDestination(entry: SnapshotGroupManifestEntry): Promise<void> {
  if (entry.kind === "sqlite") {
    await removeSqliteSidecars(entry.path);
    await rm(entry.path, { force: true });
    return;
  }
  await rm(entry.path, { recursive: entry.kind === "directory", force: true });
}

async function backupSqlite(source: string, destination: string): Promise<void> {
  await verifySqliteDatabase(source);
  await rm(destination, { force: true });
  await removeSqliteSidecars(destination);
  await mkdir(dirname(destination), { recursive: true, mode: 0o700 });
  const sqlite = new Database(source, { readonly: true, fileMustExist: true });
  try {
    await sqlite.backup(destination);
  } finally {
    sqlite.close();
  }
  await chmod(destination, 0o600);
  await fsyncFile(destination);
  await verifySqliteDatabase(destination);
}

async function verifySqliteDatabase(path: string): Promise<void> {
  const metadata = await lstat(path);
  if (!metadata.isFile() || metadata.isSymbolicLink()) {
    throw new Error(`SQLite store is not a regular file: ${path}`);
  }
  const sqlite = new Database(path, { readonly: true, fileMustExist: true });
  try {
    const integrity = sqlite.pragma("integrity_check", { simple: true });
    if (integrity !== "ok") throw new Error(`SQLite integrity check failed for ${path}: ${String(integrity)}`);
    const foreignKeys = sqlite.pragma("foreign_key_check") as unknown[];
    if (foreignKeys.length > 0) throw new Error(`SQLite foreign-key check failed for ${path}.`);
  } finally {
    sqlite.close();
  }
}

async function copyDirectory(source: string, destination: string): Promise<void> {
  const sourceRoot = resolve(source);
  const destinationRoot = resolve(destination);
  await mkdir(destinationRoot, { recursive: true, mode: 0o700 });
  const visit = async (directory: string): Promise<void> => {
    const entries = await readdir(directory, { withFileTypes: true });
    entries.sort((left, right) => compareCodeUnits(left.name, right.name));
    for (const entry of entries) {
      const sourcePath = join(directory, entry.name);
      const relativePath = relative(sourceRoot, sourcePath);
      const destinationPath = join(destinationRoot, relativePath);
      const metadata = await lstat(sourcePath);
      if (metadata.isSymbolicLink()) throw new Error(`Snapshot directory may not contain symlinks: ${sourcePath}`);
      if (metadata.isDirectory()) {
        await mkdir(destinationPath, { recursive: true, mode: metadata.mode & 0o777 });
        await chmod(destinationPath, metadata.mode & 0o777);
        await visit(sourcePath);
      } else if (metadata.isFile()) {
        await mkdir(dirname(destinationPath), { recursive: true, mode: 0o700 });
        await copyFile(sourcePath, destinationPath);
        await chmod(destinationPath, metadata.mode & 0o777);
        await fsyncFile(destinationPath);
      } else {
        throw new Error(`Snapshot directory contains unsupported file type: ${sourcePath}`);
      }
    }
  };
  await visit(sourceRoot);
  await fsyncDirectory(destinationRoot);
}

async function treeEvidence(root: string): Promise<SnapshotTreeEvidence> {
  const base = resolve(root);
  const digest = createHash("sha256");
  let files = 0;
  let directories = 0;
  let bytes = 0;
  const visit = async (directory: string): Promise<void> => {
    const entries = await readdir(directory, { withFileTypes: true });
    entries.sort((left, right) => compareCodeUnits(left.name, right.name));
    for (const entry of entries) {
      const path = join(directory, entry.name);
      const relativePath = relative(base, path).split(sep).join("/");
      const metadata = await lstat(path);
      if (metadata.isSymbolicLink()) throw new Error(`Snapshot tree may not contain symlinks: ${path}`);
      if (metadata.isDirectory()) {
        directories += 1;
        digest.update("d\0");
        digest.update(relativePath);
        digest.update("\0");
        digest.update(String(metadata.mode & 0o777));
        digest.update("\n");
        await visit(path);
      } else if (metadata.isFile()) {
        files += 1;
        bytes += metadata.size;
        digest.update("f\0");
        digest.update(relativePath);
        digest.update("\0");
        digest.update(await fileSha256(path));
        digest.update("\0");
        digest.update(String(metadata.mode & 0o777));
        digest.update("\n");
      } else {
        throw new Error(`Snapshot tree contains unsupported file type: ${path}`);
      }
    }
  };
  await visit(base);
  return { files, directories, bytes, sha256: `sha256:${digest.digest("hex")}` };
}

async function fileSha256(path: string): Promise<string> {
  return `sha256:${createHash("sha256").update(await readFile(path)).digest("hex")}`;
}

async function removeSqliteSidecars(path: string): Promise<void> {
  await Promise.all([
    rm(`${path}-wal`, { force: true }),
    rm(`${path}-shm`, { force: true }),
  ]);
}

async function fsyncFile(path: string): Promise<void> {
  const handle = await open(path, "r");
  try {
    await handle.sync();
  } finally {
    await handle.close();
  }
}

async function fsyncDirectory(path: string): Promise<void> {
  const handle = await open(path, "r").catch((error: unknown) => {
    if (
      isNodeError(error, "EINVAL")
      || isNodeError(error, "ENOTSUP")
      || isNodeError(error, "EISDIR")
      || isNodeError(error, "EPERM")
    ) return undefined;
    throw error;
  });
  if (!handle) return;
  try {
    await handle.sync();
  } catch (error) {
    if (
      !isNodeError(error, "EINVAL")
      && !isNodeError(error, "ENOTSUP")
      && !isNodeError(error, "EISDIR")
      && !isNodeError(error, "EPERM")
    ) throw error;
  } finally {
    await handle.close();
  }
}

async function writeJsonAtomic(path: string, value: unknown, mode: number): Promise<void> {
  await mkdir(dirname(path), { recursive: true, mode: 0o700 });
  const temporary = join(dirname(path), `.${basename(path)}.${process.pid}.${randomUUID()}.tmp`);
  const handle = await open(temporary, "wx", mode);
  try {
    await writeFile(handle, `${JSON.stringify(value, null, 2)}\n`, "utf8");
    await handle.sync();
  } finally {
    await handle.close();
  }
  await chmod(temporary, mode);
  await rename(temporary, path);
  await fsyncDirectory(dirname(path));
}

function normalizeEntries(entries: readonly SnapshotGroupEntryRequest[]): NormalizedSnapshotEntry[] {
  if (!Array.isArray(entries) || entries.length < 1) {
    throw new Error("Snapshot group requires at least one store entry.");
  }
  const byId = new Set<string>();
  const byPath = new Set<string>();
  const normalized = entries.map((entry) => {
    if (!entry || !/^[a-z][a-z0-9-]{1,127}$/u.test(entry.id)) {
      throw new Error(`Invalid snapshot store id: ${String(entry?.id)}`);
    }
    if (!["sqlite", "file", "directory"].includes(entry.kind)) {
      throw new Error(`Invalid snapshot store kind for ${entry.id}: ${String(entry.kind)}`);
    }
    if (byId.has(entry.id)) throw new Error(`Duplicate snapshot store id: ${entry.id}`);
    byId.add(entry.id);
    const path = canonicalNoFollowPath(
      resolveAbsolutePath(entry.path, `snapshot store ${entry.id}`),
      `snapshot store ${entry.id}`,
    );
    if (byPath.has(path)) throw new Error(`Duplicate snapshot store path: ${path}`);
    byPath.add(path);
    if (entry.purpose !== undefined && (entry.purpose.length === 0 || entry.purpose.length > 512)) {
      throw new Error(`Invalid snapshot store purpose: ${entry.id}`);
    }
    return {
      ...entry,
      path,
      required: entry.required !== false,
    };
  });
  for (let left = 0; left < normalized.length; left += 1) {
    for (let right = left + 1; right < normalized.length; right += 1) {
      const leftTargets = snapshotEntryMutablePaths(normalized[left]!);
      const rightTargets = snapshotEntryMutablePaths(normalized[right]!);
      if (leftTargets.some((leftTarget) => (
        rightTargets.some((rightTarget) => pathsOverlapCanonical(leftTarget, rightTarget))
      ))) {
        throw new Error(
          `Snapshot stores overlap: ${normalized[left]!.id} and ${normalized[right]!.id}.`,
        );
      }
    }
  }
  return normalized;
}

function validateManifestEntry(
  entry: SnapshotGroupManifestEntry,
  snapshotRoot: string,
): SnapshotGroupManifestEntry {
  const [normalized] = normalizeEntries([entry]);
  if (entry.state !== "captured" && entry.state !== "absent") {
    throw new Error(`Invalid snapshot entry state: ${entry.id}`);
  }
  if (entry.state === "captured") {
    if (!entry.snapshotPath) throw new Error(`Captured snapshot entry has no snapshot path: ${entry.id}`);
    const snapshotPath = canonicalNoFollowPath(
      resolveAbsolutePath(entry.snapshotPath, `snapshot entry ${entry.id}`),
      `snapshot entry ${entry.id}`,
    );
    if (!isSameOrInside(snapshotRoot, snapshotPath)) {
      throw new Error(`Snapshot entry escapes snapshot root: ${entry.id}`);
    }
    if (entry.kind === "directory") {
      if (!entry.tree || !isSha256Digest(entry.tree.sha256)) throw new Error(`Directory snapshot tree is invalid: ${entry.id}`);
    } else if (!isSha256Digest(entry.sha256)) {
      throw new Error(`Snapshot file digest is invalid: ${entry.id}`);
    }
    return {
      ...entry,
      path: normalized.path,
      required: normalized.required,
      snapshotPath,
    };
  }
  return {
    id: normalized.id,
    kind: normalized.kind,
    path: normalized.path,
    required: normalized.required,
    state: "absent",
    ...(normalized.purpose ? { purpose: normalized.purpose } : {}),
  };
}

function assertSnapshotRootDoesNotOverlapStores(
  snapshotRoot: string,
  entries: readonly NormalizedSnapshotEntry[],
): void {
  for (const entry of entries) {
    if (snapshotEntryMutablePaths(entry).some((path) => pathsOverlapCanonical(path, snapshotRoot))) {
      throw new Error(`Snapshot root overlaps mutable store ${entry.id}: ${snapshotRoot}`);
    }
  }
}

function normalizeBarrier(barrier: SnapshotGroupBarrier, capturedAt: string): SnapshotGroupBarrier {
  if (!barrier || typeof barrier.kind !== "string" || !/^[A-Z][A-Z0-9_]{1,63}$/u.test(barrier.kind)) {
    throw new Error("Snapshot barrier kind is invalid.");
  }
  const establishedAt = normalizeTimestamp(barrier.establishedAt ?? capturedAt);
  if (Date.parse(establishedAt) > Date.parse(capturedAt)) {
    throw new Error("Snapshot capture may not precede its verified stop barrier.");
  }
  return {
    ...barrier,
    establishedAt,
  };
}

function resolveAbsoluteDirectory(path: string, name: string): string {
  const resolved = resolveAbsolutePath(path, name);
  if (resolved === resolve(sep)) throw new Error(`${name} may not be the filesystem root.`);
  return resolved;
}

function resolveAbsolutePath(path: string, name: string): string {
  if (typeof path !== "string" || path.length === 0 || path.includes("\0")) {
    throw new Error(`${name} path is invalid.`);
  }
  if (!isAbsolute(path)) throw new Error(`${name} path must be absolute: ${path}`);
  return resolve(path);
}

function temporaryPath(path: string): string {
  return join(dirname(path), `.${basename(path)}.restore-${process.pid}-${randomUUID()}`);
}

function isSameOrInside(parent: string, child: string): boolean {
  const relativePath = relative(resolve(parent), resolve(child));
  return relativePath === "" || (!relativePath.startsWith("..") && !isAbsolute(relativePath));
}

/**
 * Resolves a path through its nearest existing ancestor while rejecting every
 * symbolic-link component. Missing leaf components remain prospective but are
 * anchored to the real identity of their existing parent.
 */
export function canonicalNoFollowPath(path: string, label = "path"): string {
  const absolute = resolveAbsolutePath(path, label);
  const ancestors: string[] = [];
  let cursor = absolute;
  while (true) {
    ancestors.push(cursor);
    const parent = dirname(cursor);
    if (parent === cursor) break;
    cursor = parent;
  }
  ancestors.reverse();
  let nearestExisting = ancestors[0]!;
  let existingCount = 0;
  for (const ancestor of ancestors) {
    let metadata;
    try {
      metadata = lstatSync(ancestor);
    } catch (error) {
      if (isNodeError(error, "ENOENT")) break;
      throw error;
    }
    if (metadata.isSymbolicLink()) {
      throw new Error(`${label} contains a symbolic-link component: ${ancestor}`);
    }
    nearestExisting = ancestor;
    existingCount += 1;
  }
  const realAncestor = realpathSync(nearestExisting);
  const missingSegments = ancestors.slice(existingCount).map((ancestor) => basename(ancestor));
  return resolve(realAncestor, ...missingSegments);
}

export function canonicalPathsOverlap(left: string, right: string): boolean {
  return pathsOverlapCanonical(
    canonicalNoFollowPath(left, "left containment path"),
    canonicalNoFollowPath(right, "right containment path"),
  );
}

/**
 * Returns every filesystem identity that a snapshot restore may replace or
 * remove. SQLite WAL/SHM sidecars are part of the mutable preimage even when
 * they are absent at capture time.
 */
export function snapshotEntryMutablePaths(
  entry: Pick<SnapshotGroupEntryRequest, "kind" | "path">,
): readonly string[] {
  const path = canonicalNoFollowPath(
    resolveAbsolutePath(entry.path, "snapshot mutable path"),
    "snapshot mutable path",
  );
  if (entry.kind !== "sqlite") return [path];
  return [
    path,
    canonicalNoFollowPath(`${path}-wal`, "snapshot SQLite WAL path"),
    canonicalNoFollowPath(`${path}-shm`, "snapshot SQLite SHM path"),
  ];
}

function pathsOverlapCanonical(left: string, right: string): boolean {
  return isSameOrInside(left, right) || isSameOrInside(right, left);
}

function compareCodeUnits(left: string, right: string): number {
  return left < right ? -1 : left > right ? 1 : 0;
}

function normalizeTimestamp(value: string): string {
  const parsed = new Date(value);
  if (!Number.isFinite(parsed.getTime())) throw new Error(`Snapshot timestamp is invalid: ${value}`);
  return parsed.toISOString();
}

function digestJson(value: unknown): string {
  return `sha256:${createHash("sha256").update(stableJson(value)).digest("hex")}`;
}

function stableJson(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(stableJson).join(",")}]`;
  if (value && typeof value === "object") {
    const record = value as Record<string, unknown>;
    return `{${Object.keys(record)
      .filter((key) => record[key] !== undefined)
      .sort()
      .map((key) => `${JSON.stringify(key)}:${stableJson(record[key])}`)
      .join(",")}}`;
  }
  return JSON.stringify(value) ?? "null";
}

function isSha256Digest(value: unknown): value is string {
  return typeof value === "string" && /^sha256:[a-f0-9]{64}$/u.test(value);
}

function isNodeError(error: unknown, code: string): error is NodeJS.ErrnoException {
  return error instanceof Error && (error as NodeJS.ErrnoException).code === code;
}
