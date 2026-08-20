import { createHash, randomUUID } from "node:crypto";
import { constants as fsConstants, createReadStream, type PathLike, type Stats } from "node:fs";
import {
  chmod,
  copyFile,
  cp,
  link,
  lstat,
  open,
  readlink,
  rename,
  rm,
  stat,
  symlink,
  unlink,
  writeFile,
} from "node:fs/promises";
import { basename, dirname, join } from "node:path";
import { pipeline } from "node:stream/promises";
import { UniversalBrokerError } from "./errors.js";

export interface FilesystemPreimage {
  exists: boolean;
  type?: "file" | "directory" | "symlink" | "other";
  device?: number;
  inode?: number;
  mode?: number;
  size?: number;
  mtimeMs?: number;
  ctimeMs?: number;
  sha256?: string;
  linkTarget?: string;
}

export interface AtomicFilesystemOperations {
  chmod: typeof chmod;
  copyFile: typeof copyFile;
  cp: typeof cp;
  link: typeof link;
  lstat: (path: PathLike) => Promise<Stats>;
  open: typeof open;
  readlink: typeof readlink;
  rename: typeof rename;
  rm: typeof rm;
  stat: (path: PathLike) => Promise<Stats>;
  symlink: typeof symlink;
  unlink: typeof unlink;
  writeFile: typeof writeFile;
}

export const nodeAtomicFilesystemOperations: AtomicFilesystemOperations = {
  chmod,
  copyFile,
  cp,
  link,
  lstat,
  open,
  readlink,
  rename,
  rm,
  stat,
  symlink,
  unlink,
  writeFile,
};

export interface AtomicPublishOptions {
  overwrite: boolean;
  expectedSha256?: string;
  allowReplaceSymlink?: boolean;
  mode?: number;
  filesystem?: AtomicFilesystemOperations;
}

export interface AtomicPublicationResult {
  path: string;
  size: number;
  sha256: string;
  overwritten: boolean;
  preimage: FilesystemPreimage;
}

/**
 * Capture enough identity to reject a destination changed while bytes were staged.
 * File contents are hashed so same-inode rewrites do not evade the fence.
 */
export async function captureFilesystemPreimage(
  path: string,
  filesystem: AtomicFilesystemOperations = nodeAtomicFilesystemOperations,
): Promise<FilesystemPreimage> {
  let value;
  try {
    value = await filesystem.lstat(path);
  } catch (error) {
    if (isNodeError(error, "ENOENT")) return { exists: false };
    throw error;
  }
  const type = value.isFile()
    ? "file"
    : value.isDirectory()
      ? "directory"
      : value.isSymbolicLink()
        ? "symlink"
        : "other";
  return {
    exists: true,
    type,
    device: value.dev,
    inode: value.ino,
    mode: value.mode & 0o7777,
    size: value.size,
    mtimeMs: value.mtimeMs,
    ctimeMs: value.ctimeMs,
    ...(type === "file" ? { sha256: await sha256File(path) } : {}),
    ...(type === "symlink" ? { linkTarget: await filesystem.readlink(path) } : {}),
  };
}

export function filesystemPreimagesEqual(
  left: FilesystemPreimage,
  right: FilesystemPreimage,
): boolean {
  return left.exists === right.exists
    && left.type === right.type
    && left.device === right.device
    && left.inode === right.inode
    && left.mode === right.mode
    && left.size === right.size
    && left.mtimeMs === right.mtimeMs
    && left.ctimeMs === right.ctimeMs
    && left.sha256 === right.sha256
    && left.linkTarget === right.linkTarget;
}

export async function atomicWriteBuffer(
  destination: string,
  content: Buffer,
  options: AtomicPublishOptions,
): Promise<AtomicPublicationResult> {
  return atomicPublishFile(destination, options, async (temporary) => {
    await (options.filesystem ?? nodeAtomicFilesystemOperations)
      .writeFile(temporary, content, { flag: "wx", mode: options.mode ?? 0o600 });
  });
}

export async function atomicCopyFile(
  source: string,
  destination: string,
  options: AtomicPublishOptions,
): Promise<AtomicPublicationResult> {
  const filesystem = options.filesystem ?? nodeAtomicFilesystemOperations;
  const sourcePreimage = await captureFilesystemPreimage(source, filesystem);
  if (!sourcePreimage.exists) throw pathNotFound(source);
  if (sourcePreimage.type !== "file" || !sourcePreimage.sha256) {
    throw pathTypeMismatch(source, "file");
  }
  const result = await atomicPublishFile(destination, options, async (temporary) => {
    await filesystem.copyFile(source, temporary, fsConstants.COPYFILE_EXCL);
    const copiedSha256 = await sha256File(temporary);
    const sourceAfterCopy = await captureFilesystemPreimage(source, filesystem);
    if (
      copiedSha256 !== sourcePreimage.sha256
      || !filesystemPreimagesEqual(sourcePreimage, sourceAfterCopy)
    ) {
      throw new UniversalBrokerError(
        "PRECONDITION_FAILED",
        `Source changed while it was copied: ${source}`,
        { evidence: { source, expectedSha256: sourcePreimage.sha256, actualSha256: copiedSha256 } },
      );
    }
  });
  if (result.sha256 !== sourcePreimage.sha256 || result.size !== sourcePreimage.size) {
    throw new UniversalBrokerError(
      "PRECONDITION_FAILED",
      `Destination verification failed after copying ${source}.`,
      {
        evidence: {
          source,
          destination,
          sourceSha256: sourcePreimage.sha256,
          destinationSha256: result.sha256,
          sourceSize: sourcePreimage.size,
          destinationSize: result.size,
        },
      },
    );
  }
  return result;
}

/**
 * Move a regular file without deleting the destination first. On EXDEV, the
 * source remains present until a staged destination copy passes hash/size and
 * source-preimage verification.
 */
export async function safeMoveFile(
  source: string,
  destination: string,
  options: AtomicPublishOptions,
): Promise<AtomicPublicationResult & { crossDevice: boolean }> {
  const filesystem = options.filesystem ?? nodeAtomicFilesystemOperations;
  const sourcePreimage = await captureFilesystemPreimage(source, filesystem);
  if (!sourcePreimage.exists) throw pathNotFound(source);
  if (sourcePreimage.type !== "file" || !sourcePreimage.sha256) {
    throw pathTypeMismatch(source, "file");
  }
  const destinationPreimage = await captureFilesystemPreimage(destination, filesystem);
  validateDestinationPreimage(destination, destinationPreimage, options);
  const quarantine = join(
    dirname(source),
    `.devspace-v2-move-${basename(source)}-${randomUUID()}.tmp`,
  );
  try {
    await quarantineVerifiedMoveSource(
      source,
      destination,
      quarantine,
      sourcePreimage,
      filesystem,
    );
    try {
      let removeQuarantineAfterVerification = false;
      await assertMoveSourceUnchanged(quarantine, sourcePreimage, filesystem);
      await assertDestinationUnchanged(destination, destinationPreimage, filesystem);
      if (!destinationPreimage.exists) {
        let sourceMoved = false;
        try {
          await filesystem.link(quarantine, destination);
        } catch (error) {
          if (isNodeError(error, "EXDEV")) throw error;
          if (!isHardLinkUnsupported(error)) throw error;
          if (!options.overwrite) throw noReplaceCapabilityUnavailable(destination, error);
          await filesystem.rename(quarantine, destination);
          sourceMoved = true;
        }
        removeQuarantineAfterVerification = !sourceMoved;
      } else {
        await filesystem.rename(quarantine, destination);
      }
      await syncDirectory(dirname(destination));
      const published = await verifyPublishedFile(
        destination,
        sourcePreimage.sha256,
        sourcePreimage.size!,
        filesystem,
      );
      const publishedIdentity = await captureFilesystemPreimage(destination, filesystem);
      if (!filesystemMoveSourceIdentitiesEqual(sourcePreimage, publishedIdentity)) {
        throw new UniversalBrokerError(
          "PRECONDITION_FAILED",
          "Move destination identity does not match the verified source.",
          {
            evidence: {
              source,
              destination,
              quarantine,
              expectedDevice: sourcePreimage.device,
              expectedInode: sourcePreimage.inode,
              actualDevice: publishedIdentity.device,
              actualInode: publishedIdentity.inode,
              expectedSha256: sourcePreimage.sha256,
              actualSha256: publishedIdentity.sha256,
            },
          },
        );
      }
      if (removeQuarantineAfterVerification) {
        await filesystem.unlink(quarantine);
        await syncDirectory(dirname(source));
      }
      return {
        ...published,
        overwritten: destinationPreimage.exists,
        preimage: destinationPreimage,
        crossDevice: false,
      };
    } catch (error) {
      if (!isNodeError(error, "EXDEV")) throw error;
    }

    await assertMoveSourceUnchanged(quarantine, sourcePreimage, filesystem);
    const published = await atomicCopyFile(quarantine, destination, options);
    const publishedDestinationIdentity = await captureFilesystemPreimage(destination, filesystem);
    // Keep the destination readback last. If the two reads run concurrently, a
    // destination replacement can complete after its read but during the
    // quarantine read, causing us to delete the final verified source copy.
    const sourceBeforeDelete = await captureFilesystemPreimage(quarantine, filesystem);
    const destinationBeforeDelete = await captureFilesystemPreimage(destination, filesystem);
    if (
      !filesystemMoveSourceIdentitiesEqual(sourcePreimage, sourceBeforeDelete)
      || !filesystemPublishedDestinationIdentitiesEqual(
        publishedDestinationIdentity,
        destinationBeforeDelete,
      )
    ) {
      throw new UniversalBrokerError(
        "PRECONDITION_FAILED",
        "Cross-device move verification failed; the source was preserved.",
        {
          evidence: {
            source,
            destination,
            sourcePreserved: sourceBeforeDelete.exists,
            quarantine: sourceBeforeDelete.exists ? quarantine : undefined,
            expectedSha256: sourcePreimage.sha256,
            destinationSha256: destinationBeforeDelete.sha256,
          },
        },
      );
    }
    await filesystem.unlink(quarantine);
    await syncDirectory(dirname(source));
    return { ...published, crossDevice: true };
  } catch (error) {
    const recovery = await recoverQuarantinedSource(
      quarantine,
      source,
      sourcePreimage,
      filesystem,
    );
    if (recovery.publicSourceRestored && !recovery.quarantineRetained) {
      throw error;
    }
    const original = error instanceof UniversalBrokerError ? error : undefined;
    const sourcePreservedAtQuarantine = recovery.quarantineRetained
      && recovery.quarantineIdentityMatches;
    throw new UniversalBrokerError(
      sourcePreservedAtQuarantine
        ? (original?.code ?? "PRECONDITION_FAILED")
        : "PRECONDITION_FAILED",
      sourcePreservedAtQuarantine
        ? `${original?.message ?? "Move publication failed."} The verified source remains recoverable at ${quarantine}.`
        : `${original?.message ?? "Move publication failed."} Automatic source recovery could not verify the original bytes.`,
      {
        operationId: original?.operationId,
        retryable: false,
        evidence: {
          ...(original?.evidence ?? {}),
          source,
          destination,
          quarantine,
          sourcePreservedAtQuarantine,
          publicSourceRestored: recovery.publicSourceRestored,
          publicSourceIdentityMatches: recovery.publicSourceIdentityMatches,
          quarantineRetained: recovery.quarantineRetained,
          quarantineIdentityMatches: recovery.quarantineIdentityMatches,
          ...(recovery.recoveryError ? { recoveryError: recovery.recoveryError } : {}),
          originalErrorCode: original?.code ?? "UNKNOWN_ERROR",
        },
        ...(sourcePreservedAtQuarantine ? {
          suggestions: [{
            action: recovery.publicSourceRestored
              ? "verify-and-remove-quarantine"
              : "restore-quarantined-source",
            source: quarantine,
            destination: source,
            overwrite: false,
          }],
        } : {}),
      },
    );
  }
}

async function atomicPublishFile(
  destination: string,
  options: AtomicPublishOptions,
  stage: (temporary: string) => Promise<void>,
): Promise<AtomicPublicationResult> {
  const filesystem = options.filesystem ?? nodeAtomicFilesystemOperations;
  const parent = dirname(destination);
  const parentMetadata = await filesystem.stat(parent);
  if (!parentMetadata.isDirectory()) throw pathTypeMismatch(parent, "directory");
  const preimage = await captureFilesystemPreimage(destination, filesystem);
  validateDestinationPreimage(destination, preimage, options);
  const mode = options.mode ?? (preimage.type === "file" ? preimage.mode : undefined) ?? 0o600;
  const temporary = join(
    parent,
    `.devspace-v2-${basename(destination)}-${randomUUID()}.tmp`,
  );
  let published = false;
  try {
    await stage(temporary);
    await filesystem.chmod(temporary, mode);
    const staged = await filesystem.stat(temporary);
    if (!staged.isFile()) throw pathTypeMismatch(temporary, "file");
    const stagedSha256 = await sha256File(temporary);
    const handle = await filesystem.open(temporary, "r");
    try {
      await handle.sync();
    } finally {
      await handle.close();
    }
    await assertDestinationUnchanged(destination, preimage, filesystem);

    if (!preimage.exists) {
      // A hard-link publication gives POSIX/Windows file systems a real
      // no-clobber primitive. Filesystems such as exFAT may not support hard
      // links; only explicit overwrite permission permits atomic rename there.
      try {
        await filesystem.link(temporary, destination);
      } catch (error) {
        if (!isHardLinkUnsupported(error)) throw error;
        if (!options.overwrite) throw noReplaceCapabilityUnavailable(destination, error);
        await filesystem.rename(temporary, destination);
      }
      published = true;
      await filesystem.rm(temporary, { force: true });
    } else {
      // rename replaces the final directory entry atomically; the old entry is
      // never removed first and therefore cannot expose a missing-path window.
      await filesystem.rename(temporary, destination);
    }
    published = true;
    await syncDirectory(parent);
    const readback = await verifyPublishedFile(
      destination,
      stagedSha256,
      staged.size,
      filesystem,
    );
    return {
      ...readback,
      overwritten: preimage.exists,
      preimage,
    };
  } finally {
    if (!published) await filesystem.rm(temporary, { force: true }).catch(() => undefined);
  }
}

function isHardLinkUnsupported(error: unknown): boolean {
  return ["ENOTSUP", "EOPNOTSUPP", "ENOSYS", "EPERM"].some((code) => isNodeError(error, code));
}

function noReplaceCapabilityUnavailable(
  destination: string,
  cause: unknown,
): UniversalBrokerError {
  return new UniversalBrokerError(
    "CAPABILITY_UNAVAILABLE",
    `This filesystem cannot atomically publish a new file without overwrite permission: ${destination}`,
    {
      evidence: {
        destination,
        overwrite: false,
        requiredCapability: "atomic-no-replace",
        filesystemError: cause instanceof Error ? cause.message : String(cause),
      },
    },
  );
}

interface QuarantinedSourceRecovery {
  publicSourceRestored: boolean;
  publicSourceIdentityMatches: boolean;
  quarantineRetained: boolean;
  quarantineIdentityMatches: boolean;
  recoveryError?: string;
}

async function recoverQuarantinedSource(
  quarantine: string,
  source: string,
  expected: FilesystemPreimage,
  filesystem: AtomicFilesystemOperations,
): Promise<QuarantinedSourceRecovery> {
  let recoveryError: string | undefined;
  const initialSource = await inspectRecoveryPath(source, expected, filesystem);
  const initialQuarantine = await inspectRecoveryPath(quarantine, expected, filesystem);

  if (!initialSource.exists && initialQuarantine.identityMatches) {
    try {
      await filesystem.link(quarantine, source);
    } catch (error) {
      recoveryError = error instanceof Error ? error.message : String(error);
    }
  }

  const [finalSource, finalQuarantine] = await Promise.all([
    inspectRecoveryPath(source, expected, filesystem),
    inspectRecoveryPath(quarantine, expected, filesystem),
  ]);
  return {
    publicSourceRestored: finalSource.identityMatches,
    publicSourceIdentityMatches: finalSource.identityMatches,
    quarantineRetained: finalQuarantine.exists,
    quarantineIdentityMatches: finalQuarantine.identityMatches,
    ...(recoveryError ? { recoveryError } : {}),
  };
}

async function quarantineVerifiedMoveSource(
  source: string,
  destination: string,
  quarantine: string,
  sourcePreimage: FilesystemPreimage,
  filesystem: AtomicFilesystemOperations,
): Promise<void> {
  await filesystem.rename(source, quarantine);
  const quarantinedSource = await captureFilesystemPreimage(quarantine, filesystem);
  if (!filesystemMoveSourceIdentitiesEqual(sourcePreimage, quarantinedSource)) {
    throw new UniversalBrokerError(
      "PRECONDITION_FAILED",
      "Move source changed before verified deletion; the replacement was not deleted.",
      {
        evidence: {
          source,
          destination,
          quarantine,
        },
      },
    );
  }
}

async function assertMoveSourceUnchanged(
  quarantine: string,
  expected: FilesystemPreimage,
  filesystem: AtomicFilesystemOperations = nodeAtomicFilesystemOperations,
): Promise<void> {
  const observed = await captureFilesystemPreimage(quarantine, filesystem);
  if (filesystemMoveSourceIdentitiesEqual(expected, observed)) return;
  throw new UniversalBrokerError(
    "PRECONDITION_FAILED",
    "Move source quarantine changed before publication.",
    { evidence: { quarantine, expectedSha256: expected.sha256, actualSha256: observed.sha256 } },
  );
}

async function inspectRecoveryPath(
  path: string,
  expected: FilesystemPreimage,
  filesystem: AtomicFilesystemOperations,
): Promise<{ exists: boolean; identityMatches: boolean }> {
  try {
    const observed = await captureFilesystemPreimage(path, filesystem);
    return {
      exists: observed.exists,
      identityMatches: filesystemMoveSourceIdentitiesEqual(expected, observed),
    };
  } catch {
    const exists = await filesystem.lstat(path).then(() => true, () => false);
    return { exists, identityMatches: false };
  }
}

function filesystemMoveSourceIdentitiesEqual(
  expected: FilesystemPreimage,
  observed: FilesystemPreimage,
): boolean {
  return expected.exists === true
    && observed.exists === true
    && expected.type === "file"
    && observed.type === "file"
    && expected.device === observed.device
    && expected.inode === observed.inode
    && expected.mode === observed.mode
    && expected.size === observed.size
    && expected.sha256 === observed.sha256;
}

function filesystemPublishedDestinationIdentitiesEqual(
  expected: FilesystemPreimage,
  observed: FilesystemPreimage,
): boolean {
  return expected.exists === true
    && observed.exists === true
    && expected.type === "file"
    && observed.type === "file"
    && expected.device === observed.device
    && expected.inode === observed.inode
    && expected.mode === observed.mode
    && expected.size === observed.size
    && expected.sha256 === observed.sha256;
}

function validateDestinationPreimage(
  destination: string,
  preimage: FilesystemPreimage,
  options: AtomicPublishOptions,
): void {
  if (preimage.type === "symlink" && !options.allowReplaceSymlink) {
    throw new UniversalBrokerError(
      "PERMISSION_DENIED",
      `Refusing final symlink publication without finalSymlink=replace: ${destination}`,
      { evidence: { destination, finalSymlink: "reject" } },
    );
  }
  if (preimage.exists && !["file", "symlink"].includes(preimage.type ?? "")) {
    throw pathTypeMismatch(destination, "file");
  }
  if (preimage.exists && !options.overwrite) {
    throw new UniversalBrokerError(
      "PRECONDITION_FAILED",
      `Destination already exists and overwrite is false: ${destination}`,
      { evidence: { destination, overwrite: false } },
    );
  }
  if (options.expectedSha256) {
    if (
      preimage.type !== "file"
      || preimage.sha256?.toLowerCase() !== options.expectedSha256.toLowerCase()
    ) {
      throw new UniversalBrokerError(
        "PRECONDITION_FAILED",
        `SHA-256 precondition failed for ${destination}.`,
        {
          evidence: {
            destination,
            expectedSha256: options.expectedSha256,
            actualSha256: preimage.sha256,
          },
        },
      );
    }
  }
}

async function assertDestinationUnchanged(
  destination: string,
  preimage: FilesystemPreimage,
  filesystem: AtomicFilesystemOperations,
): Promise<void> {
  const current = await captureFilesystemPreimage(destination, filesystem);
  if (filesystemPreimagesEqual(preimage, current)) return;
  throw new UniversalBrokerError(
    "PRECONDITION_FAILED",
    `Destination changed while bytes were staged: ${destination}`,
    { evidence: { destination, expectedPreimage: preimage, actualPreimage: current } },
  );
}

async function verifyPublishedFile(
  destination: string,
  expectedSha256: string,
  expectedSize: number,
  filesystem: AtomicFilesystemOperations = nodeAtomicFilesystemOperations,
): Promise<Pick<AtomicPublicationResult, "path" | "size" | "sha256">> {
  const readback = await captureFilesystemPreimage(destination, filesystem);
  if (
    readback.type !== "file"
    || readback.sha256 !== expectedSha256
    || readback.size !== expectedSize
  ) {
    throw new UniversalBrokerError(
      "PRECONDITION_FAILED",
      `Post-publication readback failed for ${destination}.`,
      {
        evidence: {
          destination,
          expectedSha256,
          actualSha256: readback.sha256,
          expectedSize,
          actualSize: readback.size,
        },
      },
    );
  }
  return { path: destination, size: expectedSize, sha256: expectedSha256 };
}

export async function sha256File(path: string): Promise<string> {
  const digest = createHash("sha256");
  await pipeline(createReadStream(path), digest);
  return digest.digest("hex");
}

async function syncDirectory(path: string): Promise<void> {
  try {
    const handle = await open(path, "r");
    try {
      await handle.sync();
    } finally {
      await handle.close();
    }
  } catch {
    // Windows and some network filesystems do not expose directory fsync.
  }
}

function pathNotFound(path: string): UniversalBrokerError {
  return new UniversalBrokerError(
    "PATH_NOT_FOUND",
    `Path not found: ${path}`,
    { evidence: { path } },
  );
}

function pathTypeMismatch(path: string, expected: string): UniversalBrokerError {
  return new UniversalBrokerError(
    "PATH_TYPE_MISMATCH",
    `Expected ${expected}: ${path}`,
    { evidence: { path, expected } },
  );
}

function isNodeError(error: unknown, code: string): error is NodeJS.ErrnoException {
  return error instanceof Error && (error as NodeJS.ErrnoException).code === code;
}
