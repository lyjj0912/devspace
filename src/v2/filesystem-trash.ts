import { createHash, randomUUID } from "node:crypto";
import { createReadStream } from "node:fs";
import {
  cp,
  lstat,
  mkdir,
  open,
  readdir,
  readFile,
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
import {
  captureFilesystemPreimage,
  safeMoveFile,
  type AtomicPublicationHooks,
} from "./filesystem-atomic.js";

interface TrashMetadata {
  version: 1;
  trashId: string;
  originalPath: string;
  type: "file" | "directory" | "symlink";
  digest: string;
  createdAt: string;
  state: "RESERVED" | "AVAILABLE";
}

export class RecoverableFilesystemTrash {
  constructor(
    private readonly root: string,
    private readonly hooks?: AtomicPublicationHooks,
  ) {}

  async trash(
    source: string,
    recursive: boolean,
  ): Promise<Record<string, unknown>> {
    const sourceValue = await requiredLstat(source);
    const type = sourceValue.isFile()
      ? "file"
      : sourceValue.isDirectory() && !sourceValue.isSymbolicLink()
        ? "directory"
        : sourceValue.isSymbolicLink()
          ? "symlink"
          : undefined;
    if (!type) throw pathTypeMismatch(source, "file, directory, or symlink");
    if (type === "directory" && !recursive) {
      throw new UniversalBrokerError(
        "PRECONDITION_FAILED",
        `Directory removal requires recursive=true: ${source}`,
      );
    }

    await mkdir(this.root, { recursive: true, mode: 0o700 });
    const trashId = randomUUID();
    const entry = join(this.root, trashId);
    const payload = join(entry, "payload");
    await mkdir(entry, { mode: 0o700 });
    const digest = await pathDigest(source, type);
    const metadata: TrashMetadata = {
      version: 1,
      trashId,
      originalPath: source,
      type,
      digest,
      createdAt: new Date().toISOString(),
      state: "RESERVED",
    };
    await writeMetadata(entry, metadata);
    try {
      await moveRecoverably(source, payload, type, digest, this.hooks);
      metadata.state = "AVAILABLE";
      await writeMetadata(entry, metadata);
      await syncDirectory(this.root);
      return {
        path: source,
        removed: true,
        disposition: "trash",
        recoverable: true,
        trashId,
        restoreOperation: "restore",
      };
    } catch (error) {
      const sourceStillExists = (await captureFilesystemPreimage(source)).exists;
      if (sourceStillExists) await rm(entry, { recursive: true, force: true }).catch(() => undefined);
      throw error;
    }
  }

  async restore(input: {
    trashId: string;
    destination?: string;
    overwrite: boolean;
  }): Promise<Record<string, unknown>> {
    if (!/^[0-9a-f-]{36}$/iu.test(input.trashId)) {
      throw new UniversalBrokerError("PRECONDITION_FAILED", "Invalid trashId.");
    }
    const entry = join(this.root, input.trashId);
    const metadata = await readMetadata(entry);
    if (metadata.state !== "AVAILABLE" || metadata.trashId !== input.trashId) {
      throw new UniversalBrokerError("PRECONDITION_FAILED", "Trash entry is not restorable.");
    }
    const payload = join(entry, "payload");
    const destination = input.destination ?? metadata.originalPath;
    const actualDigest = await pathDigest(payload, metadata.type);
    if (actualDigest !== metadata.digest) {
      throw new UniversalBrokerError(
        "PRECONDITION_FAILED",
        "Trash payload integrity verification failed.",
        { evidence: { trashId: input.trashId, expectedDigest: metadata.digest, actualDigest } },
      );
    }
    const existing = await captureFilesystemPreimage(destination);
    if (existing.exists && !input.overwrite) {
      throw new UniversalBrokerError(
        "PRECONDITION_FAILED",
        `Restore destination exists: ${destination}`,
      );
    }
    if (metadata.type !== "file" && existing.exists) {
      throw new UniversalBrokerError(
        "CAPABILITY_UNAVAILABLE",
        "Atomic overwrite restore is supported only for regular files.",
      );
    }
    await mkdir(dirname(destination), { recursive: true, mode: 0o700 });
    await moveRecoverably(
      payload,
      destination,
      metadata.type,
      metadata.digest,
      this.hooks,
      input.overwrite,
    );
    await rm(entry, { recursive: true, force: true });
    await syncDirectory(this.root);
    return {
      trashId: input.trashId,
      restored: true,
      originalPath: metadata.originalPath,
      path: destination,
      sha256: metadata.digest,
    };
  }
}

async function moveRecoverably(
  source: string,
  destination: string,
  type: TrashMetadata["type"],
  expectedDigest: string,
  hooks?: AtomicPublicationHooks,
  overwrite = false,
): Promise<void> {
  if (type === "file") {
    const moved = await safeMoveFile(source, destination, { overwrite, hooks });
    if (moved.sha256 !== expectedDigest) {
      throw new UniversalBrokerError(
        "PRECONDITION_FAILED",
        "Moved file failed trash integrity verification.",
      );
    }
    return;
  }
  if (type === "symlink") {
    if ((await captureFilesystemPreimage(destination)).exists) {
      throw new UniversalBrokerError("PRECONDITION_FAILED", `Destination exists: ${destination}`);
    }
    const target = await readlink(source);
    await symlink(target, destination);
    if (await pathDigest(destination, type) !== expectedDigest) {
      await unlink(destination).catch(() => undefined);
      throw new UniversalBrokerError("PRECONDITION_FAILED", "Symlink copy verification failed.");
    }
    await unlink(source);
    return;
  }

  if ((await captureFilesystemPreimage(destination)).exists) {
    throw new UniversalBrokerError("PRECONDITION_FAILED", `Destination exists: ${destination}`);
  }
  try {
    if (hooks?.forceCrossDevice) throw nodeError("EXDEV", "forced EXDEV");
    await rename(source, destination);
    return;
  } catch (error) {
    if (!isNodeError(error, "EXDEV")) throw error;
  }
  await cp(source, destination, {
    recursive: true,
    force: false,
    errorOnExist: true,
    dereference: false,
    preserveTimestamps: true,
  });
  await hooks?.afterCrossDevicePublication?.({ source, destination });
  const [sourceDigest, destinationDigest] = await Promise.all([
    pathDigest(source, type),
    pathDigest(destination, type),
  ]);
  if (sourceDigest !== expectedDigest || destinationDigest !== expectedDigest) {
    throw new UniversalBrokerError(
      "PRECONDITION_FAILED",
      "Cross-device directory move verification failed; the source was preserved.",
      { evidence: { source, destination, sourceDigest, destinationDigest, expectedDigest } },
    );
  }
  await rm(source, { recursive: true, force: false });
}

async function pathDigest(path: string, type: TrashMetadata["type"]): Promise<string> {
  if (type === "file") return sha256File(path);
  if (type === "symlink") {
    return createHash("sha256").update(`symlink\0${await readlink(path)}`).digest("hex");
  }
  const digest = createHash("sha256");
  const walk = async (directory: string, relative: string): Promise<void> => {
    const entries = (await readdir(directory, { withFileTypes: true }))
      .sort((left, right) => left.name.localeCompare(right.name));
    for (const entry of entries) {
      const child = join(directory, entry.name);
      const childRelative = relative ? `${relative}/${entry.name}` : entry.name;
      if (entry.isDirectory()) {
        digest.update(`d\0${childRelative}\0`);
        await walk(child, childRelative);
      } else if (entry.isFile()) {
        digest.update(`f\0${childRelative}\0${await sha256File(child)}\0`);
      } else if (entry.isSymbolicLink()) {
        digest.update(`l\0${childRelative}\0${await readlink(child)}\0`);
      } else {
        throw pathTypeMismatch(child, "file, directory, or symlink");
      }
    }
  };
  await walk(path, "");
  return digest.digest("hex");
}

async function writeMetadata(entry: string, metadata: TrashMetadata): Promise<void> {
  const destination = join(entry, "metadata.json");
  const temporary = join(entry, `.metadata-${randomUUID()}.tmp`);
  try {
    await writeFile(temporary, `${JSON.stringify(metadata)}\n`, { flag: "wx", mode: 0o600 });
    const handle = await open(temporary, "r");
    try {
      await handle.sync();
    } finally {
      await handle.close();
    }
    await rename(temporary, destination);
    await syncDirectory(entry);
  } finally {
    await rm(temporary, { force: true }).catch(() => undefined);
  }
}

async function readMetadata(entry: string): Promise<TrashMetadata> {
  try {
    const parsed = JSON.parse(await readFile(join(entry, "metadata.json"), "utf8")) as TrashMetadata;
    if (
      parsed.version !== 1
      || typeof parsed.originalPath !== "string"
      || !["file", "directory", "symlink"].includes(parsed.type)
      || typeof parsed.digest !== "string"
    ) {
      throw new Error("invalid trash metadata");
    }
    return parsed;
  } catch (error) {
    if (isNodeError(error, "ENOENT")) {
      throw new UniversalBrokerError("PATH_NOT_FOUND", "Trash entry was not found.");
    }
    throw new UniversalBrokerError(
      "PRECONDITION_FAILED",
      "Trash metadata is invalid.",
      { evidence: { error: errorMessage(error) } },
    );
  }
}

async function requiredLstat(path: string) {
  try {
    return await lstat(path);
  } catch (error) {
    if (isNodeError(error, "ENOENT")) {
      throw new UniversalBrokerError("PATH_NOT_FOUND", `Path not found: ${path}`);
    }
    throw error;
  }
}

async function sha256File(path: string): Promise<string> {
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
    // Directory fsync is unavailable on some Windows/network filesystems.
  }
}

function pathTypeMismatch(path: string, expected: string): UniversalBrokerError {
  return new UniversalBrokerError(
    "PATH_TYPE_MISMATCH",
    `Expected ${expected}: ${path}`,
    { evidence: { path, expected } },
  );
}

function nodeError(code: string, message: string): NodeJS.ErrnoException {
  return Object.assign(new Error(message), { code });
}

function isNodeError(error: unknown, code: string): error is NodeJS.ErrnoException {
  return error instanceof Error && (error as NodeJS.ErrnoException).code === code;
}

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}
