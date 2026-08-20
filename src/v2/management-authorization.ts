import { createHash, randomBytes, timingSafeEqual } from "node:crypto";
import {
  chmodSync,
  closeSync,
  constants,
  fsyncSync,
  lstatSync,
  mkdirSync,
  openSync,
  readFileSync,
  unlinkSync,
  writeFileSync,
} from "node:fs";
import { dirname, isAbsolute, join, resolve } from "node:path";

const REFERENCE_PATTERN = /^[A-Za-z][A-Za-z0-9._-]{0,127}$/u;
const KEY_TEXT_PATTERN = /^[A-Za-z0-9_-]{43}$/u;
const HEADER_PATTERN = /^Bearer devspace-management-v1\.([A-Za-z0-9_-]{43})$/u;
const KEY_BYTES = 32;

export interface ManagementAuthorizationKey {
  keyId: `management-${string}`;
  secret: Uint8Array;
  path: string;
}

export function loadOrCreateManagementAuthorizationKey(input: {
  keyRef: string;
  stateDir: string;
}): ManagementAuthorizationKey {
  const path = resolveManagementAuthorizationKeyReference(input.keyRef, input.stateDir);
  try {
    return loadExistingManagementAuthorizationKey({ keyRef: path, stateDir: input.stateDir });
  } catch (error) {
    if (!isMissing(error)) throw error;
  }
  mkdirSync(dirname(path), { recursive: true, mode: 0o700 });
  chmodSync(dirname(path), 0o700);
  const encoded = randomBytes(KEY_BYTES).toString("base64url");
  let descriptor: number | undefined;
  try {
    descriptor = openSync(path, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL, 0o600);
    writeFileSync(descriptor, `${encoded}\n`, "utf8");
    fsyncSync(descriptor);
    closeSync(descriptor);
    descriptor = undefined;
    fsyncDirectory(dirname(path));
  } catch (error) {
    if (descriptor !== undefined) closeSync(descriptor);
    if (!isAlreadyExists(error)) {
      try {
        unlinkSync(path);
      } catch {
        // The key may not have been created or another process may own the winning file.
      }
      throw error;
    }
  }
  return loadExistingManagementAuthorizationKey({ keyRef: path, stateDir: input.stateDir });
}

export function loadExistingManagementAuthorizationKey(input: {
  keyRef: string;
  stateDir: string;
}): ManagementAuthorizationKey {
  const path = resolveManagementAuthorizationKeyReference(input.keyRef, input.stateDir);
  const metadata = lstatSync(path);
  if (!metadata.isFile() || metadata.isSymbolicLink()) {
    throw new Error("Management authorization key must be an owner-only regular file, not a symlink.");
  }
  if ((metadata.mode & 0o077) !== 0 || (metadata.mode & 0o400) === 0) {
    throw new Error("Management authorization key must be readable only by its owner.");
  }
  if (typeof process.getuid === "function" && metadata.uid !== process.getuid()) {
    throw new Error("Management authorization key must be owned by the broker service user.");
  }
  const text = readFileSync(path, "utf8").trim();
  if (!KEY_TEXT_PATTERN.test(text)) {
    throw new Error("Management authorization key file does not contain one canonical 256-bit key.");
  }
  const secret = Buffer.from(text, "base64url");
  if (secret.length !== KEY_BYTES || secret.toString("base64url") !== text) {
    throw new Error("Management authorization key file does not contain one canonical 256-bit key.");
  }
  return Object.freeze({
    keyId: `management-${createHash("sha256").update(secret).digest("hex").slice(0, 24)}`,
    secret: Uint8Array.from(secret),
    path,
  });
}

export function managementAuthorizationHeader(key: ManagementAuthorizationKey): string {
  return `Bearer devspace-management-v1.${Buffer.from(key.secret).toString("base64url")}`;
}

export function isManagementAuthorized(
  authorizationHeader: string | undefined,
  key: ManagementAuthorizationKey,
): boolean {
  if (!authorizationHeader || authorizationHeader.length > 256) return false;
  const match = HEADER_PATTERN.exec(authorizationHeader);
  if (!match) return false;
  const candidate = Buffer.from(match[1]!, "base64url");
  const expected = Buffer.from(key.secret);
  return candidate.length === expected.length && timingSafeEqual(candidate, expected);
}

export function resolveManagementAuthorizationKeyReference(
  reference: string,
  stateDir: string,
): string {
  const normalized = reference.trim();
  if (!normalized || /[\r\n\0]/u.test(normalized)) {
    throw new Error("Management authorization key reference is missing or invalid.");
  }
  if (isAbsolute(normalized)) return resolve(normalized);
  if (!REFERENCE_PATTERN.test(normalized)) {
    throw new Error("Relative management authorization key references must be bounded logical names.");
  }
  return join(resolve(stateDir), "secret-refs", `${normalized}.key`);
}

function fsyncDirectory(path: string): void {
  const descriptor = openSync(path, constants.O_RDONLY);
  try {
    fsyncSync(descriptor);
  } finally {
    closeSync(descriptor);
  }
}

function isMissing(error: unknown): boolean {
  return (error as NodeJS.ErrnoException | undefined)?.code === "ENOENT";
}

function isAlreadyExists(error: unknown): boolean {
  return (error as NodeJS.ErrnoException | undefined)?.code === "EEXIST";
}
