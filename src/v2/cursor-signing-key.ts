import { createHash, randomBytes } from "node:crypto";
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
import type { CursorSigningKey } from "./cursor-capability.js";

const REFERENCE_PATTERN = /^[A-Za-z][A-Za-z0-9._-]{0,127}$/u;
const KEY_TEXT_PATTERN = /^[A-Za-z0-9_-]{43}$/u;
const KEY_BYTES = 32;

export interface CursorSigningKeyRing {
  currentKey: CursorSigningKey;
  previousKey?: CursorSigningKey;
  currentPath: string;
  previousPath?: string;
}

export function loadCursorSigningKeyRing(input: {
  currentKeyRef: string;
  previousKeyRef?: string;
  stateDir: string;
}): CursorSigningKeyRing {
  const currentPath = resolveCursorSigningKeyReference(input.currentKeyRef, input.stateDir);
  const previousPath = input.previousKeyRef
    ? resolveCursorSigningKeyReference(input.previousKeyRef, input.stateDir)
    : undefined;
  if (previousPath === currentPath) {
    throw new Error("Cursor current and previous signing key references must differ.");
  }
  const currentKey = loadOrCreateSigningKey(currentPath);
  const previousKey = previousPath ? loadExistingSigningKey(previousPath) : undefined;
  if (previousKey?.keyId === currentKey.keyId) {
    throw new Error("Cursor current and previous signing keys must contain different key material.");
  }
  return Object.freeze({
    currentKey,
    ...(previousKey ? { previousKey } : {}),
    currentPath,
    ...(previousPath ? { previousPath } : {}),
  });
}

export function resolveCursorSigningKeyReference(reference: string, stateDir: string): string {
  const normalized = reference.trim();
  if (!normalized || /[\r\n\0]/u.test(normalized)) {
    throw new Error("Cursor signing key reference is missing or invalid.");
  }
  if (isAbsolute(normalized)) return resolve(normalized);
  if (!REFERENCE_PATTERN.test(normalized)) {
    throw new Error("Relative cursor signing key references must be bounded logical names.");
  }
  return join(resolve(stateDir), "secret-refs", `${normalized}.key`);
}

function loadOrCreateSigningKey(path: string): CursorSigningKey {
  try {
    return loadExistingSigningKey(path);
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
        // The key may never have been created or another process may own the winning file.
      }
      throw error;
    }
  }
  return loadExistingSigningKey(path);
}

function loadExistingSigningKey(path: string): CursorSigningKey {
  const metadata = lstatSync(path);
  if (!metadata.isFile() || metadata.isSymbolicLink()) {
    throw new Error("Cursor signing key must be an owner-only regular file, not a symlink.");
  }
  if ((metadata.mode & 0o077) !== 0 || (metadata.mode & 0o400) === 0) {
    throw new Error("Cursor signing key must be readable only by its owner.");
  }
  if (typeof process.getuid === "function" && metadata.uid !== process.getuid()) {
    throw new Error("Cursor signing key must be owned by the broker service user.");
  }
  const text = readFileSync(path, "utf8").trim();
  if (!KEY_TEXT_PATTERN.test(text)) {
    throw new Error("Cursor signing key file does not contain one canonical 256-bit key.");
  }
  const secret = Buffer.from(text, "base64url");
  if (secret.length !== KEY_BYTES || secret.toString("base64url") !== text) {
    throw new Error("Cursor signing key file does not contain one canonical 256-bit key.");
  }
  const keyId = `cursor-${createHash("sha256").update(secret).digest("hex").slice(0, 24)}`;
  return Object.freeze({ keyId, secret: Uint8Array.from(secret) });
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
