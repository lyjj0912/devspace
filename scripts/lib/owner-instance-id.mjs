import { randomUUID } from "node:crypto";
import { chmodSync, closeSync, existsSync, fsyncSync, lstatSync, mkdirSync, openSync, readFileSync, writeFileSync } from "node:fs";
import { resolve } from "node:path";

const OWNER_ID_PATTERN = /^owner-[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;

export function ensureOwnerInstanceId(identityDirectory) {
  const directory = resolve(identityDirectory);
  const path = resolve(directory, "owner-instance-id");
  mkdirSync(directory, { recursive: true, mode: 0o700 });
  chmodSync(directory, 0o700);
  if (existsSync(path)) return readOwnerInstanceId(path);

  const candidate = `owner-${randomUUID()}`;
  let descriptor;
  try {
    descriptor = openSync(path, "wx", 0o600);
    writeFileSync(descriptor, `${candidate}\n`, "utf8");
    fsyncSync(descriptor);
  } catch (error) {
    if (error?.code !== "EEXIST") throw error;
  } finally {
    if (descriptor !== undefined) closeSync(descriptor);
  }
  if (descriptor !== undefined) {
    chmodSync(path, 0o600);
    fsyncDirectory(directory);
  } else {
    for (let attempt = 0; attempt < 20; attempt += 1) {
      try { return readOwnerInstanceId(path); } catch (error) {
        if (attempt === 19) throw error;
        Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 5);
      }
    }
  }
  return readOwnerInstanceId(path);
}

export function readOwnerInstanceId(path) {
  const metadata = lstatSync(path);
  if (!metadata.isFile()) throw new Error(`Owner instance identity is not a regular file: ${path}`);
  if (process.platform !== "win32" && (metadata.mode & 0o077) !== 0) {
    throw new Error(`Owner instance identity must be owner-only: ${path}`);
  }
  const value = readFileSync(path, "utf8").trim();
  if (!OWNER_ID_PATTERN.test(value)) throw new Error(`Owner instance identity is invalid: ${path}`);
  return value;
}

function fsyncDirectory(path) {
  let descriptor;
  try {
    descriptor = openSync(path, "r");
    fsyncSync(descriptor);
  } catch (error) {
    if (!new Set(["EINVAL", "ENOTSUP", "EISDIR", "EPERM"]).has(error?.code)) throw error;
  } finally {
    if (descriptor !== undefined) closeSync(descriptor);
  }
}
