import { createHash } from "node:crypto";
import { mkdir } from "node:fs/promises";
import { join, resolve } from "node:path";

const UNIX_SOCKET_PATH_BUDGET = 100;
const CONTROL_HASH_CHARACTERS = 40;

export async function prepareSshControlPath(configuredDirectory: string): Promise<string> {
  const resolved = resolve(configuredDirectory);
  const projected = join(resolved, "x".repeat(CONTROL_HASH_CHARACTERS));
  const directory = Buffer.byteLength(projected) < UNIX_SOCKET_PATH_BUDGET
    ? resolved
    : join(
        "/tmp",
        `dv2-ssh-${createHash("sha256").update(resolved).digest("hex").slice(0, 12)}`,
      );
  await mkdir(directory, { recursive: true, mode: 0o700 });
  return join(directory, "%C");
}
