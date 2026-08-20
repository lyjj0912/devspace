import assert from "node:assert/strict";
import { mkdtemp, readFile, rm, stat, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import {
  isManagementAuthorized,
  loadExistingManagementAuthorizationKey,
  loadOrCreateManagementAuthorizationKey,
  managementAuthorizationHeader,
} from "./management-authorization.js";

test("management authorization key is owner-only, stable, and timing-safe checked", async (t) => {
  const root = await mkdtemp(join(tmpdir(), "devspace-management-auth-"));
  t.after(() => rm(root, { recursive: true, force: true }));
  const input = { keyRef: join(root, "management.key"), stateDir: root };
  const created = loadOrCreateManagementAuthorizationKey(input);
  const reopened = loadExistingManagementAuthorizationKey(input);
  assert.equal(reopened.keyId, created.keyId);
  assert.equal((await stat(created.path)).mode & 0o777, 0o600);
  assert.equal((await readFile(created.path, "utf8")).trim().length, 43);
  const header = managementAuthorizationHeader(created);
  assert.equal(isManagementAuthorized(header, reopened), true);
  assert.equal(isManagementAuthorized(undefined, reopened), false);
  const finalCharacter = header.at(-1);
  assert.equal(
    isManagementAuthorized(`${header.slice(0, -1)}${finalCharacter === "A" ? "B" : "A"}`, reopened),
    false,
  );
  assert.equal(isManagementAuthorized(`Bearer ${"x".repeat(300)}`, reopened), false);
});

test("management authorization rejects permissive or malformed key files", async (t) => {
  const root = await mkdtemp(join(tmpdir(), "devspace-management-auth-invalid-"));
  t.after(() => rm(root, { recursive: true, force: true }));
  const path = join(root, "management.key");
  await writeFile(path, "not-a-key\n", { mode: 0o600 });
  assert.throws(
    () => loadExistingManagementAuthorizationKey({ keyRef: path, stateDir: root }),
    /canonical 256-bit key/u,
  );
});
