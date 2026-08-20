import assert from "node:assert/strict";
import { chmod, lstat, mkdtemp, readFile, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import {
  loadCursorSigningKeyRing,
  resolveCursorSigningKeyReference,
} from "./cursor-signing-key.js";

test("cursor key ring atomically creates and reuses an owner-only current key", async (t) => {
  const root = await mkdtemp(join(tmpdir(), "cursor-key-ring-"));
  t.after(() => rm(root, { recursive: true, force: true }));
  const first = loadCursorSigningKeyRing({ currentKeyRef: "cursor-current", stateDir: root });
  const second = loadCursorSigningKeyRing({ currentKeyRef: "cursor-current", stateDir: root });
  assert.equal(first.currentPath, join(root, "secret-refs", "cursor-current.key"));
  assert.equal(first.currentKey.keyId, second.currentKey.keyId);
  assert.deepEqual(first.currentKey.secret, second.currentKey.secret);
  assert.equal((await lstat(first.currentPath)).mode & 0o777, 0o600);
  assert.match((await readFile(first.currentPath, "utf8")).trim(), /^[A-Za-z0-9_-]{43}$/u);
});

test("cursor key ring accepts one distinct previous key and rejects aliases or weak files", async (t) => {
  const root = await mkdtemp(join(tmpdir(), "cursor-key-rotation-"));
  t.after(() => rm(root, { recursive: true, force: true }));
  const current = loadCursorSigningKeyRing({ currentKeyRef: "current", stateDir: root });
  const previousPath = resolveCursorSigningKeyReference("previous", root);
  await writeFile(previousPath, `${Buffer.alloc(32, 0x44).toString("base64url")}\n`, { mode: 0o600 });
  const ring = loadCursorSigningKeyRing({
    currentKeyRef: current.currentPath,
    previousKeyRef: previousPath,
    stateDir: root,
  });
  assert.notEqual(ring.currentKey.keyId, ring.previousKey?.keyId);
  assert.throws(() => loadCursorSigningKeyRing({
    currentKeyRef: current.currentPath,
    previousKeyRef: current.currentPath,
    stateDir: root,
  }), /references must differ/u);

  const weak = join(root, "weak.key");
  await writeFile(weak, `${Buffer.alloc(32, 0x55).toString("base64url")}\n`, { mode: 0o644 });
  await chmod(weak, 0o644);
  assert.throws(
    () => loadCursorSigningKeyRing({ currentKeyRef: weak, stateDir: root }),
    /only by its owner/u,
  );
});

test("cursor key references reject symlinks and unbounded relative paths", async (t) => {
  const root = await mkdtemp(join(tmpdir(), "cursor-key-boundary-"));
  t.after(() => rm(root, { recursive: true, force: true }));
  const target = join(root, "target.key");
  await writeFile(target, `${Buffer.alloc(32, 0x66).toString("base64url")}\n`, { mode: 0o600 });
  const link = join(root, "link.key");
  await symlink(target, link);
  assert.throws(
    () => loadCursorSigningKeyRing({ currentKeyRef: link, stateDir: root }),
    /regular file/u,
  );
  assert.throws(
    () => resolveCursorSigningKeyReference("../escape", root),
    /bounded logical names/u,
  );
});
