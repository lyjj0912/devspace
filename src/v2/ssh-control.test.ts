import assert from "node:assert/strict";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { prepareSshControlPath } from "./ssh-control.js";

test("SSH control paths retain short configured roots", async (t) => {
  const root = await mkdtemp("/tmp/dv2-s-");
  t.after(() => rm(root, { recursive: true, force: true }));
  assert.equal(await prepareSshControlPath(root), join(root, "%C"));
});

test("SSH control paths fall back before the Unix socket path limit", async () => {
  const long = join(tmpdir(), "a".repeat(120), "nested");
  const prepared = await prepareSshControlPath(long);
  assert.ok(Buffer.byteLength(prepared.replace("%C", "x".repeat(40))) < 100);
  assert.match(prepared, /dv2-ssh-[0-9a-f]{12}\/\%C$/);
});
