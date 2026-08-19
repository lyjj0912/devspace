import assert from "node:assert/strict";
import { mkdtemp, mkdir, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { ProcessOutputSpool } from "./process-output-spool.js";

test("process output spool preserves UTF-8 chunk boundaries and channel/global byte offsets", async (t) => {
  const root = await mkdtemp(join(tmpdir(), "devspace-process-spool-"));
  t.after(() => rm(root, { recursive: true, force: true }));
  await mkdir(join(root, "output"), { mode: 0o700 });
  const spool = new ProcessOutputSpool({
    path: join(root, "output", "process.log"),
    maximumInlineBytes: 64 * 1024,
    maximumFileBytes: 100 * 1024 * 1024,
  });
  await spool.open();
  const emoji = Buffer.from("🙂", "utf8");
  const first = await spool.append("stdout", emoji.subarray(0, 2));
  const second = await spool.append("stdout", emoji.subarray(2));
  const third = await spool.append("stderr", Buffer.from("!", "utf8"));
  assert.deepEqual(first, { channel: "stdout", globalOffset: 0, channelOffset: 0, bytes: 2 });
  assert.deepEqual(second, { channel: "stdout", globalOffset: 2, channelOffset: 2, bytes: 2 });
  assert.deepEqual(third, { channel: "stderr", globalOffset: 4, channelOffset: 0, bytes: 1 });
  assert.equal(spool.drain(100).output, "🙂!");
  assert.deepEqual(spool.currentOffsets, { global: 5, stdout: 4, stderr: 1, pty: 0 });
  const stdout = await spool.read(0, 100, "stdout");
  assert.equal(stdout.text, "🙂");
  assert.deepEqual(stdout.bytes, emoji);
  const global = await spool.read(0, 100);
  assert.equal(global.text, "🙂!");
  await spool.close();
});

test("process output spool retains at most the configured raw-byte budget", async (t) => {
  const root = await mkdtemp(join(tmpdir(), "devspace-process-spool-limit-"));
  t.after(() => rm(root, { recursive: true, force: true }));
  const spool = new ProcessOutputSpool({
    path: join(root, "process.log"),
    maximumInlineBytes: 4,
    maximumFileBytes: 5,
  });
  await spool.open();
  await spool.append("pty", Buffer.from("123456789", "utf8"));
  assert.equal(spool.totalFileBytes, 5);
  assert.equal(spool.currentOffsets.pty, 5);
  assert.equal(spool.fileTruncated, true);
  const read = await spool.read(0, 100);
  assert.equal(read.text, "12345");
  await spool.close();
});
