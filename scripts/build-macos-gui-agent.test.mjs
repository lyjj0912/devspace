import assert from "node:assert/strict";
import { readFile, stat } from "node:fs/promises";
import { spawnSync } from "node:child_process";
import { join, resolve } from "node:path";
import test from "node:test";

test("macOS GUI agent build emits a signed stable application bundle", { skip: process.platform !== "darwin" }, async () => {
  const root = resolve(".");
  const result = spawnSync(process.execPath, ["scripts/build-macos-gui-agent.mjs"], {
    cwd: root,
    encoding: "utf8",
    timeout: 120_000,
  });
  assert.equal(result.error, undefined, result.error?.message);
  assert.equal(result.status, 0, `${result.stdout}\n${result.stderr}`);
  const manifest = JSON.parse(await readFile(join(root, "dist/native/macos-gui-agent/MANIFEST.json"), "utf8"));
  assert.equal(manifest.bundleIdentifier, "com.devspace.gui-agent");
  assert.match(manifest.executableSha256, /^sha256:[a-f0-9]{64}$/u);
  const executable = join(root, manifest.executableRelativePath);
  assert.equal((await stat(executable)).mode & 0o777, 0o700);
  const capabilities = spawnSync(executable, ["capabilities"], { encoding: "utf8", timeout: 10_000 });
  assert.equal(capabilities.status, 0, capabilities.stderr);
  assert.match(capabilities.stdout, /^__DEVSPACE_V2_GUI_JSON__/u);
  const payload = JSON.parse(capabilities.stdout.replace(/^__DEVSPACE_V2_GUI_JSON__/u, ""));
  assert.equal(payload.ok, true);
  assert.equal(payload.data.bundleIdentifier, "com.devspace.gui-agent");
  assert.equal(typeof payload.data.accessibility, "boolean");
  assert.equal(typeof payload.data.screenCapture, "boolean");
  const verification = spawnSync("/usr/bin/codesign", [
    "--verify", "--deep", "--strict", join(root, manifest.appRelativePath),
  ], { encoding: "utf8", timeout: 10_000 });
  assert.equal(verification.status, 0, verification.stderr);
});
