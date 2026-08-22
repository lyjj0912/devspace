import assert from "node:assert/strict";
import { mkdtemp, readFile, rm, stat } from "node:fs/promises";
import { spawnSync } from "node:child_process";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import test from "node:test";

test("macOS GUI agent build emits a signed stable application bundle without mutating dist", { skip: process.platform !== "darwin" }, async (t) => {
  const root = resolve(".");
  const output = await mkdtemp(join(tmpdir(), "devspace-gui-agent-build-test-"));
  t.after(() => rm(output, { recursive: true, force: true }));
  const canonicalManifest = join(root, "dist/native/macos-gui-agent/MANIFEST.json");
  const before = await readFile(canonicalManifest).catch(() => undefined);
  const result = spawnSync(process.execPath, ["scripts/build-macos-gui-agent.mjs"], {
    cwd: root,
    encoding: "utf8",
    timeout: 120_000,
    env: { ...process.env, DEVSPACE_MACOS_GUI_AGENT_OUTPUT: output },
  });
  assert.equal(result.error, undefined, result.error?.message);
  assert.equal(result.status, 0, `${result.stdout}\n${result.stderr}`);
  const manifest = JSON.parse(await readFile(join(output, "MANIFEST.json"), "utf8"));
  assert.equal(manifest.bundleIdentifier, "com.devspace.gui-agent");
  assert.match(manifest.executableSha256, /^sha256:[a-f0-9]{64}$/u);
  assert.ok(["adhoc", "certificate"].includes(manifest.signatureKind));
  assert.equal(typeof manifest.designatedRequirement, "string");
  assert.ok(manifest.designatedRequirement.length > 0);
  if (manifest.signatureKind === "certificate") {
    assert.match(manifest.designatedRequirement, /com\.devspace\.gui-agent/u);
  } else {
    assert.match(manifest.designatedRequirement, /^cdhash H"[a-f0-9]+"$/u);
  }
  const executable = join(output, "DevSpace GUI Agent.app/Contents/MacOS/devspace-gui-agent");
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
    "--verify", "--deep", "--strict", join(output, "DevSpace GUI Agent.app"),
  ], { encoding: "utf8", timeout: 10_000 });
  assert.equal(verification.status, 0, verification.stderr);
  const after = await readFile(canonicalManifest).catch(() => undefined);
  assert.deepEqual(after, before, "isolated build test changed canonical dist output");
});

test("actual GUI verifier binds capture and identity checks to the task-owned fixture", async () => {
  const source = await readFile(resolve("scripts/verify-macos-gui-agent-actual.mjs"), "utf8");
  assert.match(source, /\["capture", "jpeg", "40", "640", String\(fixturePid\)\]/u);
  assert.match(source, /assert\.deepEqual\(agentIdentityAfterRequest, agentIdentity/u);
  assert.match(source, /fixturePidBoundCapture/u);
  assert.match(source, /cleanupComplete/u);
  assert.match(source, /realpathSync\(appPath\)/u);
  assert.doesNotMatch(source, /\/usr\/bin\/realpath/u);
});
