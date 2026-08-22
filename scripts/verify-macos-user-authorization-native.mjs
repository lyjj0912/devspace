import assert from "node:assert/strict";
import { mkdtemp, readFile, realpath, rm } from "node:fs/promises";
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";

if (process.platform !== "darwin") {
  process.stdout.write("MACOS_USER_AUTHORIZATION_NATIVE_NOT_APPLICABLE\n");
  process.exit(0);
}
const root = await realpath(await mkdtemp(join(tmpdir(), "devspace-macos-authorization-native-")));
try {
  const sourceRoot = resolve("native/macos-authorization");
  const build = spawnSync(join(sourceRoot, "build.sh"), [root], {
    cwd: process.cwd(),
    encoding: "utf8",
    timeout: 120_000,
  });
  assert.equal(build.error, undefined, build.error?.message);
  assert.equal(build.status, 0, `${build.stdout}\n${build.stderr}`);
  const approvalApp = join(root, "DevSpace Approval Agent.app");
  const approvalExecutable = join(
    approvalApp,
    "Contents",
    "MacOS",
    "devspace-approval-agent",
  );
  const relay = join(root, "devspace-approval-relay");
  const helper = join(root, "devspace-privileged-helper");
  const helperSha = `sha256:${createHash("sha256").update(await readFile(helper)).digest("hex")}`;
  const selfTest = spawnSync(approvalExecutable, [
    "--self-test", "yes",
    "--helper", helper,
    "--helper-sha256", helperSha,
  ], { encoding: "utf8", timeout: 10_000 });
  assert.equal(selfTest.status, 0, `${selfTest.stdout}\n${selfTest.stderr}`);
  assert.match(selfTest.stdout, /DEVSPACE_AUTHORIZATION_SELF_TEST\tPASS/u);
  const approvalSource = await readFile(join(sourceRoot, "devspace-approval-agent.c"), "utf8");
  assert.match(
    approvalSource,
    /kAuthorizationRightExecute,[\s\S]*strlen\(canonical_helper\),[\s\S]*canonical_helper/u,
    "execute right is not bound to the exact helper path",
  );
  const relayNonRoot = spawnSync(relay, [], { encoding: "utf8", timeout: 10_000 });
  assert.equal(relayNonRoot.status, 64);
  const appVerification = spawnSync("/usr/bin/codesign", [
    "--verify", "--deep", "--strict", approvalApp,
  ], { encoding: "utf8", timeout: 10_000 });
  assert.equal(appVerification.status, 0, appVerification.stderr);
  const nonRoot = spawnSync(helper, [], { encoding: "utf8", timeout: 10_000 });
  assert.equal(nonRoot.status, 77);
  assert.match(nonRoot.stderr, /requires effective uid 0/u);
  process.stdout.write("MACOS_USER_AUTHORIZATION_NATIVE_SOURCE_PASS\n");
} finally {
  await rm(root, { recursive: true, force: true });
}
