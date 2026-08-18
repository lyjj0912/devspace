import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { spawnSync } from "node:child_process";
import { chmod, mkdtemp, realpath, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import {
  assertInternalExecutionCommand,
  assertServiceAccountBoundary,
  internalExecutionSpec,
  linuxCapabilitiesAreOrdinary,
  macosUserOnlyProfile,
  posixRemoteUserOnlyRunner,
  windowsIntegrityIsElevated,
  windowsNonElevatedPrelude,
  wrapLocalUserOnlyExecution,
  type GuiInternalExecutionPolicy,
} from "./no-elevation.js";
import { UniversalBrokerError } from "./errors.js";

test("service account boundary accepts the ordinary test account", () => {
  assert.doesNotThrow(() => assertServiceAccountBoundary());
});

test("macOS execution wrapper blocks sudo at the kernel sandbox boundary", { skip: process.platform !== "darwin" }, () => {
  const wrapped = wrapLocalUserOnlyExecution("macos", {
    executable: "/usr/bin/sudo",
    args: ["-n", "true"],
  });
  const denied = spawnSync(wrapped.executable, wrapped.args, { encoding: "utf8" });
  assert.notEqual(denied.status, 0);
  assert.match(denied.stderr, /Operation not permitted/u);

  const allowed = spawnSync("/usr/bin/sandbox-exec", [
    "-p",
    macosUserOnlyProfile(),
    "/bin/echo",
    "ordinary-user",
  ], { encoding: "utf8" });
  assert.equal(allowed.status, 0);
  assert.equal(allowed.stdout.trim(), "ordinary-user");
});

test("macOS profile rejects set-id executables generically", { skip: process.platform !== "darwin" }, () => {
  const denied = spawnSync("/usr/bin/sandbox-exec", [
    "-p",
    macosUserOnlyProfile(),
    "/bin/ps",
    "-p",
    String(process.pid),
  ], { encoding: "utf8" });
  assert.notEqual(denied.status, 0);
  assert.match(denied.stderr, /Operation not permitted/u);
});

test("Linux service boundary requires zero effective, permitted, and ambient capabilities", () => {
  assert.equal(linuxCapabilitiesAreOrdinary([
    "CapPrm:\t0000000000000000",
    "CapEff:\t0000000000000000",
    "CapAmb:\t0000000000000000",
  ].join("\n")), true);
  assert.equal(linuxCapabilitiesAreOrdinary([
    "CapPrm:\t0000000000000000",
    "CapEff:\t0000000000000001",
    "CapAmb:\t0000000000000000",
  ].join("\n")), false);
  assert.equal(linuxCapabilitiesAreOrdinary("CapEff:\t0000000000000000\n"), false);
});

test("Windows remote prelude detects high and system integrity tokens", () => {
  const source = windowsNonElevatedPrelude("BLOCKED-MARKER").join(";");
  assert.match(source, /S-1-16-\(12288\|16384\)/u);
  assert.match(source, /BLOCKED-MARKER/u);
  assert.match(source, /exit 77/u);
  assert.equal(windowsIntegrityIsElevated('"High Mandatory Level","S-1-16-12288"'), true);
  assert.equal(windowsIntegrityIsElevated('"Medium Mandatory Level","S-1-16-8192"'), false);
});

test("macOS profile denies Authorization Services acquisition", () => {
  assert.match(macosUserOnlyProfile(), /deny authorization-right-obtain/u);
});

test("macOS ordinary AppleScript remains usable while administrator AppleScript fails closed", { skip: process.platform !== "darwin" }, () => {
  const ordinary = wrapLocalUserOnlyExecution("macos", {
    executable: "/usr/bin/osascript",
    args: ["-e", "return 2 + 2"],
  });
  const ordinaryResult = spawnSync(ordinary.executable, ordinary.args, {
    encoding: "utf8",
    timeout: 5_000,
  });
  assert.equal(ordinaryResult.status, 0, ordinaryResult.stderr);
  assert.equal(ordinaryResult.stdout.trim(), "4");

  const elevated = wrapLocalUserOnlyExecution("macos", {
    executable: "/usr/bin/osascript",
    args: ["-e", 'do shell script "/usr/bin/id" with administrator privileges'],
  });
  const elevatedResult = spawnSync(elevated.executable, elevated.args, {
    encoding: "utf8",
    timeout: 5_000,
  });
  assert.notEqual(elevatedResult.status, 0);
  assert.equal(elevatedResult.signal, null);
  assert.doesNotMatch(elevatedResult.stdout, /uid=0/u);
});


test("exact GUI internal execution accepts only the bound owner script and argument grammar", async (t) => {
  const root = await mkdtemp(join(tmpdir(), "devspace-gui-exact-policy-test-"));
  t.after(() => rm(root, { recursive: true, force: true }));
  const provisionalScriptPath = join(root, "gui-node.applescript");
  const source = [
    "on run argv",
    "  return item 1 of argv",
    "end run",
    "",
  ].join("\n");
  await writeFile(provisionalScriptPath, source, { mode: 0o600 });
  const scriptPath = await realpath(provisionalScriptPath);
  const policy: GuiInternalExecutionPolicy = {
    kind: "gui",
    scriptPath,
    scriptSha256: sha256(source),
  };
  const command = `/usr/bin/osascript ${quote(scriptPath)} capabilities`;
  const spec = internalExecutionSpec(policy, command, { verifyLocalScript: true });
  assert.deepEqual(spec, {
    executable: "/usr/bin/osascript",
    args: [scriptPath, "capabilities"],
  });
  assert.doesNotThrow(() => assertInternalExecutionCommand(policy, command));

  if (process.platform === "darwin") {
    const result = spawnSync(spec!.executable, spec!.args, {
      encoding: "utf8",
      timeout: 5_000,
    });
    assert.equal(result.status, 0, result.stderr);
    assert.equal(result.stdout.trim(), "capabilities");
  }

  const remote = posixRemoteUserOnlyRunner("macos", "sh", command, policy);
  assert.match(remote, /\/usr\/bin\/shasum -a 256/u);
  assert.match(remote, new RegExp(policy.scriptSha256, "u"));
  assert.match(remote, /\[ -f/u);
  assert.match(remote, /! -L/u);
  assert.match(remote, /\/bin\/realpath/u);
  assert.match(remote, /\/usr\/bin\/stat -f '%u'/u);
  assert.match(remote, /8#\$mode & 8#22/u);
  assert.match(remote, /exec '\/usr\/bin\/osascript'/u);
  assert.doesNotMatch(remote, /sandbox-exec/u);
  if (process.platform === "darwin") {
    const remoteResult = spawnSync("/bin/sh", ["-lc", remote], {
      encoding: "utf8",
      timeout: 5_000,
    });
    assert.equal(remoteResult.status, 0, remoteResult.stderr);
    assert.equal(remoteResult.stdout.trim(), "capabilities");
  }
});

test("exact GUI internal execution fails closed on path, hash, mode, symlink, shell, and argument drift", async (t) => {
  const root = await mkdtemp(join(tmpdir(), "devspace-gui-exact-denial-test-"));
  t.after(() => rm(root, { recursive: true, force: true }));
  const scriptPath = join(root, "gui-node.applescript");
  const alternatePath = join(root, "alternate.applescript");
  const symlinkPath = join(root, "linked.applescript");
  const source = "on run argv\nreturn item 1 of argv\nend run\n";
  await writeFile(scriptPath, source, { mode: 0o600 });
  await writeFile(alternatePath, source, { mode: 0o600 });
  await symlink(scriptPath, symlinkPath);
  const policy: GuiInternalExecutionPolicy = {
    kind: "gui",
    scriptPath,
    scriptSha256: sha256(source),
  };
  const valid = `/usr/bin/osascript ${quote(scriptPath)} capabilities`;
  for (const invalid of [
    `/usr/bin/osascript -e ${quote("return 4")}`,
    `/usr/bin/osascript ${quote(alternatePath)} capabilities`,
    `${valid}; /usr/bin/id`,
    `/usr/bin/osascript ${quote(scriptPath)} $(/usr/bin/id)`,
    `/usr/bin/osascript ${quote(scriptPath)} unsupported`,
    `/usr/bin/osascript ${quote(scriptPath)} observe 0`,
    `/usr/bin/osascript ${quote(scriptPath)} act -1 press`,
  ]) {
    assert.throws(
      () => internalExecutionSpec(policy, invalid),
      hasCode("ELEVATION_BLOCKED"),
      invalid,
    );
  }
  assert.throws(
    () => internalExecutionSpec({ ...policy, scriptSha256: "not-a-hash" }, valid),
    hasCode("ELEVATION_BLOCKED"),
  );
  assert.throws(
    () => internalExecutionSpec({ ...policy, scriptPath: symlinkPath }, `/usr/bin/osascript ${quote(symlinkPath)} capabilities`, { verifyLocalScript: true }),
    hasCode("ELEVATION_BLOCKED"),
  );

  await writeFile(scriptPath, `${source}-- tampered\n`, { mode: 0o600 });
  assert.throws(
    () => internalExecutionSpec(policy, valid, { verifyLocalScript: true }),
    hasCode("ELEVATION_BLOCKED"),
  );
  await writeFile(scriptPath, source, { mode: 0o666 });
  await chmod(scriptPath, 0o666);
  assert.throws(
    () => internalExecutionSpec(policy, valid, { verifyLocalScript: true }),
    hasCode("ELEVATION_BLOCKED"),
  );
  if (process.platform === "darwin") {
    const remote = posixRemoteUserOnlyRunner("macos", "sh", valid, policy);
    const remoteResult = spawnSync("/bin/sh", ["-lc", remote], {
      encoding: "utf8",
      timeout: 5_000,
    });
    assert.equal(remoteResult.status, 78, remoteResult.stderr);
  }
});

test("MCP provider children remain in the generic no-elevation wrapper", { skip: process.platform !== "darwin" }, () => {
  const local = wrapLocalUserOnlyExecution("macos", {
    executable: "/bin/echo",
    args: ["provider"],
  }, "mcp");
  assert.equal(local.executable, "/usr/bin/sandbox-exec");
  assert.match(local.args.join(" "), /deny authorization-right-obtain/u);

  const remote = posixRemoteUserOnlyRunner(
    "macos",
    "sh",
    "exec '/bin/echo' 'provider'",
    "mcp",
  );
  assert.match(remote, /sandbox-exec/u);
  assert.doesNotMatch(remote, /shasum -a 256/u);
});

function sha256(value: string): string {
  return createHash("sha256").update(value).digest("hex");
}

function quote(value: string): string {
  return `'${value.replaceAll("'", `'"'"'`)}'`;
}

function hasCode(expected: string): (error: unknown) => boolean {
  return (error) => error instanceof UniversalBrokerError && error.code === expected;
}
