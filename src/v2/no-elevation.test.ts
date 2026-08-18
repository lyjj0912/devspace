import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import test from "node:test";
import {
  assertServiceAccountBoundary,
  linuxCapabilitiesAreOrdinary,
  macosUserOnlyProfile,
  windowsIntegrityIsElevated,
  windowsNonElevatedPrelude,
  wrapLocalUserOnlyExecution,
} from "./no-elevation.js";

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
