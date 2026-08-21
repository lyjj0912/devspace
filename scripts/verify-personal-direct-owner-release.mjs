#!/usr/bin/env node
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { chmodSync, existsSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { mkdirSync } from "node:fs";
import { sourceGateEnvironment } from "./lib/source-gate-environment.mjs";

const options = parseOptions(process.argv.slice(2));
const sourceEnvironment = sourceGateEnvironment(process.env);
const requireClean = options.flags.has("require-clean");
const reportPath = options.values.get("report");
if (options.flags.size > (requireClean ? 1 : 0) || options.values.size > (reportPath ? 1 : 0)) {
  throw new Error(
    "Usage: verify-personal-direct-owner-release.mjs [--require-clean] [--report FILE]",
  );
}

const sourceRevision = capture("git", ["rev-parse", "HEAD"]).trim();
if (!/^[a-f0-9]{40}$/u.test(sourceRevision)) {
  throw new Error("Personal source revision is not an exact Git SHA-1.");
}
if (requireClean) assertClean("before source verification");

run("npm", ["run", "release:focused-test"]);

if (requireClean) assertClean("after source verification");
const receipt = {
  schemaVersion: 1,
  kind: "PERSONAL_DIRECT_OWNER_SOURCE_GATE",
  status: "PASS",
  productProfile: "PERSONAL_DIRECT_OWNER",
  sourceRevision,
  sourceTreeDigest: digest(Buffer.from(capture("git", [
    "ls-tree",
    "-r",
    "--full-tree",
    sourceRevision,
  ]))),
  packageLockSha256: digest(readFileSync(resolve("package-lock.json"))),
  buildCapabilitiesSchemaSha256: digest(
    readFileSync(resolve("contracts/build-capabilities.schema.json")),
  ),
  toolsSchemaSha256: digest(readFileSync(resolve("contracts/tools-v2.schema.json"))),
  nodeVersion: process.version,
  platform: `${process.platform}-${process.arch}`,
  gateCommand: "npm run release:focused-test",
  cleanRequired: requireClean,
  completedAt: new Date().toISOString(),
};
if (reportPath) writeExclusiveReport(reportPath, receipt);
process.stdout.write("PERSONAL_DIRECT_OWNER_SOURCE_RELEASE_PASS\n");
if (reportPath) process.stdout.write(`${JSON.stringify({ reportPath: resolve(reportPath), ...receipt })}\n`);

function assertClean(stage) {
  const status = capture("git", ["status", "--porcelain=v1", "--untracked-files=all"]);
  if (status.trim()) throw new Error(`Personal release verification requires a clean working tree ${stage}.`);
}

function run(command, args) {
  const result = spawnSync(command, args, {
    cwd: process.cwd(),
    env: sourceEnvironment,
    encoding: "utf8",
    stdio: "inherit",
    timeout: 20 * 60_000,
  });
  if (result.error) throw result.error;
  if (result.status !== 0) throw new Error(`${command} exited ${String(result.status)}.`);
}

function capture(command, args) {
  const result = spawnSync(command, args, {
    cwd: process.cwd(),
    env: sourceEnvironment,
    encoding: "utf8",
    stdio: "pipe",
    timeout: 20 * 60_000,
  });
  if (result.error) throw result.error;
  if (result.status !== 0) {
    throw new Error(`${command} exited ${String(result.status)}: ${(result.stderr ?? "").trim()}`);
  }
  return result.stdout;
}

function writeExclusiveReport(path, value) {
  const output = resolve(path);
  if (existsSync(output)) throw new Error(`Source-gate report already exists: ${output}`);
  mkdirSync(dirname(output), { recursive: true, mode: 0o700 });
  writeFileSync(output, `${JSON.stringify(value, null, 2)}\n`, {
    encoding: "utf8",
    flag: "wx",
    mode: 0o600,
  });
  chmodSync(output, 0o600);
}

function digest(value) {
  return `sha256:${createHash("sha256").update(value).digest("hex")}`;
}

function parseOptions(values) {
  const flags = new Set();
  const optionsMap = new Map();
  for (let index = 0; index < values.length; index += 1) {
    const value = values[index];
    if (value === "--require-clean") {
      flags.add("require-clean");
      continue;
    }
    if (value === "--report") {
      const next = values[index + 1];
      if (!next) throw new Error("--report requires a path.");
      optionsMap.set("report", next);
      index += 1;
      continue;
    }
    throw new Error(`Unknown source-gate option: ${value}`);
  }
  return { flags, values: optionsMap };
}
