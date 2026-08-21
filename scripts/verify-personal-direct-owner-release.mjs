#!/usr/bin/env node
import { spawnSync } from "node:child_process";

const argumentsSet = new Set(process.argv.slice(2));
const unknown = [...argumentsSet].filter((argument) => argument !== "--require-clean");
if (unknown.length > 0) {
  throw new Error(`Usage: verify-personal-direct-owner-release.mjs [--require-clean]; unknown: ${unknown.join(" ")}`);
}

if (argumentsSet.has("--require-clean")) {
  const status = run("git", ["status", "--porcelain=v1", "--untracked-files=all"], { capture: true });
  if (status.stdout.trim()) throw new Error("Personal release verification requires a clean working tree.");
}

run("npm", ["run", "release:focused-test"]);
process.stdout.write("PERSONAL_DIRECT_OWNER_SOURCE_RELEASE_PASS\n");

function run(command, args, options = {}) {
  const result = spawnSync(command, args, {
    cwd: process.cwd(),
    env: process.env,
    encoding: "utf8",
    stdio: options.capture ? "pipe" : "inherit",
    timeout: 20 * 60_000,
  });
  if (result.error) throw result.error;
  if (result.status !== 0) {
    throw new Error(`${command} exited ${String(result.status)}${result.stderr ? `: ${result.stderr.trim()}` : ""}`);
  }
  return result;
}
