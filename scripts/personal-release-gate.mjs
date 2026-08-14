#!/usr/bin/env node
import { createHash } from "node:crypto";
import { existsSync, readdirSync, readFileSync, statSync } from "node:fs";
import { relative, resolve } from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";

const root = resolve(fileURLToPath(new URL("..", import.meta.url)));
const argumentsSet = new Set(process.argv.slice(2));
const liveOnly = argumentsSet.has("--live-only");
const live = liveOnly || argumentsSet.has("--live");
const requireClean = argumentsSet.has("--require-clean");
const supported = new Set(["--live", "--live-only", "--require-clean"]);
const unknown = [...argumentsSet].filter((argument) => !supported.has(argument));
if (unknown.length > 0) fail(`Unknown release-gate option: ${unknown.join(" ")}`);

if (!liveOnly) {
  run("npm", ["run", "typecheck"]);
  run("npm", ["test"]);
  run("npm", ["run", "build"]);
  run("git", ["diff", "--check"]);
}

if (requireClean) {
  const status = capture("git", ["status", "--porcelain=v1", "--untracked-files=all"]);
  if (status.trim()) fail(`Tracked release tree is not clean:\n${status}`);
}

for (const path of ["dist/cli.js", "dist/server.js", "dist/maintenance.js"]) {
  if (!existsSync(resolve(root, path))) fail(`Missing build output: ${path}`);
}
const serverOutput = readFileSync(resolve(root, "dist/server.js"), "utf8");
if (!serverOutput.includes('localShell: "local_shell"')) {
  fail("Build output does not contain the required local_shell tool.");
}
const cliOutput = readFileSync(resolve(root, "dist/cli.js"), "utf8");
if (!cliOutput.includes('case "maintenance"')) {
  fail("Build output does not contain the maintenance command.");
}

const distFiles = walkFiles(resolve(root, "dist"));
const digest = createHash("sha256");
for (const file of distFiles) {
  digest.update(relative(resolve(root, "dist"), file));
  digest.update("\0");
  digest.update(readFileSync(file));
  digest.update("\0");
}
console.log(`dist files: ${distFiles.length}`);
console.log(`dist tree sha256: ${digest.digest("hex")}`);

if (live) await verifyLiveEndpoints();
console.log("personal release gate: PASS");

function run(command, args) {
  const result = spawnSync(command, args, {
    cwd: root,
    stdio: "inherit",
    env: process.env,
  });
  if (result.error) fail(`${command} failed to start: ${result.error.message}`);
  if (result.status !== 0) fail(`${command} ${args.join(" ")} exited with ${result.status}`);
}

function capture(command, args) {
  const result = spawnSync(command, args, {
    cwd: root,
    encoding: "utf8",
    env: process.env,
  });
  if (result.error) fail(`${command} failed to start: ${result.error.message}`);
  if (result.status !== 0) {
    fail(`${command} ${args.join(" ")} exited with ${result.status}: ${result.stderr}`);
  }
  return result.stdout;
}

function walkFiles(directory) {
  const files = [];
  for (const entry of readdirSync(directory, { withFileTypes: true })) {
    const path = resolve(directory, entry.name);
    if (entry.isDirectory()) files.push(...walkFiles(path));
    else if (entry.isFile() && statSync(path).isFile()) files.push(path);
  }
  return files.sort();
}

async function verifyLiveEndpoints() {
  const health = await fetch("http://127.0.0.1:7676/healthz");
  const healthBody = await health.text();
  if (health.status !== 200 || !healthBody.includes('"ok":true')) {
    fail(`Live health check failed: ${health.status} ${healthBody}`);
  }
  const unauthenticated = await fetch("http://127.0.0.1:7676/mcp");
  if (unauthenticated.status !== 401) {
    fail(`Unauthenticated MCP boundary returned ${unauthenticated.status}, expected 401.`);
  }
  console.log("live health: 200");
  console.log("live unauthenticated MCP: 401");
}

function fail(message) {
  console.error(message);
  process.exit(1);
}
