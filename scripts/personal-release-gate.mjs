#!/usr/bin/env node
import { spawnSync } from "node:child_process";

const argumentsSet = new Set(process.argv.slice(2));
const liveOnly = argumentsSet.has("--live-only");
const live = liveOnly || argumentsSet.has("--live");
const requireClean = argumentsSet.has("--require-clean");
const supported = new Set(["--live", "--live-only", "--require-clean"]);
const unknown = [...argumentsSet].filter((argument) => !supported.has(argument));
if (unknown.length > 0) fail(`Unknown release-gate option: ${unknown.join(" ")}`);

if (!liveOnly) {
  const args = ["scripts/verify-universal-broker-v2-release.mjs"];
  if (requireClean) args.push("--require-clean");
  run(process.execPath, args);
}
if (live) await verifyLiveEndpoints();
console.log("personal release gate: PASS");

async function verifyLiveEndpoints() {
  const base = new URL(process.env.DEVSPACE_V2_LIVE_BASE_URL ?? "http://127.0.0.1:7676");
  const healthPath = process.env.DEVSPACE_V2_LIVE_HEALTH_PATH ?? "/healthz";
  const mcpPath = process.env.DEVSPACE_V2_LIVE_MCP_PATH ?? "/mcp";
  const health = await fetch(new URL(healthPath, base));
  const healthBody = await health.text();
  if (health.status !== 200 || !healthBody.includes('"ok":true')) {
    fail(`Live health check failed: ${health.status} ${healthBody.slice(0, 1_000)}`);
  }
  const unauthenticated = await fetch(new URL(mcpPath, base), {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      jsonrpc: "2.0",
      id: 1,
      method: "initialize",
      params: {
        protocolVersion: "2025-06-18",
        capabilities: {},
        clientInfo: { name: "release-live-boundary", version: "1" },
      },
    }),
  });
  if (unauthenticated.status !== 401) {
    fail(`Unauthenticated MCP boundary returned ${unauthenticated.status}, expected 401.`);
  }
}

function run(command, args) {
  const result = spawnSync(command, args, {
    cwd: process.cwd(),
    stdio: "inherit",
    env: process.env,
    timeout: 20 * 60_000,
  });
  if (result.error) fail(`${command} failed to start: ${result.error.message}`);
  if (result.status !== 0) process.exit(result.status ?? 1);
}

function fail(message) {
  console.error(message);
  process.exit(1);
}
