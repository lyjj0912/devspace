import assert from "node:assert/strict";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { loadConfig } from "../config.js";
import { collectUniversalBrokerDoctor } from "./doctor.js";

test("doctor JSON reports contracts, registries, targets, and quotas without credentials", async (t) => {
  const root = await mkdtemp(join(tmpdir(), "devspace-v2-doctor-test-"));
  t.after(() => rm(root, { recursive: true, force: true }));
  const base = loadConfig({
    DEVSPACE_CONFIG_DIR: join(root, "config"),
    DEVSPACE_ALLOWED_ROOTS: root,
    DEVSPACE_STATE_DIR: join(root, "legacy"),
    DEVSPACE_WORKTREE_ROOT: join(root, "legacy-worktrees"),
    DEVSPACE_OAUTH_OWNER_TOKEN: "owner-token-not-for-output-1234567890",
    DEVSPACE_PUBLIC_BASE_URL: "http://127.0.0.1:17676",
    DEVSPACE_LOG_LEVEL: "silent",
  });
  const report = await collectUniversalBrokerDoctor(base, {
    DEVSPACE_NEXT_STATE_DIR: join(root, "next"),
    DEVSPACE_NEXT_TARGET_CONFIG: join(root, "missing-targets.json"),
    DEVSPACE_NEXT_MCP_ROUTE_CONFIG: join(root, "missing-routes.json"),
    DEVSPACE_NEXT_PUBLIC_BASE_URL: "http://127.0.0.1:17677",
  });
  assert.equal((report.contracts as { passed: boolean }).passed, true);
  assert.equal(Array.isArray(report.targets), true);
  assert.equal(JSON.stringify(report).includes("owner-token-not-for-output"), false);
  assert.equal((report.quotas as { httpMcpSessions: number }).httpMcpSessions, 128);
  assert.deepEqual(
    report.selfManagement,
    {
      stateDir: join(root, "next", "self-management"),
      pm2ProcessName: "devspace-next",
      expectedScript: undefined,
      restartDelayMs: 2_000,
      restartTimeoutMs: 120_000,
      transactionModel: "detached-worker-with-post-reconnect-readback",
    },
  );
  assert.deepEqual(
    report.endpoint,
    {
      deploymentMode: "parallel",
      local: "http://127.0.0.1:7677/mcp-next",
      public: "http://127.0.0.1:17677/mcp-next",
      health: "http://127.0.0.1:7677/healthz-next",
      metrics: "http://127.0.0.1:7677/metrics-next",
      stateDir: join(root, "next"),
      oauthStateReused: false,
      granularScopesOnly: true,
    },
  );
});
