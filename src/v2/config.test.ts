import assert from "node:assert/strict";
import { mkdtemp, rm } from "node:fs/promises";
import { homedir } from "node:os";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { loadConfig } from "../config.js";
import { UNIVERSAL_OWNER_SCOPES } from "./contracts.js";
import { loadUniversalBrokerNextConfig, OAUTH_OFFLINE_ACCESS_SCOPE } from "./config.js";

test("next config uses an isolated port, endpoint, state directory, and full owner scopes", async (t) => {
  const root = await mkdtemp(join(tmpdir(), "devspace-v2-config-test-"));
  t.after(() => rm(root, { recursive: true, force: true }));
  const base = baseConfig(root);
  const next = loadUniversalBrokerNextConfig(base, {});

  assert.equal(next.deploymentMode, "parallel");
  assert.equal(next.port, base.port + 1);
  assert.equal(next.deploymentMode, "parallel");
  assert.equal(next.endpointPath, "/mcp-next");
  assert.equal(next.healthPath, "/healthz-next");
  assert.equal(next.metricsPath, "/metrics-next");
  assert.equal(next.artifactPathPrefix, "/artifacts-next");
  assert.equal(next.publicBaseUrl, `http://127.0.0.1:${base.port + 1}`);
  assert.equal(next.publicMcpUrl, `http://127.0.0.1:${base.port + 1}/mcp-next`);
  assert.equal(next.stateDir, join(base.stateDir, "universal-broker-v2"));
  assert.equal(next.oauthStateDir, next.stateDir);
  assert.equal(next.targetConfigPath, join(root, ".config", "targets.v2.json"));
  assert.equal(next.mcpRouteConfigPath, join(root, ".config", "mcp-routes.v2.json"));
  assert.equal(next.contextStorePath, join(next.stateDir, "contexts.json"));
  assert.equal(next.envProfileConfigPath, join(homedir(), ".devspace", "env-profiles.v2.json"));
  assert.equal(next.contextIdleTtlMs, 30 * 60_000);
  assert.equal(next.contextWorktreeRoot, join(next.stateDir, "worktrees"));
  assert.equal(next.contextMaximumEntries, 256);
  assert.equal(next.contextMaximumWorktrees, 8);
  assert.equal(next.contextMaximumWorktreeBytes, 8 * 1024 * 1024 * 1024);
  assert.equal(next.contextDiffMaximumEntries, 64);
  assert.equal(next.contextDiffMaximumCharacters, 50_000_000);
  assert.equal(next.contextDiffTtlMs, 15 * 60_000);
  assert.equal(next.processOutputDir, join(next.stateDir, "process-output"));
  assert.equal(next.selfManagementDir, join(next.stateDir, "self-management"));
  assert.equal(next.selfRestartPm2ProcessName, "devspace-next");
  assert.equal(next.selfRestartExpectedScript, undefined);
  assert.equal(next.selfRestartDelayMs, 2_000);
  assert.equal(next.selfRestartTimeoutMs, 120_000);
  assert.equal(next.maxRunningProcesses, 32);
  assert.equal(next.maxRunningProcessesPerTarget, 16);
  assert.equal(next.processBufferCharacters, 1_000_000);
  assert.equal(next.processOutputMaxBytes, 100 * 1024 * 1024);
  assert.equal(next.completedProcessTtlMs, 15 * 60 * 1_000);
  assert.equal(next.artifactStagingDir, join(next.stateDir, "artifacts"));
  assert.equal(next.artifactMaximumEntries, 64);
  assert.equal(next.artifactMaximumTotalBytes, 2 * 1024 * 1024 * 1024);
  assert.equal(next.artifactMaximumFileBytes, 1024 * 1024 * 1024);
  assert.equal(next.artifactTtlMs, 15 * 60 * 1_000);
  assert.equal(next.guiMaximumSessions, 32);
  assert.equal(next.guiSessionTtlMs, 5 * 60 * 1_000);
  assert.equal(next.guiPayloadBudgetCharacters, 12_000);
  assert.equal(next.downstreamMcpMaximumSessions, 16);
  assert.equal(next.downstreamMcpSessionIdleTtlMs, 5 * 60_000);
  assert.equal(next.mcpResultMaximumEntries, 64);
  assert.equal(next.mcpResultMaximumCharacters, 10_000_000);
  assert.equal(next.mcpResultTtlMs, 15 * 60_000);
  assert.equal(next.maximumMcpSessions, 128);
  assert.deepEqual(next.oauth.scopes, [...UNIVERSAL_OWNER_SCOPES, OAUTH_OFFLINE_ACCESS_SCOPE]);
  assert.notEqual(next.stateDir, base.stateDir);
});

test("production v2 uses canonical production routes and may reuse the legacy OAuth state", async (t) => {
  const root = await mkdtemp(join(tmpdir(), "devspace-v2-config-production-test-"));
  t.after(() => rm(root, { recursive: true, force: true }));
  const base = baseConfig(root);
  const production = loadUniversalBrokerNextConfig(base, {
    DEVSPACE_V2_DEPLOYMENT_MODE: "production",
    DEVSPACE_NEXT_PUBLIC_BASE_URL: base.publicBaseUrl,
    DEVSPACE_NEXT_STATE_DIR: join(root, "v2-production-state"),
  });

  assert.equal(production.deploymentMode, "production");
  assert.equal(production.endpointPath, "/mcp");
  assert.equal(production.healthPath, "/healthz");
  assert.equal(production.metricsPath, "/metrics");
  assert.equal(production.artifactPathPrefix, "/artifacts");
  assert.equal(production.oauthStateDir, base.stateDir);
  assert.equal(production.stateDir, join(root, "v2-production-state"));
  assert.equal(production.publicBaseUrl, new URL(base.publicBaseUrl).origin);
  assert.equal(production.selfRestartPm2ProcessName, "devspace-v2-production");

  const isolatedCandidate = loadUniversalBrokerNextConfig(base, {
    DEVSPACE_V2_DEPLOYMENT_MODE: "production",
    DEVSPACE_NEXT_PUBLIC_BASE_URL: base.publicBaseUrl,
    DEVSPACE_NEXT_STATE_DIR: join(root, "candidate-state"),
    DEVSPACE_NEXT_OAUTH_STATE_DIR: join(root, "candidate-oauth"),
  });
  assert.equal(isolatedCandidate.oauthStateDir, join(root, "candidate-oauth"));
  assert.notEqual(isolatedCandidate.oauthStateDir, base.stateDir);

  assert.throws(
    () => loadUniversalBrokerNextConfig(base, {
      DEVSPACE_V2_DEPLOYMENT_MODE: "production",
      DEVSPACE_NEXT_PUBLIC_BASE_URL: base.publicBaseUrl,
      DEVSPACE_NEXT_MCP_PATH: "/mcp-next",
    }),
    /canonical \/mcp endpoint/,
  );

  const granularOnly = loadUniversalBrokerNextConfig(base, {
    DEVSPACE_V2_DEPLOYMENT_MODE: "production",
    DEVSPACE_V2_LEGACY_SCOPE_COMPATIBILITY: "false",
  });
  assert.deepEqual(granularOnly.oauth.scopes, [...UNIVERSAL_OWNER_SCOPES, OAUTH_OFFLINE_ACCESS_SCOPE]);

  assert.throws(
    () => loadUniversalBrokerNextConfig(base, {
      DEVSPACE_V2_LEGACY_SCOPE_COMPATIBILITY: "true",
    }),
    /removed in Universal Broker v2\.1/,
  );
  assert.throws(
    () => loadUniversalBrokerNextConfig(base, {
      DEVSPACE_NEXT_MCP_SESSION_IDLE_TIMEOUT_MS: String(24 * 60 * 60_000 + 1),
    }),
    /DEVSPACE_NEXT_MCP_SESSION_IDLE_TIMEOUT_MS/,
  );
  assert.throws(
    () => loadUniversalBrokerNextConfig(base, {
      DEVSPACE_NEXT_MCP_SESSION_CLEANUP_INTERVAL_MS: String(60 * 60_000 + 1),
    }),
    /DEVSPACE_NEXT_MCP_SESSION_CLEANUP_INTERVAL_MS/,
  );
});

test("next config accepts explicit parallel deployment values", async (t) => {
  const root = await mkdtemp(join(tmpdir(), "devspace-v2-config-test-"));
  t.after(() => rm(root, { recursive: true, force: true }));
  const next = loadUniversalBrokerNextConfig(baseConfig(root), {
    DEVSPACE_NEXT_HOST: "0.0.0.0",
    DEVSPACE_NEXT_PORT: "17677",
    DEVSPACE_NEXT_PUBLIC_BASE_URL: "https://devspace-next.example.com/v2/",
    DEVSPACE_NEXT_MCP_PATH: "/mcp-next/v2",
    DEVSPACE_NEXT_STATE_DIR: join(root, "next-state"),
    DEVSPACE_NEXT_TARGETS_FILE: join(root, "targets.json"),
    DEVSPACE_NEXT_MCP_ROUTES_FILE: join(root, "routes.json"),
    DEVSPACE_NEXT_CONTEXT_STORE: join(root, "context-state.json"),
    DEVSPACE_NEXT_ENV_PROFILE_CONFIG: join(root, "env-profiles.json"),
    DEVSPACE_NEXT_CONTEXT_IDLE_TTL_MS: "55000",
    DEVSPACE_NEXT_CONTEXT_WORKTREE_ROOT: join(root, "context-worktrees"),
    DEVSPACE_NEXT_CONTEXT_MAXIMUM_ENTRIES: "12",
    DEVSPACE_NEXT_CONTEXT_MAXIMUM_WORKTREES: "3",
    DEVSPACE_NEXT_CONTEXT_MAXIMUM_WORKTREE_BYTES: "9000000",
    DEVSPACE_NEXT_CONTEXT_DIFF_MAXIMUM_ENTRIES: "7",
    DEVSPACE_NEXT_CONTEXT_DIFF_MAXIMUM_CHARACTERS: "800000",
    DEVSPACE_NEXT_CONTEXT_DIFF_TTL_MS: "45000",
    DEVSPACE_NEXT_PROCESS_OUTPUT_DIR: join(root, "process-output"),
    DEVSPACE_NEXT_SSH_CONTROL_DIR: join(root, "ssh-control"),
    DEVSPACE_NEXT_SELF_MANAGEMENT_DIR: join(root, "self-management"),
    DEVSPACE_NEXT_PM2_PROCESS_NAME: "devspace-custom",
    DEVSPACE_NEXT_PM2_EXPECTED_SCRIPT: join(root, "start-custom.sh"),
    DEVSPACE_NEXT_SELF_RESTART_DELAY_MS: "3000",
    DEVSPACE_NEXT_SELF_RESTART_TIMEOUT_MS: "180000",
    DEVSPACE_NEXT_MAX_RUNNING_PROCESSES: "10",
    DEVSPACE_NEXT_MAX_RUNNING_PROCESSES_PER_TARGET: "4",
    DEVSPACE_NEXT_PROCESS_BUFFER_CHARACTERS: "200000",
    DEVSPACE_NEXT_PROCESS_OUTPUT_MAX_BYTES: "4000000",
    DEVSPACE_NEXT_COMPLETED_PROCESS_TTL_MS: "120000",
    DEVSPACE_NEXT_ARTIFACT_STAGING_DIR: join(root, "artifact-staging"),
    DEVSPACE_NEXT_ARTIFACT_MAXIMUM_ENTRIES: "10",
    DEVSPACE_NEXT_ARTIFACT_MAXIMUM_TOTAL_BYTES: "2000000",
    DEVSPACE_NEXT_ARTIFACT_MAXIMUM_FILE_BYTES: "1000000",
    DEVSPACE_NEXT_ARTIFACT_TTL_MS: "60000",
    DEVSPACE_NEXT_GUI_MAXIMUM_SESSIONS: "8",
    DEVSPACE_NEXT_GUI_SESSION_TTL_MS: "90000",
    DEVSPACE_NEXT_GUI_PAYLOAD_BUDGET_CHARACTERS: "4000",
    DEVSPACE_NEXT_DOWNSTREAM_MCP_MAXIMUM_SESSIONS: "5",
    DEVSPACE_NEXT_DOWNSTREAM_MCP_SESSION_IDLE_TTL_MS: "40000",
    DEVSPACE_NEXT_MCP_RESULT_MAXIMUM_ENTRIES: "6",
    DEVSPACE_NEXT_MCP_RESULT_MAXIMUM_CHARACTERS: "700000",
    DEVSPACE_NEXT_MCP_RESULT_TTL_MS: "50000",
    DEVSPACE_NEXT_ALLOWED_HOSTS: "devspace-next.example.com,127.0.0.1",
    DEVSPACE_NEXT_MCP_SESSION_IDLE_TIMEOUT_MS: "60000",
    DEVSPACE_NEXT_MCP_SESSION_CLEANUP_INTERVAL_MS: "5000",
    DEVSPACE_NEXT_MAXIMUM_MCP_SESSIONS: "9",
  });

  assert.equal(next.host, "0.0.0.0");
  assert.equal(next.port, 17677);
  assert.equal(next.publicBaseUrl, "https://devspace-next.example.com/v2");
  assert.equal(next.publicMcpUrl, "https://devspace-next.example.com/v2/mcp-next/v2");
  assert.equal(next.endpointPath, "/mcp-next/v2");
  assert.deepEqual(next.allowedHosts, ["devspace-next.example.com", "127.0.0.1"]);
  assert.equal(next.mcpSessionIdleTimeoutMs, 60_000);
  assert.equal(next.mcpSessionCleanupIntervalMs, 5_000);
  assert.equal(next.targetConfigPath, join(root, "targets.json"));
  assert.equal(next.mcpRouteConfigPath, join(root, "routes.json"));
  assert.equal(next.contextStorePath, join(root, "context-state.json"));
  assert.equal(next.envProfileConfigPath, join(root, "env-profiles.json"));
  assert.equal(next.contextIdleTtlMs, 55_000);
  assert.equal(next.contextWorktreeRoot, join(root, "context-worktrees"));
  assert.equal(next.contextMaximumEntries, 12);
  assert.equal(next.contextMaximumWorktrees, 3);
  assert.equal(next.contextMaximumWorktreeBytes, 9_000_000);
  assert.equal(next.contextDiffMaximumEntries, 7);
  assert.equal(next.contextDiffMaximumCharacters, 800_000);
  assert.equal(next.contextDiffTtlMs, 45_000);
  assert.equal(next.processOutputDir, join(root, "process-output"));
  assert.equal(next.sshControlDir, join(root, "ssh-control"));
  assert.equal(next.selfManagementDir, join(root, "self-management"));
  assert.equal(next.selfRestartPm2ProcessName, "devspace-custom");
  assert.equal(next.selfRestartExpectedScript, join(root, "start-custom.sh"));
  assert.equal(next.selfRestartDelayMs, 3_000);
  assert.equal(next.selfRestartTimeoutMs, 180_000);
  assert.equal(next.maxRunningProcesses, 10);
  assert.equal(next.maxRunningProcessesPerTarget, 4);
  assert.equal(next.processBufferCharacters, 200_000);
  assert.equal(next.processOutputMaxBytes, 4_000_000);
  assert.equal(next.completedProcessTtlMs, 120_000);
  assert.equal(next.artifactStagingDir, join(root, "artifact-staging"));
  assert.equal(next.artifactMaximumEntries, 10);
  assert.equal(next.artifactMaximumTotalBytes, 2_000_000);
  assert.equal(next.artifactMaximumFileBytes, 1_000_000);
  assert.equal(next.artifactTtlMs, 60_000);
  assert.equal(next.guiMaximumSessions, 8);
  assert.equal(next.guiSessionTtlMs, 90_000);
  assert.equal(next.guiPayloadBudgetCharacters, 4_000);
  assert.equal(next.downstreamMcpMaximumSessions, 5);
  assert.equal(next.downstreamMcpSessionIdleTtlMs, 40_000);
  assert.equal(next.mcpResultMaximumEntries, 6);
  assert.equal(next.mcpResultMaximumCharacters, 700_000);
  assert.equal(next.mcpResultTtlMs, 50_000);
  assert.equal(next.maximumMcpSessions, 9);
});

test("next config accepts a same-origin path prefix but rejects invalid public URLs", async (t) => {
  const root = await mkdtemp(join(tmpdir(), "devspace-v2-config-test-"));
  t.after(() => rm(root, { recursive: true, force: true }));
  const base = baseConfig(root);

  assert.throws(
    () => loadUniversalBrokerNextConfig(base, {
      DEVSPACE_NEXT_MCP_PATH: "/mcp",
    }),
    /conflicts with a reserved endpoint/,
  );
  const sameOrigin = loadUniversalBrokerNextConfig(base, {
    DEVSPACE_NEXT_PUBLIC_BASE_URL: `${base.publicBaseUrl}/v2/`,
  });
  assert.equal(sameOrigin.publicBaseUrl, `${base.publicBaseUrl}/v2`);
  assert.equal(sameOrigin.publicMcpUrl, `${base.publicBaseUrl}/v2/mcp-next`);
  assert.throws(
    () => loadUniversalBrokerNextConfig(base, {
      DEVSPACE_NEXT_STATE_DIR: base.stateDir,
    }),
    /must be separate from the production state directory/,
  );
  assert.throws(
    () => loadUniversalBrokerNextConfig(base, {
      DEVSPACE_NEXT_PUBLIC_BASE_URL: "httpx://example.com",
    }),
    /must use HTTP or HTTPS/,
  );
  assert.throws(
    () => loadUniversalBrokerNextConfig(base, {
      DEVSPACE_NEXT_PUBLIC_BASE_URL: "https://user:secret@example.com/v2",
    }),
    /must not contain credentials/,
  );
  assert.throws(
    () => loadUniversalBrokerNextConfig(base, {
      DEVSPACE_NEXT_PUBLIC_BASE_URL: "https://example.com/v2?query=1",
    }),
    /must not contain credentials/,
  );
});

test("production deployment mode binds the canonical production MCP URL with isolated v2 state", async (t) => {
  const root = await mkdtemp(join(tmpdir(), "devspace-v2-config-test-"));
  t.after(() => rm(root, { recursive: true, force: true }));
  const base = baseConfig(root);
  const production = loadUniversalBrokerNextConfig(base, {
    DEVSPACE_V2_DEPLOYMENT_MODE: "production",
  });

  assert.equal(production.deploymentMode, "production");
  assert.equal(production.host, base.host);
  assert.equal(production.port, base.port);
  assert.equal(production.publicBaseUrl, base.publicBaseUrl);
  assert.equal(production.publicMcpUrl, `${base.publicBaseUrl}/mcp`);
  assert.equal(production.endpointPath, "/mcp");
  assert.equal(
    production.stateDir,
    join(base.stateDir, "universal-broker-v2-production"),
  );
  assert.notEqual(production.stateDir, base.stateDir);

  assert.throws(
    () => loadUniversalBrokerNextConfig(base, {
      DEVSPACE_V2_DEPLOYMENT_MODE: "production",
      DEVSPACE_NEXT_MCP_PATH: "/mcp-next",
    }),
    /must be \/mcp/u,
  );
  assert.throws(
    () => loadUniversalBrokerNextConfig(base, {
      DEVSPACE_V2_DEPLOYMENT_MODE: "production",
      DEVSPACE_NEXT_PUBLIC_BASE_URL: `${base.publicBaseUrl}/v2`,
    }),
    /canonical production \/mcp URL/u,
  );
  assert.throws(
    () => loadUniversalBrokerNextConfig(base, {
      DEVSPACE_V2_DEPLOYMENT_MODE: "unsupported",
    }),
    /Invalid DEVSPACE_V2_DEPLOYMENT_MODE/u,
  );
});

function baseConfig(root: string) {
  return loadConfig({
    DEVSPACE_CONFIG_DIR: join(root, ".config"),
    DEVSPACE_ALLOWED_ROOTS: root,
    DEVSPACE_STATE_DIR: join(root, "state"),
    DEVSPACE_WORKTREE_ROOT: join(root, "worktrees"),
    DEVSPACE_OAUTH_OWNER_TOKEN: "v2-test-owner-token-not-a-real-secret-123456",
    DEVSPACE_HOST: "127.0.0.1",
    DEVSPACE_PORT: "7676",
    DEVSPACE_PUBLIC_BASE_URL: "http://127.0.0.1:7676",
    DEVSPACE_LOG_LEVEL: "silent",
  });
}
