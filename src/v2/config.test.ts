import assert from "node:assert/strict";
import { mkdtemp, readFile, rm, stat, writeFile } from "node:fs/promises";
import { homedir } from "node:os";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { loadConfig } from "../config.js";
import { UNIVERSAL_OWNER_SCOPES } from "./contracts.js";
import { loadUniversalBrokerNextConfig, OAUTH_OFFLINE_ACCESS_SCOPE } from "./config.js";
import { UniversalMcpRouteRegistry } from "./mcp-routes.js";
import { TargetRegistry } from "./targets.js";

const PARALLEL_OWNER_ENV = {
  DEVSPACE_NEXT_AUTHORITY_OWNER_INSTANCE_ID: "parallel-config-test-owner",
} as const;

test("next config uses an isolated port, endpoint, state directory, and full owner scopes", async (t) => {
  const root = await mkdtemp(join(tmpdir(), "devspace-v2-config-test-"));
  t.after(() => rm(root, { recursive: true, force: true }));
  const base = baseConfig(root);
  assert.throws(
    () => loadUniversalBrokerNextConfig(base, {}),
    /DEVSPACE_NEXT_AUTHORITY_OWNER_INSTANCE_ID/u,
  );
  const next = loadUniversalBrokerNextConfig(base, PARALLEL_OWNER_ENV);

  assert.equal(next.deploymentMode, "parallel");
  assert.equal(next.port, base.port + 1);
  assert.equal(next.deploymentMode, "parallel");
  assert.equal(next.endpointPath, "/mcp-next");
  assert.equal(next.healthPath, "/healthz-next");
  assert.equal(next.metricsPath, "/metrics");
  assert.equal(next.managementHost, "127.0.0.1");
  assert.equal(next.managementPort, next.port + 1_000);
  assert.equal(next.readyPath, "/readyz");
  assert.equal(next.artifactPathPrefix, "/artifacts-next");
  assert.equal(next.publicBaseUrl, `http://127.0.0.1:${base.port + 1}`);
  assert.equal(next.publicMcpUrl, `http://127.0.0.1:${base.port + 1}/mcp-next`);
  assert.equal(next.stateDir, join(base.stateDir, "universal-broker-v2"));
  assert.equal(next.authorityStorePath, join(next.stateDir, "authority.sqlite"));
  assert.equal(
    next.connectorActivationJournalPath,
    join(next.stateDir, "connector-activation-journal.sqlite"),
  );
  assert.equal(next.lifecycleFinalizationStorePath, join(next.stateDir, "lifecycle.sqlite"));
  assert.equal(next.authorityPrincipalMode, "single-owner");
  assert.equal(next.authorityOwnerInstanceId, "parallel-config-test-owner");
  assert.equal(next.oauthStateDir, next.stateDir);
  assert.equal(next.targetConfigPath, join(root, ".config", "targets.v2.json"));
  assert.equal(next.mcpRouteConfigPath, join(root, ".config", "mcp-routes.v2.json"));
  assert.equal(next.contextStorePath, join(next.stateDir, "contexts.json"));
  assert.equal(next.envProfileConfigPath, join(homedir(), ".devspace", "env-profiles.v2.json"));
  assert.equal(next.contextIdleTtlMs, 30 * 60_000);
  assert.equal(next.contextWorktreeRoot, join(next.stateDir, "worktrees"));
  assert.equal(next.contextMaximumEntries, 64);
  assert.equal(next.contextMaximumWorktrees, 8);
  assert.equal(next.contextMaximumWorktreeBytes, 8 * 1024 * 1024 * 1024);
  assert.equal(next.contextDiffMaximumEntries, 64);
  assert.equal(next.contextDiffMaximumCharacters, 50_000_000);
  assert.equal(next.contextDiffTtlMs, 15 * 60_000);
  assert.equal(next.processOutputDir, join(next.stateDir, "process-output"));
  assert.equal(next.selfManagementDir, join(next.stateDir, "self-management"));
  assert.equal(next.selfRestartPm2ProcessName, "devspace-next");
  assert.equal(next.selfRestartExpectedScript, undefined);
  assert.equal(next.selfRestartTimeoutMs, 120_000);
  assert.equal(next.maxRunningProcesses, 16);
  assert.equal(next.maxRunningProcessesPerTarget, 16);
  assert.equal(next.maximumProcessRecords, 128);
  assert.equal(next.processBufferCharacters, 64 * 1024);
  assert.equal(next.processOutputMaxBytes, 100 * 1024 * 1024);
  assert.equal(next.completedProcessTtlMs, 15 * 60_000);
  assert.equal(next.artifactStagingDir, join(next.stateDir, "artifacts"));
  assert.equal(next.artifactMaximumEntries, 256);
  assert.equal(next.artifactMaximumTotalBytes, 2 * 1024 * 1024 * 1024);
  assert.equal(next.artifactMaximumFileBytes, 1024 * 1024 * 1024);
  assert.equal(next.artifactTtlMs, 24 * 60 * 60_000);
  assert.equal(next.guiMaximumSessions, 16);
  assert.equal(next.guiSessionTtlMs, 10 * 60_000);
  assert.equal(next.guiPayloadBudgetCharacters, 12_000);
  assert.equal(next.downstreamMcpMaximumSessions, 64);
  assert.equal(next.downstreamMcpSessionIdleTtlMs, 15 * 60_000);
  assert.equal(next.mcpResultMaximumEntries, 64);
  assert.equal(next.mcpResultMaximumBytes, 256 * 1024 * 1024);
  assert.equal(next.mcpResultTtlMs, 15 * 60_000);
  assert.equal(next.maximumMcpSessions, 128);
  assert.equal(next.canonicalConnectorName, "myDevSpace");
  assert.equal(next.authorityDeployment, "in-process");
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
    DEVSPACE_NEXT_AUTHORITY_OWNER_INSTANCE_ID: "production-owner",
  });

  assert.equal(production.deploymentMode, "production");
  assert.equal(production.endpointPath, "/mcp");
  assert.equal(production.healthPath, "/healthz");
  assert.equal(production.metricsPath, "/metrics");
  assert.equal(production.artifactPathPrefix, "/artifacts");
  assert.equal(production.oauthStateDir, base.stateDir);
  assert.equal(production.stateDir, join(root, "v2-production-state"));
  assert.equal(production.authorityStorePath, join(production.stateDir, "authority.sqlite"));
  assert.equal(
    production.connectorActivationJournalPath,
    join(production.stateDir, "connector-activation-journal.sqlite"),
  );
  assert.equal(
    production.lifecycleFinalizationStorePath,
    join(production.stateDir, "lifecycle.sqlite"),
  );
  assert.equal(production.publicBaseUrl, new URL(base.publicBaseUrl).origin);
  assert.equal(production.selfRestartPm2ProcessName, "devspace-v2-production");

  const isolatedCandidate = loadUniversalBrokerNextConfig(base, {
    DEVSPACE_V2_DEPLOYMENT_MODE: "production",
    DEVSPACE_NEXT_PUBLIC_BASE_URL: base.publicBaseUrl,
    DEVSPACE_NEXT_STATE_DIR: join(root, "candidate-state"),
    DEVSPACE_NEXT_OAUTH_STATE_DIR: join(root, "candidate-oauth"),
    DEVSPACE_NEXT_AUTHORITY_OWNER_INSTANCE_ID: "candidate-owner",
  });
  assert.equal(isolatedCandidate.oauthStateDir, join(root, "candidate-oauth"));
  assert.notEqual(isolatedCandidate.oauthStateDir, base.stateDir);

  assert.throws(
    () => loadUniversalBrokerNextConfig(base, {
      DEVSPACE_V2_DEPLOYMENT_MODE: "production",
      DEVSPACE_NEXT_PUBLIC_BASE_URL: base.publicBaseUrl,
      DEVSPACE_NEXT_MCP_PATH: "/mcp-next",
      DEVSPACE_NEXT_AUTHORITY_OWNER_INSTANCE_ID: "invalid-path-owner",
    }),
    /canonical \/mcp endpoint/,
  );

  const granularOnly = loadUniversalBrokerNextConfig(base, {
    DEVSPACE_V2_DEPLOYMENT_MODE: "production",
    DEVSPACE_V2_LEGACY_SCOPE_COMPATIBILITY: "false",
    DEVSPACE_NEXT_AUTHORITY_OWNER_INSTANCE_ID: "granular-only-owner",
  });
  assert.deepEqual(granularOnly.oauth.scopes, [...UNIVERSAL_OWNER_SCOPES, OAUTH_OFFLINE_ACCESS_SCOPE]);

  assert.throws(
    () => loadUniversalBrokerNextConfig(base, {
      ...PARALLEL_OWNER_ENV,
      DEVSPACE_V2_LEGACY_SCOPE_COMPATIBILITY: "true",
    }),
    /removed in Universal Broker v2\.1/,
  );
  assert.throws(
    () => loadUniversalBrokerNextConfig(base, {
      ...PARALLEL_OWNER_ENV,
      DEVSPACE_NEXT_MCP_SESSION_IDLE_TIMEOUT_MS: String(24 * 60 * 60_000 + 1),
    }),
    /DEVSPACE_NEXT_MCP_SESSION_IDLE_TIMEOUT_MS/,
  );
  assert.throws(
    () => loadUniversalBrokerNextConfig(base, {
      ...PARALLEL_OWNER_ENV,
      DEVSPACE_NEXT_MCP_SESSION_CLEANUP_INTERVAL_MS: String(60 * 60_000 + 1),
    }),
    /DEVSPACE_NEXT_MCP_SESSION_CLEANUP_INTERVAL_MS/,
  );
  assert.throws(
    () => loadUniversalBrokerNextConfig(base, {
      ...PARALLEL_OWNER_ENV,
      DEVSPACE_NEXT_STATE_DIR: join(root, "authority-state"),
      DEVSPACE_NEXT_AUTHORITY_STORE: join(root, "outside-authority.sqlite"),
    }),
    /must stay inside DEVSPACE_NEXT_STATE_DIR/,
  );
  assert.throws(
    () => loadUniversalBrokerNextConfig(base, {
      ...PARALLEL_OWNER_ENV,
      DEVSPACE_NEXT_STATE_DIR: join(root, "shared-authority-state"),
      DEVSPACE_NEXT_OAUTH_STATE_DIR: join(root, "shared-authority-state"),
      DEVSPACE_NEXT_AUTHORITY_STORE: join(root, "shared-authority-state", "devspace.sqlite"),
    }),
    /must not reuse the OAuth database/,
  );
  assert.throws(
    () => loadUniversalBrokerNextConfig(base, {
      ...PARALLEL_OWNER_ENV,
      DEVSPACE_NEXT_STATE_DIR: join(root, "connector-journal-state"),
      DEVSPACE_NEXT_CONNECTOR_ACTIVATION_JOURNAL: join(root, "outside-connector-journal.sqlite"),
    }),
    /CONNECTOR_ACTIVATION_JOURNAL must stay inside DEVSPACE_NEXT_STATE_DIR/,
  );
  assert.throws(
    () => loadUniversalBrokerNextConfig(base, {
      ...PARALLEL_OWNER_ENV,
      DEVSPACE_NEXT_STATE_DIR: join(root, "shared-connector-journal-state"),
      DEVSPACE_NEXT_CONNECTOR_ACTIVATION_JOURNAL: join(
        root,
        "shared-connector-journal-state",
        "authority.sqlite",
      ),
    }),
    /CONNECTOR_ACTIVATION_JOURNAL must use a dedicated database path/,
  );
  assert.throws(
    () => loadUniversalBrokerNextConfig(base, {
      ...PARALLEL_OWNER_ENV,
      DEVSPACE_NEXT_STATE_DIR: join(root, "lifecycle-state"),
      DEVSPACE_NEXT_LIFECYCLE_FINALIZATION_STORE: join(root, "outside", "lifecycle.sqlite"),
    }),
    /LIFECYCLE_FINALIZATION_STORE must stay inside DEVSPACE_NEXT_STATE_DIR/,
  );
  assert.throws(
    () => loadUniversalBrokerNextConfig(base, {
      ...PARALLEL_OWNER_ENV,
      DEVSPACE_NEXT_STATE_DIR: join(root, "lifecycle-name-state"),
      DEVSPACE_NEXT_LIFECYCLE_FINALIZATION_STORE: join(
        root,
        "lifecycle-name-state",
        "finalization.sqlite",
      ),
    }),
    /LIFECYCLE_FINALIZATION_STORE must use the canonical lifecycle.sqlite basename/,
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
    DEVSPACE_NEXT_CONNECTOR_ACTIVATION_JOURNAL: join(root, "next-state", "activation.sqlite"),
    DEVSPACE_NEXT_LIFECYCLE_FINALIZATION_STORE: join(root, "next-state", "lifecycle.sqlite"),
    DEVSPACE_NEXT_AUTHORITY_PRINCIPAL_MODE: "single-owner",
    DEVSPACE_NEXT_AUTHORITY_OWNER_INSTANCE_ID: "configured-owner-instance",
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
    DEVSPACE_NEXT_MCP_RESULT_MAXIMUM_BYTES: "700000",
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
  assert.equal(next.authorityPrincipalMode, "single-owner");
  assert.equal(next.authorityOwnerInstanceId, "configured-owner-instance");
  assert.equal(next.connectorActivationJournalPath, join(root, "next-state", "activation.sqlite"));
  assert.equal(next.lifecycleFinalizationStorePath, join(root, "next-state", "lifecycle.sqlite"));
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
  assert.equal(next.mcpResultMaximumBytes, 700_000);
  assert.equal(next.mcpResultTtlMs, 50_000);
  assert.equal(next.maximumMcpSessions, 9);

  assert.throws(
    () => loadUniversalBrokerNextConfig(baseConfig(root), {
      ...PARALLEL_OWNER_ENV,
      DEVSPACE_NEXT_AUTHORITY_PRINCIPAL_MODE: "shared-session",
    }),
    /DEVSPACE_NEXT_AUTHORITY_PRINCIPAL_MODE/u,
  );
  assert.throws(
    () => loadUniversalBrokerNextConfig(baseConfig(root), {
      ...PARALLEL_OWNER_ENV,
      DEVSPACE_NEXT_AUTHORITY_OWNER_INSTANCE_ID: "   ",
    }),
    /DEVSPACE_NEXT_AUTHORITY_OWNER_INSTANCE_ID/u,
  );
  assert.throws(
    () => loadUniversalBrokerNextConfig(baseConfig(root), {
      DEVSPACE_NEXT_AUTHORITY_PRINCIPAL_MODE: "multi-user",
    }),
    /supports single-owner only/u,
  );
});

test("next config accepts a same-origin path prefix but rejects invalid public URLs", async (t) => {
  const root = await mkdtemp(join(tmpdir(), "devspace-v2-config-test-"));
  t.after(() => rm(root, { recursive: true, force: true }));
  const base = baseConfig(root);

  assert.throws(
    () => loadUniversalBrokerNextConfig(base, {
      ...PARALLEL_OWNER_ENV,
      DEVSPACE_NEXT_MCP_PATH: "/mcp",
    }),
    /conflicts with a reserved endpoint/,
  );
  const sameOrigin = loadUniversalBrokerNextConfig(base, {
    ...PARALLEL_OWNER_ENV,
    DEVSPACE_NEXT_PUBLIC_BASE_URL: `${base.publicBaseUrl}/v2/`,
  });
  assert.equal(sameOrigin.publicBaseUrl, `${base.publicBaseUrl}/v2`);
  assert.equal(sameOrigin.publicMcpUrl, `${base.publicBaseUrl}/v2/mcp-next`);
  assert.throws(
    () => loadUniversalBrokerNextConfig(base, {
      ...PARALLEL_OWNER_ENV,
      DEVSPACE_NEXT_STATE_DIR: base.stateDir,
    }),
    /must be separate from the production state directory/,
  );
  assert.throws(
    () => loadUniversalBrokerNextConfig(base, {
      ...PARALLEL_OWNER_ENV,
      DEVSPACE_NEXT_PUBLIC_BASE_URL: "httpx://example.com",
    }),
    /must use HTTP or HTTPS/,
  );
  assert.throws(
    () => loadUniversalBrokerNextConfig(base, {
      ...PARALLEL_OWNER_ENV,
      DEVSPACE_NEXT_PUBLIC_BASE_URL: "https://user:secret@example.com/v2",
    }),
    /must not contain credentials/,
  );
  assert.throws(
    () => loadUniversalBrokerNextConfig(base, {
      ...PARALLEL_OWNER_ENV,
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
    DEVSPACE_NEXT_AUTHORITY_OWNER_INSTANCE_ID: "canonical-production-owner",
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
      DEVSPACE_NEXT_AUTHORITY_OWNER_INSTANCE_ID: "invalid-production-path-owner",
    }),
    /must be \/mcp/u,
  );
  assert.throws(
    () => loadUniversalBrokerNextConfig(base, {
      DEVSPACE_V2_DEPLOYMENT_MODE: "production",
      DEVSPACE_NEXT_PUBLIC_BASE_URL: `${base.publicBaseUrl}/v2`,
      DEVSPACE_NEXT_AUTHORITY_OWNER_INSTANCE_ID: "invalid-production-url-owner",
    }),
    /canonical production \/mcp URL/u,
  );
  assert.throws(
    () => loadUniversalBrokerNextConfig(base, {
      DEVSPACE_V2_DEPLOYMENT_MODE: "unsupported",
    }),
    /Invalid DEVSPACE_V2_DEPLOYMENT_MODE/u,
  );
  assert.throws(
    () => loadUniversalBrokerNextConfig(base, {
      DEVSPACE_V2_DEPLOYMENT_MODE: "production",
    }),
    /DEVSPACE_NEXT_AUTHORITY_OWNER_INSTANCE_ID/u,
  );
});

test("unified production config is canonical, materializes inline registries, and honors explicit env overrides", async (t) => {
  const root = await mkdtemp(join(tmpdir(), "devspace-v2-unified-config-test-"));
  t.after(() => rm(root, { recursive: true, force: true }));
  const firstPath = join(root, "first.json");
  const secondPath = join(root, "second.json");
  const input = productionUnifiedConfig(root);
  await writeFile(firstPath, JSON.stringify(input, null, 2));
  await writeFile(
    secondPath,
    JSON.stringify(Object.fromEntries(Object.entries(input).reverse()), null, 2),
  );

  const first = loadUniversalBrokerNextConfig(baseConfig(root), {
    DEVSPACE_V2_CONFIG_FILE: firstPath,
  });
  const reordered = loadUniversalBrokerNextConfig(baseConfig(root), {
    DEVSPACE_V2_CONFIG_FILE: secondPath,
  });
  const overridden = loadUniversalBrokerNextConfig(baseConfig(root), {
    DEVSPACE_V2_CONFIG_FILE: firstPath,
    DEVSPACE_NEXT_CONTEXT_MAXIMUM_ENTRIES: "129",
  });

  assert.equal(first.configSourcePath, firstPath);
  assert.equal(first.configProfile, "production");
  assert.equal(first.publicBaseUrl, "http://127.0.0.1:8686");
  assert.equal(first.publicMcpUrl, "http://127.0.0.1:8686/mcp");
  assert.equal(first.oauthIssuer, "http://127.0.0.1:8686");
  assert.equal(first.oauthResource, "http://127.0.0.1:8686/mcp");
  assert.equal(first.authorityOwnerInstanceId, "stable-production-owner");
  assert.equal(first.authorityMode, "enforced");
  assert.deepEqual(first.authorityTtlSeconds, { R1: 1800, R2: 900, R3: 300 });
  assert.deepEqual(first.authorityMaximumUses, { R1: 50, R2: 10, R3: 1 });
  assert.equal(first.authorityResourceLeaseTtlSeconds, 900);
  assert.equal(first.authorityResourceLeaseHeartbeatSeconds, 30);
  assert.equal(first.authorityResourceLeaseRecoveryGraceSeconds, 60);
  assert.equal(first.authorityApprovalAssurance, "cooperative");
  assert.equal(first.authorityMaximumActionsPerPlan, 64);
  assert.equal(first.supervisorEndpoint, "http://127.0.0.1:9797");
  assert.equal(first.supervisorRestartMaximumAttempts, 4);
  assert.equal(first.publicMetrics, false);
  assert.equal(first.canonicalConnectorName, "myDevSpace");
  assert.equal(first.contextMaximumEntries, 64);
  assert.equal(first.maximumProcessRecords, 128);
  assert.equal(first.maxRunningProcesses, 16);
  assert.equal(first.downstreamMcpMaximumSessions, 64);
  assert.equal(first.guiMaximumSessions, 16);
  assert.equal(first.artifactMaximumEntries, 256);
  assert.equal(first.processBufferCharacters, 65_536);
  assert.equal(first.processOutputMaxBytes, 104_857_600);
  assert.equal(first.artifactMaximumFileBytes, 1_073_741_824);
  assert.equal(first.artifactMaximumTotalBytes, 2_147_483_648);
  assert.equal(first.artifactCatalogPath, join(root, "unified-state", "artifacts.sqlite"));
  assert.equal(first.artifactObjectRoot, join(root, "unified-state", "artifact-objects"));
  assert.equal(first.lifecycleFinalizationStorePath, join(root, "unified-state", "lifecycle.sqlite"));
  assert.equal(first.cursorTtlMs, 600_000);
  assert.equal(first.mcpResultTtlMs, 900_000);
  assert.equal(first.cursorMaximumSnapshotsPerPrincipal, 128);
  assert.equal(first.connectorDrainGraceSeconds, 3_600);
  assert.equal(first.rateLimit.mode, "internal");
  assert.equal(first.contextIdleTtlMs, 1_800_000);
  assert.equal(first.completedProcessTtlMs, 900_000);
  assert.equal(first.downstreamMcpSessionIdleTtlMs, 900_000);
  assert.equal(first.guiSessionTtlMs, 600_000);
  assert.equal(first.artifactTtlMs, 86_400_000);
  assert.match(first.configDigest, /^sha256:[a-f0-9]{64}$/u);
  assert.equal(first.configDigest, reordered.configDigest);
  assert.notEqual(first.configDigest, overridden.configDigest);
  assert.equal(overridden.contextMaximumEntries, 129);

  assert.equal(first.targetConfigPath, join(root, "unified-state", "generated-config", "targets.v1.json"));
  assert.equal(first.mcpRouteConfigPath, join(root, "unified-state", "generated-config", "mcp-routes.v1.json"));
  assert.equal((await stat(first.targetConfigPath)).mode & 0o777, 0o600);
  assert.equal((await stat(first.mcpRouteConfigPath)).mode & 0o777, 0o600);
  const materializedTargets = JSON.parse(await readFile(first.targetConfigPath, "utf8")) as {
    targets: Record<string, {
      endpointId: string;
      sshHost?: string;
      capabilities?: Record<string, boolean>;
      gui?: { mode?: string };
    }>;
  };
  assert.equal(materializedTargets.targets.company?.sshHost, "company");
  assert.equal(materializedTargets.targets["company-readonly"]?.endpointId, "company-mac");
  assert.equal(materializedTargets.targets.local?.capabilities?.exec, true);
  assert.equal(materializedTargets.targets.local?.gui?.mode, "local-ipc");
  assert.deepEqual(
    materializedTargets.targets["company-readonly"]?.capabilities,
    materializedTargets.targets.company?.capabilities,
  );

  const targetSnapshot = await new TargetRegistry({ configPath: first.targetConfigPath }).inspect();
  assert.equal(targetSnapshot.targets.find((target) => target.id === "company")?.endpointId, "company-mac");
  assert.equal(
    targetSnapshot.targets.find((target) => target.id === "company-readonly")?.endpointId,
    "company-mac",
  );
  assert.equal(
    targetSnapshot.targets.find((target) => target.id === "local")?.configuredCapabilities.gui,
    true,
  );
  const routeSnapshot = await new UniversalMcpRouteRegistry(first.mcpRouteConfigPath).inspect();
  assert.equal(routeSnapshot.routes[0]?.id, "company-jira");
  assert.equal(routeSnapshot.routes[0]?.target, "company-readonly");
  assert.equal(routeSnapshot.routes[0]?.transport, "ssh-stdio");
});

test("unified YAML config uses central defaults", async (t) => {
  const root = await mkdtemp(join(tmpdir(), "devspace-v2-unified-yaml-test-"));
  t.after(() => rm(root, { recursive: true, force: true }));
  const path = join(root, "config.yaml");
  await writeFile(path, [
    "version: 2",
    "productProfile: BASE_SINGLE_OWNER",
    "profile: development",
    "oauth:",
    "  principalMode: single-owner",
    "  ownerInstanceId: yaml-stable-owner",
    "supervisor:",
    "  endpoint: internal://pm2",
    "storage:",
    `  stateDirectory: ${JSON.stringify(join(root, "yaml-state"))}`,
    "targets: []",
    "mcpRoutes: []",
    "",
  ].join("\n"));

  const config = loadUniversalBrokerNextConfig(baseConfig(root), {
    DEVSPACE_V2_CONFIG_FILE: path,
  });
  assert.equal(config.configProfile, "development");
  assert.equal(config.authorityOwnerInstanceId, "yaml-stable-owner");
  assert.equal(config.contextMaximumEntries, 64);
  assert.equal(config.artifactTtlMs, 24 * 60 * 60_000);
  assert.equal(config.targetConfigPath, join(root, "yaml-state", "generated-config", "targets.v1.json"));
});

test("unified production validation rejects unsafe policy and broken references", async (t) => {
  const root = await mkdtemp(join(tmpdir(), "devspace-v2-unified-negative-test-"));
  t.after(() => rm(root, { recursive: true, force: true }));
  const base = baseConfig(root);
  let sequence = 0;
  const load = async (value: unknown) => {
    const path = join(root, `invalid-${sequence++}.json`);
    await writeFile(path, JSON.stringify(value));
    return () => loadUniversalBrokerNextConfig(base, { DEVSPACE_V2_CONFIG_FILE: path });
  };

  const anonymous = productionUnifiedConfig(root);
  anonymous.oauth.allowAnonymousSessionFallback = true;
  assert.throws(await load(anonymous), /allowAnonymousSessionFallback|expected false/u);

  const publicMetrics = productionUnifiedConfig(root);
  publicMetrics.observability.publicMetrics = true;
  assert.throws(await load(publicMetrics), /publicMetrics|expected false/u);

  const auditAuthority = productionUnifiedConfig(root);
  auditAuthority.authority.mode = "audit";
  assert.throws(await load(auditAuthority), /authority\.mode must be enforced/u);

  const repeatedR3 = productionUnifiedConfig(root);
  repeatedR3.authority.maximumUses.R3 = 2;
  assert.throws(await load(repeatedR3), /R3 authority maximumUses must be exactly 1/u);

  const sidecar = productionUnifiedConfig(root);
  sidecar.authority.deployment = "sidecar";
  assert.throws(await load(sidecar), /deployment|in-process/u);

  const attestation = productionUnifiedConfig(root);
  (attestation.authority as Record<string, unknown>).requireHostAttestation = true;
  assert.throws(await load(attestation), /requireHostAttestation|Unrecognized/u);

  const duplicateTarget = productionUnifiedConfig(root);
  duplicateTarget.targets.push({ ...duplicateTarget.targets[0]! });
  assert.throws(await load(duplicateTarget), /duplicate targetId local/u);

  const unknownReference = productionUnifiedConfig(root);
  unknownReference.mcpRoutes[0]!.targetId = "missing";
  unknownReference.mcpRoutes[0]!.transport.targetId = "missing";
  assert.throws(await load(unknownReference), /references unknown target missing/u);

  const relativeMcpCommand = productionUnifiedConfig(root);
  relativeMcpCommand.mcpRoutes[0]!.transport.command = "mcp-router";
  assert.throws(await load(relativeMcpCommand), /absolute remote path/u);

  const aliasCycle = productionUnifiedConfig(root);
  Object.assign(aliasCycle.targets[1]!, { aliasOf: "company-readonly" });
  Object.assign(aliasCycle.targets[2]!, { aliasOf: "company" });
  assert.throws(await load(aliasCycle), /target alias cycle/u);

  const elevation = productionUnifiedConfig(root);
  elevation.targets[0]!.elevationPolicy = "sudo";
  assert.throws(await load(elevation), /elevationPolicy must be deny/u);

  const missingConnector = productionUnifiedConfig(root);
  delete (missingConnector as { connector?: unknown }).connector;
  assert.throws(await load(missingConnector), /canonicalConnectorName/u);

  assert.throws(
    () => loadUniversalBrokerNextConfig(base, {
      DEVSPACE_NEXT_SELF_RESTART_DELAY_MS: "2000",
      DEVSPACE_NEXT_AUTHORITY_OWNER_INSTANCE_ID: "delay-negative-owner",
    }),
    /requires transport ACK_FLUSHED evidence/u,
  );
});

test("published config schema describes the unified production safety surface", async () => {
  const schema = JSON.parse(
    await readFile(join(process.cwd(), "config", "config.schema.json"), "utf8"),
  ) as Record<string, unknown>;
  assert.equal(schema.$schema, "https://json-schema.org/draft/2020-12/schema");
  assert.deepEqual(schema.required, ["version", "productProfile"]);
  assert.equal(
    ((schema.properties as Record<string, unknown>).observability as {
      properties: { publicMetrics: { const: boolean } };
    }).properties.publicMetrics.const,
    false,
  );
  assert.deepEqual(
    (((schema.properties as Record<string, unknown>).authority as {
      properties: { mode: { enum: string[] } };
    }).properties.mode.enum),
    ["enforced", "audit", "disabled"],
  );
  const schemaText = JSON.stringify(schema);
  assert.doesNotMatch(schemaText, /multi-user|sidecar|host-attested|requireHostAttestation|GUI_CAPTURE/u);
  assert.match(schemaText, /BASE_SINGLE_OWNER/u);
});

function productionUnifiedConfig(root: string) {
  return {
    version: 2,
    productProfile: "BASE_SINGLE_OWNER",
    profile: "production",
    server: {
      publicBaseUrl: "http://127.0.0.1:8686",
      mcpPath: "/mcp",
      dataPlane: { host: "127.0.0.1", port: 8686 },
      managementPlane: { host: "127.0.0.1", port: 9696 },
    },
    oauth: {
      issuer: "http://127.0.0.1:8686",
      resource: "http://127.0.0.1:8686/mcp",
      principalMode: "single-owner",
      ownerInstanceId: "stable-production-owner",
      capabilityScopes: [...UNIVERSAL_OWNER_SCOPES],
      allowOfflineAccess: true,
      legacyBlanketScopeCompatibility: false,
      adminScopeEnabled: false,
      allowAnonymousSessionFallback: false,
    },
    authority: {
      mode: "enforced",
      deployment: "in-process",
      approvalAssurance: "cooperative",
      stateDirectory: join(root, "unified-state", "authority"),
      r0FastPath: true,
      authorityTtlSeconds: { R1: 1800, R2: 900, R3: 300 },
      resourceLease: { ttlSeconds: 900, heartbeatSeconds: 30, recoveryGraceSeconds: 60 },
      maximumActionsPerPlan: 64,
      maximumUses: { R1: 50, R2: 10, R3: 1 },
    },
    supervisor: {
      endpoint: "http://127.0.0.1:9797",
      processManager: "pm2",
      transactionDirectory: join(root, "unified-state", "restarts"),
      healthTimeoutMs: 30_000,
      responseFlushRequired: true,
      restartPolicy: { maximumAttempts: 4, maximumDelayMs: 60_000 },
    },
    pagination: {
      cursorTtlSeconds: 600,
      maximumSnapshotsPerPrincipal: 128,
      signingKeyRef: join(root, "cursor-current.key"),
      previousSigningKeyRef: join(root, "cursor-previous.key"),
    },
    artifact: {
      catalogPath: join(root, "unified-state", "artifacts.sqlite"),
      objectRoot: join(root, "unified-state", "artifact-objects"),
      defaultTtlSeconds: 86_400,
      maximumArtifactBytes: 1_073_741_824,
      maximumTotalBytes: 2_147_483_648,
    },
    connector: {
      canonicalName: "myDevSpace",
      activationMode: "owner-approved",
      drainGraceSeconds: 3_600,
    },
    rateLimit: {
      mode: "internal",
      preAuth: { refillPerMinute: 120, burst: 30 },
      postAuth: { refillPerMinute: 600, burst: 100 },
      initialize: { refillPerMinute: 30, burst: 10 },
    },
    management: { bind: "127.0.0.1", port: 9696, publicExposure: "deny" },
    audit: {
      sink: join(root, "unified-state", "audit", "operations.jsonl"),
      flushIntervalMs: 250,
      rawArguments: false,
    },
    storage: {
      root,
      stateDirectory: join(root, "unified-state"),
      lifecycleFinalizationStore: join(root, "unified-state", "lifecycle.sqlite"),
      artifactRoot: join(root, "resources", "artifacts", "sha256"),
      processOutputRoot: join(root, "resources", "process-output"),
      stateFileMode: "0600",
      directoryMode: "0700",
    },
    quotas: {
      contexts: 64,
      processes: 128,
      concurrentProcesses: 16,
      mcpConnections: 64,
      mcpRetainedResultBytes: 268_435_456,
      guiSessions: 16,
      artifacts: 256,
      inlineOutputBytes: 65_536,
      processOutputBytes: 104_857_600,
      artifactMaxBytes: 1_073_741_824,
    },
    ttls: {
      contextSeconds: 1_800,
      completedProcessSeconds: 900,
      mcpIdleSeconds: 900,
      guiSeconds: 600,
      artifactSeconds: 86_400,
      cursorSnapshotSeconds: 600,
      mcpRetainedResultSeconds: 900,
    },
    targets: [
      {
        targetId: "local",
        displayName: "Local Mac",
        endpointId: "local-primary",
        transport: "local",
        platform: "macos",
        defaultCwd: root,
        elevationPolicy: "deny",
        capabilities: { fs: true, exec: true, pty: true, mcp: true, artifact: true, gui: true },
      },
      {
        targetId: "company",
        displayName: "Company Mac",
        aliases: ["corp"],
        endpointId: "company-mac",
        transport: "ssh",
        host: "company",
        user: "remote-user",
        platform: "macos",
        defaultCwd: "/Users/remote-user",
        elevationPolicy: "deny",
        capabilities: { fs: true, exec: true, pty: true, mcp: true, artifact: true, gui: false },
      },
      {
        targetId: "company-readonly",
        displayName: "Company Read Only",
        aliasOf: "company",
        transport: "ssh",
        host: "company",
        user: "remote-user",
        platform: "macos",
        defaultCwd: "/Users/remote-user",
        elevationPolicy: "deny",
      },
    ],
    mcpRoutes: [
      {
        routeId: "company-jira",
        displayName: "Jira via Company Mac",
        enabled: true,
        targetId: "company-readonly",
        transport: {
          type: "ssh-stdio",
          targetId: "company-readonly",
          command: "/usr/local/bin/mcp-router",
          args: ["jira-oauth"],
        },
        idleTtlSeconds: 900,
        connectTimeoutMs: 15_000,
        invokeTimeoutMs: 120_000,
      },
    ],
    observability: {
      publicHealth: true,
      publicMetrics: false,
      logLevel: "info",
      redactSecrets: true,
    },
    release: {
      expectedToolNames: ["target", "context", "fs", "exec", "process", "mcp", "artifact", "gui"],
      requireCleanSource: true,
      requireRuntimeBuildDigestMatch: true,
      requireAuthorityContractDigestMatch: true,
      requireHostSessionChurnCanary: true,
      forbidParallelRuntime: true,
      forbidLegacyScopes: true,
      forbidPrivilegedArtifacts: true,
    },
  };
}

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
