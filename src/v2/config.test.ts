import assert from "node:assert/strict";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { loadConfig } from "../config.js";
import { UNIVERSAL_OWNER_SCOPES } from "./contracts.js";
import { loadUniversalBrokerNextConfig } from "./config.js";

test("next config uses an isolated port, endpoint, state directory, and full owner scopes", async (t) => {
  const root = await mkdtemp(join(tmpdir(), "devspace-v2-config-test-"));
  t.after(() => rm(root, { recursive: true, force: true }));
  const base = baseConfig(root);
  const next = loadUniversalBrokerNextConfig(base, {});

  assert.equal(next.port, base.port + 1);
  assert.equal(next.endpointPath, "/mcp-next");
  assert.equal(next.publicBaseUrl, `http://127.0.0.1:${base.port + 1}`);
  assert.equal(next.stateDir, join(base.stateDir, "universal-broker-v2"));
  assert.equal(next.targetConfigPath, join(root, ".config", "targets.v2.json"));
  assert.equal(next.mcpRouteConfigPath, join(root, ".config", "mcp-routes.v2.json"));
  assert.equal(next.contextStorePath, join(next.stateDir, "contexts.json"));
  assert.equal(next.processOutputDir, join(next.stateDir, "process-output"));
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
  assert.deepEqual(next.oauth.scopes, [...UNIVERSAL_OWNER_SCOPES]);
  assert.notEqual(next.stateDir, base.stateDir);
});

test("next config accepts explicit parallel deployment values", async (t) => {
  const root = await mkdtemp(join(tmpdir(), "devspace-v2-config-test-"));
  t.after(() => rm(root, { recursive: true, force: true }));
  const next = loadUniversalBrokerNextConfig(baseConfig(root), {
    DEVSPACE_NEXT_HOST: "0.0.0.0",
    DEVSPACE_NEXT_PORT: "17677",
    DEVSPACE_NEXT_PUBLIC_BASE_URL: "https://devspace-next.example.com",
    DEVSPACE_NEXT_MCP_PATH: "/mcp-next/v2",
    DEVSPACE_NEXT_STATE_DIR: join(root, "next-state"),
    DEVSPACE_NEXT_TARGETS_FILE: join(root, "targets.json"),
    DEVSPACE_NEXT_MCP_ROUTES_FILE: join(root, "routes.json"),
    DEVSPACE_NEXT_CONTEXT_STORE: join(root, "context-state.json"),
    DEVSPACE_NEXT_PROCESS_OUTPUT_DIR: join(root, "process-output"),
    DEVSPACE_NEXT_SSH_CONTROL_DIR: join(root, "ssh-control"),
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
    DEVSPACE_NEXT_ALLOWED_HOSTS: "devspace-next.example.com,127.0.0.1",
    DEVSPACE_NEXT_MCP_SESSION_IDLE_TIMEOUT_MS: "60000",
    DEVSPACE_NEXT_MCP_SESSION_CLEANUP_INTERVAL_MS: "5000",
  });

  assert.equal(next.host, "0.0.0.0");
  assert.equal(next.port, 17677);
  assert.equal(next.publicBaseUrl, "https://devspace-next.example.com");
  assert.equal(next.endpointPath, "/mcp-next/v2");
  assert.deepEqual(next.allowedHosts, ["devspace-next.example.com", "127.0.0.1"]);
  assert.equal(next.mcpSessionIdleTimeoutMs, 60_000);
  assert.equal(next.mcpSessionCleanupIntervalMs, 5_000);
  assert.equal(next.targetConfigPath, join(root, "targets.json"));
  assert.equal(next.mcpRouteConfigPath, join(root, "routes.json"));
  assert.equal(next.contextStorePath, join(root, "context-state.json"));
  assert.equal(next.processOutputDir, join(root, "process-output"));
  assert.equal(next.sshControlDir, join(root, "ssh-control"));
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
});

test("next config cannot replace production /mcp or use a pathful public base URL", async (t) => {
  const root = await mkdtemp(join(tmpdir(), "devspace-v2-config-test-"));
  t.after(() => rm(root, { recursive: true, force: true }));
  const base = baseConfig(root);

  assert.throws(
    () => loadUniversalBrokerNextConfig(base, {
      DEVSPACE_NEXT_MCP_PATH: "/mcp",
    }),
    /conflicts with a reserved endpoint/,
  );
  assert.throws(
    () => loadUniversalBrokerNextConfig(base, {
      DEVSPACE_NEXT_PUBLIC_BASE_URL: "https://example.com/path",
    }),
    /must be an origin/,
  );
  assert.throws(
    () => loadUniversalBrokerNextConfig(base, {
      DEVSPACE_NEXT_PUBLIC_BASE_URL: base.publicBaseUrl,
    }),
    /must use a separate origin/,
  );
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
