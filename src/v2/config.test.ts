import assert from "node:assert/strict";
import { mkdtemp, readFile, rm, stat, writeFile } from "node:fs/promises";
import { homedir, tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { loadConfig } from "../config.js";
import { BASE_PRODUCT_PROFILE } from "./build-capabilities.js";
import { UNIVERSAL_OWNER_SCOPES } from "./contracts.js";
import { loadUniversalBrokerNextConfig, OAUTH_OFFLINE_ACCESS_SCOPE } from "./config.js";
import { UniversalMcpRouteRegistry } from "./mcp-routes.js";
import { TargetRegistry } from "./targets.js";

const OWNER_ENV = {
  DEVSPACE_OAUTH_OWNER_INSTANCE_ID: "personal-config-test-owner",
} as const;

test("personal environment config uses isolated state and inert legacy stores", async (t) => {
  const root = await mkdtemp(join(tmpdir(), "devspace-personal-config-test-"));
  t.after(() => rm(root, { recursive: true, force: true }));
  const base = baseConfig(root);

  assert.throws(
    () => loadUniversalBrokerNextConfig(base, {}),
    /DEVSPACE_OAUTH_OWNER_INSTANCE_ID/u,
  );

  const next = loadUniversalBrokerNextConfig(base, OWNER_ENV);
  assert.equal(next.productProfile, BASE_PRODUCT_PROFILE);
  assert.equal(next.deploymentMode, "parallel");
  assert.equal(next.port, base.port + 1);
  assert.equal(next.endpointPath, "/mcp-next");
  assert.equal(next.healthPath, "/healthz-next");
  assert.equal(next.readyPath, "/readyz");
  assert.equal(next.managementHost, "127.0.0.1");
  assert.equal(next.managementPort, next.port + 1_000);
  assert.equal(next.publicMcpUrl, `http://127.0.0.1:${base.port + 1}/mcp-next`);
  assert.equal(next.stateDir, join(base.stateDir, "universal-broker-v2"));
  assert.equal(next.authorityStorePath, join(next.stateDir, "legacy-unused-authority.sqlite"));
  assert.equal(
    next.connectorActivationJournalPath,
    join(next.stateDir, "legacy-unused-connector-journal.sqlite"),
  );
  assert.equal(next.lifecycleFinalizationStorePath, join(next.stateDir, "legacy-unused-lifecycle.sqlite"));
  assert.equal(
    next.lifecycleFinalizationControlPath,
    join(next.stateDir, "legacy-unused-lifecycle-control.json"),
  );
  assert.equal(next.authorityPrincipalMode, "single-owner");
  assert.equal(next.authorityOwnerInstanceId, OWNER_ENV.DEVSPACE_OAUTH_OWNER_INSTANCE_ID);
  assert.equal(next.authorityMode, "disabled");
  assert.equal(next.authorityDeployment, "in-process");
  assert.deepEqual(next.authorityTtlSeconds, { R1: 1, R2: 1, R3: 1 });
  assert.deepEqual(next.authorityMaximumUses, { R1: 1, R2: 1, R3: 1 });
  assert.equal(next.oauthStateDir, next.stateDir);
  assert.equal(next.targetConfigPath, join(root, ".config", "targets.v2.json"));
  assert.equal(next.mcpRouteConfigPath, join(root, ".config", "mcp-routes.v2.json"));
  assert.equal(next.contextStorePath, join(next.stateDir, "contexts.json"));
  assert.equal(next.envProfileConfigPath, join(homedir(), ".devspace", "env-profiles.v2.json"));
  assert.equal(next.processOutputDir, join(next.stateDir, "process-output"));
  assert.equal(next.selfManagementDir, join(next.stateDir, "self-management"));
  assert.equal(next.artifactCatalogPath, join(next.stateDir, "artifacts.sqlite"));
  assert.equal(next.artifactObjectRoot, join(next.stateDir, "artifact-objects"));
  assert.equal(next.canonicalConnectorName, "myDevSpace");
  assert.equal(next.allowAnonymousSessionFallback, false);
  assert.equal(next.legacyBlanketScopeCompatibility, false);
  assert.equal(next.adminScopeEnabled, false);
  assert.deepEqual(next.oauth.scopes, [...UNIVERSAL_OWNER_SCOPES, OAUTH_OFFLINE_ACCESS_SCOPE]);
  assert.notEqual(next.stateDir, base.stateDir);
});

test("personal production config binds canonical routes and may isolate OAuth state", async (t) => {
  const root = await mkdtemp(join(tmpdir(), "devspace-personal-production-config-test-"));
  t.after(() => rm(root, { recursive: true, force: true }));
  const base = baseConfig(root);
  const productionState = join(root, "v2-production-state");
  const production = loadUniversalBrokerNextConfig(base, {
    DEVSPACE_V2_DEPLOYMENT_MODE: "production",
    DEVSPACE_NEXT_PUBLIC_BASE_URL: base.publicBaseUrl,
    DEVSPACE_NEXT_STATE_DIR: productionState,
    ...OWNER_ENV,
  });

  assert.equal(production.deploymentMode, "production");
  assert.equal(production.endpointPath, "/mcp");
  assert.equal(production.healthPath, "/healthz");
  assert.equal(production.artifactPathPrefix, "/artifacts");
  assert.equal(production.oauthStateDir, base.stateDir);
  assert.equal(production.stateDir, productionState);
  assert.equal(production.authorityStorePath, join(productionState, "legacy-unused-authority.sqlite"));
  assert.equal(
    production.connectorActivationJournalPath,
    join(productionState, "legacy-unused-connector-journal.sqlite"),
  );
  assert.equal(production.lifecycleFinalizationStorePath, join(productionState, "legacy-unused-lifecycle.sqlite"));
  assert.equal(production.selfRestartPm2ProcessName, "devspace-v2-production");

  const candidateOauth = join(root, "candidate-oauth");
  const isolatedCandidate = loadUniversalBrokerNextConfig(base, {
    DEVSPACE_V2_DEPLOYMENT_MODE: "production",
    DEVSPACE_NEXT_PUBLIC_BASE_URL: base.publicBaseUrl,
    DEVSPACE_NEXT_STATE_DIR: join(root, "candidate-state"),
    DEVSPACE_NEXT_OAUTH_STATE_DIR: candidateOauth,
    ...OWNER_ENV,
  });
  assert.equal(isolatedCandidate.oauthStateDir, candidateOauth);
  assert.notEqual(isolatedCandidate.oauthStateDir, base.stateDir);

  assert.throws(
    () => loadUniversalBrokerNextConfig(base, {
      DEVSPACE_V2_DEPLOYMENT_MODE: "production",
      DEVSPACE_NEXT_PUBLIC_BASE_URL: base.publicBaseUrl,
      DEVSPACE_NEXT_MCP_PATH: "/mcp-next",
      ...OWNER_ENV,
    }),
    /canonical \/mcp endpoint|must be \/mcp/u,
  );
  assert.throws(
    () => loadUniversalBrokerNextConfig(base, {
      ...OWNER_ENV,
      DEVSPACE_V2_LEGACY_SCOPE_COMPATIBILITY: "true",
    }),
    /removed in Universal Broker v2\.1/u,
  );
  assert.throws(
    () => loadUniversalBrokerNextConfig(base, {
      ...OWNER_ENV,
      DEVSPACE_NEXT_STATE_DIR: base.stateDir,
    }),
    /must be separate from the production state directory/u,
  );
});

test("personal environment config accepts bounded resource overrides", async (t) => {
  const root = await mkdtemp(join(tmpdir(), "devspace-personal-explicit-config-test-"));
  t.after(() => rm(root, { recursive: true, force: true }));
  const stateDir = join(root, "next-state");
  const next = loadUniversalBrokerNextConfig(baseConfig(root), {
    ...OWNER_ENV,
    DEVSPACE_NEXT_HOST: "0.0.0.0",
    DEVSPACE_NEXT_PORT: "17677",
    DEVSPACE_NEXT_PUBLIC_BASE_URL: "https://devspace-next.example.com/v2/",
    DEVSPACE_NEXT_MCP_PATH: "/mcp-next/v2",
    DEVSPACE_NEXT_STATE_DIR: stateDir,
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
    DEVSPACE_NEXT_MAXIMUM_PROCESS_RECORDS: "25",
    DEVSPACE_NEXT_INTERNAL_RUNNER_MAXIMUM_CONCURRENT: "6",
    DEVSPACE_NEXT_PROCESS_BUFFER_CHARACTERS: "200000",
    DEVSPACE_NEXT_PROCESS_OUTPUT_MAX_BYTES: "4000000",
    DEVSPACE_NEXT_COMPLETED_PROCESS_TTL_MS: "120000",
    DEVSPACE_NEXT_ARTIFACT_STAGING_DIR: join(root, "artifact-staging"),
    DEVSPACE_NEXT_ARTIFACT_CATALOG: join(root, "artifacts.sqlite"),
    DEVSPACE_NEXT_ARTIFACT_OBJECT_ROOT: join(root, "artifact-objects"),
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
  assert.equal(next.authorityOwnerInstanceId, OWNER_ENV.DEVSPACE_OAUTH_OWNER_INSTANCE_ID);
  assert.deepEqual(next.allowedHosts, ["devspace-next.example.com", "127.0.0.1"]);
  assert.equal(next.contextMaximumEntries, 12);
  assert.equal(next.contextMaximumWorktrees, 3);
  assert.equal(next.contextMaximumWorktreeBytes, 9_000_000);
  assert.equal(next.contextDiffMaximumEntries, 7);
  assert.equal(next.contextDiffMaximumCharacters, 800_000);
  assert.equal(next.contextDiffTtlMs, 45_000);
  assert.equal(next.maximumProcessRecords, 25);
  assert.equal(next.maxRunningProcesses, 10);
  assert.equal(next.maxRunningProcessesPerTarget, 4);
  assert.equal(next.internalRunnerMaximumConcurrent, 6);
  assert.equal(next.processBufferCharacters, 200_000);
  assert.equal(next.processOutputMaxBytes, 4_000_000);
  assert.equal(next.completedProcessTtlMs, 120_000);
  assert.equal(next.artifactStagingDir, join(root, "artifact-staging"));
  assert.equal(next.artifactCatalogPath, join(root, "artifacts.sqlite"));
  assert.equal(next.artifactObjectRoot, join(root, "artifact-objects"));
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
});

test("personal unified config materializes prompt elevation without claiming provider availability", async (t) => {
  const root = await mkdtemp(join(tmpdir(), "devspace-personal-unified-config-test-"));
  t.after(() => rm(root, { recursive: true, force: true }));
  const firstPath = join(root, "first.json");
  const secondPath = join(root, "second.json");
  const input = personalUnifiedConfig(root);
  await writeFile(firstPath, JSON.stringify(input, null, 2));
  await writeFile(secondPath, JSON.stringify(Object.fromEntries(Object.entries(input).reverse()), null, 2));

  const first = loadUniversalBrokerNextConfig(baseConfig(root), { DEVSPACE_V2_CONFIG_FILE: firstPath });
  const reordered = loadUniversalBrokerNextConfig(baseConfig(root), { DEVSPACE_V2_CONFIG_FILE: secondPath });
  const overridden = loadUniversalBrokerNextConfig(baseConfig(root), {
    DEVSPACE_V2_CONFIG_FILE: firstPath,
    DEVSPACE_NEXT_CONTEXT_MAXIMUM_ENTRIES: "129",
  });

  assert.equal(first.productProfile, BASE_PRODUCT_PROFILE);
  assert.equal(first.configProfile, "production");
  assert.equal(first.publicBaseUrl, "http://127.0.0.1:8686");
  assert.equal(first.publicMcpUrl, "http://127.0.0.1:8686/mcp");
  assert.equal(first.oauthIssuer, "http://127.0.0.1:8686");
  assert.equal(first.oauthResource, "http://127.0.0.1:8686/mcp");
  assert.equal(first.authorityOwnerInstanceId, "stable-personal-owner");
  assert.equal(first.authorityMode, "disabled");
  assert.deepEqual(first.authorityTtlSeconds, { R1: 1, R2: 1, R3: 1 });
  assert.deepEqual(first.authorityMaximumUses, { R1: 1, R2: 1, R3: 1 });
  assert.equal(first.supervisorEndpoint, "internal://pm2");
  assert.equal(first.canonicalConnectorName, "myDevSpace");
  assert.equal(first.oauth.canonicalConnector?.installationEpoch, 3);
  assert.equal(first.artifactCatalogPath, join(root, "unified-state", "artifacts.sqlite"));
  assert.equal(first.artifactObjectRoot, join(root, "unified-state", "artifact-objects"));
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
      elevationPolicy: "deny" | "prompt";
      capabilities?: Record<string, boolean>;
      gui?: { mode?: string };
    }>;
  };
  assert.equal(materializedTargets.targets.local?.elevationPolicy, "prompt");
  assert.equal(materializedTargets.targets.company?.elevationPolicy, "deny");
  assert.equal(materializedTargets.targets.local?.gui?.mode, "local-ipc");

  const targetRegistry = new TargetRegistry({ configPath: first.targetConfigPath });
  const targetSnapshot = await targetRegistry.inspect();
  assert.equal(targetSnapshot.targets.find((target) => target.id === "local")?.elevationPolicy, "prompt");
  assert.deepEqual((await targetRegistry.list()).targets.find((target) => target.targetId === "local")?.elevation, {
    policy: "prompt",
    configured: true,
    requiresUserInteraction: true,
    mechanism: "macos-authorization-services",
    available: false,
    reason: "A user-authorized execution provider has not been verified for this target.",
  });

  const routeSnapshot = await new UniversalMcpRouteRegistry(first.mcpRouteConfigPath).inspect();
  assert.equal(routeSnapshot.routes[0]?.id, "company-jira");
  assert.equal(routeSnapshot.routes[0]?.target, "company");
  assert.equal(routeSnapshot.routes[0]?.transport, "ssh-stdio");

  assert.equal("authority" in first.canonicalConfig, false);
  assert.equal("lifecycleFinalizationStore" in (first.canonicalConfig.storage as object), false);
});

test("personal unified YAML uses current product defaults", async (t) => {
  const root = await mkdtemp(join(tmpdir(), "devspace-personal-unified-yaml-test-"));
  t.after(() => rm(root, { recursive: true, force: true }));
  const path = join(root, "config.yaml");
  await writeFile(path, [
    "version: 2",
    `productProfile: ${BASE_PRODUCT_PROFILE}`,
    "profile: development",
    "oauth:",
    "  principalMode: single-owner",
    "  ownerInstanceId: yaml-personal-owner",
    "supervisor:",
    "  endpoint: internal://pm2",
    "storage:",
    `  stateDirectory: ${JSON.stringify(join(root, "yaml-state"))}`,
    "targets: []",
    "mcpRoutes: []",
    "",
  ].join("\n"));

  const config = loadUniversalBrokerNextConfig(baseConfig(root), { DEVSPACE_V2_CONFIG_FILE: path });
  assert.equal(config.productProfile, BASE_PRODUCT_PROFILE);
  assert.equal(config.configProfile, "development");
  assert.equal(config.authorityOwnerInstanceId, "yaml-personal-owner");
  assert.equal(config.authorityMode, "disabled");
  assert.equal(config.contextMaximumEntries, 64);
  assert.equal(config.artifactTtlMs, 24 * 60 * 60_000);
  assert.equal(config.targetConfigPath, join(root, "yaml-state", "generated-config", "targets.v1.json"));
});

test("personal unified validation rejects legacy authority and unsafe references", async (t) => {
  const root = await mkdtemp(join(tmpdir(), "devspace-personal-unified-negative-test-"));
  t.after(() => rm(root, { recursive: true, force: true }));
  const base = baseConfig(root);
  let sequence = 0;
  const load = async (value: unknown) => {
    const path = join(root, `invalid-${sequence++}.json`);
    await writeFile(path, JSON.stringify(value));
    return () => loadUniversalBrokerNextConfig(base, { DEVSPACE_V2_CONFIG_FILE: path });
  };

  const anonymous = personalUnifiedConfig(root);
  anonymous.oauth.allowAnonymousSessionFallback = true;
  assert.throws(await load(anonymous), /allowAnonymousSessionFallback|expected false/u);

  const publicMetrics = personalUnifiedConfig(root);
  publicMetrics.observability.publicMetrics = true;
  assert.throws(await load(publicMetrics), /publicMetrics|expected false/u);

  const duplicateTarget = personalUnifiedConfig(root);
  duplicateTarget.targets.push({ ...duplicateTarget.targets[0]! });
  assert.throws(await load(duplicateTarget), /duplicate targetId local/u);

  const unknownReference = personalUnifiedConfig(root);
  unknownReference.mcpRoutes[0]!.targetId = "missing";
  unknownReference.mcpRoutes[0]!.transport.targetId = "missing";
  assert.throws(await load(unknownReference), /references unknown target missing/u);

  const relativeMcpCommand = personalUnifiedConfig(root);
  relativeMcpCommand.mcpRoutes[0]!.transport.command = "mcp-router";
  assert.throws(await load(relativeMcpCommand), /absolute remote path/u);

  const invalidElevation = personalUnifiedConfig(root);
  invalidElevation.targets[0]!.elevationPolicy = "sudo";
  assert.throws(await load(invalidElevation), /elevationPolicy|expected one of|Invalid option/u);

  const promptElevation = personalUnifiedConfig(root);
  promptElevation.targets[0]!.elevationPolicy = "prompt";
  assert.doesNotThrow(await load(promptElevation));

  const missingConnector = personalUnifiedConfig(root);
  delete (missingConnector as { connector?: unknown }).connector;
  delete (missingConnector.server as { canonicalConnectorName?: unknown }).canonicalConnectorName;
  assert.throws(await load(missingConnector), /canonicalConnectorName/u);

  const legacyAuthority = personalUnifiedConfig(root) as Record<string, unknown>;
  legacyAuthority.authority = { mode: "enforced" };
  assert.throws(await load(legacyAuthority), /authority|Unrecognized|unrecognized/i);

  const legacyConnector = personalUnifiedConfig(root);
  (legacyConnector.connector as Record<string, unknown>).activationMode = "owner-approved";
  assert.throws(await load(legacyConnector), /activationMode|Unrecognized|unrecognized/i);

  const legacyStorage = personalUnifiedConfig(root);
  (legacyStorage.storage as Record<string, unknown>).lifecycleFinalizationStore = join(root, "lifecycle.sqlite");
  assert.throws(await load(legacyStorage), /lifecycleFinalizationStore|Unrecognized|unrecognized/i);

  const legacyQuota = personalUnifiedConfig(root);
  (legacyQuota.quotas as Record<string, unknown>).processes = 128;
  assert.throws(await load(legacyQuota), /quotas\.processes|processes|Unrecognized|unrecognized/i);

  const legacyRelease = personalUnifiedConfig(root);
  (legacyRelease.release as Record<string, unknown>).requireAuthorityContractDigestMatch = true;
  assert.throws(await load(legacyRelease), /requireAuthorityContractDigestMatch|Unrecognized|unrecognized/i);

  assert.throws(
    () => loadUniversalBrokerNextConfig(base, {
      ...OWNER_ENV,
      DEVSPACE_NEXT_SELF_RESTART_DELAY_MS: "2000",
    }),
    /requires transport ACK_FLUSHED evidence/u,
  );
});

test("published config schema describes prompt elevation and omits legacy authority", async () => {
  const schema = JSON.parse(await readFile(join(process.cwd(), "config", "config.schema.json"), "utf8")) as {
    $schema: string;
    required: string[];
    properties: Record<string, unknown>;
  };
  assert.equal(schema.$schema, "https://json-schema.org/draft/2020-12/schema");
  assert.deepEqual(schema.required, ["version", "productProfile"]);
  assert.equal((schema.properties.productProfile as { const: string }).const, BASE_PRODUCT_PROFILE);
  assert.equal("authority" in schema.properties, false);
  const targetItems = (schema.properties.targets as {
    items: { properties: { elevationPolicy: { enum: string[] } } };
  }).items;
  assert.deepEqual(targetItems.properties.elevationPolicy.enum, ["deny", "prompt"]);
  const schemaText = JSON.stringify(schema);
  assert.doesNotMatch(
    schemaText,
    /BASE_SINGLE_OWNER|activationMode|lifecycleFinalizationStore|requireAuthorityContractDigestMatch/u,
  );
  assert.match(schemaText, /PERSONAL_DIRECT_OWNER/u);
});

function personalUnifiedConfig(root: string) {
  return {
    version: 2,
    productProfile: BASE_PRODUCT_PROFILE,
    profile: "production",
    server: {
      publicBaseUrl: "http://127.0.0.1:8686",
      mcpPath: "/mcp",
      dataPlane: { host: "127.0.0.1", port: 8686 },
      managementPlane: { host: "127.0.0.1", port: 9696 },
      canonicalConnectorName: "myDevSpace",
    },
    oauth: {
      issuer: "http://127.0.0.1:8686",
      resource: "http://127.0.0.1:8686/mcp",
      principalMode: "single-owner",
      ownerInstanceId: "stable-personal-owner",
      capabilityScopes: [...UNIVERSAL_OWNER_SCOPES],
      allowOfflineAccess: true,
      legacyBlanketScopeCompatibility: false,
      adminScopeEnabled: false,
      allowAnonymousSessionFallback: false,
    },
    supervisor: {
      endpoint: "internal://pm2",
      processManager: "pm2",
      processName: "devspace-v2-production",
      transactionDirectory: join(root, "unified-state", "self-management"),
      healthTimeoutMs: 120_000,
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
      installationEpoch: 3,
      drainGraceSeconds: 3_600,
    },
    rateLimit: {
      mode: "internal",
      preAuth: { refillPerMinute: 120, burst: 30 },
      postAuth: { refillPerMinute: 600, burst: 100 },
      initialize: { refillPerMinute: 30, burst: 10 },
    },
    management: {
      bind: "127.0.0.1",
      port: 9696,
      publicExposure: "deny",
      authorizationKeyRef: join(root, "unified-state", "management.key"),
    },
    audit: {
      sink: join(root, "unified-state", "audit", "operations.jsonl"),
      flushIntervalMs: 250,
      rawArguments: false,
    },
    storage: {
      stateDirectory: join(root, "unified-state"),
      oauthStateDirectory: join(root, "unified-oauth"),
      artifactRoot: join(root, "unified-state", "artifact-staging"),
      processOutputRoot: join(root, "unified-state", "process-output"),
      sshControlDirectory: join(root, "unified-state", "ssh-control"),
      contextStore: join(root, "unified-state", "contexts.json"),
      contextWorktreeRoot: join(root, "unified-state", "worktrees"),
      envProfileConfig: join(root, "env-profiles.json"),
      stateFileMode: "0600",
      directoryMode: "0700",
    },
    process: {
      maximumRunningTotal: 16,
      maximumRunningPerTarget: 16,
      terminalRetentionTtlSeconds: 900,
      maximumRetainedTerminalRecords: 128,
      maximumOutputBytesPerProcess: 104_857_600,
      terminalOverflowPolicy: "prune-oldest",
      internalRunnerMaximumConcurrent: 32,
    },
    quotas: {
      contexts: 64,
      mcpConnections: 64,
      mcpRetainedResultBytes: 268_435_456,
      guiSessions: 16,
      artifacts: 256,
      inlineOutputBytes: 65_536,
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
        elevationPolicy: "prompt",
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
    ],
    mcpRoutes: [
      {
        routeId: "company-jira",
        displayName: "Jira via Company Mac",
        enabled: true,
        targetId: "company",
        transport: {
          type: "ssh-stdio",
          targetId: "company",
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
