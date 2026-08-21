import assert from "node:assert/strict";
import { mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { loadConfig } from "../config.js";
import {
  BASE_PRODUCT_PROFILE,
  buildCapabilityContract,
  SUPPORTED_PRODUCT_PROFILES,
} from "./build-capabilities.js";
import {
  UNIVERSAL_BROKER_INSTRUCTIONS,
  UNIVERSAL_TOOL_CONTRACTS,
  UNIVERSAL_TOOL_NAMES,
  UNIVERSAL_TOOL_OPERATIONS,
  universalRequestMetaSchema,
  universalResultEnvelopeSchema,
} from "./contracts.js";
import { createRuntimeIdentity } from "./runtime-identity.js";
import { loadUniversalBrokerNextConfig } from "./config.js";

test("personal build exposes the exact direct-owner public contract", () => {
  assert.equal(BASE_PRODUCT_PROFILE, "PERSONAL_DIRECT_OWNER");
  assert.deepEqual(SUPPORTED_PRODUCT_PROFILES, ["PERSONAL_DIRECT_OWNER"]);
  assert.deepEqual(UNIVERSAL_TOOL_NAMES, [
    "target",
    "context",
    "fs",
    "exec",
    "process",
    "mcp",
    "artifact",
    "gui",
  ]);
  assert.deepEqual(UNIVERSAL_TOOL_OPERATIONS.context, ["open", "search", "diff", "close"]);

  const serializedContract = JSON.stringify({
    instructions: UNIVERSAL_BROKER_INSTRUCTIONS,
    requestMeta: Object.keys(universalRequestMetaSchema.shape),
    result: Object.keys(universalResultEnvelopeSchema.shape),
    tools: UNIVERSAL_TOOL_CONTRACTS,
    capabilities: buildCapabilityContract(),
  });
  assert.doesNotMatch(
    serializedContract,
    /authority(?:Id|_|Contract|Text|Preview|Status)?|taskInstanceId|correctionEpoch|actionClaim|CLAIMED/iu,
  );
  assert.deepEqual(Object.keys(universalRequestMetaSchema.shape), [
    "requestId",
    "transactionId",
    "expectedSchemaGeneration",
    "expectedTargetGeneration",
    "expectedRouteGeneration",
  ]);
  assert.equal("transactionId" in UNIVERSAL_TOOL_CONTRACTS.process.inputSchema, true);

  const runtimeIdentity = createRuntimeIdentity({ config: {} });
  assert.equal(runtimeIdentity.productProfile, "PERSONAL_DIRECT_OWNER");
  assert.equal("authorityContractGeneration" in runtimeIdentity, false);
  assert.equal("authorityContractGeneration" in buildCapabilityContract(), false);
});

test("generated personal schemas contain no enterprise authority contract residue", async () => {
  for (const relative of [
    "../../contracts/tools-v2.schema.json",
    "../../contracts/errors.schema.json",
    "../../contracts/build-capabilities.schema.json",
    "../../config/config.schema.json",
  ]) {
    const source = await readFile(new URL(relative, import.meta.url), "utf8");
    assert.doesNotMatch(
      source,
      /BASE_SINGLE_OWNER|authorityContractGeneration|AUTHORITY_(?:REQUIRED|EXPIRED|MISMATCH)|CONNECTOR_ACTIVATION_REQUIRED|CLAIMED/iu,
      relative,
    );
  }
});

test("personal production request and build paths do not register the authority engine", async () => {
  for (const relative of [
    "./server.ts",
    "./http-server.ts",
    "../../scripts/generate-universal-broker-v2-contracts.mjs",
  ]) {
    const source = await readFile(new URL(relative, import.meta.url), "utf8");
    assert.doesNotMatch(source, /OperationAuthorityRegistry|withOperationAuthority/u, relative);
  }

  const configSchema = JSON.parse(
    await readFile(new URL("../../config/config.schema.json", import.meta.url), "utf8"),
  ) as {
    properties?: Record<string, { properties?: Record<string, unknown> }>;
  };
  assert.equal("authority" in (configSchema.properties ?? {}), false);
  assert.deepEqual(
    Object.keys(configSchema.properties?.process?.properties ?? {}).sort(),
    [
      "internalRunnerMaximumConcurrent",
      "maximumOutputBytesPerProcess",
      "maximumRetainedTerminalRecords",
      "maximumRunningPerTarget",
      "maximumRunningTotal",
      "terminalOverflowPolicy",
      "terminalRetentionTtlSeconds",
    ],
  );
  const unifiedSource = await readFile(new URL("./unified-config.ts", import.meta.url), "utf8");
  assert.doesNotMatch(unifiedSource, /DEVSPACE_NEXT_AUTHORITY|activation|finalization/iu);
});

test("canonical personal configuration exposes split process limits and no legacy lifecycle gate", async (t) => {
  const root = await mkdtemp(join(tmpdir(), "devspace-personal-config-"));
  t.after(() => rm(root, { recursive: true, force: true }));
  const baseEnvironment = {
    DEVSPACE_CONFIG_DIR: join(root, "config"),
    DEVSPACE_ALLOWED_ROOTS: root,
    DEVSPACE_STATE_DIR: join(root, "state"),
    DEVSPACE_WORKTREE_ROOT: join(root, "worktrees"),
    DEVSPACE_OAUTH_OWNER_TOKEN: "personal-config-owner-token-123456789",
    DEVSPACE_PUBLIC_BASE_URL: "https://devspace.example.test",
    DEVSPACE_LOG_LEVEL: "silent",
  };
  const base = loadConfig(baseEnvironment);
  const config = loadUniversalBrokerNextConfig(base, {
    ...baseEnvironment,
    DEVSPACE_OAUTH_OWNER_INSTANCE_ID: "personal-owner",
  });
  const canonical = config.canonicalConfig as Record<string, unknown>;
  assert.equal(canonical.productProfile, "PERSONAL_DIRECT_OWNER");
  assert.equal("authority" in canonical, false);
  assert.doesNotMatch(JSON.stringify(canonical), /activation|finalization/iu);
  assert.deepEqual(canonical.process, {
    maximumRunningTotal: 64,
    maximumRunningPerTarget: 32,
    terminalRetentionTtlSeconds: 3600,
    maximumRetainedTerminalRecords: 10_000,
    maximumOutputBytesPerProcess: 1_073_741_824,
    terminalOverflowPolicy: "prune-oldest",
    internalRunnerMaximumConcurrent: 32,
  });
});
