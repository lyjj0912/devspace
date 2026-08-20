import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import * as z from "zod/v4";
import {
  BASE_PRODUCT_PROFILE,
  buildCapabilityContract,
  RESOURCE_URI_VERSION,
  SUPPORTED_PRODUCT_PROFILES,
} from "./build-capabilities.js";
import {
  UNIVERSAL_BROKER_BUDGETS,
  UNIVERSAL_BROKER_VERSION,
  UNIVERSAL_ERROR_CODES,
  UNIVERSAL_OWNER_SCOPES,
  UNIVERSAL_TOOL_CONTRACTS,
  UNIVERSAL_TOOL_NAMES,
  UNIVERSAL_TOOL_OPERATIONS,
  universalRequestMetaSchema,
  universalResultEnvelopeSchema,
} from "./contracts.js";
import {
  computeRuntimeContractIdentities,
  generatedRuntimeContractIdentitySource,
} from "./contract-generation.js";
import {
  RUNTIME_AUTHORITY_CONTRACT_GENERATION,
  RUNTIME_SCHEMA_GENERATION,
} from "./runtime-contract-identity.js";
import { generatedContractFiles, prettyGeneratedJson } from "./generated-contracts.js";

test("dependency-free runtime contract identities match every canonical public surface", async () => {
  const identities = computeRuntimeContractIdentities(await runtimeContractSources());
  assert.equal(RUNTIME_AUTHORITY_CONTRACT_GENERATION, identities.authorityContractGeneration);
  assert.equal(RUNTIME_SCHEMA_GENERATION, identities.schemaGeneration);
  assert.equal(
    await readFile(new URL("./runtime-contract-identity.ts", import.meta.url), "utf8"),
    generatedRuntimeContractIdentitySource(identities),
  );
});

test("schema generation changes with the canonical unified config contract", async () => {
  const sources = await runtimeContractSources();
  const baseline = computeRuntimeContractIdentities(sources);
  const sourceChanged = computeRuntimeContractIdentities({
    ...sources,
    unifiedConfigSource: `${sources.unifiedConfigSource}\n// schema contract change`,
  });
  const schemaChanged = computeRuntimeContractIdentities({
    ...sources,
    unifiedConfigSchema: {
      ...(sources.unifiedConfigSchema as Record<string, unknown>),
      title: "changed unified config schema",
    },
  });
  assert.notEqual(sourceChanged.schemaGeneration, baseline.schemaGeneration);
  assert.notEqual(schemaChanged.schemaGeneration, baseline.schemaGeneration);
  assert.equal(sourceChanged.authorityContractGeneration, baseline.authorityContractGeneration);
  assert.equal(schemaChanged.authorityContractGeneration, baseline.authorityContractGeneration);
});

test("authority generation changes with the canonical connector route identity contract", async () => {
  const sources = await runtimeContractSources();
  const baseline = computeRuntimeContractIdentities(sources);
  const changed = computeRuntimeContractIdentities({
    ...sources,
    connectorRouteIdentitySource: `${sources.connectorRouteIdentitySource}\n// route identity contract change`,
  });
  assert.notEqual(changed.authorityContractGeneration, baseline.authorityContractGeneration);
  assert.notEqual(changed.schemaGeneration, baseline.schemaGeneration);
});

test("checked-in contract manifests match the TypeScript authority", async () => {
  const tools = await readJson("../../contracts/tools-v2.schema.json") as {
    properties: {
      version: { const: string };
      requestMetaSchema: { $ref: string };
      resultOutputSchema: { $ref: string };
      tools: { properties: Record<string, unknown> };
      budgets: { properties: Record<string, { const: number }> };
    };
    $defs: Record<string, {
      const?: unknown;
      allOf?: Array<{ properties?: {
        operations?: { const?: string[] };
        inputSchema?: { const?: unknown };
      } }>;
    }>;
  };
  assert.equal(tools.properties.version.const, UNIVERSAL_BROKER_VERSION);
  assert.deepEqual(
    Object.keys(tools.properties.tools.properties),
    [...UNIVERSAL_TOOL_NAMES],
  );
  assert.deepEqual(
    Object.fromEntries(
      Object.entries(tools.properties.budgets.properties)
        .map(([name, value]) => [name, value.const]),
    ),
    UNIVERSAL_BROKER_BUDGETS,
  );

  const defs = tools.$defs as Record<string, {
    const?: unknown;
    allOf?: Array<{ properties?: {
      operations?: { const?: string[] };
      inputSchema?: { const?: unknown };
    } }>;
  }>;
  assert.deepEqual(
    defs.requestMetaSchemaConstant?.const,
    z.toJSONSchema(universalRequestMetaSchema, {
      target: "draft-2020-12",
      io: "input",
      reused: "inline",
    }),
  );
  assert.deepEqual(
    defs.resultOutputSchemaConstant?.const,
    z.toJSONSchema(universalResultEnvelopeSchema, {
      target: "draft-2020-12",
      io: "output",
      reused: "inline",
    }),
  );
  const manifestOperations = {
    target: operationConst(defs.targetTool),
    context: operationConst(defs.contextTool),
    fs: operationConst(defs.fsTool),
    exec: operationConst(defs.execTool),
    process: operationConst(defs.processTool),
    mcp: operationConst(defs.mcpTool),
    artifact: operationConst(defs.artifactTool),
    gui: operationConst(defs.guiTool),
  };
  assert.deepEqual(manifestOperations, UNIVERSAL_TOOL_OPERATIONS);
  for (const name of UNIVERSAL_TOOL_NAMES) {
    assert.deepEqual(
      inputSchemaConst(defs[`${name}Tool`]!),
      z.toJSONSchema(z.object(UNIVERSAL_TOOL_CONTRACTS[name].inputSchema), {
        target: "draft-2020-12",
        io: "input",
        reused: "inline",
      }),
      name,
    );
  }

  const errors = await readJson("../../contracts/errors.schema.json") as {
    properties: { code: { enum: string[] } };
  };
  assert.deepEqual(errors.properties.code.enum, [...UNIVERSAL_ERROR_CODES]);
});

test("checked-in generated schemas are byte-identical to the base capability source", async () => {
  for (const [relative, generated] of Object.entries(generatedContractFiles())) {
    const checkedIn = await readFile(new URL(`../../${relative}`, import.meta.url), "utf8");
    assert.equal(checkedIn, prettyGeneratedJson(generated), relative);
  }
});

test("every fixed tool contract has operations and no service-specific top-level name", () => {
  const forbidden = /jira|mail|gmail|chrome|database|company/i;
  for (const name of UNIVERSAL_TOOL_NAMES) {
    assert.doesNotMatch(name, forbidden);
    const input = UNIVERSAL_TOOL_CONTRACTS[name].inputSchema as Record<string, unknown>;
    if (name !== "exec") assert.ok("operation" in input, name);
  }
});

test("public fs input rejects the unadvertised internal restore operation", () => {
  const publicFilesystemInput = z.strictObject(UNIVERSAL_TOOL_CONTRACTS.fs.inputSchema);
  assert.equal((UNIVERSAL_TOOL_OPERATIONS.fs as readonly string[]).includes("restore"), false);
  assert.equal("trashId" in UNIVERSAL_TOOL_CONTRACTS.fs.inputSchema, false);
  assert.equal(publicFilesystemInput.safeParse({
    operation: "restore",
    trashId: "00000000-0000-0000-0000-000000000000",
  }).success, false);
  assert.equal(publicFilesystemInput.safeParse({
    operation: "sync",
    path: "/source",
    destination: "/destination",
    sync: { phase: "apply", planId: "sync_plan", planDigest: "a".repeat(64) },
  }).success, true);
  assert.equal(publicFilesystemInput.safeParse({
    operation: "sync",
    path: "/source",
    destination: "/destination",
    sync: {
      phase: "apply",
      planId: "sync_plan",
      planDigest: "a".repeat(64),
      deleteMode: "permanent",
    },
  }).success, false);
});

test("common request metadata is strict and stays out of repeated tool argument schemas", () => {
  const fields = [
    "requestId",
    "transactionId",
    "taskInstanceId",
    "authorityId",
    "expectedSchemaGeneration",
    "expectedAuthorityContractGeneration",
    "expectedTargetGeneration",
    "expectedRouteGeneration",
  ];
  assert.deepEqual(Object.keys(universalRequestMetaSchema.shape), fields);
  assert.deepEqual(universalRequestMetaSchema.parse({
    requestId: "request-1",
    transactionId: "transaction-1",
    taskInstanceId: "task-1",
    authorityId: "authority-1",
    expectedSchemaGeneration: `sha256:${"a".repeat(64)}`,
    expectedAuthorityContractGeneration: `sha256:${"b".repeat(64)}`,
    expectedTargetGeneration: "target-generation",
    expectedRouteGeneration: "route-generation",
  }).requestId, "request-1");
  assert.equal(universalRequestMetaSchema.safeParse({ unexpected: true }).success, false);
  for (const contract of Object.values(UNIVERSAL_TOOL_CONTRACTS)) {
    for (const field of [
      "requestId",
      "transactionId",
      "taskInstanceId",
      "authorityId",
      "expectedSchemaGeneration",
      "expectedAuthorityContractGeneration",
      "expectedTargetGeneration",
      "expectedRouteGeneration",
    ]) {
      assert.equal(field in contract.inputSchema, false, field);
    }
  }
  assert.equal(universalResultEnvelopeSchema.safeParse({
    ok: true,
    operationId: "op-1",
    data: { value: true },
    observedSchemaGeneration: `sha256:${"a".repeat(64)}`,
    observedAuthorityContractGeneration: `sha256:${"b".repeat(64)}`,
  }).success, true);
  assert.equal(universalResultEnvelopeSchema.safeParse({
    ok: true,
    operationId: "op-1",
    observedSchemaGeneration: "schema",
    observedAuthorityContractGeneration: "authority",
    unexpected: true,
  }).success, false);
});

test("base profile capability manifest excludes unsupported conditional profiles", () => {
  const capabilities = buildCapabilityContract();
  assert.equal(capabilities.productProfile, BASE_PRODUCT_PROFILE);
  assert.deepEqual(SUPPORTED_PRODUCT_PROFILES, ["BASE_SINGLE_OWNER"]);
  assert.equal(capabilities.resourceUriVersion, RESOURCE_URI_VERSION);
  assert.deepEqual(capabilities.supportedOperations, UNIVERSAL_TOOL_OPERATIONS);
  assert.doesNotMatch(
    JSON.stringify(capabilities),
    /MULTI_USER|SIDECAR_AUTHORITY|HOST_ATTESTED|GUI_CAPTURE/u,
  );
});

test("contracts expose only user-account authority", async () => {
  assert.deepEqual(UNIVERSAL_OWNER_SCOPES, [
    "devspace.read",
    "devspace.write",
    "devspace.exec",
    "devspace.mcp",
    "devspace.artifact",
    "devspace.gui",
  ]);
  for (const contract of Object.values(UNIVERSAL_TOOL_CONTRACTS)) {
    assert.ok(!("privilege" in contract.inputSchema));
  }
  assert.deepEqual(Object.keys(UNIVERSAL_TOOL_CONTRACTS.gui.inputSchema), [
    "operation",
    "target",
    "sessionId",
    "generation",
    "action",
    "timeoutMs",
    "maxElements",
    "focusPolicy",
  ]);
  for (const path of [
    "../../contracts/tools-v2.schema.json",
    "../../contracts/targets.schema.json",
    "../../contracts/capabilities.schema.json",
    "../../contracts/errors.schema.json",
  ]) {
    const source = await readFile(new URL(path, import.meta.url), "utf8");
    assert.doesNotMatch(source, /devspace\.admin|ADMIN_UNAVAILABLE|["']privilege["']/u, path);
  }
});

test("target capability contract is closed and requires complete observed capability evidence", async () => {
  const schema = await readJson("../../contracts/capabilities.schema.json") as {
    required?: string[];
    properties?: {
      capabilities?: {
        required?: string[];
        additionalProperties?: boolean;
        properties?: {
          filesystem?: { required?: string[]; additionalProperties?: boolean };
        };
      };
      evidence?: {
        required?: string[];
        additionalProperties?: boolean;
        properties?: { cache?: { enum?: string[] } };
      };
    };
  };
  assert.deepEqual(schema.required, [
    "targetId",
    "endpointId",
    "targetGeneration",
    "status",
    "ready",
    "observedAt",
    "expiresAt",
    "platform",
    "capabilities",
    "evidence",
  ]);
  assert.deepEqual(schema.properties?.capabilities?.required, [
    "fs",
    "exec",
    "pty",
    "sftp",
    "rsync",
    "git",
    "gui",
    "mcp",
    "durableProcess",
    "filesystem",
  ]);
  assert.equal(schema.properties?.capabilities?.additionalProperties, false);
  assert.deepEqual(schema.properties?.capabilities?.properties?.filesystem?.required, [
    "atomicReplace",
    "atomicNoReplace",
    "renameExchange",
    "directoryFsync",
    "hardlinkPublish",
    "trash",
    "reflink",
    "sparseCopy",
  ]);
  assert.equal(
    schema.properties?.capabilities?.properties?.filesystem?.additionalProperties,
    false,
  );
  assert.deepEqual(schema.properties?.evidence?.required, [
    "transport",
    "endpointId",
    "endpointFingerprint",
    "configuredIdentity",
    "observedIdentity",
    "identityMatches",
    "readiness",
  ]);
  assert.equal(schema.properties?.evidence?.additionalProperties, false);
  assert.deepEqual(schema.properties?.evidence?.properties?.cache?.enum, ["hit", "miss", "shared"]);
});

test("all JSON contract files parse", async () => {
  for (const path of [
    "../../contracts/tools-v2.schema.json",
    "../../contracts/targets.schema.json",
    "../../contracts/mcp-routes.schema.json",
    "../../contracts/mcp-risk-policy.schema.json",
    "../../contracts/errors.schema.json",
    "../../contracts/capabilities.schema.json",
    "../../contracts/universal-broker-v2-baseline.json",
  ]) {
    assert.equal(typeof await readJson(path), "object", path);
  }
});

async function readJson(path: string): Promise<unknown> {
  return JSON.parse(await readFile(new URL(path, import.meta.url), "utf8"));
}

function operationConst(definition: {
  allOf?: Array<{ properties?: { operations?: { const?: string[] } } }>;
}): string[] {
  const operations = definition.allOf
    ?.map((entry) => entry.properties?.operations?.const)
    .find((value): value is string[] => Array.isArray(value));
  assert.ok(operations);
  return operations;
}

function inputSchemaConst(definition: {
  allOf?: Array<{ properties?: { inputSchema?: { const?: unknown } } }>;
}): unknown {
  const inputSchema = definition.allOf
    ?.map((entry) => entry.properties?.inputSchema?.const)
    .find((value) => value !== undefined);
  assert.ok(inputSchema);
  return inputSchema;
}

async function runtimeContractSources() {
  const generatedFiles = generatedContractFiles();
  return {
    authorityPolicySource: await readFile(new URL("./authority-policy.ts", import.meta.url), "utf8"),
    authorityPrincipalSource: await readFile(new URL("./authority-principal.ts", import.meta.url), "utf8"),
    authorityCoreSource: await readFile(new URL("./authority.ts", import.meta.url), "utf8"),
    serverCanonicalizationSource: await readFile(new URL("./server.ts", import.meta.url), "utf8"),
    connectorAuthorityDescriptorSource: await readFile(new URL("../oauth-store.ts", import.meta.url), "utf8"),
    connectorActivationEvidenceSource: await readFile(
      new URL("./connector-activation-evidence.ts", import.meta.url),
      "utf8",
    ),
    connectorActivationFinalizerSource: await readFile(
      new URL("./connector-activation-finalizer.ts", import.meta.url),
      "utf8",
    ),
    connectorStagingActivationContractSource: await readFile(
      new URL("./connector-staging-activation-contract.ts", import.meta.url),
      "utf8",
    ),
    connectorRouteIdentitySource: await readFile(
      new URL("./connector-route-identity.ts", import.meta.url),
      "utf8",
    ),
    resourceUriSource: await readFile(new URL("./resource-uri.ts", import.meta.url), "utf8"),
    unifiedConfigSource: await readFile(new URL("./unified-config.ts", import.meta.url), "utf8"),
    unifiedConfigSchema: generatedFiles["config/config.schema.json"],
  };
}
