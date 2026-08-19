import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import * as z from "zod/v4";
import {
  UNIVERSAL_BROKER_BUDGETS,
  UNIVERSAL_BROKER_VERSION,
  UNIVERSAL_ERROR_CODES,
  UNIVERSAL_OWNER_SCOPES,
  UNIVERSAL_TOOL_CONTRACTS,
  UNIVERSAL_TOOL_NAMES,
  UNIVERSAL_TOOL_OPERATIONS,
  universalRequestMetaSchema,
} from "./contracts.js";
import {
  EXEC_RISK_CLASSIFIER_GENERATION,
  PROCESS_RISK_CLASSIFIER_GENERATION,
} from "./authority-policy.js";
import {
  RUNTIME_AUTHORITY_CONTRACT_GENERATION,
  RUNTIME_SCHEMA_GENERATION,
} from "./runtime-contract-identity.js";
import { digest } from "./runtime-identity.js";

test("dependency-free runtime contract identities match live contracts", () => {
  assert.equal(RUNTIME_SCHEMA_GENERATION, digest({
    version: UNIVERSAL_BROKER_VERSION,
    tools: UNIVERSAL_TOOL_NAMES.map((name) => {
      const contract = UNIVERSAL_TOOL_CONTRACTS[name];
      return {
        name,
        title: contract.title,
        description: contract.description,
        inputSchema: z.toJSONSchema(z.object(contract.inputSchema), {
          target: "draft-07",
          io: "input",
          reused: "inline",
        }),
        annotations: contract.annotations,
      };
    }),
    errors: UNIVERSAL_ERROR_CODES,
    budgets: UNIVERSAL_BROKER_BUDGETS,
  }));
  assert.equal(RUNTIME_AUTHORITY_CONTRACT_GENERATION, digest({
    exec: EXEC_RISK_CLASSIFIER_GENERATION,
    process: PROCESS_RISK_CLASSIFIER_GENERATION,
    canonicalization: "operation-authority-v5",
    principal: "stable-principal-v1",
  }));
});

test("checked-in contract manifests match the TypeScript authority", async () => {
  const tools = await readJson("../../contracts/tools-v2.schema.json") as {
    properties: {
      version: { const: string };
      tools: { properties: Record<string, unknown> };
      budgets: { properties: Record<string, { const: number }> };
    };
    $defs: Record<string, {
      allOf?: Array<{ properties?: { operations?: { const?: string[] } } }>;
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
    allOf?: Array<{ properties?: { operations?: { const?: string[] } } }>;
  }>;
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

  const errors = await readJson("../../contracts/errors.schema.json") as {
    properties: { code: { enum: string[] } };
  };
  assert.deepEqual(errors.properties.code.enum, [...UNIVERSAL_ERROR_CODES]);
});

test("every fixed tool contract has operations and no service-specific top-level name", () => {
  const forbidden = /jira|mail|gmail|chrome|database|company/i;
  for (const name of UNIVERSAL_TOOL_NAMES) {
    assert.doesNotMatch(name, forbidden);
    const input = UNIVERSAL_TOOL_CONTRACTS[name].inputSchema as Record<string, unknown>;
    if (name !== "exec") assert.ok("operation" in input, name);
  }
});

test("common request metadata is strict and stays out of repeated tool argument schemas", () => {
  const fields = [
    "requestId",
    "transactionId",
    "taskInstanceId",
    "authorityId",
    "expectedSchemaGeneration",
    "expectedTargetGeneration",
    "expectedRouteGeneration",
    "humanApprovalAttestation",
  ];
  assert.deepEqual(Object.keys(universalRequestMetaSchema.shape), fields);
  assert.deepEqual(universalRequestMetaSchema.parse({
    requestId: "request-1",
    transactionId: "transaction-1",
    taskInstanceId: "task-1",
    authorityId: "authority-1",
    expectedSchemaGeneration: `sha256:${"a".repeat(64)}`,
    expectedTargetGeneration: "target-generation",
    expectedRouteGeneration: "route-generation",
    humanApprovalAttestation: "opaque-compact-attestation",
  }).requestId, "request-1");
  assert.equal(universalRequestMetaSchema.safeParse({ unexpected: true }).success, false);
  for (const contract of Object.values(UNIVERSAL_TOOL_CONTRACTS)) {
    for (const field of [
      "requestId",
      "expectedSchemaGeneration",
      "expectedTargetGeneration",
      "expectedRouteGeneration",
      "humanApprovalAttestation",
    ]) {
      assert.equal(field in contract.inputSchema, false, field);
    }
  }
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
    "authorityId",
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
      capabilities?: { required?: string[]; additionalProperties?: boolean };
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
  ]);
  assert.equal(schema.properties?.capabilities?.additionalProperties, false);
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
