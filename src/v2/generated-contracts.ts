import * as z from "zod/v4";
import {
  BASE_PRODUCT_PROFILE,
  RESOURCE_URI_VERSION,
  SUPPORTED_PRODUCT_PROFILES,
} from "./build-capabilities.js";
import {
  UNIVERSAL_BROKER_BUDGETS,
  UNIVERSAL_BROKER_VERSION,
  UNIVERSAL_ERROR_CODES,
  UNIVERSAL_TOOL_CONTRACTS,
  UNIVERSAL_TOOL_NAMES,
  UNIVERSAL_TOOL_OPERATIONS,
  universalRequestMetaSchema,
  universalResultEnvelopeSchema,
} from "./contracts.js";
import { unifiedConfigSchema } from "./unified-config.js";

export function generatedToolsManifestSchema(): Record<string, unknown> {
  const requestMetaSchema = z.toJSONSchema(universalRequestMetaSchema, {
    target: "draft-2020-12",
    io: "input",
    reused: "inline",
  });
  const resultOutputSchema = z.toJSONSchema(universalResultEnvelopeSchema, {
    target: "draft-2020-12",
    io: "output",
    reused: "inline",
  });
  const toolDefinitions = Object.fromEntries(UNIVERSAL_TOOL_NAMES.map((tool) => [
    `${tool}Tool`,
    {
      allOf: [
        { $ref: "#/$defs/tool" },
        {
          properties: {
            operations: { const: [...UNIVERSAL_TOOL_OPERATIONS[tool]] },
            inputSchema: {
              const: z.toJSONSchema(z.object(UNIVERSAL_TOOL_CONTRACTS[tool].inputSchema), {
                target: "draft-2020-12",
                io: "input",
                reused: "inline",
              }),
            },
            outputSchema: { $ref: "#/$defs/resultOutputSchemaConstant" },
            annotations: { const: UNIVERSAL_TOOL_CONTRACTS[tool].annotations },
          },
        },
      ],
    },
  ]));
  return {
    $schema: "https://json-schema.org/draft/2020-12/schema",
    $id: "https://devspace.local/contracts/tools-v2.schema.json",
    title: "DevSpace Universal Broker v2 Tool Manifest",
    type: "object",
    additionalProperties: false,
    required: ["version", "requestMetaSchema", "resultOutputSchema", "tools", "budgets"],
    properties: {
      version: { const: UNIVERSAL_BROKER_VERSION },
      requestMetaSchema: { $ref: "#/$defs/requestMetaSchemaConstant" },
      resultOutputSchema: { $ref: "#/$defs/resultOutputSchemaConstant" },
      tools: {
        type: "object",
        additionalProperties: false,
        required: [...UNIVERSAL_TOOL_NAMES],
        properties: Object.fromEntries(UNIVERSAL_TOOL_NAMES.map((tool) => [
          tool,
          { $ref: `#/$defs/${tool}Tool` },
        ])),
      },
      budgets: {
        type: "object",
        additionalProperties: false,
        required: Object.keys(UNIVERSAL_BROKER_BUDGETS),
        properties: Object.fromEntries(Object.entries(UNIVERSAL_BROKER_BUDGETS).map(([name, value]) => [
          name,
          { const: value },
        ])),
      },
    },
    $defs: {
      tool: {
        type: "object",
        additionalProperties: false,
        required: ["operations", "inputSchema", "outputSchema", "annotations"],
        properties: {
          operations: {
            type: "array",
            minItems: 1,
            uniqueItems: true,
            items: { type: "string", minLength: 1 },
          },
          inputSchema: { type: "object" },
          outputSchema: { type: "object" },
          annotations: { type: "object" },
        },
      },
      requestMetaSchemaConstant: { const: requestMetaSchema },
      resultOutputSchemaConstant: { const: resultOutputSchema },
      ...toolDefinitions,
    },
  };
}

export function generatedErrorSchema(): Record<string, unknown> {
  return {
    $schema: "https://json-schema.org/draft/2020-12/schema",
    $id: "https://devspace.local/contracts/errors.schema.json",
    title: "DevSpace Universal Broker v2 Error",
    type: "object",
    additionalProperties: false,
    required: ["code", "message", "retryable", "dispatchState"],
    properties: {
      code: { enum: [...UNIVERSAL_ERROR_CODES] },
      message: { type: "string", minLength: 1 },
      retryable: { type: "boolean" },
      dispatchState: {
        enum: ["NOT_DISPATCHED", "DISPATCHED", "ACKNOWLEDGED", "UNKNOWN"],
      },
      resourceKey: { type: "string" },
      evidence: { type: "object" },
      suggestions: { type: "array", items: { type: "object" } },
      recovery: { type: "array", items: { type: "object" } },
    },
  };
}

export function generatedUnifiedConfigSchema(): Record<string, unknown> {
  const schema = z.toJSONSchema(unifiedConfigSchema, {
    target: "draft-2020-12",
    io: "input",
    reused: "inline",
  }) as Record<string, unknown>;
  return {
    $schema: "https://json-schema.org/draft/2020-12/schema",
    $id: "https://devspace.local/config/config.schema.json",
    title: "DevSpace Universal Broker PERSONAL_DIRECT_OWNER Configuration",
    ...schema,
  };
}

export function generatedBuildCapabilitySchema(): Record<string, unknown> {
  return {
    $schema: "https://json-schema.org/draft/2020-12/schema",
    $id: "https://devspace.local/contracts/build-capabilities.schema.json",
    title: "DevSpace Universal Broker Build Capability Manifest",
    type: "object",
    additionalProperties: false,
    required: [
      "productVersion",
      "productProfile",
      "schemaGeneration",
      "supportedProfiles",
      "supportedOperations",
      "resourceUriVersion",
      "buildDigest",
      "capabilityDigest",
    ],
    properties: {
      productVersion: { const: UNIVERSAL_BROKER_VERSION },
      productProfile: { const: BASE_PRODUCT_PROFILE },
      schemaGeneration: { type: "string", pattern: "^sha256:[a-f0-9]{64}$" },
      supportedProfiles: { const: [...SUPPORTED_PRODUCT_PROFILES] },
      supportedOperations: {
        type: "object",
        additionalProperties: false,
        required: [...UNIVERSAL_TOOL_NAMES],
        properties: Object.fromEntries(UNIVERSAL_TOOL_NAMES.map((tool) => [
          tool,
          { const: [...UNIVERSAL_TOOL_OPERATIONS[tool]] },
        ])),
      },
      resourceUriVersion: { const: RESOURCE_URI_VERSION },
      buildDigest: { type: "string", pattern: "^sha256:[a-f0-9]{64}$" },
      capabilityDigest: { type: "string", pattern: "^sha256:[a-f0-9]{64}$" },
    },
  };
}

export function generatedContractFiles(): Readonly<Record<string, Record<string, unknown>>> {
  return Object.freeze({
    "contracts/tools-v2.schema.json": generatedToolsManifestSchema(),
    "contracts/errors.schema.json": generatedErrorSchema(),
    "contracts/build-capabilities.schema.json": generatedBuildCapabilitySchema(),
    "config/config.schema.json": generatedUnifiedConfigSchema(),
  });
}

export function prettyGeneratedJson(value: unknown): string {
  return `${JSON.stringify(value, null, 2)}\n`;
}
