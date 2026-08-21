import { createHash } from "node:crypto";
import {
  UNIVERSAL_BROKER_VERSION,
  UNIVERSAL_TOOL_NAMES,
  UNIVERSAL_TOOL_OPERATIONS,
  type UniversalToolName,
} from "./contracts.js";
import { RUNTIME_SCHEMA_GENERATION } from "./runtime-contract-identity.js";
export {
  BASE_PRODUCT_PROFILE,
  RESOURCE_URI_VERSION,
  SUPPORTED_PRODUCT_PROFILES,
} from "./profile-contract.js";
import {
  BASE_PRODUCT_PROFILE,
  RESOURCE_URI_VERSION,
  SUPPORTED_PRODUCT_PROFILES,
} from "./profile-contract.js";

export type ProductProfile = (typeof SUPPORTED_PRODUCT_PROFILES)[number];

export interface BuildCapabilityManifest {
  productVersion: string;
  productProfile: ProductProfile;
  schemaGeneration: string;
  supportedProfiles: readonly ProductProfile[];
  supportedOperations: Readonly<Record<UniversalToolName, readonly string[]>>;
  resourceUriVersion: typeof RESOURCE_URI_VERSION;
  buildDigest: string;
  capabilityDigest: string;
}

export interface BuildCapabilityContract {
  productVersion: string;
  productProfile: ProductProfile;
  schemaGeneration: string;
  supportedProfiles: readonly ProductProfile[];
  supportedOperations: Readonly<Record<UniversalToolName, readonly string[]>>;
  resourceUriVersion: typeof RESOURCE_URI_VERSION;
}

export function buildCapabilityContract(): BuildCapabilityContract {
  return deepFreeze({
    productVersion: UNIVERSAL_BROKER_VERSION,
    productProfile: BASE_PRODUCT_PROFILE,
    schemaGeneration: RUNTIME_SCHEMA_GENERATION,
    supportedProfiles: [...SUPPORTED_PRODUCT_PROFILES],
    supportedOperations: Object.fromEntries(UNIVERSAL_TOOL_NAMES.map((tool) => [
      tool,
      [...UNIVERSAL_TOOL_OPERATIONS[tool]],
    ])) as Record<UniversalToolName, string[]>,
    resourceUriVersion: RESOURCE_URI_VERSION,
  });
}

export function createBuildCapabilityManifest(buildDigest: string): BuildCapabilityManifest {
  if (!/^sha256:[a-f0-9]{64}$/u.test(buildDigest)) {
    throw new Error("buildDigest must be a canonical SHA-256 digest.");
  }
  const contract = buildCapabilityContract();
  return deepFreeze({
    ...contract,
    buildDigest,
    capabilityDigest: capabilityDigest(contract),
  });
}

export function capabilityDigest(contract: BuildCapabilityContract = buildCapabilityContract()): string {
  return `sha256:${createHash("sha256").update(canonicalJson(contract)).digest("hex")}`;
}

function canonicalJson(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  if (value && typeof value === "object") {
    return `{${Object.entries(value as Record<string, unknown>)
      .filter(([, child]) => child !== undefined)
      .sort(([left], [right]) => left < right ? -1 : left > right ? 1 : 0)
      .map(([key, child]) => `${JSON.stringify(key)}:${canonicalJson(child)}`)
      .join(",")}}`;
  }
  return JSON.stringify(value) ?? "null";
}

function deepFreeze<T>(value: T): T {
  if (value && typeof value === "object" && !Object.isFrozen(value)) {
    for (const child of Object.values(value as Record<string, unknown>)) deepFreeze(child);
    Object.freeze(value);
  }
  return value;
}
