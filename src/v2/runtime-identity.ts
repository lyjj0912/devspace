import { createHash } from "node:crypto";
import {
  UNIVERSAL_BROKER_VERSION,
  type RuntimeIdentity,
} from "./contracts.js";
import { RUNTIME_SCHEMA_GENERATION } from "./runtime-contract-identity.js";
import {
  BASE_PRODUCT_PROFILE,
  capabilityDigest,
  RESOURCE_URI_VERSION,
} from "./build-capabilities.js";

export interface RuntimeIdentityInput {
  config: unknown;
  sourceRevision?: string;
  runtimeRevision?: string;
  buildDigest?: string;
  startedAt?: string;
}

/** Builds the public, secret-free identity used by health, readiness, restart and release gates. */
export function createRuntimeIdentity(input: RuntimeIdentityInput): RuntimeIdentity {
  return Object.freeze({
    productVersion: UNIVERSAL_BROKER_VERSION,
    productProfile: BASE_PRODUCT_PROFILE,
    buildCapabilityDigest: capabilityDigest(),
    resourceUriVersion: RESOURCE_URI_VERSION,
    schemaGeneration: RUNTIME_SCHEMA_GENERATION,
    configDigest: digest(redactConfigForDigest(input.config)),
    sourceRevision: boundedIdentity(input.sourceRevision, "unknown-source"),
    runtimeRevision: boundedIdentity(input.runtimeRevision, "development-runtime"),
    buildDigest: normalizeDigest(input.buildDigest),
    startedAt: normalizeDate(input.startedAt),
  }) as RuntimeIdentity;
}

export function publicRuntimeHealth(identity: RuntimeIdentity): Record<string, unknown> {
  return {
    status: "ok",
    productVersion: identity.productVersion,
    productProfile: identity.productProfile,
    buildCapabilityDigest: identity.buildCapabilityDigest,
    resourceUriVersion: identity.resourceUriVersion,
    schemaGeneration: identity.schemaGeneration,
    runtimeRevision: identity.runtimeRevision,
    startedAt: identity.startedAt,
  };
}

export function canonicalJson(value: unknown): string {
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

export function digest(value: unknown): string {
  return `sha256:${createHash("sha256").update(canonicalJson(value)).digest("hex")}`;
}

function redactConfigForDigest(value: unknown, key = ""): unknown {
  if (isSecretKey(key)) return "[secret]";
  if (Array.isArray(value)) return value.map((child) => redactConfigForDigest(child));
  if (value && typeof value === "object") {
    return Object.fromEntries(Object.entries(value as Record<string, unknown>)
      .map(([childKey, child]) => [childKey, redactConfigForDigest(child, childKey)]));
  }
  return value;
}

function isSecretKey(value: string): boolean {
  return /(?:authorization|cookie|credential|password|private.?key|refresh.?token|secret|token)$/iu.test(value);
}

function boundedIdentity(value: string | undefined, fallback: string): string {
  const normalized = value?.trim();
  return normalized ? normalized.slice(0, 256) : fallback;
}

function normalizeDigest(value: string | undefined): string {
  const normalized = value?.trim();
  if (normalized && /^sha256:[a-f0-9]{64}$/u.test(normalized)) return normalized;
  return digest(normalized || "development-build");
}

function normalizeDate(value: string | undefined): string {
  const date = value ? new Date(value) : new Date();
  if (!Number.isFinite(date.valueOf())) throw new Error("Runtime identity startedAt is invalid.");
  return date.toISOString();
}
