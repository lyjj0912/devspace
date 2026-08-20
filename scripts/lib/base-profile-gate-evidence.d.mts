import type { FinalizationManagementKey, Sha256Digest } from "./finalization-store-contract.mjs";

export const BASE_PROFILE_GATE_EVIDENCE_SCHEMA_VERSION: 2;
export const BASE_PROFILE_GATE_NAMES: readonly string[];
export const POST_CUTOVER_GATE_NAME: "G13 CUTOVER";
export const DEFERRED_FINALIZATION_GATE_NAMES: readonly ["G16 CLEANUP", "G17 FINALIZATION"];
export const BASE_PROFILE_PRECUTOVER_CAPABILITIES: readonly string[];
export const CONDITIONAL_PROFILE_NAMES: readonly string[];
export const BASE_PROFILE_GATE_THRESHOLD_DIGEST: Sha256Digest;

export interface BaseProfileGateBindings {
  readonly transactionId: string;
  readonly requestBindingDigest: Sha256Digest;
  readonly candidateIdentityDigest: Sha256Digest;
  readonly releaseManifestSha256: Sha256Digest;
  readonly runtimeIdentityDigest: Sha256Digest;
  readonly buildDigest: Sha256Digest;
  readonly schemaGeneration: Sha256Digest;
  readonly authorityContractGeneration: Sha256Digest;
  readonly buildCapabilityManifestDigest: Sha256Digest;
  readonly generatedSchemaDigest: Sha256Digest;
  readonly packageSha256: Sha256Digest;
  readonly migrationManifestDigest: Sha256Digest;
  readonly executableManifestDigest: Sha256Digest;
}

export interface BaseProfileGateReportReference {
  readonly schemaVersion: 2;
  readonly kind: "BASE_PROFILE_GATE_REPORT_REFERENCE";
  readonly profile: "BASE_SINGLE_OWNER";
  readonly gate: string;
  readonly bindings: BaseProfileGateBindings;
  readonly observedAt: string;
  readonly report: Readonly<{ path: string; sha256: Sha256Digest; format: string }>;
}

export interface SignedBaseProfileGateEvidence<T> {
  readonly schemaVersion: 2;
  readonly kind: "BASE_PROFILE_GATE_EVIDENCE" | "BASE_PROFILE_GATE_EVIDENCE_MANIFEST";
  readonly keyId: string;
  readonly payload: T;
  readonly payloadDigest: Sha256Digest;
  readonly signature: string;
}

export interface BaseProfileGateEvidenceManifest {
  readonly schemaVersion: 2;
  readonly kind: "BASE_PROFILE_GATE_EVIDENCE_MANIFEST";
  readonly profile: "BASE_SINGLE_OWNER";
  readonly bindings: BaseProfileGateBindings;
  readonly evidenceRoot: string;
  readonly createdAt: string;
  readonly artifacts: readonly Readonly<{ gate: string; path: string; sha256: Sha256Digest }>[];
  readonly postCutover: Readonly<{ path: string; reportPath: string; challenge: Sha256Digest }>;
}

export interface BaseProfileGateManifestOptions {
  readonly manifestPath: string;
  readonly manifestSha256: Sha256Digest;
  readonly key: FinalizationManagementKey;
  readonly expectedBindings: BaseProfileGateBindings;
  readonly releaseRoot: string;
  readonly requirePostCutoverAbsent?: boolean;
}

export function signBaseProfileGateEvidence(
  reference: BaseProfileGateReportReference,
  key: FinalizationManagementKey,
): SignedBaseProfileGateEvidence<BaseProfileGateReportReference>;
export function signBaseProfileGateEvidenceManifest(
  manifest: BaseProfileGateEvidenceManifest,
  key: FinalizationManagementKey,
): SignedBaseProfileGateEvidence<BaseProfileGateEvidenceManifest>;
export function inspectBaseProfileGateEvidenceManifest(options: BaseProfileGateManifestOptions): Readonly<Record<string, unknown>>;
export function evaluateBaseProfilePreCutoverEvidence(options: BaseProfileGateManifestOptions): Readonly<Record<string, unknown>>;
export function writeBaseProfilePostCutoverEvidence(options: BaseProfileGateManifestOptions & Readonly<{
  report: Readonly<Record<string, unknown>>;
}>): Readonly<{ path: string; sha256: Sha256Digest; reportPath: string; reportSha256: Sha256Digest; payloadDigest: Sha256Digest }>;
export function evaluateBaseProfilePostCutoverEvidence(options: BaseProfileGateManifestOptions & Readonly<{
  notBefore: string;
}>): Readonly<Record<string, unknown>>;
