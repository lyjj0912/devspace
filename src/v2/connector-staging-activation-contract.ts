import { createHash } from "node:crypto";
import {
  connectorActivationAuthorityActionFingerprint,
  connectorActivationAuthorityDescriptor,
  connectorActivationAuthorityResourceKeySha256,
  connectorActivationTupleDigest,
  type ConnectorActivationAuthorityBinding,
  type ConnectorActivationAuthorityDescriptor,
  type ConnectorActivationAuthorityReceipt,
  type ConnectorActivationReceipt,
} from "../oauth-store.js";

const SHA256_DIGEST_PATTERN = /^sha256:[a-f0-9]{64}$/u;
const RAW_SHA256_PATTERN = /^[a-f0-9]{64}$/u;
const CANONICAL_NAME_PATTERN = /^[A-Za-z][A-Za-z0-9._-]{0,127}$/u;

export const CONNECTOR_STAGING_ACTIVATION_OUTWARD_STATE =
  "STAGING_ACTIVATED_PENDING_PRE_CANARY" as const;

export interface ConnectorStagingActivationCandidateIdentityProjection {
  runtimeIdentityDigest: string;
  buildDigest: string;
  schemaGeneration: string;
  authorityContractGeneration: string;
  buildCapabilityManifestDigest: string;
  generatedSchemaDigest: string;
  packageSha256: string;
}

export interface ConnectorStagingActivationCandidateBindingProjection {
  environmentIdentityDigest: string;
  canonicalName: string;
  clientId: string;
  bindingId: string;
  installationEpoch: number;
  state: "ACTIVATION_PREPARED";
}

export interface ConnectorStagingActivationPrecheckPlanProjection {
  signedPayloadDigest: string;
  stagingActivationPrecheckId: string;
  managementNonce: string;
  managementCorrelationId: string;
  principalKeyFingerprint: string;
  candidateIdentity: ConnectorStagingActivationCandidateIdentityProjection;
  stagingRouteIdentityDigest: string;
  stagingCandidateBinding: ConnectorStagingActivationCandidateBindingProjection;
}

export interface ConnectorStagingActivationAuthorityContract {
  binding: ConnectorActivationAuthorityBinding;
  descriptor: ConnectorActivationAuthorityDescriptor;
  actionFingerprint: string;
  resourceKeySha256: string;
}

export function connectorStagingActivationCandidateIdentityDigest(
  identity: ConnectorStagingActivationCandidateIdentityProjection,
): string {
  validateCandidateIdentityProjection(identity);
  return sha256Digest(stableJson(projectCandidateIdentity(identity)));
}

export function connectorStagingActivationPlanDigest(
  receipt: ConnectorActivationReceipt,
  stagingActivationPrecheck: ConnectorStagingActivationPrecheckPlanProjection,
): string {
  validateActivationReceiptProjection(receipt);
  validatePrecheckProjection(stagingActivationPrecheck);
  const previousActiveBindingId = receipt.previousActiveBindingId ?? null;
  return sha256Digest(stableJson({
    schemaVersion: 1,
    operation: "context.connector_staging_activation_finalize",
    outwardState: CONNECTOR_STAGING_ACTIVATION_OUTWARD_STATE,
    authority: { maximumUses: 1, risk: "R3" },
    receipt: {
      receiptId: receipt.receiptId,
      tuple: receipt.tuple,
      tupleDigest: receipt.tupleDigest,
      activePreimageDigest: receipt.preimageDigest,
      previousActiveBindingId,
      drainDeadlineAt: receipt.drainDeadlineAt,
      refreshAllowedDuringDrain: receipt.refreshAllowedDuringDrain,
    },
    stagingPrecheck: projectStagingPrecheck(stagingActivationPrecheck),
    transitions: {
      candidate: ["ACTIVATION_PREPARED", "ACTIVE"],
      previousActive: previousActiveBindingId === null ? null : ["ACTIVE", "DRAINING"],
    },
  }));
}

export function connectorStagingActivationAuthorityBinding(
  receipt: ConnectorActivationReceipt,
  stagingActivationPrecheck: ConnectorStagingActivationPrecheckPlanProjection,
): ConnectorActivationAuthorityBinding {
  validateActivationReceiptProjection(receipt);
  return {
    receiptId: receipt.receiptId,
    canonicalName: receipt.tuple.canonicalName,
    tupleDigest: receipt.tupleDigest,
    activePreimageDigest: receipt.preimageDigest,
    finalizationPlanDigest: connectorStagingActivationPlanDigest(receipt, stagingActivationPrecheck),
  };
}

export function connectorStagingActivationAuthorityContract(
  receipt: ConnectorActivationReceipt,
  stagingActivationPrecheck: ConnectorStagingActivationPrecheckPlanProjection,
): ConnectorStagingActivationAuthorityContract {
  const binding = connectorStagingActivationAuthorityBinding(receipt, stagingActivationPrecheck);
  return {
    binding,
    descriptor: connectorActivationAuthorityDescriptor(binding),
    actionFingerprint: connectorActivationAuthorityActionFingerprint(binding),
    resourceKeySha256: connectorActivationAuthorityResourceKeySha256(binding),
  };
}

export function assertConnectorStagingActivationAuthorityReceiptMatchesContract(
  receipt: ConnectorActivationReceipt,
  stagingActivationPrecheck: ConnectorStagingActivationPrecheckPlanProjection,
  authorityReceipt: ConnectorActivationAuthorityReceipt,
): void {
  const expected = connectorStagingActivationAuthorityContract(receipt, stagingActivationPrecheck);
  const mismatches: string[] = [];
  if (authorityReceipt.receiptId !== expected.binding.receiptId) mismatches.push("receiptId");
  if (authorityReceipt.canonicalName !== expected.binding.canonicalName) mismatches.push("canonicalName");
  if (authorityReceipt.tupleDigest !== expected.binding.tupleDigest) mismatches.push("tupleDigest");
  if (authorityReceipt.activePreimageDigest !== expected.binding.activePreimageDigest) {
    mismatches.push("activePreimageDigest");
  }
  if (authorityReceipt.finalizationPlanDigest !== expected.binding.finalizationPlanDigest) {
    mismatches.push("finalizationPlanDigest");
  }
  if (authorityReceipt.actionFingerprint !== expected.actionFingerprint) mismatches.push("actionFingerprint");
  if (authorityReceipt.resourceKeySha256 !== expected.resourceKeySha256) mismatches.push("resourceKeySha256");
  if (mismatches.length > 0) {
    throw new Error(
      `Embedded staging activation authority receipt does not match canonical staging activation authority contract: ${
        mismatches.join(", ")
      }.`,
    );
  }
}

function validateActivationReceiptProjection(receipt: ConnectorActivationReceipt): void {
  if (!receipt || typeof receipt !== "object") {
    throw new Error("Staging activation receipt is invalid.");
  }
  if (!SHA256_DIGEST_PATTERN.test(receipt.tupleDigest)
    || !SHA256_DIGEST_PATTERN.test(receipt.preimageDigest)
    || receipt.tupleDigest !== connectorActivationTupleDigest(receipt.tuple)
    || !Number.isFinite(Date.parse(receipt.drainDeadlineAt))) {
    throw new Error("Staging activation receipt identity or tuple digest is invalid.");
  }
}

function validatePrecheckProjection(input: ConnectorStagingActivationPrecheckPlanProjection): void {
  if (!input || typeof input !== "object") throw new Error("Staging activation precheck projection is invalid.");
  for (const [value, label] of [
    [input.signedPayloadDigest, "signedPayloadDigest"],
    [input.stagingRouteIdentityDigest, "stagingRouteIdentityDigest"],
  ] as const) {
    if (!SHA256_DIGEST_PATTERN.test(value)) throw new Error(`Staging activation precheck ${label} is invalid.`);
  }
  validateCandidateIdentityProjection(input.candidateIdentity);
  if (!input.stagingCandidateBinding
    || input.stagingCandidateBinding.state !== "ACTIVATION_PREPARED"
    || !SHA256_DIGEST_PATTERN.test(input.stagingCandidateBinding.environmentIdentityDigest)
    || !CANONICAL_NAME_PATTERN.test(input.stagingCandidateBinding.canonicalName)
    || typeof input.stagingCandidateBinding.clientId !== "string"
    || input.stagingCandidateBinding.clientId.length < 1
    || typeof input.stagingCandidateBinding.bindingId !== "string"
    || input.stagingCandidateBinding.bindingId.length < 1
    || !Number.isSafeInteger(input.stagingCandidateBinding.installationEpoch)
    || input.stagingCandidateBinding.installationEpoch < 1) {
    throw new Error("Staging activation precheck candidate binding is invalid.");
  }
  if (!RAW_SHA256_PATTERN.test(input.principalKeyFingerprint) || /^0{64}$/u.test(input.principalKeyFingerprint)) {
    throw new Error("Staging activation precheck principal fingerprint is invalid.");
  }
  if (typeof input.stagingActivationPrecheckId !== "string"
    || input.stagingActivationPrecheckId.length < 1
    || typeof input.managementNonce !== "string"
    || input.managementNonce.length < 1
    || typeof input.managementCorrelationId !== "string"
    || input.managementCorrelationId.length < 1) {
    throw new Error("Staging activation precheck management identity is invalid.");
  }
}

function validateCandidateIdentityProjection(
  input: ConnectorStagingActivationCandidateIdentityProjection,
): void {
  if (!input || typeof input !== "object") throw new Error("Staging activation candidate identity is invalid.");
  for (const [value, label] of [
    [input.runtimeIdentityDigest, "runtimeIdentityDigest"],
    [input.buildDigest, "buildDigest"],
    [input.schemaGeneration, "schemaGeneration"],
    [input.authorityContractGeneration, "authorityContractGeneration"],
    [input.buildCapabilityManifestDigest, "buildCapabilityManifestDigest"],
    [input.generatedSchemaDigest, "generatedSchemaDigest"],
    [input.packageSha256, "packageSha256"],
  ] as const) {
    if (!SHA256_DIGEST_PATTERN.test(value)) throw new Error(`Staging activation candidate ${label} is invalid.`);
  }
}

function projectStagingPrecheck(
  input: ConnectorStagingActivationPrecheckPlanProjection,
): ConnectorStagingActivationPrecheckPlanProjection {
  return {
    signedPayloadDigest: input.signedPayloadDigest,
    stagingActivationPrecheckId: input.stagingActivationPrecheckId,
    managementNonce: input.managementNonce,
    managementCorrelationId: input.managementCorrelationId,
    principalKeyFingerprint: input.principalKeyFingerprint,
    candidateIdentity: projectCandidateIdentity(input.candidateIdentity),
    stagingRouteIdentityDigest: input.stagingRouteIdentityDigest,
    stagingCandidateBinding: {
      environmentIdentityDigest: input.stagingCandidateBinding.environmentIdentityDigest,
      canonicalName: input.stagingCandidateBinding.canonicalName,
      clientId: input.stagingCandidateBinding.clientId,
      bindingId: input.stagingCandidateBinding.bindingId,
      installationEpoch: input.stagingCandidateBinding.installationEpoch,
      state: input.stagingCandidateBinding.state,
    },
  };
}

function projectCandidateIdentity(
  input: ConnectorStagingActivationCandidateIdentityProjection,
): ConnectorStagingActivationCandidateIdentityProjection {
  return {
    runtimeIdentityDigest: input.runtimeIdentityDigest,
    buildDigest: input.buildDigest,
    schemaGeneration: input.schemaGeneration,
    authorityContractGeneration: input.authorityContractGeneration,
    buildCapabilityManifestDigest: input.buildCapabilityManifestDigest,
    generatedSchemaDigest: input.generatedSchemaDigest,
    packageSha256: input.packageSha256,
  };
}

function sha256Digest(value: string): string {
  return `sha256:${createHash("sha256").update(value).digest("hex")}`;
}

function stableJson(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(stableJson).join(",")}]`;
  if (value && typeof value === "object") {
    const record = value as Record<string, unknown>;
    return `{${Object.keys(record).sort().map((key) => `${JSON.stringify(key)}:${stableJson(record[key])}`).join(",")}}`;
  }
  return JSON.stringify(value) ?? "null";
}
