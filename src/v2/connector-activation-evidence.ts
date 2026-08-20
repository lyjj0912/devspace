import { createHash, createHmac, timingSafeEqual } from "node:crypto";
import {
  connectorActivationTupleDigest,
  type ConnectorActivationAuthorityReceipt,
  type ConnectorActivationReceipt,
  type ConnectorActivationTuple,
} from "../oauth-store.js";
import {
  UNIVERSAL_OWNER_SCOPES,
  UNIVERSAL_TOOL_NAMES,
  type UniversalToolName,
} from "./contracts.js";
import {
  assertConnectorStagingActivationAuthorityReceiptMatchesContract,
} from "./connector-staging-activation-contract.js";
import type { ManagementAuthorizationKey } from "./management-authorization.js";

const OWNER_APPROVAL_BRAND: unique symbol = Symbol("verified-connector-owner-approval");
const STAGING_PRECHECK_BRAND: unique symbol = Symbol("verified-staging-activation-precheck");
const PRE_CUTOVER_HOST_CANARY_BRAND: unique symbol = Symbol("verified-pre-cutover-host-canary");
const PRODUCTION_PRECHECK_BRAND: unique symbol = Symbol("verified-production-activation-precheck");
const POST_ACTIVATION_HOST_CANARY_BRAND: unique symbol = Symbol("verified-post-activation-host-canary");

const DIGEST_PATTERN = /^sha256:[a-f0-9]{64}$/u;
const RAW_DIGEST_PATTERN = /^[a-f0-9]{64}$/u;
const SIGNATURE_PATTERN = /^[A-Za-z0-9_-]{43}$/u;
const AUTHORITY_ID_PATTERN = /^authority_[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/u;
const ACTION_CLAIM_ID_PATTERN = /^authority_claim_[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/u;
const ACTIVATION_RECEIPT_ID_PATTERN = /^connector-activation-[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/u;
const MAXIMUM_APPROVAL_LIFETIME_MS = 5 * 60_000;
const MAXIMUM_HOST_RECEIPT_LIFETIME_MS = 2 * 60_000;
const MAXIMUM_PRECHECK_LIFETIME_MS = 2 * 60_000;

const ENVELOPE_KEYS = ["keyId", "kind", "payload", "payloadDigest", "schemaVersion", "signature"] as const;
const OWNER_PAYLOAD_KEYS = [
  "activePreimageDigest", "approvalId", "approvedAtMs", "authorityText", "canonicalName",
  "evidenceDigest", "expiresAtMs", "finalizationPlanDigest", "preCutoverHostCanaryDigest",
  "principalKeyFingerprint", "productionActivationPrecheckDigest", "receiptId", "tupleDigest",
] as const;
const CANDIDATE_IDENTITY_KEYS = [
  "authorityContractGeneration", "buildCapabilityManifestDigest", "buildDigest",
  "generatedSchemaDigest", "packageSha256", "runtimeIdentityDigest", "schemaGeneration",
] as const;
const STAGING_BINDING_KEYS = [
  "bindingId", "canonicalName", "clientId", "environmentIdentityDigest", "installationEpoch", "state",
] as const;
const TUPLE_KEYS = [
  "authorityContractGeneration", "buildDigest", "candidateBindingId", "canonicalName", "clientId",
  "installationEpoch", "redirectUrisDigest", "schemaGeneration",
] as const;
const R0_CANARY_KEYS = [
  "argumentsDigest", "operation", "providerDispatchCount", "readbackDigest", "resourceDigest", "tool",
] as const;
const CANARY_MUTATION_KEYS = [
  "actionClaimId", "actionFingerprint", "argumentsDigest", "authorityId", "authorityReceiptDigest",
  "cleanupEvidenceDigest", "cleanupPerformed", "fencingToken", "operation", "postReadbackDigest",
  "providerDispatchCount", "resourceDigest", "resourceKeySha256", "sessionAAuthorizationEvidenceDigest",
  "sessionAAuthorizedAtMs", "sessionACloseEvidenceDigest", "sessionAClosedAtMs", "sessionAIdDigest",
  "sessionBIdDigest", "sessionBMutationAtMs", "sessionBMutationEvidenceDigest", "tool",
] as const;
const FOREIGN_ISOLATION_KEYS = [
  "clientId", "errorCode", "evidenceDigest", "principalKeyFingerprint", "providerDispatchCount",
] as const;
const STAGING_PRECHECK_KEYS = [
  "actualHost", "candidateIdentity", "discoveredToolNames", "expiresAtMs", "hostProvider",
  "managementCorrelationId", "managementNonce", "observedAtMs", "principalKeyFingerprint", "r0Canary",
  "stage", "stagingActivationPrecheckId", "stagingCandidateBinding", "stagingRouteIdentityDigest",
  "toolDiscoveryEvidenceDigest",
] as const;
const PRE_CUTOVER_KEYS = [
  "actualHost", "candidateIdentity", "discoveredToolNames", "expiresAtMs", "foreignClientIsolation",
  "hostProvider", "managementCorrelationId", "managementNonce", "mutation", "observedAtMs",
  "preCutoverHostCanaryId", "principalKeyFingerprint", "stage", "stagingBinding",
  "stagingActivatedAtMs", "stagingActivationAuthorityReceipt", "stagingActivationAuthorityReceiptDigest",
  "stagingActivationPrecheckDigest",
  "stagingActivationProofDigest", "stagingActivationReceiptDigest", "stagingActivationReceiptId",
  "stagingActivationReceipt", "stagingActiveTuple", "stagingRouteIdentityDigest", "stagingTokenFamilyBindingId",
  "stagingTokenFamilyIdDigest", "toolDiscoveryEvidenceDigest",
] as const;
const ACTIVATED_RECEIPT_KEYS = [
  "activatedAt", "activationAuthority", "drainDeadlineAt", "ownerAuthorityId", "preimageDigest",
  "preparedAt", "receiptId", "refreshAllowedDuringDrain", "status", "tuple", "tupleDigest",
] as const;
const ACTIVATION_AUTHORITY_RECEIPT_KEYS = [
  "actionClaimId", "actionFingerprint", "activePreimageDigest", "approvalAssurance", "authorityId",
  "canonicalName", "claimedAtMs", "claimState", "consumedAt", "dispatchedAtMs", "evidenceDigest",
  "fencingToken", "finalizationPlanDigest", "principalKeyFingerprint", "proofDigest", "receiptId",
  "resourceKeySha256", "risk", "schemaVersion", "tupleDigest",
] as const;
const PRODUCTION_PRECHECK_KEYS = [
  "activePreimageDigest", "candidateIdentity", "canonicalName", "expiresAtMs", "finalizationPlanDigest",
  "managementCorrelationId", "oauthResource", "oauthScopes", "observedAtMs",
  "preCutoverHostCanaryDigest", "principalKeyFingerprint", "productionActivationPrecheckId",
  "productionEnvironmentIdentityDigest", "productionRouteIdentityDigest", "receiptId", "stage",
  "stagingBinding", "stagingProductionBindingRelation", "stagingRouteIdentityDigest", "tuple", "tupleDigest",
] as const;
const POST_ACTIVATION_KEYS = [
  "activatedAtMs", "activationAuthorityReceiptDigest", "activationProofDigest", "activationReceiptDigest",
  "activationReceiptId", "actualHost", "discoveredToolNames", "expiresAtMs", "foreignClientIsolation",
  "hostProvider", "managementCorrelationId", "managementNonce", "mutation", "newActiveBindingState",
  "newActiveTuple", "observedAtMs", "postActivationHostCanaryId", "precheckDigest",
  "previousActiveBindingId", "previousBindingState", "principalKeyFingerprint", "productionEnvironmentIdentityDigest",
  "productionIdentity", "productionRouteIdentityDigest", "stage", "tokenFamilyBindingId",
  "tokenFamilyIdDigest", "toolDiscoveryEvidenceDigest",
] as const;

export type ConnectorActivationBaseOAuthScope = (typeof UNIVERSAL_OWNER_SCOPES)[number];
export type ConnectorActivationStagingProductionBindingRelation =
  | "DISTINCT_STAGING_BINDING"
  | "IDENTICAL_BINDING_IDENTIFIERS_ISOLATED_STAGING";

export interface ConnectorActivationEvidenceBinding {
  principalKeyFingerprint: string;
  receiptId: string;
  canonicalName: string;
  tupleDigest: string;
  activePreimageDigest: string;
  finalizationPlanDigest: string;
}

export interface ConnectorActivationOwnerApprovalBinding
  extends ConnectorActivationEvidenceBinding {
  preCutoverHostCanaryDigest: string;
  productionActivationPrecheckDigest: string;
}

export interface ConnectorActivationOwnerApprovalPayload
  extends ConnectorActivationOwnerApprovalBinding {
  approvalId: string;
  authorityText: string;
  evidenceDigest: string;
  approvedAtMs: number;
  expiresAtMs: number;
}

export interface ConnectorActivationImmutableCandidateIdentity {
  runtimeIdentityDigest: string;
  buildDigest: string;
  schemaGeneration: string;
  authorityContractGeneration: string;
  buildCapabilityManifestDigest: string;
  generatedSchemaDigest: string;
  packageSha256: string;
}

export interface ConnectorActivationStagingCandidateBindingIdentity {
  environmentIdentityDigest: string;
  canonicalName: string;
  clientId: string;
  bindingId: string;
  installationEpoch: number;
  state: "ACTIVATION_PREPARED";
}

export interface ConnectorActivationStagingBindingIdentity {
  environmentIdentityDigest: string;
  canonicalName: string;
  clientId: string;
  bindingId: string;
  installationEpoch: number;
  state: "ACTIVE";
}

export interface ConnectorActivationR0CanaryEvidence {
  tool: UniversalToolName;
  operation: string;
  argumentsDigest: string;
  resourceDigest: string;
  providerDispatchCount: 1;
  readbackDigest: string;
}

export interface ConnectorActivationCanaryMutationEvidence {
  tool: UniversalToolName;
  operation: string;
  argumentsDigest: string;
  resourceDigest: string;
  sessionAIdDigest: string;
  sessionAAuthorizationEvidenceDigest: string;
  sessionAAuthorizedAtMs: number;
  sessionACloseEvidenceDigest: string;
  sessionAClosedAtMs: number;
  sessionBIdDigest: string;
  sessionBMutationEvidenceDigest: string;
  sessionBMutationAtMs: number;
  actionFingerprint: string;
  resourceKeySha256: string;
  authorityId: string;
  actionClaimId: string;
  fencingToken: number;
  authorityReceiptDigest: string;
  providerDispatchCount: 1;
  postReadbackDigest: string;
  cleanupPerformed: true;
  cleanupEvidenceDigest: string;
}

export interface ConnectorActivationForeignClientIsolationEvidence {
  clientId: string;
  principalKeyFingerprint: string;
  errorCode: "AUTHORITY_PRINCIPAL_MISMATCH";
  providerDispatchCount: 0;
  evidenceDigest: string;
}

export interface ConnectorActivationStagingPrecheckPayload {
  stage: "STAGING_ACTIVATION_PRECHECK";
  stagingActivationPrecheckId: string;
  managementNonce: string;
  managementCorrelationId: string;
  principalKeyFingerprint: string;
  hostProvider: "chatgpt";
  actualHost: true;
  candidateIdentity: ConnectorActivationImmutableCandidateIdentity;
  stagingRouteIdentityDigest: string;
  stagingCandidateBinding: ConnectorActivationStagingCandidateBindingIdentity;
  discoveredToolNames: readonly UniversalToolName[];
  toolDiscoveryEvidenceDigest: string;
  r0Canary: ConnectorActivationR0CanaryEvidence;
  observedAtMs: number;
  expiresAtMs: number;
}

export interface ConnectorActivationStagingPrecheckExpected {
  principalKeyFingerprint: string;
  managementNonce: string;
  managementCorrelationId: string;
  candidateIdentity: ConnectorActivationImmutableCandidateIdentity;
  stagingRouteIdentityDigest: string;
  stagingCandidateBinding: ConnectorActivationStagingCandidateBindingIdentity;
}

export interface ConnectorActivationPreCutoverHostCanaryPayload {
  stage: "PRE_CUTOVER_HOST_CANARY";
  preCutoverHostCanaryId: string;
  managementNonce: string;
  managementCorrelationId: string;
  principalKeyFingerprint: string;
  hostProvider: "chatgpt";
  actualHost: true;
  candidateIdentity: ConnectorActivationImmutableCandidateIdentity;
  stagingRouteIdentityDigest: string;
  stagingBinding: ConnectorActivationStagingBindingIdentity;
  stagingActivationPrecheckDigest: string;
  stagingActivationReceipt: ConnectorActivationReceipt;
  stagingActivationAuthorityReceipt: ConnectorActivationAuthorityReceipt;
  stagingActivationReceiptId: string;
  stagingActivationReceiptDigest: string;
  stagingActivationProofDigest: string;
  stagingActivationAuthorityReceiptDigest: string;
  stagingActivatedAtMs: number;
  stagingActiveTuple: ConnectorActivationTuple;
  stagingTokenFamilyIdDigest: string;
  stagingTokenFamilyBindingId: string;
  discoveredToolNames: readonly UniversalToolName[];
  toolDiscoveryEvidenceDigest: string;
  mutation: ConnectorActivationCanaryMutationEvidence;
  foreignClientIsolation: ConnectorActivationForeignClientIsolationEvidence;
  observedAtMs: number;
  expiresAtMs: number;
}

export interface ConnectorActivationPersistedPreCutoverHostCanaryExpected {
  principalKeyFingerprint: string;
  managementNonce: string;
  managementCorrelationId: string;
  candidateIdentity: ConnectorActivationImmutableCandidateIdentity;
  stagingRouteIdentityDigest: string;
  stagingBinding: ConnectorActivationStagingBindingIdentity;
  stagingActivationPrecheck: VerifiedConnectorActivationStagingPrecheck;
}

export interface ConnectorActivationPreCutoverHostCanaryExpected
  extends ConnectorActivationPersistedPreCutoverHostCanaryExpected {
  stagingActivationReceipt: ConnectorActivationReceipt;
  stagingActivationAuthorityReceipt: ConnectorActivationAuthorityReceipt;
  stagingTokenFamilyIdDigest: string;
  stagingTokenFamilyBindingId: string;
}

export interface ConnectorActivationProductionPrecheckPayload
  extends ConnectorActivationEvidenceBinding {
  stage: "PRODUCTION_ACTIVATION_PRECHECK";
  productionActivationPrecheckId: string;
  managementCorrelationId: string;
  tuple: ConnectorActivationTuple;
  oauthResource: string;
  oauthScopes: readonly ConnectorActivationBaseOAuthScope[];
  candidateIdentity: ConnectorActivationImmutableCandidateIdentity;
  preCutoverHostCanaryDigest: string;
  stagingBinding: ConnectorActivationStagingBindingIdentity;
  stagingRouteIdentityDigest: string;
  productionEnvironmentIdentityDigest: string;
  productionRouteIdentityDigest: string;
  stagingProductionBindingRelation: ConnectorActivationStagingProductionBindingRelation;
  observedAtMs: number;
  expiresAtMs: number;
}

export interface ConnectorActivationProductionPrecheckExpected
  extends ConnectorActivationEvidenceBinding {
  tuple: ConnectorActivationTuple;
  preCutoverHostCanary: VerifiedConnectorActivationPreCutoverHostCanary;
  oauthResource: string;
  productionEnvironmentIdentityDigest: string;
  productionRouteIdentityDigest: string;
}

export interface ConnectorActivationPostActivationHostCanaryPayload {
  stage: "POST_ACTIVATION_HOST_CANARY";
  postActivationHostCanaryId: string;
  managementNonce: string;
  managementCorrelationId: string;
  principalKeyFingerprint: string;
  hostProvider: "chatgpt";
  actualHost: true;
  precheckDigest: string;
  activationReceiptId: string;
  activationReceiptDigest: string;
  activationProofDigest: string;
  activationAuthorityReceiptDigest: string;
  activatedAtMs: number;
  newActiveTuple: ConnectorActivationTuple;
  newActiveBindingState: "ACTIVE";
  tokenFamilyIdDigest: string;
  tokenFamilyBindingId: string;
  previousActiveBindingId: string | null;
  previousBindingState: "DRAINING" | "ABSENT";
  productionIdentity: ConnectorActivationImmutableCandidateIdentity;
  productionEnvironmentIdentityDigest: string;
  productionRouteIdentityDigest: string;
  discoveredToolNames: readonly UniversalToolName[];
  toolDiscoveryEvidenceDigest: string;
  mutation: ConnectorActivationCanaryMutationEvidence;
  foreignClientIsolation: ConnectorActivationForeignClientIsolationEvidence;
  observedAtMs: number;
  expiresAtMs: number;
}

export interface ConnectorActivationPostActivationHostCanaryExpected {
  principalKeyFingerprint: string;
  managementNonce: string;
  managementCorrelationId: string;
  productionActivationPrecheckDigest: string;
  activationReceipt: ConnectorActivationReceipt;
  activationAuthorityReceipt: ConnectorActivationAuthorityReceipt;
  newActiveBindingState: "ACTIVE";
  tokenFamilyIdDigest: string;
  tokenFamilyBindingId: string;
  previousBindingState: "DRAINING" | "ABSENT";
  productionIdentity: ConnectorActivationImmutableCandidateIdentity;
  productionEnvironmentIdentityDigest: string;
  productionRouteIdentityDigest: string;
}

export interface VerifiedConnectorActivationOwnerApproval
  extends Readonly<ConnectorActivationOwnerApprovalPayload> {
  readonly assurance: "cooperative";
  readonly signedPayloadDigest: string;
  readonly [OWNER_APPROVAL_BRAND]: true;
}

export interface VerifiedConnectorActivationStagingPrecheck
  extends Readonly<ConnectorActivationStagingPrecheckPayload> {
  readonly signedPayloadDigest: string;
  readonly [STAGING_PRECHECK_BRAND]: true;
}

export interface VerifiedConnectorActivationPreCutoverHostCanary
  extends Readonly<ConnectorActivationPreCutoverHostCanaryPayload> {
  readonly signedPayloadDigest: string;
  readonly [PRE_CUTOVER_HOST_CANARY_BRAND]: true;
}

export interface VerifiedConnectorActivationProductionPrecheck
  extends Readonly<ConnectorActivationProductionPrecheckPayload> {
  readonly signedPayloadDigest: string;
  readonly [PRODUCTION_PRECHECK_BRAND]: true;
}

export interface VerifiedConnectorActivationPostActivationHostCanary
  extends Readonly<ConnectorActivationPostActivationHostCanaryPayload> {
  readonly signedPayloadDigest: string;
  readonly [POST_ACTIVATION_HOST_CANARY_BRAND]: true;
}

export type ConnectorActivationEvidenceKind =
  | "OWNER_MANAGEMENT_APPROVAL"
  | "STAGING_ACTIVATION_PRECHECK"
  | "PRE_CUTOVER_HOST_CANARY"
  | "PRODUCTION_ACTIVATION_PRECHECK"
  | "POST_ACTIVATION_HOST_CANARY";

export interface SignedConnectorActivationEvidence<T> {
  schemaVersion: 2;
  kind: ConnectorActivationEvidenceKind;
  keyId: string;
  payload: T;
  payloadDigest: string;
  signature: string;
}

export function signConnectorActivationOwnerApproval(
  input: ConnectorActivationOwnerApprovalPayload,
  key: ManagementAuthorizationKey,
  nowMs = Date.now(),
): SignedConnectorActivationEvidence<ConnectorActivationOwnerApprovalPayload> {
  const payload = clonePlain(input);
  validateOwnerApproval(payload, nowMs);
  return sign("OWNER_MANAGEMENT_APPROVAL", payload, key);
}

export function verifyConnectorActivationOwnerApproval(
  envelope: SignedConnectorActivationEvidence<ConnectorActivationOwnerApprovalPayload>,
  key: ManagementAuthorizationKey,
  expected: ConnectorActivationOwnerApprovalBinding,
  nowMs = Date.now(),
): VerifiedConnectorActivationOwnerApproval {
  const payload = verify("OWNER_MANAGEMENT_APPROVAL", envelope, key);
  validateOwnerApproval(payload, nowMs);
  assertOwnerBinding(payload, expected);
  const value = {
    ...payload,
    assurance: "cooperative" as const,
    signedPayloadDigest: envelope.payloadDigest,
  };
  Object.defineProperty(value, "authorityText", {
    value: payload.authorityText,
    enumerable: false,
    configurable: false,
    writable: false,
  });
  return brandedFrozen(value, OWNER_APPROVAL_BRAND);
}

export function signConnectorActivationStagingPrecheck(
  input: ConnectorActivationStagingPrecheckPayload,
  key: ManagementAuthorizationKey,
  nowMs = Date.now(),
): SignedConnectorActivationEvidence<ConnectorActivationStagingPrecheckPayload> {
  const payload = clonePlain(input);
  validateStagingPrecheck(payload, nowMs);
  return sign("STAGING_ACTIVATION_PRECHECK", payload, key);
}

export function verifyConnectorActivationStagingPrecheck(
  envelope: SignedConnectorActivationEvidence<ConnectorActivationStagingPrecheckPayload>,
  key: ManagementAuthorizationKey,
  expected: ConnectorActivationStagingPrecheckExpected,
  nowMs = Date.now(),
): VerifiedConnectorActivationStagingPrecheck {
  const payload = verify("STAGING_ACTIVATION_PRECHECK", envelope, key);
  validateStagingPrecheck(payload, nowMs);
  if (payload.principalKeyFingerprint !== expected.principalKeyFingerprint
    || payload.managementNonce !== expected.managementNonce
    || payload.managementCorrelationId !== expected.managementCorrelationId
    || payload.stagingRouteIdentityDigest !== expected.stagingRouteIdentityDigest
    || !objectsEqual(payload.candidateIdentity, expected.candidateIdentity)
    || !objectsEqual(payload.stagingCandidateBinding, expected.stagingCandidateBinding)) {
    throw new Error("STAGING_ACTIVATION_PRECHECK does not match its trusted management binding.");
  }
  return brandedFrozen({ ...payload, signedPayloadDigest: envelope.payloadDigest }, STAGING_PRECHECK_BRAND);
}

export function signConnectorActivationPreCutoverHostCanary(
  input: ConnectorActivationPreCutoverHostCanaryPayload,
  key: ManagementAuthorizationKey,
  nowMs = Date.now(),
): SignedConnectorActivationEvidence<ConnectorActivationPreCutoverHostCanaryPayload> {
  const payload = clonePlain(input);
  validatePreCutoverHostCanary(payload, nowMs);
  return sign("PRE_CUTOVER_HOST_CANARY", payload, key);
}

export function verifyConnectorActivationPreCutoverHostCanary(
  envelope: SignedConnectorActivationEvidence<ConnectorActivationPreCutoverHostCanaryPayload>,
  key: ManagementAuthorizationKey,
  expected: ConnectorActivationPreCutoverHostCanaryExpected,
  nowMs = Date.now(),
): VerifiedConnectorActivationPreCutoverHostCanary {
  const payload = verify("PRE_CUTOVER_HOST_CANARY", envelope, key);
  validatePreCutoverHostCanary(payload, nowMs);
  assertPersistedPreCutoverHostCanaryBinding(payload, expected);
  assertConnectorStagingActivationAuthorityReceiptMatchesContract(
    payload.stagingActivationReceipt,
    expected.stagingActivationPrecheck,
    payload.stagingActivationAuthorityReceipt,
  );
  validateActivatedOAuthReadback(
    expected.stagingActivationReceipt,
    expected.stagingActivationAuthorityReceipt,
  );
  if (!objectsEqual(payload.stagingActivationReceipt, expected.stagingActivationReceipt)
    || !objectsEqual(
      payload.stagingActivationAuthorityReceipt,
      expected.stagingActivationAuthorityReceipt,
    )
    || payload.stagingTokenFamilyIdDigest !== expected.stagingTokenFamilyIdDigest
    || payload.stagingTokenFamilyBindingId !== expected.stagingTokenFamilyBindingId) {
    throw new Error(
      "PRE_CUTOVER_HOST_CANARY does not match its trusted management binding or exact staging activation readback.",
    );
  }
  return brandedFrozen({ ...payload, signedPayloadDigest: envelope.payloadDigest }, PRE_CUTOVER_HOST_CANARY_BRAND);
}

/**
 * Verifies a persisted PRE artifact after isolated staging has been cleaned.
 * The signed payload carries the complete secret-free OAuth/authority readback;
 * callers must supply only durable management and immutable staging bindings.
 */
export function verifyPersistedConnectorActivationPreCutoverHostCanary(
  envelope: SignedConnectorActivationEvidence<ConnectorActivationPreCutoverHostCanaryPayload>,
  key: ManagementAuthorizationKey,
  expected: ConnectorActivationPersistedPreCutoverHostCanaryExpected,
  nowMs = Date.now(),
): VerifiedConnectorActivationPreCutoverHostCanary {
  const payload = verify("PRE_CUTOVER_HOST_CANARY", envelope, key);
  validatePreCutoverHostCanary(payload, nowMs);
  assertPersistedPreCutoverHostCanaryBinding(payload, expected);
  assertConnectorStagingActivationAuthorityReceiptMatchesContract(
    payload.stagingActivationReceipt,
    expected.stagingActivationPrecheck,
    payload.stagingActivationAuthorityReceipt,
  );
  return brandedFrozen({ ...payload, signedPayloadDigest: envelope.payloadDigest }, PRE_CUTOVER_HOST_CANARY_BRAND);
}

export function signConnectorActivationProductionPrecheck(
  input: ConnectorActivationProductionPrecheckPayload,
  key: ManagementAuthorizationKey,
  nowMs = Date.now(),
): SignedConnectorActivationEvidence<ConnectorActivationProductionPrecheckPayload> {
  const payload = clonePlain(input);
  validateProductionPrecheck(payload, nowMs);
  return sign("PRODUCTION_ACTIVATION_PRECHECK", payload, key);
}

export function verifyConnectorActivationProductionPrecheck(
  envelope: SignedConnectorActivationEvidence<ConnectorActivationProductionPrecheckPayload>,
  key: ManagementAuthorizationKey,
  expected: ConnectorActivationProductionPrecheckExpected,
  nowMs = Date.now(),
): VerifiedConnectorActivationProductionPrecheck {
  assertVerifiedConnectorActivationPreCutoverHostCanary(expected.preCutoverHostCanary);
  validateLifetime(
    expected.preCutoverHostCanary.observedAtMs,
    expected.preCutoverHostCanary.expiresAtMs,
    nowMs,
    MAXIMUM_HOST_RECEIPT_LIFETIME_MS,
  );
  const payload = verify("PRODUCTION_ACTIVATION_PRECHECK", envelope, key);
  validateProductionPrecheck(payload, nowMs);
  assertBinding(payload, expected);
  if (!activationTuplesEqual(payload.tuple, expected.tuple)
    || payload.preCutoverHostCanaryDigest !== expected.preCutoverHostCanary.signedPayloadDigest
    || payload.principalKeyFingerprint !== expected.preCutoverHostCanary.principalKeyFingerprint
    || payload.managementCorrelationId !== expected.preCutoverHostCanary.managementCorrelationId
    || !objectsEqual(payload.candidateIdentity, expected.preCutoverHostCanary.candidateIdentity)
    || !objectsEqual(payload.stagingBinding, expected.preCutoverHostCanary.stagingBinding)
    || payload.stagingRouteIdentityDigest !== expected.preCutoverHostCanary.stagingRouteIdentityDigest
    || payload.oauthResource !== expected.oauthResource
    || payload.productionEnvironmentIdentityDigest !== expected.productionEnvironmentIdentityDigest
    || payload.productionRouteIdentityDigest !== expected.productionRouteIdentityDigest
    || payload.observedAtMs < expected.preCutoverHostCanary.observedAtMs) {
    throw new Error("PRODUCTION_ACTIVATION_PRECHECK does not match the verified PRE canary and production binding.");
  }
  return brandedFrozen({ ...payload, signedPayloadDigest: envelope.payloadDigest }, PRODUCTION_PRECHECK_BRAND);
}

export function signConnectorActivationPostActivationHostCanary(
  input: ConnectorActivationPostActivationHostCanaryPayload,
  key: ManagementAuthorizationKey,
  nowMs = Date.now(),
): SignedConnectorActivationEvidence<ConnectorActivationPostActivationHostCanaryPayload> {
  const payload = clonePlain(input);
  validatePostActivationHostCanary(payload, nowMs);
  return sign("POST_ACTIVATION_HOST_CANARY", payload, key);
}

export function verifyConnectorActivationPostActivationHostCanary(
  envelope: SignedConnectorActivationEvidence<ConnectorActivationPostActivationHostCanaryPayload>,
  key: ManagementAuthorizationKey,
  expected: ConnectorActivationPostActivationHostCanaryExpected,
  nowMs = Date.now(),
): VerifiedConnectorActivationPostActivationHostCanary {
  const payload = verify("POST_ACTIVATION_HOST_CANARY", envelope, key);
  validatePostActivationHostCanary(payload, nowMs);
  validateActivatedOAuthReadback(expected.activationReceipt, expected.activationAuthorityReceipt);
  const activatedAtMs = exactActivatedAtMs(expected.activationReceipt);
  if (payload.principalKeyFingerprint !== expected.principalKeyFingerprint
    || payload.managementNonce !== expected.managementNonce
    || payload.managementCorrelationId !== expected.managementCorrelationId
    || payload.precheckDigest !== expected.productionActivationPrecheckDigest
    || payload.activationReceiptId !== expected.activationReceipt.receiptId
    || payload.activationReceiptDigest !== connectorActivationReceiptDigest(expected.activationReceipt)
    || payload.activationProofDigest !== expected.activationAuthorityReceipt.proofDigest
    || payload.activationAuthorityReceiptDigest
      !== connectorActivationAuthorityReceiptDigest(expected.activationAuthorityReceipt)
    || payload.activatedAtMs !== activatedAtMs
    || !activationTuplesEqual(payload.newActiveTuple, expected.activationReceipt.tuple)
    || payload.newActiveBindingState !== expected.newActiveBindingState
    || payload.tokenFamilyIdDigest !== expected.tokenFamilyIdDigest
    || payload.tokenFamilyBindingId !== expected.tokenFamilyBindingId
    || payload.previousActiveBindingId !== (expected.activationReceipt.previousActiveBindingId ?? null)
    || payload.previousBindingState !== expected.previousBindingState
    || payload.productionEnvironmentIdentityDigest !== expected.productionEnvironmentIdentityDigest
    || payload.productionRouteIdentityDigest !== expected.productionRouteIdentityDigest
    || !objectsEqual(payload.productionIdentity, expected.productionIdentity)) {
    throw new Error("POST_ACTIVATION_HOST_CANARY does not match exact activated OAuth and production readback.");
  }
  const expectedPreviousState = expected.activationReceipt.previousActiveBindingId ? "DRAINING" : "ABSENT";
  if (payload.previousBindingState !== expectedPreviousState) {
    throw new Error("POST_ACTIVATION_HOST_CANARY prior binding disposition is invalid.");
  }
  return brandedFrozen({ ...payload, signedPayloadDigest: envelope.payloadDigest }, POST_ACTIVATION_HOST_CANARY_BRAND);
}

export function assertVerifiedConnectorActivationOwnerApproval(
  value: unknown,
): asserts value is VerifiedConnectorActivationOwnerApproval {
  if (!hasOwnBrand(value, OWNER_APPROVAL_BRAND)) {
    throw new Error("Owner management approval is not verified signed evidence.");
  }
}

export function assertVerifiedConnectorActivationStagingPrecheck(
  value: unknown,
): asserts value is VerifiedConnectorActivationStagingPrecheck {
  if (!hasOwnBrand(value, STAGING_PRECHECK_BRAND)) {
    throw new Error("STAGING_ACTIVATION_PRECHECK is not verified signed evidence.");
  }
}

export function assertVerifiedConnectorActivationPreCutoverHostCanary(
  value: unknown,
): asserts value is VerifiedConnectorActivationPreCutoverHostCanary {
  if (!hasOwnBrand(value, PRE_CUTOVER_HOST_CANARY_BRAND)) {
    throw new Error("PRE_CUTOVER_HOST_CANARY is not verified signed evidence.");
  }
}

export function assertVerifiedConnectorActivationProductionPrecheck(
  value: unknown,
): asserts value is VerifiedConnectorActivationProductionPrecheck {
  if (!hasOwnBrand(value, PRODUCTION_PRECHECK_BRAND)) {
    throw new Error("PRODUCTION_ACTIVATION_PRECHECK is not verified signed evidence.");
  }
}

export function assertVerifiedConnectorActivationPostActivationHostCanary(
  value: unknown,
): asserts value is VerifiedConnectorActivationPostActivationHostCanary {
  if (!hasOwnBrand(value, POST_ACTIVATION_HOST_CANARY_BRAND)) {
    throw new Error("POST_ACTIVATION_HOST_CANARY is not verified signed evidence.");
  }
}

export function connectorActivationReceiptDigest(receipt: ConnectorActivationReceipt): string {
  return sha256Digest(stableJson(receipt));
}

export function connectorActivationAuthorityReceiptDigest(
  receipt: ConnectorActivationAuthorityReceipt,
): string {
  return sha256Digest(stableJson(receipt));
}

function sign<T>(
  kind: ConnectorActivationEvidenceKind,
  payload: T,
  key: ManagementAuthorizationKey,
): SignedConnectorActivationEvidence<T> {
  const frozenPayload = deepFreeze(payload);
  const base = { schemaVersion: 2 as const, kind, keyId: key.keyId, payload: frozenPayload };
  const canonical = stableJson(base);
  return Object.freeze({
    ...base,
    payloadDigest: sha256Digest(canonical),
    signature: createHmac("sha256", key.secret)
      .update(signatureDomain(kind))
      .update(canonical)
      .digest("base64url"),
  });
}

function verify<T>(
  kind: ConnectorActivationEvidenceKind,
  envelope: SignedConnectorActivationEvidence<T>,
  key: ManagementAuthorizationKey,
): T {
  assertExactObjectKeys(envelope, ENVELOPE_KEYS, "Connector activation evidence envelope");
  if (envelope.schemaVersion !== 2 || envelope.kind !== kind || envelope.keyId !== key.keyId) {
    throw new Error("Connector activation evidence identity is invalid.");
  }
  if (!DIGEST_PATTERN.test(envelope.payloadDigest) || !SIGNATURE_PATTERN.test(envelope.signature)) {
    throw new Error("Connector activation evidence signature fields are invalid.");
  }
  const canonical = stableJson({
    schemaVersion: envelope.schemaVersion,
    kind: envelope.kind,
    keyId: envelope.keyId,
    payload: envelope.payload,
  });
  const expectedSignature = createHmac("sha256", key.secret)
    .update(signatureDomain(kind))
    .update(canonical)
    .digest();
  const observedSignature = Buffer.from(envelope.signature, "base64url");
  if (observedSignature.toString("base64url") !== envelope.signature
    || envelope.payloadDigest !== sha256Digest(canonical)
    || observedSignature.length !== expectedSignature.length
    || !timingSafeEqual(observedSignature, expectedSignature)) {
    throw new Error("Connector activation evidence signature verification failed.");
  }
  return clonePlain(envelope.payload);
}

function signatureDomain(kind: ConnectorActivationEvidenceKind): string {
  return `devspace.connector-activation-evidence.v2/${kind}\0`;
}

function validateOwnerApproval(input: ConnectorActivationOwnerApprovalPayload, nowMs: number): void {
  assertExactObjectKeys(input, OWNER_PAYLOAD_KEYS, "Owner management approval payload");
  validateOwnerBinding(input);
  requiredText(input.approvalId, "approvalId", 256);
  requiredText(input.authorityText, "authorityText", 8_000);
  requiredDigest(input.evidenceDigest, "approval evidenceDigest");
  validateLifetime(input.approvedAtMs, input.expiresAtMs, nowMs, MAXIMUM_APPROVAL_LIFETIME_MS);
}

function validateStagingPrecheck(input: ConnectorActivationStagingPrecheckPayload, nowMs: number): void {
  assertExactObjectKeys(input, STAGING_PRECHECK_KEYS, "STAGING_ACTIVATION_PRECHECK payload");
  if (input.stage !== "STAGING_ACTIVATION_PRECHECK"
    || input.hostProvider !== "chatgpt"
    || input.actualHost !== true) {
    throw new Error("STAGING_ACTIVATION_PRECHECK must identify the actual ChatGPT Host boundary.");
  }
  requiredText(input.stagingActivationPrecheckId, "stagingActivationPrecheckId", 256);
  requiredText(input.managementNonce, "managementNonce", 512);
  requiredText(input.managementCorrelationId, "managementCorrelationId", 256);
  requiredPrincipal(input.principalKeyFingerprint, "staging precheck principalKeyFingerprint");
  validateCandidateIdentity(input.candidateIdentity);
  requiredDigest(input.stagingRouteIdentityDigest, "stagingRouteIdentityDigest");
  validateStagingCandidateBinding(input.stagingCandidateBinding);
  validateToolDiscovery(input.discoveredToolNames, input.toolDiscoveryEvidenceDigest);
  validateR0Canary(input.r0Canary);
  validateLifetime(input.observedAtMs, input.expiresAtMs, nowMs, MAXIMUM_PRECHECK_LIFETIME_MS);
}

function validatePreCutoverHostCanary(
  input: ConnectorActivationPreCutoverHostCanaryPayload,
  nowMs: number,
): void {
  assertExactObjectKeys(input, PRE_CUTOVER_KEYS, "PRE_CUTOVER_HOST_CANARY payload");
  if (input.stage !== "PRE_CUTOVER_HOST_CANARY"
    || input.hostProvider !== "chatgpt"
    || input.actualHost !== true) {
    throw new Error("PRE_CUTOVER_HOST_CANARY must identify the actual ChatGPT Host boundary.");
  }
  requiredText(input.preCutoverHostCanaryId, "preCutoverHostCanaryId", 256);
  requiredText(input.managementNonce, "managementNonce", 512);
  requiredText(input.managementCorrelationId, "managementCorrelationId", 256);
  requiredPrincipal(input.principalKeyFingerprint, "PRE canary principalKeyFingerprint");
  validateCandidateIdentity(input.candidateIdentity);
  requiredDigest(input.stagingRouteIdentityDigest, "stagingRouteIdentityDigest");
  validateStagingBinding(input.stagingBinding);
  requiredDigest(input.stagingActivationPrecheckDigest, "stagingActivationPrecheckDigest");
  validateEmbeddedStagingActivationReadback(input);
  validateToolDiscovery(input.discoveredToolNames, input.toolDiscoveryEvidenceDigest);
  validateCanaryMutation(input.mutation);
  validateForeignIsolation(
    input.foreignClientIsolation,
    input.principalKeyFingerprint,
    input.stagingBinding.clientId,
  );
  if (input.stagingActivatedAtMs >= input.mutation.sessionAAuthorizedAtMs
    || input.mutation.sessionBMutationAtMs > input.observedAtMs) {
    throw new Error(
      "PRE_CUTOVER_HOST_CANARY session A/B evidence must be strictly after staging activation.",
    );
  }
  validateLifetime(input.observedAtMs, input.expiresAtMs, nowMs, MAXIMUM_HOST_RECEIPT_LIFETIME_MS);
}

function validateEmbeddedStagingActivationReadback(
  input: ConnectorActivationPreCutoverHostCanaryPayload,
): void {
  const receipt = input.stagingActivationReceipt;
  const authorityReceipt = input.stagingActivationAuthorityReceipt;
  const receiptKeys = Object.prototype.hasOwnProperty.call(receipt, "previousActiveBindingId")
    ? [...ACTIVATED_RECEIPT_KEYS, "previousActiveBindingId"]
    : ACTIVATED_RECEIPT_KEYS;
  assertExactObjectKeys(receipt, receiptKeys, "Embedded staging activation receipt");
  assertExactObjectKeys(
    authorityReceipt,
    ACTIVATION_AUTHORITY_RECEIPT_KEYS,
    "Embedded staging activation authority receipt",
  );
  validateActivatedOAuthReadback(receipt, authorityReceipt);
  if (!ACTIVATION_RECEIPT_ID_PATTERN.test(receipt.receiptId)) {
    throw new Error("Embedded staging activation receiptId is invalid.");
  }
  validateTuple(receipt.tuple);
  requiredDigest(receipt.tupleDigest, "embedded staging tupleDigest");
  requiredDigest(receipt.preimageDigest, "embedded staging preimageDigest");
  requiredDigest(
    authorityReceipt.finalizationPlanDigest,
    "embedded staging finalizationPlanDigest",
  );
  if (receipt.refreshAllowedDuringDrain !== true
    && receipt.refreshAllowedDuringDrain !== false) {
    throw new Error("Embedded staging activation drain policy is invalid.");
  }
  if (Object.prototype.hasOwnProperty.call(receipt, "previousActiveBindingId")) {
    requiredText(receipt.previousActiveBindingId ?? "", "staging previousActiveBindingId", 256);
  }
  if (!receipt.activationAuthority
    || !objectsEqual(receipt.activationAuthority, authorityReceipt)) {
    throw new Error("Embedded staging activation receipt omits its exact authority receipt.");
  }
  const activatedAtMs = exactActivatedAtMs(receipt);
  const preparedAtMs = Date.parse(receipt.preparedAt);
  if (!Number.isSafeInteger(preparedAtMs)
    || preparedAtMs > activatedAtMs
    || !Number.isFinite(Date.parse(receipt.drainDeadlineAt))) {
    throw new Error("Embedded staging activation receipt timing is invalid.");
  }
  requiredText(input.stagingActivationReceiptId, "stagingActivationReceiptId", 256);
  requiredDigest(input.stagingActivationReceiptDigest, "stagingActivationReceiptDigest");
  requiredDigest(input.stagingActivationProofDigest, "stagingActivationProofDigest");
  requiredDigest(
    input.stagingActivationAuthorityReceiptDigest,
    "stagingActivationAuthorityReceiptDigest",
  );
  requiredTimestamp(input.stagingActivatedAtMs, "stagingActivatedAtMs");
  validateTuple(input.stagingActiveTuple);
  if (input.stagingActivationReceiptId !== receipt.receiptId
    || input.stagingActivationReceiptDigest !== connectorActivationReceiptDigest(receipt)
    || input.stagingActivationProofDigest !== authorityReceipt.proofDigest
    || input.stagingActivationAuthorityReceiptDigest
      !== connectorActivationAuthorityReceiptDigest(authorityReceipt)
    || input.stagingActivatedAtMs !== activatedAtMs
    || !activationTuplesEqual(input.stagingActiveTuple, receipt.tuple)
    || authorityReceipt.principalKeyFingerprint !== input.principalKeyFingerprint) {
    throw new Error("Signed staging activation fields do not match the embedded exact readback.");
  }
  assertTupleMatchesCandidateIdentity(
    input.stagingActiveTuple,
    input.candidateIdentity,
    "Staging activation readback",
  );
  if (input.stagingActiveTuple.canonicalName !== input.stagingBinding.canonicalName
    || input.stagingActiveTuple.clientId !== input.stagingBinding.clientId
    || input.stagingActiveTuple.candidateBindingId !== input.stagingBinding.bindingId
    || input.stagingActiveTuple.installationEpoch !== input.stagingBinding.installationEpoch) {
    throw new Error("Staging activation tuple does not match the observed ACTIVE staging binding.");
  }
  requiredDigest(input.stagingTokenFamilyIdDigest, "stagingTokenFamilyIdDigest");
  requiredText(input.stagingTokenFamilyBindingId, "stagingTokenFamilyBindingId", 256);
  if (input.stagingTokenFamilyBindingId !== input.stagingBinding.bindingId) {
    throw new Error("Staging token family is not bound to the activated staging connector.");
  }
}

function assertPersistedPreCutoverHostCanaryBinding(
  payload: ConnectorActivationPreCutoverHostCanaryPayload,
  expected: ConnectorActivationPersistedPreCutoverHostCanaryExpected,
): void {
  assertVerifiedConnectorActivationStagingPrecheck(expected.stagingActivationPrecheck);
  const stagingCandidate = expected.stagingActivationPrecheck.stagingCandidateBinding;
  if (payload.principalKeyFingerprint !== expected.principalKeyFingerprint
    || payload.managementNonce !== expected.managementNonce
    || payload.managementCorrelationId !== expected.managementCorrelationId
    || payload.stagingActivationPrecheckDigest !== expected.stagingActivationPrecheck.signedPayloadDigest
    || payload.principalKeyFingerprint !== expected.stagingActivationPrecheck.principalKeyFingerprint
    || payload.managementCorrelationId !== expected.stagingActivationPrecheck.managementCorrelationId
    || payload.stagingRouteIdentityDigest !== expected.stagingRouteIdentityDigest
    || payload.stagingRouteIdentityDigest !== expected.stagingActivationPrecheck.stagingRouteIdentityDigest
    || !objectsEqual(payload.candidateIdentity, expected.candidateIdentity)
    || !objectsEqual(payload.candidateIdentity, expected.stagingActivationPrecheck.candidateIdentity)
    || !objectsEqual(payload.stagingBinding, expected.stagingBinding)
    || payload.stagingBinding.environmentIdentityDigest !== stagingCandidate.environmentIdentityDigest
    || payload.stagingBinding.canonicalName !== stagingCandidate.canonicalName
    || payload.stagingBinding.clientId !== stagingCandidate.clientId
    || payload.stagingBinding.bindingId !== stagingCandidate.bindingId
    || payload.stagingBinding.installationEpoch !== stagingCandidate.installationEpoch
    || payload.stagingActivatedAtMs <= expected.stagingActivationPrecheck.observedAtMs
    || payload.observedAtMs < expected.stagingActivationPrecheck.observedAtMs
    || payload.observedAtMs >= expected.stagingActivationPrecheck.expiresAtMs) {
    throw new Error(
      "PRE_CUTOVER_HOST_CANARY does not match its trusted management binding or exact staging activation readback.",
    );
  }
}

function validateProductionPrecheck(
  input: ConnectorActivationProductionPrecheckPayload,
  nowMs: number,
): void {
  assertExactObjectKeys(input, PRODUCTION_PRECHECK_KEYS, "PRODUCTION_ACTIVATION_PRECHECK payload");
  if (input.stage !== "PRODUCTION_ACTIVATION_PRECHECK") {
    throw new Error("Production activation precheck stage is invalid.");
  }
  requiredText(input.productionActivationPrecheckId, "productionActivationPrecheckId", 256);
  requiredText(input.managementCorrelationId, "managementCorrelationId", 256);
  validateBinding(input);
  validateTuple(input.tuple);
  if (input.tupleDigest !== connectorActivationTupleDigest(input.tuple)
    || input.canonicalName !== input.tuple.canonicalName) {
    throw new Error("Production activation precheck tuple digest is not exact.");
  }
  validateCandidateIdentity(input.candidateIdentity);
  assertTupleMatchesCandidateIdentity(input.tuple, input.candidateIdentity, "Production activation precheck");
  validateOAuthResource(input.oauthResource);
  validateExactOAuthScopes(input.oauthScopes);
  requiredDigest(input.preCutoverHostCanaryDigest, "preCutoverHostCanaryDigest");
  validateStagingBinding(input.stagingBinding);
  if (input.stagingBinding.canonicalName !== input.tuple.canonicalName) {
    throw new Error("Staging and production canonical connector names do not match.");
  }
  requiredDigest(input.stagingRouteIdentityDigest, "stagingRouteIdentityDigest");
  requiredDigest(input.productionEnvironmentIdentityDigest, "productionEnvironmentIdentityDigest");
  requiredDigest(input.productionRouteIdentityDigest, "productionRouteIdentityDigest");
  if (input.stagingBinding.environmentIdentityDigest === input.productionEnvironmentIdentityDigest) {
    throw new Error("Staging and production environment identities must remain distinct.");
  }
  const identifiersEqual = input.stagingBinding.bindingId === input.tuple.candidateBindingId
    && input.stagingBinding.clientId === input.tuple.clientId;
  if (input.stagingProductionBindingRelation !== "DISTINCT_STAGING_BINDING"
    && input.stagingProductionBindingRelation !== "IDENTICAL_BINDING_IDENTIFIERS_ISOLATED_STAGING") {
    throw new Error("Staging versus production binding relation is invalid.");
  }
  if ((input.stagingProductionBindingRelation === "DISTINCT_STAGING_BINDING" && identifiersEqual)
    || (input.stagingProductionBindingRelation === "IDENTICAL_BINDING_IDENTIFIERS_ISOLATED_STAGING"
      && !identifiersEqual)) {
    throw new Error("Staging versus production binding relation is not truthful.");
  }
  validateLifetime(input.observedAtMs, input.expiresAtMs, nowMs, MAXIMUM_PRECHECK_LIFETIME_MS);
}

function validatePostActivationHostCanary(
  input: ConnectorActivationPostActivationHostCanaryPayload,
  nowMs: number,
): void {
  assertExactObjectKeys(input, POST_ACTIVATION_KEYS, "POST_ACTIVATION_HOST_CANARY payload");
  if (input.stage !== "POST_ACTIVATION_HOST_CANARY"
    || input.hostProvider !== "chatgpt"
    || input.actualHost !== true) {
    throw new Error("POST_ACTIVATION_HOST_CANARY must identify the actual ChatGPT Host boundary.");
  }
  requiredText(input.postActivationHostCanaryId, "postActivationHostCanaryId", 256);
  requiredText(input.managementNonce, "managementNonce", 512);
  requiredText(input.managementCorrelationId, "managementCorrelationId", 256);
  requiredPrincipal(input.principalKeyFingerprint, "POST canary principalKeyFingerprint");
  requiredDigest(input.precheckDigest, "precheckDigest");
  requiredText(input.activationReceiptId, "activationReceiptId", 256);
  requiredDigest(input.activationReceiptDigest, "activationReceiptDigest");
  requiredDigest(input.activationProofDigest, "activationProofDigest");
  requiredDigest(input.activationAuthorityReceiptDigest, "activationAuthorityReceiptDigest");
  requiredTimestamp(input.activatedAtMs, "activatedAtMs");
  validateTuple(input.newActiveTuple);
  if (input.newActiveBindingState !== "ACTIVE") throw new Error("Post-activation binding must be ACTIVE.");
  requiredDigest(input.tokenFamilyIdDigest, "tokenFamilyIdDigest");
  requiredText(input.tokenFamilyBindingId, "tokenFamilyBindingId", 256);
  if (input.tokenFamilyBindingId !== input.newActiveTuple.candidateBindingId) {
    throw new Error("Post-activation token family is not bound to the new ACTIVE connector.");
  }
  if (input.previousBindingState === "DRAINING") {
    requiredText(input.previousActiveBindingId ?? "", "previousActiveBindingId", 256);
    if (input.previousActiveBindingId === input.newActiveTuple.candidateBindingId) {
      throw new Error("Prior DRAINING binding cannot be the new ACTIVE binding.");
    }
  } else if (input.previousBindingState === "ABSENT") {
    if (input.previousActiveBindingId !== null) throw new Error("Absent prior binding must use a null identity.");
  } else {
    throw new Error("Prior binding disposition is invalid.");
  }
  validateCandidateIdentity(input.productionIdentity);
  assertTupleMatchesCandidateIdentity(input.newActiveTuple, input.productionIdentity, "Post-activation canary");
  requiredDigest(input.productionEnvironmentIdentityDigest, "productionEnvironmentIdentityDigest");
  requiredDigest(input.productionRouteIdentityDigest, "productionRouteIdentityDigest");
  validateToolDiscovery(input.discoveredToolNames, input.toolDiscoveryEvidenceDigest);
  validateCanaryMutation(input.mutation);
  validateForeignIsolation(
    input.foreignClientIsolation,
    input.principalKeyFingerprint,
    input.newActiveTuple.clientId,
  );
  if (input.observedAtMs <= input.activatedAtMs
    || input.mutation.sessionAAuthorizedAtMs <= input.activatedAtMs
    || input.mutation.sessionBMutationAtMs > input.observedAtMs) {
    throw new Error("Post-activation Host observations must be fresh and strictly after activation.");
  }
  validateLifetime(input.observedAtMs, input.expiresAtMs, nowMs, MAXIMUM_HOST_RECEIPT_LIFETIME_MS);
}

function validateCandidateIdentity(input: ConnectorActivationImmutableCandidateIdentity): void {
  assertExactObjectKeys(input, CANDIDATE_IDENTITY_KEYS, "Immutable candidate identity");
  for (const name of CANDIDATE_IDENTITY_KEYS) requiredDigest(input[name], name);
}

function validateStagingCandidateBinding(input: ConnectorActivationStagingCandidateBindingIdentity): void {
  validateStagingBindingShape(input, "ACTIVATION_PREPARED");
}

function validateStagingBinding(input: ConnectorActivationStagingBindingIdentity): void {
  validateStagingBindingShape(input, "ACTIVE");
}

function validateStagingBindingShape(
  input: ConnectorActivationStagingCandidateBindingIdentity | ConnectorActivationStagingBindingIdentity,
  expectedState: "ACTIVATION_PREPARED" | "ACTIVE",
): void {
  assertExactObjectKeys(input, STAGING_BINDING_KEYS, "Staging binding identity");
  requiredDigest(input.environmentIdentityDigest, "staging environmentIdentityDigest");
  requiredText(input.canonicalName, "staging canonicalName", 128);
  requiredText(input.clientId, "staging clientId", 256);
  requiredText(input.bindingId, "staging bindingId", 256);
  if (!Number.isSafeInteger(input.installationEpoch) || input.installationEpoch < 1) {
    throw new Error("Staging installationEpoch is invalid.");
  }
  if (input.state !== expectedState) {
    throw new Error(`Staging binding must be ${expectedState} at this evidence stage.`);
  }
}

function validateTuple(input: ConnectorActivationTuple): void {
  assertExactObjectKeys(input, TUPLE_KEYS, "Connector activation tuple");
  requiredText(input.canonicalName, "tuple canonicalName", 128);
  requiredText(input.candidateBindingId, "tuple candidateBindingId", 256);
  requiredText(input.clientId, "tuple clientId", 256);
  if (!Number.isSafeInteger(input.installationEpoch) || input.installationEpoch < 1) {
    throw new Error("Connector activation tuple installationEpoch is invalid.");
  }
  requiredDigest(input.schemaGeneration, "tuple schemaGeneration");
  requiredDigest(input.authorityContractGeneration, "tuple authorityContractGeneration");
  requiredDigest(input.redirectUrisDigest, "tuple redirectUrisDigest");
  requiredDigest(input.buildDigest, "tuple buildDigest");
}

function validateR0Canary(input: ConnectorActivationR0CanaryEvidence): void {
  assertExactObjectKeys(input, R0_CANARY_KEYS, "Staging R0 canary evidence");
  validateCanaryOperation(input.tool, input.operation, input.argumentsDigest, input.resourceDigest);
  if (input.providerDispatchCount !== 1) throw new Error("Staging R0 canary provider dispatch count must be one.");
  requiredDigest(input.readbackDigest, "staging R0 readbackDigest");
}

function validateCanaryMutation(input: ConnectorActivationCanaryMutationEvidence): void {
  assertExactObjectKeys(input, CANARY_MUTATION_KEYS, "Host canary mutation evidence");
  validateCanaryOperation(input.tool, input.operation, input.argumentsDigest, input.resourceDigest);
  requiredDigest(input.sessionAIdDigest, "sessionAIdDigest");
  requiredDigest(input.sessionAAuthorizationEvidenceDigest, "sessionAAuthorizationEvidenceDigest");
  requiredTimestamp(input.sessionAAuthorizedAtMs, "sessionAAuthorizedAtMs");
  requiredDigest(input.sessionACloseEvidenceDigest, "sessionACloseEvidenceDigest");
  requiredTimestamp(input.sessionAClosedAtMs, "sessionAClosedAtMs");
  requiredDigest(input.sessionBIdDigest, "sessionBIdDigest");
  requiredDigest(input.sessionBMutationEvidenceDigest, "sessionBMutationEvidenceDigest");
  requiredTimestamp(input.sessionBMutationAtMs, "sessionBMutationAtMs");
  if (input.sessionAIdDigest === input.sessionBIdDigest
    || input.sessionAAuthorizedAtMs >= input.sessionAClosedAtMs
    || input.sessionAClosedAtMs >= input.sessionBMutationAtMs) {
    throw new Error("Host canary must authorize and close session A before distinct session B mutation.");
  }
  requiredRawDigest(input.actionFingerprint, "canary actionFingerprint");
  requiredRawDigest(input.resourceKeySha256, "canary resourceKeySha256");
  if (!AUTHORITY_ID_PATTERN.test(input.authorityId)) throw new Error("Canary authorityId is invalid.");
  if (!ACTION_CLAIM_ID_PATTERN.test(input.actionClaimId)) throw new Error("Canary actionClaimId is invalid.");
  if (!Number.isSafeInteger(input.fencingToken) || input.fencingToken < 1) {
    throw new Error("Canary fencingToken is invalid.");
  }
  requiredDigest(input.authorityReceiptDigest, "canary authorityReceiptDigest");
  if (input.providerDispatchCount !== 1) {
    throw new Error("Host canary provider dispatch count must be exactly one.");
  }
  requiredDigest(input.postReadbackDigest, "canary postReadbackDigest");
  if (input.cleanupPerformed !== true) throw new Error("Host canary cleanup was not performed.");
  requiredDigest(input.cleanupEvidenceDigest, "canary cleanupEvidenceDigest");
}

function validateCanaryOperation(
  tool: UniversalToolName,
  operation: string,
  argumentsDigest: string,
  resourceDigest: string,
): void {
  if (!UNIVERSAL_TOOL_NAMES.includes(tool)) {
    throw new Error("Host canary tool is not one of the canonical eight tools.");
  }
  requiredText(operation, "canary operation", 128);
  requiredDigest(argumentsDigest, "canary argumentsDigest");
  requiredDigest(resourceDigest, "canary resourceDigest");
}

function validateForeignIsolation(
  input: ConnectorActivationForeignClientIsolationEvidence,
  ownerPrincipalKeyFingerprint: string,
  authorizedClientId: string,
): void {
  assertExactObjectKeys(input, FOREIGN_ISOLATION_KEYS, "Foreign client isolation evidence");
  requiredText(input.clientId, "foreign clientId", 256);
  requiredPrincipal(input.principalKeyFingerprint, "foreign principalKeyFingerprint");
  if (input.clientId === authorizedClientId
    || input.principalKeyFingerprint === ownerPrincipalKeyFingerprint
    || input.errorCode !== "AUTHORITY_PRINCIPAL_MISMATCH"
    || input.providerDispatchCount !== 0) {
    throw new Error("Foreign client isolation did not prove principal mismatch with provider dispatch zero.");
  }
  requiredDigest(input.evidenceDigest, "foreign isolation evidenceDigest");
}

function validateToolDiscovery(names: readonly UniversalToolName[], evidenceDigest: string): void {
  if (!Array.isArray(names)
    || names.length !== UNIVERSAL_TOOL_NAMES.length
    || names.some((tool, index) => tool !== UNIVERSAL_TOOL_NAMES[index])) {
    throw new Error("Host evidence must discover exactly the canonical eight tools.");
  }
  requiredDigest(evidenceDigest, "tool discovery evidenceDigest");
}

function validateOAuthResource(value: string): void {
  requiredText(value, "oauthResource", 2_048);
  let parsed: URL;
  try {
    parsed = new URL(value);
  } catch {
    throw new Error("Production OAuth resource is invalid.");
  }
  if (parsed.protocol !== "https:" || parsed.username || parsed.password || parsed.hash) {
    throw new Error("Production OAuth resource is invalid.");
  }
}

function validateExactOAuthScopes(scopes: readonly ConnectorActivationBaseOAuthScope[]): void {
  if (!Array.isArray(scopes)
    || scopes.length !== UNIVERSAL_OWNER_SCOPES.length
    || scopes.some((scope, index) => scope !== UNIVERSAL_OWNER_SCOPES[index])) {
    throw new Error("Production activation precheck must bind exactly the six Base OAuth scopes.");
  }
}

function assertTupleMatchesCandidateIdentity(
  tuple: ConnectorActivationTuple,
  identity: ConnectorActivationImmutableCandidateIdentity,
  label: string,
): void {
  if (tuple.buildDigest !== identity.buildDigest
    || tuple.schemaGeneration !== identity.schemaGeneration
    || tuple.authorityContractGeneration !== identity.authorityContractGeneration) {
    throw new Error(`${label} build, schema, or authority identity drifted.`);
  }
}

function validateBinding(input: ConnectorActivationEvidenceBinding): void {
  requiredPrincipal(input.principalKeyFingerprint, "owner principal fingerprint");
  requiredText(input.receiptId, "receiptId", 256);
  requiredText(input.canonicalName, "canonicalName", 128);
  requiredDigest(input.tupleDigest, "tupleDigest");
  requiredDigest(input.activePreimageDigest, "activePreimageDigest");
  requiredDigest(input.finalizationPlanDigest, "finalizationPlanDigest");
}

function validateOwnerBinding(input: ConnectorActivationOwnerApprovalBinding): void {
  validateBinding(input);
  requiredDigest(input.preCutoverHostCanaryDigest, "preCutoverHostCanaryDigest");
  requiredDigest(input.productionActivationPrecheckDigest, "productionActivationPrecheckDigest");
}

function assertBinding(observed: ConnectorActivationEvidenceBinding, expected: ConnectorActivationEvidenceBinding): void {
  for (const key of [
    "principalKeyFingerprint", "receiptId", "canonicalName", "tupleDigest",
    "activePreimageDigest", "finalizationPlanDigest",
  ] as const) {
    if (observed[key] !== expected[key]) throw new Error(`Connector activation evidence ${key} mismatch.`);
  }
}

function assertOwnerBinding(
  observed: ConnectorActivationOwnerApprovalBinding,
  expected: ConnectorActivationOwnerApprovalBinding,
): void {
  assertBinding(observed, expected);
  if (observed.preCutoverHostCanaryDigest !== expected.preCutoverHostCanaryDigest
    || observed.productionActivationPrecheckDigest !== expected.productionActivationPrecheckDigest) {
    throw new Error("Owner management approval does not bind both staged evidence receipts.");
  }
}

function validateLifetime(issuedAtMs: number, expiresAtMs: number, nowMs: number, maximumMs: number): void {
  if (!Number.isSafeInteger(issuedAtMs)
    || !Number.isSafeInteger(expiresAtMs)
    || !Number.isSafeInteger(nowMs)
    || issuedAtMs < 0
    || expiresAtMs <= issuedAtMs
    || expiresAtMs - issuedAtMs > maximumMs) {
    throw new Error("Connector activation evidence lifetime is invalid.");
  }
  if (nowMs < issuedAtMs || nowMs >= expiresAtMs) {
    throw new Error("Connector activation evidence is not currently valid.");
  }
}

function exactActivatedAtMs(receipt: ConnectorActivationReceipt): number {
  if (receipt.status !== "ACTIVATED" || !receipt.activatedAt) {
    throw new Error("Expected OAuth activation receipt is not ACTIVATED.");
  }
  const value = Date.parse(receipt.activatedAt);
  if (!Number.isSafeInteger(value)) throw new Error("Expected OAuth activatedAt is invalid.");
  return value;
}

function validateActivatedOAuthReadback(
  receipt: ConnectorActivationReceipt,
  authorityReceipt: ConnectorActivationAuthorityReceipt,
): void {
  exactActivatedAtMs(receipt);
  const proofRecord: Record<string, unknown> = { ...authorityReceipt };
  delete proofRecord.proofDigest;
  delete proofRecord.consumedAt;
  if (receipt.tupleDigest !== connectorActivationTupleDigest(receipt.tuple)
    || receipt.ownerAuthorityId !== authorityReceipt.authorityId
    || receipt.activatedAt !== authorityReceipt.consumedAt
    || authorityReceipt.receiptId !== receipt.receiptId
    || authorityReceipt.canonicalName !== receipt.tuple.canonicalName
    || authorityReceipt.tupleDigest !== receipt.tupleDigest
    || authorityReceipt.activePreimageDigest !== receipt.preimageDigest
    || authorityReceipt.risk !== "R3"
    || authorityReceipt.claimState !== "DISPATCHED"
    || authorityReceipt.approvalAssurance !== "cooperative"
    || !AUTHORITY_ID_PATTERN.test(authorityReceipt.authorityId)
    || !ACTION_CLAIM_ID_PATTERN.test(authorityReceipt.actionClaimId)
    || !RAW_DIGEST_PATTERN.test(authorityReceipt.actionFingerprint)
    || !RAW_DIGEST_PATTERN.test(authorityReceipt.resourceKeySha256)
    || !Number.isSafeInteger(authorityReceipt.fencingToken)
    || authorityReceipt.fencingToken < 1
    || !Number.isSafeInteger(authorityReceipt.claimedAtMs)
    || !Number.isSafeInteger(authorityReceipt.dispatchedAtMs)
    || authorityReceipt.dispatchedAtMs < authorityReceipt.claimedAtMs
    || !DIGEST_PATTERN.test(authorityReceipt.evidenceDigest)
    || authorityReceipt.proofDigest !== sha256Digest(oauthStableJson(proofRecord))
    || (receipt.activationAuthority !== undefined
      && connectorActivationAuthorityReceiptDigest(receipt.activationAuthority)
        !== connectorActivationAuthorityReceiptDigest(authorityReceipt))) {
    throw new Error("Expected OAuth activation readback or authority proof is not exact.");
  }
}

function activationTuplesEqual(left: ConnectorActivationTuple, right: ConnectorActivationTuple): boolean {
  return Boolean(left && right) && objectsEqual(left, right);
}

function assertExactObjectKeys(
  value: unknown,
  expectedKeys: readonly string[],
  label: string,
): asserts value is Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error(`${label} is invalid.`);
  const keys = Object.keys(value).sort();
  const expected = [...expectedKeys].sort();
  if (keys.length !== expected.length || keys.some((key, index) => key !== expected[index])) {
    throw new Error(`${label} shape is invalid.`);
  }
}

function brandedFrozen<T extends object, K extends symbol>(value: T, brand: K): T & { readonly [P in K]: true } {
  Object.defineProperty(value, brand, {
    value: true,
    enumerable: false,
    configurable: false,
    writable: false,
  });
  return deepFreeze(value) as T & { readonly [P in K]: true };
}

function deepFreeze<T>(value: T): T {
  if (value && typeof value === "object" && !Object.isFrozen(value)) {
    for (const child of Object.values(value as Record<string, unknown>)) deepFreeze(child);
    Object.freeze(value);
  }
  return value;
}

function clonePlain<T>(value: T): T {
  return structuredClone(value);
}

function hasOwnBrand(value: unknown, brand: symbol): value is Record<PropertyKey, unknown> {
  return Boolean(value && typeof value === "object" && Object.prototype.hasOwnProperty.call(value, brand));
}

function requiredDigest(value: string, name: string): void {
  if (!DIGEST_PATTERN.test(value)) throw new Error(`${name} is invalid.`);
}

function requiredRawDigest(value: string, name: string): void {
  if (!RAW_DIGEST_PATTERN.test(value)) throw new Error(`${name} is invalid.`);
}

function requiredPrincipal(value: string, name: string): void {
  if (!RAW_DIGEST_PATTERN.test(value) || /^0{64}$/u.test(value)) throw new Error(`${name} is invalid.`);
}

function requiredTimestamp(value: number, name: string): void {
  if (!Number.isSafeInteger(value) || value < 0) throw new Error(`${name} is invalid.`);
}

function requiredText(value: string, name: string, maximum: number): void {
  if (!value || value.length > maximum || /[\0\r\n]/u.test(value)) throw new Error(`${name} is invalid.`);
}

function objectsEqual(left: unknown, right: unknown): boolean {
  return stableJson(left) === stableJson(right);
}

function oauthStableJson(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(oauthStableJson).join(",")}]`;
  if (value && typeof value === "object") {
    const record = value as Record<string, unknown>;
    return `{${Object.keys(record).sort().map(
      (key) => `${JSON.stringify(key)}:${oauthStableJson(record[key])}`,
    ).join(",")}}`;
  }
  return JSON.stringify(value) ?? "null";
}

function sha256Digest(value: string): string {
  return `sha256:${createHash("sha256").update(value).digest("hex")}`;
}

function stableJson(value: unknown): string {
  return JSON.stringify(canonical(value));
}

function canonical(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(canonical);
  if (!value || typeof value !== "object") return value;
  return Object.fromEntries(
    Object.entries(value as Record<string, unknown>)
      .sort(([left], [right]) => (left < right ? -1 : left > right ? 1 : 0))
      .map(([key, item]) => [key, canonical(item)]),
  );
}
