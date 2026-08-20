import type { SnapshotGroupManifest } from "../../src/v2/snapshot-group.js";
import type {
  SignedConnectorActivationEvidence,
  ConnectorActivationPostActivationHostCanaryPayload,
  VerifiedConnectorActivationPostActivationHostCanary,
} from "../../src/v2/connector-activation-evidence.js";

export {
  FINALIZATION_STORE_ID,
  FINALIZATION_STORE_MIGRATION,
  FINALIZATION_STORE_MIGRATION_CHECKSUM,
  FINALIZATION_STORE_MIGRATION_NAME,
  FINALIZATION_STORE_SCHEMA_FINGERPRINT,
  FINALIZATION_STORE_SCHEMA_VERSION,
} from "./finalization-store-contract.mjs";

export type Sha256Digest = `sha256:${string}`;

export type FinalizationState =
  | "DRAFT"
  | "PREPARED"
  | "PROFILE_GATES_EVALUATED"
  | "ACTIVATION_PENDING"
  | "POST_ACTIVATION_VERIFIED"
  | "DRAINING"
  | "SEALED"
  | "BASE_PROFILE_FINAL_PASS"
  | "FAILED"
  | "UNKNOWN";

export interface FinalizationRuntimeIdentity {
  readonly sourceRevision: string;
  readonly runtimeRevision: string;
  readonly buildDigest: Sha256Digest;
  readonly schemaGeneration: Sha256Digest;
  readonly authorityContractGeneration: Sha256Digest;
  readonly configDigest: Sha256Digest;
  readonly configSchemaIdentity: Sha256Digest;
}

export interface FinalizationImmutableIdentity {
  readonly runtimeIdentityDigest: Sha256Digest;
  readonly buildDigest: Sha256Digest;
  readonly schemaGeneration: Sha256Digest;
  readonly authorityContractGeneration: Sha256Digest;
  readonly buildCapabilityManifestDigest: Sha256Digest;
  readonly generatedSchemaDigest: Sha256Digest;
  readonly packageSha256: Sha256Digest;
  readonly migrationManifestDigest: Sha256Digest;
}

export interface FinalizationStoreIdentity {
  readonly storeId: "lifecycle-finalization-store";
  readonly path: string;
  readonly schemaVersion: 1;
  readonly schemaFingerprint: Sha256Digest;
  readonly migration: Readonly<{
    storeId: "lifecycle-finalization-store";
    version: 1;
    name: "lifecycle-finalization-sqlite";
    checksum: Sha256Digest;
    module: "scripts/lib/finalization-store-contract.mjs";
  }>;
  readonly state: FinalizationState;
  readonly revision: number;
  readonly transactionId: string | null;
  readonly inputDigest: Sha256Digest | null;
  readonly prepareDigest: Sha256Digest | null;
  readonly sealInputDigest: Sha256Digest | null;
  readonly finalDigest: Sha256Digest | null;
  readonly contentGeneration: Sha256Digest;
  readonly integrity: "ok";
  readonly foreignKeyViolations: 0;
  readonly createdAt: string;
  readonly updatedAt: string;
}

export interface FinalizationStoreOptions {
  readonly storePath: string;
}

export interface InitializeFinalizationStoreOptions extends FinalizationStoreOptions {
  readonly now?: () => string;
  readonly requireDraft?: boolean;
}

export interface FinalizationSnapshotBinding {
  readonly manifestPath: string;
  readonly manifestSha256: Sha256Digest;
  readonly manifest: SnapshotGroupManifest;
}

export interface FinalizationProfileApplicability {
  readonly profile:
    | "BASE_SINGLE_OWNER"
    | "MULTI_USER"
    | "SIDECAR_AUTHORITY"
    | "HOST_ATTESTED"
    | "GUI_CAPTURE";
  readonly applicability: "REQUIRED" | "NOT_APPLICABLE";
}

export type FinalizationPrecutoverGateName =
  | "G00 PROFILE" | "G01 SOURCE" | "G02 STATIC" | "G03 UNIT"
  | "G04 PROTOCOL" | "G05 FUNCTIONAL" | "G06 SECURITY" | "G07 DURABILITY"
  | "G08 LOAD" | "G09 PACKAGE" | "G10 STAGING" | "G11 HOST"
  | "G12 CONNECTOR" | "G13 CUTOVER";

export type FinalizationDeferredGateName = "G16 CLEANUP" | "G17 FINALIZATION";

export type FinalizationGateResult =
  | Readonly<{
    profile: "BASE_SINGLE_OWNER";
    gate: FinalizationPrecutoverGateName;
    applicability: "REQUIRED";
    result: "PASS";
    evidenceDigest: Sha256Digest;
  }>
  | Readonly<{
    profile: "BASE_SINGLE_OWNER";
    gate: FinalizationDeferredGateName;
    applicability: "REQUIRED";
    result: "NOT_RUN";
    evidenceDigest?: never;
  }>;

export type FinalizationPrecutoverCapabilityName =
  | "source-runtime-build-profile-identity"
  | "one-production-process-route"
  | "health-ready-doctor"
  | "unauthenticated-mcp-401"
  | "public-management-blocked"
  | "exact-eight-tools"
  | "canonical-active-one"
  | "fresh-host-discovery"
  | "cross-session-harmless-mutation"
  | "local-target-read-write-exec-process-mcp-artifact"
  | "self-restart-transaction"
  | "all-store-consistent-snapshot";

export type FinalizationConditionalCapabilityResult = Readonly<{
  profile: "MULTI_USER" | "SIDECAR_AUTHORITY" | "HOST_ATTESTED" | "GUI_CAPTURE";
  capability: string;
  applicability: "NOT_APPLICABLE";
  result: "NOT_APPLICABLE";
  evidenceDigest?: never;
}>;

export type FinalizationCapabilityResult =
  | Readonly<{
    profile: "BASE_SINGLE_OWNER";
    capability: FinalizationPrecutoverCapabilityName;
    applicability: "REQUIRED";
    result: "PASS";
    evidenceDigest: Sha256Digest;
  }>
  | Readonly<{
    profile: "BASE_SINGLE_OWNER";
    capability: "no-residue";
    applicability: "REQUIRED";
    result: "NOT_RUN";
    evidenceDigest?: never;
  }>
  | FinalizationConditionalCapabilityResult;

export interface FinalizationFinalGateResult {
  readonly profile: "BASE_SINGLE_OWNER";
  readonly gate: FinalizationPrecutoverGateName | FinalizationDeferredGateName;
  readonly applicability: "REQUIRED";
  readonly result: "PASS";
  readonly evidenceDigest: Sha256Digest;
}

export type FinalizationFinalCapabilityResult =
  | Readonly<{
    profile: "BASE_SINGLE_OWNER";
    capability: FinalizationPrecutoverCapabilityName | "no-residue";
    applicability: "REQUIRED";
    result: "PASS";
    evidenceDigest: Sha256Digest;
  }>
  | FinalizationConditionalCapabilityResult;

export interface FinalizationSqliteSource {
  readonly path: string;
  readonly userVersion: number;
  readonly schemaFingerprint: Sha256Digest;
}

export interface FinalizationProductionSources {
  readonly schemaVersion: 1;
  readonly managementAuthorization: Readonly<{
    keyRef: string;
    stateDir: string;
    keyId: string;
  }>;
  readonly processManager: Readonly<{
    definitionPath: string;
    definitionSha256: Sha256Digest;
    canonicalProcessName: string;
    expectedProcesses: readonly Readonly<{
      name: string;
      status: "online";
      cwd: string;
      script: string;
    }>[];
    savedStatePath: string;
  }>;
  readonly endpoints: Readonly<{
    runtimeIdentityUrl: string;
    routeIdentityUrl: string;
    managementIdentityUrl: string;
    managementIdentityDigest: Sha256Digest;
  }>;
  readonly listeners: Readonly<{
    scopePorts: readonly number[];
    expected: readonly Readonly<{ command: string; address: string; port: number }>[];
  }>;
  readonly route: Readonly<{
    definitionPath: string;
    definitionSha256: Sha256Digest;
    targetGenerationConfigPath: string;
    targetGenerationConfigSha256: Sha256Digest;
    publicRouteKey: string;
    expectedFunnelInventoryDigest: Sha256Digest;
  }>;
  readonly runtimeEnvironmentPath: string;
  readonly stores: Readonly<{
    oauth: FinalizationSqliteSource;
    authority: FinalizationSqliteSource;
    connectorJournal: FinalizationSqliteSource;
    postActivationReceipt: Readonly<{ path: string }>;
  }>;
  readonly activation: Readonly<{
    receiptId: string;
    approvalId: string;
    canonicalName: string;
    principalKeyFingerprint: string;
    managementNonce: string;
    managementCorrelationId: string;
    productionActivationPrecheckDigest: Sha256Digest;
    tokenFamilyIdDigest: Sha256Digest;
    tokenFamilyBindingId: string;
    previousBindingState: "DRAINING" | "ABSENT";
    productionIdentity: Omit<FinalizationImmutableIdentity, "migrationManifestDigest">;
    productionEnvironmentIdentityDigest: Sha256Digest;
    productionRouteIdentityDigest: Sha256Digest;
  }>;
  readonly residue: Readonly<{ paths: readonly string[] }>;
}

export interface FinalizationDestructiveStage extends Readonly<Record<string, unknown>> {
  readonly id: string;
  readonly destructive: boolean;
  readonly operation: string;
  readonly target: string;
}

export interface FinalizationPreimage {
  readonly target: string;
  readonly sha256: Sha256Digest | "ABSENT";
  readonly [key: string]: unknown;
}

export interface FinalizationPrepareEvidence {
  readonly schemaVersion: 1;
  readonly status: "PASS";
  readonly phase: "production-reconnect";
  readonly transactionId: string;
  readonly upgradeRequestDigest: Sha256Digest;
  readonly releasePackage: string;
  readonly runtimeIdentity: FinalizationRuntimeIdentity;
  readonly immutableIdentity: FinalizationImmutableIdentity;
  readonly snapshotGroup: FinalizationSnapshotBinding;
  readonly profileApplicability: readonly FinalizationProfileApplicability[];
  readonly gateResults: readonly FinalizationGateResult[];
  readonly capabilities: readonly FinalizationCapabilityResult[];
  readonly productionSources: FinalizationProductionSources;
  readonly inventories: Readonly<{
    processes: readonly Readonly<Record<string, unknown>>[];
    listeners: readonly Readonly<Record<string, unknown>>[];
    routes: readonly Readonly<Record<string, unknown>>[];
    oauth: readonly Readonly<Record<string, unknown>>[];
    connectors: readonly Readonly<Record<string, unknown>>[];
    temporaryArtifacts: readonly Readonly<Record<string, unknown>>[];
  }>;
  readonly expectedCanary: Readonly<{ toolNames: readonly string[] }>;
  readonly canonicalConnector: Readonly<{
    name: string;
    bindingId: string;
    installationEpoch: number;
  }>;
  readonly destructivePlan: readonly FinalizationDestructiveStage[];
  readonly preimages?: readonly FinalizationPreimage[];
}

export interface FinalizationPreparedRecord {
  readonly schemaVersion: 1;
  readonly state: "PREPARED";
  readonly revision: 1;
  readonly transactionId: string;
  readonly preparedAt: string;
  readonly inputDigest: Sha256Digest;
  readonly sourceRevision: string;
  readonly runtimeIdentity: FinalizationRuntimeIdentity;
  readonly immutableIdentity: FinalizationImmutableIdentity;
  readonly releasePackage: string;
  readonly releaseManifestSha256: Sha256Digest;
  readonly snapshotGroup: FinalizationSnapshotBinding;
  readonly profileApplicability: readonly FinalizationProfileApplicability[];
  readonly gateResults: readonly FinalizationGateResult[];
  readonly capabilities: readonly FinalizationCapabilityResult[];
  readonly productionSources: FinalizationProductionSources;
  readonly inventories: FinalizationPrepareEvidence["inventories"];
  readonly expectedCanary: FinalizationPrepareEvidence["expectedCanary"];
  readonly canonicalConnector: FinalizationPrepareEvidence["canonicalConnector"];
  readonly destructivePlan: readonly FinalizationDestructiveStage[];
  readonly preimages: readonly FinalizationPreimage[];
  readonly finalizationStore: FinalizationStoreIdentity;
  readonly checksum: Sha256Digest;
}

export interface FinalizationPrepareResult {
  readonly status: "PREPARED";
  readonly resumed: boolean;
  readonly path: string;
  readonly prepareDigest: Sha256Digest;
  readonly storeIdentity: FinalizationStoreIdentity;
  readonly bindings: Readonly<{
    transactionId: string;
    snapshotGroupDigest: Sha256Digest;
    immutableIdentityDigest: Sha256Digest;
    productionSourcesDigest: Sha256Digest;
    gateResultsDigest: Sha256Digest;
    capabilitiesDigest: Sha256Digest;
    profileApplicabilityDigest: Sha256Digest;
    activationReceiptId: string;
    activationApprovalId: string;
    previousBindingId: string | null;
  }>;
}

export interface PrepareFinalizationOptions extends FinalizationStoreOptions {
  readonly auditRoot: string;
  readonly evidencePath: string;
  readonly now?: () => string;
}

export interface PrepareFinalizationTransactionOptions extends FinalizationStoreOptions {
  readonly auditRoot: string;
  readonly evidence: FinalizationPrepareEvidence;
  readonly evidencePath?: string;
  readonly now?: () => string;
}

interface FinalizationTransitionBase extends FinalizationStoreOptions {
  readonly transactionId: string;
  readonly now?: () => string;
}

export type TransitionFinalizationLifecycleOptions = FinalizationTransitionBase & (
  | Readonly<{
    expectedState: "PREPARED";
    nextState: "PROFILE_GATES_EVALUATED";
    evidence: Readonly<{
      kind: "PROFILE_GATES_EVALUATED";
      gateResultsDigest: Sha256Digest;
      capabilitiesDigest: Sha256Digest;
      profileApplicabilityDigest: Sha256Digest;
    }>;
  }>
  | Readonly<{
    expectedState: "PROFILE_GATES_EVALUATED";
    nextState: "ACTIVATION_PENDING";
    evidence: Readonly<{
      kind: "ACTIVATION_PENDING";
      receiptId: string;
      approvalId: string;
      productionSourcesDigest: Sha256Digest;
    }>;
  }>
  | Readonly<{
    expectedState: "ACTIVATION_PENDING";
    nextState: "POST_ACTIVATION_VERIFIED";
    evidence: Readonly<{
      kind: "POST_ACTIVATION_VERIFIED";
      receiptId: string;
      postActivationEvidenceDigest: Sha256Digest;
    }>;
  }>
  | Readonly<{
    expectedState: "POST_ACTIVATION_VERIFIED";
    nextState: "DRAINING";
    evidence: Readonly<{
      kind: "DRAINING";
      receiptId: string;
      previousBindingId: string | null;
    }>;
  }>
  | Readonly<{
    expectedState: Exclude<
      FinalizationState,
      "DRAFT" | "FAILED" | "UNKNOWN" | "BASE_PROFILE_FINAL_PASS"
    >;
    nextState: "FAILED";
    evidence: Readonly<{
      kind: "FINALIZATION_FAILED";
      reasonCode: string;
      evidenceDigest: Sha256Digest;
    }>;
  }>
  | Readonly<{
    expectedState: Exclude<
      FinalizationState,
      "DRAFT" | "FAILED" | "UNKNOWN" | "BASE_PROFILE_FINAL_PASS"
    >;
    nextState: "UNKNOWN";
    evidence: Readonly<{
      kind: "FINALIZATION_UNKNOWN";
      reasonCode: string;
      evidenceDigest: Sha256Digest;
    }>;
  }>
);

export interface FinalizationTransitionResult {
  readonly status: FinalizationState;
  readonly resumed: boolean;
  readonly storeIdentity: FinalizationStoreIdentity;
}

export interface FinalizationSealEvidence {
  readonly schemaVersion: 1;
  readonly status: "PASS";
  readonly phase: "post-activation";
  readonly runtimeIdentity: FinalizationRuntimeIdentity;
  readonly toolNames: readonly string[];
  readonly assurance: "COOPERATIVE_AUTHORITY";
  readonly transactionId: string;
  readonly snapshotGroupDigest: Sha256Digest;
  readonly immutableIdentityDigest: Sha256Digest;
  readonly productionSourcesDigest: Sha256Digest;
  readonly gateResultsDigest: Sha256Digest;
  readonly capabilitiesDigest: Sha256Digest;
  readonly profileApplicabilityDigest: Sha256Digest;
}

export interface SealFinalizationOptions extends FinalizationStoreOptions {
  readonly auditRoot: string;
  readonly evidencePath: string;
  readonly driverPath: string;
}

export interface FinalizationFinalRecord {
  readonly schemaVersion: 1;
  readonly status: "BASE_PROFILE_FINAL_PASS";
  readonly productProfile: "BASE_SINGLE_OWNER";
  readonly assurance: "COOPERATIVE_AUTHORITY";
  readonly sourceRevision: string;
  readonly runtimeIdentity: FinalizationRuntimeIdentity;
  readonly immutableIdentity: FinalizationImmutableIdentity;
  readonly releasePackage: string;
  readonly releaseManifestSha256: Sha256Digest;
  readonly sealedFinalizationStoreIdentity: FinalizationStoreIdentity & Readonly<{ state: "SEALED" }>;
  readonly prepareDigest: Sha256Digest;
  readonly sealInputDigest: Sha256Digest;
  readonly snapshotGroupDigest: Sha256Digest;
  readonly preparedGateResultsDigest: Sha256Digest;
  readonly preparedCapabilitiesDigest: Sha256Digest;
  readonly gateResults: readonly FinalizationFinalGateResult[];
  readonly gateResultsDigest: Sha256Digest;
  readonly capabilities: readonly FinalizationFinalCapabilityResult[];
  readonly capabilitiesDigest: Sha256Digest;
  readonly profileApplicabilityDigest: Sha256Digest;
  readonly tokenFamilyId: string;
  readonly connectorBindingId: string;
  readonly connectorDrainEpoch: number;
  readonly connectorActivationReceiptId: string;
  readonly connectorActivationOwnerAuthorityId: string;
  readonly postActivationHostCanaryEvidenceDigest: Sha256Digest;
  readonly canonicalFinalReadbackDigest: Sha256Digest;
  readonly retiredConnectorReceipts: readonly Readonly<{
    bindingId: string;
    retirementReceiptId: string;
    retirementReason: "REFERENCE_ZERO" | "DEADLINE_ELAPSED";
  }>[];
  readonly completedStages: readonly string[];
  readonly completedAt: string;
  readonly checksum: Sha256Digest;
}

export interface FinalizationFinalReadback extends Readonly<Record<string, unknown>> {
  readonly complete: true;
  readonly productionSourcesDigest: Sha256Digest;
  readonly runtimeIdentity: FinalizationRuntimeIdentity;
  readonly postActivationHostCanaryReceipt:
    SignedConnectorActivationEvidence<ConnectorActivationPostActivationHostCanaryPayload>;
  readonly verifiedPostActivationHostCanary: VerifiedConnectorActivationPostActivationHostCanary;
}

export interface TrustedFinalizationReadback extends Readonly<Record<string, unknown>> {
  readonly runtimeIdentity: FinalizationRuntimeIdentity;
  readonly verifiedPostActivationHostCanary: VerifiedConnectorActivationPostActivationHostCanary;
}

export function initializeFinalizationStore(
  options: InitializeFinalizationStoreOptions,
): FinalizationStoreIdentity;

export function readFinalizationStoreIdentity(
  options: FinalizationStoreOptions,
): FinalizationStoreIdentity;

export function prepareFinalization(options: PrepareFinalizationOptions): FinalizationPrepareResult;

export function prepareFinalizationTransaction(
  options: PrepareFinalizationTransactionOptions,
): FinalizationPrepareResult;

export function transitionFinalizationLifecycle(
  options: TransitionFinalizationLifecycleOptions,
): FinalizationTransitionResult;

export function sealFinalization(options: SealFinalizationOptions): FinalizationFinalRecord;

export function verifyFinalizationDirectory(finalizationRoot: string): FinalizationFinalRecord;

export function validateFinalReadbackEvidence(
  prepare: FinalizationPreparedRecord,
  sealEvidence: FinalizationSealEvidence,
  value: FinalizationFinalReadback,
): TrustedFinalizationReadback;
