export type Sha256Digest = `sha256:${string}`;
export type HmacSha256Tag = `hmac-sha256:${string}`;

export interface FinalizationManagementKey {
  readonly keyId: `management-${string}`;
  readonly secret: Uint8Array;
  readonly path?: string;
}

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

export const FINALIZATION_STORE_ID: "lifecycle-finalization-store";
export const FINALIZATION_STORE_SCHEMA_VERSION: 2;
export const FINALIZATION_STORE_MIGRATION_NAME: "lifecycle-finalization-authenticated-event-ledger";
export const FINALIZATION_STORE_MIGRATION_MODULE: "scripts/lib/finalization-store-contract.mjs";
export const FINALIZATION_STORE_TABLES: readonly ["finalization_anchor", "finalization_events"];
export const FINALIZATION_STORE_INDEXES: readonly ["finalization_events_transaction_idx"];
export const FINALIZATION_STORE_TRIGGERS: readonly string[];
export const FINALIZATION_STORE_DDL: readonly string[];
export const FINALIZATION_STORE_MIGRATION_CHECKSUM: Sha256Digest;
export const FINALIZATION_STORE_SCHEMA_FINGERPRINT: Sha256Digest;
export const FINALIZATION_STORE_MIGRATION: Readonly<{
  storeId: "lifecycle-finalization-store";
  version: 2;
  name: "lifecycle-finalization-authenticated-event-ledger";
  checksum: Sha256Digest;
  module: "scripts/lib/finalization-store-contract.mjs";
}>;

export interface FinalizationStoreIdentity {
  readonly storeId: "lifecycle-finalization-store";
  readonly path: string;
  readonly schemaVersion: 2;
  readonly schemaFingerprint: Sha256Digest;
  readonly migration: typeof FINALIZATION_STORE_MIGRATION;
  readonly keyId: string;
  readonly state: FinalizationState;
  readonly revision: number;
  readonly transactionId: string | null;
  readonly inputDigest: Sha256Digest | null;
  readonly prepareDigest: Sha256Digest | null;
  readonly requestBindingDigest?: Sha256Digest | null;
  readonly candidateIdentityDigest?: Sha256Digest | null;
  readonly snapshotGroupDigest?: Sha256Digest | null;
  readonly snapshotCapturedAt?: string | null;
  readonly preparedAt?: string | null;
  readonly sealInputDigest: Sha256Digest | null;
  readonly finalDigest: Sha256Digest | null;
  readonly contentGeneration: Sha256Digest;
  readonly integrity: "ok";
  readonly foreignKeyViolations: 0;
  readonly createdAt: string;
  readonly updatedAt: string;
  readonly controlEpoch?: number;
  readonly controlTag?: HmacSha256Tag;
  readonly preSnapshotIdentity?: Readonly<Record<string, unknown>>;
  readonly preSnapshotIdentityDigest?: Sha256Digest;
}

export interface FinalizationStoreEvent<T = Readonly<Record<string, unknown>>> {
  readonly sequence: number;
  readonly transactionId: string;
  readonly fromState: FinalizationState;
  readonly toState: Exclude<FinalizationState, "DRAFT">;
  readonly kind: string;
  readonly payloadJson: string;
  readonly payloadDigest: Sha256Digest;
  readonly occurredAt: string;
  readonly previousTransitionTag: HmacSha256Tag;
  readonly eventTag: HmacSha256Tag;
  readonly transitionTag: HmacSha256Tag;
  readonly finalTag: HmacSha256Tag | null;
  readonly payload: T;
}

export interface FinalizationStoreLedger {
  readonly identity: FinalizationStoreIdentity;
  readonly anchor: Readonly<{
    keyId: string;
    anchorNonce: string;
    createdAt: string;
    anchorTag: HmacSha256Tag;
  }>;
  readonly events: readonly FinalizationStoreEvent[];
}

export interface FinalizationStoreAccessOptions {
  readonly storePath: string;
  readonly controlPath: string;
  readonly key: FinalizationManagementKey;
}

export interface FinalizationStoreBootstrapAuthorization {
  readonly schemaVersion: 2;
  readonly operation: "OWNER_AUTHORIZED_R2_BOOTSTRAP";
  readonly storeId: "lifecycle-finalization-store";
  readonly recoveryClass: "R2";
  readonly storePath: string;
  readonly controlPath: string;
  readonly keyId: string;
  readonly approvedAt: string;
  readonly expiresAt: string;
  readonly authorizationId: string;
  readonly authorizationTag: HmacSha256Tag;
}

export interface InitializeFinalizationStoreOptions extends FinalizationStoreAccessOptions {
  readonly now?: () => string;
  readonly requireDraft?: boolean;
  readonly bootstrapAuthorization?: FinalizationStoreBootstrapAuthorization;
}

export function createFinalizationStoreBootstrapAuthorization(options: Readonly<{
  storePath: string;
  controlPath: string;
  key: FinalizationManagementKey;
  approvedAt?: string;
  expiresAt?: string;
  now?: () => string;
}>): FinalizationStoreBootstrapAuthorization;
export function bootstrapFinalizationStore(options: InitializeFinalizationStoreOptions): FinalizationStoreIdentity;
export function initializeFinalizationStore(options: InitializeFinalizationStoreOptions): FinalizationStoreIdentity;
export function readFinalizationStoreIdentity(options: FinalizationStoreAccessOptions): FinalizationStoreIdentity;
export function readFinalizationStoreLedger(options: FinalizationStoreAccessOptions): FinalizationStoreLedger;
export function readFinalizationStoreSnapshotIdentity(options: Readonly<{
  snapshotPath: string;
  key: FinalizationManagementKey;
}>): FinalizationStoreIdentity;
export function assertImmutableFinalizationExecution(options: Readonly<{
  releaseRoot: string;
  modulePath: string;
  expectedModulePath: string;
  manifestSha256: Sha256Digest;
  checksumsSha256: Sha256Digest;
}>): Readonly<{
  releaseRoot: string;
  modulePath: string;
  moduleRelativePath: string;
  manifestSha256: Sha256Digest;
  checksumsSha256: Sha256Digest;
  closureDigest: Sha256Digest;
  manifest: Readonly<Record<string, unknown>>;
}>;

export interface PreparedFinalizationCommitOptions extends FinalizationStoreAccessOptions {
  readonly transactionId?: string;
  readonly record: Readonly<Record<string, unknown>>;
  readonly now?: () => string;
}

export interface FinalizationTransitionCommitOptions extends FinalizationStoreAccessOptions {
  readonly transactionId: string;
  readonly now?: () => string;
}

export interface PostActivationProof {
  readonly schemaVersion: 1;
  readonly kind: "POST_ACTIVATION_VERIFIED_PROOF";
  readonly activatedAt: string;
  readonly activationReceiptId: string;
  readonly postActivationEvidenceDigest: Sha256Digest;
  readonly gateResult: Readonly<Record<string, unknown>>;
  readonly readback: Readonly<Record<string, unknown>>;
}

export interface CanonicalFinalizationSealProof {
  readonly schemaVersion: 1;
  readonly kind: "FINALIZATION_SEAL_PROOF";
  readonly sealedAt: string;
  readonly sealInputDigest: Sha256Digest;
  readonly finalArtifactsDigest: Sha256Digest;
  readonly finalGateResultsDigest: Sha256Digest;
  readonly residueEvidenceDigest: Sha256Digest;
  readonly finalGateResults: readonly Readonly<Record<string, unknown>>[];
  readonly residueEvidence: Readonly<Record<string, unknown>>;
}

export interface BaseProfileFinalPassProof {
  readonly schemaVersion: 1;
  readonly kind: "BASE_PROFILE_FINAL_PASS_PROOF";
  readonly completedAt: string;
  readonly finalDigest: Sha256Digest;
  readonly finalManifestDigest: Sha256Digest;
  readonly finalReportDigest: Sha256Digest;
  readonly finalManifest: Readonly<Record<string, unknown>>;
  readonly finalReport: Readonly<Record<string, unknown>>;
}

export interface FinalizationProofArtifactReference {
  readonly path: string;
  readonly sha256: Sha256Digest;
}

export function commitPreparedFinalization(options: PreparedFinalizationCommitOptions): Readonly<{
  resumed: boolean;
  identity: FinalizationStoreIdentity;
  record: Readonly<Record<string, unknown>>;
}>;
export function commitProfileGatesEvaluated(options: FinalizationTransitionCommitOptions & Readonly<{
  evaluation?: Readonly<Record<string, unknown>>;
}>): Promise<Readonly<{
  resumed: boolean;
  identity: FinalizationStoreIdentity;
  evaluation: Readonly<Record<string, unknown>>;
}>>;
export function commitActivationPending(options: FinalizationTransitionCommitOptions & Readonly<{
  activationBinding?: Readonly<{ approvalId: string; receiptId: string }>;
}>): Readonly<{
  resumed: boolean;
  identity: FinalizationStoreIdentity;
  binding: Readonly<Record<string, unknown>>;
}>;
export function commitPostActivationVerified(options: FinalizationTransitionCommitOptions & Readonly<{
  postActivationProofArtifact: FinalizationProofArtifactReference;
}>): Readonly<{
  resumed: boolean;
  identity: FinalizationStoreIdentity;
  binding: Readonly<Record<string, unknown>>;
}>;
export function commitDraining(options: FinalizationTransitionCommitOptions): Readonly<{
  resumed: boolean;
  identity: FinalizationStoreIdentity;
  binding: Readonly<Record<string, unknown>>;
}>;
export function commitCanonicalFinalizationSeal(options: FinalizationTransitionCommitOptions & Readonly<{
  sealProofArtifact: FinalizationProofArtifactReference;
}>): Readonly<{
  resumed: boolean;
  identity: FinalizationStoreIdentity;
  seal: Readonly<Record<string, unknown>>;
}>;
export function commitBaseProfileFinalPass(options: FinalizationTransitionCommitOptions & Readonly<{
  finalPassProofArtifact: FinalizationProofArtifactReference;
}>): Readonly<{
  resumed: boolean;
  identity: FinalizationStoreIdentity;
  finalPass: Readonly<Record<string, unknown>>;
}>;
export function commitFinalizationError(options: FinalizationTransitionCommitOptions & Readonly<{
  terminalState: "FAILED" | "UNKNOWN";
  reasonCode: string;
  evidencePath: string;
}>): Readonly<{
  resumed: boolean;
  identity: FinalizationStoreIdentity;
}>;
export function requestFinalizationStoreRollback(options: FinalizationStoreAccessOptions & Readonly<{
  transactionId: string;
  requestBindingDigest: Sha256Digest;
  candidateIdentityDigest: Sha256Digest;
  snapshotManifestPath: string;
  snapshotManifestSha256: Sha256Digest;
  rollbackJournalPath: string;
  rollbackJournalSha256: Sha256Digest;
  workerClaimPath: string;
  workerClaimSha256: Sha256Digest;
  now?: () => string;
}>): Readonly<{
  resumed: boolean;
  controlEpoch: number;
  authorization: Readonly<Record<string, unknown>>;
}>;
export function verifyFinalizationStoreRollback(options: FinalizationStoreAccessOptions & Readonly<{
  transactionId: string;
  requestBindingDigest: Sha256Digest;
  candidateIdentityDigest: Sha256Digest;
  snapshotManifestPath: string;
  snapshotManifestSha256: Sha256Digest;
  rollbackJournalPath: string;
  rollbackJournalSha256: Sha256Digest;
  workerClaimPath: string;
  workerClaimSha256: Sha256Digest;
  restoreEvidencePath: string;
  restoreEvidenceSha256: Sha256Digest;
  now?: () => string;
}>): Readonly<{
  resumed: boolean;
  identity: FinalizationStoreIdentity;
  authorization: Readonly<Record<string, unknown>>;
}>;
export function recoverFinalizationStoreControl(options: FinalizationStoreAccessOptions & Readonly<{
  now?: () => string;
}>): Readonly<{
  recoveredLockKind: string;
  identity: FinalizationStoreIdentity;
}>;
