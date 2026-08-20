export interface ConnectorRollbackManagementKey {
  readonly keyId: string;
  readonly secret: Uint8Array;
  readonly path?: string;
}

export interface ConnectorRollbackHostChallengePayload {
  readonly challengeId: string;
  readonly transactionId: string;
  readonly nonce: string;
  readonly managementCorrelationId: string;
  readonly hostProvider: "chatgpt";
  readonly actualHostRequired: true;
  readonly previousRuntimeIdentityDigest: string;
  readonly previousMainMigrationIdentityDigest: string;
  readonly issuedAtMs: number;
  readonly expiresAtMs: number;
  readonly receiptPath: string;
}

export interface ConnectorRollbackHostReceiptPayload {
  readonly challengeId: string;
  readonly challengePayloadDigest: string;
  readonly transactionId: string;
  readonly nonce: string;
  readonly managementCorrelationId: string;
  readonly hostProvider: "chatgpt";
  readonly actualHost: true;
  readonly previousRuntimeIdentityDigest: string;
  readonly previousMainMigrationIdentityDigest: string;
  readonly runtimeReadbackDigest: string;
  readonly healthReadbackDigest: string;
  readonly readyReadbackDigest: string;
  readonly sessionAIdDigest: string;
  readonly sessionBIdDigest: string;
  readonly observedAtMs: number;
  readonly expiresAtMs: number;
}

export interface ConnectorRollbackChallengeExpectedBinding {
  readonly transactionId: string;
  readonly previousRuntimeIdentityDigest: string;
  readonly previousMainMigrationIdentityDigest: string;
  readonly receiptPath: string;
}

export interface ConnectorRollbackReceiptExpectedBinding
  extends ConnectorRollbackChallengeExpectedBinding {
  readonly runtimeReadbackDigest: string;
  readonly healthReadbackDigest: string;
  readonly readyReadbackDigest: string;
}

/** @deprecated Prefer the operation-specific challenge/receipt binding types. */
export type ConnectorRollbackExpectedBinding = ConnectorRollbackChallengeExpectedBinding;

export interface ConnectorRollbackHealthReadbackBinding {
  readonly challengeId: string;
  readonly transactionId: string;
  readonly nonce: string;
  readonly managementCorrelationId: string;
  readonly httpStatus: number;
}

export interface ConnectorRollbackReadyReadbackBinding
  extends ConnectorRollbackHealthReadbackBinding {
  readonly runtimeIdentityDigest: string;
}

export interface ConnectorRollbackRuntimeReadbackBinding {
  readonly challengeId: string;
  readonly transactionId: string;
  readonly nonce: string;
  readonly managementCorrelationId: string;
  readonly processName: string;
  readonly processStatus: "online";
  readonly cwd: string;
  readonly script: string;
  readonly runtimeIdentityDigest: string;
  readonly mainMigrationIdentityDigest: string;
}

export type ConnectorRollbackEvidenceKind = "ROLLBACK_HOST_CHALLENGE" | "ROLLBACK_HOST_RECEIPT";

export interface SignedConnectorRollbackEvidence<
  T,
  K extends ConnectorRollbackEvidenceKind = ConnectorRollbackEvidenceKind,
> {
  readonly schemaVersion: 1;
  readonly kind: K;
  readonly keyId: string;
  readonly payload: Readonly<T>;
  readonly payloadDigest: string;
  readonly signature: string;
}

export type SignedConnectorRollbackHostChallenge = SignedConnectorRollbackEvidence<
  ConnectorRollbackHostChallengePayload,
  "ROLLBACK_HOST_CHALLENGE"
>;
export type SignedConnectorRollbackHostReceipt = SignedConnectorRollbackEvidence<
  ConnectorRollbackHostReceiptPayload,
  "ROLLBACK_HOST_RECEIPT"
>;
export type VerifiedConnectorRollbackHostChallenge = Readonly<ConnectorRollbackHostChallengePayload> & {
  readonly signedPayloadDigest: string;
};
export type VerifiedConnectorRollbackHostReceipt = Readonly<ConnectorRollbackHostReceiptPayload> & {
  readonly signedPayloadDigest: string;
};

export function canonicalizeConnectorRollbackEvidence(value: unknown): string;
export function connectorRollbackEvidenceDigest(value: unknown): string;
export function connectorRollbackHealthReadbackDigest(
  input: ConnectorRollbackHealthReadbackBinding,
): string;
export function connectorRollbackReadyReadbackDigest(
  input: ConnectorRollbackReadyReadbackBinding,
): string;
export function connectorRollbackRuntimeReadbackDigest(
  input: ConnectorRollbackRuntimeReadbackBinding,
): string;
export function signConnectorRollbackHostChallenge(
  payload: ConnectorRollbackHostChallengePayload,
  key: ConnectorRollbackManagementKey,
  nowMs?: number,
): SignedConnectorRollbackHostChallenge;
export function verifyConnectorRollbackHostChallenge(
  envelope: SignedConnectorRollbackHostChallenge,
  key: ConnectorRollbackManagementKey,
  expected: ConnectorRollbackChallengeExpectedBinding,
  nowMs?: number,
): VerifiedConnectorRollbackHostChallenge;
export function signConnectorRollbackHostReceipt(
  payload: ConnectorRollbackHostReceiptPayload,
  key: ConnectorRollbackManagementKey,
  challengeEnvelope: SignedConnectorRollbackHostChallenge,
  expected: ConnectorRollbackReceiptExpectedBinding,
  nowMs?: number,
): SignedConnectorRollbackHostReceipt;
export function verifyConnectorRollbackHostReceipt(
  envelope: SignedConnectorRollbackHostReceipt,
  key: ConnectorRollbackManagementKey,
  challengeEnvelope: SignedConnectorRollbackHostChallenge,
  expected: ConnectorRollbackReceiptExpectedBinding,
  nowMs?: number,
): VerifiedConnectorRollbackHostReceipt;
