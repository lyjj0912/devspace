export type Sha256Digest = `sha256:${string}`;
export type GateProducerKeyId = `gate-producer-ed25519-sha256:${string}`;

export const BASE_PROFILE_GATE_PRODUCER_SCHEMA_VERSION: 1;
export const BASE_PROFILE_GATE_PRODUCER_PUBLIC_KEY_PATH: "evidence/base-profile-gates/GATE-PRODUCER-PUBLIC-KEY.json";
export const BASE_PROFILE_PRECUTOVER_LEDGER_PATH: "evidence/base-profile-gates/PRE-CUTOVER-GATE-LEDGER.json";

export interface BaseProfileGateProducerBindings {
  readonly sourceRevision: string;
  readonly buildDigest: Sha256Digest;
  readonly schemaGeneration: Sha256Digest;
  readonly authorityContractGeneration: Sha256Digest;
  readonly buildCapabilityManifestDigest: Sha256Digest;
  readonly generatedSchemaDigest: Sha256Digest;
  readonly migrationManifestDigest: Sha256Digest;
}

export interface BaseProfileGateProducerManifestBinding {
  readonly schemaVersion: 1;
  readonly keyId: GateProducerKeyId;
  readonly publicKeySha256: Sha256Digest;
  readonly publicKeyPath: typeof BASE_PROFILE_GATE_PRODUCER_PUBLIC_KEY_PATH;
  readonly preCutoverLedgerPath: typeof BASE_PROFILE_PRECUTOVER_LEDGER_PATH;
  readonly preCutoverLedgerSha256: Sha256Digest;
}

export interface CollectBaseProfilePreCutoverGateLedgerOptions {
  readonly sourceRoot: string;
  readonly packageRoot: string;
  readonly privateKeyPath: string;
  readonly sourceRevision: string;
  readonly bindings: BaseProfileGateProducerBindings;
}

export interface BaseProfilePreCutoverGateLedgerResult {
  readonly gateProducer: BaseProfileGateProducerManifestBinding;
  readonly ledgerPath: string;
  readonly ledger: Readonly<Record<string, unknown>>;
}

export function collectBaseProfilePreCutoverGateLedger(
  options: CollectBaseProfilePreCutoverGateLedgerOptions,
): BaseProfilePreCutoverGateLedgerResult;
