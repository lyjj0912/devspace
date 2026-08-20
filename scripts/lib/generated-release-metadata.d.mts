export interface GeneratedReleaseMetadataPayload {
  schemaVersion: 1;
  sourceRevision: string;
  buildDigest: string;
  schemaGeneration: string;
  authorityContractGeneration: string;
  configSchemaIdentity: string;
  runtimeClosureInputSha256: string;
  sourceTreeSha256: string;
  dependencyTreeSha256: string;
  collectorReceiptSha256: string;
  buildCapabilities: Record<string, unknown>;
  migrationManifest: Array<Record<string, unknown>>;
  migrationManifestDigest: string;
}

export interface GeneratedReleaseMetadataEnvelope {
  schemaVersion: 1;
  kind: "DEVSPACE_GENERATED_RELEASE_METADATA" | "DEVSPACE_GENERATED_RELEASE_METADATA_FIXTURE";
  keyId: string | null;
  payload: GeneratedReleaseMetadataPayload;
  payloadDigest: string;
  signature: string | null;
}

export const GENERATED_RELEASE_METADATA_PATH: "RELEASE-RUNTIME-METADATA.json";
export const GENERATED_RELEASE_METADATA_KIND: "DEVSPACE_GENERATED_RELEASE_METADATA";
export const GENERATED_RELEASE_METADATA_FIXTURE_KIND: "DEVSPACE_GENERATED_RELEASE_METADATA_FIXTURE";
export const GENERATED_RELEASE_METADATA_DOMAIN: "devspace.generated-release-metadata.v1";

export function generatedReleaseMetadataSigningBytes(keyId: string, payload: GeneratedReleaseMetadataPayload): Buffer;
export function encodeGeneratedReleaseMetadataEnvelope(value: GeneratedReleaseMetadataEnvelope): Buffer;
export function createUnsignedGeneratedReleaseMetadataFixture(payload: GeneratedReleaseMetadataPayload): Buffer;
export function createSignedGeneratedReleaseMetadata(
  payload: GeneratedReleaseMetadataPayload,
  privateKeyPath: string,
): Readonly<{
  bytes: Buffer;
  keyId: string;
  publicKeySha256: string;
  publicKeySpkiDerBase64: string;
}>;
export function parseGeneratedReleaseMetadata(
  bytes: Buffer,
  options?: {
    allowUnattestedFixture?: boolean;
    expectedProducer?: {
      keyId: string;
      publicKeySha256: string;
      publicKeySpkiDerBase64: string;
    };
  },
): Readonly<GeneratedReleaseMetadataEnvelope>;
