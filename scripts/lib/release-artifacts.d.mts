export interface VerifiedGateProducerTrustAnchor {
  readonly path: string;
  readonly sha256: `sha256:${string}`;
  readonly keyId: string;
  readonly ownerInstanceId: string;
  readonly environment: string;
  readonly createdAt: string;
  readonly anchorNonce: string;
  readonly gateProducer: Readonly<{
    keyId: string;
    publicKeySha256: `sha256:${string}`;
  }>;
}

export function verifyGateProducerTrustAnchor(options: Readonly<{
  path: string;
  sha256: `sha256:${string}`;
  key: Readonly<{ keyId: string; secret: Uint8Array }>;
  expectedOwnerInstanceId: string;
  expectedEnvironment: string;
}>): VerifiedGateProducerTrustAnchor;

export function inspectVerifiedReleaseGateLedger(packageRoot: string, options: Readonly<{
  gateProducerTrustAnchor: VerifiedGateProducerTrustAnchor;
  expectedSourceRevision?: string;
  expectedRuntimeRevision?: string;
}>): Readonly<{
  release: Readonly<Record<string, unknown>> & { status: string; manifestSha256: string; buildDigest: string };
  manifest: Readonly<Record<string, unknown>>;
  ledger: Readonly<{
    payloadDigest: `sha256:${string}`;
    payload: Readonly<{
      gateBindings: Readonly<Record<string, Readonly<Record<string, unknown>>>>;
      receipts: readonly Readonly<Record<string, unknown>>[];
    }>;
  }>;
  gateProducer: Readonly<{ keyId: string; publicKeySha256: `sha256:${string}` }>;
}>;

export function canonicalJson(value: unknown): string;
export function fileSha256(path: string): string;
