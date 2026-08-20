import {
  createHash,
  createPrivateKey,
  createPublicKey,
  sign,
  verify as verifySignature,
} from "node:crypto";
import { readFileSync } from "node:fs";

export const GENERATED_RELEASE_METADATA_PATH = "RELEASE-RUNTIME-METADATA.json";
export const GENERATED_RELEASE_METADATA_KIND = "DEVSPACE_GENERATED_RELEASE_METADATA";
export const GENERATED_RELEASE_METADATA_FIXTURE_KIND = "DEVSPACE_GENERATED_RELEASE_METADATA_FIXTURE";
export const GENERATED_RELEASE_METADATA_DOMAIN = "devspace.generated-release-metadata.v1";

const DIGEST_PATTERN = /^sha256:[a-f0-9]{64}$/u;
const KEY_ID_PATTERN = /^gate-producer-ed25519-sha256:[a-f0-9]{64}$/u;
const ENVELOPE_KEYS = Object.freeze([
  "keyId",
  "kind",
  "payload",
  "payloadDigest",
  "schemaVersion",
  "signature",
]);
const PAYLOAD_KEYS = Object.freeze([
  "authorityContractGeneration",
  "buildCapabilities",
  "buildDigest",
  "collectorReceiptSha256",
  "configSchemaIdentity",
  "dependencyTreeSha256",
  "migrationManifest",
  "migrationManifestDigest",
  "runtimeClosureInputSha256",
  "schemaGeneration",
  "schemaVersion",
  "sourceRevision",
  "sourceTreeSha256",
]);

export function generatedReleaseMetadataSigningBytes(keyId, payload) {
  requireKeyId(keyId);
  const normalized = normalizePayload(payload);
  const unsigned = {
    schemaVersion: 1,
    kind: GENERATED_RELEASE_METADATA_KIND,
    keyId,
    payload: normalized,
    payloadDigest: digestJson(normalized),
  };
  return Buffer.from(`${GENERATED_RELEASE_METADATA_DOMAIN}/${GENERATED_RELEASE_METADATA_KIND}\0${canonicalJson(unsigned)}`);
}

export function encodeGeneratedReleaseMetadataEnvelope(value) {
  const envelope = normalizeEnvelope(value);
  return Buffer.from(`${canonicalJson(envelope)}\n`);
}

export function createUnsignedGeneratedReleaseMetadataFixture(payload) {
  const normalized = normalizePayload(payload);
  return encodeGeneratedReleaseMetadataEnvelope({
    schemaVersion: 1,
    kind: GENERATED_RELEASE_METADATA_FIXTURE_KIND,
    keyId: null,
    payload: normalized,
    payloadDigest: digestJson(normalized),
    signature: null,
  });
}

export function createSignedGeneratedReleaseMetadata(payload, privateKeyPath) {
  let privateKey;
  try { privateKey = createPrivateKey(readFileSync(privateKeyPath)); }
  catch { throw new Error("Generated release metadata private key is unreadable or invalid."); }
  if (privateKey.asymmetricKeyType !== "ed25519") {
    throw new Error("Generated release metadata private key must be Ed25519.");
  }
  const publicKey = createPublicKey(privateKey);
  const publicDer = publicKey.export({ format: "der", type: "spki" });
  const publicKeySha256 = `sha256:${createHash("sha256").update(publicDer).digest("hex")}`;
  const keyId = `gate-producer-ed25519-sha256:${publicKeySha256.slice("sha256:".length)}`;
  const normalized = normalizePayload(payload);
  const signature = sign(null, generatedReleaseMetadataSigningBytes(keyId, normalized), privateKey).toString("base64url");
  const bytes = encodeGeneratedReleaseMetadataEnvelope({
    schemaVersion: 1,
    kind: GENERATED_RELEASE_METADATA_KIND,
    keyId,
    payload: normalized,
    payloadDigest: digestJson(normalized),
    signature,
  });
  return Object.freeze({
    bytes,
    keyId,
    publicKeySha256,
    publicKeySpkiDerBase64: publicDer.toString("base64"),
  });
}

export function parseGeneratedReleaseMetadata(bytes, options = {}) {
  if (!Buffer.isBuffer(bytes)) throw new Error("Generated release metadata must be supplied as captured bytes.");
  let value;
  try { value = JSON.parse(bytes.toString("utf8")); }
  catch { throw new Error("Generated release metadata is invalid JSON."); }
  const envelope = normalizeEnvelope(value);
  if (bytes.toString("utf8") !== `${canonicalJson(envelope)}\n`) {
    throw new Error("Generated release metadata is not canonical JSON.");
  }
  if (envelope.kind === GENERATED_RELEASE_METADATA_FIXTURE_KIND) {
    if (options.allowUnattestedFixture !== true || envelope.keyId !== null || envelope.signature !== null) {
      throw new Error("Unsigned generated release metadata is fixture-only and not release-eligible.");
    }
  } else {
    verifyTrustedEnvelope(envelope, options.expectedProducer);
  }
  return deepFreeze(envelope);
}

function normalizeEnvelope(value) {
  requireExactObject(value, ENVELOPE_KEYS, "generated release metadata envelope");
  if (value.schemaVersion !== 1
    || ![GENERATED_RELEASE_METADATA_KIND, GENERATED_RELEASE_METADATA_FIXTURE_KIND].includes(value.kind)
    || !DIGEST_PATTERN.test(value.payloadDigest ?? "")) {
    throw new Error("Generated release metadata envelope identity is invalid.");
  }
  const payload = normalizePayload(value.payload);
  if (value.payloadDigest !== digestJson(payload)) throw new Error("Generated release metadata payload digest differs.");
  if (value.kind === GENERATED_RELEASE_METADATA_KIND) {
    requireKeyId(value.keyId);
    if (typeof value.signature !== "string") throw new Error("Generated release metadata signature is missing.");
  } else if (value.keyId !== null || value.signature !== null) {
    throw new Error("Fixture generated release metadata must remain unsigned.");
  }
  return {
    schemaVersion: 1,
    kind: value.kind,
    keyId: value.keyId,
    payload,
    payloadDigest: value.payloadDigest,
    signature: value.signature,
  };
}

function normalizePayload(value) {
  requireExactObject(value, PAYLOAD_KEYS, "generated release metadata payload");
  if (value.schemaVersion !== 1) throw new Error("Generated release metadata payload version is invalid.");
  if (typeof value.sourceRevision !== "string" || !/^[A-Za-z0-9][A-Za-z0-9._:+/-]{6,255}$/u.test(value.sourceRevision)) {
    throw new Error("Generated release metadata source revision is invalid.");
  }
  for (const key of [
    "authorityContractGeneration",
    "buildDigest",
    "collectorReceiptSha256",
    "configSchemaIdentity",
    "dependencyTreeSha256",
    "migrationManifestDigest",
    "runtimeClosureInputSha256",
    "schemaGeneration",
    "sourceTreeSha256",
  ]) {
    if (!DIGEST_PATTERN.test(value[key] ?? "")) throw new Error(`Generated release metadata digest is invalid: ${key}`);
  }
  if (!value.buildCapabilities || typeof value.buildCapabilities !== "object" || Array.isArray(value.buildCapabilities)) {
    throw new Error("Generated release metadata build capabilities are invalid.");
  }
  if (!Array.isArray(value.migrationManifest) || value.migrationManifest.length === 0) {
    throw new Error("Generated release metadata migration manifest is invalid.");
  }
  return JSON.parse(JSON.stringify(value));
}

function verifyTrustedEnvelope(envelope, expectedProducer) {
  requireExactObject(expectedProducer, ["keyId", "publicKeySha256", "publicKeySpkiDerBase64"], "trusted generated metadata producer");
  requireKeyId(expectedProducer.keyId);
  if (!DIGEST_PATTERN.test(expectedProducer.publicKeySha256 ?? "")
    || expectedProducer.keyId.slice("gate-producer-ed25519-sha256:".length)
      !== expectedProducer.publicKeySha256.slice("sha256:".length)
    || envelope.keyId !== expectedProducer.keyId) {
    throw new Error("Generated release metadata producer differs from the trusted identity.");
  }
  let publicDer;
  try { publicDer = Buffer.from(expectedProducer.publicKeySpkiDerBase64, "base64"); }
  catch { throw new Error("Generated release metadata producer public key is invalid."); }
  if (publicDer.toString("base64") !== expectedProducer.publicKeySpkiDerBase64
    || `sha256:${createHash("sha256").update(publicDer).digest("hex")}` !== expectedProducer.publicKeySha256) {
    throw new Error("Generated release metadata producer public key digest differs.");
  }
  let publicKey;
  try { publicKey = createPublicKey({ key: publicDer, format: "der", type: "spki" }); }
  catch { throw new Error("Generated release metadata producer public key is not canonical SPKI DER."); }
  if (publicKey.asymmetricKeyType !== "ed25519") throw new Error("Generated release metadata producer key is not Ed25519.");
  let signature;
  try { signature = Buffer.from(envelope.signature, "base64url"); }
  catch { throw new Error("Generated release metadata signature is invalid."); }
  if (signature.length !== 64 || signature.toString("base64url") !== envelope.signature) {
    throw new Error("Generated release metadata signature is noncanonical.");
  }
  const message = generatedReleaseMetadataSigningBytes(envelope.keyId, envelope.payload);
  if (!verifySignature(null, message, publicKey, signature)) {
    throw new Error("Generated release metadata Ed25519 signature is invalid.");
  }
}

function requireExactObject(value, keys, label) {
  if (!value || typeof value !== "object" || Array.isArray(value)
    || canonicalJson(Object.keys(value).sort(compareAscii)) !== canonicalJson([...keys].sort(compareAscii))) {
    throw new Error(`${label} has missing or unsupported fields.`);
  }
}

function requireKeyId(value) {
  if (!KEY_ID_PATTERN.test(value ?? "")) throw new Error("Generated release metadata keyId is invalid.");
}

function digestJson(value) {
  return `sha256:${createHash("sha256").update(canonicalJson(value)).digest("hex")}`;
}

function canonicalJson(value) {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  return `{${Object.keys(value).sort(compareAscii).map((key) => `${JSON.stringify(key)}:${canonicalJson(value[key])}`).join(",")}}`;
}

function compareAscii(left, right) {
  return left < right ? -1 : left > right ? 1 : 0;
}

function deepFreeze(value) {
  if (value && typeof value === "object" && !Object.isFrozen(value)) {
    for (const child of Object.values(value)) deepFreeze(child);
    Object.freeze(value);
  }
  return value;
}
