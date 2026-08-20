import { createHash, createHmac, timingSafeEqual } from "node:crypto";
import { isAbsolute, normalize } from "node:path";

const DIGEST = /^sha256:[a-f0-9]{64}$/u;
const SIGNATURE = /^[A-Za-z0-9_-]{43}$/u;
const NONCE = /^[A-Za-z0-9_-]{43}$/u;
const SAFE_ID = /^[A-Za-z0-9][A-Za-z0-9._:@/-]{0,511}$/u;
const ENVELOPE_KEYS = ["keyId", "kind", "payload", "payloadDigest", "schemaVersion", "signature"];
const CHALLENGE_KEYS = [
  "actualHostRequired",
  "challengeId",
  "expiresAtMs",
  "hostProvider",
  "issuedAtMs",
  "managementCorrelationId",
  "nonce",
  "previousMainMigrationIdentityDigest",
  "previousRuntimeIdentityDigest",
  "receiptPath",
  "transactionId",
];
const RECEIPT_KEYS = [
  "actualHost",
  "challengeId",
  "challengePayloadDigest",
  "expiresAtMs",
  "healthReadbackDigest",
  "hostProvider",
  "managementCorrelationId",
  "nonce",
  "observedAtMs",
  "previousMainMigrationIdentityDigest",
  "previousRuntimeIdentityDigest",
  "readyReadbackDigest",
  "runtimeReadbackDigest",
  "sessionAIdDigest",
  "sessionBIdDigest",
  "transactionId",
];
const CHALLENGE_EXPECTED_KEYS = [
  "previousMainMigrationIdentityDigest",
  "previousRuntimeIdentityDigest",
  "receiptPath",
  "transactionId",
];
const RECEIPT_EXPECTED_KEYS = [
  "healthReadbackDigest",
  "previousMainMigrationIdentityDigest",
  "previousRuntimeIdentityDigest",
  "readyReadbackDigest",
  "receiptPath",
  "runtimeReadbackDigest",
  "transactionId",
];
const HEALTH_READBACK_KEYS = [
  "challengeId",
  "httpStatus",
  "managementCorrelationId",
  "nonce",
  "transactionId",
];
const READY_READBACK_KEYS = [
  "challengeId",
  "httpStatus",
  "managementCorrelationId",
  "nonce",
  "runtimeIdentityDigest",
  "transactionId",
];
const RUNTIME_READBACK_KEYS = [
  "challengeId",
  "cwd",
  "mainMigrationIdentityDigest",
  "managementCorrelationId",
  "nonce",
  "processName",
  "processStatus",
  "runtimeIdentityDigest",
  "script",
  "transactionId",
];
const MAX_CHALLENGE_LIFETIME_MS = 30 * 60_000;
const MAX_RECEIPT_LIFETIME_MS = 2 * 60_000;

/** Return the one canonical byte representation used by every rollback digest and HMAC. */
export function canonicalizeConnectorRollbackEvidence(value) {
  return JSON.stringify(canonical(value));
}

export function connectorRollbackEvidenceDigest(value) {
  return sha256(canonicalizeConnectorRollbackEvidence(value));
}

export function connectorRollbackHealthReadbackDigest(input) {
  return httpReadbackDigest(
    "ROLLBACK_HEALTH_READBACK_BINDING",
    input,
    HEALTH_READBACK_KEYS,
  );
}

export function connectorRollbackReadyReadbackDigest(input) {
  const value = httpReadbackBinding(
    "ROLLBACK_READY_READBACK_BINDING",
    input,
    READY_READBACK_KEYS,
  );
  requiredDigest(value.runtimeIdentityDigest, "rollback ready runtime identity");
  return connectorRollbackEvidenceDigest({
    schemaVersion: 1,
    kind: "ROLLBACK_READY_READBACK_BINDING",
    ...value,
  });
}

export function connectorRollbackRuntimeReadbackDigest(input) {
  const value = clonePlain(input);
  assertExactKeys(value, RUNTIME_READBACK_KEYS, "rollback runtime readback binding");
  validateReadbackChallengeBinding(value, "rollback runtime readback binding");
  requiredSafeId(value.processName, "rollback runtime processName");
  if (value.processStatus !== "online") {
    throw new Error("Rollback runtime processStatus must be online.");
  }
  requiredCanonicalAbsolutePath(value.cwd, "rollback runtime cwd");
  requiredCanonicalAbsolutePath(value.script, "rollback runtime script");
  requiredDigest(value.runtimeIdentityDigest, "rollback runtime identity");
  requiredDigest(value.mainMigrationIdentityDigest, "rollback runtime migration identity");
  return connectorRollbackEvidenceDigest({
    schemaVersion: 1,
    kind: "ROLLBACK_RUNTIME_READBACK_BINDING",
    ...value,
  });
}

export function signConnectorRollbackHostChallenge(payloadInput, key, nowMs = Date.now()) {
  const payload = clonePlain(payloadInput);
  validateChallenge(payload, nowMs);
  return sign("ROLLBACK_HOST_CHALLENGE", payload, key);
}

export function verifyConnectorRollbackHostChallenge(envelope, key, expected, nowMs = Date.now()) {
  const payload = verify("ROLLBACK_HOST_CHALLENGE", envelope, key);
  validateChallenge(payload, nowMs);
  validateExpected(expected, CHALLENGE_EXPECTED_KEYS, "rollback challenge expected binding");
  assertChallengeExpected(payload, expected);
  return deepFreeze({ ...payload, signedPayloadDigest: envelope.payloadDigest });
}

export function signConnectorRollbackHostReceipt(payloadInput, key, challengeEnvelope, expected, nowMs = Date.now()) {
  validateExpected(expected, RECEIPT_EXPECTED_KEYS, "rollback receipt expected binding");
  const challenge = verifyConnectorRollbackHostChallenge(
    challengeEnvelope,
    key,
    challengeExpectedBinding(expected),
    nowMs,
  );
  const payload = clonePlain(payloadInput);
  validateReceipt(payload, challenge, nowMs);
  assertReceiptExpected(payload, expected);
  return sign("ROLLBACK_HOST_RECEIPT", payload, key);
}

export function verifyConnectorRollbackHostReceipt(envelope, key, challengeEnvelope, expected, nowMs = Date.now()) {
  validateExpected(expected, RECEIPT_EXPECTED_KEYS, "rollback receipt expected binding");
  const challenge = verifyConnectorRollbackHostChallenge(
    challengeEnvelope,
    key,
    challengeExpectedBinding(expected),
    nowMs,
  );
  const payload = verify("ROLLBACK_HOST_RECEIPT", envelope, key);
  validateReceipt(payload, challenge, nowMs);
  assertReceiptExpected(payload, expected);
  return deepFreeze({ ...payload, signedPayloadDigest: envelope.payloadDigest });
}

function sign(kind, payload, key) {
  validateKey(key);
  const base = deepFreeze({ schemaVersion: 1, kind, keyId: key.keyId, payload: deepFreeze(payload) });
  const canonicalBase = canonicalizeConnectorRollbackEvidence(base);
  return deepFreeze({
    ...base,
    payloadDigest: sha256(canonicalBase),
    signature: createHmac("sha256", key.secret)
      .update(signatureDomain(kind))
      .update(canonicalBase)
      .digest("base64url"),
  });
}

function verify(kind, envelope, key) {
  validateKey(key);
  assertExactKeys(envelope, ENVELOPE_KEYS, "rollback evidence envelope");
  if (envelope.schemaVersion !== 1 || envelope.kind !== kind || envelope.keyId !== key.keyId) {
    throw new Error("Rollback evidence envelope identity is invalid.");
  }
  requiredDigest(envelope.payloadDigest, "rollback payloadDigest");
  if (typeof envelope.signature !== "string" || !SIGNATURE.test(envelope.signature)) {
    throw new Error("Rollback evidence signature is invalid.");
  }
  const canonicalBase = canonicalizeConnectorRollbackEvidence({
    schemaVersion: envelope.schemaVersion,
    kind: envelope.kind,
    keyId: envelope.keyId,
    payload: envelope.payload,
  });
  const observed = Buffer.from(envelope.signature, "base64url");
  const expectedSignature = createHmac("sha256", key.secret)
    .update(signatureDomain(kind))
    .update(canonicalBase)
    .digest();
  if (observed.toString("base64url") !== envelope.signature
    || envelope.payloadDigest !== sha256(canonicalBase)
    || observed.length !== expectedSignature.length
    || !timingSafeEqual(observed, expectedSignature)) {
    throw new Error("Rollback evidence signature verification failed.");
  }
  return clonePlain(envelope.payload);
}

function signatureDomain(kind) {
  return `devspace.connector-rollback-evidence.v1/${kind}\0`;
}

function validateChallenge(payload, nowMs) {
  assertExactKeys(payload, CHALLENGE_KEYS, "ROLLBACK_HOST_CHALLENGE payload");
  if (payload.hostProvider !== "chatgpt" || payload.actualHostRequired !== true) {
    throw new Error("Rollback challenge must require the actual ChatGPT Host boundary.");
  }
  requiredSafeId(payload.challengeId, "rollback challengeId");
  requiredSafeId(payload.transactionId, "rollback transactionId");
  requiredSafeId(payload.managementCorrelationId, "rollback managementCorrelationId");
  if (typeof payload.nonce !== "string" || !NONCE.test(payload.nonce)) {
    throw new Error("Rollback challenge nonce must be one canonical 256-bit value.");
  }
  requiredDigest(payload.previousRuntimeIdentityDigest, "previous runtime identity");
  requiredDigest(payload.previousMainMigrationIdentityDigest, "previous main migration identity");
  requiredAbsolutePath(payload.receiptPath, "rollback receiptPath");
  validateLifetime(payload.issuedAtMs, payload.expiresAtMs, nowMs, MAX_CHALLENGE_LIFETIME_MS, "rollback challenge");
}

function validateReceipt(payload, challenge, nowMs) {
  assertExactKeys(payload, RECEIPT_KEYS, "ROLLBACK_HOST_RECEIPT payload");
  if (payload.hostProvider !== "chatgpt" || payload.actualHost !== true) {
    throw new Error("Rollback receipt must identify the actual ChatGPT Host boundary.");
  }
  requiredDigest(payload.challengePayloadDigest, "rollback challenge payload digest");
  requiredDigest(payload.runtimeReadbackDigest, "rollback runtime readback digest");
  requiredDigest(payload.healthReadbackDigest, "rollback health readback digest");
  requiredDigest(payload.readyReadbackDigest, "rollback ready readback digest");
  requiredDigest(payload.sessionAIdDigest, "rollback session A identity");
  requiredDigest(payload.sessionBIdDigest, "rollback session B identity");
  if (payload.sessionAIdDigest === payload.sessionBIdDigest) {
    throw new Error("Rollback actual-Host receipt requires two distinct ChatGPT sessions.");
  }
  if (payload.challengeId !== challenge.challengeId
    || payload.challengePayloadDigest !== challenge.signedPayloadDigest
    || payload.transactionId !== challenge.transactionId
    || payload.nonce !== challenge.nonce
    || payload.managementCorrelationId !== challenge.managementCorrelationId
    || payload.previousRuntimeIdentityDigest !== challenge.previousRuntimeIdentityDigest
    || payload.previousMainMigrationIdentityDigest !== challenge.previousMainMigrationIdentityDigest) {
    throw new Error("Rollback receipt does not bind the exact signed challenge.");
  }
  validateLifetime(payload.observedAtMs, payload.expiresAtMs, nowMs, MAX_RECEIPT_LIFETIME_MS, "rollback receipt");
  if (payload.observedAtMs < challenge.issuedAtMs || payload.expiresAtMs > challenge.expiresAtMs) {
    throw new Error("Rollback receipt lifetime is outside its signed challenge.");
  }
}

function validateExpected(expected, keys, label) {
  assertExactKeys(expected, keys, label);
  requiredSafeId(expected.transactionId, `${label} transactionId`);
  requiredDigest(expected.previousRuntimeIdentityDigest, `${label} previous runtime identity`);
  requiredDigest(expected.previousMainMigrationIdentityDigest, `${label} previous main migration identity`);
  requiredAbsolutePath(expected.receiptPath, `${label} receiptPath`);
  if (keys === RECEIPT_EXPECTED_KEYS) {
    requiredDigest(expected.runtimeReadbackDigest, `${label} runtime readback`);
    requiredDigest(expected.healthReadbackDigest, `${label} health readback`);
    requiredDigest(expected.readyReadbackDigest, `${label} ready readback`);
  }
}

function assertChallengeExpected(payload, expected) {
  if (payload.transactionId !== expected.transactionId
    || payload.previousRuntimeIdentityDigest !== expected.previousRuntimeIdentityDigest
    || payload.previousMainMigrationIdentityDigest !== expected.previousMainMigrationIdentityDigest
    || payload.receiptPath !== expected.receiptPath) {
    throw new Error("Rollback challenge does not match the trusted transaction preimage binding.");
  }
}

function assertReceiptExpected(payload, expected) {
  if (payload.runtimeReadbackDigest !== expected.runtimeReadbackDigest
    || payload.healthReadbackDigest !== expected.healthReadbackDigest
    || payload.readyReadbackDigest !== expected.readyReadbackDigest) {
    throw new Error("Rollback receipt does not match trusted runtime, health, and ready readback bindings.");
  }
}

function challengeExpectedBinding(expected) {
  return {
    transactionId: expected.transactionId,
    previousRuntimeIdentityDigest: expected.previousRuntimeIdentityDigest,
    previousMainMigrationIdentityDigest: expected.previousMainMigrationIdentityDigest,
    receiptPath: expected.receiptPath,
  };
}

function httpReadbackDigest(kind, input, keys) {
  const value = httpReadbackBinding(kind, input, keys);
  return connectorRollbackEvidenceDigest({ schemaVersion: 1, kind, ...value });
}

function httpReadbackBinding(kind, input, keys) {
  const value = clonePlain(input);
  assertExactKeys(value, keys, `${kind} input`);
  validateReadbackChallengeBinding(value, kind);
  if (!Number.isSafeInteger(value.httpStatus) || value.httpStatus < 100 || value.httpStatus > 599) {
    throw new Error(`${kind} httpStatus is invalid.`);
  }
  return value;
}

function validateReadbackChallengeBinding(value, label) {
  requiredSafeId(value.challengeId, `${label} challengeId`);
  requiredSafeId(value.transactionId, `${label} transactionId`);
  requiredSafeId(value.managementCorrelationId, `${label} managementCorrelationId`);
  if (typeof value.nonce !== "string" || !NONCE.test(value.nonce)) {
    throw new Error(`${label} nonce must be one canonical 256-bit value.`);
  }
}

function validateLifetime(issuedAtMs, expiresAtMs, nowMs, maximumMs, label) {
  requiredTimestamp(issuedAtMs, `${label} issued/observed time`);
  requiredTimestamp(expiresAtMs, `${label} expiry`);
  requiredTimestamp(nowMs, "verification time");
  if (expiresAtMs <= issuedAtMs || expiresAtMs - issuedAtMs > maximumMs
    || nowMs < issuedAtMs || nowMs > expiresAtMs) {
    throw new Error(`${label} is not currently valid or exceeds its maximum lifetime.`);
  }
}

function validateKey(key) {
  if (!key || typeof key !== "object" || typeof key.keyId !== "string"
    || key.keyId.length < 1 || key.keyId.length > 256
    || !(key.secret instanceof Uint8Array) || key.secret.byteLength !== 32) {
    throw new Error("Rollback evidence requires one valid management authorization key.");
  }
}

function requiredDigest(value, label) {
  if (typeof value !== "string" || !DIGEST.test(value)) throw new Error(`${label} is invalid.`);
}

function requiredTimestamp(value, label) {
  if (!Number.isSafeInteger(value) || value < 0) throw new Error(`${label} is invalid.`);
}

function requiredSafeId(value, label) {
  if (typeof value !== "string" || !SAFE_ID.test(value)) throw new Error(`${label} is invalid.`);
}

function requiredAbsolutePath(value, label) {
  if (typeof value !== "string" || value.length < 2 || value.length > 4_096
    || /[\0\r\n]/u.test(value) || !isAbsolute(value)) {
    throw new Error(`${label} must be one absolute path.`);
  }
}

function requiredCanonicalAbsolutePath(value, label) {
  requiredAbsolutePath(value, label);
  if (normalize(value) !== value) throw new Error(`${label} must be normalized.`);
}

function assertExactKeys(value, expected, label) {
  if (!isPlainObject(value)) throw new Error(`${label} must be one plain object.`);
  const observed = Object.keys(value).sort();
  const wanted = [...expected].sort();
  if (observed.length !== wanted.length || observed.some((key, index) => key !== wanted[index])) {
    throw new Error(`${label} has unexpected or missing fields.`);
  }
}

function isPlainObject(value) {
  if (!value || typeof value !== "object" || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function canonical(value) {
  if (Array.isArray(value)) return value.map(canonical);
  if (isPlainObject(value)) {
    return Object.fromEntries(
      Object.entries(value)
        .sort(([left], [right]) => (left < right ? -1 : left > right ? 1 : 0))
        .map(([key, child]) => [key, canonical(child)]),
    );
  }
  if (value === null || typeof value === "string" || typeof value === "boolean") return value;
  if (typeof value === "number" && Number.isFinite(value)) return value;
  throw new Error("Rollback evidence must contain only finite canonical JSON values.");
}

function clonePlain(value) {
  return JSON.parse(canonicalizeConnectorRollbackEvidence(value));
}

function deepFreeze(value) {
  if (value && typeof value === "object" && !Object.isFrozen(value)) {
    for (const child of Object.values(value)) deepFreeze(child);
    Object.freeze(value);
  }
  return value;
}

function sha256(value) {
  return `sha256:${createHash("sha256").update(value).digest("hex")}`;
}
