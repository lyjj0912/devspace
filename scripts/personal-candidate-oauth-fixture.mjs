#!/usr/bin/env node
import { createHash, randomBytes, randomUUID } from "node:crypto";
import { chmod, lstat, mkdir, realpath, writeFile } from "node:fs/promises";
import { dirname, isAbsolute, resolve } from "node:path";
import {
  SqliteOAuthClientsStore,
  SqliteOAuthStore,
  connectorActivationAuthorityActionFingerprint,
  connectorActivationAuthorityResourceKeySha256,
} from "../dist/oauth-store.js";
import { UNIVERSAL_OWNER_SCOPES } from "../dist/v2/contracts.js";
import { RUNTIME_AUTHORITY_CONTRACT_GENERATION } from "../dist/v2/runtime-contract-identity.js";

const options = parseOptions(process.argv.slice(2));
const stateDir = await realDirectory(required(options, "state-dir"), "candidate OAuth state directory");
const tokenFile = absolute(required(options, "token-file"), "token file");
const evidenceFile = absolute(required(options, "evidence-file"), "evidence file");
await assertAbsent(tokenFile, "Candidate token file already exists");
await assertAbsent(evidenceFile, "Candidate evidence file already exists");
const canonicalName = required(options, "canonical-name");
const installationEpoch = positiveInteger(required(options, "installation-epoch"), "installation epoch");
const schemaGeneration = digestValue(required(options, "schema-generation"), "schema generation");
const resource = safeResource(required(options, "resource"));

const store = new SqliteOAuthStore(stateDir);
let evidence;
try {
  const before = store.personalConnectorReadiness({
    canonicalName,
    installationEpoch,
    schemaGeneration,
    resource,
  });
  const bindingCount = Object.values(before.bindingsByState).reduce((sum, count) => sum + count, 0);
  if (bindingCount !== 0 || before.activeFamilyCount !== 0 || before.unboundActiveFamilyCount !== 0) {
    throw new Error("Candidate OAuth fixture state is not empty.");
  }
  const clients = new SqliteOAuthClientsStore(store, ["127.0.0.1", "localhost"]);
  const client = clients.registerClient({
    redirect_uris: ["http://127.0.0.1/callback"],
    client_name: "DevSpace Personal isolated candidate gate",
    token_endpoint_auth_method: "none",
    grant_types: ["authorization_code", "refresh_token"],
    response_types: ["code"],
  });
  const candidateInput = {
    canonicalName,
    clientId: client.client_id,
    installationEpoch,
    schemaGeneration,
  };
  const candidate = store.ensureCandidateConnectorBinding(candidateInput);
  const tuple = {
    ...candidateInput,
    candidateBindingId: candidate.bindingId,
    authorityContractGeneration: RUNTIME_AUTHORITY_CONTRACT_GENERATION,
    redirectUrisDigest: digest("http://127.0.0.1/callback"),
    buildDigest: digest(`candidate:${schemaGeneration}`),
  };
  store.markConnectorBindingVerified(candidate.bindingId, {
    authorityContractGeneration: tuple.authorityContractGeneration,
    redirectUrisDigest: tuple.redirectUrisDigest,
    buildDigest: tuple.buildDigest,
  });
  const receipt = store.prepareConnectorActivation(tuple, {
    drainDeadlineAt: new Date(Date.now() + 60_000).toISOString(),
    refreshAllowedDuringDrain: false,
  });
  store.activatePreparedConnector(receipt.receiptId, tuple, activationProof(receipt));
  const active = store.getConnectorBinding(candidate.bindingId);
  if (!active || active.state !== "ACTIVE") throw new Error("Candidate connector did not become ACTIVE.");

  const accessToken = randomBytes(32).toString("base64url");
  const refreshToken = randomBytes(32).toString("base64url");
  const familyId = `candidate-family-${randomUUID()}`;
  const expiresAt = Math.floor(Date.now() / 1_000) + 60 * 60;
  const tokenRecord = {
    clientId: active.clientId,
    scopes: [...UNIVERSAL_OWNER_SCOPES],
    expiresAt,
    resource,
    familyId,
    connectorBindingId: active.bindingId,
    connectorDrainEpoch: active.drainEpoch,
    installationEpoch: active.installationEpoch,
    rotationSequence: 0,
  };
  const saved = store.saveTokenPair({
    accessTokenHash: hashToken(accessToken),
    accessToken: tokenRecord,
    refreshTokenHash: hashToken(refreshToken),
    refreshToken: tokenRecord,
  });
  if (!saved) throw new Error("Candidate OAuth token pair was not saved.");
  const readiness = store.personalConnectorReadiness({
    canonicalName,
    installationEpoch,
    schemaGeneration,
    resource,
  });
  if (readiness.state !== "PASS") {
    throw new Error(`Candidate connector readiness failed: ${readiness.invalidStates.join(", ")}`);
  }

  await writeExclusive(tokenFile, `${accessToken}\n`, 0o600);
  evidence = {
    schemaVersion: 1,
    kind: "PERSONAL_DIRECT_OWNER_ISOLATED_CANDIDATE_OAUTH_FIXTURE",
    status: "PASS",
    createdAt: new Date().toISOString(),
    stateDir,
    canonicalName,
    installationEpoch,
    schemaGeneration,
    resource,
    clientIdDigest: digest(active.clientId),
    bindingIdDigest: digest(active.bindingId),
    familyIdDigest: digest(familyId),
    accessTokenHash: hashToken(accessToken),
    refreshTokenHash: hashToken(refreshToken),
    scopes: tokenRecord.scopes,
    expiresAt,
    rotationSequence: 0,
    readiness,
  };
  await writeExclusive(evidenceFile, `${JSON.stringify(evidence, null, 2)}\n`, 0o600);
} finally {
  store.close();
}

process.stdout.write(`${JSON.stringify({
  status: evidence.status,
  evidenceFile,
  tokenFile,
  tokenFileMode: "600",
  canonicalName: evidence.canonicalName,
  installationEpoch: evidence.installationEpoch,
  schemaGeneration: evidence.schemaGeneration,
  resource: evidence.resource,
  clientIdDigest: evidence.clientIdDigest,
  bindingIdDigest: evidence.bindingIdDigest,
  familyIdDigest: evidence.familyIdDigest,
  accessTokenHash: evidence.accessTokenHash,
  rotationSequence: evidence.rotationSequence,
  readiness: evidence.readiness,
}, null, 2)}\n`);

function activationProof(receipt) {
  const binding = {
    receiptId: receipt.receiptId,
    tupleDigest: receipt.tupleDigest,
    activePreimageDigest: receipt.preimageDigest,
    finalizationPlanDigest: digest("personal-candidate-fixture-finalization"),
    canonicalName: receipt.tuple.canonicalName,
  };
  const claimedAtMs = Date.now();
  return {
    schemaVersion: 1,
    authorityId: `authority_${randomUUID()}`,
    actionClaimId: `authority_claim_${randomUUID()}`,
    actionFingerprint: connectorActivationAuthorityActionFingerprint(binding),
    resourceKeySha256: connectorActivationAuthorityResourceKeySha256(binding),
    fencingToken: receipt.tuple.installationEpoch,
    principalKeyFingerprint: createHash("sha256")
      .update("personal-isolated-candidate-owner")
      .digest("hex"),
    risk: "R3",
    claimState: "DISPATCHED",
    approvalAssurance: "cooperative",
    ...binding,
    evidenceDigest: digest("personal-isolated-candidate-oauth-fixture"),
    claimedAtMs,
    dispatchedAtMs: claimedAtMs + 1,
  };
}

function parseOptions(values) {
  const result = new Map();
  for (let index = 0; index < values.length; index += 2) {
    const key = values[index];
    const value = values[index + 1];
    if (!key?.startsWith("--") || value === undefined) throw new Error("Options must use --name value pairs.");
    result.set(key.slice(2), value);
  }
  return result;
}

function required(optionsMap, key) {
  const value = optionsMap.get(key);
  if (!value) throw new Error(`--${key} is required.`);
  return value;
}

async function realDirectory(value, label) {
  const path = await realpath(absolute(value, label));
  const metadata = await lstat(path);
  if (!metadata.isDirectory() || metadata.isSymbolicLink()) throw new Error(`${label} must be a real directory.`);
  return path;
}

function absolute(value, label) {
  if (!isAbsolute(value)) throw new Error(`${label} must be absolute.`);
  return resolve(value);
}

function positiveInteger(value, label) {
  const number = Number(value);
  if (!Number.isSafeInteger(number) || number <= 0) throw new Error(`${label} must be a positive integer.`);
  return number;
}

function digestValue(value, label) {
  if (!/^sha256:[a-f0-9]{64}$/u.test(value)) throw new Error(`${label} must be a SHA-256 digest.`);
  return value;
}

function safeResource(value) {
  const url = new URL(value);
  if (!/^https?:$/u.test(url.protocol) || url.username || url.password || url.hash) {
    throw new Error("Candidate OAuth resource is invalid.");
  }
  return url.href;
}

async function assertAbsent(path, message) {
  try { await lstat(path); } catch (error) {
    if (error && typeof error === "object" && "code" in error && error.code === "ENOENT") return;
    throw error;
  }
  throw new Error(`${message}: ${path}`);
}

async function writeExclusive(path, content, mode) {
  await mkdir(dirname(path), { recursive: true, mode: 0o700 });
  await writeFile(path, content, { encoding: "utf8", flag: "wx", mode });
  await chmod(path, mode);
}

function hashToken(token) {
  return createHash("sha256").update(token).digest("base64url");
}

function digest(value) {
  return `sha256:${createHash("sha256").update(value).digest("hex")}`;
}
