import { spawnSync } from "node:child_process";
import { createHash, randomUUID } from "node:crypto";
import {
  chmodSync,
  closeSync,
  constants,
  fsyncSync,
  lstatSync,
  mkdirSync,
  openSync,
  readFileSync,
  readdirSync,
  realpathSync,
  renameSync,
  unlinkSync,
  writeFileSync,
} from "node:fs";
import { dirname, isAbsolute, join, relative, resolve, sep } from "node:path";
import { fileURLToPath } from "node:url";
import { DatabaseSync } from "node:sqlite";
import {
  assertImmutableFinalizationExecution,
  commitActivationPending,
  commitDraining,
  commitFinalizationError,
  commitPreparedFinalization,
  commitProfileGatesEvaluated,
  initializeFinalizationStore,
  readFinalizationStoreIdentity,
  readFinalizationStoreLedger,
  readFinalizationStoreSnapshotIdentity,
  FINALIZATION_STORE_ID,
  FINALIZATION_STORE_MIGRATION,
  FINALIZATION_STORE_MIGRATION_CHECKSUM,
  FINALIZATION_STORE_MIGRATION_NAME,
  FINALIZATION_STORE_SCHEMA_FINGERPRINT,
  FINALIZATION_STORE_SCHEMA_VERSION,
} from "./finalization-store-contract.mjs";
import { inspectBaseProfileGateEvidenceManifest } from "./base-profile-gate-evidence.mjs";
import { assertVerifiedConnectorActivationPostActivationHostCanary } from "../../dist/v2/connector-activation-evidence.js";
import {
  canonicalJson,
  fileSha256,
  verifyReleasePackage,
} from "./release-artifacts.mjs";

export {
  FINALIZATION_STORE_ID,
  FINALIZATION_STORE_MIGRATION,
  FINALIZATION_STORE_MIGRATION_CHECKSUM,
  FINALIZATION_STORE_MIGRATION_NAME,
  FINALIZATION_STORE_SCHEMA_FINGERPRINT,
  FINALIZATION_STORE_SCHEMA_VERSION,
  initializeFinalizationStore,
  readFinalizationStoreIdentity,
};

const THIS_STATE_PATH = realpathSync(fileURLToPath(import.meta.url));
const MODULE_RELEASE_ROOT = realpathSync(resolve(dirname(THIS_STATE_PATH), "../.."));
const REQUIRED_SNAPSHOT_ENTRIES = Object.freeze([
  "oauth-main-and-connector-state",
  "authority-store",
  "contexts-store",
  "process-metadata",
  "process-output",
  "filesystem-sync",
  "artifact-catalog",
  "artifact-cas",
  "artifact-quarantine",
  "pagination-current-signing-key",
  "lifecycle-finalization-store",
  "runtime-environment",
  "process-manager-definition",
  "process-manager-saved-state",
  "public-route",
  "target-route-generation-config",
]);
const GENERATED_SCHEMA_PATHS = Object.freeze([
  "config.schema.json",
  "config/config.schema.json",
  "contracts/tools-v2.schema.json",
  "contracts/build-capabilities.schema.json",
]);
const EXECUTABLE_NAMES = Object.freeze(["curl", "lsof", "node", "pm2", "tailscale"]);
const EXECUTABLE_VERSION_ARGUMENTS = Object.freeze({
  node: ["--version"],
  pm2: ["--version"],
  curl: ["--version"],
  lsof: ["-v"],
  tailscale: ["version"],
});
const ENVIRONMENT_KEYS = Object.freeze(["HOME", "LANG", "LC_ALL", "PM2_HOME", "TMPDIR"]);
const DIGEST_PATTERN = /^sha256:[a-f0-9]{64}$/u;
const TOOL_NAMES = Object.freeze(["target", "context", "fs", "exec", "process", "mcp", "artifact", "gui"]);

export function prepareFinalization(options) {
  const configuration = requiredObject(options, "prepareFinalization options");
  const evidencePath = canonicalOwnerOnlyFile(configuration.evidencePath, "finalization prepare evidence");
  const evidence = readJsonStable(evidencePath, "finalization prepare evidence");
  return prepareFinalizationTransaction({ ...configuration, evidence, evidencePath });
}

export function prepareFinalizationTransaction(options) {
  const configuration = requiredObject(options, "prepareFinalizationTransaction options");
  const auditRoot = canonicalAuditRoot(configuration.auditRoot);
  const storePath = requiredAbsolutePath(configuration.storePath, "finalization storePath");
  const controlPath = requiredAbsolutePath(configuration.controlPath, "finalization controlPath");
  if (pathsOverlap(auditRoot, storePath)) {
    throw new Error("Lifecycle finalization store must remain outside non-restored audit/control root.");
  }
  if (!isSameOrInside(auditRoot, controlPath) || controlPath === auditRoot || pathsOverlap(storePath, controlPath)) {
    throw new Error("Lifecycle finalization control must be inside rollback-preserved audit root and outside mutable stateRoot.");
  }
  const currentStore = readFinalizationStoreIdentity({ storePath, controlPath, key: configuration.key });
  if (currentStore.state !== "DRAFT") {
    const ledger = readFinalizationStoreLedger({ storePath, controlPath, key: configuration.key });
    const existing = ledger.events.find((event) => event.toState === "PREPARED")?.payload?.record;
    if (!existing) throw new Error(`Finalization store is not DRAFT/PREPARED: ${currentStore.state}`);
    const input = canonicalClone(configuration.evidence);
    if (existing.inputDigest !== digestJson(input)) {
      throw new Error("Prepared finalization replay differs from the exact durable input.");
    }
    mirrorPreparedRecord(auditRoot, existing);
    return prepareResult(existing, currentStore, true);
  }

  const evidence = validatePrepareInput(configuration.evidence);
  const upgradeRequestPath = canonicalOwnerOnlyFile(evidence.upgradeRequest.path, "production upgrade request");
  if (digestFile(upgradeRequestPath) !== evidence.upgradeRequest.sha256) {
    throw new Error("Production upgrade request bytes differ from finalization input binding.");
  }
  const upgradeRequest = readJsonStable(upgradeRequestPath, "production upgrade request");
  if (upgradeRequest.transactionId !== evidence.transactionId) {
    throw new Error("Production upgrade request transactionId differs from finalization input.");
  }
  const finalization = validateUpgradeFinalizationContract(upgradeRequest.finalization);
  if (finalization.releaseRoot !== MODULE_RELEASE_ROOT) {
    throw new Error("Finalization state module is not executing from the immutable upgrade release root.");
  }
  const moduleClosure = assertImmutableFinalizationExecution({
    releaseRoot: finalization.releaseRoot,
    modulePath: THIS_STATE_PATH,
    expectedModulePath: "scripts/lib/finalization-state.mjs",
    manifestSha256: finalization.releaseManifestSha256,
    checksumsSha256: finalization.releaseChecksumsSha256,
  });
  const release = verifyReleasePackage(finalization.releaseRoot, {
    expectedSourceRevision: evidence.runtimeIdentity.sourceRevision,
    expectedRuntimeRevision: evidence.runtimeIdentity.runtimeRevision,
  });
  validateRuntimeIdentity(evidence.runtimeIdentity, release);
  const immutableIdentity = deriveImmutableProductionIdentity(finalization.releaseRoot, evidence.runtimeIdentity);
  assertCanonicalEqual(evidence.immutableIdentity, immutableIdentity, "immutable production identity");
  const candidateIdentity = omitMigrationIdentity(immutableIdentity);
  const candidateIdentityDigest = digestJson(candidateIdentity);
  if (candidateIdentityDigest !== evidence.candidateIdentityDigest
    || upgradeRequest.candidateIdentityDigest !== evidence.candidateIdentityDigest) {
    throw new Error("Candidate identity digest differs across request/finalization/release identities.");
  }

  const snapshotGroup = validateSnapshotGroupBinding(evidence.snapshotGroup, {
    transactionId: evidence.transactionId,
    requestBindingDigest: evidence.requestBindingDigest,
    candidateIdentityDigest,
    deadline: finalization.snapshotDeadlineAt,
    storePath,
    key: configuration.key,
    currentStore,
  });
  for (const entry of Object.values(snapshotGroup.entriesById)) {
    if (pathsOverlap(controlPath, entry.path) || (entry.snapshotPath && pathsOverlap(controlPath, entry.snapshotPath))) {
      throw new Error(`Rollback-preserved finalization control overlaps snapshot/restore material: ${entry.id}`);
    }
  }
  const environment = validateExecutionEnvironment(finalization.environment);
  const executables = validateExecutables(finalization.executables, environment);
  const executableManifestDigest = digestJson(executables);
  const productionSources = validateProductionSources(finalization, snapshotGroup, {
    releaseRoot: finalization.releaseRoot,
    immutableIdentity,
    executables,
    environment,
  });
  const expectedBindings = {
    transactionId: evidence.transactionId,
    requestBindingDigest: evidence.requestBindingDigest,
    candidateIdentityDigest,
    releaseManifestSha256: finalization.releaseManifestSha256,
    runtimeIdentityDigest: digestJson(evidence.runtimeIdentity),
    buildDigest: immutableIdentity.buildDigest,
    schemaGeneration: immutableIdentity.schemaGeneration,
    authorityContractGeneration: immutableIdentity.authorityContractGeneration,
    buildCapabilityManifestDigest: immutableIdentity.buildCapabilityManifestDigest,
    generatedSchemaDigest: immutableIdentity.generatedSchemaDigest,
    packageSha256: immutableIdentity.packageSha256,
    migrationManifestDigest: immutableIdentity.migrationManifestDigest,
    executableManifestDigest,
  };
  const gateInspection = inspectBaseProfileGateEvidenceManifest({
    manifestPath: finalization.gateEvidence.manifestPath,
    manifestSha256: finalization.gateEvidence.manifestSha256,
    key: configuration.key,
    expectedBindings,
    releaseRoot: finalization.releaseRoot,
    requirePostCutoverAbsent: true,
  });
  const preparedAt = normalizedNow(configuration.now);
  if (Date.parse(preparedAt) <= Date.parse(snapshotGroup.manifest.capturedAt)
    || Date.parse(preparedAt) > Date.parse(finalization.snapshotDeadlineAt)) {
    throw new Error("PREPARED timestamp is outside the real snapshot completion/deadline interval.");
  }
  const destructivePlan = deriveDestructivePlan(finalization.cleanup, finalization.residue, auditRoot);
  const input = canonicalClone(evidence);
  const record = Object.freeze({
    schemaVersion: 2,
    state: "PREPARED",
    transactionId: evidence.transactionId,
    preparedAt,
    input,
    inputDigest: digestJson(input),
    sourceRevision: evidence.runtimeIdentity.sourceRevision,
    runtimeIdentity: evidence.runtimeIdentity,
    immutableIdentity,
    releasePackage: finalization.releaseRoot,
    releaseManifestSha256: finalization.releaseManifestSha256,
    releaseChecksumsSha256: finalization.releaseChecksumsSha256,
    moduleClosureDigest: moduleClosure.closureDigest,
    snapshotGroup,
    gateEvidence: {
      manifestPath: gateInspection.manifestPath,
      manifestSha256: gateInspection.manifestSha256,
      bindingDigest: gateInspection.bindingDigest,
      expectedBindings,
    },
    productionSources,
    destructivePlan,
    finalizationStore: currentStore,
  });
  const committed = commitPreparedFinalization({
    storePath,
    controlPath,
    key: configuration.key,
    record,
    now: () => preparedAt,
  });
  mirrorPreparedRecord(auditRoot, record);
  return prepareResult(record, committed.identity, committed.resumed);
}

export async function transitionFinalizationLifecycle(options) {
  const configuration = requiredObject(options, "transitionFinalizationLifecycle options");
  const common = {
    storePath: configuration.storePath,
    controlPath: configuration.controlPath,
    key: configuration.key,
    transactionId: configuration.transactionId,
    now: configuration.now,
  };
  const edge = `${configuration.expectedState}->${configuration.nextState}`;
  switch (edge) {
    case "PREPARED->PROFILE_GATES_EVALUATED":
      return transitionResult(await commitProfileGatesEvaluated(common));
    case "PROFILE_GATES_EVALUATED->ACTIVATION_PENDING":
      return transitionResult(commitActivationPending(common));
    case "ACTIVATION_PENDING->POST_ACTIVATION_VERIFIED": {
      const contract = await import("./finalization-store-contract.mjs");
      if (typeof contract.commitPostActivationVerified !== "function") {
        throw new Error("Canonical POST transition implementation is unavailable.");
      }
      return transitionResult(await contract.commitPostActivationVerified(common));
    }
    case "POST_ACTIVATION_VERIFIED->DRAINING":
      return transitionResult(commitDraining(common));
    default:
      if (["FAILED", "UNKNOWN"].includes(configuration.nextState)) {
        return transitionResult(commitFinalizationError({
          ...common,
          terminalState: configuration.nextState,
          reasonCode: configuration.reasonCode,
          evidencePath: configuration.evidencePath,
        }));
      }
      throw new Error(`Public lifecycle transition is unsupported or exceeds DRAINING: ${edge}`);
  }
}

export async function sealFinalization(options) {
  const contract = await import("./finalization-store-contract.mjs");
  if (typeof contract.commitCanonicalFinalizationSeal !== "function") {
    throw new Error("Canonical immutable finalization sealer is unavailable.");
  }
  return contract.commitCanonicalFinalizationSeal(options);
}

export async function verifyFinalizationDirectory(options) {
  const contract = await import("./finalization-store-contract.mjs");
  if (typeof contract.verifyFinalizationDirectory !== "function") {
    throw new Error("Canonical finalization directory verifier is unavailable.");
  }
  return contract.verifyFinalizationDirectory(options);
}

export function validateFinalReadbackEvidence(prepare, sealEvidence, value) {
  const prepared = requiredObject(prepare, "prepared finalization record");
  const seal = requiredObject(sealEvidence, "finalization seal evidence");
  const readback = requiredObject(value, "canonical final readback");
  assertExactKeys(readback, [
    "activationAuthorityReadback", "activeConnector", "activeTokenFamily", "complete",
    "connectorActivationReceipt", "connectorJournalReadback", "funnelInventoryDigest",
    "listenerReadback", "managementIdentity", "oauthReadback", "pm2Runtime",
    "postActivationHostCanaryReceipt", "postMutationAuthorityReadback", "productionSourcesDigest",
    "residueReadback", "retiredConnectors", "revokedTokenFamilyIds", "routeIdentity",
    "runtimeIdentity", "runtimeReadback", "stages", "verifiedPostActivationHostCanary",
  ], "canonical final readback");
  assertVerifiedConnectorActivationPostActivationHostCanary(readback.verifiedPostActivationHostCanary);
  if (readback.complete !== true) throw new Error("Canonical final readback is incomplete.");

  validateRuntimeIdentityShape(readback.runtimeIdentity);
  assertCanonicalEqual(readback.runtimeIdentity, prepared.runtimeIdentity, "canonical runtime readback");
  assertCanonicalEqual(seal.runtimeIdentity, prepared.runtimeIdentity, "seal runtime identity");
  if (seal.schemaVersion !== 1 || seal.status !== "PASS" || seal.phase !== "post-activation"
    || seal.assurance !== "COOPERATIVE_AUTHORITY" || seal.transactionId !== prepared.transactionId) {
    throw new Error("Finalization seal evidence identity is invalid.");
  }
  assertCanonicalEqual(seal.toolNames, TOOL_NAMES, "seal exact tool names");

  const expectedBindings = {
    snapshotGroupDigest: prepared.snapshotGroup?.manifest?.groupDigest ?? prepared.snapshotGroup?.manifestSha256,
    immutableIdentityDigest: digestJson(prepared.immutableIdentity),
    productionSourcesDigest: digestJson(prepared.productionSources),
    gateResultsDigest: digestJson(prepared.gateResults),
    capabilitiesDigest: digestJson(prepared.capabilities),
    profileApplicabilityDigest: digestJson(prepared.profileApplicability),
  };
  for (const [name, expected] of Object.entries(expectedBindings)) {
    requireDigest(expected, `prepared ${name}`);
    if (seal[name] !== expected) throw new Error(`Finalization seal ${name} differs from prepared evidence.`);
  }
  if (readback.productionSourcesDigest !== expectedBindings.productionSourcesDigest) {
    throw new Error("Canonical final readback production sources differ from prepared evidence.");
  }
  if (readback.runtimeReadback?.identityDigest !== digestJson(readback.runtimeIdentity)) {
    throw new Error("Canonical final readback runtime identity digest is invalid.");
  }
  assertCanonicalEqual(
    readback.residueReadback,
    { paths: prepared.productionSources.residue.paths, present: [] },
    "canonical residue readback",
  );
  if (readback.activeConnector?.bindingId !== prepared.canonicalConnector?.bindingId
    || readback.connectorActivationReceipt?.receiptId !== prepared.productionSources.activation.receiptId
    || readback.verifiedPostActivationHostCanary.activationReceiptId
      !== prepared.productionSources.activation.receiptId) {
    throw new Error("Canonical connector activation readback differs from prepared evidence.");
  }
  assertCompleteReadbackTree(readback);
  return Object.freeze(readback);
}

function validatePrepareInput(value) {
  const evidence = canonicalClone(requiredObject(value, "finalization prepare input"));
  assertExactKeys(evidence, [
    "candidateIdentityDigest", "immutableIdentity", "phase", "requestBindingDigest", "runtimeIdentity",
    "schemaVersion", "snapshotGroup", "status", "transactionId", "upgradeRequest",
  ], "finalization prepare input");
  if (evidence.schemaVersion !== 2 || evidence.status !== "SNAPSHOT_CAPTURED"
    || evidence.phase !== "production-reconnect") throw new Error("Finalization prepare input identity is invalid.");
  requiredTransactionId(evidence.transactionId);
  requireDigest(evidence.requestBindingDigest, "prepare requestBindingDigest");
  requireDigest(evidence.candidateIdentityDigest, "prepare candidateIdentityDigest");
  assertExactKeys(evidence.upgradeRequest, ["path", "sha256"], "prepare upgradeRequest binding");
  requiredAbsolutePath(evidence.upgradeRequest.path, "prepare upgrade request path");
  requireDigest(evidence.upgradeRequest.sha256, "prepare upgrade request sha256");
  assertExactKeys(evidence.snapshotGroup, ["manifestPath", "manifestSha256"], "prepare snapshot group binding");
  requiredAbsolutePath(evidence.snapshotGroup.manifestPath, "snapshot group manifestPath");
  requireDigest(evidence.snapshotGroup.manifestSha256, "snapshot group manifestSha256");
  validateRuntimeIdentityShape(evidence.runtimeIdentity);
  validateImmutableIdentityShape(evidence.immutableIdentity);
  return evidence;
}

function validateUpgradeFinalizationContract(value) {
  const contract = canonicalClone(requiredObject(value, "upgrade request finalization contract"));
  assertExactKeys(contract, [
    "activation", "cleanup", "endpoints", "environment", "executables", "gateEvidence", "listeners",
    "processManager", "releaseChecksumsSha256", "releaseManifestSha256", "releaseRoot", "residue",
    "route", "runtimeEnvironmentPath", "schemaVersion", "snapshotDeadlineAt", "stores",
  ], "upgrade request finalization contract");
  if (contract.schemaVersion !== 2) throw new Error("Upgrade request finalization contract version is unsupported.");
  contract.releaseRoot = canonicalRealDirectory(contract.releaseRoot, "upgrade immutable releaseRoot");
  requireDigest(contract.releaseManifestSha256, "upgrade releaseManifestSha256");
  requireDigest(contract.releaseChecksumsSha256, "upgrade releaseChecksumsSha256");
  requiredTimestamp(contract.snapshotDeadlineAt, "upgrade snapshotDeadlineAt");
  assertExactKeys(contract.gateEvidence, ["manifestPath", "manifestSha256"], "upgrade gateEvidence");
  requiredAbsolutePath(contract.gateEvidence.manifestPath, "upgrade gate manifestPath");
  requireDigest(contract.gateEvidence.manifestSha256, "upgrade gate manifestSha256");
  return contract;
}

function validateSnapshotGroupBinding(binding, expected) {
  const manifestPath = canonicalOwnerOnlyFile(binding.manifestPath, "snapshot group manifest");
  if (digestFile(manifestPath) !== binding.manifestSha256) throw new Error("Snapshot group manifest bytes changed.");
  const manifest = readJsonStable(manifestPath, "snapshot group manifest");
  assertExactKeys(manifest, ["barrier", "capturedAt", "entries", "groupDigest", "schemaVersion", "snapshotRoot"], "snapshot group manifest");
  if (manifest.schemaVersion !== 1 || !Array.isArray(manifest.entries) || manifest.entries.length < REQUIRED_SNAPSHOT_ENTRIES.length) {
    throw new Error("Snapshot group manifest shape is invalid.");
  }
  requiredTimestamp(manifest.capturedAt, "snapshot capturedAt");
  const snapshotRoot = canonicalOwnerOnlyDirectory(manifest.snapshotRoot, "snapshot group root", false);
  if (!isSameOrInside(snapshotRoot, manifestPath)) throw new Error("Snapshot manifest escapes snapshot root.");
  const unsigned = {
    schemaVersion: 1,
    capturedAt: manifest.capturedAt,
    snapshotRoot,
    barrier: manifest.barrier,
    entries: manifest.entries,
  };
  if (manifest.groupDigest !== digestJson(unsigned)) throw new Error("Snapshot group digest mismatch.");
  const barrier = requiredObject(manifest.barrier, "snapshot barrier");
  for (const key of ["transactionId", "requestBindingDigest", "candidateIdentityDigest", "stoppedAt", "establishedAt"]) {
    if (!Object.hasOwn(barrier, key)) throw new Error(`Snapshot barrier is missing ${key}.`);
  }
  if (barrier.transactionId !== expected.transactionId
    || barrier.requestBindingDigest !== expected.requestBindingDigest
    || barrier.candidateIdentityDigest !== expected.candidateIdentityDigest
    || barrier.stoppedAt !== barrier.establishedAt) {
    throw new Error("Snapshot barrier transaction/request/candidate/stop binding mismatch.");
  }
  requiredTimestamp(barrier.stoppedAt, "snapshot barrier stoppedAt");
  requiredTimestamp(barrier.establishedAt, "snapshot barrier establishedAt");
  const capturedAt = Date.parse(manifest.capturedAt);
  if (capturedAt < Date.parse(barrier.establishedAt) || capturedAt > Date.parse(expected.deadline)) {
    throw new Error("Snapshot capturedAt is outside the established barrier/request deadline interval.");
  }
  const byId = new Map();
  const byPath = new Set();
  for (const entry of manifest.entries) {
    if (!entry || typeof entry.id !== "string" || byId.has(entry.id)) throw new Error("Snapshot entries are invalid or duplicated.");
    byId.set(entry.id, entry);
    if (byPath.has(entry.path)) throw new Error("Snapshot entry source path is duplicated.");
    byPath.add(entry.path);
    validateSnapshotArtifact(entry, snapshotRoot);
  }
  for (const id of REQUIRED_SNAPSHOT_ENTRIES) {
    const entry = byId.get(id);
    if (!entry || entry.required !== true || entry.state !== "captured") throw new Error(`Required snapshot entry is missing or not captured: ${id}`);
  }
  const lifecycle = byId.get("lifecycle-finalization-store");
  if (lifecycle.kind !== "sqlite" || lifecycle.path !== expected.storePath) throw new Error("Lifecycle finalization snapshot entry path/kind is invalid.");
  const snapshotIdentity = readFinalizationStoreSnapshotIdentity({ snapshotPath: lifecycle.snapshotPath, key: expected.key });
  if (snapshotIdentity.state !== "DRAFT" || snapshotIdentity.contentGeneration !== expected.currentStore.contentGeneration
    || snapshotIdentity.keyId !== expected.currentStore.keyId) throw new Error("Snapshotted lifecycle finalization store is not the exact authenticated DRAFT identity.");
  return Object.freeze({ manifestPath, manifestSha256: binding.manifestSha256, manifest: canonicalClone(manifest), entriesById: Object.fromEntries(byId) });
}

function validateSnapshotArtifact(entry, snapshotRoot) {
  const expectedKeys = entry.kind === "directory"
    ? ["id", "kind", "mode", "path", "required", "snapshotPath", "state", "tree"]
    : ["bytes", "id", "kind", "mode", "path", "required", "sha256", "snapshotPath", "state"];
  if (Object.hasOwn(entry, "purpose")) expectedKeys.push("purpose");
  assertExactKeys(entry, expectedKeys, `snapshot entry ${entry.id}`);
  if (!["sqlite", "file", "directory"].includes(entry.kind) || entry.state !== "captured") throw new Error(`Snapshot entry kind/state is invalid: ${entry.id}`);
  requiredAbsolutePath(entry.path, `snapshot source ${entry.id}`);
  const snapshotPath = entry.kind === "directory"
    ? canonicalOwnerOnlyDirectory(entry.snapshotPath, `snapshot artifact ${entry.id}`, false)
    : canonicalOwnerOnlyFile(entry.snapshotPath, `snapshot artifact ${entry.id}`);
  if (!isSameOrInside(snapshotRoot, snapshotPath)) throw new Error(`Snapshot artifact escapes root: ${entry.id}`);
  if (entry.kind === "directory") {
    if (canonicalJson(snapshotTreeEvidence(snapshotPath)) !== canonicalJson(entry.tree)) throw new Error(`Snapshot directory tree digest changed: ${entry.id}`);
  } else if (`sha256:${fileSha256(snapshotPath)}` !== entry.sha256) {
    throw new Error(`Snapshot file digest changed: ${entry.id}`);
  }
}

function snapshotTreeEvidence(root) {
  const base = resolve(root);
  const digest = createHash("sha256");
  let files = 0;
  let directories = 0;
  let bytes = 0;
  const visit = (directory) => {
    const entries = readdirSync(directory, { withFileTypes: true }).sort((left, right) => compareCodeUnits(left.name, right.name));
    for (const entry of entries) {
      const path = join(directory, entry.name);
      const relativePath = relative(base, path).split(sep).join("/");
      const metadata = lstatSync(path);
      if (metadata.isSymbolicLink()) throw new Error(`Snapshot tree contains a symlink: ${path}`);
      if (metadata.isDirectory()) {
        directories += 1;
        digest.update("d\0"); digest.update(relativePath); digest.update("\0"); digest.update(String(metadata.mode & 0o777)); digest.update("\n");
        visit(path);
      } else if (metadata.isFile()) {
        files += 1;
        bytes += metadata.size;
        digest.update("f\0"); digest.update(relativePath); digest.update("\0"); digest.update(`sha256:${fileSha256(path)}`);
        digest.update("\0"); digest.update(String(metadata.mode & 0o777)); digest.update("\n");
      } else throw new Error(`Snapshot tree contains unsupported file type: ${path}`);
    }
  };
  visit(base);
  return { files, directories, bytes, sha256: `sha256:${digest.digest("hex")}` };
}

function validateExecutionEnvironment(value) {
  const input = canonicalClone(requiredObject(value, "finalization execution environment"));
  assertExactKeys(input, ENVIRONMENT_KEYS, "finalization execution environment");
  for (const key of ["HOME", "TMPDIR", "PM2_HOME"]) canonicalRealDirectory(input[key], `execution environment ${key}`);
  for (const key of ["LANG", "LC_ALL"]) {
    if (typeof input[key] !== "string" || !/^[A-Za-z0-9_.@-]{1,64}$/u.test(input[key])) throw new Error(`Execution environment ${key} is invalid.`);
  }
  return input;
}

function validateExecutables(value, environment) {
  const input = canonicalClone(requiredObject(value, "finalization executable manifest"));
  assertExactKeys(input, EXECUTABLE_NAMES, "finalization executable manifest");
  const output = {};
  for (const name of EXECUTABLE_NAMES) {
    const identity = input[name];
    assertExactKeys(identity, ["path", "sha256", "version"], `finalization executable ${name}`);
    const path = canonicalExecutable(identity.path, `finalization executable ${name}`);
    const sha256 = digestFile(path);
    if (sha256 !== identity.sha256) throw new Error(`Finalization executable digest changed: ${name}`);
    const sanitized = sanitizedEnvironment(environment, input);
    const result = spawnSync(path, EXECUTABLE_VERSION_ARGUMENTS[name], {
      env: sanitized,
      encoding: "utf8",
      shell: false,
      timeout: 10_000,
      maxBuffer: 1024 * 1024,
    });
    const observed = `${result.stdout ?? ""}\n${result.stderr ?? ""}`.split("\n").map((line) => line.trim()).find(Boolean) ?? "";
    if (result.error || result.status !== 0 || observed !== identity.version) {
      throw new Error(`Finalization executable version differs from immutable evidence: ${name}`);
    }
    if (name === "node" && (identity.version !== "v22.23.2" || realpathSync(process.execPath) !== path)) {
      throw new Error("Canonical finalization requires the executing Node v22.23.2 binary identity.");
    }
    output[name] = Object.freeze({ name, path, sha256, version: identity.version, versionArguments: EXECUTABLE_VERSION_ARGUMENTS[name] });
  }
  return Object.freeze(output);
}

function validateProductionSources(finalization, snapshotGroup, context) {
  const byId = new Map(Object.values(snapshotGroup.entriesById).map((entry) => [entry.id, entry]));
  const processManager = deriveProcessManager(finalization.processManager, byId, context.releaseRoot, finalization.runtimeEnvironmentPath);
  const endpoints = validateEndpoints(finalization.endpoints);
  const listeners = validateListeners(finalization.listeners);
  const route = validateRoute(finalization.route, byId);
  const stores = validateStores(finalization.stores);
  const activation = validateActivation(finalization.activation, context.immutableIdentity, stores);
  const residue = validateResidue(finalization.residue);
  return Object.freeze({
    schemaVersion: 2,
    moduleClosure: {
      releaseRoot: context.releaseRoot,
      manifestSha256: finalization.releaseManifestSha256,
      checksumsSha256: finalization.releaseChecksumsSha256,
    },
    executables: context.executables,
    environment: sanitizedEnvironment(context.environment, context.executables),
    processManager,
    endpoints,
    listeners,
    route,
    runtimeEnvironmentPath: canonicalSnapshottedSource(finalization.runtimeEnvironmentPath, byId.get("runtime-environment"), "runtime environment"),
    stores,
    activation,
    residue,
  });
}

function deriveProcessManager(value, entries, releaseRoot, runtimeEnvironmentPath) {
  const input = requiredObject(value, "processManager contract");
  assertExactKeys(input, ["canonicalProcessName", "definitionPath", "savedStatePath"], "processManager contract");
  const definitionPath = canonicalSnapshottedSource(input.definitionPath, entries.get("process-manager-definition"), "PM2 definition");
  const savedStatePath = canonicalSnapshottedSource(input.savedStatePath, entries.get("process-manager-saved-state"), "PM2 saved state");
  const definition = readJsonStable(entries.get("process-manager-definition").snapshotPath, "snapshotted PM2 definition");
  assertExactKeys(definition, ["apps"], "snapshotted PM2 definition");
  if (!Array.isArray(definition.apps) || definition.apps.length !== 1) throw new Error("Snapshotted PM2 definition must contain exactly one app and no unrelated definition.");
  const app = definition.apps[0];
  assertExactKeys(app, ["cwd", "env", "name", "script"], "snapshotted PM2 app definition");
  if (app.name !== input.canonicalProcessName) throw new Error("Snapshotted PM2 app name differs from canonical process name.");
  const cwd = canonicalRealDirectory(app.cwd, "snapshotted PM2 cwd");
  if (cwd !== releaseRoot) throw new Error("Snapshotted PM2 cwd differs from immutable release root.");
  const script = canonicalRealFile(isAbsolute(app.script) ? app.script : resolve(cwd, app.script), "snapshotted PM2 script");
  if (!isSameOrInside(releaseRoot, script)) throw new Error("Snapshotted PM2 script escapes immutable release root.");
  const requiredEnv = normalizeStringMap(app.env, "snapshotted PM2 env");
  const environmentFile = parseEnvironmentFile(canonicalSnapshottedSource(runtimeEnvironmentPath, entries.get("runtime-environment"), "runtime environment"));
  for (const [key, value] of Object.entries(requiredEnv)) {
    if (environmentFile[key] !== value) throw new Error(`PM2 required environment is absent from snapshotted runtime environment: ${key}`);
  }
  const saved = readJsonStable(entries.get("process-manager-saved-state").snapshotPath, "snapshotted PM2 saved state");
  if (!Array.isArray(saved) || saved.length !== 1) throw new Error("Snapshotted PM2 saved state must contain exactly one process.");
  const savedEnv = requiredObject(saved[0].pm2_env, "snapshotted PM2 saved env");
  if (saved[0].name !== app.name || realpathSync(savedEnv.pm_cwd) !== cwd || realpathSync(savedEnv.pm_exec_path) !== script) {
    throw new Error("Snapshotted PM2 saved state differs from definition name/cwd/script tuple.");
  }
  for (const [key, expected] of Object.entries(requiredEnv)) {
    if (String(savedEnv[key]) !== expected) throw new Error(`Snapshotted PM2 saved state lacks required env containment: ${key}`);
  }
  return Object.freeze({
    canonicalProcessName: app.name,
    definitionPath,
    definitionSha256: digestFile(definitionPath),
    savedStatePath,
    savedStateSha256: digestFile(savedStatePath),
    expectedProcess: { name: app.name, cwd, script, scriptSha256: digestFile(script), requiredEnv },
  });
}

function validateEndpoints(value) {
  const input = canonicalClone(requiredObject(value, "finalization endpoints"));
  assertExactKeys(input, ["managementIdentityDigest", "managementIdentityUrl", "routeIdentityUrl", "runtimeIdentityUrl"], "finalization endpoints");
  for (const key of ["managementIdentityUrl", "routeIdentityUrl", "runtimeIdentityUrl"]) requiredHttpUrl(input[key], `finalization endpoint ${key}`);
  requireDigest(input.managementIdentityDigest, "management identity digest");
  return input;
}

function validateListeners(value) {
  const input = canonicalClone(requiredObject(value, "finalization listeners"));
  assertExactKeys(input, ["expected", "scopePorts"], "finalization listeners");
  if (!Array.isArray(input.scopePorts) || input.scopePorts.length < 1 || new Set(input.scopePorts).size !== input.scopePorts.length
    || input.scopePorts.some((port) => !Number.isInteger(port) || port < 1 || port > 65535)) throw new Error("Finalization listener scope ports are invalid.");
  if (!Array.isArray(input.expected) || input.expected.length !== input.scopePorts.length) throw new Error("Finalization expected listener set is not exact.");
  input.expected.forEach((listener) => {
    assertExactKeys(listener, ["address", "command", "port"], "expected listener");
    if (!input.scopePorts.includes(listener.port) || typeof listener.address !== "string" || typeof listener.command !== "string") throw new Error("Expected listener tuple is invalid.");
  });
  input.expected.sort(compareListener);
  input.scopePorts.sort((left, right) => left - right);
  return input;
}

function validateRoute(value, entries) {
  const input = canonicalClone(requiredObject(value, "finalization route"));
  assertExactKeys(input, ["definitionPath", "expectedFunnelInventoryDigest", "publicRouteKey", "targetGenerationConfigPath"], "finalization route");
  const definitionPath = canonicalSnapshottedSource(input.definitionPath, entries.get("public-route"), "public route definition");
  const targetGenerationConfigPath = canonicalSnapshottedSource(input.targetGenerationConfigPath, entries.get("target-route-generation-config"), "target route generation config");
  requireDigest(input.expectedFunnelInventoryDigest, "expected funnel inventory digest");
  if (!/^https:\/\//u.test(input.publicRouteKey)) throw new Error("Finalization public route key must be HTTPS.");
  return { ...input, definitionPath, definitionSha256: digestFile(definitionPath), targetGenerationConfigPath, targetGenerationConfigSha256: digestFile(targetGenerationConfigPath) };
}

function validateStores(value) {
  const input = canonicalClone(requiredObject(value, "finalization stores"));
  assertExactKeys(input, ["authority", "connectorJournal", "oauth", "postActivationReceipt"], "finalization stores");
  const output = {};
  for (const name of ["oauth", "authority", "connectorJournal"]) {
    assertExactKeys(input[name], ["path", "schemaFingerprint", "userVersion"], `finalization store ${name}`);
    const observed = sqliteIdentity(canonicalOwnerOnlyFile(input[name].path, `finalization store ${name}`));
    if (observed.userVersion !== input[name].userVersion || observed.schemaFingerprint !== input[name].schemaFingerprint) throw new Error(`Finalization SQLite store identity drifted: ${name}`);
    output[name] = { path: input[name].path, ...observed };
  }
  assertExactKeys(input.postActivationReceipt, ["path"], "post activation receipt store");
  const postPath = canonicalProspectiveOwnerPath(input.postActivationReceipt.path, "post activation receipt");
  if (lstatIfPresent(postPath)) throw new Error("POST activation receipt path must be absent before activation, including dangling symlinks.");
  output.postActivationReceipt = { path: postPath };
  return Object.freeze(output);
}

function validateActivation(value, immutableIdentity, stores) {
  const input = canonicalClone(requiredObject(value, "finalization activation binding"));
  assertExactKeys(input, [
    "approvalId", "canonicalName", "managementCorrelationId", "managementNonce", "postActivationNotBefore",
    "previousBindingId", "previousBindingState", "principalKeyFingerprint", "productionActivationPrecheckDigest",
    "productionEnvironmentIdentityDigest", "productionIdentity", "productionRouteIdentityDigest", "receiptId",
    "tokenFamilyBindingId", "tokenFamilyIdDigest",
  ], "finalization activation binding");
  for (const key of ["productionActivationPrecheckDigest", "productionEnvironmentIdentityDigest", "productionRouteIdentityDigest", "tokenFamilyIdDigest"]) requireDigest(input[key], `activation ${key}`);
  requiredTimestamp(input.postActivationNotBefore, "activation postActivationNotBefore");
  if (!["DRAINING", "ABSENT"].includes(input.previousBindingState)
    || (input.previousBindingState === "DRAINING") !== (typeof input.previousBindingId === "string" && input.previousBindingId.length > 0)) throw new Error("Activation previous binding state/identity is invalid.");
  assertCanonicalEqual(input.productionIdentity, omitMigrationIdentity(immutableIdentity), "activation production identity");
  if (!stores.postActivationReceipt.path) throw new Error("Activation POST receipt prospective path is missing.");
  return input;
}

function validateResidue(value) {
  const input = canonicalClone(requiredObject(value, "finalization residue contract"));
  assertExactKeys(input, ["paths"], "finalization residue contract");
  if (!Array.isArray(input.paths) || new Set(input.paths).size !== input.paths.length) throw new Error("Finalization residue paths are invalid or duplicated.");
  input.paths = input.paths.map((path) => canonicalProspectiveOwnerPath(path, "finalization residue path")).sort(compareCodeUnits);
  return input;
}

function deriveDestructivePlan(cleanup, residue, auditRoot) {
  const input = canonicalClone(requiredObject(cleanup, "finalization cleanup contract"));
  assertExactKeys(input, ["stages"], "finalization cleanup contract");
  if (!Array.isArray(input.stages)) throw new Error("Finalization cleanup stages are invalid.");
  const ids = new Set();
  return Object.freeze(input.stages.map((stage) => {
    assertExactKeys(stage, ["id", "operation", "target"], "finalization cleanup stage");
    if (!/^[a-z][a-z0-9-]{1,127}$/u.test(stage.id) || ids.has(stage.id) || stage.operation !== "remove-file") throw new Error("Finalization cleanup stage id/operation is invalid.");
    ids.add(stage.id);
    const target = canonicalProspectiveOwnerPath(stage.target, "finalization cleanup target");
    if (!residue.paths.includes(target) || pathsOverlap(auditRoot, target)) throw new Error("Cleanup target is not one exact external residue path.");
    const parent = canonicalOwnerOnlyDirectory(dirname(target), "cleanup target parent");
    const parentState = lstatSync(parent, { bigint: true });
    const metadata = lstatIfPresent(target, true);
    if (metadata?.isSymbolicLink()) throw new Error("Cleanup target symlink/dangling symlink is residue but cannot be destructively trusted.");
    if (metadata && !metadata.isFile()) throw new Error("Cleanup target must be a regular file or absent.");
    return Object.freeze({
      id: stage.id,
      operation: "remove-file",
      target,
      parentIdentity: { path: parent, dev: String(parentState.dev), ino: String(parentState.ino) },
      preimage: metadata
        ? { state: "PRESENT", dev: String(metadata.dev), ino: String(metadata.ino), sha256: digestFile(target) }
        : { state: "ABSENT" },
    });
  }));
}

function deriveImmutableProductionIdentity(releaseRoot, runtimeIdentity) {
  const manifest = JSON.parse(readFileSync(join(releaseRoot, "BUILD-MANIFEST.json"), "utf8"));
  const schemas = generatedSchemaTreeEvidence(releaseRoot);
  const identity = {
    runtimeIdentityDigest: digestJson(runtimeIdentity),
    buildDigest: manifest.buildDigest,
    schemaGeneration: manifest.schemaGeneration,
    authorityContractGeneration: manifest.authorityContractGeneration,
    buildCapabilityManifestDigest: manifest.buildCapabilities?.capabilityDigest,
    generatedSchemaDigest: schemas,
    packageSha256: manifest.payloadDigest,
    migrationManifestDigest: manifest.migrationManifestDigest,
  };
  validateImmutableIdentityShape(identity);
  return Object.freeze(identity);
}

function generatedSchemaTreeEvidence(root) {
  const digest = createHash("sha256");
  for (const path of [...GENERATED_SCHEMA_PATHS].sort(compareCodeUnits)) {
    const absolute = canonicalRealFile(join(root, path), `generated schema ${path}`);
    digest.update(path); digest.update("\0"); digest.update(fileSha256(absolute)); digest.update("\n");
  }
  return `sha256:${digest.digest("hex")}`;
}

function validateRuntimeIdentity(value, release) {
  validateRuntimeIdentityShape(value);
  const expected = {
    sourceRevision: release.sourceRevision,
    runtimeRevision: release.runtimeRevision,
    buildDigest: release.buildDigest,
    schemaGeneration: release.schemaGeneration,
    authorityContractGeneration: release.authorityContractGeneration,
    configSchemaIdentity: release.configSchemaIdentity,
  };
  for (const [key, expectedValue] of Object.entries(expected)) {
    if (value[key] !== expectedValue) throw new Error(`Runtime identity differs from immutable release: ${key}`);
  }
}

function validateRuntimeIdentityShape(value) {
  const input = requiredObject(value, "runtimeIdentity");
  assertExactKeys(input, ["authorityContractGeneration", "buildDigest", "configDigest", "configSchemaIdentity", "runtimeRevision", "schemaGeneration", "sourceRevision"], "runtimeIdentity");
  for (const key of ["buildDigest", "schemaGeneration", "authorityContractGeneration", "configDigest", "configSchemaIdentity"]) requireDigest(input[key], `runtimeIdentity.${key}`);
  requiredText(input.sourceRevision, "runtimeIdentity.sourceRevision"); requiredText(input.runtimeRevision, "runtimeIdentity.runtimeRevision");
}

function validateImmutableIdentityShape(value) {
  const input = requiredObject(value, "immutableIdentity");
  assertExactKeys(input, ["authorityContractGeneration", "buildCapabilityManifestDigest", "buildDigest", "generatedSchemaDigest", "migrationManifestDigest", "packageSha256", "runtimeIdentityDigest", "schemaGeneration"], "immutableIdentity");
  for (const key of Object.keys(input)) requireDigest(input[key], `immutableIdentity.${key}`);
}

function canonicalSnapshottedSource(value, entry, label) {
  const path = canonicalOwnerOnlyFile(value, label);
  if (!entry || entry.required !== true || entry.state !== "captured" || entry.path !== path
    || entry.sha256 !== digestFile(path)) throw new Error(`${label} differs from exact snapshot source identity.`);
  return path;
}

function sqliteIdentity(path) {
  const database = new DatabaseSync(path, { readOnly: true });
  try {
    const integrity = firstColumn(database.prepare("pragma integrity_check").get());
    const foreignKeys = database.prepare("pragma foreign_key_check").all();
    if (integrity !== "ok" || foreignKeys.length !== 0) throw new Error(`SQLite identity is not healthy: ${path}`);
    const userVersion = Number(firstColumn(database.prepare("pragma user_version").get()));
    const schema = database.prepare("select type, name, tbl_name as tableName, sql from sqlite_master where name not like 'sqlite_%' order by type, name").all();
    return { userVersion, schemaFingerprint: digestJson({ userVersion, schema }) };
  } finally { database.close(); }
}

function parseEnvironmentFile(path) {
  const output = {};
  for (const line of readFileSync(path, "utf8").split("\n")) {
    if (!line || line.startsWith("#")) continue;
    const index = line.indexOf("=");
    if (index < 1) throw new Error("Runtime environment file contains a malformed entry.");
    const key = line.slice(0, index); const value = line.slice(index + 1);
    if (!/^[A-Z][A-Z0-9_]{0,127}$/u.test(key) || Object.hasOwn(output, key)) throw new Error("Runtime environment file contains invalid/duplicate keys.");
    output[key] = value;
  }
  return output;
}

function normalizeStringMap(value, label) {
  const input = requiredObject(value, label); const output = {};
  for (const key of Object.keys(input).sort(compareCodeUnits)) {
    if (!/^[A-Z][A-Z0-9_]{0,127}$/u.test(key) || typeof input[key] !== "string") throw new Error(`${label} contains invalid key/value.`);
    output[key] = input[key];
  }
  return output;
}

function sanitizedEnvironment(environment, executables) {
  const paths = Object.values(executables).map((entry) => dirname(entry.path)).filter((path, index, values) => values.indexOf(path) === index);
  return Object.freeze({ ...environment, PATH: paths.join(":"), NODE_OPTIONS: "", NO_PROXY: "*", no_proxy: "*" });
}

function mirrorPreparedRecord(auditRoot, record) {
  const root = join(auditRoot, "finalization");
  ensureOwnerOnlyDirectory(root);
  writeJsonAtomic(join(root, "prepare.json"), { record, recordDigest: digestJson(record) });
}

function prepareResult(record, identity, resumed) {
  return Object.freeze({
    status: "PREPARED",
    resumed,
    path: identity.path,
    prepareDigest: digestJson(record),
    storeIdentity: identity,
    bindings: {
      transactionId: record.transactionId,
      requestBindingDigest: record.input.requestBindingDigest,
      candidateIdentityDigest: record.input.candidateIdentityDigest,
      snapshotGroupDigest: record.snapshotGroup.manifest.groupDigest,
      immutableIdentityDigest: digestJson(record.immutableIdentity),
      productionSourcesDigest: digestJson(record.productionSources),
      gateEvidenceBindingDigest: record.gateEvidence.bindingDigest,
      moduleClosureDigest: record.moduleClosureDigest,
      activationReceiptId: record.productionSources.activation.receiptId,
      activationApprovalId: record.productionSources.activation.approvalId,
      previousBindingId: record.productionSources.activation.previousBindingId ?? null,
    },
  });
}

function transitionResult(value) { return Object.freeze({ status: value.identity.state, resumed: value.resumed, storeIdentity: value.identity, ...(value.evaluation ? { evaluation: value.evaluation } : {}) }); }
function canonicalAuditRoot(value) { return canonicalOwnerOnlyDirectory(requiredAbsolutePath(value, "auditRoot"), "auditRoot"); }
function canonicalOwnerOnlyFile(value, label) { const path = requiredAbsolutePath(value, label); const metadata = lstatSync(path); if (!metadata.isFile() || metadata.isSymbolicLink() || realpathSync(path) !== path || (metadata.mode & 0o077) !== 0 || (typeof process.getuid === "function" && metadata.uid !== process.getuid())) throw new Error(`${label} must be an owner-only canonical real file.`); return path; }
function canonicalRealFile(value, label) { const path = requiredAbsolutePath(value, label); const metadata = lstatSync(path); if (!metadata.isFile() || metadata.isSymbolicLink() || realpathSync(path) !== path) throw new Error(`${label} must be a canonical real file.`); return path; }
function canonicalExecutable(value, label) { const path = canonicalRealFile(value, label); const metadata = lstatSync(path); if ((metadata.mode & 0o111) === 0) throw new Error(`${label} is not executable.`); return path; }
function canonicalOwnerOnlyDirectory(value, label = "directory", requireOwnerOnly = true) { const path = requiredAbsolutePath(value, label); const metadata = lstatSync(path); if (!metadata.isDirectory() || metadata.isSymbolicLink() || realpathSync(path) !== path || (requireOwnerOnly && (metadata.mode & 0o077) !== 0) || (typeof process.getuid === "function" && metadata.uid !== process.getuid())) throw new Error(`${label} must be an owner-only canonical real directory.`); return path; }
function canonicalRealDirectory(value, label) { const path = requiredAbsolutePath(value, label); const metadata = lstatSync(path); if (!metadata.isDirectory() || metadata.isSymbolicLink() || realpathSync(path) !== path) throw new Error(`${label} must be a canonical real directory.`); return path; }
function canonicalProspectiveOwnerPath(value, label) { const path = requiredAbsolutePath(value, label); canonicalOwnerOnlyDirectory(dirname(path), `${label} parent`); return path; }
function ensureOwnerOnlyDirectory(path) { const existing = lstatIfPresent(path); if (!existing) { mkdirSync(path, { recursive: false, mode: 0o700 }); chmodSync(path, 0o700); fsyncDirectory(dirname(path)); } canonicalOwnerOnlyDirectory(path, "finalization audit directory"); }
function readJsonStable(path, label) { const before = lstatSync(path, { bigint: true }); const bytes = readFileSync(path); const after = lstatSync(path, { bigint: true }); if (before.dev !== after.dev || before.ino !== after.ino || before.size !== after.size || before.mtimeNs !== after.mtimeNs) throw new Error(`${label} changed during readback.`); try { return JSON.parse(bytes.toString("utf8")); } catch { throw new Error(`${label} is not valid JSON.`); } }
function writeJsonAtomic(path, value) { if (lstatIfPresent(path)) { const existing = readJsonStable(canonicalOwnerOnlyFile(path, "existing finalization mirror"), "existing finalization mirror"); if (canonicalJson(existing) !== canonicalJson(value)) throw new Error("Finalization mirror replay differs from durable ledger."); return; } const temporary = `${path}.tmp-${process.pid}-${randomUUID()}`; const descriptor = openSync(temporary, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | (constants.O_NOFOLLOW ?? 0), 0o600); try { writeFileSync(descriptor, `${JSON.stringify(value, null, 2)}\n`, "utf8"); fsyncSync(descriptor); } finally { closeSync(descriptor); } try { chmodSync(temporary, 0o600); renameSync(temporary, path); fsyncDirectory(dirname(path)); } catch (error) { try { unlinkSync(temporary); } catch { /* preserve write error */ } throw error; } }
function fsyncDirectory(path) { let descriptor; try { descriptor = openSync(path, constants.O_RDONLY); fsyncSync(descriptor); } catch (error) { if (!["EINVAL", "ENOTSUP", "EISDIR", "EPERM"].includes(error?.code)) throw error; } finally { if (descriptor !== undefined) closeSync(descriptor); } }
function lstatIfPresent(path, bigint = false) { try { return lstatSync(path, bigint ? { bigint: true } : undefined); } catch (error) { if (error?.code === "ENOENT") return undefined; throw error; } }
function requiredObject(value, label) { if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error(`${label} is missing or invalid.`); return value; }
function requiredText(value, label) { if (typeof value !== "string" || value.length === 0 || value.length > 4096 || /[\0\r\n]/u.test(value)) throw new Error(`${label} is missing or invalid.`); return value; }
function requiredAbsolutePath(value, label) { if (typeof value !== "string" || !isAbsolute(value) || resolve(value) !== value || /[\0\r\n]/u.test(value)) throw new Error(`${label} must be an absolute canonical path.`); return value; }
function requiredTimestamp(value, label) { if (typeof value !== "string" || !Number.isFinite(Date.parse(value)) || new Date(Date.parse(value)).toISOString() !== value) throw new Error(`${label} must be a canonical UTC timestamp.`); return value; }
function normalizedNow(now) { return requiredTimestamp(typeof now === "function" ? now() : new Date().toISOString(), "finalization timestamp"); }
function requiredTransactionId(value) { const text = requiredText(value, "transactionId"); if (text.length < 8 || text.length > 200 || !/^[A-Za-z0-9._:-]+$/u.test(text)) throw new Error("Finalization transactionId is not canonical."); return text; }
function requiredHttpUrl(value, label) { const text = requiredText(value, label); const url = new URL(text); if (url.protocol !== "http:" || url.username || url.password || url.hash) throw new Error(`${label} must be a plain private HTTP URL.`); return text; }
function requireDigest(value, label) { if (!DIGEST_PATTERN.test(value ?? "")) throw new Error(`${label} is not a canonical SHA-256 digest.`); return value; }
function assertExactKeys(value, expected, label) { const actual = Object.keys(requiredObject(value, label)).sort(compareCodeUnits); const wanted = [...expected].sort(compareCodeUnits); if (canonicalJson(actual) !== canonicalJson(wanted)) throw new Error(`${label} contains a missing or unsupported field.`); }
function assertCanonicalEqual(actual, expected, label) { if (canonicalJson(actual) !== canonicalJson(expected)) throw new Error(`${label} differs from immutable expected value.`); }
function assertCompleteReadbackTree(value, path = "canonical final readback", seen = new Set()) {
  if (value === undefined) throw new Error(`${path} contains an undefined required value.`);
  if (typeof value === "number" && !Number.isFinite(value)) throw new Error(`${path} contains a non-finite number.`);
  if (value === null || typeof value !== "object") return;
  if (seen.has(value)) throw new Error(`${path} contains a cyclic value.`);
  seen.add(value);
  if (Array.isArray(value)) {
    for (let index = 0; index < value.length; index += 1) {
      if (!Object.hasOwn(value, index)) throw new Error(`${path} contains a sparse array entry.`);
      assertCompleteReadbackTree(value[index], `${path}[${index}]`, seen);
    }
  } else {
    for (const [key, nested] of Object.entries(value)) {
      assertCompleteReadbackTree(nested, `${path}.${key}`, seen);
    }
  }
  seen.delete(value);
}
function omitMigrationIdentity(value) { const { migrationManifestDigest: _omitted, ...identity } = value; return identity; }
function canonicalClone(value) { return JSON.parse(canonicalJson(value)); }
function digestFile(path) { return `sha256:${fileSha256(path)}`; }
function digestJson(value) { return `sha256:${createHash("sha256").update(canonicalJson(value)).digest("hex")}`; }
function pathsOverlap(left, right) { const a = resolve(left); const b = resolve(right); return a === b || a.startsWith(`${b}${sep}`) || b.startsWith(`${a}${sep}`); }
function isSameOrInside(root, path) { const relation = relative(root, path); return relation === "" || (relation !== ".." && !relation.startsWith(`..${sep}`) && !isAbsolute(relation)); }
function compareCodeUnits(left, right) { return left < right ? -1 : left > right ? 1 : 0; }
function compareListener(left, right) { return left.port - right.port || compareCodeUnits(canonicalJson(left), canonicalJson(right)); }
function firstColumn(row) { return row ? Object.values(row)[0] : undefined; }
