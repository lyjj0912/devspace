import { createHash } from "node:crypto";
import { spawnSync } from "node:child_process";
import {
  chmodSync,
  closeSync,
  existsSync,
  fsyncSync,
  mkdirSync,
  openSync,
  readFileSync,
  readdirSync,
  renameSync,
  statSync,
  unlinkSync,
  writeFileSync,
} from "node:fs";
import { basename, dirname, join, relative, resolve, sep } from "node:path";
import { canonicalJson, fileSha256, sha256, verifyReleasePackage } from "./release-artifacts.mjs";

const EXPECTED_TOOLS = ["target", "context", "fs", "exec", "process", "mcp", "artifact", "gui"];
const RECORD_VERSION = 1;

export class FinalizationInterruptedError extends Error {
  constructor(stageId) {
    super(`Finalization interruption injected after stage action: ${stageId}`);
    this.name = "FinalizationInterruptedError";
    this.exitCode = 75;
  }
}

export function prepareFinalization(options) {
  const auditRoot = resolve(options.auditRoot);
  const finalizationRoot = join(auditRoot, "finalization");
  mkdirSync(finalizationRoot, { recursive: true, mode: 0o700 });
  chmodSync(finalizationRoot, 0o700);
  return withLock(join(finalizationRoot, ".prepare.lock"), () => {
    const evidence = readJson(options.evidencePath);
    validatePrepareEvidence(evidence);
    const packageEvidence = verifyReleasePackage(evidence.releasePackage, {
      expectedSourceRevision: evidence.runtimeIdentity.sourceRevision,
      expectedRuntimeRevision: evidence.runtimeIdentity.runtimeRevision,
    });
    assertManifestIdentity(packageEvidence, evidence.runtimeIdentity);
    const inputDigest = digestJson(evidence);
    const preparePath = join(finalizationRoot, "prepare.json");
    if (existsSync(preparePath)) {
      const existing = readCheckedRecord(preparePath);
      if (existing.state !== "PREPARED" || existing.inputDigest !== inputDigest) {
        throw new Error("Existing finalization preparation is for different evidence; create a new audit directory.");
      }
      return { status: "PREPARED", resumed: true, path: preparePath, prepareDigest: recordDigest(existing) };
    }
    const preparedAt = normalizedNow(options.now);
    const record = checkedRecord({
      schemaVersion: RECORD_VERSION,
      state: "PREPARED",
      revision: 1,
      preparedAt,
      inputDigest,
      sourceRevision: evidence.runtimeIdentity.sourceRevision,
      runtimeIdentity: evidence.runtimeIdentity,
      releasePackage: resolve(evidence.releasePackage),
      releaseManifestSha256: packageEvidence.manifestSha256,
      inventories: evidence.inventories,
      expectedCanary: evidence.expectedCanary,
      canonicalConnector: evidence.canonicalConnector,
      destructivePlan: evidence.destructivePlan,
      preimages: evidence.preimages ?? [],
    });
    writeJsonAtomic(preparePath, record, 0o600);
    writeJsonAtomic(join(finalizationRoot, "prepare-input.json"), redactPrepareEvidence(evidence), 0o600);
    return { status: "PREPARED", resumed: false, path: preparePath, prepareDigest: recordDigest(record) };
  });
}

export function sealFinalization(options) {
  const auditRoot = resolve(options.auditRoot);
  const finalizationRoot = join(auditRoot, "finalization");
  const preparePath = join(finalizationRoot, "prepare.json");
  if (!existsSync(preparePath)) throw new Error("Finalization prepare record is missing.");
  mkdirSync(join(finalizationRoot, "receipts"), { recursive: true, mode: 0o700 });
  return withLock(join(finalizationRoot, ".seal.lock"), () => {
    const prepare = readCheckedRecord(preparePath);
    if (prepare.state !== "PREPARED") throw new Error(`Finalization preparation state is invalid: ${prepare.state}`);
    const prepareDigest = recordDigest(prepare);
    const evidence = readJson(options.evidencePath);
    validateSealEvidence(prepare, evidence);
    const packageEvidence = verifyReleasePackage(prepare.releasePackage, {
      expectedSourceRevision: prepare.sourceRevision,
      expectedRuntimeRevision: prepare.runtimeIdentity.runtimeRevision,
    });
    assertManifestIdentity(packageEvidence, evidence.runtimeIdentity);
    const sealInputDigest = digestJson({ prepareDigest, evidence });
    const sealPath = join(finalizationRoot, "seal.json");
    let seal = existsSync(sealPath) ? readCheckedRecord(sealPath) : undefined;
    if (seal) {
      if (seal.prepareDigest !== prepareDigest || seal.sealInputDigest !== sealInputDigest) {
        throw new Error("Seal evidence changed after finalization began; refusing to reuse stage receipts.");
      }
      if (seal.state === "FINAL_PASS") return verifyFinalizationDirectory(finalizationRoot);
    } else {
      seal = checkedRecord({
        schemaVersion: RECORD_VERSION,
        state: "POST_ROTATION_VERIFIED",
        revision: 1,
        prepareDigest,
        sealInputDigest,
        startedAt: normalizedNow(options.now),
        completedStages: [],
      });
      writeJsonAtomic(sealPath, seal, 0o600);
      writeJsonAtomic(join(finalizationRoot, "post-rotation-evidence.json"), redactSealEvidence(evidence), 0o600);
    }

    const contextPath = join(finalizationRoot, "driver-context.json");
    writeJsonAtomic(contextPath, {
      schemaVersion: 1,
      auditRoot,
      finalizationRoot,
      preparePath,
      sealEvidencePath: resolve(options.evidencePath),
      releasePackage: prepare.releasePackage,
      runtimeIdentity: prepare.runtimeIdentity,
    }, 0o600);

    for (const stage of prepare.destructivePlan) {
      const result = runStage({
        stage,
        prepareDigest,
        finalizationRoot,
        driverPath: options.driverPath,
        contextPath,
        now: options.now,
        interruptAfterAction: options.interruptAfterAction,
      });
      if (!seal.completedStages.includes(stage.id)) {
        seal = checkedRecord({
          ...withoutChecksum(seal),
          revision: seal.revision + 1,
          state: "ROTATION_PENDING",
          completedStages: [...seal.completedStages, stage.id],
          updatedAt: normalizedNow(options.now),
          lastReceiptDigest: result.receiptDigest,
        });
        writeJsonAtomic(sealPath, seal, 0o600);
      }
    }

    if (options.driverPath) {
      const finalReadback = invokeDriver(options.driverPath, "final-readback", "FINAL", contextPath);
      if (!finalReadback.complete) throw new Error(`Final readback failed: ${finalReadback.message}`);
    }
    const completedAt = normalizedNow(options.now);
    const finalRecord = checkedRecord({
      schemaVersion: RECORD_VERSION,
      status: "FINAL_PASS",
      assurance: evidence.assurance ?? "COOPERATIVE_AUTHORITY",
      sourceRevision: prepare.sourceRevision,
      runtimeIdentity: evidence.runtimeIdentity,
      releasePackage: prepare.releasePackage,
      releaseManifestSha256: packageEvidence.manifestSha256,
      prepareDigest,
      sealInputDigest,
      tokenFamilyId: evidence.activeTokenFamily.familyId,
      connectorBindingId: evidence.activeConnector.bindingId,
      connectorDrainEpoch: evidence.activeConnector.drainEpoch,
      completedStages: prepare.destructivePlan.map((stage) => stage.id),
      completedAt,
    });
    writeJsonAtomic(join(finalizationRoot, "final.json"), finalRecord, 0o600);
    writeFinalReport(join(finalizationRoot, "report.md"), finalRecord);
    seal = checkedRecord({
      ...withoutChecksum(seal),
      revision: seal.revision + 1,
      state: "FINAL_PASS",
      completedAt,
      finalDigest: recordDigest(finalRecord),
    });
    writeJsonAtomic(sealPath, seal, 0o600);
    writeFinalChecksums(finalizationRoot);
    verifyFinalizationDirectory(finalizationRoot);
    return finalRecord;
  });
}

export function verifyFinalizationDirectory(finalizationRoot) {
  const root = resolve(finalizationRoot);
  const checksumPath = join(root, "SHA256SUMS");
  if (!existsSync(checksumPath)) throw new Error("Finalization checksum manifest is missing.");
  const expected = new Set();
  for (const line of readFileSync(checksumPath, "utf8").split("\n")) {
    if (!line) continue;
    const match = /^([a-f0-9]{64})  ([^\0\r\n]+)$/u.exec(line);
    if (!match) throw new Error(`Invalid finalization checksum line: ${line}`);
    const path = resolveContained(root, match[2]);
    if (!existsSync(path) || fileSha256(path) !== match[1]) throw new Error(`Finalization checksum mismatch: ${match[2]}`);
    expected.add(match[2]);
  }
  const actual = [];
  const visit = (directory) => {
    for (const entry of readdirSync(directory, { withFileTypes: true })) {
      if (entry.name.startsWith(".")) continue;
      const path = join(directory, entry.name);
      if (entry.isDirectory()) visit(path);
      else if (entry.isFile() && entry.name !== "SHA256SUMS") actual.push(relative(root, path).split(sep).join("/"));
    }
  };
  visit(root);
  const extras = actual.filter((path) => !expected.has(path));
  const missing = [...expected].filter((path) => !actual.includes(path));
  if (extras.length > 0 || missing.length > 0) throw new Error(`Finalization file set mismatch: ${JSON.stringify({ extras, missing })}`);
  const finalRecord = readCheckedRecord(join(root, "final.json"));
  if (finalRecord.status !== "FINAL_PASS") throw new Error("Finalization result is not FINAL_PASS.");
  const seal = readCheckedRecord(join(root, "seal.json"));
  if (seal.state !== "FINAL_PASS" || seal.finalDigest !== recordDigest(finalRecord)) throw new Error("Finalization seal does not bind final.json.");
  return finalRecord;
}

function runStage(options) {
  const { stage, prepareDigest, finalizationRoot, driverPath, contextPath } = options;
  const planDigest = digestJson(stage);
  const receiptPath = join(finalizationRoot, "receipts", `${stage.id}.json`);
  let receipt = existsSync(receiptPath) ? readCheckedRecord(receiptPath) : undefined;
  if (receipt && (receipt.prepareDigest !== prepareDigest || receipt.planDigest !== planDigest)) {
    throw new Error(`Stage receipt does not match the current plan: ${stage.id}`);
  }
  if (receipt?.state === "PASS") {
    const readback = driverPath ? invokeDriver(driverPath, "readback", stage.id, contextPath) : { complete: true, evidence: { driver: "none" } };
    if (!readback.complete) throw new Error(`Completed destructive stage drifted and will not be repeated: ${stage.id}: ${readback.message}`);
    return { skipped: true, receiptDigest: recordDigest(receipt) };
  }
  if (!receipt) {
    receipt = checkedRecord({
      schemaVersion: RECORD_VERSION,
      stageId: stage.id,
      destructive: stage.destructive,
      state: "INTENT",
      revision: 1,
      attempts: 0,
      prepareDigest,
      planDigest,
      createdAt: normalizedNow(options.now),
    });
    writeJsonAtomic(receiptPath, receipt, 0o600);
  }
  const before = driverPath ? invokeDriver(driverPath, "readback", stage.id, contextPath) : { complete: !stage.destructive, evidence: { driver: "none" } };
  if (before.complete) return passReceipt(receiptPath, receipt, before.evidence, options.now, false);
  if (!driverPath) throw new Error(`A finalization driver is required for incomplete stage: ${stage.id}`);

  receipt = checkedRecord({
    ...withoutChecksum(receipt),
    state: "APPLYING",
    revision: receipt.revision + 1,
    attempts: receipt.attempts + 1,
    applyingAt: normalizedNow(options.now),
  });
  writeJsonAtomic(receiptPath, receipt, 0o600);
  const applied = invokeDriver(driverPath, "apply", stage.id, contextPath);
  if (!applied.complete) {
    const failed = checkedRecord({
      ...withoutChecksum(receipt),
      state: "FAILED",
      revision: receipt.revision + 1,
      failedAt: normalizedNow(options.now),
      failure: applied.message,
    });
    writeJsonAtomic(receiptPath, failed, 0o600);
    throw new Error(`Finalization stage failed: ${stage.id}: ${applied.message}`);
  }
  if (options.interruptAfterAction === stage.id) throw new FinalizationInterruptedError(stage.id);
  const after = invokeDriver(driverPath, "readback", stage.id, contextPath);
  if (!after.complete) throw new Error(`Finalization stage readback did not prove completion: ${stage.id}: ${after.message}`);
  return passReceipt(receiptPath, receipt, after.evidence, options.now, true);
}

function passReceipt(path, current, evidence, now, applied) {
  const receipt = checkedRecord({
    ...withoutChecksum(current),
    state: "PASS",
    revision: current.revision + 1,
    completedAt: normalizedNow(now),
    completion: applied ? "APPLIED_AND_READ_BACK" : "READBACK_PROVED_COMPLETE",
    readbackDigest: digestJson(evidence ?? null),
  });
  writeJsonAtomic(path, receipt, 0o600);
  return { skipped: !applied, receiptDigest: recordDigest(receipt) };
}

function invokeDriver(driverPath, operation, stageId, contextPath) {
  const absoluteDriver = resolve(driverPath);
  const command = absoluteDriver.endsWith(".mjs") || absoluteDriver.endsWith(".js") ? process.execPath : absoluteDriver;
  const arguments_ = command === absoluteDriver
    ? [operation, stageId, contextPath]
    : [absoluteDriver, operation, stageId, contextPath];
  const result = spawnSync(command, arguments_, {
    encoding: "utf8",
    maxBuffer: 1024 * 1024,
    timeout: 120_000,
    env: process.env,
  });
  let evidence;
  try { evidence = result.stdout.trim() ? JSON.parse(result.stdout) : {}; } catch { evidence = { stdoutSha256: sha256(result.stdout ?? "") }; }
  return {
    complete: result.status === 0,
    evidence,
    message: String(evidence?.message ?? result.stderr?.trim() ?? `driver exit ${result.status}`),
  };
}

function validatePrepareEvidence(value) {
  if (!value || value.schemaVersion !== 1 || value.status !== "PASS" || value.phase !== "production-reconnect") {
    throw new Error("Prepare evidence must be a version 1 production-reconnect PASS record.");
  }
  assertNoRawCredentialEvidence(value);
  validateRuntimeIdentity(value.runtimeIdentity);
  if (typeof value.releasePackage !== "string") throw new Error("Prepare evidence releasePackage is required.");
  if (!value.inventories || typeof value.inventories !== "object") throw new Error("Prepare evidence inventories are required.");
  for (const name of ["processes", "listeners", "routes", "oauth", "connectors", "temporaryArtifacts"]) {
    if (!Array.isArray(value.inventories[name])) throw new Error(`Prepare inventory is missing: ${name}`);
  }
  if (!value.expectedCanary || canonicalJson(value.expectedCanary.toolNames) !== canonicalJson(EXPECTED_TOOLS)) {
    throw new Error("Prepare evidence must bind the exact eight-tool canary.");
  }
  if (!value.canonicalConnector || typeof value.canonicalConnector.name !== "string" || typeof value.canonicalConnector.bindingId !== "string"
    || !Number.isInteger(value.canonicalConnector.installationEpoch) || value.canonicalConnector.installationEpoch < 1) {
    throw new Error("Prepare evidence canonical connector binding is required.");
  }
  if (!Array.isArray(value.destructivePlan)) throw new Error("Prepare evidence destructive plan is required.");
  const identifiers = new Set();
  for (const stage of value.destructivePlan) {
    if (!stage || typeof stage.id !== "string" || !/^[a-z][a-z0-9-]{2,63}$/u.test(stage.id) || identifiers.has(stage.id)) {
      throw new Error("Finalization stage identifiers must be unique kebab-case values.");
    }
    if (stage.destructive !== true && stage.destructive !== false) throw new Error(`Finalization stage destructive flag is invalid: ${stage.id}`);
    if (typeof stage.target !== "string" || stage.target.length === 0) throw new Error(`Finalization stage target is missing: ${stage.id}`);
    identifiers.add(stage.id);
  }
}

function validateSealEvidence(prepare, value) {
  if (!value || value.schemaVersion !== 1 || value.status !== "PASS" || value.phase !== "post-rotation") {
    throw new Error("Seal evidence must be a version 1 post-rotation PASS record.");
  }
  assertNoRawCredentialEvidence(value);
  validateRuntimeIdentity(value.runtimeIdentity);
  assertSameRuntimeIdentity(prepare.runtimeIdentity, value.runtimeIdentity);
  if (canonicalJson(value.toolNames) !== canonicalJson(EXPECTED_TOOLS)) throw new Error("Post-rotation evidence does not contain exactly eight canonical tools.");
  if (value.freshHostCanary !== true) throw new Error("Post-rotation fresh Host canary is required.");
  if (typeof value.targetInventoryDigest !== "string" || !/^sha256:[a-f0-9]{64}$/u.test(value.targetInventoryDigest)) {
    throw new Error("Post-rotation Target inventory digest is required.");
  }
  const family = value.activeTokenFamily;
  const connector = value.activeConnector;
  if (!family || family.status !== "ACTIVE" || !connector || connector.state !== "ACTIVE") {
    throw new Error("One active token family and canonical connector binding are required.");
  }
  for (const [name, entry] of [["token family", family], ["connector", connector]]) {
    if (!Number.isInteger(entry.installationEpoch) || entry.installationEpoch < 1
      || !Number.isInteger(entry.drainEpoch) || entry.drainEpoch < 0) {
      throw new Error(`Post-rotation ${name} epoch is invalid.`);
    }
  }
  for (const [name, entry] of [
    ["familyId", family.familyId],
    ["family.clientId", family.clientId],
    ["family.connectorBindingId", family.connectorBindingId],
    ["connector.bindingId", connector.bindingId],
    ["connector.clientId", connector.clientId],
    ["connector.tokenFamilyId", connector.tokenFamilyId],
  ]) {
    if (typeof entry !== "string" || entry.length === 0) throw new Error(`Post-rotation ${name} is invalid.`);
  }
  if (connector.canonicalName !== prepare.canonicalConnector.name) {
    throw new Error("Post-rotation connector is not the prepared canonical identity.");
  }
  if (connector.bindingId === prepare.canonicalConnector.bindingId
    || connector.installationEpoch <= prepare.canonicalConnector.installationEpoch) {
    throw new Error("Post-rotation connector reused the prepared installation binding or epoch.");
  }
  if (family.connectorBindingId !== connector.bindingId || family.clientId !== connector.clientId || family.familyId !== connector.tokenFamilyId) {
    throw new Error("Stale token family cannot seal the canonical connector binding.");
  }
  if (family.drainEpoch !== connector.drainEpoch || family.installationEpoch !== connector.installationEpoch) {
    throw new Error("Token family connector epoch is stale.");
  }
  if (connector.schemaGeneration !== value.runtimeIdentity.schemaGeneration) throw new Error("Connector schema generation is stale.");
  if (!Number.isInteger(connector.refCount) || connector.refCount < 1) throw new Error("Canonical connector has no live reference.");
  if (!Array.isArray(value.retiredConnectors) || value.retiredConnectors.some((entry) => entry.state !== "DRAINED" || entry.refCount !== 0)) {
    throw new Error("Retired connector bindings have not reached zero-reference drain.");
  }
  if (!value.retiredConnectors.some((entry) => entry.bindingId === prepare.canonicalConnector.bindingId)) {
    throw new Error("Prepared canonical connector binding has not been retired and drained.");
  }
  const previousFamilies = new Set(prepare.inventories.oauth.map((entry) => entry.familyId).filter(Boolean));
  if (previousFamilies.has(family.familyId)) throw new Error("Post-rotation token family reused a prepared token family.");
  const revoked = new Set(value.revokedTokenFamilyIds ?? []);
  for (const familyId of previousFamilies) {
    if (!revoked.has(familyId)) throw new Error(`Prepared token family was not revoked: ${familyId}`);
  }
}

function validateRuntimeIdentity(value) {
  if (!value || typeof value !== "object") throw new Error("Runtime identity is required.");
  for (const key of ["sourceRevision", "runtimeRevision"]) {
    if (typeof value[key] !== "string" || value[key].length < 7) throw new Error(`Runtime identity field is invalid: ${key}`);
  }
  for (const key of ["buildDigest", "schemaGeneration", "authorityContractGeneration", "configDigest", "configSchemaIdentity"]) {
    if (typeof value[key] !== "string" || !/^sha256:[a-f0-9]{64}$/u.test(value[key])) throw new Error(`Runtime identity digest is invalid: ${key}`);
  }
}

function assertNoRawCredentialEvidence(value, trail = []) {
  if (Array.isArray(value)) {
    value.forEach((entry, index) => assertNoRawCredentialEvidence(entry, [...trail, index]));
    return;
  }
  if (!value || typeof value !== "object") return;
  for (const [key, child] of Object.entries(value)) {
    const normalized = key.replaceAll(/[-_]/gu, "").toLowerCase();
    if (["accesstoken", "refreshtoken", "ownertoken", "password", "secret", "clientsecret"].includes(normalized)
      && typeof child === "string" && child.length > 0) {
      throw new Error(`Raw credential evidence is forbidden: ${[...trail, key].join(".")}`);
    }
    assertNoRawCredentialEvidence(child, [...trail, key]);
  }
}

function assertManifestIdentity(packageEvidence, runtimeIdentity) {
  for (const key of ["sourceRevision", "runtimeRevision", "buildDigest", "schemaGeneration", "authorityContractGeneration", "configSchemaIdentity"]) {
    if (packageEvidence[key] !== runtimeIdentity[key]) throw new Error(`Release manifest/runtime identity mismatch: ${key}`);
  }
}

function assertSameRuntimeIdentity(expected, observed) {
  for (const key of ["sourceRevision", "runtimeRevision", "buildDigest", "schemaGeneration", "authorityContractGeneration", "configDigest", "configSchemaIdentity"]) {
    if (expected[key] !== observed[key]) throw new Error(`Prepared runtime identity changed before seal: ${key}`);
  }
}

function checkedRecord(unsigned) {
  return { ...unsigned, checksum: digestJson(unsigned) };
}

function readCheckedRecord(path) {
  const value = readJson(path);
  const unsigned = withoutChecksum(value);
  if (value.checksum !== digestJson(unsigned)) throw new Error(`Finalization record checksum mismatch: ${path}`);
  return value;
}

function withoutChecksum(value) {
  const { checksum: _checksum, ...unsigned } = value;
  return unsigned;
}

function recordDigest(value) {
  return digestJson(value);
}

function digestJson(value) {
  return `sha256:${sha256(canonicalJson(value))}`;
}

function readJson(path) {
  return JSON.parse(readFileSync(resolve(path), "utf8"));
}

function redactPrepareEvidence(value) {
  return {
    schemaVersion: value.schemaVersion,
    status: value.status,
    phase: value.phase,
    releasePackage: resolve(value.releasePackage),
    runtimeIdentity: value.runtimeIdentity,
    inventories: value.inventories,
    expectedCanary: value.expectedCanary,
    canonicalConnector: value.canonicalConnector,
    destructivePlan: value.destructivePlan,
    preimages: value.preimages ?? [],
  };
}

function redactSealEvidence(value) {
  return {
    schemaVersion: value.schemaVersion,
    status: value.status,
    phase: value.phase,
    runtimeIdentity: value.runtimeIdentity,
    toolNames: value.toolNames,
    freshHostCanary: value.freshHostCanary,
    targetInventoryDigest: value.targetInventoryDigest,
    activeTokenFamily: value.activeTokenFamily,
    activeConnector: value.activeConnector,
    retiredConnectors: value.retiredConnectors,
    revokedTokenFamilyIds: value.revokedTokenFamilyIds,
    assurance: value.assurance,
  };
}

function writeFinalReport(path, finalRecord) {
  const lines = [
    "# Universal Broker v2 Finalization",
    "",
    `Status: ${finalRecord.status}`,
    `Assurance: ${finalRecord.assurance}`,
    `Source revision: ${finalRecord.sourceRevision}`,
    `Runtime revision: ${finalRecord.runtimeIdentity.runtimeRevision}`,
    `Build digest: ${finalRecord.runtimeIdentity.buildDigest}`,
    `Schema generation: ${finalRecord.runtimeIdentity.schemaGeneration}`,
    `Authority contract generation: ${finalRecord.runtimeIdentity.authorityContractGeneration}`,
    `Runtime config digest: ${finalRecord.runtimeIdentity.configDigest}`,
    `Config schema identity: ${finalRecord.runtimeIdentity.configSchemaIdentity}`,
    `Connector binding: ${finalRecord.connectorBindingId}`,
    `Token family: ${finalRecord.tokenFamilyId}`,
    `Completed at: ${finalRecord.completedAt}`,
    "",
  ];
  writeTextAtomic(path, lines.join("\n"), 0o600);
}

function writeFinalChecksums(root) {
  const paths = [];
  const visit = (directory) => {
    for (const entry of readdirSync(directory, { withFileTypes: true })) {
      if (entry.name.startsWith(".")) continue;
      const path = join(directory, entry.name);
      if (entry.isDirectory()) visit(path);
      else if (entry.isFile() && entry.name !== "SHA256SUMS") paths.push(path);
    }
  };
  visit(root);
  paths.sort((left, right) => relative(root, left).localeCompare(relative(root, right)));
  const contents = paths.map((path) => `${fileSha256(path)}  ${relative(root, path).split(sep).join("/")}`).join("\n") + "\n";
  writeTextAtomic(join(root, "SHA256SUMS"), contents, 0o600);
}

function writeJsonAtomic(path, value, mode) {
  writeTextAtomic(path, `${JSON.stringify(value, null, 2)}\n`, mode);
}

function writeTextAtomic(path, value, mode) {
  mkdirSync(dirname(path), { recursive: true, mode: 0o700 });
  const temporary = join(dirname(path), `.${basename(path)}.${process.pid}.tmp`);
  const descriptor = openSync(temporary, "wx", mode);
  try {
    writeFileSync(descriptor, value, "utf8");
    fsyncSync(descriptor);
  } finally {
    closeSync(descriptor);
  }
  chmodSync(temporary, mode);
  renameSync(temporary, path);
  fsyncDirectory(dirname(path));
}

function withLock(path, operation) {
  let descriptor;
  for (let attempt = 0; attempt < 2; attempt += 1) {
    try {
      const candidate = openSync(path, "wx", 0o600);
      try {
        writeFileSync(candidate, `${process.pid}\n`, "utf8");
        fsyncSync(candidate);
      } catch (error) {
        closeSync(candidate);
        try { unlinkSync(path); } catch {}
        throw error;
      }
      descriptor = candidate;
      break;
    } catch (error) {
      if (error?.code !== "EEXIST") throw error;
      let ownerText;
      let lockAgeMs;
      try {
        ownerText = readFileSync(path, "utf8").trim();
        lockAgeMs = Math.max(0, Date.now() - statSync(path).mtimeMs);
      } catch (readError) {
        if (readError?.code === "ENOENT") continue;
        throw readError;
      }
      const ownerPid = Number.parseInt(ownerText, 10);
      if (Number.isInteger(ownerPid) && processIsAlive(ownerPid)) {
        throw new Error(`Finalization transaction is already locked by pid ${ownerPid}: ${path}`);
      }
      if (!Number.isInteger(ownerPid) && lockAgeMs < 30_000) {
        throw new Error(`Finalization lock owner is not yet readable; refusing unsafe reclamation: ${path}`);
      }
      const stalePath = `${path}.stale-${Date.now()}-${ownerPid || "unknown"}`;
      try { renameSync(path, stalePath); } catch (renameError) {
        if (renameError?.code !== "ENOENT") throw renameError;
      }
      fsyncDirectory(dirname(path));
    }
  }
  if (descriptor === undefined) throw new Error(`Unable to acquire finalization transaction lock: ${path}`);
  try {
    return operation();
  } finally {
    closeSync(descriptor);
    unlinkSync(path);
    fsyncDirectory(dirname(path));
  }
}

function processIsAlive(pid) {
  if (pid === process.pid) return true;
  try { process.kill(pid, 0); return true; }
  catch (error) { return error?.code === "EPERM"; }
}

function fsyncDirectory(path) {
  let descriptor;
  try {
    descriptor = openSync(path, "r");
    fsyncSync(descriptor);
  } catch (error) {
    if (!new Set(["EINVAL", "ENOTSUP", "EISDIR", "EPERM"]).has(error?.code)) throw error;
  } finally {
    if (descriptor !== undefined) closeSync(descriptor);
  }
}

function resolveContained(root, child) {
  const base = resolve(root);
  const path = resolve(base, child);
  if (path !== base && !path.startsWith(`${base}${sep}`)) throw new Error(`Finalization path escapes root: ${child}`);
  return path;
}

function normalizedNow(now) {
  const value = typeof now === "function" ? now() : new Date().toISOString();
  const parsed = new Date(value);
  if (!Number.isFinite(parsed.getTime())) throw new Error("Finalization timestamp is invalid.");
  return parsed.toISOString();
}
