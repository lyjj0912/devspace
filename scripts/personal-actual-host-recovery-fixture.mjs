#!/usr/bin/env node

import { createHash } from "node:crypto";
import {
  mkdir,
  readdir,
  readFile,
  rm,
  stat,
  writeFile,
} from "node:fs/promises";
import { dirname, isAbsolute, join, relative, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const SCHEMA_VERSION = 1;
const DEFAULT_COUNTS = Object.freeze({ terminal: 1_000, expired: 5, running: 2 });
const FIXTURE_ID_PATTERN = /^pdo-e2e-[a-z0-9-]{8,48}$/u;

export async function planRecoveryFixture(options) {
  const paths = fixturePaths(options);
  const template = await selectTemplateRecord(paths.processDirectory, paths.prefix);
  const baselineRecords = await baselineRecordIdentities(paths.processDirectory, paths.prefix);
  return {
    operation: "plan",
    fixtureId: paths.fixtureId,
    prefix: paths.prefix,
    stateDirectory: paths.stateDirectory,
    processDirectory: paths.processDirectory,
    outputDirectory: paths.outputDirectory,
    templateProcessId: template.processId,
    principalKeyFingerprintDigest: digest(template.principalKeyFingerprint),
    counts: normalizedCounts(options),
    baselineRecordCount: baselineRecords.length,
    collisionCount: (await prefixedFiles(paths)).length,
  };
}

export async function prepareRecoveryFixture(options) {
  const paths = fixturePaths(options);
  const counts = normalizedCounts(options);
  const collisions = await prefixedFiles(paths);
  if (collisions.length > 0) {
    throw new Error(`Recovery fixture prefix already exists (${collisions.length} path(s)): ${paths.prefix}`);
  }
  try {
    await stat(paths.fixtureDirectory);
    throw new Error(`Recovery fixture directory already exists: ${paths.fixtureDirectory}`);
  } catch (error) {
    if (!isNodeError(error, "ENOENT")) throw error;
  }

  const template = await selectTemplateRecord(paths.processDirectory, paths.prefix);
  const baselineRecords = await baselineRecordIdentities(paths.processDirectory, paths.prefix);
  await mkdir(dirname(paths.fixtureDirectory), { recursive: true, mode: 0o700 });
  await mkdir(paths.fixtureDirectory, { recursive: false, mode: 0o700 });
  const now = options.now ?? Date.now();
  const created = [];
  try {
    for (let index = 0; index < counts.terminal; index += 1) {
      const processId = fixtureProcessId(paths.prefix, "terminal", index);
      const outputPath = await createEmptyOutput(paths.outputDirectory, processId);
      const endedAtMs = now - 10_000 + index;
      await createRecord(paths.processDirectory, processRecord(template, {
        processId,
        state: "EXITED",
        startedAtMs: endedAtMs - 1_000,
        endedAtMs,
        exitCode: 0,
        outputPath,
        durable: false,
      }));
      created.push(processId);
    }
    for (let index = 0; index < counts.expired; index += 1) {
      const processId = fixtureProcessId(paths.prefix, "expired", index);
      const outputPath = await createEmptyOutput(paths.outputDirectory, processId);
      const endedAtMs = now - 7_200_000 - index;
      await createRecord(paths.processDirectory, processRecord(template, {
        processId,
        state: "EXITED",
        startedAtMs: endedAtMs - 1_000,
        endedAtMs,
        exitCode: 0,
        outputPath,
        durable: false,
      }));
      created.push(processId);
    }
    for (let index = 0; index < counts.running; index += 1) {
      const processId = fixtureProcessId(paths.prefix, "running", index);
      const outputPath = await createEmptyOutput(paths.outputDirectory, processId);
      await createRecord(paths.processDirectory, processRecord(template, {
        processId,
        state: "RUNNING",
        startedAtMs: now - 5_000 - index,
        outputPath,
        durable: true,
        durableIdentity: {
          managerHandle: `${paths.fixtureId}-missing-manager-${index}`,
          pid: 900_000 + index,
          startToken: `${paths.fixtureId}-missing-start-${index}`,
        },
      }));
      created.push(processId);
    }
    const corruptProcessId = `${paths.prefix}-corrupt`;
    await writeFile(
      join(paths.processDirectory, `${corruptProcessId}.json`),
      "{actual-host-corrupt-fixture",
      { mode: 0o600, flag: "wx" },
    );
    created.push(corruptProcessId);

    const manifest = {
      schemaVersion: SCHEMA_VERSION,
      fixtureId: paths.fixtureId,
      prefix: paths.prefix,
      createdAt: new Date(now).toISOString(),
      stateDirectory: paths.stateDirectory,
      processDirectory: paths.processDirectory,
      outputDirectory: paths.outputDirectory,
      counts,
      templateProcessId: template.processId,
      principalKeyFingerprintDigest: digest(template.principalKeyFingerprint),
      baselineRecords,
      createdProcessIdsDigest: digest(created.slice().sort().join("\n")),
    };
    await writeFile(paths.manifestPath, `${JSON.stringify(manifest, null, 2)}\n`, {
      mode: 0o600,
      flag: "wx",
    });
    return { operation: "prepare", ...await verifyInputFixture(options) };
  } catch (error) {
    await removePrefixedFiles(paths);
    await rm(paths.fixtureDirectory, { recursive: true, force: true });
    throw error;
  }
}

export async function verifyInputFixture(options) {
  const paths = fixturePaths(options);
  const manifest = await readManifest(paths);
  const records = await readFixtureRecords(paths);
  const counts = countRecordStates(records.valid);
  const outputBaseCount = (await outputFiles(paths)).filter((name) => name.endsWith(".log")).length;
  const expectedValid = manifest.counts.terminal + manifest.counts.expired + manifest.counts.running;
  assertEqual(records.valid.length, expectedValid, "valid input record count");
  assertEqual(records.corruptJson.length, 1, "corrupt input record count");
  assertEqual(counts.EXITED ?? 0, manifest.counts.terminal + manifest.counts.expired, "terminal input count");
  assertEqual(counts.RUNNING ?? 0, manifest.counts.running, "running input count");
  assertEqual(outputBaseCount, expectedValid, "input output-spool count");
  return {
    fixtureId: paths.fixtureId,
    prefix: paths.prefix,
    phase: "INPUT_READY",
    validRecordCount: records.valid.length,
    corruptRecordCount: records.corruptJson.length,
    outputBaseCount,
    states: counts,
    baseline: await verifyBaselineRecords(manifest),
  };
}

export async function verifyRecoveredFixture(options) {
  const paths = fixturePaths(options);
  const manifest = await readManifest(paths);
  const records = await readFixtureRecords(paths);
  const byId = new Map(records.valid.map((record) => [record.processId, record]));
  const terminal = range(manifest.counts.terminal).map((index) => fixtureProcessId(paths.prefix, "terminal", index));
  const expired = range(manifest.counts.expired).map((index) => fixtureProcessId(paths.prefix, "expired", index));
  const running = range(manifest.counts.running).map((index) => fixtureProcessId(paths.prefix, "running", index));
  const missingTerminal = terminal.filter((id) => !byId.has(id));
  const retainedExpired = expired.filter((id) => byId.has(id));
  const reconciledStates = running.map((id) => byId.get(id)?.state ?? "MISSING");
  const acceptedReconciled = new Set(["RUNNING", "UNKNOWN", "ORPHANED", "FAILED"]);
  if (missingTerminal.length > 0) throw new Error(`Recovery lost ${missingTerminal.length} retained terminal record(s).`);
  if (retainedExpired.length > 0) throw new Error(`Recovery retained ${retainedExpired.length} expired record(s).`);
  if (reconciledStates.some((state) => !acceptedReconciled.has(state))) {
    throw new Error(`Recovery did not reconcile running records: ${reconciledStates.join(",")}`);
  }
  if (records.corruptJson.length !== 0 || records.quarantined.length < 1) {
    throw new Error("Recovery did not quarantine the corrupt record.");
  }
  return {
    fixtureId: paths.fixtureId,
    prefix: paths.prefix,
    phase: "RECOVERED",
    retainedTerminalCount: terminal.length,
    prunedExpiredCount: expired.length,
    reconciledRunningCount: running.length,
    reconciledRunningStates: reconciledStates,
    quarantinedCorruptCount: records.quarantined.length,
    baseline: await verifyBaselineRecords(manifest),
  };
}

export async function cleanupRecoveryFixture(options) {
  const paths = fixturePaths(options);
  let baseline = { checked: 0, unchanged: 0, changed: [] };
  try {
    baseline = await verifyBaselineRecords(await readManifest(paths));
  } catch (error) {
    baseline = {
      checked: 0,
      unchanged: 0,
      changed: [],
      unavailable: error instanceof Error ? error.message.slice(0, 240) : String(error).slice(0, 240),
    };
  }
  const removed = await removePrefixedFiles(paths);
  await rm(paths.fixtureDirectory, { recursive: true, force: true });
  return {
    operation: "cleanup",
    fixtureId: paths.fixtureId,
    prefix: paths.prefix,
    removed,
    baseline,
    ...await verifyCleanFixture(options),
  };
}

export async function verifyCleanFixture(options) {
  const paths = fixturePaths(options);
  const remaining = await prefixedFiles(paths);
  if (remaining.length > 0) throw new Error(`Recovery fixture cleanup left ${remaining.length} path(s).`);
  return { phase: "CLEAN", remainingCount: 0 };
}

export function checksumRecord(record) {
  return createHash("sha256").update(stableJson(record)).digest("hex");
}

async function main() {
  const [operation, ...args] = process.argv.slice(2);
  const options = parseOptions(args);
  const handlers = {
    plan: planRecoveryFixture,
    prepare: prepareRecoveryFixture,
    "verify-input": verifyInputFixture,
    "verify-recovered": verifyRecoveredFixture,
    cleanup: cleanupRecoveryFixture,
    "verify-clean": verifyCleanFixture,
  };
  const handler = handlers[operation];
  if (!handler) throw new Error("Usage: personal-actual-host-recovery-fixture.mjs <plan|prepare|verify-input|verify-recovered|cleanup|verify-clean> --fixture-id pdo-e2e-<id> [--state-dir PATH] [--output-dir PATH]");
  process.stdout.write(`${JSON.stringify(await handler(options))}\n`);
}

function parseOptions(args) {
  const options = {
    stateDirectory: process.env.DEVSPACE_NEXT_STATE_DIR,
    outputDirectory: process.env.DEVSPACE_NEXT_PROCESS_OUTPUT_DIR,
  };
  for (let index = 0; index < args.length; index += 2) {
    const flag = args[index];
    const value = args[index + 1];
    if (!value) throw new Error(`Missing value for ${flag}.`);
    if (flag === "--fixture-id") options.fixtureId = value;
    else if (flag === "--state-dir") options.stateDirectory = value;
    else if (flag === "--output-dir") options.outputDirectory = value;
    else if (flag === "--terminal") options.terminalCount = Number(value);
    else if (flag === "--expired") options.expiredCount = Number(value);
    else if (flag === "--running") options.runningCount = Number(value);
    else throw new Error(`Unknown option: ${flag}`);
  }
  return options;
}

function fixturePaths(options) {
  const fixtureId = String(options.fixtureId ?? "");
  if (!FIXTURE_ID_PATTERN.test(fixtureId)) throw new Error(`Invalid fixture ID: ${fixtureId}`);
  const stateDirectory = requiredAbsolute(options.stateDirectory, "state directory");
  const outputDirectory = requiredAbsolute(options.outputDirectory, "output directory");
  if (!isWithin(stateDirectory, outputDirectory)) {
    throw new Error("Recovery fixture output directory must stay inside the state directory.");
  }
  const processDirectory = join(stateDirectory, "processes");
  const fixtureDirectory = join(stateDirectory, "actual-host-recovery-fixtures", fixtureId);
  return {
    fixtureId,
    prefix: `proc_${fixtureId}`,
    stateDirectory,
    outputDirectory,
    processDirectory,
    fixtureDirectory,
    manifestPath: join(fixtureDirectory, "manifest.json"),
  };
}

function normalizedCounts(options) {
  return {
    terminal: boundedCount(options.terminalCount, DEFAULT_COUNTS.terminal, "terminal", 10_000),
    expired: boundedCount(options.expiredCount, DEFAULT_COUNTS.expired, "expired", 100),
    running: boundedCount(options.runningCount, DEFAULT_COUNTS.running, "running", 64),
  };
}

async function selectTemplateRecord(processDirectory, prefix) {
  const names = await safeDirectory(processDirectory);
  const candidates = [];
  for (const name of names.filter((entry) => entry.endsWith(".json") && !entry.startsWith(prefix))) {
    const path = join(processDirectory, name);
    try {
      const record = JSON.parse(await readFile(path, "utf8"));
      validateTemplateRecord(record);
      candidates.push({ record, modifiedAtMs: (await stat(path)).mtimeMs });
    } catch {
      // A malformed unrelated record is not a safe owner template.
    }
  }
  candidates.sort((left, right) => right.modifiedAtMs - left.modifiedAtMs);
  if (!candidates[0]) throw new Error("No valid existing owner process record is available as a fixture template.");
  return candidates[0].record;
}

function validateTemplateRecord(record) {
  for (const key of ["processId", "principalKeyFingerprint", "targetId", "targetGeneration", "transport", "cwd"]) {
    if (typeof record?.[key] !== "string" || !record[key]) throw new Error(`Template record lacks ${key}.`);
  }
  if (!/^[a-f0-9]{64}$/u.test(record.principalKeyFingerprint)) throw new Error("Template owner fingerprint is invalid.");
  if (!/^(local|ssh)$/u.test(record.transport)) throw new Error("Template transport is invalid.");
  const { checksum, ...unsigned } = record;
  if (typeof checksum !== "string" || checksum !== checksumRecord(unsigned)) {
    throw new Error("Template record checksum is invalid.");
  }
}

function processRecord(template, overrides) {
  const unsigned = {
    schemaVersion: SCHEMA_VERSION,
    processId: overrides.processId,
    principalKeyFingerprint: template.principalKeyFingerprint,
    targetId: template.targetId,
    targetGeneration: template.targetGeneration,
    transport: template.transport,
    cwd: template.cwd,
    tty: false,
    launchRisk: "R0",
    state: overrides.state,
    startedAtMs: overrides.startedAtMs,
    ...(overrides.endedAtMs === undefined ? {} : { endedAtMs: overrides.endedAtMs }),
    ...(overrides.exitCode === undefined ? {} : { exitCode: overrides.exitCode }),
    outputPath: overrides.outputPath,
    durable: overrides.durable,
    ...(overrides.durableIdentity ? { durableIdentity: overrides.durableIdentity } : {}),
  };
  return { ...unsigned, checksum: checksumRecord(unsigned) };
}

async function createRecord(processDirectory, record) {
  await writeFile(join(processDirectory, `${record.processId}.json`), `${JSON.stringify(record)}\n`, {
    mode: 0o600,
    flag: "wx",
  });
}

async function createEmptyOutput(outputDirectory, processId) {
  const path = join(outputDirectory, `${processId}.log`);
  await writeFile(path, "", { mode: 0o600, flag: "wx" });
  return path;
}

async function readFixtureRecords(paths) {
  const valid = [];
  const corruptJson = [];
  const quarantined = [];
  for (const name of (await safeDirectory(paths.processDirectory)).filter((entry) => entry.startsWith(paths.prefix))) {
    if (name.includes(".json.corrupt-")) {
      quarantined.push(name);
      continue;
    }
    if (!name.endsWith(".json")) continue;
    try {
      const record = JSON.parse(await readFile(join(paths.processDirectory, name), "utf8"));
      const { checksum, ...unsigned } = record;
      if (checksum !== checksumRecord(unsigned)) throw new Error("checksum mismatch");
      valid.push(record);
    } catch {
      corruptJson.push(name);
    }
  }
  return { valid, corruptJson, quarantined };
}

async function readManifest(paths) {
  const manifest = JSON.parse(await readFile(paths.manifestPath, "utf8"));
  if (manifest?.fixtureId !== paths.fixtureId || manifest?.prefix !== paths.prefix) {
    throw new Error("Recovery fixture manifest identity mismatch.");
  }
  return manifest;
}

async function baselineRecordIdentities(processDirectory, prefix) {
  const identities = [];
  for (const name of (await safeDirectory(processDirectory)).filter((entry) => entry.endsWith(".json") && !entry.startsWith(prefix)).sort()) {
    identities.push({ name, sha256: digest(await readFile(join(processDirectory, name))) });
  }
  return identities;
}

async function verifyBaselineRecords(manifest) {
  const changed = [];
  let unchanged = 0;
  for (const entry of manifest.baselineRecords ?? []) {
    try {
      const observed = digest(await readFile(join(manifest.processDirectory, entry.name)));
      if (observed === entry.sha256) unchanged += 1;
      else changed.push(entry.name);
    } catch {
      changed.push(entry.name);
    }
  }
  return { checked: (manifest.baselineRecords ?? []).length, unchanged, changed };
}

async function prefixedFiles(paths) {
  const process = (await safeDirectory(paths.processDirectory))
    .filter((name) => name.startsWith(paths.prefix))
    .map((name) => join(paths.processDirectory, name));
  const output = (await safeDirectory(paths.outputDirectory))
    .filter((name) => name.startsWith(paths.prefix))
    .map((name) => join(paths.outputDirectory, name));
  return [...process, ...output];
}

async function outputFiles(paths) {
  return (await safeDirectory(paths.outputDirectory)).filter((name) => name.startsWith(paths.prefix));
}

async function removePrefixedFiles(paths) {
  const files = await prefixedFiles(paths);
  await Promise.all(files.map((path) => rm(path, { force: true })));
  return { fileCount: files.length };
}

async function safeDirectory(path) {
  try {
    return await readdir(path);
  } catch (error) {
    if (isNodeError(error, "ENOENT")) return [];
    throw error;
  }
}

function fixtureProcessId(prefix, kind, index) {
  return `${prefix}-${kind}-${String(index).padStart(4, "0")}`;
}

function countRecordStates(records) {
  const counts = {};
  for (const record of records) counts[record.state] = (counts[record.state] ?? 0) + 1;
  return counts;
}

function stableJson(value) {
  if (Array.isArray(value)) return `[${value.map(stableJson).join(",")}]`;
  if (value && typeof value === "object") {
    return `{${Object.keys(value)
      .filter((key) => value[key] !== undefined)
      .sort()
      .map((key) => `${JSON.stringify(key)}:${stableJson(value[key])}`)
      .join(",")}}`;
  }
  return JSON.stringify(value) ?? "null";
}

function digest(value) {
  return createHash("sha256").update(value).digest("hex");
}

function requiredAbsolute(value, label) {
  if (typeof value !== "string" || !value.trim()) throw new Error(`Missing ${label}.`);
  if (!isAbsolute(value)) throw new Error(`${label} must be absolute.`);
  const path = resolve(value);
  return path;
}

function isWithin(parent, child) {
  const nested = relative(parent, child);
  return nested !== "" && !nested.startsWith("..") && !isAbsolute(nested);
}

function boundedCount(value, fallback, label, maximum) {
  const observed = value ?? fallback;
  if (!Number.isSafeInteger(observed) || observed < 1 || observed > maximum) {
    throw new Error(`${label} count must be an integer from 1 through ${maximum}.`);
  }
  return observed;
}

function range(length) {
  return Array.from({ length }, (_, index) => index);
}

function assertEqual(actual, expected, label) {
  if (actual !== expected) throw new Error(`${label} mismatch: expected ${expected}, observed ${actual}.`);
}

function isNodeError(error, code) {
  return error instanceof Error && "code" in error && error.code === code;
}

const isMain = process.argv[1] && resolve(process.argv[1]) === resolve(fileURLToPath(import.meta.url));
if (isMain) {
  main().catch((error) => {
    process.stderr.write(`${error instanceof Error ? error.message : String(error)}\n`);
    process.exitCode = 1;
  });
}
