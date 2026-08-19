#!/usr/bin/env node
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import {
  chmodSync,
  closeSync,
  existsSync,
  fsyncSync,
  lstatSync,
  mkdirSync,
  openSync,
  readFileSync,
  renameSync,
  unlinkSync,
  writeFileSync,
} from "node:fs";
import { dirname, join, resolve } from "node:path";
import { homedir } from "node:os";
import Database from "better-sqlite3";

const [operation, stageId, contextPath, ...extra] = process.argv.slice(2);
if (!operation || !stageId || !contextPath || extra.length > 0 || !["readback", "apply", "final-readback"].includes(operation)) usage();

try {
  const context = readJson(contextPath);
  const prepare = readJson(context.preparePath);
  const stages = new Map(prepare.destructivePlan.map((stage) => [stage.id, stage]));
  if (operation === "final-readback") {
    const results = [];
    for (const stage of stages.values()) {
      const result = readback(stage, context, prepare);
      if (!result.complete) throw new Error(`Final readback is incomplete for ${stage.id}: ${result.message ?? "not complete"}`);
      results.push({ stageId: stage.id, evidence: result.evidence });
    }
    emit({ complete: true, stages: results });
  } else {
    const stage = stages.get(stageId);
    if (!stage) throw new Error(`Unknown finalization stage: ${stageId}`);
    const result = operation === "readback" ? readback(stage, context, prepare) : apply(stage, context, prepare);
    emit(result);
    if (!result.complete) process.exit(1);
  }
} catch (error) {
  console.error(error instanceof Error ? error.message : String(error));
  process.exit(1);
}

function readback(stage, context, prepare) {
  switch (stage.operation) {
    case "remove-file": {
      validateTemporaryTarget(stage.target, prepare);
      return { complete: !existsSync(stage.target), evidence: { path: stage.target, absent: !existsSync(stage.target) } };
    }
    case "replace-file": {
      validatePreimageTarget(stage.target, prepare);
      const expected = requireDigest(stage.expectedSha256, "expectedSha256");
      const actual = existsSync(stage.target) ? digestFile(stage.target) : undefined;
      return { complete: actual === expected, evidence: { path: stage.target, sha256: actual } };
    }
    case "pm2-delete": {
      validateProcessTarget(stage.target, prepare);
      const processes = pm2Inventory();
      const entry = processes.find((item) => item.name === stage.target);
      return { complete: !entry, evidence: { name: stage.target, present: Boolean(entry) } };
    }
    case "pm2-save": {
      return pm2SavedStateReadback(stage);
    }
    case "funnel-disable": {
      const routeKey = requiredText(stage.routeKey, "routeKey");
      const inventory = commandJson("tailscale", ["funnel", "status", "--json"]);
      const present = JSON.stringify(inventory).includes(routeKey);
      return { complete: !present, evidence: { routeKey, present, inventoryDigest: digestJson(inventory) } };
    }
    case "sqlite-revoke-token-family":
      return sqliteFamilyReadback(stage);
    case "sqlite-drain-connector":
      return sqliteConnectorReadback(stage);
    case "verify-runtime": {
      const observed = curlJson(requiredText(stage.identityUrl, "identityUrl"));
      const mismatches = runtimeMismatches(context.runtimeIdentity, observed);
      return { complete: mismatches.length === 0, evidence: { identityDigest: digestJson(observed), mismatches }, message: mismatches.join(", ") };
    }
    case "evidence-assert":
      return { complete: true, evidence: { assertion: stage.target } };
    default:
      throw new Error(`Unsupported finalization stage operation: ${stage.operation}`);
  }
}

function apply(stage, context, prepare) {
  switch (stage.operation) {
    case "remove-file": {
      validateTemporaryTarget(stage.target, prepare);
      verifyPreimageIfPresent(stage.target, prepare);
      const metadata = lstatSync(stage.target);
      if (!metadata.isFile() && !metadata.isSymbolicLink()) throw new Error(`Refusing to remove non-file finalization target: ${stage.target}`);
      unlinkSync(stage.target);
      fsyncDirectory(dirname(stage.target));
      return readback(stage, context, prepare);
    }
    case "replace-file": {
      validatePreimageTarget(stage.target, prepare);
      verifyPreimageIfPresent(stage.target, prepare);
      if (typeof stage.contentBase64 !== "string") throw new Error("replace-file contentBase64 is required.");
      const content = Buffer.from(stage.contentBase64, "base64");
      if (`sha256:${createHash("sha256").update(content).digest("hex")}` !== requireDigest(stage.expectedSha256, "expectedSha256")) {
        throw new Error("replace-file content does not match expectedSha256.");
      }
      writeFileAtomic(stage.target, content, stage.mode ?? 0o700);
      return readback(stage, context, prepare);
    }
    case "pm2-delete":
      validateProcessTarget(stage.target, prepare);
      run("pm2", ["delete", stage.target]);
      return readback(stage, context, prepare);
    case "pm2-save":
      run("pm2", ["save"]);
      return readback(stage, context, prepare);
    case "funnel-disable": {
      if (!Array.isArray(stage.arguments) || stage.arguments.some((value) => typeof value !== "string")) throw new Error("funnel-disable arguments are required.");
      if (stage.arguments[0] !== "funnel" || !stage.arguments.includes("off") || stage.arguments.some((value) => /[^A-Za-z0-9_./:=+-]/u.test(value))) {
        throw new Error("Unsafe funnel-disable argument list.");
      }
      run("tailscale", stage.arguments);
      return readback(stage, context, prepare);
    }
    case "sqlite-revoke-token-family": {
      const database = openFinalizationDatabase(stage, prepare);
      try {
        const transaction = database.transaction(() => {
          const familyId = requiredText(stage.familyId, "familyId");
          const family = database.prepare(
            "select status, connector_binding_id from oauth_token_families where family_id = ?",
          ).get(familyId);
          if (!family) throw new Error("Token family is absent from the prepared OAuth database.");
          const updated = database.prepare(
            "update oauth_token_families set status = 'REVOKED', revoked_at = coalesce(revoked_at, ?) where family_id = ? and status in ('ACTIVE', 'ROTATING')",
          ).run(new Date().toISOString(), familyId);
          if (updated.changes > 1) throw new Error("Token family update affected multiple rows.");
          if (updated.changes === 1 && family.connector_binding_id) {
            const released = database.prepare(
              "update oauth_connector_bindings set ref_count = ref_count - 1, updated_at = ? where binding_id = ? and ref_count > 0",
            ).run(new Date().toISOString(), family.connector_binding_id);
            if (released.changes !== 1) throw new Error("Connector reference could not be released with token-family revocation.");
          }
          database.prepare("delete from oauth_access_tokens where family_id = ?").run(familyId);
          database.prepare("delete from oauth_refresh_tokens where family_id = ?").run(familyId);
        });
        transaction.immediate();
      } finally { database.close(); }
      return sqliteFamilyReadback(stage);
    }
    case "sqlite-drain-connector": {
      const database = openFinalizationDatabase(stage, prepare);
      try {
        const expectedEpoch = requiredInteger(stage.expectedDrainEpoch, "expectedDrainEpoch");
        const result = database.prepare(
          `update oauth_connector_bindings
             set state = 'DRAINED', drain_epoch = drain_epoch + 1, updated_at = ?
           where binding_id = ? and state = 'DEPRECATED' and ref_count = 0 and drain_epoch = ?`,
        ).run(new Date().toISOString(), requiredText(stage.bindingId, "bindingId"), expectedEpoch);
        if (result.changes !== 1) throw new Error("Connector binding is not eligible for zero-reference drain.");
      } finally { database.close(); }
      return sqliteConnectorReadback(stage);
    }
    case "verify-runtime":
    case "evidence-assert":
      return readback(stage, context, prepare);
    default:
      throw new Error(`Unsupported finalization stage operation: ${stage.operation}`);
  }
}

function sqliteFamilyReadback(stage) {
  const database = new Database(resolve(requiredText(stage.database, "database")), { readonly: true, fileMustExist: true });
  try {
    const familyId = requiredText(stage.familyId, "familyId");
    const family = database.prepare("select status, revoked_at from oauth_token_families where family_id = ?").get(familyId);
    const access = database.prepare("select count(*) as count from oauth_access_tokens where family_id = ?").get(familyId).count;
    const refresh = database.prepare("select count(*) as count from oauth_refresh_tokens where family_id = ?").get(familyId).count;
    const complete = family?.status === "REVOKED" && typeof family.revoked_at === "string" && access === 0 && refresh === 0;
    return { complete, evidence: { familyId, status: family?.status, accessTokens: access, refreshTokens: refresh } };
  } finally { database.close(); }
}

function sqliteConnectorReadback(stage) {
  const database = new Database(resolve(requiredText(stage.database, "database")), { readonly: true, fileMustExist: true });
  try {
    const expected = requiredInteger(stage.expectedDrainEpoch, "expectedDrainEpoch") + 1;
    const row = database.prepare("select state, ref_count, drain_epoch from oauth_connector_bindings where binding_id = ?")
      .get(requiredText(stage.bindingId, "bindingId"));
    return {
      complete: row?.state === "DRAINED" && row.ref_count === 0 && row.drain_epoch === expected,
      evidence: { bindingId: stage.bindingId, state: row?.state, refCount: row?.ref_count, drainEpoch: row?.drain_epoch },
    };
  } finally { database.close(); }
}

function openFinalizationDatabase(stage, prepare) {
  const path = resolve(requiredText(stage.database, "database"));
  const known = prepare.inventories.oauth.some((entry) => resolve(entry.database ?? "") === path);
  if (!known) throw new Error(`OAuth database is not in the prepared inventory: ${path}`);
  const database = new Database(path, { fileMustExist: true });
  database.pragma("busy_timeout = 5000");
  database.pragma("foreign_keys = ON");
  return database;
}

function validateTemporaryTarget(target, prepare) {
  const path = resolve(requiredText(target, "target"));
  const known = prepare.inventories.temporaryArtifacts.some((entry) => resolve(typeof entry === "string" ? entry : entry.path) === path);
  if (!known) throw new Error(`Removal target is not in the prepared temporary inventory: ${path}`);
}

function validatePreimageTarget(target, prepare) {
  const path = resolve(requiredText(target, "target"));
  if (!prepare.preimages.some((entry) => resolve(entry.target) === path)) throw new Error(`Replacement target has no prepared preimage: ${path}`);
}

function verifyPreimageIfPresent(target, prepare) {
  const path = resolve(target);
  const preimage = prepare.preimages.find((entry) => resolve(entry.target) === path);
  if (!preimage) return;
  const observed = existsSync(path) ? digestFile(path) : "ABSENT";
  if (observed !== preimage.sha256) throw new Error(`Finalization target changed after prepare: ${path}`);
}

function validateProcessTarget(target, prepare) {
  const name = requiredText(target, "target");
  if (!prepare.inventories.processes.some((entry) => entry.name === name)) throw new Error(`PM2 process is not in the prepared inventory: ${name}`);
}

function pm2Inventory() {
  const result = run("pm2", ["jlist"], true);
  const value = JSON.parse(result.stdout);
  return value.map((entry) => ({ name: entry.name, pid: entry.pid, status: entry.pm2_env?.status }));
}

function pm2SavedStateReadback(stage) {
  if (!Array.isArray(stage.expectedProcesses) || stage.expectedProcesses.length === 0) {
    throw new Error("pm2-save requires a non-empty expectedProcesses readback set.");
  }
  const dumpPath = resolve(stage.dumpFile ?? join(process.env.PM2_HOME ?? join(homedir(), ".pm2"), "dump.pm2"));
  if (!existsSync(dumpPath)) return { complete: false, evidence: { dumpPath, present: false } };
  const saved = JSON.parse(readFileSync(dumpPath, "utf8"));
  if (!Array.isArray(saved)) throw new Error(`PM2 saved-state file is invalid: ${dumpPath}`);
  const current = pm2InventoryDetails();
  const expected = stage.expectedProcesses.map(normalizeExpectedProcess);
  const savedProcesses = saved.map((entry) => normalizeProcess(entry, entry));
  const missingCurrent = expected.filter((entry) => !current.some((candidate) => sameProcess(entry, candidate)));
  const missingSaved = expected.filter((entry) => !savedProcesses.some((candidate) => sameProcess(entry, candidate)));
  return {
    complete: missingCurrent.length === 0 && missingSaved.length === 0,
    evidence: {
      dumpPath,
      dumpSha256: digestFile(dumpPath),
      expectedDigest: digestJson(expected),
      missingCurrent,
      missingSaved,
    },
  };
}

function pm2InventoryDetails() {
  const result = run("pm2", ["jlist"], true);
  const value = JSON.parse(result.stdout);
  if (!Array.isArray(value)) throw new Error("PM2 inventory is invalid.");
  return value.map((entry) => normalizeProcess(entry, entry.pm2_env ?? {}));
}

function normalizeExpectedProcess(entry) {
  if (!entry || typeof entry !== "object") throw new Error("pm2-save expected process entry is invalid.");
  return {
    name: requiredText(entry.name, "expectedProcesses.name"),
    cwd: resolve(requiredText(entry.cwd, "expectedProcesses.cwd")),
    script: resolve(requiredText(entry.script, "expectedProcesses.script")),
  };
}

function normalizeProcess(entry, environment) {
  return {
    name: String(entry.name ?? environment.name ?? ""),
    cwd: environment.pm_cwd ? resolve(environment.pm_cwd) : "",
    script: environment.pm_exec_path ? resolve(environment.pm_exec_path) : "",
  };
}

function sameProcess(expected, observed) {
  return expected.name === observed.name && expected.cwd === observed.cwd && expected.script === observed.script;
}

function curlJson(url) {
  const result = run("curl", ["--fail", "--silent", "--show-error", "--max-time", "10", url], true);
  return JSON.parse(result.stdout);
}

function commandJson(command, arguments_) {
  return JSON.parse(run(command, arguments_, true).stdout);
}

function run(command, arguments_, capture = false) {
  const result = spawnSync(command, arguments_, { encoding: "utf8", stdio: capture ? ["ignore", "pipe", "pipe"] : ["ignore", "pipe", "pipe"], timeout: 60_000 });
  if (result.status !== 0) throw new Error(`${command} failed with exit ${result.status}: ${result.stderr?.trim() ?? ""}`);
  return result;
}

function runtimeMismatches(expected, observed) {
  const identity = observed?.identity ?? observed;
  return ["sourceRevision", "runtimeRevision", "buildDigest", "schemaGeneration", "authorityContractGeneration", "configDigest"]
    .filter((key) => expected[key] !== identity?.[key]);
}

function writeFileAtomic(path, content, mode) {
  mkdirSync(dirname(path), { recursive: true, mode: 0o700 });
  const temporary = `${path}.tmp-${process.pid}`;
  const descriptor = openSync(temporary, "wx", mode);
  try { writeFileSync(descriptor, content); fsyncSync(descriptor); } finally { closeSync(descriptor); }
  chmodSync(temporary, mode);
  renameSync(temporary, path);
  fsyncDirectory(dirname(path));
}

function fsyncDirectory(path) {
  let descriptor;
  try { descriptor = openSync(path, "r"); fsyncSync(descriptor); }
  catch (error) { if (!new Set(["EINVAL", "ENOTSUP", "EISDIR", "EPERM"]).has(error?.code)) throw error; }
  finally { if (descriptor !== undefined) closeSync(descriptor); }
}

function digestFile(path) {
  return `sha256:${createHash("sha256").update(readFileSync(path)).digest("hex")}`;
}

function digestJson(value) {
  return `sha256:${createHash("sha256").update(JSON.stringify(value)).digest("hex")}`;
}

function requiredText(value, name) {
  if (typeof value !== "string" || value.length === 0) throw new Error(`${name} is required.`);
  return value;
}

function requiredInteger(value, name) {
  if (!Number.isInteger(value) || value < 0) throw new Error(`${name} is invalid.`);
  return value;
}

function requireDigest(value, name) {
  if (typeof value !== "string" || !/^sha256:[a-f0-9]{64}$/u.test(value)) throw new Error(`${name} is invalid.`);
  return value;
}

function readJson(path) { return JSON.parse(readFileSync(resolve(path), "utf8")); }
function emit(value) { process.stdout.write(`${JSON.stringify(value)}\n`); }
function usage() { console.error("Usage: finalization-live-driver.mjs <readback|apply|final-readback> <stage-id> <context.json>"); process.exit(2); }
