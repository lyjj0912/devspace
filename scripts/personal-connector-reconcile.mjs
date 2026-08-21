#!/usr/bin/env node
import { spawnSync } from "node:child_process";
import { createHash, randomUUID } from "node:crypto";
import { createReadStream } from "node:fs";
import {
  chmod,
  lstat,
  mkdir,
  readFile,
  realpath,
  stat,
  writeFile,
} from "node:fs/promises";
import { dirname, join, resolve } from "node:path";
import { databasePath } from "../dist/db/client.js";
import { SqliteOAuthStore } from "../dist/oauth-store.js";

const [command = "status", ...argumentList] = process.argv.slice(2);
const options = parseOptions(argumentList);

if (command === "status") {
  const stateDir = await existingDirectory(required(options, "state-dir"), "state directory");
  const expectation = expectationOptions(options);
  const store = new SqliteOAuthStore(stateDir);
  try {
    process.stdout.write(`${JSON.stringify({
      status: "OBSERVED",
      stateDir,
      databasePath: databasePath(stateDir),
      readiness: store.personalConnectorReadiness(expectation),
    }, null, 2)}\n`);
  } finally {
    store.close();
  }
} else if (command === "plan") {
  const stateDir = await existingDirectory(required(options, "state-dir"), "state directory");
  const outputPath = absolute(required(options, "output"), "output");
  const expectation = expectationOptions(options);
  const store = new SqliteOAuthStore(stateDir);
  try {
    const plan = store.planPersonalConnectorReconciliation(expectation);
    await writeExclusiveJson(outputPath, plan);
    process.stdout.write(`${JSON.stringify({
      status: "PLANNED",
      outputPath,
      planId: plan.planId,
      planDigest: plan.planDigest,
      preimageDigest: plan.preimageDigest,
      actionCount: plan.actions.length,
      blockers: plan.blockers,
      readinessBefore: plan.readinessBefore,
    }, null, 2)}\n`);
  } finally {
    store.close();
  }
} else if (command === "apply") {
  const stateDir = await existingDirectory(required(options, "state-dir"), "state directory");
  const planPath = await ownerOnlyExistingFile(required(options, "plan"), "reconciliation plan");
  const backupDir = absolute(required(options, "backup-dir"), "backup directory");
  const outputPath = absolute(required(options, "output"), "output");
  await assertAbsent(backupDir, "backup directory");
  await assertAbsent(outputPath, "result output");
  const plan = JSON.parse(await readFile(planPath, "utf8"));
  const sourceDatabase = await ownerOnlyExistingFile(
    databasePath(stateDir),
    "OAuth database",
  );
  await mkdir(backupDir, { recursive: false, mode: 0o700 });
  await chmod(backupDir, 0o700);
  const backupPath = join(backupDir, "devspace.sqlite.before-personal-connector-reconciliation.sqlite");
  const backupManifestPath = join(backupDir, "BACKUP-MANIFEST.json");
  const sourceBefore = await fileIdentity(sourceDatabase);
  createSqliteBackup(sourceDatabase, backupPath);
  await chmod(backupPath, 0o600);
  const backupVerification = verifySqliteDatabase(backupPath);
  const backupIdentity = await fileIdentity(backupPath);
  const backupManifest = {
    schemaVersion: 1,
    backupId: `personal-connector-backup-${randomUUID()}`,
    createdAt: new Date().toISOString(),
    stateDir,
    sourceDatabase,
    sourceBefore,
    backupPath,
    backupIdentity,
    backupVerification,
    planPath,
    planId: plan.planId,
    planDigest: plan.planDigest,
    preimageDigest: plan.preimageDigest,
    restoreCommand: [
      "sqlite3",
      backupPath,
      `.backup '${sqliteQuote(sourceDatabase)}'`,
    ],
    retentionCondition:
      "Retain until the new runtime, Personal connector readiness, token refresh, restart, and actual-host A-J evidence are independently verified.",
  };
  await writeExclusiveJson(backupManifestPath, backupManifest);

  const store = new SqliteOAuthStore(stateDir);
  let result;
  try {
    result = store.applyPersonalConnectorReconciliation(plan);
  } finally {
    store.close();
  }
  const sourceAfter = await fileIdentity(sourceDatabase);
  const output = {
    ...result,
    stateDir,
    sourceDatabase,
    sourceBefore,
    sourceAfter,
    backupPath,
    backupManifestPath,
    backupIdentity,
    backupVerification,
  };
  await writeExclusiveJson(outputPath, output);
  process.stdout.write(`${JSON.stringify({
    status: result.status,
    outputPath,
    backupManifestPath,
    backupPath,
    planId: result.planId,
    planDigest: result.planDigest,
    preimageDigest: result.preimageDigest,
    postimageDigest: result.postimageDigest,
    readinessAfter: result.readinessAfter,
  }, null, 2)}\n`);
} else {
  throw new Error(
    "Usage: personal-connector-reconcile.mjs <status|plan|apply> --state-dir DIR ...",
  );
}

function expectationOptions(optionsMap) {
  const installationEpoch = Number(required(optionsMap, "installation-epoch"));
  if (!Number.isSafeInteger(installationEpoch) || installationEpoch <= 0) {
    throw new Error("--installation-epoch must be a positive integer.");
  }
  return {
    canonicalName: required(optionsMap, "canonical-name"),
    installationEpoch,
    schemaGeneration: required(optionsMap, "schema-generation"),
    resource: required(optionsMap, "resource"),
  };
}

function parseOptions(values) {
  const result = new Map();
  for (let index = 0; index < values.length; index += 2) {
    const key = values[index];
    const value = values[index + 1];
    if (!key?.startsWith("--") || value === undefined) {
      throw new Error("Options must use --name value pairs.");
    }
    result.set(key.slice(2), value);
  }
  return result;
}

function required(optionsMap, key) {
  const value = optionsMap.get(key);
  if (!value) throw new Error(`--${key} is required.`);
  return value;
}

function absolute(value, label) {
  if (!value.startsWith("/")) throw new Error(`${label} must be absolute.`);
  return resolve(value);
}

async function existingDirectory(value, label) {
  const path = await realpath(absolute(value, label));
  const metadata = await lstat(path);
  if (!metadata.isDirectory() || metadata.isSymbolicLink()) {
    throw new Error(`${label} must be a real directory.`);
  }
  return path;
}

async function ownerOnlyExistingFile(value, label) {
  const path = await realpath(absolute(value, label));
  const metadata = await lstat(path);
  if (!metadata.isFile() || metadata.isSymbolicLink() || (metadata.mode & 0o077) !== 0) {
    throw new Error(`${label} must be an owner-only regular file.`);
  }
  return path;
}

async function assertAbsent(path, label) {
  try {
    await lstat(path);
  } catch (error) {
    if (error && typeof error === "object" && "code" in error && error.code === "ENOENT") return;
    throw error;
  }
  throw new Error(`${label} already exists: ${path}`);
}

function createSqliteBackup(source, destination) {
  const result = spawnSync(
    "/usr/bin/sqlite3",
    [source, `.backup '${sqliteQuote(destination)}'`],
    { encoding: "utf8", stdio: "pipe" },
  );
  if (result.error) throw result.error;
  if (result.status !== 0) {
    throw new Error(`SQLite backup failed: ${(result.stderr ?? result.stdout ?? "").trim()}`);
  }
}

function verifySqliteDatabase(path) {
  const result = spawnSync(
    "/usr/bin/sqlite3",
    ["-batch", "-noheader", path, "PRAGMA quick_check; SELECT count(*) FROM pragma_foreign_key_check;"],
    { encoding: "utf8", stdio: "pipe" },
  );
  if (result.error) throw result.error;
  if (result.status !== 0) {
    throw new Error(`SQLite backup verification failed: ${(result.stderr ?? result.stdout ?? "").trim()}`);
  }
  const lines = result.stdout.trim().split(/\r?\n/u);
  if (lines[0] !== "ok" || lines[1] !== "0") {
    throw new Error(`SQLite backup is inconsistent: ${result.stdout.trim()}`);
  }
  return { quickCheck: lines[0], foreignKeyViolations: Number(lines[1]) };
}

async function fileIdentity(path) {
  const metadata = await stat(path);
  return {
    path,
    bytes: metadata.size,
    mode: (metadata.mode & 0o777).toString(8).padStart(3, "0"),
    mtime: metadata.mtime.toISOString(),
    sha256: await sha256File(path),
  };
}

async function sha256File(path) {
  const digest = createHash("sha256");
  for await (const chunk of createReadStream(path)) digest.update(chunk);
  return `sha256:${digest.digest("hex")}`;
}

async function writeExclusiveJson(path, value) {
  await mkdir(dirname(path), { recursive: true, mode: 0o700 });
  await writeFile(path, `${JSON.stringify(value, null, 2)}\n`, {
    encoding: "utf8",
    flag: "wx",
    mode: 0o600,
  });
  await chmod(path, 0o600);
}

function sqliteQuote(value) {
  return value.replaceAll("'", "''");
}
