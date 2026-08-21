#!/usr/bin/env node
import { spawnSync } from "node:child_process";
import { randomUUID } from "node:crypto";
import {
  copyFile,
  cp,
  lstat,
  mkdir,
  readFile,
  readlink,
  rename,
  rm,
  symlink,
  writeFile,
} from "node:fs/promises";
import { dirname, join, resolve } from "node:path";
import {
  assertPersonalProductionReadback,
  createPersonalUpgradePlan,
} from "../dist/v2/personal-upgrade.js";
import { waitForHealthyPersonalRuntime } from "./lib/personal-runtime-health.mjs";

const [command = "plan", ...argumentsList] = process.argv.slice(2);
const options = parseArguments(argumentsList);
const requestPath = requiredOption(options, "request");
const request = JSON.parse(await readFile(requestPath, "utf8"));
const plan = createPersonalUpgradePlan(request.upgrade);

if (command === "plan") {
  process.stdout.write(`${JSON.stringify(plan, null, 2)}\n`);
} else if (command === "verify-readback") {
  assertPersonalProductionReadback(request.upgrade.candidate, request.observed);
  process.stdout.write(`${JSON.stringify({ status: "PASS", runtimeRevision: plan.runtimeRevision })}\n`);
} else if (command === "apply") {
  await applyRuntimeUpgrade(request, plan);
} else if (command === "status") {
  const pointer = await readlink(plan.currentRuntimePointer);
  process.stdout.write(`${JSON.stringify({
    productProfile: plan.productProfile,
    currentRuntimePointer: plan.currentRuntimePointer,
    resolvedRuntime: resolve(dirname(plan.currentRuntimePointer), pointer),
  }, null, 2)}\n`);
} else {
  throw new Error("Usage: personal-direct-owner-upgrade.mjs <plan|apply|status|verify-readback> --request FILE");
}

async function applyRuntimeUpgrade(request, plan) {
  const apply = request.apply ?? {};
  const productionEnvironment = absolute(apply.productionEnvironment, "apply.productionEnvironment");
  const candidateEnvironment = absolute(apply.candidateEnvironment, "apply.candidateEnvironment");
  const auditDirectory = absolute(apply.auditDirectory, "apply.auditDirectory");
  const productionProcess = processName(apply.productionProcess, "apply.productionProcess");
  const candidateProcess = processName(apply.candidateProcess, "apply.candidateProcess");
  const productionHealthUrl = httpsOrLoopbackUrl(apply.productionHealthUrl, "apply.productionHealthUrl");
  const candidateHealthUrl = httpsOrLoopbackUrl(apply.candidateHealthUrl, "apply.candidateHealthUrl");
  await assertOwnerFile(productionEnvironment);
  await assertOwnerFile(candidateEnvironment);
  await assertPreservedEnvironment(productionEnvironment, candidateEnvironment);
  await waitForHealthyPersonalRuntime(candidateHealthUrl, plan.runtimeRevision);
  await mkdir(auditDirectory, { recursive: false, mode: 0o700 });
  const oldPointer = await readlink(plan.currentRuntimePointer);
  const oldRuntime = resolve(dirname(plan.currentRuntimePointer), oldPointer);
  if (oldRuntime !== plan.existingRuntimePath) {
    throw new Error("Current runtime pointer differs from the reviewed existing runtime.");
  }
  const environmentPreimage = join(auditDirectory, "production.env.before");
  await copyFile(productionEnvironment, environmentPreimage);
  await writeFile(join(auditDirectory, "PLAN.json"), JSON.stringify(plan, null, 2), { mode: 0o600 });
  await backupStores(plan.backupSet, auditDirectory);

  let pointerSwitched = false;
  let environmentSwitched = false;
  try {
    await atomicSymlink(plan.candidateRuntimePath, plan.currentRuntimePointer);
    pointerSwitched = true;
    await atomicFileReplacement(candidateEnvironment, productionEnvironment);
    environmentSwitched = true;
    run("pm2", ["delete", candidateProcess], { allowFailure: true });
    run("pm2", ["delete", productionProcess], { allowFailure: true });
    run("pm2", [
      "start",
      join(plan.currentRuntimePointer, "scripts", "start-universal-broker-v2-production.sh"),
      "--name",
      productionProcess,
      "--cwd",
      plan.currentRuntimePointer,
    ]);
    await waitForHealthyPersonalRuntime(productionHealthUrl, plan.runtimeRevision);
    process.stdout.write(`${JSON.stringify({
      status: "SWITCHED_PENDING_ACTUAL_HOST_VERIFICATION",
      runtimeRevision: plan.runtimeRevision,
      currentRuntimePointer: plan.currentRuntimePointer,
      backupSet: plan.backupSet.map((store) => store.id),
      auditDirectory,
    })}\n`);
  } catch (error) {
    if (environmentSwitched) await atomicFileReplacement(environmentPreimage, productionEnvironment).catch(() => undefined);
    if (pointerSwitched) await atomicSymlink(oldRuntime, plan.currentRuntimePointer).catch(() => undefined);
    await restoreStores(plan.backupSet, auditDirectory).catch(() => undefined);
    run("pm2", ["delete", productionProcess], { allowFailure: true });
    run("pm2", [
      "start",
      join(oldRuntime, "scripts", "start-universal-broker-v2-production.sh"),
      "--name",
      productionProcess,
      "--cwd",
      oldRuntime,
    ], { allowFailure: true });
    throw error;
  }
}

async function backupStores(stores, auditDirectory) {
  const root = join(auditDirectory, "stores");
  await mkdir(root, { recursive: true, mode: 0o700 });
  for (const store of stores) {
    const destination = join(root, store.id);
    if (store.kind === "sqlite") {
      run("sqlite3", [store.path, `.backup '${destination.replaceAll("'", "''")}'`]);
      run("sqlite3", [destination, "PRAGMA quick_check;"]);
    } else {
      await cp(store.path, destination, { recursive: store.kind === "directory", preserveTimestamps: true });
    }
  }
}

async function restoreStores(stores, auditDirectory) {
  const root = join(auditDirectory, "stores");
  for (const store of [...stores].reverse()) {
    const source = join(root, store.id);
    if (store.kind === "sqlite") {
      run("sqlite3", [source, `.backup '${store.path.replaceAll("'", "''")}'`]);
    } else {
      await rm(store.path, { recursive: true, force: true });
      await cp(source, store.path, { recursive: store.kind === "directory", preserveTimestamps: true });
    }
  }
}

async function assertPreservedEnvironment(existingPath, candidatePath) {
  const [existing, candidate] = await Promise.all([
    parseEnvironment(existingPath),
    parseEnvironment(candidatePath),
  ]);
  for (const field of [
    { label: "public origin", keys: ["DEVSPACE_NEXT_PUBLIC_BASE_URL"], required: true },
    { label: "OAuth issuer", keys: ["DEVSPACE_NEXT_OAUTH_ISSUER", "DEVSPACE_OAUTH_ISSUER"] },
    { label: "OAuth resource", keys: ["DEVSPACE_OAUTH_RESOURCE"] },
    { label: "OAuth client", keys: ["DEVSPACE_OAUTH_CLIENT_ID"] },
    {
      label: "owner instance",
      keys: ["DEVSPACE_OAUTH_OWNER_INSTANCE_ID", "DEVSPACE_NEXT_AUTHORITY_OWNER_INSTANCE_ID"],
      required: true,
    },
    { label: "canonical connector", keys: ["DEVSPACE_OAUTH_CANONICAL_CONNECTOR_NAME"], required: true },
    { label: "connector installation epoch", keys: ["DEVSPACE_OAUTH_CONNECTOR_INSTALLATION_EPOCH"], required: true },
  ]) {
    const existingValue = firstEnvironmentValue(existing, field.keys);
    const candidateValue = firstEnvironmentValue(candidate, field.keys);
    if ((field.required && !existingValue) || existingValue !== candidateValue) {
      throw new Error(`Candidate environment must preserve ${field.label}.`);
    }
  }
}

function firstEnvironmentValue(environment, keys) {
  for (const key of keys) {
    const value = environment.get(key);
    if (value) return value;
  }
  return undefined;
}

async function parseEnvironment(path) {
  const values = new Map();
  for (const line of (await readFile(path, "utf8")).split(/\r?\n/u)) {
    if (!line || /^\s*#/u.test(line)) continue;
    const match = /^([A-Z][A-Z0-9_]*)=(.*)$/u.exec(line);
    if (match) values.set(match[1], match[2]);
  }
  return values;
}

async function atomicSymlink(target, pointer) {
  await mkdir(dirname(pointer), { recursive: true, mode: 0o700 });
  const temporary = `${pointer}.next-${randomUUID()}`;
  try {
    await symlink(target, temporary);
    await rename(temporary, pointer);
  } finally {
    await rm(temporary, { force: true });
  }
}

async function atomicFileReplacement(source, destination) {
  const temporary = `${destination}.next-${randomUUID()}`;
  try {
    await copyFile(source, temporary);
    await rename(temporary, destination);
  } finally {
    await rm(temporary, { force: true });
  }
}

async function assertOwnerFile(path) {
  const metadata = await lstat(path);
  if (!metadata.isFile() || metadata.isSymbolicLink() || (metadata.mode & 0o077) !== 0) {
    throw new Error(`Owner-only regular file required: ${path}`);
  }
}

function run(command, args, options = {}) {
  const result = spawnSync(command, args, { encoding: "utf8", stdio: options.allowFailure ? "ignore" : "pipe" });
  if (!options.allowFailure && result.status !== 0) {
    throw new Error(`${command} failed with status ${result.status}: ${(result.stderr ?? "").trim()}`);
  }
}

function parseArguments(values) {
  const result = new Map();
  for (let index = 0; index < values.length; index += 2) {
    const key = values[index];
    const value = values[index + 1];
    if (!key?.startsWith("--") || value === undefined) throw new Error("Options must use --name value pairs.");
    result.set(key.slice(2), value);
  }
  return result;
}

function requiredOption(optionsMap, key) {
  const value = optionsMap.get(key);
  if (!value) throw new Error(`--${key} is required.`);
  return resolve(value);
}

function absolute(value, label) {
  if (typeof value !== "string" || !value.startsWith("/")) throw new Error(`${label} must be absolute.`);
  return resolve(value);
}

function processName(value, label) {
  if (typeof value !== "string" || !/^[A-Za-z0-9._-]+$/u.test(value)) throw new Error(`${label} is invalid.`);
  return value;
}

function httpsOrLoopbackUrl(value, label) {
  const parsed = new URL(value);
  if (parsed.protocol === "https:") return parsed.href;
  if (parsed.protocol === "http:" && ["127.0.0.1", "localhost", "::1"].includes(parsed.hostname)) return parsed.href;
  throw new Error(`${label} must be HTTPS or loopback HTTP.`);
}
