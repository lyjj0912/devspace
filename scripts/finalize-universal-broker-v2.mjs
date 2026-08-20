#!/usr/bin/env node
import { createHash } from "node:crypto";
import { lstatSync, readFileSync, realpathSync } from "node:fs";
import { isAbsolute, join, resolve } from "node:path";
import { loadExistingManagementAuthorizationKey } from "../dist/v2/management-authorization.js";
import {
  readFinalizationStoreIdentity,
  readFinalizationStoreLedger,
} from "./lib/finalization-store-contract.mjs";

const [command, ...arguments_] = process.argv.slice(2);
const options = parseOptions(arguments_);

try {
  if (!["status", "verify"].includes(command)) usage();
  const storePath = requiredAbsolute(options, "store");
  const controlPath = requiredAbsolute(options, "control");
  const stateDir = requiredAbsolute(options, "state-dir");
  const keyRef = required(options, "key-ref");
  const key = loadExistingManagementAuthorizationKey({ keyRef, stateDir });
  const identity = readFinalizationStoreIdentity({ storePath, controlPath, key });
  const ledger = readFinalizationStoreLedger({ storePath, controlPath, key });
  const result = command === "status"
    ? { status: identity.state, identity, eventCount: ledger.events.length }
    : verifyFinalization({ identity, ledger, auditRoot: requiredAbsolute(options, "audit") });
  console.log(JSON.stringify(result, null, 2));
} catch (error) {
  console.error(error instanceof Error ? error.message : String(error));
  process.exitCode = 1;
}

function verifyFinalization({ identity, ledger, auditRoot }) {
  if (identity.state !== "BASE_PROFILE_FINAL_PASS" || !/^sha256:[a-f0-9]{64}$/u.test(identity.finalDigest ?? "")) {
    throw new Error(`Finalization is not BASE_PROFILE_FINAL_PASS: ${identity.state}`);
  }
  const root = canonicalDirectory(auditRoot, "finalization audit root");
  const indexPath = canonicalFile(join(root, "finalization", "evidence", "artifact-index.json"), "finalization artifact index");
  const indexBytes = readFileSync(indexPath);
  const index = JSON.parse(indexBytes.toString("utf8"));
  if (index?.schemaVersion !== 1 || index.transactionId !== identity.transactionId
    || index.finalDigest !== identity.finalDigest || !Array.isArray(index.artifacts) || index.artifacts.length < 6) {
    throw new Error("Finalization artifact index differs from the authenticated terminal identity.");
  }
  for (const artifact of index.artifacts) {
    const path = canonicalFile(artifact?.path, "finalization evidence artifact");
    const sha256 = `sha256:${createHash("sha256").update(readFileSync(path)).digest("hex")}`;
    if (sha256 !== artifact.sha256) throw new Error(`Finalization evidence digest changed: ${path}`);
  }
  const requiredStates = [
    "PREPARED", "PROFILE_GATES_EVALUATED", "ACTIVATION_PENDING", "POST_ACTIVATION_VERIFIED",
    "DRAINING", "SEALED", "BASE_PROFILE_FINAL_PASS",
  ];
  const observedStates = ledger.events.map((event) => event.toState);
  if (JSON.stringify(observedStates) !== JSON.stringify(requiredStates)) {
    throw new Error(`Finalization event sequence is incomplete: ${observedStates.join(",")}`);
  }
  return {
    status: "BASE_PROFILE_FINAL_PASS",
    identity,
    eventCount: ledger.events.length,
    artifactIndex: {
      path: indexPath,
      sha256: `sha256:${createHash("sha256").update(indexBytes).digest("hex")}`,
      artifacts: index.artifacts.length,
    },
  };
}

function parseOptions(values) {
  const output = new Map();
  for (let index = 0; index < values.length; index += 2) {
    const name = values[index];
    const value = values[index + 1];
    if (!name?.startsWith("--") || value === undefined || output.has(name.slice(2))) usage();
    output.set(name.slice(2), value);
  }
  return output;
}

function required(values, key) {
  const value = values.get(key);
  if (!value) throw new Error(`--${key} is required.`);
  return value;
}

function requiredAbsolute(values, key) {
  const value = required(values, key);
  if (!isAbsolute(value) || resolve(value) !== value) throw new Error(`--${key} must be an absolute path.`);
  return value;
}

function canonicalFile(value, label) {
  if (typeof value !== "string" || !isAbsolute(value) || resolve(value) !== value) {
    throw new Error(`${label} path is invalid.`);
  }
  const metadata = lstatSync(value);
  if (!metadata.isFile() || metadata.isSymbolicLink() || realpathSync(value) !== value
    || (metadata.mode & 0o077) !== 0) throw new Error(`${label} must be an owner-only canonical file.`);
  return value;
}

function canonicalDirectory(value, label) {
  const metadata = lstatSync(value);
  if (!metadata.isDirectory() || metadata.isSymbolicLink() || realpathSync(value) !== value) {
    throw new Error(`${label} must be a canonical directory.`);
  }
  return value;
}

function usage() {
  console.error("Usage: finalize-universal-broker-v2.mjs <status|verify> --store FILE --control FILE --state-dir DIR --key-ref REF [--audit DIR]");
  process.exit(2);
}
