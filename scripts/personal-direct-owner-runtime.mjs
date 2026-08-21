#!/usr/bin/env node
import { createHash, randomUUID } from "node:crypto";
import {
  lstat,
  readFile,
  readdir,
  rename,
  rm,
  writeFile,
} from "node:fs/promises";
import { isAbsolute, join, relative, resolve, sep } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const PROFILE = "PERSONAL_DIRECT_OWNER";
const MANIFEST_NAME = "BUILD-MANIFEST.json";

export async function createPersonalRuntimeManifest(input) {
  const root = await realDirectory(input.packageRoot, "package root");
  const manifestPath = containedPath(root, input.manifestPath ?? join(root, MANIFEST_NAME), "manifest");
  await assertAbsent(manifestPath, "Runtime manifest already exists");
  const sourceRevision = revision(input.sourceRevision, "source revision");
  const runtimeRevision = revision(input.runtimeRevision, "runtime revision");
  const files = await snapshotFiles(root, relative(root, manifestPath));
  const buildDigest = digest(files);
  const buildCapabilities = await buildCapabilitiesFromGeneratedContract(root, buildDigest);
  if (buildCapabilities.productProfile !== PROFILE || "authorityContractGeneration" in buildCapabilities) {
    throw new Error("Built capabilities are not the Personal Direct Owner contract.");
  }
  const packageIdentity = JSON.parse(await readFile(join(root, "package.json"), "utf8"));
  const manifest = {
    schemaVersion: 1,
    productProfile: PROFILE,
    packageName: packageIdentity.name,
    packageVersion: packageIdentity.version,
    sourceRevision,
    runtimeRevision,
    buildDigest,
    schemaGeneration: buildCapabilities.schemaGeneration,
    buildCapabilities,
    runtime: {
      entrypoint: "scripts/start-universal-broker-v2-production.sh",
      nodeEntrypoint: "dist/cli.js",
      dependencyMode: "external-node-modules-loader-v1",
    },
    files,
  };
  const bytes = Buffer.from(`${JSON.stringify(manifest, null, 2)}\n`);
  const temporary = `${manifestPath}.next-${randomUUID()}`;
  try {
    await writeFile(temporary, bytes, { flag: "wx", mode: 0o600 });
    await rename(temporary, manifestPath);
  } finally {
    await rm(temporary, { force: true });
  }
  return { manifest, manifestPath, manifestSha256: bufferDigest(bytes) };
}

async function buildCapabilitiesFromGeneratedContract(root, buildDigest) {
  const schema = JSON.parse(await readFile(join(root, "contracts", "build-capabilities.schema.json"), "utf8"));
  const properties = schema.properties ?? {};
  const runtimeIdentity = await import(pathToFileURL(join(root, "dist/v2/runtime-contract-identity.js")).href);
  const supportedOperations = Object.fromEntries(Object.entries(
    properties.supportedOperations?.properties ?? {},
  ).map(([name, value]) => [name, value.const]));
  const contract = {
    productVersion: properties.productVersion?.const,
    productProfile: properties.productProfile?.const,
    schemaGeneration: runtimeIdentity.RUNTIME_SCHEMA_GENERATION,
    supportedProfiles: properties.supportedProfiles?.const,
    supportedOperations,
    resourceUriVersion: properties.resourceUriVersion?.const,
  };
  if (contract.productProfile !== PROFILE
      || !Array.isArray(contract.supportedProfiles)
      || contract.supportedProfiles.length !== 1
      || contract.supportedProfiles[0] !== PROFILE
      || Object.keys(supportedOperations).length !== 8) {
    throw new Error("Generated build capability contract is not Personal Direct Owner.");
  }
  return {
    ...contract,
    buildDigest,
    capabilityDigest: bufferDigest(Buffer.from(canonicalJson(contract))),
  };
}

export async function verifyPersonalRuntime(input) {
  const root = await realDirectory(input.packageRoot, "package root");
  const manifestPath = containedPath(root, input.manifestPath, "manifest");
  const manifestBytes = await ownerRegularFile(manifestPath, "runtime manifest");
  const manifestSha256 = bufferDigest(manifestBytes);
  if (input.manifestSha256 && manifestSha256 !== canonicalDigest(input.manifestSha256, "manifest SHA-256")) {
    throw new Error("Runtime manifest digest mismatch.");
  }
  const manifest = JSON.parse(manifestBytes.toString("utf8"));
  if (manifest.schemaVersion !== 1 || manifest.productProfile !== PROFILE) {
    throw new Error("Runtime manifest profile or version is invalid.");
  }
  if (input.sourceRevision && manifest.sourceRevision !== revision(input.sourceRevision, "source revision")) {
    throw new Error("Runtime source revision mismatch.");
  }
  if (input.runtimeRevision && manifest.runtimeRevision !== revision(input.runtimeRevision, "runtime revision")) {
    throw new Error("Runtime revision mismatch.");
  }
  if (manifest.buildCapabilities?.productProfile !== PROFILE
      || "authorityContractGeneration" in (manifest.buildCapabilities ?? {})) {
    throw new Error("Runtime build capabilities are not personal.");
  }
  const entrypoint = containedPath(root, input.entrypoint, "entrypoint");
  const expectedEntrypoint = join(root, manifest.runtime?.entrypoint ?? "");
  if (entrypoint !== expectedEntrypoint) throw new Error("Runtime entrypoint mismatch.");
  await ownerRegularFile(entrypoint, "runtime entrypoint", false);
  const observedFiles = await snapshotFiles(root, relative(root, manifestPath));
  if (JSON.stringify(observedFiles) !== JSON.stringify(manifest.files)
      || digest(observedFiles) !== manifest.buildDigest) {
    throw new Error("Runtime package content differs from its immutable manifest.");
  }
  const dependency = await verifyDependencyReuse(root, input);
  return {
    status: "PASS",
    productProfile: PROFILE,
    sourceRevision: manifest.sourceRevision,
    runtimeRevision: manifest.runtimeRevision,
    buildDigest: manifest.buildDigest,
    manifestSha256,
    dependency,
  };
}

async function verifyDependencyReuse(root, input) {
  const dependencyRoot = await realDirectory(input.dependencyRoot, "dependency root");
  if (overlap(root, dependencyRoot)) throw new Error("Dependency root must remain outside the runtime package.");
  await realDirectory(join(dependencyRoot, "node_modules"), "dependency node_modules");
  const evidenceBytes = await ownerRegularFile(input.dependencyEvidence, "dependency evidence");
  const evidenceSha256 = bufferDigest(evidenceBytes);
  if (evidenceSha256 !== canonicalDigest(input.dependencyEvidenceSha256, "dependency evidence SHA-256")) {
    throw new Error("Runtime dependency evidence digest mismatch.");
  }
  const evidence = JSON.parse(evidenceBytes.toString("utf8"));
  const runtimeLockSha256 = bufferDigest(await readFile(join(root, "package-lock.json")));
  const dependencyLockSha256 = bufferDigest(await readFile(join(dependencyRoot, "package-lock.json")));
  if (runtimeLockSha256 !== dependencyLockSha256 || evidence.lockfileSha256 !== runtimeLockSha256) {
    throw new Error("Runtime dependency lockfile identity mismatch.");
  }
  if (evidence.nodeVersion !== process.version || evidence.platform !== `${process.platform}-${process.arch}`) {
    throw new Error("Runtime dependency platform identity mismatch.");
  }
  if (!evidence.nodeModules?.sha256) throw new Error("Runtime dependency tree evidence is incomplete.");
  return { dependencyRoot, evidenceSha256, lockfileSha256: runtimeLockSha256 };
}

async function snapshotFiles(root, excludedRelativePath) {
  const files = [];
  const visit = async (directory) => {
    const entries = await readdir(directory, { withFileTypes: true });
    entries.sort((left, right) => left.name.localeCompare(right.name));
    for (const entry of entries) {
      const path = join(directory, entry.name);
      const relativePath = relative(root, path).split(sep).join("/");
      if (relativePath === excludedRelativePath || relativePath === "SHA256SUMS") continue;
      if (entry.isSymbolicLink()) throw new Error(`Runtime package contains a symlink: ${relativePath}`);
      if (entry.isDirectory()) await visit(path);
      else if (entry.isFile()) files.push({ path: relativePath, sha256: bufferDigest(await readFile(path)) });
      else throw new Error(`Runtime package contains an unsupported entry: ${relativePath}`);
    }
  };
  await visit(root);
  return files;
}

async function realDirectory(path, label) {
  if (typeof path !== "string" || !isAbsolute(path)) throw new Error(`${label} must be absolute.`);
  const resolved = resolve(path);
  const metadata = await lstat(resolved);
  if (!metadata.isDirectory() || metadata.isSymbolicLink()) throw new Error(`${label} must be a real directory.`);
  return resolved;
}

async function ownerRegularFile(path, label, ownerOnly = true) {
  if (typeof path !== "string" || !isAbsolute(path)) throw new Error(`${label} must be absolute.`);
  const metadata = await lstat(path);
  if (!metadata.isFile() || metadata.isSymbolicLink() || (ownerOnly && (metadata.mode & 0o077) !== 0)) {
    throw new Error(`${label} must be an owner-only regular file.`);
  }
  return readFile(path);
}

function containedPath(root, path, label) {
  if (typeof path !== "string" || !isAbsolute(path)) throw new Error(`${label} must be absolute.`);
  const resolved = resolve(path);
  const child = relative(root, resolved);
  if (child === ".." || child.startsWith(`..${sep}`) || isAbsolute(child)) {
    throw new Error(`${label} must stay inside the runtime package.`);
  }
  return resolved;
}

async function assertAbsent(path, message) {
  try {
    await lstat(path);
  } catch (error) {
    if (error?.code === "ENOENT") return;
    throw error;
  }
  throw new Error(`${message}: ${path}`);
}

function overlap(left, right) {
  const leftToRight = relative(left, right);
  const rightToLeft = relative(right, left);
  return leftToRight === "" || (!leftToRight.startsWith(`..${sep}`) && leftToRight !== "..")
    || (!rightToLeft.startsWith(`..${sep}`) && rightToLeft !== "..");
}

function revision(value, label) {
  if (typeof value !== "string" || !/^[a-f0-9]{40}$/u.test(value)) throw new Error(`${label} must be a Git SHA-1.`);
  return value;
}

function digest(value) {
  return bufferDigest(Buffer.from(JSON.stringify(value)));
}

function canonicalJson(value) {
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  if (value && typeof value === "object") {
    return `{${Object.entries(value)
      .filter(([, child]) => child !== undefined)
      .sort(([left], [right]) => left.localeCompare(right))
      .map(([key, child]) => `${JSON.stringify(key)}:${canonicalJson(child)}`)
      .join(",")}}`;
  }
  return JSON.stringify(value) ?? "null";
}

function bufferDigest(value) {
  return `sha256:${createHash("sha256").update(value).digest("hex")}`;
}

function canonicalDigest(value, label) {
  if (typeof value !== "string" || !/^sha256:[a-f0-9]{64}$/u.test(value)) throw new Error(`${label} is invalid.`);
  return value;
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

function required(options, key) {
  const value = options.get(key);
  if (!value) throw new Error(`--${key} is required.`);
  return resolve(value);
}

async function main() {
  const [command, ...values] = process.argv.slice(2);
  const options = parseOptions(values);
  if (command === "create") {
    const result = await createPersonalRuntimeManifest({
      packageRoot: required(options, "package"),
      manifestPath: options.has("manifest") ? required(options, "manifest") : undefined,
      sourceRevision: options.get("source-revision"),
      runtimeRevision: options.get("runtime-revision"),
    });
    process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
  } else if (command === "verify") {
    const result = await verifyPersonalRuntime({
      packageRoot: required(options, "package"),
      entrypoint: required(options, "entrypoint"),
      manifestPath: required(options, "manifest"),
      manifestSha256: options.get("manifest-sha256"),
      sourceRevision: options.get("source-revision"),
      runtimeRevision: options.get("runtime-revision"),
      dependencyRoot: required(options, "dependency-root"),
      dependencyEvidence: required(options, "dependency-evidence"),
      dependencyEvidenceSha256: options.get("dependency-evidence-sha256"),
    });
    process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
  } else {
    throw new Error("Usage: personal-direct-owner-runtime.mjs <create|verify> --package PATH ...");
  }
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) await main();
