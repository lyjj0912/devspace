#!/usr/bin/env node
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import {
  chmod,
  copyFile,
  lstat,
  mkdir,
  readFile,
  readdir,
  realpath,
  rm,
  stat,
  writeFile,
} from "node:fs/promises";
import { dirname, isAbsolute, join, relative, resolve, sep } from "node:path";
import { fileURLToPath } from "node:url";
import {
  createPersonalRuntimeManifest,
  verifyPersonalRuntime,
} from "./personal-direct-owner-runtime.mjs";

const PROFILE = "PERSONAL_DIRECT_OWNER";
const SOURCE_GATE_NAME = "SOURCE-GATE.json";
const MANIFEST_NAME = "BUILD-MANIFEST.json";
const CHECKSUM_NAME = "SHA256SUMS";
const TRACKED_PAYLOADS = Object.freeze([
  "package.json",
  "package-lock.json",
  "config",
  "contracts",
  "scripts",
  "skills",
]);

export async function createPersonalReleasePackage(input) {
  const sourceRoot = await realDirectory(input.sourceRoot, "source root");
  const outputRoot = absolute(input.outputRoot, "output root");
  await assertAbsent(outputRoot, "Release package output already exists");
  const sourceGatePath = await ownerRegularFilePath(input.sourceGateReport, "source-gate report");
  const sourceRevision = revision(input.sourceRevision, "source revision");
  const runtimeRevision = revision(input.runtimeRevision, "runtime revision");
  if (inside(sourceRoot, outputRoot)) throw new Error("Release output must stay outside the source tree.");
  const observedRevision = git(sourceRoot, ["rev-parse", "HEAD"]).trim();
  if (observedRevision !== sourceRevision) throw new Error("Source HEAD differs from the requested release revision.");
  const dirty = git(sourceRoot, ["status", "--porcelain=v1", "--untracked-files=all"]);
  if (dirty.trim()) throw new Error("Personal release package creation requires a clean source tree.");
  const sourceGate = await verifySourceGateReceipt(sourceRoot, sourceGatePath, sourceRevision);
  await realDirectory(join(sourceRoot, "dist"), "built dist tree");
  await ownerRegularFilePath(
    join(sourceRoot, "dist", "v2", "runtime-contract-identity.js"),
    "built runtime identity",
    false,
  );

  await mkdir(outputRoot, { recursive: false, mode: 0o700 });
  try {
    await copyBuiltTree(join(sourceRoot, "dist"), join(outputRoot, "dist"));
    const tracked = gitFiles(sourceRoot, TRACKED_PAYLOADS);
    for (const path of tracked) {
      const source = join(sourceRoot, path);
      const destination = join(outputRoot, path);
      const metadata = await lstat(source);
      if (!metadata.isFile() || metadata.isSymbolicLink()) {
        throw new Error(`Tracked release payload is not a regular file: ${path}`);
      }
      await mkdir(dirname(destination), { recursive: true, mode: 0o700 });
      await copyFile(source, destination);
      await chmod(destination, metadata.mode & 0o777);
    }
    await copyFile(sourceGatePath, join(outputRoot, SOURCE_GATE_NAME));
    await chmod(join(outputRoot, SOURCE_GATE_NAME), 0o600);
    const manifest = await createPersonalRuntimeManifest({
      packageRoot: outputRoot,
      sourceRevision,
      runtimeRevision,
    });
    await writeChecksums(outputRoot, manifest.manifest, manifest.manifestSha256);
    return {
      status: "CREATED",
      productProfile: PROFILE,
      packageRoot: outputRoot,
      sourceRevision,
      runtimeRevision,
      buildDigest: manifest.manifest.buildDigest,
      schemaGeneration: manifest.manifest.schemaGeneration,
      manifestPath: manifest.manifestPath,
      manifestSha256: manifest.manifestSha256,
      sourceGateDigest: digest(await readFile(join(outputRoot, SOURCE_GATE_NAME))),
      sourceTreeDigest: sourceGate.sourceTreeDigest,
      fileCount: manifest.manifest.files.length,
    };
  } catch (error) {
    await rm(outputRoot, { recursive: true, force: true });
    throw error;
  }
}

export async function verifyPersonalReleasePackage(input) {
  const packageRoot = await realDirectory(input.packageRoot, "package root");
  const manifestPath = join(packageRoot, MANIFEST_NAME);
  const manifestBytes = await ownerRegularFile(manifestPath, "runtime manifest");
  const manifest = JSON.parse(manifestBytes.toString("utf8"));
  const sourceGate = await verifyPackagedSourceGate(packageRoot, manifest);
  const manifestSha256 = digest(manifestBytes);
  await verifyChecksums(packageRoot, manifest, manifestSha256);
  const dependencyEvidenceSha256 = input.dependencyEvidenceSha256
    ?? digest(await ownerRegularFile(input.dependencyEvidence, "dependency evidence"));
  const runtime = await verifyPersonalRuntime({
    packageRoot,
    entrypoint: join(packageRoot, "scripts", "start-universal-broker-v2-production.sh"),
    manifestPath,
    manifestSha256: input.manifestSha256 ?? manifestSha256,
    sourceRevision: input.sourceRevision ?? manifest.sourceRevision,
    runtimeRevision: input.runtimeRevision ?? manifest.runtimeRevision,
    dependencyRoot: input.dependencyRoot,
    dependencyEvidence: input.dependencyEvidence,
    dependencyEvidenceSha256,
  });
  return {
    status: "PASS",
    productProfile: PROFILE,
    packageRoot,
    sourceRevision: runtime.sourceRevision,
    runtimeRevision: runtime.runtimeRevision,
    buildDigest: runtime.buildDigest,
    schemaGeneration: manifest.schemaGeneration,
    manifestSha256: runtime.manifestSha256,
    sourceGateDigest: digest(await readFile(join(packageRoot, SOURCE_GATE_NAME))),
    sourceTreeDigest: sourceGate.sourceTreeDigest,
    dependency: runtime.dependency,
    fileCount: manifest.files.length,
  };
}

export async function verifyPersonalReleaseRuntimeIdentity(input) {
  const packageRoot = await realDirectory(input.packageRoot, "package root");
  const manifest = JSON.parse(await readFile(join(packageRoot, MANIFEST_NAME), "utf8"));
  const identityPath = await ownerRegularFilePath(input.identityPath, "runtime identity", false);
  const payload = JSON.parse(await readFile(identityPath, "utf8"));
  const identity = payload.identity ?? payload;
  for (const [field, expected] of [
    ["productProfile", PROFILE],
    ["sourceRevision", manifest.sourceRevision],
    ["runtimeRevision", manifest.runtimeRevision],
    ["buildDigest", manifest.buildDigest],
    ["schemaGeneration", manifest.schemaGeneration],
  ]) {
    if (identity[field] !== expected) {
      throw new Error(`Runtime identity differs from Personal release manifest: ${field}`);
    }
  }
  return {
    status: "PASS",
    productProfile: PROFILE,
    sourceRevision: manifest.sourceRevision,
    runtimeRevision: manifest.runtimeRevision,
    buildDigest: manifest.buildDigest,
    schemaGeneration: manifest.schemaGeneration,
    identityPath,
  };
}

async function verifySourceGateReceipt(sourceRoot, reportPath, sourceRevision) {
  const receipt = JSON.parse(await readFile(reportPath, "utf8"));
  if (receipt.schemaVersion !== 1
    || receipt.kind !== "PERSONAL_DIRECT_OWNER_SOURCE_GATE"
    || receipt.status !== "PASS"
    || receipt.productProfile !== PROFILE
    || receipt.sourceRevision !== sourceRevision) {
    throw new Error("Source-gate receipt identity is invalid.");
  }
  const sourceTreeDigest = digest(Buffer.from(git(sourceRoot, [
    "ls-tree",
    "-r",
    "--full-tree",
    sourceRevision,
  ])));
  if (receipt.sourceTreeDigest !== sourceTreeDigest
    || receipt.packageLockSha256 !== digest(await readFile(join(sourceRoot, "package-lock.json")))
    || receipt.buildCapabilitiesSchemaSha256 !== digest(
      await readFile(join(sourceRoot, "contracts", "build-capabilities.schema.json")),
    )
    || receipt.toolsSchemaSha256 !== digest(
      await readFile(join(sourceRoot, "contracts", "tools-v2.schema.json")),
    )) {
    throw new Error("Source-gate receipt does not match the clean source tree.");
  }
  if (receipt.nodeVersion !== process.version || receipt.platform !== `${process.platform}-${process.arch}`) {
    throw new Error("Source-gate receipt platform differs from package creation.");
  }
  return receipt;
}

async function verifyPackagedSourceGate(packageRoot, manifest) {
  const path = join(packageRoot, SOURCE_GATE_NAME);
  const bytes = await ownerRegularFile(path, "packaged source-gate receipt");
  const receipt = JSON.parse(bytes.toString("utf8"));
  if (receipt.schemaVersion !== 1
    || receipt.kind !== "PERSONAL_DIRECT_OWNER_SOURCE_GATE"
    || receipt.status !== "PASS"
    || receipt.productProfile !== PROFILE
    || receipt.sourceRevision !== manifest.sourceRevision
    || receipt.packageLockSha256 !== digest(await readFile(join(packageRoot, "package-lock.json")))
    || receipt.buildCapabilitiesSchemaSha256 !== digest(
      await readFile(join(packageRoot, "contracts", "build-capabilities.schema.json")),
    )
    || receipt.toolsSchemaSha256 !== digest(
      await readFile(join(packageRoot, "contracts", "tools-v2.schema.json")),
    )) {
    throw new Error("Packaged source-gate receipt is invalid.");
  }
  return receipt;
}

async function writeChecksums(root, manifest, manifestSha256) {
  const entries = [
    ...manifest.files.map((file) => ({ path: file.path, sha256: file.sha256 })),
    { path: MANIFEST_NAME, sha256: manifestSha256 },
  ].sort((left, right) => left.path.localeCompare(right.path));
  const text = `${entries.map((entry) => `${entry.sha256.slice("sha256:".length)}  ${entry.path}`).join("\n")}\n`;
  await writeFile(join(root, CHECKSUM_NAME), text, { flag: "wx", mode: 0o600 });
}

async function verifyChecksums(root, manifest, manifestSha256) {
  const checksumPath = join(root, CHECKSUM_NAME);
  const text = (await ownerRegularFile(checksumPath, "SHA256SUMS")).toString("utf8");
  const observed = new Map();
  for (const line of text.trim().split("\n")) {
    const match = /^([a-f0-9]{64})  ([^\0\r\n]+)$/u.exec(line);
    if (!match || observed.has(match[2])) throw new Error("SHA256SUMS contains an invalid or duplicate row.");
    observed.set(match[2], `sha256:${match[1]}`);
  }
  const expected = new Map([
    ...manifest.files.map((file) => [file.path, file.sha256]),
    [MANIFEST_NAME, manifestSha256],
  ]);
  if (observed.size !== expected.size) throw new Error("SHA256SUMS entry count is invalid.");
  for (const [path, sha256] of expected) {
    if (observed.get(path) !== sha256 || digest(await readFile(join(root, path))) !== sha256) {
      throw new Error(`SHA256SUMS mismatch: ${path}`);
    }
  }
}

async function copyBuiltTree(source, destination) {
  await mkdir(destination, { recursive: false, mode: 0o700 });
  const entries = await readdir(source, { withFileTypes: true });
  entries.sort((left, right) => left.name.localeCompare(right.name));
  for (const entry of entries) {
    const from = join(source, entry.name);
    const to = join(destination, entry.name);
    if (entry.isSymbolicLink()) throw new Error(`Built runtime contains a symlink: ${from}`);
    if (entry.isDirectory()) await copyBuiltTree(from, to);
    else if (entry.isFile()) {
      const metadata = await stat(from);
      await copyFile(from, to);
      await chmod(to, metadata.mode & 0o777);
    } else throw new Error(`Built runtime contains an unsupported entry: ${from}`);
  }
}

function gitFiles(root, paths) {
  const output = spawnSync("git", ["ls-files", "-z", "--", ...paths], {
    cwd: root,
    encoding: "buffer",
    stdio: "pipe",
  });
  if (output.error) throw output.error;
  if (output.status !== 0) throw new Error(`git ls-files failed: ${output.stderr.toString("utf8").trim()}`);
  return output.stdout.toString("utf8").split("\0").filter(Boolean).sort();
}

function git(root, args) {
  const output = spawnSync("git", args, { cwd: root, encoding: "utf8", stdio: "pipe" });
  if (output.error) throw output.error;
  if (output.status !== 0) throw new Error(`git ${args.join(" ")} failed: ${(output.stderr ?? "").trim()}`);
  return output.stdout;
}

async function realDirectory(path, label) {
  const absolutePath = absolute(path, label);
  const resolved = await realpath(absolutePath);
  const metadata = await lstat(resolved);
  if (!metadata.isDirectory() || metadata.isSymbolicLink()) throw new Error(`${label} must be a real directory.`);
  return resolved;
}

async function ownerRegularFile(path, label, ownerOnly = true) {
  const resolved = await ownerRegularFilePath(path, label, ownerOnly);
  return readFile(resolved);
}

async function ownerRegularFilePath(path, label, ownerOnly = true) {
  const absolutePath = absolute(path, label);
  const resolved = await realpath(absolutePath);
  const metadata = await lstat(resolved);
  if (!metadata.isFile() || metadata.isSymbolicLink() || (ownerOnly && (metadata.mode & 0o077) !== 0)) {
    throw new Error(`${label} must be an owner-only regular file.`);
  }
  return resolved;
}

function absolute(value, label) {
  if (typeof value !== "string" || !isAbsolute(value)) throw new Error(`${label} must be absolute.`);
  return resolve(value);
}

function revision(value, label) {
  if (typeof value !== "string" || !/^[a-f0-9]{40}$/u.test(value)) throw new Error(`${label} must be a Git SHA-1.`);
  return value;
}

async function assertAbsent(path, message) {
  try { await lstat(path); } catch (error) {
    if (error && typeof error === "object" && "code" in error && error.code === "ENOENT") return;
    throw error;
  }
  throw new Error(`${message}: ${path}`);
}

function inside(root, path) {
  const child = relative(root, path);
  return child === "" || (child !== ".." && !child.startsWith(`..${sep}`) && !isAbsolute(child));
}

function digest(value) {
  return `sha256:${createHash("sha256").update(value).digest("hex")}`;
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
    const result = await createPersonalReleasePackage({
      sourceRoot: required(options, "source-root"),
      outputRoot: required(options, "output"),
      sourceGateReport: required(options, "source-gate-report"),
      sourceRevision: options.get("source-revision"),
      runtimeRevision: options.get("runtime-revision"),
    });
    process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
  } else if (command === "verify") {
    const result = await verifyPersonalReleasePackage({
      packageRoot: required(options, "package"),
      dependencyRoot: required(options, "dependency-root"),
      dependencyEvidence: required(options, "dependency-evidence"),
      dependencyEvidenceSha256: options.get("dependency-evidence-sha256"),
      manifestSha256: options.get("manifest-sha256"),
      sourceRevision: options.get("source-revision"),
      runtimeRevision: options.get("runtime-revision"),
    });
    process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
  } else if (command === "verify-runtime") {
    const result = await verifyPersonalReleaseRuntimeIdentity({
      packageRoot: required(options, "package"),
      identityPath: required(options, "identity"),
    });
    process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
  } else {
    throw new Error("Usage: personal-direct-owner-release.mjs <create|verify|verify-runtime> --name value ...");
  }
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) await main();
