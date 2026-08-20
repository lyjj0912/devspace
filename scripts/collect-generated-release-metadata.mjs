#!/usr/bin/env node
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { readFileSync, realpathSync } from "node:fs";
import { join, resolve } from "node:path";
import { pathToFileURL } from "node:url";

const [sourceRootInput, sourceRevision, buildDigest, schemaGeneration,
  authorityContractGeneration, configSchemaIdentity, runtimeClosureInputSha256] = process.argv.slice(2);
if (!sourceRootInput || !sourceRevision) {
  throw new Error("Usage: collect-generated-release-metadata.mjs SOURCE REVISION BUILD SCHEMA AUTHORITY CONFIG CLOSURE");
}
for (const [name, value] of Object.entries({
  buildDigest,
  schemaGeneration,
  authorityContractGeneration,
  configSchemaIdentity,
  runtimeClosureInputSha256,
})) {
  if (!/^sha256:[a-f0-9]{64}$/u.test(value ?? "")) throw new Error(`Collector ${name} is invalid.`);
}
const sourceRoot = realpathSync(resolve(sourceRootInput));
const buildCapabilitiesModule = await import(pathToFileURL(join(sourceRoot, "dist/v2/build-capabilities.js")).href);
const mainMigrationsModule = await import(pathToFileURL(join(sourceRoot, "dist/db/migrations.js")).href);
const migrationRegistryModule = await import(pathToFileURL(join(sourceRoot, "dist/v2/migration-registry.js")).href);
const buildCapabilities = buildCapabilitiesModule.createBuildCapabilityManifest(buildDigest);
const migrationManifest = migrationRegistryModule.universalBrokerStoreMigrationManifest(
  mainMigrationsModule.mainDatabaseMigrationManifest(),
);
const migrationManifestDigest = migrationRegistryModule.migrationManifestDigest(migrationManifest);
const tracked = spawnSync("/usr/bin/git", ["-C", sourceRoot, "ls-files", "-z", "--cached"], {
  encoding: "buffer",
  env: { LANG: "C", LC_ALL: "C", PATH: "", TZ: "UTC", GIT_CONFIG_NOSYSTEM: "1", GIT_CONFIG_GLOBAL: "/dev/null" },
  maxBuffer: 32 * 1024 * 1024,
});
if (tracked.error || tracked.status !== 0 || tracked.signal !== null) {
  throw new Error("Generated metadata collector could not enumerate tracked source.");
}
const paths = tracked.stdout.toString("utf8").split("\0").filter(Boolean).sort();
if (paths.length === 0) throw new Error("Generated metadata collector found no tracked source.");
const sourceTree = createHash("sha256");
for (const path of paths) {
  const bytes = readFileSync(join(sourceRoot, path));
  sourceTree.update(path); sourceTree.update("\0");
  sourceTree.update(createHash("sha256").update(bytes).digest("hex")); sourceTree.update("\n");
}
const dependencyTreeSha256 = digestBytes(readFileSync(join(sourceRoot, "package-lock.json")));
const sourceTreeSha256 = `sha256:${sourceTree.digest("hex")}`;
const collectorReceiptSha256 = digestJson({
  schemaVersion: 1,
  collector: "scripts/collect-generated-release-metadata.mjs",
  nodeVersion: process.version,
  sourceRevision,
  sourceTreeSha256,
  dependencyTreeSha256,
  buildDigest,
  runtimeClosureInputSha256,
  buildCapabilitiesDigest: buildCapabilities.capabilityDigest,
  migrationManifestDigest,
});
const payload = {
  schemaVersion: 1,
  sourceRevision,
  buildDigest,
  schemaGeneration,
  authorityContractGeneration,
  configSchemaIdentity,
  runtimeClosureInputSha256,
  sourceTreeSha256,
  dependencyTreeSha256,
  collectorReceiptSha256,
  buildCapabilities,
  migrationManifest,
  migrationManifestDigest,
};
process.stdout.write(`${canonicalJson(payload)}\n`);

function digestBytes(bytes) {
  return `sha256:${createHash("sha256").update(bytes).digest("hex")}`;
}

function digestJson(value) {
  return digestBytes(Buffer.from(canonicalJson(value)));
}

function canonicalJson(value) {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonicalJson(value[key])}`).join(",")}}`;
}
