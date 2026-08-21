import {
  createHash,
  createHmac,
  createPrivateKey,
  createPublicKey,
  randomBytes,
  timingSafeEqual,
  verify as verifySignature,
} from "node:crypto";
import { execFileSync, spawnSync } from "node:child_process";
import { isBuiltin } from "node:module";
import {
  chmodSync,
  copyFileSync,
  constants,
  existsSync,
  fstatSync,
  lstatSync,
  mkdirSync,
  openSync,
  closeSync,
  readFileSync,
  readlinkSync,
  realpathSync,
  readdirSync,
  renameSync,
  rmSync,
  statSync,
  writeFileSync,
  fsyncSync,
} from "node:fs";
import { dirname, isAbsolute, join, relative, resolve, sep } from "node:path";
import {
  BASE_PROFILE_GATE_PRODUCER_PUBLIC_KEY_PATH,
  BASE_PROFILE_PRECUTOVER_LEDGER_PATH,
  collectBaseProfilePreCutoverGateLedger,
} from "./base-profile-gate-producer.mjs";
import {
  GENERATED_RELEASE_METADATA_FIXTURE_KIND,
  GENERATED_RELEASE_METADATA_KIND,
  GENERATED_RELEASE_METADATA_PATH,
  createSignedGeneratedReleaseMetadata,
  createUnsignedGeneratedReleaseMetadataFixture,
  parseGeneratedReleaseMetadata,
} from "./generated-release-metadata.mjs";

export const RELEASE_MANIFEST_NAME = "BUILD-MANIFEST.json";
export const RELEASE_CHECKSUM_NAME = "SHA256SUMS";
export const SPDX_SBOM_NAME = "SBOM.spdx.json";
export const CYCLONEDX_SBOM_NAME = "SBOM.cyclonedx.json";
export const SBOM_INDEX_NAME = "SBOM.json";
export const RUNTIME_DEPENDENCY_MANIFEST_NAME = "RUNTIME-DEPENDENCIES.json";
export const RUNTIME_OPERATIONS_CLOSURE_SCHEMA_VERSION = 1;

const RUNTIME_CWD = ".";
const RUNTIME_ENTRYPOINT = "scripts/start-universal-broker-v2-production.sh";
const RUNTIME_NODE_ENTRYPOINT = "dist/cli.js";
const RUNTIME_DEPENDENCY_LOADER = "scripts/lib/runtime-dependency-loader.mjs";
const RUNTIME_DEPENDENCY_MODE = "external-node-modules-loader-v1";

const REQUIRED_PAYLOADS = ["dist", "package.json", "package-lock.json", "config", "contracts", "scripts", "skills"];
const OPTIONAL_PAYLOADS = [];
const TOOLS_SCHEMA_PATH = "contracts/tools-v2.schema.json";
const BUILD_CAPABILITY_SCHEMA_PATH = "contracts/build-capabilities.schema.json";
const EXPECTED_TOOL_NAMES = ["target", "context", "fs", "exec", "process", "mcp", "artifact", "gui"];
const BUILD_CAPABILITY_CONTRACT_KEYS = [
  "productVersion",
  "productProfile",
  "schemaGeneration",
  "authorityContractGeneration",
  "supportedProfiles",
  "supportedOperations",
  "resourceUriVersion",
];
const BUILD_CAPABILITY_SCHEMA_REQUIRED = [...BUILD_CAPABILITY_CONTRACT_KEYS, "buildDigest", "capabilityDigest"];
const DIGEST_PATTERN_SOURCE = "^sha256:[a-f0-9]{64}$";
const DIGEST_PATTERN = /^sha256:[a-f0-9]{64}$/u;
const MANAGEMENT_KEY_ID_PATTERN = /^management-[a-f0-9]{24}$/u;
const MANAGEMENT_SIGNATURE_PATTERN = /^[A-Za-z0-9_-]{43}$/u;
const TRUST_ANCHOR_KIND = "DEVSPACE_GATE_PRODUCER_TRUST_ANCHOR";
const TRUST_ANCHOR_DOMAIN = "devspace.gate-producer-trust-anchor.v1";
const verifiedGateProducerTrustAnchors = new WeakMap();
const verifiedReleaseContexts = new WeakMap();
export const RUNTIME_OPERATIONS_CLOSURE_ROOTS = Object.freeze([
  "dist/cli.js",
  "dist/v2/production-upgrade-worker.js",
  "dist/v2/production-upgrade-worker-cli.js",
  "scripts/connector-activation-release-driver.mjs",
  "scripts/collect-generated-release-metadata.mjs",
  "scripts/cutover-universal-broker-v2-production.sh",
  "scripts/deploy-universal-broker-v2-parallel.sh",
  "scripts/promote-universal-broker-v2-personal.sh",
  "scripts/deploy-universal-broker-v2-pm2.sh",
  "scripts/deploy-universal-broker-v2-production.sh",
  "scripts/ensure-owner-instance-id.mjs",
  "scripts/finalization-live-driver.mjs",
  "scripts/finalize-universal-broker-v2-production.sh",
  "scripts/finalize-universal-broker-v2.mjs",
  "scripts/release-artifacts.mjs",
  "scripts/rollback-universal-broker-v2-production.sh",
  "scripts/start-universal-broker-v2-production.sh",
  "scripts/start-universal-broker-v2.sh",
  "scripts/status-universal-broker-v2-upgrade.sh",
  "scripts/undeploy-universal-broker-v2-pm2.sh",
  "scripts/upgrade-universal-broker-v2-production.sh",
  "scripts/verify-universal-broker-v2-live.mjs",
  "scripts/verify-universal-broker-v2-release.mjs",
  "scripts/lib/base-profile-gate-evidence.d.mts",
  "scripts/lib/base-profile-gate-evidence.mjs",
  "scripts/lib/base-profile-gate-producer.d.mts",
  "scripts/lib/base-profile-gate-producer.mjs",
  "scripts/lib/connector-activation-release-driver.mjs",
  "scripts/lib/connector-rollback-evidence.d.mts",
  "scripts/lib/connector-rollback-evidence.mjs",
  "scripts/lib/finalization-state.d.mts",
  "scripts/lib/finalization-state.mjs",
  "scripts/lib/finalization-store-contract.d.mts",
  "scripts/lib/finalization-store-contract.mjs",
  "scripts/lib/generated-release-metadata.d.mts",
  "scripts/lib/generated-release-metadata.mjs",
  "scripts/lib/owner-instance-id.mjs",
  "scripts/lib/release-artifacts.mjs",
  "scripts/lib/release-environment.mjs",
  "scripts/lib/runtime-dependency-loader.mjs",
].sort(compareAscii));
const REVIEWED_PRODUCTION_SCRIPT_PATHS = new Set([
  "scripts/check-universal-broker-rev3-nfr.mjs",
  "scripts/check-universal-broker-v2-budgets.mjs",
  "scripts/connector-activation-release-driver.mjs",
  "scripts/configure-devspace-log-rotation.sh",
  "scripts/cutover-universal-broker-v2-production.sh",
  "scripts/deploy-personal-pm2.sh",
  "scripts/deploy-universal-broker-v2-parallel.sh",
  "scripts/deploy-universal-broker-v2-pm2.sh",
  "scripts/deploy-universal-broker-v2-production.sh",
  "scripts/dev-server.mjs",
  "scripts/ensure-owner-instance-id.mjs",
  "scripts/finalization-live-driver.mjs",
  "scripts/finalize-universal-broker-v2-production.sh",
  "scripts/finalize-universal-broker-v2.mjs",
  "scripts/fix-node-pty-permissions.mjs",
  "scripts/personal-release-gate.mjs",
  "scripts/release-artifacts.mjs",
  "scripts/rollback-universal-broker-v2-production.sh",
  "scripts/start-universal-broker-v2-production.sh",
  "scripts/start-universal-broker-v2.sh",
  "scripts/status-universal-broker-v2-upgrade.sh",
  "scripts/undeploy-universal-broker-v2-pm2.sh",
  "scripts/upgrade-universal-broker-v2-production.sh",
  "scripts/verify-universal-broker-v2-live.mjs",
  "scripts/verify-universal-broker-v2-load.mjs",
  "scripts/verify-universal-broker-v2-release.mjs",
  "scripts/lib/finalization-state.mjs",
  "scripts/lib/finalization-state.d.mts",
  "scripts/lib/base-profile-gate-evidence.mjs",
  "scripts/lib/base-profile-gate-evidence.d.mts",
  "scripts/lib/base-profile-gate-producer.mjs",
  "scripts/lib/base-profile-gate-producer.d.mts",
  "scripts/lib/connector-activation-release-driver.mjs",
  "scripts/lib/connector-rollback-evidence.d.mts",
  "scripts/lib/connector-rollback-evidence.mjs",
  "scripts/lib/finalization-store-contract.mjs",
  "scripts/lib/finalization-store-contract.d.mts",
  "scripts/lib/owner-instance-id.mjs",
  "scripts/lib/release-artifacts.mjs",
]);
const GENERATED_FILES = new Set([
  RELEASE_MANIFEST_NAME,
  RELEASE_CHECKSUM_NAME,
  SPDX_SBOM_NAME,
  CYCLONEDX_SBOM_NAME,
  SBOM_INDEX_NAME,
  "config.schema.json",
]);

export function canonicalJson(value) {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonicalJson(value[key])}`).join(",")}}`;
}

export function sha256(value) {
  return createHash("sha256").update(value).digest("hex");
}

export function canonicalJsonSha256(value) {
  return `sha256:${sha256(canonicalJson(value))}`;
}

export function fileSha256(path) {
  return sha256(readFileSync(path));
}

export function listRegularFiles(root) {
  if (!existsSync(root)) return [];
  const output = [];
  const visit = (directory) => {
    for (const entry of readdirSync(directory, { withFileTypes: true })) {
      const path = join(directory, entry.name);
      if (entry.isSymbolicLink()) throw new Error(`Release payload may not contain symlinks: ${toPosix(relative(root, path))}`);
      if (entry.isDirectory()) visit(path);
      else if (entry.isFile()) output.push(path);
      else throw new Error(`Release payload contains an unsupported file type: ${toPosix(relative(root, path))}`);
    }
  };
  visit(root);
  return output.sort((left, right) => compareAscii(
    toPosix(relative(root, left)),
    toPosix(relative(root, right)),
  ));
}

function snapshotReleaseTree(root) {
  const canonicalRoot = resolve(root);
  const rootBefore = lstatSync(canonicalRoot, { bigint: true });
  if (!rootBefore.isDirectory() || rootBefore.isSymbolicLink() || realpathSync(canonicalRoot) !== canonicalRoot) {
    throw new Error("Release package root must be a canonical real directory.");
  }
  const files = new Map();
  const directories = new Map();
  const visit = (directory) => {
    const before = lstatSync(directory, { bigint: true });
    if (!before.isDirectory() || before.isSymbolicLink()) throw new Error(`Release package directory is invalid: ${directory}`);
    directories.set(directory, inodeIdentity(before));
    const entries = readdirSync(directory, { withFileTypes: true }).sort((left, right) => compareAscii(left.name, right.name));
    for (const entry of entries) {
      const absolute = join(directory, entry.name);
      const path = toPosix(relative(canonicalRoot, absolute));
      if (entry.isSymbolicLink()) throw new Error(`Release payload may not contain symlinks: ${path}`);
      if (entry.isDirectory()) visit(absolute);
      else if (entry.isFile()) {
        const stable = stableReadRegularFile(absolute, `release payload ${path}`);
        files.set(path, Object.freeze({ bytes: stable.bytes, sha256: sha256(stable.bytes), identity: stable.identity }));
      } else throw new Error(`Release payload contains an unsupported file type: ${path}`);
    }
  };
  visit(canonicalRoot);
  for (const [directory, identity] of directories) {
    if (canonicalJson(inodeIdentity(lstatSync(directory, { bigint: true }))) !== canonicalJson(identity)) {
      throw new Error(`Release package directory changed during snapshot: ${directory}`);
    }
  }
  const rootAfter = lstatSync(canonicalRoot, { bigint: true });
  if (canonicalJson(inodeIdentity(rootBefore)) !== canonicalJson(inodeIdentity(rootAfter))) {
    throw new Error("Release package root changed during snapshot.");
  }
  return Object.freeze({
    root: canonicalRoot,
    rootIdentity: inodeIdentity(rootAfter),
    files,
    paths: Object.freeze([...files.keys()].sort(compareAscii)),
    directories: Object.freeze([...directories].map(([path, identity]) => Object.freeze({ path, identity }))),
  });
}

function stableReadRegularFile(path, label) {
  const descriptor = openSync(path, constantsReadOnlyNoFollow());
  try {
    const before = fstatSync(descriptor, { bigint: true });
    const bytes = readFileSync(descriptor);
    const after = fstatSync(descriptor, { bigint: true });
    if (!before.isFile() || canonicalJson(inodeIdentity(before)) !== canonicalJson(inodeIdentity(after))
      || BigInt(bytes.length) !== after.size) {
      throw new Error(`${label} changed during single-descriptor read.`);
    }
    return Object.freeze({ bytes, identity: inodeIdentity(after) });
  } finally {
    closeSync(descriptor);
  }
}

function constantsReadOnlyNoFollow() {
  return constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0);
}

function inodeIdentity(metadata) {
  return Object.freeze({
    dev: metadata.dev.toString(),
    ino: metadata.ino.toString(),
    mode: metadata.mode.toString(),
    nlink: metadata.nlink.toString(),
    size: metadata.size.toString(),
    mtimeNs: metadata.mtimeNs.toString(),
    ctimeNs: metadata.ctimeNs.toString(),
  });
}

function snapshotFile(snapshot, path) {
  const normalized = normalizeRelativePath(path);
  const file = snapshot.files.get(normalized);
  if (!file) throw new Error(`Release snapshot is missing: ${normalized}`);
  return file;
}

function snapshotText(snapshot, path) {
  return snapshotFile(snapshot, path).bytes.toString("utf8");
}

function snapshotJson(snapshot, path, label) {
  try {
    return JSON.parse(snapshotText(snapshot, path));
  } catch {
    throw new Error(`${label} is invalid JSON.`);
  }
}

function snapshotWithoutGeneratedMetadata(snapshot) {
  const files = new Map(snapshot.files);
  files.delete(GENERATED_RELEASE_METADATA_PATH);
  return Object.freeze({
    ...snapshot,
    files,
    paths: Object.freeze(snapshot.paths.filter((path) => path !== GENERATED_RELEASE_METADATA_PATH)),
  });
}

function treeEvidenceFromSnapshot(snapshot, paths) {
  const normalized = [...paths].sort(compareAscii);
  const digest = createHash("sha256");
  for (const path of normalized) {
    const file = snapshotFile(snapshot, path);
    digest.update(path);
    digest.update("\0");
    digest.update(file.sha256);
    digest.update("\n");
  }
  return Object.freeze({ files: normalized.length, sha256: `sha256:${digest.digest("hex")}` });
}

function assertReleaseSnapshotUnchanged(snapshot, label) {
  const current = snapshotReleaseTree(snapshot.root);
  if (canonicalJson(current.rootIdentity) !== canonicalJson(snapshot.rootIdentity)
    || canonicalJson(current.paths) !== canonicalJson(snapshot.paths)) {
    throw new Error(`Release package changed during ${label}.`);
  }
  for (const path of snapshot.paths) {
    const expected = snapshotFile(snapshot, path);
    const observed = snapshotFile(current, path);
    if (expected.sha256 !== observed.sha256 || canonicalJson(expected.identity) !== canonicalJson(observed.identity)) {
      throw new Error(`Release package changed during ${label}: ${path}`);
    }
  }
}

export function deriveRuntimeOperationsClosure(packageRoot, options = {}) {
  return deriveRuntimeOperationsClosureFromSnapshot(snapshotReleaseTree(resolve(packageRoot)), options);
}

function deriveRuntimeOperationsClosureFromSnapshot(snapshot, options = {}) {
  const requireGeneratedMetadata = options.requireGeneratedMetadata !== false;
  const roots = [...RUNTIME_OPERATIONS_CLOSURE_ROOTS];
  if (requireGeneratedMetadata) roots.push(GENERATED_RELEASE_METADATA_PATH);
  roots.sort(compareAscii);
  const lock = snapshotJson(snapshot, "package-lock.json", "release package lockfile");
  const pending = [...roots];
  const visited = new Set();
  const edges = [];
  const externals = [];
  while (pending.length > 0) {
    const path = pending.shift();
    if (visited.has(path)) continue;
    assertProductionClosurePath(path);
    const file = snapshotFile(snapshot, path);
    visited.add(path);
    for (const reference of productionClosureReferences(path, file.bytes.toString("utf8"))) {
      if (reference.kind === "host-external") {
        assertHostExternalClosureSpecifier(reference.specifier, path);
        externals.push(Object.freeze({ from: path, kind: reference.kind, specifier: reference.specifier }));
        continue;
      }
      if (reference.kind === "external") {
        assertExternalClosureSpecifier(reference.specifier, lock, path);
        externals.push(Object.freeze({ from: path, specifier: reference.specifier }));
        continue;
      }
      const target = resolveClosureReference(path, reference.specifier, reference.packagePath === true);
      if (!snapshot.files.has(target)) {
        const directoryMembers = snapshot.paths.filter((candidate) => candidate.startsWith(`${target}/`));
        if (directoryMembers.length === 0) {
          throw new Error(`Runtime operations closure has an unresolved packaged edge: ${path} -> ${reference.specifier}`);
        }
        for (const member of directoryMembers) {
          assertProductionClosurePath(member);
          edges.push(Object.freeze({
            from: path,
            kind: `${reference.kind}-directory-member`,
            specifier: reference.specifier,
            to: member,
          }));
          if (!visited.has(member)) pending.push(member);
        }
        continue;
      }
      assertProductionClosurePath(target);
      edges.push(Object.freeze({ from: path, kind: reference.kind, specifier: reference.specifier, to: target }));
      if (!visited.has(target)) pending.push(target);
    }
    pending.sort(compareAscii);
  }
  const files = [...visited].sort(compareAscii).map((path) => Object.freeze({
    path,
    sha256: `sha256:${snapshotFile(snapshot, path).sha256}`,
  }));
  const contract = {
    schemaVersion: RUNTIME_OPERATIONS_CLOSURE_SCHEMA_VERSION,
    roots: Object.freeze(roots),
    files: Object.freeze(files),
    edges: Object.freeze(uniqueCanonicalObjects(edges)),
    externals: Object.freeze(uniqueCanonicalObjects(externals)),
  };
  return deepFreezeJson({ ...contract, sha256: canonicalJsonSha256(contract) });
}

function productionClosureReferences(path, text) {
  if (path === GENERATED_RELEASE_METADATA_PATH || /(?:\.d\.mts|\.json)$/iu.test(path)) return [];
  const output = [];
  if (/\.(?:mjs|js|mts)$/u.test(path)) {
    const patterns = [
      { kind: "module", pattern: /^\s*import\s*["']([^"'\r\n]+)["']/gmu },
      { kind: "module", pattern: /^\s*(?:import|export)\s+(?:type\s+)?[^;]*?\bfrom\s*["']([^"'\r\n]+)["']/gmu },
      { kind: "dynamic-import", pattern: /\bimport\s*\(\s*["']([^"'\r\n]+)["']\s*\)/gu },
      { kind: "require", pattern: /\brequire\s*\(\s*["']([^"'\r\n]+)["']\s*\)/gu },
      { kind: "url-asset", pattern: /\bnew\s+URL\s*\(\s*["']([^"'\r\n]+)["']\s*,\s*import\.meta\.url\s*\)/gu },
    ];
    for (const { kind, pattern } of patterns) {
      for (const match of text.matchAll(pattern)) {
        const specifier = match[1];
        output.push({ kind: isRelativeClosureSpecifier(specifier) ? kind : "external", specifier });
      }
    }
    output.push(...computedProductionModuleReferences(path, text));
  }
  if (/\.(?:sh|bash|zsh)$/u.test(path)) {
    for (const match of text.matchAll(/(?:^|[^A-Za-z0-9_.-])((?:scripts|dist)\/[A-Za-z0-9_./-]+\.(?:mjs|js|sh|mts))(?![A-Za-z0-9_.-])/gmu)) {
      output.push({ kind: "shell-package-path", specifier: match[1], packagePath: true });
    }
    for (const match of text.matchAll(/\$(?:\{)?SCRIPT_DIR(?:\})?\/([A-Za-z0-9_./-]+\.(?:mjs|js|sh|mts))(?![A-Za-z0-9_.-])/gu)) {
      output.push({ kind: "shell-script-dir", specifier: `scripts/${match[1]}`, packagePath: true });
    }
  }
  return uniqueCanonicalObjects(output);
}

function computedProductionModuleReferences(path, text) {
  const output = [];
  const computedImports = [...text.matchAll(/\bimport\s*\(\s*(?!["'])/gu)];
  if (path === "scripts/lib/connector-activation-release-driver.mjs") {
    const loader = /const module = \(path\) => import\(pathToFileURL\(join\(repositoryRoot, "dist", path\)\)\.href\);/u;
    if (computedImports.length !== 1 || !loader.test(text)) {
      throw new Error("Connector activation runtime loader is not statically closure-auditable.");
    }
    const loaded = [...text.matchAll(/\bmodule\(\s*"([A-Za-z0-9_./-]+\.js)"\s*\)/gu)];
    if (loaded.length === 0) throw new Error("Connector activation runtime loader has no exact compiled module set.");
    for (const match of loaded) {
      output.push({ kind: "computed-dist-module", specifier: `dist/${match[1]}`, packagePath: true });
    }
    computedImports.length = 0;
  } else if (path === "scripts/lib/base-profile-gate-producer.mjs") {
    const reporterImport = ["import", "(pathToFileURL(modulePath).href)"].join("");
    if (computedImports.length !== 1 || !text.includes(reporterImport)) {
      throw new Error("Base-profile gate identity reporter is not statically closure-auditable.");
    }
    output.push({ kind: "computed-package-reporter", specifier: "scripts/lib/release-artifacts.mjs", packagePath: true });
    computedImports.length = 0;
  } else if (path === "scripts/collect-generated-release-metadata.mjs") {
    const exactModules = [
      "dist/db/migrations.js",
      "dist/v2/build-capabilities.js",
      "dist/v2/migration-registry.js",
    ];
    const explicitFixtureStub = computedImports.length === 0
      && text === "export const fixtureRuntimeOperation = true;\n";
    if (!explicitFixtureStub && (computedImports.length !== exactModules.length
      || exactModules.some((modulePath) => !text.includes([
        "import",
        `(pathToFileURL(join(sourceRoot, "${modulePath}")).href)`,
      ].join(""))))) {
      throw new Error("Generated release metadata collector is not statically closure-auditable.");
    }
    if (!explicitFixtureStub) {
      for (const modulePath of exactModules) {
        output.push({ kind: "computed-dist-module", specifier: modulePath, packagePath: true });
      }
    }
    computedImports.length = 0;
  } else if (path === "scripts/personal-direct-owner-runtime.mjs") {
    const exactModule = "dist/v2/runtime-contract-identity.js";
    const exactImport = [
      "import",
      `(pathToFileURL(join(root, "${exactModule}")).href)`,
    ].join("");
    if (computedImports.length !== 1 || !text.includes(exactImport)) {
      throw new Error("Personal runtime identity loader is not statically closure-auditable.");
    }
    output.push({ kind: "computed-dist-module", specifier: exactModule, packagePath: true });
    computedImports.length = 0;
  }
  if (computedImports.length > 0) {
    throw new Error(`Runtime operations closure has an unresolved computed import in ${path}.`);
  }

  for (const match of text.matchAll(/(?<![A-Za-z0-9_$.])require\s*\(\s*([^"'][^)]*)\)/gu)) {
    const tail = text.slice(match.index + match[0].length);
    if (/^\s*\{/u.test(tail)) continue;
    if (path === "dist/v2/self-management.js" && match[1].trim() === "pm2Root") {
      output.push({ kind: "host-external", specifier: "pm2" });
      continue;
    }
    throw new Error(`Runtime operations closure has an unresolved computed require in ${path}.`);
  }
  return output;
}

function assertHostExternalClosureSpecifier(specifier, from) {
  if (from !== "dist/v2/self-management.js" || specifier !== "pm2") {
    throw new Error(`Runtime operations closure has an unapproved host external: ${from} -> ${specifier}`);
  }
}

function resolveClosureReference(from, specifier, packagePath) {
  if (packagePath) return normalizeRelativePath(specifier);
  if (!isRelativeClosureSpecifier(specifier) || /[?#]/u.test(specifier) || specifier.includes("\\")) {
    throw new Error(`Runtime operations closure edge is unsafe: ${from} -> ${specifier}`);
  }
  const target = toPosix(relative("/", resolve("/", dirname(from), specifier)));
  return normalizeRelativePath(target);
}

function isRelativeClosureSpecifier(value) {
  return typeof value === "string" && (value.startsWith("./") || value.startsWith("../"));
}

function assertProductionClosurePath(path) {
  const normalized = normalizeRelativePath(path);
  if (/(?:^|\/)(?:fixtures?|tests?|__tests__)(?:\/|$)|\.test\.[cm]?[jt]sx?$/iu.test(normalized)) {
    throw new Error(`Runtime operations closure may not include a test or fixture file: ${normalized}`);
  }
  if (!/\.(?:js|mjs|mts|sh|bash|zsh|json|md|txt|ya?ml|html|css|wasm|node|sql)$/iu.test(normalized)) {
    throw new Error(`Runtime operations closure contains an unsupported file type: ${normalized}`);
  }
}

function assertExternalClosureSpecifier(specifier, lock, from) {
  if (typeof specifier !== "string" || specifier.length === 0 || /[\0\r\n]/u.test(specifier)) {
    throw new Error(`Runtime operations closure has an invalid external specifier in ${from}.`);
  }
  if (isBuiltin(specifier)) return;
  if (specifier.startsWith("#") || specifier.startsWith("/") || specifier.startsWith("file:")
    || specifier.includes(":")) {
    throw new Error(`Runtime operations closure has a forbidden external/import escape: ${from} -> ${specifier}`);
  }
  const packageName = externalPackageName(specifier);
  const packagePath = `node_modules/${packageName}`;
  if (!lock?.packages || !Object.hasOwn(lock.packages, packagePath)) {
    throw new Error(`Runtime operations closure external is absent from package-lock.json: ${from} -> ${specifier}`);
  }
}

function externalPackageName(specifier) {
  const parts = specifier.split("/");
  if (specifier.startsWith("@")) {
    if (parts.length < 2 || !parts[0] || !parts[1]) throw new Error(`Runtime operations closure package specifier is invalid: ${specifier}`);
    return `${parts[0]}/${parts[1]}`;
  }
  if (!parts[0]) throw new Error(`Runtime operations closure package specifier is invalid: ${specifier}`);
  return parts[0];
}

function uniqueCanonicalObjects(values) {
  const byCanonical = new Map();
  for (const value of values) byCanonical.set(canonicalJson(value), value);
  return [...byCanonical.values()].sort((left, right) => compareAscii(canonicalJson(left), canonicalJson(right)));
}

export function treeEvidence(root, files = listRegularFiles(root).map((path) => toPosix(relative(root, path)))) {
  const normalized = [...files].sort();
  const digest = createHash("sha256");
  for (const path of normalized) {
    const absolute = resolveContained(root, path);
    if (!statSync(absolute).isFile()) throw new Error(`Release payload file is missing: ${path}`);
    digest.update(path);
    digest.update("\0");
    digest.update(fileSha256(absolute));
    digest.update("\n");
  }
  return { files: normalized.length, sha256: `sha256:${digest.digest("hex")}` };
}

export function deriveReleaseIdentities(sourceRoot) {
  return deriveReleaseIdentitiesFromSnapshot(snapshotReleaseTree(resolve(sourceRoot)));
}

function deriveReleaseIdentitiesFromSnapshot(snapshot) {
  const tools = snapshotJson(snapshot, "contracts/tools-v2.schema.json", "tools contract schema");
  const authorityFiles = ["contracts/mcp-risk-policy.schema.json", "contracts/errors.schema.json"]
    .filter((path) => snapshot.files.has(path))
    .map((path) => ({ path, value: snapshotJson(snapshot, path, `authority contract ${path}`) }));
  const configSchema = snapshotJson(snapshot, "config/config.schema.json", "config schema");
  if (authorityFiles.length === 0) throw new Error("Authority contract inputs are missing.");
  const runtimeContracts = runtimeContractIdentities(snapshot);
  return {
    schemaGeneration: runtimeContracts?.schemaGeneration ?? canonicalJsonSha256(tools),
    authorityContractGeneration: runtimeContracts?.authorityContractGeneration ?? canonicalJsonSha256(authorityFiles),
    configSchemaIdentity: canonicalJsonSha256(configSchema),
  };
}

export function deriveReleaseGateIdentityReport(packageRoot, sourceRevision) {
  const root = resolve(packageRoot);
  requireIdentity("sourceRevision", sourceRevision);
  const snapshot = snapshotReleaseTree(root);
  const packageFiles = snapshot.paths
    .filter((path) => path !== "evidence/base-profile-gates"
      && !path.startsWith("evidence/base-profile-gates/"))
    .sort(compareAscii);
  const runtimeFiles = packageFiles.filter((path) => path.startsWith("dist/"));
  if (runtimeFiles.length === 0) throw new Error("Release gate identity report has no packaged runtime files.");
  const build = treeEvidenceFromSnapshot(snapshot, runtimeFiles);
  const identities = deriveReleaseIdentitiesFromSnapshot(snapshot);
  const runtimeClosure = deriveRuntimeOperationsClosureFromSnapshot(snapshot);
  const runtimeMetadata = runtimeReleaseMetadataFromSnapshot(snapshot, {
    allowUnattestedFixture: false,
    buildDigest: build.sha256,
    identities,
    runtimeClosure,
    sourceRevision,
  });
  return Object.freeze({
    sourceRevision,
    buildDigest: build.sha256,
    schemaGeneration: identities.schemaGeneration,
    authorityContractGeneration: identities.authorityContractGeneration,
    buildCapabilityManifestDigest: runtimeMetadata.buildCapabilities.capabilityDigest,
    generatedSchemaDigest: generatedSchemaTreeDigestFromSnapshot(snapshot),
    migrationManifestDigest: runtimeMetadata.migrationManifestDigest,
    buildCapabilities: runtimeMetadata.buildCapabilities,
    migrationManifest: runtimeMetadata.migrationManifest,
    packageInputDigest: treeEvidenceFromSnapshot(snapshot, packageFiles).sha256,
  });
}

export function createUnattestedReleaseFixture(options) {
  const result = assembleReleasePackage(options, null);
  return Object.freeze({ ...result, eligibility: "UNATTESTED_FIXTURE_ONLY" });
}

export function createStagingReleasePackage(options) {
  const sourceRoot = resolve(options.sourceRoot);
  const result = assembleReleasePackage({
    ...options,
    fixtureGeneratedReleaseMetadata: (context) => {
      const payload = collectGeneratedReleaseMetadataPayload({
        sourceRoot,
        sourceRevision: context.sourceRevision,
        build: { sha256: context.buildDigest },
        identities: context.identities,
        runtimeClosureInput: { sha256: context.runtimeClosureInputSha256 },
      });
      return {
        sourceTreeSha256: payload.sourceTreeSha256,
        dependencyTreeSha256: payload.dependencyTreeSha256,
        collectorReceiptSha256: payload.collectorReceiptSha256,
        buildCapabilities: payload.buildCapabilities,
        migrationManifest: payload.migrationManifest,
        migrationManifestDigest: payload.migrationManifestDigest,
      };
    },
  }, null);
  return Object.freeze({ ...result, eligibility: "UNATTESTED_STAGING_ONLY" });
}

export function createReleasePackage(options) {
  if (options?.fixtureOnly !== true) {
    throw new Error("createReleasePackage is fixture-only; production release construction requires createAttestedReleasePackage.");
  }
  return createUnattestedReleaseFixture(options);
}

export function createAttestedReleasePackage(options) {
  requiredGateProducerPrivateKeyPath(options.gateProducerPrivateKeyPath);
  const expectedGateProducer = trustedGateProducerIdentity(options.gateProducerTrustAnchor);
  const result = assembleReleasePackage({
    ...options,
    expectedGateProducer,
    generatedReleaseMetadataFactory: (context) => collectGeneratedReleaseMetadata({
      ...context,
      gateProducerPrivateKeyPath: options.gateProducerPrivateKeyPath,
      expectedGateProducer,
    }),
  }, ({ sourceRoot, staging, sourceRevision, identities, build, runtimeMetadata }) => (
    collectBaseProfilePreCutoverGateLedger({
      sourceRoot,
      packageRoot: staging,
      privateKeyPath: options.gateProducerPrivateKeyPath,
      sourceRevision,
      bindings: {
        sourceRevision,
        buildDigest: build.sha256,
        schemaGeneration: identities.schemaGeneration,
        authorityContractGeneration: identities.authorityContractGeneration,
        buildCapabilityManifestDigest: runtimeMetadata.buildCapabilities.capabilityDigest,
        generatedSchemaDigest: generatedSchemaTreeDigestFromSnapshot(snapshotReleaseTree(staging)),
        migrationManifestDigest: runtimeMetadata.migrationManifestDigest,
      },
    })
  ));
  return Object.freeze({ ...result, eligibility: "ATTESTED_RELEASE_CANDIDATE" });
}

function assembleReleasePackage(options, collectGateEvidence) {
  const sourceRoot = resolve(options.sourceRoot);
  const outputRoot = resolve(options.outputRoot);
  if (sourceRoot === outputRoot || outputRoot.startsWith(`${sourceRoot}${sep}`)) {
    throw new Error("Release output must be outside the source tree.");
  }
  if (existsSync(outputRoot)) throw new Error(`Release output already exists: ${outputRoot}`);
  for (const path of REQUIRED_PAYLOADS) {
    if (!existsSync(resolveContained(sourceRoot, path))) throw new Error(`Required release payload is missing: ${path}`);
  }

  const staging = `${outputRoot}.staging-${process.pid}`;
  if (existsSync(staging)) rmSync(staging, { recursive: true, force: true });
  mkdirSync(staging, { recursive: true, mode: 0o700 });
  try {
    for (const path of [...REQUIRED_PAYLOADS, ...OPTIONAL_PAYLOADS]) {
      const source = resolveContained(sourceRoot, path);
      if (existsSync(source)) copyTree(source, resolveContained(staging, path), path);
    }
    const observedSourceRevision = collectGateEvidence === null ? tryGitRevision(sourceRoot) : gitRevision(sourceRoot);
    const sourceRevision = options.sourceRevision ?? observedSourceRevision;
    if (collectGateEvidence !== null && sourceRevision !== observedSourceRevision) {
      throw new Error(`Requested sourceRevision differs from canonical /usr/bin/git HEAD: expected ${observedSourceRevision}, observed ${sourceRevision}`);
    }
    const runtimeRevision = options.runtimeRevision ?? sourceRevision;
    requireIdentity("sourceRevision", sourceRevision);
    requireIdentity("runtimeRevision", runtimeRevision);
    const createdAt = normalizeCreatedAt(options.createdAt);

    copyFileSync(
      resolveContained(staging, "config/config.schema.json"),
      resolveContained(staging, "config.schema.json"),
    );

    const inputSnapshot = snapshotReleaseTree(staging);
    const identities = deriveReleaseIdentitiesFromSnapshot(inputSnapshot);
    const preliminaryPayloadFiles = inputSnapshot.paths.filter((path) => !GENERATED_FILES.has(path));
    const distFiles = preliminaryPayloadFiles.filter((path) => path.startsWith("dist/"));
    const build = treeEvidenceFromSnapshot(inputSnapshot, distFiles);
    const runtimeClosureInput = deriveRuntimeOperationsClosureFromSnapshot(inputSnapshot, { requireGeneratedMetadata: false });
    const generatedMetadata = collectGateEvidence === null
      ? null
      : options.generatedReleaseMetadataFactory({
          sourceRoot,
          packageRoot: staging,
          sourceRevision,
          build,
          identities,
          runtimeClosureInput,
        });
    const metadataBytes = collectGateEvidence === null
      ? fixtureGeneratedReleaseMetadataBytes(options, {
        build,
        identities,
        runtimeClosureInput,
        sourceRevision,
      })
      : Buffer.from(generatedMetadata.bytes);
    writeCapturedBytesAtomic(resolveContained(staging, GENERATED_RELEASE_METADATA_PATH), metadataBytes);
    const metadataSnapshot = snapshotReleaseTree(staging);
    const runtimeClosure = deriveRuntimeOperationsClosureFromSnapshot(metadataSnapshot);
    const runtimeMetadata = runtimeReleaseMetadataFromSnapshot(metadataSnapshot, {
      allowUnattestedFixture: collectGateEvidence === null,
      buildDigest: build.sha256,
      expectedProducer: collectGateEvidence === null ? undefined : {
        ...options.expectedGateProducer,
        publicKeySpkiDerBase64: generatedMetadata.publicKeySpkiDerBase64,
      },
      identities,
      runtimeClosure,
      runtimeClosureInput,
      sourceRevision,
    });
    const gateEvidence = collectGateEvidence?.({ sourceRoot, staging, sourceRevision, identities, build, runtimeMetadata }) ?? null;
    const payloadSnapshot = snapshotReleaseTree(staging);
    const finalClosure = deriveRuntimeOperationsClosureFromSnapshot(payloadSnapshot);
    if (canonicalJson(finalClosure) !== canonicalJson(runtimeClosure)) {
      throw new Error("Runtime operations closure changed during trusted gate collection.");
    }
    const payloadFiles = payloadSnapshot.paths.filter((path) => !GENERATED_FILES.has(path));
    const payload = treeEvidenceFromSnapshot(payloadSnapshot, payloadFiles);
    assertForbiddenArtifactGateFromSnapshot(payloadSnapshot, {
      buildCapabilities: runtimeMetadata.buildCapabilities,
      identities,
      migrationManifest: runtimeMetadata.migrationManifest,
    });
    const packageJson = snapshotJson(payloadSnapshot, "package.json", "release package manifest");
    const components = lockfileComponentsFromSnapshot(payloadSnapshot);
    writeJsonAtomic(resolveContained(staging, SPDX_SBOM_NAME), createSpdxSbom(packageJson, components, build.sha256, createdAt));
    writeJsonAtomic(resolveContained(staging, CYCLONEDX_SBOM_NAME), createCycloneDxSbom(packageJson, components, build.sha256, createdAt));
    writeJsonAtomic(resolveContained(staging, SBOM_INDEX_NAME), {
      schemaVersion: 1,
      formats: [
        { format: "SPDX-2.3", path: SPDX_SBOM_NAME },
        { format: "CycloneDX-1.6", path: CYCLONEDX_SBOM_NAME },
      ],
    });

    const manifest = {
      manifestVersion: 2,
      sourceRevision,
      buildDigest: build.sha256,
      payloadDigest: payload.sha256,
      runtimeRevision,
      schemaGeneration: identities.schemaGeneration,
      authorityContractGeneration: identities.authorityContractGeneration,
      configSchemaIdentity: identities.configSchemaIdentity,
      buildCapabilities: runtimeMetadata.buildCapabilities,
      migrationManifest: runtimeMetadata.migrationManifest,
      migrationManifestDigest: runtimeMetadata.migrationManifestDigest,
      gateProducer: gateEvidence?.gateProducer ?? null,
      releaseMetadata: {
        path: GENERATED_RELEASE_METADATA_PATH,
        sha256: `sha256:${snapshotFile(payloadSnapshot, GENERATED_RELEASE_METADATA_PATH).sha256}`,
        kind: runtimeMetadata.envelope.kind,
        payloadDigest: runtimeMetadata.envelope.payloadDigest,
      },
      runtime: runtimeDescriptor(payloadSnapshot, finalClosure),
      runtimeClosure: finalClosure,
      files: payload.files,
      payloadFiles,
      runtimeFiles: distFiles,
      createdAt,
      nodeVersion: process.version,
      platform: `${process.platform}-${process.arch}`,
      forbiddenArtifactScan: "PASS",
    };
    writeJsonAtomic(resolveContained(staging, RELEASE_MANIFEST_NAME), manifest);
    writeChecksums(staging);
    verifyReleasePackageInternal(staging, {
      expectedSourceRevision: sourceRevision,
      expectedRuntimeRevision: runtimeRevision,
      allowUnattestedFixture: gateEvidence === null,
      expectedGateProducer: gateEvidence === null ? null : options.expectedGateProducer,
      expectedGeneratedMetadataProducer: gateEvidence === null ? undefined : {
        ...options.expectedGateProducer,
        publicKeySpkiDerBase64: generatedMetadata.publicKeySpkiDerBase64,
      },
    });
    fsyncDirectory(staging);
    mkdirSync(dirname(outputRoot), { recursive: true, mode: 0o700 });
    renameSync(staging, outputRoot);
    fsyncDirectory(dirname(outputRoot));
    return { root: outputRoot, manifest };
  } catch (error) {
    rmSync(staging, { recursive: true, force: true });
    throw error;
  }
}

export function verifyReleasePackage(packageRoot, options = {}) {
  return verifyReleasePackageInternal(packageRoot, {
    ...options,
    allowUnattestedFixture: false,
    expectedGateProducer: trustedGateProducerIdentity(options.gateProducerTrustAnchor),
  });
}

export function verifyUnattestedReleaseFixture(packageRoot, options = {}) {
  return verifyReleasePackageInternal(packageRoot, {
    ...options,
    allowUnattestedFixture: true,
    expectedGateProducer: null,
  });
}

export function verifyGateProducerTrustAnchor(options) {
  const configuration = requiredObjectValue(options, "gate producer trust anchor options");
  const path = canonicalOwnerOnlyAbsoluteFile(configuration.path, "gate producer trust anchor");
  const bytes = stableReadRegularFile(path, "gate producer trust anchor").bytes;
  const sha = `sha256:${sha256(bytes)}`;
  if (sha !== requireSha256(configuration.sha256, "gate producer trust anchor sha256")) {
    throw new Error("Gate producer trust anchor digest differs from its configured immutable binding.");
  }
  const envelope = parseCanonicalJsonBytes(bytes, "gate producer trust anchor");
  const envelopeKeys = ["keyId", "kind", "payload", "payloadDigest", "schemaVersion", "signature"];
  if (canonicalJson(Object.keys(envelope).sort(compareAscii)) !== canonicalJson(envelopeKeys.sort(compareAscii))
    || envelope.schemaVersion !== 1 || envelope.kind !== TRUST_ANCHOR_KIND
    || !MANAGEMENT_KEY_ID_PATTERN.test(envelope.keyId ?? "")
    || !DIGEST_PATTERN.test(envelope.payloadDigest ?? "")
    || !MANAGEMENT_SIGNATURE_PATTERN.test(envelope.signature ?? "")) {
    throw new Error("Gate producer trust anchor envelope is invalid.");
  }
  const key = normalizeManagementAuthorizationKey(configuration.key);
  if (envelope.keyId !== key.keyId) throw new Error("Gate producer trust anchor management keyId differs.");
  const payload = requiredObjectValue(envelope.payload, "gate producer trust anchor payload");
  const payloadKeys = ["anchorNonce", "createdAt", "environment", "gateProducer", "ownerInstanceId", "provisioning"];
  if (canonicalJson(Object.keys(payload).sort(compareAscii)) !== canonicalJson(payloadKeys.sort(compareAscii))
    || envelope.payloadDigest !== canonicalJsonSha256(payload)
    || payload.provisioning !== "ONE_TIME_OWNER_APPROVED"
    || typeof payload.anchorNonce !== "string" || !/^[A-Za-z0-9_-]{22,128}$/u.test(payload.anchorNonce)
    || typeof payload.createdAt !== "string" || !Number.isFinite(Date.parse(payload.createdAt))
    || typeof payload.ownerInstanceId !== "string" || payload.ownerInstanceId.length < 8 || payload.ownerInstanceId.length > 512
    || typeof payload.environment !== "string" || payload.environment.length < 1 || payload.environment.length > 128) {
    throw new Error("Gate producer trust anchor payload is invalid.");
  }
  if (payload.ownerInstanceId !== configuration.expectedOwnerInstanceId
    || payload.environment !== configuration.expectedEnvironment) {
    throw new Error("Gate producer trust anchor owner/environment scope differs.");
  }
  const identity = normalizeExpectedGateProducer(payload.gateProducer);
  const unsigned = {
    schemaVersion: envelope.schemaVersion,
    kind: envelope.kind,
    keyId: envelope.keyId,
    payload,
    payloadDigest: envelope.payloadDigest,
  };
  const expectedSignature = createHmac("sha256", key.secret)
    .update(`${TRUST_ANCHOR_DOMAIN}/${TRUST_ANCHOR_KIND}\0`)
    .update(canonicalJson(unsigned))
    .digest("base64url");
  const expectedBytes = Buffer.from(expectedSignature);
  const actualBytes = Buffer.from(envelope.signature);
  if (expectedBytes.length !== actualBytes.length || !timingSafeEqual(expectedBytes, actualBytes)) {
    throw new Error("Gate producer trust anchor management HMAC is invalid.");
  }
  const verified = Object.freeze({
    path,
    sha256: sha,
    keyId: key.keyId,
    ownerInstanceId: payload.ownerInstanceId,
    environment: payload.environment,
    createdAt: payload.createdAt,
    anchorNonce: payload.anchorNonce,
    gateProducer: identity,
  });
  verifiedGateProducerTrustAnchors.set(verified, identity);
  return verified;
}

export function createGateProducerTrustAnchor(options) {
  const configuration = requiredObjectValue(options, "gate producer trust anchor creation options");
  const path = configuration.path;
  if (typeof path !== "string" || !isAbsolute(path) || resolve(path) !== path || /[\0\r\n]/u.test(path)) {
    throw new Error("Gate producer trust anchor output must be a canonical absolute path.");
  }
  if (existsSync(path)) throw new Error(`Gate producer trust anchor already exists: ${path}`);
  const privateKeyPath = canonicalOwnerOnlyAbsoluteFile(configuration.privateKeyPath, "gate producer private key");
  let privateKey;
  try { privateKey = createPrivateKey(readFileSync(privateKeyPath)); }
  catch { throw new Error("Gate producer private key is unreadable or invalid."); }
  if (privateKey.asymmetricKeyType !== "ed25519") throw new Error("Gate producer private key must be Ed25519.");
  const publicDer = createPublicKey(privateKey).export({ format: "der", type: "spki" });
  const publicKeySha256 = `sha256:${sha256(publicDer)}`;
  const gateProducer = Object.freeze({
    keyId: `gate-producer-ed25519-sha256:${publicKeySha256.slice("sha256:".length)}`,
    publicKeySha256,
  });
  const key = normalizeManagementAuthorizationKey(configuration.key);
  const createdAt = normalizeCreatedAt(configuration.createdAt);
  const ownerInstanceId = configuration.ownerInstanceId;
  const environment = configuration.environment;
  if (typeof ownerInstanceId !== "string" || ownerInstanceId.length < 8 || ownerInstanceId.length > 512
    || typeof environment !== "string" || environment.length < 1 || environment.length > 128) {
    throw new Error("Gate producer trust anchor owner/environment scope is invalid.");
  }
  const payload = {
    anchorNonce: randomBytes(32).toString("base64url"),
    createdAt,
    environment,
    gateProducer,
    ownerInstanceId,
    provisioning: "ONE_TIME_OWNER_APPROVED",
  };
  const unsigned = {
    schemaVersion: 1,
    kind: TRUST_ANCHOR_KIND,
    keyId: key.keyId,
    payload,
    payloadDigest: canonicalJsonSha256(payload),
  };
  const envelope = {
    ...unsigned,
    signature: createHmac("sha256", key.secret)
      .update(`${TRUST_ANCHOR_DOMAIN}/${TRUST_ANCHOR_KIND}\0`)
      .update(canonicalJson(unsigned))
      .digest("base64url"),
  };
  writeOwnerOnlyTextAtomic(path, `${canonicalJson(envelope)}\n`);
  return verifyGateProducerTrustAnchor({
    path,
    sha256: `sha256:${fileSha256(path)}`,
    key: configuration.key,
    expectedOwnerInstanceId: ownerInstanceId,
    expectedEnvironment: environment,
  });
}

export function assertVerifiedGateProducerTrustAnchor(value) {
  return Object.freeze({ ...trustedGateProducerIdentity(value) });
}

export function verifiedReleaseManifest(verification) {
  const context = verifiedReleaseContexts.get(verification);
  if (!context) throw new Error("Release manifest access requires the exact frozen verification result.");
  return context.manifest;
}

function verifiedReleaseContext(verification, packageRoot, options = {}) {
  const context = verifiedReleaseContexts.get(verification);
  if (!context) throw new Error("Runtime helper requires the exact frozen release verification result.");
  if (resolve(packageRoot) !== context.root) throw new Error("Frozen release verification belongs to a different package root.");
  if (options.allowUnattestedFixture !== true && verification.status !== "PASS") {
    throw new Error("Unattested fixture verification cannot satisfy a production runtime helper.");
  }
  return context;
}

function verifyForRuntimeHelper(packageRoot, options) {
  if (options.verifiedRelease !== undefined) {
    return {
      release: options.verifiedRelease,
      context: verifiedReleaseContext(options.verifiedRelease, packageRoot, {
        allowUnattestedFixture: options.allowUnattestedFixture === true,
      }),
    };
  }
  if (options.allowUnattestedFixture === true) {
    const release = verifyUnattestedReleaseFixture(packageRoot, options);
    return {
      release,
      context: verifiedReleaseContext(release, packageRoot, { allowUnattestedFixture: true }),
    };
  }
  const release = verifyReleasePackage(packageRoot, { gateProducerTrustAnchor: options.gateProducerTrustAnchor });
  return { release, context: verifiedReleaseContext(release, packageRoot) };
}

export function inspectVerifiedReleaseGateLedger(packageRoot, options = {}) {
  const gateProducer = trustedGateProducerIdentity(options.gateProducerTrustAnchor);
  const release = verifyReleasePackage(packageRoot, { ...options, gateProducerTrustAnchor: options.gateProducerTrustAnchor });
  const { manifest, snapshot } = verifiedReleaseContext(release, packageRoot);
  assertExpectedGateProducer(manifest.gateProducer, gateProducer);
  const ledger = validateGateProducerPackageBinding(snapshot, manifest);
  return Object.freeze({
    release,
    manifest: Object.freeze(manifest),
    ledger: Object.freeze(ledger),
    gateProducer,
    verifyGateProducerEnvelope(bytes, expectedKind) {
      return verifyExternalGateProducerEnvelope(bytes, snapshot, manifest, expectedKind);
    },
    readPayload(path) {
      if (!manifest.payloadFiles.includes(path)) throw new Error(`Requested gate artifact is absent from immutable payload: ${path}`);
      return Buffer.from(snapshotFile(snapshot, path).bytes);
    },
  });
}

function verifyExternalGateProducerEnvelope(bytes, snapshot, manifest, expectedKind) {
  if (!Buffer.isBuffer(bytes) || typeof expectedKind !== "string" || expectedKind.length === 0) {
    throw new Error("Gate producer envelope verification input is invalid.");
  }
  const artifact = snapshotJson(snapshot, manifest.gateProducer.publicKeyPath, "gate producer public-key artifact");
  let publicDer;
  try { publicDer = Buffer.from(artifact.publicKeySpkiDerBase64, "base64"); }
  catch { throw new Error("Gate producer public key is not canonical base64 DER."); }
  if (publicDer.toString("base64") !== artifact.publicKeySpkiDerBase64
    || `sha256:${sha256(publicDer)}` !== manifest.gateProducer.publicKeySha256
    || artifact.keyId !== manifest.gateProducer.keyId) {
    throw new Error("Gate producer public key differs from the independently pinned package identity.");
  }
  let publicKey;
  try { publicKey = createPublicKey({ key: publicDer, format: "der", type: "spki" }); }
  catch { throw new Error("Gate producer public key is not canonical SPKI DER."); }
  if (publicKey.asymmetricKeyType !== "ed25519") throw new Error("Gate producer public key is not Ed25519.");
  const envelope = parseCanonicalJsonBytes(bytes, "gate producer signed envelope");
  const keys = ["keyId", "kind", "payload", "payloadDigest", "schemaVersion", "signature"];
  if (canonicalJson(Object.keys(envelope).sort(compareAscii)) !== canonicalJson(keys.sort(compareAscii))
    || envelope.schemaVersion !== 1 || envelope.kind !== expectedKind
    || envelope.keyId !== manifest.gateProducer.keyId
    || envelope.payloadDigest !== canonicalJsonSha256(envelope.payload)
    || typeof envelope.signature !== "string") {
    throw new Error("Gate producer signed envelope identity is invalid.");
  }
  let signature;
  try { signature = Buffer.from(envelope.signature, "base64url"); }
  catch { throw new Error("Gate producer signed envelope signature is invalid."); }
  if (signature.length !== 64 || signature.toString("base64url") !== envelope.signature) {
    throw new Error("Gate producer signed envelope signature is noncanonical.");
  }
  const unsigned = {
    schemaVersion: envelope.schemaVersion,
    kind: envelope.kind,
    keyId: envelope.keyId,
    payloadDigest: envelope.payloadDigest,
    payload: envelope.payload,
  };
  const message = Buffer.from(`devspace.base-profile-gate-producer.v1/${expectedKind}\0${canonicalJson(unsigned)}`);
  if (!verifySignature(null, message, publicKey, signature)) throw new Error("Gate producer signed envelope Ed25519 signature is invalid.");
  return Object.freeze(envelope);
}

function verifyReleasePackageInternal(packageRoot, options = {}) {
  const root = resolve(packageRoot);
  const snapshot = snapshotReleaseTree(root);
  for (const path of [
    "dist",
    "package.json",
    "config",
    "contracts",
    "config.schema.json",
    SPDX_SBOM_NAME,
    CYCLONEDX_SBOM_NAME,
    SBOM_INDEX_NAME,
    GENERATED_RELEASE_METADATA_PATH,
    RELEASE_MANIFEST_NAME,
    RELEASE_CHECKSUM_NAME,
  ]) {
    if (path === "dist" || path === "config" || path === "contracts") {
      if (!snapshot.paths.some((candidate) => candidate.startsWith(`${path}/`))) throw new Error(`Release package is missing: ${path}`);
    } else if (!snapshot.files.has(path)) throw new Error(`Release package is missing: ${path}`);
  }
  const expectedChecksums = parseChecksums(snapshotText(snapshot, RELEASE_CHECKSUM_NAME));
  const actualFiles = snapshot.paths.filter((path) => path !== RELEASE_CHECKSUM_NAME);
  const expectedFiles = [...expectedChecksums.keys()].sort();
  if (actualFiles.length !== expectedFiles.length || actualFiles.some((path) => !expectedChecksums.has(path))) {
    const added = actualFiles.filter((path) => !expectedChecksums.has(path));
    const missing = expectedFiles.filter((path) => !actualFiles.includes(path));
    throw new Error(`Release package file set mismatch: ${JSON.stringify({ added, missing })}`);
  }
  for (const [path, expected] of expectedChecksums) {
    const actual = snapshotFile(snapshot, path).sha256;
    if (actual !== expected) throw new Error(`Release package checksum mismatch: ${path}`);
  }

  const manifest = snapshotJson(snapshot, RELEASE_MANIFEST_NAME, "release manifest");
  validateManifest(manifest);
  if (manifest.gateProducer !== null) validateGateProducerPackageBinding(snapshot, manifest);
  if (manifest.gateProducer === null && options.allowUnattestedFixture !== true) {
    throw new Error("Release package has no attested gate producer ledger.");
  }
  if (manifest.gateProducer !== null) {
    assertExpectedGateProducer(manifest.gateProducer, options.expectedGateProducer);
  } else if (options.expectedGateProducer !== null && options.expectedGateProducer !== undefined) {
    throw new Error("Unattested fixture package cannot satisfy a trusted gate producer identity.");
  }
  if (options.expectedSourceRevision && manifest.sourceRevision !== options.expectedSourceRevision) {
    throw new Error(`Release source revision mismatch: expected ${options.expectedSourceRevision}, observed ${manifest.sourceRevision}`);
  }
  if (options.expectedRuntimeRevision && manifest.runtimeRevision !== options.expectedRuntimeRevision) {
    throw new Error(`Release runtime revision mismatch: expected ${options.expectedRuntimeRevision}, observed ${manifest.runtimeRevision}`);
  }
  const build = treeEvidenceFromSnapshot(snapshot, manifest.payloadFiles);
  if (build.files !== manifest.files || build.sha256 !== manifest.payloadDigest) {
    throw new Error(`Release payload digest mismatch: expected ${manifest.payloadDigest}, observed ${build.sha256}`);
  }
  const runtimeBuild = treeEvidenceFromSnapshot(snapshot, manifest.runtimeFiles);
  if (runtimeBuild.sha256 !== manifest.buildDigest) throw new Error(`Release build digest mismatch: expected ${manifest.buildDigest}, observed ${runtimeBuild.sha256}`);
  const runtimeClosure = deriveRuntimeOperationsClosureFromSnapshot(snapshot);
  if (canonicalJson(runtimeClosure) !== canonicalJson(manifest.runtimeClosure)) {
    throw new Error("Release runtime operations closure differs from the exact captured transitive closure.");
  }
  const runtimeClosureInput = deriveRuntimeOperationsClosureFromSnapshot(snapshotWithoutGeneratedMetadata(snapshot), {
    requireGeneratedMetadata: false,
  });
  const identities = deriveReleaseIdentitiesFromSnapshot(snapshot);
  for (const key of ["schemaGeneration", "authorityContractGeneration", "configSchemaIdentity"]) {
    if (manifest[key] !== identities[key]) throw new Error(`Release ${key} mismatch.`);
  }
  const expectedMetadataProducer = manifest.gateProducer === null
    ? undefined
    : generatedMetadataProducerFromSnapshot(snapshot, manifest, options.expectedGateProducer);
  const runtimeMetadata = runtimeReleaseMetadataFromSnapshot(snapshot, {
    allowUnattestedFixture: options.allowUnattestedFixture === true,
    buildDigest: manifest.buildDigest,
    expectedProducer: expectedMetadataProducer,
    identities,
    runtimeClosure,
    runtimeClosureInput,
    sourceRevision: manifest.sourceRevision,
  });
  if (manifest.releaseMetadata.path !== GENERATED_RELEASE_METADATA_PATH
    || manifest.releaseMetadata.sha256 !== `sha256:${snapshotFile(snapshot, GENERATED_RELEASE_METADATA_PATH).sha256}`
    || manifest.releaseMetadata.kind !== runtimeMetadata.envelope.kind
    || manifest.releaseMetadata.payloadDigest !== runtimeMetadata.envelope.payloadDigest) {
    throw new Error("Release generated metadata binding differs from the captured artifact.");
  }
  if (canonicalJson(manifest.buildCapabilities) !== canonicalJson(runtimeMetadata.buildCapabilities)) {
    throw new Error("Release build capability manifest mismatch.");
  }
  if (canonicalJson(manifest.migrationManifest) !== canonicalJson(runtimeMetadata.migrationManifest)
    || manifest.migrationManifestDigest !== runtimeMetadata.migrationManifestDigest) {
    throw new Error("Release migration manifest mismatch.");
  }
  const configSchema = snapshotJson(snapshot, "config.schema.json", "top-level config schema");
  const canonicalConfigSchema = snapshotJson(snapshot, "config/config.schema.json", "canonical config schema");
  if (canonicalJson(configSchema) !== canonicalJson(canonicalConfigSchema)
    || canonicalJsonSha256(configSchema) !== manifest.configSchemaIdentity) {
    throw new Error("Release config schema identity is not bound to the canonical packaged schema.");
  }
  assertForbiddenArtifactGateFromSnapshot(snapshot, {
    buildCapabilities: runtimeMetadata.buildCapabilities,
    identities,
    migrationManifest: runtimeMetadata.migrationManifest,
  });
  verifySboms(snapshot, manifest);
  const result = Object.freeze({
    status: manifest.gateProducer === null ? "UNATTESTED_FIXTURE_ONLY" : "PASS",
    sourceRevision: manifest.sourceRevision,
    runtimeRevision: manifest.runtimeRevision,
    buildDigest: manifest.buildDigest,
    schemaGeneration: manifest.schemaGeneration,
    authorityContractGeneration: manifest.authorityContractGeneration,
    configSchemaIdentity: manifest.configSchemaIdentity,
    buildCapabilityDigest: manifest.buildCapabilities.capabilityDigest,
    migrationManifestDigest: manifest.migrationManifestDigest,
    files: actualFiles.length + 1,
    manifestSha256: `sha256:${snapshotFile(snapshot, RELEASE_MANIFEST_NAME).sha256}`,
    checksumsSha256: `sha256:${snapshotFile(snapshot, RELEASE_CHECKSUM_NAME).sha256}`,
    runtimeClosureSha256: runtimeClosure.sha256,
    releaseMetadataSha256: manifest.releaseMetadata.sha256,
  });
  verifiedReleaseContexts.set(result, Object.freeze({
    manifest: deepFreezeJson(manifest),
    root,
    runtimeMetadata,
    snapshot,
  }));
  return result;
}

export function verifyRuntimeCommand(packageRoot, runtimeRoot, entrypoint, options = {}) {
  const root = resolve(packageRoot);
  const { release, context } = verifyForRuntimeHelper(root, options);
  const { manifest, snapshot } = context;
  const expectedRoot = manifest.runtime.cwd === "." ? root : resolveContained(root, manifest.runtime.cwd);
  const expectedEntrypoint = resolveContained(root, manifest.runtime.entrypoint);
  if (resolve(runtimeRoot) !== expectedRoot) {
    throw new Error(`Runtime cwd is not bound to the immutable release manifest: expected ${expectedRoot}, observed ${resolve(runtimeRoot)}`);
  }
  if (resolve(entrypoint) !== expectedEntrypoint) {
    throw new Error(`Runtime entrypoint is not bound to the immutable release manifest: expected ${expectedEntrypoint}, observed ${resolve(entrypoint)}`);
  }
  snapshotFile(snapshot, manifest.runtime.entrypoint);
  const manifestSha256 = release.manifestSha256;
  if (options.expectedManifestSha256 && manifestSha256 !== options.expectedManifestSha256) {
    throw new Error(`Runtime release manifest digest mismatch: expected ${options.expectedManifestSha256}, observed ${manifestSha256}`);
  }
  return {
    status: "PASS",
    packageRoot: root,
    runtimeRoot: expectedRoot,
    entrypoint: expectedEntrypoint,
    manifestSha256,
  };
}

export function sealRuntimeDependencies(packageRoot, dependencyRoot, options = {}) {
  const root = resolve(packageRoot);
  const dependencies = resolve(dependencyRoot);
  if (pathsOverlap(dependencies, root)) {
    throw new Error("Runtime dependency root must remain separate from the immutable package.");
  }
  const dependencyRootMetadata = lstatSync(dependencies);
  if (!dependencyRootMetadata.isDirectory() || dependencyRootMetadata.isSymbolicLink()) {
    throw new Error("Runtime dependency root must be a real directory.");
  }
  const { release, context } = verifyForRuntimeHelper(root, options);
  const { manifest, snapshot } = context;
  const evidencePath = resolveContained(dependencies, RUNTIME_DEPENDENCY_MANIFEST_NAME);
  if (existsSync(evidencePath)) throw new Error(`Runtime dependency evidence already exists: ${evidencePath}`);
  assertDependencyInputs(manifest, snapshot, dependencies);
  const tree = runtimeDependencyTreeEvidence(resolveContained(dependencies, "node_modules"));
  const evidence = {
    manifestVersion: 1,
    installMode: "npm-ci-lockfile-v1",
    packageManifestSha256: release.manifestSha256,
    packageJsonSha256: manifest.runtime.dependencies.packageJsonSha256,
    lockfileSha256: manifest.runtime.dependencies.lockfileSha256,
    nodeVersion: process.version,
    platform: `${process.platform}-${process.arch}`,
    nodeModules: tree,
    createdAt: normalizeCreatedAt(options.createdAt),
  };
  writeJsonAtomic(evidencePath, evidence);
  chmodSync(evidencePath, 0o600);
  fsyncFile(evidencePath);
  fsyncDirectory(dirname(evidencePath));
  return {
    status: "SEALED",
    dependencyRoot: dependencies,
    evidencePath,
    evidenceSha256: `sha256:${fileSha256(evidencePath)}`,
    evidence,
  };
}

export function verifyRuntimeDependencies(packageRoot, dependencyRoot, options = {}) {
  const root = resolve(packageRoot);
  const dependencies = resolve(dependencyRoot);
  if (pathsOverlap(dependencies, root)) {
    throw new Error("Runtime dependency root must remain separate from the immutable package.");
  }
  const dependencyRootMetadata = lstatSync(dependencies);
  if (!dependencyRootMetadata.isDirectory() || dependencyRootMetadata.isSymbolicLink()) {
    throw new Error("Runtime dependency root must be a real directory.");
  }
  const { release, context } = verifyForRuntimeHelper(root, options);
  const { manifest, snapshot } = context;
  const evidencePath = resolve(options.evidencePath ?? resolveContained(dependencies, RUNTIME_DEPENDENCY_MANIFEST_NAME));
  if (evidencePath !== resolveContained(dependencies, RUNTIME_DEPENDENCY_MANIFEST_NAME)) {
    throw new Error("Runtime dependency evidence must use the canonical dependency-root path.");
  }
  const stableEvidence = stableReadRegularFile(evidencePath, "runtime dependency evidence");
  if ((BigInt(stableEvidence.identity.mode) & 0o77n) !== 0n) {
    throw new Error("Runtime dependency evidence must be an owner-only regular file.");
  }
  const evidenceSha256 = `sha256:${sha256(stableEvidence.bytes)}`;
  if (options.expectedEvidenceSha256 && evidenceSha256 !== options.expectedEvidenceSha256) {
    throw new Error(`Runtime dependency evidence digest mismatch: expected ${options.expectedEvidenceSha256}, observed ${evidenceSha256}`);
  }
  let evidence;
  try { evidence = JSON.parse(stableEvidence.bytes.toString("utf8")); }
  catch { throw new Error("Runtime dependency evidence is invalid JSON."); }
  if (evidence?.manifestVersion !== 1 || evidence.installMode !== "npm-ci-lockfile-v1") {
    throw new Error("Runtime dependency evidence format is invalid.");
  }
  for (const [name, expected, observed] of [
    ["package manifest", release.manifestSha256, evidence.packageManifestSha256],
    ["package.json", manifest.runtime.dependencies.packageJsonSha256, evidence.packageJsonSha256],
    ["package lock", manifest.runtime.dependencies.lockfileSha256, evidence.lockfileSha256],
    ["Node version", process.version, evidence.nodeVersion],
    ["platform", `${process.platform}-${process.arch}`, evidence.platform],
  ]) {
    if (observed !== expected) throw new Error(`Runtime dependency ${name} binding mismatch: expected ${expected}, observed ${observed}`);
  }
  assertDependencyInputs(manifest, snapshot, dependencies);
  const observedTree = runtimeDependencyTreeEvidence(resolveContained(dependencies, "node_modules"));
  if (canonicalJson(observedTree) !== canonicalJson(evidence.nodeModules)) {
    throw new Error(`Runtime dependency tree mismatch: expected ${canonicalJson(evidence.nodeModules)}, observed ${canonicalJson(observedTree)}`);
  }
  return {
    status: "PASS",
    dependencyRoot: dependencies,
    evidencePath,
    evidenceSha256,
    nodeModules: observedTree,
  };
}

export function assertRuntimeIdentity(manifest, observed) {
  const identity = observed?.identity ?? observed;
  const fields = [
    ["sourceRevision", "sourceRevision"],
    ["runtimeRevision", "runtimeRevision"],
    ["buildDigest", "buildDigest"],
    ["schemaGeneration", "schemaGeneration"],
    ["authorityContractGeneration", "authorityContractGeneration"],
  ];
  for (const [manifestKey, observedKey] of fields) {
    if (identity?.[observedKey] !== manifest?.[manifestKey]) {
      throw new Error(`Runtime identity mismatch for ${observedKey}: expected ${manifest?.[manifestKey]}, observed ${identity?.[observedKey]}`);
    }
  }
  if (!/^sha256:[a-f0-9]{64}$/u.test(identity?.configDigest ?? "")) throw new Error("Runtime configDigest is missing or invalid.");
  return true;
}

export function assertGatewayIdentity(manifest, observed) {
  const fields = ["runtimeRevision", "schemaGeneration", "authorityContractGeneration"];
  for (const key of fields) {
    if (observed?.[key] !== manifest?.[key]) throw new Error(`Gateway identity mismatch for ${key}: expected ${manifest?.[key]}, observed ${observed?.[key]}`);
  }
  if (observed?.status !== "ok") throw new Error(`Gateway health is not ok: ${observed?.status}`);
  return true;
}

export function verifyRuntimeTree(packageRoot, runtimeRoot, options = {}) {
  const root = resolve(packageRoot);
  const { context } = verifyForRuntimeHelper(root, options);
  const { manifest, snapshot } = context;
  const runtime = resolve(runtimeRoot);
  const observed = runtime === root
    ? treeEvidenceFromSnapshot(snapshot, manifest.runtimeFiles)
    : treeEvidenceFromStableRuntimeRoot(runtime, manifest.runtimeFiles);
  if (observed.sha256 !== manifest.buildDigest) {
    throw new Error(`Runtime dist differs from immutable release: expected ${manifest.buildDigest}, observed ${observed.sha256}`);
  }
  return { status: "PASS", runtimeRoot: runtime, runtimeRevision: manifest.runtimeRevision, buildDigest: observed.sha256, files: observed.files };
}

function validateManifest(value) {
  if (!value || value.manifestVersion !== 2) throw new Error("Unsupported release manifest version.");
  for (const key of [
    "sourceRevision",
    "runtimeRevision",
    "buildDigest",
    "payloadDigest",
    "schemaGeneration",
    "authorityContractGeneration",
    "configSchemaIdentity",
    "createdAt",
    "nodeVersion",
    "platform",
  ]) {
    if (typeof value[key] !== "string" || value[key].length === 0) throw new Error(`Release manifest field is invalid: ${key}`);
  }
  for (const key of ["buildDigest", "payloadDigest", "schemaGeneration", "authorityContractGeneration", "configSchemaIdentity"]) {
    if (!/^sha256:[a-f0-9]{64}$/u.test(value[key])) throw new Error(`Release manifest digest is invalid: ${key}`);
  }
  if (!Number.isInteger(value.files) || value.files < 1) throw new Error("Release manifest file count is invalid.");
  if (!Array.isArray(value.payloadFiles) || value.payloadFiles.length !== value.files) throw new Error("Release manifest payload list is invalid.");
  if (!Array.isArray(value.runtimeFiles) || value.runtimeFiles.length < 1 || value.runtimeFiles.some((path) => !value.payloadFiles.includes(path))) {
    throw new Error("Release manifest runtime file list is invalid.");
  }
  validateRuntimeOperationsClosureShape(value.runtimeClosure, value.payloadFiles);
  validateReleaseMetadataBindingShape(value.releaseMetadata, value.payloadFiles);
  validateBuildCapabilities(value.buildCapabilities, value.buildDigest);
  validateMigrationManifestShape(value.migrationManifest, value.migrationManifestDigest);
  if (value.gateProducer !== null) validateGateProducerManifestShape(value.gateProducer);
  validateRuntimeDescriptor(value.runtime, value.payloadFiles, value.runtimeClosure);
  if (value.forbiddenArtifactScan !== "PASS") throw new Error("Release manifest forbidden artifact gate did not pass.");
}

function validateReleaseMetadataBindingShape(value, payloadFiles) {
  const keys = ["kind", "path", "payloadDigest", "sha256"];
  if (!value || typeof value !== "object" || Array.isArray(value)
    || canonicalJson(Object.keys(value).sort(compareAscii)) !== canonicalJson(keys)
    || value.path !== GENERATED_RELEASE_METADATA_PATH
    || !payloadFiles.includes(value.path)
    || ![GENERATED_RELEASE_METADATA_KIND, GENERATED_RELEASE_METADATA_FIXTURE_KIND].includes(value.kind)
    || !DIGEST_PATTERN.test(value.payloadDigest ?? "")
    || !DIGEST_PATTERN.test(value.sha256 ?? "")) {
    throw new Error("Release generated metadata binding is invalid.");
  }
}

function validateRuntimeOperationsClosureShape(value, payloadFiles) {
  const keys = ["edges", "externals", "files", "roots", "schemaVersion", "sha256"];
  if (!value || typeof value !== "object" || Array.isArray(value)
    || canonicalJson(Object.keys(value).sort(compareAscii)) !== canonicalJson(keys)
    || value.schemaVersion !== RUNTIME_OPERATIONS_CLOSURE_SCHEMA_VERSION
    || !DIGEST_PATTERN.test(value.sha256 ?? "")
    || !Array.isArray(value.roots) || !Array.isArray(value.files)
    || !Array.isArray(value.edges) || !Array.isArray(value.externals)) {
    throw new Error("Release runtime operations closure shape is invalid.");
  }
  const expectedRoots = [...RUNTIME_OPERATIONS_CLOSURE_ROOTS, GENERATED_RELEASE_METADATA_PATH].sort(compareAscii);
  if (canonicalJson(value.roots) !== canonicalJson(expectedRoots)) {
    throw new Error("Release runtime operations closure roots differ from the production root contract.");
  }
  const filePaths = [];
  for (const file of value.files) {
    if (!file || canonicalJson(Object.keys(file).sort(compareAscii)) !== canonicalJson(["path", "sha256"])
      || !DIGEST_PATTERN.test(file.sha256 ?? "")) throw new Error("Release runtime operations closure file binding is invalid.");
    const path = normalizeRelativePath(file.path);
    assertProductionClosurePath(path);
    if (!payloadFiles.includes(path)) throw new Error(`Release runtime operations closure file is absent from payload: ${path}`);
    filePaths.push(path);
  }
  if (new Set(filePaths).size !== filePaths.length || canonicalJson(filePaths) !== canonicalJson([...filePaths].sort(compareAscii))) {
    throw new Error("Release runtime operations closure file list is duplicated or unsorted.");
  }
  for (const root of value.roots) {
    if (!filePaths.includes(root)) throw new Error(`Release runtime operations closure root is absent: ${root}`);
  }
  const { sha256: _sha256, ...contract } = value;
  if (value.sha256 !== canonicalJsonSha256(contract)) throw new Error("Release runtime operations closure digest is invalid.");
}

function validateGateProducerManifestShape(value) {
  const expectedKeys = [
    "keyId", "preCutoverLedgerPath", "preCutoverLedgerSha256", "publicKeyPath",
    "publicKeySha256", "schemaVersion",
  ];
  if (!value || typeof value !== "object" || Array.isArray(value)
    || canonicalJson(Object.keys(value).sort(compareAscii)) !== canonicalJson(expectedKeys.sort(compareAscii))
    || value.schemaVersion !== 1
    || value.publicKeyPath !== BASE_PROFILE_GATE_PRODUCER_PUBLIC_KEY_PATH
    || value.preCutoverLedgerPath !== BASE_PROFILE_PRECUTOVER_LEDGER_PATH
    || !/^gate-producer-ed25519-sha256:[a-f0-9]{64}$/u.test(value.keyId ?? "")
    || !DIGEST_PATTERN.test(value.publicKeySha256 ?? "")
    || !DIGEST_PATTERN.test(value.preCutoverLedgerSha256 ?? "")
    || value.keyId.slice("gate-producer-ed25519-sha256:".length) !== value.publicKeySha256.slice("sha256:".length)) {
    throw new Error("Release gate producer manifest binding is invalid.");
  }
}

function normalizeExpectedGateProducer(value) {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new Error("A trusted external gate producer identity is required for release eligibility.");
  }
  const keys = Object.keys(value).sort(compareAscii);
  if (canonicalJson(keys) !== canonicalJson(["keyId", "publicKeySha256"])) {
    throw new Error("Trusted gate producer identity contains a missing or unsupported field.");
  }
  if (!/^gate-producer-ed25519-sha256:[a-f0-9]{64}$/u.test(value.keyId ?? "")
    || !DIGEST_PATTERN.test(value.publicKeySha256 ?? "")
    || value.keyId.slice("gate-producer-ed25519-sha256:".length)
      !== value.publicKeySha256.slice("sha256:".length)) {
    throw new Error("Trusted gate producer identity is invalid.");
  }
  return Object.freeze({ keyId: value.keyId, publicKeySha256: value.publicKeySha256 });
}

function trustedGateProducerIdentity(value) {
  const identity = value && typeof value === "object" ? verifiedGateProducerTrustAnchors.get(value) : undefined;
  if (!identity) throw new Error("A verified external gate producer trust anchor is required for release eligibility.");
  return identity;
}

function normalizeManagementAuthorizationKey(value) {
  const key = requiredObjectValue(value, "management authorization key");
  if (!MANAGEMENT_KEY_ID_PATTERN.test(key.keyId ?? "")) throw new Error("Management authorization keyId is invalid.");
  if (!(key.secret instanceof Uint8Array) || key.secret.byteLength !== 32) throw new Error("Management authorization key secret must contain exactly 32 bytes.");
  const expectedId = `management-${createHash("sha256").update(key.secret).digest("hex").slice(0, 24)}`;
  if (key.keyId !== expectedId) throw new Error("Management authorization keyId does not match its secret.");
  return Object.freeze({ keyId: key.keyId, secret: Buffer.from(key.secret) });
}

function canonicalOwnerOnlyAbsoluteFile(value, label) {
  if (typeof value !== "string" || !isAbsolute(value) || resolve(value) !== value || /[\0\r\n]/u.test(value)) {
    throw new Error(`${label} must be an absolute canonical path.`);
  }
  const metadata = lstatSync(value);
  if (!metadata.isFile() || metadata.isSymbolicLink() || realpathSync(value) !== value
    || (metadata.mode & 0o077) !== 0
    || (typeof process.getuid === "function" && metadata.uid !== process.getuid())) {
    throw new Error(`${label} must be an owner-only canonical real file.`);
  }
  return value;
}

function parseCanonicalJsonBytes(bytes, label) {
  let value;
  try { value = JSON.parse(bytes.toString("utf8")); }
  catch { throw new Error(`${label} is invalid JSON.`); }
  if (bytes.toString("utf8") !== `${canonicalJson(value)}\n`) throw new Error(`${label} is not canonical JSON.`);
  return value;
}

function requiredObjectValue(value, label) {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error(`${label} is missing or invalid.`);
  return value;
}

function requireSha256(value, label) {
  if (!DIGEST_PATTERN.test(value ?? "")) throw new Error(`${label} is not a canonical SHA-256 digest.`);
  return value;
}

function assertExpectedGateProducer(observed, expected) {
  const trusted = normalizeExpectedGateProducer(expected);
  if (observed.keyId !== trusted.keyId || observed.publicKeySha256 !== trusted.publicKeySha256) {
    throw new Error("Release gate producer differs from the independently pinned trusted identity.");
  }
}

function generatedMetadataProducerFromSnapshot(snapshot, manifest, expected) {
  const trusted = normalizeExpectedGateProducer(expected);
  assertExpectedGateProducer(manifest.gateProducer, trusted);
  const artifact = snapshotJson(snapshot, manifest.gateProducer.publicKeyPath, "gate producer public-key artifact");
  if (artifact.keyId !== trusted.keyId || artifact.publicKeySha256 !== trusted.publicKeySha256
    || typeof artifact.publicKeySpkiDerBase64 !== "string") {
    throw new Error("Generated release metadata producer key differs from the trusted packaged gate producer.");
  }
  return Object.freeze({
    keyId: trusted.keyId,
    publicKeySha256: trusted.publicKeySha256,
    publicKeySpkiDerBase64: artifact.publicKeySpkiDerBase64,
  });
}

function validateGateProducerPackageBinding(snapshot, manifest) {
  const value = manifest.gateProducer;
  validateGateProducerManifestShape(value);
  if (!manifest.payloadFiles.includes(value.publicKeyPath) || !manifest.payloadFiles.includes(value.preCutoverLedgerPath)) {
    throw new Error("Release gate producer artifacts are absent from the immutable payload list.");
  }
  const publicBytes = snapshotFile(snapshot, value.publicKeyPath).bytes;
  const ledgerBytes = snapshotFile(snapshot, value.preCutoverLedgerPath).bytes;
  if (`sha256:${sha256(ledgerBytes)}` !== value.preCutoverLedgerSha256) {
    throw new Error("Release pre-cutover gate ledger digest differs from BUILD-MANIFEST.json.");
  }
  let artifact;
  try { artifact = JSON.parse(publicBytes.toString("utf8")); }
  catch { throw new Error("Release gate producer public-key artifact is invalid JSON."); }
  const artifactKeys = ["algorithm", "keyId", "kind", "publicKeySha256", "publicKeySpkiDerBase64", "schemaVersion"];
  if (!artifact || canonicalJson(Object.keys(artifact).sort(compareAscii)) !== canonicalJson(artifactKeys.sort(compareAscii))
    || artifact.schemaVersion !== 1 || artifact.kind !== "DEVSPACE_BASE_PROFILE_GATE_PRODUCER_PUBLIC_KEY"
    || artifact.algorithm !== "Ed25519" || artifact.keyId !== value.keyId
    || artifact.publicKeySha256 !== value.publicKeySha256
    || typeof artifact.publicKeySpkiDerBase64 !== "string") {
    throw new Error("Release gate producer public-key artifact differs from BUILD-MANIFEST.json.");
  }
  if (publicBytes.toString("utf8") !== `${canonicalJson(artifact)}\n`) {
    throw new Error("Release gate producer public-key artifact is not canonical JSON.");
  }
  let publicDer;
  try { publicDer = Buffer.from(artifact.publicKeySpkiDerBase64, "base64"); }
  catch { throw new Error("Release gate producer public key is not canonical base64 DER."); }
  if (publicDer.toString("base64") !== artifact.publicKeySpkiDerBase64
    || `sha256:${sha256(publicDer)}` !== value.publicKeySha256) {
    throw new Error("Release gate producer public key digest is invalid.");
  }
  let publicKey;
  try { publicKey = createPublicKey({ key: publicDer, format: "der", type: "spki" }); }
  catch { throw new Error("Release gate producer public key is not canonical SPKI DER."); }
  if (publicKey.asymmetricKeyType !== "ed25519") throw new Error("Release gate producer public key is not Ed25519.");

  let ledger;
  try { ledger = JSON.parse(ledgerBytes.toString("utf8")); }
  catch { throw new Error("Release pre-cutover gate ledger is invalid JSON."); }
  if (ledgerBytes.toString("utf8") !== `${canonicalJson(ledger)}\n`) {
    throw new Error("Release pre-cutover gate ledger is not canonical JSON.");
  }
  const ledgerKeys = ["keyId", "kind", "payload", "payloadDigest", "schemaVersion", "signature"];
  if (!ledger || typeof ledger !== "object" || Array.isArray(ledger)
    || canonicalJson(Object.keys(ledger).sort(compareAscii)) !== canonicalJson(ledgerKeys.sort(compareAscii))
    || ledger.schemaVersion !== 1
    || ledger.kind !== "DEVSPACE_BASE_PROFILE_PRECUTOVER_GATE_LEDGER"
    || ledger.keyId !== value.keyId
    || !DIGEST_PATTERN.test(ledger.payloadDigest ?? "")
    || ledger.payloadDigest !== canonicalJsonSha256(ledger.payload)
    || typeof ledger.signature !== "string") {
    throw new Error("Release pre-cutover gate ledger envelope is invalid.");
  }
  let signature;
  try { signature = Buffer.from(ledger.signature, "base64url"); }
  catch { throw new Error("Release pre-cutover gate ledger signature is invalid."); }
  if (signature.length !== 64 || signature.toString("base64url") !== ledger.signature) {
    throw new Error("Release pre-cutover gate ledger signature is noncanonical.");
  }
  const unsigned = {
    schemaVersion: ledger.schemaVersion,
    kind: ledger.kind,
    keyId: ledger.keyId,
    payloadDigest: ledger.payloadDigest,
    payload: ledger.payload,
  };
  const message = Buffer.from(`devspace.base-profile-gate-producer.v1/${ledger.kind}\0${canonicalJson(unsigned)}`);
  if (!verifySignature(null, message, publicKey, signature)) {
    throw new Error("Release pre-cutover gate ledger Ed25519 signature is invalid.");
  }
  validateSignedPrecutoverLedgerPayload(snapshot, manifest, ledger.payload);
  return ledger;
}

function validateSignedPrecutoverLedgerPayload(snapshot, manifest, payload) {
  const keys = [
    "bindings", "environment", "environmentDigest", "gateBindings", "packageInputTree", "producer",
    "profileEvidence", "receipts", "receiptsDigest", "schemaVersion", "sourceRevision", "sourceTree",
    "testInventory", "toolchain", "toolchainDigest",
  ];
  if (!payload || typeof payload !== "object" || Array.isArray(payload)
    || canonicalJson(Object.keys(payload).sort(compareAscii)) !== canonicalJson(keys.sort(compareAscii))
    || payload.schemaVersion !== 1 || payload.sourceRevision !== manifest.sourceRevision
    || canonicalJson(payload.producer) !== canonicalJson({
      keyId: manifest.gateProducer.keyId,
      publicKeySha256: manifest.gateProducer.publicKeySha256,
    })
    || payload.environmentDigest !== canonicalJsonSha256(payload.environment)
    || payload.toolchainDigest !== canonicalJsonSha256(payload.toolchain)) {
    throw new Error("Release pre-cutover gate ledger payload identity is invalid.");
  }
  const bindingKeys = [
    "authorityContractGeneration", "buildCapabilityManifestDigest", "buildDigest", "generatedSchemaDigest",
    "migrationManifestDigest", "schemaGeneration", "sourceRevision",
  ];
  if (!payload.bindings || canonicalJson(Object.keys(payload.bindings).sort(compareAscii)) !== canonicalJson(bindingKeys.sort(compareAscii))) {
    throw new Error("Release pre-cutover gate ledger immutable bindings are invalid.");
  }
  for (const [key, expected] of [
    ["sourceRevision", manifest.sourceRevision],
    ["buildDigest", manifest.buildDigest],
    ["schemaGeneration", manifest.schemaGeneration],
    ["authorityContractGeneration", manifest.authorityContractGeneration],
    ["buildCapabilityManifestDigest", manifest.buildCapabilities.capabilityDigest],
    ["generatedSchemaDigest", generatedSchemaTreeDigestFromSnapshot(snapshot)],
    ["migrationManifestDigest", manifest.migrationManifestDigest],
  ]) {
    if (payload.bindings[key] !== expected) throw new Error(`Release pre-cutover gate ledger binding differs: ${key}`);
  }
  const packageInputPaths = snapshot.paths.filter((path) => (
    path !== RELEASE_MANIFEST_NAME && path !== RELEASE_CHECKSUM_NAME
      && path !== SPDX_SBOM_NAME && path !== CYCLONEDX_SBOM_NAME && path !== SBOM_INDEX_NAME
      && path !== BASE_PROFILE_GATE_PRODUCER_PUBLIC_KEY_PATH
      && path !== BASE_PROFILE_PRECUTOVER_LEDGER_PATH
      && !path.startsWith("evidence/base-profile-gates/")
  ));
  if (!payload.packageInputTree || payload.packageInputTree.sha256 !== treeEvidenceFromSnapshot(snapshot, packageInputPaths).sha256) {
    throw new Error("Release pre-cutover gate ledger package input tree differs.");
  }
  if (!Array.isArray(payload.receipts) || payload.receipts.length === 0) throw new Error("Release pre-cutover gate ledger has no command receipts.");
  const receipts = new Map();
  for (const receipt of payload.receipts) {
    if (!receipt || typeof receipt !== "object" || Array.isArray(receipt)
      || typeof receipt.id !== "string" || receipts.has(receipt.id)) {
      throw new Error("Release pre-cutover gate ledger command receipt is invalid or duplicated.");
    }
    const { receiptDigest, ...unsigned } = receipt;
    if (receiptDigest !== canonicalJsonSha256(unsigned) || receipt.exitCode !== 0 || receipt.signal !== null) {
      throw new Error(`Release pre-cutover gate ledger command receipt is invalid: ${receipt.id}`);
    }
    for (const stream of [receipt.stdout, receipt.stderr]) {
      if (!stream || typeof stream.path !== "string" || !DIGEST_PATTERN.test(stream.sha256 ?? "")) {
        throw new Error(`Release pre-cutover gate ledger stream reference is invalid: ${receipt.id}`);
      }
      const file = snapshotFile(snapshot, `evidence/base-profile-gates/${stream.path}`);
      if (file.bytes.length !== stream.bytes || `sha256:${file.sha256}` !== stream.sha256) {
        throw new Error(`Release pre-cutover gate ledger stream differs: ${receipt.id}/${stream.path}`);
      }
    }
    receipts.set(receipt.id, receipt);
  }
  const receiptIndex = Object.fromEntries([...receipts].map(([id, receipt]) => [id, receipt]));
  if (payload.receiptsDigest !== canonicalJsonSha256(receiptIndex)) {
    throw new Error("Release pre-cutover gate ledger receipt index digest differs.");
  }
  const expectedGates = [
    "G00 PROFILE", "G01 SOURCE", "G02 STATIC", "G03 UNIT", "G04 PROTOCOL",
    "G05 FUNCTIONAL", "G06 SECURITY", "G07 DURABILITY", "G08 LOAD",
  ];
  if (canonicalJson(Object.keys(payload.gateBindings ?? {})) !== canonicalJson(expectedGates)) {
    throw new Error("Release pre-cutover gate ledger gate inventory differs.");
  }
  const referenced = [];
  for (const gate of expectedGates) {
    const binding = payload.gateBindings[gate];
    if (!binding || !Array.isArray(binding.receiptIds) || binding.receiptIds.length === 0) {
      throw new Error(`Release pre-cutover gate ledger gate binding is invalid: ${gate}`);
    }
    for (const id of binding.receiptIds) {
      if (!receipts.has(id) || receipts.get(id).gate !== gate) throw new Error(`Release pre-cutover gate receipt is misbound: ${gate}/${id}`);
      referenced.push(id);
    }
  }
  if (referenced.length !== receipts.size || new Set(referenced).size !== receipts.size) {
    throw new Error("Release pre-cutover gate ledger receipt coverage is incomplete or duplicated.");
  }
  if (payload.profileEvidence?.profile !== "BASE_SINGLE_OWNER"
    || canonicalJson(payload.profileEvidence?.supportedProfiles) !== canonicalJson(["BASE_SINGLE_OWNER"])
    || payload.profileEvidence?.buildCapabilityManifestDigest !== manifest.buildCapabilities.capabilityDigest) {
    throw new Error("Release pre-cutover gate ledger profile evidence is invalid.");
  }
}

function generatedSchemaTreeDigestFromSnapshot(snapshot) {
  const paths = [
    "config.schema.json",
    "config/config.schema.json",
    "contracts/tools-v2.schema.json",
    "contracts/build-capabilities.schema.json",
  ].sort(compareAscii);
  const digest = createHash("sha256");
  for (const path of paths) {
    digest.update(path);
    digest.update("\0");
    digest.update(snapshotFile(snapshot, path).sha256);
    digest.update("\n");
  }
  return `sha256:${digest.digest("hex")}`;
}

function generatedSchemaTreeDigest(root) {
  const paths = [
    "config.schema.json",
    "config/config.schema.json",
    "contracts/tools-v2.schema.json",
    "contracts/build-capabilities.schema.json",
  ].sort(compareAscii);
  const digest = createHash("sha256");
  for (const path of paths) {
    digest.update(path);
    digest.update("\0");
    digest.update(fileSha256(resolveContained(root, path)));
    digest.update("\n");
  }
  return `sha256:${digest.digest("hex")}`;
}

function requiredGateProducerPrivateKeyPath(value) {
  if (typeof value !== "string" || !isAbsolute(value) || resolve(value) !== value || /[\0\r\n]/u.test(value)) {
    throw new Error("Release creation requires an absolute gateProducerPrivateKeyPath.");
  }
  return value;
}

function runtimeDescriptor(snapshot, runtimeClosure) {
  for (const path of [RUNTIME_ENTRYPOINT, RUNTIME_NODE_ENTRYPOINT, RUNTIME_DEPENDENCY_LOADER]) {
    snapshotFile(snapshot, path);
  }
  return {
    cwd: RUNTIME_CWD,
    entrypoint: RUNTIME_ENTRYPOINT,
    nodeEntrypoint: RUNTIME_NODE_ENTRYPOINT,
    closureSha256: runtimeClosure.sha256,
    releaseMetadataPath: GENERATED_RELEASE_METADATA_PATH,
    dependencies: {
      mode: RUNTIME_DEPENDENCY_MODE,
      loader: RUNTIME_DEPENDENCY_LOADER,
      lockfile: "package-lock.json",
      lockfileSha256: `sha256:${snapshotFile(snapshot, "package-lock.json").sha256}`,
      packageJsonSha256: `sha256:${snapshotFile(snapshot, "package.json").sha256}`,
      evidenceName: RUNTIME_DEPENDENCY_MANIFEST_NAME,
    },
  };
}

function validateRuntimeDescriptor(value, payloadFiles, runtimeClosure) {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error("Release runtime descriptor is missing.");
  if (value.cwd !== RUNTIME_CWD || value.entrypoint !== RUNTIME_ENTRYPOINT || value.nodeEntrypoint !== RUNTIME_NODE_ENTRYPOINT) {
    throw new Error("Release runtime cwd/entrypoint descriptor is invalid.");
  }
  if (value.closureSha256 !== runtimeClosure.sha256 || value.releaseMetadataPath !== GENERATED_RELEASE_METADATA_PATH) {
    throw new Error("Release runtime closure/metadata descriptor is invalid.");
  }
  const dependencies = value.dependencies;
  if (!dependencies || dependencies.mode !== RUNTIME_DEPENDENCY_MODE
    || dependencies.loader !== RUNTIME_DEPENDENCY_LOADER
    || dependencies.lockfile !== "package-lock.json"
    || dependencies.evidenceName !== RUNTIME_DEPENDENCY_MANIFEST_NAME
    || !DIGEST_PATTERN.test(dependencies.lockfileSha256)
    || !DIGEST_PATTERN.test(dependencies.packageJsonSha256)) {
    throw new Error("Release runtime dependency descriptor is invalid.");
  }
  for (const path of [value.entrypoint, value.nodeEntrypoint, value.releaseMetadataPath, dependencies.loader, dependencies.lockfile, "package.json"]) {
    if (!payloadFiles.includes(path)) throw new Error(`Release runtime descriptor path is not packaged: ${path}`);
  }
}

function assertDependencyInputs(manifest, packageSnapshot, dependencyRoot) {
  const bindings = [
    ["package.json", manifest.runtime.dependencies.packageJsonSha256],
    [manifest.runtime.dependencies.lockfile, manifest.runtime.dependencies.lockfileSha256],
  ];
  for (const [path, expected] of bindings) {
    const packaged = `sha256:${snapshotFile(packageSnapshot, path).sha256}`;
    const installedBytes = stableReadRegularFile(
      resolveContained(dependencyRoot, path),
      `runtime dependency input ${path}`,
    ).bytes;
    const installed = `sha256:${sha256(installedBytes)}`;
    if (packaged !== expected || installed !== expected) {
      throw new Error(`Runtime dependency input differs from the packaged lock contract: ${path}`);
    }
  }
}

function treeEvidenceFromStableRuntimeRoot(root, paths) {
  const canonicalRoot = resolve(root);
  const digest = createHash("sha256");
  for (const path of [...paths].sort(compareAscii)) {
    const absolute = resolveContained(canonicalRoot, path);
    const stable = stableReadRegularFile(absolute, `runtime tree ${path}`);
    digest.update(path);
    digest.update("\0");
    digest.update(sha256(stable.bytes));
    digest.update("\n");
  }
  return { files: paths.length, sha256: `sha256:${digest.digest("hex")}` };
}

function runtimeDependencyTreeEvidence(root) {
  const absoluteRoot = resolve(root);
  const digest = createHash("sha256");
  let files = 0;
  let directories = 0;
  let symlinks = 0;
  const visit = (directory) => {
    for (const entry of readdirSync(directory, { withFileTypes: true }).sort((left, right) => (
      left.name < right.name ? -1 : left.name > right.name ? 1 : 0
    ))) {
      const absolute = join(directory, entry.name);
      const path = toPosix(relative(absoluteRoot, absolute));
      const metadata = lstatSync(absolute);
      if (metadata.isSymbolicLink()) {
        const target = readlinkSync(absolute);
        const resolvedTarget = realpathSync(absolute);
        const targetRelative = relative(absoluteRoot, resolvedTarget);
        if (!targetRelative || targetRelative === ".." || targetRelative.startsWith(`..${sep}`) || isAbsolute(targetRelative)) {
          throw new Error(`Runtime dependency symlink escapes node_modules: ${path}`);
        }
        digest.update(`L\0${path}\0${target}\n`);
        symlinks += 1;
      } else if (metadata.isDirectory()) {
        digest.update(`D\0${path}\n`);
        directories += 1;
        visit(absolute);
      } else if (metadata.isFile()) {
        const stable = stableReadRegularFile(absolute, `runtime dependency ${path}`);
        digest.update(`F\0${path}\0${sha256(stable.bytes)}\n`);
        files += 1;
      } else {
        throw new Error(`Runtime dependency tree contains an unsupported file type: ${path}`);
      }
    }
  };
  const rootMetadata = lstatSync(absoluteRoot);
  if (!rootMetadata.isDirectory() || rootMetadata.isSymbolicLink()) throw new Error("Runtime node_modules must be a real directory.");
  visit(absoluteRoot);
  return { files, directories, symlinks, sha256: `sha256:${digest.digest("hex")}` };
}

function writeChecksums(root) {
  const files = listRegularFiles(root)
    .map((path) => toPosix(relative(root, path)))
    .filter((path) => path !== RELEASE_CHECKSUM_NAME)
    .sort();
  const text = files.map((path) => `${fileSha256(resolveContained(root, path))}  ${path}`).join("\n") + "\n";
  writeTextAtomic(resolveContained(root, RELEASE_CHECKSUM_NAME), text);
}

function parseChecksums(text) {
  const output = new Map();
  for (const line of text.split("\n")) {
    if (!line) continue;
    const match = /^([a-f0-9]{64})  ([^\0\r\n]+)$/u.exec(line);
    if (!match) throw new Error(`Invalid SHA256SUMS entry: ${line}`);
    const path = normalizeRelativePath(match[2]);
    if (path === RELEASE_CHECKSUM_NAME || output.has(path)) throw new Error(`Duplicate or recursive SHA256SUMS entry: ${path}`);
    output.set(path, match[1]);
  }
  if (output.size === 0) throw new Error("SHA256SUMS is empty.");
  return output;
}

function assertForbiddenArtifactGateFromSnapshot(snapshot, context = {}) {
  if (context.buildCapabilities) {
    assertReleaseGeneratedContractsFromSnapshot(snapshot, context.buildCapabilities, context.identities);
  }
  const manifestedMigrationPaths = migrationModulePaths(context.migrationManifest);
  for (const path of snapshot.paths) {
    const forbiddenPath = forbiddenArtifactPathReason(path, manifestedMigrationPaths);
    if (forbiddenPath) throw new Error(`Forbidden ${forbiddenPath}: ${path}`);
    const raw = snapshotFile(snapshot, path).bytes;
    if (raw.length > 8 * 1024 * 1024) continue;
    if (containsBinaryByte(raw)) continue;
    const text = raw.toString("utf8");
    assertNoRawSecretMaterial(text, path);
    if (isScriptLikePath(path) && path !== "scripts/lib/release-artifacts.mjs") {
      assertNoProductionFaultSurface(text, path);
    }
    if (/\.json$/iu.test(path)) {
      let value;
      try { value = JSON.parse(text); } catch { continue; }
      inspectForbiddenJson(value, path);
    }
    if (/\.sh$/iu.test(path)) {
      if (/^(?!\s*#).*\b(?:sudo|doas)\s+/imu.test(text)) throw new Error(`Forbidden elevation command in ${path}`);
      if (/\/Library\/LaunchDaemons|NOPASSWD|PrivilegedHelperTools/u.test(text)) throw new Error(`Forbidden privileged helper content in ${path}`);
    }
  }
}

function assertNoProductionFaultSurface(text, path) {
  if (/\b(?:test[_-]?hooks?|(?:failure|fault)[_-]?injection|interrupt[_-]?after[_-]?action|inject(?:ed)?[_-]?crash|crash[_-]?point)\b/iu.test(text)) {
    throw new Error(`Forbidden production test/failure-injection surface in ${path}`);
  }
}

function inspectForbiddenJson(value, path, trail = []) {
  if (Array.isArray(value)) {
    value.forEach((child, index) => inspectForbiddenJson(child, path, [...trail, index]));
    return;
  }
  if (!value || typeof value !== "object") return;
  for (const [key, child] of Object.entries(value)) {
    const normalized = key.replaceAll(/[-_]/gu, "").toLowerCase();
    const location = [...trail, key].join(".");
    if (normalized === "privilege" && String(child).toLowerCase() === "admin") throw new Error(`Forbidden admin privilege in ${path}:${location}`);
    if (["legacyblanketscopecompatibility", "adminscopeenabled", "allowanonymoussessionfallback", "publicmetricsenabled"].includes(normalized) && child === true) {
      throw new Error(`Forbidden production configuration in ${path}:${location}`);
    }
    if (typeof child === "string" && child === "devspace.admin") throw new Error(`Forbidden OAuth scope in ${path}:${location}`);
    if (/^(?:root|system)?password$/iu.test(normalized) && typeof child === "string" && child.length > 0) {
      throw new Error(`Forbidden password material in ${path}:${location}`);
    }
    if (/^(?:access|refresh|owner|oauth)?token$/iu.test(normalized) && typeof child === "string" && looksLikeRawSecret(child)) {
      throw new Error(`Forbidden raw token material in ${path}:${location}`);
    }
    if (/^(?:client)?secret$/iu.test(normalized) && typeof child === "string" && looksLikeRawSecret(child)) {
      throw new Error(`Forbidden raw secret material in ${path}:${location}`);
    }
    if (/(?:failure|fault)injection/u.test(normalized) && child !== false && child !== undefined && child !== null) {
      throw new Error(`Forbidden failure injection flag in ${path}:${location}`);
    }
    if (/(?:temporary|temp).*(?:oauth|token)|(?:oauth|token).*(?:temporary|temp)/u.test(normalized)) {
      throw new Error(`Forbidden temporary OAuth/token residue in ${path}:${location}`);
    }
    if (normalized === "supportedprofiles" && Array.isArray(child) && child.some((profile) => profile !== "BASE_SINGLE_OWNER")) {
      throw new Error(`Forbidden unsupported profile placeholder in ${path}:${location}`);
    }
    if (typeof child === "string" && /(?:MULTI_USER|SIDECAR_AUTHORITY|HOST_ATTESTED|GUI_CAPTURE)/u.test(child)
      && /(?:placeholder|stub|todo|unsupported)/iu.test(child)) {
      throw new Error(`Forbidden unsupported profile placeholder in ${path}:${location}`);
    }
    inspectForbiddenJson(child, path, [...trail, key]);
  }
}

function forbiddenArtifactPathReason(path, manifestedMigrationPaths) {
  const normalized = path.toLowerCase();
  if (/(^|\/)(?:fixtures?|__fixtures__|test-fixtures?|tests?)(?:\/|$)|(?:^|\/)(?:(?:test|fixture|mock|fake)[._-]?(?:mcp[._-]?)?provider|(?:provider[._-])?(?:test|fixture|mock|fake))(?:[._/-]|$)/iu.test(path)) {
    return "test fixture provider";
  }
  if (/(?:^|\/)(?:(?:failure|fault|chaos)[._-]?injection|canary|peer-gate)(?:[._/-]|$)/iu.test(path)) {
    return "failure injection/canary residue";
  }
  if (/(?:^|\/)(?:(?:temp|tmp|temporary)[^/]*(?:oauth|token)|(?:oauth|token)[^/]*(?:temp|tmp|temporary))(?:[._/-]|$)/iu.test(path)) {
    return "temporary OAuth/token residue";
  }
  if (/(?:^|\/)(?:not[._-]?run[._-]?phase|phase[._-]?(?:marker|[0-9]+))(?:[._/-]|$)/iu.test(path)) {
    return "phase-specific marker";
  }
  if (/(?:^|\/)(?:root[._-]?helper|privileged(?:[._-]?(?:client|helper))?|launchdaemon[._-]?helper|raw[._-]?secret|system[._-]?password|root[._-]?password|password[._-]?material)(?:[._/-]|$)/iu.test(path)) {
    return "root/privileged/password/raw secret residue";
  }
  if (/(?:multi[._-]?user|sidecar[._-]?authority|host[._-]?attested|gui[._-]?capture|unsupported[._-]?profile)[^/]*(?:placeholder|stub|todo|not[._-]?implemented)|(?:placeholder|stub|todo)[^/]*(?:multi[._-]?user|sidecar[._-]?authority|host[._-]?attested|gui[._-]?capture)/iu.test(path)) {
    return "unsupported profile placeholder";
  }
  if (isScriptLikePath(normalized) && /(?:rollback|migrat(?:e|ion|ions))/iu.test(path)
    && !REVIEWED_PRODUCTION_SCRIPT_PATHS.has(path)
    && !manifestedMigrationPaths.has(path)) {
    return "unmanifested one-off migration/rollback script";
  }
  return undefined;
}

function isScriptLikePath(path) {
  return /\.(?:[cm]?[jt]s|sh|bash|zsh|py|sql)$/iu.test(path);
}

function migrationModulePaths(manifest) {
  const output = new Set(["dist/v2/migration-registry.js", "dist/db/migrations.js"]);
  if (!Array.isArray(manifest)) return output;
  for (const entry of manifest) {
    if (!entry || typeof entry.module !== "string") continue;
    const moduleName = entry.module.replace(/\.[cm]?js$/iu, "");
    const modulePath = normalizeRelativePath(
      moduleName.startsWith("scripts/") ? `${moduleName}.mjs` : `dist/${moduleName}.js`,
    );
    output.add(modulePath);
  }
  return output;
}

function containsBinaryByte(value) {
  return value.includes(0);
}

function assertNoRawSecretMaterial(text, path) {
  for (const [name, pattern] of [
    ["PEM private key", /-----BEGIN (?:[A-Z0-9 ]+ )?PRIVATE KEY-----/u],
    ["AWS access key", /\b(?:AKIA|ASIA)[A-Z0-9]{16}\b/u],
    ["GitHub token", /\b(?:gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{50,})\b/u],
    ["Slack token", /\bxox[baprs]-[A-Za-z0-9-]{20,}\b/u],
    ["OpenAI-style secret", /\bsk-[A-Za-z0-9_-]{32,}\b/u],
    ["Google API key", /\bAIza[0-9A-Za-z_-]{35}\b/u],
  ]) {
    if (pattern.test(text)) throw new Error(`Forbidden raw secret material in ${path}: ${name}`);
  }
}

function looksLikeRawSecret(value) {
  if (!value || /^(?:redacted|change[_-]?me|example|placeholder|test|fixture|null|undefined)$/iu.test(value)) return false;
  return value.length >= 16 && /[A-Za-z]/u.test(value) && /[0-9]/u.test(value);
}

function createSpdxSbom(packageJson, components, buildDigest, createdAt) {
  const namespaceDigest = buildDigest.slice("sha256:".length);
  return {
    spdxVersion: "SPDX-2.3",
    dataLicense: "CC0-1.0",
    SPDXID: "SPDXRef-DOCUMENT",
    name: `${packageJson.name}-${packageJson.version}`,
    documentNamespace: `https://devspace.local/spdx/${namespaceDigest}`,
    creationInfo: { created: createdAt, creators: ["Tool: DevSpace release-artifacts"] },
    packages: [rootSpdxPackage(packageJson, buildDigest), ...components.map((component, index) => ({
      SPDXID: `SPDXRef-Package-${index + 1}`,
      name: component.name,
      versionInfo: component.version,
      downloadLocation: "NOASSERTION",
      filesAnalyzed: false,
      licenseConcluded: "NOASSERTION",
      licenseDeclared: "NOASSERTION",
      copyrightText: "NOASSERTION",
    }))],
  };
}

function rootSpdxPackage(packageJson, buildDigest) {
  return {
    SPDXID: "SPDXRef-Package-DevSpace",
    name: packageJson.name,
    versionInfo: packageJson.version,
    downloadLocation: "NOASSERTION",
    filesAnalyzed: false,
    checksums: [{ algorithm: "SHA256", checksumValue: buildDigest.slice("sha256:".length) }],
    licenseConcluded: packageJson.license ?? "NOASSERTION",
    licenseDeclared: packageJson.license ?? "NOASSERTION",
    copyrightText: "NOASSERTION",
  };
}

function createCycloneDxSbom(packageJson, components, buildDigest, createdAt) {
  return {
    bomFormat: "CycloneDX",
    specVersion: "1.6",
    serialNumber: `urn:uuid:${digestUuid(buildDigest)}`,
    version: 1,
    metadata: {
      timestamp: createdAt,
      tools: { components: [{ type: "application", name: "DevSpace release-artifacts" }] },
      component: {
        type: "application",
        name: packageJson.name,
        version: packageJson.version,
        hashes: [{ alg: "SHA-256", content: buildDigest.slice("sha256:".length) }],
      },
    },
    components: components.map((component) => ({ type: "library", name: component.name, version: component.version })),
  };
}

function verifySboms(snapshot, manifest) {
  const spdx = snapshotJson(snapshot, SPDX_SBOM_NAME, "SPDX SBOM");
  const cyclone = snapshotJson(snapshot, CYCLONEDX_SBOM_NAME, "CycloneDX SBOM");
  const index = snapshotJson(snapshot, SBOM_INDEX_NAME, "SBOM index");
  if (spdx.spdxVersion !== "SPDX-2.3" || spdx.packages?.[0]?.checksums?.[0]?.checksumValue !== manifest.buildDigest.slice(7)) {
    throw new Error("SPDX SBOM is not bound to the release build digest.");
  }
  if (cyclone.bomFormat !== "CycloneDX" || cyclone.specVersion !== "1.6" || cyclone.metadata?.component?.hashes?.[0]?.content !== manifest.buildDigest.slice(7)) {
    throw new Error("CycloneDX SBOM is not bound to the release build digest.");
  }
  if (canonicalJson(index.formats) !== canonicalJson([
    { format: "SPDX-2.3", path: SPDX_SBOM_NAME },
    { format: "CycloneDX-1.6", path: CYCLONEDX_SBOM_NAME },
  ])) throw new Error("SBOM index is invalid.");
}

function lockfileComponents(root) {
  const path = resolveContained(root, "package-lock.json");
  if (!existsSync(path)) return [];
  const lock = JSON.parse(readFileSync(path, "utf8"));
  const output = [];
  for (const [key, value] of Object.entries(lock.packages ?? {})) {
    if (!key || !value || typeof value !== "object" || typeof value.version !== "string") continue;
    const name = typeof value.name === "string" ? value.name : key.replace(/^node_modules\//u, "");
    output.push({ name, version: value.version });
  }
  return output.sort((left, right) => compareAscii(
    `${left.name}@${left.version}`,
    `${right.name}@${right.version}`,
  ));
}

function lockfileComponentsFromSnapshot(snapshot) {
  const lock = snapshotJson(snapshot, "package-lock.json", "release package lockfile");
  const output = [];
  for (const [key, value] of Object.entries(lock.packages ?? {})) {
    if (!key || !value || typeof value !== "object" || typeof value.version !== "string") continue;
    const name = typeof value.name === "string" ? value.name : key.replace(/^node_modules\//u, "");
    output.push({ name, version: value.version });
  }
  return output.sort((left, right) => compareAscii(
    `${left.name}@${left.version}`,
    `${right.name}@${right.version}`,
  ));
}

function copyTree(source, target, relativePath) {
  if (/(^|\/)(?:fixtures?|tests?)(\/|$)|\.test\.[cm]?[jt]sx?$/iu.test(toPosix(relativePath))) return;
  const metadata = lstatSync(source);
  if (metadata.isSymbolicLink()) throw new Error(`Release payload may not contain symlinks: ${source}`);
  if (metadata.isDirectory()) {
    mkdirSync(target, { recursive: true, mode: 0o755 });
    for (const entry of readdirSync(source)) copyTree(join(source, entry), join(target, entry), `${toPosix(relativePath)}/${entry}`);
    return;
  }
  if (!metadata.isFile()) throw new Error(`Release payload contains an unsupported file type: ${source}`);
  mkdirSync(dirname(target), { recursive: true, mode: 0o755 });
  copyFileSync(source, target);
  chmodSync(target, metadata.mode & 0o111 ? 0o755 : 0o644);
}

function writeJsonAtomic(path, value) {
  writeTextAtomic(path, `${JSON.stringify(value, null, 2)}\n`);
}

function writeCapturedBytesAtomic(path, value) {
  if (!Buffer.isBuffer(value)) throw new Error("Generated release metadata must be captured bytes.");
  mkdirSync(dirname(path), { recursive: true, mode: 0o700 });
  const temporary = `${path}.tmp-${process.pid}`;
  const descriptor = openSync(temporary, "wx", 0o600);
  try {
    writeFileSync(descriptor, value);
    fsyncSync(descriptor);
  } finally {
    closeSync(descriptor);
  }
  chmodSync(temporary, 0o644);
  renameSync(temporary, path);
  fsyncDirectory(dirname(path));
}

function writeTextAtomic(path, value) {
  mkdirSync(dirname(path), { recursive: true, mode: 0o700 });
  const temporary = `${path}.tmp-${process.pid}`;
  const descriptor = openSync(temporary, "wx", 0o600);
  try {
    writeFileSync(descriptor, value, "utf8");
    fsyncSync(descriptor);
  } finally {
    closeSync(descriptor);
  }
  chmodSync(temporary, 0o644);
  renameSync(temporary, path);
  fsyncDirectory(dirname(path));
}

function writeOwnerOnlyTextAtomic(path, value) {
  mkdirSync(dirname(path), { recursive: true, mode: 0o700 });
  chmodSync(dirname(path), 0o700);
  const temporary = `${path}.tmp-${process.pid}-${randomBytes(8).toString("hex")}`;
  let descriptor;
  try {
    descriptor = openSync(temporary, "wx", 0o600);
    writeFileSync(descriptor, value, "utf8");
    fsyncSync(descriptor);
    closeSync(descriptor);
    descriptor = undefined;
    renameSync(temporary, path);
    fsyncDirectory(dirname(path));
  } catch (error) {
    if (descriptor !== undefined) closeSync(descriptor);
    try { unlinkSync(temporary); } catch {}
    throw error;
  }
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

function fsyncFile(path) {
  const descriptor = openSync(path, "r");
  try {
    fsyncSync(descriptor);
  } finally {
    closeSync(descriptor);
  }
}

function pathsOverlap(left, right) {
  const leftRelative = relative(left, right);
  const rightRelative = relative(right, left);
  return leftRelative === ""
    || (leftRelative !== ".." && !leftRelative.startsWith(`..${sep}`) && !isAbsolute(leftRelative))
    || (rightRelative !== ".." && !rightRelative.startsWith(`..${sep}`) && !isAbsolute(rightRelative));
}

function resolveContained(root, path) {
  const normalized = normalizeRelativePath(path);
  const absolute = resolve(root, normalized);
  if (absolute !== resolve(root) && !absolute.startsWith(`${resolve(root)}${sep}`)) throw new Error(`Release path escapes its root: ${path}`);
  return absolute;
}

function normalizeRelativePath(path) {
  if (typeof path !== "string" || path.length === 0 || path.includes("\0")) throw new Error("Release path is invalid.");
  const normalized = toPosix(path);
  if (normalized.startsWith("/") || normalized.split("/").some((part) => part === "" || part === "." || part === "..")) {
    throw new Error(`Release path is unsafe: ${path}`);
  }
  return normalized;
}

function toPosix(path) {
  return path.split(sep).join("/");
}

function tryGitRevision(root) {
  try {
    return gitRevision(root);
  } catch {
    return undefined;
  }
}

function gitRevision(root) {
  try {
    const revision = execFileSync("/usr/bin/git", ["-C", root, "rev-parse", "HEAD"], {
      encoding: "utf8",
      stdio: ["ignore", "pipe", "ignore"],
      env: { LANG: "C", LC_ALL: "C", PATH: "", TZ: "UTC", GIT_CONFIG_NOSYSTEM: "1", GIT_CONFIG_GLOBAL: "/dev/null" },
    }).trim();
    requireIdentity("sourceRevision", revision);
    return revision;
  } catch {
    throw new Error("sourceRevision is required when the source is not a Git checkout.");
  }
}

function runtimeContractIdentities(snapshot) {
  const modulePath = "dist/v2/runtime-contract-identity.js";
  if (!snapshot.files.has(modulePath)) {
    if (snapshot.files.has("dist/v2/runtime-identity.js")) {
      throw new Error("Packaged runtime is missing dependency-free contract identities.");
    }
    return undefined;
  }
  const source = snapshotText(snapshot, modulePath);
  const readExport = (name) => {
    const pattern = new RegExp(`^export const ${name} = ["'](sha256:[a-f0-9]{64})["'];?\\s*$`, "gmu");
    const matches = [...source.matchAll(pattern)];
    if (matches.length !== 1) throw new Error(`Dependency-free runtime contract export is missing or ambiguous: ${name}`);
    return matches[0][1];
  };
  return Object.freeze({
    schemaGeneration: readExport("RUNTIME_SCHEMA_GENERATION"),
    authorityContractGeneration: readExport("RUNTIME_AUTHORITY_CONTRACT_GENERATION"),
  });
}

function fixtureGeneratedReleaseMetadataBytes(options, context) {
  if (typeof options.fixtureGeneratedReleaseMetadata !== "function") {
    throw new Error("Unattested release fixtures require fixtureGeneratedReleaseMetadata(context); production metadata cannot be inferred from live runtime modules.");
  }
  const supplied = options.fixtureGeneratedReleaseMetadata(Object.freeze({
    buildDigest: context.build.sha256,
    identities: Object.freeze({ ...context.identities }),
    runtimeClosureInputSha256: context.runtimeClosureInput.sha256,
    sourceRevision: context.sourceRevision,
  }));
  if (!supplied || typeof supplied !== "object" || Array.isArray(supplied)) {
    throw new Error("fixtureGeneratedReleaseMetadata must return the explicit fixture metadata fields.");
  }
  return createUnsignedGeneratedReleaseMetadataFixture({
    schemaVersion: 1,
    sourceRevision: context.sourceRevision,
    buildDigest: context.build.sha256,
    schemaGeneration: context.identities.schemaGeneration,
    authorityContractGeneration: context.identities.authorityContractGeneration,
    configSchemaIdentity: context.identities.configSchemaIdentity,
    runtimeClosureInputSha256: context.runtimeClosureInput.sha256,
    sourceTreeSha256: supplied.sourceTreeSha256,
    dependencyTreeSha256: supplied.dependencyTreeSha256,
    collectorReceiptSha256: supplied.collectorReceiptSha256,
    buildCapabilities: supplied.buildCapabilities,
    migrationManifest: supplied.migrationManifest,
    migrationManifestDigest: supplied.migrationManifestDigest,
  });
}

function collectGeneratedReleaseMetadataPayload(context) {
  const collectorInput = resolveContained(context.sourceRoot, "scripts/collect-generated-release-metadata.mjs");
  const collectorPath = realpathSync(collectorInput);
  const collectorMetadata = lstatSync(collectorPath);
  if (collectorPath !== collectorInput || !collectorMetadata.isFile() || collectorMetadata.isSymbolicLink()) {
    throw new Error("Generated release metadata collector is not a canonical real file.");
  }
  const result = spawnSync(process.execPath, [
    "--disable-warning=ExperimentalWarning",
    collectorPath,
    context.sourceRoot,
    context.sourceRevision,
    context.build.sha256,
    context.identities.schemaGeneration,
    context.identities.authorityContractGeneration,
    context.identities.configSchemaIdentity,
    context.runtimeClosureInput.sha256,
  ], {
    cwd: context.sourceRoot,
    encoding: "utf8",
    shell: false,
    timeout: 60_000,
    maxBuffer: 16 * 1024 * 1024,
    env: {
      HOME: process.env.HOME ?? "",
      LANG: "C",
      LC_ALL: "C",
      NODE_OPTIONS: "",
      PATH: "",
      TZ: "UTC",
      GIT_CONFIG_NOSYSTEM: "1",
      GIT_CONFIG_GLOBAL: "/dev/null",
    },
  });
  if (result.error || result.status !== 0 || result.signal !== null || result.stderr !== "") {
    throw new Error(`Generated release metadata collector failed: ${result.stderr?.trim() || result.error?.message || `status ${result.status}`}`);
  }
  let payload;
  try { payload = JSON.parse(result.stdout); }
  catch { throw new Error("Generated release metadata collector returned invalid JSON."); }
  return payload;
}

function collectGeneratedReleaseMetadata(context) {
  const payload = collectGeneratedReleaseMetadataPayload(context);
  const signed = createSignedGeneratedReleaseMetadata(payload, context.gateProducerPrivateKeyPath);
  if (signed.keyId !== context.expectedGateProducer.keyId
    || signed.publicKeySha256 !== context.expectedGateProducer.publicKeySha256) {
    throw new Error("Generated release metadata signing key differs from the trusted gate producer.");
  }
  return signed;
}

function runtimeReleaseMetadataFromSnapshot(snapshot, options) {
  const bytes = snapshotFile(snapshot, GENERATED_RELEASE_METADATA_PATH).bytes;
  const envelope = parseGeneratedReleaseMetadata(bytes, {
    allowUnattestedFixture: options.allowUnattestedFixture === true,
    expectedProducer: options.expectedProducer,
  });
  const value = envelope.payload;
  for (const [name, expected, observed] of [
    ["source revision", options.sourceRevision, value.sourceRevision],
    ["build digest", options.buildDigest, value.buildDigest],
    ["schema generation", options.identities.schemaGeneration, value.schemaGeneration],
    ["authority contract generation", options.identities.authorityContractGeneration, value.authorityContractGeneration],
    ["config schema identity", options.identities.configSchemaIdentity, value.configSchemaIdentity],
    ["runtime closure input", options.runtimeClosureInput.sha256, value.runtimeClosureInputSha256],
  ]) {
    if (observed !== expected) throw new Error(`Generated release metadata ${name} binding mismatch: expected ${expected}, observed ${observed}`);
  }
  validateBuildCapabilities(value.buildCapabilities, options.buildDigest);
  if (value.buildCapabilities.schemaGeneration !== options.identities.schemaGeneration
    || value.buildCapabilities.authorityContractGeneration !== options.identities.authorityContractGeneration) {
    throw new Error("Generated release metadata build capabilities differ from the captured runtime contract identities.");
  }
  validateMigrationManifestShape(value.migrationManifest, value.migrationManifestDigest);
  if (!options.runtimeClosure.files.some((file) => file.path === GENERATED_RELEASE_METADATA_PATH)) {
    throw new Error("Generated release metadata artifact is absent from the runtime operations closure.");
  }
  return deepFreezeJson({
    envelope,
    buildCapabilities: value.buildCapabilities,
    migrationManifest: value.migrationManifest,
    migrationManifestDigest: value.migrationManifestDigest,
  });
}

function validateBuildCapabilities(value, buildDigest) {
  if (!value || typeof value !== "object") throw new Error("Release build capability manifest is missing.");
  if (typeof value.productVersion !== "string" || value.productVersion.length === 0) throw new Error("Release build capability product version is invalid.");
  if (value.productProfile !== "BASE_SINGLE_OWNER") throw new Error("Release build capability profile is invalid.");
  if (!Array.isArray(value.supportedProfiles) || canonicalJson(value.supportedProfiles) !== canonicalJson(["BASE_SINGLE_OWNER"])) {
    throw new Error("Release build capabilities advertise unsupported profiles.");
  }
  if (value.resourceUriVersion !== "v1") throw new Error("Release build capability resource URI version is invalid.");
  for (const key of ["schemaGeneration", "authorityContractGeneration", "buildDigest", "capabilityDigest"]) {
    if (!DIGEST_PATTERN.test(value[key] ?? "")) throw new Error(`Release build capability digest is invalid: ${key}`);
  }
  if (value.buildDigest !== buildDigest) throw new Error("Release build capabilities are not bound to the build digest.");
  if (!value.supportedOperations || typeof value.supportedOperations !== "object" || Array.isArray(value.supportedOperations)) {
    throw new Error("Release build capabilities are missing supported operations.");
  }
  if (canonicalJson(Object.keys(value.supportedOperations).sort(compareAscii))
    !== canonicalJson([...EXPECTED_TOOL_NAMES].sort(compareAscii))) {
    throw new Error("Release build capabilities do not bind exactly eight tools.");
  }
  for (const tool of EXPECTED_TOOL_NAMES) {
    const operations = value.supportedOperations[tool];
    if (!Array.isArray(operations) || operations.length < 1 || operations.some((operation) => typeof operation !== "string" || operation.length === 0)) {
      throw new Error(`Release build capability operations are invalid for ${tool}.`);
    }
    if (new Set(operations).size !== operations.length) throw new Error(`Release build capability operations contain duplicates for ${tool}.`);
  }
  const expectedCapabilityDigest = canonicalJsonSha256(buildCapabilityContract(value));
  if (value.capabilityDigest !== expectedCapabilityDigest) {
    throw new Error(`Release build capability digest mismatch: expected ${expectedCapabilityDigest}, observed ${value.capabilityDigest}`);
  }
}

function buildCapabilityContract(value) {
  return Object.fromEntries(BUILD_CAPABILITY_CONTRACT_KEYS.map((key) => [key, value[key]]));
}

function assertReleaseGeneratedContractsFromSnapshot(snapshot, buildCapabilities, identities = {}) {
  validateBuildCapabilities(buildCapabilities, buildCapabilities.buildDigest);
  if (identities.schemaGeneration && buildCapabilities.schemaGeneration !== identities.schemaGeneration) {
    throw new Error("Release build capability schema generation is not bound to the runtime contract identity.");
  }
  if (identities.authorityContractGeneration && buildCapabilities.authorityContractGeneration !== identities.authorityContractGeneration) {
    throw new Error("Release build capability authority generation is not bound to the runtime contract identity.");
  }
  const toolsSchema = readGeneratedSchemaFromSnapshot(snapshot, TOOLS_SCHEMA_PATH);
  assertToolsSchemaBound(toolsSchema, buildCapabilities);
  const buildCapabilitySchema = readGeneratedSchemaFromSnapshot(snapshot, BUILD_CAPABILITY_SCHEMA_PATH);
  assertBuildCapabilitySchemaBound(buildCapabilitySchema, buildCapabilities);
}

function readGeneratedSchemaFromSnapshot(snapshot, path) {
  try {
    return JSON.parse(snapshotText(snapshot, path));
  } catch (error) {
    throw new Error(`Forbidden stale generated schema ${path}: ${error instanceof Error ? error.message : String(error)}`);
  }
}

function assertToolsSchemaBound(schema, buildCapabilities) {
  const schemaPath = TOOLS_SCHEMA_PATH;
  if (schema?.$id !== "https://devspace.local/contracts/tools-v2.schema.json") staleSchema(schemaPath, "$id mismatch");
  assertSchemaConst(schemaPath, schema?.properties?.version, buildCapabilities.productVersion, "version");
  const tools = schema?.properties?.tools;
  if (!tools || typeof tools !== "object") staleSchema(schemaPath, "tools object missing");
  assertExactStringArray(schemaPath, tools.required, EXPECTED_TOOL_NAMES, "tools.required");
  assertExactStringArray(schemaPath, Object.keys(tools.properties ?? {}), EXPECTED_TOOL_NAMES, "tools.properties");
  for (const tool of EXPECTED_TOOL_NAMES) {
    const expected = buildCapabilities.supportedOperations[tool];
    assertExactStringArray(schemaPath, extractToolSchemaOperations(schema, tool), expected, `${tool}.operations`);
  }
  const maximumTools = schema?.properties?.budgets?.properties?.maximumTools?.const;
  if (maximumTools !== undefined && maximumTools !== EXPECTED_TOOL_NAMES.length) {
    staleSchema(schemaPath, `maximumTools mismatch: expected ${EXPECTED_TOOL_NAMES.length}, observed ${maximumTools}`);
  }
}

function assertBuildCapabilitySchemaBound(schema, buildCapabilities) {
  const schemaPath = BUILD_CAPABILITY_SCHEMA_PATH;
  if (schema?.$id !== "https://devspace.local/contracts/build-capabilities.schema.json") staleSchema(schemaPath, "$id mismatch");
  if (schema?.additionalProperties !== false) staleSchema(schemaPath, "additionalProperties must be false");
  assertExactStringArray(schemaPath, schema?.required, BUILD_CAPABILITY_SCHEMA_REQUIRED, "required");
  const properties = schema?.properties;
  if (!properties || typeof properties !== "object") staleSchema(schemaPath, "properties object missing");
  assertSchemaConst(schemaPath, properties.productVersion, buildCapabilities.productVersion, "productVersion");
  assertSchemaConst(schemaPath, properties.productProfile, buildCapabilities.productProfile, "productProfile");
  assertSchemaConst(schemaPath, properties.supportedProfiles, buildCapabilities.supportedProfiles, "supportedProfiles");
  assertSchemaConst(schemaPath, properties.resourceUriVersion, buildCapabilities.resourceUriVersion, "resourceUriVersion");
  for (const key of ["schemaGeneration", "authorityContractGeneration", "buildDigest", "capabilityDigest"]) {
    assertDigestStringSchema(schemaPath, properties[key], key);
  }
  const supportedOperations = properties.supportedOperations;
  if (!supportedOperations || typeof supportedOperations !== "object") staleSchema(schemaPath, "supportedOperations object missing");
  if (supportedOperations.additionalProperties !== false) staleSchema(schemaPath, "supportedOperations.additionalProperties must be false");
  assertExactStringArray(schemaPath, supportedOperations.required, EXPECTED_TOOL_NAMES, "supportedOperations.required");
  assertExactStringArray(schemaPath, Object.keys(supportedOperations.properties ?? {}), EXPECTED_TOOL_NAMES, "supportedOperations.properties");
  for (const tool of EXPECTED_TOOL_NAMES) {
    assertSchemaConst(schemaPath, supportedOperations.properties?.[tool], buildCapabilities.supportedOperations[tool], `supportedOperations.${tool}`);
  }
}

function extractToolSchemaOperations(schema, tool) {
  const definition = schema?.$defs?.[`${tool}Tool`];
  const operations = Array.isArray(definition?.allOf)
    ? definition.allOf.map((entry) => entry?.properties?.operations?.const).find(Array.isArray)
    : undefined;
  if (!operations) staleSchema(TOOLS_SCHEMA_PATH, `${tool} operations const missing`);
  return operations;
}

function assertSchemaConst(schemaPath, schema, expected, label) {
  if (!schema || typeof schema !== "object" || !Object.hasOwn(schema, "const")) staleSchema(schemaPath, `${label} const missing`);
  if (canonicalJson(schema.const) !== canonicalJson(expected)) {
    staleSchema(schemaPath, `${label} mismatch: expected ${canonicalJson(expected)}, observed ${canonicalJson(schema.const)}`);
  }
}

function assertDigestStringSchema(schemaPath, schema, label) {
  if (!schema || schema.type !== "string" || schema.pattern !== DIGEST_PATTERN_SOURCE) {
    staleSchema(schemaPath, `${label} digest pattern mismatch`);
  }
}

function assertExactStringArray(schemaPath, observed, expected, label) {
  if (!Array.isArray(observed) || observed.some((item) => typeof item !== "string")) staleSchema(schemaPath, `${label} must be a string array`);
  if (canonicalJson(observed) !== canonicalJson(expected)) {
    staleSchema(schemaPath, `${label} mismatch: expected ${canonicalJson(expected)}, observed ${canonicalJson(observed)}`);
  }
}

function staleSchema(path, detail) {
  throw new Error(`Forbidden stale generated schema ${path}: ${detail}`);
}

function validateMigrationManifestShape(manifest, digest) {
  if (!Array.isArray(manifest) || manifest.length < 1) throw new Error("Release migration manifest is missing.");
  if (!/^sha256:[a-f0-9]{64}$/u.test(digest ?? "")) throw new Error("Release migration manifest digest is invalid.");
  const keys = new Set();
  for (const entry of manifest) {
    if (!entry || typeof entry !== "object") throw new Error("Release migration manifest entry is invalid.");
    if (!/^[A-Za-z][A-Za-z0-9._-]{0,127}$/u.test(entry.storeId ?? "")) throw new Error("Release migration manifest storeId is invalid.");
    if (!Number.isInteger(entry.version) || entry.version < 1) throw new Error("Release migration manifest version is invalid.");
    if (!/^[A-Za-z][A-Za-z0-9._-]{0,255}$/u.test(entry.name ?? "")) throw new Error("Release migration manifest name is invalid.");
    if (!/^sha256:[a-f0-9]{64}$/u.test(entry.checksum ?? "")) throw new Error("Release migration manifest checksum is invalid.");
    if (!/^[A-Za-z][A-Za-z0-9._/-]{0,255}$/u.test(entry.module ?? "")) throw new Error("Release migration manifest module is invalid.");
    const key = `${entry.storeId}/${entry.version}`;
    if (keys.has(key)) throw new Error(`Release migration manifest contains duplicate key: ${key}`);
    keys.add(key);
  }
  const expectedDigest = `sha256:${sha256(JSON.stringify(normalizedMigrationManifest(manifest)))}`;
  if (digest !== expectedDigest) throw new Error("Release migration manifest digest is not canonical.");
}

function normalizedMigrationManifest(manifest) {
  return manifest.map((entry) => ({
    storeId: entry.storeId,
    version: entry.version,
    name: entry.name,
    checksum: entry.checksum,
    module: entry.module,
  })).sort((left, right) => (
    compareAscii(left.storeId, right.storeId)
    || left.version - right.version
    || compareAscii(left.name, right.name)
    || compareAscii(left.module, right.module)
  ));
}

function compareAscii(left, right) {
  return left < right ? -1 : left > right ? 1 : 0;
}

function deepFreezeJson(value) {
  if (value && typeof value === "object" && !Object.isFrozen(value)) {
    for (const child of Object.values(value)) deepFreezeJson(child);
    Object.freeze(value);
  }
  return value;
}

function requireIdentity(name, value) {
  if (typeof value !== "string" || !/^[A-Za-z0-9][A-Za-z0-9._:+/-]{6,255}$/u.test(value)) throw new Error(`Invalid ${name}.`);
}

function normalizeCreatedAt(value) {
  if (value !== undefined) {
    const parsed = new Date(value);
    if (!Number.isFinite(parsed.getTime())) throw new Error("Invalid release creation timestamp.");
    return parsed.toISOString();
  }
  const epoch = process.env.SOURCE_DATE_EPOCH;
  if (epoch !== undefined && /^\d+$/u.test(epoch)) return new Date(Number(epoch) * 1000).toISOString();
  return new Date().toISOString();
}

function digestUuid(value) {
  const hex = sha256(value).slice(0, 32).split("");
  hex[12] = "5";
  hex[16] = ((Number.parseInt(hex[16], 16) & 0x3) | 0x8).toString(16);
  return `${hex.slice(0, 8).join("")}-${hex.slice(8, 12).join("")}-${hex.slice(12, 16).join("")}-${hex.slice(16, 20).join("")}-${hex.slice(20).join("")}`;
}
