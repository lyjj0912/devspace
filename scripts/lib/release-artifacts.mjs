import { createHash } from "node:crypto";
import { execFileSync } from "node:child_process";
import {
  chmodSync,
  copyFileSync,
  existsSync,
  lstatSync,
  mkdirSync,
  openSync,
  closeSync,
  readFileSync,
  readdirSync,
  renameSync,
  rmSync,
  statSync,
  writeFileSync,
  fsyncSync,
} from "node:fs";
import { dirname, join, relative, resolve, sep } from "node:path";

export const RELEASE_MANIFEST_NAME = "BUILD-MANIFEST.json";
export const RELEASE_CHECKSUM_NAME = "SHA256SUMS";
export const SPDX_SBOM_NAME = "SBOM.spdx.json";
export const CYCLONEDX_SBOM_NAME = "SBOM.cyclonedx.json";
export const SBOM_INDEX_NAME = "SBOM.json";

const REQUIRED_PAYLOADS = ["dist", "package.json", "package-lock.json", "config", "contracts"];
const OPTIONAL_PAYLOADS = ["scripts"];
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
  return output.sort((left, right) => toPosix(relative(root, left)).localeCompare(toPosix(relative(root, right))));
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
  const readCanonicalFile = (path) => JSON.parse(readFileSync(resolveContained(sourceRoot, path), "utf8"));
  const tools = readCanonicalFile("contracts/tools-v2.schema.json");
  const authorityFiles = ["contracts/mcp-risk-policy.schema.json", "contracts/errors.schema.json"]
    .filter((path) => existsSync(resolveContained(sourceRoot, path)))
    .map((path) => ({ path, value: readCanonicalFile(path) }));
  const configSchema = readCanonicalFile("config/config.schema.json");
  if (authorityFiles.length === 0) throw new Error("Authority contract inputs are missing.");
  const runtimeContracts = runtimeContractIdentities(sourceRoot);
  return {
    schemaGeneration: runtimeContracts?.schemaGeneration ?? canonicalJsonSha256(tools),
    authorityContractGeneration: runtimeContracts?.authorityContractGeneration ?? canonicalJsonSha256(authorityFiles),
    configSchemaIdentity: canonicalJsonSha256(configSchema),
  };
}

export function createReleasePackage(options) {
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
    const identities = deriveReleaseIdentities(sourceRoot);
    const sourceRevision = options.sourceRevision ?? gitRevision(sourceRoot);
    const runtimeRevision = options.runtimeRevision ?? sourceRevision;
    requireIdentity("sourceRevision", sourceRevision);
    requireIdentity("runtimeRevision", runtimeRevision);
    const createdAt = normalizeCreatedAt(options.createdAt);

    copyFileSync(
      resolveContained(staging, "config/config.schema.json"),
      resolveContained(staging, "config.schema.json"),
    );
    assertForbiddenArtifactGate(staging);

    const payloadFiles = listRegularFiles(staging)
      .map((path) => toPosix(relative(staging, path)))
      .filter((path) => !GENERATED_FILES.has(path));
    const payload = treeEvidence(staging, payloadFiles);
    const distFiles = payloadFiles.filter((path) => path.startsWith("dist/"));
    const build = treeEvidence(staging, distFiles);
    const packageJson = JSON.parse(readFileSync(resolveContained(staging, "package.json"), "utf8"));
    const components = lockfileComponents(staging);
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
    verifyReleasePackage(staging, { expectedSourceRevision: sourceRevision, expectedRuntimeRevision: runtimeRevision });
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
  const root = resolve(packageRoot);
  for (const path of [
    "dist",
    "package.json",
    "config",
    "contracts",
    "config.schema.json",
    SPDX_SBOM_NAME,
    CYCLONEDX_SBOM_NAME,
    SBOM_INDEX_NAME,
    RELEASE_MANIFEST_NAME,
    RELEASE_CHECKSUM_NAME,
  ]) {
    if (!existsSync(resolveContained(root, path))) throw new Error(`Release package is missing: ${path}`);
  }
  const expectedChecksums = parseChecksums(readFileSync(resolveContained(root, RELEASE_CHECKSUM_NAME), "utf8"));
  const actualFiles = listRegularFiles(root)
    .map((path) => toPosix(relative(root, path)))
    .filter((path) => path !== RELEASE_CHECKSUM_NAME);
  const expectedFiles = [...expectedChecksums.keys()].sort();
  if (actualFiles.length !== expectedFiles.length || actualFiles.some((path) => !expectedChecksums.has(path))) {
    const added = actualFiles.filter((path) => !expectedChecksums.has(path));
    const missing = expectedFiles.filter((path) => !actualFiles.includes(path));
    throw new Error(`Release package file set mismatch: ${JSON.stringify({ added, missing })}`);
  }
  for (const [path, expected] of expectedChecksums) {
    const actual = fileSha256(resolveContained(root, path));
    if (actual !== expected) throw new Error(`Release package checksum mismatch: ${path}`);
  }

  const manifest = JSON.parse(readFileSync(resolveContained(root, RELEASE_MANIFEST_NAME), "utf8"));
  validateManifest(manifest);
  if (options.expectedSourceRevision && manifest.sourceRevision !== options.expectedSourceRevision) {
    throw new Error(`Release source revision mismatch: expected ${options.expectedSourceRevision}, observed ${manifest.sourceRevision}`);
  }
  if (options.expectedRuntimeRevision && manifest.runtimeRevision !== options.expectedRuntimeRevision) {
    throw new Error(`Release runtime revision mismatch: expected ${options.expectedRuntimeRevision}, observed ${manifest.runtimeRevision}`);
  }
  const build = treeEvidence(root, manifest.payloadFiles);
  if (build.files !== manifest.files || build.sha256 !== manifest.payloadDigest) {
    throw new Error(`Release payload digest mismatch: expected ${manifest.payloadDigest}, observed ${build.sha256}`);
  }
  const runtimeBuild = treeEvidence(root, manifest.runtimeFiles);
  if (runtimeBuild.sha256 !== manifest.buildDigest) throw new Error(`Release build digest mismatch: expected ${manifest.buildDigest}, observed ${runtimeBuild.sha256}`);
  const identities = deriveReleaseIdentities(root);
  for (const key of ["schemaGeneration", "authorityContractGeneration", "configSchemaIdentity"]) {
    if (manifest[key] !== identities[key]) throw new Error(`Release ${key} mismatch.`);
  }
  const configSchema = JSON.parse(readFileSync(resolveContained(root, "config.schema.json"), "utf8"));
  const canonicalConfigSchema = JSON.parse(readFileSync(resolveContained(root, "config/config.schema.json"), "utf8"));
  if (canonicalJson(configSchema) !== canonicalJson(canonicalConfigSchema)
    || canonicalJsonSha256(configSchema) !== manifest.configSchemaIdentity) {
    throw new Error("Release config schema identity is not bound to the canonical packaged schema.");
  }
  verifySboms(root, manifest);
  assertForbiddenArtifactGate(root);
  return {
    status: "PASS",
    sourceRevision: manifest.sourceRevision,
    runtimeRevision: manifest.runtimeRevision,
    buildDigest: manifest.buildDigest,
    schemaGeneration: manifest.schemaGeneration,
    authorityContractGeneration: manifest.authorityContractGeneration,
    configSchemaIdentity: manifest.configSchemaIdentity,
    files: actualFiles.length + 1,
    manifestSha256: `sha256:${fileSha256(resolveContained(root, RELEASE_MANIFEST_NAME))}`,
    checksumsSha256: `sha256:${fileSha256(resolveContained(root, RELEASE_CHECKSUM_NAME))}`,
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

export function verifyRuntimeTree(packageRoot, runtimeRoot) {
  const root = resolve(packageRoot);
  const runtime = resolve(runtimeRoot);
  const manifest = JSON.parse(readFileSync(resolveContained(root, RELEASE_MANIFEST_NAME), "utf8"));
  validateManifest(manifest);
  const observed = treeEvidence(runtime, manifest.runtimeFiles);
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
  if (value.forbiddenArtifactScan !== "PASS") throw new Error("Release manifest forbidden artifact gate did not pass.");
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

function assertForbiddenArtifactGate(root) {
  const forbiddenNames = /(^|\/)(?:privileged(?:-client|-helper)?|launchdaemon-helper|root-helper)(?:\.|\/|$)/iu;
  for (const absolute of listRegularFiles(root)) {
    const path = toPosix(relative(root, absolute));
    if (forbiddenNames.test(path)) throw new Error(`Forbidden artifact path: ${path}`);
    if (statSync(absolute).size > 8 * 1024 * 1024) continue;
    if (/\.json$/iu.test(path)) {
      let value;
      try { value = JSON.parse(readFileSync(absolute, "utf8")); } catch { continue; }
      inspectForbiddenJson(value, path);
    }
    if (/\.sh$/iu.test(path)) {
      const value = readFileSync(absolute, "utf8");
      if (/^(?!\s*#).*\b(?:sudo|doas)\s+/imu.test(value)) throw new Error(`Forbidden elevation command in ${path}`);
      if (/\/Library\/LaunchDaemons|NOPASSWD|PrivilegedHelperTools/u.test(value)) throw new Error(`Forbidden privileged helper content in ${path}`);
    }
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
    inspectForbiddenJson(child, path, [...trail, key]);
  }
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

function verifySboms(root, manifest) {
  const spdx = JSON.parse(readFileSync(resolveContained(root, SPDX_SBOM_NAME), "utf8"));
  const cyclone = JSON.parse(readFileSync(resolveContained(root, CYCLONEDX_SBOM_NAME), "utf8"));
  const index = JSON.parse(readFileSync(resolveContained(root, SBOM_INDEX_NAME), "utf8"));
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
  return output.sort((left, right) => `${left.name}@${left.version}`.localeCompare(`${right.name}@${right.version}`));
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

function gitRevision(root) {
  try {
    return execFileSync("git", ["-C", root, "rev-parse", "HEAD"], { encoding: "utf8", stdio: ["ignore", "pipe", "ignore"] }).trim();
  } catch {
    throw new Error("sourceRevision is required when the source is not a Git checkout.");
  }
}

function runtimeContractIdentities(root) {
  const modulePath = resolveContained(root, "dist/v2/runtime-identity.js");
  if (!existsSync(modulePath)) return undefined;
  try {
    const output = execFileSync(process.execPath, ["--input-type=module", "-e", `
      import { pathToFileURL } from "node:url";
      const module = await import(pathToFileURL(process.argv[1]).href);
      const identity = module.createRuntimeIdentity({ config: {}, startedAt: "2000-01-01T00:00:00.000Z" });
      process.stdout.write(JSON.stringify({ schemaGeneration: identity.schemaGeneration, authorityContractGeneration: identity.authorityContractGeneration }));
    `, modulePath], { encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] });
    const value = JSON.parse(output);
    if (!/^sha256:[a-f0-9]{64}$/u.test(value.schemaGeneration)
      || !/^sha256:[a-f0-9]{64}$/u.test(value.authorityContractGeneration)) {
      throw new Error("runtime identity returned invalid contract digests");
    }
    return value;
  } catch (error) {
    throw new Error(`Unable to derive contract identities from the packaged runtime: ${error instanceof Error ? error.message : String(error)}`);
  }
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
