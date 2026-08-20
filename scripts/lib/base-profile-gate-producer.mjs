import { spawnSync } from "node:child_process";
import {
  createHash,
  createPrivateKey,
  createPublicKey,
  sign,
} from "node:crypto";
import {
  chmodSync,
  closeSync,
  constants,
  fstatSync,
  fsyncSync,
  lstatSync,
  mkdirSync,
  openSync,
  readFileSync,
  readdirSync,
  realpathSync,
  statSync,
  writeFileSync,
} from "node:fs";
import { dirname, isAbsolute, join, relative, resolve, sep } from "node:path";

export const BASE_PROFILE_GATE_PRODUCER_SCHEMA_VERSION = 1;
export const BASE_PROFILE_GATE_PRODUCER_PUBLIC_KEY_PATH = "evidence/base-profile-gates/GATE-PRODUCER-PUBLIC-KEY.json";
export const BASE_PROFILE_PRECUTOVER_LEDGER_PATH = "evidence/base-profile-gates/PRE-CUTOVER-GATE-LEDGER.json";

const PUBLIC_KEY_KIND = "DEVSPACE_BASE_PROFILE_GATE_PRODUCER_PUBLIC_KEY";
const PRECUTOVER_LEDGER_KIND = "DEVSPACE_BASE_PROFILE_PRECUTOVER_GATE_LEDGER";
const DIGEST_PATTERN = /^sha256:[a-f0-9]{64}$/u;
const EXACT_NODE_VERSION = "v22.23.2";
const GATE_NAMES = Object.freeze([
  "G00 PROFILE",
  "G01 SOURCE",
  "G02 STATIC",
  "G03 UNIT",
  "G04 PROTOCOL",
  "G05 FUNCTIONAL",
  "G06 SECURITY",
  "G07 DURABILITY",
  "G08 LOAD",
]);

export function collectBaseProfilePreCutoverGateLedger(options) {
  const configuration = requiredObject(options, "base profile gate producer options");
  const sourceRoot = canonicalRealDirectory(configuration.sourceRoot, "gate producer sourceRoot");
  const packageRoot = canonicalRealDirectory(configuration.packageRoot, "gate producer packageRoot");
  const outputRoot = resolveContained(packageRoot, "evidence/base-profile-gates");
  if (lstatIfPresent(outputRoot)) throw new Error("Base profile gate evidence output already exists.");
  mkdirSync(resolveContained(packageRoot, "evidence"), { recursive: false, mode: 0o700 });
  mkdirSync(outputRoot, { recursive: false, mode: 0o700 });
  const rawRoot = join(outputRoot, "raw");
  mkdirSync(rawRoot, { recursive: false, mode: 0o700 });
  const homeRoot = join(outputRoot, "runner-home");
  const temporaryRoot = join(homeRoot, "tmp");
  mkdirSync(homeRoot, { recursive: false, mode: 0o700 });
  mkdirSync(temporaryRoot, { recursive: false, mode: 0o700 });
  chmodSync(outputRoot, 0o700);
  chmodSync(rawRoot, 0o700);

  const producer = loadGateProducerPrivateKey(configuration.privateKeyPath);
  const sourceRevision = requiredRevision(configuration.sourceRevision);
  const environment = canonicalProducerEnvironment(homeRoot, temporaryRoot);
  const node = executableIdentity(process.execPath, ["--version"]);
  if (node.version !== EXACT_NODE_VERSION) {
    throw new Error(`Gate producer requires exact Node ${EXACT_NODE_VERSION}, observed ${node.version}.`);
  }
  const git = executableIdentity("/usr/bin/git", ["--version"]);
  const tscPath = canonicalRealFile(join(sourceRoot, "node_modules/typescript/bin/tsc"), "gate producer TypeScript compiler");
  const tsxLoaderPath = canonicalRealFile(join(sourceRoot, "node_modules/tsx/dist/loader.mjs"), "gate producer tsx loader");
  const nfrPath = canonicalRealFile(join(sourceRoot, "scripts/check-universal-broker-rev3-nfr.mjs"), "gate producer NFR evaluator");
  const trackedPaths = listCanonicalTrackedPaths(sourceRoot, git, environment);
  const sourceTree = sourceTreeSnapshot(sourceRoot, trackedPaths);
  const packageTree = packageInputTreeSnapshot(packageRoot);
  const testFiles = listCanonicalTestFiles(sourceRoot);
  const testInventory = classifyCanonicalTests(sourceRoot, testFiles);
  const sourceInputs = trackedPaths.map((path) => join(sourceRoot, path));
  if (testFiles.length === 0) throw new Error("Gate producer found no canonical source test files.");

  const commandContext = Object.freeze({
    sourceRoot,
    packageRoot,
    trackedPaths,
    expectedSourceTree: sourceTree,
    expectedPackageTree: packageTree,
  });
  const toolchain = Object.freeze({
    node,
    git,
    typescriptCompiler: fileIdentity(tscPath, "gate producer TypeScript compiler"),
    tsxLoader: fileIdentity(tsxLoaderPath, "gate producer tsx loader"),
    nfrEvaluator: fileIdentity(nfrPath, "gate producer NFR evaluator"),
  });

  const receipts = [];
  receipts.push(runExactCommand({
    id: "source-head-before",
    gate: "G01 SOURCE",
    executable: git,
    argv: ["rev-parse", "HEAD"],
    cwd: sourceRoot,
    environment,
    outputRoot: rawRoot,
    commandContext,
    validate: ({ stdout }) => stdout.trim() === sourceRevision,
    failure: "Source HEAD differs from the requested immutable source revision.",
  }));
  receipts.push(runExactCommand({
    id: "source-clean-before",
    gate: "G01 SOURCE",
    executable: git,
    argv: ["status", "--porcelain=v1", "--untracked-files=all"],
    cwd: sourceRoot,
    environment,
    outputRoot: rawRoot,
    commandContext,
    validate: ({ stdout }) => stdout === "",
    failure: "Source worktree is not clean.",
  }));
  receipts.push(runExactCommand({
    id: "source-upstream-before",
    gate: "G01 SOURCE",
    executable: git,
    argv: ["rev-list", "--left-right", "--count", "HEAD...@{upstream}"],
    cwd: sourceRoot,
    environment,
    outputRoot: rawRoot,
    commandContext,
    validate: ({ stdout }) => /^0\s+0\s*$/u.test(stdout),
    failure: "Source HEAD is not exactly synchronized with its configured upstream.",
  }));
  const profileReceipt = runExactCommand({
    id: "profile-runtime-identities",
    gate: "G00 PROFILE",
    executable: node,
    argv: packageIdentityReporterArguments(sourceRoot, packageRoot, sourceRevision),
    cwd: sourceRoot,
    environment,
    outputRoot: rawRoot,
    commandContext,
    inputPaths: packageIdentityReporterInputPaths(sourceRoot),
    argumentFiles: packageIdentityReporterInputPaths(sourceRoot),
    validate: ({ stdout }) => validatePackageIdentityReport(stdout, packageRoot),
    failure: "Packaged runtime identity reporter did not reproduce the canonical Base profile identities.",
  });
  receipts.push(profileReceipt);
  const profileReport = JSON.parse(readFileSync(join(outputRoot, profileReceipt.stdout.path), "utf8"));
  const bindings = deriveProducerBindings(packageRoot, sourceRevision, profileReport);
  if (configuration.bindings !== undefined) {
    const supplied = validateProducerBindings(configuration.bindings, sourceRevision);
    if (canonicalJson(supplied) !== canonicalJson(bindings)) {
      throw new Error("Caller-supplied gate bindings differ from independently recomputed package identities.");
    }
  }
  receipts.push(runExactCommand({
    id: "static-source-hygiene",
    gate: "G02 STATIC",
    executable: node,
    argv: ["--input-type=module", "-e", SOURCE_HYGIENE_PROGRAM, sourceRoot],
    cwd: sourceRoot,
    environment,
    outputRoot: rawRoot,
    commandContext,
    inputPaths: sourceInputs,
    validate: ({ stdout }) => /^SOURCE_HYGIENE_PASS files=[1-9][0-9]*\n$/u.test(stdout),
    failure: "Canonical source hygiene/lint gate failed.",
  }));
  receipts.push(runExactCommand({
    id: "static-typecheck",
    gate: "G02 STATIC",
    executable: node,
    argv: [tscPath, "-p", join(sourceRoot, "tsconfig.json"), "--noEmit"],
    cwd: sourceRoot,
    environment,
    outputRoot: rawRoot,
    commandContext,
    inputPaths: [join(sourceRoot, "tsconfig.json"), ...sourceInputs],
    argumentFiles: [tscPath],
  }));
  for (const [gate, id] of [
    ["G02 STATIC", "static-contract-generation-tests"],
    ["G03 UNIT", "unit-tests"],
    ["G04 PROTOCOL", "protocol-tests"],
    ["G05 FUNCTIONAL", "functional-tests"],
    ["G06 SECURITY", "security-tests"],
    ["G07 DURABILITY", "durability-tests"],
    ["G08 LOAD", "nfr-predicate-tests"],
  ]) {
    const files = testInventory[gate];
    if (!Array.isArray(files) || files.length === 0) {
      throw new Error(`Canonical test inventory for ${gate} is empty.`);
    }
    receipts.push(runExactCommand({
      id,
      gate,
      executable: node,
      argv: ["--disable-warning=ExperimentalWarning", "--import", tsxLoaderPath, "--test", "--test-concurrency=1", ...files],
      cwd: sourceRoot,
      environment,
      outputRoot: rawRoot,
      commandContext,
      inputPaths: sourceInputs,
      argumentFiles: [tsxLoaderPath, ...files],
      validate: validateNodeTap,
      failure: `${gate} canonical Node test reporter did not prove a nonempty zero-failure suite.`,
    }));
  }
  receipts.push(runExactCommand({
    id: "release-nfr",
    gate: "G08 LOAD",
    executable: node,
    argv: ["--expose-gc", "--import", tsxLoaderPath, nfrPath],
    cwd: sourceRoot,
    environment,
    outputRoot: rawRoot,
    commandContext,
    inputPaths: [nfrPath, ...sourceInputs],
    argumentFiles: [tsxLoaderPath, nfrPath],
    validate: validateReleaseNfrReport,
    failure: "Canonical NFR evaluator did not emit exact BASE_PROFILE_NFR_PASS.",
  }));
  for (const [suffix, argv, validate, failure] of [
    ["head-after", ["rev-parse", "HEAD"], ({ stdout }) => stdout.trim() === sourceRevision, "Final source HEAD changed during gate execution."],
    ["clean-after", ["status", "--porcelain=v1", "--untracked-files=all"], ({ stdout }) => stdout === "", "Final source worktree is not clean."],
    ["upstream-after", ["rev-list", "--left-right", "--count", "HEAD...@{upstream}"], ({ stdout }) => /^0\s+0\s*$/u.test(stdout), "Final source HEAD is not synchronized with upstream."],
  ]) {
    receipts.push(runExactCommand({
      id: `source-${suffix}`,
      gate: "G01 SOURCE",
      executable: git,
      argv,
      cwd: sourceRoot,
      environment,
      outputRoot: rawRoot,
      commandContext,
      validate,
      failure,
    }));
  }
  const finalSourceTree = sourceTreeSnapshot(sourceRoot, trackedPaths);
  const finalPackageTree = packageInputTreeSnapshot(packageRoot);
  if (canonicalJson(finalSourceTree) !== canonicalJson(sourceTree)
    || canonicalJson(finalPackageTree) !== canonicalJson(packageTree)) {
    throw new Error("Source or package input tree changed during canonical gate execution.");
  }

  const profileEvidence = Object.freeze({
    profile: profileReport.buildCapabilities.productProfile,
    supportedProfiles: Object.freeze([...profileReport.buildCapabilities.supportedProfiles]),
    buildCapabilityManifestDigest: bindings.buildCapabilityManifestDigest,
    generatedSchemaDigest: bindings.generatedSchemaDigest,
    schemaGeneration: bindings.schemaGeneration,
    authorityContractGeneration: bindings.authorityContractGeneration,
  });
  const receiptById = Object.fromEntries(receipts.map((receipt) => [receipt.id, receipt]));
  const gateBindings = Object.freeze({
    "G00 PROFILE": Object.freeze({ profileEvidenceDigest: digestJson(profileEvidence), receiptIds: Object.freeze(["profile-runtime-identities"]) }),
    "G01 SOURCE": Object.freeze({ receiptIds: Object.freeze([
      "source-head-before", "source-clean-before", "source-upstream-before",
      "source-head-after", "source-clean-after", "source-upstream-after",
    ]) }),
    "G02 STATIC": Object.freeze({ receiptIds: Object.freeze(["static-source-hygiene", "static-typecheck", "static-contract-generation-tests"]) }),
    "G03 UNIT": Object.freeze({ receiptIds: Object.freeze(["unit-tests"]) }),
    "G04 PROTOCOL": Object.freeze({ receiptIds: Object.freeze(["protocol-tests"]) }),
    "G05 FUNCTIONAL": Object.freeze({ receiptIds: Object.freeze(["functional-tests"]) }),
    "G06 SECURITY": Object.freeze({ receiptIds: Object.freeze(["security-tests"]) }),
    "G07 DURABILITY": Object.freeze({ receiptIds: Object.freeze(["durability-tests"]) }),
    "G08 LOAD": Object.freeze({ receiptIds: Object.freeze(["nfr-predicate-tests", "release-nfr"]) }),
  });
  if (canonicalJson(Object.keys(gateBindings)) !== canonicalJson(GATE_NAMES)) {
    throw new Error("Gate producer canonical gate ordering drifted.");
  }
  const payload = Object.freeze({
    schemaVersion: BASE_PROFILE_GATE_PRODUCER_SCHEMA_VERSION,
    sourceRevision,
    bindings,
    producer: producer.publicIdentity,
    environment,
    environmentDigest: digestJson(environment),
    toolchain,
    toolchainDigest: digestJson(toolchain),
    sourceTree,
    packageInputTree: packageTree,
    testInventory: Object.freeze(Object.fromEntries(GATE_NAMES.map((gate) => [
      gate,
      Object.freeze((testInventory[gate] ?? []).map((path) => relative(sourceRoot, path))),
    ]))),
    profileEvidence,
    receipts: Object.freeze(receipts),
    receiptsDigest: digestJson(receiptById),
    gateBindings,
  });
  const ledger = signedEnvelope(PRECUTOVER_LEDGER_KIND, payload, producer);
  const publicKeyPath = resolveContained(packageRoot, BASE_PROFILE_GATE_PRODUCER_PUBLIC_KEY_PATH);
  const ledgerPath = resolveContained(packageRoot, BASE_PROFILE_PRECUTOVER_LEDGER_PATH);
  writeOwnerOnlyJsonNew(publicKeyPath, producer.publicArtifact, "gate producer public-key artifact");
  writeOwnerOnlyJsonNew(ledgerPath, ledger, "base profile pre-cutover gate ledger");
  return Object.freeze({
    gateProducer: Object.freeze({
      schemaVersion: BASE_PROFILE_GATE_PRODUCER_SCHEMA_VERSION,
      keyId: producer.publicIdentity.keyId,
      publicKeySha256: producer.publicIdentity.publicKeySha256,
      publicKeyPath: BASE_PROFILE_GATE_PRODUCER_PUBLIC_KEY_PATH,
      preCutoverLedgerPath: BASE_PROFILE_PRECUTOVER_LEDGER_PATH,
      preCutoverLedgerSha256: digestBytes(readFileSync(ledgerPath)),
    }),
    ledgerPath,
    ledger,
  });
}

function loadGateProducerPrivateKey(value) {
  const path = canonicalOwnerOnlyFile(value, "gate producer private key");
  const bytes = stableReadFile(path, "gate producer private key");
  let privateKey;
  try { privateKey = createPrivateKey({ key: bytes, format: "der", type: "pkcs8" }); }
  catch { throw new Error("Gate producer private key is not canonical PKCS8 DER."); }
  if (privateKey.asymmetricKeyType !== "ed25519") throw new Error("Gate producer private key must be Ed25519.");
  const publicDer = createPublicKey(privateKey).export({ format: "der", type: "spki" });
  const publicKeySha256 = digestBytes(publicDer);
  const keyId = `gate-producer-ed25519-sha256:${publicKeySha256.slice("sha256:".length)}`;
  const publicIdentity = Object.freeze({ keyId, publicKeySha256 });
  const publicArtifact = Object.freeze({
    schemaVersion: BASE_PROFILE_GATE_PRODUCER_SCHEMA_VERSION,
    kind: PUBLIC_KEY_KIND,
    algorithm: "Ed25519",
    keyId,
    publicKeySpkiDerBase64: publicDer.toString("base64"),
    publicKeySha256,
  });
  return Object.freeze({ privateKey, publicIdentity, publicArtifact });
}

function signedEnvelope(kind, payload, producer) {
  const payloadDigest = digestJson(payload);
  const unsigned = Object.freeze({
    schemaVersion: BASE_PROFILE_GATE_PRODUCER_SCHEMA_VERSION,
    kind,
    keyId: producer.publicIdentity.keyId,
    payloadDigest,
    payload,
  });
  const message = Buffer.from(`devspace.base-profile-gate-producer.v1/${kind}\0${canonicalJson(unsigned)}`);
  return Object.freeze({ ...unsigned, signature: sign(null, message, producer.privateKey).toString("base64url") });
}

function runExactCommand(options) {
  const commandInputs = captureCommandInputs(options);
  assertCommandContextUnchanged(options.commandContext, `${options.id} pre-execution`);
  const startedAt = new Date().toISOString();
  const result = spawnSync(options.executable.path, options.argv, {
    cwd: options.cwd,
    env: options.environment,
    encoding: "utf8",
    timeout: 30 * 60 * 1000,
    maxBuffer: 128 * 1024 * 1024,
    windowsHide: true,
  });
  const completedAt = new Date().toISOString();
  const stdout = result.stdout ?? "";
  const stderr = result.stderr ?? "";
  const stdoutRelativePath = `raw/${options.id}.stdout`;
  const stderrRelativePath = `raw/${options.id}.stderr`;
  writeOwnerOnlyBytesNew(join(dirname(options.outputRoot), stdoutRelativePath), Buffer.from(stdout), `${options.id} stdout`);
  writeOwnerOnlyBytesNew(join(dirname(options.outputRoot), stderrRelativePath), Buffer.from(stderr), `${options.id} stderr`);
  if (result.error) throw new Error(`Canonical gate command ${options.id} failed to execute: ${result.error.message}`);
  if (result.signal !== null || result.status !== 0) {
    throw new Error(`Canonical gate command ${options.id} failed: exit=${String(result.status)} signal=${String(result.signal)}`);
  }
  if (options.validate && !options.validate({ stdout, stderr })) {
    throw new Error(options.failure ?? `Canonical gate command ${options.id} output validation failed.`);
  }
  assertCommandInputsUnchanged(commandInputs, `${options.id} post-execution`);
  assertCommandContextUnchanged(options.commandContext, `${options.id} post-execution`);
  const receipt = Object.freeze({
    schemaVersion: BASE_PROFILE_GATE_PRODUCER_SCHEMA_VERSION,
    id: options.id,
    gate: options.gate,
    executable: options.executable,
    argv: Object.freeze([...options.argv]),
    cwd: options.cwd,
    environmentDigest: digestJson(options.environment),
    sourceTreeDigest: options.commandContext.expectedSourceTree.sha256,
    packageInputTreeDigest: options.commandContext.expectedPackageTree.sha256,
    startedAt,
    completedAt,
    exitCode: result.status,
    signal: result.signal,
    stdout: Object.freeze({ path: stdoutRelativePath, bytes: Buffer.byteLength(stdout), sha256: digestBytes(Buffer.from(stdout)) }),
    stderr: Object.freeze({ path: stderrRelativePath, bytes: Buffer.byteLength(stderr), sha256: digestBytes(Buffer.from(stderr)) }),
    inputs: commandInputs,
  });
  return Object.freeze({ ...receipt, receiptDigest: digestJson(receipt) });
}

function captureCommandInputs(options) {
  const argumentFiles = new Set((options.argumentFiles ?? []).map((path) => canonicalRealFile(path, `${options.id} argv file`)));
  for (const path of argumentFiles) {
    if (!options.argv.includes(path)) throw new Error(`${options.id} argv does not contain its bound argument file: ${path}`);
  }
  const paths = [...new Set([...(options.inputPaths ?? []), ...argumentFiles])]
    .map((path) => canonicalRealFile(path, `${options.id} command input`))
    .sort(compareCodeUnits);
  return Object.freeze(paths.map((path) => Object.freeze({
    path,
    sha256: digestBytes(stableReadFile(path, `${options.id} command input`)),
  })));
}

function assertCommandInputsUnchanged(inputs, label) {
  for (const input of inputs) {
    const path = canonicalRealFile(input.path, `${label} command input`);
    if (digestBytes(stableReadFile(path, `${label} command input`)) !== input.sha256) {
      throw new Error(`${label} changed command input: ${path}`);
    }
  }
}

function assertCommandContextUnchanged(context, label) {
  const source = sourceTreeSnapshot(context.sourceRoot, context.trackedPaths);
  const packageTree = packageInputTreeSnapshot(context.packageRoot);
  if (canonicalJson(source) !== canonicalJson(context.expectedSourceTree)
    || canonicalJson(packageTree) !== canonicalJson(context.expectedPackageTree)) {
    throw new Error(`${label} observed a source or package input tree change.`);
  }
}

function executableIdentity(value, versionArguments) {
  const path = canonicalExecutable(value, "gate producer executable");
  const version = spawnSync(path, versionArguments, {
    encoding: "utf8",
    env: { LANG: "C", LC_ALL: "C", PATH: "", TZ: "UTC" },
    timeout: 30_000,
  });
  if (version.error || version.status !== 0 || version.signal !== null) {
    throw new Error(`Gate producer executable version probe failed: ${path}`);
  }
  const text = `${version.stdout ?? ""}${version.stderr ?? ""}`.trim().split("\n")[0];
  if (!text) throw new Error(`Gate producer executable version is empty: ${path}`);
  return Object.freeze({ path, sha256: digestBytes(stableReadFile(path, "gate producer executable")), version: text });
}

function fileIdentity(path, label) {
  const canonical = canonicalRealFile(path, label);
  const metadata = lstatSync(canonical, { bigint: true });
  return Object.freeze({
    path: canonical,
    bytes: Number(metadata.size),
    sha256: digestBytes(stableReadFile(canonical, label)),
  });
}

function validateProducerBindings(value, sourceRevision) {
  const input = canonicalClone(requiredObject(value, "gate producer immutable bindings"));
  assertExactKeys(input, [
    "authorityContractGeneration", "buildCapabilityManifestDigest", "buildDigest", "generatedSchemaDigest",
    "migrationManifestDigest", "schemaGeneration", "sourceRevision",
  ], "gate producer immutable bindings");
  if (input.sourceRevision !== sourceRevision) throw new Error("Gate producer source revision binding differs.");
  for (const key of Object.keys(input).filter((key) => key !== "sourceRevision")) requireDigest(input[key], `gate producer ${key}`);
  return Object.freeze(input);
}

function canonicalProducerEnvironment(homeRoot, temporaryRoot) {
  const environment = {
    HOME: homeRoot,
    LANG: "C",
    LC_ALL: "C",
    NODE_OPTIONS: "",
    NO_COLOR: "1",
    PATH: "/usr/bin:/bin",
    TMPDIR: temporaryRoot,
    TZ: "UTC",
    GIT_CONFIG_NOSYSTEM: "1",
    GIT_CONFIG_GLOBAL: "/dev/null",
  };
  for (const name of [
    "DEVSPACE_REV3_NFR_PUBLIC_BASE_URL",
    "DEVSPACE_REV3_NFR_MANAGEMENT_BASE_URL",
    "DEVSPACE_REV3_NFR_SELF_RESTART_EVIDENCE",
    "DEVSPACE_REV3_NFR_SSH_TARGETS_FILE",
    "DEVSPACE_REV3_NFR_SSH_TARGET",
    "DEVSPACE_REV3_NFR_SSH_READ_PATH",
    "DEVSPACE_REV3_NFR_SSH_EXECUTABLE",
    "DEVSPACE_REV3_NFR_SFTP_EXECUTABLE",
  ]) {
    const value = process.env[name]?.trim();
    if (value) environment[name] = value;
  }
  return Object.freeze(environment);
}

function listCanonicalTrackedPaths(sourceRoot, git, environment) {
  const result = spawnSync(git.path, ["-C", sourceRoot, "ls-files", "-z", "--cached"], {
    encoding: "buffer",
    env: environment,
    timeout: 30_000,
    maxBuffer: 32 * 1024 * 1024,
  });
  if (result.error || result.status !== 0 || result.signal !== null || (result.stderr?.length ?? 0) !== 0) {
    throw new Error("Gate producer could not enumerate the canonical tracked source tree.");
  }
  const text = (result.stdout ?? Buffer.alloc(0)).toString("utf8");
  const paths = text.split("\0").filter(Boolean);
  if (paths.length === 0 || new Set(paths).size !== paths.length) throw new Error("Gate producer tracked source inventory is empty or duplicated.");
  const sorted = [...paths].sort(compareCodeUnits);
  if (canonicalJson(paths) !== canonicalJson(sorted)) throw new Error("Git tracked source inventory is not code-unit ordered.");
  for (const path of sorted) {
    if (path !== path.split(sep).join("/") || path.startsWith("/") || path.split("/").some((part) => !part || part === "." || part === "..")) {
      throw new Error(`Gate producer tracked source path is unsafe: ${path}`);
    }
    canonicalRealFile(join(sourceRoot, path), `gate producer tracked source ${path}`);
  }
  return Object.freeze(sorted);
}

function sourceTreeSnapshot(sourceRoot, trackedPaths) {
  return immutableTreeSnapshot(sourceRoot, trackedPaths, "gate producer tracked source");
}

function packageInputTreeSnapshot(packageRoot) {
  const paths = [];
  const visit = (directory) => {
    for (const entry of readdirSync(directory, { withFileTypes: true }).sort((a, b) => compareCodeUnits(a.name, b.name))) {
      const path = join(directory, entry.name);
      const relativePath = relative(packageRoot, path).split(sep).join("/");
      if (relativePath === "evidence/base-profile-gates" || relativePath.startsWith("evidence/base-profile-gates/")) continue;
      if (entry.isSymbolicLink()) throw new Error(`Gate producer package input contains a symlink: ${path}`);
      if (entry.isDirectory()) visit(path);
      else if (entry.isFile()) paths.push(relativePath);
      else throw new Error(`Gate producer package input contains an unsupported entry: ${path}`);
    }
  };
  visit(packageRoot);
  return immutableTreeSnapshot(packageRoot, paths.sort(compareCodeUnits), "gate producer package input");
}

function immutableTreeSnapshot(root, paths, label) {
  const digest = createHash("sha256");
  const files = [];
  for (const path of paths) {
    const absolute = canonicalRealFile(join(root, path), `${label} ${path}`);
    const bytes = stableReadFile(absolute, `${label} ${path}`);
    const sha256 = digestBytes(bytes);
    digest.update(path);
    digest.update("\0");
    digest.update(sha256.slice("sha256:".length));
    digest.update("\n");
    files.push(Object.freeze({ path, bytes: bytes.length, sha256 }));
  }
  return Object.freeze({
    files: Object.freeze(files),
    count: files.length,
    sha256: `sha256:${digest.digest("hex")}`,
  });
}

function listCanonicalTestFiles(sourceRoot) {
  const output = [];
  const visit = (directory) => {
    for (const entry of readdirSync(directory, { withFileTypes: true }).sort((a, b) => compareCodeUnits(a.name, b.name))) {
      const path = join(directory, entry.name);
      if (entry.isSymbolicLink()) throw new Error(`Gate producer source test tree contains a symlink: ${path}`);
      if (entry.isDirectory()) visit(path);
      else if (entry.isFile() && /\.test\.(?:ts|mjs)$/u.test(entry.name)) output.push(path);
      else if (!entry.isFile()) throw new Error(`Gate producer source test tree contains an unsupported entry: ${path}`);
    }
  };
  for (const relativeRoot of ["src", "scripts"]) {
    visit(canonicalRealDirectory(join(sourceRoot, relativeRoot), `gate producer ${relativeRoot} test root`));
  }
  return Object.freeze(output.sort(compareCodeUnits));
}

function classifyCanonicalTests(sourceRoot, testFiles) {
  const inventory = Object.fromEntries(GATE_NAMES.map((gate) => [gate, []]));
  const staticFiles = new Set([
    "src/v2/build-capabilities.test.ts",
    "src/v2/contracts.test.ts",
    "src/v2/migration-registry.test.ts",
  ]);
  for (const absolute of testFiles) {
    const path = relative(sourceRoot, absolute).split(sep).join("/");
    let gate;
    if (staticFiles.has(path)) gate = "G02 STATIC";
    else if (path === "scripts/check-universal-broker-rev3-nfr.test.mjs") gate = "G08 LOAD";
    else if (/(?:authority|no-elevation|oauth|management-authorization|cursor-signing|cursor-capability|rate-limit|connector-activation-evidence|connector-staging-activation|release-upgrade-isolation)/u.test(path)) gate = "G06 SECURITY";
    else if (/(?:snapshot-group|filesystem|artifact-catalog|process-output|operation-audit|connector-activation-journal|connector-activation-lifecycle|connector-activation-finalizer|local-agent-store|db\/schema|maintenance)/u.test(path)) gate = "G07 DURABILITY";
    else if (/(?:contracts|production-upgrade-contract|connector-route-identity|mcp-|resource-|build-capabilities|migration-registry)/u.test(path)) gate = "G04 PROTOCOL";
    else if (/(?:http-server|server|cli|env-profiles-integration|local-agent|targets|gui|connector-activation-release-driver|release-finalization)/u.test(path)) gate = "G05 FUNCTIONAL";
    else gate = "G03 UNIT";
    inventory[gate].push(absolute);
  }
  const flattened = Object.values(inventory).flat();
  if (flattened.length !== testFiles.length || new Set(flattened).size !== testFiles.length) {
    throw new Error("Canonical gate test inventory is missing or duplicates a test file.");
  }
  return Object.freeze(Object.fromEntries(GATE_NAMES.map((gate) => [
    gate,
    Object.freeze(inventory[gate].sort(compareCodeUnits)),
  ])));
}

function packageIdentityReporterArguments(sourceRoot, packageRoot, sourceRevision) {
  const modulePath = join(sourceRoot, "scripts/lib/release-artifacts.mjs");
  return Object.freeze([
    "--input-type=module",
    "-e",
    `import { pathToFileURL } from "node:url"; const [modulePath, packageRoot, sourceRevision] = process.argv.slice(1); const module = await import(pathToFileURL(modulePath).href); process.stdout.write(JSON.stringify(module.deriveReleaseGateIdentityReport(packageRoot, sourceRevision)));`,
    modulePath,
    packageRoot,
    sourceRevision,
  ]);
}

function packageIdentityReporterInputPaths(sourceRoot) {
  return Object.freeze([join(sourceRoot, "scripts/lib/release-artifacts.mjs")]);
}

function validatePackageIdentityReport(stdout, packageRoot) {
  let value;
  try { value = JSON.parse(stdout); }
  catch { return false; }
  try {
    assertExactKeys(value, [
      "authorityContractGeneration", "buildCapabilities", "buildCapabilityManifestDigest", "buildDigest",
      "generatedSchemaDigest", "migrationManifest", "migrationManifestDigest", "packageInputDigest",
      "schemaGeneration", "sourceRevision",
    ], "gate producer package identity report");
    requiredRevision(value.sourceRevision);
    for (const key of [
      "authorityContractGeneration", "buildCapabilityManifestDigest", "buildDigest", "generatedSchemaDigest",
      "migrationManifestDigest", "packageInputDigest", "schemaGeneration",
    ]) requireDigest(value[key], `gate producer package report ${key}`);
    if (value.buildCapabilities?.productProfile !== "BASE_SINGLE_OWNER"
      || canonicalJson(value.buildCapabilities?.supportedProfiles) !== canonicalJson(["BASE_SINGLE_OWNER"])
      || value.buildCapabilities?.buildDigest !== value.buildDigest
      || value.buildCapabilities?.capabilityDigest !== value.buildCapabilityManifestDigest
      || !Array.isArray(value.migrationManifest) || value.migrationManifest.length === 0) return false;
    return packageInputTreeSnapshot(packageRoot).sha256 === value.packageInputDigest;
  } catch {
    return false;
  }
}

function deriveProducerBindings(packageRoot, sourceRevision, report) {
  if (!validatePackageIdentityReport(canonicalJson(report), packageRoot)) {
    throw new Error("Gate producer package identity report is invalid.");
  }
  if (report.sourceRevision !== sourceRevision) throw new Error("Gate producer package report source revision differs.");
  return Object.freeze({
    sourceRevision,
    buildDigest: report.buildDigest,
    schemaGeneration: report.schemaGeneration,
    authorityContractGeneration: report.authorityContractGeneration,
    buildCapabilityManifestDigest: report.buildCapabilityManifestDigest,
    generatedSchemaDigest: report.generatedSchemaDigest,
    migrationManifestDigest: report.migrationManifestDigest,
  });
}

function validateNodeTap({ stdout, stderr }) {
  if (stderr !== "" || !/^TAP version 13\n/mu.test(stdout)) return false;
  const tests = /^# tests ([0-9]+)$/mu.exec(stdout);
  const pass = /^# pass ([0-9]+)$/mu.exec(stdout);
  const fail = /^# fail ([0-9]+)$/mu.exec(stdout);
  const cancelled = /^# cancelled ([0-9]+)$/mu.exec(stdout);
  const skipped = /^# skipped ([0-9]+)$/mu.exec(stdout);
  const todo = /^# todo ([0-9]+)$/mu.exec(stdout);
  if (![tests, pass, fail, cancelled, skipped, todo].every(Boolean)) return false;
  const count = Number(tests[1]);
  return count > 0 && Number(pass[1]) === count && Number(fail[1]) === 0
    && Number(cancelled[1]) === 0 && Number(skipped[1]) === 0 && Number(todo[1]) === 0;
}

function validateReleaseNfrReport({ stdout, stderr }) {
  if (stderr !== "") return false;
  let report;
  try { report = JSON.parse(stdout); } catch { return false; }
  return report?.mode === "release"
    && report?.evaluation?.status === "BASE_PROFILE_NFR_PASS"
    && report?.evaluation?.releaseEligible === true
    && report?.evaluation?.exitCode === 0
    && Array.isArray(report?.evaluation?.failures) && report.evaluation.failures.length === 0
    && Array.isArray(report?.evaluation?.releaseBlockers) && report.evaluation.releaseBlockers.length === 0
    && Array.isArray(report?.results) && report.results.length > 0;
}

const SOURCE_HYGIENE_PROGRAM = [
  'import { readFileSync } from "node:fs";',
  'import { spawnSync } from "node:child_process";',
  "const root = process.argv[1];",
  'const git = spawnSync("/usr/bin/git", ["-C", root, "ls-files", "-z", "--cached"], { encoding: "buffer", env: { LANG: "C", LC_ALL: "C", PATH: "", TZ: "UTC", GIT_CONFIG_NOSYSTEM: "1", GIT_CONFIG_GLOBAL: "/dev/null" } });',
  "if (git.status !== 0 || git.signal !== null || git.error) process.exit(2);",
  'const files = git.stdout.toString("utf8").split("\\0").filter(Boolean).filter((path) => /\\.(?:[cm]?[jt]s|json|sh|bash|zsh)$/u.test(path));',
  "if (files.length === 0) process.exit(3);",
  "for (const path of files) {",
  '  const text = readFileSync(root + "/" + path, "utf8");',
  "  if (/^(?:<<<<<<<|=======|>>>>>>>)(?: |$)/mu.test(text) || /[ \\t]+$/mu.test(text)) process.exit(4);",
  "}",
  'process.stdout.write("SOURCE_HYGIENE_PASS files=" + files.length + "\\n");',
].join("\n");

function listCanonicalSourceInputs(sourceRoot) {
  const output = [];
  const visit = (directory) => {
    for (const entry of readdirSync(directory, { withFileTypes: true }).sort((a, b) => compareCodeUnits(a.name, b.name))) {
      const path = join(directory, entry.name);
      if (entry.isSymbolicLink()) throw new Error(`Gate producer source input tree contains a symlink: ${path}`);
      if (entry.isDirectory()) visit(path);
      else if (entry.isFile() && /\.(?:ts|mts|cts|js|mjs|cjs|json)$/u.test(entry.name)) output.push(path);
      else if (!entry.isFile()) throw new Error(`Gate producer source input tree contains an unsupported entry: ${path}`);
    }
  };
  visit(canonicalRealDirectory(join(sourceRoot, "src"), "gate producer source input root"));
  return Object.freeze(output.sort(compareCodeUnits));
}

function writeOwnerOnlyJsonNew(path, value, label) {
  writeOwnerOnlyBytesNew(path, Buffer.from(`${canonicalJson(value)}\n`), label);
}

function writeOwnerOnlyBytesNew(path, bytes, label) {
  const parent = canonicalRealDirectory(dirname(path), `${label} parent`);
  const descriptor = openSync(path, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | (constants.O_NOFOLLOW ?? 0), 0o600);
  try { writeFileSync(descriptor, bytes); fsyncSync(descriptor); }
  finally { closeSync(descriptor); }
  chmodSync(path, 0o600);
  fsyncDirectory(parent);
}

function stableReadFile(path, label) {
  const descriptor = openSync(path, constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0));
  try {
    const before = fstatSync(descriptor, { bigint: true });
    const bytes = readFileSync(descriptor);
    const after = fstatSync(descriptor, { bigint: true });
    if (!before.isFile() || before.dev !== after.dev || before.ino !== after.ino
      || before.size !== after.size || before.mtimeNs !== after.mtimeNs || BigInt(bytes.length) !== after.size) {
      throw new Error(`${label} changed during single-descriptor read.`);
    }
    return bytes;
  } finally { closeSync(descriptor); }
}

function canonicalOwnerOnlyFile(value, label) {
  const path = requiredAbsolutePath(value, label);
  const metadata = lstatSync(path);
  if (!metadata.isFile() || metadata.isSymbolicLink() || realpathSync(path) !== path
    || (metadata.mode & 0o077) !== 0
    || (typeof process.getuid === "function" && metadata.uid !== process.getuid())) {
    throw new Error(`${label} must be an owner-only canonical real file.`);
  }
  return path;
}

function canonicalRealFile(value, label) {
  const path = requiredAbsolutePath(value, label);
  const metadata = lstatSync(path);
  if (!metadata.isFile() || metadata.isSymbolicLink() || realpathSync(path) !== path) throw new Error(`${label} must be a canonical real file.`);
  return path;
}

function canonicalExecutable(value, label) {
  const path = canonicalRealFile(value, label);
  if ((lstatSync(path).mode & 0o111) === 0) throw new Error(`${label} is not executable.`);
  return path;
}

function canonicalRealDirectory(value, label) {
  const path = requiredAbsolutePath(value, label);
  const metadata = lstatSync(path);
  if (!metadata.isDirectory() || metadata.isSymbolicLink() || realpathSync(path) !== path) throw new Error(`${label} must be a canonical real directory.`);
  return path;
}

function resolveContained(root, path) {
  const absolute = resolve(root, path);
  const relation = relative(root, absolute);
  if (relation === ".." || relation.startsWith(`..${sep}`) || isAbsolute(relation)) throw new Error(`Gate producer path escapes root: ${path}`);
  return absolute;
}

function requiredAbsolutePath(value, label) {
  if (typeof value !== "string" || !isAbsolute(value) || resolve(value) !== value || /[\0\r\n]/u.test(value)) throw new Error(`${label} must be an absolute canonical path.`);
  return value;
}

function requiredObject(value, label) {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error(`${label} is missing or invalid.`);
  return value;
}

function requiredRevision(value) {
  if (typeof value !== "string" || !/^[a-f0-9]{40}$/u.test(value)) throw new Error("Gate producer sourceRevision must be an exact 40-hex Git revision.");
  return value;
}

function requireDigest(value, label) {
  if (!DIGEST_PATTERN.test(value ?? "")) throw new Error(`${label} is not a canonical SHA-256 digest.`);
  return value;
}

function assertExactKeys(value, expected, label) {
  const actual = Object.keys(requiredObject(value, label)).sort(compareCodeUnits);
  const wanted = [...expected].sort(compareCodeUnits);
  if (canonicalJson(actual) !== canonicalJson(wanted)) throw new Error(`${label} contains a missing or unsupported field.`);
}

function canonicalClone(value) { return JSON.parse(canonicalJson(value)); }
function canonicalJson(value) {
  if (value === null || typeof value !== "object") {
    const encoded = JSON.stringify(value);
    if (encoded === undefined) throw new Error("Gate producer value is not canonically serializable.");
    return encoded;
  }
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  return `{${Object.keys(value).sort(compareCodeUnits).map((key) => `${JSON.stringify(key)}:${canonicalJson(value[key])}`).join(",")}}`;
}
function digestJson(value) { return digestBytes(Buffer.from(canonicalJson(value))); }
function digestBytes(value) { return `sha256:${createHash("sha256").update(value).digest("hex")}`; }
function compareCodeUnits(left, right) { return left < right ? -1 : left > right ? 1 : 0; }
function lstatIfPresent(path) { try { return lstatSync(path); } catch (error) { if (error?.code === "ENOENT") return undefined; throw error; } }
function fsyncDirectory(path) { const descriptor = openSync(path, constants.O_RDONLY); try { fsyncSync(descriptor); } catch (error) { if (!["EINVAL", "ENOTSUP", "EISDIR", "EPERM"].includes(error?.code)) throw error; } finally { closeSync(descriptor); } }
