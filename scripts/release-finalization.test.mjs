import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { chmodSync } from "node:fs";
import { chmod, cp, mkdir, mkdtemp, readFile, realpath, rm, stat, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join, relative, resolve, sep } from "node:path";
import { fileURLToPath } from "node:url";
import Database from "better-sqlite3";
import { ensureOwnerInstanceId } from "./lib/owner-instance-id.mjs";
import {
  RELEASE_CHECKSUM_NAME,
  RELEASE_MANIFEST_NAME,
  RUNTIME_OPERATIONS_CLOSURE_ROOTS,
  canonicalJson,
  createReleasePackage,
  fileSha256,
  listRegularFiles,
  sealRuntimeDependencies,
  sha256,
  treeEvidence,
  verifyReleasePackage,
  verifyUnattestedReleaseFixture,
  verifyRuntimeCommand,
  verifyRuntimeDependencies,
} from "./lib/release-artifacts.mjs";
import {
  initializeFinalizationStore,
  FINALIZATION_STORE_MIGRATION,
  prepareFinalizationTransaction,
  readFinalizationStoreIdentity,
  sealFinalization,
  transitionFinalizationLifecycle,
  validateFinalReadbackEvidence,
  verifyFinalizationDirectory,
} from "./lib/finalization-state.mjs";
import {
  bootstrapFinalizationStore,
  createFinalizationStoreBootstrapAuthorization,
  initializeFinalizationStore as initializeFinalizationStoreContract,
  readFinalizationStoreIdentity as readFinalizationStoreIdentityContract,
} from "./lib/finalization-store-contract.mjs";
import { runCanonicalFinalReadback } from "./finalization-live-driver.mjs";
import { captureSnapshotGroup } from "../dist/v2/snapshot-group.js";
import {
  connectorActivationAuthorityReceiptDigest,
  connectorActivationReceiptDigest,
  signConnectorActivationPostActivationHostCanary,
} from "../dist/v2/connector-activation-evidence.js";
import { loadOrCreateManagementAuthorizationKey } from "../dist/v2/management-authorization.js";
import { connectorActivationTupleDigest } from "../dist/oauth-store.js";
import { SqliteConnectorActivationRecoveryJournal } from "../dist/v2/connector-activation-journal.js";

const scriptsRoot = dirname(fileURLToPath(import.meta.url));
const repositoryRoot = dirname(scriptsRoot);
const nodeDirectory = dirname(process.execPath);
const root = await realpath(await mkdtemp(join(tmpdir(), "devspace-release-finalization-")));
let currentFinalizationAssertionCount = 0;

try {
  const source = join(root, "source");
  const release = join(root, "release");
  await createFixtureSource(source);
  const sourceRevision = "0123456789abcdef0123456789abcdef01234567";
  const created = createReleasePackage({
    fixtureOnly: true,
    fixtureGeneratedReleaseMetadata,
    sourceRoot: source,
    outputRoot: release,
    sourceRevision,
    runtimeRevision: sourceRevision,
    createdAt: "2026-08-19T00:00:00.000Z",
  });
  const packageEvidence = verifyUnattestedReleaseFixture(release, {
    expectedSourceRevision: sourceRevision,
    expectedRuntimeRevision: sourceRevision,
  });
  const fixtureRuntimeVerification = {
    allowUnattestedFixture: true,
    verifiedRelease: packageEvidence,
  };
  assert.equal(packageEvidence.status, "UNATTESTED_FIXTURE_ONLY");
  assert.equal(created.manifest.buildDigest, packageEvidence.buildDigest);
  assert.equal(created.manifest.schemaGeneration, `sha256:${"a".repeat(64)}`);
  assert.equal(created.manifest.authorityContractGeneration, `sha256:${"b".repeat(64)}`);
  assert.equal(created.manifest.buildCapabilities.productProfile, "BASE_SINGLE_OWNER");
  assert.equal(created.manifest.buildCapabilities.buildDigest, created.manifest.buildDigest);
  assert.deepEqual(created.manifest.buildCapabilities.supportedProfiles, ["BASE_SINGLE_OWNER"]);
  assert.match(created.manifest.migrationManifestDigest, /^sha256:[a-f0-9]{64}$/u);
  assert.equal(packageEvidence.migrationManifestDigest, created.manifest.migrationManifestDigest);
  assert.ok(created.manifest.migrationManifest.some((entry) => entry.storeId === "main" && entry.name === "fixture-main"));
  assert.ok(created.manifest.migrationManifest.some((entry) => entry.storeId === "artifact-catalog"));
  assert.ok(created.manifest.migrationManifest.some((entry) => entry.storeId === "filesystem-sync" && entry.name === "filesystem-sync-sqlite"));
  assert.deepEqual(
    created.manifest.migrationManifest.find((entry) => entry.storeId === "lifecycle-finalization-store"),
    FINALIZATION_STORE_MIGRATION,
  );
  assert.equal(created.manifest.runtime.cwd, ".");
  assert.equal(created.manifest.runtime.entrypoint, "scripts/start-universal-broker-v2-production.sh");
  assert.equal(created.manifest.runtime.nodeEntrypoint, "dist/cli.js");
  assert.equal(created.manifest.runtime.dependencies.mode, "external-node-modules-loader-v1");
  assert.match(created.manifest.runtime.dependencies.lockfileSha256, /^sha256:[a-f0-9]{64}$/u);
  await assert.rejects(stat(join(release, "node_modules")), /ENOENT/u, "release must remain dependency-free");
  const runtimeCommand = verifyRuntimeCommand(
    release,
    release,
    join(release, "scripts", "start-universal-broker-v2-production.sh"),
    fixtureRuntimeVerification,
  );
  assert.equal(runtimeCommand.status, "PASS");
  assert.throws(
    () => verifyRuntimeCommand(release, source, join(source, "scripts", "start-universal-broker-v2-production.sh"), fixtureRuntimeVerification),
    /immutable release manifest/u,
  );
  const dependencyRoot = join(root, "runtime-dependencies");
  await mkdir(dependencyRoot, { recursive: true });
  await cp(join(source, "package.json"), join(dependencyRoot, "package.json"));
  await cp(join(source, "package-lock.json"), join(dependencyRoot, "package-lock.json"));
  await cp(join(source, "node_modules"), join(dependencyRoot, "node_modules"), { recursive: true });
  const sealedDependencies = sealRuntimeDependencies(release, dependencyRoot, {
    ...fixtureRuntimeVerification,
    createdAt: "2026-08-19T00:00:01.000Z",
  });
  assert.equal(sealedDependencies.status, "SEALED");
  assert.equal((await stat(sealedDependencies.evidencePath)).mode & 0o777, 0o600);
  assert.throws(
    () => sealRuntimeDependencies(release, root),
    /must remain separate/u,
  );
  assert.equal(verifyRuntimeDependencies(release, dependencyRoot, {
    ...fixtureRuntimeVerification,
    evidencePath: sealedDependencies.evidencePath,
    expectedEvidenceSha256: sealedDependencies.evidenceSha256,
  }).status, "PASS");
  assert.throws(
    () => verifyRuntimeDependencies(release, dependencyRoot, {
      ...fixtureRuntimeVerification,
      evidencePath: sealedDependencies.evidencePath,
      expectedEvidenceSha256: `sha256:${"0".repeat(64)}`,
    }),
    /evidence digest mismatch/u,
  );
  const dependencyModule = join(dependencyRoot, "node_modules", "fixture-identity-dependency", "index.js");
  const dependencyModuleSource = await readFile(dependencyModule, "utf8");
  await writeFile(dependencyModule, `${dependencyModuleSource}// tampered\n`);
  assert.throws(
    () => verifyRuntimeDependencies(release, dependencyRoot, {
      ...fixtureRuntimeVerification,
      evidencePath: sealedDependencies.evidencePath,
      expectedEvidenceSha256: sealedDependencies.evidenceSha256,
    }),
    /dependency tree mismatch/u,
  );
  await writeFile(dependencyModule, dependencyModuleSource);
  const escapingDependencyRoot = join(root, "runtime-dependencies-escaping");
  const escapingTarget = join(root, "outside-runtime-dependency.js");
  await mkdir(escapingDependencyRoot, { recursive: true });
  await cp(join(source, "package.json"), join(escapingDependencyRoot, "package.json"));
  await cp(join(source, "package-lock.json"), join(escapingDependencyRoot, "package-lock.json"));
  await cp(join(source, "node_modules"), join(escapingDependencyRoot, "node_modules"), { recursive: true });
  await writeFile(escapingTarget, "export const outside = true;\n");
  await symlink(escapingTarget, join(escapingDependencyRoot, "node_modules", "escaping-runtime-dependency.js"));
  assert.throws(
    () => sealRuntimeDependencies(release, escapingDependencyRoot, fixtureRuntimeVerification),
    /symlink escapes node_modules/u,
  );
  await assertReleaseVerifierRunsRev3NfrGate();

  const staleToolsSource = join(root, "stale-tools-source");
  await createFixtureSource(staleToolsSource);
  const staleToolsSchemaPath = join(staleToolsSource, "contracts", "tools-v2.schema.json");
  const staleToolsSchema = JSON.parse(await readFile(staleToolsSchemaPath, "utf8"));
  staleToolsSchema.$defs.fsTool.allOf[1].properties.operations.const = ["write"];
  await writeJson(staleToolsSchemaPath, staleToolsSchema);
  assert.throws(() => createReleasePackage({
    fixtureOnly: true,
    fixtureGeneratedReleaseMetadata,
    sourceRoot: staleToolsSource,
    outputRoot: join(root, "stale-tools-release"),
    sourceRevision,
    runtimeRevision: sourceRevision,
  }), /stale generated schema.*tools-v2/u);

  const staleBuildSchemaSource = join(root, "stale-build-schema-source");
  await createFixtureSource(staleBuildSchemaSource);
  const staleBuildSchemaPath = join(staleBuildSchemaSource, "contracts", "build-capabilities.schema.json");
  const staleBuildSchema = JSON.parse(await readFile(staleBuildSchemaPath, "utf8"));
  staleBuildSchema.properties.supportedOperations.properties.fs.const = ["write"];
  await writeJson(staleBuildSchemaPath, staleBuildSchema);
  assert.throws(() => createReleasePackage({
    fixtureOnly: true,
    fixtureGeneratedReleaseMetadata,
    sourceRoot: staleBuildSchemaSource,
    outputRoot: join(root, "stale-build-schema-release"),
    sourceRevision,
    runtimeRevision: sourceRevision,
  }), /stale generated schema.*build-capabilities/u);

  const staleDigestSource = join(root, "stale-digest-source");
  await createFixtureSource(staleDigestSource);
  assert.throws(() => createReleasePackage({
    fixtureOnly: true,
    fixtureGeneratedReleaseMetadata: (context) => {
      const metadata = fixtureGeneratedReleaseMetadata(context);
      return {
        ...metadata,
        buildCapabilities: {
          ...metadata.buildCapabilities,
          capabilityDigest: `sha256:${"c".repeat(64)}`,
        },
      };
    },
    sourceRoot: staleDigestSource,
    outputRoot: join(root, "stale-digest-release"),
    sourceRevision,
    runtimeRevision: sourceRevision,
  }), /capability digest/u);

  for (const [name, mutate, expected] of [
    ["fixture-provider", async (path) => {
      await writeFile(join(path, "dist", "v2", "test-fixture-provider.js"), "export const provider = 'fixture';\n");
    }, /test fixture provider/u],
    ["temporary-oauth-token", async (path) => {
      await writeJson(join(path, "config", "temp-oauth-token.json"), { temporaryOAuthClient: true, accessToken: "devspace-temporary-token-1234567890" });
    }, /temporary OAuth\/token residue/u],
    ["root-password", async (path) => {
      await writeJson(join(path, "config", "root-password.json"), { rootPassword: "not-for-release-1234567890" });
    }, /password\/raw secret residue|password material/u],
    ["unsupported-profile-placeholder", async (path) => {
      await writeFile(join(path, "dist", "v2", "multi-user-profile-placeholder.js"), "export const profile = 'MULTI_USER';\n");
    }, /unsupported profile placeholder/u],
    ["one-off-rollback", async (path) => {
      await writeFile(join(path, "scripts", "rollback-temp-phase1.sh"), "#!/bin/bash\nexit 0\n", { mode: 0o755 });
    }, /unmanifested one-off migration\/rollback script/u],
  ]) {
    const residueSource = join(root, `${name}-source`);
    await createFixtureSource(residueSource);
    await mutate(residueSource);
    assert.throws(() => createReleasePackage({
      fixtureOnly: true,
      fixtureGeneratedReleaseMetadata,
      sourceRoot: residueSource,
      outputRoot: join(root, `${name}-release`),
      sourceRevision,
      runtimeRevision: sourceRevision,
    }), expected);
  }

  const tamperedToolsRelease = join(root, "tampered-tools-release");
  await cp(release, tamperedToolsRelease, { recursive: true });
  const tamperedToolsPath = join(tamperedToolsRelease, "contracts", "tools-v2.schema.json");
  const tamperedTools = JSON.parse(await readFile(tamperedToolsPath, "utf8"));
  tamperedTools.$defs.processTool.allOf[1].properties.operations.const = ["wait"];
  await writeJson(tamperedToolsPath, tamperedTools);
  await repairReleaseDigests(tamperedToolsRelease);
  assert.throws(() => verifyUnattestedReleaseFixture(tamperedToolsRelease), /stale generated schema.*tools-v2/u);

  const tamperedBuildSchemaRelease = join(root, "tampered-build-schema-release");
  await cp(release, tamperedBuildSchemaRelease, { recursive: true });
  const tamperedBuildPath = join(tamperedBuildSchemaRelease, "contracts", "build-capabilities.schema.json");
  const tamperedBuild = JSON.parse(await readFile(tamperedBuildPath, "utf8"));
  tamperedBuild.properties.supportedOperations.properties.process.const = ["wait"];
  await writeJson(tamperedBuildPath, tamperedBuild);
  await repairReleaseDigests(tamperedBuildSchemaRelease);
  assert.throws(() => verifyUnattestedReleaseFixture(tamperedBuildSchemaRelease), /stale generated schema.*build-capabilities/u);

  const brokenSource = join(root, "broken-source");
  await createFixtureSource(brokenSource);
  await rm(join(brokenSource, "dist", "v2", "runtime-contract-identity.js"));
  assert.throws(() => createReleasePackage({
    fixtureOnly: true,
    fixtureGeneratedReleaseMetadata,
    sourceRoot: brokenSource,
    outputRoot: join(root, "broken-release"),
    sourceRevision,
    runtimeRevision: sourceRevision,
  }), /missing dependency-free contract identities/u);

  const ownerDirectory = join(root, "persistent-identity");
  const firstOwner = ensureOwnerInstanceId(ownerDirectory);
  const secondOwner = ensureOwnerInstanceId(ownerDirectory);
  assert.equal(firstOwner, secondOwner, "ownerInstanceId must survive release upgrades");
  assert.match(firstOwner, /^owner-[0-9a-f-]{36}$/u);
  if (process.platform !== "win32") {
    assert.equal((await stat(join(ownerDirectory, "owner-instance-id"))).mode & 0o777, 0o600);
  }
  const firstDeployPreflight = runParallelPreflight(release, ownerDirectory, join(root, "parallel-audit-1"));
  const secondDeployPreflight = runParallelPreflight(release, ownerDirectory, join(root, "parallel-audit-2"));
  assert.equal(firstDeployPreflight.status, 1);
  assert.equal(secondDeployPreflight.status, 1);
  assert.match(firstDeployPreflight.stderr, /--state-dir is required/u);
  assert.match(secondDeployPreflight.stderr, /--state-dir is required/u);

  const runtimeIdentity = {
    sourceRevision,
    runtimeRevision: sourceRevision,
    buildDigest: packageEvidence.buildDigest,
    schemaGeneration: packageEvidence.schemaGeneration,
    authorityContractGeneration: packageEvidence.authorityContractGeneration,
    configDigest: `sha256:${"d".repeat(64)}`,
    configSchemaIdentity: packageEvidence.configSchemaIdentity,
  };
  await assertCurrentFinalizationStoreIntegration(root);

  const distPath = join(release, "dist", "server.js");
  const original = await readFile(distPath);
  await writeFile(distPath, Buffer.concat([original, Buffer.from("// tampered\n")]));
  assert.throws(() => verifyUnattestedReleaseFixture(release), /checksum mismatch/u);
  await writeFile(distPath, original);
  assert.equal(verifyUnattestedReleaseFixture(release).status, "UNATTESTED_FIXTURE_ONLY");
} finally {
  await rm(root, { recursive: true, force: true });
}
assert.ok(currentFinalizationAssertionCount >= 8, "current keyed finalization integration assertions did not execute");
console.log(`Release package/finalization tests: PASS (current-finalization-assertions=${currentFinalizationAssertionCount})`);

async function assertCurrentFinalizationStoreIntegration(root) {
  const checked = () => { currentFinalizationAssertionCount += 1; };
  assert.equal(
    initializeFinalizationStore,
    initializeFinalizationStoreContract,
    "finalization-state must re-export the one dist-independent store initializer",
  );
  checked();
  assert.equal(
    readFinalizationStoreIdentity,
    readFinalizationStoreIdentityContract,
    "finalization-state must re-export the one dist-independent readonly identity reader",
  );
  checked();
  const storeContractSource = await readFile(
    join(repositoryRoot, "scripts", "lib", "finalization-store-contract.mjs"),
    "utf8",
  );
  assert.doesNotMatch(storeContractSource, /(?:^|["'])\.\.\/\.\.\/dist\//mu);
  checked();

  const stateRoot = join(root, "current-finalization-state");
  const controlRoot = join(root, "current-finalization-control");
  const managementStateDir = join(root, "current-finalization-management");
  await mkdir(stateRoot, { recursive: true, mode: 0o700 });
  await mkdir(controlRoot, { recursive: true, mode: 0o700 });
  await mkdir(managementStateDir, { recursive: true, mode: 0o700 });
  const storePath = join(stateRoot, "lifecycle.sqlite");
  const controlPath = join(controlRoot, "lifecycle-finalization-head.json");
  const key = loadOrCreateManagementAuthorizationKey({
    keyRef: "release-finalization-current-test",
    stateDir: managementStateDir,
  });

  const insecureStateRoot = join(root, "insecure-current-finalization-state");
  await mkdir(insecureStateRoot, { recursive: true, mode: 0o777 });
  await chmod(insecureStateRoot, 0o777);
  assert.throws(
    () => initializeFinalizationStoreContract({
      storePath: join(insecureStateRoot, "lifecycle.sqlite"),
      controlPath,
      key,
    }),
    /owner-only canonical real directory/u,
  );

  const approvedAt = "2026-08-20T00:00:00.000Z";
  const bootstrapAuthorization = createFinalizationStoreBootstrapAuthorization({
    storePath,
    controlPath,
    key,
    approvedAt,
  });
  const initialized = bootstrapFinalizationStore({
    storePath,
    controlPath,
    key,
    bootstrapAuthorization,
    now: () => approvedAt,
    requireDraft: true,
  });
  assert.equal(initialized.state, "DRAFT");
  checked();
  assert.equal(initialized.revision, 1);
  assert.equal(initialized.transactionId, null);
  assert.equal(initializeFinalizationStore({ storePath, controlPath, key, requireDraft: true }).state, "DRAFT");
  checked();
  assert.equal(readFinalizationStoreIdentity({ storePath, controlPath, key }).state, "DRAFT");
  checked();
  assert.equal((await stat(storePath)).mode & 0o777, 0o600);
  assert.equal((await stat(controlPath)).mode & 0o777, 0o600);
  checked();

  const wrongKeyState = join(root, "current-finalization-wrong-key");
  await mkdir(wrongKeyState, { recursive: true, mode: 0o700 });
  const wrongKey = loadOrCreateManagementAuthorizationKey({
    keyRef: "release-finalization-current-wrong-key",
    stateDir: wrongKeyState,
  });
  assert.throws(
    () => readFinalizationStoreIdentity({ storePath, controlPath, key: wrongKey }),
    /authentication|authorization|key|identity is invalid or foreign/iu,
  );
  checked();
}

async function assertStrictFinalizationTrustGates(root, release, runtimeIdentity, packageEvidence) {
  assert.equal(
    initializeFinalizationStore,
    initializeFinalizationStoreContract,
    "finalization-state must re-export the one dist-independent store initializer",
  );
  assert.equal(
    readFinalizationStoreIdentity,
    readFinalizationStoreIdentityContract,
    "finalization-state must re-export the one dist-independent readonly identity reader",
  );
  const storeContractSource = await readFile(
    join(repositoryRoot, "scripts", "lib", "finalization-store-contract.mjs"),
    "utf8",
  );
  assert.doesNotMatch(storeContractSource, /(?:^|["'])\.\.\/\.\.\/dist\//mu);
  const liveRoot = join(root, "strict-finalization-live");
  const audit = join(root, "strict-finalization-audit");
  const stateRoot = join(root, "strict-finalization-state");
  const storePath = join(stateRoot, "lifecycle.sqlite");
  const bin = join(liveRoot, "bin");
  await mkdir(audit, { recursive: true, mode: 0o700 });
  await mkdir(stateRoot, { recursive: true, mode: 0o700 });
  await mkdir(bin, { recursive: true, mode: 0o700 });
  const insecureStateRoot = join(root, "insecure-finalization-state");
  await mkdir(insecureStateRoot, { recursive: true, mode: 0o777 });
  await chmod(insecureStateRoot, 0o777);
  assert.throws(
    () => initializeFinalizationStoreContract({ storePath: join(insecureStateRoot, "lifecycle.sqlite") }),
    /owner-only canonical real directory/u,
  );

  const manifest = JSON.parse(await readFile(join(release, RELEASE_MANIFEST_NAME), "utf8"));
  const immutableIdentity = {
    runtimeIdentityDigest: fixtureDigest(runtimeIdentity),
    buildDigest: manifest.buildDigest,
    schemaGeneration: manifest.schemaGeneration,
    authorityContractGeneration: manifest.authorityContractGeneration,
    buildCapabilityManifestDigest: manifest.buildCapabilities.capabilityDigest,
    generatedSchemaDigest: treeEvidence(release, [
      "config.schema.json",
      "config/config.schema.json",
      "contracts/tools-v2.schema.json",
      "contracts/build-capabilities.schema.json",
    ]).sha256,
    packageSha256: manifest.payloadDigest,
    migrationManifestDigest: manifest.migrationManifestDigest,
  };
  assert.equal(immutableIdentity.buildDigest, packageEvidence.buildDigest);

  const managementStateDir = join(liveRoot, "management-state");
  await mkdir(managementStateDir, { recursive: true, mode: 0o700 });
  const managementKey = loadOrCreateManagementAuthorizationKey({
    keyRef: "finalization-test",
    stateDir: managementStateDir,
  });
  const processScript = join(release, "dist", "server.js");
  const proof = finalReadbackProof(runtimeIdentity, immutableIdentity, managementKey, {
    cwd: release,
    script: processScript,
  });
  const finalReadbackNowMs = proof.postActivationHostCanaryReceipt.payload.observedAtMs + 10_000;

  const oauthPath = join(liveRoot, "oauth.sqlite");
  const authorityPath = join(liveRoot, "authority.sqlite");
  const journalPath = join(liveRoot, "connector-journal.sqlite");
  const postPath = join(liveRoot, "post-activation-host-receipt.json");
  createLiveOAuthFixture(oauthPath, proof);
  createLiveAuthorityFixture(
    authorityPath,
    proof.activationAuthorityReadback,
    proof.postMutationAuthorityReadback,
    `action_${proof.postMutationAuthorityReadback.actionFingerprint}`,
    "task-instance-post-finalization",
  );
  createLiveJournalFixture(journalPath, proof);

  const processDefinitionPath = join(liveRoot, "ecosystem.production.json");
  const runtimeEnvironmentPath = join(liveRoot, "production.env");
  const routeDefinitionPath = join(liveRoot, "route.production.json");
  const targetRoutePath = join(liveRoot, "targets.production.json");
  const contextsPath = join(liveRoot, "contexts.json");
  const paginationKeyPath = join(liveRoot, "pagination.key");
  const savedStatePath = join(liveRoot, "dump.pm2");
  const expectedPm2Entry = {
    name: proof.pm2Runtime.name,
    pid: proof.pm2Runtime.pid,
    pm2_env: {
      name: proof.pm2Runtime.name,
      status: "online",
      pm_cwd: release,
      pm_exec_path: processScript,
    },
  };
  await writeOwnerJson(processDefinitionPath, { processes: [expectedPm2Entry] });
  await writeOwnerJson(savedStatePath, [expectedPm2Entry]);
  await writeOwnerJson(routeDefinitionPath, { routeKey: "https://broker.example.test", target: "127.0.0.1:43110" });
  await writeOwnerJson(targetRoutePath, { generation: runtimeIdentity.configDigest });
  await writeOwnerJson(contextsPath, { contexts: [] });
  await writeFile(runtimeEnvironmentPath, "DEVSPACE_DEPLOYMENT_MODE=production\n", { mode: 0o600 });
  await writeFile(paginationKeyPath, `${"p".repeat(43)}\n`, { mode: 0o600 });

  const processMetadata = join(liveRoot, "process-metadata");
  const processOutput = join(liveRoot, "process-output");
  const artifactCas = join(liveRoot, "artifact-cas");
  const artifactQuarantine = join(liveRoot, "artifact-quarantine");
  for (const directory of [processMetadata, processOutput, artifactCas, artifactQuarantine]) {
    await mkdir(directory, { recursive: true, mode: 0o700 });
  }
  await writeFile(join(processMetadata, "z-order.txt"), "code-unit-z\n", { mode: 0o600 });
  await writeFile(join(processMetadata, "ä-order.txt"), "code-unit-non-ascii\n", { mode: 0o600 });
  const filesystemSyncPath = join(liveRoot, "filesystem-sync.sqlite");
  const artifactCatalogPath = join(liveRoot, "artifact-catalog.sqlite");
  createEmptySqlite(filesystemSyncPath, "filesystem_sync_plans");
  createEmptySqlite(artifactCatalogPath, "artifacts");

  const initialized = initializeFinalizationStoreContract({ storePath, now: () => "2026-08-20T00:00:00.000Z" });
  assert.equal(initialized.state, "DRAFT");
  const beforeInitializeReopen = await stat(storePath);
  const beforeInitializeReopenSha256 = fileSha256(storePath);
  assert.equal(initializeFinalizationStore({ storePath }).state, "DRAFT", "DRAFT store reopen must be idempotent");
  const afterInitializeReopen = await stat(storePath);
  assert.equal(fileSha256(storePath), beforeInitializeReopenSha256, "idempotent initialize must not modify lifecycle.sqlite bytes");
  assert.equal(afterInitializeReopen.mtimeMs, beforeInitializeReopen.mtimeMs, "idempotent initialize must not modify lifecycle.sqlite mtime");
  const beforeRead = await stat(storePath);
  const beforeReadSha256 = fileSha256(storePath);
  assert.equal(readFinalizationStoreIdentityContract({ storePath }).state, "DRAFT");
  const afterRead = await stat(storePath);
  assert.equal(fileSha256(storePath), beforeReadSha256, "identity readback must not modify lifecycle.sqlite bytes");
  assert.equal(afterRead.mtimeMs, beforeRead.mtimeMs, "identity readback must remain side-effect-free");
  const transactionId = "finalization-transaction-11111111-1111-4111-8111-111111111111";
  const upgradeRequestDigest = `sha256:${"e".repeat(64)}`;
  const snapshotRoot = join(root, "strict-finalization-snapshot");
  const snapshotEntries = [
    { id: "oauth-main-and-connector-state", kind: "sqlite", path: oauthPath, required: true },
    { id: "authority-store", kind: "sqlite", path: authorityPath, required: true },
    { id: "contexts-store", kind: "file", path: contextsPath, required: true },
    { id: "process-metadata", kind: "directory", path: processMetadata, required: true },
    { id: "process-output", kind: "directory", path: processOutput, required: true },
    { id: "filesystem-sync", kind: "sqlite", path: filesystemSyncPath, required: true },
    { id: "artifact-catalog", kind: "sqlite", path: artifactCatalogPath, required: true },
    { id: "artifact-cas", kind: "directory", path: artifactCas, required: true },
    { id: "artifact-quarantine", kind: "directory", path: artifactQuarantine, required: true },
    { id: "pagination-current-signing-key", kind: "file", path: paginationKeyPath, required: true },
    { id: "lifecycle-finalization-store", kind: "sqlite", path: initialized.path, required: true },
    { id: "runtime-environment", kind: "file", path: runtimeEnvironmentPath, required: true },
    { id: "process-manager-definition", kind: "file", path: processDefinitionPath, required: true },
    { id: "public-route", kind: "file", path: routeDefinitionPath, required: true },
    { id: "target-route-generation-config", kind: "file", path: targetRoutePath, required: true },
  ];
  const snapshot = await captureSnapshotGroup({
    snapshotRoot,
    now: () => "2026-08-20T00:00:10.000Z",
    barrier: {
      kind: "PM2_STOPPED",
      establishedAt: "2026-08-20T00:00:10.000Z",
      transactionId,
      upgradeRequestDigest,
      candidateIdentityDigest: fixtureDigest(immutableIdentity),
    },
    entries: snapshotEntries,
  });
  const funnelInventory = { schemaVersion: 1, routes: [{ key: "https://broker.example.test", target: "127.0.0.1:43110" }] };
  const managementIdentity = { schemaVersion: 1, state: "PRIVATE", listener: "127.0.0.1:43111" };
  const cleanupTarget = join(liveRoot, "parallel-temporary.env");
  await writeFile(cleanupTarget, "temporary\n", { mode: 0o600 });
  const productionSources = {
    schemaVersion: 1,
    managementAuthorization: { keyRef: managementKey.path, stateDir: managementStateDir, keyId: managementKey.keyId },
    processManager: {
      definitionPath: processDefinitionPath,
      definitionSha256: `sha256:${fileSha256(processDefinitionPath)}`,
      canonicalProcessName: proof.pm2Runtime.name,
      expectedProcesses: [{ name: proof.pm2Runtime.name, status: "online", cwd: release, script: processScript }],
      savedStatePath,
    },
    endpoints: {
      runtimeIdentityUrl: "http://127.0.0.1:43110/identity",
      routeIdentityUrl: "http://127.0.0.1:43110/route",
      managementIdentityUrl: "http://127.0.0.1:43111/identity",
      managementIdentityDigest: fixtureDigest(managementIdentity),
    },
    listeners: {
      scopePorts: [43110, 43111],
      expected: [
        { command: "node", address: "127.0.0.1", port: 43110 },
        { command: "node", address: "127.0.0.1", port: 43111 },
      ],
    },
    route: {
      definitionPath: routeDefinitionPath,
      definitionSha256: `sha256:${fileSha256(routeDefinitionPath)}`,
      targetGenerationConfigPath: targetRoutePath,
      targetGenerationConfigSha256: `sha256:${fileSha256(targetRoutePath)}`,
      publicRouteKey: "https://broker.example.test",
      expectedFunnelInventoryDigest: fixtureDigest(funnelInventory),
    },
    runtimeEnvironmentPath,
    stores: {
      oauth: { path: oauthPath, ...sqliteFixtureIdentity(oauthPath) },
      authority: { path: authorityPath, ...sqliteFixtureIdentity(authorityPath) },
      connectorJournal: { path: journalPath, ...sqliteFixtureIdentity(journalPath) },
      postActivationReceipt: { path: postPath },
    },
    activation: {
      receiptId: proof.connectorActivationReceipt.receiptId,
      approvalId: proof.connectorJournalReadback.approvalId,
      canonicalName: proof.activeConnector.canonicalName,
      principalKeyFingerprint: proof.postActivationHostCanaryReceipt.payload.principalKeyFingerprint,
      managementNonce: proof.postActivationHostCanaryReceipt.payload.managementNonce,
      managementCorrelationId: proof.postActivationHostCanaryReceipt.payload.managementCorrelationId,
      productionActivationPrecheckDigest: proof.postActivationHostCanaryReceipt.payload.precheckDigest,
      tokenFamilyIdDigest: proof.postActivationHostCanaryReceipt.payload.tokenFamilyIdDigest,
      tokenFamilyBindingId: proof.postActivationHostCanaryReceipt.payload.tokenFamilyBindingId,
      previousBindingState: proof.postActivationHostCanaryReceipt.payload.previousBindingState,
      productionIdentity: proof.postActivationHostCanaryReceipt.payload.productionIdentity,
      productionEnvironmentIdentityDigest:
        proof.postActivationHostCanaryReceipt.payload.productionEnvironmentIdentityDigest,
      productionRouteIdentityDigest: proof.postActivationHostCanaryReceipt.payload.productionRouteIdentityDigest,
    },
    residue: { paths: [cleanupTarget] },
  };
  const gateResults = [
    "G00 PROFILE", "G01 SOURCE", "G02 STATIC", "G03 UNIT", "G04 PROTOCOL", "G05 FUNCTIONAL",
    "G06 SECURITY", "G07 DURABILITY", "G08 LOAD", "G09 PACKAGE", "G10 STAGING", "G11 HOST",
    "G12 CONNECTOR", "G13 CUTOVER", "G16 CLEANUP", "G17 FINALIZATION",
  ].map((gate, index) => (
    gate === "G16 CLEANUP" || gate === "G17 FINALIZATION"
      ? {
        profile: "BASE_SINGLE_OWNER",
        gate,
        applicability: "REQUIRED",
        result: "NOT_RUN",
      }
      : {
        profile: "BASE_SINGLE_OWNER",
        gate,
        applicability: "REQUIRED",
        result: "PASS",
        evidenceDigest: `sha256:${index.toString(16).padStart(2, "0").repeat(32)}`,
      }
  ));
  const baseCapabilities = [
    "source-runtime-build-profile-identity", "one-production-process-route", "health-ready-doctor",
    "unauthenticated-mcp-401", "public-management-blocked", "exact-eight-tools", "canonical-active-one",
    "fresh-host-discovery", "cross-session-harmless-mutation", "local-target-read-write-exec-process-mcp-artifact",
    "self-restart-transaction", "all-store-consistent-snapshot", "no-residue",
  ].map((capability, index) => (
    capability === "no-residue"
      ? {
        profile: "BASE_SINGLE_OWNER",
        capability,
        applicability: "REQUIRED",
        result: "NOT_RUN",
      }
      : {
        profile: "BASE_SINGLE_OWNER",
        capability,
        applicability: "REQUIRED",
        result: "PASS",
        evidenceDigest: `sha256:${(index + 32).toString(16).padStart(2, "0").repeat(32)}`,
      }
  ));
  const prepare = {
    schemaVersion: 1,
    status: "PASS",
    phase: "production-reconnect",
    transactionId,
    upgradeRequestDigest,
    releasePackage: release,
    runtimeIdentity,
    immutableIdentity,
    snapshotGroup: {
      manifestPath: snapshot.manifestPath,
      manifestSha256: `sha256:${fileSha256(snapshot.manifestPath)}`,
      manifest: snapshot.manifest,
    },
    profileApplicability: [
      { profile: "BASE_SINGLE_OWNER", applicability: "REQUIRED" },
      { profile: "MULTI_USER", applicability: "NOT_APPLICABLE" },
      { profile: "SIDECAR_AUTHORITY", applicability: "NOT_APPLICABLE" },
      { profile: "HOST_ATTESTED", applicability: "NOT_APPLICABLE" },
      { profile: "GUI_CAPTURE", applicability: "NOT_APPLICABLE" },
    ],
    gateResults,
    capabilities: [...baseCapabilities, ...[
      "MULTI_USER", "SIDECAR_AUTHORITY", "HOST_ATTESTED", "GUI_CAPTURE",
    ].map((profile) => ({
      profile,
      capability: `${profile.toLowerCase()}-profile`,
      applicability: "NOT_APPLICABLE",
      result: "NOT_APPLICABLE",
    }))],
    productionSources,
    inventories: {
      processes: [], listeners: [], routes: [],
      oauth: [{ familyId: "family-old", status: "ACTIVE", database: oauthPath }],
      connectors: [{ bindingId: "binding-old", canonicalName: "myDevSpace", state: "ACTIVE" }],
      temporaryArtifacts: [{ path: cleanupTarget }],
    },
    expectedCanary: { toolNames: ["target", "context", "fs", "exec", "process", "mcp", "artifact", "gui"] },
    canonicalConnector: { name: "myDevSpace", bindingId: "binding-old", installationEpoch: 1 },
    destructivePlan: [{
      id: "cleanup-temporary-artifact",
      destructive: true,
      operation: "remove-file",
      target: cleanupTarget,
    }],
    preimages: [],
  };

  const symlinkAuditRoot = join(root, "symlink-finalization-audit");
  const symlinkAuditTarget = join(root, "symlink-finalization-target");
  await mkdir(symlinkAuditRoot, { recursive: true, mode: 0o700 });
  await mkdir(symlinkAuditTarget, { recursive: true, mode: 0o700 });
  await symlink(symlinkAuditTarget, join(symlinkAuditRoot, "finalization"));
  assert.throws(
    () => prepareFinalizationTransaction({
      auditRoot: symlinkAuditRoot,
      storePath,
      evidence: prepare,
      now: () => "2026-08-20T00:00:20.000Z",
    }),
    /owner-only canonical real directory/u,
  );

  const overlappingStorePath = join(audit, "lifecycle.sqlite");
  initializeFinalizationStore({ storePath: overlappingStorePath });
  assert.throws(
    () => prepareFinalizationTransaction({ auditRoot: audit, storePath: overlappingStorePath, evidence: prepare }),
    /outside non-restored audit\/control root/u,
  );

  for (const result of ["NOT_RUN", "LIMITED_PASS", "FAIL", "UNKNOWN"]) {
    const invalid = structuredClone(prepare);
    invalid.gateResults[0].result = result;
    assert.throws(() => prepareFinalizationTransaction({ auditRoot: audit, storePath, evidence: invalid, now: () => "2026-08-20T00:00:20.000Z" }), /pre-cutover gate/u);
  }
  for (const gate of ["G16 CLEANUP", "G17 FINALIZATION"]) {
    const invalid = structuredClone(prepare);
    const entry = invalid.gateResults.find((value) => value.gate === gate);
    entry.result = "PASS";
    entry.evidenceDigest = `sha256:${"f".repeat(64)}`;
    assert.throws(
      () => prepareFinalizationTransaction({ auditRoot: audit, storePath, evidence: invalid, now: () => "2026-08-20T00:00:20.000Z" }),
      /deferred prepare gate/u,
      `${gate} cannot be caller-authored PASS before cleanup/finalization`,
    );
  }
  const prematureNoResidue = structuredClone(prepare);
  const noResidue = prematureNoResidue.capabilities.find((entry) => entry.capability === "no-residue");
  noResidue.result = "PASS";
  noResidue.evidenceDigest = `sha256:${"e".repeat(64)}`;
  assert.throws(
    () => prepareFinalizationTransaction({ auditRoot: audit, storePath, evidence: prematureNoResidue, now: () => "2026-08-20T00:00:20.000Z" }),
    /deferred prepare capability no-residue/u,
  );
  for (const mutate of [
    (value) => value.gateResults.pop(),
    (value) => { value.gateResults[1] = structuredClone(value.gateResults[0]); },
    (value) => { value.profileApplicability[1].applicability = "REQUIRED"; },
    (value) => { value.capabilities[0].result = "NOT_RUN"; },
    (value) => { value.capabilities.splice(0, 1); },
    (value) => { value.capabilities.pop(); },
    (value) => { value.capabilities[1] = structuredClone(value.capabilities[0]); },
    (value) => {
      value.capabilities.at(-1).applicability = "CONDITIONAL";
      value.capabilities.at(-1).result = "PASS";
      value.capabilities.at(-1).evidenceDigest = `sha256:${"f".repeat(64)}`;
    },
    (value) => { delete value.snapshotGroup; },
  ]) {
    const invalid = structuredClone(prepare);
    mutate(invalid);
    assert.throws(() => prepareFinalizationTransaction({ auditRoot: audit, storePath, evidence: invalid, now: () => "2026-08-20T00:00:20.000Z" }));
  }
  for (const key of Object.keys(immutableIdentity)) {
    const invalid = structuredClone(prepare);
    invalid.immutableIdentity[key] = `sha256:${"0".repeat(64)}`;
    assert.throws(() => prepareFinalizationTransaction({ auditRoot: audit, storePath, evidence: invalid, now: () => "2026-08-20T00:00:20.000Z" }), /immutable production identity/u);
  }
  const stalePrepare = structuredClone(prepare);
  stalePrepare.snapshotGroup = await snapshotBindingVariant(root, prepare.snapshotGroup, (manifestValue) => {
    manifestValue.capturedAt = "2026-08-19T00:00:00.000Z";
    manifestValue.barrier.establishedAt = manifestValue.capturedAt;
  });
  assert.throws(() => prepareFinalizationTransaction({ auditRoot: audit, storePath, evidence: stalePrepare, now: () => "2026-08-20T00:00:20.000Z" }), /stale/u);

  const alternateOauth = join(liveRoot, "alternate-oauth.sqlite");
  await cp(oauthPath, alternateOauth);
  await chmod(alternateOauth, 0o600);
  const alternateStorePrepare = structuredClone(prepare);
  alternateStorePrepare.productionSources.stores.oauth = {
    path: alternateOauth,
    ...sqliteFixtureIdentity(alternateOauth),
  };
  assert.throws(() => prepareFinalizationTransaction({ auditRoot: audit, storePath, evidence: alternateStorePrepare, now: () => "2026-08-20T00:00:20.000Z" }), /snapshotted stores/u);
  const alternateRoute = join(liveRoot, "alternate-route.json");
  await writeOwnerJson(alternateRoute, { routeKey: "alternate" });
  const alternateRoutePrepare = structuredClone(prepare);
  alternateRoutePrepare.productionSources.route.definitionPath = alternateRoute;
  alternateRoutePrepare.productionSources.route.definitionSha256 = `sha256:${fileSha256(alternateRoute)}`;
  assert.throws(() => prepareFinalizationTransaction({ auditRoot: audit, storePath, evidence: alternateRoutePrepare, now: () => "2026-08-20T00:00:20.000Z" }), /snapshotted canonical route/u);
  const alternateTargetRoute = join(liveRoot, "alternate-target-route.json");
  await writeOwnerJson(alternateTargetRoute, { generation: `sha256:${"0".repeat(64)}` });
  const alternateTargetPrepare = structuredClone(prepare);
  alternateTargetPrepare.productionSources.route.targetGenerationConfigPath = alternateTargetRoute;
  alternateTargetPrepare.productionSources.route.targetGenerationConfigSha256 =
    `sha256:${fileSha256(alternateTargetRoute)}`;
  assert.throws(
    () => prepareFinalizationTransaction({ auditRoot: audit, storePath, evidence: alternateTargetPrepare, now: () => "2026-08-20T00:00:20.000Z" }),
    /target\/route generation config/iu,
  );
  const symlinkRoute = join(liveRoot, "symlink-route.json");
  await symlink(routeDefinitionPath, symlinkRoute);
  const symlinkPrepare = structuredClone(prepare);
  symlinkPrepare.productionSources.route.definitionPath = symlinkRoute;
  assert.throws(() => prepareFinalizationTransaction({ auditRoot: audit, storePath, evidence: symlinkPrepare, now: () => "2026-08-20T00:00:20.000Z" }), /canonical real file/u);
  const alternateEndpointPrepare = structuredClone(prepare);
  alternateEndpointPrepare.productionSources.endpoints.managementIdentityUrl = "http://127.0.0.1:43112/identity";
  assert.throws(
    () => prepareFinalizationTransaction({ auditRoot: audit, storePath, evidence: alternateEndpointPrepare, now: () => "2026-08-20T00:00:20.000Z" }),
    /endpoint ports/u,
  );

  await assertFinalizationStoreCorruption(root);
  const prepared = prepareFinalizationTransaction({
    auditRoot: audit,
    storePath,
    evidence: prepare,
    now: () => "2026-08-20T00:00:20.000Z",
  });
  assert.equal(prepared.status, "PREPARED");
  assert.equal(readFinalizationStoreIdentity({ storePath }).state, "PREPARED");
  assert.deepEqual(prepared.bindings, {
    transactionId,
    snapshotGroupDigest: prepare.snapshotGroup.manifest.groupDigest,
    immutableIdentityDigest: fixtureDigest(immutableIdentity),
    productionSourcesDigest: fixtureDigest(productionSources),
    gateResultsDigest: fixtureDigest(gateResults),
    capabilitiesDigest: fixtureDigest(prepare.capabilities),
    profileApplicabilityDigest: fixtureDigest(prepare.profileApplicability),
    activationReceiptId: productionSources.activation.receiptId,
    activationApprovalId: productionSources.activation.approvalId,
    previousBindingId: "binding-old",
  });
  assert.throws(
    () => initializeFinalizationStore({ storePath, requireDraft: true }),
    /not DRAFT/u,
    "requireDraft initialize cannot bless an existing prepared lifecycle",
  );
  await assertPreparedFinalizationStoreCorruption(root, storePath);
  await assertFinalizationErrorTransitions({
    root,
    prepare,
    snapshotEntries,
    immutableIdentity,
  });
  assert.equal(prepareFinalizationTransaction({
    auditRoot: audit,
    storePath,
    evidence: prepare,
    now: () => "2026-08-20T00:00:21.000Z",
  }).resumed, true, "PREPARED reopen must reconstruct from SQLite and be idempotent");
  const prepareRecord = JSON.parse(await readFile(prepared.path, "utf8"));
  const seal = strictSealEvidence(prepareRecord);
  const sealPath = join(liveRoot, "seal-evidence.json");
  await writeOwnerJson(sealPath, seal);
  const canonicalDriver = join(repositoryRoot, "scripts", "finalization-live-driver.mjs");
  const snapshottedRuntimeEnvironment = prepare.snapshotGroup.manifest.entries
    .find((entry) => entry.id === "runtime-environment").snapshotPath;
  const snapshotPreimage = await readFile(snapshottedRuntimeEnvironment);
  await writeFile(snapshottedRuntimeEnvironment, Buffer.concat([snapshotPreimage, Buffer.from("tampered\n")]));
  assert.throws(() => sealFinalization({
    auditRoot: audit,
    storePath,
    evidencePath: sealPath,
    driverPath: canonicalDriver,
  }), /Snapshot artifact digest changed/u);
  await writeFile(snapshottedRuntimeEnvironment, snapshotPreimage);
  assert.throws(() => sealFinalization({
    auditRoot: audit,
    storePath,
    evidencePath: sealPath,
    driverPath: canonicalDriver,
  }), /not prepared for this seal/u);
  assert.throws(() => transitionFinalizationLifecycle({
    storePath,
    transactionId,
    expectedState: "PREPARED",
    nextState: "ACTIVATION_PENDING",
    evidence: { kind: "SKIPPED_STATE" },
  }), /one exact forward step/u);
  assert.throws(() => transitionFinalizationLifecycle({
    storePath,
    transactionId,
    expectedState: "PREPARED",
    nextState: "PROFILE_GATES_EVALUATED",
    evidence: {
      kind: "PROFILE_GATES_EVALUATED",
      gateResultsDigest: prepared.bindings.gateResultsDigest,
      capabilitiesDigest: prepared.bindings.capabilitiesDigest,
      profileApplicabilityDigest: prepared.bindings.profileApplicabilityDigest,
    },
    now: () => "2026-08-20T00:00:19.000Z",
  }), /timestamp cannot regress/u);

  const transitions = [
    ["PREPARED", "PROFILE_GATES_EVALUATED", {
      kind: "PROFILE_GATES_EVALUATED",
      gateResultsDigest: fixtureDigest(gateResults),
      capabilitiesDigest: fixtureDigest(prepare.capabilities),
      profileApplicabilityDigest: fixtureDigest(prepare.profileApplicability),
    }],
    ["PROFILE_GATES_EVALUATED", "ACTIVATION_PENDING", {
      kind: "ACTIVATION_PENDING",
      receiptId: prepared.bindings.activationReceiptId,
      approvalId: prepared.bindings.activationApprovalId,
      productionSourcesDigest: prepared.bindings.productionSourcesDigest,
    }],
    ["ACTIVATION_PENDING", "POST_ACTIVATION_VERIFIED", {
      kind: "POST_ACTIVATION_VERIFIED",
      receiptId: prepared.bindings.activationReceiptId,
      postActivationEvidenceDigest: proof.postActivationHostCanaryReceipt.payloadDigest,
    }],
    ["POST_ACTIVATION_VERIFIED", "DRAINING", {
      kind: "DRAINING",
      receiptId: prepared.bindings.activationReceiptId,
      previousBindingId: prepared.bindings.previousBindingId,
    }],
  ];
  for (const [expectedState, nextState, evidence] of transitions) {
    const result = transitionFinalizationLifecycle({
      storePath,
      transactionId,
      expectedState,
      nextState,
      evidence,
      now: () => new Date(
        proof.postActivationHostCanaryReceipt.payload.observedAtMs + 2,
      ).toISOString(),
    });
    assert.equal(result.status, nextState);
    const replay = transitionFinalizationLifecycle({ storePath, transactionId, expectedState, nextState, evidence });
    assert.equal(replay.resumed, true, `${nextState} exact replay must be idempotent`);
  }
  assert.throws(() => transitionFinalizationLifecycle({
    storePath,
    transactionId,
    expectedState: "PREPARED",
    nextState: "DRAINING",
    evidence: transitions.at(-1)[2],
  }), /one exact forward step/u, "replay cannot bless a skipped or false predecessor state");
  assert.throws(() => transitionFinalizationLifecycle({
    storePath,
    transactionId,
    expectedState: "PREPARED",
    nextState: "PROFILE_GATES_EVALUATED",
    evidence: transitions[0][2],
  }), /expected PREPARED, observed DRAINING/u);
  assert.throws(() => transitionFinalizationLifecycle({
    storePath,
    transactionId,
    expectedState: "DRAINING",
    nextState: "SEALED",
    evidence: { kind: "FORGED_CALLER_SEAL", finalDigest: `sha256:${"f".repeat(64)}` },
  }), /canonical in-process final readback authority/u);

  await writeOwnerJson(postPath, proof.postActivationHostCanaryReceipt);
  assert.equal(prepareFinalizationTransaction({
    auditRoot: audit,
    storePath,
    evidence: prepare,
    now: () => "2026-08-21T00:00:22.000Z",
  }).resumed, true, "PREPARED resume must tolerate the later genuine receipt at its prebound path");
  const mockPaths = await writeFinalizationCommandMocks({
    bin,
    proof,
    funnelInventory,
    managementIdentity,
  });
  const testPath = `${bin}:${nodeDirectory}:${process.env.PATH ?? ""}`;
  const alternateDriver = join(root, "fixture-driver.mjs");
  await writeFile(alternateDriver, fixtureDriverSource(), { mode: 0o700 });
  assert.throws(() => sealFinalization({
    auditRoot: audit,
    storePath,
    evidencePath: sealPath,
    driverPath: alternateDriver,
  }), /canonical live driver realpath/u);

  const callerAuthoredSeal = { ...seal, activeConnector: proof.activeConnector };
  const callerSealPath = join(liveRoot, "caller-seal.json");
  await writeOwnerJson(callerSealPath, callerAuthoredSeal);
  assert.throws(() => sealFinalization({
    auditRoot: audit,
    storePath,
    evidencePath: callerSealPath,
    driverPath: canonicalDriver,
  }), /Caller-authored activeConnector/u);
  const callerPostPath = join(liveRoot, "caller-post-seal.json");
  await writeOwnerJson(callerPostPath, { ...seal, postActivationHostCanaryReceipt: proof.postActivationHostCanaryReceipt });
  assert.throws(() => sealFinalization({
    auditRoot: audit,
    storePath,
    evidencePath: callerPostPath,
    driverPath: canonicalDriver,
  }), /Caller-authored postActivationHostCanaryReceipt/u);
  const unsupportedSealPath = join(liveRoot, "unsupported-seal.json");
  await writeOwnerJson(unsupportedSealPath, { ...seal, assurance: "HOST_ATTESTED_AUTHORITY" });
  assert.throws(() => sealFinalization({
    auditRoot: audit,
    storePath,
    evidencePath: unsupportedSealPath,
    driverPath: canonicalDriver,
  }), /exactly COOPERATIVE_AUTHORITY/u);
  const extraCallerSealPath = join(liveRoot, "extra-caller-seal.json");
  await writeOwnerJson(extraCallerSealPath, { ...seal, syntheticPass: true });
  assert.throws(() => sealFinalization({
    auditRoot: audit,
    storePath,
    evidencePath: extraCallerSealPath,
    driverPath: canonicalDriver,
  }), /unsupported caller-authored field/u);

  const previousPath = process.env.PATH;
  process.env.PATH = testPath;
  const finalizationEvidenceDirectory = join(audit, "finalization", "evidence");
  await chmod(finalizationEvidenceDirectory, 0o500);
  try {
    assert.throws(() => sealFinalization({
      auditRoot: audit,
      storePath,
      evidencePath: sealPath,
      driverPath: canonicalDriver,
    }), (error) => error?.code === "EACCES" || /EACCES|permission denied/u.test(String(error)));
  } finally {
    await chmod(finalizationEvidenceDirectory, 0o700);
  }
  await assert.rejects(readFile(cleanupTarget, "utf8"), /ENOENT/u);
  assert.equal(readFinalizationStoreIdentity({ storePath }).state, "SEALED");
  const cleanupReceiptPath = join(audit, "finalization", "receipts", "cleanup-temporary-artifact.json");
  const cleanupReceiptBeforeResume = await readFile(cleanupReceiptPath, "utf8");
  const cleanupReceipt = JSON.parse(cleanupReceiptBeforeResume);
  assert.equal(cleanupReceipt.state, "PASS");
  assert.equal(cleanupReceipt.attempts, 1);
  assert.equal(cleanupReceipt.completion, "APPLIED_AND_READ_BACK");

  const context = {
    schemaVersion: 1,
    auditRoot: audit,
    finalizationRoot: join(audit, "finalization"),
    preparePath: prepared.path,
    sealEvidencePath: sealPath,
    releasePackage: release,
    runtimeIdentity,
    canonicalDriverPath: canonicalDriver,
    prepareDigest: fixtureDigest(prepareRecord),
    productionSourcesDigest: fixtureDigest(prepareRecord.productionSources),
  };
  const currentFinalReadback = (nowMs = finalReadbackNowMs) => runCanonicalFinalReadback({
    context,
    prepare: prepareRecord,
    stages: [],
    nowMs,
  });
  try {
    const trusted = currentFinalReadback();
    assert.throws(
      () => currentFinalReadback(proof.postActivationHostCanaryReceipt.payload.expiresAtMs),
      /not currently valid/u,
      "final seal cannot reuse an expired signed POST Host receipt",
    );
    assert.equal(validateFinalReadbackEvidence(prepareRecord, seal, trusted).activeConnector.bindingId, "binding-current");
    assert.throws(() => validateFinalReadbackEvidence(prepareRecord, seal, {
      ...trusted,
      verifiedPostActivationHostCanary: { ...trusted.verifiedPostActivationHostCanary },
    }), /not verified signed evidence/u, "plain caller-cloned fields must not recreate the private verifier brand");

    const serializable = { ...trusted };
    delete serializable.verifiedPostActivationHostCanary;
    const requiredPaths = requiredTrustedFinalReadbackPaths();
    currentFinalizationAssertionCount += requiredPaths.length;
    assert.ok(requiredPaths.length >= 230, `missing-path matrix regressed to ${requiredPaths.length}`);
    for (const path of requiredPaths) {
      assert.notEqual(readPath(serializable, path), undefined, `matrix path must exist before deletion: ${path}`);
      const incomplete = structuredClone(serializable);
      incomplete.verifiedPostActivationHostCanary = trusted.verifiedPostActivationHostCanary;
      deletePath(incomplete, path);
      assert.throws(
        () => validateFinalReadbackEvidence(prepareRecord, seal, incomplete),
        `trusted final readback must reject missing ${path}`,
      );
    }

    for (const invalidEnvelope of [
      { ...proof.postActivationHostCanaryReceipt, signature: "A".repeat(43) },
      { ...proof.postActivationHostCanaryReceipt, signature: `${proof.postActivationHostCanaryReceipt.signature}=` },
      {
        ...proof.postActivationHostCanaryReceipt,
        payload: { ...proof.postActivationHostCanaryReceipt.payload, observedAtMs: proof.postActivationHostCanaryReceipt.payload.observedAtMs + 1 },
      },
    ]) {
      await writeOwnerJson(postPath, invalidEnvelope);
      assert.throws(() => currentFinalReadback());
    }
    const wrongKeyDir = join(liveRoot, "wrong-key-state");
    await mkdir(wrongKeyDir, { recursive: true, mode: 0o700 });
    const wrongKey = loadOrCreateManagementAuthorizationKey({ keyRef: "wrong", stateDir: wrongKeyDir });
    await writeOwnerJson(postPath, signConnectorActivationPostActivationHostCanary(
      structuredClone(proof.postActivationHostCanaryReceipt.payload),
      wrongKey,
      proof.postActivationHostCanaryReceipt.payload.observedAtMs,
    ));
    assert.throws(() => currentFinalReadback(), /signed evidence|identity|signature/u);
    await writeOwnerJson(postPath, proof.postActivationHostCanaryReceipt);

    await writeFile(mockPaths.pm2, mockPm2Source(proof, [{
      name: "devspace-parallel-extra",
      pid: 54321,
      pm2_env: { status: "online", pm_cwd: release, pm_exec_path: processScript },
    }]), { mode: 0o700 });
    assert.throws(() => currentFinalReadback(), /PM2 inventory/u);
    await writeFile(mockPaths.pm2, mockPm2Source(proof), { mode: 0o700 });
    await writeFile(mockPaths.lsof, mockLsofSource(true), { mode: 0o700 });
    assert.throws(() => currentFinalReadback(), /extra listener/u);
    await writeFile(mockPaths.lsof, mockLsofSource(false), { mode: 0o700 });
    await writeOwnerJson(cleanupTarget, { residue: true });
    assert.throws(() => currentFinalReadback(), /residue remains/u);
    await rm(cleanupTarget);
    await writeOwnerJson(targetRoutePath, { generation: `sha256:${"0".repeat(64)}` });
    assert.throws(
      () => currentFinalReadback(),
      /target-route-generation-config/u,
    );
    await writeOwnerJson(targetRoutePath, { generation: runtimeIdentity.configDigest });
    const extraBindingDatabase = new Database(oauthPath);
    extraBindingDatabase.prepare("insert into oauth_connector_bindings values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)")
      .run(
        "binding-undisposed", proof.activeConnector.canonicalName, "client-undisposed", 1,
        proof.activeConnector.schemaGeneration, proof.activeConnector.authorityContractGeneration,
        proof.activeConnector.redirectUrisDigest, proof.activeConnector.buildDigest, 3, 0, "DRAINING",
      );
    extraBindingDatabase.close();
    assert.throws(
      () => currentFinalReadback(),
      /extra DRAINING\/parallel/u,
    );
    const cleanupBindingDatabase = new Database(oauthPath);
    cleanupBindingDatabase.prepare("delete from oauth_connector_bindings where binding_id = 'binding-undisposed'").run();
    cleanupBindingDatabase.close();
    mutateJournalPostTimestamp(journalPath, 1);
    assert.throws(
      () => currentFinalReadback(),
      /journal|checksum|corrupt/u,
    );
    mutateJournalPostTimestamp(journalPath, -1);
  } finally {
    await writeOwnerJson(postPath, proof.postActivationHostCanaryReceipt);
    await writeFile(mockPaths.pm2, mockPm2Source(proof), { mode: 0o700 });
    await writeFile(mockPaths.lsof, mockLsofSource(false), { mode: 0o700 });
    await writeOwnerJson(targetRoutePath, { generation: runtimeIdentity.configDigest });
    const cleanupBindingDatabase = new Database(oauthPath);
    cleanupBindingDatabase.prepare("delete from oauth_connector_bindings where binding_id = 'binding-undisposed'").run();
    cleanupBindingDatabase.close();
  }

  assert.equal(readFinalizationStoreIdentity({ storePath }).state, "SEALED");
  const resumed = sealFinalization({
    auditRoot: audit,
    storePath,
    evidencePath: sealPath,
    driverPath: canonicalDriver,
  });
  assert.equal(await readFile(cleanupReceiptPath, "utf8"), cleanupReceiptBeforeResume);
  assert.equal(resumed.status, "BASE_PROFILE_FINAL_PASS");
  assert.equal(resumed.sealedFinalizationStoreIdentity.state, "SEALED");
  assert.deepEqual(resumed.immutableIdentity, immutableIdentity);
  assert.equal(resumed.gateResults.length, 16);
  assert.ok(resumed.gateResults.every((entry) => (
    entry.profile === "BASE_SINGLE_OWNER"
    && entry.applicability === "REQUIRED"
    && entry.result === "PASS"
    && /^sha256:[a-f0-9]{64}$/u.test(entry.evidenceDigest)
  )), "final output must contain exact evidence-backed PASS for all 16 Base gates");
  assert.deepEqual(
    prepareRecord.gateResults.slice(-2).map(({ gate, result, evidenceDigest }) => ({ gate, result, evidenceDigest })),
    [
      { gate: "G16 CLEANUP", result: "NOT_RUN", evidenceDigest: undefined },
      { gate: "G17 FINALIZATION", result: "NOT_RUN", evidenceDigest: undefined },
    ],
  );
  const finalNoResidue = resumed.capabilities.find((entry) => entry.capability === "no-residue");
  assert.equal(finalNoResidue.result, "PASS");
  assert.match(finalNoResidue.evidenceDigest, /^sha256:[a-f0-9]{64}$/u);
  assert.equal(
    prepareRecord.capabilities.find((entry) => entry.capability === "no-residue").result,
    "NOT_RUN",
  );
  const preservedReadback = JSON.parse(await readFile(
    join(audit, "finalization", "evidence", "canonical-final-readback.json"),
    "utf8",
  ));
  assert.equal(
    preservedReadback.readback.postActivationHostCanaryReceipt.signature,
    proof.postActivationHostCanaryReceipt.signature,
  );
  assert.equal(Object.hasOwn(preservedReadback.readback, "verifiedPostActivationHostCanary"), false);
  assert.equal(resumed.canonicalFinalReadbackDigest, fixtureDigest(preservedReadback));
  assert.equal(readFinalizationStoreIdentity({ storePath }).state, "BASE_PROFILE_FINAL_PASS");
  assert.equal(verifyFinalizationDirectory(join(audit, "finalization")).status, "BASE_PROFILE_FINAL_PASS");
  const finalRecordPath = join(audit, "finalization", "final.json");
  await assertDerivedFinalizationTamperRejected({
    finalizationRoot: join(audit, "finalization"),
    mutate(finalRecord) {
      finalRecord.gateResults.find((entry) => entry.gate === "G16 CLEANUP").evidenceDigest =
        `sha256:${"0".repeat(64)}`;
      finalRecord.gateResultsDigest = fixtureDigest(finalRecord.gateResults);
    },
    expected: /G16\/G17 gates are not derived/u,
  });
  await assertDerivedFinalizationTamperRejected({
    finalizationRoot: join(audit, "finalization"),
    mutate(finalRecord) {
      finalRecord.gateResults.find((entry) => entry.gate === "G17 FINALIZATION").evidenceDigest =
        `sha256:${"1".repeat(64)}`;
      finalRecord.gateResultsDigest = fixtureDigest(finalRecord.gateResults);
    },
    expected: /G16\/G17 gates are not derived/u,
  });
  await assertDerivedFinalizationTamperRejected({
    finalizationRoot: join(audit, "finalization"),
    mutate(finalRecord) {
      finalRecord.capabilities.find((entry) => entry.capability === "no-residue").evidenceDigest =
        `sha256:${"2".repeat(64)}`;
      finalRecord.capabilitiesDigest = fixtureDigest(finalRecord.capabilities);
    },
    expected: /no-residue capability is not derived/u,
  });
  await assertDerivedFinalizationTamperRejected({
    finalizationRoot: join(audit, "finalization"),
    mutate(finalRecord) {
      finalRecord.tokenFamilyId = "forged-final-token-family";
    },
    expected: /prepared\/current readback binding/u,
  });
  await assertDerivedFinalizationTamperRejected({
    finalizationRoot: join(audit, "finalization"),
    mutate(finalRecord) {
      finalRecord.syntheticFinalPass = true;
    },
    expected: /missing or unsupported field/u,
  });
  const finalizationRoot = join(audit, "finalization");
  const reportPath = join(finalizationRoot, "report.md");
  const checksumsPath = join(finalizationRoot, "SHA256SUMS");
  const originalReport = await readFile(reportPath, "utf8");
  const originalChecksums = await readFile(checksumsPath, "utf8");
  try {
    await writeFile(reportPath, `${originalReport}forged report PASS\n`);
    await chmod(reportPath, 0o600);
    const reportChecksums = originalChecksums.split("\n").map((line) => (
      line.endsWith("  report.md") ? `${fileSha256(reportPath)}  report.md` : line
    )).join("\n");
    await writeFile(checksumsPath, reportChecksums);
    await chmod(checksumsPath, 0o600);
    assert.throws(
      () => verifyFinalizationDirectory(finalizationRoot),
      /G16\/G17 gates are not derived/u,
      "G17 evidence must be recomputed from the durable report/artifact set",
    );
  } finally {
    await writeFile(reportPath, originalReport);
    await chmod(reportPath, 0o600);
    await writeFile(checksumsPath, originalChecksums);
    await chmod(checksumsPath, 0o600);
  }
  const manifestLines = originalChecksums.trimEnd().split("\n");
  assert.ok(manifestLines.length > 2);
  [manifestLines[0], manifestLines[1]] = [manifestLines[1], manifestLines[0]];
  await writeFile(checksumsPath, `${manifestLines.join("\n")}\n`);
  await chmod(checksumsPath, 0o600);
  assert.throws(
    () => verifyFinalizationDirectory(finalizationRoot),
    /path\/order is not canonical/u,
  );
  await writeFile(checksumsPath, originalChecksums);
  await chmod(checksumsPath, 0o600);
  const forgedHiddenFinalizationPath = join(audit, "finalization", ".forged-pass");
  await writeOwnerJson(forgedHiddenFinalizationPath, { status: "PASS" });
  assert.throws(
    () => verifyFinalizationDirectory(join(audit, "finalization")),
    /unexpected hidden entry/u,
  );
  await rm(forgedHiddenFinalizationPath);
  await chmod(finalRecordPath, 0o644);
  assert.throws(
    () => verifyFinalizationDirectory(join(audit, "finalization")),
    /not owner-only/u,
  );
  await chmod(finalRecordPath, 0o600);

  await writeFile(mockPaths.pm2, mockPm2Source(proof, [{
    name: "stale-resume-runtime",
    pid: 60000,
    pm2_env: { status: "online", pm_cwd: release, pm_exec_path: processScript },
  }]), { mode: 0o700 });
  assert.throws(
    () => sealFinalization({
      auditRoot: audit,
      storePath,
      evidencePath: sealPath,
      driverPath: canonicalDriver,
    }),
    /PM2 inventory/u,
    "completed resume must use current canonical readback",
  );
  await writeFile(mockPaths.pm2, mockPm2Source(proof), { mode: 0o700 });
  assert.equal(
    sealFinalization({
      auditRoot: audit,
      storePath,
      evidencePath: sealPath,
      driverPath: canonicalDriver,
    }).status,
    "BASE_PROFILE_FINAL_PASS",
  );
  process.env.PATH = previousPath;
}

async function writeOwnerJson(path, value) {
  await writeJson(path, value);
  await chmod(path, 0o600);
}

async function assertDerivedFinalizationTamperRejected({ finalizationRoot, mutate, expected }) {
  const finalPath = join(finalizationRoot, "final.json");
  const sealPath = join(finalizationRoot, "seal.json");
  const checksumsPath = join(finalizationRoot, "SHA256SUMS");
  const originalFinal = await readFile(finalPath, "utf8");
  const originalSeal = await readFile(sealPath, "utf8");
  const originalChecksums = await readFile(checksumsPath, "utf8");
  try {
    const finalRecord = JSON.parse(originalFinal);
    mutate(finalRecord);
    const { checksum: _finalChecksum, ...unsignedFinal } = finalRecord;
    finalRecord.checksum = fixtureDigest(unsignedFinal);
    await writeOwnerJson(finalPath, finalRecord);

    const seal = JSON.parse(originalSeal);
    seal.finalDigest = fixtureDigest(finalRecord);
    const { checksum: _sealChecksum, ...unsignedSeal } = seal;
    seal.checksum = fixtureDigest(unsignedSeal);
    await writeOwnerJson(sealPath, seal);

    let replaced = 0;
    const rewrittenChecksums = originalChecksums.split("\n").map((line) => {
      if (line.endsWith("  final.json")) {
        replaced += 1;
        return `${fileSha256(finalPath)}  final.json`;
      }
      if (line.endsWith("  seal.json")) {
        replaced += 1;
        return `${fileSha256(sealPath)}  seal.json`;
      }
      return line;
    }).join("\n");
    assert.equal(replaced, 2, "tamper fixture must rewrite exact final/seal checksum entries");
    await writeFile(checksumsPath, rewrittenChecksums);
    await chmod(checksumsPath, 0o600);
    assert.throws(() => verifyFinalizationDirectory(finalizationRoot), expected);
  } finally {
    await writeFile(finalPath, originalFinal);
    await chmod(finalPath, 0o600);
    await writeFile(sealPath, originalSeal);
    await chmod(sealPath, 0o600);
    await writeFile(checksumsPath, originalChecksums);
    await chmod(checksumsPath, 0o600);
  }
}

function createEmptySqlite(path, table) {
  const database = new Database(path);
  database.exec(`create table ${table} (id text primary key) strict`);
  database.pragma("user_version = 1");
  database.close();
  chmodSync(path, 0o600);
}

function sqliteFixtureIdentity(path) {
  const database = new Database(path, { readonly: true, fileMustExist: true });
  try {
    const userVersion = database.pragma("user_version", { simple: true });
    const schema = database.prepare(`
      select type, name, tbl_name as tableName, sql from sqlite_master
       where name not like 'sqlite_%' order by type, name
    `).all();
    return { userVersion, schemaFingerprint: fixtureDigest({ userVersion, schema }) };
  } finally {
    database.close();
  }
}

async function snapshotBindingVariant(root, binding, mutate) {
  const manifest = structuredClone(binding.manifest);
  mutate(manifest);
  const { groupDigest: _groupDigest, ...unsigned } = manifest;
  manifest.groupDigest = fixtureDigest(unsigned);
  const path = join(root, "snapshot-variant-stale.json");
  await writeOwnerJson(path, manifest);
  return { manifestPath: path, manifestSha256: `sha256:${fileSha256(path)}`, manifest };
}

async function assertFinalizationStoreCorruption(root) {
  const metadataRoot = join(root, "corrupt-finalization-metadata-state");
  const metadataPath = join(metadataRoot, "lifecycle.sqlite");
  await mkdir(metadataRoot, { recursive: true, mode: 0o700 });
  const metadataIdentity = initializeFinalizationStore({ storePath: metadataPath });
  const metadataDatabase = new Database(metadataIdentity.path);
  metadataDatabase.prepare("update finalization_metadata set schema_fingerprint = ? where singleton = 1")
    .run(`sha256:${"0".repeat(64)}`);
  metadataDatabase.close();
  assert.throws(() => readFinalizationStoreIdentity({ storePath: metadataPath }), /metadata identity/u);

  const timestampRoot = join(root, "corrupt-finalization-timestamp-state");
  const timestampPath = join(timestampRoot, "lifecycle.sqlite");
  await mkdir(timestampRoot, { recursive: true, mode: 0o700 });
  const timestampIdentity = initializeFinalizationStore({ storePath: timestampPath });
  const timestampDatabase = new Database(timestampIdentity.path);
  timestampDatabase.prepare("update finalization_metadata set created_at = 'not-a-timestamp' where singleton = 1").run();
  timestampDatabase.close();
  assert.throws(() => readFinalizationStoreIdentity({ storePath: timestampPath }), /metadata identity/u);

  const schemaRoot = join(root, "corrupt-finalization-schema-state");
  const schemaPath = join(schemaRoot, "lifecycle.sqlite");
  await mkdir(schemaRoot, { recursive: true, mode: 0o700 });
  const schemaIdentity = initializeFinalizationStore({ storePath: schemaPath });
  const schemaDatabase = new Database(schemaIdentity.path);
  schemaDatabase.exec("alter table finalization_evidence add column forged_pass text");
  schemaDatabase.close();
  assert.throws(() => readFinalizationStoreIdentity({ storePath: schemaPath }), /sqlite_master SQL/u);

  const triggerRoot = join(root, "corrupt-finalization-trigger-state");
  const triggerPath = join(triggerRoot, "lifecycle.sqlite");
  await mkdir(triggerRoot, { recursive: true, mode: 0o700 });
  const triggerIdentity = initializeFinalizationStore({ storePath: triggerPath });
  const triggerDatabase = new Database(triggerIdentity.path);
  triggerDatabase.exec(`
    create trigger forged_finalization_pass after update on finalization_lifecycle
    begin select 1; end
  `);
  triggerDatabase.close();
  assert.throws(() => readFinalizationStoreIdentity({ storePath: triggerPath }), /sqlite_master SQL/u);

  const evidenceRoot = join(root, "corrupt-finalization-evidence-state");
  const evidencePath = join(evidenceRoot, "lifecycle.sqlite");
  await mkdir(evidenceRoot, { recursive: true, mode: 0o700 });
  initializeFinalizationStore({ storePath: evidencePath });
  const evidenceDatabase = new Database(evidencePath);
  evidenceDatabase.prepare(`
    insert into finalization_evidence (digest, kind, canonical_json, recorded_at)
    values (?, 'PREPARE_INPUT', '{}', '2026-08-20T00:00:00.000Z')
  `).run(`sha256:${"0".repeat(64)}`);
  evidenceDatabase.close();
  assert.throws(() => readFinalizationStoreIdentity({ storePath: evidencePath }), /evidence digest/u);
}

async function assertPreparedFinalizationStoreCorruption(root, sourcePath) {
  const transitionRoot = join(root, "corrupt-finalization-transition-state");
  const transitionPath = join(transitionRoot, "lifecycle.sqlite");
  await mkdir(transitionRoot, { recursive: true, mode: 0o700 });
  await cp(sourcePath, transitionPath);
  await chmod(transitionPath, 0o600);
  const database = new Database(transitionPath);
  database.prepare("update finalization_transitions set to_state = 'ACTIVATION_PENDING' where sequence = 1").run();
  database.close();
  assert.throws(
    () => readFinalizationStoreIdentity({ storePath: transitionPath }),
    /inconsistent|checksum|transition/u,
  );
}

async function assertFinalizationErrorTransitions({ root, prepare, snapshotEntries, immutableIdentity }) {
  const auditRoot = join(root, "failed-finalization-audit");
  const stateRoot = join(root, "failed-finalization-state");
  const storePath = join(stateRoot, "lifecycle.sqlite");
  await mkdir(auditRoot, { recursive: true, mode: 0o700 });
  await mkdir(stateRoot, { recursive: true, mode: 0o700 });
  initializeFinalizationStore({ storePath, now: () => "2026-08-20T00:00:00.000Z" });
  const transactionId = "finalization-transaction-99999999-9999-4999-8999-999999999999";
  const upgradeRequestDigest = `sha256:${"9".repeat(64)}`;
  const snapshot = await captureSnapshotGroup({
    snapshotRoot: join(root, "failed-finalization-snapshot"),
    now: () => "2026-08-20T00:00:11.000Z",
    barrier: {
      kind: "PM2_STOPPED",
      establishedAt: "2026-08-20T00:00:11.000Z",
      transactionId,
      upgradeRequestDigest,
      candidateIdentityDigest: fixtureDigest(immutableIdentity),
    },
    entries: snapshotEntries.map((entry) => (
      entry.id === "lifecycle-finalization-store" ? { ...entry, path: storePath } : entry
    )),
  });
  const evidence = structuredClone(prepare);
  evidence.transactionId = transactionId;
  evidence.upgradeRequestDigest = upgradeRequestDigest;
  evidence.snapshotGroup = {
    manifestPath: snapshot.manifestPath,
    manifestSha256: `sha256:${fileSha256(snapshot.manifestPath)}`,
    manifest: snapshot.manifest,
  };
  prepareFinalizationTransaction({
    auditRoot,
    storePath,
    evidence,
    now: () => "2026-08-20T00:00:21.000Z",
  });
  const failureEvidence = {
    kind: "FINALIZATION_FAILED",
    reasonCode: "G13_CUTOVER_FAILED",
    evidenceDigest: `sha256:${"8".repeat(64)}`,
  };
  assert.equal(transitionFinalizationLifecycle({
    storePath,
    transactionId,
    expectedState: "PREPARED",
    nextState: "FAILED",
    evidence: failureEvidence,
    now: () => "2026-08-20T00:00:22.000Z",
  }).status, "FAILED");
  assert.equal(transitionFinalizationLifecycle({
    storePath,
    transactionId,
    expectedState: "PREPARED",
    nextState: "FAILED",
    evidence: failureEvidence,
    now: () => "2026-08-20T00:00:22.000Z",
  }).resumed, true);
  assert.throws(() => transitionFinalizationLifecycle({
    storePath,
    transactionId,
    expectedState: "FAILED",
    nextState: "UNKNOWN",
    evidence: { kind: "ILLEGAL_ERROR_REPLACEMENT" },
  }), /terminal/u);
  assert.throws(() => prepareFinalizationTransaction({
    auditRoot,
    storePath,
    evidence,
    now: () => "2026-08-20T00:00:23.000Z",
  }), /cannot resume terminal lifecycle state/u);
  const corrupted = new Database(storePath);
  corrupted.prepare("update finalization_transitions set to_state = 'UNKNOWN' where sequence = 1").run();
  corrupted.close();
  assert.throws(
    () => readFinalizationStoreIdentity({ storePath }),
    /checksum|transition/u,
  );
}

function strictSealEvidence(prepare) {
  return {
    schemaVersion: 1,
    status: "PASS",
    phase: "post-activation",
    runtimeIdentity: prepare.runtimeIdentity,
    toolNames: ["target", "context", "fs", "exec", "process", "mcp", "artifact", "gui"],
    assurance: "COOPERATIVE_AUTHORITY",
    transactionId: prepare.transactionId,
    snapshotGroupDigest: prepare.snapshotGroup.manifest.groupDigest,
    immutableIdentityDigest: fixtureDigest(prepare.immutableIdentity),
    productionSourcesDigest: fixtureDigest(prepare.productionSources),
    gateResultsDigest: fixtureDigest(prepare.gateResults),
    capabilitiesDigest: fixtureDigest(prepare.capabilities),
    profileApplicabilityDigest: fixtureDigest(prepare.profileApplicability),
  };
}

async function writeFinalizationCommandMocks({ bin, proof, funnelInventory, managementIdentity }) {
  const pm2 = join(bin, "pm2");
  const curl = join(bin, "curl");
  const lsof = join(bin, "lsof");
  const tailscale = join(bin, "tailscale");
  await writeFile(pm2, mockPm2Source(proof), { mode: 0o700 });
  await writeFile(lsof, mockLsofSource(false), { mode: 0o700 });
  await writeFile(curl, `#!/usr/bin/env node
const url = process.argv.at(-1);
const runtime = ${JSON.stringify(proof.runtimeIdentity)};
const route = ${JSON.stringify(proof.routeIdentity)};
const management = ${JSON.stringify(managementIdentity)};
process.stdout.write(JSON.stringify(url.includes(":43111/") ? management : url.includes("/route") ? route : runtime));
`, { mode: 0o700 });
  await writeFile(tailscale, `#!/usr/bin/env node
process.stdout.write(${JSON.stringify(JSON.stringify(funnelInventory))});
`, { mode: 0o700 });
  return { pm2, curl, lsof, tailscale };
}

function mockPm2Source(proof, extras = []) {
  return `#!/usr/bin/env node
const processes = ${JSON.stringify([{
    name: proof.pm2Runtime.name,
    pid: proof.pm2Runtime.pid,
    pm2_env: {
      name: proof.pm2Runtime.name,
      status: proof.pm2Runtime.status,
      pm_cwd: proof.pm2Runtime.cwd,
      pm_exec_path: proof.pm2Runtime.script,
    },
  }, ...extras])};
process.stdout.write(JSON.stringify(processes));
`;
}

function mockLsofSource(extra) {
  const lines = ["p43210", "cnode", "n127.0.0.1:43110", "n127.0.0.1:43111"];
  if (extra) lines.push("p54321", "cparallel-node", "n127.0.0.1:43110");
  return `#!/usr/bin/env node
process.stdout.write(${JSON.stringify(`${lines.join("\n")}\n`)});
`;
}

function withoutMigrationIdentity(value) {
  const { migrationManifestDigest: _migrationManifestDigest, ...identity } = value;
  return identity;
}

function readPath(value, path) {
  return path.split(".").reduce((current, segment) => current?.[segment], value);
}

async function createFixtureSource(source) {
  await mkdir(join(source, "dist"), { recursive: true });
  await mkdir(join(source, "dist", "v2"), { recursive: true });
  await mkdir(join(source, "dist", "db"), { recursive: true });
  await mkdir(join(source, "node_modules", "fixture-identity-dependency"), { recursive: true });
  await mkdir(join(source, "config"), { recursive: true });
  await mkdir(join(source, "contracts"), { recursive: true });
  await mkdir(join(source, "scripts"), { recursive: true });
  await mkdir(join(source, "scripts", "lib"), { recursive: true });
  await mkdir(join(source, "skills"), { recursive: true });
  await writeFile(join(source, "dist", "server.js"), "export const ready = true;\n");
  await writeFile(join(source, "dist", "cli.js"), "export const ready = true;\n");
  await writeJson(join(source, "node_modules", "fixture-identity-dependency", "package.json"), {
    name: "fixture-identity-dependency",
    version: "1.0.0",
    type: "module",
    exports: "./index.js",
  });
  await writeFile(join(source, "node_modules", "fixture-identity-dependency", "index.js"), [
    `export const schemaGeneration = "sha256:${"a".repeat(64)}";`,
    `export const authorityContractGeneration = "sha256:${"b".repeat(64)}";`,
    "",
  ].join("\n"));
  await writeFile(join(source, "dist", "v2", "runtime-identity.js"), [
    'import "fixture-identity-dependency";',
    'import { RUNTIME_SCHEMA_GENERATION, RUNTIME_AUTHORITY_CONTRACT_GENERATION } from "./runtime-contract-identity.js";',
    "export function createRuntimeIdentity() {",
    "  return { schemaGeneration: RUNTIME_SCHEMA_GENERATION, authorityContractGeneration: RUNTIME_AUTHORITY_CONTRACT_GENERATION };",
    "}",
    "",
  ].join("\n"));
  await writeFile(join(source, "dist", "v2", "runtime-contract-identity.js"), [
    `export const RUNTIME_SCHEMA_GENERATION = "sha256:${"a".repeat(64)}";`,
    `export const RUNTIME_AUTHORITY_CONTRACT_GENERATION = "sha256:${"b".repeat(64)}";`,
    "",
  ].join("\n"));
  const buildCapabilityContract = fixtureBuildCapabilityContract();
  await writeFile(join(source, "dist", "v2", "build-capabilities.js"), buildCapabilitiesModuleSource(buildCapabilityContract));
  await writeFile(join(source, "dist", "v2", "migration-registry.js"), [
    'import { createHash } from "node:crypto";',
    "export function universalBrokerStoreMigrationManifest(mainDatabaseManifest = []) {",
    "  return normalize([",
    "    ...mainDatabaseManifest,",
    `    { storeId: "artifact-catalog", version: 1, name: "fixture-artifacts", checksum: "sha256:${"d".repeat(64)}", module: "v2/artifact-catalog" },`,
    `    { storeId: "filesystem-sync", version: 1, name: "filesystem-sync-sqlite", checksum: "sha256:${"f".repeat(64)}", module: "v2/filesystem-sync" },`,
    `    ${JSON.stringify(FINALIZATION_STORE_MIGRATION)},`,
    "  ]);",
    "}",
    "export function migrationManifestDigest(manifest) {",
    '  return `sha256:${createHash("sha256").update(JSON.stringify(normalize(manifest))).digest("hex")}`;',
    "}",
    "function normalize(manifest) {",
    "  return manifest.map((entry) => ({ storeId: entry.storeId, version: entry.version, name: entry.name, checksum: entry.checksum, module: entry.module }))",
    "    .sort((left, right) => (left.storeId < right.storeId ? -1 : left.storeId > right.storeId ? 1 : left.version - right.version));",
    "}",
    "",
  ].join("\n"));
  await writeFile(join(source, "dist", "db", "migrations.js"), [
    "export function mainDatabaseMigrationManifest() {",
    `  return [{ storeId: "main", version: 1, name: "fixture-main", checksum: "sha256:${"e".repeat(64)}", module: "db/migrations" }];`,
    "}",
    "",
  ].join("\n"));
  await writeJson(join(source, "package.json"), { name: "fixture-broker", version: "1.0.0", license: "MIT" });
  await writeJson(join(source, "package-lock.json"), {
    name: "fixture-broker",
    version: "1.0.0",
    lockfileVersion: 3,
    packages: { "": { name: "fixture-broker", version: "1.0.0" }, "node_modules/example": { version: "2.0.0" } },
  });
  await writeJson(join(source, "config", "config.schema.json"), {
    $schema: "https://json-schema.org/draft/2020-12/schema",
    $id: "https://devspace.local/config/config.schema.json",
    type: "object",
    properties: { deploymentMode: { enum: ["parallel", "production"] } },
  });
  const schemas = {
    "tools-v2.schema.json": fixtureToolsSchema(buildCapabilityContract),
    "build-capabilities.schema.json": fixtureBuildCapabilitySchema(buildCapabilityContract),
    "mcp-risk-policy.schema.json": { $schema: "https://json-schema.org/draft/2020-12/schema", risk: ["R0", "R1", "R2", "R3"] },
    "errors.schema.json": { $schema: "https://json-schema.org/draft/2020-12/schema", errors: ["SCHEMA_STALE"] },
    "targets.schema.json": { $schema: "https://json-schema.org/draft/2020-12/schema", type: "array" },
    "mcp-routes.schema.json": { $schema: "https://json-schema.org/draft/2020-12/schema", type: "array" },
    "capabilities.schema.json": { $schema: "https://json-schema.org/draft/2020-12/schema", type: "object" },
  };
  for (const [name, value] of Object.entries(schemas)) await writeJson(join(source, "contracts", name), value);
  await writeFile(join(source, "scripts", "start-universal-broker-v2-production.sh"), "#!/bin/bash\nexec node dist/server.js\n", { mode: 0o755 });
  await writeFile(join(source, "scripts", "lib", "runtime-dependency-loader.mjs"), "export function resolve(s,c,n) { return n(s,c); }\n");
  await writeFile(join(source, "scripts", "rollback-universal-broker-v2-production.sh"), "#!/bin/bash\nexit 0\n", { mode: 0o755 });
  for (const relativePath of RUNTIME_OPERATIONS_CLOSURE_ROOTS) {
    const path = join(source, relativePath);
    try {
      await stat(path);
      continue;
    } catch (error) {
      if (error?.code !== "ENOENT") throw error;
    }
    await mkdir(dirname(path), { recursive: true });
    const shell = relativePath.endsWith(".sh");
    let content = shell ? "#!/bin/bash\nexit 0\n" : "export const fixtureRuntimeOperation = true;\n";
    if (relativePath === "scripts/lib/base-profile-gate-producer.mjs") {
      content = [
        'import { pathToFileURL } from "node:url";',
        'const modulePath = "scripts/lib/release-artifacts.mjs";',
        'export const loadFixtureReporter = () => import(pathToFileURL(modulePath).href);',
        "",
      ].join("\n");
    } else if (relativePath === "scripts/lib/connector-activation-release-driver.mjs") {
      content = [
        'import { join } from "node:path";',
        'import { pathToFileURL } from "node:url";',
        'const repositoryRoot = ".";',
        'const module = (path) => import(pathToFileURL(join(repositoryRoot, "dist", path)).href);',
        'export const loadFixtureRuntime = () => module("v2/production-upgrade-worker.js");',
        "",
      ].join("\n");
    }
    await writeFile(
      path,
      content,
      shell ? { mode: 0o755 } : undefined,
    );
  }
}

function fixtureBuildCapabilityContract() {
  return {
    productVersion: "2.1.0",
    productProfile: "BASE_SINGLE_OWNER",
    schemaGeneration: `sha256:${"a".repeat(64)}`,
    authorityContractGeneration: `sha256:${"b".repeat(64)}`,
    supportedProfiles: ["BASE_SINGLE_OWNER"],
    supportedOperations: {
      target: ["list"],
      context: ["open"],
      fs: ["read"],
      exec: ["run"],
      process: ["list"],
      mcp: ["call"],
      artifact: ["receive"],
      gui: ["inspect"],
    },
    resourceUriVersion: "v1",
  };
}

function fixtureGeneratedReleaseMetadata(context) {
  const capabilityContract = fixtureBuildCapabilityContract();
  const buildCapabilities = {
    ...capabilityContract,
    buildDigest: context.buildDigest,
    capabilityDigest: fixtureDigest(capabilityContract),
  };
  const migrationManifest = [
    { storeId: "artifact-catalog", version: 1, name: "fixture-artifacts", checksum: `sha256:${"d".repeat(64)}`, module: "v2/artifact-catalog" },
    { storeId: "filesystem-sync", version: 1, name: "filesystem-sync-sqlite", checksum: `sha256:${"f".repeat(64)}`, module: "v2/filesystem-sync" },
    FINALIZATION_STORE_MIGRATION,
    { storeId: "main", version: 1, name: "fixture-main", checksum: `sha256:${"e".repeat(64)}`, module: "db/migrations" },
  ].sort((left, right) => left.storeId < right.storeId ? -1 : left.storeId > right.storeId ? 1 : left.version - right.version);
  return {
    sourceTreeSha256: fixtureDigest({ sourceRevision: context.sourceRevision }),
    dependencyTreeSha256: fixtureDigest({ dependency: "fixture-identity-dependency@1.0.0" }),
    collectorReceiptSha256: fixtureDigest({ collector: "release-finalization-fixture" }),
    buildCapabilities,
    migrationManifest,
    migrationManifestDigest: `sha256:${sha256(JSON.stringify(migrationManifest))}`,
  };
}

function buildCapabilitiesModuleSource(contract, options = {}) {
  const digestExpression = options.capabilityDigest
    ? JSON.stringify(options.capabilityDigest)
    : "capabilityDigest(contract)";
  return [
    'import { createHash } from "node:crypto";',
    `const contract = ${JSON.stringify(contract, null, 2)};`,
    "export function createBuildCapabilityManifest(buildDigest) {",
    `  return Object.freeze({ ...contract, buildDigest, capabilityDigest: ${digestExpression} });`,
    "}",
    "function capabilityDigest(value) {",
    '  return `sha256:${createHash("sha256").update(canonicalJson(value)).digest("hex")}`;',
    "}",
    "function canonicalJson(value) {",
    '  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;',
    "  if (value && typeof value === 'object') {",
    '    return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonicalJson(value[key])}`).join(",")}}`;',
    "  }",
    "  return JSON.stringify(value) ?? 'null';",
    "}",
    "",
  ].join("\n");
}

function fixtureToolsSchema(contract) {
  return {
    $schema: "https://json-schema.org/draft/2020-12/schema",
    $id: "https://devspace.local/contracts/tools-v2.schema.json",
    title: "DevSpace Universal Broker v2 Tool Manifest",
    type: "object",
    additionalProperties: false,
    required: ["version", "tools", "budgets"],
    properties: {
      version: { const: contract.productVersion },
      tools: {
        type: "object",
        additionalProperties: false,
        required: Object.keys(contract.supportedOperations),
        properties: Object.fromEntries(Object.keys(contract.supportedOperations).map((tool) => [
          tool,
          { $ref: `#/$defs/${tool}Tool` },
        ])),
      },
      budgets: {
        type: "object",
        additionalProperties: false,
        required: ["maximumTools"],
        properties: { maximumTools: { const: Object.keys(contract.supportedOperations).length } },
      },
    },
    $defs: {
      tool: {
        type: "object",
        additionalProperties: false,
        required: ["operations"],
        properties: {
          operations: {
            type: "array",
            minItems: 1,
            uniqueItems: true,
            items: { type: "string", minLength: 1 },
          },
        },
      },
      ...Object.fromEntries(Object.entries(contract.supportedOperations).map(([tool, operations]) => [
        `${tool}Tool`,
        {
          allOf: [
            { $ref: "#/$defs/tool" },
            { properties: { operations: { const: operations } } },
          ],
        },
      ])),
    },
  };
}

function fixtureBuildCapabilitySchema(contract) {
  return {
    $schema: "https://json-schema.org/draft/2020-12/schema",
    $id: "https://devspace.local/contracts/build-capabilities.schema.json",
    title: "DevSpace Universal Broker Build Capability Manifest",
    type: "object",
    additionalProperties: false,
    required: [
      "productVersion",
      "productProfile",
      "schemaGeneration",
      "authorityContractGeneration",
      "supportedProfiles",
      "supportedOperations",
      "resourceUriVersion",
      "buildDigest",
      "capabilityDigest",
    ],
    properties: {
      productVersion: { const: contract.productVersion },
      productProfile: { const: contract.productProfile },
      schemaGeneration: { type: "string", pattern: "^sha256:[a-f0-9]{64}$" },
      authorityContractGeneration: { type: "string", pattern: "^sha256:[a-f0-9]{64}$" },
      supportedProfiles: { const: contract.supportedProfiles },
      supportedOperations: {
        type: "object",
        additionalProperties: false,
        required: Object.keys(contract.supportedOperations),
        properties: Object.fromEntries(Object.entries(contract.supportedOperations).map(([tool, operations]) => [
          tool,
          { const: operations },
        ])),
      },
      resourceUriVersion: { const: contract.resourceUriVersion },
      buildDigest: { type: "string", pattern: "^sha256:[a-f0-9]{64}$" },
      capabilityDigest: { type: "string", pattern: "^sha256:[a-f0-9]{64}$" },
    },
  };
}

async function repairReleaseDigests(releaseRoot) {
  const manifestPath = join(releaseRoot, RELEASE_MANIFEST_NAME);
  const manifest = JSON.parse(await readFile(manifestPath, "utf8"));
  manifest.payloadDigest = treeEvidence(releaseRoot, manifest.payloadFiles).sha256;
  await writeJson(manifestPath, manifest);
  const files = listRegularFiles(releaseRoot)
    .map((path) => relative(releaseRoot, path).split(sep).join("/"))
    .filter((path) => path !== RELEASE_CHECKSUM_NAME)
    .sort();
  await writeFile(
    join(releaseRoot, RELEASE_CHECKSUM_NAME),
    `${files.map((path) => `${fileSha256(join(releaseRoot, path))}  ${path}`).join("\n")}\n`,
  );
}

function finalReadbackProof(runtimeIdentity, immutableIdentity, managementKey, runtimePaths = {}) {
  const activeTokenFamily = {
    familyId: "family-current",
    clientId: "client-current",
    connectorBindingId: "binding-current",
    installationEpoch: 2,
    drainEpoch: 4,
    status: "ACTIVE",
  };
  const activeConnector = {
    canonicalName: "myDevSpace",
    bindingId: "binding-current",
    clientId: "client-current",
    tokenFamilyId: "family-current",
    installationEpoch: 2,
    drainEpoch: 4,
    schemaGeneration: runtimeIdentity.schemaGeneration,
    authorityContractGeneration: runtimeIdentity.authorityContractGeneration,
    redirectUrisDigest: `sha256:${"c".repeat(64)}`,
    buildDigest: runtimeIdentity.buildDigest,
    refCount: 1,
    state: "ACTIVE",
  };
  const runtimeIdentityDigest = fixtureDigest(runtimeIdentity);
  const activatedAtMs = Date.now() - 5_000;
  const activatedAt = new Date(activatedAtMs).toISOString();
  const ownerPrincipal = "1".repeat(64);
  const activationAuthorityProof = {
    schemaVersion: 1,
    authorityId: "authority_11111111-1111-4111-8111-111111111111",
    actionClaimId: "authority_claim_22222222-2222-4222-8222-222222222222",
    actionFingerprint: "2".repeat(64),
    resourceKeySha256: "3".repeat(64),
    fencingToken: 4,
    principalKeyFingerprint: ownerPrincipal,
    risk: "R3",
    claimState: "DISPATCHED",
    approvalAssurance: "cooperative",
    receiptId: "connector-activation-33333333-3333-4333-8333-333333333333",
    tupleDigest: connectorActivationTupleDigest({
      canonicalName: activeConnector.canonicalName,
      candidateBindingId: activeConnector.bindingId,
      clientId: activeConnector.clientId,
      installationEpoch: activeConnector.installationEpoch,
      schemaGeneration: activeConnector.schemaGeneration,
      authorityContractGeneration: activeConnector.authorityContractGeneration,
      redirectUrisDigest: activeConnector.redirectUrisDigest,
      buildDigest: activeConnector.buildDigest,
    }),
    activePreimageDigest: `sha256:${"4".repeat(64)}`,
    finalizationPlanDigest: `sha256:${"5".repeat(64)}`,
    canonicalName: activeConnector.canonicalName,
    evidenceDigest: `sha256:${"6".repeat(64)}`,
    claimedAtMs: activatedAtMs - 2,
    dispatchedAtMs: activatedAtMs - 1,
  };
  const activationAuthority = {
    ...activationAuthorityProof,
    proofDigest: fixtureDigest(activationAuthorityProof),
    consumedAt: activatedAt,
  };
  const activationReceiptBase = {
    receiptId: activationAuthority.receiptId,
    tuple: {
      canonicalName: activeConnector.canonicalName,
      candidateBindingId: activeConnector.bindingId,
      clientId: activeConnector.clientId,
      installationEpoch: activeConnector.installationEpoch,
      schemaGeneration: activeConnector.schemaGeneration,
      authorityContractGeneration: activeConnector.authorityContractGeneration,
      redirectUrisDigest: activeConnector.redirectUrisDigest,
      buildDigest: activeConnector.buildDigest,
    },
    tupleDigest: activationAuthority.tupleDigest,
    previousActiveBindingId: "binding-old",
    preimageDigest: activationAuthority.activePreimageDigest,
    activationAuthority,
    ownerAuthorityId: activationAuthority.authorityId,
    drainDeadlineAt: "2026-08-19T00:20:00.000Z",
    refreshAllowedDuringDrain: false,
    status: "ACTIVATED",
    preparedAt: "2026-08-19T00:09:00.000Z",
    activatedAt,
  };
  const connectorActivationReceipt = activationReceiptBase;
  const mutationAuthorityReceiptDigest = `sha256:${"7".repeat(64)}`;
  const mutation = {
    tool: "fs",
    operation: "write",
    argumentsDigest: `sha256:${"8".repeat(64)}`,
    resourceDigest: `sha256:${"9".repeat(64)}`,
    sessionAIdDigest: `sha256:${"a".repeat(64)}`,
    sessionAAuthorizationEvidenceDigest: `sha256:${"b".repeat(64)}`,
    sessionAAuthorizedAtMs: activatedAtMs + 1_000,
    sessionACloseEvidenceDigest: `sha256:${"c".repeat(64)}`,
    sessionAClosedAtMs: activatedAtMs + 2_000,
    sessionBIdDigest: `sha256:${"d".repeat(64)}`,
    sessionBMutationEvidenceDigest: `sha256:${"e".repeat(64)}`,
    sessionBMutationAtMs: activatedAtMs + 3_000,
    actionFingerprint: "8".repeat(64),
    resourceKeySha256: "9".repeat(64),
    authorityId: "authority_44444444-4444-4444-8444-444444444444",
    actionClaimId: "authority_claim_55555555-5555-4555-8555-555555555555",
    fencingToken: 5,
    authorityReceiptDigest: mutationAuthorityReceiptDigest,
    providerDispatchCount: 1,
    postReadbackDigest: `sha256:${"1".repeat(64)}`,
    cleanupPerformed: true,
    cleanupEvidenceDigest: `sha256:${"2".repeat(64)}`,
  };
  const postActionId = `action_${mutation.actionFingerprint}`;
  const postTaskInstanceId = "task-instance-post-finalization";
  const postMutationAuthorityReadback = authorityReadback({
    authority: {
      ...mutation,
      principalKeyFingerprint: ownerPrincipal,
      claimedAtMs: mutation.sessionBMutationAtMs - 2,
      dispatchedAtMs: mutation.sessionBMutationAtMs - 1,
    },
    tool: mutation.tool,
    operation: mutation.operation,
    receiptDigest: mutation.authorityReceiptDigest,
    completedAtMs: mutation.sessionBMutationAtMs,
  });
  const exactMutationReceiptDigest = fixtureAuthorityReceiptDigest(
    postMutationAuthorityReadback,
    postActionId,
    postTaskInstanceId,
  );
  mutation.authorityReceiptDigest = exactMutationReceiptDigest;
  postMutationAuthorityReadback.receiptDigest = exactMutationReceiptDigest;
  const postPayload = {
    stage: "POST_ACTIVATION_HOST_CANARY",
    postActivationHostCanaryId: "post-activation-host-33333333",
    managementNonce: "finalization-management-nonce",
    managementCorrelationId: "finalization-management-correlation",
    principalKeyFingerprint: ownerPrincipal,
    hostProvider: "chatgpt",
    actualHost: true,
    precheckDigest: `sha256:${"3".repeat(64)}`,
    activationReceiptId: connectorActivationReceipt.receiptId,
    activationReceiptDigest: connectorActivationReceiptDigest(connectorActivationReceipt),
    activationProofDigest: connectorActivationReceipt.activationAuthority.proofDigest,
    activationAuthorityReceiptDigest: connectorActivationAuthorityReceiptDigest(
      connectorActivationReceipt.activationAuthority,
    ),
    activatedAtMs,
    newActiveTuple: connectorActivationReceipt.tuple,
    newActiveBindingState: "ACTIVE",
    tokenFamilyIdDigest: fixtureTextDigest(activeTokenFamily.familyId),
    tokenFamilyBindingId: activeConnector.bindingId,
    previousActiveBindingId: "binding-old",
    previousBindingState: "DRAINING",
    productionIdentity: immutableIdentity ? withoutMigrationIdentity(immutableIdentity) : {
      runtimeIdentityDigest,
      buildDigest: activeConnector.buildDigest,
      schemaGeneration: activeConnector.schemaGeneration,
      authorityContractGeneration: activeConnector.authorityContractGeneration,
      buildCapabilityManifestDigest: `sha256:${"4".repeat(64)}`,
      generatedSchemaDigest: `sha256:${"5".repeat(64)}`,
      packageSha256: `sha256:${"6".repeat(64)}`,
    },
    productionEnvironmentIdentityDigest: `sha256:${"7".repeat(64)}`,
    productionRouteIdentityDigest: `sha256:${"8".repeat(64)}`,
    discoveredToolNames: ["target", "context", "fs", "exec", "process", "mcp", "artifact", "gui"],
    toolDiscoveryEvidenceDigest: `sha256:${"9".repeat(64)}`,
    mutation,
    foreignClientIsolation: {
      clientId: "foreign-client",
      principalKeyFingerprint: "f".repeat(64),
      errorCode: "AUTHORITY_PRINCIPAL_MISMATCH",
      providerDispatchCount: 0,
      evidenceDigest: `sha256:${"a".repeat(64)}`,
    },
    observedAtMs: activatedAtMs + 4_000,
    expiresAtMs: activatedAtMs + 60_000,
  };
  const postActivationHostCanaryReceipt = managementKey
    ? signConnectorActivationPostActivationHostCanary(postPayload, managementKey, postPayload.observedAtMs)
    : {
        schemaVersion: 2,
        kind: "POST_ACTIVATION_HOST_CANARY",
        keyId: "management-fixture-finalization",
        payload: postPayload,
        payloadDigest: fixtureDigest({
          schemaVersion: 2,
          kind: "POST_ACTIVATION_HOST_CANARY",
          keyId: "management-fixture-finalization",
          payload: postPayload,
        }),
        signature: "A".repeat(43),
      };
  const activationAuthorityReadback = authorityReadback({
    authority: activationAuthority,
    tool: "context",
    operation: "connector_activation_finalize",
    receiptDigest: `sha256:${"b".repeat(64)}`,
    completedAtMs: activatedAtMs,
  });
  return {
    complete: true,
    runtimeIdentity,
    runtimeReadback: { identityDigest: runtimeIdentityDigest },
    pm2Runtime: {
      name: "devspace-universal-broker-v2",
      pid: 43210,
      status: "online",
      cwd: runtimePaths.cwd ?? "/srv/devspace/release",
      script: runtimePaths.script ?? "/srv/devspace/release/dist/server.js",
      runtimeIdentityDigest,
    },
    routeIdentity: {
      schemaVersion: 1,
      state: "ACTIVE",
      routeCount: 1,
      canonicalName: activeConnector.canonicalName,
      bindingId: activeConnector.bindingId,
      runtimeIdentityDigest,
      productionEnvironmentIdentityDigest: postPayload.productionEnvironmentIdentityDigest,
      productionRouteIdentityDigest: postPayload.productionRouteIdentityDigest,
    },
    oauthReadback: { canonicalActiveCount: 1, selectedActiveTokenFamilyCount: 1 },
    activeTokenFamily,
    activeConnector,
    retiredConnectors: [{
      bindingId: "binding-old",
      state: "RETIRED",
      refCount: 0,
      retirementReceiptId: "connector-retirement-old",
      retirementReason: "REFERENCE_ZERO",
    }],
    revokedTokenFamilyIds: ["family-old"],
    connectorActivationReceipt,
    activationAuthorityReadback,
    postMutationAuthorityReadback,
    connectorJournalReadback: {
      storeId: "11111111-1111-4111-8111-111111111111",
      snapshotPolicy: "PRESERVE_OUTSIDE_MUTABLE_ROLLBACK",
      receiptReplayPolicy: "PREPARED_RECEIPT_PERMANENTLY_ONE_SHOT",
      contentGeneration: `sha256:${"c".repeat(64)}`,
      principalKeyFingerprint: ownerPrincipal,
      approvalId: "owner-approval-finalization",
      receiptId: connectorActivationReceipt.receiptId,
      freshHostReceiptId: "pre-cutover-host-finalization",
      dispatchState: "DISPATCHED",
      authorityId: activationAuthority.authorityId,
      actionClaimId: activationAuthority.actionClaimId,
      actionFingerprint: activationAuthority.actionFingerprint,
      resourceKeySha256: activationAuthority.resourceKeySha256,
      fencingToken: activationAuthority.fencingToken,
      pendingEvidenceDigest: `sha256:${"d".repeat(64)}`,
      postActivationEvidenceDigest: postActivationHostCanaryReceipt.payloadDigest,
      postActivationRecordedAtMs: postPayload.observedAtMs + 1,
      terminalState: "POST_ACTIVATION_VERIFIED",
    },
    postActivationHostCanaryReceipt,
  };
}

function requiredTrustedFinalReadbackPaths() {
  const paths = [
    "complete",
    "productionSourcesDigest",
    "runtimeIdentity", ...[
      "sourceRevision", "runtimeRevision", "buildDigest", "schemaGeneration",
      "authorityContractGeneration", "configDigest", "configSchemaIdentity",
    ].map((key) => `runtimeIdentity.${key}`),
    "runtimeReadback", "runtimeReadback.identityDigest",
    "pm2Runtime", ...["name", "pid", "status", "cwd", "script", "runtimeIdentityDigest"]
      .map((key) => `pm2Runtime.${key}`),
    "listenerReadback", "listenerReadback.scopePorts", "listenerReadback.listeners",
    "listenerReadback.inventoryDigest",
    ...["command", "address", "port"].map((key) => `listenerReadback.listeners.0.${key}`),
    ...["command", "address", "port"].map((key) => `listenerReadback.listeners.1.${key}`),
    "managementIdentity", "managementIdentity.schemaVersion", "managementIdentity.state",
    "managementIdentity.listener", "funnelInventoryDigest", "residueReadback",
    "residueReadback.paths", "residueReadback.present",
    "routeIdentity", ...[
      "schemaVersion", "state", "routeCount", "canonicalName", "bindingId",
      "runtimeIdentityDigest", "productionEnvironmentIdentityDigest",
      "productionRouteIdentityDigest",
    ].map((key) => `routeIdentity.${key}`),
    "oauthReadback", "oauthReadback.canonicalActiveCount",
    "oauthReadback.selectedActiveTokenFamilyCount", "oauthReadback.canonicalBindingCount",
    "oauthReadback.retiredCanonicalBindingCount", "oauthReadback.undisposedCanonicalBindingCount",
    "activeTokenFamily", ...[
      "familyId", "clientId", "connectorBindingId", "installationEpoch", "drainEpoch", "status",
    ].map((key) => `activeTokenFamily.${key}`),
    "activeConnector", ...[
      "canonicalName", "bindingId", "clientId", "tokenFamilyId", "installationEpoch",
      "drainEpoch", "schemaGeneration", "authorityContractGeneration", "redirectUrisDigest",
      "buildDigest", "refCount", "state",
    ].map((key) => `activeConnector.${key}`),
    "retiredConnectors", ...[
      "bindingId", "state", "refCount", "retirementReceiptId", "retirementReason",
    ].map((key) => `retiredConnectors.0.${key}`),
    "revokedTokenFamilyIds",
    "connectorActivationReceipt", ...[
      "receiptId", "tuple", "tupleDigest", "previousActiveBindingId", "preimageDigest",
      "activationAuthority", "ownerAuthorityId", "drainDeadlineAt", "refreshAllowedDuringDrain",
      "status", "preparedAt", "activatedAt",
    ].map((key) => `connectorActivationReceipt.${key}`),
    ...[
      "canonicalName", "candidateBindingId", "clientId", "installationEpoch",
      "schemaGeneration", "authorityContractGeneration", "redirectUrisDigest", "buildDigest",
    ].map((key) => `connectorActivationReceipt.tuple.${key}`),
    ...[
      "schemaVersion", "authorityId", "actionClaimId", "actionFingerprint", "resourceKeySha256",
      "fencingToken", "principalKeyFingerprint", "risk", "claimState", "approvalAssurance",
      "receiptId", "tupleDigest", "activePreimageDigest", "finalizationPlanDigest",
      "canonicalName", "evidenceDigest", "claimedAtMs", "dispatchedAtMs", "proofDigest", "consumedAt",
    ].map((key) => `connectorActivationReceipt.activationAuthority.${key}`),
  ];
  for (const root of ["activationAuthorityReadback", "postMutationAuthorityReadback"]) {
    paths.push(root, ...[
      "authorityId", "actionClaimId", "actionFingerprint", "resourceKeySha256", "fencingToken",
      "principalKeyFingerprint", "tool", "operation", "claimedAtMs", "dispatchedAtMs",
      "completedAtMs", "state", "result", "leaseState", "providerCallCount", "receiptDigest",
    ].map((key) => `${root}.${key}`));
  }
  paths.push(
    "connectorJournalReadback",
    ...[
      "storeId", "snapshotPolicy", "receiptReplayPolicy", "contentGeneration",
      "principalKeyFingerprint", "approvalId", "receiptId", "freshHostReceiptId", "dispatchState",
      "authorityId", "actionClaimId", "actionFingerprint", "resourceKeySha256", "fencingToken",
      "pendingEvidenceDigest", "postActivationEvidenceDigest", "postActivationRecordedAtMs", "terminalState",
    ].map((key) => `connectorJournalReadback.${key}`),
    "postActivationHostCanaryReceipt",
    ...["schemaVersion", "kind", "keyId", "payload", "payloadDigest", "signature"]
      .map((key) => `postActivationHostCanaryReceipt.${key}`),
  );
  paths.push(...[
    "stage", "postActivationHostCanaryId", "managementNonce", "managementCorrelationId",
    "principalKeyFingerprint", "hostProvider", "actualHost", "precheckDigest", "activationReceiptId",
    "activationReceiptDigest", "activationProofDigest", "activationAuthorityReceiptDigest",
    "activatedAtMs", "newActiveTuple", "newActiveBindingState", "tokenFamilyIdDigest",
    "tokenFamilyBindingId", "previousActiveBindingId", "previousBindingState", "productionIdentity",
    "productionEnvironmentIdentityDigest", "productionRouteIdentityDigest", "discoveredToolNames",
    "toolDiscoveryEvidenceDigest", "mutation", "foreignClientIsolation", "observedAtMs", "expiresAtMs",
  ].map((key) => `postActivationHostCanaryReceipt.payload.${key}`));
  paths.push(...[
    "runtimeIdentityDigest", "buildDigest", "schemaGeneration", "authorityContractGeneration",
    "buildCapabilityManifestDigest", "generatedSchemaDigest", "packageSha256",
  ].map((key) => `postActivationHostCanaryReceipt.payload.productionIdentity.${key}`));
  paths.push(...[
    "canonicalName", "candidateBindingId", "clientId", "installationEpoch",
    "schemaGeneration", "authorityContractGeneration", "redirectUrisDigest", "buildDigest",
  ].map((key) => `postActivationHostCanaryReceipt.payload.newActiveTuple.${key}`));
  paths.push(...[
    "tool", "operation", "argumentsDigest", "resourceDigest", "sessionAIdDigest",
    "sessionAAuthorizationEvidenceDigest", "sessionAAuthorizedAtMs", "sessionACloseEvidenceDigest",
    "sessionAClosedAtMs", "sessionBIdDigest", "sessionBMutationEvidenceDigest",
    "sessionBMutationAtMs", "actionFingerprint", "resourceKeySha256", "authorityId",
    "actionClaimId", "fencingToken", "authorityReceiptDigest", "providerDispatchCount",
    "postReadbackDigest", "cleanupPerformed", "cleanupEvidenceDigest",
  ].map((key) => `postActivationHostCanaryReceipt.payload.mutation.${key}`));
  paths.push(...[
    "clientId", "principalKeyFingerprint", "errorCode", "providerDispatchCount", "evidenceDigest",
  ].map((key) => `postActivationHostCanaryReceipt.payload.foreignClientIsolation.${key}`));
  return paths;
}

function deletePath(value, path) {
  const segments = path.split(".");
  let parent = value;
  for (const segment of segments.slice(0, -1)) parent = parent?.[segment];
  if (parent && typeof parent === "object") delete parent[segments.at(-1)];
}

function createLiveOAuthFixture(path, proof) {
  const database = new Database(path);
  database.exec(`
    create table oauth_connector_bindings (
      binding_id text, canonical_name text, client_id text, installation_epoch integer,
      schema_generation text, authority_contract_generation text, redirect_uris_digest text,
      build_digest text, drain_epoch integer, ref_count integer, state text
    );
    create table oauth_token_families (
      family_id text, client_id text, connector_binding_id text,
      installation_epoch integer, drain_epoch integer, status text
    );
    create table oauth_connector_retirement_receipts (
      binding_id text, receipt_id text, reason text
    );
    create table oauth_connector_activation_receipts (
      receipt_id text, canonical_name text, candidate_binding_id text, client_id text,
      installation_epoch integer, schema_generation text, authority_contract_generation text,
      redirect_uris_digest text, build_digest text, tuple_digest text, preimage_digest text,
      previous_active_binding_id text, owner_authority_id text, drain_deadline_at text,
      refresh_allowed_during_drain integer, status text, prepared_at text, activated_at text
    );
    create table oauth_connector_activation_authorities (
      action_claim_id text, receipt_id text, authority_id text,
      principal_key_fingerprint text, action_fingerprint text, resource_key_sha256 text,
      fencing_token integer, risk text, claim_state text, approval_assurance text,
      canonical_name text, tuple_digest text, active_preimage_digest text,
      finalization_plan_digest text, evidence_digest text, claimed_at_ms integer,
      dispatched_at_ms integer, proof_digest text, consumed_at text
    );
  `);
  const active = proof.activeConnector;
  database.prepare(`
    insert into oauth_connector_bindings values
      (@bindingId, @canonicalName, @clientId, @installationEpoch, @schemaGeneration,
       @authorityContractGeneration, @redirectUrisDigest, @buildDigest, @drainEpoch, @refCount, @state)
  `).run(active);
  database.prepare("insert into oauth_connector_bindings values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)")
    .run(
      "binding-old", active.canonicalName, "client-old", 1, active.schemaGeneration,
      active.authorityContractGeneration, active.redirectUrisDigest, active.buildDigest,
      3, 0, "RETIRED",
    );
  database.prepare("insert into oauth_token_families values (?, ?, ?, ?, ?, ?)").run(
    proof.activeTokenFamily.familyId,
    proof.activeTokenFamily.clientId,
    proof.activeTokenFamily.connectorBindingId,
    proof.activeTokenFamily.installationEpoch,
    proof.activeTokenFamily.drainEpoch,
    "ACTIVE",
  );
  database.prepare("insert into oauth_token_families values (?, ?, ?, ?, ?, ?)")
    .run("family-old", "client-old", "binding-old", 1, 3, "REVOKED");
  database.prepare("insert into oauth_connector_retirement_receipts values (?, ?, ?)")
    .run("binding-old", "connector-retirement-old", "REFERENCE_ZERO");
  const receipt = proof.connectorActivationReceipt;
  database.prepare(`
    insert into oauth_connector_activation_receipts values
      (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `).run(
    receipt.receiptId,
    receipt.tuple.canonicalName,
    receipt.tuple.candidateBindingId,
    receipt.tuple.clientId,
    receipt.tuple.installationEpoch,
    receipt.tuple.schemaGeneration,
    receipt.tuple.authorityContractGeneration,
    receipt.tuple.redirectUrisDigest,
    receipt.tuple.buildDigest,
    receipt.tupleDigest,
    receipt.preimageDigest,
    receipt.previousActiveBindingId,
    receipt.ownerAuthorityId,
    receipt.drainDeadlineAt,
    receipt.refreshAllowedDuringDrain ? 1 : 0,
    receipt.status,
    receipt.preparedAt,
    receipt.activatedAt,
  );
  const authority = receipt.activationAuthority;
  database.prepare(`
    insert into oauth_connector_activation_authorities values
      (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `).run(
    authority.actionClaimId, authority.receiptId, authority.authorityId,
    authority.principalKeyFingerprint, authority.actionFingerprint, authority.resourceKeySha256,
    authority.fencingToken, authority.risk, authority.claimState, authority.approvalAssurance,
    authority.canonicalName, authority.tupleDigest, authority.activePreimageDigest,
    authority.finalizationPlanDigest, authority.evidenceDigest, authority.claimedAtMs,
    authority.dispatchedAtMs, authority.proofDigest, authority.consumedAt,
  );
  database.close();
  chmodSync(path, 0o600);
}

function createLiveAuthorityFixture(
  path,
  activationReadback,
  postReadback,
  postActionId,
  postTaskInstanceId,
) {
  const database = new Database(path);
  database.exec(`
    create table operation_authority_actions (
      authority_id text, action_id text, tool text, operation text
    );
    create table operation_authority_claims (
      authority_id text, action_claim_id text, action_id text, task_instance_id text,
      principal_key_fingerprint text, action_fingerprint text, resource_key_sha256 text,
      fencing_token integer, claimed_at_ms integer, dispatched_at_ms integer,
      completed_at_ms integer, state text, provider_call_count integer,
      error_code text, reason_code text
    );
    create table operation_authority_resource_leases (
      resource_key_sha256 text, action_claim_id text, fencing_token integer, lease_state text
    );
  `);
  const rows = [
    {
      readback: activationReadback,
      actionId: `action_${activationReadback.actionFingerprint}`,
      taskInstanceId: "task-instance-activation-finalization",
    },
    { readback: postReadback, actionId: postActionId, taskInstanceId: postTaskInstanceId },
  ];
  for (const { readback, actionId, taskInstanceId } of rows) {
    database.prepare("insert into operation_authority_actions values (?, ?, ?, ?)")
      .run(readback.authorityId, actionId, readback.tool, readback.operation);
    database.prepare(`
      insert into operation_authority_claims values
        (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, null, null)
    `).run(
      readback.authorityId, readback.actionClaimId, actionId, taskInstanceId,
      readback.principalKeyFingerprint, readback.actionFingerprint, readback.resourceKeySha256,
      readback.fencingToken, readback.claimedAtMs, readback.dispatchedAtMs,
      readback.completedAtMs, "PASS", 1,
    );
    database.prepare("insert into operation_authority_resource_leases values (?, ?, ?, ?)")
      .run(readback.resourceKeySha256, readback.actionClaimId, readback.fencingToken, "RELEASED");
  }
  database.close();
  chmodSync(path, 0o600);
}

function createLiveJournalFixture(path, proof) {
  const journal = proof.connectorJournalReadback;
  const store = new SqliteConnectorActivationRecoveryJournal({
    storePath: path,
    now: () => proof.postActivationHostCanaryReceipt.payload.observedAtMs,
  });
  const binding = {
    receiptId: journal.receiptId,
    canonicalName: proof.activeConnector.canonicalName,
    tupleDigest: proof.connectorActivationReceipt.tupleDigest,
    activePreimageDigest: proof.connectorActivationReceipt.preimageDigest,
    finalizationPlanDigest: proof.connectorActivationReceipt.activationAuthority.finalizationPlanDigest,
  };
  const intent = {
    schema: "devspace.connector_activation_recovery_intent",
    schemaVersion: 1,
    state: "INTENT_RESERVED",
    approvalId: journal.approvalId,
    freshHostReceiptId: journal.freshHostReceiptId,
    principalKeyFingerprint: journal.principalKeyFingerprint,
    actionFingerprint: journal.actionFingerprint,
    resourceKeySha256: journal.resourceKeySha256,
    evidenceDigest: journal.pendingEvidenceDigest,
    ...binding,
  };
  store.reserve(intent);
  const handle = {
    schema: "devspace.connector_activation_recovery",
    schemaVersion: 1,
    approvalId: journal.approvalId,
    freshHostReceiptId: journal.freshHostReceiptId,
    authorityId: journal.authorityId,
    principalKeyFingerprint: journal.principalKeyFingerprint,
    actionFingerprint: journal.actionFingerprint,
    resourceKeySha256: journal.resourceKeySha256,
    evidenceDigest: journal.pendingEvidenceDigest,
    ...binding,
  };
  store.record({ ...handle, dispatchState: "NOT_CLAIMED" });
  store.record({
    ...handle,
    dispatchState: "CLAIMED",
    actionClaimId: journal.actionClaimId,
    fencingToken: journal.fencingToken,
    claimedAtMs: proof.connectorActivationReceipt.activationAuthority.claimedAtMs,
  });
  store.record({
    ...handle,
    dispatchState: "DISPATCHED",
    actionClaimId: journal.actionClaimId,
    fencingToken: journal.fencingToken,
    claimedAtMs: proof.connectorActivationReceipt.activationAuthority.claimedAtMs,
    dispatchedAtMs: proof.connectorActivationReceipt.activationAuthority.dispatchedAtMs,
  });
  const key = {
    principalKeyFingerprint: journal.principalKeyFingerprint,
    approvalId: journal.approvalId,
    receiptId: journal.receiptId,
  };
  store.markTerminal(key, {
    state: "ACTIVATED_PENDING_POSTCHECK",
    evidenceDigest: journal.pendingEvidenceDigest,
  });
  store.markTerminal(key, {
    state: "POST_ACTIVATION_VERIFIED",
    evidenceDigest: journal.postActivationEvidenceDigest,
  });
  const identity = store.identity();
  const entry = store.load(key);
  store.close();
  proof.connectorJournalReadback.storeId = identity.storeId;
  proof.connectorJournalReadback.contentGeneration = identity.contentGeneration;
  proof.connectorJournalReadback.postActivationRecordedAtMs = entry.outcomes[1].recordedAtMs;
}

function mutateJournalPostTimestamp(path, delta) {
  const database = new Database(path);
  const trigger = database.prepare(`
    select sql from sqlite_master
     where type = 'trigger' and name = 'connector_activation_journal_outcomes_no_update'
  `).get()?.sql;
  assert.equal(typeof trigger, "string");
  database.exec("drop trigger connector_activation_journal_outcomes_no_update");
  database.prepare(`
    update connector_activation_journal_outcomes
       set recorded_at_ms = recorded_at_ms + ? where state = 'POST_ACTIVATION_VERIFIED'
  `).run(delta);
  database.exec(trigger);
  database.close();
  chmodSync(path, 0o600);
}

function fixtureAuthorityReceiptDigest(readback, actionId, taskInstanceId) {
  return fixtureDigest({
    schemaVersion: 1,
    authorityId: readback.authorityId,
    actionClaimId: readback.actionClaimId,
    useId: readback.actionClaimId,
    actionId,
    taskInstanceId,
    principalKeyFingerprint: readback.principalKeyFingerprint,
    actionFingerprint: readback.actionFingerprint,
    resourceKeySha256: readback.resourceKeySha256,
    fencingToken: readback.fencingToken,
    claimedAtMs: readback.claimedAtMs,
    reservedAtMs: readback.claimedAtMs,
    dispatchedAtMs: readback.dispatchedAtMs,
    completedAtMs: readback.completedAtMs,
    state: "PASS",
    result: "PASS",
    leaseState: "RELEASED",
    providerCallCount: 1,
  });
}

function authorityReadback({ authority, tool, operation, receiptDigest, completedAtMs }) {
  return {
    authorityId: authority.authorityId,
    actionClaimId: authority.actionClaimId,
    actionFingerprint: authority.actionFingerprint,
    resourceKeySha256: authority.resourceKeySha256,
    fencingToken: authority.fencingToken,
    principalKeyFingerprint: authority.principalKeyFingerprint,
    tool,
    operation,
    claimedAtMs: authority.claimedAtMs,
    dispatchedAtMs: authority.dispatchedAtMs,
    completedAtMs,
    state: "PASS",
    result: "PASS",
    leaseState: "RELEASED",
    providerCallCount: 1,
    receiptDigest,
  };
}

function fixtureDigest(value) {
  return `sha256:${sha256(canonicalJson(value))}`;
}

function fixtureTextDigest(value) {
  return `sha256:${sha256(String(value))}`;
}

function runParallelPreflight(release, ownerDirectory, audit) {
  return spawnSync("/bin/bash", [
    join(repositoryRoot, "scripts", "deploy-universal-broker-v2-parallel.sh"),
    "--release-package", release,
    "--runtime-root", release,
    "--identity-directory", ownerDirectory,
    "--audit", audit,
    "--verify-only",
  ], {
    encoding: "utf8",
    env: { ...process.env, PATH: `${nodeDirectory}:${process.env.PATH ?? ""}` },
    timeout: 30_000,
  });
}

function fixtureDriverSource() {
  return `#!/usr/bin/env node
import { appendFileSync, existsSync, readFileSync, unlinkSync } from "node:fs";
const [operation, stageId, contextPath] = process.argv.slice(2);
const context = JSON.parse(readFileSync(contextPath, "utf8"));
const prepare = JSON.parse(readFileSync(context.preparePath, "utf8"));
const stage = prepare.destructivePlan.find((entry) => entry.id === stageId);
if (operation === "final-readback") {
  const complete = prepare.destructivePlan.every((entry) => !existsSync(entry.target));
  const proof = process.env.DRIVER_FINAL_READBACK ? JSON.parse(readFileSync(process.env.DRIVER_FINAL_READBACK, "utf8")) : {};
  console.log(JSON.stringify({ ...proof, complete: complete && proof.complete !== false }));
  process.exit(complete && proof.complete !== false ? 0 : 1);
}
if (!stage) process.exit(2);
if (operation === "readback") {
  const complete = !existsSync(stage.target);
  console.log(JSON.stringify({ complete, target: stage.target }));
  process.exit(complete ? 0 : 1);
}
if (operation === "apply") {
  appendFileSync(process.env.DRIVER_LOG, stage.id + "\\n");
  if (existsSync(stage.target)) unlinkSync(stage.target);
  console.log(JSON.stringify({ complete: true, target: stage.target }));
  process.exit(0);
}
process.exit(2);
`;
}

async function assertReleaseVerifierRunsRev3NfrGate() {
  const source = await readFile(join(repositoryRoot, "scripts", "verify-universal-broker-v2-release.mjs"), "utf8");
  for (const marker of [
    "runRevision3NfrReleaseGate",
    "preStageRevision3NfrEvidence",
    'releaseMode === "release"',
    'gate: "G08"',
    'status: "NOT_RUN"',
    'status: releaseMode === "release" ? "PASS" : "PRE_STAGE_PASS"',
    'finalReleaseEligible: releaseMode === "release"',
    'const reportAt = optionValue("--report")',
    "Release verification report already exists",
    "scripts/check-universal-broker-rev3-nfr.mjs",
    "--mode=release",
    "--json",
    "DEVSPACE_REV3_NFR_PUBLIC_BASE_URL",
    "DEVSPACE_REV3_NFR_MANAGEMENT_BASE_URL",
    "DEVSPACE_REV3_NFR_SELF_RESTART_EVIDENCE",
    "BASE_PROFILE_NFR_PASS",
    "releaseEligible",
    "releaseBlockers",
    "NOT_RUN",
    "LIMITED_PASS",
    "FAIL",
  ]) {
    assert.ok(source.includes(marker), `release verifier must run and validate the Rev3 NFR release gate marker: ${marker}`);
  }
}

async function writeJson(path, value) {
  await mkdir(dirname(path), { recursive: true });
  await writeFile(path, `${JSON.stringify(value, null, 2)}\n`);
}
