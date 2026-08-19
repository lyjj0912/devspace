import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { chmod, mkdir, mkdtemp, readFile, rm, stat, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { ensureOwnerInstanceId } from "./lib/owner-instance-id.mjs";
import { createReleasePackage, verifyReleasePackage } from "./lib/release-artifacts.mjs";
import { verifyFinalizationDirectory } from "./lib/finalization-state.mjs";

const scriptsRoot = dirname(fileURLToPath(import.meta.url));
const repositoryRoot = dirname(scriptsRoot);
const nodeDirectory = dirname(process.execPath);
const root = await mkdtemp(join(tmpdir(), "devspace-release-finalization-"));

try {
  const source = join(root, "source");
  const release = join(root, "release");
  await createFixtureSource(source);
  const sourceRevision = "0123456789abcdef0123456789abcdef01234567";
  const created = createReleasePackage({
    sourceRoot: source,
    outputRoot: release,
    sourceRevision,
    runtimeRevision: sourceRevision,
    createdAt: "2026-08-19T00:00:00.000Z",
  });
  const packageEvidence = verifyReleasePackage(release, {
    expectedSourceRevision: sourceRevision,
    expectedRuntimeRevision: sourceRevision,
  });
  assert.equal(packageEvidence.status, "PASS");
  assert.equal(created.manifest.buildDigest, packageEvidence.buildDigest);

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
  assert.equal(firstDeployPreflight.status, 0, firstDeployPreflight.stderr);
  assert.equal(secondDeployPreflight.status, 0, secondDeployPreflight.stderr);
  assert.equal(JSON.parse(firstDeployPreflight.stdout).ownerInstanceId, firstOwner);
  assert.equal(JSON.parse(secondDeployPreflight.stdout).ownerInstanceId, firstOwner);

  const runtimeIdentity = {
    sourceRevision,
    runtimeRevision: sourceRevision,
    buildDigest: packageEvidence.buildDigest,
    schemaGeneration: packageEvidence.schemaGeneration,
    authorityContractGeneration: packageEvidence.authorityContractGeneration,
    configDigest: `sha256:${"d".repeat(64)}`,
    configSchemaIdentity: packageEvidence.configSchemaIdentity,
  };
  const driver = join(root, "fixture-driver.mjs");
  await writeFile(driver, fixtureDriverSource(), { mode: 0o700 });
  await chmod(driver, 0o700);
  const driverLog = join(root, "driver.log");
  const externalTarget = join(root, "temporary-one-shot.env");
  await writeFile(externalTarget, "temporary\n", { mode: 0o600 });
  const audit = join(root, "audit");
  await mkdir(audit, { recursive: true, mode: 0o700 });
  const prepareEvidencePath = join(root, "prepare-evidence.json");
  await writeJson(prepareEvidencePath, prepareEvidence(release, runtimeIdentity, externalTarget));

  const prepareResult = runFinalizer("prepare", audit, prepareEvidencePath, driver, { DRIVER_LOG: driverLog });
  assert.equal(prepareResult.status, 0, prepareResult.stderr);
  assert.equal(await readFile(externalTarget, "utf8"), "temporary\n", "prepare must not mutate planned targets");
  await assert.rejects(readFile(driverLog, "utf8"), /ENOENT/u, "prepare must not invoke the seal driver");
  const resumedPrepare = runFinalizer("prepare", audit, prepareEvidencePath, driver, { DRIVER_LOG: driverLog });
  assert.equal(resumedPrepare.status, 0, resumedPrepare.stderr);
  assert.equal(JSON.parse(resumedPrepare.stdout).resumed, true);

  const sealEvidencePath = join(root, "seal-evidence.json");
  await writeJson(sealEvidencePath, sealEvidence(runtimeIdentity));
  const interrupted = runFinalizer("seal", audit, sealEvidencePath, driver, {
    DRIVER_LOG: driverLog,
    INTERRUPT_STAGE: "cleanup-temporary-artifact",
  }, "cleanup-temporary-artifact");
  assert.equal(interrupted.status, 75, interrupted.stderr);
  await assert.rejects(readFile(externalTarget, "utf8"), /ENOENT/u);
  assert.equal((await readFile(driverLog, "utf8")).trim().split("\n").length, 1);

  const resumedSeal = runFinalizer("seal", audit, sealEvidencePath, driver, { DRIVER_LOG: driverLog });
  assert.equal(resumedSeal.status, 0, resumedSeal.stderr);
  assert.equal(JSON.parse(resumedSeal.stdout).status, "FINAL_PASS");
  assert.equal((await readFile(driverLog, "utf8")).trim().split("\n").length, 1, "completed destructive action must not repeat");
  assert.equal(verifyFinalizationDirectory(join(audit, "finalization")).status, "FINAL_PASS");

  const staleAudit = join(root, "stale-audit");
  const staleTarget = join(root, "stale-temp.env");
  await mkdir(staleAudit, { recursive: true, mode: 0o700 });
  await writeFile(staleTarget, "keep\n", { mode: 0o600 });
  const stalePreparePath = join(root, "stale-prepare.json");
  await writeJson(stalePreparePath, prepareEvidence(release, runtimeIdentity, staleTarget));
  assert.equal(runFinalizer("prepare", staleAudit, stalePreparePath, driver, { DRIVER_LOG: driverLog }).status, 0);
  const staleSealPath = join(root, "stale-seal.json");
  const staleEvidence = sealEvidence(runtimeIdentity);
  staleEvidence.activeTokenFamily.familyId = "family-stale";
  await writeJson(staleSealPath, staleEvidence);
  const staleResult = runFinalizer("seal", staleAudit, staleSealPath, driver, { DRIVER_LOG: driverLog });
  assert.equal(staleResult.status, 1);
  assert.match(staleResult.stderr, /Stale token family/u);
  assert.equal(await readFile(staleTarget, "utf8"), "keep\n");

  const distPath = join(release, "dist", "server.js");
  const original = await readFile(distPath);
  await writeFile(distPath, Buffer.concat([original, Buffer.from("// tampered\n")]));
  assert.throws(() => verifyReleasePackage(release), /checksum mismatch/u);
  await writeFile(distPath, original);
  assert.equal(verifyReleasePackage(release).status, "PASS");
} finally {
  await rm(root, { recursive: true, force: true });
}
console.log("Release package/finalization tests: PASS");

async function createFixtureSource(source) {
  await mkdir(join(source, "dist"), { recursive: true });
  await mkdir(join(source, "config"), { recursive: true });
  await mkdir(join(source, "contracts"), { recursive: true });
  await mkdir(join(source, "scripts"), { recursive: true });
  await writeFile(join(source, "dist", "server.js"), "export const ready = true;\n");
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
    "tools-v2.schema.json": { $schema: "https://json-schema.org/draft/2020-12/schema", tools: ["target", "context", "fs", "exec", "process", "mcp", "artifact", "gui"] },
    "mcp-risk-policy.schema.json": { $schema: "https://json-schema.org/draft/2020-12/schema", risk: ["R0", "R1", "R2", "R3"] },
    "errors.schema.json": { $schema: "https://json-schema.org/draft/2020-12/schema", errors: ["SCHEMA_STALE"] },
    "targets.schema.json": { $schema: "https://json-schema.org/draft/2020-12/schema", type: "array" },
    "mcp-routes.schema.json": { $schema: "https://json-schema.org/draft/2020-12/schema", type: "array" },
    "capabilities.schema.json": { $schema: "https://json-schema.org/draft/2020-12/schema", type: "object" },
  };
  for (const [name, value] of Object.entries(schemas)) await writeJson(join(source, "contracts", name), value);
  await writeFile(join(source, "scripts", "start-universal-broker-v2-production.sh"), "#!/bin/bash\nexec node dist/server.js\n", { mode: 0o755 });
}

function prepareEvidence(release, runtimeIdentity, temporaryPath) {
  return {
    schemaVersion: 1,
    status: "PASS",
    phase: "production-reconnect",
    releasePackage: release,
    runtimeIdentity,
    inventories: {
      processes: [],
      listeners: [],
      routes: [],
      oauth: [{ familyId: "family-old", status: "ACTIVE" }],
      connectors: [{ bindingId: "binding-current", canonicalName: "myDevSpace", state: "ACTIVE" }],
      temporaryArtifacts: [{ path: temporaryPath }],
    },
    expectedCanary: { toolNames: ["target", "context", "fs", "exec", "process", "mcp", "artifact", "gui"] },
    canonicalConnector: { name: "myDevSpace", bindingId: "binding-old", installationEpoch: 1 },
    destructivePlan: [{
      id: "cleanup-temporary-artifact",
      destructive: true,
      operation: "fixture-delete",
      target: temporaryPath,
    }],
    preimages: [],
  };
}

function sealEvidence(runtimeIdentity) {
  return {
    schemaVersion: 1,
    status: "PASS",
    phase: "post-rotation",
    runtimeIdentity,
    toolNames: ["target", "context", "fs", "exec", "process", "mcp", "artifact", "gui"],
    freshHostCanary: true,
    targetInventoryDigest: `sha256:${"a".repeat(64)}`,
    activeTokenFamily: {
      familyId: "family-current",
      clientId: "client-current",
      connectorBindingId: "binding-current",
      installationEpoch: 2,
      drainEpoch: 4,
      status: "ACTIVE",
    },
    activeConnector: {
      canonicalName: "myDevSpace",
      bindingId: "binding-current",
      clientId: "client-current",
      tokenFamilyId: "family-current",
      installationEpoch: 2,
      drainEpoch: 4,
      schemaGeneration: runtimeIdentity.schemaGeneration,
      refCount: 1,
      state: "ACTIVE",
    },
    retiredConnectors: [{ bindingId: "binding-old", state: "DRAINED", refCount: 0 }],
    revokedTokenFamilyIds: ["family-old"],
    assurance: "HOST_ATTESTED_AUTHORITY",
  };
}

function runFinalizer(command, audit, evidence, driver, extraEnvironment, interruptAfterAction) {
  const arguments_ = [
    join(repositoryRoot, "scripts", "finalize-universal-broker-v2-production.sh"),
    command,
    "--audit", audit,
    "--evidence", evidence,
    "--driver", driver,
  ];
  if (interruptAfterAction) arguments_.push("--interrupt-after-action", interruptAfterAction);
  return spawnSync("/bin/bash", arguments_, {
    encoding: "utf8",
    env: { ...process.env, PATH: `${nodeDirectory}:${process.env.PATH ?? ""}`, ...extraEnvironment },
    timeout: 30_000,
  });
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
  console.log(JSON.stringify({ complete }));
  process.exit(complete ? 0 : 1);
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

async function writeJson(path, value) {
  await mkdir(dirname(path), { recursive: true });
  await writeFile(path, `${JSON.stringify(value, null, 2)}\n`);
}
