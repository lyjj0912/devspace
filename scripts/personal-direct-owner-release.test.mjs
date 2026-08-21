import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import {
  chmod,
  mkdir,
  mkdtemp,
  readFile,
  rm,
  stat,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import {
  createPersonalReleasePackage,
  verifyPersonalReleasePackage,
  verifyPersonalReleaseRuntimeIdentity,
} from "./personal-direct-owner-release.mjs";

const tools = ["target", "context", "fs", "exec", "process", "mcp", "artifact", "gui"];
const schemaGeneration = `sha256:${"5".repeat(64)}`;

test("Personal source-gate receipt creates and verifies one immutable release package", async (t) => {
  const fixture = await releaseFixture(t);
  const output = join(fixture.root, "release");
  const created = await createPersonalReleasePackage({
    sourceRoot: fixture.source,
    outputRoot: output,
    sourceGateReport: fixture.sourceGate,
    sourceRevision: fixture.revision,
    runtimeRevision: fixture.revision,
  });
  assert.equal(created.status, "CREATED");
  assert.equal(created.productProfile, "PERSONAL_DIRECT_OWNER");
  assert.equal(created.sourceRevision, fixture.revision);
  assert.equal(created.runtimeRevision, fixture.revision);
  assert.match(created.buildDigest, /^sha256:[a-f0-9]{64}$/u);
  assert.equal(created.schemaGeneration, schemaGeneration);
  assert.equal(await mode(output), "700");
  assert.equal(await mode(join(output, "BUILD-MANIFEST.json")), "600");
  assert.equal(await mode(join(output, "SOURCE-GATE.json")), "600");
  assert.equal(await mode(join(output, "SHA256SUMS")), "600");

  const verified = await verifyPersonalReleasePackage({
    packageRoot: output,
    dependencyRoot: fixture.dependency,
    dependencyEvidence: fixture.dependencyEvidence,
    dependencyEvidenceSha256: fixture.dependencyEvidenceSha256,
    manifestSha256: created.manifestSha256,
    sourceRevision: fixture.revision,
    runtimeRevision: fixture.revision,
  });
  assert.equal(verified.status, "PASS");
  assert.equal(verified.buildDigest, created.buildDigest);
  assert.equal(verified.sourceTreeDigest, fixture.sourceTreeDigest);

  const identityPath = join(fixture.root, "runtime-identity.json");
  await writeFile(identityPath, `${JSON.stringify({
    identity: {
      productProfile: "PERSONAL_DIRECT_OWNER",
      sourceRevision: fixture.revision,
      runtimeRevision: fixture.revision,
      buildDigest: created.buildDigest,
      schemaGeneration,
    },
  })}\n`, { mode: 0o600 });
  assert.equal((await verifyPersonalReleaseRuntimeIdentity({
    packageRoot: output,
    identityPath,
  })).status, "PASS");

  await writeFile(join(output, "dist", "cli.js"), "tampered\n");
  await assert.rejects(
    verifyPersonalReleasePackage({
      packageRoot: output,
      dependencyRoot: fixture.dependency,
      dependencyEvidence: fixture.dependencyEvidence,
      dependencyEvidenceSha256: fixture.dependencyEvidenceSha256,
    }),
    /SHA256SUMS mismatch|package content differs/u,
  );
});

test("Personal release creation rejects dirty source and stale source-gate receipts", async (t) => {
  const dirty = await releaseFixture(t, "dirty");
  await writeFile(join(dirty.source, "scripts", "untracked.txt"), "dirty\n");
  await assert.rejects(
    createPersonalReleasePackage({
      sourceRoot: dirty.source,
      outputRoot: join(dirty.root, "dirty-release"),
      sourceGateReport: dirty.sourceGate,
      sourceRevision: dirty.revision,
      runtimeRevision: dirty.revision,
    }),
    /clean source tree/u,
  );

  const stale = await releaseFixture(t, "stale");
  const receipt = JSON.parse(await readFile(stale.sourceGate, "utf8"));
  receipt.sourceTreeDigest = `sha256:${"0".repeat(64)}`;
  await writeFile(stale.sourceGate, `${JSON.stringify(receipt)}\n`, { mode: 0o600 });
  await assert.rejects(
    createPersonalReleasePackage({
      sourceRoot: stale.source,
      outputRoot: join(stale.root, "stale-release"),
      sourceGateReport: stale.sourceGate,
      sourceRevision: stale.revision,
      runtimeRevision: stale.revision,
    }),
    /does not match the clean source tree/u,
  );
});

async function releaseFixture(t, suffix = "valid") {
  const root = await mkdtemp(join(tmpdir(), `devspace-personal-release-${suffix}-`));
  const source = join(root, "source");
  const dependency = join(root, "dependency");
  const sourceGate = join(root, "source-gate.json");
  const dependencyEvidence = join(root, "dependency-evidence.json");
  t.after(() => rm(root, { recursive: true, force: true }));
  await mkdir(source, { recursive: true });
  await mkdir(join(source, "contracts"), { recursive: true });
  await mkdir(join(source, "config"), { recursive: true });
  await mkdir(join(source, "scripts"), { recursive: true });
  await mkdir(join(source, "skills"), { recursive: true });
  await mkdir(join(source, "dist", "v2"), { recursive: true });
  await writeFile(join(source, ".gitignore"), "dist/\n");
  await writeFile(join(source, "package.json"), `${JSON.stringify({
    name: "personal-release-fixture",
    version: "1.0.0",
  })}\n`);
  await writeFile(join(source, "package-lock.json"), `${JSON.stringify({
    name: "personal-release-fixture",
    version: "1.0.0",
    lockfileVersion: 3,
    packages: {},
  })}\n`);
  const buildCapabilitySchema = {
    type: "object",
    properties: {
      productVersion: { const: "2.1.1" },
      productProfile: { const: "PERSONAL_DIRECT_OWNER" },
      schemaGeneration: { type: "string" },
      supportedProfiles: { const: ["PERSONAL_DIRECT_OWNER"] },
      supportedOperations: {
        type: "object",
        properties: Object.fromEntries(tools.map((name) => [name, { const: ["fixture"] }])),
      },
      resourceUriVersion: { const: "v1" },
    },
  };
  await writeFile(
    join(source, "contracts", "build-capabilities.schema.json"),
    `${JSON.stringify(buildCapabilitySchema)}\n`,
  );
  await writeFile(join(source, "contracts", "tools-v2.schema.json"), "{}\n");
  await writeFile(join(source, "config", "config.schema.json"), "{}\n");
  await writeFile(
    join(source, "scripts", "start-universal-broker-v2-production.sh"),
    "#!/bin/sh\nexit 0\n",
    { mode: 0o755 },
  );
  await writeFile(join(source, "skills", "index.json"), "{}\n");
  await writeFile(join(source, "dist", "cli.js"), "export {};\n");
  await writeFile(
    join(source, "dist", "v2", "runtime-contract-identity.js"),
    `export const RUNTIME_SCHEMA_GENERATION = ${JSON.stringify(schemaGeneration)};\n`,
  );
  run(source, "git", ["init", "-q"]);
  run(source, "git", ["config", "user.name", "Release Fixture"]);
  run(source, "git", ["config", "user.email", "release@example.invalid"]);
  run(source, "git", ["add", "."]);
  run(source, "git", ["commit", "-qm", "fixture"]);
  const revision = capture(source, "git", ["rev-parse", "HEAD"]).trim();
  const sourceTreeDigest = digest(Buffer.from(capture(source, "git", [
    "ls-tree",
    "-r",
    "--full-tree",
    revision,
  ])));
  const sourceGateReceipt = {
    schemaVersion: 1,
    kind: "PERSONAL_DIRECT_OWNER_SOURCE_GATE",
    status: "PASS",
    productProfile: "PERSONAL_DIRECT_OWNER",
    sourceRevision: revision,
    sourceTreeDigest,
    packageLockSha256: digest(await readFile(join(source, "package-lock.json"))),
    buildCapabilitiesSchemaSha256: digest(
      await readFile(join(source, "contracts", "build-capabilities.schema.json")),
    ),
    toolsSchemaSha256: digest(await readFile(join(source, "contracts", "tools-v2.schema.json"))),
    nodeVersion: process.version,
    platform: `${process.platform}-${process.arch}`,
    gateCommand: "fixture",
    cleanRequired: true,
    completedAt: new Date().toISOString(),
  };
  await writeFile(sourceGate, `${JSON.stringify(sourceGateReceipt, null, 2)}\n`, { mode: 0o600 });
  await chmod(sourceGate, 0o600);

  await mkdir(join(dependency, "node_modules"), { recursive: true });
  await writeFile(join(dependency, "package-lock.json"), await readFile(join(source, "package-lock.json")));
  const dependencyReceipt = {
    nodeVersion: process.version,
    platform: `${process.platform}-${process.arch}`,
    lockfileSha256: digest(await readFile(join(source, "package-lock.json"))),
    nodeModules: { sha256: `sha256:${"8".repeat(64)}` },
  };
  await writeFile(
    dependencyEvidence,
    `${JSON.stringify(dependencyReceipt)}\n`,
    { mode: 0o600 },
  );
  await chmod(dependencyEvidence, 0o600);
  return {
    root,
    source,
    dependency,
    sourceGate,
    dependencyEvidence,
    dependencyEvidenceSha256: digest(await readFile(dependencyEvidence)),
    revision,
    sourceTreeDigest,
  };
}

function run(cwd, command, args) {
  const result = spawnSync(command, args, { cwd, encoding: "utf8", stdio: "pipe" });
  if (result.error) throw result.error;
  assert.equal(result.status, 0, result.stderr);
}

function capture(cwd, command, args) {
  const result = spawnSync(command, args, { cwd, encoding: "utf8", stdio: "pipe" });
  if (result.error) throw result.error;
  assert.equal(result.status, 0, result.stderr);
  return result.stdout;
}

async function mode(path) {
  return ((await stat(path)).mode & 0o777).toString(8).padStart(3, "0");
}

function digest(value) {
  return `sha256:${createHash("sha256").update(value).digest("hex")}`;
}
