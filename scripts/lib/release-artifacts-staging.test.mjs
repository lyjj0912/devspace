import assert from "node:assert/strict";
import { execFileSync, spawnSync } from "node:child_process";
import { mkdirSync, mkdtempSync, readFileSync, realpathSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import test from "node:test";
import {
  createStagingReleasePackage,
  verifyReleasePackage,
  verifyRuntimeCommand,
  verifyUnattestedReleaseFixture,
  verifiedReleaseManifest,
} from "./release-artifacts.mjs";

test("staging package runs the real metadata collector but remains ineligible for production", () => {
  const sourceRoot = resolve(process.cwd());
  const sourceRevision = execFileSync("/usr/bin/git", ["-C", sourceRoot, "rev-parse", "HEAD"], {
    encoding: "utf8",
  }).trim();
  const temporaryRoot = realpathSync(mkdtempSync(join(tmpdir(), "devspace-staging-package-")));
  const packageRoot = join(temporaryRoot, "package");
  try {
    const created = createStagingReleasePackage({
      sourceRoot,
      outputRoot: packageRoot,
      sourceRevision,
      runtimeRevision: sourceRevision,
    });
    assert.equal(created.eligibility, "UNATTESTED_STAGING_ONLY");

    const fixture = verifyUnattestedReleaseFixture(packageRoot, {
      expectedSourceRevision: sourceRevision,
      expectedRuntimeRevision: sourceRevision,
    });
    assert.equal(fixture.status, "UNATTESTED_FIXTURE_ONLY");
    assert.equal(verifiedReleaseManifest(fixture).gateProducer, null);

    assert.throws(
      () => verifyReleasePackage(packageRoot),
      /verified external gate producer trust anchor is required/iu,
    );
    assert.equal(verifyRuntimeCommand(
      packageRoot,
      packageRoot,
      join(packageRoot, "scripts/start-universal-broker-v2-production.sh"),
      { allowUnattestedFixture: true },
    ).status, "PASS");

    const ownerDirectory = join(temporaryRoot, "identity");
    mkdirSync(ownerDirectory, { mode: 0o700 });
    const personalPreflight = spawnSync("/bin/bash", [
      join(sourceRoot, "scripts", "deploy-universal-broker-v2-parallel.sh"),
      "--release-package", packageRoot,
      "--runtime-root", packageRoot,
      "--identity-directory", ownerDirectory,
      "--audit", join(temporaryRoot, "personal-parallel-audit"),
      "--verify-only",
      "--staging-fixture",
    ], {
      encoding: "utf8",
      env: {
        ...process.env,
        PATH: `${process.execPath.slice(0, process.execPath.lastIndexOf("/"))}:${process.env.PATH ?? ""}`,
      },
    });
    assert.equal(personalPreflight.status, 0, personalPreflight.stderr);
    assert.equal(JSON.parse(personalPreflight.stdout).status, "VERIFIED");

    const productionPreflight = spawnSync("/bin/bash", [
      join(sourceRoot, "scripts", "deploy-universal-broker-v2-parallel.sh"),
      "--release-package", packageRoot,
      "--runtime-root", packageRoot,
      "--identity-directory", ownerDirectory,
      "--audit", join(temporaryRoot, "production-parallel-audit"),
      "--verify-only",
    ], {
      encoding: "utf8",
      env: {
        ...process.env,
        PATH: `${process.execPath.slice(0, process.execPath.lastIndexOf("/"))}:${process.env.PATH ?? ""}`,
      },
    });
    assert.notEqual(productionPreflight.status, 0);
    assert.match(productionPreflight.stderr, /gate producer trust anchor|--state-dir is required/iu);

    const incompleteDependencyRoot = spawnSync("/bin/bash", [
      join(sourceRoot, "scripts", "deploy-universal-broker-v2-parallel.sh"),
      "--release-package", packageRoot,
      "--dependency-root", sourceRoot,
      "--verify-only",
      "--staging-fixture",
    ], { encoding: "utf8" });
    assert.notEqual(incompleteDependencyRoot.status, 0);
    assert.match(incompleteDependencyRoot.stderr, /--dependency-evidence must name an existing file/iu);

    const startSource = readFileSync(join(sourceRoot, "scripts", "start-universal-broker-v2.sh"), "utf8");
    assert.match(startSource, /DEVSPACE_PERSONAL_STAGING_FIXTURE/gu);
    assert.match(startSource, /verify_release_artifact verify-runtime-command/gu);
    assert.match(startSource, /verify_release_artifact verify-runtime-dependencies/gu);
    assert.match(startSource, /DEVSPACE_RUNTIME_DEPENDENCY_ROOT/gu);
  } finally {
    rmSync(temporaryRoot, { recursive: true, force: true });
  }
});
