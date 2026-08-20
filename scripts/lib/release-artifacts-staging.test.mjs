import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdtempSync, realpathSync, rmSync } from "node:fs";
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
  } finally {
    rmSync(temporaryRoot, { recursive: true, force: true });
  }
});
