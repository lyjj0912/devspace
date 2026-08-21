import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";
import { sourceGateEnvironment } from "./lib/source-gate-environment.mjs";

const scriptsRoot = dirname(fileURLToPath(import.meta.url));

test("source gates remove every inherited DevSpace runtime value and preserve ordinary process context", () => {
  const source = {
    PATH: "/usr/bin:/bin",
    HOME: "/tmp/home",
    CI: "1",
    DEVSPACE_V2_DEPLOYMENT_MODE: "production",
    DEVSPACE_OAUTH_CANONICAL_CONNECTOR_NAME: "must-not-leak",
    DEVSPACE_TEST_FIXTURE: "must-also-not-leak",
  };
  assert.deepEqual(sourceGateEnvironment(source), {
    PATH: "/usr/bin:/bin",
    HOME: "/tmp/home",
    CI: "1",
  });
});

test("the Personal release verifier executes its source gate with the sanitized environment", async () => {
  const source = await readFile(
    join(scriptsRoot, "verify-personal-direct-owner-release.mjs"),
    "utf8",
  );
  assert.match(source, /sourceGateEnvironment\(process\.env\)/u);
  assert.match(source, /env: sourceEnvironment/u);
  assert.doesNotMatch(source, /env: process\.env/u);
  assert.match(source, /PERSONAL_DIRECT_OWNER_SOURCE_GATE/u);
  assert.match(source, /sourceTreeDigest/u);
  assert.match(source, /--report/u);
});
