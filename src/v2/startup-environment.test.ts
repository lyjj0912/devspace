import assert from "node:assert/strict";
import { chmod, mkdtemp, mkdir, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { spawnSync } from "node:child_process";
import test from "node:test";

const startupScript = resolve("scripts/start-universal-broker-v2.sh");

test("startup environment file overrides and removes inherited DevSpace variables", async (t) => {
  const fixture = await createFixture(t, [
    "DEVSPACE_V2_DEPLOYMENT_MODE=production",
    "DEVSPACE_NEXT_PORT=17678",
    "DEVSPACE_NEXT_PM2_EXPECTED_SCRIPT=/from-file/start.sh",
    "DEVSPACE_CONFIG_DIR=/from-file/config",
  ]);
  const result = spawnSync("/bin/bash", [startupScript], {
    encoding: "utf8",
    env: {
      ...process.env,
      HOME: fixture.root,
      PATH: `${fixture.bin}:${process.env.PATH ?? "/usr/bin:/bin"}`,
      DEVSPACE_NEXT_ENV_FILE: fixture.environmentFile,
      DEVSPACE_V2_DEPLOYMENT_MODE: "parallel",
      DEVSPACE_V2_LEGACY_SCOPE_COMPATIBILITY: "true",
      DEVSPACE_NEXT_PORT: "9999",
      DEVSPACE_NEXT_STALE_VALUE: "must-not-survive",
      DEVSPACE_NEXT_PM2_EXPECTED_SCRIPT: "/inherited/start.sh",
      DEVSPACE_OAUTH_OWNER_TOKEN: "must-not-survive",
    },
  });
  assert.equal(result.status, 0, result.stderr);
  assert.deepEqual(parseOutput(result.stdout), {
    deployment: "production",
    port: "17678",
    legacy: "<unset>",
    stale: "<unset>",
    ownerToken: "<unset>",
    configDir: "/from-file/config",
    expectedScript: "/from-file/start.sh",
    args: `--import ${resolve("scripts/lib/runtime-dependency-loader.mjs")} ${resolve("dist/cli.js")} serve-next`,
  });
});

test("startup preserves only the production wrapper expected-script fallback when the file omits it", async (t) => {
  const fixture = await createFixture(t, [
    "DEVSPACE_V2_DEPLOYMENT_MODE=production",
    "DEVSPACE_NEXT_PORT=17679",
  ]);
  const result = spawnSync("/bin/bash", [startupScript], {
    encoding: "utf8",
    env: {
      ...process.env,
      HOME: fixture.root,
      PATH: `${fixture.bin}:${process.env.PATH ?? "/usr/bin:/bin"}`,
      DEVSPACE_NEXT_ENV_FILE: fixture.environmentFile,
      DEVSPACE_NEXT_PM2_EXPECTED_SCRIPT: "/wrapper/start.sh",
      DEVSPACE_NEXT_STALE_VALUE: "must-not-survive",
    },
  });
  assert.equal(result.status, 0, result.stderr);
  const output = parseOutput(result.stdout);
  assert.equal(output.expectedScript, "/wrapper/start.sh");
  assert.equal(output.stale, "<unset>");
  assert.equal(output.port, "17679");
});

async function createFixture(t: test.TestContext, lines: string[]) {
  const root = await mkdtemp(join(tmpdir(), "devspace-v2-startup-environment-test-"));
  t.after(() => rm(root, { recursive: true, force: true }));
  const bin = join(root, "bin");
  await mkdir(bin, { recursive: true });
  const environmentFile = join(root, "runtime.env");
  const productionRuntime = [
    `DEVSPACE_RUNTIME_PACKAGE_ROOT=${resolve(".")}`,
    `DEVSPACE_RUNTIME_DEPENDENCY_ROOT=${join(root, "runtime-dependencies")}`,
    `DEVSPACE_RUNTIME_DEPENDENCY_EVIDENCE=${join(root, "runtime-dependencies.json")}`,
    `DEVSPACE_EXPECTED_RUNTIME_DEPENDENCY_EVIDENCE_SHA256=sha256:${"1".repeat(64)}`,
    `DEVSPACE_RELEASE_MANIFEST=${resolve("BUILD-MANIFEST.json")}`,
    `DEVSPACE_EXPECTED_RELEASE_MANIFEST_SHA256=sha256:${"2".repeat(64)}`,
  ];
  await writeFile(environmentFile, `${[...lines, ...productionRuntime].join("\n")}\n`, { mode: 0o600 });
  await chmod(environmentFile, 0o600);
  const fakeNode = join(bin, "node");
  await writeFile(fakeNode, [
    "#!/bin/bash",
    "set -euo pipefail",
    "if [[ \"${1-}\" == " + JSON.stringify(resolve("scripts/release-artifacts.mjs")) + " ]]; then exit 0; fi",
    "printf 'deployment=%s\\n' \"${DEVSPACE_V2_DEPLOYMENT_MODE-<unset>}\"",
    "printf 'port=%s\\n' \"${DEVSPACE_NEXT_PORT-<unset>}\"",
    "printf 'legacy=%s\\n' \"${DEVSPACE_V2_LEGACY_SCOPE_COMPATIBILITY-<unset>}\"",
    "printf 'stale=%s\\n' \"${DEVSPACE_NEXT_STALE_VALUE-<unset>}\"",
    "printf 'ownerToken=%s\\n' \"${DEVSPACE_OAUTH_OWNER_TOKEN-<unset>}\"",
    "printf 'configDir=%s\\n' \"${DEVSPACE_CONFIG_DIR-<unset>}\"",
    "printf 'expectedScript=%s\\n' \"${DEVSPACE_NEXT_PM2_EXPECTED_SCRIPT-<unset>}\"",
    "printf 'args=%s\\n' \"$*\"",
    "",
  ].join("\n"), { mode: 0o700 });
  await chmod(fakeNode, 0o700);
  return { root, bin, environmentFile };
}

function parseOutput(value: string): Record<string, string> {
  return Object.fromEntries(value.trim().split("\n").map((line) => {
    const separator = line.indexOf("=");
    return [line.slice(0, separator), line.slice(separator + 1)];
  }));
}
