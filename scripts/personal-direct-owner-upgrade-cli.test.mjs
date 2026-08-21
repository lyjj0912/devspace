import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { promisify } from "node:util";
import { test } from "node:test";
import { personalProductionStartArguments } from "./lib/personal-upgrade-process.mjs";

const execute = promisify(execFile);

test("packaged personal upgrade CLI resolves its compiled planner", async (t) => {
  const root = await mkdtemp(join(tmpdir(), "devspace-personal-upgrade-cli-"));
  t.after(() => rm(root, { recursive: true, force: true }));
  const identity = {
    publicOrigin: "https://devspace.example.test",
    oauthClientId: "client-existing",
    oauthResource: "https://devspace.example.test/mcp",
    ownerInstanceId: "owner-existing",
    connectorName: "myDevSpace",
    connectorInstallationEpoch: 3,
  };
  const requestPath = join(root, "request.json");
  await writeFile(requestPath, JSON.stringify({
    upgrade: {
      existing: {
        ...identity,
        productProfile: "BASE_SINGLE_OWNER",
        runtimePath: join(root, "old-runtime"),
      },
      candidate: {
        ...identity,
        productProfile: "PERSONAL_DIRECT_OWNER",
        runtimePath: join(root, "new-runtime"),
        sourceRevision: "a".repeat(40),
        runtimeRevision: "a".repeat(40),
        buildDigest: `sha256:${"b".repeat(64)}`,
      },
      stores: [],
      currentRuntimePointer: join(root, "current"),
    },
  }));
  const { stdout } = await execute(process.execPath, [
    "scripts/personal-direct-owner-upgrade.mjs",
    "plan",
    "--request",
    requestPath,
  ]);
  const plan = JSON.parse(stdout);
  assert.equal(plan.productProfile, "PERSONAL_DIRECT_OWNER");
  assert.equal(plan.identityAction, "PRESERVE_EXISTING_BINDING");
  assert.deepEqual(plan.backupSet, []);
});

test("personal production PM2 identity uses the real immutable runtime rather than the current pointer", () => {
  const runtime = "/Users/example/.devspace/releases/universal-broker-v2/revision-personal-direct-owner";
  assert.deepEqual(personalProductionStartArguments(runtime, "devspace-v2-production"), [
    `${runtime}/scripts/start-universal-broker-v2-production.sh`,
    "--name",
    "devspace-v2-production",
    "--cwd",
    runtime,
  ]);
});
