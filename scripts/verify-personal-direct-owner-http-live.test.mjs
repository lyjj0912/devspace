import assert from "node:assert/strict";
import { spawn, spawnSync } from "node:child_process";
import { mkdtemp, mkdir, readFile, rm, stat, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import test from "node:test";
import { loadConfig } from "../dist/config.js";
import { loadUniversalBrokerNextConfig } from "../dist/v2/config.js";
import { createUniversalBrokerNextServer } from "../dist/v2/http-server.js";
import { createRuntimeIdentity } from "../dist/v2/runtime-identity.js";
import { UniversalSelfManagementService } from "../dist/v2/self-management.js";

const node = process.execPath;
const seeder = resolve("scripts/personal-candidate-oauth-fixture.mjs");
const verifier = resolve("scripts/verify-personal-direct-owner-http-live.mjs");

test("isolated candidate OAuth and real HTTP server pass the deterministic Personal live gate", {
  timeout: 60_000,
}, async (t) => {
  const root = await mkdtemp(join(tmpdir(), "devspace-personal-http-live-"));
  const stateDir = join(root, "state");
  const oauthStateDir = join(root, "oauth");
  const targetConfigPath = join(root, "targets.json");
  const tokenFile = join(root, "candidate-access-token.txt");
  const oauthEvidence = join(root, "candidate-oauth-evidence.json");
  const releasePackage = join(root, "release-package");
  const outputPath = join(root, "http-live-result.json");
  const disposableRoot = join(root, "disposable-live-root");
  const acceptanceRunId = "personal-http-live-fixture-20260822";
  const sourceRevision = "1".repeat(40);
  const runtimeRevision = "2".repeat(40);
  const buildDigest = `sha256:${"3".repeat(64)}`;
  await mkdir(stateDir, { recursive: true, mode: 0o700 });
  await mkdir(oauthStateDir, { recursive: true, mode: 0o700 });
  await mkdir(releasePackage, { recursive: true, mode: 0o700 });
  await writeFile(targetConfigPath, `${JSON.stringify({
    version: 1,
    targets: {
      local: {
        displayName: "Local live fixture",
        aliases: ["local"],
        transport: "local",
        platform: "macos",
        shell: "zsh",
        defaultCwd: root,
      },
    },
  })}\n`, { mode: 0o600 });

  const baseEnvironment = {
    DEVSPACE_CONFIG_DIR: join(root, "config"),
    DEVSPACE_ALLOWED_ROOTS: root,
    DEVSPACE_STATE_DIR: join(root, "legacy-state"),
    DEVSPACE_WORKTREE_ROOT: join(root, "legacy-worktrees"),
    DEVSPACE_OAUTH_OWNER_TOKEN: "personal-live-owner-token-not-a-secret-123456789",
    DEVSPACE_HOST: "127.0.0.1",
    DEVSPACE_PORT: "17676",
    DEVSPACE_PUBLIC_BASE_URL: "http://127.0.0.1:17676",
    DEVSPACE_LOG_LEVEL: "silent",
  };
  const base = loadConfig(baseEnvironment);
  const config = loadUniversalBrokerNextConfig(base, {
    ...baseEnvironment,
    DEVSPACE_V2_DEPLOYMENT_MODE: "production",
    DEVSPACE_NEXT_HOST: "127.0.0.1",
    DEVSPACE_NEXT_PORT: "17676",
    DEVSPACE_NEXT_MANAGEMENT_PORT: "18676",
    DEVSPACE_NEXT_PUBLIC_BASE_URL: "http://127.0.0.1:17676",
    DEVSPACE_NEXT_STATE_DIR: stateDir,
    DEVSPACE_NEXT_OAUTH_STATE_DIR: oauthStateDir,
    DEVSPACE_NEXT_TARGETS_FILE: targetConfigPath,
    DEVSPACE_NEXT_AUDIT_SINK: join(stateDir, "audit", "operations.jsonl"),
    DEVSPACE_NEXT_AUDIT_FLUSH_INTERVAL_MS: "1",
    DEVSPACE_NEXT_AUTHORITY_OWNER_INSTANCE_ID: "personal-http-live-owner",
    DEVSPACE_NEXT_CANONICAL_CONNECTOR_NAME: "myDevSpace",
    DEVSPACE_OAUTH_CONNECTOR_INSTALLATION_EPOCH: "3",
    DEVSPACE_SOURCE_REVISION: sourceRevision,
    DEVSPACE_RUNTIME_REVISION: runtimeRevision,
    DEVSPACE_BUILD_DIGEST: buildDigest,
    DEVSPACE_NEXT_PM2_PROCESS_NAME: "devspace-personal-http-live-fixture",
    DEVSPACE_NEXT_PM2_EXPECTED_SCRIPT: join(root, "fixture-start.sh"),
  });
  const runtimeIdentity = createRuntimeIdentity({
    config,
    sourceRevision: config.sourceRevision,
    runtimeRevision: config.runtimeRevision,
    ...(config.buildDigest ? { buildDigest: config.buildDigest } : {}),
  });
  assert.equal(runtimeIdentity.sourceRevision, sourceRevision);
  assert.equal(runtimeIdentity.runtimeRevision, runtimeRevision);
  assert.equal(runtimeIdentity.buildDigest, buildDigest);

  const seed = spawnSync(node, [
    seeder,
    "--state-dir", oauthStateDir,
    "--token-file", tokenFile,
    "--evidence-file", oauthEvidence,
    "--canonical-name", config.oauth.canonicalConnector.name,
    "--installation-epoch", String(config.oauth.canonicalConnector.installationEpoch),
    "--schema-generation", config.oauth.canonicalConnector.schemaGeneration,
    "--resource", config.publicMcpUrl,
  ], {
    cwd: process.cwd(),
    encoding: "utf8",
    stdio: "pipe",
    env: process.env,
  });
  assert.equal(seed.status, 0, seed.stderr);
  const seedSummary = JSON.parse(seed.stdout);
  const token = (await readFile(tokenFile, "utf8")).trim();
  assert.equal(seedSummary.status, "PASS");
  assert.equal(seedSummary.readiness.state, "PASS");
  assert.equal(seed.stdout.includes(token), false);
  assert.equal(await mode(tokenFile), "600");
  assert.equal(await mode(oauthEvidence), "600");

  const selfManagement = new UniversalSelfManagementService({
    stateDir: config.selfManagementDir,
    pm2ProcessName: config.selfRestartPm2ProcessName,
    localHealthUrl: `http://${config.managementHost}:${config.managementPort}${config.readyPath}`,
    expectedCwd: process.cwd(),
    expectedScript: config.selfRestartExpectedScript,
    timeoutMs: config.selfRestartTimeoutMs,
    runtimeIdentity,
    supervisorReadinessProbe: async () => ({
      state: "PASS",
      evidence: {
        controlChannel: "test-readiness-probe",
        processMatches: 1,
        online: true,
        cwdMatches: true,
        scriptMatches: true,
        pid: process.pid,
      },
    }),
  });
  const running = createUniversalBrokerNextServer(config, {
    incomingArtifactAdapters: [],
    selfManagement,
    acceptanceRunId,
  });
  for (const field of [
    "productProfile",
    "sourceRevision",
    "runtimeRevision",
    "buildDigest",
    "schemaGeneration",
    "configDigest",
  ]) {
    assert.equal(running.runtimeIdentity[field], runtimeIdentity[field], field);
  }
  await writeFile(join(releasePackage, "BUILD-MANIFEST.json"), `${JSON.stringify({
    schemaVersion: 1,
    productProfile: running.runtimeIdentity.productProfile,
    sourceRevision: running.runtimeIdentity.sourceRevision,
    runtimeRevision: running.runtimeIdentity.runtimeRevision,
    buildDigest: running.runtimeIdentity.buildDigest,
    schemaGeneration: running.runtimeIdentity.schemaGeneration,
    files: [],
  }, null, 2)}\n`, { mode: 0o600 });
  const dataServer = running.app.listen(0, "127.0.0.1");
  const managementServer = running.managementApp.listen(0, "127.0.0.1");
  await Promise.all([dataServer, managementServer].map((server) => new Promise((resolvePromise, reject) => {
    server.once("listening", resolvePromise);
    server.once("error", reject);
  })));
  t.after(async () => {
    await Promise.all([
      closeServer(dataServer),
      closeServer(managementServer),
    ]);
    await running.close();
    await rm(root, { recursive: true, force: true });
  });

  const dataPort = dataServer.address().port;
  const managementPort = managementServer.address().port;
  const execution = await spawnAndCollect(node, [
    verifier,
    "--data-base-url", `http://127.0.0.1:${dataPort}`,
    "--management-base-url", `http://127.0.0.1:${managementPort}`,
    "--release-package", releasePackage,
    "--token-file", tokenFile,
    "--audit-path", config.auditSinkPath,
    "--disposable-root", disposableRoot,
    "--acceptance-run-id", acceptanceRunId,
    "--connector-installation-epoch", "3",
    "--connector-rotation-sequence", "0",
    "--output", outputPath,
  ]);
  assert.equal(execution.code, 0, execution.stderr);
  assert.equal(execution.stdout.includes(token), false);
  const summary = JSON.parse(execution.stdout);
  assert.equal(summary.status, "PERSONAL_DIRECT_OWNER_HTTP_LIVE_PASS");
  assert.equal(summary.productProfile, "PERSONAL_DIRECT_OWNER");
  assert.equal(summary.acceptanceRunId, acceptanceRunId);
  assert.deepEqual(summary.toolNames, [
    "target", "context", "fs", "exec", "process", "mcp", "artifact", "gui",
  ]);
  assert.ok(summary.verifiedOperationIds.length >= 10);
  assert.ok(summary.verifiedMutationIds.length >= 4);
  assert.equal(summary.cleanup, "PATH_NOT_FOUND");
  assert.equal(await mode(outputPath), "600");
  await assert.rejects(stat(disposableRoot), /ENOENT/u);
  const persisted = JSON.parse(await readFile(outputPath, "utf8"));
  assert.equal(JSON.stringify(persisted).includes(token), false);
});

function spawnAndCollect(command, args) {
  return new Promise((resolvePromise, reject) => {
    const child = spawn(command, args, {
      cwd: process.cwd(),
      env: process.env,
      stdio: ["ignore", "pipe", "pipe"],
    });
    let stdout = "";
    let stderr = "";
    child.stdout.setEncoding("utf8");
    child.stderr.setEncoding("utf8");
    child.stdout.on("data", (chunk) => { stdout += chunk; });
    child.stderr.on("data", (chunk) => { stderr += chunk; });
    child.once("error", reject);
    child.once("close", (code) => resolvePromise({ code, stdout, stderr }));
  });
}

function closeServer(server) {
  return new Promise((resolvePromise) => server.close(() => resolvePromise()));
}

async function mode(path) {
  return ((await stat(path)).mode & 0o777).toString(8).padStart(3, "0");
}
