import { spawnSync } from "node:child_process";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { createServer, type Server } from "node:http";
import {
  chmod,
  mkdtemp,
  mkdir,
  readFile,
  readlink,
  rm,
  stat,
  symlink,
  writeFile,
} from "node:fs/promises";
import type { AddressInfo } from "node:net";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import test, { type TestContext } from "node:test";
import {
  directoryEvidence,
  pm2CommandEnvironment,
  pm2WorkerCleanupEnvironment,
  productionPm2Environment,
  runProductionUpgradeWorker,
  schedulePm2WorkerCleanup,
  type ProductionUpgradeRequest,
} from "./production-upgrade-worker.js";
import { runPm2UpgradeCleanupMonitor } from "./production-upgrade-cleanup-monitor.js";

const expectedScopes = [
  "devspace.read",
  "devspace.write",
  "devspace.exec",
  "devspace.mcp",
  "devspace.artifact",
  "devspace.gui",
  "offline_access",
];

test("production PM2 launches retain ordinary process variables but drop inherited DevSpace runtime state", () => {
  const sanitized = productionPm2Environment({
    HOME: "/Users/example",
    PATH: "/usr/bin:/bin",
    DEVSPACE_V2_LEGACY_SCOPE_COMPATIBILITY: "true",
    DEVSPACE_NEXT_PORT: "9999",
    DEVSPACE_NEXT_STALE_VALUE: "must-not-survive",
    DEVSPACE_OAUTH_OWNER_TOKEN: "must-not-survive",
    DEVSPACE_PRODUCTION_ENV_FILE: "/old.env",
  }, "/new.env", "/Users/example/.nvm/versions/node/v22/bin/node");
  assert.deepEqual(sanitized, {
    HOME: "/Users/example",
    PATH: "/Users/example/.nvm/versions/node/v22/bin:/usr/bin:/bin",
    DEVSPACE_PRODUCTION_ENV_FILE: "/new.env",
  });
});

test("every detached PM2 command can resolve the worker Node executable without duplicating PATH entries", () => {
  assert.deepEqual(
    pm2CommandEnvironment({
      HOME: "/Users/example",
      PATH: "/usr/bin:/Users/example/.nvm/versions/node/v22/bin:/bin",
      DEVSPACE_NEXT_PORT: "7678",
    }, "/Users/example/.nvm/versions/node/v22/bin/node"),
    {
      HOME: "/Users/example",
      PATH: "/Users/example/.nvm/versions/node/v22/bin:/usr/bin:/bin",
      DEVSPACE_NEXT_PORT: "7678",
    },
  );
  assert.throws(
    () => pm2CommandEnvironment({ PATH: "/usr/bin:/bin" }, "node"),
    /Node executable must be absolute/u,
  );
});

test("detached PM2 environment runs an env-node shebang under a minimal launchd PATH", async (t) => {
  const root = await mkdtemp(join(tmpdir(), "devspace-pm2-node-path-test-"));
  t.after(() => rm(root, { recursive: true, force: true }));
  const executable = join(root, "pm2-like.mjs");
  await writeFile(executable, [
    "#!/usr/bin/env node",
    "process.stdout.write(JSON.stringify({execPath:process.execPath,args:process.argv.slice(2)}));",
    "",
  ].join("\n"), { mode: 0o700 });
  await chmod(executable, 0o700);
  const result = spawnSync(executable, ["jlist"], {
    encoding: "utf8",
    env: pm2CommandEnvironment({
      HOME: root,
      PATH: "/usr/bin:/bin",
    }, process.execPath),
  });
  assert.equal(result.status, 0, result.stderr);
  const value = JSON.parse(result.stdout) as { execPath: string; args: string[] };
  assert.equal(value.execPath, process.execPath);
  assert.deepEqual(value.args, ["jlist"]);
});

test("PM2 fallback worker schedules credential-free terminal cleanup and dump persistence", async (t) => {
  const root = await mkdtemp(join(tmpdir(), "devspace-pm2-worker-cleanup-test-"));
  t.after(() => rm(root, { recursive: true, force: true }));
  const calls = join(root, "pm2.calls");
  const pm2 = join(root, "pm2-fixture.sh");
  await writeFile(pm2, [
    "#!/bin/sh",
    `printf '%s\\n' \"$*\" >> ${shellQuote(calls)}`,
    "exit 0",
    "",
  ].join("\n"), { mode: 0o700 });
  await chmod(pm2, 0o700);
  const inherited = {
    HOME: root,
    USER: "fixture",
    LOGNAME: "fixture",
    PATH: "/usr/bin:/bin",
    PM2_HOME: join(root, ".pm2"),
    DEVSPACE_OAUTH_OWNER_TOKEN: "must-not-survive",
  };
  assert.deepEqual(pm2WorkerCleanupEnvironment(inherited, process.execPath), {
    HOME: root,
    USER: "fixture",
    LOGNAME: "fixture",
    PATH: `${dirname(process.execPath)}:/usr/bin:/bin`,
    PM2_HOME: join(root, ".pm2"),
  });
  const previousEnvironment = process.env;
  process.env = { ...inherited };
  try {
    const pid = schedulePm2WorkerCleanup(pm2, "devspace-v2-upgrade-deadbeef", root, 20);
    assert.ok(pid > 0);
  } finally {
    process.env = previousEnvironment;
  }
  const evidencePath = join(root, "scheduler-cleanup.json");
  for (let attempt = 0; attempt < 100; attempt += 1) {
    if (await readFile(evidencePath, "utf8").catch(() => undefined)) break;
    await new Promise((resolve) => setTimeout(resolve, 20));
  }
  const evidence = JSON.parse(await readFile(evidencePath, "utf8")) as {
    version: number;
    workerName: string;
    deleted: boolean;
    dumpSaved: boolean;
    deleteStatus: number;
    saveStatus: number;
    completedAt: string;
  };
  assert.equal(evidence.version, 1);
  assert.equal(evidence.workerName, "devspace-v2-upgrade-deadbeef");
  assert.equal(evidence.deleted, true);
  assert.equal(evidence.deleteStatus, 0);
  assert.equal(evidence.dumpSaved, true);
  assert.equal(evidence.saveStatus, 0);
  assert.equal(typeof evidence.completedAt, "string");
  assert.equal((await stat(evidencePath)).mode & 0o777, 0o600);
  assert.deepEqual((await readFile(calls, "utf8")).trim().split("\n"), [
    "delete devspace-v2-upgrade-deadbeef",
    "save",
  ]);
});

test("external PM2 cleanup monitor persists dump state after terminal worker self-delete races", async (t) => {
  const root = await mkdtemp(join(tmpdir(), "devspace-pm2-cleanup-monitor-test-"));
  t.after(() => rm(root, { recursive: true, force: true }));
  const pm2Home = join(root, ".pm2");
  const workerState = join(root, "worker.present");
  const calls = join(root, "pm2.calls");
  const statusPath = join(root, "status.json");
  const pm2 = join(root, "pm2-fixture.sh");
  await mkdir(pm2Home, { recursive: true });
  await writeFile(workerState, "present\n");
  await writeFile(statusPath, JSON.stringify({
    transactionId: "upgrade_00000000-0000-4000-8000-000000000000",
    state: "PASS",
  }));
  await writeFile(pm2, [
    "#!/bin/sh",
    `state=${shellQuote(workerState)}`,
    `calls=${shellQuote(calls)}`,
    `dump=${shellQuote(join(pm2Home, "dump.pm2"))}`,
    "printf '%s\\n' \"$*\" >> \"$calls\"",
    "case \"$1\" in",
    "  jlist)",
    "    if [ -f \"$state\" ]; then printf '%s\\n' '[{\"name\":\"devspace-v2-upgrade-feedface\"}]'; else printf '%s\\n' '[]'; fi",
    "    ;;",
    "  delete)",
    "    rm -f \"$state\"",
    "    ;;",
    "  save)",
    "    if [ -f \"$state\" ]; then printf '%s\\n' '[{\"name\":\"devspace-v2-upgrade-feedface\"}]' > \"$dump\"; else printf '%s\\n' '[]' > \"$dump\"; fi",
    "    ;;",
    "  *) exit 64 ;;",
    "esac",
    "",
  ].join("\n"), { mode: 0o700 });
  await chmod(pm2, 0o700);
  const evidence = await runPm2UpgradeCleanupMonitor({
    statusPath,
    pm2Executable: pm2,
    workerName: "devspace-v2-upgrade-feedface",
    auditDirectory: root,
    timeoutMs: 1_000,
    pollMs: 10,
    graceMs: 0,
    env: {
      HOME: root,
      PATH: `${dirname(process.execPath)}:/usr/bin:/bin`,
      PM2_HOME: pm2Home,
    },
  });
  assert.equal(evidence.ok, true);
  assert.equal(evidence.terminalState, "PASS");
  assert.equal(evidence.workerPresentBefore, true);
  assert.equal(evidence.deleteAttempted, true);
  assert.equal(evidence.workerPresentAfter, false);
  assert.equal(evidence.dumpWorkerResidue, false);
  assert.equal(evidence.dumpSaved, true);
  const persistedPath = join(root, "scheduler-cleanup.json");
  assert.equal((await stat(persistedPath)).mode & 0o777, 0o600);
  assert.deepEqual((await readFile(calls, "utf8")).trim().split("\n"), [
    "jlist",
    "delete devspace-v2-upgrade-feedface",
    "save",
    "jlist",
  ]);
});

test("production upgrade worker switches one PM2 process and commits canonical pointers only after verification", async (t) => {
  const fixture = await createFixture(t, { publicMetricsStatus: 404 });
  await runProductionUpgradeWorker(fixture.requestPath);
  const status = JSON.parse(await readFile(fixture.statusPath, "utf8")) as {
    state: string;
    acceptedAt?: string;
    history?: Array<{ state: string }>;
    pidAfter?: number;
    publicMetricsStatus?: number;
    unauthenticatedMcpStatus?: number;
    oauthScopes?: string[];
    runtimeCommit?: string;
    runtimeSourceTree?: string;
    runtimeDist?: { files: number; sha256: string };
    manifestSha256?: string;
    manifestIdentity?: Record<string, unknown>;
    managementReadyUrl?: string;
    managementReadyStatus?: number;
    runtimeIdentity?: Record<string, unknown>;
    runtimeIdentityConfirmed?: boolean;
    configSchemaIdentity?: string;
  };
  assert.equal(status.state, "PASS");
  assert.equal(typeof status.acceptedAt, "string");
  assert.deepEqual(
    status.history?.map((entry) => entry.state),
    ["PREPARED", "ACCEPTED", "SWITCHING", "VERIFYING", "PASS"],
  );
  assert.equal(status.pidAfter, 222);
  assert.equal(status.publicMetricsStatus, 404);
  assert.equal(status.unauthenticatedMcpStatus, 401);
  assert.deepEqual(status.oauthScopes, expectedScopes);
  assert.equal(status.runtimeCommit, fixture.nextCommit);
  assert.equal(status.runtimeSourceTree, fixture.nextSourceTree);
  assert.deepEqual(status.runtimeDist, fixture.nextDist);
  assert.equal(status.manifestSha256, fixture.manifestSha256);
  assert.deepEqual(status.manifestIdentity, fixture.manifestIdentity);
  assert.equal(status.managementReadyUrl, fixture.managementReadyUrl);
  assert.equal(status.managementReadyStatus, 200);
  assert.deepEqual(status.runtimeIdentity, fixture.runtimeIdentity);
  assert.equal(status.runtimeIdentityConfirmed, true);
  assert.equal(status.configSchemaIdentity, fixture.manifestIdentity.configSchemaIdentity);
  assert.equal(await readFile(fixture.productionEnvPath, "utf8"), fixture.nextEnvContent);
  assert.match(await readFile(fixture.startScriptPath, "utf8"), new RegExp(escapeRegExp(fixture.nextScript), "u"));
  assert.equal(await readlink(fixture.currentAuditLink), fixture.auditDirectory);
  assert.equal((await readFile(fixture.pm2State.pid, "utf8")).trim(), "222");
  assert.equal((await readFile(fixture.pm2State.cwd, "utf8")).trim(), fixture.nextRelease);
  assert.equal((await readFile(fixture.pm2State.script, "utf8")).trim(), fixture.nextScript);
});

test("production upgrade worker fails closed before switching when request manifest identity is stale", async (t) => {
  const fixture = await createFixture(t, {
    publicMetricsStatus: 404,
    requestManifestOverride: { configSchemaIdentity: `sha256:${"9".repeat(64)}` },
  });
  await assert.rejects(
    runProductionUpgradeWorker(fixture.requestPath),
    /Immutable manifest configSchemaIdentity mismatch/u,
  );
  const status = JSON.parse(await readFile(fixture.statusPath, "utf8")) as {
    state: string;
    history?: Array<{ state: string }>;
    failure?: { code?: string; phase?: string };
    rollback?: { attempted?: boolean; verified?: boolean; outcome?: string };
  };
  assert.equal(status.state, "FAIL");
  assert.deepEqual(status.history?.map((entry) => entry.state), ["PREPARED", "ACCEPTED", "FAIL"]);
  assert.equal(status.failure?.code, "MANIFEST_MISMATCH");
  assert.equal(status.failure?.phase, "PREFLIGHT");
  assert.equal(status.rollback?.attempted, false);
  assert.equal(status.rollback?.verified, false);
  assert.equal(status.rollback?.outcome, "NOT_REQUIRED_SWITCH_NOT_STARTED");
  assert.equal(await readFile(fixture.productionEnvPath, "utf8"), "OLD_ENV=1\n");
  assert.equal(await readFile(fixture.startScriptPath, "utf8"), "#!/bin/bash\nexec old\n");
  assert.equal(await readlink(fixture.currentAuditLink), fixture.previousAudit);
  assert.equal((await readFile(fixture.pm2State.pid, "utf8")).trim(), "111");
  assert.equal((await readFile(fixture.pm2State.cwd, "utf8")).trim(), fixture.previousRelease);
  assert.equal((await readFile(fixture.pm2State.script, "utf8")).trim(), fixture.previousScript);
});

test("production upgrade worker rejects private readiness identity drift and proves rollback", async (t) => {
  const fixture = await createFixture(t, {
    publicMetricsStatus: 404,
    timeoutMs: 250,
    runtimeIdentityOverride: { runtimeRevision: "f".repeat(40) },
  });
  await assert.rejects(
    runProductionUpgradeWorker(fixture.requestPath),
    /Private readiness identity mismatch for runtimeRevision/u,
  );
  const status = JSON.parse(await readFile(fixture.statusPath, "utf8")) as {
    state: string;
    failure?: { code?: string; phase?: string };
    rollback?: { restored?: boolean; verified?: boolean; outcome?: string };
  };
  assert.equal(status.state, "FAIL");
  assert.equal(status.failure?.code, "RUNTIME_IDENTITY_MISMATCH");
  assert.equal(status.failure?.phase, "VERIFYING");
  assert.equal(status.rollback?.restored, true);
  assert.equal(status.rollback?.verified, true);
  assert.equal(status.rollback?.outcome, "RESTORED_PREVIOUS_RUNTIME");
  assert.equal(await readFile(fixture.productionEnvPath, "utf8"), "OLD_ENV=1\n");
  assert.equal((await readFile(fixture.pm2State.cwd, "utf8")).trim(), fixture.previousRelease);
});

test("production upgrade worker rolls back env, process, start path, and audit link on public-boundary failure", async (t) => {
  const fixture = await createFixture(t, { publicMetricsStatus: 200, timeoutMs: 250 });
  await assert.rejects(runProductionUpgradeWorker(fixture.requestPath), /Public metrics returned 200/u);
  const status = JSON.parse(await readFile(fixture.statusPath, "utf8")) as {
    state: string;
    failure?: { code?: string };
    rollback?: { restored?: boolean; verified?: boolean; outcome?: string; healthStatus?: number };
  };
  assert.equal(status.state, "FAIL");
  assert.equal(status.failure?.code, "PUBLIC_BOUNDARY_FAILED");
  assert.equal(status.rollback?.restored, true);
  assert.equal(status.rollback?.verified, true);
  assert.equal(status.rollback?.outcome, "RESTORED_PREVIOUS_RUNTIME");
  assert.equal(status.rollback?.healthStatus, 200);
  assert.equal(await readFile(fixture.productionEnvPath, "utf8"), "OLD_ENV=1\n");
  assert.equal(await readFile(fixture.startScriptPath, "utf8"), "#!/bin/bash\nexec old\n");
  assert.equal(await readlink(fixture.currentAuditLink), fixture.previousAudit);
  assert.equal((await readFile(fixture.pm2State.cwd, "utf8")).trim(), fixture.previousRelease);
  assert.equal((await readFile(fixture.pm2State.script, "utf8")).trim(), fixture.previousScript);
});

test("production upgrade worker records UNKNOWN when rollback cannot establish the previous runtime", async (t) => {
  const fixture = await createFixture(t, {
    publicMetricsStatus: 200,
    timeoutMs: 250,
    rollbackFails: true,
  });
  await assert.rejects(runProductionUpgradeWorker(fixture.requestPath), /Public metrics returned 200/u);
  const status = JSON.parse(await readFile(fixture.statusPath, "utf8")) as {
    state: string;
    history?: Array<{ state: string }>;
    failure?: { code?: string };
    rollback?: {
      restored?: boolean;
      verified?: boolean;
      outcome?: string;
      error?: string;
      failure?: { code?: string };
    };
  };
  assert.equal(status.state, "UNKNOWN");
  assert.equal(status.history?.at(-1)?.state, "UNKNOWN");
  assert.equal(status.failure?.code, "PUBLIC_BOUNDARY_FAILED");
  assert.equal(status.rollback?.restored, false);
  assert.equal(status.rollback?.verified, false);
  assert.equal(status.rollback?.outcome, "RESTORATION_UNVERIFIED");
  assert.equal(status.rollback?.failure?.code, "ROLLBACK_FAILED");
  assert.equal(typeof status.rollback?.error, "string");
});

interface FixtureRuntimeIdentity {
  productVersion: string;
  schemaGeneration: string;
  authorityContractGeneration: string;
  configDigest: string;
  sourceRevision: string;
  runtimeRevision: string;
  buildDigest: string;
  startedAt: string;
}

interface FixtureOptions {
  publicMetricsStatus: number;
  timeoutMs?: number;
  rollbackFails?: boolean;
  requestManifestOverride?: Partial<ProductionUpgradeRequest["next"]["manifest"]>;
  runtimeIdentityOverride?: Partial<FixtureRuntimeIdentity>;
}

async function createFixture(t: TestContext, options: FixtureOptions) {
  const root = await mkdtemp(join(tmpdir(), "devspace-production-upgrade-worker-test-"));
  t.after(() => rm(root, { recursive: true, force: true }));
  const auditDirectory = join(root, "audit-next");
  const previousAudit = join(root, "audit-previous");
  const previousRelease = join(root, "release-previous");
  const nextRelease = join(root, "release-next");
  const requestPath = join(auditDirectory, "request.json");
  const statusPath = join(auditDirectory, "status.json");
  await Promise.all([
    mkdir(auditDirectory, { recursive: true }),
    mkdir(previousAudit, { recursive: true }),
    mkdir(previousRelease, { recursive: true }),
    mkdir(nextRelease, { recursive: true }),
  ]);
  const previousScript = join(previousRelease, "start.sh");
  const nextScript = join(nextRelease, "start.sh");
  await writeFile(previousScript, "#!/bin/sh\n", { mode: 0o700 });
  await writeFile(nextScript, "#!/bin/sh\n", { mode: 0o700 });
  await mkdir(join(nextRelease, "dist"), { recursive: true });
  await writeFile(join(nextRelease, "dist", "runtime.js"), "export const runtime = true;\n");
  const nextDist = await directoryEvidence(join(nextRelease, "dist"));
  const nextCommit = "a".repeat(40);
  const nextSourceTree = "b".repeat(40);
  const manifestIdentity = {
    sourceRevision: nextCommit,
    runtimeRevision: "c".repeat(40),
    buildDigest: await releaseTreeDigest(nextRelease, ["dist/runtime.js"]),
    schemaGeneration: `sha256:${"d".repeat(64)}`,
    authorityContractGeneration: `sha256:${"e".repeat(64)}`,
    configSchemaIdentity: `sha256:${"f".repeat(64)}`,
  };
  const manifestPath = join(nextRelease, "BUILD-MANIFEST.json");
  await writeFile(manifestPath, `${JSON.stringify({
    manifestVersion: 2,
    ...manifestIdentity,
    payloadDigest: `sha256:${"8".repeat(64)}`,
    files: 1,
    payloadFiles: ["dist/runtime.js"],
    runtimeFiles: ["dist/runtime.js"],
    createdAt: "2026-08-19T00:00:00.000Z",
    nodeVersion: "v22.23.0",
    platform: "darwin-arm64",
    forbiddenArtifactScan: "PASS",
  }, null, 2)}\n`, { mode: 0o444 });
  const manifestSha256 = `sha256:${createHash("sha256").update(await readFile(manifestPath)).digest("hex")}`;
  const runtimeIdentity: FixtureRuntimeIdentity = {
    productVersion: "2.1.0",
    schemaGeneration: manifestIdentity.schemaGeneration,
    authorityContractGeneration: manifestIdentity.authorityContractGeneration,
    configDigest: `sha256:${"7".repeat(64)}`,
    sourceRevision: manifestIdentity.sourceRevision,
    runtimeRevision: manifestIdentity.runtimeRevision,
    buildDigest: manifestIdentity.buildDigest,
    startedAt: "2026-08-19T00:00:01.000Z",
    ...options.runtimeIdentityOverride,
  };
  const managementServer = createServer((request, response) => {
    if (request.url === "/readyz") {
      response.setHeader("content-type", "application/json");
      response.end(JSON.stringify({
        status: "ready",
        identity: runtimeIdentity,
        checks: {
          nonRoot: true,
          targetRegistry: manifestIdentity.schemaGeneration,
          routeRegistry: manifestIdentity.schemaGeneration,
          authorityStore: true,
          principalMode: "single-owner",
          authorityDeployment: "in-process",
          canonicalConnectorName: "devspace-production",
        },
      }));
      return;
    }
    response.statusCode = 404;
    response.end();
  });
  await listen(managementServer);
  t.after(() => close(managementServer));
  const managementPort = (managementServer.address() as AddressInfo).port;
  const managementReadyUrl = `http://127.0.0.1:${managementPort}/readyz`;
  const git = join(root, "git-fixture.sh");
  await writeFile(git, [
    "#!/bin/sh",
    "last=",
    "for value in \"$@\"; do last=$value; done",
    `if [ \"$last\" = HEAD ]; then printf '%s\\n' ${shellQuote(nextCommit)}; exit 0; fi`,
    `if [ \"$last\" = 'HEAD^{tree}' ]; then printf '%s\\n' ${shellQuote(nextSourceTree)}; exit 0; fi`,
    "exit 64",
    "",
  ].join("\n"), { mode: 0o700 });
  await chmod(git, 0o700);

  const productionEnvPath = join(root, "production.env");
  const productionEnvBackupPath = join(auditDirectory, "production.env.before");
  const nextEnvPath = join(auditDirectory, "production.env.next");
  const startScriptPath = join(root, "canonical-start.sh");
  const startScriptBackupPath = join(auditDirectory, "canonical-start.before");
  await writeFile(productionEnvPath, "OLD_ENV=1\n", { mode: 0o600 });
  await writeFile(productionEnvBackupPath, "OLD_ENV=1\n", { mode: 0o600 });
  const nextEnvContent = [
    "NEXT_ENV=1",
    "DEVSPACE_NEXT_MANAGEMENT_HOST=127.0.0.1",
    `DEVSPACE_NEXT_MANAGEMENT_PORT=${managementPort}`,
    `DEVSPACE_RELEASE_MANIFEST=${manifestPath}`,
    `DEVSPACE_EXPECTED_SOURCE_REVISION=${manifestIdentity.sourceRevision}`,
    `DEVSPACE_EXPECTED_RUNTIME_REVISION=${manifestIdentity.runtimeRevision}`,
    `DEVSPACE_EXPECTED_BUILD_DIGEST=${manifestIdentity.buildDigest}`,
    `DEVSPACE_EXPECTED_SCHEMA_GENERATION=${manifestIdentity.schemaGeneration}`,
    `DEVSPACE_EXPECTED_AUTHORITY_CONTRACT_GENERATION=${manifestIdentity.authorityContractGeneration}`,
    `DEVSPACE_EXPECTED_CONFIG_SCHEMA_IDENTITY=${manifestIdentity.configSchemaIdentity}`,
    `DEVSPACE_SOURCE_REVISION=${manifestIdentity.sourceRevision}`,
    `DEVSPACE_RUNTIME_REVISION=${manifestIdentity.runtimeRevision}`,
    `DEVSPACE_BUILD_DIGEST=${manifestIdentity.buildDigest}`,
    "",
  ].join("\n");
  await writeFile(nextEnvPath, nextEnvContent, { mode: 0o600 });
  await writeFile(startScriptPath, "#!/bin/bash\nexec old\n", { mode: 0o700 });
  await writeFile(startScriptBackupPath, "#!/bin/bash\nexec old\n", { mode: 0o700 });
  const currentAuditLink = join(root, "current-audit");
  await symlink(previousAudit, currentAuditLink);

  const pm2State = {
    pid: join(root, "pm2.pid"),
    cwd: join(root, "pm2.cwd"),
    script: join(root, "pm2.script"),
  };
  await writeFile(pm2State.pid, "111\n");
  await writeFile(pm2State.cwd, `${previousRelease}\n`);
  await writeFile(pm2State.script, `${previousScript}\n`);
  const pm2 = join(root, "pm2-fixture.sh");
  await writeFile(pm2, [
    "#!/bin/sh",
    `pid_file=${shellQuote(pm2State.pid)}`,
    `cwd_file=${shellQuote(pm2State.cwd)}`,
    `script_file=${shellQuote(pm2State.script)}`,
    `status_file=${shellQuote(statusPath)}`,
    "case \"$1\" in",
    "  jlist)",
    "    pid=$(cat \"$pid_file\")",
    "    cwd=$(cat \"$cwd_file\")",
    "    script=$(cat \"$script_file\")",
    "    printf '[{\"name\":\"devspace-v2-production\",\"pid\":%s,\"pm2_env\":{\"status\":\"online\",\"pm_cwd\":\"%s\",\"pm_exec_path\":\"%s\"}}]\\n' \"$pid\" \"$cwd\" \"$script\"",
    "    ;;",
    "  delete)",
    "    grep -q '\"state\": \"ACCEPTED\"' \"$status_file\" || exit 65",
    "    ;;",
    "  start)",
    "    script=$2",
    "    shift 2",
    "    cwd=",
    "    while [ $# -gt 0 ]; do",
    "      if [ \"$1\" = \"--cwd\" ]; then cwd=$2; shift 2; else shift; fi",
    "    done",
    options.rollbackFails
      ? `    if [ \"$script\" = ${shellQuote(nextScript)} ]; then printf '222\\n' > \"$pid_file\"; else exit 70; fi`
      : `    if [ \"$script\" = ${shellQuote(nextScript)} ]; then printf '222\\n' > \"$pid_file\"; else printf '333\\n' > \"$pid_file\"; fi`,
    "    printf '%s\\n' \"$cwd\" > \"$cwd_file\"",
    "    printf '%s\\n' \"$script\" > \"$script_file\"",
    "    ;;",
    "  save) : ;;",
    "  *) exit 64 ;;",
    "esac",
    "",
  ].join("\n"));
  await chmod(pm2, 0o700);

  const server = createServer((request, response) => {
    if (request.url === "/healthz") {
      response.statusCode = 200;
      response.end("ok");
      return;
    }
    if (request.url === "/metrics") {
      response.statusCode = options.publicMetricsStatus;
      response.end("metrics");
      return;
    }
    if (request.url === "/mcp" && request.method === "POST") {
      response.statusCode = 401;
      response.end("unauthorized");
      return;
    }
    if (request.url === "/.well-known/oauth-protected-resource/mcp") {
      response.setHeader("content-type", "application/json");
      response.end(JSON.stringify({ scopes_supported: expectedScopes }));
      return;
    }
    response.statusCode = 404;
    response.end();
  });
  await listen(server);
  t.after(() => close(server));
  const port = (server.address() as AddressInfo).port;
  const transactionId = "upgrade_11111111-1111-4111-8111-111111111111";
  const request: ProductionUpgradeRequest = {
    version: 1,
    transactionId,
    requestedAt: new Date().toISOString(),
    delayMs: 1,
    timeoutMs: options.timeoutMs ?? 2_000,
    pm2ProcessName: "devspace-v2-production",
    pm2Executable: pm2,
    gitExecutable: git,
    previous: {
      pid: 111,
      cwd: previousRelease,
      script: previousScript,
      auditTarget: previousAudit,
    },
    next: {
      commit: nextCommit,
      sourceTree: nextSourceTree,
      release: nextRelease,
      script: nextScript,
      dist: nextDist,
      manifest: {
        path: manifestPath,
        buildDigest: manifestIdentity.buildDigest,
        runtimeRevision: manifestIdentity.runtimeRevision,
        schemaGeneration: manifestIdentity.schemaGeneration,
        authorityContractGeneration: manifestIdentity.authorityContractGeneration,
        configSchemaIdentity: manifestIdentity.configSchemaIdentity,
        ...options.requestManifestOverride,
      },
    },
    productionEnvPath,
    productionEnvBackupPath,
    nextEnvPath,
    startScriptPath,
    startScriptBackupPath,
    auditDirectory,
    currentAuditLink,
    statusPath,
    workerLogPath: join(auditDirectory, "worker.log"),
    localHealthUrl: `http://127.0.0.1:${port}/healthz`,
    publicHealthUrl: `http://127.0.0.1:${port}/healthz`,
    publicMetricsUrl: `http://127.0.0.1:${port}/metrics`,
    publicMcpUrl: `http://127.0.0.1:${port}/mcp`,
    oauthMetadataUrl: `http://127.0.0.1:${port}/.well-known/oauth-protected-resource/mcp`,
    expectedScopes,
  };
  await writeFile(requestPath, `${JSON.stringify(request, null, 2)}\n`, { mode: 0o600 });
  return {
    requestPath,
    statusPath,
    productionEnvPath,
    startScriptPath,
    currentAuditLink,
    auditDirectory,
    previousAudit,
    previousRelease,
    previousScript,
    nextRelease,
    nextScript,
    nextCommit,
    nextSourceTree,
    nextDist,
    nextEnvContent,
    manifestSha256,
    manifestIdentity,
    managementReadyUrl,
    runtimeIdentity,
    pm2State,
  };
}

async function listen(server: Server): Promise<void> {
  await new Promise<void>((resolvePromise, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", resolvePromise);
  });
}

async function close(server: Server): Promise<void> {
  if (!server.listening) return;
  await new Promise<void>((resolvePromise) => server.close(() => resolvePromise()));
}

function shellQuote(value: string): string {
  return `'${value.replaceAll("'", `'"'"'`)}'`;
}

function escapeRegExp(value: string): string {
  return value.replace(/[.*+?^${}()|[\]\\]/gu, "\\$&");
}

async function releaseTreeDigest(root: string, files: string[]): Promise<string> {
  const digest = createHash("sha256");
  for (const path of [...files].sort()) {
    const content = await readFile(join(root, path));
    digest.update(path);
    digest.update("\0");
    digest.update(createHash("sha256").update(content).digest("hex"));
    digest.update("\n");
  }
  return `sha256:${digest.digest("hex")}`;
}
