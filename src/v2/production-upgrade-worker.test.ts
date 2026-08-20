import { spawnSync } from "node:child_process";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFileSync, realpathSync } from "node:fs";
import { createServer, type Server } from "node:http";
import {
  chmod,
  link,
  mkdtemp,
  mkdir,
  readFile,
  readdir,
  readlink,
  rename,
  rm,
  stat,
  symlink,
  writeFile,
} from "node:fs/promises";
import type { AddressInfo } from "node:net";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import test, { type TestContext } from "node:test";
import { fileURLToPath } from "node:url";
import Database from "better-sqlite3";
import {
  directoryEvidence,
  pm2CommandEnvironment,
  pm2WorkerCleanupEnvironment,
  productionPm2Environment,
  productionUpgradeLifecycleBindingDigest,
  productionUpgradeRequestBindingDigest,
  runProductionUpgradeWorker,
  schedulePm2WorkerCleanup,
  type ProductionUpgradeRequest,
  type ProductionUpgradeWorkerDependencies,
} from "./production-upgrade-worker.js";
import {
  canonicalizeProductionUpgradeValue,
  productionUpgradeCandidateIdentityDigest,
  serializeProductionUpgradeRequestV4,
} from "./production-upgrade-contract.js";
import { runPm2UpgradeCleanupMonitor } from "./production-upgrade-cleanup-monitor.js";
import { migrationManifestDigest, type MigrationManifestEntry } from "./migration-registry.js";
import {
  connectorRollbackHealthReadbackDigest,
  connectorRollbackReadyReadbackDigest,
  connectorRollbackRuntimeReadbackDigest,
  signConnectorRollbackHostChallenge,
  signConnectorRollbackHostReceipt,
} from "../../scripts/lib/connector-rollback-evidence.mjs";
import { captureSnapshotGroup } from "./snapshot-group.js";

const expectedScopes = [
  "devspace.read",
  "devspace.write",
  "devspace.exec",
  "devspace.mcp",
  "devspace.artifact",
  "devspace.gui",
  "offline_access",
];

function serializeUncheckedProductionUpgradeRequest(value: unknown): string {
  return `${canonicalizeProductionUpgradeValue(value)}\n`;
}

test("canonical v4 uses the concrete lifecycle dependency when no test override is supplied", async (t) => {
  const fixture = await createFixture(t, { publicMetricsStatus: 404 });
  const request = JSON.parse(await readFile(fixture.requestPath, "utf8")) as ProductionUpgradeRequest;
  await assert.rejects(runProductionUpgradeWorker(fixture.requestPath), (error: unknown) => {
    assert.doesNotMatch(String(error), /NOT_INTEGRATED/u);
    return true;
  });
  assert.equal(fixture.lifecycleProbe.opens, 0);
  assert.equal(fixture.lifecycleProbe.prepares, 0);
  assert.equal(fixture.lifecycleProbe.providerDispatches, 0);
  assert.equal(
    (await readFile(fixture.pm2State.pid, "utf8")).trim(),
    "333",
    "a post-snapshot integration failure must restore and restart the previous runtime",
  );
  assert.equal(readFixtureDatabaseValue(fixture.oauthDatabasePath), "OLD_OAUTH_DATABASE");
  const status = JSON.parse(await readFile(fixture.statusPath, "utf8")) as { state: string };
  assert.equal(status.state, "ROLLED_BACK");
  await assert.rejects(stat(`${fixture.statusPath}.worker-claim.json`), { code: "ENOENT" });
  assert.equal(
    (await stat(join(request.snapshotGroup.snapshotRoot, "SNAPSHOT-GROUP.json"))).isFile(),
    true,
    "post-snapshot failure retains the rollback evidence",
  );
});

test("worker CLI enters the concrete request path instead of the removed integration guard", async (t) => {
  const fixture = await createFixture(t, { publicMetricsStatus: 404 });
  const request = JSON.parse(await readFile(fixture.requestPath, "utf8")) as ProductionUpgradeRequest;
  const callsPath = join(fixture.auditDirectory, "forbidden-cli-pm2-calls.txt");
  const fakePm2 = join(fixture.auditDirectory, "forbidden-cli-pm2");
  await writeFile(fakePm2, [
    "#!/bin/sh",
    `printf '%s\\n' "$*" >> ${shellQuote(callsPath)}`,
    "exit 0",
    "",
  ].join("\n"), { mode: 0o700 });
  await chmod(fakePm2, 0o700);
  request.pm2Executable = fakePm2;
  request.localHealthUrl = "http://127.0.0.1:9/healthz";
  request.localDoctorUrl = "http://127.0.0.1:10/doctorz";
  request.previous.localHealthUrl = request.localHealthUrl;
  request.previous.localReadyUrl = "http://127.0.0.1:10/readyz";
  request.connectorLifecycle.postActivation.runtimeIdentityUrl = request.previous.localReadyUrl;
  request.connectorLifecycle.postActivation.routeIdentityUrl = "http://127.0.0.1:10/route-identityz";
  request.connectorLifecycle.bindingDigest = productionUpgradeLifecycleBindingDigest(request);
  await writeFile(
    fixture.requestPath,
    serializeProductionUpgradeRequestV4(request),
    { mode: 0o600 },
  );

  const cliPath = fileURLToPath(new URL("./production-upgrade-worker-cli.ts", import.meta.url));
  const result = spawnSync(process.execPath, ["--import", "tsx", cliPath, fixture.requestPath], {
    encoding: "utf8",
    timeout: 10_000,
    env: {
      ...process.env,
      DEVSPACE_UPGRADE_SCHEDULER: "pm2",
      DEVSPACE_UPGRADE_PM2_WORKER_NAME: "devspace-v2-upgrade-probe",
    },
  });
  assert.equal(result.status, 1, result.stderr || result.stdout);
  assert.doesNotMatch(result.stderr, /NOT_INTEGRATED/u);
  await new Promise((resolvePromise) => setTimeout(resolvePromise, 1_000));
  await assert.rejects(stat(callsPath), { code: "ENOENT" });
  await assert.rejects(stat(join(fixture.auditDirectory, "scheduler-cleanup.json")), { code: "ENOENT" });
});

test("directory evidence orders non-ASCII paths by code unit independent of filesystem enumeration", async (t) => {
  const root = await mkdtemp(join(realpathSync(tmpdir()), "devspace-directory-evidence-order-"));
  t.after(() => rm(root, { recursive: true, force: true }));
  const entries = [
    ["é.txt", "accent\n"],
    ["a.txt", "ascii-a\n"],
    ["😀.txt", "astral\n"],
    ["z.txt", "ascii-z\n"],
  ] as const;
  for (const [name, content] of entries) await writeFile(join(root, name), content, { mode: 0o600 });

  const expected = createHash("sha256");
  for (const [name, content] of [...entries].sort(([left], [right]) => left < right ? -1 : left > right ? 1 : 0)) {
    expected.update(name);
    expected.update("\0");
    expected.update(createHash("sha256").update(content).digest("hex"));
    expected.update("\n");
  }

  assert.deepEqual(await directoryEvidence(root), {
    files: entries.length,
    sha256: expected.digest("hex"),
  });
});

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
  await runProductionUpgradeWorker(fixture.requestPath, fixture.dependencies);
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
    snapshotGroupPreimage?: { groupDigest?: string; barrier?: { kind?: string }; entries?: Array<{ id: string; state: string }> };
    connectorLifecycle?: { state?: string; postActivationEvidenceDigest?: string };
  };
  assert.equal(status.state, "PASS");
  assert.equal(typeof status.acceptedAt, "string");
  assert.deepEqual(
    status.history?.map((entry) => entry.state),
    [
      "PREPARED",
      "ACCEPTED",
      "PREFLIGHT_VERIFIED",
      "CUTOVER_STOP_REQUESTED",
      "CUTOVER_PROCESSES_STOPPED",
      "STATE_SNAPSHOTTED",
      "CONNECTOR_ACTIVATION_PREPARED",
      "ACTIVATED_PENDING_POSTCHECK",
      "RUNTIME_STARTED",
      "POST_SWITCH_VERIFIED",
      "POST_ACTIVATION_VERIFIED",
      "PASS",
    ],
  );
  assert.equal(status.pidAfter, 222);
  assert.equal(status.publicMetricsStatus, 404);
  assert.equal(status.unauthenticatedMcpStatus, 401);
  assert.deepEqual(status.oauthScopes, expectedScopes);
  assert.equal(status.runtimeCommit, fixture.nextCommit);
  assert.equal(status.runtimeSourceTree, fixture.nextSourceTree);
  assert.deepEqual(status.runtimeDist, fixture.nextDist);
  assert.notEqual(fixture.nextSourceEvidenceRoot, fixture.nextRelease);
  assert.equal(status.manifestSha256, fixture.manifestSha256);
  assert.deepEqual(status.manifestIdentity, fixture.manifestIdentity);
  assert.equal(status.managementReadyUrl, fixture.managementReadyUrl);
  assert.equal(status.managementReadyStatus, 200);
  assert.deepEqual(status.runtimeIdentity, fixture.runtimeIdentity);
  assert.equal(status.runtimeIdentityConfirmed, true);
  assert.equal(status.configSchemaIdentity, fixture.manifestIdentity.configSchemaIdentity);
  assert.equal(status.connectorLifecycle?.state, "POST_ACTIVATION_VERIFIED");
  assert.match(status.connectorLifecycle?.postActivationEvidenceDigest ?? "", /^sha256:[a-f0-9]{64}$/u);
  assert.equal(fixture.lifecycleProbe.providerDispatches, 1);
  assert.equal(fixture.lifecycleProbe.postVerifications, 1);
  assert.equal(readFixtureDatabaseValue(fixture.connectorJournalPath), "DISPATCHED_PERMANENT_ONE_SHOT");
  assert.match(status.snapshotGroupPreimage?.groupDigest ?? "", /^sha256:[a-f0-9]{64}$/u);
  assert.equal(status.snapshotGroupPreimage?.barrier?.kind, "PM2_STOPPED");
  assert.deepEqual(status.snapshotGroupPreimage?.entries?.map((entry) => entry.id), fixture.snapshotStoreIds);
  assert.equal(await readFile(fixture.productionEnvPath, "utf8"), fixture.nextEnvContent);
  assert.match(await readFile(fixture.startScriptPath, "utf8"), new RegExp(escapeRegExp(fixture.nextScript), "u"));
  assert.equal(await readlink(fixture.currentAuditLink), fixture.auditDirectory);
  assert.equal((await readFile(fixture.pm2State.pid, "utf8")).trim(), "222");
  assert.equal((await readFile(fixture.pm2State.cwd, "utf8")).trim(), fixture.nextRelease);
  assert.equal((await readFile(fixture.pm2State.script, "utf8")).trim(), fixture.nextScript);
  assert.equal(readFixtureDatabaseValue(fixture.oauthDatabasePath), "CANDIDATE_OAUTH_DATABASE");
  assert.equal(readFixtureDatabaseValue(fixture.authorityDatabasePath), "CANDIDATE_AUTHORITY_DATABASE");
  assert.equal(readFixtureDatabaseValue(fixture.filesystemSyncStorePath), "CANDIDATE_FILESYSTEM_SYNC_STORE");
  assert.equal(await readFile(fixture.rollbackJournalPath, "utf8"), "");
  assert.equal((await stat(fixture.rollbackJournalPath)).mode & 0o777, 0o600);
});

test("v3 requests fail closed before lifecycle, PM2, OAuth, or provider dispatch", async (t) => {
  const fixture = await createFixture(t, { publicMetricsStatus: 404 });
  const request = JSON.parse(await readFile(fixture.requestPath, "utf8")) as Record<string, unknown>;
  request.version = 3;
  await writeFile(fixture.requestPath, serializeUncheckedProductionUpgradeRequest(request), { mode: 0o600 });
  await assert.rejects(
    runProductionUpgradeWorker(fixture.requestPath, fixture.dependencies),
    /production upgrade request version/u,
  );
  assert.equal(fixture.lifecycleProbe.opens, 0);
  assert.equal(fixture.lifecycleProbe.providerDispatches, 0);
  assert.equal((await readFile(fixture.pm2State.pid, "utf8")).trim(), "111");
  assert.equal(readFixtureDatabaseValue(fixture.oauthDatabasePath), "OLD_OAUTH_DATABASE");
});

test("request reader rejects noncanonical bytes and duplicate JSON keys before lifecycle", async (t) => {
  const fixture = await createFixture(t, { publicMetricsStatus: 404 });
  const request = JSON.parse(await readFile(fixture.requestPath, "utf8")) as ProductionUpgradeRequest;

  await writeFile(fixture.requestPath, `${JSON.stringify(request, null, 2)}\n`, { mode: 0o600 });
  await assert.rejects(
    runProductionUpgradeWorker(fixture.requestPath, fixture.dependencies),
    /one canonical code-unit JSON serialization plus newline/u,
  );
  assert.equal(fixture.lifecycleProbe.opens, 0);

  const canonical = serializeProductionUpgradeRequestV4(request);
  const duplicateKey = canonical.replace('"version":4', '"version":4,"version":4');
  assert.notEqual(duplicateKey, canonical);
  await writeFile(fixture.requestPath, duplicateKey, { mode: 0o600 });
  await assert.rejects(
    runProductionUpgradeWorker(fixture.requestPath, fixture.dependencies),
    /one canonical code-unit JSON serialization plus newline/u,
  );
  assert.equal(fixture.lifecycleProbe.opens, 0);

  await writeFile(fixture.requestPath, canonical, { mode: 0o600 });
  await link(fixture.requestPath, join(dirname(fixture.requestPath), "request-hardlink.json"));
  await assert.rejects(
    runProductionUpgradeWorker(fixture.requestPath, fixture.dependencies),
    /one bounded owner-only regular file/u,
  );
  assert.equal(fixture.lifecycleProbe.opens, 0);
});

test("request-bound shell PREPARED status is accepted exactly once before preflight", async (t) => {
  const fixture = await createFixture(t, { publicMetricsStatus: 404 });
  const request = JSON.parse(await readFile(fixture.requestPath, "utf8")) as ProductionUpgradeRequest;
  await writeFile(fixture.statusPath, `${JSON.stringify({
    version: 2,
    transactionId: request.transactionId,
    requestBindingDigest: productionUpgradeRequestBindingDigest(request),
    state: "PREPARED",
    requestedAt: request.requestedAt,
    updatedAt: request.requestedAt,
    expectedDisconnect: true,
    previous: request.previous,
    next: request.next,
    history: [{ state: "PREPARED", at: request.requestedAt }],
  }, null, 2)}\n`, { mode: 0o600 });

  await runProductionUpgradeWorker(fixture.requestPath, fixture.dependencies);
  const status = JSON.parse(await readFile(fixture.statusPath, "utf8")) as {
    state: string;
    history: Array<{ state: string }>;
  };
  assert.equal(status.state, "PASS");
  assert.deepEqual(status.history.slice(0, 2).map((entry) => entry.state), ["PREPARED", "ACCEPTED"]);
  assert.equal(status.history.filter((entry) => entry.state === "ACCEPTED").length, 1);
});

test("one exclusive worker claim prevents concurrent stop snapshot and provider replay", async (t) => {
  const fixture = await createFixture(t, { publicMetricsStatus: 404 });
  const request = JSON.parse(await readFile(fixture.requestPath, "utf8")) as ProductionUpgradeRequest;
  request.delayMs = 500;
  request.connectorLifecycle.bindingDigest = productionUpgradeLifecycleBindingDigest(request);
  await writeFile(fixture.requestPath, serializeProductionUpgradeRequestV4(request), { mode: 0o600 });
  const claimPath = `${fixture.statusPath}.worker-claim.json`;

  const winner = runProductionUpgradeWorker(fixture.requestPath, fixture.dependencies);
  let claimed = false;
  for (let attempt = 0; attempt < 100; attempt += 1) {
    const status = await readFile(fixture.statusPath, "utf8").catch(() => undefined);
    if (status && JSON.parse(status).state === "CONNECTOR_ACTIVATION_PREPARED") {
      claimed = true;
      break;
    }
    await new Promise((resolve) => setTimeout(resolve, 10));
  }
  assert.equal(claimed, true, "the winning worker must publish its claim before the contender starts");
  await assert.rejects(
    runProductionUpgradeWorker(fixture.requestPath, fixture.dependencies),
    /active worker claim/u,
  );
  await winner;

  const status = JSON.parse(await readFile(fixture.statusPath, "utf8")) as {
    state: string;
    history: Array<{ state: string }>;
  };
  assert.equal(status.state, "PASS");
  assert.equal(status.history.filter((entry) => entry.state === "ACCEPTED").length, 1);
  assert.equal(status.history.filter((entry) => entry.state === "CUTOVER_STOP_REQUESTED").length, 1);
  assert.equal(status.history.filter((entry) => entry.state === "STATE_SNAPSHOTTED").length, 1);
  assert.equal(fixture.lifecycleProbe.providerDispatches, 1);
  await assert.rejects(stat(claimPath), /ENOENT/u);
});

test("request and existing status must be owner-only regular files before JSON is trusted", async (t) => {
  await t.test("request", async (t) => {
    const fixture = await createFixture(t, { publicMetricsStatus: 404, lifecycleFailure: "PREPARE" });
    await chmod(fixture.requestPath, 0o666);
    await assert.rejects(
      runProductionUpgradeWorker(fixture.requestPath, fixture.dependencies),
      /request.*owner-only regular file/u,
    );
    assert.equal(fixture.lifecycleProbe.opens, 0);
  });

  await t.test("persisted status", async (t) => {
    const fixture = await createFixture(t, { publicMetricsStatus: 404 });
    await runProductionUpgradeWorker(fixture.requestPath, fixture.dependencies);
    await chmod(fixture.statusPath, 0o666);
    const opensBeforeReplay = fixture.lifecycleProbe.opens;
    await assert.rejects(
      runProductionUpgradeWorker(fixture.requestPath, fixture.dependencies),
      /status.*owner-only regular file/u,
    );
    assert.equal(fixture.lifecycleProbe.opens, opensBeforeReplay);
  });

  await t.test("request ancestor symlink", async (t) => {
    const fixture = await createFixture(t, { publicMetricsStatus: 404 });
    const alias = join(dirname(fixture.auditDirectory), "request-audit-alias");
    await symlink(fixture.auditDirectory, alias);
    await assert.rejects(
      runProductionUpgradeWorker(join(alias, "request.json"), fixture.dependencies),
      /request.*symbolic-link component/u,
    );
    assert.equal(fixture.lifecycleProbe.opens, 0);
  });

  await t.test("status ancestor symlink", async (t) => {
    const fixture = await createFixture(t, { publicMetricsStatus: 404 });
    const realStatusDirectory = join(fixture.auditDirectory, "status-real");
    const aliasStatusDirectory = join(fixture.auditDirectory, "status-alias");
    await mkdir(realStatusDirectory, { mode: 0o700 });
    await symlink(realStatusDirectory, aliasStatusDirectory);
    const request = JSON.parse(await readFile(fixture.requestPath, "utf8")) as ProductionUpgradeRequest;
    request.statusPath = join(aliasStatusDirectory, "status.json");
    request.workerClaimPath = `${request.statusPath}.worker-claim.json`;
    request.connectorLifecycle.bindingDigest = productionUpgradeLifecycleBindingDigest(request);
    await writeFile(fixture.requestPath, serializeProductionUpgradeRequestV4(request), { mode: 0o600 });
    await assert.rejects(
      runProductionUpgradeWorker(fixture.requestPath, fixture.dependencies),
      /status directory.*symbolic-link component/u,
    );
    assert.equal(fixture.lifecycleProbe.opens, 0);
  });
});

test("persisted PASS performs exact current runtime and connector readback before returning", async (t) => {
  const fixture = await createFixture(t, { publicMetricsStatus: 404, timeoutMs: 250 });
  await runProductionUpgradeWorker(fixture.requestPath, fixture.dependencies);
  const opensBeforeReplay = fixture.lifecycleProbe.opens;
  const dispatchesBeforeReplay = fixture.lifecycleProbe.providerDispatches;
  await writeFile(fixture.pm2State.cwd, "/nonexistent/stale-pass-runtime\n", { mode: 0o600 });
  await assert.rejects(
    runProductionUpgradeWorker(fixture.requestPath, fixture.dependencies),
    /PM2 cwd mismatch|Persisted PASS current-state verification failed/u,
  );
  assert.ok(fixture.lifecycleProbe.opens > opensBeforeReplay, "persisted PASS must reopen the lifecycle stores");
  assert.equal(fixture.lifecycleProbe.providerDispatches, dispatchesBeforeReplay, "PASS readback must not replay provider dispatch");
  const status = JSON.parse(await readFile(fixture.statusPath, "utf8")) as { state?: string };
  assert.equal(status.state, "UNKNOWN");
});

test("legacy five-state PASS cannot bypass POST_ACTIVATION_VERIFIED", async (t) => {
  const fixture = await createFixture(t, {
    publicMetricsStatus: 404,
    lifecycleFailure: "PREPARE",
  });
  await assert.rejects(
    runProductionUpgradeWorker(fixture.requestPath, fixture.dependencies),
    /fixture lifecycle prepare fault/u,
  );
  const status = JSON.parse(await readFile(fixture.statusPath, "utf8")) as Record<string, unknown>;
  status.state = "PASS";
  status.history = [
    { state: "PREPARED", at: new Date().toISOString() },
    { state: "ACCEPTED", at: new Date().toISOString() },
    { state: "SWITCHING", at: new Date().toISOString() },
    { state: "VERIFYING", at: new Date().toISOString() },
    { state: "PASS", at: new Date().toISOString() },
  ];
  delete status.connectorLifecycle;
  await writeFile(fixture.statusPath, `${JSON.stringify(status, null, 2)}\n`, { mode: 0o600 });
  const opensBeforeReplay = fixture.lifecycleProbe.opens;
  await assert.rejects(
    runProductionUpgradeWorker(fixture.requestPath, fixture.dependencies),
    /Legacy production upgrade status cannot claim PASS/u,
  );
  assert.equal(fixture.lifecycleProbe.opens, opensBeforeReplay);
  assert.equal(fixture.lifecycleProbe.providerDispatches, 0);
  assert.equal(
    (await readFile(fixture.pm2State.pid, "utf8")).trim(),
    "333",
    "the initial post-snapshot prepare failure already restored and restarted the previous runtime",
  );
});

test("tampered evidence and external-control journal state fail before switch", async (t) => {
  await t.test("release-driver provenance is complete, immutable, distinct, and external", async (t) => {
    await t.test("omitted provenance", async (t) => {
      const fixture = await createFixture(t, { publicMetricsStatus: 404 });
      const request = JSON.parse(await readFile(fixture.requestPath, "utf8")) as ProductionUpgradeRequest;
      delete (request.connectorLifecycle as Partial<ProductionUpgradeRequest["connectorLifecycle"]>).releaseDriver;
      await writeFile(fixture.requestPath, `${JSON.stringify(request, null, 2)}\n`, { mode: 0o600 });
      await assert.rejects(
        runProductionUpgradeWorker(fixture.requestPath, fixture.dependencies),
        /missing key releaseDriver/u,
      );
      assert.equal(fixture.lifecycleProbe.opens, 0);
    });

    await t.test("tampered provenance bytes", async (t) => {
      const fixture = await createFixture(t, { publicMetricsStatus: 404 });
      await writeFile(fixture.releaseDriverPaths.stagingActivationReadback, "tampered\n", { mode: 0o600 });
      await assert.rejects(
        runProductionUpgradeWorker(fixture.requestPath, fixture.dependencies),
        /release-driver provenance digest mismatch/u,
      );
      assert.equal(fixture.lifecycleProbe.opens, 0);
    });

    await t.test("aliased provenance paths", async (t) => {
      const fixture = await createFixture(t, { publicMetricsStatus: 404 });
      const request = JSON.parse(await readFile(fixture.requestPath, "utf8")) as ProductionUpgradeRequest;
      request.connectorLifecycle.releaseDriver.preCutoverRequest = {
        ...request.connectorLifecycle.releaseDriver.stagingPrecheckRequest,
      };
      await writeFile(fixture.requestPath, serializeUncheckedProductionUpgradeRequest(request), { mode: 0o600 });
      await assert.rejects(
        runProductionUpgradeWorker(fixture.requestPath, fixture.dependencies),
        /release-driver provenance.*non-overlapping/u,
      );
      assert.equal(fixture.lifecycleProbe.opens, 0);
    });

    await t.test("mutable snapshot overlap", async (t) => {
      const fixture = await createFixture(t, { publicMetricsStatus: 404 });
      const request = JSON.parse(await readFile(fixture.requestPath, "utf8")) as ProductionUpgradeRequest;
      request.connectorLifecycle.releaseDriver.stagingPrecheckRequest = {
        path: fixture.contextStorePath,
        sha256: digestBytes(await readFile(fixture.contextStorePath)),
      };
      await writeFile(fixture.requestPath, serializeUncheckedProductionUpgradeRequest(request), { mode: 0o600 });
      await assert.rejects(
        runProductionUpgradeWorker(fixture.requestPath, fixture.dependencies),
        /overlaps mutable snapshot state/u,
      );
      assert.equal(fixture.lifecycleProbe.opens, 0);
    });

    await t.test("immutable package overlap", async (t) => {
      const fixture = await createFixture(t, { publicMetricsStatus: 404 });
      const request = JSON.parse(await readFile(fixture.requestPath, "utf8")) as ProductionUpgradeRequest;
      request.connectorLifecycle.releaseDriver.productionPreparationRequest = {
        path: fixture.nextScript,
        sha256: digestBytes(await readFile(fixture.nextScript)),
      };
      await writeFile(fixture.requestPath, serializeUncheckedProductionUpgradeRequest(request), { mode: 0o600 });
      await assert.rejects(
        runProductionUpgradeWorker(fixture.requestPath, fixture.dependencies),
        /immutable release root|overlaps immutable package state/u,
      );
      assert.equal(fixture.lifecycleProbe.opens, 0);
    });
  });

  await t.test("tampered PRE evidence", async (t) => {
    const fixture = await createFixture(t, { publicMetricsStatus: 404 });
    const request = JSON.parse(await readFile(fixture.requestPath, "utf8")) as ProductionUpgradeRequest;
    await writeFile(request.connectorLifecycle.preCutoverHostCanary.path, "tampered\n", { mode: 0o600 });
    await assert.rejects(
      runProductionUpgradeWorker(fixture.requestPath, fixture.dependencies),
      /Connector lifecycle evidence digest mismatch/u,
    );
    assert.equal(fixture.lifecycleProbe.opens, 0);
    assert.equal((await readFile(fixture.pm2State.pid, "utf8")).trim(), "111");
  });

  await t.test("rollback challenge is signed, fresh, and has an absent receipt target", async (t) => {
    await t.test("tampered challenge bytes", async (t) => {
      const fixture = await createFixture(t, { publicMetricsStatus: 404 });
      await writeFile(fixture.rollbackHostChallengePath, "tampered\n", { mode: 0o600 });
      await assert.rejects(
        runProductionUpgradeWorker(fixture.requestPath, fixture.dependencies),
        /Rollback Host challenge digest is not request-bound/u,
      );
      assert.equal(fixture.lifecycleProbe.opens, 0);
      assert.equal((await readFile(fixture.pm2State.pid, "utf8")).trim(), "111");
    });

    await t.test("expired signed challenge", async (t) => {
      const fixture = await createFixture(t, { publicMetricsStatus: 404 });
      const request = JSON.parse(await readFile(fixture.requestPath, "utf8")) as ProductionUpgradeRequest;
      const original = JSON.parse(
        await readFile(fixture.rollbackHostChallengePath, "utf8"),
      ) as { payload: Record<string, unknown> };
      const issuedAtMs = Date.now() - 10_000;
      const envelope = signConnectorRollbackHostChallenge({
        ...(original.payload as unknown as Parameters<typeof signConnectorRollbackHostChallenge>[0]),
        issuedAtMs,
        expiresAtMs: Date.now() - 1,
      }, fixture.managementKey, issuedAtMs);
      const content = `${JSON.stringify(envelope, null, 2)}\n`;
      await writeFile(fixture.rollbackHostChallengePath, content, { mode: 0o600 });
      request.previous.rollbackHostChallenge.challengeSha256 = digestBytes(content);
      request.connectorLifecycle.bindingDigest = productionUpgradeLifecycleBindingDigest(request);
      await writeFile(fixture.requestPath, serializeProductionUpgradeRequestV4(request), { mode: 0o600 });
      await assert.rejects(
        runProductionUpgradeWorker(fixture.requestPath, fixture.dependencies),
        /rollback challenge is not currently valid/u,
      );
      assert.equal(fixture.lifecycleProbe.opens, 0);
      assert.equal((await readFile(fixture.pm2State.pid, "utf8")).trim(), "111");
    });

    await t.test("preexisting future receipt", async (t) => {
      const fixture = await createFixture(t, { publicMetricsStatus: 404 });
      await writeFile(fixture.rollbackHostReceiptPath, "caller-authored PASS\n", { mode: 0o600 });
      await assert.rejects(
        runProductionUpgradeWorker(fixture.requestPath, fixture.dependencies),
        /receipt target must be absent/u,
      );
      assert.equal(fixture.lifecycleProbe.opens, 0);
      assert.equal((await readFile(fixture.pm2State.pid, "utf8")).trim(), "111");
    });
  });

  await t.test("stale empty or manifested snapshot root", async (t) => {
    for (const manifest of [false, true]) {
      await t.test(manifest ? "manifest" : "empty", async (t) => {
        const fixture = await createFixture(t, { publicMetricsStatus: 404 });
        const request = JSON.parse(await readFile(fixture.requestPath, "utf8")) as ProductionUpgradeRequest;
        await mkdir(request.snapshotGroup!.snapshotRoot, { mode: 0o700 });
        if (manifest) {
          await writeFile(
            join(request.snapshotGroup!.snapshotRoot, "SNAPSHOT-GROUP.json"),
            "{}\n",
            { mode: 0o600 },
          );
        }
        await assert.rejects(
          runProductionUpgradeWorker(fixture.requestPath, fixture.dependencies),
          /new transaction-specific path/u,
        );
        assert.equal(fixture.lifecycleProbe.opens, 0);
        assert.equal((await readFile(fixture.pm2State.pid, "utf8")).trim(), "111");
      });
    }
  });

  await t.test("snapshot entry reaches an external journal through an ancestor symlink", async (t) => {
    const fixture = await createFixture(t, { publicMetricsStatus: 404 });
    const request = JSON.parse(await readFile(fixture.requestPath, "utf8")) as ProductionUpgradeRequest;
    const controlAlias = join(dirname(dirname(fixture.connectorJournalPath)), "control-alias");
    await symlink(dirname(fixture.connectorJournalPath), controlAlias);
    const contextEntry = request.snapshotGroup!.entries.find((entry) => entry.id === "contexts-store")!;
    contextEntry.path = join(controlAlias, "connector-activation.sqlite");
    request.connectorLifecycle.bindingDigest = productionUpgradeLifecycleBindingDigest(request);
    await writeFile(fixture.requestPath, serializeProductionUpgradeRequestV4(request), { mode: 0o600 });
    await assert.rejects(
      runProductionUpgradeWorker(fixture.requestPath, fixture.dependencies),
      /symbolic-link component/u,
    );
    assert.equal(fixture.lifecycleProbe.opens, 0);
    assert.equal((await readFile(fixture.pm2State.pid, "utf8")).trim(), "111");
  });

  await t.test("journal overlaps mutable snapshot entry", async (t) => {
    const fixture = await createFixture(t, { publicMetricsStatus: 404 });
    const request = JSON.parse(await readFile(fixture.requestPath, "utf8")) as ProductionUpgradeRequest;
    const contextEntry = request.snapshotGroup!.entries.find((entry) => entry.id === "contexts-store")!;
    contextEntry.path = request.connectorLifecycle.journal.path;
    await writeFile(fixture.requestPath, serializeUncheckedProductionUpgradeRequest(request), { mode: 0o600 });
    await assert.rejects(
      runProductionUpgradeWorker(fixture.requestPath, fixture.dependencies),
      /external control path overlaps mutable snapshot state/u,
    );
    assert.equal(fixture.lifecycleProbe.opens, 0);
    assert.equal((await readFile(fixture.pm2State.pid, "utf8")).trim(), "111");
  });

  await t.test("journal overlaps a mutable SQLite sidecar restore target", async (t) => {
    for (const suffix of ["-wal", "-shm"] as const) {
      await t.test(suffix, async (t) => {
        const fixture = await createFixture(t, { publicMetricsStatus: 404 });
        const request = JSON.parse(await readFile(fixture.requestPath, "utf8")) as ProductionUpgradeRequest;
        const journalPath = `${fixture.filesystemSyncStorePath}${suffix}`;
        await writeFile(journalPath, `external connector journal ${suffix}\n`, { mode: 0o600 });
        request.connectorLifecycle.journal.path = journalPath;
        request.connectorLifecycle.journal.identity.storePath = journalPath;
        await writeFile(fixture.requestPath, serializeUncheckedProductionUpgradeRequest(request), { mode: 0o600 });
        await assert.rejects(
          runProductionUpgradeWorker(fixture.requestPath, fixture.dependencies),
          /external control path overlaps mutable snapshot state/u,
        );
        assert.equal(fixture.lifecycleProbe.opens, 0);
        assert.equal(await readFile(journalPath, "utf8"), `external connector journal ${suffix}\n`);
        assert.equal((await readFile(fixture.pm2State.pid, "utf8")).trim(), "111");
      });
    }
  });

  await t.test("malformed rollback journal", async (t) => {
    const fixture = await createFixture(t, { publicMetricsStatus: 404 });
    await writeFile(fixture.rollbackJournalPath, "{not-json}\n", { mode: 0o600 });
    await assert.rejects(
      runProductionUpgradeWorker(fixture.requestPath, fixture.dependencies),
      /Rollback control journal contains invalid JSON/u,
    );
    assert.equal(fixture.lifecycleProbe.opens, 0);
    assert.equal((await readFile(fixture.pm2State.pid, "utf8")).trim(), "111");
    assert.equal(readFixtureDatabaseValue(fixture.oauthDatabasePath), "OLD_OAUTH_DATABASE");
  });
});

test("resume rejects a snapshot barrier rebound to a foreign transaction without replay", async (t) => {
  const fixture = await createFixture(t, { publicMetricsStatus: 404 });
  await runProductionUpgradeWorker(fixture.requestPath, fixture.dependencies);
  const request = JSON.parse(await readFile(fixture.requestPath, "utf8")) as ProductionUpgradeRequest;
  const status = JSON.parse(await readFile(fixture.statusPath, "utf8")) as Record<string, unknown> & {
    history: Array<{ state: string; at: string }>;
    snapshotGroupPreimage: Record<string, unknown> & {
      barrier: Record<string, unknown>;
    };
  };
  const runtimeIndex = status.history.findIndex((entry) => entry.state === "RUNTIME_STARTED");
  assert.notEqual(runtimeIndex, -1);
  status.state = "RUNTIME_STARTED";
  status.history = status.history.slice(0, runtimeIndex + 1);
  status.connectorLifecycle = {
    state: "ACTIVATED_PENDING_POSTCHECK",
    receiptId: fixture.activation.receiptId,
    tupleDigest: fixture.activation.tupleDigest,
    activationReceiptDigest: digestLabel("fixture-activation-receipt"),
    activationProofDigest: digestLabel("fixture-activation-proof"),
    authorityReceiptDigest: digestLabel("fixture-activation-authority-receipt"),
    journalContentGeneration: digestLabel("fixture-journal-pending"),
  };
  status.snapshotGroupPreimage.barrier.transactionId = "upgrade_22222222-2222-4222-8222-222222222222";
  const { groupDigest: _discarded, ...unsigned } = status.snapshotGroupPreimage;
  status.snapshotGroupPreimage.groupDigest = digestJson(unsigned);
  await writeFile(fixture.statusPath, `${JSON.stringify(status, null, 2)}\n`, { mode: 0o600 });
  const dispatchesBefore = fixture.lifecycleProbe.providerDispatches;
  await assert.rejects(
    runProductionUpgradeWorker(fixture.requestPath, fixture.dependencies),
    /snapshot barrier is not bound to this stopped transaction/u,
  );
  assert.equal(fixture.lifecycleProbe.providerDispatches, dispatchesBefore);
});

test("fault after durable activation dispatch never replays and snapshot restore preserves the journal", async (t) => {
  const fixture = await createFixture(t, {
    publicMetricsStatus: 404,
    lifecycleFailure: "ACTIVATE_AFTER_DISPATCH",
  });
  await assert.rejects(
    runProductionUpgradeWorker(fixture.requestPath, fixture.dependencies),
    /fixture lifecycle fault after durable DISPATCHED/u,
  );
  assert.equal(fixture.lifecycleProbe.providerDispatches, 1);
  assert.equal(readFixtureDatabaseValue(fixture.connectorJournalPath), "DISPATCHED_PERMANENT_ONE_SHOT");
  await assert.rejects(
    runProductionUpgradeWorker(fixture.requestPath, fixture.dependencies),
    /terminal or rollback-bound/u,
  );
  assert.equal(fixture.lifecycleProbe.providerDispatches, 1);
  assert.equal(readFixtureDatabaseValue(fixture.connectorJournalPath), "DISPATCHED_PERMANENT_ONE_SHOT");
});

test("restore uncertainty records UNKNOWN before old start and retains external dispatch tombstone", async (t) => {
  const fixture = await createFixture(t, {
    publicMetricsStatus: 404,
    lifecycleFailure: "WAIT_POST",
    corruptSnapshotBeforeRollback: true,
  });
  await assert.rejects(
    runProductionUpgradeWorker(fixture.requestPath, fixture.dependencies),
    /fixture lifecycle POST wait fault/u,
  );
  const status = JSON.parse(await readFile(fixture.statusPath, "utf8")) as {
    state?: string;
    rollback?: { verified?: boolean };
  };
  assert.equal(status.state, "ROLLBACK_UNKNOWN");
  assert.equal(status.rollback?.verified, false);
  assert.equal((await readFile(fixture.pm2State.pid, "utf8")).trim(), "0", "old runtime must not start");
  assert.equal(readFixtureDatabaseValue(fixture.connectorJournalPath), "DISPATCHED_PERMANENT_ONE_SHOT");
  const events = (await readFile(fixture.rollbackJournalPath, "utf8"))
    .trim()
    .split("\n")
    .map((line) => (JSON.parse(line) as { event: string }).event);
  assert.deepEqual(events, [
    "ROLLBACK_REQUESTED",
    "ROLLBACK_RESTORE_UNKNOWN",
    "ROLLBACK_RUNTIME_UNKNOWN",
  ]);
});

test("resume from a running-candidate phase reconciles without stopping or replaying it", async (t) => {
  for (const resumeState of [
    "RUNTIME_STARTED",
    "POST_SWITCH_VERIFIED",
    "POST_ACTIVATION_VERIFIED",
  ] as const) {
    await t.test(resumeState, async (t) => {
      const fixture = await createFixture(t, { publicMetricsStatus: 404 });
      await runProductionUpgradeWorker(fixture.requestPath, fixture.dependencies);
      const request = JSON.parse(
        await readFile(fixture.requestPath, "utf8"),
      ) as ProductionUpgradeRequest;
      const status = JSON.parse(
        await readFile(fixture.statusPath, "utf8"),
      ) as Record<string, unknown> & {
        history: Array<{ state: string; at: string }>;
        snapshotGroupPreimage: { groupDigest: string };
      };
      const snapshotDigest = status.snapshotGroupPreimage.groupDigest;
      const resumeIndex = status.history.findIndex((entry) => entry.state === resumeState);
      assert.notEqual(resumeIndex, -1);
      status.state = resumeState;
      status.history = status.history.slice(0, resumeIndex + 1);
      if (resumeState !== "POST_ACTIVATION_VERIFIED") {
        status.connectorLifecycle = {
          state: "ACTIVATED_PENDING_POSTCHECK",
          receiptId: fixture.activation.receiptId,
          tupleDigest: fixture.activation.tupleDigest,
          activationReceiptDigest: digestLabel("fixture-activation-receipt"),
          activationProofDigest: digestLabel("fixture-activation-proof"),
          authorityReceiptDigest: digestLabel("fixture-activation-authority-receipt"),
          journalContentGeneration: digestLabel("fixture-journal-pending"),
        };
      }
      await writeFile(fixture.statusPath, `${JSON.stringify(status, null, 2)}\n`, { mode: 0o600 });
      await writeFile(fixture.startScriptPath, "#!/bin/bash\nexec old\n", { mode: 0o700 });
      await rm(fixture.currentAuditLink);
      await symlink(fixture.previousAudit, fixture.currentAuditLink);

      const waitsBeforeResume = fixture.lifecycleProbe.waits;
      await runProductionUpgradeWorker(fixture.requestPath, fixture.dependencies);

      const resumed = JSON.parse(await readFile(fixture.statusPath, "utf8")) as {
        state: string;
        snapshotGroupPreimage: { groupDigest: string };
      };
      assert.equal(resumed.state, "PASS");
      assert.equal(resumed.snapshotGroupPreimage.groupDigest, snapshotDigest);
      assert.equal((await readFile(fixture.pm2State.pid, "utf8")).trim(), "222");
      assert.match(await readFile(fixture.startScriptPath, "utf8"), new RegExp(escapeRegExp(fixture.nextScript), "u"));
      assert.equal(await readlink(fixture.currentAuditLink), fixture.auditDirectory);
      assert.equal(fixture.lifecycleProbe.providerDispatches, 1);
      if (resumeState === "POST_ACTIVATION_VERIFIED") {
        assert.equal(
          fixture.lifecycleProbe.waits,
          waitsBeforeResume,
          "terminal POST restart must not wait for or reinterpret a new receipt",
        );
      }
      assert.equal(readFixtureDatabaseValue(fixture.connectorJournalPath), "DISPATCHED_PERMANENT_ONE_SHOT");
      assert.equal(await readFile(fixture.rollbackJournalPath, "utf8"), "");
    });
  }
});

test("resume after the durable stop barrier does not probe the intentionally absent old runtime", async (t) => {
  const fixture = await createFixture(t, {
    publicMetricsStatus: 404,
    previousRuntimeUnavailableWhenStopped: true,
  });
  const request = JSON.parse(await readFile(fixture.requestPath, "utf8")) as ProductionUpgradeRequest;
  const requestedAtMs = Date.parse(request.requestedAt);
  const history = [
    "PREPARED",
    "ACCEPTED",
    "PREFLIGHT_VERIFIED",
    "CONNECTOR_ACTIVATION_PREPARED",
    "CUTOVER_STOP_REQUESTED",
    "CUTOVER_PROCESSES_STOPPED",
  ].map((state, index) => ({
    state,
    at: new Date(requestedAtMs + index).toISOString(),
  }));
  await writeFile(fixture.statusPath, `${JSON.stringify({
    version: 2,
    transactionId: request.transactionId,
    requestBindingDigest: productionUpgradeRequestBindingDigest(request),
    state: "CUTOVER_PROCESSES_STOPPED",
    requestedAt: request.requestedAt,
    updatedAt: history.at(-1)!.at,
    expectedDisconnect: true,
    previous: request.previous,
    next: request.next,
    history,
    connectorLifecycle: {
      state: "CONNECTOR_ACTIVATION_PREPARED",
      receiptId: fixture.activation.receiptId,
      tupleDigest: fixture.activation.tupleDigest,
      journalContentGeneration: digestLabel("fixture-journal-prepared"),
    },
  }, null, 2)}\n`, { mode: 0o600 });
  await writeFile(fixture.pm2State.pid, "0\n", { mode: 0o600 });

  await runProductionUpgradeWorker(fixture.requestPath, fixture.dependencies);

  const status = JSON.parse(await readFile(fixture.statusPath, "utf8")) as {
    state: string;
    history: Array<{ state: string }>;
  };
  assert.equal(status.state, "PASS");
  assert.equal(status.history.filter((entry) => entry.state === "CUTOVER_PROCESSES_STOPPED").length, 1);
  assert.equal(status.history.filter((entry) => entry.state === "STATE_SNAPSHOTTED").length, 1);
});

test("durable stop intent closes the PM2-delete to stopped-status crash window", async (t) => {
  const fixture = await createFixture(t, {
    publicMetricsStatus: 404,
    previousRuntimeUnavailableWhenStopped: true,
  });
  const request = JSON.parse(await readFile(fixture.requestPath, "utf8")) as ProductionUpgradeRequest;
  const requestedAtMs = Date.parse(request.requestedAt);
  const history = [
    "PREPARED",
    "ACCEPTED",
    "PREFLIGHT_VERIFIED",
    "CONNECTOR_ACTIVATION_PREPARED",
    "CUTOVER_STOP_REQUESTED",
  ].map((state, index) => ({
    state,
    at: new Date(requestedAtMs + index).toISOString(),
  }));
  await writeFile(fixture.statusPath, `${JSON.stringify({
    version: 2,
    transactionId: request.transactionId,
    requestBindingDigest: productionUpgradeRequestBindingDigest(request),
    state: "CUTOVER_STOP_REQUESTED",
    requestedAt: request.requestedAt,
    updatedAt: history.at(-1)!.at,
    expectedDisconnect: true,
    previous: request.previous,
    next: request.next,
    history,
    connectorLifecycle: {
      state: "CONNECTOR_ACTIVATION_PREPARED",
      receiptId: fixture.activation.receiptId,
      tupleDigest: fixture.activation.tupleDigest,
      journalContentGeneration: digestLabel("fixture-journal-prepared"),
    },
  }, null, 2)}\n`, { mode: 0o600 });
  await writeFile(fixture.pm2State.pid, "0\n", { mode: 0o600 });

  await runProductionUpgradeWorker(fixture.requestPath, fixture.dependencies);

  const status = JSON.parse(await readFile(fixture.statusPath, "utf8")) as {
    state: string;
    history: Array<{ state: string }>;
  };
  assert.equal(status.state, "PASS");
  assert.equal(status.history.filter((entry) => entry.state === "CUTOVER_STOP_REQUESTED").length, 1);
  assert.equal(status.history.filter((entry) => entry.state === "CUTOVER_PROCESSES_STOPPED").length, 1);
});

test("partial multi-process stop failure remains resumable instead of terminal FAIL", async (t) => {
  const fixture = await createFixture(t, { publicMetricsStatus: 404 });
  const request = JSON.parse(await readFile(fixture.requestPath, "utf8")) as ProductionUpgradeRequest;
  const originalPm2 = `${request.pm2Executable}.original`;
  const extraProcessState = `${request.pm2Executable}.extra-process`;
  const failOnce = `${request.pm2Executable}.fail-once`;
  await rename(request.pm2Executable, originalPm2);
  await writeFile(extraProcessState, "1\n", { mode: 0o600 });
  await writeFile(request.pm2Executable, [
    "#!/bin/sh",
    `original=${shellQuote(originalPm2)}`,
    `pid_file=${shellQuote(fixture.pm2State.pid)}`,
    `cwd_file=${shellQuote(fixture.pm2State.cwd)}`,
    `script_file=${shellQuote(fixture.pm2State.script)}`,
    `extra_state=${shellQuote(extraProcessState)}`,
    `fail_once=${shellQuote(failOnce)}`,
    "if [ \"$1\" = jlist ]; then",
    "  pid=$(cat \"$pid_file\")",
    "  extra=$(cat \"$extra_state\")",
    "  if [ \"$pid\" = 0 ] && [ \"$extra\" = 0 ]; then printf '[]\\n'; exit 0; fi",
    "  separator=",
    "  printf '['",
    "  if [ \"$pid\" != 0 ]; then",
    "    cwd=$(cat \"$cwd_file\"); script=$(cat \"$script_file\")",
    "    printf '{\"name\":\"devspace-v2-production\",\"pid\":%s,\"pm2_env\":{\"status\":\"online\",\"pm_cwd\":\"%s\",\"pm_exec_path\":\"%s\"}}' \"$pid\" \"$cwd\" \"$script\"",
    "    separator=,",
    "  fi",
    "  if [ \"$extra\" != 0 ]; then printf '%s{\"name\":\"fixture-cutover-worker\",\"pid\":444,\"pm2_env\":{\"status\":\"online\"}}' \"$separator\"; fi",
    "  printf ']\\n'",
    "  exit 0",
    "fi",
    "if [ \"$1\" = delete ] && [ \"$2\" = fixture-cutover-worker ]; then",
    "  if [ ! -e \"$fail_once\" ]; then : > \"$fail_once\"; exit 70; fi",
    "  printf '0\\n' > \"$extra_state\"",
    "  exit 0",
    "fi",
    "exec \"$original\" \"$@\"",
    "",
  ].join("\n"), { mode: 0o700 });
  await chmod(request.pm2Executable, 0o700);
  request.cutoverProcessNames = [request.pm2ProcessName, "fixture-cutover-worker"];
  request.snapshotGroup.barrier.cutoverProcessNames = [...request.cutoverProcessNames];
  request.connectorLifecycle.bindingDigest = productionUpgradeLifecycleBindingDigest(request);
  await writeFile(fixture.requestPath, serializeProductionUpgradeRequestV4(request), { mode: 0o600 });

  await assert.rejects(
    runProductionUpgradeWorker(fixture.requestPath, fixture.dependencies),
    /Cutover processes remain active: fixture-cutover-worker/u,
  );
  const interrupted = JSON.parse(await readFile(fixture.statusPath, "utf8")) as {
    state: string;
    history: Array<{ state: string }>;
  };
  assert.equal(interrupted.state, "CUTOVER_STOP_REQUESTED");
  assert.equal(interrupted.history.at(-1)?.state, "CUTOVER_STOP_REQUESTED");
  assert.equal((await readFile(fixture.pm2State.pid, "utf8")).trim(), "0");
  assert.equal((await readFile(extraProcessState, "utf8")).trim(), "1");

  await runProductionUpgradeWorker(fixture.requestPath, fixture.dependencies);
  const resumed = JSON.parse(await readFile(fixture.statusPath, "utf8")) as {
    state: string;
    history: Array<{ state: string }>;
  };
  assert.equal(resumed.state, "PASS");
  assert.equal(resumed.history.filter((entry) => entry.state === "CUTOVER_STOP_REQUESTED").length, 1);
  assert.equal(resumed.history.filter((entry) => entry.state === "CUTOVER_PROCESSES_STOPPED").length, 1);
  assert.equal((await readFile(extraProcessState, "utf8")).trim(), "0");
  assert.equal(fixture.lifecycleProbe.providerDispatches, 1);
});

test("resume adopts an exact published snapshot when status persistence was interrupted", async (t) => {
  const fixture = await createFixture(t, {
    publicMetricsStatus: 404,
    previousRuntimeUnavailableWhenStopped: true,
  });
  const request = JSON.parse(await readFile(fixture.requestPath, "utf8")) as ProductionUpgradeRequest;
  const snapshotGroup = request.snapshotGroup!;
  const requestedAtMs = Date.parse(request.requestedAt);
  const history = [
    "PREPARED",
    "ACCEPTED",
    "PREFLIGHT_VERIFIED",
    "CONNECTOR_ACTIVATION_PREPARED",
    "CUTOVER_STOP_REQUESTED",
    "CUTOVER_PROCESSES_STOPPED",
  ].map((state, index) => ({
    state,
    at: new Date(requestedAtMs + index).toISOString(),
  }));
  const stoppedAt = history.at(-1)!.at;
  const requestBindingDigest = productionUpgradeRequestBindingDigest(request);
  const captured = await captureSnapshotGroup({
    snapshotRoot: snapshotGroup.snapshotRoot,
    barrier: {
      kind: "PM2_STOPPED",
      processName: request.pm2ProcessName,
      previousPid: request.previous.pid,
      previousRuntimeIdentityDigest: request.previous.runtimeIdentityDigest,
      previousMigrationManifestDigest: request.previous.migrationManifestDigest,
      transactionId: request.transactionId,
      requestBindingDigest,
      cutoverProcessNames: [...request.cutoverProcessNames].sort(),
      establishedAt: stoppedAt,
    },
    entries: snapshotGroup.entries,
  });
  await writeFile(fixture.statusPath, `${JSON.stringify({
    version: 2,
    transactionId: request.transactionId,
    requestBindingDigest,
    state: "CUTOVER_PROCESSES_STOPPED",
    requestedAt: request.requestedAt,
    updatedAt: stoppedAt,
    expectedDisconnect: true,
    previous: request.previous,
    next: request.next,
    history,
    connectorLifecycle: {
      state: "CONNECTOR_ACTIVATION_PREPARED",
      receiptId: fixture.activation.receiptId,
      tupleDigest: fixture.activation.tupleDigest,
      journalContentGeneration: digestLabel("fixture-journal-prepared"),
    },
  }, null, 2)}\n`, { mode: 0o600 });
  await writeFile(fixture.pm2State.pid, "0\n", { mode: 0o600 });

  await runProductionUpgradeWorker(fixture.requestPath, fixture.dependencies);

  const status = JSON.parse(await readFile(fixture.statusPath, "utf8")) as {
    state: string;
    snapshotGroupPreimage: { groupDigest: string };
    history: Array<{ state: string }>;
  };
  assert.equal(status.state, "PASS");
  assert.equal(status.snapshotGroupPreimage.groupDigest, captured.manifest.groupDigest);
  assert.equal(status.history.filter((entry) => entry.state === "STATE_SNAPSHOTTED").length, 1);
});

test("rollback journal write uncertainty stops the candidate and never starts the old runtime", async (t) => {
  await t.test("first ROLLBACK_REQUESTED append fails", async (t) => {
    const fixture = await createFixture(t, {
      publicMetricsStatus: 404,
      lifecycleFailure: "WAIT_POST",
      rollbackJournalFailure: "BEFORE_REQUEST",
    });
    await assert.rejects(
      runProductionUpgradeWorker(fixture.requestPath, fixture.dependencies),
      /fixture lifecycle POST wait fault/u,
    );
    const status = JSON.parse(await readFile(fixture.statusPath, "utf8")) as {
      state: string;
      rollback?: {
        restored?: boolean;
        verified?: boolean;
        outcome?: string;
        controlJournal?: { rollbackRequestDurable?: boolean };
      };
    };
    assert.equal(status.state, "ROLLBACK_UNKNOWN");
    assert.equal(status.rollback?.restored, false);
    assert.equal(status.rollback?.verified, false);
    assert.equal(status.rollback?.outcome, "ROLLBACK_CONTROL_JOURNAL_UNAVAILABLE");
    assert.equal(status.rollback?.controlJournal?.rollbackRequestDurable, false);
    assert.equal((await readFile(fixture.pm2State.pid, "utf8")).trim(), "0");
    assert.equal(readFixtureDatabaseValue(fixture.oauthDatabasePath), "CANDIDATE_OAUTH_DATABASE");
    assert.equal(await readFile(fixture.rollbackJournalPath, "utf8"), "");
  });

  await t.test("restore-evidence append fails after the request tombstone", async (t) => {
    const fixture = await createFixture(t, {
      publicMetricsStatus: 404,
      lifecycleFailure: "WAIT_POST",
      rollbackJournalFailure: "BEFORE_RESTORE_RECORD",
    });
    await assert.rejects(
      runProductionUpgradeWorker(fixture.requestPath, fixture.dependencies),
      /fixture lifecycle POST wait fault/u,
    );
    const status = JSON.parse(await readFile(fixture.statusPath, "utf8")) as {
      state: string;
      rollback?: {
        restored?: boolean;
        verified?: boolean;
        outcome?: string;
        controlJournal?: { rollbackRequestDurable?: boolean };
      };
    };
    assert.equal(status.state, "ROLLBACK_UNKNOWN");
    assert.equal(status.rollback?.restored, true);
    assert.equal(status.rollback?.verified, false);
    assert.equal(status.rollback?.outcome, "ROLLBACK_CONTROL_JOURNAL_UNAVAILABLE");
    assert.equal(status.rollback?.controlJournal?.rollbackRequestDurable, true);
    assert.equal((await readFile(fixture.pm2State.pid, "utf8")).trim(), "0");
    assert.equal(readFixtureDatabaseValue(fixture.oauthDatabasePath), "OLD_OAUTH_DATABASE");
    const records = (await readFile(fixture.rollbackJournalPath, "utf8"))
      .trim()
      .split("\n")
      .map((line) => JSON.parse(line) as { event: string });
    assert.deepEqual(records.map((record) => record.event), ["ROLLBACK_REQUESTED"]);
  });
});

test("durable rollback REQUESTED and RESTORING states resume from journal and snapshot", async (t) => {
  for (const [resumeState, journalLines] of [
    ["ROLLBACK_REQUESTED", 1],
    ["ROLLBACK_RESTORING", 2],
  ] as const) {
    await t.test(resumeState, async (t) => {
      const fixture = await createFixture(t, { publicMetricsStatus: 200, timeoutMs: 1_000 });
      await assert.rejects(
        runProductionUpgradeWorker(fixture.requestPath, fixture.dependencies),
        /Public metrics returned 200/u,
      );
      const status = JSON.parse(await readFile(fixture.statusPath, "utf8")) as Record<string, unknown> & {
        history: Array<{ state: string; at: string }>;
      };
      const resumeIndex = status.history.findIndex((entry) => entry.state === resumeState);
      assert.notEqual(resumeIndex, -1);
      status.state = resumeState;
      status.history = status.history.slice(0, resumeIndex + 1);
      status.updatedAt = status.history.at(-1)!.at;
      delete status.rollback;
      await writeFile(fixture.statusPath, `${JSON.stringify(status, null, 2)}\n`, { mode: 0o600 });
      const journal = (await readFile(fixture.rollbackJournalPath, "utf8"))
        .trim()
        .split("\n")
        .slice(0, journalLines);
      await writeFile(fixture.rollbackJournalPath, `${journal.join("\n")}\n`, { mode: 0o600 });
      await rm(fixture.rollbackHostReceiptPath, { force: true });
      await writeFile(fixture.pm2State.pid, "0\n", { mode: 0o600 });
      if (resumeState === "ROLLBACK_REQUESTED") {
        const request = JSON.parse(await readFile(fixture.requestPath, "utf8")) as {
          connectorLifecycle: { preCutoverHostCanary: { path: string } };
        };
        await writeFile(request.connectorLifecycle.preCutoverHostCanary.path, "tampered after rollback request\n", {
          mode: 0o600,
        });
      }

      await runProductionUpgradeWorker(fixture.requestPath, fixture.dependencies);

      const resumed = JSON.parse(await readFile(fixture.statusPath, "utf8")) as {
        state: string;
        rollback?: { verified?: boolean };
        history: Array<{ state: string }>;
      };
      assert.equal(resumed.state, "ROLLED_BACK");
      assert.equal(resumed.rollback?.verified, true);
      assert.equal(
        resumed.history.filter((entry) => entry.state === "ROLLBACK_REQUESTED").length,
        1,
      );
      assert.equal(
        resumed.history.filter((entry) => entry.state === "ROLLBACK_RESTORING").length,
        1,
      );
      const events = (await readFile(fixture.rollbackJournalPath, "utf8"))
        .trim()
        .split("\n")
        .map((line) => (JSON.parse(line) as { event: string }).event);
      assert.deepEqual(events, [
        "ROLLBACK_REQUESTED",
        "ROLLBACK_RESTORE_VERIFIED",
        "ROLLBACK_RUNTIME_VERIFIED",
      ]);
      assert.equal(fixture.lifecycleProbe.providerDispatches, 1);
    });
  }
});

test("production upgrade generated request keeps artifact catalog as a required Base SQLite snapshot", async (t) => {
  const upgradeScript = await readFile(new URL("../../scripts/upgrade-universal-broker-v2-production.sh", import.meta.url), "utf8");
  assert.match(
    upgradeScript,
    /\{"id":"artifact-catalog","kind":"sqlite","path":artifactCatalog,"required":true\}/u,
  );

  const fixture = await createFixture(t, { publicMetricsStatus: 404 });
  const request = JSON.parse(await readFile(fixture.requestPath, "utf8")) as ProductionUpgradeRequest;
  request.snapshotGroup.entries.find((entry) => entry.id === "artifact-catalog")!.required = false;
  await writeFile(
    fixture.requestPath,
    serializeUncheckedProductionUpgradeRequest(request),
    { mode: 0o600 },
  );
  await assert.rejects(
    runProductionUpgradeWorker(fixture.requestPath, fixture.dependencies),
    /snapshotGroup\.entries\[6\]\.required: must equal true/u,
  );
  await assert.rejects(stat(fixture.statusPath), /ENOENT/u);
  assert.equal(readFixtureDatabaseValue(fixture.artifactCatalogPath), "OLD_ARTIFACT_CATALOG");
  assert.equal((await readFile(fixture.pm2State.pid, "utf8")).trim(), "111");
  assert.equal((await readFile(fixture.pm2State.cwd, "utf8")).trim(), fixture.previousRelease);
});

test("production upgrade worker rejects legacy requests without a complete snapshot group before switching", async (t) => {
  const fixture = await createFixture(t, { publicMetricsStatus: 404 });
  const request = JSON.parse(await readFile(fixture.requestPath, "utf8")) as Record<string, unknown>;
  delete request.snapshotGroup;
  await writeFile(fixture.requestPath, serializeUncheckedProductionUpgradeRequest(request), { mode: 0o600 });

  await assert.rejects(
    runProductionUpgradeWorker(fixture.requestPath, fixture.dependencies),
    /missing key snapshotGroup/u,
  );
  await assert.rejects(stat(fixture.statusPath), /ENOENT/u);
  assert.equal((await readFile(fixture.pm2State.pid, "utf8")).trim(), "111");
  assert.equal((await readFile(fixture.pm2State.cwd, "utf8")).trim(), fixture.previousRelease);
  assert.equal(readFixtureDatabaseValue(fixture.oauthDatabasePath), "OLD_OAUTH_DATABASE");
  assert.equal(readFixtureDatabaseValue(fixture.authorityDatabasePath), "OLD_AUTHORITY_DATABASE");
  assert.equal(readFixtureDatabaseValue(fixture.filesystemSyncStorePath), "OLD_FILESYSTEM_SYNC_STORE");
  assert.equal(readFixtureDatabaseValue(fixture.artifactCatalogPath), "OLD_ARTIFACT_CATALOG");
});

test("production upgrade worker rejects a corrupt live database before switching", async (t) => {
  const fixture = await createFixture(t, { publicMetricsStatus: 404 });
  await writeFile(fixture.authorityDatabasePath, "TAMPERED\n", { mode: 0o600 });
  await assert.rejects(
    runProductionUpgradeWorker(fixture.requestPath, fixture.dependencies),
    /file is not a database/u,
  );
  const status = JSON.parse(await readFile(fixture.statusPath, "utf8")) as {
    state: string;
    rollback?: { attempted?: boolean };
  };
  assert.equal(status.state, "FAIL");
  assert.equal(status.rollback?.attempted, false);
  assert.equal((await readFile(fixture.pm2State.pid, "utf8")).trim(), "111");
  assert.equal(readFixtureDatabaseValue(fixture.oauthDatabasePath), "OLD_OAUTH_DATABASE");
  assert.equal(await readFile(fixture.authorityDatabasePath, "utf8"), "TAMPERED\n");
});

test("production upgrade worker fails closed before switching when request manifest identity is stale", async (t) => {
  const fixture = await createFixture(t, {
    publicMetricsStatus: 404,
    requestManifestOverride: { configSchemaIdentity: `sha256:${"9".repeat(64)}` },
  });
  await assert.rejects(
    runProductionUpgradeWorker(fixture.requestPath, fixture.dependencies),
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

test("candidate immutable identity digests are derived from packaged bytes before lifecycle dispatch", async (t) => {
  for (const field of [
    "buildCapabilityManifestDigest",
    "generatedSchemaDigest",
    "packageSha256",
  ] as const) {
    await t.test(field, async (t) => {
      const fixture = await createFixture(t, { publicMetricsStatus: 404 });
      const request = JSON.parse(await readFile(fixture.requestPath, "utf8")) as ProductionUpgradeRequest;
      const invented = digestLabel(`invented-${field}`);
      request.connectorLifecycle.candidateIdentity[field] = invented;
      request.next.manifest[field] = invented;
      request.snapshotGroup.barrier.candidateIdentityDigest = productionUpgradeCandidateIdentityDigest(
        request.connectorLifecycle.candidateIdentity,
      );
      request.connectorLifecycle.bindingDigest = productionUpgradeLifecycleBindingDigest(request);
      await writeFile(fixture.requestPath, serializeProductionUpgradeRequestV4(request), { mode: 0o600 });
      await assert.rejects(
        runProductionUpgradeWorker(fixture.requestPath, fixture.dependencies),
        new RegExp(`immutable identity mismatch for ${field}`, "u"),
      );
      assert.equal(fixture.lifecycleProbe.opens, 0);
      assert.equal((await readFile(fixture.pm2State.pid, "utf8")).trim(), "111");
    });
  }
});

test("ready and deep-doctor fixed evidence cannot be aliased or weakened", async (t) => {
  await t.test("doctor aliases ready", async (t) => {
    const fixture = await createFixture(t, { publicMetricsStatus: 404 });
    const request = JSON.parse(await readFile(fixture.requestPath, "utf8")) as ProductionUpgradeRequest;
    request.localDoctorUrl = request.previous.localReadyUrl;
    await writeFile(fixture.requestPath, serializeUncheckedProductionUpgradeRequest(request), { mode: 0o600 });
    await assert.rejects(
      runProductionUpgradeWorker(fixture.requestPath, fixture.dependencies),
      /request URLs: local health\/ready\/doctor and management identities/u,
    );
    assert.equal(fixture.lifecycleProbe.opens, 0);
  });

  await t.test("route identity uses a foreign management path", async (t) => {
    const fixture = await createFixture(t, { publicMetricsStatus: 404 });
    const request = JSON.parse(await readFile(fixture.requestPath, "utf8")) as ProductionUpgradeRequest;
    request.connectorLifecycle.postActivation.routeIdentityUrl = request.previous.localReadyUrl;
    await writeFile(fixture.requestPath, serializeUncheckedProductionUpgradeRequest(request), { mode: 0o600 });
    await assert.rejects(
      runProductionUpgradeWorker(fixture.requestPath, fixture.dependencies),
      /runtime and route identities require one loopback origin/u,
    );
    assert.equal(fixture.lifecycleProbe.opens, 0);
  });

  for (const [label, options, expected] of [
    ["missing readiness check", { omitReadinessCheck: "required_store_migrations" }, /readiness fixed check set is incomplete/u],
    ["missing store identity", { omitRequiredStoreObservation: "artifact-catalog" }, /required-store observation set is not exact|store identity is incomplete/u],
    ["doctor status ready", { doctorStatus: "ready" }, /did not report exact deep PASS/u],
    ["missing migration doctor", { omitDoctorCheck: "migration_manifest_scan" }, /deep doctor fixed check set is incomplete/u],
    ["migration digest drift", { doctorMigrationManifestDigest: digestLabel("invented-global-migration") }, /global migration manifest/u],
    ["missing artifact reconciliation", { omitDoctorCheck: "artifact_reconciliation" }, /deep doctor fixed check set is incomplete/u],
  ] as const) {
    await t.test(label, async (t) => {
      const fixture = await createFixture(t, { publicMetricsStatus: 404, ...options });
      await assert.rejects(runProductionUpgradeWorker(fixture.requestPath, fixture.dependencies), expected);
      assert.equal(fixture.lifecycleProbe.opens, 0);
      assert.equal((await readFile(fixture.pm2State.pid, "utf8")).trim(), "111");
    });
  }
});

test("production upgrade worker rejects a changed immutable runtime entrypoint before switching", async (t) => {
  const fixture = await createFixture(t, { publicMetricsStatus: 404 });
  await writeFile(fixture.nextScript, "#!/bin/sh\nexit 91\n", { mode: 0o700 });
  await assert.rejects(
    runProductionUpgradeWorker(fixture.requestPath, fixture.dependencies),
    /Immutable package payload differs from BUILD-MANIFEST\.json/u,
  );
  const status = JSON.parse(await readFile(fixture.statusPath, "utf8")) as {
    state: string;
    rollback?: { attempted?: boolean };
  };
  assert.equal(status.state, "FAIL");
  assert.equal(status.rollback?.attempted, false);
  assert.equal((await readFile(fixture.pm2State.pid, "utf8")).trim(), "111");
  assert.equal((await readFile(fixture.pm2State.cwd, "utf8")).trim(), fixture.previousRelease);
  assert.equal((await readFile(fixture.pm2State.script, "utf8")).trim(), fixture.previousScript);
});

test("production upgrade worker rejects private readiness identity drift and proves rollback", async (t) => {
  const fixture = await createFixture(t, {
    publicMetricsStatus: 404,
    timeoutMs: 1_000,
    runtimeIdentityOverride: { runtimeRevision: "f".repeat(40) },
  });
  writeFixtureDatabaseValue(fixture.oauthDatabasePath, "LATEST_OAUTH_DATABASE");
  await writeFile(fixture.expectedOauthDatabasePath, "LATEST_OAUTH_DATABASE\n", { mode: 0o600 });
  writeFixtureDatabaseValue(fixture.authorityDatabasePath, "LATEST_AUTHORITY_DATABASE");
  await writeFile(fixture.expectedAuthorityDatabasePath, "LATEST_AUTHORITY_DATABASE\n", { mode: 0o600 });
  await assert.rejects(
    runProductionUpgradeWorker(fixture.requestPath, fixture.dependencies),
    /Private readiness (?:runtime identity digest does not match|identity mismatch for runtimeRevision)/u,
  );
  const status = JSON.parse(await readFile(fixture.statusPath, "utf8")) as {
    state: string;
    failure?: { code?: string; phase?: string };
    rollback?: {
      restored?: boolean;
      verified?: boolean;
      outcome?: string;
      snapshotGroup?: { verified?: boolean; entries?: Array<{ id: string; staleSidecarsRemoved?: boolean }> };
      oauthDatabase?: { restored?: boolean; restoredSha256?: string };
      authorityDatabase?: { restored?: boolean; restoredSha256?: string };
    };
  };
  assert.equal(status.state, "ROLLED_BACK", JSON.stringify(status.rollback));
  assert.equal(status.failure?.code, "RUNTIME_IDENTITY_MISMATCH");
  assert.equal(status.failure?.phase, "VERIFYING");
  assert.equal(status.rollback?.restored, true);
  assert.equal(status.rollback?.verified, true);
  assert.equal(status.rollback?.outcome, "RESTORED_PREVIOUS_RUNTIME");
  assert.equal(status.rollback?.snapshotGroup?.verified, true);
  assert.deepEqual(status.rollback?.snapshotGroup?.entries?.map((entry) => entry.id), fixture.snapshotStoreIds);
  assert.equal(status.rollback?.snapshotGroup?.entries?.find((entry) => entry.id === "oauth-main-and-connector-state")?.staleSidecarsRemoved, true);
  assert.equal(status.rollback?.snapshotGroup?.entries?.find((entry) => entry.id === "authority-store")?.staleSidecarsRemoved, true);
  assert.equal(status.rollback?.oauthDatabase?.restored, true);
  assert.match(status.rollback?.oauthDatabase?.restoredSha256 ?? "", /^sha256:[a-f0-9]{64}$/u);
  assert.equal(status.rollback?.authorityDatabase?.restored, true);
  assert.match(status.rollback?.authorityDatabase?.restoredSha256 ?? "", /^sha256:[a-f0-9]{64}$/u);
  assert.equal(await readFile(fixture.productionEnvPath, "utf8"), "OLD_ENV=1\n");
  assert.equal(readFixtureDatabaseValue(fixture.oauthDatabasePath), "LATEST_OAUTH_DATABASE");
  assert.equal(readFixtureDatabaseValue(fixture.authorityDatabasePath), "LATEST_AUTHORITY_DATABASE");
  assert.equal(await readFile(fixture.contextStorePath, "utf8"), "{\"version\":2,\"contexts\":[]}\n");
  assert.deepEqual(await readdir(fixture.processStateDir), ["proc_old.json"]);
  assert.deepEqual(await readdir(fixture.processOutputDir), ["proc_old.log"]);
  assert.equal(readFixtureDatabaseValue(fixture.artifactCatalogPath), "OLD_ARTIFACT_CATALOG");
  assert.equal(readFixtureDatabaseValue(fixture.filesystemSyncStorePath), "OLD_FILESYSTEM_SYNC_STORE");
  await assert.rejects(stat(`${fixture.filesystemSyncStorePath}-wal`), /ENOENT/u);
  await assert.rejects(stat(`${fixture.filesystemSyncStorePath}-shm`), /ENOENT/u);
  assert.deepEqual(await readdir(fixture.artifactObjectRoot), ["aa"]);
  assert.deepEqual(await readdir(fixture.artifactQuarantineRoot), ["bb"]);
  assert.equal(await readFile(fixture.cursorCurrentPath, "utf8"), "old-current-key\n");
  await assert.rejects(stat(fixture.cursorPreviousPath), /ENOENT/u);
  assert.equal((await readFile(fixture.pm2State.cwd, "utf8")).trim(), fixture.previousRelease);
});

test("production upgrade worker rolls back env, process, start path, and audit link on public-boundary failure", async (t) => {
  const fixture = await createFixture(t, { publicMetricsStatus: 200, timeoutMs: 1_000 });
  await assert.rejects(
    runProductionUpgradeWorker(fixture.requestPath, fixture.dependencies),
    /Public metrics returned 200/u,
  );
  const status = JSON.parse(await readFile(fixture.statusPath, "utf8")) as {
    state: string;
    failure?: { code?: string };
    rollback?: {
      restored?: boolean;
      verified?: boolean;
      outcome?: string;
      healthStatus?: number;
      rollbackHostReceiptDigest?: string;
      rollbackHostReceiptPayloadDigest?: string;
    };
  };
  assert.equal(status.state, "ROLLED_BACK");
  assert.equal(status.failure?.code, "PUBLIC_BOUNDARY_FAILED");
  assert.equal(status.rollback?.restored, true);
  assert.equal(status.rollback?.verified, true);
  assert.equal(status.rollback?.outcome, "RESTORED_PREVIOUS_RUNTIME");
  assert.equal(status.rollback?.healthStatus, 200);
  assert.match(status.rollback?.rollbackHostReceiptDigest ?? "", /^sha256:[a-f0-9]{64}$/u);
  assert.match(status.rollback?.rollbackHostReceiptPayloadDigest ?? "", /^sha256:[a-f0-9]{64}$/u);
  assert.equal(await readFile(fixture.productionEnvPath, "utf8"), "OLD_ENV=1\n");
  assert.equal(readFixtureDatabaseValue(fixture.oauthDatabasePath), "OLD_OAUTH_DATABASE");
  assert.equal(readFixtureDatabaseValue(fixture.authorityDatabasePath), "OLD_AUTHORITY_DATABASE");
  assert.equal(await readFile(fixture.startScriptPath, "utf8"), "#!/bin/bash\nexec old\n");
  assert.equal(await readlink(fixture.currentAuditLink), fixture.previousAudit);
  assert.equal((await readFile(fixture.pm2State.cwd, "utf8")).trim(), fixture.previousRelease);
  assert.equal((await readFile(fixture.pm2State.script, "utf8")).trim(), fixture.previousScript);
});

test("rollback Host receipt gets its own request-bounded wait after runtime readiness", async (t) => {
  const fixture = await createFixture(t, {
    publicMetricsStatus: 200,
    timeoutMs: 600,
    previousRuntimeReadyDelayMs: 500,
    rollbackReceiptDelayMs: 800,
  });
  await assert.rejects(
    runProductionUpgradeWorker(fixture.requestPath, fixture.dependencies),
    /Public metrics returned 200/u,
  );
  const status = JSON.parse(await readFile(fixture.statusPath, "utf8")) as {
    state: string;
    rollback?: { verified?: boolean; rollbackHostReceiptDigest?: string };
  };
  assert.equal(status.state, "ROLLED_BACK");
  assert.equal(status.rollback?.verified, true);
  assert.match(status.rollback?.rollbackHostReceiptDigest ?? "", /^sha256:[a-f0-9]{64}$/u);
});

test("rollback Host receipt cannot substitute stale or semantically different readbacks", async (t) => {
  for (const [mode, expected] of [
    ["HEALTH_DRIFT", /trusted runtime, health, and ready readback bindings/u],
    ["STALE_OBSERVED", /strictly after durable rollback request/u],
  ] as const) {
    await t.test(mode, async (t) => {
      const fixture = await createFixture(t, {
        publicMetricsStatus: 200,
        timeoutMs: 1_000,
        rollbackReceiptMode: mode,
      });
      await assert.rejects(
        runProductionUpgradeWorker(fixture.requestPath, fixture.dependencies),
        /Public metrics returned 200/u,
      );
      const status = JSON.parse(await readFile(fixture.statusPath, "utf8")) as {
        state?: string;
        rollback?: { verified?: boolean; error?: string };
      };
      assert.equal(status.state, "ROLLBACK_UNKNOWN");
      assert.equal(status.rollback?.verified, false);
      assert.match(status.rollback?.error ?? "", expected);
      assert.equal((await readFile(fixture.pm2State.pid, "utf8")).trim(), "0");
      const events = (await readFile(fixture.rollbackJournalPath, "utf8"))
        .trim()
        .split("\n")
        .map((line) => (JSON.parse(line) as { event: string }).event);
      assert.deepEqual(events, [
        "ROLLBACK_REQUESTED",
        "ROLLBACK_RESTORE_VERIFIED",
        "ROLLBACK_RUNTIME_UNKNOWN",
      ]);
    });
  }
});

test("production upgrade worker records UNKNOWN when rollback cannot establish the previous runtime", async (t) => {
  const fixture = await createFixture(t, {
    publicMetricsStatus: 200,
    timeoutMs: 250,
    rollbackFails: true,
  });
  await assert.rejects(
    runProductionUpgradeWorker(fixture.requestPath, fixture.dependencies),
    /Public metrics returned 200/u,
  );
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
  assert.equal(status.state, "ROLLBACK_UNKNOWN");
  assert.equal(status.history?.at(-1)?.state, "ROLLBACK_UNKNOWN");
  assert.equal(status.failure?.code, "PUBLIC_BOUNDARY_FAILED");
  assert.equal(status.rollback?.restored, true);
  assert.equal(status.rollback?.verified, false);
  assert.equal(status.rollback?.outcome, "RESTORATION_UNVERIFIED");
  assert.equal(status.rollback?.failure?.code, "ROLLBACK_FAILED");
  assert.equal(typeof status.rollback?.error, "string");
  assert.equal(readFixtureDatabaseValue(fixture.oauthDatabasePath), "OLD_OAUTH_DATABASE");
  assert.equal(readFixtureDatabaseValue(fixture.authorityDatabasePath), "OLD_AUTHORITY_DATABASE");
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
  lifecycleFailure?: "PREPARE" | "ACTIVATE_AFTER_DISPATCH" | "WAIT_POST" | "VERIFY_POST";
  rollbackJournalFailure?: "BEFORE_REQUEST" | "BEFORE_RESTORE_RECORD";
  corruptSnapshotBeforeRollback?: boolean;
  requestManifestOverride?: Partial<ProductionUpgradeRequest["next"]["manifest"]>;
  runtimeIdentityOverride?: Partial<FixtureRuntimeIdentity>;
  snapshotEntriesOverride?: (entries: SnapshotGroupEntry[]) => SnapshotGroupEntry[];
  omitReadinessCheck?: string;
  omitRequiredStoreObservation?: string;
  omitDoctorCheck?: string;
  doctorMigrationManifestDigest?: string;
  doctorStatus?: "PASS" | "ready";
  rollbackReceiptMode?: "VALID" | "HEALTH_DRIFT" | "STALE_OBSERVED";
  previousRuntimeUnavailableWhenStopped?: boolean;
  previousRuntimeReadyDelayMs?: number;
  rollbackReceiptDelayMs?: number;
}

interface FixtureLifecycleProbe {
  opens: number;
  prepares: number;
  activations: number;
  providerDispatches: number;
  waits: number;
  postVerifications: number;
  closes: number;
}

type SnapshotGroupEntry = NonNullable<ProductionUpgradeRequest["snapshotGroup"]>["entries"][number];

async function createFixture(t: TestContext, options: FixtureOptions) {
  const root = await mkdtemp(join(realpathSync(tmpdir()), "devspace-production-upgrade-worker-test-"));
  const transactionId = "upgrade_11111111-1111-4111-8111-111111111111";
  t.after(() => rm(root, { recursive: true, force: true }));
  const auditDirectory = join(root, "audit-next");
  const previousAudit = join(root, "audit-previous");
  const previousRelease = join(root, "release-previous");
  const nextSourceEvidenceRoot = join(root, "source-evidence-next");
  const nextRelease = join(root, "immutable-runtime-next");
  const runtimeDependencyRoot = join(root, "runtime-dependencies-next");
  const runtimeDependencyEvidencePath = join(runtimeDependencyRoot, "RUNTIME-DEPENDENCIES.json");
  const requestPath = join(auditDirectory, "request.json");
  const statusPath = join(auditDirectory, "status.json");
  await Promise.all([
    mkdir(auditDirectory, { recursive: true, mode: 0o700 }),
    mkdir(previousAudit, { recursive: true }),
    mkdir(previousRelease, { recursive: true }),
    mkdir(nextSourceEvidenceRoot, { recursive: true }),
    mkdir(nextRelease, { recursive: true }),
    mkdir(runtimeDependencyRoot, { recursive: true }),
  ]);
  const previousScript = join(previousRelease, "start.sh");
  const nextScript = join(nextRelease, "scripts", "start-universal-broker-v2-production.sh");
  await writeFile(previousScript, "#!/bin/sh\n", { mode: 0o700 });
  await mkdir(dirname(nextScript), { recursive: true });
  await writeFile(nextScript, "#!/bin/sh\n", { mode: 0o700 });
  for (const runtimeRoot of [nextSourceEvidenceRoot, nextRelease]) {
    await mkdir(join(runtimeRoot, "dist"), { recursive: true });
    await writeFile(join(runtimeRoot, "dist", "runtime.js"), "export const runtime = true;\n");
    await writeFile(join(runtimeRoot, "dist", "cli.js"), "export const cli = true;\n");
  }
  await mkdir(join(nextRelease, "scripts", "lib"), { recursive: true });
  await writeFile(join(nextRelease, "scripts", "lib", "runtime-dependency-loader.mjs"), "export {};\n");
  await writeFile(join(nextRelease, "package.json"), '{"name":"fixture-runtime"}\n');
  await writeFile(join(nextRelease, "package-lock.json"), '{"name":"fixture-runtime","lockfileVersion":3}\n');
  await mkdir(join(nextRelease, "config"), { recursive: true });
  await mkdir(join(nextRelease, "contracts"), { recursive: true });
  await writeFile(join(nextRelease, "config.schema.json"), '{"fixture":"generated-config"}\n');
  await writeFile(join(nextRelease, "config", "config.schema.json"), '{"fixture":"generated-config"}\n');
  await writeFile(join(nextRelease, "contracts", "tools-v2.schema.json"), '{"fixture":"tools"}\n');
  await writeFile(
    join(nextRelease, "contracts", "build-capabilities.schema.json"),
    '{"fixture":"build-capabilities"}\n',
  );
  await writeFile(join(runtimeDependencyRoot, "package.json"), '{"name":"fixture-runtime"}\n');
  await writeFile(join(runtimeDependencyRoot, "package-lock.json"), '{"name":"fixture-runtime","lockfileVersion":3}\n');
  const packageJsonSha256 = `sha256:${createHash("sha256").update(await readFile(join(nextRelease, "package.json"))).digest("hex")}`;
  const lockfileSha256 = `sha256:${createHash("sha256").update(await readFile(join(nextRelease, "package-lock.json"))).digest("hex")}`;
  const nextDist = await directoryEvidence(join(nextSourceEvidenceRoot, "dist"));
  const nextCommit = "a".repeat(40);
  const nextSourceTree = "b".repeat(40);
  const manifestIdentity = {
    sourceRevision: nextCommit,
    runtimeRevision: "c".repeat(40),
    buildDigest: await releaseTreeDigest(nextRelease, ["dist/cli.js", "dist/runtime.js"]),
    schemaGeneration: `sha256:${"d".repeat(64)}` as `sha256:${string}`,
    authorityContractGeneration: `sha256:${"e".repeat(64)}` as `sha256:${string}`,
    configSchemaIdentity: `sha256:${"f".repeat(64)}` as `sha256:${string}`,
  };
  const supportedOperations = Object.fromEntries([
    "target", "context", "fs", "exec", "process", "mcp", "artifact", "gui",
  ].map((tool) => [tool, ["fixture_operation"]]));
  const buildCapabilityContract = {
    productVersion: "2.1.0",
    productProfile: "BASE_SINGLE_OWNER",
    schemaGeneration: manifestIdentity.schemaGeneration,
    authorityContractGeneration: manifestIdentity.authorityContractGeneration,
    supportedProfiles: ["BASE_SINGLE_OWNER"],
    supportedOperations,
    resourceUriVersion: "v1",
  };
  const buildCapabilities = {
    ...buildCapabilityContract,
    buildDigest: manifestIdentity.buildDigest,
    capabilityDigest: digestJson(buildCapabilityContract),
  };
  const migrationManifest: MigrationManifestEntry[] = [
    fixtureMigration("main", 1),
    fixtureMigration("authority", 7),
    fixtureMigration("artifact-catalog", 1),
    fixtureMigration("filesystem-sync", 1),
    fixtureMigration("connector-activation-journal", 1),
  ];
  const globalMigrationManifestDigest = migrationManifestDigest(migrationManifest) as `sha256:${string}`;
  const runtimeFiles = ["dist/cli.js", "dist/runtime.js"];
  const payloadFiles = [
    ...runtimeFiles,
    "config/config.schema.json",
    "contracts/build-capabilities.schema.json",
    "contracts/tools-v2.schema.json",
    "package.json",
    "package-lock.json",
    "scripts/lib/runtime-dependency-loader.mjs",
    "scripts/start-universal-broker-v2-production.sh",
  ];
  const payloadDigest = await releaseTreeDigest(nextRelease, payloadFiles);
  const manifestPath = join(nextRelease, "BUILD-MANIFEST.json");
  await writeFile(manifestPath, `${JSON.stringify({
    manifestVersion: 2,
    ...manifestIdentity,
    payloadDigest,
    files: payloadFiles.length,
    payloadFiles,
    runtimeFiles,
    runtime: {
      cwd: ".",
      entrypoint: "scripts/start-universal-broker-v2-production.sh",
      nodeEntrypoint: "dist/cli.js",
      dependencies: {
        mode: "external-node-modules-loader-v1",
        loader: "scripts/lib/runtime-dependency-loader.mjs",
        lockfile: "package-lock.json",
        lockfileSha256,
        packageJsonSha256,
        evidenceName: "RUNTIME-DEPENDENCIES.json",
      },
    },
    createdAt: "2026-08-19T00:00:00.000Z",
    nodeVersion: "v22.23.0",
    platform: "darwin-arm64",
    forbiddenArtifactScan: "PASS",
    buildCapabilities,
    migrationManifest,
    migrationManifestDigest: globalMigrationManifestDigest,
  }, null, 2)}\n`, { mode: 0o444 });
  const manifestSha256 = `sha256:${createHash("sha256").update(await readFile(manifestPath)).digest("hex")}` as `sha256:${string}`;
  const runtimeDependencyEvidence = `${JSON.stringify({
    manifestVersion: 1,
    installMode: "npm-ci-lockfile-v1",
    packageManifestSha256: manifestSha256,
    packageJsonSha256,
    lockfileSha256,
    nodeVersion: "v22.23.0",
    platform: "darwin-arm64",
    nodeModules: {
      files: 0,
      directories: 0,
      symlinks: 0,
      sha256: `sha256:${createHash("sha256").digest("hex")}`,
    },
    createdAt: "2026-08-19T00:00:00.000Z",
  }, null, 2)}\n`;
  await writeFile(runtimeDependencyEvidencePath, runtimeDependencyEvidence, { mode: 0o600 });
  const runtimeDependencyEvidenceSha256 = `sha256:${createHash("sha256").update(runtimeDependencyEvidence).digest("hex")}` as `sha256:${string}`;
  const expectedRuntimeIdentity: FixtureRuntimeIdentity = {
    productVersion: "2.1.0",
    schemaGeneration: manifestIdentity.schemaGeneration,
    authorityContractGeneration: manifestIdentity.authorityContractGeneration,
    configDigest: `sha256:${"7".repeat(64)}`,
    sourceRevision: manifestIdentity.sourceRevision,
    runtimeRevision: manifestIdentity.runtimeRevision,
    buildDigest: manifestIdentity.buildDigest,
    startedAt: "2026-08-19T00:00:01.000Z",
  };
  const runtimeIdentity: FixtureRuntimeIdentity = {
    ...expectedRuntimeIdentity,
    ...options.runtimeIdentityOverride,
  };
  const previousRuntimeIdentity = {
    productVersion: "2.0.9",
    schemaGeneration: `sha256:${"1".repeat(64)}`,
    authorityContractGeneration: `sha256:${"2".repeat(64)}`,
    configDigest: `sha256:${"3".repeat(64)}`,
    sourceRevision: "8".repeat(40),
    runtimeRevision: "9".repeat(40),
    buildDigest: `sha256:${"4".repeat(64)}`,
    startedAt: "2026-08-18T00:00:01.000Z",
  };
  const previousRuntimeIdentityDigest = digestJson(previousRuntimeIdentity);
  let previousRuntimeReadyObservedAtMs: number | undefined;
  const managementServer = createServer((request, response) => {
    if (request.url === "/readyz") {
      const activePid = readFixturePid(pm2State.pid);
      if (activePid === 333 && options.previousRuntimeReadyDelayMs) {
        previousRuntimeReadyObservedAtMs ??= Date.now();
        if (Date.now() - previousRuntimeReadyObservedAtMs < options.previousRuntimeReadyDelayMs) {
          response.statusCode = 503;
          response.end(JSON.stringify({ status: "starting" }));
          return;
        }
      }
      const activeIdentity = activePid === 222
        ? runtimeIdentity
        : previousRuntimeIdentity;
      response.setHeader("content-type", "application/json");
      response.end(JSON.stringify(fixtureReadinessReport({
        identity: activeIdentity,
        buildCapabilityDigest: buildCapabilities.capabilityDigest,
        oauthDatabasePath,
        authorityDatabasePath,
        artifactCatalogPath,
        filesystemSyncStorePath,
        connectorJournalPath,
        cursorCurrentPath,
        managementKeyPath,
        omitCheck: options.omitReadinessCheck,
        omitStoreObservation: options.omitRequiredStoreObservation,
      })));
      return;
    }
    if (request.url === "/doctorz" && request.method === "POST") {
      const activeIdentity = readFixturePid(pm2State.pid) === 222
        ? runtimeIdentity
        : previousRuntimeIdentity;
      response.setHeader("content-type", "application/json");
      response.end(JSON.stringify(fixtureDoctorReport({
        identity: activeIdentity,
        migrationManifestDigest: options.doctorMigrationManifestDigest
          ?? globalMigrationManifestDigest,
        status: options.doctorStatus ?? "PASS",
        omitCheck: options.omitDoctorCheck,
      })));
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
  const oauthDatabasePath = join(root, "devspace.sqlite");
  const oauthDatabaseBackupPath = join(auditDirectory, "oauth-cutover-before.sqlite");
  const authorityDatabasePath = join(root, "authority.sqlite");
  const authorityDatabaseBackupPath = join(auditDirectory, "authority-cutover-before.sqlite");
  const expectedOauthDatabasePath = join(root, "expected-oauth.sqlite");
  const expectedAuthorityDatabasePath = join(root, "expected-authority.sqlite");
  const contextStorePath = join(root, "contexts.json");
  const processStateDir = join(root, "processes");
  const processOutputDir = join(root, "process-output");
  const filesystemSyncStorePath = join(root, "filesystem-sync", "sync.sqlite");
  const artifactCatalogPath = join(root, "artifacts.sqlite");
  const artifactObjectRoot = join(root, "artifact-objects");
  const artifactQuarantineRoot = join(root, "artifact-quarantine");
  const cursorCurrentPath = join(root, "cursor-current.key");
  const cursorPreviousPath = join(root, "cursor-previous.key");
  const lifecycleFinalizationStorePath = join(root, "lifecycle.sqlite");
  const publicRoutePath = join(root, "public-route.json");
  const targetRouteConfigPath = join(root, "target-route-generation.json");
  const controlDirectory = join(root, "control-plane");
  const connectorJournalPath = join(controlDirectory, "connector-activation.sqlite");
  const rollbackJournalPath = join(controlDirectory, "rollback.jsonl");
  const postReceiptDirectory = join(controlDirectory, "post-receipts");
  const snapshotGroupRoot = join(auditDirectory, "store-snapshot-preimage");
  const nextEnvPath = join(auditDirectory, "production.env.next");
  const startScriptPath = join(root, "canonical-start.sh");
  const startScriptBackupPath = join(auditDirectory, "canonical-start.before");
  await writeFile(productionEnvPath, "OLD_ENV=1\n", { mode: 0o600 });
  await writeFile(productionEnvBackupPath, "OLD_ENV=1\n", { mode: 0o600 });
  createFixtureDatabase(oauthDatabasePath, "OLD_OAUTH_DATABASE");
  createFixtureDatabase(authorityDatabasePath, "OLD_AUTHORITY_DATABASE");
  setFixtureUserVersion(authorityDatabasePath, 7);
  await mkdir(dirname(filesystemSyncStorePath), { recursive: true });
  createFixtureDatabase(filesystemSyncStorePath, "OLD_FILESYSTEM_SYNC_STORE");
  createFixtureDatabase(artifactCatalogPath, "OLD_ARTIFACT_CATALOG");
  setFixtureUserVersion(filesystemSyncStorePath, 1);
  setFixtureUserVersion(artifactCatalogPath, 1);
  createFixtureDatabase(lifecycleFinalizationStorePath, "OLD_LIFECYCLE_FINALIZATION_STORE");
  await writeFile(expectedOauthDatabasePath, "OLD_OAUTH_DATABASE\n", { mode: 0o600 });
  await writeFile(expectedAuthorityDatabasePath, "OLD_AUTHORITY_DATABASE\n", { mode: 0o600 });
  await writeFile(contextStorePath, "{\"version\":2,\"contexts\":[]}\n", { mode: 0o600 });
  await mkdir(processStateDir, { recursive: true });
  await mkdir(processOutputDir, { recursive: true });
  await mkdir(artifactObjectRoot, { recursive: true });
  await mkdir(artifactQuarantineRoot, { recursive: true });
  await writeFile(join(processStateDir, "proc_old.json"), "{\"state\":\"OLD\"}\n", { mode: 0o600 });
  await writeFile(join(processOutputDir, "proc_old.log"), "old output\n", { mode: 0o600 });
  await writeFile(join(artifactObjectRoot, "aa"), "old object\n", { mode: 0o600 });
  await writeFile(join(artifactQuarantineRoot, "bb"), "old quarantine\n", { mode: 0o600 });
  await writeFile(cursorCurrentPath, "old-current-key\n", { mode: 0o600 });
  await writeFile(publicRoutePath, "{\"route\":\"OLD\"}\n", { mode: 0o600 });
  await writeFile(targetRouteConfigPath, "{\"generation\":\"OLD\"}\n", { mode: 0o600 });
  await mkdir(postReceiptDirectory, { recursive: true, mode: 0o700 });
  await mkdir(controlDirectory, { recursive: true, mode: 0o700 });
  createFixtureDatabase(connectorJournalPath, "JOURNAL_INITIAL");
  setFixtureUserVersion(connectorJournalPath, 1);
  await chmod(connectorJournalPath, 0o600);
  const nextEnvContent = [
    "NEXT_ENV=1",
    "DEVSPACE_NEXT_MANAGEMENT_HOST=127.0.0.1",
    `DEVSPACE_NEXT_MANAGEMENT_PORT=${managementPort}`,
    `DEVSPACE_RELEASE_MANIFEST=${manifestPath}`,
    `DEVSPACE_EXPECTED_RELEASE_MANIFEST_SHA256=${manifestSha256}`,
    `DEVSPACE_EXPECTED_SOURCE_REVISION=${manifestIdentity.sourceRevision}`,
    `DEVSPACE_EXPECTED_RUNTIME_REVISION=${manifestIdentity.runtimeRevision}`,
    `DEVSPACE_EXPECTED_BUILD_DIGEST=${manifestIdentity.buildDigest}`,
    `DEVSPACE_EXPECTED_SCHEMA_GENERATION=${manifestIdentity.schemaGeneration}`,
    `DEVSPACE_EXPECTED_AUTHORITY_CONTRACT_GENERATION=${manifestIdentity.authorityContractGeneration}`,
    `DEVSPACE_EXPECTED_CONFIG_SCHEMA_IDENTITY=${manifestIdentity.configSchemaIdentity}`,
    `DEVSPACE_SOURCE_REVISION=${manifestIdentity.sourceRevision}`,
    `DEVSPACE_RUNTIME_REVISION=${manifestIdentity.runtimeRevision}`,
    `DEVSPACE_BUILD_DIGEST=${manifestIdentity.buildDigest}`,
    `DEVSPACE_RUNTIME_PACKAGE_ROOT=${nextRelease}`,
    `DEVSPACE_RUNTIME_DEPENDENCY_ROOT=${runtimeDependencyRoot}`,
    `DEVSPACE_RUNTIME_DEPENDENCY_EVIDENCE=${runtimeDependencyEvidencePath}`,
    `DEVSPACE_EXPECTED_RUNTIME_DEPENDENCY_EVIDENCE_SHA256=${runtimeDependencyEvidenceSha256}`,
    "",
  ].join("\n");
  await writeFile(nextEnvPath, nextEnvContent, { mode: 0o600 });
  await writeFile(startScriptPath, "#!/bin/bash\nexec old\n", { mode: 0o700 });
  await writeFile(startScriptBackupPath, "#!/bin/bash\nexec old\n", { mode: 0o700 });
  const currentAuditLink = join(root, "current-audit");
  await symlink(previousAudit, currentAuditLink);

  const rollbackHostChallengePath = join(controlDirectory, "rollback-host-challenge.json");
  const rollbackHostReceiptPath = join(controlDirectory, "rollback-host-receipt.json");
  const rollbackHostReceiptProducerPath = join(controlDirectory, "produce-rollback-host-receipt.mjs");
  const managementKeyPath = join(controlDirectory, "management.key");
  const managementSecret = Buffer.alloc(32, 7);
  const managementKey = {
    keyId: `management-${createHash("sha256").update(managementSecret).digest("hex").slice(0, 24)}`,
    secret: Uint8Array.from(managementSecret),
    path: managementKeyPath,
  };
  await writeFile(managementKeyPath, `${managementSecret.toString("base64url")}\n`, { mode: 0o600 });
  const rollbackChallengeNow = Date.now();
  const rollbackHostChallenge = signConnectorRollbackHostChallenge({
    challengeId: "fixture-rollback-challenge",
    transactionId,
    nonce: Buffer.alloc(32, 11).toString("base64url"),
    managementCorrelationId: "fixture-rollback-correlation",
    hostProvider: "chatgpt",
    actualHostRequired: true,
    previousRuntimeIdentityDigest,
    previousMainMigrationIdentityDigest: globalMigrationManifestDigest,
    issuedAtMs: rollbackChallengeNow,
    expiresAtMs: rollbackChallengeNow + 10 * 60_000,
    receiptPath: rollbackHostReceiptPath,
  }, managementKey, rollbackChallengeNow);
  const rollbackHostChallengeContent = `${JSON.stringify(rollbackHostChallenge, null, 2)}\n`;
  await writeFile(rollbackHostChallengePath, rollbackHostChallengeContent, { mode: 0o600 });
  const rollbackHostChallengeSha256 = digestBytes(rollbackHostChallengeContent);
  const rollbackEvidenceModule = join(
    dirname(dirname(dirname(fileURLToPath(import.meta.url)))),
    "scripts",
    "lib",
    "connector-rollback-evidence.mjs",
  );
  await writeFile(rollbackHostReceiptProducerPath, [
    'import { createHash } from "node:crypto";',
    'import { chmod, readFile, rename, writeFile } from "node:fs/promises";',
    `import { connectorRollbackHealthReadbackDigest, connectorRollbackReadyReadbackDigest, connectorRollbackRuntimeReadbackDigest, signConnectorRollbackHostReceipt } from ${JSON.stringify(rollbackEvidenceModule)};`,
    'const [challengePath,receiptPath,keyPath,processName,cwd,script,runtimeIdentityDigest,migrationIdentityDigest] = process.argv.slice(2);',
    `await new Promise((resolve) => setTimeout(resolve, ${options.rollbackReceiptDelayMs ?? 50}));`,
    'const challengeEnvelope = JSON.parse(await readFile(challengePath, "utf8"));',
    'const secret = Buffer.from((await readFile(keyPath, "utf8")).trim(), "base64url");',
    'const key = { keyId: `management-${createHash("sha256").update(secret).digest("hex").slice(0, 24)}`, secret: Uint8Array.from(secret), path: keyPath };',
    'const challenge = challengeEnvelope.payload;',
    `const receiptMode = ${JSON.stringify(options.rollbackReceiptMode ?? "VALID")};`,
    'const common = { challengeId: challenge.challengeId, transactionId: challenge.transactionId, nonce: challenge.nonce, managementCorrelationId: challenge.managementCorrelationId };',
    'const healthReadbackDigest = connectorRollbackHealthReadbackDigest({ ...common, httpStatus: receiptMode === "HEALTH_DRIFT" ? 204 : 200 });',
    'const readyReadbackDigest = connectorRollbackReadyReadbackDigest({ ...common, httpStatus: 200, runtimeIdentityDigest });',
    'const runtimeReadbackDigest = connectorRollbackRuntimeReadbackDigest({ ...common, processName, processStatus: "online", cwd, script, runtimeIdentityDigest, mainMigrationIdentityDigest: migrationIdentityDigest });',
    'const expected = { transactionId: challenge.transactionId, previousRuntimeIdentityDigest: runtimeIdentityDigest, previousMainMigrationIdentityDigest: migrationIdentityDigest, receiptPath, healthReadbackDigest, readyReadbackDigest, runtimeReadbackDigest };',
    'const observedAtMs = receiptMode === "STALE_OBSERVED" ? challenge.issuedAtMs : Date.now();',
    'const digest = (label) => `sha256:${createHash("sha256").update(label).digest("hex")}`;',
    'const envelope = signConnectorRollbackHostReceipt({ challengeId: challenge.challengeId, challengePayloadDigest: challengeEnvelope.payloadDigest, transactionId: challenge.transactionId, nonce: challenge.nonce, managementCorrelationId: challenge.managementCorrelationId, hostProvider: "chatgpt", actualHost: true, previousRuntimeIdentityDigest: runtimeIdentityDigest, previousMainMigrationIdentityDigest: migrationIdentityDigest, runtimeReadbackDigest, healthReadbackDigest, readyReadbackDigest, sessionAIdDigest: digest("fixture-rollback-session-a"), sessionBIdDigest: digest("fixture-rollback-session-b"), observedAtMs, expiresAtMs: Math.min(observedAtMs + 60_000, challenge.expiresAtMs) }, key, challengeEnvelope, expected, observedAtMs);',
    'const temporary = `${receiptPath}.${process.pid}.tmp`;',
    'await writeFile(temporary, `${JSON.stringify(envelope, null, 2)}\\n`, { mode: 0o600, flag: "wx" });',
    'await chmod(temporary, 0o600);',
    'await rename(temporary, receiptPath);',
    '',
  ].join("\n"), { mode: 0o600 });

  const stagingActivationPrecheckPath = join(controlDirectory, "staging-precheck.json");
  const preCutoverHostCanaryPath = join(controlDirectory, "pre-cutover.json");
  const postChallengePath = join(controlDirectory, "post-challenge.json");
  const postReceiptPath = join(postReceiptDirectory, "post-receipt.json");
  const evidenceFiles = [
    [stagingActivationPrecheckPath, "staging activation precheck"],
    [preCutoverHostCanaryPath, "pre cutover Host canary"],
    [postChallengePath, "post activation challenge"],
  ] as const;
  for (const [path, kind] of evidenceFiles) {
    await writeFile(path, `${JSON.stringify({ schemaVersion: 1, kind })}\n`, { mode: 0o600 });
  }
  const releaseDriverPaths = {
    stagingPrecheckRequest: join(controlDirectory, "driver-staging-precheck-request.json"),
    stagingActivationRequest: join(controlDirectory, "driver-staging-activation-request.json"),
    stagingActivationReadback: join(controlDirectory, "driver-staging-activation-readback.json"),
    preCutoverRequest: join(controlDirectory, "driver-pre-cutover-request.json"),
    productionPredecisionRequest: join(controlDirectory, "driver-production-predecision-request.json"),
    productionPredecisionEnvelope: join(controlDirectory, "driver-production-predecision-envelope.json"),
    productionPreparationRequest: join(controlDirectory, "driver-production-preparation-request.json"),
  } as const;
  const releaseDriverArtifacts = Object.fromEntries(await Promise.all(Object.entries(releaseDriverPaths).map(
    async ([key, path]) => {
      const content = `${JSON.stringify({ schemaVersion: 1, kind: key })}\n`;
      await writeFile(path, content, { mode: 0o600 });
      return [key, { path, sha256: digestBytes(content) }];
    },
  ))) as unknown as Omit<
    ProductionUpgradeRequest["connectorLifecycle"]["releaseDriver"],
    "productionApprovalOutputDirectory"
  >;
  const rollbackChallengeRequestPath = join(controlDirectory, "driver-rollback-challenge-request.json");
  const rollbackChallengeRequestContent = `${JSON.stringify({ schemaVersion: 1, kind: "rollbackChallengeRequest" })}\n`;
  await writeFile(rollbackChallengeRequestPath, rollbackChallengeRequestContent, { mode: 0o600 });
  const rollbackChallengeRequest = {
    path: rollbackChallengeRequestPath,
    sha256: digestBytes(rollbackChallengeRequestContent),
  };
  const productionApprovalOutputDirectory = join(controlDirectory, "production-approval-output");
  const releaseDriver: ProductionUpgradeRequest["connectorLifecycle"]["releaseDriver"] = {
    ...releaseDriverArtifacts,
    productionApprovalOutputDirectory,
  };

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
    `oauth_database=${shellQuote(oauthDatabasePath)}`,
    `authority_database=${shellQuote(authorityDatabasePath)}`,
    `expected_oauth_database=${shellQuote(expectedOauthDatabasePath)}`,
    `expected_authority_database=${shellQuote(expectedAuthorityDatabasePath)}`,
    `context_store=${shellQuote(contextStorePath)}`,
    `process_state_dir=${shellQuote(processStateDir)}`,
    `process_output_dir=${shellQuote(processOutputDir)}`,
    `filesystem_sync_store=${shellQuote(filesystemSyncStorePath)}`,
    `artifact_catalog=${shellQuote(artifactCatalogPath)}`,
    `artifact_object_root=${shellQuote(artifactObjectRoot)}`,
    `artifact_quarantine_root=${shellQuote(artifactQuarantineRoot)}`,
    `cursor_current=${shellQuote(cursorCurrentPath)}`,
    `cursor_previous=${shellQuote(cursorPreviousPath)}`,
    `lifecycle_store=${shellQuote(lifecycleFinalizationStorePath)}`,
    `public_route=${shellQuote(publicRoutePath)}`,
    `target_route_config=${shellQuote(targetRouteConfigPath)}`,
    `rollback_journal=${shellQuote(rollbackJournalPath)}`,
    `rollback_challenge=${shellQuote(rollbackHostChallengePath)}`,
    `rollback_receipt=${shellQuote(rollbackHostReceiptPath)}`,
    `rollback_receipt_producer=${shellQuote(rollbackHostReceiptProducerPath)}`,
    `rollback_receipt_node=${shellQuote(process.execPath)}`,
    `management_key=${shellQuote(managementKeyPath)}`,
    `production_process_name=${shellQuote("devspace-v2-production")}`,
    `previous_runtime_identity=${shellQuote(previousRuntimeIdentityDigest)}`,
    `previous_migration_identity=${shellQuote(globalMigrationManifestDigest)}`,
    "case \"$1\" in",
    "  jlist)",
    "    pid=$(cat \"$pid_file\")",
    "    if [ \"$pid\" = 0 ]; then printf '[]\\n'; exit 0; fi",
    "    cwd=$(cat \"$cwd_file\")",
    "    script=$(cat \"$script_file\")",
    "    printf '[{\"name\":\"devspace-v2-production\",\"pid\":%s,\"pm2_env\":{\"status\":\"online\",\"pm_cwd\":\"%s\",\"pm_exec_path\":\"%s\"}}]\\n' \"$pid\" \"$cwd\" \"$script\"",
    "    ;;",
    "  delete)",
    "    current_pid=$(cat \"$pid_file\")",
    options.rollbackJournalFailure === "BEFORE_RESTORE_RECORD"
      ? "    if [ \"$current_pid\" = 222 ]; then chmod 400 \"$rollback_journal\"; fi"
      : "    :",
    "    printf '0\\n' > \"$pid_file\"",
    "    ;;",
    "  start)",
    "    script=$2",
    "    shift 2",
    "    cwd=",
    "    while [ $# -gt 0 ]; do",
    "      if [ \"$1\" = \"--cwd\" ]; then cwd=$2; shift 2; else shift; fi",
    "    done",
    `    if [ "$script" = ${shellQuote(nextScript)} ]; then`,
    "      sqlite3 \"$oauth_database\" \"update sentinel set value='CANDIDATE_OAUTH_DATABASE';\"",
    "      sqlite3 \"$authority_database\" \"update sentinel set value='CANDIDATE_AUTHORITY_DATABASE';\"",
    "      printf 'stale\\n' > \"${oauth_database}-wal\"",
    "      printf 'stale\\n' > \"${oauth_database}-shm\"",
      "      printf 'stale\\n' > \"${authority_database}-wal\"",
      "      printf 'stale\\n' > \"${authority_database}-shm\"",
      "      sqlite3 \"$artifact_catalog\" \"update sentinel set value='CANDIDATE_ARTIFACT_CATALOG';\"",
      "      printf 'stale\\n' > \"${artifact_catalog}-wal\"",
      "      sqlite3 \"$filesystem_sync_store\" \"update sentinel set value='CANDIDATE_FILESYSTEM_SYNC_STORE';\"",
      "      printf 'stale\\n' > \"${filesystem_sync_store}-wal\"",
      "      printf 'stale\\n' > \"${filesystem_sync_store}-shm\"",
      "      printf '{\"version\":2,\"contexts\":[{\"candidate\":true}]}\\n' > \"$context_store\"",
      "      rm -rf \"$process_state_dir\" \"$process_output_dir\" \"$artifact_object_root\" \"$artifact_quarantine_root\"",
      "      mkdir -p \"$process_state_dir\" \"$process_output_dir\" \"$artifact_object_root\" \"$artifact_quarantine_root\"",
      "      printf '{\"state\":\"NEW\"}\\n' > \"$process_state_dir/proc_new.json\"",
      "      printf 'new output\\n' > \"$process_output_dir/proc_new.log\"",
      "      printf 'new object\\n' > \"$artifact_object_root/cc\"",
      "      printf 'new quarantine\\n' > \"$artifact_quarantine_root/dd\"",
      "      printf 'new-current-key\\n' > \"$cursor_current\"",
      "      printf 'new-previous-key\\n' > \"$cursor_previous\"",
      "      sqlite3 \"$lifecycle_store\" \"update sentinel set value='CANDIDATE_LIFECYCLE_FINALIZATION_STORE';\"",
      "      printf '{\"route\":\"NEW\"}\\n' > \"$public_route\"",
      "      printf '{\"generation\":\"NEW\"}\\n' > \"$target_route_config\"",
      "      printf '222\\n' > \"$pid_file\"",
    "    else",
      "      [ \"$(sqlite3 \"$oauth_database\" 'select value from sentinel;')\" = \"$(cat \"$expected_oauth_database\")\" ] || exit 71",
      "      [ \"$(sqlite3 \"$authority_database\" 'select value from sentinel;')\" = \"$(cat \"$expected_authority_database\")\" ] || exit 72",
      "      [ \"$(sqlite3 \"$artifact_catalog\" 'select value from sentinel;')\" = OLD_ARTIFACT_CATALOG ] || exit 73",
      "      [ \"$(sqlite3 \"$filesystem_sync_store\" 'select value from sentinel;')\" = OLD_FILESYSTEM_SYNC_STORE ] || exit 74",
      "      [ ! -e \"${filesystem_sync_store}-wal\" ] && [ ! -e \"${filesystem_sync_store}-shm\" ] || exit 75",
      "      [ \"$(cat \"$context_store\")\" = '{\"version\":2,\"contexts\":[]}' ] || exit 76",
      "      [ -f \"$process_state_dir/proc_old.json\" ] && [ ! -e \"$process_state_dir/proc_new.json\" ] || exit 77",
      "      [ -f \"$process_output_dir/proc_old.log\" ] && [ ! -e \"$process_output_dir/proc_new.log\" ] || exit 78",
      "      [ -f \"$artifact_object_root/aa\" ] && [ ! -e \"$artifact_object_root/cc\" ] || exit 79",
      "      [ -f \"$artifact_quarantine_root/bb\" ] && [ ! -e \"$artifact_quarantine_root/dd\" ] || exit 80",
      "      [ \"$(cat \"$cursor_current\")\" = old-current-key ] || exit 81",
      "      [ ! -e \"$cursor_previous\" ] || exit 82",
      "      [ \"$(sqlite3 \"$lifecycle_store\" 'select value from sentinel;')\" = OLD_LIFECYCLE_FINALIZATION_STORE ] || exit 83",
      "      [ \"$(cat \"$public_route\")\" = '{\"route\":\"OLD\"}' ] || exit 85",
      "      [ \"$(cat \"$target_route_config\")\" = '{\"generation\":\"OLD\"}' ] || exit 86",
      "      (\"$rollback_receipt_node\" \"$rollback_receipt_producer\" \"$rollback_challenge\" \"$rollback_receipt\" \"$management_key\" \"$production_process_name\" \"$cwd\" \"$script\" \"$previous_runtime_identity\" \"$previous_migration_identity\") >/dev/null 2>&1 &",
      options.rollbackFails ? "      exit 70" : "      printf '333\\n' > \"$pid_file\"",
    "    fi",
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
      if (options.previousRuntimeUnavailableWhenStopped && readFixturePid(pm2State.pid) === 0) {
        response.statusCode = 503;
        response.end("stopped");
        return;
      }
      response.statusCode = 200;
      response.end("ok");
      return;
    }
    if (request.url === "/doctor") {
      response.setHeader("content-type", "application/json");
      response.end(JSON.stringify({ status: "PASS" }));
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
  const snapshotStoreIds = [
    "oauth-main-and-connector-state",
    "authority-store",
    "contexts-store",
    "process-metadata",
    "process-output",
    "filesystem-sync",
    "artifact-catalog",
    "artifact-cas",
    "artifact-quarantine",
    "pagination-current-signing-key",
    "lifecycle-finalization-store",
    "runtime-environment",
    "process-manager-definition",
    "public-route",
    "target-route-generation-config",
    "pagination-previous-signing-key",
  ];
  const snapshotEntries: SnapshotGroupEntry[] = [
    { id: "oauth-main-and-connector-state", kind: "sqlite", path: oauthDatabasePath, required: true },
    { id: "authority-store", kind: "sqlite", path: authorityDatabasePath, required: true },
    { id: "contexts-store", kind: "file", path: contextStorePath, required: true },
    { id: "process-metadata", kind: "directory", path: processStateDir, required: true },
    { id: "process-output", kind: "directory", path: processOutputDir, required: true },
    { id: "filesystem-sync", kind: "sqlite", path: filesystemSyncStorePath, required: true },
    { id: "artifact-catalog", kind: "sqlite", path: artifactCatalogPath, required: true },
    { id: "artifact-cas", kind: "directory", path: artifactObjectRoot, required: true },
    { id: "artifact-quarantine", kind: "directory", path: artifactQuarantineRoot, required: true },
    { id: "pagination-current-signing-key", kind: "file", path: cursorCurrentPath, required: true },
    { id: "lifecycle-finalization-store", kind: "sqlite", path: lifecycleFinalizationStorePath, required: true },
    { id: "runtime-environment", kind: "file", path: productionEnvPath, required: true },
    { id: "process-manager-definition", kind: "file", path: startScriptPath, required: true },
    { id: "public-route", kind: "file", path: publicRoutePath, required: true },
    { id: "target-route-generation-config", kind: "file", path: targetRouteConfigPath, required: true },
    { id: "pagination-previous-signing-key", kind: "file", path: cursorPreviousPath, required: false },
  ];
  const activation = {
    receiptId: "connector-activation-aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
    tupleDigest: digestLabel("fixture-activation-tuple"),
    activePreimageDigest: digestLabel("fixture-activation-preimage"),
    finalizationPlanDigest: digestLabel("fixture-finalization-plan"),
  };
  const candidateIdentity: ProductionUpgradeRequest["connectorLifecycle"]["candidateIdentity"] = {
    runtimeIdentityDigest: digestJson(expectedRuntimeIdentity),
    buildDigest: manifestIdentity.buildDigest,
    schemaGeneration: manifestIdentity.schemaGeneration,
    authorityContractGeneration: manifestIdentity.authorityContractGeneration,
    buildCapabilityManifestDigest: buildCapabilities.capabilityDigest,
    generatedSchemaDigest: await releaseTreeDigest(nextRelease, [
      "config.schema.json",
      "config/config.schema.json",
      "contracts/tools-v2.schema.json",
      "contracts/build-capabilities.schema.json",
    ]),
    packageSha256: payloadDigest,
  };
  const lifecycleEvidence = Object.fromEntries(await Promise.all(evidenceFiles.map(
    async ([path, kind]) => [kind, { path, sha256: digestBytes(await readFile(path)) }],
  ))) as Record<string, { path: string; sha256: `sha256:${string}` }>;
  const requestedAt = new Date().toISOString();
  const timeoutMs = options.timeoutMs ?? 2_000;
  const producerSha256 = createHash("sha256").update("fixture-gate-producer-spki").digest("hex");
  const request: ProductionUpgradeRequest = {
    version: 4,
    transactionId,
    requestedAt,
    delayMs: 1,
    timeoutMs,
    pm2ProcessName: "devspace-v2-production",
    pm2Executable: pm2,
    gitExecutable: git,
    previous: {
      pid: 111,
      cwd: previousRelease,
      script: previousScript,
      auditTarget: previousAudit,
      runtimeIdentityDigest: previousRuntimeIdentityDigest,
      migrationManifestDigest: globalMigrationManifestDigest,
      localHealthUrl: `http://127.0.0.1:${port}/healthz`,
      localReadyUrl: managementReadyUrl,
      rollbackHostChallenge: {
        rollbackChallengeRequest,
        challengePath: rollbackHostChallengePath,
        challengeSha256: rollbackHostChallengeSha256,
        receiptPath: rollbackHostReceiptPath,
        deadlineAt: new Date(rollbackHostChallenge.payload.expiresAtMs).toISOString(),
        pollIntervalMs: 10,
      },
    },
    next: {
      commit: nextCommit,
      sourceTree: nextSourceTree,
      sourceEvidenceRoot: nextSourceEvidenceRoot,
      immutableRuntimeRoot: nextRelease,
      immutableRuntimeEntrypoint: nextScript,
      runtimeDependencies: {
        root: runtimeDependencyRoot,
        evidencePath: runtimeDependencyEvidencePath,
        evidenceSha256: runtimeDependencyEvidenceSha256,
      },
      dist: nextDist,
      manifest: {
        path: manifestPath,
        sha256: manifestSha256,
        buildDigest: manifestIdentity.buildDigest,
        runtimeRevision: manifestIdentity.runtimeRevision,
        schemaGeneration: manifestIdentity.schemaGeneration,
        authorityContractGeneration: manifestIdentity.authorityContractGeneration,
        configSchemaIdentity: manifestIdentity.configSchemaIdentity,
        migrationManifestDigest: globalMigrationManifestDigest,
        buildCapabilityManifestDigest: candidateIdentity.buildCapabilityManifestDigest,
        generatedSchemaDigest: candidateIdentity.generatedSchemaDigest,
        packageSha256: candidateIdentity.packageSha256,
        runtimeIdentityDigest: candidateIdentity.runtimeIdentityDigest,
        ...options.requestManifestOverride,
      },
    },
    oauthStateDirectory: dirname(oauthDatabasePath),
    productionEnvPath,
    productionEnvBackupPath,
    oauthDatabasePath,
    oauthDatabaseBackupPath,
    authorityDatabasePath,
    authorityDatabaseBackupPath,
    snapshotGroup: {
      snapshotRoot: snapshotGroupRoot,
      manifestPath: join(snapshotGroupRoot, "SNAPSHOT-GROUP.json"),
      paginationPreviousSigningKey: { state: "ABSENT", path: cursorPreviousPath },
      barrier: {
        kind: "PM2_STOPPED",
        transactionId,
        processName: "devspace-v2-production",
        previousPid: 111,
        previousRuntimeIdentityDigest,
        previousMigrationManifestDigest: globalMigrationManifestDigest,
        candidateIdentityDigest: digestJson(candidateIdentity),
        cutoverProcessNames: ["devspace-v2-production"],
        captureDeadlineAt: new Date(Date.parse(requestedAt) + timeoutMs).toISOString(),
      },
      entries: options.snapshotEntriesOverride?.(snapshotEntries) ?? snapshotEntries,
    },
    cutoverProcessNames: ["devspace-v2-production"],
    connectorLifecycle: {
      bindingDigest: digestLabel("placeholder-lifecycle-binding"),
      stagingActivationPrecheck: lifecycleEvidence["staging activation precheck"]!,
      preCutoverHostCanary: lifecycleEvidence["pre cutover Host canary"]!,
      releaseDriver,
      journal: {
        path: connectorJournalPath,
        identity: {
          storeId: "33333333-3333-4333-8333-333333333333",
          storePath: connectorJournalPath,
          schemaVersion: 1,
          migrationManifestDigest: digestLabel("connector-journal-migration"),
          contentGeneration: digestLabel("connector-journal-initial-content"),
          snapshotPolicy: "PRESERVE_OUTSIDE_MUTABLE_ROLLBACK",
          receiptReplayPolicy: "PREPARED_RECEIPT_PERMANENTLY_ONE_SHOT",
          schemaFingerprint: digestLabel("connector-journal-schema"),
          createdAtMs: Date.now() - 1_000,
        },
      },
      postActivation: {
        challengePath: postChallengePath,
        challengeSha256: lifecycleEvidence["post activation challenge"]!.sha256,
        receiptPath: postReceiptPath,
        deadlineAt: new Date(Date.now() + 5 * 60_000).toISOString(),
        pollIntervalMs: 10,
        runtimeIdentityUrl: managementReadyUrl,
        routeIdentityUrl: `http://127.0.0.1:${managementPort}/route-identityz`,
      },
      managementAuthorizationKeyRef: managementKeyPath,
      managementNonce: "fixture-management-nonce",
      managementCorrelationId: "fixture-management-correlation",
      candidateIdentity,
      oauthResource: "https://devspace.example.test/mcp",
      productionEnvironmentIdentityDigest: digestLabel("production-environment"),
      productionRouteIdentityDigest: digestLabel("production-route"),
      finalization: {
        storePath: lifecycleFinalizationStorePath,
        controlPath: join(controlDirectory, "finalization-control.json"),
        keyId: managementKey.keyId,
        gateProducer: {
          keyId: `gate-producer-ed25519-sha256:${producerSha256}`,
          publicKeySha256: `sha256:${producerSha256}` as `sha256:${string}`,
        },
        gateProducerTrustAnchor: {
          path: join(controlDirectory, "gate-producer-trust-anchor.json"),
          sha256: digestLabel("gate-producer-trust-anchor"),
        },
        preSnapshotIdentity: {
          storeId: "lifecycle-finalization-store",
          schemaVersion: 2,
          state: "DRAFT",
          revision: 1,
          transactionId: null,
          contentGeneration: digestLabel("fixture-finalization-content-generation"),
          controlEpoch: 1,
          controlTag: `hmac-sha256:${"7".repeat(64)}` as `hmac-sha256:${string}`,
          identityDigest: digestLabel("fixture-finalization-identity"),
        },
      },
    },
    rollbackJournalPath,
    nextEnvPath,
    startScriptPath,
    startScriptBackupPath,
    auditDirectory,
    currentAuditLink,
    statusPath,
    workerClaimPath: `${statusPath}.worker-claim.json`,
    workerLogPath: join(auditDirectory, "worker.log"),
    localHealthUrl: `http://127.0.0.1:${port}/healthz`,
    localDoctorUrl: `http://127.0.0.1:${managementPort}/doctorz`,
    publicHealthUrl: "https://devspace.example.test/healthz",
    publicMetricsUrl: "https://devspace.example.test/metrics",
    publicMcpUrl: "https://devspace.example.test/mcp",
    oauthMetadataUrl: "https://devspace.example.test/.well-known/oauth-protected-resource/mcp",
    expectedScopes,
  };
  request.connectorLifecycle.bindingDigest = productionUpgradeLifecycleBindingDigest(request);
  const lifecycleProbe: FixtureLifecycleProbe = {
    opens: 0,
    prepares: 0,
    activations: 0,
    providerDispatches: 0,
    waits: 0,
    postVerifications: 0,
    closes: 0,
  };
  let dispatched = false;
  let postVerified = false;
  const verifiedLifecycleReadback = () => ({
    state: "POST_ACTIVATION_VERIFIED" as const,
    receiptId: activation.receiptId,
    tupleDigest: activation.tupleDigest,
    activationReceiptDigest: digestLabel("fixture-activation-receipt"),
    activationProofDigest: digestLabel("fixture-activation-proof"),
    authorityReceiptDigest: digestLabel("fixture-activation-authority-receipt"),
    postActivationEvidenceDigest: digestLabel("fixture-post-activation-evidence"),
    journalContentGeneration: digestLabel("fixture-journal-post-verified"),
  });
  const dependencies: ProductionUpgradeWorkerDependencies = {
    async publicFetch(input, init) {
      const requested = new URL(typeof input === "string" ? input : input instanceof URL ? input.href : input.url);
      const local = new URL(requested.pathname + requested.search, `http://127.0.0.1:${port}`);
      return fetch(local, init);
    },
    openConnectorLifecycle() {
      lifecycleProbe.opens += 1;
      let closed = false;
      return {
        async prepare() {
          lifecycleProbe.prepares += 1;
          if (options.lifecycleFailure === "PREPARE") {
            throw new Error("fixture lifecycle prepare fault");
          }
          return {
            state: "CONNECTOR_ACTIVATION_PREPARED",
            receiptId: activation.receiptId,
            tupleDigest: activation.tupleDigest,
            journalContentGeneration: digestLabel("fixture-journal-prepared"),
          };
        },
        async activateOrReconcile() {
          lifecycleProbe.activations += 1;
          if (postVerified) return verifiedLifecycleReadback();
          if (!dispatched) {
            dispatched = true;
            lifecycleProbe.providerDispatches += 1;
            writeFixtureDatabaseValue(connectorJournalPath, "DISPATCHED_PERMANENT_ONE_SHOT");
          }
          if (options.lifecycleFailure === "ACTIVATE_AFTER_DISPATCH") {
            throw new Error("fixture lifecycle fault after durable DISPATCHED");
          }
          return {
            state: "ACTIVATED_PENDING_POSTCHECK",
            receiptId: activation.receiptId,
            tupleDigest: activation.tupleDigest,
            activationReceiptDigest: digestLabel("fixture-activation-receipt"),
            activationProofDigest: digestLabel("fixture-activation-proof"),
            authorityReceiptDigest: digestLabel("fixture-activation-authority-receipt"),
            journalContentGeneration: digestLabel("fixture-journal-pending"),
          };
        },
        async waitForPostActivationReceipt() {
          lifecycleProbe.waits += 1;
          if (options.rollbackJournalFailure === "BEFORE_REQUEST") {
            await chmod(rollbackJournalPath, 0o400);
          }
          if (options.corruptSnapshotBeforeRollback) {
            const manifest = JSON.parse(
              await readFile(join(snapshotGroupRoot, "SNAPSHOT-GROUP.json"), "utf8"),
            ) as { entries?: Array<{ snapshotPath?: string }> };
            const snapshotPath = manifest.entries?.find((entry) => entry.snapshotPath)?.snapshotPath;
            if (snapshotPath) await rm(snapshotPath, { recursive: true, force: true });
          }
          if (options.lifecycleFailure === "WAIT_POST"
            || options.corruptSnapshotBeforeRollback
            || options.rollbackJournalFailure === "BEFORE_REQUEST"
            || options.rollbackJournalFailure === "BEFORE_RESTORE_RECORD") {
            throw new Error("fixture lifecycle POST wait fault");
          }
        },
        async verifyPostActivation() {
          lifecycleProbe.postVerifications += 1;
          if (options.lifecycleFailure === "VERIFY_POST") {
            throw new Error("fixture lifecycle POST verification fault");
          }
          postVerified = true;
          return verifiedLifecycleReadback();
        },
        close() {
          if (closed) return;
          closed = true;
          lifecycleProbe.closes += 1;
        },
      };
    },
    async finalizeProduction() {
      return {
        state: "BASE_PROFILE_FINAL_PASS",
        finalDigest: digestLabel("fixture-base-profile-final-pass"),
      };
    },
    async advanceFinalizationBeforeActivation() {},
    verifyFinalizedProduction() {},
  };
  await writeFile(requestPath, serializeProductionUpgradeRequestV4(request), { mode: 0o600 });
  return {
    activation,
    dependencies,
    lifecycleProbe,
    requestPath,
    statusPath,
    productionEnvPath,
    oauthDatabasePath,
    oauthDatabaseBackupPath,
    authorityDatabasePath,
    authorityDatabaseBackupPath,
    expectedOauthDatabasePath,
    expectedAuthorityDatabasePath,
    contextStorePath,
    processStateDir,
    processOutputDir,
    artifactCatalogPath,
    filesystemSyncStorePath,
    artifactObjectRoot,
    artifactQuarantineRoot,
    cursorCurrentPath,
    cursorPreviousPath,
    connectorJournalPath,
    rollbackJournalPath,
    rollbackHostChallengePath,
    rollbackHostReceiptPath,
    managementKey,
    releaseDriverPaths,
    snapshotStoreIds,
    startScriptPath,
    currentAuditLink,
    auditDirectory,
    previousAudit,
    previousRelease,
    previousScript,
    nextRelease,
    nextSourceEvidenceRoot,
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

function createFixtureDatabase(path: string, value: string): void {
  const database = new Database(path);
  try {
    database.exec("create table sentinel (value text not null)");
    database.prepare("insert into sentinel (value) values (?)").run(value);
  } finally {
    database.close();
  }
}

function setFixtureUserVersion(path: string, version: number): void {
  const database = new Database(path);
  try {
    database.pragma(`user_version = ${version}`);
  } finally {
    database.close();
  }
}

function writeFixtureDatabaseValue(path: string, value: string): void {
  const database = new Database(path);
  try {
    database.prepare("update sentinel set value = ?").run(value);
  } finally {
    database.close();
  }
}

function readFixtureDatabaseValue(path: string): string {
  const database = new Database(path, { readonly: true });
  try {
    return database.prepare("select value from sentinel").pluck().get() as string;
  } finally {
    database.close();
  }
}

function shellQuote(value: string): string {
  return `'${value.replaceAll("'", `'"'"'`)}'`;
}

function escapeRegExp(value: string): string {
  return value.replace(/[.*+?^${}()|[\]\\]/gu, "\\$&");
}

async function releaseTreeDigest(root: string, files: string[]): Promise<`sha256:${string}`> {
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

function digestLabel(value: string): `sha256:${string}` {
  return `sha256:${createHash("sha256").update(value).digest("hex")}`;
}

function digestBytes(value: string | Uint8Array): `sha256:${string}` {
  return `sha256:${createHash("sha256").update(value).digest("hex")}`;
}

function digestJson(value: unknown): `sha256:${string}` {
  return digestBytes(stableJson(value));
}

function stableJson(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(stableJson).join(",")}]`;
  if (value && typeof value === "object") {
    const record = value as Record<string, unknown>;
    return `{${Object.keys(record).sort().map(
      (key) => `${JSON.stringify(key)}:${stableJson(record[key])}`,
    ).join(",")}}`;
  }
  return JSON.stringify(value) ?? "null";
}

function fixtureMigration(storeId: string, version: number): MigrationManifestEntry {
  return {
    storeId,
    version,
    name: `${storeId}-fixture-v${version}`,
    checksum: digestLabel(`${storeId}-fixture-v${version}`),
    module: `v2/${storeId}`,
  };
}

function readFixturePid(path: string): number {
  return Number(readFileSync(path, "utf8").trim());
}

function fixtureReadinessReport(input: {
  identity: FixtureRuntimeIdentity;
  buildCapabilityDigest: string;
  oauthDatabasePath: string;
  authorityDatabasePath: string;
  artifactCatalogPath: string;
  filesystemSyncStorePath: string;
  connectorJournalPath: string;
  cursorCurrentPath: string;
  managementKeyPath: string;
  omitCheck?: string;
  omitStoreObservation?: string;
}): Record<string, unknown> {
  const storeObservations = [
    readinessStore("main", input.oauthDatabasePath, {
      manifestDigest: digestLabel("fixture-main-migration"),
      appliedEntries: 1,
      complete: true,
    }),
    readinessStore("authority", input.authorityDatabasePath, { userVersion: 7, expectedUserVersion: 7 }),
    readinessStore("artifact-catalog", input.artifactCatalogPath, { userVersion: 1, expectedUserVersion: 1 }),
    readinessStore("filesystem-sync", input.filesystemSyncStorePath, { userVersion: 1, expectedUserVersion: 1 }),
    readinessStore("connector-activation-journal", input.connectorJournalPath, {
      userVersion: 1,
      expectedUserVersion: 1,
    }),
    readinessChild({
      id: "pagination-current-signing-key",
      path: input.cursorCurrentPath,
      exists: true,
      required: true,
    }),
    readinessChild({
      id: "management-authorization-key",
      path: input.managementKeyPath,
      exists: true,
      required: true,
    }),
    readinessChild({
      id: "connector-activation-journal-identity",
      storePath: input.connectorJournalPath,
      schemaVersion: 1,
    }),
  ].filter((observation) => {
    const evidence = observation.evidence as Record<string, unknown>;
    return (evidence.id ?? evidence.storeId) !== input.omitStoreObservation;
  });
  const capabilityEvidence = {
    productProfile: "BASE_SINGLE_OWNER",
    buildCapabilityDigest: input.buildCapabilityDigest,
    expectedCapabilityDigest: input.buildCapabilityDigest,
    resourceUriVersion: "v1",
    schemaGeneration: input.identity.schemaGeneration,
    authorityContractGeneration: input.identity.authorityContractGeneration,
    buildDigest: input.identity.buildDigest,
  };
  const checks = [
    readinessCheck("config_build_capabilities", capabilityEvidence),
    readinessCheck("non_root", {}),
    readinessCheck("required_store_migrations", { observations: storeObservations }),
    readinessCheck("authority_artifact_readability", {}),
    readinessCheck("target_route_generation", { targetGeneration: 1, routeGeneration: 1 }),
    readinessCheck("cursor_signing", { currentKeyId: "fixture-key" }),
    readinessCheck("canonical_connector", { activeCount: 1, invalidStates: [], bindingsByState: { ACTIVE: 1 } }),
    readinessCheck("supervisor_control", { processManager: "pm2" }),
    readinessCheck("rate_limit_identity", { policyDigest: digestLabel("fixture-rate-policy") }),
    readinessCheck("management_isolation", { managementHost: "127.0.0.1" }),
    readinessCheck("audit_sink", { startupProof: "RECORDED" }),
    readinessCheck("runtime_contract_identity", capabilityEvidence),
  ].filter((check) => check.id !== input.omitCheck);
  return {
    status: "ready",
    httpStatus: 200,
    checkedAt: new Date().toISOString(),
    durationMs: 1,
    checks,
    identity: input.identity,
  };
}

function readinessStore(
  storeId: string,
  path: string,
  extra: Record<string, unknown>,
): Record<string, unknown> {
  return readinessChild({
    storeId,
    path,
    required: true,
    integrity: "ok",
    foreignKeyViolations: 0,
    ...extra,
  });
}

function readinessChild(evidence: Record<string, unknown>): Record<string, unknown> {
  return { state: "PASS", evidence };
}

function readinessCheck(id: string, evidence: Record<string, unknown>): Record<string, unknown> {
  return { id, state: "PASS", durationMs: 1, evidence };
}

function fixtureDoctorReport(input: {
  identity: FixtureRuntimeIdentity;
  migrationManifestDigest: string;
  status: "PASS" | "ready";
  omitCheck?: string;
}): Record<string, unknown> {
  const checks = [
    doctorCheck("authority_claim_receipt", { receiptResults: [{ result: "CANCELLED_NOT_DISPATCHED" }] }),
    doctorCheck("connector_consistency", { activeCount: 1, invalidStates: [], bindingsByState: { ACTIVE: 1 } }),
    doctorCheck("pm2_uniqueness", { matches: 1, statuses: ["online"] }),
    doctorCheck("public_metrics_negative_probe", { status: 404 }),
    doctorCheck("artifact_reconciliation", {
      abortedReservations: 0,
      quarantinedObjects: 0,
      quarantinedRecords: 0,
      receipts: 0,
    }),
    doctorCheck("migration_manifest_scan", {
      digest: input.migrationManifestDigest,
      entries: 5,
      stores: ["main", "authority", "artifact-catalog", "filesystem-sync", "connector-activation-journal"],
      requiredStores: ["authority", "artifact-catalog", "filesystem-sync", "connector-activation-journal"],
      missingRequiredStores: [],
    }),
    doctorCheck("mutable_snapshot_capability", {
      groupDigest: digestLabel("fixture-doctor-snapshot"),
      entries: 1,
    }),
    doctorCheck("rate_canary", { allowed: true }),
    doctorCheck("stale_lease_nonterminal_report", {
      authority: { pendingReservations: 0 },
      selfManagement: { activeRestartTransactions: 0 },
    }),
    doctorCheck("runtime_identity_readback", { expected: input.identity, actual: input.identity }),
  ].filter((check) => check.id !== input.omitCheck);
  return {
    status: input.status,
    correlationId: "doctor-fixture-correlation",
    namespace: "doctor_11111111-1111-4111-8111-111111111111",
    startedAt: new Date().toISOString(),
    completedAt: new Date().toISOString(),
    durationMs: 10,
    maximumDurationMs: 30_000,
    checks,
    cleanup: { state: "CLEANED", receiptDigest: digestLabel("fixture-doctor-cleanup") },
    releasePassClaimed: false,
  };
}

function doctorCheck(id: string, evidence: Record<string, unknown>): Record<string, unknown> {
  return { id, state: "PASS", durationMs: 1, evidence };
}
