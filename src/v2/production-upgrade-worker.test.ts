import { spawnSync } from "node:child_process";
import assert from "node:assert/strict";
import { createServer, type Server } from "node:http";
import {
  chmod,
  mkdtemp,
  mkdir,
  readFile,
  readlink,
  rm,
  symlink,
  writeFile,
} from "node:fs/promises";
import type { AddressInfo } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test, { type TestContext } from "node:test";
import {
  directoryEvidence,
  pm2CommandEnvironment,
  productionPm2Environment,
  runProductionUpgradeWorker,
  type ProductionUpgradeRequest,
} from "./production-upgrade-worker.js";

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

test("production upgrade worker switches one PM2 process and commits canonical pointers only after verification", async (t) => {
  const fixture = await createFixture(t, { publicMetricsStatus: 403 });
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
  };
  assert.equal(status.state, "PASS");
  assert.equal(typeof status.acceptedAt, "string");
  assert.deepEqual(
    status.history?.map((entry) => entry.state),
    ["PREPARED", "ACCEPTED", "SWITCHING", "VERIFYING", "PASS"],
  );
  assert.equal(status.pidAfter, 222);
  assert.equal(status.publicMetricsStatus, 403);
  assert.equal(status.unauthenticatedMcpStatus, 401);
  assert.deepEqual(status.oauthScopes, expectedScopes);
  assert.equal(status.runtimeCommit, fixture.nextCommit);
  assert.equal(status.runtimeSourceTree, fixture.nextSourceTree);
  assert.deepEqual(status.runtimeDist, fixture.nextDist);
  assert.equal(await readFile(fixture.productionEnvPath, "utf8"), "NEXT_ENV=1\n");
  assert.match(await readFile(fixture.startScriptPath, "utf8"), new RegExp(escapeRegExp(fixture.nextScript), "u"));
  assert.equal(await readlink(fixture.currentAuditLink), fixture.auditDirectory);
  assert.equal((await readFile(fixture.pm2State.pid, "utf8")).trim(), "222");
  assert.equal((await readFile(fixture.pm2State.cwd, "utf8")).trim(), fixture.nextRelease);
  assert.equal((await readFile(fixture.pm2State.script, "utf8")).trim(), fixture.nextScript);
});

test("production upgrade worker rolls back env, process, start path, and audit link on public-boundary failure", async (t) => {
  const fixture = await createFixture(t, { publicMetricsStatus: 200, timeoutMs: 250 });
  await assert.rejects(runProductionUpgradeWorker(fixture.requestPath), /Public metrics returned 200/u);
  const status = JSON.parse(await readFile(fixture.statusPath, "utf8")) as {
    state: string;
    rollback?: { restored?: boolean; healthStatus?: number };
  };
  assert.equal(status.state, "FAIL");
  assert.equal(status.rollback?.restored, true);
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
    rollback?: { restored?: boolean; error?: string };
  };
  assert.equal(status.state, "UNKNOWN");
  assert.equal(status.history?.at(-1)?.state, "UNKNOWN");
  assert.equal(status.rollback?.restored, false);
  assert.equal(typeof status.rollback?.error, "string");
});

async function createFixture(
  t: TestContext,
  options: { publicMetricsStatus: number; timeoutMs?: number; rollbackFails?: boolean },
) {
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
  await writeFile(nextEnvPath, "NEXT_ENV=1\n", { mode: 0o600 });
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
