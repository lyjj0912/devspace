import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { access, chmod, mkdir, mkdtemp, readFile, realpath, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join, relative, resolve, sep } from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";
import {
  RETIRED_RELEASE_ENVIRONMENT_KEYS,
  RUNTIME_STATE_PATH_KEYS,
  materializeReleaseEnvironment,
} from "./lib/release-environment.mjs";
import { cleanupCandidateBeforeCutover } from "./lib/release-candidate-cleanup.mjs";

const scriptsRoot = dirname(fileURLToPath(import.meta.url));
const repositoryRoot = dirname(scriptsRoot);

test("production upgrade shell rejects incomplete v4 input before filesystem or PM2 mutation", async (t) => {
  const root = await mkdtemp(join(await realpath(tmpdir()), "devspace-upgrade-not-integrated-"));
  t.after(() => rm(root, { recursive: true, force: true }));
  await chmod(root, 0o700);
  const releaseRoot = join(root, "release-root-must-remain-absent");
  const deploymentRoot = join(root, "deployment-root-must-remain-absent");
  const bin = join(root, "bin");
  const pm2Log = join(root, "pm2-must-not-run.log");
  await mkdir(bin, { mode: 0o700 });
  await writeFile(join(bin, "pm2"), [
    "#!/bin/sh",
    ': > "$DEVSPACE_TEST_PM2_LOG"',
    "exit 99",
    "",
  ].join("\n"), { mode: 0o700 });
  const result = spawnSync("/bin/bash", [
    join(repositoryRoot, "scripts", "upgrade-universal-broker-v2-production.sh"),
    "--release-root", releaseRoot,
    "--deployment-root", deploymentRoot,
  ], {
    encoding: "utf8",
    env: {
      ...process.env,
      PATH: `${bin}:${process.env.PATH ?? ""}`,
      DEVSPACE_TEST_PM2_LOG: pm2Log,
    },
  });

  assert.equal(result.status, 2, result.stderr);
  assert.match(result.stderr, /must be absolute/u);
  await assert.rejects(access(releaseRoot), /ENOENT/u);
  await assert.rejects(access(deploymentRoot), /ENOENT/u);
  await assert.rejects(access(pm2Log), /ENOENT/u);

  const help = spawnSync("/bin/bash", [
    join(repositoryRoot, "scripts", "upgrade-universal-broker-v2-production.sh"),
    "--help",
  ], { encoding: "utf8" });
  assert.equal(help.status, 0, help.stderr);
  assert.match(help.stdout, /Usage: upgrade-universal-broker-v2-production\.sh/u);

  const releaseVerifier = await readFile(
    join(repositoryRoot, "scripts", "verify-universal-broker-v2-release.mjs"),
    "utf8",
  );
  assert.doesNotMatch(
    await readFile(join(repositoryRoot, "scripts", "upgrade-universal-broker-v2-production.sh"), "utf8"),
    /NOT_INTEGRATED:/u,
  );
  assert.match(releaseVerifier, /upgrade\.includes\("NOT_INTEGRATED:"\)/u);
});

test("candidate and production runtime environments materialize all writable paths explicitly", async (t) => {
  const root = await mkdtemp(join(tmpdir(), "devspace-release-env-isolation-"));
  t.after(() => rm(root, { recursive: true, force: true }));
  const productionRoot = join(root, "production-state");
  const candidateRoot = join(root, "audit", "candidate-state");
  const candidateControl = join(root, "audit", "candidate-control", "lifecycle-finalization-head.json");
  const productionControl = join(root, "production-control", "lifecycle-finalization-head.json");
  const source = join(root, "production.env");
  const candidate = join(root, "candidate.env");
  const next = join(root, "production.env.next");
  const productionPaths = runtimeStatePaths(productionRoot, true);
  await writeFile(source, [
    "KEEP_UNRELATED='preserved value'",
    "DEVSPACE_NEXT_SELF_RESTART_DELAY_MS='500'",
    "DEVSPACE_PERSONAL_STAGING_FIXTURE='stale'",
    "DEVSPACE_NEXT_LIFECYCLE_FINALIZATION_CONTROL='stale-control'",
    ...Object.entries(productionPaths).map(([key, value]) => `${key}='${value}'`),
    "",
  ].join("\n"), { mode: 0o600 });

  const candidatePaths = runtimeStatePaths(candidateRoot, false);
  materializeReleaseEnvironment({
    sourcePath: source,
    destinationPath: candidate,
    values: {
      ...candidatePaths,
      DEVSPACE_NEXT_PORT: "7679",
      DEVSPACE_NEXT_LIFECYCLE_FINALIZATION_CONTROL: candidateControl,
    },
  });
  materializeReleaseEnvironment({
    sourcePath: source,
    destinationPath: next,
    values: {
      ...productionPaths,
      DEVSPACE_NEXT_PORT: "7678",
      DEVSPACE_NEXT_LIFECYCLE_FINALIZATION_CONTROL: productionControl,
    },
  });

  const releaseStateKeys = [
    "DEVSPACE_NEXT_STATE_DIR",
    "DEVSPACE_NEXT_OAUTH_STATE_DIR",
    ...RUNTIME_STATE_PATH_KEYS,
  ];
  const candidateEnvironment = sourceEnvironment(candidate, [...releaseStateKeys, "KEEP_UNRELATED"]);
  const productionEnvironment = sourceEnvironment(next, [...releaseStateKeys, "KEEP_UNRELATED"]);
  assert.equal(candidateEnvironment.KEEP_UNRELATED, "preserved value");
  assert.equal(productionEnvironment.KEEP_UNRELATED, "preserved value");
  const removed = sourceEnvironment(candidate, [
    "DEVSPACE_NEXT_SELF_RESTART_DELAY_MS",
    "DEVSPACE_PERSONAL_STAGING_FIXTURE",
  ]);
  assert.equal(removed.DEVSPACE_NEXT_SELF_RESTART_DELAY_MS, "");
  assert.equal(removed.DEVSPACE_PERSONAL_STAGING_FIXTURE, "");
  assert.deepEqual(RETIRED_RELEASE_ENVIRONMENT_KEYS, ["DEVSPACE_PERSONAL_STAGING_FIXTURE"]);
  assert.throws(() => materializeReleaseEnvironment({
    sourcePath: source,
    destinationPath: join(root, "forbidden.env"),
    values: { DEVSPACE_PERSONAL_STAGING_FIXTURE: "1" },
  }), /key is not managed/u);
  assert.deepEqual(
    sourceEnvironment(candidate, ["DEVSPACE_NEXT_LIFECYCLE_FINALIZATION_CONTROL"]),
    { DEVSPACE_NEXT_LIFECYCLE_FINALIZATION_CONTROL: candidateControl },
  );
  for (const key of releaseStateKeys) {
    const candidateValue = candidateEnvironment[key];
    assert.notEqual(candidateValue, productionPaths[key], `${key} must not reuse production state`);
    if (key === "DEVSPACE_NEXT_CURSOR_PREVIOUS_SIGNING_KEY_REF") {
      assert.equal(candidateValue, "", "a fresh candidate must explicitly clear the production previous key");
    } else if (key === "DEVSPACE_NEXT_STATE_DIR") {
      assert.equal(candidateValue, candidateRoot, "candidate state root must be exact and isolated");
    } else {
      assertContained(candidateRoot, candidateValue, key);
    }
    assert.equal(productionEnvironment[key], productionPaths[key], `${key} production path must be exact`);
  }
});

test("personal promotion snapshots mutable state and installs rollback before stopping production", async () => {
  const path = join(repositoryRoot, "scripts", "promote-universal-broker-v2-personal.sh");
  const help = spawnSync("/bin/bash", [path, "--help"], { encoding: "utf8" });
  assert.equal(help.status, 0, help.stderr);
  const source = await readFile(path, "utf8");
  const trapIndex = source.indexOf("trap 'rollback $?' ERR");
  const stopIndex = source.indexOf('pm2 stop "$PRODUCTION_PROCESS"');
  assert.ok(trapIndex >= 0 && stopIndex > trapIndex, "rollback trap must precede production stop");
  for (const required of [
    'cp -p "$PRODUCTION_ENV" "$AUDIT/production.env.before"',
    'cp -a "$STATE_DIR" "$AUDIT/state.before"',
    'sqlite3 "$OAUTH_STATE_DIR/devspace.sqlite" ".backup',
    'cp -a "$CONTROL_DIR" "$AUDIT/finalization-control.before"',
    'cp -p "$AUDIT/oauth.sqlite.before" "$OAUTH_STATE_DIR/devspace.sqlite"',
    'pm2 start "$OLD_SCRIPT"',
    'Previous production listener did not stop.',
    'observed!=sys.argv[2]',
    'wait_json "$PUBLIC_BASE_URL/healthz"',
    'pm2 delete "$CANDIDATE_PROCESS"',
  ]) assert.ok(source.includes(required), `missing personal promotion boundary: ${required}`);
  assert.doesNotMatch(source, /tailscale funnel --bg|tailscale funnel --https/u);
});

test("pre-cutover candidate cleanup fails closed at delete, save, PM2 readback, listener readback, and listener presence", async () => {
  const scenarios = [
    { name: "delete", responses: [{ status: 7, stdout: "", stderr: "delete failed" }], expected: /delete/u },
    { name: "save", responses: [ok(), { status: 8, stdout: "", stderr: "save failed" }], expected: /save/u },
    {
      name: "pm2-present",
      responses: [ok(), ok(), { status: 0, stdout: pm2List("candidate"), stderr: "" }],
      expected: /still present/u,
    },
    {
      name: "listener-readback",
      responses: [ok(), ok(), { status: 0, stdout: "[]\n", stderr: "" }, { status: 2, stdout: "", stderr: "lsof failed" }],
      expected: /listener readback/u,
    },
    {
      name: "listener-present",
      responses: [ok(), ok(), { status: 0, stdout: "[]\n", stderr: "" }, { status: 0, stdout: "991\n", stderr: "" }],
      expected: /still has a listener/u,
    },
  ];
  for (const scenario of scenarios) {
    let removed = false;
    const responses = [...scenario.responses];
    assert.throws(
      () => cleanupCandidateBeforeCutover({
        pm2Executable: "/fixture/pm2",
        lsofExecutable: "/fixture/lsof",
        candidateName: "candidate",
        candidatePort: 7679,
        candidateState: "/fixture/candidate-state",
        run: () => responses.shift() ?? ok(),
        removeState: () => { removed = true; },
      }),
      scenario.expected,
      scenario.name,
    );
    assert.equal(removed, false, `${scenario.name} must stop before deleting candidate evidence`);
  }

  let removed = false;
  const responses = [ok(), ok(), { status: 0, stdout: "[]\n", stderr: "" }, { status: 1, stdout: "", stderr: "" }];
  const evidence = await cleanupCandidateBeforeCutover({
    pm2Executable: "/fixture/pm2",
    lsofExecutable: "/fixture/lsof",
    candidateName: "candidate",
    candidatePort: 7679,
    candidateState: "/fixture/candidate-state",
    run: () => responses.shift() ?? ok(),
    removeState: () => { removed = true; },
  });
  assert.equal(removed, true);
  assert.equal(evidence.pm2Absent, true);
  assert.equal(evidence.listenerAbsent, true);
});

test("external runtime dependency loader resolves only from the sealed dependency root", async (t) => {
  const root = await mkdtemp(join(tmpdir(), "devspace-runtime-loader-"));
  t.after(() => rm(root, { recursive: true, force: true }));
  const packageRoot = join(root, "immutable-package");
  const dependencyRoot = join(root, "dependencies");
  await mkdir(join(dependencyRoot, "node_modules", "fixture-runtime-dependency"), { recursive: true });
  await mkdir(join(dependencyRoot, "node_modules", "fixture-runtime-commonjs"), { recursive: true });
  await mkdir(packageRoot, { recursive: true });
  await writeFile(join(packageRoot, "main.mjs"), [
    'import { createRequire } from "node:module";',
    'import { identity } from "fixture-runtime-dependency";',
    "const require = createRequire(import.meta.url);",
    'const commonjs = require("fixture-runtime-commonjs");',
    'const builtin = require("fs");',
    "console.log(`${identity}:${commonjs.identity}:${typeof builtin.readFileSync}`);",
    "",
  ].join("\n"));
  await writeFile(join(dependencyRoot, "package.json"), '{"type":"module"}\n');
  await writeFile(join(dependencyRoot, "node_modules", "fixture-runtime-dependency", "package.json"), [
    '{"name":"fixture-runtime-dependency","type":"module","exports":"./index.mjs"}',
    "",
  ].join("\n"));
  await writeFile(join(dependencyRoot, "node_modules", "fixture-runtime-dependency", "index.mjs"), [
    'export const identity = "SEALED_DEPENDENCY_ROOT";',
    "",
  ].join("\n"));
  await writeFile(join(dependencyRoot, "node_modules", "fixture-runtime-commonjs", "package.json"), [
    '{"name":"fixture-runtime-commonjs","main":"index.cjs"}',
    "",
  ].join("\n"));
  await writeFile(join(dependencyRoot, "node_modules", "fixture-runtime-commonjs", "index.cjs"), [
    'module.exports = { identity: "SEALED_COMMONJS_ROOT" };',
    "",
  ].join("\n"));
  const result = spawnSync(process.execPath, [
    "--import", join(repositoryRoot, "scripts", "lib", "runtime-dependency-loader.mjs"),
    join(packageRoot, "main.mjs"),
  ], {
    encoding: "utf8",
    env: {
      ...process.env,
      DEVSPACE_RUNTIME_PACKAGE_ROOT: packageRoot,
      DEVSPACE_RUNTIME_DEPENDENCY_ROOT: dependencyRoot,
    },
  });
  assert.equal(result.status, 0, result.stderr);
  assert.equal(result.stdout.trim(), "SEALED_DEPENDENCY_ROOT:SEALED_COMMONJS_ROOT:function");
});

test("upgrade source orders immutable PM2 launch and gated cleanup before cutover construction", async () => {
  const source = await readFile(join(repositoryRoot, "scripts", "upgrade-universal-broker-v2-production.sh"), "utf8");
  for (const marker of [
    'sourceEvidenceRoot',
    'immutableRuntimeRoot',
    'immutableRuntimeEntrypoint',
    'start "$IMMUTABLE_RUNTIME_ENTRYPOINT"',
    '--cwd "$IMMUTABLE_RUNTIME_ROOT"',
    'assert_candidate_pm2_runtime',
    'cleanup_candidate_before_cutover',
    'cleanup_candidate_best_effort',
    'WORKER="$IMMUTABLE_RUNTIME_ROOT/dist/v2/production-upgrade-worker-cli.js"',
    'CLEANUP_MONITOR="$IMMUTABLE_RUNTIME_ROOT/dist/v2/production-upgrade-cleanup-monitor.js"',
  ]) assert.ok(source.includes(marker), `missing release-isolation marker: ${marker}`);
  for (const key of RUNTIME_STATE_PATH_KEYS) {
    assert.ok(source.includes(`--set ${key}`), `upgrade environment does not materialize ${key}`);
  }
  const candidateCallStart = source.indexOf('write_env "$CANDIDATE_ENV"');
  const candidateCall = source.slice(candidateCallStart, source.indexOf("\npm2 delete", candidateCallStart));
  for (const variable of [
    "CANDIDATE_AUTHORITY_STATE_DIR",
    "CANDIDATE_AUTHORITY_STORE",
    "CANDIDATE_CONNECTOR_ACTIVATION_JOURNAL",
    "CANDIDATE_LIFECYCLE_FINALIZATION_STORE",
    "CANDIDATE_CONTEXT_STORE",
    "CANDIDATE_CONTEXT_WORKTREE_ROOT",
    "CANDIDATE_PROCESS_OUTPUT_DIR",
    "CANDIDATE_SSH_CONTROL_DIR",
    "CANDIDATE_ARTIFACT_STAGING_DIR",
    "CANDIDATE_ARTIFACT_CATALOG",
    "CANDIDATE_ARTIFACT_OBJECT_ROOT",
    "CANDIDATE_AUDIT_SINK",
    "CANDIDATE_CURSOR_CURRENT_KEY",
    "CANDIDATE_CURSOR_PREVIOUS_KEY",
    "CANDIDATE_MANAGEMENT_AUTHORIZATION_KEY",
  ]) assert.ok(candidateCall.includes(`$${variable}`), `candidate call does not supply ${variable}`);
  const cleanup = source.lastIndexOf("\ncleanup_candidate_before_cutover\n");
  const nextEnvironment = source.indexOf('cp -p "$PRODUCTION_ENV" "$ENV_BACKUP"');
  const requestConstruction = source.indexOf("request={");
  const scheduling = source.indexOf('/bin/launchctl submit -l "$LABEL"');
  assert.ok(cleanup >= 0 && cleanup < nextEnvironment && cleanup < requestConstruction && cleanup < scheduling);
  assert.doesNotMatch(
    source.slice(source.indexOf("cleanup_candidate_before_cutover()"), source.indexOf("cleanup_candidate_best_effort()")),
    /\|\|\s*true/u,
  );
  assert.match(
    source.slice(source.indexOf("cleanup_on_exit()"), source.indexOf("trap cleanup_on_exit EXIT")),
    /if \[\[ "\$UPGRADE_SCHEDULED" != 1 \]\]; then\s+cleanup_candidate_best_effort/u,
  );
});

test("scheduler timeout uses the same atomic worker claim and preserves an active claimant", async (t) => {
  const source = await readFile(join(repositoryRoot, "scripts", "upgrade-universal-broker-v2-production.sh"), "utf8");
  const functionSource = source.slice(
    source.indexOf("acquire_timeout_claim_guard()"),
    source.indexOf("\nif [[ -d \"$RELEASE/.git\"", source.indexOf("acquire_timeout_claim_guard()")),
  );
  assert.ok(functionSource.startsWith("acquire_timeout_claim_guard()"));
  const timeoutStart = source.indexOf('TIMEOUT_GUARD_CLAIM_ID="$(acquire_timeout_claim_guard');
  const activeBranchStart = source.indexOf('if [[ "$TIMEOUT_GUARD_RC" == 75 ]]', timeoutStart);
  const guardBranchStart = source.indexOf('elif [[ "$TIMEOUT_GUARD_RC" == 0 ]]', activeBranchStart);
  assert.ok(timeoutStart >= 0 && activeBranchStart > timeoutStart && guardBranchStart > activeBranchStart);
  assert.doesNotMatch(source.slice(activeBranchStart, guardBranchStart), /delete "\$PM2_WORKER_NAME"|launchctl remove/u);

  const root = await mkdtemp(join(await realpath(tmpdir()), "devspace-timeout-claim-"));
  t.after(() => rm(root, { recursive: true, force: true }));
  await chmod(root, 0o700);
  const statusPath = join(root, "status.json");
  const claimPath = `${statusPath}.worker-claim.json`;
  const binding = `sha256:${"a".repeat(64)}`;
  const status = {
    version: 2,
    transactionId: "upgrade-fixture",
    requestBindingDigest: binding,
    state: "PREPARED",
  };
  await writeFile(statusPath, `${JSON.stringify(status)}\n`, { mode: 0o600 });
  const harness = join(root, "harness.sh");
  await writeFile(harness, [
    "#!/bin/bash",
    "set -Eeuo pipefail",
    functionSource,
    'set +e; output="$(acquire_timeout_claim_guard "$1" "$$")"; rc=$?; set -e',
    'printf "%s\\n%s\\n" "$rc" "$output"',
    "",
  ].join("\n"), { mode: 0o700 });

  const acquired = spawnSync("/bin/bash", [harness, statusPath], { encoding: "utf8" });
  assert.equal(acquired.status, 0, acquired.stderr);
  const [acquiredRc, acquiredId] = acquired.stdout.trim().split("\n");
  assert.equal(acquiredRc, "0");
  const createdClaim = JSON.parse(await readFile(claimPath, "utf8"));
  assert.equal(createdClaim.claimId, acquiredId);
  assert.equal(createdClaim.transactionId, status.transactionId);
  assert.equal(createdClaim.requestBindingDigest, binding);
  await rm(claimPath);

  await writeFile(claimPath, `${JSON.stringify({
    schemaVersion: 1,
    claimId: "00000000-0000-4000-8000-000000000001",
    claimPath,
    transactionId: status.transactionId,
    requestBindingDigest: binding,
    pid: process.pid,
    acquiredAt: new Date().toISOString(),
  })}\n`, { mode: 0o600 });
  const active = spawnSync("/bin/bash", [harness, statusPath], { encoding: "utf8" });
  assert.equal(active.status, 0, active.stderr);
  assert.equal(active.stdout.trim(), "75");
  assert.equal(JSON.parse(await readFile(statusPath, "utf8")).state, "PREPARED");
  assert.equal(JSON.parse(await readFile(claimPath, "utf8")).pid, process.pid);
});

test("upgrade source orders predecision before cleanup and defers production approval to the worker", async () => {
  const source = await readFile(join(repositoryRoot, "scripts", "upgrade-universal-broker-v2-production.sh"), "utf8");
  const stagingPrecheck = source.indexOf("run_connector_release_driver \\\n  staging-precheck");
  const stagingActivation = source.indexOf("run_connector_release_driver \\\n  staging-activate");
  const preCutover = source.indexOf("run_connector_release_driver \\\n  pre-cutover");
  const productionPredecision = source.indexOf("run_connector_release_driver \\\n  production-predecision");
  const rollbackChallenge = source.indexOf("run_connector_release_driver \\\n  rollback-challenge");
  const cleanup = source.lastIndexOf("\ncleanup_candidate_before_cutover\n");
  const requestConstruction = source.indexOf("request={");
  const scheduling = source.indexOf('/bin/launchctl submit -l "$LABEL"');
  assert.ok(stagingPrecheck >= 0);
  assert.ok(stagingPrecheck < stagingActivation);
  assert.ok(stagingActivation < preCutover);
  assert.ok(preCutover < productionPredecision);
  assert.ok(productionPredecision < rollbackChallenge);
  assert.ok(rollbackChallenge < cleanup);
  assert.ok(cleanup < requestConstruction && requestConstruction < scheduling);
  assert.doesNotMatch(source, /run_connector_release_driver \\\n  production-approve/u);
  assert.match(source, /node --import "\$WORKER_DEPENDENCY_LOADER" "\$CONNECTOR_RELEASE_DRIVER" "\$command"/u);
  assert.doesNotMatch(
    source.slice(source.indexOf("run_connector_release_driver()"), source.indexOf("quote()")),
    /\|\|\s*true/u,
  );
});

test("owner-only evidence rendezvous rejects absent, permissive, and symlink requests", async (t) => {
  const source = await readFile(join(repositoryRoot, "scripts", "upgrade-universal-broker-v2-production.sh"), "utf8");
  const functions = source.slice(
    source.indexOf("await_owner_only_request_copy()"),
    source.indexOf("quote()"),
  );
  assert.ok(functions.startsWith("await_owner_only_request_copy()"));
  for (const scenario of ["absent", "permissive", "symlink", "valid"]) {
    await t.test(scenario, async () => {
      const root = await mkdtemp(join(await realpath(tmpdir()), `devspace-evidence-rendezvous-${scenario}-`));
      try {
        await chmod(root, 0o700);
        const sourcePath = join(root, "request.json");
        const destinationDirectory = join(root, "audit");
        const destinationPath = join(destinationDirectory, "request.json");
        await mkdir(destinationDirectory, { mode: 0o700 });
        if (scenario === "permissive") {
          await writeFile(sourcePath, '{"schemaVersion":1}\n', { mode: 0o666 });
        } else if (scenario === "symlink") {
          const target = join(root, "target.json");
          await writeFile(target, '{"schemaVersion":1}\n', { mode: 0o600 });
          await symlink(target, sourcePath);
        } else if (scenario === "valid") {
          await writeFile(sourcePath, '{"schemaVersion":1}\n', { mode: 0o600 });
        }
        const harness = join(root, "harness.sh");
        await writeFile(harness, [
          "#!/bin/bash",
          "set -Eeuo pipefail",
          "EVIDENCE_WAIT_SECONDS=1",
          functions,
          'await_owner_only_request_copy "$1" "$2" fixture',
          "",
        ].join("\n"), { mode: 0o700 });
        const result = spawnSync("/bin/bash", [harness, sourcePath, destinationPath], { encoding: "utf8" });
        if (scenario === "valid") {
          assert.equal(result.status, 0, result.stderr);
          assert.equal(await readFile(destinationPath, "utf8"), '{"schemaVersion":1}\n');
        } else {
          assert.notEqual(result.status, 0, `${scenario} request was accepted`);
          await assert.rejects(readFile(destinationPath), /ENOENT/u);
        }
      } finally {
        await rm(root, { recursive: true, force: true });
      }
    });
  }
});

test("release-driver failure exits before any scheduling continuation", async () => {
  const source = await readFile(join(repositoryRoot, "scripts", "upgrade-universal-broker-v2-production.sh"), "utf8");
  const functions = source.slice(
    source.indexOf("await_owner_only_request_copy()"),
    source.indexOf("quote()"),
  );
  const root = await mkdtemp(join(await realpath(tmpdir()), "devspace-driver-failure-gate-"));
  try {
    await chmod(root, 0o700);
    const bin = join(root, "bin");
    const audit = join(root, "audit");
    await mkdir(bin, { mode: 0o700 });
    await mkdir(audit, { mode: 0o700 });
    const request = join(root, "request.json");
    await writeFile(request, '{"schemaVersion":1}\n', { mode: 0o600 });
    await writeFile(join(bin, "node"), "#!/bin/sh\nexit 65\n", { mode: 0o700 });
    const scheduled = join(root, "scheduled");
    const harness = join(root, "harness.sh");
    await writeFile(harness, [
      "#!/bin/bash",
      "set -Eeuo pipefail",
      "EVIDENCE_WAIT_SECONDS=1",
      `PATH=${shellQuote(bin)}:$PATH`,
      'IMMUTABLE_RUNTIME_ROOT="/fixture/runtime"',
      'RUNTIME_DEPENDENCY_ROOT="/fixture/dependencies"',
      'WORKER_DEPENDENCY_LOADER="/fixture/loader.mjs"',
      'CONNECTOR_RELEASE_DRIVER="/fixture/driver.mjs"',
      functions,
      `run_connector_release_driver staging-precheck "$1" ${shellQuote(join(audit, "request.json"))} ${shellQuote(join(audit, "artifact.json"))} ${shellQuote(join(audit, "summary.json"))}`,
      `touch ${shellQuote(scheduled)}`,
      "",
    ].join("\n"), { mode: 0o700 });
    const result = spawnSync("/bin/bash", [harness, request], { encoding: "utf8" });
    assert.equal(result.status, 65, result.stderr);
    await assert.rejects(readFile(scheduled), /ENOENT/u);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("release-driver summary digest drift exits before scheduling continuation", async () => {
  const source = await readFile(join(repositoryRoot, "scripts", "upgrade-universal-broker-v2-production.sh"), "utf8");
  const functions = source.slice(
    source.indexOf("await_owner_only_request_copy()"),
    source.indexOf("quote()"),
  );
  const root = await mkdtemp(join(await realpath(tmpdir()), "devspace-driver-summary-drift-"));
  try {
    await chmod(root, 0o700);
    const bin = join(root, "bin");
    const audit = join(root, "audit");
    await mkdir(bin, { mode: 0o700 });
    await mkdir(audit, { mode: 0o700 });
    const request = join(root, "request.json");
    await writeFile(request, '{"schemaVersion":1}\n', { mode: 0o600 });
    await writeFile(join(bin, "node"), [
      "#!/bin/sh",
      'while [ "$#" -gt 0 ]; do',
      '  if [ "$1" = "--output" ]; then output="$2"; shift 2; continue; fi',
      "  shift",
      "done",
      'printf "tampered\\n" > "$output"',
      'chmod 600 "$output"',
      'printf \'{"path":"%s","sha256":"sha256:%064d","artifactDigest":"sha256:%064d","kind":"STAGING_ACTIVATION_PRECHECK"}\\n\' "$output" 0 0',
      "",
    ].join("\n"), { mode: 0o700 });
    const scheduled = join(root, "scheduled");
    const harness = join(root, "harness.sh");
    await writeFile(harness, [
      "#!/bin/bash",
      "set -Eeuo pipefail",
      "EVIDENCE_WAIT_SECONDS=1",
      `PATH=${shellQuote(bin)}:$PATH`,
      'IMMUTABLE_RUNTIME_ROOT="/fixture/runtime"',
      'RUNTIME_DEPENDENCY_ROOT="/fixture/dependencies"',
      'WORKER_DEPENDENCY_LOADER="/fixture/loader.mjs"',
      'CONNECTOR_RELEASE_DRIVER="/fixture/driver.mjs"',
      functions,
      `run_connector_release_driver staging-precheck "$1" ${shellQuote(join(audit, "request.json"))} ${shellQuote(join(audit, "artifact.json"))} ${shellQuote(join(audit, "summary.json"))}`,
      `touch ${shellQuote(scheduled)}`,
      "",
    ].join("\n"), { mode: 0o700 });
    const result = spawnSync("/bin/bash", [harness, request], { encoding: "utf8" });
    assert.notEqual(result.status, 0, "a driver summary with a foreign byte digest was accepted");
    await assert.rejects(readFile(scheduled), /ENOENT/u);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("upgrade source can construct only the exact worker-v4 connector and rollback contract", async () => {
  const source = await readFile(join(repositoryRoot, "scripts", "upgrade-universal-broker-v2-production.sh"), "utf8");
  assert.doesNotMatch(source, /["']version["']\s*:\s*3\b/u);
  assert.doesNotMatch(source, /["']candidateEvidence["']\s*:/u);
  for (const field of [
    '"version":4',
    '"version":2',
    '"requestBindingDigest"',
    '"runtimeIdentityDigest"',
    '"migrationManifestDigest"',
    '"localHealthUrl"',
    '"localReadyUrl"',
    '"rollbackHostChallenge"',
    '"cutoverProcessNames"',
    '"connectorLifecycle"',
    '"bindingDigest"',
    '"stagingActivationPrecheck"',
    '"preCutoverHostCanary"',
    '"finalization"',
    '"workerClaimPath"',
    '"manifestPath"',
    '"managementAuthorizationKeyRef"',
    '"managementNonce"',
    '"managementCorrelationId"',
    '"candidateIdentity"',
    '"oauthResource"',
    '"productionEnvironmentIdentityDigest"',
    '"productionRouteIdentityDigest"',
    '"rollbackJournalPath"',
    '"localDoctorUrl"',
    '"releaseDriver"',
    '"stagingPrecheckRequest"',
    '"stagingActivationRequest"',
    '"stagingActivationReadback"',
    '"preCutoverRequest"',
    '"productionPredecisionRequest"',
    '"productionPredecisionEnvelope"',
    '"productionPreparationRequest"',
    '"productionApprovalOutputDirectory"',
    '"rollbackChallengeRequest"',
    '"runtimeIdentityUrl"',
    '"routeIdentityUrl"',
  ]) assert.ok(source.includes(field), `missing worker-v4 request field: ${field}`);
  assert.match(source, /routeIdentityUrl":`http:\/\/127\.0\.0\.1:\$\{productionManagementPort\}\/route-identityz`/u);
  assert.match(source, /verifyConnectorRollbackHostChallenge\(/u);
  assert.match(source, /snapshotEntryMutablePaths\(entry\)/u);
  assert.match(source, /canonicalPathsOverlap\(mutablePath, controlPath\)/u);
  assert.doesNotMatch(source, /futureReceiptSha256|rollbackHostPass|caller-authored PASS/u);
  for (const snapshotId of [
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
  ]) assert.ok(source.includes(`"id":"${snapshotId}"`), `missing required mutable snapshot store: ${snapshotId}`);
});

function runtimeStatePaths(root, includePrevious) {
  return {
    DEVSPACE_NEXT_STATE_DIR: root,
    DEVSPACE_NEXT_OAUTH_STATE_DIR: join(root, "oauth"),
    DEVSPACE_NEXT_AUTHORITY_STATE_DIR: join(root, "authority"),
    DEVSPACE_NEXT_AUTHORITY_STORE: join(root, "authority", "authority.sqlite"),
    DEVSPACE_NEXT_CONNECTOR_ACTIVATION_JOURNAL: join(root, "connector-activation-journal.sqlite"),
    DEVSPACE_NEXT_LIFECYCLE_FINALIZATION_STORE: join(root, "lifecycle.sqlite"),
    DEVSPACE_NEXT_CONTEXT_STORE: join(root, "contexts.json"),
    DEVSPACE_NEXT_CONTEXT_WORKTREE_ROOT: join(root, "worktrees"),
    DEVSPACE_NEXT_PROCESS_OUTPUT_DIR: join(root, "process-output"),
    DEVSPACE_NEXT_SSH_CONTROL_DIR: join(root, "ssh-control"),
    DEVSPACE_NEXT_ARTIFACT_STAGING_DIR: join(root, "artifacts"),
    DEVSPACE_NEXT_ARTIFACT_CATALOG: join(root, "artifacts.sqlite"),
    DEVSPACE_NEXT_ARTIFACT_OBJECT_ROOT: join(root, "artifact-objects"),
    DEVSPACE_NEXT_AUDIT_SINK: join(root, "audit", "operations.jsonl"),
    DEVSPACE_NEXT_CURSOR_SIGNING_KEY_REF: join(root, "cursor-hmac-current.key"),
    DEVSPACE_NEXT_CURSOR_PREVIOUS_SIGNING_KEY_REF: includePrevious
      ? join(root, "cursor-hmac-previous.key")
      : "",
    DEVSPACE_NEXT_MANAGEMENT_AUTHORIZATION_KEY_REF: join(root, "management-authorization.key"),
  };
}

function sourceEnvironment(path, keys) {
  const script = [
    'path="$1"; shift',
    'for key in "$@"; do unset "$key"; done',
    'set -a; source "$path"; set +a',
    'for key in "$@"; do printf "%s\\0%s\\0" "$key" "${!key-}"; done',
  ].join("\n");
  const result = spawnSync("/bin/bash", ["-c", script, "_", path, ...keys], { encoding: "buffer" });
  assert.equal(result.status, 0, result.stderr.toString("utf8"));
  const fields = result.stdout.toString("utf8").split("\0");
  const output = {};
  for (let index = 0; index + 1 < fields.length; index += 2) output[fields[index]] = fields[index + 1];
  return output;
}

function assertContained(root, value, key) {
  const normalizedRoot = resolve(root);
  const normalized = resolve(value);
  const rel = relative(normalizedRoot, normalized);
  assert.ok(rel && rel !== ".." && !rel.startsWith(`..${sep}`), `${key} escaped candidate state: ${value}`);
}

function ok() {
  return { status: 0, stdout: "", stderr: "" };
}

function pm2List(name) {
  return `${JSON.stringify([{ name, pm2_env: { status: "online" } }])}\n`;
}

function shellQuote(value) {
  return `'${value.replaceAll("'", `'"'"'`)}'`;
}
