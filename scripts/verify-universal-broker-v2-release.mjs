#!/usr/bin/env node
import { createHash } from "node:crypto";
import { spawnSync } from "node:child_process";
import { existsSync, readFileSync, readdirSync, statSync } from "node:fs";
import { homedir } from "node:os";
import { relative, resolve } from "node:path";
import { createReleasePackage, verifyReleasePackage as verifyImmutableReleasePackage } from "./lib/release-artifacts.mjs";

const root = process.cwd();
const requireClean = process.argv.includes("--require-clean");
const createPackageAt = optionValue("--create-package");
const verifyPackageAt = optionValue("--verify-package");
if (createPackageAt || verifyPackageAt) {
  if (createPackageAt && verifyPackageAt) fail("Choose only one immutable package operation.");
  const sourceRevision = optionValue("--source-revision");
  const runtimeRevision = optionValue("--runtime-revision");
  const result = createPackageAt
    ? createReleasePackage({ sourceRoot: root, outputRoot: createPackageAt, sourceRevision, runtimeRevision })
    : verifyImmutableReleasePackage(verifyPackageAt, {
        expectedSourceRevision: sourceRevision,
        expectedRuntimeRevision: runtimeRevision,
      });
  console.log(JSON.stringify(result, null, 2));
  process.exit(0);
}

run("npm", ["run", "typecheck"]);
run("npm", ["run", "test"]);
run(process.execPath, ["scripts/release-finalization.test.mjs"]);
run("npm", ["audit", "--omit=dev", "--audit-level=low"]);
run("npm", ["run", "build"]);
run("npm", ["run", "v2:budget"]);
run("npm", ["run", "v2:load:quick"]);

for (const script of [
  "scripts/deploy-universal-broker-v2-production.sh",
  "scripts/cutover-universal-broker-v2-production.sh",
  "scripts/rollback-universal-broker-v2-production.sh",
  "scripts/finalize-universal-broker-v2-production.sh",
  "scripts/start-universal-broker-v2.sh",
  "scripts/start-universal-broker-v2-production.sh",
  "scripts/deploy-universal-broker-v2-pm2.sh",
  "scripts/undeploy-universal-broker-v2-pm2.sh",
  "scripts/configure-devspace-log-rotation.sh",
  "scripts/upgrade-universal-broker-v2-production.sh",
  "scripts/status-universal-broker-v2-upgrade.sh",
  "scripts/deploy-universal-broker-v2-parallel.sh",
]) {
  run("/bin/bash", ["-n", script]);
}
for (const script of [
  "scripts/verify-universal-broker-v2-live.mjs",
  "scripts/verify-universal-broker-v2-load.mjs",
  "scripts/release-artifacts.mjs",
  "scripts/finalize-universal-broker-v2.mjs",
  "scripts/finalization-live-driver.mjs",
]) {
  run(process.execPath, ["--check", script]);
}

verifyNoPrivilegeElevationSources();
verifyRuntimeNoElevationSources();
verifyOperationAuthoritySources();
verifySelfManagementSources();
verifyMetricsIsolationSources();
verifyP1OperabilitySources();
verifyDeploymentSources();
verifyReleaseArtifactSources();
verifyGranularOAuthSources();
verifyLiveVerifierSources();
verifyTestComposition();
verifyDist();
const packageEvidence = verifyPackage();
const contractEvidence = verifyContract();

if (requireClean) {
  const status = capture("git", ["status", "--porcelain=v1", "--untracked-files=all"]);
  if (status.trim()) fail(`Git tree is not clean:\n${status}`);
}

const distEvidence = treeEvidence(resolve(root, "dist"));
console.log(JSON.stringify({
  status: "PASS",
  contract: contractEvidence,
  dist: distEvidence,
  package: packageEvidence,
  cleanRequired: requireClean,
}, null, 2));

function verifyNoPrivilegeElevationSources() {
  const forbiddenPaths = [
    "privileged",
    "src/v2/privileged-client.ts",
    "src/v2/privileged-client.test.ts",
    "src/v2/remote-privileged-client.ts",
    "src/v2/remote-privileged-client.test.ts",
    "src/v2/peer-gate.test.ts",
    "src/v2/fixtures/privileged-helper.ts",
    "scripts/install-universal-broker-v2-privileged-helper.sh",
    "scripts/uninstall-universal-broker-v2-privileged-helper.sh",
    "scripts/install-universal-broker-v2-remote-helper.sh",
    "scripts/uninstall-universal-broker-v2-remote-helper.sh",
  ];
  for (const path of forbiddenPaths) {
    if (existsSync(resolve(root, path))) {
      fail(`Privilege-elevation component must not ship: ${path}`);
    }
  }
  const forbiddenPathPatterns = [
    /(^|\/)privileged(?:\/|[-.])/iu,
    /(^|\/)peer-gate(?:\.|\/|$)/iu,
    /(^|\/)(?:install|uninstall)[^/]*(?:privileged|remote)[^/]*helper/iu,
    /(^|\/)remote-privileged-client(?:\.|$)/iu,
  ];
  for (const path of ["src", "scripts", "contracts", "examples"]
    .flatMap((entry) => walkFiles(resolve(root, entry)))) {
    const relativePath = relative(root, path).replaceAll("\\", "/");
    if (forbiddenPathPatterns.some((pattern) => pattern.test(relativePath))) {
      fail(`Privilege-elevation file name must not ship: ${relativePath}`);
    }
  }
  const productionPaths = [
    "src",
    "contracts",
    "examples",
    "scripts",
    "package.json",
    "package-lock.json",
  ];
  const forbiddenPatterns = [
    { name: "administrator OAuth scope", pattern: /devspace\.admin/u },
    { name: "administrator error contract", pattern: /ADMIN_UNAVAILABLE/u },
    { name: "administrator schema value", pattern: /["']admin["']/iu },
    { name: "privilege field or input", pattern: /["']?privilege["']?\s*(?:=|:)/iu },
    { name: "sudo execution path", pattern: /\bsudo(?:\s|$|-n\b)/iu },
    { name: "privileged client", pattern: /privileged-client/iu },
    { name: "privileged helper", pattern: /privileged\s+helper/iu },
    { name: "peer-gate helper", pattern: /devspace-v2-peer-gate/iu },
    { name: "LaunchDaemon helper", pattern: /LaunchDaemon/iu },
    { name: "macOS authorization command", pattern: /with\s+administrator\s+privileges/iu },
    { name: "macOS privileged helper path", pattern: /\/Library\/PrivilegedHelperTools/iu },
    { name: "passwordless sudo configuration", pattern: /(?:\/etc\/sudoers|\bNOPASSWD\b)/iu },
    {
      name: "helper or elevation target mode",
      pattern: /\bmode\b[^\n]{0,100}(?:sudo-n|privileged|admin|elevation-helper)/iu,
    },
    {
      name: "system service privileged-helper instruction",
      pattern: /(?:systemd|launchd)[^\n]{0,120}(?:privileged|elevation|root)[^\n]{0,40}helper|(?:privileged|elevation|root)[^\n]{0,120}helper[^\n]{0,40}(?:systemd|launchd)/iu,
    },
  ];
  const allowedAbsenceTests = new Set([
    "src/v2/contracts.test.ts",
    "src/v2/targets.test.ts",
    "src/v2/authority.test.ts",
    "src/v2/no-elevation.test.ts",
  ]);
  const allowedEnforcementSources = new Set([
    "src/v2/authority-policy.ts",
    "src/v2/no-elevation.ts",
    "scripts/verify-universal-broker-v2-live.mjs",
    "scripts/lib/release-artifacts.mjs",
  ]);
  for (const path of productionPaths) {
    const absolute = resolve(root, path);
    const files = statSync(absolute).isDirectory() ? walkFiles(absolute) : [absolute];
    for (const file of files) {
      const relativePath = relative(root, file).replaceAll("\\", "/");
      if (relativePath === "scripts/verify-universal-broker-v2-release.mjs") continue;
      if (allowedEnforcementSources.has(relativePath)) continue;
      if (/\.test\.[cm]?[jt]sx?$/u.test(file) && allowedAbsenceTests.has(relativePath)) continue;
      if (statSync(file).size > 8 * 1024 * 1024) continue;
      const source = readFileSync(file, "utf8");
      for (const forbidden of forbiddenPatterns) {
        if (forbidden.pattern.test(source)) {
          fail(`Privilege-elevation marker remains in ${relative(root, file)}: ${forbidden.name}`);
        }
      }
    }
  }
  const forbiddenInstructionPatterns = [
    /\/Library\/(?:PrivilegedHelperTools|LaunchDaemons)/iu,
    /\blaunchctl\b[^\n]{0,160}(?:helper|daemon)/iu,
    /\bsystemctl\b[^\n]{0,160}(?:privileged|root|elevation)[^\n]{0,40}helper/iu,
    /(?:\/etc\/sudoers|\bNOPASSWD\b|\bsudo\s+-n\b)/iu,
    /\bosascript\b[^\n]{0,160}administrator/iu,
  ];
  for (const file of walkFiles(resolve(root, "docs"))) {
    if (statSync(file).size > 8 * 1024 * 1024) continue;
    const source = readFileSync(file, "utf8");
    for (const pattern of forbiddenInstructionPatterns) {
      if (pattern.test(source)) {
        fail(`Usable administrator-helper instruction remains in ${relative(root, file)}`);
      }
    }
  }
}

function verifyTestComposition() {
  const packageJson = JSON.parse(text("package.json"));
  const testScript = packageJson?.scripts?.test;
  if (typeof testScript !== "string" || !testScript.includes("npm run v2:test")) {
    fail("The canonical npm test gate must include the complete v2 test suite.");
  }
  if (packageJson.files?.includes("src")) {
    fail("The npm package must not include the test-bearing src tree.");
  }
  const buildConfig = JSON.parse(text("tsconfig.build.json"));
  const exclusions = Array.isArray(buildConfig.exclude) ? buildConfig.exclude : [];
  for (const required of ["src/**/*.test.ts", "src/v2/fixtures/**/*"]) {
    if (!exclusions.includes(required)) fail(`Production build exclusion is missing: ${required}`);
  }
}

function verifyGranularOAuthSources() {
  const config = text("src/v2/config.ts");
  const http = text("src/v2/http-server.ts");
  const broker = text("src/v2/server.ts");
  const deploy = text("scripts/deploy-universal-broker-v2-production.sh");
  const tests = text("src/v2/http-server.test.ts");
  for (const marker of [
    "was removed in Universal Broker v2.1",
    "UNIVERSAL_OWNER_SCOPES",
    "OAUTH_OFFLINE_ACCESS_SCOPE",
  ]) {
    if (!config.includes(marker)) fail(`Granular OAuth source is missing: ${marker}`);
  }
  for (const marker of [
    "authenticatedBrokerScopes",
    "granted.every",
    "config.oauth.scopes.includes(scope)",
  ]) {
    if (!http.includes(marker)) fail(`Granular OAuth enforcement is missing: ${marker}`);
  }
  for (const forbidden of [
    'granted.includes("devspace")',
    'scopes.includes("devspace")',
  ]) {
    if (http.includes(forbidden) || broker.includes(forbidden)) {
      fail(`Blanket legacy OAuth authority remains: ${forbidden}`);
    }
  }
  if (deploy.includes("DEVSPACE_V2_LEGACY_SCOPE_COMPATIBILITY")) {
    fail("Production deployment must not emit the removed legacy-scope compatibility flag.");
  }
  for (const marker of [
    "rejects legacy-scope tokens",
    'authenticatedBrokerScopes(["devspace"], production), undefined',
  ]) {
    if (!tests.includes(marker)) fail(`Legacy OAuth rejection test is missing: ${marker}`);
  }
}

function verifyOperationAuthoritySources() {
  const contracts = text("src/v2/contracts.ts");
  const authority = text("src/v2/authority.ts");
  const principal = text("src/v2/authority-principal.ts");
  const store = text("src/v2/authority-store.ts");
  const policy = text("src/v2/authority-policy.ts");
  const server = text("src/v2/server.ts");
  const config = text("src/v2/config.ts");
  const http = text("src/v2/http-server.ts");
  const tests = text("src/v2/authority.test.ts");
  const packageJson = JSON.parse(text("package.json"));
  for (const marker of [
    'UNIVERSAL_BROKER_VERSION = "2.1.1"',
    '"authority_preview"',
    '"authorize"',
    '"authority_status"',
    '"invalidate_authority"',
    '"release_authority"',
    '"AUTHORITY_REQUIRED"',
    '"AUTHORITY_CONSUMED"',
    "authorityId",
  ]) {
    if (!contracts.includes(marker)) fail(`Operation-authority contract is missing: ${marker}`);
  }
  for (const marker of [
    "OperationAuthorityRegistry",
    "OperationAuthorityDispatchController",
    "preview(actionsInput",
    "planFingerprint",
    "assertUniqueActionFingerprints",
    "taskInstanceId",
    "correctionEpoch",
    "maximumUses",
    "consumedUses",
    "requiredPrincipalFingerprint",
    "persistentActionKey",
    "this.requireStore().claimAction",
    "markClaimDispatched",
    "cancelClaimNotDispatched",
    "terminalizeClaim",
  ]) {
    if (!authority.includes(marker) && !server.includes(marker) && !principal.includes(marker)) {
      fail(`Operation-authority implementation is missing: ${marker}`);
    }
  }
  for (const marker of [
    "resolveAuthorityPrincipal",
    "principalKeyFingerprint",
    "ownerInstanceId",
    "AUTHENTICATION_FAILED",
  ]) {
    if (!principal.includes(marker)) fail(`Stable authority principal implementation is missing: ${marker}`);
  }
  for (const marker of [
    "authority_text_sha256",
    "principal_key_fingerprint",
    "task_instance_id",
    "owner_instance_id",
    "operation_authority_claims",
    "operation_authority_resource_fences",
    "operation_authority_resource_leases",
    "CLAIMED",
    "DISPATCHED",
    "CANCELLED_NOT_DISPATCHED",
    "UNCERTAIN",
    "PROCESS_RESTARTED",
    "synchronous = FULL",
    "claimAction(input",
    "markClaimDispatched(input",
    "cancelClaimNotDispatched(input",
    "terminalizeClaim(input",
    "incrementTaskCorrectionEpoch",
    "releaseAuthority",
  ]) {
    if (!store.includes(marker)) fail(`Durable operation-authority store is missing: ${marker}`);
  }
  for (const forbidden of [
    /\btask_id\s+text\b/iu,
    /\bauthority_text\s+text\b/iu,
    /\bscope_id\s+text\b/iu,
    /\bclient_id\s+text\b/iu,
    /\bcommand\s+text\b/iu,
    /\bpath\s+text\b/iu,
    /\barguments_json\b/iu,
    /\bcontent\s+text\b/iu,
    /\bpatch\s+text\b/iu,
    /\bcredential\s+text\b/iu,
  ]) {
    if (forbidden.test(store)) fail(`Durable authority schema stores a forbidden raw field: ${forbidden}`);
  }
  if (!config.includes("authorityStorePath") || !http.includes("storePath: config.authorityStorePath")) {
    fail("Production HTTP runtime is not wired to the dedicated durable authority store.");
  }
  for (const marker of [
    "minimumAuthorityRisk",
    "authorityActionFromToolCall",
    "commandRisk",
    "filesystemRisk",
    "mcpRisk",
  ]) {
    if (!policy.includes(marker)) fail(`Operation-risk classifier is missing: ${marker}`);
  }
  for (const marker of [
    "withOperationAuthority",
    'case "authority_preview"',
    "authority.preview",
    'case "authorize"',
    "authority.create",
    "authority.prepareDispatch",
    "dispatch.claim",
    "dispatch.markDispatched",
    "dispatch.cancelNotDispatched",
    "dispatch.complete",
  ]) {
    if (!server.includes(marker)) fail(`Operation-authority server gate is missing: ${marker}`);
  }
  for (const marker of [
    "authority preview classifies exact actions",
    "R3 authority is one-shot",
    "task-local correction invalidates Task A without invalidating Task B",
    "R0 actions cannot be wrapped",
    "verified-dead CLAIMED action recovers as cancelled and reclaimed without persisting raw payload",
    "restart after authority expiry still cancels a verified-zero CLAIMED use without replay",
    "stale overlapping workers cannot reserve the same R3 action twice",
    "atomic claim, use, and resource lease admit one writer and advance the fence after release",
    "persistent terminal SQL fault rolls back receipt and lease, then restart freezes without replay",
    "stale fencing token cannot terminalize or release the current writer",
    "correction preserves an in-flight receipt and epochs remain monotonic across workers",
  ]) {
    if (!tests.includes(marker)) fail(`Operation-authority regression test is missing: ${marker}`);
  }
  if (!packageJson.scripts?.["v2:test"]?.includes("src/v2/authority.test.ts")) {
    fail("The canonical v2 test gate omits operation-authority tests.");
  }
}

function verifyRuntimeNoElevationSources() {
  const boundary = text("src/v2/no-elevation.ts");
  const policy = text("src/v2/authority-policy.ts");
  const execution = text("src/v2/execution.ts");
  const mcpProxy = text("src/v2/mcp-proxy.ts");
  const targets = text("src/v2/targets.ts");
  const tests = text("src/v2/no-elevation.test.ts");
  const mcpTests = text("src/v2/mcp-proxy.test.ts");
  const packageJson = JSON.parse(text("package.json"));
  for (const marker of [
    "assertServiceAccountBoundary",
    "sandbox-exec",
    "authorization-right-obtain",
    "file-mode #o4000",
    "file-mode #o2000",
    "setpriv --no-new-privs",
    "S-1-16-(12288|16384)",
    "internalExecutionSpec",
    "verifyLocalGuiScript",
    "scriptSha256",
    "GUI node source hash changed",
  ]) {
    if (!boundary.includes(marker)) fail(`Runtime no-elevation boundary is missing: ${marker}`);
  }
  for (const marker of [
    "assertNoElevationCommand",
    "containsElevationCommand",
    "structuralCommandRisk",
    "EXEC_RISK_CLASSIFIER_GENERATION",
    "ELEVATION_BLOCKED",
  ]) {
    if (!policy.includes(marker)) fail(`No-elevation command policy is missing: ${marker}`);
  }
  for (const marker of [
    "assertInternalExecutionCommand",
    "internalExecutionSpec",
    "wrapLocalUserOnlyExecution",
    "posixRemoteUserOnlyRunner",
    "windowsNonElevatedPrelude",
    "Internal execution policies cannot load an environment profile",
  ]) {
    if (!execution.includes(marker)) fail(`Execution plane no-elevation wiring is missing: ${marker}`);
  }
  for (const marker of [
    "wrapLocalUserOnlyExecution",
    "posixRemoteUserOnlyRunner",
    '"mcp"',
  ]) {
    if (!mcpProxy.includes(marker)) fail(`Downstream MCP no-elevation wiring is missing: ${marker}`);
  }
  if (!mcpTests.includes("local stdio MCP routes inherit the runtime no-elevation boundary")) {
    fail("Downstream MCP no-elevation regression test is missing.");
  }
  if (mcpProxy.includes('wrapLocalUserOnlyExecution(localTarget.platform, direct, "gui")')
      || mcpProxy.includes('posixRemoteUserOnlyRunner(\n      target.platform,\n      "sh",\n      shellQuote(remoteCommand),\n      "gui"')) {
    fail("Downstream MCP incorrectly reuses the exact GUI execution policy.");
  }
  for (const marker of [
    "probeLocalUserAccountBoundary",
    "setpriv_boundary=1",
    "sandbox_boundary=1",
    "blocked-elevated-token",
  ]) {
    if (!targets.includes(marker)) fail(`Target no-elevation probe is missing: ${marker}`);
  }
  for (const marker of [
    "blocks sudo at the kernel sandbox boundary",
    "rejects set-id executables generically",
    "denies Authorization Services acquisition",
  ]) {
    if (!tests.includes(marker)) fail(`Runtime no-elevation regression test is missing: ${marker}`);
  }
  for (const marker of [
    "ordinary AppleScript remains usable while administrator AppleScript fails closed",
    "exact GUI internal execution accepts only the bound owner script and argument grammar",
    "exact GUI internal execution fails closed on path, hash, mode, symlink, shell, and argument drift",
    "MCP provider children remain in the generic no-elevation wrapper",
    "__DEVSPACE_TEST_COMPLETED__:0",
    "__DEVSPACE_TEST_COMPLETED__:78",
    'executable: "/usr/bin/osascript"',
    "with administrator privileges",
  ]) {
    if (!tests.includes(marker)) fail(`macOS AppleScript boundary regression test is missing: ${marker}`);
  }
  if (!packageJson.scripts?.["v2:test"]?.includes("src/v2/no-elevation.test.ts")) {
    fail("The canonical v2 test gate omits no-elevation tests.");
  }
  if (!text("src/v2/execution.test.ts").includes("internal GUI execution cannot combine its exact contract with an environment profile")) {
    fail("The internal GUI environment-profile denial regression test is missing.");
  }
  if (boundary.includes("`exec ${exactCommand}`")) {
    fail("Exact remote GUI execution replaces the SSH completion-marker shell.");
  }
  for (const marker of [
    "const exactScript = [",
    "return `(${exactScript})`",
  ]) {
    if (!boundary.includes(marker)) fail(`Exact remote GUI subshell framing is missing: ${marker}`);
  }
  const guiSource = text("src/v2/gui.ts");
  for (const marker of [
    'internalPolicy: { kind: "gui", scriptPath, scriptSha256: this.sourceSha256 }',
    "sourceSha256",
    "expectedSha256",
    "ensureInstalled",
  ]) {
    if (!guiSource.includes(marker)) fail(`The built-in GUI node integrity wiring is missing: ${marker}`);
  }
}

function verifySelfManagementSources() {
  const contracts = text("src/v2/contracts.ts");
  const service = text("src/v2/self-management.ts");
  const worker = text("src/v2/self-management-worker.ts");
  const upgradeWorker = text("src/v2/production-upgrade-worker.ts");
  const cleanupMonitor = text("src/v2/production-upgrade-cleanup-monitor.ts");
  const upgrade = text("scripts/upgrade-universal-broker-v2-production.sh");
  const upgradeStatus = text("scripts/status-universal-broker-v2-upgrade.sh");
  const server = text("src/v2/server.ts");
  const start = text("scripts/start-universal-broker-v2-production.sh");
  const startup = text("scripts/start-universal-broker-v2.sh");
  const deploy = text("scripts/deploy-universal-broker-v2-production.sh");
  const tests = text("src/v2/self-management.test.ts");
  const upgradeTests = text("src/v2/production-upgrade-worker.test.ts");
  const packageJson = JSON.parse(text("package.json"));
  for (const marker of ["restart_broker", "restart_status", "transactionId", "delayMs"]) {
    if (!contracts.includes(marker)) fail(`Self-management contract is missing: ${marker}`);
  }
  for (const marker of [
    "UniversalSelfManagementService",
    "WAITING_FOR_RESPONSE",
    "expectedDisconnect",
    "launchDetachedRestartWorker",
    "staleRecovered",
  ]) {
    if (!service.includes(marker)) fail(`Durable restart service is missing: ${marker}`);
  }
  for (const marker of [
    'runPm2(request, ["restart"',
    'runPm2(request, ["save"]',
    "pidBefore",
    "pidAfter",
    "localHealthStatus",
    "publicHealthStatus",
  ]) {
    if (!worker.includes(marker)) fail(`Detached restart worker is missing: ${marker}`);
  }
  for (const marker of [
    'typed.operation === "restart_broker"',
    'typed.operation === "restart_status"',
    "selfManagement.requestRestart",
    "selfManagement.status",
  ]) {
    if (!server.includes(marker)) fail(`Self-management MCP wiring is missing: ${marker}`);
  }
  if (!start.includes("DEVSPACE_NEXT_PM2_EXPECTED_SCRIPT")) {
    fail("Production start script does not bind the expected PM2 script for restart verification.");
  }
  for (const marker of [
    "compgen -A variable DEVSPACE_",
    'unset "$variable"',
    "expected_script_fallback",
  ]) {
    if (!startup.includes(marker)) fail(`Authoritative startup environment isolation is missing: ${marker}`);
  }
  for (const marker of [
    "DEVSPACE_NEXT_SELF_MANAGEMENT_DIR",
    "DEVSPACE_NEXT_PM2_PROCESS_NAME",
    "DEVSPACE_NEXT_SELF_RESTART_TIMEOUT_MS",
  ]) {
    if (!deploy.includes(marker)) fail(`Production deploy source is missing self-management config: ${marker}`);
  }
  if (!upgrade.includes("run_pm2_with_environment_file")) {
    fail("Production upgrade candidate launch does not sanitize inherited DevSpace environment variables.");
  }
  for (const marker of [
    "stale transactions fail closed",
    "changes PM2 PID",
  ]) {
    if (!tests.includes(marker)) fail(`Self-management regression test is missing: ${marker}`);
  }
  if (!packageJson.scripts?.["v2:test"]?.includes("src/v2/self-management.test.ts")) {
    fail("The canonical v2 test gate omits self-management tests.");
  }
  if (!upgradeWorker.includes("productionPm2Environment")) {
    fail("Production upgrade worker does not sanitize inherited DevSpace environment variables.");
  }
  for (const marker of [
    "pm2CommandEnvironment",
    "pm2ExecutablePath",
    "dirname(resolve(nodeExecutable))",
    "env: env ?? pm2CommandEnvironment(process.env)",
  ]) {
    if (!upgradeWorker.includes(marker)) fail(`Detached PM2 Node-path continuity is missing: ${marker}`);
  }
  if (!upgradeTests.includes("drop inherited DevSpace runtime state")) {
    fail("Production upgrade environment isolation regression test is missing.");
  }
  if (!upgradeTests.includes("every detached PM2 command can resolve the worker Node executable")) {
    fail("Detached PM2 Node-path continuity regression test is missing.");
  }
  if (!upgradeTests.includes("runs an env-node shebang under a minimal launchd PATH")) {
    fail("Detached PM2 env-node shebang regression test is missing.");
  }
  if (!packageJson.scripts?.["v2:test"]?.includes("src/v2/startup-environment.test.ts")) {
    fail("The canonical v2 test gate omits startup environment isolation tests.");
  }
  for (const marker of [
    "PRODUCTION_UPGRADE_STATES",
    '"ACCEPTED"',
    "ROLLING_BACK",
    '"UNKNOWN"',
    "replacePm2Process",
    "verifyNextRuntime",
    "directoryEvidence",
    "runtimeCommit",
    "runtimeSourceTree",
    "runtimeDist",
    "publicMetricsStatus",
    "unauthenticatedMcpStatus",
    "rollbackRuntime",
    "schedulePm2WorkerCleanup",
    "pm2WorkerCleanupEnvironment",
    "scheduler-cleanup.json",
  ]) {
    if (!upgradeWorker.includes(marker)) fail(`Production upgrade worker is missing: ${marker}`);
  }
  for (const marker of [
    "runPm2UpgradeCleanupMonitor",
    "TERMINAL_STATES",
    "scheduler-cleanup.json",
    'runPm2(options, ["delete", options.workerName]',
    'runPm2(options, ["save"]',
    "dumpWorkerResidue",
  ]) {
    if (!cleanupMonitor.includes(marker)) fail(`Production upgrade cleanup monitor is missing: ${marker}`);
  }
  for (const marker of [
    "npm run release:verify -- --require-clean",
    "DEVSPACE_V2_LOAD_SSH_TARGET",
    "SKIP_COMPANY_GATES=0",
    "SKIP_COMPANY_CHROME_GATE=0",
    "--skip-company-gates",
    "--skip-company-chrome-gate",
    "full-load-company-skipped.json",
    "LIVE_ARGUMENTS+=(--skip-company-gates)",
    "LIVE_ARGUMENTS+=(--skip-company-chrome-gate)",
    "candidate-live.json",
    "full-load-real-",
    "DEVSPACE_V2_LOAD_REQUIRE_REAL_SSH=1",
    "cleanup_on_exit",
    "worktree remove --force",
    "pm2-before.json",
    "production.env.before",
    "DEVSPACE_NEXT_OAUTH_STATE_DIR",
    "CANDIDATE_OAUTH_DATABASE",
    "WINDOWS_LIVE_TARGET",
    "--windows-live-target",
    "LIVE_ARGUMENTS",
    "PRODUCTION_OAUTH_DATABASE",
    "Managed Universal Broker v2.1 runtime values",
    "DEVSPACE_V2_LEGACY_SCOPE_COMPATIBILITY",
    "oauth-before.sqlite",
    "launchctl submit",
    "production-upgrade-worker-cli.js",
    "DEVSPACE_UPGRADE_SCHEDULER=pm2",
    "DEVSPACE_UPGRADE_PM2_WORKER_NAME",
    "--no-autorestart",
    "scheduler.json",
    "production-upgrade-cleanup-monitor.js",
    "scheduler-cleanup.log",
    "cleanupMonitorPid",
    "/usr/bin/nohup",
    "Detached upgrade scheduler did not claim the transaction.",
    "SOURCE_TREE",
    "DIST_EVIDENCE",
    '"gitExecutable":git_executable',
    '"history":[{"state":"PREPARED"',
  ]) {
    if (!upgrade.includes(marker)) fail(`Production upgrade transaction is missing: ${marker}`);
  }
  if (!upgradeStatus.includes("transactionId")) {
    fail("Production upgrade status reader does not resolve transaction IDs.");
  }
  for (const marker of [
    "commits canonical pointers only after verification",
    "rolls back env, process, start path, and audit link",
    "records UNKNOWN when rollback cannot establish the previous runtime",
    "acceptedAt",
    "PM2 fallback worker schedules credential-free terminal cleanup",
    "external PM2 cleanup monitor persists dump state",
  ]) {
    if (!upgradeTests.includes(marker)) fail(`Production upgrade regression test is missing: ${marker}`);
  }
  if (!packageJson.scripts?.["v2:test"]?.includes("src/v2/production-upgrade-worker.test.ts")) {
    fail("The canonical v2 test gate omits production-upgrade worker tests.");
  }
  if (packageJson.scripts?.["upgrade:v2"] !== "bash scripts/upgrade-universal-broker-v2-production.sh") {
    fail("The canonical production upgrade command is missing.");
  }
}

function verifyMetricsIsolationSources() {
  const http = text("src/v2/http-server.ts");
  const tests = text("src/v2/http-server.test.ts");
  for (const marker of [
    "const managementApp = express()",
    "managementApp.get(config.readyPath",
    "managementApp.get(config.metricsPath",
    "managementApp,",
  ]) {
    if (!http.includes(marker)) fail(`Metrics isolation source is missing: ${marker}`);
  }
  for (const marker of [
    "const managementServer = running.managementApp.listen",
    "await requestStatus(`${origin}${config.metricsPath}`",
    "const localMetrics = await fetch(`${managementOrigin}${config.metricsPath}`)",
    "assert.equal(localMetrics.status, 200)",
    "const readiness = await fetch(`${managementOrigin}${config.readyPath}`)",
  ]) {
    if (!tests.includes(marker)) fail(`Management-plane isolation regression test is missing: ${marker}`);
  }
}

function verifyP1OperabilitySources() {
  const contracts = text("src/v2/contracts.ts");
  const authority = text("src/v2/authority.ts");
  const server = text("src/v2/server.ts");
  const targets = text("src/v2/targets.ts");
  const execution = text("src/v2/execution.ts");
  const filesystem = text("src/v2/filesystem.ts");
  const doctor = text("src/v2/doctor.ts");
  const http = text("src/v2/http-server.ts");
  const authorityTests = text("src/v2/authority.test.ts");
  const targetTests = text("src/v2/targets.test.ts");
  const executionTests = text("src/v2/execution.test.ts");
  const filesystemTests = text("src/v2/filesystem.test.ts");
  const httpTests = text("src/v2/http-server.test.ts");
  const live = text("scripts/verify-universal-broker-v2-live.mjs");
  const load = text("scripts/verify-universal-broker-v2-load.mjs");
  const planPath = resolve(root, "docs/UNIVERSAL_BROKER_V2_1_P1_PLAN.md");
  if (!existsSync(planPath)) fail("The authoritative v2.1 P1 plan is missing.");

  for (const marker of [
    '"authority_preview"',
    "refresh: z.boolean().optional()",
    "Use context.authority_preview",
  ]) {
    if (!contracts.includes(marker)) fail(`P1 contract marker is missing: ${marker}`);
  }
  for (const marker of [
    "preview(actionsInput",
    "planFingerprint",
    "authorityActionCount",
    "r0ActionCount",
  ]) {
    if (!authority.includes(marker)) fail(`P1 authority preview implementation is missing: ${marker}`);
  }
  for (const marker of [
    'case "authority_preview"',
    "authority.preview",
    "normalizeRequestedAuthorityActions",
    "requireAuthorityPlanningInputScopes",
    "requireAuthorityPlanningScopes",
    "targets.resolveWithGeneration(targetId ?? selector)",
    "assertTargetGeneration(requestMeta, binding.generation",
    "targets.probe(binding.target.id, { refresh })",
  ]) {
    if (!server.includes(marker)) fail(`P1 server wiring is missing: ${marker}`);
  }
  for (const marker of [
    "probePosixSshPty",
    "probeWindowsSshPty",
    "probeSftp",
    "cachedObservation",
    "probeInFlight",
    "probeCoalesced",
    "probeCacheHits",
    "capabilityProbes",
    'cache: "hit" | "miss" | "shared"',
  ]) {
    if (!targets.includes(marker)) fail(`P1 target capability implementation is missing: ${marker}`);
  }
  if (targets.includes("not_run_phase_2")) {
    fail("A stale phase placeholder remains in target capability evidence.");
  }
  if (!execution.includes("assertCachedExecutionCapability")) {
    fail("Execution does not use fresh cached capability evidence before impossible dispatch.");
  }
  if (!filesystem.includes("assertCachedSftpCapability")) {
    fail("Filesystem transfer does not use fresh cached SFTP evidence before dispatch.");
  }
  for (const marker of [
    "targetProbeStats",
    "mapWithConcurrency",
    "devspace_authority_previews",
    "devspace_target_probe_cache_hits",
    "devspace_target_probe_coalesced",
    "devspace_target_probe_average_duration_ms",
  ]) {
    if (!doctor.includes(marker) && !http.includes(marker)) {
      fail(`P1 operability telemetry is missing: ${marker}`);
    }
  }
  for (const [source, markers, label] of [
    [authorityTests, ["authority preview classifies exact actions", "Duplicate exact authority actions"], "authority"],
    [targetTests, ["POSIX SSH probes verify PTY and SFTP", "concurrent probes for one generation share", "Linux SSH PTY probe rechecks no-new-privileges", "SSH capability probes fail independently"], "target"],
    [executionTests, ["fresh cached target evidence blocks impossible PTY dispatch"], "execution"],
    [filesystemTests, ["fresh cached SFTP denial fails before transfer dispatch"], "filesystem"],
    [httpTests, ["authority-preview-scope-test", "devspace_authority_previews 0", "devspace_target_probe_cache_hits 0", "devspace_target_probe_coalesced 0"], "HTTP metrics and scope"],
  ]) {
    for (const marker of markers) {
      if (!source.includes(marker)) fail(`P1 ${label} regression test is missing: ${marker}`);
    }
  }
  for (const marker of [
    'operation: "authority_preview"',
    "refresh: true",
    "company-pty-ok",
    "authority preview unexpectedly created its remote fixture path",
  ]) {
    if (!live.includes(marker)) fail(`P1 live verifier marker is missing: ${marker}`);
  }
  for (const marker of [
    "DEVSPACE_V2_LOAD_REQUIRE_REAL_SSH",
    "capabilityProbe",
    "executionPtyCanary",
    "missingCapabilities",
  ]) {
    if (!load.includes(marker)) fail(`P1 load gate marker is missing: ${marker}`);
  }
}

function verifyLiveVerifierSources() {
  const live = text("scripts/verify-universal-broker-v2-live.mjs");
  const deploy = text("scripts/deploy-universal-broker-v2-production.sh");
  for (const marker of [
    'baseUrl: "http://127.0.0.1:7677"',
    'mcpPath: "/mcp-next"',
    'healthPath: "/healthz-next"',
    "/.local/share/devspace/universal-broker-v2/devspace.sqlite",
    'createHash("sha256").update(token).digest("base64url")',
    "discoverTokenResource(mcpUrl, options.tokenResource)",
    "metadata?.resource",
    "JSON.stringify(userScopes)",
    '"offline_access"',
    "fileMustExist: true",
    "prepareExactAuthority",
    'operation: "authority_preview"',
    "authorityPreview.authorityActionCount",
    "refresh: true",
    "capabilities?.pty === true",
    "capabilities?.sftp === true",
    "company-pty-ok",
    "windowsTarget: undefined",
    "No explicit Windows live target was supplied.",
    "callReadOnlyMcpWhenReady",
    "readOnlyHint === true",
    "destructiveHint !== true",
    'callWithAuthority(client, "mcp", args, ["R2"])',
    "allowedRisks.includes(requiredRisk)",
    "AUTHORITY_ACTION_MISMATCH",
    "AUTHORITY_PRINCIPAL_MISMATCH",
    "AUTHORITY_CONSUMED",
    "AUTHORITY_STALE",
    "crossTransportAccepted",
    "crossClientRejected",
    "sameClientTransport",
    "foreignClient",
    "sessions must be 2..20",
    "skipCompanyGates: false",
    "skipCompanyChromeGate: false",
    'argument === "--skip-company-gates"',
    'argument === "--skip-company-chrome-gate"',
    "Explicit --skip-company-gates deployment option.",
    "documented Chrome 150+ default-profile permission-proxy incompatibility",
    "companyGateSkipped: options.skipCompanyGates",
    "ELEVATION_BLOCKED",
    "runtimeElevationBlocked",
  ]) {
    if (!live.includes(marker)) fail(`The live verifier user-only parallel contract is missing: ${marker}`);
  }
  for (const forbidden of [
    "templateDatabasePath",
    "--template-database",
    "production OAuth database",
    'JSON.stringify(["devspace"',
    '  "devspace",',
  ]) {
    if (live.includes(forbidden)) fail(`The live verifier retains a legacy OAuth dependency: ${forbidden}`);
  }
  if (deploy.includes("--template-database")) {
    fail("The production live-verifier invocation retains a removed template-database option.");
  }
}

function verifyDeploymentSources() {
  const deploy = text("scripts/deploy-universal-broker-v2-production.sh");
  const cutover = text("scripts/cutover-universal-broker-v2-production.sh");
  const rollback = text("scripts/rollback-universal-broker-v2-production.sh");
  const finalize = text("scripts/finalize-universal-broker-v2-production.sh");
  for (const marker of [
    "PHASE9_EVIDENCE",
    "freshChatGptSessions",
    "npm run release:verify -- --require-clean",
    "DEVSPACE_V2_LOAD_SSH_TARGET",
    "devspace-v2-production",
    "switch_public_route",
    "live-canaries.local.json",
    "live-canaries.public.json",
    "rollback-drill-to-legacy",
    "CUTOVER_PASS",
    "productionConnectorReconnectPending",
  ]) {
    if (!deploy.includes(marker)) fail(`Production deployment source is missing: ${marker}`);
  }
  for (const forbidden of [
    "serve-v2",
    "secrets.token_urlsafe",
    "oauthAccessTokensRevoked",
    "oldOwnerTokenSha256",
  ]) {
    if (deploy.includes(forbidden)) fail(`Production cutover performs forbidden finalization work: ${forbidden}`);
  }
  if (!cutover.includes("deploy-universal-broker-v2-production.sh")) {
    fail("cutover:v2 is not a thin wrapper around the canonical deployment transaction.");
  }
  for (const marker of [
    "route.json",
    "devspace.sqlite.before",
    "switch_legacy_route",
    "ROLLBACK_PASS",
  ]) {
    if (!rollback.includes(marker)) fail(`Production rollback source is missing: ${marker}`);
  }
  for (const marker of [
    "prepare|seal",
    "finalize-universal-broker-v2.mjs",
    "--evidence",
    "--driver",
    "interrupt-after-action",
    "driver is intentionally unreachable until seal",
  ]) {
    if (!finalize.includes(marker)) fail(`Production finalizer source is missing: ${marker}`);
  }
  const finalizationState = text("scripts/lib/finalization-state.mjs");
  for (const marker of [
    "PREPARED",
    "POST_ROTATION_VERIFIED",
    "APPLYING",
    "Completed destructive stage drifted and will not be repeated",
    "Stale token family cannot seal",
    "FINAL_PASS",
    "SHA256SUMS",
  ]) {
    if (!finalizationState.includes(marker)) fail(`Finalization state machine source is missing: ${marker}`);
  }
}

function verifyReleaseArtifactSources() {
  const artifacts = text("scripts/lib/release-artifacts.mjs");
  for (const marker of [
    "BUILD-MANIFEST.json",
    "SBOM.spdx.json",
    "SBOM.cyclonedx.json",
    "SBOM.json",
    "SHA256SUMS",
    "config/config.schema.json",
    "payloadDigest",
    "verifyRuntimeTree",
  ]) {
    if (!artifacts.includes(marker)) fail(`Immutable release artifact source is missing: ${marker}`);
  }
}

function verifyDist() {
  for (const path of [
    "dist/cli.js",
    "dist/v2/server.js",
    "dist/v2/http-server.js",
    "dist/v2/runtime-contract-identity.js",
    "dist/v2/remote-windows-filesystem-helper.js",
    "dist/v2/authority.js",
    "dist/v2/authority-store.js",
    "dist/v2/no-elevation.js",
    "dist/v2/self-management.js",
    "dist/v2/self-management-worker.js",
    "dist/v2/production-upgrade-worker.js",
    "dist/v2/production-upgrade-worker-cli.js",
    "dist/v2/production-upgrade-cleanup-monitor.js",
    "dist/v2/doctor.js",
  ]) {
    if (!existsSync(resolve(root, path))) fail(`Missing build output: ${path}`);
  }
  const forbidden = walkFiles(resolve(root, "dist")).filter((path) =>
    /(^|\/)(fixtures?|test|tests|privileged)(\/|$)|\.test\.|canary|peer-gate|privileged-client|(?:install|uninstall)[^/]*(?:privileged|remote)[^/]*helper/i
      .test(relative(root, path).replaceAll("\\", "/"))
  );
  if (forbidden.length) fail(`Production dist contains test-only files: ${forbidden.join(", ")}`);
}

function verifyPackage() {
  const result = spawnSync("npm", ["pack", "--dry-run", "--json"], {
    cwd: root,
    encoding: "utf8",
    maxBuffer: 64 * 1024 * 1024,
    timeout: 5 * 60_000,
  });
  if (result.status !== 0) fail(`npm pack failed:\n${result.stderr}`);
  const item = JSON.parse(result.stdout)[0];
  const files = item.files.map((entry) => entry.path).sort();
  const forbidden = files.filter((path) =>
    /(^|\/)(src|fixtures?|test|tests|privileged|preservation|tmp|temp|scratch|canary|backup)(\/|$)|\.test\.|peer-gate|privileged-client|(?:install|uninstall)[^/]*(?:privileged|remote)[^/]*helper|\.orig$|\.rej$|\.bak$|\.patch$|\.log$/i.test(path)
  );
  const required = [
    "config/config.schema.json",
    "contracts/capabilities.schema.json",
    "contracts/errors.schema.json",
    "contracts/mcp-risk-policy.schema.json",
    "contracts/mcp-routes.schema.json",
    "contracts/targets.schema.json",
    "contracts/tools-v2.schema.json",
    "docs/UNIVERSAL_BROKER_V2_1_P1_PLAN.md",
    "scripts/deploy-universal-broker-v2-production.sh",
    "scripts/cutover-universal-broker-v2-production.sh",
    "scripts/rollback-universal-broker-v2-production.sh",
    "scripts/finalize-universal-broker-v2-production.sh",
    "scripts/start-universal-broker-v2.sh",
    "scripts/start-universal-broker-v2-production.sh",
    "scripts/deploy-universal-broker-v2-pm2.sh",
    "scripts/undeploy-universal-broker-v2-pm2.sh",
    "scripts/upgrade-universal-broker-v2-production.sh",
    "scripts/status-universal-broker-v2-upgrade.sh",
    "scripts/deploy-universal-broker-v2-parallel.sh",
    "scripts/release-artifacts.mjs",
    "scripts/lib/release-artifacts.mjs",
    "scripts/lib/finalization-state.mjs",
    "scripts/lib/owner-instance-id.mjs",
    "scripts/finalize-universal-broker-v2.mjs",
    "scripts/finalization-live-driver.mjs",
    "scripts/ensure-owner-instance-id.mjs",
    "scripts/verify-universal-broker-v2-live.mjs",
  ];
  const missing = required.filter((path) => !files.includes(path));
  if (forbidden.length || missing.length) {
    fail(`Invalid npm package boundary: ${JSON.stringify({ forbidden, missing })}`);
  }
  verifySecretBoundary(files);
  return {
    files: files.length,
    size: item.size,
    unpackedSize: item.unpackedSize,
    shasum: item.shasum,
    integrity: item.integrity,
  };
}

function verifySecretBoundary(files) {
  const exactSecrets = collectRuntimeSecrets();
  const patterns = [
    { name: "PEM private key", pattern: /-----BEGIN (?:[A-Z0-9 ]+ )?PRIVATE KEY-----/u },
    { name: "AWS access key", pattern: /\b(?:AKIA|ASIA)[A-Z0-9]{16}\b/u },
    { name: "GitHub token", pattern: /\b(?:gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{50,})\b/u },
    { name: "Slack token", pattern: /\bxox[baprs]-[A-Za-z0-9-]{20,}\b/u },
    { name: "OpenAI-style secret", pattern: /\bsk-[A-Za-z0-9_-]{32,}\b/u },
    { name: "Google API key", pattern: /\bAIza[0-9A-Za-z_-]{35}\b/u },
  ];
  for (const relativePath of files) {
    const absolutePath = resolve(root, relativePath);
    if (!existsSync(absolutePath) || statSync(absolutePath).size > 8 * 1024 * 1024) continue;
    const content = readFileSync(absolutePath);
    if (content.includes(0)) continue;
    const value = content.toString("utf8");
    for (const entry of patterns) {
      if (entry.pattern.test(value)) {
        fail(`Packaged file contains a ${entry.name}: ${relativePath}`);
      }
    }
    for (const secret of exactSecrets) {
      if (value.includes(secret)) {
        fail(`Packaged file contains a live runtime credential: ${relativePath}`);
      }
    }
  }
}

function collectRuntimeSecrets() {
  const values = new Set();
  for (const [name, value] of Object.entries(process.env)) {
    if (!/(?:TOKEN|SECRET|PASSWORD|CREDENTIAL|PRIVATE_KEY|API_KEY|AUTH)/iu.test(name)) continue;
    if (typeof value === "string" && value.length >= 16) values.add(value);
  }
  const authPath = resolve(homedir(), ".devspace", "auth.json");
  if (existsSync(authPath)) {
    try {
      collectSecretValues(JSON.parse(readFileSync(authPath, "utf8")), values);
    } catch {
      fail(`Unable to parse the owner credential file for secret scanning: ${authPath}`);
    }
  }
  return [...values];
}

function collectSecretValues(value, output, key = "") {
  if (typeof value === "string") {
    if (/(?:TOKEN|SECRET|PASSWORD|CREDENTIAL|PRIVATE_KEY|API_KEY|AUTH)/iu.test(key)
      && value.length >= 16) {
      output.add(value);
    }
    return;
  }
  if (Array.isArray(value)) {
    for (const entry of value) collectSecretValues(entry, output, key);
    return;
  }
  if (!value || typeof value !== "object") return;
  for (const [childKey, childValue] of Object.entries(value)) {
    collectSecretValues(childValue, output, childKey);
  }
}

function verifyContract() {
  const packageJson = JSON.parse(text("package.json"));
  if (packageJson.version !== "1.0.8") {
    fail(`Unexpected package version: ${packageJson.version}`);
  }
  const output = capture(process.execPath, ["--input-type=module", "-e", [
    "import { UNIVERSAL_BROKER_VERSION, UNIVERSAL_TOOL_NAMES } from './dist/v2/contracts.js';",
    "console.log(JSON.stringify({version:UNIVERSAL_BROKER_VERSION,tools:UNIVERSAL_TOOL_NAMES}));",
  ].join("")]);
  const value = JSON.parse(output.trim());
  const expected = ["target", "context", "fs", "exec", "process", "mcp", "artifact", "gui"];
  if (value.version !== "2.1.1" || JSON.stringify(value.tools) !== JSON.stringify(expected)) {
    fail(`Unexpected broker contract: ${output}`);
  }
  return value;
}

function treeEvidence(directory) {
  const files = walkFiles(directory).sort((left, right) => relative(directory, left).localeCompare(relative(directory, right)));
  const digest = createHash("sha256");
  for (const path of files) {
    const rel = relative(directory, path).replaceAll("\\", "/");
    const content = readFileSync(path);
    digest.update(rel);
    digest.update("\0");
    digest.update(createHash("sha256").update(content).digest("hex"));
    digest.update("\n");
  }
  return { files: files.length, sha256: digest.digest("hex") };
}

function walkFiles(directory) {
  if (!existsSync(directory)) return [];
  const output = [];
  for (const entry of readdirSync(directory)) {
    const path = resolve(directory, entry);
    const metadata = statSync(path);
    if (metadata.isDirectory()) output.push(...walkFiles(path));
    else if (metadata.isFile()) output.push(path);
  }
  return output;
}

function text(path) {
  return readFileSync(resolve(root, path), "utf8");
}

function capture(command, args) {
  const result = spawnSync(command, args, {
    cwd: root,
    encoding: "utf8",
    maxBuffer: 64 * 1024 * 1024,
    timeout: 5 * 60_000,
  });
  if (result.status !== 0) fail(`${command} ${args.join(" ")} failed:\n${result.stdout}\n${result.stderr}`);
  return result.stdout;
}

function run(command, args) {
  const result = spawnSync(command, args, {
    cwd: root,
    stdio: "inherit",
    env: process.env,
    timeout: 15 * 60_000,
  });
  if (result.status !== 0) process.exit(result.status ?? 1);
}

function fail(message) {
  console.error(message);
  process.exit(1);
}

function optionValue(name) {
  const index = process.argv.indexOf(name);
  if (index < 0) return undefined;
  const value = process.argv[index + 1];
  if (!value || value.startsWith("--")) fail(`${name} requires a value.`);
  return value;
}
