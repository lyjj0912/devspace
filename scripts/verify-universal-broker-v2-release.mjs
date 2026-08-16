#!/usr/bin/env node
import { createHash } from "node:crypto";
import { spawnSync } from "node:child_process";
import { existsSync, readFileSync, readdirSync, statSync } from "node:fs";
import { homedir } from "node:os";
import { relative, resolve } from "node:path";

const root = process.cwd();
const requireClean = process.argv.includes("--require-clean");

run("npm", ["run", "typecheck"]);
run("npm", ["run", "test"]);
run("npm", ["run", "build"]);
run("npm", ["run", "v2:budget"]);

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
]) {
  run("/bin/bash", ["-n", script]);
}
for (const script of [
  "scripts/verify-universal-broker-v2-live.mjs",
  "scripts/verify-universal-broker-v2-load.mjs",
]) {
  run(process.execPath, ["--check", script]);
}

verifyNoPrivilegeElevationSources();
verifyDeploymentSources();
verifyOAuthCompatibilitySources();
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
  ]);
  for (const path of productionPaths) {
    const absolute = resolve(root, path);
    const files = statSync(absolute).isDirectory() ? walkFiles(absolute) : [absolute];
    for (const file of files) {
      const relativePath = relative(root, file).replaceAll("\\", "/");
      if (relativePath === "scripts/verify-universal-broker-v2-release.mjs") continue;
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

function verifyOAuthCompatibilitySources() {
  const config = text("src/v2/config.ts");
  const http = text("src/v2/http-server.ts");
  const broker = text("src/v2/server.ts");
  const deploy = text("scripts/deploy-universal-broker-v2-production.sh");
  for (const marker of [
    "DEVSPACE_V2_LEGACY_SCOPE_COMPATIBILITY",
    'deploymentMode === "production"',
    "legacyScopeCompatibility",
  ]) {
    if (!config.includes(marker)) fail(`Production OAuth compatibility config is missing: ${marker}`);
  }
  for (const marker of ["authenticatedBrokerScopes", 'granted.includes("devspace")']) {
    if (!http.includes(marker)) fail(`Production OAuth compatibility path is missing: ${marker}`);
  }
  if (broker.includes('scopes.includes("devspace")')) {
    fail("The generic tool authorization layer must not grant blanket legacy scope authority.");
  }
  if (!deploy.includes("DEVSPACE_V2_LEGACY_SCOPE_COMPATIBILITY")) {
    fail("The cutover environment must state the temporary legacy scope contract explicitly.");
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
    "fileMustExist: true",
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
    "production-reconnect",
    "post-rotation",
    "keepClientId",
    "ownerCredentialRotated",
    "DELETE FROM oauth_access_tokens",
    "DELETE FROM oauth_refresh_tokens",
    "DELETE FROM oauth_clients",
    "legacyConnectorRemoved",
    "legacyRuntimeRemoved",
    "FINAL_PASS",
  ]) {
    if (!finalize.includes(marker)) fail(`Production finalizer source is missing: ${marker}`);
  }
}

function verifyDist() {
  for (const path of [
    "dist/cli.js",
    "dist/v2/server.js",
    "dist/v2/http-server.js",
    "dist/v2/remote-windows-filesystem-helper.js",
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
    "scripts/deploy-universal-broker-v2-production.sh",
    "scripts/cutover-universal-broker-v2-production.sh",
    "scripts/rollback-universal-broker-v2-production.sh",
    "scripts/finalize-universal-broker-v2-production.sh",
    "scripts/start-universal-broker-v2.sh",
    "scripts/start-universal-broker-v2-production.sh",
    "scripts/deploy-universal-broker-v2-pm2.sh",
    "scripts/undeploy-universal-broker-v2-pm2.sh",
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
  const output = capture(process.execPath, ["--input-type=module", "-e", [
    "import { UNIVERSAL_BROKER_VERSION, UNIVERSAL_TOOL_NAMES } from './dist/v2/contracts.js';",
    "console.log(JSON.stringify({version:UNIVERSAL_BROKER_VERSION,tools:UNIVERSAL_TOOL_NAMES}));",
  ].join("")]);
  const value = JSON.parse(output.trim());
  const expected = ["target", "context", "fs", "exec", "process", "mcp", "artifact", "gui"];
  if (value.version !== "2.0.0" || JSON.stringify(value.tools) !== JSON.stringify(expected)) {
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
