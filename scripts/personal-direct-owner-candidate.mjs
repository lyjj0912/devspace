#!/usr/bin/env node
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import {
  chmod,
  lstat,
  mkdir,
  readFile,
  realpath,
  stat,
  writeFile,
} from "node:fs/promises";
import { dirname, isAbsolute, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { materializeReleaseEnvironment } from "./lib/release-environment.mjs";
import { sourceGateEnvironment } from "./lib/source-gate-environment.mjs";
import {
  verifyPersonalReleasePackage,
  verifyPersonalReleaseRuntimeIdentity,
} from "./personal-direct-owner-release.mjs";
import { verifyPersonalHttpLive } from "./verify-personal-direct-owner-http-live.mjs";

const PROFILE = "PERSONAL_DIRECT_OWNER";

export async function deployPersonalDirectOwnerCandidate(input, adapters = {}) {
  const releasePackage = await realDirectory(input.releasePackage, "release package");
  const dependencyRoot = await realDirectory(input.dependencyRoot, "dependency root");
  const dependencyEvidence = await ownerFile(input.dependencyEvidence, "dependency evidence");
  const productionEnvironment = await ownerFile(
    input.productionEnvironment,
    "production environment",
  );
  const targetConfig = await regularFile(input.targetConfig, "target configuration");
  const routeConfig = await regularFile(input.routeConfig, "route configuration");
  const envProfileConfig = await regularFile(input.envProfileConfig, "environment profile configuration");
  const candidateEnvironment = absolute(input.candidateEnvironment, "candidate environment");
  const stateDir = absolute(input.stateDir, "candidate state directory");
  const auditDir = absolute(input.auditDir, "candidate audit directory");
  await assertAbsent(candidateEnvironment, "Candidate environment already exists");
  await assertAbsent(stateDir, "Candidate state directory already exists");
  await assertAbsent(auditDir, "Candidate audit directory already exists");
  if (inside(releasePackage, stateDir) || inside(releasePackage, auditDir)) {
    throw new Error("Candidate state and audit directories must stay outside the immutable package.");
  }
  const processName = processIdentifier(input.processName, "process name");
  const dataPort = port(input.dataPort, "data port");
  const managementPort = port(input.managementPort, "management port");
  if (dataPort === managementPort) throw new Error("Candidate data and management ports must differ.");
  const connectorName = safeIdentifier(input.connectorName, "connector name");
  const connectorInstallationEpoch = positiveInteger(
    input.connectorInstallationEpoch,
    "connector installation epoch",
  );
  const acceptanceRunId = safeIdentifier(input.acceptanceRunId, "acceptance run ID");
  const pm2 = adapters.processManager ?? new Pm2CandidateProcessManager(input.pm2Command);
  const packageVerifier = adapters.verifyPackage ?? verifyPersonalReleasePackage;
  const runtimeVerifier = adapters.verifyRuntime ?? verifyPersonalReleaseRuntimeIdentity;
  const liveVerifier = adapters.verifyLive ?? verifyPersonalHttpLive;
  const seedOauth = adapters.seedOauth ?? seedCandidateOauth;
  const waitForJson = adapters.waitForJson ?? waitForHealthyJson;
  const now = adapters.now ?? (() => Date.now());

  await mkdir(auditDir, { recursive: false, mode: 0o700 });
  await chmod(auditDir, 0o700);
  await mkdir(stateDir, { recursive: false, mode: 0o700 });
  await chmod(stateDir, 0o700);
  const audit = {
    packageVerification: join(auditDir, "PACKAGE-VERIFICATION.json"),
    oauthEvidence: join(auditDir, "CANDIDATE-OAUTH.json"),
    tokenFile: join(auditDir, "candidate-access-token.txt"),
    health: join(auditDir, "HEALTH.json"),
    readiness: join(auditDir, "READINESS.json"),
    runtimeVerification: join(auditDir, "RUNTIME-VERIFICATION.json"),
    live: join(auditDir, "HTTP-LIVE.json"),
    process: join(auditDir, "PROCESS.json"),
    deployment: join(auditDir, "DEPLOYMENT.json"),
    failure: join(auditDir, "FAILURE.json"),
  };
  let started = false;
  try {
    const packageVerification = await packageVerifier({
      packageRoot: releasePackage,
      dependencyRoot,
      dependencyEvidence,
      dependencyEvidenceSha256: input.dependencyEvidenceSha256,
      manifestSha256: input.manifestSha256,
      sourceRevision: input.sourceRevision,
      runtimeRevision: input.runtimeRevision,
    });
    requirePersonalPackagePass(packageVerification);
    await writeExclusiveJson(audit.packageVerification, packageVerification);
    const manifest = JSON.parse(await readFile(join(releasePackage, "BUILD-MANIFEST.json"), "utf8"));
    const startScript = join(releasePackage, "scripts", "start-universal-broker-v2-production.sh");
    const oauthStateDir = join(stateDir, "oauth");
    await mkdir(oauthStateDir, { recursive: true, mode: 0o700 });
    await chmod(oauthStateDir, 0o700);
    const publicBaseUrl = `http://127.0.0.1:${dataPort}`;
    const publicMcpUrl = `${publicBaseUrl}/mcp`;
    const values = candidateEnvironmentValues({
      releasePackage,
      dependencyRoot,
      dependencyEvidence,
      dependencyEvidenceSha256: packageVerification.dependency.evidenceSha256,
      manifest,
      manifestSha256: packageVerification.manifestSha256,
      startScript,
      processName,
      dataPort,
      managementPort,
      publicBaseUrl,
      stateDir,
      oauthStateDir,
      targetConfig,
      routeConfig,
      envProfileConfig,
      connectorName,
      connectorInstallationEpoch,
      acceptanceRunId,
    });
    materializeReleaseEnvironment({
      sourcePath: productionEnvironment,
      destinationPath: candidateEnvironment,
      values,
    });
    if ((await stat(candidateEnvironment)).mode & 0o077) {
      throw new Error("Candidate environment is not owner-only.");
    }
    assertPersonalCandidateEnvironment(await readFile(candidateEnvironment, "utf8"), values);

    const oauthEvidence = await seedOauth({
      stateDir: oauthStateDir,
      tokenFile: audit.tokenFile,
      evidenceFile: audit.oauthEvidence,
      canonicalName: connectorName,
      installationEpoch: connectorInstallationEpoch,
      schemaGeneration: manifest.schemaGeneration,
      resource: publicMcpUrl,
    });
    if (oauthEvidence.status !== "PASS" || oauthEvidence.readiness?.state !== "PASS") {
      throw new Error("Isolated candidate OAuth fixture did not become ready.");
    }
    if (await pm2.exists(processName)) {
      throw new Error(`Candidate PM2 process already exists: ${processName}`);
    }
    await pm2.start({
      name: processName,
      script: startScript,
      cwd: releasePackage,
      environmentFile: candidateEnvironment,
    });
    started = true;

    const health = await waitForJson(`${publicBaseUrl}/healthz`, {
      timeoutMs: input.startupTimeoutMs ?? 60_000,
      expectedStatus: 200,
    });
    await writeExclusiveJson(audit.health, health);
    const managementBaseUrl = `http://127.0.0.1:${managementPort}`;
    const readiness = await waitForJson(`${managementBaseUrl}/readyz`, {
      timeoutMs: input.startupTimeoutMs ?? 60_000,
      expectedStatus: 200,
    });
    await writeExclusiveJson(audit.readiness, readiness);
    const runtimeVerification = await runtimeVerifier({
      packageRoot: releasePackage,
      identityPath: audit.readiness,
    });
    await writeExclusiveJson(audit.runtimeVerification, runtimeVerification);

    const errorLog = await pm2.errorLogPath(processName);
    const errorLogOffset = errorLog ? await fileSizeOrZero(errorLog) : undefined;
    const live = await liveVerifier({
      dataBaseUrl: publicBaseUrl,
      managementBaseUrl,
      releasePackage,
      tokenFile: audit.tokenFile,
      auditPath: join(stateDir, "audit", "operations.jsonl"),
      disposableRoot: join(stateDir, "live-gate-disposable"),
      acceptanceRunId,
      connectorInstallationEpoch,
      connectorRotationSequence: oauthEvidence.rotationSequence,
      target: input.target ?? "local",
      ...(errorLog ? { errorLog, errorLogOffset } : {}),
    });
    await writeExclusiveJson(audit.live, live);
    const processReadback = await pm2.inspect(processName);
    verifyCandidateProcessReadback(processReadback, {
      processName,
      releasePackage,
      startScript,
    });
    await writeExclusiveJson(audit.process, processReadback);
    const deployment = {
      schemaVersion: 1,
      kind: "PERSONAL_DIRECT_OWNER_CANDIDATE_DEPLOYMENT",
      status: "CANDIDATE_READY",
      productProfile: PROFILE,
      createdAt: new Date(now()).toISOString(),
      processName,
      pid: processReadback.pid,
      releasePackage,
      dependencyRoot,
      dependencyEvidence,
      dependencyEvidenceSha256: packageVerification.dependency.evidenceSha256,
      candidateEnvironment,
      stateDir,
      auditDir,
      dataPort,
      managementPort,
      publicBaseUrl,
      sourceRevision: packageVerification.sourceRevision,
      runtimeRevision: packageVerification.runtimeRevision,
      buildDigest: packageVerification.buildDigest,
      schemaGeneration: packageVerification.schemaGeneration,
      manifestSha256: packageVerification.manifestSha256,
      sourceGateDigest: packageVerification.sourceGateDigest,
      dependencyEvidenceSha256: packageVerification.dependency.evidenceSha256,
      connectorName,
      connectorInstallationEpoch,
      acceptanceRunId,
      packageVerificationPath: audit.packageVerification,
      oauthEvidencePath: audit.oauthEvidence,
      healthPath: audit.health,
      readinessPath: audit.readiness,
      runtimeVerificationPath: audit.runtimeVerification,
      liveVerificationPath: audit.live,
      processReadbackPath: audit.process,
      rollback: {
        action: "DELETE_CANDIDATE_PROCESS_ONLY",
        processName,
        productionUntouched: true,
      },
    };
    await writeExclusiveJson(audit.deployment, deployment);
    return deployment;
  } catch (error) {
    let rollbackError;
    if (started) {
      try { await pm2.delete(processName); } catch (candidateError) { rollbackError = candidateError; }
    }
    const failure = {
      schemaVersion: 1,
      kind: "PERSONAL_DIRECT_OWNER_CANDIDATE_FAILURE",
      status: rollbackError ? "ROLLBACK_FAILED" : "ROLLED_BACK",
      failedAt: new Date(now()).toISOString(),
      processName,
      releasePackage,
      candidateEnvironment,
      stateDir,
      auditDir,
      error: boundedError(error),
      ...(rollbackError ? { rollbackError: boundedError(rollbackError) } : {}),
      productionUntouched: true,
    };
    await writeExclusiveJson(audit.failure, failure).catch(() => undefined);
    if (rollbackError) {
      throw new AggregateError([error, rollbackError], "Candidate deployment and rollback both failed.");
    }
    throw error;
  }
}

function candidateEnvironmentValues(input) {
  return {
    DEVSPACE_V2_DEPLOYMENT_MODE: "production",
    DEVSPACE_NEXT_HOST: "127.0.0.1",
    DEVSPACE_NEXT_PORT: String(input.dataPort),
    DEVSPACE_NEXT_MANAGEMENT_PORT: String(input.managementPort),
    DEVSPACE_NEXT_PUBLIC_BASE_URL: input.publicBaseUrl,
    DEVSPACE_NEXT_MCP_PATH: "/mcp",
    DEVSPACE_NEXT_STATE_DIR: input.stateDir,
    DEVSPACE_NEXT_OAUTH_STATE_DIR: input.oauthStateDir,
    DEVSPACE_NEXT_TARGETS_FILE: input.targetConfig,
    DEVSPACE_NEXT_MCP_ROUTES_FILE: input.routeConfig,
    DEVSPACE_NEXT_ENV_PROFILE_CONFIG: input.envProfileConfig,
    DEVSPACE_NEXT_SELF_MANAGEMENT_DIR: join(input.stateDir, "self-management"),
    DEVSPACE_NEXT_PM2_PROCESS_NAME: input.processName,
    DEVSPACE_NEXT_PM2_EXPECTED_SCRIPT: input.startScript,
    DEVSPACE_NEXT_SELF_RESTART_TIMEOUT_MS: "120000",
    DEVSPACE_NEXT_ALLOWED_HOSTS: "127.0.0.1,localhost",
    DEVSPACE_TRUST_PROXY: "0",
    DEVSPACE_OAUTH_OWNER_INSTANCE_ID: `candidate:${input.acceptanceRunId}`,
    DEVSPACE_RELEASE_MANIFEST: join(input.releasePackage, "BUILD-MANIFEST.json"),
    DEVSPACE_EXPECTED_RELEASE_MANIFEST_SHA256: input.manifestSha256,
    DEVSPACE_EXPECTED_SOURCE_REVISION: input.manifest.sourceRevision,
    DEVSPACE_EXPECTED_RUNTIME_REVISION: input.manifest.runtimeRevision,
    DEVSPACE_EXPECTED_BUILD_DIGEST: input.manifest.buildDigest,
    DEVSPACE_EXPECTED_SCHEMA_GENERATION: input.manifest.schemaGeneration,
    DEVSPACE_RUNTIME_PACKAGE_ROOT: input.releasePackage,
    DEVSPACE_RUNTIME_DEPENDENCY_ROOT: input.dependencyRoot,
    DEVSPACE_RUNTIME_DEPENDENCY_EVIDENCE: input.dependencyEvidence,
    DEVSPACE_EXPECTED_RUNTIME_DEPENDENCY_EVIDENCE_SHA256: input.dependencyEvidenceSha256,
    DEVSPACE_OAUTH_CANONICAL_CONNECTOR_NAME: input.connectorName,
    DEVSPACE_OAUTH_CONNECTOR_INSTALLATION_EPOCH: String(input.connectorInstallationEpoch),
    DEVSPACE_NEXT_CANONICAL_CONNECTOR_NAME: input.connectorName,
    DEVSPACE_SOURCE_REVISION: input.manifest.sourceRevision,
    DEVSPACE_RUNTIME_REVISION: input.manifest.runtimeRevision,
    DEVSPACE_BUILD_DIGEST: input.manifest.buildDigest,
    DEVSPACE_NEXT_CONTEXT_STORE: join(input.stateDir, "contexts.json"),
    DEVSPACE_NEXT_CONTEXT_WORKTREE_ROOT: join(input.stateDir, "worktrees"),
    DEVSPACE_NEXT_PROCESS_OUTPUT_DIR: join(input.stateDir, "process-output"),
    DEVSPACE_NEXT_SSH_CONTROL_DIR: join(input.stateDir, "ssh-control"),
    DEVSPACE_NEXT_ARTIFACT_STAGING_DIR: join(input.stateDir, "artifacts"),
    DEVSPACE_NEXT_ARTIFACT_CATALOG: join(input.stateDir, "artifacts.sqlite"),
    DEVSPACE_NEXT_ARTIFACT_OBJECT_ROOT: join(input.stateDir, "artifact-objects"),
    DEVSPACE_NEXT_AUDIT_SINK: join(input.stateDir, "audit", "operations.jsonl"),
    DEVSPACE_NEXT_CURSOR_SIGNING_KEY_REF: join(input.stateDir, "cursor-hmac-current.key"),
    DEVSPACE_NEXT_MANAGEMENT_AUTHORIZATION_KEY_REF: join(
      input.stateDir,
      "management-authorization.key",
    ),
    DEVSPACE_NEXT_ACCEPTANCE_RUN_ID: input.acceptanceRunId,
  };
}

export function assertPersonalCandidateEnvironment(text, expectedValues) {
  const values = parseEnvironment(text);
  for (const [key, expected] of Object.entries(expectedValues)) {
    if (values.get(key) !== shellLiteralValue(expected)) {
      throw new Error(`Candidate environment differs at ${key}.`);
    }
  }
  for (const forbidden of [
    "DEVSPACE_PERSONAL_STAGING_FIXTURE",
    "DEVSPACE_NEXT_AUTHORITY_OWNER_INSTANCE_ID",
    "DEVSPACE_NEXT_AUTHORITY_STATE_DIR",
    "DEVSPACE_NEXT_AUTHORITY_STORE",
    "DEVSPACE_NEXT_CONNECTOR_ACTIVATION_JOURNAL",
    "DEVSPACE_NEXT_LIFECYCLE_FINALIZATION_STORE",
    "DEVSPACE_NEXT_LIFECYCLE_FINALIZATION_CONTROL",
    "DEVSPACE_EXPECTED_AUTHORITY_CONTRACT_GENERATION",
    "DEVSPACE_EXPECTED_CONFIG_SCHEMA_IDENTITY",
  ]) {
    if (values.has(forbidden)) throw new Error(`Candidate environment contains retired key ${forbidden}.`);
  }
}

class Pm2CandidateProcessManager {
  constructor(command = "pm2") {
    this.command = command;
  }

  async exists(name) {
    return (await this.list()).some((item) => item.name === name);
  }

  async start(input) {
    run(this.command, [
      "start",
      input.script,
      "--name",
      input.name,
      "--interpreter",
      "/bin/bash",
      "--cwd",
      input.cwd,
      "--time",
    ], {
      ...sourceGateEnvironment(process.env),
      DEVSPACE_PRODUCTION_ENV_FILE: input.environmentFile,
    });
  }

  async delete(name) {
    run(this.command, ["delete", name], sourceGateEnvironment(process.env));
  }

  async inspect(name) {
    const match = (await this.list()).filter((item) => item.name === name);
    if (match.length !== 1) throw new Error(`Candidate PM2 readback count is ${match.length}.`);
    return match[0];
  }

  async errorLogPath(name) {
    return (await this.inspect(name)).errorLogPath;
  }

  async list() {
    const result = spawnSync(this.command, ["jlist"], {
      encoding: "utf8",
      stdio: "pipe",
      env: sourceGateEnvironment(process.env),
    });
    if (result.error) throw result.error;
    if (result.status !== 0) throw new Error(`pm2 jlist failed: ${(result.stderr ?? "").trim()}`);
    return JSON.parse(result.stdout).map((item) => ({
      name: item.name,
      pid: item.pid,
      status: item.pm2_env?.status,
      cwd: item.pm2_env?.pm_cwd,
      script: item.pm2_env?.pm_exec_path,
      errorLogPath: item.pm2_env?.pm_err_log_path,
      outputLogPath: item.pm2_env?.pm_out_log_path,
      restartCount: item.pm2_env?.restart_time,
      createdAt: item.pm2_env?.created_at,
    }));
  }
}

async function seedCandidateOauth(input) {
  const result = spawnSync(process.execPath, [
    resolve("scripts/personal-candidate-oauth-fixture.mjs"),
    "--state-dir", input.stateDir,
    "--token-file", input.tokenFile,
    "--evidence-file", input.evidenceFile,
    "--canonical-name", input.canonicalName,
    "--installation-epoch", String(input.installationEpoch),
    "--schema-generation", input.schemaGeneration,
    "--resource", input.resource,
  ], {
    cwd: process.cwd(),
    encoding: "utf8",
    stdio: "pipe",
    env: sourceGateEnvironment(process.env),
  });
  if (result.error) throw result.error;
  if (result.status !== 0) {
    throw new Error(`Candidate OAuth seeding failed: ${(result.stderr ?? result.stdout ?? "").trim()}`);
  }
  return JSON.parse(result.stdout);
}

async function waitForHealthyJson(url, options) {
  const deadline = Date.now() + options.timeoutMs;
  let lastError;
  do {
    try {
      const response = await fetch(url);
      const text = await response.text();
      if (response.status === options.expectedStatus) return JSON.parse(text);
      lastError = new Error(`${url} returned ${response.status}: ${text.slice(0, 500)}`);
    } catch (error) {
      lastError = error;
    }
    await new Promise((resolvePromise) => setTimeout(resolvePromise, 250));
  } while (Date.now() < deadline);
  throw new Error(`Candidate endpoint did not become ready: ${boundedError(lastError)}`);
}

function verifyCandidateProcessReadback(observed, expected) {
  if (observed.name !== expected.processName
    || observed.status !== "online"
    || !Number.isSafeInteger(observed.pid)
    || observed.pid <= 0
    || resolve(observed.cwd ?? "") !== expected.releasePackage
    || resolve(observed.script ?? "") !== expected.startScript) {
    throw new Error("Candidate PM2 readback does not match the verified package and process.");
  }
}

function requirePersonalPackagePass(result) {
  if (result?.status !== "PASS" || result.productProfile !== PROFILE) {
    throw new Error("Personal release package verification did not PASS.");
  }
}

function parseEnvironment(text) {
  const values = new Map();
  for (const line of text.split(/\r?\n/u)) {
    if (!line || /^\s*#/u.test(line)) continue;
    const match = /^([A-Z][A-Z0-9_]*)=(.*)$/u.exec(line);
    if (!match || values.has(match[1])) throw new Error("Candidate environment contains an invalid or duplicate key.");
    values.set(match[1], match[2]);
  }
  return values;
}

function shellLiteralValue(value) {
  return `'${String(value).replaceAll("'", `'"'"'`)}'`;
}

function run(command, args, env) {
  const result = spawnSync(command, args, { encoding: "utf8", stdio: "pipe", env });
  if (result.error) throw result.error;
  if (result.status !== 0) {
    throw new Error(`${command} ${args.join(" ")} failed: ${(result.stderr ?? result.stdout ?? "").trim()}`);
  }
}

async function writeExclusiveJson(path, value) {
  await mkdir(dirname(path), { recursive: true, mode: 0o700 });
  await writeFile(path, `${JSON.stringify(value, null, 2)}\n`, {
    encoding: "utf8",
    flag: "wx",
    mode: 0o600,
  });
  await chmod(path, 0o600);
}

async function realDirectory(value, label) {
  const path = await realpath(absolute(value, label));
  const metadata = await lstat(path);
  if (!metadata.isDirectory() || metadata.isSymbolicLink()) throw new Error(`${label} must be a real directory.`);
  return path;
}

async function regularFile(value, label) {
  const path = await realpath(absolute(value, label));
  const metadata = await lstat(path);
  if (!metadata.isFile() || metadata.isSymbolicLink()) throw new Error(`${label} must be a regular file.`);
  return path;
}

async function ownerFile(value, label) {
  const path = await regularFile(value, label);
  const metadata = await lstat(path);
  if ((metadata.mode & 0o077) !== 0) throw new Error(`${label} must be owner-only.`);
  return path;
}

function absolute(value, label) {
  if (typeof value !== "string" || !isAbsolute(value)) throw new Error(`${label} must be absolute.`);
  return resolve(value);
}

function inside(root, path) {
  const normalizedRoot = root.endsWith("/") ? root : `${root}/`;
  return path === root || path.startsWith(normalizedRoot);
}

async function assertAbsent(path, message) {
  try { await lstat(path); } catch (error) {
    if (error && typeof error === "object" && "code" in error && error.code === "ENOENT") return;
    throw error;
  }
  throw new Error(`${message}: ${path}`);
}

function safeIdentifier(value, label) {
  if (typeof value !== "string" || !/^[A-Za-z0-9][A-Za-z0-9._:@/-]{0,255}$/u.test(value)) {
    throw new Error(`${label} is invalid.`);
  }
  return value;
}

function processIdentifier(value, label) {
  if (typeof value !== "string" || !/^[A-Za-z0-9._-]{1,128}$/u.test(value)) {
    throw new Error(`${label} is invalid.`);
  }
  return value;
}

function positiveInteger(value, label) {
  const number = Number(value);
  if (!Number.isSafeInteger(number) || number <= 0) throw new Error(`${label} must be positive.`);
  return number;
}

function port(value, label) {
  const number = positiveInteger(value, label);
  if (number > 65535) throw new Error(`${label} must not exceed 65535.`);
  return number;
}

async function fileSizeOrZero(path) {
  try { return (await stat(path)).size; } catch (error) {
    if (error && typeof error === "object" && "code" in error && error.code === "ENOENT") return 0;
    throw error;
  }
}

function boundedError(error) {
  const message = error instanceof Error ? error.message : String(error);
  return message.replace(/[\r\n\0]+/gu, " ").slice(0, 2_000);
}

function parseOptions(values) {
  const result = new Map();
  for (let index = 0; index < values.length; index += 2) {
    const key = values[index];
    const value = values[index + 1];
    if (!key?.startsWith("--") || value === undefined) throw new Error("Options must use --name value pairs.");
    result.set(key.slice(2), value);
  }
  return result;
}

function required(options, key) {
  const value = options.get(key);
  if (!value) throw new Error(`--${key} is required.`);
  return value;
}

async function main() {
  const options = parseOptions(process.argv.slice(2));
  const result = await deployPersonalDirectOwnerCandidate({
    releasePackage: required(options, "release-package"),
    dependencyRoot: required(options, "dependency-root"),
    dependencyEvidence: required(options, "dependency-evidence"),
    dependencyEvidenceSha256: options.get("dependency-evidence-sha256"),
    manifestSha256: options.get("manifest-sha256"),
    sourceRevision: options.get("source-revision"),
    runtimeRevision: options.get("runtime-revision"),
    productionEnvironment: required(options, "production-environment"),
    candidateEnvironment: required(options, "candidate-environment"),
    stateDir: required(options, "state-dir"),
    auditDir: required(options, "audit-dir"),
    processName: required(options, "process-name"),
    dataPort: required(options, "data-port"),
    managementPort: required(options, "management-port"),
    connectorName: required(options, "connector-name"),
    connectorInstallationEpoch: required(options, "connector-installation-epoch"),
    acceptanceRunId: required(options, "acceptance-run-id"),
    targetConfig: required(options, "target-config"),
    routeConfig: required(options, "route-config"),
    envProfileConfig: required(options, "env-profile-config"),
    target: options.get("target") ?? "local",
    startupTimeoutMs: options.get("startup-timeout-ms")
      ? positiveInteger(options.get("startup-timeout-ms"), "startup timeout")
      : undefined,
    pm2Command: options.get("pm2-command"),
  });
  process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) await main();
