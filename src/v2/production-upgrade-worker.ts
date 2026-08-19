import { spawn, spawnSync } from "node:child_process";
import { createHash, randomUUID } from "node:crypto";
import {
  chmod,
  copyFile,
  lstat,
  mkdir,
  readdir,
  readFile,
  readlink,
  rename,
  rm,
  symlink,
  writeFile,
} from "node:fs/promises";
import { basename, delimiter, dirname, isAbsolute, join, relative, resolve, sep } from "node:path";
import { fileURLToPath } from "node:url";

export const PRODUCTION_UPGRADE_STATES = [
  "PREPARED",
  "ACCEPTED",
  "SWITCHING",
  "VERIFYING",
  "PASS",
  "ROLLING_BACK",
  "FAIL",
  "UNKNOWN",
] as const;

export type ProductionUpgradeState = (typeof PRODUCTION_UPGRADE_STATES)[number];

export const PRODUCTION_UPGRADE_FAILURE_CODES = [
  "MANIFEST_INVALID",
  "MANIFEST_MISMATCH",
  "SWITCH_FAILED",
  "RUNTIME_EQUIVALENCE_FAILED",
  "MANAGEMENT_NOT_READY",
  "RUNTIME_IDENTITY_MISMATCH",
  "PUBLIC_BOUNDARY_FAILED",
  "ROLLBACK_FAILED",
] as const;

export type ProductionUpgradeFailureCode = (typeof PRODUCTION_UPGRADE_FAILURE_CODES)[number];
export type ProductionUpgradeFailurePhase =
  | "PREFLIGHT"
  | "SWITCHING"
  | "VERIFYING"
  | "ROLLING_BACK";

export interface ProductionUpgradeFailure {
  code: ProductionUpgradeFailureCode;
  phase: ProductionUpgradeFailurePhase;
  message: string;
  retryable: boolean;
  evidence?: Record<string, unknown>;
}

export interface ProductionUpgradeRequest {
  version: 1;
  transactionId: string;
  requestedAt: string;
  delayMs: number;
  timeoutMs: number;
  pm2ProcessName: string;
  pm2Executable: string;
  gitExecutable: string;
  previous: {
    pid: number;
    cwd: string;
    script: string;
    auditTarget?: string;
  };
  next: {
    commit: string;
    sourceTree: string;
    release: string;
    script: string;
    dist: {
      files: number;
      sha256: string;
    };
    manifest: {
      path: string;
      buildDigest: string;
      runtimeRevision: string;
      schemaGeneration: string;
      authorityContractGeneration: string;
      configSchemaIdentity: string;
    };
  };
  productionEnvPath: string;
  productionEnvBackupPath: string;
  nextEnvPath: string;
  startScriptPath: string;
  startScriptBackupPath: string;
  auditDirectory: string;
  currentAuditLink: string;
  statusPath: string;
  workerLogPath: string;
  localHealthUrl: string;
  publicHealthUrl: string;
  publicMetricsUrl: string;
  publicMcpUrl: string;
  oauthMetadataUrl: string;
  expectedScopes: string[];
  launchdLabel?: string;
}

export interface ProductionUpgradeStatus extends Record<string, unknown> {
  version: 1;
  transactionId: string;
  state: ProductionUpgradeState;
  requestedAt: string;
  updatedAt: string;
  expectedDisconnect: true;
  previous: ProductionUpgradeRequest["previous"];
  next: ProductionUpgradeRequest["next"];
  workerPid?: number;
  acceptedAt?: string;
  history?: Array<{ state: ProductionUpgradeState; at: string }>;
  pidAfter?: number;
  pm2Status?: string;
  cwd?: string;
  script?: string;
  localHealthStatus?: number;
  publicHealthStatus?: number;
  publicMetricsStatus?: number;
  unauthenticatedMcpStatus?: number;
  oauthScopes?: string[];
  runtimeCommit?: string;
  runtimeSourceTree?: string;
  runtimeDist?: { files: number; sha256: string };
  manifestSha256?: string;
  manifestIdentity?: ReleaseIdentity;
  managementReadyUrl?: string;
  managementReadyStatus?: number;
  runtimeIdentity?: RuntimeIdentityEvidence;
  runtimeIdentityConfirmed?: boolean;
  configSchemaIdentity?: string;
  failure?: ProductionUpgradeFailure;
  rollback?: Record<string, unknown>;
  error?: string;
}

interface ImmutableBuildManifest extends ReleaseIdentity {
  manifestVersion: 2;
  payloadDigest: string;
  files: number;
  payloadFiles: string[];
  runtimeFiles: string[];
  createdAt: string;
  nodeVersion: string;
  platform: string;
  forbiddenArtifactScan: "PASS";
}

interface ReleaseIdentity {
  sourceRevision: string;
  runtimeRevision: string;
  buildDigest: string;
  schemaGeneration: string;
  authorityContractGeneration: string;
  configSchemaIdentity: string;
}

interface RuntimeIdentityEvidence {
  productVersion: string;
  schemaGeneration: string;
  authorityContractGeneration: string;
  configDigest: string;
  sourceRevision: string;
  runtimeRevision: string;
  buildDigest: string;
  startedAt: string;
}

interface ManifestBindingEvidence {
  manifest: ImmutableBuildManifest;
  manifestPath: string;
  manifestSha256: string;
  identity: ReleaseIdentity;
  managementReadyUrl: string;
}

class ProductionUpgradeFailureError extends Error {
  readonly failure: ProductionUpgradeFailure;

  constructor(failure: ProductionUpgradeFailure) {
    super(failure.message);
    this.name = "ProductionUpgradeFailureError";
    this.failure = failure;
  }
}

interface Pm2ProcessSnapshot {
  name?: string;
  pid?: number;
  pm2_env?: {
    status?: string;
    pm_cwd?: string;
    pm_exec_path?: string;
  };
}

const TRANSACTION_PATTERN = /^upgrade_[0-9a-f-]{36}$/u;

export async function runProductionUpgradeWorker(requestPath: string): Promise<void> {
  const request = await readRequest(requestPath);
  const acceptedAt = new Date().toISOString();
  let status: ProductionUpgradeStatus = {
    version: 1,
    transactionId: request.transactionId,
    state: "ACCEPTED",
    requestedAt: request.requestedAt,
    updatedAt: acceptedAt,
    expectedDisconnect: true,
    previous: request.previous,
    next: request.next,
    workerPid: process.pid,
    acceptedAt,
    history: [
      { state: "PREPARED", at: request.requestedAt },
      { state: "ACCEPTED", at: acceptedAt },
    ],
  };
  await writeStatus(request.statusPath, status);
  let phase: ProductionUpgradeFailurePhase = "PREFLIGHT";
  let switchAttempted = false;
  try {
    const manifestBinding = await verifyManifestBinding(request);
    await sleep(request.delayMs);
    phase = "SWITCHING";
    status = await transition(request, status, "SWITCHING");
    switchAttempted = true;
    await installFile(request.nextEnvPath, request.productionEnvPath, 0o600);
    replacePm2Process(request, request.next.script, request.next.release);
    phase = "VERIFYING";
    status = await transition(request, status, "VERIFYING");
    const evidence = await verifyNextRuntime(request, manifestBinding);

    await installStartScript(request);
    await replaceSymlink(request.currentAuditLink, request.auditDirectory);
    const passedAt = new Date().toISOString();
    status = {
      ...status,
      state: "PASS",
      updatedAt: passedAt,
      history: [...(status.history ?? []), { state: "PASS", at: passedAt }],
      ...evidence,
    };
    await writeStatus(request.statusPath, status);
  } catch (error) {
    const failure = normalizeFailure(error, phase);
    if (!switchAttempted) {
      const failedAt = new Date().toISOString();
      status = {
        ...status,
        state: "FAIL",
        updatedAt: failedAt,
        error: failure.message,
        failure,
        rollback: {
          attempted: false,
          restored: false,
          verified: false,
          outcome: "NOT_REQUIRED_SWITCH_NOT_STARTED",
        },
        history: [...(status.history ?? []), { state: "FAIL", at: failedAt }],
      };
      await writeStatus(request.statusPath, status);
      throw error;
    }
    status = await transition(request, {
      ...status,
      error: failure.message,
      failure,
    }, "ROLLING_BACK");
    const rollback = await rollbackRuntime(request);
    const terminalAt = new Date().toISOString();
    const terminalState: ProductionUpgradeState = rollback.verified === true ? "FAIL" : "UNKNOWN";
    status = {
      ...status,
      state: terminalState,
      updatedAt: terminalAt,
      error: failure.message,
      failure,
      rollback,
      history: [...(status.history ?? []), { state: terminalState, at: terminalAt }],
    };
    await writeStatus(request.statusPath, status);
    throw error;
  } finally {
    removeLaunchdJob(request.launchdLabel);
  }
}

async function verifyNextRuntime(
  request: ProductionUpgradeRequest,
  manifestBinding: ManifestBindingEvidence,
): Promise<Pick<ProductionUpgradeStatus,
  | "pidAfter"
  | "pm2Status"
  | "cwd"
  | "script"
  | "localHealthStatus"
  | "publicHealthStatus"
  | "publicMetricsStatus"
  | "unauthenticatedMcpStatus"
  | "oauthScopes"
  | "runtimeCommit"
  | "runtimeSourceTree"
  | "runtimeDist"
  | "manifestSha256"
  | "manifestIdentity"
  | "managementReadyUrl"
  | "managementReadyStatus"
  | "runtimeIdentity"
  | "runtimeIdentityConfirmed"
  | "configSchemaIdentity"
>> {
  let runtimeCommit: string;
  let runtimeSourceTree: string;
  let runtimeDist: { files: number; sha256: string };
  try {
    runtimeCommit = gitValue(request, ["-C", request.next.release, "rev-parse", "HEAD"]);
    runtimeSourceTree = gitValue(request, ["-C", request.next.release, "rev-parse", "HEAD^{tree}"]);
    runtimeDist = await directoryEvidence(join(request.next.release, "dist"));
  } catch (error) {
    throw upgradeFailure(
      "RUNTIME_EQUIVALENCE_FAILED",
      "VERIFYING",
      `Runtime source evidence could not be read: ${errorMessage(error)}`,
      false,
    );
  }
  if (runtimeCommit !== request.next.commit) {
    throw upgradeFailure(
      "RUNTIME_EQUIVALENCE_FAILED",
      "VERIFYING",
      `Runtime commit mismatch: expected ${request.next.commit}, actual ${runtimeCommit}.`,
      false,
      { expected: request.next.commit, observed: runtimeCommit },
    );
  }
  if (runtimeSourceTree !== request.next.sourceTree) {
    throw upgradeFailure(
      "RUNTIME_EQUIVALENCE_FAILED",
      "VERIFYING",
      `Runtime source tree mismatch: expected ${request.next.sourceTree}, actual ${runtimeSourceTree}.`,
      false,
      { expected: request.next.sourceTree, observed: runtimeSourceTree },
    );
  }
  if (
    runtimeDist.files !== request.next.dist.files
    || runtimeDist.sha256 !== request.next.dist.sha256
  ) {
    throw upgradeFailure(
      "RUNTIME_EQUIVALENCE_FAILED",
      "VERIFYING",
      `Runtime dist fingerprint mismatch: expected ${JSON.stringify(request.next.dist)}, actual ${JSON.stringify(runtimeDist)}.`,
      false,
      { expected: request.next.dist, observed: runtimeDist },
    );
  }
  const deadline = Date.now() + request.timeoutMs;
  let lastError = upgradeFailure(
    "MANAGEMENT_NOT_READY",
    "VERIFYING",
    "Production upgrade verification did not run.",
    true,
  );
  while (Date.now() < deadline) {
    try {
      const process = pm2Process(request);
      if (!process) {
        throw upgradeFailure(
          "MANAGEMENT_NOT_READY",
          "VERIFYING",
          `PM2 process is missing: ${request.pm2ProcessName}`,
          true,
        );
      }
      if (process.pm2_env?.status !== "online") {
        throw upgradeFailure(
          "MANAGEMENT_NOT_READY",
          "VERIFYING",
          `PM2 status is ${process.pm2_env?.status ?? "unknown"}.`,
          true,
        );
      }
      const processCwd = process.pm2_env.pm_cwd;
      const processScript = process.pm2_env.pm_exec_path;
      if (!processCwd || resolve(processCwd) !== resolve(request.next.release)) {
        throw upgradeFailure(
          "RUNTIME_IDENTITY_MISMATCH",
          "VERIFYING",
          `PM2 cwd mismatch: ${processCwd ?? "missing"}`,
          false,
        );
      }
      if (!processScript || resolve(processScript) !== resolve(request.next.script)) {
        throw upgradeFailure(
          "RUNTIME_IDENTITY_MISMATCH",
          "VERIFYING",
          `PM2 script mismatch: ${processScript ?? "missing"}`,
          false,
        );
      }
      const processPid = process.pid;
      if (typeof processPid !== "number" || !Number.isInteger(processPid) || processPid === request.previous.pid) {
        throw upgradeFailure(
          "RUNTIME_IDENTITY_MISMATCH",
          "VERIFYING",
          `PM2 PID did not change: ${processPid ?? "missing"}`,
          false,
        );
      }
      const ready = await readManagementReady(manifestBinding);
      const localHealthStatus = await httpStatus(request.localHealthUrl);
      const publicHealthStatus = await httpStatus(request.publicHealthUrl);
      const publicMetricsStatus = await httpStatus(request.publicMetricsUrl);
      const unauthenticatedMcpStatus = await httpStatus(request.publicMcpUrl, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          jsonrpc: "2.0",
          id: 1,
          method: "initialize",
          params: {
            protocolVersion: "2025-06-18",
            capabilities: {},
            clientInfo: { name: "production-upgrade-worker", version: "1" },
          },
        }),
      });
      const metadataResponse = await fetchWithTimeout(request.oauthMetadataUrl);
      const metadata = await metadataResponse.json() as { scopes_supported?: unknown };
      const oauthScopes = Array.isArray(metadata.scopes_supported)
        ? metadata.scopes_supported.filter((scope): scope is string => typeof scope === "string")
        : [];
      if (localHealthStatus !== 200) {
        throw publicBoundaryFailure(`Local health returned ${localHealthStatus}.`);
      }
      if (publicHealthStatus !== 200) {
        throw publicBoundaryFailure(`Public health returned ${publicHealthStatus}.`);
      }
      if (publicMetricsStatus !== 404) {
        throw publicBoundaryFailure(`Public metrics returned ${publicMetricsStatus}.`);
      }
      if (unauthenticatedMcpStatus !== 401) {
        throw publicBoundaryFailure(`Unauthenticated public MCP returned ${unauthenticatedMcpStatus}.`);
      }
      if (JSON.stringify(oauthScopes) !== JSON.stringify(request.expectedScopes)) {
        throw publicBoundaryFailure(`OAuth scopes mismatch: ${JSON.stringify(oauthScopes)}`);
      }
      if (oauthScopes.includes("devspace")) {
        throw publicBoundaryFailure("Legacy blanket OAuth scope remains advertised.");
      }
      const confirmedReady = await readManagementReady(manifestBinding);
      if (!sameRuntimeIdentity(ready.identity, confirmedReady.identity)) {
        throw upgradeFailure(
          "RUNTIME_IDENTITY_MISMATCH",
          "VERIFYING",
          "Private readiness runtime identity changed during production verification.",
          false,
          { first: ready.identity, confirmed: confirmedReady.identity },
        );
      }
      await assertManifestUnchanged(manifestBinding);
      return {
        pidAfter: processPid,
        pm2Status: process.pm2_env.status,
        cwd: processCwd,
        script: processScript,
        localHealthStatus,
        publicHealthStatus,
        publicMetricsStatus,
        unauthenticatedMcpStatus,
        oauthScopes,
        runtimeCommit,
        runtimeSourceTree,
        runtimeDist,
        manifestSha256: manifestBinding.manifestSha256,
        manifestIdentity: manifestBinding.identity,
        managementReadyUrl: manifestBinding.managementReadyUrl,
        managementReadyStatus: confirmedReady.status,
        runtimeIdentity: confirmedReady.identity,
        runtimeIdentityConfirmed: true,
        configSchemaIdentity: manifestBinding.identity.configSchemaIdentity,
      };
    } catch (error) {
      lastError = normalizeFailureError(error, "VERIFYING");
      const remaining = deadline - Date.now();
      if (remaining > 0) await sleep(Math.min(500, remaining));
    }
  }
  throw lastError;
}

async function verifyManifestBinding(
  request: ProductionUpgradeRequest,
): Promise<ManifestBindingEvidence> {
  const manifestPath = resolve(request.next.manifest.path);
  let manifestBytes: Buffer;
  try {
    const metadata = await lstat(manifestPath);
    if (!metadata.isFile() || metadata.isSymbolicLink()) {
      throw new Error("manifest is not a regular file");
    }
    if ((metadata.mode & 0o022) !== 0) {
      throw new Error(`manifest mode is writable by group or other: ${(metadata.mode & 0o777).toString(8)}`);
    }
    const uid = typeof process.getuid === "function" ? process.getuid() : undefined;
    if (uid !== undefined && metadata.uid !== uid) {
      throw new Error(`manifest owner uid ${metadata.uid} does not match worker uid ${uid}`);
    }
    manifestBytes = await readFile(manifestPath);
  } catch (error) {
    throw upgradeFailure(
      "MANIFEST_INVALID",
      "PREFLIGHT",
      `Immutable build manifest cannot be trusted: ${errorMessage(error)}`,
      false,
      { path: manifestPath },
    );
  }

  let parsed: unknown;
  try {
    parsed = JSON.parse(manifestBytes.toString("utf8"));
  } catch (error) {
    throw upgradeFailure(
      "MANIFEST_INVALID",
      "PREFLIGHT",
      `Immutable build manifest is not valid JSON: ${errorMessage(error)}`,
      false,
      { path: manifestPath },
    );
  }
  const manifest = validateBuildManifest(parsed, manifestPath);
  const requestIdentity = request.next.manifest;
  const exactBindings: Array<[keyof ReleaseIdentity, string, string]> = [
    ["sourceRevision", request.next.commit, manifest.sourceRevision],
    ["runtimeRevision", requestIdentity.runtimeRevision, manifest.runtimeRevision],
    ["buildDigest", requestIdentity.buildDigest, manifest.buildDigest],
    ["schemaGeneration", requestIdentity.schemaGeneration, manifest.schemaGeneration],
    [
      "authorityContractGeneration",
      requestIdentity.authorityContractGeneration,
      manifest.authorityContractGeneration,
    ],
    ["configSchemaIdentity", requestIdentity.configSchemaIdentity, manifest.configSchemaIdentity],
  ];
  for (const [field, expected, observed] of exactBindings) {
    if (expected !== observed) {
      throw upgradeFailure(
        "MANIFEST_MISMATCH",
        "PREFLIGHT",
        `Immutable manifest ${field} mismatch: expected ${expected}, observed ${observed}.`,
        false,
        { field, expected, observed, path: manifestPath },
      );
    }
  }
  if (manifest.runtimeFiles.length !== request.next.dist.files) {
    throw upgradeFailure(
      "MANIFEST_MISMATCH",
      "PREFLIGHT",
      `Immutable manifest runtime file count mismatch: expected ${request.next.dist.files}, observed ${manifest.runtimeFiles.length}.`,
      false,
      { expected: request.next.dist.files, observed: manifest.runtimeFiles.length },
    );
  }

  let runtimeBuild: { files: number; sha256: string };
  try {
    runtimeBuild = await manifestRuntimeEvidence(request.next.release, manifest.runtimeFiles);
  } catch (error) {
    if (error instanceof ProductionUpgradeFailureError) throw error;
    throw upgradeFailure(
      "MANIFEST_MISMATCH",
      "PREFLIGHT",
      `Immutable manifest runtime tree cannot be verified: ${errorMessage(error)}`,
      false,
    );
  }
  if (runtimeBuild.sha256 !== manifest.buildDigest) {
    throw upgradeFailure(
      "MANIFEST_MISMATCH",
      "PREFLIGHT",
      `Immutable manifest build digest mismatch: expected ${manifest.buildDigest}, observed ${runtimeBuild.sha256}.`,
      false,
      { expected: manifest.buildDigest, observed: runtimeBuild.sha256 },
    );
  }

  const environment = await readManagedEnvironment(request.nextEnvPath);
  assertEnvironmentBinding(environment, "DEVSPACE_RELEASE_MANIFEST", manifestPath);
  assertEnvironmentBinding(environment, "DEVSPACE_EXPECTED_SOURCE_REVISION", manifest.sourceRevision);
  assertEnvironmentBinding(environment, "DEVSPACE_EXPECTED_RUNTIME_REVISION", manifest.runtimeRevision);
  assertEnvironmentBinding(environment, "DEVSPACE_EXPECTED_BUILD_DIGEST", manifest.buildDigest);
  assertEnvironmentBinding(environment, "DEVSPACE_EXPECTED_SCHEMA_GENERATION", manifest.schemaGeneration);
  assertEnvironmentBinding(
    environment,
    "DEVSPACE_EXPECTED_AUTHORITY_CONTRACT_GENERATION",
    manifest.authorityContractGeneration,
  );
  assertEnvironmentBinding(
    environment,
    "DEVSPACE_EXPECTED_CONFIG_SCHEMA_IDENTITY",
    manifest.configSchemaIdentity,
  );
  assertEnvironmentBinding(environment, "DEVSPACE_SOURCE_REVISION", manifest.sourceRevision);
  assertEnvironmentBinding(environment, "DEVSPACE_RUNTIME_REVISION", manifest.runtimeRevision);
  assertEnvironmentBinding(environment, "DEVSPACE_BUILD_DIGEST", manifest.buildDigest);

  const managementHost = environment.DEVSPACE_NEXT_MANAGEMENT_HOST ?? "127.0.0.1";
  if (!["127.0.0.1", "::1", "localhost"].includes(managementHost)) {
    throw upgradeFailure(
      "MANIFEST_MISMATCH",
      "PREFLIGHT",
      `Next management host is not loopback-only: ${managementHost}`,
      false,
    );
  }
  const managementPort = Number(environment.DEVSPACE_NEXT_MANAGEMENT_PORT);
  if (!Number.isInteger(managementPort) || managementPort < 1 || managementPort > 65_535) {
    throw upgradeFailure(
      "MANIFEST_MISMATCH",
      "PREFLIGHT",
      `Next management port is invalid: ${environment.DEVSPACE_NEXT_MANAGEMENT_PORT ?? "missing"}`,
      false,
    );
  }
  const hostForUrl = managementHost === "::1" ? "[::1]" : managementHost;
  const identity: ReleaseIdentity = {
    sourceRevision: manifest.sourceRevision,
    runtimeRevision: manifest.runtimeRevision,
    buildDigest: manifest.buildDigest,
    schemaGeneration: manifest.schemaGeneration,
    authorityContractGeneration: manifest.authorityContractGeneration,
    configSchemaIdentity: manifest.configSchemaIdentity,
  };
  return {
    manifest,
    manifestPath,
    manifestSha256: `sha256:${createHash("sha256").update(manifestBytes).digest("hex")}`,
    identity,
    managementReadyUrl: `http://${hostForUrl}:${managementPort}/readyz`,
  };
}

async function assertManifestUnchanged(binding: ManifestBindingEvidence): Promise<void> {
  let observed: string;
  try {
    observed = `sha256:${createHash("sha256").update(await readFile(binding.manifestPath)).digest("hex")}`;
  } catch (error) {
    throw upgradeFailure(
      "MANIFEST_MISMATCH",
      "VERIFYING",
      `Immutable build manifest could not be re-read: ${errorMessage(error)}`,
      false,
      { path: binding.manifestPath },
    );
  }
  if (observed !== binding.manifestSha256) {
    throw upgradeFailure(
      "MANIFEST_MISMATCH",
      "VERIFYING",
      `Immutable build manifest changed during production switch: expected ${binding.manifestSha256}, observed ${observed}.`,
      false,
      { path: binding.manifestPath, expected: binding.manifestSha256, observed },
    );
  }
}

function validateBuildManifest(value: unknown, path: string): ImmutableBuildManifest {
  if (!isRecord(value) || value.manifestVersion !== 2) {
    throw upgradeFailure(
      "MANIFEST_INVALID",
      "PREFLIGHT",
      `Unsupported immutable build manifest version: ${path}`,
      false,
    );
  }
  const requiredText = [
    "sourceRevision",
    "runtimeRevision",
    "buildDigest",
    "payloadDigest",
    "schemaGeneration",
    "authorityContractGeneration",
    "configSchemaIdentity",
    "createdAt",
    "nodeVersion",
    "platform",
  ] as const;
  for (const field of requiredText) {
    if (typeof value[field] !== "string" || value[field].length === 0) {
      throw upgradeFailure(
        "MANIFEST_INVALID",
        "PREFLIGHT",
        `Immutable build manifest field is invalid: ${field}`,
        false,
      );
    }
  }
  for (const field of [
    "buildDigest",
    "payloadDigest",
    "schemaGeneration",
    "authorityContractGeneration",
    "configSchemaIdentity",
  ] as const) {
    if (!isSha256Digest(value[field])) {
      throw upgradeFailure(
        "MANIFEST_INVALID",
        "PREFLIGHT",
        `Immutable build manifest digest is invalid: ${field}`,
        false,
      );
    }
  }
  if (!Number.isInteger(value.files) || (value.files as number) < 1) {
    throw upgradeFailure("MANIFEST_INVALID", "PREFLIGHT", "Immutable manifest file count is invalid.", false);
  }
  if (!isSafeManifestFileList(value.payloadFiles)) {
    throw upgradeFailure("MANIFEST_INVALID", "PREFLIGHT", "Immutable manifest payload file list is invalid.", false);
  }
  const payloadFiles = value.payloadFiles;
  if (
    !isSafeManifestFileList(value.runtimeFiles)
    || value.runtimeFiles.length < 1
    || value.runtimeFiles.some((runtimePath) => (
      !runtimePath.startsWith("dist/") || !payloadFiles.includes(runtimePath)
    ))
  ) {
    throw upgradeFailure("MANIFEST_INVALID", "PREFLIGHT", "Immutable manifest runtime file list is invalid.", false);
  }
  if (payloadFiles.length !== value.files || value.forbiddenArtifactScan !== "PASS") {
    throw upgradeFailure("MANIFEST_INVALID", "PREFLIGHT", "Immutable manifest package gate is invalid.", false);
  }
  return value as unknown as ImmutableBuildManifest;
}

async function manifestRuntimeEvidence(
  releaseRoot: string,
  runtimeFiles: string[],
): Promise<{ files: number; sha256: string }> {
  const root = resolve(releaseRoot);
  const digest = createHash("sha256");
  for (const manifestPath of [...runtimeFiles].sort()) {
    const absolute = resolve(root, manifestPath);
    const contained = relative(root, absolute);
    if (
      contained === ""
      || contained === ".."
      || contained.startsWith(`..${sep}`)
      || isAbsolute(contained)
    ) {
      throw new Error(`runtime path escapes release root: ${manifestPath}`);
    }
    const metadata = await lstat(absolute);
    if (!metadata.isFile() || metadata.isSymbolicLink()) {
      throw new Error(`runtime path is not a regular file: ${manifestPath}`);
    }
    const content = await readFile(absolute);
    digest.update(manifestPath);
    digest.update("\0");
    digest.update(createHash("sha256").update(content).digest("hex"));
    digest.update("\n");
  }
  return { files: runtimeFiles.length, sha256: `sha256:${digest.digest("hex")}` };
}

async function readManagedEnvironment(path: string): Promise<Record<string, string>> {
  const tracked = new Set([
    "DEVSPACE_NEXT_MANAGEMENT_HOST",
    "DEVSPACE_NEXT_MANAGEMENT_PORT",
    "DEVSPACE_RELEASE_MANIFEST",
    "DEVSPACE_EXPECTED_SOURCE_REVISION",
    "DEVSPACE_EXPECTED_RUNTIME_REVISION",
    "DEVSPACE_EXPECTED_BUILD_DIGEST",
    "DEVSPACE_EXPECTED_SCHEMA_GENERATION",
    "DEVSPACE_EXPECTED_AUTHORITY_CONTRACT_GENERATION",
    "DEVSPACE_EXPECTED_CONFIG_SCHEMA_IDENTITY",
    "DEVSPACE_SOURCE_REVISION",
    "DEVSPACE_RUNTIME_REVISION",
    "DEVSPACE_BUILD_DIGEST",
  ]);
  let content: string;
  try {
    const metadata = await lstat(path);
    if (!metadata.isFile() || metadata.isSymbolicLink() || (metadata.mode & 0o077) !== 0) {
      throw new Error("next environment must be an owner-only regular file");
    }
    content = await readFile(path, "utf8");
  } catch (error) {
    throw upgradeFailure(
      "MANIFEST_INVALID",
      "PREFLIGHT",
      `Next production environment cannot be trusted: ${errorMessage(error)}`,
      false,
      { path },
    );
  }
  const values: Record<string, string> = {};
  for (const line of content.split(/\r?\n/u)) {
    const match = /^(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)=(.*)$/u.exec(line);
    if (!match || !tracked.has(match[1])) continue;
    const key = match[1];
    if (Object.hasOwn(values, key)) {
      throw upgradeFailure(
        "MANIFEST_INVALID",
        "PREFLIGHT",
        `Next production environment contains duplicate ${key}.`,
        false,
      );
    }
    values[key] = decodeShellWord(match[2], key);
  }
  return values;
}

function decodeShellWord(value: string, key: string): string {
  let output = "";
  let quote: "plain" | "single" | "double" = "plain";
  for (let index = 0; index < value.length; index += 1) {
    const character = value[index];
    if (quote === "single") {
      if (character === "'") quote = "plain";
      else output += character;
      continue;
    }
    if (quote === "double") {
      if (character === '"') {
        quote = "plain";
      } else if (character === "\\") {
        index += 1;
        if (index >= value.length) break;
        output += value[index];
      } else if (character === "$" || character === "`") {
        throw invalidEnvironmentWord(key);
      } else {
        output += character;
      }
      continue;
    }
    if (character === "'") {
      quote = "single";
    } else if (character === '"') {
      quote = "double";
    } else if (character === "\\") {
      index += 1;
      if (index >= value.length) break;
      output += value[index];
    } else if (/\s/u.test(character) || /[;&|<>()`$]/u.test(character)) {
      throw invalidEnvironmentWord(key);
    } else {
      output += character;
    }
  }
  if (quote !== "plain" || (value.endsWith("\\") && !value.endsWith("\\\\"))) {
    throw invalidEnvironmentWord(key);
  }
  return output;
}

function invalidEnvironmentWord(key: string): ProductionUpgradeFailureError {
  return upgradeFailure(
    "MANIFEST_INVALID",
    "PREFLIGHT",
    `Next production environment value is not a supported literal: ${key}`,
    false,
  );
}

function assertEnvironmentBinding(
  environment: Record<string, string>,
  key: string,
  expected: string,
): void {
  const observed = environment[key];
  const normalizedExpected = key === "DEVSPACE_RELEASE_MANIFEST" ? resolve(expected) : expected;
  const normalizedObserved = key === "DEVSPACE_RELEASE_MANIFEST" && observed ? resolve(observed) : observed;
  if (normalizedObserved !== normalizedExpected) {
    throw upgradeFailure(
      "MANIFEST_MISMATCH",
      "PREFLIGHT",
      `Next production environment ${key} mismatch: expected ${normalizedExpected}, observed ${normalizedObserved ?? "missing"}.`,
      false,
      { key, expected: normalizedExpected, observed: normalizedObserved ?? null },
    );
  }
}

async function readManagementReady(
  manifestBinding: ManifestBindingEvidence,
): Promise<{ status: 200; identity: RuntimeIdentityEvidence }> {
  let response: Response;
  let payload: unknown;
  try {
    response = await fetchWithTimeout(manifestBinding.managementReadyUrl);
    const body = await response.text();
    if (body.length > 64 * 1024) throw new Error("readiness payload exceeds 64 KiB");
    payload = JSON.parse(body);
  } catch (error) {
    throw upgradeFailure(
      "MANAGEMENT_NOT_READY",
      "VERIFYING",
      `Private management readiness could not be read: ${errorMessage(error)}`,
      true,
      { url: manifestBinding.managementReadyUrl },
    );
  }
  if (response.status !== 200 || !isRecord(payload) || payload.status !== "ready") {
    throw upgradeFailure(
      "MANAGEMENT_NOT_READY",
      "VERIFYING",
      `Private management readiness is not ready: HTTP ${response.status}.`,
      true,
      { url: manifestBinding.managementReadyUrl, status: response.status },
    );
  }
  if (!isRecord(payload.identity)) {
    throw upgradeFailure(
      "RUNTIME_IDENTITY_MISMATCH",
      "VERIFYING",
      "Private readiness runtime identity is missing.",
      false,
    );
  }
  const identity = payload.identity;
  for (const field of [
    "sourceRevision",
    "runtimeRevision",
    "buildDigest",
    "schemaGeneration",
    "authorityContractGeneration",
  ] as const) {
    const expected = manifestBinding.identity[field];
    const observed = identity[field];
    if (observed !== expected) {
      throw upgradeFailure(
        "RUNTIME_IDENTITY_MISMATCH",
        "VERIFYING",
        `Private readiness identity mismatch for ${field}: expected ${expected}, observed ${String(observed)}.`,
        false,
        { field, expected, observed: observed ?? null },
      );
    }
  }
  if (identity.configSchemaIdentity !== undefined
    && identity.configSchemaIdentity !== manifestBinding.identity.configSchemaIdentity) {
    throw upgradeFailure(
      "RUNTIME_IDENTITY_MISMATCH",
      "VERIFYING",
      `Private readiness identity mismatch for configSchemaIdentity: expected ${manifestBinding.identity.configSchemaIdentity}, observed ${String(identity.configSchemaIdentity)}.`,
      false,
    );
  }
  if (
    typeof identity.productVersion !== "string"
    || identity.productVersion.length === 0
    || !isSha256Digest(identity.configDigest)
    || typeof identity.startedAt !== "string"
    || !Number.isFinite(Date.parse(identity.startedAt))
  ) {
    throw upgradeFailure(
      "RUNTIME_IDENTITY_MISMATCH",
      "VERIFYING",
      "Private readiness product/config/start identity is missing or invalid.",
      false,
    );
  }
  if (
    !isRecord(payload.checks)
    || payload.checks.nonRoot !== true
    || payload.checks.authorityStore !== true
    || typeof payload.checks.canonicalConnectorName !== "string"
    || payload.checks.canonicalConnectorName.length === 0
  ) {
    throw upgradeFailure(
      "MANAGEMENT_NOT_READY",
      "VERIFYING",
      "Private readiness safety checks are incomplete.",
      true,
    );
  }
  return { status: 200, identity: identity as unknown as RuntimeIdentityEvidence };
}

function sameRuntimeIdentity(left: RuntimeIdentityEvidence, right: RuntimeIdentityEvidence): boolean {
  return [
    "productVersion",
    "schemaGeneration",
    "authorityContractGeneration",
    "configDigest",
    "sourceRevision",
    "runtimeRevision",
    "buildDigest",
    "startedAt",
  ].every((field) => (
    left[field as keyof RuntimeIdentityEvidence] === right[field as keyof RuntimeIdentityEvidence]
  ));
}

function publicBoundaryFailure(message: string): ProductionUpgradeFailureError {
  return upgradeFailure("PUBLIC_BOUNDARY_FAILED", "VERIFYING", message, true);
}

function upgradeFailure(
  code: ProductionUpgradeFailureCode,
  phase: ProductionUpgradeFailurePhase,
  message: string,
  retryable: boolean,
  evidence?: Record<string, unknown>,
): ProductionUpgradeFailureError {
  return new ProductionUpgradeFailureError({
    code,
    phase,
    message,
    retryable,
    ...(evidence ? { evidence } : {}),
  });
}

function normalizeFailureError(
  error: unknown,
  phase: ProductionUpgradeFailurePhase,
): ProductionUpgradeFailureError {
  if (error instanceof ProductionUpgradeFailureError) return error;
  const code: ProductionUpgradeFailureCode = phase === "PREFLIGHT"
    ? "MANIFEST_INVALID"
    : phase === "SWITCHING"
      ? "SWITCH_FAILED"
      : "PUBLIC_BOUNDARY_FAILED";
  return upgradeFailure(code, phase, errorMessage(error), phase === "VERIFYING");
}

function normalizeFailure(
  error: unknown,
  phase: ProductionUpgradeFailurePhase,
): ProductionUpgradeFailure {
  return normalizeFailureError(error, phase).failure;
}

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return Boolean(value) && typeof value === "object" && !Array.isArray(value);
}

function isSha256Digest(value: unknown): value is string {
  return typeof value === "string" && /^sha256:[a-f0-9]{64}$/u.test(value);
}

function isSafeManifestFileList(value: unknown): value is string[] {
  if (!Array.isArray(value) || value.length < 1 || value.some((path) => (
    typeof path !== "string"
    || path.length === 0
    || path.includes("\\")
    || path.startsWith("/")
    || path.split("/").some((segment) => segment === "" || segment === "." || segment === "..")
  ))) return false;
  return new Set(value).size === value.length;
}

function replacePm2Process(
  request: ProductionUpgradeRequest,
  script: string,
  cwd: string,
): void {
  runPm2(request, ["delete", request.pm2ProcessName], 30_000, true);
  runPm2(request, [
    "start",
    script,
    "--name",
    request.pm2ProcessName,
    "--interpreter",
    "/bin/bash",
    "--cwd",
    cwd,
    "--time",
  ], 60_000, false, productionPm2Environment(
    process.env,
    request.productionEnvPath,
  ));
  runPm2(request, ["save"], 30_000);
}

export function productionPm2Environment(
  inherited: NodeJS.ProcessEnv,
  productionEnvPath: string,
  nodeExecutable = process.execPath,
): NodeJS.ProcessEnv {
  const sanitized: NodeJS.ProcessEnv = {};
  for (const [key, value] of Object.entries(inherited)) {
    if (!key.startsWith("DEVSPACE_")) sanitized[key] = value;
  }
  sanitized.PATH = pm2ExecutablePath(inherited.PATH, nodeExecutable);
  sanitized.DEVSPACE_PRODUCTION_ENV_FILE = productionEnvPath;
  return sanitized;
}

export function pm2CommandEnvironment(
  inherited: NodeJS.ProcessEnv,
  nodeExecutable = process.execPath,
): NodeJS.ProcessEnv {
  return {
    ...inherited,
    PATH: pm2ExecutablePath(inherited.PATH, nodeExecutable),
  };
}

export function pm2WorkerCleanupEnvironment(
  inherited: NodeJS.ProcessEnv,
  nodeExecutable = process.execPath,
): NodeJS.ProcessEnv {
  const sanitized: NodeJS.ProcessEnv = {};
  for (const key of ["HOME", "USER", "LOGNAME", "TMPDIR", "LANG", "LC_ALL", "PM2_HOME"]) {
    const value = inherited[key];
    if (value) sanitized[key] = value;
  }
  sanitized.PATH = pm2ExecutablePath(inherited.PATH, nodeExecutable);
  return sanitized;
}

export function schedulePm2WorkerCleanup(
  pm2Executable: string,
  workerName: string,
  auditDirectory: string,
  delayMs = 750,
): number {
  if (!isAbsolute(pm2Executable)) {
    throw new Error(`PM2 executable must be absolute: ${pm2Executable}`);
  }
  if (!/^[A-Za-z0-9_.-]{1,128}$/u.test(workerName)) {
    throw new Error(`Invalid PM2 cleanup worker name: ${workerName}`);
  }
  if (!isAbsolute(auditDirectory)) {
    throw new Error(`PM2 cleanup audit directory must be absolute: ${auditDirectory}`);
  }
  if (!Number.isInteger(delayMs) || delayMs < 0 || delayMs > 30_000) {
    throw new Error(`Invalid PM2 cleanup delay: ${delayMs}`);
  }
  const cleanupProgram = [
    'const { spawnSync } = require("node:child_process");',
    'const { chmodSync, renameSync, writeFileSync } = require("node:fs");',
    'const { join } = require("node:path");',
    'const [pm2, workerName, auditDirectory, delayText] = process.argv.slice(1);',
    'const delay = Number(delayText);',
    'setTimeout(() => {',
    '  const run = (args) => spawnSync(pm2, args, { cwd: auditDirectory, env: process.env, encoding: "utf8", timeout: 30000 });',
    '  const deleted = run(["delete", workerName]);',
    '  const saved = run(["save"]);',
    '  const evidence = { version: 1, workerName, deleted: deleted.status === 0, deleteStatus: deleted.status, dumpSaved: saved.status === 0, saveStatus: saved.status, completedAt: new Date().toISOString() };',
    '  const evidencePath = join(auditDirectory, "scheduler-cleanup.json");',
    '  const temporary = `${evidencePath}.${process.pid}.tmp`;',
    '  writeFileSync(temporary, `${JSON.stringify(evidence, null, 2)}\\n`, { mode: 0o600 });',
    '  chmodSync(temporary, 0o600);',
    '  renameSync(temporary, evidencePath);',
    '  process.exitCode = saved.status === 0 ? 0 : 1;',
    '}, delay);',
  ].join("\n");
  const child = spawn(process.execPath, [
    "-e",
    cleanupProgram,
    pm2Executable,
    workerName,
    auditDirectory,
    String(delayMs),
  ], {
    cwd: auditDirectory,
    detached: true,
    stdio: "ignore",
    env: pm2WorkerCleanupEnvironment(process.env),
  });
  if (!child.pid) throw new Error("Failed to create detached PM2 cleanup process.");
  child.unref();
  return child.pid;
}

function pm2ExecutablePath(
  inheritedPath: string | undefined,
  nodeExecutable: string,
): string {
  if (!isAbsolute(nodeExecutable)) {
    throw new Error(`Node executable must be absolute for detached PM2 control: ${nodeExecutable}`);
  }
  const entries = [
    dirname(resolve(nodeExecutable)),
    ...(inheritedPath ?? "").split(delimiter),
  ].filter((entry) => entry.length > 0);
  return [...new Set(entries)].join(delimiter);
}

async function rollbackRuntime(request: ProductionUpgradeRequest): Promise<{
  attempted: true;
  restored: boolean;
  verified: boolean;
  outcome: "RESTORED_PREVIOUS_RUNTIME" | "RESTORATION_UNVERIFIED";
  healthStatus?: number;
  error?: string;
  failure?: ProductionUpgradeFailure;
}> {
  let restored = false;
  let healthStatus: number | undefined;
  let error: string | undefined;
  try {
    await installFile(request.productionEnvBackupPath, request.productionEnvPath, 0o600);
    replacePm2Process(request, request.previous.script, request.previous.cwd);
    await installFile(request.startScriptBackupPath, request.startScriptPath, 0o700);
    if (request.previous.auditTarget) {
      await replaceSymlink(request.currentAuditLink, request.previous.auditTarget);
    }
    const deadline = Date.now() + Math.min(request.timeoutMs, 60_000);
    while (Date.now() < deadline) {
      const process = pm2Process(request);
      if (
        process?.pm2_env?.status === "online"
        && resolve(process.pm2_env?.pm_cwd ?? "/") === resolve(request.previous.cwd)
        && resolve(process.pm2_env?.pm_exec_path ?? "/") === resolve(request.previous.script)
      ) {
        healthStatus = await httpStatus(request.localHealthUrl);
        if (healthStatus === 200) {
          restored = true;
          break;
        }
      }
      await sleep(500);
    }
    if (!restored) throw new Error("Previous production runtime did not recover before rollback timeout.");
  } catch (rollbackError) {
    error = rollbackError instanceof Error ? rollbackError.message : String(rollbackError);
  }
  const failure = error
    ? {
        code: "ROLLBACK_FAILED" as const,
        phase: "ROLLING_BACK" as const,
        message: error,
        retryable: false,
      }
    : undefined;
  return {
    attempted: true,
    restored,
    verified: restored,
    outcome: restored ? "RESTORED_PREVIOUS_RUNTIME" : "RESTORATION_UNVERIFIED",
    ...(healthStatus !== undefined ? { healthStatus } : {}),
    ...(error ? { error } : {}),
    ...(failure ? { failure } : {}),
  };
}

async function installStartScript(request: ProductionUpgradeRequest): Promise<void> {
  const content = [
    "#!/bin/bash",
    "set -euo pipefail",
    `export DEVSPACE_PRODUCTION_ENV_FILE=${shellQuote(request.productionEnvPath)}`,
    `exec ${shellQuote(request.next.script)}`,
    "",
  ].join("\n");
  const temporary = temporaryPath(request.startScriptPath);
  await writeFile(temporary, content, { mode: 0o700 });
  await rename(temporary, request.startScriptPath);
  await chmod(request.startScriptPath, 0o700);
}

function pm2Process(request: ProductionUpgradeRequest): Pm2ProcessSnapshot | undefined {
  const result = runPm2(request, ["jlist"], 30_000);
  const start = result.stdout.indexOf("[");
  if (start < 0) throw new Error(`PM2 jlist did not return JSON: ${bounded(result.stdout)}`);
  const processes = JSON.parse(result.stdout.slice(start)) as Pm2ProcessSnapshot[];
  return processes.find((candidate) => candidate.name === request.pm2ProcessName);
}

function runPm2(
  request: ProductionUpgradeRequest,
  args: string[],
  timeout: number,
  allowFailure = false,
  env?: NodeJS.ProcessEnv,
): { stdout: string; stderr: string; status: number | null } {
  const result = spawnSync(request.pm2Executable, args, {
    encoding: "utf8",
    timeout,
    env: env ?? pm2CommandEnvironment(process.env),
    cwd: request.auditDirectory,
  });
  if (result.error) throw result.error;
  if (!allowFailure && result.status !== 0) {
    throw new Error(`pm2 ${args.join(" ")} failed: ${bounded(result.stderr || result.stdout)}`);
  }
  return { stdout: result.stdout ?? "", stderr: result.stderr ?? "", status: result.status };
}

async function readRequest(path: string): Promise<ProductionUpgradeRequest> {
  const request = JSON.parse(await readFile(resolve(path), "utf8")) as ProductionUpgradeRequest;
  if (
    request?.version !== 1
    || !TRANSACTION_PATTERN.test(request.transactionId)
    || !request.pm2ProcessName
    || !request.pm2Executable
    || !request.gitExecutable
    || !request.previous?.cwd
    || !request.previous?.script
    || !request.next?.release
    || !request.next?.script
    || !/^[0-9a-f]{40,64}$/u.test(request.next?.commit ?? "")
    || !/^[0-9a-f]{40,64}$/u.test(request.next?.sourceTree ?? "")
    || !Number.isInteger(request.next?.dist?.files)
    || request.next.dist.files < 1
    || !/^[0-9a-f]{64}$/u.test(request.next?.dist?.sha256 ?? "")
    || !request.next?.manifest
    || typeof request.next.manifest.path !== "string"
    || request.next.manifest.path.length < 1
    || !isSha256Digest(request.next.manifest.buildDigest)
    || typeof request.next.manifest.runtimeRevision !== "string"
    || request.next.manifest.runtimeRevision.length < 1
    || request.next.manifest.runtimeRevision.length > 256
    || !isSha256Digest(request.next.manifest.schemaGeneration)
    || !isSha256Digest(request.next.manifest.authorityContractGeneration)
    || !isSha256Digest(request.next.manifest.configSchemaIdentity)
  ) {
    throw new Error(`Malformed production upgrade request: ${path}`);
  }
  for (const absolutePath of [
    request.pm2Executable,
    request.gitExecutable,
    request.previous.cwd,
    request.previous.script,
    request.next.release,
    request.next.script,
    request.next.manifest.path,
    request.productionEnvPath,
    request.productionEnvBackupPath,
    request.nextEnvPath,
    request.startScriptPath,
    request.startScriptBackupPath,
    request.auditDirectory,
    request.currentAuditLink,
    request.statusPath,
  ]) {
    if (!isAbsolute(absolutePath)) throw new Error(`Upgrade request path is not absolute: ${absolutePath}`);
  }
  return request;
}

async function transition(
  request: ProductionUpgradeRequest,
  status: ProductionUpgradeStatus,
  state: ProductionUpgradeState,
): Promise<ProductionUpgradeStatus> {
  const at = new Date().toISOString();
  const next = {
    ...status,
    state,
    updatedAt: at,
    history: [...(status.history ?? []), { state, at }],
  };
  await writeStatus(request.statusPath, next);
  return next;
}

function gitValue(request: ProductionUpgradeRequest, args: string[]): string {
  const result = spawnSync(request.gitExecutable, args, {
    encoding: "utf8",
    timeout: 30_000,
    cwd: request.auditDirectory,
    env: pm2CommandEnvironment(process.env),
  });
  if (result.error) throw result.error;
  if (result.status !== 0) {
    throw new Error(`git ${args.join(" ")} failed: ${bounded(result.stderr || result.stdout)}`);
  }
  return (result.stdout ?? "").trim();
}

export async function directoryEvidence(directory: string): Promise<{ files: number; sha256: string }> {
  const root = resolve(directory);
  const files: string[] = [];
  const visit = async (current: string): Promise<void> => {
    const entries = (await readdir(current, { withFileTypes: true }))
      .sort((left, right) => left.name.localeCompare(right.name));
    for (const entry of entries) {
      const path = join(current, entry.name);
      if (entry.isDirectory()) await visit(path);
      else if (entry.isFile()) files.push(path);
    }
  };
  await visit(root);
  files.sort((left, right) => relative(root, left).localeCompare(relative(root, right)));
  const digest = createHash("sha256");
  for (const path of files) {
    const rel = relative(root, path).replaceAll("\\", "/");
    const content = await readFile(path);
    digest.update(rel);
    digest.update("\0");
    digest.update(createHash("sha256").update(content).digest("hex"));
    digest.update("\n");
  }
  return { files: files.length, sha256: digest.digest("hex") };
}

async function writeStatus(path: string, value: ProductionUpgradeStatus): Promise<void> {
  await mkdir(dirname(path), { recursive: true, mode: 0o700 });
  const temporary = temporaryPath(path);
  await writeFile(temporary, `${JSON.stringify(value, null, 2)}\n`, { mode: 0o600 });
  await rename(temporary, path);
}

async function installFile(source: string, destination: string, mode: number): Promise<void> {
  const temporary = temporaryPath(destination);
  await copyFile(source, temporary);
  await chmod(temporary, mode);
  await rename(temporary, destination);
}

async function replaceSymlink(path: string, target: string): Promise<void> {
  await mkdir(dirname(path), { recursive: true, mode: 0o700 });
  const temporary = temporaryPath(path);
  await rm(temporary, { force: true, recursive: true });
  await symlink(target, temporary);
  await rename(temporary, path);
}

async function httpStatus(url: string, init?: RequestInit): Promise<number> {
  const response = await fetchWithTimeout(url, init);
  await response.body?.cancel();
  return response.status;
}

async function fetchWithTimeout(url: string, init?: RequestInit): Promise<Response> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 10_000);
  timer.unref?.();
  try {
    return await fetch(url, { ...init, redirect: "error", cache: "no-store", signal: controller.signal });
  } finally {
    clearTimeout(timer);
  }
}

function removeLaunchdJob(label: string | undefined): void {
  if (!label || process.platform !== "darwin") return;
  spawnSync("/bin/launchctl", ["remove", label], { encoding: "utf8", timeout: 5_000 });
}

function temporaryPath(path: string): string {
  return join(dirname(path), `.${basename(path)}.${process.pid}.${randomUUID()}.tmp`);
}

function shellQuote(value: string): string {
  return `'${value.replaceAll("'", `'"'"'`)}'`;
}

function sleep(milliseconds: number): Promise<void> {
  return new Promise((resolvePromise) => setTimeout(resolvePromise, milliseconds));
}

function bounded(value: string, maximum = 2_000): string {
  return value.length <= maximum ? value : `${value.slice(0, maximum)}…`;
}

const invokedPath = process.argv[1] ? resolve(process.argv[1]) : undefined;
if (invokedPath && invokedPath === fileURLToPath(import.meta.url)) {
  const requestPath = process.argv[2];
  if (!requestPath) {
    console.error("Production upgrade worker requires a request path.");
    process.exitCode = 2;
  } else {
    void runProductionUpgradeWorker(requestPath).catch((error) => {
      console.error(error instanceof Error ? error.stack ?? error.message : String(error));
      process.exitCode = 1;
    });
  }
}
