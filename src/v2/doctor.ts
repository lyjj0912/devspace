import { execFile } from "node:child_process";
import { createHash } from "node:crypto";
import { lstat } from "node:fs/promises";
import { join } from "node:path";
import { promisify } from "node:util";
import type { ServerConfig } from "../config.js";
import { buildCapabilityContract } from "./build-capabilities.js";
import { inspectUniversalBrokerBudgets } from "./budgets.js";
import { loadUniversalBrokerNextConfig } from "./config.js";
import { UniversalMcpRouteRegistry } from "./mcp-routes.js";
import { UniversalEnvProfileRegistry } from "./env-profiles.js";
import { baseMutableSqliteStoreRequirements } from "./migration-registry.js";
import { createRuntimeIdentity } from "./runtime-identity.js";
import { TargetRegistry } from "./targets.js";

const execFileAsync = promisify(execFile);

export type DeepDoctorCheckState = "PASS" | "FAIL" | "UNKNOWN";

export interface DeepDoctorCheckObservation {
  state: DeepDoctorCheckState;
  summary?: string;
  evidence?: Record<string, unknown>;
}

export interface DeepDoctorCheckContext {
  readonly namespace: string;
  readonly correlationId: string;
  readonly signal: AbortSignal;
  readonly deadlineAt: number;
}

export interface DeepDoctorCheck {
  id: string;
  timeoutMs?: number;
  check(
    context: DeepDoctorCheckContext,
  ): DeepDoctorCheckObservation | Promise<DeepDoctorCheckObservation>;
}

export interface DeepDoctorCleanupReceipt {
  state: "CLEANED" | "FAILED";
  receiptDigest: string;
  error?: string;
}

export interface DeepDoctorLifecycleContext {
  readonly correlationId: string;
  readonly namespace?: string;
  readonly signal: AbortSignal;
  readonly deadlineAt: number;
}

export interface DeepDoctorIsolation {
  namespace: string;
  cleanup(context: DeepDoctorLifecycleContext): Promise<DeepDoctorCleanupReceipt>;
}

export interface BoundedDeepDoctorOptions {
  checks: readonly DeepDoctorCheck[];
  createIsolation(context: DeepDoctorLifecycleContext): Promise<DeepDoctorIsolation>;
  maximumDurationMs?: number;
  cleanupReserveMs?: number;
  now?: () => number;
}

export interface DeepDoctorReport {
  status: DeepDoctorCheckState;
  correlationId: string;
  namespace: string;
  startedAt: string;
  completedAt: string;
  durationMs: number;
  maximumDurationMs: number;
  checks: Array<DeepDoctorCheckObservation & { id: string; durationMs: number }>;
  cleanup: DeepDoctorCleanupReceipt;
}

const DEEP_DOCTOR_ID_PATTERN = /^[a-z][a-z0-9_]{1,63}$/u;
const SHA256_DIGEST_PATTERN = /^sha256:[a-f0-9]{64}$/u;

/** Bounded, management-authorized deep-doctor executor with mandatory isolation cleanup. */
export class BoundedDeepDoctor {
  private readonly checks: readonly DeepDoctorCheck[];
  private readonly createIsolation: (
    context: DeepDoctorLifecycleContext,
  ) => Promise<DeepDoctorIsolation>;
  private readonly maximumDurationMs: number;
  private readonly cleanupReserveMs: number;
  private readonly now: () => number;

  constructor(options: BoundedDeepDoctorOptions) {
    if (options.checks.length === 0) {
      throw new Error("Deep doctor requires at least one bounded check.");
    }
    if (typeof options.createIsolation !== "function") {
      throw new Error("Deep doctor isolation factory is missing.");
    }
    const identifiers = new Set<string>();
    this.checks = Object.freeze(options.checks.map((check) => {
      if (!DEEP_DOCTOR_ID_PATTERN.test(check.id)) throw new Error(`Invalid deep doctor check id: ${check.id}`);
      if (identifiers.has(check.id)) throw new Error(`Duplicate deep doctor check: ${check.id}`);
      if (typeof check.check !== "function") throw new Error(`Deep doctor check ${check.id} is missing.`);
      identifiers.add(check.id);
      return Object.freeze({ ...check });
    }));
    if (this.checks.length > 64) throw new Error("Deep doctor accepts at most 64 checks.");
    this.maximumDurationMs = doctorInteger(
      options.maximumDurationMs,
      30_000,
      100,
      30_000,
      "maximumDurationMs",
    );
    this.cleanupReserveMs = doctorInteger(
      options.cleanupReserveMs,
      Math.min(5_000, Math.floor(this.maximumDurationMs / 3)),
      10,
      this.maximumDurationMs - 1,
      "cleanupReserveMs",
    );
    this.createIsolation = options.createIsolation;
    this.now = options.now ?? Date.now;
  }

  async run(input: { authorized: boolean; correlationId: string }): Promise<DeepDoctorReport> {
    if (input.authorized !== true) {
      throw new Error("Deep doctor requires management authorization.");
    }
    const correlationId = doctorSafeText(input.correlationId, "correlationId", 256);
    const startedAtMs = this.now();
    const startedAt = new Date(startedAtMs).toISOString();
    const checkDeadline = startedAtMs + this.maximumDurationMs - this.cleanupReserveMs;
    const overallDeadline = startedAtMs + this.maximumDurationMs;
    const checks: DeepDoctorReport["checks"] = [];
    let isolation: DeepDoctorIsolation | undefined;
    let namespace = "UNAVAILABLE";
    let cleanup: DeepDoctorCleanupReceipt | undefined;

    try {
      const isolationController = new AbortController();
      isolation = await boundedDoctorCall(
        () => this.createIsolation(Object.freeze({
          correlationId,
          signal: isolationController.signal,
          deadlineAt: checkDeadline,
        })),
        Math.max(1, checkDeadline - this.now()),
        "deep doctor isolation creation",
        isolationController,
      );
      namespace = doctorSafeText(isolation.namespace, "namespace", 256);
      for (const check of this.checks) {
        const remaining = checkDeadline - this.now();
        if (remaining <= 0) {
          checks.push({
            id: check.id,
            state: "UNKNOWN",
            summary: "Deep doctor check budget was exhausted.",
            durationMs: 0,
          });
          continue;
        }
        const timeoutMs = Math.min(
          check.timeoutMs === undefined
            ? remaining
            : doctorInteger(check.timeoutMs, undefined, 1, this.maximumDurationMs, `${check.id}.timeoutMs`),
          remaining,
        );
        const checkStartedAt = this.now();
        const controller = new AbortController();
        try {
          const observation = await boundedDoctorCall(
            () => check.check(Object.freeze({
              namespace,
              correlationId,
              signal: controller.signal,
              deadlineAt: checkStartedAt + timeoutMs,
            })),
            timeoutMs,
            `deep doctor check ${check.id}`,
            controller,
          );
          assertDoctorObservation(check.id, observation);
          checks.push({
            id: check.id,
            state: observation.state,
            ...(observation.summary ? { summary: doctorBounded(observation.summary) } : {}),
            ...(observation.evidence ? { evidence: doctorSanitize(observation.evidence) } : {}),
            durationMs: Math.max(0, this.now() - checkStartedAt),
          });
        } catch (error) {
          checks.push({
            id: check.id,
            state: "UNKNOWN",
            summary: doctorBounded(errorMessage(error)),
            durationMs: Math.max(0, this.now() - checkStartedAt),
          });
        }
      }
    } catch (error) {
      checks.push({
        id: "isolation",
        state: "UNKNOWN",
        summary: doctorBounded(errorMessage(error)),
        durationMs: Math.max(0, this.now() - startedAtMs),
      });
    } finally {
      if (isolation) {
        try {
          const cleanupController = new AbortController();
          const observed = await boundedDoctorCall(
            () => isolation!.cleanup(Object.freeze({
              correlationId,
              namespace,
              signal: cleanupController.signal,
              deadlineAt: overallDeadline,
            })),
            Math.max(1, overallDeadline - this.now()),
            "deep doctor cleanup",
            cleanupController,
          );
          if (!SHA256_DIGEST_PATTERN.test(observed.receiptDigest)) {
            throw new Error("Deep doctor cleanup receipt digest is invalid.");
          }
          if (!["CLEANED", "FAILED"].includes(observed.state)) {
            throw new Error("Deep doctor cleanup receipt state is invalid.");
          }
          cleanup = {
            state: observed.state,
            receiptDigest: observed.receiptDigest,
            ...(observed.error ? { error: doctorBounded(observed.error) } : {}),
          };
        } catch (error) {
          cleanup = failedCleanupReceipt(namespace, error);
        }
      } else {
        cleanup = failedCleanupReceipt(namespace, new Error("Isolation was not created."));
      }
    }

    const completedAtMs = this.now();
    const anyUnknown = checks.some((check) => check.state === "UNKNOWN") || cleanup.state !== "CLEANED";
    const anyFail = checks.some((check) => check.state === "FAIL");
    return {
      status: anyUnknown ? "UNKNOWN" : anyFail ? "FAIL" : "PASS",
      correlationId,
      namespace,
      startedAt,
      completedAt: new Date(completedAtMs).toISOString(),
      durationMs: Math.max(0, completedAtMs - startedAtMs),
      maximumDurationMs: this.maximumDurationMs,
      checks,
      cleanup,
    };
  }
}

export async function collectUniversalBrokerDoctor(
  baseConfig: ServerConfig,
  env: NodeJS.ProcessEnv = process.env,
): Promise<Record<string, unknown>> {
  const config = loadUniversalBrokerNextConfig(baseConfig, env);
  const targets = new TargetRegistry({
    configPath: config.targetConfigPath,
  });
  const routes = new UniversalMcpRouteRegistry(config.mcpRouteConfigPath);
  const envProfiles = new UniversalEnvProfileRegistry({ configPath: config.envProfileConfigPath });
  const [targetSnapshot, routeSnapshot, environmentProfiles, budgets, sourceCommit] = await Promise.all([
    targets.inspect(),
    routes.inspect(),
    envProfiles.list(),
    inspectUniversalBrokerBudgets(),
    gitCommit(),
  ]);
  const observations = await mapWithConcurrency(targetSnapshot.targets, 4, async (target) => {
    try {
      return await targets.probe(target.id);
    } catch (error) {
      const observedAt = new Date().toISOString();
      return {
        targetId: target.id,
        status: "UNKNOWN" as const,
        observedAt,
        expiresAt: observedAt,
        platform: target.platform,
        capabilities: {
          fs: false,
          exec: false,
          pty: false,
          sftp: false,
          rsync: false,
          git: false,
          gui: false,
          mcp: false,
          durableProcess: false,
        },
        reason: errorMessage(error),
        evidence: {
          transport: target.transport,
          ...(target.sshHost ? { sshHost: target.sshHost } : {}),
        },
      };
    }
  });
  const [targetFile, routeFile, envProfileFile] = await Promise.all([
    safePathMetadata(config.targetConfigPath),
    safePathMetadata(config.mcpRouteConfigPath),
    safePathMetadata(config.envProfileConfigPath),
  ]);
  const runtimeIdentity = createRuntimeIdentity({
    config,
    sourceRevision: sourceCommit ?? config.sourceRevision,
    runtimeRevision: config.runtimeRevision,
    ...(config.buildDigest ? { buildDigest: config.buildDigest } : {}),
  });
  return {
    generatedAt: new Date().toISOString(),
    sourceCommit,
    runtimeIdentity,
    platform: { platform: process.platform, architecture: process.arch, node: process.version },
    endpoint: {
      deploymentMode: config.deploymentMode,
      local: `http://${config.host}:${config.port}${config.endpointPath}`,
      public: config.publicMcpUrl,
      health: `http://${config.host}:${config.port}${config.healthPath}`,
      managementHealth: `http://${config.managementHost}:${config.managementPort}/healthz`,
      readiness: `http://${config.managementHost}:${config.managementPort}${config.readyPath}`,
      metrics: `http://${config.managementHost}:${config.managementPort}${config.metricsPath}`,
      stateDir: config.stateDir,
      oauthStateReused: config.oauthStateDir === config.serverConfig.stateDir,
      granularScopesOnly: true,
    },
    storeInventory: baseMutableStoreInventory(config),
    contracts: budgets,
    selfManagement: {
      stateDir: config.selfManagementDir,
      pm2ProcessName: config.selfRestartPm2ProcessName,
      expectedScript: config.selfRestartExpectedScript,
      restartTimeoutMs: config.selfRestartTimeoutMs,
      transactionModel: "response-bound-ack-flushed-supervisor",
    },
    registries: {
      targets: {
        path: config.targetConfigPath,
        metadata: targetFile,
        generation: targetSnapshot.generation,
        count: targetSnapshot.targets.length,
      },
      mcpRoutes: {
        path: config.mcpRouteConfigPath,
        metadata: routeFile,
        generation: routeSnapshot.generation,
        count: routeSnapshot.routes.length,
        routes: routeSnapshot.routes.map((route) => ({
          id: route.id,
          transport: route.transport,
          target: route.target,
          envProfile: route.envProfile,
        })),
      },
      environmentProfiles: {
        path: config.envProfileConfigPath,
        metadata: envProfileFile,
        count: environmentProfiles.length,
        profiles: environmentProfiles,
      },
    },
    targets: observations,
    targetProbeStats: targets.stats(),
    quotas: {
      httpMcpSessions: config.maximumMcpSessions,
      httpMcpIdleTtlMs: config.mcpSessionIdleTimeoutMs,
      contexts: config.contextMaximumEntries,
      worktrees: config.contextMaximumWorktrees,
      worktreeBytes: config.contextMaximumWorktreeBytes,
      contextDiffEntries: config.contextDiffMaximumEntries,
      contextDiffCharacters: config.contextDiffMaximumCharacters,
      contextIdleTtlMs: config.contextIdleTtlMs,
      contextDiffTtlMs: config.contextDiffTtlMs,
      processes: config.maxRunningProcesses,
      processRecords: config.maximumProcessRecords,
      processesPerTarget: config.maxRunningProcessesPerTarget,
      processOutputBytes: config.processOutputMaxBytes,
      completedProcessTtlMs: config.completedProcessTtlMs,
      restartTimeoutMs: config.selfRestartTimeoutMs,
      downstreamMcpSessions: config.downstreamMcpMaximumSessions,
      downstreamMcpIdleTtlMs: config.downstreamMcpSessionIdleTtlMs,
      mcpResultEntries: config.mcpResultMaximumEntries,
      mcpResultBytes: config.mcpResultMaximumBytes,
      mcpResultTtlMs: config.mcpResultTtlMs,
      artifactEntries: config.artifactMaximumEntries,
      artifactTotalBytes: config.artifactMaximumTotalBytes,
      artifactFileBytes: config.artifactMaximumFileBytes,
      artifactTtlMs: config.artifactTtlMs,
      guiSessions: config.guiMaximumSessions,
      guiSessionTtlMs: config.guiSessionTtlMs,
    },
  };
}

function baseMutableStoreInventory(config: ReturnType<typeof loadUniversalBrokerNextConfig>): Record<string, unknown> {
  const pathByStoreId = new Map([
    ["authority", config.authorityStorePath],
    ["artifact-catalog", config.artifactCatalogPath],
    ["connector-activation-journal", config.connectorActivationJournalPath],
    ["lifecycle-finalization-store", config.lifecycleFinalizationStorePath],
    ["filesystem-sync", join(config.stateDir, "filesystem-sync", "sync.sqlite")],
  ]);
  return {
    sqliteStores: baseMutableSqliteStoreRequirements(buildCapabilityContract()).map((requirement) => ({
      storeId: requirement.storeId,
      required: requirement.required,
      expectedUserVersion: requirement.expectedUserVersion,
      reason: requirement.reason,
      path: pathByStoreId.get(requirement.storeId),
    })),
  };
}

async function mapWithConcurrency<T, R>(
  values: readonly T[],
  maximumConcurrency: number,
  mapper: (value: T, index: number) => Promise<R>,
): Promise<R[]> {
  const output = new Array<R>(values.length);
  let nextIndex = 0;
  const workers = Array.from(
    { length: Math.min(Math.max(maximumConcurrency, 1), values.length) },
    async () => {
      while (nextIndex < values.length) {
        const index = nextIndex;
        nextIndex += 1;
        output[index] = await mapper(values[index]!, index);
      }
    },
  );
  await Promise.all(workers);
  return output;
}

async function safePathMetadata(path: string): Promise<Record<string, unknown>> {
  try {
    const metadata = await lstat(path);
    return {
      exists: true,
      type: metadata.isFile() ? "file" : metadata.isDirectory() ? "directory" : metadata.isSocket() ? "socket" : "other",
      mode: (metadata.mode & 0o777).toString(8).padStart(3, "0"),
      uid: metadata.uid,
      gid: metadata.gid,
      size: metadata.size,
      modifiedAt: metadata.mtime.toISOString(),
    };
  } catch (error) {
    return { exists: false, error: errorMessage(error) };
  }
}

async function gitCommit(): Promise<string | undefined> {
  try {
    return (await execFileAsync("git", ["rev-parse", "HEAD"], {
      encoding: "utf8",
      maxBuffer: 64 * 1024,
    })).stdout.trim();
  } catch {
    return undefined;
  }
}

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

async function boundedDoctorCall<T>(
  operation: () => T | Promise<T>,
  timeoutMs: number,
  label: string,
  controller = new AbortController(),
): Promise<T> {
  let timer: NodeJS.Timeout | undefined;
  try {
    return await Promise.race([
      Promise.resolve().then(operation),
      new Promise<never>((_resolve, reject) => {
        timer = setTimeout(() => {
          controller.abort(new Error(`${label} timed out.`));
          reject(new Error(`${label} timed out after ${timeoutMs} ms.`));
        }, timeoutMs);
      }),
    ]);
  } finally {
    if (timer) clearTimeout(timer);
  }
}

function assertDoctorObservation(id: string, value: DeepDoctorCheckObservation): void {
  if (!value || !["PASS", "FAIL", "UNKNOWN"].includes(value.state)) {
    throw new Error(`Deep doctor check ${id} returned an invalid state.`);
  }
}

function failedCleanupReceipt(namespace: string, error: unknown): DeepDoctorCleanupReceipt {
  const message = doctorBounded(errorMessage(error));
  return {
    state: "FAILED",
    receiptDigest: `sha256:${createHash("sha256")
      .update(namespace)
      .update("\0")
      .update(message)
      .digest("hex")}`,
    error: message,
  };
}

function doctorSanitize(value: Record<string, unknown>): Record<string, unknown> {
  return doctorSanitizeValue(value, "", 0) as Record<string, unknown>;
}

function doctorSanitizeValue(value: unknown, key: string, depth: number): unknown {
  if (/(?:authorization|cookie|credential|password|private.?key|secret|token)$/iu.test(key)) {
    return "[REDACTED]";
  }
  if (depth >= 6) return "[DEPTH_LIMIT]";
  if (typeof value === "string") return doctorBounded(value, 512);
  if (typeof value === "number" || typeof value === "boolean" || value === null) return value;
  if (Array.isArray(value)) return value.slice(0, 32).map((child) => doctorSanitizeValue(child, key, depth + 1));
  if (value && typeof value === "object") {
    return Object.fromEntries(Object.entries(value as Record<string, unknown>)
      .slice(0, 64)
      .map(([childKey, child]) => [childKey, doctorSanitizeValue(child, childKey, depth + 1)]));
  }
  return value === undefined ? undefined : String(value);
}

function doctorInteger(
  value: number | undefined,
  fallback: number | undefined,
  minimum: number,
  maximum: number,
  field: string,
): number {
  const parsed = value ?? fallback;
  if (parsed === undefined || !Number.isInteger(parsed) || parsed < minimum || parsed > maximum) {
    throw new Error(`${field} must be an integer from ${minimum} through ${maximum}.`);
  }
  return parsed;
}

function doctorSafeText(value: string, field: string, maximum: number): string {
  const normalized = value.trim();
  if (!normalized || normalized.length > maximum || /[\r\n\0]/u.test(normalized)) {
    throw new Error(`${field} is missing or invalid.`);
  }
  return normalized;
}

function doctorBounded(value: string, maximum = 1_000): string {
  const normalized = value.replace(/[\r\n\0]+/gu, " ").trim();
  return normalized.length <= maximum ? normalized : `${normalized.slice(0, maximum)}…`;
}
