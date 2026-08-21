import { constants as fsConstants, existsSync } from "node:fs";
import { access, lstat } from "node:fs/promises";
import Database from "better-sqlite3";
import {
  FINALIZATION_STORE_ID,
  readFinalizationStoreIdentity,
} from "../../scripts/lib/finalization-store-contract.mjs";
import type { ManagementAuthorizationKey } from "./management-authorization.js";
import {
  buildCapabilityContract,
  capabilityDigest,
  type BuildCapabilityContract,
} from "./build-capabilities.js";
import { baseMutableSqliteStoreRequirements } from "./migration-registry.js";
import type { RuntimeIdentity } from "./contracts.js";

export type ReadinessCheckState = "PASS" | "FAIL" | "UNKNOWN";

export interface ReadinessCheckObservation {
  state: ReadinessCheckState;
  summary?: string;
  evidence?: Record<string, unknown>;
}

export interface CanonicalConnectorReadinessInput {
  state: "PASS" | "FAIL";
  activeCount: number;
  bindingsByState: Record<string, number>;
  invalidStates: readonly string[];
}

export interface PersonalConnectorReadinessInput {
  state: "PASS" | "FAIL";
  activeCount: number;
  bindingsByState: Record<string, number>;
  invalidStates: readonly string[];
  expectedInstallationEpoch?: number;
  activeInstallationEpoch?: number;
  activeSchemaGeneration?: string;
  activeBindingIdDigest?: string;
  activeClientIdDigest?: string;
  activeFamilyCount: number;
  activeRefreshTokenCount: number;
  activePersistedTokenCount: number;
  overdueDrainingCount: number;
  unboundActiveFamilyCount: number;
  nonActiveTokenFamilyCount: number;
  preparedReceiptCount: number;
}

export interface ReadinessCheckContext {
  readonly mode: "READ_ONLY";
  readonly signal: AbortSignal;
  readonly deadlineAt: number;
}

export interface ReadinessCheck {
  id: string;
  sideEffectFree: boolean;
  timeoutMs?: number;
  check(
    context: ReadinessCheckContext,
  ): ReadinessCheckObservation | Promise<ReadinessCheckObservation>;
}

export interface ReadinessCheckReport extends ReadinessCheckObservation {
  id: string;
  durationMs: number;
}

export interface ReadinessReport {
  status: "ready" | "not_ready";
  httpStatus: 200 | 503;
  checkedAt: string;
  durationMs: number;
  checks: ReadinessCheckReport[];
}

export interface ReadinessRegistryOptions {
  maximumDurationMs?: number;
  defaultCheckTimeoutMs?: number;
  now?: () => number;
}

export interface ReadinessSqliteStoreOptions {
  storeId: string;
  path: string;
  required: boolean;
  expectedUserVersion?: number;
}

export interface RuntimeCapabilityIdentityInput {
  productProfile?: string;
  buildCapabilityDigest?: string;
  resourceUriVersion?: string;
  schemaGeneration: string;
  buildDigest: string;
}

export interface BaseMutableSqliteStoreReadinessInput {
  artifactCatalogPath: string;
  filesystemSyncStorePath: string;
  capabilities?: BuildCapabilityContract;
}

const DEFAULT_MAXIMUM_DURATION_MS = 250;
const DEFAULT_CHECK_TIMEOUT_MS = 200;
const MAXIMUM_CHECKS = 64;
const CHECK_ID_PATTERN = /^[a-z][a-z0-9_]{1,63}$/u;
const SHA256_DIGEST_PATTERN = /^sha256:[a-f0-9]{64}$/u;
/**
 * A parallel runtime is started before its connector is activated. Treat only that
 * exact empty-but-consistent state as ready; production still requires one ACTIVE
 * connector and every other connector consistency failure remains fail-closed.
 */
export function canonicalConnectorReadinessObservation(
  deploymentMode: "parallel" | "production",
  connector: CanonicalConnectorReadinessInput,
): ReadinessCheckObservation {
  const awaitingParallelActivation = deploymentMode === "parallel"
    && connector.state === "FAIL"
    && connector.activeCount === 0
    && connector.invalidStates.length === 1
    && connector.invalidStates[0] === "ACTIVE_COUNT";
  return {
    state: awaitingParallelActivation ? "PASS" : connector.state,
    evidence: {
      activeCount: connector.activeCount,
      bindingsByState: connector.bindingsByState,
      invalidStates: connector.invalidStates,
      activationState: awaitingParallelActivation
        ? "PENDING"
        : connector.state === "PASS" && connector.activeCount === 1
          ? "ACTIVE"
          : "INVALID",
    },
  };
}

/**
 * Personal production accepts no enterprise verification ceremony bypass. A fresh parallel
 * candidate may be ready before its isolated connector is activated, but production requires
 * the exact Personal connector/token-family invariants reported by the OAuth store.
 */
export function personalConnectorReadinessObservation(
  deploymentMode: "parallel" | "production",
  connector: PersonalConnectorReadinessInput,
): ReadinessCheckObservation {
  const bindingCount = Object.values(connector.bindingsByState)
    .reduce((total, count) => total + Number(count), 0);
  const awaitingParallelActivation = deploymentMode === "parallel"
    && connector.state === "FAIL"
    && connector.activeCount === 0
    && bindingCount === 0
    && connector.invalidStates.length === 1
    && connector.invalidStates[0] === "ACTIVE_COUNT"
    && connector.unboundActiveFamilyCount === 0
    && connector.nonActiveTokenFamilyCount === 0
    && connector.preparedReceiptCount === 0;
  return {
    state: awaitingParallelActivation ? "PASS" : connector.state,
    ...(awaitingParallelActivation
      ? { summary: "Parallel Personal connector activation is pending." }
      : connector.state === "PASS"
        ? {}
        : { summary: "Personal connector consistency failed." }),
    evidence: {
      ...connector,
      activationState: awaitingParallelActivation
        ? "PENDING"
        : connector.state === "PASS" && connector.activeCount === 1
          ? "ACTIVE"
          : "INVALID",
    },
  };
}

/** A bounded registry whose check API deliberately exposes no mutation capabilities. */
export class ReadinessRegistry {
  private readonly checks: readonly ReadinessCheck[];
  private readonly maximumDurationMs: number;
  private readonly defaultCheckTimeoutMs: number;
  private readonly now: () => number;

  constructor(checks: readonly ReadinessCheck[], options: ReadinessRegistryOptions = {}) {
    if (checks.length === 0) {
      throw new Error("Readiness requires at least one side-effect-free check.");
    }
    if (checks.length > MAXIMUM_CHECKS) {
      throw new Error(`Readiness accepts at most ${MAXIMUM_CHECKS} checks.`);
    }
    const identifiers = new Set<string>();
    this.checks = Object.freeze(checks.map((check) => {
      if (!CHECK_ID_PATTERN.test(check.id)) throw new Error(`Invalid readiness check id: ${check.id}`);
      if (identifiers.has(check.id)) throw new Error(`Duplicate readiness check: ${check.id}`);
      if (check.sideEffectFree !== true) {
        throw new Error(`Readiness check ${check.id} must be declared side-effect-free.`);
      }
      if (typeof check.check !== "function") throw new Error(`Readiness check ${check.id} is missing.`);
      identifiers.add(check.id);
      return Object.freeze({ ...check });
    }));
    this.maximumDurationMs = boundedInteger(
      options.maximumDurationMs,
      DEFAULT_MAXIMUM_DURATION_MS,
      1,
      5_000,
      "maximumDurationMs",
    );
    this.defaultCheckTimeoutMs = boundedInteger(
      options.defaultCheckTimeoutMs,
      Math.min(DEFAULT_CHECK_TIMEOUT_MS, this.maximumDurationMs),
      1,
      this.maximumDurationMs,
      "defaultCheckTimeoutMs",
    );
    this.now = options.now ?? Date.now;
  }

  async evaluate(): Promise<ReadinessReport> {
    const startedAt = this.now();
    const checkedAt = new Date(startedAt).toISOString();
    const checks = await Promise.all(this.checks.map((check) => this.runCheck(check, startedAt)));
    const ready = checks.every((check) => check.state === "PASS");
    return {
      status: ready ? "ready" : "not_ready",
      httpStatus: ready ? 200 : 503,
      checkedAt,
      durationMs: Math.max(0, this.now() - startedAt),
      checks,
    };
  }

  private async runCheck(check: ReadinessCheck, startedAt: number): Promise<ReadinessCheckReport> {
    const checkStartedAt = this.now();
    const timeoutMs = Math.min(
      check.timeoutMs === undefined
        ? this.defaultCheckTimeoutMs
        : boundedInteger(check.timeoutMs, undefined, 1, this.maximumDurationMs, `${check.id}.timeoutMs`),
      Math.max(1, startedAt + this.maximumDurationMs - checkStartedAt),
    );
    const deadlineAt = checkStartedAt + timeoutMs;
    const controller = new AbortController();
    let timer: NodeJS.Timeout | undefined;
    try {
      const timeout = new Promise<never>((_resolve, reject) => {
        timer = setTimeout(() => {
          controller.abort(new Error(`Readiness check ${check.id} timed out.`));
          reject(new Error(`Readiness check ${check.id} timed out after ${timeoutMs} ms.`));
        }, timeoutMs);
      });
      const context = Object.freeze<ReadinessCheckContext>({
        mode: "READ_ONLY",
        signal: controller.signal,
        deadlineAt,
      });
      const observation = await Promise.race([
        Promise.resolve().then(() => check.check(context)),
        timeout,
      ]);
      assertObservation(check.id, observation);
      return {
        id: check.id,
        state: observation.state,
        ...(observation.summary ? { summary: bounded(observation.summary) } : {}),
        ...(observation.evidence ? { evidence: sanitizeEvidence(observation.evidence) } : {}),
        durationMs: Math.max(0, this.now() - checkStartedAt),
      };
    } catch (error) {
      return {
        id: check.id,
        state: "UNKNOWN",
        summary: bounded(errorMessage(error)),
        durationMs: Math.max(0, this.now() - checkStartedAt),
      };
    } finally {
      if (timer) clearTimeout(timer);
    }
  }
}

function assertObservation(id: string, value: ReadinessCheckObservation): void {
  if (!value || !["PASS", "FAIL", "UNKNOWN"].includes(value.state)) {
    throw new Error(`Readiness check ${id} returned an invalid state.`);
  }
}

export function runtimeCapabilityIdentityReadiness(
  identity: RuntimeCapabilityIdentityInput,
): ReadinessCheckObservation {
  const contract = buildCapabilityContract();
  const expectedCapabilityDigest = capabilityDigest(contract);
  const mismatches: string[] = [];
  if (identity.productProfile !== contract.productProfile) mismatches.push("productProfile");
  if (identity.buildCapabilityDigest !== expectedCapabilityDigest) mismatches.push("buildCapabilityDigest");
  if (identity.resourceUriVersion !== contract.resourceUriVersion) mismatches.push("resourceUriVersion");
  if (identity.schemaGeneration !== contract.schemaGeneration) mismatches.push("schemaGeneration");
  if (!SHA256_DIGEST_PATTERN.test(identity.buildDigest)) mismatches.push("buildDigest");
  return {
    state: mismatches.length === 0 ? "PASS" : "FAIL",
    ...(mismatches.length > 0 ? { summary: `Runtime identity drift: ${mismatches.join(", ")}` } : {}),
    evidence: {
      productProfile: identity.productProfile,
      buildCapabilityDigest: identity.buildCapabilityDigest,
      resourceUriVersion: identity.resourceUriVersion,
      schemaGeneration: identity.schemaGeneration,
      buildDigest: identity.buildDigest,
      expectedCapabilityDigest,
    },
  };
}

export async function readablePathReadiness(
  path: string,
  options: { id: string; required: boolean },
): Promise<ReadinessCheckObservation> {
  try {
    const metadata = await lstat(path);
    await access(path, fsConstants.R_OK);
    return {
      state: "PASS",
      evidence: {
        id: options.id,
        path,
        exists: true,
        type: metadata.isFile() ? "file" : metadata.isDirectory() ? "directory" : "other",
        mode: (metadata.mode & 0o777).toString(8).padStart(3, "0"),
        size: metadata.size,
      },
    };
  } catch (error) {
    if (!options.required && isNodeError(error, "ENOENT")) {
      return {
        state: "PASS",
        summary: `${options.id} is not initialized yet.`,
        evidence: { id: options.id, path, exists: false, required: false },
      };
    }
    return {
      state: options.required ? "FAIL" : "UNKNOWN",
      summary: `${options.id} is not readable: ${errorMessage(error)}`,
      evidence: { id: options.id, path, required: options.required },
    };
  }
}

export function sqliteStoreReadiness(
  options: ReadinessSqliteStoreOptions,
): ReadinessCheckObservation {
  let database: Database.Database | undefined;
  try {
    if (!options.required && !existsSync(options.path)) {
      return {
        state: "PASS",
        summary: `${options.storeId} is not initialized yet.`,
        evidence: { storeId: options.storeId, path: options.path, required: false, exists: false },
      };
    }
    database = new Database(options.path, { readonly: true, fileMustExist: true });
    database.pragma("query_only = ON");
    database.pragma("foreign_keys = ON");
    const integrity = String(database.pragma("quick_check", { simple: true }));
    const foreignKeyViolations = (database.pragma("foreign_key_check") as unknown[]).length;
    const userVersion = Number(database.pragma("user_version", { simple: true }));
    const versionOk = options.expectedUserVersion === undefined
      || userVersion === options.expectedUserVersion;
    return {
      state: integrity === "ok" && foreignKeyViolations === 0 && versionOk ? "PASS" : "FAIL",
      ...(versionOk ? {} : { summary: `${options.storeId} schema version is ${userVersion}.` }),
      evidence: {
        storeId: options.storeId,
        path: options.path,
        required: options.required,
        exists: true,
        userVersion,
        expectedUserVersion: options.expectedUserVersion,
        integrity,
        foreignKeyViolations,
      },
    };
  } catch (error) {
    if (!options.required && isNodeError(error, "SQLITE_CANTOPEN")) {
      return {
        state: "PASS",
        summary: `${options.storeId} is not initialized yet.`,
        evidence: { storeId: options.storeId, path: options.path, required: false, exists: false },
      };
    }
    return {
      state: options.required ? "FAIL" : "UNKNOWN",
      summary: `${options.storeId} SQLite readback failed: ${errorMessage(error)}`,
      evidence: { storeId: options.storeId, path: options.path, required: options.required },
    };
  } finally {
    database?.close();
  }
}

export function baseMutableSqliteStoreReadiness(
  input: BaseMutableSqliteStoreReadinessInput,
): ReadinessCheckObservation {
  const pathByStoreId = new Map([
    ["artifact-catalog", input.artifactCatalogPath],
    ["filesystem-sync", input.filesystemSyncStorePath],
  ]);
  const observations = baseMutableSqliteStoreRequirements(input.capabilities ?? buildCapabilityContract())
    .map((requirement) => {
      const path = pathByStoreId.get(requirement.storeId);
      if (!path) {
        return {
          state: "FAIL" as const,
          summary: `${requirement.storeId} path is not configured.`,
          evidence: {
            storeId: requirement.storeId,
            required: requirement.required,
            expectedUserVersion: requirement.expectedUserVersion,
          },
        };
      }
      return sqliteStoreReadiness({
        storeId: requirement.storeId,
        path,
        required: requirement.required,
        expectedUserVersion: requirement.expectedUserVersion,
      });
    });
  const state = observations.some((observation) => observation.state === "FAIL")
    ? "FAIL"
    : observations.some((observation) => observation.state === "UNKNOWN")
      ? "UNKNOWN"
      : "PASS";
  return {
    state,
    ...(state === "PASS" ? {} : { summary: "Required Base mutable SQLite stores are not fully ready." }),
    evidence: { observations },
  };
}

function finalizationStoreReadiness(
  path: string,
  controlPath: string,
  key: ManagementAuthorizationKey,
  required: boolean,
): ReadinessCheckObservation {
  try {
    const identity = readFinalizationStoreIdentity({ storePath: path, controlPath, key });
    return {
      state: "PASS",
      evidence: {
        storeId: FINALIZATION_STORE_ID,
        path,
        controlPath,
        required,
        schemaVersion: identity.schemaVersion,
        schemaFingerprint: identity.schemaFingerprint,
        state: identity.state,
        revision: identity.revision,
        transactionId: identity.transactionId,
        integrity: identity.integrity,
        foreignKeyViolations: identity.foreignKeyViolations,
        contentGeneration: identity.contentGeneration,
        controlEpoch: identity.controlEpoch,
      },
    };
  } catch (error) {
    return {
      state: required ? "FAIL" : "UNKNOWN",
      summary: `Lifecycle finalization keyed control readback failed: ${errorMessage(error)}`,
      evidence: { storeId: FINALIZATION_STORE_ID, path, controlPath, required },
    };
  }
}

function sanitizeEvidence(value: Record<string, unknown>): Record<string, unknown> {
  return sanitizeValue(value, "", 0) as Record<string, unknown>;
}

function sanitizeValue(value: unknown, key: string, depth: number): unknown {
  if (/(?:authorization|cookie|credential|password|private.?key|secret|token)$/iu.test(key)) {
    return "[REDACTED]";
  }
  if (depth >= 6) return "[DEPTH_LIMIT]";
  if (typeof value === "string") return bounded(value, 512);
  if (typeof value === "number" || typeof value === "boolean" || value === null) return value;
  if (Array.isArray(value)) return value.slice(0, 32).map((child) => sanitizeValue(child, key, depth + 1));
  if (value && typeof value === "object") {
    return Object.fromEntries(Object.entries(value as Record<string, unknown>)
      .slice(0, 64)
      .map(([childKey, child]) => [childKey, sanitizeValue(child, childKey, depth + 1)]));
  }
  return value === undefined ? undefined : String(value);
}

function boundedInteger(
  value: number | undefined,
  fallback: number | undefined,
  minimum: number,
  maximum: number,
  name: string,
): number {
  const parsed = value ?? fallback;
  if (parsed === undefined || !Number.isInteger(parsed) || parsed < minimum || parsed > maximum) {
    throw new Error(`${name} must be an integer from ${minimum} through ${maximum}.`);
  }
  return parsed;
}

function bounded(value: string, maximum = 1_000): string {
  const normalized = value.replace(/[\r\n\0]+/gu, " ").trim();
  return normalized.length <= maximum ? normalized : `${normalized.slice(0, maximum)}…`;
}

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

function isNodeError(error: unknown, code: string): boolean {
  return Boolean(error && typeof error === "object" && "code" in error && error.code === code);
}
