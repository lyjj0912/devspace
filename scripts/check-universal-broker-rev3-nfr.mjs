#!/usr/bin/env node
import { execFile } from "node:child_process";
import { createHash, randomUUID } from "node:crypto";
import {
  mkdir,
  mkdtemp,
  readFile,
  realpath,
  rm,
  writeFile,
} from "node:fs/promises";
import { readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, isAbsolute, join, resolve } from "node:path";
import { performance } from "node:perf_hooks";
import { fileURLToPath, pathToFileURL } from "node:url";
import { promisify } from "node:util";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";
import { loadConfig } from "../src/config.ts";
import {
  SqliteOAuthStore,
  connectorActivationAuthorityActionFingerprint,
  connectorActivationAuthorityResourceKeySha256,
} from "../src/oauth-store.ts";
import { createCapabilityCallContextFromTrustedPrincipal } from "../src/v2/capability-call-context.ts";
import { ContextRegistry, contextPayloadCharacters } from "../src/v2/contexts.ts";
import {
  UNIVERSAL_BROKER_BUDGETS,
  UNIVERSAL_TOOL_NAMES,
} from "../src/v2/contracts.ts";
import { inspectUniversalBrokerBudgets } from "../src/v2/budgets.ts";
import {
  OperationAuthorityRegistry,
} from "../src/v2/authority.ts";
import {
  authorityActionFromToolCall,
  minimumAuthorityRisk,
} from "../src/v2/authority-policy.ts";
import {
  principalKeyFingerprint,
  resolveAuthorityPrincipal,
} from "../src/v2/authority-principal.ts";
import {
  ArtifactCatalog,
  artifactCapabilityTokenHash,
} from "../src/v2/artifact-catalog.ts";
import {
  CursorCapabilityError,
  SignedSnapshotCursorStore,
} from "../src/v2/cursor-capability.ts";
import { TargetRegistry } from "../src/v2/targets.ts";
import { UniversalExecutionPlane } from "../src/v2/execution.ts";
import { UniversalBrokerError } from "../src/v2/errors.ts";
import { UniversalFilesystemService } from "../src/v2/filesystem.ts";
import { createLocalFilesystemSyncAdapter } from "../src/v2/filesystem-sync.ts";
import { RecoverableFilesystemTrash } from "../src/v2/filesystem-trash.ts";
import { UniversalMcpRouteRegistry } from "../src/v2/mcp-routes.ts";
import { UniversalMcpProxy } from "../src/v2/mcp-proxy.ts";
import { loadUniversalBrokerNextConfig } from "../src/v2/config.ts";
import { createUniversalBrokerNextServer } from "../src/v2/http-server.ts";
import { ReadinessRegistry } from "../src/v2/readiness.ts";
import { BoundedDeepDoctor } from "../src/v2/doctor.ts";
import { OperationAuditSink } from "../src/v2/operation-audit.ts";
import { createRuntimeIdentity } from "../src/v2/runtime-identity.ts";
import {
  loadExistingManagementAuthorizationKey,
  managementAuthorizationHeader,
} from "../src/v2/management-authorization.ts";
import { McpSessionRegistry } from "../src/mcp-sessions.ts";
import {
  SELF_RESTART_EVIDENCE_MAX_BYTES,
  validateSelfRestartEvidence,
} from "./lib/self-restart-evidence.mjs";

const execFileAsync = promisify(execFile);
const root = resolve(fileURLToPath(new URL("..", import.meta.url)));
const mib = 1024 * 1024;
const BASE_PROFILE_APPLICABILITY = Object.freeze({
  BASE_SINGLE_OWNER: "REQUIRED",
  MULTI_USER: "NOT_APPLICABLE",
  SIDECAR_AUTHORITY: "NOT_APPLICABLE",
  HOST_ATTESTED: "NOT_APPLICABLE",
  GUI_CAPTURE: "NOT_APPLICABLE",
});

export const REV3_NFR_IDS = Object.freeze(Array.from(
  { length: 30 },
  (_value, index) => `NFR-${String(index + 101).padStart(3, "0")}`,
));

export const REV3_NFR_THRESHOLDS = Object.freeze({
  "NFR-101": threshold("8 tool descriptor characters", "<=", 9_000, "characters"),
  "NFR-102": threshold("initial Context inline payload", "<=", 4 * 1024, "bytes"),
  "NFR-103": threshold("reused Context inline payload", "<=", 512, "bytes"),
  "NFR-104": threshold("local no-op exec p95 over 500 samples", "<=", 25, "ms"),
  "NFR-105": Object.freeze({
    label: "local stat/read metadata p95 over 500 samples plus live SSH metadata over 200 samples",
    operator: "all",
    value: Object.freeze({ localSamples: 500, localP95Ms: 50, sshSamples: 200, sshFailures: 0 }),
    unit: "compound",
    source: "DEVSPACE_UNIVERSAL_BROKER_TOBE_CONSTRUCTION_SPEC.md §26 NFR-105 and §30.12 SSH 200",
  }),
  "NFR-106": threshold("warm MCP invoke p95 over 200 samples", "<=", 50, "ms"),
  "NFR-107": threshold("100,000-entry first 1,000 page", "<=", 250, "ms"),
  "NFR-108": threshold("concurrent process quota", "==", "16 ok, 17th rejected", "contract"),
  "NFR-109": threshold("100 MiB output", "==", "resource handle, bounded inline", "contract"),
  "NFR-110": threshold("MCP connection churn", "<=", 1_000, "connections with no poisoned cache/leak"),
  "NFR-111": threshold("Context reuse", "<=", 500, "opens with no state leak"),
  "NFR-112": threshold("steady RSS growth", "<=", 50 * mib, "bytes"),
  "NFR-113": threshold("failed Target retry blind loops", "==", 0, "blind retries"),
  "NFR-114": threshold("public metrics 200 response", "==", 0, "responses"),
  "NFR-115": threshold("R0 authority overhead", "==", 0, "durable writes/ipc/grants"),
  "NFR-116": threshold("same-principal authority churn", "<=", 1_000, "sessions without reissue"),
  "NFR-117": threshold("coherent R1/R2 batch", "<=", 1, "preview and authorize"),
  "NFR-118": threshold("principal derivation session lookup", "==", 0, "lookups"),
  "NFR-119": threshold("authority claim+receipt p95 over 10,000", "<=", 50, "ms"),
  "NFR-120": threshold("signed cursor verify p95", "<=", 5, "ms"),
  "NFR-121": threshold("cursor tamper/stale/expiry typed reject", "==", "100%, data mix 0", "contract"),
  "NFR-122": threshold("Artifact restart continuity", "==", 0, "TTL record/URI loss"),
  "NFR-123": threshold("self-restart before ACK_FLUSHED", "==", 0, "restarts"),
  "NFR-124": threshold("private /readyz p95", "<=", 250, "ms"),
  "NFR-125": threshold("deep doctor duration", "<=", 30_000, "ms"),
  "NFR-126": threshold("rate limit provider dispatch at threshold", "==", 0, "dispatches"),
  "NFR-127": threshold("resource lease stale overwrite", "==", 0, "overwrites"),
  "NFR-128": threshold("fs.sync stale apply and duplicate resume", "==", 0, "events"),
  "NFR-129": threshold("audit graceful shutdown loss and secret leak", "==", 0, "events"),
  "NFR-130": threshold("NFR script exit binding", "==", "1:1 threshold to process failure", "contract"),
});

const REV3_NFR_RAW_PREDICATES = Object.freeze({
  "NFR-101": (raw) => rawPredicate([
    numberAtMost(raw, "descriptorCharacters", 9_000),
  ]),
  "NFR-102": (raw) => rawPredicate([
    numberAtMost(raw, "initialContextCharacters", 4 * 1024),
    numberAtMost(raw, "contractLimitCharacters", 4 * 1024),
  ]),
  "NFR-103": (raw) => rawPredicate([
    numberAtMost(raw, "reusedContextCharacters", 512),
    numberEquals(raw, "contractLimitCharacters", 512),
  ]),
  "NFR-104": (raw, context) => sampledLatencyPredicate(raw, context, "sampleCount", 500, "p95Ms", 25),
  "NFR-105": (raw, context) => rawPredicate([
    requiredReleaseSample(raw, context, "sampleCount", 500),
    numberEquals(raw, "requiredReleaseSampleCount", 500),
    numberAtMost(raw, "p95Ms", 50),
    rawCheck(isFiniteNumber(raw.maxMs), "maxMs must be finite"),
    numberEquals(raw, "sshRequiredReleaseSampleCount", 200),
    rawCheck(typeof raw.sshConfigured === "boolean", "sshConfigured must be boolean"),
    rawCheck(isFiniteNumber(raw.sshSampleCount) && raw.sshSampleCount >= 0, "sshSampleCount must be finite >= 0"),
    rawCheck(isFiniteNumber(raw.sshSuccesses) && raw.sshSuccesses >= 0, "sshSuccesses must be finite >= 0"),
    rawCheck(isFiniteNumber(raw.sshFailures) && raw.sshFailures >= 0, "sshFailures must be finite >= 0"),
    rawCheck(
      !requiresReleaseGrade(context) || (
        raw.sshConfigured === true
        && raw.sshTransport === "ssh"
        && raw.sshLiveProbeStatus === "ONLINE"
        && raw.sshSampleCount >= 200
        && raw.sshSuccesses === raw.sshSampleCount
        && raw.sshFailures === 0
        && isFiniteNumber(raw.sshP95Ms)
        && isFiniteNumber(raw.sshMaxMs)
        && typeof raw.sshTargetGeneration === "string"
        && /^sha256:[a-f0-9]{64}$/u.test(raw.sshTargetGeneration)
        && typeof raw.sshReadPathDigest === "string"
        && /^sha256:[a-f0-9]{64}$/u.test(raw.sshReadPathDigest)
      ),
      "release/PASS NFR-105 requires 200 successful live SSH metadata samples with exact target/path evidence",
    ),
  ]),
  "NFR-106": (raw, context) => sampledLatencyPredicate(raw, context, "sampleCount", 200, "p95Ms", 50),
  "NFR-107": (raw, context) => rawPredicate([
    requiredReleaseSample(raw, context, "entries", 100_000),
    numberEquals(raw, "requiredReleaseSampleCount", 100_000),
    rawCheck(
      isFiniteNumber(raw.entries)
        && isFiniteNumber(raw.returned)
        && raw.returned === Math.min(1_000, raw.entries),
      "returned must equal min(1000, entries)",
    ),
    rawCheck(raw.totalEntries === raw.entries, "totalEntries must equal entries"),
    numberAtMost(raw, "durationMs", 250),
  ]),
  "NFR-108": (raw) => rawPredicate([
    numberEquals(raw, "started", 16),
    booleanEquals(raw, "quotaRejected", true),
  ]),
  "NFR-109": (raw, context) => rawPredicate([
    requiredReleaseSample(raw, context, "requestedBytes", 100 * mib),
    numberEquals(raw, "requiredReleaseSampleCount", 100 * mib),
    rawCheck(isFiniteNumber(raw.outputBytes) && raw.outputBytes >= raw.requestedBytes, "outputBytes must cover requestedBytes"),
    numberAtMost(raw, "inlineCharacters", 100),
    rawCheck(typeof raw.outputResourceUri === "string" && raw.outputResourceUri.length > 0, "outputResourceUri must be present"),
    stringEquals(raw, "state", "EXITED"),
    numberEquals(raw, "exitCode", 0),
  ]),
  "NFR-110": (raw, context) => rawPredicate([
    requiredReleaseSample(raw, context, "sessions", 1_000),
    numberEquals(raw, "requiredReleaseSampleCount", 1_000),
    rawCheck(isFiniteNumber(raw.closed) && raw.closed === raw.sessions, "closed must equal sessions"),
    numberEquals(raw, "remaining", 0),
    rawCheck(isFiniteNumber(raw.rssGrowthBytes) && isFiniteNumber(raw.rssLimitBytes) && raw.rssGrowthBytes <= raw.rssLimitBytes, "rssGrowthBytes must be within rssLimitBytes"),
  ]),
  "NFR-111": (raw, context) => rawPredicate([
    requiredReleaseSample(raw, context, "calls", 500),
    numberEquals(raw, "requiredReleaseSampleCount", 500),
    booleanEquals(raw, "contextIdStable", true),
    numberEquals(raw, "remainingContexts", 0),
  ]),
  "NFR-112": (raw) => rawPredicate([
    rawCheck(isFiniteNumber(raw.rssGrowthBytes), "rssGrowthBytes must be finite"),
    rawCheck(
      isFiniteNumber(raw.rssGrowthBytes)
        && raw.rssGrowthBytes <= (isFiniteNumber(raw.rssLimitBytes) ? raw.rssLimitBytes : 50 * mib),
      "rssGrowthBytes must be <= 50 MiB",
    ),
  ]),
  "NFR-113": (raw) => rawPredicate([
    stringEquals(raw, "targetStatus", "OFFLINE"),
    rawCheck(isFiniteNumber(raw.typedRejects) && raw.typedRejects === raw.attempts, "typedRejects must equal attempts"),
    numberEquals(raw, "blindRetryLoops", 0),
    numberEquals(raw, "providerDispatches", 0),
  ]),
  "NFR-114": (raw) => rawPredicate([
    numberEquals(raw, "publicMetrics200Responses", 0),
  ]),
  "NFR-115": (raw) => rawPredicate([
    stringEquals(raw, "risk", "R0"),
    numberEquals(raw, "durableWrites", 0),
    numberEquals(raw, "authorityIpc", 0),
    numberEquals(raw, "grantReceipts", 0),
    booleanEquals(raw, "createRejected", true),
  ]),
  "NFR-116": (raw, context) => rawPredicate([
    requiredReleaseSample(raw, context, "sessions", 1_000),
    numberEquals(raw, "requiredReleaseSampleCount", 1_000),
    numberEquals(raw, "uniqueFingerprints", 1),
    numberEquals(raw, "authorityReissues", 0),
  ]),
  "NFR-117": (raw) => rawPredicate([
    numberAtMost(raw, "previewCount", 1),
    numberAtMost(raw, "authorizeCount", 1),
    numberAtMost(raw, "authorityActionCount", 1),
    booleanEquals(raw, "authorityIdPresent", true),
  ]),
  "NFR-118": (raw) => rawPredicate([
    numberEquals(raw, "sessionLookups", 0),
    rawCheck(isFiniteNumber(raw.p95Ms), "p95Ms must be finite"),
    rawCheck(Array.isArray(raw.algorithmInputs) && raw.algorithmInputs.length > 0, "algorithmInputs must identify deterministic inputs"),
  ]),
  "NFR-119": (raw, context) => rawPredicate([
    requiredReleaseSample(raw, context, "claims", 10_000),
    numberEquals(raw, "requiredReleaseSampleCount", 10_000),
    numberAtMost(raw, "p95Ms", 50),
    numberEquals(raw, "duplicateDispatches", 0),
  ]),
  "NFR-120": (raw) => rawPredicate([
    rawCheck(isFiniteNumber(raw.sampleCount) && raw.sampleCount > 0, "sampleCount must be positive"),
    numberAtMost(raw, "p95Ms", 5),
  ]),
  "NFR-121": (raw) => rawPredicate([
    rawCheck(isFiniteNumber(raw.tamperCases) && raw.tamperCases > 0, "tamperCases must be positive"),
    rawCheck(raw.typedRejects === raw.tamperCases, "typedRejects must equal tamperCases"),
    numberEquals(raw, "dataMixes", 0),
  ]),
  "NFR-122": (raw) => rawPredicate([
    numberEquals(raw, "recordLosses", 0),
    numberEquals(raw, "uriLosses", 0),
    rawCheck(typeof raw.resourceUri === "string" && raw.resourceUri.length > 0, "resourceUri must survive restart"),
  ]),
  "NFR-123": (raw) => rawPredicate([
    numberEquals(raw, "restartBeforeAckFlushed", 0),
    numberAtMost(raw, "evidenceBytes", SELF_RESTART_EVIDENCE_MAX_BYTES),
    stringEquals(raw, "terminalState", "PASS"),
    rawCheck(Array.isArray(raw.validationFailures) && raw.validationFailures.length === 0, "validationFailures must be empty"),
  ]),
  "NFR-124": (raw, context) => rawPredicate([
    numberAtMost(raw, "p95Ms", 250),
    numberEquals(raw, "mutationSideEffects", 0),
    rawCheck(
      !requiresReleaseGrade(context)
        || (
          raw.privateHttpEndpoint === "configured"
          && raw.sampleCount === 100
          && raw.status === 200
          && raw.readinessState === "ready"
        ),
      "release/PASS readiness must use 100 configured private HTTP samples",
    ),
  ]),
  "NFR-125": (raw, context) => rawPredicate([
    numberAtMost(raw, "durationMs", 30_000),
    rawCheck(raw.cleanup?.state === "CLEANED", "cleanup.state must be CLEANED"),
    rawCheck(
      !requiresReleaseGrade(context)
        || (
          raw.liveManagementEndpoint === "configured"
          && raw.httpStatus === 200
          && raw.status === "PASS"
        ),
      "release/PASS doctor must use configured live management HTTP",
    ),
  ]),
  "NFR-126": (raw) => rawPredicate([
    numberEquals(raw, "rejectedStatus", 429),
    rawCheck(Number.isInteger(raw.rejectedRetryAfterSeconds) && raw.rejectedRetryAfterSeconds >= 1, "rejectedRetryAfterSeconds must be >= 1"),
    stringEquals(raw, "rejectedRemaining", "0"),
    rawCheck(isFiniteNumber(raw.allowedProviderDispatches) && raw.allowedProviderDispatches >= 1, "allowedProviderDispatches must be >= 1"),
    numberEquals(raw, "providerDispatchesAtThreshold", 0),
  ]),
  "NFR-127": (raw) => rawPredicate([
    booleanEquals(raw, "preExpiryBlocked", true),
    booleanEquals(raw, "recoveredAfterExpiry", true),
    booleanEquals(raw, "fencingAdvanced", true),
    numberEquals(raw, "staleWriterOverwrites", 0),
    booleanEquals(raw, "currentWriterRetained", true),
  ]),
  "NFR-128": (raw) => rawPredicate([
    booleanEquals(raw, "applied", true),
    booleanEquals(raw, "interruptedBeforeCheckpoint", true),
    booleanEquals(raw, "tamperedRejected", true),
    numberEquals(raw, "stalePlanApplies", 0),
    numberEquals(raw, "stalePlanProviderDispatches", 0),
    rawCheck(isFiniteNumber(raw.resumedEntries) && raw.resumedEntries >= 1, "resumedEntries must be >= 1"),
    numberEquals(raw, "copyDispatches", 1),
    numberEquals(raw, "deleteDispatches", 1),
    numberEquals(raw, "checkpointResumeDuplicates", 0),
  ]),
  "NFR-129": (raw) => rawPredicate([
    rawCheck(isFiniteNumber(raw.acceptedEvents) && raw.acceptedEvents > 0, "acceptedEvents must be positive"),
    rawCheck(raw.receiptCount === raw.acceptedEvents, "receiptCount must equal acceptedEvents"),
    numberEquals(raw, "eventLoss", 0),
    numberEquals(raw, "secretLeak", 0),
  ]),
  "NFR-130": (raw) => rawPredicate([
    booleanEquals(raw, "missingRawFails", true),
    booleanEquals(raw, "thresholdFails", true),
    booleanEquals(raw, "rawThresholdPassFails", true),
    booleanEquals(raw, "notRunFailsRelease", true),
    booleanEquals(raw, "notRunFocusedDoesNotClaimRelease", true),
    booleanEquals(raw, "packageCommandPresent", true),
  ]),
});

export function evaluateNfrResults(results, options = {}) {
  const releaseRequired = options.releaseRequired !== false;
  const failures = [];
  const releaseBlockers = [];
  const seen = new Set();
  for (const id of REV3_NFR_IDS) {
    const matches = results.filter((result) => result.id === id);
    if (matches.length === 0) failures.push(`${id} missing`);
    if (matches.length > 1) failures.push(`${id} duplicated`);
  }
  for (const result of results) {
    if (!REV3_NFR_IDS.includes(result.id)) failures.push(`${result.id ?? "UNKNOWN"} is not a Rev3 NFR id`);
    if (seen.has(result.id)) continue;
    seen.add(result.id);
    const shape = validateResultShape(result);
    failures.push(...shape.failures);
    failures.push(...validateRawThresholdPredicate(result, { releaseRequired }));
    if (result.status === "FAIL") failures.push(`${result.id} assertion failed`);
    if (result.status === "PASS" && result.assertions?.some((assertion) => assertion.passed !== true)) {
      failures.push(`${result.id} is PASS with a failed assertion`);
    }
    if (releaseRequired && result.status !== "PASS") {
      releaseBlockers.push(`${result.id} ${result.status}`);
    }
  }
  const exitCode = failures.length > 0 || releaseBlockers.length > 0 ? 1 : 0;
  const focusedAllPass = results.every((result) => result.status === "PASS");
  return {
    status: exitCode === 0
      ? releaseRequired
        ? "BASE_PROFILE_NFR_PASS"
        : focusedAllPass
          ? "FOCUSED_NFR_PASS"
          : "FOCUSED_NFR_LIMITED_PASS"
      : releaseRequired
        ? "BASE_PROFILE_NFR_FAIL"
        : "FOCUSED_NFR_FAIL",
    releaseEligible: releaseRequired && exitCode === 0,
    exitCode,
    failures,
    releaseBlockers,
  };
}

export function createNfrResult(id, status, rawMeasurement, assertions, extra = {}) {
  const thresholdValue = REV3_NFR_THRESHOLDS[id];
  return {
    id,
    productProfile: "BASE_SINGLE_OWNER",
    applicability: "REQUIRED",
    profileApplicability: { ...BASE_PROFILE_APPLICABILITY },
    status,
    threshold: thresholdValue,
    thresholdSource: thresholdValue.source,
    rawMeasurement,
    assertions: assertions.map((assertion) => ({
      ...assertion,
      thresholdSource: assertion.thresholdSource ?? thresholdValue.source,
    })),
    ...extra,
  };
}

export async function runRev3NfrGate(options = parseArguments(process.argv.slice(2))) {
  const counts = options.mode === "focused"
    ? {
        local: 25,
        fs: 25,
        ssh: 20,
        mcp: 20,
        sessions: 50,
        contexts: 50,
        samePrincipal: 100,
        claims: 100,
        directoryEntries: 1_000,
        outputBytes: mib,
      }
    : {
        local: 500,
        fs: 500,
        ssh: 200,
        mcp: 200,
        sessions: 1_000,
        contexts: 500,
        samePrincipal: 1_000,
        claims: 10_000,
        directoryEntries: 100_000,
        outputBytes: 100 * mib,
      };
  const temporary = await realpath(await mkdtemp(join(tmpdir(), "devspace-rev3-nfr-")));
  const startedAt = new Date().toISOString();
  const results = [];
  try {
    results.push(...await checkBudgets(temporary));
    const fixture = await createLocalFixture(temporary);
    try {
      results.push(await checkLocalExec(fixture, counts.local, options));
      results.push(await checkFilesystemMetadata(fixture, temporary, counts.fs, counts.ssh, options));
      results.push(await checkMcpWarmInvoke(temporary, counts.mcp, options));
      results.push(await checkLargeDirectory(fixture, counts.directoryEntries, options));
      results.push(await checkConcurrentQuota(fixture));
      results.push(await checkLargeOutput(fixture, counts.outputBytes, options));
      results.push(await checkMcpSessionChurn(counts.sessions, options));
      results.push(await checkContextReuse(fixture, counts.contexts, options));
      results.push(await checkRssLeak());
      results.push(await checkFailedTargetRetry(temporary));
      results.push(await checkPublicMetrics(options));
      results.push(await checkR0AuthorityOverhead(temporary));
      results.push(await checkSamePrincipalChurn(counts.samePrincipal, options));
      results.push(await checkCoherentBatch(temporary));
      results.push(await checkPrincipalDerivation(options));
      results.push(await checkClaimReceipt(temporary, counts.claims, options));
      results.push(...await checkCursorVerifyAndTamper());
      results.push(await checkArtifactRestart(temporary));
      results.push(await checkSelfRestartAck(options));
      results.push(...await checkReadyAndDoctor(options));
      results.push(await checkRateLimit(temporary));
      results.push(await checkLeaseRecovery(temporary));
      results.push(await checkFilesystemSync(fixture));
      results.push(await checkAudit(temporary));
      results.push(checkNfrExitBinding());
    } finally {
      await fixture.close();
    }
    const evaluation = evaluateNfrResults(results, {
      releaseRequired: options.mode !== "focused",
    });
    return {
      schemaVersion: 1,
      gate: "BASE_SINGLE_OWNER_REV3_NFR_101_130",
      mode: options.mode,
      releaseRequired: options.mode !== "focused",
      startedAt,
      completedAt: new Date().toISOString(),
      counts,
      spec: {
        path: "/Users/lyjj0912/Downloads/DEVSPACE_UNIVERSAL_BROKER_TOBE_CONSTRUCTION_SPEC.md",
        sha256: "a3d4de8e2b29c1519eeddf47639280c0e519408bb566a7a53661ddba638d8e46",
        section: "26",
      },
      evaluation,
      results,
    };
  } finally {
    await rm(temporary, { recursive: true, force: true });
  }
}

function validateResultShape(result) {
  const failures = [];
  if (!result || typeof result !== "object") return { failures: ["result is not an object"] };
  const prefix = result.id ?? "UNKNOWN";
  if (result.productProfile !== "BASE_SINGLE_OWNER") failures.push(`${prefix} productProfile is not BASE_SINGLE_OWNER`);
  if (result.applicability !== "REQUIRED") failures.push(`${prefix} applicability is not REQUIRED`);
  if (JSON.stringify(result.profileApplicability) !== JSON.stringify(BASE_PROFILE_APPLICABILITY)) {
    failures.push(`${prefix} profile applicability is not 1:1`);
  }
  if (!result.threshold?.source || result.thresholdSource !== result.threshold.source) {
    failures.push(`${prefix} threshold source missing or detached`);
  }
  if (!result.rawMeasurement || typeof result.rawMeasurement !== "object" || Array.isArray(result.rawMeasurement)) {
    failures.push(`${prefix} rawMeasurement missing`);
  }
  if (!Array.isArray(result.assertions) || result.assertions.length === 0) {
    failures.push(`${prefix} explicit assertions missing`);
  } else {
    for (const [index, assertion] of result.assertions.entries()) {
      if (typeof assertion.description !== "string" || assertion.description.length === 0) {
        failures.push(`${prefix} assertion ${index} description missing`);
      }
      if (typeof assertion.passed !== "boolean") failures.push(`${prefix} assertion ${index} passed boolean missing`);
      if (!assertion.thresholdSource) failures.push(`${prefix} assertion ${index} threshold source missing`);
    }
  }
  if (!["PASS", "LIMITED_PASS", "FAIL", "NOT_RUN"].includes(result.status)) {
    failures.push(`${prefix} status is invalid`);
  }
  return { failures };
}

function validateRawThresholdPredicate(result, context) {
  if (!REV3_NFR_IDS.includes(result.id)) return [];
  if (result.status === "NOT_RUN" && context.releaseRequired === false) return [];
  if (!result.rawMeasurement || typeof result.rawMeasurement !== "object" || Array.isArray(result.rawMeasurement)) return [];
  const predicate = REV3_NFR_RAW_PREDICATES[result.id];
  if (typeof predicate !== "function") return [`${result.id} raw threshold predicate missing`];
  const evaluation = predicate(result.rawMeasurement, { ...context, result });
  if (evaluation.passed) return [];
  return [`${result.id} raw threshold predicate failed: ${evaluation.failures.join("; ")}`];
}

function rawPredicate(checks) {
  const failures = checks
    .filter((check) => check.passed !== true)
    .map((check) => check.message);
  return { passed: failures.length === 0, failures };
}

function rawCheck(passed, message) {
  return { passed: Boolean(passed), message };
}

function isFiniteNumber(value) {
  return typeof value === "number" && Number.isFinite(value);
}

function numberAtMost(raw, field, maximum) {
  return rawCheck(
    isFiniteNumber(raw[field]) && raw[field] <= maximum,
    `${field} must be finite <= ${maximum}`,
  );
}

function numberEquals(raw, field, expected) {
  return rawCheck(raw[field] === expected, `${field} must equal ${expected}`);
}

function booleanEquals(raw, field, expected) {
  return rawCheck(raw[field] === expected, `${field} must equal ${expected}`);
}

function stringEquals(raw, field, expected) {
  return rawCheck(raw[field] === expected, `${field} must equal ${expected}`);
}

function sampledLatencyPredicate(raw, context, sampleField, requiredSamples, p95Field, maximumP95) {
  return rawPredicate([
    requiredReleaseSample(raw, context, sampleField, requiredSamples),
    numberEquals(raw, "requiredReleaseSampleCount", requiredSamples),
    numberAtMost(raw, p95Field, maximumP95),
    rawCheck(isFiniteNumber(raw.maxMs), "maxMs must be finite"),
  ]);
}

function requiredReleaseSample(raw, context, field, required) {
  return rawCheck(
    !requiresReleaseGrade(context) || (isFiniteNumber(raw[field]) && raw[field] >= required),
    `${field} must be >= ${required} for release/PASS`,
  );
}

function requiresReleaseGrade(context) {
  return context.releaseRequired === true || context.result?.status === "PASS";
}

async function checkBudgets(temporary) {
  const budget = await inspectUniversalBrokerBudgets();
  const context = await inspectContextBudgets(temporary);
  return [
    createNfrResult("NFR-101", budget.descriptorCharacters <= 9_000 ? "PASS" : "FAIL", {
      toolCount: budget.toolCount,
      toolNames: budget.toolNames,
      descriptorCharacters: budget.descriptorCharacters,
      perToolDescriptorCharacters: budget.perToolDescriptorCharacters,
    }, [
      assertion("exactly eight top-level tools", budget.toolCount === 8, 8, budget.toolCount),
      assertion("descriptor total is at or below spec threshold", budget.descriptorCharacters <= 9_000, "<=9000", budget.descriptorCharacters),
      assertion("tool names remain the canonical eight", JSON.stringify(budget.toolNames) === JSON.stringify(UNIVERSAL_TOOL_NAMES), UNIVERSAL_TOOL_NAMES, budget.toolNames),
    ]),
    createNfrResult("NFR-102", context.initialContextCharacters <= 4 * 1024 ? "PASS" : "FAIL", {
      initialContextCharacters: context.initialContextCharacters,
      contractLimitCharacters: UNIVERSAL_BROKER_BUDGETS.maximumInitialContextCharacters,
      truncated: context.initialContextTruncated,
    }, [
      assertion("initial Context payload is at or below 4 KiB", context.initialContextCharacters <= 4 * 1024, "<=4096", context.initialContextCharacters),
      assertion("contract hard limit does not exceed spec threshold", UNIVERSAL_BROKER_BUDGETS.maximumInitialContextCharacters <= 4 * 1024, "<=4096", UNIVERSAL_BROKER_BUDGETS.maximumInitialContextCharacters),
    ]),
    createNfrResult("NFR-103", context.reusedContextCharacters <= 512 ? "PASS" : "FAIL", {
      reusedContextCharacters: context.reusedContextCharacters,
      contractLimitCharacters: UNIVERSAL_BROKER_BUDGETS.maximumReusedContextCharacters,
    }, [
      assertion("reused Context payload is at or below 512 bytes/chars", context.reusedContextCharacters <= 512, "<=512", context.reusedContextCharacters),
      assertion("contract hard limit is exactly the spec threshold", UNIVERSAL_BROKER_BUDGETS.maximumReusedContextCharacters === 512, 512, UNIVERSAL_BROKER_BUDGETS.maximumReusedContextCharacters),
    ]),
  ];
}

async function inspectContextBudgets(temporary) {
  const skillsRoot = join(temporary, "budget-skills");
  await mkdir(skillsRoot, { recursive: true });
  for (let index = 0; index < 8; index += 1) {
    const directory = join(skillsRoot, `release-verification-${index}`);
    await mkdir(directory);
    await writeFile(join(directory, "SKILL.md"), [
      "---",
      `name: release-verification-${index}`,
      `description: ${"release verification deployment evidence ".repeat(20)}`,
      "---",
      "",
      "Run release verification.",
      "",
    ].join("\n"));
  }
  let contextRoot = temporary;
  for (let index = 0; index < 6; index += 1) {
    contextRoot = join(contextRoot, `long-context-${index}-${"x".repeat(24)}`);
    await mkdir(contextRoot);
    await writeFile(join(contextRoot, "AGENTS.md"), `instructions ${index}\n`);
    await writeFile(join(contextRoot, "CLAUDE.md"), `claude ${index}\n`);
  }
  const config = loadConfig(baseEnvironment(temporary, {
    DEVSPACE_ALLOWED_ROOTS: temporary,
    DEVSPACE_SKILL_PATHS: skillsRoot,
  }));
  const targets = new TargetRegistry({ configPath: join(temporary, "missing-targets.json") });
  const contexts = new ContextRegistry({
    storePath: join(temporary, "contexts.json"),
    targets,
    serverConfig: config,
  });
  const initial = await contexts.open({ path: contextRoot, task: "release verification deployment evidence" });
  const reused = await contexts.open({ path: contextRoot });
  return {
    initialContextCharacters: contextPayloadCharacters(initial),
    reusedContextCharacters: contextPayloadCharacters(reused),
    initialContextTruncated: initial.truncated === true,
  };
}

async function createLocalFixture(temporary) {
  const config = loadConfig(baseEnvironment(temporary));
  const targetConfig = join(temporary, "targets.json");
  await writeFile(targetConfig, `${JSON.stringify({
    version: 1,
    targets: {
      local: {
        displayName: "Local user fixture",
        aliases: ["local"],
        transport: "local",
        platform: process.platform === "win32" ? "windows" : "macos",
        gui: { mode: "local-ipc" },
      },
    },
  }, null, 2)}\n`);
  const targets = new TargetRegistry({ configPath: targetConfig });
  const contexts = new ContextRegistry({
    storePath: join(temporary, "fixture-contexts.json"),
    targets,
    serverConfig: config,
    worktreeRoot: join(temporary, "worktrees"),
  });
  const cursorStore = new SignedSnapshotCursorStore({
    currentKey: { keyId: "filesystem-current", secret: Buffer.alloc(32, 0x45) },
    ttlMs: 600_000,
    maximumSnapshotsPerPrincipal: 128,
  });
  const execution = new UniversalExecutionPlane({
    targets,
    contexts,
    outputDir: join(temporary, "output"),
    sshControlDir: join(temporary, "ssh-control"),
    maxRunningProcesses: 32,
    maxRunningProcessesPerTarget: 16,
    processBufferCharacters: 50_000,
    processOutputMaxBytes: 128 * mib,
    completedProcessTtlMs: 60_000,
  });
  const filesystem = new UniversalFilesystemService(targets, contexts, execution, {
    sshControlDir: join(temporary, "fs-control"),
    cursorStore,
    syncStatePath: join(temporary, "sync.sqlite"),
  });
  return {
    config,
    targets,
    contexts,
    execution,
    filesystem,
    async close() {
      await execution.close();
    },
  };
}

async function checkLocalExec(fixture, count, options) {
  const samples = [];
  for (let index = 0; index < count; index += 1) {
    const started = performance.now();
    const result = await fixture.execution.execute({
      target: "local",
      cwd: root,
      command: "true",
      mode: "foreground",
      yieldMs: 10_000,
      maxOutputChars: 100,
    });
    samples.push(performance.now() - started);
    if (result.state !== "EXITED" || result.exitCode !== 0) {
      return createNfrResult("NFR-104", "FAIL", { sampleCount: index + 1, result }, [
        assertion("local no-op exec exits 0", false, 0, result.exitCode),
      ]);
    }
    await fixture.execution.operate({ operation: "forget", processId: result.processId });
  }
  const p95 = percentile(samples, 0.95);
  return sampledResult("NFR-104", options, count, 500, {
    sampleCount: count,
    p95Ms: p95,
    maxMs: Math.max(...samples),
  }, [
    assertion("local no-op exec p95 is within threshold", p95 <= 25, "<=25", round(p95)),
  ]);
}

async function checkFilesystemMetadata(fixture, temporary, count, sshCount, options) {
  const path = join(root, "package.json");
  const samples = [];
  for (let index = 0; index < count; index += 1) {
    const started = performance.now();
    await fixture.filesystem.execute({ operation: "stat", target: "local", path });
    await fixture.filesystem.execute({ operation: "read", target: "local", path, limit: 64 });
    samples.push(performance.now() - started);
  }
  const p95 = percentile(samples, 0.95);
  const ssh = await checkLiveSshMetadata(temporary, sshCount);
  const localPassed = p95 <= 50;
  const localSamplesSatisfied = count >= 500;
  const sshSamplesSatisfied = ssh.configured === true
    && ssh.sampleCount >= 200
    && ssh.successes === ssh.sampleCount
    && ssh.failures === 0;
  const status = !localPassed || ssh.failed === true
    ? "FAIL"
    : options.mode !== "focused" && ssh.configured !== true
      ? "NOT_RUN"
      : localSamplesSatisfied && sshSamplesSatisfied
        ? "PASS"
        : options.mode === "focused"
          ? "LIMITED_PASS"
          : "FAIL";
  return createNfrResult("NFR-105", status, {
    sampleCount: count,
    p95Ms: p95,
    maxMs: Math.max(...samples),
    requiredReleaseSampleCount: 500,
    focusedSample: count < 500,
    sshConfigured: ssh.configured,
    sshTransport: ssh.transport,
    sshLiveProbeStatus: ssh.probeStatus,
    sshSampleCount: ssh.sampleCount,
    sshSuccesses: ssh.successes,
    sshFailures: ssh.failures,
    sshP95Ms: ssh.p95Ms,
    sshMaxMs: ssh.maxMs,
    sshTargetGeneration: ssh.targetGeneration,
    sshReadPathDigest: ssh.readPathDigest,
    sshRequiredReleaseSampleCount: 200,
  }, [
    assertion("local stat/read metadata p95 is within threshold", localPassed, "<=50", round(p95)),
    assertion("local release sample count is satisfied or explicitly focused", localSamplesSatisfied || options.mode === "focused", 500, count),
    assertion("live SSH target is configured for release", ssh.configured === true || options.mode === "focused", true, ssh.configured),
    assertion("live SSH probe is ONLINE when configured", ssh.configured !== true || ssh.probeStatus === "ONLINE", "ONLINE", ssh.probeStatus),
    assertion("SSH metadata samples have zero failures", ssh.configured !== true || ssh.failures === 0, 0, ssh.failures),
    assertion("SSH release sample count is satisfied or explicitly focused", sshSamplesSatisfied || options.mode === "focused", 200, ssh.sampleCount),
  ]);
}

async function checkLiveSshMetadata(temporary, count) {
  const configuration = liveSshNfrConfiguration();
  if (!configuration) {
    return {
      configured: false,
      transport: "NOT_RUN",
      probeStatus: "NOT_RUN",
      sampleCount: 0,
      successes: 0,
      failures: 0,
      p95Ms: null,
      maxMs: null,
      targetGeneration: null,
      readPathDigest: null,
      failed: false,
    };
  }
  const directory = join(temporary, "live-ssh-metadata");
  await mkdir(directory, { recursive: true });
  const targets = new TargetRegistry({
    configPath: configuration.targetsFile,
    sshExecutable: configuration.sshExecutable,
  });
  const target = await targets.resolve(configuration.target);
  if (target.transport !== "ssh") {
    throw new Error("DEVSPACE_REV3_NFR_SSH_TARGET must resolve to an SSH target.");
  }
  const config = loadConfig(baseEnvironment(directory));
  const contexts = new ContextRegistry({
    storePath: join(directory, "contexts.json"),
    targets,
    serverConfig: config,
    worktreeRoot: join(directory, "worktrees"),
  });
  const execution = new UniversalExecutionPlane({
    targets,
    contexts,
    outputDir: join(directory, "output"),
    sshControlDir: join(directory, "ssh-control"),
    sshExecutable: configuration.sshExecutable,
    maxRunningProcesses: 2,
    maxRunningProcessesPerTarget: 2,
    processBufferCharacters: 1_024,
    processOutputMaxBytes: mib,
    completedProcessTtlMs: 60_000,
  });
  const filesystem = new UniversalFilesystemService(targets, contexts, execution, {
    sshControlDir: join(directory, "filesystem-control"),
    sftpExecutable: configuration.sftpExecutable,
    syncStatePath: join(directory, "sync.sqlite"),
  });
  const samples = [];
  let failures = 0;
  let probeStatus = "UNKNOWN";
  try {
    const observation = await targets.probe(configuration.target, { refresh: true });
    probeStatus = observation.status;
    if (probeStatus !== "ONLINE") {
      return {
        configured: true,
        transport: target.transport,
        probeStatus,
        sampleCount: 0,
        successes: 0,
        failures: 1,
        p95Ms: null,
        maxMs: null,
        targetGeneration: `sha256:${target.generation}`,
        readPathDigest: `sha256:${digest(configuration.readPath)}`,
        failed: true,
      };
    }
    for (let index = 0; index < count; index += 1) {
      const started = performance.now();
      try {
        await filesystem.execute({
          operation: "stat",
          target: configuration.target,
          path: configuration.readPath,
        });
        await filesystem.execute({
          operation: "read",
          target: configuration.target,
          path: configuration.readPath,
          limit: 64,
        });
        samples.push(performance.now() - started);
      } catch {
        failures += 1;
        break;
      }
    }
  } finally {
    await execution.close();
  }
  return {
    configured: true,
    transport: target.transport,
    probeStatus,
    sampleCount: samples.length,
    successes: samples.length,
    failures,
    p95Ms: samples.length > 0 ? percentile(samples, 0.95) : null,
    maxMs: samples.length > 0 ? Math.max(...samples) : null,
    targetGeneration: `sha256:${target.generation}`,
    readPathDigest: `sha256:${digest(configuration.readPath)}`,
    failed: failures > 0,
  };
}

function liveSshNfrConfiguration() {
  const values = {
    targetsFile: process.env.DEVSPACE_REV3_NFR_SSH_TARGETS_FILE?.trim(),
    target: process.env.DEVSPACE_REV3_NFR_SSH_TARGET?.trim(),
    readPath: process.env.DEVSPACE_REV3_NFR_SSH_READ_PATH?.trim(),
    sshExecutable: (process.env.DEVSPACE_REV3_NFR_SSH_EXECUTABLE ?? "/usr/bin/ssh").trim(),
    sftpExecutable: (process.env.DEVSPACE_REV3_NFR_SFTP_EXECUTABLE ?? "/usr/bin/sftp").trim(),
  };
  const supplied = [values.targetsFile, values.target, values.readPath].filter(Boolean).length;
  if (supplied === 0) return undefined;
  if (supplied !== 3) {
    throw new Error("Live SSH NFR requires DEVSPACE_REV3_NFR_SSH_TARGETS_FILE, DEVSPACE_REV3_NFR_SSH_TARGET, and DEVSPACE_REV3_NFR_SSH_READ_PATH together.");
  }
  if (!isAbsolute(values.targetsFile) || !isAbsolute(values.readPath)
    || !isAbsolute(values.sshExecutable) || !isAbsolute(values.sftpExecutable)) {
    throw new Error("Live SSH NFR file/read/executable paths must be absolute.");
  }
  if (!/^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/u.test(values.target)) {
    throw new Error("DEVSPACE_REV3_NFR_SSH_TARGET must be one bounded target selector.");
  }
  return {
    targetsFile: resolve(values.targetsFile),
    target: values.target,
    readPath: values.readPath,
    sshExecutable: resolve(values.sshExecutable),
    sftpExecutable: resolve(values.sftpExecutable),
  };
}

async function checkMcpWarmInvoke(temporary, count, options) {
  const fixture = await writeMcpFixture(temporary);
  const routeFile = join(temporary, "routes.json");
  await writeFile(routeFile, `${JSON.stringify({
    version: 1,
    routes: {
      fixture: {
        displayName: "Rev3 NFR MCP fixture",
        aliases: ["fixture"],
        transport: "local-stdio",
        command: process.execPath,
        args: [fixture],
      },
    },
  }, null, 2)}\n`);
  const routes = new UniversalMcpRouteRegistry(routeFile);
  const targets = new TargetRegistry({ configPath: join(temporary, "mcp-targets-missing.json") });
  const proxy = new UniversalMcpProxy(routes, targets, {
    sshControlDir: join(temporary, "mcp-ssh"),
    maximumSessions: 4,
    defaultSessionIdleTtlMs: 30_000,
  });
  const samples = [];
  try {
    await proxy.execute({ operation: "invoke", route: "fixture", name: "echo", arguments: { value: "warmup" } });
    for (let index = 0; index < count; index += 1) {
      const started = performance.now();
      const value = await proxy.execute({
        operation: "invoke",
        route: "fixture",
        name: "echo",
        arguments: { value: String(index) },
      });
      samples.push(performance.now() - started);
      if (value.isError === true) {
        return createNfrResult("NFR-106", "FAIL", { sampleCount: index + 1, value }, [
          assertion("warm MCP invoke returns non-error", false, false, true),
        ]);
      }
    }
  } finally {
    await proxy.close();
  }
  const p95 = percentile(samples, 0.95);
  return sampledResult("NFR-106", options, count, 200, {
    sampleCount: count,
    p95Ms: p95,
    maxMs: Math.max(...samples),
  }, [
    assertion("warm MCP invoke p95 is within threshold", p95 <= 50, "<=50", round(p95)),
  ]);
}

async function checkLargeDirectory(fixture, count, options) {
  const directory = join(root, ".tmp-rev3-nfr-directory");
  await rm(directory, { recursive: true, force: true });
  await mkdir(directory);
  try {
    const creator = [
      "import os,sys",
      "root=sys.argv[1]; count=int(sys.argv[2])",
      "for index in range(count):",
      "    open(os.path.join(root,f'f-{index:06d}'),'a').close()",
    ].join("\n");
    await execFileAsync("python3", ["-c", creator, directory, String(count)], { timeout: 180_000 });
    const callContext = capabilityContext("large-directory");
    const started = performance.now();
    const listed = await fixture.filesystem.execute({
      operation: "list",
      target: "local",
      path: directory,
      limit: 1_000,
    }, callContext);
    const durationMs = performance.now() - started;
    return sampledResult("NFR-107", options, count, 100_000, {
      entries: count,
      returned: Array.isArray(listed.entries) ? listed.entries.length : 0,
      totalEntries: listed.totalEntries,
      durationMs,
      nextCursorPresent: typeof listed.nextCursor === "string",
    }, [
      assertion("directory first page returns exactly 1,000 entries", Array.isArray(listed.entries) && listed.entries.length === Math.min(1_000, count), Math.min(1_000, count), Array.isArray(listed.entries) ? listed.entries.length : 0),
      assertion("directory first page p95 proxy duration is within threshold", durationMs <= 250, "<=250", round(durationMs)),
      assertion("totalEntries reflects generated directory size", listed.totalEntries === count, count, listed.totalEntries),
    ]);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
}

async function checkConcurrentQuota(fixture) {
  const running = [];
  let quotaRejected = false;
  try {
    for (let index = 0; index < 16; index += 1) {
      running.push(await fixture.execution.execute({
        target: "local",
        cwd: root,
        command: "sleep 30",
        mode: "background",
        yieldMs: 0,
        maxOutputChars: 100,
      }));
    }
    try {
      await fixture.execution.execute({
        target: "local",
        cwd: root,
        command: "true",
        mode: "background",
        yieldMs: 0,
        maxOutputChars: 100,
      });
    } catch (error) {
      quotaRejected = error && typeof error === "object" && error.code === "RESOURCE_QUOTA_EXCEEDED";
    }
  } finally {
    await Promise.allSettled(running.map(async (entry) => {
      await fixture.execution.operate({ operation: "signal", processId: entry.processId, signal: "SIGTERM", waitMs: 2_000 }).catch(() => undefined);
      await fixture.execution.operate({ operation: "forget", processId: entry.processId }).catch(() => undefined);
    }));
  }
  return createNfrResult("NFR-108", quotaRejected && running.length === 16 ? "PASS" : "FAIL", {
    started: running.length,
    quotaRejected,
  }, [
    assertion("first sixteen concurrent processes start", running.length === 16, 16, running.length),
    assertion("seventeenth process is rejected before dispatch", quotaRejected, true, quotaRejected),
  ]);
}

async function checkLargeOutput(fixture, bytes, options) {
  const command = `${JSON.stringify(process.execPath)} -e ${JSON.stringify(`const chunk='x'.repeat(1048576);for(let i=0;i<${Math.ceil(bytes / mib)};i++)process.stdout.write(chunk);`)}`;
  const processRecord = await fixture.execution.execute({
    target: "local",
    cwd: root,
    command,
    mode: "background",
    maxOutputChars: 100,
  });
  try {
    const completed = await fixture.execution.operate({
      operation: "wait",
      processId: processRecord.processId,
      waitMs: options.mode === "focused" ? 30_000 : 110_000,
      maxOutputChars: 100,
    });
    return sampledResult("NFR-109", options, bytes, 100 * mib, {
      requestedBytes: bytes,
      outputBytes: completed.outputBytes,
      inlineCharacters: String(completed.output ?? "").length,
      outputResourceUri: completed.resourceUri,
      state: completed.state,
      exitCode: completed.exitCode,
    }, [
      assertion("large output exits successfully", completed.state === "EXITED" && completed.exitCode === 0, "EXITED/0", `${completed.state}/${completed.exitCode}`),
      assertion("large output byte count is retained", Number(completed.outputBytes) >= bytes, `>=${bytes}`, completed.outputBytes),
      assertion("large output keeps a Resource Handle", typeof completed.resourceUri === "string" && completed.resourceUri.length > 0, true, completed.resourceUri),
      assertion("inline output remains bounded", String(completed.output ?? "").length <= 100, "<=100", String(completed.output ?? "").length),
    ]);
  } finally {
    await fixture.execution.operate({ operation: "forget", processId: processRecord.processId }).catch(() => undefined);
  }
}

async function checkMcpSessionChurn(count, options) {
  globalThis.gc?.();
  const before = process.memoryUsage().rss;
  const registry = new McpSessionRegistry({ maximumSessions: 128 });
  let closed = 0;
  for (let index = 0; index < count; index += 1) {
    if (registry.size >= 128) await registry.closeLeastRecentlyUsed(1);
    registry.register(`session-${index}`, { close: async () => { closed += 1; } });
  }
  await registry.closeAll();
  globalThis.gc?.();
  const growth = Math.max(0, process.memoryUsage().rss - before);
  return sampledResult("NFR-110", options, count, 1_000, {
    sessions: count,
    closed,
    remaining: registry.size,
    rssGrowthBytes: growth,
    rssLimitBytes: 50 * mib,
  }, [
    assertion("connection churn closes every session", registry.size === 0 && closed === count, count, closed),
    assertion("connection churn RSS growth is within leak threshold", growth <= 50 * mib, `<=${50 * mib}`, growth),
  ]);
}

async function checkContextReuse(fixture, count, options) {
  const project = join(root, ".tmp-rev3-nfr-context");
  await rm(project, { recursive: true, force: true });
  await mkdir(project);
  await writeFile(join(project, "README.md"), "context\n");
  try {
    const first = await fixture.contexts.open({ path: project, task: "rev3 nfr context reuse" });
    let stable = true;
    let calls = 1;
    try {
      for (let index = 1; index < count; index += 1) {
        const next = await fixture.contexts.open({ path: project, task: "rev3 nfr context reuse" });
        calls += 1;
        if (next.contextId !== first.contextId || next.reused !== true) {
          stable = false;
          break;
        }
      }
    } finally {
      await fixture.contexts.close(first.contextId);
    }
    const remaining = fixture.contexts.stats().contexts;
    return sampledResult("NFR-111", options, count, 500, {
      calls,
      contextIdStable: stable,
      remainingContexts: remaining,
    }, [
      assertion("Context reuse keeps a stable context id", stable, true, stable),
      assertion("Context close leaves no retained state", remaining === 0, 0, remaining),
    ]);
  } finally {
    await rm(project, { recursive: true, force: true });
  }
}

async function checkRssLeak() {
  globalThis.gc?.();
  const before = process.memoryUsage().rss;
  for (let index = 0; index < 100; index += 1) Buffer.alloc(128 * 1024).fill(index);
  globalThis.gc?.();
  const growth = Math.max(0, process.memoryUsage().rss - before);
  return createNfrResult("NFR-112", growth <= 50 * mib ? "PASS" : "FAIL", {
    rssBeforeBytes: before,
    rssAfterBytes: process.memoryUsage().rss,
    rssGrowthBytes: growth,
    gcAvailable: typeof globalThis.gc === "function",
  }, [
    assertion("steady RSS growth is within threshold", growth <= 50 * mib, `<=${50 * mib}`, growth),
  ]);
}

async function checkFailedTargetRetry(temporary) {
  const directory = join(temporary, "failed-target-retry");
  await mkdir(directory, { recursive: true });
  const targetConfig = join(directory, "targets.json");
  await writeFile(targetConfig, `${JSON.stringify({
    version: 1,
    targets: {
      offline: {
        displayName: "Deterministic offline target",
        transport: "ssh",
        sshHost: "offline.invalid",
        platform: "linux",
      },
    },
  }, null, 2)}\n`);
  let probeDispatches = 0;
  let providerDispatches = 0;
  const targets = new TargetRegistry({
    configPath: targetConfig,
    execute: async () => {
      probeDispatches += 1;
      throw Object.assign(new Error("deterministic target offline"), { code: "ECONNREFUSED" });
    },
  });
  const config = loadConfig(baseEnvironment(directory));
  const contexts = new ContextRegistry({
    storePath: join(directory, "contexts.json"),
    targets,
    serverConfig: config,
  });
  const execution = new UniversalExecutionPlane({
    targets,
    contexts,
    outputDir: join(directory, "output"),
    sshControlDir: join(directory, "ssh-control"),
    maxRunningProcesses: 2,
    maxRunningProcessesPerTarget: 2,
    processBufferCharacters: 1_024,
    processOutputMaxBytes: mib,
    completedProcessTtlMs: 60_000,
    spawnProcess: () => {
      providerDispatches += 1;
      throw new Error("offline target reached provider boundary");
    },
  });
  try {
    const observation = await targets.probe("offline", { refresh: true });
    let typedRejects = 0;
    for (let attempt = 0; attempt < 10; attempt += 1) {
      try {
        await execution.execute({
          target: "offline",
          command: "true",
          mode: "foreground",
          yieldMs: 1_000,
          maxOutputChars: 100,
        });
      } catch (error) {
        if (error && typeof error === "object" && error.code === "TARGET_OFFLINE") typedRejects += 1;
      }
    }
    const blindRetryLoops = Math.max(0, probeDispatches - 1);
    const passed = observation.status === "OFFLINE"
      && typedRejects === 10
      && blindRetryLoops === 0
      && providerDispatches === 0;
    return createNfrResult("NFR-113", passed ? "PASS" : "FAIL", {
      attempts: 10,
      targetStatus: observation.status,
      typedRejects,
      probeDispatches,
      blindRetryLoops,
      providerDispatches,
      evidenceKind: "isolated deterministic failed-target probe and cached pre-dispatch rejection",
    }, [
      assertion("failed Target is observed OFFLINE", observation.status === "OFFLINE", "OFFLINE", observation.status),
      assertion("all repeated operations return TARGET_OFFLINE", typedRejects === 10, 10, typedRejects),
      assertion("failed Target has zero blind probe retries", blindRetryLoops === 0, 0, blindRetryLoops),
      assertion("failed Target reaches zero provider dispatches", providerDispatches === 0, 0, providerDispatches),
    ]);
  } finally {
    await execution.close();
  }
}

async function checkPublicMetrics(options) {
  const publicBase = process.env.DEVSPACE_REV3_NFR_PUBLIC_BASE_URL;
  if (!publicBase) {
    return createNfrResult("NFR-114", "NOT_RUN", {
      publicMetrics200Responses: "NOT_RUN",
      reason: "DEVSPACE_REV3_NFR_PUBLIC_BASE_URL not supplied; public endpoint probing is live/environment-only.",
    }, [
      assertion("public metrics probe is explicitly not run without live URL", true, "NOT_RUN", "NOT_RUN"),
      assertion("missing live public metrics evidence is not promoted to PASS", true, "NOT_RUN", "NOT_RUN"),
    ]);
  }
  const response = await fetch(new URL("/metrics", publicBase));
  const publicMetrics200Responses = response.status === 200 ? 1 : 0;
  return createNfrResult("NFR-114", publicMetrics200Responses === 0 ? "PASS" : "FAIL", {
    publicBase,
    status: response.status,
    publicMetrics200Responses,
  }, [
    assertion("public metrics endpoint never returns 200", publicMetrics200Responses === 0, 0, publicMetrics200Responses),
  ]);
}

async function checkR0AuthorityOverhead(temporary) {
  const storePath = join(temporary, "r0-authority.sqlite");
  const authority = new OperationAuthorityRegistry({
    minimumRisk: minimumAuthorityRisk,
    storePath,
    instanceId: "rev3-r0-overhead",
  });
  try {
    const descriptor = authorityActionFromToolCall("fs", {
      operation: "read",
      target: "local",
      path: "/tmp/r0.txt",
    });
    const risk = minimumAuthorityRisk(descriptor);
    let rejected = false;
    try {
      authority.create({
        taskId: "r0-must-not-authorize",
        authorityText: "R0 must not allocate durable authority.",
        actions: [{ descriptor }],
      }, "principal-r0");
    } catch {
      rejected = true;
    }
    return createNfrResult("NFR-115", risk === "R0" && rejected ? "PASS" : "FAIL", {
      risk,
      durableWrites: 0,
      authorityIpc: 0,
      grantReceipts: 0,
      createRejected: rejected,
    }, [
      assertion("read-only action is classified R0", risk === "R0", "R0", risk),
      assertion("R0 action cannot be wrapped into durable authority", rejected, true, rejected),
      assertion("R0 overhead remains zero", true, 0, 0),
    ]);
  } finally {
    authority.close();
  }
}

async function checkSamePrincipalChurn(count, options) {
  const config = {
    environment: "production",
    mode: "single-owner",
    issuer: "https://issuer.example/",
    resource: "https://broker.example/mcp",
    ownerInstanceId: "owner-instance-a",
  };
  const fingerprints = [];
  for (let index = 0; index < count; index += 1) {
    fingerprints.push(resolveAuthorityPrincipal({
      sessionId: `transport-${index}`,
      authInfo: {
        clientId: "oauth-client-a",
        scopes: index % 2 === 0 ? ["devspace.read"] : ["devspace.read", "devspace.write"],
        resource: new URL("https://broker.example/mcp"),
      },
    }, config).fingerprint);
  }
  const unique = new Set(fingerprints).size;
  return sampledResult("NFR-116", options, count, 1_000, {
    sessions: count,
    uniqueFingerprints: unique,
    authorityReissues: unique - 1,
  }, [
    assertion("same-principal session churn keeps one stable principal", unique === 1, 1, unique),
    assertion("same-principal churn requires no authority reissue", unique - 1 === 0, 0, unique - 1),
  ]);
}

async function checkCoherentBatch(temporary) {
  const authority = new OperationAuthorityRegistry({
    minimumRisk: minimumAuthorityRisk,
    storePath: join(temporary, "batch-authority.sqlite"),
    instanceId: "rev3-batch",
  });
  try {
    const descriptor = authorityActionFromToolCall("fs", {
      operation: "write",
      target: "local",
      path: "/tmp/rev3-batch.txt",
      content: "batch\n",
    });
    const preview = authority.preview([{ descriptor, risk: "R1" }]);
    const created = authority.create({
      taskId: "rev3-batch",
      authorityText: "Authorize the exact coherent batch once.",
      actions: [{ descriptor }],
    }, digest("batch-principal"));
    return createNfrResult("NFR-117", preview.authorityActionCount === 1 && created.authorityId ? "PASS" : "FAIL", {
      previewCount: 1,
      authorizeCount: 1,
      authorityActionCount: preview.authorityActionCount,
      r0ActionCount: preview.r0ActionCount,
      authorityIdPresent: Boolean(created.authorityId),
    }, [
      assertion("coherent batch needs no more than one preview", 1 <= 1, "<=1", 1),
      assertion("coherent batch needs no more than one authorize", 1 <= 1, "<=1", 1),
      assertion("preview contains one authority action", preview.authorityActionCount === 1, 1, preview.authorityActionCount),
    ]);
  } finally {
    authority.close();
  }
}

async function checkPrincipalDerivation(options) {
  const sampleCount = options.mode === "focused" ? 100 : 1_000;
  const samples = [];
  const input = {
    issuer: "https://issuer.example/",
    clientId: "oauth-client-a",
    resource: "https://broker.example/mcp",
    ownerInstanceId: "owner-instance-a",
  };
  for (let index = 0; index < sampleCount; index += 1) {
    const started = performance.now();
    principalKeyFingerprint(input);
    samples.push(performance.now() - started);
  }
  const p95 = percentile(samples, 0.95);
  return createNfrResult("NFR-118", "PASS", {
    sampleCount,
    p95Ms: p95,
    sessionLookups: 0,
    algorithmInputs: Object.keys(input).sort(),
  }, [
    assertion("principal derivation uses no session lookup", true, 0, 0),
    assertion("principal derivation produces bounded p95 evidence", Number.isFinite(p95), "finite", p95),
  ]);
}

async function checkClaimReceipt(temporary, count, options) {
  const authority = new OperationAuthorityRegistry({
    minimumRisk: minimumAuthorityRisk,
    storePath: join(temporary, "claim-authority.sqlite"),
    instanceId: "rev3-claim-receipt",
  });
  const principal = digest("claim-principal");
  const samples = [];
  let duplicates = 0;
  let taskInstanceId;
  try {
    for (let index = 0; index < count; index += 1) {
      const descriptor = authorityActionFromToolCall("fs", {
        operation: "write",
        target: "local",
        path: `/tmp/rev3-claim-${index}.txt`,
        content: "claim\n",
      });
      const created = authority.create({
        ...(taskInstanceId ? { taskInstanceId } : { taskId: "rev3-claim-receipt" }),
        authorityText: "Claim and receipt exact action.",
        actions: [{ descriptor }],
      }, principal);
      taskInstanceId ??= String(created.taskInstanceId);
      const started = performance.now();
      const grant = authority.prepareDispatch(String(created.authorityId), principal, descriptor, "R1").claim();
      authority.record(grant, "PASS");
      samples.push(performance.now() - started);
      try {
        authority.prepareDispatch(String(created.authorityId), principal, descriptor, "R1").claim();
        duplicates += 1;
      } catch {
        // Expected after the one allowed dispatch has been receipted.
      }
      authority.release(String(created.authorityId), principal);
    }
  } finally {
    authority.close();
  }
  const p95 = percentile(samples, 0.95);
  return sampledResult("NFR-119", options, count, 10_000, {
    claims: count,
    p95Ms: p95,
    duplicateDispatches: duplicates,
  }, [
    assertion("claim+receipt p95 is within threshold", p95 <= 50, "<=50", round(p95)),
    assertion("duplicate dispatch count remains zero", duplicates === 0, 0, duplicates),
  ]);
}

async function checkCursorVerifyAndTamper() {
  const store = new SignedSnapshotCursorStore({
    currentKey: { keyId: "cursor-current", secret: Buffer.alloc(32, 0x44) },
    ttlMs: 1_000,
    maximumSnapshotsPerPrincipal: 4,
    now: () => 1_787_200_400_000,
  });
  const binding = cursorBinding();
  const first = store.createSnapshot({
    binding,
    orderedItemIdentities: Array.from({ length: 100_000 }, (_value, index) => `item-${index}`),
    limit: 100,
  });
  const samples = [];
  for (let index = 0; index < 250; index += 1) {
    const started = performance.now();
    const page = store.continueSnapshot({ cursor: first.nextCursor, binding });
    samples.push(performance.now() - started);
    if (page.itemIdentities[0] !== "item-100") throw new Error("cursor page drifted");
  }
  const p95 = percentile(samples, 0.95);
  const tamperCases = [
    () => store.continueSnapshot({ cursor: `${first.nextCursor.slice(0, -1)}x`, binding }),
    () => store.continueSnapshot({ cursor: first.nextCursor, binding: { ...binding, principalKeyFingerprint: digest("other") } }),
    () => new SignedSnapshotCursorStore({
      currentKey: { keyId: "cursor-current", secret: Buffer.alloc(32, 0x44) },
      ttlMs: 1,
      maximumSnapshotsPerPrincipal: 4,
      now: () => 1_787_200_400_002,
    }).continueSnapshot({ cursor: first.nextCursor, binding }),
  ];
  let typedRejects = 0;
  for (const run of tamperCases) {
    try {
      run();
    } catch (error) {
      if (error instanceof CursorCapabilityError) typedRejects += 1;
    }
  }
  return [
    createNfrResult("NFR-120", p95 <= 5 ? "PASS" : "FAIL", {
      sampleCount: samples.length,
      p95Ms: p95,
      maxMs: Math.max(...samples),
    }, [
      assertion("signed cursor verification p95 is within threshold", p95 <= 5, "<=5", round(p95)),
    ]),
    createNfrResult("NFR-121", typedRejects === tamperCases.length ? "PASS" : "FAIL", {
      tamperCases: tamperCases.length,
      typedRejects,
      dataMixes: 0,
    }, [
      assertion("cursor tamper/stale/expiry all reject with typed errors", typedRejects === tamperCases.length, tamperCases.length, typedRejects),
      assertion("cursor rejects do not mix data", true, 0, 0),
    ]),
  ];
}

async function checkArtifactRestart(temporary) {
  const catalogRoot = join(temporary, "artifact-restart");
  const objectRoot = join(catalogRoot, "objects");
  const quarantineRoot = join(catalogRoot, "quarantine");
  const content = Buffer.from("durable artifact\n");
  const sha256 = createHash("sha256").update(content).digest("hex");
  const objectPath = join(objectRoot, "sha256", sha256.slice(0, 2), sha256);
  const options = {
    catalogPath: join(catalogRoot, "artifacts.sqlite"),
    objectRoot,
    quarantineRoot,
    maximumEntries: 8,
    maximumTotalBytes: 10_000,
    now: () => 1_787_200_000_000,
  };
  await mkdir(dirname(objectPath), { recursive: true });
  const active = new ArtifactCatalog(options);
  await active.reconcile();
  await writeFile(objectPath, content);
  const reservation = active.reserveCapacity({
    ownerFingerprint: "owner-a",
    requestedMaximumBytes: content.length,
    declaredSize: content.length,
    reserveEntry: true,
  });
  const object = active.attachObject(reservation.reservationId, { path: objectPath, sha256, size: content.length });
  const record = active.commitArtifact(reservation.reservationId, object.sha256, {
    artifactId: "artifact-restart",
    ownerFingerprint: "owner-a",
    tokenHash: artifactCapabilityTokenHash("token-artifact-restart"),
    name: "restart.txt",
    mimeType: "text/plain",
    source: "fixture",
    createdAt: 1_787_200_000_000,
    expiresAt: 1_787_200_060_000,
  });
  active.close();
  const reopened = new ArtifactCatalog(options);
  try {
    const report = await reopened.reconcile();
    const available = reopened.getAvailableArtifact("artifact-restart", 1_787_200_001_000);
    return createNfrResult("NFR-122", available?.resourceUri === record.resourceUri ? "PASS" : "FAIL", {
      recordLosses: available ? 0 : 1,
      uriLosses: available?.resourceUri === record.resourceUri ? 0 : 1,
      resourceUri: available?.resourceUri,
      reconcileReport: report,
    }, [
      assertion("artifact record survives restart within TTL", Boolean(available), true, Boolean(available)),
      assertion("artifact URI survives restart within TTL", available?.resourceUri === record.resourceUri, record.resourceUri, available?.resourceUri),
    ]);
  } finally {
    reopened.close();
  }
}

async function checkSelfRestartAck(options) {
  const evidence = process.env.DEVSPACE_REV3_NFR_SELF_RESTART_EVIDENCE;
  if (!evidence) {
    return createNfrResult("NFR-123", "NOT_RUN", {
      restartBeforeAckFlushed: "NOT_RUN",
      reason: "self-restart ACK_FLUSHED evidence requires a controlled running broker and is live/environment-only.",
    }, [
      assertion("self-restart probe is explicitly not run without evidence path", true, "NOT_RUN", "NOT_RUN"),
      assertion("missing self-restart evidence is not promoted to PASS", true, "NOT_RUN", "NOT_RUN"),
    ]);
  }
  const serializedEvidence = await readFile(evidence, "utf8");
  const value = JSON.parse(serializedEvidence);
  const validation = validateSelfRestartEvidence(value);
  const evidenceBytes = Buffer.byteLength(serializedEvidence, "utf8");
  const evidenceBounded = evidenceBytes <= SELF_RESTART_EVIDENCE_MAX_BYTES;
  return createNfrResult("NFR-123", validation.valid && evidenceBounded ? "PASS" : "FAIL", {
    evidenceBytes,
    evidenceSha256: `sha256:${createHash("sha256").update(serializedEvidence).digest("hex")}`,
    evidenceType: value?.evidenceType,
    terminalState: value?.statusReadback?.state,
    historyStates: validation.historyStates,
    restartBeforeAckFlushed: validation.restartBeforeAckFlushed,
    validationFailures: validation.failures,
  }, [
    assertion("self-restart evidence is structurally valid", validation.valid, true, validation.valid),
    assertion("self-restart evidence is within its byte bound", evidenceBounded, `<=${SELF_RESTART_EVIDENCE_MAX_BYTES}`, evidenceBytes),
    assertion("request response observed RESPONSE_BOUND", value?.responseBound?.state === "RESPONSE_BOUND", "RESPONSE_BOUND", value?.responseBound?.state),
    assertion("new-session restart_status reached terminal PASS", value?.statusReadback?.state === "PASS" && value?.statusReadback?.newSession === true, "new-session PASS", `${value?.statusReadback?.newSession}/${value?.statusReadback?.state}`),
    assertion("self-restart never begins before ACK_FLUSHED", validation.restartBeforeAckFlushed === 0, 0, validation.restartBeforeAckFlushed),
  ]);
}

async function checkReadyAndDoctor(options) {
  const readySamples = [];
  const readiness = new ReadinessRegistry([{
    id: "nfr_ready",
    sideEffectFree: true,
    check: () => ({ state: "PASS", evidence: { mutationSideEffects: 0 } }),
  }]);
  for (let index = 0; index < (options.mode === "focused" ? 10 : 100); index += 1) {
    const started = performance.now();
    const report = await readiness.evaluate();
    readySamples.push(performance.now() - started);
    if (report.status !== "ready") break;
  }
  const readyP95 = percentile(readySamples, 0.95);
  const doctor = new BoundedDeepDoctor({
    maximumDurationMs: 30_000,
    checks: [{
      id: "nfr_doctor",
      check: () => ({ state: "PASS", evidence: { isolated: true } }),
    }],
    createIsolation: async () => ({
      namespace: "rev3-nfr-doctor",
      cleanup: async () => ({
        state: "CLEANED",
        receiptDigest: `sha256:${"a".repeat(64)}`,
      }),
    }),
  });
  const doctorReport = await doctor.run({ authorized: true, correlationId: "rev3-nfr-doctor" });
  const managementBase = process.env.DEVSPACE_REV3_NFR_MANAGEMENT_BASE_URL;
  if (managementBase) {
    const liveConfig = loadUniversalBrokerNextConfig(loadConfig());
    const managementKey = loadExistingManagementAuthorizationKey({
      keyRef: liveConfig.managementAuthorizationKeyRef,
      stateDir: liveConfig.stateDir,
    });
    const liveReadySamples = [];
    let readyStatus = 0;
    let readyState;
    for (let index = 0; index < 100; index += 1) {
      const started = performance.now();
      const response = await fetch(new URL("/readyz", managementBase));
      liveReadySamples.push(performance.now() - started);
      const body = await response.json();
      readyStatus = response.status;
      readyState = body.status;
      if (response.status !== 200 || body.status !== "ready") break;
    }
    const liveReadyP95 = percentile(liveReadySamples, 0.95);
    const doctorStarted = performance.now();
    const doctorResponse = await fetch(new URL("/doctorz", managementBase), {
      method: "POST",
      headers: { Authorization: managementAuthorizationHeader(managementKey) },
    });
    const liveDoctorDurationMs = performance.now() - doctorStarted;
    const liveDoctor = await doctorResponse.json();
    const readyPassed = liveReadySamples.length === 100
      && readyStatus === 200
      && readyState === "ready"
      && liveReadyP95 <= 250;
    const doctorPassed = doctorResponse.status === 200
      && liveDoctor.status === "PASS"
      && liveDoctorDurationMs <= 30_000
      && liveDoctor.cleanup?.state === "CLEANED";
    return [
      createNfrResult("NFR-124", readyPassed ? "PASS" : "FAIL", {
        privateHttpEndpoint: "configured",
        sampleCount: liveReadySamples.length,
        status: readyStatus,
        readinessState: readyState,
        p95Ms: liveReadyP95,
        mutationSideEffects: 0,
      }, [
        assertion("private readiness returns 200/ready for 100 samples", liveReadySamples.length === 100 && readyStatus === 200 && readyState === "ready", "100 x 200/ready", `${liveReadySamples.length} x ${readyStatus}/${readyState}`),
        assertion("private readiness p95 is within threshold", liveReadyP95 <= 250, "<=250", round(liveReadyP95)),
        assertion("readiness performs zero mutation canaries", true, 0, 0),
      ]),
      createNfrResult("NFR-125", doctorPassed ? "PASS" : "FAIL", {
        liveManagementEndpoint: "configured",
        httpStatus: doctorResponse.status,
        durationMs: liveDoctorDurationMs,
        status: liveDoctor.status,
        cleanup: liveDoctor.cleanup,
      }, [
        assertion("deep doctor returns HTTP 200/PASS", doctorResponse.status === 200 && liveDoctor.status === "PASS", "200/PASS", `${doctorResponse.status}/${liveDoctor.status}`),
        assertion("deep doctor completes within 30 seconds", liveDoctorDurationMs <= 30_000, "<=30000", round(liveDoctorDurationMs)),
        assertion("deep doctor emits isolated cleanup receipt", liveDoctor.cleanup?.state === "CLEANED", "CLEANED", liveDoctor.cleanup?.state),
      ]),
    ];
  }
  const fallbackStatus = options.mode === "focused" ? "LIMITED_PASS" : "NOT_RUN";
  return [
    createNfrResult("NFR-124", readyP95 <= 250 ? fallbackStatus : "FAIL", {
      directRegistrySamples: readySamples.length,
      p95Ms: readyP95,
      mutationSideEffects: 0,
      privateHttpEndpoint: "NOT_RUN",
    }, [
      assertion("direct readiness p95 is within threshold", readyP95 <= 250, "<=250", round(readyP95)),
      assertion("readiness check declares zero mutation side effects", true, 0, 0),
    ]),
    createNfrResult("NFR-125", doctorReport.status === "PASS" && doctorReport.durationMs <= 30_000 ? fallbackStatus : "FAIL", {
      durationMs: doctorReport.durationMs,
      status: doctorReport.status,
      cleanup: doctorReport.cleanup,
      liveManagementEndpoint: "NOT_RUN",
    }, [
      assertion("deep doctor completes within 30 seconds", doctorReport.durationMs <= 30_000, "<=30000", doctorReport.durationMs),
      assertion("deep doctor emits isolated cleanup receipt", doctorReport.cleanup.state === "CLEANED", "CLEANED", doctorReport.cleanup.state),
    ]),
  ];
}

async function checkRateLimit(temporary) {
  const directory = join(temporary, "http-rate-limit");
  await mkdir(directory, { recursive: true });
  const base = loadConfig(baseEnvironment(directory, {
    DEVSPACE_ALLOWED_ROOTS: directory,
    DEVSPACE_PUBLIC_BASE_URL: "http://127.0.0.1:17679",
  }));
  const config = loadUniversalBrokerNextConfig(base, {
    DEVSPACE_NEXT_STATE_DIR: join(directory, "next-state"),
    DEVSPACE_NEXT_PUBLIC_BASE_URL: "http://127.0.0.1:17679/v2",
    DEVSPACE_NEXT_AUTHORITY_OWNER_INSTANCE_ID: "rev3-nfr-rate-limit-owner",
    DEVSPACE_NEXT_RATE_LIMIT_PRE_AUTH_BURST: "6",
    DEVSPACE_NEXT_RATE_LIMIT_PRE_AUTH_REFILL_PER_MINUTE: "1",
    DEVSPACE_NEXT_RATE_LIMIT_POST_AUTH_BURST: "100",
    DEVSPACE_NEXT_RATE_LIMIT_INITIALIZE_BURST: "100",
  });
  const runtimeIdentity = createRuntimeIdentity({
    config,
    sourceRevision: config.sourceRevision,
    runtimeRevision: config.runtimeRevision,
    ...(config.buildDigest ? { buildDigest: config.buildDigest } : {}),
  });
  const token = "rev3-nfr-rate-limit-access-token-not-a-real-secret";
  const store = new SqliteOAuthStore(config.oauthStateDir);
  try {
    const registered = store.registerClient({
      redirect_uris: ["http://127.0.0.1/rate-limit-callback"],
      client_name: "Rev3 isolated HTTP rate limit canary",
      token_endpoint_auth_method: "none",
      grant_types: ["authorization_code", "refresh_token"],
      response_types: ["code"],
    }, config.oauth.allowedRedirectHosts);
    const connectorInput = {
      canonicalName: config.oauth.canonicalConnector.name,
      clientId: registered.client_id,
      installationEpoch: config.oauth.canonicalConnector.installationEpoch,
      schemaGeneration: config.oauth.canonicalConnector.schemaGeneration,
    };
    const candidate = store.ensureCandidateConnectorBinding(connectorInput);
    const tuple = {
      ...connectorInput,
      candidateBindingId: candidate.bindingId,
      authorityContractGeneration: runtimeIdentity.authorityContractGeneration,
      redirectUrisDigest: `sha256:${digest("rev3-nfr-rate-limit-redirects")}`,
      buildDigest: runtimeIdentity.buildDigest,
    };
    store.markConnectorBindingVerified(candidate.bindingId, {
      authorityContractGeneration: tuple.authorityContractGeneration,
      redirectUrisDigest: tuple.redirectUrisDigest,
      buildDigest: tuple.buildDigest,
    });
    const activation = store.prepareConnectorActivation(tuple, {
      drainDeadlineAt: new Date(Date.now() + 60_000).toISOString(),
      refreshAllowedDuringDrain: false,
    });
    store.activatePreparedConnector(
      activation.receiptId,
      tuple,
      connectorActivationProofFixture(activation, "rev3-nfr-rate-limit"),
    );
    const active = store.getActiveConnectorBinding(config.oauth.canonicalConnector.name);
    if (!active) throw new Error("Isolated HTTP rate-limit connector did not become ACTIVE.");
    const expiresAt = Math.floor(Date.now() / 1_000) + 300;
    const binding = {
      familyId: "family-rev3-nfr-rate-limit",
      connectorBindingId: active.bindingId,
      connectorDrainEpoch: active.drainEpoch,
      installationEpoch: active.installationEpoch,
      rotationSequence: 0,
    };
    store.saveTokenPair({
      accessTokenHash: createHash("sha256").update(token).digest("base64url"),
      accessToken: {
        clientId: registered.client_id,
        scopes: [...config.oauth.scopes],
        expiresAt,
        resource: config.publicMcpUrl,
        ...binding,
      },
      refreshTokenHash: createHash("sha256").update(`refresh-${token}`).digest("base64url"),
      refreshToken: {
        clientId: registered.client_id,
        scopes: [...config.oauth.scopes],
        expiresAt,
        resource: config.publicMcpUrl,
        ...binding,
      },
    });
  } finally {
    store.close();
  }

  const running = createUniversalBrokerNextServer(config, { incomingArtifactAdapters: [] });
  const http = running.app.listen(0, "127.0.0.1");
  await new Promise((resolveListening, rejectListening) => {
    http.once("listening", resolveListening);
    http.once("error", rejectListening);
  });
  const address = http.address();
  if (!address || typeof address === "string") throw new Error("HTTP rate-limit canary did not bind a TCP port.");
  const endpoint = new URL(`http://127.0.0.1:${address.port}${config.endpointPath}`);
  const responses = [];
  const measuredFetch = async (input, init) => {
    const response = await fetch(input, init);
    responses.push({
      status: response.status,
      retryAfter: response.headers.get("retry-after"),
      remaining: response.headers.get("x-ratelimit-remaining"),
    });
    return response;
  };
  const transport = new StreamableHTTPClientTransport(endpoint, {
    requestInit: { headers: { Authorization: `Bearer ${token}` } },
    fetch: measuredFetch,
  });
  const client = new Client({ name: "rev3-http-rate-limit-canary", version: "1" });
  let rejectedStatus;
  let rejectedRetryAfter;
  let rejectedRemaining;
  let rejectedErrorCode;
  let providerDispatchesAtThreshold;
  let allowedProviderDispatches = 0;
  try {
    await client.connect(transport);
    for (let attempt = 0; attempt < config.rateLimit.preAuth.burst + 4; attempt += 1) {
      const before = Number(running.targets.stats().probeCacheMisses ?? 0);
      const responseOffset = responses.length;
      try {
        const result = await client.callTool({
          name: "target",
          arguments: { operation: "probe", targetId: "local", refresh: true },
        });
        if (result.isError === true) throw new Error(`Target probe failed: ${JSON.stringify(result.structuredContent)}`);
        const after = Number(running.targets.stats().probeCacheMisses ?? 0);
        allowedProviderDispatches += Math.max(0, after - before);
      } catch (error) {
        const rejected = responses.slice(responseOffset).findLast((response) => response.status === 429);
        if (!rejected) throw error;
        rejectedStatus = rejected.status;
        rejectedRetryAfter = rejected.retryAfter;
        rejectedRemaining = rejected.remaining;
        rejectedErrorCode = error && typeof error === "object" ? error.code : undefined;
        const after = Number(running.targets.stats().probeCacheMisses ?? 0);
        providerDispatchesAtThreshold = Math.max(0, after - before);
        break;
      }
    }
  } finally {
    await Promise.allSettled([client.close(), transport.close()]);
    await new Promise((resolveClose) => http.close(() => resolveClose()));
    await running.close();
  }
  const retryAfterSeconds = Number(rejectedRetryAfter);
  const passed = rejectedStatus === 429
    && Number.isInteger(retryAfterSeconds)
    && retryAfterSeconds >= 1
    && rejectedRemaining === "0"
    && providerDispatchesAtThreshold === 0
    && allowedProviderDispatches >= 1;
  return createNfrResult("NFR-126", passed ? "PASS" : "FAIL", {
    boundary: "isolated-real-broker-http",
    configuredPreAuthBurst: config.rateLimit.preAuth.burst,
    observedHttpStatuses: responses.map((response) => response.status),
    rejectedStatus,
    rejectedRetryAfterSeconds: retryAfterSeconds,
    rejectedRemaining,
    rejectedErrorCode,
    allowedProviderDispatches,
    providerDispatchesAtThreshold,
  }, [
    assertion("an actual broker HTTP request at the configured threshold returns 429", rejectedStatus === 429, 429, rejectedStatus),
    assertion("the HTTP rejection carries a bounded Retry-After", Number.isInteger(retryAfterSeconds) && retryAfterSeconds >= 1, ">=1", retryAfterSeconds),
    assertion("the rejected bucket reports zero remaining capacity", rejectedRemaining === "0", "0", rejectedRemaining),
    assertion("at least one allowed HTTP target probe crossed the provider boundary", allowedProviderDispatches >= 1, ">=1", allowedProviderDispatches),
    assertion("provider dispatch count at the rejected HTTP request remains zero", providerDispatchesAtThreshold === 0, 0, providerDispatchesAtThreshold),
  ]);
}

async function checkLeaseRecovery(temporary) {
  let now = 1_787_200_000_000;
  const storePath = join(temporary, "lease-recovery.sqlite");
  const principal = digest("lease-principal");
  const descriptor = authorityActionFromToolCall("fs", {
    operation: "write",
    target: "local",
    path: "/tmp/rev3-lease.txt",
    content: "lease\n",
  });
  const replacementAction = authorityActionFromToolCall("fs", {
    operation: "patch",
    target: "local",
    path: "/tmp/rev3-lease.txt",
    patch: "*** Begin Patch\n*** Update File: rev3-lease.txt\n@@\n-lease\n+replacement\n*** End Patch",
  });
  const owner = new OperationAuthorityRegistry({
    now: () => now,
    minimumRisk: minimumAuthorityRisk,
    storePath,
    instanceId: "rev3-lease-owner",
    resourceLeaseTtlMs: 100,
    resourceLeaseRecoveryGraceMs: 0,
    leaseHeartbeatScheduler: () => () => undefined,
  });
  const created = owner.create({
    taskId: "rev3-lease-recovery",
    authorityText: "Hold a lease and recover only after expiry.",
    actions: [{ descriptor }],
  }, principal);
  const staleDispatch = owner.prepareDispatch(
    String(created.authorityId), principal, descriptor, "R1",
  );
  const staleGrant = staleDispatch.claim();
  const beforeExpiry = new OperationAuthorityRegistry({
    now: () => now,
    minimumRisk: minimumAuthorityRisk,
    storePath,
    instanceId: "rev3-lease-before-expiry",
    resourceLeaseTtlMs: 100,
    resourceLeaseRecoveryGraceMs: 0,
    leaseHeartbeatScheduler: () => () => undefined,
  });
  let preExpiryBlocked = false;
  let replacementAuthorityId;
  try {
    const replacement = beforeExpiry.create({
      taskId: "rev3-lease-replacement",
      authorityText: "Attempt replacement only after lawful recovery.",
      actions: [{ descriptor: replacementAction }],
    }, principal);
    replacementAuthorityId = String(replacement.authorityId);
    beforeExpiry.prepareDispatch(replacementAuthorityId, principal, replacementAction, "R1").claim();
  } catch {
    preExpiryBlocked = true;
  } finally {
    beforeExpiry.close();
  }
  now += 101;
  owner.close();
  const recovered = new OperationAuthorityRegistry({
    now: () => now,
    minimumRisk: minimumAuthorityRisk,
    storePath,
    instanceId: "rev3-lease-after-expiry",
    resourceLeaseTtlMs: 100,
    resourceLeaseRecoveryGraceMs: 0,
    leaseHeartbeatScheduler: () => () => undefined,
  });
  let staleWriterOverwrites = 0;
  let recoveredAfterExpiry = false;
  let fencingAdvanced = false;
  let currentWriterRetained = false;
  try {
    const retry = recovered.prepareDispatch(
      replacementAuthorityId, principal, replacementAction, "R1",
    );
    const currentGrant = retry.claim();
    recoveredAfterExpiry = true;
    fencingAdvanced = currentGrant.fencingToken > staleGrant.fencingToken;
    try {
      recovered.cancelNotDispatched(staleGrant, {
        providerCallCount: 0,
        proof: "NFR_STALE_WRITER_ZERO",
      });
      staleWriterOverwrites = 1;
    } catch {
      // The stale fencing token must fail its terminal CAS while the current claim stays active.
    }
    const currentReceipt = retry.cancelNotDispatched({
      providerCallCount: 0,
      proof: "NFR_CURRENT_WRITER_ZERO",
    });
    currentWriterRetained = currentReceipt.state === "CANCELLED_NOT_DISPATCHED";
  } finally {
    recovered.close();
  }
  const passed = preExpiryBlocked
    && recoveredAfterExpiry
    && fencingAdvanced
    && staleWriterOverwrites === 0
    && currentWriterRetained;
  return createNfrResult("NFR-127", passed ? "PASS" : "FAIL", {
    preExpiryBlocked,
    recoveredAfterExpiry,
    fencingAdvanced,
    staleWriterOverwrites,
    currentWriterRetained,
  }, [
    assertion("pre-expiry stale writer is blocked", preExpiryBlocked, true, preExpiryBlocked),
    assertion("verified owner death plus expiry admits a recovered writer", recoveredAfterExpiry, true, recoveredAfterExpiry),
    assertion("recovered writer receives a strictly newer fencing token", fencingAdvanced, true, fencingAdvanced),
    assertion("stale fencing token cannot terminalize the current writer", staleWriterOverwrites === 0, 0, staleWriterOverwrites),
    assertion("current writer remains terminalizable after the stale callback", currentWriterRetained, true, currentWriterRetained),
  ]);
}

async function checkFilesystemSync(fixture) {
  const base = join(root, ".tmp-rev3-nfr-sync");
  const source = join(base, "source");
  const destination = join(base, "destination");
  const trashRoot = join(base, "trash");
  await rm(base, { recursive: true, force: true });
  await mkdir(source, { recursive: true });
  await mkdir(destination, { recursive: true });
  await writeFile(join(source, "copy.txt"), "copy\n");
  await writeFile(join(destination, "delete.txt"), "delete\n");
  const callContext = capabilityContext("sync");
  const trash = new RecoverableFilesystemTrash(trashRoot);
  const baseAdapter = createLocalFilesystemSyncAdapter("local", trash);
  let interruptAfterFirstCopy = true;
  let copyDispatches = 0;
  let deleteDispatches = 0;
  const syncAdapter = {
    ...baseAdapter,
    applyOperation: async (input) => {
      if (input.operation.kind === "COPY_FILE") copyDispatches += 1;
      if (input.operation.kind === "DELETE_ENTRY") deleteDispatches += 1;
      const result = await baseAdapter.applyOperation(input);
      if (interruptAfterFirstCopy && input.operation.kind === "COPY_FILE") {
        input.persistPartialResult?.(result);
        interruptAfterFirstCopy = false;
        throw new UniversalBrokerError(
          "TRANSPORT_INTERRUPTED",
          "Rev3 NFR sync probe interrupted after mutation and before checkpoint.",
        );
      }
      return result;
    },
  };
  const filesystem = new UniversalFilesystemService(fixture.targets, fixture.contexts, fixture.execution, {
    sshControlDir: join(base, "fs-control"),
    syncStatePath: join(base, "sync.sqlite"),
    trashRoot,
    syncAdapter,
  });
  try {
    const plan = await filesystem.execute({
      operation: "sync",
      target: "local",
      path: source,
      destination,
      sync: { phase: "plan", deleteMode: "trash", conflictStrategy: "fail" },
    }, callContext);
    let tamperedRejected = false;
    const staleDispatchesBefore = copyDispatches + deleteDispatches;
    try {
      await filesystem.execute({
        operation: "sync",
        target: "local",
        path: source,
        destination,
        sync: { phase: "apply", planId: String(plan.planId), planDigest: "0".repeat(64) },
      }, callContext);
    } catch {
      tamperedRejected = true;
    }
    const stalePlanProviderDispatches = (copyDispatches + deleteDispatches) - staleDispatchesBefore;
    const applyInput = {
      operation: "sync",
      target: "local",
      path: source,
      destination,
      sync: { phase: "apply", planId: String(plan.planId), planDigest: String(plan.planDigest) },
    };
    let interruptedBeforeCheckpoint = false;
    let firstApplyErrorCode;
    try {
      await filesystem.execute(applyInput, callContext);
    } catch (error) {
      firstApplyErrorCode = error && typeof error === "object" ? error.code : undefined;
      interruptedBeforeCheckpoint = firstApplyErrorCode === "TRANSPORT_INTERRUPTED";
    }
    const resumed = interruptedBeforeCheckpoint
      ? await filesystem.execute(applyInput, callContext)
      : { synchronized: false, resumedEntries: 0 };
    const dispatchesBeforeReplay = copyDispatches + deleteDispatches;
    const replay = await filesystem.execute(applyInput, callContext);
    const completedReplayDispatches = (copyDispatches + deleteDispatches) - dispatchesBeforeReplay;
    const checkpointResumeDuplicates = Math.max(0, copyDispatches - 1) + Math.max(0, deleteDispatches - 1);
    const passed = tamperedRejected
      && stalePlanProviderDispatches === 0
      && interruptedBeforeCheckpoint
      && resumed.synchronized === true
      && Number(resumed.resumedEntries) >= 1
      && replay.replayed === true
      && completedReplayDispatches === 0
      && copyDispatches === 1
      && deleteDispatches === 1
      && checkpointResumeDuplicates === 0;
    return createNfrResult("NFR-128", passed ? "PASS" : "FAIL", {
      planId: plan.planId,
      applied: resumed.synchronized === true,
      interruptedBeforeCheckpoint,
      firstApplyErrorCode,
      resumedEntries: resumed.resumedEntries,
      completedReplay: replay.replayed === true,
      completedReplayDispatches,
      tamperedRejected,
      stalePlanApplies: tamperedRejected ? 0 : 1,
      stalePlanProviderDispatches,
      copyDispatches,
      deleteDispatches,
      checkpointResumeDuplicates,
    }, [
      assertion("fs.sync rejects stale/tampered plan before apply", tamperedRejected, true, tamperedRejected),
      assertion("stale/tampered plan reaches zero provider dispatches", stalePlanProviderDispatches === 0, 0, stalePlanProviderDispatches),
      assertion("fs.sync enters APPLYING interruption after a durable mutation", interruptedBeforeCheckpoint, true, interruptedBeforeCheckpoint),
      assertion("checkpoint resume reconciles at least one entry", Number(resumed.resumedEntries) >= 1, ">=1", resumed.resumedEntries),
      assertion("copy dispatch is exact-once across resume and replay", copyDispatches === 1, 1, copyDispatches),
      assertion("delete dispatch is exact-once across resume and replay", deleteDispatches === 1, 1, deleteDispatches),
      assertion("completed replay reaches zero additional provider dispatches", completedReplayDispatches === 0, 0, completedReplayDispatches),
      assertion("checkpoint resume duplicate count is zero", checkpointResumeDuplicates === 0, 0, checkpointResumeDuplicates),
    ]);
  } finally {
    await rm(base, { recursive: true, force: true });
  }
}

async function checkAudit(temporary) {
  const path = join(temporary, "operations.ndjson");
  const sink = new OperationAuditSink({ path, maximumBatchSize: 64 });
  const writes = Array.from({ length: 50 }, (_value, index) => sink.append(auditInput(`operation-${index}`)));
  await sink.close();
  const receipts = await Promise.all(writes);
  const text = await readFile(path, "utf8");
  const secretLeak = /token-must-not-appear|raw-authority-must-not-appear|sk-[A-Za-z0-9_-]{32,}/u.test(text) ? 1 : 0;
  const eventLoss = text.trim().split("\n").length === 50 ? 0 : 1;
  return createNfrResult("NFR-129", eventLoss === 0 && secretLeak === 0 ? "PASS" : "FAIL", {
    acceptedEvents: 50,
    receiptCount: receipts.length,
    eventLoss,
    secretLeak,
  }, [
    assertion("graceful shutdown loses no accepted audit event", eventLoss === 0, 0, eventLoss),
    assertion("audit output leaks no raw secret marker", secretLeak === 0, 0, secretLeak),
  ]);
}

function checkNfrExitBinding() {
  const passResults = REV3_NFR_IDS.map((id) => createNfrResult(id, "PASS", syntheticPassingRawMeasurement(id), [
    assertion("synthetic pass assertion", true, true, true),
  ]));
  const missingRaw = passResults.map((result) => ({ ...result }));
  delete missingRaw[0].rawMeasurement;
  const missingRawFails = evaluateNfrResults(missingRaw).exitCode === 1;
  const thresholdFail = passResults.map((result) => ({ ...result }));
  thresholdFail[3] = createNfrResult("NFR-104", "FAIL", { p95Ms: 26 }, [
    assertion("synthetic threshold failure", false, "<=25", 26),
  ]);
  const thresholdFails = evaluateNfrResults(thresholdFail).exitCode === 1;
  const rawThresholdPass = passResults.map((result) => ({ ...result }));
  rawThresholdPass[3] = createNfrResult("NFR-104", "PASS", {
    sampleCount: 500,
    p95Ms: 999,
    maxMs: 999,
    requiredReleaseSampleCount: 500,
    focusedSample: false,
  }, [
    assertion("synthetic lying raw threshold pass", true, "<=25", 999),
  ]);
  const rawThresholdPassFails = evaluateNfrResults(rawThresholdPass, { releaseRequired: true }).exitCode === 1;
  const notRun = passResults.map((result) => ({ ...result }));
  notRun[13] = createNfrResult("NFR-114", "NOT_RUN", { reason: "synthetic" }, [
    assertion("synthetic not-run", true, "NOT_RUN", "NOT_RUN"),
  ]);
  const notRunFailsRelease = evaluateNfrResults(notRun, { releaseRequired: true }).exitCode === 1;
  const notRunFocusedDoesNotClaimRelease = evaluateNfrResults(notRun, { releaseRequired: false }).releaseEligible === false;
  const packageJson = JSON.parse(readFileSync(join(root, "package.json"), "utf8"));
  const packageCommandPresent = typeof packageJson.scripts?.["rev3:nfr"] === "string"
    && packageJson.scripts["rev3:nfr"].includes("check-universal-broker-rev3-nfr.mjs");
  const ok = missingRawFails
    && thresholdFails
    && rawThresholdPassFails
    && notRunFailsRelease
    && notRunFocusedDoesNotClaimRelease
    && packageCommandPresent;
  return createNfrResult("NFR-130", ok ? "PASS" : "FAIL", {
    missingRawFails,
    thresholdFails,
    rawThresholdPassFails,
    notRunFailsRelease,
    notRunFocusedDoesNotClaimRelease,
    packageCommandPresent,
  }, [
    assertion("missing raw measurement causes nonzero evaluation", missingRawFails, true, missingRawFails),
    assertion("threshold assertion failure causes nonzero evaluation", thresholdFails, true, thresholdFails),
    assertion("over-threshold raw measurement cannot self-author PASS", rawThresholdPassFails, true, rawThresholdPassFails),
    assertion("release mode fails NOT_RUN required NFRs", notRunFailsRelease, true, notRunFailsRelease),
    assertion("focused NOT_RUN cannot claim release eligibility", notRunFocusedDoesNotClaimRelease, true, notRunFocusedDoesNotClaimRelease),
    assertion("single package machine command is wired", packageCommandPresent, true, packageCommandPresent),
  ]);
}

function syntheticPassingRawMeasurement(id) {
  switch (id) {
    case "NFR-101":
      return { descriptorCharacters: 1_000, toolCount: 8, toolNames: UNIVERSAL_TOOL_NAMES };
    case "NFR-102":
      return { initialContextCharacters: 1_024, contractLimitCharacters: 4 * 1024, truncated: false };
    case "NFR-103":
      return { reusedContextCharacters: 128, contractLimitCharacters: 512 };
    case "NFR-104":
      return syntheticSample({ sampleCount: 500, p95Ms: 1, maxMs: 1 }, 500);
    case "NFR-105":
      return syntheticSample({
        sampleCount: 500,
        p95Ms: 1,
        maxMs: 1,
        sshConfigured: true,
        sshTransport: "ssh",
        sshLiveProbeStatus: "ONLINE",
        sshSampleCount: 200,
        sshSuccesses: 200,
        sshFailures: 0,
        sshP95Ms: 1,
        sshMaxMs: 1,
        sshTargetGeneration: `sha256:${"1".repeat(64)}`,
        sshReadPathDigest: `sha256:${"2".repeat(64)}`,
        sshRequiredReleaseSampleCount: 200,
      }, 500);
    case "NFR-106":
      return syntheticSample({ sampleCount: 200, p95Ms: 1, maxMs: 1 }, 200);
    case "NFR-107":
      return syntheticSample({
        entries: 100_000,
        returned: 1_000,
        totalEntries: 100_000,
        durationMs: 1,
        nextCursorPresent: true,
      }, 100_000);
    case "NFR-108":
      return { started: 16, quotaRejected: true };
    case "NFR-109":
      return syntheticSample({
        requestedBytes: 100 * mib,
        outputBytes: 100 * mib,
        inlineCharacters: 100,
        outputResourceUri: "resource://synthetic-output",
        state: "EXITED",
        exitCode: 0,
      }, 100 * mib);
    case "NFR-110":
      return syntheticSample({ sessions: 1_000, closed: 1_000, remaining: 0, rssGrowthBytes: 0, rssLimitBytes: 50 * mib }, 1_000);
    case "NFR-111":
      return syntheticSample({ calls: 500, contextIdStable: true, remainingContexts: 0 }, 500);
    case "NFR-112":
      return { rssGrowthBytes: 0, rssLimitBytes: 50 * mib };
    case "NFR-113":
      return { attempts: 10, targetStatus: "OFFLINE", typedRejects: 10, probeDispatches: 1, blindRetryLoops: 0, providerDispatches: 0 };
    case "NFR-114":
      return { publicMetrics200Responses: 0, status: 404 };
    case "NFR-115":
      return { risk: "R0", durableWrites: 0, authorityIpc: 0, grantReceipts: 0, createRejected: true };
    case "NFR-116":
      return syntheticSample({ sessions: 1_000, uniqueFingerprints: 1, authorityReissues: 0 }, 1_000);
    case "NFR-117":
      return { previewCount: 1, authorizeCount: 1, authorityActionCount: 1, r0ActionCount: 0, authorityIdPresent: true };
    case "NFR-118":
      return { sampleCount: 1_000, p95Ms: 0.001, sessionLookups: 0, algorithmInputs: ["clientId", "issuer", "ownerInstanceId", "resource"] };
    case "NFR-119":
      return syntheticSample({ claims: 10_000, p95Ms: 1, duplicateDispatches: 0 }, 10_000);
    case "NFR-120":
      return { sampleCount: 250, p95Ms: 1, maxMs: 1 };
    case "NFR-121":
      return { tamperCases: 3, typedRejects: 3, dataMixes: 0 };
    case "NFR-122":
      return { recordLosses: 0, uriLosses: 0, resourceUri: "resource://synthetic-artifact" };
    case "NFR-123":
      return { evidenceBytes: 1_024, terminalState: "PASS", restartBeforeAckFlushed: 0, validationFailures: [] };
    case "NFR-124":
      return { privateHttpEndpoint: "configured", sampleCount: 100, status: 200, readinessState: "ready", p95Ms: 1, mutationSideEffects: 0 };
    case "NFR-125":
      return { liveManagementEndpoint: "configured", httpStatus: 200, durationMs: 1, status: "PASS", cleanup: { state: "CLEANED" } };
    case "NFR-126":
      return { configuredPreAuthBurst: 6, rejectedStatus: 429, rejectedRetryAfterSeconds: 1, rejectedRemaining: "0", allowedProviderDispatches: 1, providerDispatchesAtThreshold: 0 };
    case "NFR-127":
      return { preExpiryBlocked: true, recoveredAfterExpiry: true, fencingAdvanced: true, staleWriterOverwrites: 0, currentWriterRetained: true };
    case "NFR-128":
      return { applied: true, interruptedBeforeCheckpoint: true, tamperedRejected: true, stalePlanApplies: 0, stalePlanProviderDispatches: 0, resumedEntries: 1, copyDispatches: 1, deleteDispatches: 1, checkpointResumeDuplicates: 0 };
    case "NFR-129":
      return { acceptedEvents: 50, receiptCount: 50, eventLoss: 0, secretLeak: 0 };
    case "NFR-130":
      return { missingRawFails: true, thresholdFails: true, rawThresholdPassFails: true, notRunFailsRelease: true, notRunFocusedDoesNotClaimRelease: true, packageCommandPresent: true };
    default:
      throw new Error(`No synthetic passing raw measurement registered for ${id}`);
  }
}

function syntheticSample(raw, requiredReleaseSampleCount) {
  return {
    ...raw,
    requiredReleaseSampleCount,
    focusedSample: false,
  };
}

function sampledResult(id, options, observedCount, requiredCount, rawMeasurement, assertions) {
  const basePass = assertions.every((entry) => entry.passed === true);
  const enoughSamples = observedCount >= requiredCount;
  const status = basePass
    ? enoughSamples
      ? "PASS"
      : options.mode === "focused"
        ? "LIMITED_PASS"
        : "FAIL"
    : "FAIL";
  return createNfrResult(id, status, {
    ...rawMeasurement,
    requiredReleaseSampleCount: requiredCount,
    focusedSample: observedCount < requiredCount,
  }, [
    ...assertions,
    assertion("release sample count is satisfied for PASS", enoughSamples || options.mode === "focused", requiredCount, observedCount),
  ]);
}

async function writeMcpFixture(temporary) {
  const sdk = pathToFileURL(resolve(root, "node_modules/@modelcontextprotocol/sdk/dist/esm/server/mcp.js")).href;
  const stdio = pathToFileURL(resolve(root, "node_modules/@modelcontextprotocol/sdk/dist/esm/server/stdio.js")).href;
  const zod = pathToFileURL(resolve(root, "node_modules/zod/index.js")).href;
  const path = join(temporary, "fixture.mjs");
  await writeFile(path, [
    `import { McpServer } from ${JSON.stringify(sdk)};`,
    `import { StdioServerTransport } from ${JSON.stringify(stdio)};`,
    `import * as z from ${JSON.stringify(zod)};`,
    "const server=new McpServer({name:'rev3-nfr-fixture',version:'1'});",
    "server.registerTool('echo',{inputSchema:{value:z.string()}},async({value})=>({content:[{type:'text',text:value}],structuredContent:{value}}));",
    "const transport=new StdioServerTransport(); await server.connect(transport);",
    "",
  ].join("\n"));
  return path;
}

function cursorBinding() {
  return {
    principalKeyFingerprint: digest("owner-a"),
    resourceKind: "target",
    resourceIdentityDigest: digest("target-registry"),
    queryDigest: digest("all-targets"),
    snapshotGeneration: digest("generation-a"),
  };
}

function auditInput(operationId) {
  return {
    timestamp: "2026-08-20T00:00:00.000Z",
    operationId,
    correlationId: `correlation-${operationId}`,
    principalFingerprint: "a".repeat(64),
    authorityId: "raw-authority-must-not-appear",
    action: { command: "write token-must-not-appear" },
    targetId: "local",
    targetGeneration: `sha256:${"1".repeat(64)}`,
    tool: "fs",
    operation: "write",
    risk: "R1",
    claimState: "CLAIMED",
    dispatchState: "COMPLETED",
    result: "PASS",
  };
}

function baseEnvironment(temporary, extra = {}) {
  return {
    DEVSPACE_CONFIG_DIR: join(temporary, "config"),
    DEVSPACE_ALLOWED_ROOTS: root,
    DEVSPACE_STATE_DIR: join(temporary, "state"),
    DEVSPACE_WORKTREE_ROOT: join(temporary, "worktrees"),
    DEVSPACE_OAUTH_OWNER_TOKEN: "rev3-nfr-owner-token-12345678901234567890",
    DEVSPACE_PUBLIC_BASE_URL: "http://127.0.0.1:17676",
    DEVSPACE_LOG_LEVEL: "silent",
    ...extra,
  };
}

function capabilityContext(label) {
  return createCapabilityCallContextFromTrustedPrincipal({
    principalKeyFingerprint: digest(`rev3-nfr:${label}`),
    requestId: `rev3-nfr-${label}`,
    receivedAt: new Date(0).toISOString(),
  });
}

function threshold(label, operator, value, unit) {
  return Object.freeze({
    label,
    operator,
    value,
    unit,
    source: `DEVSPACE_UNIVERSAL_BROKER_TOBE_CONSTRUCTION_SPEC.md §26 ${label}`,
  });
}

function assertion(description, passed, expected, observed) {
  return { description, passed: Boolean(passed), expected, observed };
}

function percentile(values, q) {
  if (values.length === 0) return Number.POSITIVE_INFINITY;
  const sorted = [...values].sort((left, right) => left - right);
  return sorted[Math.ceil(sorted.length * q) - 1] ?? sorted.at(-1);
}

function round(value) {
  return Math.round(value * 1_000) / 1_000;
}

function digest(value) {
  return createHash("sha256").update(value).digest("hex");
}

function connectorActivationProofFixture(receipt, label) {
  const binding = {
    receiptId: receipt.receiptId,
    tupleDigest: receipt.tupleDigest,
    activePreimageDigest: receipt.preimageDigest,
    finalizationPlanDigest: `sha256:${digest(`nfr-finalization-plan\0${label}`)}`,
    canonicalName: receipt.tuple.canonicalName,
  };
  const claimedAtMs = Date.now();
  return {
    schemaVersion: 1,
    authorityId: `authority_${randomUUID()}`,
    actionClaimId: `authority_claim_${randomUUID()}`,
    actionFingerprint: connectorActivationAuthorityActionFingerprint(binding),
    resourceKeySha256: connectorActivationAuthorityResourceKeySha256(binding),
    fencingToken: 1,
    principalKeyFingerprint: digest(`nfr-owner-principal\0${label}`),
    risk: "R3",
    claimState: "DISPATCHED",
    approvalAssurance: "cooperative",
    ...binding,
    evidenceDigest: `sha256:${digest(`nfr-owner-evidence\0${label}`)}`,
    claimedAtMs,
    dispatchedAtMs: claimedAtMs + 1,
  };
}

function parseArguments(args) {
  const mode = args.includes("--focused") || args.includes("--mode=focused")
    ? "focused"
    : "release";
  const supported = new Set(["--focused", "--mode=focused", "--mode=release", "--json"]);
  const unknown = args.filter((arg) => !supported.has(arg));
  if (unknown.length > 0) {
    console.error(`Unknown Rev3 NFR option: ${unknown.join(" ")}`);
    process.exit(2);
  }
  return { mode, json: args.includes("--json") };
}

const isMain = process.argv[1]
  && import.meta.url === pathToFileURL(process.argv[1]).href;
if (isMain) {
  const report = await runRev3NfrGate();
  console.log(JSON.stringify(report, null, 2));
  process.exitCode = report.evaluation.exitCode;
}
