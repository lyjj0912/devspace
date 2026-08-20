import assert from "node:assert/strict";
import test from "node:test";
import {
  REV3_NFR_IDS,
  createNfrResult,
  evaluateNfrResults,
} from "./check-universal-broker-rev3-nfr.mjs";
import {
  SELF_RESTART_EVIDENCE_MAX_BYTES,
  SELF_RESTART_EVIDENCE_TYPE,
  createBoundedSelfRestartEvidence,
  validateSelfRestartEvidence,
} from "./lib/self-restart-evidence.mjs";

const mib = 1024 * 1024;

test("release-required mode fails any required NOT_RUN row", () => {
  const results = passingResults();
  results[13] = createNfrResult("NFR-114", "NOT_RUN", { reason: "live URL absent" }, [
    { description: "not run is explicit", passed: true },
  ]);

  const release = evaluateNfrResults(results, { releaseRequired: true });
  assert.equal(release.exitCode, 1);
  assert.equal(release.releaseEligible, false);
  assert.ok(release.releaseBlockers.includes("NFR-114 NOT_RUN"));

  const focused = evaluateNfrResults(results, { releaseRequired: false });
  assert.equal(focused.exitCode, 0);
  assert.equal(focused.releaseEligible, false);
  assert.equal(focused.status, "FOCUSED_NFR_LIMITED_PASS");
});

test("raw measurement, threshold source, and explicit assertions are mandatory", () => {
  const missingRaw = passingResults();
  delete missingRaw[0].rawMeasurement;
  assert.equal(evaluateNfrResults(missingRaw).exitCode, 1);
  assert.match(evaluateNfrResults(missingRaw).failures.join("\n"), /NFR-101 rawMeasurement missing/u);

  const missingSource = passingResults();
  missingSource[1] = { ...missingSource[1], thresholdSource: "" };
  const missingSourceEvaluation = evaluateNfrResults(missingSource);
  assert.equal(missingSourceEvaluation.exitCode, 1);
  assert.match(missingSourceEvaluation.failures.join("\n"), /NFR-102 threshold source missing/u);

  const measurementOnly = passingResults();
  measurementOnly[2] = { ...measurementOnly[2], assertions: [] };
  const measurementOnlyEvaluation = evaluateNfrResults(measurementOnly);
  assert.equal(measurementOnlyEvaluation.exitCode, 1);
  assert.match(measurementOnlyEvaluation.failures.join("\n"), /NFR-103 explicit assertions missing/u);
});

test("profile applicability must remain one-to-one for every NFR", () => {
  const results = passingResults();
  results[3] = {
    ...results[3],
    profileApplicability: { BASE_SINGLE_OWNER: "REQUIRED" },
  };
  const evaluation = evaluateNfrResults(results);
  assert.equal(evaluation.exitCode, 1);
  assert.match(evaluation.failures.join("\n"), /NFR-104 profile applicability is not 1:1/u);
});

test("threshold failures and duplicate or missing IDs cannot be hidden", () => {
  const thresholdFailure = passingResults();
  thresholdFailure[4] = createNfrResult("NFR-105", "FAIL", { p95Ms: 51 }, [
    { description: "p95 threshold", passed: false, expected: "<=50", observed: 51 },
  ]);
  const failed = evaluateNfrResults(thresholdFailure);
  assert.equal(failed.exitCode, 1);
  assert.match(failed.failures.join("\n"), /NFR-105 assertion failed/u);

  const duplicate = passingResults();
  duplicate[5] = duplicate[4];
  const duplicateEvaluation = evaluateNfrResults(duplicate);
  assert.equal(duplicateEvaluation.exitCode, 1);
  assert.match(duplicateEvaluation.failures.join("\n"), /NFR-106 missing/u);
  assert.match(duplicateEvaluation.failures.join("\n"), /NFR-105 duplicated/u);
});

test("raw thresholds are independently recomputed for PASS rows", () => {
  const overThresholdPass = passingResults();
  overThresholdPass[3] = createNfrResult("NFR-104", "PASS", {
    sampleCount: 500,
    p95Ms: 999,
    maxMs: 999,
    requiredReleaseSampleCount: 500,
    focusedSample: false,
  }, [
    { description: "self-authored p95 PASS must not be trusted", passed: true, expected: "<=25", observed: 999 },
  ]);

  const overThresholdEvaluation = evaluateNfrResults(overThresholdPass, { releaseRequired: true });
  assert.equal(overThresholdEvaluation.exitCode, 1);
  assert.equal(overThresholdEvaluation.releaseEligible, false);
  assert.match(overThresholdEvaluation.failures.join("\n"), /NFR-104 raw threshold predicate failed/u);

  const missingRequiredRawField = passingResults();
  missingRequiredRawField[4] = createNfrResult("NFR-105", "PASS", {
    sampleCount: 500,
    maxMs: 10,
    requiredReleaseSampleCount: 500,
    focusedSample: false,
  }, [
    { description: "self-authored missing p95 PASS must not be trusted", passed: true, expected: "<=50", observed: "missing" },
  ]);
  const missingFieldEvaluation = evaluateNfrResults(missingRequiredRawField, { releaseRequired: true });
  assert.equal(missingFieldEvaluation.exitCode, 1);
  assert.match(missingFieldEvaluation.failures.join("\n"), /NFR-105 raw threshold predicate failed/u);

  const missingLiveSsh = passingResults();
  missingLiveSsh[4] = createNfrResult("NFR-105", "PASS", {
    ...sampledLatency(500, 50),
    sshConfigured: false,
    sshTransport: "NOT_RUN",
    sshLiveProbeStatus: "NOT_RUN",
    sshSampleCount: 0,
    sshSuccesses: 0,
    sshFailures: 0,
    sshP95Ms: null,
    sshMaxMs: null,
    sshTargetGeneration: null,
    sshReadPathDigest: null,
    sshRequiredReleaseSampleCount: 200,
  }, [
    { description: "self-authored SSH PASS must not be trusted", passed: true, expected: 200, observed: 0 },
  ]);
  const missingSshEvaluation = evaluateNfrResults(missingLiveSsh, { releaseRequired: true });
  assert.equal(missingSshEvaluation.exitCode, 1);
  assert.match(missingSshEvaluation.failures.join("\n"), /NFR-105 raw threshold predicate failed/u);

  const partialLiveSsh = passingResults();
  partialLiveSsh[4].rawMeasurement.sshSampleCount = 199;
  partialLiveSsh[4].rawMeasurement.sshSuccesses = 199;
  const partialSshEvaluation = evaluateNfrResults(partialLiveSsh, { releaseRequired: true });
  assert.equal(partialSshEvaluation.exitCode, 1);
  assert.match(partialSshEvaluation.failures.join("\n"), /200 successful live SSH metadata samples/u);
});

test("NFR-128 requires a real checkpoint resume metric, not completed replay only", () => {
  const completedReplayOnly = passingResults();
  completedReplayOnly[27] = createNfrResult("NFR-128", "PASS", {
    applied: true,
    tamperedRejected: true,
    stalePlanApplies: 0,
    checkpointResumeDuplicates: 0,
  }, [
    { description: "completed replay is not checkpoint resume", passed: true, expected: 0, observed: 0 },
  ]);

  const evaluation = evaluateNfrResults(completedReplayOnly, { releaseRequired: true });
  assert.equal(evaluation.exitCode, 1);
  assert.match(evaluation.failures.join("\n"), /NFR-128 raw threshold predicate failed/u);
});

test("self-restart evidence requires the durable ACK timeline and a new-session PASS", () => {
  const created = createBoundedSelfRestartEvidence(rawSelfRestartObservation());
  assert.equal(validateSelfRestartEvidence(created).valid, true);
  assert.throws(() => createBoundedSelfRestartEvidence({
    ...rawSelfRestartObservation(),
    responseBound: {
      ...rawSelfRestartObservation().responseBound,
      transactionId: "restart_aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
    },
  }), /not bound to the exact RESPONSE_BOUND transaction/u);

  const valid = selfRestartEvidence();
  const accepted = validateSelfRestartEvidence(valid);
  assert.equal(accepted.valid, true, accepted.failures.join("\n"));
  assert.equal(accepted.restartBeforeAckFlushed, 0);

  const numberOnly = { restartBeforeAckFlushed: 0 };
  const rejectedNumber = validateSelfRestartEvidence(numberOnly);
  assert.equal(rejectedNumber.valid, false);
  assert.match(rejectedNumber.failures.join("\n"), /schemaVersion|evidenceType|transactionId/u);

  const reordered = selfRestartEvidence();
  [reordered.timeline[2], reordered.timeline[4]] = [reordered.timeline[4], reordered.timeline[2]];
  reordered.restartBeforeAckFlushed = 0;
  const rejectedOrder = validateSelfRestartEvidence(reordered);
  assert.equal(rejectedOrder.valid, false);
  assert.match(rejectedOrder.failures.join("\n"), /history must be|restartBeforeAckFlushed/u);

  const sameSession = selfRestartEvidence();
  sameSession.statusReadback.sessionIdSha256 = sameSession.responseBound.sessionIdSha256;
  sameSession.statusReadback.newSession = true;
  const rejectedSession = validateSelfRestartEvidence(sameSession);
  assert.equal(rejectedSession.valid, false);
  assert.match(rejectedSession.failures.join("\n"), /session digests are identical/u);

  const wrongPublicProcess = selfRestartEvidence();
  wrongPublicProcess.postRestartPublicHealth.startedAt = "2026-08-20T01:00:00.000Z";
  const rejectedPublicProcess = validateSelfRestartEvidence(wrongPublicProcess);
  assert.equal(rejectedPublicProcess.valid, false);
  assert.match(rejectedPublicProcess.failures.join("\n"), /startedAt does not match the local candidate process/u);

  const oversized = structuredClone(valid);
  oversized.padding = "x".repeat(SELF_RESTART_EVIDENCE_MAX_BYTES);
  const rejectedOversized = validateSelfRestartEvidence(oversized);
  assert.equal(rejectedOversized.valid, false);
  assert.match(rejectedOversized.failures.join("\n"), /evidence exceeds 32768 bytes/u);
});

function passingResults() {
  return REV3_NFR_IDS.map((id) => createNfrResult(id, "PASS", validRawMeasurement(id), [
    { description: "synthetic assertion", passed: true, expected: true, observed: true },
  ]));
}

function validRawMeasurement(id) {
  switch (id) {
    case "NFR-101":
      return { descriptorCharacters: 1_000, toolCount: 8, toolNames: [] };
    case "NFR-102":
      return { initialContextCharacters: 1_024, contractLimitCharacters: 4 * 1024, truncated: false };
    case "NFR-103":
      return { reusedContextCharacters: 128, contractLimitCharacters: 512 };
    case "NFR-104":
      return sampledLatency(500, 25);
    case "NFR-105":
      return {
        ...sampledLatency(500, 50),
        sshConfigured: true,
        sshTransport: "ssh",
        sshLiveProbeStatus: "ONLINE",
        sshSampleCount: 200,
        sshSuccesses: 200,
        sshFailures: 0,
        sshP95Ms: 10,
        sshMaxMs: 20,
        sshTargetGeneration: `sha256:${"1".repeat(64)}`,
        sshReadPathDigest: `sha256:${"2".repeat(64)}`,
        sshRequiredReleaseSampleCount: 200,
      };
    case "NFR-106":
      return sampledLatency(200, 50);
    case "NFR-107":
      return {
        entries: 100_000,
        returned: 1_000,
        totalEntries: 100_000,
        durationMs: 250,
        nextCursorPresent: true,
        requiredReleaseSampleCount: 100_000,
        focusedSample: false,
      };
    case "NFR-108":
      return { started: 16, quotaRejected: true };
    case "NFR-109":
      return {
        requestedBytes: 100 * mib,
        outputBytes: 100 * mib,
        inlineCharacters: 100,
        outputResourceUri: "resource://nfr-output",
        state: "EXITED",
        exitCode: 0,
        requiredReleaseSampleCount: 100 * mib,
        focusedSample: false,
      };
    case "NFR-110":
      return sampledCount({ sessions: 1_000, closed: 1_000, remaining: 0, rssGrowthBytes: 0, rssLimitBytes: 50 * mib }, 1_000);
    case "NFR-111":
      return sampledCount({ calls: 500, contextIdStable: true, remainingContexts: 0 }, 500);
    case "NFR-112":
      return { rssGrowthBytes: 0, rssLimitBytes: 50 * mib };
    case "NFR-113":
      return { attempts: 10, targetStatus: "OFFLINE", typedRejects: 10, probeDispatches: 1, blindRetryLoops: 0, providerDispatches: 0 };
    case "NFR-114":
      return { publicMetrics200Responses: 0, status: 404 };
    case "NFR-115":
      return { risk: "R0", durableWrites: 0, authorityIpc: 0, grantReceipts: 0, createRejected: true };
    case "NFR-116":
      return sampledCount({ sessions: 1_000, uniqueFingerprints: 1, authorityReissues: 0 }, 1_000);
    case "NFR-117":
      return { previewCount: 1, authorizeCount: 1, authorityActionCount: 1, r0ActionCount: 0, authorityIdPresent: true };
    case "NFR-118":
      return { sampleCount: 1_000, p95Ms: 0.001, sessionLookups: 0, algorithmInputs: ["clientId", "issuer", "ownerInstanceId", "resource"] };
    case "NFR-119":
      return sampledCount({ claims: 10_000, p95Ms: 50, duplicateDispatches: 0 }, 10_000);
    case "NFR-120":
      return { sampleCount: 250, p95Ms: 5, maxMs: 5 };
    case "NFR-121":
      return { tamperCases: 3, typedRejects: 3, dataMixes: 0 };
    case "NFR-122":
      return { recordLosses: 0, uriLosses: 0, resourceUri: "resource://artifact-restart" };
    case "NFR-123":
      return {
        evidenceBytes: 1_024,
        evidenceType: SELF_RESTART_EVIDENCE_TYPE,
        terminalState: "PASS",
        historyStates: ["PREPARED", "RESPONSE_BOUND", "ACK_FLUSHED", "HANDOFF_ACCEPTED", "RESTARTING", "VERIFYING", "PASS"],
        restartBeforeAckFlushed: 0,
        validationFailures: [],
      };
    case "NFR-124":
      return { privateHttpEndpoint: "configured", sampleCount: 100, status: 200, readinessState: "ready", p95Ms: 250, mutationSideEffects: 0 };
    case "NFR-125":
      return { liveManagementEndpoint: "configured", httpStatus: 200, durationMs: 30_000, status: "PASS", cleanup: { state: "CLEANED", receiptDigest: `sha256:${"a".repeat(64)}` } };
    case "NFR-126":
      return { configuredPreAuthBurst: 6, observedHttpStatuses: [200, 429], rejectedStatus: 429, rejectedRetryAfterSeconds: 1, rejectedRemaining: "0", allowedProviderDispatches: 1, providerDispatchesAtThreshold: 0 };
    case "NFR-127":
      return { preExpiryBlocked: true, recoveredAfterExpiry: true, fencingAdvanced: true, staleWriterOverwrites: 0, currentWriterRetained: true };
    case "NFR-128":
      return { applied: true, interruptedBeforeCheckpoint: true, tamperedRejected: true, stalePlanApplies: 0, stalePlanProviderDispatches: 0, resumedEntries: 1, copyDispatches: 1, deleteDispatches: 1, checkpointResumeDuplicates: 0 };
    case "NFR-129":
      return { acceptedEvents: 50, receiptCount: 50, eventLoss: 0, secretLeak: 0 };
    case "NFR-130":
      return { missingRawFails: true, thresholdFails: true, rawThresholdPassFails: true, notRunFailsRelease: true, notRunFocusedDoesNotClaimRelease: true, packageCommandPresent: true };
    default:
      throw new Error(`No synthetic NFR raw fixture registered for ${id}`);
  }
}

function sampledLatency(sampleCount, p95Ms) {
  return {
    sampleCount,
    p95Ms,
    maxMs: p95Ms,
    requiredReleaseSampleCount: sampleCount,
    focusedSample: false,
  };
}

function sampledCount(raw, requiredReleaseSampleCount) {
  return {
    ...raw,
    requiredReleaseSampleCount,
    focusedSample: false,
  };
}

function selfRestartEvidence() {
  const states = [
    "PREPARED",
    "RESPONSE_BOUND",
    "ACK_FLUSHED",
    "HANDOFF_ACCEPTED",
    "RESTARTING",
    "VERIFYING",
    "PASS",
  ];
  const timeline = states.map((state, index) => ({
    state,
    at: new Date(Date.UTC(2026, 7, 20, 0, 0, index)).toISOString(),
  }));
  const identity = {
    productVersion: "2.1.0",
    productProfile: "BASE_SINGLE_OWNER",
    buildCapabilityDigest: `sha256:${"1".repeat(64)}`,
    resourceUriVersion: "v1",
    schemaGeneration: `sha256:${"2".repeat(64)}`,
    authorityContractGeneration: `sha256:${"3".repeat(64)}`,
    configDigest: `sha256:${"4".repeat(64)}`,
    sourceRevision: "source-revision",
    runtimeRevision: "runtime-revision",
    buildDigest: `sha256:${"5".repeat(64)}`,
  };
  return {
    schemaVersion: 1,
    evidenceType: SELF_RESTART_EVIDENCE_TYPE,
    transactionId: "restart_12345678-1234-4234-8234-123456789abc",
    responseBound: {
      transactionId: "restart_12345678-1234-4234-8234-123456789abc",
      state: "RESPONSE_BOUND",
      observedAt: timeline[1].at,
      responseBoundAt: timeline[1].at,
      requestIdSha256: `sha256:${"6".repeat(64)}`,
      transportIdSha256: `sha256:${"7".repeat(64)}`,
      sessionIdSha256: `sha256:${"8".repeat(64)}`,
    },
    statusReadback: {
      transactionId: "restart_12345678-1234-4234-8234-123456789abc",
      state: "PASS",
      observedAt: timeline.at(-1).at,
      requestIdSha256: `sha256:${"6".repeat(64)}`,
      transportIdSha256: `sha256:${"7".repeat(64)}`,
      sessionIdSha256: `sha256:${"9".repeat(64)}`,
      newSession: true,
    },
    timeline,
    timing: {
      responseBoundAt: timeline[1].at,
      ackFlushedAt: timeline[2].at,
      handoffAcceptedAt: timeline[3].at,
      restartStartedAt: timeline[4].at,
      verifyingAt: timeline[5].at,
      completedAt: timeline[6].at,
    },
    runtime: {
      pidBefore: 101,
      pidAfter: 202,
      pm2Status: "online",
      cwdSha256: `sha256:${"a".repeat(64)}`,
      scriptSha256: `sha256:${"b".repeat(64)}`,
      localHealthStatus: 200,
      publicHealthStatus: 200,
      expectedRuntimeIdentity: identity,
    },
    handoff: {
      policy: "ACK_FLUSHED_ONLY",
      pm2Restarted: true,
      pm2Saved: true,
    },
    postRestartLocalHealth: {
      status: "ok",
      productVersion: identity.productVersion,
      productProfile: identity.productProfile,
      buildCapabilityDigest: identity.buildCapabilityDigest,
      resourceUriVersion: identity.resourceUriVersion,
      schemaGeneration: identity.schemaGeneration,
      authorityContractGeneration: identity.authorityContractGeneration,
      runtimeRevision: identity.runtimeRevision,
      startedAt: timeline.at(-1).at,
    },
    postRestartPublicHealth: {
      status: "ok",
      productVersion: identity.productVersion,
      productProfile: identity.productProfile,
      buildCapabilityDigest: identity.buildCapabilityDigest,
      resourceUriVersion: identity.resourceUriVersion,
      schemaGeneration: identity.schemaGeneration,
      authorityContractGeneration: identity.authorityContractGeneration,
      runtimeRevision: identity.runtimeRevision,
      startedAt: timeline.at(-1).at,
    },
    restartBeforeAckFlushed: 0,
  };
}

function rawSelfRestartObservation() {
  const evidence = selfRestartEvidence();
  const responseRequestId = "json-rpc-request-17";
  const responseTransportId = "http-response-transport-23";
  const runtime = evidence.runtime;
  return {
    requestSessionId: "mcp-session-before",
    statusSessionId: "mcp-session-after",
    responseBoundObservedAt: evidence.responseBound.observedAt,
    statusObservedAt: evidence.statusReadback.observedAt,
    responseBound: {
      version: 2,
      transactionId: evidence.transactionId,
      state: "RESPONSE_BOUND",
      responseRequestId,
      responseTransportId,
      responseBoundAt: evidence.timing.responseBoundAt,
      history: evidence.timeline.slice(0, 2),
    },
    terminalStatus: {
      version: 2,
      transactionId: evidence.transactionId,
      state: "PASS",
      responseRequestId,
      responseTransportId,
      history: evidence.timeline,
      ...evidence.timing,
      pidBefore: runtime.pidBefore,
      pidAfter: runtime.pidAfter,
      pm2Status: runtime.pm2Status,
      cwd: "/immutable/runtime",
      script: "/immutable/runtime/scripts/start.sh",
      localHealthStatus: runtime.localHealthStatus,
      publicHealthStatus: runtime.publicHealthStatus,
      expectedRuntimeIdentity: runtime.expectedRuntimeIdentity,
      evidence: {
        handoffPolicy: evidence.handoff.policy,
        pm2Restarted: evidence.handoff.pm2Restarted,
        pm2Saved: evidence.handoff.pm2Saved,
      },
    },
    postRestartLocalHealth: evidence.postRestartLocalHealth,
    postRestartPublicHealth: evidence.postRestartPublicHealth,
  };
}
