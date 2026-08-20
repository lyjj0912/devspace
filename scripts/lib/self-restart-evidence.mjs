import { createHash } from "node:crypto";

export const SELF_RESTART_EVIDENCE_TYPE = "DEVSPACE_REV3_SELF_RESTART_ACK_FLUSHED";
export const SELF_RESTART_EVIDENCE_MAX_BYTES = 32 * 1024;

const TERMINAL_PASS_HISTORY = Object.freeze([
  "PREPARED",
  "RESPONSE_BOUND",
  "ACK_FLUSHED",
  "HANDOFF_ACCEPTED",
  "RESTARTING",
  "VERIFYING",
  "PASS",
]);
const DIGEST_PATTERN = /^sha256:[a-f0-9]{64}$/u;
const TRANSACTION_PATTERN = /^restart_[0-9a-f-]{36}$/u;

export function createBoundedSelfRestartEvidence(input) {
  const responseBound = record(input?.responseBound);
  const terminalStatus = record(input?.terminalStatus);
  const terminalEvidence = record(terminalStatus?.evidence);
  const requestSessionId = requiredText(input?.requestSessionId, "request session ID");
  const statusSessionId = requiredText(input?.statusSessionId, "status session ID");
  const requestId = requiredScalar(responseBound?.responseRequestId, "response request ID");
  const transportId = requiredText(responseBound?.responseTransportId, "response transport ID");
  const terminalRequestId = requiredScalar(terminalStatus?.responseRequestId, "terminal response request ID");
  const terminalTransportId = requiredText(terminalStatus?.responseTransportId, "terminal response transport ID");
  if (
    responseBound?.transactionId !== terminalStatus?.transactionId
    || String(requestId) !== String(terminalRequestId)
    || transportId !== terminalTransportId
  ) {
    throw new Error("Self-restart terminal status is not bound to the exact RESPONSE_BOUND transaction.");
  }
  const history = Array.isArray(terminalStatus?.history)
    ? terminalStatus.history.map((entry) => ({
        state: record(entry)?.state,
        at: record(entry)?.at,
      }))
    : [];
  const restartBeforeAckFlushed = history.findIndex((entry) => entry.state === "RESTARTING")
    < history.findIndex((entry) => entry.state === "ACK_FLUSHED")
    ? 1
    : 0;
  const value = {
    schemaVersion: 1,
    evidenceType: SELF_RESTART_EVIDENCE_TYPE,
    transactionId: terminalStatus?.transactionId,
    responseBound: {
      transactionId: responseBound?.transactionId,
      state: responseBound?.state,
      observedAt: normalizeTimestamp(input?.responseBoundObservedAt),
      responseBoundAt: responseBound?.responseBoundAt,
      requestIdSha256: sha256(String(requestId)),
      transportIdSha256: sha256(transportId),
      sessionIdSha256: sha256(requestSessionId),
    },
    statusReadback: {
      transactionId: terminalStatus?.transactionId,
      state: terminalStatus?.state,
      observedAt: normalizeTimestamp(input?.statusObservedAt),
      requestIdSha256: sha256(String(terminalRequestId)),
      transportIdSha256: sha256(terminalTransportId),
      sessionIdSha256: sha256(statusSessionId),
      newSession: requestSessionId !== statusSessionId,
    },
    timeline: history,
    timing: {
      responseBoundAt: terminalStatus?.responseBoundAt,
      ackFlushedAt: terminalStatus?.ackFlushedAt,
      handoffAcceptedAt: terminalStatus?.handoffAcceptedAt,
      restartStartedAt: terminalStatus?.restartStartedAt,
      verifyingAt: terminalStatus?.verifyingAt,
      completedAt: terminalStatus?.completedAt,
    },
    runtime: {
      pidBefore: terminalStatus?.pidBefore,
      pidAfter: terminalStatus?.pidAfter,
      pm2Status: terminalStatus?.pm2Status,
      cwdSha256: optionalDigest(terminalStatus?.cwd),
      scriptSha256: optionalDigest(terminalStatus?.script),
      localHealthStatus: terminalStatus?.localHealthStatus,
      publicHealthStatus: terminalStatus?.publicHealthStatus,
      expectedRuntimeIdentity: boundedRuntimeIdentity(terminalStatus?.expectedRuntimeIdentity),
    },
    handoff: {
      policy: terminalEvidence?.handoffPolicy,
      pm2Restarted: terminalEvidence?.pm2Restarted,
      pm2Saved: terminalEvidence?.pm2Saved,
    },
    postRestartLocalHealth: boundedPublicHealth(input?.postRestartLocalHealth),
    postRestartPublicHealth: boundedPublicHealth(input?.postRestartPublicHealth),
    restartBeforeAckFlushed,
  };
  const validation = validateSelfRestartEvidence(value);
  if (!validation.valid) {
    throw new Error(`Self-restart evidence is invalid: ${validation.failures.slice(0, 8).join("; ")}`);
  }
  return value;
}

export function validateSelfRestartEvidence(value) {
  const failures = [];
  const evidence = record(value);
  if (!evidence) return { valid: false, failures: ["evidence is not an object"], restartBeforeAckFlushed: 1 };
  let evidenceBytes = Number.POSITIVE_INFINITY;
  try {
    evidenceBytes = Buffer.byteLength(JSON.stringify(evidence), "utf8");
  } catch {
    failures.push("evidence is not JSON serializable");
  }
  if (evidenceBytes > SELF_RESTART_EVIDENCE_MAX_BYTES) {
    failures.push(`evidence exceeds ${SELF_RESTART_EVIDENCE_MAX_BYTES} bytes`);
  }
  if (evidence.schemaVersion !== 1) failures.push("schemaVersion must be 1");
  if (evidence.evidenceType !== SELF_RESTART_EVIDENCE_TYPE) failures.push("evidenceType is invalid");
  if (!TRANSACTION_PATTERN.test(String(evidence.transactionId ?? ""))) failures.push("transactionId is invalid");

  const responseBound = record(evidence.responseBound);
  const statusReadback = record(evidence.statusReadback);
  const timing = record(evidence.timing);
  const runtime = record(evidence.runtime);
  const handoff = record(evidence.handoff);
  const localHealth = record(evidence.postRestartLocalHealth);
  const publicHealth = record(evidence.postRestartPublicHealth);
  if (responseBound?.state !== "RESPONSE_BOUND") failures.push("request response did not return RESPONSE_BOUND");
  if (statusReadback?.state !== "PASS") failures.push("new-session restart_status is not PASS");
  if (responseBound?.transactionId !== evidence.transactionId) failures.push("RESPONSE_BOUND transactionId does not match evidence");
  if (statusReadback?.transactionId !== evidence.transactionId) failures.push("restart_status transactionId does not match evidence");
  if (statusReadback?.newSession !== true) failures.push("restart_status was not read through a new session");
  for (const [label, digest] of [
    ["response request", responseBound?.requestIdSha256],
    ["response transport", responseBound?.transportIdSha256],
    ["request session", responseBound?.sessionIdSha256],
    ["status session", statusReadback?.sessionIdSha256],
    ["status response request", statusReadback?.requestIdSha256],
    ["status response transport", statusReadback?.transportIdSha256],
  ]) {
    if (!DIGEST_PATTERN.test(String(digest ?? ""))) failures.push(`${label} digest is invalid`);
  }
  if (
    DIGEST_PATTERN.test(String(responseBound?.sessionIdSha256 ?? ""))
    && responseBound?.sessionIdSha256 === statusReadback?.sessionIdSha256
  ) failures.push("request and status session digests are identical");
  if (responseBound?.requestIdSha256 !== statusReadback?.requestIdSha256) {
    failures.push("restart_status response request binding does not match RESPONSE_BOUND");
  }
  if (responseBound?.transportIdSha256 !== statusReadback?.transportIdSha256) {
    failures.push("restart_status response transport binding does not match RESPONSE_BOUND");
  }

  const timeline = Array.isArray(evidence.timeline) ? evidence.timeline.map(record) : [];
  const states = timeline.map((entry) => entry?.state);
  if (JSON.stringify(states) !== JSON.stringify(TERMINAL_PASS_HISTORY)) {
    failures.push(`history must be ${TERMINAL_PASS_HISTORY.join(" -> ")}`);
  }
  const timelineTimes = timeline.map((entry, index) => parsedTimestamp(entry?.at, `history[${index}].at`, failures));
  if (timelineTimes.every(Number.isFinite)) {
    for (let index = 1; index < timelineTimes.length; index += 1) {
      if (timelineTimes[index] < timelineTimes[index - 1]) failures.push("history timestamps are not monotonic");
    }
  }
  const stateTimes = Object.fromEntries(timeline.map((entry) => [entry?.state, entry?.at]));
  if (responseBound?.responseBoundAt !== stateTimes.RESPONSE_BOUND) {
    failures.push("RESPONSE_BOUND observation timestamp is not bound to durable history");
  }
  for (const [field, state] of [
    ["responseBoundAt", "RESPONSE_BOUND"],
    ["ackFlushedAt", "ACK_FLUSHED"],
    ["handoffAcceptedAt", "HANDOFF_ACCEPTED"],
    ["restartStartedAt", "RESTARTING"],
    ["verifyingAt", "VERIFYING"],
    ["completedAt", "PASS"],
  ]) {
    parsedTimestamp(timing?.[field], `timing.${field}`, failures);
    if (timing?.[field] !== stateTimes[state]) failures.push(`timing.${field} is not bound to ${state}`);
  }
  const responseObservedAt = parsedTimestamp(responseBound?.observedAt, "responseBound.observedAt", failures);
  const statusObservedAt = parsedTimestamp(statusReadback?.observedAt, "statusReadback.observedAt", failures);
  if (Number.isFinite(responseObservedAt) && responseObservedAt < Date.parse(String(timing?.responseBoundAt ?? ""))) {
    failures.push("RESPONSE_BOUND was observed before its durable timestamp");
  }
  if (Number.isFinite(statusObservedAt) && statusObservedAt < Date.parse(String(timing?.completedAt ?? ""))) {
    failures.push("terminal PASS was observed before its durable timestamp");
  }
  const ackAt = Date.parse(String(timing?.ackFlushedAt ?? ""));
  const restartAt = Date.parse(String(timing?.restartStartedAt ?? ""));
  const restartBeforeAckFlushed = Number.isFinite(ackAt) && Number.isFinite(restartAt) && restartAt >= ackAt ? 0 : 1;
  if (evidence.restartBeforeAckFlushed !== restartBeforeAckFlushed) {
    failures.push("restartBeforeAckFlushed does not match the durable timeline");
  }
  if (restartBeforeAckFlushed !== 0) failures.push("restart began before ACK_FLUSHED");

  if (!positiveInteger(runtime?.pidBefore)) failures.push("pidBefore is invalid");
  if (!positiveInteger(runtime?.pidAfter)) failures.push("pidAfter is invalid");
  if (runtime?.pidBefore === runtime?.pidAfter) failures.push("PID did not change");
  if (runtime?.pm2Status !== "online") failures.push("PM2 terminal status is not online");
  if (!DIGEST_PATTERN.test(String(runtime?.cwdSha256 ?? ""))) failures.push("cwd digest is invalid");
  if (!DIGEST_PATTERN.test(String(runtime?.scriptSha256 ?? ""))) failures.push("script digest is invalid");
  if (runtime?.localHealthStatus !== 200) failures.push("local health status is not 200");
  if (runtime?.publicHealthStatus !== 200) failures.push("public health status is not 200");
  if (handoff?.policy !== "ACK_FLUSHED_ONLY") failures.push("handoff policy is not ACK_FLUSHED_ONLY");
  if (handoff?.pm2Restarted !== true) failures.push("PM2 restart was not confirmed");
  if (handoff?.pm2Saved !== true) failures.push("PM2 save was not confirmed");

  const identity = record(runtime?.expectedRuntimeIdentity);
  for (const key of [
    "productVersion",
    "productProfile",
    "resourceUriVersion",
    "sourceRevision",
    "runtimeRevision",
  ]) {
    if (typeof identity?.[key] !== "string" || identity[key].length === 0) failures.push(`runtime identity ${key} is missing`);
  }
  for (const key of [
    "buildCapabilityDigest",
    "schemaGeneration",
    "authorityContractGeneration",
    "configDigest",
    "buildDigest",
  ]) {
    if (!DIGEST_PATTERN.test(String(identity?.[key] ?? ""))) failures.push(`runtime identity ${key} is invalid`);
  }
  if (localHealth?.status !== "ok") failures.push("post-restart local health is not ok");
  if (publicHealth?.status !== "ok") failures.push("post-restart public health is not ok");
  for (const key of [
    "productVersion",
    "productProfile",
    "buildCapabilityDigest",
    "resourceUriVersion",
    "schemaGeneration",
    "authorityContractGeneration",
    "runtimeRevision",
  ]) {
    if (localHealth?.[key] !== identity?.[key]) failures.push(`post-restart local health ${key} does not match runtime identity`);
    if (publicHealth?.[key] !== identity?.[key]) failures.push(`post-restart public health ${key} does not match runtime identity`);
    if (publicHealth?.[key] !== localHealth?.[key]) failures.push(`post-restart public health ${key} does not match local candidate health`);
  }
  const localStartedAt = parsedTimestamp(localHealth?.startedAt, "postRestartLocalHealth.startedAt", failures);
  const publicStartedAt = parsedTimestamp(publicHealth?.startedAt, "postRestartPublicHealth.startedAt", failures);
  if (Number.isFinite(localStartedAt) && Number.isFinite(publicStartedAt) && localStartedAt !== publicStartedAt) {
    failures.push("post-restart public health startedAt does not match the local candidate process");
  }

  return {
    valid: failures.length === 0,
    failures,
    restartBeforeAckFlushed,
    historyStates: states,
    evidenceBytes,
  };
}

function boundedRuntimeIdentity(value) {
  const identity = record(value);
  if (!identity) return undefined;
  return Object.fromEntries([
    "productVersion",
    "productProfile",
    "buildCapabilityDigest",
    "resourceUriVersion",
    "schemaGeneration",
    "authorityContractGeneration",
    "configDigest",
    "sourceRevision",
    "runtimeRevision",
    "buildDigest",
  ].map((key) => [key, identity[key]]));
}

function boundedPublicHealth(value) {
  const health = record(value);
  if (!health) return undefined;
  return Object.fromEntries([
    "status",
    "productVersion",
    "productProfile",
    "buildCapabilityDigest",
    "resourceUriVersion",
    "schemaGeneration",
    "authorityContractGeneration",
    "runtimeRevision",
    "startedAt",
  ].map((key) => [key, health[key]]));
}

function optionalDigest(value) {
  return typeof value === "string" && value.length > 0 ? sha256(value) : undefined;
}

function sha256(value) {
  return `sha256:${createHash("sha256").update(value).digest("hex")}`;
}

function normalizeTimestamp(value) {
  const timestamp = value === undefined ? new Date() : new Date(value);
  if (!Number.isFinite(timestamp.valueOf())) throw new Error("Self-restart evidence timestamp is invalid.");
  return timestamp.toISOString();
}

function parsedTimestamp(value, label, failures) {
  const parsed = Date.parse(String(value ?? ""));
  if (!Number.isFinite(parsed)) failures.push(`${label} is invalid`);
  return parsed;
}

function positiveInteger(value) {
  return Number.isInteger(value) && value > 0;
}

function requiredScalar(value, label) {
  if ((typeof value !== "string" && typeof value !== "number") || String(value).length === 0) {
    throw new Error(`Self-restart ${label} is missing.`);
  }
  return value;
}

function requiredText(value, label) {
  if (typeof value !== "string" || value.length === 0) throw new Error(`Self-restart ${label} is missing.`);
  return value;
}

function record(value) {
  return value && typeof value === "object" && !Array.isArray(value) ? value : undefined;
}
