import { BASE_PRODUCT_PROFILE } from "./profile-contract.js";
import { UNIVERSAL_TOOL_NAMES } from "./contracts.js";
import {
  digestOperationAuditPayload,
  type StoredOperationAuditEvent,
} from "./operation-audit.js";

export const PERSONAL_ACTUAL_HOST_SECTION_IDS = Object.freeze([
  "discovery",
  "localFilesystem",
  "localCompositeExec",
  "processLifecycle",
  "sshTarget",
  "downstreamMcp",
  "artifact",
  "gui",
  "recoveryRegression",
  "reconnection",
] as const);

export type PersonalActualHostSectionId = typeof PERSONAL_ACTUAL_HOST_SECTION_IDS[number];

export interface PersonalActualHostRunManifest {
  acceptanceRunId: string;
  productProfile: string;
  sourceRevision: string;
  runtimeRevision: string;
  buildDigest: string;
  schemaGeneration: string;
  runtimeStartedAt: string;
  connectorInstallationEpoch: number;
  connectorRotationSequenceBefore: number;
  connectorRotationSequenceAfter: number;
  auditSequenceStart: number;
  auditSequenceEnd: number;
  auditFirstEventDigest: string;
  auditLastEventDigest: string;
  startedAt: string;
  endedAt: string;
  chatGptConversationId: string;
  primaryPrincipalFingerprintPrefix: string;
  targetGeneration?: string;
  routeGeneration?: string;
}

export interface PersonalActualHostEvidence {
  evidenceSource: string;
  hostProduct: string;
  connectorName: string;
  toolNames: readonly string[];
  run: PersonalActualHostRunManifest;
  actualMutationEvidenceIds: readonly string[];
  receiptPayloads: Readonly<Record<string, unknown>>;
  sections: Record<PersonalActualHostSectionId, {
    status: "PASS" | "FAIL" | "NOT_RUN";
    evidenceIds: readonly string[];
  }>;
  recoveryFixture: {
    terminalRecords: number;
    runningRecords: number;
    expiredTerminalRecords: number;
    corruptTerminalRecords: number;
    prepareOperationId: string;
    recoveredVerificationOperationId: string;
    cleanVerificationOperationId: string;
  };
  reconnection: {
    newChatGptSessionMutationOperationId: string;
    brokerRestartOperationId: string;
    postRestartMutationOperationId: string;
    tokenRefreshMutationOperationId: string;
    distinctClientIsolationOperationId: string;
  };
}

export interface PersonalActualHostAcceptanceResult {
  status: "PERSONAL_DIRECT_OWNER_E2E_PASS";
  acceptanceRunId: string;
  auditSequenceStart: number;
  auditSequenceEnd: number;
  auditLastEventDigest: string;
  verifiedEvidenceCount: number;
  verifiedMutationCount: number;
  sections: readonly PersonalActualHostSectionId[];
}

const SECTION_TOOL_REQUIREMENTS: Readonly<Record<
  PersonalActualHostSectionId,
  readonly string[]
>> = Object.freeze({
  discovery: ["target"],
  localFilesystem: ["fs"],
  localCompositeExec: ["exec"],
  processLifecycle: ["process"],
  sshTarget: ["fs", "exec", "target"],
  downstreamMcp: ["mcp"],
  artifact: ["artifact"],
  gui: ["gui"],
  recoveryRegression: ["exec", "process"],
  reconnection: ["fs", "exec", "process"],
});
const SHA256 = /^sha256:[a-f0-9]{64}$/u;
const PRINCIPAL_PREFIX = /^[a-f0-9]{12}$/u;
const CHATGPT_CONVERSATION_ID = /^[a-z0-9][a-z0-9-]{15,127}$/u;

export function verifyPersonalActualHostEvidence(
  input: PersonalActualHostEvidence,
  auditRecords: readonly StoredOperationAuditEvent[],
): PersonalActualHostAcceptanceResult {
  verifyStaticHostContract(input);
  verifyAuditRecordChain(auditRecords);
  const run = verifyRunManifest(input.run);
  const records = auditRange(auditRecords, run);
  const byOperationId = uniqueRecordsByOperationId(records);
  const referenced = new Set<string>();

  for (const sectionId of PERSONAL_ACTUAL_HOST_SECTION_IDS) {
    const section = input.sections?.[sectionId];
    if (section?.status !== "PASS" || !Array.isArray(section.evidenceIds) || section.evidenceIds.length === 0) {
      throw new Error(`Actual-host section ${sectionId} is not PASS with concrete evidence.`);
    }
    const sectionRecords = section.evidenceIds.map((operationId) => {
      if (referenced.has(operationId)) {
        throw new Error(`Actual-host operation ${operationId} is reused across sections.`);
      }
      referenced.add(operationId);
      return verifiedEvidenceRecord(input, run, byOperationId, operationId);
    });
    const allowedTools = SECTION_TOOL_REQUIREMENTS[sectionId];
    if (!sectionRecords.some((record) => allowedTools.includes(record.tool))) {
      throw new Error(`Actual-host section ${sectionId} lacks its required tool evidence.`);
    }
    if (!sectionRecords.some((record) => record.result === "pass")) {
      throw new Error(`Actual-host section ${sectionId} has no successful operation.`);
    }
  }

  const mutationIds = uniqueNonEmpty(input.actualMutationEvidenceIds, "actual mutation evidence");
  if (mutationIds.length < 6) {
    throw new Error("Read-only smoke evidence cannot substitute for the required actual mutations.");
  }
  for (const operationId of mutationIds) {
    const record = verifiedEvidenceRecord(input, run, byOperationId, operationId);
    requireAcknowledgedMutation(record, operationId);
  }

  verifyRecoveryFixture(input, run, byOperationId);
  verifyReconnection(input, run, byOperationId);

  return {
    status: "PERSONAL_DIRECT_OWNER_E2E_PASS",
    acceptanceRunId: run.acceptanceRunId,
    auditSequenceStart: run.auditSequenceStart,
    auditSequenceEnd: run.auditSequenceEnd,
    auditLastEventDigest: run.auditLastEventDigest,
    verifiedEvidenceCount: referenced.size,
    verifiedMutationCount: mutationIds.length,
    sections: PERSONAL_ACTUAL_HOST_SECTION_IDS,
  };
}

function verifyAuditRecordChain(auditRecords: readonly StoredOperationAuditEvent[]): void {
  if (auditRecords.length === 0) throw new Error("Actual-host audit ledger is empty.");
  let previousEventDigest: string | undefined;
  for (const [index, record] of auditRecords.entries()) {
    const expectedSequence = index + 1;
    if (record.schemaVersion !== 1 || record.sequence !== expectedSequence) {
      throw new Error(`Actual-host audit sequence is invalid at ${expectedSequence}.`);
    }
    if (record.previousEventDigest !== previousEventDigest) {
      throw new Error(`Actual-host audit previous digest is invalid at ${expectedSequence}.`);
    }
    const { eventDigest, ...unsigned } = record;
    if (!SHA256.test(eventDigest) || digestOperationAuditPayload(unsigned) !== eventDigest) {
      throw new Error(`Actual-host audit event digest is invalid at ${expectedSequence}.`);
    }
    previousEventDigest = eventDigest;
  }
}

function verifyStaticHostContract(input: PersonalActualHostEvidence): void {
  if (input.evidenceSource !== "ACTUAL_CHATGPT_INSTALLED_CONNECTOR") {
    throw new Error("Synthetic, curl, local SDK, PM2, and health-only evidence cannot satisfy actual-host acceptance.");
  }
  if (input.hostProduct !== "ChatGPT" || input.connectorName !== "myDevSpace-v2-production") {
    throw new Error("Actual-host evidence must use the installed myDevSpace-v2-production ChatGPT connector.");
  }
  if (JSON.stringify(input.toolNames) !== JSON.stringify(UNIVERSAL_TOOL_NAMES)) {
    throw new Error("Actual-host discovery must report the exact ordered eight-tool surface.");
  }
  if (!input.receiptPayloads || typeof input.receiptPayloads !== "object") {
    throw new Error("Actual-host evidence must include receipt payloads bound to the audit ledger.");
  }
}

function verifyRunManifest(run: PersonalActualHostRunManifest): PersonalActualHostRunManifest {
  if (!run || run.productProfile !== BASE_PRODUCT_PROFILE) {
    throw new Error(`Actual-host run profile must be ${BASE_PRODUCT_PROFILE}.`);
  }
  for (const [field, value] of [
    ["acceptanceRunId", run.acceptanceRunId],
    ["sourceRevision", run.sourceRevision],
    ["runtimeRevision", run.runtimeRevision],
  ] as const) {
    if (!safeIdentifier(value)) throw new Error(`Actual-host run ${field} is invalid.`);
  }
  for (const [field, value] of [
    ["buildDigest", run.buildDigest],
    ["schemaGeneration", run.schemaGeneration],
    ["auditFirstEventDigest", run.auditFirstEventDigest],
    ["auditLastEventDigest", run.auditLastEventDigest],
  ] as const) {
    if (!SHA256.test(value)) throw new Error(`Actual-host run ${field} is not a SHA-256 digest.`);
  }
  if (run.targetGeneration && !SHA256.test(run.targetGeneration)) {
    throw new Error("Actual-host target generation is invalid.");
  }
  if (run.routeGeneration && !SHA256.test(run.routeGeneration)) {
    throw new Error("Actual-host route generation is invalid.");
  }
  if (!PRINCIPAL_PREFIX.test(run.primaryPrincipalFingerprintPrefix)) {
    throw new Error("Actual-host primary principal fingerprint prefix is invalid.");
  }
  if (!CHATGPT_CONVERSATION_ID.test(run.chatGptConversationId)) {
    throw new Error("Actual-host ChatGPT conversation identity is invalid.");
  }
  const startedAtMs = timestamp(run.startedAt, "startedAt");
  const endedAtMs = timestamp(run.endedAt, "endedAt");
  timestamp(run.runtimeStartedAt, "runtimeStartedAt");
  if (endedAtMs < startedAtMs) throw new Error("Actual-host run ended before it started.");
  if (!positiveInteger(run.connectorInstallationEpoch)) {
    throw new Error("Actual-host connector installation epoch is invalid.");
  }
  if (!nonNegativeInteger(run.connectorRotationSequenceBefore)
    || !nonNegativeInteger(run.connectorRotationSequenceAfter)
    || run.connectorRotationSequenceAfter <= run.connectorRotationSequenceBefore) {
    throw new Error("Actual-host connector rotation sequence did not advance.");
  }
  if (!positiveInteger(run.auditSequenceStart)
    || !positiveInteger(run.auditSequenceEnd)
    || run.auditSequenceEnd < run.auditSequenceStart) {
    throw new Error("Actual-host audit sequence range is invalid.");
  }
  return run;
}

function auditRange(
  auditRecords: readonly StoredOperationAuditEvent[],
  run: PersonalActualHostRunManifest,
): readonly StoredOperationAuditEvent[] {
  const first = auditRecords.find((record) => record.sequence === run.auditSequenceStart);
  const last = auditRecords.find((record) => record.sequence === run.auditSequenceEnd);
  if (!first || !last) throw new Error("Actual-host audit sequence range is not present in the verified ledger.");
  if (first.eventDigest !== run.auditFirstEventDigest || last.eventDigest !== run.auditLastEventDigest) {
    throw new Error("Actual-host audit boundary digest does not match the verified ledger.");
  }
  const records = auditRecords.filter((record) => (
    record.sequence >= run.auditSequenceStart && record.sequence <= run.auditSequenceEnd
  ));
  if (records.length !== run.auditSequenceEnd - run.auditSequenceStart + 1) {
    throw new Error("Actual-host audit sequence range contains a gap.");
  }
  return records;
}

function uniqueRecordsByOperationId(
  records: readonly StoredOperationAuditEvent[],
): ReadonlyMap<string, StoredOperationAuditEvent> {
  const byOperationId = new Map<string, StoredOperationAuditEvent>();
  for (const record of records) {
    if (byOperationId.has(record.operationId)) {
      throw new Error(`Actual-host audit contains duplicate operationId ${record.operationId}.`);
    }
    byOperationId.set(record.operationId, record);
  }
  return byOperationId;
}

function verifiedEvidenceRecord(
  input: PersonalActualHostEvidence,
  run: PersonalActualHostRunManifest,
  byOperationId: ReadonlyMap<string, StoredOperationAuditEvent>,
  operationId: string,
): StoredOperationAuditEvent {
  if (!safeIdentifier(operationId)) throw new Error(`Actual-host evidence ID is invalid: ${operationId}`);
  const record = byOperationId.get(operationId);
  if (!record) throw new Error(`Actual-host evidence ID is absent from the verified audit range: ${operationId}`);
  verifyRecordRunIdentity(record, run);
  if (!record.actionDigest || !SHA256.test(record.actionDigest)) {
    throw new Error(`Actual-host evidence ${operationId} lacks an action digest.`);
  }
  if (!record.receiptDigest || !SHA256.test(record.receiptDigest)) {
    throw new Error(`Actual-host evidence ${operationId} lacks a receipt digest.`);
  }
  if (!Object.hasOwn(input.receiptPayloads, operationId)) {
    throw new Error(`Actual-host receipt payload is missing: ${operationId}`);
  }
  const receipt = input.receiptPayloads[operationId];
  if (digestOperationAuditPayload(receipt) !== record.receiptDigest) {
    throw new Error(`Actual-host receipt payload digest mismatch: ${operationId}`);
  }
  return record;
}

function verifyRecordRunIdentity(
  record: StoredOperationAuditEvent,
  run: PersonalActualHostRunManifest,
): void {
  for (const [field, expected] of [
    ["acceptanceRunId", run.acceptanceRunId],
    ["productProfile", run.productProfile],
    ["sourceRevision", run.sourceRevision],
    ["runtimeRevision", run.runtimeRevision],
    ["buildDigest", run.buildDigest],
    ["schemaGeneration", run.schemaGeneration],
    ["runtimeStartedAt", new Date(run.runtimeStartedAt).toISOString()],
    ["connectorInstallationEpoch", run.connectorInstallationEpoch],
  ] as const) {
    if (record[field] !== expected) {
      throw new Error(`Actual-host evidence ${record.operationId} crosses run identity field ${field}.`);
    }
  }
  const occurredAt = timestamp(record.timestamp, `audit timestamp ${record.operationId}`);
  if (occurredAt < Date.parse(run.startedAt) || occurredAt > Date.parse(run.endedAt)) {
    throw new Error(`Actual-host evidence ${record.operationId} is outside the run time window.`);
  }
  if (record.targetGeneration && run.targetGeneration && record.targetGeneration !== run.targetGeneration) {
    throw new Error(`Actual-host evidence ${record.operationId} crosses target generation.`);
  }
  if (record.routeGeneration && run.routeGeneration && record.routeGeneration !== run.routeGeneration) {
    throw new Error(`Actual-host evidence ${record.operationId} crosses route generation.`);
  }
}

function requireAcknowledgedMutation(record: StoredOperationAuditEvent, operationId: string): void {
  if (!/^R[1-3]$/u.test(record.risk)
    || record.result !== "pass"
    || record.dispatchState !== "ACKNOWLEDGED") {
    throw new Error(`Actual-host mutation ${operationId} is not an acknowledged PASS mutation.`);
  }
}

function verifyRecoveryFixture(
  input: PersonalActualHostEvidence,
  run: PersonalActualHostRunManifest,
  byOperationId: ReadonlyMap<string, StoredOperationAuditEvent>,
): void {
  const fixture = input.recoveryFixture;
  if (!fixture
    || fixture.terminalRecords < 1_000
    || fixture.runningRecords < 2
    || fixture.expiredTerminalRecords < 1
    || fixture.corruptTerminalRecords < 1) {
    throw new Error("Recovery evidence does not contain the required regression fixture.");
  }
  const prepare = verifiedEvidenceRecord(input, run, byOperationId, fixture.prepareOperationId);
  const recovered = verifiedEvidenceRecord(
    input,
    run,
    byOperationId,
    fixture.recoveredVerificationOperationId,
  );
  const clean = verifiedEvidenceRecord(input, run, byOperationId, fixture.cleanVerificationOperationId);
  for (const record of [prepare, recovered, clean]) {
    if (record.result !== "pass" || record.dispatchState !== "ACKNOWLEDGED") {
      throw new Error(`Recovery evidence operation ${record.operationId} is not acknowledged PASS.`);
    }
  }
  const preparedClaim = embeddedPhase(input.receiptPayloads[fixture.prepareOperationId], "INPUT_READY");
  const recoveredClaim = embeddedPhase(
    input.receiptPayloads[fixture.recoveredVerificationOperationId],
    "RECOVERED",
  );
  const cleanClaim = embeddedPhase(input.receiptPayloads[fixture.cleanVerificationOperationId], "CLEAN");
  requireMinimumNumber(
    preparedClaim,
    "validRecordCount",
    fixture.terminalRecords + fixture.expiredTerminalRecords + fixture.runningRecords,
  );
  requireMinimumNumber(preparedClaim, "corruptRecordCount", fixture.corruptTerminalRecords);
  requireMinimumNumber(recoveredClaim, "retainedTerminalCount", fixture.terminalRecords);
  requireMinimumNumber(recoveredClaim, "prunedExpiredCount", fixture.expiredTerminalRecords);
  requireMinimumNumber(recoveredClaim, "reconciledRunningCount", fixture.runningRecords);
  requireMinimumNumber(recoveredClaim, "quarantinedCorruptCount", fixture.corruptTerminalRecords);
  if (cleanClaim.remainingCount !== 0) throw new Error("Recovery fixture cleanup is not clean.");
}

function verifyReconnection(
  input: PersonalActualHostEvidence,
  run: PersonalActualHostRunManifest,
  byOperationId: ReadonlyMap<string, StoredOperationAuditEvent>,
): void {
  const evidence = input.reconnection;
  if (!evidence) throw new Error("Reconnection evidence is missing.");
  const newSession = verifiedEvidenceRecord(
    input,
    run,
    byOperationId,
    evidence.newChatGptSessionMutationOperationId,
  );
  const restart = verifiedEvidenceRecord(input, run, byOperationId, evidence.brokerRestartOperationId);
  const postRestart = verifiedEvidenceRecord(
    input,
    run,
    byOperationId,
    evidence.postRestartMutationOperationId,
  );
  const tokenRefresh = verifiedEvidenceRecord(
    input,
    run,
    byOperationId,
    evidence.tokenRefreshMutationOperationId,
  );
  const distinctClient = verifiedEvidenceRecord(
    input,
    run,
    byOperationId,
    evidence.distinctClientIsolationOperationId,
  );
  for (const record of [newSession, restart, postRestart, tokenRefresh]) {
    requireAcknowledgedMutation(record, record.operationId);
    if (record.principalFingerprintPrefix !== run.primaryPrincipalFingerprintPrefix) {
      throw new Error(`Reconnection mutation ${record.operationId} belongs to a different principal.`);
    }
  }
  if (restart.tool !== "process" || restart.operation !== "restart_broker") {
    throw new Error("Reconnection broker restart evidence is not process.restart_broker.");
  }
  if (Date.parse(postRestart.timestamp) <= Date.parse(restart.timestamp)) {
    throw new Error("Reconnection post-restart mutation did not occur after the restart request.");
  }
  if (tokenRefresh.connectorRotationSequence !== run.connectorRotationSequenceAfter) {
    throw new Error("Token-refresh mutation is not bound to the post-rotation sequence.");
  }
  if (newSession.connectorRotationSequence === undefined
    || newSession.connectorRotationSequence < run.connectorRotationSequenceBefore) {
    throw new Error("New-session mutation has no valid connector rotation identity.");
  }
  if (distinctClient.principalFingerprintPrefix === run.primaryPrincipalFingerprintPrefix
    || distinctClient.result !== "fail"
    || distinctClient.dispatchState !== "NOT_DISPATCHED"
    || !distinctClient.errorCode) {
    throw new Error("Distinct-client isolation evidence is not a different-principal pre-dispatch failure.");
  }
}

function embeddedPhase(value: unknown, phase: string): Record<string, unknown> {
  const match = embeddedObjects(value).find((candidate) => candidate.phase === phase);
  if (!match) throw new Error(`Actual-host receipt does not contain phase ${phase}.`);
  return match;
}

function embeddedObjects(value: unknown): Record<string, unknown>[] {
  const found: Record<string, unknown>[] = [];
  const visit = (candidate: unknown): void => {
    if (typeof candidate === "string") {
      for (const line of candidate.split(/\r?\n/u)) {
        const trimmed = line.trim();
        if (!trimmed.startsWith("{") || !trimmed.endsWith("}")) continue;
        try { visit(JSON.parse(trimmed)); } catch { /* A non-JSON output line is ordinary evidence. */ }
      }
      return;
    }
    if (Array.isArray(candidate)) {
      for (const child of candidate) visit(child);
      return;
    }
    if (!candidate || typeof candidate !== "object") return;
    const record = candidate as Record<string, unknown>;
    found.push(record);
    for (const child of Object.values(record)) visit(child);
  };
  visit(value);
  return found;
}

function requireMinimumNumber(
  claim: Record<string, unknown>,
  field: string,
  minimum: number,
): void {
  const value = claim[field];
  if (typeof value !== "number" || !Number.isInteger(value) || value < minimum) {
    throw new Error(`Actual-host recovery claim ${field} is below ${minimum}.`);
  }
}

function uniqueNonEmpty(values: readonly string[], label: string): string[] {
  if (!Array.isArray(values) || values.some((value) => !safeIdentifier(value))) {
    throw new Error(`Actual-host ${label} is invalid.`);
  }
  const unique = [...new Set(values)];
  if (unique.length !== values.length) throw new Error(`Actual-host ${label} contains duplicates.`);
  return unique;
}

function safeIdentifier(value: unknown): value is string {
  return typeof value === "string" && /^[A-Za-z0-9][A-Za-z0-9._:@/-]{0,255}$/u.test(value);
}

function positiveInteger(value: unknown): value is number {
  return typeof value === "number" && Number.isSafeInteger(value) && value > 0;
}

function nonNegativeInteger(value: unknown): value is number {
  return typeof value === "number" && Number.isSafeInteger(value) && value >= 0;
}

function timestamp(value: string, field: string): number {
  const parsed = Date.parse(value);
  if (!Number.isFinite(parsed)) throw new Error(`Actual-host ${field} is not a timestamp.`);
  return parsed;
}
