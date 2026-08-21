import assert from "node:assert/strict";
import test from "node:test";
import {
  PERSONAL_ACTUAL_HOST_SECTION_IDS,
  verifyPersonalActualHostEvidence,
  type PersonalActualHostEvidence,
} from "./personal-actual-host-acceptance.js";
import {
  digestOperationAuditPayload,
  type StoredOperationAuditEvent,
} from "./operation-audit.js";

const ACCEPTANCE_RUN_ID = "pdo-e2e-20260822-ledger-0001";
const PRODUCT_PROFILE = "PERSONAL_DIRECT_OWNER";
const SOURCE_REVISION = "02c2af72a174fb61860c166c989e635b18037865";
const RUNTIME_REVISION = "02c2af72a174fb61860c166c989e635b18037865";
const BUILD_DIGEST = `sha256:${"a".repeat(64)}`;
const SCHEMA_GENERATION = `sha256:${"b".repeat(64)}`;
const TARGET_GENERATION = `sha256:${"c".repeat(64)}`;
const ROUTE_GENERATION = `sha256:${"d".repeat(64)}`;
const RUNTIME_STARTED_AT = "2026-08-21T23:50:00.000Z";
const RUN_STARTED_AT = "2026-08-22T00:00:00.000Z";
const RUN_ENDED_AT = "2026-08-22T00:30:00.000Z";
const PRIMARY_PRINCIPAL = "1a2b3c4d5e6f";
const DISTINCT_PRINCIPAL = "abcdef123456";
const CONNECTOR_EPOCH = 3;
const ROTATION_BEFORE = 29;
const ROTATION_AFTER = 30;

interface Fixture {
  evidence: PersonalActualHostEvidence;
  auditRecords: StoredOperationAuditEvent[];
}

interface AuditSpecification {
  id: string;
  tool: string;
  operation: string;
  risk: "R0" | "R1" | "R2" | "R3";
  receipt: unknown;
  minute: number;
  rotation?: number;
  principal?: string;
  result?: "pass" | "fail" | "unknown";
  dispatchState?: string;
  errorCode?: string;
  target?: boolean;
  route?: boolean;
}

function fixture(): Fixture {
  const specifications: AuditSpecification[] = [
    pass("op_discovery", "target", "list", "R0", 1),
    pass("op_local_fs_write", "fs", "write", "R1", 2, { target: true }),
    pass("op_local_exec", "exec", "run", "R2", 3, { target: true }),
    pass("op_process_signal", "process", "signal", "R2", 4, { target: true }),
    pass("op_ssh_write", "fs", "write", "R1", 5, { target: true }),
    pass("op_downstream_mcp", "mcp", "invoke", "R2", 6, { route: true }),
    pass("op_artifact_copy", "artifact", "copy", "R2", 7, { target: true }),
    pass("op_gui_act", "gui", "act", "R2", 8, { target: true }),
    pass("op_recovery_prepare", "exec", "run", "R2", 9, {
      target: true,
      receipt: successReceipt("op_recovery_prepare", {
        output: `${JSON.stringify({
          phase: "INPUT_READY",
          validRecordCount: 1_007,
          corruptRecordCount: 1,
        })}\n`,
      }),
    }),
    pass("op_recovery_recovered", "exec", "run", "R2", 10, {
      target: true,
      receipt: successReceipt("op_recovery_recovered", {
        output: `${JSON.stringify({
          phase: "RECOVERED",
          retainedTerminalCount: 1_000,
          prunedExpiredCount: 5,
          reconciledRunningCount: 2,
          quarantinedCorruptCount: 1,
        })}\n`,
      }),
    }),
    pass("op_recovery_clean", "exec", "run", "R2", 11, {
      target: true,
      receipt: successReceipt("op_recovery_clean", {
        output: `${JSON.stringify({ phase: "CLEAN", remainingCount: 0 })}\n`,
      }),
    }),
    pass("op_new_session_write", "fs", "write", "R1", 12, {
      target: true,
      rotation: ROTATION_BEFORE,
    }),
    pass("op_restart_broker", "process", "restart_broker", "R3", 13, {
      rotation: ROTATION_BEFORE,
      receipt: successReceipt("op_restart_broker", {
        state: "ACK_FLUSHED",
        transactionId: "restart_fixture",
      }),
    }),
    pass("op_post_restart_write", "fs", "write", "R1", 14, {
      target: true,
      rotation: ROTATION_AFTER,
    }),
    pass("op_token_refresh_exec", "exec", "run", "R2", 15, {
      target: true,
      rotation: ROTATION_AFTER,
    }),
    {
      id: "op_distinct_client_negative",
      tool: "process",
      operation: "poll",
      risk: "R0",
      minute: 16,
      rotation: ROTATION_AFTER,
      principal: DISTINCT_PRINCIPAL,
      result: "fail",
      dispatchState: "NOT_DISPATCHED",
      errorCode: "PROCESS_NOT_FOUND",
      receipt: failureReceipt(
        "op_distinct_client_negative",
        "PROCESS_NOT_FOUND",
        "NOT_DISPATCHED",
      ),
    },
  ];
  const receiptPayloads = Object.fromEntries(
    specifications.map((specification) => [specification.id, specification.receipt]),
  );
  const auditRecords = buildAuditRecords(specifications);
  const evidence: PersonalActualHostEvidence = {
    evidenceSource: "ACTUAL_CHATGPT_INSTALLED_CONNECTOR",
    hostProduct: "ChatGPT",
    connectorName: "myDevSpace-v2-production",
    toolNames: ["target", "context", "fs", "exec", "process", "mcp", "artifact", "gui"],
    run: {
      acceptanceRunId: ACCEPTANCE_RUN_ID,
      productProfile: PRODUCT_PROFILE,
      sourceRevision: SOURCE_REVISION,
      runtimeRevision: RUNTIME_REVISION,
      buildDigest: BUILD_DIGEST,
      schemaGeneration: SCHEMA_GENERATION,
      runtimeStartedAt: RUNTIME_STARTED_AT,
      connectorInstallationEpoch: CONNECTOR_EPOCH,
      connectorRotationSequenceBefore: ROTATION_BEFORE,
      connectorRotationSequenceAfter: ROTATION_AFTER,
      auditSequenceStart: 1,
      auditSequenceEnd: auditRecords.length,
      auditFirstEventDigest: auditRecords[0]!.eventDigest,
      auditLastEventDigest: auditRecords.at(-1)!.eventDigest,
      startedAt: RUN_STARTED_AT,
      endedAt: RUN_ENDED_AT,
      chatGptConversationId: "6a999999-1111-2222-3333-444444444444",
      primaryPrincipalFingerprintPrefix: PRIMARY_PRINCIPAL,
      targetGeneration: TARGET_GENERATION,
      routeGeneration: ROUTE_GENERATION,
    },
    actualMutationEvidenceIds: [
      "op_local_fs_write",
      "op_local_exec",
      "op_process_signal",
      "op_ssh_write",
      "op_downstream_mcp",
      "op_artifact_copy",
      "op_gui_act",
      "op_recovery_prepare",
      "op_recovery_clean",
      "op_new_session_write",
      "op_restart_broker",
      "op_post_restart_write",
      "op_token_refresh_exec",
    ],
    receiptPayloads,
    sections: {
      discovery: section("op_discovery"),
      localFilesystem: section("op_local_fs_write"),
      localCompositeExec: section("op_local_exec"),
      processLifecycle: section("op_process_signal"),
      sshTarget: section("op_ssh_write"),
      downstreamMcp: section("op_downstream_mcp"),
      artifact: section("op_artifact_copy"),
      gui: section("op_gui_act"),
      recoveryRegression: section(
        "op_recovery_prepare",
        "op_recovery_recovered",
        "op_recovery_clean",
      ),
      reconnection: section(
        "op_new_session_write",
        "op_restart_broker",
        "op_post_restart_write",
        "op_token_refresh_exec",
        "op_distinct_client_negative",
      ),
    },
    recoveryFixture: {
      terminalRecords: 1_000,
      runningRecords: 2,
      expiredTerminalRecords: 5,
      corruptTerminalRecords: 1,
      prepareOperationId: "op_recovery_prepare",
      recoveredVerificationOperationId: "op_recovery_recovered",
      cleanVerificationOperationId: "op_recovery_clean",
    },
    reconnection: {
      newChatGptSessionMutationOperationId: "op_new_session_write",
      brokerRestartOperationId: "op_restart_broker",
      postRestartMutationOperationId: "op_post_restart_write",
      tokenRefreshMutationOperationId: "op_token_refresh_exec",
      distinctClientIsolationOperationId: "op_distinct_client_negative",
    },
  };
  return { evidence, auditRecords };
}

test("complete audit-backed actual ChatGPT evidence earns the exact terminal status", () => {
  const value = fixture();
  const result = verifyPersonalActualHostEvidence(value.evidence, value.auditRecords);
  assert.equal(result.status, "PERSONAL_DIRECT_OWNER_E2E_PASS");
  assert.equal(result.verifiedMutationCount, value.evidence.actualMutationEvidenceIds.length);
  assert.deepEqual(result.sections, PERSONAL_ACTUAL_HOST_SECTION_IDS);
});

test("synthetic sources and NOT_RUN sections cannot be promoted", () => {
  const synthetic = fixture();
  synthetic.evidence.evidenceSource = "LOCAL_MCP_SDK";
  assert.throws(
    () => verifyPersonalActualHostEvidence(synthetic.evidence, synthetic.auditRecords),
    /cannot satisfy actual-host acceptance/u,
  );

  const notRun = fixture();
  notRun.evidence.sections.gui = { status: "NOT_RUN", evidenceIds: [] };
  assert.throws(
    () => verifyPersonalActualHostEvidence(notRun.evidence, notRun.auditRecords),
    /gui is not PASS/u,
  );
});

test("fabricated IDs, reused section evidence, and receipt tampering fail closed", () => {
  const fabricated = fixture();
  fabricated.evidence.sections.discovery = section("op_does_not_exist");
  assert.throws(
    () => verifyPersonalActualHostEvidence(fabricated.evidence, fabricated.auditRecords),
    /absent from the verified audit range/u,
  );

  const reused = fixture();
  reused.evidence.sections.gui = section("op_artifact_copy");
  assert.throws(
    () => verifyPersonalActualHostEvidence(reused.evidence, reused.auditRecords),
    /reused across sections/u,
  );

  const tampered = fixture();
  (tampered.evidence.receiptPayloads as Record<string, unknown>).op_local_fs_write = {
    ok: true,
    operationId: "op_local_fs_write",
    data: { changed: "tampered" },
  };
  assert.throws(
    () => verifyPersonalActualHostEvidence(tampered.evidence, tampered.auditRecords),
    /receipt payload digest mismatch/u,
  );
});

test("read-only, failed, and cross-run operations cannot satisfy mutation evidence", () => {
  const readOnly = fixture();
  readOnly.evidence.actualMutationEvidenceIds = [
    "op_discovery",
    ...readOnly.evidence.actualMutationEvidenceIds.slice(1),
  ];
  assert.throws(
    () => verifyPersonalActualHostEvidence(readOnly.evidence, readOnly.auditRecords),
    /not an acknowledged PASS mutation/u,
  );

  const failed = fixture();
  const failedRecords = failed.auditRecords.map((record) => ({ ...record }));
  const failedRecord = failedRecords.find((record) => record.operationId === "op_local_fs_write")!;
  failedRecord.result = "fail";
  failedRecord.dispatchState = "NOT_DISPATCHED";
  failedRecord.errorCode = "PERMISSION_DENIED";
  bindRechainedAudit(failed, failedRecords);
  assert.throws(
    () => verifyPersonalActualHostEvidence(failed.evidence, failed.auditRecords),
    /localFilesystem has no successful operation|not an acknowledged PASS mutation/u,
  );

  const crossRun = fixture();
  const crossRunRecords = crossRun.auditRecords.map((record) => ({ ...record }));
  crossRunRecords.find((record) => record.operationId === "op_local_exec")!.sourceRevision =
    "different-source-revision";
  bindRechainedAudit(crossRun, crossRunRecords);
  assert.throws(
    () => verifyPersonalActualHostEvidence(crossRun.evidence, crossRun.auditRecords),
    /crosses run identity field sourceRevision/u,
  );
});

test("audit chain tampering is rejected before section claims are evaluated", () => {
  const tampered = fixture();
  tampered.auditRecords[5]!.result = "fail";
  assert.throws(
    () => verifyPersonalActualHostEvidence(tampered.evidence, tampered.auditRecords),
    /audit event digest is invalid/u,
  );
});

test("recovery, token rotation, and distinct-client claims are semantically checked", () => {
  const recovery = fixture();
  recovery.evidence.recoveryFixture.terminalRecords = 1_001;
  assert.throws(
    () => verifyPersonalActualHostEvidence(recovery.evidence, recovery.auditRecords),
    /validRecordCount is below 1008|retainedTerminalCount is below 1001/u,
  );

  const rotation = fixture();
  rotation.evidence.run.connectorRotationSequenceAfter = ROTATION_BEFORE;
  assert.throws(
    () => verifyPersonalActualHostEvidence(rotation.evidence, rotation.auditRecords),
    /rotation sequence did not advance/u,
  );

  const distinct = fixture();
  const distinctRecords = distinct.auditRecords.map((record) => ({ ...record }));
  distinctRecords.find((record) => record.operationId === "op_distinct_client_negative")!
    .principalFingerprintPrefix = PRIMARY_PRINCIPAL;
  bindRechainedAudit(distinct, distinctRecords);
  assert.throws(
    () => verifyPersonalActualHostEvidence(distinct.evidence, distinct.auditRecords),
    /Distinct-client isolation evidence/u,
  );
});

function pass(
  id: string,
  tool: string,
  operation: string,
  risk: "R0" | "R1" | "R2" | "R3",
  minute: number,
  options: {
    receipt?: unknown;
    rotation?: number;
    target?: boolean;
    route?: boolean;
  } = {},
): AuditSpecification {
  return {
    id,
    tool,
    operation,
    risk,
    minute,
    rotation: options.rotation,
    target: options.target,
    route: options.route,
    receipt: options.receipt ?? successReceipt(id, { state: "PASS" }),
  };
}

function buildAuditRecords(
  specifications: readonly AuditSpecification[],
): StoredOperationAuditEvent[] {
  let previousEventDigest: string | undefined;
  return specifications.map((specification, index) => {
    const unsigned = {
      schemaVersion: 1 as const,
      sequence: index + 1,
      ...(previousEventDigest ? { previousEventDigest } : {}),
      timestamp: new Date(Date.parse(RUN_STARTED_AT) + specification.minute * 60_000).toISOString(),
      operationId: specification.id,
      correlationId: `correlation-${specification.id}`,
      principalFingerprintPrefix: specification.principal ?? PRIMARY_PRINCIPAL,
      productProfile: PRODUCT_PROFILE,
      sourceRevision: SOURCE_REVISION,
      runtimeRevision: RUNTIME_REVISION,
      buildDigest: BUILD_DIGEST,
      schemaGeneration: SCHEMA_GENERATION,
      runtimeStartedAt: RUNTIME_STARTED_AT,
      connectorInstallationEpoch: CONNECTOR_EPOCH,
      connectorRotationSequence: specification.rotation ?? ROTATION_BEFORE,
      acceptanceRunId: ACCEPTANCE_RUN_ID,
      ...(specification.target ? { targetGeneration: TARGET_GENERATION } : {}),
      ...(specification.route ? { routeGeneration: ROUTE_GENERATION } : {}),
      actionDigest: digestOperationAuditPayload({
        tool: specification.tool,
        operation: specification.operation,
        arguments: { fixture: specification.id },
      }),
      tool: specification.tool,
      operation: specification.operation,
      risk: specification.risk,
      dispatchState: specification.dispatchState ?? "ACKNOWLEDGED",
      result: specification.result ?? "pass",
      ...(specification.errorCode ? { errorCode: specification.errorCode } : {}),
      receiptDigest: digestOperationAuditPayload(specification.receipt),
    };
    const eventDigest = digestOperationAuditPayload(unsigned);
    previousEventDigest = eventDigest;
    return { ...unsigned, eventDigest };
  });
}

function bindRechainedAudit(fixtureValue: Fixture, records: StoredOperationAuditEvent[]): void {
  fixtureValue.auditRecords = rechain(records);
  fixtureValue.evidence.run.auditSequenceEnd = fixtureValue.auditRecords.length;
  fixtureValue.evidence.run.auditFirstEventDigest = fixtureValue.auditRecords[0]!.eventDigest;
  fixtureValue.evidence.run.auditLastEventDigest = fixtureValue.auditRecords.at(-1)!.eventDigest;
}

function rechain(records: readonly StoredOperationAuditEvent[]): StoredOperationAuditEvent[] {
  let previousEventDigest: string | undefined;
  return records.map((record, index) => {
    const {
      eventDigest: _eventDigest,
      previousEventDigest: _previousEventDigest,
      ...base
    } = record;
    const unsigned = {
      ...base,
      sequence: index + 1,
      ...(previousEventDigest ? { previousEventDigest } : {}),
    };
    const eventDigest = digestOperationAuditPayload(unsigned);
    previousEventDigest = eventDigest;
    return { ...unsigned, eventDigest };
  });
}

function successReceipt(operationId: string, data: Record<string, unknown>): unknown {
  return { ok: true, operationId, data };
}

function failureReceipt(operationId: string, code: string, dispatchState: string): unknown {
  return {
    ok: false,
    operationId,
    error: { code, dispatchState, retryable: false },
  };
}

function section(...evidenceIds: string[]): { status: "PASS"; evidenceIds: string[] } {
  return { status: "PASS", evidenceIds };
}
