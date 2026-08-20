import assert from "node:assert/strict";
import test from "node:test";
import { UniversalBrokerMetrics } from "./metrics.js";

test("metrics render bounded counters, duration summaries, and gauges", () => {
  const metrics = new UniversalBrokerMetrics();
  metrics.increment("devspace_http_requests_total", "HTTP requests", 2);
  metrics.increment("devspace_requests_total", "Requests", 1, {
    tool: "fs",
    operation: "read",
    result: "pass",
    error_code: "none",
  });
  metrics.observeMilliseconds("devspace_request_duration_seconds", "Duration", 250, {
    tool: "fs",
    operation: "read",
    result: "pass",
  });
  metrics.recordMcpReconnect("local-stdio", "pass");
  metrics.recordMcpConnection("local-stdio", "connected");
  const text = metrics.render({
    devspace_open_http_sessions: { help: "Open sessions", value: 3 },
  });
  assert.match(text, /devspace_http_requests_total 2/);
  assert.match(text, /devspace_requests_total\{error_code="none",operation="read",result="pass",tool="fs"\} 1/);
  assert.match(text, /devspace_request_duration_seconds_count\{operation="read",result="pass",tool="fs"\} 1/);
  assert.match(text, /devspace_request_duration_seconds_sum\{operation="read",result="pass",tool="fs"\} 0.25/);
  assert.match(text, /devspace_open_http_sessions 3/);
  assert.match(text, /devspace_mcp_reconnects_total\{result="pass",transport="local-stdio"\} 1/);
  assert.match(text, /devspace_mcp_connections\{state="connected",transport="local-stdio"\} 1/);
  assert.match(text, /devspace_mcp_connections\{state="disconnected",transport="local-stdio"\} 0/);

  metrics.recordMcpConnection("local-stdio", "disconnected");
  const disconnected = metrics.render({});
  assert.match(disconnected, /devspace_mcp_connections\{state="connected",transport="local-stdio"\} 0/);
  assert.match(disconnected, /devspace_mcp_connections\{state="disconnected",transport="local-stdio"\} 1/);
});

test("metrics reject unregistered families and high-cardinality identity labels", () => {
  const metrics = new UniversalBrokerMetrics();
  assert.throws(
    () => metrics.increment("devspace_ad_hoc_total", "Ad hoc"),
    /not registered/u,
  );
  assert.throws(
    () => metrics.recordMcpReconnect("customer-specific-route-id", "pass"),
    /unsupported MCP transport metric label/iu,
  );
  assert.throws(
    () => metrics.increment("devspace_mcp_reconnects_total", "Reconnects", 1, {
      transport: "customer-specific-route-id",
      result: "pass",
    }),
    /unsupported MCP transport metric label/iu,
  );
  for (const label of [
    "principal",
    "principal_fingerprint",
    "task_id",
    "authority_id",
    "resource_digest",
    "resource",
    "path",
    "command",
    "url",
    "route",
    "request_id",
    "transaction_id",
  ]) {
    assert.throws(
      () => metrics.increment("devspace_requests_total", "Requests", 1, { [label]: "secret-or-unique" }),
      /forbidden|does not allow/u,
    );
  }
});

test("metric family policy rejects labels outside each family's finite dimension set", () => {
  const metrics = new UniversalBrokerMetrics();
  assert.throws(
    () => metrics.increment("devspace_http_requests_total", "HTTP", 1, { method: "GET" }),
    /does not allow label/u,
  );
  assert.throws(
    () => metrics.observeMilliseconds(
      "devspace_request_duration_seconds",
      "Duration",
      1,
      { tool: "fs", operation: "read" },
    ),
    /requires labels/u,
  );
  assert.throws(
    () => metrics.observeMilliseconds(
      "devspace_request_duration_seconds",
      "Duration",
      1,
      { tool: "fs", operation: "read", result: "pass", error_code: "none" },
    ),
    /does not allow label/u,
  );
});

test("Rev3 core metric producers emit bounded low-cardinality families", () => {
  const metrics = new UniversalBrokerMetrics();
  metrics.recordToolRequest("fs", "write", "fail", 10, "PRECONDITION_FAILED");
  metrics.recordAuthorityCheck("R1", "pass");
  metrics.recordAuthorityClaim("R1", "CLAIMED");
  metrics.recordAuthorityStoreFailure("claim");
  metrics.recordResourceLeaseEvent("acquired");
  metrics.recordCursorEvent("process", "issued");
  metrics.recordQuotaRejection("authority_receipt");
  metrics.recordQuotaRejection("worktree");
  metrics.recordQuotaRejection("mcp_result");
  metrics.recordMcpReconnect("ssh-stdio", "fail");
  metrics.recordDispatchUnknown("ssh");
  metrics.recordRestartTransaction("ack_flushed");
  metrics.recordConnectorTransition("PREPARED", "ACTIVE", "pass");
  metrics.recordArtifactEvent("published", "pass");
  metrics.recordRateLimitRejection("post_auth");
  metrics.recordAuditResult("recorded");

  const text = metrics.render({});
  for (const family of [
    "devspace_requests_total",
    "devspace_request_duration_seconds",
    "devspace_authority_checks_total",
    "devspace_authority_claims_total",
    "devspace_authority_store_failures_total",
    "devspace_resource_lease_events_total",
    "devspace_cursor_events_total",
    "devspace_quota_rejections_total",
    "devspace_mcp_reconnects_total",
    "devspace_restart_transactions_total",
    "devspace_connector_transitions_total",
    "devspace_artifact_events_total",
    "devspace_rate_limit_rejections_total",
    "devspace_operation_audit_events_total",
    "devspace_dispatch_unknown_total",
  ]) {
    assert.match(text, new RegExp(`# HELP ${family}\\b`, "u"), family);
  }
  assert.match(
    text,
    /devspace_requests_total\{error_code="PRECONDITION_FAILED",operation="write",result="fail",tool="fs"\} 1/u,
  );
  assert.match(text, /devspace_quota_rejections_total\{resource_kind="worktree"\} 1/u);
  assert.match(text, /devspace_quota_rejections_total\{resource_kind="mcp_result"\} 1/u);
  assert.match(text, /devspace_dispatch_unknown_total\{transport="ssh"\} 1/u);
  metrics.increment("devspace_doctor_checks_total", "Doctor checks", 1, {
    check: "authority_claim_receipt",
    result: "pass",
  });
  metrics.observeMilliseconds("devspace_doctor_duration_seconds", "Doctor duration", 5, {
    result: "PASS",
  });
  const doctorText = metrics.render({});
  assert.match(
    doctorText,
    /devspace_doctor_checks_total\{check="authority_claim_receipt",result="pass"\} 1/u,
  );
  assert.match(doctorText, /devspace_doctor_duration_seconds_count\{result="PASS"\} 1/u);
  assert.throws(
    () => metrics.recordDispatchUnknown("customer-route-id"),
    /unsupported unknown-dispatch transport metric label/iu,
  );
});

test("metric series quotas reject high-cardinality values even on allowed labels", () => {
  const metrics = new UniversalBrokerMetrics();
  for (let index = 0; index < 16; index += 1) {
    metrics.increment(
      "devspace_authority_checks_total",
      "Authority checks",
      1,
      { risk: `risk_${index}`, result: "pass" },
    );
  }
  assert.throws(
    () => metrics.increment(
      "devspace_authority_checks_total",
      "Authority checks",
      1,
      { risk: "risk_16", result: "pass" },
    ),
    /series quota exceeded/u,
  );
});
