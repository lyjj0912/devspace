type MetricKind = "counter" | "duration" | "gauge";

export interface MetricFamilyPolicy {
  kind: MetricKind;
  labels: readonly string[];
  maximumSeries: number;
}

const METRIC_FAMILIES = Object.freeze<Record<string, MetricFamilyPolicy>>({
  devspace_requests_total: family("counter", ["tool", "operation", "result", "error_code"], 512),
  devspace_request_duration_seconds: family("duration", ["tool", "operation", "result"], 256),
  devspace_dispatch_unknown_total: family("counter", ["transport"], 16),
  devspace_authority_checks_total: family("counter", ["risk", "result"], 16),
  devspace_authority_claims_total: family("counter", ["risk", "state"], 32),
  devspace_authority_store_failures_total: family("counter", ["operation"], 32),
  devspace_resource_lease_events_total: family("counter", ["event"], 16),
  devspace_cursor_events_total: family("counter", ["resource_kind", "result"], 32),
  devspace_quota_rejections_total: family("counter", ["resource_kind"], 16),
  devspace_mcp_reconnects_total: family("counter", ["transport", "result"], 32),
  devspace_mcp_connections: family("gauge", ["transport", "state"], 32),
  devspace_http_requests_total: family("counter", [], 1),
  devspace_http_request_duration_seconds: family("duration", [], 1),
  devspace_mcp_session_close_failures_total: family("counter", [], 1),
  devspace_mcp_sessions_closed_total: family("counter", [], 1),
  devspace_mcp_sessions_created_total: family("counter", [], 1),
  devspace_mcp_request_errors_total: family("counter", [], 1),
  devspace_restart_transactions_total: family("counter", ["result"], 8),
  devspace_connector_transitions_total: family("counter", ["from", "to", "result"], 64),
  devspace_artifact_events_total: family("counter", ["event", "result"], 32),
  devspace_rate_limit_rejections_total: family("counter", ["stage"], 3),
  devspace_operation_audit_events_total: family("counter", ["result"], 4),
  devspace_readiness_checks_total: family("counter", ["check", "result"], 128),
  devspace_readiness_duration_seconds: family("duration", ["result"], 4),
  devspace_doctor_checks_total: family("counter", ["check", "result"], 128),
  devspace_doctor_duration_seconds: family("duration", ["result"], 4),
  devspace_open_http_sessions: family("gauge", [], 1),
  devspace_pending_mcp_initializations: family("gauge", [], 1),
  devspace_contexts: family("gauge", [], 1),
  devspace_managed_worktrees: family("gauge", [], 1),
  devspace_running_processes: family("gauge", [], 1),
  devspace_process_output_bytes: family("gauge", [], 1),
  devspace_downstream_mcp_sessions: family("gauge", [], 1),
  devspace_downstream_mcp_active_calls: family("gauge", [], 1),
  devspace_artifacts: family("gauge", [], 1),
  devspace_artifact_bytes: family("gauge", [], 1),
  devspace_gui_sessions: family("gauge", [], 1),
  devspace_operation_authorities: family("gauge", [], 1),
  devspace_authority_previews: family("gauge", [], 1),
  devspace_target_probe_cache_entries: family("gauge", [], 1),
  devspace_target_probe_in_flight: family("gauge", [], 1),
  devspace_target_probe_cache_hits: family("gauge", [], 1),
  devspace_target_probe_cache_misses: family("gauge", [], 1),
  devspace_target_probe_coalesced: family("gauge", [], 1),
  devspace_target_probe_online: family("gauge", [], 1),
  devspace_target_probe_degraded: family("gauge", [], 1),
  devspace_target_probe_offline: family("gauge", [], 1),
  devspace_target_probe_average_duration_ms: family("gauge", [], 1),
  devspace_target_probe_last_duration_ms: family("gauge", [], 1),
  devspace_restart_transactions: family("gauge", [], 1),
  devspace_active_restart_transactions: family("gauge", [], 1),
  devspace_rate_limit_buckets: family("gauge", [], 1),
  devspace_operation_audit_pending: family("gauge", [], 1),
});

const FORBIDDEN_LABEL = /^(?:principal(?:_fingerprint)?|task(?:_id)?|authority(?:_id)?|resource|resource_(?:digest|key)|path|command|url|uri|route(?:_id)?|request_id|transaction_id|session_id)$/iu;
const MCP_TRANSPORT_LABELS = new Set(["local-stdio", "ssh-stdio", "streamable-http"]);
const UNKNOWN_DISPATCH_TRANSPORTS = new Set([
  "target",
  "context",
  "fs",
  "exec",
  "process",
  "mcp",
  "artifact",
  "gui",
  "local",
  "ssh",
  "local-stdio",
  "ssh-stdio",
  "streamable-http",
]);
const AUTHORITY_RISKS = new Set(["R1", "R2", "R3"]);
const METRIC_RESULTS = new Set(["pass", "fail", "unknown"]);
const AUDIT_RESULTS = new Set(["recorded", "sink_failed"]);
const AUTHORITY_CLAIM_STATES = new Set([
  "CLAIMED",
  "DISPATCHED",
  "PASS",
  "FAIL",
  "UNCERTAIN",
  "CANCELLED_NOT_DISPATCHED",
]);
const AUTHORITY_STORE_OPERATIONS = new Set([
  "create",
  "task",
  "claim",
  "dispatch",
  "heartbeat",
  "cancel",
  "complete",
  "reconcile",
  "invalidate",
  "release",
  "status",
  "delete",
]);
const RESOURCE_LEASE_EVENTS = new Set([
  "acquired",
  "dispatched",
  "heartbeat",
  "released",
  "recovery_required",
  "reconciled",
  "busy",
]);
const CURSOR_RESOURCE_KINDS = new Set([
  "target",
  "target.list",
  "context",
  "context.search",
  "process",
  "process.list",
  "filesystem.list",
  "filesystem.search",
  "mcp.routes",
  "mcp.search_tools",
  "mcp.list_resources",
  "mcp.list_prompts",
  "mcp_result",
  "artifact",
  "audit",
]);
const CURSOR_RESULTS = new Set(["issued", "accepted", "rejected", "expired", "stale"]);
const QUOTA_RESOURCE_KINDS = new Set([
  "authority",
  "authority_receipt",
  "cursor",
  "context",
  "worktree",
  "process",
  "mcp_session",
  "mcp_result",
  "artifact",
  "rate_limit",
]);
const RESTART_RESULTS = new Set(["requested", "ack_flushed", "pass", "fail", "unknown"]);
const CONNECTOR_STATES = new Set([
  "NONE",
  "REGISTERED",
  "CANDIDATE",
  "VERIFIED",
  "PREPARED",
  "ACTIVATION_PREPARED",
  "ACTIVE",
  "DRAINING",
  "RETIRED",
  "REJECTED",
  "FAILED",
]);
const ARTIFACT_EVENTS = new Set([
  "reserved",
  "published",
  "read",
  "cleanup_planned",
  "cleanup_completed",
  "cleanup_failed",
]);

interface CounterRecord {
  name: string;
  help: string;
  labels: Record<string, string>;
  value: number;
}

interface DurationRecord {
  name: string;
  help: string;
  labels: Record<string, string>;
  count: number;
  sumSeconds: number;
}

export class UniversalBrokerMetrics {
  private readonly counters = new Map<string, CounterRecord>();
  private readonly durations = new Map<string, DurationRecord>();
  private readonly mcpConnectionCounts = new Map<string, number>();

  recordToolRequest(
    tool: string,
    operation: string,
    result: "pass" | "fail" | "unknown",
    durationMs: number,
    errorCode = "none",
  ): void {
    const labels = {
      tool: boundedLabel(tool),
      operation: boundedLabel(operation),
      result: knownLabel(result, METRIC_RESULTS, "request result"),
    };
    this.increment("devspace_requests_total", "Universal Broker requests", 1, {
      ...labels,
      error_code: safeMetricCode(errorCode),
    });
    this.observeMilliseconds(
      "devspace_request_duration_seconds",
      "Universal Broker request duration",
      durationMs,
      labels,
    );
  }

  recordDispatchUnknown(transport: string): void {
    this.increment(
      "devspace_dispatch_unknown_total",
      "Dispatches with unknown result",
      1,
      { transport: knownLabel(transport, UNKNOWN_DISPATCH_TRANSPORTS, "unknown-dispatch transport") },
    );
  }

  recordMcpReconnect(transport: string, result: "pass" | "fail"): void {
    this.increment(
      "devspace_mcp_reconnects_total",
      "Downstream MCP reconnect attempts",
      1,
      { transport: boundedMcpTransport(transport), result },
    );
  }

  recordMcpConnection(transport: string, state: "connected" | "disconnected"): void {
    const boundedTransport = boundedMcpTransport(transport);
    validateFamily("devspace_mcp_connections", "gauge", { transport: boundedTransport, state });
    if (!this.mcpConnectionCounts.has(boundedTransport) && this.mcpConnectionCounts.size >= 16) {
      throw new Error("MCP connection transport metric quota exceeded.");
    }
    const current = this.mcpConnectionCounts.get(boundedTransport) ?? 0;
    this.mcpConnectionCounts.set(
      boundedTransport,
      state === "connected" ? current + 1 : Math.max(0, current - 1),
    );
  }

  recordRateLimitRejection(stage: "pre_auth" | "post_auth" | "initialize"): void {
    this.increment(
      "devspace_rate_limit_rejections_total",
      "Requests rejected by broker rate limiting",
      1,
      { stage },
    );
  }

  recordAuditResult(result: "recorded" | "sink_failed"): void {
    knownLabel(result, AUDIT_RESULTS, "operation audit result");
    this.increment(
      "devspace_operation_audit_events_total",
      "Structured operation audit outcomes",
      1,
      { result },
    );
  }

  recordAuthorityCheck(risk: string, result: "pass" | "fail"): void {
    this.increment(
      "devspace_authority_checks_total",
      "Operation authority check outcomes",
      1,
      {
        risk: knownLabel(risk, AUTHORITY_RISKS, "authority risk"),
        result,
      },
    );
  }

  recordAuthorityClaim(risk: string, state: string): void {
    this.increment(
      "devspace_authority_claims_total",
      "Durable operation authority claim states",
      1,
      {
        risk: knownLabel(risk, AUTHORITY_RISKS, "authority risk"),
        state: knownLabel(state, AUTHORITY_CLAIM_STATES, "authority claim state"),
      },
    );
  }

  recordAuthorityStoreFailure(operation: string): void {
    this.increment(
      "devspace_authority_store_failures_total",
      "Durable authority store failures",
      1,
      { operation: knownLabel(operation, AUTHORITY_STORE_OPERATIONS, "authority store operation") },
    );
  }

  recordResourceLeaseEvent(event: string): void {
    this.increment(
      "devspace_resource_lease_events_total",
      "Resource lease lifecycle events",
      1,
      { event: knownLabel(event, RESOURCE_LEASE_EVENTS, "resource lease event") },
    );
  }

  recordCursorEvent(resourceKind: string, result: string): void {
    this.increment(
      "devspace_cursor_events_total",
      "Cursor lifecycle events",
      1,
      {
        resource_kind: knownLabel(resourceKind, CURSOR_RESOURCE_KINDS, "cursor resource kind"),
        result: knownLabel(result, CURSOR_RESULTS, "cursor result"),
      },
    );
  }

  recordQuotaRejection(resourceKind: string): void {
    this.increment(
      "devspace_quota_rejections_total",
      "Broker quota rejections",
      1,
      { resource_kind: knownLabel(resourceKind, QUOTA_RESOURCE_KINDS, "quota resource kind") },
    );
  }

  recordRestartTransaction(result: string): void {
    this.increment(
      "devspace_restart_transactions_total",
      "Broker restart transaction outcomes",
      1,
      { result: knownLabel(result, RESTART_RESULTS, "restart result") },
    );
  }

  recordConnectorTransition(from: string, to: string, result: "pass" | "fail"): void {
    this.increment(
      "devspace_connector_transitions_total",
      "Connector lifecycle transitions",
      1,
      {
        from: knownLabel(from, CONNECTOR_STATES, "connector source state"),
        to: knownLabel(to, CONNECTOR_STATES, "connector target state"),
        result,
      },
    );
  }

  recordArtifactEvent(event: string, result: "pass" | "fail"): void {
    this.increment(
      "devspace_artifact_events_total",
      "Artifact catalog events",
      1,
      {
        event: knownLabel(event, ARTIFACT_EVENTS, "artifact event"),
        result,
      },
    );
  }

  increment(
    name: string,
    help: string,
    amount = 1,
    labels: Record<string, string> = {},
  ): void {
    if (!Number.isFinite(amount) || amount < 0) throw new Error("Metric counter amount is invalid.");
    const normalizedLabels = validateFamily(name, "counter", labels);
    const key = seriesKey(name, normalizedLabels);
    this.assertSeriesCapacity(this.counters, name, key);
    const current = this.counters.get(key) ?? {
      name,
      help: boundedHelp(help),
      labels: normalizedLabels,
      value: 0,
    };
    if (current.help !== boundedHelp(help)) throw new Error(`Metric help changed for ${name}.`);
    current.value += amount;
    this.counters.set(key, current);
  }

  observeMilliseconds(
    name: string,
    help: string,
    milliseconds: number,
    labels: Record<string, string> = {},
  ): void {
    if (!Number.isFinite(milliseconds) || milliseconds < 0) {
      throw new Error("Metric duration is invalid.");
    }
    const normalizedLabels = validateFamily(name, "duration", labels);
    const key = seriesKey(name, normalizedLabels);
    this.assertSeriesCapacity(this.durations, name, key);
    const current = this.durations.get(key) ?? {
      name,
      help: boundedHelp(help),
      labels: normalizedLabels,
      count: 0,
      sumSeconds: 0,
    };
    if (current.help !== boundedHelp(help)) throw new Error(`Metric help changed for ${name}.`);
    current.count += 1;
    current.sumSeconds += milliseconds / 1_000;
    this.durations.set(key, current);
  }

  render(gauges: Record<string, { help: string; value: number }>): string {
    const lines: string[] = [];
    const emittedCounters = new Set<string>();
    for (const [, record] of [...this.counters].sort(([left], [right]) => left.localeCompare(right))) {
      if (!emittedCounters.has(record.name)) {
        lines.push(`# HELP ${record.name} ${escapeHelp(record.help)}`);
        lines.push(`# TYPE ${record.name} counter`);
        emittedCounters.add(record.name);
      }
      lines.push(`${record.name}${renderLabels(record.labels)} ${number(record.value)}`);
    }
    const emittedDurations = new Set<string>();
    for (const [, record] of [...this.durations].sort(([left], [right]) => left.localeCompare(right))) {
      if (!emittedDurations.has(record.name)) {
        lines.push(`# HELP ${record.name} ${escapeHelp(record.help)}`);
        lines.push(`# TYPE ${record.name} summary`);
        emittedDurations.add(record.name);
      }
      const labels = renderLabels(record.labels);
      lines.push(`${record.name}_count${labels} ${number(record.count)}`);
      lines.push(`${record.name}_sum${labels} ${number(record.sumSeconds)}`);
    }
    if (this.mcpConnectionCounts.size > 0) {
      lines.push("# HELP devspace_mcp_connections Current downstream MCP connection state");
      lines.push("# TYPE devspace_mcp_connections gauge");
      for (const [transport, connected] of [...this.mcpConnectionCounts]
        .sort(([left], [right]) => left.localeCompare(right))) {
        lines.push(`devspace_mcp_connections${renderLabels({ state: "connected", transport })} ${connected}`);
        lines.push(`devspace_mcp_connections${renderLabels({ state: "disconnected", transport })} ${connected === 0 ? 1 : 0}`);
      }
    }
    for (const [name, record] of Object.entries(gauges).sort(([left], [right]) => left.localeCompare(right))) {
      validateFamily(name, "gauge", {});
      if (!Number.isFinite(record.value)) throw new Error(`Metric gauge value is invalid: ${name}`);
      lines.push(`# HELP ${name} ${escapeHelp(boundedHelp(record.help))}`);
      lines.push(`# TYPE ${name} gauge`);
      lines.push(`${name} ${number(record.value)}`);
    }
    return `${lines.join("\n")}\n`;
  }

  private assertSeriesCapacity(
    records: Map<string, unknown>,
    name: string,
    key: string,
  ): void {
    if (records.has(key)) return;
    const policy = METRIC_FAMILIES[name]!;
    const count = [...records.keys()].filter((candidate) => candidate.startsWith(`${name}\0`)).length;
    if (count >= policy.maximumSeries) throw new Error(`Metric series quota exceeded: ${name}`);
  }
}

export function metricFamilyPolicy(): Readonly<Record<string, MetricFamilyPolicy>> {
  return METRIC_FAMILIES;
}

function family(kind: MetricKind, labels: readonly string[], maximumSeries: number): MetricFamilyPolicy {
  return Object.freeze({ kind, labels: Object.freeze([...labels]), maximumSeries });
}

function validateFamily(
  name: string,
  kind: MetricKind,
  labels: Record<string, string>,
): Record<string, string> {
  const policy = METRIC_FAMILIES[name];
  if (!policy) throw new Error(`Metric family is not registered: ${name}`);
  if (policy.kind !== kind) throw new Error(`Metric family ${name} is ${policy.kind}, not ${kind}.`);
  const normalized = Object.fromEntries(Object.entries(labels)
    .sort(([left], [right]) => left.localeCompare(right))
    .map(([key, value]) => {
      if (FORBIDDEN_LABEL.test(key)) throw new Error(`Metric label is forbidden: ${key}`);
      if (!policy.labels.includes(key)) throw new Error(`Metric family ${name} does not allow label ${key}.`);
      const normalizedValue = key === "transport"
        && ["devspace_mcp_reconnects_total", "devspace_mcp_connections"].includes(name)
        ? boundedMcpTransport(String(value))
        : boundedLabel(String(value));
      return [key, normalizedValue];
    }));
  if (Object.keys(normalized).length > policy.labels.length) {
    throw new Error(`Metric family ${name} has too many labels.`);
  }
  const missing = policy.labels.filter((label) => !(label in normalized));
  if (missing.length > 0) {
    throw new Error(`Metric family ${name} requires labels: ${missing.join(", ")}.`);
  }
  return normalized;
}

function escapeHelp(value: string): string {
  return value.replaceAll("\\", "\\\\").replaceAll("\n", "\\n");
}

function boundedHelp(value: string): string {
  const normalized = value.trim();
  if (!normalized || normalized.length > 256 || /[\r\0]/u.test(normalized)) {
    throw new Error("Metric help is missing or invalid.");
  }
  return normalized;
}

function number(value: number): string {
  return Number.isFinite(value) ? String(value) : "0";
}

function seriesKey(name: string, labels: Record<string, string>): string {
  return `${name}\0${JSON.stringify(labels)}`;
}

function renderLabels(labels: Record<string, string>): string {
  const entries = Object.entries(labels);
  if (entries.length === 0) return "";
  return `{${entries.map(([key, value]) => `${key}="${value
    .replaceAll("\\", "\\\\")
    .replaceAll("\n", "\\n")
    .replaceAll('"', '\\"')}"`).join(",")}}`;
}

function boundedLabel(value: string): string {
  const normalized = value.trim();
  if (!normalized || normalized.length > 64 || /[\r\n\0]/u.test(normalized)) {
    throw new Error("Invalid bounded metric label.");
  }
  return normalized;
}

function boundedMcpTransport(value: string): string {
  const normalized = boundedLabel(value);
  if (!MCP_TRANSPORT_LABELS.has(normalized)) {
    throw new Error(`Unsupported MCP transport metric label: ${normalized}`);
  }
  return normalized;
}

function knownLabel(value: string, allowed: ReadonlySet<string>, field: string): string {
  const normalized = boundedLabel(value);
  if (!allowed.has(normalized)) throw new Error(`Unsupported ${field} metric label: ${normalized}`);
  return normalized;
}

function safeMetricCode(value: string): string {
  const normalized = boundedLabel(value);
  if (!/^[A-Za-z][A-Za-z0-9_:-]{0,63}$|^none$/u.test(normalized)) {
    throw new Error(`Unsupported error_code metric label: ${normalized}`);
  }
  return normalized;
}
