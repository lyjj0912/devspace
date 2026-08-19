const METRIC_NAME = /^[a-zA-Z_:][a-zA-Z0-9_:]*$/;

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
  ): void {
    const labels = { tool: boundedLabel(tool), operation: boundedLabel(operation) };
    this.increment(
      "devspace_requests_total",
      "Universal Broker requests",
      1,
      { ...labels, result },
    );
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
      { transport: boundedLabel(transport) },
    );
  }

  recordMcpReconnect(route: string, result: "pass" | "fail"): void {
    this.increment(
      "devspace_mcp_reconnect_total",
      "Downstream MCP reconnect attempts",
      1,
      { route: boundedLabel(route), result },
    );
  }

  recordMcpConnection(
    route: string,
    state: "connected" | "disconnected",
  ): void {
    const boundedRoute = boundedLabel(route);
    if (!this.mcpConnectionCounts.has(boundedRoute) && this.mcpConnectionCounts.size >= 256) {
      throw new Error("MCP connection route metric quota exceeded.");
    }
    const current = this.mcpConnectionCounts.get(boundedRoute) ?? 0;
    this.mcpConnectionCounts.set(
      boundedRoute,
      state === "connected" ? current + 1 : Math.max(0, current - 1),
    );
  }

  increment(
    name: string,
    help: string,
    amount = 1,
    labels: Record<string, string> = {},
  ): void {
    validateMetricName(name);
    const normalizedLabels = normalizeLabels(labels);
    const key = seriesKey(name, normalizedLabels);
    this.assertSeriesCapacity(this.counters, name, key);
    const current = this.counters.get(key) ?? {
      name,
      help,
      labels: normalizedLabels,
      value: 0,
    };
    current.value += amount;
    this.counters.set(key, current);
  }

  observeMilliseconds(
    name: string,
    help: string,
    milliseconds: number,
    labels: Record<string, string> = {},
  ): void {
    validateMetricName(name);
    const normalizedLabels = normalizeLabels(labels);
    const key = seriesKey(name, normalizedLabels);
    this.assertSeriesCapacity(this.durations, name, key);
    const current = this.durations.get(key) ?? {
      name,
      help,
      labels: normalizedLabels,
      count: 0,
      sumSeconds: 0,
    };
    current.count += 1;
    current.sumSeconds += Math.max(0, milliseconds) / 1_000;
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
      for (const [route, connected] of [...this.mcpConnectionCounts]
        .sort(([left], [right]) => left.localeCompare(right))) {
        lines.push(`devspace_mcp_connections${renderLabels({ route, state: "connected" })} ${connected}`);
        lines.push(`devspace_mcp_connections${renderLabels({ route, state: "disconnected" })} ${connected === 0 ? 1 : 0}`);
      }
    }
    for (const [name, record] of Object.entries(gauges).sort(([left], [right]) => left.localeCompare(right))) {
      validateMetricName(name);
      lines.push(`# HELP ${name} ${escapeHelp(record.help)}`);
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
    const count = [...records.keys()].filter((candidate) => candidate.startsWith(`${name}\0`)).length;
    if (count >= 256) throw new Error(`Metric series quota exceeded: ${name}`);
  }
}

function validateMetricName(name: string): void {
  if (!METRIC_NAME.test(name)) throw new Error(`Invalid metric name: ${name}`);
}

function escapeHelp(value: string): string {
  return value.replaceAll("\\", "\\\\").replaceAll("\n", "\\n");
}

function number(value: number): string {
  return Number.isFinite(value) ? String(value) : "0";
}

function normalizeLabels(labels: Record<string, string>): Record<string, string> {
  if (Object.keys(labels).length > 8) throw new Error("Metrics accept at most eight labels.");
  return Object.fromEntries(Object.entries(labels)
    .sort(([left], [right]) => left.localeCompare(right))
    .map(([key, value]) => {
      if (!/^[a-zA-Z_][a-zA-Z0-9_]*$/u.test(key)) throw new Error(`Invalid metric label: ${key}`);
      const normalized = String(value);
      if (normalized.length > 128 || /[\r\n\0]/u.test(normalized)) {
        throw new Error(`Invalid metric label value: ${key}`);
      }
      return [key, normalized];
    }));
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
  if (!normalized || normalized.length > 128 || /[\r\n\0]/u.test(normalized)) {
    throw new Error("Invalid bounded metric label.");
  }
  return normalized;
}
