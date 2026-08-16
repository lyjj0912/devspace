const METRIC_NAME = /^[a-zA-Z_:][a-zA-Z0-9_:]*$/;

interface CounterRecord {
  help: string;
  value: number;
}

interface DurationRecord {
  help: string;
  count: number;
  sumSeconds: number;
}

export class UniversalBrokerMetrics {
  private readonly counters = new Map<string, CounterRecord>();
  private readonly durations = new Map<string, DurationRecord>();

  increment(name: string, help: string, amount = 1): void {
    validateMetricName(name);
    const current = this.counters.get(name) ?? { help, value: 0 };
    current.value += amount;
    this.counters.set(name, current);
  }

  observeMilliseconds(name: string, help: string, milliseconds: number): void {
    validateMetricName(name);
    const current = this.durations.get(name) ?? { help, count: 0, sumSeconds: 0 };
    current.count += 1;
    current.sumSeconds += Math.max(0, milliseconds) / 1_000;
    this.durations.set(name, current);
  }

  render(gauges: Record<string, { help: string; value: number }>): string {
    const lines: string[] = [];
    for (const [name, record] of [...this.counters].sort(([left], [right]) => left.localeCompare(right))) {
      lines.push(`# HELP ${name} ${escapeHelp(record.help)}`);
      lines.push(`# TYPE ${name} counter`);
      lines.push(`${name} ${number(record.value)}`);
    }
    for (const [name, record] of [...this.durations].sort(([left], [right]) => left.localeCompare(right))) {
      lines.push(`# HELP ${name} ${escapeHelp(record.help)}`);
      lines.push(`# TYPE ${name} summary`);
      lines.push(`${name}_count ${number(record.count)}`);
      lines.push(`${name}_sum ${number(record.sumSeconds)}`);
    }
    for (const [name, record] of Object.entries(gauges).sort(([left], [right]) => left.localeCompare(right))) {
      validateMetricName(name);
      lines.push(`# HELP ${name} ${escapeHelp(record.help)}`);
      lines.push(`# TYPE ${name} gauge`);
      lines.push(`${name} ${number(record.value)}`);
    }
    return `${lines.join("\n")}\n`;
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
