import assert from "node:assert/strict";
import test from "node:test";
import { UniversalBrokerMetrics } from "./metrics.js";

test("metrics render bounded counters, duration summaries, and gauges", () => {
  const metrics = new UniversalBrokerMetrics();
  metrics.increment("devspace_requests_total", "Requests", 2);
  metrics.observeMilliseconds("devspace_request_duration_seconds", "Duration", 250);
  const text = metrics.render({
    devspace_open_sessions: { help: "Open sessions", value: 3 },
  });
  assert.match(text, /devspace_requests_total 2/);
  assert.match(text, /devspace_request_duration_seconds_count 1/);
  assert.match(text, /devspace_request_duration_seconds_sum 0.25/);
  assert.match(text, /devspace_open_sessions 3/);
});
