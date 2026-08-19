import assert from "node:assert/strict";
import test from "node:test";
import { UniversalBrokerMetrics } from "./metrics.js";

test("metrics render bounded counters, duration summaries, and gauges", () => {
  const metrics = new UniversalBrokerMetrics();
  metrics.increment("devspace_requests_total", "Requests", 2);
  metrics.increment("devspace_requests_total", "Requests", 1, {
    tool: "fs",
    operation: "read",
    result: "pass",
  });
  metrics.observeMilliseconds("devspace_request_duration_seconds", "Duration", 250);
  metrics.recordMcpReconnect("fixture", "pass");
  metrics.recordMcpConnection("fixture", "connected");
  const text = metrics.render({
    devspace_open_sessions: { help: "Open sessions", value: 3 },
  });
  assert.match(text, /devspace_requests_total 2/);
  assert.match(text, /devspace_requests_total\{operation="read",result="pass",tool="fs"\} 1/);
  assert.match(text, /devspace_request_duration_seconds_count 1/);
  assert.match(text, /devspace_request_duration_seconds_sum 0.25/);
  assert.match(text, /devspace_open_sessions 3/);
  assert.match(text, /devspace_mcp_reconnect_total\{result="pass",route="fixture"\} 1/);
  assert.match(text, /devspace_mcp_connections\{route="fixture",state="connected"\} 1/);
  assert.match(text, /devspace_mcp_connections\{route="fixture",state="disconnected"\} 0/);

  metrics.recordMcpConnection("fixture", "disconnected");
  const disconnected = metrics.render({});
  assert.match(disconnected, /devspace_mcp_connections\{route="fixture",state="connected"\} 0/);
  assert.match(disconnected, /devspace_mcp_connections\{route="fixture",state="disconnected"\} 1/);
});
