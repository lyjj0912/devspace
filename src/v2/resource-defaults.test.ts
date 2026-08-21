import assert from "node:assert/strict";
import test from "node:test";
import { UNIVERSAL_RESOURCE_DEFAULTS } from "./resource-defaults.js";

test("resource defaults exactly match the normative quota and TTL table", () => {
  assert.deepEqual(UNIVERSAL_RESOURCE_DEFAULTS, {
    process: {
      maximumRunningTotal: 64,
      maximumRunningPerTarget: 32,
      terminalRetentionTtlMs: 3_600_000,
      maximumRetainedTerminalRecords: 10_000,
      maximumOutputBytesPerProcess: 1_073_741_824,
      terminalOverflowPolicy: "prune-oldest",
      internalRunnerMaximumConcurrent: 32,
    },
    quotas: {
      contexts: 64,
      mcpConnections: 64,
      guiSessions: 16,
      artifacts: 256,
      inlineOutputBytes: 65_536,
      artifactMaxBytes: 1_073_741_824,
      mcpResultMaxBytes: 268_435_456,
    },
    ttlMs: {
      context: 1_800_000,
      mcpIdle: 900_000,
      gui: 600_000,
      artifact: 86_400_000,
      cursorSnapshot: 600_000,
    },
  });
  assert.equal(Object.isFrozen(UNIVERSAL_RESOURCE_DEFAULTS), true);
  assert.equal(Object.isFrozen(UNIVERSAL_RESOURCE_DEFAULTS.process), true);
  assert.equal(Object.isFrozen(UNIVERSAL_RESOURCE_DEFAULTS.quotas), true);
  assert.equal(Object.isFrozen(UNIVERSAL_RESOURCE_DEFAULTS.ttlMs), true);
});
