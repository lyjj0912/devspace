import assert from "node:assert/strict";
import test from "node:test";
import { UNIVERSAL_RESOURCE_DEFAULTS } from "./resource-defaults.js";

test("resource defaults exactly match the normative quota and TTL table", () => {
  assert.deepEqual(UNIVERSAL_RESOURCE_DEFAULTS, {
    quotas: {
      contexts: 64,
      processes: 128,
      concurrentProcesses: 16,
      mcpConnections: 64,
      guiSessions: 16,
      artifacts: 256,
      inlineOutputBytes: 65_536,
      processOutputBytes: 104_857_600,
      artifactMaxBytes: 1_073_741_824,
      mcpResultMaxBytes: 268_435_456,
    },
    ttlMs: {
      context: 1_800_000,
      completedProcess: 900_000,
      mcpIdle: 900_000,
      gui: 600_000,
      artifact: 86_400_000,
      cursorSnapshot: 600_000,
    },
  });
  assert.equal(Object.isFrozen(UNIVERSAL_RESOURCE_DEFAULTS), true);
  assert.equal(Object.isFrozen(UNIVERSAL_RESOURCE_DEFAULTS.quotas), true);
  assert.equal(Object.isFrozen(UNIVERSAL_RESOURCE_DEFAULTS.ttlMs), true);
});
