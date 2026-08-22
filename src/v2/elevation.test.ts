import assert from "node:assert/strict";
import test from "node:test";
import { UniversalBrokerError } from "./errors.js";
import { configuredElevationCapability, normalizeExecutionElevation } from "./elevation.js";

test("execution elevation defaults to the ordinary lane and validates prompt requests", () => {
  assert.deepEqual(normalizeExecutionElevation(undefined), {
    mode: "none",
    scope: "operation",
    timeoutMs: 0,
  });
  assert.deepEqual(normalizeExecutionElevation({
    mode: "prompt",
    reason: "Read a protected task-owned fixture",
  }), {
    mode: "prompt",
    scope: "operation",
    timeoutMs: 120_000,
    reason: "Read a protected task-owned fixture",
    reasonSha256: "a4226608492a41ea6c9544a3b99e0494358280841f43aa8313f63a9b5dc2280e",
  });
  for (const input of [
    { mode: "prompt" },
    { mode: "none", reason: "not allowed" },
    { mode: "prompt", reason: "bad\nreason" },
    { mode: "prompt", reason: "ok", timeoutMs: 999 },
  ] as const) {
    assert.throws(
      () => normalizeExecutionElevation(input as never),
      (error: unknown) => error instanceof UniversalBrokerError && error.code === "INVALID_ARGUMENT",
    );
  }
});

test("target elevation capability is explicit and does not claim an unverified provider", () => {
  assert.deepEqual(configuredElevationCapability("deny", "macos"), {
    policy: "deny",
    configured: false,
    requiresUserInteraction: false,
  });
  assert.deepEqual(configuredElevationCapability("prompt", "macos"), {
    policy: "prompt",
    configured: true,
    requiresUserInteraction: true,
    mechanism: "macos-authorization-services",
    available: false,
    reason: "A user-authorized execution provider has not been verified for this target.",
  });
});
