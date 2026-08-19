import assert from "node:assert/strict";
import test from "node:test";
import {
  failedToolResult,
  successfulToolResult,
  UniversalBrokerError,
} from "./errors.js";

test("universal result helpers preserve stable operation and error contracts", () => {
  const success = successfulToolResult({ value: 1 }, "op_success");
  assert.deepEqual(success.structuredContent, {
    ok: true,
    operationId: "op_success",
    data: { value: 1 },
    observedSchemaGeneration: `sha256:${"0".repeat(64)}`,
  });

  const failure = failedToolResult(new UniversalBrokerError(
    "TARGET_NOT_FOUND",
    "Unknown target",
    {
      operationId: "op_failure",
      suggestions: [{ targetId: "local" }],
    },
  ));
  assert.equal(failure.isError, true);
  assert.deepEqual(failure.structuredContent, {
    ok: false,
    operationId: "op_failure",
    error: {
      code: "TARGET_NOT_FOUND",
      message: "Unknown target",
      retryable: false,
      dispatchState: "NOT_DISPATCHED",
      suggestions: [{ targetId: "local" }],
      recovery: [{ targetId: "local" }],
    },
    observedSchemaGeneration: `sha256:${"0".repeat(64)}`,
  });
});
