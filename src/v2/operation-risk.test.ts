import assert from "node:assert/strict";
import test from "node:test";
import { UNIVERSAL_TOOL_OPERATIONS } from "./contracts.js";
import { personalOperationRisk } from "./operation-risk.js";

test("Personal operation audit risk distinguishes reads, mutations, and irreversible boundaries", () => {
  const cases = [
    ["target", "list", {}, "R0"],
    ["context", "search", {}, "R0"],
    ["context", "open", { mode: "existing" }, "R1"],
    ["context", "open", { mode: "worktree" }, "R2"],
    ["fs", "read", {}, "R0"],
    ["fs", "sync", { sync: { phase: "plan" } }, "R0"],
    ["fs", "sync", { sync: { phase: "apply" } }, "R2"],
    ["fs", "write", {}, "R1"],
    ["fs", "remove", { disposition: "permanent" }, "R3"],
    ["exec", "run", {}, "R2"],
    ["process", "restart_status", {}, "R0"],
    ["process", "signal", {}, "R2"],
    ["process", "restart_broker", {}, "R3"],
    ["mcp", "read_resource", {}, "R0"],
    ["mcp", "invoke", {}, "R2"],
    ["artifact", "publish", {}, "R1"],
    ["artifact", "copy", {}, "R2"],
    ["gui", "observe", {}, "R0"],
    ["gui", "act", {}, "R2"],
  ] as const;
  for (const [tool, operation, input, expected] of cases) {
    assert.equal(personalOperationRisk(tool, operation, input), expected, `${tool}.${operation}`);
  }
});

test("every advertised operation has an explicit bounded audit classification", () => {
  for (const [tool, operations] of Object.entries(UNIVERSAL_TOOL_OPERATIONS)) {
    for (const operation of operations) {
      assert.match(
        personalOperationRisk(tool as keyof typeof UNIVERSAL_TOOL_OPERATIONS, operation, {}),
        /^R[0-3]$/u,
        `${tool}.${operation}`,
      );
    }
  }
});
