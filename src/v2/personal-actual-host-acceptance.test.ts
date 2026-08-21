import assert from "node:assert/strict";
import test from "node:test";
import {
  PERSONAL_ACTUAL_HOST_SECTION_IDS,
  verifyPersonalActualHostEvidence,
  type PersonalActualHostEvidence,
} from "./personal-actual-host-acceptance.js";

function fixture(): PersonalActualHostEvidence {
  return {
    productProfile: "PERSONAL_DIRECT_OWNER",
    evidenceSource: "ACTUAL_CHATGPT_INSTALLED_CONNECTOR",
    hostProduct: "ChatGPT",
    connectorName: "myDevSpace-v2-production",
    toolNames: ["target", "context", "fs", "exec", "process", "mcp", "artifact", "gui"],
    actualMutationEvidenceIds: ["fs", "exec", "process", "mcp", "artifact", "gui"],
    sections: Object.fromEntries(PERSONAL_ACTUAL_HOST_SECTION_IDS.map((id) => [id, {
      status: "PASS",
      evidenceIds: [`actual:${id}`],
    }])) as unknown as PersonalActualHostEvidence["sections"],
    recoveryFixture: {
      terminalRecords: 1_000,
      runningRecords: 2,
      expiredTerminalRecords: 1,
      corruptTerminalRecords: 1,
    },
    reconnection: {
      newChatGptSessionMutation: true,
      brokerRestartMutation: true,
      tokenRefreshMutation: true,
      distinctClientSeparated: true,
    },
  };
}

test("complete actual ChatGPT connector evidence earns the exact terminal status", () => {
  assert.equal(verifyPersonalActualHostEvidence(fixture()).status, "PERSONAL_DIRECT_OWNER_E2E_PASS");
});

test("synthetic or read-only evidence cannot be promoted to actual-host PASS", () => {
  assert.throws(
    () => verifyPersonalActualHostEvidence({ ...fixture(), evidenceSource: "LOCAL_MCP_SDK" }),
    /cannot satisfy actual-host acceptance/u,
  );
  assert.throws(
    () => verifyPersonalActualHostEvidence({ ...fixture(), actualMutationEvidenceIds: ["target.list"] }),
    /Read-only smoke evidence/u,
  );
});

test("every A-J section is mandatory and NOT_RUN remains NOT_RUN", () => {
  const evidence = fixture();
  evidence.sections.gui = { status: "NOT_RUN", evidenceIds: [] };
  assert.throws(() => verifyPersonalActualHostEvidence(evidence), /gui is not PASS/u);
});
