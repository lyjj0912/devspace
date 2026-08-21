import { BASE_PRODUCT_PROFILE } from "./profile-contract.js";
import { UNIVERSAL_TOOL_NAMES } from "./contracts.js";

export const PERSONAL_ACTUAL_HOST_SECTION_IDS = Object.freeze([
  "discovery",
  "localFilesystem",
  "localCompositeExec",
  "processLifecycle",
  "sshTarget",
  "downstreamMcp",
  "artifact",
  "gui",
  "recoveryRegression",
  "reconnection",
] as const);

export type PersonalActualHostSectionId = typeof PERSONAL_ACTUAL_HOST_SECTION_IDS[number];

export interface PersonalActualHostEvidence {
  productProfile: string;
  evidenceSource: string;
  hostProduct: string;
  connectorName: string;
  toolNames: readonly string[];
  actualMutationEvidenceIds: readonly string[];
  sections: Record<PersonalActualHostSectionId, {
    status: "PASS" | "FAIL" | "NOT_RUN";
    evidenceIds: readonly string[];
  }>;
  recoveryFixture: {
    terminalRecords: number;
    runningRecords: number;
    expiredTerminalRecords: number;
    corruptTerminalRecords: number;
  };
  reconnection: {
    newChatGptSessionMutation: boolean;
    brokerRestartMutation: boolean;
    tokenRefreshMutation: boolean;
    distinctClientSeparated: boolean;
  };
}

export function verifyPersonalActualHostEvidence(input: PersonalActualHostEvidence): {
  status: "PERSONAL_DIRECT_OWNER_E2E_PASS";
  sections: readonly PersonalActualHostSectionId[];
} {
  if (input.productProfile !== BASE_PRODUCT_PROFILE) {
    throw new Error(`Actual-host evidence profile must be ${BASE_PRODUCT_PROFILE}.`);
  }
  if (input.evidenceSource !== "ACTUAL_CHATGPT_INSTALLED_CONNECTOR") {
    throw new Error("Synthetic, curl, local SDK, PM2, and health-only evidence cannot satisfy actual-host acceptance.");
  }
  if (input.hostProduct !== "ChatGPT" || input.connectorName !== "myDevSpace-v2-production") {
    throw new Error("Actual-host evidence must use the installed myDevSpace-v2-production ChatGPT connector.");
  }
  if (JSON.stringify(input.toolNames) !== JSON.stringify(UNIVERSAL_TOOL_NAMES)) {
    throw new Error("Actual-host discovery must report the exact ordered eight-tool surface.");
  }
  for (const sectionId of PERSONAL_ACTUAL_HOST_SECTION_IDS) {
    const section = input.sections?.[sectionId];
    if (section?.status !== "PASS" || !Array.isArray(section.evidenceIds) || section.evidenceIds.length === 0) {
      throw new Error(`Actual-host section ${sectionId} is not PASS with concrete evidence.`);
    }
  }
  if (!Array.isArray(input.actualMutationEvidenceIds) || input.actualMutationEvidenceIds.length < 6) {
    throw new Error("Read-only smoke evidence cannot substitute for the required actual mutations.");
  }
  const fixture = input.recoveryFixture;
  if (
    fixture?.terminalRecords < 1_000
    || fixture.runningRecords < 2
    || fixture.expiredTerminalRecords < 1
    || fixture.corruptTerminalRecords < 1
  ) {
    throw new Error("Recovery evidence does not contain the required regression fixture.");
  }
  if (Object.values(input.reconnection ?? {}).some((value) => value !== true)) {
    throw new Error("Reconnection evidence is incomplete.");
  }
  return {
    status: "PERSONAL_DIRECT_OWNER_E2E_PASS",
    sections: PERSONAL_ACTUAL_HOST_SECTION_IDS,
  };
}
