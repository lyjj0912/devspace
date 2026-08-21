#!/usr/bin/env node
import { readFile } from "node:fs/promises";
import { resolve } from "node:path";
import { verifyPersonalActualHostEvidence } from "../src/v2/personal-actual-host-acceptance.js";
import { verifyOperationAuditText } from "../src/v2/operation-audit.js";

const argumentsList = process.argv.slice(2);
const evidencePath = requiredPath(argumentsList, "--evidence");
const auditPath = requiredPath(argumentsList, "--audit");
const [evidenceText, auditText] = await Promise.all([
  readFile(evidencePath, "utf8"),
  readFile(auditPath, "utf8"),
]);
const evidence = JSON.parse(evidenceText);
const auditRecords = verifyOperationAuditText(auditText);
const result = verifyPersonalActualHostEvidence(evidence, auditRecords);
process.stdout.write(`${JSON.stringify({
  ...result,
  evidencePath,
  auditPath,
  verifiedAuditRecordCount: auditRecords.length,
}, null, 2)}\n`);

function requiredPath(values, flag) {
  const index = values.indexOf(flag);
  const value = index < 0 ? undefined : values[index + 1];
  if (!value) {
    throw new Error(
      "Usage: verify-personal-direct-owner-actual-host.mjs --evidence FILE --audit FILE",
    );
  }
  return resolve(value);
}
