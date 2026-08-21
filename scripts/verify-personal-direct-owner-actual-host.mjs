#!/usr/bin/env node
import { readFile } from "node:fs/promises";
import { resolve } from "node:path";
import { verifyPersonalActualHostEvidence } from "../src/v2/personal-actual-host-acceptance.js";

const argument = process.argv.slice(2);
const evidenceIndex = argument.indexOf("--evidence");
if (evidenceIndex < 0 || !argument[evidenceIndex + 1]) {
  throw new Error("Usage: verify-personal-direct-owner-actual-host.mjs --evidence FILE");
}
const path = resolve(argument[evidenceIndex + 1]);
const evidence = JSON.parse(await readFile(path, "utf8"));
const result = verifyPersonalActualHostEvidence(evidence);
process.stdout.write(`${JSON.stringify({ ...result, evidencePath: path }, null, 2)}\n`);
