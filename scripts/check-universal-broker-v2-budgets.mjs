#!/usr/bin/env node
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import {
  assertUniversalBrokerBudgets,
  inspectUniversalBrokerBudgets,
} from "../dist/v2/budgets.js";

const root = resolve(fileURLToPath(new URL("..", import.meta.url)));
verifyBaseline();
const report = await inspectUniversalBrokerBudgets();
console.log(JSON.stringify(report, null, 2));
assertUniversalBrokerBudgets(report);
console.log("Universal Broker v2 budget gate: PASS");

function verifyBaseline() {
  const baseline = JSON.parse(
    readFileSync(resolve(root, "contracts/universal-broker-v2-baseline.json"), "utf8"),
  );
  const tagCommit = git(["rev-list", "-n", "1", baseline.sourceTag]);
  if (tagCommit !== baseline.sourceCommit) {
    throw new Error(
      `Universal Broker baseline mismatch: ${baseline.sourceTag} -> ${tagCommit}, expected ${baseline.sourceCommit}`,
    );
  }
  console.log(`Universal Broker v2 baseline: ${baseline.sourceTag} -> ${tagCommit}`);
}

function git(args) {
  const result = spawnSync("git", args, {
    cwd: root,
    encoding: "utf8",
  });
  if (result.error) throw result.error;
  if (result.status !== 0) {
    throw new Error(`git ${args.join(" ")} failed: ${result.stderr.trim()}`);
  }
  return result.stdout.trim();
}
