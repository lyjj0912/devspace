#!/usr/bin/env node
import {
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { resolve } from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import {
  assertUniversalBrokerBudgets,
  inspectUniversalBrokerBudgets,
} from "../src/v2/budgets.ts";
import { loadConfig } from "../src/config.ts";
import {
  ContextRegistry,
  contextPayloadCharacters,
} from "../src/v2/contexts.ts";
import {
  UNIVERSAL_BROKER_BUDGETS,
} from "../src/v2/contracts.ts";
import { TargetRegistry } from "../src/v2/targets.ts";

const root = resolve(fileURLToPath(new URL("..", import.meta.url)));
verifyBaseline();
verifyRevisionTwoLimits();
const report = await inspectUniversalBrokerBudgets();
console.log(JSON.stringify(report, null, 2));
assertUniversalBrokerBudgets(report);
const contextReport = await inspectContextBudgets();
console.log(JSON.stringify(contextReport, null, 2));
console.log("Universal Broker v2 budget gate: PASS");

function verifyRevisionTwoLimits() {
  const expected = {
    maximumToolDescriptorCharacters: 9_000,
    maximumReusedContextCharacters: 512,
  };
  for (const [name, limit] of Object.entries(expected)) {
    if (UNIVERSAL_BROKER_BUDGETS[name] !== limit) {
      throw new Error(
        `Universal Broker v2.1 ${name} changed: expected ${limit}, observed ${UNIVERSAL_BROKER_BUDGETS[name]}`,
      );
    }
  }
}

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

async function inspectContextBudgets() {
  const temporaryRoot = mkdtempSync(resolve(tmpdir(), "devspace-v2-budget-"));
  try {
    const skillsRoot = resolve(temporaryRoot, "skills");
    mkdirSync(skillsRoot, { recursive: true });
    for (let index = 0; index < 8; index += 1) {
      const directory = resolve(skillsRoot, `release-verification-${index}`);
      mkdirSync(directory);
      writeFileSync(resolve(directory, "SKILL.md"), [
        "---",
        `name: release-verification-${index}`,
        `description: ${"release verification deployment evidence ".repeat(20)}`,
        "---",
        "",
        "Run release verification.",
        "",
      ].join("\n"));
    }
    let contextRoot = temporaryRoot;
    for (let index = 0; index < 6; index += 1) {
      contextRoot = resolve(contextRoot, `long-context-${index}-${"x".repeat(24)}`);
      mkdirSync(contextRoot);
      writeFileSync(resolve(contextRoot, "AGENTS.md"), `instructions ${index}\n`);
      writeFileSync(resolve(contextRoot, "CLAUDE.md"), `claude ${index}\n`);
    }
    const config = loadConfig({
      DEVSPACE_CONFIG_DIR: resolve(temporaryRoot, ".config"),
      DEVSPACE_ALLOWED_ROOTS: temporaryRoot,
      DEVSPACE_STATE_DIR: resolve(temporaryRoot, "legacy-state"),
      DEVSPACE_WORKTREE_ROOT: resolve(temporaryRoot, "worktrees"),
      DEVSPACE_OAUTH_OWNER_TOKEN: "x".repeat(32),
      DEVSPACE_PUBLIC_BASE_URL: "http://127.0.0.1:17676",
      DEVSPACE_LOG_LEVEL: "silent",
      DEVSPACE_SKILL_PATHS: skillsRoot,
    });
    const targets = new TargetRegistry({
      configPath: resolve(temporaryRoot, "missing-targets.json"),
    });
    const contexts = new ContextRegistry({
      storePath: resolve(temporaryRoot, "contexts.json"),
      targets,
      serverConfig: config,
    });
    const initial = await contexts.open({
      path: contextRoot,
      task: "release verification deployment evidence",
    });
    const reused = await contexts.open({ path: contextRoot });
    const initialCharacters = contextPayloadCharacters(initial);
    const reusedCharacters = contextPayloadCharacters(reused);
    if (initialCharacters > UNIVERSAL_BROKER_BUDGETS.maximumInitialContextCharacters) {
      throw new Error(`Initial context uses ${initialCharacters} characters.`);
    }
    if (reusedCharacters > UNIVERSAL_BROKER_BUDGETS.maximumReusedContextCharacters) {
      throw new Error(`Reused context uses ${reusedCharacters} characters.`);
    }
    return {
      initialContextCharacters: initialCharacters,
      initialContextLimit: UNIVERSAL_BROKER_BUDGETS.maximumInitialContextCharacters,
      reusedContextCharacters: reusedCharacters,
      reusedContextLimit: UNIVERSAL_BROKER_BUDGETS.maximumReusedContextCharacters,
      initialContextTruncated: initial.truncated === true,
      passed: true,
    };
  } finally {
    rmSync(temporaryRoot, { recursive: true, force: true });
  }
}
