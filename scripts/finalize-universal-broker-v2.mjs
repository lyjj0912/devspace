#!/usr/bin/env node
import { FinalizationInterruptedError, prepareFinalization, sealFinalization } from "./lib/finalization-state.mjs";

const [command, ...arguments_] = process.argv.slice(2);
const options = parseOptions(arguments_);

try {
  const common = {
    auditRoot: required(options, "audit"),
    evidencePath: required(options, "evidence"),
  };
  const result = command === "prepare"
    ? prepareFinalization(common)
    : command === "seal"
      ? sealFinalization({
          ...common,
          driverPath: options.get("driver"),
          interruptAfterAction: options.get("interrupt-after-action"),
        })
      : usage();
  console.log(JSON.stringify(result, null, 2));
} catch (error) {
  console.error(error instanceof Error ? error.message : String(error));
  process.exit(error instanceof FinalizationInterruptedError ? error.exitCode : 1);
}

function parseOptions(values) {
  const output = new Map();
  for (let index = 0; index < values.length; index += 2) {
    const name = values[index];
    const value = values[index + 1];
    if (!name?.startsWith("--") || value === undefined) usage();
    output.set(name.slice(2), value);
  }
  return output;
}

function required(values, key) {
  const value = values.get(key);
  if (!value) throw new Error(`--${key} is required.`);
  return value;
}

function usage() {
  console.error("Usage: finalize-universal-broker-v2.mjs <prepare|seal> --audit DIR --evidence FILE [--driver FILE]");
  process.exit(2);
}
