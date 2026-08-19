#!/usr/bin/env node
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { assertGatewayIdentity, assertRuntimeIdentity, createReleasePackage, verifyReleasePackage, verifyRuntimeTree } from "./lib/release-artifacts.mjs";

const [command, ...arguments_] = process.argv.slice(2);
const options = parseOptions(arguments_);

try {
  if (command === "create") {
    const result = createReleasePackage({
      sourceRoot: required(options, "source"),
      outputRoot: required(options, "output"),
      sourceRevision: options.get("source-revision"),
      runtimeRevision: options.get("runtime-revision"),
      createdAt: options.get("created-at"),
    });
    console.log(JSON.stringify({ status: "CREATED", ...result }, null, 2));
  } else if (command === "verify") {
    const result = verifyReleasePackage(required(options, "package"), {
      expectedSourceRevision: options.get("source-revision"),
      expectedRuntimeRevision: options.get("runtime-revision"),
    });
    console.log(JSON.stringify(result, null, 2));
  } else if (command === "verify-runtime") {
    const packageRoot = required(options, "package");
    const observedPath = required(options, "identity");
    const manifest = JSON.parse(readFileSync(resolve(packageRoot, "BUILD-MANIFEST.json"), "utf8"));
    const observed = JSON.parse(readFileSync(resolve(observedPath), "utf8"));
    assertRuntimeIdentity(manifest, observed);
    console.log(JSON.stringify({ status: "PASS", identity: observed }, null, 2));
  } else if (command === "verify-gateway") {
    const packageRoot = required(options, "package");
    const observedPath = required(options, "identity");
    const manifest = JSON.parse(readFileSync(resolve(packageRoot, "BUILD-MANIFEST.json"), "utf8"));
    const observed = JSON.parse(readFileSync(resolve(observedPath), "utf8"));
    assertGatewayIdentity(manifest, observed);
    console.log(JSON.stringify({ status: "PASS", identity: observed }, null, 2));
  } else if (command === "verify-runtime-tree") {
    console.log(JSON.stringify(verifyRuntimeTree(
      required(options, "package"),
      required(options, "runtime-root"),
    ), null, 2));
  } else {
    usage();
  }
} catch (error) {
  console.error(error instanceof Error ? error.message : String(error));
  process.exit(1);
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
  console.error("Usage: release-artifacts.mjs <create|verify|verify-runtime|verify-gateway|verify-runtime-tree> [options]");
  process.exit(2);
}
