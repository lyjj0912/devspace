#!/usr/bin/env node
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import {
  assertGatewayIdentity,
  assertRuntimeIdentity,
  createAttestedReleasePackage,
  createStagingReleasePackage,
  sealRuntimeDependencies,
  verifyGateProducerTrustAnchor,
  verifyReleasePackage,
  verifyUnattestedReleaseFixture,
  verifyRuntimeCommand,
  verifyRuntimeDependencies,
  verifyRuntimeTree,
  verifiedReleaseManifest,
} from "./lib/release-artifacts.mjs";
import { loadExistingManagementAuthorizationKey } from "../dist/v2/management-authorization.js";

const [command, ...arguments_] = process.argv.slice(2);
const options = parseOptions(arguments_);

try {
  if (command === "create-staging-fixture") {
    const result = createStagingReleasePackage({
      sourceRoot: required(options, "source"),
      outputRoot: required(options, "output"),
      sourceRevision: options.get("source-revision"),
      runtimeRevision: options.get("runtime-revision"),
      createdAt: options.get("created-at"),
    });
    console.log(JSON.stringify({ status: "CREATED_STAGING_FIXTURE", ...result }, null, 2));
  } else if (command === "create") {
    const gateProducerTrustAnchor = trustedGateProducer(options);
    const result = createAttestedReleasePackage({
      sourceRoot: required(options, "source"),
      outputRoot: required(options, "output"),
      sourceRevision: options.get("source-revision"),
      runtimeRevision: options.get("runtime-revision"),
      createdAt: options.get("created-at"),
      gateProducerPrivateKeyPath: required(options, "gate-producer-private-key"),
      gateProducerTrustAnchor,
    });
    console.log(JSON.stringify({ status: "CREATED", ...result }, null, 2));
  } else if (command === "verify") {
    const result = verifySelectedRelease(required(options, "package"), options);
    console.log(JSON.stringify(result, null, 2));
  } else if (command === "verify-runtime") {
    const packageRoot = required(options, "package");
    const observedPath = required(options, "identity");
    const release = verifySelectedRelease(packageRoot, options);
    const manifest = verifiedReleaseManifest(release);
    const observed = JSON.parse(readFileSync(resolve(observedPath), "utf8"));
    assertRuntimeIdentity(manifest, observed);
    console.log(JSON.stringify({ status: "PASS", identity: observed }, null, 2));
  } else if (command === "verify-gateway") {
    const packageRoot = required(options, "package");
    const observedPath = required(options, "identity");
    const release = verifySelectedRelease(packageRoot, options);
    const manifest = verifiedReleaseManifest(release);
    const observed = JSON.parse(readFileSync(resolve(observedPath), "utf8"));
    assertGatewayIdentity(manifest, observed);
    console.log(JSON.stringify({ status: "PASS", identity: observed }, null, 2));
  } else if (command === "verify-runtime-tree") {
    console.log(JSON.stringify(verifyRuntimeTree(
      required(options, "package"),
      required(options, "runtime-root"),
      runtimeHelperOptions(options),
    ), null, 2));
  } else if (command === "verify-runtime-command") {
    console.log(JSON.stringify(verifyRuntimeCommand(
      required(options, "package"),
      required(options, "runtime-root"),
      required(options, "entrypoint"),
      {
        expectedManifestSha256: options.get("manifest-sha256"),
        ...runtimeHelperOptions(options),
      },
    ), null, 2));
  } else if (command === "seal-runtime-dependencies") {
    console.log(JSON.stringify(sealRuntimeDependencies(
      required(options, "package"),
      required(options, "dependency-root"),
      runtimeHelperOptions(options),
    ), null, 2));
  } else if (command === "verify-runtime-dependencies") {
    console.log(JSON.stringify(verifyRuntimeDependencies(
      required(options, "package"),
      required(options, "dependency-root"),
      {
        evidencePath: options.get("evidence"),
        expectedEvidenceSha256: options.get("evidence-sha256"),
        ...runtimeHelperOptions(options),
      },
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

function isStagingFixture(values) {
  const value = values.get("staging-fixture");
  if (value === undefined) return false;
  if (value !== "true") throw new Error("--staging-fixture must be exactly true when supplied.");
  return true;
}

function verifySelectedRelease(packageRoot, values) {
  const common = {
    expectedSourceRevision: values.get("source-revision"),
    expectedRuntimeRevision: values.get("runtime-revision"),
  };
  return isStagingFixture(values)
    ? verifyUnattestedReleaseFixture(packageRoot, common)
    : verifyReleasePackage(packageRoot, { ...common, gateProducerTrustAnchor: trustedGateProducer(values) });
}

function runtimeHelperOptions(values) {
  return isStagingFixture(values)
    ? { allowUnattestedFixture: true }
    : { gateProducerTrustAnchor: trustedGateProducer(values) };
}

function trustedGateProducer(values) {
  const stateDir = required(values, "state-dir");
  const key = loadExistingManagementAuthorizationKey({
    keyRef: required(values, "management-key-ref"),
    stateDir,
  });
  return verifyGateProducerTrustAnchor({
    path: required(values, "gate-producer-trust-anchor"),
    sha256: required(values, "gate-producer-trust-anchor-sha256"),
    key,
    expectedOwnerInstanceId: required(values, "owner-instance-id"),
    expectedEnvironment: required(values, "environment"),
  });
}

function usage() {
  console.error("Usage: release-artifacts.mjs <command> [options]. Production commands require the gate-producer trust options; create additionally requires --gate-producer-private-key. create-staging-fixture and helper calls with --staging-fixture true are non-release-eligible and require no trust material.");
  process.exit(2);
}
