import assert from "node:assert/strict";
import test from "node:test";
import {
  BASE_PRODUCT_PROFILE,
  buildCapabilityContract,
  capabilityDigest,
  createBuildCapabilityManifest,
  RESOURCE_URI_VERSION,
  SUPPORTED_PRODUCT_PROFILES,
} from "./build-capabilities.js";
import { UNIVERSAL_TOOL_NAMES, UNIVERSAL_TOOL_OPERATIONS } from "./contracts.js";

test("base build advertises only implemented BASE_SINGLE_OWNER capabilities", () => {
  const contract = buildCapabilityContract();
  assert.equal(contract.productProfile, BASE_PRODUCT_PROFILE);
  assert.deepEqual(contract.supportedProfiles, ["BASE_SINGLE_OWNER"]);
  assert.deepEqual(SUPPORTED_PRODUCT_PROFILES, ["BASE_SINGLE_OWNER"]);
  assert.equal(contract.resourceUriVersion, RESOURCE_URI_VERSION);
  assert.deepEqual(Object.keys(contract.supportedOperations), [...UNIVERSAL_TOOL_NAMES]);
  assert.deepEqual(contract.supportedOperations, UNIVERSAL_TOOL_OPERATIONS);
  assert.equal((contract.supportedOperations.fs as readonly string[]).includes("restore"), false);
  assert.doesNotMatch(JSON.stringify(contract), /MULTI_USER|SIDECAR_AUTHORITY|HOST_ATTESTED|GUI_CAPTURE/u);
});

test("build capability manifest binds a deterministic contract digest and build digest", () => {
  const buildDigest = `sha256:${"a".repeat(64)}`;
  const first = createBuildCapabilityManifest(buildDigest);
  const second = createBuildCapabilityManifest(buildDigest);
  assert.deepEqual(first, second);
  assert.equal(first.buildDigest, buildDigest);
  assert.equal(first.capabilityDigest, capabilityDigest());
  assert.match(first.capabilityDigest, /^sha256:[a-f0-9]{64}$/u);
  assert.throws(() => createBuildCapabilityManifest("pending"), /canonical SHA-256/u);
});
