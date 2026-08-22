import assert from "node:assert/strict";
import { join } from "node:path";
import test from "node:test";
import {
  bindUserAuthorizationConfigurationDigest,
  loadUserAuthorizationRuntimeConfiguration,
} from "./macos-authorization-runtime-config.js";

const STATE = "/private/tmp/devspace-authorization-config-state";
const DIGEST_A = `sha256:${"a".repeat(64)}`;
const DIGEST_B = `sha256:${"b".repeat(64)}`;
const BASE_DIGEST = `sha256:${"c".repeat(64)}`;

test("authorization runtime configuration is disabled by default without changing the base digest", () => {
  const value = loadUserAuthorizationRuntimeConfiguration({}, STATE);
  assert.deepEqual(value, {
    userAuthorizationStorePath: join(STATE, "user-authorization.sqlite"),
  });
  assert.equal(bindUserAuthorizationConfigurationDigest(BASE_DIGEST, value), BASE_DIGEST);
});

test("authorization runtime configuration requires a complete explicit native provider", () => {
  const environment = {
    DEVSPACE_NEXT_MACOS_AUTHORIZATION_ENABLED: "true",
    DEVSPACE_NEXT_USER_AUTHORIZATION_STORE: join(STATE, "authorization.sqlite"),
    DEVSPACE_NEXT_MACOS_AUTHORIZATION_AGENT: "/private/tmp/release/devspace-approval-agent",
    DEVSPACE_NEXT_MACOS_AUTHORIZATION_AGENT_SHA256: DIGEST_A,
    DEVSPACE_NEXT_MACOS_PRIVILEGED_HELPER: "/private/tmp/release/devspace-privileged-helper",
    DEVSPACE_NEXT_MACOS_PRIVILEGED_HELPER_SHA256: DIGEST_B,
    DEVSPACE_NEXT_MACOS_AUTHORIZATION_WORK_ROOT: join(STATE, "authorization-work"),
  };
  const first = loadUserAuthorizationRuntimeConfiguration(environment, STATE);
  const reordered = loadUserAuthorizationRuntimeConfiguration(
    Object.fromEntries(Object.entries(environment).reverse()),
    STATE,
  );
  assert.equal(first.macosAuthorization?.provider, "macos-authorization-services-v1");
  assert.equal(first.macosAuthorization?.agentSha256, DIGEST_A);
  assert.equal(first.macosAuthorization?.helperSha256, DIGEST_B);
  assert.match(bindUserAuthorizationConfigurationDigest(BASE_DIGEST, first), /^sha256:[a-f0-9]{64}$/u);
  assert.equal(
    bindUserAuthorizationConfigurationDigest(BASE_DIGEST, first),
    bindUserAuthorizationConfigurationDigest(BASE_DIGEST, reordered),
  );
  assert.notEqual(bindUserAuthorizationConfigurationDigest(BASE_DIGEST, first), BASE_DIGEST);
});

test("authorization runtime configuration rejects partial, hidden, and unsafe values", () => {
  assert.throws(
    () => loadUserAuthorizationRuntimeConfiguration({
      DEVSPACE_NEXT_MACOS_AUTHORIZATION_AGENT: "/private/tmp/agent",
    }, STATE),
    /configured while.*ENABLED is not true/u,
  );
  assert.throws(
    () => loadUserAuthorizationRuntimeConfiguration({
      DEVSPACE_NEXT_MACOS_AUTHORIZATION_ENABLED: "true",
      DEVSPACE_NEXT_MACOS_AUTHORIZATION_AGENT: "/private/tmp/agent",
    }, STATE),
    /configuration is incomplete/u,
  );
  assert.throws(
    () => loadUserAuthorizationRuntimeConfiguration({
      DEVSPACE_NEXT_MACOS_AUTHORIZATION_ENABLED: "sometimes",
    }, STATE),
    /must be true or false/u,
  );
  assert.throws(
    () => loadUserAuthorizationRuntimeConfiguration({
      DEVSPACE_NEXT_USER_AUTHORIZATION_STORE: "relative.sqlite",
    }, STATE),
    /canonical absolute path/u,
  );
});
