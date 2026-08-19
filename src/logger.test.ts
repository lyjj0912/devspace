import assert from "node:assert/strict";
import test from "node:test";
import { commandPreview, redactLogFields, sessionIdPrefix } from "./logger.js";

test("logger structurally redacts secrets and hashes opaque identifiers", () => {
  const redacted = redactLogFields({
    authorization: "Bearer raw-token",
    nested: { refreshToken: "raw-refresh", message: "access_token=raw-access" },
  });
  const json = JSON.stringify(redacted);
  assert.doesNotMatch(json, /raw-token|raw-refresh|raw-access/u);
  assert.match(json, /REDACTED/u);
  assert.match(sessionIdPrefix("session-secret") ?? "", /^sha256:[a-f0-9]{16}$/u);
  assert.doesNotMatch(commandPreview("deploy --token raw-command-secret"), /raw-command-secret/u);
});
