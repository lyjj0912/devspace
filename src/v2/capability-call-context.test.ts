import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import test from "node:test";
import {
  asyncLocalCapabilityCallContextProvider,
  createCapabilityCallContextFromTrustedPrincipal,
  currentCapabilityCallContext,
  requireCapabilityCallContext,
  runWithCapabilityCallContext,
  type CapabilityCallContext,
} from "./capability-call-context.js";

const PRINCIPAL = createHash("sha256").update("owner-a").digest("hex");

test("capability call context is immutable and carries only trusted stable identity", () => {
  const context = createCapabilityCallContextFromTrustedPrincipal({
    principalKeyFingerprint: PRINCIPAL.toUpperCase(),
    requestId: "request-1",
    receivedAt: "2026-08-19T00:00:00.000Z",
  });
  assert.equal(Object.isFrozen(context), true);
  assert.equal(context.principalKeyFingerprint, PRINCIPAL);
  assert.throws(
    () => { (context as { principalKeyFingerprint: string }).principalKeyFingerprint = "0".repeat(64); },
    TypeError,
  );
});

test("missing and structurally fabricated capability contexts fail closed", () => {
  assert.throws(() => requireCapabilityCallContext(), hasCode("AUTHENTICATION_FAILED"));
  const fabricated = Object.freeze({
    principalKeyFingerprint: PRINCIPAL,
  }) as CapabilityCallContext;
  assert.throws(
    () => requireCapabilityCallContext(fabricated),
    hasCode("AUTHENTICATION_FAILED"),
  );
});

test("async-local helper propagates a prevalidated context without becoming a fallback", async () => {
  const context = createCapabilityCallContextFromTrustedPrincipal({
    principalKeyFingerprint: PRINCIPAL,
  });
  assert.equal(currentCapabilityCallContext(), undefined);
  await runWithCapabilityCallContext(context, async () => {
    await Promise.resolve();
    assert.equal(asyncLocalCapabilityCallContextProvider(), context);
    assert.equal(requireCapabilityCallContext(undefined, asyncLocalCapabilityCallContextProvider), context);
  });
  assert.equal(currentCapabilityCallContext(), undefined);
});

function hasCode(code: string) {
  return (error: unknown) => error instanceof Error
    && "code" in error
    && error.code === code;
}
