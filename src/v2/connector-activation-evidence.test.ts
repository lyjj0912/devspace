import assert from "node:assert/strict";
import { createHash, createHmac } from "node:crypto";
import { readFileSync } from "node:fs";
import test from "node:test";
import {
  connectorActivationTupleDigest,
  type ConnectorActivationAuthorityReceipt,
  type ConnectorActivationReceipt,
  type ConnectorActivationTuple,
} from "../oauth-store.js";
import {
  assertVerifiedConnectorActivationOwnerApproval,
  assertVerifiedConnectorActivationPostActivationHostCanary,
  assertVerifiedConnectorActivationPreCutoverHostCanary,
  assertVerifiedConnectorActivationProductionPrecheck,
  assertVerifiedConnectorActivationStagingPrecheck,
  connectorActivationAuthorityReceiptDigest,
  connectorActivationReceiptDigest,
  signConnectorActivationOwnerApproval,
  signConnectorActivationPostActivationHostCanary,
  signConnectorActivationPreCutoverHostCanary,
  signConnectorActivationProductionPrecheck,
  signConnectorActivationStagingPrecheck,
  verifyConnectorActivationOwnerApproval,
  verifyConnectorActivationPostActivationHostCanary,
  verifyPersistedConnectorActivationPreCutoverHostCanary,
  verifyConnectorActivationPreCutoverHostCanary,
  verifyConnectorActivationProductionPrecheck,
  verifyConnectorActivationStagingPrecheck,
  type ConnectorActivationCanaryMutationEvidence,
  type ConnectorActivationEvidenceBinding,
  type ConnectorActivationForeignClientIsolationEvidence,
  type ConnectorActivationImmutableCandidateIdentity,
  type ConnectorActivationOwnerApprovalPayload,
  type ConnectorActivationPostActivationHostCanaryPayload,
  type ConnectorActivationPreCutoverHostCanaryPayload,
  type ConnectorActivationProductionPrecheckPayload,
  type ConnectorActivationStagingBindingIdentity,
  type ConnectorActivationStagingCandidateBindingIdentity,
  type ConnectorActivationStagingPrecheckPayload,
  type SignedConnectorActivationEvidence,
  type VerifiedConnectorActivationPostActivationHostCanary,
  type VerifiedConnectorActivationPreCutoverHostCanary,
} from "./connector-activation-evidence.js";
import {
  connectorStagingActivationAuthorityContract,
} from "./connector-staging-activation-contract.js";
import { UNIVERSAL_OWNER_SCOPES, UNIVERSAL_TOOL_NAMES } from "./contracts.js";
import type { ManagementAuthorizationKey } from "./management-authorization.js";

const NOW_MS = 1_700_000_000_000;
const KEY: ManagementAuthorizationKey = Object.freeze({
  keyId: "management-evidence-test",
  secret: Uint8Array.from({ length: 32 }, (_value, index) => index + 1),
  path: "/private/test-management.key",
});
const OWNER_PRINCIPAL = rawDigest("owner-principal");
const MANAGEMENT_CORRELATION_ID = "cutover-correlation-11111111";
const STAGING_ROUTE_DIGEST = digest("staging-route");
const PRODUCTION_ENVIRONMENT_DIGEST = digest("production-environment");
const PRODUCTION_ROUTE_DIGEST = digest("production-route");
const OAUTH_RESOURCE = "https://devspace.example.test/mcp";

const tuple: ConnectorActivationTuple = {
  canonicalName: "myDevSpace",
  candidateBindingId: "production-candidate-binding",
  clientId: "production-client",
  installationEpoch: 2,
  schemaGeneration: digest("schema"),
  authorityContractGeneration: digest("authority"),
  redirectUrisDigest: digest("redirects"),
  buildDigest: digest("build"),
};
const candidateIdentity: ConnectorActivationImmutableCandidateIdentity = {
  runtimeIdentityDigest: digest("runtime"),
  buildDigest: tuple.buildDigest,
  schemaGeneration: tuple.schemaGeneration,
  authorityContractGeneration: tuple.authorityContractGeneration,
  buildCapabilityManifestDigest: digest("build-capability"),
  generatedSchemaDigest: digest("generated-schema"),
  packageSha256: digest("package"),
};
const stagingCandidateBinding: ConnectorActivationStagingCandidateBindingIdentity = {
  environmentIdentityDigest: digest("staging-environment"),
  canonicalName: tuple.canonicalName,
  clientId: "isolated-staging-client",
  bindingId: "isolated-staging-binding",
  installationEpoch: 1,
  state: "ACTIVATION_PREPARED",
};
const stagingBinding: ConnectorActivationStagingBindingIdentity = {
  ...stagingCandidateBinding,
  state: "ACTIVE",
};
const binding: ConnectorActivationEvidenceBinding = {
  principalKeyFingerprint: OWNER_PRINCIPAL,
  receiptId: "connector-activation-11111111-1111-4111-8111-111111111111",
  canonicalName: tuple.canonicalName,
  tupleDigest: connectorActivationTupleDigest(tuple),
  activePreimageDigest: digest("preimage"),
  finalizationPlanDigest: digest("plan"),
};

test("old opaque Fresh Host API and unsigned hardcoded PRE stage are absent", () => {
  const source = readFileSync(new URL("./connector-activation-evidence.ts", import.meta.url), "utf8");
  for (const forbidden of [
    "FRESH_CHATGPT_HOST",
    "ConnectorActivationFreshHostPayload",
    "VerifiedConnectorActivationFreshHostEvidence",
    "signConnectorActivationFreshHostEvidence",
    "verifyConnectorActivationFreshHostEvidence",
    'stage: "PRE_ACTIVATION"',
  ]) {
    assert.equal(source.includes(forbidden), false, `old opaque evidence residue: ${forbidden}`);
  }
});

test("staging bootstrap is a domain-separated actual-Host R0 precheck, not production PRE", () => {
  const payload = stagingPrecheckPayload();
  const signed = signConnectorActivationStagingPrecheck(payload, KEY, NOW_MS);
  assert.equal(signed.kind, "STAGING_ACTIVATION_PRECHECK");
  assert.equal(signed.schemaVersion, 2);
  const verified = verifyConnectorActivationStagingPrecheck(
    signed,
    KEY,
    {
      principalKeyFingerprint: OWNER_PRINCIPAL,
      managementNonce: payload.managementNonce,
      managementCorrelationId: payload.managementCorrelationId,
      candidateIdentity,
      stagingRouteIdentityDigest: STAGING_ROUTE_DIGEST,
      stagingCandidateBinding,
    },
    NOW_MS,
  );
  assertVerifiedConnectorActivationStagingPrecheck(verified);
  assert.throws(
    () => assertVerifiedConnectorActivationPreCutoverHostCanary(verified),
    /PRE_CUTOVER_HOST_CANARY is not verified/u,
  );

  const wrongDomain = {
    ...signed,
    kind: "PRE_CUTOVER_HOST_CANARY" as const,
  } as unknown as SignedConnectorActivationEvidence<ConnectorActivationPreCutoverHostCanaryPayload>;
  assert.throws(
    () => verifyConnectorActivationPreCutoverHostCanary(
      wrongDomain,
      KEY,
      preExpected(preCutoverPayload()),
      NOW_MS,
    ),
    /signature verification failed/u,
  );
});

test("PRE_CUTOVER_HOST_CANARY proves ACTIVE staging A-close-B mutation and foreign-client zero", () => {
  const payload = preCutoverPayload();
  const verified = verifiedPre(payload);
  assert.equal(verified.stage, "PRE_CUTOVER_HOST_CANARY");
  assert.equal(verified.stagingBinding.state, "ACTIVE");
  assert.equal(verified.mutation.providerDispatchCount, 1);
  assert.equal(verified.foreignClientIsolation.providerDispatchCount, 0);
  assert.equal(verified.stagingActiveTuple.candidateBindingId, stagingBinding.bindingId);
  assert.equal(verified.stagingTokenFamilyBindingId, stagingBinding.bindingId);
  assert.ok(verified.stagingActivatedAtMs < verified.mutation.sessionAAuthorizedAtMs);
  assert.equal(verified.stagingActivationReceipt.status, "ACTIVATED");
  assert.deepEqual(verified.stagingActivationAuthorityReceipt, verified.stagingActivationReceipt.activationAuthority);
  assert.deepEqual(verified.discoveredToolNames, UNIVERSAL_TOOL_NAMES);
  assert.ok(verified.mutation.sessionAAuthorizedAtMs < verified.mutation.sessionAClosedAtMs);
  assert.ok(verified.mutation.sessionAClosedAtMs < verified.mutation.sessionBMutationAtMs);
  assertVerifiedConnectorActivationPreCutoverHostCanary(verified);
  assert.throws(
    () => assertVerifiedConnectorActivationPreCutoverHostCanary(
      JSON.parse(JSON.stringify(verified)) as VerifiedConnectorActivationPreCutoverHostCanary,
    ),
    /not verified signed evidence/u,
  );
  assert.throws(
    () => {
      (verified.mutation as { operation: string }).operation = "forged";
    },
    TypeError,
    "verified nested provenance must be immutable",
  );

  const persisted = verifyPersistedConnectorActivationPreCutoverHostCanary(
    signConnectorActivationPreCutoverHostCanary(payload, KEY, NOW_MS),
    KEY,
    persistedPreExpected(payload),
    NOW_MS,
  );
  assertVerifiedConnectorActivationPreCutoverHostCanary(persisted);
  assert.equal(persisted.stagingActivationReceiptDigest, verified.stagingActivationReceiptDigest);
  assert.throws(
    () => verifyPersistedConnectorActivationPreCutoverHostCanary(
      signConnectorActivationPreCutoverHostCanary(payload, KEY, NOW_MS),
      KEY,
      persistedPreExpected(payload),
      payload.expiresAtMs,
    ),
    /not currently valid/u,
  );
});

test("PRE rejects embedded staging activation authority plan, action, and resource drift", () => {
  const base = preCutoverPayload();
  for (const [field, value] of [
    ["finalizationPlanDigest", digest("wrong-staging-finalization-plan")],
    ["actionFingerprint", rawDigest("wrong-staging-action")],
    ["resourceKeySha256", rawDigest("wrong-staging-resource")],
  ] as const) {
    const payload = withMutatedStagingAuthority(base, field, value);
    const signed = signConnectorActivationPreCutoverHostCanary(payload, KEY, NOW_MS);
    const expectedReadback = {
      receipt: payload.stagingActivationReceipt,
      authorityReceipt: payload.stagingActivationAuthorityReceipt,
    };
    assert.throws(
      () => verifyConnectorActivationPreCutoverHostCanary(
        signed,
        KEY,
        preExpected(payload, verifiedStagingPrecheck(), expectedReadback),
        NOW_MS,
      ),
      /canonical staging activation authority|finalizationPlanDigest|actionFingerprint|resourceKeySha256/u,
      `live PRE verifier must reject canonical staging authority ${field} drift`,
    );
    assert.throws(
      () => verifyPersistedConnectorActivationPreCutoverHostCanary(
        signed,
        KEY,
        persistedPreExpected(payload),
        NOW_MS,
      ),
      /canonical staging activation authority|finalizationPlanDigest|actionFingerprint|resourceKeySha256/u,
      `persisted PRE verifier must reject canonical staging authority ${field} drift`,
    );
  }
});

test("PRE rejects synthetic or incomplete dispatch, readback, cleanup, isolation, and provider tools", () => {
  const base = preCutoverPayload();
  const invalid: unknown[] = [
    { ...base, mutation: { ...base.mutation, providerDispatchCount: 0 } },
    { ...base, mutation: without(base.mutation, "postReadbackDigest") },
    { ...base, mutation: { ...base.mutation, cleanupPerformed: false } },
    { ...base, foreignClientIsolation: { ...base.foreignClientIsolation, providerDispatchCount: 1 } },
    { ...base, mutation: { ...base.mutation, tool: "github" } },
    { ...base, discoveredToolNames: [...UNIVERSAL_TOOL_NAMES, "github"] },
    {
      ...base,
      stagingActivationReceipt: { ...base.stagingActivationReceipt, unexpected: true },
    },
  ];
  for (const payload of invalid) {
    assert.throws(
      () => signConnectorActivationPreCutoverHostCanary(
        payload as ConnectorActivationPreCutoverHostCanaryPayload,
        KEY,
        NOW_MS,
      ),
    );
  }
});

test("PRE cannot relabel an unactivated production or staging candidate as ACTIVE", () => {
  const base = preCutoverPayload();
  assert.throws(
    () => signConnectorActivationPreCutoverHostCanary({
      ...base,
      stagingBinding: {
        ...base.stagingBinding,
        clientId: tuple.clientId,
        bindingId: tuple.candidateBindingId,
        state: "ACTIVATION_PREPARED",
      } as never,
    }, KEY, NOW_MS),
    /must be ACTIVE/u,
  );

  const wrongBootstrapLink = signConnectorActivationPreCutoverHostCanary({
    ...base,
    stagingActivationPrecheckDigest: digest("unrelated-staging-bootstrap"),
  }, KEY, NOW_MS);
  assert.throws(
    () => verifyConnectorActivationPreCutoverHostCanary(
      wrongBootstrapLink,
      KEY,
      preExpected(base),
      NOW_MS,
    ),
    /does not match its trusted management binding/u,
  );

  const wrongBootstrapIdentity = signConnectorActivationPreCutoverHostCanary({
    ...base,
    candidateIdentity: { ...base.candidateIdentity, packageSha256: digest("other-package") },
  }, KEY, NOW_MS);
  assert.throws(
    () => verifyConnectorActivationPreCutoverHostCanary(
      wrongBootstrapIdentity,
      KEY,
      preExpected(base),
      NOW_MS,
    ),
    /does not match its trusted management binding/u,
  );

  const stagingActivation = stagingActivatedOAuthReadback();
  const differentActivation = stagingActivatedOAuthReadback({
    receiptId: "connector-activation-99999999-9999-4999-8999-999999999999",
  });
  assert.throws(
    () => verifyConnectorActivationPreCutoverHostCanary(
      signConnectorActivationPreCutoverHostCanary(base, KEY, NOW_MS),
      KEY,
      {
        ...preExpected(base, undefined, differentActivation),
      },
      NOW_MS,
    ),
    /staging activation readback/u,
    "PRE must reject a different otherwise-valid staging activation receipt",
  );
  assert.throws(
    () => signConnectorActivationPreCutoverHostCanary({
      ...base,
      stagingActivatedAtMs: base.mutation.sessionAAuthorizedAtMs,
    }, KEY, NOW_MS),
    /readback|strictly after staging activation/u,
    "PRE session A cannot precede the exact staging activation",
  );
  assert.throws(
    () => signConnectorActivationPreCutoverHostCanary({
      ...base,
      stagingActivationReceipt: {
        ...base.stagingActivationReceipt,
        status: "PREPARED",
      },
    }, KEY, NOW_MS),
    /not ACTIVATED/u,
    "PRE must never embed an unactivated staging candidate receipt",
  );
  assert.equal(
    base.stagingActivationReceiptDigest,
    connectorActivationReceiptDigest(stagingActivation.receipt),
  );
});

test("production precheck binds exact tuple/resource/scopes and preserves staging-production separation", () => {
  const pre = verifiedPre();
  const precheck = verifiedPrecheck(pre);
  assert.equal(precheck.preCutoverHostCanaryDigest, pre.signedPayloadDigest);
  assert.equal(precheck.stagingProductionBindingRelation, "DISTINCT_STAGING_BINDING");
  assert.deepEqual(precheck.oauthScopes, UNIVERSAL_OWNER_SCOPES);
  assert.equal(precheck.oauthResource, OAUTH_RESOURCE);
  assertVerifiedConnectorActivationProductionPrecheck(precheck);
  assert.notEqual(precheck.stagingRouteIdentityDigest, precheck.productionRouteIdentityDigest);
  assert.notEqual(precheck.stagingBinding.environmentIdentityDigest, precheck.productionEnvironmentIdentityDigest);
});

test("production precheck rejects build/schema/authority drift and staging identity conflation", () => {
  const pre = verifiedPre();
  const base = productionPrecheckPayload(pre);
  for (const candidateDrift of [
    { buildDigest: digest("wrong-build") },
    { schemaGeneration: digest("wrong-schema") },
    { authorityContractGeneration: digest("wrong-authority") },
  ]) {
    assert.throws(
      () => signConnectorActivationProductionPrecheck({
        ...base,
        candidateIdentity: { ...base.candidateIdentity, ...candidateDrift },
      }, KEY, NOW_MS),
      /identity drifted/u,
    );
  }
  assert.throws(
    () => signConnectorActivationProductionPrecheck({
      ...base,
      productionEnvironmentIdentityDigest: base.stagingBinding.environmentIdentityDigest,
    }, KEY, NOW_MS),
    /environment identities must remain distinct/u,
  );
  assert.throws(
    () => signConnectorActivationProductionPrecheck({
      ...base,
      stagingBinding: {
        ...base.stagingBinding,
        clientId: tuple.clientId,
        bindingId: tuple.candidateBindingId,
      },
      stagingProductionBindingRelation: "DISTINCT_STAGING_BINDING",
    }, KEY, NOW_MS),
    /relation is not truthful/u,
  );
  assert.throws(
    () => signConnectorActivationProductionPrecheck({
      ...base,
      stagingProductionBindingRelation: "SAME" as never,
    }, KEY, NOW_MS),
    /relation is invalid/u,
  );

  const wrongLink = signConnectorActivationProductionPrecheck({
    ...base,
    preCutoverHostCanaryDigest: digest("wrong-pre-link"),
  }, KEY, NOW_MS);
  assert.throws(
    () => verifyConnectorActivationProductionPrecheck(
      wrongLink,
      KEY,
      productionExpected(pre),
      NOW_MS,
    ),
    /does not match the verified PRE/u,
  );
});

test("owner approval is cooperative and binds both signed staged receipts plus exact activation plan", () => {
  const pre = verifiedPre();
  const precheck = verifiedPrecheck(pre);
  const payload = ownerApprovalPayload(pre, precheck.signedPayloadDigest);
  const signed = signConnectorActivationOwnerApproval(payload, KEY, NOW_MS);
  const verified = verifyConnectorActivationOwnerApproval(signed, KEY, ownerExpected(payload), NOW_MS);
  assert.equal(verified.assurance, "cooperative");
  assert.equal(verified.preCutoverHostCanaryDigest, pre.signedPayloadDigest);
  assert.equal(verified.productionActivationPrecheckDigest, precheck.signedPayloadDigest);
  assertVerifiedConnectorActivationOwnerApproval(verified);

  assert.throws(
    () => verifyConnectorActivationOwnerApproval(
      signed,
      KEY,
      { ...ownerExpected(payload), preCutoverHostCanaryDigest: digest("other-pre") },
      NOW_MS,
    ),
    /does not bind both staged evidence/u,
  );
  assert.throws(
    () => verifyConnectorActivationOwnerApproval(
      signed,
      KEY,
      { ...ownerExpected(payload), productionActivationPrecheckDigest: digest("other-precheck") },
      NOW_MS,
    ),
    /does not bind both staged evidence/u,
  );
});

test("POST canary exact-binds activated OAuth, new token family, old DRAINING, and fresh A/B provenance", () => {
  const pre = verifiedPre();
  const precheck = verifiedPrecheck(pre);
  const activation = activatedOAuthReadback();
  const payload = postPayload(precheck.signedPayloadDigest, activation);
  const signed = signConnectorActivationPostActivationHostCanary(payload, KEY, NOW_MS);
  const verified = verifyConnectorActivationPostActivationHostCanary(
    signed,
    KEY,
    postExpected(precheck.signedPayloadDigest, activation),
    NOW_MS,
  );
  assert.equal(verified.stage, "POST_ACTIVATION_HOST_CANARY");
  assert.equal(verified.newActiveBindingState, "ACTIVE");
  assert.equal(verified.tokenFamilyBindingId, tuple.candidateBindingId);
  assert.equal(verified.previousBindingState, "DRAINING");
  assert.ok(verified.observedAtMs > verified.activatedAtMs);
  assertVerifiedConnectorActivationPostActivationHostCanary(verified);
  assert.throws(
    () => assertVerifiedConnectorActivationPreCutoverHostCanary(verified),
    /PRE_CUTOVER_HOST_CANARY is not verified/u,
    "POST evidence brand must never satisfy the finalizer PRE slot",
  );
  assert.throws(
    () => assertVerifiedConnectorActivationPostActivationHostCanary(
      JSON.parse(JSON.stringify(verified)) as VerifiedConnectorActivationPostActivationHostCanary,
    ),
    /not verified signed evidence/u,
  );
});

test("POST rejects old token-family binding, non-fresh time, new-ACTIVE drift, and OAuth proof drift", () => {
  const pre = verifiedPre();
  const precheck = verifiedPrecheck(pre);
  const activation = activatedOAuthReadback();
  const base = postPayload(precheck.signedPayloadDigest, activation);
  assert.throws(
    () => signConnectorActivationPostActivationHostCanary({
      ...base,
      tokenFamilyBindingId: base.previousActiveBindingId!,
    }, KEY, NOW_MS),
    /token family is not bound to the new ACTIVE/u,
  );
  assert.throws(
    () => signConnectorActivationPostActivationHostCanary({
      ...base,
      observedAtMs: base.activatedAtMs,
    }, KEY, base.activatedAtMs),
    /strictly after activation/u,
  );
  const tupleDrift = { ...base, newActiveTuple: { ...base.newActiveTuple, clientId: "other-client" } };
  const signedTupleDrift = signConnectorActivationPostActivationHostCanary(tupleDrift, KEY, NOW_MS);
  assert.throws(
    () => verifyConnectorActivationPostActivationHostCanary(
      signedTupleDrift,
      KEY,
      postExpected(precheck.signedPayloadDigest, activation),
      NOW_MS,
    ),
    /does not match exact activated OAuth/u,
  );
  const proofDrift = signConnectorActivationPostActivationHostCanary({
    ...base,
    activationProofDigest: digest("wrong-proof"),
  }, KEY, NOW_MS);
  assert.throws(
    () => verifyConnectorActivationPostActivationHostCanary(
      proofDrift,
      KEY,
      postExpected(precheck.signedPayloadDigest, activation),
      NOW_MS,
    ),
    /does not match exact activated OAuth/u,
  );
});

test("evidence rejects wrong keys, expiry, extra fields, and noncanonical signatures", () => {
  const pre = verifiedPre();
  const precheck = verifiedPrecheck(pre);
  const payload = ownerApprovalPayload(pre, precheck.signedPayloadDigest);
  const signed = signConnectorActivationOwnerApproval(payload, KEY, NOW_MS);
  const otherKey: ManagementAuthorizationKey = {
    keyId: KEY.keyId,
    secret: Uint8Array.from({ length: 32 }, (_value, index) => 255 - index),
    path: "/private/other.key",
  };
  assert.throws(
    () => verifyConnectorActivationOwnerApproval(signed, otherKey, ownerExpected(payload), NOW_MS),
    /signature verification failed/u,
  );
  assert.throws(
    () => verifyConnectorActivationOwnerApproval(
      signed,
      KEY,
      ownerExpected(payload),
      payload.expiresAtMs,
    ),
    /not currently valid/u,
  );
  assert.throws(
    () => signConnectorActivationOwnerApproval({ ...payload, unexpected: true } as never, KEY, NOW_MS),
    /shape is invalid/u,
  );
  const noncanonical = structuredClone(signed);
  noncanonical.signature = sameBytesNoncanonicalBase64Url(signed.signature);
  assert.throws(
    () => verifyConnectorActivationOwnerApproval(noncanonical, KEY, ownerExpected(payload), NOW_MS),
    /signature verification failed/u,
  );
});

test("evidence signing uses locale-independent code-unit canonical JSON", () => {
  const pre = verifiedPre();
  const precheck = verifiedPrecheck(pre);
  const payload = ownerApprovalPayload(pre, precheck.signedPayloadDigest);
  const signed = signConnectorActivationOwnerApproval(payload, KEY, NOW_MS);
  const canonical = codeUnitStableJson({
    schemaVersion: signed.schemaVersion,
    kind: signed.kind,
    keyId: signed.keyId,
    payload: signed.payload,
  });
  assert.equal(signed.payloadDigest, `sha256:${createHash("sha256").update(canonical).digest("hex")}`);
  assert.equal(
    signed.signature,
    createHmac("sha256", KEY.secret)
      .update(`devspace.connector-activation-evidence.v2/${signed.kind}\0`)
      .update(canonical)
      .digest("base64url"),
  );
});

function stagingPrecheckPayload(): ConnectorActivationStagingPrecheckPayload {
  return {
    stage: "STAGING_ACTIVATION_PRECHECK",
    stagingActivationPrecheckId: "staging-precheck-11111111",
    managementNonce: "staging-management-nonce-11111111",
    managementCorrelationId: MANAGEMENT_CORRELATION_ID,
    principalKeyFingerprint: OWNER_PRINCIPAL,
    hostProvider: "chatgpt",
    actualHost: true,
    candidateIdentity,
    stagingRouteIdentityDigest: STAGING_ROUTE_DIGEST,
    stagingCandidateBinding,
    discoveredToolNames: UNIVERSAL_TOOL_NAMES,
    toolDiscoveryEvidenceDigest: digest("staging-tool-discovery"),
    r0Canary: {
      tool: "target",
      operation: "list",
      argumentsDigest: digest("staging-r0-arguments"),
      resourceDigest: digest("staging-r0-resource"),
      providerDispatchCount: 1,
      readbackDigest: digest("staging-r0-readback"),
    },
    observedAtMs: NOW_MS - 5_000,
    expiresAtMs: NOW_MS + 60_000,
  };
}

function preCutoverPayload(
  stagingPrecheck = verifiedStagingPrecheck(),
): ConnectorActivationPreCutoverHostCanaryPayload {
  const stagingActivation = stagingActivatedOAuthReadback({}, stagingPrecheck);
  return {
    stage: "PRE_CUTOVER_HOST_CANARY",
    preCutoverHostCanaryId: "pre-cutover-host-11111111",
    managementNonce: "pre-cutover-management-nonce-11111111",
    managementCorrelationId: MANAGEMENT_CORRELATION_ID,
    principalKeyFingerprint: OWNER_PRINCIPAL,
    hostProvider: "chatgpt",
    actualHost: true,
    candidateIdentity,
    stagingRouteIdentityDigest: STAGING_ROUTE_DIGEST,
    stagingBinding,
    stagingActivationPrecheckDigest: stagingPrecheck.signedPayloadDigest,
    stagingActivationReceiptId: stagingActivation.receipt.receiptId,
    stagingActivationReceiptDigest: connectorActivationReceiptDigest(stagingActivation.receipt),
    stagingActivationProofDigest: stagingActivation.authorityReceipt.proofDigest,
    stagingActivationAuthorityReceiptDigest:
      connectorActivationAuthorityReceiptDigest(stagingActivation.authorityReceipt),
    stagingActivationReceipt: stagingActivation.receipt,
    stagingActivationAuthorityReceipt: stagingActivation.authorityReceipt,
    stagingActivatedAtMs: Date.parse(stagingActivation.receipt.activatedAt!),
    stagingActiveTuple: stagingActivation.receipt.tuple,
    stagingTokenFamilyIdDigest: digest("staging-token-family"),
    stagingTokenFamilyBindingId: stagingBinding.bindingId,
    discoveredToolNames: UNIVERSAL_TOOL_NAMES,
    toolDiscoveryEvidenceDigest: digest("pre-tool-discovery"),
    mutation: mutationEvidence("pre", NOW_MS - 4_000),
    foreignClientIsolation: foreignIsolation("pre"),
    observedAtMs: NOW_MS - 1_000,
    expiresAtMs: NOW_MS + 60_000,
  };
}

function mutationEvidence(label: string, startMs: number): ConnectorActivationCanaryMutationEvidence {
  return {
    tool: "context",
    operation: "create",
    argumentsDigest: digest(`${label}-mutation-arguments`),
    resourceDigest: digest(`${label}-mutation-resource`),
    sessionAIdDigest: digest(`${label}-session-a`),
    sessionAAuthorizationEvidenceDigest: digest(`${label}-session-a-authorization`),
    sessionAAuthorizedAtMs: startMs,
    sessionACloseEvidenceDigest: digest(`${label}-session-a-close`),
    sessionAClosedAtMs: startMs + 1,
    sessionBIdDigest: digest(`${label}-session-b`),
    sessionBMutationEvidenceDigest: digest(`${label}-session-b-mutation`),
    sessionBMutationAtMs: startMs + 2,
    actionFingerprint: rawDigest(`${label}-action`),
    resourceKeySha256: rawDigest(`${label}-resource-key`),
    authorityId: "authority_11111111-1111-4111-8111-111111111111",
    actionClaimId: "authority_claim_22222222-2222-4222-8222-222222222222",
    fencingToken: 1,
    authorityReceiptDigest: digest(`${label}-authority-receipt`),
    providerDispatchCount: 1,
    postReadbackDigest: digest(`${label}-post-readback`),
    cleanupPerformed: true,
    cleanupEvidenceDigest: digest(`${label}-cleanup`),
  };
}

function foreignIsolation(label: string): ConnectorActivationForeignClientIsolationEvidence {
  return {
    clientId: `foreign-client-${label}`,
    principalKeyFingerprint: rawDigest(`foreign-principal-${label}`),
    errorCode: "AUTHORITY_PRINCIPAL_MISMATCH",
    providerDispatchCount: 0,
    evidenceDigest: digest(`${label}-foreign-isolation`),
  };
}

function verifiedPre(
  payload = preCutoverPayload(),
): VerifiedConnectorActivationPreCutoverHostCanary {
  const stagingPrecheck = verifiedStagingPrecheck();
  const signed = signConnectorActivationPreCutoverHostCanary(payload, KEY, NOW_MS);
  return verifyConnectorActivationPreCutoverHostCanary(
    signed,
    KEY,
    preExpected(payload, stagingPrecheck),
    NOW_MS,
  );
}

function preExpected(
  payload: ConnectorActivationPreCutoverHostCanaryPayload,
  stagingActivationPrecheck = verifiedStagingPrecheck(),
  stagingActivation = stagingActivatedOAuthReadback(),
) {
  return {
    principalKeyFingerprint: payload.principalKeyFingerprint,
    managementNonce: payload.managementNonce,
    managementCorrelationId: payload.managementCorrelationId,
    candidateIdentity: payload.candidateIdentity,
    stagingRouteIdentityDigest: payload.stagingRouteIdentityDigest,
    stagingBinding: payload.stagingBinding,
    stagingActivationPrecheck,
    stagingActivationReceipt: stagingActivation.receipt,
    stagingActivationAuthorityReceipt: stagingActivation.authorityReceipt,
    stagingTokenFamilyIdDigest: digest("staging-token-family"),
    stagingTokenFamilyBindingId: stagingBinding.bindingId,
  };
}

function persistedPreExpected(
  payload: ConnectorActivationPreCutoverHostCanaryPayload,
  stagingActivationPrecheck = verifiedStagingPrecheck(),
) {
  return {
    principalKeyFingerprint: payload.principalKeyFingerprint,
    managementNonce: payload.managementNonce,
    managementCorrelationId: payload.managementCorrelationId,
    candidateIdentity: payload.candidateIdentity,
    stagingRouteIdentityDigest: payload.stagingRouteIdentityDigest,
    stagingBinding: payload.stagingBinding,
    stagingActivationPrecheck,
  };
}

function verifiedStagingPrecheck() {
  const payload = stagingPrecheckPayload();
  const signed = signConnectorActivationStagingPrecheck(payload, KEY, NOW_MS);
  return verifyConnectorActivationStagingPrecheck(signed, KEY, {
    principalKeyFingerprint: payload.principalKeyFingerprint,
    managementNonce: payload.managementNonce,
    managementCorrelationId: payload.managementCorrelationId,
    candidateIdentity: payload.candidateIdentity,
    stagingRouteIdentityDigest: payload.stagingRouteIdentityDigest,
    stagingCandidateBinding: payload.stagingCandidateBinding,
  }, NOW_MS);
}

function productionPrecheckPayload(
  pre: VerifiedConnectorActivationPreCutoverHostCanary,
): ConnectorActivationProductionPrecheckPayload {
  return {
    ...binding,
    stage: "PRODUCTION_ACTIVATION_PRECHECK",
    productionActivationPrecheckId: "production-precheck-11111111",
    managementCorrelationId: MANAGEMENT_CORRELATION_ID,
    tuple,
    oauthResource: OAUTH_RESOURCE,
    oauthScopes: UNIVERSAL_OWNER_SCOPES,
    candidateIdentity,
    preCutoverHostCanaryDigest: pre.signedPayloadDigest,
    stagingBinding,
    stagingRouteIdentityDigest: STAGING_ROUTE_DIGEST,
    productionEnvironmentIdentityDigest: PRODUCTION_ENVIRONMENT_DIGEST,
    productionRouteIdentityDigest: PRODUCTION_ROUTE_DIGEST,
    stagingProductionBindingRelation: "DISTINCT_STAGING_BINDING",
    observedAtMs: NOW_MS - 500,
    expiresAtMs: NOW_MS + 60_000,
  };
}

function verifiedPrecheck(pre: VerifiedConnectorActivationPreCutoverHostCanary) {
  const payload = productionPrecheckPayload(pre);
  const signed = signConnectorActivationProductionPrecheck(payload, KEY, NOW_MS);
  return verifyConnectorActivationProductionPrecheck(signed, KEY, productionExpected(pre), NOW_MS);
}

function productionExpected(pre: VerifiedConnectorActivationPreCutoverHostCanary) {
  return {
    ...binding,
    tuple,
    preCutoverHostCanary: pre,
    oauthResource: OAUTH_RESOURCE,
    productionEnvironmentIdentityDigest: PRODUCTION_ENVIRONMENT_DIGEST,
    productionRouteIdentityDigest: PRODUCTION_ROUTE_DIGEST,
  };
}

function ownerApprovalPayload(
  pre: VerifiedConnectorActivationPreCutoverHostCanary,
  productionActivationPrecheckDigest: string,
): ConnectorActivationOwnerApprovalPayload {
  return {
    ...binding,
    preCutoverHostCanaryDigest: pre.signedPayloadDigest,
    productionActivationPrecheckDigest,
    approvalId: "owner-approval-11111111",
    authorityText: "Activate this exact production connector tuple once after verified staging.",
    evidenceDigest: digest("owner-management-evidence"),
    approvedAtMs: NOW_MS - 100,
    expiresAtMs: NOW_MS + 60_000,
  };
}

function ownerExpected(payload: ConnectorActivationOwnerApprovalPayload) {
  return {
    principalKeyFingerprint: payload.principalKeyFingerprint,
    receiptId: payload.receiptId,
    canonicalName: payload.canonicalName,
    tupleDigest: payload.tupleDigest,
    activePreimageDigest: payload.activePreimageDigest,
    finalizationPlanDigest: payload.finalizationPlanDigest,
    preCutoverHostCanaryDigest: payload.preCutoverHostCanaryDigest,
    productionActivationPrecheckDigest: payload.productionActivationPrecheckDigest,
  };
}

function activatedOAuthReadback(): {
  receipt: ConnectorActivationReceipt;
  authorityReceipt: ConnectorActivationAuthorityReceipt;
} {
  const activatedAt = new Date(NOW_MS - 5_000).toISOString();
  const proof: Omit<ConnectorActivationAuthorityReceipt, "proofDigest" | "consumedAt"> = {
    schemaVersion: 1,
    authorityId: "authority_33333333-3333-4333-8333-333333333333",
    actionClaimId: "authority_claim_44444444-4444-4444-8444-444444444444",
    actionFingerprint: rawDigest("activation-action"),
    resourceKeySha256: rawDigest("activation-resource"),
    fencingToken: 2,
    principalKeyFingerprint: OWNER_PRINCIPAL,
    risk: "R3",
    claimState: "DISPATCHED",
    approvalAssurance: "cooperative",
    receiptId: binding.receiptId,
    tupleDigest: binding.tupleDigest,
    activePreimageDigest: binding.activePreimageDigest,
    finalizationPlanDigest: binding.finalizationPlanDigest,
    canonicalName: binding.canonicalName,
    evidenceDigest: digest("finalization-evidence"),
    claimedAtMs: NOW_MS - 5_100,
    dispatchedAtMs: NOW_MS - 5_050,
  };
  const authorityReceipt: ConnectorActivationAuthorityReceipt = {
    ...proof,
    proofDigest: digestJson(proof),
    consumedAt: activatedAt,
  };
  const receipt: ConnectorActivationReceipt = {
    receiptId: binding.receiptId,
    tuple,
    tupleDigest: binding.tupleDigest,
    previousActiveBindingId: "prior-production-binding",
    preimageDigest: binding.activePreimageDigest,
    activationAuthority: authorityReceipt,
    ownerAuthorityId: authorityReceipt.authorityId,
    drainDeadlineAt: new Date(NOW_MS + 600_000).toISOString(),
    refreshAllowedDuringDrain: false,
    status: "ACTIVATED",
    preparedAt: new Date(NOW_MS - 10_000).toISOString(),
    activatedAt,
  };
  return { receipt, authorityReceipt };
}

function stagingActivatedOAuthReadback(
  overrides: Partial<ConnectorActivationReceipt> = {},
  stagingPrecheck = verifiedStagingPrecheck(),
): {
  receipt: ConnectorActivationReceipt;
  authorityReceipt: ConnectorActivationAuthorityReceipt;
} {
  const stagingTuple: ConnectorActivationTuple = {
    canonicalName: stagingBinding.canonicalName,
    candidateBindingId: stagingBinding.bindingId,
    clientId: stagingBinding.clientId,
    installationEpoch: stagingBinding.installationEpoch,
    schemaGeneration: candidateIdentity.schemaGeneration,
    authorityContractGeneration: candidateIdentity.authorityContractGeneration,
    redirectUrisDigest: digest("staging-redirects"),
    buildDigest: candidateIdentity.buildDigest,
  };
  const receiptId = overrides.receiptId
    ?? "connector-activation-88888888-8888-4888-8888-888888888888";
  const tupleDigest = connectorActivationTupleDigest(stagingTuple);
  const preimageDigest = digest("staging-preimage");
  const activatedAt = new Date(NOW_MS - 4_500).toISOString();
  const receiptBase: ConnectorActivationReceipt = {
    receiptId,
    tuple: stagingTuple,
    tupleDigest,
    preimageDigest,
    drainDeadlineAt: new Date(NOW_MS + 600_000).toISOString(),
    refreshAllowedDuringDrain: false,
    status: "ACTIVATED",
    preparedAt: new Date(NOW_MS - 10_000).toISOString(),
    activatedAt,
    ...overrides,
  };
  const contract = connectorStagingActivationAuthorityContract(receiptBase, stagingPrecheck);
  const proof: Omit<ConnectorActivationAuthorityReceipt, "proofDigest" | "consumedAt"> = {
    schemaVersion: 1,
    authorityId: "authority_55555555-5555-4555-8555-555555555555",
    actionClaimId: "authority_claim_66666666-6666-4666-8666-666666666666",
    actionFingerprint: contract.actionFingerprint,
    resourceKeySha256: contract.resourceKeySha256,
    fencingToken: 1,
    principalKeyFingerprint: OWNER_PRINCIPAL,
    risk: "R3",
    claimState: "DISPATCHED",
    approvalAssurance: "cooperative",
    receiptId: contract.binding.receiptId,
    tupleDigest: contract.binding.tupleDigest,
    activePreimageDigest: contract.binding.activePreimageDigest,
    finalizationPlanDigest: contract.binding.finalizationPlanDigest,
    canonicalName: contract.binding.canonicalName,
    evidenceDigest: digest("staging-finalization-evidence"),
    claimedAtMs: NOW_MS - 4_700,
    dispatchedAtMs: NOW_MS - 4_600,
  };
  const authorityReceipt: ConnectorActivationAuthorityReceipt = {
    ...proof,
    proofDigest: digestJson(proof),
    consumedAt: activatedAt,
  };
  const receipt: ConnectorActivationReceipt = {
    ...receiptBase,
    activationAuthority: authorityReceipt,
    ownerAuthorityId: authorityReceipt.authorityId,
  };
  return { receipt, authorityReceipt };
}

function postPayload(
  precheckDigest: string,
  activation: ReturnType<typeof activatedOAuthReadback>,
): ConnectorActivationPostActivationHostCanaryPayload {
  const activatedAtMs = Date.parse(activation.receipt.activatedAt!);
  return {
    stage: "POST_ACTIVATION_HOST_CANARY",
    postActivationHostCanaryId: "post-activation-host-11111111",
    managementNonce: "post-management-nonce-11111111",
    managementCorrelationId: MANAGEMENT_CORRELATION_ID,
    principalKeyFingerprint: OWNER_PRINCIPAL,
    hostProvider: "chatgpt",
    actualHost: true,
    precheckDigest,
    activationReceiptId: activation.receipt.receiptId,
    activationReceiptDigest: connectorActivationReceiptDigest(activation.receipt),
    activationProofDigest: activation.authorityReceipt.proofDigest,
    activationAuthorityReceiptDigest: connectorActivationAuthorityReceiptDigest(activation.authorityReceipt),
    activatedAtMs,
    newActiveTuple: tuple,
    newActiveBindingState: "ACTIVE",
    tokenFamilyIdDigest: digest("new-token-family"),
    tokenFamilyBindingId: tuple.candidateBindingId,
    previousActiveBindingId: activation.receipt.previousActiveBindingId!,
    previousBindingState: "DRAINING",
    productionIdentity: candidateIdentity,
    productionEnvironmentIdentityDigest: PRODUCTION_ENVIRONMENT_DIGEST,
    productionRouteIdentityDigest: PRODUCTION_ROUTE_DIGEST,
    discoveredToolNames: UNIVERSAL_TOOL_NAMES,
    toolDiscoveryEvidenceDigest: digest("post-tool-discovery"),
    mutation: mutationEvidence("post", activatedAtMs + 100),
    foreignClientIsolation: foreignIsolation("post"),
    observedAtMs: activatedAtMs + 1_000,
    expiresAtMs: NOW_MS + 60_000,
  };
}

function postExpected(
  precheckDigest: string,
  activation: ReturnType<typeof activatedOAuthReadback>,
) {
  return {
    principalKeyFingerprint: OWNER_PRINCIPAL,
    managementNonce: "post-management-nonce-11111111",
    managementCorrelationId: MANAGEMENT_CORRELATION_ID,
    productionActivationPrecheckDigest: precheckDigest,
    activationReceipt: activation.receipt,
    activationAuthorityReceipt: activation.authorityReceipt,
    newActiveBindingState: "ACTIVE" as const,
    tokenFamilyIdDigest: digest("new-token-family"),
    tokenFamilyBindingId: tuple.candidateBindingId,
    previousBindingState: "DRAINING" as const,
    productionIdentity: candidateIdentity,
    productionEnvironmentIdentityDigest: PRODUCTION_ENVIRONMENT_DIGEST,
    productionRouteIdentityDigest: PRODUCTION_ROUTE_DIGEST,
  };
}

function withMutatedStagingAuthority<K extends "finalizationPlanDigest" | "actionFingerprint" | "resourceKeySha256">(
  input: ConnectorActivationPreCutoverHostCanaryPayload,
  field: K,
  value: ConnectorActivationAuthorityReceipt[K],
): ConnectorActivationPreCutoverHostCanaryPayload {
  const proofRecord = {
    ...input.stagingActivationAuthorityReceipt,
    [field]: value,
  } as Record<string, unknown>;
  delete proofRecord.proofDigest;
  delete proofRecord.consumedAt;
  const authorityReceipt: ConnectorActivationAuthorityReceipt = {
    ...input.stagingActivationAuthorityReceipt,
    [field]: value,
    proofDigest: digestJson(proofRecord),
  };
  const receipt: ConnectorActivationReceipt = {
    ...input.stagingActivationReceipt,
    activationAuthority: authorityReceipt,
    ownerAuthorityId: authorityReceipt.authorityId,
  };
  return {
    ...input,
    stagingActivationReceipt: receipt,
    stagingActivationAuthorityReceipt: authorityReceipt,
    stagingActivationReceiptDigest: connectorActivationReceiptDigest(receipt),
    stagingActivationProofDigest: authorityReceipt.proofDigest,
    stagingActivationAuthorityReceiptDigest:
      connectorActivationAuthorityReceiptDigest(authorityReceipt),
  };
}

function without<T extends object, K extends keyof T>(value: T, key: K): Omit<T, K> {
  const clone = { ...value };
  delete clone[key];
  return clone;
}

function digest(value: string): string {
  return `sha256:${rawDigest(value)}`;
}

function digestJson(value: unknown): string {
  return `sha256:${createHash("sha256").update(stableJson(value)).digest("hex")}`;
}

function stableJson(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(stableJson).join(",")}]`;
  if (value && typeof value === "object") {
    const record = value as Record<string, unknown>;
    return `{${Object.keys(record).sort().map(
      (key) => `${JSON.stringify(key)}:${stableJson(record[key])}`,
    ).join(",")}}`;
  }
  return JSON.stringify(value) ?? "null";
}

function rawDigest(value: string): string {
  return createHash("sha256").update(value).digest("hex");
}

function sameBytesNoncanonicalBase64Url(value: string): string {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
  const canonicalIndex = alphabet.indexOf(value.at(-1) ?? "");
  assert.notEqual(canonicalIndex, -1);
  const prefix = value.slice(0, -1);
  for (let offset = 1; offset < 4; offset += 1) {
    const candidate = `${prefix}${alphabet[(canonicalIndex + offset) % alphabet.length]}`;
    if (candidate !== value
      && Buffer.from(candidate, "base64url").equals(Buffer.from(value, "base64url"))) {
      return candidate;
    }
  }
  throw new Error("Unable to construct a noncanonical base64url alias.");
}

function codeUnitStableJson(value: unknown): string {
  return JSON.stringify(codeUnitCanonical(value));
}

function codeUnitCanonical(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(codeUnitCanonical);
  if (!value || typeof value !== "object") return value;
  return Object.fromEntries(
    Object.entries(value as Record<string, unknown>)
      .sort(([left], [right]) => (left < right ? -1 : left > right ? 1 : 0))
      .map(([key, item]) => [key, codeUnitCanonical(item)]),
  );
}
