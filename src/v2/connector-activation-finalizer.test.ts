import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import {
  SqliteOAuthClientsStore,
  SqliteOAuthStore,
  connectorActivationTupleDigest,
  type ConnectorActivationAuthorityProof,
  type ConnectorActivationAuthorityReceipt,
  type ConnectorActivationReceipt,
  type ConnectorActivationTuple,
} from "../oauth-store.js";
import {
  OperationAuthorityRegistry,
  type RecoveredConnectorActivationPassInput,
} from "./authority.js";
import {
  signConnectorActivationOwnerApproval,
  signConnectorActivationPreCutoverHostCanary,
  signConnectorActivationProductionPrecheck,
  signConnectorActivationStagingPrecheck,
  connectorActivationAuthorityReceiptDigest,
  connectorActivationReceiptDigest,
  verifyConnectorActivationOwnerApproval,
  verifyConnectorActivationPreCutoverHostCanary,
  verifyConnectorActivationProductionPrecheck,
  verifyConnectorActivationStagingPrecheck,
  type ConnectorActivationCanaryMutationEvidence,
  type ConnectorActivationForeignClientIsolationEvidence,
  type ConnectorActivationImmutableCandidateIdentity,
  type ConnectorActivationOwnerApprovalPayload,
  type ConnectorActivationPreCutoverHostCanaryPayload,
  type ConnectorActivationProductionPrecheckPayload,
  type ConnectorActivationStagingBindingIdentity,
  type ConnectorActivationStagingPrecheckPayload,
  type VerifiedConnectorActivationOwnerApproval,
  type VerifiedConnectorActivationPreCutoverHostCanary,
  type VerifiedConnectorActivationProductionPrecheck,
  type VerifiedConnectorActivationStagingPrecheck,
} from "./connector-activation-evidence.js";
import {
  ConnectorActivationFinalizer,
  ConnectorActivationUnknownError,
  connectorActivationFinalizationPlanDigest,
  type ConnectorActivationFinalizationInput,
  type ConnectorActivationRecoveryHandle,
  type ConnectorActivationRecoveryIntent,
  type ConnectorActivationRecoveryJournal,
} from "./connector-activation-finalizer.js";
import { connectorStagingActivationAuthorityContract } from "./connector-staging-activation-contract.js";
import { UNIVERSAL_OWNER_SCOPES, UNIVERSAL_TOOL_NAMES } from "./contracts.js";
import type { ManagementAuthorizationKey } from "./management-authorization.js";

const FIXED_NOW_MS = 1_787_100_000_000;
const REDIRECT_URI = "https://chatgpt.com/connector_platform_oauth_redirect";
const OWNER_PRINCIPAL = rawDigest("stable-finalizer-owner");
const MANAGEMENT_CORRELATION_ID = "finalizer-cutover-correlation";
const STAGING_ROUTE_IDENTITY_DIGEST = digest("staging-route-identity");
const PRODUCTION_ENVIRONMENT_IDENTITY_DIGEST = digest("production-environment-identity");
const PRODUCTION_ROUTE_IDENTITY_DIGEST = digest("production-route-identity");
const OAUTH_RESOURCE = "https://devspace.example.test/mcp";
const MANAGEMENT_KEY: ManagementAuthorizationKey = Object.freeze({
  keyId: "management-finalizer-test",
  secret: Uint8Array.from({ length: 32 }, (_value, index) => index + 1),
  path: "/private/finalizer-test-management.key",
});

class CountingActivationStore {
  activationCalls = 0;

  constructor(readonly delegate: SqliteOAuthStore) {}

  getActivationReceipt(receiptId: string): ConnectorActivationReceipt | undefined {
    return this.delegate.getActivationReceipt(receiptId);
  }

  getActivationAuthorityReceipt(receiptId: string): ConnectorActivationAuthorityReceipt | undefined {
    return this.delegate.getActivationAuthorityReceipt(receiptId);
  }

  activatePreparedConnector(
    receiptId: string,
    tuple: ConnectorActivationTuple,
    proof: ConnectorActivationAuthorityProof,
  ): ConnectorActivationReceipt {
    this.activationCalls += 1;
    return this.delegate.activatePreparedConnector(receiptId, tuple, proof);
  }
}

class ThrowingActivationStore extends CountingActivationStore {
  override activatePreparedConnector(
    _receiptId: string,
    _tuple: ConnectorActivationTuple,
    _proof: ConnectorActivationAuthorityProof,
  ): ConnectorActivationReceipt {
    this.activationCalls += 1;
    throw new Error("injected OAuth CAS transport fault");
  }
}

class ActivationReadbackOverrideStore {
  constructor(
    readonly delegate: CountingActivationStore,
    readonly overrideAuthorityReceipt: (
      receipt: ConnectorActivationAuthorityReceipt | undefined,
    ) => ConnectorActivationAuthorityReceipt | undefined,
  ) {}

  getActivationReceipt(receiptId: string): ConnectorActivationReceipt | undefined {
    return this.delegate.getActivationReceipt(receiptId);
  }

  getActivationAuthorityReceipt(receiptId: string): ConnectorActivationAuthorityReceipt | undefined {
    return this.overrideAuthorityReceipt(this.delegate.getActivationAuthorityReceipt(receiptId));
  }

  activatePreparedConnector(
    receiptId: string,
    tuple: ConnectorActivationTuple,
    proof: ConnectorActivationAuthorityProof,
  ): ConnectorActivationReceipt {
    return this.delegate.activatePreparedConnector(receiptId, tuple, proof);
  }
}

class CommitThenThrowActivationStore extends ActivationReadbackOverrideStore {
  override activatePreparedConnector(
    receiptId: string,
    tuple: ConnectorActivationTuple,
    proof: ConnectorActivationAuthorityProof,
  ): ConnectorActivationReceipt {
    this.delegate.activatePreparedConnector(receiptId, tuple, proof);
    throw new Error("simulated process loss after committed OAuth CAS");
  }
}

class RecordingRecoveryJournal implements ConnectorActivationRecoveryJournal {
  readonly intents: ConnectorActivationRecoveryIntent[] = [];
  readonly records: ConnectorActivationRecoveryHandle[] = [];
  private readonly intentByApproval = new Map<string, ConnectorActivationRecoveryIntent>();
  private readonly latestByApproval = new Map<string, ConnectorActivationRecoveryHandle>();

  constructor(
    private readonly failOn?: "INTENT_RESERVED" | ConnectorActivationRecoveryHandle["dispatchState"],
    private readonly afterPersist?: (
      state: "INTENT_RESERVED" | ConnectorActivationRecoveryHandle["dispatchState"],
    ) => void,
    private readonly throwAfterPersist?:
      | "INTENT_RESERVED"
      | ConnectorActivationRecoveryHandle["dispatchState"],
  ) {}

  reserve(intent: Readonly<ConnectorActivationRecoveryIntent>): void {
    if (this.failOn === "INTENT_RESERVED") throw new Error("injected INTENT_RESERVED recovery journal fault");
    const copy = JSON.parse(JSON.stringify(intent)) as ConnectorActivationRecoveryIntent;
    const key = recoveryJournalKey(copy);
    const existing = this.intentByApproval.get(key);
    if (existing) {
      throw new Error(
        JSON.stringify(existing) === JSON.stringify(copy)
          ? "connector activation approval already has an unresolved reserved intent"
          : "connector activation approval already has a different reserved intent",
      );
    }
    this.intents.push(copy);
    this.intentByApproval.set(key, copy);
    this.afterPersist?.("INTENT_RESERVED");
    if (this.throwAfterPersist === "INTENT_RESERVED") {
      throw new Error("simulated process loss after durable INTENT_RESERVED write");
    }
  }

  record(handle: Readonly<ConnectorActivationRecoveryHandle>): void {
    if (handle.dispatchState === this.failOn) {
      throw new Error(`injected ${handle.dispatchState} recovery journal fault`);
    }
    const copy = JSON.parse(JSON.stringify(handle)) as ConnectorActivationRecoveryHandle;
    const key = recoveryJournalKey(copy);
    const intent = this.intentByApproval.get(key);
    if (!intent || !handleMatchesIntent(copy, intent)) {
      throw new Error("connector activation recovery handle does not match a reserved intent");
    }
    const existing = this.latestByApproval.get(key);
    if (existing) {
      if (JSON.stringify(existing) === JSON.stringify(copy)) return;
      const order = { NOT_CLAIMED: 0, CLAIMED: 1, DISPATCHED: 2 } as const;
      if (order[copy.dispatchState] <= order[existing.dispatchState]
        || existing.authorityId !== copy.authorityId
        || (existing.actionClaimId && existing.actionClaimId !== copy.actionClaimId)) {
        throw new Error("connector activation recovery state cannot regress or replace its claim");
      }
    }
    this.records.push(copy);
    this.latestByApproval.set(key, copy);
    this.afterPersist?.(copy.dispatchState);
    if (this.throwAfterPersist === copy.dispatchState) {
      throw new Error(`simulated process loss after durable ${copy.dispatchState} write`);
    }
  }

  latest(): ConnectorActivationRecoveryHandle {
    const latest = this.records.at(-1);
    assert.ok(latest, "recovery journal must contain a durable handle");
    return latest;
  }

  latestIntent(): ConnectorActivationRecoveryIntent {
    const latest = this.intents.at(-1);
    assert.ok(latest, "recovery journal must contain a durable reserved intent");
    return latest;
  }
}

class AuthorityRegistryProbe {
  readonly createdAuthorityIds: string[] = [];
  readonly recoveredPassInputs: RecoveredConnectorActivationPassInput[] = [];

  constructor(
    readonly delegate: OperationAuthorityRegistry,
    readonly options: {
      throwAfterCreate?: boolean;
      maskControllerPhase?: () => boolean;
    } = {},
  ) {}

  createConnectorActivationAuthority(
    ...args: Parameters<OperationAuthorityRegistry["createConnectorActivationAuthority"]>
  ): ReturnType<OperationAuthorityRegistry["createConnectorActivationAuthority"]> {
    const created = this.delegate.createConnectorActivationAuthority(...args);
    this.createdAuthorityIds.push(String(created.authorityId));
    if (this.options.throwAfterCreate) {
      throw new Error("simulated process loss after authority creation");
    }
    return created;
  }

  prepareDispatch(
    ...args: Parameters<OperationAuthorityRegistry["prepareDispatch"]>
  ): ReturnType<OperationAuthorityRegistry["prepareDispatch"]> {
    const controller = this.delegate.prepareDispatch(...args);
    if (!this.options.maskControllerPhase) return controller;
    const maskControllerPhase = this.options.maskControllerPhase;
    return new Proxy(controller, {
      get(target, property) {
        if (property === "phase" && maskControllerPhase()) return "READY";
        const value = Reflect.get(target, property, target) as unknown;
        return typeof value === "function" ? value.bind(target) : value;
      },
    });
  }

  status(
    ...args: Parameters<OperationAuthorityRegistry["status"]>
  ): ReturnType<OperationAuthorityRegistry["status"]> {
    return this.delegate.status(...args);
  }

  terminalizeRecoveredConnectorActivationClaimPass(
    input: RecoveredConnectorActivationPassInput,
  ): ReturnType<OperationAuthorityRegistry["terminalizeRecoveredConnectorActivationClaimPass"]> {
    this.recoveredPassInputs.push(structuredClone(input));
    return this.delegate.terminalizeRecoveredConnectorActivationClaimPass(input);
  }
}

interface Clock {
  value: number;
}

interface Fixture {
  root: string;
  clock: Clock;
  oauthStore: SqliteOAuthStore;
  activationStore: CountingActivationStore;
  authorityStorePath: string;
  authorityRegistry: OperationAuthorityRegistry;
  recoveryJournal: RecordingRecoveryJournal;
  prepared: ConnectorActivationReceipt;
  input: ConnectorActivationFinalizationInput;
}

test("production finalizer contains no crash hook or failure-injection surface", () => {
  const source = readFileSync(new URL("./connector-activation-finalizer.ts", import.meta.url), "utf8");
  for (const forbidden of [
    "ConnectorActivationCrashPoint",
    "ConnectorActivationInjectedCrashError",
    "ConnectorActivationFinalizerTestHooks",
    "testHooks",
    "CONNECTOR_ACTIVATION_INJECTED_CRASH",
    "VerifiedConnectorActivationFreshHostEvidence",
    "VerifiedConnectorActivationStagingPrecheck",
    "VerifiedConnectorActivationPostActivationHostCanary",
    "freshHostReceipt:",
  ]) {
    assert.equal(source.includes(forbidden), false, `production source contains forbidden residue: ${forbidden}`);
  }
});

test("exact owner/Host/tuple binding activates once and completes the live authority PASS", async (t) => {
  const fixture = await createFixture("pass");
  t.after(async () => cleanupFixture(fixture));
  const finalizer = new ConnectorActivationFinalizer({
    oauthStore: fixture.activationStore,
    authorityRegistry: fixture.authorityRegistry,
    recoveryJournal: fixture.recoveryJournal,
    now: () => fixture.clock.value,
  });

  const planDigest = connectorActivationFinalizationPlanDigest(fixture.prepared);
  assert.match(planDigest, /^sha256:[a-f0-9]{64}$/u);
  assert.notEqual(
    planDigest,
    connectorActivationFinalizationPlanDigest({
      ...fixture.prepared,
      refreshAllowedDuringDrain: !fixture.prepared.refreshAllowedDuringDrain,
    }),
    "the digest must bind the destructive drain policy",
  );

  const result = finalizer.finalize(fixture.input);
  assert.equal(result.state, "ACTIVATED_PENDING_POSTCHECK");
  assert.notEqual(result.state as string, "PASS");
  assert.equal(result.finalizationPlanDigest, planDigest);
  assert.equal(fixture.activationStore.activationCalls, 1);
  assert.equal(result.activationReceipt.status, "ACTIVATED");
  assert.equal(
    fixture.oauthStore.getActiveConnectorBinding("myDevSpace")?.bindingId,
    fixture.prepared.tuple.candidateBindingId,
  );
  assert.deepEqual(
    result.activationAuthorityReceipt,
    fixture.oauthStore.getActivationAuthorityReceipt(fixture.prepared.receiptId),
  );
  assert.equal(result.activationAuthorityReceipt.actionClaimId, result.recovery.actionClaimId);
  assert.equal(result.activationAuthorityReceipt.finalizationPlanDigest, planDigest);
  assert.equal(result.activationAuthorityReceipt.evidenceDigest, result.evidenceDigest);
  assert.equal(
    result.recovery.freshHostReceiptId,
    fixture.input.preCutoverHostCanary.preCutoverHostCanaryId,
    "the frozen journal compatibility field must locate the exact PRE canary receipt",
  );
  assert.equal(
    result.evidenceDigest,
    expectedFinalizerEvidenceDigest(fixture.prepared, fixture.input),
    "final evidence must bind the complete verified owner and Host provenance",
  );

  const authorityStatus = fixture.authorityRegistry.status(
    result.recovery.authorityId,
    OWNER_PRINCIPAL,
  ) as {
    actions: Array<{ risk: string; maximumUses: number; consumedUses: number }>;
    receipts: Array<{ actionClaimId: string; state: string; leaseState: string }>;
  };
  assert.deepEqual(authorityStatus.actions, [{
    id: `action_${result.recovery.actionFingerprint}`,
    tool: "context",
    operation: "connector_activation_finalize",
    resourceKeySha256: result.recovery.resourceKeySha256,
    risk: "R3",
    maximumUses: 1,
    consumedUses: 1,
  }]);
  assert.equal(authorityStatus.receipts[0]?.actionClaimId, result.recovery.actionClaimId);
  assert.equal(authorityStatus.receipts[0]?.state, "PASS");
  assert.equal(authorityStatus.receipts[0]?.leaseState, "RELEASED");

  assert.throws(
    () => finalizer.finalize(fixture.input),
    (error: unknown) => errorCode(error) === "PRECONDITION_FAILED",
    "an ACTIVATED receipt must not mint or consume another authority",
  );
  assert.equal(fixture.activationStore.activationCalls, 1, "replay must make no second OAuth call");

  assert.throws(
    () => finalizer.reconcile({
      ...fixture.input,
      recovery: { ...result.recovery, actionFingerprint: rawDigest("forged-action") },
    }),
    (error: unknown) => errorCode(error) === "PRECONDITION_FAILED",
    "a caller-shaped recovery handle cannot override the exact live-grant fingerprint",
  );
  const reconciled = finalizer.reconcile({ ...fixture.input, recovery: result.recovery });
  assert.equal(reconciled.state, "ACTIVATED_PENDING_POSTCHECK");
});

test("durable intent closes both pre-record crash windows and tombstones restart replay", async (t) => {
  for (const fault of ["INTENT_WRITE_THEN_THROW", "AUTHORITY_CREATE_THEN_THROW"] as const) {
    await t.test(fault, async (t) => {
      const fixture = await createFixture(`intent-${fault.toLowerCase()}`);
      let reopenedRegistry: OperationAuthorityRegistry | undefined;
      t.after(async () => {
        reopenedRegistry?.close();
        await cleanupFixture(fixture);
      });
      const crashJournal = fault === "INTENT_WRITE_THEN_THROW"
        ? new RecordingRecoveryJournal(undefined, undefined, "INTENT_RESERVED")
        : fixture.recoveryJournal;
      const probe = new AuthorityRegistryProbe(fixture.authorityRegistry, {
        throwAfterCreate: fault === "AUTHORITY_CREATE_THEN_THROW",
      });
      const crashing = new ConnectorActivationFinalizer({
        oauthStore: fixture.activationStore,
        authorityRegistry: probe,
        recoveryJournal: crashJournal,
        now: () => fixture.clock.value,
      });

      let faultError: unknown;
      try {
        crashing.finalize(fixture.input);
      } catch (error) {
        faultError = error;
      }
      assert.ok(faultError);
      assert.equal(crashJournal.intents.length, 1);
      assert.equal(crashJournal.records.length, 0);
      assert.equal(fixture.activationStore.activationCalls, 0);
      assert.equal(
        probe.createdAuthorityIds.length,
        fault === "INTENT_WRITE_THEN_THROW" ? 0 : 1,
      );

      fixture.authorityRegistry.close();
      fixture.clock.value += 1;
      reopenedRegistry = authorityRegistry(
        fixture.authorityStorePath,
        fixture.clock,
        `intent-reopened-${fault.toLowerCase()}`,
      );
      const retryProbe = new AuthorityRegistryProbe(reopenedRegistry);
      const retrying = new ConnectorActivationFinalizer({
        oauthStore: fixture.activationStore,
        authorityRegistry: retryProbe,
        recoveryJournal: crashJournal,
        now: () => fixture.clock.value,
      });
      assert.throws(
        () => retrying.finalize(fixture.input),
        (error: unknown) => errorCode(error) === "AUTHORITY_STATE_UNCERTAIN",
        "an unresolved intent-only crash must never mint another authority",
      );
      assert.equal(crashJournal.intents.length, 1);
      assert.equal(retryProbe.createdAuthorityIds.length, 0);
      if (fault === "AUTHORITY_CREATE_THEN_THROW") {
        const orphanStatus = reopenedRegistry.status(probe.createdAuthorityIds[0]!, OWNER_PRINCIPAL) as {
          actions: Array<{ consumedUses: number }>;
          receipts: unknown[];
        };
        assert.equal(orphanStatus.actions[0]?.consumedUses, 0);
        assert.equal(orphanStatus.receipts.length, 0, "orphan authority must remain unused/provider-zero");
      }
      assert.equal(fixture.activationStore.activationCalls, 0);
    });
  }
});

test("forged capabilities and principal, tuple, plan, or freshness drift fail before claim/OAuth", async (t) => {
  const fixture = await createFixture("negative");
  t.after(async () => cleanupFixture(fixture));
  const finalizer = new ConnectorActivationFinalizer({
    oauthStore: fixture.activationStore,
    authorityRegistry: fixture.authorityRegistry,
    recoveryJournal: fixture.recoveryJournal,
    now: () => fixture.clock.value,
  });
  const approval = fixture.input.ownerApproval;
  const pre = fixture.input.preCutoverHostCanary;
  const precheck = fixture.input.productionActivationPrecheck;
  const wrongPre = preCutoverHostCanary(
    fixture.prepared,
    fixture.clock.value,
    {},
    { buildDigest: digest("wrong-pre-build") },
  );
  const planDriftPrecheck = productionPrecheck(
    fixture.prepared,
    fixture.clock.value,
    pre,
    { finalizationPlanDigest: digest("wrong-plan") },
  );
  const expiredPre = preCutoverHostCanary(fixture.prepared, fixture.clock.value, {
    observedAtMs: fixture.clock.value - 5_000,
    expiresAtMs: fixture.clock.value - 1,
  });
  const olderStillValidPre = preCutoverHostCanary(fixture.prepared, fixture.clock.value, {
    observedAtMs: fixture.clock.value - 6_000,
  });
  const expiredPrecheck = productionPrecheck(
    fixture.prepared,
    fixture.clock.value,
    olderStillValidPre,
    { observedAtMs: fixture.clock.value - 5_000, expiresAtMs: fixture.clock.value - 1 },
  );

  const cases: Array<{ name: string; input: ConnectorActivationFinalizationInput }> = [
    {
      name: "JSON-forged approval",
      input: {
        ...fixture.input,
        ownerApproval: JSON.parse(JSON.stringify(approval)) as VerifiedConnectorActivationOwnerApproval,
      },
    },
    {
      name: "JSON-forged PRE canary",
      input: {
        ...fixture.input,
        preCutoverHostCanary: JSON.parse(JSON.stringify(pre)) as VerifiedConnectorActivationPreCutoverHostCanary,
      },
    },
    {
      name: "JSON-forged production precheck",
      input: {
        ...fixture.input,
        productionActivationPrecheck: JSON.parse(
          JSON.stringify(precheck),
        ) as VerifiedConnectorActivationProductionPrecheck,
      },
    },
    {
      name: "wrong authenticated owner",
      input: {
        ...fixture.input,
        authenticatedOwnerPrincipalKeyFingerprint: rawDigest("different-owner"),
      },
    },
    {
      name: "tuple drift",
      input: {
        ...fixture.input,
        tuple: { ...fixture.input.tuple, buildDigest: digest("tuple-drift") },
      },
    },
    {
      name: "owner staged-receipt binding drift",
      input: {
        ...fixture.input,
        ownerApproval: ownerApproval(
          fixture.prepared,
          fixture.clock.value,
          pre,
          precheck,
          { preCutoverHostCanaryDigest: digest("wrong-pre-link") },
        ),
      },
    },
    {
      name: "production plan drift",
      input: {
        ...fixture.input,
        productionActivationPrecheck: planDriftPrecheck,
        ownerApproval: ownerApproval(
          fixture.prepared,
          fixture.clock.value,
          pre,
          planDriftPrecheck,
        ),
      },
    },
    {
      name: "PRE immutable build drift",
      input: {
        ...fixture.input,
        preCutoverHostCanary: wrongPre,
        ownerApproval: ownerApproval(fixture.prepared, fixture.clock.value, wrongPre, precheck),
      },
    },
    {
      name: "expired approval",
      input: {
        ...fixture.input,
        ownerApproval: ownerApproval(
          fixture.prepared,
          fixture.clock.value,
          pre,
          precheck,
          { approvedAtMs: fixture.clock.value - 5_000, expiresAtMs: fixture.clock.value - 1 },
        ),
      },
    },
    {
      name: "owner approval predates its staged receipts",
      input: {
        ...fixture.input,
        ownerApproval: ownerApproval(
          fixture.prepared,
          fixture.clock.value,
          pre,
          precheck,
          { approvedAtMs: fixture.clock.value - 10, expiresAtMs: fixture.clock.value + 60_000 },
        ),
      },
    },
    {
      name: "expired PRE canary",
      input: {
        ...fixture.input,
        preCutoverHostCanary: expiredPre,
        ownerApproval: ownerApproval(fixture.prepared, fixture.clock.value, expiredPre, precheck),
      },
    },
    {
      name: "expired production precheck",
      input: {
        ...fixture.input,
        preCutoverHostCanary: olderStillValidPre,
        productionActivationPrecheck: expiredPrecheck,
        ownerApproval: ownerApproval(
          fixture.prepared,
          fixture.clock.value,
          olderStillValidPre,
          expiredPrecheck,
        ),
      },
    },
    {
      name: "POST-shaped evidence cannot substitute for PRE or create overall PASS",
      input: {
        ...fixture.input,
        preCutoverHostCanary: {
          ...pre,
          stage: "POST_ACTIVATION_HOST_CANARY",
        } as unknown as VerifiedConnectorActivationPreCutoverHostCanary,
      },
    },
  ];

  for (const entry of cases) {
    assert.throws(
      () => finalizer.finalize(entry.input),
      (error: unknown) => ["PRECONDITION_FAILED", "AUTHORITY_PRINCIPAL_MISMATCH"].includes(errorCode(error)),
      entry.name,
    );
  }
  assert.equal(fixture.activationStore.activationCalls, 0);
  assert.equal(fixture.oauthStore.getActivationReceipt(fixture.prepared.receiptId)?.status, "PREPARED");
  assert.equal(fixture.oauthStore.getActiveConnectorBinding("myDevSpace"), undefined);
});

test("evidence expiry during each durable journal write stops before the next boundary", async (t) => {
  for (const expiredAfter of [
    "INTENT_RESERVED",
    "NOT_CLAIMED",
    "CLAIMED",
    "DISPATCHED",
  ] as const) {
    await t.test(expiredAfter, async (t) => {
      const fixture = await createFixture(`journal-expiry-${expiredAfter.toLowerCase()}`);
      t.after(async () => cleanupFixture(fixture));
      const journal = new RecordingRecoveryJournal(undefined, (state) => {
        if (state === expiredAfter) fixture.clock.value += 30_001;
      });
      const probe = new AuthorityRegistryProbe(fixture.authorityRegistry);
      const finalizer = new ConnectorActivationFinalizer({
        oauthStore: fixture.activationStore,
        authorityRegistry: probe,
        recoveryJournal: journal,
        now: () => fixture.clock.value,
      });

      let error: unknown;
      try {
        finalizer.finalize(fixture.input);
      } catch (caught) {
        error = caught;
      }
      assert.ok(error);
      assert.equal(fixture.activationStore.activationCalls, 0);
      assert.equal(fixture.oauthStore.getActivationReceipt(fixture.prepared.receiptId)?.status, "PREPARED");
      assert.equal(probe.createdAuthorityIds.length, expiredAfter === "INTENT_RESERVED" ? 0 : 1);
      if (expiredAfter === "DISPATCHED") {
        assert.ok(error instanceof ConnectorActivationUnknownError);
      } else {
        assert.equal(errorCode(error), "PRECONDITION_FAILED");
      }
      if (probe.createdAuthorityIds.length === 1) {
        const status = fixture.authorityRegistry.status(probe.createdAuthorityIds[0]!, OWNER_PRINCIPAL) as {
          receipts: Array<{ state: string; leaseState: string }>;
        };
        if (expiredAfter === "NOT_CLAIMED") assert.equal(status.receipts.length, 0);
        if (expiredAfter === "CLAIMED") {
          assert.equal(status.receipts[0]?.state, "CANCELLED_NOT_DISPATCHED");
          assert.equal(status.receipts[0]?.leaseState, "RELEASED");
        }
        if (expiredAfter === "DISPATCHED") {
          assert.equal(status.receipts[0]?.state, "UNCERTAIN");
          assert.equal(status.receipts[0]?.leaseState, "RECOVERY_REQUIRED");
        }
      }
    });
  }
});

test("crash barriers recover pre-dispatch, freeze unknown DISPATCHED, and terminalize exact committed OAuth", async (t) => {
  for (const fault of [
    "NOT_CLAIMED_WRITE_THEN_THROW",
    "CLAIMED_WRITE_THEN_THROW",
    "DISPATCHED_WRITE_THEN_THROW",
    "OAUTH_COMMIT_THEN_THROW",
  ] as const) {
    await t.test(fault, async (t) => {
      const fixture = await createFixture(`crash-${fault.toLowerCase()}`);
      let recoveredRegistry: OperationAuthorityRegistry | undefined;
      t.after(async () => {
        recoveredRegistry?.close();
        await cleanupFixture(fixture);
      });
      const durableState = fault === "NOT_CLAIMED_WRITE_THEN_THROW"
        ? "NOT_CLAIMED" as const
        : fault === "CLAIMED_WRITE_THEN_THROW"
          ? "CLAIMED" as const
          : fault === "DISPATCHED_WRITE_THEN_THROW"
            ? "DISPATCHED" as const
            : undefined;
      const processLost = { value: false };
      const recoveryJournal = durableState
        ? new RecordingRecoveryJournal(
          undefined,
          (state) => {
            if (state === durableState) processLost.value = true;
          },
          durableState,
        )
        : fixture.recoveryJournal;
      const registryProbe = new AuthorityRegistryProbe(fixture.authorityRegistry, {
        maskControllerPhase: () => processLost.value,
      });
      const activationStore = fault === "OAUTH_COMMIT_THEN_THROW"
        ? new CommitThenThrowActivationStore(fixture.activationStore, (receipt) => receipt)
        : fixture.activationStore;
      const finalizer = new ConnectorActivationFinalizer({
        oauthStore: activationStore,
        authorityRegistry: registryProbe,
        recoveryJournal,
        now: () => fixture.clock.value,
      });

      let faultError: unknown;
      try {
        finalizer.finalize(fixture.input);
      } catch (error) {
        faultError = error;
      }
      assert.ok(faultError);
      assert.equal(
        fixture.activationStore.activationCalls,
        fault === "OAUTH_COMMIT_THEN_THROW" ? 1 : 0,
      );
      const expectedJournalStates = fault === "NOT_CLAIMED_WRITE_THEN_THROW"
        ? ["NOT_CLAIMED"]
        : fault === "CLAIMED_WRITE_THEN_THROW"
          ? ["NOT_CLAIMED", "CLAIMED"]
          : ["NOT_CLAIMED", "CLAIMED", "DISPATCHED"];
      assert.deepEqual(
        recoveryJournal.records.map((record) => record.dispatchState),
        expectedJournalStates,
        "every hard-crash point must have an already-durable recovery locator",
      );
      const durableRecovery = recoveryJournal.latest();

      fixture.authorityRegistry.close();
      fixture.clock.value += 51;
      recoveredRegistry = authorityRegistry(
        fixture.authorityStorePath,
        fixture.clock,
        `recovered-${fault.toLowerCase()}`,
      );
      let recoveredProbe = new AuthorityRegistryProbe(recoveredRegistry);
      const recoveredFinalizer = new ConnectorActivationFinalizer({
        oauthStore: fixture.activationStore,
        authorityRegistry: recoveredProbe,
        recoveryJournal,
        now: () => fixture.clock.value,
      });
      const reconciled = recoveredFinalizer.reconcile({
        ...fixture.input,
        recovery: durableRecovery,
      });

      if (fault === "NOT_CLAIMED_WRITE_THEN_THROW") {
        assert.deepEqual(
          { state: reconciled.state, authorityState: reconciled.authorityState },
          { state: "NOT_DISPATCHED", authorityState: "NOT_CLAIMED" },
        );
      } else if (fault === "CLAIMED_WRITE_THEN_THROW") {
        assert.deepEqual(
          { state: reconciled.state, authorityState: reconciled.authorityState },
          { state: "NOT_DISPATCHED", authorityState: "CANCELLED_NOT_DISPATCHED" },
        );
      } else if (fault === "DISPATCHED_WRITE_THEN_THROW") {
        assert.equal(reconciled.state, "UNKNOWN");
        if (reconciled.state !== "UNKNOWN") return;
        assert.equal(reconciled.retryAllowed, false);
        assert.equal(reconciled.oauthCommitted, false);
        assert.equal(reconciled.reason, "DISPATCHED_OUTCOME_NOT_PROVEN");
        assert.equal(reconciled.leaseState, "RECOVERY_REQUIRED");
        assert.equal(recoveredProbe.recoveredPassInputs.length, 0);

        const status = recoveredRegistry.status(
          durableRecovery.authorityId,
          OWNER_PRINCIPAL,
        ) as { receipts: Array<{ state: string; leaseState: string }> };
        assert.equal(status.receipts[0]?.state, "UNCERTAIN");
        assert.equal(status.receipts[0]?.leaseState, "RECOVERY_REQUIRED");

        assert.throws(
          () => recoveredFinalizer.finalize(fixture.input),
          (error: unknown) => ["RESOURCE_BUSY", "AUTHORITY_STATE_UNCERTAIN"].includes(errorCode(error)),
          "a DISPATCHED recovery path must never replay the OAuth CAS",
        );
        assert.equal(fixture.activationStore.activationCalls, 0);
      } else {
        assert.equal(reconciled.state, "ACTIVATED_PENDING_POSTCHECK");
        if (reconciled.state !== "ACTIVATED_PENDING_POSTCHECK") return;
        assert.equal(reconciled.oauthCommitted, true);
        assert.equal(reconciled.authorityState, "PASS");
        assert.equal(reconciled.recoveredAuthorityReceipt?.state, "PASS");
        assert.equal(reconciled.recoveredAuthorityReceipt?.leaseState, "RELEASED");
        assert.equal(reconciled.recoveredAuthorityReceipt?.recovered, true);
        assert.equal(recoveredProbe.recoveredPassInputs.length, 1);
        assert.equal(
          recoveredProbe.recoveredPassInputs[0]?.oauthProofDigest,
          reconciled.activationAuthorityReceipt.proofDigest,
        );
        const status = recoveredRegistry.status(
          durableRecovery.authorityId,
          OWNER_PRINCIPAL,
        ) as { receipts: Array<{ state: string; leaseState: string }> };
        assert.equal(status.receipts[0]?.state, "PASS");
        assert.equal(status.receipts[0]?.leaseState, "RELEASED");

        recoveredRegistry.close();
        fixture.clock.value += 1;
        recoveredRegistry = authorityRegistry(
          fixture.authorityStorePath,
          fixture.clock,
          `reopened-${fault.toLowerCase()}`,
        );
        recoveredProbe = new AuthorityRegistryProbe(recoveredRegistry);
        const reopenedFinalizer = new ConnectorActivationFinalizer({
          oauthStore: fixture.activationStore,
          authorityRegistry: recoveredProbe,
          recoveryJournal,
          now: () => fixture.clock.value,
        });
        const reopened = reopenedFinalizer.reconcile({
          ...fixture.input,
          recovery: durableRecovery,
        });
        assert.equal(reopened.state, "ACTIVATED_PENDING_POSTCHECK");
        assert.equal(recoveredProbe.recoveredPassInputs.length, 0, "durable PASS reopen is exact and idempotent");
        assert.throws(
          () => reopenedFinalizer.finalize(fixture.input),
          (error: unknown) => errorCode(error) === "PRECONDITION_FAILED",
          "committed OAuth activation must never replay",
        );
        assert.equal(fixture.activationStore.activationCalls, 1);
      }
    });
  }
});

test("recovered PASS seam is unreachable for wrong OAuth proof, principal, or fence", async (t) => {
  for (const mismatch of ["proof", "principal", "fence"] as const) {
    await t.test(mismatch, async (t) => {
      const fixture = await createFixture(`recovery-mismatch-${mismatch}`);
      let recoveredRegistry: OperationAuthorityRegistry | undefined;
      t.after(async () => {
        recoveredRegistry?.close();
        await cleanupFixture(fixture);
      });
      const commitThenThrow = new CommitThenThrowActivationStore(
        fixture.activationStore,
        (receipt) => receipt,
      );
      const crashing = new ConnectorActivationFinalizer({
        oauthStore: commitThenThrow,
        authorityRegistry: fixture.authorityRegistry,
        recoveryJournal: fixture.recoveryJournal,
        now: () => fixture.clock.value,
      });
      assert.throws(
        () => crashing.finalize(fixture.input),
        (error: unknown) => error instanceof ConnectorActivationUnknownError,
      );
      const durableRecovery = fixture.recoveryJournal.latest();
      fixture.authorityRegistry.close();
      fixture.clock.value += 51;
      recoveredRegistry = authorityRegistry(
        fixture.authorityStorePath,
        fixture.clock,
        `recovery-mismatch-${mismatch}`,
      );
      const probe = new AuthorityRegistryProbe(recoveredRegistry);
      const oauthStore = mismatch === "proof"
        ? new ActivationReadbackOverrideStore(fixture.activationStore, (receipt) => (
          receipt ? { ...receipt, proofDigest: digest("forged-oauth-proof") } : undefined
        ))
        : fixture.activationStore;
      const finalizer = new ConnectorActivationFinalizer({
        oauthStore,
        authorityRegistry: probe,
        recoveryJournal: fixture.recoveryJournal,
        now: () => fixture.clock.value,
      });
      const recovery = mismatch === "principal"
        ? { ...durableRecovery, principalKeyFingerprint: rawDigest("wrong-recovery-principal") }
        : mismatch === "fence"
          ? { ...durableRecovery, fencingToken: durableRecovery.fencingToken! + 1 }
          : durableRecovery;

      if (mismatch === "proof") {
        const reconciled = finalizer.reconcile({ ...fixture.input, recovery });
        assert.equal(reconciled.state, "UNKNOWN");
        if (reconciled.state === "UNKNOWN") {
          assert.equal(reconciled.reason, "OAUTH_ACTIVATION_RECEIPT_MISMATCH");
        }
      } else {
        assert.throws(
          () => finalizer.reconcile({ ...fixture.input, recovery }),
          (error: unknown) => errorCode(error) === "PRECONDITION_FAILED",
        );
      }
      assert.equal(probe.recoveredPassInputs.length, 0);
      const status = recoveredRegistry.status(durableRecovery.authorityId, OWNER_PRINCIPAL) as {
        receipts: Array<{ state: string; leaseState: string }>;
      };
      assert.equal(status.receipts[0]?.state, "UNCERTAIN");
      assert.equal(status.receipts[0]?.leaseState, "RECOVERY_REQUIRED");
      assert.equal(fixture.activationStore.activationCalls, 1);
    });
  }
});

test("ordinary OAuth error after the durable barrier seals UNKNOWN and leaves the receipt frozen", async (t) => {
  const fixture = await createFixture("post-dispatch-error", true);
  t.after(async () => cleanupFixture(fixture));
  const throwingStore = fixture.activationStore as ThrowingActivationStore;
  const finalizer = new ConnectorActivationFinalizer({
    oauthStore: throwingStore,
    authorityRegistry: fixture.authorityRegistry,
    recoveryJournal: fixture.recoveryJournal,
    now: () => fixture.clock.value,
  });

  let unknown: ConnectorActivationUnknownError | undefined;
  try {
    finalizer.finalize(fixture.input);
  } catch (error) {
    if (error instanceof ConnectorActivationUnknownError) unknown = error;
    else throw error;
  }
  assert.ok(unknown);
  assert.equal(throwingStore.activationCalls, 1);
  assert.equal(fixture.oauthStore.getActivationReceipt(fixture.prepared.receiptId)?.status, "PREPARED");
  assert.equal(fixture.oauthStore.getActivationAuthorityReceipt(fixture.prepared.receiptId), undefined);
  const status = fixture.authorityRegistry.status(
    unknown!.recovery.authorityId,
    OWNER_PRINCIPAL,
  ) as { receipts: Array<{ state: string; leaseState: string }> };
  assert.equal(status.receipts[0]?.state, "UNCERTAIN");
  assert.equal(status.receipts[0]?.leaseState, "RECOVERY_REQUIRED");

  const reconciled = finalizer.reconcile({ ...fixture.input, recovery: unknown!.recovery });
  assert.equal(reconciled.state, "UNKNOWN");
  if (reconciled.state === "UNKNOWN") {
    assert.equal(reconciled.reason, "DISPATCHED_OUTCOME_NOT_PROVEN");
    assert.equal(reconciled.leaseReconciled, false);
  }
  assert.throws(
    () => finalizer.finalize(fixture.input),
    (error: unknown) => ["RESOURCE_BUSY", "AUTHORITY_STATE_UNCERTAIN"].includes(errorCode(error)),
  );
  assert.equal(throwingStore.activationCalls, 1);
});

test("required journal failure stops before the next boundary and stale CLAIMED readback upgrades safely", async (t) => {
  for (const failedState of ["INTENT_RESERVED", "NOT_CLAIMED", "CLAIMED", "DISPATCHED"] as const) {
    await t.test(failedState, async (t) => {
      const fixture = await createFixture(`journal-fault-${failedState.toLowerCase()}`);
      t.after(async () => cleanupFixture(fixture));
      const journal = new RecordingRecoveryJournal(failedState);
      const probe = new AuthorityRegistryProbe(fixture.authorityRegistry);
      const finalizer = new ConnectorActivationFinalizer({
        oauthStore: fixture.activationStore,
        authorityRegistry: probe,
        recoveryJournal: journal,
        now: () => fixture.clock.value,
      });

      let error: unknown;
      try {
        finalizer.finalize(fixture.input);
      } catch (caught) {
        error = caught;
      }
      assert.ok(error);
      assert.equal(fixture.activationStore.activationCalls, 0, "journal failure must precede OAuth CAS");
      assert.equal(fixture.oauthStore.getActivationReceipt(fixture.prepared.receiptId)?.status, "PREPARED");

      if (failedState === "INTENT_RESERVED") {
        assert.equal(journal.intents.length, 0);
        assert.equal(journal.records.length, 0);
        assert.equal(probe.createdAuthorityIds.length, 0, "failed intent fsync must precede authority creation");
        return;
      }

      assert.equal(journal.intents.length, 1);
      if (failedState === "NOT_CLAIMED") {
        assert.equal(journal.records.length, 0);
        assert.equal(probe.createdAuthorityIds.length, 1);
        return;
      }

      const durable = journal.latest();
      const status = fixture.authorityRegistry.status(durable.authorityId, OWNER_PRINCIPAL) as {
        receipts: Array<{ state: string; leaseState: string }>;
      };
      if (failedState === "CLAIMED") {
        assert.equal(durable.dispatchState, "NOT_CLAIMED");
        assert.equal(status.receipts[0]?.state, "CANCELLED_NOT_DISPATCHED");
        assert.equal(status.receipts[0]?.leaseState, "RELEASED");
        const reconciled = finalizer.reconcile({ ...fixture.input, recovery: durable });
        assert.equal(reconciled.state, "NOT_DISPATCHED");
        if (reconciled.state === "NOT_DISPATCHED") {
          assert.equal(reconciled.authorityState, "CANCELLED_NOT_DISPATCHED");
          assert.equal(reconciled.recovery.dispatchState, "CLAIMED");
          assert.ok(reconciled.recovery.actionClaimId);
        }
        return;
      }

      assert.ok(error instanceof ConnectorActivationUnknownError);
      assert.equal(durable.dispatchState, "CLAIMED", "failed DISPATCHED fsync retains the prior durable locator");
      assert.equal(status.receipts[0]?.state, "UNCERTAIN");
      assert.equal(status.receipts[0]?.leaseState, "RECOVERY_REQUIRED");
      const reconciled = finalizer.reconcile({ ...fixture.input, recovery: durable });
      assert.equal(reconciled.state, "UNKNOWN");
      if (reconciled.state === "UNKNOWN") {
        assert.equal(reconciled.recovery.dispatchState, "DISPATCHED");
        assert.ok(reconciled.recovery.dispatchedAtMs);
        assert.equal(reconciled.reason, "DISPATCHED_OUTCOME_NOT_PROVEN");
      }
    });
  }
});

async function createFixture(label: string, throwing = false): Promise<Fixture> {
  const root = await mkdtemp(join(tmpdir(), `devspace-connector-finalizer-${label}-`));
  const clock = { value: FIXED_NOW_MS };
  const oauthStore = new SqliteOAuthStore(join(root, "oauth"));
  const client = new SqliteOAuthClientsStore(oauthStore, ["chatgpt.com"]).registerClient({
    redirect_uris: [REDIRECT_URI],
    client_name: `Finalizer ${label}`,
  });
  const input = {
    canonicalName: "myDevSpace",
    clientId: client.client_id,
    installationEpoch: 1,
    schemaGeneration: digest("schema"),
  };
  const binding = oauthStore.ensureCandidateConnectorBinding(input);
  const evidence = {
    authorityContractGeneration: digest("authority"),
    redirectUrisDigest: digest("redirect"),
    buildDigest: digest("build"),
  };
  oauthStore.markConnectorBindingVerified(binding.bindingId, evidence);
  const tuple: ConnectorActivationTuple = {
    ...input,
    candidateBindingId: binding.bindingId,
    ...evidence,
  };
  const prepared = oauthStore.prepareConnectorActivation(tuple, {
    drainDeadlineAt: new Date(clock.value + 10 * 60_000).toISOString(),
    refreshAllowedDuringDrain: false,
  });
  const authorityStorePath = join(root, "authority.sqlite");
  const authority = authorityRegistry(authorityStorePath, clock, `owner-${label}`);
  const activationStore = throwing
    ? new ThrowingActivationStore(oauthStore)
    : new CountingActivationStore(oauthStore);
  const recoveryJournal = new RecordingRecoveryJournal();
  const preCutoverHostCanary = preCutoverHostCanaryFor(prepared, clock.value);
  const activationPrecheck = productionPrecheck(
    prepared,
    clock.value,
    preCutoverHostCanary,
  );
  return {
    root,
    clock,
    oauthStore,
    activationStore,
    authorityStorePath,
    authorityRegistry: authority,
    recoveryJournal,
    prepared,
    input: {
      receiptId: prepared.receiptId,
      tuple,
      authenticatedOwnerPrincipalKeyFingerprint: OWNER_PRINCIPAL,
      ownerApproval: ownerApproval(
        prepared,
        clock.value,
        preCutoverHostCanary,
        activationPrecheck,
      ),
      preCutoverHostCanary,
      productionActivationPrecheck: activationPrecheck,
    },
  };
}

function authorityRegistry(
  storePath: string,
  clock: Clock,
  instanceId: string,
): OperationAuthorityRegistry {
  return new OperationAuthorityRegistry({
    storePath,
    instanceId,
    now: () => clock.value,
    resourceLeaseTtlMs: 50,
    resourceLeaseHeartbeatMs: 20,
    resourceLeaseRecoveryGraceMs: 0,
    leaseHeartbeatScheduler: () => () => {},
  });
}

function ownerApproval(
  prepared: ConnectorActivationReceipt,
  nowMs: number,
  preCutoverHostCanary: VerifiedConnectorActivationPreCutoverHostCanary,
  productionActivationPrecheck: VerifiedConnectorActivationProductionPrecheck,
  overrides: Partial<ConnectorActivationOwnerApprovalPayload> = {},
): VerifiedConnectorActivationOwnerApproval {
  const payload: ConnectorActivationOwnerApprovalPayload = {
    approvalId: `owner-approval-${prepared.receiptId}`,
    authorityText: "Activate this exact verified connector tuple and destructive drain plan.",
    principalKeyFingerprint: OWNER_PRINCIPAL,
    receiptId: prepared.receiptId,
    canonicalName: prepared.tuple.canonicalName,
    tupleDigest: prepared.tupleDigest,
    activePreimageDigest: prepared.preimageDigest,
    finalizationPlanDigest: connectorActivationFinalizationPlanDigest(prepared),
    preCutoverHostCanaryDigest: preCutoverHostCanary.signedPayloadDigest,
    productionActivationPrecheckDigest: productionActivationPrecheck.signedPayloadDigest,
    evidenceDigest: digest("owner-management-evidence"),
    approvedAtMs: nowMs - 1,
    expiresAtMs: nowMs + 60_000,
    ...overrides,
  };
  const signed = signConnectorActivationOwnerApproval(payload, MANAGEMENT_KEY, payload.approvedAtMs);
  return verifyConnectorActivationOwnerApproval(signed, MANAGEMENT_KEY, {
    ...evidenceBinding(payload),
    preCutoverHostCanaryDigest: payload.preCutoverHostCanaryDigest,
    productionActivationPrecheckDigest: payload.productionActivationPrecheckDigest,
  }, payload.approvedAtMs);
}

function preCutoverHostCanaryFor(
  prepared: ConnectorActivationReceipt,
  nowMs: number,
  overrides: Partial<ConnectorActivationPreCutoverHostCanaryPayload> = {},
  identityOverrides: Partial<ConnectorActivationImmutableCandidateIdentity> = {},
): VerifiedConnectorActivationPreCutoverHostCanary {
  const observedAtMs = overrides.observedAtMs ?? nowMs - 1;
  const candidateIdentity = immutableCandidateIdentity(prepared, identityOverrides);
  const stagingBinding = stagingBindingIdentity(prepared);
  const stagingPrecheck = stagingActivationPrecheck(
    prepared,
    observedAtMs - 5,
    candidateIdentity,
    stagingBinding,
  );
  const stagingActivation = stagingActivatedOAuthReadbackFor(
    prepared,
    candidateIdentity,
    stagingBinding,
    stagingPrecheck,
    observedAtMs - 4,
  );
  const payload: ConnectorActivationPreCutoverHostCanaryPayload = {
    stage: "PRE_CUTOVER_HOST_CANARY",
    preCutoverHostCanaryId: `pre-cutover-host-${prepared.receiptId}`,
    managementNonce: `pre-cutover-nonce-${prepared.receiptId}`,
    managementCorrelationId: MANAGEMENT_CORRELATION_ID,
    hostProvider: "chatgpt",
    actualHost: true,
    principalKeyFingerprint: OWNER_PRINCIPAL,
    candidateIdentity,
    stagingRouteIdentityDigest: STAGING_ROUTE_IDENTITY_DIGEST,
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
    stagingTokenFamilyIdDigest: digest("isolated-staging-token-family"),
    stagingTokenFamilyBindingId: stagingBinding.bindingId,
    discoveredToolNames: UNIVERSAL_TOOL_NAMES,
    toolDiscoveryEvidenceDigest: digest("pre-host-eight-tool-discovery"),
    mutation: canaryMutationEvidence("pre", observedAtMs - 3),
    foreignClientIsolation: foreignClientIsolationEvidence("pre"),
    observedAtMs,
    expiresAtMs: nowMs + 30_000,
    ...overrides,
  };
  const signed = signConnectorActivationPreCutoverHostCanary(
    payload,
    MANAGEMENT_KEY,
    payload.observedAtMs,
  );
  return verifyConnectorActivationPreCutoverHostCanary(
    signed,
    MANAGEMENT_KEY,
    {
      principalKeyFingerprint: payload.principalKeyFingerprint,
      managementNonce: payload.managementNonce,
      managementCorrelationId: payload.managementCorrelationId,
      candidateIdentity: payload.candidateIdentity,
      stagingRouteIdentityDigest: payload.stagingRouteIdentityDigest,
      stagingBinding: payload.stagingBinding,
      stagingActivationPrecheck: stagingPrecheck,
      stagingActivationReceipt: stagingActivation.receipt,
      stagingActivationAuthorityReceipt: stagingActivation.authorityReceipt,
      stagingTokenFamilyIdDigest: payload.stagingTokenFamilyIdDigest,
      stagingTokenFamilyBindingId: payload.stagingTokenFamilyBindingId,
    },
    payload.observedAtMs,
  );
}

const preCutoverHostCanary = preCutoverHostCanaryFor;

function stagingActivationPrecheck(
  prepared: ConnectorActivationReceipt,
  observedAtMs: number,
  candidateIdentity: ConnectorActivationImmutableCandidateIdentity,
  activeBinding: ConnectorActivationStagingBindingIdentity,
): VerifiedConnectorActivationStagingPrecheck {
  const payload: ConnectorActivationStagingPrecheckPayload = {
    stage: "STAGING_ACTIVATION_PRECHECK",
    stagingActivationPrecheckId: `staging-precheck-${prepared.receiptId}`,
    managementNonce: `staging-precheck-nonce-${prepared.receiptId}`,
    managementCorrelationId: MANAGEMENT_CORRELATION_ID,
    principalKeyFingerprint: OWNER_PRINCIPAL,
    hostProvider: "chatgpt",
    actualHost: true,
    candidateIdentity,
    stagingRouteIdentityDigest: STAGING_ROUTE_IDENTITY_DIGEST,
    stagingCandidateBinding: { ...activeBinding, state: "ACTIVATION_PREPARED" },
    discoveredToolNames: UNIVERSAL_TOOL_NAMES,
    toolDiscoveryEvidenceDigest: digest("staging-precheck-tool-discovery"),
    r0Canary: {
      tool: "target",
      operation: "list",
      argumentsDigest: digest("staging-precheck-r0-arguments"),
      resourceDigest: digest("staging-precheck-r0-resource"),
      providerDispatchCount: 1,
      readbackDigest: digest("staging-precheck-r0-readback"),
    },
    observedAtMs,
    expiresAtMs: observedAtMs + 30_000,
  };
  const signed = signConnectorActivationStagingPrecheck(payload, MANAGEMENT_KEY, observedAtMs);
  return verifyConnectorActivationStagingPrecheck(signed, MANAGEMENT_KEY, {
    principalKeyFingerprint: payload.principalKeyFingerprint,
    managementNonce: payload.managementNonce,
    managementCorrelationId: payload.managementCorrelationId,
    candidateIdentity: payload.candidateIdentity,
    stagingRouteIdentityDigest: payload.stagingRouteIdentityDigest,
    stagingCandidateBinding: payload.stagingCandidateBinding,
  }, observedAtMs);
}

function stagingActivatedOAuthReadbackFor(
  prepared: ConnectorActivationReceipt,
  candidateIdentity: ConnectorActivationImmutableCandidateIdentity,
  activeBinding: ConnectorActivationStagingBindingIdentity,
  stagingPrecheck: VerifiedConnectorActivationStagingPrecheck,
  activatedAtMs: number,
): {
  receipt: ConnectorActivationReceipt;
  authorityReceipt: ConnectorActivationAuthorityReceipt;
} {
  const tuple: ConnectorActivationTuple = {
    canonicalName: activeBinding.canonicalName,
    candidateBindingId: activeBinding.bindingId,
    clientId: activeBinding.clientId,
    installationEpoch: activeBinding.installationEpoch,
    schemaGeneration: candidateIdentity.schemaGeneration,
    authorityContractGeneration: candidateIdentity.authorityContractGeneration,
    redirectUrisDigest: digest("isolated-staging-redirects"),
    buildDigest: candidateIdentity.buildDigest,
  };
  const receiptId = "connector-activation-77777777-7777-4777-8777-777777777777";
  const tupleDigest = connectorActivationTupleDigest(tuple);
  const preimageDigest = digest(`isolated-staging-preimage-${prepared.tuple.canonicalName}`);
  const activatedAt = new Date(activatedAtMs).toISOString();
  const receipt: ConnectorActivationReceipt = {
    receiptId,
    tuple,
    tupleDigest,
    preimageDigest,
    drainDeadlineAt: new Date(activatedAtMs + 10 * 60_000).toISOString(),
    refreshAllowedDuringDrain: false,
    status: "ACTIVATED",
    preparedAt: new Date(activatedAtMs - 10).toISOString(),
    activatedAt,
  };
  const stagingAuthority = connectorStagingActivationAuthorityContract(receipt, stagingPrecheck);
  const proof: Omit<ConnectorActivationAuthorityReceipt, "proofDigest" | "consumedAt"> = {
    schemaVersion: 1,
    authorityId: "authority_77777777-7777-4777-8777-777777777777",
    actionClaimId: "authority_claim_88888888-8888-4888-8888-888888888888",
    actionFingerprint: stagingAuthority.actionFingerprint,
    resourceKeySha256: stagingAuthority.resourceKeySha256,
    fencingToken: 1,
    principalKeyFingerprint: OWNER_PRINCIPAL,
    risk: "R3",
    claimState: "DISPATCHED",
    approvalAssurance: "cooperative",
    receiptId,
    tupleDigest,
    activePreimageDigest: preimageDigest,
    finalizationPlanDigest: stagingAuthority.binding.finalizationPlanDigest,
    canonicalName: tuple.canonicalName,
    evidenceDigest: digest("isolated-staging-finalization-evidence"),
    claimedAtMs: activatedAtMs - 2,
    dispatchedAtMs: activatedAtMs - 1,
  };
  const authorityReceipt: ConnectorActivationAuthorityReceipt = {
    ...proof,
    proofDigest: digestJson(proof),
    consumedAt: activatedAt,
  };
  Object.assign(receipt, {
    activationAuthority: authorityReceipt,
    ownerAuthorityId: authorityReceipt.authorityId,
  });
  return { receipt, authorityReceipt };
}

function productionPrecheck(
  prepared: ConnectorActivationReceipt,
  nowMs: number,
  preCutoverHostCanary: VerifiedConnectorActivationPreCutoverHostCanary,
  overrides: Partial<ConnectorActivationProductionPrecheckPayload> = {},
): VerifiedConnectorActivationProductionPrecheck {
  const observedAtMs = overrides.observedAtMs ?? nowMs - 1;
  const payload: ConnectorActivationProductionPrecheckPayload = {
    ...evidenceBinding({
      principalKeyFingerprint: OWNER_PRINCIPAL,
      receiptId: prepared.receiptId,
      canonicalName: prepared.tuple.canonicalName,
      tupleDigest: prepared.tupleDigest,
      activePreimageDigest: prepared.preimageDigest,
      finalizationPlanDigest: connectorActivationFinalizationPlanDigest(prepared),
    }),
    stage: "PRODUCTION_ACTIVATION_PRECHECK",
    productionActivationPrecheckId: `production-precheck-${prepared.receiptId}`,
    managementCorrelationId: MANAGEMENT_CORRELATION_ID,
    tuple: prepared.tuple,
    oauthResource: OAUTH_RESOURCE,
    oauthScopes: UNIVERSAL_OWNER_SCOPES,
    candidateIdentity: immutableCandidateIdentity(prepared),
    preCutoverHostCanaryDigest: preCutoverHostCanary.signedPayloadDigest,
    stagingBinding: stagingBindingIdentity(prepared),
    stagingRouteIdentityDigest: STAGING_ROUTE_IDENTITY_DIGEST,
    productionEnvironmentIdentityDigest: PRODUCTION_ENVIRONMENT_IDENTITY_DIGEST,
    productionRouteIdentityDigest: PRODUCTION_ROUTE_IDENTITY_DIGEST,
    stagingProductionBindingRelation: "DISTINCT_STAGING_BINDING",
    observedAtMs,
    expiresAtMs: nowMs + 30_000,
    ...overrides,
  };
  const signed = signConnectorActivationProductionPrecheck(
    payload,
    MANAGEMENT_KEY,
    payload.observedAtMs,
  );
  return verifyConnectorActivationProductionPrecheck(signed, MANAGEMENT_KEY, {
    ...evidenceBinding(payload),
    tuple: payload.tuple,
    preCutoverHostCanary,
    oauthResource: payload.oauthResource,
    productionEnvironmentIdentityDigest: payload.productionEnvironmentIdentityDigest,
    productionRouteIdentityDigest: payload.productionRouteIdentityDigest,
  }, payload.observedAtMs);
}

function immutableCandidateIdentity(
  prepared: ConnectorActivationReceipt,
  overrides: Partial<ConnectorActivationImmutableCandidateIdentity> = {},
): ConnectorActivationImmutableCandidateIdentity {
  return {
    runtimeIdentityDigest: digest("candidate-runtime"),
    buildDigest: prepared.tuple.buildDigest,
    schemaGeneration: prepared.tuple.schemaGeneration,
    authorityContractGeneration: prepared.tuple.authorityContractGeneration,
    buildCapabilityManifestDigest: digest("candidate-build-capability"),
    generatedSchemaDigest: digest("candidate-generated-schema"),
    packageSha256: digest("candidate-package"),
    ...overrides,
  };
}

function stagingBindingIdentity(
  prepared: ConnectorActivationReceipt,
): ConnectorActivationStagingBindingIdentity {
  return {
    environmentIdentityDigest: digest("isolated-staging-environment"),
    canonicalName: prepared.tuple.canonicalName,
    clientId: "isolated-staging-client",
    bindingId: "isolated-staging-binding",
    installationEpoch: 1,
    state: "ACTIVE",
  };
}

function canaryMutationEvidence(
  label: string,
  startedAtMs: number,
): ConnectorActivationCanaryMutationEvidence {
  return {
    tool: "context",
    operation: "create",
    argumentsDigest: digest(`${label}-mutation-arguments`),
    resourceDigest: digest(`${label}-mutation-resource`),
    sessionAIdDigest: digest(`${label}-session-a`),
    sessionAAuthorizationEvidenceDigest: digest(`${label}-session-a-authorization`),
    sessionAAuthorizedAtMs: startedAtMs,
    sessionACloseEvidenceDigest: digest(`${label}-session-a-close`),
    sessionAClosedAtMs: startedAtMs + 1,
    sessionBIdDigest: digest(`${label}-session-b`),
    sessionBMutationEvidenceDigest: digest(`${label}-session-b-mutation`),
    sessionBMutationAtMs: startedAtMs + 2,
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

function foreignClientIsolationEvidence(
  label: string,
): ConnectorActivationForeignClientIsolationEvidence {
  return {
    clientId: `foreign-client-${label}`,
    principalKeyFingerprint: rawDigest(`foreign-principal-${label}`),
    errorCode: "AUTHORITY_PRINCIPAL_MISMATCH",
    providerDispatchCount: 0,
    evidenceDigest: digest(`${label}-foreign-isolation`),
  };
}

function evidenceBinding(input: {
  principalKeyFingerprint: string;
  receiptId: string;
  canonicalName: string;
  tupleDigest: string;
  activePreimageDigest: string;
  finalizationPlanDigest: string;
}) {
  return {
    principalKeyFingerprint: input.principalKeyFingerprint,
    receiptId: input.receiptId,
    canonicalName: input.canonicalName,
    tupleDigest: input.tupleDigest,
    activePreimageDigest: input.activePreimageDigest,
    finalizationPlanDigest: input.finalizationPlanDigest,
  };
}

function expectedFinalizerEvidenceDigest(
  prepared: ConnectorActivationReceipt,
  input: ConnectorActivationFinalizationInput,
): string {
  const approval = input.ownerApproval;
  return digestJson({
    schemaVersion: 2,
    operation: "context.connector_activation_finalize",
    binding: {
      receiptId: prepared.receiptId,
      tupleDigest: prepared.tupleDigest,
      activePreimageDigest: prepared.preimageDigest,
      finalizationPlanDigest: connectorActivationFinalizationPlanDigest(prepared),
      canonicalName: prepared.tuple.canonicalName,
    },
    ownerApproval: { ...approval },
    preCutoverHostCanary: { ...input.preCutoverHostCanary },
    productionActivationPrecheck: { ...input.productionActivationPrecheck },
  });
}

function recoveryJournalKey(input: {
  principalKeyFingerprint: string;
  approvalId: string;
  receiptId: string;
}): string {
  return `${input.principalKeyFingerprint}\0${input.approvalId}\0${input.receiptId}`;
}

function handleMatchesIntent(
  handle: ConnectorActivationRecoveryHandle,
  intent: ConnectorActivationRecoveryIntent,
): boolean {
  return handle.approvalId === intent.approvalId
    && handle.freshHostReceiptId === intent.freshHostReceiptId
    && handle.principalKeyFingerprint === intent.principalKeyFingerprint
    && handle.actionFingerprint === intent.actionFingerprint
    && handle.resourceKeySha256 === intent.resourceKeySha256
    && handle.evidenceDigest === intent.evidenceDigest
    && handle.receiptId === intent.receiptId
    && handle.canonicalName === intent.canonicalName
    && handle.tupleDigest === intent.tupleDigest
    && handle.activePreimageDigest === intent.activePreimageDigest
    && handle.finalizationPlanDigest === intent.finalizationPlanDigest;
}

async function cleanupFixture(fixture: Fixture): Promise<void> {
  fixture.authorityRegistry.close();
  fixture.oauthStore.close();
  await rm(fixture.root, { recursive: true, force: true });
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

function errorCode(error: unknown): string {
  return error && typeof error === "object" && "code" in error
    ? String(error.code)
    : "";
}
