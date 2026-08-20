import assert from "node:assert/strict";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { loadConfig } from "../config.js";
import {
  BoundedDeepDoctor,
  collectUniversalBrokerDoctor,
  type DeepDoctorIsolation,
} from "./doctor.js";

test("doctor JSON reports contracts, registries, targets, and quotas without credentials", async (t) => {
  const root = await mkdtemp(join(tmpdir(), "devspace-v2-doctor-test-"));
  t.after(() => rm(root, { recursive: true, force: true }));
  const base = loadConfig({
    DEVSPACE_CONFIG_DIR: join(root, "config"),
    DEVSPACE_ALLOWED_ROOTS: root,
    DEVSPACE_STATE_DIR: join(root, "legacy"),
    DEVSPACE_WORKTREE_ROOT: join(root, "legacy-worktrees"),
    DEVSPACE_OAUTH_OWNER_TOKEN: "owner-token-not-for-output-1234567890",
    DEVSPACE_PUBLIC_BASE_URL: "http://127.0.0.1:17676",
    DEVSPACE_LOG_LEVEL: "silent",
  });
  const report = await collectUniversalBrokerDoctor(base, {
    DEVSPACE_NEXT_STATE_DIR: join(root, "next"),
    DEVSPACE_NEXT_AUTHORITY_OWNER_INSTANCE_ID: "doctor-test-owner",
    DEVSPACE_NEXT_TARGET_CONFIG: join(root, "missing-targets.json"),
    DEVSPACE_NEXT_MCP_ROUTE_CONFIG: join(root, "missing-routes.json"),
    DEVSPACE_NEXT_PUBLIC_BASE_URL: "http://127.0.0.1:17677",
  });
  assert.equal(typeof (report.contracts as { passed: boolean }).passed, "boolean");
  assert.match(
    (report.runtimeIdentity as { schemaGeneration: string }).schemaGeneration,
    /^sha256:[a-f0-9]{64}$/u,
  );
  assert.equal(Array.isArray(report.targets), true);
  for (const observation of report.targets as Array<{
    targetId?: string;
    status?: string;
    observedAt?: string;
    expiresAt?: string;
    platform?: string;
    capabilities?: Record<string, boolean>;
    evidence?: { transport?: string };
  }>) {
    assert.equal(typeof observation.targetId, "string");
    assert.equal(typeof observation.status, "string");
    assert.equal(typeof observation.observedAt, "string");
    assert.equal(typeof observation.expiresAt, "string");
    assert.equal(typeof observation.platform, "string");
    assert.equal(typeof observation.capabilities, "object");
    assert.equal(typeof observation.evidence?.transport, "string");
  }
  assert.equal(JSON.stringify(report).includes("owner-token-not-for-output"), false);
  assert.equal((report.quotas as { httpMcpSessions: number }).httpMcpSessions, 128);
  assert.deepEqual(
    report.targetProbeStats,
    {
      probeCacheEntries: 1,
      probeInFlight: 0,
      probeCacheHits: 0,
      probeCacheMisses: 1,
      probeCoalesced: 0,
      probeOnline: 1,
      probeDegraded: 0,
      probeOffline: 0,
      probeDurationMsTotal: (report.targetProbeStats as { probeDurationMsTotal: number }).probeDurationMsTotal,
      averageProbeDurationMs: (report.targetProbeStats as { averageProbeDurationMs: number }).averageProbeDurationMs,
      lastProbeDurationMs: (report.targetProbeStats as { lastProbeDurationMs: number }).lastProbeDurationMs,
    },
  );
  assert.deepEqual(
    report.selfManagement,
    {
      stateDir: join(root, "next", "self-management"),
      pm2ProcessName: "devspace-next",
      expectedScript: undefined,
      restartTimeoutMs: 120_000,
      transactionModel: "response-bound-ack-flushed-supervisor",
    },
  );
  assert.deepEqual(
    report.endpoint,
    {
      deploymentMode: "parallel",
      local: "http://127.0.0.1:7677/mcp-next",
      public: "http://127.0.0.1:17677/mcp-next",
      health: "http://127.0.0.1:7677/healthz-next",
      managementHealth: "http://127.0.0.1:8677/healthz",
      readiness: "http://127.0.0.1:8677/readyz",
      metrics: "http://127.0.0.1:8677/metrics",
      stateDir: join(root, "next"),
      oauthStateReused: false,
      granularScopesOnly: true,
    },
  );
  assert.deepEqual(
    (report.storeInventory as {
      sqliteStores: Array<{ storeId: string; required: boolean; expectedUserVersion: number; path: string }>;
    }).sqliteStores.map((store) => ({
      storeId: store.storeId,
      required: store.required,
      expectedUserVersion: store.expectedUserVersion,
      path: store.path,
    })),
    [
      {
        storeId: "authority",
        required: true,
        expectedUserVersion: 7,
        path: join(root, "next", "authority.sqlite"),
      },
      {
        storeId: "artifact-catalog",
        required: true,
        expectedUserVersion: 1,
        path: join(root, "next", "artifacts.sqlite"),
      },
      {
        storeId: "connector-activation-journal",
        required: true,
        expectedUserVersion: 1,
        path: join(root, "next", "connector-activation-journal.sqlite"),
      },
      {
        storeId: "lifecycle-finalization-store",
        required: true,
        expectedUserVersion: 2,
        path: join(root, "next", "lifecycle.sqlite"),
      },
      {
        storeId: "filesystem-sync",
        required: true,
        expectedUserVersion: 1,
        path: join(root, "next", "filesystem-sync", "sync.sqlite"),
      },
    ],
  );
});

test("bounded deep doctor uses an isolated namespace and always returns a cleanup receipt", async () => {
  const actions: string[] = [];
  const isolation: DeepDoctorIsolation = {
    namespace: "doctor-isolated-1",
    async cleanup(context) {
      assert.equal(context.namespace, "doctor-isolated-1");
      assert.equal(context.correlationId, "doctor-correlation-1");
      assert.equal(context.signal.aborted, false);
      actions.push("cleanup");
      return {
        state: "CLEANED",
        receiptDigest: `sha256:${"a".repeat(64)}`,
      };
    },
  };
  const doctor = new BoundedDeepDoctor({
    maximumDurationMs: 1_000,
    cleanupReserveMs: 100,
    createIsolation: async (context) => {
      assert.equal(context.correlationId, "doctor-correlation-1");
      assert.equal(context.signal.aborted, false);
      return isolation;
    },
    checks: [
      {
        id: "authority_claim_receipt",
        async check(context) {
          actions.push(`check:${context.namespace}`);
          return { state: "PASS", evidence: { receipt: true } };
        },
      },
      {
        id: "public_metrics_negative_probe",
        async check() {
          actions.push("negative-probe");
          return { state: "PASS" };
        },
      },
    ],
  });

  const report = await doctor.run({
    authorized: true,
    correlationId: "doctor-correlation-1",
  });
  assert.equal(report.status, "PASS");
  assert.equal(report.namespace, "doctor-isolated-1");
  assert.equal(report.cleanup.state, "CLEANED");
  assert.match(report.cleanup.receiptDigest, /^sha256:[a-f0-9]{64}$/u);
  assert.deepEqual(actions, [
    "check:doctor-isolated-1",
    "negative-probe",
    "cleanup",
  ]);
});

test("deep doctor rejects unauthenticated execution before creating isolation", async () => {
  let created = 0;
  const doctor = new BoundedDeepDoctor({
    createIsolation: async () => {
      created += 1;
      throw new Error("must not create");
    },
    checks: [{
      id: "must_not_run",
      check: async () => ({ state: "PASS" }),
    }],
  });
  await assert.rejects(
    doctor.run({ authorized: false, correlationId: "doctor-denied" }),
    /management authorization/u,
  );
  assert.equal(created, 0);
});

test("deep doctor remains fail-closed and cleans isolation after a check failure", async () => {
  let cleanupCalls = 0;
  const doctor = new BoundedDeepDoctor({
    maximumDurationMs: 1_000,
    cleanupReserveMs: 100,
    createIsolation: async () => ({
      namespace: "doctor-isolated-failure",
      async cleanup() {
        cleanupCalls += 1;
        return { state: "CLEANED", receiptDigest: `sha256:${"b".repeat(64)}` };
      },
    }),
    checks: [{
      id: "artifact_reconciliation",
      check() {
        throw new Error("catalog mismatch");
      },
    }],
  });
  const report = await doctor.run({ authorized: true, correlationId: "doctor-failure" });
  assert.equal(report.status, "UNKNOWN");
  assert.equal(report.checks[0]?.state, "UNKNOWN");
  assert.match(report.checks[0]?.summary ?? "", /catalog mismatch/u);
  assert.equal(report.cleanup.state, "CLEANED");
  assert.equal(cleanupCalls, 1);
});

test("deep doctor rejects an invalid cleanup receipt state", async () => {
  const doctor = new BoundedDeepDoctor({
    maximumDurationMs: 1_000,
    cleanupReserveMs: 100,
    createIsolation: async () => ({
      namespace: "doctor-invalid-cleanup",
      async cleanup() {
        return {
          state: "NOT_CLEANED" as never,
          receiptDigest: `sha256:${"c".repeat(64)}`,
        };
      },
    }),
    checks: [{
      id: "runtime_identity",
      check: async () => ({ state: "PASS" }),
    }],
  });
  const report = await doctor.run({ authorized: true, correlationId: "doctor-invalid-cleanup" });
  assert.equal(report.status, "UNKNOWN");
  assert.equal(report.cleanup.state, "FAILED");
  assert.match(report.cleanup.error ?? "", /state is invalid/u);
});
