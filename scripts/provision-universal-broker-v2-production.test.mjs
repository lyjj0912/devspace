import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { lstatSync, mkdtempSync, realpathSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import {
  inspectProductionProvisioning,
  provisionProductionState,
} from "./provision-universal-broker-v2-production.mjs";

test("production provisioning creates the complete missing store set once and preserves identity", async () => {
  const root = realpathSync(mkdtempSync(join(tmpdir(), "devspace-production-provisioning-")));
  const options = {
    stateDir: join(root, "state"),
    identityDirectory: join(root, "identity"),
    finalizationControl: join(root, "control", "lifecycle-finalization-head.json"),
    ownerInstanceId: "owner-provisioning-test-0001",
    environment: "PRODUCTION_TEST",
  };
  try {
    const before = inspectProductionProvisioning(options);
    assert.equal(before.status, "NOT_READY");
    assert.deepEqual(before.errors, []);
    assert.deepEqual(before.missing, [
      "managementKey",
      "cursorKey",
      "gatePrivateKey",
      "gateTrustAnchor",
      "lifecycleStore",
      "finalizationControl",
      "finalizationBootstrapConsumed",
      "connectorJournal",
      "filesystemSyncStore",
      "artifactCatalog",
      "artifactObjectRoot",
      "artifactQuarantineRoot",
    ]);

    const first = await provisionProductionState(options);
    assert.equal(first.status, "READY");
    assert.equal(first.identities.finalizationState, "DRAFT");
    assert.equal(first.identities.finalizationRevision, 1);
    assert.match(first.identities.managementKeyId, /^management-[a-f0-9]{24}$/u);
    assert.match(first.identities.cursorKeyId, /^cursor-[a-f0-9]{24}$/u);
    assert.match(first.identities.gateProducerKeyId, /^gate-producer-ed25519-sha256:[a-f0-9]{64}$/u);
    assert.match(first.identities.connectorJournalGeneration, /^sha256:[a-f0-9]{64}$/u);
    assert.deepEqual(first.artifactReconciliation, {
      abortedReservations: 0,
      quarantinedObjects: 0,
      quarantinedRecords: 0,
      receipts: 0,
    });

    const second = await provisionProductionState(options);
    assert.equal(second.status, "READY");
    assert.deepEqual(second.identities, first.identities);
    assert.equal(second.gateTrustAnchorSha256, first.gateTrustAnchorSha256);
    for (const [key, path] of Object.entries(second.paths)) {
      if (["stateDir", "identityDirectory"].includes(key)) continue;
      const mode = lstatSync(path).mode & 0o777;
      assert.equal(mode & 0o077, 0, `${key} is owner-only`);
    }

    const cli = JSON.parse(execFileSync(process.execPath, [
      "scripts/provision-universal-broker-v2-production.mjs",
      "status",
      "--state-dir", options.stateDir,
      "--identity-directory", options.identityDirectory,
      "--finalization-control", options.finalizationControl,
      "--owner-instance-id", options.ownerInstanceId,
      "--environment", options.environment,
    ], { cwd: process.cwd(), encoding: "utf8" }));
    assert.equal(cli.status, "READY");
    assert.deepEqual(cli.identities, {
      managementKeyId: first.identities.managementKeyId,
      gateProducerKeyId: first.identities.gateProducerKeyId,
      gateTrustAnchorSha256: first.identities.gateTrustAnchorSha256,
      finalizationState: first.identities.finalizationState,
      finalizationRevision: first.identities.finalizationRevision,
      finalizationHead: first.identities.finalizationHead,
    });
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});
