import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import test from "node:test";
import {
  PRODUCTION_UPGRADE_REQUIRED_SNAPSHOT_ENTRIES,
  PRODUCTION_UPGRADE_PREVIOUS_CURSOR_SNAPSHOT_ENTRY,
  canonicalizeProductionUpgradeValue,
  productionUpgradeCandidateIdentityDigest,
  productionUpgradeLifecycleBindingDigest,
  productionUpgradeRequestBindingDigest,
  serializeProductionUpgradeRequestV4,
  validateProductionUpgradeProducedApprovalArtifacts,
  validateProductionUpgradeRequestV4,
  type ProductionUpgradeRequestV4,
} from "./production-upgrade-contract.js";

const digest = (label: string): `sha256:${string}` => (
  `sha256:${createHash("sha256").update(label).digest("hex")}`
);

function artifact(root: string, name: string) {
  return { path: `${root}/${name}.json`, sha256: digest(name) } as const;
}

function validRequest(root = "/private/tmp/devspace-production-upgrade-contract"): ProductionUpgradeRequestV4 {
  const state = `${root}/state`;
  const audit = `${root}/audit`;
  const control = `${root}/control`;
  const immutable = `${root}/immutable`;
  const requestedAt = "2026-08-20T09:00:00.000Z";
  const captureDeadlineAt = "2026-08-20T09:05:00.000Z";
  const candidateIdentity = {
    runtimeIdentityDigest: digest("candidate-runtime"),
    buildDigest: digest("candidate-build"),
    schemaGeneration: digest("candidate-schema"),
    authorityContractGeneration: digest("candidate-authority"),
    buildCapabilityManifestDigest: digest("candidate-capabilities"),
    generatedSchemaDigest: digest("candidate-generated-schema"),
    packageSha256: digest("candidate-package"),
  } as const;
  const snapshotPaths: Record<(typeof PRODUCTION_UPGRADE_REQUIRED_SNAPSHOT_ENTRIES)[number]["id"], string> = {
    "oauth-main-and-connector-state": `${state}/oauth/devspace.sqlite`,
    "authority-store": `${state}/authority.sqlite`,
    "contexts-store": `${state}/contexts.json`,
    "process-metadata": `${state}/processes`,
    "process-output": `${state}/process-output`,
    "filesystem-sync": `${state}/filesystem-sync/sync.sqlite`,
    "artifact-catalog": `${state}/artifacts.sqlite`,
    "artifact-cas": `${state}/artifact-objects`,
    "artifact-quarantine": `${state}/artifact-quarantine`,
    "pagination-current-signing-key": `${state}/pagination/current.key`,
    "lifecycle-finalization-store": `${state}/lifecycle.sqlite`,
    "runtime-environment": `${state}/production.env`,
    "process-manager-definition": `${state}/canonical-start.sh`,
    "public-route": `${state}/public-route.json`,
    "target-route-generation-config": `${state}/target-route-generation.json`,
  };
  const entries: ProductionUpgradeRequestV4["snapshotGroup"]["entries"] = PRODUCTION_UPGRADE_REQUIRED_SNAPSHOT_ENTRIES.map(({ id, kind }) => ({
    id,
    kind,
    path: snapshotPaths[id],
    required: true as const,
  }));
  const previousCursorPath = `${state}/oauth/cursor-previous.key`;
  entries.push({
    ...PRODUCTION_UPGRADE_PREVIOUS_CURSOR_SNAPSHOT_ENTRY,
    path: previousCursorPath,
    required: false,
  });
  const producerSha = createHash("sha256").update("fixture-gate-producer-spki").digest("hex");
  const request = {
    version: 4 as const,
    transactionId: "upgrade_11111111-1111-4111-8111-111111111111",
    requestedAt,
    delayMs: 0,
    timeoutMs: 300_000,
    pm2ProcessName: "devspace-v2-production",
    pm2Executable: "/opt/devspace/bin/pm2",
    gitExecutable: "/usr/bin/git",
    previous: {
      pid: 4111,
      cwd: `${root}/previous-release`,
      script: `${root}/previous-release/start.sh`,
      auditTarget: `${root}/previous-audit`,
      runtimeIdentityDigest: digest("previous-runtime"),
      migrationManifestDigest: digest("previous-migrations"),
      localHealthUrl: "http://127.0.0.1:43110/healthz",
      localReadyUrl: "http://127.0.0.1:43111/readyz",
      rollbackHostChallenge: {
        rollbackChallengeRequest: artifact(control, "rollback-challenge-request"),
        challengePath: `${control}/rollback-challenge.json`,
        challengeSha256: digest("rollback-challenge"),
        receiptPath: `${control}/rollback-receipt.json`,
        deadlineAt: "2026-08-20T09:20:00.000Z",
        pollIntervalMs: 250,
      },
    },
    next: {
      commit: "1".repeat(40),
      sourceTree: "2".repeat(40),
      sourceEvidenceRoot: `${immutable}/source-evidence`,
      immutableRuntimeRoot: `${immutable}/runtime`,
      immutableRuntimeEntrypoint: `${immutable}/runtime/scripts/start-universal-broker-v2-production.sh`,
      runtimeDependencies: {
        root: `${immutable}/dependencies`,
        evidencePath: `${immutable}/dependencies/RUNTIME-DEPENDENCIES.json`,
        evidenceSha256: digest("runtime-dependencies"),
      },
      dist: { files: 17, sha256: "3".repeat(64) },
      manifest: {
        path: `${immutable}/runtime/BUILD-MANIFEST.json`,
        sha256: digest("build-manifest"),
        buildDigest: candidateIdentity.buildDigest,
        runtimeRevision: "release-20260820-1",
        schemaGeneration: candidateIdentity.schemaGeneration,
        authorityContractGeneration: candidateIdentity.authorityContractGeneration,
        configSchemaIdentity: digest("config-schema"),
        migrationManifestDigest: digest("next-migrations"),
        buildCapabilityManifestDigest: candidateIdentity.buildCapabilityManifestDigest,
        generatedSchemaDigest: candidateIdentity.generatedSchemaDigest,
        packageSha256: candidateIdentity.packageSha256,
        runtimeIdentityDigest: candidateIdentity.runtimeIdentityDigest,
      },
    },
    oauthStateDirectory: `${state}/oauth`,
    productionEnvPath: snapshotPaths["runtime-environment"],
    productionEnvBackupPath: `${audit}/preimage/production.env`,
    oauthDatabasePath: snapshotPaths["oauth-main-and-connector-state"],
    oauthDatabaseBackupPath: `${audit}/preimage/oauth.sqlite`,
    authorityDatabasePath: snapshotPaths["authority-store"],
    authorityDatabaseBackupPath: `${audit}/preimage/authority.sqlite`,
    snapshotGroup: {
      snapshotRoot: `${audit}/snapshot`,
      manifestPath: `${audit}/snapshot/SNAPSHOT-GROUP.json`,
      paginationPreviousSigningKey: { state: "ABSENT" as const, path: previousCursorPath },
      barrier: {
        kind: "PM2_STOPPED" as const,
        transactionId: "upgrade_11111111-1111-4111-8111-111111111111",
        processName: "devspace-v2-production",
        previousPid: 4111,
        previousRuntimeIdentityDigest: digest("previous-runtime"),
        previousMigrationManifestDigest: digest("previous-migrations"),
        candidateIdentityDigest: productionUpgradeCandidateIdentityDigest(candidateIdentity),
        cutoverProcessNames: ["devspace-v2-production", "devspace-v2-worker"],
        captureDeadlineAt,
      },
      entries,
    },
    cutoverProcessNames: ["devspace-v2-production", "devspace-v2-worker"],
    connectorLifecycle: {
      bindingDigest: digest("placeholder-lifecycle-binding"),
      stagingActivationPrecheck: artifact(control, "staging-activation-precheck"),
      preCutoverHostCanary: artifact(control, "pre-cutover-host-canary"),
      releaseDriver: {
        stagingPrecheckRequest: artifact(control, "driver-staging-precheck-request"),
        stagingActivationRequest: artifact(control, "driver-staging-activation-request"),
        stagingActivationReadback: artifact(control, "driver-staging-activation-readback"),
        preCutoverRequest: artifact(control, "driver-pre-cutover-request"),
        productionPredecisionRequest: artifact(control, "driver-production-predecision-request"),
        productionPredecisionEnvelope: artifact(control, "driver-production-predecision-envelope"),
        productionPreparationRequest: artifact(control, "driver-production-preparation-request"),
        productionApprovalOutputDirectory: `${control}/production-approval-output`,
      },
      journal: {
        path: `${control}/connector-activation.sqlite`,
        identity: {
          storeId: "33333333-3333-4333-8333-333333333333",
          storePath: `${control}/connector-activation.sqlite`,
          schemaVersion: 1 as const,
          migrationManifestDigest: digest("connector-journal-migration"),
          contentGeneration: digest("connector-journal-generation"),
          snapshotPolicy: "PRESERVE_OUTSIDE_MUTABLE_ROLLBACK" as const,
          receiptReplayPolicy: "PREPARED_RECEIPT_PERMANENTLY_ONE_SHOT" as const,
          schemaFingerprint: digest("connector-journal-schema"),
          createdAtMs: Date.parse(requestedAt) - 1,
        },
      },
      postActivation: {
        challengePath: `${control}/post-activation-challenge.json`,
        challengeSha256: digest("post-activation-challenge"),
        receiptPath: `${control}/post-activation-receipt.json`,
        deadlineAt: "2026-08-20T09:20:00.000Z",
        pollIntervalMs: 250,
        runtimeIdentityUrl: "http://127.0.0.1:43111/readyz",
        routeIdentityUrl: "http://127.0.0.1:43111/route-identityz",
      },
      managementAuthorizationKeyRef: `${control}/management.key`,
      managementNonce: "fixture-management-nonce",
      managementCorrelationId: "fixture-management-correlation",
      candidateIdentity,
      oauthResource: "https://devspace.example.test/mcp",
      productionEnvironmentIdentityDigest: digest("production-environment"),
      productionRouteIdentityDigest: digest("production-route"),
      finalization: {
        storePath: snapshotPaths["lifecycle-finalization-store"],
        controlPath: `${control}/finalization-control.json`,
        keyId: `management-${"4".repeat(24)}`,
        gateProducer: {
          keyId: `gate-producer-ed25519-sha256:${producerSha}`,
          publicKeySha256: `sha256:${producerSha}` as `sha256:${string}`,
        },
        gateProducerTrustAnchor: artifact(control, "gate-producer-trust-anchor"),
        preSnapshotIdentity: {
          storeId: "lifecycle-finalization-store" as const,
          schemaVersion: 2 as const,
          state: "DRAFT" as const,
          revision: 1 as const,
          transactionId: null,
          contentGeneration: digest("finalization-content-generation"),
          controlEpoch: 1,
          controlTag: `hmac-sha256:${"5".repeat(64)}` as `hmac-sha256:${string}`,
          identityDigest: digest("finalization-identity"),
        },
      },
    },
    rollbackJournalPath: `${control}/rollback.jsonl`,
    nextEnvPath: `${audit}/production.env.next`,
    startScriptPath: `${state}/canonical-start.sh`,
    startScriptBackupPath: `${audit}/preimage/canonical-start.sh`,
    auditDirectory: audit,
    currentAuditLink: `${root}/current-audit`,
    statusPath: `${audit}/status.json`,
    workerClaimPath: `${audit}/status.json.worker-claim.json`,
    workerLogPath: `${audit}/worker.log`,
    localHealthUrl: "http://127.0.0.1:43110/healthz",
    localDoctorUrl: "http://127.0.0.1:43111/doctorz",
    publicHealthUrl: "https://devspace.example.test/healthz",
    publicMetricsUrl: "https://devspace.example.test/metrics",
    publicMcpUrl: "https://devspace.example.test/mcp",
    oauthMetadataUrl: "https://devspace.example.test/.well-known/oauth-protected-resource/mcp",
    expectedScopes: [
      "devspace.read", "devspace.write", "devspace.exec", "devspace.mcp",
      "devspace.artifact", "devspace.gui", "offline_access",
    ],
  };
  request.connectorLifecycle.bindingDigest = productionUpgradeLifecycleBindingDigest(request);
  return request;
}

function clone(value: ProductionUpgradeRequestV4): ProductionUpgradeRequestV4 {
  return structuredClone(value);
}

test("validates and freezes one exact post-snapshot-ready v4 request", () => {
  const request = validRequest();
  const observed = validateProductionUpgradeRequestV4(request);
  assert.deepEqual(observed, request);
  assert.equal(Object.isFrozen(observed), true);
  assert.equal(Object.isFrozen(observed.connectorLifecycle.releaseDriver), true);
  assert.equal(observed.snapshotGroup.entries.length, 16);
  assert.deepEqual(
    observed.snapshotGroup.entries.map(({ id, kind }) => ({ id, kind })),
    [...PRODUCTION_UPGRADE_REQUIRED_SNAPSHOT_ENTRIES, PRODUCTION_UPGRADE_PREVIOUS_CURSOR_SNAPSHOT_ENTRY],
  );
  assert.match(productionUpgradeRequestBindingDigest(request), /^sha256:[a-f0-9]{64}$/u);
});

test("rejects legacy v4 production activation material and every missing or extra key", () => {
  const v3 = clone(validRequest()) as unknown as { version: number };
  v3.version = 3;
  assert.throws(() => validateProductionUpgradeRequestV4(v3), /version/u);

  const extra = clone(validRequest()) as unknown as Record<string, unknown>;
  extra.productionActivationPrecheck = artifact("/private/tmp", "legacy-production-precheck");
  assert.throws(() => validateProductionUpgradeRequestV4(extra), /unexpected key/u);

  const nestedExtra = clone(validRequest()) as unknown as {
    connectorLifecycle: Record<string, unknown>;
  };
  nestedExtra.connectorLifecycle.ownerApproval = artifact("/private/tmp", "legacy-owner-approval");
  assert.throws(() => validateProductionUpgradeRequestV4(nestedExtra), /unexpected key/u);

  const prototypeKey = clone(validRequest()) as unknown as Record<string, unknown>;
  Object.defineProperty(prototypeKey, "__proto__", {
    enumerable: true,
    configurable: true,
    writable: true,
    value: { releasePass: true },
  });
  assert.throws(() => validateProductionUpgradeRequestV4(prototypeKey), /unexpected key __proto__/u);

  const legacyActivation = clone(validRequest()) as unknown as {
    connectorLifecycle: Record<string, unknown>;
  };
  legacyActivation.connectorLifecycle.activation = {
    receiptId: "connector-activation-aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
  };
  assert.throws(() => validateProductionUpgradeRequestV4(legacyActivation), /unexpected key/u);

  const missing = clone(validRequest()) as unknown as {
    connectorLifecycle: Record<string, unknown>;
  };
  delete missing.connectorLifecycle.finalization;
  assert.throws(() => validateProductionUpgradeRequestV4(missing), /missing key/u);
});

test("rejects wrong scalar, digest, producer, and cross-identity types before hashing", () => {
  const wrongType = clone(validRequest()) as unknown as { timeoutMs: string };
  wrongType.timeoutMs = "300000";
  assert.throws(() => productionUpgradeRequestBindingDigest(wrongType), /timeoutMs/u);

  const producer = clone(validRequest());
  producer.connectorLifecycle.finalization.gateProducer.publicKeySha256 = digest("different-public-key");
  assert.throws(() => productionUpgradeRequestBindingDigest(producer), /gateProducer|gate producer/u);

  const anchor = clone(validRequest());
  anchor.connectorLifecycle.finalization.gateProducerTrustAnchor.sha256 = "sha256:INVALID";
  assert.throws(() => productionUpgradeRequestBindingDigest(anchor), /gateProducerTrustAnchor.sha256/u);

  const manifest = clone(validRequest());
  manifest.next.manifest.packageSha256 = digest("different-package");
  assert.throws(() => productionUpgradeRequestBindingDigest(manifest), /candidate identity/u);

  const lifecycle = clone(validRequest());
  lifecycle.connectorLifecycle.bindingDigest = digest("wrong-lifecycle-binding");
  assert.throws(() => productionUpgradeRequestBindingDigest(lifecycle), /lifecycle binding/u);
});

test("rejects noncanonical and derived-control path drift", () => {
  const relative = clone(validRequest());
  relative.statusPath = "audit/status.json";
  assert.throws(() => validateProductionUpgradeRequestV4(relative), /absolute/u);

  const dotSegment = clone(validRequest());
  dotSegment.next.manifest.path = `${dotSegment.next.immutableRuntimeRoot}/./BUILD-MANIFEST.json`;
  assert.throws(() => validateProductionUpgradeRequestV4(dotSegment), /canonical/u);

  const claim = clone(validRequest());
  claim.workerClaimPath = `${claim.auditDirectory}/different-claim.json`;
  assert.throws(() => validateProductionUpgradeRequestV4(claim), /workerClaimPath/u);

  const manifest = clone(validRequest());
  manifest.snapshotGroup.manifestPath = `${manifest.snapshotGroup.snapshotRoot}/other.json`;
  assert.throws(() => validateProductionUpgradeRequestV4(manifest), /manifestPath/u);

  const processDefinition = clone(validRequest());
  processDefinition.snapshotGroup.entries.find(
    (entry) => entry.id === "process-manager-definition",
  )!.path = `${processDefinition.auditDirectory}/invented-start.sh`;
  assert.throws(() => validateProductionUpgradeRequestV4(processDefinition), /process-manager-definition/u);

  const externalStatus = clone(validRequest());
  externalStatus.statusPath = `${externalStatus.auditDirectory}-outside/status.json`;
  externalStatus.workerClaimPath = `${externalStatus.statusPath}.worker-claim.json`;
  assert.throws(() => validateProductionUpgradeRequestV4(externalStatus), /statusPath.*strict descendant/u);
});

test("rejects duplicate, missing, reordered, optional, and sidecar-alias snapshot entries", () => {
  const duplicate = clone(validRequest());
  duplicate.snapshotGroup.entries[1] = { ...duplicate.snapshotGroup.entries[0]! };
  assert.throws(() => validateProductionUpgradeRequestV4(duplicate), /snapshot entry/u);

  const missing = clone(validRequest());
  missing.snapshotGroup.entries.pop();
  assert.throws(() => validateProductionUpgradeRequestV4(missing), /16 snapshot entries/u);

  const reordered = clone(validRequest());
  [reordered.snapshotGroup.entries[0], reordered.snapshotGroup.entries[1]] = [
    reordered.snapshotGroup.entries[1]!, reordered.snapshotGroup.entries[0]!,
  ];
  assert.throws(() => validateProductionUpgradeRequestV4(reordered), /snapshot entry/u);

  const optional = clone(validRequest());
  (optional.snapshotGroup.entries[0] as unknown as { required: boolean }).required = false;
  assert.throws(() => validateProductionUpgradeRequestV4(optional), /required/u);

  const sidecarAlias = clone(validRequest());
  sidecarAlias.snapshotGroup.entries[2]!.path = `${sidecarAlias.oauthDatabasePath}-wal`;
  assert.throws(() => validateProductionUpgradeRequestV4(sidecarAlias), /sidecar|overlap/u);
});

test("binds configured previous cursor keys as the exact final required snapshot entry", () => {
  const present = clone(validRequest());
  const previousPath = `${present.oauthStateDirectory}/cursor-previous.key`;
  present.snapshotGroup.paginationPreviousSigningKey = { state: "PRESENT", path: previousPath };
  present.snapshotGroup.entries.at(-1)!.path = previousPath;
  present.snapshotGroup.entries.at(-1)!.required = true;
  const absentLifecycleDigest = present.connectorLifecycle.bindingDigest;
  present.connectorLifecycle.bindingDigest = productionUpgradeLifecycleBindingDigest(present);
  assert.notEqual(present.connectorLifecycle.bindingDigest, absentLifecycleDigest);
  assert.equal(validateProductionUpgradeRequestV4(present).snapshotGroup.entries.length, 16);

  const missing = clone(present);
  missing.snapshotGroup.entries.pop();
  assert.throws(() => validateProductionUpgradeRequestV4(missing), /exactly 16/u);

  const wrongPath = clone(present);
  wrongPath.snapshotGroup.paginationPreviousSigningKey = {
    state: "PRESENT",
    path: `${present.oauthStateDirectory}/other.key`,
  };
  assert.throws(() => validateProductionUpgradeRequestV4(wrongPath), /previous-signing-key snapshot path/u);

  const absentRequired = clone(present);
  absentRequired.snapshotGroup.paginationPreviousSigningKey = { state: "ABSENT", path: previousPath };
  assert.throws(() => validateProductionUpgradeRequestV4(absentRequired), /required/u);

  const absentWithoutPath = clone(present);
  (absentWithoutPath.snapshotGroup.paginationPreviousSigningKey as unknown as { state: string }) = {
    state: "ABSENT",
  };
  assert.throws(() => validateProductionUpgradeRequestV4(absentWithoutPath), /path/u);
});

test("rejects mutable, snapshot, immutable, journal, evidence, and future-output overlaps", () => {
  const journal = clone(validRequest());
  journal.connectorLifecycle.journal.path = `${journal.oauthDatabasePath}-shm`;
  journal.connectorLifecycle.journal.identity.storePath = journal.connectorLifecycle.journal.path;
  assert.throws(() => validateProductionUpgradeRequestV4(journal), /overlap/u);

  const output = clone(validRequest());
  output.connectorLifecycle.releaseDriver.productionApprovalOutputDirectory = output.snapshotGroup.snapshotRoot;
  assert.throws(() => validateProductionUpgradeRequestV4(output), /overlap/u);

  const immutable = clone(validRequest());
  immutable.next.sourceEvidenceRoot = immutable.snapshotGroup.snapshotRoot;
  assert.throws(() => validateProductionUpgradeRequestV4(immutable), /overlap/u);

  const immutableEvidence = clone(validRequest());
  immutableEvidence.connectorLifecycle.releaseDriver.productionPreparationRequest.path =
    `${immutableEvidence.next.immutableRuntimeRoot}/production-preparation-request.json`;
  assert.throws(() => validateProductionUpgradeRequestV4(immutableEvidence), /immutable release root.*control/u);

  const provenance = clone(validRequest());
  provenance.connectorLifecycle.releaseDriver.preCutoverRequest = {
    ...provenance.connectorLifecycle.releaseDriver.stagingPrecheckRequest,
  };
  assert.throws(() => validateProductionUpgradeRequestV4(provenance), /provenance.*distinct/u);

  const rollback = clone(validRequest());
  rollback.previous.rollbackHostChallenge.receiptPath = rollback.previous.rollbackHostChallenge.challengePath;
  assert.throws(() => validateProductionUpgradeRequestV4(rollback), /rollback.*distinct/u);

  const previousAudit = clone(validRequest());
  previousAudit.previous.auditTarget = previousAudit.oauthDatabasePath;
  assert.throws(() => validateProductionUpgradeRequestV4(previousAudit), /overlap/u);

  const anchor = clone(validRequest());
  anchor.connectorLifecycle.finalization.gateProducerTrustAnchor.path = anchor.next.manifest.path;
  assert.throws(() => validateProductionUpgradeRequestV4(anchor), /immutable release root|control/u);
});

test("rejects stale deadline, poll, barrier, journal, and finalization generation drift", () => {
  const deadline = clone(validRequest());
  deadline.connectorLifecycle.postActivation.deadlineAt = deadline.requestedAt;
  assert.throws(() => validateProductionUpgradeRequestV4(deadline), /deadline/u);

  const poll = clone(validRequest());
  poll.previous.rollbackHostChallenge.pollIntervalMs = 0;
  assert.throws(() => validateProductionUpgradeRequestV4(poll), /pollIntervalMs/u);

  const barrier = clone(validRequest());
  barrier.snapshotGroup.barrier.previousRuntimeIdentityDigest = digest("barrier-drift");
  assert.throws(() => validateProductionUpgradeRequestV4(barrier), /barrier/u);

  const journal = clone(validRequest());
  journal.connectorLifecycle.journal.identity.contentGeneration = "sha256:INVALID";
  assert.throws(() => validateProductionUpgradeRequestV4(journal), /contentGeneration/u);

  const journalStore = clone(validRequest());
  journalStore.connectorLifecycle.journal.identity.storeId = "caller-selected-journal";
  assert.throws(() => validateProductionUpgradeRequestV4(journalStore), /storeId/u);

  const finalization = clone(validRequest());
  finalization.connectorLifecycle.finalization.preSnapshotIdentity.controlEpoch = 0;
  assert.throws(() => validateProductionUpgradeRequestV4(finalization), /controlEpoch/u);
});

test("rejects public-origin, OAuth-resource, and management endpoint drift", () => {
  const origin = clone(validRequest());
  origin.publicMetricsUrl = "https://metrics.example.test/metrics";
  assert.throws(() => validateProductionUpgradeRequestV4(origin), /public URLs/u);

  const http = clone(validRequest());
  http.publicHealthUrl = "http://devspace.example.test/healthz";
  assert.throws(() => validateProductionUpgradeRequestV4(http), /public URLs/u);

  const resource = clone(validRequest());
  resource.connectorLifecycle.oauthResource = "https://other.example.test/mcp";
  assert.throws(() => validateProductionUpgradeRequestV4(resource), /oauthResource/u);

  const route = clone(validRequest());
  route.connectorLifecycle.postActivation.routeIdentityUrl = "http://127.0.0.1:43111/routez";
  assert.throws(() => validateProductionUpgradeRequestV4(route), /route identities/u);

  const previousReady = clone(validRequest());
  previousReady.previous.localReadyUrl = "http://127.0.0.1:43112/readyz";
  assert.throws(() => validateProductionUpgradeRequestV4(previousReady), /exact paths and origin/u);

  const localHttps = clone(validRequest());
  localHttps.connectorLifecycle.postActivation.runtimeIdentityUrl = "https://127.0.0.1:43111/readyz";
  assert.throws(() => validateProductionUpgradeRequestV4(localHttps), /HTTP loopback/u);
});

test("code-unit canonical hashing is stable with non-ASCII path values", () => {
  const left = validRequest("/private/tmp/업그레이드-é");
  const right = structuredClone(left);
  assert.equal(productionUpgradeRequestBindingDigest(left), productionUpgradeRequestBindingDigest(right));
  assert.equal(
    canonicalizeProductionUpgradeValue({ "é": 1, z: 2, "中": 3 }),
    "{\"z\":2,\"é\":1,\"中\":3}",
  );
  const serialized = serializeProductionUpgradeRequestV4(left);
  assert.equal(serialized.endsWith("\n"), true);
  assert.equal(serialized, `${canonicalizeProductionUpgradeValue(left)}\n`);
});

test("rejects accessors and undefined instead of hashing an unstable object", () => {
  const accessor = clone(validRequest()) as unknown as Record<string, unknown>;
  let getterCalls = 0;
  Object.defineProperty(accessor, "timeoutMs", {
    enumerable: true,
    get() {
      getterCalls += 1;
      return 300_000;
    },
  });
  assert.throws(() => productionUpgradeRequestBindingDigest(accessor), /data property/u);
  assert.equal(getterCalls, 0);

  const undefinedValue = clone(validRequest()) as unknown as Record<string, unknown>;
  undefinedValue.launchdLabel = undefined;
  assert.throws(() => productionUpgradeRequestBindingDigest(undefinedValue), /undefined/u);
});

test("validates exact post-snapshot approval artifacts without putting them in the request", () => {
  const outputDirectory = validRequest().connectorLifecycle.releaseDriver.productionApprovalOutputDirectory;
  const produced = {
    outputDirectory,
    manifest: artifact(outputDirectory, "manifest"),
    productionActivationPrecheck: artifact(outputDirectory, "production-activation-precheck"),
    ownerManagementApproval: artifact(outputDirectory, "owner-management-approval"),
    recordedAt: "2026-08-20T09:05:01.000Z",
  };
  assert.deepEqual(
    validateProductionUpgradeProducedApprovalArtifacts(produced, outputDirectory),
    produced,
  );

  const extra = { ...produced, ownerPass: true };
  assert.throws(
    () => validateProductionUpgradeProducedApprovalArtifacts(extra, outputDirectory),
    /unexpected key/u,
  );
  const drift = structuredClone(produced);
  (drift.manifest as { path: string }).path = `${outputDirectory}/other.json`;
  assert.throws(
    () => validateProductionUpgradeProducedApprovalArtifacts(drift, outputDirectory),
    /frozen driver output filename/u,
  );
});
