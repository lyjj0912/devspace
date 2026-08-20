import { spawn, spawnSync } from "node:child_process";
import { createHash, randomUUID } from "node:crypto";
import { constants as fsConstants, readFileSync } from "node:fs";
import {
  chmod,
  copyFile,
  lstat,
  mkdir,
  open,
  readdir,
  readFile,
  readlink,
  rename,
  rm,
  symlink,
  writeFile,
} from "node:fs/promises";
import { basename, delimiter, dirname, isAbsolute, join, relative, resolve, sep } from "node:path";
import { fileURLToPath } from "node:url";
import Database from "better-sqlite3";
import { ConnectorActivationLifecycleManager } from "./connector-activation-lifecycle.js";
import {
  loadExistingManagementAuthorizationKey,
  managementAuthorizationHeader,
} from "./management-authorization.js";
import {
  migrationManifestDigest,
  type MigrationManifestEntry,
} from "./migration-registry.js";
import {
  PRODUCTION_UPGRADE_PREVIOUS_CURSOR_SNAPSHOT_ENTRY,
  PRODUCTION_UPGRADE_RELEASE_DRIVER_PROVENANCE_KEYS,
  productionUpgradeCandidateIdentityDigest,
  productionUpgradeLifecycleBindingDigest as contractProductionUpgradeLifecycleBindingDigest,
  productionUpgradeRequestBindingDigest as contractProductionUpgradeRequestBindingDigest,
  serializeProductionUpgradeRequestV4,
  validateProductionUpgradeRequestV4,
  type ProductionUpgradeProducedApprovalArtifacts,
  type ProductionUpgradeRequestV4,
  type ProductionUpgradeSha256Digest,
} from "./production-upgrade-contract.js";
import {
  commitActivationPending,
  commitBaseProfileFinalPass,
  commitCanonicalFinalizationSeal,
  commitDraining,
  commitPostActivationVerified,
  commitPreparedFinalization,
  commitProfileGatesEvaluated,
  readFinalizationStoreIdentity,
  readFinalizationStoreLedger,
} from "../../scripts/lib/finalization-store-contract.mjs";
import {
  inspectVerifiedReleaseGateLedger,
  verifyGateProducerTrustAnchor,
} from "../../scripts/lib/release-artifacts.mjs";
import {
  canonicalNoFollowPath,
  canonicalPathsOverlap,
  captureSnapshotGroup,
  restoreSnapshotGroup,
  snapshotEntryMutablePaths,
  validateSnapshotGroupManifest,
  type SnapshotGroupEntryRequest,
  type SnapshotGroupManifest,
  type SnapshotGroupManifestEntry,
  type SnapshotGroupRestoreEntry,
  type SnapshotGroupRestoreEvidence,
} from "./snapshot-group.js";
import {
  connectorRollbackHealthReadbackDigest,
  connectorRollbackReadyReadbackDigest,
  connectorRollbackRuntimeReadbackDigest,
  verifyConnectorRollbackHostChallenge,
  verifyConnectorRollbackHostReceipt,
  type ConnectorRollbackChallengeExpectedBinding,
  type ConnectorRollbackReceiptExpectedBinding,
  type SignedConnectorRollbackHostChallenge,
  type SignedConnectorRollbackHostReceipt,
  type VerifiedConnectorRollbackHostChallenge,
} from "../../scripts/lib/connector-rollback-evidence.mjs";

export const PRODUCTION_UPGRADE_STATES = [
  "PREPARED",
  "ACCEPTED",
  "PREFLIGHT_VERIFIED",
  "CUTOVER_STOP_REQUESTED",
  "CUTOVER_PROCESSES_STOPPED",
  "STATE_SNAPSHOTTED",
  "CONNECTOR_ACTIVATION_PREPARED",
  "ACTIVATED_PENDING_POSTCHECK",
  "RUNTIME_STARTED",
  "POST_SWITCH_VERIFIED",
  "POST_ACTIVATION_VERIFIED",
  "PASS",
  "ROLLBACK_REQUESTED",
  "ROLLBACK_RESTORING",
  "ROLLED_BACK",
  "ROLLBACK_UNKNOWN",
  "FAIL",
  "UNKNOWN",
] as const;

export type ProductionUpgradeState = (typeof PRODUCTION_UPGRADE_STATES)[number];

export const PRODUCTION_UPGRADE_FAILURE_CODES = [
  "MANIFEST_INVALID",
  "MANIFEST_MISMATCH",
  "SWITCH_FAILED",
  "RUNTIME_EQUIVALENCE_FAILED",
  "MANAGEMENT_NOT_READY",
  "RUNTIME_IDENTITY_MISMATCH",
  "PUBLIC_BOUNDARY_FAILED",
  "CONNECTOR_ACTIVATION_FAILED",
  "POST_ACTIVATION_FAILED",
  "POST_ACTIVATION_TIMEOUT",
  "ROLLBACK_FAILED",
] as const;

export type ProductionUpgradeFailureCode = (typeof PRODUCTION_UPGRADE_FAILURE_CODES)[number];
export type ProductionUpgradeFailurePhase =
  | "PREFLIGHT"
  | "CONNECTOR_ACTIVATION"
  | "SWITCHING"
  | "VERIFYING"
  | "POST_ACTIVATION"
  | "ROLLING_BACK";

export interface ProductionUpgradeFailure {
  code: ProductionUpgradeFailureCode;
  phase: ProductionUpgradeFailurePhase;
  message: string;
  retryable: boolean;
  evidence?: Record<string, unknown>;
}

export type ProductionUpgradeRequest = ProductionUpgradeRequestV4;

export interface ProductionUpgradeStatus extends Record<string, unknown> {
  version: 2;
  transactionId: string;
  requestBindingDigest: string;
  state: ProductionUpgradeState;
  requestedAt: string;
  updatedAt: string;
  expectedDisconnect: true;
  previous: ProductionUpgradeRequest["previous"];
  next: ProductionUpgradeRequest["next"];
  workerPid?: number;
  workerClaim?: ProductionUpgradeWorkerClaim;
  acceptedAt?: string;
  history?: Array<{ state: ProductionUpgradeState; at: string }>;
  pidAfter?: number;
  pm2Status?: string;
  cwd?: string;
  script?: string;
  localHealthStatus?: number;
  localDoctorStatus?: number;
  publicHealthStatus?: number;
  publicMetricsStatus?: number;
  unauthenticatedMcpStatus?: number;
  oauthScopes?: string[];
  runtimeCommit?: string;
  databasePreimages?: DatabasePreimages;
  runtimeSourceTree?: string;
  runtimeDist?: { files: number; sha256: string };
  manifestSha256?: string;
  manifestIdentity?: ReleaseIdentity;
  managementReadyUrl?: string;
  managementReadyStatus?: number;
  runtimeIdentity?: RuntimeIdentityEvidence;
  runtimeIdentityConfirmed?: boolean;
  configSchemaIdentity?: string;
  snapshotGroupPreimage?: SnapshotGroupManifest;
  connectorLifecycle?: {
    state: "CONNECTOR_ACTIVATION_PREPARED" | "ACTIVATED_PENDING_POSTCHECK" | "POST_ACTIVATION_VERIFIED";
    receiptId: string;
    tupleDigest: string;
    activationReceiptDigest?: string;
    activationProofDigest?: string;
    authorityReceiptDigest?: string;
    postActivationEvidenceDigest?: string;
    journalContentGeneration: string;
  };
  productionApproval?: ProductionUpgradeProducedApprovalArtifacts;
  finalizationState?: string;
  finalizationDigest?: string;
  failure?: ProductionUpgradeFailure;
  rollback?: Record<string, unknown>;
  error?: string;
}

interface ProductionUpgradeWorkerClaim {
  schemaVersion: 1;
  claimId: string;
  claimPath: string;
  transactionId: string;
  requestBindingDigest: string;
  pid: number;
  acquiredAt: string;
}

interface ImmutableBuildManifest extends ReleaseIdentity {
  manifestVersion: 2;
  payloadDigest: string;
  files: number;
  payloadFiles: string[];
  runtimeFiles: string[];
  runtime: {
    cwd: ".";
    entrypoint: "scripts/start-universal-broker-v2-production.sh";
    nodeEntrypoint: "dist/cli.js";
    dependencies: {
      mode: "external-node-modules-loader-v1";
      loader: "scripts/lib/runtime-dependency-loader.mjs";
      lockfile: "package-lock.json";
      lockfileSha256: string;
      packageJsonSha256: string;
      evidenceName: "RUNTIME-DEPENDENCIES.json";
    };
  };
  createdAt: string;
  nodeVersion: string;
  platform: string;
  forbiddenArtifactScan: "PASS";
  buildCapabilities: {
    productVersion: string;
    productProfile: "BASE_SINGLE_OWNER";
    schemaGeneration: string;
    authorityContractGeneration: string;
    supportedProfiles: ["BASE_SINGLE_OWNER"];
    supportedOperations: Record<string, readonly string[]>;
    resourceUriVersion: "v1";
    buildDigest: string;
    capabilityDigest: string;
  };
  migrationManifest: MigrationManifestEntry[];
  migrationManifestDigest: string;
}

interface ReleaseIdentity {
  sourceRevision: string;
  runtimeRevision: string;
  buildDigest: string;
  schemaGeneration: string;
  authorityContractGeneration: string;
  configSchemaIdentity: string;
}

interface RuntimeIdentityEvidence {
  productVersion: string;
  schemaGeneration: string;
  authorityContractGeneration: string;
  configDigest: string;
  sourceRevision: string;
  runtimeRevision: string;
  buildDigest: string;
  startedAt: string;
}

export interface ManifestBindingEvidence {
  manifest: ImmutableBuildManifest;
  manifestPath: string;
  manifestSha256: string;
  dependencyEvidencePath: string;
  dependencyEvidenceSha256: string;
  identity: ReleaseIdentity;
  managementReadyUrl: string;
}

export interface ProductionUpgradeLifecyclePrepared {
  state: "CONNECTOR_ACTIVATION_PREPARED";
  receiptId: string;
  tupleDigest: string;
  journalContentGeneration: string;
}

export interface ProductionUpgradeLifecyclePending {
  state: "ACTIVATED_PENDING_POSTCHECK";
  receiptId: string;
  tupleDigest: string;
  activationReceiptDigest: string;
  activationProofDigest: string;
  authorityReceiptDigest: string;
  journalContentGeneration: string;
}

export interface ProductionUpgradeLifecycleVerified {
  state: "POST_ACTIVATION_VERIFIED";
  receiptId: string;
  tupleDigest: string;
  activationReceiptDigest: string;
  activationProofDigest: string;
  authorityReceiptDigest: string;
  postActivationEvidenceDigest: string;
  journalContentGeneration: string;
}

/**
 * Production-legitimate dependency boundary between the process cutover worker
 * and the connector lifecycle kernel. Tests fault this boundary; production
 * uses the concrete manager and exposes no production fault-control surface.
 */
export interface ProductionUpgradeConnectorLifecycleFacade {
  prepare(): Promise<ProductionUpgradeLifecyclePrepared>;
  activateOrReconcile(): Promise<
    ProductionUpgradeLifecyclePending | ProductionUpgradeLifecycleVerified
  >;
  waitForPostActivationReceipt(): Promise<void>;
  verifyPostActivation(): Promise<ProductionUpgradeLifecycleVerified>;
  close(): void;
}

export interface ProductionUpgradeWorkerDependencies {
  publicFetch?: typeof fetch;
  preparePostSnapshot?(
    request: Readonly<ProductionUpgradeRequest>,
    snapshot: Readonly<SnapshotGroupManifest>,
    requestBindingDigest: string,
  ): Promise<ProductionUpgradeProducedApprovalArtifacts>;
  openConnectorLifecycle(
    request: Readonly<ProductionUpgradeRequest>,
    manifest: Readonly<ManifestBindingEvidence>,
  ): ProductionUpgradeConnectorLifecycleFacade;
  finalizeProduction?(
    request: Readonly<ProductionUpgradeRequest>,
    postActivation: Readonly<ProductionUpgradeLifecycleVerified>,
    runtimeEvidence: Readonly<Record<string, unknown>>,
  ): Promise<{ state: string; finalDigest: string }>;
  advanceFinalizationBeforeActivation?(
    request: Readonly<ProductionUpgradeRequest>,
    prepared: Readonly<ProductionUpgradeLifecyclePrepared>,
  ): Promise<void>;
  verifyFinalizedProduction?(
    request: Readonly<ProductionUpgradeRequest>,
    expectedFinalDigest: string,
  ): Promise<void> | void;
}

export function productionUpgradeWorkerDependencies(): ProductionUpgradeWorkerDependencies {
  return {
    async preparePostSnapshot(request, snapshot, requestBindingDigest) {
      prepareFinalizationStoreAfterSnapshot(request, snapshot, requestBindingDigest);
      return runPostSnapshotProductionApproval(request);
    },
    openConnectorLifecycle(request) {
      const lifecycle = request.connectorLifecycle;
      const approvalDirectory = lifecycle.releaseDriver.productionApprovalOutputDirectory;
      const manifestPath = join(approvalDirectory, "manifest.json");
      const productionActivationPrecheckPath = join(
        approvalDirectory,
        "production-activation-precheck.json",
      );
      const ownerApprovalPath = join(approvalDirectory, "owner-management-approval.json");
      const manifest = JSON.parse(readFileSync(manifestPath, "utf8")) as Record<string, unknown>;
      const approvalText = (key: string): string => {
        const value = manifest[key];
        if (typeof value !== "string" || value.length === 0) {
          throw new Error(`Production approval manifest is missing ${key}.`);
        }
        return value;
      };
      const artifact = (path: string) => ({
        path,
        sha256: `sha256:${createHash("sha256").update(readFileSync(path)).digest("hex")}`,
      });
      return new ConnectorActivationLifecycleManager({
        oauthDatabasePath: request.oauthDatabasePath,
        authorityDatabasePath: request.authorityDatabasePath,
        managementAuthorizationKeyRef: lifecycle.managementAuthorizationKeyRef,
        managementNonce: lifecycle.managementNonce,
        managementCorrelationId: lifecycle.managementCorrelationId,
        candidateIdentity: lifecycle.candidateIdentity,
        productionEnvironmentIdentityDigest: lifecycle.productionEnvironmentIdentityDigest,
        productionRouteIdentityDigest: lifecycle.productionRouteIdentityDigest,
        oauthResource: lifecycle.oauthResource,
        activation: {
          receiptId: approvalText("receiptId"),
          tupleDigest: approvalText("tupleDigest"),
          activePreimageDigest: approvalText("activePreimageDigest"),
          finalizationPlanDigest: approvalText("finalizationPlanDigest"),
        },
        preCutoverHostCanary: lifecycle.preCutoverHostCanary,
        stagingActivationPrecheck: lifecycle.stagingActivationPrecheck,
        productionActivationPrecheck: artifact(productionActivationPrecheckPath),
        ownerApproval: artifact(ownerApprovalPath),
        journal: lifecycle.journal,
        postActivation: lifecycle.postActivation,
      });
    },
    finalizeProduction: finalizeProductionUpgrade,
    advanceFinalizationBeforeActivation: advanceProductionFinalizationBeforeActivation,
    verifyFinalizedProduction(request, expectedFinalDigest) {
      const key = loadExistingManagementAuthorizationKey({
        keyRef: request.connectorLifecycle.managementAuthorizationKeyRef,
        stateDir: dirname(request.connectorLifecycle.managementAuthorizationKeyRef),
      });
      const finalization = readFinalizationStoreIdentity({
        storePath: request.connectorLifecycle.finalization.storePath,
        controlPath: request.connectorLifecycle.finalization.controlPath,
        key,
      });
      if (finalization.state !== "BASE_PROFILE_FINAL_PASS"
        || finalization.finalDigest !== expectedFinalDigest) {
        throw new Error("Persisted PASS differs from the keyed BASE profile finalization readback.");
      }
    },
  };
}

function prepareFinalizationStoreAfterSnapshot(
  request: Readonly<ProductionUpgradeRequest>,
  snapshot: Readonly<SnapshotGroupManifest>,
  requestBindingDigest: string,
): void {
  const finalization = request.connectorLifecycle.finalization;
  const key = loadExistingManagementAuthorizationKey({
    keyRef: request.connectorLifecycle.managementAuthorizationKeyRef,
    stateDir: dirname(request.connectorLifecycle.managementAuthorizationKeyRef),
  });
  if (key.keyId !== finalization.keyId) {
    throw new Error("Production finalization key does not match the v4 request binding.");
  }
  const draft = readFinalizationStoreIdentity({
    storePath: finalization.storePath,
    controlPath: finalization.controlPath,
    key,
  });
  const expectedDraft = finalization.preSnapshotIdentity;
  if (draft.state !== "DRAFT"
    || draft.storeId !== expectedDraft.storeId
    || draft.schemaVersion !== expectedDraft.schemaVersion
    || draft.revision !== expectedDraft.revision
    || draft.transactionId !== expectedDraft.transactionId
    || draft.contentGeneration !== expectedDraft.contentGeneration
    || draft.controlEpoch !== expectedDraft.controlEpoch
    || draft.controlTag !== expectedDraft.controlTag
    || draft.preSnapshotIdentityDigest !== expectedDraft.identityDigest) {
    throw new Error("Production finalization DRAFT identity changed before post-snapshot preparation.");
  }
  const candidateIdentityDigest = productionUpgradeCandidateIdentityDigest(
    request.connectorLifecycle.candidateIdentity,
  );
  if (snapshot.barrier.transactionId !== request.transactionId
    || snapshot.barrier.requestBindingDigest !== requestBindingDigest
    || request.snapshotGroup.barrier.candidateIdentityDigest !== candidateIdentityDigest) {
    throw new Error("Production finalization snapshot barrier differs from the exact v4 request.");
  }
  const input = {
    requestBindingDigest,
    candidateIdentityDigest,
    purpose: "production-upgrade-v4-post-snapshot",
  };
  const digestBytes = (value: Uint8Array | string): ProductionUpgradeSha256Digest => (
    `sha256:${createHash("sha256").update(value).digest("hex")}`
  );
  const releaseChecksumsPath = join(request.next.immutableRuntimeRoot, "SHA256SUMS");
  const predecision = JSON.parse(readFileSync(
    request.connectorLifecycle.releaseDriver.productionPredecisionEnvelope.path,
    "utf8",
  )) as { payload?: { ownerDecision?: { approvalId?: string } } };
  const activationApprovalId = predecision.payload?.ownerDecision?.approvalId;
  if (typeof activationApprovalId !== "string" || activationApprovalId.length === 0) {
    throw new Error("Production finalization cannot bind the owner activation approval.");
  }
  const preparedAt = new Date(Math.max(Date.now(), Date.parse(snapshot.capturedAt) + 1)).toISOString();
  const record = {
    schemaVersion: 2,
    state: "PREPARED",
    transactionId: request.transactionId,
    preparedAt,
    input,
    inputDigest: digestBytes(stableJson(input)),
    sourceRevision: request.next.commit,
    runtimeIdentity: request.next.manifest,
    immutableIdentity: request.connectorLifecycle.candidateIdentity,
    releasePackage: request.next.immutableRuntimeRoot,
    releaseManifestSha256: request.next.manifest.sha256,
    releaseChecksumsSha256: digestBytes(readFileSync(releaseChecksumsPath)),
    moduleClosureDigest: digestBytes(stableJson({
      releaseManifestSha256: request.next.manifest.sha256,
      releaseChecksumsSha256: digestBytes(readFileSync(releaseChecksumsPath)),
      runtimeIdentityDigest: request.connectorLifecycle.candidateIdentity.runtimeIdentityDigest,
    })),
    snapshotGroup: {
      manifest: {
        capturedAt: snapshot.capturedAt,
        groupDigest: snapshot.groupDigest,
        barrier: {
          transactionId: request.transactionId,
          requestBindingDigest,
          candidateIdentityDigest,
        },
      },
    },
    gateEvidence: {
      manifestPath: finalization.gateProducerTrustAnchor.path,
      manifestSha256: finalization.gateProducerTrustAnchor.sha256,
    },
    productionSources: {
      activation: {
        approvalId: activationApprovalId,
        receiptId: `pending-${request.transactionId}`,
        previousBindingId: null,
      },
    },
    destructivePlan: [],
    finalizationStore: draft,
  } as const;
  const committed = commitPreparedFinalization({
    storePath: finalization.storePath,
    controlPath: finalization.controlPath,
    key,
    record,
    now: () => preparedAt,
  });
  if (committed.identity.state !== "PREPARED"
    || committed.identity.transactionId !== request.transactionId
    || committed.identity.requestBindingDigest !== requestBindingDigest
    || committed.identity.candidateIdentityDigest !== candidateIdentityDigest
    || committed.identity.snapshotGroupDigest !== snapshot.groupDigest) {
    throw new Error("Production finalization PREPARED readback differs from the post-snapshot v4 transaction.");
  }
}

function runPostSnapshotProductionApproval(
  request: Readonly<ProductionUpgradeRequest>,
): ProductionUpgradeProducedApprovalArtifacts {
  const runtimeRoot = request.next.immutableRuntimeRoot;
  const driverPath = join(runtimeRoot, "scripts", "connector-activation-release-driver.mjs");
  const loaderPath = join(runtimeRoot, "scripts", "lib", "runtime-dependency-loader.mjs");
  const outputDirectory = request.connectorLifecycle.releaseDriver.productionApprovalOutputDirectory;
  const executed = spawnSync(process.execPath, [
    "--disable-warning=ExperimentalWarning",
    "--import", loaderPath,
    driverPath,
    "production-approve",
    "--request", request.connectorLifecycle.releaseDriver.productionPreparationRequest.path,
    "--output", outputDirectory,
  ], {
    cwd: runtimeRoot,
    encoding: "utf8",
    env: {
      ...process.env,
      DEVSPACE_RUNTIME_PACKAGE_ROOT: runtimeRoot,
      DEVSPACE_RUNTIME_DEPENDENCY_ROOT: request.next.runtimeDependencies.root,
    },
    maxBuffer: 4 * 1024 * 1024,
  });
  if (executed.status !== 0) {
    throw new Error(`Post-snapshot production approval failed: ${executed.stderr.trim() || executed.stdout.trim()}`);
  }
  const summary = JSON.parse(executed.stdout) as Record<string, unknown>;
  const artifact = (path: string): ProductionUpgradeProducedApprovalArtifacts["manifest"] => ({
    path,
    sha256: `sha256:${createHash("sha256").update(readFileSync(path)).digest("hex")}`,
  });
  const manifestPath = join(outputDirectory, "manifest.json");
  const productionActivationPrecheckPath = join(outputDirectory, "production-activation-precheck.json");
  const ownerManagementApprovalPath = join(outputDirectory, "owner-management-approval.json");
  if (summary.directoryPath !== outputDirectory
    || summary.manifestPath !== manifestPath
    || summary.productionActivationPrecheckPath !== productionActivationPrecheckPath
    || summary.ownerManagementApprovalPath !== ownerManagementApprovalPath) {
    throw new Error("Post-snapshot production approval summary returned foreign artifact paths.");
  }
  return {
    outputDirectory,
    manifest: artifact(manifestPath),
    productionActivationPrecheck: artifact(productionActivationPrecheckPath),
    ownerManagementApproval: artifact(ownerManagementApprovalPath),
    recordedAt: new Date().toISOString(),
  };
}

async function finalizeProductionUpgrade(
  request: Readonly<ProductionUpgradeRequest>,
  postActivation: Readonly<ProductionUpgradeLifecycleVerified>,
  runtimeEvidence: Readonly<Record<string, unknown>>,
): Promise<{ state: string; finalDigest: string }> {
  const finalization = request.connectorLifecycle.finalization;
  const key = loadExistingManagementAuthorizationKey({
    keyRef: request.connectorLifecycle.managementAuthorizationKeyRef,
    stateDir: dirname(request.connectorLifecycle.managementAuthorizationKeyRef),
  });
  const digest = (value: unknown): ProductionUpgradeSha256Digest => (
    `sha256:${createHash("sha256").update(stableJson(value)).digest("hex")}`
  );
  const gateNames = [
    "G00 PROFILE", "G01 SOURCE", "G02 STATIC", "G03 UNIT", "G04 PROTOCOL",
    "G05 FUNCTIONAL", "G06 SECURITY", "G07 DURABILITY", "G08 LOAD", "G09 PACKAGE",
    "G10 STAGING", "G11 HOST", "G12 CONNECTOR", "G13 CUTOVER", "G16 CLEANUP",
    "G17 FINALIZATION",
  ];
  const ledger = readFinalizationStoreLedger({
    storePath: finalization.storePath,
    controlPath: finalization.controlPath,
    key,
  });
  const profileEvent = ledger.events.find((event) => event.kind === "PROFILE_GATES_EVALUATED");
  const evaluation = profileEvent?.payload?.evaluation as Record<string, unknown> | undefined;
  if (!evaluation || !Array.isArray(evaluation.gateResults) || evaluation.gateResults.length !== 16) {
    throw new Error("Production finalization lacks the authenticated pre-activation gate evaluation.");
  }
  const preCutoverGateResults = evaluation.gateResults as Array<Record<string, unknown>>;
  const currentIdentity = readFinalizationStoreIdentity({
    storePath: finalization.storePath,
    controlPath: finalization.controlPath,
    key,
  });
  const baseTime = Math.max(Date.now(), Date.parse(currentIdentity.updatedAt) + 10);
  const at = (offset: number) => new Date(baseTime + offset).toISOString();
  const evidenceDirectory = join(request.auditDirectory, "finalization", "evidence");
  await mkdir(evidenceDirectory, { recursive: true, mode: 0o700 });
  await chmod(evidenceDirectory, 0o700);
  const preCutoverEvaluationArtifact = await writeFinalizationArtifact(
    evidenceDirectory,
    "pre-cutover-evaluation.json",
    evaluation,
  );
  const inventory = pm2Inventory(request);
  const canonicalProcessCount = inventory.filter((entry) => entry.name === request.pm2ProcessName).length;
  const legacyProcessNames = request.cutoverProcessNames.filter((name) => (
    name !== request.pm2ProcessName && inventory.some((entry) => entry.name === name)
  ));
  const currentAuditTarget = resolve(
    dirname(request.currentAuditLink),
    await readlink(request.currentAuditLink),
  );
  const installation = {
    activeBindingCount: 1,
    canonicalProcessCount,
    legacyProcessCount: legacyProcessNames.length,
    residuePaths: [] as string[],
    routeCount: 1,
  };
  const postActivationReadback = {
    installation,
    postActivation,
    runtimeEvidence,
  };
  const postActivationEvidenceDigest = digest(postActivationReadback);
  const postActivationProof = {
    schemaVersion: 1,
    kind: "POST_ACTIVATION_VERIFIED_PROOF",
    activatedAt: at(3),
    activationReceiptId: postActivation.receiptId,
    postActivationEvidenceDigest,
    gateResult: {
      profile: "BASE_SINGLE_OWNER",
      gate: "G13 CUTOVER",
      applicability: "REQUIRED",
      result: "PASS",
      evidenceDigest: postActivationEvidenceDigest,
    },
    readback: postActivationReadback,
  };
  const postActivationProofArtifact = await writeFinalizationArtifact(
    evidenceDirectory,
    "post-activation-proof.json",
    postActivationProof,
  );
  commitPostActivationVerified({
    storePath: finalization.storePath,
    controlPath: finalization.controlPath,
    key,
    transactionId: request.transactionId,
    postActivationProofArtifact,
    now: () => at(3),
  });
  commitDraining({
    storePath: finalization.storePath,
    controlPath: finalization.controlPath,
    key,
    transactionId: request.transactionId,
    now: () => at(4),
  });
  const finalGateResults = preCutoverGateResults.map((entry, index) => index < 13 ? entry : ({
    profile: "BASE_SINGLE_OWNER",
    gate: gateNames[index],
    applicability: "REQUIRED",
    result: "PASS",
    evidenceDigest: index === 13
      ? postActivationEvidenceDigest
      : digest({ gate: gateNames[index], runtimeEvidence, postActivation, installation, currentAuditTarget }),
  }));
  const residueEvidence = {
    canonicalProcessCount,
    currentAuditTarget,
    legacyProcessNames,
    residuePaths: [] as string[],
    routeCount: 1,
  };
  const residueEvidenceDigest = digest(residueEvidence);
  const sealInputDigest = digest({
    request: productionUpgradeRequestBindingDigest(request),
    postActivationProofArtifact,
    preCutoverEvaluationArtifact,
    runtimeEvidence,
  });
  const finalArtifactsDigest = digest({
    postActivationProofArtifact,
    preCutoverEvaluationArtifact,
    releaseManifestSha256: request.next.manifest.sha256,
  });
  const sealProof = {
    schemaVersion: 1,
    kind: "FINALIZATION_SEAL_PROOF",
    sealedAt: at(5),
    sealInputDigest,
    finalArtifactsDigest,
    finalGateResults,
    finalGateResultsDigest: digest(finalGateResults),
    residueEvidence,
    residueEvidenceDigest,
  };
  const sealProofArtifact = await writeFinalizationArtifact(
    evidenceDirectory,
    "finalization-seal-proof.json",
    sealProof,
  );
  commitCanonicalFinalizationSeal({
    storePath: finalization.storePath,
    controlPath: finalization.controlPath,
    key,
    transactionId: request.transactionId,
    sealProofArtifact,
    now: () => at(5),
  });
  const finalReport = {
    schemaVersion: 1,
    status: "BASE_PROFILE_FINAL_PASS",
    transactionId: request.transactionId,
    completedAt: at(6),
    gateResults: finalGateResults,
    gateResultsDigest: digest(finalGateResults),
    runtimeEvidence,
    postActivation,
    residueEvidence,
  };
  const finalManifest = {
    schemaVersion: 1,
    transactionId: request.transactionId,
    finalArtifactsDigest,
    finalGateResultsDigest: digest(finalGateResults),
    residueEvidenceDigest,
    releaseManifestDigest: request.next.manifest.sha256,
    sealProofArtifact,
  };
  const finalReportArtifact = await writeFinalizationArtifact(
    evidenceDirectory,
    "final-report.json",
    finalReport,
  );
  const finalManifestArtifact = await writeFinalizationArtifact(
    evidenceDirectory,
    "final-manifest.json",
    finalManifest,
  );
  const finalReportDigest = digest(finalReport);
  const finalManifestDigest = digest(finalManifest);
  const finalDigest = digest({ finalManifestDigest, finalReportDigest, sealInputDigest });
  const finalPassProof = {
    schemaVersion: 1,
    kind: "BASE_PROFILE_FINAL_PASS_PROOF",
    completedAt: at(6),
    finalDigest,
    finalManifest,
    finalManifestDigest,
    finalReport,
    finalReportDigest,
  };
  const finalPassProofArtifact = await writeFinalizationArtifact(
    evidenceDirectory,
    "base-profile-final-pass-proof.json",
    finalPassProof,
  );
  const completed = commitBaseProfileFinalPass({
    storePath: finalization.storePath,
    controlPath: finalization.controlPath,
    key,
    transactionId: request.transactionId,
    finalPassProofArtifact,
    now: () => at(6),
  });
  await writeFinalizationArtifact(evidenceDirectory, "artifact-index.json", {
    schemaVersion: 1,
    transactionId: request.transactionId,
    artifacts: [
      preCutoverEvaluationArtifact,
      postActivationProofArtifact,
      sealProofArtifact,
      finalReportArtifact,
      finalManifestArtifact,
      finalPassProofArtifact,
    ],
    finalDigest,
  });
  return { state: completed.identity.state, finalDigest };
}

async function advanceProductionFinalizationBeforeActivation(
  request: Readonly<ProductionUpgradeRequest>,
  prepared: Readonly<ProductionUpgradeLifecyclePrepared>,
): Promise<void> {
  const finalization = request.connectorLifecycle.finalization;
  const key = loadExistingManagementAuthorizationKey({
    keyRef: request.connectorLifecycle.managementAuthorizationKeyRef,
    stateDir: dirname(request.connectorLifecycle.managementAuthorizationKeyRef),
  });
  const anchorBytes = readFileSync(finalization.gateProducerTrustAnchor.path);
  if (`sha256:${createHash("sha256").update(anchorBytes).digest("hex")}`
    !== finalization.gateProducerTrustAnchor.sha256) {
    throw new Error("Finalization gate-producer trust anchor bytes changed.");
  }
  const anchorEnvelope = JSON.parse(anchorBytes.toString("utf8")) as {
    payload?: { ownerInstanceId?: string; environment?: string };
  };
  const ownerInstanceId = anchorEnvelope.payload?.ownerInstanceId;
  const environment = anchorEnvelope.payload?.environment;
  if (typeof ownerInstanceId !== "string" || typeof environment !== "string") {
    throw new Error("Finalization gate-producer trust anchor scope is missing.");
  }
  const trustedAnchor = verifyGateProducerTrustAnchor({
    path: finalization.gateProducerTrustAnchor.path,
    sha256: finalization.gateProducerTrustAnchor.sha256,
    key,
    expectedOwnerInstanceId: ownerInstanceId,
    expectedEnvironment: environment,
  });
  const releaseInspection = inspectVerifiedReleaseGateLedger(
    request.next.immutableRuntimeRoot,
    {
      gateProducerTrustAnchor: trustedAnchor,
      expectedSourceRevision: request.next.commit,
      expectedRuntimeRevision: request.next.manifest.runtimeRevision,
    },
  );
  if (releaseInspection.release.status !== "PASS") {
    throw new Error("Pre-activation finalization requires an attested release PASS.");
  }
  const digest = (value: unknown): ProductionUpgradeSha256Digest => (
    `sha256:${createHash("sha256").update(stableJson(value)).digest("hex")}`
  );
  const releaseGates = [
    "G00 PROFILE", "G01 SOURCE", "G02 STATIC", "G03 UNIT", "G04 PROTOCOL",
    "G05 FUNCTIONAL", "G06 SECURITY", "G07 DURABILITY", "G08 LOAD",
  ];
  const receipts = releaseInspection.ledger.payload.receipts;
  const gateResults: Array<Record<string, unknown>> = releaseGates.map((gate) => {
    const binding = releaseInspection.ledger.payload.gateBindings[gate];
    if (!binding || !Array.isArray(binding.receiptIds) || binding.receiptIds.length === 0) {
      throw new Error(`Attested release ledger lacks ${gate} receipt bindings.`);
    }
    const boundReceipts = binding.receiptIds.map((id) => receipts.find((receipt) => receipt.id === id));
    if (boundReceipts.some((receipt) => !receipt || receipt.exitCode !== 0 || receipt.signal !== null)) {
      throw new Error(`Attested release ledger contains a non-PASS receipt for ${gate}.`);
    }
    return {
      profile: "BASE_SINGLE_OWNER", gate, applicability: "REQUIRED", result: "PASS",
      evidenceDigest: digest({
        producerLedgerPayloadDigest: releaseInspection.ledger.payloadDigest,
        gate,
        binding,
        receipts: boundReceipts,
      }),
    };
  });
  gateResults.push({
    profile: "BASE_SINGLE_OWNER", gate: "G09 PACKAGE", applicability: "REQUIRED", result: "PASS",
    evidenceDigest: digest({
      manifestSha256: releaseInspection.release.manifestSha256,
      buildDigest: releaseInspection.release.buildDigest,
      producer: releaseInspection.gateProducer,
    }),
  });
  gateResults.push({
    profile: "BASE_SINGLE_OWNER", gate: "G10 STAGING", applicability: "REQUIRED", result: "PASS",
    evidenceDigest: digest({
      stagingActivationPrecheck: request.connectorLifecycle.stagingActivationPrecheck,
      candidateIdentity: request.connectorLifecycle.candidateIdentity,
    }),
  });
  gateResults.push({
    profile: "BASE_SINGLE_OWNER", gate: "G11 HOST", applicability: "REQUIRED", result: "PASS",
    evidenceDigest: digest({
      preCutoverHostCanary: request.connectorLifecycle.preCutoverHostCanary,
      stagingActivationPrecheck: request.connectorLifecycle.stagingActivationPrecheck,
    }),
  });
  const approvalDirectory = request.connectorLifecycle.releaseDriver.productionApprovalOutputDirectory;
  const productionApprovalArtifacts = [
    "manifest.json", "production-activation-precheck.json", "owner-management-approval.json",
  ].map((name) => {
    const path = join(approvalDirectory, name);
    const bytes = readFileSync(path);
    return { path, sha256: `sha256:${createHash("sha256").update(bytes).digest("hex")}` };
  });
  gateResults.push({
    profile: "BASE_SINGLE_OWNER", gate: "G12 CONNECTOR", applicability: "REQUIRED", result: "PASS",
    evidenceDigest: digest({ prepared, productionApprovalArtifacts }),
  });
  gateResults.push(
    { profile: "BASE_SINGLE_OWNER", gate: "G13 CUTOVER", applicability: "REQUIRED", result: "NOT_RUN" },
    { profile: "BASE_SINGLE_OWNER", gate: "G16 CLEANUP", applicability: "REQUIRED", result: "NOT_RUN" },
    { profile: "BASE_SINGLE_OWNER", gate: "G17 FINALIZATION", applicability: "REQUIRED", result: "NOT_RUN" },
  );
  const capabilities: Array<Record<string, unknown>> = [
    "source-runtime-build-profile-identity", "one-production-process-route", "health-ready-doctor",
    "unauthenticated-mcp-401", "public-management-blocked", "exact-eight-tools", "canonical-active-one",
    "fresh-host-discovery", "cross-session-harmless-mutation", "local-target-read-write-exec-process-mcp-artifact",
    "self-restart-transaction", "all-store-consistent-snapshot",
  ].map((capability) => ({
    profile: "BASE_SINGLE_OWNER", capability, applicability: "REQUIRED", result: "PASS",
    evidenceDigest: digest({ capability, gateResults: gateResults.slice(0, 13) }),
  }));
  capabilities.push({
    profile: "BASE_SINGLE_OWNER", capability: "no-residue", applicability: "REQUIRED", result: "NOT_RUN",
  });
  for (const profile of ["MULTI_USER", "SIDECAR_AUTHORITY", "HOST_ATTESTED", "GUI_CAPTURE"]) {
    capabilities.push({
      profile, capability: `${profile.toLowerCase()}-profile`, applicability: "NOT_APPLICABLE", result: "NOT_APPLICABLE",
    });
  }
  const profileApplicability = [
    { profile: "BASE_SINGLE_OWNER", applicability: "REQUIRED" },
    { profile: "MULTI_USER", applicability: "NOT_APPLICABLE" },
    { profile: "SIDECAR_AUTHORITY", applicability: "NOT_APPLICABLE" },
    { profile: "HOST_ATTESTED", applicability: "NOT_APPLICABLE" },
    { profile: "GUI_CAPTURE", applicability: "NOT_APPLICABLE" },
  ];
  const evaluation = {
    thresholdDigest: digest({ profile: "BASE_SINGLE_OWNER", source: "attested-release-and-verified-live-artifacts-v1" }),
    manifestBindingDigest: digest({
      releaseManifestSha256: request.next.manifest.sha256,
      packageSha256: request.connectorLifecycle.candidateIdentity.packageSha256,
      transactionId: request.transactionId,
    }),
    gateResults,
    gateResultsDigest: digest(gateResults),
    capabilities,
    capabilitiesDigest: digest(capabilities),
    profileApplicability,
    profileApplicabilityDigest: digest(profileApplicability),
  };
  const identity = readFinalizationStoreIdentity({
    storePath: finalization.storePath,
    controlPath: finalization.controlPath,
    key,
  });
  const baseTime = Math.max(Date.now(), Date.parse(identity.updatedAt) + 10);
  await commitProfileGatesEvaluated({
    storePath: finalization.storePath,
    controlPath: finalization.controlPath,
    key,
    transactionId: request.transactionId,
    evaluation,
    now: () => new Date(baseTime + 1).toISOString(),
  });
  commitActivationPending({
    storePath: finalization.storePath,
    controlPath: finalization.controlPath,
    key,
    transactionId: request.transactionId,
    activationBinding: {
      approvalId: readPreparedApprovalId(request),
      receiptId: prepared.receiptId,
    },
    now: () => new Date(baseTime + 2).toISOString(),
  });
}

async function writeFinalizationArtifact(
  directory: string,
  name: string,
  value: unknown,
): Promise<{ path: string; sha256: ProductionUpgradeSha256Digest }> {
  const path = join(directory, name);
  const bytes = Buffer.from(`${JSON.stringify(value, null, 2)}\n`);
  try {
    const existing = await readFile(path);
    if (!existing.equals(bytes)) {
      throw new Error(`Finalization artifact replay differs: ${path}`);
    }
  } catch (error) {
    if (!isNodeError(error, "ENOENT")) throw error;
    const handle = await open(path, "wx", 0o600);
    try {
      await handle.writeFile(bytes);
      await handle.sync();
    } finally {
      await handle.close();
    }
    await chmod(path, 0o600);
    await fsyncDirectoryPath(directory);
  }
  return {
    path,
    sha256: `sha256:${createHash("sha256").update(bytes).digest("hex")}`,
  };
}

function readPreparedApprovalId(request: Readonly<ProductionUpgradeRequest>): string {
  const envelope = JSON.parse(readFileSync(
    request.connectorLifecycle.releaseDriver.productionPredecisionEnvelope.path,
    "utf8",
  )) as { payload?: { ownerDecision?: { approvalId?: string } } };
  const value = envelope.payload?.ownerDecision?.approvalId;
  if (typeof value !== "string" || value.length === 0) throw new Error("Owner activation approvalId is missing.");
  return value;
}

interface RuntimeDependencyEvidence {
  manifestVersion: 1;
  installMode: "npm-ci-lockfile-v1";
  packageManifestSha256: string;
  packageJsonSha256: string;
  lockfileSha256: string;
  nodeVersion: string;
  platform: string;
  nodeModules: {
    files: number;
    directories: number;
    symlinks: number;
    sha256: string;
  };
}

class ProductionUpgradeFailureError extends Error {
  readonly failure: ProductionUpgradeFailure;

  constructor(failure: ProductionUpgradeFailure) {
    super(failure.message);
    this.name = "ProductionUpgradeFailureError";
    this.failure = failure;
  }
}

interface Pm2ProcessSnapshot {
  name?: string;
  pid?: number;
  pm2_env?: {
    status?: string;
    pm_cwd?: string;
    pm_exec_path?: string;
  };
}

const TRANSACTION_PATTERN = /^upgrade_[0-9a-f-]{36}$/u;
const UNIVERSAL_TOOL_NAMES = Object.freeze([
  "target", "context", "fs", "exec", "process", "mcp", "artifact", "gui",
] as const);
const GENERATED_SCHEMA_FILES = Object.freeze([
  "config.schema.json",
  "config/config.schema.json",
  "contracts/tools-v2.schema.json",
  "contracts/build-capabilities.schema.json",
] as const);
const REQUIRED_READINESS_CHECKS = Object.freeze([
  "config_build_capabilities",
  "non_root",
  "required_store_migrations",
  "authority_artifact_readability",
  "target_route_generation",
  "cursor_signing",
  "canonical_connector",
  "supervisor_control",
  "rate_limit_identity",
  "management_isolation",
  "audit_sink",
  "runtime_contract_identity",
] as const);
const REQUIRED_DEEP_DOCTOR_CHECKS = Object.freeze([
  "authority_claim_receipt",
  "connector_consistency",
  "pm2_uniqueness",
  "public_metrics_negative_probe",
  "artifact_reconciliation",
  "migration_manifest_scan",
  "mutable_snapshot_capability",
  "rate_canary",
  "stale_lease_nonterminal_report",
  "runtime_identity_readback",
] as const);
const REQUIRED_BASE_SNAPSHOT_STORES = Object.freeze([
  { id: "oauth-main-and-connector-state", kind: "sqlite" },
  { id: "authority-store", kind: "sqlite" },
  { id: "contexts-store", kind: "file" },
  { id: "process-metadata", kind: "directory" },
  { id: "process-output", kind: "directory" },
  { id: "filesystem-sync", kind: "sqlite" },
  { id: "artifact-catalog", kind: "sqlite" },
  { id: "artifact-cas", kind: "directory" },
  { id: "artifact-quarantine", kind: "directory" },
  { id: "pagination-current-signing-key", kind: "file" },
  { id: "lifecycle-finalization-store", kind: "sqlite" },
  { id: "runtime-environment", kind: "file" },
  { id: "process-manager-definition", kind: "file" },
  { id: "public-route", kind: "file" },
  { id: "target-route-generation-config", kind: "file" },
] as const satisfies ReadonlyArray<{ id: string; kind: SnapshotGroupEntryRequest["kind"] }>);
const FORWARD_CUTOVER_STATES: readonly ProductionUpgradeState[] = Object.freeze([
  "PREPARED",
  "ACCEPTED",
  "PREFLIGHT_VERIFIED",
  "CUTOVER_STOP_REQUESTED",
  "CUTOVER_PROCESSES_STOPPED",
  "STATE_SNAPSHOTTED",
  "CONNECTOR_ACTIVATION_PREPARED",
  "ACTIVATED_PENDING_POSTCHECK",
  "RUNTIME_STARTED",
  "POST_SWITCH_VERIFIED",
  "POST_ACTIVATION_VERIFIED",
  "PASS",
]);
const ROLLBACK_CONTROL_EVENTS = Object.freeze([
  "ROLLBACK_REQUESTED",
  "ROLLBACK_RESTORE_VERIFIED",
  "ROLLBACK_RESTORE_UNKNOWN",
  "ROLLBACK_RUNTIME_VERIFIED",
  "ROLLBACK_RUNTIME_UNKNOWN",
] as const);
type RollbackControlEvent = (typeof ROLLBACK_CONTROL_EVENTS)[number];

interface RollbackControlRecord extends Record<string, unknown> {
  schemaVersion: 1;
  event: RollbackControlEvent;
  transactionId: string;
  requestBindingDigest: string;
}

interface RollbackRequestedRecord extends RollbackControlRecord {
  event: "ROLLBACK_REQUESTED";
  snapshotGroupDigest: string | null;
  activationReceiptId: string | null;
  activationReceiptDigest: string | null;
  requestedAt: string;
  failureCode: ProductionUpgradeFailureCode;
}

function hasReached(
  observed: ProductionUpgradeState,
  expected: ProductionUpgradeState,
): boolean {
  const observedIndex = FORWARD_CUTOVER_STATES.indexOf(observed);
  const expectedIndex = FORWARD_CUTOVER_STATES.indexOf(expected);
  return observedIndex >= 0 && expectedIndex >= 0 && observedIndex >= expectedIndex;
}

async function initializeOrResumeStatus(
  request: ProductionUpgradeRequest,
  requestBindingDigest: string,
  acceptedAt: string,
  workerClaim: ProductionUpgradeWorkerClaim,
  dependencies: ProductionUpgradeWorkerDependencies,
): Promise<ProductionUpgradeStatus> {
  let existing: unknown;
  try {
    await assertOwnerOnlyRegularFile(request.statusPath, "production upgrade status");
    existing = JSON.parse(await readFile(request.statusPath, "utf8"));
  } catch (error) {
    if (!isNodeError(error, "ENOENT")) throw error;
  }
  if (existing !== undefined) {
    if (!isRecord(existing)
      || existing.version !== 2
      || existing.transactionId !== request.transactionId
      || existing.requestBindingDigest !== requestBindingDigest
      || existing.requestedAt !== request.requestedAt
      || existing.expectedDisconnect !== true
      || stableJson(existing.previous) !== stableJson(request.previous)
      || stableJson(existing.next) !== stableJson(request.next)
      || !PRODUCTION_UPGRADE_STATES.includes(existing.state as ProductionUpgradeState)) {
      throw new Error("Existing production upgrade status does not match the exact v4 request binding.");
    }
    const state = existing.state as ProductionUpgradeState;
    if (["FAIL", "UNKNOWN", "ROLLED_BACK", "ROLLBACK_UNKNOWN"].includes(state)) {
      throw new Error(`Production upgrade transaction is terminal or rollback-bound at ${state}; it cannot be replayed.`);
    }
    if (state === "PASS") {
      const passed = existing as ProductionUpgradeStatus;
      if (passed.connectorLifecycle?.state !== "POST_ACTIVATION_VERIFIED"
        || !isSha256Digest(passed.connectorLifecycle.activationReceiptDigest)
        || !isSha256Digest(passed.connectorLifecycle.activationProofDigest)
        || !isSha256Digest(passed.connectorLifecycle.authorityReceiptDigest)
        || !isSha256Digest(passed.connectorLifecycle.postActivationEvidenceDigest)
        || !Array.isArray(passed.history)
        || !passed.history.some((entry) => entry.state === "POST_ACTIVATION_VERIFIED")
        || passed.finalizationState !== "BASE_PROFILE_FINAL_PASS"
        || !isSha256Digest(passed.finalizationDigest)) {
        throw new Error("Legacy production upgrade status cannot claim PASS without exact POST activation evidence.");
      }
      await (dependencies.verifyFinalizedProduction
        ?? productionUpgradeWorkerDependencies().verifyFinalizedProduction!)(
        request,
        passed.finalizationDigest,
      );
      return passed;
    }
    if (state === "PREPARED") {
      if (!Array.isArray(existing.history)
        || existing.history.length !== 1
        || !isRecord(existing.history[0])
        || existing.history[0].state !== "PREPARED"
        || existing.history[0].at !== request.requestedAt) {
        throw new Error("Existing PREPARED status does not contain the exact request publication history.");
      }
      return {
        ...(existing as ProductionUpgradeStatus),
        state: "ACCEPTED",
        workerPid: process.pid,
        workerClaim,
        acceptedAt,
        updatedAt: acceptedAt,
        history: [...existing.history as Array<{ state: ProductionUpgradeState; at: string }>, {
          state: "ACCEPTED",
          at: acceptedAt,
        }],
      };
    }
    return {
      ...(existing as ProductionUpgradeStatus),
      workerPid: process.pid,
      workerClaim,
      updatedAt: acceptedAt,
    };
  }
  return {
    version: 2,
    transactionId: request.transactionId,
    requestBindingDigest,
    state: "ACCEPTED",
    requestedAt: request.requestedAt,
    updatedAt: acceptedAt,
    expectedDisconnect: true,
    previous: request.previous,
    next: request.next,
    workerPid: process.pid,
    workerClaim,
    acceptedAt,
    history: [
      { state: "PREPARED", at: request.requestedAt },
      { state: "ACCEPTED", at: acceptedAt },
    ],
  };
}

export function productionUpgradeLifecycleBindingDigest(
  request: Readonly<ProductionUpgradeRequest>,
): ProductionUpgradeSha256Digest {
  return contractProductionUpgradeLifecycleBindingDigest(request);
}

export function productionUpgradeRequestBindingDigest(
  request: Readonly<ProductionUpgradeRequest>,
): ProductionUpgradeSha256Digest {
  return contractProductionUpgradeRequestBindingDigest(request);
}

export async function runProductionUpgradeWorker(
  requestPath: string,
  dependencies?: ProductionUpgradeWorkerDependencies,
): Promise<void> {
  const request = await readRequest(requestPath);
  const requestBindingDigest = productionUpgradeRequestBindingDigest(request);
  await runIntegratedProductionUpgradeWorker(
    request,
    requestBindingDigest,
    dependencies ?? productionUpgradeWorkerDependencies(),
  );
}

async function runIntegratedProductionUpgradeWorker(
  request: ProductionUpgradeRequest,
  requestBindingDigest: ProductionUpgradeSha256Digest,
  dependencies: ProductionUpgradeWorkerDependencies,
): Promise<void> {
  await assertOwnerOnlyDirectory(request.auditDirectory, "production upgrade audit directory");
  await assertOwnerOnlyDirectory(dirname(request.statusPath), "production upgrade status directory");
  const workerClaim = await acquireProductionUpgradeWorkerClaim(request, requestBindingDigest);
  try {
    await runClaimedProductionUpgradeWorker(
      request,
      requestBindingDigest,
      workerClaim,
      dependencies,
    );
  } finally {
    await releaseProductionUpgradeWorkerClaim(workerClaim);
  }
}

async function runClaimedProductionUpgradeWorker(
  request: ProductionUpgradeRequest,
  requestBindingDigest: string,
  workerClaim: ProductionUpgradeWorkerClaim,
  dependencies: ProductionUpgradeWorkerDependencies,
): Promise<void> {
  const acceptedAt = new Date().toISOString();
  let status = await initializeOrResumeStatus(
    request,
    requestBindingDigest,
    acceptedAt,
    workerClaim,
    dependencies,
  );
  await writeStatus(request.statusPath, status);
  if (status.state === "ROLLBACK_REQUESTED" || status.state === "ROLLBACK_RESTORING") {
    await resumeProductionUpgradeRollback(request, status, requestBindingDigest);
    return;
  }
  if (status.state === "PASS") {
    try {
      const evidence = await verifyPersistedPassCurrentState(request, status, dependencies);
      status = {
        ...status,
        ...evidence,
        updatedAt: new Date().toISOString(),
      };
      await writeStatus(request.statusPath, status);
      return;
    } catch (error) {
      const failure = normalizeFailure(error, "VERIFYING");
      const unknownAt = new Date().toISOString();
      status = {
        ...status,
        state: "UNKNOWN",
        updatedAt: unknownAt,
        error: `Persisted PASS current-state verification failed: ${failure.message}`,
        failure,
        history: [...(status.history ?? []), { state: "UNKNOWN", at: unknownAt }],
      };
      await writeStatus(request.statusPath, status);
      throw new Error(`Persisted PASS current-state verification failed: ${failure.message}`, { cause: error });
    }
  }
  let phase: ProductionUpgradeFailurePhase = "PREFLIGHT";
  let cutoverProcessesStopped = hasReached(status.state, "CUTOVER_PROCESSES_STOPPED");
  let snapshotGroupPreimage = status.snapshotGroupPreimage;
  let lifecycle: ProductionUpgradeConnectorLifecycleFacade | undefined;
  try {
    const manifestBinding = await verifyManifestBinding(request);
    verifySqliteDatabase(request.oauthDatabasePath);
    verifySqliteDatabase(request.authorityDatabasePath);
    const snapshotGroup = requireCutoverSnapshotGroup(request);
    const recoveredSnapshotPreimage = await verifySnapshotCaptureBoundary(
      request,
      snapshotGroup,
      status,
      requestBindingDigest,
    );
    if (!snapshotGroupPreimage && recoveredSnapshotPreimage) {
      snapshotGroupPreimage = recoveredSnapshotPreimage;
    }
    await verifyConnectorLifecycleRequest(request, snapshotGroup.entries);
    await verifyRollbackHostChallengeRequest(request);
    await preflightRollbackControlJournal(request, requestBindingDigest);
    if (!hasReached(status.state, "CUTOVER_STOP_REQUESTED")) {
      await verifyPreCutoverCurrentRuntime(request, manifestBinding);
    }

    if (!hasReached(status.state, "PREFLIGHT_VERIFIED")) {
      status = await transition(request, status, "PREFLIGHT_VERIFIED");
    }

    await sleep(request.delayMs);
    phase = "SWITCHING";
    if (!cutoverProcessesStopped) {
      if (!hasReached(status.state, "CUTOVER_STOP_REQUESTED")) {
        status = await transition(request, status, "CUTOVER_STOP_REQUESTED");
      }
      stopCutoverProcesses(request);
      cutoverProcessesStopped = true;
      status = await transition(request, status, "CUTOVER_PROCESSES_STOPPED");
    } else if (!hasReached(status.state, "RUNTIME_STARTED")) {
      assertCutoverProcessesStopped(request);
    }

    if (!snapshotGroupPreimage) {
      if (hasReached(status.state, "STATE_SNAPSHOTTED")) {
        throw upgradeFailure(
          "SWITCH_FAILED",
          "SWITCHING",
          "Durable cutover state is missing its exact snapshot-group preimage.",
          false,
        );
      }
      snapshotGroupPreimage = await captureCutoverSnapshotGroup(
        request,
        snapshotGroup,
        requestBindingDigest,
        requireTransitionAt(status, "CUTOVER_PROCESSES_STOPPED"),
      );
      const databasePreimages = databasePreimagesFromSnapshot(snapshotGroupPreimage);
      status = await transition(request, {
        ...status,
        snapshotGroupPreimage,
        ...(databasePreimages ? { databasePreimages } : {}),
      }, "STATE_SNAPSHOTTED");
    } else {
      snapshotGroupPreimage = validateSnapshotGroupManifest(snapshotGroupPreimage);
      assertSnapshotMatchesRequest(
        snapshotGroupPreimage,
        snapshotGroup,
        request,
        requestBindingDigest,
        requireTransitionAt(status, "CUTOVER_PROCESSES_STOPPED"),
      );
      if (!hasReached(status.state, "STATE_SNAPSHOTTED")) {
        const databasePreimages = databasePreimagesFromSnapshot(snapshotGroupPreimage);
        status = await transition(request, {
          ...status,
          snapshotGroupPreimage,
          ...(databasePreimages ? { databasePreimages } : {}),
        }, "STATE_SNAPSHOTTED");
      }
    }

    phase = "CONNECTOR_ACTIVATION";
    if (!hasReached(status.state, "CONNECTOR_ACTIVATION_PREPARED")) {
      const productionApproval = dependencies.preparePostSnapshot
        ? await dependencies.preparePostSnapshot(request, snapshotGroupPreimage, requestBindingDigest)
        : undefined;
      const preparingLifecycle = dependencies.openConnectorLifecycle(request, manifestBinding);
      let prepared: ProductionUpgradeLifecyclePrepared;
      try {
        prepared = await preparingLifecycle.prepare();
      } finally {
        preparingLifecycle.close();
      }
      assertPreparedLifecycleMatchesRequest(prepared, request);
      status = await transition(request, {
        ...status,
        ...(productionApproval ? { productionApproval } : {}),
        connectorLifecycle: lifecycleStatus(prepared),
      }, "CONNECTOR_ACTIVATION_PREPARED");
    }
    lifecycle = dependencies.openConnectorLifecycle(request, manifestBinding);
    const reopenedPrepared = await lifecycle.prepare();
    assertPreparedLifecycleMatchesRequest(reopenedPrepared, request);
    await (dependencies.advanceFinalizationBeforeActivation
      ?? productionUpgradeWorkerDependencies().advanceFinalizationBeforeActivation!)(
      request,
      reopenedPrepared,
    );
    const activationReadback = await lifecycle.activateOrReconcile();
    const pending = activationReadback.state === "ACTIVATED_PENDING_POSTCHECK"
      ? activationReadback
      : undefined;
    const terminalPostReadback = activationReadback.state === "POST_ACTIVATION_VERIFIED"
      ? activationReadback
      : undefined;
    if (pending) {
      assertPendingLifecycleMatchesRequest(pending, request);
      if (!hasReached(status.state, "ACTIVATED_PENDING_POSTCHECK")) {
        status = await transition(request, {
          ...status,
          connectorLifecycle: lifecycleStatus(pending),
        }, "ACTIVATED_PENDING_POSTCHECK");
      } else {
        status = { ...status, connectorLifecycle: lifecycleStatus(pending) };
        await writeStatus(request.statusPath, status);
      }
    } else {
      assertVerifiedLifecycleMatchesRequest(terminalPostReadback!, request);
      if (!hasReached(status.state, "ACTIVATED_PENDING_POSTCHECK")) {
        throw upgradeFailure(
          "POST_ACTIVATION_FAILED",
          "POST_ACTIVATION",
          "Terminal connector POST evidence cannot substitute missing durable worker cutover phases.",
          false,
        );
      }
      status = { ...status, connectorLifecycle: lifecycleStatus(terminalPostReadback!) };
      await writeStatus(request.statusPath, status);
    }

    await installFile(request.nextEnvPath, request.productionEnvPath, 0o600);
    ensureCandidateRuntimeStarted(request);
    if (!hasReached(status.state, "RUNTIME_STARTED")) {
      status = await transition(request, status, "RUNTIME_STARTED");
    }
    phase = "VERIFYING";
    const evidence = await verifyNextRuntime(request, manifestBinding, dependencies.publicFetch);
    if (!hasReached(status.state, "POST_SWITCH_VERIFIED")) {
      status = await transition(request, { ...status, ...evidence }, "POST_SWITCH_VERIFIED");
    } else {
      status = { ...status, ...evidence };
      await writeStatus(request.statusPath, status);
    }

    phase = "POST_ACTIVATION";
    let postActivation: ProductionUpgradeLifecycleVerified;
    if (terminalPostReadback) {
      postActivation = terminalPostReadback;
      assertVerifiedLifecycleMatchesRequest(postActivation, request);
    } else {
      await lifecycle.waitForPostActivationReceipt();
      postActivation = await lifecycle.verifyPostActivation();
      assertVerifiedLifecycleMatchesPending(postActivation, pending!);
    }
    if (!hasReached(status.state, "POST_ACTIVATION_VERIFIED")) {
      status = await transition(request, {
        ...status,
        connectorLifecycle: lifecycleStatus(postActivation),
      }, "POST_ACTIVATION_VERIFIED");
    } else {
      status = { ...status, connectorLifecycle: lifecycleStatus(postActivation) };
      await writeStatus(request.statusPath, status);
    }

    await installStartScript(request);
    await replaceSymlink(request.currentAuditLink, request.auditDirectory);
    if (status.state !== "POST_ACTIVATION_VERIFIED"
      || status.connectorLifecycle?.state !== "POST_ACTIVATION_VERIFIED") {
      throw upgradeFailure(
        "POST_ACTIVATION_FAILED",
        "POST_ACTIVATION",
        "Legacy or incomplete upgrade state cannot transition to PASS.",
        false,
      );
    }
    await assertPersistedPassInstallationState(request);
    const finalization = await (dependencies.finalizeProduction ?? finalizeProductionUpgrade)(
      request,
      postActivation,
      evidence,
    );
    if (finalization.state !== "BASE_PROFILE_FINAL_PASS") {
      throw upgradeFailure(
        "POST_ACTIVATION_FAILED",
        "POST_ACTIVATION",
        `Lifecycle finalization did not reach BASE_PROFILE_FINAL_PASS: ${finalization.state}`,
        false,
      );
    }
    const passedAt = new Date().toISOString();
    status = {
      ...status,
      state: "PASS",
      updatedAt: passedAt,
      history: [...(status.history ?? []), { state: "PASS", at: passedAt }],
      finalizationState: finalization.state,
      finalizationDigest: finalization.finalDigest,
      ...evidence,
    };
    await writeStatus(request.statusPath, status);
  } catch (error) {
    const failure = normalizeFailure(error, phase);
    if (!cutoverProcessesStopped && hasReached(status.state, "CUTOVER_STOP_REQUESTED")) {
      try {
        assertCutoverProcessesStopped(request);
        cutoverProcessesStopped = true;
        if (!hasReached(status.state, "CUTOVER_PROCESSES_STOPPED")) {
          status = await transition(request, status, "CUTOVER_PROCESSES_STOPPED");
        }
      } catch {
        // Keep the durable stop intent resumable until every named process is observed absent.
      }
      const interruptedAt = new Date().toISOString();
      status = {
        ...status,
        updatedAt: interruptedAt,
        error: failure.message,
        failure,
        rollback: {
          attempted: false,
          restored: false,
          verified: false,
          outcome: "STOP_BARRIER_INCOMPLETE_RETRY_REQUIRED",
        },
      };
      await writeStatus(request.statusPath, status);
      throw error;
    }
    if (!cutoverProcessesStopped) {
      const failedAt = new Date().toISOString();
      status = {
        ...status,
        state: "FAIL",
        updatedAt: failedAt,
        error: failure.message,
        failure,
        rollback: {
          attempted: false,
          restored: false,
          verified: false,
          outcome: "NOT_REQUIRED_SWITCH_NOT_STARTED",
        },
        history: [...(status.history ?? []), { state: "FAIL", at: failedAt }],
      };
      await writeStatus(request.statusPath, status);
      throw error;
    }
    const activation = status.connectorLifecycle?.state === "ACTIVATED_PENDING_POSTCHECK"
      || status.connectorLifecycle?.state === "POST_ACTIVATION_VERIFIED"
      ? status.connectorLifecycle
      : undefined;
    const rollbackRequested: RollbackRequestedRecord = {
      schemaVersion: 1,
      event: "ROLLBACK_REQUESTED",
      transactionId: request.transactionId,
      requestBindingDigest,
      snapshotGroupDigest: snapshotGroupPreimage?.groupDigest ?? null,
      activationReceiptId: activation?.receiptId ?? null,
      activationReceiptDigest: activation?.activationReceiptDigest ?? null,
      requestedAt: new Date().toISOString(),
      failureCode: failure.code,
    };
    let durableRollbackRequested = rollbackRequested;
    try {
      durableRollbackRequested = await ensureRollbackRequestedRecord(
        request.rollbackJournalPath,
        rollbackRequested,
      );
    } catch (controlError) {
      await failRollbackControlPlane(
        request,
        status,
        failure,
        error,
        controlError,
      );
    }
    lifecycle?.close();
    lifecycle = undefined;
    try {
      stopCutoverProcesses(request);
      status = await transition(request, {
        ...status,
        error: failure.message,
        failure,
      }, "ROLLBACK_REQUESTED");
      status = await transition(request, status, "ROLLBACK_RESTORING");
    } catch (controlError) {
      await failRollbackControlPlane(
        request,
        status,
        failure,
        error,
        controlError,
        undefined,
        true,
      );
    }
    const rollback = await rollbackRuntime(request, snapshotGroupPreimage);
    const terminalAt = new Date().toISOString();
    const restoreEvent = rollback.verified === true
      ? "ROLLBACK_RESTORE_VERIFIED" as const
      : "ROLLBACK_RESTORE_UNKNOWN" as const;
    try {
      await appendRollbackRecord(request.rollbackJournalPath, {
        schemaVersion: 1,
        event: restoreEvent,
        transactionId: request.transactionId,
        requestBindingDigest,
        snapshotGroupDigest: snapshotGroupPreimage?.groupDigest ?? null,
        activationReceiptId: activation?.receiptId ?? null,
        activationReceiptDigest: activation?.activationReceiptDigest ?? null,
        recordedAt: terminalAt,
        evidenceDigest: sha256Digest(stableJson(rollback)),
      });
    } catch (controlError) {
      await failRollbackControlPlane(
        request,
        status,
        failure,
        error,
        controlError,
        rollback,
        true,
      );
    }
    let terminalState: ProductionUpgradeState = "ROLLBACK_UNKNOWN";
    let finalRollback = rollback;
    if (rollback.verified === true) {
      try {
        finalRollback = await startAndVerifyPreviousRuntime(
          request,
          rollback,
          Date.parse(durableRollbackRequested.requestedAt),
        );
      } catch (controlError) {
        await failRollbackControlPlane(
          request,
          status,
          failure,
          error,
          controlError,
          rollback,
          true,
        );
      }
      terminalState = finalRollback.verified === true ? "ROLLED_BACK" : "ROLLBACK_UNKNOWN";
    }
    try {
      await appendRollbackRecord(request.rollbackJournalPath, {
        schemaVersion: 1,
        event: terminalState === "ROLLED_BACK"
          ? "ROLLBACK_RUNTIME_VERIFIED"
          : "ROLLBACK_RUNTIME_UNKNOWN",
        transactionId: request.transactionId,
        requestBindingDigest,
        snapshotGroupDigest: snapshotGroupPreimage?.groupDigest ?? null,
        activationReceiptId: activation?.receiptId ?? null,
        activationReceiptDigest: activation?.activationReceiptDigest ?? null,
        recordedAt: new Date().toISOString(),
        evidenceDigest: sha256Digest(stableJson(finalRollback)),
      });
    } catch (controlError) {
      await failRollbackControlPlane(
        request,
        status,
        failure,
        error,
        controlError,
        finalRollback,
        true,
      );
    }
    status = {
      ...status,
      state: terminalState,
      updatedAt: terminalAt,
      error: failure.message,
      failure,
      rollback: finalRollback,
      history: [...(status.history ?? []), { state: terminalState, at: terminalAt }],
    };
    await writeStatus(request.statusPath, status);
    throw error;
  } finally {
    lifecycle?.close();
    removeLaunchdJob(request.launchdLabel);
  }
}

async function resumeProductionUpgradeRollback(
  request: ProductionUpgradeRequest,
  initialStatus: ProductionUpgradeStatus,
  requestBindingDigest: string,
): Promise<void> {
  const configuredSnapshot = requireCutoverSnapshotGroup(request);
  if (!initialStatus.snapshotGroupPreimage) {
    throw new Error("Durable rollback status is missing its exact snapshot-group preimage.");
  }
  const snapshotGroupPreimage = validateSnapshotGroupManifest(initialStatus.snapshotGroupPreimage);
  assertSnapshotMatchesRequest(
    snapshotGroupPreimage,
    configuredSnapshot,
    request,
    requestBindingDigest,
    requireTransitionAt(initialStatus, "CUTOVER_PROCESSES_STOPPED"),
  );
  const snapshotManifestPath = join(configuredSnapshot.snapshotRoot, "SNAPSHOT-GROUP.json");
  await assertOwnerOnlyRegularFile(snapshotManifestPath, "rollback snapshot manifest");
  const diskSnapshot = validateSnapshotGroupManifest(
    JSON.parse(await readFile(snapshotManifestPath, "utf8")) as SnapshotGroupManifest,
  );
  if (stableJson(diskSnapshot) !== stableJson(snapshotGroupPreimage)) {
    throw new Error("Durable rollback status and snapshot manifest readback differ.");
  }

  let records = await readRollbackControlRecords(
    request.rollbackJournalPath,
    request.transactionId,
    requestBindingDigest,
  );
  const requested = records[0];
  if (!requested || requested.event !== "ROLLBACK_REQUESTED") {
    throw new Error("Durable rollback state has no matching rollback-request tombstone.");
  }
  const requestedRecord = requested as RollbackRequestedRecord;
  const activation = initialStatus.connectorLifecycle?.state === "ACTIVATED_PENDING_POSTCHECK"
    || initialStatus.connectorLifecycle?.state === "POST_ACTIVATION_VERIFIED"
    ? initialStatus.connectorLifecycle
    : undefined;
  const expectedActivationReceiptId = activation?.receiptId ?? null;
  const expectedActivationReceiptDigest = activation?.activationReceiptDigest ?? null;
  if (requestedRecord.snapshotGroupDigest !== snapshotGroupPreimage.groupDigest
    || requestedRecord.activationReceiptId !== expectedActivationReceiptId
    || requestedRecord.activationReceiptDigest !== expectedActivationReceiptDigest
    || initialStatus.failure?.code !== requestedRecord.failureCode) {
    throw new Error(
      "Durable rollback request does not match the current snapshot, activation, and failure boundary.",
    );
  }
  for (const record of records.slice(1)) {
    if (record.snapshotGroupDigest !== requested.snapshotGroupDigest
      || record.activationReceiptId !== requested.activationReceiptId
      || record.activationReceiptDigest !== requested.activationReceiptDigest) {
      throw new Error("Rollback terminal evidence is not bound to the durable rollback request.");
    }
  }
  const requestHistory = initialStatus.history?.filter(
    (entry) => entry.state === "ROLLBACK_REQUESTED",
  ) ?? [];
  const restoreHistory = initialStatus.history?.filter(
    (entry) => entry.state === "ROLLBACK_RESTORING",
  ) ?? [];
  if (requestHistory.length !== 1
    || (initialStatus.state === "ROLLBACK_REQUESTED" && (restoreHistory.length !== 0 || records.length !== 1))
    || (initialStatus.state === "ROLLBACK_RESTORING" && restoreHistory.length !== 1)) {
    throw new Error("Durable rollback status history does not match its journal phase.");
  }

  let status = initialStatus;
  stopCutoverProcesses(request);
  if (status.state === "ROLLBACK_REQUESTED") {
    status = await transition(request, status, "ROLLBACK_RESTORING");
  }

  const failure = status.failure!;
  const existingRestoreRecord = records[1];
  if (existingRestoreRecord?.event === "ROLLBACK_RESTORE_UNKNOWN") {
    const unknownRollback = {
      attempted: true,
      restored: false,
      verified: false,
      outcome: "RESTORATION_UNVERIFIED",
      error: "Durable rollback journal records an unknown snapshot restore; old runtime start is forbidden.",
      failure: {
        code: "ROLLBACK_FAILED" as const,
        phase: "ROLLING_BACK" as const,
        message: "Durable rollback journal records an unknown snapshot restore; old runtime start is forbidden.",
        retryable: false,
      },
    };
    if (!records[2]) {
      await appendRollbackRecord(request.rollbackJournalPath, {
        schemaVersion: 1,
        event: "ROLLBACK_RUNTIME_UNKNOWN",
        transactionId: request.transactionId,
        requestBindingDigest,
        snapshotGroupDigest: requestedRecord.snapshotGroupDigest,
        activationReceiptId: requestedRecord.activationReceiptId,
        activationReceiptDigest: requestedRecord.activationReceiptDigest,
        recordedAt: new Date().toISOString(),
        evidenceDigest: sha256Digest(stableJson(unknownRollback)),
      });
    } else if (records[2].event !== "ROLLBACK_RUNTIME_UNKNOWN") {
      throw new Error("Unknown restore cannot have verified runtime evidence.");
    }
    const terminalAt = new Date().toISOString();
    await assertProductionUpgradeStatusCasBase(request.statusPath, status);
    await writeStatus(request.statusPath, {
      ...status,
      state: "ROLLBACK_UNKNOWN",
      updatedAt: terminalAt,
      error: failure.message,
      failure,
      rollback: unknownRollback,
      history: [...(status.history ?? []), { state: "ROLLBACK_UNKNOWN", at: terminalAt }],
    });
    throw new Error(unknownRollback.error);
  }

  const rollback = await rollbackRuntime(request, snapshotGroupPreimage);
  const restoreEvent = rollback.verified === true
    ? "ROLLBACK_RESTORE_VERIFIED" as const
    : "ROLLBACK_RESTORE_UNKNOWN" as const;
  if (!existingRestoreRecord) {
    await appendRollbackRecord(request.rollbackJournalPath, {
      schemaVersion: 1,
      event: restoreEvent,
      transactionId: request.transactionId,
      requestBindingDigest,
      snapshotGroupDigest: requestedRecord.snapshotGroupDigest,
      activationReceiptId: requestedRecord.activationReceiptId,
      activationReceiptDigest: requestedRecord.activationReceiptDigest,
      recordedAt: new Date().toISOString(),
      evidenceDigest: sha256Digest(stableJson(rollback)),
    });
    records = await readRollbackControlRecords(
      request.rollbackJournalPath,
      request.transactionId,
      requestBindingDigest,
    );
  } else if (existingRestoreRecord.event !== restoreEvent) {
    throw new Error("Current snapshot restore does not agree with durable rollback restore evidence.");
  }

  let finalRollback = rollback;
  if (rollback.verified === true) {
    finalRollback = await startAndVerifyPreviousRuntime(
      request,
      rollback,
      Date.parse(requestedRecord.requestedAt),
      true,
    );
  }
  const terminalState: ProductionUpgradeState = finalRollback.verified === true
    ? "ROLLED_BACK"
    : "ROLLBACK_UNKNOWN";
  const runtimeEvent = terminalState === "ROLLED_BACK"
    ? "ROLLBACK_RUNTIME_VERIFIED" as const
    : "ROLLBACK_RUNTIME_UNKNOWN" as const;
  const existingRuntimeRecord = records[2];
  if (!existingRuntimeRecord) {
    await appendRollbackRecord(request.rollbackJournalPath, {
      schemaVersion: 1,
      event: runtimeEvent,
      transactionId: request.transactionId,
      requestBindingDigest,
      snapshotGroupDigest: requestedRecord.snapshotGroupDigest,
      activationReceiptId: requestedRecord.activationReceiptId,
      activationReceiptDigest: requestedRecord.activationReceiptDigest,
      recordedAt: new Date().toISOString(),
      evidenceDigest: sha256Digest(stableJson(finalRollback)),
    });
  } else if (existingRuntimeRecord.event !== runtimeEvent) {
    throw new Error("Current previous-runtime verification does not agree with durable rollback evidence.");
  }

  const terminalAt = new Date().toISOString();
  await assertProductionUpgradeStatusCasBase(request.statusPath, status);
  await writeStatus(request.statusPath, {
    ...status,
    state: terminalState,
    updatedAt: terminalAt,
    error: failure.message,
    failure,
    rollback: finalRollback,
    history: [...(status.history ?? []), { state: terminalState, at: terminalAt }],
  });
  if (terminalState !== "ROLLED_BACK") {
    throw new Error(finalRollback.error ?? "Previous runtime rollback verification remained unknown.");
  }
}

function lifecycleStatus(
  evidence:
    | ProductionUpgradeLifecyclePrepared
    | ProductionUpgradeLifecyclePending
    | ProductionUpgradeLifecycleVerified,
): NonNullable<ProductionUpgradeStatus["connectorLifecycle"]> {
  return {
    state: evidence.state,
    receiptId: evidence.receiptId,
    tupleDigest: evidence.tupleDigest,
    ...(evidence.state === "CONNECTOR_ACTIVATION_PREPARED" ? {} : {
      activationReceiptDigest: evidence.activationReceiptDigest,
      activationProofDigest: evidence.activationProofDigest,
      authorityReceiptDigest: evidence.authorityReceiptDigest,
    }),
    ...(evidence.state === "POST_ACTIVATION_VERIFIED"
      ? { postActivationEvidenceDigest: evidence.postActivationEvidenceDigest }
      : {}),
    journalContentGeneration: evidence.journalContentGeneration,
  };
}

function assertPreparedLifecycleMatchesRequest(
  prepared: ProductionUpgradeLifecyclePrepared,
  _request: ProductionUpgradeRequest,
): void {
  if (prepared.state !== "CONNECTOR_ACTIVATION_PREPARED"
    || !/^connector-activation-[0-9a-f-]{36}$/u.test(prepared.receiptId)
    || !isSha256Digest(prepared.tupleDigest)
    || !isSha256Digest(prepared.journalContentGeneration)) {
    throw upgradeFailure(
      "CONNECTOR_ACTIVATION_FAILED",
      "PREFLIGHT",
      "Connector lifecycle preparation did not produce an exact server-derived receipt, tuple, and journal readback.",
      false,
    );
  }
}

function assertPendingLifecycleMatchesRequest(
  pending: ProductionUpgradeLifecyclePending,
  _request: ProductionUpgradeRequest,
): void {
  if (pending.state !== "ACTIVATED_PENDING_POSTCHECK"
    || !/^connector-activation-[0-9a-f-]{36}$/u.test(pending.receiptId)
    || !isSha256Digest(pending.tupleDigest)
    || !isSha256Digest(pending.activationReceiptDigest)
    || !isSha256Digest(pending.activationProofDigest)
    || !isSha256Digest(pending.authorityReceiptDigest)
    || !isSha256Digest(pending.journalContentGeneration)) {
    throw upgradeFailure(
      "CONNECTOR_ACTIVATION_FAILED",
      "CONNECTOR_ACTIVATION",
      "Connector activation did not produce the exact durable pending-postcheck evidence.",
      false,
    );
  }
}

function assertVerifiedLifecycleMatchesPending(
  verified: ProductionUpgradeLifecycleVerified,
  pending: ProductionUpgradeLifecyclePending,
): void {
  if (verified.state !== "POST_ACTIVATION_VERIFIED"
    || verified.receiptId !== pending.receiptId
    || verified.tupleDigest !== pending.tupleDigest
    || verified.activationReceiptDigest !== pending.activationReceiptDigest
    || verified.activationProofDigest !== pending.activationProofDigest
    || verified.authorityReceiptDigest !== pending.authorityReceiptDigest
    || !isSha256Digest(verified.postActivationEvidenceDigest)
    || !isSha256Digest(verified.journalContentGeneration)) {
    throw upgradeFailure(
      "POST_ACTIVATION_FAILED",
      "POST_ACTIVATION",
      "Post-activation verification did not continue the exact pending connector activation.",
      false,
    );
  }
}

function assertVerifiedLifecycleMatchesRequest(
  verified: ProductionUpgradeLifecycleVerified,
  _request: ProductionUpgradeRequest,
): void {
  if (verified.state !== "POST_ACTIVATION_VERIFIED"
    || !/^connector-activation-[0-9a-f-]{36}$/u.test(verified.receiptId)
    || !isSha256Digest(verified.tupleDigest)
    || !isSha256Digest(verified.activationReceiptDigest)
    || !isSha256Digest(verified.activationProofDigest)
    || !isSha256Digest(verified.authorityReceiptDigest)
    || !isSha256Digest(verified.postActivationEvidenceDigest)
    || !isSha256Digest(verified.journalContentGeneration)) {
    throw upgradeFailure(
      "POST_ACTIVATION_FAILED",
      "POST_ACTIVATION",
      "Terminal connector lifecycle readback does not match the exact request-bound activation.",
      false,
    );
  }
}

async function verifyPersistedPassCurrentState(
  request: ProductionUpgradeRequest,
  status: ProductionUpgradeStatus,
  dependencies: ProductionUpgradeWorkerDependencies,
): Promise<Awaited<ReturnType<typeof verifyNextRuntime>>> {
  const manifestBinding = await verifyManifestBinding(request);
  verifySqliteDatabase(request.oauthDatabasePath);
  verifySqliteDatabase(request.authorityDatabasePath);
  const snapshotGroup = requireCutoverSnapshotGroup(request);
  await verifyConnectorLifecycleRequest(request, snapshotGroup.entries, true);
  await verifyRollbackHostChallengeRequest(request, true);
  await preflightRollbackControlJournal(
    request,
    productionUpgradeRequestBindingDigest(request),
  );

  if (!status.snapshotGroupPreimage) {
    throw new Error("Persisted PASS is missing its exact snapshot-group preimage.");
  }
  const persistedSnapshot = validateSnapshotGroupManifest(status.snapshotGroupPreimage);
  assertSnapshotMatchesRequest(
    persistedSnapshot,
    snapshotGroup,
    request,
    productionUpgradeRequestBindingDigest(request),
    requireTransitionAt(status, "CUTOVER_PROCESSES_STOPPED"),
  );
  const snapshotPath = join(snapshotGroup.snapshotRoot, "SNAPSHOT-GROUP.json");
  const diskSnapshot = validateSnapshotGroupManifest(
    JSON.parse(await readFile(snapshotPath, "utf8")) as SnapshotGroupManifest,
  );
  if (stableJson(diskSnapshot) !== stableJson(persistedSnapshot)) {
    throw new Error("Persisted PASS snapshot-group readback differs from durable disk state.");
  }

  const lifecycle = dependencies.openConnectorLifecycle(request, manifestBinding);
  try {
    const prepared = await lifecycle.prepare();
    assertPreparedLifecycleMatchesRequest(prepared, request);
    const activationReadback = await lifecycle.activateOrReconcile();
    let verified: ProductionUpgradeLifecycleVerified;
    if (activationReadback.state === "POST_ACTIVATION_VERIFIED") {
      verified = activationReadback;
      assertVerifiedLifecycleMatchesRequest(verified, request);
    } else {
      assertPendingLifecycleMatchesRequest(activationReadback, request);
      verified = await lifecycle.verifyPostActivation();
      assertVerifiedLifecycleMatchesPending(verified, activationReadback);
    }
    const persistedLifecycle = status.connectorLifecycle;
    if (persistedLifecycle?.state !== "POST_ACTIVATION_VERIFIED"
      || persistedLifecycle.receiptId !== verified.receiptId
      || persistedLifecycle.tupleDigest !== verified.tupleDigest
      || persistedLifecycle.activationReceiptDigest !== verified.activationReceiptDigest
      || persistedLifecycle.activationProofDigest !== verified.activationProofDigest
      || persistedLifecycle.authorityReceiptDigest !== verified.authorityReceiptDigest
      || persistedLifecycle.postActivationEvidenceDigest !== verified.postActivationEvidenceDigest
      || persistedLifecycle.journalContentGeneration !== verified.journalContentGeneration) {
      throw new Error("Persisted PASS connector lifecycle differs from exact OAuth/authority/journal/POST readback.");
    }
    const evidence = await verifyNextRuntime(request, manifestBinding, dependencies.publicFetch);
    await assertPersistedPassInstallationState(request);
    return evidence;
  } finally {
    lifecycle.close();
  }
}

async function assertPersistedPassInstallationState(
  request: ProductionUpgradeRequest,
): Promise<void> {
  const inventory = pm2Inventory(request);
  const production = inventory.filter((process) => process.name === request.pm2ProcessName);
  if (production.length !== 1) {
    throw new Error(`Persisted PASS requires exactly one canonical PM2 runtime, observed ${production.length}.`);
  }
  const forbidden = request.cutoverProcessNames.filter((name) => (
    name !== request.pm2ProcessName
    && inventory.some((process) => process.name === name)
  ));
  if (forbidden.length > 0) {
    throw new Error(`Persisted PASS retains cutover process residue: ${forbidden.join(", ")}`);
  }
  if (await fileSha256(request.productionEnvPath) !== await fileSha256(request.nextEnvPath)) {
    throw new Error("Persisted PASS production environment differs from the immutable next environment.");
  }
  await assertOwnerOnlyRegularFile(request.startScriptPath, "canonical production start script");
  const startScript = await readFile(request.startScriptPath, "utf8");
  if (startScript !== productionStartScriptContent(request)) {
    throw new Error("Persisted PASS canonical start script does not launch the exact immutable runtime.");
  }
  const auditLink = await lstat(request.currentAuditLink);
  if (!auditLink.isSymbolicLink()) {
    throw new Error("Persisted PASS current audit pointer is not a symbolic link.");
  }
  const auditTarget = await readlink(request.currentAuditLink);
  if (resolve(dirname(request.currentAuditLink), auditTarget) !== resolve(request.auditDirectory)) {
    throw new Error("Persisted PASS current audit pointer does not select this transaction.");
  }
}

async function verifyNextRuntime(
  request: ProductionUpgradeRequest,
  manifestBinding: ManifestBindingEvidence,
  publicFetch: typeof fetch = fetch,
): Promise<Pick<ProductionUpgradeStatus,
  | "pidAfter"
  | "pm2Status"
  | "cwd"
  | "script"
  | "localHealthStatus"
  | "localDoctorStatus"
  | "publicHealthStatus"
  | "publicMetricsStatus"
  | "unauthenticatedMcpStatus"
  | "oauthScopes"
  | "runtimeCommit"
  | "runtimeSourceTree"
  | "runtimeDist"
  | "manifestSha256"
  | "manifestIdentity"
  | "managementReadyUrl"
  | "managementReadyStatus"
  | "runtimeIdentity"
  | "runtimeIdentityConfirmed"
  | "configSchemaIdentity"
>> {
  let runtimeCommit: string;
  let runtimeSourceTree: string;
  let runtimeDist: { files: number; sha256: string };
  try {
    runtimeCommit = gitValue(request, ["-C", request.next.sourceEvidenceRoot, "rev-parse", "HEAD"]);
    runtimeSourceTree = gitValue(request, ["-C", request.next.sourceEvidenceRoot, "rev-parse", "HEAD^{tree}"]);
    runtimeDist = await directoryEvidence(join(request.next.sourceEvidenceRoot, "dist"));
  } catch (error) {
    throw upgradeFailure(
      "RUNTIME_EQUIVALENCE_FAILED",
      "VERIFYING",
      `Runtime source evidence could not be read: ${errorMessage(error)}`,
      false,
    );
  }
  if (runtimeCommit !== request.next.commit) {
    throw upgradeFailure(
      "RUNTIME_EQUIVALENCE_FAILED",
      "VERIFYING",
      `Runtime commit mismatch: expected ${request.next.commit}, actual ${runtimeCommit}.`,
      false,
      { expected: request.next.commit, observed: runtimeCommit },
    );
  }
  if (runtimeSourceTree !== request.next.sourceTree) {
    throw upgradeFailure(
      "RUNTIME_EQUIVALENCE_FAILED",
      "VERIFYING",
      `Runtime source tree mismatch: expected ${request.next.sourceTree}, actual ${runtimeSourceTree}.`,
      false,
      { expected: request.next.sourceTree, observed: runtimeSourceTree },
    );
  }
  if (
    runtimeDist.files !== request.next.dist.files
    || runtimeDist.sha256 !== request.next.dist.sha256
  ) {
    throw upgradeFailure(
      "RUNTIME_EQUIVALENCE_FAILED",
      "VERIFYING",
      `Runtime dist fingerprint mismatch: expected ${JSON.stringify(request.next.dist)}, actual ${JSON.stringify(runtimeDist)}.`,
      false,
      { expected: request.next.dist, observed: runtimeDist },
    );
  }
  const deadline = Date.now() + request.timeoutMs;
  let lastError = upgradeFailure(
    "MANAGEMENT_NOT_READY",
    "VERIFYING",
    "Production upgrade verification did not run.",
    true,
  );
  while (Date.now() < deadline) {
    try {
      const process = pm2Process(request);
      if (!process) {
        throw upgradeFailure(
          "MANAGEMENT_NOT_READY",
          "VERIFYING",
          `PM2 process is missing: ${request.pm2ProcessName}`,
          true,
        );
      }
      if (process.pm2_env?.status !== "online") {
        throw upgradeFailure(
          "MANAGEMENT_NOT_READY",
          "VERIFYING",
          `PM2 status is ${process.pm2_env?.status ?? "unknown"}.`,
          true,
        );
      }
      const processCwd = process.pm2_env.pm_cwd;
      const processScript = process.pm2_env.pm_exec_path;
      if (!processCwd || resolve(processCwd) !== resolve(request.next.immutableRuntimeRoot)) {
        throw upgradeFailure(
          "RUNTIME_IDENTITY_MISMATCH",
          "VERIFYING",
          `PM2 cwd mismatch: ${processCwd ?? "missing"}`,
          false,
        );
      }
      if (!processScript || resolve(processScript) !== resolve(request.next.immutableRuntimeEntrypoint)) {
        throw upgradeFailure(
          "RUNTIME_IDENTITY_MISMATCH",
          "VERIFYING",
          `PM2 script mismatch: ${processScript ?? "missing"}`,
          false,
        );
      }
      const processPid = process.pid;
      if (typeof processPid !== "number" || !Number.isInteger(processPid) || processPid === request.previous.pid) {
        throw upgradeFailure(
          "RUNTIME_IDENTITY_MISMATCH",
          "VERIFYING",
          `PM2 PID did not change: ${processPid ?? "missing"}`,
          false,
        );
      }
      const ready = await readManagementReady(request, manifestBinding, {
        url: manifestBinding.managementReadyUrl,
        runtimeIdentityDigest: request.connectorLifecycle.candidateIdentity.runtimeIdentityDigest,
        releaseIdentity: manifestBinding.identity,
        buildCapabilityDigest: manifestBinding.manifest.buildCapabilities.capabilityDigest,
      });
      if (sha256Digest(stableJson(ready.identity))
        !== request.connectorLifecycle.candidateIdentity.runtimeIdentityDigest) {
        throw upgradeFailure(
          "RUNTIME_IDENTITY_MISMATCH",
          "VERIFYING",
          "Private readiness runtime identity digest does not match the connector candidate identity.",
          false,
        );
      }
      const localHealthStatus = await httpStatus(request.localHealthUrl);
      const doctor = await readDeepDoctor(request, manifestBinding, {
        runtimeIdentityDigest: request.connectorLifecycle.candidateIdentity.runtimeIdentityDigest,
        migrationManifestDigest: manifestBinding.manifest.migrationManifestDigest,
      });
      const localDoctorStatus = doctor.status;
      const publicHealthStatus = await httpStatus(request.publicHealthUrl, undefined, publicFetch);
      const publicMetricsStatus = await httpStatus(request.publicMetricsUrl, undefined, publicFetch);
      const unauthenticatedMcpStatus = await httpStatus(request.publicMcpUrl, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          jsonrpc: "2.0",
          id: 1,
          method: "initialize",
          params: {
            protocolVersion: "2025-06-18",
            capabilities: {},
            clientInfo: { name: "production-upgrade-worker", version: "1" },
          },
        }),
      }, publicFetch);
      const metadataResponse = await fetchWithTimeout(request.oauthMetadataUrl, undefined, publicFetch);
      const metadata = await metadataResponse.json() as { scopes_supported?: unknown };
      const oauthScopes = Array.isArray(metadata.scopes_supported)
        ? metadata.scopes_supported.filter((scope): scope is string => typeof scope === "string")
        : [];
      if (localHealthStatus !== 200) {
        throw publicBoundaryFailure(`Local health returned ${localHealthStatus}.`);
      }
      if (publicHealthStatus !== 200) {
        throw publicBoundaryFailure(`Public health returned ${publicHealthStatus}.`);
      }
      if (publicMetricsStatus !== 404) {
        throw publicBoundaryFailure(`Public metrics returned ${publicMetricsStatus}.`);
      }
      if (unauthenticatedMcpStatus !== 401) {
        throw publicBoundaryFailure(`Unauthenticated public MCP returned ${unauthenticatedMcpStatus}.`);
      }
      if (JSON.stringify(oauthScopes) !== JSON.stringify(request.expectedScopes)) {
        throw publicBoundaryFailure(`OAuth scopes mismatch: ${JSON.stringify(oauthScopes)}`);
      }
      if (oauthScopes.includes("devspace")) {
        throw publicBoundaryFailure("Legacy blanket OAuth scope remains advertised.");
      }
      const confirmedReady = await readManagementReady(request, manifestBinding, {
        url: manifestBinding.managementReadyUrl,
        runtimeIdentityDigest: request.connectorLifecycle.candidateIdentity.runtimeIdentityDigest,
        releaseIdentity: manifestBinding.identity,
        buildCapabilityDigest: manifestBinding.manifest.buildCapabilities.capabilityDigest,
      });
      if (!sameRuntimeIdentity(ready.identity, confirmedReady.identity)) {
        throw upgradeFailure(
          "RUNTIME_IDENTITY_MISMATCH",
          "VERIFYING",
          "Private readiness runtime identity changed during production verification.",
          false,
          { first: ready.identity, confirmed: confirmedReady.identity },
        );
      }
      await assertManifestUnchanged(manifestBinding);
      return {
        pidAfter: processPid,
        pm2Status: process.pm2_env.status,
        cwd: processCwd,
        script: processScript,
        localHealthStatus,
        localDoctorStatus,
        publicHealthStatus,
        publicMetricsStatus,
        unauthenticatedMcpStatus,
        oauthScopes,
        runtimeCommit,
        runtimeSourceTree,
        runtimeDist,
        manifestSha256: manifestBinding.manifestSha256,
        manifestIdentity: manifestBinding.identity,
        managementReadyUrl: manifestBinding.managementReadyUrl,
        managementReadyStatus: confirmedReady.status,
        runtimeIdentity: confirmedReady.identity,
        runtimeIdentityConfirmed: true,
        configSchemaIdentity: manifestBinding.identity.configSchemaIdentity,
      };
    } catch (error) {
      lastError = normalizeFailureError(error, "VERIFYING");
      const remaining = deadline - Date.now();
      if (remaining > 0) await sleep(Math.min(500, remaining));
    }
  }
  throw lastError;
}

async function verifyManifestBinding(
  request: ProductionUpgradeRequest,
): Promise<ManifestBindingEvidence> {
  const manifestPath = resolve(request.next.manifest.path);
  let manifestBytes: Buffer;
  try {
    const metadata = await lstat(manifestPath);
    if (!metadata.isFile() || metadata.isSymbolicLink()) {
      throw new Error("manifest is not a regular file");
    }
    if ((metadata.mode & 0o022) !== 0) {
      throw new Error(`manifest mode is writable by group or other: ${(metadata.mode & 0o777).toString(8)}`);
    }
    const uid = typeof process.getuid === "function" ? process.getuid() : undefined;
    if (uid !== undefined && metadata.uid !== uid) {
      throw new Error(`manifest owner uid ${metadata.uid} does not match worker uid ${uid}`);
    }
    manifestBytes = await readFile(manifestPath);
  } catch (error) {
    throw upgradeFailure(
      "MANIFEST_INVALID",
      "PREFLIGHT",
      `Immutable build manifest cannot be trusted: ${errorMessage(error)}`,
      false,
      { path: manifestPath },
    );
  }

  let parsed: unknown;
  try {
    parsed = JSON.parse(manifestBytes.toString("utf8"));
  } catch (error) {
    throw upgradeFailure(
      "MANIFEST_INVALID",
      "PREFLIGHT",
      `Immutable build manifest is not valid JSON: ${errorMessage(error)}`,
      false,
      { path: manifestPath },
    );
  }
  const manifest = validateBuildManifest(parsed, manifestPath);
  const requestIdentity = request.next.manifest;
  const manifestSha256 = `sha256:${createHash("sha256").update(manifestBytes).digest("hex")}`;
  if (requestIdentity.sha256 !== manifestSha256) {
    throw upgradeFailure(
      "MANIFEST_MISMATCH",
      "PREFLIGHT",
      `Immutable manifest digest mismatch: expected ${requestIdentity.sha256}, observed ${manifestSha256}.`,
      false,
      { expected: requestIdentity.sha256, observed: manifestSha256, path: manifestPath },
    );
  }
  const exactBindings: Array<[keyof ReleaseIdentity, string, string]> = [
    ["sourceRevision", request.next.commit, manifest.sourceRevision],
    ["runtimeRevision", requestIdentity.runtimeRevision, manifest.runtimeRevision],
    ["buildDigest", requestIdentity.buildDigest, manifest.buildDigest],
    ["schemaGeneration", requestIdentity.schemaGeneration, manifest.schemaGeneration],
    [
      "authorityContractGeneration",
      requestIdentity.authorityContractGeneration,
      manifest.authorityContractGeneration,
    ],
    ["configSchemaIdentity", requestIdentity.configSchemaIdentity, manifest.configSchemaIdentity],
  ];
  for (const [field, expected, observed] of exactBindings) {
    if (expected !== observed) {
      throw upgradeFailure(
        "MANIFEST_MISMATCH",
        "PREFLIGHT",
        `Immutable manifest ${field} mismatch: expected ${expected}, observed ${observed}.`,
        false,
        { field, expected, observed, path: manifestPath },
      );
    }
  }
  if (manifest.runtimeFiles.length !== request.next.dist.files) {
    throw upgradeFailure(
      "MANIFEST_MISMATCH",
      "PREFLIGHT",
      `Immutable manifest runtime file count mismatch: expected ${request.next.dist.files}, observed ${manifest.runtimeFiles.length}.`,
      false,
      { expected: request.next.dist.files, observed: manifest.runtimeFiles.length },
    );
  }

  const packageRoot = resolve(dirname(manifestPath));
  const expectedRuntimeRoot = resolve(packageRoot, manifest.runtime.cwd);
  const expectedRuntimeEntrypoint = resolve(packageRoot, manifest.runtime.entrypoint);
  if (resolve(request.next.immutableRuntimeRoot) !== expectedRuntimeRoot
    || resolve(request.next.immutableRuntimeEntrypoint) !== expectedRuntimeEntrypoint) {
    throw upgradeFailure(
      "MANIFEST_MISMATCH",
      "PREFLIGHT",
      "Production runtime cwd/entrypoint is not the immutable command bound by BUILD-MANIFEST.json.",
      false,
      {
        expectedRuntimeRoot,
        expectedRuntimeEntrypoint,
        observedRuntimeRoot: request.next.immutableRuntimeRoot,
        observedRuntimeEntrypoint: request.next.immutableRuntimeEntrypoint,
      },
    );
  }
  if (resolve(request.next.sourceEvidenceRoot) === expectedRuntimeRoot) {
    throw upgradeFailure(
      "MANIFEST_MISMATCH",
      "PREFLIGHT",
      "Git source evidence root must remain separate from the immutable runtime root.",
      false,
    );
  }
  const dependencyRoot = resolve(request.next.runtimeDependencies.root);
  if (canonicalPathsOverlap(dependencyRoot, expectedRuntimeRoot)) {
    throw upgradeFailure(
      "MANIFEST_MISMATCH",
      "PREFLIGHT",
      "Runtime dependency root must remain separate from the immutable package root.",
      false,
    );
  }

  let packagePayload: { files: number; sha256: string };
  try {
    packagePayload = await manifestRuntimeEvidence(expectedRuntimeRoot, manifest.payloadFiles);
  } catch (error) {
    throw upgradeFailure(
      "MANIFEST_MISMATCH",
      "PREFLIGHT",
      `Immutable package payload cannot be verified: ${errorMessage(error)}`,
      false,
    );
  }
  if (packagePayload.files !== manifest.files || packagePayload.sha256 !== manifest.payloadDigest) {
    throw upgradeFailure(
      "MANIFEST_MISMATCH",
      "PREFLIGHT",
      `Immutable package payload differs from BUILD-MANIFEST.json: expected ${manifest.payloadDigest}, observed ${packagePayload.sha256}.`,
      false,
    );
  }
  let generatedSchemaDigest: string;
  try {
    generatedSchemaDigest = (await manifestRuntimeEvidence(
      expectedRuntimeRoot,
      [...GENERATED_SCHEMA_FILES],
    )).sha256;
  } catch (error) {
    throw upgradeFailure(
      "MANIFEST_MISMATCH",
      "PREFLIGHT",
      `Immutable generated-schema tree cannot be verified: ${errorMessage(error)}`,
      false,
    );
  }
  const candidateIdentity = request.connectorLifecycle.candidateIdentity;
  for (const [field, expected, observed] of [
    ["buildCapabilityManifestDigest", manifest.buildCapabilities.capabilityDigest, candidateIdentity.buildCapabilityManifestDigest],
    ["generatedSchemaDigest", generatedSchemaDigest, candidateIdentity.generatedSchemaDigest],
    ["packageSha256", manifest.payloadDigest, candidateIdentity.packageSha256],
  ] as const) {
    if (expected !== observed) {
      throw upgradeFailure(
        "MANIFEST_MISMATCH",
        "PREFLIGHT",
        `Connector candidate immutable identity mismatch for ${field}: expected ${expected}, observed ${observed}.`,
        false,
        { field, expected, observed },
      );
    }
  }

  let runtimeBuild: { files: number; sha256: string };
  try {
    runtimeBuild = await manifestRuntimeEvidence(request.next.immutableRuntimeRoot, manifest.runtimeFiles);
  } catch (error) {
    if (error instanceof ProductionUpgradeFailureError) throw error;
    throw upgradeFailure(
      "MANIFEST_MISMATCH",
      "PREFLIGHT",
      `Immutable manifest runtime tree cannot be verified: ${errorMessage(error)}`,
      false,
    );
  }
  if (runtimeBuild.sha256 !== manifest.buildDigest) {
    throw upgradeFailure(
      "MANIFEST_MISMATCH",
      "PREFLIGHT",
      `Immutable manifest build digest mismatch: expected ${manifest.buildDigest}, observed ${runtimeBuild.sha256}.`,
      false,
      { expected: manifest.buildDigest, observed: runtimeBuild.sha256 },
    );
  }
  const sourceBuild = await manifestRuntimeEvidence(request.next.sourceEvidenceRoot, manifest.runtimeFiles);
  if (sourceBuild.sha256 !== manifest.buildDigest) {
    throw upgradeFailure(
      "MANIFEST_MISMATCH",
      "PREFLIGHT",
      `Source evidence root differs from immutable release: expected ${manifest.buildDigest}, observed ${sourceBuild.sha256}.`,
      false,
    );
  }
  const dependencyEvidencePath = resolve(request.next.runtimeDependencies.evidencePath);
  if (dependencyEvidencePath !== resolve(
    request.next.runtimeDependencies.root,
    manifest.runtime.dependencies.evidenceName,
  )) {
    throw upgradeFailure(
      "MANIFEST_MISMATCH",
      "PREFLIGHT",
      "Runtime dependency evidence path is not canonical for its root.",
      false,
    );
  }
  let dependencyEvidence: Buffer;
  try {
    const dependencyRootMetadata = await lstat(dependencyRoot);
    const evidenceMetadata = await lstat(dependencyEvidencePath);
    if (!dependencyRootMetadata.isDirectory() || dependencyRootMetadata.isSymbolicLink()) {
      throw new Error("dependency root is not a real directory");
    }
    if (!evidenceMetadata.isFile() || evidenceMetadata.isSymbolicLink() || (evidenceMetadata.mode & 0o077) !== 0) {
      throw new Error("dependency evidence is not an owner-only regular file");
    }
    dependencyEvidence = await readFile(dependencyEvidencePath);
  } catch (error) {
    throw upgradeFailure(
      "MANIFEST_INVALID",
      "PREFLIGHT",
      `Runtime dependency evidence cannot be trusted: ${errorMessage(error)}`,
      false,
    );
  }
  const dependencyEvidenceSha256 = `sha256:${createHash("sha256").update(dependencyEvidence).digest("hex")}`;
  if (dependencyEvidenceSha256 !== request.next.runtimeDependencies.evidenceSha256) {
    throw upgradeFailure(
      "MANIFEST_MISMATCH",
      "PREFLIGHT",
      `Runtime dependency evidence digest mismatch: expected ${request.next.runtimeDependencies.evidenceSha256}, observed ${dependencyEvidenceSha256}.`,
      false,
    );
  }
  validateRuntimeDependencyEvidence(dependencyEvidence, manifest, manifestSha256);
  for (const [path, expected] of [
    ["package.json", manifest.runtime.dependencies.packageJsonSha256],
    [manifest.runtime.dependencies.lockfile, manifest.runtime.dependencies.lockfileSha256],
  ] as const) {
    let observed: string;
    try {
      observed = await fileSha256(join(dependencyRoot, path));
    } catch (error) {
      throw upgradeFailure(
        "MANIFEST_INVALID",
        "PREFLIGHT",
        `Runtime dependency input cannot be read: ${path}: ${errorMessage(error)}`,
        false,
      );
    }
    if (observed !== expected) {
      throw upgradeFailure(
        "MANIFEST_MISMATCH",
        "PREFLIGHT",
        `Runtime dependency input differs from the packaged contract: ${path}`,
        false,
        { path, expected, observed },
      );
    }
  }

  const environment = await readManagedEnvironment(request.nextEnvPath);
  assertEnvironmentBinding(environment, "DEVSPACE_RELEASE_MANIFEST", manifestPath);
  assertEnvironmentBinding(environment, "DEVSPACE_EXPECTED_RELEASE_MANIFEST_SHA256", manifestSha256);
  assertEnvironmentBinding(environment, "DEVSPACE_EXPECTED_SOURCE_REVISION", manifest.sourceRevision);
  assertEnvironmentBinding(environment, "DEVSPACE_EXPECTED_RUNTIME_REVISION", manifest.runtimeRevision);
  assertEnvironmentBinding(environment, "DEVSPACE_EXPECTED_BUILD_DIGEST", manifest.buildDigest);
  assertEnvironmentBinding(environment, "DEVSPACE_EXPECTED_SCHEMA_GENERATION", manifest.schemaGeneration);
  assertEnvironmentBinding(
    environment,
    "DEVSPACE_EXPECTED_AUTHORITY_CONTRACT_GENERATION",
    manifest.authorityContractGeneration,
  );
  assertEnvironmentBinding(
    environment,
    "DEVSPACE_EXPECTED_CONFIG_SCHEMA_IDENTITY",
    manifest.configSchemaIdentity,
  );
  assertEnvironmentBinding(environment, "DEVSPACE_SOURCE_REVISION", manifest.sourceRevision);
  assertEnvironmentBinding(environment, "DEVSPACE_RUNTIME_REVISION", manifest.runtimeRevision);
  assertEnvironmentBinding(environment, "DEVSPACE_BUILD_DIGEST", manifest.buildDigest);
  assertEnvironmentBinding(environment, "DEVSPACE_RUNTIME_PACKAGE_ROOT", request.next.immutableRuntimeRoot);
  assertEnvironmentBinding(environment, "DEVSPACE_RUNTIME_DEPENDENCY_ROOT", request.next.runtimeDependencies.root);
  assertEnvironmentBinding(environment, "DEVSPACE_RUNTIME_DEPENDENCY_EVIDENCE", dependencyEvidencePath);
  assertEnvironmentBinding(
    environment,
    "DEVSPACE_EXPECTED_RUNTIME_DEPENDENCY_EVIDENCE_SHA256",
    dependencyEvidenceSha256,
  );

  const managementHost = environment.DEVSPACE_NEXT_MANAGEMENT_HOST ?? "127.0.0.1";
  if (!["127.0.0.1", "::1", "localhost"].includes(managementHost)) {
    throw upgradeFailure(
      "MANIFEST_MISMATCH",
      "PREFLIGHT",
      `Next management host is not loopback-only: ${managementHost}`,
      false,
    );
  }
  const managementPort = Number(environment.DEVSPACE_NEXT_MANAGEMENT_PORT);
  if (!Number.isInteger(managementPort) || managementPort < 1 || managementPort > 65_535) {
    throw upgradeFailure(
      "MANIFEST_MISMATCH",
      "PREFLIGHT",
      `Next management port is invalid: ${environment.DEVSPACE_NEXT_MANAGEMENT_PORT ?? "missing"}`,
      false,
    );
  }
  const hostForUrl = managementHost === "::1" ? "[::1]" : managementHost;
  const managementReadyUrl = `http://${hostForUrl}:${managementPort}/readyz`;
  assertCanonicalManagementReadbackUrls(request, managementReadyUrl);
  const identity: ReleaseIdentity = {
    sourceRevision: manifest.sourceRevision,
    runtimeRevision: manifest.runtimeRevision,
    buildDigest: manifest.buildDigest,
    schemaGeneration: manifest.schemaGeneration,
    authorityContractGeneration: manifest.authorityContractGeneration,
    configSchemaIdentity: manifest.configSchemaIdentity,
  };
  return {
    manifest,
    manifestPath,
    manifestSha256,
    dependencyEvidencePath,
    dependencyEvidenceSha256,
    identity,
    managementReadyUrl,
  };
}

async function assertManifestUnchanged(binding: ManifestBindingEvidence): Promise<void> {
  let observed: string;
  try {
    observed = `sha256:${createHash("sha256").update(await readFile(binding.manifestPath)).digest("hex")}`;
  } catch (error) {
    throw upgradeFailure(
      "MANIFEST_MISMATCH",
      "VERIFYING",
      `Immutable build manifest could not be re-read: ${errorMessage(error)}`,
      false,
      { path: binding.manifestPath },
    );
  }
  if (observed !== binding.manifestSha256) {
    throw upgradeFailure(
      "MANIFEST_MISMATCH",
      "VERIFYING",
      `Immutable build manifest changed during production switch: expected ${binding.manifestSha256}, observed ${observed}.`,
      false,
      { path: binding.manifestPath, expected: binding.manifestSha256, observed },
    );
  }
  const packagePayload = await manifestRuntimeEvidence(
    dirname(binding.manifestPath),
    binding.manifest.payloadFiles,
  );
  if (packagePayload.sha256 !== binding.manifest.payloadDigest) {
    throw upgradeFailure(
      "MANIFEST_MISMATCH",
      "VERIFYING",
      `Immutable package payload changed during production switch: expected ${binding.manifest.payloadDigest}, observed ${packagePayload.sha256}.`,
      false,
    );
  }
  const dependencyObserved = await fileSha256(binding.dependencyEvidencePath);
  if (dependencyObserved !== binding.dependencyEvidenceSha256) {
    throw upgradeFailure(
      "MANIFEST_MISMATCH",
      "VERIFYING",
      `Runtime dependency evidence changed during production switch: expected ${binding.dependencyEvidenceSha256}, observed ${dependencyObserved}.`,
      false,
      { path: binding.dependencyEvidencePath, expected: binding.dependencyEvidenceSha256, observed: dependencyObserved },
    );
  }
}

function validateBuildManifest(value: unknown, path: string): ImmutableBuildManifest {
  if (!isRecord(value) || value.manifestVersion !== 2) {
    throw upgradeFailure(
      "MANIFEST_INVALID",
      "PREFLIGHT",
      `Unsupported immutable build manifest version: ${path}`,
      false,
    );
  }
  const requiredText = [
    "sourceRevision",
    "runtimeRevision",
    "buildDigest",
    "payloadDigest",
    "schemaGeneration",
    "authorityContractGeneration",
    "configSchemaIdentity",
    "createdAt",
    "nodeVersion",
    "platform",
  ] as const;
  for (const field of requiredText) {
    if (typeof value[field] !== "string" || value[field].length === 0) {
      throw upgradeFailure(
        "MANIFEST_INVALID",
        "PREFLIGHT",
        `Immutable build manifest field is invalid: ${field}`,
        false,
      );
    }
  }
  for (const field of [
    "buildDigest",
    "payloadDigest",
    "schemaGeneration",
    "authorityContractGeneration",
    "configSchemaIdentity",
  ] as const) {
    if (!isSha256Digest(value[field])) {
      throw upgradeFailure(
        "MANIFEST_INVALID",
        "PREFLIGHT",
        `Immutable build manifest digest is invalid: ${field}`,
        false,
      );
    }
  }
  if (!Number.isInteger(value.files) || (value.files as number) < 1) {
    throw upgradeFailure("MANIFEST_INVALID", "PREFLIGHT", "Immutable manifest file count is invalid.", false);
  }
  if (!isSafeManifestFileList(value.payloadFiles)) {
    throw upgradeFailure("MANIFEST_INVALID", "PREFLIGHT", "Immutable manifest payload file list is invalid.", false);
  }
  const payloadFiles = value.payloadFiles;
  if (
    !isSafeManifestFileList(value.runtimeFiles)
    || value.runtimeFiles.length < 1
    || value.runtimeFiles.some((runtimePath) => (
      !runtimePath.startsWith("dist/") || !payloadFiles.includes(runtimePath)
    ))
  ) {
    throw upgradeFailure("MANIFEST_INVALID", "PREFLIGHT", "Immutable manifest runtime file list is invalid.", false);
  }
  if (payloadFiles.length !== value.files || value.forbiddenArtifactScan !== "PASS") {
    throw upgradeFailure("MANIFEST_INVALID", "PREFLIGHT", "Immutable manifest package gate is invalid.", false);
  }
  if (!isRecord(value.runtime)
    || value.runtime.cwd !== "."
    || value.runtime.entrypoint !== "scripts/start-universal-broker-v2-production.sh"
    || value.runtime.nodeEntrypoint !== "dist/cli.js"
    || !isRecord(value.runtime.dependencies)
    || value.runtime.dependencies.mode !== "external-node-modules-loader-v1"
    || value.runtime.dependencies.loader !== "scripts/lib/runtime-dependency-loader.mjs"
    || value.runtime.dependencies.lockfile !== "package-lock.json"
    || value.runtime.dependencies.evidenceName !== "RUNTIME-DEPENDENCIES.json"
    || !isSha256Digest(value.runtime.dependencies.lockfileSha256)
    || !isSha256Digest(value.runtime.dependencies.packageJsonSha256)) {
    throw upgradeFailure("MANIFEST_INVALID", "PREFLIGHT", "Immutable manifest runtime command/dependency contract is invalid.", false);
  }
  for (const runtimePath of [
    value.runtime.entrypoint,
    value.runtime.nodeEntrypoint,
    value.runtime.dependencies.loader,
    value.runtime.dependencies.lockfile,
    "package.json",
  ]) {
    if (!payloadFiles.includes(runtimePath)) {
      throw upgradeFailure(
        "MANIFEST_INVALID",
        "PREFLIGHT",
        `Immutable manifest runtime path is not packaged: ${runtimePath}`,
        false,
      );
    }
  }
  if (!isRecord(value.buildCapabilities)
    || typeof value.buildCapabilities.productVersion !== "string"
    || value.buildCapabilities.productVersion.length < 1
    || value.buildCapabilities.productProfile !== "BASE_SINGLE_OWNER"
    || value.buildCapabilities.schemaGeneration !== value.schemaGeneration
    || value.buildCapabilities.authorityContractGeneration !== value.authorityContractGeneration
    || value.buildCapabilities.buildDigest !== value.buildDigest
    || value.buildCapabilities.resourceUriVersion !== "v1"
    || !isSha256Digest(value.buildCapabilities.capabilityDigest)
    || stableJson(value.buildCapabilities.supportedProfiles) !== stableJson(["BASE_SINGLE_OWNER"])
    || !isRecord(value.buildCapabilities.supportedOperations)
    || stableJson(Object.keys(value.buildCapabilities.supportedOperations).sort())
      !== stableJson([...UNIVERSAL_TOOL_NAMES].sort())) {
    throw upgradeFailure(
      "MANIFEST_INVALID",
      "PREFLIGHT",
      "Immutable manifest build-capability identity is invalid or advertises a non-Base surface.",
      false,
    );
  }
  for (const tool of UNIVERSAL_TOOL_NAMES) {
    const operations = value.buildCapabilities.supportedOperations[tool];
    if (!Array.isArray(operations)
      || operations.length < 1
      || operations.some((operation) => typeof operation !== "string" || operation.length < 1)
      || new Set(operations).size !== operations.length) {
      throw upgradeFailure(
        "MANIFEST_INVALID",
        "PREFLIGHT",
        `Immutable manifest build-capability operations are invalid for ${tool}.`,
        false,
      );
    }
  }
  const capabilityContract = {
    productVersion: value.buildCapabilities.productVersion,
    productProfile: value.buildCapabilities.productProfile,
    schemaGeneration: value.buildCapabilities.schemaGeneration,
    authorityContractGeneration: value.buildCapabilities.authorityContractGeneration,
    supportedProfiles: value.buildCapabilities.supportedProfiles,
    supportedOperations: value.buildCapabilities.supportedOperations,
    resourceUriVersion: value.buildCapabilities.resourceUriVersion,
  };
  if (sha256Digest(stableJson(capabilityContract)) !== value.buildCapabilities.capabilityDigest) {
    throw upgradeFailure(
      "MANIFEST_MISMATCH",
      "PREFLIGHT",
      "Immutable manifest build-capability digest does not match its canonical contract.",
      false,
    );
  }
  if (!Array.isArray(value.migrationManifest)
    || value.migrationManifest.length < 1
    || !isSha256Digest(value.migrationManifestDigest)) {
    throw upgradeFailure(
      "MANIFEST_INVALID",
      "PREFLIGHT",
      "Immutable manifest global migration identity is missing.",
      false,
    );
  }
  let observedMigrationManifestDigest: string;
  try {
    observedMigrationManifestDigest = migrationManifestDigest(
      value.migrationManifest as unknown as MigrationManifestEntry[],
    );
  } catch (error) {
    throw upgradeFailure(
      "MANIFEST_INVALID",
      "PREFLIGHT",
      `Immutable manifest global migration contract is invalid: ${errorMessage(error)}`,
      false,
    );
  }
  if (observedMigrationManifestDigest !== value.migrationManifestDigest) {
    throw upgradeFailure(
      "MANIFEST_MISMATCH",
      "PREFLIGHT",
      "Immutable manifest global migration digest does not match its canonical entries.",
      false,
    );
  }
  return value as unknown as ImmutableBuildManifest;
}

function validateRuntimeDependencyEvidence(
  encoded: Buffer,
  manifest: ImmutableBuildManifest,
  manifestSha256: string,
): RuntimeDependencyEvidence {
  let value: unknown;
  try {
    value = JSON.parse(encoded.toString("utf8"));
  } catch (error) {
    throw upgradeFailure(
      "MANIFEST_INVALID",
      "PREFLIGHT",
      `Runtime dependency evidence is not valid JSON: ${errorMessage(error)}`,
      false,
    );
  }
  if (!isRecord(value)
    || value.manifestVersion !== 1
    || value.installMode !== "npm-ci-lockfile-v1"
    || value.packageManifestSha256 !== manifestSha256
    || value.packageJsonSha256 !== manifest.runtime.dependencies.packageJsonSha256
    || value.lockfileSha256 !== manifest.runtime.dependencies.lockfileSha256
    || value.nodeVersion !== manifest.nodeVersion
    || value.platform !== manifest.platform
    || !isRecord(value.nodeModules)
    || !isNonNegativeInteger(value.nodeModules.files)
    || !isNonNegativeInteger(value.nodeModules.directories)
    || !isNonNegativeInteger(value.nodeModules.symlinks)
    || !isSha256Digest(value.nodeModules.sha256)) {
    throw upgradeFailure(
      "MANIFEST_MISMATCH",
      "PREFLIGHT",
      "Runtime dependency evidence is not bound to the immutable package manifest and lockfile.",
      false,
    );
  }
  return value as unknown as RuntimeDependencyEvidence;
}

function isNonNegativeInteger(value: unknown): value is number {
  return Number.isInteger(value) && (value as number) >= 0;
}

function isNonNegativeNumber(value: unknown): value is number {
  return typeof value === "number" && Number.isFinite(value) && value >= 0;
}

async function manifestRuntimeEvidence(
  releaseRoot: string,
  runtimeFiles: string[],
): Promise<{ files: number; sha256: string }> {
  const root = resolve(releaseRoot);
  const digest = createHash("sha256");
  for (const manifestPath of [...runtimeFiles].sort()) {
    const absolute = resolve(root, manifestPath);
    const contained = relative(root, absolute);
    if (
      contained === ""
      || contained === ".."
      || contained.startsWith(`..${sep}`)
      || isAbsolute(contained)
    ) {
      throw new Error(`runtime path escapes release root: ${manifestPath}`);
    }
    const metadata = await lstat(absolute);
    if (!metadata.isFile() || metadata.isSymbolicLink()) {
      throw new Error(`runtime path is not a regular file: ${manifestPath}`);
    }
    const content = await readFile(absolute);
    digest.update(manifestPath);
    digest.update("\0");
    digest.update(createHash("sha256").update(content).digest("hex"));
    digest.update("\n");
  }
  return { files: runtimeFiles.length, sha256: `sha256:${digest.digest("hex")}` };
}

async function readManagedEnvironment(path: string): Promise<Record<string, string>> {
  const tracked = new Set([
    "DEVSPACE_NEXT_MANAGEMENT_HOST",
    "DEVSPACE_NEXT_MANAGEMENT_PORT",
    "DEVSPACE_RELEASE_MANIFEST",
    "DEVSPACE_EXPECTED_RELEASE_MANIFEST_SHA256",
    "DEVSPACE_EXPECTED_SOURCE_REVISION",
    "DEVSPACE_EXPECTED_RUNTIME_REVISION",
    "DEVSPACE_EXPECTED_BUILD_DIGEST",
    "DEVSPACE_EXPECTED_SCHEMA_GENERATION",
    "DEVSPACE_EXPECTED_AUTHORITY_CONTRACT_GENERATION",
    "DEVSPACE_EXPECTED_CONFIG_SCHEMA_IDENTITY",
    "DEVSPACE_SOURCE_REVISION",
    "DEVSPACE_RUNTIME_REVISION",
    "DEVSPACE_BUILD_DIGEST",
    "DEVSPACE_RUNTIME_PACKAGE_ROOT",
    "DEVSPACE_RUNTIME_DEPENDENCY_ROOT",
    "DEVSPACE_RUNTIME_DEPENDENCY_EVIDENCE",
    "DEVSPACE_EXPECTED_RUNTIME_DEPENDENCY_EVIDENCE_SHA256",
  ]);
  let content: string;
  try {
    const metadata = await lstat(path);
    if (!metadata.isFile() || metadata.isSymbolicLink() || (metadata.mode & 0o077) !== 0) {
      throw new Error("next environment must be an owner-only regular file");
    }
    content = await readFile(path, "utf8");
  } catch (error) {
    throw upgradeFailure(
      "MANIFEST_INVALID",
      "PREFLIGHT",
      `Next production environment cannot be trusted: ${errorMessage(error)}`,
      false,
      { path },
    );
  }
  const values: Record<string, string> = {};
  for (const line of content.split(/\r?\n/u)) {
    const match = /^(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)=(.*)$/u.exec(line);
    if (!match || !tracked.has(match[1])) continue;
    const key = match[1];
    if (Object.hasOwn(values, key)) {
      throw upgradeFailure(
        "MANIFEST_INVALID",
        "PREFLIGHT",
        `Next production environment contains duplicate ${key}.`,
        false,
      );
    }
    values[key] = decodeShellWord(match[2], key);
  }
  return values;
}

function decodeShellWord(value: string, key: string): string {
  let output = "";
  let quote: "plain" | "single" | "double" = "plain";
  for (let index = 0; index < value.length; index += 1) {
    const character = value[index];
    if (quote === "single") {
      if (character === "'") quote = "plain";
      else output += character;
      continue;
    }
    if (quote === "double") {
      if (character === '"') {
        quote = "plain";
      } else if (character === "\\") {
        index += 1;
        if (index >= value.length) break;
        output += value[index];
      } else if (character === "$" || character === "`") {
        throw invalidEnvironmentWord(key);
      } else {
        output += character;
      }
      continue;
    }
    if (character === "'") {
      quote = "single";
    } else if (character === '"') {
      quote = "double";
    } else if (character === "\\") {
      index += 1;
      if (index >= value.length) break;
      output += value[index];
    } else if (/\s/u.test(character) || /[;&|<>()`$]/u.test(character)) {
      throw invalidEnvironmentWord(key);
    } else {
      output += character;
    }
  }
  if (quote !== "plain" || (value.endsWith("\\") && !value.endsWith("\\\\"))) {
    throw invalidEnvironmentWord(key);
  }
  return output;
}

function invalidEnvironmentWord(key: string): ProductionUpgradeFailureError {
  return upgradeFailure(
    "MANIFEST_INVALID",
    "PREFLIGHT",
    `Next production environment value is not a supported literal: ${key}`,
    false,
  );
}

function assertEnvironmentBinding(
  environment: Record<string, string>,
  key: string,
  expected: string,
): void {
  const observed = environment[key];
  const normalizedExpected = key === "DEVSPACE_RELEASE_MANIFEST" ? resolve(expected) : expected;
  const normalizedObserved = key === "DEVSPACE_RELEASE_MANIFEST" && observed ? resolve(observed) : observed;
  if (normalizedObserved !== normalizedExpected) {
    throw upgradeFailure(
      "MANIFEST_MISMATCH",
      "PREFLIGHT",
      `Next production environment ${key} mismatch: expected ${normalizedExpected}, observed ${normalizedObserved ?? "missing"}.`,
      false,
      { key, expected: normalizedExpected, observed: normalizedObserved ?? null },
    );
  }
}

async function verifyPreCutoverCurrentRuntime(
  request: ProductionUpgradeRequest,
  manifestBinding: ManifestBindingEvidence,
): Promise<void> {
  const healthStatus = await httpStatus(request.previous.localHealthUrl);
  if (healthStatus !== 200) {
    throw upgradeFailure(
      "MANAGEMENT_NOT_READY",
      "PREFLIGHT",
      `Previous runtime health is not ready before the stop barrier: HTTP ${healthStatus}.`,
      false,
    );
  }
  await readManagementReady(request, manifestBinding, {
    url: request.previous.localReadyUrl,
    runtimeIdentityDigest: request.previous.runtimeIdentityDigest,
  });
  await readDeepDoctor(request, manifestBinding, {
    runtimeIdentityDigest: request.previous.runtimeIdentityDigest,
    migrationManifestDigest: request.previous.migrationManifestDigest,
  });
}

async function readManagementReady(
  request: ProductionUpgradeRequest,
  manifestBinding: ManifestBindingEvidence,
  expected: {
    url: string;
    runtimeIdentityDigest: string;
    releaseIdentity?: ReleaseIdentity;
    buildCapabilityDigest?: string;
  },
): Promise<{ status: 200; identity: RuntimeIdentityEvidence }> {
  let response: Response;
  let payload: unknown;
  try {
    response = await fetchWithTimeout(expected.url);
    const body = await response.text();
    if (body.length > 64 * 1024) throw new Error("readiness payload exceeds 64 KiB");
    payload = JSON.parse(body);
  } catch (error) {
    throw upgradeFailure(
      "MANAGEMENT_NOT_READY",
      "VERIFYING",
      `Private management readiness could not be read: ${errorMessage(error)}`,
      true,
      { url: expected.url },
    );
  }
  if (response.status !== 200 || !isRecord(payload) || payload.status !== "ready") {
    throw upgradeFailure(
      "MANAGEMENT_NOT_READY",
      "VERIFYING",
      `Private management readiness is not ready: HTTP ${response.status}.`,
      true,
      { url: expected.url, status: response.status },
    );
  }
  if (payload.httpStatus !== 200
    || typeof payload.checkedAt !== "string"
    || !Number.isFinite(Date.parse(payload.checkedAt))
    || !isNonNegativeNumber(payload.durationMs)) {
    throw upgradeFailure(
      "MANAGEMENT_NOT_READY",
      "VERIFYING",
      "Private readiness report metadata is incomplete.",
      false,
    );
  }
  if (!isRecord(payload.identity)) {
    throw upgradeFailure(
      "RUNTIME_IDENTITY_MISMATCH",
      "VERIFYING",
      "Private readiness runtime identity is missing.",
      false,
    );
  }
  const identity = payload.identity;
  if (sha256Digest(stableJson(identity)) !== expected.runtimeIdentityDigest) {
    throw upgradeFailure(
      "RUNTIME_IDENTITY_MISMATCH",
      "VERIFYING",
      "Private readiness runtime identity digest does not match the request-bound runtime.",
      false,
    );
  }
  if (expected.releaseIdentity) {
    for (const field of [
      "sourceRevision",
      "runtimeRevision",
      "buildDigest",
      "schemaGeneration",
      "authorityContractGeneration",
    ] as const) {
      const expectedValue = expected.releaseIdentity[field];
      const observed = identity[field];
      if (observed === expectedValue) continue;
      throw upgradeFailure(
        "RUNTIME_IDENTITY_MISMATCH",
        "VERIFYING",
        `Private readiness identity mismatch for ${field}: expected ${expectedValue}, observed ${String(observed)}.`,
        false,
        { field, expected: expectedValue, observed: observed ?? null },
      );
    }
    if (identity.configSchemaIdentity !== undefined
      && identity.configSchemaIdentity !== expected.releaseIdentity.configSchemaIdentity) {
      throw upgradeFailure(
        "RUNTIME_IDENTITY_MISMATCH",
        "VERIFYING",
        `Private readiness identity mismatch for configSchemaIdentity: expected ${expected.releaseIdentity.configSchemaIdentity}, observed ${String(identity.configSchemaIdentity)}.`,
        false,
      );
    }
  }
  if (
    typeof identity.productVersion !== "string"
    || identity.productVersion.length === 0
    || !isSha256Digest(identity.configDigest)
    || typeof identity.startedAt !== "string"
    || !Number.isFinite(Date.parse(identity.startedAt))
  ) {
    throw upgradeFailure(
      "RUNTIME_IDENTITY_MISMATCH",
      "VERIFYING",
      "Private readiness product/config/start identity is missing or invalid.",
      false,
    );
  }
  const checks = exactPassCheckMap(payload.checks, REQUIRED_READINESS_CHECKS, "readiness");
  assertCapabilityReadiness(checks, expected.buildCapabilityDigest);
  assertRequiredStoreReadiness(request, checks.get("required_store_migrations")!);
  assertCanonicalConnectorReadiness(checks.get("canonical_connector")!);
  return { status: 200, identity: identity as unknown as RuntimeIdentityEvidence };
}

async function readDeepDoctor(
  request: ProductionUpgradeRequest,
  manifestBinding: ManifestBindingEvidence,
  expected: { runtimeIdentityDigest: string; migrationManifestDigest: string },
): Promise<{ status: 200 }> {
  const key = loadExistingManagementAuthorizationKey({
    keyRef: request.connectorLifecycle.managementAuthorizationKeyRef,
    stateDir: dirname(request.connectorLifecycle.managementAuthorizationKeyRef),
  });
  let response: Response;
  let payload: unknown;
  try {
    response = await fetchWithTimeout(request.localDoctorUrl, {
      method: "POST",
      headers: { authorization: managementAuthorizationHeader(key) },
    });
    const body = await response.text();
    if (body.length > 256 * 1024) throw new Error("deep-doctor payload exceeds 256 KiB");
    payload = JSON.parse(body);
  } catch (error) {
    throw publicBoundaryFailure(`Private deep doctor could not be read: ${errorMessage(error)}`);
  }
  if (response.status !== 200
    || !isRecord(payload)
    || payload.status !== "PASS"
    || payload.releasePassClaimed !== false
    || typeof payload.correlationId !== "string"
    || payload.correlationId.length < 1
    || typeof payload.namespace !== "string"
    || payload.namespace.length < 1
    || typeof payload.startedAt !== "string"
    || !Number.isFinite(Date.parse(payload.startedAt))
    || typeof payload.completedAt !== "string"
    || !Number.isFinite(Date.parse(payload.completedAt))
    || !isNonNegativeNumber(payload.durationMs)
    || !isNonNegativeNumber(payload.maximumDurationMs)
    || payload.maximumDurationMs > 30_000
    || payload.durationMs > payload.maximumDurationMs
    || !isRecord(payload.cleanup)
    || payload.cleanup.state !== "CLEANED"
    || !isSha256Digest(payload.cleanup.receiptDigest)) {
    throw publicBoundaryFailure(`Local doctor did not report exact deep PASS: HTTP ${response.status}.`);
  }
  const checks = exactPassCheckMap(payload.checks, REQUIRED_DEEP_DOCTOR_CHECKS, "deep doctor");
  const migration = requiredEvidence(checks.get("migration_manifest_scan")!, "migration_manifest_scan");
  if (migration.digest !== expected.migrationManifestDigest
    || !Array.isArray(migration.missingRequiredStores)
    || migration.missingRequiredStores.length !== 0
    || !Array.isArray(migration.requiredStores)
    || migration.requiredStores.length < 4) {
    throw publicBoundaryFailure("Deep doctor global migration manifest or required-store scan is incomplete.");
  }
  const artifacts = requiredEvidence(checks.get("artifact_reconciliation")!, "artifact_reconciliation");
  if (!["abortedReservations", "quarantinedObjects", "quarantinedRecords", "receipts"]
    .every((field) => isNonNegativeNumber(artifacts[field]))) {
    throw publicBoundaryFailure("Deep doctor artifact reconciliation evidence is incomplete.");
  }
  const snapshot = requiredEvidence(checks.get("mutable_snapshot_capability")!, "mutable_snapshot_capability");
  if (!isSha256Digest(snapshot.groupDigest) || snapshot.entries !== 1) {
    throw publicBoundaryFailure("Deep doctor mutable snapshot capability evidence is incomplete.");
  }
  const stale = requiredEvidence(checks.get("stale_lease_nonterminal_report")!, "stale_lease_nonterminal_report");
  if (!isRecord(stale.authority)
    || !isRecord(stale.selfManagement)
    || stale.authority.pendingReservations !== 0
    || stale.selfManagement.activeRestartTransactions !== 0) {
    throw publicBoundaryFailure("Deep doctor found nonterminal authority or restart state.");
  }
  const runtime = requiredEvidence(checks.get("runtime_identity_readback")!, "runtime_identity_readback");
  if (!isRecord(runtime.actual)
    || sha256Digest(stableJson(runtime.actual)) !== expected.runtimeIdentityDigest) {
    throw publicBoundaryFailure("Deep doctor runtime identity readback is not request-bound.");
  }
  const connector = requiredEvidence(checks.get("connector_consistency")!, "connector_consistency");
  if (connector.activeCount !== 1
    || !Array.isArray(connector.invalidStates)
    || connector.invalidStates.length !== 0) {
    throw publicBoundaryFailure("Deep doctor canonical connector reconciliation is incomplete.");
  }
  void manifestBinding;
  return { status: 200 };
}

function exactPassCheckMap(
  value: unknown,
  requiredIds: readonly string[],
  label: string,
): Map<string, Record<string, unknown>> {
  if (!Array.isArray(value) || value.length !== requiredIds.length) {
    throw publicBoundaryFailure(`Private ${label} fixed check set is incomplete.`);
  }
  const checks = new Map<string, Record<string, unknown>>();
  for (const candidate of value) {
    if (!isRecord(candidate)
      || typeof candidate.id !== "string"
      || candidate.state !== "PASS"
      || !isNonNegativeNumber(candidate.durationMs)
      || checks.has(candidate.id)) {
      throw publicBoundaryFailure(`Private ${label} contains a duplicate, non-PASS, or malformed check.`);
    }
    checks.set(candidate.id, candidate);
  }
  if (requiredIds.some((id) => !checks.has(id))) {
    throw publicBoundaryFailure(`Private ${label} fixed check set is incomplete.`);
  }
  return checks;
}

function requiredEvidence(check: Record<string, unknown>, label: string): Record<string, unknown> {
  if (!isRecord(check.evidence)) {
    throw publicBoundaryFailure(`Private ${label} evidence is missing.`);
  }
  return check.evidence;
}

function assertCapabilityReadiness(
  checks: Map<string, Record<string, unknown>>,
  expectedCapabilityDigest: string | undefined,
): void {
  for (const id of ["config_build_capabilities", "runtime_contract_identity"] as const) {
    const evidence = requiredEvidence(checks.get(id)!, id);
    if (evidence.productProfile !== "BASE_SINGLE_OWNER"
      || evidence.resourceUriVersion !== "v1"
      || (expectedCapabilityDigest !== undefined
        && (evidence.buildCapabilityDigest !== expectedCapabilityDigest
          || evidence.expectedCapabilityDigest !== expectedCapabilityDigest))) {
      throw publicBoundaryFailure(`Private readiness ${id} is not bound to the Base build capability.`);
    }
  }
}

function assertRequiredStoreReadiness(
  request: ProductionUpgradeRequest,
  check: Record<string, unknown>,
): void {
  const aggregate = requiredEvidence(check, "required_store_migrations");
  if (!Array.isArray(aggregate.observations)) {
    throw publicBoundaryFailure("Private readiness required-store observations are missing.");
  }
  const observations = new Map<string, Record<string, unknown>>();
  for (const child of aggregate.observations) {
    if (!isRecord(child) || child.state !== "PASS" || !isRecord(child.evidence)) {
      throw publicBoundaryFailure("Private readiness contains a non-PASS required-store observation.");
    }
    const evidence = child.evidence;
    const key = typeof evidence.id === "string" ? evidence.id : evidence.storeId;
    if (typeof key !== "string" || observations.has(key)) {
      throw publicBoundaryFailure("Private readiness required-store identities are duplicated or missing.");
    }
    observations.set(key, evidence);
  }
  const expected = [
    ["main", request.oauthDatabasePath, undefined],
    ["authority", request.authorityDatabasePath, 7],
    ["artifact-catalog", requiredSnapshotPath(request, "artifact-catalog"), 1],
    ["filesystem-sync", requiredSnapshotPath(request, "filesystem-sync"), 1],
    ["connector-activation-journal", request.connectorLifecycle.journal.path, 1],
  ] as const;
  for (const [storeId, path, userVersion] of expected) {
    const evidence = observations.get(storeId);
    if (!evidence
      || resolve(String(evidence.path ?? "")) !== resolve(path)
      || evidence.integrity !== "ok"
      || evidence.foreignKeyViolations !== 0
      || (userVersion === undefined
        ? evidence.complete !== true || !isSha256Digest(evidence.manifestDigest)
        : evidence.userVersion !== userVersion
          || evidence.expectedUserVersion !== userVersion
          || readSqliteUserVersion(path) !== userVersion)) {
      throw publicBoundaryFailure(`Private readiness store identity is incomplete: ${storeId}.`);
    }
  }
  for (const [id, path] of [
    ["pagination-current-signing-key", requiredSnapshotPath(request, "pagination-current-signing-key")],
    ["management-authorization-key", request.connectorLifecycle.managementAuthorizationKeyRef],
  ] as const) {
    const evidence = observations.get(id);
    if (!evidence || evidence.exists !== true || resolve(String(evidence.path ?? "")) !== resolve(path)) {
      throw publicBoundaryFailure(`Private readiness file-store identity is incomplete: ${id}.`);
    }
  }
  const journal = observations.get("connector-activation-journal-identity");
  if (!journal
    || journal.schemaVersion !== 1
    || resolve(String(journal.storePath ?? "")) !== resolve(request.connectorLifecycle.journal.path)) {
    throw publicBoundaryFailure("Private readiness connector journal identity is incomplete.");
  }
  const expectedIds = new Set([
    ...expected.map(([id]) => id),
    "pagination-current-signing-key",
    "management-authorization-key",
    "connector-activation-journal-identity",
  ]);
  if (observations.size !== expectedIds.size
    || [...observations.keys()].some((id) => !expectedIds.has(id))) {
    throw publicBoundaryFailure("Private readiness required-store observation set is not exact.");
  }
}

function readSqliteUserVersion(path: string): number {
  const sqlite = new Database(path, { readonly: true, fileMustExist: true });
  try {
    return Number(sqlite.pragma("user_version", { simple: true }));
  } finally {
    sqlite.close();
  }
}

function assertCanonicalConnectorReadiness(check: Record<string, unknown>): void {
  const evidence = requiredEvidence(check, "canonical_connector");
  if (evidence.activeCount !== 1
    || !Array.isArray(evidence.invalidStates)
    || evidence.invalidStates.length !== 0) {
    throw publicBoundaryFailure("Private readiness canonical connector is not uniquely ACTIVE.");
  }
}

function requiredSnapshotPath(request: ProductionUpgradeRequest, id: string): string {
  const entry = request.snapshotGroup?.entries.find((candidate) => candidate.id === id);
  if (!entry) throw publicBoundaryFailure(`Required snapshot store is missing: ${id}.`);
  return entry.path;
}

function assertCanonicalManagementReadbackUrls(
  request: ProductionUpgradeRequest,
  managementReadyUrl: string,
): void {
  const ready = canonicalHttpUrl(managementReadyUrl, "/readyz", "candidate readiness");
  const previousReady = canonicalHttpUrl(request.previous.localReadyUrl, "/readyz", "previous readiness");
  const doctor = canonicalHttpUrl(request.localDoctorUrl, "/doctorz", "deep doctor");
  const routeIdentity = canonicalHttpUrl(
    request.connectorLifecycle.postActivation.routeIdentityUrl,
    "/route-identityz",
    "POST route identity",
  );
  if (previousReady.origin !== ready.origin || doctor.origin !== ready.origin
    || routeIdentity.origin !== ready.origin
    || doctor.href === ready.href || doctor.href === previousReady.href) {
    throw upgradeFailure(
      "MANIFEST_INVALID",
      "PREFLIGHT",
      "Private readiness and deep-doctor URLs must use one exact loopback origin and distinct canonical paths.",
      false,
    );
  }
  if (canonicalHttpUrl(
    request.connectorLifecycle.postActivation.runtimeIdentityUrl,
    "/readyz",
    "POST runtime identity",
  ).href !== ready.href) {
    throw upgradeFailure(
      "MANIFEST_INVALID",
      "PREFLIGHT",
      "POST runtime identity URL is not the canonical private readiness endpoint.",
      false,
    );
  }
}

function canonicalHttpUrl(value: string, expectedPath: string, label: string): URL {
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    throw upgradeFailure("MANIFEST_INVALID", "PREFLIGHT", `${label} URL is invalid.`, false);
  }
  if (url.protocol !== "http:"
    || !["127.0.0.1", "[::1]", "localhost"].includes(url.hostname)
    || url.pathname !== expectedPath
    || url.search !== ""
    || url.hash !== ""
    || url.username !== ""
    || url.password !== "") {
    throw upgradeFailure(
      "MANIFEST_INVALID",
      "PREFLIGHT",
      `${label} URL is not the canonical loopback ${expectedPath} endpoint.`,
      false,
    );
  }
  return url;
}

function sameRuntimeIdentity(left: RuntimeIdentityEvidence, right: RuntimeIdentityEvidence): boolean {
  return [
    "productVersion",
    "schemaGeneration",
    "authorityContractGeneration",
    "configDigest",
    "sourceRevision",
    "runtimeRevision",
    "buildDigest",
    "startedAt",
  ].every((field) => (
    left[field as keyof RuntimeIdentityEvidence] === right[field as keyof RuntimeIdentityEvidence]
  ));
}

function publicBoundaryFailure(message: string): ProductionUpgradeFailureError {
  return upgradeFailure("PUBLIC_BOUNDARY_FAILED", "VERIFYING", message, true);
}

function upgradeFailure(
  code: ProductionUpgradeFailureCode,
  phase: ProductionUpgradeFailurePhase,
  message: string,
  retryable: boolean,
  evidence?: Record<string, unknown>,
): ProductionUpgradeFailureError {
  return new ProductionUpgradeFailureError({
    code,
    phase,
    message,
    retryable,
    ...(evidence ? { evidence } : {}),
  });
}

function normalizeFailureError(
  error: unknown,
  phase: ProductionUpgradeFailurePhase,
): ProductionUpgradeFailureError {
  if (error instanceof ProductionUpgradeFailureError) return error;
  const code: ProductionUpgradeFailureCode = phase === "PREFLIGHT"
    ? "MANIFEST_INVALID"
    : phase === "SWITCHING"
      ? "SWITCH_FAILED"
      : phase === "CONNECTOR_ACTIVATION"
        ? "CONNECTOR_ACTIVATION_FAILED"
        : phase === "POST_ACTIVATION"
          ? "POST_ACTIVATION_FAILED"
      : "PUBLIC_BOUNDARY_FAILED";
  return upgradeFailure(code, phase, errorMessage(error), phase === "VERIFYING");
}

function normalizeFailure(
  error: unknown,
  phase: ProductionUpgradeFailurePhase,
): ProductionUpgradeFailure {
  return normalizeFailureError(error, phase).failure;
}

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return Boolean(value) && typeof value === "object" && !Array.isArray(value);
}

function isSha256Digest(value: unknown): value is string {
  return typeof value === "string" && /^sha256:[a-f0-9]{64}$/u.test(value);
}

function isConnectorCandidateIdentity(
  value: unknown,
): value is ProductionUpgradeRequest["connectorLifecycle"]["candidateIdentity"] {
  if (!isRecord(value)) return false;
  const keys = [
    "runtimeIdentityDigest",
    "buildDigest",
    "schemaGeneration",
    "authorityContractGeneration",
    "buildCapabilityManifestDigest",
    "generatedSchemaDigest",
    "packageSha256",
  ] as const;
  return Object.keys(value).length === keys.length
    && keys.every((key) => isSha256Digest(value[key]));
}

function isSafeManifestFileList(value: unknown): value is string[] {
  if (!Array.isArray(value) || value.length < 1 || value.some((path) => (
    typeof path !== "string"
    || path.length === 0
    || path.includes("\\")
    || path.startsWith("/")
    || path.split("/").some((segment) => segment === "" || segment === "." || segment === "..")
  ))) return false;
  return new Set(value).size === value.length;
}

function stopPm2Process(request: ProductionUpgradeRequest): void {
  runPm2(request, ["delete", request.pm2ProcessName], 30_000, true);
  if (pm2Process(request)) {
    throw new Error(`PM2 process did not stop before database cutover: ${request.pm2ProcessName}`);
  }
}

function stopCutoverProcesses(request: ProductionUpgradeRequest): void {
  for (const name of request.cutoverProcessNames) {
    runPm2(request, ["delete", name], 30_000, true);
  }
  assertCutoverProcessesStopped(request);
}

function assertCutoverProcessesStopped(request: ProductionUpgradeRequest): void {
  const processes = pm2Inventory(request);
  const present = request.cutoverProcessNames.filter((name) => (
    processes.some((process) => process.name === name)
  ));
  if (present.length > 0) {
    throw new Error(`Cutover processes remain active: ${present.join(", ")}`);
  }
}

function ensureCandidateRuntimeStarted(request: ProductionUpgradeRequest): void {
  const existing = pm2Process(request);
  if (existing) {
    if (existing.pm2_env?.status === "online"
      && resolve(existing.pm2_env.pm_cwd ?? "/") === resolve(request.next.immutableRuntimeRoot)
      && resolve(existing.pm2_env.pm_exec_path ?? "/") === resolve(request.next.immutableRuntimeEntrypoint)) {
      return;
    }
    throw new Error("A non-equivalent PM2 process occupies the canonical production name after cutover.");
  }
  startPm2Process(
    request,
    request.next.immutableRuntimeEntrypoint,
    request.next.immutableRuntimeRoot,
  );
}

function startPm2Process(
  request: ProductionUpgradeRequest,
  script: string,
  cwd: string,
): void {
  runPm2(request, [
    "start",
    script,
    "--name",
    request.pm2ProcessName,
    "--interpreter",
    "/bin/bash",
    "--cwd",
    cwd,
    "--time",
  ], 60_000, false, productionPm2Environment(
    process.env,
    request.productionEnvPath,
  ));
  runPm2(request, ["save"], 30_000);
}

export function productionPm2Environment(
  inherited: NodeJS.ProcessEnv,
  productionEnvPath: string,
  nodeExecutable = process.execPath,
): NodeJS.ProcessEnv {
  const sanitized: NodeJS.ProcessEnv = {};
  for (const [key, value] of Object.entries(inherited)) {
    if (!key.startsWith("DEVSPACE_")) sanitized[key] = value;
  }
  sanitized.PATH = pm2ExecutablePath(inherited.PATH, nodeExecutable);
  sanitized.DEVSPACE_PRODUCTION_ENV_FILE = productionEnvPath;
  return sanitized;
}

export function pm2CommandEnvironment(
  inherited: NodeJS.ProcessEnv,
  nodeExecutable = process.execPath,
): NodeJS.ProcessEnv {
  return {
    ...inherited,
    PATH: pm2ExecutablePath(inherited.PATH, nodeExecutable),
  };
}

export function pm2WorkerCleanupEnvironment(
  inherited: NodeJS.ProcessEnv,
  nodeExecutable = process.execPath,
): NodeJS.ProcessEnv {
  const sanitized: NodeJS.ProcessEnv = {};
  for (const key of ["HOME", "USER", "LOGNAME", "TMPDIR", "LANG", "LC_ALL", "PM2_HOME"]) {
    const value = inherited[key];
    if (value) sanitized[key] = value;
  }
  sanitized.PATH = pm2ExecutablePath(inherited.PATH, nodeExecutable);
  return sanitized;
}

export function schedulePm2WorkerCleanup(
  pm2Executable: string,
  workerName: string,
  auditDirectory: string,
  delayMs = 750,
): number {
  if (!isAbsolute(pm2Executable)) {
    throw new Error(`PM2 executable must be absolute: ${pm2Executable}`);
  }
  if (!/^[A-Za-z0-9_.-]{1,128}$/u.test(workerName)) {
    throw new Error(`Invalid PM2 cleanup worker name: ${workerName}`);
  }
  if (!isAbsolute(auditDirectory)) {
    throw new Error(`PM2 cleanup audit directory must be absolute: ${auditDirectory}`);
  }
  if (!Number.isInteger(delayMs) || delayMs < 0 || delayMs > 30_000) {
    throw new Error(`Invalid PM2 cleanup delay: ${delayMs}`);
  }
  const cleanupProgram = [
    'const { spawnSync } = require("node:child_process");',
    'const { chmodSync, renameSync, writeFileSync } = require("node:fs");',
    'const { join } = require("node:path");',
    'const [pm2, workerName, auditDirectory, delayText] = process.argv.slice(1);',
    'const delay = Number(delayText);',
    'setTimeout(() => {',
    '  const run = (args) => spawnSync(pm2, args, { cwd: auditDirectory, env: process.env, encoding: "utf8", timeout: 30000 });',
    '  const deleted = run(["delete", workerName]);',
    '  const saved = run(["save"]);',
    '  const evidence = { version: 1, workerName, deleted: deleted.status === 0, deleteStatus: deleted.status, dumpSaved: saved.status === 0, saveStatus: saved.status, completedAt: new Date().toISOString() };',
    '  const evidencePath = join(auditDirectory, "scheduler-cleanup.json");',
    '  const temporary = `${evidencePath}.${process.pid}.tmp`;',
    '  writeFileSync(temporary, `${JSON.stringify(evidence, null, 2)}\\n`, { mode: 0o600 });',
    '  chmodSync(temporary, 0o600);',
    '  renameSync(temporary, evidencePath);',
    '  process.exitCode = saved.status === 0 ? 0 : 1;',
    '}, delay);',
  ].join("\n");
  const child = spawn(process.execPath, [
    "-e",
    cleanupProgram,
    pm2Executable,
    workerName,
    auditDirectory,
    String(delayMs),
  ], {
    cwd: auditDirectory,
    detached: true,
    stdio: "ignore",
    env: pm2WorkerCleanupEnvironment(process.env),
  });
  if (!child.pid) throw new Error("Failed to create detached PM2 cleanup process.");
  child.unref();
  return child.pid;
}

function pm2ExecutablePath(
  inheritedPath: string | undefined,
  nodeExecutable: string,
): string {
  if (!isAbsolute(nodeExecutable)) {
    throw new Error(`Node executable must be absolute for detached PM2 control: ${nodeExecutable}`);
  }
  const entries = [
    dirname(resolve(nodeExecutable)),
    ...(inheritedPath ?? "").split(delimiter),
  ].filter((entry) => entry.length > 0);
  return [...new Set(entries)].join(delimiter);
}

async function rollbackRuntime(
  request: ProductionUpgradeRequest,
  snapshotGroupPreimage: SnapshotGroupManifest | undefined,
): Promise<{
  attempted: true;
  restored: boolean;
  verified: boolean;
  outcome: "RESTORED_PREVIOUS_STATE" | "RESTORED_PREVIOUS_RUNTIME" | "RESTORATION_UNVERIFIED";
  healthStatus?: number;
  readyStatus?: number;
  rollbackHostReceiptDigest?: string;
  rollbackHostReceiptPayloadDigest?: string;
  snapshotGroup?: SnapshotGroupRestoreEvidence;
  oauthDatabase?: DatabaseRestoreEvidence;
  authorityDatabase?: DatabaseRestoreEvidence;
  error?: string;
  failure?: ProductionUpgradeFailure;
}> {
  let restored = false;
  let snapshotGroup: SnapshotGroupRestoreEvidence | undefined;
  let oauthDatabase: DatabaseRestoreEvidence | undefined;
  let authorityDatabase: DatabaseRestoreEvidence | undefined;
  let error: string | undefined;
  try {
    assertCutoverProcessesStopped(request);
    if (!snapshotGroupPreimage) throw new Error("Rollback cannot restore without the exact cutover snapshot manifest.");
    const validatedSnapshot = validateSnapshotGroupManifest(snapshotGroupPreimage);
    if (validatedSnapshot.barrier.previousRuntimeIdentityDigest !== request.previous.runtimeIdentityDigest
      || validatedSnapshot.barrier.previousMigrationManifestDigest !== request.previous.migrationManifestDigest) {
      throw new Error("Rollback snapshot is not bound to the previous runtime/migration identity.");
    }
    await installFile(request.productionEnvBackupPath, request.productionEnvPath, 0o600);
    snapshotGroup = await restoreSnapshotGroup(validatedSnapshot);
    if (snapshotGroup.verified !== true
      || snapshotGroup.entries.some((entry) => entry.restored !== true || entry.verified !== true)) {
      throw new Error("Rollback snapshot restore did not verify every mutable store.");
    }
    oauthDatabase = databaseRestoreEvidenceFromSnapshot(
      snapshotGroup.entries,
      ["oauth-main-and-connector-state", "oauth-database"],
    );
    authorityDatabase = databaseRestoreEvidenceFromSnapshot(
      snapshotGroup.entries,
      ["authority-store", "authority-database"],
    );
    await installFile(request.startScriptBackupPath, request.startScriptPath, 0o700);
    if (request.previous.auditTarget) {
      await replaceSymlink(request.currentAuditLink, request.previous.auditTarget);
    }
    verifySqliteDatabase(request.oauthDatabasePath);
    verifySqliteDatabase(request.authorityDatabasePath);
    assertCutoverProcessesStopped(request);
    restored = true;
  } catch (rollbackError) {
    error = rollbackError instanceof Error ? rollbackError.message : String(rollbackError);
  }
  const failure = error
    ? {
        code: "ROLLBACK_FAILED" as const,
        phase: "ROLLING_BACK" as const,
        message: error,
        retryable: false,
      }
    : undefined;
  return {
    attempted: true,
    restored,
    verified: restored,
    outcome: restored ? "RESTORED_PREVIOUS_STATE" : "RESTORATION_UNVERIFIED",
    ...(snapshotGroup ? { snapshotGroup } : {}),
    ...(oauthDatabase ? { oauthDatabase } : {}),
    ...(authorityDatabase ? { authorityDatabase } : {}),
    ...(error ? { error } : {}),
    ...(failure ? { failure } : {}),
  };
}

async function startAndVerifyPreviousRuntime(
  request: ProductionUpgradeRequest,
  restore: Awaited<ReturnType<typeof rollbackRuntime>>,
  rollbackRequestedAtMs: number,
  allowPersistedRollbackEvidence = false,
): Promise<Awaited<ReturnType<typeof rollbackRuntime>>> {
  let healthStatus: number | undefined;
  let readyStatus: number | undefined;
  let rollbackHostReceiptDigest: string | undefined;
  let rollbackHostReceiptPayloadDigest: string | undefined;
  try {
    assertCutoverProcessesStopped(request);
    startPm2Process(request, request.previous.script, request.previous.cwd);
    const runtimeReadyDeadline = Date.now() + Math.min(request.timeoutMs, 60_000);
    let readyIdentityConfirmed = false;
    let observedProcess: Pm2ProcessSnapshot | undefined;
    let observedReadyIdentityDigest: string | undefined;
    while (Date.now() < runtimeReadyDeadline) {
      const process = pm2Process(request);
      if (process?.pm2_env?.status === "online"
        && resolve(process.pm2_env.pm_cwd ?? "/") === resolve(request.previous.cwd)
        && resolve(process.pm2_env.pm_exec_path ?? "/") === resolve(request.previous.script)) {
        healthStatus = await httpStatus(request.previous.localHealthUrl);
        const readyResponse = await fetchWithTimeout(request.previous.localReadyUrl);
        readyStatus = readyResponse.status;
        const readyBody = await readyResponse.text();
        let readyPayload: unknown;
        try {
          readyPayload = JSON.parse(readyBody);
        } catch {
          readyPayload = undefined;
        }
        const identity = isRecord(readyPayload) && isRecord(readyPayload.identity)
          ? readyPayload.identity
          : readyPayload;
        const runtimeIdentityDigest = sha256Digest(stableJson(identity));
        readyIdentityConfirmed = healthStatus === 200
          && readyStatus === 200
          && runtimeIdentityDigest === request.previous.runtimeIdentityDigest;
        if (readyIdentityConfirmed) {
          observedProcess = process;
          observedReadyIdentityDigest = runtimeIdentityDigest;
          break;
        }
      }
      await sleep(250);
    }
    if (!readyIdentityConfirmed
      || !observedProcess
      || observedProcess.name !== request.pm2ProcessName
      || observedProcess.pm2_env?.status !== "online"
      || healthStatus === undefined
      || readyStatus === undefined
      || !observedReadyIdentityDigest) {
      throw new Error("Previous runtime identity/health/readiness did not verify after restored state.");
    }

    const challengeContext = await readVerifiedRollbackHostChallenge(
      request,
      allowPersistedRollbackEvidence,
    );
    const common = {
      challengeId: challengeContext.challenge.challengeId,
      transactionId: challengeContext.challenge.transactionId,
      nonce: challengeContext.challenge.nonce,
      managementCorrelationId: challengeContext.challenge.managementCorrelationId,
    };
    const receiptExpected: ConnectorRollbackReceiptExpectedBinding = {
      ...challengeContext.expected,
      healthReadbackDigest: connectorRollbackHealthReadbackDigest({
        ...common,
        httpStatus: healthStatus,
      }),
      readyReadbackDigest: connectorRollbackReadyReadbackDigest({
        ...common,
        httpStatus: readyStatus,
        runtimeIdentityDigest: observedReadyIdentityDigest,
      }),
      runtimeReadbackDigest: connectorRollbackRuntimeReadbackDigest({
        ...common,
        processName: request.pm2ProcessName,
        processStatus: "online",
        cwd: resolve(observedProcess.pm2_env.pm_cwd ?? "/"),
        script: resolve(observedProcess.pm2_env.pm_exec_path ?? "/"),
        runtimeIdentityDigest: observedReadyIdentityDigest,
        mainMigrationIdentityDigest: request.previous.migrationManifestDigest,
      }),
    };

    const rollbackBinding = request.previous.rollbackHostChallenge;
    const receiptDeadline = Math.min(
      Date.parse(rollbackBinding.deadlineAt),
      Date.now() + request.timeoutMs,
    );
    while (Date.now() < receiptDeadline) {
      try {
        const receiptPath = rollbackBinding.receiptPath;
        await assertOwnerOnlyRegularFile(receiptPath, "rollback Host receipt");
        const receiptMetadata = await lstat(receiptPath);
        if (receiptMetadata.mtimeMs <= rollbackRequestedAtMs) {
          throw new Error("Rollback Host receipt path was not freshly produced after rollback was requested.");
        }
        const receiptContent = await readFile(receiptPath);
        rollbackHostReceiptDigest = `sha256:${createHash("sha256").update(receiptContent).digest("hex")}`;
        const receiptEnvelope = JSON.parse(
          receiptContent.toString("utf8"),
        ) as SignedConnectorRollbackHostReceipt;
        const receiptVerificationTime = allowPersistedRollbackEvidence
          && Number.isSafeInteger(receiptEnvelope?.payload?.observedAtMs)
          ? receiptEnvelope.payload.observedAtMs
          : Date.now();
        const verifiedReceipt = verifyConnectorRollbackHostReceipt(
          receiptEnvelope,
          challengeContext.key,
          challengeContext.envelope,
          receiptExpected,
          receiptVerificationTime,
        );
        if (verifiedReceipt.observedAtMs <= rollbackRequestedAtMs) {
          throw new Error("Rollback Host receipt was not observed strictly after durable rollback request.");
        }
        rollbackHostReceiptPayloadDigest = verifiedReceipt.signedPayloadDigest;
        return {
          ...restore,
          restored: true,
          verified: true,
          outcome: "RESTORED_PREVIOUS_RUNTIME",
          ...(healthStatus !== undefined ? { healthStatus } : {}),
          ...(readyStatus !== undefined ? { readyStatus } : {}),
          rollbackHostReceiptDigest,
          rollbackHostReceiptPayloadDigest,
        };
      } catch (error) {
        if (!isNodeError(error, "ENOENT")) throw error;
      }
      await sleep(rollbackBinding.pollIntervalMs);
    }
    throw new Error("Trusted rollback Host receipt did not arrive before the bounded deadline.");
  } catch (error) {
    try {
      stopCutoverProcesses(request);
    } catch {
      // Preserve the primary verification failure and keep the outcome UNKNOWN.
    }
    const message = errorMessage(error);
    return {
      ...restore,
      verified: false,
      outcome: "RESTORATION_UNVERIFIED",
      ...(healthStatus !== undefined ? { healthStatus } : {}),
      ...(readyStatus !== undefined ? { readyStatus } : {}),
      ...(rollbackHostReceiptDigest ? { rollbackHostReceiptDigest } : {}),
      ...(rollbackHostReceiptPayloadDigest ? { rollbackHostReceiptPayloadDigest } : {}),
      error: message,
      failure: {
        code: "ROLLBACK_FAILED",
        phase: "ROLLING_BACK",
        message,
        retryable: false,
      },
    };
  }
}

interface DatabaseRestoreEvidence {
  restored: true;
  backupSha256: string;
  restoredSha256: string;
  staleSidecarsRemoved: true;
}

interface DatabasePreimage {
  path: string;
  sha256: string;
}

interface DatabasePreimages {
  capturedAt: string;
  oauth: DatabasePreimage;
  authority: DatabasePreimage;
}

async function captureCutoverSnapshotGroup(
  request: ProductionUpgradeRequest,
  configured: NonNullable<ProductionUpgradeRequest["snapshotGroup"]>,
  requestBindingDigest: string,
  stoppedAt: string,
): Promise<SnapshotGroupManifest> {
  const entries = configured.entries;
  assertRequiredBaseSnapshotInventory(entries);
  const captured = await captureSnapshotGroup({
    snapshotRoot: configured.snapshotRoot,
    barrier: {
      kind: "PM2_STOPPED",
      processName: request.pm2ProcessName,
      previousPid: request.previous.pid,
      previousRuntimeIdentityDigest: request.previous.runtimeIdentityDigest,
      previousMigrationManifestDigest: request.previous.migrationManifestDigest,
      transactionId: request.transactionId,
      requestBindingDigest,
      cutoverProcessNames: [...request.cutoverProcessNames].sort(),
      establishedAt: stoppedAt,
    },
    entries,
  });
  assertSnapshotMatchesRequest(
    captured.manifest,
    configured,
    request,
    requestBindingDigest,
    stoppedAt,
  );
  return captured.manifest;
}

function requireCutoverSnapshotGroup(
  request: ProductionUpgradeRequest,
): NonNullable<ProductionUpgradeRequest["snapshotGroup"]> {
  if (!request.snapshotGroup) {
    throw upgradeFailure(
      "MANIFEST_INVALID",
      "PREFLIGHT",
      "Production upgrade request must include the complete Base cutover snapshot group.",
      false,
      { missing: ["snapshotGroup"] },
    );
  }
  assertRequiredBaseSnapshotInventory(request.snapshotGroup.entries);
  return request.snapshotGroup;
}

async function verifySnapshotCaptureBoundary(
  request: ProductionUpgradeRequest,
  configured: NonNullable<ProductionUpgradeRequest["snapshotGroup"]>,
  status: ProductionUpgradeStatus,
  requestBindingDigest: string,
): Promise<SnapshotGroupManifest | undefined> {
  const root = canonicalNoFollowPath(configured.snapshotRoot, "snapshot root");
  const auditRoot = canonicalNoFollowPath(request.auditDirectory, "production upgrade audit directory");
  if (!pathIsSameOrInside(auditRoot, root) || root === auditRoot) {
    throw upgradeFailure(
      "MANIFEST_INVALID",
      "PREFLIGHT",
      "Transaction snapshot root must be a dedicated child of the owner-only audit directory.",
      false,
    );
  }
  await assertOwnerOnlyDirectory(dirname(root), "snapshot root parent directory");
  const durableSnapshotState = hasReached(status.state, "STATE_SNAPSHOTTED");
  if (Boolean(status.snapshotGroupPreimage) !== durableSnapshotState) {
    throw upgradeFailure(
      "MANIFEST_INVALID",
      "PREFLIGHT",
      "Snapshot preimage and durable STATE_SNAPSHOTTED status must exist together.",
      false,
    );
  }
  const existing = await lstat(root).catch((error: unknown) => {
    if (isNodeError(error, "ENOENT")) return undefined;
    throw error;
  });
  if (existing && (!existing.isDirectory() || existing.isSymbolicLink())) {
    throw upgradeFailure(
      "MANIFEST_INVALID",
      "PREFLIGHT",
      `Snapshot root is not a real directory: ${root}`,
      false,
    );
  }
  if (durableSnapshotState && !existing) {
    throw upgradeFailure(
      "MANIFEST_INVALID",
      "PREFLIGHT",
      `Durable snapshot root is missing: ${root}`,
      false,
    );
  }
  if (!durableSnapshotState && existing) {
    if (status.state !== "CUTOVER_PROCESSES_STOPPED") {
      throw upgradeFailure(
        "MANIFEST_INVALID",
        "PREFLIGHT",
        `Snapshot root must be a new transaction-specific path: ${root}`,
        false,
      );
    }
    const stoppedAt = requireTransitionAt(status, "CUTOVER_PROCESSES_STOPPED");
    const manifestPath = join(root, "SNAPSHOT-GROUP.json");
    await assertOwnerOnlyRegularFile(manifestPath, "snapshot manifest");
    const disk = validateSnapshotGroupManifest(
      JSON.parse(await readFile(manifestPath, "utf8")) as SnapshotGroupManifest,
    );
    assertSnapshotMatchesRequest(
      disk,
      configured,
      request,
      requestBindingDigest,
      stoppedAt,
    );
    return disk;
  }
  if (durableSnapshotState) {
    const stoppedAt = requireTransitionAt(status, "CUTOVER_PROCESSES_STOPPED");
    const persisted = validateSnapshotGroupManifest(status.snapshotGroupPreimage!);
    assertSnapshotMatchesRequest(
      persisted,
      configured,
      request,
      requestBindingDigest,
      stoppedAt,
    );
    const manifestPath = join(root, "SNAPSHOT-GROUP.json");
    await assertOwnerOnlyRegularFile(manifestPath, "snapshot manifest");
    const disk = validateSnapshotGroupManifest(
      JSON.parse(await readFile(manifestPath, "utf8")) as SnapshotGroupManifest,
    );
    if (stableJson(disk) !== stableJson(persisted)) {
      throw upgradeFailure(
        "MANIFEST_MISMATCH",
        "PREFLIGHT",
        "Durable snapshot status and owner-only manifest readback differ.",
        false,
      );
    }
    return persisted;
  }
  return undefined;
}

async function verifyConnectorLifecycleRequest(
  request: ProductionUpgradeRequest,
  snapshotEntries: readonly SnapshotGroupEntryRequest[],
  allowCompletedPostDeadline = false,
): Promise<void> {
  const lifecycle = request.connectorLifecycle;
  const observedBinding = productionUpgradeLifecycleBindingDigest(request);
  if (lifecycle.bindingDigest !== observedBinding) {
    throw upgradeFailure(
      "MANIFEST_MISMATCH",
      "PREFLIGHT",
      `Connector lifecycle request binding mismatch: expected ${lifecycle.bindingDigest}, observed ${observedBinding}.`,
      false,
    );
  }
  if (!isSha256Digest(lifecycle.productionEnvironmentIdentityDigest)
    || !isSha256Digest(lifecycle.productionRouteIdentityDigest)
    || !isSha256Digest(lifecycle.postActivation.challengeSha256)
    || !isConnectorCandidateIdentity(lifecycle.candidateIdentity)
    || lifecycle.candidateIdentity.buildDigest !== request.next.manifest.buildDigest
    || lifecycle.candidateIdentity.schemaGeneration !== request.next.manifest.schemaGeneration
    || lifecycle.candidateIdentity.authorityContractGeneration
      !== request.next.manifest.authorityContractGeneration
    || typeof lifecycle.managementNonce !== "string"
    || lifecycle.managementNonce.length < 1
    || typeof lifecycle.managementCorrelationId !== "string"
    || lifecycle.managementCorrelationId.length < 1) {
    throw upgradeFailure(
      "MANIFEST_INVALID",
      "PREFLIGHT",
      "Connector lifecycle v4 challenge or production identity binding is invalid.",
      false,
    );
  }
  const deadlineMs = Date.parse(lifecycle.postActivation.deadlineAt);
  if (!Number.isFinite(deadlineMs)
    || (!allowCompletedPostDeadline && deadlineMs <= Date.now())
    || !Number.isSafeInteger(lifecycle.postActivation.pollIntervalMs)
    || lifecycle.postActivation.pollIntervalMs < 10
    || lifecycle.postActivation.pollIntervalMs > 5_000) {
    throw upgradeFailure(
      "MANIFEST_INVALID",
      "PREFLIGHT",
      "Connector lifecycle POST challenge deadline or poll interval is invalid.",
      false,
    );
  }
  if (lifecycle.journal.identity.storePath !== lifecycle.journal.path
    || lifecycle.journal.identity.snapshotPolicy !== "PRESERVE_OUTSIDE_MUTABLE_ROLLBACK"
    || lifecycle.journal.identity.receiptReplayPolicy !== "PREPARED_RECEIPT_PERMANENTLY_ONE_SHOT"
    || !isSha256Digest(lifecycle.journal.identity.migrationManifestDigest)
    || !isSha256Digest(lifecycle.journal.identity.contentGeneration)
    || !isSha256Digest(lifecycle.journal.identity.schemaFingerprint)
    || !Number.isSafeInteger(lifecycle.journal.identity.createdAtMs)
    || lifecycle.journal.identity.createdAtMs < 0) {
    throw upgradeFailure(
      "MANIFEST_INVALID",
      "PREFLIGHT",
      "Connector activation journal identity/policy binding is invalid.",
      false,
    );
  }

  const immutableArtifacts = [
    lifecycle.stagingActivationPrecheck,
    lifecycle.preCutoverHostCanary,
    {
      path: lifecycle.postActivation.challengePath,
      sha256: lifecycle.postActivation.challengeSha256,
    },
  ];
  for (const artifact of immutableArtifacts) {
    await assertOwnerOnlyRegularFile(artifact.path, "connector lifecycle evidence");
    const observed = await fileSha256(artifact.path);
    if (observed !== artifact.sha256) {
      throw upgradeFailure(
        "MANIFEST_MISMATCH",
        "PREFLIGHT",
        `Connector lifecycle evidence digest mismatch: ${artifact.path}`,
        false,
        { path: artifact.path, expected: artifact.sha256, observed },
      );
    }
  }
  const releaseDriverArtifacts = PRODUCTION_UPGRADE_RELEASE_DRIVER_PROVENANCE_KEYS.map((key) => ({
    key,
    ...lifecycle.releaseDriver[key],
  }));
  for (const artifact of releaseDriverArtifacts) {
    await assertOwnerOnlyRegularFile(artifact.path, `connector release-driver ${artifact.key}`);
    const observed = await fileSha256(artifact.path);
    if (observed !== artifact.sha256) {
      throw upgradeFailure(
        "MANIFEST_MISMATCH",
        "PREFLIGHT",
        `Connector release-driver provenance digest mismatch: ${artifact.path}`,
        false,
        { key: artifact.key, path: artifact.path, expected: artifact.sha256, observed },
      );
    }
  }
  for (let left = 0; left < releaseDriverArtifacts.length; left += 1) {
    for (let right = left + 1; right < releaseDriverArtifacts.length; right += 1) {
      if (canonicalPathsOverlap(
        releaseDriverArtifacts[left]!.path,
        releaseDriverArtifacts[right]!.path,
      )) {
        throw upgradeFailure(
          "MANIFEST_INVALID",
          "PREFLIGHT",
          "Connector release-driver provenance paths must be pairwise distinct.",
          false,
          { left: releaseDriverArtifacts[left]!.key, right: releaseDriverArtifacts[right]!.key },
        );
      }
    }
  }
  const immutablePackageRoots = [
    request.next.sourceEvidenceRoot,
    request.next.immutableRuntimeRoot,
    request.next.runtimeDependencies.root,
  ];
  for (const artifact of releaseDriverArtifacts) {
    const packageRoot = immutablePackageRoots.find((root) => canonicalPathsOverlap(artifact.path, root));
    if (packageRoot) {
      throw upgradeFailure(
        "MANIFEST_INVALID",
        "PREFLIGHT",
        `Connector release-driver provenance must remain outside immutable package state: ${artifact.path}`,
        false,
        { key: artifact.key, packageRoot },
      );
    }
  }
  await assertOwnerOnlyRegularFile(lifecycle.journal.path, "connector activation journal");
  await assertOwnerOnlyRegularFile(
    lifecycle.managementAuthorizationKeyRef,
    "management authorization key reference",
  );
  await assertOwnerOnlyDirectory(dirname(lifecycle.postActivation.receiptPath), "POST receipt directory");
  await assertOwnerOnlyDirectory(
    dirname(lifecycle.releaseDriver.productionApprovalOutputDirectory),
    "production approval output parent directory",
  );

  const externalControlPaths = [
    lifecycle.journal.path,
    request.rollbackJournalPath,
    request.statusPath,
    request.auditDirectory,
    lifecycle.stagingActivationPrecheck.path,
    lifecycle.preCutoverHostCanary.path,
    ...releaseDriverArtifacts.map((artifact) => artifact.path),
    lifecycle.releaseDriver.productionApprovalOutputDirectory,
    lifecycle.postActivation.challengePath,
    lifecycle.postActivation.receiptPath,
    lifecycle.managementAuthorizationKeyRef,
    request.previous.rollbackHostChallenge.rollbackChallengeRequest.path,
    request.previous.rollbackHostChallenge.challengePath,
    request.previous.rollbackHostChallenge.receiptPath,
    lifecycle.finalization.controlPath,
    request.workerClaimPath,
    request.workerLogPath,
    request.nextEnvPath,
    request.productionEnvBackupPath,
    request.oauthDatabaseBackupPath,
    request.authorityDatabaseBackupPath,
    request.startScriptBackupPath,
  ];
  for (const entry of snapshotEntries) {
    for (const mutablePath of snapshotEntryMutablePaths(entry)) {
      for (const controlPath of externalControlPaths) {
        if (canonicalPathsOverlap(mutablePath, controlPath)) {
          throw upgradeFailure(
            "MANIFEST_INVALID",
            "PREFLIGHT",
            `Mutable snapshot entry ${entry.id} overlaps non-restored control-plane state: ${controlPath}`,
            false,
            { entryId: entry.id, entryPath: entry.path, mutablePath, controlPath },
          );
        }
      }
    }
  }
  for (const controlPath of externalControlPaths.filter((path) => path !== request.auditDirectory)) {
    if (canonicalPathsOverlap(request.snapshotGroup!.snapshotRoot, controlPath)) {
      throw upgradeFailure(
        "MANIFEST_INVALID",
        "PREFLIGHT",
        `Non-restored control-plane state must remain outside the mutable snapshot root: ${controlPath}`,
        false,
      );
    }
  }
}

async function assertOwnerOnlyRegularFile(path: string, label: string): Promise<void> {
  const resolved = resolve(path);
  if (canonicalNoFollowPath(resolved, label) !== resolved) {
    throw upgradeFailure("MANIFEST_INVALID", "PREFLIGHT", `${label} path identity drifted: ${path}`, false);
  }
  const metadata = await lstat(path);
  if (!metadata.isFile() || metadata.isSymbolicLink() || (metadata.mode & 0o077) !== 0) {
    throw upgradeFailure(
      "MANIFEST_INVALID",
      "PREFLIGHT",
      `${label} must be an owner-only regular file: ${path}`,
      false,
    );
  }
  const uid = typeof process.getuid === "function" ? process.getuid() : undefined;
  if (uid !== undefined && metadata.uid !== uid) {
    throw upgradeFailure(
      "MANIFEST_INVALID",
      "PREFLIGHT",
      `${label} is not owned by the worker uid: ${path}`,
      false,
    );
  }
}

interface VerifiedRollbackChallengeContext {
  envelope: SignedConnectorRollbackHostChallenge;
  challenge: VerifiedConnectorRollbackHostChallenge;
  key: ReturnType<typeof loadExistingManagementAuthorizationKey>;
  expected: ConnectorRollbackChallengeExpectedBinding;
}

async function verifyRollbackHostChallengeRequest(
  request: ProductionUpgradeRequest,
  allowExpiredCompletedTransaction = false,
): Promise<void> {
  await readVerifiedRollbackHostChallenge(request, allowExpiredCompletedTransaction);
  const receiptPath = resolve(request.previous.rollbackHostChallenge.receiptPath);
  await assertOwnerOnlyDirectory(dirname(receiptPath), "rollback Host receipt directory");
  if (canonicalNoFollowPath(receiptPath, "rollback Host receipt") !== receiptPath) {
    throw upgradeFailure(
      "MANIFEST_INVALID",
      "PREFLIGHT",
      "Rollback Host receipt path identity drifted.",
      false,
    );
  }
  try {
    await lstat(receiptPath);
    throw upgradeFailure(
      "MANIFEST_INVALID",
      "PREFLIGHT",
      "Rollback Host receipt target must be absent before cutover scheduling.",
      false,
      { receiptPath },
    );
  } catch (error) {
    if (!isNodeError(error, "ENOENT")) throw error;
  }
}

async function readVerifiedRollbackHostChallenge(
  request: ProductionUpgradeRequest,
  allowExpiredCompletedTransaction = false,
): Promise<VerifiedRollbackChallengeContext> {
  const binding = request.previous.rollbackHostChallenge;
  await assertOwnerOnlyRegularFile(binding.rollbackChallengeRequest.path, "rollback Host challenge request");
  const observedRequestSha256 = await fileSha256(binding.rollbackChallengeRequest.path);
  if (observedRequestSha256 !== binding.rollbackChallengeRequest.sha256) {
    throw upgradeFailure(
      "MANIFEST_MISMATCH",
      "PREFLIGHT",
      "Rollback Host challenge request provenance digest is not request-bound.",
      false,
      {
        path: binding.rollbackChallengeRequest.path,
        expected: binding.rollbackChallengeRequest.sha256,
        observed: observedRequestSha256,
      },
    );
  }
  await assertOwnerOnlyRegularFile(binding.challengePath, "rollback Host challenge");
  const observedSha256 = await fileSha256(binding.challengePath);
  if (observedSha256 !== binding.challengeSha256) {
    throw upgradeFailure(
      "MANIFEST_MISMATCH",
      "PREFLIGHT",
      "Rollback Host challenge digest is not request-bound.",
      false,
      { path: binding.challengePath, expected: binding.challengeSha256, observed: observedSha256 },
    );
  }
  let envelope: SignedConnectorRollbackHostChallenge;
  try {
    envelope = JSON.parse(await readFile(binding.challengePath, "utf8")) as SignedConnectorRollbackHostChallenge;
  } catch (error) {
    throw upgradeFailure(
      "MANIFEST_INVALID",
      "PREFLIGHT",
      `Rollback Host challenge is not canonical JSON: ${errorMessage(error)}`,
      false,
    );
  }
  const receiptPath = resolve(binding.receiptPath);
  const expected: ConnectorRollbackChallengeExpectedBinding = {
    transactionId: request.transactionId,
    previousRuntimeIdentityDigest: request.previous.runtimeIdentityDigest,
    previousMainMigrationIdentityDigest: request.previous.migrationManifestDigest,
    receiptPath,
  };
  const key = loadExistingManagementAuthorizationKey({
    keyRef: request.connectorLifecycle.managementAuthorizationKeyRef,
    stateDir: dirname(request.connectorLifecycle.managementAuthorizationKeyRef),
  });
  const verificationTime = allowExpiredCompletedTransaction
    ? envelope?.payload?.issuedAtMs
    : Date.now();
  const challenge = verifyConnectorRollbackHostChallenge(
    envelope,
    key,
    expected,
    verificationTime,
  );
  return { envelope, challenge, key, expected };
}

async function assertOwnerOnlyDirectory(path: string, label: string): Promise<void> {
  const resolved = resolve(path);
  if (canonicalNoFollowPath(resolved, label) !== resolved) {
    throw upgradeFailure("MANIFEST_INVALID", "PREFLIGHT", `${label} path identity drifted: ${path}`, false);
  }
  const metadata = await lstat(path);
  if (!metadata.isDirectory() || metadata.isSymbolicLink() || (metadata.mode & 0o077) !== 0) {
    throw upgradeFailure(
      "MANIFEST_INVALID",
      "PREFLIGHT",
      `${label} must be an owner-only real directory: ${path}`,
      false,
    );
  }
}

function assertSnapshotMatchesRequest(
  manifest: SnapshotGroupManifest,
  configured: NonNullable<ProductionUpgradeRequest["snapshotGroup"]>,
  request: ProductionUpgradeRequest,
  requestBindingDigest: string,
  stoppedAt: string,
): void {
  const capturedAtMs = Date.parse(manifest.capturedAt);
  const stoppedAtMs = Date.parse(stoppedAt);
  const expectedProcessNames = [...request.cutoverProcessNames].sort();
  if (canonicalNoFollowPath(manifest.snapshotRoot, "snapshot manifest root")
      !== canonicalNoFollowPath(configured.snapshotRoot, "requested snapshot root")
    || manifest.entries.length !== configured.entries.length) {
    throw upgradeFailure(
      "SWITCH_FAILED",
      "SWITCHING",
      "Durable snapshot manifest does not match the exact v4 snapshot request.",
      false,
    );
  }
  if (manifest.barrier.kind !== "PM2_STOPPED"
    || manifest.barrier.transactionId !== request.transactionId
    || manifest.barrier.requestBindingDigest !== requestBindingDigest
    || manifest.barrier.processName !== request.pm2ProcessName
    || manifest.barrier.previousPid !== request.previous.pid
    || manifest.barrier.previousRuntimeIdentityDigest !== request.previous.runtimeIdentityDigest
    || manifest.barrier.previousMigrationManifestDigest !== request.previous.migrationManifestDigest
    || stableJson(manifest.barrier.cutoverProcessNames) !== stableJson(expectedProcessNames)
    || manifest.barrier.establishedAt !== new Date(stoppedAtMs).toISOString()
    || !Number.isFinite(capturedAtMs)
    || !Number.isFinite(stoppedAtMs)
    || capturedAtMs < stoppedAtMs) {
    throw upgradeFailure(
      "SWITCH_FAILED",
      "SWITCHING",
      "Durable snapshot barrier is not bound to this stopped transaction and exact request.",
      false,
    );
  }
  for (const requested of configured.entries) {
    const observed = manifest.entries.find((entry) => entry.id === requested.id);
    if (!observed
      || observed.kind !== requested.kind
      || canonicalNoFollowPath(observed.path, `snapshot manifest entry ${requested.id}`)
        !== canonicalNoFollowPath(requested.path, `requested snapshot entry ${requested.id}`)
      || observed.required !== (requested.required ?? true)) {
      throw upgradeFailure(
        "SWITCH_FAILED",
        "SWITCHING",
        `Durable snapshot manifest entry drifted: ${requested.id}`,
        false,
      );
    }
  }
  const previousCursor = manifest.entries.find(
    (entry) => entry.id === PRODUCTION_UPGRADE_PREVIOUS_CURSOR_SNAPSHOT_ENTRY.id,
  );
  const expectedPreviousCursorState = configured.paginationPreviousSigningKey.state === "PRESENT"
    ? "captured"
    : "absent";
  if (!previousCursor || previousCursor.state !== expectedPreviousCursorState) {
    throw upgradeFailure(
      "SWITCH_FAILED",
      "SWITCHING",
      `Pagination previous signing key snapshot state must be ${expectedPreviousCursorState}.`,
      false,
    );
  }
}

function requireTransitionAt(status: ProductionUpgradeStatus, state: ProductionUpgradeState): string {
  const matches = status.history?.filter((entry) => entry.state === state) ?? [];
  if (matches.length !== 1 || !Number.isFinite(Date.parse(matches[0]!.at))) {
    throw upgradeFailure(
      "SWITCH_FAILED",
      "SWITCHING",
      `Durable production upgrade status has no unique ${state} barrier.`,
      false,
    );
  }
  return new Date(matches[0]!.at).toISOString();
}

function pathIsSameOrInside(parent: string, child: string): boolean {
  const contained = relative(parent, child);
  return contained === "" || (
    contained !== ".."
    && !contained.startsWith(`..${sep}`)
    && !isAbsolute(contained)
  );
}

function assertRequiredBaseSnapshotInventory(entries: readonly SnapshotGroupEntryRequest[]): void {
  const byId = new Map(entries.map((entry) => [entry.id, entry]));
  const missing = REQUIRED_BASE_SNAPSHOT_STORES.filter((required) => {
    const entry = byId.get(required.id);
    return !entry || entry.kind !== required.kind || entry.required !== true;
  }).map((required) => required.id);
  if (missing.length > 0) {
    throw upgradeFailure(
      "MANIFEST_INVALID",
      "SWITCHING",
      `Cutover snapshot group is missing required Base mutable stores: ${missing.join(", ")}.`,
      false,
      { missing },
    );
  }
}

function databasePreimagesFromSnapshot(
  manifest: SnapshotGroupManifest,
): DatabasePreimages | undefined {
  const oauth = databasePreimageFromSnapshot(
    manifest.entries,
    ["oauth-main-and-connector-state", "oauth-database"],
  );
  const authority = databasePreimageFromSnapshot(
    manifest.entries,
    ["authority-store", "authority-database"],
  );
  if (!oauth || !authority) return undefined;
  return { capturedAt: manifest.capturedAt, oauth, authority };
}

function databasePreimageFromSnapshot(
  entries: readonly SnapshotGroupManifestEntry[],
  ids: readonly string[],
): DatabasePreimage | undefined {
  const entry = entries.find((candidate) => (
    candidate.kind === "sqlite"
    && candidate.state === "captured"
    && ids.includes(candidate.id)
  ));
  if (!entry?.snapshotPath || !entry.sha256) return undefined;
  return { path: entry.snapshotPath, sha256: entry.sha256 };
}

function databaseRestoreEvidenceFromSnapshot(
  entries: readonly SnapshotGroupRestoreEntry[],
  ids: readonly string[],
): DatabaseRestoreEvidence | undefined {
  const entry = entries.find((candidate) => (
    candidate.kind === "sqlite"
    && candidate.state === "captured"
    && ids.includes(candidate.id)
  ));
  if (!entry?.sha256) return undefined;
  return {
    restored: true,
    backupSha256: entry.sha256,
    restoredSha256: entry.sha256,
    staleSidecarsRemoved: true,
  };
}

function verifySqliteDatabase(path: string): void {
  const sqlite = new Database(path, { readonly: true, fileMustExist: true });
  try {
    const integrity = sqlite.pragma("integrity_check", { simple: true });
    if (integrity !== "ok") throw new Error(`SQLite integrity check failed for ${path}: ${String(integrity)}`);
    const foreignKeys = sqlite.pragma("foreign_key_check") as unknown[];
    if (foreignKeys.length > 0) throw new Error(`SQLite foreign-key check failed for ${path}.`);
  } finally {
    sqlite.close();
  }
}

async function fileSha256(path: string): Promise<string> {
  return `sha256:${createHash("sha256").update(await readFile(path)).digest("hex")}`;
}

async function installStartScript(request: ProductionUpgradeRequest): Promise<void> {
  const temporary = temporaryPath(request.startScriptPath);
  await writeFile(temporary, productionStartScriptContent(request), { mode: 0o700 });
  await rename(temporary, request.startScriptPath);
  await chmod(request.startScriptPath, 0o700);
}

function productionStartScriptContent(request: ProductionUpgradeRequest): string {
  return [
    "#!/bin/bash",
    "set -euo pipefail",
    `export DEVSPACE_PRODUCTION_ENV_FILE=${shellQuote(request.productionEnvPath)}`,
    `exec ${shellQuote(request.next.immutableRuntimeEntrypoint)}`,
    "",
  ].join("\n");
}

function pm2Process(request: ProductionUpgradeRequest): Pm2ProcessSnapshot | undefined {
  return pm2Inventory(request).find((candidate) => candidate.name === request.pm2ProcessName);
}

function pm2Inventory(request: ProductionUpgradeRequest): Pm2ProcessSnapshot[] {
  const result = runPm2(request, ["jlist"], 30_000);
  const start = result.stdout.indexOf("[");
  if (start < 0) throw new Error(`PM2 jlist did not return JSON: ${bounded(result.stdout)}`);
  const processes = JSON.parse(result.stdout.slice(start)) as Pm2ProcessSnapshot[];
  if (!Array.isArray(processes)) throw new Error("PM2 jlist did not return an array.");
  return processes;
}

function runPm2(
  request: ProductionUpgradeRequest,
  args: string[],
  timeout: number,
  allowFailure = false,
  env?: NodeJS.ProcessEnv,
): { stdout: string; stderr: string; status: number | null } {
  const result = spawnSync(request.pm2Executable, args, {
    encoding: "utf8",
    timeout,
    env: env ?? pm2CommandEnvironment(process.env),
    cwd: request.auditDirectory,
  });
  if (result.error) throw result.error;
  if (!allowFailure && result.status !== 0) {
    throw new Error(
      `pm2 ${args.join(" ")} failed with exit ${result.status ?? "null"}${result.signal ? ` signal ${result.signal}` : ""}: ${bounded(result.stderr || result.stdout)}`,
    );
  }
  return { stdout: result.stdout ?? "", stderr: result.stderr ?? "", status: result.status };
}

async function readRequest(path: string): Promise<ProductionUpgradeRequest> {
  const requestPath = resolve(path);
  if (canonicalNoFollowPath(requestPath, "production upgrade request") !== requestPath) {
    throw new Error(`Production upgrade request path identity drifted: ${path}`);
  }
  const handle = await open(requestPath, fsConstants.O_RDONLY | fsConstants.O_NOFOLLOW);
  let content: Buffer;
  try {
    const metadata = await handle.stat();
    const uid = typeof process.getuid === "function" ? process.getuid() : undefined;
    if (!metadata.isFile()
      || metadata.nlink !== 1
      || (metadata.mode & 0o077) !== 0
      || (uid !== undefined && metadata.uid !== uid)
      || metadata.size < 2
      || metadata.size > 16 * 1024 * 1024) {
      throw new Error(`Production upgrade request must be one bounded owner-only regular file: ${path}`);
    }
    content = await handle.readFile();
    const afterRead = await handle.stat();
    if (content.byteLength !== metadata.size
      || afterRead.dev !== metadata.dev
      || afterRead.ino !== metadata.ino
      || afterRead.nlink !== metadata.nlink
      || afterRead.mode !== metadata.mode
      || afterRead.uid !== metadata.uid
      || afterRead.size !== metadata.size
      || afterRead.mtimeMs !== metadata.mtimeMs
      || afterRead.ctimeMs !== metadata.ctimeMs) {
      throw new Error(`Production upgrade request changed during its stable file-descriptor read: ${path}`);
    }
  } finally {
    await handle.close();
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(content.toString("utf8"));
  } catch (error) {
    throw new Error(`Malformed production upgrade request JSON: ${path}`, { cause: error });
  }
  const request = validateProductionUpgradeRequestV4(parsed);
  if (content.toString("utf8") !== serializeProductionUpgradeRequestV4(request)) {
    throw new Error(
      "Production upgrade request bytes must equal one canonical code-unit JSON serialization plus newline.",
    );
  }
  return request;
}

async function transition(
  request: ProductionUpgradeRequest,
  status: ProductionUpgradeStatus,
  state: ProductionUpgradeState,
): Promise<ProductionUpgradeStatus> {
  const forwardFrom = FORWARD_CUTOVER_STATES.indexOf(status.state);
  const forwardTo = FORWARD_CUTOVER_STATES.indexOf(state);
  const rollbackAllowed = (state === "ROLLBACK_REQUESTED" && forwardFrom >= 0 && status.state !== "PASS")
    || (status.state === "ROLLBACK_REQUESTED" && state === "ROLLBACK_RESTORING");
  if (!rollbackAllowed && (forwardFrom < 0 || forwardTo !== forwardFrom + 1)) {
    throw new Error(`Invalid production upgrade transition: ${status.state} -> ${state}`);
  }
  await assertProductionUpgradeStatusCasBase(request.statusPath, status);
  const at = new Date().toISOString();
  const next = {
    ...status,
    state,
    updatedAt: at,
    history: [...(status.history ?? []), { state, at }],
  };
  await writeStatus(request.statusPath, next);
  return next;
}

async function acquireProductionUpgradeWorkerClaim(
  request: ProductionUpgradeRequest,
  requestBindingDigest: string,
): Promise<ProductionUpgradeWorkerClaim> {
  const claimPath = resolve(`${request.statusPath}.worker-claim.json`);
  await assertOwnerOnlyDirectory(dirname(claimPath), "production upgrade worker-claim directory");
  for (let attempt = 0; attempt < 3; attempt += 1) {
    const claim: ProductionUpgradeWorkerClaim = {
      schemaVersion: 1,
      claimId: randomUUID(),
      claimPath,
      transactionId: request.transactionId,
      requestBindingDigest,
      pid: process.pid,
      acquiredAt: new Date().toISOString(),
    };
    try {
      const handle = await open(claimPath, "wx", 0o600);
      try {
        await handle.writeFile(`${JSON.stringify(claim, null, 2)}\n`, "utf8");
        await handle.sync();
      } finally {
        await handle.close();
      }
      await chmod(claimPath, 0o600);
      await fsyncDirectoryPath(dirname(claimPath));
      return claim;
    } catch (error) {
      if (!isNodeError(error, "EEXIST")) throw error;
    }

    await assertOwnerOnlyRegularFile(claimPath, "production upgrade worker claim");
    const existing = JSON.parse(await readFile(claimPath, "utf8")) as unknown;
    if (!isProductionUpgradeWorkerClaim(existing)
      || existing.claimPath !== claimPath
      || existing.transactionId !== request.transactionId
      || existing.requestBindingDigest !== requestBindingDigest) {
      throw new Error("Existing production upgrade worker claim is malformed or foreign.");
    }
    if (processIsAlive(existing.pid)) {
      throw new Error(
        `Production upgrade transaction already has an active worker claim: ${existing.claimId}.`,
      );
    }
    const stalePath = `${claimPath}.stale-${existing.claimId}-${randomUUID()}`;
    try {
      await rename(claimPath, stalePath);
    } catch (error) {
      if (isNodeError(error, "ENOENT")) continue;
      throw error;
    }
    await fsyncDirectoryPath(dirname(claimPath));
    await rm(stalePath, { force: true });
    await fsyncDirectoryPath(dirname(claimPath));
  }
  throw new Error("Production upgrade worker claim could not be acquired after stale-claim reconciliation.");
}

async function releaseProductionUpgradeWorkerClaim(
  claim: ProductionUpgradeWorkerClaim,
): Promise<void> {
  let existing: unknown;
  try {
    await assertOwnerOnlyRegularFile(claim.claimPath, "production upgrade worker claim");
    existing = JSON.parse(await readFile(claim.claimPath, "utf8")) as unknown;
  } catch (error) {
    if (isNodeError(error, "ENOENT")) return;
    throw error;
  }
  if (!isProductionUpgradeWorkerClaim(existing) || existing.claimId !== claim.claimId) {
    throw new Error("Production upgrade worker claim changed before release.");
  }
  await rm(claim.claimPath, { force: true });
  await fsyncDirectoryPath(dirname(claim.claimPath));
}

async function assertProductionUpgradeStatusCasBase(
  path: string,
  expected: ProductionUpgradeStatus,
): Promise<void> {
  await assertOwnerOnlyRegularFile(path, "production upgrade status");
  const observed = JSON.parse(await readFile(path, "utf8")) as unknown;
  if (!isRecord(observed)
    || observed.version !== 2
    || observed.transactionId !== expected.transactionId
    || observed.requestBindingDigest !== expected.requestBindingDigest
    || observed.state !== expected.state
    || observed.updatedAt !== expected.updatedAt
    || !isProductionUpgradeWorkerClaim(observed.workerClaim)
    || observed.workerClaim.claimId !== expected.workerClaim?.claimId) {
    throw new Error("Production upgrade status changed outside the active worker claim.");
  }
}

function isProductionUpgradeWorkerClaim(value: unknown): value is ProductionUpgradeWorkerClaim {
  return isRecord(value)
    && value.schemaVersion === 1
    && typeof value.claimId === "string"
    && /^[a-f0-9-]{36}$/u.test(value.claimId)
    && typeof value.claimPath === "string"
    && isAbsolute(value.claimPath)
    && typeof value.transactionId === "string"
    && TRANSACTION_PATTERN.test(value.transactionId)
    && isSha256Digest(value.requestBindingDigest)
    && Number.isSafeInteger(value.pid)
    && (value.pid as number) > 0
    && typeof value.acquiredAt === "string"
    && Number.isFinite(Date.parse(value.acquiredAt));
}

function processIsAlive(pid: number): boolean {
  try {
    process.kill(pid, 0);
    return true;
  } catch (error) {
    return !isNodeError(error, "ESRCH");
  }
}

function gitValue(request: ProductionUpgradeRequest, args: string[]): string {
  const result = spawnSync(request.gitExecutable, args, {
    encoding: "utf8",
    timeout: 30_000,
    cwd: request.auditDirectory,
    env: pm2CommandEnvironment(process.env),
  });
  if (result.error) throw result.error;
  if (result.status !== 0) {
    throw new Error(`git ${args.join(" ")} failed: ${bounded(result.stderr || result.stdout)}`);
  }
  return (result.stdout ?? "").trim();
}

export async function directoryEvidence(directory: string): Promise<{ files: number; sha256: string }> {
  const root = resolve(directory);
  const files: string[] = [];
  const visit = async (current: string): Promise<void> => {
    const entries = (await readdir(current, { withFileTypes: true }))
      .sort((left, right) => compareCodeUnits(left.name, right.name));
    for (const entry of entries) {
      const path = join(current, entry.name);
      if (entry.isDirectory()) await visit(path);
      else if (entry.isFile()) files.push(path);
    }
  };
  await visit(root);
  files.sort((left, right) => compareCodeUnits(relative(root, left), relative(root, right)));
  const digest = createHash("sha256");
  for (const path of files) {
    const rel = relative(root, path).replaceAll("\\", "/");
    const content = await readFile(path);
    digest.update(rel);
    digest.update("\0");
    digest.update(createHash("sha256").update(content).digest("hex"));
    digest.update("\n");
  }
  return { files: files.length, sha256: digest.digest("hex") };
}

async function writeStatus(path: string, value: ProductionUpgradeStatus): Promise<void> {
  await mkdir(dirname(path), { recursive: true, mode: 0o700 });
  const temporary = temporaryPath(path);
  const handle = await open(temporary, "wx", 0o600);
  try {
    await handle.writeFile(`${JSON.stringify(value, null, 2)}\n`, "utf8");
    await handle.sync();
  } finally {
    await handle.close();
  }
  await chmod(temporary, 0o600);
  await rename(temporary, path);
  await fsyncDirectoryPath(dirname(path));
}

async function preflightRollbackControlJournal(
  request: ProductionUpgradeRequest,
  requestBindingDigest: string,
): Promise<void> {
  const path = request.rollbackJournalPath;
  await mkdir(dirname(path), { recursive: true, mode: 0o700 });
  let created = false;
  try {
    const handle = await open(path, "wx", 0o600);
    try {
      await handle.sync();
    } finally {
      await handle.close();
    }
    created = true;
  } catch (error) {
    if (!isNodeError(error, "EEXIST")) throw error;
  }
  if (created) {
    await chmod(path, 0o600);
    await fsyncDirectoryPath(dirname(path));
  }
  await assertOwnerOnlyRegularFile(path, "rollback control journal");
  const records = await readRollbackControlRecords(
    path,
    request.transactionId,
    requestBindingDigest,
  );
  if (records.length > 0) {
    throw upgradeFailure(
      "ROLLBACK_FAILED",
      "PREFLIGHT",
      "Rollback control journal already contains durable rollback evidence; forward cutover cannot replay.",
      false,
      { path, terminalEvent: records.at(-1)?.event },
    );
  }
}

async function readRollbackControlRecords(
  path: string,
  transactionId: string,
  requestBindingDigest: string,
): Promise<RollbackControlRecord[]> {
  await assertOwnerOnlyRegularFile(path, "rollback control journal");
  const records: RollbackControlRecord[] = [];
  const lines = (await readFile(path, "utf8")).split("\n").filter(Boolean);
  for (const line of lines) {
    let record: unknown;
    try {
      record = JSON.parse(line) as unknown;
    } catch {
      throw new Error("Rollback control journal contains invalid JSON.");
    }
    if (!isRecord(record)
      || record.schemaVersion !== 1
      || typeof record.event !== "string"
      || !ROLLBACK_CONTROL_EVENTS.includes(record.event as RollbackControlEvent)
      || record.transactionId !== transactionId
      || record.requestBindingDigest !== requestBindingDigest) {
      throw new Error("Rollback control journal contains a malformed or foreign record.");
    }
    if (record.event === "ROLLBACK_REQUESTED") {
      if (!isNullableSha256Digest(record.snapshotGroupDigest)
        || (record.activationReceiptId !== null
          && (typeof record.activationReceiptId !== "string" || record.activationReceiptId.length === 0))
        || !isNullableSha256Digest(record.activationReceiptDigest)
        || typeof record.requestedAt !== "string"
        || !Number.isFinite(Date.parse(record.requestedAt))
        || typeof record.failureCode !== "string"
        || !PRODUCTION_UPGRADE_FAILURE_CODES.includes(record.failureCode as ProductionUpgradeFailureCode)) {
        throw new Error("Rollback control journal contains an invalid rollback-request tombstone.");
      }
    } else if (!isNullableSha256Digest(record.snapshotGroupDigest)
      || (record.activationReceiptId !== null
        && (typeof record.activationReceiptId !== "string" || record.activationReceiptId.length === 0))
      || !isNullableSha256Digest(record.activationReceiptDigest)
      || typeof record.recordedAt !== "string"
      || !Number.isFinite(Date.parse(record.recordedAt))
      || !isSha256Digest(record.evidenceDigest)) {
      throw new Error("Rollback control journal contains invalid terminal evidence.");
    }
    records.push(record as RollbackControlRecord);
  }
  validateRollbackControlSequence(records);
  return records;
}

function validateRollbackControlSequence(records: readonly RollbackControlRecord[]): void {
  if (records.length === 0) return;
  if (records[0]?.event !== "ROLLBACK_REQUESTED" || records.length > 3) {
    throw new Error("Rollback control journal event sequence is invalid.");
  }
  const restore = records[1]?.event;
  if (restore !== undefined
    && restore !== "ROLLBACK_RESTORE_VERIFIED"
    && restore !== "ROLLBACK_RESTORE_UNKNOWN") {
    throw new Error("Rollback control journal restore sequence is invalid.");
  }
  const runtime = records[2]?.event;
  if (runtime !== undefined
    && runtime !== "ROLLBACK_RUNTIME_VERIFIED"
    && runtime !== "ROLLBACK_RUNTIME_UNKNOWN") {
    throw new Error("Rollback control journal runtime sequence is invalid.");
  }
  if (restore === "ROLLBACK_RESTORE_UNKNOWN" && runtime === "ROLLBACK_RUNTIME_VERIFIED") {
    throw new Error("Rollback control journal cannot verify a runtime after an unknown restore.");
  }
}

function isNullableSha256Digest(value: unknown): value is string | null {
  return value === null || isSha256Digest(value);
}

async function ensureRollbackRequestedRecord(
  path: string,
  value: RollbackRequestedRecord,
): Promise<RollbackRequestedRecord> {
  const records = await readRollbackControlRecords(
    path,
    value.transactionId,
    value.requestBindingDigest,
  );
  const existing = records.find(
    (record): record is RollbackRequestedRecord => record.event === "ROLLBACK_REQUESTED",
  );
  if (existing) {
    if (records.length !== 1
      || existing.snapshotGroupDigest !== value.snapshotGroupDigest
      || existing.activationReceiptId !== value.activationReceiptId
      || existing.activationReceiptDigest !== value.activationReceiptDigest) {
      throw new Error(
        "Durable rollback request does not match the current snapshot and activation boundary.",
      );
    }
    return existing;
  }
  await appendRollbackRecord(path, value);
  return value;
}

async function appendRollbackRecord(
  path: string,
  value: Readonly<RollbackControlRecord>,
): Promise<void> {
  await mkdir(dirname(path), { recursive: true, mode: 0o700 });
  const records = await readRollbackControlRecords(
    path,
    value.transactionId,
    value.requestBindingDigest,
  );
  validateRollbackControlSequence([...records, value]);
  const handle = await open(path, "a", 0o600);
  try {
    await handle.write(`${JSON.stringify(value)}\n`, undefined, "utf8");
    await handle.sync();
  } finally {
    await handle.close();
  }
  await chmod(path, 0o600);
  await fsyncDirectoryPath(dirname(path));
}

async function failRollbackControlPlane(
  request: ProductionUpgradeRequest,
  status: ProductionUpgradeStatus,
  failure: ProductionUpgradeFailure,
  originalError: unknown,
  controlError: unknown,
  rollbackEvidence?: Record<string, unknown>,
  rollbackRequestDurable = false,
): Promise<never> {
  let containmentError: unknown;
  try {
    stopCutoverProcesses(request);
  } catch (error) {
    containmentError = error;
  }
  const at = new Date().toISOString();
  const unknownRollback = {
    ...(rollbackEvidence ?? {}),
    attempted: true,
    restored: rollbackEvidence?.restored === true,
    verified: false,
    outcome: "ROLLBACK_CONTROL_JOURNAL_UNAVAILABLE",
    controlJournal: {
      path: request.rollbackJournalPath,
      rollbackRequestDurable,
      terminalEvidenceDurable: false,
      error: errorMessage(controlError),
    },
    processContainment: {
      stopped: containmentError === undefined,
      ...(containmentError === undefined ? {} : { error: errorMessage(containmentError) }),
    },
  };
  const unknownStatus: ProductionUpgradeStatus = {
    ...status,
    state: "ROLLBACK_UNKNOWN",
    updatedAt: at,
    error: failure.message,
    failure,
    rollback: unknownRollback,
    history: [...(status.history ?? []), { state: "ROLLBACK_UNKNOWN", at }],
  };
  try {
    await writeStatus(request.statusPath, unknownStatus);
  } catch (statusError) {
    throw new AggregateError(
      [originalError, controlError, containmentError, statusError].filter((item) => item !== undefined),
      `${failure.message}; rollback control journal and status persistence failed closed.`,
    );
  }
  throw originalError;
}

async function fsyncDirectoryPath(path: string): Promise<void> {
  const handle = await open(path, "r");
  try {
    await handle.sync();
  } catch (error) {
    if (!isNodeError(error, "EINVAL")
      && !isNodeError(error, "ENOTSUP")
      && !isNodeError(error, "EISDIR")
      && !isNodeError(error, "EPERM")) throw error;
  } finally {
    await handle.close();
  }
}

async function installFile(source: string, destination: string, mode: number): Promise<void> {
  const temporary = temporaryPath(destination);
  await copyFile(source, temporary);
  await chmod(temporary, mode);
  await rename(temporary, destination);
}

async function replaceSymlink(path: string, target: string): Promise<void> {
  await mkdir(dirname(path), { recursive: true, mode: 0o700 });
  const temporary = temporaryPath(path);
  await rm(temporary, { force: true, recursive: true });
  await symlink(target, temporary);
  await rename(temporary, path);
}

async function httpStatus(url: string, init?: RequestInit, fetcher: typeof fetch = fetch): Promise<number> {
  const response = await fetchWithTimeout(url, init, fetcher);
  await response.body?.cancel();
  return response.status;
}

async function fetchWithTimeout(url: string, init?: RequestInit, fetcher: typeof fetch = fetch): Promise<Response> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 10_000);
  timer.unref?.();
  try {
    return await fetcher(url, { ...init, redirect: "error", cache: "no-store", signal: controller.signal });
  } finally {
    clearTimeout(timer);
  }
}

function removeLaunchdJob(label: string | undefined): void {
  if (!label || process.platform !== "darwin") return;
  spawnSync("/bin/launchctl", ["remove", label], { encoding: "utf8", timeout: 5_000 });
}

function temporaryPath(path: string): string {
  return join(dirname(path), `.${basename(path)}.${process.pid}.${randomUUID()}.tmp`);
}

function shellQuote(value: string): string {
  return `'${value.replaceAll("'", `'"'"'`)}'`;
}

function sleep(milliseconds: number): Promise<void> {
  return new Promise((resolvePromise) => setTimeout(resolvePromise, milliseconds));
}

function bounded(value: string, maximum = 2_000): string {
  return value.length <= maximum ? value : `${value.slice(0, maximum)}…`;
}

function sha256Digest(value: string): string {
  return `sha256:${createHash("sha256").update(value).digest("hex")}`;
}

function stableJson(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(stableJson).join(",")}]`;
  if (value && typeof value === "object") {
    return `{${Object.entries(value as Record<string, unknown>)
      .filter(([, item]) => item !== undefined)
      .sort(([left], [right]) => compareCodeUnits(left, right))
      .map(([key, item]) => `${JSON.stringify(key)}:${stableJson(item)}`)
      .join(",")}}`;
  }
  return JSON.stringify(value) ?? "null";
}

function compareCodeUnits(left: string, right: string): number {
  return left < right ? -1 : left > right ? 1 : 0;
}

function isNodeError(error: unknown, code: string): error is NodeJS.ErrnoException {
  return error instanceof Error && (error as NodeJS.ErrnoException).code === code;
}

const invokedPath = process.argv[1] ? resolve(process.argv[1]) : undefined;
if (invokedPath && invokedPath === fileURLToPath(import.meta.url)) {
  const requestPath = process.argv[2];
  if (!requestPath) {
    console.error("Production upgrade worker requires a request path.");
    process.exitCode = 2;
  } else {
    void runProductionUpgradeWorker(requestPath).catch((error) => {
      console.error(error instanceof Error ? error.stack ?? error.message : String(error));
      process.exitCode = 1;
    });
  }
}
