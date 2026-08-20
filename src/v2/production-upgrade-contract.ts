import { createHash } from "node:crypto";
import { basename, isAbsolute, join, normalize, relative, resolve, sep } from "node:path";

export type ProductionUpgradeSha256Digest = `sha256:${string}`;
export type ProductionUpgradeHmacSha256Tag = `hmac-sha256:${string}`;

export interface ProductionUpgradeArtifactReference {
  path: string;
  sha256: ProductionUpgradeSha256Digest;
}

export interface ProductionUpgradeCandidateIdentity {
  runtimeIdentityDigest: ProductionUpgradeSha256Digest;
  buildDigest: ProductionUpgradeSha256Digest;
  schemaGeneration: ProductionUpgradeSha256Digest;
  authorityContractGeneration: ProductionUpgradeSha256Digest;
  buildCapabilityManifestDigest: ProductionUpgradeSha256Digest;
  generatedSchemaDigest: ProductionUpgradeSha256Digest;
  packageSha256: ProductionUpgradeSha256Digest;
}

export type ProductionUpgradeSnapshotEntryKind = "sqlite" | "file" | "directory";

export interface ProductionUpgradeSnapshotEntry {
  id: string;
  kind: ProductionUpgradeSnapshotEntryKind;
  path: string;
  required: boolean;
}

const REQUIRED_SNAPSHOT_ENTRY_DEFINITIONS = [
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
] as const satisfies ReadonlyArray<{ id: string; kind: ProductionUpgradeSnapshotEntryKind }>;

export const PRODUCTION_UPGRADE_REQUIRED_SNAPSHOT_ENTRIES = Object.freeze(
  REQUIRED_SNAPSHOT_ENTRY_DEFINITIONS.map((entry) => Object.freeze({ ...entry })),
) as unknown as typeof REQUIRED_SNAPSHOT_ENTRY_DEFINITIONS;

export const PRODUCTION_UPGRADE_PREVIOUS_CURSOR_SNAPSHOT_ENTRY = Object.freeze({
  id: "pagination-previous-signing-key",
  kind: "file",
} as const);

export const PRODUCTION_UPGRADE_RELEASE_DRIVER_PROVENANCE_KEYS = Object.freeze([
  "stagingPrecheckRequest",
  "stagingActivationRequest",
  "stagingActivationReadback",
  "preCutoverRequest",
  "productionPredecisionRequest",
  "productionPredecisionEnvelope",
  "productionPreparationRequest",
] as const);

export const PRODUCTION_UPGRADE_EXPECTED_SCOPES = Object.freeze([
  "devspace.read",
  "devspace.write",
  "devspace.exec",
  "devspace.mcp",
  "devspace.artifact",
  "devspace.gui",
  "offline_access",
] as const);

export interface ProductionUpgradeRequestV4 {
  version: 4;
  transactionId: string;
  requestedAt: string;
  delayMs: number;
  timeoutMs: number;
  pm2ProcessName: string;
  pm2Executable: string;
  gitExecutable: string;
  previous: {
    pid: number;
    cwd: string;
    script: string;
    auditTarget?: string;
    runtimeIdentityDigest: ProductionUpgradeSha256Digest;
    migrationManifestDigest: ProductionUpgradeSha256Digest;
    localHealthUrl: string;
    localReadyUrl: string;
    rollbackHostChallenge: {
      rollbackChallengeRequest: ProductionUpgradeArtifactReference;
      challengePath: string;
      challengeSha256: ProductionUpgradeSha256Digest;
      receiptPath: string;
      deadlineAt: string;
      pollIntervalMs: number;
    };
  };
  next: {
    commit: string;
    sourceTree: string;
    sourceEvidenceRoot: string;
    immutableRuntimeRoot: string;
    immutableRuntimeEntrypoint: string;
    runtimeDependencies: {
      root: string;
      evidencePath: string;
      evidenceSha256: ProductionUpgradeSha256Digest;
    };
    dist: {
      files: number;
      sha256: string;
    };
    manifest: {
      path: string;
      sha256: ProductionUpgradeSha256Digest;
      buildDigest: ProductionUpgradeSha256Digest;
      runtimeRevision: string;
      schemaGeneration: ProductionUpgradeSha256Digest;
      authorityContractGeneration: ProductionUpgradeSha256Digest;
      configSchemaIdentity: ProductionUpgradeSha256Digest;
      migrationManifestDigest: ProductionUpgradeSha256Digest;
      buildCapabilityManifestDigest: ProductionUpgradeSha256Digest;
      generatedSchemaDigest: ProductionUpgradeSha256Digest;
      packageSha256: ProductionUpgradeSha256Digest;
      runtimeIdentityDigest: ProductionUpgradeSha256Digest;
    };
  };
  oauthStateDirectory: string;
  productionEnvPath: string;
  productionEnvBackupPath: string;
  oauthDatabasePath: string;
  oauthDatabaseBackupPath: string;
  authorityDatabasePath: string;
  authorityDatabaseBackupPath: string;
  snapshotGroup: {
    snapshotRoot: string;
    manifestPath: string;
    paginationPreviousSigningKey:
      | { state: "ABSENT"; path: string }
      | { state: "PRESENT"; path: string };
    barrier: {
      kind: "PM2_STOPPED";
      transactionId: string;
      processName: string;
      previousPid: number;
      previousRuntimeIdentityDigest: ProductionUpgradeSha256Digest;
      previousMigrationManifestDigest: ProductionUpgradeSha256Digest;
      candidateIdentityDigest: ProductionUpgradeSha256Digest;
      cutoverProcessNames: string[];
      captureDeadlineAt: string;
    };
    entries: ProductionUpgradeSnapshotEntry[];
  };
  cutoverProcessNames: string[];
  connectorLifecycle: {
    bindingDigest: ProductionUpgradeSha256Digest;
    stagingActivationPrecheck: ProductionUpgradeArtifactReference;
    preCutoverHostCanary: ProductionUpgradeArtifactReference;
    releaseDriver: {
      stagingPrecheckRequest: ProductionUpgradeArtifactReference;
      stagingActivationRequest: ProductionUpgradeArtifactReference;
      stagingActivationReadback: ProductionUpgradeArtifactReference;
      preCutoverRequest: ProductionUpgradeArtifactReference;
      productionPredecisionRequest: ProductionUpgradeArtifactReference;
      productionPredecisionEnvelope: ProductionUpgradeArtifactReference;
      productionPreparationRequest: ProductionUpgradeArtifactReference;
      productionApprovalOutputDirectory: string;
    };
    journal: {
      path: string;
      identity: {
        storeId: string;
        storePath: string;
        schemaVersion: 1;
        migrationManifestDigest: ProductionUpgradeSha256Digest;
        contentGeneration: ProductionUpgradeSha256Digest;
        snapshotPolicy: "PRESERVE_OUTSIDE_MUTABLE_ROLLBACK";
        receiptReplayPolicy: "PREPARED_RECEIPT_PERMANENTLY_ONE_SHOT";
        schemaFingerprint: ProductionUpgradeSha256Digest;
        createdAtMs: number;
      };
    };
    postActivation: {
      challengePath: string;
      challengeSha256: ProductionUpgradeSha256Digest;
      receiptPath: string;
      deadlineAt: string;
      pollIntervalMs: number;
      runtimeIdentityUrl: string;
      routeIdentityUrl: string;
    };
    managementAuthorizationKeyRef: string;
    managementNonce: string;
    managementCorrelationId: string;
    candidateIdentity: ProductionUpgradeCandidateIdentity;
    oauthResource: string;
    productionEnvironmentIdentityDigest: ProductionUpgradeSha256Digest;
    productionRouteIdentityDigest: ProductionUpgradeSha256Digest;
    finalization: {
      storePath: string;
      controlPath: string;
      keyId: string;
      /** Format/binding only; the worker must rederive this identity from trusted pinned runtime configuration. */
      gateProducer: {
        keyId: string;
        publicKeySha256: ProductionUpgradeSha256Digest;
      };
      /** Identity-only reference; the trusted verifier owns anchor authentication and one-time semantics. */
      gateProducerTrustAnchor: ProductionUpgradeArtifactReference;
      /** Provisional format/binding only until the keyed finalization store freezes its exact digest projection. */
      preSnapshotIdentity: {
        storeId: "lifecycle-finalization-store";
        schemaVersion: 2;
        state: "DRAFT";
        revision: 1;
        transactionId: null;
        contentGeneration: ProductionUpgradeSha256Digest;
        controlEpoch: number;
        controlTag: ProductionUpgradeHmacSha256Tag;
        identityDigest: ProductionUpgradeSha256Digest;
      };
    };
  };
  rollbackJournalPath: string;
  nextEnvPath: string;
  startScriptPath: string;
  startScriptBackupPath: string;
  auditDirectory: string;
  currentAuditLink: string;
  statusPath: string;
  workerClaimPath: string;
  workerLogPath: string;
  localHealthUrl: string;
  localDoctorUrl: string;
  publicHealthUrl: string;
  publicMetricsUrl: string;
  publicMcpUrl: string;
  oauthMetadataUrl: string;
  expectedScopes: string[];
  launchdLabel?: string;
}

export interface ProductionUpgradeProducedApprovalArtifacts {
  /** Identity-only durable status record; the signed driver manifest remains the sole semantic authority. */
  outputDirectory: string;
  manifest: ProductionUpgradeArtifactReference;
  productionActivationPrecheck: ProductionUpgradeArtifactReference;
  ownerManagementApproval: ProductionUpgradeArtifactReference;
  recordedAt: string;
}

export class ProductionUpgradeContractError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "ProductionUpgradeContractError";
  }
}

const TRANSACTION_PATTERN = /^upgrade_[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;
const UUID_V4_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;
const SHA256_PATTERN = /^sha256:[a-f0-9]{64}$/u;
const HMAC_SHA256_PATTERN = /^hmac-sha256:[a-f0-9]{64}$/u;
const GATE_PRODUCER_PATTERN = /^gate-producer-ed25519-sha256:([a-f0-9]{64})$/u;
const MANAGEMENT_KEY_PATTERN = /^management-[a-f0-9]{24}$/u;
const PROCESS_NAME_PATTERN = /^[A-Za-z0-9_.-]{1,128}$/u;
const RELEASE_ID_PATTERN = /^[0-9a-f]{40,64}$/u;
const MAX_EVIDENCE_LIFETIME_MS = 30 * 60_000;

const TOP_LEVEL_REQUIRED_KEYS = Object.freeze([
  "auditDirectory", "authorityDatabaseBackupPath", "authorityDatabasePath", "connectorLifecycle",
  "currentAuditLink", "cutoverProcessNames", "delayMs", "expectedScopes", "gitExecutable",
  "localDoctorUrl", "localHealthUrl", "next", "nextEnvPath", "oauthDatabaseBackupPath",
  "oauthDatabasePath", "oauthMetadataUrl", "oauthStateDirectory", "pm2Executable",
  "pm2ProcessName", "previous", "productionEnvBackupPath", "productionEnvPath",
  "publicHealthUrl", "publicMcpUrl", "publicMetricsUrl", "requestedAt", "rollbackJournalPath",
  "snapshotGroup", "startScriptBackupPath", "startScriptPath", "statusPath", "timeoutMs",
  "transactionId", "version", "workerClaimPath", "workerLogPath",
] as const);

/**
 * Validates, clones, and deep-freezes the exact dependency-neutral v4 request.
 * No filesystem, process, OAuth, finalization, or provider access occurs here.
 */
export function validateProductionUpgradeRequestV4(value: unknown): ProductionUpgradeRequestV4 {
  const request = validateRequestStructure(value);
  const observedLifecycleBinding = computeLifecycleBindingDigest(request);
  if (request.connectorLifecycle.bindingDigest !== observedLifecycleBinding) {
    fail("connectorLifecycle.bindingDigest", "does not match the exact v4 lifecycle binding");
  }
  return deepFreeze(request);
}

/**
 * Computes the lifecycle binding after exact structural validation. This helper
 * intentionally ignores the supplied bindingDigest so a request publisher can
 * populate that one non-recursive field before computing the full request hash.
 */
export function productionUpgradeLifecycleBindingDigest(value: unknown): ProductionUpgradeSha256Digest {
  return computeLifecycleBindingDigest(validateRequestStructure(value));
}

/** The only supported v4 request digest entrypoint. Arbitrary objects are rejected first. */
export function productionUpgradeRequestBindingDigest(value: unknown): ProductionUpgradeSha256Digest {
  const request = validateProductionUpgradeRequestV4(value);
  return sha256Digest(canonicalizeJson(request));
}

export function serializeProductionUpgradeRequestV4(value: unknown): string {
  return `${canonicalizeJson(validateProductionUpgradeRequestV4(value))}\n`;
}

export function productionUpgradeCandidateIdentityDigest(
  value: unknown,
): ProductionUpgradeSha256Digest {
  const candidate = cloneExactJson(value, "candidateIdentity");
  validateCandidateIdentity(candidate, "candidateIdentity");
  return sha256Digest(canonicalizeJson(candidate));
}

export function validateProductionUpgradeProducedApprovalArtifacts(
  value: unknown,
  expectedOutputDirectory: string,
): ProductionUpgradeProducedApprovalArtifacts {
  const cloned = cloneExactJson(value, "producedApprovalArtifacts");
  const produced = record(cloned, "producedApprovalArtifacts");
  exactKeys(produced, [
    "manifest", "outputDirectory", "ownerManagementApproval", "productionActivationPrecheck",
    "recordedAt",
  ], [], "producedApprovalArtifacts");
  absolutePath(produced.outputDirectory, "producedApprovalArtifacts.outputDirectory");
  absolutePath(expectedOutputDirectory, "expectedOutputDirectory");
  if (produced.outputDirectory !== expectedOutputDirectory) {
    fail("producedApprovalArtifacts.outputDirectory", "does not match the prebound output directory");
  }
  artifactReference(produced.manifest, "producedApprovalArtifacts.manifest");
  artifactReference(
    produced.productionActivationPrecheck,
    "producedApprovalArtifacts.productionActivationPrecheck",
  );
  artifactReference(produced.ownerManagementApproval, "producedApprovalArtifacts.ownerManagementApproval");
  const outputDirectory = produced.outputDirectory as string;
  const expectedPaths = new Map<string, string>([
    ["manifest", join(outputDirectory, "manifest.json")],
    ["productionActivationPrecheck", join(outputDirectory, "production-activation-precheck.json")],
    ["ownerManagementApproval", join(outputDirectory, "owner-management-approval.json")],
  ]);
  for (const [key, expectedPath] of expectedPaths) {
    if ((produced[key] as ProductionUpgradeArtifactReference).path !== expectedPath) {
      fail(`producedApprovalArtifacts.${key}.path`, "does not use the frozen driver output filename");
    }
  }
  isoTimestamp(produced.recordedAt, "producedApprovalArtifacts.recordedAt");
  return deepFreeze(produced as unknown as ProductionUpgradeProducedApprovalArtifacts);
}

export function canonicalizeProductionUpgradeValue(value: unknown): string {
  return canonicalizeJson(cloneExactJson(value, "value"));
}

function validateRequestStructure(value: unknown): ProductionUpgradeRequestV4 {
  const cloned = cloneExactJson(value, "request");
  const request = record(cloned, "request");
  exactKeys(request, TOP_LEVEL_REQUIRED_KEYS, ["launchdLabel"], "request");
  literal(request.version, 4, "version");
  requiredPattern(request.transactionId, TRANSACTION_PATTERN, "transactionId");
  const requestedAtMs = isoTimestamp(request.requestedAt, "requestedAt");
  integer(request.delayMs, 0, 60_000, "delayMs");
  integer(request.timeoutMs, 100, 15 * 60_000, "timeoutMs");
  requiredPattern(request.pm2ProcessName, PROCESS_NAME_PATTERN, "pm2ProcessName");
  absolutePath(request.pm2Executable, "pm2Executable");
  absolutePath(request.gitExecutable, "gitExecutable");
  if (request.launchdLabel !== undefined) {
    requiredPattern(request.launchdLabel, /^[A-Za-z0-9_.-]{1,256}$/u, "launchdLabel");
  }

  validatePrevious(request.previous, request.transactionId, requestedAtMs);
  validateNext(request.next);
  absolutePath(request.oauthStateDirectory, "oauthStateDirectory");
  for (const key of [
    "productionEnvPath", "productionEnvBackupPath", "oauthDatabasePath", "oauthDatabaseBackupPath",
    "authorityDatabasePath", "authorityDatabaseBackupPath", "rollbackJournalPath", "nextEnvPath",
    "startScriptPath", "startScriptBackupPath", "auditDirectory", "currentAuditLink", "statusPath",
    "workerClaimPath", "workerLogPath",
  ] as const) {
    absolutePath(request[key], key);
  }
  if (request.oauthDatabasePath !== join(request.oauthStateDirectory, "devspace.sqlite")) {
    fail("oauthDatabasePath", "must be the canonical devspace.sqlite inside oauthStateDirectory");
  }
  if (request.workerClaimPath !== `${request.statusPath}.worker-claim.json`) {
    fail("workerClaimPath", "must be derived exactly from statusPath");
  }

  validateCutoverProcessNames(request.cutoverProcessNames, request.pm2ProcessName, "cutoverProcessNames");
  validateConnectorLifecycle(request.connectorLifecycle, requestedAtMs);
  validateSnapshotGroup(request, requestedAtMs);
  validateUrlsAndScopes(request);
  validateCrossBindings(request);
  validatePathTopology(request);
  return request as unknown as ProductionUpgradeRequestV4;
}

function validatePrevious(value: unknown, transactionId: string, requestedAtMs: number): void {
  const previous = record(value, "previous");
  exactKeys(previous, [
    "cwd", "localHealthUrl", "localReadyUrl", "migrationManifestDigest", "pid",
    "rollbackHostChallenge", "runtimeIdentityDigest", "script",
  ], ["auditTarget"], "previous");
  integer(previous.pid, 1, Number.MAX_SAFE_INTEGER, "previous.pid");
  absolutePath(previous.cwd, "previous.cwd");
  absolutePath(previous.script, "previous.script");
  if (previous.auditTarget !== undefined) absolutePath(previous.auditTarget, "previous.auditTarget");
  sha256(previous.runtimeIdentityDigest, "previous.runtimeIdentityDigest");
  sha256(previous.migrationManifestDigest, "previous.migrationManifestDigest");
  httpUrl(previous.localHealthUrl, "previous.localHealthUrl", true);
  httpUrl(previous.localReadyUrl, "previous.localReadyUrl", true);

  const rollback = record(previous.rollbackHostChallenge, "previous.rollbackHostChallenge");
  exactKeys(rollback, [
    "challengePath", "challengeSha256", "deadlineAt", "pollIntervalMs", "receiptPath",
    "rollbackChallengeRequest",
  ], [], "previous.rollbackHostChallenge");
  artifactReference(rollback.rollbackChallengeRequest, "previous.rollbackHostChallenge.rollbackChallengeRequest");
  absolutePath(rollback.challengePath, "previous.rollbackHostChallenge.challengePath");
  sha256(rollback.challengeSha256, "previous.rollbackHostChallenge.challengeSha256");
  absolutePath(rollback.receiptPath, "previous.rollbackHostChallenge.receiptPath");
  boundedDeadline(rollback.deadlineAt, requestedAtMs, "previous.rollbackHostChallenge.deadlineAt");
  integer(rollback.pollIntervalMs, 10, 5_000, "previous.rollbackHostChallenge.pollIntervalMs");
  const rollbackPaths = [
    (rollback.rollbackChallengeRequest as ProductionUpgradeArtifactReference).path,
    rollback.challengePath as string,
    rollback.receiptPath as string,
  ];
  if (new Set(rollbackPaths).size !== rollbackPaths.length) {
    fail("previous.rollbackHostChallenge", "rollback request, challenge, and receipt paths must be distinct");
  }
  void transactionId;
}

function validateNext(value: unknown): void {
  const next = record(value, "next");
  exactKeys(next, [
    "commit", "dist", "immutableRuntimeEntrypoint", "immutableRuntimeRoot", "manifest",
    "runtimeDependencies", "sourceEvidenceRoot", "sourceTree",
  ], [], "next");
  requiredPattern(next.commit, RELEASE_ID_PATTERN, "next.commit");
  requiredPattern(next.sourceTree, RELEASE_ID_PATTERN, "next.sourceTree");
  absolutePath(next.sourceEvidenceRoot, "next.sourceEvidenceRoot");
  absolutePath(next.immutableRuntimeRoot, "next.immutableRuntimeRoot");
  absolutePath(next.immutableRuntimeEntrypoint, "next.immutableRuntimeEntrypoint");
  requireStrictDescendant(
    next.immutableRuntimeRoot as string,
    next.immutableRuntimeEntrypoint as string,
    "next.immutableRuntimeEntrypoint",
  );

  const dependencies = record(next.runtimeDependencies, "next.runtimeDependencies");
  exactKeys(dependencies, ["evidencePath", "evidenceSha256", "root"], [], "next.runtimeDependencies");
  absolutePath(dependencies.root, "next.runtimeDependencies.root");
  absolutePath(dependencies.evidencePath, "next.runtimeDependencies.evidencePath");
  sha256(dependencies.evidenceSha256, "next.runtimeDependencies.evidenceSha256");
  requireStrictDescendant(
    dependencies.root as string,
    dependencies.evidencePath as string,
    "next.runtimeDependencies.evidencePath",
  );

  const dist = record(next.dist, "next.dist");
  exactKeys(dist, ["files", "sha256"], [], "next.dist");
  integer(dist.files, 1, Number.MAX_SAFE_INTEGER, "next.dist.files");
  requiredPattern(dist.sha256, /^[a-f0-9]{64}$/u, "next.dist.sha256");

  const manifest = record(next.manifest, "next.manifest");
  exactKeys(manifest, [
    "authorityContractGeneration", "buildCapabilityManifestDigest", "buildDigest",
    "configSchemaIdentity", "generatedSchemaDigest", "migrationManifestDigest", "packageSha256",
    "path", "runtimeIdentityDigest", "runtimeRevision", "schemaGeneration", "sha256",
  ], [], "next.manifest");
  absolutePath(manifest.path, "next.manifest.path");
  requireStrictDescendant(next.immutableRuntimeRoot as string, manifest.path as string, "next.manifest.path");
  for (const key of [
    "sha256", "buildDigest", "schemaGeneration", "authorityContractGeneration", "configSchemaIdentity",
    "migrationManifestDigest", "buildCapabilityManifestDigest", "generatedSchemaDigest", "packageSha256",
    "runtimeIdentityDigest",
  ] as const) {
    sha256(manifest[key], `next.manifest.${key}`);
  }
  requiredText(manifest.runtimeRevision, "next.manifest.runtimeRevision", 256);
}

function validateConnectorLifecycle(value: unknown, requestedAtMs: number): void {
  const lifecycle = record(value, "connectorLifecycle");
  exactKeys(lifecycle, [
    "bindingDigest", "candidateIdentity", "finalization", "journal", "managementAuthorizationKeyRef",
    "managementCorrelationId", "managementNonce", "oauthResource", "postActivation",
    "preCutoverHostCanary", "productionEnvironmentIdentityDigest", "productionRouteIdentityDigest",
    "releaseDriver", "stagingActivationPrecheck",
  ], [], "connectorLifecycle");
  sha256(lifecycle.bindingDigest, "connectorLifecycle.bindingDigest");
  artifactReference(lifecycle.stagingActivationPrecheck, "connectorLifecycle.stagingActivationPrecheck");
  artifactReference(lifecycle.preCutoverHostCanary, "connectorLifecycle.preCutoverHostCanary");
  validateReleaseDriver(lifecycle.releaseDriver);
  validateConnectorJournal(lifecycle.journal, requestedAtMs);
  validatePostActivation(lifecycle.postActivation, requestedAtMs);
  absolutePath(lifecycle.managementAuthorizationKeyRef, "connectorLifecycle.managementAuthorizationKeyRef");
  requiredText(lifecycle.managementNonce, "connectorLifecycle.managementNonce", 512);
  requiredText(lifecycle.managementCorrelationId, "connectorLifecycle.managementCorrelationId", 512);
  validateCandidateIdentity(lifecycle.candidateIdentity, "connectorLifecycle.candidateIdentity");
  resourceUrl(lifecycle.oauthResource, "connectorLifecycle.oauthResource");
  sha256(lifecycle.productionEnvironmentIdentityDigest, "connectorLifecycle.productionEnvironmentIdentityDigest");
  sha256(lifecycle.productionRouteIdentityDigest, "connectorLifecycle.productionRouteIdentityDigest");
  validateFinalization(lifecycle.finalization);
}

function validateReleaseDriver(value: unknown): void {
  const releaseDriver = record(value, "connectorLifecycle.releaseDriver");
  exactKeys(releaseDriver, [
    ...PRODUCTION_UPGRADE_RELEASE_DRIVER_PROVENANCE_KEYS,
    "productionApprovalOutputDirectory",
  ], [], "connectorLifecycle.releaseDriver");
  for (const key of PRODUCTION_UPGRADE_RELEASE_DRIVER_PROVENANCE_KEYS) {
    artifactReference(releaseDriver[key], `connectorLifecycle.releaseDriver.${key}`);
  }
  absolutePath(
    releaseDriver.productionApprovalOutputDirectory,
    "connectorLifecycle.releaseDriver.productionApprovalOutputDirectory",
  );
}

function validateConnectorJournal(value: unknown, requestedAtMs: number): void {
  const journal = record(value, "connectorLifecycle.journal");
  exactKeys(journal, ["identity", "path"], [], "connectorLifecycle.journal");
  absolutePath(journal.path, "connectorLifecycle.journal.path");
  const identity = record(journal.identity, "connectorLifecycle.journal.identity");
  exactKeys(identity, [
    "contentGeneration", "createdAtMs", "migrationManifestDigest", "receiptReplayPolicy",
    "schemaFingerprint", "schemaVersion", "snapshotPolicy", "storeId", "storePath",
  ], [], "connectorLifecycle.journal.identity");
  requiredPattern(identity.storeId, UUID_V4_PATTERN, "connectorLifecycle.journal.identity.storeId");
  absolutePath(identity.storePath, "connectorLifecycle.journal.identity.storePath");
  if (identity.storePath !== journal.path) fail("connectorLifecycle.journal.identity.storePath", "must equal journal.path");
  literal(identity.schemaVersion, 1, "connectorLifecycle.journal.identity.schemaVersion");
  sha256(identity.migrationManifestDigest, "connectorLifecycle.journal.identity.migrationManifestDigest");
  sha256(identity.contentGeneration, "connectorLifecycle.journal.identity.contentGeneration");
  literal(
    identity.snapshotPolicy,
    "PRESERVE_OUTSIDE_MUTABLE_ROLLBACK",
    "connectorLifecycle.journal.identity.snapshotPolicy",
  );
  literal(
    identity.receiptReplayPolicy,
    "PREPARED_RECEIPT_PERMANENTLY_ONE_SHOT",
    "connectorLifecycle.journal.identity.receiptReplayPolicy",
  );
  sha256(identity.schemaFingerprint, "connectorLifecycle.journal.identity.schemaFingerprint");
  integer(identity.createdAtMs, 0, requestedAtMs, "connectorLifecycle.journal.identity.createdAtMs");
}

function validatePostActivation(value: unknown, requestedAtMs: number): void {
  const post = record(value, "connectorLifecycle.postActivation");
  exactKeys(post, [
    "challengePath", "challengeSha256", "deadlineAt", "pollIntervalMs", "receiptPath",
    "routeIdentityUrl", "runtimeIdentityUrl",
  ], [], "connectorLifecycle.postActivation");
  absolutePath(post.challengePath, "connectorLifecycle.postActivation.challengePath");
  sha256(post.challengeSha256, "connectorLifecycle.postActivation.challengeSha256");
  absolutePath(post.receiptPath, "connectorLifecycle.postActivation.receiptPath");
  if (post.challengePath === post.receiptPath) {
    fail("connectorLifecycle.postActivation", "challenge and future receipt paths must be distinct");
  }
  boundedDeadline(post.deadlineAt, requestedAtMs, "connectorLifecycle.postActivation.deadlineAt");
  integer(post.pollIntervalMs, 10, 5_000, "connectorLifecycle.postActivation.pollIntervalMs");
  httpUrl(post.runtimeIdentityUrl, "connectorLifecycle.postActivation.runtimeIdentityUrl", true);
  httpUrl(post.routeIdentityUrl, "connectorLifecycle.postActivation.routeIdentityUrl", true);
  const runtime = new URL(post.runtimeIdentityUrl as string);
  const route = new URL(post.routeIdentityUrl as string);
  if (runtime.origin !== route.origin
    || runtime.pathname !== "/readyz"
    || route.pathname !== "/route-identityz") {
    fail(
      "connectorLifecycle.postActivation",
      "runtime and route identities require one loopback origin with exact /readyz and /route-identityz paths",
    );
  }
}

function validateFinalization(value: unknown): void {
  const finalization = record(value, "connectorLifecycle.finalization");
  exactKeys(finalization, [
    "controlPath", "gateProducer", "gateProducerTrustAnchor", "keyId", "preSnapshotIdentity", "storePath",
  ], [], "connectorLifecycle.finalization");
  absolutePath(finalization.storePath, "connectorLifecycle.finalization.storePath");
  if (basename(finalization.storePath as string) !== "lifecycle.sqlite") {
    fail("connectorLifecycle.finalization.storePath", "must use canonical basename lifecycle.sqlite");
  }
  absolutePath(finalization.controlPath, "connectorLifecycle.finalization.controlPath");
  requiredPattern(finalization.keyId, MANAGEMENT_KEY_PATTERN, "connectorLifecycle.finalization.keyId");
  const producer = record(finalization.gateProducer, "connectorLifecycle.finalization.gateProducer");
  exactKeys(producer, ["keyId", "publicKeySha256"], [], "connectorLifecycle.finalization.gateProducer");
  const match = typeof producer.keyId === "string" ? GATE_PRODUCER_PATTERN.exec(producer.keyId) : null;
  if (!match) fail("connectorLifecycle.finalization.gateProducer.keyId", "has invalid gate producer identity");
  sha256(producer.publicKeySha256, "connectorLifecycle.finalization.gateProducer.publicKeySha256");
  if (producer.publicKeySha256 !== `sha256:${match[1]}`) {
    fail("connectorLifecycle.finalization.gateProducer", "keyId and public key SHA-256 suffix differ");
  }
  artifactReference(
    finalization.gateProducerTrustAnchor,
    "connectorLifecycle.finalization.gateProducerTrustAnchor",
  );

  const identity = record(finalization.preSnapshotIdentity, "connectorLifecycle.finalization.preSnapshotIdentity");
  exactKeys(identity, [
    "contentGeneration", "controlEpoch", "controlTag", "identityDigest", "revision",
    "schemaVersion", "state", "storeId", "transactionId",
  ], [], "connectorLifecycle.finalization.preSnapshotIdentity");
  literal(identity.storeId, "lifecycle-finalization-store", "connectorLifecycle.finalization.preSnapshotIdentity.storeId");
  literal(identity.schemaVersion, 2, "connectorLifecycle.finalization.preSnapshotIdentity.schemaVersion");
  literal(identity.state, "DRAFT", "connectorLifecycle.finalization.preSnapshotIdentity.state");
  literal(identity.revision, 1, "connectorLifecycle.finalization.preSnapshotIdentity.revision");
  literal(identity.transactionId, null, "connectorLifecycle.finalization.preSnapshotIdentity.transactionId");
  sha256(identity.contentGeneration, "connectorLifecycle.finalization.preSnapshotIdentity.contentGeneration");
  integer(identity.controlEpoch, 1, Number.MAX_SAFE_INTEGER, "connectorLifecycle.finalization.preSnapshotIdentity.controlEpoch");
  requiredPattern(
    identity.controlTag,
    HMAC_SHA256_PATTERN,
    "connectorLifecycle.finalization.preSnapshotIdentity.controlTag",
  );
  sha256(identity.identityDigest, "connectorLifecycle.finalization.preSnapshotIdentity.identityDigest");
}

function validateSnapshotGroup(request: Record<string, unknown>, requestedAtMs: number): void {
  const snapshot = record(request.snapshotGroup, "snapshotGroup");
  exactKeys(snapshot, [
    "barrier", "entries", "manifestPath", "paginationPreviousSigningKey", "snapshotRoot",
  ], [], "snapshotGroup");
  absolutePath(snapshot.snapshotRoot, "snapshotGroup.snapshotRoot");
  absolutePath(snapshot.manifestPath, "snapshotGroup.manifestPath");
  const expectedManifest = join(snapshot.snapshotRoot as string, "SNAPSHOT-GROUP.json");
  if (snapshot.manifestPath !== expectedManifest) {
    fail("snapshotGroup.manifestPath", "must be SNAPSHOT-GROUP.json inside snapshotRoot");
  }
  const previousCursor = record(
    snapshot.paginationPreviousSigningKey,
    "snapshotGroup.paginationPreviousSigningKey",
  );
  if (previousCursor.state === "ABSENT" || previousCursor.state === "PRESENT") {
    exactKeys(previousCursor, ["path", "state"], [], "snapshotGroup.paginationPreviousSigningKey");
    absolutePath(previousCursor.path, "snapshotGroup.paginationPreviousSigningKey.path");
  } else {
    fail("snapshotGroup.paginationPreviousSigningKey.state", "must equal ABSENT or PRESENT");
  }
  const expectedEntries = [
    ...PRODUCTION_UPGRADE_REQUIRED_SNAPSHOT_ENTRIES,
    PRODUCTION_UPGRADE_PREVIOUS_CURSOR_SNAPSHOT_ENTRY,
  ];
  if (!Array.isArray(snapshot.entries) || snapshot.entries.length !== expectedEntries.length) {
    fail(
      "snapshotGroup.entries",
      `must contain exactly ${expectedEntries.length} snapshot entries for ${String(previousCursor.state)} previous-key state`,
    );
  }
  snapshot.entries.forEach((entry, index) => {
    const observed = record(entry, `snapshotGroup.entries[${index}]`);
    exactKeys(observed, ["id", "kind", "path", "required"], [], `snapshotGroup.entries[${index}]`);
    const expected = expectedEntries[index]!;
    if (observed.id !== expected.id || observed.kind !== expected.kind) {
      fail(`snapshotGroup.entries[${index}]`, `snapshot entry must be ${expected.id}/${expected.kind} in canonical order`);
    }
    absolutePath(observed.path, `snapshotGroup.entries[${index}].path`);
    const expectedRequired = expected.id === PRODUCTION_UPGRADE_PREVIOUS_CURSOR_SNAPSHOT_ENTRY.id
      ? previousCursor.state === "PRESENT"
      : true;
    literal(observed.required, expectedRequired, `snapshotGroup.entries[${index}].required`);
  });
  if ((snapshot.entries.at(-1) as ProductionUpgradeSnapshotEntry).path !== previousCursor.path) {
    fail(
      "snapshotGroup.paginationPreviousSigningKey.path",
      "must equal the final pagination-previous-signing-key snapshot path",
    );
  }

  const barrier = record(snapshot.barrier, "snapshotGroup.barrier");
  exactKeys(barrier, [
    "candidateIdentityDigest", "captureDeadlineAt", "cutoverProcessNames", "kind",
    "previousMigrationManifestDigest", "previousPid", "previousRuntimeIdentityDigest",
    "processName", "transactionId",
  ], [], "snapshotGroup.barrier");
  literal(barrier.kind, "PM2_STOPPED", "snapshotGroup.barrier.kind");
  requiredPattern(barrier.transactionId, TRANSACTION_PATTERN, "snapshotGroup.barrier.transactionId");
  requiredPattern(barrier.processName, PROCESS_NAME_PATTERN, "snapshotGroup.barrier.processName");
  integer(barrier.previousPid, 1, Number.MAX_SAFE_INTEGER, "snapshotGroup.barrier.previousPid");
  sha256(barrier.previousRuntimeIdentityDigest, "snapshotGroup.barrier.previousRuntimeIdentityDigest");
  sha256(barrier.previousMigrationManifestDigest, "snapshotGroup.barrier.previousMigrationManifestDigest");
  sha256(barrier.candidateIdentityDigest, "snapshotGroup.barrier.candidateIdentityDigest");
  validateCutoverProcessNames(
    barrier.cutoverProcessNames,
    barrier.processName as string,
    "snapshotGroup.barrier.cutoverProcessNames",
  );
  const captureDeadlineMs = isoTimestamp(barrier.captureDeadlineAt, "snapshotGroup.barrier.captureDeadlineAt");
  const timeoutMs = request.timeoutMs as number;
  if (captureDeadlineMs <= requestedAtMs || captureDeadlineMs > requestedAtMs + timeoutMs) {
    fail("snapshotGroup.barrier.captureDeadlineAt", "must be after requestedAt and within timeoutMs");
  }
}

function validateUrlsAndScopes(request: Record<string, unknown>): void {
  httpUrl(request.localHealthUrl, "localHealthUrl", true);
  httpUrl(request.localDoctorUrl, "localDoctorUrl", true);
  httpUrl(request.publicHealthUrl, "publicHealthUrl", false);
  httpUrl(request.publicMetricsUrl, "publicMetricsUrl", false);
  httpUrl(request.publicMcpUrl, "publicMcpUrl", false);
  httpUrl(request.oauthMetadataUrl, "oauthMetadataUrl", false);
  const localHealth = new URL(request.localHealthUrl as string);
  const localDoctor = new URL(request.localDoctorUrl as string);
  const previous = request.previous as ProductionUpgradeRequestV4["previous"];
  const post = (request.connectorLifecycle as ProductionUpgradeRequestV4["connectorLifecycle"]).postActivation;
  const previousHealth = new URL(previous.localHealthUrl);
  const previousReady = new URL(previous.localReadyUrl);
  const postReady = new URL(post.runtimeIdentityUrl);
  const publicUrls = [
    new URL(request.publicHealthUrl as string),
    new URL(request.publicMetricsUrl as string),
    new URL(request.publicMcpUrl as string),
    new URL(request.oauthMetadataUrl as string),
  ];
  if (localHealth.pathname !== "/healthz"
    || localDoctor.pathname !== "/doctorz"
    || previousHealth.pathname !== "/healthz"
    || previousReady.pathname !== "/readyz"
    || localHealth.origin !== previousHealth.origin
    || localDoctor.origin !== previousReady.origin
    || localDoctor.origin !== postReady.origin) {
    fail("request URLs", "local health/ready/doctor and management identities must use their exact paths and origin");
  }
  const [publicHealth, publicMetrics, publicMcp, oauthMetadata] = publicUrls;
  if (publicHealth!.pathname !== "/healthz"
    || publicMetrics!.pathname !== "/metrics"
    || publicMcp!.pathname !== "/mcp"
    || oauthMetadata!.pathname !== "/.well-known/oauth-protected-resource/mcp"
    || publicUrls.some((url) => url.origin !== publicHealth!.origin)
    || publicUrls.some((url) => url.protocol !== "https:")) {
    fail(
      "public URLs",
      "must share one HTTPS origin and exact health/metrics/MCP/OAuth paths",
    );
  }
  const lifecycle = request.connectorLifecycle as ProductionUpgradeRequestV4["connectorLifecycle"];
  if (lifecycle.oauthResource !== request.publicMcpUrl) {
    fail("connectorLifecycle.oauthResource", "must equal the exact publicMcpUrl resource identity");
  }
  if (!Array.isArray(request.expectedScopes)
    || canonicalizeJson(request.expectedScopes) !== canonicalizeJson(PRODUCTION_UPGRADE_EXPECTED_SCOPES)) {
    fail("expectedScopes", "must equal the exact production OAuth scope sequence");
  }
}

function validateCrossBindings(request: Record<string, unknown>): void {
  const previous = request.previous as ProductionUpgradeRequestV4["previous"];
  const next = request.next as ProductionUpgradeRequestV4["next"];
  const snapshot = request.snapshotGroup as ProductionUpgradeRequestV4["snapshotGroup"];
  const lifecycle = request.connectorLifecycle as ProductionUpgradeRequestV4["connectorLifecycle"];
  const entries = new Map(snapshot.entries.map((entry) => [entry.id, entry]));
  const expectedEntryPaths = new Map<string, string>([
    ["oauth-main-and-connector-state", request.oauthDatabasePath as string],
    ["authority-store", request.authorityDatabasePath as string],
    ["lifecycle-finalization-store", lifecycle.finalization.storePath],
    ["runtime-environment", request.productionEnvPath as string],
    ["process-manager-definition", request.startScriptPath as string],
  ]);
  for (const [id, expectedPath] of expectedEntryPaths) {
    if (entries.get(id)?.path !== expectedPath) {
      fail("snapshotGroup.entries", `${id} path does not match its exact request binding`);
    }
  }
  const candidate = lifecycle.candidateIdentity;
  const manifest = next.manifest;
  const identityBindings = [
    ["buildDigest", candidate.buildDigest, manifest.buildDigest],
    ["schemaGeneration", candidate.schemaGeneration, manifest.schemaGeneration],
    ["authorityContractGeneration", candidate.authorityContractGeneration, manifest.authorityContractGeneration],
    ["buildCapabilityManifestDigest", candidate.buildCapabilityManifestDigest, manifest.buildCapabilityManifestDigest],
    ["generatedSchemaDigest", candidate.generatedSchemaDigest, manifest.generatedSchemaDigest],
    ["packageSha256", candidate.packageSha256, manifest.packageSha256],
    ["runtimeIdentityDigest", candidate.runtimeIdentityDigest, manifest.runtimeIdentityDigest],
  ] as const;
  for (const [field, candidateValue, manifestValue] of identityBindings) {
    if (candidateValue !== manifestValue) {
      fail(`next.manifest.${field}`, "does not match connector candidate identity");
    }
  }
  if (snapshot.barrier.transactionId !== request.transactionId
    || snapshot.barrier.processName !== request.pm2ProcessName
    || snapshot.barrier.previousPid !== previous.pid
    || snapshot.barrier.previousRuntimeIdentityDigest !== previous.runtimeIdentityDigest
    || snapshot.barrier.previousMigrationManifestDigest !== previous.migrationManifestDigest
    || snapshot.barrier.candidateIdentityDigest !== productionUpgradeCandidateIdentityDigest(candidate)
    || canonicalizeJson(snapshot.barrier.cutoverProcessNames)
      !== canonicalizeJson(request.cutoverProcessNames)) {
    fail("snapshotGroup.barrier", "does not match the request runtime, process, or candidate identities");
  }
}

function validatePathTopology(request: Record<string, unknown>): void {
  const typed = request as unknown as ProductionUpgradeRequestV4;
  const entries = typed.snapshotGroup.entries;
  const mutablePaths = entries.flatMap((entry) => entry.kind === "sqlite"
    ? [entry.path, `${entry.path}-wal`, `${entry.path}-shm`]
    : [entry.path]);
  assertPairwiseNonOverlapping(mutablePaths, "snapshot mutable path or SQLite sidecar");
  for (const mutablePath of mutablePaths) {
    if (pathsOverlap(typed.snapshotGroup.snapshotRoot, mutablePath)) {
      fail("snapshotGroup.snapshotRoot", `overlaps mutable snapshot source or SQLite sidecar: ${mutablePath}`);
    }
  }
  requireStrictDescendant(typed.auditDirectory, typed.snapshotGroup.snapshotRoot, "snapshotGroup.snapshotRoot");
  for (const [label, auditArtifact] of [
    ["productionEnvBackupPath", typed.productionEnvBackupPath],
    ["oauthDatabaseBackupPath", typed.oauthDatabaseBackupPath],
    ["authorityDatabaseBackupPath", typed.authorityDatabaseBackupPath],
    ["nextEnvPath", typed.nextEnvPath],
    ["startScriptBackupPath", typed.startScriptBackupPath],
    ["statusPath", typed.statusPath],
    ["workerClaimPath", typed.workerClaimPath],
    ["workerLogPath", typed.workerLogPath],
  ] as const) {
    requireStrictDescendant(typed.auditDirectory, auditArtifact, label);
  }
  if (pathsOverlap(typed.currentAuditLink, typed.auditDirectory)) {
    fail("currentAuditLink", "must remain outside the transaction audit directory");
  }
  for (const mutablePath of mutablePaths) {
    if (pathsOverlap(typed.auditDirectory, mutablePath)) {
      fail("auditDirectory", `external audit/control root overlaps mutable state: ${mutablePath}`);
    }
  }

  const releaseArtifacts = PRODUCTION_UPGRADE_RELEASE_DRIVER_PROVENANCE_KEYS.map(
    (key) => typed.connectorLifecycle.releaseDriver[key].path,
  );
  assertPairwiseNonOverlapping(releaseArtifacts, "release-driver provenance");
  const rollback = typed.previous.rollbackHostChallenge;
  const controlPaths = [
    rollback.rollbackChallengeRequest.path,
    rollback.challengePath,
    rollback.receiptPath,
    typed.connectorLifecycle.stagingActivationPrecheck.path,
    typed.connectorLifecycle.preCutoverHostCanary.path,
    ...releaseArtifacts,
    typed.connectorLifecycle.releaseDriver.productionApprovalOutputDirectory,
    typed.connectorLifecycle.journal.path,
    typed.connectorLifecycle.postActivation.challengePath,
    typed.connectorLifecycle.postActivation.receiptPath,
    typed.connectorLifecycle.managementAuthorizationKeyRef,
    typed.connectorLifecycle.finalization.controlPath,
    typed.connectorLifecycle.finalization.gateProducerTrustAnchor.path,
    typed.rollbackJournalPath,
    typed.statusPath,
    typed.workerClaimPath,
    typed.workerLogPath,
    typed.productionEnvBackupPath,
    typed.oauthDatabaseBackupPath,
    typed.authorityDatabaseBackupPath,
    typed.nextEnvPath,
    typed.startScriptBackupPath,
    typed.currentAuditLink,
    ...(typed.previous.auditTarget ? [typed.previous.auditTarget] : []),
  ];
  assertPairwiseNonOverlapping(controlPaths, "external control/evidence/future-output path");
  for (const controlPath of controlPaths) {
    if (pathsOverlap(controlPath, typed.snapshotGroup.snapshotRoot)) {
      fail("request path topology", `external control path overlaps snapshot root: ${controlPath}`);
    }
    const mutable = mutablePaths.find((path) => pathsOverlap(controlPath, path));
    if (mutable) {
      fail("request path topology", `external control path overlaps mutable snapshot state: ${controlPath} / ${mutable}`);
    }
  }

  const immutableRoots = [
    typed.next.sourceEvidenceRoot,
    typed.next.immutableRuntimeRoot,
    typed.next.runtimeDependencies.root,
  ];
  assertPairwiseNonOverlapping(immutableRoots, "immutable release root");
  for (const immutableRoot of immutableRoots) {
    if (pathsOverlap(immutableRoot, typed.snapshotGroup.snapshotRoot)) {
      fail("request path topology", `immutable release root overlaps snapshot root: ${immutableRoot}`);
    }
    const mutable = mutablePaths.find((path) => pathsOverlap(immutableRoot, path));
    if (mutable) {
      fail("request path topology", `immutable release root overlaps mutable state: ${immutableRoot} / ${mutable}`);
    }
    if (pathsOverlap(immutableRoot, typed.connectorLifecycle.releaseDriver.productionApprovalOutputDirectory)) {
      fail("request path topology", `immutable release root overlaps production approval output: ${immutableRoot}`);
    }
    const control = controlPaths.find((path) => pathsOverlap(immutableRoot, path));
    if (control) {
      fail("request path topology", `immutable release root overlaps external control/evidence path: ${immutableRoot} / ${control}`);
    }
  }
  if (pathsOverlap(typed.connectorLifecycle.finalization.storePath, typed.connectorLifecycle.finalization.controlPath)) {
    fail("connectorLifecycle.finalization", "mutable storePath overlaps rollback-preserved controlPath");
  }
}

function computeLifecycleBindingDigest(request: ProductionUpgradeRequestV4): ProductionUpgradeSha256Digest {
  const lifecycle = request.connectorLifecycle;
  return sha256Digest(canonicalizeJson({
    schemaVersion: 2,
    transactionId: request.transactionId,
    requestedAt: request.requestedAt,
    immutableRelease: {
      commit: request.next.commit,
      sourceTree: request.next.sourceTree,
      sourceEvidenceRoot: request.next.sourceEvidenceRoot,
      immutableRuntimeRoot: request.next.immutableRuntimeRoot,
      immutableRuntimeEntrypoint: request.next.immutableRuntimeEntrypoint,
      runtimeDependencies: request.next.runtimeDependencies,
      dist: request.next.dist,
      manifest: request.next.manifest,
    },
    previousRuntime: {
      runtimeIdentityDigest: request.previous.runtimeIdentityDigest,
      migrationManifestDigest: request.previous.migrationManifestDigest,
      rollbackHostChallenge: request.previous.rollbackHostChallenge,
    },
    snapshot: {
      snapshotRoot: request.snapshotGroup.snapshotRoot,
      manifestPath: request.snapshotGroup.manifestPath,
      paginationPreviousSigningKey: request.snapshotGroup.paginationPreviousSigningKey,
      barrier: request.snapshotGroup.barrier,
      entries: request.snapshotGroup.entries,
    },
    stagingActivationPrecheck: lifecycle.stagingActivationPrecheck,
    preCutoverHostCanary: lifecycle.preCutoverHostCanary,
    releaseDriver: lifecycle.releaseDriver,
    journal: lifecycle.journal,
    postActivation: lifecycle.postActivation,
    managementAuthorizationKeyRef: lifecycle.managementAuthorizationKeyRef,
    managementNonce: lifecycle.managementNonce,
    managementCorrelationId: lifecycle.managementCorrelationId,
    candidateIdentity: lifecycle.candidateIdentity,
    oauthStateDirectory: request.oauthStateDirectory,
    oauthDatabasePath: request.oauthDatabasePath,
    oauthResource: lifecycle.oauthResource,
    productionEnvironmentIdentityDigest: lifecycle.productionEnvironmentIdentityDigest,
    productionRouteIdentityDigest: lifecycle.productionRouteIdentityDigest,
    finalization: lifecycle.finalization,
    rollbackJournalPath: request.rollbackJournalPath,
    statusPath: request.statusPath,
    workerClaimPath: request.workerClaimPath,
  }));
}

function validateCandidateIdentity(value: unknown, path: string): asserts value is ProductionUpgradeCandidateIdentity {
  const candidate = record(value, path);
  exactKeys(candidate, [
    "authorityContractGeneration", "buildCapabilityManifestDigest", "buildDigest",
    "generatedSchemaDigest", "packageSha256", "runtimeIdentityDigest", "schemaGeneration",
  ], [], path);
  for (const key of Object.keys(candidate)) sha256(candidate[key], `${path}.${key}`);
}

function validateCutoverProcessNames(value: unknown, requiredName: string, path: string): void {
  if (!Array.isArray(value) || value.length < 1 || value.length > 32) {
    fail(path, "must contain 1..32 process names");
  }
  for (let index = 0; index < value.length; index += 1) {
    requiredPattern(value[index], PROCESS_NAME_PATTERN, `${path}[${index}]`);
  }
  if (!value.includes(requiredName) || new Set(value).size !== value.length) {
    fail(path, "must contain the exact primary process once and no duplicates");
  }
  const sorted = [...value].sort(compareCodeUnits);
  if (canonicalizeJson(value) !== canonicalizeJson(sorted)) {
    fail(path, "must use canonical code-unit order");
  }
}

function artifactReference(value: unknown, path: string): asserts value is ProductionUpgradeArtifactReference {
  const artifact = record(value, path);
  exactKeys(artifact, ["path", "sha256"], [], path);
  absolutePath(artifact.path, `${path}.path`);
  sha256(artifact.sha256, `${path}.sha256`);
}

function absolutePath(value: unknown, path: string): asserts value is string {
  if (typeof value !== "string" || value.length < 2 || value.includes("\0") || !isAbsolute(value)) {
    fail(path, "must be an absolute path");
  }
  if (normalize(value) !== value || resolve(value) !== value || value.endsWith(sep)) {
    fail(path, "must be a lexical canonical absolute path");
  }
}

function requireStrictDescendant(parent: string, child: string, path: string): void {
  const displacement = relative(parent, child);
  if (!displacement || displacement === ".." || displacement.startsWith(`..${sep}`) || isAbsolute(displacement)) {
    fail(path, `must be a strict descendant of ${parent}`);
  }
}

function pathsOverlap(left: string, right: string): boolean {
  if (left === right) return true;
  const leftToRight = relative(left, right);
  if (leftToRight && leftToRight !== ".." && !leftToRight.startsWith(`..${sep}`) && !isAbsolute(leftToRight)) {
    return true;
  }
  const rightToLeft = relative(right, left);
  return Boolean(rightToLeft)
    && rightToLeft !== ".."
    && !rightToLeft.startsWith(`..${sep}`)
    && !isAbsolute(rightToLeft);
}

function assertPairwiseNonOverlapping(paths: readonly string[], label: string): void {
  for (let left = 0; left < paths.length; left += 1) {
    for (let right = left + 1; right < paths.length; right += 1) {
      if (pathsOverlap(paths[left]!, paths[right]!)) {
        fail(label, `paths must be distinct and non-overlapping: ${paths[left]} / ${paths[right]}`);
      }
    }
  }
}

function boundedDeadline(value: unknown, notBeforeMs: number, path: string): number {
  const deadlineMs = isoTimestamp(value, path);
  if (deadlineMs <= notBeforeMs || deadlineMs > notBeforeMs + MAX_EVIDENCE_LIFETIME_MS) {
    fail(path, "deadline must be fresh, ordered, and bounded to 30 minutes");
  }
  return deadlineMs;
}

function isoTimestamp(value: unknown, path: string): number {
  if (typeof value !== "string") fail(path, "must be an ISO timestamp string");
  const milliseconds = Date.parse(value);
  if (!Number.isFinite(milliseconds) || new Date(milliseconds).toISOString() !== value) {
    fail(path, "must be a canonical ISO timestamp");
  }
  return milliseconds;
}

function httpUrl(value: unknown, path: string, loopback: boolean): asserts value is string {
  if (typeof value !== "string") fail(path, "must be an HTTP(S) URL string");
  let parsed: URL;
  try {
    parsed = new URL(value);
  } catch {
    fail(path, "must be a valid HTTP(S) URL");
  }
  if (!(["http:", "https:"] as string[]).includes(parsed.protocol)
    || parsed.username || parsed.password || parsed.search || parsed.hash
    || parsed.href !== value) {
    fail(path, "must be a canonical HTTP(S) URL without credentials, query, or fragment");
  }
  if (loopback && (parsed.protocol !== "http:"
    || !["127.0.0.1", "[::1]", "::1"].includes(parsed.hostname))) {
    fail(path, "must use an HTTP loopback management origin");
  }
}

function resourceUrl(value: unknown, path: string): asserts value is string {
  httpUrl(value, path, false);
  if (new URL(value).protocol !== "https:") fail(path, "must use HTTPS");
}

function sha256(value: unknown, path: string): asserts value is ProductionUpgradeSha256Digest {
  requiredPattern(value, SHA256_PATTERN, path);
}

function integer(value: unknown, minimum: number, maximum: number, path: string): asserts value is number {
  if (!Number.isSafeInteger(value) || (value as number) < minimum || (value as number) > maximum) {
    fail(path, `must be a safe integer from ${minimum} through ${maximum}`);
  }
}

function requiredText(value: unknown, path: string, maximum: number): asserts value is string {
  if (typeof value !== "string" || value.length < 1 || value.length > maximum || value.includes("\0")) {
    fail(path, `must be non-empty text no longer than ${maximum} characters`);
  }
}

function requiredPattern(value: unknown, pattern: RegExp, path: string): asserts value is string {
  if (typeof value !== "string" || !pattern.test(value)) fail(path, "has invalid format");
}

function literal<T>(value: unknown, expected: T, path: string): asserts value is T {
  if (value !== expected) fail(path, `must equal ${String(expected)}`);
}

function record(value: unknown, path: string): Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value)) fail(path, "must be an exact object");
  return value as Record<string, unknown>;
}

function exactKeys(
  value: Record<string, unknown>,
  required: readonly string[],
  optional: readonly string[],
  path: string,
): void {
  const allowed = new Set([...required, ...optional]);
  const keys = Object.keys(value);
  for (const key of required) {
    if (!Object.prototype.hasOwnProperty.call(value, key)) fail(path, `is missing key ${key}`);
  }
  for (const key of keys) {
    if (!allowed.has(key)) fail(path, `has unexpected key ${key}`);
  }
}

function cloneExactJson(value: unknown, path: string): unknown {
  if (value === null || typeof value === "string" || typeof value === "boolean") return value;
  if (typeof value === "number") {
    if (!Number.isFinite(value) || Object.is(value, -0)) fail(path, "contains an invalid JSON number");
    return value;
  }
  if (Array.isArray(value)) {
    if (Object.getPrototypeOf(value) !== Array.prototype || Object.getOwnPropertySymbols(value).length > 0) {
      fail(path, "must use a plain JSON array without symbol keys");
    }
    const keys = Object.keys(value);
    const ownNames = Object.getOwnPropertyNames(value);
    if (keys.length !== value.length
      || keys.some((key, index) => key !== String(index))
      || ownNames.length !== value.length + 1
      || ownNames.at(-1) !== "length") {
      fail(path, "must be a dense exact JSON array");
    }
    return keys.map((key, index) => cloneExactJsonDataProperty(value, key, `${path}[${index}]`));
  }
  if (!value || typeof value !== "object") fail(path, `contains unsupported ${typeof value}`);
  const prototype = Object.getPrototypeOf(value);
  if (prototype !== Object.prototype) fail(path, "must use a plain JSON object prototype");
  if (Object.getOwnPropertySymbols(value).length > 0) fail(path, "contains symbol keys");
  const output: Record<string, unknown> = {};
  const keys = Object.keys(value);
  if (Object.getOwnPropertyNames(value).length !== keys.length) {
    fail(path, "contains non-enumerable data outside exact JSON");
  }
  for (const key of keys) {
    Object.defineProperty(output, key, {
      configurable: true,
      enumerable: true,
      writable: true,
      value: cloneExactJsonDataProperty(value, key, `${path}.${key}`),
    });
  }
  return output;
}

function cloneExactJsonDataProperty(
  owner: object,
  key: string,
  path: string,
): unknown {
  const descriptor = Object.getOwnPropertyDescriptor(owner, key);
  if (!descriptor || !("value" in descriptor) || !descriptor.enumerable) {
    fail(path, "must be an enumerable data property");
  }
  if (descriptor.value === undefined) fail(path, "contains undefined");
  return cloneExactJson(descriptor.value, path);
}

function canonicalizeJson(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(canonicalizeJson).join(",")}]`;
  if (value && typeof value === "object") {
    return `{${Object.entries(value as Record<string, unknown>)
      .sort(([left], [right]) => compareCodeUnits(left, right))
      .map(([key, item]) => `${JSON.stringify(key)}:${canonicalizeJson(item)}`)
      .join(",")}}`;
  }
  return JSON.stringify(value);
}

function compareCodeUnits(left: string, right: string): number {
  return left < right ? -1 : left > right ? 1 : 0;
}

function sha256Digest(value: string): ProductionUpgradeSha256Digest {
  return `sha256:${createHash("sha256").update(value).digest("hex")}`;
}

function deepFreeze<T>(value: T): T {
  if (value && typeof value === "object" && !Object.isFrozen(value)) {
    for (const item of Object.values(value as Record<string, unknown>)) deepFreeze(item);
    Object.freeze(value);
  }
  return value;
}

function fail(path: string, message: string): never {
  throw new ProductionUpgradeContractError(`Invalid production upgrade request ${path}: ${message}.`);
}
