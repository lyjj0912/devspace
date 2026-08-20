import { createHash } from "node:crypto";
import {
  closeSync,
  constants,
  fstatSync,
  lstatSync,
  openSync,
  readFileSync,
  realpathSync,
} from "node:fs";
import { dirname, isAbsolute, relative, resolve, sep } from "node:path";
import {
  assertVerifiedConnectorActivationOwnerApproval,
  assertVerifiedConnectorActivationPostActivationHostCanary,
  assertVerifiedConnectorActivationPreCutoverHostCanary,
  assertVerifiedConnectorActivationProductionPrecheck,
  assertVerifiedConnectorActivationStagingPrecheck,
  verifyConnectorActivationOwnerApproval,
  verifyConnectorActivationPreCutoverHostCanary,
  verifyConnectorActivationProductionPrecheck,
  verifyConnectorActivationStagingPrecheck,
} from "../../dist/v2/connector-activation-evidence.js";
import {
  assertVerifiedGateProducerTrustAnchor,
  inspectVerifiedReleaseGateLedger,
} from "./release-artifacts.mjs";

export const BASE_PROFILE_GATE_EVIDENCE_SCHEMA_VERSION = 3;
export const BASE_PROFILE_GATE_NAMES = Object.freeze([
  "G00 PROFILE", "G01 SOURCE", "G02 STATIC", "G03 UNIT", "G04 PROTOCOL",
  "G05 FUNCTIONAL", "G06 SECURITY", "G07 DURABILITY", "G08 LOAD",
  "G09 PACKAGE", "G10 STAGING", "G11 HOST", "G12 CONNECTOR",
]);
export const POST_CUTOVER_GATE_NAME = "G13 CUTOVER";
export const DEFERRED_FINALIZATION_GATE_NAMES = Object.freeze(["G16 CLEANUP", "G17 FINALIZATION"]);
export const BASE_PROFILE_PRECUTOVER_CAPABILITIES = Object.freeze([
  "source-runtime-build-profile-identity", "one-production-process-route", "health-ready-doctor",
  "unauthenticated-mcp-401", "public-management-blocked", "exact-eight-tools",
  "canonical-active-one", "fresh-host-discovery", "cross-session-harmless-mutation",
  "local-target-read-write-exec-process-mcp-artifact", "self-restart-transaction",
  "all-store-consistent-snapshot",
]);
export const CONDITIONAL_PROFILE_NAMES = Object.freeze([
  "MULTI_USER", "SIDECAR_AUTHORITY", "HOST_ATTESTED", "GUI_CAPTURE",
]);

const LIVE_LEDGER_KIND = "DEVSPACE_BASE_PROFILE_PREACTIVATION_LIVE_LEDGER";
const DIGEST_PATTERN = /^sha256:[a-f0-9]{64}$/u;
const TOOL_NAMES = Object.freeze(["target", "context", "fs", "exec", "process", "mcp", "artifact", "gui"]);
const LIVE_GATES = Object.freeze(["G10 STAGING", "G11 HOST", "G12 CONNECTOR"]);
const GATE_FORMATS = Object.freeze({
  "G10 STAGING": "STAGING_READBACK_REPORT_V2",
  "G11 HOST": "HOST_PRE_CUTOVER_REPORT_V2",
  "G12 CONNECTOR": "CONNECTOR_PRECHECK_REPORT_V2",
});
const COMMON_BINDING_KEYS = Object.freeze([
  "authorityContractGeneration", "buildCapabilityManifestDigest", "buildDigest",
  "candidateIdentityDigest", "executableManifestDigest", "generatedSchemaDigest",
  "migrationManifestDigest", "packageSha256", "releaseManifestSha256",
  "requestBindingDigest", "runtimeIdentityDigest", "schemaGeneration", "transactionId",
]);
const CAPABILITY_DEPENDENCIES = Object.freeze({
  "source-runtime-build-profile-identity": ["G00 PROFILE", "G01 SOURCE", "G09 PACKAGE"],
  "one-production-process-route": ["G10 STAGING"],
  "health-ready-doctor": ["G10 STAGING"],
  "unauthenticated-mcp-401": ["G06 SECURITY"],
  "public-management-blocked": ["G06 SECURITY"],
  "exact-eight-tools": ["G04 PROTOCOL", "G05 FUNCTIONAL", "G11 HOST"],
  "canonical-active-one": ["G10 STAGING", "G12 CONNECTOR"],
  "fresh-host-discovery": ["G11 HOST"],
  "cross-session-harmless-mutation": ["G05 FUNCTIONAL", "G11 HOST"],
  "local-target-read-write-exec-process-mcp-artifact": ["G05 FUNCTIONAL"],
  "self-restart-transaction": ["G07 DURABILITY"],
  "all-store-consistent-snapshot": ["G07 DURABILITY"],
});
const PRE_CUTOVER_RECEIPTS = Object.freeze({
  "G00 PROFILE": ["profile-runtime-identities"],
  "G01 SOURCE": [
    "source-head-before", "source-clean-before", "source-upstream-before",
    "source-head-after", "source-clean-after", "source-upstream-after",
  ],
  "G02 STATIC": ["static-source-hygiene", "static-typecheck", "static-contract-generation-tests"],
  "G03 UNIT": ["unit-tests"],
  "G04 PROTOCOL": ["protocol-tests"],
  "G05 FUNCTIONAL": ["functional-tests"],
  "G06 SECURITY": ["security-tests"],
  "G07 DURABILITY": ["durability-tests"],
  "G08 LOAD": ["nfr-predicate-tests", "release-nfr"],
});
const THRESHOLD_DESCRIPTOR = Object.freeze({
  schemaVersion: BASE_PROFILE_GATE_EVIDENCE_SCHEMA_VERSION,
  profile: "BASE_SINGLE_OWNER",
  producer: "Ed25519 independently pinned one-way release/live evidence",
  preCutoverReceipts: PRE_CUTOVER_RECEIPTS,
  liveFormats: GATE_FORMATS,
  capabilityDependencies: CAPABILITY_DEPENDENCIES,
  temporal: Object.freeze({
    evaluated: "G00-G12",
    notRun: Object.freeze(["G13 CUTOVER", "G16 CLEANUP", "G17 FINALIZATION", "no-residue"]),
  }),
});
export const BASE_PROFILE_GATE_THRESHOLD_DIGEST = domainDigest(
  "devspace.base-profile-gate-thresholds.v3",
  THRESHOLD_DESCRIPTOR,
);

export function inspectBaseProfileGateEvidenceManifest(options) {
  const configuration = requiredObject(options, "base profile gate evidence inspection options");
  const releaseRoot = canonicalRealDirectory(configuration.releaseRoot, "gate evidence immutable release root");
  const trustedProducer = assertVerifiedGateProducerTrustAnchor(configuration.gateProducerTrustAnchor);
  const releaseInspection = inspectVerifiedReleaseGateLedger(releaseRoot, {
    gateProducerTrustAnchor: configuration.gateProducerTrustAnchor,
    expectedSourceRevision: configuration.expectedSourceRevision,
    expectedRuntimeRevision: configuration.expectedRuntimeRevision,
  });
  if (canonicalJson(releaseInspection.gateProducer) !== canonicalJson(trustedProducer)) {
    throw new Error("Immutable release producer differs from the verified external trust anchor.");
  }
  const expectedBindings = normalizeBindings(configuration.expectedBindings);
  assertPrecutoverLedgerBindings(releaseInspection, expectedBindings);

  const manifestPath = canonicalOwnerOnlyFile(configuration.manifestPath, "pre-activation live evidence ledger");
  const manifestBytes = stableReadFile(manifestPath, "pre-activation live evidence ledger");
  const manifestSha256 = digestBytes(manifestBytes);
  if (manifestSha256 !== requireDigest(configuration.manifestSha256, "live evidence ledger sha256")) {
    throw new Error("Pre-activation live evidence ledger bytes differ from their immutable binding.");
  }
  const envelope = releaseInspection.verifyGateProducerEnvelope(manifestBytes, LIVE_LEDGER_KIND);
  const manifest = canonicalClone(requiredObject(envelope.payload, "pre-activation live evidence payload"));
  validateLiveManifest(manifest, expectedBindings);
  const evidenceRoot = canonicalOwnerOnlyDirectory(manifest.evidenceRoot, "pre-activation live evidence root");
  if (!isSameOrInside(evidenceRoot, manifestPath)) throw new Error("Pre-activation live ledger escapes its evidence root.");
  const artifacts = [];
  for (let index = 0; index < LIVE_GATES.length; index += 1) {
    const expectedGate = LIVE_GATES[index];
    const reference = manifest.artifacts[index];
    const path = canonicalOwnerOnlyFile(reference.path, `live evidence ${expectedGate}`);
    if (!isSameOrInside(evidenceRoot, path)) throw new Error(`Live gate evidence escapes evidence root: ${expectedGate}`);
    const bytes = stableReadFile(path, `live evidence ${expectedGate}`);
    if (digestBytes(bytes) !== reference.sha256) throw new Error(`Live gate evidence bytes changed: ${expectedGate}`);
    const report = parseCanonicalJson(bytes, `live evidence ${expectedGate}`);
    if (report.observedAt !== reference.observedAt) throw new Error(`Live gate observedAt differs from signed reference: ${expectedGate}`);
    if (Date.parse(report.observedAt) > Date.parse(manifest.createdAt)) throw new Error(`Live gate evidence postdates its signed ledger: ${expectedGate}`);
    artifacts.push(Object.freeze({ gate: expectedGate, reference, path, bytes, report }));
  }
  const postCutoverPath = canonicalProspectivePath(manifest.postCutover.path, evidenceRoot, "post-cutover evidence path");
  const postCutoverReportPath = canonicalProspectivePath(manifest.postCutover.reportPath, evidenceRoot, "post-cutover report path");
  if (configuration.requirePostCutoverAbsent !== false
    && (lstatIfPresent(postCutoverPath) || lstatIfPresent(postCutoverReportPath))) {
    throw new Error("Post-cutover evidence must be absent before activation, including dangling symlinks.");
  }
  return Object.freeze({
    manifestPath,
    manifestSha256,
    envelope,
    manifest,
    evidenceRoot,
    artifacts: Object.freeze(artifacts),
    releaseInspection,
    expectedBindings,
    postCutoverPath,
    postCutoverReportPath,
    bindingDigest: domainDigest("devspace.base-profile-live-ledger-binding.v3", {
      releaseManifestSha256: releaseInspection.release.manifestSha256,
      producerLedgerSha256: releaseInspection.manifest.gateProducer.preCutoverLedgerSha256,
      liveLedgerSha256: manifestSha256,
      livePayloadDigest: envelope.payloadDigest,
      thresholdDigest: BASE_PROFILE_GATE_THRESHOLD_DIGEST,
    }),
  });
}

export function evaluateBaseProfilePreCutoverEvidence(options) {
  const inspected = inspectBaseProfileGateEvidenceManifest(options);
  const configuration = requiredObject(options, "base profile pre-cutover evaluation options");
  const releaseResults = evaluateReleaseProducerEvidence(inspected.releaseInspection, inspected.expectedBindings);
  const liveByGate = new Map(inspected.artifacts.map((artifact) => [artifact.gate, artifact]));
  const hostReport = liveByGate.get("G11 HOST")?.report;
  const liveResults = [
    evaluateLiveGate("G10 STAGING", liveByGate.get("G10 STAGING"), () => evaluateStagingReport(
      liveByGate.get("G10 STAGING").report,
      requiredObject(configuration.liveExpectations, "live gate expectations"),
    )),
    evaluateLiveGate("G11 HOST", liveByGate.get("G11 HOST"), () => evaluateHostReport(
      hostReport,
      inspected.expectedBindings,
      configuration.managementKey,
      configuration.now,
    )),
    evaluateLiveGate("G12 CONNECTOR", liveByGate.get("G12 CONNECTOR"), () => evaluateConnectorReport(
      liveByGate.get("G12 CONNECTOR").report,
      inspected.expectedBindings,
      configuration.managementKey,
      hostReport,
      configuration.now,
    )),
  ];
  const gateResults = [
    ...releaseResults,
    ...liveResults,
    notRunGate(POST_CUTOVER_GATE_NAME),
    ...DEFERRED_FINALIZATION_GATE_NAMES.map(notRunGate),
  ];
  assertGateOrder(gateResults);
  const gateByName = new Map(gateResults.map((entry) => [entry.gate, entry]));
  const capabilities = BASE_PROFILE_PRECUTOVER_CAPABILITIES.map((capability) => {
    const evidence = CAPABILITY_DEPENDENCIES[capability].map((gate) => gateByName.get(gate));
    if (evidence.some((entry) => entry?.result !== "PASS")) throw new Error(`Capability lacks reconstructed gate evidence: ${capability}`);
    return Object.freeze({
      profile: "BASE_SINGLE_OWNER",
      capability,
      applicability: "REQUIRED",
      result: "PASS",
      evidenceDigest: domainDigest("devspace.base-profile-capability-result.v3", {
        capability,
        gates: evidence.map(({ gate, evidenceDigest }) => ({ gate, evidenceDigest })),
        thresholdDigest: BASE_PROFILE_GATE_THRESHOLD_DIGEST,
      }),
    });
  });
  capabilities.push(Object.freeze({
    profile: "BASE_SINGLE_OWNER", capability: "no-residue", applicability: "REQUIRED", result: "NOT_RUN",
  }));
  for (const profile of CONDITIONAL_PROFILE_NAMES) {
    capabilities.push(Object.freeze({
      profile, capability: `${profile.toLowerCase()}-profile`, applicability: "NOT_APPLICABLE", result: "NOT_APPLICABLE",
    }));
  }
  const profileApplicability = Object.freeze([
    Object.freeze({ profile: "BASE_SINGLE_OWNER", applicability: "REQUIRED" }),
    ...CONDITIONAL_PROFILE_NAMES.map((profile) => Object.freeze({ profile, applicability: "NOT_APPLICABLE" })),
  ]);
  return Object.freeze({
    thresholdDigest: BASE_PROFILE_GATE_THRESHOLD_DIGEST,
    manifestBindingDigest: inspected.bindingDigest,
    gateResults: Object.freeze(gateResults),
    gateResultsDigest: digestJson(gateResults),
    capabilities: Object.freeze(capabilities),
    capabilitiesDigest: digestJson(capabilities),
    profileApplicability,
    profileApplicabilityDigest: digestJson(profileApplicability),
  });
}

export function evaluateBaseProfilePostCutoverEvidence(options) {
  const configuration = requiredObject(options, "post-cutover evidence evaluation options");
  const inspected = inspectBaseProfileGateEvidenceManifest({ ...configuration, requirePostCutoverAbsent: false });
  const reportPath = canonicalOwnerOnlyFile(configuration.reportPath, "canonical post-cutover report");
  if (reportPath !== inspected.postCutoverReportPath) throw new Error("Canonical post-cutover report path differs from signed prebinding.");
  const bytes = stableReadFile(reportPath, "canonical post-cutover report");
  if (digestBytes(bytes) !== requireDigest(configuration.reportSha256, "post-cutover report sha256")) {
    throw new Error("Canonical post-cutover report digest differs from its caller binding.");
  }
  const report = parseCanonicalJson(bytes, "canonical post-cutover report");
  const verifiedPost = configuration.verifiedPostActivationHostCanary;
  assertVerifiedConnectorActivationPostActivationHostCanary(verifiedPost);
  const derived = validateCutoverReport(report, configuration.liveExpectations, inspected.manifest.postCutover, verifiedPost);
  const activatedAt = requiredTimestamp(configuration.activatedAt, "post-cutover activatedAt");
  if (Date.parse(report.observedAt) <= Date.parse(activatedAt)) {
    throw new Error("G13 observedAt must be strictly later than the authenticated activation timestamp.");
  }
  const result = Object.freeze({
    profile: "BASE_SINGLE_OWNER",
    gate: POST_CUTOVER_GATE_NAME,
    applicability: "REQUIRED",
    result: "PASS",
    evidenceDigest: domainDigest("devspace.base-profile-gate-result.v3", {
      gate: POST_CUTOVER_GATE_NAME,
      reportSha256: digestBytes(bytes),
      liveLedgerPayloadDigest: inspected.envelope.payloadDigest,
      derived,
      thresholdDigest: BASE_PROFILE_GATE_THRESHOLD_DIGEST,
    }),
  });
  return Object.freeze({ result, report, reportSha256: digestBytes(bytes), derived });
}

function evaluateReleaseProducerEvidence(inspection, expectedBindings) {
  const payload = inspection.ledger.payload;
  const receiptById = new Map(payload.receipts.map((receipt) => [receipt.id, receipt]));
  const rawText = (receipt, stream = "stdout") => {
    const reference = receipt[stream];
    const bytes = inspection.readPayload(`evidence/base-profile-gates/${reference.path}`);
    if (bytes.length !== reference.bytes || digestBytes(bytes) !== reference.sha256) {
      throw new Error(`Producer ${receipt.id} ${stream} bytes differ from the signed ledger.`);
    }
    return bytes.toString("utf8");
  };
  const results = [];
  for (const gate of Object.keys(PRE_CUTOVER_RECEIPTS)) {
    const receipts = PRE_CUTOVER_RECEIPTS[gate].map((id) => {
      const receipt = receiptById.get(id);
      if (!receipt || receipt.gate !== gate || receipt.exitCode !== 0 || receipt.signal !== null) {
        throw new Error(`Producer ledger lacks exact successful receipt ${gate}/${id}.`);
      }
      return receipt;
    });
    let derived;
    if (gate === "G00 PROFILE") {
      const report = parseJsonText(rawText(receipts[0]), "producer profile identity report");
      if (report.sourceRevision !== expectedBindings.sourceRevision
        || report.buildDigest !== expectedBindings.buildDigest
        || report.schemaGeneration !== expectedBindings.schemaGeneration
        || report.authorityContractGeneration !== expectedBindings.authorityContractGeneration
        || report.buildCapabilityManifestDigest !== expectedBindings.buildCapabilityManifestDigest
        || report.generatedSchemaDigest !== expectedBindings.generatedSchemaDigest
        || report.migrationManifestDigest !== expectedBindings.migrationManifestDigest
        || report.buildCapabilities?.productProfile !== "BASE_SINGLE_OWNER"
        || canonicalJson(report.buildCapabilities?.supportedProfiles) !== canonicalJson(["BASE_SINGLE_OWNER"])) {
        throw new Error("Producer G00 runtime/package identity report differs from finalization bindings.");
      }
      derived = { reportDigest: digestJson(report) };
    } else if (gate === "G01 SOURCE") {
      const outputs = Object.fromEntries(receipts.map((receipt) => [receipt.id, rawText(receipt)]));
      if (outputs["source-head-before"].trim() !== expectedBindings.sourceRevision
        || outputs["source-head-after"].trim() !== expectedBindings.sourceRevision
        || outputs["source-clean-before"] !== "" || outputs["source-clean-after"] !== ""
        || !/^0\s+0\s*$/u.test(outputs["source-upstream-before"])
        || !/^0\s+0\s*$/u.test(outputs["source-upstream-after"])) {
        throw new Error("Producer G01 raw Git readbacks do not prove exact clean synchronized source.");
      }
      derived = { sourceTreeDigest: payload.sourceTree.sha256, sourceRevision: expectedBindings.sourceRevision };
    } else if (gate === "G02 STATIC") {
      if (!/^SOURCE_HYGIENE_PASS files=[1-9][0-9]*\n$/u.test(rawText(receipts[0]))
        || receipts.some((receipt) => rawText(receipt, "stderr") !== "")) {
        throw new Error("Producer G02 exact hygiene/typecheck/contracts commands did not pass cleanly.");
      }
      validateTap(rawText(receipts[2]), "G02 STATIC");
      derived = { receiptDigests: receipts.map((receipt) => receipt.receiptDigest) };
    } else if (["G03 UNIT", "G04 PROTOCOL", "G05 FUNCTIONAL", "G06 SECURITY", "G07 DURABILITY"].includes(gate)) {
      const summary = validateTap(rawText(receipts[0]), gate);
      derived = { ...summary, inventory: payload.testInventory[gate] };
    } else if (gate === "G08 LOAD") {
      validateTap(rawText(receipts[0]), "G08 LOAD predicate tests");
      const report = parseJsonText(rawText(receipts[1]), "release NFR report");
      const evaluation = executePackagedNfrEvaluator(inspection, report.results);
      if (canonicalJson(evaluation) !== canonicalJson(report.evaluation)
        || evaluation.status !== "BASE_PROFILE_NFR_PASS" || evaluation.exitCode !== 0 || evaluation.releaseEligible !== true) {
        throw new Error("Producer G08 raw NFR results fail the immutable packaged release predicate.");
      }
      derived = { evaluationDigest: digestJson(evaluation), resultsDigest: digestJson(report.results) };
    }
    results.push(passGate(gate, {
      producerLedgerPayloadDigest: inspection.ledger.payloadDigest,
      receiptDigests: receipts.map((receipt) => receipt.receiptDigest),
      derived,
    }));
  }
  if (inspection.release.status !== "PASS") throw new Error("G09 immutable release package is not attested/eligible.");
  results.push(passGate("G09 PACKAGE", {
    manifestSha256: inspection.release.manifestSha256,
    buildDigest: inspection.release.buildDigest,
    producerLedgerSha256: inspection.manifest.gateProducer.preCutoverLedgerSha256,
  }));
  return results;
}

function assertPrecutoverLedgerBindings(inspection, expected) {
  const observed = inspection.ledger.payload.bindings;
  for (const [key, expectedValue] of [
    ["sourceRevision", expected.sourceRevision],
    ["buildDigest", expected.buildDigest],
    ["schemaGeneration", expected.schemaGeneration],
    ["authorityContractGeneration", expected.authorityContractGeneration],
    ["buildCapabilityManifestDigest", expected.buildCapabilityManifestDigest],
    ["generatedSchemaDigest", expected.generatedSchemaDigest],
    ["migrationManifestDigest", expected.migrationManifestDigest],
  ]) {
    if (observed[key] !== expectedValue) throw new Error(`Producer pre-cutover ledger binding differs: ${key}`);
  }
  if (inspection.release.manifestSha256 !== expected.releaseManifestSha256) {
    throw new Error("Verified release manifest digest differs from finalization bindings.");
  }
}

function evaluateLiveGate(gate, artifact, evaluator) {
  if (!artifact || artifact.gate !== gate) throw new Error(`Missing signed live evidence: ${gate}`);
  const derived = evaluator();
  return passGate(gate, {
    reportSha256: artifact.reference.sha256,
    observedAt: artifact.reference.observedAt,
    derived,
  });
}

function evaluateStagingReport(report, expected) {
  assertExactKeys(report, [
    "doctor", "environmentIdentityDigest", "health", "kind", "listeners", "observedAt",
    "processes", "ready", "routeIdentityDigest", "routes", "runtimeIdentity", "schemaVersion", "stores",
  ], "G10 staging report");
  if (report.schemaVersion !== 2 || report.kind !== "STAGING_READBACK_REPORT"
    || report.health?.status !== "ok" || report.ready?.status !== "ready" || report.doctor?.status !== "PASS"
    || digestJson(report.runtimeIdentity) !== expected.runtimeIdentityDigest
    || report.environmentIdentityDigest !== expected.productionEnvironmentIdentityDigest
    || report.routeIdentityDigest !== expected.productionRouteIdentityDigest) {
    throw new Error("G10 staging health/ready/doctor/runtime/environment/route identity differs.");
  }
  if (!Array.isArray(report.processes) || report.processes.length !== 1) throw new Error("G10 must observe exactly one scoped PM2 process.");
  const process = report.processes[0];
  assertExactKeys(process, ["cwd", "envDigest", "name", "pid", "script", "scriptSha256", "status"], "G10 PM2 process");
  if (process.name !== expected.processName || process.status !== "online" || !Number.isSafeInteger(process.pid) || process.pid < 1
    || process.cwd !== expected.cwd || process.script !== expected.script || process.scriptSha256 !== expected.scriptSha256
    || process.envDigest !== expected.environmentDigest) {
    throw new Error("G10 PM2 tuple/script/hash/environment containment differs.");
  }
  if (!Array.isArray(report.listeners) || report.listeners.length === 0
    || report.listeners.some((listener) => listener.pid !== process.pid)
    || canonicalJson([...new Set(report.listeners.map((listener) => listener.port))].sort((a, b) => a - b))
      !== canonicalJson([...expected.scopePorts].sort((a, b) => a - b))) {
    throw new Error("G10 scoped listeners do not all belong to the one accepted PM2 PID/port set.");
  }
  if (!Array.isArray(report.routes) || report.routes.length !== 1
    || report.routes[0]?.identityDigest !== expected.productionRouteIdentityDigest) {
    throw new Error("G10 must observe exactly one expected production route.");
  }
  if (!Array.isArray(report.stores) || report.stores.length === 0
    || report.stores.some((store) => store.integrity !== "ok" || store.foreignKeyViolations !== 0)) {
    throw new Error("G10 store integrity/readiness matrix is incomplete.");
  }
  return Object.freeze({ processPid: process.pid, listenerDigest: digestJson(report.listeners), storeDigest: digestJson(report.stores) });
}

function evaluateHostReport(report, bindings, key, now) {
  assertExactKeys(report, [
    "expiresAt", "nonce", "observedAt", "preCutoverEnvelope", "preCutoverExpected", "schemaVersion",
    "stagingEnvelope", "stagingExpected", "verifiedAtMs",
  ], "G11 Host report");
  if (report.schemaVersion !== 2 || !Number.isSafeInteger(report.verifiedAtMs)
    || typeof report.nonce !== "string" || report.nonce.length < 16) throw new Error("G11 Host report identity is invalid.");
  const evaluationNow = Date.parse(normalizedNow(now));
  if (Date.parse(report.observedAt) > evaluationNow || Date.parse(report.expiresAt) < evaluationNow) {
    throw new Error("G11 Host evidence is stale or from the future.");
  }
  const staging = verifyConnectorActivationStagingPrecheck(report.stagingEnvelope, key, report.stagingExpected, report.verifiedAtMs);
  assertVerifiedConnectorActivationStagingPrecheck(staging);
  const pre = verifyConnectorActivationPreCutoverHostCanary(report.preCutoverEnvelope, key, {
    ...report.preCutoverExpected,
    stagingActivationPrecheck: staging,
  }, report.verifiedAtMs);
  assertVerifiedConnectorActivationPreCutoverHostCanary(pre);
  if (pre.hostProvider !== "ChatGPT" || canonicalJson(pre.discoveredToolNames) !== canonicalJson(TOOL_NAMES)
    || digestJson(pre.candidateIdentity) !== bindings.candidateIdentityDigest) {
    throw new Error("G11 verified Host PRE differs from the candidate/tool/Host contract.");
  }
  return Object.freeze({ signedPayloadDigest: pre.signedPayloadDigest, nonce: report.nonce, expiresAt: report.expiresAt });
}

function evaluateConnectorReport(report, bindings, key, hostReport, now) {
  assertExactKeys(report, [
    "activationPlan", "journalReadback", "observedAt", "ownerEnvelope", "ownerExpected",
    "productionEnvelope", "productionExpected", "schemaVersion", "verifiedAtMs",
  ], "G12 connector report");
  if (report.schemaVersion !== 2 || !Number.isSafeInteger(report.verifiedAtMs)
    || Date.parse(report.observedAt) > Date.parse(normalizedNow(now))) throw new Error("G12 connector report identity/freshness is invalid.");
  const staging = verifyConnectorActivationStagingPrecheck(hostReport.stagingEnvelope, key, hostReport.stagingExpected, hostReport.verifiedAtMs);
  assertVerifiedConnectorActivationStagingPrecheck(staging);
  const pre = verifyConnectorActivationPreCutoverHostCanary(hostReport.preCutoverEnvelope, key, {
    ...hostReport.preCutoverExpected,
    stagingActivationPrecheck: staging,
  }, hostReport.verifiedAtMs);
  assertVerifiedConnectorActivationPreCutoverHostCanary(pre);
  const production = verifyConnectorActivationProductionPrecheck(report.productionEnvelope, key, {
    ...report.productionExpected,
    preCutoverHostCanary: pre,
  }, report.verifiedAtMs);
  assertVerifiedConnectorActivationProductionPrecheck(production);
  const owner = verifyConnectorActivationOwnerApproval(report.ownerEnvelope, key, report.ownerExpected, report.verifiedAtMs);
  assertVerifiedConnectorActivationOwnerApproval(owner);
  assertExactKeys(report.activationPlan, ["candidateIdentityDigest", "receiptId", "state", "tupleDigest"], "G12 activation plan");
  assertExactKeys(report.journalReadback, ["contentGeneration", "receiptId", "state", "tupleDigest"], "G12 journal readback");
  if (report.activationPlan.state !== "PREPARED" || report.journalReadback.state !== "PREPARED"
    || report.activationPlan.receiptId !== production.receiptId || report.journalReadback.receiptId !== production.receiptId
    || report.activationPlan.tupleDigest !== production.tupleDigest || report.journalReadback.tupleDigest !== production.tupleDigest
    || report.activationPlan.candidateIdentityDigest !== bindings.candidateIdentityDigest
    || owner.receiptId !== production.receiptId
    || owner.productionActivationPrecheckDigest !== production.signedPayloadDigest
    || !DIGEST_PATTERN.test(report.journalReadback.contentGeneration ?? "")) {
    throw new Error("G12 production precheck/owner/activation/journal bindings differ.");
  }
  return Object.freeze({
    productionPrecheckDigest: production.signedPayloadDigest,
    ownerApprovalDigest: owner.signedPayloadDigest,
    journalGeneration: report.journalReadback.contentGeneration,
  });
}

function validateCutoverReport(report, expected, prebinding, verifiedPost) {
  assertExactKeys(report, [
    "activeCount", "activationReceiptId", "challenge", "environmentIdentityDigest", "kind", "listenerPids",
    "listeners", "observedAt", "oldActiveCount", "process", "routeCount", "routeIdentityDigest",
    "routes", "runtimeIdentity", "schemaVersion",
  ], "canonical G13 cutover report");
  if (report.schemaVersion !== 2 || report.kind !== "CANONICAL_CUTOVER_READBACK"
    || report.challenge !== prebinding.challenge || report.activationReceiptId !== verifiedPost.receiptId
    || report.activeCount !== 1 || report.oldActiveCount !== 0 || report.routeCount !== 1
    || digestJson(report.runtimeIdentity) !== expected.runtimeIdentityDigest
    || report.environmentIdentityDigest !== expected.productionEnvironmentIdentityDigest
    || report.routeIdentityDigest !== expected.productionRouteIdentityDigest
    || report.process?.name !== expected.processName || report.process?.cwd !== expected.cwd
    || report.process?.script !== expected.script || report.process?.scriptSha256 !== expected.scriptSha256
    || report.process?.envDigest !== expected.environmentDigest
    || !Number.isSafeInteger(report.process?.pid) || report.process.pid < 1
    || !Array.isArray(report.listenerPids) || report.listenerPids.length < 1
    || report.listenerPids.some((pid) => pid !== report.process.pid)
    || !Array.isArray(report.listeners) || report.listeners.some((listener) => listener.pid !== report.process.pid)
    || !Array.isArray(report.routes) || report.routes.length !== 1
    || report.routes[0]?.identityDigest !== expected.productionRouteIdentityDigest) {
    throw new Error("Canonical G13 readback does not prove one current runtime/route/ACTIVE tuple and zero old family.");
  }
  requiredTimestamp(report.observedAt, "canonical G13 observedAt");
  return Object.freeze({
    processPid: report.process.pid,
    runtimeIdentityDigest: digestJson(report.runtimeIdentity),
    postActivationPayloadDigest: verifiedPost.signedPayloadDigest,
    listenerDigest: digestJson(report.listeners),
    routeDigest: digestJson(report.routes),
  });
}

function validateLiveManifest(value, expectedBindings) {
  assertExactKeys(value, [
    "artifacts", "bindings", "createdAt", "evidenceRoot", "nonce", "postCutover", "profile", "schemaVersion",
  ], "pre-activation live evidence payload");
  if (value.schemaVersion !== 3 || value.profile !== "BASE_SINGLE_OWNER"
    || typeof value.nonce !== "string" || value.nonce.length < 16) throw new Error("Pre-activation live evidence identity is invalid.");
  assertCanonicalEqual(value.bindings, expectedBindings, "pre-activation live evidence bindings");
  requiredTimestamp(value.createdAt, "pre-activation live evidence createdAt");
  canonicalOwnerOnlyDirectory(value.evidenceRoot, "pre-activation live evidence root");
  if (!Array.isArray(value.artifacts) || value.artifacts.length !== LIVE_GATES.length) throw new Error("Pre-activation live evidence must bind exactly G10-G12.");
  value.artifacts.forEach((reference, index) => {
    assertExactKeys(reference, ["format", "gate", "observedAt", "path", "sha256"], `live evidence reference ${LIVE_GATES[index]}`);
    if (reference.gate !== LIVE_GATES[index] || reference.format !== GATE_FORMATS[reference.gate]
      || !isAbsolute(reference.path) || resolve(reference.path) !== reference.path
      || !DIGEST_PATTERN.test(reference.sha256 ?? "")) throw new Error("Pre-activation live evidence reference is invalid or reordered.");
    requiredTimestamp(reference.observedAt, `live evidence observedAt ${reference.gate}`);
  });
  assertExactKeys(value.postCutover, ["activationIdentityDigest", "challenge", "expiresAt", "path", "reportPath"], "post-cutover prebinding");
  for (const path of [value.postCutover.path, value.postCutover.reportPath]) {
    if (!isAbsolute(path) || resolve(path) !== path) throw new Error("Post-cutover prebound path is invalid.");
  }
  requireDigest(value.postCutover.activationIdentityDigest, "post-cutover activationIdentityDigest");
  requireDigest(value.postCutover.challenge, "post-cutover challenge");
  requiredTimestamp(value.postCutover.expiresAt, "post-cutover expiresAt");
}

function normalizeBindings(value) {
  const input = canonicalClone(requiredObject(value, "gate identity bindings"));
  const expected = [...COMMON_BINDING_KEYS, "sourceRevision"];
  assertExactKeys(input, expected, "gate identity bindings");
  for (const key of expected) {
    if (key === "transactionId") {
      if (typeof input[key] !== "string" || input[key].length < 8 || input[key].length > 200) throw new Error("Gate transactionId is invalid.");
    } else if (key === "sourceRevision") {
      if (!/^[a-f0-9]{40}$/u.test(input[key] ?? "")) throw new Error("Gate sourceRevision is invalid.");
    } else requireDigest(input[key], `gate identity ${key}`);
  }
  return Object.freeze(input);
}

function executePackagedNfrEvaluator(inspection, results) {
  const source = inspection.readPayload("scripts/check-universal-broker-rev3-nfr.mjs").toString("utf8");
  const declarationsStart = source.indexOf("export const REV3_NFR_IDS");
  const declarationsEnd = source.indexOf("export function createNfrResult", declarationsStart);
  const helpersStart = source.indexOf("function validateResultShape", declarationsEnd);
  const helpersEnd = source.indexOf("function threshold(", helpersStart);
  const parseArgumentsStart = source.indexOf("function parseArguments", helpersStart);
  const thresholdEnd = source.indexOf("\n}", helpersEnd) + 2;
  if ([declarationsStart, declarationsEnd, helpersStart, helpersEnd, parseArgumentsStart, thresholdEnd].some((value) => value < 0)) {
    throw new Error("Immutable packaged NFR evaluator markers changed; refusing an approximate predicate.");
  }
  const declarations = source.slice(declarationsStart, declarationsEnd).replaceAll("export ", "");
  const helpers = source.slice(helpersStart, parseArgumentsStart);
  const threshold = source.slice(helpersEnd, thresholdEnd);
  const factory = new Function("input", [
    '"use strict";',
    "const mib = 1024 * 1024;",
    `const BASE_PROFILE_APPLICABILITY = ${canonicalJson({ BASE_SINGLE_OWNER: "REQUIRED", MULTI_USER: "NOT_APPLICABLE", SIDECAR_AUTHORITY: "NOT_APPLICABLE", HOST_ATTESTED: "NOT_APPLICABLE", GUI_CAPTURE: "NOT_APPLICABLE" })};`,
    threshold,
    declarations,
    helpers,
    "return evaluateNfrResults(input, { releaseRequired: true });",
  ].join("\n"));
  return factory(canonicalClone(results));
}

function validateTap(stdout, label) {
  if (!/^TAP version 13\n/mu.test(stdout)) throw new Error(`${label} output is not canonical Node TAP.`);
  const read = (name) => Number(new RegExp(`^# ${name} ([0-9]+)$`, "mu").exec(stdout)?.[1]);
  const tests = read("tests");
  const pass = read("pass");
  const fail = read("fail");
  const cancelled = read("cancelled");
  const skipped = read("skipped");
  const todo = read("todo");
  if (!Number.isSafeInteger(tests) || tests < 1 || pass !== tests || fail !== 0 || cancelled !== 0 || skipped !== 0 || todo !== 0) {
    throw new Error(`${label} TAP summary is incomplete, skipped, or failed.`);
  }
  return Object.freeze({ tests, pass });
}

function passGate(gate, evidence) {
  return Object.freeze({
    profile: "BASE_SINGLE_OWNER",
    gate,
    applicability: "REQUIRED",
    result: "PASS",
    evidenceDigest: domainDigest("devspace.base-profile-gate-result.v3", {
      gate,
      evidence,
      thresholdDigest: BASE_PROFILE_GATE_THRESHOLD_DIGEST,
    }),
  });
}

function notRunGate(gate) {
  return Object.freeze({ profile: "BASE_SINGLE_OWNER", gate, applicability: "REQUIRED", result: "NOT_RUN" });
}

function assertGateOrder(results) {
  const expected = [...BASE_PROFILE_GATE_NAMES, POST_CUTOVER_GATE_NAME, ...DEFERRED_FINALIZATION_GATE_NAMES];
  if (canonicalJson(results.map((entry) => entry.gate)) !== canonicalJson(expected)) {
    throw new Error("Base profile gate result ordering/coverage differs.");
  }
}

function normalizedNow(now) {
  const value = typeof now === "function" ? now() : new Date().toISOString();
  return requiredTimestamp(value, "gate evaluation time");
}

function requiredTimestamp(value, label) {
  if (typeof value !== "string" || !Number.isFinite(Date.parse(value)) || new Date(Date.parse(value)).toISOString() !== value) {
    throw new Error(`${label} is not canonical UTC ISO-8601.`);
  }
  return value;
}

function canonicalOwnerOnlyFile(value, label) {
  if (typeof value !== "string" || !isAbsolute(value) || resolve(value) !== value || /[\0\r\n]/u.test(value)) {
    throw new Error(`${label} must be an absolute canonical path.`);
  }
  const metadata = lstatSync(value);
  if (!metadata.isFile() || metadata.isSymbolicLink() || realpathSync(value) !== value
    || (metadata.mode & 0o077) !== 0
    || (typeof process.getuid === "function" && metadata.uid !== process.getuid())) {
    throw new Error(`${label} must be an owner-only canonical real file.`);
  }
  return value;
}

function canonicalOwnerOnlyDirectory(value, label) {
  if (typeof value !== "string" || !isAbsolute(value) || resolve(value) !== value) throw new Error(`${label} must be an absolute canonical path.`);
  const metadata = lstatSync(value);
  if (!metadata.isDirectory() || metadata.isSymbolicLink() || realpathSync(value) !== value
    || (metadata.mode & 0o077) !== 0
    || (typeof process.getuid === "function" && metadata.uid !== process.getuid())) {
    throw new Error(`${label} must be an owner-only canonical real directory.`);
  }
  return value;
}

function canonicalRealDirectory(value, label) {
  if (typeof value !== "string" || !isAbsolute(value) || resolve(value) !== value) throw new Error(`${label} must be an absolute canonical path.`);
  const metadata = lstatSync(value);
  if (!metadata.isDirectory() || metadata.isSymbolicLink() || realpathSync(value) !== value) throw new Error(`${label} must be a canonical real directory.`);
  return value;
}

function canonicalProspectivePath(value, root, label) {
  if (typeof value !== "string" || !isAbsolute(value) || resolve(value) !== value || !isSameOrInside(root, value) || value === root) {
    throw new Error(`${label} must be a contained canonical absolute path.`);
  }
  const parent = canonicalOwnerOnlyDirectory(dirname(value), `${label} parent`);
  if (!isSameOrInside(root, parent)) throw new Error(`${label} parent escapes evidence root.`);
  return value;
}

function stableReadFile(path, label) {
  const descriptor = openSync(path, constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0));
  try {
    const before = fstatSync(descriptor, { bigint: true });
    const bytes = readFileSync(descriptor);
    const after = fstatSync(descriptor, { bigint: true });
    if (!before.isFile() || before.dev !== after.dev || before.ino !== after.ino
      || before.size !== after.size || before.mtimeNs !== after.mtimeNs || BigInt(bytes.length) !== after.size) {
      throw new Error(`${label} changed during its single-descriptor no-follow read.`);
    }
    return bytes;
  } finally { closeSync(descriptor); }
}

function parseCanonicalJson(bytes, label) {
  const value = parseJsonText(bytes.toString("utf8"), label);
  if (bytes.toString("utf8") !== `${canonicalJson(value)}\n`) throw new Error(`${label} is not canonical JSON.`);
  return value;
}

function parseJsonText(text, label) {
  try { return JSON.parse(text); } catch { throw new Error(`${label} is invalid JSON.`); }
}

function assertCanonicalEqual(actual, expected, label) {
  if (canonicalJson(actual) !== canonicalJson(expected)) throw new Error(`${label} differs.`);
}

function assertExactKeys(value, expected, label) {
  const actual = Object.keys(requiredObject(value, label)).sort(compareCodeUnits);
  const wanted = [...expected].sort(compareCodeUnits);
  if (canonicalJson(actual) !== canonicalJson(wanted)) throw new Error(`${label} contains a missing or unsupported field.`);
}

function requiredObject(value, label) {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error(`${label} is missing or invalid.`);
  return value;
}

function requireDigest(value, label) {
  if (!DIGEST_PATTERN.test(value ?? "")) throw new Error(`${label} is not a canonical SHA-256 digest.`);
  return value;
}

function isSameOrInside(root, path) {
  const relation = relative(root, path);
  return relation === "" || (relation !== ".." && !relation.startsWith(`..${sep}`) && !isAbsolute(relation));
}

function lstatIfPresent(path) {
  try { return lstatSync(path); } catch (error) { if (error?.code === "ENOENT") return undefined; throw error; }
}

function canonicalClone(value) { return JSON.parse(canonicalJson(value)); }
function canonicalJson(value) {
  if (value === null || typeof value !== "object") {
    const encoded = JSON.stringify(value);
    if (encoded === undefined) throw new Error("Gate evidence value is not canonically serializable.");
    return encoded;
  }
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  return `{${Object.keys(value).sort(compareCodeUnits).map((key) => `${JSON.stringify(key)}:${canonicalJson(value[key])}`).join(",")}}`;
}
function digestBytes(value) { return `sha256:${createHash("sha256").update(value).digest("hex")}`; }
function digestJson(value) { return digestBytes(Buffer.from(canonicalJson(value))); }
function domainDigest(domain, value) { return digestBytes(Buffer.from(`${domain}\0${canonicalJson(value)}`)); }
function compareCodeUnits(left, right) { return left < right ? -1 : left > right ? 1 : 0; }
