#!/usr/bin/env node
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import {
  chmodSync,
  closeSync,
  existsSync,
  fsyncSync,
  lstatSync,
  mkdirSync,
  openSync,
  realpathSync,
  readFileSync,
  renameSync,
  unlinkSync,
  writeFileSync,
} from "node:fs";
import { dirname, isAbsolute, join, resolve } from "node:path";
import { homedir } from "node:os";
import { fileURLToPath, pathToFileURL } from "node:url";
import Database from "better-sqlite3";
import { verifyConnectorActivationPostActivationHostCanary } from "../dist/v2/connector-activation-evidence.js";
import { loadExistingManagementAuthorizationKey } from "../dist/v2/management-authorization.js";
import { SqliteConnectorActivationRecoveryJournal } from "../dist/v2/connector-activation-journal.js";
import { canonicalJson } from "./lib/release-artifacts.mjs";

const THIS_DRIVER_PATH = realpathSync(fileURLToPath(import.meta.url));

export function runFinalizationDriverCli(arguments_ = process.argv.slice(2)) {
  const [operation, stageId, contextPath, ...extra] = arguments_;
  if (!operation || !stageId || !contextPath || extra.length > 0 || !["readback", "apply"].includes(operation)) {
    throw new Error("Usage: finalization-live-driver.mjs <readback|apply> <stage-id> <context.json>");
  }
  const context = readJson(contextPath);
  if (realpathSync(context.canonicalDriverPath) !== THIS_DRIVER_PATH) {
    throw new Error("Driver context is not bound to this canonical finalization-live-driver realpath.");
  }
  const prepare = readJson(context.preparePath);
  const { checksum, ...unsignedPrepare } = prepare;
  if (checksum !== digestJson(unsignedPrepare) || context.prepareDigest !== digestJson(prepare)) {
    throw new Error("Driver context prepared record checksum/digest changed.");
  }
  const stages = new Map(prepare.destructivePlan.map((stage) => [stage.id, stage]));
  const stage = stages.get(stageId);
  if (!stage) throw new Error(`Unknown finalization stage: ${stageId}`);
  const result = operation === "readback" ? readback(stage, context, prepare) : apply(stage, context, prepare);
  emit(result);
  if (!result.complete) process.exitCode = 1;
  return result;
}

if (process.argv[1] && pathToFileURL(realpathSync(process.argv[1])).href === import.meta.url) {
  try {
    runFinalizationDriverCli();
  } catch (error) {
    console.error(error instanceof Error ? error.message : String(error));
    process.exitCode = 1;
  }
}

export function runCanonicalFinalReadback({ context, prepare, stages, nowMs = Date.now() }) {
  if (!Number.isSafeInteger(nowMs)) throw new Error("Canonical final readback nowMs is invalid.");
  if (realpathSync(context.canonicalDriverPath) !== THIS_DRIVER_PATH) {
    throw new Error("Final readback context is not bound to the canonical in-process driver realpath.");
  }
  if (context.prepareDigest !== digestJson(prepare)) {
    throw new Error("Final readback prepared-record digest changed.");
  }
  const sources = validatePreparedProductionSources(prepare.productionSources, prepare.snapshotGroup);
  if (context.productionSourcesDigest !== digestJson(prepare.productionSources)) {
    throw new Error("Final readback context production-source binding changed.");
  }
  const postEnvelope = readOwnerOnlyJson(sources.stores.postActivationReceipt.path, "POST activation receipt");
  if (postEnvelope?.schemaVersion !== 2
    || postEnvelope.kind !== "POST_ACTIVATION_HOST_CANARY"
    || !postEnvelope.payload
    || typeof postEnvelope.payload !== "object") {
    throw new Error("POST activation receipt is not a signed version 2 Host envelope.");
  }
  const runtimeResponse = curlJson(sources.endpoints.runtimeIdentityUrl);
  const runtimeIdentity = runtimeResponse?.identity ?? runtimeResponse;
  const runtimeIdentityDigest = digestJson(runtimeIdentity);
  const routeIdentity = curlJson(sources.endpoints.routeIdentityUrl);
  const managementIdentity = curlJson(sources.endpoints.managementIdentityUrl);
  if (digestJson(managementIdentity) !== sources.endpoints.managementIdentityDigest) {
    throw new Error("Private management endpoint identity differs from the prepared canonical source.");
  }
  const processReadback = exactPm2Runtime(sources.processManager, runtimeIdentityDigest);
  const listenerReadback = exactListenerInventory(sources.listeners);
  const funnelInventory = commandJson("tailscale", ["funnel", "status", "--json"]);
  if (digestJson(funnelInventory) !== sources.route.expectedFunnelInventoryDigest) {
    throw new Error("Public route inventory differs from the prepared canonical route.");
  }
  const presentResidue = sources.residue.paths.filter((path) => existsSync(path));
  if (presentResidue.length > 0) throw new Error(`Legacy/parallel/temp residue remains: ${presentResidue.join(", ")}`);
  const oauth = readOAuthFinalizationState(sources.stores.oauth.path, sources.activation);
  const activationAuthorityReadback = readAuthorityPass(
    sources.stores.authority.path,
    oauth.connectorActivationReceipt.activationAuthority,
  );
  const connectorJournalReadback = readConnectorJournal(
    sources.stores.connectorJournal.path,
    oauth.connectorActivationReceipt,
    sources.activation,
  );
  const key = loadExistingManagementAuthorizationKey({
    keyRef: sources.managementAuthorization.keyRef,
    stateDir: sources.managementAuthorization.stateDir,
  });
  if (key.keyId !== sources.managementAuthorization.keyId) {
    throw new Error("Management authorization key identity differs from the prepared source.");
  }
  const verifiedPostActivationHostCanary = verifyConnectorActivationPostActivationHostCanary(
    postEnvelope,
    key,
    {
      principalKeyFingerprint: sources.activation.principalKeyFingerprint,
      managementNonce: sources.activation.managementNonce,
      managementCorrelationId: sources.activation.managementCorrelationId,
      productionActivationPrecheckDigest: sources.activation.productionActivationPrecheckDigest,
      activationReceipt: oauth.connectorActivationReceipt,
      activationAuthorityReceipt: oauth.connectorActivationReceipt.activationAuthority,
      newActiveBindingState: "ACTIVE",
      tokenFamilyIdDigest: sources.activation.tokenFamilyIdDigest,
      tokenFamilyBindingId: sources.activation.tokenFamilyBindingId,
      previousBindingState: sources.activation.previousBindingState,
      productionIdentity: sources.activation.productionIdentity,
      productionEnvironmentIdentityDigest: sources.activation.productionEnvironmentIdentityDigest,
      productionRouteIdentityDigest: sources.activation.productionRouteIdentityDigest,
    },
    nowMs,
  );
  const postMutationAuthorityReadback = readAuthorityPass(
    sources.stores.authority.path,
    verifiedPostActivationHostCanary.mutation,
  );
  return {
    complete: true,
    stages,
    productionSourcesDigest: digestJson(prepare.productionSources),
    runtimeIdentity,
    runtimeReadback: { identityDigest: runtimeIdentityDigest },
    pm2Runtime: processReadback,
    listenerReadback,
    managementIdentity,
    funnelInventoryDigest: digestJson(funnelInventory),
    residueReadback: { paths: sources.residue.paths, present: [] },
    routeIdentity,
    oauthReadback: oauth.oauthReadback,
    activeTokenFamily: oauth.activeTokenFamily,
    activeConnector: oauth.activeConnector,
    retiredConnectors: oauth.retiredConnectors,
    revokedTokenFamilyIds: oauth.revokedTokenFamilyIds,
    connectorActivationReceipt: oauth.connectorActivationReceipt,
    activationAuthorityReadback,
    postMutationAuthorityReadback,
    connectorJournalReadback,
    postActivationHostCanaryReceipt: postEnvelope,
    verifiedPostActivationHostCanary,
  };
}

function validatePreparedProductionSources(value, snapshotGroup) {
  if (!value || value.schemaVersion !== 1) throw new Error("Prepared canonical production sources are missing.");
  for (const path of [value.managementAuthorization?.keyRef, value.processManager?.definitionPath,
    value.processManager?.savedStatePath, value.runtimeEnvironmentPath,
    value.route?.definitionPath, value.route?.targetGenerationConfigPath,
    value.stores?.oauth?.path, value.stores?.authority?.path, value.stores?.connectorJournal?.path,
    value.stores?.postActivationReceipt?.path]) canonicalOwnerOnlyFile(path, "prepared production source file");
  canonicalRealDirectory(value.managementAuthorization?.stateDir, "management authorization state directory");
  for (const key of ["runtimeIdentityUrl", "routeIdentityUrl", "managementIdentityUrl"]) {
    requiredHttpUrl(value.endpoints?.[key], `prepared endpoints.${key}`);
  }
  for (const name of ["oauth", "authority", "connectorJournal"]) {
    const expected = value.stores?.[name];
    const observed = sqliteStoreIdentity(expected.path);
    if (observed.userVersion !== expected.userVersion || observed.schemaFingerprint !== expected.schemaFingerprint) {
      throw new Error(`Prepared production ${name} store identity drifted.`);
    }
  }
  const snapshotEntries = new Map(snapshotGroup?.manifest?.entries?.map((entry) => [entry.id, entry]) ?? []);
  assertCurrentSnapshottedFile(
    snapshotEntries,
    "process-manager-definition",
    value.processManager.definitionPath,
    value.processManager.definitionSha256,
  );
  assertCurrentSnapshottedFile(
    snapshotEntries,
    "runtime-environment",
    value.runtimeEnvironmentPath,
  );
  assertCurrentSnapshottedFile(
    snapshotEntries,
    "public-route",
    value.route.definitionPath,
    value.route.definitionSha256,
  );
  assertCurrentSnapshottedFile(
    snapshotEntries,
    "target-route-generation-config",
    value.route.targetGenerationConfigPath,
    value.route.targetGenerationConfigSha256,
  );
  return value;
}

function assertCurrentSnapshottedFile(entries, id, path, explicitDigest) {
  const entry = entries.get(id);
  const canonicalPath = canonicalOwnerOnlyFile(path, `prepared ${id}`);
  const observedDigest = digestFile(canonicalPath);
  if (!entry
    || entry.kind !== "file"
    || entry.required !== true
    || entry.state !== "captured"
    || entry.path !== canonicalPath
    || entry.sha256 !== observedDigest
    || (explicitDigest !== undefined && explicitDigest !== observedDigest)) {
    throw new Error(`Current ${id} differs from the exact snapshotted production source.`);
  }
}

function exactPm2Runtime(expectedManager, runtimeIdentityDigest) {
  const observed = pm2InventoryDetails();
  const expected = expectedManager.expectedProcesses.map(normalizeExpectedLiveProcess).sort(compareCanonicalProcess);
  const normalizedObserved = observed.map(({ name, status, cwd, script }) => ({ name, status, cwd, script }))
    .sort(compareCanonicalProcess);
  if (canonicalJson(expected) !== canonicalJson(normalizedObserved)) {
    throw new Error("PM2 inventory is not the exact prepared one-process production definition.");
  }
  const saved = readOwnerOnlyJson(expectedManager.savedStatePath, "PM2 saved-state definition")
    .map((entry) => normalizeProcess(entry, entry.pm2_env ?? entry));
  const normalizedSaved = saved.map(({ name, status, cwd, script }) => ({ name, status, cwd, script }))
    .sort(compareCanonicalProcess);
  if (canonicalJson(expected) !== canonicalJson(normalizedSaved)) {
    throw new Error("PM2 saved state is not the exact prepared one-process production definition.");
  }
  const process = observed[0];
  if (process.status !== "online" || !Number.isInteger(process.pid) || process.pid < 1
    || !process.cwd || !process.script) {
    throw new Error(`PM2 runtime ${expectedManager.canonicalProcessName} is not one exact online immutable process.`);
  }
  return { ...process, runtimeIdentityDigest };
}

function normalizeExpectedLiveProcess(entry) {
  return {
    name: requiredText(entry?.name, "expected process name"),
    status: entry?.status === "online" ? "online" : "",
    cwd: realpathSync(requiredAbsolutePath(entry?.cwd, "expected process cwd")),
    script: realpathSync(requiredAbsolutePath(entry?.script, "expected process script")),
  };
}

function compareCanonicalProcess(left, right) {
  return compareCodeUnits(canonicalJson(left), canonicalJson(right));
}

function exactListenerInventory(expectedSources) {
  const output = run("lsof", ["-nP", "-iTCP", "-sTCP:LISTEN", "-Fpcn"], true).stdout;
  const observed = parseLsofListeners(output)
    .filter((listener) => expectedSources.scopePorts.includes(listener.port))
    .map(({ command, address, port }) => ({ command, address, port }))
    .sort(compareListener);
  const expected = expectedSources.expected
    .map(({ command, address, port }) => ({ command, address, port }))
    .sort(compareListener);
  if (canonicalJson(observed) !== canonicalJson(expected)) {
    throw new Error("Scoped public/management listener inventory is not exact or contains an extra listener.");
  }
  return { scopePorts: expectedSources.scopePorts, listeners: observed, inventoryDigest: digestJson(observed) };
}

function parseLsofListeners(output) {
  const listeners = [];
  let pid;
  let command;
  for (const line of String(output).split("\n")) {
    if (line.startsWith("p")) pid = Number.parseInt(line.slice(1), 10);
    else if (line.startsWith("c")) command = line.slice(1);
    else if (line.startsWith("n")) {
      const endpoint = line.slice(1).replace(/^TCP\s+/u, "").replace(/\s+\(LISTEN\)$/u, "");
      const match = /^(.*):(\d+)$/u.exec(endpoint);
      if (match && Number.isInteger(pid) && command) {
        listeners.push({ pid, command, address: match[1], port: Number.parseInt(match[2], 10) });
      }
    }
  }
  return listeners;
}

function compareListener(left, right) {
  if (left.port !== right.port) return left.port - right.port;
  return compareCodeUnits(canonicalJson(left), canonicalJson(right));
}

function sqliteStoreIdentity(path) {
  const database = new Database(canonicalOwnerOnlyFile(path, "production sqlite store"), {
    readonly: true,
    fileMustExist: true,
  });
  try {
    const integrity = database.pragma("integrity_check", { simple: true });
    if (integrity !== "ok") throw new Error(`Production sqlite store integrity failed: ${path}`);
    const foreignKeys = database.pragma("foreign_key_check");
    if (!Array.isArray(foreignKeys) || foreignKeys.length !== 0) {
      throw new Error(`Production sqlite store foreign-key check failed: ${path}`);
    }
    const userVersion = database.pragma("user_version", { simple: true });
    const schema = database.prepare(`
      select type, name, tbl_name as tableName, sql from sqlite_master
       where name not like 'sqlite_%' order by type, name
    `).all();
    return { userVersion, schemaFingerprint: digestJson({ userVersion, schema }) };
  } finally {
    database.close();
  }
}

function canonicalOwnerOnlyFile(path, label) {
  const absolute = requiredAbsolutePath(path, label);
  const metadata = lstatSync(absolute);
  if (!metadata.isFile() || metadata.isSymbolicLink() || (metadata.mode & 0o077) !== 0
    || (typeof process.getuid === "function" && metadata.uid !== process.getuid())
    || realpathSync(absolute) !== absolute) {
    throw new Error(`${label} must be an owner-only canonical real file.`);
  }
  return absolute;
}

function canonicalRealDirectory(path, label) {
  const absolute = requiredAbsolutePath(path, label);
  const metadata = lstatSync(absolute);
  if (!metadata.isDirectory() || metadata.isSymbolicLink() || realpathSync(absolute) !== absolute) {
    throw new Error(`${label} must be a canonical real directory.`);
  }
  return absolute;
}

function readOAuthFinalizationState(databasePath, activation) {
  const database = new Database(databasePath, { readonly: true, fileMustExist: true });
  try {
    const canonicalName = requiredText(activation.canonicalName, "prepared canonicalName");
    const activeRows = database.prepare(`
      select binding_id as bindingId, canonical_name as canonicalName, client_id as clientId,
             installation_epoch as installationEpoch, schema_generation as schemaGeneration,
             authority_contract_generation as authorityContractGeneration,
             redirect_uris_digest as redirectUrisDigest, build_digest as buildDigest,
             drain_epoch as drainEpoch, ref_count as refCount, state
        from oauth_connector_bindings
       where canonical_name = ? and state = 'ACTIVE'
       order by binding_id
    `).all(canonicalName);
    if (activeRows.length !== 1) throw new Error("OAuth readback does not contain one canonical ACTIVE binding.");
    const active = activeRows[0];
    const canonicalRows = database.prepare(`
      select binding_id as bindingId, state, ref_count as refCount
        from oauth_connector_bindings where canonical_name = ? order by binding_id
    `).all(canonicalName);
    const familyRows = database.prepare(`
      select family_id as familyId, client_id as clientId,
             connector_binding_id as connectorBindingId,
             installation_epoch as installationEpoch, drain_epoch as drainEpoch, status
        from oauth_token_families
       where status = 'ACTIVE'
       order by family_id
    `).all();
    const selectedFamilies = familyRows.filter(
      (family) => digestText(family.familyId) === activation.tokenFamilyIdDigest,
    );
    if (selectedFamilies.length !== 1) {
      throw new Error("POST token family digest does not select exactly one ACTIVE OAuth family.");
    }
    const activeTokenFamily = selectedFamilies[0];
    const activeConnector = { ...active, tokenFamilyId: activeTokenFamily.familyId };
    const retiredConnectors = database.prepare(`
      select binding.binding_id as bindingId, binding.state,
             binding.ref_count as refCount, receipt.receipt_id as retirementReceiptId,
             receipt.reason as retirementReason
        from oauth_connector_bindings binding
        join oauth_connector_retirement_receipts receipt
          on receipt.binding_id = binding.binding_id
       where binding.canonical_name = ? and binding.state = 'RETIRED'
       order by binding.binding_id
    `).all(canonicalName);
    const retiredIds = new Set(retiredConnectors.map((entry) => entry.bindingId));
    const undisposed = canonicalRows.filter((entry) => (
      entry.bindingId !== active.bindingId
      && (entry.state !== "RETIRED" || entry.refCount !== 0 || !retiredIds.has(entry.bindingId))
    ));
    if (canonicalRows.length !== retiredConnectors.length + 1 || undisposed.length > 0) {
      throw new Error("OAuth readback retains an extra DRAINING/parallel canonical connector binding.");
    }
    const revokedTokenFamilyIds = database.prepare(`
      select family_id as familyId from oauth_token_families
       where status = 'REVOKED' order by family_id
    `).all().map((row) => row.familyId);
    const receiptRow = database.prepare(`
      select receipt_id as receiptId, canonical_name as canonicalName,
             candidate_binding_id as candidateBindingId, client_id as clientId,
             installation_epoch as installationEpoch, schema_generation as schemaGeneration,
             authority_contract_generation as authorityContractGeneration,
             redirect_uris_digest as redirectUrisDigest, build_digest as buildDigest,
             tuple_digest as tupleDigest, preimage_digest as preimageDigest,
             previous_active_binding_id as previousActiveBindingId,
             owner_authority_id as ownerAuthorityId, drain_deadline_at as drainDeadlineAt,
             refresh_allowed_during_drain as refreshAllowedDuringDrain,
             status, prepared_at as preparedAt, activated_at as activatedAt
        from oauth_connector_activation_receipts
       where receipt_id = ? and candidate_binding_id = ?
    `).get(requiredText(activation.receiptId, "prepared activationReceiptId"), active.bindingId);
    if (!receiptRow || receiptRow.status !== "ACTIVATED") {
      throw new Error("Exact activated OAuth connector receipt is missing.");
    }
    const authorityRow = database.prepare(`
      select action_claim_id as actionClaimId, receipt_id as receiptId,
             authority_id as authorityId, principal_key_fingerprint as principalKeyFingerprint,
             action_fingerprint as actionFingerprint, resource_key_sha256 as resourceKeySha256,
             fencing_token as fencingToken, risk, claim_state as claimState,
             approval_assurance as approvalAssurance, canonical_name as canonicalName,
             tuple_digest as tupleDigest, active_preimage_digest as activePreimageDigest,
             finalization_plan_digest as finalizationPlanDigest, evidence_digest as evidenceDigest,
             claimed_at_ms as claimedAtMs, dispatched_at_ms as dispatchedAtMs,
             proof_digest as proofDigest, consumed_at as consumedAt
        from oauth_connector_activation_authorities where receipt_id = ?
    `).get(receiptRow.receiptId);
    if (!authorityRow) throw new Error("OAuth connector activation authority proof is missing.");
    // schemaVersion is a type-level invariant reconstructed by SqliteOAuthStore;
    // the normalized table deliberately does not persist a redundant column.
    const authority = { schemaVersion: 1, ...authorityRow };
    const tuple = {
      canonicalName: receiptRow.canonicalName,
      candidateBindingId: receiptRow.candidateBindingId,
      clientId: receiptRow.clientId,
      installationEpoch: receiptRow.installationEpoch,
      schemaGeneration: receiptRow.schemaGeneration,
      authorityContractGeneration: receiptRow.authorityContractGeneration,
      redirectUrisDigest: receiptRow.redirectUrisDigest,
      buildDigest: receiptRow.buildDigest,
    };
    const receipt = {
      receiptId: receiptRow.receiptId,
      tuple,
      tupleDigest: receiptRow.tupleDigest,
      ...(receiptRow.previousActiveBindingId
        ? { previousActiveBindingId: receiptRow.previousActiveBindingId }
        : {}),
      preimageDigest: receiptRow.preimageDigest,
      activationAuthority: authority,
      ownerAuthorityId: receiptRow.ownerAuthorityId,
      drainDeadlineAt: receiptRow.drainDeadlineAt,
      refreshAllowedDuringDrain: receiptRow.refreshAllowedDuringDrain === 1,
      status: receiptRow.status,
      preparedAt: receiptRow.preparedAt,
      activatedAt: receiptRow.activatedAt,
    };
    return {
      oauthReadback: {
        canonicalActiveCount: activeRows.length,
        selectedActiveTokenFamilyCount: selectedFamilies.length,
        canonicalBindingCount: canonicalRows.length,
        retiredCanonicalBindingCount: retiredConnectors.length,
        undisposedCanonicalBindingCount: undisposed.length,
      },
      activeTokenFamily,
      activeConnector,
      retiredConnectors,
      revokedTokenFamilyIds,
      connectorActivationReceipt: receipt,
    };
  } finally {
    database.close();
  }
}

function readAuthorityPass(databasePath, expected) {
  const database = new Database(databasePath, { readonly: true, fileMustExist: true });
  try {
    const row = database.prepare(`
      select claim.authority_id as authorityId, claim.action_claim_id as actionClaimId,
             claim.action_id as actionId, claim.task_instance_id as taskInstanceId,
             claim.principal_key_fingerprint as principalKeyFingerprint,
             claim.action_fingerprint as actionFingerprint,
             claim.resource_key_sha256 as resourceKeySha256,
             claim.fencing_token as fencingToken, claim.claimed_at_ms as claimedAtMs,
             claim.dispatched_at_ms as dispatchedAtMs, claim.completed_at_ms as completedAtMs,
             claim.state, claim.provider_call_count as providerCallCount,
             claim.error_code as errorCode, claim.reason_code as reasonCode,
             action.tool, action.operation,
             coalesce(lease.lease_state, case when claim.state = 'UNCERTAIN'
               then 'RECOVERY_REQUIRED' else 'RELEASED' end) as leaseState
        from operation_authority_claims claim
        join operation_authority_actions action
          on action.authority_id = claim.authority_id and action.action_id = claim.action_id
        left join operation_authority_resource_leases lease
          on lease.resource_key_sha256 = claim.resource_key_sha256
         and lease.action_claim_id = claim.action_claim_id
         and lease.fencing_token = claim.fencing_token
       where claim.authority_id = ? and claim.action_claim_id = ?
    `).get(
      requiredText(expected.authorityId, "authorityId"),
      requiredText(expected.actionClaimId, "actionClaimId"),
    );
    if (!row) throw new Error("Exact authority PASS readback is missing.");
    const digestInput = {
      schemaVersion: 1,
      authorityId: row.authorityId,
      actionClaimId: row.actionClaimId,
      useId: row.actionClaimId,
      actionId: row.actionId,
      taskInstanceId: row.taskInstanceId,
      principalKeyFingerprint: row.principalKeyFingerprint,
      actionFingerprint: row.actionFingerprint,
      resourceKeySha256: row.resourceKeySha256,
      fencingToken: row.fencingToken,
      claimedAtMs: row.claimedAtMs,
      reservedAtMs: row.claimedAtMs,
      ...(row.dispatchedAtMs === null ? {} : { dispatchedAtMs: row.dispatchedAtMs }),
      ...(row.completedAtMs === null ? {} : { completedAtMs: row.completedAtMs }),
      state: row.state,
      result: row.state,
      leaseState: row.leaseState,
      ...(row.providerCallCount === null ? {} : { providerCallCount: row.providerCallCount }),
      ...(row.errorCode ? { errorCode: row.errorCode } : {}),
      ...(row.reasonCode ? { reasonCode: row.reasonCode } : {}),
    };
    return {
      authorityId: row.authorityId,
      actionClaimId: row.actionClaimId,
      actionFingerprint: row.actionFingerprint,
      resourceKeySha256: row.resourceKeySha256,
      fencingToken: row.fencingToken,
      principalKeyFingerprint: row.principalKeyFingerprint,
      tool: row.tool,
      operation: row.operation,
      claimedAtMs: row.claimedAtMs,
      dispatchedAtMs: row.dispatchedAtMs,
      completedAtMs: row.completedAtMs,
      state: row.state,
      result: row.state,
      leaseState: row.leaseState,
      providerCallCount: row.providerCallCount,
      receiptDigest: digestJson(digestInput),
    };
  } finally {
    database.close();
  }
}

function readConnectorJournal(databasePath, activationReceipt, activation) {
  const journal = new SqliteConnectorActivationRecoveryJournal({ storePath: databasePath });
  try {
    const identity = journal.identity();
    const entry = journal.load({
      principalKeyFingerprint: activationReceipt.activationAuthority.principalKeyFingerprint,
      approvalId: requiredText(activation.approvalId, "prepared activation approvalId"),
      receiptId: activationReceipt.receiptId,
    });
    if (!entry || !entry.recovery || entry.outcomes.length !== 2) {
      throw new Error("Connector activation journal final readback is incomplete.");
    }
    const pending = entry.outcomes.find((outcome) => outcome.state === "ACTIVATED_PENDING_POSTCHECK");
    const post = entry.outcomes.find((outcome) => outcome.state === "POST_ACTIVATION_VERIFIED");
    if (!pending || !post) throw new Error("Connector activation journal lacks pending/POST terminal outcomes.");
    const transition = entry.recovery;
    return {
      storeId: identity.storeId,
      snapshotPolicy: identity.snapshotPolicy,
      receiptReplayPolicy: identity.receiptReplayPolicy,
      contentGeneration: identity.contentGeneration,
      principalKeyFingerprint: entry.intent.principalKeyFingerprint,
      approvalId: entry.intent.approvalId,
      receiptId: entry.intent.receiptId,
      freshHostReceiptId: entry.intent.freshHostReceiptId,
      dispatchState: transition.dispatchState,
      authorityId: transition.authorityId,
      actionClaimId: transition.actionClaimId,
      actionFingerprint: transition.actionFingerprint,
      resourceKeySha256: transition.resourceKeySha256,
      fencingToken: transition.fencingToken,
      pendingEvidenceDigest: pending.evidenceDigest,
      postActivationEvidenceDigest: post.evidenceDigest,
      postActivationRecordedAtMs: post.recordedAtMs,
      terminalState: post.state,
    };
  } finally {
    journal.close();
  }
}

function readback(stage, context, prepare) {
  switch (stage.operation) {
    case "remove-file": {
      validateTemporaryTarget(stage.target, prepare);
      return { complete: !existsSync(stage.target), evidence: { path: stage.target, absent: !existsSync(stage.target) } };
    }
    case "replace-file": {
      validatePreimageTarget(stage.target, prepare);
      const expected = requireDigest(stage.expectedSha256, "expectedSha256");
      const actual = existsSync(stage.target) ? digestFile(stage.target) : undefined;
      return { complete: actual === expected, evidence: { path: stage.target, sha256: actual } };
    }
    case "pm2-delete": {
      validateProcessTarget(stage.target, prepare);
      const processes = pm2Inventory();
      const entry = processes.find((item) => item.name === stage.target);
      return { complete: !entry, evidence: { name: stage.target, present: Boolean(entry) } };
    }
    case "pm2-save": {
      return pm2SavedStateReadback(stage);
    }
    case "funnel-disable": {
      const routeKey = requiredText(stage.routeKey, "routeKey");
      const inventory = commandJson("tailscale", ["funnel", "status", "--json"]);
      const present = JSON.stringify(inventory).includes(routeKey);
      return { complete: !present, evidence: { routeKey, present, inventoryDigest: digestJson(inventory) } };
    }
    case "sqlite-revoke-token-family":
      return sqliteFamilyReadback(stage);
    case "sqlite-drain-connector":
      return sqliteConnectorReadback(stage);
    case "verify-runtime": {
      const observed = curlJson(requiredText(stage.identityUrl, "identityUrl"));
      const mismatches = runtimeMismatches(context.runtimeIdentity, observed);
      return { complete: mismatches.length === 0, evidence: { identityDigest: digestJson(observed), mismatches }, message: mismatches.join(", ") };
    }
    case "evidence-assert":
      return { complete: true, evidence: { assertion: stage.target } };
    default:
      throw new Error(`Unsupported finalization stage operation: ${stage.operation}`);
  }
}

function apply(stage, context, prepare) {
  switch (stage.operation) {
    case "remove-file": {
      validateTemporaryTarget(stage.target, prepare);
      verifyPreimageIfPresent(stage.target, prepare);
      const metadata = lstatSync(stage.target);
      if (!metadata.isFile() && !metadata.isSymbolicLink()) throw new Error(`Refusing to remove non-file finalization target: ${stage.target}`);
      unlinkSync(stage.target);
      fsyncDirectory(dirname(stage.target));
      return readback(stage, context, prepare);
    }
    case "replace-file": {
      validatePreimageTarget(stage.target, prepare);
      verifyPreimageIfPresent(stage.target, prepare);
      if (typeof stage.contentBase64 !== "string") throw new Error("replace-file contentBase64 is required.");
      const content = Buffer.from(stage.contentBase64, "base64");
      if (`sha256:${createHash("sha256").update(content).digest("hex")}` !== requireDigest(stage.expectedSha256, "expectedSha256")) {
        throw new Error("replace-file content does not match expectedSha256.");
      }
      writeFileAtomic(stage.target, content, stage.mode ?? 0o700);
      return readback(stage, context, prepare);
    }
    case "pm2-delete":
      validateProcessTarget(stage.target, prepare);
      run("pm2", ["delete", stage.target]);
      return readback(stage, context, prepare);
    case "pm2-save":
      run("pm2", ["save"]);
      return readback(stage, context, prepare);
    case "funnel-disable": {
      if (!Array.isArray(stage.arguments) || stage.arguments.some((value) => typeof value !== "string")) throw new Error("funnel-disable arguments are required.");
      if (stage.arguments[0] !== "funnel" || !stage.arguments.includes("off") || stage.arguments.some((value) => /[^A-Za-z0-9_./:=+-]/u.test(value))) {
        throw new Error("Unsafe funnel-disable argument list.");
      }
      run("tailscale", stage.arguments);
      return readback(stage, context, prepare);
    }
    case "sqlite-revoke-token-family": {
      const database = openFinalizationDatabase(stage, prepare);
      try {
        const transaction = database.transaction(() => {
          const familyId = requiredText(stage.familyId, "familyId");
          const family = database.prepare(
            "select status, connector_binding_id from oauth_token_families where family_id = ?",
          ).get(familyId);
          if (!family) throw new Error("Token family is absent from the prepared OAuth database.");
          const updated = database.prepare(
            "update oauth_token_families set status = 'REVOKED', revoked_at = coalesce(revoked_at, ?) where family_id = ? and status in ('ACTIVE', 'ROTATING')",
          ).run(new Date().toISOString(), familyId);
          if (updated.changes > 1) throw new Error("Token family update affected multiple rows.");
          if (updated.changes === 1 && family.connector_binding_id) {
            const released = database.prepare(
              "update oauth_connector_bindings set ref_count = ref_count - 1, updated_at = ? where binding_id = ? and ref_count > 0",
            ).run(new Date().toISOString(), family.connector_binding_id);
            if (released.changes !== 1) throw new Error("Connector reference could not be released with token-family revocation.");
          }
          database.prepare("delete from oauth_access_tokens where family_id = ?").run(familyId);
          database.prepare("delete from oauth_refresh_tokens where family_id = ?").run(familyId);
        });
        transaction.immediate();
      } finally { database.close(); }
      return sqliteFamilyReadback(stage);
    }
    case "sqlite-drain-connector": {
      const database = openFinalizationDatabase(stage, prepare);
      try {
        const expectedEpoch = requiredInteger(stage.expectedDrainEpoch, "expectedDrainEpoch");
        const retiredAt = new Date().toISOString();
        const reason = retirementReason(stage.retirementReason ?? "REFERENCE_ZERO");
        const bindingId = requiredText(stage.bindingId, "bindingId");
        const receiptId = requiredText(
          stage.retirementReceiptId ?? `connector-retirement-${createHash("sha256").update(`${bindingId}:${expectedEpoch}`).digest("hex").slice(0, 32)}`,
          "retirementReceiptId",
        );
        const result = database.prepare(
          `update oauth_connector_bindings
             set state = 'RETIRED', state_reason = ?, ref_count = 0,
                 drain_epoch = drain_epoch + 1, refresh_allowed_during_drain = 0, updated_at = ?
           where binding_id = ? and state = 'DRAINING' and ref_count = 0 and drain_epoch = ?`,
        ).run(reason, retiredAt, bindingId, expectedEpoch);
        if (result.changes !== 1) throw new Error("Connector binding is not eligible for zero-reference drain.");
        database.prepare(`
          insert into oauth_connector_retirement_receipts
            (receipt_id, binding_id, canonical_name, drain_epoch, reason, revoked_family_count, retired_at)
          select ?, binding_id, canonical_name, drain_epoch, ?, 0, ?
            from oauth_connector_bindings
           where binding_id = ? and state = 'RETIRED'
          on conflict(binding_id) do nothing
        `).run(receiptId, reason, retiredAt, bindingId);
      } finally { database.close(); }
      return sqliteConnectorReadback(stage);
    }
    case "verify-runtime":
    case "evidence-assert":
      return readback(stage, context, prepare);
    default:
      throw new Error(`Unsupported finalization stage operation: ${stage.operation}`);
  }
}

function sqliteFamilyReadback(stage) {
  const database = new Database(resolve(requiredText(stage.database, "database")), { readonly: true, fileMustExist: true });
  try {
    const familyId = requiredText(stage.familyId, "familyId");
    const family = database.prepare("select status, revoked_at from oauth_token_families where family_id = ?").get(familyId);
    const access = database.prepare("select count(*) as count from oauth_access_tokens where family_id = ?").get(familyId).count;
    const refresh = database.prepare("select count(*) as count from oauth_refresh_tokens where family_id = ?").get(familyId).count;
    const complete = family?.status === "REVOKED" && typeof family.revoked_at === "string" && access === 0 && refresh === 0;
    return { complete, evidence: { familyId, status: family?.status, accessTokens: access, refreshTokens: refresh } };
  } finally { database.close(); }
}

function sqliteConnectorReadback(stage) {
  const database = new Database(resolve(requiredText(stage.database, "database")), { readonly: true, fileMustExist: true });
  try {
    const expected = requiredInteger(stage.expectedDrainEpoch, "expectedDrainEpoch") + 1;
    const row = database.prepare("select state, ref_count, drain_epoch from oauth_connector_bindings where binding_id = ?")
      .get(requiredText(stage.bindingId, "bindingId"));
    const receipt = database.prepare(
      "select receipt_id, reason, drain_epoch from oauth_connector_retirement_receipts where binding_id = ?",
    ).get(requiredText(stage.bindingId, "bindingId"));
    return {
      complete: row?.state === "RETIRED"
        && row.ref_count === 0
        && row.drain_epoch === expected
        && Boolean(receipt?.receipt_id)
        && receipt.drain_epoch === expected,
      evidence: {
        bindingId: stage.bindingId,
        state: row?.state,
        refCount: row?.ref_count,
        drainEpoch: row?.drain_epoch,
        retirementReceiptId: receipt?.receipt_id,
        retirementReason: receipt?.reason,
        retirementReceiptDrainEpoch: receipt?.drain_epoch,
      },
    };
  } finally { database.close(); }
}

function openFinalizationDatabase(stage, prepare) {
  const path = resolve(requiredText(stage.database, "database"));
  const known = prepare.inventories.oauth.some((entry) => resolve(entry.database ?? "") === path);
  if (!known) throw new Error(`OAuth database is not in the prepared inventory: ${path}`);
  const database = new Database(path, { fileMustExist: true });
  database.pragma("busy_timeout = 5000");
  database.pragma("foreign_keys = ON");
  return database;
}

function validateTemporaryTarget(target, prepare) {
  const path = resolve(requiredText(target, "target"));
  const known = prepare.inventories.temporaryArtifacts.some((entry) => resolve(typeof entry === "string" ? entry : entry.path) === path);
  if (!known) throw new Error(`Removal target is not in the prepared temporary inventory: ${path}`);
}

function validatePreimageTarget(target, prepare) {
  const path = resolve(requiredText(target, "target"));
  if (!prepare.preimages.some((entry) => resolve(entry.target) === path)) throw new Error(`Replacement target has no prepared preimage: ${path}`);
}

function verifyPreimageIfPresent(target, prepare) {
  const path = resolve(target);
  const preimage = prepare.preimages.find((entry) => resolve(entry.target) === path);
  if (!preimage) return;
  const observed = existsSync(path) ? digestFile(path) : "ABSENT";
  if (observed !== preimage.sha256) throw new Error(`Finalization target changed after prepare: ${path}`);
}

function validateProcessTarget(target, prepare) {
  const name = requiredText(target, "target");
  if (!prepare.inventories.processes.some((entry) => entry.name === name)) throw new Error(`PM2 process is not in the prepared inventory: ${name}`);
}

function pm2Inventory() {
  const result = run("pm2", ["jlist"], true);
  const value = JSON.parse(result.stdout);
  return value.map((entry) => ({ name: entry.name, pid: entry.pid, status: entry.pm2_env?.status }));
}

function pm2SavedStateReadback(stage) {
  if (!Array.isArray(stage.expectedProcesses) || stage.expectedProcesses.length === 0) {
    throw new Error("pm2-save requires a non-empty expectedProcesses readback set.");
  }
  const dumpPath = resolve(stage.dumpFile ?? join(process.env.PM2_HOME ?? join(homedir(), ".pm2"), "dump.pm2"));
  if (!existsSync(dumpPath)) return { complete: false, evidence: { dumpPath, present: false } };
  const saved = JSON.parse(readFileSync(dumpPath, "utf8"));
  if (!Array.isArray(saved)) throw new Error(`PM2 saved-state file is invalid: ${dumpPath}`);
  const current = pm2InventoryDetails();
  const expected = stage.expectedProcesses.map(normalizeExpectedProcess);
  const savedProcesses = saved.map((entry) => normalizeProcess(entry, entry));
  const missingCurrent = expected.filter((entry) => !current.some((candidate) => sameProcess(entry, candidate)));
  const missingSaved = expected.filter((entry) => !savedProcesses.some((candidate) => sameProcess(entry, candidate)));
  return {
    complete: missingCurrent.length === 0 && missingSaved.length === 0,
    evidence: {
      dumpPath,
      dumpSha256: digestFile(dumpPath),
      expectedDigest: digestJson(expected),
      missingCurrent,
      missingSaved,
    },
  };
}

function pm2InventoryDetails() {
  const result = run("pm2", ["jlist"], true);
  const value = JSON.parse(result.stdout);
  if (!Array.isArray(value)) throw new Error("PM2 inventory is invalid.");
  return value.map((entry) => normalizeProcess(entry, entry.pm2_env ?? {}));
}

function normalizeExpectedProcess(entry) {
  if (!entry || typeof entry !== "object") throw new Error("pm2-save expected process entry is invalid.");
  return {
    name: requiredText(entry.name, "expectedProcesses.name"),
    cwd: resolve(requiredText(entry.cwd, "expectedProcesses.cwd")),
    script: resolve(requiredText(entry.script, "expectedProcesses.script")),
  };
}

function normalizeProcess(entry, environment) {
  return {
    name: String(entry.name ?? environment.name ?? ""),
    pid: Number(entry.pid ?? 0),
    status: String(environment.status ?? entry.status ?? ""),
    cwd: environment.pm_cwd ? resolve(environment.pm_cwd) : "",
    script: environment.pm_exec_path ? resolve(environment.pm_exec_path) : "",
  };
}

function sameProcess(expected, observed) {
  return expected.name === observed.name && expected.cwd === observed.cwd && expected.script === observed.script;
}

function curlJson(url) {
  const result = run("curl", ["--fail", "--silent", "--show-error", "--max-time", "10", url], true);
  return JSON.parse(result.stdout);
}

function commandJson(command, arguments_) {
  return JSON.parse(run(command, arguments_, true).stdout);
}

function run(command, arguments_, capture = false) {
  const result = spawnSync(command, arguments_, { encoding: "utf8", stdio: capture ? ["ignore", "pipe", "pipe"] : ["ignore", "pipe", "pipe"], timeout: 60_000 });
  if (result.status !== 0) throw new Error(`${command} failed with exit ${result.status}: ${result.stderr?.trim() ?? ""}`);
  return result;
}

function runtimeMismatches(expected, observed) {
  const identity = observed?.identity ?? observed;
  return ["sourceRevision", "runtimeRevision", "buildDigest", "schemaGeneration", "authorityContractGeneration", "configDigest"]
    .filter((key) => expected[key] !== identity?.[key]);
}

function writeFileAtomic(path, content, mode) {
  mkdirSync(dirname(path), { recursive: true, mode: 0o700 });
  const temporary = `${path}.tmp-${process.pid}`;
  const descriptor = openSync(temporary, "wx", mode);
  try { writeFileSync(descriptor, content); fsyncSync(descriptor); } finally { closeSync(descriptor); }
  chmodSync(temporary, mode);
  renameSync(temporary, path);
  fsyncDirectory(dirname(path));
}

function fsyncDirectory(path) {
  let descriptor;
  try { descriptor = openSync(path, "r"); fsyncSync(descriptor); }
  catch (error) { if (!new Set(["EINVAL", "ENOTSUP", "EISDIR", "EPERM"]).has(error?.code)) throw error; }
  finally { if (descriptor !== undefined) closeSync(descriptor); }
}

function digestFile(path) {
  return `sha256:${createHash("sha256").update(readFileSync(path)).digest("hex")}`;
}

function digestJson(value) {
  return `sha256:${createHash("sha256").update(canonicalJson(value)).digest("hex")}`;
}

function digestText(value) {
  return `sha256:${createHash("sha256").update(String(value)).digest("hex")}`;
}

function requiredText(value, name) {
  if (typeof value !== "string" || value.length === 0) throw new Error(`${name} is required.`);
  return value;
}

function compareCodeUnits(left, right) {
  return left < right ? -1 : left > right ? 1 : 0;
}

function requiredInteger(value, name) {
  if (!Number.isInteger(value) || value < 0) throw new Error(`${name} is invalid.`);
  return value;
}

function retirementReason(value) {
  if (!["REFERENCE_ZERO", "DEADLINE_ELAPSED"].includes(value)) throw new Error("retirementReason is invalid.");
  return value;
}

function requireDigest(value, name) {
  if (typeof value !== "string" || !/^sha256:[a-f0-9]{64}$/u.test(value)) throw new Error(`${name} is invalid.`);
  return value;
}

function requiredHttpUrl(value, name) {
  const text = requiredText(value, name);
  const parsed = new URL(text);
  if (!new Set(["http:", "https:"]).has(parsed.protocol) || parsed.username || parsed.password) {
    throw new Error(`${name} must be an HTTP(S) URL without embedded credentials.`);
  }
  return parsed.href;
}

function requiredAbsolutePath(value, name) {
  const text = requiredText(value, name);
  if (!isAbsolute(text)) throw new Error(`${name} must be absolute.`);
  return resolve(text);
}

function readOwnerOnlyJson(path, label) {
  const resolved = resolve(path);
  const metadata = lstatSync(resolved);
  if (!metadata.isFile() || metadata.isSymbolicLink() || (metadata.mode & 0o077) !== 0
    || (typeof process.getuid === "function" && metadata.uid !== process.getuid())) {
    throw new Error(`${label} must be an owner-only regular file.`);
  }
  return readJson(resolved);
}

function readJson(path) { return JSON.parse(readFileSync(resolve(path), "utf8")); }
function emit(value) { process.stdout.write(`${JSON.stringify(value)}\n`); }
