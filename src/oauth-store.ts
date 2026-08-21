import { createHash, randomUUID } from "node:crypto";
import type { OAuthRegisteredClientsStore } from "@modelcontextprotocol/sdk/server/auth/clients.js";
import { InvalidRequestError } from "@modelcontextprotocol/sdk/server/auth/errors.js";
import type { OAuthClientInformationFull } from "@modelcontextprotocol/sdk/shared/auth.js";
import { openDatabase, type DatabaseHandle } from "./db/client.js";
import type { UniversalBrokerMetrics } from "./v2/metrics.js";

export interface PersistedTokenBinding {
  familyId?: string;
  connectorBindingId?: string;
  connectorDrainEpoch?: number;
  installationEpoch?: number;
  rotationSequence?: number;
}

export interface PersistedAccessTokenRecord extends PersistedTokenBinding {
  clientId: string;
  scopes: string[];
  expiresAt: number;
  resource?: string;
}

export interface PersistedRefreshTokenRecord extends PersistedTokenBinding {
  clientId: string;
  scopes: string[];
  expiresAt: number;
  resource?: string;
}

export interface PersistedTokenPair {
  accessTokenHash: string;
  accessToken: PersistedAccessTokenRecord;
  refreshTokenHash: string;
  refreshToken: PersistedRefreshTokenRecord;
}

export const CONNECTOR_BINDING_STATES = [
  "REGISTERED",
  "CANDIDATE",
  "VERIFIED",
  "ACTIVATION_PREPARED",
  "ACTIVE",
  "DRAINING",
  "RETIRED",
  "REJECTED",
  "FAILED",
] as const;

export type ConnectorBindingState = typeof CONNECTOR_BINDING_STATES[number];

export type ConnectorReadinessInvalidState =
  | "ACTIVE_COUNT"
  | "VERIFICATION_IDENTITY_INCOMPLETE"
  | "ACTIVE_DRAIN_FIELDS_SET"
  | "DRAINING_DEADLINE_INVALID"
  | "DRAINING_DEADLINE_ELAPSED"
  | "REFERENCE_COUNT_UNDERFLOW"
  | "TERMINAL_REFERENCES_REMAIN"
  | "PREPARED_RECEIPT_MISMATCH"
  | "UNKNOWN_BINDING_STATE"
  | "CANONICAL_NAME_UNCONFIGURED";

export interface ConnectorReadinessSummary {
  state: "PASS" | "FAIL";
  activeCount: number;
  bindingsByState: Record<ConnectorBindingState, number>;
  invalidStates: ConnectorReadinessInvalidState[];
}

export interface PersonalConnectorExpectation {
  canonicalName: string;
  installationEpoch: number;
  schemaGeneration: string;
  resource: string;
}

export type PersonalConnectorReadinessInvalidState =
  | "CANONICAL_NAME_UNCONFIGURED"
  | "ACTIVE_COUNT"
  | "ACTIVE_EPOCH_MISMATCH"
  | "ACTIVE_SCHEMA_STALE"
  | "ACTIVE_SCHEMA_INVALID"
  | "ACTIVE_DRAIN_FIELDS_SET"
  | "ACTIVE_FAMILY_MISSING"
  | "ACTIVE_REFRESH_TOKEN_MISSING"
  | "ACTIVE_TOKEN_RESOURCE_MISMATCH"
  | "TOKEN_CLIENT_MISMATCH"
  | "DRAINING_DEADLINE_INVALID"
  | "DRAINING_DEADLINE_ELAPSED"
  | "REFERENCE_COUNT_MISMATCH"
  | "TERMINAL_REFERENCES_REMAIN"
  | "PREPARED_RECEIPT_RESIDUE"
  | "UNBOUND_ACTIVE_FAMILY"
  | "NON_ACTIVE_TOKEN_FAMILY"
  | "UNKNOWN_BINDING_STATE";

export interface PersonalConnectorReadinessSummary {
  state: "PASS" | "FAIL";
  activeCount: number;
  bindingsByState: Record<ConnectorBindingState, number>;
  invalidStates: PersonalConnectorReadinessInvalidState[];
  expectedInstallationEpoch?: number;
  activeInstallationEpoch?: number;
  activeSchemaGeneration?: string;
  activeBindingIdDigest?: string;
  activeClientIdDigest?: string;
  activeFamilyCount: number;
  activeRefreshTokenCount: number;
  activePersistedTokenCount: number;
  overdueDrainingCount: number;
  unboundActiveFamilyCount: number;
  nonActiveTokenFamilyCount: number;
  preparedReceiptCount: number;
}

export type PersonalConnectorReconciliationAction =
  | {
      kind: "UPDATE_ACTIVE_SCHEMA";
      bindingId: string;
      expectedInstallationEpoch: number;
      expectedSchemaGeneration: string;
      nextSchemaGeneration: string;
    }
  | {
      kind: "REVOKE_UNBOUND_FAMILY";
      familyId: string;
    }
  | {
      kind: "RETIRE_DRAINING_BINDING";
      bindingId: string;
      expectedDrainEpoch: number;
      reason: "REFERENCE_ZERO" | "DEADLINE_ELAPSED";
    }
  | {
      kind: "PURGE_TERMINAL_BINDING";
      bindingId: string;
      expectedState: "RETIRED" | "REJECTED" | "FAILED";
    };

export interface PersonalConnectorReconciliationPlan {
  schemaVersion: 1;
  planId: string;
  planDigest: string;
  preimageDigest: string;
  createdAt: string;
  expectation: PersonalConnectorExpectation;
  actions: readonly PersonalConnectorReconciliationAction[];
  blockers: readonly PersonalConnectorReadinessInvalidState[];
  readinessBefore: PersonalConnectorReadinessSummary;
}

export interface PersonalConnectorReconciliationResult {
  status: "APPLIED" | "NO_CHANGES";
  planId: string;
  planDigest: string;
  preimageDigest: string;
  postimageDigest: string;
  appliedAt: string;
  appliedActions: readonly PersonalConnectorReconciliationAction[];
  retirementReceipts: readonly ConnectorRetirementReceipt[];
  readinessAfter: PersonalConnectorReadinessSummary;
}

const DIGEST_PATTERN = /^sha256:[a-f0-9]{64}$/u;
const RAW_SHA256_PATTERN = /^[a-f0-9]{64}$/u;
const UUID_PATTERN = /^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/u;

export interface ConnectorBindingRecord {
  bindingId: string;
  canonicalName: string;
  clientId: string;
  installationEpoch: number;
  schemaGeneration: string;
  authorityContractGeneration?: string;
  redirectUrisDigest?: string;
  buildDigest?: string;
  drainEpoch: number;
  drainDeadlineAt?: string;
  refreshAllowedDuringDrain: boolean;
  state: ConnectorBindingState;
  stateReason?: string;
  refCount: number;
  createdAt: string;
  updatedAt: string;
}

export interface ConnectorRegistrationInput {
  canonicalName: string;
  clientId: string;
  installationEpoch: number;
  schemaGeneration: string;
}

export interface ConnectorVerificationEvidence {
  authorityContractGeneration: string;
  redirectUrisDigest: string;
  buildDigest: string;
}

export interface ConnectorActivationTuple extends ConnectorVerificationEvidence {
  canonicalName: string;
  candidateBindingId: string;
  clientId: string;
  installationEpoch: number;
  schemaGeneration: string;
}

export interface ConnectorActivationPlan {
  drainDeadlineAt: string;
  refreshAllowedDuringDrain: boolean;
}

export interface ConnectorActivationAuthorityBinding {
  receiptId: string;
  tupleDigest: string;
  activePreimageDigest: string;
  finalizationPlanDigest: string;
  canonicalName: string;
}

export interface ConnectorActivationAuthorityDescriptor {
  readonly tool: "context";
  readonly operation: "connector_activation_finalize";
  readonly target: string;
  readonly resource: string;
  readonly parameters: Readonly<ConnectorActivationAuthorityBinding>;
}

/**
 * Cross-store proof from the already-claimed owner-only internal R3 action.
 * It contains identifiers and digests only; no authority text, token, or raw evidence.
 */
export interface ConnectorActivationAuthorityProof extends ConnectorActivationAuthorityBinding {
  schemaVersion: 1;
  authorityId: string;
  actionClaimId: string;
  actionFingerprint: string;
  resourceKeySha256: string;
  fencingToken: number;
  principalKeyFingerprint: string;
  risk: "R3";
  claimState: "DISPATCHED";
  approvalAssurance: "cooperative";
  evidenceDigest: string;
  claimedAtMs: number;
  dispatchedAtMs: number;
}

export interface ConnectorActivationAuthorityReceipt extends ConnectorActivationAuthorityProof {
  proofDigest: string;
  consumedAt: string;
}

export function connectorActivationAuthorityDescriptor(
  binding: ConnectorActivationAuthorityBinding,
): ConnectorActivationAuthorityDescriptor {
  validateConnectorActivationAuthorityBinding(binding);
  return {
    tool: "context",
    operation: "connector_activation_finalize",
    target: binding.canonicalName,
    resource: `connector:${binding.canonicalName}`,
    parameters: {
      receiptId: binding.receiptId,
      tupleDigest: binding.tupleDigest,
      activePreimageDigest: binding.activePreimageDigest,
      finalizationPlanDigest: binding.finalizationPlanDigest,
      canonicalName: binding.canonicalName,
    },
  };
}

export function connectorActivationAuthorityActionFingerprint(
  binding: ConnectorActivationAuthorityBinding,
): string {
  return sha256Hex(stableJson(connectorActivationAuthorityDescriptor(binding)));
}

export function connectorActivationAuthorityResourceKeySha256(
  binding: ConnectorActivationAuthorityBinding,
): string {
  const descriptor = connectorActivationAuthorityDescriptor(binding);
  return sha256Hex(stableJson({
    tool: descriptor.tool,
    target: descriptor.target,
    resource: descriptor.resource,
    endpointGeneration: "unversioned-endpoint",
  }));
}

export type ConnectorActivationReceiptStatus = "PREPARED" | "ACTIVATED" | "FAILED";

export interface ConnectorActivationReceipt {
  receiptId: string;
  tuple: ConnectorActivationTuple;
  tupleDigest: string;
  previousActiveBindingId?: string;
  preimageDigest: string;
  activationAuthority?: ConnectorActivationAuthorityReceipt;
  /** Compatibility readback; equals activationAuthority.authorityId for v8 activations. */
  ownerAuthorityId?: string;
  drainDeadlineAt: string;
  refreshAllowedDuringDrain: boolean;
  status: ConnectorActivationReceiptStatus;
  failureCode?: string;
  preparedAt: string;
  activatedAt?: string;
  failedAt?: string;
}

export interface ConnectorRetirementReceipt {
  receiptId: string;
  bindingId: string;
  canonicalName: string;
  drainEpoch: number;
  reason: "REFERENCE_ZERO" | "DEADLINE_ELAPSED";
  revokedFamilyCount: number;
  retiredAt: string;
}

export interface ConnectorAuthenticationContext {
  bindingId: string;
  canonicalName: string;
  state: ConnectorBindingState;
  installationEpoch: number;
  rotationSequence: number;
  schemaGeneration: string;
  buildDigest?: string;
  drainDeadlineAt?: string;
  activationRequired: boolean;
}

export class ConnectorStateConflictError extends Error {
  readonly code = "CONNECTOR_STATE_CONFLICT";

  constructor(message: string) {
    super(message);
    this.name = "ConnectorStateConflictError";
  }
}

function redirectHostAllowed(redirectUri: string, allowedHosts: string[]): boolean {
  let parsed: URL;
  try {
    parsed = new URL(redirectUri);
  } catch {
    return false;
  }

  if (["localhost", "127.0.0.1", "[::1]"].includes(parsed.hostname)) return true;
  return allowedHosts.includes(parsed.hostname);
}

export class SqliteOAuthStore {
  private readonly database: DatabaseHandle;
  private readonly metrics?: UniversalBrokerMetrics;

  constructor(stateDir: string, metrics?: UniversalBrokerMetrics) {
    this.database = openDatabase(stateDir);
    this.metrics = metrics;
    this.deleteExpiredTokens(Math.floor(Date.now() / 1000));
  }

  getClient(clientId: string): OAuthClientInformationFull | undefined {
    const row = this.database.sqlite
      .prepare("select client_json from oauth_clients where client_id = ?")
      .get(clientId) as { client_json: string } | undefined;

    return row ? (JSON.parse(row.client_json) as OAuthClientInformationFull) : undefined;
  }

  registerClient(
    client: Omit<OAuthClientInformationFull, "client_id" | "client_id_issued_at">,
    allowedRedirectHosts: string[],
    connectorRegistration?: Omit<ConnectorRegistrationInput, "clientId">,
  ): OAuthClientInformationFull {
    if (!client.redirect_uris.every((uri) => redirectHostAllowed(String(uri), allowedRedirectHosts))) {
      throw new InvalidRequestError("Client redirect_uri is not allowed for this DevSpace server");
    }

    const now = Math.floor(Date.now() / 1000);
    const registered: OAuthClientInformationFull = {
      ...client,
      client_id: `devspace-${randomUUID()}`,
      client_id_issued_at: now,
      token_endpoint_auth_method: client.token_endpoint_auth_method ?? "none",
      grant_types: client.grant_types ?? ["authorization_code", "refresh_token"],
      response_types: client.response_types ?? ["code"],
    };

    let registeredBinding = false;
    const register = this.database.sqlite.transaction(() => {
      this.database.sqlite
        .prepare("insert into oauth_clients (client_id, client_json, issued_at) values (?, ?, ?)")
        .run(registered.client_id, JSON.stringify(registered), now);
      if (connectorRegistration) {
        const bindingInput = { ...connectorRegistration, clientId: registered.client_id };
        validateConnectorBindingInput(bindingInput);
        this.insertConnectorBinding(bindingInput, "REGISTERED");
        registeredBinding = true;
      }
      return registered;
    });
    const result = register.immediate();
    if (registeredBinding) this.recordConnectorTransition("NONE", "REGISTERED");
    return result;
  }

  registerConnectorBinding(input: ConnectorRegistrationInput): ConnectorBindingRecord {
    validateConnectorBindingInput(input);
    let inserted = false;
    const register = this.database.sqlite.transaction(() => {
      const existing = this.getConnectorBindingByIdentity(input);
      if (existing) {
        if (existing.clientId !== input.clientId || existing.schemaGeneration !== input.schemaGeneration) {
          throw new ConnectorStateConflictError("Connector installation epoch is already assigned to a different client or schema.");
        }
        return existing;
      }
      inserted = true;
      return this.insertConnectorBinding(input, "REGISTERED");
    });
    const result = register.immediate();
    if (inserted) this.recordConnectorTransition("NONE", "REGISTERED");
    return result;
  }

  ensureCandidateConnectorBinding(input: ConnectorRegistrationInput): ConnectorBindingRecord {
    validateConnectorBindingInput(input);
    let transitionFrom: ConnectorBindingState | "NONE" | undefined;
    const ensure = this.database.sqlite.transaction(() => {
      const existing = this.getConnectorBindingByIdentity(input);
      if (!existing) {
        transitionFrom = "NONE";
        return this.insertConnectorBinding(input, "CANDIDATE");
      }
      if (existing.clientId !== input.clientId || existing.schemaGeneration !== input.schemaGeneration) {
        throw new ConnectorStateConflictError("Connector installation epoch is already assigned to a different client or schema.");
      }
      if (existing.state === "REGISTERED") {
        const updated = this.database.sqlite.prepare(`
          update oauth_connector_bindings
             set state = 'CANDIDATE', state_reason = null, updated_at = ?
           where binding_id = ? and state = 'REGISTERED'
        `).run(new Date().toISOString(), existing.bindingId);
        if (updated.changes !== 1) throw new ConnectorStateConflictError("Connector registration changed concurrently.");
        transitionFrom = "REGISTERED";
        return this.getConnectorBinding(existing.bindingId)!;
      }
      if (["CANDIDATE", "VERIFIED", "ACTIVATION_PREPARED", "ACTIVE"].includes(existing.state)) return existing;
      throw new ConnectorStateConflictError(`Connector binding in ${existing.state} cannot issue a new token family.`);
    });
    const result = ensure.immediate();
    if (transitionFrom) this.recordConnectorTransition(transitionFrom, "CANDIDATE");
    return result;
  }

  markConnectorBindingVerified(
    bindingId: string,
    evidence: ConnectorVerificationEvidence,
  ): ConnectorBindingRecord {
    validateVerificationEvidence(evidence);
    let transitioned = false;
    const verify = this.database.sqlite.transaction(() => {
      const binding = this.getConnectorBinding(bindingId);
      if (!binding) throw new ConnectorStateConflictError("Connector candidate does not exist.");
      if (binding.state === "VERIFIED"
        && binding.authorityContractGeneration === evidence.authorityContractGeneration
        && binding.redirectUrisDigest === evidence.redirectUrisDigest
        && binding.buildDigest === evidence.buildDigest) return binding;
      if (binding.state !== "CANDIDATE") {
        throw new ConnectorStateConflictError(`Connector binding in ${binding.state} cannot be verified.`);
      }
      const updated = this.database.sqlite.prepare(`
        update oauth_connector_bindings
           set authority_contract_generation = ?, redirect_uris_digest = ?, build_digest = ?,
               state = 'VERIFIED', state_reason = null, updated_at = ?
         where binding_id = ? and state = 'CANDIDATE'
      `).run(
        evidence.authorityContractGeneration,
        evidence.redirectUrisDigest,
        evidence.buildDigest,
        new Date().toISOString(),
        bindingId,
      );
      if (updated.changes !== 1) throw new ConnectorStateConflictError("Connector candidate changed concurrently.");
      transitioned = true;
      return this.getConnectorBinding(bindingId)!;
    });
    const result = verify.immediate();
    if (transitioned) this.recordConnectorTransition("CANDIDATE", "VERIFIED");
    return result;
  }

  prepareConnectorActivation(
    tuple: ConnectorActivationTuple,
    plan: ConnectorActivationPlan,
  ): ConnectorActivationReceipt {
    validateActivationTuple(tuple);
    validateActivationPlan(plan);
    let transitioned = false;
    const prepare = this.database.sqlite.transaction(() => {
      const candidate = this.getConnectorBinding(tuple.candidateBindingId);
      if (!candidate || !bindingMatchesTuple(candidate, tuple)) {
        throw new ConnectorStateConflictError("Connector activation tuple does not match the persisted candidate.");
      }
      const existing = this.getPreparedActivationReceipt(tuple.canonicalName);
      if (existing) {
        if (existing.tupleDigest === connectorActivationTupleDigest(tuple)
          && existing.drainDeadlineAt === plan.drainDeadlineAt
          && existing.refreshAllowedDuringDrain === plan.refreshAllowedDuringDrain) return existing;
        throw new ConnectorStateConflictError("A different activation tuple is already prepared for this connector.");
      }
      if (candidate.state !== "VERIFIED") {
        throw new ConnectorStateConflictError(`Connector binding in ${candidate.state} cannot prepare activation.`);
      }

      const previousActive = this.getActiveConnectorBinding(tuple.canonicalName);
      const preimageJson = connectorPreimageJson(previousActive);
      const preparedAt = new Date().toISOString();
      const receiptId = `connector-activation-${randomUUID()}`;
      const tupleJson = activationTupleJson(tuple);
      this.database.sqlite.prepare(`
        insert into oauth_connector_activation_receipts
          (receipt_id, canonical_name, candidate_binding_id, client_id, installation_epoch,
           schema_generation, authority_contract_generation, redirect_uris_digest, build_digest,
           tuple_digest, preimage_json, preimage_digest, previous_active_binding_id,
           drain_deadline_at, refresh_allowed_during_drain, status, prepared_at)
        values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'PREPARED', ?)
      `).run(
        receiptId,
        tuple.canonicalName,
        tuple.candidateBindingId,
        tuple.clientId,
        tuple.installationEpoch,
        tuple.schemaGeneration,
        tuple.authorityContractGeneration,
        tuple.redirectUrisDigest,
        tuple.buildDigest,
        sha256Digest(tupleJson),
        preimageJson,
        sha256Digest(preimageJson),
        previousActive?.bindingId ?? null,
        plan.drainDeadlineAt,
        plan.refreshAllowedDuringDrain ? 1 : 0,
        preparedAt,
      );
      const updated = this.database.sqlite.prepare(`
        update oauth_connector_bindings
           set state = 'ACTIVATION_PREPARED', state_reason = ?, updated_at = ?
         where binding_id = ? and state = 'VERIFIED'
      `).run(receiptId, preparedAt, candidate.bindingId);
      if (updated.changes !== 1) throw new ConnectorStateConflictError("Connector candidate changed concurrently.");
      transitioned = true;
      return this.getActivationReceipt(receiptId)!;
    });
    const result = prepare.immediate();
    if (transitioned) this.recordConnectorTransition("VERIFIED", "ACTIVATION_PREPARED");
    return result;
  }

  activatePreparedConnector(
    receiptId: string,
    tuple: ConnectorActivationTuple,
    authorityProof: ConnectorActivationAuthorityProof,
  ): ConnectorActivationReceipt {
    validateActivationTuple(tuple);
    validateConnectorActivationAuthorityProof(authorityProof);
    let previousDrained = false;
    let candidateActivated = false;
    const activate = this.database.sqlite.transaction(() => {
      const receipt = this.getActivationReceipt(receiptId);
      if (!receipt) throw new ConnectorStateConflictError("Connector activation receipt does not exist.");
      if (receipt.tupleDigest !== connectorActivationTupleDigest(tuple)) {
        throw new ConnectorStateConflictError("Connector activation tuple changed after preparation.");
      }
      if (receipt.status === "ACTIVATED") {
        throw new ConnectorStateConflictError(
          "Connector activation authority was already consumed; reconcile from the persisted activation receipt.",
        );
      }
      if (receipt.status !== "PREPARED") {
        throw new ConnectorStateConflictError(`Connector activation receipt is ${receipt.status}.`);
      }
      assertConnectorActivationAuthorityMatchesReceipt(authorityProof, receipt);
      const candidate = this.getConnectorBinding(tuple.candidateBindingId);
      if (!candidate || candidate.state !== "ACTIVATION_PREPARED" || !bindingMatchesTuple(candidate, tuple)) {
        throw new ConnectorStateConflictError("Prepared connector candidate no longer matches the activation tuple.");
      }
      const current = this.getActiveConnectorBinding(tuple.canonicalName);
      if ((current?.bindingId ?? undefined) !== receipt.previousActiveBindingId) {
        throw new ConnectorStateConflictError("Canonical ACTIVE binding changed after activation preparation.");
      }
      if (sha256Digest(connectorPreimageJson(current)) !== receipt.preimageDigest) {
        throw new ConnectorStateConflictError("Canonical ACTIVE preimage changed after activation preparation.");
      }

      const activatedAt = new Date().toISOString();
      const proofDigest = connectorActivationAuthorityProofDigest(authorityProof);
      try {
        const consumed = this.database.sqlite.prepare(`
          insert into oauth_connector_activation_authorities
            (action_claim_id, receipt_id, authority_id, principal_key_fingerprint,
             action_fingerprint, resource_key_sha256, fencing_token, risk, claim_state,
             approval_assurance, canonical_name, tuple_digest, active_preimage_digest,
             finalization_plan_digest, evidence_digest, claimed_at_ms, dispatched_at_ms,
             proof_digest, consumed_at)
          values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        `).run(
          authorityProof.actionClaimId,
          receiptId,
          authorityProof.authorityId,
          authorityProof.principalKeyFingerprint,
          authorityProof.actionFingerprint,
          authorityProof.resourceKeySha256,
          authorityProof.fencingToken,
          authorityProof.risk,
          authorityProof.claimState,
          authorityProof.approvalAssurance,
          authorityProof.canonicalName,
          authorityProof.tupleDigest,
          authorityProof.activePreimageDigest,
          authorityProof.finalizationPlanDigest,
          authorityProof.evidenceDigest,
          authorityProof.claimedAtMs,
          authorityProof.dispatchedAtMs,
          proofDigest,
          activatedAt,
        );
        if (consumed.changes !== 1) {
          throw new ConnectorStateConflictError("Connector activation authority could not be atomically consumed.");
        }
      } catch (error) {
        if (isSqliteConstraintError(error)) {
          throw new ConnectorStateConflictError(
            "Connector activation authority proof was already consumed or conflicts with persisted evidence.",
          );
        }
        throw error;
      }
      if (current) {
        const drained = this.database.sqlite.prepare(`
          update oauth_connector_bindings
             set state = 'DRAINING', state_reason = ?, drain_deadline_at = ?,
                 refresh_allowed_during_drain = ?, updated_at = ?
           where binding_id = ? and state = 'ACTIVE' and drain_epoch = ?
        `).run(
          receiptId,
          receipt.drainDeadlineAt,
          receipt.refreshAllowedDuringDrain ? 1 : 0,
          activatedAt,
          current.bindingId,
          current.drainEpoch,
        );
        if (drained.changes !== 1) throw new ConnectorStateConflictError("Canonical ACTIVE binding changed concurrently.");
        previousDrained = true;
      }
      const promoted = this.database.sqlite.prepare(`
        update oauth_connector_bindings
           set state = 'ACTIVE', state_reason = ?, drain_deadline_at = null,
               refresh_allowed_during_drain = 0, updated_at = ?
         where binding_id = ? and state = 'ACTIVATION_PREPARED'
      `).run(receiptId, activatedAt, candidate.bindingId);
      if (promoted.changes !== 1) throw new ConnectorStateConflictError("Prepared connector changed concurrently.");
      candidateActivated = true;
      const sealed = this.database.sqlite.prepare(`
        update oauth_connector_activation_receipts
           set status = 'ACTIVATED', owner_authority_id = ?, activated_at = ?
         where receipt_id = ? and status = 'PREPARED'
      `).run(authorityProof.authorityId, activatedAt, receiptId);
      if (sealed.changes !== 1) throw new ConnectorStateConflictError("Connector activation receipt changed concurrently.");
      return this.getActivationReceipt(receiptId)!;
    });
    const result = activate.immediate();
    if (previousDrained) this.recordConnectorTransition("ACTIVE", "DRAINING");
    if (candidateActivated) this.recordConnectorTransition("ACTIVATION_PREPARED", "ACTIVE");
    return result;
  }

  rejectConnectorBinding(bindingId: string, reason: string): ConnectorBindingRecord {
    validateStateReason(reason);
    let transitionFrom: ConnectorBindingState | undefined;
    const reject = this.database.sqlite.transaction(() => {
      const binding = this.getConnectorBinding(bindingId);
      if (!binding) throw new ConnectorStateConflictError("Connector binding does not exist.");
      if (binding.state === "REJECTED" && binding.stateReason === reason) return binding;
      if (!["CANDIDATE", "VERIFIED"].includes(binding.state)) {
        throw new ConnectorStateConflictError("Connector binding cannot be rejected from its current state.");
      }
      const rejectedAt = new Date().toISOString();
      this.revokeBindingTokenFamilies(bindingId, rejectedAt);
      const rejected = this.database.sqlite.prepare(`
        update oauth_connector_bindings
           set state = 'REJECTED', state_reason = ?, ref_count = 0, updated_at = ?
         where binding_id = ? and state in ('CANDIDATE', 'VERIFIED')
      `).run(reason, rejectedAt, bindingId);
      if (rejected.changes !== 1) throw new ConnectorStateConflictError("Connector binding changed concurrently.");
      transitionFrom = binding.state;
      return this.getConnectorBinding(bindingId)!;
    });
    const result = reject.immediate();
    if (transitionFrom) this.recordConnectorTransition(transitionFrom, "REJECTED");
    return result;
  }

  failPreparedConnectorActivation(receiptId: string, failureCode: string): ConnectorActivationReceipt {
    validateStateReason(failureCode);
    let transitioned = false;
    const fail = this.database.sqlite.transaction(() => {
      const receipt = this.getActivationReceipt(receiptId);
      if (!receipt) throw new ConnectorStateConflictError("Connector activation receipt does not exist.");
      if (receipt.status === "FAILED" && receipt.failureCode === failureCode) return receipt;
      if (receipt.status !== "PREPARED") {
        throw new ConnectorStateConflictError(`Connector activation receipt is ${receipt.status}.`);
      }
      const failedAt = new Date().toISOString();
      this.revokeBindingTokenFamilies(receipt.tuple.candidateBindingId, failedAt);
      const binding = this.database.sqlite.prepare(`
        update oauth_connector_bindings
           set state = 'FAILED', state_reason = ?, ref_count = 0, updated_at = ?
         where binding_id = ? and state = 'ACTIVATION_PREPARED'
      `).run(failureCode, failedAt, receipt.tuple.candidateBindingId);
      if (binding.changes !== 1) throw new ConnectorStateConflictError("Prepared connector changed concurrently.");
      const result = this.database.sqlite.prepare(`
        update oauth_connector_activation_receipts
           set status = 'FAILED', failure_code = ?, failed_at = ?
         where receipt_id = ? and status = 'PREPARED'
      `).run(failureCode, failedAt, receiptId);
      if (result.changes !== 1) throw new ConnectorStateConflictError("Connector activation receipt changed concurrently.");
      transitioned = true;
      return this.getActivationReceipt(receiptId)!;
    });
    const result = fail.immediate();
    if (transitioned) this.recordConnectorTransition("ACTIVATION_PREPARED", "FAILED");
    return result;
  }

  getActiveConnectorBinding(canonicalName: string): ConnectorBindingRecord | undefined {
    const row = this.database.sqlite.prepare(
      `select ${CONNECTOR_BINDING_COLUMNS}
         from oauth_connector_bindings where canonical_name = ? and state = 'ACTIVE'`,
    ).get(canonicalName) as ConnectorBindingRow | undefined;
    return row ? rowToConnectorBinding(row) : undefined;
  }

  getConnectorBinding(bindingId: string): ConnectorBindingRecord | undefined {
    const row = this.database.sqlite.prepare(
      `select ${CONNECTOR_BINDING_COLUMNS}
         from oauth_connector_bindings where binding_id = ?`,
    ).get(bindingId) as ConnectorBindingRow | undefined;
    return row ? rowToConnectorBinding(row) : undefined;
  }

  getConnectorBindingForClient(canonicalName: string, clientId: string): ConnectorBindingRecord | undefined {
    const row = this.database.sqlite.prepare(`
      select ${CONNECTOR_BINDING_COLUMNS}
        from oauth_connector_bindings
       where canonical_name = ? and client_id = ?
       order by installation_epoch desc, created_at desc limit 1
    `).get(canonicalName, clientId) as ConnectorBindingRow | undefined;
    return row ? rowToConnectorBinding(row) : undefined;
  }

  connectorReadiness(canonicalName?: string, nowMs = Date.now()): ConnectorReadinessSummary {
    const bindingsByState = emptyConnectorBindingCounts();
    if (!canonicalName) {
      return {
        state: "FAIL",
        activeCount: 0,
        bindingsByState,
        invalidStates: ["CANONICAL_NAME_UNCONFIGURED"],
      };
    }
    const invalidStates = new Set<ConnectorReadinessInvalidState>();
    const rows = this.database.sqlite.prepare(`
      select binding_id, canonical_name, client_id, installation_epoch, state,
             schema_generation, authority_contract_generation, redirect_uris_digest, build_digest,
             drain_deadline_at, refresh_allowed_during_drain, ref_count,
             (select count(*) from oauth_token_families as family
               where family.connector_binding_id = binding.binding_id and family.status <> 'REVOKED')
               as active_family_count,
             ((select count(*) from oauth_access_tokens as access_token
                 where access_token.connector_binding_id = binding.binding_id)
               + (select count(*) from oauth_refresh_tokens as refresh_token
                   where refresh_token.connector_binding_id = binding.binding_id)) as persisted_token_count,
             (select count(*) from oauth_connector_activation_receipts as receipt
               where receipt.candidate_binding_id = binding.binding_id
                 and receipt.status = 'PREPARED') as prepared_receipt_count,
             (select count(*) from oauth_connector_activation_receipts as receipt
                where receipt.candidate_binding_id = binding.binding_id
                  and receipt.canonical_name = binding.canonical_name
                  and receipt.client_id = binding.client_id
                  and receipt.installation_epoch = binding.installation_epoch
                  and receipt.schema_generation = binding.schema_generation
                  and receipt.authority_contract_generation = binding.authority_contract_generation
                  and receipt.redirect_uris_digest = binding.redirect_uris_digest
                  and receipt.build_digest = binding.build_digest
                  and receipt.status = 'PREPARED') as prepared_receipt_identity_match_count,
             (select tuple_digest from oauth_connector_activation_receipts as receipt
               where receipt.candidate_binding_id = binding.binding_id and receipt.status = 'PREPARED'
               order by receipt_id limit 1) as prepared_tuple_digest,
             (select count(*) from oauth_connector_activation_receipts as receipt
               where receipt.canonical_name = binding.canonical_name and receipt.status = 'PREPARED')
               as canonical_prepared_receipt_count
        from oauth_connector_bindings as binding
       where canonical_name = ?
       order by installation_epoch, binding_id
    `).all(canonicalName) as ConnectorReadinessRow[];

    for (const row of rows) {
      if (!isConnectorBindingState(row.state)) {
        invalidStates.add("UNKNOWN_BINDING_STATE");
        continue;
      }
      bindingsByState[row.state] += 1;
      if (["VERIFIED", "ACTIVATION_PREPARED", "ACTIVE", "DRAINING"].includes(row.state)
        && !connectorVerificationIdentityIsComplete(row)) {
        invalidStates.add("VERIFICATION_IDENTITY_INCOMPLETE");
      }
      if (row.state === "ACTIVE" && (row.drain_deadline_at !== null || row.refresh_allowed_during_drain !== 0)) {
        invalidStates.add("ACTIVE_DRAIN_FIELDS_SET");
      }
      if (row.state === "DRAINING") {
        const deadlineMs = row.drain_deadline_at === null ? Number.NaN : Date.parse(row.drain_deadline_at);
        if (!Number.isFinite(deadlineMs)) invalidStates.add("DRAINING_DEADLINE_INVALID");
        else if (nowMs >= deadlineMs) invalidStates.add("DRAINING_DEADLINE_ELAPSED");
      }
      if (row.active_family_count > row.ref_count) invalidStates.add("REFERENCE_COUNT_UNDERFLOW");
      if (["RETIRED", "REJECTED", "FAILED"].includes(row.state)
        && (row.ref_count !== 0 || row.active_family_count !== 0 || row.persisted_token_count !== 0)) {
        invalidStates.add("TERMINAL_REFERENCES_REMAIN");
      }
      if (row.state === "ACTIVATION_PREPARED"
        ? !preparedReceiptMatchesBinding(row)
        : row.prepared_receipt_count !== 0) {
        invalidStates.add("PREPARED_RECEIPT_MISMATCH");
      }
    }

    if ((rows[0]?.canonical_prepared_receipt_count ?? 0) !== bindingsByState.ACTIVATION_PREPARED) {
      invalidStates.add("PREPARED_RECEIPT_MISMATCH");
    }

    const activeCount = bindingsByState.ACTIVE;
    if (activeCount !== 1) invalidStates.add("ACTIVE_COUNT");
    const orderedInvalidStates = CONNECTOR_READINESS_INVALID_STATE_ORDER.filter((state) => invalidStates.has(state));
    return {
      state: orderedInvalidStates.length === 0 ? "PASS" : "FAIL",
      activeCount,
      bindingsByState,
      invalidStates: orderedInvalidStates,
    };
  }

  personalConnectorReadiness(
    expectation: PersonalConnectorExpectation | undefined,
    nowMs = Date.now(),
  ): PersonalConnectorReadinessSummary {
    const bindingsByState = emptyConnectorBindingCounts();
    const empty = (invalidStates: PersonalConnectorReadinessInvalidState[]): PersonalConnectorReadinessSummary => ({
      state: "FAIL",
      activeCount: 0,
      bindingsByState,
      invalidStates,
      ...(expectation ? { expectedInstallationEpoch: expectation.installationEpoch } : {}),
      activeFamilyCount: 0,
      activeRefreshTokenCount: 0,
      activePersistedTokenCount: 0,
      overdueDrainingCount: 0,
      unboundActiveFamilyCount: 0,
      nonActiveTokenFamilyCount: 0,
      preparedReceiptCount: 0,
    });
    if (!expectation?.canonicalName) return empty(["CANONICAL_NAME_UNCONFIGURED"]);
    validatePersonalConnectorExpectation(expectation);

    const rows = this.database.sqlite.prepare(`
      select binding_id, canonical_name, client_id, installation_epoch, state,
             schema_generation, drain_deadline_at, refresh_allowed_during_drain, ref_count,
             (select count(*) from oauth_token_families as family
               where family.connector_binding_id = binding.binding_id and family.status <> 'REVOKED')
               as active_family_count,
             (select count(*) from oauth_refresh_tokens as refresh_token
               where refresh_token.connector_binding_id = binding.binding_id)
               as persisted_refresh_token_count,
             ((select count(*) from oauth_access_tokens as access_token
                 where access_token.connector_binding_id = binding.binding_id)
               + (select count(*) from oauth_refresh_tokens as refresh_token
                   where refresh_token.connector_binding_id = binding.binding_id))
               as persisted_token_count,
             ((select count(*) from oauth_access_tokens as access_token
                 where access_token.connector_binding_id = binding.binding_id
                   and (access_token.resource is null or access_token.resource <> ?))
               + (select count(*) from oauth_refresh_tokens as refresh_token
                   where refresh_token.connector_binding_id = binding.binding_id
                     and (refresh_token.resource is null or refresh_token.resource <> ?)))
               as resource_mismatch_count,
             ((select count(*) from oauth_access_tokens as access_token
                 where access_token.connector_binding_id = binding.binding_id
                   and access_token.client_id <> binding.client_id)
               + (select count(*) from oauth_refresh_tokens as refresh_token
                   where refresh_token.connector_binding_id = binding.binding_id
                     and refresh_token.client_id <> binding.client_id)
               + (select count(*) from oauth_token_families as family
                   where family.connector_binding_id = binding.binding_id
                     and family.status <> 'REVOKED'
                     and family.client_id <> binding.client_id))
               as client_mismatch_count
        from oauth_connector_bindings as binding
       where canonical_name = ?
       order by installation_epoch, binding_id
    `).all(
      expectation.resource,
      expectation.resource,
      expectation.canonicalName,
    ) as PersonalConnectorReadinessRow[];
    const invalidStates = new Set<PersonalConnectorReadinessInvalidState>();
    let activeRow: PersonalConnectorReadinessRow | undefined;
    let overdueDrainingCount = 0;
    for (const row of rows) {
      if (!isConnectorBindingState(row.state)) {
        invalidStates.add("UNKNOWN_BINDING_STATE");
        continue;
      }
      bindingsByState[row.state] += 1;
      if (row.ref_count !== row.active_family_count) invalidStates.add("REFERENCE_COUNT_MISMATCH");
      if (row.client_mismatch_count !== 0) invalidStates.add("TOKEN_CLIENT_MISMATCH");
      if (row.state === "ACTIVE") {
        activeRow = row;
        if (row.drain_deadline_at !== null || row.refresh_allowed_during_drain !== 0) {
          invalidStates.add("ACTIVE_DRAIN_FIELDS_SET");
        }
      }
      if (row.state === "DRAINING") {
        const deadlineMs = row.drain_deadline_at === null ? Number.NaN : Date.parse(row.drain_deadline_at);
        if (!Number.isFinite(deadlineMs)) invalidStates.add("DRAINING_DEADLINE_INVALID");
        else if (nowMs >= deadlineMs) {
          invalidStates.add("DRAINING_DEADLINE_ELAPSED");
          overdueDrainingCount += 1;
        }
      }
      if (["RETIRED", "REJECTED", "FAILED"].includes(row.state)
        && (row.ref_count !== 0 || row.active_family_count !== 0 || row.persisted_token_count !== 0)) {
        invalidStates.add("TERMINAL_REFERENCES_REMAIN");
      }
    }

    const activeCount = bindingsByState.ACTIVE;
    if (activeCount !== 1) invalidStates.add("ACTIVE_COUNT");
    if (activeCount === 1 && activeRow) {
      if (activeRow.installation_epoch !== expectation.installationEpoch) {
        invalidStates.add("ACTIVE_EPOCH_MISMATCH");
      }
      if (activeRow.schema_generation !== expectation.schemaGeneration) {
        invalidStates.add("ACTIVE_SCHEMA_STALE");
      }
      if (!DIGEST_PATTERN.test(activeRow.schema_generation)) {
        invalidStates.add("ACTIVE_SCHEMA_INVALID");
      }
      if (activeRow.active_family_count < 1) invalidStates.add("ACTIVE_FAMILY_MISSING");
      if (activeRow.persisted_refresh_token_count < activeRow.active_family_count) {
        invalidStates.add("ACTIVE_REFRESH_TOKEN_MISSING");
      }
      if (activeRow.resource_mismatch_count !== 0) {
        invalidStates.add("ACTIVE_TOKEN_RESOURCE_MISMATCH");
      }
    }

    const unboundActiveFamilyCount = Number(this.database.sqlite.prepare(`
      select count(*) from oauth_token_families
       where connector_binding_id is null and status <> 'REVOKED'
    `).pluck().get());
    if (unboundActiveFamilyCount > 0) invalidStates.add("UNBOUND_ACTIVE_FAMILY");
    const nonActiveTokenFamilyCount = Number(this.database.sqlite.prepare(`
      select count(*)
        from oauth_token_families as family
        join oauth_connector_bindings as binding on binding.binding_id = family.connector_binding_id
       where binding.canonical_name = ?
         and family.status <> 'REVOKED'
         and binding.state not in ('ACTIVE', 'DRAINING')
    `).pluck().get(expectation.canonicalName));
    if (nonActiveTokenFamilyCount > 0) invalidStates.add("NON_ACTIVE_TOKEN_FAMILY");
    const preparedReceiptCount = Number(this.database.sqlite.prepare(`
      select count(*) from oauth_connector_activation_receipts
       where canonical_name = ? and status = 'PREPARED'
    `).pluck().get(expectation.canonicalName));
    if (preparedReceiptCount > 0) invalidStates.add("PREPARED_RECEIPT_RESIDUE");

    const orderedInvalidStates = PERSONAL_CONNECTOR_READINESS_INVALID_STATE_ORDER
      .filter((state) => invalidStates.has(state));
    return {
      state: orderedInvalidStates.length === 0 ? "PASS" : "FAIL",
      activeCount,
      bindingsByState,
      invalidStates: orderedInvalidStates,
      expectedInstallationEpoch: expectation.installationEpoch,
      ...(activeRow ? {
        activeInstallationEpoch: activeRow.installation_epoch,
        activeSchemaGeneration: activeRow.schema_generation,
        activeBindingIdDigest: sha256Digest(activeRow.binding_id),
        activeClientIdDigest: sha256Digest(activeRow.client_id),
      } : {}),
      activeFamilyCount: activeRow?.active_family_count ?? 0,
      activeRefreshTokenCount: activeRow?.persisted_refresh_token_count ?? 0,
      activePersistedTokenCount: activeRow?.persisted_token_count ?? 0,
      overdueDrainingCount,
      unboundActiveFamilyCount,
      nonActiveTokenFamilyCount,
      preparedReceiptCount,
    };
  }

  planPersonalConnectorReconciliation(
    expectation: PersonalConnectorExpectation,
    nowMs = Date.now(),
  ): PersonalConnectorReconciliationPlan {
    validatePersonalConnectorExpectation(expectation);
    const createdAt = new Date(nowMs).toISOString();
    const snapshot = this.personalConnectorReconciliationSnapshot(expectation.canonicalName);
    const preimageDigest = sha256Digest(stableJson(snapshot));
    const readinessBefore = this.personalConnectorReadiness(expectation, nowMs);
    const actions: PersonalConnectorReconciliationAction[] = [];

    const activeBinding = snapshot.bindings.find((binding) => binding.state === "ACTIVE");
    if (activeBinding
      && activeBinding.installationEpoch === expectation.installationEpoch
      && activeBinding.schemaGeneration !== expectation.schemaGeneration) {
      actions.push({
        kind: "UPDATE_ACTIVE_SCHEMA",
        bindingId: activeBinding.bindingId,
        expectedInstallationEpoch: activeBinding.installationEpoch,
        expectedSchemaGeneration: activeBinding.schemaGeneration,
        nextSchemaGeneration: expectation.schemaGeneration,
      });
    }

    for (const family of snapshot.families) {
      if (family.connectorBindingId === null && family.status !== "REVOKED") {
        actions.push({ kind: "REVOKE_UNBOUND_FAMILY", familyId: family.familyId });
      }
    }
    for (const binding of snapshot.bindings) {
      if (binding.state === "DRAINING") {
        const deadlineMs = binding.drainDeadlineAt === null
          ? Number.NaN
          : Date.parse(binding.drainDeadlineAt);
        if (Number.isFinite(deadlineMs)
          && binding.refCount === binding.activeFamilyCount
          && (binding.refCount === 0 || nowMs >= deadlineMs)) {
          actions.push({
            kind: "RETIRE_DRAINING_BINDING",
            bindingId: binding.bindingId,
            expectedDrainEpoch: binding.drainEpoch,
            reason: nowMs >= deadlineMs ? "DEADLINE_ELAPSED" : "REFERENCE_ZERO",
          });
        }
      } else if (["RETIRED", "REJECTED", "FAILED"].includes(binding.state)
        && binding.refCount === binding.activeFamilyCount
        && (binding.refCount > 0 || binding.persistedTokenCount > 0)) {
        actions.push({
          kind: "PURGE_TERMINAL_BINDING",
          bindingId: binding.bindingId,
          expectedState: binding.state as "RETIRED" | "REJECTED" | "FAILED",
        });
      }
    }
    actions.sort((left, right) => reconciliationActionIdentity(left)
      .localeCompare(reconciliationActionIdentity(right)));

    const terminalBindingIds = new Set(snapshot.bindings
      .filter((binding) => ["RETIRED", "REJECTED", "FAILED"].includes(binding.state))
      .map((binding) => binding.bindingId));
    const nonActiveFamiliesAreTerminal = snapshot.families
      .filter((family) => family.status !== "REVOKED" && family.connectorBindingId !== null)
      .filter((family) => {
        const binding = snapshot.bindings.find((candidate) => candidate.bindingId === family.connectorBindingId);
        return binding && !["ACTIVE", "DRAINING"].includes(binding.state);
      })
      .every((family) => terminalBindingIds.has(family.connectorBindingId!));
    const reconcilable = new Set<PersonalConnectorReadinessInvalidState>([
      ...(actions.some((action) => action.kind === "UPDATE_ACTIVE_SCHEMA")
        ? ["ACTIVE_SCHEMA_STALE" as const]
        : []),
      "DRAINING_DEADLINE_ELAPSED",
      "TERMINAL_REFERENCES_REMAIN",
      "UNBOUND_ACTIVE_FAMILY",
      ...(nonActiveFamiliesAreTerminal ? ["NON_ACTIVE_TOKEN_FAMILY" as const] : []),
    ]);
    const blockers = readinessBefore.invalidStates.filter((state) => !reconcilable.has(state));
    const unsigned = {
      schemaVersion: 1 as const,
      planId: `personal-connector-reconcile-${sha256Hex(stableJson({
        expectation,
        preimageDigest,
      })).slice(0, 32)}`,
      preimageDigest,
      createdAt,
      expectation: { ...expectation },
      actions,
      blockers,
      readinessBefore,
    };
    return Object.freeze({
      ...unsigned,
      planDigest: sha256Digest(stableJson(unsigned)),
    });
  }

  applyPersonalConnectorReconciliation(
    plan: PersonalConnectorReconciliationPlan,
    nowMs = Date.now(),
  ): PersonalConnectorReconciliationResult {
    validatePersonalConnectorReconciliationPlan(plan);
    if (plan.blockers.length > 0) {
      throw new ConnectorStateConflictError(
        `Personal connector reconciliation is blocked: ${plan.blockers.join(", ")}`,
      );
    }
    const currentSnapshot = this.personalConnectorReconciliationSnapshot(
      plan.expectation.canonicalName,
    );
    const currentPreimageDigest = sha256Digest(stableJson(currentSnapshot));
    if (currentPreimageDigest !== plan.preimageDigest) {
      throw new ConnectorStateConflictError(
        "Personal connector reconciliation preimage changed after planning.",
      );
    }
    const appliedAt = new Date(nowMs).toISOString();
    const retirementReceipts: ConnectorRetirementReceipt[] = [];
    let retiredCount = 0;
    const apply = this.database.sqlite.transaction(() => {
      for (const action of plan.actions) {
        if (action.kind === "UPDATE_ACTIVE_SCHEMA") {
          const updated = this.database.sqlite.prepare(`
            update oauth_connector_bindings
               set schema_generation = ?, updated_at = ?
             where binding_id = ? and state = 'ACTIVE'
               and installation_epoch = ? and schema_generation = ?
               and drain_deadline_at is null and refresh_allowed_during_drain = 0
          `).run(
            action.nextSchemaGeneration,
            appliedAt,
            action.bindingId,
            action.expectedInstallationEpoch,
            action.expectedSchemaGeneration,
          );
          if (updated.changes !== 1) {
            throw new ConnectorStateConflictError(
              "Planned ACTIVE connector schema generation changed concurrently.",
            );
          }
          continue;
        }
        if (action.kind === "REVOKE_UNBOUND_FAMILY") {
          const family = this.database.sqlite.prepare(`
            select connector_binding_id, status from oauth_token_families where family_id = ?
          `).get(action.familyId) as {
            connector_binding_id: string | null;
            status: string;
          } | undefined;
          if (!family || family.connector_binding_id !== null || family.status === "REVOKED") {
            throw new ConnectorStateConflictError(
              "Planned unbound token family is absent, bound, or already revoked.",
            );
          }
          this.database.sqlite.prepare(`
            update oauth_token_families
               set status = 'REVOKED', revoked_at = ?
             where family_id = ? and connector_binding_id is null and status <> 'REVOKED'
          `).run(appliedAt, action.familyId);
          this.database.sqlite.prepare("delete from oauth_access_tokens where family_id = ?")
            .run(action.familyId);
          this.database.sqlite.prepare("delete from oauth_refresh_tokens where family_id = ?")
            .run(action.familyId);
          continue;
        }
        const binding = this.getConnectorBinding(action.bindingId);
        if (!binding) {
          throw new ConnectorStateConflictError("Planned connector binding no longer exists.");
        }
        if (action.kind === "PURGE_TERMINAL_BINDING") {
          if (binding.state !== action.expectedState) {
            throw new ConnectorStateConflictError("Planned terminal binding state changed.");
          }
          this.revokeBindingTokenFamilies(binding.bindingId, appliedAt);
          this.database.sqlite.prepare(`
            update oauth_connector_bindings
               set ref_count = 0, updated_at = ?
             where binding_id = ? and state = ?
          `).run(appliedAt, binding.bindingId, action.expectedState);
          continue;
        }
        if (binding.state !== "DRAINING"
          || binding.drainEpoch !== action.expectedDrainEpoch) {
          throw new ConnectorStateConflictError("Planned DRAINING binding generation changed.");
        }
        const activeFamilyCount = Number(this.database.sqlite.prepare(`
          select count(*) from oauth_token_families
           where connector_binding_id = ? and status <> 'REVOKED'
        `).pluck().get(binding.bindingId));
        if (activeFamilyCount !== binding.refCount) {
          throw new ConnectorStateConflictError(
            "Planned DRAINING binding reference count changed.",
          );
        }
        const deadlineMs = binding.drainDeadlineAt
          ? Date.parse(binding.drainDeadlineAt)
          : Number.NaN;
        const deadlineElapsed = Number.isFinite(deadlineMs) && nowMs >= deadlineMs;
        if (action.reason === "DEADLINE_ELAPSED" && !deadlineElapsed) {
          throw new ConnectorStateConflictError("Planned DRAINING deadline has not elapsed.");
        }
        if (action.reason === "REFERENCE_ZERO" && binding.refCount !== 0) {
          throw new ConnectorStateConflictError("Planned DRAINING binding still has references.");
        }
        const revokedFamilyCount = action.reason === "DEADLINE_ELAPSED"
          ? this.revokeBindingTokenFamilies(binding.bindingId, appliedAt)
          : 0;
        const updated = this.database.sqlite.prepare(`
          update oauth_connector_bindings
             set state = 'RETIRED', state_reason = ?, ref_count = 0,
                 drain_epoch = drain_epoch + 1, drain_deadline_at = null,
                 refresh_allowed_during_drain = 0, updated_at = ?
           where binding_id = ? and state = 'DRAINING' and drain_epoch = ?
        `).run(
          action.reason,
          appliedAt,
          binding.bindingId,
          action.expectedDrainEpoch,
        );
        if (updated.changes !== 1) {
          throw new ConnectorStateConflictError("DRAINING connector changed concurrently.");
        }
        const receiptId = `connector-retirement-${randomUUID()}`;
        this.database.sqlite.prepare(`
          insert into oauth_connector_retirement_receipts
            (receipt_id, binding_id, canonical_name, drain_epoch, reason,
             revoked_family_count, retired_at)
          values (?, ?, ?, ?, ?, ?, ?)
        `).run(
          receiptId,
          binding.bindingId,
          binding.canonicalName,
          action.expectedDrainEpoch + 1,
          action.reason,
          revokedFamilyCount,
          appliedAt,
        );
        retirementReceipts.push(this.getRetirementReceipt(binding.bindingId)!);
        retiredCount += 1;
      }
      const readinessAfter = this.personalConnectorReadiness(plan.expectation, nowMs);
      if (readinessAfter.state !== "PASS") {
        throw new ConnectorStateConflictError(
          `Personal connector reconciliation did not establish readiness: ${readinessAfter.invalidStates.join(", ")}`,
        );
      }
      const postimageDigest = sha256Digest(stableJson(
        this.personalConnectorReconciliationSnapshot(plan.expectation.canonicalName),
      ));
      return { readinessAfter, postimageDigest };
    });
    const committed = apply.immediate();
    for (let index = 0; index < retiredCount; index += 1) {
      this.recordConnectorTransition("DRAINING", "RETIRED");
    }
    return {
      status: plan.actions.length === 0 ? "NO_CHANGES" : "APPLIED",
      planId: plan.planId,
      planDigest: plan.planDigest,
      preimageDigest: plan.preimageDigest,
      postimageDigest: committed.postimageDigest,
      appliedAt,
      appliedActions: plan.actions,
      retirementReceipts,
      readinessAfter: committed.readinessAfter,
    };
  }

  connectorCanIssueAuthorizationCode(canonicalName: string, clientId: string): boolean {
    const binding = this.getConnectorBindingForClient(canonicalName, clientId);
    if (!binding) return true;
    return ["REGISTERED", "CANDIDATE", "VERIFIED", "ACTIVATION_PREPARED", "ACTIVE"].includes(binding.state);
  }

  getActivationReceipt(receiptId: string): ConnectorActivationReceipt | undefined {
    const row = this.database.sqlite.prepare(`
      select receipt_id, canonical_name, candidate_binding_id, client_id, installation_epoch,
             schema_generation, authority_contract_generation, redirect_uris_digest, build_digest,
             tuple_digest, preimage_digest, previous_active_binding_id, owner_authority_id, drain_deadline_at,
             refresh_allowed_during_drain, status, failure_code, prepared_at, activated_at, failed_at
        from oauth_connector_activation_receipts where receipt_id = ?
    `).get(receiptId) as ConnectorActivationReceiptRow | undefined;
    if (!row) return undefined;
    const receipt = rowToActivationReceipt(row);
    const activationAuthority = this.getActivationAuthorityReceipt(receiptId);
    return activationAuthority ? { ...receipt, activationAuthority } : receipt;
  }

  getActivationAuthorityReceipt(receiptId: string): ConnectorActivationAuthorityReceipt | undefined {
    const row = this.database.sqlite.prepare(`
      select action_claim_id, receipt_id, authority_id, principal_key_fingerprint,
             action_fingerprint, resource_key_sha256, fencing_token, risk, claim_state,
             approval_assurance, canonical_name, tuple_digest, active_preimage_digest,
             finalization_plan_digest, evidence_digest, claimed_at_ms, dispatched_at_ms,
             proof_digest, consumed_at
        from oauth_connector_activation_authorities where receipt_id = ?
    `).get(receiptId) as ConnectorActivationAuthorityReceiptRow | undefined;
    return row ? rowToActivationAuthorityReceipt(row) : undefined;
  }

  getRetirementReceipt(bindingId: string): ConnectorRetirementReceipt | undefined {
    const row = this.database.sqlite.prepare(`
      select receipt_id, binding_id, canonical_name, drain_epoch, reason,
             revoked_family_count, retired_at
        from oauth_connector_retirement_receipts where binding_id = ?
    `).get(bindingId) as ConnectorRetirementReceiptRow | undefined;
    return row ? rowToRetirementReceipt(row) : undefined;
  }

  acquireConnectorReference(bindingId: string, expectedDrainEpoch: number): boolean {
    const result = this.database.sqlite.prepare(
      `update oauth_connector_bindings set ref_count = ref_count + 1, updated_at = ?
        where binding_id = ?
          and state in ('CANDIDATE', 'VERIFIED', 'ACTIVATION_PREPARED', 'ACTIVE')
          and drain_epoch = ?`,
    ).run(new Date().toISOString(), bindingId, expectedDrainEpoch);
    return result.changes === 1;
  }

  releaseConnectorReference(bindingId: string): boolean {
    const result = this.database.sqlite.prepare(
      `update oauth_connector_bindings set ref_count = ref_count - 1, updated_at = ?
        where binding_id = ? and ref_count > 0`,
    ).run(new Date().toISOString(), bindingId);
    return result.changes === 1;
  }

  retireConnectorBinding(
    bindingId: string,
    expectedDrainEpoch: number,
    nowMs = Date.now(),
  ): ConnectorRetirementReceipt | undefined {
    let transitioned = false;
    const retire = this.database.sqlite.transaction(() => {
      const binding = this.getConnectorBinding(bindingId);
      if (!binding) throw new ConnectorStateConflictError("Connector binding does not exist.");
      if (binding.state === "RETIRED") return this.getRetirementReceipt(bindingId);
      if (binding.state !== "DRAINING" || binding.drainEpoch !== expectedDrainEpoch) {
        throw new ConnectorStateConflictError("Connector binding is not the expected DRAINING generation.");
      }
      const activeFamilies = this.database.sqlite.prepare(`
        select family_id from oauth_token_families
         where connector_binding_id = ? and status <> 'REVOKED'
         order by family_id
      `).pluck().all(bindingId) as string[];
      if (activeFamilies.length > binding.refCount) {
        throw new ConnectorStateConflictError("Connector reference count does not match active token families.");
      }
      const deadlineMs = binding.drainDeadlineAt ? Date.parse(binding.drainDeadlineAt) : Number.NaN;
      const deadlineElapsed = Number.isFinite(deadlineMs) && nowMs >= deadlineMs;
      if (binding.refCount > 0 && !deadlineElapsed) return undefined;

      const retiredAt = new Date(nowMs).toISOString();
      let revokedFamilyCount = 0;
      if (deadlineElapsed && activeFamilies.length > 0) {
        revokedFamilyCount = this.revokeBindingTokenFamilies(bindingId, retiredAt);
      }
      const reason: ConnectorRetirementReceipt["reason"] = deadlineElapsed
        ? "DEADLINE_ELAPSED"
        : "REFERENCE_ZERO";
      const updated = this.database.sqlite.prepare(`
        update oauth_connector_bindings
           set state = 'RETIRED', state_reason = ?, ref_count = 0,
               drain_epoch = drain_epoch + 1, refresh_allowed_during_drain = 0, updated_at = ?
         where binding_id = ? and state = 'DRAINING' and drain_epoch = ?
      `).run(reason, retiredAt, bindingId, expectedDrainEpoch);
      if (updated.changes !== 1) throw new ConnectorStateConflictError("DRAINING connector changed concurrently.");
      this.database.sqlite.prepare(`
        insert into oauth_connector_retirement_receipts
          (receipt_id, binding_id, canonical_name, drain_epoch, reason, revoked_family_count, retired_at)
        values (?, ?, ?, ?, ?, ?, ?)
      `).run(
        `connector-retirement-${randomUUID()}`,
        bindingId,
        binding.canonicalName,
        expectedDrainEpoch + 1,
        reason,
        revokedFamilyCount,
        retiredAt,
      );
      transitioned = true;
      return this.getRetirementReceipt(bindingId)!;
    });
    const result = retire.immediate();
    if (transitioned) this.recordConnectorTransition("DRAINING", "RETIRED");
    return result;
  }

  saveAccessToken(tokenHash: string, record: PersistedAccessTokenRecord): void {
    this.database.sqlite
      .prepare(
        `insert into oauth_access_tokens
          (token_hash, client_id, scopes_json, expires_at, resource, family_id,
           connector_binding_id, connector_drain_epoch, installation_epoch, rotation_sequence)
         values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
         on conflict(token_hash) do update set
           client_id = excluded.client_id,
           scopes_json = excluded.scopes_json,
           expires_at = excluded.expires_at,
           resource = excluded.resource,
           family_id = excluded.family_id,
           connector_binding_id = excluded.connector_binding_id,
           connector_drain_epoch = excluded.connector_drain_epoch,
           installation_epoch = excluded.installation_epoch,
           rotation_sequence = excluded.rotation_sequence`,
      )
      .run(
        tokenHash,
        record.clientId,
        JSON.stringify(record.scopes),
        record.expiresAt,
        record.resource ?? null,
        record.familyId ?? null,
        record.connectorBindingId ?? null,
        record.connectorDrainEpoch ?? null,
        record.installationEpoch ?? null,
        record.rotationSequence ?? 0,
      );
  }

  getAccessToken(tokenHash: string): PersistedAccessTokenRecord | undefined {
    const row = this.database.sqlite
      .prepare(
        `select client_id, scopes_json, expires_at, resource, family_id,
                connector_binding_id, connector_drain_epoch, installation_epoch, rotation_sequence
           from oauth_access_tokens where token_hash = ?`,
      )
      .get(tokenHash) as TokenRow | undefined;
    return row ? rowToAccessTokenRecord(row) : undefined;
  }

  deleteAccessToken(tokenHash: string): void {
    this.database.sqlite.prepare("delete from oauth_access_tokens where token_hash = ?").run(tokenHash);
  }

  saveRefreshToken(tokenHash: string, record: PersistedRefreshTokenRecord): void {
    this.database.sqlite
      .prepare(
        `insert into oauth_refresh_tokens
          (token_hash, client_id, scopes_json, expires_at, resource, family_id,
           connector_binding_id, connector_drain_epoch, installation_epoch, rotation_sequence)
         values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
         on conflict(token_hash) do update set
           client_id = excluded.client_id,
           scopes_json = excluded.scopes_json,
           expires_at = excluded.expires_at,
           resource = excluded.resource,
           family_id = excluded.family_id,
           connector_binding_id = excluded.connector_binding_id,
           connector_drain_epoch = excluded.connector_drain_epoch,
           installation_epoch = excluded.installation_epoch,
           rotation_sequence = excluded.rotation_sequence`,
      )
      .run(
        tokenHash,
        record.clientId,
        JSON.stringify(record.scopes),
        record.expiresAt,
        record.resource ?? null,
        record.familyId ?? null,
        record.connectorBindingId ?? null,
        record.connectorDrainEpoch ?? null,
        record.installationEpoch ?? null,
        record.rotationSequence ?? 0,
      );
  }

  saveTokenPair(pair: PersistedTokenPair, consumedRefreshTokenHash?: string): boolean {
    validateTokenPairBinding(pair);
    const save = this.database.sqlite.transaction(() => {
      const familyId = pair.refreshToken.familyId;
      if (consumedRefreshTokenHash) {
        const consumed = this.database.sqlite.prepare(
          `select client_id, family_id, connector_binding_id, connector_drain_epoch,
                  installation_epoch, rotation_sequence
             from oauth_refresh_tokens where token_hash = ?`,
        ).get(consumedRefreshTokenHash) as {
          client_id: string;
          family_id: string | null;
          connector_binding_id: string | null;
          connector_drain_epoch: number | null;
          installation_epoch: number | null;
          rotation_sequence: number;
        } | undefined;
        if (!consumed
          || consumed.client_id !== pair.refreshToken.clientId
          || (familyId && (
            consumed.family_id !== familyId
            || consumed.connector_binding_id !== (pair.refreshToken.connectorBindingId ?? null)
            || consumed.connector_drain_epoch !== (pair.refreshToken.connectorDrainEpoch ?? null)
            || consumed.installation_epoch !== (pair.refreshToken.installationEpoch ?? null)
            || consumed.rotation_sequence !== (pair.refreshToken.rotationSequence ?? 0) - 1
          ))) return false;
        if (familyId && !this.bindingAndFamilyAreCurrent({
          ...pair.refreshToken,
          rotationSequence: consumed.rotation_sequence,
        }, "refresh", Date.now())) return false;
        const removed = this.database.sqlite.prepare("delete from oauth_refresh_tokens where token_hash = ?").run(consumedRefreshTokenHash);
        if (removed.changes !== 1) return false;
        if (familyId) {
          const advanced = this.database.sqlite.prepare(
            `update oauth_token_families
                set status = 'ACTIVE', rotation_sequence = ?, rotated_at = ?
              where family_id = ? and status in ('ACTIVE', 'ROTATING') and rotation_sequence = ?`,
          ).run(
            pair.refreshToken.rotationSequence ?? 0,
            new Date().toISOString(),
            familyId,
            consumed.rotation_sequence,
          );
          if (advanced.changes !== 1) return false;
        }
      } else if (familyId) {
        const bindingId = pair.refreshToken.connectorBindingId;
        if (bindingId && !this.acquireConnectorReference(bindingId, pair.refreshToken.connectorDrainEpoch ?? -1)) return false;
        const created = new Date().toISOString();
        try {
          this.database.sqlite.prepare(
            `insert into oauth_token_families
              (family_id, client_id, connector_binding_id, installation_epoch, drain_epoch,
               status, rotation_sequence, created_at)
             values (?, ?, ?, ?, ?, 'ACTIVE', ?, ?)`,
          ).run(
            familyId,
            pair.refreshToken.clientId,
            bindingId ?? null,
            pair.refreshToken.installationEpoch ?? null,
            pair.refreshToken.connectorDrainEpoch ?? null,
            pair.refreshToken.rotationSequence ?? 0,
            created,
          );
        } catch (error) {
          if (bindingId) this.releaseConnectorReference(bindingId);
          throw error;
        }
      }

      this.saveAccessToken(pair.accessTokenHash, pair.accessToken);
      this.saveRefreshToken(pair.refreshTokenHash, pair.refreshToken);
      return true;
    });

    return save.immediate();
  }

  getRefreshToken(tokenHash: string): PersistedRefreshTokenRecord | undefined {
    const row = this.database.sqlite
      .prepare(
        `select client_id, scopes_json, expires_at, resource, family_id,
                connector_binding_id, connector_drain_epoch, installation_epoch, rotation_sequence
           from oauth_refresh_tokens where token_hash = ?`,
      )
      .get(tokenHash) as TokenRow | undefined;
    return row ? rowToRefreshTokenRecord(row) : undefined;
  }

  credentialBindingIsCurrent(record: PersistedTokenBinding & { clientId: string }): boolean {
    return this.accessTokenBindingIsCurrent(record);
  }

  accessTokenBindingIsCurrent(
    record: PersistedTokenBinding & { clientId: string },
    nowMs = Date.now(),
  ): boolean {
    if (!record.familyId && !record.connectorBindingId) return true;
    return this.bindingAndFamilyAreCurrent(record, "access", nowMs);
  }

  refreshTokenBindingIsCurrent(
    record: PersistedTokenBinding & { clientId: string },
    nowMs = Date.now(),
  ): boolean {
    if (!record.familyId && !record.connectorBindingId) return true;
    return this.bindingAndFamilyAreCurrent(record, "refresh", nowMs);
  }

  revokeTokenFamily(familyId: string): boolean {
    const revoke = this.database.sqlite.transaction(() => {
      const row = this.database.sqlite.prepare(
        "select status, connector_binding_id from oauth_token_families where family_id = ?",
      ).get(familyId) as { status: string; connector_binding_id: string | null } | undefined;
      if (!row) return false;
      if (row.status !== "REVOKED") {
        const updated = this.database.sqlite.prepare(
          "update oauth_token_families set status = 'REVOKED', revoked_at = ? where family_id = ? and status <> 'REVOKED'",
        ).run(new Date().toISOString(), familyId);
        if (updated.changes !== 1) return false;
        if (row.connector_binding_id && !this.releaseConnectorReference(row.connector_binding_id)) {
          throw new Error("Connector reference could not be released with token-family revocation.");
        }
      }
      this.database.sqlite.prepare("delete from oauth_access_tokens where family_id = ?").run(familyId);
      this.database.sqlite.prepare("delete from oauth_refresh_tokens where family_id = ?").run(familyId);
      return true;
    });
    return revoke.immediate();
  }

  deleteRefreshToken(tokenHash: string): void {
    const row = this.database.sqlite.prepare("select family_id from oauth_refresh_tokens where token_hash = ?")
      .get(tokenHash) as { family_id: string | null } | undefined;
    if (row?.family_id) this.revokeTokenFamily(row.family_id);
    else this.database.sqlite.prepare("delete from oauth_refresh_tokens where token_hash = ?").run(tokenHash);
  }

  close(): void {
    this.database.close();
  }

  private insertConnectorBinding(
    input: ConnectorRegistrationInput,
    state: "REGISTERED" | "CANDIDATE",
  ): ConnectorBindingRecord {
    const highestEpoch = this.database.sqlite.prepare(`
      select max(installation_epoch) from oauth_connector_bindings where canonical_name = ?
    `).pluck().get(input.canonicalName) as number | null;
    if (highestEpoch !== null && input.installationEpoch <= highestEpoch) {
      throw new ConnectorStateConflictError("Connector installation epoch must advance monotonically.");
    }
    const bindingId = `connector-${randomUUID()}`;
    const now = new Date().toISOString();
    this.database.sqlite.prepare(`
      insert into oauth_connector_bindings
        (binding_id, canonical_name, client_id, installation_epoch, schema_generation,
         drain_epoch, refresh_allowed_during_drain, state, ref_count, created_at, updated_at)
      values (?, ?, ?, ?, ?, 0, 0, ?, 0, ?, ?)
    `).run(
      bindingId,
      input.canonicalName,
      input.clientId,
      input.installationEpoch,
      input.schemaGeneration,
      state,
      now,
      now,
    );
    return this.getConnectorBinding(bindingId)!;
  }

  private getConnectorBindingByIdentity(input: ConnectorRegistrationInput): ConnectorBindingRecord | undefined {
    const row = this.database.sqlite.prepare(`
      select ${CONNECTOR_BINDING_COLUMNS}
        from oauth_connector_bindings
       where canonical_name = ? and installation_epoch = ?
    `).get(input.canonicalName, input.installationEpoch) as ConnectorBindingRow | undefined;
    return row ? rowToConnectorBinding(row) : undefined;
  }

  private getPreparedActivationReceipt(canonicalName: string): ConnectorActivationReceipt | undefined {
    const row = this.database.sqlite.prepare(`
      select receipt_id from oauth_connector_activation_receipts
       where canonical_name = ? and status = 'PREPARED'
    `).get(canonicalName) as { receipt_id: string } | undefined;
    return row ? this.getActivationReceipt(row.receipt_id) : undefined;
  }

  private personalConnectorReconciliationSnapshot(
    canonicalName: string,
  ): PersonalConnectorReconciliationSnapshot {
    const bindings = this.database.sqlite.prepare(`
      select binding_id as bindingId, client_id as clientId,
             installation_epoch as installationEpoch, schema_generation as schemaGeneration,
             drain_epoch as drainEpoch, drain_deadline_at as drainDeadlineAt,
             refresh_allowed_during_drain as refreshAllowedDuringDrain,
             state, state_reason as stateReason, ref_count as refCount,
             (select count(*) from oauth_token_families as family
               where family.connector_binding_id = binding.binding_id and family.status <> 'REVOKED')
               as activeFamilyCount,
             ((select count(*) from oauth_access_tokens as access_token
                 where access_token.connector_binding_id = binding.binding_id)
               + (select count(*) from oauth_refresh_tokens as refresh_token
                   where refresh_token.connector_binding_id = binding.binding_id))
               as persistedTokenCount
        from oauth_connector_bindings as binding
       where canonical_name = ?
       order by installation_epoch, binding_id
    `).all(canonicalName) as PersonalConnectorSnapshotBinding[];
    const families = this.database.sqlite.prepare(`
      select family.family_id as familyId, family.client_id as clientId,
             family.connector_binding_id as connectorBindingId,
             family.installation_epoch as installationEpoch,
             family.drain_epoch as drainEpoch, family.status,
             family.rotation_sequence as rotationSequence,
             family.created_at as createdAt, family.rotated_at as rotatedAt,
             family.revoked_at as revokedAt
        from oauth_token_families as family
        left join oauth_connector_bindings as binding
          on binding.binding_id = family.connector_binding_id
       where family.connector_binding_id is null or binding.canonical_name = ?
       order by family.family_id
    `).all(canonicalName) as PersonalConnectorSnapshotFamily[];
    const accessTokens = this.database.sqlite.prepare(`
      select token_hash as tokenHash, client_id as clientId, resource,
             family_id as familyId, connector_binding_id as connectorBindingId,
             connector_drain_epoch as connectorDrainEpoch,
             installation_epoch as installationEpoch,
             rotation_sequence as rotationSequence, expires_at as expiresAt
        from oauth_access_tokens
       where connector_binding_id is null
          or connector_binding_id in (
            select binding_id from oauth_connector_bindings where canonical_name = ?
          )
       order by token_hash
    `).all(canonicalName) as PersonalConnectorSnapshotToken[];
    const refreshTokens = this.database.sqlite.prepare(`
      select token_hash as tokenHash, client_id as clientId, resource,
             family_id as familyId, connector_binding_id as connectorBindingId,
             connector_drain_epoch as connectorDrainEpoch,
             installation_epoch as installationEpoch,
             rotation_sequence as rotationSequence, expires_at as expiresAt
        from oauth_refresh_tokens
       where connector_binding_id is null
          or connector_binding_id in (
            select binding_id from oauth_connector_bindings where canonical_name = ?
          )
       order by token_hash
    `).all(canonicalName) as PersonalConnectorSnapshotToken[];
    const preparedReceipts = this.database.sqlite.prepare(`
      select receipt_id as receiptId, candidate_binding_id as candidateBindingId,
             tuple_digest as tupleDigest, preimage_digest as preimageDigest,
             drain_deadline_at as drainDeadlineAt, prepared_at as preparedAt
        from oauth_connector_activation_receipts
       where canonical_name = ? and status = 'PREPARED'
       order by receipt_id
    `).all(canonicalName) as PersonalConnectorSnapshotPreparedReceipt[];
    return {
      schemaVersion: 1,
      canonicalName,
      bindings,
      families,
      accessTokens,
      refreshTokens,
      preparedReceipts,
    };
  }

  private revokeBindingTokenFamilies(bindingId: string, revokedAt: string): number {
    const revoked = this.database.sqlite.prepare(`
      update oauth_token_families
         set status = 'REVOKED', revoked_at = ?
       where connector_binding_id = ? and status <> 'REVOKED'
    `).run(revokedAt, bindingId);
    this.database.sqlite.prepare("delete from oauth_access_tokens where connector_binding_id = ?").run(bindingId);
    this.database.sqlite.prepare("delete from oauth_refresh_tokens where connector_binding_id = ?").run(bindingId);
    return revoked.changes;
  }

  private bindingAndFamilyAreCurrent(
    record: PersistedTokenBinding & { clientId: string },
    use: "access" | "refresh",
    nowMs: number,
  ): boolean {
    if (!record.familyId) return false;
    const family = this.database.sqlite.prepare(
      `select client_id, connector_binding_id, installation_epoch, drain_epoch, status, rotation_sequence
         from oauth_token_families where family_id = ?`,
    ).get(record.familyId) as {
      client_id: string;
      connector_binding_id: string | null;
      installation_epoch: number | null;
      drain_epoch: number | null;
      status: string;
      rotation_sequence: number;
    } | undefined;
    if (!family || family.status !== "ACTIVE" || family.client_id !== record.clientId) return false;
    if (family.rotation_sequence !== (record.rotationSequence ?? 0)) return false;
    if (!record.connectorBindingId) return family.connector_binding_id === null;
    if (family.connector_binding_id !== record.connectorBindingId
      || family.installation_epoch !== record.installationEpoch
      || family.drain_epoch !== record.connectorDrainEpoch) return false;
    const binding = this.getConnectorBinding(record.connectorBindingId);
    if (!binding
      || binding.clientId !== record.clientId
      || binding.installationEpoch !== record.installationEpoch
      || binding.drainEpoch !== record.connectorDrainEpoch) return false;
    if (["CANDIDATE", "VERIFIED", "ACTIVATION_PREPARED", "ACTIVE"].includes(binding.state)) return true;
    if (binding.state !== "DRAINING" || !binding.drainDeadlineAt) return false;
    const deadlineMs = Date.parse(binding.drainDeadlineAt);
    if (!Number.isFinite(deadlineMs) || nowMs >= deadlineMs) return false;
    return use === "access" || binding.refreshAllowedDuringDrain;
  }

  private recordConnectorTransition(
    from: ConnectorBindingState | "NONE",
    to: ConnectorBindingState,
  ): void {
    try {
      this.metrics?.recordConnectorTransition(from, to, "pass");
    } catch {
      // Observability must never replace the committed connector transition.
    }
  }

  private deleteExpiredTokens(nowSeconds: number): void {
    this.database.sqlite.prepare("delete from oauth_access_tokens where expires_at < ?").run(nowSeconds);
    this.database.sqlite.prepare("delete from oauth_refresh_tokens where expires_at < ?").run(nowSeconds);
    const orphanedFamilies = this.database.sqlite.prepare(
      `select family_id from oauth_token_families
        where status <> 'REVOKED'
          and not exists (
            select 1 from oauth_refresh_tokens
             where oauth_refresh_tokens.family_id = oauth_token_families.family_id
          )`,
    ).pluck().all() as string[];
    for (const familyId of orphanedFamilies) this.revokeTokenFamily(familyId);
  }
}

export class SqliteOAuthClientsStore implements OAuthRegisteredClientsStore {
  constructor(
    private readonly store: SqliteOAuthStore,
    private readonly allowedRedirectHosts: string[],
    private readonly connectorRegistration?: Omit<ConnectorRegistrationInput, "clientId">,
  ) {}

  getClient(clientId: string): OAuthClientInformationFull | undefined {
    return this.store.getClient(clientId);
  }

  registerClient(
    client: Omit<OAuthClientInformationFull, "client_id" | "client_id_issued_at">,
  ): OAuthClientInformationFull {
    return this.store.registerClient(client, this.allowedRedirectHosts, this.connectorRegistration);
  }
}

interface TokenRow {
  client_id: string;
  scopes_json: string;
  expires_at: number;
  resource: string | null;
  family_id: string | null;
  connector_binding_id: string | null;
  connector_drain_epoch: number | null;
  installation_epoch: number | null;
  rotation_sequence: number;
}

const CONNECTOR_BINDING_COLUMNS = `
  binding_id, canonical_name, client_id, installation_epoch, schema_generation,
  authority_contract_generation, redirect_uris_digest, build_digest, drain_epoch,
  drain_deadline_at, refresh_allowed_during_drain, state, state_reason, ref_count,
  created_at, updated_at
`;

interface ConnectorBindingRow {
  binding_id: string;
  canonical_name: string;
  client_id: string;
  installation_epoch: number;
  schema_generation: string;
  authority_contract_generation: string | null;
  redirect_uris_digest: string | null;
  build_digest: string | null;
  drain_epoch: number;
  drain_deadline_at: string | null;
  refresh_allowed_during_drain: number;
  state: ConnectorBindingState;
  state_reason: string | null;
  ref_count: number;
  created_at: string;
  updated_at: string;
}

interface ConnectorReadinessRow {
  binding_id: string;
  canonical_name: string;
  client_id: string;
  installation_epoch: number;
  state: string;
  schema_generation: string;
  authority_contract_generation: string | null;
  redirect_uris_digest: string | null;
  build_digest: string | null;
  drain_deadline_at: string | null;
  refresh_allowed_during_drain: number;
  ref_count: number;
  active_family_count: number;
  persisted_token_count: number;
  prepared_receipt_count: number;
  prepared_receipt_identity_match_count: number;
  prepared_tuple_digest: string | null;
  canonical_prepared_receipt_count: number;
}

interface PersonalConnectorReadinessRow {
  binding_id: string;
  canonical_name: string;
  client_id: string;
  installation_epoch: number;
  state: string;
  schema_generation: string;
  drain_deadline_at: string | null;
  refresh_allowed_during_drain: number;
  ref_count: number;
  active_family_count: number;
  persisted_refresh_token_count: number;
  persisted_token_count: number;
  resource_mismatch_count: number;
  client_mismatch_count: number;
}

interface PersonalConnectorSnapshotBinding {
  bindingId: string;
  clientId: string;
  installationEpoch: number;
  schemaGeneration: string;
  drainEpoch: number;
  drainDeadlineAt: string | null;
  refreshAllowedDuringDrain: number;
  state: ConnectorBindingState;
  stateReason: string | null;
  refCount: number;
  activeFamilyCount: number;
  persistedTokenCount: number;
}

interface PersonalConnectorSnapshotFamily {
  familyId: string;
  clientId: string;
  connectorBindingId: string | null;
  installationEpoch: number | null;
  drainEpoch: number | null;
  status: string;
  rotationSequence: number;
  createdAt: string;
  rotatedAt: string | null;
  revokedAt: string | null;
}

interface PersonalConnectorSnapshotToken {
  tokenHash: string;
  clientId: string;
  resource: string | null;
  familyId: string | null;
  connectorBindingId: string | null;
  connectorDrainEpoch: number | null;
  installationEpoch: number | null;
  rotationSequence: number;
  expiresAt: number;
}

interface PersonalConnectorSnapshotPreparedReceipt {
  receiptId: string;
  candidateBindingId: string;
  tupleDigest: string;
  preimageDigest: string;
  drainDeadlineAt: string;
  preparedAt: string;
}

interface PersonalConnectorReconciliationSnapshot {
  schemaVersion: 1;
  canonicalName: string;
  bindings: PersonalConnectorSnapshotBinding[];
  families: PersonalConnectorSnapshotFamily[];
  accessTokens: PersonalConnectorSnapshotToken[];
  refreshTokens: PersonalConnectorSnapshotToken[];
  preparedReceipts: PersonalConnectorSnapshotPreparedReceipt[];
}

interface ConnectorActivationReceiptRow {
  receipt_id: string;
  canonical_name: string;
  candidate_binding_id: string;
  client_id: string;
  installation_epoch: number;
  schema_generation: string;
  authority_contract_generation: string;
  redirect_uris_digest: string;
  build_digest: string;
  tuple_digest: string;
  preimage_digest: string;
  previous_active_binding_id: string | null;
  owner_authority_id: string | null;
  drain_deadline_at: string;
  refresh_allowed_during_drain: number;
  status: ConnectorActivationReceiptStatus;
  failure_code: string | null;
  prepared_at: string;
  activated_at: string | null;
  failed_at: string | null;
}

interface ConnectorActivationAuthorityReceiptRow {
  action_claim_id: string;
  receipt_id: string;
  authority_id: string;
  principal_key_fingerprint: string;
  action_fingerprint: string;
  resource_key_sha256: string;
  fencing_token: number;
  risk: "R3";
  claim_state: "DISPATCHED";
  approval_assurance: "cooperative";
  canonical_name: string;
  tuple_digest: string;
  active_preimage_digest: string;
  finalization_plan_digest: string;
  evidence_digest: string;
  claimed_at_ms: number;
  dispatched_at_ms: number;
  proof_digest: string;
  consumed_at: string;
}

interface ConnectorRetirementReceiptRow {
  receipt_id: string;
  binding_id: string;
  canonical_name: string;
  drain_epoch: number;
  reason: ConnectorRetirementReceipt["reason"];
  revoked_family_count: number;
  retired_at: string;
}

function rowToAccessTokenRecord(row: TokenRow): PersistedAccessTokenRecord {
  return tokenRow(row);
}

function rowToRefreshTokenRecord(row: TokenRow): PersistedRefreshTokenRecord {
  return tokenRow(row);
}

function tokenRow(row: TokenRow): PersistedAccessTokenRecord {
  return {
    clientId: row.client_id,
    scopes: JSON.parse(row.scopes_json) as string[],
    expiresAt: row.expires_at,
    resource: row.resource ?? undefined,
    familyId: row.family_id ?? undefined,
    connectorBindingId: row.connector_binding_id ?? undefined,
    connectorDrainEpoch: row.connector_drain_epoch ?? undefined,
    installationEpoch: row.installation_epoch ?? undefined,
    rotationSequence: row.rotation_sequence,
  };
}

function rowToConnectorBinding(row: ConnectorBindingRow): ConnectorBindingRecord {
  return {
    bindingId: row.binding_id,
    canonicalName: row.canonical_name,
    clientId: row.client_id,
    installationEpoch: row.installation_epoch,
    schemaGeneration: row.schema_generation,
    authorityContractGeneration: row.authority_contract_generation ?? undefined,
    redirectUrisDigest: row.redirect_uris_digest ?? undefined,
    buildDigest: row.build_digest ?? undefined,
    drainEpoch: row.drain_epoch,
    drainDeadlineAt: row.drain_deadline_at ?? undefined,
    refreshAllowedDuringDrain: row.refresh_allowed_during_drain === 1,
    state: row.state,
    stateReason: row.state_reason ?? undefined,
    refCount: row.ref_count,
    createdAt: row.created_at,
    updatedAt: row.updated_at,
  };
}

function rowToActivationReceipt(row: ConnectorActivationReceiptRow): ConnectorActivationReceipt {
  return {
    receiptId: row.receipt_id,
    tuple: {
      canonicalName: row.canonical_name,
      candidateBindingId: row.candidate_binding_id,
      clientId: row.client_id,
      installationEpoch: row.installation_epoch,
      schemaGeneration: row.schema_generation,
      authorityContractGeneration: row.authority_contract_generation,
      redirectUrisDigest: row.redirect_uris_digest,
      buildDigest: row.build_digest,
    },
    tupleDigest: row.tuple_digest,
    previousActiveBindingId: row.previous_active_binding_id ?? undefined,
    preimageDigest: row.preimage_digest,
    ownerAuthorityId: row.owner_authority_id ?? undefined,
    drainDeadlineAt: row.drain_deadline_at,
    refreshAllowedDuringDrain: row.refresh_allowed_during_drain === 1,
    status: row.status,
    failureCode: row.failure_code ?? undefined,
    preparedAt: row.prepared_at,
    activatedAt: row.activated_at ?? undefined,
    failedAt: row.failed_at ?? undefined,
  };
}

function rowToActivationAuthorityReceipt(
  row: ConnectorActivationAuthorityReceiptRow,
): ConnectorActivationAuthorityReceipt {
  return {
    schemaVersion: 1,
    authorityId: row.authority_id,
    actionClaimId: row.action_claim_id,
    actionFingerprint: row.action_fingerprint,
    resourceKeySha256: row.resource_key_sha256,
    fencingToken: row.fencing_token,
    principalKeyFingerprint: row.principal_key_fingerprint,
    risk: row.risk,
    claimState: row.claim_state,
    approvalAssurance: row.approval_assurance,
    receiptId: row.receipt_id,
    canonicalName: row.canonical_name,
    tupleDigest: row.tuple_digest,
    activePreimageDigest: row.active_preimage_digest,
    finalizationPlanDigest: row.finalization_plan_digest,
    evidenceDigest: row.evidence_digest,
    claimedAtMs: row.claimed_at_ms,
    dispatchedAtMs: row.dispatched_at_ms,
    proofDigest: row.proof_digest,
    consumedAt: row.consumed_at,
  };
}

function rowToRetirementReceipt(row: ConnectorRetirementReceiptRow): ConnectorRetirementReceipt {
  return {
    receiptId: row.receipt_id,
    bindingId: row.binding_id,
    canonicalName: row.canonical_name,
    drainEpoch: row.drain_epoch,
    reason: row.reason,
    revokedFamilyCount: row.revoked_family_count,
    retiredAt: row.retired_at,
  };
}

const CONNECTOR_READINESS_INVALID_STATE_ORDER: readonly ConnectorReadinessInvalidState[] = [
  "ACTIVE_COUNT",
  "VERIFICATION_IDENTITY_INCOMPLETE",
  "ACTIVE_DRAIN_FIELDS_SET",
  "DRAINING_DEADLINE_INVALID",
  "DRAINING_DEADLINE_ELAPSED",
  "REFERENCE_COUNT_UNDERFLOW",
  "TERMINAL_REFERENCES_REMAIN",
  "PREPARED_RECEIPT_MISMATCH",
  "UNKNOWN_BINDING_STATE",
  "CANONICAL_NAME_UNCONFIGURED",
];

const PERSONAL_CONNECTOR_READINESS_INVALID_STATE_ORDER:
readonly PersonalConnectorReadinessInvalidState[] = [
  "CANONICAL_NAME_UNCONFIGURED",
  "ACTIVE_COUNT",
  "ACTIVE_EPOCH_MISMATCH",
  "ACTIVE_SCHEMA_STALE",
  "ACTIVE_SCHEMA_INVALID",
  "ACTIVE_DRAIN_FIELDS_SET",
  "ACTIVE_FAMILY_MISSING",
  "ACTIVE_REFRESH_TOKEN_MISSING",
  "ACTIVE_TOKEN_RESOURCE_MISMATCH",
  "TOKEN_CLIENT_MISMATCH",
  "DRAINING_DEADLINE_INVALID",
  "DRAINING_DEADLINE_ELAPSED",
  "REFERENCE_COUNT_MISMATCH",
  "TERMINAL_REFERENCES_REMAIN",
  "PREPARED_RECEIPT_RESIDUE",
  "UNBOUND_ACTIVE_FAMILY",
  "NON_ACTIVE_TOKEN_FAMILY",
  "UNKNOWN_BINDING_STATE",
];

function validatePersonalConnectorExpectation(expectation: PersonalConnectorExpectation): void {
  if (!expectation.canonicalName.trim()
    || !Number.isSafeInteger(expectation.installationEpoch)
    || expectation.installationEpoch <= 0
    || !DIGEST_PATTERN.test(expectation.schemaGeneration)) {
    throw new Error("Personal connector expectation is invalid.");
  }
  const resource = new URL(expectation.resource);
  if (!resource.href || resource.username || resource.password || resource.hash) {
    throw new Error("Personal connector resource is invalid.");
  }
}

function reconciliationActionIdentity(action: PersonalConnectorReconciliationAction): string {
  if (action.kind === "UPDATE_ACTIVE_SCHEMA") return `${action.kind}:${action.bindingId}`;
  if (action.kind === "REVOKE_UNBOUND_FAMILY") return `${action.kind}:${action.familyId}`;
  return `${action.kind}:${action.bindingId}`;
}

function validatePersonalConnectorReconciliationPlan(
  plan: PersonalConnectorReconciliationPlan,
): void {
  if (!plan || plan.schemaVersion !== 1 || !plan.planId.startsWith("personal-connector-reconcile-")) {
    throw new ConnectorStateConflictError("Personal connector reconciliation plan is invalid.");
  }
  validatePersonalConnectorExpectation(plan.expectation);
  if (!DIGEST_PATTERN.test(plan.preimageDigest) || !DIGEST_PATTERN.test(plan.planDigest)) {
    throw new ConnectorStateConflictError("Personal connector reconciliation digest is invalid.");
  }
  if (!Number.isFinite(Date.parse(plan.createdAt))) {
    throw new ConnectorStateConflictError("Personal connector reconciliation timestamp is invalid.");
  }
  const { planDigest, ...unsigned } = plan;
  if (sha256Digest(stableJson(unsigned)) !== planDigest) {
    throw new ConnectorStateConflictError("Personal connector reconciliation plan digest mismatch.");
  }
  const identities = plan.actions.map(reconciliationActionIdentity);
  if (new Set(identities).size !== identities.length
    || identities.some((identity, index) => index > 0 && identity < identities[index - 1]!)) {
    throw new ConnectorStateConflictError("Personal connector reconciliation actions are not unique and ordered.");
  }
}

function emptyConnectorBindingCounts(): Record<ConnectorBindingState, number> {
  return {
    REGISTERED: 0,
    CANDIDATE: 0,
    VERIFIED: 0,
    ACTIVATION_PREPARED: 0,
    ACTIVE: 0,
    DRAINING: 0,
    RETIRED: 0,
    REJECTED: 0,
    FAILED: 0,
  };
}

function isConnectorBindingState(value: string): value is ConnectorBindingState {
  return (CONNECTOR_BINDING_STATES as readonly string[]).includes(value);
}

function connectorVerificationIdentityIsComplete(row: ConnectorReadinessRow): boolean {
  return DIGEST_PATTERN.test(row.schema_generation)
    && row.authority_contract_generation !== null
    && DIGEST_PATTERN.test(row.authority_contract_generation)
    && row.redirect_uris_digest !== null
    && DIGEST_PATTERN.test(row.redirect_uris_digest)
    && row.build_digest !== null
    && DIGEST_PATTERN.test(row.build_digest);
}

function preparedReceiptMatchesBinding(row: ConnectorReadinessRow): boolean {
  if (row.prepared_receipt_count !== 1
    || row.prepared_receipt_identity_match_count !== 1
    || !connectorVerificationIdentityIsComplete(row)) return false;
  return row.prepared_tuple_digest === connectorActivationTupleDigest({
    canonicalName: row.canonical_name,
    candidateBindingId: row.binding_id,
    clientId: row.client_id,
    installationEpoch: row.installation_epoch,
    schemaGeneration: row.schema_generation,
    authorityContractGeneration: row.authority_contract_generation!,
    redirectUrisDigest: row.redirect_uris_digest!,
    buildDigest: row.build_digest!,
  });
}

function validateConnectorBindingInput(input: ConnectorRegistrationInput): void {
  if (!/^[A-Za-z][A-Za-z0-9._-]{0,127}$/u.test(input.canonicalName)) throw new Error("Canonical connector name is invalid.");
  if (!input.clientId) throw new Error("Canonical connector clientId is required.");
  if (!Number.isInteger(input.installationEpoch) || input.installationEpoch < 1) throw new Error("Connector installation epoch is invalid.");
  validateDigest(input.schemaGeneration, "Connector schema generation");
}

function validateVerificationEvidence(evidence: ConnectorVerificationEvidence): void {
  validateDigest(evidence.authorityContractGeneration, "Connector authority contract generation");
  validateDigest(evidence.redirectUrisDigest, "Connector redirect URI digest");
  validateDigest(evidence.buildDigest, "Connector build digest");
}

function validateActivationTuple(tuple: ConnectorActivationTuple): void {
  validateConnectorBindingInput({
    canonicalName: tuple.canonicalName,
    clientId: tuple.clientId,
    installationEpoch: tuple.installationEpoch,
    schemaGeneration: tuple.schemaGeneration,
  });
  if (!/^connector-[A-Za-z0-9-]{8,}$/u.test(tuple.candidateBindingId)) {
    throw new Error("Connector candidate binding ID is invalid.");
  }
  validateVerificationEvidence(tuple);
}

function validateActivationPlan(plan: ConnectorActivationPlan): void {
  if (!Number.isFinite(Date.parse(plan.drainDeadlineAt))) {
    throw new Error("Connector drain deadline is invalid.");
  }
}

const CONNECTOR_ACTIVATION_AUTHORITY_PROOF_KEYS = [
  "actionClaimId",
  "actionFingerprint",
  "activePreimageDigest",
  "approvalAssurance",
  "authorityId",
  "canonicalName",
  "claimState",
  "claimedAtMs",
  "dispatchedAtMs",
  "evidenceDigest",
  "fencingToken",
  "finalizationPlanDigest",
  "principalKeyFingerprint",
  "receiptId",
  "resourceKeySha256",
  "risk",
  "schemaVersion",
  "tupleDigest",
] as const;

function validateConnectorActivationAuthorityBinding(binding: ConnectorActivationAuthorityBinding): void {
  if (!binding || typeof binding !== "object") {
    throw new Error("Connector activation authority binding is required.");
  }
  if (!new RegExp(`^connector-activation-${UUID_PATTERN.source.slice(1, -1)}$`, "u").test(binding.receiptId)) {
    throw new Error("Connector activation authority receiptId is invalid.");
  }
  if (!/^[A-Za-z][A-Za-z0-9._-]{0,127}$/u.test(binding.canonicalName)) {
    throw new Error("Connector activation authority canonicalName is invalid.");
  }
  validateDigest(binding.tupleDigest, "Connector activation authority tuple digest");
  validateDigest(binding.activePreimageDigest, "Connector activation authority active preimage digest");
  validateDigest(binding.finalizationPlanDigest, "Connector activation authority finalization plan digest");
}

function validateConnectorActivationAuthorityProof(
  value: unknown,
): asserts value is ConnectorActivationAuthorityProof {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new ConnectorStateConflictError("Connector activation authority proof must be a typed object.");
  }
  const prototype = Object.getPrototypeOf(value);
  if (prototype !== Object.prototype && prototype !== null) {
    throw new ConnectorStateConflictError("Connector activation authority proof must be a plain typed object.");
  }
  const proof = value as Partial<ConnectorActivationAuthorityProof> & Record<string, unknown>;
  const keys = Object.keys(proof).sort();
  if (keys.length !== CONNECTOR_ACTIVATION_AUTHORITY_PROOF_KEYS.length
    || keys.some((key, index) => key !== CONNECTOR_ACTIVATION_AUTHORITY_PROOF_KEYS[index])) {
    throw new ConnectorStateConflictError("Connector activation authority proof shape is invalid.");
  }
  if (proof.schemaVersion !== 1
    || proof.risk !== "R3"
    || proof.claimState !== "DISPATCHED"
    || proof.approvalAssurance !== "cooperative") {
    throw new ConnectorStateConflictError("Connector activation authority proof state is invalid.");
  }
  if (typeof proof.authorityId !== "string"
    || !new RegExp(`^authority_${UUID_PATTERN.source.slice(1, -1)}$`, "u").test(proof.authorityId)
    || typeof proof.actionClaimId !== "string"
    || !new RegExp(`^authority_claim_${UUID_PATTERN.source.slice(1, -1)}$`, "u").test(proof.actionClaimId)) {
    throw new ConnectorStateConflictError("Connector activation authority proof identity is invalid.");
  }
  if (typeof proof.actionFingerprint !== "string" || !RAW_SHA256_PATTERN.test(proof.actionFingerprint)
    || typeof proof.resourceKeySha256 !== "string" || !RAW_SHA256_PATTERN.test(proof.resourceKeySha256)
    || typeof proof.principalKeyFingerprint !== "string" || !RAW_SHA256_PATTERN.test(proof.principalKeyFingerprint)) {
    throw new ConnectorStateConflictError("Connector activation authority proof fingerprint is invalid.");
  }
  if (!Number.isSafeInteger(proof.fencingToken) || Number(proof.fencingToken) < 1
    || !Number.isSafeInteger(proof.claimedAtMs) || Number(proof.claimedAtMs) < 1
    || !Number.isSafeInteger(proof.dispatchedAtMs) || Number(proof.dispatchedAtMs) < Number(proof.claimedAtMs)) {
    throw new ConnectorStateConflictError("Connector activation authority proof timing or fencing is invalid.");
  }
  try {
    validateConnectorActivationAuthorityBinding(proof as unknown as ConnectorActivationAuthorityBinding);
    if (typeof proof.evidenceDigest !== "string") throw new Error("Evidence digest is required.");
    validateDigest(proof.evidenceDigest, "Connector activation authority evidence digest");
  } catch {
    throw new ConnectorStateConflictError("Connector activation authority proof binding is invalid.");
  }
  const binding = proof as unknown as ConnectorActivationAuthorityBinding;
  if (proof.actionFingerprint !== connectorActivationAuthorityActionFingerprint(binding)
    || proof.resourceKeySha256 !== connectorActivationAuthorityResourceKeySha256(binding)) {
    throw new ConnectorStateConflictError("Connector activation authority proof does not match its exact action descriptor.");
  }
}

function assertConnectorActivationAuthorityMatchesReceipt(
  proof: ConnectorActivationAuthorityProof,
  receipt: ConnectorActivationReceipt,
): void {
  if (proof.receiptId !== receipt.receiptId
    || proof.canonicalName !== receipt.tuple.canonicalName
    || proof.tupleDigest !== receipt.tupleDigest
    || proof.activePreimageDigest !== receipt.preimageDigest) {
    throw new ConnectorStateConflictError(
      "Connector activation authority proof does not match the exact prepared receipt, tuple, or ACTIVE preimage.",
    );
  }
}

function connectorActivationAuthorityProofDigest(proof: ConnectorActivationAuthorityProof): string {
  return sha256Digest(stableJson(proof));
}

function validateStateReason(reason: string): void {
  if (!/^[A-Z][A-Z0-9._:-]{0,255}$/u.test(reason)) throw new Error("Connector state reason is invalid.");
}

function validateDigest(value: string, label: string): void {
  if (!DIGEST_PATTERN.test(value)) throw new Error(`${label} is invalid.`);
}

function bindingMatchesTuple(binding: ConnectorBindingRecord, tuple: ConnectorActivationTuple): boolean {
  return binding.bindingId === tuple.candidateBindingId
    && binding.canonicalName === tuple.canonicalName
    && binding.clientId === tuple.clientId
    && binding.installationEpoch === tuple.installationEpoch
    && binding.schemaGeneration === tuple.schemaGeneration
    && binding.authorityContractGeneration === tuple.authorityContractGeneration
    && binding.redirectUrisDigest === tuple.redirectUrisDigest
    && binding.buildDigest === tuple.buildDigest;
}

function activationTupleJson(tuple: ConnectorActivationTuple): string {
  return JSON.stringify({
    canonicalName: tuple.canonicalName,
    candidateBindingId: tuple.candidateBindingId,
    clientId: tuple.clientId,
    installationEpoch: tuple.installationEpoch,
    schemaGeneration: tuple.schemaGeneration,
    authorityContractGeneration: tuple.authorityContractGeneration,
    redirectUrisDigest: tuple.redirectUrisDigest,
    buildDigest: tuple.buildDigest,
  });
}

export function connectorActivationTupleDigest(tuple: ConnectorActivationTuple): string {
  return sha256Digest(activationTupleJson(tuple));
}

function connectorPreimageJson(binding: ConnectorBindingRecord | undefined): string {
  if (!binding) return "null";
  return JSON.stringify({
    bindingId: binding.bindingId,
    canonicalName: binding.canonicalName,
    clientId: binding.clientId,
    installationEpoch: binding.installationEpoch,
    schemaGeneration: binding.schemaGeneration,
    authorityContractGeneration: binding.authorityContractGeneration ?? null,
    redirectUrisDigest: binding.redirectUrisDigest ?? null,
    buildDigest: binding.buildDigest ?? null,
    drainEpoch: binding.drainEpoch,
    drainDeadlineAt: binding.drainDeadlineAt ?? null,
    refreshAllowedDuringDrain: binding.refreshAllowedDuringDrain,
    state: binding.state,
    stateReason: binding.stateReason ?? null,
    refCount: binding.refCount,
    createdAt: binding.createdAt,
    updatedAt: binding.updatedAt,
  });
}

function sha256Digest(value: string): string {
  return `sha256:${createHash("sha256").update(value).digest("hex")}`;
}

function sha256Hex(value: string): string {
  return createHash("sha256").update(value).digest("hex");
}

function stableJson(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(stableJson).join(",")}]`;
  if (value && typeof value === "object") {
    const record = value as Record<string, unknown>;
    return `{${Object.keys(record).sort().map((key) => `${JSON.stringify(key)}:${stableJson(record[key])}`).join(",")}}`;
  }
  return JSON.stringify(value) ?? "null";
}

function isSqliteConstraintError(error: unknown): boolean {
  return Boolean(
    error
      && typeof error === "object"
      && "code" in error
      && String(error.code).startsWith("SQLITE_CONSTRAINT"),
  );
}

function validateTokenPairBinding(pair: PersistedTokenPair): void {
  const fields: Array<keyof PersistedTokenBinding> = [
    "familyId",
    "connectorBindingId",
    "connectorDrainEpoch",
    "installationEpoch",
    "rotationSequence",
  ];
  if (pair.accessToken.clientId !== pair.refreshToken.clientId) throw new Error("OAuth token pair client identity mismatch.");
  for (const field of fields) {
    if (pair.accessToken[field] !== pair.refreshToken[field]) throw new Error(`OAuth token pair binding mismatch: ${field}`);
  }
  if (pair.refreshToken.connectorBindingId && !pair.refreshToken.familyId) throw new Error("Bound connector credentials require a token family.");
}
