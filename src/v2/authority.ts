import { createHash, randomUUID } from "node:crypto";
import {
  DurableAuthorityStore,
  type DurableAuthorityRecord,
} from "./authority-store.js";
import {
  UNIVERSAL_AUTHORITY_RISKS,
  UNIVERSAL_TOOL_OPERATIONS,
  type AuthorityRiskClass,
  type UniversalToolName,
} from "./contracts.js";
import { UniversalBrokerError } from "./errors.js";

export { UNIVERSAL_AUTHORITY_RISKS as AUTHORITY_RISK_CLASSES };
export type { AuthorityRiskClass };

export interface AuthorityActionDescriptor {
  tool: UniversalToolName;
  operation: string;
  target?: string;
  resource?: string;
  parameters?: Record<string, unknown>;
}

export interface RequestedAuthorityAction {
  id?: string;
  descriptor: AuthorityActionDescriptor;
  risk?: AuthorityRiskClass;
  uses?: number;
}

export interface CreateOperationAuthorityInput {
  taskId: string;
  authorityText: string;
  actions: RequestedAuthorityAction[];
  expiresInSeconds?: number;
}

export interface AuthorityGrant {
  authorityId: string;
  actionId: string;
  useId: string;
  risk: AuthorityRiskClass;
  fingerprint: string;
}

interface StoredAuthorityAction {
  id: string;
  descriptor: AuthorityActionDescriptor;
  fingerprint: string;
  minimumRisk: AuthorityRiskClass;
  risk: AuthorityRiskClass;
  maximumUses: number;
  consumedUses: number;
}

interface StoredOperationAuthority {
  authorityId: string;
  taskId?: string;
  taskIdSha256: string;
  authorityTextSha256: string;
  scopeKey: string;
  correctionEpoch: number;
  createdAtMs: number;
  expiresAtMs: number;
  fingerprint: string;
  actions: StoredAuthorityAction[];
  receipts: AuthorityReceipt[];
}

interface AuthorityReceipt {
  useId: string;
  actionId: string;
  reservedAtMs: number;
  completedAtMs?: number;
  result: "PENDING" | "PASS" | "FAIL" | "UNCERTAIN";
  evidence?: Record<string, unknown>;
}

export interface OperationAuthorityRegistryOptions {
  now?: () => number;
  minimumRisk?: (action: AuthorityActionDescriptor) => AuthorityRiskClass;
  storePath?: string;
  instanceId?: string;
}

const DEFAULT_AUTHORITY_TTL_SECONDS = 15 * 60;
const MAXIMUM_AUTHORITY_TTL_SECONDS = 8 * 60 * 60;
const MAXIMUM_ACTIONS = 64;
const MAXIMUM_AUTHORITY_TEXT_CHARACTERS = 8_000;
const MAXIMUM_ACTION_PARAMETERS_CHARACTERS = 16_000;
const MAXIMUM_RECEIPTS = 256;
const MAXIMUM_ACTIVE_AUTHORITIES = 4_096;
const MAXIMUM_ACTIVE_AUTHORITIES_PER_SCOPE = 512;
const AUTHORITY_RECEIPT_RETENTION_MS = 24 * 60 * 60_000;

export class OperationAuthorityRegistry {
  private readonly now: () => number;
  private readonly minimumRisk: (action: AuthorityActionDescriptor) => AuthorityRiskClass;
  private readonly store: DurableAuthorityStore;
  private readonly authorities = new Map<string, StoredOperationAuthority>();
  private readonly correctionEpochs = new Map<string, number>();
  private readonly authorityIdsByFingerprint = new Map<string, string>();
  private readonly recoveredPendingUses: number;
  private previews = 0;

  constructor(options: OperationAuthorityRegistryOptions = {}) {
    this.now = options.now ?? Date.now;
    this.minimumRisk = options.minimumRisk ?? (() => "R1");
    this.store = new DurableAuthorityStore(options.storePath, this.now(), options.instanceId);
    const snapshot = this.store.load();
    this.recoveredPendingUses = snapshot.recoveredPendingUses;
    for (const [scopeKey, correctionEpoch] of snapshot.correctionEpochs) {
      this.correctionEpochs.set(scopeKey, correctionEpoch);
    }
    for (const record of snapshot.authorities) {
      if (record.correctionEpoch !== (snapshot.correctionEpochs.get(record.scopeKey) ?? 0)) {
        continue;
      }
      const authority = this.fromDurable(record);
      this.authorities.set(authority.authorityId, authority);
      this.authorityIdsByFingerprint.set(authority.fingerprint, authority.authorityId);
    }
    this.pruneExpired();
  }

  create(input: CreateOperationAuthorityInput, scopeId: string): Record<string, unknown> {
    this.pruneExpired();
    const taskId = requiredText(input.taskId, "context.authorize requires taskId.", 256);
    const authorityText = requiredText(
      input.authorityText,
      "context.authorize requires the controlling user instruction in authorityText.",
      MAXIMUM_AUTHORITY_TEXT_CHARACTERS,
    );
    if (!Array.isArray(input.actions) || input.actions.length < 1 || input.actions.length > MAXIMUM_ACTIONS) {
      throw new UniversalBrokerError(
        "PRECONDITION_FAILED",
        `context.authorize requires 1 through ${MAXIMUM_ACTIONS} exact actions.`,
      );
    }
    const scopeKey = scopeKeyFor(scopeId);
    const correctionEpoch = this.correctionEpoch(scopeKey);
    this.dropStaleScopeAuthorities(scopeKey, correctionEpoch);
    const actions = input.actions.map((action, index) => this.prepareAction(action, index, false));
    assertUniqueActionIds(actions);
    assertUniqueActionFingerprints(actions);
    const expiresInSeconds = boundedInteger(
      input.expiresInSeconds,
      DEFAULT_AUTHORITY_TTL_SECONDS,
      60,
      MAXIMUM_AUTHORITY_TTL_SECONDS,
      "expiresInSeconds",
    );
    const taskIdSha256 = sha256(taskId);
    const authorityTextSha256 = sha256(authorityText);
    const fingerprint = sha256(stableJson({
      scopeKey,
      correctionEpoch,
      taskIdSha256,
      authorityTextSha256,
      actions: actions.map((action) => ({
        id: action.id,
        fingerprint: action.fingerprint,
        minimumRisk: action.minimumRisk,
        risk: action.risk,
        maximumUses: action.maximumUses,
      })),
      expiresInSeconds,
    }));
    const existingId = this.authorityIdsByFingerprint.get(fingerprint);
    const existing = existingId ? this.authorities.get(existingId) : undefined;
    if (
      existing
      && existing.expiresAtMs > this.now()
      && existing.receipts.length === 0
      && existing.actions.every((action) => action.consumedUses === 0)
    ) {
      return this.present(existing, true);
    }
    if (existingId) this.authorityIdsByFingerprint.delete(fingerprint);
    this.assertAuthorityCapacity(scopeKey);

    const createdAtMs = this.now();
    const authority: StoredOperationAuthority = {
      authorityId: `authority_${randomUUID()}`,
      taskId,
      taskIdSha256,
      authorityTextSha256,
      scopeKey,
      correctionEpoch,
      createdAtMs,
      expiresAtMs: createdAtMs + expiresInSeconds * 1_000,
      fingerprint,
      actions,
      receipts: [],
    };
    this.store.saveAuthority(this.toDurable(authority));
    this.authorities.set(authority.authorityId, authority);
    this.authorityIdsByFingerprint.set(fingerprint, authority.authorityId);
    return this.present(authority, false);
  }

  preview(actionsInput: RequestedAuthorityAction[]): Record<string, unknown> {
    this.pruneExpired();
    if (!Array.isArray(actionsInput) || actionsInput.length < 1 || actionsInput.length > MAXIMUM_ACTIONS) {
      throw new UniversalBrokerError(
        "PRECONDITION_FAILED",
        `context.authority_preview requires 1 through ${MAXIMUM_ACTIONS} exact actions.`,
      );
    }
    const actions = actionsInput.map((action, index) => this.prepareAction(action, index, true));
    assertUniqueActionIds(actions);
    assertUniqueActionFingerprints(actions);
    this.previews += 1;
    const planFingerprint = sha256(stableJson(actions.map((action) => ({
      id: action.id,
      descriptor: action.descriptor,
      minimumRisk: action.minimumRisk,
      risk: action.risk,
      maximumUses: action.maximumUses,
    }))));
    const authorityActions = actions.filter((action) => action.minimumRisk !== "R0");
    return {
      planFingerprint,
      actionCount: actions.length,
      authorityActionCount: authorityActions.length,
      r0ActionCount: actions.length - authorityActions.length,
      authorityRequired: authorityActions.length > 0,
      actions: actions.map((action) => ({
        id: action.id,
        tool: action.descriptor.tool,
        operation: action.descriptor.operation,
        target: action.descriptor.target,
        resource: action.descriptor.resource,
        fingerprint: action.fingerprint,
        minimumRisk: action.minimumRisk,
        effectiveRisk: action.risk,
        authorityRequired: action.minimumRisk !== "R0",
        maximumUses: action.maximumUses,
        parameterKeys: Object.keys(action.descriptor.parameters ?? {}).sort(),
      })),
    };
  }

  require(
    authorityId: string | undefined,
    scopeId: string,
    action: AuthorityActionDescriptor,
    requiredRisk: AuthorityRiskClass,
  ): AuthorityGrant | undefined {
    if (requiredRisk === "R0") return undefined;
    this.pruneExpired();
    if (!authorityId) {
      throw new UniversalBrokerError(
        "AUTHORITY_REQUIRED",
        `${action.tool}.${action.operation} requires ${requiredRisk} task authority. Prepare it with context.authorize and pass authorityId.`,
        { evidence: { requiredRisk, action: boundedAction(action) } },
      );
    }
    const authority = this.authorities.get(authorityId);
    if (!authority) {
      throw new UniversalBrokerError(
        "AUTHORITY_EXPIRED",
        `Task authority is unknown, released, stale, or expired: ${authorityId}`,
      );
    }
    const scopeKey = scopeKeyFor(scopeId);
    if (authority.scopeKey !== scopeKey) {
      throw new UniversalBrokerError(
        "AUTHORITY_MISMATCH",
        "Task authority belongs to a different authenticated OAuth client.",
      );
    }
    if (authority.correctionEpoch !== this.correctionEpoch(scopeKey)) {
      this.remove(authority, false);
      throw new UniversalBrokerError(
        "AUTHORITY_EXPIRED",
        `Task authority is stale after a correction: ${authorityId}`,
      );
    }
    if (authority.expiresAtMs <= this.now()) {
      if (this.authorityIdsByFingerprint.get(authority.fingerprint) === authority.authorityId) {
        this.authorityIdsByFingerprint.delete(authority.fingerprint);
      }
      throw new UniversalBrokerError(
        "AUTHORITY_EXPIRED",
        `Task authority expired: ${authorityId}`,
      );
    }
    const fingerprint = actionFingerprint(action);
    const candidates = authority.actions.filter((candidate) => candidate.fingerprint === fingerprint);
    if (candidates.length !== 1) {
      throw new UniversalBrokerError(
        "AUTHORITY_MISMATCH",
        `Task authority does not contain exactly one matching ${action.tool}.${action.operation} action.`,
        {
          evidence: {
            authorityId,
            requiredRisk,
            action: boundedAction(action),
            matchingActions: candidates.length,
          },
        },
      );
    }
    const selected = candidates[0]!;
    if (riskRank(selected.risk) < riskRank(requiredRisk)) {
      throw new UniversalBrokerError(
        "AUTHORITY_MISMATCH",
        `Task authority action ${selected.id} is ${selected.risk}, but ${requiredRisk} is required.`,
      );
    }
    if (selected.consumedUses >= selected.maximumUses) {
      throw new UniversalBrokerError(
        "AUTHORITY_CONSUMED",
        `Task authority action is fully consumed: ${selected.id}`,
        {
          evidence: {
            authorityId,
            actionId: selected.id,
            maximumUses: selected.maximumUses,
          },
        },
      );
    }
    const grant: AuthorityGrant = {
      authorityId,
      actionId: selected.id,
      useId: `authority_use_${randomUUID()}`,
      risk: requiredRisk,
      fingerprint,
    };
    const reservedAtMs = this.now();
    const receipt: AuthorityReceipt = {
      useId: grant.useId,
      actionId: grant.actionId,
      reservedAtMs,
      result: "PENDING",
    };
    let reservation: ReturnType<DurableAuthorityStore["reserveUse"]>;
    try {
      reservation = this.store.reserveUse({
        authorityId,
        scopeKey,
        correctionEpoch: authority.correctionEpoch,
        actionId: persistentActionKey(fingerprint),
        actionFingerprint: fingerprint,
        useId: grant.useId,
        reservedAtMs,
        maximumReceipts: MAXIMUM_RECEIPTS,
      });
    } catch (error) {
      throw new UniversalBrokerError(
        "EXECUTION_STATE_UNKNOWN",
        "Task authority reservation outcome could not be confirmed; the action was not dispatched.",
        {
          evidence: {
            authorityId,
            actionId: selected.id,
            persistenceError: error instanceof Error ? error.name : "UNKNOWN_ERROR",
          },
        },
      );
    }
    if (!reservation.ok) {
      switch (reservation.code) {
        case "AUTHORITY_EXPIRED":
          this.remove(authority, false);
          throw new UniversalBrokerError(
            "AUTHORITY_EXPIRED",
            `Task authority is stale or expired: ${authorityId}`,
          );
        case "AUTHORITY_MISMATCH":
          throw new UniversalBrokerError(
            "AUTHORITY_MISMATCH",
            "Task authority no longer matches the exact persisted action or OAuth client.",
          );
        case "AUTHORITY_CONSUMED":
          selected.consumedUses = reservation.consumedUses ?? selected.maximumUses;
          throw new UniversalBrokerError(
            "AUTHORITY_CONSUMED",
            `Task authority action is fully consumed: ${selected.id}`,
            {
              evidence: {
                authorityId,
                actionId: selected.id,
                maximumUses: selected.maximumUses,
              },
            },
          );
        case "RESOURCE_QUOTA_EXCEEDED":
          throw new UniversalBrokerError(
            "RESOURCE_QUOTA_EXCEEDED",
            "Task authority has too many in-flight reservations; wait for terminal receipts.",
            {
              evidence: {
                authorityId,
                maximumReceipts: MAXIMUM_RECEIPTS,
              },
            },
          );
      }
    }
    selected.consumedUses = reservation.consumedUses;
    authority.receipts = trimReceipts([...authority.receipts, receipt]);
    return grant;
  }

  record(
    grant: AuthorityGrant | undefined,
    result: "PASS" | "FAIL" | "UNCERTAIN",
    evidence?: Record<string, unknown>,
  ): void {
    if (!grant) return;
    const authority = this.authorities.get(grant.authorityId);
    const receiptIndex = authority?.receipts.findIndex(
      (receipt) => receipt.useId === grant.useId && receipt.result === "PENDING",
    ) ?? -1;
    const completedAtMs = this.now();
    const boundedEvidence = evidence ? boundedRecord(evidence, 4_000) : undefined;
    let finalized: boolean;
    try {
      finalized = this.store.finalizeUse({
        authorityId: grant.authorityId,
        useId: grant.useId,
        completedAtMs,
        result,
        ...(typeof boundedEvidence?.errorCode === "string"
          ? { errorCode: boundedEvidence.errorCode }
          : {}),
        ...(typeof boundedEvidence?.reasonCode === "string"
          ? { reasonCode: boundedEvidence.reasonCode }
          : {}),
        maximumReceipts: MAXIMUM_RECEIPTS,
      });
    } catch (error) {
      throw new UniversalBrokerError(
        "EXECUTION_STATE_UNKNOWN",
        "The action completed, but its authority receipt could not be durably finalized.",
        {
          evidence: {
            authorityId: grant.authorityId,
            actionId: grant.actionId,
            persistenceError: error instanceof Error ? error.name : "UNKNOWN_ERROR",
          },
        },
      );
    }
    if (!finalized) {
      throw new UniversalBrokerError(
        "EXECUTION_STATE_UNKNOWN",
        "The authority reservation was no longer PENDING; it may already be terminal or recovered as UNCERTAIN.",
        {
          evidence: {
            authorityId: grant.authorityId,
            actionId: grant.actionId,
          },
        },
      );
    }
    if (!authority || receiptIndex < 0) return;
    const nextReceipt: AuthorityReceipt = {
      ...authority.receipts[receiptIndex]!,
      completedAtMs,
      result,
      ...(boundedEvidence ? { evidence: boundedEvidence } : {}),
    };
    authority.receipts = trimReceipts([
      ...authority.receipts.slice(0, receiptIndex),
      nextReceipt,
      ...authority.receipts.slice(receiptIndex + 1),
    ]);
  }

  status(authorityId: string, scopeId: string): Record<string, unknown> {
    this.pruneExpired();
    const authority = this.authorities.get(requiredText(authorityId, "authorityId is required.", 256));
    if (!authority || authority.scopeKey !== scopeKeyFor(scopeId)) {
      throw new UniversalBrokerError("AUTHORITY_EXPIRED", `Unknown task authority: ${authorityId}`);
    }
    if (authority.correctionEpoch !== this.correctionEpoch(authority.scopeKey)) {
      this.remove(authority, false);
      throw new UniversalBrokerError("AUTHORITY_EXPIRED", "Task authority was invalidated by a user correction.");
    }
    return this.present(authority, false);
  }

  invalidate(scopeId: string, correctionText: string): Record<string, unknown> {
    requiredText(correctionText, "context.invalidate_authority requires correctionText.", 8_000);
    const scopeKey = scopeKeyFor(scopeId);
    const correctionEpoch = this.store.incrementCorrectionEpoch(scopeKey, this.now());
    const invalidated: string[] = [];
    for (const authority of [...this.authorities.values()]) {
      if (authority.scopeKey !== scopeKey) continue;
      invalidated.push(authority.authorityId);
    }
    this.correctionEpochs.set(scopeKey, correctionEpoch);
    for (const authorityId of invalidated) {
      const authority = this.authorities.get(authorityId);
      if (authority) this.remove(authority, false);
    }
    return {
      correctionEpoch,
      invalidatedAuthorityIds: invalidated.sort(),
      correctionTextSha256: sha256(correctionText),
    };
  }

  release(authorityId: string, scopeId: string): Record<string, unknown> {
    const authority = this.authorities.get(requiredText(authorityId, "authorityId is required.", 256));
    if (!authority || authority.scopeKey !== scopeKeyFor(scopeId)) {
      throw new UniversalBrokerError("AUTHORITY_EXPIRED", `Unknown task authority: ${authorityId}`);
    }
    let released: ReturnType<DurableAuthorityStore["releaseAuthority"]>;
    try {
      released = this.store.releaseAuthority({
        authorityId: authority.authorityId,
        scopeKey: authority.scopeKey,
        correctionEpoch: authority.correctionEpoch,
      });
    } catch (error) {
      throw new UniversalBrokerError(
        "EXECUTION_STATE_UNKNOWN",
        "Task authority release outcome could not be confirmed.",
        {
          evidence: {
            authorityId,
            persistenceError: error instanceof Error ? error.name : "UNKNOWN_ERROR",
          },
        },
      );
    }
    if (!released.ok) {
      if (released.code === "PRECONDITION_FAILED") {
        throw new UniversalBrokerError(
          "PRECONDITION_FAILED",
          "A task authority with in-flight PENDING reservations cannot be released.",
          { evidence: { authorityId, pendingReceipts: released.pendingReceipts ?? 1 } },
        );
      }
      if (released.code === "AUTHORITY_MISMATCH") {
        throw new UniversalBrokerError(
          "AUTHORITY_MISMATCH",
          "Task authority belongs to a different authenticated OAuth client.",
        );
      }
      this.remove(authority, false);
      throw new UniversalBrokerError(
        "AUTHORITY_EXPIRED",
        `Task authority is stale, released, or expired: ${authorityId}`,
      );
    }
    this.remove(authority, false);
    return {
      authorityId,
      released: true,
      receipts: authority.receipts.length,
      unconsumedActions: authority.actions.filter((action) => action.consumedUses < action.maximumUses).length,
    };
  }

  stats(): Record<string, unknown> {
    this.pruneExpired();
    return {
      authorities: this.authorities.size,
      scopes: new Set([...this.authorities.values()].map((authority) => authority.scopeKey)).size,
      pendingReservations: [...this.authorities.values()].reduce(
        (total, authority) => total + authority.receipts.filter((receipt) => receipt.result === "PENDING").length,
        0,
      ),
      recoveredPendingUses: this.recoveredPendingUses,
      previews: this.previews,
    };
  }

  close(): void {
    this.store.close();
  }

  private prepareAction(
    action: RequestedAuthorityAction,
    index: number,
    allowR0: boolean,
  ): StoredAuthorityAction {
    if (!action || typeof action !== "object") {
      throw new UniversalBrokerError("PRECONDITION_FAILED", `Invalid authority action at index ${index}.`);
    }
    const source = action.descriptor;
    const descriptor: AuthorityActionDescriptor = {
      tool: source.tool,
      operation: requiredText(source.operation, `Authority action ${index} requires operation.`, 128),
      ...(source.target ? { target: requiredText(source.target, `Authority action ${index} target is invalid.`, 256) } : {}),
      ...(source.resource ? { resource: requiredText(source.resource, `Authority action ${index} resource is invalid.`, 2_048) } : {}),
      ...(source.parameters ? { parameters: boundedParameters(source.parameters, index) } : {}),
    };
    const operations = UNIVERSAL_TOOL_OPERATIONS[descriptor.tool] as readonly string[];
    if (!operations.includes(descriptor.operation)) {
      throw new UniversalBrokerError(
        "PRECONDITION_FAILED",
        `Authority action ${index} uses unsupported operation ${descriptor.tool}.${descriptor.operation}.`,
      );
    }
    const minimumRisk = this.minimumRisk(descriptor);
    if (minimumRisk === "R0" && !allowR0) {
      throw new UniversalBrokerError(
        "PRECONDITION_FAILED",
        `Authority action ${index} is R0 and must run without task authority: ${descriptor.tool}.${descriptor.operation}.`,
      );
    }
    const requestedRisk = action.risk ?? minimumRisk;
    if (!UNIVERSAL_AUTHORITY_RISKS.includes(requestedRisk)) {
      throw new UniversalBrokerError("PRECONDITION_FAILED", `Invalid authority risk at index ${index}.`);
    }
    if (minimumRisk === "R0" && (action.risk !== undefined || action.uses !== undefined)) {
      throw new UniversalBrokerError(
        "PRECONDITION_FAILED",
        `Authority preview action ${index} is R0; omit risk and uses because no authority is required.`,
      );
    }
    if (riskRank(requestedRisk) < riskRank(minimumRisk)) {
      throw new UniversalBrokerError(
        "PRECONDITION_FAILED",
        `Authority action ${index} requests ${requestedRisk}, but ${minimumRisk} is the minimum risk.`,
      );
    }
    const maximumForRisk = requestedRisk === "R3" ? 1 : requestedRisk === "R2" ? 10 : 50;
    const maximumUses = minimumRisk === "R0"
      ? 0
      : boundedInteger(action.uses, 1, 1, maximumForRisk, `actions[${index}].uses`);
    return {
      id: action.id === undefined
        ? `action-${index + 1}`
        : requiredText(action.id, `Authority action ${index} ID is invalid.`, 128),
      descriptor,
      fingerprint: actionFingerprint(descriptor),
      minimumRisk,
      risk: requestedRisk,
      maximumUses,
      consumedUses: 0,
    };
  }

  private present(authority: StoredOperationAuthority, reused: boolean): Record<string, unknown> {
    return {
      authorityId: authority.authorityId,
      ...(authority.taskId ? { taskId: authority.taskId } : {}),
      taskIdSha256: authority.taskIdSha256,
      correctionEpoch: authority.correctionEpoch,
      createdAt: new Date(authority.createdAtMs).toISOString(),
      expiresAt: new Date(authority.expiresAtMs).toISOString(),
      expired: authority.expiresAtMs <= this.now(),
      authorityTextSha256: authority.authorityTextSha256,
      reused,
      actions: authority.actions.map((action) => ({
        id: action.id,
        tool: action.descriptor.tool,
        operation: action.descriptor.operation,
        target: action.descriptor.target,
        resource: action.descriptor.resource,
        risk: action.risk,
        maximumUses: action.maximumUses,
        consumedUses: action.consumedUses,
      })),
      receipts: authority.receipts.map((receipt) => ({
        useId: receipt.useId,
        actionId: receipt.actionId,
        reservedAt: new Date(receipt.reservedAtMs).toISOString(),
        ...(receipt.completedAtMs === undefined
          ? {}
          : {
              completedAt: new Date(receipt.completedAtMs).toISOString(),
              recordedAt: new Date(receipt.completedAtMs).toISOString(),
            }),
        result: receipt.result,
        ...(receipt.evidence ? { evidence: receipt.evidence } : {}),
      })),
    };
  }

  private correctionEpoch(scopeKey: string): number {
    const correctionEpoch = this.store.currentCorrectionEpoch(scopeKey);
    this.correctionEpochs.set(scopeKey, correctionEpoch);
    return correctionEpoch;
  }

  private dropStaleScopeAuthorities(scopeKey: string, correctionEpoch: number): void {
    for (const authority of [...this.authorities.values()]) {
      if (authority.scopeKey === scopeKey && authority.correctionEpoch !== correctionEpoch) {
        this.remove(authority, false);
      }
    }
  }

  private pruneExpired(): void {
    const now = this.now();
    const purgedAuthorityIds = this.store.deleteAuthoritiesExpiredBefore(
      now - AUTHORITY_RECEIPT_RETENTION_MS,
    );
    for (const authorityId of purgedAuthorityIds) {
      const authority = this.authorities.get(authorityId);
      if (authority) this.remove(authority, false);
    }
    for (const authority of this.authorities.values()) {
      if (
        authority.expiresAtMs <= now
        && this.authorityIdsByFingerprint.get(authority.fingerprint) === authority.authorityId
      ) {
        this.authorityIdsByFingerprint.delete(authority.fingerprint);
      }
    }
  }

  private remove(authority: StoredOperationAuthority, persist = true): void {
    if (persist) this.store.deleteAuthorities([authority.authorityId]);
    this.authorities.delete(authority.authorityId);
    if (this.authorityIdsByFingerprint.get(authority.fingerprint) === authority.authorityId) {
      this.authorityIdsByFingerprint.delete(authority.fingerprint);
    }
  }

  private assertAuthorityCapacity(scopeKey: string): void {
    const now = this.now();
    const activeAuthorities = [...this.authorities.values()].filter(
      (authority) => authority.expiresAtMs > now,
    );
    const scopeAuthorities = activeAuthorities.filter(
      (authority) => authority.scopeKey === scopeKey,
    ).length;
    if (
      activeAuthorities.length >= MAXIMUM_ACTIVE_AUTHORITIES
      || scopeAuthorities >= MAXIMUM_ACTIVE_AUTHORITIES_PER_SCOPE
    ) {
      throw new UniversalBrokerError(
        "RESOURCE_QUOTA_EXCEEDED",
        "Operation authority quota is full; release or wait for existing authorities to expire.",
        {
          evidence: {
            authorities: activeAuthorities.length,
            maximumAuthorities: MAXIMUM_ACTIVE_AUTHORITIES,
            scopeAuthorities,
            maximumAuthoritiesPerScope: MAXIMUM_ACTIVE_AUTHORITIES_PER_SCOPE,
          },
        },
      );
    }
  }

  private toDurable(authority: StoredOperationAuthority): DurableAuthorityRecord {
    const persistentActionIds = new Map(
      authority.actions.map((action) => [action.id, persistentActionKey(action.fingerprint)]),
    );
    return {
      authorityId: authority.authorityId,
      taskIdSha256: authority.taskIdSha256,
      authorityTextSha256: authority.authorityTextSha256,
      scopeKey: authority.scopeKey,
      correctionEpoch: authority.correctionEpoch,
      createdAtMs: authority.createdAtMs,
      expiresAtMs: authority.expiresAtMs,
      fingerprint: authority.fingerprint,
      actions: authority.actions.map((action) => ({
        id: persistentActionKey(action.fingerprint),
        tool: action.descriptor.tool,
        operation: action.descriptor.operation,
        fingerprint: action.fingerprint,
        minimumRisk: action.minimumRisk,
        risk: action.risk,
        maximumUses: action.maximumUses,
        consumedUses: action.consumedUses,
      })),
      receipts: authority.receipts.map((receipt) => {
        const actionId = persistentActionIds.get(receipt.actionId);
        if (!actionId) {
          throw new Error(`Authority receipt references an unknown in-memory action: ${receipt.actionId}`);
        }
        return {
          useId: receipt.useId,
          actionId,
          reservedAtMs: receipt.reservedAtMs,
          ...(receipt.completedAtMs === undefined ? {} : { completedAtMs: receipt.completedAtMs }),
          result: receipt.result,
          ...(typeof receipt.evidence?.errorCode === "string"
            ? { errorCode: receipt.evidence.errorCode }
            : {}),
          ...(typeof receipt.evidence?.reasonCode === "string"
            ? { reasonCode: receipt.evidence.reasonCode }
            : {}),
        };
      }),
    };
  }

  private fromDurable(record: DurableAuthorityRecord): StoredOperationAuthority {
    return {
      authorityId: record.authorityId,
      taskIdSha256: record.taskIdSha256,
      authorityTextSha256: record.authorityTextSha256,
      scopeKey: record.scopeKey,
      correctionEpoch: record.correctionEpoch,
      createdAtMs: record.createdAtMs,
      expiresAtMs: record.expiresAtMs,
      fingerprint: record.fingerprint,
      actions: record.actions.map((action) => ({
        id: action.id,
        descriptor: {
          tool: persistedTool(action.tool),
          operation: action.operation,
        },
        fingerprint: action.fingerprint,
        minimumRisk: persistedRisk(action.minimumRisk),
        risk: persistedRisk(action.risk),
        maximumUses: action.maximumUses,
        consumedUses: action.consumedUses,
      })),
      receipts: record.receipts.map((receipt) => ({
        useId: receipt.useId,
        actionId: receipt.actionId,
        reservedAtMs: receipt.reservedAtMs,
        ...(receipt.completedAtMs === undefined ? {} : { completedAtMs: receipt.completedAtMs }),
        result: receipt.result,
        ...(receipt.errorCode || receipt.reasonCode
          ? {
              evidence: {
                ...(receipt.errorCode ? { errorCode: receipt.errorCode } : {}),
                ...(receipt.reasonCode ? { reasonCode: receipt.reasonCode } : {}),
              },
            }
          : {}),
      })),
    };
  }
}

export function actionFingerprint(action: AuthorityActionDescriptor): string {
  return sha256(stableJson(normalizeAction(action)));
}

export function authorityRiskAtLeast(actual: AuthorityRiskClass, required: AuthorityRiskClass): boolean {
  return riskRank(actual) >= riskRank(required);
}

function normalizeAction(action: AuthorityActionDescriptor): Record<string, unknown> {
  return {
    tool: action.tool,
    operation: action.operation.trim(),
    ...(action.target?.trim() ? { target: action.target.trim() } : {}),
    ...(action.resource?.trim() ? { resource: action.resource.trim() } : {}),
    ...(action.parameters ? { parameters: normalizeValue(action.parameters) } : {}),
  };
}

function normalizeValue(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(normalizeValue);
  if (value && typeof value === "object") {
    return Object.fromEntries(
      Object.entries(value as Record<string, unknown>)
        .filter(([, child]) => child !== undefined)
        .sort(([left], [right]) => left.localeCompare(right))
        .map(([key, child]) => [key, normalizeValue(child)]),
    );
  }
  return value;
}

function boundedParameters(value: Record<string, unknown>, index: number): Record<string, unknown> {
  const normalized = normalizeValue(value) as Record<string, unknown>;
  const characters = JSON.stringify(normalized).length;
  if (characters > MAXIMUM_ACTION_PARAMETERS_CHARACTERS) {
    throw new UniversalBrokerError(
      "PRECONDITION_FAILED",
      `Authority action ${index} parameters use ${characters} characters; limit is ${MAXIMUM_ACTION_PARAMETERS_CHARACTERS}.`,
    );
  }
  return normalized;
}

function boundedAction(action: AuthorityActionDescriptor): Record<string, unknown> {
  const normalized = normalizeAction(action);
  const serialized = JSON.stringify(normalized);
  return serialized.length <= 4_000
    ? normalized
    : { tool: action.tool, operation: action.operation, fingerprint: actionFingerprint(action) };
}

function boundedRecord(value: Record<string, unknown>, maximumCharacters: number): Record<string, unknown> {
  const normalized = normalizeValue(value) as Record<string, unknown>;
  const serialized = JSON.stringify(normalized);
  return serialized.length <= maximumCharacters
    ? normalized
    : { truncated: true, sha256: sha256(serialized), characters: serialized.length };
}

function assertUniqueActionIds(actions: StoredAuthorityAction[]): void {
  const ids = new Set<string>();
  for (const action of actions) {
    if (ids.has(action.id)) {
      throw new UniversalBrokerError("PRECONDITION_FAILED", `Duplicate authority action ID: ${action.id}`);
    }
    ids.add(action.id);
  }
}

function assertUniqueActionFingerprints(actions: StoredAuthorityAction[]): void {
  const fingerprints = new Map<string, string>();
  for (const action of actions) {
    const previous = fingerprints.get(action.fingerprint);
    if (previous) {
      throw new UniversalBrokerError(
        "PRECONDITION_FAILED",
        `Duplicate exact authority actions ${previous} and ${action.id}; combine repeated identical calls with one action and uses.`,
      );
    }
    fingerprints.set(action.fingerprint, action.id);
  }
}

function trimReceipts(receipts: AuthorityReceipt[]): AuthorityReceipt[] {
  if (receipts.length <= MAXIMUM_RECEIPTS) return receipts;
  const pending = receipts.filter((receipt) => receipt.result === "PENDING");
  const terminalCapacity = Math.max(0, MAXIMUM_RECEIPTS - pending.length);
  const terminal = receipts.filter((receipt) => receipt.result !== "PENDING");
  const retainedTerminalIds = new Set(
    terminal.slice(Math.max(0, terminal.length - terminalCapacity)).map((receipt) => receipt.useId),
  );
  return receipts.filter(
    (receipt) => receipt.result === "PENDING" || retainedTerminalIds.has(receipt.useId),
  );
}

function scopeKeyFor(scopeId: string): string {
  return sha256(requiredText(scopeId, "Authenticated authority scope is required.", 2_048));
}

function persistentActionKey(fingerprint: string): string {
  return `action_${fingerprint}`;
}

function persistedTool(value: string): UniversalToolName {
  if (!Object.prototype.hasOwnProperty.call(UNIVERSAL_TOOL_OPERATIONS, value)) {
    throw new Error(`Invalid persisted authority tool: ${value}`);
  }
  return value as UniversalToolName;
}

function persistedRisk(value: string): AuthorityRiskClass {
  if (!UNIVERSAL_AUTHORITY_RISKS.includes(value as AuthorityRiskClass)) {
    throw new Error(`Invalid persisted authority risk: ${value}`);
  }
  return value as AuthorityRiskClass;
}

function riskRank(risk: AuthorityRiskClass): number {
  return UNIVERSAL_AUTHORITY_RISKS.indexOf(risk);
}

function sha256(value: string): string {
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

function requiredText(value: string | undefined, message: string, maximum: number): string {
  const normalized = value?.trim();
  if (!normalized) throw new UniversalBrokerError("PRECONDITION_FAILED", message);
  if (normalized.length > maximum) {
    throw new UniversalBrokerError(
      "PRECONDITION_FAILED",
      `${message} Maximum characters: ${maximum}.`,
    );
  }
  return normalized;
}

function boundedInteger(
  value: number | undefined,
  fallback: number,
  minimum: number,
  maximum: number,
  name: string,
): number {
  const parsed = value ?? fallback;
  if (!Number.isInteger(parsed) || parsed < minimum || parsed > maximum) {
    throw new UniversalBrokerError(
      "PRECONDITION_FAILED",
      `${name} must be an integer from ${minimum} through ${maximum}.`,
    );
  }
  return parsed;
}
