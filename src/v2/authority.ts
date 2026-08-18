import { createHash, randomUUID } from "node:crypto";
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
  risk: AuthorityRiskClass;
  maximumUses: number;
  consumedUses: number;
}

interface StoredOperationAuthority {
  authorityId: string;
  taskId: string;
  authorityTextSha256: string;
  scopeId: string;
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
  recordedAt: string;
  result: "PASS" | "FAIL" | "UNCERTAIN";
  evidence?: Record<string, unknown>;
}

export interface OperationAuthorityRegistryOptions {
  now?: () => number;
  minimumRisk?: (action: AuthorityActionDescriptor) => AuthorityRiskClass;
}

const DEFAULT_AUTHORITY_TTL_SECONDS = 15 * 60;
const MAXIMUM_AUTHORITY_TTL_SECONDS = 8 * 60 * 60;
const MAXIMUM_ACTIONS = 64;
const MAXIMUM_AUTHORITY_TEXT_CHARACTERS = 8_000;
const MAXIMUM_ACTION_PARAMETERS_CHARACTERS = 16_000;
const MAXIMUM_RECEIPTS = 256;

export class OperationAuthorityRegistry {
  private readonly now: () => number;
  private readonly minimumRisk: (action: AuthorityActionDescriptor) => AuthorityRiskClass;
  private readonly authorities = new Map<string, StoredOperationAuthority>();
  private readonly correctionEpochs = new Map<string, number>();
  private readonly authorityIdsByFingerprint = new Map<string, string>();

  constructor(options: OperationAuthorityRegistryOptions = {}) {
    this.now = options.now ?? Date.now;
    this.minimumRisk = options.minimumRisk ?? (() => "R1");
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
    const correctionEpoch = this.correctionEpoch(scopeId);
    const actions = input.actions.map((action, index) => this.prepareAction(action, index));
    assertUniqueActionIds(actions);
    const expiresInSeconds = boundedInteger(
      input.expiresInSeconds,
      DEFAULT_AUTHORITY_TTL_SECONDS,
      60,
      MAXIMUM_AUTHORITY_TTL_SECONDS,
      "expiresInSeconds",
    );
    const fingerprint = sha256(stableJson({
      scopeId,
      correctionEpoch,
      taskId,
      authorityText,
      actions: actions.map((action) => ({
        id: action.id,
        descriptor: action.descriptor,
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

    const createdAtMs = this.now();
    const authority: StoredOperationAuthority = {
      authorityId: `authority_${randomUUID()}`,
      taskId,
      authorityTextSha256: sha256(authorityText),
      scopeId,
      correctionEpoch,
      createdAtMs,
      expiresAtMs: createdAtMs + expiresInSeconds * 1_000,
      fingerprint,
      actions,
      receipts: [],
    };
    this.authorities.set(authority.authorityId, authority);
    this.authorityIdsByFingerprint.set(fingerprint, authority.authorityId);
    return this.present(authority, false);
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
    if (authority.scopeId !== scopeId) {
      throw new UniversalBrokerError(
        "AUTHORITY_MISMATCH",
        "Task authority belongs to a different MCP session or OAuth client.",
      );
    }
    if (authority.correctionEpoch !== this.correctionEpoch(scopeId)) {
      this.remove(authority);
      throw new UniversalBrokerError(
        "AUTHORITY_EXPIRED",
        `Task authority is stale after a correction: ${authorityId}`,
      );
    }
    if (authority.expiresAtMs <= this.now()) {
      this.remove(authority);
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
    selected.consumedUses += 1;
    return {
      authorityId,
      actionId: selected.id,
      useId: `authority_use_${randomUUID()}`,
      risk: requiredRisk,
      fingerprint,
    };
  }

  record(
    grant: AuthorityGrant | undefined,
    result: AuthorityReceipt["result"],
    evidence?: Record<string, unknown>,
  ): void {
    if (!grant) return;
    const authority = this.authorities.get(grant.authorityId);
    if (!authority) return;
    authority.receipts.push({
      useId: grant.useId,
      actionId: grant.actionId,
      recordedAt: new Date(this.now()).toISOString(),
      result,
      ...(evidence ? { evidence: boundedRecord(evidence, 4_000) } : {}),
    });
    if (authority.receipts.length > MAXIMUM_RECEIPTS) {
      authority.receipts.splice(0, authority.receipts.length - MAXIMUM_RECEIPTS);
    }
  }

  status(authorityId: string, scopeId: string): Record<string, unknown> {
    this.pruneExpired();
    const authority = this.authorities.get(requiredText(authorityId, "authorityId is required.", 256));
    if (!authority || authority.scopeId !== scopeId) {
      throw new UniversalBrokerError("AUTHORITY_EXPIRED", `Unknown task authority: ${authorityId}`);
    }
    return this.present(authority, false);
  }

  invalidate(scopeId: string, correctionText: string): Record<string, unknown> {
    requiredText(correctionText, "context.invalidate_authority requires correctionText.", 8_000);
    const previousEpoch = this.correctionEpoch(scopeId);
    const correctionEpoch = previousEpoch + 1;
    this.correctionEpochs.set(scopeId, correctionEpoch);
    const invalidated: string[] = [];
    for (const authority of [...this.authorities.values()]) {
      if (authority.scopeId !== scopeId) continue;
      invalidated.push(authority.authorityId);
      this.remove(authority);
    }
    return {
      correctionEpoch,
      invalidatedAuthorityIds: invalidated.sort(),
      correctionTextSha256: sha256(correctionText),
    };
  }

  release(authorityId: string, scopeId: string): Record<string, unknown> {
    const authority = this.authorities.get(requiredText(authorityId, "authorityId is required.", 256));
    if (!authority || authority.scopeId !== scopeId) {
      throw new UniversalBrokerError("AUTHORITY_EXPIRED", `Unknown task authority: ${authorityId}`);
    }
    this.remove(authority);
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
      scopes: new Set([...this.authorities.values()].map((authority) => authority.scopeId)).size,
    };
  }

  private prepareAction(action: RequestedAuthorityAction, index: number): StoredAuthorityAction {
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
    if (minimumRisk === "R0") {
      throw new UniversalBrokerError(
        "PRECONDITION_FAILED",
        `Authority action ${index} is R0 and must run without task authority: ${descriptor.tool}.${descriptor.operation}.`,
      );
    }
    const requestedRisk = action.risk ?? minimumRisk;
    if (!UNIVERSAL_AUTHORITY_RISKS.includes(requestedRisk)) {
      throw new UniversalBrokerError("PRECONDITION_FAILED", `Invalid authority risk at index ${index}.`);
    }
    if (riskRank(requestedRisk) < riskRank(minimumRisk)) {
      throw new UniversalBrokerError(
        "PRECONDITION_FAILED",
        `Authority action ${index} requests ${requestedRisk}, but ${minimumRisk} is the minimum risk.`,
      );
    }
    const maximumForRisk = requestedRisk === "R3" ? 1 : requestedRisk === "R2" ? 10 : 50;
    const maximumUses = boundedInteger(action.uses, 1, 1, maximumForRisk, `actions[${index}].uses`);
    return {
      id: action.id?.trim() || `action-${index + 1}`,
      descriptor,
      fingerprint: actionFingerprint(descriptor),
      risk: requestedRisk,
      maximumUses,
      consumedUses: 0,
    };
  }

  private present(authority: StoredOperationAuthority, reused: boolean): Record<string, unknown> {
    return {
      authorityId: authority.authorityId,
      taskId: authority.taskId,
      correctionEpoch: authority.correctionEpoch,
      createdAt: new Date(authority.createdAtMs).toISOString(),
      expiresAt: new Date(authority.expiresAtMs).toISOString(),
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
      receipts: authority.receipts.map((receipt) => ({ ...receipt })),
    };
  }

  private correctionEpoch(scopeId: string): number {
    return this.correctionEpochs.get(scopeId) ?? 0;
  }

  private pruneExpired(): void {
    const now = this.now();
    for (const authority of [...this.authorities.values()]) {
      if (authority.expiresAtMs <= now) this.remove(authority);
    }
  }

  private remove(authority: StoredOperationAuthority): void {
    this.authorities.delete(authority.authorityId);
    if (this.authorityIdsByFingerprint.get(authority.fingerprint) === authority.authorityId) {
      this.authorityIdsByFingerprint.delete(authority.fingerprint);
    }
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
