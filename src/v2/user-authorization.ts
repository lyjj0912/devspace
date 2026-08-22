import { createHash, randomUUID } from "node:crypto";
import type { ChildProcessWithoutNullStreams } from "node:child_process";
import type {
  AuthorizationState,
  RuntimeIdentity,
} from "./contracts.js";
import type { CapabilityCallContext } from "./capability-call-context.js";
import type { NormalizedExecutionElevation } from "./elevation.js";
import { UniversalBrokerError } from "./errors.js";

const SHA256_PATTERN = /^sha256:[a-f0-9]{64}$/u;
const PRINCIPAL_PATTERN = /^[a-f0-9]{64}$/u;
const SAFE_ID_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,255}$/u;
const MAX_COMMAND_CHARACTERS = 100_000;
const MAX_CWD_CHARACTERS = 32_768;
const MAX_ARGUMENTS = 4_096;
const MAX_ARGUMENT_CHARACTERS = 32_768;

export type UserAuthorizationDecisionState = Exclude<
  AuthorizationState,
  "NOT_REQUIRED" | "PENDING"
>;

export interface UserAuthorizationActionIdentity {
  commandDigest: string;
  commandCharacters: number;
  cwdDigest: string;
  cwdCharacters: number;
  mode: "auto" | "foreground" | "background";
  tty: boolean;
  reasonDigest: string;
  reasonCharacters: number;
  timeoutMs: number;
  envProfileDigest?: string;
}

export interface UserAuthorizationDescriptor {
  schemaVersion: 1;
  authorizationOperationId: string;
  principalFingerprint: string;
  explicitRequestIdDigest?: string;
  explicitRequestKey?: string;
  correlationRequestIdDigest?: string;
  requestNamespaceDigest: string;
  target: {
    id: string;
    generation: string;
    transport: "local" | "ssh";
    platform: string;
  };
  runtime: Pick<
    RuntimeIdentity,
    | "productProfile"
    | "sourceRevision"
    | "runtimeRevision"
    | "buildDigest"
    | "schemaGeneration"
    | "startedAt"
  >;
  action: UserAuthorizationActionIdentity;
  actionDigest: string;
  issuedAt: string;
  expiresAt: string;
  nonce: string;
  descriptorDigest: string;
}

export interface UserAuthorizationReceipt {
  schemaVersion: 1;
  receiptId: string;
  authorizationOperationId: string;
  descriptorDigest: string;
  actionDigest: string;
  decision: UserAuthorizationDecisionState;
  providerId: string;
  providerGeneration: string;
  decidedAt: string;
  expiresAt: string;
  helperIdentityDigest?: string;
  evidenceDigest?: string;
  receiptDigest: string;
}

export interface UserAuthorizationProviderRequest {
  descriptor: UserAuthorizationDescriptor;
  command: string;
  cwd: string;
  environment?: Record<string, string>;
  elevation: NormalizedExecutionElevation & { mode: "prompt" };
}

export interface UserAuthorizationProviderDecision {
  receipt: UserAuthorizationReceipt;
}

export interface UserAuthorizationProviderLaunchRequest extends UserAuthorizationProviderRequest {
  receipt: UserAuthorizationReceipt;
}

export interface UserAuthorizationProviderCapability {
  available: boolean;
  providerId: string;
  providerGeneration: string;
  mechanism: "macos-authorization-services" | "linux-polkit" | "windows-uac";
  reason?: string;
}

export interface UserAuthorizationProvider {
  capability(input: {
    targetId: string;
    targetGeneration: string;
    platform: string;
  }): Promise<UserAuthorizationProviderCapability> | UserAuthorizationProviderCapability;
  authorize(
    request: UserAuthorizationProviderRequest,
  ): Promise<UserAuthorizationProviderDecision>;
  launch(
    request: UserAuthorizationProviderLaunchRequest,
  ): Promise<ChildProcessWithoutNullStreams>;
  close?(): Promise<void> | void;
}

export function createUserAuthorizationDescriptor(input: {
  authorizationOperationId: string;
  callContext: CapabilityCallContext;
  target: {
    id: string;
    generation: string;
    transport: "local" | "ssh";
    platform: string;
  };
  runtimeIdentity: RuntimeIdentity;
  command: string;
  cwd: string;
  mode: "auto" | "foreground" | "background";
  tty: boolean;
  envProfile?: string;
  elevation: NormalizedExecutionElevation & { mode: "prompt" };
  issuedAt?: string;
  nonce?: string;
}): UserAuthorizationDescriptor {
  const authorizationOperationId = safeId(
    input.authorizationOperationId,
    "authorizationOperationId",
  );
  const principalFingerprint = input.callContext.principalKeyFingerprint.trim().toLowerCase();
  if (!PRINCIPAL_PATTERN.test(principalFingerprint)) {
    throw invalid("Authorization principal fingerprint is invalid.");
  }
  const requestNamespace = requiredSingleLine(
    input.callContext.requestNamespace,
    "requestNamespace",
    1_024,
  );
  const explicitRequestId = optionalSingleLine(
    input.callContext.explicitRequestId,
    "explicitRequestId",
    512,
  );
  const correlationRequestId = optionalSingleLine(
    input.callContext.requestId,
    "requestId",
    512,
  );
  if (explicitRequestId && correlationRequestId && explicitRequestId !== correlationRequestId) {
    throw invalid("Explicit request identity does not match the trusted correlation identity.");
  }
  const command = requiredText(input.command, "command", MAX_COMMAND_CHARACTERS);
  const cwd = requiredText(input.cwd, "cwd", MAX_CWD_CHARACTERS);
  const issuedAt = timestamp(input.issuedAt ?? new Date().toISOString(), "issuedAt");
  const issuedAtMs = Date.parse(issuedAt);
  const expiresAt = new Date(issuedAtMs + input.elevation.timeoutMs).toISOString();
  const reason = requiredSingleLine(input.elevation.reason, "elevation.reason", 2_000);
  const nonce = safeId(input.nonce ?? randomUUID(), "nonce");
  const target = {
    id: safeId(input.target.id, "target.id"),
    generation: requiredDigest(input.target.generation, "target.generation"),
    transport: input.target.transport,
    platform: safeId(input.target.platform, "target.platform"),
  } satisfies UserAuthorizationDescriptor["target"];
  const runtime = runtimeDescriptor(input.runtimeIdentity);
  const action: UserAuthorizationActionIdentity = {
    commandDigest: digestText(command),
    commandCharacters: command.length,
    cwdDigest: digestText(cwd),
    cwdCharacters: cwd.length,
    mode: input.mode,
    tty: input.tty,
    reasonDigest: digestText(reason),
    reasonCharacters: reason.length,
    timeoutMs: input.elevation.timeoutMs,
    ...(input.envProfile
      ? { envProfileDigest: digestText(requiredSingleLine(input.envProfile, "envProfile", 256)) }
      : {}),
  };
  const explicitRequestIdDigest = explicitRequestId
    ? digestText(explicitRequestId)
    : undefined;
  const explicitRequestKey = explicitRequestIdDigest
    ? digestUserAuthorizationValue({ principalFingerprint, explicitRequestIdDigest })
    : undefined;
  const actionDigest = digestUserAuthorizationValue({
    principalFingerprint,
    ...(explicitRequestIdDigest
      ? { explicitRequestIdDigest }
      : { requestNamespaceDigest: digestText(requestNamespace) }),
    target,
    runtime: stableRuntimeActionIdentity(runtime),
    action,
  });
  const unsigned = {
    schemaVersion: 1 as const,
    authorizationOperationId,
    principalFingerprint,
    ...(explicitRequestIdDigest ? { explicitRequestIdDigest } : {}),
    ...(explicitRequestKey ? { explicitRequestKey } : {}),
    ...(correlationRequestId ? { correlationRequestIdDigest: digestText(correlationRequestId) } : {}),
    requestNamespaceDigest: digestText(requestNamespace),
    target,
    runtime,
    action,
    actionDigest,
    issuedAt,
    expiresAt,
    nonce,
  };
  return Object.freeze({
    ...unsigned,
    descriptorDigest: digestUserAuthorizationValue(unsigned),
  });
}

export function createUserAuthorizationReceipt(input: {
  descriptor: UserAuthorizationDescriptor;
  decision: UserAuthorizationDecisionState;
  providerId: string;
  providerGeneration: string;
  decidedAt?: string;
  expiresAt?: string;
  receiptId?: string;
  helperIdentityDigest?: string;
  evidence?: unknown;
}): UserAuthorizationReceipt {
  verifyUserAuthorizationDescriptor(input.descriptor);
  const decidedAt = timestamp(input.decidedAt ?? new Date().toISOString(), "decidedAt");
  const expiresAt = timestamp(input.expiresAt ?? input.descriptor.expiresAt, "expiresAt");
  if (Date.parse(decidedAt) > Date.parse(expiresAt)) {
    throw invalid("Authorization receipt decision is later than its expiry.");
  }
  const unsigned = {
    schemaVersion: 1 as const,
    receiptId: safeId(input.receiptId ?? randomUUID(), "receiptId"),
    authorizationOperationId: input.descriptor.authorizationOperationId,
    descriptorDigest: input.descriptor.descriptorDigest,
    actionDigest: input.descriptor.actionDigest,
    decision: input.decision,
    providerId: safeId(input.providerId, "providerId"),
    providerGeneration: requiredDigest(input.providerGeneration, "providerGeneration"),
    decidedAt,
    expiresAt,
    ...(input.helperIdentityDigest
      ? { helperIdentityDigest: requiredDigest(input.helperIdentityDigest, "helperIdentityDigest") }
      : {}),
    ...(input.evidence === undefined
      ? {}
      : { evidenceDigest: digestUserAuthorizationValue(input.evidence) }),
  };
  return Object.freeze({
    ...unsigned,
    receiptDigest: digestUserAuthorizationValue(unsigned),
  });
}

export function verifyUserAuthorizationDescriptor(
  descriptor: UserAuthorizationDescriptor,
): void {
  const { descriptorDigest, ...unsigned } = descriptor;
  if (
    descriptor.schemaVersion !== 1
    || !SHA256_PATTERN.test(descriptorDigest)
    || digestUserAuthorizationValue(unsigned) !== descriptorDigest
    || digestUserAuthorizationValue({
      principalFingerprint: descriptor.principalFingerprint,
      ...(descriptor.explicitRequestIdDigest
        ? { explicitRequestIdDigest: descriptor.explicitRequestIdDigest }
        : { requestNamespaceDigest: descriptor.requestNamespaceDigest }),
      target: descriptor.target,
      runtime: stableRuntimeActionIdentity(descriptor.runtime),
      action: descriptor.action,
    }) !== descriptor.actionDigest
  ) {
    throw stateCorrupted("User authorization descriptor digest is invalid.");
  }
  if (
    descriptor.explicitRequestIdDigest
    && digestUserAuthorizationValue({
      principalFingerprint: descriptor.principalFingerprint,
      explicitRequestIdDigest: descriptor.explicitRequestIdDigest,
    }) !== descriptor.explicitRequestKey
  ) {
    throw stateCorrupted("User authorization explicit request key is invalid.");
  }
  if (!descriptor.explicitRequestIdDigest && descriptor.explicitRequestKey) {
    throw stateCorrupted("User authorization request key exists without an explicit request ID.");
  }
}

export function verifyUserAuthorizationReceipt(receipt: UserAuthorizationReceipt): void {
  const { receiptDigest, ...unsigned } = receipt;
  if (
    receipt.schemaVersion !== 1
    || !SHA256_PATTERN.test(receiptDigest)
    || digestUserAuthorizationValue(unsigned) !== receiptDigest
  ) {
    throw stateCorrupted("User authorization receipt digest is invalid.");
  }
}

export function digestUserAuthorizationValue(value: unknown): string {
  return `sha256:${createHash("sha256").update(canonicalAuthorizationJson(value)).digest("hex")}`;
}

export function digestAuthorizationCommand(executable: string, args: readonly string[]): string {
  const normalizedExecutable = requiredText(executable, "executable", MAX_CWD_CHARACTERS);
  if (!normalizedExecutable.startsWith("/")) {
    throw invalid("Authorized executable must be an absolute path.");
  }
  if (args.length > MAX_ARGUMENTS) throw invalid("Authorized command has too many arguments.");
  return digestUserAuthorizationValue({
    executable: normalizedExecutable,
    args: args.map((argument, index) => requiredText(
      argument,
      `args[${index}]`,
      MAX_ARGUMENT_CHARACTERS,
      true,
    )),
  });
}

function runtimeDescriptor(identity: RuntimeIdentity): UserAuthorizationDescriptor["runtime"] {
  return {
    productProfile: identity.productProfile,
    sourceRevision: safeId(identity.sourceRevision, "runtime.sourceRevision"),
    runtimeRevision: safeId(identity.runtimeRevision, "runtime.runtimeRevision"),
    buildDigest: requiredDigest(identity.buildDigest, "runtime.buildDigest"),
    schemaGeneration: requiredDigest(identity.schemaGeneration, "runtime.schemaGeneration"),
    startedAt: timestamp(identity.startedAt, "runtime.startedAt"),
  };
}

function stableRuntimeActionIdentity(
  runtime: UserAuthorizationDescriptor["runtime"],
): Omit<UserAuthorizationDescriptor["runtime"], "startedAt"> {
  const { startedAt: _startedAt, ...stable } = runtime;
  return stable;
}

function canonicalAuthorizationJson(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(canonicalAuthorizationJson).join(",")}]`;
  if (value && typeof value === "object") {
    return `{${Object.entries(value as Record<string, unknown>)
      .filter(([, child]) => child !== undefined)
      .sort(([left], [right]) => left < right ? -1 : left > right ? 1 : 0)
      .map(([key, child]) => `${JSON.stringify(key)}:${canonicalAuthorizationJson(child)}`)
      .join(",")}}`;
  }
  return JSON.stringify(value) ?? "null";
}

function digestText(value: string): string {
  return `sha256:${createHash("sha256").update(value).digest("hex")}`;
}

function requiredDigest(value: string, field: string): string {
  const normalized = value.trim().toLowerCase();
  if (!SHA256_PATTERN.test(normalized)) throw invalid(`${field} must be a SHA-256 digest.`);
  return normalized;
}

function safeId(value: string, field: string): string {
  const normalized = value.trim();
  if (!SAFE_ID_PATTERN.test(normalized)) throw invalid(`${field} contains unsafe characters.`);
  return normalized;
}

function requiredSingleLine(value: string | undefined, field: string, maximum: number): string {
  const normalized = value?.trim();
  if (!normalized || normalized.length > maximum || /[\0\r\n]/u.test(normalized)) {
    throw invalid(`${field} must be a single line of at most ${maximum} characters.`);
  }
  return normalized;
}

function optionalSingleLine(value: string | undefined, field: string, maximum: number): string | undefined {
  return value === undefined ? undefined : requiredSingleLine(value, field, maximum);
}

function requiredText(value: string, field: string, maximum: number, allowEmpty = false): string {
  if (
    typeof value !== "string"
    || value.length > maximum
    || value.includes("\0")
    || (!allowEmpty && value.length === 0)
  ) throw invalid(`${field} is invalid or exceeds ${maximum} characters.`);
  return value;
}

function timestamp(value: string, field: string): string {
  const normalized = value.trim();
  if (!normalized || !Number.isFinite(Date.parse(normalized))) {
    throw invalid(`${field} must be an ISO-8601 timestamp.`);
  }
  return new Date(normalized).toISOString();
}

function invalid(message: string): UniversalBrokerError {
  return new UniversalBrokerError("INVALID_ARGUMENT", message, {
    evidence: { providerDispatchCount: 0 },
  });
}

function stateCorrupted(message: string): UniversalBrokerError {
  return new UniversalBrokerError("STATE_CORRUPTED", message, {
    evidence: { providerDispatchCount: 0 },
  });
}
