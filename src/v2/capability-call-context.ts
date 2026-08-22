import { AsyncLocalStorage } from "node:async_hooks";
import { UniversalBrokerError } from "./errors.js";

const PRINCIPAL_FINGERPRINT_PATTERN = /^[a-f0-9]{64}$/;
const trustedContexts = new WeakSet<object>();
const storage = new AsyncLocalStorage<CapabilityCallContext>();
declare const capabilityCallContextBrand: unique symbol;

/**
 * Authenticated request identity supplied by the broker boundary, never by tool
 * arguments. The unexported runtime trust mark prevents structurally similar
 * model input from being accepted as an ownership credential.
 */
export type CapabilityCallContext = Readonly<{
  principalKeyFingerprint: string;
  requestId?: string;
  explicitRequestId?: string;
  requestNamespace?: string;
  receivedAt?: string;
  [capabilityCallContextBrand]: true;
}>;

export type CapabilityCallContextProvider = () => CapabilityCallContext | undefined;

export interface TrustedCapabilityPrincipal {
  principalKeyFingerprint: string;
  requestId?: string;
  explicitRequestId?: string;
  requestNamespace?: string;
  receivedAt?: string;
}

export function createCapabilityCallContextFromTrustedPrincipal(
  principal: TrustedCapabilityPrincipal,
): CapabilityCallContext {
  const principalKeyFingerprint = principal.principalKeyFingerprint.trim().toLowerCase();
  if (!PRINCIPAL_FINGERPRINT_PATTERN.test(principalKeyFingerprint)) {
    throw new UniversalBrokerError(
      "AUTHENTICATION_FAILED",
      "A full SHA-256 stable principal fingerprint is required for capability ownership.",
    );
  }
  const requestId = principal.requestId
    ? requireBoundedText(principal.requestId, "requestId", 512)
    : undefined;
  const explicitRequestId = principal.explicitRequestId
    ? requireBoundedText(principal.explicitRequestId, "explicitRequestId", 512)
    : undefined;
  const requestNamespace = principal.requestNamespace
    ? requireBoundedText(principal.requestNamespace, "requestNamespace", 1_024)
    : undefined;
  if (explicitRequestId && requestId && explicitRequestId !== requestId) {
    throw new UniversalBrokerError(
      "AUTHENTICATION_FAILED",
      "Explicit request identity must match the trusted correlation request ID.",
    );
  }
  const context = Object.freeze({
    principalKeyFingerprint,
    ...(requestId ? { requestId } : {}),
    ...(explicitRequestId ? { explicitRequestId } : {}),
    ...(requestNamespace ? { requestNamespace } : {}),
    ...(principal.receivedAt ? { receivedAt: requireTimestamp(principal.receivedAt) } : {}),
  }) as CapabilityCallContext;
  trustedContexts.add(context);
  return context;
}

export function requireCapabilityCallContext(
  explicit?: CapabilityCallContext,
  provider?: CapabilityCallContextProvider,
): CapabilityCallContext {
  const context = explicit ?? provider?.();
  if (!context || !trustedContexts.has(context)) {
    throw new UniversalBrokerError(
      "AUTHENTICATION_FAILED",
      "Trusted capability call context is unavailable.",
      { evidence: { reasonCode: "CAPABILITY_CALL_CONTEXT_REQUIRED" } },
    );
  }
  return context;
}

export function runWithCapabilityCallContext<T>(
  context: CapabilityCallContext,
  callback: () => T,
): T {
  const trusted = requireCapabilityCallContext(context);
  return storage.run(trusted, callback);
}

export function currentCapabilityCallContext(): CapabilityCallContext | undefined {
  return storage.getStore();
}

export const asyncLocalCapabilityCallContextProvider: CapabilityCallContextProvider =
  currentCapabilityCallContext;

function requireBoundedText(value: string, field: string, maximumCharacters = 256): string {
  const normalized = value.trim();
  if (!normalized || normalized.length > maximumCharacters || /[\0\r\n]/u.test(normalized)) {
    throw new UniversalBrokerError(
      "AUTHENTICATION_FAILED",
      `Trusted capability ${field} is invalid.`,
    );
  }
  return normalized;
}

function requireTimestamp(value: string): string {
  if (!Number.isFinite(Date.parse(value))) {
    throw new UniversalBrokerError(
      "AUTHENTICATION_FAILED",
      "Trusted capability receivedAt is invalid.",
    );
  }
  return value;
}
