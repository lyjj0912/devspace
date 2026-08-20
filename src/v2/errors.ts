import { randomUUID } from "node:crypto";
import type { CallToolResult } from "@modelcontextprotocol/sdk/types.js";
import {
  universalResultEnvelopeSchema,
  type DispatchState,
  type RuntimeIdentity,
  type UniversalErrorCode,
} from "./contracts.js";
import { cursorFailure } from "./cursor-capability.js";

type EnvelopeIdentity = Pick<RuntimeIdentity, "schemaGeneration" | "authorityContractGeneration">;
let envelopeIdentity: EnvelopeIdentity | undefined;

export function configureResultEnvelopeIdentity(identity: EnvelopeIdentity): void {
  envelopeIdentity = Object.freeze({
    schemaGeneration: identity.schemaGeneration,
    authorityContractGeneration: identity.authorityContractGeneration,
  });
}

export interface UniversalErrorDetails {
  evidence?: Record<string, unknown>;
  suggestions?: Array<Record<string, unknown>>;
  retryable?: boolean;
  operationId?: string;
}

export class UniversalBrokerError extends Error {
  readonly operationId: string;
  readonly retryable: boolean;
  readonly evidence?: Record<string, unknown>;
  readonly suggestions?: Array<Record<string, unknown>>;

  constructor(
    readonly code: UniversalErrorCode,
    message: string,
    details: UniversalErrorDetails = {},
  ) {
    super(message);
    this.name = "UniversalBrokerError";
    this.operationId = details.operationId ?? newOperationId();
    this.retryable = details.retryable ?? false;
    this.evidence = details.evidence;
    this.suggestions = details.suggestions;
  }
}

export function newOperationId(): string {
  return `op_${randomUUID()}`;
}

export function successfulToolResult(
  data: Record<string, unknown>,
  operationId = newOperationId(),
  text?: string,
): CallToolResult {
  const structuredContent = universalResultEnvelopeSchema.parse({
    ok: true,
    operationId,
    data,
    ...(Array.isArray(data.warnings) ? { warnings: data.warnings } : {}),
    ...(typeof data.resourceUri === "string" ? { resourceUri: data.resourceUri } : {}),
    ...(typeof data.nextCursor === "string" ? { nextCursor: data.nextCursor } : {}),
    observedSchemaGeneration: observedSchemaGeneration(),
    observedAuthorityContractGeneration: observedAuthorityContractGeneration(),
    ...(typeof data.targetGeneration === "string"
      ? { observedTargetGeneration: data.targetGeneration }
      : {}),
    ...(typeof data.routeGeneration === "string"
      ? { observedRouteGeneration: data.routeGeneration }
      : {}),
  });
  return {
    content: [{
      type: "text",
      text: text ?? JSON.stringify(data),
    }],
    structuredContent,
  };
}

export function failedToolResult(error: unknown): CallToolResult {
  const normalized = normalizeError(error);
  const structuredContent = universalResultEnvelopeSchema.parse({
    ok: false,
    operationId: normalized.operationId,
    error: {
      code: normalized.code,
      message: normalized.message,
      retryable: normalized.retryable,
      dispatchState: errorDispatchState(normalized),
      ...(typeof normalized.evidence?.resourceKey === "string"
        ? { resourceKey: normalized.evidence.resourceKey }
        : {}),
      ...(normalized.evidence ? { evidence: normalized.evidence } : {}),
      ...(normalized.suggestions ? {
        suggestions: normalized.suggestions,
        recovery: normalized.suggestions,
      } : {}),
    },
    observedSchemaGeneration: observedSchemaGeneration(),
    observedAuthorityContractGeneration: observedAuthorityContractGeneration(),
    ...(typeof normalized.evidence?.targetGeneration === "string"
      ? { observedTargetGeneration: normalized.evidence.targetGeneration }
      : {}),
    ...(typeof normalized.evidence?.routeGeneration === "string"
      ? { observedRouteGeneration: normalized.evidence.routeGeneration }
      : {}),
  });
  return {
    isError: true,
    content: [{ type: "text", text: normalized.message }],
    structuredContent,
  };
}

function observedSchemaGeneration(): string {
  return envelopeIdentity?.schemaGeneration ?? `sha256:${"0".repeat(64)}`;
}

function observedAuthorityContractGeneration(): string {
  return envelopeIdentity?.authorityContractGeneration ?? `sha256:${"0".repeat(64)}`;
}

function errorDispatchState(error: UniversalBrokerError): DispatchState {
  const declared = error.evidence?.dispatchState;
  if (
    declared === "NOT_DISPATCHED"
    || declared === "CLAIMED"
    || declared === "DISPATCHED"
    || declared === "ACKNOWLEDGED"
    || declared === "UNKNOWN"
  ) return declared;
  if ([
    "AUTHORITY_STATE_UNCERTAIN",
    "DISPATCH_STATE_UNKNOWN",
    "MCP_RESULT_UNKNOWN",
    "EXECUTION_STATE_UNKNOWN",
    "TRANSPORT_INTERRUPTED",
  ].includes(error.code)) return "UNKNOWN";
  return "NOT_DISPATCHED";
}

export async function executeUniversalTool(
  callback: () => Promise<CallToolResult>,
): Promise<CallToolResult> {
  try {
    return await callback();
  } catch (error) {
    return failedToolResult(error);
  }
}

function normalizeError(error: unknown): UniversalBrokerError {
  if (error instanceof UniversalBrokerError) return error;
  const cursor = cursorFailure(error);
  if (cursor) {
    const code: UniversalErrorCode = cursor.reason === "CURSOR_QUOTA_EXCEEDED"
      ? "RESOURCE_QUOTA_EXCEEDED"
      : cursor.reason;
    return new UniversalBrokerError(
      code,
      error instanceof Error ? error.message : "Pagination cursor was rejected.",
      { retryable: false, evidence: { ...cursor.evidence, providerDispatchCount: 0 } },
    );
  }
  return new UniversalBrokerError(
    "MCP_PROVIDER_ERROR",
    error instanceof Error ? error.message : String(error),
    {
      evidence: {
        errorType: error instanceof Error ? error.name : typeof error,
      },
    },
  );
}
