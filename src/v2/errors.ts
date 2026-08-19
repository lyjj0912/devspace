import { randomUUID } from "node:crypto";
import type { CallToolResult } from "@modelcontextprotocol/sdk/types.js";
import type { DispatchState, RuntimeIdentity, UniversalErrorCode } from "./contracts.js";

type EnvelopeIdentity = Pick<RuntimeIdentity, "schemaGeneration">;
let envelopeIdentity: EnvelopeIdentity | undefined;

export function configureResultEnvelopeIdentity(identity: EnvelopeIdentity): void {
  envelopeIdentity = Object.freeze({ schemaGeneration: identity.schemaGeneration });
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
  return {
    content: [{
      type: "text",
      text: text ?? JSON.stringify(data),
    }],
    structuredContent: {
      ok: true,
      operationId,
      data,
      ...(Array.isArray(data.warnings) ? { warnings: data.warnings } : {}),
      ...(typeof data.resourceUri === "string" ? { resourceUri: data.resourceUri } : {}),
      ...(typeof data.nextCursor === "string" ? { nextCursor: data.nextCursor } : {}),
      observedSchemaGeneration: observedSchemaGeneration(),
      ...(typeof data.targetGeneration === "string"
        ? { observedTargetGeneration: data.targetGeneration }
        : {}),
      ...(typeof data.routeGeneration === "string"
        ? { observedRouteGeneration: data.routeGeneration }
        : {}),
    },
  };
}

export function failedToolResult(error: unknown): CallToolResult {
  const normalized = normalizeError(error);
  return {
    isError: true,
    content: [{ type: "text", text: normalized.message }],
    structuredContent: {
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
      ...(typeof normalized.evidence?.targetGeneration === "string"
        ? { observedTargetGeneration: normalized.evidence.targetGeneration }
        : {}),
      ...(typeof normalized.evidence?.routeGeneration === "string"
        ? { observedRouteGeneration: normalized.evidence.routeGeneration }
        : {}),
    },
  };
}

function observedSchemaGeneration(): string {
  return envelopeIdentity?.schemaGeneration ?? `sha256:${"0".repeat(64)}`;
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
