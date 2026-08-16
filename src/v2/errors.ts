import { randomUUID } from "node:crypto";
import type { CallToolResult } from "@modelcontextprotocol/sdk/types.js";
import type { UniversalErrorCode } from "./contracts.js";

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
        ...(normalized.evidence ? { evidence: normalized.evidence } : {}),
        ...(normalized.suggestions ? { suggestions: normalized.suggestions } : {}),
      },
    },
  };
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
