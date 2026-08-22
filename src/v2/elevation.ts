import { createHash } from "node:crypto";
import type { AuthorizationState, ElevationMode, ElevationPolicy } from "./contracts.js";
import { UniversalBrokerError } from "./errors.js";

export interface ExecuteElevationRequest {
  mode: ElevationMode;
  reason?: string;
  scope?: "operation";
  timeoutMs?: number;
}

export interface NormalizedExecutionElevation {
  mode: ElevationMode;
  scope: "operation";
  timeoutMs: number;
  reason?: string;
  reasonSha256?: string;
}

export interface ElevationCapability {
  policy: ElevationPolicy;
  configured: boolean;
  requiresUserInteraction: boolean;
  mechanism?: "macos-authorization-services" | "linux-polkit" | "windows-uac";
  available?: boolean;
  reason?: string;
}

export interface AuthorizationLifecycle {
  state: AuthorizationState;
  requestedAt?: string;
  decidedAt?: string;
}

const DEFAULT_PROMPT_TIMEOUT_MS = 120_000;

export function normalizeExecutionElevation(
  input: ExecuteElevationRequest | undefined,
): NormalizedExecutionElevation {
  if (input === undefined) return { mode: "none", scope: "operation", timeoutMs: 0 };
  if (input.mode !== "none" && input.mode !== "prompt") {
    throw invalid("elevation.mode must be none or prompt.");
  }
  if (input.scope !== undefined && input.scope !== "operation") {
    throw invalid("elevation.scope must be operation.");
  }
  if (input.mode === "none") {
    if (input.reason !== undefined || input.timeoutMs !== undefined || input.scope !== undefined) {
      throw invalid("elevation.mode=none does not accept reason, scope, or timeoutMs.");
    }
    return { mode: "none", scope: "operation", timeoutMs: 0 };
  }
  const reason = input.reason?.trim();
  if (!reason) throw invalid("elevation.mode=prompt requires a reason.");
  if (reason.length > 2_000 || /[\0\r\n]/u.test(reason)) {
    throw invalid("elevation.reason must be a single line of at most 2000 characters.");
  }
  const timeoutMs = input.timeoutMs ?? DEFAULT_PROMPT_TIMEOUT_MS;
  if (!Number.isSafeInteger(timeoutMs) || timeoutMs < 1_000 || timeoutMs > 120_000) {
    throw invalid("elevation.timeoutMs must be an integer from 1000 through 120000.");
  }
  return {
    mode: "prompt",
    scope: "operation",
    timeoutMs,
    reason,
    reasonSha256: createHash("sha256").update(reason).digest("hex"),
  };
}

export function configuredElevationCapability(
  policy: ElevationPolicy,
  platform: string,
): ElevationCapability {
  if (policy === "deny") {
    return { policy, configured: false, requiresUserInteraction: false };
  }
  const mechanism = platform === "macos"
    ? "macos-authorization-services"
    : platform === "windows"
      ? "windows-uac"
      : platform === "linux"
        ? "linux-polkit"
        : undefined;
  return {
    policy,
    configured: true,
    requiresUserInteraction: true,
    ...(mechanism ? { mechanism } : {}),
    available: false,
    reason: "A user-authorized execution provider has not been verified for this target.",
  };
}

function invalid(message: string): UniversalBrokerError {
  return new UniversalBrokerError("INVALID_ARGUMENT", message, {
    evidence: { providerDispatchCount: 0 },
  });
}
