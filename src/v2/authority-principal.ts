import { createHash } from "node:crypto";
import { UniversalBrokerError } from "./errors.js";

export type PrincipalMode = "single-owner" | "multi-user";
export type AuthorityRuntimeEnvironment = "production" | "development" | "test";

export interface AuthenticatedPrincipalClaims {
  issuer: string;
  subject?: string;
  clientId: string;
  resource: string;
  scopes: string[];
}

export interface AuthorityPrincipalKey {
  issuer: string;
  clientId: string;
  resource: string;
  ownerInstanceId?: string;
  subject?: string;
}

export interface AuthorityPrincipalConfiguration {
  environment: AuthorityRuntimeEnvironment;
  mode: PrincipalMode;
  issuer?: string;
  resource?: string;
  ownerInstanceId?: string;
  developmentPrincipal?: AuthorityPrincipalKey;
}

export interface AuthorityAuthenticationInfo {
  clientId?: string;
  scopes?: string[];
  resource?: URL;
  extra?: Record<string, unknown>;
}

export interface AuthorityRequestIdentity {
  authInfo?: AuthorityAuthenticationInfo;
  sessionId?: string;
}

export interface ResolvedAuthorityPrincipal {
  claims?: AuthenticatedPrincipalClaims;
  key: AuthorityPrincipalKey;
  fingerprint: string;
  source: "authenticated" | "development-injection";
}

export function resolveAuthorityPrincipal(
  request: AuthorityRequestIdentity,
  config: AuthorityPrincipalConfiguration,
): ResolvedAuthorityPrincipal {
  const clientId = optionalIdentifier(request.authInfo?.clientId, 512);
  if (!clientId) {
    if (
      config.environment !== "production"
      && config.developmentPrincipal
    ) {
      const key = normalizePrincipalKey(config.developmentPrincipal, config.mode);
      return {
        key,
        fingerprint: principalKeyFingerprint(key),
        source: "development-injection",
      };
    }
    throw authenticationFailure(
      "A validated OAuth clientId is required; transport session fallback is disabled.",
    );
  }

  const issuer = normalizedUrl(config.issuer, "authority issuer");
  const configuredResource = normalizedUrl(config.resource, "authority resource");
  const requestResource = request.authInfo?.resource
    ? normalizedUrl(request.authInfo.resource.href, "authenticated resource")
    : undefined;
  if (!requestResource || requestResource !== configuredResource) {
    throw authenticationFailure(
      "The authenticated OAuth resource is missing or does not match this broker.",
    );
  }

  const subject = subjectClaim(request.authInfo?.extra);
  const key = config.mode === "single-owner"
    ? {
        issuer,
        clientId,
        resource: configuredResource,
        ownerInstanceId: requiredIdentifier(
          config.ownerInstanceId,
          "A configured ownerInstanceId is required for single-owner authority.",
          512,
        ),
      }
    : {
        issuer,
        clientId,
        resource: configuredResource,
        subject: requiredIdentifier(
          subject,
          "An authenticated subject is required for multi-user authority.",
          512,
        ),
      };
  const claims: AuthenticatedPrincipalClaims = {
    issuer,
    clientId,
    resource: configuredResource,
    scopes: [...(request.authInfo?.scopes ?? [])],
    ...(subject ? { subject } : {}),
  };
  return {
    claims,
    key,
    fingerprint: principalKeyFingerprint(key),
    source: "authenticated",
  };
}

export function principalKeyFingerprint(key: AuthorityPrincipalKey): string {
  return createHash("sha256")
    .update(canonicalJson(normalizePrincipalKey(
      key,
      key.subject === undefined ? "single-owner" : "multi-user",
    )))
    .digest("hex");
}

function normalizePrincipalKey(
  key: AuthorityPrincipalKey,
  mode: PrincipalMode,
): AuthorityPrincipalKey {
  const normalized = {
    issuer: normalizedUrl(key.issuer, "principal issuer"),
    clientId: requiredIdentifier(key.clientId, "Principal clientId is required.", 512),
    resource: normalizedUrl(key.resource, "principal resource"),
  };
  if (mode === "single-owner") {
    return {
      ...normalized,
      ownerInstanceId: requiredIdentifier(
        key.ownerInstanceId,
        "Principal ownerInstanceId is required in single-owner mode.",
        512,
      ),
    };
  }
  return {
    ...normalized,
    subject: requiredIdentifier(
      key.subject,
      "Principal subject is required in multi-user mode.",
      512,
    ),
  };
}

function subjectClaim(extra: Record<string, unknown> | undefined): string | undefined {
  const value = extra?.subject ?? extra?.sub;
  return typeof value === "string" ? optionalIdentifier(value, 512) : undefined;
}

function normalizedUrl(value: string | undefined, label: string): string {
  const normalized = optionalIdentifier(value, 2_048);
  if (!normalized) throw authenticationFailure(`A configured ${label} is required.`);
  let url: URL;
  try {
    url = new URL(normalized);
  } catch {
    throw authenticationFailure(`The configured ${label} is not a valid URL.`);
  }
  if (url.username || url.password || url.hash) {
    throw authenticationFailure(`The configured ${label} must not contain credentials or a fragment.`);
  }
  return url.href;
}

function requiredIdentifier(
  value: string | undefined,
  message: string,
  maximum: number,
): string {
  const normalized = optionalIdentifier(value, maximum);
  if (!normalized) throw authenticationFailure(message);
  return normalized;
}

function optionalIdentifier(value: string | undefined, maximum: number): string | undefined {
  const normalized = value?.trim();
  if (!normalized) return undefined;
  if (normalized.length > maximum || /[\0\r\n]/u.test(normalized)) {
    throw authenticationFailure("Authenticated principal data is invalid.");
  }
  return normalized;
}

function authenticationFailure(message: string): UniversalBrokerError {
  return new UniversalBrokerError("AUTHENTICATION_FAILED", message);
}

function canonicalJson(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  if (value && typeof value === "object") {
    const record = value as Record<string, unknown>;
    return `{${Object.keys(record)
      .filter((key) => record[key] !== undefined)
      .sort()
      .map((key) => `${JSON.stringify(key)}:${canonicalJson(record[key])}`)
      .join(",")}}`;
  }
  return JSON.stringify(value) ?? "null";
}
