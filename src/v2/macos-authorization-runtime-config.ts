import { createHash } from "node:crypto";
import { isAbsolute, join, resolve } from "node:path";

const DIGEST_PATTERN = /^sha256:[a-f0-9]{64}$/u;

export interface MacOsAuthorizationRuntimeConfig {
  provider: "macos-authorization-services-v1";
  agentPath: string;
  agentSha256: string;
  helperPath: string;
  helperSha256: string;
  workRoot: string;
}

export interface UserAuthorizationRuntimeConfiguration {
  userAuthorizationStorePath: string;
  macosAuthorization?: MacOsAuthorizationRuntimeConfig;
}

export function loadUserAuthorizationRuntimeConfiguration(
  environment: NodeJS.ProcessEnv | Record<string, string | undefined>,
  stateDir: string,
): UserAuthorizationRuntimeConfiguration {
  const userAuthorizationStorePath = absolutePath(
    environment.DEVSPACE_NEXT_USER_AUTHORIZATION_STORE
      ?? join(stateDir, "user-authorization.sqlite"),
    "DEVSPACE_NEXT_USER_AUTHORIZATION_STORE",
  );
  const enabled = optionalBoolean(
    environment.DEVSPACE_NEXT_MACOS_AUTHORIZATION_ENABLED,
    "DEVSPACE_NEXT_MACOS_AUTHORIZATION_ENABLED",
  ) ?? false;
  const names = [
    "DEVSPACE_NEXT_MACOS_AUTHORIZATION_AGENT",
    "DEVSPACE_NEXT_MACOS_AUTHORIZATION_AGENT_SHA256",
    "DEVSPACE_NEXT_MACOS_PRIVILEGED_HELPER",
    "DEVSPACE_NEXT_MACOS_PRIVILEGED_HELPER_SHA256",
    "DEVSPACE_NEXT_MACOS_AUTHORIZATION_WORK_ROOT",
  ] as const;
  const configured = names.filter((name) => Boolean(environment[name]?.trim()));
  if (!enabled) {
    if (configured.length > 0) {
      throw new Error(
        "macOS authorization paths or digests were configured while DEVSPACE_NEXT_MACOS_AUTHORIZATION_ENABLED is not true.",
      );
    }
    return { userAuthorizationStorePath };
  }
  if (configured.length !== names.length) {
    const missing = names.filter((name) => !environment[name]?.trim());
    throw new Error(`macOS authorization configuration is incomplete: ${missing.join(", ")}`);
  }
  return {
    userAuthorizationStorePath,
    macosAuthorization: Object.freeze({
      provider: "macos-authorization-services-v1",
      agentPath: absolutePath(
        environment.DEVSPACE_NEXT_MACOS_AUTHORIZATION_AGENT!,
        "DEVSPACE_NEXT_MACOS_AUTHORIZATION_AGENT",
      ),
      agentSha256: digest(
        environment.DEVSPACE_NEXT_MACOS_AUTHORIZATION_AGENT_SHA256!,
        "DEVSPACE_NEXT_MACOS_AUTHORIZATION_AGENT_SHA256",
      ),
      helperPath: absolutePath(
        environment.DEVSPACE_NEXT_MACOS_PRIVILEGED_HELPER!,
        "DEVSPACE_NEXT_MACOS_PRIVILEGED_HELPER",
      ),
      helperSha256: digest(
        environment.DEVSPACE_NEXT_MACOS_PRIVILEGED_HELPER_SHA256!,
        "DEVSPACE_NEXT_MACOS_PRIVILEGED_HELPER_SHA256",
      ),
      workRoot: absolutePath(
        environment.DEVSPACE_NEXT_MACOS_AUTHORIZATION_WORK_ROOT!,
        "DEVSPACE_NEXT_MACOS_AUTHORIZATION_WORK_ROOT",
      ),
    }),
  };
}

export function bindUserAuthorizationConfigurationDigest(
  baseConfigDigest: string,
  configuration: UserAuthorizationRuntimeConfiguration,
): string {
  if (!configuration.macosAuthorization) return baseConfigDigest;
  return `sha256:${createHash("sha256").update(canonicalJson({
    baseConfigDigest,
    userAuthorizationStorePath: configuration.userAuthorizationStorePath,
    macosAuthorization: configuration.macosAuthorization,
  })).digest("hex")}`;
}

function absolutePath(value: string, field: string): string {
  const normalized = value.trim();
  if (
    !normalized
    || !isAbsolute(normalized)
    || resolve(normalized) !== normalized
    || /[\0\r\n]/u.test(normalized)
  ) throw new Error(`${field} must be a canonical absolute path.`);
  return normalized;
}

function digest(value: string, field: string): string {
  const normalized = value.trim().toLowerCase();
  if (!DIGEST_PATTERN.test(normalized)) throw new Error(`${field} must be a SHA-256 digest.`);
  return normalized;
}

function optionalBoolean(value: string | undefined, field: string): boolean | undefined {
  if (value === undefined || !value.trim()) return undefined;
  if (value === "true") return true;
  if (value === "false") return false;
  throw new Error(`${field} must be true or false.`);
}

function canonicalJson(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  if (value && typeof value === "object") {
    return `{${Object.entries(value as Record<string, unknown>)
      .filter(([, child]) => child !== undefined)
      .sort(([left], [right]) => left < right ? -1 : left > right ? 1 : 0)
      .map(([key, child]) => `${JSON.stringify(key)}:${canonicalJson(child)}`)
      .join(",")}}`;
  }
  return JSON.stringify(value) ?? "null";
}
