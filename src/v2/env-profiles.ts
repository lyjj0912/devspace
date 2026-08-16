import { lstat, readFile } from "node:fs/promises";
import { homedir } from "node:os";
import { isAbsolute, resolve } from "node:path";
import * as z from "zod/v4";
import { UniversalBrokerError } from "./errors.js";

const PROFILE_ID = /^[a-z][a-z0-9._-]{0,63}$/;
const ENV_NAME = /^[A-Za-z_][A-Za-z0-9_]*$/;
const HEADER_NAME = /^[!#$%&'*+.^_`|~0-9A-Za-z-]+$/;

const profileSchema = z.strictObject({
  description: z.string().max(500).optional(),
  targets: z.array(z.string().min(1).max(128)).max(100).optional(),
  environment: z.record(z.string(), z.string()).optional(),
  sourceFile: z.string().min(1).optional(),
  headers: z.record(z.string(), z.string()).optional(),
});

const profileFileSchema = z.strictObject({
  version: z.literal(1),
  profiles: z.record(z.string(), profileSchema),
});

export interface UniversalEnvProfile {
  id: string;
  description?: string;
  targets: string[];
  environment: Record<string, string>;
  sourceFile?: string;
  headers: Record<string, string>;
}

export interface ResolvedEnvProfile {
  id: string;
  environment: Record<string, string>;
  sourceFile?: string;
  headers: Record<string, string>;
}

export interface UniversalEnvProfileRegistryOptions {
  configPath: string;
}

export class UniversalEnvProfileRegistry {
  private cached?: { mtimeMs: number; size: number; profiles: Map<string, UniversalEnvProfile> };

  constructor(private readonly options: UniversalEnvProfileRegistryOptions) {}

  async list(): Promise<Array<Record<string, unknown>>> {
    const profiles = await this.load();
    return [...profiles.values()]
      .sort((left, right) => left.id.localeCompare(right.id))
      .map((profile) => ({
        id: profile.id,
        description: profile.description,
        targets: profile.targets,
        hasEnvironment: Object.keys(profile.environment).length > 0,
        hasSourceFile: Boolean(profile.sourceFile),
        hasHeaders: Object.keys(profile.headers).length > 0,
      }));
  }

  async resolve(name: string, targetId: string): Promise<ResolvedEnvProfile> {
    if (!PROFILE_ID.test(name)) {
      throw new UniversalBrokerError("PRECONDITION_FAILED", `Invalid environment profile ID: ${name}`);
    }
    const profile = (await this.load()).get(name);
    if (!profile) {
      throw new UniversalBrokerError(
        "PATH_NOT_FOUND",
        `Environment profile is not configured: ${name}`,
        { suggestions: (await this.list()).map((entry) => ({ profileId: entry.id })) },
      );
    }
    if (profile.targets.length > 0 && !profile.targets.includes(targetId)) {
      throw new UniversalBrokerError(
        "PERMISSION_DENIED",
        `Environment profile ${name} is not authorized for target ${targetId}.`,
        { evidence: { profileId: name, targetId, allowedTargets: profile.targets } },
      );
    }
    return {
      id: profile.id,
      environment: { ...profile.environment },
      ...(profile.sourceFile ? { sourceFile: profile.sourceFile } : {}),
      headers: { ...profile.headers },
    };
  }

  private async load(): Promise<Map<string, UniversalEnvProfile>> {
    let metadata;
    try {
      metadata = await lstat(this.options.configPath);
    } catch (error) {
      if (isNodeError(error, "ENOENT")) return new Map();
      throw new UniversalBrokerError(
        "PRECONDITION_FAILED",
        `Unable to inspect environment profile registry: ${this.options.configPath}`,
        { evidence: { error: errorMessage(error) } },
      );
    }
    const uid = process.getuid?.();
    if (
      !metadata.isFile()
      || metadata.isSymbolicLink()
      || (metadata.mode & 0o077) !== 0
      || (uid !== undefined && metadata.uid !== uid)
    ) {
      throw new UniversalBrokerError(
        "PERMISSION_DENIED",
        "Environment profile registry must be a regular owner-only file owned by the service user.",
        { evidence: { path: this.options.configPath, mode: metadata.mode & 0o777, uid: metadata.uid } },
      );
    }
    if (this.cached && this.cached.mtimeMs === metadata.mtimeMs && this.cached.size === metadata.size) {
      return this.cached.profiles;
    }
    let parsed: unknown;
    try {
      parsed = JSON.parse(await readFile(this.options.configPath, "utf8"));
    } catch (error) {
      throw new UniversalBrokerError(
        "PRECONDITION_FAILED",
        "Environment profile registry is not valid JSON.",
        { evidence: { error: errorMessage(error) } },
      );
    }
    const validated = profileFileSchema.safeParse(parsed);
    if (!validated.success) {
      throw new UniversalBrokerError(
        "PRECONDITION_FAILED",
        "Environment profile registry does not match its schema.",
        { evidence: { issues: validated.error.issues.slice(0, 20) } },
      );
    }
    const profiles = new Map<string, UniversalEnvProfile>();
    for (const [id, value] of Object.entries(validated.data.profiles)) {
      if (!PROFILE_ID.test(id)) {
        throw new UniversalBrokerError("PRECONDITION_FAILED", `Invalid environment profile ID: ${id}`);
      }
      const environment: Record<string, string> = {};
      for (const [key, entry] of Object.entries(value.environment ?? {})) {
        if (!ENV_NAME.test(key) || key.includes("\0") || entry.includes("\0")) {
          throw new UniversalBrokerError("PRECONDITION_FAILED", `Invalid environment entry in profile ${id}: ${key}`);
        }
        environment[key] = entry;
      }
      const headers: Record<string, string> = {};
      for (const [key, entry] of Object.entries(value.headers ?? {})) {
        if (!HEADER_NAME.test(key) || /[\r\n\0]/.test(entry)) {
          throw new UniversalBrokerError("PRECONDITION_FAILED", `Invalid HTTP header in profile ${id}: ${key}`);
        }
        headers[key] = entry;
      }
      if (value.sourceFile && !isAbsoluteOrTilde(value.sourceFile)) {
        throw new UniversalBrokerError(
          "PRECONDITION_FAILED",
          `Environment profile ${id} sourceFile must be absolute or begin with ~/.`,
        );
      }
      profiles.set(id, {
        id,
        description: value.description,
        targets: [...(value.targets ?? [])],
        environment,
        ...(value.sourceFile ? { sourceFile: value.sourceFile } : {}),
        headers,
      });
    }
    this.cached = { mtimeMs: metadata.mtimeMs, size: metadata.size, profiles };
    return profiles;
  }
}

export function resolveLocalProfileSourceFile(path: string): string {
  return path === "~" ? homedir() : path.startsWith("~/") ? resolve(homedir(), path.slice(2)) : path;
}

function isAbsoluteOrTilde(path: string): boolean {
  return isAbsolute(path) || path === "~" || path.startsWith("~/");
}

function isNodeError(error: unknown, code: string): error is NodeJS.ErrnoException {
  return error instanceof Error && (error as NodeJS.ErrnoException).code === code;
}

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}
