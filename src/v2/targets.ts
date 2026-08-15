import { createHash } from "node:crypto";
import { execFile } from "node:child_process";
import { readFile, stat } from "node:fs/promises";
import { homedir, platform as nodePlatform, arch, tmpdir } from "node:os";
import { promisify } from "node:util";
import * as z from "zod/v4";
import { UniversalBrokerError } from "./errors.js";

const execFileAsync = promisify(execFile);
const TARGET_ID_PATTERN = /^[a-z][a-z0-9._-]{0,63}$/;
const DEFAULT_PROBE_TTL_MS = 30_000;
const DEFAULT_PROBE_TIMEOUT_MS = 7_000;

export type TargetTransport = "local" | "ssh";
export type TargetPlatform = "macos" | "linux" | "windows" | "unknown";
export type TargetAdminMode = "unavailable" | "helper" | "sudo-n";

export interface TargetDefinition {
  id: string;
  displayName: string;
  aliases: string[];
  transport: TargetTransport;
  sshHost?: string;
  platform: TargetPlatform;
  shell: "auto" | "sh" | "bash" | "zsh" | "powershell" | "cmd";
  defaultCwd?: string;
  envProfile?: string;
  probeTtlMs: number;
  privilege: {
    user: true;
    admin: {
      mode: TargetAdminMode;
      socketPath?: string;
      helperCommand?: string;
    };
  };
  durableProcess: {
    mode: "none" | "tmux" | "systemd-run" | "launchd" | "task-scheduler";
  };
  gui: {
    mode: "none" | "local-ipc" | "ssh-stdio";
    command?: string;
  };
}

export interface TargetCapabilities {
  fs: boolean;
  exec: boolean;
  pty: boolean;
  admin: boolean;
  sftp: boolean;
  rsync: boolean;
  git: boolean;
  gui: boolean;
  mcp: boolean;
  durableProcess: boolean;
}

export interface TargetObservation {
  targetId: string;
  status: "ONLINE" | "OFFLINE" | "DEGRADED" | "UNKNOWN";
  observedAt: string;
  expiresAt: string;
  platform: TargetPlatform;
  architecture?: string;
  homeDirectory?: string;
  temporaryDirectory?: string;
  capabilities: TargetCapabilities;
  reason?: string;
  evidence?: Record<string, unknown>;
}

export interface TargetRegistrySnapshot {
  generation: string;
  targets: TargetDefinition[];
}

export interface TargetRegistryOptions {
  configPath: string;
  now?: () => number;
  probeTimeoutMs?: number;
  execute?: typeof execFileAsync;
}

const adminSchema = z.strictObject({
  mode: z.enum(["unavailable", "helper", "sudo-n"]),
  socketPath: z.string().min(1).optional(),
  helperCommand: z.string().min(1).optional(),
});

const targetSchema = z.strictObject({
  displayName: z.string().min(1).max(128),
  aliases: z.array(z.string().min(1).max(128)).optional(),
  transport: z.enum(["local", "ssh"]),
  sshHost: z.string().min(1).optional(),
  platform: z.enum(["macos", "linux", "windows", "unknown"]),
  shell: z.enum(["auto", "sh", "bash", "zsh", "powershell", "cmd"]).optional(),
  defaultCwd: z.string().min(1).optional(),
  envProfile: z.string().min(1).optional(),
  probeTtlMs: z.number().int().min(1_000).max(3_600_000).optional(),
  privilege: z.strictObject({
    user: z.literal(true),
    admin: adminSchema,
  }),
  durableProcess: z.strictObject({
    mode: z.enum(["none", "tmux", "systemd-run", "launchd", "task-scheduler"]),
  }).optional(),
  gui: z.strictObject({
    mode: z.enum(["none", "local-ipc", "ssh-stdio"]),
    command: z.string().min(1).optional(),
  }).optional(),
}).superRefine((target, context) => {
  if (target.transport === "ssh" && !target.sshHost) {
    context.addIssue({
      code: "custom",
      path: ["sshHost"],
      message: "sshHost is required for SSH targets",
    });
  }
  if (target.transport === "local" && target.gui?.mode === "ssh-stdio") {
    context.addIssue({
      code: "custom",
      path: ["gui", "mode"],
      message: "local targets cannot use ssh-stdio GUI mode",
    });
  }
});

const targetFileSchema = z.strictObject({
  version: z.literal(1),
  targets: z.record(z.string(), targetSchema),
});

export class TargetRegistry {
  private snapshot?: TargetRegistrySnapshot;
  private snapshotContentHash?: string;
  private readonly probeCache = new Map<string, TargetObservation>();
  private readonly now: () => number;
  private readonly probeTimeoutMs: number;
  private readonly execute: typeof execFileAsync;

  constructor(private readonly options: TargetRegistryOptions) {
    this.now = options.now ?? Date.now;
    this.probeTimeoutMs = options.probeTimeoutMs ?? DEFAULT_PROBE_TIMEOUT_MS;
    this.execute = options.execute ?? execFileAsync;
  }

  async inspect(): Promise<TargetRegistrySnapshot> {
    const content = await this.readConfig();
    const contentHash = sha256(content ?? "<missing>");
    if (this.snapshot && this.snapshotContentHash === contentHash) return this.snapshot;

    const configured = content === undefined
      ? { version: 1 as const, targets: {} }
      : parseTargetFile(content, this.options.configPath);
    const targets = normalizeTargets(configured.targets);
    if (!targets.some((target) => target.id === "local")) {
      targets.unshift(defaultLocalTarget());
    }
    assertUniqueTargetIds(targets, this.options.configPath);
    const generation = sha256(JSON.stringify(targets)).slice(0, 16);
    this.snapshot = { generation, targets };
    this.snapshotContentHash = contentHash;
    this.pruneProbeCache(new Set(targets.map((target) => `${generation}:${target.id}`)));
    return this.snapshot;
  }

  async list(input: { cursor?: string; limit?: number } = {}): Promise<{
    generation: string;
    targets: Array<Record<string, unknown>>;
    nextCursor?: string;
  }> {
    const snapshot = await this.inspect();
    const offset = parseCursor(input.cursor);
    const limit = Math.min(Math.max(input.limit ?? 50, 1), 200);
    const page = snapshot.targets.slice(offset, offset + limit);
    const nextOffset = offset + page.length;
    return {
      generation: snapshot.generation,
      targets: page.map(targetSummary),
      ...(nextOffset < snapshot.targets.length ? { nextCursor: String(nextOffset) } : {}),
    };
  }

  async resolve(selector: string | undefined): Promise<TargetDefinition> {
    const snapshot = await this.inspect();
    return resolveTargetFromSnapshot(snapshot, selector);
  }

  async resolveWithGeneration(selector: string | undefined): Promise<{
    generation: string;
    target: TargetDefinition;
  }> {
    const snapshot = await this.inspect();
    return {
      generation: snapshot.generation,
      target: resolveTargetFromSnapshot(snapshot, selector),
    };
  }

  async probe(selector: string | undefined): Promise<TargetObservation> {
    const { generation, target } = await this.resolveWithGeneration(selector);
    const key = `${generation}:${target.id}`;
    const cached = this.probeCache.get(key);
    if (cached && Date.parse(cached.expiresAt) > this.now()) return cached;

    const observed = target.transport === "local"
      ? await this.probeLocal(target)
      : await this.probeSsh(target);
    this.probeCache.set(key, observed);
    return observed;
  }

  private async readConfig(): Promise<string | undefined> {
    try {
      return await readFile(this.options.configPath, "utf8");
    } catch (error) {
      if (isNodeError(error, "ENOENT")) return undefined;
      throw new UniversalBrokerError(
        "PRECONDITION_FAILED",
        `Unable to read target registry: ${this.options.configPath}`,
        { evidence: { error: errorMessage(error) } },
      );
    }
  }

  private async probeLocal(target: TargetDefinition): Promise<TargetObservation> {
    const observedAtMs = this.now();
    const admin = await this.localAdminAvailable(target);
    const [git, rsync] = await Promise.all([
      commandAvailable("git", this.execute),
      commandAvailable("rsync", this.execute),
    ]);
    return {
      targetId: target.id,
      status: admin.degraded ? "DEGRADED" : "ONLINE",
      observedAt: new Date(observedAtMs).toISOString(),
      expiresAt: new Date(observedAtMs + target.probeTtlMs).toISOString(),
      platform: target.platform === "unknown" ? currentPlatform() : target.platform,
      architecture: arch(),
      homeDirectory: homedir(),
      temporaryDirectory: tmpdir(),
      capabilities: {
        fs: true,
        exec: true,
        pty: process.platform !== "win32",
        admin: admin.available,
        sftp: false,
        rsync,
        git,
        gui: target.gui.mode !== "none",
        mcp: true,
        durableProcess: target.durableProcess.mode !== "none",
      },
      ...(admin.reason ? { reason: admin.reason } : {}),
      evidence: {
        transport: "local",
        adminMode: target.privilege.admin.mode,
      },
    };
  }

  private async localAdminAvailable(target: TargetDefinition): Promise<{
    available: boolean;
    degraded: boolean;
    reason?: string;
  }> {
    switch (target.privilege.admin.mode) {
      case "unavailable":
        return { available: false, degraded: false };
      case "helper": {
        const socketPath = target.privilege.admin.socketPath;
        if (!socketPath) {
          return {
            available: false,
            degraded: true,
            reason: "Administrator helper is configured without socketPath.",
          };
        }
        try {
          const metadata = await stat(socketPath);
          return metadata.isSocket()
            ? {
                available: false,
                degraded: true,
                reason: "Administrator helper socket exists, but Phase 5 handshake is not implemented.",
              }
            : {
                available: false,
                degraded: true,
                reason: "Configured administrator helper path is not a socket.",
              };
        } catch {
          return {
            available: false,
            degraded: true,
            reason: "Configured administrator helper socket is unavailable.",
          };
        }
      }
      case "sudo-n": {
        try {
          await this.execute("sudo", ["-n", "true"], {
            timeout: this.probeTimeoutMs,
            encoding: "utf8",
          });
          return { available: true, degraded: false };
        } catch {
          return {
            available: false,
            degraded: true,
            reason: "Non-interactive sudo is unavailable.",
          };
        }
      }
    }
  }

  private async probeSsh(target: TargetDefinition): Promise<TargetObservation> {
    const observedAtMs = this.now();
    const expiresAt = new Date(observedAtMs + target.probeTtlMs).toISOString();
    if (!target.sshHost) {
      return offlineObservation(target, observedAtMs, expiresAt, "SSH target has no sshHost.");
    }
    if (target.platform === "windows") {
      return this.probeWindowsSsh(target, observedAtMs, expiresAt);
    }

    const script = [
      "printf '__DEVSPACE_TARGET_V1__\\n'",
      "printf 'kernel=%s\\n' \"$(uname -s 2>/dev/null || printf unknown)\"",
      "printf 'architecture=%s\\n' \"$(uname -m 2>/dev/null || printf unknown)\"",
      "printf 'home=%s\\n' \"$HOME\"",
      "printf 'temporary=%s\\n' \"${TMPDIR:-/tmp}\"",
      "command -v git >/dev/null 2>&1 && printf 'git=1\\n' || printf 'git=0\\n'",
      "command -v rsync >/dev/null 2>&1 && printf 'rsync=1\\n' || printf 'rsync=0\\n'",
      "sudo -n true >/dev/null 2>&1 && printf 'sudo=1\\n' || printf 'sudo=0\\n'",
    ].join("; ");

    try {
      const result = await this.execute(
        "ssh",
        sshArguments(target.sshHost, this.probeTimeoutMs, `sh -lc ${shellQuote(script)}`),
        {
          timeout: this.probeTimeoutMs + 1_000,
          encoding: "utf8",
          maxBuffer: 256 * 1024,
        },
      );
      const fields = parseKeyValueOutput(result.stdout);
      if (!result.stdout.includes("__DEVSPACE_TARGET_V1__")) {
        throw new Error("Remote probe marker missing");
      }
      const platform = target.platform === "unknown"
        ? platformFromKernel(fields.kernel)
        : target.platform;
      const configuredAdmin = target.privilege.admin.mode;
      const observedSudo = fields.sudo === "1";
      const admin = configuredAdmin === "sudo-n" && observedSudo;
      const degraded = configuredAdmin === "sudo-n" && !observedSudo;
      return {
        targetId: target.id,
        status: degraded ? "DEGRADED" : "ONLINE",
        observedAt: new Date(observedAtMs).toISOString(),
        expiresAt,
        platform,
        architecture: fields.architecture,
        homeDirectory: fields.home,
        temporaryDirectory: fields.temporary,
        capabilities: {
          fs: true,
          exec: true,
          pty: false,
          admin,
          sftp: false,
          rsync: fields.rsync === "1",
          git: fields.git === "1",
          gui: target.gui.mode !== "none",
          mcp: true,
          durableProcess: target.durableProcess.mode !== "none",
        },
        ...(degraded ? { reason: "Configured sudo-n administrator capability is unavailable." } : {}),
        evidence: {
          transport: "ssh",
          sshHost: target.sshHost,
          adminMode: configuredAdmin,
          ptyProbe: "not_run_phase_2",
          sftpProbe: "not_run_phase_2",
        },
      };
    } catch (error) {
      return offlineObservation(target, observedAtMs, expiresAt, boundedError(error));
    }
  }

  private async probeWindowsSsh(
    target: TargetDefinition,
    observedAtMs: number,
    expiresAt: string,
  ): Promise<TargetObservation> {
    try {
      const result = await this.execute(
        "ssh",
        sshArguments(
          target.sshHost!,
          this.probeTimeoutMs,
          "powershell -NoProfile -NonInteractive -Command \"Write-Output '__DEVSPACE_TARGET_V1__'; Write-Output ('architecture=' + $env:PROCESSOR_ARCHITECTURE); Write-Output ('home=' + $HOME); if (Get-Command git -ErrorAction SilentlyContinue) { Write-Output 'git=1' } else { Write-Output 'git=0' }\"",
        ),
        {
          timeout: this.probeTimeoutMs + 1_000,
          encoding: "utf8",
          maxBuffer: 256 * 1024,
        },
      );
      const fields = parseKeyValueOutput(result.stdout);
      if (!result.stdout.includes("__DEVSPACE_TARGET_V1__")) {
        throw new Error("Remote probe marker missing");
      }
      return {
        targetId: target.id,
        status: "ONLINE",
        observedAt: new Date(observedAtMs).toISOString(),
        expiresAt,
        platform: "windows",
        architecture: fields.architecture,
        homeDirectory: fields.home,
        temporaryDirectory: undefined,
        capabilities: {
          fs: true,
          exec: true,
          pty: false,
          admin: false,
          sftp: false,
          rsync: false,
          git: fields.git === "1",
          gui: target.gui.mode !== "none",
          mcp: true,
          durableProcess: target.durableProcess.mode !== "none",
        },
        evidence: {
          transport: "ssh",
          sshHost: target.sshHost,
          adminProbe: "not_run_phase_2",
          ptyProbe: "not_run_phase_2",
          sftpProbe: "not_run_phase_2",
        },
      };
    } catch (error) {
      return offlineObservation(target, observedAtMs, expiresAt, boundedError(error));
    }
  }

  private pruneProbeCache(validKeys: Set<string>): void {
    for (const key of this.probeCache.keys()) {
      if (!validKeys.has(key)) this.probeCache.delete(key);
    }
  }
}

function resolveTargetFromSnapshot(
  snapshot: TargetRegistrySnapshot,
  selector: string | undefined,
): TargetDefinition {
    const requested = selector?.trim() || "local";
    const normalized = normalizeSelector(requested);
    const matches = snapshot.targets.filter((target) => targetSelectors(target).has(normalized));
    if (matches.length === 1) return matches[0]!;
    if (matches.length > 1) {
      throw new UniversalBrokerError(
        "TARGET_AMBIGUOUS",
        `Target selector is ambiguous: ${requested}`,
        {
          suggestions: matches.map(targetSummary),
          evidence: { selector: requested, generation: snapshot.generation },
        },
      );
    }
  throw new UniversalBrokerError(
      "TARGET_NOT_FOUND",
      `Unknown target: ${requested}`,
      {
        suggestions: snapshot.targets.slice(0, 20).map(targetSummary),
        evidence: { selector: requested, generation: snapshot.generation },
      },
    );
}

function parseTargetFile(content: string, path: string) {
  try {
    return targetFileSchema.parse(JSON.parse(content));
  } catch (error) {
    throw new UniversalBrokerError(
      "PRECONDITION_FAILED",
      `Invalid target registry: ${path}`,
      { evidence: { error: errorMessage(error) } },
    );
  }
}

function normalizeTargets(
  targets: Record<string, z.infer<typeof targetSchema>>,
): TargetDefinition[] {
  return Object.entries(targets)
    .map(([id, target]) => {
      if (!TARGET_ID_PATTERN.test(id)) {
        throw new UniversalBrokerError(
          "PRECONDITION_FAILED",
          `Invalid target ID: ${id}`,
        );
      }
      return {
        id,
        displayName: target.displayName.trim(),
        aliases: Array.from(new Set((target.aliases ?? []).map((alias) => alias.trim()))),
        transport: target.transport,
        sshHost: target.sshHost,
        platform: target.platform,
        shell: target.shell ?? "auto",
        defaultCwd: target.defaultCwd,
        envProfile: target.envProfile,
        probeTtlMs: target.probeTtlMs ?? DEFAULT_PROBE_TTL_MS,
        privilege: target.privilege,
        durableProcess: target.durableProcess ?? { mode: "none" },
        gui: target.gui ?? { mode: "none" },
      } satisfies TargetDefinition;
    })
    .sort((left, right) => {
      if (left.id === "local") return -1;
      if (right.id === "local") return 1;
      return left.id.localeCompare(right.id);
    });
}

function defaultLocalTarget(): TargetDefinition {
  return {
    id: "local",
    displayName: "Local machine",
    aliases: ["local", "localhost", "로컬", "내 맥", "개인 Mac"],
    transport: "local",
    platform: currentPlatform(),
    shell: "auto",
    probeTtlMs: DEFAULT_PROBE_TTL_MS,
    privilege: {
      user: true,
      admin: { mode: "unavailable" },
    },
    durableProcess: { mode: "none" },
    gui: { mode: "none" },
  };
}

function assertUniqueTargetIds(targets: TargetDefinition[], path: string): void {
  const seen = new Set<string>();
  for (const target of targets) {
    const normalized = normalizeSelector(target.id);
    if (seen.has(normalized)) {
      throw new UniversalBrokerError(
        "PRECONDITION_FAILED",
        `Target registry contains duplicate normalized IDs: ${path}`,
      );
    }
    seen.add(normalized);
  }
}

export function targetSummary(target: TargetDefinition): Record<string, unknown> {
  return {
    targetId: target.id,
    displayName: target.displayName,
    aliases: target.aliases,
    transport: target.transport,
    platform: target.platform,
    privilege: {
      user: true,
      adminMode: target.privilege.admin.mode,
    },
    guiMode: target.gui.mode,
    durableProcessMode: target.durableProcess.mode,
    envProfileConfigured: Boolean(target.envProfile),
  };
}

function targetSelectors(target: TargetDefinition): Set<string> {
  return new Set([
    target.id,
    target.displayName,
    ...target.aliases,
  ].map(normalizeSelector));
}

function normalizeSelector(value: string): string {
  return value.normalize("NFKC").trim().replace(/\s+/g, " ").toLocaleLowerCase("en-US");
}

function parseCursor(cursor: string | undefined): number {
  if (cursor === undefined) return 0;
  const parsed = Number(cursor);
  if (!Number.isInteger(parsed) || parsed < 0) {
    throw new UniversalBrokerError(
      "PRECONDITION_FAILED",
      `Invalid target cursor: ${cursor}`,
    );
  }
  return parsed;
}

function currentPlatform(): TargetPlatform {
  switch (nodePlatform()) {
    case "darwin":
      return "macos";
    case "linux":
      return "linux";
    case "win32":
      return "windows";
    default:
      return "unknown";
  }
}

function platformFromKernel(kernel: string | undefined): TargetPlatform {
  switch (kernel?.toLowerCase()) {
    case "darwin":
      return "macos";
    case "linux":
      return "linux";
    default:
      return "unknown";
  }
}

function sshArguments(host: string, timeoutMs: number, command: string): string[] {
  return [
    "-T",
    "-o", "BatchMode=yes",
    "-o", `ConnectTimeout=${Math.max(1, Math.ceil(timeoutMs / 1_000))}`,
    "-o", "ConnectionAttempts=1",
    host,
    command,
  ];
}

function shellQuote(value: string): string {
  return `'${value.replaceAll("'", `'"'"'`)}'`;
}

function parseKeyValueOutput(output: string): Record<string, string> {
  const fields: Record<string, string> = {};
  for (const line of output.split(/\r?\n/)) {
    const separator = line.indexOf("=");
    if (separator <= 0) continue;
    fields[line.slice(0, separator)] = line.slice(separator + 1);
  }
  return fields;
}

async function commandAvailable(
  command: string,
  execute: typeof execFileAsync,
): Promise<boolean> {
  try {
    await execute("sh", ["-lc", `command -v ${shellQuote(command)} >/dev/null 2>&1`], {
      timeout: 2_000,
      encoding: "utf8",
    });
    return true;
  } catch {
    return false;
  }
}

function offlineObservation(
  target: TargetDefinition,
  observedAtMs: number,
  expiresAt: string,
  reason: string,
): TargetObservation {
  return {
    targetId: target.id,
    status: "OFFLINE",
    observedAt: new Date(observedAtMs).toISOString(),
    expiresAt,
    platform: target.platform,
    capabilities: {
      fs: false,
      exec: false,
      pty: false,
      admin: false,
      sftp: false,
      rsync: false,
      git: false,
      gui: false,
      mcp: false,
      durableProcess: false,
    },
    reason,
    evidence: {
      transport: target.transport,
      sshHost: target.sshHost,
    },
  };
}

function sha256(value: string): string {
  return createHash("sha256").update(value).digest("hex");
}

function boundedError(error: unknown): string {
  const text = errorMessage(error).replace(/\s+/g, " ").trim();
  return text.length <= 300 ? text : `${text.slice(0, 297)}...`;
}

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

function isNodeError(error: unknown, code: string): boolean {
  return error instanceof Error && "code" in error && (error as NodeJS.ErrnoException).code === code;
}
