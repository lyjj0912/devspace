import { createHash } from "node:crypto";
import { execFile } from "node:child_process";
import { access, link, mkdtemp, open, readFile, rename, rm, writeFile } from "node:fs/promises";
import { homedir, platform as nodePlatform, arch, hostname, tmpdir, userInfo } from "node:os";
import { promisify } from "node:util";
import * as z from "zod/v4";
import { requireCapabilityCallContext, type CapabilityCallContext } from "./capability-call-context.js";
import type { SignedSnapshotCursorStore } from "./cursor-capability.js";
import type { ElevationPolicy } from "./contracts.js";
import { configuredElevationCapability } from "./elevation.js";
import { UniversalBrokerError } from "./errors.js";
import { macosUserOnlyProfile, windowsIntegrityIsElevated, windowsNonElevatedPrelude } from "./no-elevation.js";

const execFileAsync = promisify(execFile);
const TARGET_ID_PATTERN = /^[a-z][a-z0-9._-]{0,63}$/;
const DEFAULT_PROBE_TTL_MS = 30_000;
const DEFAULT_PROBE_TIMEOUT_MS = 7_000;
const MAXIMUM_READY_CLOCK_SKEW_MS = 5 * 60_000;

export type TargetTransport = "local" | "ssh";
export type TargetPlatform = "macos" | "linux" | "windows" | "unknown";
export type ConfiguredTargetCapability =
  | "fs"
  | "exec"
  | "pty"
  | "mcp"
  | "artifact"
  | "gui"
  | "durableProcess";
export type ConfiguredTargetCapabilities = Readonly<Record<ConfiguredTargetCapability, boolean>>;

export interface FilesystemPrimitiveCapabilities {
  atomicReplace: boolean;
  atomicNoReplace: boolean;
  renameExchange: boolean;
  directoryFsync: boolean;
  hardlinkPublish: boolean;
  trash: boolean;
  reflink: boolean;
  sparseCopy: boolean;
}

export interface TargetDefinition {
  id: string;
  displayName: string;
  aliases: readonly string[];
  endpointId: string;
  transport: TargetTransport;
  sshHost?: string;
  sshHostKeyFingerprint?: string;
  user?: string;
  expectedHostname?: string;
  platform: TargetPlatform;
  shell: "auto" | "sh" | "bash" | "zsh" | "powershell" | "cmd";
  defaultCwd?: string;
  envProfile?: string;
  elevationPolicy: ElevationPolicy;
  probeTtlMs: number;
  durableProcess: {
    mode: "none" | "tmux" | "systemd-run" | "launchd" | "task-scheduler";
  };
  gui: {
    mode: "none" | "local-ipc" | "ssh-stdio";
    command?: string;
    sha256?: string;
  };
  configuredCapabilities: ConfiguredTargetCapabilities;
  endpointFingerprint: string;
  generation: string;
}

export interface TargetCapabilities {
  fs: boolean;
  exec: boolean;
  pty: boolean;
  sftp: boolean;
  rsync: boolean;
  git: boolean;
  gui: boolean;
  mcp: boolean;
  durableProcess: boolean;
  filesystem: FilesystemPrimitiveCapabilities;
}

export interface TargetObservation {
  targetId: string;
  endpointId: string;
  targetGeneration: string;
  status: "ONLINE" | "OFFLINE" | "DEGRADED" | "UNKNOWN";
  ready: boolean;
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
  targets: readonly TargetDefinition[];
}

export interface TargetRegistryOptions {
  configPath: string;
  now?: () => number;
  probeTimeoutMs?: number;
  sshExecutable?: string;
  sftpExecutable?: string;
  execute?: typeof execFileAsync;
  cursorStore?: SignedSnapshotCursorStore;
}

const targetSchema = z.strictObject({
  displayName: z.string().min(1).max(128),
  aliases: z.array(z.string().min(1).max(128)).optional(),
  endpointId: z.string().min(1).max(128).optional(),
  transport: z.enum(["local", "ssh"]),
  sshHost: z.string().min(1).optional(),
  sshHostKeyFingerprint: z.string().min(1).max(256).optional(),
  user: z.string().min(1).max(256).optional(),
  expectedHostname: z.string().min(1).max(256).optional(),
  platform: z.enum(["macos", "linux", "windows", "unknown"]),
  shell: z.enum(["auto", "sh", "bash", "zsh", "powershell", "cmd"]).optional(),
  defaultCwd: z.string().min(1).optional(),
  envProfile: z.string().min(1).optional(),
  elevationPolicy: z.enum(["deny", "prompt"]).optional(),
  probeTtlMs: z.number().int().min(1_000).max(3_600_000).optional(),
  durableProcess: z.strictObject({
    mode: z.enum(["none", "tmux", "systemd-run", "launchd", "task-scheduler"]),
  }).optional(),
  gui: z.strictObject({
    mode: z.enum(["none", "local-ipc", "ssh-stdio"]),
    command: z.string().min(1).optional(),
    sha256: z.string().regex(/^[a-f0-9]{64}$/u).optional(),
  }).optional(),
  capabilities: z.strictObject({
    fs: z.boolean().optional(),
    exec: z.boolean().optional(),
    pty: z.boolean().optional(),
    mcp: z.boolean().optional(),
    artifact: z.boolean().optional(),
    gui: z.boolean().optional(),
    durableProcess: z.boolean().optional(),
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
  const hasGuiCommand = target.gui?.command !== undefined;
  const hasGuiSha256 = target.gui?.sha256 !== undefined;
  if (hasGuiCommand !== hasGuiSha256) {
    context.addIssue({
      code: "custom",
      path: ["gui"],
      message: "GUI agent command and sha256 must be configured together",
    });
  }
  if ((hasGuiCommand || hasGuiSha256) && target.platform !== "macos") {
    context.addIssue({
      code: "custom",
      path: ["gui"],
      message: "A signed GUI agent is supported only on macOS",
    });
  }
  if ((hasGuiCommand || hasGuiSha256) && target.gui?.mode === "none") {
    context.addIssue({
      code: "custom",
      path: ["gui", "mode"],
      message: "A signed GUI agent cannot use gui.mode=none",
    });
  }
  if (target.gui?.command && !target.gui.command.startsWith("/")) {
    context.addIssue({
      code: "custom",
      path: ["gui", "command"],
      message: "GUI agent command must be an absolute path",
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
  private readonly probeInFlight = new Map<string, Promise<TargetObservation>>();
  private readonly now: () => number;
  private readonly probeTimeoutMs: number;
  private readonly sshExecutable: string;
  private readonly sftpExecutable: string;
  private readonly execute: typeof execFileAsync;
  private probeCacheHits = 0;
  private probeCacheMisses = 0;
  private probeCoalesced = 0;
  private probeOnline = 0;
  private probeDegraded = 0;
  private probeOffline = 0;
  private probeDurationMsTotal = 0;
  private lastProbeDurationMs = 0;

  constructor(private readonly options: TargetRegistryOptions) {
    this.now = options.now ?? Date.now;
    this.probeTimeoutMs = options.probeTimeoutMs ?? DEFAULT_PROBE_TIMEOUT_MS;
    this.sshExecutable = options.sshExecutable ?? "ssh";
    this.sftpExecutable = options.sftpExecutable ?? "sftp";
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
    const generation = sha256(JSON.stringify(targets.map((target) => ({
      targetId: target.id,
      generation: target.generation,
    }))));
    this.snapshot = deepFreeze({ generation, targets });
    this.snapshotContentHash = contentHash;
    this.pruneProbeCache(new Set(targets.map((target) => `${target.generation}:${target.id}`)));
    return this.snapshot;
  }

  async list(
    input: { cursor?: string; limit?: number } = {},
    callContext?: CapabilityCallContext,
  ): Promise<{
    generation: string;
    targets: Array<Record<string, unknown>>;
    logicalTargetCount: number;
    uniqueEndpointCount: number;
    nextCursor?: string;
  }> {
    const snapshot = await this.inspect();
    const limit = Math.min(Math.max(input.limit ?? 50, 1), 200);
    const page = this.options.cursorStore
      ? targetCursorPage(
          this.options.cursorStore,
          requireCapabilityCallContext(callContext),
          snapshot,
          input.cursor,
          limit,
        )
      : targetUnpagedResult(snapshot, input.cursor, limit);
    return {
      generation: snapshot.generation,
      targets: page.targets.map(targetSummary),
      logicalTargetCount: snapshot.targets.length,
      uniqueEndpointCount: new Set(snapshot.targets.map((target) => target.endpointId)).size,
      ...(page.nextCursor ? { nextCursor: page.nextCursor } : {}),
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
    const target = resolveTargetFromSnapshot(snapshot, selector);
    return {
      generation: target.generation,
      target,
    };
  }

  async probe(
    selector: string | undefined,
    options: { refresh?: boolean } = {},
  ): Promise<TargetObservation> {
    const { generation, target } = await this.resolveWithGeneration(selector);
    const key = `${generation}:${target.id}`;
    const cached = this.probeCache.get(key);
    if (!options.refresh && cached && Date.parse(cached.expiresAt) > this.now()) {
      this.probeCacheHits += 1;
      return observationWithProbeMetadata(cached, generation, "hit");
    }

    const inFlight = this.probeInFlight.get(key);
    if (inFlight) {
      this.probeCoalesced += 1;
      return observationWithProbeMetadata(await inFlight, generation, "shared");
    }

    this.probeCacheMisses += 1;
    const pending = this.performProbe(target, key);
    this.probeInFlight.set(key, pending);
    try {
      return observationWithProbeMetadata(await pending, generation, "miss");
    } finally {
      if (this.probeInFlight.get(key) === pending) this.probeInFlight.delete(key);
    }
  }

  async cachedObservation(selector: string | undefined): Promise<TargetObservation | undefined> {
    const { generation, target } = await this.resolveWithGeneration(selector);
    const cached = this.probeCache.get(`${generation}:${target.id}`);
    if (!cached || Date.parse(cached.expiresAt) <= this.now()) return undefined;
    return observationWithProbeMetadata(cached, generation, "hit");
  }

  stats(): Record<string, number> {
    return {
      probeCacheEntries: this.probeCache.size,
      probeInFlight: this.probeInFlight.size,
      probeCacheHits: this.probeCacheHits,
      probeCacheMisses: this.probeCacheMisses,
      probeCoalesced: this.probeCoalesced,
      probeOnline: this.probeOnline,
      probeDegraded: this.probeDegraded,
      probeOffline: this.probeOffline,
      probeDurationMsTotal: roundedMilliseconds(this.probeDurationMsTotal),
      averageProbeDurationMs: roundedMilliseconds(
        this.probeCacheMisses > 0 ? this.probeDurationMsTotal / this.probeCacheMisses : 0,
      ),
      lastProbeDurationMs: roundedMilliseconds(this.lastProbeDurationMs),
    };
  }

  private async performProbe(
    target: TargetDefinition,
    key: string,
  ): Promise<TargetObservation> {
    const started = performance.now();
    const rawObservation = target.transport === "local"
      ? await this.probeLocal(target)
      : await this.probeSsh(target);
    const observed = applyTargetIdentityReadiness(
      target,
      applyConfiguredCapabilities(target, rawObservation),
    );
    const durationMs = Math.max(0, performance.now() - started);
    this.lastProbeDurationMs = durationMs;
    this.probeDurationMsTotal += durationMs;
    if (observed.status === "ONLINE") this.probeOnline += 1;
    else if (observed.status === "DEGRADED") this.probeDegraded += 1;
    else if (observed.status === "OFFLINE") this.probeOffline += 1;
    const retained = {
      ...observed,
      evidence: {
        ...(observed.evidence ?? {}),
        probeDurationMs: roundedMilliseconds(durationMs),
      },
    };
    const currentTarget = this.snapshot?.targets.find((candidate) => candidate.id === target.id);
    const currentKey = currentTarget ? `${currentTarget.generation}:${target.id}` : undefined;
    if (currentKey === key) this.probeCache.set(key, retained);
    return retained;
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
    const platform = target.platform === "unknown" ? currentPlatform() : target.platform;
    const [git, rsync, boundary, filesystem] = await Promise.all([
      commandAvailable("git", this.execute),
      commandAvailable("rsync", this.execute),
      probeLocalUserAccountBoundary(platform, this.execute),
      probeLocalFilesystemPrimitives(),
    ]);
    return {
      targetId: target.id,
      endpointId: target.endpointId,
      targetGeneration: target.generation,
      status: boundary.available ? "ONLINE" : "DEGRADED",
      ready: boundary.available,
      observedAt: new Date(observedAtMs).toISOString(),
      expiresAt: new Date(observedAtMs + target.probeTtlMs).toISOString(),
      platform,
      architecture: arch(),
      homeDirectory: homedir(),
      temporaryDirectory: tmpdir(),
      capabilities: {
        fs: boundary.available,
        exec: boundary.available,
        pty: boundary.available && process.platform !== "win32",
        sftp: false,
        rsync,
        git,
        gui: boundary.available && target.gui.mode !== "none",
        mcp: boundary.available,
        durableProcess: boundary.available && target.durableProcess.mode !== "none",
        filesystem: boundary.available ? filesystem : unavailableFilesystemPrimitives(),
      },
      ...(!boundary.available ? { reason: boundary.reason } : {}),
      evidence: {
        transport: "local",
        userAccountBoundary: boundary.mechanism,
        observedIdentity: {
          hostname: hostname(),
          user: userInfo().username,
          platform,
          homeDirectory: homedir(),
          defaultShell: process.env.SHELL,
        },
        clockSkewMs: 0,
      },
    };
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

    const macosProfile = shellQuote(macosUserOnlyProfile());
    const script = [
      "PATH=/usr/bin:/bin:/usr/sbin:/sbin; export PATH",
      "printf '__DEVSPACE_TARGET_V1__\\n'",
      "printf 'kernel=%s\\n' \"$(uname -s 2>/dev/null || printf unknown)\"",
      "printf 'hostname=%s\\n' \"$(hostname 2>/dev/null || printf unknown)\"",
      "printf 'user=%s\\n' \"$(id -un 2>/dev/null || printf unknown)\"",
      "printf 'shell=%s\\n' \"${SHELL:-unknown}\"",
      "printf 'architecture=%s\\n' \"$(uname -m 2>/dev/null || printf unknown)\"",
      "printf 'home=%s\\n' \"$HOME\"",
      "printf 'temporary=%s\\n' \"${TMPDIR:-/tmp}\"",
      "printf 'epoch=%s\\n' \"$(date +%s 2>/dev/null || printf 0)\"",
      "command -v git >/dev/null 2>&1 && printf 'git=1\\n' || printf 'git=0\\n'",
      "command -v rsync >/dev/null 2>&1 && printf 'rsync=1\\n' || printf 'rsync=0\\n'",
      "fs_probe_root=$(mktemp -d \"${TMPDIR:-/tmp}/.devspace-target-fs.XXXXXX\" 2>/dev/null || printf ''); fs_atomic_replace=0; fs_atomic_no_replace=0; fs_directory_fsync=0; fs_hardlink_publish=0; fs_trash=0; if [ -n \"$fs_probe_root\" ]; then printf replace-source >\"$fs_probe_root/replace-source\"; printf replace-destination >\"$fs_probe_root/replace-destination\"; if mv -f \"$fs_probe_root/replace-source\" \"$fs_probe_root/replace-destination\" 2>/dev/null && [ \"$(cat \"$fs_probe_root/replace-destination\" 2>/dev/null)\" = replace-source ]; then fs_atomic_replace=1; fi; printf link-source >\"$fs_probe_root/link-source\"; if ln \"$fs_probe_root/link-source\" \"$fs_probe_root/link-destination\" 2>/dev/null; then fs_atomic_no_replace=1; fs_hardlink_publish=1; fi; if command -v python3 >/dev/null 2>&1 && python3 -c 'import os,sys; descriptor=os.open(sys.argv[1],os.O_RDONLY); os.fsync(descriptor); os.close(descriptor)' \"$fs_probe_root\" >/dev/null 2>&1; then fs_directory_fsync=1; fi; printf trash-source >\"$fs_probe_root/trash-source\"; if mv \"$fs_probe_root/trash-source\" \"$fs_probe_root/trash-destination\" 2>/dev/null && [ -f \"$fs_probe_root/trash-destination\" ]; then fs_trash=1; fi; rm -rf -- \"$fs_probe_root\"; fi; printf 'fs_atomic_replace=%s\\nfs_atomic_no_replace=%s\\nfs_rename_exchange=0\\nfs_directory_fsync=%s\\nfs_hardlink_publish=%s\\nfs_trash=%s\\nfs_reflink=0\\nfs_sparse_copy=0\\n' \"$fs_atomic_replace\" \"$fs_atomic_no_replace\" \"$fs_directory_fsync\" \"$fs_hardlink_publish\" \"$fs_trash\"",
      "setpriv_path=''; if [ -x /usr/bin/setpriv ] && [ ! -L /usr/bin/setpriv ]; then setpriv_path=/usr/bin/setpriv; elif [ -x /bin/setpriv ] && [ ! -L /bin/setpriv ]; then setpriv_path=/bin/setpriv; fi",
      "if [ -n \"$setpriv_path\" ] && \"$setpriv_path\" --no-new-privs -- /bin/sh -c 'grep -Eq \"^NoNewPrivs:[[:space:]]*1\" /proc/self/status && grep -Eq \"^CapPrm:[[:space:]]*0+$\" /proc/self/status && grep -Eq \"^CapEff:[[:space:]]*0+$\" /proc/self/status && grep -Eq \"^CapAmb:[[:space:]]*0+$\" /proc/self/status' >/dev/null 2>&1; then printf 'setpriv_boundary=1\\n'; else printf 'setpriv_boundary=0\\n'; fi",
      `if [ -x /usr/bin/sandbox-exec ] && /usr/bin/sandbox-exec -p ${macosProfile} /bin/echo boundary-ok >/dev/null 2>&1 && ! /usr/bin/sandbox-exec -p ${macosProfile} /bin/ps -p $$ >/dev/null 2>&1; then printf 'sandbox_boundary=1\\n'; else printf 'sandbox_boundary=0\\n'; fi`,
    ].join("; ");

    try {
      const result = await this.execute(
        this.sshExecutable,
        sshArguments(target.sshHost, this.probeTimeoutMs, `/bin/sh -lc ${shellQuote(script)}`),
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
      const boundary = platform === "linux"
        ? { available: fields.setpriv_boundary === "1", mechanism: "verified setpriv --no-new-privs with zero process capabilities" }
        : platform === "macos"
          ? { available: fields.sandbox_boundary === "1", mechanism: "verified sandbox-exec + authorization/set-id deny" }
          : { available: false, mechanism: "unsupported" };
      const clockSkewMs = clockSkew(fields.epoch, observedAtMs);
      const clockReady = clockSkewMs === undefined
        || clockSkewMs <= MAXIMUM_READY_CLOCK_SKEW_MS;
      const ready = boundary.available && clockReady;
      const probeSuppressionReason = boundary.available
        ? "not-probed-for-clock-skew"
        : "not-probed-without-user-account-boundary";
      const [pty, sftp] = ready
        ? await Promise.all([
            probePosixSshPty(
              target,
              platform,
              this.sshExecutable,
              this.probeTimeoutMs,
              this.execute,
            ),
            probeSftp(
              target,
              this.sftpExecutable,
              this.probeTimeoutMs,
              this.execute,
            ),
          ])
        : [
            unavailableCapabilityProbe(probeSuppressionReason),
            unavailableCapabilityProbe(probeSuppressionReason),
          ];
      return {
        targetId: target.id,
        endpointId: target.endpointId,
        targetGeneration: target.generation,
        status: ready ? "ONLINE" : "DEGRADED",
        ready,
        observedAt: new Date(observedAtMs).toISOString(),
        expiresAt,
        platform,
        architecture: fields.architecture,
        homeDirectory: fields.home,
        temporaryDirectory: fields.temporary,
        capabilities: {
          fs: ready,
          exec: ready,
          pty: ready && pty.available,
          sftp: ready && sftp.available,
          rsync: fields.rsync === "1",
          git: fields.git === "1",
          gui: ready && target.gui.mode !== "none",
          mcp: ready,
          durableProcess: ready && target.durableProcess.mode !== "none",
          filesystem: filesystemPrimitivesFromFields(fields, ready),
        },
        ...(!ready ? {
          reason: !boundary.available
            ? `Strict user-account execution boundary is unavailable: ${boundary.mechanism}.`
            : `Remote clock skew exceeds ${MAXIMUM_READY_CLOCK_SKEW_MS}ms.`,
        } : {}),
        evidence: {
          transport: "ssh",
          sshHost: target.sshHost,
          userAccountBoundary: boundary.mechanism,
          capabilityProbes: { pty, sftp },
          ...(clockSkewMs === undefined ? {} : { clockSkewMs }),
          observedIdentity: {
            hostname: fields.hostname,
            user: fields.user,
            platform,
            homeDirectory: fields.home,
            defaultShell: fields.shell,
            sshHostKeyFingerprint: sshHostKeyFingerprint(result.stderr),
          },
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
        this.sshExecutable,
        sshArguments(
          target.sshHost!,
          this.probeTimeoutMs,
          windowsTargetProbeCommand(),
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
      const elevated = fields.elevated !== "0";
      const clockSkewMs = clockSkew(fields.epoch, observedAtMs);
      const clockReady = clockSkewMs === undefined
        || clockSkewMs <= MAXIMUM_READY_CLOCK_SKEW_MS;
      const ready = !elevated && clockReady;
      const probeSuppressionReason = elevated
        ? "not-probed-for-elevated-token"
        : "not-probed-for-clock-skew";
      const [pty, sftp] = !ready
        ? [
            unavailableCapabilityProbe(probeSuppressionReason),
            unavailableCapabilityProbe(probeSuppressionReason),
          ]
        : await Promise.all([
            probeWindowsSshPty(
              target,
              this.sshExecutable,
              this.probeTimeoutMs,
              this.execute,
            ),
            probeSftp(
              target,
              this.sftpExecutable,
              this.probeTimeoutMs,
              this.execute,
            ),
          ]);
      return {
        targetId: target.id,
        endpointId: target.endpointId,
        targetGeneration: target.generation,
        status: ready ? "ONLINE" : "DEGRADED",
        ready,
        observedAt: new Date(observedAtMs).toISOString(),
        expiresAt,
        platform: "windows",
        architecture: fields.architecture,
        homeDirectory: fields.home,
        temporaryDirectory: fields.temporary,
        capabilities: {
          fs: ready && sftp.available,
          exec: ready,
          pty: ready && pty.available,
          sftp: ready && sftp.available,
          rsync: false,
          git: fields.git === "1",
          gui: ready && target.gui.mode !== "none",
          mcp: ready,
          durableProcess: ready && target.durableProcess.mode !== "none",
          filesystem: filesystemPrimitivesFromFields(fields, ready),
        },
        ...(!ready ? {
          reason: elevated
            ? "Strict user-account execution boundary rejected a high-integrity or unverifiable Windows token."
            : `Remote clock skew exceeds ${MAXIMUM_READY_CLOCK_SKEW_MS}ms.`,
        } : {}),
        evidence: {
          transport: "ssh",
          sshHost: target.sshHost,
          userAccountBoundary: elevated ? "blocked-elevated-token" : "medium-or-lower-integrity-token",
          capabilityProbes: { pty, sftp },
          ...(clockSkewMs === undefined ? {} : { clockSkewMs }),
          observedIdentity: {
            hostname: fields.hostname,
            user: fields.user,
            platform: "windows",
            homeDirectory: fields.home,
            defaultShell: fields.shell,
            sshHostKeyFingerprint: sshHostKeyFingerprint(result.stderr),
          },
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
      const sshHost = target.sshHost?.trim();
      const configuredUser = target.user?.trim() || userFromSshHost(sshHost);
      const durableProcess = target.durableProcess ?? { mode: "none" as const };
      const gui = target.gui ?? { mode: "none" as const };
      return bindTarget({
        id,
        displayName: target.displayName.trim(),
        aliases: Array.from(new Set((target.aliases ?? []).map((alias) => alias.trim()))),
        endpointId: target.endpointId?.trim()
          || (target.transport === "local" ? "local-primary" : `ssh:${sshHost}`),
        transport: target.transport,
        sshHost,
        sshHostKeyFingerprint: target.sshHostKeyFingerprint?.trim(),
        user: target.transport === "local" ? (configuredUser ?? userInfo().username) : configuredUser,
        expectedHostname: target.expectedHostname?.trim()
          || (target.transport === "local" ? hostname() : undefined),
        platform: target.platform,
        shell: target.shell ?? "auto",
        defaultCwd: target.defaultCwd,
        envProfile: target.envProfile,
        elevationPolicy: target.elevationPolicy ?? "deny",
        probeTtlMs: target.probeTtlMs ?? DEFAULT_PROBE_TTL_MS,
        durableProcess,
        gui,
        configuredCapabilities: normalizeConfiguredCapabilities(
          target.capabilities,
          gui.mode !== "none",
          durableProcess.mode !== "none",
        ),
      });
    })
    .sort((left, right) => {
      if (left.id === "local") return -1;
      if (right.id === "local") return 1;
      return left.id.localeCompare(right.id);
    });
}

type UnboundTargetDefinition = Omit<TargetDefinition, "endpointFingerprint" | "generation">;

function bindTarget(target: UnboundTargetDefinition): TargetDefinition {
  const endpointFingerprint = sha256(JSON.stringify({
    endpointId: target.endpointId,
    transport: target.transport,
    sshHost: target.sshHost,
    sshHostKeyFingerprint: target.sshHostKeyFingerprint,
    user: target.user,
    expectedHostname: target.expectedHostname,
    platform: target.platform,
  }));
  const generation = sha256(JSON.stringify({ ...target, endpointFingerprint }));
  return deepFreeze({ ...target, endpointFingerprint, generation });
}

function userFromSshHost(sshHost: string | undefined): string | undefined {
  if (!sshHost) return undefined;
  const separator = sshHost.indexOf("@");
  return separator > 0 ? sshHost.slice(0, separator) : undefined;
}

function stripSshUser(sshHost: string): string {
  const separator = sshHost.indexOf("@");
  return separator >= 0 ? sshHost.slice(separator + 1) : sshHost;
}

function defaultLocalTarget(): TargetDefinition {
  return bindTarget({
    id: "local",
    displayName: "Local machine",
    aliases: ["local", "localhost", "로컬", "내 맥", "개인 Mac"],
    endpointId: "local-primary",
    transport: "local",
    user: userInfo().username,
    expectedHostname: hostname(),
    platform: currentPlatform(),
    shell: "auto",
    elevationPolicy: "deny",
    probeTtlMs: DEFAULT_PROBE_TTL_MS,
    durableProcess: { mode: "none" },
    gui: { mode: "none" },
    configuredCapabilities: normalizeConfiguredCapabilities(undefined, false, false),
  });
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
    endpointId: target.endpointId,
    endpointFingerprint: target.endpointFingerprint,
    generation: target.generation,
    transport: target.transport,
    ...(target.sshHost ? { sshHost: target.sshHost } : {}),
    ...(target.sshHostKeyFingerprint
      ? { sshHostKeyFingerprint: target.sshHostKeyFingerprint }
      : {}),
    ...(target.user ? { user: target.user } : {}),
    platform: target.platform,
    guiMode: target.gui.mode,
    durableProcessMode: target.durableProcess.mode,
    elevation: configuredElevationCapability(target.elevationPolicy, target.platform),
    capabilities: {
      ...target.configuredCapabilities,
      filesystem: unavailableFilesystemPrimitives(),
    },
    envProfileConfigured: Boolean(target.envProfile),
  };
}

export function assertTargetCapability(
  target: TargetDefinition,
  capability: ConfiguredTargetCapability,
): void {
  if (target.configuredCapabilities[capability]) return;
  throw new UniversalBrokerError(
    "CAPABILITY_UNAVAILABLE",
    `Target ${target.id} has ${capability} disabled by configuration.`,
    {
      evidence: {
        targetId: target.id,
        targetGeneration: target.generation,
        capability,
        providerDispatchCount: 0,
      },
    },
  );
}

function normalizeConfiguredCapabilities(
  configured: Partial<Record<ConfiguredTargetCapability, boolean>> | undefined,
  guiConfigured: boolean,
  durableProcessConfigured: boolean,
): ConfiguredTargetCapabilities {
  const exec = configured?.exec ?? true;
  return Object.freeze({
    fs: configured?.fs ?? true,
    exec,
    pty: (configured?.pty ?? true) && exec,
    mcp: configured?.mcp ?? true,
    artifact: configured?.artifact ?? true,
    gui: configured?.gui ?? guiConfigured,
    durableProcess: configured?.durableProcess ?? durableProcessConfigured,
  });
}

function applyConfiguredCapabilities(
  target: TargetDefinition,
  observation: TargetObservation,
): TargetObservation {
  const configured = target.configuredCapabilities;
  return {
    ...observation,
    capabilities: {
      ...observation.capabilities,
      fs: observation.capabilities.fs && configured.fs,
      exec: observation.capabilities.exec && configured.exec,
      pty: observation.capabilities.pty && configured.pty,
      sftp: observation.capabilities.sftp && configured.fs,
      rsync: observation.capabilities.rsync && configured.fs,
      git: observation.capabilities.git && (configured.fs || configured.exec),
      gui: observation.capabilities.gui && configured.gui,
      mcp: observation.capabilities.mcp && configured.mcp,
      durableProcess: observation.capabilities.durableProcess && configured.durableProcess,
      filesystem: configured.fs
        ? { ...observation.capabilities.filesystem }
        : unavailableFilesystemPrimitives(),
    },
    evidence: {
      ...(observation.evidence ?? {}),
      configuredCapabilities: { ...configured },
    },
  };
}

function targetSelectors(target: TargetDefinition): Set<string> {
  return new Set([
    target.id,
    target.displayName,
    target.endpointId,
    ...(target.sshHost ? [target.sshHost] : []),
    ...(target.sshHost && target.user ? [`${target.user}@${stripSshUser(target.sshHost)}`] : []),
    ...target.aliases,
  ].map(normalizeSelector));
}

function normalizeSelector(value: string): string {
  return value.normalize("NFKC").trim().replace(/\s+/g, " ").toLocaleLowerCase("en-US");
}

function targetCursorPage(
  store: SignedSnapshotCursorStore,
  owner: CapabilityCallContext,
  snapshot: TargetRegistrySnapshot,
  cursor: string | undefined,
  limit: number,
): { targets: TargetDefinition[]; nextCursor?: string } {
  const binding = {
    principalKeyFingerprint: owner.principalKeyFingerprint,
    resourceKind: "target.list",
    resourceIdentityDigest: sha256("target-registry"),
    queryDigest: sha256("all-targets"),
    snapshotGeneration: snapshot.generation,
  };
  const cursorPage = cursor
    ? store.continueSnapshot({ cursor, binding, limit })
    : store.createSnapshot({
        binding,
        orderedItemIdentities: snapshot.targets.map((target) => target.id),
        limit,
      });
  const byId = new Map(snapshot.targets.map((target) => [target.id, target]));
  const targets = cursorPage.itemIdentities.map((identity) => {
    const target = byId.get(identity);
    if (!target) {
      throw new UniversalBrokerError(
        "CURSOR_STALE",
        "Target pagination snapshot no longer matches the target registry.",
        { evidence: { resourceKind: "target.list", providerDispatchCount: 0 } },
      );
    }
    return target;
  });
  return { targets, ...(cursorPage.nextCursor ? { nextCursor: cursorPage.nextCursor } : {}) };
}

function targetUnpagedResult(
  snapshot: TargetRegistrySnapshot,
  cursor: string | undefined,
  limit: number,
): { targets: TargetDefinition[]; nextCursor?: string } {
  if (cursor !== undefined || snapshot.targets.length > limit) {
    throw new UniversalBrokerError(
      "CAPABILITY_UNAVAILABLE",
      "Target pagination requires a configured signed cursor service.",
    );
  }
  return { targets: [...snapshot.targets] };
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

interface CapabilityProbeResult {
  available: boolean;
  mechanism: string;
  reason?: string;
}

interface ObservedTargetIdentity {
  hostname?: string;
  user?: string;
  platform?: TargetPlatform;
  homeDirectory?: string;
  defaultShell?: string;
  sshHostKeyFingerprint?: string;
}

function applyTargetIdentityReadiness(
  target: TargetDefinition,
  observation: TargetObservation,
): TargetObservation {
  const observedIdentity = asObservedTargetIdentity(observation.evidence?.observedIdentity);
  const configuredIdentity = {
    endpointId: target.endpointId,
    transport: target.transport,
    ...(target.sshHost ? { sshHost: target.sshHost } : {}),
    ...(target.sshHostKeyFingerprint
      ? { sshHostKeyFingerprint: target.sshHostKeyFingerprint }
      : {}),
    ...(target.user ? { user: target.user } : {}),
    ...(target.expectedHostname ? { hostname: target.expectedHostname } : {}),
    platform: target.platform,
    endpointFingerprint: target.endpointFingerprint,
  };
  const identityMatches = observation.status !== "OFFLINE"
    && (!target.user || normalizeIdentity(target.user) === normalizeIdentity(observedIdentity.user))
    && (!target.expectedHostname
      || normalizeIdentity(target.expectedHostname) === normalizeIdentity(observedIdentity.hostname))
    && (!target.sshHostKeyFingerprint
      || target.sshHostKeyFingerprint === observedIdentity.sshHostKeyFingerprint)
    && (target.platform === "unknown" || target.platform === observedIdentity.platform);
  const ready = observation.status === "ONLINE" && identityMatches;
  const capabilities = identityMatches
    ? observation.capabilities
    : unavailableCapabilities();
  return deepFreeze({
    ...observation,
    status: observation.status === "ONLINE" && !identityMatches ? "DEGRADED" : observation.status,
    ready,
    capabilities,
    ...(!identityMatches && observation.status !== "OFFLINE"
      ? { reason: "Target identity does not match the configured endpoint identity." }
      : {}),
    evidence: {
      ...(observation.evidence ?? {}),
      endpointId: target.endpointId,
      endpointFingerprint: target.endpointFingerprint,
      configuredIdentity,
      observedIdentity,
      identityMatches,
      readiness: ready,
    },
  });
}

function asObservedTargetIdentity(value: unknown): ObservedTargetIdentity {
  if (!value || typeof value !== "object" || Array.isArray(value)) return {};
  const record = value as Record<string, unknown>;
  return {
    ...(typeof record.hostname === "string" ? { hostname: record.hostname } : {}),
    ...(typeof record.user === "string" ? { user: record.user } : {}),
    ...(typeof record.platform === "string" ? { platform: record.platform as TargetPlatform } : {}),
    ...(typeof record.homeDirectory === "string" ? { homeDirectory: record.homeDirectory } : {}),
    ...(typeof record.defaultShell === "string" ? { defaultShell: record.defaultShell } : {}),
    ...(typeof record.sshHostKeyFingerprint === "string"
      ? { sshHostKeyFingerprint: record.sshHostKeyFingerprint }
      : {}),
  };
}

function normalizeIdentity(value: string | undefined): string {
  return value?.normalize("NFKC").trim().toLocaleLowerCase("en-US") ?? "";
}

function unavailableFilesystemPrimitives(): FilesystemPrimitiveCapabilities {
  return {
    atomicReplace: false,
    atomicNoReplace: false,
    renameExchange: false,
    directoryFsync: false,
    hardlinkPublish: false,
    trash: false,
    reflink: false,
    sparseCopy: false,
  };
}

function filesystemPrimitivesFromFields(
  fields: Record<string, string>,
  ready: boolean,
): FilesystemPrimitiveCapabilities {
  if (!ready) return unavailableFilesystemPrimitives();
  return {
    atomicReplace: fields.fs_atomic_replace === "1",
    atomicNoReplace: fields.fs_atomic_no_replace === "1",
    renameExchange: fields.fs_rename_exchange === "1",
    directoryFsync: fields.fs_directory_fsync === "1",
    hardlinkPublish: fields.fs_hardlink_publish === "1",
    trash: fields.fs_trash === "1",
    reflink: fields.fs_reflink === "1",
    sparseCopy: fields.fs_sparse_copy === "1",
  };
}

async function probeLocalFilesystemPrimitives(): Promise<FilesystemPrimitiveCapabilities> {
  const result = unavailableFilesystemPrimitives();
  let directory: string;
  try {
    directory = await mkdtemp(`${tmpdir().replace(/[\\/]$/u, "")}/devspace-target-fs-`);
  } catch {
    return result;
  }
  try {
    try {
      const source = `${directory}/replace-source`;
      const destination = `${directory}/replace-destination`;
      await writeFile(source, "replace-source", { mode: 0o600 });
      await writeFile(destination, "replace-destination", { mode: 0o600 });
      await rename(source, destination);
      result.atomicReplace = await readFile(destination, "utf8") === "replace-source";
    } catch {
      result.atomicReplace = false;
    }
    try {
      const source = `${directory}/link-source`;
      const destination = `${directory}/link-destination`;
      await writeFile(source, "link-source", { mode: 0o600 });
      await link(source, destination);
      result.atomicNoReplace = true;
      result.hardlinkPublish = true;
    } catch {
      result.atomicNoReplace = false;
      result.hardlinkPublish = false;
    }
    try {
      const handle = await open(directory, "r");
      try {
        await handle.sync();
        result.directoryFsync = true;
      } finally {
        await handle.close();
      }
    } catch {
      result.directoryFsync = false;
    }
    try {
      const source = `${directory}/trash-source`;
      const destination = `${directory}/trash-destination`;
      await writeFile(source, "trash-source", { mode: 0o600 });
      await rename(source, destination);
      result.trash = await readFile(destination, "utf8") === "trash-source";
    } catch {
      result.trash = false;
    }
    return result;
  } finally {
    await rm(directory, { recursive: true, force: true }).catch(() => undefined);
  }
}

function windowsTargetProbeCommand(): string {
  const source = [
    "$ErrorActionPreference='Continue'",
    "Write-Output '__DEVSPACE_TARGET_V1__'",
    "Write-Output ('hostname=' + $env:COMPUTERNAME)",
    "Write-Output ('user=' + $env:USERNAME)",
    "Write-Output ('shell=' + $env:ComSpec)",
    "Write-Output ('architecture=' + $env:PROCESSOR_ARCHITECTURE)",
    "Write-Output ('home=' + $HOME)",
    "Write-Output ('temporary=' + [IO.Path]::GetTempPath())",
    "Write-Output ('epoch=' + [DateTimeOffset]::UtcNow.ToUnixTimeSeconds())",
    "if(Get-Command git -ErrorAction SilentlyContinue){Write-Output 'git=1'}else{Write-Output 'git=0'}",
    "$groups=(& whoami.exe /groups /fo csv /nh 2>$null | Out-String)",
    "if($groups -match 'S-1-16-(12288|16384)'){Write-Output 'elevated=1'}else{Write-Output 'elevated=0'}",
    "$fsAtomicReplace=0; $fsAtomicNoReplace=0; $fsHardlinkPublish=0; $fsTrash=0",
    "$fsProbeRoot=Join-Path ([IO.Path]::GetTempPath()) ('.devspace-target-fs-' + [Guid]::NewGuid().ToString('N'))",
    "try{[IO.Directory]::CreateDirectory($fsProbeRoot)|Out-Null; $source=Join-Path $fsProbeRoot 'replace-source'; $destination=Join-Path $fsProbeRoot 'replace-destination'; [IO.File]::WriteAllText($source,'replace-source'); [IO.File]::WriteAllText($destination,'replace-destination'); [IO.File]::Replace($source,$destination,$null); if([IO.File]::ReadAllText($destination)-eq'replace-source'){$fsAtomicReplace=1}}catch{}",
    "try{$source=Join-Path $fsProbeRoot 'move-source'; $destination=Join-Path $fsProbeRoot 'move-destination'; [IO.File]::WriteAllText($source,'move-source'); [IO.File]::Move($source,$destination); if([IO.File]::Exists($destination)){$fsAtomicNoReplace=1}}catch{}",
    "try{$source=Join-Path $fsProbeRoot 'link-source'; $destination=Join-Path $fsProbeRoot 'link-destination'; [IO.File]::WriteAllText($source,'link-source'); New-Item -ItemType HardLink -Path $destination -Target $source -ErrorAction Stop|Out-Null; if([IO.File]::Exists($destination)){$fsHardlinkPublish=1}}catch{}",
    "try{$source=Join-Path $fsProbeRoot 'trash-source'; $destination=Join-Path $fsProbeRoot 'trash-destination'; [IO.File]::WriteAllText($source,'trash-source'); Move-Item -LiteralPath $source -Destination $destination -ErrorAction Stop; if([IO.File]::Exists($destination)){$fsTrash=1}}catch{}",
    "Write-Output ('fs_atomic_replace=' + $fsAtomicReplace); Write-Output ('fs_atomic_no_replace=' + $fsAtomicNoReplace); Write-Output 'fs_rename_exchange=0'; Write-Output 'fs_directory_fsync=0'; Write-Output ('fs_hardlink_publish=' + $fsHardlinkPublish); Write-Output ('fs_trash=' + $fsTrash); Write-Output 'fs_reflink=0'; Write-Output 'fs_sparse_copy=0'",
    "if(Test-Path -LiteralPath $fsProbeRoot){Remove-Item -LiteralPath $fsProbeRoot -Recurse -Force -ErrorAction SilentlyContinue}",
  ].join("; ");
  return `powershell.exe -NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -EncodedCommand ${Buffer.from(source, "utf16le").toString("base64")}`;
}

function unavailableCapabilities(): TargetCapabilities {
  return {
    fs: false,
    exec: false,
    pty: false,
    sftp: false,
    rsync: false,
    git: false,
    gui: false,
    mcp: false,
    durableProcess: false,
    filesystem: unavailableFilesystemPrimitives(),
  };
}

async function probePosixSshPty(
  target: TargetDefinition,
  platform: TargetPlatform,
  sshExecutable: string,
  timeoutMs: number,
  execute: typeof execFileAsync,
): Promise<CapabilityProbeResult> {
  if (!target.sshHost) return unavailableCapabilityProbe("missing-ssh-host");
  const ttyTest = "if [ -t 0 ] && [ -t 1 ]; then printf '__DEVSPACE_PTY_OK__\n'; else exit 73; fi";
  const linuxTest = [
    "grep -Eq '^NoNewPrivs:[[:space:]]*1' /proc/self/status",
    "grep -Eq '^CapPrm:[[:space:]]*0+$' /proc/self/status",
    "grep -Eq '^CapEff:[[:space:]]*0+$' /proc/self/status",
    "grep -Eq '^CapAmb:[[:space:]]*0+$' /proc/self/status",
    ttyTest,
  ].join(" && ");
  const remote = platform === "macos"
    ? `/usr/bin/sandbox-exec -p ${shellQuote(macosUserOnlyProfile())} /bin/sh -c ${shellQuote(ttyTest)}`
    : `setpriv --no-new-privs -- sh -c ${shellQuote(linuxTest)}`;
  try {
    const result = await execute(sshExecutable, [
      "-tt",
      "-o", "BatchMode=yes",
      "-o", `ConnectTimeout=${Math.max(1, Math.ceil(timeoutMs / 1_000))}`,
      "-o", "ConnectionAttempts=1",
      "-o", "LogLevel=ERROR",
      target.sshHost,
      remote,
    ], {
      timeout: timeoutMs + 1_000,
      encoding: "utf8",
      maxBuffer: 64 * 1024,
    });
    if (!result.stdout.includes("__DEVSPACE_PTY_OK__")) {
      return unavailableCapabilityProbe("ssh-tty-marker-missing");
    }
    return {
      available: true,
      mechanism: platform === "linux"
        ? "verified-ssh-tty-with-no-new-privileges-and-zero-capabilities"
        : "verified-ssh-tty-inside-macos-user-only-sandbox",
    };
  } catch (error) {
    return unavailableCapabilityProbe("ssh-tty-unavailable", error);
  }
}

async function probeWindowsSshPty(
  target: TargetDefinition,
  sshExecutable: string,
  timeoutMs: number,
  execute: typeof execFileAsync,
): Promise<CapabilityProbeResult> {
  if (!target.sshHost) return unavailableCapabilityProbe("missing-ssh-host");
  const source = [
    "$ErrorActionPreference='Stop'",
    ...windowsNonElevatedPrelude("__DEVSPACE_PTY_ELEVATED_TOKEN_BLOCKED__"),
    "if((-not [Console]::IsInputRedirected)-and(-not [Console]::IsOutputRedirected)){Write-Output '__DEVSPACE_PTY_OK__';exit 0}",
    "exit 73",
  ].join("; ");
  const encoded = Buffer.from(source, "utf16le").toString("base64");
  const remote = `powershell.exe -NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -EncodedCommand ${encoded}`;
  try {
    const result = await execute(sshExecutable, [
      "-tt",
      "-o", "BatchMode=yes",
      "-o", `ConnectTimeout=${Math.max(1, Math.ceil(timeoutMs / 1_000))}`,
      "-o", "ConnectionAttempts=1",
      "-o", "LogLevel=ERROR",
      target.sshHost,
      remote,
    ], {
      timeout: timeoutMs + 1_000,
      encoding: "utf8",
      maxBuffer: 64 * 1024,
    });
    if (!result.stdout.includes("__DEVSPACE_PTY_OK__")) {
      return unavailableCapabilityProbe("windows-ssh-tty-marker-missing");
    }
    return { available: true, mechanism: "verified-windows-openssh-pty-with-non-elevated-token" };
  } catch (error) {
    return unavailableCapabilityProbe("windows-ssh-tty-unavailable", error);
  }
}

async function probeSftp(
  target: TargetDefinition,
  sftpExecutable: string,
  timeoutMs: number,
  execute: typeof execFileAsync,
): Promise<CapabilityProbeResult> {
  if (!target.sshHost) return unavailableCapabilityProbe("missing-ssh-host");
  try {
    await execute(sftpExecutable, [
      "-q",
      "-b", nodePlatform() === "win32" ? "NUL" : "/dev/null",
      "-o", "BatchMode=yes",
      "-o", `ConnectTimeout=${Math.max(1, Math.ceil(timeoutMs / 1_000))}`,
      "-o", "ConnectionAttempts=1",
      "-o", "LogLevel=ERROR",
      target.sshHost,
    ], {
      timeout: timeoutMs + 1_000,
      encoding: "utf8",
      maxBuffer: 64 * 1024,
    });
    return { available: true, mechanism: "verified-sftp-subsystem-handshake" };
  } catch (error) {
    return unavailableCapabilityProbe("sftp-subsystem-unavailable", error);
  }
}

function unavailableCapabilityProbe(
  mechanism: string,
  error?: unknown,
): CapabilityProbeResult {
  return {
    available: false,
    mechanism,
    ...(error ? { reason: boundedError(error) } : {}),
  };
}

function observationWithProbeMetadata(
  observation: TargetObservation,
  generation: string,
  cache: "hit" | "miss" | "shared",
): TargetObservation {
  return deepFreeze({
    ...observation,
    capabilities: {
      ...observation.capabilities,
      filesystem: { ...observation.capabilities.filesystem },
    },
    evidence: {
      ...(observation.evidence ?? {}),
      targetGeneration: generation,
      cache,
    },
  });
}

function roundedMilliseconds(value: number): number {
  return Math.round(value * 1_000) / 1_000;
}

function sshArguments(host: string, timeoutMs: number, command: string): string[] {
  return [
    "-v",
    "-T",
    "-o", "BatchMode=yes",
    "-o", `ConnectTimeout=${Math.max(1, Math.ceil(timeoutMs / 1_000))}`,
    "-o", "ConnectionAttempts=1",
    host,
    command,
  ];
}

function sshHostKeyFingerprint(stderr: string): string | undefined {
  return /Server host key:\s+\S+\s+(SHA256:[A-Za-z0-9+/=]+)/u.exec(stderr)?.[1];
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

function clockSkew(epochSeconds: string | undefined, observedAtMs: number): number | undefined {
  const epoch = Number(epochSeconds);
  if (!Number.isSafeInteger(epoch) || epoch <= 0) return undefined;
  return Math.abs(epoch * 1_000 - observedAtMs);
}

async function probeLocalUserAccountBoundary(
  platform: TargetPlatform,
  execute: typeof execFileAsync,
): Promise<{ available: boolean; mechanism: string; reason?: string }> {
  if (platform === "macos") {
    try {
      const profile = macosUserOnlyProfile();
      await execute("/usr/bin/sandbox-exec", ["-p", profile, "/bin/echo", "boundary-ok"], {
        timeout: 5_000,
        encoding: "utf8",
        maxBuffer: 64 * 1024,
      });
      try {
        await execute("/usr/bin/sandbox-exec", ["-p", profile, "/bin/ps", "-p", String(process.pid)], {
          timeout: 5_000,
          encoding: "utf8",
          maxBuffer: 64 * 1024,
        });
        return {
          available: false,
          mechanism: "sandbox-set-id-test-failed-open",
          reason: "macOS sandbox permitted a set-id executable.",
        };
      } catch {
        return {
          available: true,
          mechanism: "verified sandbox-exec + authorization/set-id deny",
        };
      }
    } catch (error) {
      return {
        available: false,
        mechanism: "unverifiable-macos-sandbox",
        reason: `Unable to verify macOS sandbox boundary: ${boundedError(error)}`,
      };
    }
  }
  if (platform === "linux") {
    try {
      const setpriv = await firstExecutable(["/usr/bin/setpriv", "/bin/setpriv"]);
      await execute(setpriv, [
        "--no-new-privs",
        "--",
        "/bin/sh",
        "-c",
        "grep -Eq '^NoNewPrivs:[[:space:]]*1' /proc/self/status && grep -Eq '^CapPrm:[[:space:]]*0+$' /proc/self/status && grep -Eq '^CapEff:[[:space:]]*0+$' /proc/self/status && grep -Eq '^CapAmb:[[:space:]]*0+$' /proc/self/status",
      ], {
        timeout: 5_000,
        encoding: "utf8",
        maxBuffer: 64 * 1024,
      });
      return {
        available: true,
        mechanism: "verified setpriv --no-new-privs with zero process capabilities",
      };
    } catch (error) {
      return {
        available: false,
        mechanism: "unverifiable-linux-no-new-privs",
        reason: `Unable to verify Linux no_new_privs: ${boundedError(error)}`,
      };
    }
  }
  if (platform === "windows") {
    try {
      const result = await execute("whoami.exe", ["/groups", "/fo", "csv", "/nh"], {
        timeout: 5_000,
        encoding: "utf8",
        maxBuffer: 256 * 1024,
      });
      const elevated = windowsIntegrityIsElevated(result.stdout);
      return {
        available: !elevated,
        mechanism: elevated ? "blocked-elevated-token" : "medium-or-lower-integrity-token",
        ...(elevated ? { reason: "Windows process token is elevated." } : {}),
      };
    } catch (error) {
      return {
        available: false,
        mechanism: "unverifiable-windows-token",
        reason: `Unable to verify Windows integrity level: ${boundedError(error)}`,
      };
    }
  }
  return {
    available: false,
    mechanism: "unsupported-platform",
    reason: `Strict user-account execution is unsupported for platform ${platform}.`,
  };
}

async function commandAvailable(
  command: string,
  execute: typeof execFileAsync,
): Promise<boolean> {
  try {
    await execute("/bin/sh", ["-lc", `PATH=/usr/bin:/bin:/usr/sbin:/sbin; export PATH; command -v ${shellQuote(command)} >/dev/null 2>&1`], {
      timeout: 2_000,
      encoding: "utf8",
    });
    return true;
  } catch {
    return false;
  }
}

async function firstExecutable(paths: readonly string[]): Promise<string> {
  for (const path of paths) {
    try {
      await access(path);
      return path;
    } catch {
      // Try the next broker-owned system location.
    }
  }
  throw new Error(`Required system executable is unavailable: ${paths.join(", ")}`);
}

function offlineObservation(
  target: TargetDefinition,
  observedAtMs: number,
  expiresAt: string,
  reason: string,
): TargetObservation {
  return {
    targetId: target.id,
    endpointId: target.endpointId,
    targetGeneration: target.generation,
    status: "OFFLINE",
    ready: false,
    observedAt: new Date(observedAtMs).toISOString(),
    expiresAt,
    platform: target.platform,
    capabilities: unavailableCapabilities(),
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

function deepFreeze<T>(value: T): T {
  if (value && typeof value === "object" && !Object.isFrozen(value)) {
    for (const nested of Object.values(value as Record<string, unknown>)) deepFreeze(nested);
    Object.freeze(value);
  }
  return value;
}
