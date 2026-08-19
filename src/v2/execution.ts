import { createHash, randomUUID } from "node:crypto";
import {
  spawn,
  type ChildProcessWithoutNullStreams,
} from "node:child_process";
import {
  mkdir,
  realpath,
  rm,
  stat,
} from "node:fs/promises";
import { homedir } from "node:os";
import {
  dirname,
  isAbsolute,
  join,
  resolve,
} from "node:path";
import type { IPty } from "node-pty";
import { resolveShellCommand, terminateProcessTree } from "../process-platform.js";
import { expandHomePath } from "../roots.js";
import type { ContextRegistry } from "./contexts.js";
import {
  UniversalBrokerError,
} from "./errors.js";
import {
  resolveLocalProfileSourceFile,
  resolvedEnvProfileExecutionGeneration,
  type ResolvedEnvProfile,
  type UniversalEnvProfileRegistry,
} from "./env-profiles.js";
import { prepareSshControlPath } from "./ssh-control.js";
import {
  assertNoElevationCommand,
  commandRisk,
  EXEC_RISK_CLASSIFIER_GENERATION,
  type ProcessAuthorityBinding,
} from "./authority-policy.js";
import type { AuthorityRiskClass } from "./contracts.js";
import type { OperationAuthorityDispatchController } from "./authority.js";
import {
  createCapabilityCallContextFromTrustedPrincipal,
  requireCapabilityCallContext,
  type CapabilityCallContext,
  type CapabilityCallContextProvider,
} from "./capability-call-context.js";
import {
  sameDurableProcessIdentity,
  type DurableProcessAdapter,
  type DurableProcessEvents,
  type DurableProcessHandle,
  type DurableProcessIdentity,
} from "./durable-process-adapter.js";
import {
  assertInternalExecutionCommand,
  internalExecutionSpec,
  posixRemoteUserOnlyRunner,
  type InternalExecutionPolicy,
  windowsNonElevatedPrelude,
  wrapLocalUserOnlyExecution,
} from "./no-elevation.js";
import {
  assertTargetCapability,
  type TargetDefinition,
  type TargetRegistry,
} from "./targets.js";
import {
  RESOURCE_DEFAULT_COMPLETED_PROCESS_TTL_MS,
  RESOURCE_DEFAULT_CONCURRENT_PROCESSES,
  RESOURCE_DEFAULT_INLINE_OUTPUT_BYTES,
  RESOURCE_DEFAULT_PROCESSES,
  RESOURCE_DEFAULT_PROCESS_OUTPUT_BYTES,
} from "./resource-defaults.js";
import { SynchronousQuotaReservations } from "./quota-reservations.js";
import {
  ProcessOutputSpool,
  type ProcessOutputChannel,
} from "./process-output-spool.js";
import {
  FileProcessStateStore,
  type PersistentProcessRecord,
  type ProcessStateStore,
} from "./process-state.js";

const DEFAULT_AUTO_YIELD_MS = 10_000;
const DEFAULT_FOREGROUND_YIELD_MS = 10_000;
const DEFAULT_PROCESS_OUTPUT_CHARACTERS = RESOURCE_DEFAULT_INLINE_OUTPUT_BYTES;
const MAX_PROCESS_OUTPUT_CHARACTERS = 1_000_000;
const MAX_COMMAND_CHARACTERS = 100_000;
const MAX_WAIT_MS = 110_000;
const DEFAULT_LIST_LIMIT = 50;
const MAX_LIST_LIMIT = 500;

export type UniversalProcessState =
  | "STARTING"
  | "RUNNING"
  | "EXITED"
  | "SIGNALED"
  | "FAILED"
  | "ORPHANED"
  | "UNKNOWN";

export type ExecutionMode = "auto" | "foreground" | "background";

export interface ExecuteCommandInput {
  target?: string;
  contextId?: string;
  cwd?: string;
  command: string;
  tty?: boolean;
  mode?: ExecutionMode;
  yieldMs?: number;
  maxOutputChars?: number;
  envProfile?: string;
  durable?: boolean;
  authorityId?: string;
  /** Internal helpers may select a constrained policy; MCP callers cannot set this field. */
  internalPolicy?: InternalExecutionPolicy;
}

/** Internal broker-to-execution fence. This is not part of the public MCP input contract. */
export interface PreparedExecExecutionBinding {
  targetId: string;
  targetGeneration: string;
  targetTransport: TargetDefinition["transport"];
  targetPlatform: TargetDefinition["platform"];
  shellDialect: TargetDefinition["shell"];
  effectiveEnvProfile?: string;
  effectiveEnvProfileGeneration?: string;
  effectiveCwd: string;
  mode: ExecutionMode;
  tty: boolean;
  classifierGeneration: string;
  launchRisk: AuthorityRiskClass;
}

export interface ProcessOperationInput {
  operation:
    | "poll"
    | "write"
    | "resize"
    | "signal"
    | "wait"
    | "list"
    | "forget"
    | "restart_broker"
    | "restart_status";
  processId?: string;
  chars?: string;
  signal?: string;
  columns?: number;
  rows?: number;
  authorityId?: string;
  transactionId?: string;
  reason?: string;
  delayMs?: number;
  waitMs?: number;
  maxOutputChars?: number;
  cursor?: string;
  limit?: number;
}

export interface UniversalProcessSnapshot extends Record<string, unknown> {
  processId: string;
  targetId: string;
  transport: "local" | "ssh";
  cwd: string;
  tty: boolean;
  state: UniversalProcessState;
  startedAt: string;
  endedAt?: string;
  wallTimeMs: number;
  output: string;
  outputTruncated: boolean;
  outputBytes: number;
  outputFileTruncated: boolean;
  outputOffsets?: {
    global: number;
    stdout: number;
    stderr: number;
    pty: number;
  };
  resourceUri: string;
  durable?: boolean;
  pid?: number;
  exitCode?: number;
  signal?: string;
  errorCode?: string;
  errorMessage?: string;
}

export interface ExecutionPlaneOptions {
  targets: TargetRegistry;
  contexts: ContextRegistry;
  outputDir: string;
  sshControlDir: string;
  maxProcessRecords?: number;
  maxRunningProcesses?: number;
  maxRunningProcessesPerTarget?: number;
  /** @deprecated Inline retention is byte bounded; kept for configuration compatibility. */
  processBufferCharacters?: number;
  processOutputMaxBytes?: number;
  completedProcessTtlMs?: number;
  envProfiles?: UniversalEnvProfileRegistry;
  sshExecutable?: string;
  now?: () => number;
  spawnProcess?: typeof spawn;
  ownerProvider?: CapabilityCallContextProvider;
  processStateStore?: ProcessStateStore;
  processStateDir?: string;
  durableAdapter?: DurableProcessAdapter;
}

interface ProcessHandle {
  pid?: number;
  write(data: string): void | Promise<void>;
  resize?(columns: number, rows: number): void | Promise<void>;
  kill(signal: NodeJS.Signals): void | Promise<void>;
  pauseOutput?(): void;
  resumeOutput?(): void;
  close?(): void | Promise<void>;
}

interface ProcessEntry {
  processId: string;
  principalKeyFingerprint: string;
  targetId: string;
  targetGeneration: string;
  transport: "local" | "ssh";
  cwd: string;
  tty: boolean;
  launchRisk: AuthorityRiskClass;
  state: UniversalProcessState;
  startedAtMs: number;
  endedAtMs?: number;
  exitCode?: number;
  signal?: string;
  errorCode?: string;
  errorMessage?: string;
  requestedSignal?: NodeJS.Signals;
  durable: boolean;
  durableIdentity?: DurableProcessIdentity;
  dispatched: boolean;
  handle?: ProcessHandle;
  output: ProcessOutputSpool;
  outputClose?: Promise<void>;
  exitPromise: Promise<void>;
  resolveExit: () => void;
  cleanupTimer?: NodeJS.Timeout;
  remoteMarkers?: RemoteMarkerParser;
}

interface CommandSpec {
  executable: string;
  args: string[];
  cwd: string;
  env: NodeJS.ProcessEnv;
  remoteMarkers?: RemoteMarkerParser;
}

interface ResolvedExecution {
  target: TargetDefinition;
  targetGeneration: string;
  cwd: string;
  environment: Record<string, string>;
  envProfileGeneration?: string;
  sourceFile?: string;
}

export class UniversalExecutionPlane {
  private readonly entries = new Map<string, ProcessEntry>();
  private readonly now: () => number;
  private readonly spawnProcess: typeof spawn;
  private readonly ownerProvider: CapabilityCallContextProvider;
  private readonly maximumProcessRecords: number;
  private readonly maximumRunningProcesses: number;
  private readonly maximumRunningProcessesPerTarget: number;
  private readonly maximumInlineOutputBytes: number;
  private readonly maximumProcessOutputBytes: number;
  private readonly completedProcessTtlMs: number;
  private readonly reservations: SynchronousQuotaReservations;
  private readonly stateStore: ProcessStateStore;
  private readonly pendingStateWrites = new Set<Promise<void>>();
  private recoveryPromise?: Promise<void>;
  private readonly nonDurableAfterRestart = new Map<string, string>();
  private closed = false;

  constructor(private readonly options: ExecutionPlaneOptions) {
    this.now = options.now ?? Date.now;
    this.spawnProcess = options.spawnProcess ?? spawn;
    this.maximumProcessRecords = boundedOption(
      options.maxProcessRecords,
      RESOURCE_DEFAULT_PROCESSES,
      1,
      100_000,
      "maxProcessRecords",
    );
    this.maximumRunningProcesses = boundedOption(
      options.maxRunningProcesses,
      RESOURCE_DEFAULT_CONCURRENT_PROCESSES,
      1,
      10_000,
      "maxRunningProcesses",
    );
    this.maximumRunningProcessesPerTarget = boundedOption(
      options.maxRunningProcessesPerTarget,
      this.maximumRunningProcesses,
      1,
      10_000,
      "maxRunningProcessesPerTarget",
    );
    this.maximumInlineOutputBytes = boundedOption(
      options.processBufferCharacters,
      RESOURCE_DEFAULT_INLINE_OUTPUT_BYTES,
      1,
      10_000_000,
      "processBufferCharacters",
    );
    this.maximumProcessOutputBytes = boundedOption(
      options.processOutputMaxBytes,
      RESOURCE_DEFAULT_PROCESS_OUTPUT_BYTES,
      1_000,
      2_000_000_000,
      "processOutputMaxBytes",
    );
    this.completedProcessTtlMs = boundedOption(
      options.completedProcessTtlMs,
      RESOURCE_DEFAULT_COMPLETED_PROCESS_TTL_MS,
      1_000,
      7 * 24 * 60 * 60_000,
      "completedProcessTtlMs",
    );
    this.reservations = new SynchronousQuotaReservations("process", {
      records: this.maximumProcessRecords,
      concurrent: this.maximumRunningProcesses,
    });
    const compatibilityOwner = createCapabilityCallContextFromTrustedPrincipal({
      principalKeyFingerprint: createHash("sha256")
        .update(JSON.stringify({
          authority: "legacy-single-owner-execution-plane",
          outputDir: resolve(options.outputDir),
        }))
        .digest("hex"),
    });
    this.ownerProvider = options.ownerProvider ?? (() => compatibilityOwner);
    this.stateStore = options.processStateStore ?? new FileProcessStateStore(
      options.processStateDir ?? join(dirname(options.outputDir), "processes"),
    );
  }

  async prepareAuthorityBinding(
    input: ExecuteCommandInput,
    target: TargetDefinition,
    targetGeneration: string,
    callContext?: CapabilityCallContext,
  ): Promise<PreparedExecExecutionBinding> {
    await this.ensureRecovered();
    const resolved = await this.resolveExecution(input, callContext);
    if (resolved.target.id !== target.id || resolved.targetGeneration !== targetGeneration) {
      throw new UniversalBrokerError(
        "AUTHORITY_STALE",
        "Execution target changed while canonicalizing its authority resource.",
      );
    }
    return prepareExecExecutionBinding(
      input,
      resolved.target,
      resolved.targetGeneration,
      resolved.envProfileGeneration,
      resolved.cwd,
    );
  }

  async execute(
    input: ExecuteCommandInput,
    expectedBinding?: PreparedExecExecutionBinding,
    dispatch?: OperationAuthorityDispatchController,
    callContext?: CapabilityCallContext,
  ): Promise<UniversalProcessSnapshot> {
    this.assertOpen();
    await this.ensureRecovered();
    const owner = this.owner(callContext);
    validateCommand(input.command);
    assertNoElevationCommand(input.command);
    assertInternalExecutionCommand(input.internalPolicy, input.command);
    if (input.internalPolicy && input.envProfile) {
      throw new UniversalBrokerError(
        "ELEVATION_BLOCKED",
        "Internal execution policies cannot load an environment profile.",
        { evidence: { policy: typeof input.internalPolicy === "string" ? input.internalPolicy : input.internalPolicy.kind } },
      );
    }
    if (input.durable === true && !this.options.durableAdapter) {
      throw new UniversalBrokerError(
        "CAPABILITY_UNAVAILABLE",
        "durable=true requires a configured external process-manager adapter.",
        { evidence: { reasonCode: "DURABLE_PROCESS_ADAPTER_REQUIRED" } },
      );
    }
    const resolved = await this.resolveExecution(input, callContext);
    const observedBinding = prepareExecExecutionBinding(
      input,
      resolved.target,
      resolved.targetGeneration,
      resolved.envProfileGeneration,
      resolved.cwd,
    );
    assertPreparedExecExecutionBinding(expectedBinding, observedBinding);
    const launchRisk = observedBinding.launchRisk;
    await assertCachedExecutionCapability(
      this.options.targets,
      resolved.target,
      input.tty === true,
    );
    const reservation = this.reserveProcess(resolved.target.id);
    try {
      await Promise.all([
        mkdir(this.options.outputDir, { recursive: true, mode: 0o700 }),
        mkdir(this.options.sshControlDir, { recursive: true, mode: 0o700 }),
      ]);

      const processId = `proc_${randomUUID()}`;
      const output = new ProcessOutputSpool({
        path: join(this.options.outputDir, `${processId}.log`),
        maximumInlineBytes: this.maximumInlineOutputBytes,
        maximumFileBytes: this.maximumProcessOutputBytes,
      });
      await output.open();
      let resolveExit!: () => void;
      const exitPromise = new Promise<void>((resolvePromise) => {
        resolveExit = resolvePromise;
      });
      const entry: ProcessEntry = {
        processId,
        principalKeyFingerprint: owner.principalKeyFingerprint,
        targetId: resolved.target.id,
        targetGeneration: resolved.targetGeneration,
        transport: resolved.target.transport,
        cwd: resolved.cwd,
        tty: input.tty === true,
        launchRisk,
        state: "STARTING",
        startedAtMs: this.now(),
        durable: input.durable === true,
        dispatched: false,
        output,
        exitPromise,
        resolveExit,
      };
      reservation.commit(() => this.entries.set(processId, entry));
      await this.persistEntry(entry);

      try {
        const spec = await this.commandSpec(resolved, input, processId);
        entry.remoteMarkers = spec.remoteMarkers;
        dispatch?.claim();
        if (entry.durable) await this.startDurable(entry, spec, dispatch);
        else if (entry.tty) await this.startPty(entry, spec, dispatch);
        else this.startPipe(entry, spec, dispatch);
        if (entry.state === "STARTING") entry.state = "RUNNING";
        await this.persistEntry(entry);
      } catch (error) {
        this.finishSpawnFailure(entry, error);
        await this.persistEntry(entry).catch(() => undefined);
        if (
          error instanceof UniversalBrokerError
          && [
            "AUTHORITY_REQUIRED",
            "AUTHORITY_EXPIRED",
            "AUTHORITY_PRINCIPAL_MISMATCH",
            "AUTHORITY_ACTION_MISMATCH",
            "AUTHORITY_STALE",
            "AUTHORITY_CONSUMED",
            "AUTHORITY_STORE_UNAVAILABLE",
            "AUTHORITY_STATE_UNCERTAIN",
            "RESOURCE_BUSY",
          ].includes(error.code)
        ) {
          throw error;
        }
      }

      const mode = input.mode ?? "auto";
      const yieldMs = executionYield(mode, input.yieldMs);
      if (yieldMs > 0) await waitForExit(entry, yieldMs);
      const snapshot = this.snapshot(entry, input.maxOutputChars);
      return validateExecutionSnapshot(snapshot);
    } finally {
      reservation.release();
    }
  }

  async operate(
    input: ProcessOperationInput,
    dispatch?: OperationAuthorityDispatchController,
    callContext?: CapabilityCallContext,
  ): Promise<Record<string, unknown>> {
    this.assertOpen();
    await this.ensureRecovered();
    const owner = this.owner(callContext);
    if (input.operation === "restart_broker" || input.operation === "restart_status") {
      throw new UniversalBrokerError(
        "PRECONDITION_FAILED",
        `${input.operation} must be handled by the broker self-management service.`,
      );
    }
    if (input.operation === "list") return this.list(owner, input.cursor, input.limit);
    const processId = requireProcessId(input.processId, input.operation);
    const entry = this.requireEntry(processId, owner);
    if (["write", "resize", "signal", "forget"].includes(input.operation)) {
      dispatch?.claim();
    }

    switch (input.operation) {
      case "poll":
        if (entry.state === "RUNNING" || entry.state === "STARTING") {
          await waitForExit(entry, boundedWait(input.waitMs ?? 0));
        }
        return this.snapshot(entry, input.maxOutputChars);
      case "wait":
        if (entry.state === "RUNNING" || entry.state === "STARTING") {
          await waitForExit(entry, boundedWait(input.waitMs ?? MAX_WAIT_MS));
        }
        return this.snapshot(entry, input.maxOutputChars);
      case "write": {
        if (!isRunning(entry)) {
          throw new UniversalBrokerError(
            "PROCESS_NOT_FOUND",
            `Process is not running: ${processId}`,
            { evidence: { processId, state: entry.state } },
          );
        }
        if (!entry.handle) {
          throw new UniversalBrokerError(
            "PROCESS_NOT_FOUND",
            `Process has no active provider handle: ${processId}`,
            { evidence: { processId, state: entry.state } },
          );
        }
        dispatch?.markDispatched();
        await entry.handle.write(input.chars ?? "");
        if (input.waitMs) await waitForExit(entry, boundedWait(input.waitMs));
        return this.snapshot(entry, input.maxOutputChars);
      }
      case "resize": {
        if (!isRunning(entry) || !entry.handle?.resize) {
          throw new UniversalBrokerError(
            "PRECONDITION_FAILED",
            `Process does not expose a resizable PTY: ${processId}`,
            { evidence: { processId, state: entry.state, tty: entry.tty } },
          );
        }
        const columns = terminalDimension(input.columns, "columns");
        const rows = terminalDimension(input.rows, "rows");
        dispatch?.markDispatched();
        await entry.handle.resize(columns, rows);
        return this.snapshot(entry, input.maxOutputChars);
      }
      case "signal": {
        if (!isRunning(entry)) return this.snapshot(entry, input.maxOutputChars);
        const signal = processSignal(input.signal);
        if (!entry.handle) {
          throw new UniversalBrokerError(
            "PROCESS_NOT_FOUND",
            `Process has no active provider handle: ${processId}`,
            { evidence: { processId, state: entry.state } },
          );
        }
        dispatch?.markDispatched();
        await entry.handle.kill(signal);
        entry.requestedSignal = signal;
        await this.persistEntry(entry);
        await waitForExit(entry, boundedWait(input.waitMs ?? 2_000));
        return this.snapshot(entry, input.maxOutputChars);
      }
      case "forget": {
        if (isRunning(entry)) {
          throw new UniversalBrokerError(
            "PRECONDITION_FAILED",
            `Running process must be signalled before it can be forgotten: ${processId}`,
            { evidence: { processId, state: entry.state } },
          );
        }
        dispatch?.markDispatched();
        await this.forgetEntry(entry);
        return { processId, forgotten: true };
      }
    }
  }

  authorityBinding(
    processId: string | undefined,
    operation: ProcessOperationInput["operation"],
    callContext?: CapabilityCallContext,
  ): ProcessAuthorityBinding {
    const entry = this.requireEntry(requireProcessId(processId, operation), this.owner(callContext));
    return {
      targetId: entry.targetId,
      targetGeneration: entry.targetGeneration,
      targetTransport: entry.transport,
      tty: entry.tty,
      launchRisk: entry.launchRisk,
    };
  }

  async readOutput(
    processId: string,
    offset: number,
    limit: number,
    callContext?: CapabilityCallContext,
    channel: "global" | ProcessOutputChannel = "global",
  ): Promise<{ text: string; nextOffset?: number; totalBytes: number; truncated: boolean }> {
    await this.ensureRecovered();
    const entry = this.requireEntry(processId, this.owner(callContext));
    if (entry.outputClose) await Promise.race([
      entry.outputClose,
      new Promise<void>((resolvePromise) => setTimeout(resolvePromise, 50)),
    ]);
    return entry.output.read(offset, limit, channel);
  }

  async close(): Promise<void> {
    if (this.closed) return;
    this.closed = true;
    const running = [...this.entries.values()].filter((entry) => isRunning(entry) && !entry.durable);
    const durable = [...this.entries.values()].filter((entry) => isRunning(entry) && entry.durable);
    await Promise.allSettled(durable.map(async (entry) => {
      await entry.handle?.close?.();
      await entry.output.close();
      await this.persistEntry(entry);
    }));
    for (const entry of running) {
      entry.requestedSignal = "SIGTERM";
      try {
        await entry.handle?.kill("SIGTERM");
      } catch {
        // Continue shutting down other processes.
      }
    }
    await Promise.race([
      Promise.allSettled(running.map((entry) => entry.exitPromise)),
      new Promise<void>((resolvePromise) => setTimeout(resolvePromise, 2_000)),
    ]);
    for (const entry of running.filter(isRunning)) {
      entry.requestedSignal = "SIGKILL";
      try {
        await entry.handle?.kill("SIGKILL");
      } catch {
        // Process may already have exited.
      }
    }
    await Promise.race([
      Promise.allSettled(running.map((entry) => entry.exitPromise)),
      new Promise<void>((resolvePromise) => setTimeout(resolvePromise, 2_000)),
    ]);
    await Promise.allSettled(
      [...this.entries.values()]
        .map((entry) => entry.outputClose)
        .filter((pending): pending is Promise<void> => pending !== undefined),
    );
    await this.drainPendingStateWrites();
  }

  stats(): Record<string, unknown> {
    const entries = [...this.entries.values()];
    const byTarget = new Map<string, { total: number; running: number; outputBytes: number }>();
    for (const entry of entries) {
      const current = byTarget.get(entry.targetId) ?? { total: 0, running: 0, outputBytes: 0 };
      current.total += 1;
      if (isRunning(entry)) current.running += 1;
      current.outputBytes += entry.output.totalFileBytes;
      byTarget.set(entry.targetId, current);
    }
    return {
      processes: entries.length,
      runningProcesses: entries.filter(isRunning).length,
      outputBytes: entries.reduce((total, entry) => total + entry.output.totalFileBytes, 0),
      byTarget: Object.fromEntries([...byTarget].sort(([left], [right]) => left.localeCompare(right))),
    };
  }

  private async resolveExecution(
    input: ExecuteCommandInput,
    callContext?: CapabilityCallContext,
  ): Promise<ResolvedExecution> {
    const context = input.contextId
      ? await this.options.contexts.get(input.contextId, callContext)
      : undefined;
    const targetBinding = await this.options.targets.resolveWithGeneration(input.target ?? context?.targetId);
    const target = targetBinding.target;
    assertTargetCapability(target, "exec");
    if (input.tty === true) assertTargetCapability(target, "pty");
    if (input.durable === true) assertTargetCapability(target, "durableProcess");
    if (context && context.targetId !== target.id) {
      throw new UniversalBrokerError(
        "PRECONDITION_FAILED",
        `Context ${context.contextId} belongs to target ${context.targetId}, not ${target.id}.`,
        {
          evidence: {
            contextId: context.contextId,
            contextTargetId: context.targetId,
            requestedTargetId: target.id,
          },
        },
      );
    }
    const requestedCwd = input.cwd ?? context?.root ?? target.defaultCwd
      ?? (target.transport === "local" ? homedir() : "~");
    const cwd = target.transport === "local"
      ? await resolveLocalCwd(requestedCwd)
      : requestedCwd;
    const profile = await this.resolveEnvironmentProfile(input, target);
    const envProfileGeneration = profile
      ? await resolvedEnvProfileExecutionGeneration(
          profile,
          target.transport === "local" ? "local" : "remote",
        )
      : undefined;
    const sourceFile = profile?.sourceFile
      ? target.transport === "local"
        ? resolveLocalProfileSourceFile(profile.sourceFile)
        : profile.sourceFile
      : undefined;
    return {
      target,
      targetGeneration: targetBinding.generation,
      cwd,
      environment: profile?.environment ?? {},
      ...(envProfileGeneration ? { envProfileGeneration } : {}),
      ...(sourceFile ? { sourceFile } : {}),
    };
  }

  private async resolveEnvironmentProfile(
    input: ExecuteCommandInput,
    target: TargetDefinition,
  ): Promise<ResolvedEnvProfile | undefined> {
    const profileName = input.envProfile ?? target.envProfile;
    const profile = profileName
      ? await this.requireEnvProfiles().resolve(profileName, target.id)
      : undefined;
    if (target.transport === "ssh" && profile && Object.keys(profile.environment).length > 0) {
      throw new UniversalBrokerError(
        "PRECONDITION_FAILED",
        `Remote target ${target.id} environment profile ${profile.id} must use sourceFile instead of inline environment values.`,
      );
    }
    if (target.platform === "windows" && profile?.sourceFile) {
      throw new UniversalBrokerError(
        "CAPABILITY_UNAVAILABLE",
        `Windows environment profile source files are unavailable on target ${target.id}.`,
      );
    }
    return profile;
  }

  private requireEnvProfiles(): UniversalEnvProfileRegistry {
    if (!this.options.envProfiles) {
      throw new UniversalBrokerError(
        "CAPABILITY_UNAVAILABLE",
        "Environment profile registry is not configured.",
      );
    }
    return this.options.envProfiles;
  }


  private async commandSpec(
    resolved: ResolvedExecution,
    input: ExecuteCommandInput,
    processId: string,
  ): Promise<CommandSpec> {
    if (resolved.target.transport === "local") {
      return localCommandSpec(resolved, input.command, input.internalPolicy);
    }
    return remoteCommandSpec({
      resolved,
      command: input.command,
      processId,
      tty: input.tty === true,
      internalPolicy: input.internalPolicy,
      sshControlDir: this.options.sshControlDir,
      sshExecutable: this.options.sshExecutable ?? "ssh",
    });
  }

  private startPipe(
    entry: ProcessEntry,
    spec: CommandSpec,
    dispatch?: OperationAuthorityDispatchController,
  ): void {
    const detached = process.platform !== "win32";
    dispatch?.markDispatched();
    entry.dispatched = true;
    const child = this.spawnProcess(spec.executable, spec.args, {
      cwd: spec.cwd,
      env: spec.env,
      detached,
      windowsHide: true,
      stdio: ["pipe", "pipe", "pipe"],
    }) as ChildProcessWithoutNullStreams;
    entry.handle = {
      pid: child.pid,
      write: (data) => writeWritable(child.stdin, data),
      kill: (signal) => terminateProcessTree(child, signal, detached),
    };
    this.attachReadableOutput(entry, child.stdout, "stdout");
    this.attachReadableOutput(entry, child.stderr, "stderr");
    child.once("error", (error) => this.finishSpawnFailure(entry, error));
    child.once("close", (code, signal) => this.finish(entry, code, signal ?? undefined));
  }

  private async startPty(
    entry: ProcessEntry,
    spec: CommandSpec,
    dispatch?: OperationAuthorityDispatchController,
  ): Promise<void> {
    const nodePty = await import("node-pty");
    dispatch?.markDispatched();
    entry.dispatched = true;
    const pty: IPty = nodePty.spawn(spec.executable, spec.args, {
      cwd: spec.cwd,
      env: normalizePtyEnvironment(spec.env),
      name: "xterm-256color",
      cols: 80,
      rows: 24,
    });
    entry.handle = {
      pid: pty.pid,
      write: (data) => pty.write(data),
      resize: (columns, rows) => pty.resize(columns, rows),
      kill: (signal) => pty.kill(signal),
      pauseOutput: () => pty.pause(),
      resumeOutput: () => pty.resume(),
    };
    pty.onData((data) => {
      pty.pause();
      void this.appendOutput(entry, "pty", Buffer.from(data, "utf8"))
        .finally(() => {
          if (isRunning(entry)) pty.resume();
        });
    });
    pty.onExit(({ exitCode, signal }) => {
      this.finish(entry, exitCode, signal ? String(signal) : undefined);
    });
  }

  private async startDurable(
    entry: ProcessEntry,
    spec: CommandSpec,
    dispatch?: OperationAuthorityDispatchController,
  ): Promise<void> {
    const adapter = this.options.durableAdapter!;
    const events = this.durableEvents(entry);
    dispatch?.markDispatched();
    entry.dispatched = true;
    const handle = await adapter.launch({
      processId: entry.processId,
      targetId: entry.targetId,
      executable: spec.executable,
      args: spec.args,
      cwd: spec.cwd,
      environment: spec.env,
      tty: entry.tty,
    }, events);
    assertDurableIdentity(handle.identity);
    entry.durableIdentity = { ...handle.identity };
    entry.handle = adaptDurableHandle(handle);
  }

  private durableEvents(entry: ProcessEntry): DurableProcessEvents {
    return {
      output: (channel, data) => {
        entry.handle?.pauseOutput?.();
        void this.appendOutput(entry, channel, data).finally(() => entry.handle?.resumeOutput?.());
      },
      exit: (exitCode, signal) => this.finish(entry, exitCode, signal),
      error: (error) => this.finishSpawnFailure(entry, error),
    };
  }

  private attachReadableOutput(
    entry: ProcessEntry,
    readable: NodeJS.ReadableStream & { pause(): unknown; resume(): unknown },
    channel: "stdout" | "stderr",
  ): void {
    readable.on("data", (value: Buffer | string) => {
      readable.pause();
      const data = Buffer.isBuffer(value) ? value : Buffer.from(value, "utf8");
      void this.appendOutput(entry, channel, data).finally(() => {
        if (isRunning(entry)) readable.resume();
      });
    });
  }

  private appendOutput(
    entry: ProcessEntry,
    channel: ProcessOutputChannel,
    data: Uint8Array,
  ): Promise<unknown> {
    let visible = Buffer.from(data);
    if (entry.remoteMarkers) {
      const sanitized = entry.remoteMarkers.consume(visible.toString("utf8"), false, channel);
      visible = Buffer.from(sanitized, "utf8");
    }
    return visible.byteLength > 0 ? entry.output.append(channel, visible) : Promise.resolve();
  }

  private finish(entry: ProcessEntry, code: number | null, signal?: string): void {
    if (!isRunning(entry) && entry.state !== "STARTING") return;
    if (entry.remoteMarkers) {
      for (const channel of ["stdout", "stderr"] as const) {
        const finalOutput = entry.remoteMarkers.consume("", true, channel);
        if (finalOutput) void entry.output.append(channel, Buffer.from(finalOutput, "utf8"));
      }
    }
    entry.endedAtMs = this.now();

    if (entry.requestedSignal) {
      entry.state = "SIGNALED";
      entry.signal = entry.requestedSignal;
      entry.exitCode = code ?? undefined;
    } else if (entry.remoteMarkers) {
      const markers = entry.remoteMarkers;
      if (markers.elevationBlocked) {
        entry.state = "FAILED";
        entry.errorCode = "ELEVATION_BLOCKED";
        entry.errorMessage = "Remote execution target has an elevated Windows token; DevSpace requires an ordinary user token.";
      } else if (markers.cwdRejected) {
        entry.state = "FAILED";
        entry.errorCode = "PATH_NOT_FOUND";
        entry.errorMessage = `Remote working directory is unavailable: ${entry.cwd}`;
      } else if (markers.completed) {
        entry.state = "EXITED";
        entry.exitCode = markers.exitCode ?? 0;
      } else if (markers.dispatched) {
        entry.state = "UNKNOWN";
        entry.errorCode = "TRANSPORT_INTERRUPTED";
        entry.errorMessage = "SSH transport ended after dispatch but before a completion marker; the command was not retried.";
      } else {
        entry.state = "FAILED";
        entry.errorCode = "TRANSPORT_UNAVAILABLE";
        entry.errorMessage = "SSH transport ended before command dispatch.";
      }
    } else if (signal) {
      entry.state = "SIGNALED";
      entry.signal = signal;
      entry.exitCode = code ?? undefined;
    } else {
      entry.state = "EXITED";
      entry.exitCode = code ?? 0;
    }
    entry.outputClose = entry.output.close();
    entry.resolveExit();
    this.scheduleCleanup(entry);
    void this.persistEntry(entry).catch(() => undefined);
  }

  private finishSpawnFailure(entry: ProcessEntry, error: unknown): void {
    if (!isRunning(entry) && entry.state !== "STARTING") return;
    entry.endedAtMs = this.now();
    entry.state = entry.durable && entry.dispatched ? "UNKNOWN" : "FAILED";
    entry.errorCode = entry.transport === "ssh"
      ? "TRANSPORT_UNAVAILABLE"
      : "TRANSPORT_UNAVAILABLE";
    entry.errorMessage = boundedError(error);
    void entry.output.append("stderr", Buffer.from(`${entry.errorMessage}\n`, "utf8"));
    entry.outputClose = entry.output.close();
    entry.resolveExit();
    this.scheduleCleanup(entry);
    void this.persistEntry(entry).catch(() => undefined);
  }

  private snapshot(entry: ProcessEntry, maxOutputChars?: number): UniversalProcessSnapshot {
    const drained = entry.output.drain(outputLimit(maxOutputChars));
    return {
      processId: entry.processId,
      targetId: entry.targetId,
      transport: entry.transport,
      cwd: entry.cwd,
      tty: entry.tty,
      state: entry.state,
      startedAt: new Date(entry.startedAtMs).toISOString(),
      ...(entry.endedAtMs ? { endedAt: new Date(entry.endedAtMs).toISOString() } : {}),
      wallTimeMs: (entry.endedAtMs ?? this.now()) - entry.startedAtMs,
      output: drained.output,
      outputTruncated: drained.truncated,
      outputBytes: entry.output.totalFileBytes,
      outputFileTruncated: entry.output.fileTruncated,
      outputOffsets: entry.output.currentOffsets,
      resourceUri: processOutputResourceUri(entry.processId, 0, 1_048_576),
      durable: entry.durable,
      ...(entry.handle?.pid !== undefined ? { pid: entry.handle.pid } : {}),
      ...(entry.exitCode !== undefined ? { exitCode: entry.exitCode } : {}),
      ...(entry.signal ? { signal: entry.signal } : {}),
      ...(entry.errorCode ? { errorCode: entry.errorCode } : {}),
      ...(entry.errorMessage ? { errorMessage: entry.errorMessage } : {}),
    };
  }

  private async list(
    owner: CapabilityCallContext,
    cursor?: string,
    requestedLimit?: number,
  ): Promise<Record<string, unknown>> {
    const offset = parseCursor(cursor);
    const limit = Math.min(Math.max(requestedLimit ?? DEFAULT_LIST_LIMIT, 1), MAX_LIST_LIMIT);
    const entries = [...this.entries.values()]
      .filter((entry) => entry.principalKeyFingerprint === owner.principalKeyFingerprint)
      .map((entry) => ({
      processId: entry.processId,
      targetId: entry.targetId,
      transport: entry.transport,
      cwd: entry.cwd,
      tty: entry.tty,
      state: entry.state,
      durable: entry.durable,
      ...(entry.handle?.pid !== undefined ? { pid: entry.handle.pid } : {}),
      startedAt: new Date(entry.startedAtMs).toISOString(),
      ...(entry.endedAtMs ? { endedAt: new Date(entry.endedAtMs).toISOString() } : {}),
      ...(entry.exitCode !== undefined ? { exitCode: entry.exitCode } : {}),
      ...(entry.signal ? { signal: entry.signal } : {}),
    })).sort((left, right) => Date.parse(String(right.startedAt)) - Date.parse(String(left.startedAt)));
    const page = entries.slice(offset, offset + limit);
    const nextOffset = offset + page.length;
    return {
      processes: page,
      ...(nextOffset < entries.length ? { nextCursor: String(nextOffset) } : {}),
    };
  }

  private reserveProcess(targetId: string) {
    const running = [...this.entries.values()].filter(isRunning);
    const targetRunning = running.filter((entry) => entry.targetId === targetId).length;
    if (targetRunning >= this.maximumRunningProcessesPerTarget) {
      throw new UniversalBrokerError(
        "RESOURCE_QUOTA_EXCEEDED",
        `Running-process limit reached for target ${targetId}: ${this.maximumRunningProcessesPerTarget}`,
        {
          evidence: {
            targetId,
            maximum: this.maximumRunningProcessesPerTarget,
            current: targetRunning,
          },
        },
      );
    }
    return this.reservations.reserve(
      {
        records: this.entries.size + this.nonDurableAfterRestart.size,
        concurrent: running.length,
      },
      { records: 1, concurrent: 1 },
    );
  }

  private requireEntry(processId: string, owner: CapabilityCallContext): ProcessEntry {
    const nonDurableOwner = this.nonDurableAfterRestart.get(processId);
    if (nonDurableOwner) {
      this.assertProcessOwner(nonDurableOwner, owner, processId);
      throw new UniversalBrokerError(
        "PROCESS_NOT_FOUND",
        `Process ${processId} was non-durable and cannot be reattached after broker restart.`,
        {
          evidence: {
            processId,
            reasonCode: "NON_DURABLE_PROCESS_NOT_REATTACHABLE",
          },
        },
      );
    }
    const entry = this.entries.get(processId);
    if (!entry) {
      throw new UniversalBrokerError(
        "PROCESS_NOT_FOUND",
        `Unknown process: ${processId}`,
        { evidence: { processId } },
      );
    }
    this.assertProcessOwner(entry.principalKeyFingerprint, owner, processId);
    return entry;
  }

  private scheduleCleanup(entry: ProcessEntry): void {
    if (entry.cleanupTimer) clearTimeout(entry.cleanupTimer);
    const delay = Math.max(
      0,
      (entry.endedAtMs ?? this.now()) + this.completedProcessTtlMs - this.now(),
    );
    entry.cleanupTimer = setTimeout(() => {
      void this.forgetEntry(entry).catch(() => undefined);
    }, delay);
    entry.cleanupTimer.unref();
  }

  private async forgetEntry(entry: ProcessEntry): Promise<void> {
    if (entry.cleanupTimer) clearTimeout(entry.cleanupTimer);
    this.entries.delete(entry.processId);
    await entry.output.close();
    await Promise.all([
      rm(entry.output.path, { force: true }),
      rm(entry.output.channelPath("stdout"), { force: true }),
      rm(entry.output.channelPath("stderr"), { force: true }),
      rm(entry.output.channelPath("pty"), { force: true }),
      this.stateStore.delete(entry.processId),
    ]);
  }

  private ensureRecovered(): Promise<void> {
    this.recoveryPromise ??= this.recoverPersistedProcesses();
    return this.recoveryPromise;
  }

  private async recoverPersistedProcesses(): Promise<void> {
    const records = await this.stateStore.loadAll();
    if (records.length > this.maximumProcessRecords) {
      throw new UniversalBrokerError(
        "RESOURCE_QUOTA_EXCEEDED",
        "Persisted process records exceed the configured process quota.",
        { evidence: { records: records.length, maximum: this.maximumProcessRecords } },
      );
    }
    for (const record of records) {
      if (!record.durable) {
        this.nonDurableAfterRestart.set(record.processId, record.principalKeyFingerprint);
        continue;
      }
      const output = new ProcessOutputSpool({
        path: record.outputPath,
        maximumInlineBytes: this.maximumInlineOutputBytes,
        maximumFileBytes: this.maximumProcessOutputBytes,
      });
      await output.open({ existing: true });
      let resolveExit!: () => void;
      const exitPromise = new Promise<void>((resolvePromise) => {
        resolveExit = resolvePromise;
      });
      const entry: ProcessEntry = {
        processId: record.processId,
        principalKeyFingerprint: record.principalKeyFingerprint,
        targetId: record.targetId,
        targetGeneration: record.targetGeneration,
        transport: record.transport,
        cwd: record.cwd,
        tty: record.tty,
        launchRisk: record.launchRisk,
        state: persistentState(record.state),
        startedAtMs: record.startedAtMs,
        endedAtMs: record.endedAtMs,
        exitCode: record.exitCode,
        signal: record.signal,
        errorCode: record.errorCode,
        errorMessage: record.errorMessage,
        durable: true,
        durableIdentity: record.durableIdentity,
        dispatched: true,
        output,
        exitPromise,
        resolveExit,
      };
      this.entries.set(entry.processId, entry);
      if (!isRunning(entry)) {
        resolveExit();
        this.scheduleCleanup(entry);
        continue;
      }
      if (!record.durableIdentity) {
        entry.state = "ORPHANED";
        entry.endedAtMs = this.now();
        entry.errorCode = "PROCESS_NOT_FOUND";
        entry.errorMessage = "Durable process record has no external manager identity.";
        resolveExit();
        this.scheduleCleanup(entry);
        await this.persistEntry(entry);
        continue;
      }
      if (!this.options.durableAdapter) {
        entry.state = "UNKNOWN";
        entry.endedAtMs = this.now();
        entry.errorCode = "PROCESS_NOT_FOUND";
        entry.errorMessage = "The durable process adapter is unavailable after restart; execution was not replayed.";
        resolveExit();
        this.scheduleCleanup(entry);
        await this.persistEntry(entry);
        continue;
      }
      let reattached;
      try {
        reattached = await this.options.durableAdapter.reattach(
          record.durableIdentity,
          this.durableEvents(entry),
        );
      } catch (error) {
        entry.state = "UNKNOWN";
        entry.endedAtMs = this.now();
        entry.errorCode = "TRANSPORT_INTERRUPTED";
        entry.errorMessage = `Durable process reattach is unknown; execution was not replayed: ${boundedError(error)}`;
        resolveExit();
        this.scheduleCleanup(entry);
        await this.persistEntry(entry);
        continue;
      }
      if (!sameDurableProcessIdentity(record.durableIdentity, reattached.identity)) {
        entry.state = "ORPHANED";
        entry.endedAtMs = this.now();
        entry.errorCode = "PROCESS_NOT_FOUND";
        entry.errorMessage = "External manager handle no longer identifies the original PID/start token.";
        resolveExit();
        this.scheduleCleanup(entry);
      } else if (reattached.state === "RUNNING") {
        entry.handle = adaptDurableHandle(reattached.handle);
        entry.state = "RUNNING";
      } else if (reattached.state === "EXITED") {
        entry.state = reattached.signal ? "SIGNALED" : "EXITED";
        entry.exitCode = reattached.exitCode;
        entry.signal = reattached.signal;
        entry.endedAtMs = this.now();
        resolveExit();
        this.scheduleCleanup(entry);
      } else {
        entry.state = reattached.state;
        entry.endedAtMs = this.now();
        entry.errorCode = reattached.state === "ORPHANED" ? "PROCESS_NOT_FOUND" : "TRANSPORT_INTERRUPTED";
        entry.errorMessage = reattached.state === "ORPHANED"
          ? "External process manager handle exists but the original process does not."
          : reattached.message ?? "Durable process state is unknown; execution was not replayed.";
        resolveExit();
        this.scheduleCleanup(entry);
      }
      await this.persistEntry(entry);
    }
  }

  private persistEntry(entry: ProcessEntry): Promise<void> {
    const record: Omit<PersistentProcessRecord, "schemaVersion" | "checksum"> = {
      processId: entry.processId,
      principalKeyFingerprint: entry.principalKeyFingerprint,
      targetId: entry.targetId,
      targetGeneration: entry.targetGeneration,
      transport: entry.transport,
      cwd: entry.cwd,
      tty: entry.tty,
      launchRisk: entry.launchRisk,
      state: entry.state,
      startedAtMs: entry.startedAtMs,
      endedAtMs: entry.endedAtMs,
      exitCode: entry.exitCode,
      signal: entry.signal,
      errorCode: entry.errorCode,
      errorMessage: entry.errorMessage,
      outputPath: entry.output.path,
      durable: entry.durable,
      durableIdentity: entry.durableIdentity,
    };
    let tracked: Promise<void>;
    tracked = this.stateStore.save(record).finally(() => {
      this.pendingStateWrites.delete(tracked);
    });
    this.pendingStateWrites.add(tracked);
    return tracked;
  }

  private async drainPendingStateWrites(): Promise<void> {
    while (this.pendingStateWrites.size > 0) {
      await Promise.allSettled([...this.pendingStateWrites]);
    }
  }

  private assertProcessOwner(
    expected: string,
    owner: CapabilityCallContext,
    processId: string,
  ): void {
    if (expected === owner.principalKeyFingerprint) return;
    throw new UniversalBrokerError(
      "AUTHORITY_PRINCIPAL_MISMATCH",
      `Process ${processId} belongs to a different authenticated principal.`,
      { evidence: { processId, providerDispatchCount: 0 } },
    );
  }

  private owner(callContext?: CapabilityCallContext): CapabilityCallContext {
    return requireCapabilityCallContext(callContext, this.ownerProvider);
  }

  private assertOpen(): void {
    if (this.closed) {
      throw new UniversalBrokerError(
        "TRANSPORT_UNAVAILABLE",
        "Universal execution plane is closed.",
      );
    }
  }
}

export function prepareExecExecutionBinding(
  input: ExecuteCommandInput,
  target: TargetDefinition,
  targetGeneration: string,
  effectiveEnvProfileGeneration?: string,
  effectiveCwd = input.cwd
    ?? target.defaultCwd
    ?? (target.transport === "local" ? homedir() : "~"),
): PreparedExecExecutionBinding {
  const effectiveEnvProfile = input.envProfile ?? target.envProfile;
  return {
    targetId: target.id,
    targetGeneration,
    targetTransport: target.transport,
    targetPlatform: target.platform,
    shellDialect: target.shell,
    effectiveEnvProfile,
    effectiveEnvProfileGeneration,
    effectiveCwd,
    mode: input.mode ?? "auto",
    tty: input.tty === true,
    classifierGeneration: EXEC_RISK_CLASSIFIER_GENERATION,
    launchRisk: commandRisk(input.command, {
      targetId: target.id,
      targetTransport: target.transport,
      targetPlatform: target.platform,
      shellDialect: target.shell,
      mode: input.mode ?? "auto",
      tty: input.tty === true,
      envProfile: effectiveEnvProfile,
    }),
  };
}

function assertPreparedExecExecutionBinding(
  expected: PreparedExecExecutionBinding | undefined,
  observed: PreparedExecExecutionBinding,
): void {
  if (!expected) return;
  const dimensions = [
    "targetId",
    "targetGeneration",
    "targetTransport",
    "targetPlatform",
    "shellDialect",
    "effectiveEnvProfile",
    "effectiveEnvProfileGeneration",
    "effectiveCwd",
    "mode",
    "tty",
    "classifierGeneration",
    "launchRisk",
  ] as const satisfies readonly (keyof PreparedExecExecutionBinding)[];
  const mismatches = dimensions.filter((dimension) => expected[dimension] !== observed[dimension]);
  if (mismatches.length === 0) return;
  throw new UniversalBrokerError(
    "AUTHORITY_STALE",
    "Execution target or classifier binding changed after authority preparation; process dispatch was not attempted.",
    {
      evidence: {
        mismatchedDimensions: mismatches,
        expectedTargetId: expected.targetId,
        observedTargetId: observed.targetId,
        expectedTargetGeneration: expected.targetGeneration,
        observedTargetGeneration: observed.targetGeneration,
        expectedClassifierGeneration: expected.classifierGeneration,
        observedClassifierGeneration: observed.classifierGeneration,
      },
    },
  );
}

class RemoteMarkerParser {
  readonly dispatchedMarker: string;
  readonly completedPrefix: string;
  readonly cwdRejectedMarker: string;
  readonly elevationBlockedMarker: string;
  private readonly remainders = new Map<ProcessOutputChannel, string>();
  dispatched = false;
  completed = false;
  cwdRejected = false;
  elevationBlocked = false;
  exitCode?: number;

  constructor(nonce: string) {
    this.dispatchedMarker = `__DEVSPACE_DISPATCHED_${nonce}__`;
    this.completedPrefix = `__DEVSPACE_COMPLETED_${nonce}__:`;
    this.cwdRejectedMarker = `__DEVSPACE_CWD_REJECTED_${nonce}__`;
    this.elevationBlockedMarker = `__DEVSPACE_ELEVATION_BLOCKED_${nonce}__`;
  }

  consume(value: string, final: boolean, channel: ProcessOutputChannel): string {
    const combined = (this.remainders.get(channel) ?? "") + value;
    const segments = combined.match(/[^\n]*\n|[^\n]+$/gu) ?? [];
    if (!final && segments.length > 0 && !segments.at(-1)!.endsWith("\n")) {
      this.remainders.set(channel, segments.pop()!);
    } else {
      this.remainders.delete(channel);
    }
    return segments.map((segment) => this.sanitizeLine(segment)).join("");
  }

  private sanitizeLine(segment: string): string {
    const line = segment.endsWith("\r\n")
      ? segment.slice(0, -2)
      : segment.endsWith("\n")
        ? segment.slice(0, -1)
        : segment;
    if (line === this.dispatchedMarker) {
      this.dispatched = true;
      return "";
    }
    if (line === this.cwdRejectedMarker) {
      this.cwdRejected = true;
      return "";
    }
    if (line === this.elevationBlockedMarker) {
      this.elevationBlocked = true;
      return "";
    }
    if (line.startsWith(this.completedPrefix)) {
      const exitCode = line.slice(this.completedPrefix.length);
      if (/^-?\d+$/u.test(exitCode)) {
        this.completed = true;
        this.exitCode = Number(exitCode);
        return "";
      }
    }
    return segment;
  }
}

async function assertCachedExecutionCapability(
  targets: TargetRegistry,
  target: TargetDefinition,
  requiresPty: boolean,
): Promise<void> {
  const observation = await targets.cachedObservation(target.id);
  if (!observation) return;
  if (!observation.capabilities.exec) {
    throw new UniversalBrokerError(
      observation.status === "OFFLINE" ? "TARGET_OFFLINE" : "CAPABILITY_UNAVAILABLE",
      `A fresh target probe reports ordinary execution unavailable on ${target.id}.`,
      {
        evidence: {
          targetId: target.id,
          status: observation.status,
          capability: "exec",
          expiresAt: observation.expiresAt,
        },
      },
    );
  }
  if (requiresPty && !observation.capabilities.pty) {
    throw new UniversalBrokerError(
      "CAPABILITY_UNAVAILABLE",
      `A fresh target probe reports PTY unavailable on ${target.id}. Refresh the target probe after external SSH configuration changes.`,
      {
        evidence: {
          targetId: target.id,
          status: observation.status,
          capability: "pty",
          expiresAt: observation.expiresAt,
        },
      },
    );
  }
}

async function localCommandSpec(
  resolved: ResolvedExecution,
  command: string,
  internalPolicy?: InternalExecutionPolicy,
): Promise<CommandSpec> {
  const effectiveCommand = commandWithSourceFile(command, resolved.sourceFile);
  const shell = internalExecutionSpec(internalPolicy, effectiveCommand, { verifyLocalScript: true })
    ?? wrapLocalUserOnlyExecution(
      resolved.target.platform,
      localShellCommand(resolved.target, effectiveCommand),
      internalPolicy,
    );
  const environment = {
    ...executionEnvironment(),
    ...resolved.environment,
  };
  return {
    executable: shell.executable,
    args: shell.args,
    cwd: resolved.cwd,
    env: environment,
  };
}

async function remoteCommandSpec(input: {
  resolved: ResolvedExecution;
  command: string;
  processId: string;
  tty: boolean;
  internalPolicy?: InternalExecutionPolicy;
  sshControlDir: string;
  sshExecutable: string;
}): Promise<CommandSpec> {
  const { target, cwd } = input.resolved;
  if (!target.sshHost) {
    throw new UniversalBrokerError(
      "TARGET_OFFLINE",
      `SSH target has no sshHost: ${target.id}`,
    );
  }
  const nonce = randomUUID().replaceAll("-", "");
  const markers = new RemoteMarkerParser(nonce);
  const controlPath = await prepareSshControlPath(input.sshControlDir);
  const remoteCommand = target.platform === "windows"
    ? windowsRemoteCommand(target, cwd, input.command, markers)
    : posixRemoteCommand(
        target,
        cwd,
        commandWithSourceFile(input.command, input.resolved.sourceFile),
        markers,
        input.internalPolicy,
      );
  return {
    executable: input.sshExecutable,
    args: [
      input.tty ? "-tt" : "-T",
      "-o", "BatchMode=yes",
      "-o", "ConnectionAttempts=1",
      "-o", "ConnectTimeout=10",
      "-o", "ServerAliveInterval=15",
      "-o", "ServerAliveCountMax=2",
      "-o", "ControlMaster=auto",
      "-o", "ControlPersist=60",
      "-o", `ControlPath=${controlPath}`,
      "-o", "LogLevel=ERROR",
      target.sshHost,
      remoteCommand,
    ],
    cwd: homedir(),
    env: executionEnvironment(),
    remoteMarkers: markers,
  };
}

function posixRemoteCommand(
  target: TargetDefinition,
  cwd: string,
  command: string,
  markers: RemoteMarkerParser,
  internalPolicy?: InternalExecutionPolicy,
): string {
  const shell = posixShell(target.shell);
  const runner = posixRemoteUserOnlyRunner(
    target.platform,
    shell,
    command,
    internalPolicy,
  );
  const script = [
    `requested=${shellQuote(cwd)}`,
    "case \"$requested\" in '~') requested=$HOME ;; '~/'*) requested=$HOME/${requested#\~/} ;; esac",
    `if ! cd -- \"$requested\"; then printf '%s\\n' ${shellQuote(markers.cwdRejectedMarker)} >&2; exit 46; fi`,
    `printf '%s\\n' ${shellQuote(markers.dispatchedMarker)} >&2`,
    `${runner}`,
    "rc=$?",
    `printf '%s%s\\n' ${shellQuote(markers.completedPrefix)} \"$rc\" >&2`,
    "exit 0",
  ].join("; ");
  return `/bin/sh -lc ${shellQuote(script)}`;
}

function windowsRemoteCommand(
  target: TargetDefinition,
  cwd: string,
  command: string,
  markers: RemoteMarkerParser,
): string {
  if (target.shell !== "powershell" && target.shell !== "auto") {
    throw new UniversalBrokerError(
      "PRECONDITION_FAILED",
      `Shell ${target.shell} is incompatible with a Windows SSH target.`,
    );
  }
  const escapedCwd = cwd.replaceAll("'", "''");
  const commandBase64 = Buffer.from(command, "utf16le").toString("base64");
  const source = [
    "$ErrorActionPreference='Stop'",
    ...windowsNonElevatedPrelude(markers.elevationBlockedMarker),
    `$cwd='${escapedCwd}'`,
    `if(-not (Test-Path -LiteralPath $cwd -PathType Container)){[Console]::Error.WriteLine('${markers.cwdRejectedMarker}');exit 44}`,
    `Set-Location -LiteralPath $cwd`,
    `[Console]::Out.WriteLine('${markers.dispatchedMarker}')`,
    `$command=[Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('${commandBase64}'))`,
    "& powershell.exe -NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -Command $command",
    "$code=if($null -eq $LASTEXITCODE){0}else{[int]$LASTEXITCODE}",
    `[Console]::Out.WriteLine('${markers.completedPrefix}'+$code)`,
    "exit $code",
  ].join("; ");
  const encoded = Buffer.from(source, "utf16le").toString("base64");
  return `powershell.exe -NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -EncodedCommand ${encoded}`;
}

function localShellCommand(target: TargetDefinition, command: string) {
  if (target.platform === "windows" || process.platform === "win32") {
    if (target.shell === "powershell") {
      return {
        executable: "powershell.exe",
        args: ["-NoProfile", "-NonInteractive", "-Command", command],
      };
    }
    return resolveShellCommand(command, "win32");
  }
  switch (target.shell) {
    case "zsh":
      return { executable: "/bin/zsh", args: ["-lc", command] };
    case "bash":
      return { executable: "/bin/bash", args: ["-lc", command] };
    case "sh":
      return { executable: "/bin/sh", args: ["-c", command] };
    case "auto":
      return resolveShellCommand(command);
    case "powershell":
    case "cmd":
      throw new UniversalBrokerError(
        "PRECONDITION_FAILED",
        `Shell ${target.shell} is incompatible with local platform ${process.platform}.`,
      );
  }
}

function posixShell(shell: TargetDefinition["shell"]): string {
  switch (shell) {
    case "zsh":
      return "/bin/zsh";
    case "bash":
      return "/bin/bash";
    case "sh":
    case "auto":
      return "/bin/sh";
    case "powershell":
    case "cmd":
      throw new UniversalBrokerError(
        "PRECONDITION_FAILED",
        `Shell ${shell} is incompatible with a POSIX SSH target.`,
      );
  }
}

async function resolveLocalCwd(input: string): Promise<string> {
  const expanded = expandHomePath(input);
  if (!isAbsolute(expanded)) {
    throw new UniversalBrokerError(
      "PRECONDITION_FAILED",
      "Local exec cwd must be absolute or use a leading tilde.",
      { evidence: { cwd: input } },
    );
  }
  try {
    const metadata = await stat(expanded);
    if (!metadata.isDirectory()) {
      throw new UniversalBrokerError(
        "PATH_TYPE_MISMATCH",
        `Execution cwd is not a directory: ${input}`,
      );
    }
    return resolve(await realpath(expanded));
  } catch (error) {
    if (error instanceof UniversalBrokerError) throw error;
    if (isNodeError(error, "ENOENT")) {
      throw new UniversalBrokerError(
        "PATH_NOT_FOUND",
        `Execution cwd does not exist: ${input}`,
        { evidence: { cwd: input } },
      );
    }
    throw new UniversalBrokerError(
      "PERMISSION_DENIED",
      `Execution cwd is inaccessible: ${input}`,
      { evidence: { cwd: input, error: boundedError(error) } },
    );
  }
}

function executionEnvironment(): NodeJS.ProcessEnv {
  return {
    ...Object.fromEntries(
      Object.entries(process.env).filter(([name, value]) =>
        value !== undefined && !isSensitiveEnvironmentName(name)
      ),
    ),
    NO_COLOR: "1",
    PAGER: "cat",
    GIT_PAGER: "cat",
    GH_PAGER: "cat",
    LANG: process.env.LANG ?? "C.UTF-8",
    LC_ALL: process.env.LC_ALL ?? "C.UTF-8",
  };
}

function isSensitiveEnvironmentName(name: string): boolean {
  return /(?:^|_)(?:TOKEN|SECRET|PASSWORD|PASSWD|PRIVATE_KEY|API_KEY|ACCESS_KEY|REFRESH_TOKEN|CLIENT_SECRET|AUTHORIZATION|COOKIE)(?:$|_)/i.test(name)
    || name === "DEVSPACE_OAUTH_OWNER_TOKEN";
}

function normalizePtyEnvironment(environment: NodeJS.ProcessEnv): Record<string, string> {
  return Object.fromEntries(
    Object.entries(environment).filter((entry): entry is [string, string] => entry[1] !== undefined),
  );
}

function executionYield(mode: ExecutionMode, requested: number | undefined): number {
  if (mode === "background") return 0;
  const fallback = mode === "foreground"
    ? DEFAULT_FOREGROUND_YIELD_MS
    : DEFAULT_AUTO_YIELD_MS;
  if (requested === undefined) return fallback;
  if (!Number.isInteger(requested) || requested < 0 || requested > 30_000) {
    throw new UniversalBrokerError(
      "PRECONDITION_FAILED",
      `Invalid exec yieldMs: ${requested}`,
    );
  }
  return requested;
}

function boundedWait(value: number): number {
  if (!Number.isInteger(value) || value < 0 || value > MAX_WAIT_MS) {
    throw new UniversalBrokerError(
      "PRECONDITION_FAILED",
      `Invalid process waitMs: ${value}`,
    );
  }
  return value;
}

function outputLimit(value: number | undefined): number {
  if (value === undefined) return DEFAULT_PROCESS_OUTPUT_CHARACTERS;
  if (!Number.isInteger(value) || value < 1 || value > MAX_PROCESS_OUTPUT_CHARACTERS) {
    throw new UniversalBrokerError(
      "PRECONDITION_FAILED",
      `Invalid maxOutputChars: ${value}`,
    );
  }
  return value;
}

function terminalDimension(value: number | undefined, name: string): number {
  if (!Number.isInteger(value) || value! < 1 || value! > 1_000) {
    throw new UniversalBrokerError(
      "PRECONDITION_FAILED",
      `${name} must be an integer between 1 and 1000.`,
    );
  }
  return value!;
}

function processSignal(value: string | undefined): NodeJS.Signals {
  const signal = (value ?? "SIGTERM") as NodeJS.Signals;
  const allowed = new Set<NodeJS.Signals>([
    "SIGHUP",
    "SIGINT",
    "SIGQUIT",
    "SIGTERM",
    "SIGKILL",
  ]);
  if (!allowed.has(signal)) {
    throw new UniversalBrokerError(
      "PRECONDITION_FAILED",
      `Unsupported process signal: ${value}`,
    );
  }
  return signal;
}

function validateCommand(command: string): void {
  if (!command.trim()) {
    throw new UniversalBrokerError("PRECONDITION_FAILED", "exec command must not be empty.");
  }
  if (command.includes("\0")) {
    throw new UniversalBrokerError("PRECONDITION_FAILED", "exec command must not contain NUL.");
  }
  if (command.length > MAX_COMMAND_CHARACTERS) {
    throw new UniversalBrokerError(
      "RESOURCE_QUOTA_EXCEEDED",
      `exec command uses ${command.length} characters; limit is ${MAX_COMMAND_CHARACTERS}.`,
    );
  }
}

function requireProcessId(value: string | undefined, operation: string): string {
  if (!value) {
    throw new UniversalBrokerError(
      "PRECONDITION_FAILED",
      `process.${operation} requires processId.`,
    );
  }
  return value;
}

function parseCursor(cursor: string | undefined): number {
  if (cursor === undefined) return 0;
  const parsed = Number(cursor);
  if (!Number.isInteger(parsed) || parsed < 0) {
    throw new UniversalBrokerError("PRECONDITION_FAILED", `Invalid process cursor: ${cursor}`);
  }
  return parsed;
}

function isRunning(entry: ProcessEntry): boolean {
  return entry.state === "STARTING" || entry.state === "RUNNING";
}

async function waitForExit(entry: ProcessEntry, waitMs: number): Promise<void> {
  if (!isRunning(entry) || waitMs <= 0) return;
  await Promise.race([
    entry.exitPromise,
    new Promise<void>((resolvePromise) => {
      const timer = setTimeout(resolvePromise, waitMs);
      timer.unref();
    }),
  ]);
}

function compactProcessEvidence(snapshot: UniversalProcessSnapshot): Record<string, unknown> {
  return {
    processId: snapshot.processId,
    targetId: snapshot.targetId,
    transport: snapshot.transport,
    cwd: snapshot.cwd,
    state: snapshot.state,
    resourceUri: snapshot.resourceUri,
    errorCode: snapshot.errorCode,
  };
}

function validateExecutionSnapshot(
  snapshot: UniversalProcessSnapshot,
): UniversalProcessSnapshot {
  if (snapshot.state === "FAILED") {
    throw new UniversalBrokerError(
      executionFailureCode(snapshot.errorCode),
      snapshot.errorMessage ?? "Command could not be dispatched or completed.",
      {
        retryable: snapshot.errorCode === "TRANSPORT_UNAVAILABLE",
        evidence: compactProcessEvidence(snapshot),
      },
    );
  }
  if (snapshot.state === "UNKNOWN") {
    throw new UniversalBrokerError(
      "EXECUTION_STATE_UNKNOWN",
      snapshot.errorMessage ?? "Command dispatch state is unknown and was not retried.",
      { evidence: compactProcessEvidence(snapshot) },
    );
  }
  return snapshot;
}

function executionFailureCode(
  value: string | undefined,
): "TRANSPORT_UNAVAILABLE" | "PATH_NOT_FOUND" | "PERMISSION_DENIED" {
  switch (value) {
    case "PATH_NOT_FOUND":
    case "PERMISSION_DENIED":
      return value;
    default:
      return "TRANSPORT_UNAVAILABLE";
  }
}

function processOutputResourceUri(processId: string, offset: number, limit: number): string {
  return `devspace://process/${encodeURIComponent(processId)}/output/${offset}/${limit}`;
}

function shellQuote(value: string): string {
  return `'${value.replaceAll("'", `'"'"'`)}'`;
}

function commandWithSourceFile(command: string, sourceFile: string | undefined): string {
  if (!sourceFile) return command;
  return `set -a; . ${shellQuote(sourceFile)}; set +a; ${command}`;
}

function boundedError(error: unknown): string {
  const message = error instanceof Error ? error.message : String(error);
  const normalized = message.replace(/\s+/g, " ").trim();
  return normalized.length <= 300 ? normalized : `${normalized.slice(0, 297)}...`;
}

function isNodeError(error: unknown, code: string): boolean {
  return error instanceof Error && "code" in error && (error as NodeJS.ErrnoException).code === code;
}

function boundedOption(
  value: number | undefined,
  fallback: number,
  minimum: number,
  maximum: number,
  field: string,
): number {
  const observed = value ?? fallback;
  if (!Number.isSafeInteger(observed) || observed < minimum || observed > maximum) {
    throw new UniversalBrokerError(
      "PRECONDITION_FAILED",
      `${field} must be an integer from ${minimum} through ${maximum}.`,
    );
  }
  return observed;
}

function writeWritable(
  writable: NodeJS.WritableStream,
  data: string,
): Promise<void> {
  if (writable.write(data)) return Promise.resolve();
  return new Promise<void>((resolvePromise, reject) => {
    const cleanup = () => {
      writable.removeListener("drain", onDrain);
      writable.removeListener("error", onError);
    };
    const onDrain = () => {
      cleanup();
      resolvePromise();
    };
    const onError = (error: Error) => {
      cleanup();
      reject(error);
    };
    writable.once("drain", onDrain);
    writable.once("error", onError);
  });
}

function assertDurableIdentity(identity: DurableProcessIdentity): void {
  if (
    !identity.managerHandle?.trim()
    || !Number.isSafeInteger(identity.pid)
    || identity.pid < 1
    || !identity.startToken?.trim()
  ) {
    throw new UniversalBrokerError(
      "TRANSPORT_INTERRUPTED",
      "Durable process adapter returned an invalid manager handle, PID, or start token.",
    );
  }
}

function adaptDurableHandle(handle: DurableProcessHandle): ProcessHandle {
  return {
    pid: handle.identity.pid,
    write: (data) => Promise.resolve(handle.write(data)).then(() => undefined),
    ...(handle.resize ? {
      resize: (columns: number, rows: number) => Promise.resolve(handle.resize!(columns, rows)).then(() => undefined),
    } : {}),
    kill: (signal) => Promise.resolve(handle.kill(signal)).then(() => undefined),
    ...(handle.pauseOutput ? { pauseOutput: () => handle.pauseOutput!() } : {}),
    ...(handle.resumeOutput ? { resumeOutput: () => handle.resumeOutput!() } : {}),
    ...(handle.close ? { close: () => Promise.resolve(handle.close!()).then(() => undefined) } : {}),
  };
}

function persistentState(value: string): UniversalProcessState {
  const states = new Set<UniversalProcessState>([
    "STARTING",
    "RUNNING",
    "EXITED",
    "SIGNALED",
    "FAILED",
    "ORPHANED",
    "UNKNOWN",
  ]);
  if (states.has(value as UniversalProcessState)) return value as UniversalProcessState;
  throw new UniversalBrokerError(
    "STATE_CORRUPTED",
    `Persisted process state is invalid: ${value}`,
  );
}
