import { randomUUID } from "node:crypto";
import {
  spawn,
  type ChildProcessWithoutNullStreams,
} from "node:child_process";
import {
  createWriteStream,
  type WriteStream,
} from "node:fs";
import {
  mkdir,
  open,
  realpath,
  rm,
  stat,
} from "node:fs/promises";
import { homedir } from "node:os";
import {
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
  type UniversalEnvProfileRegistry,
} from "./env-profiles.js";
import { prepareSshControlPath } from "./ssh-control.js";
import { assertNoElevationCommand } from "./authority-policy.js";
import {
  assertInternalExecutionCommand,
  internalExecutionSpec,
  posixRemoteUserOnlyRunner,
  type InternalExecutionPolicy,
  windowsNonElevatedPrelude,
  wrapLocalUserOnlyExecution,
} from "./no-elevation.js";
import {
  type TargetDefinition,
  type TargetRegistry,
} from "./targets.js";

const DEFAULT_AUTO_YIELD_MS = 1_500;
const DEFAULT_FOREGROUND_YIELD_MS = 30_000;
const DEFAULT_PROCESS_OUTPUT_CHARACTERS = 12_000;
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
  authorityId?: string;
  /** Internal helpers may select a constrained policy; MCP callers cannot set this field. */
  internalPolicy?: InternalExecutionPolicy;
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
  resourceUri: string;
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
  maxRunningProcesses: number;
  maxRunningProcessesPerTarget: number;
  processBufferCharacters: number;
  processOutputMaxBytes: number;
  completedProcessTtlMs: number;
  envProfiles?: UniversalEnvProfileRegistry;
  sshExecutable?: string;
  now?: () => number;
  spawnProcess?: typeof spawn;
}

interface ProcessHandle {
  pid?: number;
  write(data: string): void;
  resize?(columns: number, rows: number): void;
  kill(signal: NodeJS.Signals): void;
}

interface ProcessEntry {
  processId: string;
  targetId: string;
  transport: "local" | "ssh";
  cwd: string;
  tty: boolean;
  state: UniversalProcessState;
  startedAtMs: number;
  endedAtMs?: number;
  exitCode?: number;
  signal?: string;
  errorCode?: string;
  errorMessage?: string;
  requestedSignal?: NodeJS.Signals;
  handle?: ProcessHandle;
  output: ProcessOutput;
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
  cwd: string;
  environment: Record<string, string>;
  sourceFile?: string;
}

export class UniversalExecutionPlane {
  private readonly entries = new Map<string, ProcessEntry>();
  private readonly now: () => number;
  private readonly spawnProcess: typeof spawn;
  private closed = false;

  constructor(private readonly options: ExecutionPlaneOptions) {
    this.now = options.now ?? Date.now;
    this.spawnProcess = options.spawnProcess ?? spawn;
  }

  async execute(input: ExecuteCommandInput): Promise<UniversalProcessSnapshot> {
    this.assertOpen();
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
    const resolved = await this.resolveExecution(input);
    await assertCachedExecutionCapability(
      this.options.targets,
      resolved.target,
      input.tty === true,
    );
    this.assertQuota(resolved.target.id);
    await Promise.all([
      mkdir(this.options.outputDir, { recursive: true, mode: 0o700 }),
      mkdir(this.options.sshControlDir, { recursive: true, mode: 0o700 }),
    ]);

    const processId = `proc_${randomUUID()}`;
    const output = new ProcessOutput({
      path: join(this.options.outputDir, `${processId}.log`),
      maximumBufferedCharacters: this.options.processBufferCharacters,
      maximumFileBytes: this.options.processOutputMaxBytes,
    });
    await output.open();
    let resolveExit!: () => void;
    const exitPromise = new Promise<void>((resolvePromise) => {
      resolveExit = resolvePromise;
    });
    const entry: ProcessEntry = {
      processId,
      targetId: resolved.target.id,
      transport: resolved.target.transport,
      cwd: resolved.cwd,
      tty: input.tty === true,
      state: "STARTING",
      startedAtMs: this.now(),
      output,
      exitPromise,
      resolveExit,
    };
    this.entries.set(processId, entry);

    try {
      const spec = await this.commandSpec(resolved, input, processId);
      entry.remoteMarkers = spec.remoteMarkers;
      if (entry.tty) await this.startPty(entry, spec);
      else this.startPipe(entry, spec);
      if (entry.state === "STARTING") entry.state = "RUNNING";
    } catch (error) {
      this.finishSpawnFailure(entry, error);
    }

    const mode = input.mode ?? "auto";
    const yieldMs = executionYield(mode, input.yieldMs);
    if (yieldMs > 0) await waitForExit(entry, yieldMs);
    const snapshot = this.snapshot(entry, input.maxOutputChars);
    return validateExecutionSnapshot(snapshot);
  }

  async operate(input: ProcessOperationInput): Promise<Record<string, unknown>> {
    this.assertOpen();
    if (input.operation === "restart_broker" || input.operation === "restart_status") {
      throw new UniversalBrokerError(
        "PRECONDITION_FAILED",
        `${input.operation} must be handled by the broker self-management service.`,
      );
    }
    if (input.operation === "list") return this.list(input.cursor, input.limit);
    const processId = requireProcessId(input.processId, input.operation);
    const entry = this.requireEntry(processId);

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
        entry.handle?.write(input.chars ?? "");
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
        entry.handle.resize(columns, rows);
        return this.snapshot(entry, input.maxOutputChars);
      }
      case "signal": {
        if (!isRunning(entry)) return this.snapshot(entry, input.maxOutputChars);
        const signal = processSignal(input.signal);
        entry.requestedSignal = signal;
        entry.handle?.kill(signal);
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
        await this.forgetEntry(entry);
        return { processId, forgotten: true };
      }
    }
  }

  async readOutput(
    processId: string,
    offset: number,
    limit: number,
  ): Promise<{ text: string; nextOffset?: number; totalBytes: number; truncated: boolean }> {
    const entry = this.requireEntry(processId);
    if (entry.outputClose) await Promise.race([
      entry.outputClose,
      new Promise<void>((resolvePromise) => setTimeout(resolvePromise, 50)),
    ]);
    return entry.output.read(offset, limit);
  }

  async close(): Promise<void> {
    if (this.closed) return;
    this.closed = true;
    const running = [...this.entries.values()].filter(isRunning);
    for (const entry of running) {
      entry.requestedSignal = "SIGTERM";
      try {
        entry.handle?.kill("SIGTERM");
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
        entry.handle?.kill("SIGKILL");
      } catch {
        // Process may already have exited.
      }
    }
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

  private async resolveExecution(input: ExecuteCommandInput): Promise<ResolvedExecution> {
    const context = input.contextId
      ? await this.options.contexts.get(input.contextId)
      : undefined;
    const target = await this.options.targets.resolve(input.target ?? context?.targetId);
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
    const sourceFile = profile?.sourceFile
      ? target.transport === "local"
        ? resolveLocalProfileSourceFile(profile.sourceFile)
        : profile.sourceFile
      : undefined;
    return {
      target,
      cwd,
      environment: profile?.environment ?? {},
      ...(sourceFile ? { sourceFile } : {}),
    };
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

  private startPipe(entry: ProcessEntry, spec: CommandSpec): void {
    const detached = process.platform !== "win32";
    const child = this.spawnProcess(spec.executable, spec.args, {
      cwd: spec.cwd,
      env: spec.env,
      detached,
      windowsHide: true,
      stdio: ["pipe", "pipe", "pipe"],
    }) as ChildProcessWithoutNullStreams;
    entry.handle = {
      pid: child.pid,
      write: (data) => child.stdin.write(data),
      kill: (signal) => terminateProcessTree(child, signal, detached),
    };
    child.stdout.on("data", (data: Buffer) => this.appendOutput(entry, data.toString("utf8")));
    child.stderr.on("data", (data: Buffer) => this.appendOutput(entry, data.toString("utf8")));
    child.once("error", (error) => this.finishSpawnFailure(entry, error));
    child.once("close", (code, signal) => this.finish(entry, code, signal ?? undefined));
  }

  private async startPty(entry: ProcessEntry, spec: CommandSpec): Promise<void> {
    const nodePty = await import("node-pty");
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
    };
    pty.onData((data) => this.appendOutput(entry, data));
    pty.onExit(({ exitCode, signal }) => {
      this.finish(entry, exitCode, signal ? String(signal) : undefined);
    });
  }

  private appendOutput(entry: ProcessEntry, value: string): void {
    const visible = entry.remoteMarkers
      ? entry.remoteMarkers.consume(value, false)
      : value;
    if (visible) entry.output.append(visible);
  }

  private finish(entry: ProcessEntry, code: number | null, signal?: string): void {
    if (!isRunning(entry) && entry.state !== "STARTING") return;
    const finalOutput = entry.remoteMarkers?.consume("", true) ?? "";
    if (finalOutput) entry.output.append(finalOutput);
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
  }

  private finishSpawnFailure(entry: ProcessEntry, error: unknown): void {
    if (!isRunning(entry) && entry.state !== "STARTING") return;
    entry.endedAtMs = this.now();
    entry.state = "FAILED";
    entry.errorCode = entry.transport === "ssh"
      ? "TRANSPORT_UNAVAILABLE"
      : "TRANSPORT_UNAVAILABLE";
    entry.errorMessage = boundedError(error);
    entry.output.append(`${entry.errorMessage}\n`);
    entry.outputClose = entry.output.close();
    entry.resolveExit();
    this.scheduleCleanup(entry);
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
      resourceUri: processOutputResourceUri(entry.processId, 0, 1_048_576),
      ...(entry.exitCode !== undefined ? { exitCode: entry.exitCode } : {}),
      ...(entry.signal ? { signal: entry.signal } : {}),
      ...(entry.errorCode ? { errorCode: entry.errorCode } : {}),
      ...(entry.errorMessage ? { errorMessage: entry.errorMessage } : {}),
    };
  }

  private async list(cursor?: string, requestedLimit?: number): Promise<Record<string, unknown>> {
    const offset = parseCursor(cursor);
    const limit = Math.min(Math.max(requestedLimit ?? DEFAULT_LIST_LIMIT, 1), MAX_LIST_LIMIT);
    const entries = [...this.entries.values()].map((entry) => ({
      processId: entry.processId,
      targetId: entry.targetId,
      transport: entry.transport,
      cwd: entry.cwd,
      tty: entry.tty,
      state: entry.state,
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

  private assertQuota(targetId: string): void {
    const running = [...this.entries.values()].filter(isRunning);
    if (running.length >= this.options.maxRunningProcesses) {
      throw new UniversalBrokerError(
        "RESOURCE_QUOTA_EXCEEDED",
        `Global running-process limit reached: ${this.options.maxRunningProcesses}`,
        { evidence: { maximum: this.options.maxRunningProcesses, current: running.length } },
      );
    }
    const targetRunning = running.filter((entry) => entry.targetId === targetId).length;
    if (targetRunning >= this.options.maxRunningProcessesPerTarget) {
      throw new UniversalBrokerError(
        "RESOURCE_QUOTA_EXCEEDED",
        `Running-process limit reached for target ${targetId}: ${this.options.maxRunningProcessesPerTarget}`,
        {
          evidence: {
            targetId,
            maximum: this.options.maxRunningProcessesPerTarget,
            current: targetRunning,
          },
        },
      );
    }
  }

  private requireEntry(processId: string): ProcessEntry {
    const entry = this.entries.get(processId);
    if (!entry) {
      throw new UniversalBrokerError(
        "PROCESS_NOT_FOUND",
        `Unknown process: ${processId}`,
        { evidence: { processId } },
      );
    }
    return entry;
  }

  private scheduleCleanup(entry: ProcessEntry): void {
    if (entry.cleanupTimer) clearTimeout(entry.cleanupTimer);
    entry.cleanupTimer = setTimeout(() => {
      void this.forgetEntry(entry).catch(() => undefined);
    }, this.options.completedProcessTtlMs);
    entry.cleanupTimer.unref();
  }

  private async forgetEntry(entry: ProcessEntry): Promise<void> {
    if (entry.cleanupTimer) clearTimeout(entry.cleanupTimer);
    this.entries.delete(entry.processId);
    await entry.output.close();
    await rm(entry.output.path, { force: true });
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

class ProcessOutput {
  private pending = "";
  private droppedCharacters = 0;
  private writeStream?: WriteStream;
  private closePromise?: Promise<void>;
  private fileBytes = 0;
  fileTruncated = false;

  constructor(readonly options: {
    path: string;
    maximumBufferedCharacters: number;
    maximumFileBytes: number;
  }) {}

  get path(): string {
    return this.options.path;
  }

  get totalFileBytes(): number {
    return this.fileBytes;
  }

  async open(): Promise<void> {
    this.writeStream = createWriteStream(this.options.path, {
      flags: "wx",
      mode: 0o600,
    });
    await new Promise<void>((resolvePromise, reject) => {
      this.writeStream!.once("open", () => resolvePromise());
      this.writeStream!.once("error", reject);
    });
    this.writeStream.on("error", () => {
      this.fileTruncated = true;
    });
  }

  append(value: string): void {
    if (!value) return;
    this.appendFile(value);
    this.pending += value;
    if (this.pending.length <= this.options.maximumBufferedCharacters) return;
    const overflow = this.pending.length - this.options.maximumBufferedCharacters;
    this.pending = this.pending.slice(overflow);
    this.droppedCharacters += overflow;
  }

  drain(maximumCharacters: number): { output: string; truncated: boolean } {
    const marker = this.droppedCharacters > 0
      ? `... ${this.droppedCharacters} buffered character(s) omitted; full output is available as a resource ...\n`
      : "";
    const available = Math.max(0, maximumCharacters - marker.length);
    const body = this.pending.slice(0, available);
    this.pending = this.pending.slice(body.length);
    const truncated = this.droppedCharacters > 0 || this.pending.length > 0;
    this.droppedCharacters = 0;
    return { output: marker + body, truncated };
  }

  async read(offset: number, limit: number): Promise<{
    text: string;
    nextOffset?: number;
    totalBytes: number;
    truncated: boolean;
  }> {
    if (!Number.isInteger(offset) || offset < 0) {
      throw new UniversalBrokerError("PRECONDITION_FAILED", `Invalid output offset: ${offset}`);
    }
    if (!Number.isInteger(limit) || limit < 1 || limit > 1_048_576) {
      throw new UniversalBrokerError("PRECONDITION_FAILED", `Invalid output limit: ${limit}`);
    }
    const handle = await open(this.options.path, "r");
    try {
      const buffer = Buffer.alloc(limit);
      const { bytesRead } = await handle.read(buffer, 0, limit, offset);
      const totalBytes = this.fileBytes;
      const nextOffset = offset + bytesRead;
      return {
        text: buffer.subarray(0, bytesRead).toString("utf8"),
        ...(nextOffset < totalBytes ? { nextOffset } : {}),
        totalBytes,
        truncated: this.fileTruncated || nextOffset < totalBytes,
      };
    } finally {
      await handle.close();
    }
  }

  close(): Promise<void> {
    if (this.closePromise) return this.closePromise;
    const stream = this.writeStream;
    if (!stream || stream.closed || stream.destroyed) {
      this.closePromise = Promise.resolve();
      return this.closePromise;
    }
    this.closePromise = new Promise<void>((resolvePromise) => {
      stream.once("close", () => resolvePromise());
      stream.end();
    });
    return this.closePromise;
  }

  private appendFile(value: string): void {
    const stream = this.writeStream;
    if (!stream || this.fileTruncated) return;
    const data = Buffer.from(value);
    const remaining = this.options.maximumFileBytes - this.fileBytes;
    if (remaining <= 0) {
      this.fileTruncated = true;
      return;
    }
    const accepted = data.subarray(0, remaining);
    this.fileBytes += accepted.byteLength;
    stream.write(accepted);
    if (accepted.byteLength < data.byteLength) this.fileTruncated = true;
  }
}

class RemoteMarkerParser {
  readonly dispatchedMarker: string;
  readonly completedPrefix: string;
  readonly cwdRejectedMarker: string;
  readonly elevationBlockedMarker: string;
  private remainder = "";
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

  consume(value: string, final: boolean): string {
    const sanitized = this.sanitize(this.remainder + value, final);
    if (final) {
      this.remainder = "";
      return sanitized;
    }
    const retained = potentialMarkerSuffixLength(sanitized, [
      this.dispatchedMarker,
      this.cwdRejectedMarker,
      this.elevationBlockedMarker,
      this.completedPrefix,
    ]);
    this.remainder = retained > 0 ? sanitized.slice(-retained) : "";
    return retained > 0 ? sanitized.slice(0, -retained) : sanitized;
  }

  private sanitize(value: string, final: boolean): string {
    let result = value;
    if (result.includes(this.dispatchedMarker)) {
      this.dispatched = true;
      result = result.replace(new RegExp(`${escapeRegExp(this.dispatchedMarker)}\\r?\\n?`, "g"), "");
    }
    if (result.includes(this.cwdRejectedMarker)) {
      this.cwdRejected = true;
      result = result.replace(new RegExp(`${escapeRegExp(this.cwdRejectedMarker)}\\r?\\n?`, "g"), "");
    }
    if (result.includes(this.elevationBlockedMarker)) {
      this.elevationBlocked = true;
      result = result.replace(new RegExp(`${escapeRegExp(this.elevationBlockedMarker)}\\r?\\n?`, "g"), "");
    }
    const escapedPrefix = escapeRegExp(this.completedPrefix);
    const terminator = final ? "(?:\\r?\\n|$)" : "\\r?\\n";
    result = result.replace(new RegExp(`${escapedPrefix}(-?\\d+)${terminator}`, "g"), (_match, exitCode: string) => {
      this.completed = true;
      this.exitCode = Number(exitCode);
      return "";
    });
    return result;
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
  return `sh -lc ${shellQuote(script)}`;
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
      return "zsh";
    case "bash":
      return "bash";
    case "sh":
    case "auto":
      return "sh";
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

function escapeRegExp(value: string): string {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

function potentialMarkerSuffixLength(value: string, markers: string[]): number {
  let retained = 0;
  for (const marker of markers) {
    const maximum = Math.min(marker.length - 1, value.length);
    for (let length = maximum; length > retained; length -= 1) {
      if (value.endsWith(marker.slice(0, length))) {
        retained = length;
        break;
      }
    }
  }
  const completedPrefix = markers.at(-1);
  if (completedPrefix) {
    const index = value.lastIndexOf(completedPrefix);
    if (index >= 0) {
      const suffix = value.slice(index + completedPrefix.length);
      if (/^-?\d*$/.test(suffix)) retained = Math.max(retained, value.length - index);
    }
  }
  return retained;
}

function boundedError(error: unknown): string {
  const message = error instanceof Error ? error.message : String(error);
  const normalized = message.replace(/\s+/g, " ").trim();
  return normalized.length <= 300 ? normalized : `${normalized.slice(0, 297)}...`;
}

function isNodeError(error: unknown, code: string): boolean {
  return error instanceof Error && "code" in error && (error as NodeJS.ErrnoException).code === code;
}
