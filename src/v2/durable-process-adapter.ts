import type { ProcessOutputChannel } from "./process-output-spool.js";

export interface DurableProcessIdentity {
  managerHandle: string;
  pid: number;
  startToken: string;
}

export interface DurableProcessEvents {
  output(channel: ProcessOutputChannel, data: Uint8Array): void;
  exit(exitCode: number | null, signal?: string): void;
  error(error: unknown): void;
}

export interface DurableProcessHandle {
  readonly identity: DurableProcessIdentity;
  write(data: string): void | boolean | Promise<void>;
  resize?(columns: number, rows: number): void | Promise<void>;
  kill(signal: NodeJS.Signals): void | Promise<void>;
  pauseOutput?(): void;
  resumeOutput?(): void;
  close?(): void | Promise<void>;
}

export interface DurableProcessLaunchRequest {
  processId: string;
  targetId: string;
  executable: string;
  args: readonly string[];
  cwd: string;
  environment: NodeJS.ProcessEnv;
  tty: boolean;
}

export type DurableProcessReattachResult =
  | { state: "RUNNING"; identity: DurableProcessIdentity; handle: DurableProcessHandle }
  | { state: "EXITED"; identity: DurableProcessIdentity; exitCode: number; signal?: string }
  | { state: "ORPHANED"; identity?: DurableProcessIdentity }
  | { state: "UNKNOWN"; identity?: DurableProcessIdentity; message?: string };

/** A durable adapter is backed by an external process manager, not a PID alone. */
export interface DurableProcessAdapter {
  launch(
    request: DurableProcessLaunchRequest,
    events: DurableProcessEvents,
  ): Promise<DurableProcessHandle>;
  reattach(
    identity: DurableProcessIdentity,
    events: DurableProcessEvents,
  ): Promise<DurableProcessReattachResult>;
}

export function sameDurableProcessIdentity(
  expected: DurableProcessIdentity,
  actual: DurableProcessIdentity | undefined,
): boolean {
  return Boolean(actual)
    && expected.managerHandle === actual!.managerHandle
    && expected.pid === actual!.pid
    && expected.startToken === actual!.startToken;
}
