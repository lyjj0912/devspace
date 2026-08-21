import { StringDecoder } from "node:string_decoder";
import { createWriteStream, type WriteStream } from "node:fs";
import { open, stat } from "node:fs/promises";
import { UniversalBrokerError } from "./errors.js";

export type ProcessOutputChannel = "stdout" | "stderr" | "pty";

export interface ProcessOutputOffsets {
  global: number;
  stdout: number;
  stderr: number;
  pty: number;
}

export interface ProcessOutputChunk {
  channel: ProcessOutputChannel;
  globalOffset: number;
  channelOffset: number;
  bytes: number;
}

/**
 * A raw-byte process spool. Each accepted byte is retained once in the global
 * stream and once in its source channel stream. Inline decoding is independent
 * per channel so a UTF-8 code point split across provider chunks is never
 * exposed as replacement characters merely because of the chunk boundary.
 */
export class ProcessOutputSpool {
  private readonly streams = new Map<"global" | ProcessOutputChannel, WriteStream>();
  private readonly decoders = new Map<ProcessOutputChannel, StringDecoder>([
    ["stdout", new StringDecoder("utf8")],
    ["stderr", new StringDecoder("utf8")],
    ["pty", new StringDecoder("utf8")],
  ]);
  private offsets: ProcessOutputOffsets = { global: 0, stdout: 0, stderr: 0, pty: 0 };
  private pending = "";
  private droppedBytes = 0;
  private writeQueue: Promise<void> = Promise.resolve();
  private closePromise?: Promise<void>;
  fileTruncated = false;

  constructor(readonly options: {
    path: string;
    maximumInlineBytes: number;
    maximumFileBytes: number;
  }) {}

  get path(): string {
    return this.options.path;
  }

  get totalFileBytes(): number {
    return this.offsets.global;
  }

  get currentOffsets(): ProcessOutputOffsets {
    return { ...this.offsets };
  }

  channelPath(channel: ProcessOutputChannel): string {
    return `${this.options.path}.${channel}`;
  }

  async open(options: { existing?: boolean; readOnly?: boolean } = {}): Promise<void> {
    if (options.existing) {
      this.offsets = {
        global: await fileSize(this.path),
        stdout: await fileSize(this.channelPath("stdout")),
        stderr: await fileSize(this.channelPath("stderr")),
        pty: await fileSize(this.channelPath("pty")),
      };
    }
    if (options.readOnly) return;
    const flags = options.existing ? "a" : "wx";
    await Promise.all(([
      ["global", this.path],
      ["stdout", this.channelPath("stdout")],
      ["stderr", this.channelPath("stderr")],
      ["pty", this.channelPath("pty")],
    ] as const).map(async ([channel, path]) => {
      const stream = createWriteStream(path, { flags, mode: 0o600 });
      await new Promise<void>((resolve, reject) => {
        stream.once("open", resolve);
        stream.once("error", reject);
      });
      stream.on("error", () => {
        this.fileTruncated = true;
      });
      this.streams.set(channel, stream);
    }));
  }

  append(channel: ProcessOutputChannel, value: Uint8Array): Promise<ProcessOutputChunk> {
    if (this.closePromise) {
      return Promise.reject(new UniversalBrokerError(
        "PRECONDITION_FAILED",
        "Cannot append to a closed process output spool.",
      ));
    }
    const data = Buffer.from(value);
    const remaining = Math.max(0, this.options.maximumFileBytes - this.offsets.global);
    const accepted = data.subarray(0, remaining);
    const chunk: ProcessOutputChunk = {
      channel,
      globalOffset: this.offsets.global,
      channelOffset: this.offsets[channel],
      bytes: accepted.byteLength,
    };
    if (accepted.byteLength < data.byteLength) this.fileTruncated = true;
    if (accepted.byteLength === 0) return Promise.resolve(chunk);

    this.offsets.global += accepted.byteLength;
    this.offsets[channel] += accepted.byteLength;
    this.appendInline(this.decoders.get(channel)!.write(accepted));
    const queued = this.writeQueue.then(async () => {
      await writeWithBackpressure(this.requireStream("global"), accepted);
      await writeWithBackpressure(this.requireStream(channel), accepted);
    }).catch(() => {
      this.fileTruncated = true;
    });
    this.writeQueue = queued;
    return queued.then(() => chunk);
  }

  drain(maximumCharacters: number): { output: string; truncated: boolean } {
    const marker = this.droppedBytes > 0
      ? `... ${this.droppedBytes} buffered byte(s) omitted; full output is available as a resource ...\n`
      : "";
    const available = Math.max(0, maximumCharacters - marker.length);
    const body = this.pending.slice(0, available);
    this.pending = this.pending.slice(body.length);
    const truncated = this.droppedBytes > 0 || this.pending.length > 0 || this.fileTruncated;
    this.droppedBytes = 0;
    return { output: marker + body, truncated };
  }

  async read(
    offset: number,
    limit: number,
    channel: "global" | ProcessOutputChannel = "global",
  ): Promise<{
    bytes: Buffer;
    text: string;
    channel: "global" | ProcessOutputChannel;
    offset: number;
    nextOffset?: number;
    totalBytes: number;
    truncated: boolean;
  }> {
    if (!Number.isSafeInteger(offset) || offset < 0) {
      throw new UniversalBrokerError("PRECONDITION_FAILED", `Invalid output offset: ${offset}`);
    }
    if (!Number.isSafeInteger(limit) || limit < 1 || limit > 1_048_576) {
      throw new UniversalBrokerError("PRECONDITION_FAILED", `Invalid output limit: ${limit}`);
    }
    await this.writeQueue;
    const totalBytes = channel === "global" ? this.offsets.global : this.offsets[channel];
    const handle = await open(channel === "global" ? this.path : this.channelPath(channel), "r");
    try {
      const buffer = Buffer.alloc(Math.min(limit, Math.max(0, totalBytes - offset)));
      const { bytesRead } = await handle.read(buffer, 0, buffer.length, offset);
      const bytes = buffer.subarray(0, bytesRead);
      const nextOffset = offset + bytesRead;
      const decoder = new StringDecoder("utf8");
      const text = decoder.write(bytes) + decoder.end();
      return {
        bytes,
        text,
        channel,
        offset,
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
    for (const decoder of this.decoders.values()) this.appendInline(decoder.end());
    this.closePromise = this.writeQueue.then(async () => {
      await Promise.all([...this.streams.values()].map(endStream));
    });
    return this.closePromise;
  }

  private appendInline(value: string): void {
    if (!value) return;
    this.pending += value;
    const bytes = Buffer.byteLength(this.pending);
    if (bytes <= this.options.maximumInlineBytes) return;
    const overflow = bytes - this.options.maximumInlineBytes;
    const encoded = Buffer.from(this.pending);
    let start = overflow;
    while (start < encoded.length && (encoded[start]! & 0xc0) === 0x80) start += 1;
    this.droppedBytes += start;
    this.pending = encoded.subarray(start).toString("utf8");
  }

  private requireStream(channel: "global" | ProcessOutputChannel): WriteStream {
    const stream = this.streams.get(channel);
    if (!stream) {
      throw new UniversalBrokerError(
        "TRANSPORT_UNAVAILABLE",
        `Process output ${channel} stream is unavailable.`,
      );
    }
    return stream;
  }
}

async function fileSize(path: string): Promise<number> {
  try {
    return (await stat(path)).size;
  } catch (error) {
    if (error instanceof Error && "code" in error && error.code === "ENOENT") return 0;
    throw error;
  }
}

function writeWithBackpressure(stream: WriteStream, data: Buffer): Promise<void> {
  if (stream.destroyed || stream.closed) return Promise.reject(new Error("output stream closed"));
  if (stream.write(data)) return Promise.resolve();
  return new Promise<void>((resolve, reject) => {
    const cleanup = () => {
      stream.off("drain", onDrain);
      stream.off("error", onError);
    };
    const onDrain = () => {
      cleanup();
      resolve();
    };
    const onError = (error: Error) => {
      cleanup();
      reject(error);
    };
    stream.once("drain", onDrain);
    stream.once("error", onError);
  });
}

function endStream(stream: WriteStream): Promise<void> {
  if (stream.closed || stream.destroyed) return Promise.resolve();
  return new Promise<void>((resolve) => {
    stream.once("close", resolve);
    stream.end();
  });
}
