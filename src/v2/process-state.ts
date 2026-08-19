import { createHash, randomUUID } from "node:crypto";
import { mkdir, open, readdir, readFile, rename, rm, writeFile } from "node:fs/promises";
import { basename, dirname, join } from "node:path";
import type { AuthorityRiskClass } from "./contracts.js";
import type { DurableProcessIdentity } from "./durable-process-adapter.js";
import { UniversalBrokerError } from "./errors.js";

export const PROCESS_STATE_SCHEMA_VERSION = 1;

export interface PersistentProcessRecord {
  schemaVersion: typeof PROCESS_STATE_SCHEMA_VERSION;
  processId: string;
  principalKeyFingerprint: string;
  targetId: string;
  targetGeneration: string;
  transport: "local" | "ssh";
  cwd: string;
  tty: boolean;
  launchRisk: AuthorityRiskClass;
  state: string;
  startedAtMs: number;
  endedAtMs?: number;
  exitCode?: number;
  signal?: string;
  errorCode?: string;
  errorMessage?: string;
  outputPath: string;
  durable: boolean;
  durableIdentity?: DurableProcessIdentity;
  checksum: string;
}

export interface ProcessStateStore {
  loadAll(): Promise<PersistentProcessRecord[]>;
  save(record: Omit<PersistentProcessRecord, "schemaVersion" | "checksum">): Promise<void>;
  delete(processId: string): Promise<void>;
}

export class FileProcessStateStore implements ProcessStateStore {
  constructor(private readonly directory: string) {}

  async loadAll(): Promise<PersistentProcessRecord[]> {
    await mkdir(this.directory, { recursive: true, mode: 0o700 });
    const names = (await readdir(this.directory)).filter((name) => name.endsWith(".json")).sort();
    const records: PersistentProcessRecord[] = [];
    for (const name of names) {
      const path = join(this.directory, name);
      try {
        const parsed = JSON.parse(await readFile(path, "utf8")) as PersistentProcessRecord;
        assertRecord(parsed, path);
        records.push(parsed);
      } catch (error) {
        const quarantine = `${path}.corrupt-${Date.now()}-${randomUUID()}`;
        await rename(path, quarantine).catch(() => undefined);
        throw new UniversalBrokerError(
          "STATE_CORRUPTED",
          `Process state is corrupt and was quarantined: ${basename(path)}`,
          { evidence: { stateFile: path, quarantine, cause: errorMessage(error) } },
        );
      }
    }
    return records;
  }

  async save(
    input: Omit<PersistentProcessRecord, "schemaVersion" | "checksum">,
  ): Promise<void> {
    await mkdir(this.directory, { recursive: true, mode: 0o700 });
    const unsigned = { schemaVersion: PROCESS_STATE_SCHEMA_VERSION as 1, ...input };
    const record: PersistentProcessRecord = {
      ...unsigned,
      checksum: checksum(unsigned),
    };
    const path = this.path(input.processId);
    const temporary = `${path}.tmp-${process.pid}-${randomUUID()}`;
    try {
      await writeFile(temporary, JSON.stringify(record), { mode: 0o600, flag: "wx" });
      const file = await open(temporary, "r");
      try {
        await file.sync();
      } finally {
        await file.close();
      }
      await rename(temporary, path);
      const parent = await open(dirname(path), "r");
      try {
        await parent.sync();
      } finally {
        await parent.close();
      }
    } catch (error) {
      await rm(temporary, { force: true }).catch(() => undefined);
      throw new UniversalBrokerError(
        "AUTHORITY_STORE_UNAVAILABLE",
        `Unable to persist process state for ${input.processId}.`,
        { evidence: { processId: input.processId, cause: errorMessage(error) } },
      );
    }
  }

  async delete(processId: string): Promise<void> {
    await rm(this.path(processId), { force: true });
  }

  private path(processId: string): string {
    if (!/^proc_[a-zA-Z0-9-]+$/.test(processId)) {
      throw new UniversalBrokerError("PRECONDITION_FAILED", "Invalid persisted process ID.");
    }
    return join(this.directory, `${processId}.json`);
  }
}

function assertRecord(record: PersistentProcessRecord, path: string): void {
  if (
    record?.schemaVersion !== PROCESS_STATE_SCHEMA_VERSION
    || typeof record.processId !== "string"
    || typeof record.principalKeyFingerprint !== "string"
    || typeof record.outputPath !== "string"
    || typeof record.checksum !== "string"
  ) {
    throw new Error(`Invalid process state shape: ${path}`);
  }
  const { checksum: observed, ...unsigned } = record;
  if (observed !== checksum(unsigned)) throw new Error(`Process state checksum mismatch: ${path}`);
}

function checksum(value: unknown): string {
  return createHash("sha256").update(stableJson(value)).digest("hex");
}

function stableJson(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(stableJson).join(",")}]`;
  if (value && typeof value === "object") {
    const record = value as Record<string, unknown>;
    return `{${Object.keys(record)
      .filter((key) => record[key] !== undefined)
      .sort()
      .map((key) => `${JSON.stringify(key)}:${stableJson(record[key])}`)
      .join(",")}}`;
  }
  return JSON.stringify(value) ?? "null";
}

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}
