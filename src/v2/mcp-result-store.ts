import { randomUUID } from "node:crypto";
import { UniversalBrokerError } from "./errors.js";

interface ResultRecord {
  id: string;
  serialized: string;
  createdAt: number;
  expiresAt: number;
  lastUsedAt: number;
}

export interface UniversalMcpResultStoreOptions {
  maximumEntries?: number;
  maximumTotalCharacters?: number;
  ttlMs?: number;
  now?: () => number;
}

export class UniversalMcpResultStore {
  private readonly records = new Map<string, ResultRecord>();
  private readonly maximumEntries: number;
  private readonly maximumTotalCharacters: number;
  private readonly ttlMs: number;
  private readonly now: () => number;
  private totalCharacters = 0;

  constructor(options: UniversalMcpResultStoreOptions = {}) {
    this.maximumEntries = boundedInteger(options.maximumEntries, 64, 1, 10_000);
    this.maximumTotalCharacters = boundedInteger(
      options.maximumTotalCharacters,
      10_000_000,
      1_000,
      1_000_000_000,
    );
    this.ttlMs = boundedInteger(options.ttlMs, 15 * 60_000, 1_000, 86_400_000);
    this.now = options.now ?? Date.now;
  }

  put(value: unknown): {
    resultId: string;
    resourceUri: string;
    characters: number;
    expiresAt: string;
  } {
    const serialized = JSON.stringify(value) ?? "null";
    if (serialized.length > this.maximumTotalCharacters) {
      throw new UniversalBrokerError(
        "RESOURCE_QUOTA_EXCEEDED",
        "One MCP result exceeds the total result-store character quota.",
        { evidence: { characters: serialized.length, maximum: this.maximumTotalCharacters } },
      );
    }
    this.pruneExpired();
    while (
      this.records.size >= this.maximumEntries
      || this.totalCharacters + serialized.length > this.maximumTotalCharacters
    ) {
      const oldest = [...this.records.values()]
        .sort((left, right) => left.lastUsedAt - right.lastUsedAt)[0];
      if (!oldest) break;
      this.delete(oldest.id);
    }
    const now = this.now();
    const id = randomUUID();
    const record: ResultRecord = {
      id,
      serialized,
      createdAt: now,
      expiresAt: now + this.ttlMs,
      lastUsedAt: now,
    };
    this.records.set(id, record);
    this.totalCharacters += serialized.length;
    return {
      resultId: id,
      resourceUri: `devspace://mcp-result/${id}/0/12000`,
      characters: serialized.length,
      expiresAt: new Date(record.expiresAt).toISOString(),
    };
  }

  readByUri(uri: string): Record<string, unknown> {
    const { id, offset, limit } = parseResultUri(uri);
    return this.read(id, offset, limit, uri);
  }

  read(
    id: string,
    offset = 0,
    maximumCharacters = 12_000,
    uri = `devspace://mcp-result/${id}/${offset}/${maximumCharacters}`,
  ): Record<string, unknown> {
    this.pruneExpired();
    const record = this.records.get(id);
    if (!record) {
      throw new UniversalBrokerError(
        "PATH_NOT_FOUND",
        `MCP result resource is unknown or expired: ${id}`,
      );
    }
    if (!Number.isSafeInteger(offset) || offset < 0 || offset > record.serialized.length) {
      throw new UniversalBrokerError("PRECONDITION_FAILED", "MCP result offset is invalid.");
    }
    const limit = boundedInteger(maximumCharacters, 12_000, 1, 100_000);
    record.lastUsedAt = this.now();
    const text = record.serialized.slice(offset, offset + limit);
    const nextOffset = offset + text.length;
    return {
      uri,
      mimeType: "application/json",
      text,
      offset,
      charactersRead: text.length,
      totalCharacters: record.serialized.length,
      truncated: nextOffset < record.serialized.length,
      ...(nextOffset < record.serialized.length ? {
        nextOffset,
        nextResourceUri: `devspace://mcp-result/${id}/${nextOffset}/${limit}`,
      } : {}),
      expiresAt: new Date(record.expiresAt).toISOString(),
    };
  }

  clear(): void {
    this.records.clear();
    this.totalCharacters = 0;
  }

  stats(): { entries: number; totalCharacters: number } {
    this.pruneExpired();
    return { entries: this.records.size, totalCharacters: this.totalCharacters };
  }

  private pruneExpired(): void {
    const now = this.now();
    for (const record of this.records.values()) {
      if (record.expiresAt <= now) this.delete(record.id);
    }
  }

  private delete(id: string): void {
    const record = this.records.get(id);
    if (!record) return;
    this.records.delete(id);
    this.totalCharacters -= record.serialized.length;
  }
}

export function parseResultUri(uri: string): { id: string; offset: number; limit: number } {
  let parsed: URL;
  try {
    parsed = new URL(uri);
  } catch {
    throw new UniversalBrokerError("PRECONDITION_FAILED", `Invalid MCP result URI: ${uri}`);
  }
  if (parsed.protocol !== "devspace:" || parsed.hostname !== "mcp-result") {
    throw new UniversalBrokerError("PRECONDITION_FAILED", `Not an MCP result URI: ${uri}`);
  }
  const [id, rawOffset = "0", rawLimit = "12000"] = parsed.pathname.replace(/^\/+/, "").split("/");
  if (!id) throw new UniversalBrokerError("PRECONDITION_FAILED", `Missing result ID: ${uri}`);
  const offset = Number(rawOffset);
  const limit = Number(rawLimit);
  if (!Number.isSafeInteger(offset) || offset < 0) {
    throw new UniversalBrokerError("PRECONDITION_FAILED", `Invalid result offset: ${uri}`);
  }
  return { id, offset, limit: boundedInteger(limit, 12_000, 1, 100_000) };
}

function boundedInteger(
  value: number | undefined,
  fallback: number,
  minimum: number,
  maximum: number,
): number {
  const parsed = value ?? fallback;
  if (!Number.isInteger(parsed) || parsed < minimum || parsed > maximum) {
    throw new UniversalBrokerError(
      "PRECONDITION_FAILED",
      `Expected an integer from ${minimum} through ${maximum}.`,
    );
  }
  return parsed;
}
