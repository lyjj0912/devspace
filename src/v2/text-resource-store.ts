import { randomUUID } from "node:crypto";
import { UniversalBrokerError } from "./errors.js";

interface TextResourceRecord {
  id: string;
  text: string;
  mimeType: string;
  createdAt: number;
  expiresAt: number;
  lastUsedAt: number;
}

export interface UniversalTextResourceStoreOptions {
  authority: string;
  maximumEntries?: number;
  maximumTotalCharacters?: number;
  ttlMs?: number;
  defaultPageCharacters?: number;
  now?: () => number;
}

export class UniversalTextResourceStore {
  private readonly records = new Map<string, TextResourceRecord>();
  private readonly authority: string;
  private readonly maximumEntries: number;
  private readonly maximumTotalCharacters: number;
  private readonly ttlMs: number;
  private readonly defaultPageCharacters: number;
  private readonly now: () => number;
  private totalCharacters = 0;

  constructor(options: UniversalTextResourceStoreOptions) {
    this.authority = requireAuthority(options.authority);
    this.maximumEntries = boundedInteger(options.maximumEntries, 64, 1, 10_000);
    this.maximumTotalCharacters = boundedInteger(
      options.maximumTotalCharacters,
      10_000_000,
      1_000,
      1_000_000_000,
    );
    this.ttlMs = boundedInteger(options.ttlMs, 15 * 60_000, 1_000, 86_400_000);
    this.defaultPageCharacters = boundedInteger(
      options.defaultPageCharacters,
      12_000,
      1,
      100_000,
    );
    this.now = options.now ?? Date.now;
  }

  put(text: string, mimeType = "text/plain"): {
    resourceId: string;
    resourceUri: string;
    characters: number;
    expiresAt: string;
  } {
    if (text.length > this.maximumTotalCharacters) {
      throw new UniversalBrokerError(
        "RESOURCE_QUOTA_EXCEEDED",
        `One ${this.authority} resource exceeds the total character quota.`,
        { evidence: { characters: text.length, maximum: this.maximumTotalCharacters } },
      );
    }
    this.pruneExpired();
    while (
      this.records.size >= this.maximumEntries
      || this.totalCharacters + text.length > this.maximumTotalCharacters
    ) {
      const oldest = [...this.records.values()]
        .sort((left, right) => left.lastUsedAt - right.lastUsedAt)[0];
      if (!oldest) break;
      this.delete(oldest.id);
    }
    const now = this.now();
    const id = randomUUID();
    const record: TextResourceRecord = {
      id,
      text,
      mimeType,
      createdAt: now,
      expiresAt: now + this.ttlMs,
      lastUsedAt: now,
    };
    this.records.set(id, record);
    this.totalCharacters += text.length;
    return {
      resourceId: id,
      resourceUri: this.uri(id, 0, this.defaultPageCharacters),
      characters: text.length,
      expiresAt: new Date(record.expiresAt).toISOString(),
    };
  }

  readByUri(uri: string): Record<string, unknown> {
    const { id, offset, limit } = this.parseUri(uri);
    return this.read(id, offset, limit, uri);
  }

  read(
    id: string,
    offset = 0,
    maximumCharacters = this.defaultPageCharacters,
    uri = this.uri(id, offset, maximumCharacters),
  ): Record<string, unknown> {
    this.pruneExpired();
    const record = this.records.get(id);
    if (!record) {
      throw new UniversalBrokerError(
        "PATH_NOT_FOUND",
        `${this.authority} resource is unknown or expired: ${id}`,
      );
    }
    if (!Number.isSafeInteger(offset) || offset < 0 || offset > record.text.length) {
      throw new UniversalBrokerError("PRECONDITION_FAILED", `${this.authority} offset is invalid.`);
    }
    const limit = boundedInteger(maximumCharacters, this.defaultPageCharacters, 1, 100_000);
    record.lastUsedAt = this.now();
    const text = record.text.slice(offset, offset + limit);
    const nextOffset = offset + text.length;
    return {
      uri,
      mimeType: record.mimeType,
      text,
      offset,
      charactersRead: text.length,
      totalCharacters: record.text.length,
      truncated: nextOffset < record.text.length,
      ...(nextOffset < record.text.length ? {
        nextOffset,
        nextResourceUri: this.uri(id, nextOffset, limit),
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

  private uri(id: string, offset: number, limit: number): string {
    return `devspace://${this.authority}/${encodeURIComponent(id)}/${offset}/${limit}`;
  }

  private parseUri(uri: string): { id: string; offset: number; limit: number } {
    let parsed: URL;
    try {
      parsed = new URL(uri);
    } catch {
      throw new UniversalBrokerError("PRECONDITION_FAILED", `Invalid ${this.authority} URI: ${uri}`);
    }
    if (parsed.protocol !== "devspace:" || parsed.hostname !== this.authority) {
      throw new UniversalBrokerError("PRECONDITION_FAILED", `Not a ${this.authority} URI: ${uri}`);
    }
    const [id, rawOffset = "0", rawLimit = String(this.defaultPageCharacters)] = parsed.pathname
      .replace(/^\/+/, "")
      .split("/");
    if (!id) throw new UniversalBrokerError("PRECONDITION_FAILED", `Missing resource ID: ${uri}`);
    const offset = Number(rawOffset);
    const limit = Number(rawLimit);
    if (!Number.isSafeInteger(offset) || offset < 0) {
      throw new UniversalBrokerError("PRECONDITION_FAILED", `Invalid resource offset: ${uri}`);
    }
    return {
      id: decodeURIComponent(id),
      offset,
      limit: boundedInteger(limit, this.defaultPageCharacters, 1, 100_000),
    };
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
    this.totalCharacters -= record.text.length;
  }
}

function requireAuthority(value: string): string {
  if (!/^[a-z][a-z0-9-]{0,63}$/.test(value)) {
    throw new UniversalBrokerError("PRECONDITION_FAILED", `Invalid resource authority: ${value}`);
  }
  return value;
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
