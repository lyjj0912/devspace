export interface ClosableMcpTransport {
  close(): Promise<void>;
}

export interface McpSessionCloseResult {
  sessionId: string;
  error?: unknown;
}

interface McpSessionEntry<TTransport> {
  transport: TTransport;
  lastActivityAt: number;
  activeRequests: number;
}

export interface McpSessionRegistryOptions {
  now?: () => number;
  maximumSessions?: number;
}

export class McpSessionRegistry<TTransport extends ClosableMcpTransport> {
  private readonly sessions = new Map<string, McpSessionEntry<TTransport>>();
  private readonly now: () => number;
  private readonly maximumSessions: number;

  constructor(options: McpSessionRegistryOptions = {}) {
    this.now = options.now ?? Date.now;
    this.maximumSessions = options.maximumSessions ?? Number.MAX_SAFE_INTEGER;
    if (!Number.isSafeInteger(this.maximumSessions) || this.maximumSessions < 1) {
      throw new Error("maximumSessions must be a positive safe integer");
    }
  }

  get size(): number {
    return this.sessions.size;
  }

  register(sessionId: string, transport: TTransport): void {
    if (!this.sessions.has(sessionId) && this.sessions.size >= this.maximumSessions) {
      throw new Error(`MCP session quota is full: ${this.maximumSessions}`);
    }
    this.sessions.set(sessionId, {
      transport,
      lastActivityAt: this.now(),
      activeRequests: 0,
    });
  }

  get(sessionId: string): TTransport | undefined {
    const entry = this.sessions.get(sessionId);
    if (!entry) return undefined;

    entry.lastActivityAt = this.now();
    return entry.transport;
  }

  acquire(sessionId: string): TTransport | undefined {
    const entry = this.sessions.get(sessionId);
    if (!entry) return undefined;
    entry.lastActivityAt = this.now();
    entry.activeRequests += 1;
    return entry.transport;
  }

  release(sessionId: string): void {
    const entry = this.sessions.get(sessionId);
    if (!entry) return;
    entry.activeRequests = Math.max(0, entry.activeRequests - 1);
    entry.lastActivityAt = this.now();
  }

  remove(sessionId: string): boolean {
    return this.sessions.delete(sessionId);
  }

  async closeIdle(idleTimeoutMs: number): Promise<McpSessionCloseResult[]> {
    const cutoff = this.now() - idleTimeoutMs;
    const idleSessions: Array<{ sessionId: string; transport: TTransport }> = [];

    for (const [sessionId, entry] of this.sessions) {
      if (entry.lastActivityAt > cutoff || entry.activeRequests > 0) continue;

      this.sessions.delete(sessionId);
      idleSessions.push({ sessionId, transport: entry.transport });
    }

    return closeSessions(idleSessions);
  }

  async closeAll(): Promise<McpSessionCloseResult[]> {
    const sessions = Array.from(this.sessions, ([sessionId, entry]) => ({
      sessionId,
      transport: entry.transport,
    }));
    this.sessions.clear();
    return closeSessions(sessions);
  }

  async closeLeastRecentlyUsed(count = 1): Promise<McpSessionCloseResult[]> {
    if (!Number.isSafeInteger(count) || count < 1) return [];
    const candidates = [...this.sessions.entries()]
      .filter(([, entry]) => entry.activeRequests === 0)
      .sort((left, right) => left[1].lastActivityAt - right[1].lastActivityAt)
      .slice(0, count)
      .map(([sessionId, entry]) => ({ sessionId, transport: entry.transport }));
    for (const candidate of candidates) this.sessions.delete(candidate.sessionId);
    return closeSessions(candidates);
  }

  snapshot(): Array<{
    sessionId: string;
    lastActivityAt: number;
    activeRequests: number;
  }> {
    return [...this.sessions.entries()].map(([sessionId, entry]) => ({
      sessionId,
      lastActivityAt: entry.lastActivityAt,
      activeRequests: entry.activeRequests,
    }));
  }
}

async function closeSessions<TTransport extends ClosableMcpTransport>(
  sessions: Array<{ sessionId: string; transport: TTransport }>,
): Promise<McpSessionCloseResult[]> {
  return Promise.all(
    sessions.map(async ({ sessionId, transport }) => {
      try {
        await transport.close();
        return { sessionId };
      } catch (error) {
        return { sessionId, error };
      }
    }),
  );
}
