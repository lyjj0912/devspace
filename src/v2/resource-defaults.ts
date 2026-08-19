export const RESOURCE_DEFAULT_CONTEXTS = 128;
export const RESOURCE_DEFAULT_PROCESSES = 256;
export const RESOURCE_DEFAULT_CONCURRENT_PROCESSES = 16;
export const RESOURCE_DEFAULT_MCP_CONNECTIONS = 64;
export const RESOURCE_DEFAULT_GUI_SESSIONS = 16;
export const RESOURCE_DEFAULT_ARTIFACTS = 256;
export const RESOURCE_DEFAULT_INLINE_OUTPUT_BYTES = 64 * 1024;
export const RESOURCE_DEFAULT_PROCESS_OUTPUT_BYTES = 100 * 1024 * 1024;
export const RESOURCE_DEFAULT_ARTIFACT_MAX_BYTES = 2 * 1024 * 1024 * 1024;

export const RESOURCE_DEFAULT_CONTEXT_TTL_MS = 24 * 60 * 60_000;
export const RESOURCE_DEFAULT_COMPLETED_PROCESS_TTL_MS = 24 * 60 * 60_000;
export const RESOURCE_DEFAULT_MCP_IDLE_TTL_MS = 15 * 60_000;
export const RESOURCE_DEFAULT_GUI_TTL_MS = 30 * 60_000;
export const RESOURCE_DEFAULT_ARTIFACT_TTL_MS = 24 * 60 * 60_000;
export const RESOURCE_DEFAULT_CURSOR_SNAPSHOT_TTL_MS = 15 * 60_000;

export const UNIVERSAL_RESOURCE_DEFAULTS = deepFreeze({
  quotas: {
    contexts: RESOURCE_DEFAULT_CONTEXTS,
    processes: RESOURCE_DEFAULT_PROCESSES,
    concurrentProcesses: RESOURCE_DEFAULT_CONCURRENT_PROCESSES,
    mcpConnections: RESOURCE_DEFAULT_MCP_CONNECTIONS,
    guiSessions: RESOURCE_DEFAULT_GUI_SESSIONS,
    artifacts: RESOURCE_DEFAULT_ARTIFACTS,
    inlineOutputBytes: RESOURCE_DEFAULT_INLINE_OUTPUT_BYTES,
    processOutputBytes: RESOURCE_DEFAULT_PROCESS_OUTPUT_BYTES,
    artifactMaxBytes: RESOURCE_DEFAULT_ARTIFACT_MAX_BYTES,
  },
  ttlMs: {
    context: RESOURCE_DEFAULT_CONTEXT_TTL_MS,
    completedProcess: RESOURCE_DEFAULT_COMPLETED_PROCESS_TTL_MS,
    mcpIdle: RESOURCE_DEFAULT_MCP_IDLE_TTL_MS,
    gui: RESOURCE_DEFAULT_GUI_TTL_MS,
    artifact: RESOURCE_DEFAULT_ARTIFACT_TTL_MS,
    cursorSnapshot: RESOURCE_DEFAULT_CURSOR_SNAPSHOT_TTL_MS,
  },
} as const);

function deepFreeze<T>(value: T): Readonly<T> {
  if (value && typeof value === "object" && !Object.isFrozen(value)) {
    for (const nested of Object.values(value as Record<string, unknown>)) deepFreeze(nested);
    Object.freeze(value);
  }
  return value;
}
