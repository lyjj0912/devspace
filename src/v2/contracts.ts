import * as z from "zod/v4";

export const UNIVERSAL_BROKER_VERSION = "2.1.1";

export const UNIVERSAL_TOOL_NAMES = [
  "target",
  "context",
  "fs",
  "exec",
  "process",
  "mcp",
  "artifact",
  "gui",
] as const;

export type UniversalToolName = (typeof UNIVERSAL_TOOL_NAMES)[number];

export const UNIVERSAL_AUTHORITY_RISKS = ["R0", "R1", "R2", "R3"] as const;
export type AuthorityRiskClass = (typeof UNIVERSAL_AUTHORITY_RISKS)[number];

export const UNIVERSAL_TOOL_OPERATIONS = {
  target: ["list", "resolve", "probe"],
  context: ["open", "search", "diff", "close"],
  fs: [
    "stat",
    "list",
    "read",
    "search",
    "write",
    "patch",
    "mkdir",
    "copy",
    "move",
    "remove",
    "hash",
    "sync",
  ],
  exec: ["run"],
  process: ["poll", "write", "resize", "signal", "wait", "list", "forget", "restart_broker", "restart_status"],
  mcp: [
    "routes",
    "search_tools",
    "describe_tool",
    "invoke",
    "list_resources",
    "read_resource",
    "list_prompts",
    "get_prompt",
    "close",
  ],
  artifact: ["receive", "publish", "copy"],
  gui: ["capabilities", "observe", "act", "wait"],
} as const satisfies Record<UniversalToolName, readonly [string, ...string[]]>;

export const UNIVERSAL_OWNER_SCOPES = [
  "devspace.read",
  "devspace.write",
  "devspace.exec",
  "devspace.mcp",
  "devspace.artifact",
  "devspace.gui",
] as const;

export const UNIVERSAL_ERROR_CODES = [
  "AUTHENTICATION_FAILED",
  "SCOPE_INSUFFICIENT",
  "CAPABILITY_UNAVAILABLE",
  "TARGET_NOT_FOUND",
  "TARGET_AMBIGUOUS",
  "TARGET_OFFLINE",
  "PATH_NOT_FOUND",
  "PATH_TYPE_MISMATCH",
  "PERMISSION_DENIED",
  "PRECONDITION_FAILED",
  "TRANSPORT_UNAVAILABLE",
  "TRANSPORT_INTERRUPTED",
  "EXECUTION_STATE_UNKNOWN",
  "PROCESS_NOT_FOUND",
  "MCP_ROUTE_NOT_FOUND",
  "MCP_TOOL_NOT_FOUND",
  "MCP_PROVIDER_ERROR",
  "MCP_CONNECTION_UNAVAILABLE",
  "MCP_RESULT_UNKNOWN",
  "DISPATCH_STATE_UNKNOWN",
  "HOST_ACTION_BLOCKED",
  "HOST_CAPABILITY_UNAVAILABLE",
  "HOST_ARTIFACT_CAPABILITY_UNAVAILABLE",
  "GUI_STATE_CHANGED",
  "OUTPUT_TRUNCATED",
  "RESOURCE_QUOTA_EXCEEDED",
  "RESOURCE_BUSY",
  "RATE_LIMITED",
  "CURSOR_INVALID",
  "CURSOR_EXPIRED",
  "CURSOR_STALE",
  "STATE_CORRUPTED",
  "INVALID_ARGUMENT",
  "RESOURCE_EXPIRED",
  "TARGET_IDENTITY_MISMATCH",
  "PROCESS_NOT_DURABLE",
  "GUI_GENERATION_MISMATCH",
  "SCHEMA_STALE",
  "ELEVATION_BLOCKED",
  "ELEVATION_DENIED",
  "SYNC_PLAN_STALE",
  "SYNC_CONFLICT",
  "RESTART_ACK_NOT_FLUSHED",
  "ARTIFACT_CATALOG_UNAVAILABLE",
  "ARTIFACT_EXPIRED",
  "PROFILE_UNSUPPORTED",
  "MIGRATION_CONFLICT",
  "ROLLBACK_STATE_UNKNOWN",
  "CONNECTOR_STATE_CONFLICT",
  "SUPERVISOR_UNAVAILABLE",
  "FINALIZATION_STAGE_CONFLICT",
] as const;

const LEGACY_AUTHORITY_ERROR_CODES = [
  "AUTHORITY_REQUIRED",
  "AUTHORITY_EXPIRED",
  "AUTHORITY_PRINCIPAL_MISMATCH",
  "AUTHORITY_ACTION_MISMATCH",
  "AUTHORITY_STALE",
  "AUTHORITY_STORE_UNAVAILABLE",
  "AUTHORITY_STATE_UNCERTAIN",
  "AUTHORITY_MISMATCH",
  "AUTHORITY_CONSUMED",
  "CONNECTOR_ACTIVATION_REQUIRED",
] as const;

export type UniversalErrorCode =
  | (typeof UNIVERSAL_ERROR_CODES)[number]
  | (typeof LEGACY_AUTHORITY_ERROR_CODES)[number];

export const UNIVERSAL_BROKER_BUDGETS = Object.freeze({
  maximumTools: 8,
  maximumToolDescriptorCharacters: 9_000,
  maximumServerInstructionCharacters: 2_000,
  maximumInitialContextCharacters: 4_000,
  maximumReusedContextCharacters: 512,
  maximumMetaCharacters: 8_000,
});

export const UNIVERSAL_BROKER_INSTRUCTIONS = [
  "DevSpace Personal Direct Owner exposes a fixed set of generic tools.",
  "Resolve named machines and environments with target instead of guessing identifiers.",
  "Use context only for project instructions, Git state, and a default target/path; it is not a security boundary.",
  "Use fs for local or remote files, exec plus process for commands, mcp for arbitrary configured MCP servers, artifact for file exchange, and gui only for operating-system UI that has no better protocol.",
  "DevSpace never installs, injects, or reuses privilege-elevation credentials. Commands and file operations run only as the configured target user; any operating-system authorization must be approved directly by the user outside DevSpace.",
  "DevSpace blocks privilege-elevation commands at validation and execution boundaries. Privileged work is manual and outside DevSpace.",
  "Do not automatically replay a mutation when its dispatch state is unknown; read back its result first.",
  "Large results are returned through resource handles rather than repeated in tool text.",
].join(" ");

export type DispatchState =
  | "NOT_DISPATCHED"
  | "DISPATCHED"
  | "ACKNOWLEDGED"
  | "UNKNOWN";

export interface WarningRecord {
  code: string;
  message: string;
  evidence?: Record<string, unknown>;
}

export interface RuntimeIdentity {
  productVersion: string;
  productProfile: "PERSONAL_DIRECT_OWNER";
  buildCapabilityDigest?: string;
  resourceUriVersion?: "v1";
  schemaGeneration: string;
  /** @deprecated Legacy compile-time compatibility; personal runtime objects omit this key. */
  authorityContractGeneration?: string;
  configDigest: string;
  sourceRevision: string;
  runtimeRevision: string;
  buildDigest: string;
  startedAt: string;
}

/** Public correlation and optimistic-concurrency metadata shared by all eight tools. */
export interface UniversalRequestMeta {
  requestId?: string;
  transactionId?: string;
  expectedSchemaGeneration?: string;
  expectedTargetGeneration?: string;
  expectedRouteGeneration?: string;
}

export interface SuccessEnvelope<T> {
  ok: true;
  operationId: string;
  data: T;
  warnings?: WarningRecord[];
  resourceUri?: string;
  nextCursor?: string;
  observedSchemaGeneration: string;
  observedTargetGeneration?: string;
  observedRouteGeneration?: string;
}

const cursorSchema = z.string().min(1).optional();
const limitSchema = z.number().int().min(1).max(10_000).optional();
const genericRecordSchema = z.record(z.string(), z.unknown());

export const UNIVERSAL_REQUEST_META_INPUT_SCHEMA = {
  requestId: z.string().min(1).max(256).optional(),
  transactionId: z.string().min(1).max(128).optional(),
  expectedSchemaGeneration: z.string().min(1).max(256).optional(),
  expectedTargetGeneration: z.string().min(1).max(256).optional(),
  expectedRouteGeneration: z.string().min(1).max(256).optional(),
} as const satisfies z.ZodRawShape;

export const universalRequestMetaSchema = z.strictObject(
  UNIVERSAL_REQUEST_META_INPUT_SCHEMA,
);

export const UNIVERSAL_RESULT_OUTPUT_SCHEMA = {
  ok: z.boolean(),
  operationId: z.string(),
  data: z.unknown().optional(),
  warnings: z.array(genericRecordSchema).optional(),
  resourceUri: z.string().optional(),
  nextCursor: z.string().optional(),
  observedSchemaGeneration: z.string(),
  observedTargetGeneration: z.string().optional(),
  observedRouteGeneration: z.string().optional(),
  error: z
    .object({
      code: z.enum(UNIVERSAL_ERROR_CODES),
      message: z.string(),
      retryable: z.boolean(),
      dispatchState: z.enum(["NOT_DISPATCHED", "DISPATCHED", "ACKNOWLEDGED", "UNKNOWN"]),
      resourceKey: z.string().optional(),
      evidence: genericRecordSchema.optional(),
      recovery: z.array(genericRecordSchema).optional(),
      suggestions: z.array(genericRecordSchema).optional(),
    })
    .optional(),
  audit: genericRecordSchema.optional(),
} as const satisfies z.ZodRawShape;

export const universalResultEnvelopeSchema = z.strictObject(
  UNIVERSAL_RESULT_OUTPUT_SCHEMA,
);

export const universalResultOutputSchema: z.ZodRawShape =
  UNIVERSAL_RESULT_OUTPUT_SCHEMA;

export interface UniversalToolContract<TShape extends z.ZodRawShape = z.ZodRawShape> {
  title: string;
  description: string;
  inputSchema: TShape;
  annotations: {
    readOnlyHint: boolean;
    destructiveHint: boolean;
    idempotentHint: boolean;
    openWorldHint: boolean;
  };
}

const targetContract = {
  title: "Target",
  description: "Discover targets.",
  inputSchema: {
    operation: z.enum(UNIVERSAL_TOOL_OPERATIONS.target),
    selector: z.string().min(1).optional(),
    targetId: z.string().min(1).optional(),
    refresh: z.boolean().optional(),
    cursor: cursorSchema,
    limit: limitSchema,
  },
  annotations: {
    readOnlyHint: true,
    destructiveHint: false,
    idempotentHint: true,
    openWorldHint: true,
  },
} satisfies UniversalToolContract;

const contextContract = {
  title: "Context",
  description: "Project context and convenience index.",
  inputSchema: {
    operation: z.enum(UNIVERSAL_TOOL_OPERATIONS.context),
    contextId: z.string().min(1).optional(),
    target: z.string().min(1).optional(),
    path: z.string().min(1).optional(),
    mode: z.enum(["existing", "worktree"]).optional(),
    baseRef: z.string().min(1).optional(),
    task: z.string().min(1).optional(),
    query: z.string().min(1).optional(),
    maxCharacters: z.number().int().min(100).max(100_000).optional(),
    cursor: cursorSchema,
    limit: limitSchema,
  },
  annotations: {
    readOnlyHint: false,
    destructiveHint: true,
    idempotentHint: false,
    openWorldHint: true,
  },
} satisfies UniversalToolContract;

const filesystemSyncInputSchema = z.strictObject({
  phase: z.enum(["plan", "apply"]),
  planId: z.string().min(1).max(256).optional(),
  planDigest: z.string().min(1).max(256).optional(),
  include: z.array(z.string().min(1).max(4_096)).max(1_024).optional(),
  exclude: z.array(z.string().min(1).max(4_096)).max(1_024).optional(),
  deleteMode: z.enum(["none", "trash", "permanent"]).optional(),
  conflictStrategy: z.enum(["fail", "source-wins"]).optional(),
}).superRefine((sync, context) => {
  if (sync.phase === "apply") {
    if (!sync.planId) {
      context.addIssue({ code: "custom", path: ["planId"], message: "planId is required for apply" });
    }
    if (!sync.planDigest) {
      context.addIssue({ code: "custom", path: ["planDigest"], message: "planDigest is required for apply" });
    }
    for (const field of ["include", "exclude", "deleteMode", "conflictStrategy"] as const) {
      if (sync[field] !== undefined) {
        context.addIssue({
          code: "custom",
          path: [field],
          message: "apply accepts only planId and planDigest",
        });
      }
    }
  } else {
    for (const field of ["planId", "planDigest"] as const) {
      if (sync[field] !== undefined) {
        context.addIssue({ code: "custom", path: [field], message: "plan does not accept apply bindings" });
      }
    }
  }
});

const fsContract = {
  title: "Filesystem",
  description: "Target files.",
  inputSchema: {
    operation: z.enum(UNIVERSAL_TOOL_OPERATIONS.fs),
    target: z.string().min(1).optional(),
    contextId: z.string().min(1).optional(),
    path: z.string().min(1).optional(),
    destination: z.string().min(1).optional(),
    content: z.string().optional(),
    patch: z.string().optional(),
    query: z.string().min(1).optional(),
    recursive: z.boolean().optional(),
    overwrite: z.boolean().optional(),
    expectedSha256: z.string().min(1).optional(),
    disposition: z.enum(["trash", "permanent"]).optional(),
    sync: filesystemSyncInputSchema.optional(),
    finalSymlink: z.enum(["follow", "preserve", "replace", "reject"]).optional(),
    offset: z.number().int().min(0).max(Number.MAX_SAFE_INTEGER).optional(),
    cursor: cursorSchema,
    limit: limitSchema,
  },
  annotations: {
    readOnlyHint: false,
    destructiveHint: true,
    idempotentHint: false,
    openWorldHint: true,
  },
} satisfies UniversalToolContract;

const execContract = {
  title: "Execute",
  description: "Run a command.",
  inputSchema: {
    target: z.string().min(1).optional(),
    contextId: z.string().min(1).optional(),
    cwd: z.string().min(1).optional(),
    command: z.string().min(1),
    tty: z.boolean().optional(),
    mode: z.enum(["auto", "foreground", "background"]).optional(),
    yieldMs: z.number().int().min(0).max(30_000).optional(),
    maxOutputChars: z.number().int().min(1).max(1_000_000).optional(),
    envProfile: z.string().min(1).optional(),
    durable: z.boolean().optional(),
  },
  annotations: {
    readOnlyHint: false,
    destructiveHint: true,
    idempotentHint: false,
    openWorldHint: true,
  },
} satisfies UniversalToolContract;

const processContract = {
  title: "Process",
  description: "Managed processes.",
  inputSchema: {
    operation: z.enum(UNIVERSAL_TOOL_OPERATIONS.process),
    processId: z.string().min(1).optional(),
    chars: z.string().optional(),
    signal: z.string().min(1).optional(),
    columns: z.number().int().min(1).max(1_000).optional(),
    rows: z.number().int().min(1).max(1_000).optional(),
    transactionId: z.string().min(1).max(128).optional(),
    reason: z.string().min(1).max(2_000).optional(),
    waitMs: z.number().int().min(0).max(110_000).optional(),
    maxOutputChars: z.number().int().min(1).max(1_000_000).optional(),
    cursor: cursorSchema,
    limit: limitSchema,
  },
  annotations: {
    readOnlyHint: false,
    destructiveHint: true,
    idempotentHint: false,
    openWorldHint: true,
  },
} satisfies UniversalToolContract;

const mcpContract = {
  title: "MCP",
  description: "MCP routes.",
  inputSchema: {
    operation: z.enum(UNIVERSAL_TOOL_OPERATIONS.mcp),
    route: z.string().min(1).optional(),
    query: z.string().min(1).optional(),
    name: z.string().min(1).optional(),
    arguments: genericRecordSchema.optional(),
    uri: z.string().min(1).optional(),
    cursor: cursorSchema,
    limit: limitSchema,
    responsePolicy: genericRecordSchema.optional(),
  },
  annotations: {
    readOnlyHint: false,
    destructiveHint: true,
    idempotentHint: false,
    openWorldHint: true,
  },
} satisfies UniversalToolContract;

const artifactContract = {
  title: "Artifact",
  description: "Transfer artifacts.",
  inputSchema: {
    operation: z.enum(UNIVERSAL_TOOL_OPERATIONS.artifact),
    source: genericRecordSchema,
    destination: genericRecordSchema.optional(),
    overwrite: z.boolean().optional(),
    maxBytes: z.number().int().min(1).optional(),
    ttlSeconds: z.number().int().min(1).max(86_400).optional(),
  },
  annotations: {
    readOnlyHint: false,
    destructiveHint: true,
    idempotentHint: false,
    openWorldHint: true,
  },
} satisfies UniversalToolContract;

const guiContract = {
  title: "GUI",
  description: "Accessible GUI.",
  inputSchema: {
    operation: z.enum(UNIVERSAL_TOOL_OPERATIONS.gui),
    target: z.string().min(1).optional(),
    sessionId: z.string().min(1).optional(),
    generation: z.string().min(1).optional(),
    action: genericRecordSchema.optional(),
    timeoutMs: z.number().int().min(0).max(120_000).optional(),
    maxElements: z.number().int().min(1).max(1_000).optional(),
    focusPolicy: z.enum(["preserve", "allow"]).optional(),
  },
  annotations: {
    readOnlyHint: false,
    destructiveHint: true,
    idempotentHint: false,
    openWorldHint: true,
  },
} satisfies UniversalToolContract;

export const UNIVERSAL_TOOL_CONTRACTS = {
  target: targetContract,
  context: contextContract,
  fs: fsContract,
  exec: execContract,
  process: processContract,
  mcp: mcpContract,
  artifact: artifactContract,
  gui: guiContract,
} as const satisfies Record<UniversalToolName, UniversalToolContract>;
