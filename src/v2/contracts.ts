import * as z from "zod/v4";

export const UNIVERSAL_BROKER_VERSION = "2.0.0";

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
  process: ["poll", "write", "resize", "signal", "wait", "list", "forget"],
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
  "MCP_RESULT_UNKNOWN",
  "HOST_ACTION_BLOCKED",
  "HOST_ARTIFACT_CAPABILITY_UNAVAILABLE",
  "GUI_STATE_CHANGED",
  "OUTPUT_TRUNCATED",
  "RESOURCE_QUOTA_EXCEEDED",
] as const;

export type UniversalErrorCode = (typeof UNIVERSAL_ERROR_CODES)[number];

export const UNIVERSAL_BROKER_BUDGETS = Object.freeze({
  maximumTools: 8,
  maximumToolDescriptorCharacters: 12_000,
  maximumServerInstructionCharacters: 2_000,
  maximumInitialContextCharacters: 4_000,
  maximumReusedContextCharacters: 800,
  maximumMetaCharacters: 8_000,
});

export const UNIVERSAL_BROKER_INSTRUCTIONS = [
  "DevSpace Universal Broker exposes a fixed set of generic tools.",
  "Resolve named machines and environments with target instead of guessing identifiers.",
  "Use context only for project instructions, Git state, and a default target/path; it is not an authority boundary.",
  "Use fs for local or remote files, exec plus process for commands, mcp for arbitrary configured MCP servers, artifact for file exchange, and gui only for operating-system UI that has no better protocol.",
  "DevSpace never installs, injects, or reuses privilege-elevation credentials. Commands and file operations run only as the configured target user; any operating-system authorization must be approved directly by the user outside DevSpace.",
  "Do not retry an identical failed operation. Provider mutations and commands whose dispatch state is unknown must not be replayed automatically.",
  "Large results are returned through resource handles rather than repeated in tool text.",
].join(" ");

const cursorSchema = z.string().min(1).optional();
const limitSchema = z.number().int().min(1).max(10_000).optional();
const genericRecordSchema = z.record(z.string(), z.unknown());

export const universalResultOutputSchema: z.ZodRawShape = {
  ok: z.boolean(),
  operationId: z.string(),
  data: genericRecordSchema.optional(),
  error: z
    .object({
      code: z.enum(UNIVERSAL_ERROR_CODES),
      message: z.string(),
      retryable: z.boolean(),
      evidence: genericRecordSchema.optional(),
      suggestions: z.array(genericRecordSchema).optional(),
    })
    .optional(),
};

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
  title: "Resolve target",
  description:
    "List, resolve, or probe local and remote execution targets. Use this before guessing a machine, alias, platform, or capability.",
  inputSchema: {
    operation: z.enum(UNIVERSAL_TOOL_OPERATIONS.target),
    selector: z.string().min(1).optional(),
    targetId: z.string().min(1).optional(),
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
  title: "Manage context",
  description:
    "Open, search, diff, or close a project context. Context supplies instructions and defaults; paths must already exist and context is not an access boundary.",
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

const fsContract = {
  title: "Operate on files",
  description:
    "Perform generic local or remote filesystem operations, including reads, atomic writes, patches, transfers, and explicit deletion.",
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
  title: "Execute command",
  description:
    "Run a command locally or over SSH as the configured target user, with PTY support and automatic conversion to a managed background process. DevSpace always uses that account and never accepts system credentials.",
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
  },
  annotations: {
    readOnlyHint: false,
    destructiveHint: true,
    idempotentHint: false,
    openWorldHint: true,
  },
} satisfies UniversalToolContract;

const processContract = {
  title: "Manage process",
  description:
    "Poll, write to, resize, signal, wait for, list, or forget managed local and remote processes returned by exec.",
  inputSchema: {
    operation: z.enum(UNIVERSAL_TOOL_OPERATIONS.process),
    processId: z.string().min(1).optional(),
    chars: z.string().optional(),
    signal: z.string().min(1).optional(),
    columns: z.number().int().min(1).max(1_000).optional(),
    rows: z.number().int().min(1).max(1_000).optional(),
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
  title: "Use MCP route",
  description:
    "Discover or invoke arbitrary configured MCP routes over local stdio, SSH stdio, or Streamable HTTP without service-specific DevSpace tools.",
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
  title: "Transfer artifact",
  description:
    "Receive, publish, or copy files between the MCP host, local storage, and remote targets using streaming transfer and hashes.",
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
  title: "Operate GUI",
  description:
    "Observe or act through an optional generic operating-system GUI session. Prefer filesystem, exec, or application MCP protocols when available.",
  inputSchema: {
    operation: z.enum(UNIVERSAL_TOOL_OPERATIONS.gui),
    target: z.string().min(1).optional(),
    sessionId: z.string().min(1).optional(),
    generation: z.string().min(1).optional(),
    action: genericRecordSchema.optional(),
    waitMs: z.number().int().min(0).max(30_000).optional(),
    maxCharacters: z.number().int().min(1).max(100_000).optional(),
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
