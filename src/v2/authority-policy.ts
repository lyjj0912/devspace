import { createHash } from "node:crypto";
import type { AuthorityActionDescriptor } from "./authority.js";
import type { AuthorityRiskClass, UniversalToolName } from "./contracts.js";
import type { UniversalFilesystemInput } from "./filesystem.js";
import type { UniversalMcpInput } from "./mcp-proxy.js";
import type { UniversalGuiInput } from "./gui.js";
import type { UniversalArtifactInput } from "./artifact-service.js";
import type { ExecuteCommandInput, ProcessOperationInput } from "./execution.js";
import { UniversalBrokerError } from "./errors.js";

const READ_ONLY_COMMANDS = new Set([
  "cat", "cut", "df", "diff", "du", "echo", "false", "file", "git", "grep",
  "head", "id", "jq", "ls", "md5", "md5sum", "printf", "pwd", "readlink", "rg",
  "sha1sum", "sha256sum", "shasum", "sleep", "stat", "tail", "test", "tree", "true",
  "uname", "uniq", "wc", "which", "whoami",
]);

const HIGH_RISK_COMMAND_PATTERNS = [
  /(?:^|[;&|()\s])rm(?:\s|$)/u,
  /(?:^|[;&|()\s])(?:rmdir|unlink|shred|truncate|mkfs(?:\.[A-Za-z0-9_-]+)?)(?:\s|$)/u,
  /\bfind\b[^\n]*(?:-delete|-exec(?:dir)?|-ok(?:dir)?|-fprint(?:f)?|-fls)\b/iu,
  /\b(?:dd|diskutil)\b[^\n]*(?:of=|erase|partition|zeroDisk|secureErase)/iu,
  /\bgit\s+(?:push|reset\s+--hard|clean\s+-|branch\s+(?:-d|-D|--delete|--force)|tag\s+(?:-d|--delete|--force)|stash\s+(?:drop|clear)|reflog\s+expire|gc\b[^\n]*--prune|rebase|filter-(?:branch|repo)|checkout\s+(?:-f|--)|restore\s+(?:--staged\s+)?(?:--worktree\s+)?)/iu,
  /\bpm2\s+(?:start|restart|reload|stop|delete|kill|save|startup|unstartup)\b/iu,
  /\b(?:launchctl|systemctl|service)\s+(?:boot|bootstrap|bootout|enable|disable|start|stop|restart|reload|daemon-reload)\b/iu,
  /\b(?:shutdown|reboot|halt|poweroff)\b/iu,
  /\b(?:npm|pnpm|yarn)\s+publish\b/iu,
  /\b(?:kubectl|helm)\s+(?:apply|delete|replace|upgrade|uninstall)\b/iu,
  /\bdocker\s+(?:rm|rmi|system\s+prune|volume\s+rm|network\s+rm)\b/iu,
  /\bcurl\b[^\n]*(?:(?:-X|--request)\s*(?:POST|PUT|PATCH|DELETE)\b|(?:-d|--data(?:-raw|-binary|-urlencode)?|--upload-file|-T)\s)/iu,
  /\b(?:gh|glab)\s+(?:release|pr\s+merge|repo\s+delete)\b/iu,
];

const OPAQUE_EXECUTION_PATTERNS = [
  /(?:^|[;&|()\s/])(?:bash|zsh|sh|dash|fish|ksh)(?:\s|$)/iu,
  /(?:^|[;&|()\s/])(?:python(?:3(?:\.\d+)?)?|ruby|perl|php|node|deno|bun|lua|osascript)(?:\s|$)/iu,
  /\bpowershell(?:\.exe)?(?:\s|$)/iu,
  /\bcmd(?:\.exe)?\s+\/c\b/iu,
  /\b(?:base64|openssl)\b[^\n]*(?:-d|--decode)\b/iu,
];

const ELEVATION_PATTERNS = [
  /(?:^|[;&|()\s/])sudo(?:\s|$)/iu,
  /(?:^|[;&|()\s/])doas(?:\s|$)/iu,
  /(?:^|[;&|()\s/])pkexec(?:\s|$)/iu,
  /(?:^|[;&|()\s/])(?:su|runuser)(?:\s|$)/iu,
  /\brunas(?:\.exe)?(?:\s|$)/iu,
  /\bstart-process\b[^\n]*\b-verb\s+runas\b/iu,
  /\bwith\s+administrator\s+privileges\b/iu,
  /\bosascript\b[^\n]*(?:administrator|privileges)/iu,
  /\bsecurity\s+authorizationdb\s+(?:write|remove)\b/iu,
  /\bschtasks\b[^\n]*\/rl\s+highest\b/iu,
  /\bpowershell(?:\.exe)?\b[^\n]*(?:-encodedcommand|-enc\b)/iu,
];

export function authorityActionFromToolCall(
  tool: UniversalToolName,
  argumentsValue: Record<string, unknown>,
): AuthorityActionDescriptor {
  const input = withoutAuthorityId(argumentsValue);
  switch (tool) {
    case "target":
      return {
        tool,
        operation: requiredOperation(input, "target"),
        resource: optionalText(input.targetId) ?? optionalText(input.selector),
      };
    case "context":
      return contextAction(requiredOperation(input, "context"), {
        target: optionalText(input.target),
        path: optionalText(input.path),
        contextId: optionalText(input.contextId),
        mode: optionalText(input.mode),
        baseRef: optionalText(input.baseRef),
      });
    case "fs": {
      const fsInput = input as unknown as UniversalFilesystemInput;
      return filesystemAction(
        fsInput,
        optionalText(input.target) ?? (optionalText(input.contextId) ? `context:${String(input.contextId)}` : "local"),
      );
    }
    case "exec": {
      const execInput = input as unknown as ExecuteCommandInput;
      if (!optionalText(input.command)) {
        throw new UniversalBrokerError("PRECONDITION_FAILED", "Authority exec action requires arguments.command.");
      }
      return execAction(
        execInput,
        optionalText(input.target) ?? (optionalText(input.contextId) ? `context:${String(input.contextId)}` : "local"),
        optionalText(input.cwd) ?? optionalText(input.contextId) ?? "default",
      );
    }
    case "process":
      return processAction(input as unknown as ProcessOperationInput);
    case "mcp":
      return mcpAction(input as unknown as UniversalMcpInput);
    case "artifact":
      return artifactAction(input as unknown as UniversalArtifactInput);
    case "gui":
      return guiAction(input as unknown as UniversalGuiInput);
  }
}

export function minimumAuthorityRisk(action: AuthorityActionDescriptor): AuthorityRiskClass {
  switch (action.tool) {
    case "target":
      return "R0";
    case "context":
      return contextRisk(action.operation, action.parameters);
    case "fs":
      return filesystemRisk(action.operation, action.target, action.parameters);
    case "exec": {
      const risk = commandRisk(String(action.parameters?.command ?? ""), action.target);
      return risk === "R0"
        && (action.parameters?.mode === "background" || action.parameters?.tty === true)
        ? "R1"
        : risk;
    }
    case "process":
      return processRisk(action.operation);
    case "mcp":
      return mcpRisk(action.operation, action.parameters);
    case "artifact":
      return artifactRisk(action.operation, action.parameters);
    case "gui":
      return action.operation === "act" ? "R3" : "R0";
  }
}

export function assertNoElevationCommand(command: string): void {
  const normalized = command.normalize("NFKC").replace(/["'`\\]/gu, "").replace(/\s+/gu, " ");
  const match = ELEVATION_PATTERNS.find((pattern) => pattern.test(normalized));
  if (match) {
    throw new UniversalBrokerError(
      "ELEVATION_BLOCKED",
      "DevSpace user-account-only enforcement blocked a privilege-elevation command. Run higher-authority work manually outside DevSpace.",
      { evidence: { commandSha256: sha256(command), policy: "user-account-only" } },
    );
  }
}

export function commandRisk(command: string, target?: string): AuthorityRiskClass {
  assertNoElevationCommand(command);
  if (HIGH_RISK_COMMAND_PATTERNS.some((pattern) => pattern.test(command))) return "R3";
  if (isReadOnlyCommand(command)) return "R0";
  if (OPAQUE_EXECUTION_PATTERNS.some((pattern) => pattern.test(command))) return "R3";
  if (isBoundedLocalDevelopmentCommand(command) && (!target || target === "local")) return "R1";
  return "R2";
}

export function contextAction(
  operation: string,
  input: {
    target?: string;
    path?: string;
    contextId?: string;
    mode?: string;
    baseRef?: string;
  },
): AuthorityActionDescriptor {
  return {
    tool: "context",
    operation,
    ...(input.target ? { target: input.target } : {}),
    resource: input.contextId ?? input.path,
    parameters: compact({ mode: input.mode, baseRef: input.baseRef }),
  };
}

export function filesystemAction(
  input: UniversalFilesystemInput,
  targetId: string,
): AuthorityActionDescriptor {
  return {
    tool: "fs",
    operation: input.operation,
    target: targetId,
    resource: input.path ?? input.destination,
    parameters: compact({
      contextId: input.contextId,
      path: input.path,
      destination: input.destination,
      overwrite: input.overwrite,
      expectedSha256: input.expectedSha256,
      disposition: input.disposition,
      recursive: input.recursive,
      contentSha256: input.content === undefined ? undefined : sha256(input.content),
      patchSha256: input.patch === undefined ? undefined : sha256(input.patch),
    }),
  };
}

export function execAction(input: ExecuteCommandInput, targetId: string, cwd: string): AuthorityActionDescriptor {
  return {
    tool: "exec",
    operation: "run",
    target: targetId,
    resource: cwd,
    parameters: compact({
      contextId: input.contextId,
      command: input.command,
      tty: input.tty === true,
      mode: input.mode ?? "auto",
      envProfile: input.envProfile,
    }),
  };
}

export function processAction(input: ProcessOperationInput): AuthorityActionDescriptor {
  return {
    tool: "process",
    operation: input.operation,
    resource: input.processId,
    parameters: compact({
      signal: input.signal,
      columns: input.columns,
      rows: input.rows,
      transactionId: input.transactionId,
      reason: input.reason,
      delayMs: input.delayMs,
      charsSha256: input.chars === undefined ? undefined : sha256(input.chars),
    }),
  };
}

export function mcpAction(input: UniversalMcpInput, routeId?: string): AuthorityActionDescriptor {
  return {
    tool: "mcp",
    operation: input.operation,
    resource: routeId ?? input.route,
    parameters: compact({
      name: input.name,
      arguments: input.arguments,
      uri: input.uri,
    }),
  };
}

export function artifactAction(input: UniversalArtifactInput): AuthorityActionDescriptor {
  const source = artifactEndpointDescriptor(input.source);
  const destination = artifactEndpointDescriptor(input.destination);
  return {
    tool: "artifact",
    operation: input.operation,
    resource: stableJson({ source, destination }),
    parameters: compact({
      overwrite: input.overwrite,
      maxBytes: input.maxBytes,
      ttlSeconds: input.ttlSeconds,
    }),
  };
}

export function guiAction(input: UniversalGuiInput, targetId?: string): AuthorityActionDescriptor {
  return {
    tool: "gui",
    operation: input.operation,
    target: targetId ?? input.target,
    resource: input.sessionId,
    parameters: compact({ generation: input.generation, action: input.action }),
  };
}

export function filesystemRisk(
  operation: string,
  target?: string,
  parameters?: Record<string, unknown>,
): AuthorityRiskClass {
  if (["stat", "list", "read", "search", "hash"].includes(operation)) return "R0";
  if (operation === "remove" && parameters?.disposition === "permanent") return "R3";
  if (operation === "remove") return "R2";
  return target && target !== "local" ? "R2" : "R1";
}

export function processRisk(operation: string): AuthorityRiskClass {
  if (["poll", "wait", "list", "restart_status"].includes(operation)) return "R0";
  if (operation === "restart_broker") return "R3";
  if (operation === "signal") return "R2";
  return "R1";
}

export function mcpRisk(
  operation: string,
  parameters?: Record<string, unknown>,
): AuthorityRiskClass {
  if (["routes", "search_tools", "describe_tool", "list_resources", "read_resource", "list_prompts", "get_prompt"].includes(operation)) {
    return "R0";
  }
  if (operation === "close") return "R1";
  if (operation === "invoke") {
    if (parameters?.destructive === true) return "R3";
    if (parameters?.readOnly === true) return "R0";
    // Missing, contradictory, or mutation annotations fail conservatively.
    return "R2";
  }
  return "R2";
}

export function artifactRisk(
  operation: string,
  parameters?: Record<string, unknown>,
): AuthorityRiskClass {
  if (operation === "publish") return "R2";
  if (parameters?.remote === true) return "R2";
  return "R1";
}

function contextRisk(operation: string, parameters?: Record<string, unknown>): AuthorityRiskClass {
  if (["authority_preview", "authorize", "authority_status", "invalidate_authority", "release_authority", "search", "diff"].includes(operation)) return "R0";
  if (operation === "open" && parameters?.mode !== "worktree") return "R0";
  return "R1";
}

function isBoundedLocalDevelopmentCommand(command: string): boolean {
  const trimmed = command.trim();
  if (!trimmed || /[|&<>;`]|\$\(/u.test(trimmed)) return false;
  return [
    /^(?:npm|pnpm|yarn|bun)\s+(?:ci|install|test|run\s+[A-Za-z0-9:._-]+)(?:\s|$)/u,
    /^(?:npx\s+)?(?:tsc|tsx|vite|vitest|jest|eslint|prettier)(?:\s|$)/u,
    /^(?:make|cmake|ninja)(?:\s|$)/u,
    /^(?:mvnw?|gradlew?|gradle)(?:\s|$)/u,
    /^(?:cargo|go|swift)\s+(?:build|test|check|vet)(?:\s|$)/u,
    /^xcodebuild(?:\s|$)/u,
  ].some((pattern) => pattern.test(trimmed));
}

function isReadOnlyCommand(command: string): boolean {
  const trimmed = command.trim();
  if (!trimmed || /[|&<>]|\btee\b|\b(?:touch|mkdir|cp|mv|install|chmod|chown|ln)\b/iu.test(trimmed)) return false;
  if (/\$\(|`|<<|\beval\b|\bsource\b|(?:^|\s)\.(?:\s)/u.test(trimmed)) return false;
  const segments = trimmed.split(/(?:&&|\|\||;|\n)/u).map((segment) => segment.trim()).filter(Boolean);
  if (segments.length === 0) return false;
  return segments.every((segment) => {
    const withoutAssignments = segment.replace(/^(?:[A-Za-z_][A-Za-z0-9_]*=[^\s]+\s+)*/u, "");
    const first = withoutAssignments.match(/^\(?\s*(?:command\s+)?(?:\/[^\s]+\/)?([A-Za-z0-9_.+-]+)/u)?.[1]?.toLowerCase();
    if (!first || !READ_ONLY_COMMANDS.has(first)) return false;
    if (first === "git") {
      return /^\(?\s*(?:command\s+)?(?:\/[^\s]+\/)?git\s+(?:status|diff|log|show|rev-parse|ls-files|ls-tree|remote\s+-v|branch(?:\s+--show-current)?|tag\s+-l|describe)\b/iu.test(withoutAssignments);
    }
    if (first === "find" && /\s-(?:delete|exec|execdir|ok|okdir)\b/iu.test(withoutAssignments)) return false;
    if (first === "sed" && /\s-i(?:\s|$|['"])/u.test(withoutAssignments)) return false;
    return true;
  });
}

function artifactEndpointDescriptor(
  value: Record<string, unknown> | undefined,
): Record<string, unknown> | undefined {
  if (!value) return undefined;
  const native = value.file && typeof value.file === "object"
    ? value.file as Record<string, unknown>
    : value;
  return compact({
    target: optionalText(value.target),
    contextId: optionalText(value.contextId),
    path: optionalText(value.path),
    name: optionalText(value.name) ?? optionalText(native.name),
    mimeType: optionalText(value.mimeType) ?? optionalText(native.mimeType) ?? optionalText(native.type),
    size: typeof value.size === "number" ? value.size : typeof native.size === "number" ? native.size : undefined,
    sha256: optionalText(value.sha256),
    expectedSha256: optionalText(value.expectedSha256),
    destinationExpectedSha256: optionalText(value.destinationExpectedSha256),
    nativeDescriptorSha256: sha256(stableJson(native)),
  });
}

function withoutAuthorityId(value: Record<string, unknown>): Record<string, unknown> {
  return Object.fromEntries(Object.entries(value).filter(([key, child]) => key !== "authorityId" && child !== undefined));
}

function requiredOperation(value: Record<string, unknown>, tool: string): string {
  const operation = optionalText(value.operation);
  if (!operation) {
    throw new UniversalBrokerError("PRECONDITION_FAILED", `Authority ${tool} action requires arguments.operation.`);
  }
  return operation;
}

function optionalText(value: unknown): string | undefined {
  return typeof value === "string" && value.trim() ? value.trim() : undefined;
}

function compact(value: Record<string, unknown>): Record<string, unknown> | undefined {
  const entries = Object.entries(value).filter(([, child]) => child !== undefined);
  return entries.length > 0 ? Object.fromEntries(entries) : undefined;
}

function stableJson(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(stableJson).join(",")}]`;
  if (value && typeof value === "object") {
    const record = value as Record<string, unknown>;
    return `{${Object.keys(record).sort().map((key) => `${JSON.stringify(key)}:${stableJson(record[key])}`).join(",")}}`;
  }
  return JSON.stringify(value) ?? "null";
}

function sha256(value: string): string {
  return createHash("sha256").update(value).digest("hex");
}
