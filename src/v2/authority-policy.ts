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
  "cat", "cut", "df", "diff", "du", "echo", "false", "file", "grep",
  "head", "id", "jq", "ls", "md5", "md5sum", "printf", "pwd", "readlink",
  "rg", "sha1sum", "sha256sum", "shasum", "sleep", "stat", "tail", "test",
  "tree", "true", "uname", "uniq", "wc", "which", "whoami",
]);

const OPAQUE_EXECUTABLES = new Set([
  "bash", "zsh", "sh", "dash", "fish", "ksh",
  "python", "python2", "python3", "ruby", "perl", "php", "node", "deno", "bun",
  "tsx", "ts-node", "ts-node-esm",
  "lua", "osascript", "powershell", "powershell.exe", "pwsh", "cmd", "cmd.exe",
]);

const DESTRUCTIVE_EXECUTABLES = new Set([
  "rm", "rmdir", "unlink", "shred", "truncate", "mkfs", "shutdown", "reboot",
  "halt", "poweroff", "kill", "pkill", "killall",
  "del", "erase", "rd", "remove-item", "ri", "clear-content", "stop-process",
  "taskkill", "format", "diskpart", "remove-computer", "restart-computer",
  "stop-computer", "unregister-scheduledtask",
]);

const ARBITRARY_EXECUTION_WRAPPERS = new Set([
  "busybox", "chronic", "gtimeout", "ionice", "mosh", "nice", "nohup",
  "parallel", "setsid", "ssh", "stdbuf", "time", "timeout", "toybox", "watch",
  "xargs",
]);

const SHELL_CONTROL_WORDS = new Set([
  "!", "{", "}", "case", "coproc", "do", "done", "elif", "else", "esac",
  "fi", "for", "function", "if", "in", "select", "then", "until", "while",
]);

const ELEVATION_EXECUTABLES = new Set([
  "doas", "pkexec", "runas", "runas.exe", "su", "sudo", "runuser",
]);

const BOUNDED_PACKAGE_SCRIPTS = new Set([
  "build", "check", "format:check", "lint", "lint:check", "test", "typecheck",
]);

const DEPLOYMENT_TASKS = new Set([
  "deploy", "publish", "push", "release", "ship", "upload",
]);

const MAX_CLASSIFIER_COMMAND_CHARACTERS = 16_384;
const MAX_CLASSIFIER_TOKENS = 256;
const MAX_CLASSIFIER_TOKEN_CHARACTERS = 4_096;
export const EXEC_RISK_CLASSIFIER_GENERATION = "exec-structural-v2";
export const PROCESS_RISK_CLASSIFIER_GENERATION = "process-structural-v1";

export interface CommandRiskContext {
  targetId?: string;
  targetTransport?: "local" | "ssh";
  targetPlatform?: string;
  shellDialect?: string;
  mode?: string;
  tty?: boolean;
  envProfile?: string;
}

export interface ExecAuthorityBinding {
  targetGeneration?: string;
  targetTransport?: "local" | "ssh";
  targetPlatform?: string;
  shellDialect?: string;
  effectiveEnvProfile?: string;
  effectiveEnvProfileGeneration?: string;
}

export interface ProcessAuthorityBinding {
  targetId?: string;
  targetGeneration?: string;
  targetTransport?: "local" | "ssh";
  tty?: boolean;
  launchRisk?: AuthorityRiskClass;
}

export interface McpAuthorityBinding {
  routeId: string;
  routeGeneration: string;
  toolName: string;
  toolContractSha256: string;
  riskPolicyGeneration: string;
  risk: AuthorityRiskClass;
}

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
    case "exec":
      return commandRisk(String(action.parameters?.command ?? ""), {
        targetId: action.target,
        targetTransport: transportValue(action.parameters?.targetTransport),
        targetPlatform: optionalText(action.parameters?.targetPlatform),
        shellDialect: optionalText(action.parameters?.shellDialect),
        mode: optionalText(action.parameters?.mode),
        tty: action.parameters?.tty === true,
        envProfile: optionalText(action.parameters?.envProfile),
      });
    case "process":
      return processRisk(action.operation, action.parameters);
    case "mcp":
      return mcpRisk(action.operation, action.parameters);
    case "artifact":
      return artifactRisk(action.operation, action.parameters);
    case "gui":
      return action.operation === "act" ? "R3" : "R0";
  }
}

export function assertNoElevationCommand(command: string): void {
  if (containsElevationCommand(command)) {
    throw new UniversalBrokerError(
      "ELEVATION_BLOCKED",
      "DevSpace user-account-only enforcement blocked a privilege-elevation command. Run higher-authority work manually outside DevSpace.",
      { evidence: { commandSha256: sha256(command), policy: "user-account-only" } },
    );
  }
}

function containsElevationCommand(command: string, depth = 0): boolean {
  if (depth > 4) return true;
  for (const nested of nestedDynamicCommands(command.normalize("NFKC"))) {
    if (containsElevationCommand(nested, depth + 1)) return true;
  }
  const parsed = parseLiteralShellCommands(command.normalize("NFKC"));
  for (const tokens of parsed.commands) {
    const located = locateExecutableToken(tokens);
    if (
      located?.kind === "unsafe"
      && located.nestedCommand
      && containsElevationCommand(located.nestedCommand, depth + 1)
    ) return true;
    const unwrapped = unwrapExecutable(tokens);
    if (!unwrapped) continue;
    const { executable, args } = unwrapped;
    if (ELEVATION_EXECUTABLES.has(executable)) return true;
    const normalizedArgs = args.join(" ").replace(/\s+/gu, " ");
    if (
      executable === "osascript"
      && /(?:administrator|privileges)/iu.test(normalizedArgs)
    ) return true;
    if (
      executable === "security"
      && /^authorizationdb\s+(?:write|remove)(?:\s|$)/iu.test(normalizedArgs)
    ) return true;
    if (
      executable === "schtasks"
      && /(?:^|\s)\/rl\s+highest(?:\s|$)/iu.test(normalizedArgs)
    ) return true;
    if (
      (executable === "start-process"
        && /(?:^|\s)-verb\s+runas(?:\s|$)/iu.test(` ${normalizedArgs}`))
      || (["powershell", "powershell.exe", "pwsh"].includes(executable)
        && /(?:^|\s)start-process\b.*(?:^|\s)-verb\s+runas(?:\s|$)/iu.test(` ${normalizedArgs}`))
    ) return true;
    if (
      ["powershell", "powershell.exe", "pwsh"].includes(executable)
      && args.some((arg) => /^-(?:encodedcommand|enc)(?:[:=].*)?$/iu.test(arg))
    ) return true;
    const nested = nestedShellCommand(executable, args);
    if (nested && containsElevationCommand(nested, depth + 1)) return true;
  }
  return false;
}

function nestedDynamicCommands(command: string): string[] {
  const nested: string[] = [];
  let quote: "single" | "double" | undefined;
  for (let index = 0; index < command.length; index += 1) {
    const character = command[index]!;
    if (character === "\\") {
      index += 1;
      continue;
    }
    if (quote === "single") {
      if (character === "'") quote = undefined;
      continue;
    }
    if (character === "'") {
      quote = "single";
      continue;
    }
    if (character === '"') {
      quote = quote === "double" ? undefined : "double";
      continue;
    }
    if (character === "`") {
      const closing = findUnescapedBacktick(command, index + 1);
      if (closing < 0) break;
      nested.push(command.slice(index + 1, closing));
      index = closing;
      continue;
    }
    const substitution = (character === "$" || character === "<" || character === ">")
      && command[index + 1] === "(";
    if (!substitution) continue;
    const arithmetic = character === "$" && command[index + 2] === "(";
    const contentStart = index + (arithmetic ? 3 : 2);
    const closing = findClosingParenthesis(command, contentStart, arithmetic ? 2 : 1);
    if (closing < 0) break;
    const content = command.slice(contentStart, arithmetic ? closing - 1 : closing);
    if (arithmetic) nested.push(...nestedDynamicCommands(content));
    else nested.push(content);
    index = closing;
  }
  return nested;
}

function findUnescapedBacktick(command: string, start: number): number {
  for (let index = start; index < command.length; index += 1) {
    if (command[index] === "\\") index += 1;
    else if (command[index] === "`") return index;
  }
  return -1;
}

function findClosingParenthesis(command: string, start: number, initialDepth: number): number {
  let depth = initialDepth;
  let quote: "single" | "double" | undefined;
  for (let index = start; index < command.length; index += 1) {
    const character = command[index]!;
    if (character === "\\") {
      index += 1;
      continue;
    }
    if (quote === "single") {
      if (character === "'") quote = undefined;
      continue;
    }
    if (character === "'") {
      quote = "single";
      continue;
    }
    if (character === '"') {
      quote = quote === "double" ? undefined : "double";
      continue;
    }
    if (character === "(") depth += 1;
    if (character === ")") {
      depth -= 1;
      if (depth === 0) return index;
    }
  }
  return -1;
}

function nestedShellCommand(executable: string, args: string[]): string | undefined {
  if (["bash", "dash", "fish", "ksh", "sh", "zsh"].includes(executable)) {
    for (let index = 0; index < args.length - 1; index += 1) {
      if (/^-[A-Za-z]*c[A-Za-z]*$/u.test(args[index]!)) return args[index + 1];
    }
  }
  if (["powershell", "powershell.exe", "pwsh"].includes(executable)) {
    const index = args.findIndex((arg) => /^-(?:command|c)$/iu.test(arg));
    if (index >= 0) return args[index + 1];
  }
  if (["cmd", "cmd.exe"].includes(executable)) {
    const index = args.findIndex((arg) => /^\/c$/iu.test(arg));
    if (index >= 0) return args[index + 1];
  }
  return undefined;
}

export function commandRisk(
  command: string,
  targetOrContext?: string | CommandRiskContext,
): AuthorityRiskClass {
  assertNoElevationCommand(command);
  const context = typeof targetOrContext === "string"
    ? {
        targetId: targetOrContext,
        targetTransport: targetOrContext === "local" ? "local" as const : "ssh" as const,
      }
    : targetOrContext ?? {};
  const parsed = parseLiteralShellCommands(command);
  if (parsed.unsafeDynamicExecution) return "R3";
  if (parsed.commands.some((tokens) => structuralCommandRisk(tokens) === "R3")) return "R3";
  if (!isSupportedPosixDialect(context) || !parsed.simpleLiteral) return "R2";

  let risk: AuthorityRiskClass;
  const tokens = parsed.commands[0] ?? [];
  if (isStructurallyReadOnlyCommand(tokens)) risk = "R0";
  else if (isBoundedLocalDevelopmentCommand(tokens)) {
    risk = context.targetTransport === "ssh" ? "R2" : "R1";
  } else {
    risk = "R2";
  }
  if (context.envProfile) risk = maximumRisk(risk, "R2");
  if (context.tty === true || context.mode === "background") {
    risk = maximumRisk(risk, context.targetTransport === "ssh" ? "R2" : "R1");
  }
  return risk;
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

export function execAction(
  input: ExecuteCommandInput,
  targetId: string,
  cwd: string,
  binding: ExecAuthorityBinding = {},
): AuthorityActionDescriptor {
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
      envProfile: binding.effectiveEnvProfile ?? input.envProfile,
      envProfileGeneration: binding.effectiveEnvProfileGeneration,
      classifierGeneration: EXEC_RISK_CLASSIFIER_GENERATION,
      targetGeneration: binding.targetGeneration,
      targetTransport: binding.targetTransport,
      targetPlatform: binding.targetPlatform,
      shellDialect: binding.shellDialect,
    }),
  };
}

export function processAction(
  input: ProcessOperationInput,
  binding: ProcessAuthorityBinding = {},
): AuthorityActionDescriptor {
  return {
    tool: "process",
    operation: input.operation,
    ...(binding.targetId ? { target: binding.targetId } : {}),
    resource: input.processId,
    parameters: compact({
      signal: input.signal,
      columns: input.columns,
      rows: input.rows,
      transactionId: input.transactionId,
      reason: input.reason,
      delayMs: input.delayMs,
      charsSha256: input.chars === undefined ? undefined : sha256(input.chars),
      classifierGeneration: PROCESS_RISK_CLASSIFIER_GENERATION,
      targetGeneration: binding.targetGeneration,
      targetTransport: binding.targetTransport,
      tty: binding.tty,
      launchRisk: binding.launchRisk,
    }),
  };
}

export function mcpAction(
  input: UniversalMcpInput,
  routeOrBinding?: string | McpAuthorityBinding,
): AuthorityActionDescriptor {
  const binding = typeof routeOrBinding === "object" ? routeOrBinding : undefined;
  return {
    tool: "mcp",
    operation: input.operation,
    resource: binding?.routeId
      ?? (typeof routeOrBinding === "string" ? routeOrBinding : undefined)
      ?? input.route,
    parameters: compact({
      name: input.name,
      arguments: input.arguments,
      uri: input.uri,
      routeGeneration: binding?.routeGeneration,
      toolContractSha256: binding?.toolContractSha256,
      riskPolicyGeneration: binding?.riskPolicyGeneration,
      riskDecision: binding?.risk,
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

export function processRisk(
  operation: string,
  parameters?: Record<string, unknown>,
): AuthorityRiskClass {
  if (["poll", "wait", "list", "restart_status"].includes(operation)) return "R0";
  if (["restart_broker", "forget"].includes(operation)) return "R3";
  if (operation === "signal") return "R3";
  if (operation === "write") {
    const launchRisk = authorityRiskValue(parameters?.launchRisk) ?? "R2";
    return maximumRisk("R2", launchRisk);
  }
  if (operation === "resize") {
    return parameters?.targetTransport === "local" ? "R1" : "R2";
  }
  return "R3";
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
    return authorityRiskValue(parameters?.riskDecision) ?? "R2";
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

interface ParsedShellCommands {
  commands: string[][];
  simpleLiteral: boolean;
  unsafeDynamicExecution: boolean;
}

function parseLiteralShellCommands(command: string): ParsedShellCommands {
  if (!command.trim() || command.length > MAX_CLASSIFIER_COMMAND_CHARACTERS) {
    return { commands: [], simpleLiteral: false, unsafeDynamicExecution: true };
  }
  const commands: string[][] = [];
  let words: string[] = [];
  let word = "";
  let wordStarted = false;
  let quote: "single" | "double" | undefined;
  let simpleLiteral = true;
  let unsafeDynamicExecution = false;
  let tokenCount = 0;

  const finishWord = () => {
    if (!wordStarted) return;
    tokenCount += 1;
    if (tokenCount <= MAX_CLASSIFIER_TOKENS) words.push(word);
    else {
      simpleLiteral = false;
      unsafeDynamicExecution = true;
    }
    word = "";
    wordStarted = false;
  };
  const finishCommand = () => {
    finishWord();
    if (words.length > 0) commands.push(words);
    words = [];
  };
  const append = (value: string) => {
    wordStarted = true;
    if (word.length + value.length <= MAX_CLASSIFIER_TOKEN_CHARACTERS) word += value;
    else {
      simpleLiteral = false;
      unsafeDynamicExecution = true;
    }
  };

  for (let index = 0; index < command.length; index += 1) {
    const character = command[index]!;
    if (quote === "single") {
      if (character === "'") quote = undefined;
      else append(character);
      continue;
    }
    if (quote === "double") {
      if (character === '"') quote = undefined;
      else if (character === "\\") {
        const next = command[index + 1];
        if (next === undefined || next === "\n") simpleLiteral = false;
        else {
          append(next);
          index += 1;
        }
      } else {
        if (character === "$" || character === "`") simpleLiteral = false;
        if (character === "`" || (character === "$" && command[index + 1] === "(")) {
          unsafeDynamicExecution = true;
        }
        append(character);
      }
      continue;
    }
    if (character === "'") {
      quote = "single";
      wordStarted = true;
      continue;
    }
    if (character === '"') {
      quote = "double";
      wordStarted = true;
      continue;
    }
    if (character === "\\") {
      const next = command[index + 1];
      if (next === undefined || next === "\n") simpleLiteral = false;
      else {
        append(next);
        index += 1;
      }
      continue;
    }
    if (character === "$" || character === "`") {
      simpleLiteral = false;
      if (character === "`" || command[index + 1] === "(") unsafeDynamicExecution = true;
      append(character);
      continue;
    }
    if (/\s/u.test(character)) {
      if (character === "\n" || character === "\r") {
        simpleLiteral = false;
        finishCommand();
      } else finishWord();
      continue;
    }
    if (character === "#" && !wordStarted) {
      simpleLiteral = false;
      const newline = command.indexOf("\n", index + 1);
      if (newline < 0) break;
      finishCommand();
      index = newline;
      continue;
    }
    if (";&|()".includes(character)) {
      simpleLiteral = false;
      finishCommand();
      continue;
    }
    if (character === "<" || character === ">") {
      simpleLiteral = false;
      if (command[index + 1] === "(") unsafeDynamicExecution = true;
      finishWord();
      continue;
    }
    append(character);
  }
  if (quote) simpleLiteral = false;
  finishCommand();
  return {
    commands,
    simpleLiteral: simpleLiteral && commands.length === 1 && commands[0]!.length > 0,
    unsafeDynamicExecution,
  };
}

function structuralCommandRisk(tokens: string[]): AuthorityRiskClass {
  const leadingToken = tokens.find((token) => !isEnvironmentAssignment(token));
  if (leadingToken && SHELL_CONTROL_WORDS.has(executableName(leadingToken))) return "R3";
  const executableToken = locateExecutableToken(tokens);
  if (!executableToken) return "R2";
  if (executableToken.kind === "unsafe") return "R3";
  if (isDynamicExecutableToken(executableToken.value)) return "R3";
  const unwrapped = unwrapExecutable(tokens);
  if (!unwrapped) return "R2";
  const { executable, args } = unwrapped;
  if (
    DESTRUCTIVE_EXECUTABLES.has(executable)
    || executable.startsWith("mkfs.")
    || isOpaqueExecutable(executable)
    || ARBITRARY_EXECUTION_WRAPPERS.has(executable)
    || executable === "eval"
    || executable === "source"
    || executable === "."
  ) return "R3";
  if (
    (executable === "base64" && hasAnyOption(args, ["-d", "-D", "--decode"]))
    || (executable === "openssl" && hasAnyOption(args, ["-d", "-D", "--decode"]))
  ) return "R3";
  if (executable === "find" && args.some((arg) => [
    "-delete", "-exec", "-execdir", "-ok", "-okdir", "-fprint", "-fprintf", "-fls",
  ].includes(arg))) return "R3";
  if (["awk", "gawk", "mawk", "nawk"].includes(executable) && args.some((arg) => /\bsystem\s*\(/iu.test(arg))) {
    return "R3";
  }
  if (executable === "dd" && args.some((arg) => arg.startsWith("of="))) return "R3";
  if (executable === "diskutil" && args.some((arg) => [
    "erase", "erasevolume", "erasedisk", "partitiondisk", "zerodisk", "secureerase",
  ].includes(arg.toLowerCase()))) return "R3";
  if (executable === "git") return gitStructuralRisk(args);
  if (packageRunnerHighRisk(executable, args)) return "R3";
  if (executable === "npx" && packageExecutesOpaqueInterpreter(args)) return "R3";
  if (
    ["make", "mvn", "mvnw", "gradle", "gradlew", "cargo", "go", "swift", "xcodebuild"].includes(executable)
    && args.some(isDeploymentTask)
  ) return "R3";
  if (executable === "pm2" && args[0] && [
    "start", "restart", "reload", "stop", "delete", "kill", "save", "startup", "unstartup",
  ].includes(args[0])) return "R3";
  if (["launchctl", "systemctl", "service"].includes(executable) && args.some((arg) => [
    "boot", "bootstrap", "bootout", "enable", "disable", "start", "stop", "restart",
    "reload", "daemon-reload",
  ].includes(arg.toLowerCase()))) return "R3";
  if (executable === "kubectl" && args.some((arg) => [
    "apply", "create", "delete", "edit", "patch", "replace", "rollout", "scale", "set",
  ].includes(arg.toLowerCase()))) return "R3";
  if (executable === "helm" && args.some((arg) => [
    "delete", "install", "rollback", "uninstall", "upgrade",
  ].includes(arg.toLowerCase()))) return "R3";
  if (executable === "docker" && dockerHighRisk(args)) return "R3";
  if (executable === "curl" && curlMutates(args)) return "R3";
  if (["gh", "glab"].includes(executable) && hostedGitMutates(args)) return "R3";
  return "R2";
}

function isStructurallyReadOnlyCommand(tokens: string[]): boolean {
  if (tokens.length === 0 || isEnvironmentAssignment(tokens[0]!)) return false;
  const executable = executableName(tokens[0]!);
  const args = tokens.slice(1);
  if (executable === "git") return isReadOnlyGit(args);
  if (!READ_ONLY_COMMANDS.has(executable)) return false;
  if (executable === "diff" && hasOutputOption(args)) return false;
  if (executable === "rg" && args.some((arg) => arg === "--pre" || arg.startsWith("--pre="))) return false;
  return true;
}

function isReadOnlyGit(args: string[]): boolean {
  const located = gitSubcommand(args);
  if (!located) return false;
  const { subcommand, args: subcommandArgs } = located;
  if (["status", "rev-parse", "ls-files", "ls-tree", "describe"].includes(subcommand)) return true;
  if (["diff", "log", "show"].includes(subcommand)) {
    return !hasOutputOption(subcommandArgs)
      && !hasAnyOption(subcommandArgs, ["--ext-diff", "--textconv"]);
  }
  if (subcommand === "remote") return subcommandArgs.length === 1 && subcommandArgs[0] === "-v";
  if (subcommand === "branch") {
    return subcommandArgs.length === 0
      || (subcommandArgs.length === 1 && subcommandArgs[0] === "--show-current");
  }
  if (subcommand === "tag") {
    return subcommandArgs.length === 0
      || subcommandArgs[0] === "-l"
      || subcommandArgs[0] === "--list";
  }
  return false;
}

function isBoundedLocalDevelopmentCommand(tokens: string[]): boolean {
  const unwrapped = unwrapExecutable(tokens);
  if (!unwrapped) return false;
  const { executable, args } = unwrapped;
  if (["npm", "pnpm", "yarn"].includes(executable)) {
    const script = args[0] === "run" ? args[1] : args[0];
    return Boolean(script) && BOUNDED_PACKAGE_SCRIPTS.has(script!);
  }
  if (executable === "npx") {
    const tool = executableName(args[0] ?? "");
    if (["tsc", "vitest", "jest", "eslint", "prettier"].includes(tool)) return true;
    return tool === "vite" && args[1] === "build";
  }
  if (["tsc", "vitest", "jest", "eslint", "prettier"].includes(executable)) return true;
  if (executable === "vite") return args[0] === "build";
  if (executable === "cmake") return args.some((arg) => arg === "--build" || arg.startsWith("--build="));
  if (executable === "ninja") return true;
  if (["make", "mvn", "mvnw", "gradle", "gradlew", "xcodebuild"].includes(executable)) {
    return args.some((arg) => [
      "analyze", "assemble", "build", "check", "compile", "package", "test", "verify",
    ].includes(arg.toLowerCase()));
  }
  return ["cargo", "go", "swift"].includes(executable)
    && ["build", "test", "check", "vet"].includes(args[0] ?? "");
}

function unwrapExecutable(tokens: string[]): { executable: string; args: string[] } | undefined {
  const located = locateExecutableToken(tokens);
  if (!located || located.kind === "unsafe") return undefined;
  const executable = executableName(located.value);
  return executable ? { executable, args: tokens.slice(located.index + 1) } : undefined;
}

type LocatedExecutable =
  | { kind: "executable"; value: string; index: number }
  | { kind: "unsafe"; nestedCommand?: string };

function locateExecutableToken(tokens: string[]): LocatedExecutable | undefined {
  let index = 0;
  while (index < tokens.length && isEnvironmentAssignment(tokens[index]!)) index += 1;
  while (SHELL_CONTROL_WORDS.has(executableName(tokens[index] ?? ""))) index += 1;
  let executable = executableName(tokens[index] ?? "");
  if (!executable) return undefined;
  if (executable === "command" || executable === "exec") {
    index += 1;
    while (tokens[index]?.startsWith("-")) index += 1;
    executable = executableName(tokens[index] ?? "");
  }
  if (executable === "env") {
    return locateEnvExecutableToken(tokens, index + 1);
  }
  return tokens[index]
    ? { kind: "executable", value: tokens[index]!, index }
    : undefined;
}

function locateEnvExecutableToken(tokens: string[], start: number): LocatedExecutable | undefined {
  let index = start;
  let parseOptions = true;
  while (index < tokens.length) {
    const token = tokens[index]!;
    if (isEnvironmentAssignment(token)) {
      index += 1;
      continue;
    }
    if (!parseOptions) {
      return { kind: "executable", value: token, index };
    }
    if (token === "--") {
      parseOptions = false;
      index += 1;
      continue;
    }
    if (token === "-S" || token === "--split-string") {
      return {
        kind: "unsafe",
        ...(tokens[index + 1] ? { nestedCommand: tokens[index + 1] } : {}),
      };
    }
    if (token.startsWith("-S") && token.length > 2) {
      return { kind: "unsafe", nestedCommand: token.slice(2) };
    }
    if (token.startsWith("--split-string=")) {
      return { kind: "unsafe", nestedCommand: token.slice("--split-string=".length) };
    }
    if (["-u", "--unset", "-C", "--chdir", "-a", "--argv0"].includes(token)) {
      if (tokens[index + 1] === undefined) return { kind: "unsafe" };
      index += 2;
      continue;
    }
    if (
      /^-(?:u|C|a).+/u.test(token)
      || /^--(?:unset|chdir|argv0)=/u.test(token)
    ) {
      index += 1;
      continue;
    }
    if ([
      "-i", "--ignore-environment", "-0", "--null", "-v", "--debug",
      "--help", "--version",
    ].includes(token)) {
      index += 1;
      continue;
    }
    if (token.startsWith("-")) return { kind: "unsafe" };
    return { kind: "executable", value: token, index };
  }
  return undefined;
}

function isDynamicExecutableToken(value: string): boolean {
  return value.includes("$")
    || /%[^%\s]+%/u.test(value)
    || /![^!\s]+!/u.test(value);
}

function isOpaqueExecutable(executable: string): boolean {
  if (OPAQUE_EXECUTABLES.has(executable)) return true;
  return /^(?:node|perl|php|pypy|python|pythonw|ruby|lua)\d+(?:\.\d+)*(?:\.exe)?$/u.test(executable)
    || ["iex", "invoke-expression", "start-process"].includes(executable);
}

function gitStructuralRisk(args: string[]): AuthorityRiskClass {
  const located = gitSubcommand(args);
  if (!located) return "R2";
  const subcommandArgs = located.args;
  switch (located.subcommand) {
    case "push":
    case "rebase":
    case "filter-branch":
    case "filter-repo":
      return "R3";
    case "reset":
      return hasAnyOption(subcommandArgs, ["--hard", "--merge", "--keep"]) ? "R3" : "R2";
    case "clean":
      return subcommandArgs.some((arg) => arg.startsWith("-")) ? "R3" : "R2";
    case "branch":
    case "tag":
      return hasAnyOption(subcommandArgs, ["-d", "-D", "--delete", "-f", "--force"]) ? "R3" : "R2";
    case "stash":
      return ["drop", "clear"].includes(subcommandArgs[0] ?? "") ? "R3" : "R2";
    case "reflog":
      return subcommandArgs[0] === "expire" ? "R3" : "R2";
    case "gc":
      return subcommandArgs.some((arg) => arg === "--prune" || arg.startsWith("--prune=")) ? "R3" : "R2";
    case "checkout":
      return hasAnyOption(subcommandArgs, ["-f", "--force"]) ? "R3" : "R2";
    case "restore":
      return hasAnyOption(subcommandArgs, ["--worktree"]) ? "R3" : "R2";
    case "commit":
      return hasAnyOption(subcommandArgs, ["--amend"]) ? "R3" : "R2";
    default:
      return "R2";
  }
}

function gitSubcommand(args: string[]): { subcommand: string; args: string[] } | undefined {
  let index = 0;
  while (index < args.length) {
    const value = args[index]!;
    if (value === "-C" || value === "--git-dir" || value === "--work-tree") {
      index += 2;
      continue;
    }
    if (value.startsWith("--git-dir=") || value.startsWith("--work-tree=")) {
      index += 1;
      continue;
    }
    if (value.startsWith("-")) return undefined;
    return { subcommand: value.toLowerCase(), args: args.slice(index + 1) };
  }
  return undefined;
}

function dockerHighRisk(args: string[]): boolean {
  if (args[0] === "push") return true;
  if (["rm", "rmi"].includes(args[0] ?? "")) return true;
  return (args[0] === "system" && args[1] === "prune")
    || (["volume", "network"].includes(args[0] ?? "") && args[1] === "rm");
}

function packageRunnerHighRisk(executable: string, args: string[]): boolean {
  if (!["npm", "pnpm", "yarn", "bun"].includes(executable)) return false;
  if (args[0] === "publish" || args[0] === "deploy") return true;
  const script = args[0] === "run" ? args[1] : args[0];
  return script ? isDeploymentTask(script) : false;
}

function packageExecutesOpaqueInterpreter(args: string[]): boolean {
  const candidate = executableName(args.find((arg) => arg !== "--" && !arg.startsWith("-")) ?? "");
  return OPAQUE_EXECUTABLES.has(candidate);
}

function isDeploymentTask(value: string): boolean {
  const normalized = value.toLowerCase();
  return DEPLOYMENT_TASKS.has(normalized)
    || [...DEPLOYMENT_TASKS].some((task) => normalized.startsWith(`${task}:`));
}

function curlMutates(args: string[]): boolean {
  for (let index = 0; index < args.length; index += 1) {
    const value = args[index]!;
    if (["-d", "--data", "--data-raw", "--data-binary", "--data-urlencode", "-T", "--upload-file"].includes(value)) return true;
    if (["-X", "--request"].includes(value)) {
      const method = args[index + 1]?.toUpperCase();
      if (method && ["POST", "PUT", "PATCH", "DELETE"].includes(method)) return true;
    }
    if (value.startsWith("--request=") && ["POST", "PUT", "PATCH", "DELETE"].includes(value.slice(10).toUpperCase())) return true;
    if (value.startsWith("--data=") || value.startsWith("--upload-file=")) return true;
  }
  return false;
}

function hostedGitMutates(args: string[]): boolean {
  return args[0] === "release"
    || (args[0] === "pr" && args[1] === "merge")
    || (args[0] === "repo" && args[1] === "delete");
}

function hasOutputOption(args: string[]): boolean {
  return args.some((arg) => arg === "--output" || arg.startsWith("--output="));
}

function hasAnyOption(args: string[], options: string[]): boolean {
  return args.some((arg) => options.includes(arg));
}

function executableName(value: string): string {
  return value.split(/[\\/]/u).at(-1)?.toLowerCase() ?? "";
}

function isEnvironmentAssignment(value: string): boolean {
  return /^[A-Za-z_][A-Za-z0-9_]*=/u.test(value);
}

function isSupportedPosixDialect(context: CommandRiskContext): boolean {
  if (context.targetPlatform?.toLowerCase() === "windows") return false;
  const dialect = context.shellDialect?.toLowerCase();
  return !dialect || ["auto", "sh", "bash", "zsh"].includes(dialect);
}

function maximumRisk(left: AuthorityRiskClass, right: AuthorityRiskClass): AuthorityRiskClass {
  const order: AuthorityRiskClass[] = ["R0", "R1", "R2", "R3"];
  return order[Math.max(order.indexOf(left), order.indexOf(right))]!;
}

function authorityRiskValue(value: unknown): AuthorityRiskClass | undefined {
  return value === "R0" || value === "R1" || value === "R2" || value === "R3"
    ? value
    : undefined;
}

function transportValue(value: unknown): "local" | "ssh" | undefined {
  return value === "local" || value === "ssh" ? value : undefined;
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
