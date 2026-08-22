import { createHash } from "node:crypto";
import { spawnSync } from "node:child_process";
import { existsSync, lstatSync, readFileSync, realpathSync } from "node:fs";
import type { TargetPlatform } from "./targets.js";
import { UniversalBrokerError } from "./errors.js";

export interface GuiInternalExecutionPolicy {
  kind: "gui";
  scriptPath: string;
  scriptSha256: string;
}

export interface GuiAgentInternalExecutionPolicy {
  kind: "gui-agent";
  executablePath: string;
  executableSha256: string;
}

export type InternalExecutionPolicy =
  | "filesystem"
  | "artifact"
  | "mcp"
  | "system"
  | GuiInternalExecutionPolicy
  | GuiAgentInternalExecutionPolicy;

export interface ExecutableSpec {
  executable: string;
  args: string[];
}

const MACOS_ALWAYS_DENIED_EXECUTABLES = [
  "/usr/bin/sudo",
  "/bin/su",
  "/usr/bin/login",
  "/usr/bin/passwd",
  "/usr/bin/chfn",
  "/usr/bin/chsh",
  "/usr/bin/crontab",
  "/usr/bin/at",
  "/usr/sbin/installer",
  "/usr/libexec/security_authtrampoline",
];

export function assertServiceAccountBoundary(): void {
  const uid = process.getuid?.();
  const euid = process.geteuid?.();
  if (uid === 0 || euid === 0) {
    throw new UniversalBrokerError(
      "ELEVATION_BLOCKED",
      "DevSpace refuses to run as root or another system account.",
      { evidence: { uid, euid, policy: "user-account-only" } },
    );
  }
  if (uid !== undefined && euid !== undefined && uid !== euid) {
    throw new UniversalBrokerError(
      "ELEVATION_BLOCKED",
      "DevSpace refuses a process whose real and effective user identities differ.",
      { evidence: { uid, euid, policy: "user-account-only" } },
    );
  }
  if (process.platform === "linux") {
    let status: string;
    try {
      status = readFileSync("/proc/self/status", "utf8");
    } catch (error) {
      throw new UniversalBrokerError(
        "ELEVATION_BLOCKED",
        "DevSpace could not verify Linux process capabilities.",
        { evidence: { policy: "user-account-only", error: error instanceof Error ? error.message : String(error) } },
      );
    }
    if (!linuxCapabilitiesAreOrdinary(status)) {
      throw new UniversalBrokerError(
        "ELEVATION_BLOCKED",
        "DevSpace refuses a Linux service process with effective, permitted, or ambient capabilities.",
        { evidence: { policy: "user-account-only" } },
      );
    }
  }
  if (process.platform === "win32") {
    const result = spawnSync("whoami.exe", ["/groups", "/fo", "csv", "/nh"], {
      encoding: "utf8",
      timeout: 5_000,
      windowsHide: true,
    });
    if (result.error || result.status !== 0) {
      throw new UniversalBrokerError(
        "ELEVATION_BLOCKED",
        "DevSpace could not verify that the Windows service token is non-elevated.",
        { evidence: { policy: "user-account-only", status: result.status } },
      );
    }
    if (windowsIntegrityIsElevated(result.stdout)) {
      throw new UniversalBrokerError(
        "ELEVATION_BLOCKED",
        "DevSpace refuses to run with a high-integrity or system Windows token.",
        { evidence: { policy: "user-account-only" } },
      );
    }
  }
}

export function assertInternalExecutionCommand(
  policy: InternalExecutionPolicy | undefined,
  command: string,
): void {
  if (!policy || typeof policy === "string") return;
  internalExecutionSpec(policy, command);
}

export function internalExecutionSpec(
  policy: InternalExecutionPolicy | undefined,
  command: string,
  options: { verifyLocalScript?: boolean } = {},
): ExecutableSpec | undefined {
  if (!policy || typeof policy === "string") return undefined;
  if (policy.kind === "gui-agent") {
    if (!policy.executablePath.startsWith("/") || /[\0\r\n]/u.test(policy.executablePath)) {
      throw internalExecutionViolation("GUI agent path is not an absolute single-line path");
    }
    if (!/^[a-f0-9]{64}$/u.test(policy.executableSha256)) {
      throw internalExecutionViolation("GUI agent executable hash is invalid");
    }
    if (options.verifyLocalScript) verifyLocalGuiAgent(policy);
    const words = restrictedPosixWords(command);
    if (words[0] !== policy.executablePath) {
      throw internalExecutionViolation("GUI execution does not match the pinned native agent path");
    }
    validateGuiAgentWords(words);
    return { executable: words[0], args: words.slice(1) };
  }
  if (policy.kind !== "gui") {
    throw internalExecutionViolation("unsupported internal execution policy");
  }
  if (!policy.scriptPath.startsWith("/") || /[\0\r\n]/u.test(policy.scriptPath)) {
    throw internalExecutionViolation("GUI node path is not an absolute single-line path");
  }
  if (!/^[a-f0-9]{64}$/u.test(policy.scriptSha256)) {
    throw internalExecutionViolation("GUI node source hash is invalid");
  }
  if (options.verifyLocalScript) verifyLocalGuiScript(policy);
  const words = restrictedPosixWords(command);
  if (words[0] !== "/usr/bin/osascript") {
    throw internalExecutionViolation("GUI execution must invoke /usr/bin/osascript exactly");
  }
  if (words[1] !== policy.scriptPath) {
    throw internalExecutionViolation("GUI execution does not match the installed GUI node path");
  }
  const operation = words[2];
  if (operation === "capabilities") {
    if (words.length !== 3) throw internalExecutionViolation("GUI capabilities argument shape is invalid");
  } else if (operation === "observe") {
    if (words.length !== 4 || !boundedDecimal(words[3], 1, 1_000)) {
      throw internalExecutionViolation("GUI observe argument shape is invalid");
    }
  } else if (operation === "act") {
    validateGuiActWords(words);
  } else {
    throw internalExecutionViolation("GUI node operation is unsupported");
  }
  return { executable: words[0], args: words.slice(1) };
}

export function wrapLocalUserOnlyExecution(
  platform: TargetPlatform,
  spec: ExecutableSpec,
  internalPolicy?: InternalExecutionPolicy,
): ExecutableSpec {
  if (platform === "macos") {
    if (typeof internalPolicy === "object" && internalPolicy.kind === "gui") {
      throw internalExecutionViolation(
        "exact GUI execution must use internalExecutionSpec instead of the generic wrapper",
      );
    }
    if (!existsSync("/usr/bin/sandbox-exec")) {
      throw new UniversalBrokerError(
        "ELEVATION_BLOCKED",
        "Strict user-account enforcement requires /usr/bin/sandbox-exec on macOS.",
      );
    }
    return {
      executable: "/usr/bin/sandbox-exec",
      args: [
        "-p",
        macosUserOnlyProfile(internalPolicy),
        spec.executable,
        ...spec.args,
      ],
    };
  }
  if (platform === "linux") {
    const setpriv = ["/usr/bin/setpriv", "/bin/setpriv"].find(existsSync);
    if (!setpriv) {
      throw new UniversalBrokerError(
        "ELEVATION_BLOCKED",
        "Strict user-account enforcement requires setpriv --no-new-privs on Linux.",
      );
    }
    return {
      executable: setpriv,
      args: ["--no-new-privs", "--", spec.executable, ...spec.args],
    };
  }
  if (platform === "windows") return spec;
  throw new UniversalBrokerError(
    "ELEVATION_BLOCKED",
    `Strict user-account enforcement is unavailable for platform ${platform}.`,
  );
}

export function posixRemoteUserOnlyRunner(
  platform: TargetPlatform,
  shell: string,
  command: string,
  internalPolicy?: InternalExecutionPolicy,
): string {
  const pinnedShell = pinnedPosixShell(shell);
  const exact = internalExecutionSpec(internalPolicy, command);
  if (exact) {
    const policy = internalPolicy as GuiInternalExecutionPolicy | GuiAgentInternalExecutionPolicy;
    const exactPath = policy.kind === "gui" ? policy.scriptPath : policy.executablePath;
    const exactSha256 = policy.kind === "gui" ? policy.scriptSha256 : policy.executableSha256;
    const quotedPath = shellQuote(exactPath);
    const quotedHash = shellQuote(exactSha256);
    const exactCommand = [exact.executable, ...exact.args].map(shellQuote).join(" ");
    const exactScript = [
      `[ -f ${quotedPath} ] && [ ! -L ${quotedPath} ] || exit 78`,
      `[ "$(/bin/realpath -- ${quotedPath})" = ${quotedPath} ] || exit 78`,
      `[ "$(/usr/bin/stat -f '%u' -- ${quotedPath})" = "$(/usr/bin/id -u)" ] || exit 78`,
      `mode=$(/usr/bin/stat -f '%OLp' -- ${quotedPath})`,
      `[ "$((8#$mode & 8#22))" -eq 0 ] || exit 78`,
      `actual=$(/usr/bin/shasum -a 256 -- ${quotedPath} | /usr/bin/awk '{print $1}')`,
      `[ "$actual" = ${quotedHash} ] || exit 78`,
      exactCommand,
    ].join("; ");
    return `(${exactScript})`;
  }
  const quotedCommand = shellQuote(command);
  if (platform === "macos") {
    const profile = shellQuote(macosUserOnlyProfile(internalPolicy));
    return `/usr/bin/sandbox-exec -p ${profile} ${pinnedShell} -lc ${quotedCommand}`;
  }
  if (platform === "linux") {
    const invocation = `${pinnedShell} -lc ${quotedCommand}`;
    return [
      "if [ -x /usr/bin/setpriv ] && [ ! -L /usr/bin/setpriv ]; then",
      `/usr/bin/setpriv --no-new-privs -- ${invocation};`,
      "elif [ -x /bin/setpriv ] && [ ! -L /bin/setpriv ]; then",
      `/bin/setpriv --no-new-privs -- ${invocation};`,
      "else exit 78; fi",
    ].join(" ");
  }
  throw new UniversalBrokerError(
    "ELEVATION_BLOCKED",
    `Strict POSIX user-account enforcement is unavailable for platform ${platform}.`,
  );
}

function pinnedPosixShell(shell: string): "/bin/sh" | "/bin/bash" | "/bin/zsh" {
  switch (shell) {
    case "sh":
    case "/bin/sh":
      return "/bin/sh";
    case "bash":
    case "/bin/bash":
      return "/bin/bash";
    case "zsh":
    case "/bin/zsh":
      return "/bin/zsh";
    default:
      throw new UniversalBrokerError(
        "ELEVATION_BLOCKED",
        "Remote POSIX execution requires a broker-pinned system shell.",
        { evidence: { shell } },
      );
  }
}

function verifyLocalGuiAgent(policy: GuiAgentInternalExecutionPolicy): void {
  let metadata: ReturnType<typeof lstatSync>;
  try {
    metadata = lstatSync(policy.executablePath);
  } catch {
    throw internalExecutionViolation("GUI agent executable is unavailable");
  }
  if (!metadata.isFile() || metadata.isSymbolicLink()) {
    throw internalExecutionViolation("GUI agent executable is not a regular file");
  }
  if (realpathSync(policy.executablePath) !== policy.executablePath) {
    throw internalExecutionViolation("GUI agent executable path is not canonical");
  }
  const uid = process.getuid?.();
  if (uid !== undefined && metadata.uid !== uid) {
    throw internalExecutionViolation("GUI agent executable is not owned by the service account");
  }
  if ((metadata.mode & 0o022) !== 0) {
    throw internalExecutionViolation("GUI agent executable is group- or world-writable");
  }
  const actualSha256 = createHash("sha256")
    .update(readFileSync(policy.executablePath))
    .digest("hex");
  if (actualSha256 !== policy.executableSha256) {
    throw internalExecutionViolation("GUI agent executable hash changed");
  }
}

function validateGuiAgentWords(words: string[]): void {
  const operation = words[1];
  if (operation === "capabilities") {
    if (words.length !== 2) throw internalExecutionViolation("GUI agent capabilities arguments are invalid");
    return;
  }
  if (operation === "request-access") {
    if (words.length !== 3 || !/^(?:accessibility|screen_capture)(?:,(?:accessibility|screen_capture))?$/u.test(words[2]!)) {
      throw internalExecutionViolation("GUI agent permission request is invalid");
    }
    if (new Set(words[2]!.split(",")).size !== words[2]!.split(",").length) {
      throw internalExecutionViolation("GUI agent permission request contains duplicates");
    }
    return;
  }
  if (operation === "observe") {
    if (
      (words.length !== 3 && words.length !== 4)
      || !boundedDecimal(words[2], 1, 1_000)
      || (words.length === 4 && !boundedDecimal(words[3], 1, 2_147_483_647))
    ) {
      throw internalExecutionViolation("GUI agent observe arguments are invalid");
    }
    return;
  }
  if (operation === "capture") {
    if (words.length !== 5 || !/^(?:jpeg|png)$/u.test(words[2]!)
        || !boundedDecimal(words[3], 1, 100)
        || !boundedDecimal(words[4], 320, 2_560)) {
      throw internalExecutionViolation("GUI agent capture arguments are invalid");
    }
    return;
  }
  if (operation === "act") {
    validateGuiAgentActWords(words);
    return;
  }
  throw internalExecutionViolation("GUI agent operation is unsupported");
}

function validateGuiAgentActWords(words: string[]): void {
  if (words.length !== 14) throw internalExecutionViolation("GUI agent act argument count is invalid");
  if (!boundedDecimal(words[2], -1, 1_000)) throw internalExecutionViolation("GUI element index is invalid");
  if (!new Set(["perform", "press", "click", "set_value", "focus", "keystroke", "key_code"]).has(words[3]!)) {
    throw internalExecutionViolation("GUI action type is invalid");
  }
  for (const index of [4, 5, 9, 10, 11, 12, 13]) {
    if (!boundedBase64(words[index])) throw internalExecutionViolation("GUI encoded argument is invalid");
  }
  if (!/^(?:(?:command|option|control|shift)(?:,(?:command|option|control|shift))*)?$/u.test(words[6]!)) {
    throw internalExecutionViolation("GUI modifier list is invalid");
  }
  if (!boundedDecimal(words[7], -1, 255)) throw internalExecutionViolation("GUI key code is invalid");
  if (!boundedDecimal(words[8], 0, 2_147_483_647)) throw internalExecutionViolation("GUI process identifier is invalid");
}

function verifyLocalGuiScript(policy: GuiInternalExecutionPolicy): void {
  let metadata: ReturnType<typeof lstatSync>;
  try {
    metadata = lstatSync(policy.scriptPath);
  } catch {
    throw internalExecutionViolation("GUI node source is unavailable");
  }
  if (!metadata.isFile() || metadata.isSymbolicLink()) {
    throw internalExecutionViolation("GUI node source is not a regular file");
  }
  if (realpathSync(policy.scriptPath) !== policy.scriptPath) {
    throw internalExecutionViolation("GUI node source path is not canonical");
  }
  const uid = process.getuid?.();
  if (uid !== undefined && metadata.uid !== uid) {
    throw internalExecutionViolation("GUI node source is not owned by the service account");
  }
  if ((metadata.mode & 0o022) !== 0) {
    throw internalExecutionViolation("GUI node source is group- or world-writable");
  }
  const actualSha256 = createHash("sha256").update(readFileSync(policy.scriptPath)).digest("hex");
  if (actualSha256 !== policy.scriptSha256) {
    throw internalExecutionViolation("GUI node source hash changed");
  }
}

function validateGuiActWords(words: string[]): void {
  if (words.length !== 15) throw internalExecutionViolation("GUI act argument count is invalid");
  if (!boundedDecimal(words[3], -1, 1_000)) {
    throw internalExecutionViolation("GUI element index is invalid");
  }
  if (!new Set(["perform", "press", "click", "set_value", "focus", "keystroke", "key_code"]).has(words[4]!)) {
    throw internalExecutionViolation("GUI action type is invalid");
  }
  for (const index of [5, 6, 10, 11, 12, 13, 14]) {
    if (!boundedBase64(words[index])) throw internalExecutionViolation("GUI encoded argument is invalid");
  }
  if (!/^(?:(?:command|option|control|shift)(?:,(?:command|option|control|shift))*)?$/u.test(words[7]!)) {
    throw internalExecutionViolation("GUI modifier list is invalid");
  }
  if (!boundedDecimal(words[8], -1, 255)) {
    throw internalExecutionViolation("GUI key code is invalid");
  }
  if (!boundedDecimal(words[9], 0, 2_147_483_647)) {
    throw internalExecutionViolation("GUI process identifier is invalid");
  }
}

function restrictedPosixWords(command: string): string[] {
  const words: string[] = [];
  let value = "";
  let active = false;
  let state: "plain" | "single" | "double" = "plain";
  for (let index = 0; index < command.length; index += 1) {
    const character = command[index]!;
    if (state === "single") {
      if (character === "'") state = "plain";
      else value += character;
      active = true;
      continue;
    }
    if (state === "double") {
      if (character === '"') state = "plain";
      else {
        if (character === "$" || character === "`" || character === "\\" || character === "\n" || character === "\r") {
          throw internalExecutionViolation("GUI command contains shell expansion");
        }
        value += character;
      }
      active = true;
      continue;
    }
    if (/\s/u.test(character)) {
      if (active) {
        words.push(value);
        value = "";
        active = false;
      }
      continue;
    }
    if (character === "'") {
      state = "single";
      active = true;
      continue;
    }
    if (character === '"') {
      state = "double";
      active = true;
      continue;
    }
    if (/[;&|<>$`(){}\\]/u.test(character)) {
      throw internalExecutionViolation("GUI command contains a shell operator or expansion");
    }
    value += character;
    active = true;
  }
  if (state !== "plain") throw internalExecutionViolation("GUI command contains an unterminated quote");
  if (active) words.push(value);
  return words;
}

function boundedBase64(value: string | undefined): boolean {
  return value !== undefined
    && value.length <= 16_384
    && /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/u.test(value);
}

function boundedDecimal(value: string | undefined, minimum: number, maximum: number): boolean {
  if (value === undefined || !/^-?\d+$/u.test(value)) return false;
  const parsed = Number(value);
  return Number.isSafeInteger(parsed) && parsed >= minimum && parsed <= maximum;
}

function internalExecutionViolation(reason: string): UniversalBrokerError {
  return new UniversalBrokerError(
    "ELEVATION_BLOCKED",
    "DevSpace blocked an invalid internal GUI execution request.",
    { evidence: { policy: "gui-node-exact", reason } },
  );
}

export function linuxCapabilitiesAreOrdinary(status: string): boolean {
  const values = new Map<string, bigint>();
  for (const line of status.split(/\r?\n/u)) {
    const match = /^(CapPrm|CapEff|CapAmb):\s*([0-9A-Fa-f]+)$/u.exec(line.trim());
    if (!match) continue;
    values.set(match[1]!, BigInt(`0x${match[2]}`));
  }
  return ["CapPrm", "CapEff", "CapAmb"].every((name) => values.get(name) === 0n);
}

export function windowsIntegrityIsElevated(groups: string): boolean {
  return /S-1-16-(12288|16384)/u.test(groups);
}

export function windowsNonElevatedPrelude(marker = "__DEVSPACE_ELEVATED_TOKEN_BLOCKED__"): string[] {
  return [
    "$groups=(& whoami.exe /groups /fo csv /nh 2>$null | Out-String)",
    `if($groups -match 'S-1-16-(12288|16384)'){[Console]::Error.WriteLine('${marker}');exit 77}`,
  ];
}

export function macosUserOnlyProfile(internalPolicy?: InternalExecutionPolicy): string {
  const denied = [...MACOS_ALWAYS_DENIED_EXECUTABLES];
  return [
    "(version 1)",
    "(allow default)",
    "(deny authorization-right-obtain)",
    "(deny process-exec (require-any (file-mode #o4000) (file-mode #o2000)))",
    `(deny process-exec ${denied.map((path) => `(literal ${JSON.stringify(path)})`).join(" ")})`,
  ].join(" ");
}

function shellQuote(value: string): string {
  return `'${value.replaceAll("'", `'"'"'`)}'`;
}
