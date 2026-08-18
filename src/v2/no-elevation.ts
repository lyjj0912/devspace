import { spawnSync } from "node:child_process";
import { existsSync, readFileSync } from "node:fs";
import type { TargetPlatform } from "./targets.js";
import { UniversalBrokerError } from "./errors.js";

export type InternalExecutionPolicy = "filesystem" | "gui" | "artifact" | "system";

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

const MACOS_USER_COMMAND_DENIED_EXECUTABLES = [
  "/usr/bin/osascript",
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

export function wrapLocalUserOnlyExecution(
  platform: TargetPlatform,
  spec: ExecutableSpec,
  internalPolicy?: InternalExecutionPolicy,
): ExecutableSpec {
  if (platform === "macos") {
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
  quotedCommand: string,
  internalPolicy?: InternalExecutionPolicy,
): string {
  if (platform === "macos") {
    const profile = shellQuote(macosUserOnlyProfile(internalPolicy));
    return `/usr/bin/sandbox-exec -p ${profile} ${shell} -lc ${quotedCommand}`;
  }
  if (platform === "linux") {
    return `setpriv --no-new-privs -- ${shell} -lc ${quotedCommand}`;
  }
  throw new UniversalBrokerError(
    "ELEVATION_BLOCKED",
    `Strict POSIX user-account enforcement is unavailable for platform ${platform}.`,
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
  const denied = [
    ...MACOS_ALWAYS_DENIED_EXECUTABLES,
    ...(internalPolicy === "gui" ? [] : MACOS_USER_COMMAND_DENIED_EXECUTABLES),
  ];
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
