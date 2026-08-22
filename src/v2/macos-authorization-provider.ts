import { createHash, randomUUID } from "node:crypto";
import {
  spawn,
  spawnSync,
  type ChildProcessWithoutNullStreams,
} from "node:child_process";
import {
  chmod,
  lstat,
  mkdir,
  readFile,
  realpath,
  rm,
  writeFile,
} from "node:fs/promises";
import { dirname, isAbsolute, join, resolve } from "node:path";
import type { UserAuthorizationDecisionState } from "./user-authorization.js";
import {
  createUserAuthorizationReceipt,
  digestUserAuthorizationValue,
  type UserAuthorizationProvider,
  type UserAuthorizationProviderCapability,
  type UserAuthorizationProviderDecision,
  type UserAuthorizationProviderLaunchRequest,
  type UserAuthorizationProviderRequest,
} from "./user-authorization.js";
import { UniversalBrokerError } from "./errors.js";

const DIGEST_PATTERN = /^sha256:[a-f0-9]{64}$/u;
const SAFE_ID_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,255}$/u;
const MAXIMUM_PROTOCOL_LINE_BYTES = 8_192;

export interface MacOsAuthorizationProviderOptions {
  agentPath: string;
  agentSha256: string;
  helperPath: string;
  helperSha256: string;
  approvalAppPath?: string;
  approvalAppExecutablePath?: string;
  approvalAppSha256?: string;
  workRoot: string;
  expectedUid?: number;
  spawnProcess?: typeof spawn;
  verifyCodeSignature?: (path: string) => void;
  now?: () => number;
}

interface ApprovalSession {
  child: ChildProcessWithoutNullStreams;
  descriptorDigest: string;
  nonce: string;
  timeout?: ReturnType<typeof setTimeout>;
}

export class MacOsAuthorizationProvider implements UserAuthorizationProvider {
  private readonly agentPath: string;
  private readonly helperPath: string;
  private readonly workRoot: string;
  private readonly agentSha256: string;
  private readonly helperSha256: string;
  private readonly approvalAppPath?: string;
  private readonly approvalAppExecutablePath?: string;
  private readonly approvalAppSha256?: string;
  private readonly expectedUid: number;
  private readonly spawnProcess: typeof spawn;
  private readonly verifyCodeSignature: (path: string) => void;
  private readonly now: () => number;
  private readonly providerGeneration: string;
  private readonly sessions = new Map<string, ApprovalSession>();
  private closed = false;

  constructor(options: MacOsAuthorizationProviderOptions) {
    this.agentPath = requireCanonicalAbsolute(options.agentPath, "agentPath");
    this.helperPath = requireCanonicalAbsolute(options.helperPath, "helperPath");
    this.workRoot = requireCanonicalAbsoluteParent(options.workRoot, "workRoot");
    this.agentSha256 = requireDigest(options.agentSha256, "agentSha256");
    this.helperSha256 = requireDigest(options.helperSha256, "helperSha256");
    const approvalValues = [
      options.approvalAppPath,
      options.approvalAppExecutablePath,
      options.approvalAppSha256,
    ];
    if (approvalValues.some((value) => value !== undefined)
        && approvalValues.some((value) => value === undefined)) {
      throw unavailable("approval app path, executable path, and SHA-256 must be configured together.");
    }
    this.approvalAppPath = options.approvalAppPath
      ? requireCanonicalAbsolute(options.approvalAppPath, "approvalAppPath")
      : undefined;
    this.approvalAppExecutablePath = options.approvalAppExecutablePath
      ? requireCanonicalAbsolute(options.approvalAppExecutablePath, "approvalAppExecutablePath")
      : undefined;
    this.approvalAppSha256 = options.approvalAppSha256
      ? requireDigest(options.approvalAppSha256, "approvalAppSha256")
      : undefined;
    this.expectedUid = options.expectedUid ?? process.getuid?.() ?? -1;
    if (!Number.isSafeInteger(this.expectedUid) || this.expectedUid < 1) {
      throw unavailable("macOS authorization provider requires a non-root user UID.");
    }
    this.spawnProcess = options.spawnProcess ?? spawn;
    this.verifyCodeSignature = options.verifyCodeSignature ?? verifyCodeSignature;
    this.now = options.now ?? Date.now;
    this.providerGeneration = digestUserAuthorizationValue({
      protocol: "devspace-macos-authorization-v1",
      agentPath: this.agentPath,
      agentSha256: this.agentSha256,
      helperPath: this.helperPath,
      helperSha256: this.helperSha256,
      approvalAppPath: this.approvalAppPath,
      approvalAppExecutablePath: this.approvalAppExecutablePath,
      approvalAppSha256: this.approvalAppSha256,
      expectedUid: this.expectedUid,
    });
  }

  async capability(input: {
    targetId: string;
    targetGeneration: string;
    platform: string;
  }): Promise<UserAuthorizationProviderCapability> {
    if (this.closed) return this.unavailableCapability("The authorization provider is closed.");
    if (input.platform !== "macos") {
      return this.unavailableCapability(`macOS Authorization Services cannot serve platform ${input.platform}.`);
    }
    try {
      await this.verifyExecutable(this.agentPath, this.agentSha256, "approval agent");
      await this.verifyExecutable(this.helperPath, this.helperSha256, "privileged helper");
      if (this.approvalAppPath && this.approvalAppExecutablePath && this.approvalAppSha256) {
        await this.verifyApplicationBundle(
          this.approvalAppPath,
          this.approvalAppExecutablePath,
          this.approvalAppSha256,
        );
      }
      await mkdir(this.workRoot, { recursive: true, mode: 0o700 });
      await chmod(this.workRoot, 0o700);
      const workState = await lstat(this.workRoot);
      if (!workState.isDirectory() || workState.isSymbolicLink() || workState.uid !== this.expectedUid) {
        throw new Error("authorization work root identity is invalid");
      }
      return {
        available: true,
        providerId: "macos-authorization-services-v1",
        providerGeneration: this.providerGeneration,
        mechanism: "macos-authorization-services",
      };
    } catch (error) {
      return this.unavailableCapability(
        `macOS authorization provider integrity check failed: ${errorMessage(error)}`,
      );
    }
  }

  async authorize(
    request: UserAuthorizationProviderRequest,
  ): Promise<UserAuthorizationProviderDecision> {
    this.assertOpen();
    if (request.descriptor.target.platform !== "macos" || request.descriptor.target.transport !== "local") {
      throw unavailable("The initial macOS authorization provider supports local macOS targets only.");
    }
    if (request.descriptor.action.tty) {
      throw unavailable("The initial macOS authorization provider does not support a privileged PTY.");
    }
    if (this.sessions.has(request.descriptor.descriptorDigest)) {
      throw new UniversalBrokerError(
        "RESOURCE_BUSY",
        "An authorization session already exists for this descriptor.",
        { evidence: { authorizationOperationId: request.descriptor.authorizationOperationId, providerDispatchCount: 0 } },
      );
    }
    const capability = await this.capability({
      targetId: request.descriptor.target.id,
      targetGeneration: request.descriptor.target.generation,
      platform: request.descriptor.target.platform,
    });
    if (!capability.available) throw unavailable(capability.reason ?? "macOS authorization provider is unavailable.");

    const nonce = randomUUID();
    const prompt = boundedPrompt(request);
    const child = this.spawnProcess(this.agentPath, [
      ...(this.approvalAppPath && this.approvalAppExecutablePath && this.approvalAppSha256
        ? [
          "--approval-app", this.approvalAppPath,
          "--approval-app-executable", this.approvalAppExecutablePath,
          "--approval-app-sha256", this.approvalAppSha256,
        ]
        : []),
      "--helper", this.helperPath,
      "--helper-sha256", this.helperSha256,
      "--descriptor-digest", request.descriptor.descriptorDigest,
      "--nonce", nonce,
      "--prompt", prompt,
      "--timeout-ms", String(request.elevation.timeoutMs),
    ], {
      cwd: this.workRoot,
      env: {
        PATH: "/usr/bin:/bin:/usr/sbin:/sbin",
        HOME: process.env.HOME ?? dirname(this.workRoot),
      },
      stdio: ["pipe", "pipe", "pipe"],
    });
    const decidedAt = new Date(this.now()).toISOString();
    const protocol = await readAuthorizationProtocolLine(child, request.elevation.timeoutMs);
    if (protocol.descriptorDigest !== request.descriptor.descriptorDigest) {
      terminate(child);
      throw unknownResult(
        request.descriptor.authorizationOperationId,
        request.descriptor.actionDigest,
        "The approval agent returned a mismatched descriptor digest.",
      );
    }
    const decision = normalizeDecision(protocol.state);
    const receipt = createUserAuthorizationReceipt({
      descriptor: request.descriptor,
      decision,
      providerId: "macos-authorization-services-v1",
      providerGeneration: this.providerGeneration,
      decidedAt,
      receiptId: `receipt-${request.descriptor.authorizationOperationId}`,
      helperIdentityDigest: this.helperSha256,
      evidence: {
        nativeAuthorization: true,
        agentSha256: this.agentSha256,
        helperSha256: this.helperSha256,
        ...(protocol.nonce ? { sessionNonceDigest: digestUserAuthorizationValue(protocol.nonce) } : {}),
      },
    });
    if (decision !== "APPROVED") {
      terminate(child);
      return { receipt };
    }
    if (protocol.nonce !== nonce) {
      terminate(child);
      throw unknownResult(
        request.descriptor.authorizationOperationId,
        request.descriptor.actionDigest,
        "The approval agent returned a mismatched session nonce.",
      );
    }
    this.sessions.set(request.descriptor.descriptorDigest, {
      child,
      descriptorDigest: request.descriptor.descriptorDigest,
      nonce,
    });
    return { receipt };
  }

  async launch(
    request: UserAuthorizationProviderLaunchRequest,
  ): Promise<ChildProcessWithoutNullStreams> {
    this.assertOpen();
    if (request.receipt.decision !== "APPROVED") {
      throw new UniversalBrokerError("ELEVATION_DENIED", "Only an approved receipt may launch a privileged action.");
    }
    const session = this.sessions.get(request.descriptor.descriptorDigest);
    if (!session) {
      throw unknownResult(
        request.descriptor.authorizationOperationId,
        request.descriptor.actionDigest,
        "The approved native authorization session is no longer available.",
      );
    }
    this.sessions.delete(request.descriptor.descriptorDigest);
    const directory = join(this.workRoot, request.descriptor.authorizationOperationId);
    const scriptPath = join(directory, "action.zsh");
    const specPath = join(directory, "task.spec");
    try {
      await mkdir(directory, { recursive: false, mode: 0o700 });
      await chmod(directory, 0o700);
      const script = `#!/bin/zsh\nset -euo pipefail\n${request.command}\n`;
      await writeExclusive(scriptPath, script, 0o600);
      const canonicalScript = await requireCanonicalOwnedPath(
        scriptPath,
        this.expectedUid,
        "authorized script",
      );
      const scriptSha256 = await fileDigest(canonicalScript);
      const canonicalCwd = await realpath(request.cwd);
      if (canonicalCwd !== request.cwd || !isAbsolute(canonicalCwd)) {
        throw unavailable("Authorized working directory is not canonical.");
      }
      const specification = [
        "DEVSPACE_AUTH_SPEC_V1",
        `descriptorDigest=${request.descriptor.descriptorDigest}`,
        `cwd=${canonicalCwd}`,
        `script=${canonicalScript}`,
        `scriptSha256=${scriptSha256}`,
        `userUid=${this.expectedUid}`,
        "",
      ].join("\n");
      await writeExclusive(specPath, specification, 0o600);
      const canonicalSpec = await requireCanonicalOwnedPath(
        specPath,
        this.expectedUid,
        "authorization task specification",
      );
      const specSha256 = await fileDigest(canonicalSpec);
      session.child.once("exit", () => {
        void rm(directory, { recursive: true, force: true });
      });
      session.child.stdin.write([
        "LAUNCH",
        request.descriptor.descriptorDigest,
        canonicalSpec,
        specSha256,
      ].join("\t") + "\n");
      session.child.stdin.end();
      return session.child;
    } catch (error) {
      terminate(session.child);
      await rm(directory, { recursive: true, force: true });
      throw error;
    }
  }

  async close(): Promise<void> {
    if (this.closed) return;
    this.closed = true;
    for (const session of this.sessions.values()) terminate(session.child);
    this.sessions.clear();
  }

  private async verifyExecutable(path: string, expectedSha256: string, label: string): Promise<void> {
    const canonical = await requireCanonicalOwnedPath(path, this.expectedUid, label);
    const state = await lstat(canonical);
    if ((state.mode & 0o100) === 0 || (state.mode & 0o022) !== 0) {
      throw new Error(`${label} mode is unsafe`);
    }
    if (await fileDigest(canonical) !== expectedSha256) throw new Error(`${label} digest changed`);
    this.verifyCodeSignature(canonical);
  }

  private async verifyApplicationBundle(
    appPath: string,
    executablePath: string,
    expectedSha256: string,
  ): Promise<void> {
    const canonicalApp = await realpath(appPath);
    if (canonicalApp !== appPath) throw new Error("approval app path changed through canonicalization");
    const appState = await lstat(canonicalApp);
    if (!appState.isDirectory() || appState.isSymbolicLink()
        || appState.uid !== this.expectedUid || (appState.mode & 0o022) !== 0) {
      throw new Error("approval app identity or mode is invalid");
    }
    const canonicalExecutable = await requireCanonicalOwnedPath(
      executablePath,
      this.expectedUid,
      "approval app executable",
    );
    if (!canonicalExecutable.startsWith(`${canonicalApp}/Contents/MacOS/`)) {
      throw new Error("approval app executable is outside the pinned bundle");
    }
    const state = await lstat(canonicalExecutable);
    if ((state.mode & 0o100) === 0 || (state.mode & 0o022) !== 0) {
      throw new Error("approval app executable mode is unsafe");
    }
    if (await fileDigest(canonicalExecutable) !== expectedSha256) {
      throw new Error("approval app executable digest changed");
    }
    this.verifyCodeSignature(canonicalApp);
  }

  private unavailableCapability(reason: string): UserAuthorizationProviderCapability {
    return {
      available: false,
      providerId: "macos-authorization-services-v1",
      providerGeneration: this.providerGeneration,
      mechanism: "macos-authorization-services",
      reason,
    };
  }

  private assertOpen(): void {
    if (this.closed) throw unavailable("macOS authorization provider is closed.");
  }
}

interface AuthorizationProtocolLine {
  state: string;
  descriptorDigest: string;
  nonce?: string;
}

async function readAuthorizationProtocolLine(
  child: ChildProcessWithoutNullStreams,
  timeoutMs: number,
): Promise<AuthorizationProtocolLine> {
  return new Promise((resolve, reject) => {
    let buffer = Buffer.alloc(0);
    let settled = false;
    const timer = setTimeout(() => {
      if (settled) return;
      settled = true;
      cleanup();
      terminate(child);
      reject(new UniversalBrokerError(
        "ELEVATION_TIMED_OUT",
        "The native administrator authorization prompt timed out.",
        { evidence: { providerDispatchCount: 0 } },
      ));
    }, timeoutMs);
    timer.unref?.();
    const onData = (chunk: Buffer): void => {
      if (settled) return;
      buffer = Buffer.concat([buffer, chunk]);
      if (buffer.length > MAXIMUM_PROTOCOL_LINE_BYTES) {
        settled = true;
        cleanup();
        terminate(child);
        reject(unknownResult(undefined, undefined, "The approval agent protocol line exceeded its bound."));
        return;
      }
      const newline = buffer.indexOf(0x0a);
      if (newline < 0) return;
      const line = buffer.subarray(0, newline).toString("utf8").replace(/\r$/u, "");
      const remainder = buffer.subarray(newline + 1);
      settled = true;
      cleanup();
      if (remainder.length > 0) child.stdout.unshift(remainder);
      const parts = line.split("\t");
      if (parts[0] !== "DEVSPACE_AUTHORIZATION_RESULT" || parts.length < 3 || parts.length > 4) {
        terminate(child);
        reject(unknownResult(undefined, undefined, "The approval agent returned a malformed protocol response."));
        return;
      }
      resolve({ state: parts[1]!, descriptorDigest: parts[2]!, ...(parts[3] ? { nonce: parts[3] } : {}) });
    };
    const onExit = (): void => {
      if (settled) return;
      settled = true;
      cleanup();
      reject(unknownResult(undefined, undefined, "The approval agent exited before returning an authorization decision."));
    };
    const onError = (error: Error): void => {
      if (settled) return;
      settled = true;
      cleanup();
      reject(unknownResult(undefined, undefined, `The approval agent failed: ${error.name}.`));
    };
    const cleanup = (): void => {
      clearTimeout(timer);
      child.stdout.off("data", onData);
      child.off("exit", onExit);
      child.off("error", onError);
    };
    child.stdout.on("data", onData);
    child.once("exit", onExit);
    child.once("error", onError);
  });
}

async function requireCanonicalOwnedPath(path: string, expectedUid: number, label: string): Promise<string> {
  if (!isAbsolute(path) || resolve(path) !== path || /[\0\r\n]/u.test(path)) {
    throw new Error(`${label} path is not canonical and absolute`);
  }
  const canonical = await realpath(path);
  if (canonical !== path) throw new Error(`${label} path changed through canonicalization`);
  const state = await lstat(canonical);
  if (!state.isFile() || state.isSymbolicLink() || state.uid !== expectedUid) {
    throw new Error(`${label} owner or type is invalid`);
  }
  return canonical;
}

async function writeExclusive(path: string, content: string, mode: number): Promise<void> {
  await writeFile(path, content, { flag: "wx", mode });
  await chmod(path, mode);
}

async function fileDigest(path: string): Promise<string> {
  return `sha256:${createHash("sha256").update(await readFile(path)).digest("hex")}`;
}

function boundedPrompt(request: UserAuthorizationProviderRequest): string {
  const reason = request.elevation.reason?.trim();
  if (!reason) throw unavailable("Native authorization prompt requires a reason.");
  const value = `DevSpace requests one-time administrator authorization on ${request.descriptor.target.id}: ${reason} [action ${request.descriptor.actionDigest.slice(0, 23)}…]`;
  if (value.length > 2_000 || /[\0\r\n]/u.test(value)) throw unavailable("Native authorization prompt is invalid.");
  return value;
}

function normalizeDecision(value: string): UserAuthorizationDecisionState {
  switch (value) {
    case "APPROVED":
    case "DENIED":
    case "CANCELED":
    case "TIMED_OUT":
    case "RESULT_UNKNOWN":
      return value;
    default:
      throw unknownResult(undefined, undefined, "The approval agent returned an unknown authorization state.");
  }
}

function verifyCodeSignature(path: string): void {
  const result = spawnSync("/usr/bin/codesign", ["--verify", "--strict", path], {
    encoding: "utf8",
    timeout: 10_000,
  });
  if (result.error || result.status !== 0) throw new Error("code signature verification failed");
}

function requireCanonicalAbsolute(value: string, field: string): string {
  if (!isAbsolute(value) || resolve(value) !== value || /[\0\r\n]/u.test(value)) {
    throw unavailable(`${field} must be canonical and absolute.`);
  }
  return value;
}

function requireCanonicalAbsoluteParent(value: string, field: string): string {
  return requireCanonicalAbsolute(value, field);
}

function requireDigest(value: string, field: string): string {
  const normalized = value.trim().toLowerCase();
  if (!DIGEST_PATTERN.test(normalized)) throw unavailable(`${field} must be a SHA-256 digest.`);
  return normalized;
}

function terminate(child: ChildProcessWithoutNullStreams): void {
  if (!child.killed && child.exitCode === null && child.signalCode === null) child.kill("SIGTERM");
}

function unavailable(message: string): UniversalBrokerError {
  return new UniversalBrokerError("ELEVATION_UNAVAILABLE", message, {
    evidence: { providerDispatchCount: 0 },
  });
}

function unknownResult(
  authorizationOperationId: string | undefined,
  actionDigest: string | undefined,
  message: string,
): UniversalBrokerError {
  return new UniversalBrokerError("ELEVATION_RESULT_UNKNOWN", message, {
    evidence: {
      ...(authorizationOperationId && SAFE_ID_PATTERN.test(authorizationOperationId)
        ? { authorizationOperationId }
        : {}),
      ...(actionDigest && DIGEST_PATTERN.test(actionDigest) ? { actionDigest } : {}),
      providerDispatchCount: 0,
    },
  });
}

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}
