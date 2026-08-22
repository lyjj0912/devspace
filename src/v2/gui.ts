import { createHash, randomUUID } from "node:crypto";
import { homedir } from "node:os";
import { dirname, isAbsolute, join, posix } from "node:path";
import type { InternalOneShotRunner, UniversalExecutionPlane } from "./execution.js";
import { asInternalOneShotRunner } from "./execution.js";
import type { UniversalFilesystemService } from "./filesystem.js";
import {
  GUI_NODE_APPLESCRIPT_SOURCE,
  GUI_NODE_RESULT_MARKER,
} from "./gui-node.js";
import { UniversalBrokerError } from "./errors.js";
import {
  assertTargetCapability,
  type TargetDefinition,
  type TargetRegistry,
} from "./targets.js";
import {
  createCapabilityCallContextFromTrustedPrincipal,
  requireCapabilityCallContext,
  type CapabilityCallContext,
  type CapabilityCallContextProvider,
} from "./capability-call-context.js";
import { SynchronousQuotaReservations } from "./quota-reservations.js";
import {
  RESOURCE_DEFAULT_GUI_SESSIONS,
  RESOURCE_DEFAULT_GUI_TTL_MS,
} from "./resource-defaults.js";

const DEFAULT_MAXIMUM_SESSIONS = RESOURCE_DEFAULT_GUI_SESSIONS;
const DEFAULT_SESSION_TTL_MS = RESOURCE_DEFAULT_GUI_TTL_MS;
const DEFAULT_MAXIMUM_ELEMENTS = 50;
const MAXIMUM_ELEMENTS = 1_000;
const DEFAULT_WAIT_MS = 5_000;
const MAXIMUM_WAIT_MS = 120_000;
const OBSERVATION_PAYLOAD_BUDGET = 12_000;
const NODE_TIMEOUT_MS = 60_000;

export type UniversalGuiOperation =
  | "capabilities"
  | "request_access"
  | "observe"
  | "act"
  | "capture"
  | "wait";

export interface UniversalGuiInput {
  operation: UniversalGuiOperation;
  target?: string;
  sessionId?: string;
  generation?: string;
  action?: Record<string, unknown>;
  timeoutMs?: number;
  maxElements?: number;
  permissions?: Array<"accessibility" | "screen_capture">;
  format?: "jpeg" | "png";
  quality?: number;
  maxWidth?: number;
  focusPolicy?: "preserve" | "allow";
}

export interface GuiApplicationObservation {
  name: string;
  bundleIdentifier: string;
  pid: number;
}

export interface GuiWindowObservation {
  title: string;
  role: string;
  subrole: string;
  position: [number, number] | null;
  size: [number, number] | null;
}

export interface GuiElementObservation {
  elementId: string;
  index: number;
  role: string;
  subrole: string;
  name: string;
  description: string;
  value: string;
  enabled: boolean | null;
  focused: boolean;
  position: [number, number] | null;
  size: [number, number] | null;
  actions: string[];
}

export interface GuiObservation {
  application: GuiApplicationObservation;
  window: GuiWindowObservation | null;
  elements: GuiElementObservation[];
  totalElements: number;
  omittedElements: number;
  truncated: boolean;
}

export interface GuiNodeRequest {
  operation: "capabilities" | "request_access" | "observe" | "act" | "capture";
  maxElements?: number;
  permissions?: Array<"accessibility" | "screen_capture">;
  format?: "jpeg" | "png";
  quality?: number;
  maxWidth?: number;
  elementIndex?: number;
  actionType?: string;
  actionName?: string;
  value?: string;
  modifiers?: string[];
  keyCode?: number;
  expected?: {
    pid: number;
    windowTitle: string;
    role: string;
    subrole: string;
    name: string;
    description: string;
  };
}

export interface GuiNodeRunner {
  call(
    target: TargetDefinition,
    request: GuiNodeRequest,
    callContext?: CapabilityCallContext,
  ): Promise<Record<string, unknown>>;
}

export interface UniversalGuiServiceOptions {
  runner?: GuiNodeRunner;
  maximumSessions?: number;
  sessionTtlMs?: number;
  payloadBudgetCharacters?: number;
  now?: () => number;
  sleep?: (milliseconds: number) => Promise<void>;
  ownerProvider?: CapabilityCallContextProvider;
}

interface GuiSession {
  sessionId: string;
  principalKeyFingerprint: string;
  targetId: string;
  targetGeneration: string;
  focusPolicy: "preserve" | "allow";
  generation: string;
  observation: GuiObservation;
  maxElements: number;
  createdAt: number;
  lastUsedAt: number;
}

interface NormalizedGuiAction {
  type: "perform" | "press" | "click" | "set_value" | "focus" | "keystroke" | "key_code";
  elementId?: string;
  actionName?: string;
  value?: string;
  modifiers: string[];
  keyCode?: number;
}

export class UniversalGuiService {
  private readonly runner: GuiNodeRunner;
  private readonly maximumSessions: number;
  private readonly sessionTtlMs: number;
  private readonly payloadBudgetCharacters: number;
  private readonly now: () => number;
  private readonly sleep: (milliseconds: number) => Promise<void>;
  private readonly ownerProvider: CapabilityCallContextProvider;
  private readonly reservations: SynchronousQuotaReservations;
  private readonly sessions = new Map<string, GuiSession>();
  private closed = false;

  constructor(
    private readonly targets: TargetRegistry,
    filesystem: UniversalFilesystemService,
    execution: UniversalExecutionPlane | InternalOneShotRunner,
    options: UniversalGuiServiceOptions = {},
  ) {
    this.runner = options.runner
      ?? new MacOsGuiNodeRunner(targets, filesystem, execution);
    this.maximumSessions = boundedInteger(
      options.maximumSessions,
      DEFAULT_MAXIMUM_SESSIONS,
      1,
      1_000,
      "maximumSessions",
    );
    this.sessionTtlMs = boundedInteger(
      options.sessionTtlMs,
      DEFAULT_SESSION_TTL_MS,
      1_000,
      24 * 60 * 60_000,
      "sessionTtlMs",
    );
    this.payloadBudgetCharacters = boundedInteger(
      options.payloadBudgetCharacters,
      OBSERVATION_PAYLOAD_BUDGET,
      1_000,
      100_000,
      "payloadBudgetCharacters",
    );
    this.now = options.now ?? Date.now;
    this.sleep = options.sleep ?? ((milliseconds) => new Promise((resolve) => {
      setTimeout(resolve, milliseconds);
    }));
    const compatibilityOwner = createCapabilityCallContextFromTrustedPrincipal({
      principalKeyFingerprint: createHash("sha256")
        .update(JSON.stringify({ authority: "legacy-single-owner-gui-service" }))
        .digest("hex"),
    });
    this.ownerProvider = options.ownerProvider ?? (() => compatibilityOwner);
    this.reservations = new SynchronousQuotaReservations("gui-session", {
      entries: this.maximumSessions,
    });
  }

  async execute(
    input: UniversalGuiInput,
    callContext?: CapabilityCallContext,
  ): Promise<Record<string, unknown>> {
    this.assertOpen();
    this.pruneExpired();
    const owner = this.owner(callContext);
    switch (input.operation) {
      case "capabilities":
        return this.capabilities(input.target, owner);
      case "request_access":
        return this.requestAccess(input, owner);
      case "capture":
        return this.capture(input, owner);
      case "observe":
        return this.observe(input, owner);
      case "act":
        return this.act(input, owner);
      case "wait":
        return this.wait(input, owner);
    }
  }

  async authorityTarget(
    input: Pick<UniversalGuiInput, "target" | "sessionId">,
    callContext?: CapabilityCallContext,
  ): Promise<{
    generation: string;
    target: TargetDefinition;
  }> {
    this.assertOpen();
    this.pruneExpired();
    const owner = this.owner(callContext);
    const session = input.sessionId ? this.requireSession(input.sessionId, owner) : undefined;
    const binding = await this.targets.resolveWithGeneration(
      input.target ?? session?.targetId ?? "local",
    );
    if (session && session.targetId !== binding.target.id) {
      throw new UniversalBrokerError(
        "PRECONDITION_FAILED",
        `GUI session ${session.sessionId} belongs to ${session.targetId}, not ${binding.target.id}.`,
      );
    }
    if (session && session.targetGeneration !== binding.generation) {
      throw guiStateChanged(
        session,
        session.generation,
        session.generation,
        "target generation changed",
      );
    }
    return binding;
  }

  close(): void {
    if (this.closed) return;
    this.closed = true;
    this.sessions.clear();
  }

  stats(): Record<string, unknown> {
    this.pruneExpired();
    return {
      sessions: this.sessions.size,
      maximumSessions: this.maximumSessions,
      sessionTtlMs: this.sessionTtlMs,
      payloadBudgetCharacters: this.payloadBudgetCharacters,
    };
  }

  private async capabilities(
    selector: string | undefined,
    owner: CapabilityCallContext,
  ): Promise<Record<string, unknown>> {
    const target = await this.targets.resolve(selector ?? "local");
    if (target.platform !== "macos") {
      return {
        targetId: target.id,
        configured: target.gui.mode !== "none",
        available: false,
        platform: target.platform,
        guiMode: target.gui.mode,
        screenCapture: false,
        reason: "The current generic GUI node implements macOS Accessibility only.",
      };
    }
    if (target.gui.mode === "none") {
      return {
        targetId: target.id,
        configured: false,
        available: false,
        platform: target.platform,
        guiMode: target.gui.mode,
        screenCapture: false,
        reason: "GUI is disabled for this target in the target registry.",
      };
    }
    let node: Record<string, unknown>;
    try {
      node = await this.runner.call(target, { operation: "capabilities" }, owner);
    } catch (error) {
      if (error instanceof UniversalBrokerError && error.code === "CAPABILITY_UNAVAILABLE") {
        return {
          targetId: target.id,
          configured: true,
          available: false,
          platform: target.platform,
          guiMode: target.gui.mode,
          screenCapture: false,
          reason: error.message,
        };
      }
      throw error;
    }
    const available = node.accessibility === true;
    const nodeReason = typeof node.reason === "string" && node.reason.trim()
      ? node.reason.trim()
      : typeof node.probeError === "string" && node.probeError.trim()
        ? node.probeError.trim()
        : undefined;
    return {
      targetId: target.id,
      configured: true,
      available,
      guiMode: target.gui.mode,
      ...node,
      screenCapture: node.screenCapture === true,
      ...(!available
        ? { reason: nodeReason ?? `macOS Accessibility UI scripting is disabled for target ${target.id}.` }
        : {}),
    };
  }

  private async requestAccess(
    input: UniversalGuiInput,
    owner: CapabilityCallContext,
  ): Promise<Record<string, unknown>> {
    const target = await this.targets.resolve(input.target ?? "local");
    this.assertGuiTarget(target);
    const permissions = normalizeGuiPermissions(input.permissions);
    const result = await this.runner.call(target, {
      operation: "request_access",
      permissions,
    }, owner);
    return { targetId: target.id, permissions, ...result };
  }

  private async capture(
    input: UniversalGuiInput,
    owner: CapabilityCallContext,
  ): Promise<Record<string, unknown>> {
    const target = await this.targets.resolve(input.target ?? "local");
    this.assertGuiTarget(target);
    const format = input.format ?? "jpeg";
    const quality = boundedInteger(input.quality, 70, 1, 100, "quality");
    const maxWidth = boundedInteger(input.maxWidth, 1_600, 320, 2_560, "maxWidth");
    const result = await this.runner.call(target, {
      operation: "capture",
      format,
      quality,
      maxWidth,
    }, owner);
    return { targetId: target.id, format, quality, maxWidth, ...result };
  }

  private async observe(
    input: UniversalGuiInput,
    owner: CapabilityCallContext,
  ): Promise<Record<string, unknown>> {
    const existing = input.sessionId ? this.requireSession(input.sessionId, owner) : undefined;
    const binding = await this.resolveSessionTarget(input.target, existing);
    const target = binding.target;
    this.assertGuiTarget(target);
    const maxElements = boundedInteger(
      input.maxElements,
      existing?.maxElements ?? DEFAULT_MAXIMUM_ELEMENTS,
      1,
      MAXIMUM_ELEMENTS,
      "maxElements",
    );
    const focusPolicy = normalizeFocusPolicy(input.focusPolicy ?? existing?.focusPolicy);
    if (existing && focusPolicy !== existing.focusPolicy) {
      throw new UniversalBrokerError(
        "PRECONDITION_FAILED",
        `GUI session ${existing.sessionId} focus policy cannot be changed after creation.`,
        { evidence: { sessionId: existing.sessionId, providerDispatchCount: 0 } },
      );
    }
    const reservation = existing ? undefined : this.reservations.reserve(
      { entries: this.sessions.size },
      { entries: 1 },
    );
    try {
      const observation = normalizeObservation(
        await this.runner.call(target, { operation: "observe", maxElements }, owner),
      );
      const generation = observationGeneration(target.id, observation);
      const now = this.now();
      const session: GuiSession = existing ?? {
        sessionId: `gui_${randomUUID()}`,
        principalKeyFingerprint: owner.principalKeyFingerprint,
        targetId: target.id,
        targetGeneration: binding.generation,
        focusPolicy,
        generation,
        observation,
        maxElements,
        createdAt: now,
        lastUsedAt: now,
      };
      session.targetId = target.id;
      session.targetGeneration = binding.generation;
      session.generation = generation;
      session.observation = observation;
      session.maxElements = maxElements;
      session.lastUsedAt = now;
      if (reservation) reservation.commit(() => this.sessions.set(session.sessionId, session));
      else this.sessions.set(session.sessionId, session);
      this.touch(session.sessionId);
      return this.presentObservation(session, false);
    } finally {
      reservation?.release();
    }
  }

  private async act(
    input: UniversalGuiInput,
    owner: CapabilityCallContext,
  ): Promise<Record<string, unknown>> {
    const session = this.requireSession(
      requiredText(input.sessionId, "gui.act requires sessionId."),
      owner,
    );
    const expectedGeneration = requiredText(input.generation, "gui.act requires generation.");
    if (session.generation !== expectedGeneration) {
      throw guiStateChanged(session, expectedGeneration, session.generation, "session generation changed");
    }
    const binding = await this.resolveSessionTarget(input.target, session);
    const target = binding.target;
    this.assertGuiTarget(target);
    const action = normalizeAction(input.action);
    const current = normalizeObservation(
      await this.runner.call(target, {
        operation: "observe",
        maxElements: session.maxElements,
      }, owner),
    );
    const currentGeneration = observationGeneration(target.id, current);
    if (currentGeneration !== expectedGeneration) {
      throw guiStateChanged(session, expectedGeneration, currentGeneration, "GUI changed after observation");
    }

    const element = action.elementId
      ? current.elements.find((candidate) => candidate.elementId === action.elementId)
      : undefined;
    if (action.elementId && !element) {
      throw guiStateChanged(session, expectedGeneration, currentGeneration, "observed element disappeared");
    }
    if (action.type === "perform" && element && !element.actions.includes(action.actionName!)) {
      throw new UniversalBrokerError(
        "CAPABILITY_UNAVAILABLE",
        `Element ${element.elementId} does not advertise ${action.actionName}.`,
        { evidence: { elementId: element.elementId, actions: element.actions } },
      );
    }
    const focusBefore = focusEvidence(current);
    const unavoidableFocusChange = actionRequiresFocusChange(action, element);
    if (session.focusPolicy === "preserve" && unavoidableFocusChange) {
      throw new UniversalBrokerError(
        "PRECONDITION_FAILED",
        "GUI action would unavoidably change focus under focusPolicy=preserve.",
        {
          evidence: {
            sessionId: session.sessionId,
            targetId: session.targetId,
            focusPolicy: session.focusPolicy,
            actionType: action.type,
            providerDispatchCount: 0,
            focusBefore,
          },
        },
      );
    }

    let performed: Record<string, unknown>;
    try {
      performed = await this.runner.call(target, {
        operation: "act",
        elementIndex: element?.index ?? -1,
        actionType: action.type,
        actionName: action.actionName,
        value: action.value,
        modifiers: action.modifiers,
        keyCode: action.keyCode,
        expected: {
          pid: current.application.pid,
          windowTitle: current.window?.title ?? "",
          role: element?.role ?? "",
          subrole: element?.subrole ?? "",
          name: element?.name ?? "",
          description: element?.description ?? "",
        },
      }, owner);
    } catch (error) {
      if (
        error instanceof UniversalBrokerError
        && ["GUI_STATE_CHANGED", "CAPABILITY_UNAVAILABLE", "PRECONDITION_FAILED"].includes(error.code)
      ) throw error;
      throw guiActionResultUnknown(session, action, focusBefore, error, "action provider failed");
    }

    await this.sleep(100);
    let next: GuiObservation;
    try {
      next = normalizeObservation(
        await this.runner.call(target, {
          operation: "observe",
          maxElements: session.maxElements,
        }, owner),
      );
    } catch (error) {
      throw guiActionResultUnknown(session, action, focusBefore, error, "post-action readback failed");
    }
    const focusAfter = focusEvidence(next);
    session.observation = next;
    session.generation = observationGeneration(target.id, next);
    session.lastUsedAt = this.now();
    this.touch(session.sessionId);
    return {
      performed,
      action: {
        type: action.type,
        ...(action.elementId ? { elementId: action.elementId } : {}),
        ...(action.actionName ? { actionName: action.actionName } : {}),
      },
      focus: {
        policy: session.focusPolicy,
        before: focusBefore,
        after: focusAfter,
        changed: !sameFocus(focusBefore, focusAfter),
        unavoidable: unavoidableFocusChange,
      },
      observation: this.presentObservation(session, false),
    };
  }

  private async wait(
    input: UniversalGuiInput,
    owner: CapabilityCallContext,
  ): Promise<Record<string, unknown>> {
    const session = this.requireSession(
      requiredText(input.sessionId, "gui.wait requires sessionId."),
      owner,
    );
    const expectedGeneration = requiredText(input.generation, "gui.wait requires generation.");
    const binding = await this.resolveSessionTarget(input.target, session);
    const target = binding.target;
    this.assertGuiTarget(target);
    const timeoutMs = boundedInteger(
      input.timeoutMs,
      DEFAULT_WAIT_MS,
      0,
      MAXIMUM_WAIT_MS,
      "timeoutMs",
    );
    const deadline = this.now() + timeoutMs;
    do {
      const current = normalizeObservation(
        await this.runner.call(target, {
          operation: "observe",
          maxElements: session.maxElements,
        }, owner),
      );
      const generation = observationGeneration(target.id, current);
      if (generation !== expectedGeneration) {
        session.observation = current;
        session.generation = generation;
        session.lastUsedAt = this.now();
        this.touch(session.sessionId);
        return {
          changed: true,
          observation: this.presentObservation(session, false),
        };
      }
      if (this.now() >= deadline) break;
      await this.sleep(Math.min(250, Math.max(1, deadline - this.now())));
    } while (true);
    session.lastUsedAt = this.now();
    this.touch(session.sessionId);
    return {
      changed: false,
      sessionId: session.sessionId,
      generation: session.generation,
      timeoutMs,
    };
  }

  private async resolveSessionTarget(
    selector: string | undefined,
    session: GuiSession | undefined,
  ): Promise<{ target: TargetDefinition; generation: string }> {
    const binding = await this.targets.resolveWithGeneration(
      selector ?? session?.targetId ?? "local",
    );
    if (session && session.targetId !== binding.target.id) {
      throw new UniversalBrokerError(
        "PRECONDITION_FAILED",
        `GUI session ${session.sessionId} belongs to ${session.targetId}, not ${binding.target.id}.`,
        { evidence: { sessionId: session.sessionId, providerDispatchCount: 0 } },
      );
    }
    if (session && session.targetGeneration !== binding.generation) {
      throw guiStateChanged(
        session,
        session.generation,
        session.generation,
        "target generation changed",
      );
    }
    return binding;
  }

  private assertGuiTarget(target: TargetDefinition): void {
    assertTargetCapability(target, "gui");
    if (target.platform !== "macos") {
      throw new UniversalBrokerError(
        "CAPABILITY_UNAVAILABLE",
        `Generic GUI is not implemented for ${target.platform} target ${target.id}.`,
      );
    }
    if (target.gui.mode === "none") {
      throw new UniversalBrokerError(
        "CAPABILITY_UNAVAILABLE",
        `GUI is disabled for target ${target.id}.`,
      );
    }
    if (target.transport === "local" && target.gui.mode !== "local-ipc") {
      throw new UniversalBrokerError(
        "PRECONDITION_FAILED",
        `Local target ${target.id} requires gui.mode=local-ipc.`,
      );
    }
    if (target.transport === "ssh" && target.gui.mode !== "ssh-stdio") {
      throw new UniversalBrokerError(
        "PRECONDITION_FAILED",
        `SSH target ${target.id} requires gui.mode=ssh-stdio.`,
      );
    }
  }

  private requireSession(sessionId: string, owner: CapabilityCallContext): GuiSession {
    const session = this.sessions.get(sessionId);
    if (!session || session.lastUsedAt + this.sessionTtlMs <= this.now()) {
      if (session) this.sessions.delete(sessionId);
      throw new UniversalBrokerError(
        "PATH_NOT_FOUND",
        `GUI session is unknown or expired: ${sessionId}`,
      );
    }
    if (session.principalKeyFingerprint !== owner.principalKeyFingerprint) {
      throw new UniversalBrokerError(
        "AUTHORITY_PRINCIPAL_MISMATCH",
        `GUI session ${sessionId} belongs to a different authenticated principal.`,
        { evidence: { sessionId, providerDispatchCount: 0 } },
      );
    }
    return session;
  }

  private presentObservation(
    session: GuiSession,
    changed: boolean,
  ): Record<string, unknown> {
    const base: Record<string, unknown> = {
      sessionId: session.sessionId,
      targetId: session.targetId,
      targetGeneration: session.targetGeneration,
      focusPolicy: session.focusPolicy,
      createdAt: new Date(session.createdAt).toISOString(),
      expiresAt: new Date(session.lastUsedAt + this.sessionTtlMs).toISOString(),
      generation: session.generation,
      changed,
      application: session.observation.application,
      window: session.observation.window,
      elements: [...session.observation.elements],
      totalElements: session.observation.totalElements,
      omittedElements: session.observation.omittedElements,
      truncated: session.observation.truncated,
    };
    let payload = base;
    let removed = 0;
    while (
      JSON.stringify(payload).length > this.payloadBudgetCharacters
      && (payload.elements as GuiElementObservation[]).length > 0
    ) {
      const elements = [...(payload.elements as GuiElementObservation[])];
      elements.pop();
      removed += 1;
      payload = {
        ...payload,
        elements,
        truncated: true,
        omittedElements: session.observation.omittedElements + removed,
      };
    }
    const payloadCharacters = JSON.stringify(payload).length;
    if (payloadCharacters > this.payloadBudgetCharacters) {
      throw new UniversalBrokerError(
        "RESOURCE_QUOTA_EXCEEDED",
        "GUI observation metadata exceeds the model-visible payload budget.",
        { evidence: { payloadCharacters, maximum: this.payloadBudgetCharacters } },
      );
    }
    return { ...payload, payloadCharacters };
  }

  private pruneExpired(): void {
    const now = this.now();
    for (const session of this.sessions.values()) {
      if (session.lastUsedAt + this.sessionTtlMs <= now) this.sessions.delete(session.sessionId);
    }
  }

  private touch(sessionId: string): void {
    const session = this.sessions.get(sessionId);
    if (!session) return;
    this.sessions.delete(sessionId);
    this.sessions.set(sessionId, session);
  }

  private assertOpen(): void {
    if (this.closed) {
      throw new UniversalBrokerError("TRANSPORT_UNAVAILABLE", "The GUI service is closed.");
    }
  }

  private owner(callContext?: CapabilityCallContext): CapabilityCallContext {
    return requireCapabilityCallContext(callContext, this.ownerProvider);
  }
}

export class MacOsGuiNodeRunner implements GuiNodeRunner {
  private readonly installed = new Set<string>();
  private readonly internalRunner: InternalOneShotRunner;
  private readonly sourceSha256 = createHash("sha256")
    .update(GUI_NODE_APPLESCRIPT_SOURCE)
    .digest("hex");

  constructor(
    private readonly targets: TargetRegistry,
    private readonly filesystem: UniversalFilesystemService,
    execution: UniversalExecutionPlane | InternalOneShotRunner,
  ) {
    this.internalRunner = asInternalOneShotRunner(execution);
  }

  async call(
    target: TargetDefinition,
    request: GuiNodeRequest,
    callContext?: CapabilityCallContext,
  ): Promise<Record<string, unknown>> {
    if (target.platform !== "macos") {
      throw new UniversalBrokerError(
        "CAPABILITY_UNAVAILABLE",
        `The built-in GUI node supports macOS only: ${target.id}`,
      );
    }
    const args = guiNodeArguments(request);
    const nativeAgent = target.gui.command && target.gui.sha256
      ? { executablePath: target.gui.command, executableSha256: target.gui.sha256 }
      : undefined;
    const scriptPath = nativeAgent ? undefined : await this.ensureInstalled(target, callContext);
    const process = await this.internalRunner.run({
      internalPolicy: nativeAgent
        ? { kind: "gui-agent", ...nativeAgent }
        : { kind: "gui", scriptPath: scriptPath!, scriptSha256: this.sourceSha256 },
      target: target.id,
      cwd: target.defaultCwd,
      command: nativeAgent
        ? [nativeAgent.executablePath, ...args].map(shellQuote).join(" ")
        : ["/usr/bin/osascript", shellQuote(scriptPath!), ...args.map(shellQuote)].join(" "),
      timeoutMs: NODE_TIMEOUT_MS,
      maxOutputChars: 1_000_000,
    }, callContext);
    if (process.state !== "EXITED" || process.exitCode !== 0) {
      throw new UniversalBrokerError(
        process.state === "UNKNOWN" ? "EXECUTION_STATE_UNKNOWN" : "TRANSPORT_INTERRUPTED",
        `GUI node failed on target ${target.id}.`,
        {
          evidence: {
            targetId: target.id,
            state: process.state,
            exitCode: process.exitCode,
            outputPreview: process.output.slice(0, 500),
          },
        },
      );
    }
    const marker = process.output.lastIndexOf(GUI_NODE_RESULT_MARKER);
    if (marker < 0) {
      throw new UniversalBrokerError(
        "TRANSPORT_INTERRUPTED",
        `GUI node returned no framed result on target ${target.id}.`,
        { evidence: { outputPreview: process.output.slice(0, 500) } },
      );
    }
    const framed = process.output
      .slice(marker + GUI_NODE_RESULT_MARKER.length)
      .trim()
      .split(/\r?\n/, 1)[0] ?? "";
    let response: { ok?: boolean; data?: unknown; code?: string; message?: string };
    try {
      response = JSON.parse(framed) as typeof response;
    } catch (error) {
      throw new UniversalBrokerError(
        "TRANSPORT_INTERRUPTED",
        `GUI node returned malformed JSON on target ${target.id}.`,
        { evidence: { error: errorMessage(error) } },
      );
    }
    if (response.ok === true && response.data && typeof response.data === "object") {
      return response.data as Record<string, unknown>;
    }
    throw new UniversalBrokerError(
      guiNodeErrorCode(response.code),
      response.message ?? `GUI node failed on target ${target.id}.`,
      { evidence: { targetId: target.id, nodeCode: response.code } },
    );
  }

  private async ensureInstalled(
    target: TargetDefinition,
    callContext?: CapabilityCallContext,
  ): Promise<string> {
    const scriptPath = target.gui.command ?? await this.defaultScriptPath(target);
    const cacheKey = `${target.id}:${scriptPath}:${this.sourceSha256}`;
    if (this.installed.has(cacheKey)) return scriptPath;
    await this.filesystem.execute({
      operation: "mkdir",
      target: target.id,
      path: dirnameForTarget(scriptPath, target),
      recursive: true,
    }, callContext);
    let existingSha256: string | undefined;
    try {
      const result = await this.filesystem.execute({
        operation: "hash",
        target: target.id,
        path: scriptPath,
      }, callContext);
      existingSha256 = typeof result.sha256 === "string" ? result.sha256 : undefined;
    } catch (error) {
      if (!(error instanceof UniversalBrokerError) || error.code !== "PATH_NOT_FOUND") throw error;
    }
    if (existingSha256 !== this.sourceSha256) {
      await this.filesystem.execute({
        operation: "write",
        target: target.id,
        path: scriptPath,
        content: GUI_NODE_APPLESCRIPT_SOURCE,
        overwrite: existingSha256 !== undefined,
        expectedSha256: existingSha256,
      }, callContext);
    }
    this.installed.add(cacheKey);
    return scriptPath;
  }

  private async defaultScriptPath(target: TargetDefinition): Promise<string> {
    if (target.transport === "local") {
      return join(homedir(), ".devspace", "run", "gui-node.applescript");
    }
    if (target.defaultCwd && target.defaultCwd.startsWith("/")) {
      return posix.join(target.defaultCwd, ".devspace", "run", "gui-node.applescript");
    }
    const observation = await this.targets.probe(target.id);
    if (!observation.homeDirectory?.startsWith("/")) {
      throw new UniversalBrokerError(
        "TRANSPORT_UNAVAILABLE",
        `Unable to resolve the remote home directory for GUI target ${target.id}.`,
      );
    }
    return posix.join(observation.homeDirectory, ".devspace", "run", "gui-node.applescript");
  }
}

function guiNodeArguments(request: GuiNodeRequest): string[] {
  if (request.operation === "capabilities") return ["capabilities"];
  if (request.operation === "request_access") {
    return ["request-access", normalizeGuiPermissions(request.permissions).join(",")];
  }
  if (request.operation === "capture") {
    return [
      "capture",
      request.format ?? "jpeg",
      String(request.quality ?? 70),
      String(request.maxWidth ?? 1_600),
    ];
  }
  if (request.operation === "observe") {
    return ["observe", String(request.maxElements ?? DEFAULT_MAXIMUM_ELEMENTS)];
  }
  const expected = request.expected;
  if (!expected) {
    throw new UniversalBrokerError("PRECONDITION_FAILED", "GUI node act requires an expected fingerprint.");
  }
  return [
    "act",
    String(request.elementIndex ?? -1),
    request.actionType ?? "",
    base64(request.actionName ?? ""),
    base64(request.value ?? ""),
    (request.modifiers ?? []).join(","),
    String(request.keyCode ?? -1),
    String(expected.pid),
    base64(expected.windowTitle),
    base64(expected.role),
    base64(expected.name),
    base64(expected.description),
    base64(expected.subrole),
  ];
}

function normalizeGuiPermissions(
  value: Array<"accessibility" | "screen_capture"> | undefined,
): Array<"accessibility" | "screen_capture"> {
  const permissions = value ?? ["accessibility", "screen_capture"];
  const unique = [...new Set(permissions)];
  if (unique.length < 1 || unique.length > 2
    || unique.some((permission) => permission !== "accessibility" && permission !== "screen_capture")) {
    throw new UniversalBrokerError("INVALID_ARGUMENT", "GUI permissions are invalid.", {
      evidence: { providerDispatchCount: 0 },
    });
  }
  return unique;
}

function normalizeObservation(value: Record<string, unknown>): GuiObservation {
  const applicationValue = requiredRecord(value.application, "GUI observation application is missing.");
  const elementsValue = Array.isArray(value.elements) ? value.elements : [];
  const elements = elementsValue.map((entry, index) => normalizeElement(entry, index));
  const identifiers = new Set<string>();
  for (const element of elements) {
    if (identifiers.has(element.elementId)) {
      throw new UniversalBrokerError("MCP_PROVIDER_ERROR", `Duplicate GUI element ID: ${element.elementId}`);
    }
    identifiers.add(element.elementId);
  }
  return {
    application: {
      name: normalizedString(applicationValue.name, 240),
      bundleIdentifier: normalizedString(applicationValue.bundleIdentifier, 240),
      pid: requiredInteger(applicationValue.pid, "GUI application pid"),
    },
    window: value.window === null || value.window === undefined
      ? null
      : normalizeWindow(requiredRecord(value.window, "GUI window is invalid.")),
    elements,
    totalElements: nonNegativeInteger(value.totalElements, elements.length),
    omittedElements: nonNegativeInteger(value.omittedElements, 0),
    truncated: value.truncated === true,
  };
}

function normalizeWindow(value: Record<string, unknown>): GuiWindowObservation {
  return {
    title: normalizedString(value.title, 240),
    role: normalizedString(value.role, 120),
    subrole: normalizedString(value.subrole, 120),
    position: normalizePair(value.position),
    size: normalizePair(value.size),
  };
}

function normalizeElement(value: unknown, fallbackIndex: number): GuiElementObservation {
  const record = requiredRecord(value, "GUI element is invalid.");
  const index = Number.isSafeInteger(record.index) && Number(record.index) >= 0
    ? Number(record.index)
    : fallbackIndex;
  const actions = Array.isArray(record.actions)
    ? [...new Set(record.actions.filter((entry): entry is string => typeof entry === "string"))]
      .slice(0, 32)
    : [];
  return {
    elementId: typeof record.elementId === "string" && record.elementId
      ? record.elementId
      : `e${index}`,
    index,
    role: normalizedString(record.role, 120),
    subrole: normalizedString(record.subrole, 120),
    name: normalizedString(record.name, 240),
    description: normalizedString(record.description, 240),
    value: normalizedString(record.value, 240),
    enabled: typeof record.enabled === "boolean" ? record.enabled : null,
    focused: record.focused === true,
    position: normalizePair(record.position),
    size: normalizePair(record.size),
    actions,
  };
}

function normalizeAction(value: Record<string, unknown> | undefined): NormalizedGuiAction {
  const record = requiredRecord(value, "gui.act requires action.");
  const type = record.type;
  if (![
    "perform",
    "press",
    "click",
    "set_value",
    "focus",
    "keystroke",
    "key_code",
  ].includes(String(type))) {
    throw new UniversalBrokerError("PRECONDITION_FAILED", `Unsupported GUI action type: ${String(type)}`);
  }
  const actionType = type as NormalizedGuiAction["type"];
  const elementRequired = ["perform", "press", "click", "set_value", "focus"].includes(actionType);
  const elementId = optionalText(record.elementId);
  if (elementRequired && !elementId) {
    throw new UniversalBrokerError("PRECONDITION_FAILED", `${actionType} requires elementId.`);
  }
  const actionName = optionalText(record.actionName);
  if (actionType === "perform" && !actionName) {
    throw new UniversalBrokerError("PRECONDITION_FAILED", "perform requires actionName.");
  }
  const actionValue = optionalText(record.value, true);
  if (["set_value", "keystroke"].includes(actionType) && actionValue === undefined) {
    throw new UniversalBrokerError("PRECONDITION_FAILED", `${actionType} requires value.`);
  }
  const modifiers = normalizeModifiers(record.modifiers);
  const keyCode = record.keyCode === undefined
    ? undefined
    : boundedInteger(Number(record.keyCode), Number(record.keyCode), 0, 255, "action.keyCode");
  if (actionType === "key_code" && keyCode === undefined) {
    throw new UniversalBrokerError("PRECONDITION_FAILED", "key_code requires keyCode.");
  }
  return {
    type: actionType,
    ...(elementId ? { elementId } : {}),
    ...(actionName ? { actionName } : {}),
    ...(actionValue !== undefined ? { value: actionValue } : {}),
    modifiers,
    ...(keyCode !== undefined ? { keyCode } : {}),
  };
}

function normalizeModifiers(value: unknown): string[] {
  if (value === undefined) return [];
  if (!Array.isArray(value)) {
    throw new UniversalBrokerError("PRECONDITION_FAILED", "action.modifiers must be an array.");
  }
  const allowed = new Set(["command", "option", "control", "shift"]);
  const result = [...new Set(value.map((entry) => String(entry).toLowerCase()))];
  const unsupported = result.find((entry) => !allowed.has(entry));
  if (unsupported) {
    throw new UniversalBrokerError("PRECONDITION_FAILED", `Unsupported GUI modifier: ${unsupported}`);
  }
  return result;
}

function observationGeneration(targetId: string, observation: GuiObservation): string {
  const stableObservation = {
    application: observation.application,
    window: observation.window
      ? {
          title: observation.window.title,
          role: observation.window.role,
          subrole: observation.window.subrole,
        }
      : null,
    elements: observation.elements.map((element) => ({
      elementId: element.elementId,
      index: element.index,
      role: element.role,
      subrole: element.subrole,
      name: element.name,
      description: element.description,
      value: element.value,
      enabled: element.enabled,
      actions: element.actions,
    })),
  };
  return createHash("sha256")
    .update(JSON.stringify({ targetId, observation: stableObservation }))
    .digest("hex")
    .slice(0, 24);
}

interface GuiFocusEvidence {
  applicationPid: number;
  applicationName: string;
  windowTitle: string;
  focusedElementId?: string;
}

function focusEvidence(observation: GuiObservation): GuiFocusEvidence {
  const focusedElementId = observation.elements.find((element) => element.focused)?.elementId;
  return {
    applicationPid: observation.application.pid,
    applicationName: observation.application.name,
    windowTitle: observation.window?.title ?? "",
    ...(focusedElementId ? { focusedElementId } : {}),
  };
}

function sameFocus(left: GuiFocusEvidence, right: GuiFocusEvidence): boolean {
  return left.applicationPid === right.applicationPid
    && left.windowTitle === right.windowTitle
    && left.focusedElementId === right.focusedElementId;
}

function actionRequiresFocusChange(
  action: NormalizedGuiAction,
  element: GuiElementObservation | undefined,
): boolean {
  if (action.type === "focus") return element?.focused !== true;
  if (action.type === "keystroke" && element) return element.focused !== true;
  return false;
}

function normalizeFocusPolicy(value: "preserve" | "allow" | undefined): "preserve" | "allow" {
  return value ?? "preserve";
}

function guiActionResultUnknown(
  session: GuiSession,
  action: NormalizedGuiAction,
  focusBefore: GuiFocusEvidence,
  error: unknown,
  phase: string,
): UniversalBrokerError {
  return new UniversalBrokerError(
    "GUI_STATE_CHANGED",
    `GUI action result is unknown because ${phase}; the action was not retried.`,
    {
      evidence: {
        sessionId: session.sessionId,
        targetId: session.targetId,
        generation: session.generation,
        actionType: action.type,
        dispatchState: "UNKNOWN",
        providerDispatchCount: 1,
        replayed: false,
        focusBefore,
        cause: errorMessage(error).slice(0, 300),
      },
    },
  );
}

function guiStateChanged(
  session: GuiSession,
  expectedGeneration: string,
  actualGeneration: string,
  reason: string,
): UniversalBrokerError {
  return new UniversalBrokerError(
    "GUI_STATE_CHANGED",
    `GUI state changed before action: ${reason}. Observe again before acting.`,
    {
      evidence: {
        sessionId: session.sessionId,
        targetId: session.targetId,
        expectedGeneration,
        actualGeneration,
        providerDispatchCount: 0,
      },
    },
  );
}

function guiNodeErrorCode(code: string | undefined):
  | "GUI_STATE_CHANGED"
  | "CAPABILITY_UNAVAILABLE"
  | "PRECONDITION_FAILED"
  | "MCP_PROVIDER_ERROR" {
  switch (code) {
    case "GUI_STATE_CHANGED":
    case "CAPABILITY_UNAVAILABLE":
    case "PRECONDITION_FAILED":
      return code;
    default:
      return "MCP_PROVIDER_ERROR";
  }
}

function requiredRecord(value: unknown, message: string): Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new UniversalBrokerError("MCP_PROVIDER_ERROR", message);
  }
  return value as Record<string, unknown>;
}

function requiredText(value: string | undefined, message: string): string {
  if (!value?.trim()) throw new UniversalBrokerError("PRECONDITION_FAILED", message);
  return value;
}

function optionalText(value: unknown, allowEmpty = false): string | undefined {
  if (value === undefined || value === null) return undefined;
  if (typeof value !== "string" || (!allowEmpty && !value)) {
    throw new UniversalBrokerError("PRECONDITION_FAILED", "GUI action text field is invalid.");
  }
  return value;
}

function normalizedString(value: unknown, maximum: number): string {
  if (value === undefined || value === null) return "";
  return String(value).slice(0, maximum);
}

function requiredInteger(value: unknown, field: string): number {
  const parsed = Number(value);
  if (!Number.isSafeInteger(parsed) || parsed < 0) {
    throw new UniversalBrokerError("MCP_PROVIDER_ERROR", `${field} is invalid.`);
  }
  return parsed;
}

function nonNegativeInteger(value: unknown, fallback: number): number {
  const parsed = Number(value);
  return Number.isSafeInteger(parsed) && parsed >= 0 ? parsed : fallback;
}

function normalizePair(value: unknown): [number, number] | null {
  if (!Array.isArray(value) || value.length < 2) return null;
  const left = Number(value[0]);
  const right = Number(value[1]);
  return Number.isFinite(left) && Number.isFinite(right) ? [left, right] : null;
}

function boundedInteger(
  value: number | undefined,
  fallback: number,
  minimum: number,
  maximum: number,
  field: string,
): number {
  const parsed = value ?? fallback;
  if (!Number.isInteger(parsed) || parsed < minimum || parsed > maximum) {
    throw new UniversalBrokerError(
      "PRECONDITION_FAILED",
      `${field} must be an integer from ${minimum} through ${maximum}.`,
    );
  }
  return parsed;
}

function dirnameForTarget(path: string, target: TargetDefinition): string {
  return target.transport === "local" ? dirname(path) : posix.dirname(path);
}

function base64(value: string): string {
  return Buffer.from(value, "utf8").toString("base64");
}

function shellQuote(value: string): string {
  return `'${value.replaceAll("'", `'"'"'`)}'`;
}

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}
