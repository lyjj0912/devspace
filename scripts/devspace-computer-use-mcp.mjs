#!/usr/bin/env node
import { createHash } from "node:crypto";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { isAbsolute } from "node:path";
import { access } from "node:fs/promises";
import readline from "node:readline";

const execFileAsync = promisify(execFile);
const PROTOCOL_VERSION = "2025-06-18";
const AGENT_MARKER = "__DEVSPACE_V2_GUI_JSON__";
const MAXIMUM_AGENT_OUTPUT_BYTES = 4 * 1024 * 1024;
const MAXIMUM_ELEMENTS = 500;
const SESSION_TTL_MS = 5 * 60_000;
const AGENT_BINARY = process.env.DEVSPACE_GUI_AGENT_BINARY?.trim();

if (!AGENT_BINARY || !isAbsolute(AGENT_BINARY)) {
  process.stderr.write("DEVSPACE_GUI_AGENT_BINARY must be an absolute path.\n");
  process.exit(78);
}
await access(AGENT_BINARY);

const READ_ONLY = Object.freeze({
  destructiveHint: false,
  idempotentHint: true,
  openWorldHint: false,
  readOnlyHint: true,
});
const MUTATING = Object.freeze({
  destructiveHint: false,
  idempotentHint: false,
  openWorldHint: false,
  readOnlyHint: false,
});
const appProperty = Object.freeze({
  description: "App name, full app path, or unambiguous bundle identifier",
  type: "string",
});
const elementProperty = Object.freeze({
  description: "Element identifier from the most recent get_app_state response",
  type: "string",
});

const TOOL_DEFINITIONS = Object.freeze([
  {
    name: "list_apps",
    description: "List the currently running graphical apps in the active macOS login session.",
    inputSchema: { type: "object", additionalProperties: false, properties: {} },
    annotations: READ_ONLY,
  },
  {
    name: "get_app_state",
    description: "Activate an app, capture its key window, and return a screenshot plus a bounded accessibility tree. Call this before every interaction.",
    inputSchema: {
      type: "object",
      additionalProperties: false,
      properties: { app: appProperty },
      required: ["app"],
    },
    annotations: READ_ONLY,
  },
  {
    name: "click",
    description: "Click an element by index or, when supported, pixel coordinates from the screenshot.",
    inputSchema: {
      type: "object",
      additionalProperties: false,
      properties: {
        app: appProperty,
        click_count: { description: "Number of clicks. Defaults to 1", type: "integer" },
        element_index: elementProperty,
        mouse_button: { description: "Mouse button. Defaults to left.", type: "string", enum: ["left", "right", "middle"] },
        x: { description: "X coordinate in screenshot pixels", type: "number" },
        y: { description: "Y coordinate in screenshot pixels", type: "number" },
      },
      required: ["app"],
    },
    annotations: MUTATING,
  },
  {
    name: "perform_secondary_action",
    description: "Invoke a secondary accessibility action exposed by an element.",
    inputSchema: {
      type: "object",
      additionalProperties: false,
      properties: {
        action: { description: "Secondary accessibility action name", type: "string" },
        app: appProperty,
        element_index: elementProperty,
      },
      required: ["app", "element_index", "action"],
    },
    annotations: MUTATING,
  },
  {
    name: "set_value",
    description: "Set the value of a settable accessibility element.",
    inputSchema: {
      type: "object",
      additionalProperties: false,
      properties: {
        app: appProperty,
        element_index: elementProperty,
        value: { description: "Value to assign", type: "string" },
      },
      required: ["app", "element_index", "value"],
    },
    annotations: MUTATING,
  },
  {
    name: "select_text",
    description: "Select text inside a text element, or place the cursor before or after it.",
    inputSchema: {
      type: "object",
      additionalProperties: false,
      properties: {
        app: appProperty,
        element_index: elementProperty,
        prefix: { type: "string" },
        selection: { type: "string", enum: ["text", "cursor_before", "cursor_after"] },
        suffix: { type: "string" },
        text: { type: "string" },
      },
      required: ["app", "element_index", "text"],
    },
    annotations: MUTATING,
  },
  {
    name: "scroll",
    description: "Scroll an element in a direction by a bounded number of pages.",
    inputSchema: {
      type: "object",
      additionalProperties: false,
      properties: {
        app: appProperty,
        direction: { type: "string", enum: ["up", "down", "left", "right"] },
        element_index: elementProperty,
        pages: { type: "number" },
      },
      required: ["app", "element_index", "direction"],
    },
    annotations: MUTATING,
  },
  {
    name: "drag",
    description: "Drag from one point to another using screenshot coordinates.",
    inputSchema: {
      type: "object",
      additionalProperties: false,
      properties: {
        app: appProperty,
        from_x: { type: "number" }, from_y: { type: "number" },
        to_x: { type: "number" }, to_y: { type: "number" },
      },
      required: ["app", "from_x", "from_y", "to_x", "to_y"],
    },
    annotations: MUTATING,
  },
  {
    name: "press_key",
    description: "Press a key or key combination in the selected app.",
    inputSchema: {
      type: "object",
      additionalProperties: false,
      properties: { app: appProperty, key: { type: "string" } },
      required: ["app", "key"],
    },
    annotations: MUTATING,
  },
  {
    name: "type_text",
    description: "Type literal text into the selected app.",
    inputSchema: {
      type: "object",
      additionalProperties: false,
      properties: { app: appProperty, text: { type: "string" } },
      required: ["app", "text"],
    },
    annotations: MUTATING,
  },
]);

class ProviderError extends Error {
  constructor(code, message, evidence = {}) {
    super(message);
    this.name = "ProviderError";
    this.code = code;
    this.evidence = evidence;
  }
}

const sessions = new Map();

function boundedText(value, field, maximum = 16_384) {
  if (typeof value !== "string") throw new ProviderError("INVALID_ARGUMENT", `${field} must be a string.`);
  const normalized = value.trim();
  if (!normalized || normalized.length > maximum || /[\0\r\n]/u.test(normalized)) {
    throw new ProviderError("INVALID_ARGUMENT", `${field} is empty or outside the supported bounds.`);
  }
  return normalized;
}

function optionalText(value, field, maximum = 16_384) {
  if (value === undefined) return undefined;
  if (typeof value !== "string" || value.length > maximum || /\0/u.test(value)) {
    throw new ProviderError("INVALID_ARGUMENT", `${field} is invalid.`);
  }
  return value;
}

function boundedInteger(value, field, fallback, minimum, maximum) {
  const resolved = value === undefined ? fallback : value;
  if (!Number.isInteger(resolved) || resolved < minimum || resolved > maximum) {
    throw new ProviderError("INVALID_ARGUMENT", `${field} must be an integer from ${minimum} through ${maximum}.`);
  }
  return resolved;
}

function finiteNumber(value, field) {
  if (typeof value !== "number" || !Number.isFinite(value)) {
    throw new ProviderError("INVALID_ARGUMENT", `${field} must be a finite number.`);
  }
  return value;
}

function encode(value) {
  return Buffer.from(value ?? "", "utf8").toString("base64");
}

function canonicalJson(value) {
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  if (value && typeof value === "object") {
    return `{${Object.entries(value)
      .filter(([, child]) => child !== undefined)
      .sort(([left], [right]) => left.localeCompare(right))
      .map(([key, child]) => `${JSON.stringify(key)}:${canonicalJson(child)}`)
      .join(",")}}`;
  }
  return JSON.stringify(value) ?? "null";
}

function digest(value) {
  return `sha256:${createHash("sha256").update(canonicalJson(value)).digest("hex")}`;
}

function sessionKey(app) {
  return app.bundleIdentifier || app.id || `pid:${app.pid}`;
}

async function callAgent(args, timeoutMs = 60_000) {
  let stdout;
  let stderr;
  try {
    ({ stdout, stderr } = await execFileAsync(AGENT_BINARY, args, {
      encoding: "utf8",
      timeout: timeoutMs,
      maxBuffer: MAXIMUM_AGENT_OUTPUT_BYTES,
      env: { ...process.env, NO_COLOR: "1" },
    }));
  } catch (error) {
    throw new ProviderError("CAPABILITY_UNAVAILABLE", "The signed GUI agent could not be executed.", {
      cause: error instanceof Error ? error.message.slice(0, 500) : String(error).slice(0, 500),
    });
  }
  const markerIndex = stdout.lastIndexOf(AGENT_MARKER);
  if (markerIndex < 0) {
    throw new ProviderError("MCP_PROVIDER_ERROR", "The signed GUI agent returned no bounded result marker.", {
      stderr: String(stderr ?? "").replace(/[\r\n\0]+/gu, " ").slice(0, 500),
    });
  }
  let payload;
  try {
    payload = JSON.parse(stdout.slice(markerIndex + AGENT_MARKER.length).trim());
  } catch (error) {
    throw new ProviderError("MCP_PROVIDER_ERROR", "The signed GUI agent returned invalid JSON.", {
      cause: error instanceof Error ? error.message : String(error),
    });
  }
  if (!payload || typeof payload !== "object") {
    throw new ProviderError("MCP_PROVIDER_ERROR", "The signed GUI agent result is not an object.");
  }
  if (payload.ok !== true) {
    throw new ProviderError(
      typeof payload.code === "string" ? payload.code : "MCP_PROVIDER_ERROR",
      typeof payload.message === "string" ? payload.message : "The signed GUI agent rejected the request.",
    );
  }
  if (!payload.data || typeof payload.data !== "object") {
    throw new ProviderError("MCP_PROVIDER_ERROR", "The signed GUI agent returned no data object.");
  }
  return payload.data;
}

async function listRunningApps() {
  const result = await callAgent(["list-apps"]);
  if (!Array.isArray(result.apps)) throw new ProviderError("MCP_PROVIDER_ERROR", "GUI agent app inventory is invalid.");
  return result.apps
    .filter((app) => app && typeof app === "object" && Number.isInteger(app.pid) && app.pid > 0)
    .map((app) => ({
      id: typeof app.id === "string" && app.id ? app.id : `pid:${app.pid}`,
      displayName: typeof app.displayName === "string" ? app.displayName : "",
      bundleIdentifier: typeof app.bundleIdentifier === "string" ? app.bundleIdentifier : "",
      appPath: typeof app.appPath === "string" ? app.appPath : "",
      pid: app.pid,
      isRunning: true,
      isFrontmost: app.isFrontmost === true,
      lastUsedDate: typeof app.lastUsedDate === "string" ? app.lastUsedDate : null,
      useCount: Number.isFinite(app.useCount) ? app.useCount : null,
    }));
}

async function resolveApp(selector) {
  const requested = boundedText(selector, "app", 1024);
  const apps = await listRunningApps();
  const normalized = requested.toLocaleLowerCase();
  const exact = apps.filter((app) => [app.id, app.bundleIdentifier, app.displayName, app.appPath]
    .some((value) => value && value.toLocaleLowerCase() === normalized));
  if (exact.length === 1) return exact[0];
  if (exact.length > 1) throw new ProviderError("PRECONDITION_FAILED", `App selector is ambiguous: ${requested}`);
  const partial = apps.filter((app) => [app.displayName, app.bundleIdentifier]
    .some((value) => value && value.toLocaleLowerCase().includes(normalized)));
  if (partial.length === 1) return partial[0];
  if (partial.length > 1) {
    throw new ProviderError("PRECONDITION_FAILED", `App selector matches multiple running apps: ${requested}`, {
      matches: partial.slice(0, 20).map((app) => app.id),
    });
  }
  throw new ProviderError("PATH_NOT_FOUND", `No running graphical app matches: ${requested}`);
}

async function activateApp(app) {
  const result = await callAgent(["activate", String(app.pid)], 15_000);
  if (result.activated !== true || result.pid !== app.pid) {
    throw new ProviderError("GUI_STATE_CHANGED", `App process changed while activating ${app.id}.`);
  }
}

function renderObservation(observation) {
  const app = observation.application ?? {};
  const window = observation.window && typeof observation.window === "object" ? observation.window : null;
  const lines = [
    `App: ${String(app.name ?? "")} (${String(app.bundleIdentifier ?? "")}, pid=${String(app.pid ?? "")})`,
    `Window: ${window ? String(window.title ?? "") : "<none>"}`,
  ];
  for (const element of Array.isArray(observation.elements) ? observation.elements : []) {
    const actions = Array.isArray(element.actions) ? element.actions.join(",") : "";
    lines.push(
      `[${String(element.index)}] ${String(element.role ?? "")} ${JSON.stringify(String(element.name ?? ""))}`
      + ` value=${JSON.stringify(String(element.value ?? ""))}`
      + (actions ? ` actions=${actions}` : ""),
    );
  }
  if (observation.truncated === true) lines.push("[Accessibility tree truncated by bounded traversal]");
  return lines.join("\n");
}

async function getAppState(args) {
  const app = await resolveApp(args.app);
  await activateApp(app);
  const observation = await callAgent(["observe", String(MAXIMUM_ELEMENTS), String(app.pid)]);
  if (observation.application?.pid !== app.pid) {
    throw new ProviderError("GUI_STATE_CHANGED", "The observed application process changed before state capture.");
  }
  const capture = await callAgent(["capture", "jpeg", "70", "1600", String(app.pid)]);
  const text = renderObservation(observation);
  const generation = digest({
    application: observation.application,
    window: observation.window,
    elements: observation.elements,
  });
  sessions.set(sessionKey(app), {
    app,
    observation,
    capture: {
      width: capture.width,
      height: capture.height,
      pid: capture.pid,
      windowId: capture.windowId,
    },
    generation,
    observedAt: Date.now(),
  });
  return {
    result: {
      content: [
        { type: "text", text },
        { type: "image", data: capture.contentBase64, mimeType: capture.mimeType },
      ],
      structuredContent: {
        app: app.id,
        application: observation.application,
        window: observation.window,
        elements: observation.elements,
        totalElements: observation.totalElements,
        omittedElements: observation.omittedElements,
        truncated: observation.truncated,
        generation,
        screenshot: {
          mimeType: capture.mimeType,
          size: capture.size,
          sha256: capture.sha256,
          width: capture.width,
          height: capture.height,
          pid: capture.pid,
          windowId: capture.windowId,
        },
      },
    },
  };
}

async function requireSession(selector) {
  const app = await resolveApp(selector);
  const key = sessionKey(app);
  const session = sessions.get(key);
  if (!session || Date.now() - session.observedAt > SESSION_TTL_MS) {
    sessions.delete(key);
    throw new ProviderError("PRECONDITION_FAILED", `Call get_app_state for ${app.id} before interacting with it.`);
  }
  if (session.app.pid !== app.pid) {
    sessions.delete(key);
    throw new ProviderError("GUI_STATE_CHANGED", `App ${app.id} restarted after get_app_state.`);
  }
  return session;
}

function elementFromSession(session, value) {
  const text = boundedText(value, "element_index", 64);
  const numeric = /^\d+$/u.test(text) ? Number(text) : undefined;
  if (!Number.isInteger(numeric) || numeric < 0 || numeric > 1000) {
    throw new ProviderError("INVALID_ARGUMENT", "element_index must be the numeric index from get_app_state.");
  }
  const element = session.observation.elements?.find((candidate) => candidate.index === numeric);
  if (!element) throw new ProviderError("GUI_STATE_CHANGED", `Element ${text} is absent from the current GUI session.`);
  return element;
}

function screenshotPointToScreen(session, xValue, yValue) {
  const x = finiteNumber(xValue, "x");
  const y = finiteNumber(yValue, "y");
  const window = session.observation.window;
  const position = window && Array.isArray(window.position) ? window.position : undefined;
  const size = window && Array.isArray(window.size) ? window.size : undefined;
  const capture = session.capture;
  if (
    !position || position.length !== 2 || !size || size.length !== 2
    || !capture || !Number.isFinite(capture.width) || !Number.isFinite(capture.height)
    || capture.width <= 0 || capture.height <= 0
    || !position.every(Number.isFinite) || !size.every(Number.isFinite)
    || size[0] <= 0 || size[1] <= 0
  ) {
    throw new ProviderError("GUI_STATE_CHANGED", "The current GUI session has no stable window geometry.");
  }
  if (x < 0 || y < 0 || x > capture.width || y > capture.height) {
    throw new ProviderError("INVALID_ARGUMENT", "Screenshot coordinates are outside the captured window.");
  }
  return {
    x: position[0] + (x / capture.width) * size[0],
    y: position[1] + (y / capture.height) * size[1],
  };
}

async function agentAct(session, actionType, element, options = {}) {
  await activateApp(session.app);
  const windowTitle = session.observation.window && typeof session.observation.window === "object"
    ? String(session.observation.window.title ?? "")
    : "";
  const args = [
    "act",
    String(element?.index ?? -1),
    actionType,
    encode(options.actionName ?? ""),
    encode(options.value ?? ""),
    Array.isArray(options.modifiers) ? options.modifiers.join(",") : "",
    String(options.keyCode ?? -1),
    String(session.app.pid),
    encode(windowTitle),
    encode(element?.role ?? ""),
    encode(element?.name ?? ""),
    encode(element?.description ?? ""),
    encode(element?.subrole ?? ""),
  ];
  const result = await callAgent(args);
  if (result.performed !== true) throw new ProviderError("CAPABILITY_UNAVAILABLE", "GUI action was not performed.");
  sessions.delete(sessionKey(session.app));
  return result;
}

function keyRequest(value) {
  const raw = boundedText(value, "key", 128);
  const pieces = raw.split("+").map((piece) => piece.trim()).filter(Boolean);
  const key = pieces.pop();
  if (!key) throw new ProviderError("INVALID_ARGUMENT", "key is missing.");
  const modifiers = pieces.map((piece) => {
    switch (piece.toLocaleLowerCase()) {
      case "super": case "cmd": case "command": return "command";
      case "alt": case "option": return "option";
      case "ctrl": case "control": return "control";
      case "shift": return "shift";
      default: throw new ProviderError("INVALID_ARGUMENT", `Unsupported key modifier: ${piece}`);
    }
  });
  const namedCodes = new Map([
    ["return", 36], ["enter", 36], ["tab", 48], ["space", 49],
    ["backspace", 51], ["delete", 51], ["escape", 53], ["esc", 53],
    ["left", 123], ["right", 124], ["down", 125], ["up", 126],
    ["home", 115], ["end", 119], ["pageup", 116], ["pagedown", 121],
  ]);
  const code = namedCodes.get(key.toLocaleLowerCase());
  if (code !== undefined) return { type: "key_code", keyCode: code, modifiers };
  if ([...key].length === 1) return { type: "keystroke", value: key, modifiers };
  throw new ProviderError("INVALID_ARGUMENT", `Unsupported key name: ${key}`);
}

async function handleTool(name, args) {
  const input = args && typeof args === "object" && !Array.isArray(args) ? args : {};
  switch (name) {
    case "list_apps": {
      const apps = await listRunningApps();
      return success({ apps, coverage: "running_graphical_apps" }, JSON.stringify(apps));
    }
    case "get_app_state":
      return (await getAppState({ app: boundedText(input.app, "app", 1024) })).result;
    case "click": {
      const session = await requireSession(input.app);
      if (input.element_index === undefined) {
        if (input.x === undefined || input.y === undefined) {
          throw new ProviderError("INVALID_ARGUMENT", "click requires element_index or both x and y coordinates.");
        }
        const count = boundedInteger(input.click_count, "click_count", 1, 1, 3);
        const button = input.mouse_button === undefined ? "left" : boundedText(input.mouse_button, "mouse_button", 16);
        if (!new Set(["left", "right", "middle"]).has(button)) {
          throw new ProviderError("INVALID_ARGUMENT", `Unsupported mouse_button: ${button}`);
        }
        const point = screenshotPointToScreen(session, input.x, input.y);
        await activateApp(session.app);
        const result = await callAgent([
          "pointer-click",
          String(session.app.pid),
          String(point.x),
          String(point.y),
          String(count),
          button,
        ]);
        if (result.performed !== true) throw new ProviderError("CAPABILITY_UNAVAILABLE", "Pointer click was not performed.");
        sessions.delete(sessionKey(session.app));
        return success({
          performed: true,
          app: session.app.id,
          screenshotPoint: { x: input.x, y: input.y },
          screenPoint: point,
          clickCount: count,
          mouseButton: button,
        });
      }
      const element = elementFromSession(session, input.element_index);
      const count = boundedInteger(input.click_count, "click_count", 1, 1, 3);
      const button = input.mouse_button === undefined ? "left" : boundedText(input.mouse_button, "mouse_button", 16);
      if (button !== "left") throw new ProviderError("CAPABILITY_UNAVAILABLE", "Accessibility element click currently supports the left button only.");
      for (let index = 0; index < count; index += 1) await agentAct(session, "press", element);
      return success({ performed: true, app: session.app.id, elementIndex: element.index, clickCount: count });
    }
    case "perform_secondary_action": {
      const session = await requireSession(input.app);
      const element = elementFromSession(session, input.element_index);
      const action = boundedText(input.action, "action", 120);
      await agentAct(session, "perform", element, { actionName: action });
      return success({ performed: true, app: session.app.id, elementIndex: element.index, action });
    }
    case "set_value": {
      const session = await requireSession(input.app);
      const element = elementFromSession(session, input.element_index);
      if (!Object.prototype.hasOwnProperty.call(input, "value")) {
        throw new ProviderError("INVALID_ARGUMENT", "set_value requires value.");
      }
      const value = optionalText(input.value, "value", 16_384) ?? "";
      await agentAct(session, "set_value", element, { value });
      return success({ performed: true, app: session.app.id, elementIndex: element.index });
    }
    case "type_text": {
      const session = await requireSession(input.app);
      if (!Object.prototype.hasOwnProperty.call(input, "text")) {
        throw new ProviderError("INVALID_ARGUMENT", "type_text requires text.");
      }
      const text = optionalText(input.text, "text", 1024) ?? "";
      await agentAct(session, "keystroke", undefined, { value: text });
      return success({ performed: true, app: session.app.id, characters: [...text].length });
    }
    case "press_key": {
      const session = await requireSession(input.app);
      const request = keyRequest(input.key);
      await agentAct(session, request.type, undefined, request);
      return success({ performed: true, app: session.app.id, key: input.key });
    }
    case "scroll": {
      const session = await requireSession(input.app);
      const element = elementFromSession(session, input.element_index);
      const direction = boundedText(input.direction, "direction", 16).toLocaleLowerCase();
      const actionNames = { up: "AXScrollUpByPage", down: "AXScrollDownByPage", left: "AXScrollLeftByPage", right: "AXScrollRightByPage" };
      const actionName = actionNames[direction];
      if (!actionName) throw new ProviderError("INVALID_ARGUMENT", `Unsupported scroll direction: ${direction}`);
      const pages = input.pages === undefined ? 1 : finiteNumber(input.pages, "pages");
      if (pages <= 0 || pages > 10 || !Number.isInteger(pages)) {
        throw new ProviderError("INVALID_ARGUMENT", "pages must currently be an integer from 1 through 10.");
      }
      for (let index = 0; index < pages; index += 1) await agentAct(session, "perform", element, { actionName });
      return success({ performed: true, app: session.app.id, elementIndex: element.index, direction, pages });
    }
    case "select_text": {
      const session = await requireSession(input.app);
      const element = elementFromSession(session, input.element_index);
      const text = boundedText(input.text, "text", 16_384);
      const prefix = optionalText(input.prefix, "prefix", 16_384) ?? "";
      const suffix = optionalText(input.suffix, "suffix", 16_384) ?? "";
      const selection = input.selection === undefined
        ? "text"
        : boundedText(input.selection, "selection", 64);
      if (!new Set(["text", "cursor_before", "cursor_after"]).has(selection)) {
        throw new ProviderError("INVALID_ARGUMENT", `Unsupported selection mode: ${selection}`);
      }
      await agentAct(session, "select_text", element, {
        value: JSON.stringify({ text, prefix, suffix, selection }),
      });
      return success({
        performed: true,
        app: session.app.id,
        elementIndex: element.index,
        selection,
      });
    }
    case "drag": {
      const session = await requireSession(input.app);
      const from = screenshotPointToScreen(session, input.from_x, input.from_y);
      const to = screenshotPointToScreen(session, input.to_x, input.to_y);
      await activateApp(session.app);
      const result = await callAgent([
        "pointer-drag",
        String(session.app.pid),
        String(from.x),
        String(from.y),
        String(to.x),
        String(to.y),
      ]);
      if (result.performed !== true) throw new ProviderError("CAPABILITY_UNAVAILABLE", "Pointer drag was not performed.");
      sessions.delete(sessionKey(session.app));
      return success({
        performed: true,
        app: session.app.id,
        fromScreenshotPoint: { x: input.from_x, y: input.from_y },
        toScreenshotPoint: { x: input.to_x, y: input.to_y },
        fromScreenPoint: from,
        toScreenPoint: to,
      });
    }
    default:
      throw new ProviderError("MCP_TOOL_NOT_FOUND", `Unknown Computer Use tool: ${name}`);
  }
}

function success(data, text = "Computer Use operation completed.") {
  return {
    content: [{ type: "text", text }],
    structuredContent: data,
  };
}

function toolFailure(error) {
  const normalized = error instanceof ProviderError
    ? error
    : new ProviderError("MCP_PROVIDER_ERROR", error instanceof Error ? error.message : String(error));
  return {
    isError: true,
    content: [{ type: "text", text: normalized.message }],
    structuredContent: {
      ok: false,
      error: {
        code: normalized.code,
        message: normalized.message,
        evidence: normalized.evidence,
      },
    },
  };
}

function send(message) {
  process.stdout.write(`${JSON.stringify(message)}\n`);
}

async function handleRequest(message) {
  const id = message.id;
  try {
    switch (message.method) {
      case "initialize":
        send({
          jsonrpc: "2.0",
          id,
          result: {
            protocolVersion: PROTOCOL_VERSION,
            capabilities: { tools: { listChanged: false } },
            serverInfo: { name: "devspace-native-computer-use", version: "1.0.0" },
            instructions: "Call get_app_state before every interaction. Actions are PID- and accessibility-fingerprint-bound.",
          },
        });
        return;
      case "ping":
        send({ jsonrpc: "2.0", id, result: {} });
        return;
      case "tools/list":
        send({ jsonrpc: "2.0", id, result: { tools: TOOL_DEFINITIONS } });
        return;
      case "tools/call": {
        const name = message.params?.name;
        if (typeof name !== "string") throw new ProviderError("INVALID_ARGUMENT", "tools/call requires a tool name.");
        let result;
        try {
          result = await handleTool(name, message.params?.arguments ?? {});
        } catch (error) {
          result = toolFailure(error);
        }
        send({ jsonrpc: "2.0", id, result });
        return;
      }
      default:
        send({ jsonrpc: "2.0", id, error: { code: -32601, message: `Method not found: ${String(message.method)}` } });
    }
  } catch (error) {
    send({
      jsonrpc: "2.0",
      id,
      error: {
        code: -32603,
        message: error instanceof Error ? error.message : String(error),
      },
    });
  }
}

const input = readline.createInterface({ input: process.stdin, crlfDelay: Infinity });
input.on("line", (line) => {
  const trimmed = line.trim();
  if (!trimmed) return;
  let message;
  try {
    message = JSON.parse(trimmed);
  } catch {
    send({ jsonrpc: "2.0", id: null, error: { code: -32700, message: "Parse error" } });
    return;
  }
  if (!message || message.jsonrpc !== "2.0" || typeof message.method !== "string") {
    send({ jsonrpc: "2.0", id: message?.id ?? null, error: { code: -32600, message: "Invalid Request" } });
    return;
  }
  if (message.id === undefined) return;
  void handleRequest(message);
});
input.on("close", () => process.exit(0));
