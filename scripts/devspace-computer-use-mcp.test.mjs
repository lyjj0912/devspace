import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { once } from "node:events";
import { chmod, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import test from "node:test";

const serverPath = resolve("scripts/devspace-computer-use-mcp.mjs");
const toolNames = [
  "list_apps",
  "get_app_state",
  "click",
  "perform_secondary_action",
  "set_value",
  "select_text",
  "scroll",
  "drag",
  "press_key",
  "type_text",
];

test("native Computer Use MCP exposes the fixed tools and preserves mutation/readback semantics", async (t) => {
  const root = await mkdtemp(join(tmpdir(), "devspace-computer-use-mcp-"));
  t.after(() => rm(root, { recursive: true, force: true }));
  const statePath = join(root, "state.json");
  const agent = join(root, "fake-agent.mjs");
  await writeFile(statePath, `${JSON.stringify({ value: "before", applied: false })}\n`, { mode: 0o600 });
  await writeFile(agent, fakeAgentSource(statePath), { mode: 0o700 });
  await chmod(agent, 0o700);
  const client = await createClient(t, agent);

  const initialized = await client.request("initialize", {
    protocolVersion: "2025-06-18",
    capabilities: {},
    clientInfo: { name: "computer-use-test", version: "1" },
  });
  assert.equal(initialized.result.serverInfo.name, "devspace-native-computer-use");

  const listed = await client.request("tools/list");
  assert.deepEqual(listed.result.tools.map((tool) => tool.name), toolNames);

  const apps = toolResult(await client.request("tools/call", {
    name: "list_apps",
    arguments: {},
  }));
  assert.equal(apps.structuredContent.apps.length, 1);
  assert.equal(apps.structuredContent.apps[0].bundleIdentifier, "com.devspace.fixture");

  let state = toolResult(await client.request("tools/call", {
    name: "get_app_state",
    arguments: { app: "com.devspace.fixture" },
  }));
  assert.equal(state.structuredContent.application.pid, 4242);
  assert.equal(state.structuredContent.elements.find((element) => element.name === "input").value, "before");
  assert.match(state.structuredContent.screenshot.sha256, /^sha256:[a-f0-9]{64}$/u);

  toolResult(await client.request("tools/call", {
    name: "set_value",
    arguments: { app: "com.devspace.fixture", element_index: "1", value: "actual-value" },
  }));
  state = toolResult(await client.request("tools/call", {
    name: "get_app_state",
    arguments: { app: "com.devspace.fixture" },
  }));
  assert.equal(state.structuredContent.elements.find((element) => element.name === "input").value, "actual-value");

  toolResult(await client.request("tools/call", {
    name: "click",
    arguments: { app: "com.devspace.fixture", element_index: "2" },
  }));
  state = toolResult(await client.request("tools/call", {
    name: "get_app_state",
    arguments: { app: "com.devspace.fixture" },
  }));
  assert.equal(state.structuredContent.elements.find((element) => element.name === "status").value, "Applied: actual-value");
  assert.deepEqual(JSON.parse(await readFile(statePath, "utf8")), {
    value: "actual-value",
    applied: true,
  });
});

test("native Computer Use MCP fails closed when the pinned agent rejects a mutation", async (t) => {
  const root = await mkdtemp(join(tmpdir(), "devspace-computer-use-mcp-reject-"));
  t.after(() => rm(root, { recursive: true, force: true }));
  const statePath = join(root, "state.json");
  const agent = join(root, "fake-agent.mjs");
  await writeFile(statePath, `${JSON.stringify({ value: "before", applied: false, reject: true })}\n`, { mode: 0o600 });
  await writeFile(agent, fakeAgentSource(statePath), { mode: 0o700 });
  await chmod(agent, 0o700);
  const client = await createClient(t, agent);
  await client.request("initialize", {
    protocolVersion: "2025-06-18",
    capabilities: {},
    clientInfo: { name: "computer-use-reject-test", version: "1" },
  });
  toolResult(await client.request("tools/call", {
    name: "get_app_state",
    arguments: { app: "com.devspace.fixture" },
  }));
  const rejected = await client.request("tools/call", {
    name: "set_value",
    arguments: { app: "com.devspace.fixture", element_index: "1", value: "must-not-apply" },
  });
  assert.equal(rejected.result.isError, true);
  assert.equal(rejected.result.structuredContent.error.code, "GUI_STATE_CHANGED");
  assert.deepEqual(JSON.parse(await readFile(statePath, "utf8")), {
    value: "before",
    applied: false,
    reject: true,
  });
});

async function createClient(t, agent) {
  const child = spawn(process.execPath, [serverPath], {
    cwd: process.cwd(),
    env: {
      PATH: "/usr/bin:/bin:/usr/sbin:/sbin",
      HOME: process.env.HOME,
      LANG: "C.UTF-8",
      DEVSPACE_GUI_AGENT_BINARY: agent,
    },
    stdio: ["pipe", "pipe", "pipe"],
  });
  t.after(async () => {
    child.stdin.end();
    await Promise.race([once(child, "exit"), new Promise((resolvePromise) => setTimeout(resolvePromise, 1_000))]);
    if (child.exitCode === null) child.kill("SIGKILL");
  });
  child.stdout.setEncoding("utf8");
  child.stderr.setEncoding("utf8");
  let stdout = "";
  let stderr = "";
  let id = 0;
  const pending = new Map();
  child.stdout.on("data", (chunk) => {
    stdout += chunk;
    while (true) {
      const newline = stdout.indexOf("\n");
      if (newline < 0) break;
      const line = stdout.slice(0, newline).trim();
      stdout = stdout.slice(newline + 1);
      if (!line) continue;
      const message = JSON.parse(line);
      const waiter = pending.get(message.id);
      if (!waiter) continue;
      pending.delete(message.id);
      clearTimeout(waiter.timer);
      waiter.resolve(message);
    }
  });
  child.stderr.on("data", (chunk) => { stderr = `${stderr}${chunk}`.slice(-4_000); });
  await once(child, "spawn");
  return {
    request(method, params = {}, timeoutMs = 10_000) {
      const requestId = ++id;
      return new Promise((resolvePromise, reject) => {
        const timer = setTimeout(() => {
          pending.delete(requestId);
          reject(new Error(`${method} timed out: ${stderr}`));
        }, timeoutMs);
        pending.set(requestId, { resolve: resolvePromise, timer });
        child.stdin.write(`${JSON.stringify({ jsonrpc: "2.0", id: requestId, method, params })}\n`);
      });
    },
  };
}

function toolResult(message) {
  assert.equal(message.error, undefined, JSON.stringify(message.error));
  assert.notEqual(message.result?.isError, true, JSON.stringify(message.result?.structuredContent));
  return message.result;
}

function fakeAgentSource(statePath) {
  return `#!${process.execPath}
import fs from "node:fs";
import crypto from "node:crypto";
const marker = "__DEVSPACE_V2_GUI_JSON__";
const statePath = ${JSON.stringify(statePath)};
const args = process.argv.slice(2);
const state = JSON.parse(fs.readFileSync(statePath, "utf8"));
const input = { index: 1, role: "AXTextField", subrole: "", name: "input", description: "Input", value: state.value, focused: true, position: [10, 10], size: [100, 30], actions: [] };
const button = { index: 2, role: "AXButton", subrole: "", name: "Apply", description: "Apply", value: "", focused: false, position: [120, 10], size: [80, 30], actions: ["AXPress"] };
const status = { index: 3, role: "AXStaticText", subrole: "", name: "status", description: "Status", value: state.applied ? "Applied: " + state.value : "Not applied", focused: false, position: [10, 60], size: [190, 30], actions: [] };
const observation = { application: { name: "Fixture", bundleIdentifier: "com.devspace.fixture", pid: 4242 }, window: { title: "Fixture", role: "AXWindow", subrole: "AXStandardWindow", position: [0, 0], size: [220, 120] }, elements: [input, button, status], totalElements: 3, omittedElements: 0, truncated: false };
function emit(ok, data, code, message) { process.stdout.write(marker + JSON.stringify({ ok, ...(data ? { data } : {}), ...(code ? { code } : {}), ...(message ? { message } : {}) }) + "\\n"); }
switch (args[0]) {
  case "list-apps": emit(true, { apps: [{ id: "com.devspace.fixture", bundleIdentifier: "com.devspace.fixture", displayName: "Fixture", appPath: "/Applications/Fixture.app", pid: 4242, isRunning: true, isFrontmost: true, lastUsedDate: null, useCount: null }] }); break;
  case "activate": emit(true, { pid: 4242, bundleIdentifier: "com.devspace.fixture", activated: true }); break;
  case "observe": emit(true, observation); break;
  case "capture": { const bytes = Buffer.from("fixture-image"); emit(true, { contentBase64: bytes.toString("base64"), mimeType: "image/jpeg", size: bytes.length, sha256: "sha256:" + crypto.createHash("sha256").update(bytes).digest("hex"), width: 220, height: 120, pid: 4242, windowId: 1 }); break; }
  case "act": {
    if (state.reject) { emit(false, null, "GUI_STATE_CHANGED", "fixture rejected mutation"); break; }
    const type = args[2];
    if (type === "set_value") state.value = Buffer.from(args[4], "base64").toString("utf8");
    if (type === "press") state.applied = true;
    fs.writeFileSync(statePath, JSON.stringify(state));
    emit(true, { performed: true, actionType: type });
    break;
  }
  default: emit(false, null, "INVALID_ARGUMENT", "unsupported fake operation");
}
`;
}
