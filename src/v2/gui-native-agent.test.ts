import assert from "node:assert/strict";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { createCapabilityCallContextFromTrustedPrincipal } from "./capability-call-context.js";
import { MacOsGuiNodeRunner } from "./gui.js";
import { GUI_NODE_RESULT_MARKER } from "./gui-node.js";
import { TargetRegistry } from "./targets.js";

const PRINCIPAL = "1".repeat(64);
const EXECUTABLE_SHA256 = "a".repeat(64);

test("native GUI agent route emits exact pinned protocol commands and parses framed results", async (t) => {
  const root = await mkdtemp(join(tmpdir(), "devspace-native-gui-runner-"));
  t.after(() => rm(root, { recursive: true, force: true }));
  const agent = join(root, "devspace-gui-agent");
  await writeFile(agent, "native-agent-fixture\n", { mode: 0o700 });
  const targetsPath = join(root, "targets.json");
  await writeFile(targetsPath, JSON.stringify({
    version: 1,
    targets: {
      local: {
        displayName: "Local",
        aliases: ["local"],
        transport: "local",
        platform: "macos",
        shell: "zsh",
        defaultCwd: root,
        gui: {
          mode: "local-ipc",
          command: agent,
          sha256: EXECUTABLE_SHA256,
        },
      },
    },
  }));
  const targets = new TargetRegistry({ configPath: targetsPath });
  const target = await targets.resolve("local");
  const calls: Array<Record<string, unknown>> = [];
  const outputs: Array<Record<string, unknown>> = [
    { platform: "macos", accessibility: true, screenCapture: true, bundleIdentifier: "com.devspace.gui-agent" },
    { requested: { accessibility: true, screenCapture: true }, accessibility: true, screenCapture: true, restartRequired: false },
    { application: { name: "Fixture", bundleIdentifier: "com.devspace.fixture", pid: 123 }, window: { title: "Fixture" }, elements: [], totalElements: 0, omittedElements: 0, truncated: false },
    { performed: true, actionType: "press" },
    { contentBase64: "YWJj", mimeType: "image/jpeg", size: 3, sha256: `sha256:${"b".repeat(64)}`, width: 640, height: 480 },
  ];
  const runner = new MacOsGuiNodeRunner(
    targets,
    {} as never,
    {
      run: async (input: Record<string, unknown>) => {
        calls.push(input);
        const data = outputs.shift();
        assert.ok(data);
        return {
          state: "EXITED",
          exitCode: 0,
          output: `${GUI_NODE_RESULT_MARKER}${JSON.stringify({ ok: true, data })}\n`,
        };
      },
    } as never,
  );
  const context = createCapabilityCallContextFromTrustedPrincipal({
    principalKeyFingerprint: PRINCIPAL,
    requestId: "gui-native-agent-test",
    explicitRequestId: "gui-native-agent-test",
    requestNamespace: "test:gui-native-agent",
  });

  const capabilities = await runner.call(target, { operation: "capabilities" }, context);
  assert.equal(capabilities.accessibility, true);
  assert.equal(capabilities.screenCapture, true);
  const access = await runner.call(target, {
    operation: "request_access",
    permissions: ["accessibility", "screen_capture"],
  }, context);
  assert.equal(access.restartRequired, false);
  const observation = await runner.call(target, { operation: "observe", maxElements: 25 }, context);
  assert.equal((observation.application as { pid: number }).pid, 123);
  const action = await runner.call(target, {
    operation: "act",
    elementIndex: 0,
    actionType: "press",
    expected: {
      pid: 123,
      windowTitle: "Fixture",
      role: "AXButton",
      name: "Run",
      description: "",
      subrole: "",
    },
  }, context);
  assert.equal(action.performed, true);
  const capture = await runner.call(target, {
    operation: "capture",
    format: "jpeg",
    quality: 70,
    maxWidth: 1600,
  }, context);
  assert.equal(capture.contentBase64, "YWJj");

  assert.equal(calls.length, 5);
  for (const call of calls) {
    const policy = call.internalPolicy as Record<string, unknown>;
    assert.equal(policy.kind, "gui-agent");
    assert.equal(policy.executablePath, agent);
    assert.equal(policy.executableSha256, EXECUTABLE_SHA256);
    assert.doesNotMatch(String(call.command), /osascript|gui-node\.applescript/u);
    assert.match(String(call.command), new RegExp(agent.replace(/[.*+?^${}()|[\]\\]/g, "\\$&"), "u"));
  }
  assert.match(String(calls[0]?.command), / 'capabilities'$/u);
  assert.match(String(calls[1]?.command), / 'request-access' 'accessibility,screen_capture'$/u);
  assert.match(String(calls[2]?.command), / 'observe' '25'$/u);
  assert.match(String(calls[3]?.command), / 'act' /u);
  assert.match(String(calls[4]?.command), / 'capture' 'jpeg' '70' '1600'$/u);
});
