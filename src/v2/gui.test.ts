import assert from "node:assert/strict";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import type { UniversalExecutionPlane } from "./execution.js";
import type { UniversalFilesystemService } from "./filesystem.js";
import {
  type GuiNodeRequest,
  type GuiNodeRunner,
  UniversalGuiService,
} from "./gui.js";
import { UniversalBrokerError } from "./errors.js";
import { GUI_NODE_APPLESCRIPT_SOURCE } from "./gui-node.js";
import { TargetRegistry, type TargetDefinition } from "./targets.js";

test("GUI node uses bounded traversal instead of materializing entire accessibility trees", () => {
  assert.doesNotMatch(GUI_NODE_APPLESCRIPT_SOURCE, /entire contents/u);
  assert.match(GUI_NODE_APPLESCRIPT_SOURCE, /boundedElements\(frontWindow, maximumScan\)/u);
  assert.match(GUI_NODE_APPLESCRIPT_SOURCE, /maximumScan < 2/u);
  assert.match(GUI_NODE_APPLESCRIPT_SOURCE, /maximumScan > 1000/u);
});

test("gui capabilities and observe create a bounded generation session", async (t) => {
  const fixture = await createFixture(t);
  const capabilities = await fixture.gui.execute({ operation: "capabilities" });
  assert.equal(capabilities.available, true);
  assert.equal(capabilities.targetId, "local");

  const observed = await fixture.gui.execute({
    operation: "observe",
    maxElements: 100,
  });
  assert.equal(typeof observed.sessionId, "string");
  assert.equal(typeof observed.generation, "string");
  assert.equal((observed.elements as unknown[]).length, 2);
  assert.ok(Number(observed.payloadCharacters) <= 12_000);
});

test("gui act rejects stale state without dispatching an action", async (t) => {
  const fixture = await createFixture(t);
  const observed = await fixture.gui.execute({ operation: "observe" });
  fixture.runner.state = observation("Changed title", "AXPress");
  await assert.rejects(
    fixture.gui.execute({
      operation: "act",
      sessionId: String(observed.sessionId),
      generation: String(observed.generation),
      action: { type: "press", elementId: "e1" },
    }),
    hasCode("GUI_STATE_CHANGED"),
  );
  assert.equal(fixture.runner.actions.length, 0);
});

test("gui act verifies an advertised action and returns a new observation", async (t) => {
  const fixture = await createFixture(t);
  const observed = await fixture.gui.execute({ operation: "observe" });
  const acted = await fixture.gui.execute({
    operation: "act",
    sessionId: String(observed.sessionId),
    generation: String(observed.generation),
    action: { type: "perform", elementId: "e1", actionName: "AXPress" },
  });
  assert.equal(fixture.runner.actions.length, 1);
  assert.equal(fixture.runner.actions[0]?.actionType, "perform");
  const next = acted.observation as { generation?: string; application?: { name?: string } };
  assert.notEqual(next.generation, observed.generation);
  assert.equal(next.application?.name, "After Action");

  const refreshed = await fixture.gui.execute({
    operation: "observe",
    sessionId: String(observed.sessionId),
  });
  await assert.rejects(
    fixture.gui.execute({
      operation: "act",
      sessionId: String(observed.sessionId),
      generation: String(refreshed.generation),
      action: { type: "perform", elementId: "e1", actionName: "AXShowMenu" },
    }),
    hasCode("CAPABILITY_UNAVAILABLE"),
  );
});

test("gui wait reports a changed generation and a timeout deterministically", async (t) => {
  let now = 1_000;
  const fixture = await createFixture(t, {
    now: () => now,
    sleep: async (milliseconds) => {
      now += milliseconds;
      if (now >= 1_250) fixture.runner.state = observation("Wait changed", "AXPress");
    },
  });
  const observed = await fixture.gui.execute({ operation: "observe" });
  const changed = await fixture.gui.execute({
    operation: "wait",
    sessionId: String(observed.sessionId),
    generation: String(observed.generation),
    timeoutMs: 1_000,
  });
  assert.equal(changed.changed, true);

  const latest = changed.observation as { generation?: string };
  const timedOut = await fixture.gui.execute({
    operation: "wait",
    sessionId: String(observed.sessionId),
    generation: String(latest.generation),
    timeoutMs: 0,
  });
  assert.equal(timedOut.changed, false);
});

test("gui observation payload trims elements instead of exceeding its budget", async (t) => {
  const fixture = await createFixture(t, { payloadBudgetCharacters: 2_000 });
  fixture.runner.state = {
    ...observation("Large", "AXPress"),
    elements: Array.from({ length: 100 }, (_, index) => ({
      elementId: `e${index}`,
      index,
      role: "AXButton",
      subrole: "",
      name: `button-${index}-${"x".repeat(100)}`,
      description: "y".repeat(100),
      value: "",
      enabled: true,
      focused: false,
      position: [index, index],
      size: [100, 20],
      actions: ["AXPress"],
    })),
    totalElements: 100,
  };
  const observed = await fixture.gui.execute({ operation: "observe", maxElements: 100 });
  assert.ok(Number(observed.payloadCharacters) <= 2_000);
  assert.equal(observed.truncated, true);
  assert.ok((observed.elements as unknown[]).length < 100);
  assert.ok(Number(observed.omittedElements) > 0);
});

test("gui sessions expire and configured non-macOS targets fail explicitly", async (t) => {
  let now = 1_000;
  const fixture = await createFixture(t, { now: () => now, sessionTtlMs: 1_000 });
  const observed = await fixture.gui.execute({ operation: "observe" });
  now = 2_001;
  await assert.rejects(
    fixture.gui.execute({
      operation: "observe",
      sessionId: String(observed.sessionId),
    }),
    hasCode("PATH_NOT_FOUND"),
  );
  const capabilities = await fixture.gui.execute({
    operation: "capabilities",
    target: "linux",
  });
  assert.equal(capabilities.available, false);
  assert.equal(capabilities.platform, "linux");
});

test("gui capabilities report configured remote TCC denial as unavailable without advertising usability", async (t) => {
  const fixture = await createFixture(t);
  fixture.runner.unavailableTargets.add("company");
  const capabilities = await fixture.gui.execute({
    operation: "capabilities",
    target: "company",
  });
  assert.equal(capabilities.targetId, "company");
  assert.equal(capabilities.configured, true);
  assert.equal(capabilities.available, false);
  assert.equal(capabilities.guiMode, "ssh-stdio");
  assert.match(String(capabilities.reason), /Accessibility|TCC/i);
});

test("gui capabilities include a reason when the node reports accessibility=false", async (t) => {
  const fixture = await createFixture(t);
  fixture.runner.disabledTargets.add("company");
  const capabilities = await fixture.gui.execute({
    operation: "capabilities",
    target: "company",
  });
  assert.equal(capabilities.configured, true);
  assert.equal(capabilities.available, false);
  assert.match(String(capabilities.reason), /Accessibility/i);
});

class FixtureGuiRunner implements GuiNodeRunner {
  state = observation("Initial", "AXPress");
  readonly actions: GuiNodeRequest[] = [];
  readonly unavailableTargets = new Set<string>();
  readonly disabledTargets = new Set<string>();

  async call(target: TargetDefinition, request: GuiNodeRequest): Promise<Record<string, unknown>> {
    if (request.operation === "capabilities") {
      if (this.unavailableTargets.has(target.id)) {
        throw new UniversalBrokerError(
          "CAPABILITY_UNAVAILABLE",
          `macOS Accessibility/TCC is unavailable for ${target.id}.`,
        );
      }
      return {
        platform: "macos",
        accessibility: !this.disabledTargets.has(target.id),
        screenCapture: "not_probed",
        frontmostProcess: { name: this.state.application.name, pid: this.state.application.pid },
      };
    }
    if (request.operation === "observe") return structuredClone(this.state);
    this.actions.push(structuredClone(request));
    this.state = observation("After Action", "AXPress");
    return { performed: true, actionType: request.actionType };
  }
}

interface Fixture {
  gui: UniversalGuiService;
  runner: FixtureGuiRunner;
}

async function createFixture(
  t: test.TestContext,
  options: {
    now?: () => number;
    sleep?: (milliseconds: number) => Promise<void>;
    sessionTtlMs?: number;
    payloadBudgetCharacters?: number;
  } = {},
): Promise<Fixture> {
  const root = await mkdtemp(join(tmpdir(), "devspace-v2-gui-test-"));
  t.after(() => rm(root, { recursive: true, force: true }));
  const targetsPath = join(root, "targets.json");
  await writeFile(targetsPath, JSON.stringify({
    version: 1,
    targets: {
      local: {
        displayName: "Local",
        aliases: ["local"],
        transport: "local",
        platform: "macos",
        gui: { mode: "local-ipc" },
      },
      linux: {
        displayName: "Linux",
        aliases: ["linux"],
        transport: "ssh",
        sshHost: "linux.invalid",
        platform: "linux",
        gui: { mode: "none" },
      },
      company: {
        displayName: "Company Mac",
        aliases: ["company"],
        transport: "ssh",
        sshHost: "company.invalid",
        platform: "macos",
        gui: { mode: "ssh-stdio" },
      },
    },
  }));
  const targets = new TargetRegistry({ configPath: targetsPath });
  const runner = new FixtureGuiRunner();
  const gui = new UniversalGuiService(
    targets,
    {} as UniversalFilesystemService,
    {} as UniversalExecutionPlane,
    { runner, ...options },
  );
  t.after(() => gui.close());
  return { gui, runner };
}

function observation(applicationName: string, action: string) {
  return {
    application: {
      name: applicationName,
      bundleIdentifier: "com.example.fixture",
      pid: 123,
    },
    window: {
      title: "Fixture Window",
      role: "AXWindow",
      subrole: "AXStandardWindow",
      position: [0, 0],
      size: [800, 600],
    },
    elements: [
      {
        elementId: "e0",
        index: 0,
        role: "AXWindow",
        subrole: "AXStandardWindow",
        name: "Fixture Window",
        description: "",
        value: "",
        enabled: true,
        focused: true,
        position: [0, 0],
        size: [800, 600],
        actions: [],
      },
      {
        elementId: "e1",
        index: 1,
        role: "AXButton",
        subrole: "",
        name: "Confirm",
        description: "confirm",
        value: "",
        enabled: true,
        focused: false,
        position: [100, 100],
        size: [80, 24],
        actions: [action],
      },
    ],
    totalElements: 2,
    omittedElements: 0,
    truncated: false,
  };
}

function hasCode(code: string) {
  return (error: unknown) => error instanceof Error && "code" in error && error.code === code;
}
