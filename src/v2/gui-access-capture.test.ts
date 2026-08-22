import assert from "node:assert/strict";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { createCapabilityCallContextFromTrustedPrincipal } from "./capability-call-context.js";
import {
  UniversalGuiService,
  type GuiNodeRequest,
  type GuiNodeRunner,
} from "./gui.js";
import { UniversalBrokerError } from "./errors.js";
import { TargetRegistry } from "./targets.js";

const PRINCIPAL = "1".repeat(64);

test("GUI execute dispatches request_access and capture through the configured target runner", async (t) => {
  const root = await mkdtemp(join(tmpdir(), "devspace-gui-access-capture-"));
  t.after(() => rm(root, { recursive: true, force: true }));
  const configPath = join(root, "targets.json");
  await writeFile(configPath, JSON.stringify({
    version: 1,
    targets: {
      local: {
        displayName: "Local",
        aliases: ["local"],
        transport: "local",
        platform: "macos",
        shell: "zsh",
        defaultCwd: root,
        gui: { mode: "local-ipc" },
      },
    },
  }));
  const targets = new TargetRegistry({ configPath });
  const calls: GuiNodeRequest[] = [];
  const runner: GuiNodeRunner = {
    async call(_target, request) {
      calls.push(request);
      if (request.operation === "request_access") {
        return {
          requested: { accessibility: true, screenCapture: true },
          accessibility: true,
          screenCapture: true,
          restartRequired: false,
        };
      }
      if (request.operation === "capture") {
        return {
          contentBase64: "YWJj",
          mimeType: "image/jpeg",
          size: 3,
          sha256: `sha256:${"a".repeat(64)}`,
          width: 640,
          height: 480,
        };
      }
      throw new Error(`unexpected GUI operation: ${request.operation}`);
    },
  };
  const service = Object.create(UniversalGuiService.prototype) as UniversalGuiService;
  Object.assign(service as unknown as Record<string, unknown>, {
    targets,
    runner,
    closed: false,
    now: Date.now,
    sessions: new Map(),
  });
  const context = createCapabilityCallContextFromTrustedPrincipal({
    principalKeyFingerprint: PRINCIPAL,
    requestId: "gui-access-capture",
    explicitRequestId: "gui-access-capture",
    requestNamespace: "test:gui-access-capture",
  });

  const access = await service.execute({
    operation: "request_access",
    target: "local",
    permissions: ["screen_capture", "accessibility", "screen_capture"],
  }, context);
  assert.equal(access.targetId, "local");
  assert.deepEqual(access.permissions, ["screen_capture", "accessibility"]);
  assert.equal(access.accessibility, true);
  assert.equal(access.screenCapture, true);

  const capture = await service.execute({
    operation: "capture",
    target: "local",
    format: "jpeg",
    quality: 82,
    maxWidth: 1280,
  }, context);
  assert.equal(capture.targetId, "local");
  assert.equal(capture.format, "jpeg");
  assert.equal(capture.quality, 82);
  assert.equal(capture.maxWidth, 1280);
  assert.equal(capture.contentBase64, "YWJj");
  assert.equal(calls.length, 2);
  assert.deepEqual(calls[0], {
    operation: "request_access",
    permissions: ["screen_capture", "accessibility"],
  });
  assert.deepEqual(calls[1], {
    operation: "capture",
    format: "jpeg",
    quality: 82,
    maxWidth: 1280,
  });
});

test("GUI execute rejects empty permissions and out-of-range capture values before provider dispatch", async (t) => {
  const root = await mkdtemp(join(tmpdir(), "devspace-gui-access-negative-"));
  t.after(() => rm(root, { recursive: true, force: true }));
  const configPath = join(root, "targets.json");
  await writeFile(configPath, JSON.stringify({
    version: 1,
    targets: {
      local: {
        displayName: "Local",
        aliases: ["local"],
        transport: "local",
        platform: "macos",
        shell: "zsh",
        defaultCwd: root,
        gui: { mode: "local-ipc" },
      },
    },
  }));
  const targets = new TargetRegistry({ configPath });
  let dispatches = 0;
  const service = Object.create(UniversalGuiService.prototype) as UniversalGuiService;
  Object.assign(service as unknown as Record<string, unknown>, {
    targets,
    runner: { call: async () => { dispatches += 1; return {}; } },
    closed: false,
    now: Date.now,
    sessions: new Map(),
  });
  const context = createCapabilityCallContextFromTrustedPrincipal({
    principalKeyFingerprint: PRINCIPAL,
  });

  await assert.rejects(
    service.execute({ operation: "request_access", target: "local", permissions: [] }, context),
    (error: unknown) => error instanceof UniversalBrokerError
      && error.code === "INVALID_ARGUMENT"
      && error.evidence?.providerDispatchCount === 0,
  );
  for (const input of [
    { operation: "capture" as const, target: "local", quality: 0 },
    { operation: "capture" as const, target: "local", quality: 101 },
    { operation: "capture" as const, target: "local", maxWidth: 319 },
    { operation: "capture" as const, target: "local", maxWidth: 2561 },
  ]) {
    await assert.rejects(service.execute(input, context), /quality|maxWidth/u);
  }
  assert.equal(dispatches, 0);
});
