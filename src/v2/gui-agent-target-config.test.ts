import assert from "node:assert/strict";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { UniversalBrokerError } from "./errors.js";
import { TargetRegistry } from "./targets.js";

const SHA256 = "a".repeat(64);

test("target registry preserves an exact signed GUI agent identity", async (t) => {
  const root = await mkdtemp(join(tmpdir(), "devspace-gui-agent-target-"));
  t.after(() => rm(root, { recursive: true, force: true }));
  const agent = join(root, "DevSpace GUI Agent.app/Contents/MacOS/devspace-gui-agent");
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
        gui: {
          mode: "local-ipc",
          command: agent,
          sha256: SHA256,
        },
      },
    },
  }));
  const registry = new TargetRegistry({ configPath });
  const target = await registry.resolve("local");
  assert.equal(target.gui.mode, "local-ipc");
  assert.equal(target.gui.command, agent);
  assert.equal(target.gui.sha256, SHA256);
});

test("target registry rejects partial or incompatible signed GUI agent configuration", async (t) => {
  const root = await mkdtemp(join(tmpdir(), "devspace-gui-agent-target-invalid-"));
  t.after(() => rm(root, { recursive: true, force: true }));

  for (const [label, platform, gui, pattern] of [
    ["missing-hash", "macos", { mode: "local-ipc", command: "/private/tmp/gui-agent" }, /configured together/u],
    ["missing-command", "macos", { mode: "local-ipc", sha256: SHA256 }, /configured together/u],
    ["wrong-platform", "linux", { mode: "ssh-stdio", command: "/tmp/gui-agent", sha256: SHA256 }, /only on macOS/u],
    ["disabled-mode", "macos", { mode: "none", command: "/private/tmp/gui-agent", sha256: SHA256 }, /cannot use gui\.mode=none/u],
  ] as const) {
    const configPath = join(root, `${label}.json`);
    await writeFile(configPath, JSON.stringify({
      version: 1,
      targets: {
        target: {
          displayName: label,
          aliases: [label],
          transport: platform === "macos" ? "local" : "ssh",
          ...(platform === "macos" ? {} : { sshHost: "fixture" }),
          platform,
          shell: platform === "macos" ? "zsh" : "bash",
          defaultCwd: platform === "macos" ? root : "/tmp",
          gui,
        },
      },
    }));
    const registry = new TargetRegistry({ configPath });
    await assert.rejects(
      registry.list(),
      (error: unknown) => error instanceof UniversalBrokerError
        && error.code === "PRECONDITION_FAILED"
        && pattern.test(JSON.stringify(error.evidence)),
      label,
    );
  }
});
