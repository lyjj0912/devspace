import assert from "node:assert/strict";
import { chmod, mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { loadConfig } from "../config.js";
import { ContextRegistry } from "./contexts.js";
import { UniversalEnvProfileRegistry } from "./env-profiles.js";
import { UniversalExecutionPlane } from "./execution.js";
import { TargetRegistry } from "./targets.js";

test("exec consumes inline and target-local source-file environment profiles", async (t) => {
  const root = await mkdtemp(join(tmpdir(), "devspace-v2-env-integration-"));
  t.after(() => rm(root, { recursive: true, force: true }));
  const profilePath = join(root, "profiles.json");
  const sourceFile = join(root, "source.env");
  await writeFile(sourceFile, "PROFILE_SOURCE_VALUE=from-source\n", { mode: 0o600 });
  await writeFile(profilePath, JSON.stringify({
    version: 1,
    profiles: {
      inline: {
        targets: ["local"],
        environment: { PROFILE_INLINE_VALUE: "from-inline" },
      },
      source: {
        targets: ["local"],
        sourceFile,
      },
    },
  }), { mode: 0o600 });
  await chmod(profilePath, 0o600);
  const config = loadConfig({
    DEVSPACE_CONFIG_DIR: join(root, "config"),
    DEVSPACE_ALLOWED_ROOTS: root,
    DEVSPACE_STATE_DIR: join(root, "legacy"),
    DEVSPACE_WORKTREE_ROOT: join(root, "legacy-worktrees"),
    DEVSPACE_OAUTH_OWNER_TOKEN: "environment-profile-test-owner-token-123456",
    DEVSPACE_PUBLIC_BASE_URL: "http://127.0.0.1:17676",
    DEVSPACE_LOG_LEVEL: "silent",
  });
  const targets = new TargetRegistry({ configPath: join(root, "targets.json") });
  const contexts = new ContextRegistry({
    storePath: join(root, "contexts.json"),
    targets,
    serverConfig: config,
    worktreeRoot: join(root, "worktrees"),
  });
  const execution = new UniversalExecutionPlane({
    targets,
    contexts,
    outputDir: join(root, "output"),
    sshControlDir: join(root, "ssh"),
    maxRunningProcesses: 4,
    maxRunningProcessesPerTarget: 4,
    processBufferCharacters: 100_000,
    processOutputMaxBytes: 1_000_000,
    completedProcessTtlMs: 60_000,
    envProfiles: new UniversalEnvProfileRegistry({ configPath: profilePath }),
  });
  t.after(() => execution.close());

  const inline = await execution.execute({
    target: "local",
    cwd: root,
    command: "printf '%s' \"$PROFILE_INLINE_VALUE\"",
    envProfile: "inline",
    mode: "foreground",
    yieldMs: 10_000,
  });
  assert.equal(inline.output, "from-inline");

  const sourced = await execution.execute({
    target: "local",
    cwd: root,
    command: "printf '%s' \"$PROFILE_SOURCE_VALUE\"",
    envProfile: "source",
    mode: "foreground",
    yieldMs: 10_000,
  });
  assert.equal(sourced.output, "from-source");
});
