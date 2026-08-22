import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { chmod, mkdtemp, readFile, realpath, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import {
  internalExecutionSpec,
  type GuiAgentInternalExecutionPolicy,
} from "./no-elevation.js";
import { UniversalBrokerError } from "./errors.js";

const hasBoundaryError = (error: unknown): boolean => error instanceof UniversalBrokerError
  && error.code === "ELEVATION_BLOCKED";

test("pinned GUI agent accepts only exact bounded protocol commands", async (t) => {
  const root = await realpath(await mkdtemp(join(tmpdir(), "devspace-gui-agent-boundary-")));
  t.after(() => rm(root, { recursive: true, force: true }));
  const executablePath = join(root, "devspace-gui-agent");
  await writeFile(executablePath, "#!/bin/zsh\nexit 0\n", { mode: 0o700 });
  await chmod(executablePath, 0o700);
  const executableSha256 = createHash("sha256")
    .update(await readFile(executablePath))
    .digest("hex");
  const policy: GuiAgentInternalExecutionPolicy = {
    kind: "gui-agent",
    executablePath,
    executableSha256,
  };

  assert.deepEqual(
    internalExecutionSpec(policy, `${executablePath} capabilities`, { verifyLocalScript: true }),
    { executable: executablePath, args: ["capabilities"] },
  );
  assert.deepEqual(
    internalExecutionSpec(
      policy,
      `${executablePath} request-access accessibility,screen_capture`,
      { verifyLocalScript: true },
    ),
    { executable: executablePath, args: ["request-access", "accessibility,screen_capture"] },
  );
  assert.deepEqual(
    internalExecutionSpec(policy, `${executablePath} observe 100`, { verifyLocalScript: true }),
    { executable: executablePath, args: ["observe", "100"] },
  );
  assert.deepEqual(
    internalExecutionSpec(policy, `${executablePath} observe 100 12345`, { verifyLocalScript: true }),
    { executable: executablePath, args: ["observe", "100", "12345"] },
  );
  assert.deepEqual(
    internalExecutionSpec(policy, `${executablePath} capture jpeg 70 1600`, { verifyLocalScript: true }),
    { executable: executablePath, args: ["capture", "jpeg", "70", "1600"] },
  );

  for (const command of [
    `/bin/zsh -lc '${executablePath} capabilities'`,
    `${executablePath} request-access accessibility,sudo`,
    `${executablePath} observe 0`,
    `${executablePath} observe 1001`,
    `${executablePath} observe 100 0`,
    `${executablePath} observe 100 2147483648`,
    `${executablePath} observe 100 not-a-pid`,
    `${executablePath} capture gif 70 1600`,
    `${executablePath} capture jpeg 0 1600`,
    `${executablePath} capture jpeg 70 99999`,
    `${executablePath} sudo id`,
  ]) {
    assert.throws(
      () => internalExecutionSpec(policy, command, { verifyLocalScript: true }),
      hasBoundaryError,
      command,
    );
  }
});

test("pinned GUI agent rejects digest, owner-safe mode, and canonical-path drift before execution", async (t) => {
  const root = await realpath(await mkdtemp(join(tmpdir(), "devspace-gui-agent-integrity-")));
  t.after(() => rm(root, { recursive: true, force: true }));
  const executablePath = join(root, "devspace-gui-agent");
  await writeFile(executablePath, "#!/bin/zsh\nexit 0\n", { mode: 0o700 });
  const originalDigest = createHash("sha256")
    .update(await readFile(executablePath))
    .digest("hex");
  const policy: GuiAgentInternalExecutionPolicy = {
    kind: "gui-agent",
    executablePath,
    executableSha256: originalDigest,
  };

  await writeFile(executablePath, "#!/bin/zsh\nexit 1\n", { mode: 0o700 });
  assert.throws(
    () => internalExecutionSpec(policy, `${executablePath} capabilities`, { verifyLocalScript: true }),
    hasBoundaryError,
  );

  const changedDigest = createHash("sha256")
    .update(await readFile(executablePath))
    .digest("hex");
  await chmod(executablePath, 0o722);
  assert.throws(
    () => internalExecutionSpec(
      { ...policy, executableSha256: changedDigest },
      `${executablePath} capabilities`,
      { verifyLocalScript: true },
    ),
    hasBoundaryError,
  );

  assert.throws(
    () => internalExecutionSpec(
      { ...policy, executablePath: `${root}/../${root.split("/").at(-1)}/devspace-gui-agent` },
      `${root}/../${root.split("/").at(-1)}/devspace-gui-agent capabilities`,
      { verifyLocalScript: true },
    ),
    hasBoundaryError,
  );
});
