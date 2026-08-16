import assert from "node:assert/strict";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { TargetRegistry } from "./targets.js";

test("target registry supplies local by default and resolves exact aliases", async (t) => {
  const root = await mkdtemp(join(tmpdir(), "devspace-v2-targets-test-"));
  t.after(() => rm(root, { recursive: true, force: true }));
  const registry = new TargetRegistry({ configPath: join(root, "missing.json") });

  const listed = await registry.list();
  assert.equal(listed.targets.length, 1);
  assert.equal(listed.targets[0]?.targetId, "local");
  assert.equal((await registry.resolve("내 맥")).id, "local");
  const probe = await registry.probe("local");
  assert.equal(probe.status, "ONLINE");
  assert.equal(probe.capabilities.fs, true);
  assert.equal(probe.capabilities.exec, true);
});

test("target registry hot reloads configuration without changing tool schema", async (t) => {
  const root = await mkdtemp(join(tmpdir(), "devspace-v2-targets-test-"));
  t.after(() => rm(root, { recursive: true, force: true }));
  const configPath = join(root, "targets.json");
  await writeTargetConfig(configPath, {
    company: sshTarget("Company Mac", ["회사맥"]),
  });
  const registry = new TargetRegistry({ configPath });
  const first = await registry.inspect();
  assert.equal((await registry.resolve("회사맥")).id, "company");

  await writeTargetConfig(configPath, {
    company: sshTarget("Company Mac", ["회사맥"]),
    build: sshTarget("Build server", ["빌드서버"]),
  });
  const second = await registry.inspect();
  assert.notEqual(first.generation, second.generation);
  assert.equal((await registry.resolve("빌드서버")).id, "build");
  assert.deepEqual((await registry.list()).targets.map((target) => target.targetId), [
    "local",
    "build",
    "company",
  ]);
});

test("target registry reports authoritative candidates instead of guessing", async (t) => {
  const root = await mkdtemp(join(tmpdir(), "devspace-v2-targets-test-"));
  t.after(() => rm(root, { recursive: true, force: true }));
  const configPath = join(root, "targets.json");
  await writeTargetConfig(configPath, {
    first: sshTarget("First", ["shared"]),
    second: sshTarget("Second", ["shared"]),
  });
  const registry = new TargetRegistry({ configPath });

  await assert.rejects(
    registry.resolve("shared"),
    (error: unknown) => error instanceof Error
      && "code" in error
      && error.code === "TARGET_AMBIGUOUS",
  );
  await assert.rejects(
    registry.resolve("invented"),
    (error: unknown) => error instanceof Error
      && "code" in error
      && error.code === "TARGET_NOT_FOUND",
  );
});

test("target registry validates SSH prerequisites and offline probes are cached", async (t) => {
  const root = await mkdtemp(join(tmpdir(), "devspace-v2-targets-test-"));
  t.after(() => rm(root, { recursive: true, force: true }));
  const configPath = join(root, "targets.json");
  await writeFile(configPath, JSON.stringify({
    version: 1,
    targets: {
      broken: {
        displayName: "Broken",
        transport: "ssh",
        platform: "linux",
      },
    },
  }));
  const invalid = new TargetRegistry({ configPath });
  await assert.rejects(invalid.inspect(), /Invalid target registry/);

  let calls = 0;
  await writeTargetConfig(configPath, {
    offline: sshTarget("Offline", ["offline"]),
  });
  const registry = new TargetRegistry({
    configPath,
    execute: (async () => {
      calls += 1;
      throw new Error("connection refused");
    }) as never,
  });
  const first = await registry.probe("offline");
  const second = await registry.probe("offline");
  assert.equal(first.status, "OFFLINE");
  assert.equal(second.status, "OFFLINE");
  assert.equal(calls, 1);
});

test("target registry rejects legacy elevation fields and modes", async (t) => {
  const root = await mkdtemp(join(tmpdir(), "devspace-v2-targets-authority-test-"));
  t.after(() => rm(root, { recursive: true, force: true }));
  const configPath = join(root, "targets.json");
  const target = {
    displayName: "Remote",
    transport: "ssh",
    sshHost: "remote",
    platform: "linux",
  };

  for (const forbidden of [
    { ...target, privilege: "admin" },
    { ...target, helper: { mode: "sudo-n" } },
  ]) {
    await writeFile(configPath, JSON.stringify({ version: 1, targets: { remote: forbidden } }));
    await assert.rejects(
      new TargetRegistry({ configPath }).inspect(),
      /Invalid target registry/,
    );
  }
});

test("Windows SSH probes report the target temporary directory", async (t) => {
  const root = await mkdtemp(join(tmpdir(), "devspace-v2-targets-windows-test-"));
  t.after(() => rm(root, { recursive: true, force: true }));
  const configPath = join(root, "targets.json");
  await writeFile(configPath, JSON.stringify({
    version: 1,
    targets: {
      windows: {
        displayName: "Windows",
        transport: "ssh",
        sshHost: "windows",
        platform: "windows",
        shell: "powershell",
      },
    },
  }));
  const registry = new TargetRegistry({
    configPath,
    execute: (async () => ({
      stdout: [
        "__DEVSPACE_TARGET_V1__",
        "architecture=AMD64",
        "home=C:\\Users\\test",
        "temporary=C:\\Users\\test\\AppData\\Local\\Temp\\",
        "git=1",
        "",
      ].join("\n"),
      stderr: "",
    })) as never,
  });

  const observation = await registry.probe("windows");
  assert.equal(observation.status, "ONLINE");
  assert.equal(observation.temporaryDirectory, "C:\\Users\\test\\AppData\\Local\\Temp\\");
});

function sshTarget(displayName: string, aliases: string[]) {
  return {
    displayName,
    aliases,
    transport: "ssh",
    sshHost: displayName.toLowerCase().replaceAll(" ", "-"),
    platform: "linux",
  };
}

async function writeTargetConfig(
  path: string,
  targets: Record<string, ReturnType<typeof sshTarget>>,
): Promise<void> {
  await writeFile(path, JSON.stringify({ version: 1, targets }, null, 2));
}
