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
  const calls: Array<{ executable: string; args: string[] }> = [];
  const registry = new TargetRegistry({
    configPath,
    execute: (async (executable: string, args: string[]) => {
      calls.push({ executable, args });
      if (executable === "sftp") return { stdout: "", stderr: "" };
      if (args.includes("-tt")) return { stdout: "__DEVSPACE_PTY_OK__\r\n", stderr: "" };
      return {
        stdout: [
          "__DEVSPACE_TARGET_V1__",
          "architecture=AMD64",
          "home=C:\\Users\\test",
          "temporary=C:\\Users\\test\\AppData\\Local\\Temp\\",
          "git=1",
          "elevated=0",
          "",
        ].join("\n"),
        stderr: "",
      };
    }) as never,
  });

  const observation = await registry.probe("windows");
  assert.equal(observation.status, "ONLINE");
  assert.equal(observation.temporaryDirectory, "C:\\Users\\test\\AppData\\Local\\Temp\\");
  assert.equal(observation.capabilities.pty, true);
  assert.equal(observation.capabilities.sftp, true);
  assert.equal(observation.capabilities.fs, true);
  assert.equal(calls.length, 3);
  const base = calls.find((call) => call.executable === "ssh" && call.args.includes("-T"));
  const pty = calls.find((call) => call.executable === "ssh" && call.args.includes("-tt"));
  const sftp = calls.find((call) => call.executable === "sftp");
  assert.ok(base);
  assert.ok(pty);
  assert.ok(sftp);
  assert.match(pty.args.at(-1) ?? "", /powershell\.exe -NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -EncodedCommand/u);
  const encoded = /-EncodedCommand\s+([A-Za-z0-9+/=]+)$/u.exec(pty.args.at(-1) ?? "")?.[1];
  assert.ok(encoded);
  const source = Buffer.from(encoded, "base64").toString("utf16le");
  assert.match(source, /__DEVSPACE_PTY_OK__/u);
  assert.match(source, /__DEVSPACE_PTY_ELEVATED_TOKEN_BLOCKED__/u);
  assert.match(source, /S-1-16-\(12288\|16384\)/u);
  assert.deepEqual(sftp.args.slice(0, 4), ["-q", "-b", "/dev/null", "-o"]);
  assert.equal(sftp.args.at(-1), "windows");
});

test("POSIX SSH probes degrade when the runtime no-elevation primitive is unavailable", async (t) => {
  const root = await mkdtemp(join(tmpdir(), "devspace-v2-target-boundary-test-"));
  t.after(() => rm(root, { recursive: true, force: true }));
  const configPath = join(root, "targets.json");
  await writeTargetConfig(configPath, {
    linux: sshTarget("Linux", ["linux"]),
  });
  const registry = new TargetRegistry({
    configPath,
    execute: (async () => ({
      stdout: [
        "__DEVSPACE_TARGET_V1__",
        "kernel=Linux",
        "architecture=x86_64",
        "home=/home/test",
        "temporary=/tmp",
        "git=1",
        "rsync=1",
        "setpriv_boundary=0",
        "sandbox_boundary=0",
        "",
      ].join("\n"),
      stderr: "",
    })) as never,
  });
  const observation = await registry.probe("linux");
  assert.equal(observation.status, "DEGRADED");
  assert.equal(observation.capabilities.exec, false);
  assert.match(observation.reason ?? "", /setpriv/u);
});

test("POSIX SSH probes verify PTY and SFTP once, cache the result, and refresh explicitly", async (t) => {
  const root = await mkdtemp(join(tmpdir(), "devspace-v2-target-capability-test-"));
  t.after(() => rm(root, { recursive: true, force: true }));
  const configPath = join(root, "targets.json");
  await writeTargetConfig(configPath, {
    company: {
      ...sshTarget("Company", ["company"]),
      platform: "macos",
    },
  });
  const calls: Array<{ executable: string; args: string[] }> = [];
  const registry = new TargetRegistry({
    configPath,
    execute: (async (executable: string, args: string[]) => {
      calls.push({ executable, args });
      if (executable === "sftp") return { stdout: "", stderr: "" };
      if (args.includes("-tt")) {
        return { stdout: "__DEVSPACE_PTY_OK__\r\n", stderr: "" };
      }
      return {
        stdout: [
          "__DEVSPACE_TARGET_V1__",
          "kernel=Darwin",
          "architecture=arm64",
          "home=/Users/test",
          "temporary=/var/folders/test/",
          "git=1",
          "rsync=1",
          "setpriv_boundary=0",
          "sandbox_boundary=1",
          "",
        ].join("\n"),
        stderr: "",
      };
    }) as never,
  });

  const first = await registry.probe("company");
  assert.equal(first.status, "ONLINE");
  assert.equal(first.capabilities.pty, true);
  assert.equal(first.capabilities.sftp, true);
  assert.equal(first.capabilities.fs, true);
  assert.equal((first.evidence as { cache?: string }).cache, "miss");
  assert.equal(calls.length, 3);

  const cached = await registry.probe("company");
  assert.equal((cached.evidence as { cache?: string }).cache, "hit");
  assert.equal(calls.length, 3);

  const refreshed = await registry.probe("company", { refresh: true });
  assert.equal((refreshed.evidence as { cache?: string }).cache, "miss");
  assert.equal(calls.length, 6);
  const previousGeneration = (refreshed.evidence as { targetGeneration?: string }).targetGeneration;
  await writeTargetConfig(configPath, {
    company: {
      ...sshTarget("Company reloaded", ["company"]),
      platform: "macos",
    },
  });
  const reloaded = await registry.probe("company");
  assert.equal((reloaded.evidence as { cache?: string }).cache, "miss");
  assert.notEqual(
    (reloaded.evidence as { targetGeneration?: string }).targetGeneration,
    previousGeneration,
  );
  assert.equal(calls.length, 9);
  assert.deepEqual(registry.stats(), {
    probeCacheEntries: 1,
    probeInFlight: 0,
    probeCacheHits: 1,
    probeCacheMisses: 3,
    probeCoalesced: 0,
    probeOnline: 3,
    probeDegraded: 0,
    probeOffline: 0,
    probeDurationMsTotal: (registry.stats() as { probeDurationMsTotal: number }).probeDurationMsTotal,
    averageProbeDurationMs: (registry.stats() as { averageProbeDurationMs: number }).averageProbeDurationMs,
    lastProbeDurationMs: (registry.stats() as { lastProbeDurationMs: number }).lastProbeDurationMs,
  });
});

test("concurrent probes for one generation share a single SSH capability probe", async (t) => {
  const root = await mkdtemp(join(tmpdir(), "devspace-v2-target-coalescing-test-"));
  t.after(() => rm(root, { recursive: true, force: true }));
  const configPath = join(root, "targets.json");
  await writeTargetConfig(configPath, {
    company: {
      ...sshTarget("Company", ["company"]),
      platform: "macos",
    },
  });
  let calls = 0;
  const registry = new TargetRegistry({
    configPath,
    execute: (async (executable: string, args: string[]) => {
      calls += 1;
      await new Promise((resolvePromise) => setTimeout(resolvePromise, 10));
      if (executable === "sftp") return { stdout: "", stderr: "" };
      if (args.includes("-tt")) return { stdout: "__DEVSPACE_PTY_OK__\r\n", stderr: "" };
      return {
        stdout: [
          "__DEVSPACE_TARGET_V1__",
          "kernel=Darwin",
          "architecture=arm64",
          "home=/Users/test",
          "temporary=/tmp",
          "git=1",
          "rsync=1",
          "setpriv_boundary=0",
          "sandbox_boundary=1",
          "",
        ].join("\n"),
        stderr: "",
      };
    }) as never,
  });

  const [first, shared] = await Promise.all([
    registry.probe("company", { refresh: true }),
    registry.probe("company", { refresh: true }),
  ]);
  assert.equal(first.status, "ONLINE");
  assert.equal(shared.status, "ONLINE");
  assert.deepEqual(
    new Set([
      (first.evidence as { cache?: string }).cache,
      (shared.evidence as { cache?: string }).cache,
    ]),
    new Set(["miss", "shared"]),
  );
  assert.equal(calls, 3);
  const stats = registry.stats();
  assert.equal(stats.probeCacheMisses, 1);
  assert.equal(stats.probeCoalesced, 1);
  assert.equal(stats.probeInFlight, 0);
});

test("a registry reload prevents an older in-flight probe from repopulating stale cache", async (t) => {
  const root = await mkdtemp(join(tmpdir(), "devspace-v2-target-stale-probe-test-"));
  t.after(() => rm(root, { recursive: true, force: true }));
  const configPath = join(root, "targets.json");
  await writeTargetConfig(configPath, {
    company: {
      ...sshTarget("Company", ["company"]),
      platform: "macos",
    },
  });
  let releaseBase!: () => void;
  let baseStarted!: () => void;
  const baseGate = new Promise<void>((resolvePromise) => { releaseBase = resolvePromise; });
  const started = new Promise<void>((resolvePromise) => { baseStarted = resolvePromise; });
  let delayFirstBase = true;
  let calls = 0;
  const registry = new TargetRegistry({
    configPath,
    execute: (async (executable: string, args: string[]) => {
      calls += 1;
      if (executable === "sftp") return { stdout: "", stderr: "" };
      if (args.includes("-tt")) return { stdout: "__DEVSPACE_PTY_OK__\r\n", stderr: "" };
      if (delayFirstBase) {
        delayFirstBase = false;
        baseStarted();
        await baseGate;
      }
      return {
        stdout: [
          "__DEVSPACE_TARGET_V1__",
          "kernel=Darwin",
          "architecture=arm64",
          "home=/Users/test",
          "temporary=/tmp",
          "git=1",
          "rsync=1",
          "setpriv_boundary=0",
          "sandbox_boundary=1",
          "",
        ].join("\n"),
        stderr: "",
      };
    }) as never,
  });

  const oldProbe = registry.probe("company", { refresh: true });
  await started;
  await writeTargetConfig(configPath, {
    company: {
      ...sshTarget("Company reloaded", ["company"]),
      platform: "macos",
    },
  });
  const reloadedSnapshot = await registry.inspect();
  releaseBase();
  const oldObservation = await oldProbe;
  assert.notEqual(
    (oldObservation.evidence as { targetGeneration?: string }).targetGeneration,
    reloadedSnapshot.generation,
  );
  assert.equal(registry.stats().probeCacheEntries, 0);
  assert.equal(await registry.cachedObservation("company"), undefined);

  const current = await registry.probe("company");
  assert.equal(current.status, "ONLINE");
  assert.equal(
    (current.evidence as { targetGeneration?: string }).targetGeneration,
    reloadedSnapshot.generation,
  );
  assert.equal((current.evidence as { cache?: string }).cache, "miss");
  assert.equal(registry.stats().probeCacheEntries, 1);
  assert.equal(calls, 6);
});

test("Linux SSH PTY probe rechecks no-new-privileges and zero process capabilities", async (t) => {
  const root = await mkdtemp(join(tmpdir(), "devspace-v2-target-linux-pty-boundary-test-"));
  t.after(() => rm(root, { recursive: true, force: true }));
  const configPath = join(root, "targets.json");
  await writeTargetConfig(configPath, { linux: sshTarget("Linux", ["linux"]) });
  const calls: Array<{ executable: string; args: string[] }> = [];
  const registry = new TargetRegistry({
    configPath,
    execute: (async (executable: string, args: string[]) => {
      calls.push({ executable, args });
      if (executable === "sftp") return { stdout: "", stderr: "" };
      if (args.includes("-tt")) return { stdout: "__DEVSPACE_PTY_OK__\r\n", stderr: "" };
      return {
        stdout: [
          "__DEVSPACE_TARGET_V1__",
          "kernel=Linux",
          "architecture=x86_64",
          "home=/home/test",
          "temporary=/tmp",
          "git=1",
          "rsync=0",
          "setpriv_boundary=1",
          "sandbox_boundary=0",
          "",
        ].join("\n"),
        stderr: "",
      };
    }) as never,
  });
  const observation = await registry.probe("linux");
  assert.equal(observation.capabilities.pty, true);
  const pty = calls.find((call) => call.executable === "ssh" && call.args.includes("-tt"));
  assert.ok(pty);
  const remote = pty.args.at(-1) ?? "";
  assert.match(remote, /setpriv --no-new-privs/u);
  assert.match(remote, /NoNewPrivs/u);
  assert.match(remote, /CapPrm/u);
  assert.match(remote, /CapEff/u);
  assert.match(remote, /CapAmb/u);
  assert.equal(
    ((observation.evidence as { capabilityProbes?: { pty?: { mechanism?: string } } }).capabilityProbes?.pty?.mechanism),
    "verified-ssh-tty-with-no-new-privileges-and-zero-capabilities",
  );
});

test("SSH capability probes fail independently without misreporting complete filesystem support", async (t) => {
  const root = await mkdtemp(join(tmpdir(), "devspace-v2-target-capability-failure-test-"));
  t.after(() => rm(root, { recursive: true, force: true }));
  const configPath = join(root, "targets.json");
  await writeTargetConfig(configPath, {
    linux: sshTarget("Linux", ["linux"]),
  });
  const registry = new TargetRegistry({
    configPath,
    execute: (async (executable: string, args: string[]) => {
      if (executable === "sftp") throw new Error("subsystem unavailable");
      if (args.includes("-tt")) throw new Error("pty allocation refused");
      return {
        stdout: [
          "__DEVSPACE_TARGET_V1__",
          "kernel=Linux",
          "architecture=x86_64",
          "home=/home/test",
          "temporary=/tmp",
          "git=1",
          "rsync=0",
          "setpriv_boundary=1",
          "sandbox_boundary=0",
          "",
        ].join("\n"),
        stderr: "",
      };
    }) as never,
  });

  const observation = await registry.probe("linux");
  assert.equal(observation.status, "ONLINE");
  assert.equal(observation.capabilities.exec, true);
  assert.equal(observation.capabilities.pty, false);
  assert.equal(observation.capabilities.sftp, false);
  assert.equal(observation.capabilities.fs, true);
  const probes = (observation.evidence as {
    capabilityProbes?: { pty?: { reason?: string }; sftp?: { reason?: string } };
  }).capabilityProbes;
  assert.match(probes?.pty?.reason ?? "", /pty allocation refused/u);
  assert.match(probes?.sftp?.reason ?? "", /subsystem unavailable/u);
});

test("Windows SSH probes reject high-integrity tokens", async (t) => {
  const root = await mkdtemp(join(tmpdir(), "devspace-v2-target-windows-boundary-test-"));
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
        "temporary=C:\\Temp\\",
        "git=1",
        "elevated=1",
        "",
      ].join("\n"),
      stderr: "",
    })) as never,
  });
  const observation = await registry.probe("windows");
  assert.equal(observation.status, "DEGRADED");
  assert.equal(observation.capabilities.exec, false);
  assert.match(observation.reason ?? "", /high-integrity/u);
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
