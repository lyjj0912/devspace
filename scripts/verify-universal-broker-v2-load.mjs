#!/usr/bin/env node
import { execFile } from "node:child_process";
import { chmod, copyFile, mkdtemp, mkdir, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { pathToFileURL } from "node:url";
import { promisify } from "node:util";

const execFileAsync = promisify(execFile);
const root = resolve(new URL("..", import.meta.url).pathname);
const quick = process.argv.includes("--quick");
const requireRealSsh = process.argv.includes("--require-ssh")
  || ["1", "true", "yes", "on"].includes(
    String(process.env.DEVSPACE_V2_LOAD_REQUIRE_REAL_SSH ?? "").trim().toLowerCase(),
  );
const counts = quick
  ? { sessions: 100, contexts: 50, localExec: 50, sshExec: 10, mcp: 20, directoryEntries: 10_000, outputBytes: 10 * 1024 * 1024 }
  : { sessions: 1_000, contexts: 500, localExec: 500, sshExec: 200, mcp: 200, directoryEntries: 100_000, outputBytes: 100 * 1024 * 1024 };
const temporary = await mkdtemp(join(tmpdir(), "devspace-v2-load-"));
const report = {
  mode: quick ? "quick" : "full",
  startedAt: new Date().toISOString(),
  counts,
  checks: {},
  passed: false,
};

class LoadGuiRunner {
  constructor() {
    this.state = guiObservation("Before action");
    this.actions = 0;
  }

  async call(_target, request) {
    if (request.operation === "capabilities") {
      return {
        platform: "macos",
        accessibility: true,
        screenCapture: "not_probed",
        frontmostProcess: { name: this.state.application.name, pid: 4242 },
      };
    }
    if (request.operation === "observe") return structuredClone(this.state);
    this.actions += 1;
    this.state = guiObservation("After action");
    return { performed: true, actionType: request.actionType };
  }
}

try {
  const [
    { loadConfig },
    { McpSessionRegistry },
    { TargetRegistry },
    { ContextRegistry },
    { UniversalExecutionPlane },
    { UniversalFilesystemService },
    { UniversalMcpRouteRegistry },
    { UniversalMcpProxy },
    { UniversalArtifactService },
    { UniversalGuiService },
    { UNIVERSAL_OWNER_SCOPES, UNIVERSAL_TOOL_CONTRACTS },
  ] = await Promise.all([
    import(pathToFileURL(join(root, "dist/config.js")).href),
    import(pathToFileURL(join(root, "dist/mcp-sessions.js")).href),
    import(pathToFileURL(join(root, "dist/v2/targets.js")).href),
    import(pathToFileURL(join(root, "dist/v2/contexts.js")).href),
    import(pathToFileURL(join(root, "dist/v2/execution.js")).href),
    import(pathToFileURL(join(root, "dist/v2/filesystem.js")).href),
    import(pathToFileURL(join(root, "dist/v2/mcp-routes.js")).href),
    import(pathToFileURL(join(root, "dist/v2/mcp-proxy.js")).href),
    import(pathToFileURL(join(root, "dist/v2/artifact-service.js")).href),
    import(pathToFileURL(join(root, "dist/v2/gui.js")).href),
    import(pathToFileURL(join(root, "dist/v2/contracts.js")).href),
  ]);

  report.checks.sessionChurn = await sessionChurn(McpSessionRegistry, counts.sessions);

  const config = loadConfig({
    DEVSPACE_CONFIG_DIR: join(temporary, "config"),
    DEVSPACE_ALLOWED_ROOTS: temporary,
    DEVSPACE_STATE_DIR: join(temporary, "legacy"),
    DEVSPACE_WORKTREE_ROOT: join(temporary, "legacy-worktrees"),
    DEVSPACE_OAUTH_OWNER_TOKEN: "load-test-owner-token-12345678901234567890",
    DEVSPACE_PUBLIC_BASE_URL: "http://127.0.0.1:17676",
    DEVSPACE_LOG_LEVEL: "silent",
  });
  const fixtureSsh = await writeSshFixture(temporary);
  const targetConfig = join(temporary, "targets.json");
  await writeFile(targetConfig, `${JSON.stringify({
    version: 1,
    targets: {
      local: {
        displayName: "Local user fixture",
        aliases: ["local"],
        transport: "local",
        platform: "macos",
        gui: { mode: "local-ipc" },
      },
      "user-ssh-fixture": {
        displayName: "SSH user fixture",
        aliases: ["user-ssh-fixture"],
        transport: "ssh",
        sshHost: "user-ssh-fixture",
        platform: "linux",
        shell: "sh",
        defaultCwd: join(temporary, "remote-user"),
      },
    },
  }, null, 2)}\n`);
  await mkdir(join(temporary, "remote-user"));
  const targets = new TargetRegistry({ configPath: targetConfig });
  const project = join(temporary, "project");
  await mkdir(project);
  await gitInit(project);
  const contexts = new ContextRegistry({
    storePath: join(temporary, "contexts.json"),
    targets,
    serverConfig: config,
    worktreeRoot: join(temporary, "worktrees"),
    maximumWorktrees: 8,
    maximumWorktreeBytes: 2 * 1024 * 1024 * 1024,
  });
  report.checks.contextReuse = await contextReuse(contexts, project, counts.contexts);
  report.checks.worktreeQuota = await worktreeQuota(contexts, project);
  report.checks.contextTtl = await contextTtlCleanup(
    ContextRegistry,
    targets,
    config,
    project,
    temporary,
  );
  report.checks.worktreeByteQuota = await worktreeByteQuota(
    ContextRegistry,
    targets,
    config,
    project,
    temporary,
  );

  const execution = new UniversalExecutionPlane({
    targets,
    contexts,
    outputDir: join(temporary, "output"),
    sshControlDir: join(temporary, "ssh-control-".repeat(12)),
    maxRunningProcesses: 32,
    maxRunningProcessesPerTarget: 16,
    processBufferCharacters: 50_000,
    processOutputMaxBytes: counts.outputBytes + 1024 * 1024,
    completedProcessTtlMs: 60_000,
    sshExecutable: fixtureSsh,
  });
  const filesystem = new UniversalFilesystemService(targets, contexts, execution, {
    sshControlDir: join(temporary, "fs-control-".repeat(12)),
    sftpPut: async ({ localPath, remotePath }) => {
      await mkdir(dirname(remotePath), { recursive: true });
      await copyFile(localPath, remotePath);
    },
    sftpGet: async ({ localPath, remotePath }) => {
      await mkdir(dirname(localPath), { recursive: true });
      await copyFile(remotePath, localPath);
    },
  });
  const artifacts = new UniversalArtifactService(filesystem, {
    stagingRoot: join(temporary, "artifacts"),
    maximumEntries: 8,
    maximumTotalBytes: 10 * 1024 * 1024,
    maximumArtifactBytes: 5 * 1024 * 1024,
    ttlMs: 60_000,
  });
  const guiRunner = new LoadGuiRunner();
  const gui = new UniversalGuiService(targets, filesystem, execution, {
    runner: guiRunner,
    sleep: async () => undefined,
  });
  try {
    report.checks.userAuthority = authorityContract(
      UNIVERSAL_OWNER_SCOPES,
      UNIVERSAL_TOOL_CONTRACTS,
    );
    report.checks.localExecution = await executionLoad(execution, "local", counts.localExec);
    report.checks.sshExecution = await executionLoad(
      execution,
      "user-ssh-fixture",
      counts.sshExec,
    );
    report.checks.realSshExecution = await optionalRealSshLoad({
      ContextRegistry,
      TargetRegistry,
      UniversalExecutionPlane,
      config,
      count: counts.sshExec,
      temporary,
      required: requireRealSsh,
    });
    report.checks.filesystem = await filesystemLoad(filesystem, temporary);
    report.checks.artifact = await artifactLoad(artifacts, temporary);
    report.checks.gui = await guiLoad(gui, guiRunner);
    report.checks.concurrentProcesses = await concurrentProcessQuota(execution);
    report.checks.largeOutput = await largeOutput(execution, counts.outputBytes);
    report.checks.largeDirectory = await largeDirectory(filesystem, temporary, counts.directoryEntries);
    const executionStats = execution.stats();
    report.checks.executionSteadyState = {
      passed: executionStats.processes === 0
        && executionStats.runningProcesses === 0
        && executionStats.outputBytes === 0,
      ...executionStats,
    };
  } finally {
    gui.close();
    await artifacts.close();
    await execution.close();
  }

  const fixture = await writeFixture(temporary);
  const routeFile = join(temporary, "routes.json");
  await writeFile(routeFile, `${JSON.stringify({
    version: 1,
    routes: {
      fixture: {
        displayName: "Load fixture",
        aliases: ["fixture"],
        transport: "local-stdio",
        command: process.execPath,
        args: [fixture],
      },
    },
  }, null, 2)}\n`);
  const routes = new UniversalMcpRouteRegistry(routeFile);
  const proxy = new UniversalMcpProxy(routes, targets, {
    sshControlDir: join(temporary, "mcp-ssh"),
    maximumSessions: 4,
    defaultSessionIdleTtlMs: 30_000,
  });
  globalThis.gc?.();
  const mcpRssBefore = process.memoryUsage().rss;
  try {
    const started = performance.now();
    for (let index = 0; index < counts.mcp; index += 1) {
      const value = await proxy.execute({
        operation: "invoke",
        route: "fixture",
        name: "echo",
        arguments: { value: String(index) },
      });
      if (value.isError === true) throw new Error(`fixture invoke failed at ${index}`);
    }
    const stats = await proxy.stats();
    report.checks.mcpInvocations = {
      passed: stats.sessions <= 1 && stats.activeCalls === 0,
      calls: counts.mcp,
      durationMs: Math.round(performance.now() - started),
      sessions: stats.sessions,
      activeCalls: stats.activeCalls,
    };
  } finally {
    await proxy.close();
  }
  globalThis.gc?.();
  const mcpFinal = await proxy.stats();
  const mcpRssGrowthBytes = Math.max(0, process.memoryUsage().rss - mcpRssBefore);
  report.checks.mcpSteadyState = {
    passed: mcpFinal.sessions === 0
      && mcpFinal.activeCalls === 0
      && mcpFinal.results?.entries === 0
      && mcpRssGrowthBytes <= 50 * 1024 * 1024,
    sessions: mcpFinal.sessions,
    activeCalls: mcpFinal.activeCalls,
    resultEntries: mcpFinal.results?.entries,
    rssGrowthBytes: mcpRssGrowthBytes,
    limitBytes: 50 * 1024 * 1024,
  };

  const failures = Object.entries(report.checks).flatMap(([name, value]) =>
    value && typeof value === "object" && "passed" in value && value.passed === false
      ? [name]
      : []);
  report.passed = failures.length === 0;
  report.failures = failures;
  report.completedAt = new Date().toISOString();
  console.log(JSON.stringify(report, null, 2));
  if (!report.passed) process.exitCode = 1;
} finally {
  await rm(temporary, { recursive: true, force: true });
}

function authorityContract(scopes, contracts) {
  const expectedScopes = [
    "devspace.read",
    "devspace.write",
    "devspace.exec",
    "devspace.mcp",
    "devspace.artifact",
    "devspace.gui",
  ];
  const expectedInputs = {
    target: ["operation", "selector", "targetId", "refresh", "cursor", "limit"],
    context: ["operation", "contextId", "target", "path", "mode", "baseRef", "task", "query", "maxCharacters", "authorityId", "taskInstanceId", "taskLabel", "taskId", "authorityText", "actions", "correctionText", "expiresInSeconds", "cursor", "limit"],
    fs: ["operation", "target", "contextId", "path", "destination", "content", "patch", "query", "recursive", "overwrite", "expectedSha256", "disposition", "trashId", "finalSymlink", "authorityId", "cursor", "limit"],
    exec: ["target", "contextId", "cwd", "command", "tty", "mode", "yieldMs", "maxOutputChars", "envProfile", "durable", "authorityId"],
    process: ["operation", "processId", "chars", "signal", "columns", "rows", "authorityId", "transactionId", "reason", "delayMs", "waitMs", "maxOutputChars", "cursor", "limit"],
    mcp: ["operation", "route", "query", "name", "arguments", "uri", "cursor", "limit", "responsePolicy", "authorityId"],
    artifact: ["operation", "source", "destination", "overwrite", "maxBytes", "ttlSeconds", "authorityId"],
    gui: ["operation", "target", "sessionId", "generation", "action", "timeoutMs", "maxElements", "focusPolicy", "authorityId"],
  };
  const scopeStable = JSON.stringify(scopes) === JSON.stringify(expectedScopes);
  const inputDrift = Object.entries(expectedInputs).flatMap(([name, expected]) => {
    const actual = Object.keys(contracts[name]?.inputSchema ?? {});
    return JSON.stringify(actual) === JSON.stringify(expected) ? [] : [{ name, expected, actual }];
  });
  return {
    passed: scopeStable && inputDrift.length === 0,
    scopes: [...scopes],
    toolInputsStable: inputDrift.length === 0,
    ...(inputDrift.length > 0 ? { inputDrift } : {}),
  };
}

async function writeSshFixture(temporary) {
  const fakeBin = join(temporary, "ssh-fixture-bin");
  await mkdir(fakeBin, { recursive: true });
  const setpriv = join(fakeBin, "setpriv");
  await writeFile(setpriv, [
    "#!/bin/sh",
    "[ \"$1\" = \"--no-new-privs\" ] || exit 64",
    "shift",
    "[ \"$1\" = \"--\" ] || exit 64",
    "shift",
    "exec \"$@\"",
    "",
  ].join("\n"));
  await chmod(setpriv, 0o700);

  const path = join(temporary, "ssh-user-fixture.sh");
  await writeFile(path, [
    "#!/bin/sh",
    `PATH=${shellQuote(fakeBin)}:$PATH`,
    `DEVSPACE_TEST_SETPRIV=${shellQuote(setpriv)}`,
    "export PATH",
    "for last do :; done",
    "last=$(printf '%s' \"$last\" | sed \"s#/usr/bin/setpriv#$DEVSPACE_TEST_SETPRIV#g; s#/bin/setpriv#$DEVSPACE_TEST_SETPRIV#g\")",
    "exec /bin/sh -c \"$last\"",
    "",
  ].join("\n"));
  await chmod(path, 0o700);
  return path;
}

function shellQuote(value) {
  return `'${value.replaceAll("'", `'"'"'`)}'`;
}

async function optionalRealSshLoad(options) {
  const target = process.env.DEVSPACE_V2_LOAD_SSH_TARGET;
  if (!target) {
    return {
      passed: !options.required,
      skipped: true,
      required: options.required,
      reason: "No explicit real SSH load target was supplied.",
    };
  }
  const targets = new options.TargetRegistry({
    configPath: process.env.DEVSPACE_V2_LOAD_TARGET_CONFIG
      ?? join(options.temporary, "missing-real-targets.json"),
  });
  const contexts = new options.ContextRegistry({
    storePath: join(options.temporary, "real-ssh-contexts.json"),
    targets,
    serverConfig: options.config,
    worktreeRoot: join(options.temporary, "real-ssh-worktrees"),
  });
  const execution = new options.UniversalExecutionPlane({
    targets,
    contexts,
    outputDir: join(options.temporary, "real-ssh-output"),
    sshControlDir: join(options.temporary, "real-ssh-control"),
    maxRunningProcesses: 4,
    maxRunningProcessesPerTarget: 2,
    processBufferCharacters: 50_000,
    processOutputMaxBytes: 1024 * 1024,
    completedProcessTtlMs: 60_000,
  });
  try {
    const observation = await targets.probe(target, { refresh: true });
    const requiredCapabilities = {
      online: observation.status === "ONLINE",
      exec: observation.capabilities.exec === true,
      pty: observation.capabilities.pty === true,
      sftp: observation.capabilities.sftp === true,
      fs: observation.capabilities.fs === true,
    };
    if (!Object.values(requiredCapabilities).every(Boolean)) {
      return {
        passed: false,
        target,
        required: options.required,
        capabilityProbe: {
          status: observation.status,
          platform: observation.platform,
          capabilities: observation.capabilities,
          evidence: observation.evidence,
        },
        missingCapabilities: Object.entries(requiredCapabilities)
          .filter(([, available]) => !available)
          .map(([name]) => name),
      };
    }
    const executionResult = await executionLoad(execution, target, options.count);
    const ptyResult = await executionPtyCanary(execution, target, observation.platform);
    return {
      ...executionResult,
      passed: executionResult.passed && ptyResult.passed,
      required: options.required,
      capabilityProbe: {
        status: observation.status,
        platform: observation.platform,
        capabilities: observation.capabilities,
        evidence: observation.evidence,
      },
      ptyCanary: ptyResult,
    };
  } finally {
    await execution.close();
  }
}

async function executionPtyCanary(execution, target, platform) {
  const command = platform === "windows"
    ? "if((-not [Console]::IsInputRedirected)-and(-not [Console]::IsOutputRedirected)){Write-Output '__DEVSPACE_REAL_PTY_OK__';exit 0};exit 73"
    : "test -t 0 && test -t 1 && printf '__DEVSPACE_REAL_PTY_OK__\n'";
  let result = await execution.execute({
    target,
    command,
    tty: true,
    mode: "foreground",
    yieldMs: 30_000,
    maxOutputChars: 1_000,
  });
  try {
    if (result.state === "RUNNING" || result.state === "STARTING") {
      result = await execution.operate({
        operation: "wait",
        processId: result.processId,
        waitMs: 30_000,
        maxOutputChars: 1_000,
      });
    }
    if (result.state === "RUNNING" || result.state === "STARTING") {
      result = await execution.operate({
        operation: "signal",
        processId: result.processId,
        signal: "SIGTERM",
        waitMs: 5_000,
        maxOutputChars: 1_000,
      });
    }
    return {
      passed: result.state === "EXITED"
        && result.exitCode === 0
        && String(result.output ?? "").includes("__DEVSPACE_REAL_PTY_OK__"),
      state: result.state,
      exitCode: result.exitCode,
    };
  } finally {
    await execution.operate({ operation: "forget", processId: result.processId }).catch(() => undefined);
  }
}

async function filesystemLoad(filesystem, temporary) {
  const localPath = join(temporary, "local-user-file.txt");
  const remotePath = join(temporary, "remote-user", "remote-user-file.txt");
  const content = "user filesystem load\n";
  await filesystem.execute({ operation: "write", target: "local", path: localPath, content });
  await filesystem.execute({
    operation: "write",
    target: "user-ssh-fixture",
    path: remotePath,
    content,
  });
  const [localRead, remoteRead] = await Promise.all([
    filesystem.execute({ operation: "read", target: "local", path: localPath }),
    filesystem.execute({ operation: "read", target: "user-ssh-fixture", path: remotePath }),
  ]);
  return {
    passed: localRead.content === content && remoteRead.content === content,
    local: localRead.content === content,
    ssh: remoteRead.content === content,
  };
}

async function artifactLoad(artifacts, temporary) {
  const source = join(temporary, "artifact-source.txt");
  const remote = join(temporary, "remote-user", "artifact-remote.txt");
  const returned = join(temporary, "artifact-returned.txt");
  const content = "user artifact load\n";
  await writeFile(source, content);
  const outbound = await artifacts.execute({
    operation: "copy",
    source: { target: "local", path: source },
    destination: { target: "user-ssh-fixture", path: remote },
  });
  const inbound = await artifacts.execute({
    operation: "copy",
    source: { target: "user-ssh-fixture", path: remote },
    destination: { target: "local", path: returned },
  });
  return {
    passed: await readFile(returned, "utf8") === content
      && outbound.sha256 === inbound.sha256,
    localToSsh: true,
    sshToLocal: true,
    size: inbound.size,
    sha256: inbound.sha256,
  };
}

async function guiLoad(gui, runner) {
  const capabilities = await gui.execute({ operation: "capabilities", target: "local" });
  const observed = await gui.execute({ operation: "observe", target: "local" });
  const acted = await gui.execute({
    operation: "act",
    target: "local",
    sessionId: observed.sessionId,
    generation: observed.generation,
    action: { type: "perform", elementId: "e1", actionName: "AXPress" },
  });
  return {
    passed: capabilities.available === true
      && runner.actions === 1
      && acted.observation?.application?.name === "After action",
    capabilities: capabilities.available === true,
    observedElements: observed.elements?.length,
    actions: runner.actions,
  };
}

function guiObservation(applicationName) {
  return {
    application: {
      name: applicationName,
      bundleIdentifier: "devspace.load.fixture",
      pid: 4242,
    },
    window: {
      title: "Load fixture",
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
        name: "Load fixture",
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
        actions: ["AXPress"],
      },
    ],
    totalElements: 2,
    omittedElements: 0,
    truncated: false,
  };
}

async function sessionChurn(Registry, count) {
  globalThis.gc?.();
  const before = process.memoryUsage().rss;
  const registry = new Registry({ maximumSessions: 128 });
  let closed = 0;
  for (let index = 0; index < count; index += 1) {
    if (registry.size >= 128) await registry.closeLeastRecentlyUsed(1);
    registry.register(`session-${index}`, { close: async () => { closed += 1; } });
  }
  await registry.closeAll();
  globalThis.gc?.();
  const rssGrowthBytes = Math.max(0, process.memoryUsage().rss - before);
  return {
    passed: registry.size === 0 && rssGrowthBytes <= 50 * 1024 * 1024,
    sessions: count,
    closed,
    remaining: registry.size,
    rssGrowthBytes,
    limitBytes: 50 * 1024 * 1024,
  };
}

async function contextReuse(contexts, project, count) {
  const first = await contexts.open({ path: project, task: "load test" });
  let passed = true;
  let calls = count;
  let reason;
  try {
    for (let index = 1; index < count; index += 1) {
      const next = await contexts.open({ path: project, task: "load test" });
      if (next.contextId !== first.contextId || next.reused !== true) {
        passed = false;
        calls = index + 1;
        reason = "context identity drift";
        break;
      }
    }
  } finally {
    await contexts.close(first.contextId);
  }
  const remaining = contexts.stats().contexts;
  return {
    passed: passed && remaining === 0,
    calls,
    contextIdStable: passed,
    remaining,
    ...(reason ? { reason } : {}),
  };
}

async function worktreeQuota(contexts, project) {
  const created = [];
  let quotaRejected = false;
  try {
    for (let index = 0; index < 8; index += 1) {
      created.push(await contexts.open({ path: project, mode: "worktree" }));
    }
    try {
      await contexts.open({ path: project, mode: "worktree" });
    } catch (error) {
      quotaRejected = error && typeof error === "object" && error.code === "RESOURCE_QUOTA_EXCEEDED";
    }
  } finally {
    await Promise.allSettled(created.map((entry) => contexts.close(entry.contextId)));
  }
  const stats = contexts.stats();
  return {
    passed: quotaRejected && stats.contexts === 0 && stats.managedWorktrees === 0,
    created: created.length,
    quotaRejected,
    remainingContexts: stats.contexts,
    remainingWorktrees: stats.managedWorktrees,
  };
}

async function contextTtlCleanup(ContextRegistry, targets, config, project, temporary) {
  let now = 0;
  const contexts = new ContextRegistry({
    storePath: join(temporary, "ttl-contexts.json"),
    targets,
    serverConfig: config,
    now: () => now,
    idleTtlMs: 1_000,
    worktreeRoot: join(temporary, "ttl-worktrees"),
  });
  await contexts.open({ path: project });
  now = 1_001;
  const cleanup = await contexts.cleanupExpired();
  return {
    passed: cleanup.removed === 1 && cleanup.remaining === 0 && cleanup.errors === 0,
    ...cleanup,
  };
}

async function worktreeByteQuota(ContextRegistry, targets, config, project, temporary) {
  const contexts = new ContextRegistry({
    storePath: join(temporary, "byte-contexts.json"),
    targets,
    serverConfig: config,
    worktreeRoot: join(temporary, "byte-worktrees"),
    maximumWorktrees: 1,
    maximumWorktreeBytes: 1,
  });
  let rejected = false;
  try {
    await contexts.open({ path: project, mode: "worktree" });
  } catch (error) {
    rejected = error && typeof error === "object" && error.code === "RESOURCE_QUOTA_EXCEEDED";
  }
  const stats = contexts.stats();
  return {
    passed: rejected && stats.contexts === 0 && stats.managedWorktrees === 0,
    rejected,
    remainingContexts: stats.contexts,
    remainingWorktrees: stats.managedWorktrees,
  };
}

async function executionLoad(execution, target, count) {
  const started = performance.now();
  for (let index = 0; index < count; index += 1) {
    const result = await execution.execute({
      target,
      cwd: target === "local" ? process.cwd() : "/tmp",
      command: "true",
      mode: "foreground",
      yieldMs: 10_000,
      maxOutputChars: 100,
    });
    if (result.state !== "EXITED" || result.exitCode !== 0) {
      return { passed: false, target, calls: index + 1, result };
    }
    await execution.operate({ operation: "forget", processId: result.processId });
  }
  return { passed: true, target, calls: count, durationMs: Math.round(performance.now() - started) };
}

async function concurrentProcessQuota(execution) {
  const running = [];
  let quotaRejected = false;
  try {
    for (let index = 0; index < 16; index += 1) {
      running.push(await execution.execute({
        target: "local",
        cwd: process.cwd(),
        command: "sleep 30",
        mode: "background",
        yieldMs: 0,
        maxOutputChars: 100,
      }));
    }
    try {
      await execution.execute({
        target: "local",
        cwd: process.cwd(),
        command: "true",
        mode: "background",
        yieldMs: 0,
        maxOutputChars: 100,
      });
    } catch (error) {
      quotaRejected = error && typeof error === "object" && error.code === "RESOURCE_QUOTA_EXCEEDED";
    }
  } finally {
    await Promise.allSettled(running.map(async (entry) => {
      await execution.operate({
        operation: "signal",
        processId: entry.processId,
        signal: "SIGTERM",
        waitMs: 2_000,
      });
      await execution.operate({ operation: "forget", processId: entry.processId });
    }));
  }
  return { passed: quotaRejected, started: running.length, quotaRejected };
}

async function largeOutput(execution, bytes) {
  const command = `${JSON.stringify(process.execPath)} -e ${JSON.stringify(`const chunk='x'.repeat(1048576);for(let i=0;i<${Math.ceil(bytes / 1048576)};i++)process.stdout.write(chunk);`)}`;
  const processRecord = await execution.execute({
    target: "local",
    cwd: process.cwd(),
    command,
    mode: "background",
    maxOutputChars: 100,
  });
  const completed = await execution.operate({
    operation: "wait",
    processId: processRecord.processId,
    waitMs: 110_000,
    maxOutputChars: 100,
  });
  const result = {
    passed: completed.state === "EXITED" && completed.exitCode === 0 && completed.outputBytes >= bytes,
    requestedBytes: bytes,
    outputBytes: completed.outputBytes,
    outputResourceUri: completed.resourceUri,
  };
  await execution.operate({ operation: "forget", processId: processRecord.processId });
  return result;
}

async function largeDirectory(filesystem, temporary, count) {
  const directory = join(temporary, "large-directory");
  await mkdir(directory);
  const creator = [
    "import os,sys",
    "root=sys.argv[1]; count=int(sys.argv[2])",
    "for index in range(count):",
    "    path=os.path.join(root,f'f-{index:06d}')",
    "    open(path,'a').close()",
  ].join("\n");
  await execFileAsync("python3", ["-c", creator, directory, String(count)], {
    timeout: 180_000,
    maxBuffer: 64 * 1024,
  });
  const started = performance.now();
  const listed = await filesystem.execute({
    operation: "list",
    target: "local",
    path: directory,
    limit: 1_000,
  });
  return {
    passed: listed.totalEntries === count && Array.isArray(listed.entries) && listed.entries.length === 1_000,
    entries: count,
    returned: Array.isArray(listed.entries) ? listed.entries.length : 0,
    totalEntries: listed.totalEntries,
    durationMs: Math.round(performance.now() - started),
  };
}

async function gitInit(project) {
  await execFileAsync("git", ["init"], { cwd: project });
  await execFileAsync("git", ["config", "user.name", "DevSpace Load"], { cwd: project });
  await execFileAsync("git", ["config", "user.email", "load@example.invalid"], { cwd: project });
  await writeFile(join(project, "README.md"), "load\n");
  await execFileAsync("git", ["add", "."], { cwd: project });
  await execFileAsync("git", ["commit", "-m", "Initial"], { cwd: project });
}

async function writeFixture(temporary) {
  const sdk = pathToFileURL(resolve(root, "node_modules/@modelcontextprotocol/sdk/dist/esm/server/mcp.js")).href;
  const stdio = pathToFileURL(resolve(root, "node_modules/@modelcontextprotocol/sdk/dist/esm/server/stdio.js")).href;
  const zod = pathToFileURL(resolve(root, "node_modules/zod/index.js")).href;
  const path = join(temporary, "fixture.mjs");
  await writeFile(path, [
    `import { McpServer } from ${JSON.stringify(sdk)};`,
    `import { StdioServerTransport } from ${JSON.stringify(stdio)};`,
    `import * as z from ${JSON.stringify(zod)};`,
    "const server=new McpServer({name:'load-fixture',version:'1'});",
    "server.registerTool('echo',{inputSchema:{value:z.string()}},async({value})=>({content:[{type:'text',text:value}],structuredContent:{value}}));",
    "const transport=new StdioServerTransport(); await server.connect(transport);",
    "",
  ].join("\n"));
  return path;
}
