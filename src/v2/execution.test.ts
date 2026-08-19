import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { spawn } from "node:child_process";
import {
  chmod,
  mkdir,
  mkdtemp,
  realpath,
  rm,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test, { type TestContext } from "node:test";
import { loadConfig } from "../config.js";
import {
  OperationAuthorityRegistry,
  actionResourceKeySha256,
  type AuthorityActionDescriptor,
  type AuthorityRiskClass,
  type OperationAuthorityDispatchController,
} from "./authority.js";
import {
  EXEC_RISK_CLASSIFIER_GENERATION,
  execAction,
  minimumAuthorityRisk,
  processAction,
  processRisk,
} from "./authority-policy.js";
import { ContextRegistry } from "./contexts.js";
import { UniversalEnvProfileRegistry } from "./env-profiles.js";
import {
  type ExecutionPlaneOptions,
  type PreparedExecExecutionBinding,
  UniversalExecutionPlane,
  type UniversalProcessSnapshot,
} from "./execution.js";
import { UniversalBrokerError } from "./errors.js";
import { TargetRegistry } from "./targets.js";
import { createCapabilityCallContextFromTrustedPrincipal } from "./capability-call-context.js";
import type {
  DurableProcessAdapter,
  DurableProcessEvents,
  DurableProcessHandle,
  DurableProcessIdentity,
} from "./durable-process-adapter.js";

test("exec auto returns a completed local result and preserves resource output", async (t) => {
  const fixture = await createFixture(t);
  const result = await fixture.execution.execute({
    target: "local",
    cwd: fixture.root,
    command: "printf 'hello-v2'",
    mode: "auto",
    yieldMs: 2_000,
  });

  assert.equal(result.state, "EXITED");
  assert.equal(result.exitCode, 0);
  assert.equal(result.output, "hello-v2");
  const resource = await fixture.execution.readOutput(result.processId, 0, 1_024);
  assert.equal(resource.text, "hello-v2");
  assert.equal(resource.nextOffset, undefined);
});

test("exec background converts to a managed process and process wait returns output", async (t) => {
  const fixture = await createFixture(t);
  const started = await fixture.execution.execute({
    cwd: fixture.root,
    command: "sleep 0.15; printf 'background-complete'",
    mode: "background",
  });
  assert.equal(started.state, "RUNNING");

  const completed = await fixture.execution.operate({
    operation: "wait",
    processId: started.processId,
    waitMs: 2_000,
  }) as UniversalProcessSnapshot;
  assert.equal(completed.state, "EXITED");
  assert.equal(completed.exitCode, 0);
  assert.match(completed.output, /background-complete/);
});

test("process write, resize validation, and signal use one generic lifecycle", async (t) => {
  const fixture = await createFixture(t);
  const input = await fixture.execution.execute({
    cwd: fixture.root,
    command: "IFS= read -r line; printf 'received:%s\\n' \"$line\"",
    mode: "background",
  });
  const written = await fixture.execution.operate({
    operation: "write",
    processId: input.processId,
    chars: "value-42\n",
    waitMs: 2_000,
  }) as UniversalProcessSnapshot;
  assert.equal(written.state, "EXITED");
  assert.match(written.output, /received:value-42/);

  const sleeping = await fixture.execution.execute({
    cwd: fixture.root,
    command: "sleep 30",
    mode: "background",
  });
  await assert.rejects(
    fixture.execution.operate({
      operation: "resize",
      processId: sleeping.processId,
      columns: 100,
      rows: 40,
    }),
    (error: unknown) => brokerCode(error) === "PRECONDITION_FAILED",
  );
  const signalled = await fixture.execution.operate({
    operation: "signal",
    processId: sleeping.processId,
    signal: "SIGTERM",
    waitMs: 2_000,
  }) as UniversalProcessSnapshot;
  assert.equal(signalled.state, "SIGNALED");
  assert.equal(signalled.signal, "SIGTERM");
});

test("process handles and listings are stable-principal owned with cross-principal dispatch zero", async (t) => {
  const fixture = await createFixture(t);
  const ownerA1 = owner("process-owner-a");
  const ownerA2 = owner("process-owner-a");
  const ownerB = owner("process-owner-b");
  const started = await fixture.execution.execute({
    cwd: fixture.root,
    command: "sleep 30",
    mode: "background",
  }, undefined, undefined, ownerA1);
  const samePrincipal = await fixture.execution.operate({
    operation: "poll",
    processId: started.processId,
  }, undefined, ownerA2);
  assert.equal(samePrincipal.processId, started.processId);
  const otherList = await fixture.execution.operate({ operation: "list" }, undefined, ownerB);
  assert.deepEqual(otherList.processes, []);

  let killCalls = 0;
  const entry = (fixture.execution as unknown as {
    entries: Map<string, { handle?: { kill(signal: NodeJS.Signals): void | Promise<void> } }>;
  }).entries.get(started.processId);
  assert.ok(entry?.handle);
  const originalKill = entry.handle.kill.bind(entry.handle);
  entry.handle.kill = async (signal) => {
    killCalls += 1;
    await originalKill(signal);
  };
  await assert.rejects(
    fixture.execution.operate({
      operation: "signal",
      processId: started.processId,
      signal: "SIGTERM",
    }, undefined, ownerB),
    (error: unknown) => brokerCode(error) === "AUTHORITY_PRINCIPAL_MISMATCH",
  );
  assert.equal(killCalls, 0);
  await fixture.execution.operate({
    operation: "signal",
    processId: started.processId,
    signal: "SIGTERM",
    waitMs: 2_000,
  }, undefined, ownerA2);
  assert.equal(killCalls, 1);
});

test("process record quota rejects synchronously before a second provider spawn", async (t) => {
  let spawnCalls = 0;
  const fixture = await createFixture(t, {
    maxProcessRecords: 1,
    spawnProcess: ((...args: Parameters<typeof spawn>) => {
      spawnCalls += 1;
      return spawn(...args);
    }) as NonNullable<ExecutionPlaneOptions["spawnProcess"]>,
  });
  await fixture.execution.execute({
    cwd: fixture.root,
    command: "printf first",
    mode: "foreground",
    yieldMs: 2_000,
  });
  assert.equal(spawnCalls, 1);
  await assert.rejects(
    fixture.execution.execute({
      cwd: fixture.root,
      command: "printf second",
      mode: "foreground",
      yieldMs: 2_000,
    }),
    (error: unknown) => brokerCode(error) === "RESOURCE_QUOTA_EXCEEDED",
  );
  assert.equal(spawnCalls, 1);
});

test("durable process reattaches by manager handle plus PID/start token without replay", async (t) => {
  const adapter = new FixtureDurableAdapter();
  const fixture = await createFixture(t, { durableAdapter: adapter });
  const started = await fixture.execution.execute({
    cwd: fixture.root,
    command: "printf durable",
    mode: "background",
    durable: true,
  });
  assert.equal(started.state, "RUNNING");
  assert.equal(adapter.launches, 1);
  await fixture.execution.close();

  const recovered = new UniversalExecutionPlane({
    targets: fixture.targets,
    contexts: fixture.contexts,
    outputDir: join(fixture.root, "v2-state", "process-output"),
    sshControlDir: join(fixture.root, "v2-state", "ssh-control-recovered"),
    durableAdapter: adapter,
  });
  t.after(() => recovered.close());
  const snapshot = await recovered.operate({
    operation: "poll",
    processId: started.processId,
  }) as UniversalProcessSnapshot;
  assert.equal(snapshot.state, "RUNNING");
  assert.equal(snapshot.pid, adapter.identity.pid);
  assert.equal(adapter.reattaches, 1);
  assert.equal(adapter.launches, 1);
});

test("non-durable process after restart returns a typed non-reattachable failure", async (t) => {
  const fixture = await createFixture(t);
  const completed = await fixture.execution.execute({
    cwd: fixture.root,
    command: "printf transient",
    mode: "foreground",
    yieldMs: 2_000,
  });
  await fixture.execution.close();
  const recovered = new UniversalExecutionPlane({
    targets: fixture.targets,
    contexts: fixture.contexts,
    outputDir: join(fixture.root, "v2-state", "process-output"),
    sshControlDir: join(fixture.root, "v2-state", "ssh-control-recovered"),
  });
  t.after(() => recovered.close());
  await assert.rejects(
    recovered.operate({ operation: "poll", processId: completed.processId }),
    (error: unknown) => brokerCode(error) === "PROCESS_NOT_FOUND"
      && (error as UniversalBrokerError).evidence?.reasonCode === "NON_DURABLE_PROCESS_NOT_REATTACHABLE",
  );
});

test("process signal does not mutate requested state before barrier and provider kill succeed", async (t) => {
  const fixture = await createFixture(t);
  type TestEntry = {
    requestedSignal?: NodeJS.Signals;
    handle?: { kill(signal: NodeJS.Signals): void };
  };
  const entries = (fixture.execution as unknown as {
    entries: Map<string, TestEntry>;
  }).entries;

  const barrierFailure = await fixture.execution.execute({
    cwd: fixture.root,
    command: "sleep 30",
    mode: "background",
  });
  const barrierEntry = entries.get(barrierFailure.processId);
  assert.ok(barrierEntry?.handle);
  const originalBarrierKill = barrierEntry.handle.kill.bind(barrierEntry.handle);
  let barrierKillCalls = 0;
  barrierEntry.handle.kill = (signal) => {
    barrierKillCalls += 1;
    originalBarrierKill(signal);
  };
  const rejectedBarrier = {
    claim() {},
    markDispatched() {
      throw new UniversalBrokerError(
        "AUTHORITY_STORE_UNAVAILABLE",
        "Injected durable dispatch barrier failure.",
      );
    },
  } as unknown as OperationAuthorityDispatchController;
  await assert.rejects(
    fixture.execution.operate({
      operation: "signal",
      processId: barrierFailure.processId,
      signal: "SIGTERM",
    }, rejectedBarrier),
    (error: unknown) => brokerCode(error) === "AUTHORITY_STORE_UNAVAILABLE",
  );
  assert.equal(barrierKillCalls, 0);
  assert.equal(barrierEntry.requestedSignal, undefined);
  barrierEntry.handle.kill = originalBarrierKill;

  const killFailure = await fixture.execution.execute({
    cwd: fixture.root,
    command: "sleep 30",
    mode: "background",
  });
  const killEntry = entries.get(killFailure.processId);
  assert.ok(killEntry?.handle);
  const originalKill = killEntry.handle.kill.bind(killEntry.handle);
  let killCalls = 0;
  killEntry.handle.kill = () => {
    killCalls += 1;
    throw new Error("injected synchronous kill failure");
  };
  const acceptedBarrier = {
    claim() {},
    markDispatched() {},
  } as unknown as OperationAuthorityDispatchController;
  await assert.rejects(
    fixture.execution.operate({
      operation: "signal",
      processId: killFailure.processId,
      signal: "SIGTERM",
    }, acceptedBarrier),
    /injected synchronous kill failure/u,
  );
  assert.equal(killCalls, 1);
  assert.equal(killEntry.requestedSignal, undefined);
  killEntry.handle.kill = originalKill;
});

test("durable DISPATCHED barrier precedes local and SSH spawn plus every process mutation hook", async (t) => {
  let boundaryAssertion: (() => void) | undefined;
  const instrumentedSpawn = ((
    command: string,
    args: readonly string[],
    options: Record<string, unknown>,
  ) => {
    boundaryAssertion?.();
    return (spawn as unknown as (
      executable: string,
      executableArgs: readonly string[],
      spawnOptions: Record<string, unknown>,
    ) => unknown)(command, args, options);
  }) as unknown as NonNullable<ExecutionPlaneOptions["spawnProcess"]>;
  const fixture = await createFixture(t, { spawnProcess: instrumentedSpawn });
  const authority = new OperationAuthorityRegistry({
    minimumRisk: minimumAuthorityRisk,
    storePath: join(fixture.root, "v2-state", "authority-boundary.sqlite"),
    instanceId: "execution-boundary-owner",
  });
  t.after(() => authority.close());
  const principal = "execution-boundary-principal";
  let taskSequence = 0;
  const prepare = (descriptor: AuthorityActionDescriptor, risk: AuthorityRiskClass) => {
    taskSequence += 1;
    const created = authority.create({
      taskId: `execution-boundary-${taskSequence}`,
      authorityText: "Cross this exact provider boundary only after durable dispatch.",
      actions: [{ descriptor, risk, uses: 1 }],
    }, principal);
    const authorityId = String(created.authorityId);
    return {
      authorityId,
      dispatch: authority.prepareDispatch(authorityId, principal, descriptor, risk),
    };
  };
  const assertDurablyDispatched = (authorityId: string) => {
    const status = authority.status(authorityId, principal) as {
      receipts: Array<{ state: string; leaseState: string }>;
    };
    assert.equal(status.receipts.at(-1)?.state, "DISPATCHED");
    assert.equal(status.receipts.at(-1)?.leaseState, "ACTIVE");
  };

  let spawnCalls = 0;
  for (const target of ["local", "fake"] as const) {
    const input = {
      target,
      cwd: fixture.root,
      command: `touch ${target}-dispatch.txt`,
      mode: "foreground" as const,
      yieldMs: 2_000,
    };
    const targetBinding = await fixture.targets.resolveWithGeneration(target);
    const binding = await fixture.execution.prepareAuthorityBinding(
      input,
      targetBinding.target,
      targetBinding.generation,
    );
    const prepared = prepare(
      execAction(input, binding.targetId, fixture.root, binding),
      binding.launchRisk,
    );
    boundaryAssertion = () => {
      assertDurablyDispatched(prepared.authorityId);
      spawnCalls += 1;
    };
    const result = await fixture.execution.execute(input, binding, prepared.dispatch);
    assert.equal(result.state, "EXITED");
    prepared.dispatch.complete("PASS");
  }
  boundaryAssertion = undefined;
  assert.equal(spawnCalls, 2);

  const writeProcess = await fixture.execution.execute({
    cwd: fixture.root,
    command: "cat",
    mode: "background",
  });
  const ptyProcess = await fixture.execution.execute({
    cwd: fixture.root,
    command: "sleep 30",
    tty: true,
    mode: "background",
  });
  type TestHandle = {
    write(data: string): void;
    resize?(columns: number, rows: number): void;
    kill(signal: NodeJS.Signals): void;
  };
  type TestEntry = { processId: string; handle?: TestHandle };
  const internals = fixture.execution as unknown as {
    entries: Map<string, TestEntry>;
    forgetEntry(entry: TestEntry): Promise<void>;
  };
  const prepareProcess = (input: Parameters<typeof processAction>[0]) => {
    const binding = fixture.execution.authorityBinding(input.processId, input.operation);
    const descriptor = processAction(input, binding);
    const risk = processRisk(input.operation, descriptor.parameters);
    return { ...prepare(descriptor, risk), input };
  };
  let processProviderCalls = 0;

  const write = prepareProcess({
    operation: "write",
    processId: writeProcess.processId,
    chars: "boundary-write\n",
  });
  const writeEntry = internals.entries.get(writeProcess.processId);
  assert.ok(writeEntry?.handle);
  const originalWrite = writeEntry.handle.write.bind(writeEntry.handle);
  writeEntry.handle.write = (data) => {
    assertDurablyDispatched(write.authorityId);
    processProviderCalls += 1;
    originalWrite(data);
  };
  await fixture.execution.operate(write.input, write.dispatch);
  write.dispatch.complete("PASS");

  const resize = prepareProcess({
    operation: "resize",
    processId: ptyProcess.processId,
    columns: 100,
    rows: 40,
  });
  const ptyEntry = internals.entries.get(ptyProcess.processId);
  assert.ok(ptyEntry?.handle?.resize);
  const originalResize = ptyEntry.handle.resize.bind(ptyEntry.handle);
  ptyEntry.handle.resize = (columns, rows) => {
    assertDurablyDispatched(resize.authorityId);
    processProviderCalls += 1;
    originalResize(columns, rows);
  };
  await fixture.execution.operate(resize.input, resize.dispatch);
  resize.dispatch.complete("PASS");

  const signal = prepareProcess({
    operation: "signal",
    processId: writeProcess.processId,
    signal: "SIGTERM",
    waitMs: 2_000,
  });
  const originalKill = writeEntry.handle.kill.bind(writeEntry.handle);
  writeEntry.handle.kill = (value) => {
    assertDurablyDispatched(signal.authorityId);
    processProviderCalls += 1;
    originalKill(value);
  };
  await fixture.execution.operate(signal.input, signal.dispatch);
  signal.dispatch.complete("PASS");

  const forget = prepareProcess({ operation: "forget", processId: writeProcess.processId });
  const originalForget = internals.forgetEntry.bind(fixture.execution);
  internals.forgetEntry = async (entry) => {
    assertDurablyDispatched(forget.authorityId);
    processProviderCalls += 1;
    await originalForget(entry);
  };
  await fixture.execution.operate(forget.input, forget.dispatch);
  forget.dispatch.complete("PASS");
  assert.equal(processProviderCalls, 4);
});

test("PTY execution accepts stdin and resize", async (t) => {
  const fixture = await createFixture(t);
  const started = await fixture.execution.execute({
    cwd: fixture.root,
    command: "read line; printf 'pty:%s\\n' \"$line\"",
    tty: true,
    mode: "background",
  });
  const resized = await fixture.execution.operate({
    operation: "resize",
    processId: started.processId,
    columns: 100,
    rows: 40,
  }) as UniversalProcessSnapshot;
  assert.equal(resized.state, "RUNNING");
  const completed = await fixture.execution.operate({
    operation: "write",
    processId: started.processId,
    chars: "interactive\r",
    waitMs: 2_000,
  }) as UniversalProcessSnapshot;
  assert.equal(completed.state, "EXITED");
  assert.match(completed.output, /pty:interactive/);
});

test("context supplies target and cwd without becoming an authority boundary", async (t) => {
  const fixture = await createFixture(t);
  const project = join(fixture.root, "project");
  await mkdir(project);
  const context = await fixture.contexts.open({ path: project });
  const result = await fixture.execution.execute({
    contextId: context.contextId,
    command: "pwd -P",
    yieldMs: 2_000,
  });
  assert.equal(result.state, "EXITED");
  assert.equal(result.output.trim(), await realpath(project));

  await assert.rejects(
    fixture.execution.execute({
      contextId: context.contextId,
      target: "fake",
      command: "true",
    }),
    (error: unknown) => brokerCode(error) === "PRECONDITION_FAILED",
  );
});

test("running-process quotas fail before spawning another command", async (t) => {
  const fixture = await createFixture(t, { maxRunningProcesses: 1 });
  const first = await fixture.execution.execute({
    cwd: fixture.root,
    command: "sleep 30",
    mode: "background",
  });
  await assert.rejects(
    fixture.execution.execute({
      cwd: fixture.root,
      command: "sleep 30",
      mode: "background",
    }),
    (error: unknown) => brokerCode(error) === "RESOURCE_QUOTA_EXCEEDED",
  );
  await fixture.execution.operate({
    operation: "signal",
    processId: first.processId,
    signal: "SIGTERM",
    waitMs: 2_000,
  });
});

test("bounded model output retains full process output as a resource", async (t) => {
  const fixture = await createFixture(t, {
    processBufferCharacters: 100,
  });
  const result = await fixture.execution.execute({
    cwd: fixture.root,
    command: "python3 - <<'PY'\nprint('x' * 5000, end='')\nPY",
    yieldMs: 2_000,
    maxOutputChars: 80,
  });
  assert.equal(result.state, "EXITED");
  assert.equal(result.outputTruncated, true);
  assert.ok(result.output.length <= 200);
  const resource = await fixture.execution.readOutput(result.processId, 0, 6_000);
  assert.equal(resource.text.length, 5_000);
  assert.equal(resource.text, "x".repeat(5_000));
});

test("environment-profile requests fail explicitly when unavailable", async (t) => {
  const fixture = await createFixture(t);
  await assert.rejects(
    fixture.execution.execute({
      target: "local",
      cwd: fixture.root,
      command: "true",
      envProfile: "secret-profile",
    }),
    (error: unknown) => brokerCode(error) === "CAPABILITY_UNAVAILABLE",
  );
});

test("internal GUI execution cannot combine its exact contract with an environment profile", async (t) => {
  const fixture = await createFixture(t);
  const scriptPath = join(fixture.root, "gui-node.applescript");
  await assert.rejects(
    fixture.execution.execute({
      target: "local",
      cwd: fixture.root,
      command: `/usr/bin/osascript ${shellQuoteForTest(scriptPath)} capabilities`,
      internalPolicy: {
        kind: "gui",
        scriptPath,
        scriptSha256: "0".repeat(64),
      },
      envProfile: "must-not-load",
    }),
    (error: unknown) => brokerCode(error) === "ELEVATION_BLOCKED",
  );
  assert.equal(fixture.execution.stats().processes, 0);
});

test("exec does not inherit service credentials into child processes", async (t) => {
  const fixture = await createFixture(t);
  const previousOwner = process.env.DEVSPACE_OAUTH_OWNER_TOKEN;
  const previousApiKey = process.env.OPENAI_API_KEY;
  process.env.DEVSPACE_OAUTH_OWNER_TOKEN = "must-not-reach-child";
  process.env.OPENAI_API_KEY = "must-not-reach-child";
  try {
    const result = await fixture.execution.execute({
      cwd: fixture.root,
      command: "printf 'owner=%s api=%s path=%s' \"${DEVSPACE_OAUTH_OWNER_TOKEN-unset}\" \"${OPENAI_API_KEY-unset}\" \"${PATH:+present}\"",
      yieldMs: 2_000,
    });
    assert.equal(result.state, "EXITED");
    assert.equal(result.output, "owner=unset api=unset path=present");
  } finally {
    restoreEnvironment("DEVSPACE_OAUTH_OWNER_TOKEN", previousOwner);
    restoreEnvironment("OPENAI_API_KEY", previousApiKey);
  }
});

test("fresh cached target evidence blocks impossible PTY dispatch", async (t) => {
  const fixture = await createFixture(t);
  const observation = await fixture.targets.probe("no-pty", { refresh: true });
  assert.equal(observation.status, "ONLINE");
  assert.equal(observation.capabilities.exec, true);
  assert.equal(observation.capabilities.pty, false);

  await assert.rejects(
    fixture.execution.execute({
      target: "no-pty",
      command: "printf should-not-run",
      tty: true,
      mode: "foreground",
    }),
    (error: unknown) => brokerCode(error) === "CAPABILITY_UNAVAILABLE",
  );
  assert.equal(fixture.execution.stats().processes, 0);
});

test("SSH execution strips dispatch markers and preserves the remote exit code", async (t) => {
  const fixture = await createFixture(t);
  const result = await fixture.execution.execute({
    target: "fake",
    cwd: fixture.root,
    command: "printf 'remote-output'; exit 7",
    yieldMs: 2_000,
  });
  assert.equal(result.state, "EXITED");
  assert.equal(result.exitCode, 7);
  assert.equal(result.output, "remote-output");
});

test("SSH failures distinguish pre-dispatch failure from post-dispatch unknown state", async (t) => {
  const fixture = await createFixture(t);
  await assert.rejects(
    fixture.execution.execute({
      target: "offline",
      cwd: fixture.root,
      command: "true",
      yieldMs: 2_000,
    }),
    (error: unknown) => brokerCode(error) === "TRANSPORT_UNAVAILABLE",
  );
  await assert.rejects(
    fixture.execution.execute({
      target: "unknown",
      cwd: fixture.root,
      command: "touch must-not-be-retried",
      yieldMs: 2_000,
    }),
    (error: unknown) => brokerCode(error) === "EXECUTION_STATE_UNKNOWN",
  );
});

test("remote cwd failures are classified before dispatch", async (t) => {
  const fixture = await createFixture(t);
  await assert.rejects(
    fixture.execution.execute({
      target: "fake",
      cwd: join(fixture.root, "missing"),
      command: "true",
      yieldMs: 2_000,
    }),
    (error: unknown) => brokerCode(error) === "PATH_NOT_FOUND",
  );
});

test("exec rejects a changed target binding before process creation or spawn", async (t) => {
  let spawnCalls = 0;
  const fixture = await createFixture(t, {
    spawnProcess: (() => {
      spawnCalls += 1;
      throw new Error("stale binding must fail before spawn");
    }) as NonNullable<ExecutionPlaneOptions["spawnProcess"]>,
  });
  const initial = await fixture.targets.resolveWithGeneration("local");
  const expected = {
    targetId: initial.target.id,
    targetGeneration: initial.generation,
    targetTransport: initial.target.transport,
    targetPlatform: initial.target.platform,
    shellDialect: initial.target.shell,
    effectiveEnvProfile: undefined,
    effectiveCwd: fixture.root,
    mode: "auto" as const,
    tty: false,
    classifierGeneration: EXEC_RISK_CLASSIFIER_GENERATION,
    launchRisk: "R1" as const,
  };
  await writeFile(fixture.targetsPath, JSON.stringify({
    version: 1,
    targets: {
      local: sshTarget("switched-to-ssh"),
    },
  }, null, 2));

  await assert.rejects(
    fixture.execution.execute({
      target: "local",
      cwd: fixture.root,
      command: "npm run build",
      yieldMs: 2_000,
    }, expected),
    (error: unknown) => brokerCode(error) === "AUTHORITY_STALE",
  );
  assert.equal(fixture.execution.stats().processes, 0);
  assert.equal(spawnCalls, 0);
});

test("exec rejects changed environment profile contents under the same profile ID", async (t) => {
  const root = await mkdtemp(join(tmpdir(), "devspace-v2-exec-profile-fence-"));
  t.after(() => rm(root, { recursive: true, force: true }));
  const profilePath = join(root, "profiles.json");
  const writeProfile = async (value: string) => {
    await writeFile(profilePath, JSON.stringify({
      version: 1,
      profiles: {
        developer: {
          targets: ["local"],
          environment: { DEVSPACE_PROFILE_VALUE: value },
        },
      },
    }, null, 2), { mode: 0o600 });
    await chmod(profilePath, 0o600);
  };
  await writeProfile("one");
  let spawnCalls = 0;
  const fixture = await createFixture(t, {
    envProfiles: new UniversalEnvProfileRegistry({ configPath: profilePath }),
    spawnProcess: (() => {
      spawnCalls += 1;
      throw new Error("stale profile binding must fail before spawn");
    }) as NonNullable<ExecutionPlaneOptions["spawnProcess"]>,
  });
  const initial = await fixture.targets.resolveWithGeneration("local");
  const input = {
    target: "local",
    cwd: fixture.root,
    command: "git status --short",
    envProfile: "developer",
  };
  const expected = await fixture.execution.prepareAuthorityBinding(
    input,
    initial.target,
    initial.generation,
  );
  await writeProfile("two");

  await assert.rejects(
    fixture.execution.execute(input, expected),
    (error: unknown) => brokerCode(error) === "AUTHORITY_STALE",
  );
  assert.equal(fixture.execution.stats().processes, 0);
  assert.equal(spawnCalls, 0);
});

test("exec omitted, explicit, and context cwd aliases share the canonical resource lease", async (t) => {
  const fixture = await createFixture(t);
  const target = await fixture.targets.resolveWithGeneration("local");
  const omittedInput = {
    target: "local",
    command: "touch omitted-cwd.txt",
  };
  const explicitInput = {
    target: "local",
    cwd: fixture.root,
    command: "touch explicit-cwd.txt",
  };
  const omittedBinding = await fixture.execution.prepareAuthorityBinding(
    omittedInput,
    target.target,
    target.generation,
  );
  const explicitBinding = await fixture.execution.prepareAuthorityBinding(
    explicitInput,
    target.target,
    target.generation,
  );
  const omittedCwd = (omittedBinding as PreparedExecExecutionBinding & {
    effectiveCwd?: string;
  }).effectiveCwd;
  const explicitCwd = (explicitBinding as PreparedExecExecutionBinding & {
    effectiveCwd?: string;
  }).effectiveCwd;
  assert.equal(omittedCwd, await realpath(fixture.root));
  assert.equal(explicitCwd, omittedCwd);
  const omittedAction = execAction(
    omittedInput,
    target.target.id,
    String(omittedCwd),
    omittedBinding,
  );
  const explicitAction = execAction(
    explicitInput,
    target.target.id,
    String(explicitCwd),
    explicitBinding,
  );
  assert.equal(
    actionResourceKeySha256(omittedAction),
    actionResourceKeySha256(explicitAction),
  );

  const authority = new OperationAuthorityRegistry({
    minimumRisk: minimumAuthorityRisk,
    storePath: join(fixture.root, "v2-state", "cwd-alias-authority.sqlite"),
    instanceId: "cwd-alias-authority-owner",
  });
  t.after(() => authority.close());
  const principal = "cwd-alias-principal";
  const first = authority.create({
    taskId: "cwd-alias-omitted",
    authorityText: "Claim the canonical default working directory.",
    actions: [{ descriptor: omittedAction, risk: omittedBinding.launchRisk }],
  }, principal);
  const second = authority.create({
    taskId: "cwd-alias-explicit",
    authorityText: "Claim the same canonical explicit working directory.",
    actions: [{ descriptor: explicitAction, risk: explicitBinding.launchRisk }],
  }, principal);
  const firstDispatch = authority.prepareDispatch(
    String(first.authorityId),
    principal,
    omittedAction,
    omittedBinding.launchRisk,
  );
  firstDispatch.claim();
  assert.throws(
    () => authority.prepareDispatch(
      String(second.authorityId),
      principal,
      explicitAction,
      explicitBinding.launchRisk,
    ).claim(),
    (error: unknown) => brokerCode(error) === "RESOURCE_BUSY",
  );
  firstDispatch.cancelNotDispatched({
    providerCallCount: 0,
    proof: "TEST_EXEC_CWD_ALIAS_PROVIDER_ZERO",
  });

  const project = join(fixture.root, "context-project");
  await mkdir(project);
  const context = await fixture.contexts.open({ path: project });
  const contextInput = { contextId: context.contextId, command: "touch context-cwd.txt" };
  const explicitContextInput = {
    target: "local",
    cwd: project,
    command: "touch context-explicit-cwd.txt",
  };
  const contextBinding = await fixture.execution.prepareAuthorityBinding(
    contextInput,
    target.target,
    target.generation,
  );
  const explicitContextBinding = await fixture.execution.prepareAuthorityBinding(
    explicitContextInput,
    target.target,
    target.generation,
  );
  const contextCwd = (contextBinding as PreparedExecExecutionBinding & {
    effectiveCwd?: string;
  }).effectiveCwd;
  const explicitContextCwd = (explicitContextBinding as PreparedExecExecutionBinding & {
    effectiveCwd?: string;
  }).effectiveCwd;
  assert.equal(contextCwd, await realpath(project));
  assert.equal(contextCwd, explicitContextCwd);
  assert.equal(
    actionResourceKeySha256(execAction(
      contextInput,
      target.target.id,
      String(contextCwd),
      contextBinding,
    )),
    actionResourceKeySha256(execAction(
      explicitContextInput,
      target.target.id,
      String(explicitContextCwd),
      explicitContextBinding,
    )),
  );
});

interface Fixture {
  root: string;
  targetsPath: string;
  targets: TargetRegistry;
  contexts: ContextRegistry;
  execution: UniversalExecutionPlane;
}

async function createFixture(
  t: TestContext,
  overrides: Partial<{
    maxProcessRecords: number;
    maxRunningProcesses: number;
    processBufferCharacters: number;
    spawnProcess: NonNullable<ExecutionPlaneOptions["spawnProcess"]>;
    envProfiles: UniversalEnvProfileRegistry;
    durableAdapter: DurableProcessAdapter;
  }> = {},
): Promise<Fixture> {
  const root = await mkdtemp(join(tmpdir(), "devspace-v2-exec-test-"));
  t.after(async () => {
    await fixtureExecution?.close();
    await rm(root, { recursive: true, force: true });
  });
  const targetsPath = join(root, "targets.json");
  const fakeBin = join(root, "fake-bin");
  const fakeSetpriv = join(fakeBin, "setpriv");
  await mkdir(fakeBin, { recursive: true });
  await writeFile(fakeSetpriv, [
    "#!/bin/sh",
    "[ \"$1\" = \"--no-new-privs\" ] || exit 64",
    "shift",
    "[ \"$1\" = \"--\" ] || exit 64",
    "shift",
    "exec \"$@\"",
    "",
  ].join("\n"));
  await chmod(fakeSetpriv, 0o700);
  const fakeSsh = join(root, "fake-ssh.sh");
  await writeFile(fakeSsh, [
    "#!/bin/sh",
    `PATH=${shellQuoteForTest(fakeBin)}:$PATH`,
    `DEVSPACE_TEST_SETPRIV=${shellQuoteForTest(fakeSetpriv)}`,
    "export PATH",
    "all=\" $* \"",
    "for last do :; done",
    "case \"$all\" in",
    "  *' offline '*) exit 255 ;;",
    "  *' unknown '*)",
    "    marker=$(printf '%s' \"$last\" | grep -o '__DEVSPACE_DISPATCHED_[A-Za-z0-9]*__' | head -1)",
    "    printf '%s\\n' \"$marker\" >&2",
    "    exit 255",
    "    ;;",
    "esac",
    "last=$(printf '%s' \"$last\" | sed \"s#/usr/bin/setpriv#$DEVSPACE_TEST_SETPRIV#g; s#/bin/setpriv#$DEVSPACE_TEST_SETPRIV#g\")",
    "exec /bin/sh -c \"$last\"",
    "",
  ].join("\n"));
  await chmod(fakeSsh, 0o700);
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
        ...(overrides.durableAdapter
          ? {
              capabilities: { durableProcess: true },
              durableProcess: { mode: "launchd" },
            }
          : {}),
      },
      fake: sshTarget("fake"),
      "no-pty": {
        ...sshTarget("no-pty"),
        platform: "macos",
      },
      offline: sshTarget("offline"),
      unknown: sshTarget("unknown"),
    },
  }, null, 2));
  const serverConfig = loadConfig({
    DEVSPACE_CONFIG_DIR: join(root, ".config"),
    DEVSPACE_ALLOWED_ROOTS: root,
    DEVSPACE_STATE_DIR: join(root, "legacy-state"),
    DEVSPACE_WORKTREE_ROOT: join(root, "worktrees"),
    DEVSPACE_OAUTH_OWNER_TOKEN: "phase3-test-owner-credential-123456789",
    DEVSPACE_PUBLIC_BASE_URL: "http://127.0.0.1:17676",
    DEVSPACE_LOG_LEVEL: "silent",
  });
  const targets = new TargetRegistry({
    configPath: targetsPath,
    sshExecutable: fakeSsh,
    sftpExecutable: "/usr/bin/true",
  });
  const contexts = new ContextRegistry({
    storePath: join(root, "v2-state", "contexts.json"),
    targets,
    serverConfig,
  });
  let fixtureExecution: UniversalExecutionPlane | undefined;
  fixtureExecution = new UniversalExecutionPlane({
    targets,
    contexts,
    outputDir: join(root, "v2-state", "process-output"),
    sshControlDir: join(root, "v2-state", "ssh-control"),
    maxRunningProcesses: overrides.maxRunningProcesses ?? 32,
    maxProcessRecords: overrides.maxProcessRecords,
    maxRunningProcessesPerTarget: 16,
    processBufferCharacters: overrides.processBufferCharacters ?? 1_000_000,
    processOutputMaxBytes: 10_000_000,
    completedProcessTtlMs: 60_000,
    sshExecutable: fakeSsh,
    spawnProcess: overrides.spawnProcess,
    envProfiles: overrides.envProfiles,
    durableAdapter: overrides.durableAdapter,
  });
  return { root, targetsPath, targets, contexts, execution: fixtureExecution };
}

function sshTarget(sshHost: string) {
  return {
    displayName: sshHost,
    aliases: [sshHost],
    transport: "ssh",
    sshHost,
    platform: "linux",
    shell: "sh",
  };
}

function shellQuoteForTest(value: string): string {
  return `'${value.replaceAll("'", `'"'"'`)}'`;
}

function brokerCode(error: unknown): string | undefined {
  return error instanceof UniversalBrokerError ? error.code : undefined;
}

function restoreEnvironment(name: string, value: string | undefined): void {
  if (value === undefined) delete process.env[name];
  else process.env[name] = value;
}

class FixtureDurableAdapter implements DurableProcessAdapter {
  readonly identity: DurableProcessIdentity = {
    managerHandle: "fixture-manager-handle",
    pid: 4242,
    startToken: "fixture-start-token",
  };
  launches = 0;
  reattaches = 0;

  async launch(
    _request: Parameters<DurableProcessAdapter["launch"]>[0],
    _events: DurableProcessEvents,
  ): Promise<DurableProcessHandle> {
    this.launches += 1;
    return this.handle();
  }

  async reattach(
    identity: DurableProcessIdentity,
    _events: DurableProcessEvents,
  ): Promise<ReturnType<DurableProcessAdapter["reattach"]> extends Promise<infer T> ? T : never> {
    this.reattaches += 1;
    assert.deepEqual(identity, this.identity);
    return { state: "RUNNING", identity: this.identity, handle: this.handle() };
  }

  private handle(): DurableProcessHandle {
    return {
      identity: this.identity,
      write: () => undefined,
      kill: () => undefined,
      close: () => undefined,
    };
  }
}

function owner(label: string) {
  return createCapabilityCallContextFromTrustedPrincipal({
    principalKeyFingerprint: createHash("sha256").update(label).digest("hex"),
  });
}
