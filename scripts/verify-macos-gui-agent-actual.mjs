import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { spawn, spawnSync } from "node:child_process";
import { realpathSync } from "node:fs";
import {
  chmod,
  mkdir,
  readFile,
  realpath,
  rename,
  rm,
  stat,
  writeFile,
} from "node:fs/promises";
import { once } from "node:events";
import { homedir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const repositoryRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const taskRoot = join(
  homedir(),
  "Downloads",
  ".agent-harness",
  "tasks",
  "20260822-devspace-codex-parity",
);
const evidenceRoot = join(taskRoot, "runs", "phase4d-gui-tcc-actual-20260822");
const workingRoot = "/private/tmp/codex-parity-gui-20260822-actual-01";
const reportPath = join(evidenceRoot, "ACTUAL-GUI-TCC.json");
const capturePath = join(evidenceRoot, "CAPTURE.jpg");
const verificationPath = join(evidenceRoot, "EVIDENCE-VERIFICATION.json");
const marker = "__DEVSPACE_V2_GUI_JSON__";
const fixtureBundleIdentifier = "com.devspace.gui-fixture.actual20260822";
class ActualBlockedError extends Error {}

const startedAt = new Date().toISOString();
let fixturePid;
let fixtureChild;
let fixtureStdout = "";
let fixtureStderr = "";
let cleanup = { fixtureTerminated: false, workingRootRemoved: false };
let report = {
  schemaVersion: 1,
  status: "FAIL",
  evidenceSource: "ACTUAL_LOCAL_MACOS_AQUA_SESSION",
  startedAt,
  endedAt: startedAt,
  repositoryRevision: gitRevision(),
  sourceRevision: gitRevision(),
  runtimeUnderTestRevision: gitRevision(),
  testCommands: [
    "node scripts/verify-macos-user-authorization-native.mjs",
    "node --test scripts/build-macos-gui-agent.test.mjs scripts/devspace-computer-use-mcp.test.mjs",
    "npm run typecheck",
    "npm run build",
    "npm run generate:v2 (byte-stable generated contract parity)",
    "npm test",
    "DEVSPACE_MACOS_CODESIGN_IDENTITY='Cozy Connect Local Development' node scripts/verify-macos-gui-agent-actual.mjs",
  ],
  steps: [],
  cleanup,
};

try {
  if (process.platform !== "darwin") throw new Error("Actual macOS GUI verification requires macOS.");
  await prepareEvidenceRoot();
  await rm(workingRoot, { recursive: true, force: true });
  await mkdir(workingRoot, { recursive: false, mode: 0o700 });
  await chmod(workingRoot, 0o700);
  const canonicalWorkingRoot = await realpath(workingRoot);
  assert.equal(canonicalWorkingRoot, workingRoot);

  const signingIdentity = process.env.DEVSPACE_MACOS_CODESIGN_IDENTITY
    ?? "Cozy Connect Local Development";
  const agentBuild = spawnSync(
    process.execPath,
    [join(repositoryRoot, "scripts", "build-macos-gui-agent.mjs")],
    {
      cwd: repositoryRoot,
      encoding: "utf8",
      timeout: 120_000,
      env: { ...process.env, DEVSPACE_MACOS_CODESIGN_IDENTITY: signingIdentity },
    },
  );
  assert.equal(agentBuild.error, undefined, agentBuild.error?.message);
  assert.equal(agentBuild.status, 0, `${agentBuild.stdout}\n${agentBuild.stderr}`);
  const agentApp = join(
    repositoryRoot,
    "dist",
    "native",
    "macos-gui-agent",
    "DevSpace GUI Agent.app",
  );
  const agent = join(agentApp, "Contents", "MacOS", "devspace-gui-agent");
  const fixtureBuildRoot = join(workingRoot, "fixture-build");
  const fixtureStatePath = join(workingRoot, "fixture-state.json");
  const fixtureApp = join(fixtureBuildRoot, "DevSpace GUI Fixture.app");
  const fixture = join(fixtureApp, "Contents", "MacOS", "devspace-gui-fixture");

  assertRegularExecutable(agent);
  const fixtureBuild = spawnSync(
    join(repositoryRoot, "native", "macos-gui-fixture", "build.sh"),
    [fixtureBuildRoot],
    {
      cwd: repositoryRoot,
      encoding: "utf8",
      timeout: 120_000,
      env: {
        ...process.env,
        DEVSPACE_MACOS_CODESIGN_IDENTITY:
          process.env.DEVSPACE_MACOS_CODESIGN_IDENTITY ?? "Cozy Connect Local Development",
        DEVSPACE_GUI_FIXTURE_BUNDLE_ID: fixtureBundleIdentifier,
      },
    },
  );
  assert.equal(fixtureBuild.error, undefined, fixtureBuild.error?.message);
  assert.equal(fixtureBuild.status, 0, `${fixtureBuild.stdout}\n${fixtureBuild.stderr}`);
  assertRegularExecutable(fixture);
  const agentIdentity = codeIdentity(agentApp, agent);
  const fixtureIdentity = codeIdentity(fixtureApp, fixture);
  assert.equal(agentIdentity.authority, signingIdentity);
  assert.ok(
    agentIdentity.designatedRequirement?.includes("certificate leaf"),
    `GUI agent does not have a stable certificate-bound requirement: ${agentIdentity.designatedRequirement}`,
  );
  report.agent = agentIdentity;
  report.fixture = fixtureIdentity;
  record("build-and-sign", "PASS", {
    agentRequirement: agentIdentity.designatedRequirement,
    fixtureRequirement: fixtureIdentity.designatedRequirement,
  });

  const before = runAgent(agent, ["capabilities"]);
  report.permissionsBefore = before.data;
  record("capabilities-before", before.ok ? "PASS" : "FAIL", before.data ?? before);

  const requested = runAgent(agent, ["request-access", "accessibility,screen_capture"], 120_000);
  report.permissionRequest = requested.data ?? requested;
  record("request-access", requested.ok ? "PASS" : "FAIL", requested.data ?? requested);

  const after = runAgent(agent, ["capabilities"]);
  const agentIdentityAfterRequest = codeIdentity(agentApp, agent);
  assert.deepEqual(agentIdentityAfterRequest, agentIdentity, "GUI agent identity changed during TCC request");
  report.agentIdentityAfterRequest = agentIdentityAfterRequest;
  report.permissionsAfter = after.data;
  if (after.data?.accessibility !== true || after.data?.screenCapture !== true) {
    report.status = "BLOCKED_TCC";
    record("capabilities-after", "BLOCKED_TCC", after.data ?? after);
    throw new ActualBlockedError("Accessibility or Screen Recording permission is not active.");
  }
  record("capabilities-after", "PASS", after.data);

  terminateBundleApplications(fixtureBundleIdentifier);
  fixtureChild = spawn(fixture, [fixtureStatePath], {
    cwd: workingRoot,
    detached: false,
    stdio: ["ignore", "pipe", "pipe"],
    env: {
      PATH: "/usr/bin:/bin:/usr/sbin:/sbin",
      HOME: homedir(),
      LANG: "C.UTF-8",
    },
  });
  fixtureChild.stdout.setEncoding("utf8");
  fixtureChild.stderr.setEncoding("utf8");
  fixtureChild.stdout.on("data", (chunk) => {
    fixtureStdout = bounded(`${fixtureStdout}${chunk}`, 8000);
  });
  fixtureChild.stderr.on("data", (chunk) => {
    fixtureStderr = bounded(`${fixtureStderr}${chunk}`, 8000);
  });
  await once(fixtureChild, "spawn");
  fixturePid = requirePid(fixtureChild.pid);
  const readyState = await waitForJson(
    fixtureStatePath,
    (value) => value.state === "READY" && value.bundleIdentifier === fixtureBundleIdentifier,
    15_000,
  );
  assert.equal(requirePid(readyState.pid), fixturePid);
  record("fixture-launch", "PASS", {
    pid: fixturePid,
    bundleIdentifier: readyState.bundleIdentifier,
    initialValue: readyState.value,
  });

  const observation = await waitForObservation(agent, fixtureBundleIdentifier, fixturePid, 15_000);
  const observed = observation.data;
  const input = findElement(observed, (element) => (
    element.role === "AXTextField"
    && (element.name === "devspace-input"
      || element.description === "DevSpace Input"
      || element.value === "before")
  ), "text field");
  const button = findElement(observed, (element) => (
    element.role === "AXButton"
    && (element.name === "Apply" || element.description === "Apply")
  ), "Apply button");
  assert.equal(observed.window?.title, "DevSpace GUI Fixture");
  record("observe", "PASS", {
    application: observed.application,
    windowTitle: observed.window?.title,
    totalElements: observed.totalElements,
    selectedElements: [elementSummary(input), elementSummary(button)],
  });

  const actualValue = "devspace-actual-gui-한글-✓";
  const setValue = runAgent(agent, actArguments(observed, input, {
    type: "set_value",
    value: actualValue,
  }));
  assert.equal(setValue.ok, true, JSON.stringify(setValue));
  record("set-value", "PASS", setValue.data);

  const afterValue = await waitForObservation(agent, fixtureBundleIdentifier, fixturePid, 5_000);
  const buttonAfterValue = findElement(afterValue.data, (element) => (
    element.role === "AXButton"
    && (element.name === "Apply" || element.description === "Apply")
  ), "Apply button after value change");
  const press = runAgent(agent, actArguments(afterValue.data, buttonAfterValue, { type: "press" }));
  assert.equal(press.ok, true, JSON.stringify(press));
  record("press", "PASS", press.data);

  const appliedState = await waitForJson(
    fixtureStatePath,
    (value) => value.state === "APPLIED" && value.applied === true && value.value === actualValue,
    10_000,
  );
  record("fixture-readback", "PASS", {
    state: appliedState.state,
    applied: appliedState.applied,
    value: appliedState.value,
  });

  const afterPress = await waitForObservation(agent, fixtureBundleIdentifier, fixturePid, 5_000);
  const status = findElement(afterPress.data, (element) => (
    (element.name === "devspace-status" || element.description === "DevSpace Status")
    && element.value === `Applied: ${actualValue}`
  ), "applied status readback");
  record("accessibility-readback", "PASS", elementSummary(status));

  const capture = runAgent(agent, ["capture", "jpeg", "40", "640", String(fixturePid)], 30_000);
  assert.equal(capture.ok, true, JSON.stringify(capture));
  const captureBytes = Buffer.from(String(capture.data.contentBase64 ?? ""), "base64");
  assert.ok(captureBytes.length > 0);
  assert.equal(captureBytes.length, capture.data.size);
  const captureSha256 = `sha256:${createHash("sha256").update(captureBytes).digest("hex")}`;
  assert.equal(captureSha256, capture.data.sha256);
  assert.equal(capture.data.mimeType, "image/jpeg");
  assert.equal(capture.data.pid, fixturePid);
  assert.ok(captureBytes.length >= 1_024 && captureBytes.length <= 2 * 1024 * 1024);
  assert.equal(captureBytes[0], 0xff);
  assert.equal(captureBytes[1], 0xd8);
  assert.equal(captureBytes.at(-2), 0xff);
  assert.equal(captureBytes.at(-1), 0xd9);
  await writeFile(capturePath, captureBytes, { mode: 0o600 });
  await chmod(capturePath, 0o600);
  report.capture = {
    mimeType: capture.data.mimeType,
    size: capture.data.size,
    sha256: capture.data.sha256,
    width: capture.data.width,
    height: capture.data.height,
    pid: capture.data.pid,
    path: capturePath,
    retained: true,
  };
  record("capture", "PASS", report.capture);

  report.status = "PASS";
} catch (error) {
  if (error instanceof ActualBlockedError) {
    if (report.status !== "BLOCKED_TCC") report.status = "BLOCKED_TCC";
  } else {
    report.status = "FAIL";
    report.error = error instanceof Error
      ? {
          name: error.name,
          message: error.message,
          stack: bounded(error.stack ?? "", 8000),
          fixtureStdout,
          fixtureStderr,
        }
      : { name: typeof error, message: String(error), fixtureStdout, fixtureStderr };
  }
} finally {
  try {
    if (fixtureChild && fixtureChild.exitCode === null && fixtureChild.signalCode === null) {
      fixtureChild.kill("SIGTERM");
      await Promise.race([
        once(fixtureChild, "exit"),
        delay(2_000),
      ]);
    }
    if (fixturePid !== undefined) {
      try { process.kill(fixturePid, 0); } catch (error) {
        if (!(error && typeof error === "object" && error.code === "ESRCH")) throw error;
      }
    }
    terminateBundleApplications(fixtureBundleIdentifier);
    cleanup.fixtureTerminated = true;
  } catch (error) {
    cleanup.fixtureTerminationError = error instanceof Error ? error.message : String(error);
  }
  try {
    await rm(workingRoot, { recursive: true, force: true });
    cleanup.workingRootRemoved = true;
  } catch (error) {
    cleanup.workingRootRemovalError = error instanceof Error ? error.message : String(error);
  }
  report.endedAt = new Date().toISOString();
  report.cleanup = cleanup;
  await mkdir(evidenceRoot, { recursive: true, mode: 0o700 });
  await chmod(evidenceRoot, 0o700);
  await writeFile(reportPath, `${JSON.stringify(report, null, 2)}\n`, { mode: 0o600 });
  await chmod(reportPath, 0o600);
  if (report.status === "PASS") {
    const reportBytes = await readFile(reportPath);
    const retainedCapture = await readFile(capturePath);
    const verification = {
      schemaVersion: 1,
      status: "PASS",
      verifiedAt: new Date().toISOString(),
      verifier: "scripts/verify-macos-gui-agent-actual.mjs",
      repositoryRevision: report.repositoryRevision,
      report: {
        path: reportPath,
        sha256: `sha256:${createHash("sha256").update(reportBytes).digest("hex")}`,
        size: reportBytes.length,
      },
      capture: {
        path: capturePath,
        sha256: `sha256:${createHash("sha256").update(retainedCapture).digest("hex")}`,
        size: retainedCapture.length,
      },
      assertions: {
        stableAgentIdentity: JSON.stringify(report.agent) === JSON.stringify(report.agentIdentityAfterRequest),
        fixturePidBoundCapture: report.capture?.pid === report.steps.find((step) => step.step === "fixture-launch")?.evidence?.pid,
        cleanupComplete: cleanup.fixtureTerminated === true && cleanup.workingRootRemoved === true,
      },
    };
    assert.ok(Object.values(verification.assertions).every(Boolean));
    assert.equal(verification.capture.sha256, report.capture.sha256);
    assert.equal(verification.capture.size, report.capture.size);
    await writeFile(verificationPath, `${JSON.stringify(verification, null, 2)}\n`, { mode: 0o600 });
    await chmod(verificationPath, 0o600);
  }
  process.stdout.write(`${JSON.stringify({ status: report.status, reportPath, cleanup })}\n`);
}

process.exit(report.status === "PASS" ? 0 : report.status === "BLOCKED_TCC" ? 2 : 1);


function terminateBundleApplications(bundleIdentifier) {
  const listed = spawnSync("/usr/bin/lsappinfo", ["list"], { encoding: "utf8", timeout: 10_000 });
  if (listed.status !== 0) return;
  const blocks = listed.stdout.split(/(?=^\d+\) )/mu);
  for (const block of blocks) {
    if (!block.includes(`bundleID="${bundleIdentifier}"`)) continue;
    const pid = Number(block.match(/\bpid = (\d+)\b/u)?.[1]);
    if (!Number.isSafeInteger(pid) || pid <= 1) continue;
    try { process.kill(pid, "SIGTERM"); } catch (error) {
      if (!(error && typeof error === "object" && error.code === "ESRCH")) throw error;
    }
  }
}

function runAgent(agent, args, timeout = 30_000) {
  const result = spawnSync(agent, args, {
    cwd: repositoryRoot,
    encoding: "utf8",
    timeout,
    maxBuffer: 2 * 1024 * 1024,
    env: {
      PATH: "/usr/bin:/bin:/usr/sbin:/sbin",
      HOME: homedir(),
      LANG: "C.UTF-8",
    },
  });
  assert.equal(result.error, undefined, result.error?.message);
  assert.equal(result.status, 0, `${result.stdout}\n${result.stderr}`);
  const line = result.stdout.split(/\r?\n/u).find((value) => value.startsWith(marker));
  assert.ok(line, `GUI agent returned no framed JSON: ${bounded(result.stdout, 2000)}`);
  return JSON.parse(line.slice(marker.length));
}

function actArguments(observation, element, action) {
  const encode = (value) => Buffer.from(String(value ?? ""), "utf8").toString("base64");
  return [
    "act",
    String(element.index),
    action.type,
    encode(action.actionName ?? ""),
    encode(action.value ?? ""),
    (action.modifiers ?? []).join(","),
    String(action.keyCode ?? -1),
    String(observation.application.pid),
    encode(observation.window?.title ?? ""),
    encode(element.role),
    encode(element.name),
    encode(element.description),
    encode(element.subrole),
  ];
}

async function waitForObservation(agent, bundleIdentifier, applicationPid, timeoutMs) {
  const deadline = Date.now() + timeoutMs;
  let last;
  while (Date.now() < deadline) {
    last = runAgent(agent, ["observe", "250", String(applicationPid)]);
    if (
      last.ok
      && last.data?.application?.bundleIdentifier === bundleIdentifier
      && last.data?.application?.pid === applicationPid
    ) return last;
    await delay(100);
  }
  throw new Error(`Fixture process did not become observable: ${JSON.stringify(last)}`);
}

async function waitForJson(path, predicate, timeoutMs) {
  const deadline = Date.now() + timeoutMs;
  let last;
  while (Date.now() < deadline) {
    try {
      last = JSON.parse(await readFile(path, "utf8"));
      if (predicate(last)) return last;
    } catch (error) {
      if (!(error && typeof error === "object" && error.code === "ENOENT")) throw error;
    }
    await delay(50);
  }
  throw new Error(`Timed out waiting for fixture state: ${JSON.stringify(last)}`);
}

function codeIdentity(appPath, executablePath) {
  const verification = spawnSync("/usr/bin/codesign", ["--verify", "--deep", "--strict", appPath], {
    encoding: "utf8",
    timeout: 10_000,
  });
  assert.equal(verification.status, 0, verification.stderr);
  const signature = spawnSync("/usr/bin/codesign", ["-dvvv", "--requirements", "-", appPath], {
    encoding: "utf8",
    timeout: 10_000,
  });
  assert.equal(signature.status, 0, signature.stderr);
  const output = `${signature.stdout}\n${signature.stderr}`;
  const requirement = output.match(/designated => (.+)$/mu)?.[1];
  const authority = output.match(/^Authority=(.+)$/mu)?.[1];
  const executableBytes = spawnSync("/usr/bin/shasum", ["-a", "256", executablePath], {
    encoding: "utf8",
    timeout: 10_000,
  });
  assert.equal(executableBytes.status, 0, executableBytes.stderr);
  const appState = spawnSync("/usr/bin/stat", ["-f", "%Su:%Sg:%Lp", appPath], { encoding: "utf8" });
  const executableState = spawnSync("/usr/bin/stat", ["-f", "%Su:%Sg:%Lp", executablePath], { encoding: "utf8" });
  const bundleIdentifier = spawnSync("/usr/bin/defaults", ["read", join(appPath, "Contents", "Info"), "CFBundleIdentifier"], { encoding: "utf8" });
  assert.equal(appState.status, 0, appState.stderr);
  assert.equal(executableState.status, 0, executableState.stderr);
  assert.equal(bundleIdentifier.status, 0, bundleIdentifier.stderr);
  return {
    appPath: realpathSync(appPath),
    executablePath: realpathSync(executablePath),
    executableSha256: `sha256:${executableBytes.stdout.trim().split(/\s+/u)[0]}`,
    bundleIdentifier: bundleIdentifier.stdout.trim(),
    authority: authority ?? null,
    designatedRequirement: requirement ?? null,
    appOwnerGroupMode: appState.stdout.trim(),
    executableOwnerGroupMode: executableState.stdout.trim(),
    codeSignatureVerified: true,
  };
}

async function prepareEvidenceRoot() {
  await mkdir(dirname(evidenceRoot), { recursive: true, mode: 0o700 });
  try {
    const state = await stat(evidenceRoot);
    if (!state.isDirectory()) throw new Error(`Evidence path is not a directory: ${evidenceRoot}`);
    const archived = `${evidenceRoot}.previous-${Date.now()}`;
    await rename(evidenceRoot, archived);
  } catch (error) {
    if (!(error && typeof error === "object" && error.code === "ENOENT")) throw error;
  }
  await mkdir(evidenceRoot, { recursive: false, mode: 0o700 });
  await chmod(evidenceRoot, 0o700);
}

function findElement(observation, predicate, label) {
  const elements = Array.isArray(observation?.elements) ? observation.elements : [];
  const match = elements.find(predicate);
  assert.ok(match, `Unable to locate ${label}. Elements: ${JSON.stringify(elements.map(elementSummary))}`);
  return match;
}

function elementSummary(element) {
  return {
    elementId: element.elementId,
    index: element.index,
    role: element.role,
    subrole: element.subrole,
    name: element.name,
    description: element.description,
    value: element.value,
    actions: element.actions,
  };
}

function record(step, status, evidence) {
  report.steps.push({ step, status, evidence });
}

function gitRevision() {
  const result = spawnSync("/usr/bin/git", ["rev-parse", "HEAD"], {
    cwd: repositoryRoot,
    encoding: "utf8",
    timeout: 10_000,
  });
  return result.status === 0 ? result.stdout.trim() : "unknown";
}

function requirePid(value) {
  assert.ok(Number.isSafeInteger(value) && value > 1 && value <= 2_147_483_647, `Invalid fixture PID: ${value}`);
  return value;
}

function assertRegularExecutable(path) {
  const result = spawnSync("/bin/test", ["-x", path]);
  assert.equal(result.status, 0, `Missing executable: ${path}`);
}

function bounded(value, maximum) {
  const text = String(value).replace(/[\0\r]+/gu, " ");
  return text.length <= maximum ? text : `${text.slice(0, maximum)}…`;
}

function delay(milliseconds) {
  return new Promise((resolvePromise) => setTimeout(resolvePromise, milliseconds));
}
