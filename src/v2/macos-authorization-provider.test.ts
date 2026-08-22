import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { once } from "node:events";
import {
  chmod,
  mkdtemp,
  readFile,
  realpath,
  readdir,
  rm,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { createCapabilityCallContextFromTrustedPrincipal } from "./capability-call-context.js";
import type { RuntimeIdentity } from "./contracts.js";
import { normalizeExecutionElevation } from "./elevation.js";
import { MacOsAuthorizationProvider } from "./macos-authorization-provider.js";
import { createUserAuthorizationDescriptor } from "./user-authorization.js";

const PRINCIPAL = "1".repeat(64);
const TARGET_GENERATION = `sha256:${"2".repeat(64)}`;
const RUNTIME: RuntimeIdentity = {
  productVersion: "2.1.1",
  productProfile: "PERSONAL_DIRECT_OWNER",
  buildCapabilityDigest: `sha256:${"3".repeat(64)}`,
  resourceUriVersion: "v1",
  schemaGeneration: `sha256:${"4".repeat(64)}`,
  configDigest: `sha256:${"5".repeat(64)}`,
  sourceRevision: "6".repeat(40),
  runtimeRevision: "6".repeat(40),
  buildDigest: `sha256:${"7".repeat(64)}`,
  startedAt: "2030-01-01T00:00:00.000Z",
};
const ELEVATION = normalizeExecutionElevation({
  mode: "prompt",
  reason: "Create a protected task-owned fixture",
  timeoutMs: 10_000,
}) as ReturnType<typeof normalizeExecutionElevation> & { mode: "prompt" };

test("macOS provider validates pinned binaries, retains approval session, and cleans exact task files", async (t) => {
  const fixture = await createFixture(t, "APPROVED");
  const request = providerRequest("macos-provider-approved");
  const capability = await fixture.provider.capability({
    targetId: "local",
    targetGeneration: TARGET_GENERATION,
    platform: "macos",
  });
  assert.equal(capability.available, true);
  assert.match(capability.providerGeneration, /^sha256:[a-f0-9]{64}$/u);

  const decision = await fixture.provider.authorize(request);
  assert.equal(decision.receipt.decision, "APPROVED");
  assert.equal(decision.receipt.descriptorDigest, request.descriptor.descriptorDigest);
  assert.doesNotMatch(JSON.stringify(decision.receipt), /Create a protected|printf MACOS/u);

  const child = await fixture.provider.launch({ ...request, receipt: decision.receipt });
  const taskDirectory = join(fixture.workRoot, request.descriptor.authorizationOperationId);
  const script = await readFile(join(taskDirectory, "action.zsh"), "utf8");
  const spec = await readFile(join(taskDirectory, "task.spec"), "utf8");
  assert.match(script, /printf MACOS_PROVIDER_LAUNCH_OK/u);
  assert.match(spec, new RegExp(request.descriptor.descriptorDigest.replace(/[.*+?^${}()|[\]\\]/g, "\\$&"), "u"));
  assert.match(spec, /scriptSha256=sha256:[a-f0-9]{64}/u);
  assert.match(spec, /userUid=/u);

  let output = "";
  child.stdout.setEncoding("utf8");
  child.stdout.on("data", (chunk: string) => { output += chunk; });
  const [code, signal] = await once(child, "exit") as [number | null, NodeJS.Signals | null];
  assert.equal(signal, null);
  assert.equal(code, 0);
  assert.match(output, /MACOS_PROVIDER_LAUNCH_OK/u);
  await waitForEmptyDirectory(fixture.workRoot);
});

test("macOS provider returns denied receipt without retaining a launch session", async (t) => {
  const fixture = await createFixture(t, "DENIED");
  const request = providerRequest("macos-provider-denied");
  const decision = await fixture.provider.authorize(request);
  assert.equal(decision.receipt.decision, "DENIED");
  await assert.rejects(
    fixture.provider.launch({ ...request, receipt: decision.receipt }),
    /Only an approved receipt/u,
  );
  assert.deepEqual(await readdir(fixture.workRoot), []);
});

test("macOS provider rejects mismatched protocol identity and changed binaries", async (t) => {
  const mismatch = await createFixture(t, "MISMATCH");
  await assert.rejects(
    mismatch.provider.authorize(providerRequest("macos-provider-mismatch")),
    /mismatched descriptor digest/u,
  );

  const changed = await createFixture(t, "APPROVED");
  await writeFile(changed.helperPath, "#!/bin/zsh\nexit 0\n# changed\n", { mode: 0o700 });
  await chmod(changed.helperPath, 0o700);
  const capability = await changed.provider.capability({
    targetId: "local",
    targetGeneration: TARGET_GENERATION,
    platform: "macos",
  });
  assert.equal(capability.available, false);
  assert.match(String(capability.reason), /digest changed/u);
});

test("macOS provider refuses unsupported target and privileged PTY before prompt", async (t) => {
  const fixture = await createFixture(t, "APPROVED");
  const linuxCapability = await fixture.provider.capability({
    targetId: "linux",
    targetGeneration: TARGET_GENERATION,
    platform: "linux",
  });
  assert.equal(linuxCapability.available, false);
  const request = providerRequest("macos-provider-pty");
  request.descriptor = createUserAuthorizationDescriptor({
    ...descriptorInput("macos-provider-pty"),
    tty: true,
  });
  await assert.rejects(
    fixture.provider.authorize(request),
    /does not support a privileged PTY/u,
  );
});

async function createFixture(
  t: test.TestContext,
  behavior: "APPROVED" | "DENIED" | "MISMATCH",
) {
  const root = await realpath(await mkdtemp(join(tmpdir(), "devspace-macos-authorization-provider-")));
  const agentPath = join(root, "fake-agent.mjs");
  const helperPath = join(root, "fake-helper");
  const workRoot = join(root, "work");
  const agentSource = `#!${process.execPath}
import fs from "node:fs";
const args = process.argv.slice(2);
const get = (name) => args[args.indexOf(name) + 1];
const descriptor = get("--descriptor-digest");
const nonce = get("--nonce");
const behavior = ${JSON.stringify(behavior)};
const returned = behavior === "MISMATCH" ? "sha256:" + "f".repeat(64) : descriptor;
const state = behavior === "DENIED" ? "DENIED" : "APPROVED";
process.stdout.write(["DEVSPACE_AUTHORIZATION_RESULT", state, returned, ...(state === "APPROVED" ? [nonce] : [])].join("\\t") + "\\n");
if (state !== "APPROVED" || behavior === "MISMATCH") process.exit(77);
let pending = "";
process.stdin.setEncoding("utf8");
process.stdin.on("data", (chunk) => {
  pending += chunk;
  const newline = pending.indexOf("\\n");
  if (newline < 0) return;
  const parts = pending.slice(0, newline).split("\\t");
  if (parts.length !== 4 || parts[0] !== "LAUNCH" || parts[1] !== descriptor) process.exit(79);
  const spec = fs.readFileSync(parts[2], "utf8");
  if (!spec.includes("descriptorDigest=" + descriptor)) process.exit(79);
  setTimeout(() => {
    process.stdout.write("MACOS_PROVIDER_LAUNCH_OK\\n");
    process.exit(0);
  }, 50);
});
`;
  await writeFile(agentPath, agentSource, { mode: 0o700 });
  await writeFile(helperPath, "#!/bin/zsh\nexit 0\n", { mode: 0o700 });
  await chmod(agentPath, 0o700);
  await chmod(helperPath, 0o700);
  const provider = new MacOsAuthorizationProvider({
    agentPath,
    agentSha256: await digest(agentPath),
    helperPath,
    helperSha256: await digest(helperPath),
    workRoot,
    expectedUid: process.getuid?.(),
    verifyCodeSignature: () => undefined,
  });
  t.after(async () => {
    await provider.close();
    await rm(root, { recursive: true, force: true });
  });
  return { root, agentPath, helperPath, workRoot, provider };
}

function providerRequest(operationId: string) {
  const descriptor = createUserAuthorizationDescriptor(descriptorInput(operationId));
  return {
    descriptor,
    command: "printf MACOS_PROVIDER_LAUNCH_OK",
    cwd: "/private/tmp",
    elevation: ELEVATION,
  };
}

function descriptorInput(operationId: string) {
  return {
    authorizationOperationId: operationId,
    callContext: createCapabilityCallContextFromTrustedPrincipal({
      principalKeyFingerprint: PRINCIPAL,
      requestId: operationId,
      explicitRequestId: operationId,
      requestNamespace: `mcp-session:${operationId}`,
      receivedAt: new Date().toISOString(),
    }),
    target: {
      id: "local",
      generation: TARGET_GENERATION,
      transport: "local" as const,
      platform: "macos",
    },
    runtimeIdentity: RUNTIME,
    command: "printf MACOS_PROVIDER_LAUNCH_OK",
    cwd: "/private/tmp",
    mode: "foreground" as const,
    tty: false,
    elevation: ELEVATION,
  };
}

async function digest(path: string): Promise<string> {
  return `sha256:${createHash("sha256").update(await readFile(path)).digest("hex")}`;
}

async function waitForEmptyDirectory(path: string): Promise<void> {
  for (let attempt = 0; attempt < 200; attempt += 1) {
    try {
      if ((await readdir(path)).length === 0) return;
    } catch {
      return;
    }
    await new Promise((resolve) => setTimeout(resolve, 10));
  }
  assert.fail(`authorization work root did not become empty: ${path}`);
}
