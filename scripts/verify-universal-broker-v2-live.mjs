#!/usr/bin/env node
import { createHash, randomBytes, randomUUID } from "node:crypto";
import { execFileSync } from "node:child_process";
import { mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import Database from "better-sqlite3";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";

const expectedTools = [
  "target",
  "context",
  "fs",
  "exec",
  "process",
  "mcp",
  "artifact",
  "gui",
];
const userScopes = [
  "devspace.read",
  "devspace.write",
  "devspace.exec",
  "devspace.mcp",
  "devspace.artifact",
  "devspace.gui",
  "offline_access",
];

const options = parseArgs(process.argv.slice(2));
const baseUrl = new URL(options.baseUrl);
const mcpUrl = options.mcpUrl
  ? new URL(options.mcpUrl)
  : new URL(options.mcpPath, baseUrl);
const healthUrl = options.healthUrl
  ? new URL(options.healthUrl)
  : new URL(options.healthPath, baseUrl);
const audit = {
  ok: false,
  baseUrl: baseUrl.href,
  mcpUrl: mcpUrl.href,
  healthUrl: healthUrl.href,
  companyGates: options.skipCompanyGates
    ? { skipped: true, reason: "Explicit --skip-company-gates deployment option." }
    : { skipped: false },
  health: undefined,
  protocolSessions: [],
  canaries: {},
};
const authorityAudit = {
  prepared: 0,
  byRisk: { R1: 0, R2: 0, R3: 0 },
  mismatchRejected: false,
  crossTransportAccepted: false,
  crossClientRejected: false,
  consumedRejected: false,
  correctionInvalidated: false,
  staticElevationBlocked: false,
  runtimeElevationBlocked: false,
};

const health = await fetch(healthUrl);
assert(health.status === 200, `health status is ${health.status}`);
audit.health = await health.json();
assert(audit.health?.status === "ok", "health payload status is not ok");

const tokenResource = await discoverTokenResource(mcpUrl, options.tokenResource);
audit.tokenResource = tokenResource;
const root = await mkdtemp(join(tmpdir(), "devspace-v2-live-"));
let credential;
let foreignCredential;
let primary;
let secondary;
let foreign;
let terminalError;
try {
  credential = createTemporaryAccessToken(options.databasePath, tokenResource);
  foreignCredential = createTemporaryAccessToken(options.databasePath, tokenResource);
  for (let index = 0; index < options.sessions; index += 1) {
    const session = await connectClient(mcpUrl, credential.token, index);
    try {
      const listed = await session.client.listTools();
      const names = listed.tools.map((tool) => tool.name);
      assert(JSON.stringify(names) === JSON.stringify(expectedTools), `tool surface mismatch: ${names.join(",")}`);
      audit.protocolSessions.push({ index: index + 1, tools: names, sessionId: session.transport.sessionId });
      if (index === 0) primary = session;
      else if (index === 1) secondary = session;
    } finally {
      if (index > 1) await session.client.close();
    }
  }
  assert(primary, "primary MCP session was not created");
  assert(secondary, "secondary MCP transport for the same OAuth client was not created");
  foreign = await connectClient(mcpUrl, foreignCredential.token, options.sessions);
  const foreignTools = await foreign.client.listTools();
  assert(
    JSON.stringify(foreignTools.tools.map((tool) => tool.name)) === JSON.stringify(expectedTools),
    "foreign OAuth client tool surface mismatch",
  );
  audit.protocolSessions.push({
    index: "foreign-client",
    tools: foreignTools.tools.map((tool) => tool.name),
    sessionId: foreign.transport.sessionId,
  });
  await runCanaries(primary.client, secondary.client, foreign.client, root, audit.canaries);
  await primary.client.close();
  await secondary.client.close();
  await foreign.client.close();
  primary = undefined;
  secondary = undefined;
  foreign = undefined;
  audit.ok = true;
} catch (error) {
  terminalError = error;
  audit.failure = safeErrorSummary(error);
} finally {
  const cleanupFailures = [];
  for (const [label, session] of [["primary", primary], ["secondary", secondary], ["foreign", foreign]]) {
    if (!session) continue;
    try {
      await session.client.close();
    } catch (error) {
      cleanupFailures.push({ label, ...safeErrorSummary(error) });
    }
  }
  for (const [label, temporaryCredential] of [["primary-oauth", credential], ["foreign-oauth", foreignCredential]]) {
    if (!temporaryCredential) continue;
    try {
      temporaryCredential.cleanup();
    } catch (error) {
      cleanupFailures.push({ label, ...safeErrorSummary(error) });
    }
  }
  try {
    await rm(root, { recursive: true, force: true });
  } catch (error) {
    cleanupFailures.push({ label: "temporary-root", ...safeErrorSummary(error) });
  }
  audit.cleanup = {
    ok: cleanupFailures.length === 0,
    ...(cleanupFailures.length > 0 ? { failures: cleanupFailures } : {}),
  };
  if (cleanupFailures.length > 0 && !terminalError) {
    terminalError = new Error("Live verifier cleanup failed.");
    audit.ok = false;
    audit.failure = safeErrorSummary(terminalError);
  }
  const serialized = JSON.stringify(audit, null, 2);
  if (options.output) await writeFile(options.output, `${serialized}\n`, { mode: 0o600 });
  console.log(serialized);
}
if (terminalError) throw terminalError;

async function runCanaries(client, sameClientTransport, foreignClient, root, canaries) {
  const targets = data(await call(client, "target", { operation: "list", limit: 100 }));
  const targetIds = (targets.targets ?? []).map((target) => target.targetId);
  assert(targetIds.includes("local"), "local target is missing");
  if (options.windowsTarget) {
    assert(targetIds.includes(options.windowsTarget), `Windows target is missing: ${options.windowsTarget}`);
  }
  if (!options.skipCompanyGates) {
    assert(targetIds.includes(options.companyTarget), `company target is missing: ${options.companyTarget}`);
  }
  canaries.targets = targetIds;

  const previewOnlyPath = join(root, "authority-preview-only.txt");
  const previewR2Path = join(root, "authority-preview-r2.txt");
  const previewRemotePath = `/tmp/devspace-preview-only-${randomUUID()}.txt`;
  const authorityPreview = data(await client.callTool({
    name: "context",
    arguments: {
      operation: "authority_preview",
      actions: [
        {
          id: "r0-inspection",
          tool: "exec",
          arguments: { target: "local", cwd: root, command: "git status --short", mode: "foreground" },
        },
        {
          id: "r1-local-write",
          tool: "fs",
          arguments: { operation: "write", path: previewOnlyPath, content: "preview-only\n" },
        },
        options.skipCompanyGates
          ? {
              id: "r2-local-remove",
              tool: "fs",
              arguments: { operation: "remove", target: "local", path: previewR2Path, disposition: "trash" },
            }
          : {
              id: "r2-remote-write",
              tool: "fs",
              arguments: { operation: "write", target: options.companyTarget, path: previewRemotePath, content: "preview-only\n" },
            },
        {
          id: "r3-push",
          tool: "exec",
          arguments: { target: "local", cwd: root, command: "git push origin main", mode: "foreground" },
        },
      ],
    },
  }));
  assert(authorityPreview.authorityActionCount === 3, "authority preview mutation count is incorrect");
  assert(authorityPreview.r0ActionCount === 1, "authority preview R0 count is incorrect");
  assert(
    JSON.stringify((authorityPreview.actions ?? []).map((action) => action.minimumRisk))
      === JSON.stringify(["R0", "R1", "R2", "R3"]),
    "authority preview risk classification is incorrect",
  );
  await assertPathMissing(previewOnlyPath);
  if (options.skipCompanyGates) {
    await assertPathMissing(previewR2Path);
  } else {
    const remotePreviewStat = await client.callTool({
      name: "fs",
      arguments: {
        operation: "stat",
        target: options.companyTarget,
        path: previewRemotePath,
      },
    });
    assert(
      errorCode(remotePreviewStat) === "PATH_NOT_FOUND",
      "authority preview unexpectedly created its remote fixture path",
    );
  }
  canaries.authorityPreview = {
    planFingerprint: authorityPreview.planFingerprint,
    risks: authorityPreview.actions.map((action) => action.minimumRisk),
    localDispatched: false,
    remoteDispatched: false,
    companyGateSkipped: options.skipCompanyGates,
  };

  const file = join(root, "plain.txt");
  const copy = join(root, "plain-copy.txt");
  await call(client, "fs", { operation: "write", path: file, content: "user-file\n", overwrite: false });
  const read = data(await call(client, "fs", { operation: "read", path: file }));
  assert(String(read.content ?? read.text ?? "").includes("user-file"), "local user filesystem round trip failed");
  await call(client, "fs", { operation: "copy", path: file, destination: copy, overwrite: false });
  await call(client, "fs", { operation: "remove", path: copy, disposition: "permanent" });
  canaries.localUserFilesystem = true;

  const exactAuthorityPath = join(root, "authority-exact.txt");
  const exactAuthorityArgs = {
    operation: "write",
    path: exactAuthorityPath,
    content: "authority-exact\n",
    overwrite: false,
  };
  const exactAuthority = await prepareExactAuthority(
    client,
    "fs",
    exactAuthorityArgs,
    "R1",
    "Verify exact local mutation authority and one-use consumption.",
  );
  const mismatchResult = await sameClientTransport.callTool({
    name: "fs",
    arguments: {
      ...exactAuthorityArgs,
      path: `${exactAuthorityPath}.mismatch`,
      authorityId: exactAuthority.authorityId,
    },
  });
  assert(
    errorCode(mismatchResult) === "AUTHORITY_ACTION_MISMATCH",
    "authority action mismatch was not rejected",
  );
  authorityAudit.mismatchRejected = true;
  const crossClientResult = await foreignClient.callTool({
    name: "fs",
    arguments: { ...exactAuthorityArgs, authorityId: exactAuthority.authorityId },
  });
  assert(
    errorCode(crossClientResult) === "AUTHORITY_PRINCIPAL_MISMATCH",
    "a different OAuth client reused another client's authority",
  );
  authorityAudit.crossClientRejected = true;
  const exactResult = await sameClientTransport.callTool({
    name: "fs",
    arguments: { ...exactAuthorityArgs, authorityId: exactAuthority.authorityId },
  });
  assert(exactResult.isError !== true && exactResult.structuredContent?.ok !== false, "exact authority action failed");
  authorityAudit.crossTransportAccepted = true;
  const consumedResult = await client.callTool({
    name: "fs",
    arguments: { ...exactAuthorityArgs, authorityId: exactAuthority.authorityId },
  });
  assert(errorCode(consumedResult) === "AUTHORITY_CONSUMED", "consumed authority was reusable");
  authorityAudit.consumedRejected = true;

  const correctedPath = join(root, "authority-corrected.txt");
  const correctedArgs = {
    operation: "write",
    path: correctedPath,
    content: "must-not-run\n",
    overwrite: false,
  };
  const correctedAuthority = await prepareExactAuthority(
    client,
    "fs",
    correctedArgs,
    "R1",
    "Prepare a canary that will be invalidated by a correction.",
  );
  await call(client, "context", {
    operation: "invalidate_authority",
    taskInstanceId: correctedAuthority.taskInstanceId,
    correctionText: "Do not execute the prepared corrected-file write.",
  });
  const correctedResult = await client.callTool({
    name: "fs",
    arguments: { ...correctedArgs, authorityId: correctedAuthority.authorityId },
  });
  assert(errorCode(correctedResult) === "AUTHORITY_STALE", "corrected authority was not invalidated");
  authorityAudit.correctionInvalidated = true;

  const staticElevation = await client.callTool({
    name: "exec",
    arguments: {
      target: "local",
      cwd: root,
      command: "sudo -n true",
      mode: "foreground",
    },
  });
  assert(errorCode(staticElevation) === "ELEVATION_BLOCKED", "static elevation command was not blocked");
  authorityAudit.staticElevationBlocked = true;

  const runtimeElevation = data(await call(client, "exec", {
    target: "local",
    cwd: root,
    command: "python3 -c 'import base64,os;p=base64.b64decode(\"L3Vzci9iaW4vc3Vkbw==\").decode();os.execv(p,[p,\"-n\",\"true\"])'",
    mode: "foreground",
    yieldMs: 30_000,
  }));
  assert(
    runtimeElevation.state === "EXITED"
      && Number(runtimeElevation.exitCode) !== 0
      && /not permitted|permission|denied/i.test(String(runtimeElevation.output ?? "")),
    "runtime OS boundary did not block an obfuscated elevation exec",
  );
  authorityAudit.runtimeElevationBlocked = true;

  await call(client, "fs", {
    operation: "remove",
    path: exactAuthorityPath,
    disposition: "permanent",
  });
  canaries.operationAuthority = authorityAudit;

  const externalRoot = data(await call(client, "fs", {
    operation: "stat",
    target: "local",
    path: options.externalStorageRoot,
  }));
  assert(externalRoot.type === "directory", `external storage is not a directory: ${options.externalStorageRoot}`);
  const externalPath = `${options.externalStorageRoot.replace(/\/+$/, "")}/.devspace-v2-${randomUUID()}.txt`;
  await call(client, "fs", {
    operation: "write",
    target: "local",
    path: externalPath,
    content: "external-storage\n",
    overwrite: false,
  });
  const externalHash = data(await call(client, "fs", {
    operation: "hash",
    target: "local",
    path: externalPath,
  }));
  assert(typeof externalHash.sha256 === "string", "external storage hash failed");
  await call(client, "fs", {
    operation: "remove",
    target: "local",
    path: externalPath,
    disposition: "permanent",
  });
  canaries.externalStorage = options.externalStorageRoot;

  const localExec = data(await call(client, "exec", {
    command: "printf 'user-exec-ok\\n'",
    cwd: root,
    mode: "foreground",
    yieldMs: 30_000,
  }));
  assert(localExec.state === "EXITED" && String(localExec.output).includes("user-exec-ok"), "local user exec failed");
  canaries.localUserExec = true;

  const background = data(await call(client, "exec", {
    command: "read value; printf 'input=%s\\n' \"$value\"",
    cwd: root,
    mode: "background",
    yieldMs: 0,
  }));
  assert(typeof background.processId === "string", "background process ID is missing");
  const backgroundWritten = data(await call(client, "process", {
    operation: "write",
    processId: background.processId,
    chars: "live-input\n",
    waitMs: 1_000,
  }));
  const backgroundDone = backgroundWritten.state === "EXITED"
    ? backgroundWritten
    : data(await call(client, "process", {
        operation: "wait",
        processId: background.processId,
        waitMs: 30_000,
      }));
  assert(backgroundDone.state === "EXITED" && String(backgroundDone.output).includes("input=live-input"), "background stdin lifecycle failed");

  const pty = data(await call(client, "exec", {
    command: "read value; stty size; printf 'pty=%s\\n' \"$value\"",
    cwd: root,
    tty: true,
    mode: "background",
    yieldMs: 0,
  }));
  assert(typeof pty.processId === "string", "PTY process ID is missing");
  await call(client, "process", {
    operation: "resize",
    processId: pty.processId,
    columns: 132,
    rows: 41,
  });
  const ptyWritten = data(await call(client, "process", {
    operation: "write",
    processId: pty.processId,
    chars: "live-pty\n",
    waitMs: 1_000,
  }));
  const ptyDone = ptyWritten.state === "EXITED"
    ? ptyWritten
    : data(await call(client, "process", {
        operation: "wait",
        processId: pty.processId,
        waitMs: 30_000,
      }));
  assert(ptyDone.state === "EXITED" && /41\s+132/.test(String(ptyDone.output)) && String(ptyDone.output).includes("pty=live-pty"), "PTY resize/input lifecycle failed");
  canaries.processLifecycle = { background: true, pty: true };

  if (options.skipCompanyGates) {
    canaries.company = {
      skipped: true,
      reason: "Explicit --skip-company-gates deployment option.",
    };
  } else {
  const companyProbe = data(await call(client, "target", {
    operation: "probe",
    targetId: options.companyTarget,
    refresh: true,
  }));
  assert(companyProbe.observation?.status === "ONLINE", "company Mac target is not online");
  assert(companyProbe.observation?.capabilities?.pty === true, "company Mac PTY probe is not verified");
  assert(companyProbe.observation?.capabilities?.sftp === true, "company Mac SFTP probe is not verified");
  assert(companyProbe.observation?.capabilities?.fs === true, "company Mac complete filesystem capability is unavailable");
  const companyTemporary = companyProbe.observation?.temporaryDirectory;
  assert(typeof companyTemporary === "string" && companyTemporary.startsWith("/"), "company Mac temporary directory is unavailable");
  const companyExec = data(await call(client, "exec", {
    target: options.companyTarget,
    command: "printf 'company-exec-ok\\n'",
    cwd: companyTemporary,
    mode: "foreground",
    yieldMs: 30_000,
  }));
  assert(companyExec.state === "EXITED" && String(companyExec.output).includes("company-exec-ok"), "company Mac user exec failed");
  const companyPty = data(await call(client, "exec", {
    target: options.companyTarget,
    command: "test -t 0 && test -t 1 && stty size && printf 'company-pty-ok\n'",
    tty: true,
    mode: "foreground",
    yieldMs: 30_000,
  }));
  assert(
    companyPty.state === "EXITED" && String(companyPty.output).includes("company-pty-ok"),
    "company Mac verified PTY execution failed",
  );
  const companyPath = `${companyTemporary.replace(/\/+$/, "")}/devspace-v2-${randomUUID()}.txt`;
  await call(client, "artifact", {
    operation: "copy",
    source: { target: "local", path: file },
    destination: { target: options.companyTarget, path: companyPath },
    overwrite: false,
  });
  const companyRead = data(await call(client, "fs", {
    operation: "read",
    target: options.companyTarget,
    path: companyPath,
  }));
  assert(String(companyRead.content ?? companyRead.text ?? "").includes("user-file"), "company Mac filesystem/artifact copy failed");
  const companyPublished = data(await call(client, "artifact", {
    operation: "publish",
    source: { target: options.companyTarget, path: companyPath, name: "company-artifact.txt", mimeType: "text/plain" },
    ttlSeconds: 60,
  }));
  const companyArtifactResponse = await fetchArtifact(companyPublished.resourceUri);
  assert(companyArtifactResponse.status === 200 && (await companyArtifactResponse.text()).includes("user-file"), "company Mac artifact publication failed");
  await call(client, "fs", {
    operation: "remove",
    target: options.companyTarget,
    path: companyPath,
    disposition: "permanent",
  });
  canaries.company = { exec: true, pty: true, sftp: true, filesystem: true, artifact: true };
  }

  if (options.windowsTarget) {
    const windowsProbe = data(await call(client, "target", {
      operation: "probe",
      targetId: options.windowsTarget,
      refresh: true,
    }));
    assert(windowsProbe.observation?.status === "ONLINE", "Windows target is not online");
    const windowsTemporary = windowsProbe.observation?.temporaryDirectory;
    assert(typeof windowsTemporary === "string" && windowsTemporary.length > 0, "Windows target temporary directory is unavailable");
    const windowsExec = data(await call(client, "exec", {
      target: options.windowsTarget,
      command: "Write-Output 'windows-exec-ok'",
      mode: "foreground",
      yieldMs: 30_000,
    }));
    assert(windowsExec.state === "EXITED" && String(windowsExec.output).includes("windows-exec-ok"), "Windows user exec failed");
    const windowsPath = `${windowsTemporary.replace(/[\\/]+$/, "")}\\devspace-v2-${randomUUID()}.txt`;
    await call(client, "fs", {
      operation: "write",
      target: options.windowsTarget,
      path: windowsPath,
      content: "windows-filesystem\n",
      overwrite: false,
    });
    const windowsRead = data(await call(client, "fs", {
      operation: "read",
      target: options.windowsTarget,
      path: windowsPath,
    }));
    assert(String(windowsRead.content ?? windowsRead.text ?? "").includes("windows-filesystem"), "Windows filesystem round trip failed");
    const windowsArtifactPath = `${windowsTemporary.replace(/[\\/]+$/, "")}\\devspace-v2-artifact-${randomUUID()}.txt`;
    await call(client, "artifact", {
      operation: "copy",
      source: { target: "local", path: file },
      destination: { target: options.windowsTarget, path: windowsArtifactPath },
      overwrite: false,
    });
    const windowsPublished = data(await call(client, "artifact", {
      operation: "publish",
      source: { target: options.windowsTarget, path: windowsArtifactPath, name: "windows-artifact.txt", mimeType: "text/plain" },
      ttlSeconds: 60,
    }));
    assert(typeof windowsPublished.resourceUri === "string", "Windows artifact publication URI is missing");
    const windowsArtifactResponse = await fetchArtifact(windowsPublished.resourceUri);
    assert(windowsArtifactResponse.status === 200 && (await windowsArtifactResponse.text()).includes("user-file"), "Windows artifact round trip failed");
    await call(client, "fs", {
      operation: "remove",
      target: options.windowsTarget,
      path: windowsArtifactPath,
      disposition: "permanent",
    });
    await call(client, "fs", {
      operation: "remove",
      target: options.windowsTarget,
      path: windowsPath,
      disposition: "permanent",
    });
    canaries.windows = { exec: true, filesystem: true, artifact: true };
  } else {
    canaries.windows = {
      skipped: true,
      required: false,
      reason: "No explicit Windows live target was supplied.",
    };
  }

  const repository = join(root, "repository");
  await mkdir(repository);
  execFileSync("git", ["init", "-q"], { cwd: repository });
  execFileSync("git", ["config", "user.name", "DevSpace Live Gate"], { cwd: repository });
  execFileSync("git", ["config", "user.email", "devspace-live@example.invalid"], { cwd: repository });
  await writeFile(join(repository, "README.md"), "baseline\n");
  execFileSync("git", ["add", "README.md"], { cwd: repository });
  execFileSync("git", ["commit", "-q", "-m", "baseline"], { cwd: repository });
  const opened = data(await call(client, "context", {
    operation: "open",
    target: "local",
    path: repository,
    mode: "worktree",
    task: "live verification",
  }));
  assert(opened.contextId && opened.mode === "worktree" && opened.managed === true, "managed worktree context failed");
  await call(client, "fs", {
    operation: "write",
    contextId: opened.contextId,
    path: "README.md",
    content: "baseline\nchanged\n",
    overwrite: true,
  });
  const diff = data(await call(client, "context", {
    operation: "diff",
    contextId: opened.contextId,
  }));
  assert(diff.resourceUri && diff.summary?.files >= 1, "context diff resource failed");
  const diffPage = await client.readResource({ uri: diff.resourceUri });
  assert(JSON.stringify(diffPage).includes("changed"), "context diff content failed");
  const reset = data(await call(client, "exec", {
    contextId: opened.contextId,
    command: "git reset --hard HEAD",
    mode: "foreground",
    yieldMs: 30_000,
  }));
  assert(reset.state === "EXITED" && reset.exitCode === 0, "managed worktree cleanup failed");
  const closed = data(await call(client, "context", { operation: "close", contextId: opened.contextId }));
  assert(closed.closed === true, "context close failed");
  assert(closed.worktree?.removed === true, "managed worktree was not removed after cleanup");
  canaries.contextWorktree = true;

  if (options.skipCompanyGates) {
    canaries.companyRoutes = {
      skipped: true,
      reason: "Explicit --skip-company-gates deployment option.",
    };
    canaries.remoteGui = {
      skipped: true,
      reason: "Explicit --skip-company-gates deployment option.",
    };
  } else {
  const routes = data(await call(client, "mcp", { operation: "routes" }));
  const routeIds = (routes.routes ?? []).map((route) => route.routeId);
  assert(routeIds.includes(options.chromeRoute), `Chrome MCP route is missing: ${options.chromeRoute}`);
  assert(routeIds.includes(options.jiraRoute), `Jira MCP route is missing: ${options.jiraRoute}`);
  assert(routeIds.includes(options.computerUseRoute), `Computer Use MCP route is missing: ${options.computerUseRoute}`);
  await call(client, "mcp", {
    operation: "search_tools",
    route: options.jiraRoute,
    query: "search issue",
    limit: 5,
  });
  const chromeReadiness = await callReadOnlyMcpWhenReady(client, {
    operation: "invoke",
    route: options.chromeRoute,
    name: "list_pages",
    arguments: {},
    responsePolicy: { maxCharacters: 12_000, preserveFullResult: true },
  });
  const chrome = data(chromeReadiness.result);
  assert(chrome.result, "Chrome DevTools MCP invocation failed");
  canaries.chromeReadiness = {
    route: options.chromeRoute,
    tool: "list_pages",
    attempts: chromeReadiness.attempts,
    readOnly: true,
  };
  const chromeMutation = data(await call(client, "mcp", {
    operation: "invoke",
    route: options.chromeRoute,
    name: "evaluate_script",
    arguments: {
      function: "() => { window.__devspaceV2Canary = 'ok'; const value = window.__devspaceV2Canary; delete window.__devspaceV2Canary; return value === 'ok'; }",
    },
    responsePolicy: { maxCharacters: 12_000, preserveFullResult: true },
  }));
  assert(/true|ok/i.test(JSON.stringify(chromeMutation.result)), "Chrome DevTools MCP mutation canary failed");
  const remoteGuiTools = data(await call(client, "mcp", {
    operation: "search_tools",
    route: options.computerUseRoute,
    query: "screenshot accessibility click keyboard",
    limit: 5,
  }));
  assert(Array.isArray(remoteGuiTools.tools) && remoteGuiTools.tools.length > 0, "remote generic GUI route exposes no tools");
  const remoteGuiDescription = data(await call(client, "mcp", {
    operation: "describe_tool",
    route: options.computerUseRoute,
    name: "get_app_state",
  }));
  assert(/get_app_state|screenshot|accessibility/i.test(JSON.stringify(remoteGuiDescription)), "remote generic GUI schema discovery failed");
  const remoteGuiCapabilities = data(await call(client, "gui", {
    operation: "capabilities",
    target: options.companyTarget,
  }));
  assert(
    remoteGuiCapabilities.targetId === options.companyTarget
      && remoteGuiCapabilities.configured === true
      && typeof remoteGuiCapabilities.available === "boolean",
    "remote generic GUI capability observation is incomplete",
  );
  canaries.mcpRoutes = routeIds;
  if (remoteGuiCapabilities.available === true) {
    const remoteGuiObservation = data(await call(client, "gui", {
      operation: "observe",
      target: options.companyTarget,
      maxElements: 100,
    }));
    assert(remoteGuiObservation.sessionId && remoteGuiObservation.generation, "remote generic GUI observation failed");
    const remoteGuiAction = data(await call(client, "gui", {
      operation: "act",
      target: options.companyTarget,
      sessionId: remoteGuiObservation.sessionId,
      generation: remoteGuiObservation.generation,
      action: { type: "key_code", keyCode: 53 },
    }));
    assert(remoteGuiAction.performed, "remote generic GUI action failed");
    canaries.remoteGui = {
      target: options.companyTarget,
      configured: true,
      available: true,
      observation: true,
      action: true,
    };
  } else {
    assert(
      typeof remoteGuiCapabilities.reason === "string" && remoteGuiCapabilities.reason.length > 0,
      "unavailable remote GUI capability has no truthful reason",
    );
    canaries.remoteGui = {
      target: options.companyTarget,
      configured: true,
      available: false,
      reason: remoteGuiCapabilities.reason,
      observation: false,
      action: false,
    };
  }
  }

  const artifactDestination = join(root, "artifact-copy.txt");
  const copied = data(await call(client, "artifact", {
    operation: "copy",
    source: { target: "local", path: file },
    destination: { target: "local", path: artifactDestination },
    overwrite: false,
  }));
  assert(copied, "artifact copy failed");
  const published = data(await call(client, "artifact", {
    operation: "publish",
    source: { target: "local", path: artifactDestination, name: "artifact-copy.txt", mimeType: "text/plain" },
    ttlSeconds: 60,
  }));
  assert(typeof published.resourceUri === "string", "artifact publish URI missing");
  const response = await fetchArtifact(published.resourceUri);
  assert(response.status === 200 && (await response.text()).includes("user-file"), "artifact HTTP publication failed");
  canaries.artifact = true;

  await prepareLocalGuiApplication();
  const gui = data(await call(client, "gui", { operation: "capabilities", target: "local" }));
  assert(
    gui.targetId === "local" && gui.configured === true && gui.available === true,
    "local generic GUI capability is not available in the production execution context",
  );
  let guiObservation = data(await call(client, "gui", {
    operation: "observe",
    target: "local",
    maxElements: 1,
  }));
  assert(guiObservation.sessionId && guiObservation.generation, "local generic GUI observation failed");
  let guiAction;
  for (let attempt = 0; attempt < 2; attempt += 1) {
    const result = await callWithAuthority(client, "gui", {
      operation: "act",
      target: "local",
      sessionId: guiObservation.sessionId,
      generation: guiObservation.generation,
      action: { type: "key_code", keyCode: 53 },
    });
    if (result.isError !== true && result.structuredContent?.ok !== false) {
      guiAction = data(result);
      break;
    }
    const code = result.structuredContent?.error?.code;
    if (code !== "GUI_STATE_CHANGED" || attempt > 0) {
      throw new Error(`gui failed: ${JSON.stringify(result.structuredContent ?? result.content).slice(0, 4_000)}`);
    }
    // A stale-generation rejection proves that no GUI action was dispatched.
    // Re-observe once, then issue the harmless Escape action against the new
    // generation. Never replay an action after an ambiguous dispatch.
    guiObservation = data(await call(client, "gui", {
      operation: "observe",
      target: "local",
      maxElements: 1,
    }));
  }
  assert(guiAction.performed, "local generic GUI action failed");
  canaries.gui = {
    configured: true,
    available: true,
    observation: true,
    action: true,
  };

  await call(client, "fs", { operation: "remove", path: artifactDestination, disposition: "permanent" });
  await call(client, "fs", { operation: "remove", path: file, disposition: "permanent" });
}

async function assertPathMissing(path) {
  const result = await clientlessLocalStat(path);
  assert(result === false, `authority preview unexpectedly created ${path}`);
}

async function clientlessLocalStat(path) {
  try {
    await readFile(path, "utf8");
    return true;
  } catch (error) {
    if (error && typeof error === "object" && error.code === "ENOENT") return false;
    throw error;
  }
}

async function prepareLocalGuiApplication() {
  const argumentsForOpen = ["-a", options.guiApplication];
  if (options.guiApplication === "Finder") {
    argumentsForOpen.push(process.env.HOME ?? "/");
  }
  execFileSync("open", argumentsForOpen, { timeout: 10_000, stdio: "ignore" });
  await new Promise((resolvePromise) => setTimeout(resolvePromise, 1_000));
}

async function connectClient(url, token, index) {
  const transport = new StreamableHTTPClientTransport(url, {
    requestInit: { headers: { Authorization: `Bearer ${token}` } },
  });
  const client = new Client({ name: `devspace-v2-live-${index + 1}`, version: "1.0.0" });
  await client.connect(transport);
  return { client, transport };
}

function fetchArtifact(resourceUri) {
  const value = new URL(resourceUri);
  if (options.artifactFetchBaseUrl) {
    const replacement = new URL(options.artifactFetchBaseUrl);
    const resource = new URL(options.tokenResource ?? mcpUrl.href);
    const resourcePrefix = resource.pathname.slice(0, resource.pathname.lastIndexOf("/")) || "/";
    if (
      resourcePrefix !== "/"
      && (value.pathname === resourcePrefix || value.pathname.startsWith(`${resourcePrefix}/`))
    ) {
      value.pathname = value.pathname.slice(resourcePrefix.length) || "/";
    }
    value.protocol = replacement.protocol;
    value.username = replacement.username;
    value.password = replacement.password;
    value.host = replacement.host;
    const replacementPrefix = replacement.pathname.replace(/\/+$/u, "");
    if (replacementPrefix) value.pathname = `${replacementPrefix}${value.pathname}`;
  }
  return fetch(value);
}

async function callReadOnlyMcpWhenReady(
  client,
  args,
  { maximumAttempts = 12, delayMs = 500 } = {},
) {
  assert(args?.operation === "invoke", "read-only MCP readiness helper requires invoke");
  assert(typeof args.route === "string" && args.route.length > 0, "read-only MCP readiness helper requires route");
  assert(typeof args.name === "string" && args.name.length > 0, "read-only MCP readiness helper requires tool name");
  let lastResult;
  for (let attempt = 1; attempt <= maximumAttempts; attempt += 1) {
    const described = data(await call(client, "mcp", {
      operation: "describe_tool",
      route: args.route,
      name: args.name,
    }));
    const tool = described.result?.value?.tool ?? described.result?.tool ?? described.tool;
    assert(tool?.name === args.name, `MCP descriptor mismatch for ${args.route}.${args.name}`);
    assert(tool.annotations?.readOnlyHint === true, `${args.route}.${args.name} is not explicitly read-only`);
    assert(tool.annotations?.destructiveHint !== true, `${args.route}.${args.name} is marked destructive`);

    const result = await client.callTool({ name: "mcp", arguments: args });
    if (result.isError !== true && result.structuredContent?.ok !== false) {
      return { result, attempts: attempt };
    }
    lastResult = result;
    const code = errorCode(result);
    assert(code !== "AUTHORITY_REQUIRED", `${args.route}.${args.name} unexpectedly requires mutation authority`);
    if (!new Set(["MCP_PROVIDER_ERROR", "MCP_TRANSPORT_ERROR"]).has(code) || attempt === maximumAttempts) {
      break;
    }
    await new Promise((resolvePromise) => setTimeout(resolvePromise, delayMs));
  }
  throw new Error(
    `read-only MCP readiness failed: ${JSON.stringify(lastResult?.structuredContent ?? lastResult?.content).slice(0, 4_000)}`,
  );
}

async function call(client, name, args) {
  const result = await callWithAuthority(client, name, args);
  if (result.isError === true || result.structuredContent?.ok === false) {
    throw new Error(`${name} failed: ${JSON.stringify(result.structuredContent ?? result.content).slice(0, 4_000)}`);
  }
  return result;
}

async function callWithAuthority(client, name, args) {
  let result = await client.callTool({ name, arguments: args });
  if (errorCode(result) !== "AUTHORITY_REQUIRED") return result;
  const requiredRisk = result.structuredContent?.error?.evidence?.requiredRisk;
  assert(["R1", "R2", "R3"].includes(requiredRisk), `invalid required authority risk: ${requiredRisk}`);
  const authority = await prepareExactAuthority(
    client,
    name,
    args,
    requiredRisk,
    `Live verification authorizes this exact ${name} canary action.`,
  );
  result = await client.callTool({
    name,
    arguments: { ...args, authorityId: authority.authorityId },
  });
  return result;
}

async function prepareExactAuthority(client, tool, args, risk, authorityText) {
  const prepared = await client.callTool({
    name: "context",
    arguments: {
      operation: "authorize",
      taskId: `live-${tool}-${randomUUID()}`,
      authorityText,
      actions: [{ tool, arguments: args, risk }],
    },
  });
  if (prepared.isError === true || prepared.structuredContent?.ok === false) {
    throw new Error(`context.authorize failed: ${JSON.stringify(prepared.structuredContent ?? prepared.content).slice(0, 4_000)}`);
  }
  const preparedData = data(prepared);
  const authorityId = preparedData.authorityId;
  const taskInstanceId = preparedData.taskInstanceId;
  assert(typeof authorityId === "string", "context.authorize returned no authorityId");
  assert(typeof taskInstanceId === "string", "context.authorize returned no taskInstanceId");
  authorityAudit.prepared += 1;
  authorityAudit.byRisk[risk] += 1;
  return { authorityId, taskInstanceId };
}

function errorCode(result) {
  return result.structuredContent?.error?.code;
}

function data(result) {
  const value = result.structuredContent?.data;
  assert(value && typeof value === "object", `missing structured data: ${JSON.stringify(result).slice(0, 1_000)}`);
  return value;
}

async function discoverTokenResource(mcpUrl, configuredResource) {
  if (configuredResource) return new URL(configuredResource).href;
  const unauthorized = await fetch(mcpUrl);
  assert(unauthorized.status === 401, `unauthenticated MCP discovery status is ${unauthorized.status}`);
  const challenge = unauthorized.headers.get("www-authenticate") ?? "";
  const metadataMatch = /\bresource_metadata="([^"]+)"/u.exec(challenge);
  assert(metadataMatch, "MCP authentication challenge has no resource_metadata URL");
  const advertisedMetadataUrl = new URL(metadataMatch[1]);
  const localMetadataUrl = new URL(
    `${advertisedMetadataUrl.pathname}${advertisedMetadataUrl.search}`,
    mcpUrl.origin,
  );
  const response = await fetch(localMetadataUrl);
  assert(response.status === 200, `OAuth protected-resource metadata status is ${response.status}`);
  const metadata = await response.json();
  assert(typeof metadata?.resource === "string", "OAuth protected-resource metadata has no resource URL");
  return new URL(metadata.resource).href;
}

function createTemporaryAccessToken(databasePath, resource) {
  const db = new Database(databasePath, { fileMustExist: true });
  const token = `dsv2_${randomBytes(36).toString("base64url")}`;
  const tokenHash = createHash("sha256").update(token).digest("base64url");
  const clientId = `devspace-v2-live-${randomUUID()}`;
  const issuedAt = Math.floor(Date.now() / 1_000);
  const clientJson = {
    client_id: clientId,
    client_id_issued_at: issuedAt,
    client_name: "DevSpace Universal Broker v2 live gate",
    redirect_uris: ["http://127.0.0.1/callback"],
    token_endpoint_auth_method: "none",
    grant_types: ["authorization_code", "refresh_token"],
    response_types: ["code"],
  };
  try {
    db.transaction(() => {
      db.prepare("INSERT INTO oauth_clients (client_id, client_json, issued_at) VALUES (?, ?, ?)")
        .run(clientId, JSON.stringify(clientJson), issuedAt);
      db.prepare("INSERT INTO oauth_access_tokens (token_hash, client_id, scopes_json, expires_at, resource) VALUES (?, ?, ?, ?, ?)")
        .run(tokenHash, clientId, JSON.stringify(userScopes), issuedAt + 3_600, resource);
    })();
  } finally {
    db.close();
  }
  return {
    token,
    cleanup() {
      const cleanupDb = new Database(databasePath, { fileMustExist: true });
      try {
        cleanupDb.transaction(() => {
          cleanupDb.prepare("DELETE FROM oauth_access_tokens WHERE token_hash = ?").run(tokenHash);
          cleanupDb.prepare("DELETE FROM oauth_refresh_tokens WHERE client_id = ?").run(clientId);
          cleanupDb.prepare("DELETE FROM oauth_clients WHERE client_id = ?").run(clientId);
        })();
      } finally {
        cleanupDb.close();
      }
    },
  };
}

function safeErrorSummary(error) {
  const name = error instanceof Error && error.name
    ? error.name.slice(0, 128)
    : "Error";
  const source = error instanceof Error ? error.message : String(error);
  const message = source
    .replace(/\bBearer\s+[A-Za-z0-9._~+/=-]+/giu, "Bearer [REDACTED]")
    .replace(/\bdsv2_[A-Za-z0-9_-]+\b/gu, "dsv2_[REDACTED]")
    .slice(0, 4_000);
  return {
    name,
    message: message || "Unknown error",
  };
}

function parseArgs(args) {
  const result = {
    baseUrl: "http://127.0.0.1:7677",
    mcpUrl: undefined,
    healthUrl: undefined,
    mcpPath: "/mcp-next",
    healthPath: "/healthz-next",
    artifactFetchBaseUrl: undefined,
    tokenResource: undefined,
    databasePath: `${process.env.HOME}/.local/share/devspace/universal-broker-v2/devspace.sqlite`,
    sessions: 5,
    output: undefined,
    skipCompanyGates: false,
    companyTarget: "company",
    chromeRoute: "company-chrome",
    jiraRoute: "company-jira",
    computerUseRoute: "company-computer-use",
    guiApplication: "Finder",
    windowsTarget: undefined,
    externalStorageRoot: "/Volumes/Untitled",
  };
  for (let index = 0; index < args.length; index += 1) {
    const argument = args[index];
    const value = args[index + 1];
    if (argument === "--base-url") result.baseUrl = requiredValue(argument, value), index += 1;
    else if (argument === "--mcp-url") result.mcpUrl = requiredValue(argument, value), index += 1;
    else if (argument === "--health-url") result.healthUrl = requiredValue(argument, value), index += 1;
    else if (argument === "--mcp-path") result.mcpPath = requiredValue(argument, value), index += 1;
    else if (argument === "--health-path") result.healthPath = requiredValue(argument, value), index += 1;
    else if (argument === "--artifact-fetch-base-url") result.artifactFetchBaseUrl = requiredValue(argument, value), index += 1;
    else if (argument === "--token-resource") result.tokenResource = requiredValue(argument, value), index += 1;
    else if (argument === "--database") result.databasePath = requiredValue(argument, value), index += 1;
    else if (argument === "--sessions") result.sessions = Number(requiredValue(argument, value)), index += 1;
    else if (argument === "--output") result.output = requiredValue(argument, value), index += 1;
    else if (argument === "--skip-company-gates") result.skipCompanyGates = true;
    else if (argument === "--company-target") result.companyTarget = requiredValue(argument, value), index += 1;
    else if (argument === "--chrome-route") result.chromeRoute = requiredValue(argument, value), index += 1;
    else if (argument === "--jira-route") result.jiraRoute = requiredValue(argument, value), index += 1;
    else if (argument === "--computer-use-route") result.computerUseRoute = requiredValue(argument, value), index += 1;
    else if (argument === "--gui-application") result.guiApplication = requiredValue(argument, value), index += 1;
    else if (argument === "--windows-target") result.windowsTarget = requiredValue(argument, value), index += 1;
    else if (argument === "--external-storage-root") result.externalStorageRoot = requiredValue(argument, value), index += 1;
    else throw new Error(`Unknown option: ${argument}`);
  }
  assert(Number.isInteger(result.sessions) && result.sessions >= 2 && result.sessions <= 20, "sessions must be 2..20");
  return result;
}

function requiredValue(name, value) {
  if (!value) throw new Error(`${name} requires a value`);
  return value;
}

function assert(condition, message) {
  if (!condition) throw new Error(message);
}
