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

const options = parseArgs(process.argv.slice(2));
const baseUrl = new URL(options.baseUrl);
const mcpUrl = options.mcpUrl
  ? new URL(options.mcpUrl)
  : new URL(options.mcpPath, baseUrl);
const healthUrl = options.healthUrl
  ? new URL(options.healthUrl)
  : new URL(options.healthPath, baseUrl);
const audit = {
  baseUrl: baseUrl.href,
  mcpUrl: mcpUrl.href,
  healthUrl: healthUrl.href,
  health: undefined,
  protocolSessions: [],
  canaries: {},
};

const health = await fetch(healthUrl);
assert(health.status === 200, `health status is ${health.status}`);
audit.health = await health.json();
assert(audit.health?.ok === true, "health payload is not ok");

const credential = createTemporaryAccessToken(
  options.databasePath,
  options.templateDatabasePath,
  options.tokenResource ?? mcpUrl.href,
);
const root = await mkdtemp(join(tmpdir(), "devspace-v2-live-"));
let primary;
try {
  for (let index = 0; index < options.sessions; index += 1) {
    const session = await connectClient(mcpUrl, credential.token, index);
    try {
      const listed = await session.client.listTools();
      const names = listed.tools.map((tool) => tool.name);
      assert(JSON.stringify(names) === JSON.stringify(expectedTools), `tool surface mismatch: ${names.join(",")}`);
      audit.protocolSessions.push({ index: index + 1, tools: names, sessionId: session.transport.sessionId });
      if (index === 0) primary = session;
    } finally {
      if (index !== 0) await session.client.close();
    }
  }
  assert(primary, "primary MCP session was not created");
  await runCanaries(primary.client, root, audit.canaries);
  await primary.client.close();
  primary = undefined;
} finally {
  if (primary) await primary.client.close().catch(() => undefined);
  credential.cleanup();
  await rm(root, { recursive: true, force: true });
}

const serialized = JSON.stringify(audit, null, 2);
if (options.output) await writeFile(options.output, `${serialized}\n`, { mode: 0o600 });
console.log(serialized);

async function runCanaries(client, root, canaries) {
  const targets = data(await call(client, "target", { operation: "list", limit: 100 }));
  const targetIds = (targets.targets ?? []).map((target) => target.targetId);
  assert(targetIds.includes("local"), "local target is missing");
  assert(targetIds.includes(options.windowsTarget), `Windows target is missing: ${options.windowsTarget}`);
  assert(targetIds.includes(options.companyTarget), `company target is missing: ${options.companyTarget}`);
  canaries.targets = targetIds;

  const file = join(root, "plain.txt");
  const copy = join(root, "plain-copy.txt");
  await call(client, "fs", { operation: "write", path: file, content: "user-file\n", overwrite: false });
  const read = data(await call(client, "fs", { operation: "read", path: file }));
  assert(String(read.content ?? read.text ?? "").includes("user-file"), "local user filesystem round trip failed");
  await call(client, "fs", { operation: "copy", path: file, destination: copy, overwrite: false });
  await call(client, "fs", { operation: "remove", path: copy, disposition: "permanent" });
  canaries.localUserFilesystem = true;

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

  const companyProbe = data(await call(client, "target", {
    operation: "probe",
    targetId: options.companyTarget,
  }));
  assert(companyProbe.observation?.status === "ONLINE", "company Mac target is not online");
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
  canaries.company = { exec: true, filesystem: true, artifact: true };

  const windowsProbe = data(await call(client, "target", {
    operation: "probe",
    targetId: options.windowsTarget,
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
  const chrome = data(await call(client, "mcp", {
    operation: "invoke",
    route: options.chromeRoute,
    name: "list_pages",
    arguments: {},
    responsePolicy: { maxCharacters: 12_000, preserveFullResult: true },
  }));
  assert(chrome.result, "Chrome DevTools MCP invocation failed");
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

  const gui = data(await call(client, "gui", { operation: "capabilities", target: "local" }));
  assert(
    gui.targetId === "local" && gui.configured === true && gui.available === true,
    "local generic GUI capability is not available in the production execution context",
  );
  const guiObservation = data(await call(client, "gui", {
    operation: "observe",
    target: "local",
    maxElements: 100,
  }));
  assert(guiObservation.sessionId && guiObservation.generation, "local generic GUI observation failed");
  const guiAction = data(await call(client, "gui", {
    operation: "act",
    target: "local",
    sessionId: guiObservation.sessionId,
    generation: guiObservation.generation,
    action: { type: "key_code", keyCode: 53 },
  }));
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

async function call(client, name, args) {
  const result = await client.callTool({ name, arguments: args });
  if (result.isError === true || result.structuredContent?.ok === false) {
    throw new Error(`${name} failed: ${JSON.stringify(result.structuredContent ?? result.content).slice(0, 4_000)}`);
  }
  return result;
}

function data(result) {
  const value = result.structuredContent?.data;
  assert(value && typeof value === "object", `missing structured data: ${JSON.stringify(result).slice(0, 1_000)}`);
  return value;
}

function createTemporaryAccessToken(databasePath, templateDatabasePath, resource) {
  const templateDb = new Database(templateDatabasePath, { readonly: true });
  const sourceToken = templateDb.prepare("SELECT client_id, expires_at, resource FROM oauth_access_tokens LIMIT 1").get();
  const sourceClient = templateDb.prepare("SELECT client_json, issued_at FROM oauth_clients LIMIT 1").get();
  templateDb.close();
  assert(sourceToken && sourceClient, "production OAuth database has no reusable client/token template");
  const db = new Database(databasePath);
  const token = `dsv2_${randomBytes(36).toString("base64url")}`;
  const tokenHash = createHash("sha256").update(token).digest("base64url");
  const clientId = `devspace-v2-live-${randomUUID()}`;
  const clientJson = JSON.parse(sourceClient.client_json);
  clientJson.client_id = clientId;
  clientJson.client_name = "DevSpace Universal Broker v2 live gate";
  db.prepare("INSERT INTO oauth_clients (client_id, client_json, issued_at) VALUES (?, ?, ?)")
    .run(clientId, JSON.stringify(clientJson), sourceClient.issued_at);
  db.prepare("INSERT INTO oauth_access_tokens (token_hash, client_id, scopes_json, expires_at, resource) VALUES (?, ?, ?, ?, ?)")
    .run(
      tokenHash,
      clientId,
      JSON.stringify(["devspace", "devspace.read", "devspace.write", "devspace.exec", "devspace.mcp", "devspace.artifact", "devspace.gui"]),
      Math.max(Number(sourceToken.expires_at) || 0, Math.floor(Date.now() / 1_000) + 3_600),
      resource,
    );
  db.close();
  return {
    token,
    cleanup() {
      const cleanupDb = new Database(databasePath);
      cleanupDb.prepare("DELETE FROM oauth_access_tokens WHERE token_hash = ?").run(tokenHash);
      cleanupDb.prepare("DELETE FROM oauth_refresh_tokens WHERE client_id = ?").run(clientId);
      cleanupDb.prepare("DELETE FROM oauth_clients WHERE client_id = ?").run(clientId);
      cleanupDb.close();
    },
  };
}

function parseArgs(args) {
  const result = {
    baseUrl: "http://127.0.0.1:7676",
    mcpUrl: undefined,
    healthUrl: undefined,
    mcpPath: "/mcp",
    healthPath: "/healthz",
    artifactFetchBaseUrl: undefined,
    tokenResource: undefined,
    databasePath: `${process.env.HOME}/.local/share/devspace/devspace.sqlite`,
    templateDatabasePath: `${process.env.HOME}/.local/share/devspace/devspace.sqlite`,
    sessions: 5,
    output: undefined,
    companyTarget: "company",
    chromeRoute: "company-chrome",
    jiraRoute: "company-jira",
    computerUseRoute: "company-computer-use",
    guiApplication: "Finder",
    windowsTarget: "windows",
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
    else if (argument === "--template-database") result.templateDatabasePath = requiredValue(argument, value), index += 1;
    else if (argument === "--sessions") result.sessions = Number(requiredValue(argument, value)), index += 1;
    else if (argument === "--output") result.output = requiredValue(argument, value), index += 1;
    else if (argument === "--company-target") result.companyTarget = requiredValue(argument, value), index += 1;
    else if (argument === "--chrome-route") result.chromeRoute = requiredValue(argument, value), index += 1;
    else if (argument === "--jira-route") result.jiraRoute = requiredValue(argument, value), index += 1;
    else if (argument === "--computer-use-route") result.computerUseRoute = requiredValue(argument, value), index += 1;
    else if (argument === "--gui-application") result.guiApplication = requiredValue(argument, value), index += 1;
    else if (argument === "--windows-target") result.windowsTarget = requiredValue(argument, value), index += 1;
    else if (argument === "--external-storage-root") result.externalStorageRoot = requiredValue(argument, value), index += 1;
    else throw new Error(`Unknown option: ${argument}`);
  }
  assert(Number.isInteger(result.sessions) && result.sessions >= 1 && result.sessions <= 20, "sessions must be 1..20");
  return result;
}

function requiredValue(name, value) {
  if (!value) throw new Error(`${name} requires a value`);
  return value;
}

function assert(condition, message) {
  if (!condition) throw new Error(message);
}
