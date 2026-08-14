import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { access, mkdtemp, mkdir, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test, { type TestContext } from "node:test";
import { promisify } from "node:util";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { loadConfig, type ServerConfig } from "./config.js";
import { createReviewCheckpointManager } from "./review-checkpoints.js";
import { ProcessSessionManager } from "./process-sessions.js";
import { ConversationBootstrapRegistry, createMcpServer } from "./server.js";
import { SqliteWorkspaceStore } from "./workspace-store.js";
import { WorkspaceRegistry } from "./workspaces.js";
import { createShortcutRuntime } from "./shortcuts/runtime.js";

const execFileAsync = promisify(execFile);

test("codex changes mode limits widgets to workspace and aggregate review", async (t) => {
  const context = await fixture(t, { toolMode: "codex", widgets: "changes" });
  const tools = await context.client.listTools();
  const byName = new Map(tools.tools.map((tool) => [tool.name, tool]));

  assert.deepEqual(
    [...byName.keys()].sort(),
    ["apply_patch", "exec_command", "local_shell", "open_workspace", "read", "show_changes", "write_stdin"],
  );
  for (const name of ["read", "apply_patch", "exec_command", "local_shell", "write_stdin"]) {
    const meta = (byName.get(name)?._meta as Record<string, unknown> | undefined) ?? {};
    assert.equal("ui" in meta, false, name);
    assert.equal("ui/resourceUri" in meta, false, name);
  }
  for (const name of ["open_workspace", "show_changes"]) {
    const meta = (byName.get(name)?._meta as Record<string, unknown> | undefined) ?? {};
    assert.equal("ui" in meta, true, name);
  }
  const execSchema = byName.get("exec_command")?.inputSchema as {
    properties?: Record<string, unknown>;
  } | undefined;
  assert.equal("background" in (execSchema?.properties ?? {}), true);
  const localShellSchema = byName.get("local_shell")?.inputSchema as {
    properties?: Record<string, unknown>;
  } | undefined;
  assert.deepEqual(Object.keys(localShellSchema?.properties ?? {}).sort(), [
    "command",
    "timeout",
    "workingDirectory",
  ]);
  assert.equal("workspaceId" in (localShellSchema?.properties ?? {}), false);
});

test("local_shell performs create, read, and delete without a workspace", async (t) => {
  const context = await fixture(t, { toolMode: "codex", widgets: "off" });
  const node = JSON.stringify(process.execPath);
  const canary = "local-shell-canary.txt";

  const created = await context.client.callTool({
    name: "local_shell",
    arguments: {
      command: `${node} -e "require('node:fs').writeFileSync('${canary}', 'local-shell-ok')"`,
      workingDirectory: context.project,
    },
  });
  assert.equal(created.isError, undefined);

  const read = await context.client.callTool({
    name: "local_shell",
    arguments: {
      command: `${node} -e "process.stdout.write(require('node:fs').readFileSync('${canary}', 'utf8'))"`,
      workingDirectory: context.project,
    },
  });
  assert.match(String(structuredContent(read).result), /local-shell-ok/);

  const deleted = await context.client.callTool({
    name: "local_shell",
    arguments: {
      command: `${node} -e "require('node:fs').unlinkSync('${canary}')"`,
      workingDirectory: context.project,
    },
  });
  assert.equal(deleted.isError, undefined);
  await assert.rejects(access(join(context.project, canary)));
});

test("background exec returns a process session without waiting for command completion", async (t) => {
  const context = await fixture(t, { toolMode: "codex", widgets: "off" });
  const opened = await callOpen(context.client, context.project, "chat-background");
  const workspaceId = structuredContent(opened).workspaceId;
  assert.equal(typeof workspaceId, "string");
  const node = JSON.stringify(process.execPath);

  const started = await context.client.callTool({
    name: "exec_command",
    arguments: {
      workspaceId,
      cmd: `${node} -e "setTimeout(() => console.log('background-finished'), 300)"`,
      background: true,
    },
  });
  const startedContent = structuredContent(started);
  assert.equal(startedContent.running, true);
  assert.equal(typeof startedContent.sessionId, "number");

  const completed = await context.client.callTool({
    name: "write_stdin",
    arguments: {
      workspaceId,
      sessionId: startedContent.sessionId,
      yieldTimeMs: 2_000,
    },
  });
  const completedContent = structuredContent(completed);
  assert.equal(completedContent.running, false);
  assert.match(String(completedContent.result), /background-finished/);

  const markerStarted = await context.client.callTool({
    name: "exec_command",
    arguments: {
      workspaceId,
      cmd: `@background ${node} -e "setTimeout(() => console.log('marker-finished'), 300)"`,
    },
  });
  const markerStartedContent = structuredContent(markerStarted);
  assert.equal(markerStartedContent.running, true);
  assert.equal(typeof markerStartedContent.sessionId, "number");

  const markerCompleted = await context.client.callTool({
    name: "write_stdin",
    arguments: {
      workspaceId,
      sessionId: markerStartedContent.sessionId,
      yieldTimeMs: 2_000,
    },
  });
  assert.equal(structuredContent(markerCompleted).running, false);
  assert.match(String(structuredContent(markerCompleted).result), /marker-finished/);
});

test("personal shortcuts use distinct names and no widget metadata", async (t) => {
  const context = await fixture(t, { shortcuts: true, toolMode: "codex", widgets: "changes" });
  const tools = await context.client.listTools();
  const byName = new Map(tools.tools.map((tool) => [tool.name, tool]));
  for (const name of [
    "browser_read_shortcut",
    "remote_mcp_read_shortcut",
    "jira_lookup_shortcut",
  ]) {
    assert.equal(byName.has(name), true, name);
    const meta = (byName.get(name)?._meta as Record<string, unknown> | undefined) ?? {};
    assert.equal("ui" in meta, false, name);
    assert.equal("ui/resourceUri" in meta, false, name);
  }
  for (const oldName of ["browser_inspect", "remote_mcp_read", "jira_lookup"]) {
    assert.equal(byName.has(oldName), false, oldName);
  }
  const browser = byName.get("browser_read_shortcut");
  const schema = browser?.inputSchema as { properties?: Record<string, unknown> } | undefined;
  assert.deepEqual(Object.keys(schema?.properties ?? {}).sort(), [
    "matchText",
    "maxCharacters",
    "operation",
    "selector",
    "tabIndex",
    "url",
    "waitMs",
    "windowIndex",
  ]);
  for (const forbidden of ["javascript", "script", "click", "fill", "type", "submit"]) {
    assert.equal(forbidden in (schema?.properties ?? {}), false, forbidden);
  }
});

test("generic remote MCP description does not recommend a disabled Jira shortcut", async (t) => {
  const context = await fixture(t, {
    shortcuts: "remote-only",
    toolMode: "codex",
    widgets: "changes",
  });
  const tools = await context.client.listTools();
  const remote = tools.tools.find((tool) => tool.name === "remote_mcp_read_shortcut");
  assert.ok(remote);
  assert.equal(tools.tools.some((tool) => tool.name === "jira_lookup_shortcut"), false);
  assert.doesNotMatch(remote.description ?? "", /jira_lookup_shortcut/);
});

test("open_workspace keeps lifecycle flags out of model output and preserves complete card metadata", async (t) => {
  const context = await fixture(t);
  const first = await callOpen(context.client, context.project, "chat-1");
  const repeated = await callOpen(context.client, context.project, "chat-1");

  const tools = await context.client.listTools();
  const openTool = tools.tools.find((tool) => tool.name === "open_workspace");
  const outputProperties = (openTool?.outputSchema as { properties?: Record<string, unknown> } | undefined)?.properties;
  assert.equal(outputProperties && "workspaceReused" in outputProperties, false);
  assert.equal(outputProperties && "includeBootstrapContext" in outputProperties, false);

  const firstStructured = structuredContent(first);
  assert.equal(firstStructured.workspaceId, structuredContent(repeated).workspaceId);
  assert.ok(Array.isArray(firstStructured.agentsFiles));
  assert.ok(Array.isArray(firstStructured.availableAgentsFiles));
  assert.ok(Array.isArray(firstStructured.skills));
  assert.ok(Array.isArray(firstStructured.agentProviders));
  assert.ok(Array.isArray(firstStructured.agents));
  assert.ok(Array.isArray(firstStructured.skillDiagnostics));
  assert.equal("workspaceReused" in firstStructured, false);
  assert.equal("includeBootstrapContext" in firstStructured, false);

  const repeatedStructured = structuredContent(repeated);
  assert.equal(repeatedStructured.agentsFiles, undefined);
  assert.equal(repeatedStructured.availableAgentsFiles, undefined);
  assert.equal(repeatedStructured.skills, undefined);
  assert.equal(repeatedStructured.agentProviders, undefined);
  assert.equal(repeatedStructured.agents, undefined);
  assert.equal(repeatedStructured.skillDiagnostics, undefined);
  assert.equal("workspaceReused" in repeatedStructured, false);
  assert.equal("includeBootstrapContext" in repeatedStructured, false);

  const repeatedText = responseText(repeated);
  assert.match(repeatedText, /Workspace already open as/);
  assert.match(repeatedText, /same checkout previously opened/);
  assert.match(repeatedText, /Reuse this workspaceId for subsequent tool calls/);
  assert.match(repeatedText, /previously provided for this workspace/);
  assert.match(repeatedText, /not repeated here/);

  const card = responseCard(repeated);
  assert.equal(card.workspaceReused, true);
  assert.equal(card.includeBootstrapContext, false);
  assert.ok(Array.isArray(card.agentsFiles));
  assert.ok(Array.isArray(card.availableAgentsFiles));
  assert.ok(Array.isArray(card.skills));
  assert.ok(Array.isArray(card.agentProviders));
  assert.ok(Array.isArray(card.agents));
});

test("concurrent checkout opens return one full context and one reuse instruction", async (t) => {
  const context = await fixture(t);
  const [first, second] = await Promise.all([
    callOpen(context.client, context.project, "chat-1"),
    callOpen(context.client, context.project, "chat-1"),
  ]);

  assert.equal(structuredContent(first).workspaceId, structuredContent(second).workspaceId);
  assert.equal(
    [first, second].filter((result) => Array.isArray(structuredContent(result).agentsFiles)).length,
    1,
  );
  assert.equal(
    [first, second].filter((result) => responseText(result).includes("Workspace already open as")).length,
    1,
  );
});

test("different workspaces in one conversation emit shared bootstrap context only once", async (t) => {
  const context = await fixture(t);
  const root = join(context.project, "..");
  const otherProject = join(root, "other-project");
  await mkdir(join(otherProject, ".agents", "skills", "other-project-skill"), {
    recursive: true,
  });
  await writeFile(join(otherProject, "AGENTS.md"), "other project instructions\n");
  await writeFile(
    join(otherProject, ".agents", "skills", "other-project-skill", "SKILL.md"),
    [
      "---",
      "name: other-project-skill",
      "description: Other project skill.",
      "---",
      "",
      "# Other Project Skill",
    ].join("\n"),
  );

  const secondClient = await connectAdditionalClient(t, context);
  const first = await callOpen(context.client, context.project, "chat-1");
  const second = await callOpen(secondClient, otherProject, "chat-1");

  const firstSkillNames = skillNames(first);
  assert.equal(firstSkillNames.includes("global-skill"), true);
  assert.equal(firstSkillNames.includes("project-skill"), true);

  const secondSkillNames = skillNames(second);
  assert.equal(secondSkillNames.includes("other-project-skill"), true);
  assert.equal(secondSkillNames.includes("global-skill"), false);
  const secondInstructionContents = agentsFileContents(second);
  assert.equal(secondInstructionContents.includes("other project instructions\n"), true);
  assert.equal(secondInstructionContents.includes("global instructions\n"), false);
  assert.match(responseText(second), /already advertised earlier in this conversation are omitted/i);

  const independentConversation = await callOpen(context.client, otherProject, "chat-2");
  assert.equal(skillNames(independentConversation).includes("global-skill"), true);
  assert.equal(agentsFileContents(independentConversation).includes("global instructions\n"), true);
});

test("new worktrees always receive a fresh workspace and complete worktree context", async (t) => {
  const context = await fixture(t, { git: true });
  const checkout = await callOpen(context.client, context.project, "chat-1");
  const firstWorktree = await callOpen(context.client, context.project, "chat-1", "worktree");
  const secondWorktree = await callOpen(context.client, context.project, "chat-1", "worktree");
  const checkoutAgain = await callOpen(context.client, context.project, "chat-1");

  assert.notEqual(structuredContent(firstWorktree).workspaceId, structuredContent(secondWorktree).workspaceId);
  assert.equal(structuredContent(checkoutAgain).workspaceId, structuredContent(checkout).workspaceId);
  for (const result of [firstWorktree, secondWorktree]) {
    const structured = structuredContent(result);
    assert.equal(structured.mode, "worktree");
    assert.ok(Array.isArray(structured.agentsFiles));
    assert.ok(Array.isArray(structured.availableAgentsFiles));
    assert.ok(Array.isArray(structured.skills));
    assert.ok(Array.isArray(structured.agentProviders));
    assert.ok(Array.isArray(structured.agents));
    assert.ok(Array.isArray(structured.skillDiagnostics));
    assert.match(responseText(result), /Opened isolated worktree workspace/);
  }
  assert.equal(structuredContent(checkoutAgain).agentsFiles, undefined);
  assert.match(responseText(checkoutAgain), /same checkout previously opened/);
});

test("checkout opened after a worktree receives its own complete context", async (t) => {
  const context = await fixture(t, { git: true });
  const worktree = await callOpen(context.client, context.project, "chat-1", "worktree");
  const checkout = await callOpen(context.client, context.project, "chat-1");
  const checkoutAgain = await callOpen(context.client, context.project, "chat-1");

  assert.equal(structuredContent(worktree).mode, "worktree");
  assert.ok(Array.isArray(structuredContent(worktree).agentsFiles));
  assert.equal(structuredContent(checkout).mode, "checkout");
  assert.ok(Array.isArray(structuredContent(checkout).agentsFiles));
  assert.equal(structuredContent(checkoutAgain).workspaceId, structuredContent(checkout).workspaceId);
  assert.equal(structuredContent(checkoutAgain).agentsFiles, undefined);
  assert.match(responseText(checkoutAgain), /same checkout previously opened/);
});

test("a host without conversation metadata receives normal explicit-workspace behavior", async (t) => {
  const context = await fixture(t);
  const first = await callOpen(context.client, context.project);
  const second = await callOpen(context.client, context.project);

  assert.notEqual(structuredContent(first).workspaceId, structuredContent(second).workspaceId);
  assert.ok(Array.isArray(structuredContent(first).agentsFiles));
  assert.ok(Array.isArray(structuredContent(second).agentsFiles));
  assert.doesNotMatch(responseText(first), /conversation metadata/i);
  assert.doesNotMatch(responseText(second), /conversation metadata/i);
});

test("checkout reuse and context suppression survive a registry restart", async (t) => {
  const context = await fixture(t);
  const first = await callOpen(context.client, context.project, "chat-1");
  const firstWorkspaceId = structuredContent(first).workspaceId;

  await context.close();

  const restoredStore = new SqliteWorkspaceStore(context.stateDir);
  const restoredServer = createMcpServer(
    context.config,
    new WorkspaceRegistry(context.config, restoredStore),
    createReviewCheckpointManager(),
    new ProcessSessionManager(),
    [],
    [],
    createShortcutRuntime(context.config.shortcuts),
  );
  const [restoredClientTransport, restoredServerTransport] = InMemoryTransport.createLinkedPair();
  const restoredClient = new Client({ name: "devspace-restored-test-client", version: "1.0.0" });
  let restoredClosed = false;
  const closeRestored = async () => {
    if (restoredClosed) return;
    restoredClosed = true;
    await restoredClient.close();
    await restoredServer.close();
    restoredStore.close();
  };
  t.after(closeRestored);

  try {
    await Promise.all([
      restoredClient.connect(restoredClientTransport),
      restoredServer.connect(restoredServerTransport),
    ]);

    const restored = await callOpen(restoredClient, context.project, "chat-1");
    assert.equal(structuredContent(restored).workspaceId, firstWorkspaceId);
    assert.equal(structuredContent(restored).agentsFiles, undefined);
    assert.match(responseText(restored), /same checkout previously opened/);
  } finally {
    await closeRestored();
  }
});

interface ServerFixture {
  client: Client;
  project: string;
  config: ServerConfig;
  stateDir: string;
  workspaces: WorkspaceRegistry;
  conversationBootstrap: ConversationBootstrapRegistry;
  close: () => Promise<void>;
}

async function fixture(
  t: TestContext,
  options: {
    git?: boolean;
    toolMode?: "minimal" | "full" | "codex";
    widgets?: "off" | "changes" | "full";
    shortcuts?: boolean | "remote-only";
  } = {},
): Promise<ServerFixture> {
  const root = await mkdtemp(join(tmpdir(), "devspace-server-test-"));
  const project = join(root, "project");
  const agentDir = join(root, "agent");
  const stateDir = join(root, ".state");

  await mkdir(join(project, ".devspace", "agents"), { recursive: true });
  await mkdir(join(project, ".agents", "skills", "project-skill"), { recursive: true });
  await mkdir(agentDir, { recursive: true });
  await mkdir(join(agentDir, "skills", "global-skill"), { recursive: true });
  await writeFile(join(agentDir, "AGENTS.md"), "global instructions\n");
  await writeFile(join(project, "AGENTS.md"), "project instructions\n");
  await writeFile(
    join(agentDir, "skills", "global-skill", "SKILL.md"),
    [
      "---",
      "name: global-skill",
      "description: Global skill.",
      "---",
      "",
      "# Global Skill",
    ].join("\n"),
  );
  await writeFile(
    join(project, ".agents", "skills", "project-skill", "SKILL.md"),
    [
      "---",
      "name: project-skill",
      "description: Project skill.",
      "---",
      "",
      "# Project Skill",
    ].join("\n"),
  );
  await writeFile(join(project, ".devspace", "agents", "reviewer.md"), [
    "---",
    "name: reviewer",
    "description: Reviews project changes.",
    "provider: codex",
    "---",
    "Review changes.",
  ].join("\n"));

  if (options.git) {
    await writeFile(join(project, "README.md"), "hello\n");
    await git(project, ["init"]);
    await git(project, ["config", "user.email", "devspace@example.com"]);
    await git(project, ["config", "user.name", "DevSpace Test"]);
    await git(project, ["add", "."]);
    await git(project, ["commit", "-m", "Initial commit"]);
  }

  const config = loadConfig({
    DEVSPACE_CONFIG_DIR: join(root, ".config"),
    DEVSPACE_ALLOWED_ROOTS: root,
    DEVSPACE_WORKTREE_ROOT: join(root, ".worktrees"),
    DEVSPACE_AGENT_DIR: agentDir,
    DEVSPACE_WIDGETS: options.widgets ?? "full",
    DEVSPACE_TOOL_MODE: options.toolMode ?? "full",
    DEVSPACE_OAUTH_OWNER_TOKEN: "test-owner-token-that-is-long-enough",
    PORT: "1",
  });
  if (options.shortcuts) {
    const jiraEnabled = options.shortcuts !== "remote-only";
    config.shortcuts = {
      browserRead: { enabled: options.shortcuts === true },
      remoteMcpRead: {
        enabled: true,
        routes: {
          jira: {
            transport: "ssh-stdio",
            host: "company",
            command: "/usr/bin/true",
            args: [],
            env: {},
            allowedTools: ["searchJiraIssuesUsingJql", "getJiraIssue"],
            toolDefaults: {},
            startupTimeoutSeconds: 45,
            callTimeoutSeconds: 60,
          },
        },
      },
      jiraLookup: jiraEnabled
        ? { enabled: true, route: "jira" }
        : { enabled: false },
    };
  }
  const store = new SqliteWorkspaceStore(stateDir);
  const workspaces = new WorkspaceRegistry(config, store);
  const conversationBootstrap = new ConversationBootstrapRegistry();
  const server = createMcpServer(
    config,
    workspaces,
    createReviewCheckpointManager(),
    new ProcessSessionManager(),
    [],
    [],
    createShortcutRuntime(config.shortcuts),
    conversationBootstrap,
  );
  const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
  const client = new Client({ name: "devspace-test-client", version: "1.0.0" });
  await Promise.all([
    client.connect(clientTransport),
    server.connect(serverTransport),
  ]);

  let closed = false;
  const close = async () => {
    if (closed) return;
    closed = true;
    await client.close();
    await server.close();
    store.close();
  };

  t.after(async () => {
    await close();
    await rm(root, { recursive: true, force: true });
  });

  return {
    client,
    project,
    config,
    stateDir,
    workspaces,
    conversationBootstrap,
    close,
  };
}

async function connectAdditionalClient(
  t: TestContext,
  context: ServerFixture,
): Promise<Client> {
  const shortcuts = createShortcutRuntime(context.config.shortcuts);
  const server = createMcpServer(
    context.config,
    context.workspaces,
    createReviewCheckpointManager(),
    new ProcessSessionManager(),
    [],
    [],
    shortcuts,
    context.conversationBootstrap,
  );
  const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
  const client = new Client({ name: "devspace-second-transport", version: "1.0.0" });
  await Promise.all([
    client.connect(clientTransport),
    server.connect(serverTransport),
  ]);
  t.after(async () => {
    await client.close();
    await server.close();
    await shortcuts.close();
  });
  return client;
}

async function git(cwd: string, args: string[]): Promise<void> {
  await execFileAsync("git", args, { cwd });
}

async function callOpen(
  client: Client,
  path: string,
  conversationScopeId?: string,
  mode?: "checkout" | "worktree",
): Promise<Awaited<ReturnType<Client["callTool"]>>> {
  const params = {
    name: "open_workspace",
    arguments: {
      path,
      ...(mode ? { mode } : {}),
    },
    ...(conversationScopeId
      ? { _meta: { "openai/session": conversationScopeId } }
      : {}),
  } as Parameters<Client["callTool"]>[0];
  return client.callTool(params);
}

function structuredContent(result: Awaited<ReturnType<Client["callTool"]>>): Record<string, unknown> {
  assert.ok(result.structuredContent);
  return result.structuredContent as Record<string, unknown>;
}

function responseText(result: Awaited<ReturnType<Client["callTool"]>>): string {
  const content = (result as { content?: unknown }).content;
  assert.ok(Array.isArray(content));
  const first = content[0] as { type?: unknown; text?: unknown } | undefined;
  assert.equal(first?.type, "text");
  assert.equal(typeof first?.text, "string");
  return first?.text as string;
}

function skillNames(result: Awaited<ReturnType<Client["callTool"]>>): string[] {
  const skills = structuredContent(result).skills;
  assert.ok(Array.isArray(skills));
  return skills.flatMap((skill) =>
    typeof skill === "object"
      && skill !== null
      && "name" in skill
      && typeof skill.name === "string"
      ? [skill.name]
      : []
  );
}

function agentsFileContents(result: Awaited<ReturnType<Client["callTool"]>>): string[] {
  const files = structuredContent(result).agentsFiles;
  assert.ok(Array.isArray(files));
  return files.flatMap((file) =>
    typeof file === "object"
      && file !== null
      && "content" in file
      && typeof file.content === "string"
      ? [file.content]
      : []
  );
}

function responseCard(result: Awaited<ReturnType<Client["callTool"]>>): Record<string, unknown> {
  const metadata = result._meta;
  assert.ok(metadata && typeof metadata === "object");
  const card = (metadata as Record<string, unknown>).card;
  assert.ok(card && typeof card === "object");
  return card as Record<string, unknown>;
}
