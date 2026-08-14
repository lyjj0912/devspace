# Configuration Reference

DevSpace can be configured through `devspace init`, persisted config files, or
environment variables.

The default files are:

```text
~/.devspace/config.json
~/.devspace/auth.json
```

Use another config directory with:

```bash
DEVSPACE_CONFIG_DIR=/path/to/config npx @waishnav/devspace serve
```

## Commands

```bash
npx @waishnav/devspace init
npx @waishnav/devspace serve
npx @waishnav/devspace doctor
npx @waishnav/devspace maintenance --dry-run
npx @waishnav/devspace maintenance
npx @waishnav/devspace config get
npx @waishnav/devspace config set publicBaseUrl https://devspace.example.com
```

This personal checkout also includes a reproducible release gate and PM2
definition:

```bash
npm run release:verify
npm run deploy:pm2
npm run release:live
```

`release:verify` runs type checking, the complete test suite, the production
build, diff validation, and build-contract checks. `release:live` checks that the
committed tree is clean, verifies the built tool/maintenance surface, and probes
the local health and unauthenticated MCP boundary. The PM2 definition fixes the
service working directory to this repository instead of inheriting the terminal
directory that happened to launch PM2. `deploy:pm2` normally reloads the
existing service; when it detects a legacy process whose actual cwd differs
from the repository, it recreates only the `devspace` PM2 process once and then
saves the corrected process definition.

## Core Environment Variables

| Variable | Purpose |
| --- | --- |
| `HOST` | Local bind host. Defaults to `127.0.0.1`. |
| `PORT` | Local port. Defaults to `7676`. |
| `DEVSPACE_ALLOWED_ROOTS` | Comma-separated local roots that workspaces may open. |
| `DEVSPACE_PUBLIC_BASE_URL` | Public origin for the server, without `/mcp`. |
| `DEVSPACE_ALLOWED_HOSTS` | Optional Host header allowlist override. |
| `DEVSPACE_OAUTH_OWNER_TOKEN` | Owner password for OAuth approval. Must be at least 16 characters. |
| `DEVSPACE_WORKTREE_ROOT` | Directory for managed Git worktrees. Defaults to `~/.devspace/worktrees`. |
| `DEVSPACE_STATE_DIR` | Directory for SQLite state. Defaults to `~/.local/share/devspace`. |

## Native Artifact Download

Native-file download is disabled by default. Enable it when ChatGPT needs to hand
an attached or generated file into an already-open workspace:

```bash
DEVSPACE_ARTIFACTS=1 npx @waishnav/devspace serve
```

This feature currently supports Linux. It is not registered on macOS, Windows,
or BSD because the secure publication path depends on traversable,
descriptor-anchored directory paths provided by Linux procfs.

| Variable | Default | Purpose |
| --- | --- | --- |
| `DEVSPACE_ARTIFACTS` | `0` | Expose `download_artifact` for trusted native files. |
| `DEVSPACE_ARTIFACT_MAX_FILE_BYTES` | `104857600` | Maximum streamed size of one file (100 MiB). |

The same settings may be persisted in `~/.devspace/config.json` as
`artifactsEnabled` and `artifactMaxFileBytes`.

`download_artifact` accepts the native file object supplied by the MCP connector,
a `workspaceId` returned by `open_workspace`, and a relative workspace `path`.
DevSpace safely creates missing parent directories, refuses to overwrite an
existing destination, and returns only the normalized workspace-relative path.
It does not accept conflict modes, expected hashes, arbitrary URL strings, local
paths, embedded credentials, or extra object fields.

There is no artifact root, total quota, TTL, pinning, persistent database record,
or background artifact cleanup service. See [Native File Download](artifact-exchange.md)
for the supported connector shape and security boundaries.

## OAuth

DevSpace uses a single-user OAuth approval flow.

| Variable | Default |
| --- | --- |
| `DEVSPACE_OAUTH_ACCESS_TOKEN_TTL_SECONDS` | `3600` |
| `DEVSPACE_OAUTH_REFRESH_TOKEN_TTL_SECONDS` | `2592000` |
| `DEVSPACE_OAUTH_SCOPES` | `devspace` |
| `DEVSPACE_OAUTH_ALLOWED_REDIRECT_HOSTS` | `chatgpt.com,localhost,127.0.0.1` |

MCP clients discover metadata from:

```text
/.well-known/oauth-protected-resource/mcp
/.well-known/oauth-authorization-server
```

## Tool Modes

`DEVSPACE_TOOL_MODE` controls the tool surface.

| Value | Behavior |
| --- | --- |
| `minimal` | Default. Exposes `open_workspace`, `read`, `write`, `edit`, and `bash`. Clients use `bash` with tools such as `rg`, `find`, and `ls` for inspection. |
| `full` | Exposes the minimal tools plus dedicated `grep`, `glob`, and `ls` tools. |
| `codex` | Experimental. Exposes `open_workspace`, `read`, `apply_patch`, `exec_command`, and `write_stdin`. Existing mutation and shell tools are hidden. |

This personal deployment also exposes `local_shell` in every tool mode. It does
not take a `workspaceId`; use it only for explicitly requested personal file
management or local automation outside coding projects. Its working directory
must be an absolute path or a leading-tilde home path and defaults to the
DevSpace service user's home directory. The command runs with that user's
existing authority, and DevSpace does not add privilege elevation. Because this
tool intentionally bypasses workspace and allowed-root containment, keep the
server behind strong authentication.

`DEVSPACE_MINIMAL_TOOLS` remains a backward-compatible alias when
`DEVSPACE_TOOL_MODE` is unset: `1` selects `minimal` and `0` selects `full`.
The `codex` mode must be selected through `DEVSPACE_TOOL_MODE` and always uses
its fixed short tool names regardless of `DEVSPACE_TOOL_NAMING`.

Codex-mode commands run without a PTY by default. Set `tty: true` on
`exec_command` for interactive terminal programs. PTY support uses the optional
`node-pty` dependency; `write_stdin` can send input, poll output, and resize PTY
sessions.

## Widgets

`DEVSPACE_WIDGETS` controls ChatGPT Apps iframe usage.

| Value | Behavior |
| --- | --- |
| `changes` | Default. Enables the aggregate `show_changes` tool and attaches widget UI only to `open_workspace` and `show_changes`. |
| `full` | Widget UI is attached to exposed workspace, file, edit, and shell tools. |
| `off` | Disables widget UI. |

## MCP Session Retention

DevSpace checks for abandoned MCP sessions once per minute and closes sessions
that have been idle for 10 minutes. Active and recently reused sessions are kept.
Both values accept milliseconds from config or environment variables:

| Config key | Environment variable | Default |
| --- | --- | --- |
| `mcpSessionIdleTimeoutMs` | `DEVSPACE_MCP_SESSION_IDLE_TIMEOUT_MS` | `600000` |
| `mcpSessionCleanupIntervalMs` | `DEVSPACE_MCP_SESSION_CLEANUP_INTERVAL_MS` | `60000` |

## Persistent Workspace Maintenance

DevSpace performs a conservative maintenance pass before the server starts.
The same pass can be inspected or run explicitly with `devspace maintenance`.
It removes expired conversation bindings, missing or stale unbound workspace
sessions, expired clean managed worktrees, and obsolete review refs. A managed
worktree with tracked or untracked changes is never deleted automatically. A
clean worktree whose HEAD diverged from its recorded base is retained unless
that HEAD remains reachable from a permanent local branch, remote branch, or
tag.
Recently used worktrees are protected even when a source repository temporarily
exceeds its configured per-source limit.

The maintenance defaults are intentionally longer than MCP transport retention:

| Config key under `maintenance` | Environment variable | Default |
| --- | --- | --- |
| `enabled` | `DEVSPACE_MAINTENANCE` | `true` |
| `minimumIntervalMs` | `DEVSPACE_MAINTENANCE_MINIMUM_INTERVAL_MS` | `86400000` (24 hours) |
| `conversationBindingRetentionMs` | `DEVSPACE_CONVERSATION_BINDING_RETENTION_MS` | `2592000000` (30 days) |
| `workspaceSessionRetentionMs` | `DEVSPACE_WORKSPACE_SESSION_RETENTION_MS` | `604800000` (7 days) |
| `workspaceSessionLimit` | `DEVSPACE_WORKSPACE_SESSION_LIMIT` | `512` |
| `managedWorktreeRetentionMs` | `DEVSPACE_MANAGED_WORKTREE_RETENTION_MS` | `604800000` (7 days) |
| `managedWorktreeRecentProtectionMs` | `DEVSPACE_MANAGED_WORKTREE_RECENT_PROTECTION_MS` | `86400000` (24 hours) |
| `managedWorktreePerSourceLimit` | `DEVSPACE_MANAGED_WORKTREE_PER_SOURCE_LIMIT` | `8` |
| `reviewWorkspaceLimit` | `DEVSPACE_REVIEW_WORKSPACE_LIMIT` | `32` per Git repository |

The session limit only removes the oldest unbound checkout sessions. Active
conversation bindings and retained managed worktrees remain authoritative even
when those protected records prevent the database from reaching the numeric
limit. Directories under the managed-worktree root that are not represented by
retained database state are reported but not deleted automatically.

`.agent-harness` and `.tmp` are local workflow/scratch roots. Workspace
instruction discovery skips them, and review snapshots exclude them even when a
repository has not added corresponding ignore rules.

## Personal Shortcut Tools

Personal extensions use the `_shortcut` suffix so they remain distinct from
upstream DevSpace tools. They are disabled by default and do not change the
selected core tool mode.

| Tool | Purpose |
| --- | --- |
| `browser_read_shortcut` | List Chrome tabs, open one HTTP(S) URL, and read bounded page text. It cannot click, type, submit, upload, download, or accept model-supplied JavaScript. |
| `remote_mcp_read_shortcut` | List or invoke allowlisted read-only tools through a configured remote MCP route. With one route, DevSpace selects it automatically and omits the route input. With multiple routes, the schema exposes only the configured route names as an enum. One process-wide SSH/stdio session is reused per route. `list_tools` reports approved/cached capabilities and is explicitly not a provider-liveness check. Generic call output defaults to 10,000 characters; request a larger bound only when necessary. |
| `jira_lookup_shortcut` | Preferred path for ordinary Jira issue or JQL reads. Returns compact summaries and explicitly requested fields instead of raw provider payloads. |

Configuration keeps provider commands and credentials outside model-visible tool
inputs:

```json
{
  "shortcuts": {
    "browserRead": { "enabled": true },
    "remoteMcpRead": {
      "enabled": true,
      "routes": {
        "company-jira": {
          "transport": "ssh-stdio",
          "host": "company",
          "command": "/absolute/path/to/node",
          "args": ["/absolute/path/to/atlassian-mcp.js"],
          "env": { "PATH": "/usr/local/bin:/usr/bin:/bin" },
          "allowedTools": [
            "searchJiraIssuesUsingJql",
            "getJiraIssue"
          ],
          "toolDefaults": {
            "searchJiraIssuesUsingJql": { "cloudId": "example.atlassian.net" },
            "getJiraIssue": { "cloudId": "example.atlassian.net" }
          }
        }
      }
    },
    "jiraLookup": { "enabled": true, "route": "company-jira" }
  }
}
```

Environment variables may override enablement and the configured Jira route:

```text
DEVSPACE_SHORTCUT_BROWSER_READ_ENABLED
DEVSPACE_SHORTCUT_REMOTE_MCP_READ_ENABLED
DEVSPACE_SHORTCUT_JIRA_LOOKUP_ENABLED
DEVSPACE_SHORTCUT_JIRA_LOOKUP_ROUTE
```

Remote route maps remain file-only. A single generic remote route is selected
without model input; multiple routes become a closed configured enum rather than
a free-form string. `jira_lookup_shortcut` does not accept a route input, so the
local configuration owns the Jira provider selection.

## Skills

| Variable | Purpose |
| --- | --- |
| `DEVSPACE_SKILLS` | Set to `0` to hide skills. Enabled by default. |
| `DEVSPACE_SUBAGENTS` | Set to `1` to expose configured agent profiles as Subagents. Experimental and disabled by default. |
| `DEVSPACE_AGENT_DIR` | Defaults to `~/.codex`; its `skills` child is loaded for compatibility. |
| `DEVSPACE_SKILL_PATHS` | Optional comma-separated additional skill directories. |

DevSpace discovers standard Agent Skills from:

- `~/.agents/skills`
- project `.agents/skills`
- `~/.devspace/skills`

It also keeps compatibility with:

- the bundled `subagent-delegation` skill when `DEVSPACE_SUBAGENTS=1`, unless `~/.devspace/skills/subagent-delegation/SKILL.md` exists
- `DEVSPACE_AGENT_DIR/skills`, defaulting to `~/.codex/skills`
- additional paths from `DEVSPACE_SKILL_PATHS`

When Subagents are enabled, DevSpace discovers agent profiles
from:

- `~/.devspace/agents/*.md`
- project `.devspace/agents/*.md`

`open_workspace` returns a compact catalog containing profile names,
descriptions, providers, and optional models/thinking levels so the host model can choose an
agent without reading provider-specific launch details. `devspace agents ls`
lists existing subagent sessions for the current workspace, scoped by the
workspace environment injected into shell commands. The `subagent-delegation`
skill teaches the model to use only the minimal `devspace agents ls`,
`devspace agents run`, and `devspace agents show` workflow.

Starter profile templates are available under `examples/agents/`. Copy or adapt
them into one of the active profile directories before use.

Legacy project paths such as `.pi/skills` can be added through `DEVSPACE_SKILL_PATHS` when needed.

Example:

```bash
DEVSPACE_SKILL_PATHS="$HOME/.claude/skills,$HOME/company/skills" \
npx @waishnav/devspace serve
```

## Logging

| Variable | Default |
| --- | --- |
| `DEVSPACE_LOG_LEVEL` | `info` |
| `DEVSPACE_LOG_FORMAT` | `json` |
| `DEVSPACE_LOG_REQUESTS` | `1` |
| `DEVSPACE_LOG_ASSETS` | `0` |
| `DEVSPACE_LOG_TOOL_CALLS` | `1` |
| `DEVSPACE_LOG_SHELL_COMMANDS` | `0` |
| `DEVSPACE_TRUST_PROXY` | `0`; set a positive hop count such as `1` when behind one trusted reverse proxy. Boolean `true` is normalized to one hop, never an unrestricted proxy trust function. |

Set `DEVSPACE_LOG_FORMAT=pretty` for local debugging.

Set `DEVSPACE_LOG_SHELL_COMMANDS=1` only when you intentionally want command
previews in logs.

## Env-Only Example

```bash
DEVSPACE_OAUTH_OWNER_TOKEN="$(openssl rand -base64 32)" \
DEVSPACE_ALLOWED_ROOTS="$HOME/personal,$HOME/work" \
DEVSPACE_PUBLIC_BASE_URL="https://devspace.example.com" \
DEVSPACE_WORKTREE_ROOT="$HOME/.devspace/worktrees" \
DEVSPACE_ARTIFACTS="1" \
DEVSPACE_TOOL_MODE="minimal" \
DEVSPACE_WIDGETS="changes" \
npx @waishnav/devspace serve
```

The environment assignments must be part of the same command invocation, or
exported first.
