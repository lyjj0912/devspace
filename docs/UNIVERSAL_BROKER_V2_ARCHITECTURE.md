# DevSpace Universal Broker v2 Architecture

Status: Phase 0 contract frozen; Phase 1 skeleton implemented on an isolated branch.

Baseline: `ea32ae5bb3518734309f4b95f222df997c045b61`, tagged
`universal-broker-v2-baseline-20260815`.

## 1. Product definition

DevSpace Universal Broker is a general MCP execution layer. It allows an
authorized MCP host to operate on the user's local machine, mounted storage,
network services, SSH-reachable computers, arbitrary MCP servers, artifacts,
and optional operating-system GUI sessions.

DevSpace does not implement Jira, email, Chrome, databases, or individual
products as top-level features. Those systems are reached through generic
filesystem, execution, MCP, artifact, or GUI protocols.

The top-level MCP surface is fixed:

```text
target
context
fs
exec
process
mcp
artifact
gui
```

Adding a target or MCP route changes configuration only. It must not add a
top-level tool, alter the ChatGPT connector schema, or require a service-specific
TypeScript adapter in DevSpace core.

## 2. Authority model

The v2 owner connection may receive the complete scope set:

```text
devspace.read
devspace.write
devspace.exec
devspace.admin
devspace.mcp
devspace.artifact
devspace.gui
```

Authorization is decided from the authenticated scope, requested target,
requested privilege, and observed target capability. It is not inferred from a
tool-name prefix such as `create`, `delete`, `send`, or `deploy`.

A context is not a security boundary. It carries project instructions, Git
state, a default target, and a default path. File and command authority comes
from the authenticated principal and target capability.

## 3. Components

### 3.1 Target registry

The target registry resolves stable IDs, display names, and aliases to one
transport profile. Initial transport types are `local` and `ssh`.

The registry owns:

- target identity and aliases;
- transport and SSH host selection;
- platform and shell profile;
- default working directory;
- user/admin privilege mode;
- environment profile references;
- GUI and durable-process backends;
- cached observed capabilities.

Unknown or ambiguous selectors fail once with authoritative candidates. The
caller must not probe guessed aliases in a loop.

### 3.2 Context index

Context is an optional project handle. `context.open` requires an existing path.
It never creates a missing directory.

The context index stores:

- target and canonical existing root;
- repository and worktree identity;
- applicable instruction-file hashes;
- task-relevant Skill references;
- change-review checkpoint identity;
- last-use and retention metadata.

Instruction and Skill content is lazy. `context.open` returns only compact
references and at most five relevant Skill candidates. Full catalogs and nested
instruction contents are not eagerly embedded in every response.

### 3.3 Filesystem plane

`fs` uses one contract over local filesystem and SSH/SFTP adapters. Operations
include stat, list, read, search, atomic write, patch, mkdir, copy, move, remove,
hash, and sync.

Write operations support preconditions such as expected SHA-256 and expected
metadata. Atomic publication uses a same-directory temporary file, validation,
sync, and rename where the target filesystem supports those semantics.

Remote operations preserve the same contract. Transport differences are adapter
details, not new tools.

### 3.4 Execution plane

`exec` replaces legacy `local_shell`, workspace `bash`, and `exec_command`.

It accepts a target, optional context, working directory, command, privilege,
PTY choice, execution mode, bounded initial yield, output budget, and environment
profile. In `auto` mode the server waits briefly; a continuing command becomes a
managed process and returns `processId`.

`process` owns polling, stdin, terminal resize, signals, wait, listing, and
forgetting. Local and remote processes share the same state model:

```text
STARTING
RUNNING
EXITED
SIGNALED
FAILED
UNKNOWN
```

A connection loss after possible dispatch produces `EXECUTION_STATE_UNKNOWN`.
The broker never blindly replays a potentially mutating command.

### 3.5 Generic MCP proxy

`mcp` proxies configured routes using local stdio, SSH stdio, or Streamable HTTP.
It preserves tools, resources, and prompts.

The caller discovers only relevant tools:

```text
mcp.search_tools
mcp.describe_tool
mcp.invoke
```

The server does not eagerly inject every downstream schema into the host model
context. Large results are stored behind resource handles with bounded previews.

Service-specific parsers and read-only tool-name filters are outside the v2 core
contract. A downstream mutation is authorized by scope and route policy, not by
English prefixes in the downstream tool name.

### 3.6 Artifact plane

`artifact` streams files between the MCP host, local target, and remote targets.
It supports receive, publish, and copy without base64-encoding large data into
tool text. Transfers produce size and hash evidence. Outbound host delivery is
reported as unavailable when the connected host lacks the required file-result
capability.

### 3.7 GUI plane

`gui` is optional and generic. Browser automation should use an application MCP
such as Chrome DevTools whenever available. GUI is reserved for operating-system
interfaces that have no better protocol.

Local GUI uses local IPC. Remote GUI uses stdio over SSH. No extra listening
network port is required. Observe results carry a generation; stale element IDs
are rejected with `GUI_STATE_CHANGED`.

## 4. Fixed schema and dynamic data

Tool names and operation enums are source-controlled contracts. Targets, aliases,
MCP routes, commands, URLs, and environment profiles are runtime data.

The following changes must leave the top-level tool schema unchanged:

- adding or removing an SSH target;
- changing a mounted storage path;
- adding Jira, Chrome, database, or internal MCP routes;
- changing a downstream MCP command;
- changing target privilege capability;
- adding an environment profile.

## 5. Error and retry contract

All failures use stable codes from `contracts/errors.schema.json`, an operation
ID, a retryability decision, evidence, and bounded suggestions.

Automatic retry is allowed only before dispatch or for an explicitly safe,
idempotent transport read. There is no automatic retry for:

- provider mutations after request dispatch;
- commands whose dispatch state is unknown;
- path-not-found or permission failures;
- ambiguous target or route selection;
- identical failed commands.

## 6. Resource handles

Large file reads, process output, diffs, MCP results, GUI observations, and
artifacts use explicit server-minted handles. Model-visible text contains a
bounded preview and metadata. Handles have type, owner, target, creation time,
expiry, size, and integrity metadata.

## 7. Quantitative budgets

The following are build gates, not recommendations:

| Contract | Limit |
| --- | ---: |
| Top-level tools | 8 |
| Tool descriptor JSON | 12,000 characters |
| Server instructions | 2,000 characters |
| Initial context payload | 4,000 characters |
| Reused context payload | 800 characters |
| Per-response `_meta` | 8,000 characters |

The current Phase 1 gate measures tool descriptors and server instructions. The
context and metadata gates become executable with the Phase 2 context service.

## 8. Parallel development boundary

Production remains on `/mcp` and port 7676. v2 uses a separate process, state
directory, OAuth resource, default port 7677, and endpoint `/mcp-next`.

```text
devspace serve       -> production /mcp
devspace serve-next  -> isolated /mcp-next skeleton
```

No incomplete v2 tool is added to production. Phase 1 tools intentionally return
`CAPABILITY_UNAVAILABLE` while preserving their final top-level names and input
shape.

## 9. Non-goals

v2 does not:

- bypass macOS SIP, TCC, disk encryption, or locked sessions;
- store administrator passwords in tool arguments or logs;
- implement a Jira, email, browser, or database workflow engine;
- treat a successful process spawn as proof of a user-visible GUI outcome;
- silently downgrade a write request to read-only behavior;
- create missing paths when the caller intended to open existing context.

## 10. Phase 1 implementation status

Implemented:

- exact eight-tool MCP skeleton;
- stable common error response;
- descriptor and instruction budget gate;
- independent v2 configuration and state directory;
- independent OAuth resource and Streamable HTTP endpoint;
- `serve-next` CLI command;
- baseline, target, route, error, and capability contracts;
- in-memory and HTTP boundary tests.

Not implemented yet:

- target registry and probes;
- context index and lazy Skill search;
- filesystem and execution adapters;
- privileged helper;
- generic downstream MCP proxy;
- artifact and GUI implementation;
- v2 production deployment.
