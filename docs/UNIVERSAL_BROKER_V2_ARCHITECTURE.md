# DevSpace Universal Broker v2 Architecture

Status: Phase 0 contract frozen; Phase 1 skeleton and Phase 2 target/context services implemented on isolated branches.

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

Routes are runtime data loaded from `~/.devspace/mcp-routes.v2.json` by default.
The registry hot reloads by content hash; adding Jira, Chrome, database, or
another downstream MCP does not change the eight top-level tool descriptors.

Downstream sessions are pooled by route with an LRU limit and route-specific
idle TTL. A changed route fingerprint replaces the previous session. Tool
schemas are discovered lazily: search returns at most five candidates and
describe returns only one exact schema.

Potentially mutating downstream calls are never replayed after dispatch. A
transport failure after `tools/call` begins returns `MCP_RESULT_UNKNOWN`. Large
results are projected into a bounded preview and retained behind
`devspace://mcp-result/...` resources with TTL and character quotas.

### 3.6 Artifact plane

`artifact` streams files between the MCP host, local target, and remote targets.
It supports receive, publish, and copy without base64-encoding large data into
tool text. Transfers produce size and hash evidence. Outbound host delivery is
reported as unavailable when the connected host lacks the required file-result
capability.

Incoming host-native file values are accepted only through registered trusted
adapters. Generic URL receive accepts HTTPS and loopback HTTP test sources,
revalidates every redirect, streams into owner-only staging, and enforces byte,
size, and SHA-256 limits before filesystem publication.

Cross-target copy is implemented as target-to-owner-only-staging-to-target and
therefore reuses the same local/SFTP atomic publication rules as `fs` without
placing file bytes in tool text. Publish creates a random, TTL-bound, one-time
capability URL and returns it as an MCP resource link. `HEAD` does not consume
the capability; the first `GET` claims it and later requests fail closed.

### `gui`

`gui` is an optional generic operating-system GUI plane. It is not a browser,
Finder, email, Jira, or application-specific adapter. The built-in node currently
uses macOS Accessibility through System Events and exposes four operations:

```text
capabilities
observe
act
wait
```

`observe` returns bounded metadata for the frontmost application, front window,
and meaningful Accessibility elements. Each observation creates or refreshes an
opaque `sessionId` and a generation hash. The generation includes application,
window identity, element order and identity, value, enabled state, and advertised
actions. Volatile focus and geometry fields remain visible but are excluded from
the generation so harmless layout settling does not make every action stale.

`act` accepts only an element ID from the referenced observation or a global
keystroke/key-code action. Before dispatch, DevSpace re-observes the target and
requires the same generation. The GUI node then independently verifies the
frontmost PID, front-window title, element index, role, subrole, name, and
description. A mismatch returns `GUI_STATE_CHANGED`; the action is not retried.

Supported generic actions are:

```text
perform an advertised AX action
press/click through AXPress
set_value
focus
keystroke with modifiers
key_code with modifiers
```

The local node is stored under `~/.devspace/run` and invoked through the same
generic execution and filesystem planes as every other target. An SSH target may
use `gui.mode=ssh-stdio`, but remote availability is determined by the target's
actual macOS TCC/Accessibility state. A configured node that lacks permission
reports `CAPABILITY_UNAVAILABLE`; it never claims GUI parity.

Chrome web inspection and automation should use a downstream Chrome DevTools MCP
route when available. The generic GUI plane is the application-agnostic fallback
for native operating-system UI and workflows unavailable through a semantic MCP.

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

The release gate measures tool descriptors, server instructions, initial context,
and reused-context payloads on every v2 milestone.

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

## 10. Current implementation status

Implemented:

- exact eight-tool MCP skeleton;
- stable common error response;
- descriptor and instruction budget gate;
- independent v2 configuration and state directory;
- independent OAuth resource and Streamable HTTP endpoint;
- `serve-next` CLI command;
- baseline, target, route, error, and capability contracts;
- in-memory and HTTP boundary tests.
- dynamic target registry loaded from `targets.v2.json`;
- exact ID/display-name/alias resolution without fuzzy retries;
- cached local, POSIX SSH, and Windows SSH capability probes;
- existing-path-only local and remote context opening;
- persistent context handles in isolated v2 state;
- instruction references by path, size, and SHA-256 without eager content;
- task-ranked Skill suggestions limited to five;
- hard initial/reused context payload budgets with deterministic trimming;
- bounded explicit context search and close;
- live validation against local external storage and an SSH-reachable Mac.

Not implemented yet:

- context worktree creation and context diff resources;
- filesystem and execution adapters;
- privileged helper;
- generic downstream MCP proxy;
- artifact and GUI implementation;
- v2 production deployment.

The checked-in `examples/targets.v2.json` demonstrates the configuration shape.
The active machine-specific registry is stored outside Git with mode `0600`.
