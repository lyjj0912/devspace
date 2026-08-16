# DevSpace Universal Broker v2 Architecture

## Product definition

DevSpace is a generic MCP broker for the user's own machines and services. It
exposes a fixed, application-independent tool surface and moves integration
details into target and route configuration.

The fixed tools are:

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

Adding another machine, storage location, browser protocol, Jira instance, or
database must not add another top-level MCP tool.

## Authority model

DevSpace runs only with the operating-system account that starts the service or
the configured SSH account on a remote target. It does not install an elevation
service, retain a system password, invoke non-interactive elevation, or expose an
MCP input that requests a higher operating-system identity.

When an operation requires a higher identity, DevSpace reports that the current
account lacks permission. The user may then inspect and run an appropriate
command directly in a local Terminal. That interaction is outside DevSpace and
its MCP transport.

Workspace or context handles are workflow defaults, not authority boundaries.
Filesystem and command operations may address any path the selected account can
access.

## Components

### Target registry

Targets are data. Each target declares an ID, aliases, transport, platform,
shell, optional default directory, optional environment profile, lifecycle
backend, and optional GUI node. A target is resolved deterministically; unknown
or ambiguous selectors fail with authoritative candidates rather than guesses.

### Context index

Contexts hold project defaults, instruction-file references, relevant Skill
references, Git state, and optional managed worktrees. Opening a missing path
never creates it. Instruction and Skill bodies are loaded lazily and bounded.

### Filesystem plane

`fs` provides local and SSH/SFTP operations using one schema:

```text
stat list read search write patch mkdir copy move remove hash sync
```

Writes use preconditions where supplied, same-directory staging, and atomic
publication. Remote operations preserve the same error and retry contract.

### Execution plane

`exec` and `process` provide local and SSH execution, PTY input, bounded output,
background conversion, polling, signalling, resizing, waiting, and cleanup. All
commands run as the selected target account. Dispatch ambiguity is explicit and
never causes an automatic replay.

### Generic MCP proxy

`mcp` proxies configured local-stdio, SSH-stdio, and Streamable HTTP routes. It
supports tools, resources, and prompts without service-specific DevSpace code.
Schemas are discovered lazily and large results are retained behind bounded
resource handles.

### Artifact plane

`artifact` streams files between the host, local storage, and remote targets.
It avoids base64 in model-visible tool text, verifies hashes, applies byte
quotas, and uses expiring one-time publication links.

### GUI plane

`gui` is an optional generic operating-system UI node. Protocol-native control,
such as Chrome DevTools MCP, is preferred. GUI actions require a fresh observed
generation so stale UI state is not acted upon.

## Error and retry contract

Path, target, permission, and schema errors are not retried. A transport may be
reconnected once only when the request was not dispatched. A command or provider
mutation whose dispatch state is unknown is reported as unknown and is never
replayed automatically.

## Quantitative budgets

```text
top-level tools                         8
combined tool descriptors              <= 12,000 characters
server instructions                    <= 2,000 characters
initial context model-visible payload  <= 4,000 characters
reused context payload                 <= 800 characters
```

Sessions, processes, contexts, worktrees, artifacts, GUI sessions, downstream
MCP sessions, result stores, and logs all have explicit quotas or retention.

## Non-goals

- application-specific top-level tools;
- a stored or reusable system-password path;
- an elevation daemon or passwordless execution bridge;
- hidden agent loops inside the broker;
- automatic creation of guessed paths;
- blind retries of commands or external mutations.
