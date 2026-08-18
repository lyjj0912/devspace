# DevSpace Universal Broker v2.1 Architecture

## Product definition

DevSpace is a generic MCP broker for the user's own machines and services. It
exposes one fixed, application-independent tool surface and moves machine,
transport, service, and credential references into owner-managed configuration.

The fixed top-level tools remain:

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
database must not add another top-level MCP tool. New integrations are target or
MCP-route data.

## Two independent authority boundaries

### Operating-system account boundary

DevSpace runs only as the ordinary operating-system account that starts the
service or the configured SSH account on a remote target. It never installs an
elevation service, accepts a system password, or exposes an MCP input that asks
for a higher identity.

The boundary is enforced at runtime, not only documented:

- macOS commands run under a sandbox profile that denies Authorization Services
  acquisition and known elevation executables and all setuid/setgid executables;
- Linux commands run with `no_new_privs` through `setpriv`;
- Windows execution rejects high-integrity and system tokens;
- target probes report a degraded target when the required enforcement
  primitive is unavailable.

Higher-identity work is outside DevSpace. The user performs it manually in a
local terminal after reviewing the command.

### Operation authority boundary

OAuth authenticates the MCP client. A separate exact-action authority layer
prevents stale, over-broad, or accidentally reused mutations.

```text
R0  inspection; no task authority
R1  bounded local mutation
R2  remote, shared, published, or externally visible mutation
R3  irreversible, destructive, deployment, delivery, or GUI action
```

`context.authorize` creates a short-lived authority record containing exact tool
calls, normalized argument fingerprints, risk, and use limits. R3 actions are
one-shot. Records are bound to the OAuth client and MCP session. A correction
increments the session correction epoch and invalidates all earlier records.
PASS, FAIL, and UNCERTAIN receipts are retained without storing the controlling
instruction text; only its SHA-256 is recorded.

The authority layer is an execution-consistency control. It does not turn model
text into a cryptographic human signature; the connected MCP host remains
responsible for presenting user intent and confirmation correctly.

Contexts remain workflow defaults, not filesystem or execution sandboxes.

## Components

### Target registry

Targets declare an ID, aliases, transport, platform, shell, optional default
directory, environment profile, process lifecycle backend, and optional GUI
node. Resolution is deterministic. Unknown or ambiguous selectors fail with
candidates instead of guesses. Probes include truthful user-account-boundary
readiness. Exact authorities for target-backed mutations include the target
registry generation and canonical target ID, so a configuration reload or alias
remap invalidates an authority prepared against the earlier registry.

### Context and authority index

Contexts hold project defaults, instruction-file references, relevant Skill
references, Git state, and optional managed worktrees. Opening a missing path
never creates it. Instruction and Skill bodies are lazy and bounded.

The same `context` top-level tool exposes the operation-authority lifecycle:

```text
authorize authority_status invalidate_authority release_authority
```

This preserves the fixed eight-tool surface.

### Filesystem plane

`fs` provides local and SSH operations using one schema:

```text
stat list read search write patch mkdir copy move remove hash sync
```

Writes use optional SHA-256 preconditions, same-directory staging, and atomic
publication. Exact authority fingerprints include paths, disposition,
overwrite/precondition flags, and hashes of model-provided content or patches.

### Execution and process plane

`exec` and `process` provide local and SSH execution, PTY input, bounded output,
background conversion, polling, signalling, resizing, waiting, cleanup, and
broker self-restart transactions. Dispatch ambiguity is explicit and never
causes an automatic replay.

Broker restart uses:

```text
process.restart_broker
process.restart_status
```

The request is written atomically, then an independent user-level worker waits
for the response grace period, restarts the exact PM2 process, persists PM2
state, verifies PID replacement and local/public health, and records PASS or
FAIL. The caller reconnects and reads the transaction by ID. A stale nonterminal
transaction fails closed rather than blocking all future restarts forever.

### Generic MCP proxy

`mcp` proxies configured local-stdio, SSH-stdio, and Streamable HTTP routes. It
supports tools, resources, and prompts without service-specific DevSpace code.
Before an invocation, downstream tool annotations are inspected. An explicitly
read-only invocation is R0, an explicitly destructive invocation is R3, and a
missing, contradictory, or mutating annotation fails conservatively at R2.
Exact MCP invocation authorities include the canonical route ID, provider risk
annotation, and route fingerprint, so provider or route drift invalidates stale
authority before dispatch. Local and
SSH stdio providers inherit the same runtime no-elevation wrapper as ordinary
commands. Large results are retained behind bounded resource handles.

### Artifact plane

`artifact` streams files between the MCP host, local storage, and remote targets.
It avoids base64 in model-visible tool text, verifies hashes, applies byte
quotas, and uses expiring one-time publication links.

### GUI plane

`gui` is an optional generic operating-system UI node. Protocol-native control,
such as Chrome DevTools MCP, is preferred. GUI actions are R3 and require both an
exact one-shot authority record and a fresh observed generation.

### Management plane

Health and OAuth discovery are public as required. Metrics are management data:
they require both a loopback socket and a local Host header. A reverse proxy that
connects from loopback cannot make a public Host eligible for metrics.

## Error and retry contract

Path, target, permission, authority, and schema failures are not retried.
Transport reconnection is permitted only before dispatch. A command or provider
mutation whose dispatch state is unknown returns an unknown result and consumes
its authority use; it is never replayed automatically.

## Quantitative budgets

```text
top-level tools                         8
combined tool descriptors              <= 12,000 characters
server instructions                    <= 2,000 characters
initial context model-visible payload  <= 4,000 characters
reused context payload                 <= 800 characters
```

Sessions, authority records, restart transactions, processes, contexts,
worktrees, artifacts, GUI sessions, downstream MCP sessions, result stores, and
logs have explicit quotas or retention.

## Non-goals

- application-specific top-level tools;
- administrator free-pass mode;
- a reusable system-password path;
- an elevation daemon or passwordless bridge;
- hidden agent loops inside the broker;
- automatic creation of guessed paths;
- blind retries of commands or external mutations;
- treating an authority record as proof of a human signature.
