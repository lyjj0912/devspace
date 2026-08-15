# DevSpace Universal Broker v2 Migration

## 1. Migration rule

Migration is additive until final cutover. The production `/mcp` tool surface,
OAuth database, PM2 process, and connector remain unchanged while v2 is built and
tested separately.

## 2. Phases

### Phase 0 — baseline and contracts

Deliverables:

- immutable baseline tag and metadata;
- architecture, security, operations, and migration documents;
- fixed eight-tool contract;
- target, MCP route, error, and capability schemas;
- executable descriptor and instruction budget gate.

### Phase 1 — isolated skeleton

Deliverables:

- `serve-next` command;
- separate default port, path, state directory, and OAuth resource;
- exact eight tools returning explicit unavailable errors;
- in-memory schema test and unauthenticated HTTP boundary test.

### Phase 2 — target and context

Implement target registry, alias resolution, capability probes, existing-path
context open, lazy instruction discovery, and task-relevant Skill search. Add
executable context and metadata budgets.

Status: implemented on `feat/universal-broker-v2-phase2-target-context-20260815`.
Context worktree and diff remain intentionally deferred to the filesystem and
execution phases.

### Phase 3 — execution and process

Implement local and SSH execution, PTY, automatic background conversion,
stdin/poll/signal/resize, bounded output resources, SSH connection reuse, and
unknown-dispatch protection.

Status: implemented and fixed at tag
`universal-broker-v2-phase3-exec-process-20260815`.

### Phase 4 — filesystem

Implement local and SFTP adapters, atomic writes, patch preconditions, explicit
deletion, copy/move/sync, and external storage. Cross-target transfer uses the
artifact plane rather than overloading one-target filesystem operations.

Status: implemented for local filesystems and POSIX SSH/SFTP targets on
`feat/universal-broker-v2-phase4-filesystem-20260815`. Windows SFTP and local
administrator filesystem access remain explicit later-phase work.

### Phase 5 — administrator helper

Implement and independently install a root-owned local helper. Add remote helper
and `sudo-n` adapters. No password is accepted through MCP.

### Phase 6 — generic MCP proxy

Implement local stdio, SSH stdio, and Streamable HTTP routes; tools, resources,
and prompts; lazy schema discovery; full read/write/destructive invocation; and
unknown-result protection.

Status: implemented on
`feat/universal-broker-v2-phase6-generic-mcp-20260815`. Downstream
read/write/destructive fixture calls and a real company Jira read route were
verified without adding a Jira-specific top-level tool.

### Phase 7 — artifact and GUI

Implement bidirectional host file exchange and generic local/remote GUI nodes.
Migrate Chrome to a downstream Chrome DevTools MCP route.

Artifact status: implemented on
`feat/universal-broker-v2-phase7-artifact-gui-20260815`. Native/URL receive,
local/remote copy, and one-time publish have deterministic and real-target
evidence. Generic GUI remains the next milestone on the same branch lineage.

GUI status: implemented on the same branch lineage. The generic macOS
Accessibility node, generation-bound observe/act/wait contract, authenticated
top-level MCP integration, local live press/input canaries, target capability
configuration, payload budgets, TTL, and stale-action rejection are complete.
The company Mac is configured for `ssh-stdio` but its SSH execution context does
not currently have Accessibility permission, so it correctly remains
`CAPABILITY_UNAVAILABLE` pending operator-side TCC approval.

### Phase 8 — lifecycle and load

Add session LRU, process and buffer quotas, downstream connection quotas,
worktree byte quotas, resource TTL, log rotation, and load tests.

### Phase 9 — cross-session host validation

Register a separate `myDevSpace-next` connector. Validate the same fixed tool
surface in multiple fresh ChatGPT sessions without repeated schema changes.

### Phase 10 — cutover

After all gates pass:

1. preserve source, dist, state, and connector evidence;
2. drain the production process;
3. deploy v2 at `/mcp`;
4. run health, auth, tool, local, external-storage, SSH, MCP, artifact, GUI, and
   admin canaries;
5. reconnect the production connector once;
6. retain the legacy build for immediate rollback;
7. remove legacy tools only after the stabilization window.

## 3. Legacy mapping

| Legacy tool | v2 replacement |
| --- | --- |
| `open_workspace` | `context` |
| `read` | `fs` |
| `apply_patch` | `fs` |
| `local_shell` | `exec` + `process` |
| `exec_command` | `exec` + `process` |
| `write_stdin` | `process` |
| `show_changes` | `context` diff |
| `browser_read_shortcut` | `mcp` Chrome route or `gui` |
| `remote_mcp_read_shortcut` | `mcp` |
| `jira_lookup_shortcut` | `mcp` Jira route |

## 4. Rollback

Before cutover, rollback means stopping the v2 process. Production is untouched.

After cutover, rollback restores:

- baseline-compatible source and dist;
- production PM2 definition;
- production state backup;
- connector resource and OAuth records where compatible.

v2 database migrations must remain additive until the legacy rollback window
closes. A phase that requires irreversible production-state conversion cannot
merge before an independently tested export/restore path exists.

## 5. Completion rule

No phase is complete merely because code compiles. Completion requires exact
contract consistency, tests, quantitative budgets, real transport canaries,
clean Git state, and explicit NOT RUN disclosure for unavailable external targets.
