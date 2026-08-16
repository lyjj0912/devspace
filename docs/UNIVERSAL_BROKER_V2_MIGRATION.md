# DevSpace Universal Broker v2 Migration

## Rule

The existing production service remains authoritative until one clean v2
revision passes source, package, load, live, connector, cutover, rollback, and
cleanup gates. Partial milestones are not production completion.

## Phases

### Phase 0 — contracts and budgets

Freeze the fixed eight-tool schema, error model, target and route formats,
payload budgets, and rollback boundary.

### Phase 1 — parallel service

Run `/mcp-next` on isolated state and OAuth storage while legacy `/mcp` remains
available.

### Phase 2 — target and context

Implement deterministic target resolution, truthful probes, lazy instructions
and Skills, existing-path-only contexts, worktree lifecycle, diff resources, and
quotas.

### Phase 3 — execution and process

Unify local and SSH commands, PTY, background conversion, process input,
signals, output resources, dispatch ambiguity, and quotas. All commands execute
as the configured target account.

### Phase 4 — filesystem

Provide local, POSIX SSH/SFTP, and Windows SSH filesystem parity with atomic
writes, preconditions, patches, transfers, and explicit deletion.

### Phase 5 — generic MCP proxy

Proxy local-stdio, SSH-stdio, and Streamable HTTP routes, including tools,
resources, prompts, lazy schemas, result paging, pooling, and no replay after
ambiguous dispatch.

### Phase 6 — artifact and GUI

Implement bidirectional artifacts and generic GUI sessions. Prefer application
protocols such as Chrome DevTools MCP to operating-system GUI automation.

### Phase 7 — lifecycle and load

Apply session, process, context, worktree-byte, result, artifact, GUI, and log
limits. Run deterministic churn and large-output tests.

### Phase 8 — ChatGPT connector validation

Register `myDevSpace-next` and validate the same eight tools in at least five
fresh ChatGPT sessions. Verify local files, external storage, SSH targets,
generic MCP mutation, artifact exchange, and GUI behavior.

### Phase 9 — production cutover

Run the blue/green transaction, authenticated canaries, public-route switch,
rollback rehearsal, stabilization, connector migration, and final owner
credential rotation.

## Removed design

The former administrator-helper phase is intentionally removed. DevSpace does
not ship a root daemon, remote elevation client, passwordless adapter, higher
authority scope, or higher-authority tool input. Operations outside the target
account are performed manually by the user in Terminal.

## Legacy mapping

```text
open_workspace        -> context
read/apply_patch      -> fs
exec_command          -> exec + process
local_shell           -> exec(target=local)
Jira/browser shortcut -> mcp route
artifact download     -> artifact
```

Legacy tools are removed only after the new connector is stable.

## Rollback

Rollback restores the prior public route, PM2 process, OAuth database, and
environment from one deployment audit directory. Additive v2 state remains
isolated and does not prevent the legacy service from restarting.

## Completion rule

Completion requires one clean pushed revision, no elevation components, all
release gates passing, real connector evidence, production cutover and rollback
evidence, final credential rotation, clean worktrees, and no temporary relay or
verification residue.
