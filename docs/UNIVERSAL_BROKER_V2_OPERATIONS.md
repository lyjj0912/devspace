# DevSpace Universal Broker v2 Operations

## 1. Production isolation

The current production process remains unchanged:

```text
command: devspace serve
port: 7676
endpoint: /mcp
state: existing DevSpace state directory
```

The v2 skeleton is a separate process:

```text
command: devspace serve-next
default port: 7677
endpoint: /mcp-next
health: /healthz-next
state: <production-state>/universal-broker-v2
```

Do not point the production connector at `/mcp-next` during development.

## 2. Configuration

Supported Phase 1 variables:

```text
DEVSPACE_NEXT_HOST
DEVSPACE_NEXT_PORT
DEVSPACE_NEXT_PUBLIC_BASE_URL
DEVSPACE_NEXT_MCP_PATH
DEVSPACE_NEXT_STATE_DIR
DEVSPACE_NEXT_TARGETS_FILE
DEVSPACE_NEXT_MCP_ROUTES_FILE
DEVSPACE_NEXT_CONTEXT_STORE
DEVSPACE_NEXT_PROCESS_OUTPUT_DIR
DEVSPACE_NEXT_SSH_CONTROL_DIR
DEVSPACE_NEXT_MAX_RUNNING_PROCESSES
DEVSPACE_NEXT_MAX_RUNNING_PROCESSES_PER_TARGET
DEVSPACE_NEXT_PROCESS_BUFFER_CHARACTERS
DEVSPACE_NEXT_PROCESS_OUTPUT_MAX_BYTES
DEVSPACE_NEXT_COMPLETED_PROCESS_TTL_MS
DEVSPACE_NEXT_ALLOWED_HOSTS
DEVSPACE_NEXT_MCP_SESSION_IDLE_TIMEOUT_MS
DEVSPACE_NEXT_MCP_SESSION_CLEANUP_INTERVAL_MS
```

The default target registry is `~/.devspace/targets.v2.json`. The file is hot
reloaded by content hash. Adding, removing, or renaming a target does not change
the MCP tool schema or require a DevSpace rebuild. Start from:

```bash
cp examples/targets.v2.json ~/.devspace/targets.v2.json
chmod 600 ~/.devspace/targets.v2.json
```

`target list`, `target resolve`, and `target probe` are implemented. Probe output
separates configured claims from observed capability. Phase 2 intentionally
reports remote PTY and SFTP probes as not run rather than assuming support.

`context open` accepts existing local absolute/tilde paths and existing remote
paths on configured SSH targets. It never creates a missing path. Context state
is stored in the isolated v2 context store and contains references and hashes,
not complete instruction or Skill bodies.

During parallel public testing, use a distinct public origin for v2 so its OAuth
authorization and token endpoints cannot conflict with production.

## 3. Commands

```bash
npm run typecheck
npm run v2:test
npm run build
npm run v2:budget
npm run release:verify
node dist/cli.js serve-next
```

`release:verify` builds v2 and runs the budget gate in addition to all legacy
tests. A descriptor or server-instruction regression fails the release.

## 4. Phase 1 health checks

```bash
curl -fsS http://127.0.0.1:7677/healthz-next
curl -i http://127.0.0.1:7677/mcp-next
```

Expected results:

```text
/healthz-next -> 200
/mcp-next without bearer token -> 401
```

An authenticated client sees exactly eight tools. `target` and the non-diff
operations of `context` are implemented. The other six tools, context worktree,
and context diff return `CAPABILITY_UNAVAILABLE` until their implementation
phases land.

## 5. Budget report

`npm run v2:budget` prints:

- exact tool count and order;
- total descriptor characters;
- server-instruction characters;
- per-tool descriptor characters;
- pass/failure reasons.

The report must be attached to every phase completion record.

## 6. Branch and tag policy

Baseline tag:

```text
universal-broker-v2-baseline-20260815
```

Initial development branch:

```text
feat/universal-broker-v2-phase0-1-20260815
```

Production deployment is forbidden from this branch. Phase branches merge only
after their contract, budget, unit, integration, and rollback gates pass.

## 7. Logs

Phase 1 v2 events use the `v2_` prefix, including:

```text
v2_http_request
v2_mcp_session_created
v2_mcp_session_closed
v2_mcp_request_error
v2_auth_denied
```

Owner credentials and bearer tokens must never appear in these records.

## 8. Failure handling

If the v2 skeleton fails, stop only the v2 process. Production `/mcp` must remain
available. Delete or archive only the separate v2 state after preserving evidence.
Do not rotate production OAuth credentials for a v2 development failure.

## 9. Phase completion evidence

Each phase records:

```text
input commit
output commit
changed paths
contract revision
typecheck/test/build results
budget report
live endpoint boundary results
rollback result
known NOT RUN items
```
