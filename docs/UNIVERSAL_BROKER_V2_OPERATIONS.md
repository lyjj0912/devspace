# DevSpace Universal Broker v2.1 Operations

## Runtime modes

Parallel verification uses `/mcp-next` with isolated state. Production binds the
canonical `/mcp` endpoint on the recorded production port. Once initial cutover
is complete, production upgrades switch between immutable v2 release
directories; they do not recreate a legacy runtime.

## Owner-managed configuration

Files under `~/.devspace` that can contain route or environment references use
mode `0600`:

```text
~/.devspace/targets.v2.json
~/.devspace/mcp-routes.v2.json
~/.devspace/env-profiles.v2.json
~/.devspace/universal-broker-v2-production.env
```

SSH PTY and SFTP support are verified with bounded read-only probes and cached by
target-registry generation and TTL. Use `target.probe(refresh=true)` after an
external target configuration or availability change; normal execution does not
implicitly repeat the probe.

Important production values include:

```text
DEVSPACE_NEXT_SELF_MANAGEMENT_DIR
DEVSPACE_NEXT_PM2_PROCESS_NAME
DEVSPACE_NEXT_PM2_EXPECTED_SCRIPT
DEVSPACE_NEXT_SELF_RESTART_DELAY_MS
DEVSPACE_NEXT_SELF_RESTART_TIMEOUT_MS
DEVSPACE_NEXT_OAUTH_STATE_DIR
```

The removed legacy-scope compatibility flag must be absent or false. Setting it
true is a startup error.

## Runtime environment isolation

`~/.devspace/universal-broker-v2-production.env` is authoritative. Startup,
candidate verification, production switch, and rollback discard inherited
`DEVSPACE_*` values before sourcing that file. An absent managed key therefore
stays absent; it cannot be resurrected from an older PM2 or broker environment.

## Verification commands

```bash
npm run typecheck
npm test
npm run build
npm run v2:budget
npm run v2:load
DEVSPACE_V2_LOAD_TARGET_CONFIG="$HOME/.devspace/targets.v2.json" \
DEVSPACE_V2_LOAD_SSH_TARGET=company \
DEVSPACE_V2_LOAD_REQUIRE_REAL_SSH=1 npm run v2:load
npm run release:verify -- --require-clean
```

`release:verify` runs the canonical test composition, a production dependency
audit with low-or-higher findings blocked, build, budget, quick load,
source/package boundary scans, granular OAuth checks, operation-authority checks,
runtime no-elevation checks, restart-worker checks, and metrics isolation checks.
The second load command is the final P1 source gate: real SSH, PTY, SFTP, and
transfer-capable remote-filesystem evidence are mandatory rather than an optional
load add-on. Production upgrade always requires the selected POSIX target
(default `company`). Add `--windows-live-target windows` only when that endpoint
is intentionally online and must be certified in the same transaction; other
configured offline targets remain truthful `OFFLINE` observations rather than
blocking unrelated production cutover. A live provider readiness check may retry
only an exact tool whose current descriptor is explicitly `readOnlyHint=true`
and not destructive. Mutating or destructive downstream MCP calls are never
replayed by the verifier.

## Operation authority workflow

Use `context.authority_preview` before the first mutation to classify and batch
the exact planned calls without dispatching or creating authority. R0 reads need
no lease. Prepare only the returned R1–R3 actions through `context.authorize`
using the current controlling instruction, then pass the returned `authorityId`
to those exact calls.

An authority record does not wildcard another path, command, target, route, GUI
generation, or argument set. Target and MCP authorities also bind the current
registry generation or route fingerprint; owner configuration changes require a
new authority. R3 is consumed once even when the result becomes UNCERTAIN. After
a user correction, call `context.invalidate_authority`; create a new record only
for the corrected action.

Release unused authority with `context.release_authority`. Inspect receipts with
`context.authority_status`.

## Filesystem and command behavior

Paths must already exist when opening a context. `fs` and `exec` operate with the
selected target account's permissions. Long-running commands return a process
handle instead of occupying one HTTP request indefinitely.

If an operation requires a higher operating-system identity, stop the MCP action
and present the exact reason. The user may perform it manually outside DevSpace.
DevSpace must not request, transmit, paste, store, or inspect the system password.

## Durable broker restart

1. Prepare one R3 action for `process.restart_broker` with the exact reason and
   delay.
2. Call `process.restart_broker` and retain the returned transaction ID.
3. The broker writes request/status files and launches a user-level worker.
4. The worker waits for the response grace period, replaces the PM2 process,
   saves PM2 state, and verifies PID/cwd/script and local/public health.
5. Reconnect the canonical connector.
6. Call `process.restart_status` with the transaction ID; no authority is needed
   for this read.
7. Treat only `PASS` as completion. Preserve `FAIL` evidence and do not blindly
   repeat the restart.

A restart changes no release revision. Use the production upgrade transaction to
switch to a different immutable release.

## Health, metrics, and authentication

```bash
curl -fsS http://127.0.0.1:7678/healthz
curl -fsS https://home-ai.tail733d38.ts.net/healthz
curl -fsS -H 'Host: 127.0.0.1:7678' http://127.0.0.1:7678/metrics
```

Expected boundaries:

- local and public health: 200;
- unauthenticated MCP initialize: 401;
- local metrics with local Host: 200;
- public metrics: 403.

## Production upgrade transaction

The upgrade procedure:

1. verifies a clean pushed revision;
2. creates an immutable release worktree;
3. runs install, release gate, full load, and real-target canaries;
4. starts the candidate with an isolated candidate OAuth database while retaining
   the canonical production OAuth database for the final switch;
5. captures current PM2, environment, OAuth, Funnel, and release evidence;
6. schedules the process switch through an independent user-level worker so the
   initiating MCP connection is not the transaction owner;
7. verifies the new PID, cwd/script, local/public health, OAuth boundary,
   authority canaries, no-elevation canaries, metrics isolation, and connector
   reconnect;
8. updates the canonical start path and audit link only after PASS;
9. restores the previous release/environment on failure.

## Logs and cleanup

PM2 log rotation is bounded separately. Authority records, restart transactions,
process output, artifacts, contexts, and downstream results have TTL or count
limits. Temporary OAuth clients, canaries, worker jobs, test files, and staging
paths are removed after verification. Audit and first-failure evidence remain.

## Failure handling

- Preserve the first failing boundary and operation/transaction ID.
- Do not repeat an identical failed request.
- Do not replay a command or external mutation after possible dispatch.
- Do not infer restart/deploy success from a disconnected connector; reconnect
  and read durable status plus PM2/health evidence.
- Leave the previous production release active when upgrade evidence is
  incomplete.
