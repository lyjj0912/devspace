# Universal Broker v2.1 Completion Gate

## Fixed contract

```text
target context fs exec process mcp artifact gui
```

- Exactly eight top-level tools.
- New targets and routes require configuration only.
- Context is a workflow default, not an access boundary.
- Missing context paths are never created.
- Tool descriptors and model-visible results remain within budgets.
- `context.authority_preview` is planning-only and cannot create, consume, or
  grant authority.
- SSH PTY and SFTP capabilities are verified rather than hard-coded or left as
  phase placeholders.

## Operation-authority gate

- R0 inspection executes without a task authority.
- R1–R3 require an exact `authorityId` prepared through `context.authorize`.
- Authority is bound to OAuth client, MCP session, correction epoch, action
  fingerprint, expiry, risk, use count, and the current target generation or MCP
  route fingerprint where applicable.
- R3 is one-shot.
- A user correction invalidates all earlier records in that session.
- PASS, FAIL, and UNCERTAIN receipts are recorded; uncertain dispatch is not
  replayed.

## Account-authority gate

- No administrator OAuth scope or administrator tool input.
- No local or remote elevation helper, passwordless adapter, privileged socket,
  peer gate, or stored system password.
- The service refuses root/effective-identity drift or an elevated Windows
  token.
- macOS, Linux, and Windows execution each have a runtime ordinary-account
  enforcement mechanism; macOS also rejects every setuid/setgid executable, and
  local/SSH stdio MCP child processes inherit the same boundary.
- A target missing that mechanism is reported DEGRADED and does not advertise
  execution/filesystem/MCP capability.
- Higher-authority work remains outside MCP.

## Runtime-environment gate

- Startup removes inherited `DEVSPACE_*` variables before sourcing the exact
  owner-only runtime environment file.
- Candidate, final switch, rollback, and ordinary restart apply the same rule.
- A removed compatibility flag cannot survive through PM2 metadata or the parent
  broker environment.

## OAuth gate

- Tool scopes are the six granular `devspace.*` scopes.
- `offline_access` may be advertised for refresh-token continuity and grants no
  tool authority.
- The legacy single scope is rejected.
- A removed compatibility flag set to true fails startup.
- Access tokens are resource-bound; PKCE S256 and refresh-token rotation pass.

## Functional gate

- Local and external-storage lifecycle passes.
- Local PTY and managed-process lifecycle passes.
- POSIX SSH and Windows SSH user-account execution/filesystem pass deterministic
  integration tests.
- Production live canaries are mandatory only for targets explicitly selected by
  the upgrade transaction. `company` is the default required real target;
  Windows becomes mandatory when `--windows-live-target` is supplied. An
  unselected or offline configured target is reported truthfully, not certified.
- Generic MCP read, write, destructive invocation, resources, and prompts pass.
- Bounded provider-readiness retry is restricted to a freshly described,
  explicitly read-only and non-destructive MCP tool. Mutation and destructive
  invocations are not replayed.
- Chrome DevTools, Jira, and generic computer-use routes are exercised through
  `mcp`.
- Artifact inbound, outbound, and target-to-target transfer pass.
- Local GUI and truthful remote GUI capability reporting pass.
- The GUI node executes only when its canonical owner-only file, built-in
  SHA-256, and bounded argument grammar match. Alternate paths, symlinks,
  writable/tampered files, shell syntax, `osascript -e`, and environment-profile
  combination fail closed.
- Local/SSH stdio MCP children remain under the generic no-elevation wrapper and
  cannot select the GUI exact-execution contract.
- The exact remote GUI invocation returns to the SSH marker shell; success and
  policy rejection both emit a deterministic completion marker with the actual
  exit code instead of becoming an ambiguous post-dispatch `UNKNOWN` result.
- Authority canaries cover R0, R1, R2, R3, mismatch, consumption, correction,
  and dispatch uncertainty.

## Self-management gate

- `process.restart_broker` requires one-shot R3 authority.
- The initial response returns a durable transaction ID before PM2 replacement.
- An independent user-level worker changes the PID and saves PM2 state.
- `process.restart_status` is readable after a new MCP connection.
- Expected process name, cwd/script, local health, and public health pass.
- Stale nonterminal transactions fail closed.
- No worker process or launch job remains after PASS/FAIL.

## Management-plane gate

- Local `/metrics` returns 200 with a local Host.
- The public service Host returns 403 even when a reverse proxy connects from
  loopback.
- Local/public health returns 200.
- Unauthenticated MCP initialize returns 401.

## Performance gate

- Tool descriptors and context payloads pass budget checks.
- HTTP session churn, context reuse, local and SSH execution, downstream MCP,
  large output, and large-directory tests pass.
- Session, authority, restart, process, context, worktree-byte, result, artifact,
  GUI, and log quotas are enforced.

## Connector gate

- The installed connector is canonical `myDevSpace`.
- Fresh post-deploy sessions expose the identical fixed eight-tool surface.
- Required local, external-storage, SSH, MCP mutation, artifact, GUI, authority,
  no-elevation, and restart scenarios pass without route/path guessing loops.
- Stale aliases in already-open conversations are not accepted as evidence.

## Production gate

- Source is clean and `HEAD == upstream`.
- Typecheck, complete tests, production dependency audit, build, budget,
  deterministic load, real-target load, package, secret scan, and live gates
  pass from the same revision.
- Candidate verification uses isolated candidate OAuth state; the final runtime
  reuses only the recorded canonical production OAuth database.
- Source and deployed `dist` tree hashes match.
- PM2, Funnel, listener, OAuth, environment, and release path match the recorded
  revision.
- Rollback to the previous release and return to v2.1 are rehearsed or the
  upgrade transaction proves the equivalent switch/restore path.

## Cleanliness gate

- No temporary installer, verification server, relay, status Funnel, fixture,
  canary file, staging directory, worker job, or orphan process remains.
- `dist` and the npm package contain no tests, fixtures, one-off scripts, or
  elevation components.
- Audit and first-failure evidence are preserved.

Any failed, stale, or unexecuted item blocks the production completion tag.
