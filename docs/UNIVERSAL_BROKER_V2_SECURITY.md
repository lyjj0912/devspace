# DevSpace Universal Broker v2.1 Security

## Security position

DevSpace is a high-authority **ordinary-user-account** broker. OAuth controls who
may connect. Exact operation authority controls which non-read action may run.
Runtime OS controls prevent the process from acquiring a higher identity.

DevSpace does not install a root service, preserve an administrator password,
provide a passwordless elevation route, or accept a system password through an
MCP argument, environment variable, clipboard workflow, file, GUI prompt, or
log.

## OAuth scopes

The tool-authority scopes are:

```text
devspace.read
devspace.write
devspace.exec
devspace.mcp
devspace.artifact
devspace.gui
```

`offline_access` is also advertised so an authorized connector may obtain and
rotate a refresh token. It grants no tool operation by itself.

The legacy single `devspace` scope is rejected. Universal Broker v2.1 has no
compatibility mode that expands it into all tool scopes. Access tokens are bound
to the configured MCP resource and all presented scopes must be recognized.
Authorization Code with PKCE S256 and rotating refresh tokens remain required.

## Operation authority

R0 inspection is immediate. R1 through R3 calls require an exact authority ID.
The server verifies:

- OAuth client and MCP session binding;
- correction epoch;
- expiry;
- normalized tool/operation/target/resource/argument fingerprint;
- minimum risk classification;
- remaining use count.

R3 is one-shot. A mismatched, expired, corrected, or consumed record fails before
dispatch. Dispatch-uncertain operations record an UNCERTAIN receipt and are not
replayed.

The server stores the controlling instruction SHA-256, not the instruction text.
The MCP host is still responsible for representing real user intent; operation
authority limits accidental reuse and scope drift but is not a standalone human
identity signature.

## Ordinary-user macOS automation

The macOS boundary permits ordinary `/usr/bin/osascript` execution because it is
a standard user-account automation primitive. Two independent controls prevent
that capability from becoming an elevation route: command policy rejects
administrator-privilege AppleScript syntax before dispatch, and the sandbox
profile denies `authorization-right-obtain` at runtime. Regression tests execute
both an ordinary AppleScript and a rejected administrator attempt.

## Operating-system account enforcement

Local actions execute as the DevSpace service account. Remote actions execute as
the configured SSH account.

- macOS uses `sandbox-exec`, denies Authorization Services acquisition, and
  blocks known identity-changing executables and every setuid/setgid executable.
  Ordinary AppleScript is available under that same boundary for `exec`, MCP,
  and GUI paths; it does not receive a privilege or identity-changing exception.
- Linux requires zero effective/permitted/ambient capabilities and wraps execution with `setpriv --no-new-privs`.
- Windows refuses a high-integrity or system token before executing a request.
- the service itself refuses root, mismatched real/effective identities, or an
  elevated Windows token;
- target probes mark the target degraded when this boundary cannot be proven.

Command validation is defense in depth. The OS enforcement wrapper is the
runtime boundary. The wrapper also applies to configured local-stdio and
SSH-stdio MCP providers, not only to the direct `exec` plane.

## Authoritative runtime environment

Every broker start, candidate, final switch, and rollback first removes inherited
`DEVSPACE_*` variables and then sources exactly one owner-only runtime environment
file. This prevents a removed compatibility flag, stale route, old port, or
credential from leaking through the serving broker or PM2 process environment.
The production wrapper may supply only the expected-script fallback; an explicit
value in the runtime file wins.

## Secrets

Secrets are referenced through owner-only environment profiles. Model-visible
calls carry profile IDs, not secret values. Child processes receive a filtered
environment, and logs omit command bodies and raw MCP arguments by default.
Release packaging scans for live credentials and common secret formats.

## Filesystem integrity

- Missing paths are never created by context discovery.
- Writes use atomic publication and optional SHA-256 preconditions.
- Symlink publication targets are rejected.
- Permanent deletion requires explicit disposition and R3 authority.
- Large transfers use bounded staging and hashes.
- Remote transport loss after possible mutation is reported as unknown and is
  not retried.

## Target and route identity

Target and MCP route selectors resolve against authoritative registries. An
ambiguous or unknown selector returns candidates and performs no operation.
Credentials, commands, and route environment are owner configuration and are not
accepted as arbitrary integration settings in model calls. Target-backed
authorities bind the canonical target and registry generation; MCP invocation
authorities bind the canonical route and route fingerprint. A hot-reloaded
registry therefore invalidates stale authority before dispatch.

## GUI integrity

GUI actions require an observed application/window/element generation and a
one-shot R3 authority. A changed generation fails before dispatch. Accessibility
or TCC denial is reported as unavailable rather than bypassed.

## Management endpoints

`/metrics` is available only when both the TCP peer and Host header are local.
Public Funnel or reverse-proxy requests receive 403 even though the proxy itself
connects from loopback. Public `/mcp` remains OAuth-protected and an
unauthenticated initialize request returns 401.

## Durable self-management

A broker restart is never a synchronous command that destroys its own response
channel. The broker records a transaction, launches an independent user-level
worker, returns the transaction ID, and then permits the worker to restart PM2.
After reconnect, `process.restart_status` verifies the stored outcome. The worker
checks the PM2 process name, expected cwd/script, PID change, PM2 persistence,
and local/public health.

## Quotas and retention

The service bounds HTTP sessions, authority records, restart transactions,
contexts, worktrees and bytes, running processes, process output, downstream MCP
sessions, retained results, artifacts, and GUI sessions. Cleanup never removes
dirty or divergent user work.

## Audit evidence

Operation IDs, authority receipts, and restart transaction IDs connect tool
results to bounded evidence. Production deployment and rollback preserve exact
commit, build, health, OAuth, route, PM2, and public-ingress state without
persisting credentials or system passwords.
