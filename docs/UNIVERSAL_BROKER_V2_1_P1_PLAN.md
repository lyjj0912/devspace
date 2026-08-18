# Universal Broker v2.1 P1 Capability and Operability

## Objective

P1 removes avoidable discovery and authorization retry loops without weakening
any P0 authority, OAuth, no-elevation, dispatch, or fixed-tool boundary.

The top-level MCP surface remains exactly:

```text
target context fs exec process mcp artifact gui
```

## Scope

### Truthful target capabilities

SSH targets perform bounded, read-only capability probes after the ordinary-user
execution boundary is established:

- forced-TTY allocation is verified with a marker emitted from an actual remote
  TTY;
- the SFTP subsystem is verified with a non-interactive empty batch handshake;
- POSIX helper-backed filesystem operations remain available when the
  ordinary-user execution boundary is available, while transfer-dependent
  operations expose the independent SFTP capability;
- Windows remote filesystem support is advertised only when its required SFTP
  script-staging path is available;
- PTY and SFTP failures are independent and retain bounded reasons;
- probe results are cached by target-registry generation and TTL;
- concurrent probes for the same target generation share one in-flight probe;
- `target.probe(refresh=true)` explicitly bypasses a still-valid cache entry.

A target may remain `ONLINE` while one optional capability is unavailable. The
capability map and evidence, rather than a guessed phase placeholder, determine
what is usable.

### Authority preview

`context.authority_preview` is an R0 planning operation. It normalizes the exact
planned calls with the same target-generation, MCP-route, provider annotation,
GUI generation, path, command, and payload-hash rules used by
`context.authorize`, then returns:

- per-action canonical fingerprint;
- minimum and effective R0–R3 risk;
- whether authority is required;
- bounded uses and parameter-key inventory;
- one deterministic plan fingerprint.

Duplicate exact actions are rejected; repeated identical calls use one action
with a bounded `uses` count. Preview does not create, consume, extend, or
approve authority and cannot execute an action. Planning also requires the same granular OAuth capability
scope as the planned tool, so `devspace.read` alone cannot inspect or prepare
exec, MCP, artifact, or GUI actions. `context.authorize` remains required for
every R1–R3 action; R3 remains one-shot.

### Ordinary-user macOS automation

Ordinary AppleScript remains available through the same generic execution plane.
Static command classification rejects AppleScript requests for administrator
privileges, and the macOS runtime profile independently denies Authorization
Services acquisition. This restores ordinary-account automation without adding
an elevation path or a GUI-specific privilege exception.

### Observability

Doctor and loopback-only metrics report bounded aggregate target-probe cache,
outcome, and latency data plus authority-preview counts. They do not expose
commands, payloads, credentials, or controlling instruction text.

### Capability-aware dispatch

A fresh cached observation may fail a request before dispatch when it proves the
required ordinary-user capability is unavailable. Absence of a cached
observation does not invent a denial or trigger an implicit probe; callers can
use `target.probe` explicitly. This keeps normal execution free of repeated
probe latency while eliminating known-impossible dispatches.

## Non-goals

- no administrator, root, helper, password, or elevation path;
- no ninth top-level tool or service-specific shortcut;
- no automatic execution from an authority preview;
- no implicit retry after a failed or ambiguous mutation;
- no background browser window, temporary browser profile, or input-focus
  automation;
- no claim that every configured target is online.

## Acceptance gates

P1 is complete only when all of the following pass from one clean revision:

1. contract and payload budgets still expose eight top-level tools;
2. unit tests cover PTY/SFTP success, independent failure, cache hit, explicit
   refresh, registry-generation invalidation, Linux/Windows PTY no-elevation,
   and ordinary-versus-administrator AppleScript;
3. real `company` target probe reports verified PTY and SFTP when available;
4. authority preview classifies mixed R0/R1/R2/R3 batches without creating an
   authority and an unapproved mutation still fails before dispatch;
5. doctor and local metrics expose only aggregate P1 telemetry;
6. P0 authority, no-elevation, granular OAuth, public-metrics isolation,
   package, load, and restart gates remain passing;
7. full load includes the real SSH target and the source tree is clean before
   commit and push.
