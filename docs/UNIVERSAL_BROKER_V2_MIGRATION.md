# DevSpace Universal Broker v2.1 Migration

## Authority

This document distinguishes the completed v2 cutover from the v2.1 hardening
upgrade. Historical parallel aliases and temporary OAuth compatibility are not
current production authority.

## Historical v2 cutover

The original sequence froze the fixed eight-tool contract, ran `/mcp-next` with
isolated state, completed local/SSH/Windows filesystem and execution parity,
added generic MCP/artifact/GUI planes, exercised load and rollback, and finally
moved canonical `/mcp` to Universal Broker v2.

The former administrator-helper design was removed before production. No root
daemon, remote elevation client, passwordless adapter, higher-authority scope,
or system-password path is part of the product.

## v2.1 hardening upgrade

v2.1 keeps the same eight top-level tools and adds operations within them.

### Gate 1 — exact operation authority

Add R0–R3 classification, `context.authorize`, status/release/correction
operations, exact fingerprints, target-generation and route-fingerprint
binding, one-shot R3 use, and receipts. Existing read operations remain R0.

### Gate 2 — runtime no-elevation

Enforce the ordinary-account boundary through macOS sandboxing, Linux
`no_new_privs`, Windows integrity checks, service-account startup checks,
truthful target probes, and the same boundary for local/SSH stdio MCP providers.

### Gate 3 — granular OAuth only

Retain the six tool scopes plus `offline_access`. Reject the legacy single scope
at metadata, token, and request boundaries. A production environment containing
the removed compatibility flag must fail startup.

### Gate 4 — durable self-management

Add `process.restart_broker` and `process.restart_status`. Restart is performed
by an independent user-level worker after the MCP response grace period and is
verified after reconnect.

### Gate 5 — management-plane isolation

A public reverse-proxy request must receive 403 from `/metrics`; local health and
public OAuth discovery remain available as designed.

## Connector rule

The canonical connector name is `myDevSpace`. A connector alias retained by an
already-open ChatGPT conversation is stale session state, not installed-state
authority. Post-deploy evidence must come from a freshly connected canonical
session exposing the fixed eight tools.

## Legacy mapping

```text
open_workspace        -> context.open
read/apply_patch      -> fs
exec_command          -> exec + process
local_shell           -> exec(target=local)
Jira/browser shortcut -> mcp route
artifact download     -> artifact
```

The mapping is documentation only; legacy top-level tools and blanket OAuth
scope do not remain in v2.1 production.

## Upgrade and rollback

An upgrade builds an immutable release from one clean pushed revision, verifies
its candidate against isolated candidate OAuth state, records the current
PM2/env/Funnel/canonical-OAuth state, switches only the named production process,
runs local and public canaries, and updates the canonical start path only after
PASS. Failure restores the previous release and environment.

A restart of the same release uses the durable in-product restart transaction.
A release upgrade uses the deployment transaction; neither relies on the MCP
connection surviving process replacement.

## Completion rule

Completion requires one clean pushed revision, the fixed eight-tool contract,
all authority/no-elevation/OAuth/restart/metrics gates, deterministic and real
load evidence, canonical connector evidence, exact production readback, and no
temporary worker, test, relay, release, or process residue.
