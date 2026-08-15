# Universal Broker v2 — Phase 7 GUI Completion Evidence

Date: 2026-08-15 KST

Input commit: `85bf8cca054538b81663162be507f6175ee0df31`

Branch: `feat/universal-broker-v2-phase7-artifact-gui-20260815`

## Delivered contract

The fixed top-level `gui` tool now implements:

```text
capabilities
observe
act
wait
```

No Chrome-, Finder-, Settings-, email-, Jira-, or application-specific tool was
added. The built-in node is a generic macOS Accessibility adapter invoked locally
or through an existing SSH target.

## Observation contract

`observe` returns bounded metadata for:

```text
frontmost application name, bundle identifier, and PID
front-window title, role, subrole, position, and size
meaningful AX elements with role, subrole, name, description, value,
enabled/focused state, position, size, and advertised actions
```

Each response supplies an opaque `sessionId`, generation, element IDs scoped to
the observation, omitted count, truncation flag, and measured payload character
count. The default result budget is 12,000 characters.

Generation contains stable UI identity and semantic state. Focus and geometry
remain observable but are excluded because macOS may settle them between two
otherwise identical observations. Application PID, window identity, element
order and identity, values, enabled state, and advertised actions remain bound.

## Action contract

Supported actions:

```text
perform an advertised AX action
press/click through AXPress
set_value
focus
keystroke
key_code
```

Before an action, the service re-observes and compares the generation. The GUI
node then verifies PID, window title, element index, role, subrole, name, and
description. A stale observation returns `GUI_STATE_CHANGED`, with zero action
dispatches. Actions are not retried after dispatch.

## Deterministic evidence

```text
capabilities and bounded observe                    PASS
opaque session and stable generation               PASS
stale generation blocks dispatch                   PASS / dispatch count 0
advertised action verification                     PASS
successful act returns a fresh observation         PASS
wait detects change                                PASS
wait timeout without change                        PASS
payload trimming below configured budget           PASS
session TTL and LRU behavior                       PASS
non-macOS capability reporting                     PASS
authenticated top-level /mcp-next GUI calls        PASS
```

## Actual local macOS canaries

The actual helper enumerated the frontmost Chrome window and meaningful AX
elements with real roles, names, descriptions, values, positions, and actions.

### Stale-action canary

A countdown dialog changed its AX value after observation. The service detected a
new generation and returned `GUI_STATE_CHANGED`; the action was not dispatched.

### Generic press canary

```text
frontmost application    applet
observed elements        5
target element           AXButton / Confirm
advertised action        AXPress
generic perform          PASS
dialog result            button returned:Confirm
dialog closed            PASS
generation changed       PASS
```

### Generic input canary

```text
target element           AXTextField
generic set_value        UniversalBrokerV2 / PASS
new generation returned  PASS
generic AXPress          PASS
dialog returned input    UniversalBrokerV2 / PASS
```

Temporary dialog processes and test directories were removed.

## Machine target state

`~/.devspace/targets.v2.json` remains mode `0600` and now declares:

```text
local.gui.mode    local-ipc
company.gui.mode  ssh-stdio
```

The generic helper was installed through the filesystem plane under
`~/.devspace/run/gui-node.applescript` on both Macs.

Observed capability:

```text
local Mac      Accessibility=true, observe/act PASS
company Mac    helper reachable, Accessibility=false for SSH context
               observe -> CAPABILITY_UNAVAILABLE
```

The company result is a truthful degraded state, not a parity claim. Operator-side
TCC approval for the remote execution context remains required before remote GUI
actions can run.

## Quantitative gates

The fixed model contract remained unchanged:

```text
tools                         8 / limit 8
descriptor characters        7,585 / limit 12,000
server instruction chars       695 / limit 2,000
initial context chars         3,656 / limit 4,000
reused context chars            543 / limit 800
GUI response budget          12,000 characters
```

## Explicit deferred scope

- Company Mac Accessibility/TCC operator approval and remote act canary.
- Screen-capture capability; current node reports `not_probed`.
- Chrome DevTools MCP route for semantic DOM/Console/Network automation.
- Local root-owned privileged-helper installation.
- Public `myDevSpace-next` connector and cross-session validation.
- Production cutover and final credential rotation.

Production `/mcp`, PM2, OAuth state, and `src/server.ts` remained unchanged.
