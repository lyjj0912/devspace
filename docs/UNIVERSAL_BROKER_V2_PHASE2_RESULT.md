# Universal Broker v2 — Phase 2 Completion Evidence

Date: 2026-08-15 KST

Input commit: `64f882ea37743581524e1290b5a83063b32ffad1`

Branch: `feat/universal-broker-v2-phase2-target-context-20260815`

## Delivered contracts

- Runtime-loaded target registry at `~/.devspace/targets.v2.json` by default.
- Fixed top-level tool schema remains exactly eight tools.
- Exact target ID, display-name, and alias resolution.
- Content-hash hot reload without process restart or schema change.
- Local, POSIX SSH, and Windows SSH target probes.
- Existing-path-only local and remote context opening.
- Persistent context handles in isolated v2 state.
- Instruction references by path, size, scope, and SHA-256.
- Task-ranked Skill references, maximum five.
- Explicit bounded context search and close.
- Initial and reused context payload gates.

`context worktree` and `context diff` remain reserved and return
`CAPABILITY_UNAVAILABLE`. They are not represented as complete.

## Machine-specific target registry

The active registry was created outside Git with mode `0600`:

```text
/Users/lyjj0912/.devspace/targets.v2.json
```

Registry generation during verification:

```text
697d16baad91bbd3
```

Configured targets:

```text
local
company
aws-ai-agent
oci-free-phoenix
oci-phoenix
oracle-ai-agent
windows
desktop-vb91sit
```

Observed result:

| Target | Status | Platform | Admin | Notes |
| --- | --- | --- | --- | --- |
| `local` | ONLINE | macOS | unavailable | user fs/exec/PTY observed |
| `company` | ONLINE | macOS | unavailable | SSH fs/exec observed |
| `aws-ai-agent` | ONLINE | Linux | `sudo-n` observed | Git and rsync observed |
| `oci-free-phoenix` | ONLINE | Linux | `sudo-n` observed | rsync observed; Git absent |
| `oci-phoenix` | ONLINE | Linux | `sudo-n` observed | rsync observed; Git absent |
| `oracle-ai-agent` | ONLINE | Linux | `sudo-n` observed | Git and rsync absent |
| `windows` | OFFLINE | Windows | unavailable | local port 2222 route refused connection |
| `desktop-vb91sit` | OFFLINE | Windows | unavailable | local port 2222 route refused connection |

Remote PTY and SFTP were deliberately reported as not run in Phase 2 rather
than inferred from SSH reachability.

## Real context canaries

Local external-storage context:

```text
target: local
path: /Volumes/Untitled
result: PASS
model-visible data: 1,137 characters
```

SSH context:

```text
target selector: 회사맥
canonical target: company
requested path: ~
resolved path: /Users/yjlee8806
result: PASS
model-visible data: 566 characters
```

Reused local context:

```text
same contextId: PASS
model-visible data: 238 characters
```

Missing-path behavior was tested separately. `context.open` returned
`PATH_NOT_FOUND` and did not create the requested directory.

## Authenticated HTTP MCP canary

A separate temporary v2 process was started on local port `18677` with an
isolated OAuth database, isolated context store, and the machine target registry.
The production process on port `7676` was not restarted.

An ephemeral OAuth client and access token were created only inside the temporary
v2 state. A real `StreamableHTTPClientTransport` connection verified:

```text
exact top-level tools                    8 / PASS
target list                              8 targets / PASS
target resolve selector "회사맥"          company / PASS
target probe company                     ONLINE / PASS
context open local /Volumes/Untitled     PASS
context open company ~                   /Users/yjlee8806 / PASS
missing local context path               PATH_NOT_FOUND / PASS
context close                            both contexts / PASS
remaining temporary contexts             0
guessed path created                     no
```

The temporary process, OAuth state, context state, token, client, and test
directory were removed after the canary. Port `18677` was confirmed closed.

## Quantitative gates

Tool surface:

```text
tools: 8 / limit 8
descriptor characters: 7,585 / limit 12,000
server instruction characters: 695 / limit 2,000
```

Worst-case synthetic context fixture:

```text
initial context: 3,656 / limit 4,000
reused context: 543 / limit 800
deterministic truncation exercised: PASS
```

The live external-storage and SSH context payloads were both smaller than the
worst-case fixture.

## Test and isolation evidence

Passed during Phase 2 development:

```text
npm run typecheck
npm run v2:test
npm run build
npm run v2:budget
```

Production source `src/server.ts`, production PM2 configuration, production
state, production OAuth records, and the production `/mcp` endpoint were not
modified or restarted.

## Explicit NOT RUN

- Persistent v2 PM2 deployment.
- Public `/mcp-next` origin and ChatGPT connector registration.
- Cross-ChatGPT-session schema validation.
- Remote PTY and SFTP probes.
- Context worktree creation.
- Context diff resource generation.
- `fs`, `exec`, `process`, `mcp`, `artifact`, and `gui` implementation.
- Local privileged helper.
