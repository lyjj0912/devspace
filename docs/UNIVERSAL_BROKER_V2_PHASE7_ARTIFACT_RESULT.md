# Universal Broker v2 — Phase 7 Artifact Completion Evidence

Date: 2026-08-15 KST

Input commit: `0fa0f54a723c3103bfecbf4861eb52d034d4c414`

Branch: `feat/universal-broker-v2-phase7-artifact-gui-20260815`

## Delivered contract

The fixed top-level `artifact` tool now implements:

```text
receive
copy
publish
```

No file-format, storage-provider, target, or application-specific tool was
added. Artifact byte movement reuses the existing generic filesystem plane.

## Receive

- Accepts host-native file values only through a registered trusted adapter.
- Accepts HTTPS URL sources and loopback HTTP for deterministic tests.
- Revalidates every redirect and rejects URL userinfo.
- Streams into mode-0600 staging under a mode-0700 directory.
- Enforces per-request, per-artifact, entry, and total-byte quotas.
- Supports declared size and SHA-256 preconditions.
- Publishes to local or remote targets only after complete verification.

## Copy

Cross-target copy exports the source to owner-only local staging and imports it
through `fs` atomic publication. No base64 file content appears in the tool
result. The same operation handles local-to-remote, remote-to-local, and
remote-to-remote paths.

## Publish

Publish returns an MCP `resource_link` backed by:

```text
/artifacts-next/{artifactId}?token=...
```

The capability is random, TTL-bound, compared timing-safely, and one-time.
`HEAD` returns metadata without consuming it. The first `GET` returns bytes and
claims the artifact; a second `GET` returns 404. Capability URLs and tokens were
not written into this evidence.

## Deterministic evidence

```text
trusted native file receive                     PASS
URL receive with redirect validation            PASS
size and SHA-256 verification                   PASS
binary copy without tool-text base64            PASS
one-time publish HEAD/GET/second-GET             PASS
byte quota before destination publication       PASS
authenticated /mcp-next artifact receive        PASS
authenticated /mcp-next artifact copy           PASS
authenticated /mcp-next artifact resource_link  PASS
```

## Real target canaries

Random temporary paths were used and all cleanup ran from `finally` blocks.

| Flow | Hash | Bytes | Result |
| --- | --- | --- | --- |
| local → company Mac → local | equal | equal | PASS |
| local → AWS Linux → local | equal | equal | PASS |
| loopback URL → `/Volumes/Untitled` | equal | equal | PASS |
| local → one-time HTTP resource | metadata + bytes | equal | PASS |

One-time HTTP behavior:

```text
HEAD         200 / non-consuming
first GET    200 / exact bytes
second GET   404
```

Residue counts after cleanup:

```text
local /tmp              0
/Volumes/Untitled       0
company /tmp            0
aws-ai-agent /tmp       0
```

## Quantitative gates

The fixed model contract remained unchanged:

```text
tools                         8 / limit 8
descriptor characters        7,585 / limit 12,000
server instruction chars       695 / limit 2,000
initial context chars         3,656 / limit 4,000
reused context chars            543 / limit 800
```

## Explicit deferred scope

- Generic GUI observe/act/wait.
- Root-owned local privileged-helper installation.
- Public `myDevSpace-next` connector and cross-session validation.
- Production cutover and final credential rotation.

Production `/mcp`, PM2, OAuth state, and `src/server.ts` remained unchanged.
