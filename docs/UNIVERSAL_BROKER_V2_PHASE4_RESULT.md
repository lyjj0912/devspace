# Universal Broker v2 — Phase 4 Completion Evidence

Date: 2026-08-15 KST

Input commit: `aa9305af1975f9605fa9695ee3c86bf80c4c3416`

Branch: `feat/universal-broker-v2-phase4-filesystem-20260815`

## Delivered contract

The fixed top-level tool surface remains:

```text
target context fs exec process mcp artifact gui
```

Phase 4 implements the existing `fs` schema rather than adding file-type,
storage, application, or target-specific tools.

Implemented operations:

```text
stat
list
read
search
write
patch
mkdir
copy
move
remove
hash
sync
```

Supported targets:

```text
local macOS filesystem
mounted external storage
POSIX SSH targets through command + SFTP adapters
```

## Integrity and publication rules

- Paths may be absolute, tilde-based, or relative to a context.
- Context is a target/path default, not an access boundary.
- A write destination symlink is rejected.
- Text writes are staged in the destination directory, synced, and atomically
  renamed.
- Existing destinations require `overwrite=true`.
- `expectedSha256` provides an optimistic-concurrency precondition.
- POSIX remote content above 64 KiB uses SFTP staging and a framed remote helper
  for atomic publication.
- Remote file patching downloads one file, applies the shared Codex patch
  engine, and republishes only after checking the original remote hash again.
- Directory removal requires `recursive=true`.
- Removal requires `disposition=permanent`; trash is not guessed.
- A cross-device move is not converted silently into copy plus delete.

## Deterministic tests

The Phase 4 suite verifies:

```text
local create/read/hash/copy/move/delete lifecycle         PASS
context-relative path and absolute escape                 PASS
single-file patch with SHA-256 precondition               PASS
bounded read, list, and content search                    PASS
destination-symlink publication refusal                  PASS
explicit permanent-delete contract                       PASS
remote framed helper execution                           PASS
remote SFTP staging for content above 64 KiB              PASS
remote copy/move/remove                                   PASS
remote patch with original-hash recheck                   PASS
OAuth-authenticated HTTP fs write/read/remove             PASS
```

## Real target canaries

Temporary names used random operation identifiers and were removed in `finally`
cleanup paths.

Local targets:

| Path | Create | Read | Hash | Delete |
| --- | --- | --- | --- | --- |
| `/tmp` | PASS | PASS | PASS | PASS |
| `~/Downloads` | PASS | PASS | PASS | PASS |
| `/Volumes/Untitled` | PASS | PASS | PASS | PASS |

Remote targets:

| Target | Small write | Patch | Read | Large SFTP write | Delete |
| --- | --- | --- | --- | --- | --- |
| `company` | PASS | PASS | PASS | PASS | PASS |
| `aws-ai-agent` | PASS | PASS | PASS | PASS | PASS |

Local canary residue count: `0`.

Remote canary cleanup calls completed successfully. No production project file,
Jira issue, service, or persistent configuration was changed.

## Quantitative gates

The top-level schema did not change:

```text
tools                         8 / limit 8
descriptor characters        7,585 / limit 12,000
server instruction chars       695 / limit 2,000
initial context chars         3,656 / limit 4,000
reused context chars            543 / limit 800
```

## Explicit NOT RUN or deferred

- Windows OpenSSH/SFTP filesystem adapter.
- Local root-owned privileged helper installation.
- Local administrator `fs` canary.
- Trash integration.
- Cross-target copy inside `fs`; this belongs to `artifact`.
- Public `/mcp-next` connector and cross-ChatGPT-session validation.
- Production cutover.
- Credential rotation.

Production `/mcp`, PM2, OAuth state, and `src/server.ts` remained unchanged.
