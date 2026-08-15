# DevSpace Universal Broker v2 Security

## 1. Security position

Universal Broker is authenticated remote control of user-owned machines. It is
not a sandbox. The security boundary is the authenticated principal, OAuth scope,
target identity, requested privilege, operating-system account, and optional
privileged helper.

Filesystem roots and project contexts are workflow defaults, not claims that a
shell command cannot reach the rest of a machine.

## 2. OAuth scopes

The owner may approve the complete scope set:

```text
devspace.read
devspace.write
devspace.exec
devspace.admin
devspace.mcp
devspace.artifact
devspace.gui
```

Each operation checks the minimum required scope. The presence of `devspace.read`
does not authorize write or execution. A host that blocks a requested action is
reported with `HOST_ACTION_BLOCKED`; DevSpace does not pretend the action ran.

Phase 1 uses a separate OAuth resource and separate SQLite state directory. It
does not reuse production clients or access tokens.

## 3. User and administrator privilege

`privilege=user` executes as the DevSpace service account or configured remote
SSH account.

`privilege=admin` requires `devspace.admin` and one target capability:

```text
helper
sudo-n
```

`helper` means a separately installed root-owned service with an authenticated
Unix socket or remote stdio protocol. `sudo-n` means the target already permits
non-interactive sudo. Password prompts are not transported through MCP.

The helper must verify peer identity, owning UID, protocol version, request
scope, target binding, operation ID, and message framing. It must not accept a
network socket or arbitrary unauthenticated local client.

## 4. Secrets

Secrets are referenced through environment profiles. Tool calls contain profile
names, not secret values. Logging defaults exclude command bodies and raw MCP
arguments. Redaction applies before serialization.

Prohibited persistence includes:

- owner password;
- access or refresh tokens;
- SSH private keys;
- sudo passwords;
- downstream MCP bearer tokens;
- presigned artifact URLs;
- raw environment profile values.

## 5. Target identity

Target resolution is deterministic. Aliases are normalized and compared against
one registry snapshot. Ambiguity returns candidates without executing anything.

SSH host identity remains enforced by OpenSSH `known_hosts`. The registry must
not disable host-key checking to make a probe pass.

## 6. Filesystem integrity

Canonicalization occurs on the target that owns the filesystem. Write and patch
operations support content-hash preconditions. Symlink resolution and final
publication are checked at the adapter boundary.

Deletion requires an explicit disposition:

```text
trash
permanent
```

The broker never chooses permanent deletion merely because trash is unavailable.

## 7. Command and downstream MCP ambiguity

The broker distinguishes failures before dispatch from failures after possible
dispatch. A retryable connection failure before request transmission may be
retried once. A failure after a command or downstream mutation might have reached
the provider returns an unknown-state error and is not replayed.

## 8. GUI integrity

GUI observations are generation-bound. An action must reference the observation
generation and stable element ID. If the UI changed, the action is rejected.

GUI nodes do not listen on new network ports. Remote nodes are invoked through
SSH stdio. Screen-lock and permission state are capabilities, not conditions to
bypass.

## 9. Resource quotas

Unbounded resources are prohibited. Later phases enforce limits for:

- HTTP MCP sessions;
- running processes;
- process output buffers;
- downstream MCP connections;
- worktree count and bytes;
- artifact and result resources;
- logs and retention.

Quota exhaustion returns `RESOURCE_QUOTA_EXCEEDED` and must not silently evict an
active mutation or dirty worktree.

## 10. Audit evidence

Every operation has a non-secret operation ID. Audit metadata may include target,
adapter, privilege, duration, result class, exit state, byte count, and hashes.
Raw file contents, full commands, credentials, and downstream payloads are not
default audit fields.

## 11. Downstream MCP credentials

MCP route files are configuration, not secret stores. Do not place bearer
tokens, passwords, private keys, or secret environment values in route command
arguments or URLs.

Permitted patterns are:

- a local `envProfile` resolved into the child environment without logging;
- a remote credential file or platform credential store read by the remote MCP;
- an authenticated HTTPS MCP whose credential provider does not embed secrets
  in the URL;
- a local stdio wrapper that obtains secrets from an owner-only source without
  putting them in argv.

SSH route arguments may reference a remote owner-only environment file, but
secret values themselves must not appear in the route registry or SSH argv.
Route files and remote credential files use mode `0600`.

Downstream write and destructive tools require the owner OAuth scope
`devspace.mcp`; there is no mutation-name denylist. Provider errors are returned
as `MCP_PROVIDER_ERROR`. A connection loss after dispatch is
`MCP_RESULT_UNKNOWN` and is never automatically retried.
