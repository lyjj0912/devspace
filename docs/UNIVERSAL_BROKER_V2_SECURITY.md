# DevSpace Universal Broker v2 Security

## Security position

DevSpace is a high-authority user-account broker. OAuth protects access to the
broker, but successful authorization intentionally gives the MCP host the same
ordinary account-level capabilities exposed by the fixed tools.

DevSpace does not provide operating-system elevation. It does not install a
root service, preserve an administrator password, provide a passwordless route,
or accept a system password through an MCP argument, environment variable,
clipboard workflow, file, or log.

## OAuth scopes

The owner scope set is:

```text
devspace.read
devspace.write
devspace.exec
devspace.mcp
devspace.artifact
devspace.gui
```

The legacy `devspace` scope may be expanded only during the bounded production
connector migration. It is removed after the new connector is validated.

## Operating-system account boundary

Local actions execute as the DevSpace service account. Remote actions execute as
the configured SSH account. Target probes report observed user-account
capabilities only. They do not advertise higher authority merely because a
machine belongs to an administrative user.

An operation that the account cannot perform returns a permission failure. The
user may manually run a reviewed command in a local Terminal and type a password
there. DevSpace must not open, feed, scrape, or automate that password prompt.

## Secrets

Secrets are referenced through owner-only environment profiles. Model-visible
calls carry profile IDs, not secret values. Child processes receive a filtered
environment, and logs exclude command bodies and raw MCP arguments by default.
Release packaging scans for live credentials and common secret formats.

## Filesystem integrity

- Missing paths are never created by context discovery.
- Writes use atomic publication and optional SHA-256 preconditions.
- Symlink publication targets are rejected.
- Destructive removal requires an explicit permanent disposition.
- Large transfers use bounded staging and hashes.
- Remote transport loss after possible mutation is reported as an unknown
  result and is not retried.

## Target and route identity

Target and MCP route selectors resolve against authoritative registries. An
ambiguous or unknown selector returns candidates and performs no operation.
Credentials, commands, and route environment are local configuration and are not
accepted as arbitrary model-supplied integration settings.

## GUI integrity

GUI actions are tied to an observed application, window, element identity, and
generation. A changed generation fails before dispatch. Accessibility or TCC
denial is reported as unavailable rather than bypassed.

## Quotas and retention

The service enforces bounded HTTP sessions, contexts, worktrees and bytes,
running processes, process output, downstream MCP sessions, retained results,
artifacts, and GUI sessions. Cleanup never removes dirty or divergent user work.

## Audit evidence

Operation IDs connect tool results to bounded logs. Logs record target, adapter,
duration, result class, and byte counts without persisting credentials or system
passwords. Production deployment and rollback preserve exact commit, build,
health, OAuth, and route evidence.
