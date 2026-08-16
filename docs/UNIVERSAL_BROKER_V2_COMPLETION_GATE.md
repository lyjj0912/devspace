# Universal Broker v2 Completion Gate

## Fixed contract

```text
target context fs exec process mcp artifact gui
```

- Exactly eight top-level tools.
- New targets and routes require configuration only.
- Context is not an authority boundary.
- Missing context paths are never created.
- Results and metadata remain within fixed budgets.

## Account-authority gate

- No `devspace.admin` scope.
- No `privilege=admin` input or target capability.
- No local or remote elevation helper.
- No passwordless elevation adapter.
- No LaunchDaemon, system service, capability token, socket, or peer gate for
  higher authority.
- No system password accepted, transmitted, stored, pasted, logged, or scraped.
- Higher-authority work is outside MCP and is run manually by the user in
  Terminal after inspecting the command.

## Functional gate

- Local and external-storage file lifecycle passes.
- Local PTY and managed-process lifecycle passes.
- POSIX SSH and Windows SSH user-account execution and filesystem pass.
- Generic MCP read, write, destructive invocation, resources, and prompts pass.
- Chrome DevTools, Jira, and generic computer-use routes are configured and
  exercised through `mcp`.
- Artifact inbound, outbound, and target-to-target transfer pass.
- Local GUI and truthful remote GUI capability reporting pass.

## Performance gate

- Tool descriptors and context payloads pass budget checks.
- HTTP session churn, context reuse, local execution, SSH execution, downstream
  MCP invocation, large output, and large-directory load tests pass.
- Session, process, context, worktree-byte, result, artifact, GUI, and log quotas
  are enforced.

## Connector gate

- A separate `myDevSpace-next` connector is authorized.
- At least five fresh ChatGPT sessions expose the identical eight-tool surface.
- The required functional scenarios pass without route or path guessing loops.

## Production gate

- Source tree clean and `HEAD == upstream`.
- Typecheck, tests, build, budget, load, package, secret scan, and live gates pass
  from the same revision.
- Blue/green local and public canaries pass.
- Rollback to legacy and return to v2 are rehearsed.
- Final connector migration and credential rotation occur last.

## Cleanliness gate

- No temporary installer, verification server, relay, status funnel, test
  fixture, canary file, staging directory, or orphan process remains.
- `dist` and npm package contain no tests, fixtures, one-off scripts, or
  elevation components.
- Legacy code is removed only after the stabilization window.

Any failed or unexecuted item blocks the production completion tag.
