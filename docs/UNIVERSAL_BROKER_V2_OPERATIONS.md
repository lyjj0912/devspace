# DevSpace Universal Broker v2 Operations

## Modes

Parallel mode runs beside the existing service:

```text
legacy production  http://127.0.0.1:7676/mcp
parallel v2        http://127.0.0.1:7677/mcp-next
```

Production mode binds the canonical `/mcp` endpoint only through the cutover
transaction.

## Configuration

Owner-managed files are stored under `~/.devspace` and must be mode `0600` when
they can contain routes or environment references:

```text
~/.devspace/targets.v2.json
~/.devspace/mcp-routes.v2.json
~/.devspace/env-profiles.v2.json
```

Target entries contain no elevation mode, helper command, socket, or system
password. Each target runs as its configured local or SSH account.

## Commands

```bash
npm run typecheck
npm test
npm run build
npm run v2:budget
npm run v2:load
npm run release:verify -- --require-clean
npm run deploy:v2
npm run undeploy:v2
npm run cutover:v2
npm run rollback:v2
npm run finalize:v2
```

`deploy:v2` starts or reloads only the parallel process. `cutover:v2` requires
clean source, pushed revision equality, load evidence, live canaries, and fresh
ChatGPT connector evidence. `finalize:v2` performs connector and credential
cleanup only after cutover stabilization.

## Health and authentication checks

```bash
curl -fsS http://127.0.0.1:7677/healthz-next
curl -fsS https://home-ai.tail733d38.ts.net/v2/healthz-next
```

An unauthenticated initialize request to the corresponding MCP endpoint must
return HTTP 401.

## Filesystem and command behavior

Paths must already exist when opening a context. `fs` and `exec` operate with the
selected target account's permissions. Long-running commands return a process
handle rather than occupying one HTTP request indefinitely.

If an operation requires a higher operating-system identity, stop the MCP
operation and present the exact command and reason to the user. The user may run
it directly in Terminal. Do not request, transmit, paste, store, or inspect the
system password through DevSpace.

## Deployment

The production transaction:

1. verifies a clean, pushed revision;
2. runs typecheck, tests, build, budgets, load, and package checks;
3. backs up OAuth state, routes, environment, PM2, and public ingress;
4. starts v2 on a blue/green local port;
5. runs authenticated local canaries;
6. switches the public route;
7. runs public canaries;
8. rehearses rollback to legacy and back to v2;
9. records cutover evidence.

No system-password or elevation setup is part of deployment.

## Logs and lifecycle

PM2 log rotation is configured separately and bounded. Temporary OAuth clients,
artifacts, test files, process outputs, context worktrees, status relays, and
verification servers are removed after use. Release gates reject test fixtures,
temporary files, and elevation components in `dist` or the npm package.

## Failure handling

- Preserve the first failing boundary and operation ID.
- Do not repeat an identical failed request.
- Do not replay a command or external mutation after possible dispatch.
- Roll back the public route and OAuth database from the captured transaction
  when cutover canaries fail.
- Leave existing production active when v2 evidence is incomplete.
