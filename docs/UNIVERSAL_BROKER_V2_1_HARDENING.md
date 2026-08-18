# Universal Broker v2.1 P0 Hardening Record

## Decision

The fixed eight-tool Universal Broker architecture remains authoritative. v2.1
closes four production control-plane gaps without restoring administrator
free-pass mode or adding service-specific tools.

## Closed gaps

| Gap | v2.1 control |
|---|---|
| Mutating operations shared one broad tool contract | Exact R0–R3 authority records under `context` |
| No-elevation was primarily a packaging assertion | Runtime macOS/Linux/Windows enforcement and truthful probes |
| Broker restart destroyed its own response channel | Durable detached restart transaction under `process` |
| Migration blanket OAuth scope remained enabled | Granular scopes plus `offline_access`; legacy scope rejected |
| Reverse proxy made public metrics look local | Socket and Host must both be loopback-local |
| Target or route configuration changed after authorization | Exact target generation and route fingerprint binding |
| Candidate validation reused production OAuth state | Isolated candidate OAuth database and explicit production OAuth handoff |
| Downstream stdio MCP child escaped the execution wrapper | Local/SSH stdio providers inherit no-elevation enforcement |

## Preserved properties

- top-level tools remain exactly eight;
- context remains a workflow hint rather than a filesystem sandbox;
- no system password or privileged helper exists;
- large output remains behind bounded resources;
- unknown dispatch is never automatically replayed;
- new targets and MCP services remain configuration data.

## Required production evidence

A release is not complete until code tests, deterministic/full/real load,
package scans, granular OAuth, public metrics denial, R0–R3 canaries,
no-elevation canaries, durable restart readback, exact PM2/release state, and
canonical connector reconnect all PASS from the same source revision.

## Dependency boundary

The production dependency graph is audited during every release. v2.1 updates
`pi-coding-agent` to 0.84.2 and pins patched same-major transitive versions for
Hono, body-parser, brace-expansion, fast-uri, ip-address, protobufjs, and
undici. A low-or-higher production advisory blocks release verification.
