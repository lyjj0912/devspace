# Universal Broker v2 — Phase 6 Completion Evidence

Date: 2026-08-15 KST

Input commit: `15eb481e0c8ded479cfbe78db74fbf68a993dc75`

Branch: `feat/universal-broker-v2-phase6-generic-mcp-20260815`

## Delivered contract

The existing top-level `mcp` tool now provides:

```text
routes search_tools describe_tool invoke
list_resources read_resource list_prompts get_prompt close
```

Supported downstream transports:

```text
local-stdio
ssh-stdio
streamable-http
```

No Jira-, Chrome-, database-, email-, or provider-specific top-level tool was
added. Downstream integrations are object-form records in the machine route
registry.

## Discovery and schema control

- Route IDs, display names, and aliases resolve exactly.
- Ambiguous aliases fail with authoritative candidates.
- Route files hot reload by content hash.
- `search_tools` returns at most five ranked candidates.
- `describe_tool` returns one exact downstream schema.
- Complete schemas from all routes are never injected into the host tool list.
- Route fingerprint changes replace a pooled downstream session.

## Mutation and retry contract

- Read, write, and destructive tools use the same `mcp.invoke` operation.
- There is no English tool-name mutation denylist.
- Provider-declared errors become `MCP_PROVIDER_ERROR`.
- A transport failure after dispatch becomes `MCP_RESULT_UNKNOWN`.
- The post-dispatch fixture counted exactly one provider call; retry count was
  zero.

## Result resource contract

Large provider responses are bounded by `maxCharacters` and `maxItems`.
Optional JSON-pointer projection is supported. The complete result is retained,
when requested, in an LRU/TTL/character-quota store and exposed through:

```text
devspace://mcp-result/{resultId}/{offset}/{limit}
```

Paging and expiry were tested through both the proxy operation and a real MCP
resource template on `/mcp-next`.

## Deterministic fixture evidence

```text
local stdio discovery                           PASS
local stdio read                                PASS
local stdio write                               PASS
local stdio destructive delete                  PASS
Streamable HTTP discovery/invoke                PASS
resources and resource templates                PASS
resource read                                   PASS
prompts and prompt retrieval                    PASS
large result resource paging                    PASS
provider-declared error                         PASS
post-dispatch retry count                       0 / PASS
route hot reload                                PASS
route selector collision rejection             PASS
unsafe public HTTP URL rejection                PASS
result TTL and LRU quotas                       PASS
authenticated top-level MCP proxy on /mcp-next  PASS
```

## Real company Jira canary

The existing production shortcut configuration was read without printing secret
values. Its environment was transferred temporarily to an owner-only file on
the company Mac. A generic `ssh-stdio` route sourced that remote file and
launched the existing Atlassian MCP.

Verified without Jira-specific proxy code:

```text
route resolve by alias                    PASS
search_tools                              PASS
describe getAccessibleAtlassianResources  PASS
invoke getAccessibleAtlassianResources    PASS
provider response                         PASS
```

The route exposed additional provider capabilities beyond the former three-tool
allowlist. No Jira mutation was performed. Temporary local and remote credential
files were removed; residue count was zero.

After the temporary canary passed, the machine route was installed as owner-only
runtime data:

```text
local route registry: ~/.devspace/mcp-routes.v2.json       mode 0600
remote credential file: ~/.config/devspace/mcp/company-jira.env mode 0600
```

The persistent route registry contains transport paths and aliases only. It does
not contain the provider environment map or credential-bearing values. A second
read-only invocation through the installed route passed.

## Quantitative gates

The top-level model contract remained unchanged:

```text
tools                         8 / limit 8
descriptor characters        7,585 / limit 12,000
server instruction chars       695 / limit 2,000
initial context chars         3,656 / limit 4,000
reused context chars            543 / limit 800
```

## Explicit deferred scope

- Public `/mcp-next` connector registration.
- Authenticated non-loopback Streamable HTTP credential provider.
- Cross-ChatGPT-session validation.
- Production cutover and legacy shortcut removal.
- Final credential rotation.

Production `/mcp`, PM2, OAuth state, and `src/server.ts` were not changed.
