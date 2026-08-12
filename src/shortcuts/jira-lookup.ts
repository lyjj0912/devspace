import { remoteToolText, type RemoteMcpReadResult } from "./remote-mcp-read.js";

export interface JiraLookupInput {
  jql?: string;
  issueKey?: string;
  cloudId?: string;
  fields?: string[];
  maxResults?: number;
  includeDetails?: boolean;
}

export interface JiraIssueSummary {
  id?: string;
  key?: string;
  summary?: string;
  status?: string;
  updated?: string;
  assignee?: string;
  reporter?: string;
  description?: string;
  requestedFields?: Record<string, unknown>;
}

export interface JiraLookupResult {
  route: string;
  mode: "search" | "issue";
  issues: JiraIssueSummary[];
  providerCalls: number;
  connectionReused: boolean;
  retried: boolean;
  truncated: boolean;
}

export interface RemoteReadClient {
  invoke(
    route: string,
    tool?: string,
    args?: Record<string, unknown>,
  ): Promise<RemoteMcpReadResult>;
}

const DEFAULT_FIELDS = ["summary", "status", "updated", "assignee", "reporter"];

export class JiraLookupError extends Error {
  constructor(message: string, readonly code = "JIRA_LOOKUP_FAILED") {
    super(message);
    this.name = "JiraLookupError";
  }
}

export class JiraLookupService {
  constructor(
    private readonly route: string,
    private readonly remote: RemoteReadClient,
  ) {}

  async lookup(input: JiraLookupInput): Promise<JiraLookupResult> {
    const jql = input.jql?.trim();
    const issueKey = input.issueKey?.trim();
    if (Boolean(jql) === Boolean(issueKey)) {
      throw new JiraLookupError("jira_lookup_shortcut requires exactly one of jql or issueKey.");
    }
    const fields = input.fields?.map((field) => field.trim()).filter(Boolean) ?? DEFAULT_FIELDS;
    const baseArgs = input.cloudId?.trim() ? { cloudId: input.cloudId.trim() } : {};

    if (issueKey) {
      const detail = await this.remote.invoke(this.route, "getJiraIssue", {
        ...baseArgs,
        issueIdOrKey: issueKey,
        fields,
        responseContentFormat: "markdown",
        updateHistory: false,
      });
      const summarized = summarizeIssue(parseRemoteJson(detail, "getJiraIssue"), fields);
      return {
        route: this.route,
        mode: "issue",
        issues: summarized.issue.key || summarized.issue.id ? [summarized.issue] : [],
        providerCalls: detail.providerCalls,
        connectionReused: detail.connectionReused,
        retried: detail.retried,
        truncated: summarized.truncated,
      };
    }

    const search = await this.remote.invoke(this.route, "searchJiraIssuesUsingJql", {
      ...baseArgs,
      jql,
      maxResults: clamp(input.maxResults ?? 50, 1, 100),
      fields,
      responseContentFormat: "markdown",
      searchResultMode: "issues",
    });
    const searchResponse = parseRemoteJson(search, "searchJiraIssuesUsingJql");
    const summaries = recordArray(searchResponse, "issues").map((issue) => summarizeIssue(issue, fields));
    let issues = summaries.map((summary) => summary.issue).filter((issue) => issue.key || issue.id);
    let providerCalls = search.providerCalls;
    let connectionReused = search.connectionReused;
    let retried = search.retried;
    let truncated = summaries.some((summary) => summary.truncated);

    if ((input.includeDetails ?? true) && issues.length === 1 && issues[0]?.key) {
      const detail = await this.remote.invoke(this.route, "getJiraIssue", {
        ...baseArgs,
        issueIdOrKey: issues[0].key,
        fields,
        responseContentFormat: "markdown",
        updateHistory: false,
      });
      const summarized = summarizeIssue(parseRemoteJson(detail, "getJiraIssue"), fields);
      issues = summarized.issue.key || summarized.issue.id ? [summarized.issue] : [];
      providerCalls += detail.providerCalls;
      connectionReused ||= detail.connectionReused;
      retried ||= detail.retried;
      truncated ||= summarized.truncated;
    }

    return {
      route: this.route,
      mode: "search",
      issues,
      providerCalls,
      connectionReused,
      retried,
      truncated,
    };
  }
}

function parseRemoteJson(result: RemoteMcpReadResult, tool: string): unknown {
  const payload = remoteToolText(result.response, 100_000);
  if (!payload.text) throw new JiraLookupError(`${tool} returned no text payload.`);
  if (payload.truncated) {
    throw new JiraLookupError(`${tool} returned a response larger than the 100000 character parse limit.`);
  }
  try {
    return JSON.parse(payload.text) as unknown;
  } catch (error) {
    throw new JiraLookupError(
      `${tool} returned non-JSON text: ${error instanceof Error ? error.message : String(error)}`,
    );
  }
}

function summarizeIssue(
  value: unknown,
  requestedFieldNames: string[],
): { issue: JiraIssueSummary; truncated: boolean } {
  if (typeof value !== "object" || value === null) return { issue: {}, truncated: false };
  const record = value as Record<string, unknown>;
  const fields = typeof record.fields === "object" && record.fields !== null
    ? record.fields as Record<string, unknown>
    : record;
  const coreFields = new Set(["summary", "description", "status", "updated", "assignee", "reporter"]);
  let truncated = false;
  const requestedFields = Object.fromEntries(requestedFieldNames
    .filter((field) => !coreFields.has(field) && field in fields)
    .map((field) => {
      const compact = compactFieldValue(fields[field]);
      truncated ||= compact.truncated;
      return [field, compact.value];
    }));
  const description = requestedFieldNames.includes("description")
    ? compactText(fields.description)
    : { value: undefined, truncated: false };
  truncated ||= description.truncated;
  return {
    issue: {
      id: stringValue(record.id),
      key: stringValue(record.key) ?? stringValue(record.issueKey),
      summary: stringValue(fields.summary),
      status: nestedString(fields.status, "name") ?? stringValue(fields.status),
      updated: stringValue(fields.updated),
      assignee: nestedString(fields.assignee, "displayName") ?? stringValue(fields.assignee),
      reporter: nestedString(fields.reporter, "displayName") ?? stringValue(fields.reporter),
      description: description.value,
      requestedFields: Object.keys(requestedFields).length > 0 ? requestedFields : undefined,
    },
    truncated,
  };
}

function compactText(value: unknown): { value?: string; truncated: boolean } {
  if (value === undefined || value === null) return { value: undefined, truncated: false };
  const text = typeof value === "string" ? value : JSON.stringify(value);
  return text.length > 20_000
    ? { value: `${text.slice(0, 20_000)}…`, truncated: true }
    : { value: text, truncated: false };
}

function compactFieldValue(value: unknown): { value: unknown; truncated: boolean } {
  if (value === null || typeof value === "number" || typeof value === "boolean") {
    return { value, truncated: false };
  }
  const compact = compactText(value);
  return { value: compact.value, truncated: compact.truncated };
}

function recordArray(value: unknown, key: string): Record<string, unknown>[] {
  if (typeof value !== "object" || value === null) return [];
  const entries = (value as Record<string, unknown>)[key];
  return Array.isArray(entries)
    ? entries.filter((entry): entry is Record<string, unknown> => typeof entry === "object" && entry !== null)
    : [];
}

function nestedString(value: unknown, key: string): string | undefined {
  return typeof value === "object" && value !== null
    ? stringValue((value as Record<string, unknown>)[key])
    : undefined;
}

function stringValue(value: unknown): string | undefined {
  return typeof value === "string" && value.length > 0 ? value : undefined;
}

function clamp(value: number, minimum: number, maximum: number): number {
  return Math.min(Math.max(Math.trunc(value), minimum), maximum);
}
