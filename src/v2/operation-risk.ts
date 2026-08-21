import type { AuthorityRiskClass, UniversalToolName } from "./contracts.js";

/**
 * Personal Direct Owner audit classification. This is observability metadata, not an authority
 * engine: OAuth scopes and the configured OS/SSH account remain the execution boundary.
 */
export function personalOperationRisk(
  tool: UniversalToolName,
  operation: string,
  input: unknown,
): AuthorityRiskClass {
  switch (tool) {
    case "target":
      return "R0";
    case "context":
      if (["search", "diff"].includes(operation)) return "R0";
      if (operation === "open" && record(input)?.mode === "worktree") return "R2";
      return "R1";
    case "fs":
      if (["stat", "list", "read", "search", "hash"].includes(operation)) return "R0";
      if (operation === "sync" && record(record(input)?.sync)?.phase === "plan") return "R0";
      if (operation === "remove" && record(input)?.disposition === "permanent") return "R3";
      return ["move", "remove", "sync"].includes(operation) ? "R2" : "R1";
    case "exec":
      return "R2";
    case "process":
      if (["poll", "wait", "list", "restart_status"].includes(operation)) return "R0";
      if (operation === "restart_broker") return "R3";
      return operation === "signal" ? "R2" : "R1";
    case "mcp":
      if ([
        "routes",
        "search_tools",
        "describe_tool",
        "list_resources",
        "read_resource",
        "list_prompts",
        "get_prompt",
      ].includes(operation)) return "R0";
      return operation === "close" ? "R1" : "R2";
    case "artifact":
      return operation === "publish" ? "R1" : "R2";
    case "gui":
      return operation === "act" ? "R2" : "R0";
  }
}

function record(value: unknown): Record<string, unknown> | undefined {
  return value && typeof value === "object" && !Array.isArray(value)
    ? value as Record<string, unknown>
    : undefined;
}
