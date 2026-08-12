import type {
  DevspaceRemoteMcpShortcutRouteConfig,
  DevspaceShortcutsConfig,
} from "../user-config.js";

export interface RemoteMcpShortcutRouteConfig {
  transport: "ssh-stdio";
  host: string;
  command: string;
  args: string[];
  env: Record<string, string>;
  allowedTools: string[];
  toolDefaults: Record<string, Record<string, unknown>>;
  startupTimeoutSeconds: number;
  callTimeoutSeconds: number;
}

export interface ShortcutConfig {
  browserRead: { enabled: boolean };
  remoteMcpRead: {
    enabled: boolean;
    routes: Record<string, RemoteMcpShortcutRouteConfig>;
  };
  jiraLookup: {
    enabled: boolean;
    route?: string;
  };
}

const MUTATION_TOOL_PREFIX = /^(?:create|update|edit|delete|remove|comment|transition|assign|add|send|publish|deploy|move|write|set|upload|attach|close|merge|push|submit)/i;

export function parseShortcutConfig(
  value: DevspaceShortcutsConfig | undefined,
  env: NodeJS.ProcessEnv,
): ShortcutConfig {
  const source: DevspaceShortcutsConfig = value ?? {};
  assertPlainObject(source, "shortcuts");
  assertOptionalPlainObject(source.browserRead, "shortcuts.browserRead");
  assertOptionalPlainObject(source.remoteMcpRead, "shortcuts.remoteMcpRead");
  assertOptionalPlainObject(source.jiraLookup, "shortcuts.jiraLookup");
  const browserRead = source.browserRead as DevspaceShortcutsConfig["browserRead"];
  const remoteMcpRead = source.remoteMcpRead as DevspaceShortcutsConfig["remoteMcpRead"];
  const jiraLookup = source.jiraLookup as DevspaceShortcutsConfig["jiraLookup"];

  const routes = parseRemoteRoutes(remoteMcpRead?.routes);
  const browserReadEnabled = parseEnabled(
    env.DEVSPACE_SHORTCUT_BROWSER_READ_ENABLED,
    browserRead?.enabled,
    false,
    "DEVSPACE_SHORTCUT_BROWSER_READ_ENABLED",
  );
  const remoteMcpReadEnabled = parseEnabled(
    env.DEVSPACE_SHORTCUT_REMOTE_MCP_READ_ENABLED,
    remoteMcpRead?.enabled,
    false,
    "DEVSPACE_SHORTCUT_REMOTE_MCP_READ_ENABLED",
  );
  const jiraLookupEnabled = parseEnabled(
    env.DEVSPACE_SHORTCUT_JIRA_LOOKUP_ENABLED,
    jiraLookup?.enabled,
    false,
    "DEVSPACE_SHORTCUT_JIRA_LOOKUP_ENABLED",
  );

  if (remoteMcpReadEnabled && Object.keys(routes).length === 0) {
    throw new Error("shortcuts.remoteMcpRead requires at least one route when enabled.");
  }

  const requestedJiraRoute = (
    env.DEVSPACE_SHORTCUT_JIRA_LOOKUP_ROUTE
    ?? jiraLookup?.route
  )?.trim();
  const jiraRoute = requestedJiraRoute || inferJiraRoute(routes);
  if (jiraLookupEnabled) {
    if (!jiraRoute) {
      throw new Error(
        "shortcuts.jiraLookup requires a route when multiple or no remote MCP routes are configured.",
      );
    }
    const route = routes[jiraRoute];
    if (!route) {
      throw new Error(`shortcuts.jiraLookup references unknown route ${jiraRoute}.`);
    }
    for (const tool of ["searchJiraIssuesUsingJql", "getJiraIssue"]) {
      if (!route.allowedTools.includes(tool)) {
        throw new Error(`shortcuts.jiraLookup route ${jiraRoute} must allow ${tool}.`);
      }
    }
  }

  return {
    browserRead: { enabled: browserReadEnabled },
    remoteMcpRead: { enabled: remoteMcpReadEnabled, routes },
    jiraLookup: {
      enabled: jiraLookupEnabled,
      ...(jiraRoute ? { route: jiraRoute } : {}),
    },
  };
}

export function isReadOnlyRemoteToolName(name: string): boolean {
  return !MUTATION_TOOL_PREFIX.test(name);
}

function parseRemoteRoutes(
  value: Record<string, DevspaceRemoteMcpShortcutRouteConfig> | undefined,
): Record<string, RemoteMcpShortcutRouteConfig> {
  if (value === undefined) return {};
  assertPlainObject(value, "shortcuts.remoteMcpRead.routes");
  const routes: Record<string, RemoteMcpShortcutRouteConfig> = {};

  for (const [rawName, rawRoute] of Object.entries(value)) {
    const name = rawName.trim();
    if (!/^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/.test(name)) {
      throw new Error(`Invalid shortcut remote MCP route name: ${rawName}.`);
    }
    assertPlainObject(rawRoute, `shortcuts.remoteMcpRead.routes.${name}`);
    const host = requiredSafeString(rawRoute.host, `shortcuts.remoteMcpRead.routes.${name}.host`);
    if (!/^[A-Za-z0-9_.@:-]+$/.test(host) || host.startsWith("-")) {
      throw new Error(`Shortcut remote MCP route ${name} has unsafe SSH host ${host}.`);
    }
    if (rawRoute.transport !== undefined && rawRoute.transport !== "ssh-stdio") {
      throw new Error(`Shortcut remote MCP route ${name} has unsupported transport ${String(rawRoute.transport)}.`);
    }
    const command = requiredSafeString(
      rawRoute.command,
      `shortcuts.remoteMcpRead.routes.${name}.command`,
    );
    const args = parseStringArray(rawRoute.args ?? [], `shortcuts.remoteMcpRead.routes.${name}.args`);
    const allowedTools = Array.from(new Set(
      parseStringArray(
        rawRoute.allowedTools,
        `shortcuts.remoteMcpRead.routes.${name}.allowedTools`,
      ).map((tool) => tool.trim()).filter(Boolean),
    ));
    if (allowedTools.length === 0) {
      throw new Error(`Shortcut remote MCP route ${name} requires at least one allowed tool.`);
    }
    const mutationTool = allowedTools.find((tool) => !isReadOnlyRemoteToolName(tool));
    if (mutationTool) {
      throw new Error(`Shortcut remote MCP route ${name} cannot allow mutation-shaped tool ${mutationTool}.`);
    }

    const env = parseEnvironment(rawRoute.env, name);
    const toolDefaults = parseToolDefaults(rawRoute.toolDefaults, name, allowedTools);
    routes[name] = {
      transport: "ssh-stdio",
      host,
      command,
      args,
      env,
      allowedTools,
      toolDefaults,
      startupTimeoutSeconds: positiveInteger(
        rawRoute.startupTimeoutSeconds,
        45,
        `shortcuts.remoteMcpRead.routes.${name}.startupTimeoutSeconds`,
      ),
      callTimeoutSeconds: positiveInteger(
        rawRoute.callTimeoutSeconds,
        60,
        `shortcuts.remoteMcpRead.routes.${name}.callTimeoutSeconds`,
      ),
    };
  }

  return routes;
}

function parseEnvironment(
  value: Record<string, string> | undefined,
  route: string,
): Record<string, string> {
  if (value === undefined) return {};
  assertPlainObject(value, `shortcuts.remoteMcpRead.routes.${route}.env`);
  return Object.fromEntries(Object.entries(value).map(([key, entry]) => {
    if (!/^[A-Za-z_][A-Za-z0-9_]*$/.test(key)) {
      throw new Error(`Shortcut remote MCP route ${route} has invalid environment key ${key}.`);
    }
    if (typeof entry !== "string") {
      throw new Error(`Shortcut remote MCP route ${route} environment value ${key} must be a string.`);
    }
    return [key, entry];
  }));
}

function parseToolDefaults(
  value: Record<string, Record<string, unknown>> | undefined,
  route: string,
  allowedTools: string[],
): Record<string, Record<string, unknown>> {
  if (value === undefined) return {};
  assertPlainObject(value, `shortcuts.remoteMcpRead.routes.${route}.toolDefaults`);
  return Object.fromEntries(Object.entries(value).map(([tool, defaults]) => {
    if (!allowedTools.includes(tool)) {
      throw new Error(`Shortcut remote MCP route ${route} has defaults for non-allowlisted tool ${tool}.`);
    }
    assertPlainObject(defaults, `shortcuts.remoteMcpRead.routes.${route}.toolDefaults.${tool}`);
    return [tool, defaults];
  }));
}

function parseEnabled(
  envValue: string | undefined,
  fileValue: boolean | undefined,
  fallback: boolean,
  name: string,
): boolean {
  if (envValue !== undefined) {
    const normalized = envValue.trim().toLowerCase();
    if (["1", "true", "yes", "on"].includes(normalized)) return true;
    if (["0", "false", "no", "off"].includes(normalized)) return false;
    throw new Error(`Invalid ${name}: ${envValue}`);
  }
  if (fileValue === undefined) return fallback;
  if (typeof fileValue !== "boolean") throw new Error(`Invalid ${name} in shortcuts config.`);
  return fileValue;
}

function inferJiraRoute(
  routes: Record<string, RemoteMcpShortcutRouteConfig>,
): string | undefined {
  if (routes["company-jira"]) return "company-jira";
  const names = Object.keys(routes);
  return names.length === 1 ? names[0] : undefined;
}

function assertOptionalPlainObject(value: unknown, name: string): void {
  if (value !== undefined) assertPlainObject(value, name);
}

function assertPlainObject(value: unknown, name: string): asserts value is Record<string, unknown> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw new Error(`${name} must be an object.`);
  }
}

function requiredSafeString(value: unknown, name: string): string {
  if (typeof value !== "string" || !value.trim()) throw new Error(`${name} is required.`);
  if (/\0|\r|\n/.test(value)) throw new Error(`${name} contains invalid control characters.`);
  return value.trim();
}

function parseStringArray(value: unknown, name: string): string[] {
  if (!Array.isArray(value) || value.some((entry) => typeof entry !== "string")) {
    throw new Error(`${name} must be an array of strings.`);
  }
  for (const entry of value) {
    if (/\0|\r|\n/.test(entry)) throw new Error(`${name} contains invalid control characters.`);
  }
  return value.slice();
}

function positiveInteger(value: unknown, fallback: number, name: string): number {
  if (value === undefined) return fallback;
  if (!Number.isInteger(value) || (value as number) < 1 || (value as number) > 300) {
    throw new Error(`${name} must be an integer between 1 and 300.`);
  }
  return value as number;
}
