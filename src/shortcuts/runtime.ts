import type { ShortcutConfig } from "./config.js";
import { BrowserReadService } from "./browser-read.js";
import { ChromeAdapter, type BrowserReadAdapter } from "./chrome-adapter.js";
import { JiraLookupService } from "./jira-lookup.js";
import {
  RemoteMcpReader,
  type RemoteMcpSessionFactory,
} from "./remote-mcp-read.js";

export interface ShortcutRuntime {
  config: ShortcutConfig;
  browser: BrowserReadService;
  remoteMcp: RemoteMcpReader;
  jira?: JiraLookupService;
  close(): Promise<void>;
}

export interface ShortcutRuntimeOptions {
  browserAdapter?: BrowserReadAdapter;
  remoteSessionFactory?: RemoteMcpSessionFactory;
}

export function createShortcutRuntime(
  config: ShortcutConfig,
  options: ShortcutRuntimeOptions = {},
): ShortcutRuntime {
  const remoteMcp = new RemoteMcpReader(
    config.remoteMcpRead.routes,
    options.remoteSessionFactory,
  );
  let closePromise: Promise<void> | undefined;
  return {
    config,
    browser: new BrowserReadService(options.browserAdapter ?? new ChromeAdapter()),
    remoteMcp,
    jira: config.jiraLookup.route
      ? new JiraLookupService(config.jiraLookup.route, remoteMcp)
      : undefined,
    close() {
      closePromise ??= remoteMcp.close();
      return closePromise;
    },
  };
}
