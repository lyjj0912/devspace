import {
  BrowserReadError,
  type BrowserPageReadback,
  type BrowserReadAdapter,
  type BrowserTabSummary,
} from "./chrome-adapter.js";

export type BrowserReadOperation = "list_tabs" | "read_page" | "open_url";

export interface BrowserReadInput {
  operation: BrowserReadOperation;
  windowIndex?: number;
  tabIndex?: number;
  url?: string;
  selector?: string;
  maxCharacters?: number;
  matchText?: string;
  waitMs?: number;
}

export type BrowserReadResult =
  | { operation: "list_tabs"; tabs: BrowserTabSummary[]; truncated: false }
  | { operation: "read_page" | "open_url"; page: BrowserPageReadback; truncated: boolean };

export class BrowserReadService {
  constructor(private readonly adapter: BrowserReadAdapter) {}

  async execute(input: BrowserReadInput): Promise<BrowserReadResult> {
    switch (input.operation) {
      case "list_tabs":
        return { operation: "list_tabs", tabs: await this.adapter.listTabs(), truncated: false };
      case "read_page": {
        const page = await this.readPage(input);
        return { operation: "read_page", page, truncated: page.truncated };
      }
      case "open_url": {
        const url = parseHttpUrl(input.url);
        await this.adapter.openUrl(url);
        await delay(clamp(input.waitMs ?? 1_000, 0, 5_000));
        const tabs = await this.adapter.listTabs();
        const target = tabs.find((tab) => tab.active && tab.url === url)
          ?? [...tabs].reverse().find((tab) => tab.url === url)
          ?? tabs.find((tab) => tab.active);
        if (!target) throw new BrowserReadError("Chrome did not expose a tab after opening the URL.");
        const page = await this.readPage({
          ...input,
          operation: "read_page",
          windowIndex: target.windowIndex,
          tabIndex: target.tabIndex,
        });
        return { operation: "open_url", page, truncated: page.truncated };
      }
    }
  }

  private async readPage(input: BrowserReadInput): Promise<BrowserPageReadback> {
    const tabs = await this.adapter.listTabs();
    if (tabs.length === 0) throw new BrowserReadError("Google Chrome has no open tabs.");
    const target = resolveTarget(tabs, input.windowIndex, input.tabIndex);
    return this.adapter.readPage({
      windowIndex: target.windowIndex,
      tabIndex: target.tabIndex,
      selector: input.selector?.trim() || "body",
      maxCharacters: clamp(input.maxCharacters ?? 20_000, 1, 100_000),
      ...(input.matchText?.trim() ? { matchText: input.matchText.trim() } : {}),
    });
  }
}

function resolveTarget(
  tabs: BrowserTabSummary[],
  windowIndex?: number,
  tabIndex?: number,
): BrowserTabSummary {
  if (windowIndex === undefined && tabIndex === undefined) {
    return tabs.find((tab) => tab.active) ?? tabs[0]!;
  }
  const resolvedWindow = windowIndex ?? tabs.find((tab) => tab.active)?.windowIndex ?? 1;
  const resolvedTab = tabIndex
    ?? tabs.find((tab) => tab.windowIndex === resolvedWindow && tab.active)?.tabIndex
    ?? 1;
  const target = tabs.find(
    (tab) => tab.windowIndex === resolvedWindow && tab.tabIndex === resolvedTab,
  );
  if (!target) throw new BrowserReadError(`Chrome tab ${resolvedWindow}:${resolvedTab} does not exist.`);
  return target;
}

function parseHttpUrl(value: string | undefined): string {
  const raw = value?.trim();
  if (!raw) throw new BrowserReadError("open_url requires url.");
  let url: URL;
  try {
    url = new URL(raw);
  } catch {
    throw new BrowserReadError(`Invalid browser URL: ${raw}`);
  }
  if (url.protocol !== "http:" && url.protocol !== "https:") {
    throw new BrowserReadError("browser_read_shortcut only opens HTTP or HTTPS URLs.");
  }
  return url.toString();
}

function clamp(value: number, minimum: number, maximum: number): number {
  return Math.min(Math.max(Math.trunc(value), minimum), maximum);
}

function delay(milliseconds: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, milliseconds));
}
