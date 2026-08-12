import { execFile } from "node:child_process";
import { promisify } from "node:util";

const execFileAsync = promisify(execFile);

export interface BrowserTabSummary {
  windowIndex: number;
  tabIndex: number;
  active: boolean;
  title: string;
  url: string;
}

export interface BrowserPageReadback {
  windowIndex: number;
  tabIndex: number;
  title: string;
  url: string;
  selector: string;
  text: string;
  matchedLines?: string[];
  truncated: boolean;
}

export interface BrowserPageRequest {
  windowIndex: number;
  tabIndex: number;
  selector: string;
  maxCharacters: number;
  matchText?: string;
}

export interface BrowserReadAdapter {
  listTabs(): Promise<BrowserTabSummary[]>;
  readPage(input: BrowserPageRequest): Promise<BrowserPageReadback>;
  openUrl(url: string): Promise<void>;
}

export class ChromeAdapter implements BrowserReadAdapter {
  constructor(
    private readonly runJxa: (script: string) => Promise<string> = runChromeJxa,
  ) {}

  async listTabs(): Promise<BrowserTabSummary[]> {
    const output = await this.runJxa(`
const chrome = Application("Google Chrome");
const tabs = [];
if (chrome.running()) {
  chrome.windows().forEach((window, windowOffset) => {
    const active = window.activeTabIndex();
    window.tabs().forEach((tab, tabOffset) => {
      tabs.push({
        windowIndex: windowOffset + 1,
        tabIndex: tabOffset + 1,
        active: active === tabOffset + 1,
        title: String(tab.title() || ""),
        url: String(tab.url() || ""),
      });
    });
  });
}
JSON.stringify(tabs);
`);
    return parseJson<BrowserTabSummary[]>(output, "Chrome tab list");
  }

  async readPage(input: BrowserPageRequest): Promise<BrowserPageReadback> {
    const browserScript = `(() => {
  const selector = ${JSON.stringify(input.selector)};
  const maxCharacters = ${input.maxCharacters};
  const matchText = ${JSON.stringify(input.matchText ?? null)};
  const element = document.querySelector(selector);
  if (!element) return JSON.stringify({ error: "selector-not-found", selector });
  const fullText = String(element.innerText || element.textContent || "");
  if (matchText) {
    const allMatches = fullText.split(/\\r?\\n/).filter((line) => line.includes(matchText));
    const matchedLines = [];
    let usedCharacters = 0;
    let lineTruncated = false;
    for (const line of allMatches) {
      if (matchedLines.length >= 200) break;
      const separatorCharacters = matchedLines.length === 0 ? 0 : 1;
      const remaining = maxCharacters - usedCharacters - separatorCharacters;
      if (remaining <= 0) break;
      const boundedLine = line.slice(0, remaining);
      matchedLines.push(boundedLine);
      usedCharacters += separatorCharacters + boundedLine.length;
      if (boundedLine.length < line.length) {
        lineTruncated = true;
        break;
      }
    }
    return JSON.stringify({
      title: document.title,
      url: location.href,
      selector,
      text: matchedLines.join("\\n"),
      matchedLines,
      truncated: lineTruncated || allMatches.length > matchedLines.length,
    });
  }
  const text = fullText.slice(0, maxCharacters);
  return JSON.stringify({
    title: document.title,
    url: location.href,
    selector,
    text,
    truncated: fullText.length > text.length,
  });
})()`;
    const output = await this.runJxa(`
const chrome = Application("Google Chrome");
if (!chrome.running()) throw new Error("Google Chrome is not running.");
const windows = chrome.windows();
const window = windows[${input.windowIndex - 1}];
if (!window) throw new Error("Chrome window ${input.windowIndex} does not exist.");
const tab = window.tabs()[${input.tabIndex - 1}];
if (!tab) throw new Error("Chrome tab ${input.windowIndex}:${input.tabIndex} does not exist.");
tab.execute({ javascript: ${JSON.stringify(browserScript)} });
`);
    const parsed = parseJson<Record<string, unknown>>(output, "Chrome page readback");
    if (parsed.error === "selector-not-found") {
      throw new BrowserReadError(`Chrome page selector was not found: ${input.selector}`);
    }
    const matchedLines = Array.isArray(parsed.matchedLines)
      ? parsed.matchedLines.filter((line): line is string => typeof line === "string")
      : undefined;
    return {
      windowIndex: input.windowIndex,
      tabIndex: input.tabIndex,
      title: typeof parsed.title === "string" ? parsed.title : "",
      url: typeof parsed.url === "string" ? parsed.url : "",
      selector: input.selector,
      text: typeof parsed.text === "string" ? parsed.text : "",
      matchedLines,
      truncated: parsed.truncated === true,
    };
  }

  async openUrl(url: string): Promise<void> {
    await this.runJxa(`
const chrome = Application("Google Chrome");
chrome.activate();
chrome.openLocation(${JSON.stringify(url)});
"opened";
`);
  }
}

export class BrowserReadError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "BrowserReadError";
  }
}

async function runChromeJxa(script: string): Promise<string> {
  if (process.platform !== "darwin") {
    throw new BrowserReadError("browser_read_shortcut currently supports macOS Google Chrome only.");
  }
  try {
    const { stdout, stderr } = await execFileAsync(
      "/usr/bin/osascript",
      ["-l", "JavaScript", "-e", script],
      { encoding: "utf8", maxBuffer: 2 * 1024 * 1024 },
    );
    if (stderr.trim()) throw new BrowserReadError(stderr.trim());
    return stdout.trim();
  } catch (error) {
    if (error instanceof BrowserReadError) throw error;
    throw new BrowserReadError(error instanceof Error ? error.message : String(error));
  }
}

function parseJson<T>(value: string, label: string): T {
  try {
    return JSON.parse(value) as T;
  } catch (error) {
    throw new BrowserReadError(
      `${label} returned invalid JSON: ${error instanceof Error ? error.message : String(error)}`,
    );
  }
}
