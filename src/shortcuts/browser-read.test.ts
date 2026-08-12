import assert from "node:assert/strict";
import test from "node:test";
import { BrowserReadService } from "./browser-read.js";
import { BrowserReadError, ChromeAdapter } from "./chrome-adapter.js";

function queuedRunner(outputs: string[]) {
  const scripts: string[] = [];
  return {
    scripts,
    run: async (script: string) => {
      scripts.push(script);
      const next = outputs.shift();
      if (next === undefined) throw new Error("Unexpected JXA call");
      return next;
    },
  };
}

test("browser shortcut lists tabs without model-supplied JavaScript", async () => {
  const runner = queuedRunner([JSON.stringify([
    { windowIndex: 1, tabIndex: 1, active: true, title: "One", url: "https://one.example/" },
  ])]);
  const service = new BrowserReadService(new ChromeAdapter(runner.run));
  const result = await service.execute({ operation: "list_tabs" });
  assert.equal(result.operation, "list_tabs");
  assert.equal(result.operation === "list_tabs" ? result.tabs.length : 0, 1);
  assert.match(runner.scripts[0] ?? "", /Application\("Google Chrome"\)/);
});

test("browser shortcut reads bounded exact matching lines", async () => {
  const runner = queuedRunner([
    JSON.stringify([
      { windowIndex: 1, tabIndex: 2, active: true, title: "Jira", url: "https://chatgpt.com/c/example" },
    ]),
    JSON.stringify({
      title: "Jira",
      url: "https://chatgpt.com/c/example",
      selector: "main",
      text: "OMNIBESU-547 진행중",
      matchedLines: ["OMNIBESU-547 진행중"],
      truncated: false,
    }),
  ]);
  const service = new BrowserReadService(new ChromeAdapter(runner.run));
  const result = await service.execute({
    operation: "read_page",
    selector: "main",
    matchText: "OMNIBESU-547",
    maxCharacters: 1_000,
  });
  assert.equal(result.operation, "read_page");
  if (!("page" in result)) assert.fail("unexpected tabs result");
  assert.deepEqual(result.page.matchedLines, ["OMNIBESU-547 진행중"]);
  assert.equal(result.page.text, "OMNIBESU-547 진행중");
  assert.match(runner.scripts[1] ?? "", /allMatches/);
});

test("browser shortcut rejects non-HTTP navigation and missing selectors", async () => {
  const adapter = new ChromeAdapter(async () => "unused");
  const service = new BrowserReadService(adapter);
  await assert.rejects(
    service.execute({ operation: "open_url", url: "file:///etc/passwd", waitMs: 0 }),
    /only opens HTTP or HTTPS URLs/,
  );

  const runner = queuedRunner([
    JSON.stringify([{ windowIndex: 1, tabIndex: 1, active: true, title: "Page", url: "https://example.com/" }]),
    JSON.stringify({ error: "selector-not-found", selector: "#missing" }),
  ]);
  await assert.rejects(
    new BrowserReadService(new ChromeAdapter(runner.run)).execute({
      operation: "read_page",
      selector: "#missing",
    }),
    (error: unknown) => error instanceof BrowserReadError && /selector was not found/.test(error.message),
  );
});
