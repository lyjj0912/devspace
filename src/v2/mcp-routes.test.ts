import assert from "node:assert/strict";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";
import { UniversalMcpRouteRegistry } from "./mcp-routes.js";

test("MCP route registry hot reloads object-form routes without schema changes", async (t) => {
  const root = await mkdtemp(join(tmpdir(), "devspace-v2-mcp-routes-"));
  t.after(() => rm(root, { recursive: true, force: true }));
  const path = join(root, "routes.json");
  await writeRoutes(path, {
    fixture: localRoute("Fixture", ["테스트"]),
  });
  const registry = new UniversalMcpRouteRegistry(path);
  const first = await registry.inspect();
  assert.equal((await registry.resolve("테스트")).id, "fixture");

  await writeRoutes(path, {
    fixture: localRoute("Fixture", ["테스트"]),
    second: localRoute("Second", ["두번째"]),
  });
  const second = await registry.inspect();
  assert.notEqual(first.generation, second.generation);
  assert.equal((await registry.resolve("두번째")).id, "second");
});

test("MCP route registry returns authoritative candidates and rejects unsafe routes", async (t) => {
  const root = await mkdtemp(join(tmpdir(), "devspace-v2-mcp-routes-"));
  t.after(() => rm(root, { recursive: true, force: true }));
  const path = join(root, "routes.json");
  await writeRoutes(path, {
    one: localRoute("One", ["shared"]),
    two: localRoute("Two", ["shared"]),
  });
  const ambiguous = new UniversalMcpRouteRegistry(path);
  await assert.rejects(ambiguous.inspect(), hasCode("PRECONDITION_FAILED"));

  await writeFile(path, JSON.stringify({
    version: 1,
    routes: {
      bad: {
        displayName: "Bad",
        transport: "streamable-http",
        url: "http://public.example.com/mcp",
      },
    },
  }));
  const unsafe = new UniversalMcpRouteRegistry(path);
  await assert.rejects(unsafe.inspect(), hasCode("PRECONDITION_FAILED"));
});

test("checked-in MCP route example satisfies the runtime registry", async () => {
  const path = fileURLToPath(new URL("../../examples/mcp-routes.v2.json", import.meta.url));
  const snapshot = await new UniversalMcpRouteRegistry(path).inspect();
  assert.deepEqual(
    snapshot.routes.map((route) => route.id),
    ["http-example", "local-example", "remote-example"],
  );
});

function localRoute(displayName: string, aliases: string[]) {
  return {
    displayName,
    aliases,
    transport: "local-stdio",
    command: process.execPath,
    args: ["--version"],
  };
}

async function writeRoutes(path: string, routes: Record<string, unknown>): Promise<void> {
  await writeFile(path, JSON.stringify({ version: 1, routes }, null, 2));
}

function hasCode(code: string) {
  return (error: unknown) => error instanceof Error && "code" in error && error.code === code;
}
