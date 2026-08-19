import assert from "node:assert/strict";
import { chmod, mkdtemp, rm, symlink, writeFile } from "node:fs/promises";
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

test("broker-owned MCP risk policy content is validated and changes route generation", async (t) => {
  const root = await mkdtemp(join(tmpdir(), "devspace-v2-mcp-policy-"));
  t.after(() => rm(root, { recursive: true, force: true }));
  const path = join(root, "routes.json");
  const policyFile = join(root, "fixture-policy.json");
  await writeRiskPolicy(policyFile, "R0", "a".repeat(64));
  await writeRoutes(path, {
    fixture: {
      ...localRoute("Fixture", []),
      riskPolicy: { mode: "broker-owned", policyFile },
    },
  });

  const registry = new UniversalMcpRouteRegistry(path);
  const first = await registry.inspect();
  assert.equal(first.routes[0]?.riskPolicy?.mode, "broker-owned");
  assert.equal(typeof first.routes[0]?.riskPolicy?.policyDigest, "string");

  await writeRiskPolicy(policyFile, "R3", "a".repeat(64));
  const second = await registry.inspect();
  assert.notEqual(second.generation, first.generation);
  assert.notEqual(
    second.routes[0]?.riskPolicy?.policyDigest,
    first.routes[0]?.riskPolicy?.policyDigest,
  );
});

test("configured MCP policy fails closed for malformed, writable, missing, and symlink files", async (t) => {
  const root = await mkdtemp(join(tmpdir(), "devspace-v2-mcp-policy-invalid-"));
  t.after(() => rm(root, { recursive: true, force: true }));
  const routePath = join(root, "routes.json");
  const policyFile = join(root, "policy.json");
  const configure = async (configuredPath: string) => {
    await writeRoutes(routePath, {
      fixture: {
        ...localRoute("Fixture", []),
        riskPolicy: { mode: "broker-owned", policyFile: configuredPath },
      },
    });
    return new UniversalMcpRouteRegistry(routePath);
  };

  await writeFile(policyFile, "{not-json", { mode: 0o600 });
  await assert.rejects((await configure(policyFile)).inspect(), hasCode("PRECONDITION_FAILED"));

  await writeRiskPolicy(policyFile, "R0", "b".repeat(64));
  await chmod(policyFile, 0o622);
  await assert.rejects((await configure(policyFile)).inspect(), hasCode("PRECONDITION_FAILED"));

  await chmod(policyFile, 0o000);
  await assert.rejects((await configure(policyFile)).inspect(), hasCode("PRECONDITION_FAILED"));

  const missing = join(root, "missing-policy.json");
  await assert.rejects((await configure(missing)).inspect(), hasCode("PRECONDITION_FAILED"));

  await chmod(policyFile, 0o600);
  const policyLink = join(root, "policy-link.json");
  await symlink(policyFile, policyLink);
  await assert.rejects((await configure(policyLink)).inspect(), hasCode("PRECONDITION_FAILED"));
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

async function writeRiskPolicy(
  path: string,
  risk: "R0" | "R2" | "R3",
  toolContractSha256: string,
): Promise<void> {
  await writeFile(path, JSON.stringify({
    version: 1,
    routeId: "fixture",
    tools: {
      read_exact: { risk, toolContractSha256 },
    },
  }, null, 2), { mode: 0o600 });
  await chmod(path, 0o600);
}

function hasCode(code: string) {
  return (error: unknown) => error instanceof Error && "code" in error && error.code === code;
}
