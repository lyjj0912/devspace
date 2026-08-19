import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { spawn } from "node:child_process";
import { createServer } from "node:http";
import { mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import test from "node:test";
import Database from "better-sqlite3";

const expectedScopes = [
  "devspace.read",
  "devspace.write",
  "devspace.exec",
  "devspace.mcp",
  "devspace.artifact",
  "devspace.gui",
  "offline_access",
];

test("live verifier defaults to parallel v2 and creates only a temporary user token", async (t) => {
  const root = await mkdtemp(join(tmpdir(), "devspace-v2-live-test-"));
  const databasePath = join(root, "devspace.sqlite");
  const database = new Database(databasePath);
  database.exec(`
    CREATE TABLE oauth_clients (client_id TEXT PRIMARY KEY, client_json TEXT NOT NULL, issued_at INTEGER NOT NULL);
    CREATE TABLE oauth_access_tokens (token_hash TEXT PRIMARY KEY, client_id TEXT NOT NULL, scopes_json TEXT NOT NULL, expires_at INTEGER NOT NULL, resource TEXT);
    CREATE TABLE oauth_refresh_tokens (token_hash TEXT PRIMARY KEY, client_id TEXT NOT NULL, scopes_json TEXT NOT NULL, expires_at INTEGER NOT NULL, resource TEXT);
  `);
  database.close();
  t.after(() => rm(root, { recursive: true, force: true }));

  const advertisedResource = "https://parallel.example.test/mcp-next";
  let resolveObserved!: () => void;
  let rejectObserved!: (error: Error) => void;
  const observed = new Promise<void>((resolve, reject) => {
    resolveObserved = resolve;
    rejectObserved = reject;
  });
  const server = createServer((request, response) => {
    try {
      if (request.method === "GET" && request.url === "/healthz-next") {
        response.writeHead(200, { "content-type": "application/json" });
        response.end('{"status":"ok","runtimeRevision":"fixture-revision"}');
        return;
      }
      if (request.method === "GET" && request.url === "/mcp-next") {
        response.writeHead(401, {
          "www-authenticate": 'Bearer resource_metadata="https://parallel.example.test/.well-known/oauth-protected-resource/mcp-next"',
        });
        response.end();
        return;
      }
      if (request.method === "GET" && request.url === "/.well-known/oauth-protected-resource/mcp-next") {
        response.writeHead(200, { "content-type": "application/json" });
        response.end(JSON.stringify({ resource: advertisedResource }));
        return;
      }
      if (request.method === "POST" && request.url === "/mcp-next") {
        const token = String(request.headers.authorization ?? "").replace(/^Bearer\s+/u, "");
        const tokenHash = createHash("sha256").update(token).digest("base64url");
        const check = new Database(databasePath, { readonly: true });
        const row = check.prepare(
          "SELECT client_id, scopes_json, resource FROM oauth_access_tokens WHERE token_hash = ?",
        ).get(tokenHash) as { client_id: string; scopes_json: string; resource: string } | undefined;
        const client = row
          ? check.prepare("SELECT client_json FROM oauth_clients WHERE client_id = ?").get(row.client_id) as { client_json: string } | undefined
          : undefined;
        check.close();
        assert.ok(row);
        assert.deepEqual(JSON.parse(row.scopes_json), expectedScopes);
        assert.equal(row.resource, advertisedResource);
        assert.equal(JSON.parse(client?.client_json ?? "null")?.client_id, row.client_id);
        resolveObserved();
        response.writeHead(418, { "content-type": "application/json" });
        response.end('{"error":"fixture intentionally stops after authentication"}');
        return;
      }
      response.writeHead(404);
      response.end();
    } catch (error) {
      rejectObserved(error instanceof Error ? error : new Error(String(error)));
      response.writeHead(500);
      response.end();
    }
  });
  await new Promise<void>((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", resolve);
  });
  t.after(() => new Promise<void>((resolve, reject) => server.close((error) => error ? reject(error) : resolve())));
  const address = server.address();
  assert.ok(address && typeof address === "object");

  const child = spawn(process.execPath, [
    "scripts/verify-universal-broker-v2-live.mjs",
    "--base-url", `http://127.0.0.1:${address.port}`,
    "--database", databasePath,
  ], { cwd: resolve("."), stdio: ["ignore", "pipe", "pipe"] });
  let stdout = "";
  let stderr = "";
  child.stdout.setEncoding("utf8");
  child.stdout.on("data", (chunk) => { stdout += chunk; });
  child.stderr.setEncoding("utf8");
  child.stderr.on("data", (chunk) => { stderr += chunk; });
  const exitCode = await new Promise<number | null>((resolveExit, reject) => {
    child.once("error", reject);
    child.once("exit", resolveExit);
  });
  await observed;
  assert.notEqual(exitCode, 0);
  assert.match(stderr, /418|fixture intentionally stops/u);
  const report = JSON.parse(stdout) as {
    ok?: boolean;
    failure?: { name?: string; message?: string };
    cleanup?: { ok?: boolean; failures?: unknown[] };
  };
  assert.equal(report.ok, false);
  assert.equal(report.cleanup?.ok, true);
  assert.equal(report.cleanup?.failures, undefined);
  assert.match(report.failure?.message ?? "", /418|fixture intentionally stops/u);
  assert.doesNotMatch(stdout, /dsv2_[A-Za-z0-9_-]{16,}/u);

  const cleaned = new Database(databasePath, { readonly: true });
  assert.equal((cleaned.prepare("SELECT count(*) AS count FROM oauth_access_tokens").get() as { count: number }).count, 0);
  assert.equal((cleaned.prepare("SELECT count(*) AS count FROM oauth_refresh_tokens").get() as { count: number }).count, 0);
  assert.equal((cleaned.prepare("SELECT count(*) AS count FROM oauth_clients").get() as { count: number }).count, 0);
  cleaned.close();

  const source = await readFile("scripts/verify-universal-broker-v2-live.mjs", "utf8");
  assert.match(source, /baseUrl: "http:\/\/127\.0\.0\.1:7677"/u);
  assert.match(source, /audit\.health\?\.status === "ok"/u);
  assert.doesNotMatch(source, /audit\.health\?\.ok === true/u);
  assert.match(source, /errorCode\(mismatchResult\) === "AUTHORITY_ACTION_MISMATCH"/u);
  assert.match(source, /errorCode\(crossClientResult\) === "AUTHORITY_PRINCIPAL_MISMATCH"/u);
  assert.match(source, /universal-broker-v2\/devspace\.sqlite/u);
  assert.match(source, /code !== "GUI_STATE_CHANGED"/u);
  assert.match(source, /for \(let attempt = 0; attempt < 2; attempt \+= 1\)/u);
  assert.match(source, /await prepareLocalGuiApplication\(\)/u);
  assert.match(source, /execFileSync\("open", argumentsForOpen/u);
  assert.match(source, /operation: "authority_preview"/u);
  assert.match(source, /refresh: true/u);
  assert.match(source, /capabilities\?\.pty === true/u);
  assert.match(source, /capabilities\?\.sftp === true/u);
  assert.match(source, /windowsTarget: undefined/u);
  assert.match(source, /No explicit Windows live target was supplied/u);
  assert.match(source, /if \(options\.windowsTarget\)/u);
  assert.match(source, /callReadOnlyMcpWhenReady/u);
  assert.match(source, /readOnlyHint === true/u);
  assert.match(source, /destructiveHint !== true/u);
  assert.match(source, /MCP_PROVIDER_ERROR.*MCP_TRANSPORT_ERROR/u);
  assert.match(source, /unexpectedly requires mutation authority/u);
  assert.match(source, /authority preview unexpectedly created its remote fixture path/u);
  assert.match(source, /skipCompanyGates: false/u);
  assert.match(source, /argument === "--skip-company-gates"/u);
  assert.match(source, /Explicit --skip-company-gates deployment option\./u);
  assert.match(source, /companyGateSkipped: options\.skipCompanyGates/u);
  assert.match(source, /if \(!options\.skipCompanyGates\)/u);
  assert.match(source, /id: "r2-local-remove"[\s\S]*disposition: "trash"/u);
  assert.doesNotMatch(source, /templateDatabasePath|--template-database|JSON\.stringify\(\["devspace"/u);
});
