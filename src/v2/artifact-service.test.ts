import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { createServer } from "node:http";
import { Readable } from "node:stream";
import { chmod, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { AddressInfo } from "node:net";
import test from "node:test";
import { createMcpExpressApp } from "@modelcontextprotocol/sdk/server/express.js";
import { loadConfig } from "../config.js";
import type { IncomingArtifactAdapter } from "../incoming-artifacts.js";
import { UniversalArtifactService } from "./artifact-service.js";
import { ContextRegistry } from "./contexts.js";
import { UniversalExecutionPlane } from "./execution.js";
import { UniversalFilesystemService } from "./filesystem.js";
import { TargetRegistry } from "./targets.js";

test("artifact.receive streams a trusted native file into local storage", async (t) => {
  const fixture = await createFixture(t, [fixtureAdapter()]);
  const destination = join(fixture.root, "received.txt");
  const result = await fixture.artifacts.execute({
    operation: "receive",
    source: { file: { fixture: true }, size: 15 },
    destination: { path: destination },
  });
  assert.equal(await readFile(destination, "utf8"), "native-fixture\n");
  assert.equal(result.sourceKind, "native:fixture");
  assert.equal(result.size, 15);
});

test("artifact.receive follows validated loopback redirects and enforces hashes", async (t) => {
  const body = Buffer.from("downloaded-artifact\n");
  const source = createServer((request, response) => {
    if (request.url === "/redirect") {
      response.statusCode = 302;
      response.setHeader("Location", "/payload");
      response.end();
      return;
    }
    response.statusCode = 200;
    response.setHeader("Content-Type", "text/plain");
    response.setHeader("Content-Length", String(body.length));
    response.end(body);
  });
  await listen(source);
  t.after(() => closeServer(source));
  const address = source.address() as AddressInfo;
  const fixture = await createFixture(t);
  const destination = join(fixture.root, "downloaded.txt");
  const result = await fixture.artifacts.execute({
    operation: "receive",
    source: {
      url: `http://127.0.0.1:${address.port}/redirect`,
      size: body.length,
      sha256: createHash("sha256").update(body).digest("hex"),
      name: "downloaded.txt",
    },
    destination: { path: destination },
  });
  assert.equal(await readFile(destination, "utf8"), body.toString("utf8"));
  assert.equal(result.sourceKind, "url");

  await assert.rejects(
    fixture.artifacts.execute({
      operation: "receive",
      source: {
        url: `http://127.0.0.1:${address.port}/payload`,
        sha256: "0".repeat(64),
      },
      destination: { path: join(fixture.root, "bad.txt") },
    }),
    hasCode("PRECONDITION_FAILED"),
  );
});

test("artifact.copy transfers through bounded staging without tool-text base64", async (t) => {
  const fixture = await createFixture(t);
  const source = join(fixture.root, "source.bin");
  const destination = join(fixture.root, "destination.bin");
  await writeFile(source, Buffer.from([0, 1, 2, 3, 4, 255]));
  const result = await fixture.artifacts.execute({
    operation: "copy",
    source: { path: source },
    destination: { path: destination },
  });
  assert.deepEqual(await readFile(destination), Buffer.from([0, 1, 2, 3, 4, 255]));
  assert.equal(result.size, 6);
  assert.equal(JSON.stringify(result).includes("AAECAwT/"), false);
});

test("artifact.publish exposes canonical owner-bound URI plus a reusable HTTP capability", async (t) => {
  const root = await mkdtemp(join(tmpdir(), "devspace-v2-artifact-http-"));
  t.after(() => rm(root, { recursive: true, force: true }));
  let baseUrl = "";
  const fixture = await createFixture(t, [], {
    root,
    baseUrl: () => baseUrl,
  });
  const app = createMcpExpressApp({ host: "127.0.0.1" });
  app.head("/artifacts-next/:artifactId", (req, res) => {
    void fixture.artifacts.handleHttp(req, res);
  });
  app.get("/artifacts-next/:artifactId", (req, res) => {
    void fixture.artifacts.handleHttp(req, res);
  });
  const server = app.listen(0, "127.0.0.1");
  await new Promise<void>((resolve, reject) => {
    server.once("listening", resolve);
    server.once("error", reject);
  });
  t.after(() => closeServer(server));
  const address = server.address() as AddressInfo;
  baseUrl = `http://127.0.0.1:${address.port}`;

  const path = join(root, "published.txt");
  await writeFile(path, "one-time artifact\n");
  const published = await fixture.artifacts.execute({
    operation: "publish",
    source: { path, mimeType: "text/plain" },
    ttlSeconds: 60,
  });
  assert.match(String(published.resourceUri), /^devspace:\/\/artifact\/[0-9a-f-]{36}$/u);
  const downloadUrl = String(published.downloadUrl);
  const head = await fetch(downloadUrl, { method: "HEAD" });
  assert.equal(head.status, 200);
  assert.equal(head.headers.get("content-length"), "18");
  const first = await fetch(downloadUrl);
  assert.equal(first.status, 200);
  assert.equal(await first.text(), "one-time artifact\n");
  const second = await fetch(downloadUrl);
  assert.equal(second.status, 200);
  assert.equal(await second.text(), "one-time artifact\n");
});

test("artifact byte quotas reject streams before destination publication", async (t) => {
  const fixture = await createFixture(t, [fixtureAdapter()], {
    maximumArtifactBytes: 5,
  });
  const destination = join(fixture.root, "too-large.txt");
  await assert.rejects(
    fixture.artifacts.execute({
      operation: "receive",
      source: { file: { fixture: true } },
      destination: { path: destination },
    }),
    hasCode("RESOURCE_QUOTA_EXCEEDED"),
  );
  await assert.rejects(readFile(destination), { code: "ENOENT" });
});

test("artifact CAS deduplicates identical bytes and fails closed on object hash mismatch", async (t) => {
  const fixture = await createFixture(t, [], {
    maximumEntries: 8,
    maximumArtifactBytes: 1_000,
    maximumTotalBytes: 10_000,
  });
  const content = Buffer.from("same-content-addressed-bytes\n");
  const sha256 = createHash("sha256").update(content).digest("hex");
  const firstPath = join(fixture.root, "first.bin");
  const secondPath = join(fixture.root, "second.bin");
  await writeFile(firstPath, content);
  await writeFile(secondPath, content);
  await fixture.artifacts.execute({
    operation: "publish",
    source: { path: firstPath, size: content.length, sha256 },
  }, "owner-a");
  await fixture.artifacts.execute({
    operation: "publish",
    source: { path: secondPath, size: content.length, sha256 },
  }, "owner-a");
  assert.deepEqual(fixture.artifacts.stats(), {
    artifacts: 2,
    objects: 1,
    totalBytes: content.length,
    reservations: 0,
    reservedEntries: 0,
    reservedBytes: 0,
    maximumEntries: 8,
    maximumTotalBytes: 10_000,
    maximumArtifactBytes: 1_000,
    ttlMs: 60_000,
  });

  const objectPath = join(
    fixture.root,
    "artifact-staging",
    "objects",
    "sha256",
    sha256.slice(0, 2),
    sha256,
  );
  await chmod(objectPath, 0o600);
  await writeFile(objectPath, Buffer.alloc(content.length, 0x78));
  await assert.rejects(
    fixture.artifacts.execute({
      operation: "publish",
      source: { path: secondPath, size: content.length, sha256 },
    }, "owner-a"),
    hasCode("PRECONDITION_FAILED"),
  );
  assert.equal((fixture.artifacts.stats().artifacts as number), 2);
});

test("artifact canonical handles deny cross-owner reads", async (t) => {
  const fixture = await createFixture(t);
  const path = join(fixture.root, "owner-bound.txt");
  await writeFile(path, "owner-bound\n");
  const published = await fixture.artifacts.execute({
    operation: "publish",
    source: { path, size: 12 },
  }, { principalKeyFingerprint: "owner-a" });
  const ownRead = await fixture.artifacts.readResource(
    String(published.resourceUri),
    { ownerFingerprint: "owner-a" },
  );
  assert.equal(Buffer.from(String(ownRead.blobBase64), "base64").toString(), "owner-bound\n");
  await assert.rejects(
    fixture.artifacts.readResource(String(published.resourceUri), "owner-b"),
    hasCode("AUTHORITY_PRINCIPAL_MISMATCH"),
  );
});

test("the 257th artifact reservation rejects before opening its source", async (t) => {
  let opens = 0;
  const adapter = fixtureAdapter(() => { opens += 1; });
  const fixture = await createFixture(t, [adapter], {
    maximumEntries: 256,
    maximumArtifactBytes: 15,
    maximumTotalBytes: 1_000,
  });
  for (let index = 0; index < 256; index += 1) {
    await fixture.artifacts.execute({
      operation: "receive",
      source: { file: { fixture: true }, size: 15, name: `record-${index}.txt` },
    }, "owner-quota");
  }
  assert.equal(opens, 256);
  await assert.rejects(
    fixture.artifacts.execute({
      operation: "receive",
      source: { file: { fixture: true }, size: 15 },
    }, "owner-quota"),
    hasCode("RESOURCE_QUOTA_EXCEEDED"),
  );
  assert.equal(opens, 256);
  assert.equal(fixture.artifacts.stats().artifacts, 256);
});

interface Fixture {
  root: string;
  artifacts: UniversalArtifactService;
}

async function createFixture(
  t: test.TestContext,
  adapters: readonly IncomingArtifactAdapter[] = [],
  overrides: {
    root?: string;
    baseUrl?: string | (() => string);
    maximumArtifactBytes?: number;
    maximumEntries?: number;
    maximumTotalBytes?: number;
  } = {},
): Promise<Fixture> {
  const root = overrides.root ?? await mkdtemp(join(tmpdir(), "devspace-v2-artifact-test-"));
  if (!overrides.root) t.after(() => rm(root, { recursive: true, force: true }));
  const serverConfig = loadConfig({
    DEVSPACE_CONFIG_DIR: join(root, ".config"),
    DEVSPACE_ALLOWED_ROOTS: root,
    DEVSPACE_STATE_DIR: join(root, "legacy-state"),
    DEVSPACE_WORKTREE_ROOT: join(root, "worktrees"),
    DEVSPACE_OAUTH_OWNER_TOKEN: "v2-artifact-test-owner-credential-123456",
    DEVSPACE_PUBLIC_BASE_URL: "http://127.0.0.1:17676",
    DEVSPACE_LOG_LEVEL: "silent",
    DEVSPACE_SKILL_PATHS: join(root, "skills"),
  });
  const targets = new TargetRegistry({ configPath: join(root, "targets.json") });
  const contexts = new ContextRegistry({
    storePath: join(root, "v2-state", "contexts.json"),
    targets,
    serverConfig,
  });
  const execution = new UniversalExecutionPlane({
    targets,
    contexts,
    outputDir: join(root, "process-output"),
    sshControlDir: join(root, "ssh-control"),
    maxRunningProcesses: 4,
    maxRunningProcessesPerTarget: 2,
    processBufferCharacters: 100_000,
    processOutputMaxBytes: 1_000_000,
    completedProcessTtlMs: 60_000,
  });
  t.after(() => execution.close());
  const filesystem = new UniversalFilesystemService(
    targets,
    contexts,
    execution,
    { sshControlDir: join(root, "ssh-control") },
  );
  const artifacts = new UniversalArtifactService(filesystem, {
    stagingRoot: join(root, "artifact-staging"),
    incomingAdapters: adapters,
    baseUrl: overrides.baseUrl,
    maximumArtifactBytes: overrides.maximumArtifactBytes,
    maximumTotalBytes: overrides.maximumTotalBytes ?? 10_000_000,
    maximumEntries: overrides.maximumEntries ?? 8,
    ttlMs: 60_000,
  });
  t.after(() => artifacts.close());
  return { root, artifacts };
}

function fixtureAdapter(onOpen?: () => void): IncomingArtifactAdapter {
  return {
    id: "fixture",
    canHandle(value) {
      return Boolean(value && typeof value === "object" && (value as { fixture?: boolean }).fixture);
    },
    async open() {
      onOpen?.();
      const content = Buffer.from("native-fixture\n");
      return {
        name: "native.txt",
        mimeType: "text/plain",
        size: content.length,
        stream: Readable.from(content),
      };
    },
  };
}

async function listen(server: ReturnType<typeof createServer>): Promise<void> {
  server.listen(0, "127.0.0.1");
  await new Promise<void>((resolve, reject) => {
    server.once("listening", resolve);
    server.once("error", reject);
  });
}

async function closeServer(server: { close(callback: () => void): void }): Promise<void> {
  await new Promise<void>((resolve) => server.close(resolve));
}

function hasCode(code: string) {
  return (error: unknown) => error instanceof Error && "code" in error && error.code === code;
}
