import assert from "node:assert/strict";
import childProcess from "node:child_process";
import { execFile, type ChildProcess, type SpawnOptions } from "node:child_process";
import { createHash } from "node:crypto";
import fs from "node:fs";
import { createServer } from "node:http";
import { syncBuiltinESMExports } from "node:module";
import { Readable } from "node:stream";
import { chmod, copyFile, mkdir, mkdtemp, readdir, readFile, rm, stat, symlink, unlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { basename, dirname, join } from "node:path";
import type { AddressInfo } from "node:net";
import test from "node:test";
import { promisify } from "node:util";
import Database from "better-sqlite3";
import { createMcpExpressApp } from "@modelcontextprotocol/sdk/server/express.js";
import { loadConfig } from "../config.js";
import type { IncomingArtifactAdapter } from "../incoming-artifacts.js";
import {
  createCapabilityCallContextFromTrustedPrincipal,
  type CapabilityCallContext,
} from "./capability-call-context.js";
import { SignedSnapshotCursorStore } from "./cursor-capability.js";
import { type ArtifactCopyHooks, UniversalArtifactService } from "./artifact-service.js";
import { ContextRegistry } from "./contexts.js";
import { UniversalExecutionPlane, type UniversalProcessSnapshot } from "./execution.js";
import { UniversalFilesystemService } from "./filesystem.js";
import { TargetRegistry } from "./targets.js";
import { UniversalBrokerMetrics } from "./metrics.js";

const execFileAsync = promisify(execFile);

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

test("artifact service exposes its completed startup reconciliation as read-only doctor evidence", async (t) => {
  const fixture = await createFixture(t);
  const first = await fixture.artifacts.reconciliationReport();
  assert.deepEqual(first, {
    abortedReservations: 0,
    quarantinedObjects: 0,
    quarantinedRecords: 0,
    receipts: 0,
  });
  assert.equal(Object.isFrozen(first), true);
  const second = await fixture.artifacts.reconciliationReport();
  assert.deepEqual(second, first);
});

test("artifact metrics cover reservation, publication, read, and quota without masking results", async (t) => {
  const metrics = new UniversalBrokerMetrics();
  const fixture = await createFixture(t, [fixtureAdapter()], {
    maximumEntries: 1,
    metrics,
  });
  const published = await fixture.artifacts.execute({
    operation: "receive",
    source: { file: { fixture: true }, size: 15 },
  }, "owner-metrics");
  await fixture.artifacts.readResource(String(published.resourceUri), "owner-metrics");
  await assert.rejects(
    fixture.artifacts.execute({
      operation: "receive",
      source: { file: { fixture: true }, size: 15 },
    }, "owner-metrics"),
    hasCode("RESOURCE_QUOTA_EXCEEDED"),
  );
  const rendered = metrics.render({});
  assert.match(rendered, /devspace_artifact_events_total\{event="reserved",result="pass"\} 1/u);
  assert.match(rendered, /devspace_artifact_events_total\{event="published",result="pass"\} 1/u);
  assert.match(rendered, /devspace_artifact_events_total\{event="read",result="pass"\} 1/u);
  assert.match(rendered, /devspace_artifact_events_total\{event="reserved",result="fail"\} 1/u);
  assert.match(rendered, /devspace_quota_rejections_total\{resource_kind="artifact"\} 1/u);
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

test("artifact.copy copies directories through immutable manifest mode", async (t) => {
  const fixture = await createFixture(t);
  const source = join(fixture.root, "source-tree");
  const nested = join(source, "nested");
  await mkdir(nested, { recursive: true });
  await writeFile(join(source, "alpha.txt"), "alpha\n");
  await writeFile(join(nested, "beta.txt"), "beta\n");
  const destination = join(fixture.root, "destination-tree");

  const result = await fixture.artifacts.execute({
    operation: "copy",
    source: { path: source },
    destination: { path: destination },
    maxBytes: 11,
    ttlSeconds: 60,
  }, "owner-directory");

  assert.equal(result.manifestMode, true);
  assert.equal(result.completedEntries, 2);
  assert.equal(result.totalEntries, 2);
  assert.match(String(result.manifestDigest), /^[0-9a-f]{64}$/u);
  assert.match(String(result.copyId), /^[0-9a-f]{64}$/u);
  assert.equal((result.source as { targetId?: string }).targetId, "local");
  assert.equal((result.destination as { targetId?: string }).targetId, "local");
  assert.match(String((result.source as { targetGeneration?: string }).targetGeneration), /^[0-9a-f]{64}$/u);
  assert.match(String((result.destination as { targetGeneration?: string }).targetGeneration), /^[0-9a-f]{64}$/u);
  assert.equal(await readFile(join(destination, "alpha.txt"), "utf8"), "alpha\n");
  assert.equal(await readFile(join(destination, "nested", "beta.txt"), "utf8"), "beta\n");

  const manifestResource = await fixture.artifacts.readResource(
    String(result.resourceUri),
    "owner-directory",
  );
  const manifest = JSON.parse(Buffer.from(String(manifestResource.blobBase64), "base64").toString("utf8")) as {
    ownerFingerprint: string;
    source: { targetId: string; targetGeneration: string };
    destination: { targetId: string; targetGeneration: string };
    entries: Array<{ relativePath: string; sha256: string }>;
  };
  assert.equal(manifest.ownerFingerprint, "owner-directory");
  assert.equal(manifest.source.targetGeneration, (result.source as { targetGeneration: string }).targetGeneration);
  assert.equal(manifest.destination.targetGeneration, (result.destination as { targetGeneration: string }).targetGeneration);
  assert.deepEqual(
    manifest.entries.map((entry) => entry.relativePath),
    ["alpha.txt", "nested/beta.txt"],
  );
  assert.equal(manifest.entries.every((entry) => /^[0-9a-f]{64}$/u.test(entry.sha256)), true);
});

test("artifact.copy copies a local directory to an SSH target through manifest mode", async (t) => {
  const fixture = await createRemoteArtifactFixture(t);
  const source = join(fixture.root, "local-source-tree");
  await mkdir(join(source, "nested"), { recursive: true });
  await writeFile(join(source, "alpha.txt"), "local-alpha\n");
  await writeFile(join(source, "nested", "beta.txt"), "local-beta\n");
  const destination = join(fixture.root, "remote-b", "local-to-remote");
  const owner = artifactCopyOwner("local-to-remote");

  const result = await fixture.artifacts.execute({
    operation: "copy",
    source: { path: source },
    destination: { target: "remote-b", path: destination },
  }, owner);

  assert.equal(result.manifestMode, true);
  assert.equal((result.source as { targetId?: string }).targetId, "local");
  assert.equal((result.destination as { targetId?: string }).targetId, "remote-b");
  assert.equal(await readFile(join(destination, "alpha.txt"), "utf8"), "local-alpha\n");
  assert.equal(await readFile(join(destination, "nested", "beta.txt"), "utf8"), "local-beta\n");
  assert.equal(fixture.sftpGets, 0);
  assert.equal(fixture.sftpPuts, 2);
});

test("artifact.copy copies an SSH directory to a local target through manifest mode", async (t) => {
  const fixture = await createRemoteArtifactFixture(t);
  const source = join(fixture.root, "remote-a", "remote-to-local-source");
  await mkdir(join(source, "nested"), { recursive: true });
  await writeFile(join(source, "alpha.txt"), "remote-alpha\n");
  await writeFile(join(source, "nested", "beta.txt"), "remote-beta\n");
  const destination = join(fixture.root, "local-from-remote");
  const owner = artifactCopyOwner("remote-to-local");

  const result = await fixture.artifacts.execute({
    operation: "copy",
    source: { target: "remote-a", path: source },
    destination: { path: destination },
  }, owner);

  assert.equal(result.manifestMode, true);
  assert.equal((result.source as { targetId?: string }).targetId, "remote-a");
  assert.equal((result.destination as { targetId?: string }).targetId, "local");
  assert.equal(await readFile(join(destination, "alpha.txt"), "utf8"), "remote-alpha\n");
  assert.equal(await readFile(join(destination, "nested", "beta.txt"), "utf8"), "remote-beta\n");
  assert.equal(fixture.sftpGets, 2);
  assert.equal(fixture.sftpPuts, 0);
});

test("artifact.copy rejects an SSH-to-local directory symlink parent before staging or outside writes", async (t) => {
  const fixture = await createRemoteArtifactFixture(t);
  const source = join(fixture.root, "remote-a", "symlink-source");
  await mkdir(join(source, "nested"), { recursive: true });
  await writeFile(join(source, "nested", "payload.txt"), "must-stay-contained\n");
  const destination = join(fixture.root, "symlink-destination");
  const outside = join(fixture.root, "outside-destination");
  await Promise.all([
    mkdir(destination, { recursive: true }),
    mkdir(outside, { recursive: true }),
  ]);
  await symlink(outside, join(destination, "nested"), "dir");

  await assert.rejects(
    fixture.artifacts.execute({
      operation: "copy",
      source: { target: "remote-a", path: source },
      destination: { path: destination },
    }, artifactCopyOwner("ssh-to-local-symlink")),
    hasCode("PERMISSION_DENIED"),
  );

  assert.deepEqual(await readdir(outside), []);
  assert.equal(fixture.sftpGets, 0);
  assert.equal(fixture.sftpPuts, 0);
  assert.equal(await leftoverArtifactCopyStaging(fixture.root), 0);
});

test("artifact.copy binds local publication to the validated parent inode across overwrite and source transports", async (t) => {
  const cases = [
    { label: "local-create", remote: false, overwrite: false },
    { label: "local-overwrite", remote: false, overwrite: true },
    { label: "ssh-create", remote: true, overwrite: false },
    { label: "ssh-overwrite", remote: true, overwrite: true },
  ] as const;

  for (const scenario of cases) {
    await t.test(scenario.label, async (t) => {
      const fixture = scenario.remote
        ? await createRemoteArtifactFixture(t)
        : await createFixture(t);
      const source = scenario.remote
        ? join(fixture.root, "remote-a", `${scenario.label}-source`)
        : join(fixture.root, `${scenario.label}-source`);
      await mkdir(source, { recursive: true });
      await writeFile(join(source, "payload.txt"), `new-${scenario.label}\n`);

      const destination = join(fixture.root, `${scenario.label}-destination`);
      const outside = join(fixture.root, `${scenario.label}-outside`);
      await Promise.all([
        mkdir(destination, { recursive: true }),
        mkdir(outside, { recursive: true }),
      ]);
      if (scenario.overwrite) {
        await Promise.all([
          writeFile(join(destination, "payload.txt"), `inside-before-${scenario.label}\n`),
          writeFile(join(outside, "payload.txt"), `outside-before-${scenario.label}\n`),
        ]);
      }

      const outcome = await runWithDeterministicLocalParentSwap({
        destinationRoot: destination,
        destinationPath: join(destination, "payload.txt"),
        outsideRoot: outside,
        overwrite: scenario.overwrite,
      }, async () => {
        try {
          await fixture.artifacts.execute({
            operation: "copy",
            source: {
              ...(scenario.remote ? { target: "remote-a" } : {}),
              path: source,
            },
            destination: { path: destination },
            overwrite: scenario.overwrite,
          }, artifactCopyOwner(`parent-swap-${scenario.label}`));
          return { resolved: true as const };
        } catch (error) {
          return { resolved: false as const, error };
        }
      });

      assert.equal(outcome.swapObserved, true);
      assert.equal(outcome.result.resolved, false);
      assert.equal((outcome.result as { error: { code?: string } }).error.code, "PERMISSION_DENIED");
      if (scenario.overwrite) {
        assert.equal(
          await readFile(join(outside, "payload.txt"), "utf8"),
          `outside-before-${scenario.label}\n`,
        );
      } else {
        assert.deepEqual(await readdir(outside), []);
      }
    });
  }
});

test("artifact.copy rejects symlinks in existing ancestors above a local destination root", async (t) => {
  for (const remote of [false, true]) {
    await t.test(remote ? "ssh-to-local" : "local-to-local", async (t) => {
      const fixture = remote
        ? await createRemoteArtifactFixture(t)
        : await createFixture(t);
      const source = remote
        ? join(fixture.root, "remote-a", "ancestor-source")
        : join(fixture.root, "ancestor-source");
      await mkdir(source, { recursive: true });
      await writeFile(join(source, "payload.txt"), "ancestor-contained\n");
      const container = join(fixture.root, "ancestor-container");
      const outside = join(fixture.root, "ancestor-outside");
      await Promise.all([
        mkdir(container, { recursive: true }),
        mkdir(outside, { recursive: true }),
      ]);
      await symlink(outside, join(container, "parent-link"), "dir");
      const destination = join(container, "parent-link", "destination");

      await assert.rejects(
        fixture.artifacts.execute({
          operation: "copy",
          source: {
            ...(remote ? { target: "remote-a" } : {}),
            path: source,
          },
          destination: { path: destination },
        }, artifactCopyOwner(`ancestor-${remote ? "remote" : "local"}`)),
        hasCode("PERMISSION_DENIED"),
      );

      assert.deepEqual(await readdir(outside), []);
      if (remote) assert.equal((fixture as RemoteArtifactFixture).sftpGets, 0);
    });
  }
});

test("artifact.copy reserves exact manifest capacity before destination dispatch or mutation", async (t) => {
  const fixture = await createRemoteArtifactFixture(t, { maximumTotalBytes: 128 });
  const source = join(fixture.root, "manifest-quota-source");
  await mkdir(source, { recursive: true });
  await writeFile(join(source, "payload.txt"), "x");
  const destination = join(fixture.root, "remote-b", "manifest-quota-destination");

  await assert.rejects(
    fixture.artifacts.execute({
      operation: "copy",
      source: { path: source, size: 1 },
      destination: { target: "remote-b", path: destination },
    }, artifactCopyOwner("manifest-capacity")),
    hasCode("RESOURCE_QUOTA_EXCEEDED"),
  );

  assert.equal(fixture.destinationDispatches, 0);
  assert.equal(fixture.sftpPuts, 0);
  await assert.rejects(stat(destination), { code: "ENOENT" });
  await assert.rejects(readdir(join(fixture.root, "artifact-staging", "copy-checkpoints")), { code: "ENOENT" });
  assert.equal(fixture.artifacts.stats().reservations, 0);
});

test("artifact.copy treats directory source.size as a precondition, not manifest capacity", async (t) => {
  const fixture = await createFixture(t, [], { maximumTotalBytes: 5_000 });
  const source = join(fixture.root, "declared-directory-source");
  await mkdir(source, { recursive: true });
  await writeFile(join(source, "payload.bin"), Buffer.alloc(10_000, 0x61));
  const destination = join(fixture.root, "declared-directory-destination");

  const result = await fixture.artifacts.execute({
    operation: "copy",
    source: { path: source, size: 10_000 },
    destination: { path: destination },
  }, "owner-declared-directory");

  assert.equal(result.manifestMode, true);
  assert.equal(await readFile(join(destination, "payload.bin")).then((value) => value.byteLength), 10_000);
  assert.equal((result.size as number) < 5_000, true);
  assert.equal(fixture.artifacts.stats().totalBytes, result.size);
});

test("artifact.copy preserves zero-byte source.size capacity when the byte quota is exactly full", async (t) => {
  const fixture = await createFixture(t, [], { maximumTotalBytes: 5 });
  const occupied = join(fixture.root, "occupied.bin");
  await writeFile(occupied, "12345");
  await fixture.artifacts.execute({
    operation: "publish",
    source: { path: occupied },
  }, "owner-zero-byte-capacity");

  const source = join(fixture.root, "zero-byte-source.bin");
  const destination = join(fixture.root, "zero-byte-destination.bin");
  await writeFile(source, Buffer.alloc(0));
  const result = await fixture.artifacts.execute({
    operation: "copy",
    source: { path: source, size: 0 },
    destination: { path: destination },
  }, "owner-zero-byte-capacity");

  assert.equal(result.size, 0);
  assert.equal((await stat(destination)).size, 0);
  assert.equal(fixture.artifacts.stats().totalBytes, 5);
});

test("concurrent directory copies reserve bounded provisional capacity before exact manifests", async (t) => {
  const fixture = await createFixture(t, [], { maximumTotalBytes: 5_000 });
  const inputs = await Promise.all(["a", "b"].map(async (label) => {
    const source = join(fixture.root, `concurrent-${label}-source`);
    await mkdir(source, { recursive: true });
    await writeFile(join(source, "payload.txt"), `${label}\n`);
    return {
      operation: "copy" as const,
      source: { path: source },
      destination: { path: join(fixture.root, `concurrent-${label}-destination`) },
    };
  }));

  const results = await Promise.all(inputs.map((input, index) =>
    fixture.artifacts.execute(input, `owner-concurrent-${index}`)));

  assert.equal(results.every((result) => result.manifestMode === true), true);
  const committedBytes = results.reduce((sum, result) => sum + Number(result.size), 0);
  assert.equal(committedBytes < 5_000, true);
  assert.equal(fixture.artifacts.stats().totalBytes, committedBytes);
  assert.equal(fixture.artifacts.stats().reservations, 0);
});

test("artifact.copy copies an SSH directory to another SSH target through immutable manifest mode", async (t) => {
  const fixture = await createRemoteArtifactFixture(t);
  const source = join(fixture.root, "remote-a", "source-tree");
  await mkdir(join(source, "nested"), { recursive: true });
  await writeFile(join(source, "one.txt"), "remote-one\n");
  await writeFile(join(source, "nested", "two.txt"), "remote-two\n");
  const destination = join(fixture.root, "remote-b", "ssh-to-ssh");
  const owner = artifactCopyOwner("ssh-to-ssh");

  const result = await fixture.artifacts.execute({
    operation: "copy",
    source: { target: "remote-a", path: source },
    destination: { target: "remote-b", path: destination },
  }, owner);

  assert.equal(result.manifestMode, true);
  assert.equal(result.completedEntries, 2);
  assert.equal(result.totalEntries, 2);
  assert.equal((result.source as { targetId?: string }).targetId, "remote-a");
  assert.equal((result.destination as { targetId?: string }).targetId, "remote-b");
  assert.equal(await readFile(join(destination, "one.txt"), "utf8"), "remote-one\n");
  assert.equal(await readFile(join(destination, "nested", "two.txt"), "utf8"), "remote-two\n");
  assert.equal(fixture.sftpGets, 2);
  assert.equal(fixture.sftpPuts, 2);

  const manifestResource = await fixture.artifacts.readResource(String(result.resourceUri), owner);
  const manifest = JSON.parse(Buffer.from(String(manifestResource.blobBase64), "base64").toString("utf8")) as {
    ownerFingerprint: string;
    source: { targetId: string; targetGeneration: string };
    destination: { targetId: string; targetGeneration: string };
    entries: Array<{ relativePath: string; sha256: string }>;
  };
  assert.equal(manifest.ownerFingerprint, owner.principalKeyFingerprint);
  assert.equal(manifest.source.targetId, "remote-a");
  assert.equal(manifest.destination.targetId, "remote-b");
  assert.equal(manifest.source.targetGeneration, (result.source as { targetGeneration: string }).targetGeneration);
  assert.equal(manifest.destination.targetGeneration, (result.destination as { targetGeneration: string }).targetGeneration);
  assert.deepEqual(
    manifest.entries.map((entry) => entry.relativePath),
    ["nested/two.txt", "one.txt"],
  );
  assert.equal(manifest.entries.every((entry) => /^[0-9a-f]{64}$/u.test(entry.sha256)), true);
  assert.equal(await leftoverArtifactCopyStaging(fixture.root), 0);
});

test("artifact.copy resumes an SSH directory checkpoint without replaying completed entries", async (t) => {
  const fixture = await createRemoteArtifactFixture(t, {
    copyHooks: failAfterFirstDirectoryCheckpoint(),
  });
  const source = join(fixture.root, "remote-a", "resume-source");
  await mkdir(source, { recursive: true });
  await writeFile(join(source, "a.txt"), "a\n");
  await writeFile(join(source, "b.txt"), "b\n");
  const destination = join(fixture.root, "remote-b", "resume-destination");
  const owner = artifactCopyOwner("remote-resume");
  const input = {
    operation: "copy" as const,
    source: { target: "remote-a", path: source },
    destination: { target: "remote-b", path: destination },
  };

  await assert.rejects(
    fixture.artifacts.execute(input, owner),
    /simulated-remote-copy-interruption/u,
  );
  assert.equal(await readFile(join(destination, "a.txt"), "utf8"), "a\n");
  await assert.rejects(readFile(join(destination, "b.txt"), "utf8"), { code: "ENOENT" });

  await fixture.artifacts.close();
  const resumed = new UniversalArtifactService(fixture.filesystem, {
    stagingRoot: join(fixture.root, "artifact-staging"),
    maximumArtifactBytes: 2 * 1024 * 1024 * 1024,
    maximumTotalBytes: 10_000_000,
    maximumEntries: 8,
    ttlMs: 60_000,
  });
  t.after(() => resumed.close());

  const result = await resumed.execute(input, owner);
  assert.equal(result.manifestMode, true);
  assert.equal(result.resumed, true);
  assert.equal(result.completedEntries, 2);
  assert.deepEqual(await Promise.all([
    readFile(join(destination, "a.txt"), "utf8"),
    readFile(join(destination, "b.txt"), "utf8"),
  ]), ["a\n", "b\n"]);

  const publishedPayloads = fixture.sftpPutPaths.filter((path) => path.includes("/resume-destination/"));
  assert.equal(publishedPayloads.filter((path) => path.endsWith("/a.txt") || path.includes("/.devspace-v2-a.txt-")).length, 1);
  assert.equal(publishedPayloads.filter((path) => path.endsWith("/b.txt") || path.includes("/.devspace-v2-b.txt-")).length, 1);
});

test("artifact.copy rejects stale remote generation and manifest checkpoint digests", async (t) => {
  const generationFixture = await createRemoteArtifactFixture(t);
  const generationSource = join(generationFixture.root, "remote-a", "generation-source");
  await mkdir(generationSource, { recursive: true });
  await writeFile(join(generationSource, "entry.txt"), "entry\n");
  await assert.rejects(
    generationFixture.artifacts.execute({
      operation: "copy",
      source: {
        target: "remote-a",
        path: generationSource,
        targetGeneration: "0".repeat(64),
      },
      destination: { target: "remote-b", path: join(generationFixture.root, "remote-b", "generation-destination") },
    }, artifactCopyOwner("stale-generation")),
    hasCode("PRECONDITION_FAILED"),
  );

  const digestFixture = await createRemoteArtifactFixture(t, {
    copyHooks: failAfterFirstDirectoryCheckpoint(),
  });
  const digestSource = join(digestFixture.root, "remote-a", "digest-source");
  await mkdir(digestSource, { recursive: true });
  await writeFile(join(digestSource, "a.txt"), "a\n");
  await writeFile(join(digestSource, "b.txt"), "b\n");
  const digestDestination = join(digestFixture.root, "remote-b", "digest-destination");
  const owner = artifactCopyOwner("stale-digest");
  const input = {
    operation: "copy" as const,
    source: { target: "remote-a", path: digestSource },
    destination: { target: "remote-b", path: digestDestination },
  };
  await assert.rejects(digestFixture.artifacts.execute(input, owner), /simulated-remote-copy-interruption/u);
  await writeFile(join(digestSource, "b.txt"), "changed\n");
  await assert.rejects(
    digestFixture.artifacts.execute(input, owner),
    hasCode("PRECONDITION_FAILED"),
  );
});

test("artifact.copy resumes directory checkpoint without rewriting completed entries", async (t) => {
  const root = await mkdtemp(join(tmpdir(), "devspace-v2-artifact-copy-resume-"));
  t.after(() => rm(root, { recursive: true, force: true }));
  const source = join(root, "resume-source");
  await mkdir(source, { recursive: true });
  await writeFile(join(source, "one.txt"), "one\n");
  await writeFile(join(source, "two.txt"), "two\n");
  const destination = join(root, "resume-destination");
  let failedOnce = false;
  const hooks: ArtifactCopyHooks = {
    afterEntryCheckpointed(event) {
      if (!failedOnce && event.completedEntries === 1) {
        failedOnce = true;
        throw new Error("simulated-copy-interruption");
      }
    },
  };
  const fixture = await createFixture(t, [], { root, copyHooks: hooks });

  await assert.rejects(
    fixture.artifacts.execute({
      operation: "copy",
      source: { path: source },
      destination: { path: destination },
    }, "owner-resume"),
    /simulated-copy-interruption/u,
  );
  const firstCopied = join(destination, "one.txt");
  assert.equal(await readFile(firstCopied, "utf8"), "one\n");
  await assert.rejects(readFile(join(destination, "two.txt")), { code: "ENOENT" });
  const firstMtime = (await stat(firstCopied)).mtimeMs;

  await fixture.artifacts.close();
  const resumed = new UniversalArtifactService(fixture.filesystem, {
    stagingRoot: join(root, "artifact-staging"),
    maximumArtifactBytes: 2 * 1024 * 1024 * 1024,
    maximumTotalBytes: 10_000_000,
    maximumEntries: 8,
    ttlMs: 60_000,
  });
  t.after(() => resumed.close());
  const result = await resumed.execute({
    operation: "copy",
    source: { path: source },
    destination: { path: destination },
  }, "owner-resume");

  assert.equal(result.manifestMode, true);
  assert.equal(result.resumed, true);
  assert.equal(result.completedEntries, 2);
  assert.equal(await readFile(join(destination, "two.txt"), "utf8"), "two\n");
  assert.equal((await stat(firstCopied)).mtimeMs, firstMtime);

  const database = new Database(join(root, "artifact-staging", "artifacts.sqlite"), {
    readonly: true,
    fileMustExist: true,
  });
  const records = database.prepare("SELECT COUNT(*) AS count FROM artifact_records").get() as { count: number };
  database.close();
  assert.equal(records.count, 1);
});

test("a COMPLETED directory checkpoint revalidates destination entries before replay success", async (t) => {
  const fixture = await createFixture(t);
  const source = join(fixture.root, "completed-destination-source");
  const destination = join(fixture.root, "completed-destination-target");
  await mkdir(source, { recursive: true });
  await writeFile(join(source, "payload.txt"), "completed-destination\n");
  const input = {
    operation: "copy" as const,
    source: { path: source },
    destination: { path: destination },
  };
  await fixture.artifacts.execute(input, "owner-completed-destination");
  await unlink(join(destination, "payload.txt"));

  await assert.rejects(
    fixture.artifacts.execute(input, "owner-completed-destination"),
    hasCode("TRANSPORT_INTERRUPTED"),
  );
});

test("a COMPLETED directory checkpoint revalidates empty destination directories before replay success", async (t) => {
  const fixture = await createFixture(t);
  const source = join(fixture.root, "completed-empty-directory-source");
  const destination = join(fixture.root, "completed-empty-directory-target");
  await mkdir(join(source, "empty"), { recursive: true });
  const input = {
    operation: "copy" as const,
    source: { path: source },
    destination: { path: destination },
  };
  await fixture.artifacts.execute(input, "owner-completed-empty-directory");
  await rm(join(destination, "empty"), { recursive: true });

  await assert.rejects(
    fixture.artifacts.execute(input, "owner-completed-empty-directory"),
    hasCode("TRANSPORT_INTERRUPTED"),
  );
});

test("a COMPLETED directory checkpoint revalidates its manifest CAS before replay success", async (t) => {
  const fixture = await createFixture(t);
  const source = join(fixture.root, "completed-cas-source");
  const destination = join(fixture.root, "completed-cas-target");
  await mkdir(source, { recursive: true });
  await writeFile(join(source, "payload.txt"), "completed-cas\n");
  const input = {
    operation: "copy" as const,
    source: { path: source },
    destination: { path: destination },
  };
  const result = await fixture.artifacts.execute(input, "owner-completed-cas");
  const database = new Database(join(fixture.root, "artifact-staging", "artifacts.sqlite"), {
    readonly: true,
    fileMustExist: true,
  });
  const object = database.prepare(`
    SELECT o.object_path AS path
    FROM artifact_records r
    JOIN artifact_objects o ON o.sha256 = r.object_sha256
    WHERE r.artifact_id = ?
  `).get(result.artifactId) as { path: string };
  database.close();
  await unlink(object.path);

  await assert.rejects(
    fixture.artifacts.execute(input, "owner-completed-cas"),
    hasCode("STATE_CORRUPTED"),
  );
});

test("directory finalization checkpoint failure retries without duplicate AVAILABLE record or refcount", async (t) => {
  const root = await mkdtemp(join(tmpdir(), "devspace-v2-artifact-finalization-retry-"));
  t.after(() => rm(root, { recursive: true, force: true }));
  const source = join(root, "source");
  const destination = join(root, "destination");
  await mkdir(source, { recursive: true });
  await writeFile(join(source, "payload.txt"), "finalization-retry\n");
  let checkpointDirectory: string | undefined;
  const fixture = await createFixture(t, [], {
    root,
    copyHooks: {
      async afterEntryCheckpointed(event) {
        if (event.completedEntries !== event.totalEntries || checkpointDirectory) return;
        checkpointDirectory = dirname(event.checkpointPath);
        await chmod(checkpointDirectory, 0o500);
      },
    },
  });
  const input = {
    operation: "copy" as const,
    source: { path: source },
    destination: { path: destination },
  };

  await assert.rejects(
    fixture.artifacts.execute(input, "owner-finalization-retry"),
    (error: unknown) => (error as NodeJS.ErrnoException).code === "EACCES",
  );
  assert.ok(checkpointDirectory);
  await chmod(checkpointDirectory, 0o700);

  const databasePath = join(root, "artifact-staging", "artifacts.sqlite");
  const afterFault = readArtifactCommitCounts(databasePath);
  assert.equal(afterFault.records, 1);
  assert.equal(afterFault.references, 1);
  assert.equal(afterFault.totalBytes > 0, true);
  assert.equal(afterFault.activeReservations, 0);
  assert.match(afterFault.artifactId, /^[0-9a-f-]{36}$/u);

  await fixture.artifacts.close();
  const resumed = new UniversalArtifactService(fixture.filesystem, {
    stagingRoot: join(root, "artifact-staging"),
    maximumArtifactBytes: 2 * 1024 * 1024 * 1024,
    maximumTotalBytes: afterFault.totalBytes,
    maximumEntries: 1,
    ttlMs: 60_000,
  });
  t.after(() => resumed.close());
  const result = await resumed.execute(input, "owner-finalization-retry");

  assert.equal(result.artifactId, afterFault.artifactId);
  assert.deepEqual(readArtifactCommitCounts(databasePath), {
    records: 1,
    references: 1,
    totalBytes: afterFault.totalBytes,
    activeReservations: 0,
    artifactId: afterFault.artifactId,
  });
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
  assert.match(String(published.resourceUri), /^devspace:\/\/v1\/artifact\/[0-9a-f-]{36}$/u);
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

test("artifact URI and hash-only HTTP capability survive service close and reopen within TTL", async (t) => {
  const root = await mkdtemp(join(tmpdir(), "devspace-v2-artifact-restart-"));
  t.after(() => rm(root, { recursive: true, force: true }));
  let baseUrl = "";
  const fixture = await createFixture(t, [], { root, baseUrl: () => baseUrl });
  let active = fixture.artifacts;
  const app = createMcpExpressApp({ host: "127.0.0.1" });
  app.get("/artifacts-next/:artifactId", (req, res) => {
    void active.handleHttp(req, res);
  });
  const server = app.listen(0, "127.0.0.1");
  await new Promise<void>((resolve, reject) => {
    server.once("listening", resolve);
    server.once("error", reject);
  });
  t.after(() => closeServer(server));
  baseUrl = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;

  const path = join(root, "restart.txt");
  await writeFile(path, "restart-continuity\n");
  const published = await active.execute({
    operation: "publish",
    source: { path, mimeType: "text/plain" },
    ttlSeconds: 60,
  }, "owner-restart");
  const resourceUri = String(published.resourceUri);
  const downloadUrl = String(published.downloadUrl);
  const rawToken = new URL(downloadUrl).searchParams.get("token")!;

  const database = new Database(join(root, "artifact-staging", "artifacts.sqlite"), {
    readonly: true,
    fileMustExist: true,
  });
  const columns = database.prepare("PRAGMA table_info(artifact_records)").all() as Array<{ name: string }>;
  assert.equal(columns.some((column) => column.name === "token"), false);
  const stored = database.prepare("SELECT token_hash AS tokenHash FROM artifact_records").get() as { tokenHash: string };
  assert.equal(stored.tokenHash, createHash("sha256").update(rawToken).digest("hex"));
  assert.equal(JSON.stringify(stored).includes(rawToken), false);
  database.close();

  await active.close();
  active = new UniversalArtifactService(fixture.filesystem, {
    stagingRoot: join(root, "artifact-staging"),
    baseUrl: () => baseUrl,
    maximumArtifactBytes: 2 * 1024 * 1024 * 1024,
    maximumTotalBytes: 10_000_000,
    maximumEntries: 8,
    ttlMs: 60_000,
  });
  t.after(() => active.close());

  const read = await active.readResource(resourceUri, "owner-restart");
  assert.equal(Buffer.from(String(read.blobBase64), "base64").toString(), "restart-continuity\n");
  const response = await fetch(downloadUrl);
  assert.equal(response.status, 200);
  assert.equal(await response.text(), "restart-continuity\n");
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
  filesystem: UniversalFilesystemService;
}

interface RemoteArtifactFixture extends Fixture {
  destinationDispatches: number;
  sftpGets: number;
  sftpPuts: number;
  sftpGetPaths: readonly string[];
  sftpPutPaths: readonly string[];
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
    copyHooks?: ArtifactCopyHooks;
    metrics?: UniversalBrokerMetrics;
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
    copyHooks: overrides.copyHooks,
    metrics: overrides.metrics,
  });
  t.after(() => artifacts.close());
  return { root, artifacts, filesystem };
}

async function createRemoteArtifactFixture(
  t: test.TestContext,
  overrides: {
    copyHooks?: ArtifactCopyHooks;
    maximumTotalBytes?: number;
  } = {},
): Promise<RemoteArtifactFixture> {
  const root = await mkdtemp(join(tmpdir(), "devspace-v2-artifact-remote-test-"));
  t.after(() => rm(root, { recursive: true, force: true }));
  await mkdir(join(root, "remote-a"), { recursive: true });
  await mkdir(join(root, "remote-b"), { recursive: true });
  const targetConfig = join(root, "targets.json");
  await writeFile(targetConfig, JSON.stringify({
    version: 1,
    targets: {
      "remote-a": {
        displayName: "Remote a fixture",
        aliases: ["remote-a"],
        transport: "ssh",
        sshHost: "remote-a.invalid",
        platform: "linux",
        defaultCwd: join(root, "remote-a"),
      },
      "remote-b": {
        displayName: "Remote b fixture",
        aliases: ["remote-b"],
        transport: "ssh",
        sshHost: "remote-b.invalid",
        platform: "linux",
        defaultCwd: join(root, "remote-b"),
      },
    },
  }));
  const serverConfig = loadConfig({
    DEVSPACE_CONFIG_DIR: join(root, ".config"),
    DEVSPACE_ALLOWED_ROOTS: root,
    DEVSPACE_STATE_DIR: join(root, "legacy-state"),
    DEVSPACE_WORKTREE_ROOT: join(root, "worktrees"),
    DEVSPACE_OAUTH_OWNER_TOKEN: "v2-artifact-remote-test-owner-credential-123456",
    DEVSPACE_PUBLIC_BASE_URL: "http://127.0.0.1:17676",
    DEVSPACE_LOG_LEVEL: "silent",
    DEVSPACE_SKILL_PATHS: join(root, "skills"),
  });
  const targets = new TargetRegistry({
    configPath: targetConfig,
    execute: (async (executable: string, args: string[]) => {
      if (executable === "sftp") return { stdout: "", stderr: "" };
      if (args.includes("-tt")) return { stdout: "__DEVSPACE_PTY_OK__\r\n", stderr: "" };
      return {
        stdout: [
          "__DEVSPACE_TARGET_V1__",
          "kernel=Linux",
          "architecture=x86_64",
          `home=${root}`,
          `temporary=${root}`,
          "git=1",
          "rsync=0",
          "setpriv_boundary=1",
          "sandbox_boundary=0",
          "",
        ].join("\n"),
        stderr: "",
      };
    }) as never,
  });
  await Promise.all([
    targets.probe("remote-a"),
    targets.probe("remote-b"),
  ]);
  const contexts = new ContextRegistry({
    storePath: join(root, "v2-state", "contexts.json"),
    targets,
    serverConfig,
  });
  let destinationDispatches = 0;
  const execution = {
    async run(
      input: { command: string; target?: string },
      _callContext?: CapabilityCallContext,
    ): Promise<UniversalProcessSnapshot> {
      if (input.target === "remote-b") destinationDispatches += 1;
      const started = Date.now();
      try {
        const result = await execFileAsync("/bin/sh", ["-lc", input.command], {
          maxBuffer: 2 * 1024 * 1024,
          env: { ...process.env, HOME: root },
        });
        return processSnapshot(result.stdout, 0, started, input.target ?? "remote-a");
      } catch (error) {
        const failure = error as Error & { stdout?: string; stderr?: string; code?: number };
        return processSnapshot(
          `${failure.stdout ?? ""}${failure.stderr ?? ""}`,
          typeof failure.code === "number" ? failure.code : 1,
          started,
          input.target ?? "remote-a",
        );
      }
    },
    stats() { return { active: 0, maximumConcurrent: 32, completed: destinationDispatches }; },
  } as unknown as UniversalExecutionPlane;
  let sftpGets = 0;
  let sftpPuts = 0;
  const sftpGetPaths: string[] = [];
  const sftpPutPaths: string[] = [];
  const filesystem = new UniversalFilesystemService(
    targets,
    contexts,
    execution,
    {
      sshControlDir: join(root, "ssh-control"),
      cursorStore: artifactCursorStore(),
      sftpGet: async ({ localPath, remotePath }) => {
        sftpGets += 1;
        sftpGetPaths.push(remotePath);
        await copyFile(remotePath, localPath);
      },
      sftpPut: async ({ localPath, remotePath }) => {
        sftpPuts += 1;
        sftpPutPaths.push(remotePath);
        await copyFile(localPath, remotePath);
      },
    },
  );
  const artifacts = new UniversalArtifactService(filesystem, {
    stagingRoot: join(root, "artifact-staging"),
    maximumArtifactBytes: 2 * 1024 * 1024 * 1024,
    maximumTotalBytes: overrides.maximumTotalBytes ?? 10_000_000,
    maximumEntries: 8,
    ttlMs: 60_000,
    copyHooks: overrides.copyHooks,
  });
  t.after(() => artifacts.close());
  return {
    root,
    artifacts,
    filesystem,
    get destinationDispatches() { return destinationDispatches; },
    get sftpGets() { return sftpGets; },
    get sftpPuts() { return sftpPuts; },
    get sftpGetPaths() { return sftpGetPaths; },
    get sftpPutPaths() { return sftpPutPaths; },
  };
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

async function runWithDeterministicLocalParentSwap<T>(
  input: {
    destinationRoot: string;
    destinationPath: string;
    outsideRoot: string;
    overwrite: boolean;
  },
  action: () => Promise<T>,
): Promise<{ result: T; swapObserved: boolean }> {
  type MutableFsPromises = {
    copyFile: typeof fs.promises.copyFile;
    link: typeof fs.promises.link;
    rename: typeof fs.promises.rename;
  };
  type SpawnLike = (
    command: string,
    args?: readonly string[],
    options?: SpawnOptions,
  ) => ChildProcess;
  const mutableFs = fs.promises as MutableFsPromises;
  const originalCopyFile = mutableFs.copyFile;
  const originalLink = mutableFs.link;
  const originalRename = mutableFs.rename;
  const originalSymlink = fs.promises.symlink;
  const originalUnlink = fs.promises.unlink;
  const originalSpawn = childProcess.spawn as unknown as SpawnLike;
  const hiddenRoot = `${input.destinationRoot}.inode-bound-preimage`;
  let swapped = false;
  let swapObserved = false;
  let stagedOutside = false;

  const swapPublicRoot = async (): Promise<void> => {
    if (swapped) return;
    await originalRename(input.destinationRoot, hiddenRoot);
    await originalSymlink(input.outsideRoot, input.destinationRoot, "dir");
    swapped = true;
    swapObserved = true;
  };
  const restorePublicRoot = async (): Promise<void> => {
    if (!swapped) return;
    await originalUnlink(input.destinationRoot);
    await originalRename(hiddenRoot, input.destinationRoot);
    swapped = false;
  };
  const isLegacyTemporary = (value: unknown): boolean => {
    const path = String(value);
    return dirname(path) === input.destinationRoot
      && basename(path).startsWith(".devspace-artifact-copy-")
      && basename(path).endsWith(".tmp");
  };

  mutableFs.copyFile = (async (source, destination, mode) => {
    if (!isLegacyTemporary(destination)) {
      return originalCopyFile(source, destination, mode);
    }
    await swapPublicRoot();
    try {
      const result = await originalCopyFile(source, destination, mode);
      stagedOutside = true;
      return result;
    } finally {
      await restorePublicRoot();
    }
  }) as typeof fs.promises.copyFile;
  mutableFs.link = (async (existingPath, newPath) => {
    if (stagedOutside && String(newPath) === input.destinationPath && !swapped) {
      await swapPublicRoot();
    }
    return originalLink(existingPath, newPath);
  }) as typeof fs.promises.link;
  mutableFs.rename = (async (oldPath, newPath) => {
    if (
      input.overwrite
      && stagedOutside
      && String(newPath) === input.destinationPath
      && isLegacyTemporary(oldPath)
      && !swapped
    ) {
      await swapPublicRoot();
    }
    return originalRename(oldPath, newPath);
  }) as typeof fs.promises.rename;
  childProcess.spawn = ((command: string, args?: readonly string[], options?: SpawnOptions) => {
    const child = originalSpawn(command, args, options);
    if (
      Array.isArray(args)
      && args.some((argument) => typeof argument === "string"
        && argument.includes("DEVSPACE_BOUND_LOCAL_PUBLICATION_HELPER"))
      && child.stdin
    ) {
      const stdin = child.stdin;
      const originalEnd = stdin.end.bind(stdin) as (...args: unknown[]) => typeof stdin;
      (stdin as unknown as { end: (...args: unknown[]) => typeof stdin }).end = (...endArgs: unknown[]) => {
        const commandText = typeof endArgs[0] === "string"
          ? endArgs[0]
          : Buffer.isBuffer(endArgs[0])
            ? endArgs[0].toString("utf8")
            : "";
        if (commandText.includes("publish") && !swapped) {
          void swapPublicRoot().then(
            () => originalEnd(...endArgs),
            (error: unknown) => stdin.destroy(error as Error),
          );
          return stdin;
        }
        return originalEnd(...endArgs);
      };
    }
    return child;
  }) as unknown as typeof childProcess.spawn;
  syncBuiltinESMExports();

  try {
    const result = await action();
    return { result, swapObserved };
  } finally {
    mutableFs.copyFile = originalCopyFile;
    mutableFs.link = originalLink;
    mutableFs.rename = originalRename;
    childProcess.spawn = originalSpawn as unknown as typeof childProcess.spawn;
    syncBuiltinESMExports();
    await restorePublicRoot();
    await rm(hiddenRoot, { recursive: true, force: true });
  }
}

function readArtifactCommitCounts(databasePath: string): {
  records: number;
  references: number;
  totalBytes: number;
  activeReservations: number;
  artifactId: string;
} {
  const database = new Database(databasePath, { readonly: true, fileMustExist: true });
  try {
    const records = database.prepare(`
      SELECT COUNT(*) AS count, MIN(artifact_id) AS artifactId
      FROM artifact_records WHERE state = 'AVAILABLE'
    `).get() as { count: number; artifactId: string };
    const objects = database.prepare(`
      SELECT COALESCE(SUM(ref_count), 0) AS count, COALESCE(SUM(size), 0) AS totalBytes
      FROM artifact_objects
      WHERE state = 'AVAILABLE'
    `).get() as { count: number; totalBytes: number };
    const reservations = database.prepare(`
      SELECT COUNT(*) AS count FROM artifact_reservations WHERE state = 'ACTIVE'
    `).get() as { count: number };
    return {
      records: records.count,
      references: objects.count,
      totalBytes: objects.totalBytes,
      activeReservations: reservations.count,
      artifactId: records.artifactId,
    };
  } finally {
    database.close();
  }
}

function artifactCopyOwner(label: string): CapabilityCallContext {
  return createCapabilityCallContextFromTrustedPrincipal({
    principalKeyFingerprint: createHash("sha256")
      .update(`artifact-copy:${label}`)
      .digest("hex"),
  });
}

function failAfterFirstDirectoryCheckpoint(): ArtifactCopyHooks {
  let failed = false;
  return {
    afterEntryCheckpointed(event) {
      if (!failed && event.completedEntries === 1) {
        failed = true;
        throw new Error("simulated-remote-copy-interruption");
      }
    },
  };
}

async function leftoverArtifactCopyStaging(root: string): Promise<number> {
  const stagingRoot = join(root, "artifact-staging");
  const entries = await readdir(stagingRoot);
  return entries.filter((entry) => entry.startsWith("copy-entry-") || entry.startsWith("copy-manifest-")).length;
}

function artifactCursorStore(): SignedSnapshotCursorStore {
  return new SignedSnapshotCursorStore({
    currentKey: {
      keyId: "artifact-copy-test-current",
      secret: Buffer.alloc(32, 0x61),
    },
    ttlMs: 60_000,
    maximumSnapshotsPerPrincipal: 128,
  });
}

function processSnapshot(
  output: string,
  exitCode: number | undefined,
  startedAt: number,
  targetId: string,
): UniversalProcessSnapshot {
  return {
    processId: `proc_${targetId}`,
    targetId,
    transport: "ssh",
    cwd: "/",
    tty: false,
    state: "EXITED",
    startedAt: new Date(startedAt).toISOString(),
    endedAt: new Date().toISOString(),
    wallTimeMs: Date.now() - startedAt,
    output,
    outputTruncated: false,
    outputBytes: Buffer.byteLength(output),
    outputFileTruncated: false,
    outputOffsets: {
      global: Buffer.byteLength(output),
      stdout: Buffer.byteLength(output),
      stderr: 0,
      pty: 0,
    },
    resourceUri: `devspace://process/proc_${targetId}/output/0/1048576`,
    durable: false,
    ...(exitCode === undefined ? {} : { exitCode }),
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
