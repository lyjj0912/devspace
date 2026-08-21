import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { createHash, randomUUID } from "node:crypto";
import {
  chmod,
  copyFile,
  lstat,
  mkdir,
  mkdtemp,
  readdir,
  readFile,
  readlink,
  rename,
  rm,
  stat,
  symlink,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { promisify } from "node:util";
import { loadConfig } from "../config.js";
import { ContextRegistry } from "./contexts.js";
import {
  createCapabilityCallContextFromTrustedPrincipal,
  type CapabilityCallContext,
} from "./capability-call-context.js";
import {
  CursorCapabilityError,
  SignedSnapshotCursorStore,
} from "./cursor-capability.js";
import type {
  UniversalExecutionPlane,
  UniversalProcessSnapshot,
} from "./execution.js";
import { UniversalBrokerError } from "./errors.js";
import {
  UniversalFilesystemService,
  type UniversalFilesystemOptions,
} from "./filesystem.js";
import {
  atomicCopyFile,
  atomicWriteBuffer,
  nodeAtomicFilesystemOperations,
  safeMoveFile,
  type AtomicFilesystemOperations,
} from "./filesystem-atomic.js";
import { RecoverableFilesystemTrash } from "./filesystem-trash.js";
import {
  createLocalFilesystemSyncAdapter,
  type FilesystemSyncAdapter,
} from "./filesystem-sync.js";
import {
  REMOTE_WINDOWS_FILESYSTEM_RESULT_MARKER,
  windowsFilesystemCommand,
} from "./remote-windows-filesystem-helper.js";
import { TargetRegistry } from "./targets.js";

const execFileAsync = promisify(execFile);

test("fs performs a complete local lifecycle without a workspace boundary", async (t) => {
  const fixture = await createFixture(t);
  const directory = join(fixture.root, "storage");
  const source = join(directory, "source.txt");
  const copy = join(directory, "copy.txt");
  const moved = join(directory, "moved.txt");

  await fixture.filesystem.execute({
    operation: "mkdir",
    path: directory,
  });
  const written = await fixture.filesystem.execute({
    operation: "write",
    path: source,
    content: "alpha\nbeta\n",
  });
  assert.equal(written.path, source);
  assert.equal(typeof written.sha256, "string");

  const read = await fixture.filesystem.execute({ operation: "read", path: source });
  assert.equal(read.encoding, "utf8");
  assert.equal(read.content, "alpha\nbeta\n");

  const hash = await fixture.filesystem.execute({ operation: "hash", path: source });
  assert.equal(hash.sha256, written.sha256);
  await fixture.filesystem.execute({
    operation: "copy",
    path: source,
    destination: copy,
  });
  await fixture.filesystem.execute({
    operation: "move",
    path: copy,
    destination: moved,
  });
  assert.equal(await readFile(moved, "utf8"), "alpha\nbeta\n");

  const listed = await fixture.filesystem.execute({
    operation: "list",
    path: directory,
    limit: 1,
  }, filesystemCursorCallContext("local-lifecycle-list"));
  assert.equal((listed.entries as unknown[]).length, 1);
  assert.equal(typeof listed.nextCursor, "string");

  await fixture.filesystem.execute({
    operation: "remove",
    path: moved,
    disposition: "permanent",
  });
  await fixture.filesystem.execute({
    operation: "remove",
    path: source,
    disposition: "permanent",
  });
  await fixture.filesystem.execute({
    operation: "remove",
    path: directory,
    disposition: "permanent",
    recursive: true,
  });
  await assert.rejects(lstat(directory));
});

test("fs.list uses an opaque owner/path/generation-bound snapshot cursor", async (t) => {
  const fixture = await createFixture(t);
  const directory = join(fixture.root, "cursor-list");
  const otherDirectory = join(fixture.root, "cursor-list-other");
  await mkdir(directory);
  await mkdir(otherDirectory);
  await Promise.all([
    writeFile(join(directory, "b.txt"), "b\n"),
    writeFile(join(directory, "a.txt"), "a\n"),
    writeFile(join(directory, "c.txt"), "c\n"),
    writeFile(join(otherDirectory, "a.txt"), "other\n"),
  ]);
  const owner = filesystemCursorCallContext("list-owner");
  const otherOwner = filesystemCursorCallContext("list-other-owner");
  await assert.rejects(
    fixture.filesystem.execute({ operation: "list", path: directory, limit: 1 }),
    hasCode("AUTHENTICATION_FAILED"),
  );
  const first = await fixture.filesystem.execute({
    operation: "list",
    path: directory,
    limit: 1,
  }, owner);
  assert.deepEqual(first.entries, [{ name: "a.txt", type: "file" }]);
  assert.equal(typeof first.nextCursor, "string");
  assert.doesNotMatch(String(first.nextCursor), /^\d+$/u);

  const second = await fixture.filesystem.execute({
    operation: "list",
    path: directory,
    cursor: String(first.nextCursor),
    limit: 1,
  }, owner);
  assert.deepEqual(second.entries, [{ name: "b.txt", type: "file" }]);
  assert.equal(second.offset, 1);
  await assert.rejects(
    fixture.filesystem.execute({
      operation: "list",
      path: directory,
      cursor: "1",
      limit: 1,
    }, owner),
    hasCursorReason("CURSOR_INVALID"),
  );
  await assert.rejects(
    fixture.filesystem.execute({
      operation: "list",
      path: directory,
      cursor: String(first.nextCursor),
      limit: 1,
    }, otherOwner),
    hasCursorReason("CURSOR_INVALID"),
  );
  await assert.rejects(
    fixture.filesystem.execute({
      operation: "list",
      path: otherDirectory,
      cursor: String(first.nextCursor),
      limit: 1,
    }, owner),
    hasCursorReason("CURSOR_INVALID"),
  );

  await writeFile(join(directory, "d.txt"), "d\n");
  await assert.rejects(
    fixture.filesystem.execute({
      operation: "list",
      path: directory,
      cursor: String(first.nextCursor),
      limit: 1,
    }, owner),
    hasCursorReason("CURSOR_STALE"),
  );

  const fresh = await fixture.filesystem.execute({
    operation: "list",
    path: directory,
    limit: 1,
  }, owner);
  const restarted = new UniversalFilesystemService(
    fixture.targets,
    fixture.contexts,
    {} as UniversalExecutionPlane,
    {
      sshControlDir: join(fixture.root, "ssh-control"),
      cursorStore: filesystemCursorStore(),
    },
  );
  await assert.rejects(
    restarted.execute({
      operation: "list",
      path: directory,
      cursor: String(fresh.nextCursor),
      limit: 1,
    }, owner),
    hasCursorReason("CURSOR_STALE"),
  );
});

test("fs pagination quota never evicts a live cursor and expiry remains typed", async (t) => {
  const clock = { value: 1_787_300_000_000 };
  const fixture = await createFixture(t, {
    cursorStore: filesystemCursorStore(() => clock.value, 100, 1),
  });
  const firstDirectory = join(fixture.root, "cursor-quota-first");
  const secondDirectory = join(fixture.root, "cursor-quota-second");
  await Promise.all([mkdir(firstDirectory), mkdir(secondDirectory)]);
  await Promise.all([
    writeFile(join(firstDirectory, "a.txt"), "a\n"),
    writeFile(join(firstDirectory, "b.txt"), "b\n"),
    writeFile(join(secondDirectory, "c.txt"), "c\n"),
    writeFile(join(secondDirectory, "d.txt"), "d\n"),
  ]);
  const owner = filesystemCursorCallContext("quota-owner");
  const first = await fixture.filesystem.execute({
    operation: "list",
    path: firstDirectory,
    limit: 1,
  }, owner);
  await assert.rejects(
    fixture.filesystem.execute({
      operation: "list",
      path: secondDirectory,
      limit: 1,
    }, owner),
    hasCursorReason("CURSOR_QUOTA_EXCEEDED"),
  );
  assert.deepEqual((await fixture.filesystem.execute({
    operation: "list",
    path: firstDirectory,
    cursor: String(first.nextCursor),
    limit: 1,
  }, owner)).entries, [{ name: "b.txt", type: "file" }]);
  clock.value += 101;
  await assert.rejects(
    fixture.filesystem.execute({
      operation: "list",
      path: firstDirectory,
      cursor: String(first.nextCursor),
      limit: 1,
    }, owner),
    hasCursorReason("CURSOR_EXPIRED"),
  );
});

test("fs.search snapshots bounded results and binds the exact query", async (t) => {
  const fixture = await createFixture(t);
  const directory = join(fixture.root, "cursor-search");
  await mkdir(directory);
  await writeFile(join(directory, "one.txt"), "needle one\nneedle two\n");
  await writeFile(join(directory, "two.txt"), "needle three\n");
  const owner = filesystemCursorCallContext("search-owner");
  const first = await fixture.filesystem.execute({
    operation: "search",
    path: directory,
    query: "needle",
    limit: 1,
  }, owner);
  assert.deepEqual(first.results, [{
    path: join(directory, "one.txt"),
    line: 1,
    text: "needle one",
  }]);
  assert.equal(typeof first.nextCursor, "string");
  const second = await fixture.filesystem.execute({
    operation: "search",
    path: directory,
    query: "needle",
    cursor: String(first.nextCursor),
    limit: 1,
  }, owner);
  assert.deepEqual(second.results, [{
    path: join(directory, "one.txt"),
    line: 2,
    text: "needle two",
  }]);
  assert.equal(second.offset, 1);
  await assert.rejects(
    fixture.filesystem.execute({
      operation: "search",
      path: directory,
      query: "different",
      cursor: String(first.nextCursor),
      limit: 1,
    }, owner),
    hasCursorReason("CURSOR_INVALID"),
  );
  await writeFile(join(directory, "one.txt"), "needle changed\n");
  await assert.rejects(
    fixture.filesystem.execute({
      operation: "search",
      path: directory,
      query: "needle",
      cursor: String(first.nextCursor),
      limit: 1,
    }, owner),
    hasCursorReason("CURSOR_STALE"),
  );
});

test("fs.sync plans without tree side effects and applies the immutable digest once", async (t) => {
  const fixture = await createFixture(t);
  const source = join(fixture.root, "sync-source");
  const destination = join(fixture.root, "sync-destination");
  await mkdir(source, { recursive: true });
  await mkdir(destination, { recursive: true });
  await writeFile(join(source, "copy.txt"), "copy\n");
  await writeFile(join(source, "update.txt"), "new\n");
  await writeFile(join(destination, "update.txt"), "old\n");
  await writeFile(join(destination, "delete.txt"), "delete\n");
  const callContext = filesystemSyncCallContext("plan-apply");

  const plan = await fixture.filesystem.execute({
    operation: "sync",
    path: source,
    destination,
    sync: {
      phase: "plan",
      deleteMode: "trash",
      conflictStrategy: "fail",
    },
  }, callContext);
  assert.equal(plan.phase, "plan");
  assert.match(String(plan.planId), /^sync_plan_/u);
  assert.match(String(plan.planDigest), /^[a-f0-9]{64}$/u);
  assert.deepEqual(syncEntryPaths(plan.copySet), ["copy.txt"]);
  assert.deepEqual(syncEntryPaths(plan.updateSet), ["update.txt"]);
  assert.deepEqual(syncEntryPaths(plan.deleteSet), ["delete.txt"]);
  assert.equal(await readFile(join(destination, "update.txt"), "utf8"), "old\n");
  assert.equal(await readFile(join(destination, "delete.txt"), "utf8"), "delete\n");
  await assert.rejects(readFile(join(destination, "copy.txt"), "utf8"), { code: "ENOENT" });

  const applyInput = {
    operation: "sync" as const,
    path: source,
    destination,
    sync: {
      phase: "apply" as const,
      planId: String(plan.planId),
      planDigest: String(plan.planDigest),
    },
  };
  const applied = await fixture.filesystem.execute(applyInput, callContext);
  assert.equal(applied.phase, "apply");
  assert.equal(applied.synchronized, true);
  assert.deepEqual(await Promise.all([
    readFile(join(destination, "copy.txt"), "utf8"),
    readFile(join(destination, "update.txt"), "utf8"),
  ]), ["copy\n", "new\n"]);
  await assert.rejects(readFile(join(destination, "delete.txt"), "utf8"), { code: "ENOENT" });

  const replay = await fixture.filesystem.execute(applyInput, callContext);
  assert.equal(replay.replayed, true);
  assert.equal(replay.synchronized, true);
});

test("fs.sync rejects tampered and stale plans before mutation", async (t) => {
  const fixture = await createFixture(t);
  const source = join(fixture.root, "sync-stale-source");
  const destination = join(fixture.root, "sync-stale-destination");
  await mkdir(source, { recursive: true });
  await mkdir(destination, { recursive: true });
  await writeFile(join(source, "value.txt"), "planned\n");
  const callContext = filesystemSyncCallContext("stale");
  const plan = await fixture.filesystem.execute({
    operation: "sync",
    path: source,
    destination,
    sync: { phase: "plan" },
  }, callContext);
  await assert.rejects(
    fixture.filesystem.execute({
      operation: "sync",
      path: source,
      destination,
      sync: {
        phase: "apply",
        planId: String(plan.planId),
        planDigest: "0".repeat(64),
      },
    }, callContext),
    hasCode("SYNC_PLAN_STALE"),
  );
  await writeFile(join(source, "value.txt"), "changed-after-plan\n");
  await assert.rejects(
    fixture.filesystem.execute({
      operation: "sync",
      path: source,
      destination,
      sync: {
        phase: "apply",
        planId: String(plan.planId),
        planDigest: String(plan.planDigest),
      },
    }, callContext),
    hasCode("SYNC_PLAN_STALE"),
  );
  await assert.rejects(readFile(join(destination, "value.txt"), "utf8"), { code: "ENOENT" });
});

test("fs.sync exposes type conflicts and fail strategy preserves the destination", async (t) => {
  const fixture = await createFixture(t);
  const source = join(fixture.root, "sync-conflict-source");
  const destination = join(fixture.root, "sync-conflict-destination");
  await mkdir(source, { recursive: true });
  await mkdir(join(destination, "node"), { recursive: true });
  await writeFile(join(source, "node"), "source-file\n");
  await writeFile(join(destination, "node", "child.txt"), "destination-child\n");
  const callContext = filesystemSyncCallContext("conflict");
  const plan = await fixture.filesystem.execute({
    operation: "sync",
    path: source,
    destination,
    sync: { phase: "plan", conflictStrategy: "fail" },
  }, callContext);
  assert.deepEqual(syncEntryPaths(plan.conflictSet), ["node"]);
  await assert.rejects(
    fixture.filesystem.execute({
      operation: "sync",
      path: source,
      destination,
      sync: {
        phase: "apply",
        planId: String(plan.planId),
        planDigest: String(plan.planDigest),
      },
    }, callContext),
    hasCode("SYNC_CONFLICT"),
  );
  assert.equal(await readFile(join(destination, "node", "child.txt"), "utf8"), "destination-child\n");
});

test("fs.sync resumes a post-mutation checkpoint without duplicating the entry", async (t) => {
  const mutationCounts = new Map<string, number>();
  let interruptOnce = true;
  let syncAdapter!: FilesystemSyncAdapter;
  const fixture = await createFixture(t, ({ root }) => createFixtureLocalSyncAdapter(
    root,
    (base) => {
      syncAdapter = {
        ...base,
        applyOperation: async (input) => {
          if (input.operation.kind.includes("FILE")) {
            mutationCounts.set(
              input.operation.path,
              (mutationCounts.get(input.operation.path) ?? 0) + 1,
            );
          }
          const result = await base.applyOperation(input);
          if (interruptOnce && input.operation.kind.includes("FILE")) {
            input.persistPartialResult?.(result);
            interruptOnce = false;
            throw new UniversalBrokerError(
              "TRANSPORT_INTERRUPTED",
              "Transport interrupted after mutation and before checkpoint.",
            );
          }
          return result;
        },
      };
      return syncAdapter;
    },
  ));
  const source = join(fixture.root, "sync-resume-source");
  const destination = join(fixture.root, "sync-resume-destination");
  await mkdir(source, { recursive: true });
  await mkdir(destination, { recursive: true });
  await writeFile(join(source, "a.txt"), "a\n");
  await writeFile(join(source, "b.txt"), "b\n");
  const callContext = filesystemSyncCallContext("resume");
  const plan = await fixture.filesystem.execute({
    operation: "sync",
    path: source,
    destination,
    sync: { phase: "plan" },
  }, callContext);
  const applyInput = {
    operation: "sync" as const,
    path: source,
    destination,
    sync: {
      phase: "apply" as const,
      planId: String(plan.planId),
      planDigest: String(plan.planDigest),
    },
  };
  await assert.rejects(
    fixture.filesystem.execute(applyInput, callContext),
    hasCode("TRANSPORT_INTERRUPTED"),
  );

  const restarted = new UniversalFilesystemService(
    fixture.targets,
    fixture.contexts,
    {} as UniversalExecutionPlane,
    {
      sshControlDir: join(fixture.root, "ssh-control"),
      trashRoot: join(fixture.root, "filesystem-trash"),
      syncAdapter,
    },
  );
  const resumed = await restarted.execute(applyInput, callContext);
  assert.equal(resumed.synchronized, true);
  assert.equal(resumed.resumedEntries, 1);
  assert.deepEqual(Object.fromEntries(mutationCounts), { "a.txt": 1, "b.txt": 1 });
  assert.deepEqual(await Promise.all([
    readFile(join(destination, "a.txt"), "utf8"),
    readFile(join(destination, "b.txt"), "utf8"),
  ]), ["a\n", "b\n"]);
  const replay = await restarted.execute(applyInput, callContext);
  assert.equal(replay.replayed, true);
  assert.deepEqual(Object.fromEntries(mutationCounts), { "a.txt": 1, "b.txt": 1 });
});

test("fs.sync resumes a permanent deletion checkpoint without deleting twice", async (t) => {
  let permanentDeleteDispatches = 0;
  let interruptOnce = true;
  let syncAdapter!: FilesystemSyncAdapter;
  const fixture = await createFixture(t, ({ root }) => createFixtureLocalSyncAdapter(
    root,
    (base) => {
      syncAdapter = {
        ...base,
        applyOperation: async (input) => {
          if (input.operation.kind === "DELETE_ENTRY") permanentDeleteDispatches += 1;
          const result = await base.applyOperation(input);
          if (interruptOnce && input.operation.kind === "DELETE_ENTRY") {
            input.persistPartialResult?.(result);
            interruptOnce = false;
            throw new UniversalBrokerError(
              "TRANSPORT_INTERRUPTED",
              "Transport interrupted after permanent deletion and before checkpoint.",
            );
          }
          return result;
        },
      };
      return syncAdapter;
    },
  ));
  const source = join(fixture.root, "sync-permanent-resume-source");
  const destination = join(fixture.root, "sync-permanent-resume-destination");
  await mkdir(source, { recursive: true });
  await mkdir(destination, { recursive: true });
  await writeFile(join(destination, "delete.txt"), "delete\n");
  const callContext = filesystemSyncCallContext("permanent-resume");
  const plan = await fixture.filesystem.execute({
    operation: "sync",
    path: source,
    destination,
    sync: { phase: "plan", deleteMode: "permanent" },
  }, callContext);
  const applyInput = {
    operation: "sync" as const,
    path: source,
    destination,
    sync: {
      phase: "apply" as const,
      planId: String(plan.planId),
      planDigest: String(plan.planDigest),
    },
  };
  await assert.rejects(
    fixture.filesystem.execute(applyInput, callContext),
    hasCode("TRANSPORT_INTERRUPTED"),
  );
  await assert.rejects(readFile(join(destination, "delete.txt"), "utf8"), { code: "ENOENT" });

  const restarted = new UniversalFilesystemService(
    fixture.targets,
    fixture.contexts,
    {} as UniversalExecutionPlane,
    {
      sshControlDir: join(fixture.root, "ssh-control"),
      trashRoot: join(fixture.root, "filesystem-trash"),
      syncAdapter,
    },
  );
  const resumed = await restarted.execute(applyInput, callContext);
  assert.equal(resumed.synchronized, true);
  assert.equal(resumed.resumedEntries, 1);
  assert.equal(permanentDeleteDispatches, 1);
  assert.ok((resumed.receipts as Array<Record<string, unknown>>).some(
    (receipt) => receipt.deleted === "delete.txt" && receipt.disposition === "permanent",
  ));
  assert.equal((await restarted.execute(applyInput, callContext)).replayed, true);
  assert.equal(permanentDeleteDispatches, 1);
});

test("fs.sync source-wins replaces a type conflict through recoverable trash", async (t) => {
  const fixture = await createFixture(t);
  const source = join(fixture.root, "sync-source-wins-source");
  const destination = join(fixture.root, "sync-source-wins-destination");
  await mkdir(source, { recursive: true });
  await mkdir(join(destination, "node"), { recursive: true });
  await writeFile(join(source, "node"), "source-wins\n");
  await writeFile(join(destination, "node", "old.txt"), "old\n");
  const callContext = filesystemSyncCallContext("source-wins");
  const plan = await fixture.filesystem.execute({
    operation: "sync",
    path: source,
    destination,
    sync: { phase: "plan", conflictStrategy: "source-wins" },
  }, callContext);
  assert.deepEqual(syncEntryPaths(plan.conflictSet), ["node"]);
  const applied = await fixture.filesystem.execute({
    operation: "sync",
    path: source,
    destination,
    sync: {
      phase: "apply",
      planId: String(plan.planId),
      planDigest: String(plan.planDigest),
    },
  }, callContext);
  assert.equal(applied.synchronized, true);
  assert.equal(await readFile(join(destination, "node"), "utf8"), "source-wins\n");
  assert.ok((applied.receipts as Array<Record<string, unknown>>).some(
    (receipt) => receipt.replacedConflict === "node" && typeof receipt.recovery === "object",
  ));
});

test("fs.sync resumes an interrupted conflict replacement without duplicate trash", async (t) => {
  let interruptOnce = true;
  let syncAdapter!: FilesystemSyncAdapter;
  const fixture = await createFixture(t, ({ root }) => createFixtureLocalSyncAdapter(
    root,
    (base, trash) => {
      syncAdapter = {
        ...base,
        applyOperation: async (input) => {
          if (interruptOnce && input.operation.kind === "REPLACE_CONFLICT") {
            const destinationPath = input.operation.path === "."
              ? input.destinationRoot
              : join(input.destinationRoot, input.operation.path);
            const recovery = await trash.trash(destinationPath, true);
            input.persistPartialResult?.({ recovery });
            interruptOnce = false;
            throw new UniversalBrokerError(
              "TRANSPORT_INTERRUPTED",
              "Transport interrupted after conflict trash and before publication.",
            );
          }
          return base.applyOperation(input);
        },
      };
      return syncAdapter;
    },
  ));
  const source = join(fixture.root, "sync-conflict-resume-source");
  const destination = join(fixture.root, "sync-conflict-resume-destination");
  await mkdir(source, { recursive: true });
  await mkdir(join(destination, "node"), { recursive: true });
  await writeFile(join(source, "node"), "resumed-source\n");
  await writeFile(join(destination, "node", "old.txt"), "old\n");
  const callContext = filesystemSyncCallContext("conflict-resume");
  const plan = await fixture.filesystem.execute({
    operation: "sync",
    path: source,
    destination,
    sync: { phase: "plan", conflictStrategy: "source-wins" },
  }, callContext);
  const applyInput = {
    operation: "sync" as const,
    path: source,
    destination,
    sync: {
      phase: "apply" as const,
      planId: String(plan.planId),
      planDigest: String(plan.planDigest),
    },
  };
  await assert.rejects(
    fixture.filesystem.execute(applyInput, callContext),
    hasCode("TRANSPORT_INTERRUPTED"),
  );
  await assert.rejects(lstat(join(destination, "node")), { code: "ENOENT" });
  assert.equal((await readdir(join(fixture.root, "filesystem-trash"))).length, 1);

  const restarted = new UniversalFilesystemService(
    fixture.targets,
    fixture.contexts,
    {} as UniversalExecutionPlane,
    {
      sshControlDir: join(fixture.root, "ssh-control"),
      trashRoot: join(fixture.root, "filesystem-trash"),
      syncAdapter,
    },
  );
  const resumed = await restarted.execute(applyInput, callContext);
  assert.equal(resumed.synchronized, true);
  assert.equal(await readFile(join(destination, "node"), "utf8"), "resumed-source\n");
  assert.equal((await readdir(join(fixture.root, "filesystem-trash"))).length, 1);
  assert.ok((resumed.receipts as Array<Record<string, unknown>>).some(
    (receipt) => receipt.replacedConflict === "node" && typeof receipt.recovery === "object",
  ));
  assert.equal((await restarted.execute(applyInput, callContext)).replayed, true);
  assert.equal((await readdir(join(fixture.root, "filesystem-trash"))).length, 1);
});

test("fs.sync binds owner, expiry, and destination snapshot and applies permanent deletion", async (t) => {
  const now = { value: 1_787_080_000_000 };
  const fixture = await createFixture(t, {
    syncNow: () => now.value,
    syncPlanTtlMs: 100,
  });
  const source = join(fixture.root, "sync-binding-source");
  const destination = join(fixture.root, "sync-binding-destination");
  await mkdir(source, { recursive: true });
  await mkdir(destination, { recursive: true });
  await writeFile(join(source, "new.txt"), "new\n");
  await writeFile(join(destination, "delete.txt"), "delete\n");
  const owner = filesystemSyncCallContext("binding-owner");
  const otherOwner = filesystemSyncCallContext("binding-other-owner");
  const plan = await fixture.filesystem.execute({
    operation: "sync",
    path: source,
    destination,
    sync: { phase: "plan", deleteMode: "permanent" },
  }, owner);
  const applyInput = {
    operation: "sync" as const,
    path: source,
    destination,
    sync: {
      phase: "apply" as const,
      planId: String(plan.planId),
      planDigest: String(plan.planDigest),
    },
  };
  await assert.rejects(fixture.filesystem.execute(applyInput, otherOwner), hasCode("SYNC_PLAN_STALE"));
  const permanent = await fixture.filesystem.execute(applyInput, owner);
  assert.equal(permanent.synchronized, true);
  await assert.rejects(readFile(join(destination, "delete.txt"), "utf8"), { code: "ENOENT" });
  assert.ok((permanent.receipts as Array<Record<string, unknown>>).some(
    (receipt) => receipt.deleted === "delete.txt" && receipt.disposition === "permanent",
  ));

  const staleDestinationPlan = await fixture.filesystem.execute({
    operation: "sync",
    path: source,
    destination,
    sync: { phase: "plan" },
  }, owner);
  await writeFile(join(destination, "racer.txt"), "racer\n");
  await assert.rejects(
    fixture.filesystem.execute({
      operation: "sync",
      path: source,
      destination,
      sync: {
        phase: "apply",
        planId: String(staleDestinationPlan.planId),
        planDigest: String(staleDestinationPlan.planDigest),
      },
    }, owner),
    hasCode("SYNC_PLAN_STALE"),
  );
  await rm(join(destination, "racer.txt"));

  const expiredPlan = await fixture.filesystem.execute({
    operation: "sync",
    path: source,
    destination,
    sync: { phase: "plan" },
  }, owner);
  now.value += 101;
  await assert.rejects(
    fixture.filesystem.execute({
      operation: "sync",
      path: source,
      destination,
      sync: {
        phase: "apply",
        planId: String(expiredPlan.planId),
        planDigest: String(expiredPlan.planDigest),
      },
    }, owner),
    hasCode("SYNC_PLAN_STALE"),
  );
});

test("context supplies only target and relative path defaults", async (t) => {
  const fixture = await createFixture(t);
  const project = join(fixture.root, "project");
  await mkdir(project);
  const context = await fixture.contexts.open({ path: project });

  await fixture.filesystem.execute({
    operation: "write",
    contextId: context.contextId,
    path: "nested.txt",
    content: "context-relative\n",
  });
  assert.equal(await readFile(join(project, "nested.txt"), "utf8"), "context-relative\n");

  await fixture.filesystem.execute({
    operation: "write",
    contextId: context.contextId,
    path: join(fixture.root, "outside-context.txt"),
    content: "absolute-authority\n",
  });
  assert.equal(
    await readFile(join(fixture.root, "outside-context.txt"), "utf8"),
    "absolute-authority\n",
  );
});

test("fs patch uses the shared Codex patch engine with a hash precondition", async (t) => {
  const fixture = await createFixture(t);
  const path = join(fixture.root, "note.txt");
  const written = await fixture.filesystem.execute({
    operation: "write",
    path,
    content: "first\nsecond\n",
  });
  const patched = await fixture.filesystem.execute({
    operation: "patch",
    path,
    expectedSha256: String(written.sha256),
    patch: [
      "*** Begin Patch",
      "*** Update File: note.txt",
      "@@",
      " first",
      "-second",
      "+changed",
      "*** End Patch",
    ].join("\n"),
  });
  assert.equal(patched.patched, true);
  assert.equal(await readFile(path, "utf8"), "first\nchanged\n");

  await assert.rejects(
    fixture.filesystem.execute({
      operation: "patch",
      path,
      expectedSha256: "0".repeat(64),
      patch: [
        "*** Begin Patch",
        "*** Update File: note.txt",
        "@@",
        "-changed",
        "+wrong",
        "*** End Patch",
      ].join("\n"),
    }),
    hasCode("PRECONDITION_FAILED"),
  );
});

test("fs bounds read and search output and never publishes through a symlink", async (t) => {
  const fixture = await createFixture(t);
  const root = join(fixture.root, "search");
  await mkdir(root);
  await writeFile(join(root, "one.txt"), "needle one\nother\nneedle two\n");
  await writeFile(join(root, "two.txt"), "needle three\n");
  const target = join(root, "target.txt");
  const link = join(root, "link.txt");
  await writeFile(target, "preserve\n");
  await symlink(target, link);

  const read = await fixture.filesystem.execute({
    operation: "read",
    path: join(root, "one.txt"),
    limit: 6,
  });
  assert.equal(read.content, "needle");
  assert.equal(read.truncated, true);
  assert.equal(read.nextOffset, 6);
  assert.equal(read.nextCursor, undefined);
  const remainder = await fixture.filesystem.execute({
    operation: "read",
    path: join(root, "one.txt"),
    offset: 6,
    limit: 4,
  });
  assert.equal(remainder.content, " one");
  await assert.rejects(
    fixture.filesystem.execute({
      operation: "read",
      path: join(root, "one.txt"),
      cursor: "6",
      limit: 4,
    }),
    hasCode("PRECONDITION_FAILED"),
  );

  const search = await fixture.filesystem.execute({
    operation: "search",
    path: root,
    query: "needle",
    limit: 2,
  }, filesystemCursorCallContext("bounded-search"));
  assert.equal((search.results as unknown[]).length, 2);
  assert.equal(search.truncated, true);

  await assert.rejects(
    fixture.filesystem.execute({
      operation: "write",
      path: link,
      content: "replace\n",
      overwrite: true,
    }),
    hasCode("PERMISSION_DENIED"),
  );
  assert.equal(await readFile(target, "utf8"), "preserve\n");
  const trashed = await fixture.filesystem.execute({ operation: "remove", path: target });
  assert.equal(trashed.disposition, "trash");
  assert.equal(trashed.recoverable, true);
  await fixture.filesystem.execute({
    operation: "restore",
    trashId: String(trashed.trashId),
  });
  assert.equal(await readFile(target, "utf8"), "preserve\n");
});

test("atomic publication rejects a deterministic destination race and preserves the racer", async (t) => {
  const root = await mkdtemp(join(tmpdir(), "devspace-v2-fs-race-test-"));
  t.after(() => rm(root, { recursive: true, force: true }));
  const destination = join(root, "destination.txt");
  await writeFile(destination, "preimage\n");
  let destinationPreimages = 0;
  const filesystem = atomicFilesystemWith({
    lstat: async (path) => {
      if (path === destination) {
        destinationPreimages += 1;
        if (destinationPreimages === 2) await writeFile(destination, "racer\n");
      }
      return nodeAtomicFilesystemOperations.lstat(path);
    },
  });
  await assert.rejects(
    atomicWriteBuffer(destination, Buffer.from("ours\n"), {
      overwrite: true,
      filesystem,
    }),
    hasCode("PRECONDITION_FAILED"),
  );
  assert.equal(await readFile(destination, "utf8"), "racer\n");
  assert.equal(
    (await readdir(root)).some((name) => name.startsWith(".devspace-v2-")),
    false,
  );
});

test("verified EXDEV fallback never deletes the source after destination corruption", async (t) => {
  const root = await mkdtemp(join(tmpdir(), "devspace-v2-fs-exdev-test-"));
  t.after(() => rm(root, { recursive: true, force: true }));
  const source = join(root, "source.txt");
  const destination = join(root, "destination.txt");
  await writeFile(source, "source-must-survive\n");
  let destinationReadbacks = 0;
  const filesystem = atomicFilesystemWith({
    link: async (existingPath, newPath) => {
      if (newPath === destination && String(existingPath).includes(".devspace-v2-move-source.txt-")) {
        throw filesystemError("EXDEV", "cross-device link");
      }
      return nodeAtomicFilesystemOperations.link(existingPath, newPath);
    },
    lstat: async (path) => {
      const value = await nodeAtomicFilesystemOperations.lstat(path);
      if (path === destination && value.isFile()) destinationReadbacks += 1;
      if (destinationReadbacks >= 2 && String(path).includes(".devspace-v2-move-source.txt-")) {
        destinationReadbacks = 0;
        await writeFile(destination, "corrupt-after-copy\n");
      }
      return value;
    },
  });
  await assert.rejects(
    safeMoveFile(source, destination, {
      overwrite: false,
      filesystem,
    }),
    hasCode("PRECONDITION_FAILED"),
  );
  assert.equal(await readFile(source, "utf8"), "source-must-survive\n");
  assert.equal(await readFile(destination, "utf8"), "corrupt-after-copy\n");
});

test("verified EXDEV deletion quarantines and preserves a late source replacement", async (t) => {
  const root = await mkdtemp(join(tmpdir(), "devspace-v2-fs-exdev-source-race-test-"));
  t.after(() => rm(root, { recursive: true, force: true }));
  const source = join(root, "source.txt");
  const original = join(root, "original.txt");
  const destination = join(root, "destination.txt");
  await writeFile(source, "original-source\n");

  let replacementQuarantine: string | undefined;
  const filesystem = atomicFilesystemWith({
    rename: async (oldPath, newPath) => {
      if (oldPath === source && String(newPath).includes(".devspace-v2-move-source.txt-")) {
        await nodeAtomicFilesystemOperations.rename(source, original);
        await writeFile(source, "late-replacement\n", { flag: "wx" });
      }
      return nodeAtomicFilesystemOperations.rename(oldPath, newPath);
    },
  });
  await assert.rejects(
    safeMoveFile(source, destination, {
      overwrite: false,
      filesystem,
    }),
    (error: unknown) => {
      assert(error instanceof UniversalBrokerError);
      assert.equal(error.code, "PRECONDITION_FAILED");
      assert.equal(error.evidence?.publicSourceRestored, false);
      assert.equal(error.evidence?.quarantineIdentityMatches, false);
      replacementQuarantine = String(error.evidence?.quarantine);
      return true;
    },
  );
  await assert.rejects(readFile(source, "utf8"), { code: "ENOENT" });
  assert.equal(await readFile(original, "utf8"), "original-source\n");
  assert.equal(await readFile(replacementQuarantine!, "utf8"), "late-replacement\n");
  await assert.rejects(readFile(destination, "utf8"), { code: "ENOENT" });
});

test("hard-link move quarantines and preserves a late source replacement", async (t) => {
  const root = await mkdtemp(join(tmpdir(), "devspace-v2-fs-link-source-race-test-"));
  t.after(() => rm(root, { recursive: true, force: true }));
  const source = join(root, "source.txt");
  const original = join(root, "original.txt");
  const destination = join(root, "destination.txt");
  await writeFile(source, "original-source\n");

  let replacementQuarantine: string | undefined;
  const filesystem = atomicFilesystemWith({
    rename: async (oldPath, newPath) => {
      if (oldPath === source && String(newPath).includes(".devspace-v2-move-source.txt-")) {
        await nodeAtomicFilesystemOperations.rename(source, original);
        await writeFile(source, "late-replacement\n", { flag: "wx" });
      }
      return nodeAtomicFilesystemOperations.rename(oldPath, newPath);
    },
  });
  await assert.rejects(
    safeMoveFile(source, destination, {
      overwrite: false,
      filesystem,
    }),
    (error: unknown) => {
      assert(error instanceof UniversalBrokerError);
      assert.equal(error.code, "PRECONDITION_FAILED");
      assert.equal(error.evidence?.publicSourceRestored, false);
      assert.equal(error.evidence?.quarantineIdentityMatches, false);
      replacementQuarantine = String(error.evidence?.quarantine);
      return true;
    },
  );
  await assert.rejects(readFile(source, "utf8"), { code: "ENOENT" });
  assert.equal(await readFile(original, "utf8"), "original-source\n");
  assert.equal(await readFile(replacementQuarantine!, "utf8"), "late-replacement\n");
  await assert.rejects(readFile(destination, "utf8"), { code: "ENOENT" });
});

test("unsupported hard links require explicit overwrite permission for atomic publication", async (t) => {
  const root = await mkdtemp(join(tmpdir(), "devspace-v2-fs-no-hardlink-test-"));
  t.after(() => rm(root, { recursive: true, force: true }));
  const written = join(root, "written.txt");
  const source = join(root, "source.txt");
  const moved = join(root, "moved.txt");
  const filesystem = atomicFilesystemWith({
    link: async () => {
      throw filesystemError("ENOTSUP", "hard links unavailable");
    },
  });

  await assert.rejects(
    atomicWriteBuffer(written, Buffer.from("must-not-publish\n"), {
      overwrite: false,
      filesystem,
    }),
    hasCode("CAPABILITY_UNAVAILABLE"),
  );
  await assert.rejects(readFile(written, "utf8"), { code: "ENOENT" });

  const publication = await atomicWriteBuffer(written, Buffer.from("explicit-overwrite\n"), {
    overwrite: true,
    filesystem,
  });
  assert.equal(await readFile(written, "utf8"), "explicit-overwrite\n");
  assert.equal(publication.overwritten, false);

  await writeFile(source, "move-fallback\n");
  let quarantinedSource: string | undefined;
  await assert.rejects(
    safeMoveFile(source, moved, {
      overwrite: false,
      filesystem,
    }),
    (error: unknown) => {
      assert(error instanceof UniversalBrokerError);
      assert.equal(error.code, "CAPABILITY_UNAVAILABLE");
      assert.equal(error.evidence?.source, source);
      assert.equal(error.evidence?.destination, moved);
      assert.equal(error.evidence?.sourcePreservedAtQuarantine, true);
      assert.equal(error.evidence?.publicSourceRestored, false);
      assert.equal(error.evidence?.originalErrorCode, "CAPABILITY_UNAVAILABLE");
      assert.equal(typeof error.evidence?.quarantine, "string");
      quarantinedSource = String(error.evidence?.quarantine);
      return true;
    },
  );
  await assert.rejects(readFile(source, "utf8"), { code: "ENOENT" });
  await assert.rejects(readFile(moved, "utf8"), { code: "ENOENT" });
  assert.equal(await readFile(quarantinedSource!, "utf8"), "move-fallback\n");

  await writeFile(source, "move-fallback\n");
  const movement = await safeMoveFile(source, moved, {
    overwrite: true,
    filesystem,
  });
  assert.equal(await readFile(moved, "utf8"), "move-fallback\n");
  await assert.rejects(readFile(source, "utf8"), { code: "ENOENT" });
  assert.equal(movement.crossDevice, false);
});

test("move recovery reports a post-quarantine verification failure", async (t) => {
  const root = await mkdtemp(join(tmpdir(), "devspace-v2-fs-quarantine-verify-test-"));
  t.after(() => rm(root, { recursive: true, force: true }));
  const source = join(root, "source.txt");
  const destination = join(root, "destination.txt");
  await writeFile(source, "verified-source\n");

  let quarantine: string | undefined;
  const filesystem = atomicFilesystemWith({
    rename: async (oldPath, newPath) => {
      if (oldPath === source && String(newPath).includes(".devspace-v2-move-source.txt-")) {
        await chmod(source, 0o000);
      }
      return nodeAtomicFilesystemOperations.rename(oldPath, newPath);
    },
  });
  await assert.rejects(
    safeMoveFile(source, destination, {
      overwrite: false,
      filesystem,
    }),
    (error: unknown) => {
      assert(error instanceof UniversalBrokerError);
      assert.equal(error.code, "PRECONDITION_FAILED");
      assert.equal(typeof error.evidence?.quarantine, "string");
      assert.equal(error.evidence?.publicSourceRestored, false);
      assert.equal(error.evidence?.quarantineRetained, true);
      quarantine = String(error.evidence?.quarantine);
      return true;
    },
  );
  await assert.rejects(readFile(source, "utf8"), { code: "ENOENT" });
  await chmod(quarantine!, 0o600);
  assert.equal(await readFile(quarantine!, "utf8"), "verified-source\n");
  await assert.rejects(readFile(destination, "utf8"), { code: "ENOENT" });
});

test("move recovery never claims a replaced quarantine is the verified source", async (t) => {
  const root = await mkdtemp(join(tmpdir(), "devspace-v2-fs-quarantine-race-test-"));
  t.after(() => rm(root, { recursive: true, force: true }));
  const source = join(root, "source.txt");
  const original = join(root, "original.txt");
  const destination = join(root, "destination.txt");
  await writeFile(source, "verified-source\n");

  let quarantineReadbacks = 0;
  const filesystem = atomicFilesystemWith({
    lstat: async (path) => {
      if (String(path).includes(".devspace-v2-move-source.txt-")) {
        quarantineReadbacks += 1;
        if (quarantineReadbacks === 2) {
          await nodeAtomicFilesystemOperations.rename(path, original);
          await writeFile(path, "quarantine-racer\n", { flag: "wx" });
        }
      }
      return nodeAtomicFilesystemOperations.lstat(path);
    },
  });
  await assert.rejects(
    safeMoveFile(source, destination, {
      overwrite: false,
      filesystem,
    }),
    (error: unknown) => {
      assert(error instanceof UniversalBrokerError);
      assert.equal(error.code, "PRECONDITION_FAILED");
      assert.equal(error.evidence?.sourcePreservedAtQuarantine, false);
      assert.equal(error.evidence?.quarantineIdentityMatches, false);
      assert.equal(error.evidence?.publicSourceRestored, false);
      return true;
    },
  );
  assert.equal(await readFile(original, "utf8"), "verified-source\n");
  await assert.rejects(readFile(destination, "utf8"), { code: "ENOENT" });
});

test("move recovery retains the verified quarantine after restoring the public source", async (t) => {
  const root = await mkdtemp(join(tmpdir(), "devspace-v2-fs-quarantine-cleanup-test-"));
  t.after(() => rm(root, { recursive: true, force: true }));
  const source = join(root, "source.txt");
  const destination = join(root, "destination.txt");
  await writeFile(source, "verified-source\n");

  let quarantine: string | undefined;
  const filesystem = atomicFilesystemWith({
    link: async (existingPath, newPath) => {
      if (newPath === destination && String(existingPath).includes(".devspace-v2-move-source.txt-")) {
        throw filesystemError("ENOTSUP", "hard links unavailable for destination");
      }
      return nodeAtomicFilesystemOperations.link(existingPath, newPath);
    },
  });
  await assert.rejects(
    safeMoveFile(source, destination, {
      overwrite: false,
      filesystem,
    }),
    (error: unknown) => {
      assert(error instanceof UniversalBrokerError);
      assert.equal(error.code, "CAPABILITY_UNAVAILABLE");
      assert.equal(error.evidence?.publicSourceRestored, true);
      assert.equal(error.evidence?.publicSourceIdentityMatches, true);
      assert.equal(error.evidence?.quarantineRetained, true);
      assert.equal(error.evidence?.quarantineIdentityMatches, true);
      quarantine = String(error.evidence?.quarantine);
      return true;
    },
  );
  assert.equal(await readFile(source, "utf8"), "verified-source\n");
  assert.equal(await readFile(quarantine!, "utf8"), "verified-source\n");
  await assert.rejects(readFile(destination, "utf8"), { code: "ENOENT" });
});

test("same-filesystem move rejects a byte-identical quarantine inode swap", async (t) => {
  const root = await mkdtemp(join(tmpdir(), "devspace-v2-fs-quarantine-inode-test-"));
  t.after(() => rm(root, { recursive: true, force: true }));
  const source = join(root, "source.txt");
  const savedOriginal = join(root, "saved-original.txt");
  const destination = join(root, "destination.txt");
  const content = "byte-identical-source\n";
  await writeFile(source, content);
  const originalIdentity = await lstat(source);
  const filesystem = atomicFilesystemWith({
    link: async (existingPath, newPath) => {
      if (newPath === destination && String(existingPath).includes(".devspace-v2-move-source.txt-")) {
        await nodeAtomicFilesystemOperations.rename(existingPath, savedOriginal);
        await writeFile(existingPath, content, { flag: "wx", mode: originalIdentity.mode & 0o7777 });
      }
      return nodeAtomicFilesystemOperations.link(existingPath, newPath);
    },
  });

  await assert.rejects(
    safeMoveFile(source, destination, {
      overwrite: false,
      filesystem,
    }),
    hasCode("PRECONDITION_FAILED"),
  );
  const destinationIdentity = await lstat(destination);
  assert.notEqual(destinationIdentity.ino, originalIdentity.ino);
  assert.equal(await readFile(destination, "utf8"), content);
  assert.equal(await readFile(savedOriginal, "utf8"), content);
});

test("EXDEV move rejects a byte-identical published destination inode swap", async (t) => {
  const root = await mkdtemp(join(tmpdir(), "devspace-v2-fs-exdev-inode-test-"));
  t.after(() => rm(root, { recursive: true, force: true }));
  const source = join(root, "source.txt");
  const replacedDestination = join(root, "replaced-destination.txt");
  const destination = join(root, "destination.txt");
  const content = "byte-identical-source\n";
  await writeFile(source, content);
  let destinationReadbacks = 0;
  let destinationSwapped = false;
  let finalDestinationReadStarted = false;
  let finishFinalDestinationRead!: () => void;
  const finalDestinationReadFinished = new Promise<void>((resolve) => {
    finishFinalDestinationRead = resolve;
  });
  const filesystem = atomicFilesystemWith({
    link: async (existingPath, newPath) => {
      if (newPath === destination && String(existingPath).includes(".devspace-v2-move-source.txt-")) {
        throw filesystemError("EXDEV", "cross-device link");
      }
      return nodeAtomicFilesystemOperations.link(existingPath, newPath);
    },
    lstat: async (path) => {
      const isFinalDestinationRead = path === destination && destinationReadbacks >= 2;
      if (isFinalDestinationRead) finalDestinationReadStarted = true;
      const value = await nodeAtomicFilesystemOperations.lstat(path);
      if (path === destination && value.isFile()) {
        destinationReadbacks += 1;
        if (isFinalDestinationRead) finishFinalDestinationRead();
      }
      if (
        destinationReadbacks >= 2
        && String(path).includes(".devspace-v2-move-source.txt-")
        && !destinationSwapped
      ) {
        if (finalDestinationReadStarted) await finalDestinationReadFinished;
        destinationSwapped = true;
        await nodeAtomicFilesystemOperations.rename(destination, replacedDestination);
        await writeFile(destination, content, { flag: "wx", mode: 0o777 });
        await chmod(destination, 0o777);
      }
      return value;
    },
  });

  await assert.rejects(
    safeMoveFile(source, destination, {
      overwrite: false,
      filesystem,
    }),
    hasCode("PRECONDITION_FAILED"),
  );
  assert.equal(await readFile(source, "utf8"), content);
  assert.equal(await readFile(destination, "utf8"), content);
  assert.equal((await lstat(destination)).mode & 0o7777, 0o777);
  assert.equal(await readFile(replacedDestination, "utf8"), content);
});

test("remote POSIX fs uses framed helper execution and SFTP atomic publication", async (t) => {
  const fixture = await createRemoteFixture(t);
  const remoteRoot = join(fixture.root, "remote");
  await mkdir(remoteRoot);
  const path = join(remoteRoot, "remote.txt");
  const copy = join(remoteRoot, "copy.txt");
  const moved = join(remoteRoot, "moved.txt");
  const content = `${"large-content-".repeat(8_000)}\n`;

  const written = await fixture.filesystem.execute({
    operation: "write",
    target: "remote",
    path,
    content,
  });
  assert.equal(written.path, path);
  assert.equal(await readFile(path, "utf8"), content);
  assert.ok(fixture.sftpPuts > 0, "large remote content must use SFTP staging");

  const read = await fixture.filesystem.execute({
    operation: "read",
    target: "remote",
    path,
    limit: 32,
  });
  assert.equal(read.content, content.slice(0, 32));
  assert.equal(read.truncated, true);

  await fixture.filesystem.execute({
    operation: "copy",
    target: "remote",
    path,
    destination: copy,
  });
  await fixture.filesystem.execute({
    operation: "move",
    target: "remote",
    path: copy,
    destination: moved,
  });
  assert.equal(await readFile(moved, "utf8"), content);

  await fixture.filesystem.execute({
    operation: "remove",
    target: "remote",
    path: moved,
    disposition: "permanent",
  });
  await fixture.filesystem.execute({
    operation: "remove",
    target: "remote",
    path,
    disposition: "permanent",
  });
  assert.ok(fixture.executionCalls >= 7);
  assert.equal(fixture.forgottenProcesses, 0);
});

test("remote filesystem one-shot helpers preserve the authenticated owner context", async (t) => {
  const fixture = await createRemoteFixture(t);
  const path = join(fixture.root, "owner-context.txt");
  await writeFile(path, "owner-context\n");
  const callContext = createCapabilityCallContextFromTrustedPrincipal({
    principalKeyFingerprint: "a".repeat(64),
  });
  await fixture.filesystem.execute({
    operation: "hash",
    target: "remote",
    path,
  }, callContext);
  assert.ok(fixture.processCallContexts.length >= 1);
  assert.ok(fixture.processCallContexts.every((observed) => observed === callContext));
});

test("remote POSIX fs.sync plans and applies through immutable remote checkpoints", async (t) => {
  const fixture = await createRemoteFixture(t);
  const source = join(fixture.root, "remote-sync-source");
  const destination = join(fixture.root, "remote-sync-destination");
  await mkdir(source, { recursive: true });
  await mkdir(destination, { recursive: true });
  await mkdir(join(source, "ignored"), { recursive: true });
  await writeFile(join(source, "copy.txt"), "copy\n");
  await writeFile(join(source, "update.txt"), "new\n");
  await writeFile(join(source, "ignored", "skip.txt"), "skip\n");
  await symlink("copy.txt", join(source, "link.ln"));
  await writeFile(join(destination, "update.txt"), "old\n");
  await writeFile(join(destination, "delete.txt"), "delete\n");
  const callContext = filesystemSyncCallContext("remote-plan-apply");

  const plan = await fixture.filesystem.execute({
    operation: "sync",
    target: "remote",
    path: source,
    destination,
    sync: {
      phase: "plan",
      deleteMode: "trash",
      include: ["*.txt", "*.ln"],
      exclude: ["ignored/**"],
      conflictStrategy: "fail",
    },
  }, callContext);
  assert.equal(plan.phase, "plan");
  assert.equal(plan.targetId, "remote");
  assert.equal(plan.targetGeneration, (await fixture.targets.resolve("remote")).generation);
  assert.deepEqual(syncEntryPaths(plan.copySet), ["copy.txt", "link.ln"]);
  assert.deepEqual(syncEntryPaths(plan.updateSet), ["update.txt"]);
  assert.deepEqual(syncEntryPaths(plan.deleteSet), ["delete.txt"]);
  assert.equal(await readFile(join(destination, "update.txt"), "utf8"), "old\n");

  const applied = await fixture.filesystem.execute({
    operation: "sync",
    target: "remote",
    path: source,
    destination,
    sync: {
      phase: "apply",
      planId: String(plan.planId),
      planDigest: String(plan.planDigest),
    },
  }, callContext);
  assert.equal(applied.synchronized, true);
  assert.deepEqual(await Promise.all([
    readFile(join(destination, "copy.txt"), "utf8"),
    readFile(join(destination, "update.txt"), "utf8"),
  ]), ["copy\n", "new\n"]);
  assert.equal(await readlink(join(destination, "link.ln")), "copy.txt");
  await assert.rejects(readFile(join(destination, "delete.txt"), "utf8"), { code: "ENOENT" });
  assert.ok((await readdir(join(fixture.root, ".devspace", "trash"))).length >= 1);
  assert.ok(fixture.remoteRequests.some((request) => request.op === "copy"));
  assert.ok(fixture.remoteRequests.some((request) => request.op === "remove"));
  assert.equal(fixture.remoteRequests.some((request) => request.op === "sync"), false);
});

test("remote POSIX fs.sync rejects stale source snapshots before mutation", async (t) => {
  const fixture = await createRemoteFixture(t);
  const source = join(fixture.root, "remote-sync-stale-source");
  const destination = join(fixture.root, "remote-sync-stale-destination");
  await mkdir(source, { recursive: true });
  await mkdir(destination, { recursive: true });
  await writeFile(join(source, "value.txt"), "planned\n");
  const callContext = filesystemSyncCallContext("remote-stale");
  const plan = await fixture.filesystem.execute({
    operation: "sync",
    target: "remote",
    path: source,
    destination,
    sync: { phase: "plan" },
  }, callContext);
  await writeFile(join(source, "value.txt"), "changed\n");
  await assert.rejects(
    fixture.filesystem.execute({
      operation: "sync",
      target: "remote",
      path: source,
      destination,
      sync: {
        phase: "apply",
        planId: String(plan.planId),
        planDigest: String(plan.planDigest),
      },
    }, callContext),
    hasCode("SYNC_PLAN_STALE"),
  );
  await assert.rejects(readFile(join(destination, "value.txt"), "utf8"), { code: "ENOENT" });
});

test("remote POSIX fs.sync resumes acknowledged remote mutation without duplicate copy", async (t) => {
  const fixture = await createRemoteFixture(t, { unknownAfterOps: ["copy"] });
  const source = join(fixture.root, "remote-sync-resume-source");
  const destination = join(fixture.root, "remote-sync-resume-destination");
  await mkdir(source, { recursive: true });
  await mkdir(destination, { recursive: true });
  await writeFile(join(source, "a.txt"), "a\n");
  await writeFile(join(source, "b.txt"), "b\n");
  const callContext = filesystemSyncCallContext("remote-resume");
  const plan = await fixture.filesystem.execute({
    operation: "sync",
    target: "remote",
    path: source,
    destination,
    sync: { phase: "plan" },
  }, callContext);
  const applyInput = {
    operation: "sync" as const,
    target: "remote",
    path: source,
    destination,
    sync: {
      phase: "apply" as const,
      planId: String(plan.planId),
      planDigest: String(plan.planDigest),
    },
  };
  await assert.rejects(
    fixture.filesystem.execute(applyInput, callContext),
    hasCode("EXECUTION_STATE_UNKNOWN"),
  );

  const resumed = await fixture.filesystem.execute(applyInput, callContext);
  assert.equal(resumed.synchronized, true);
  assert.equal(resumed.resumedEntries, 1);
  assert.deepEqual(await Promise.all([
    readFile(join(destination, "a.txt"), "utf8"),
    readFile(join(destination, "b.txt"), "utf8"),
  ]), ["a\n", "b\n"]);
  const copyDestinations = fixture.remoteRequests
    .filter((request) => request.op === "copy")
    .map((request) => String(request.destination));
  assert.equal(copyDestinations.filter((path) => path.endsWith("/a.txt")).length, 1);
  assert.equal(copyDestinations.filter((path) => path.endsWith("/b.txt")).length, 1);
});

test("remote POSIX fs.sync resumes permanent deletion without a duplicate remove", async (t) => {
  const fixture = await createRemoteFixture(t, { unknownAfterOps: ["remove"] });
  const source = join(fixture.root, "remote-sync-permanent-source");
  const destination = join(fixture.root, "remote-sync-permanent-destination");
  await mkdir(source, { recursive: true });
  await mkdir(destination, { recursive: true });
  await writeFile(join(destination, "delete.txt"), "delete\n");
  const callContext = filesystemSyncCallContext("remote-permanent-resume");
  const plan = await fixture.filesystem.execute({
    operation: "sync",
    target: "remote",
    path: source,
    destination,
    sync: { phase: "plan", deleteMode: "permanent" },
  }, callContext);
  const applyInput = {
    operation: "sync" as const,
    target: "remote",
    path: source,
    destination,
    sync: {
      phase: "apply" as const,
      planId: String(plan.planId),
      planDigest: String(plan.planDigest),
    },
  };
  await assert.rejects(
    fixture.filesystem.execute(applyInput, callContext),
    hasCode("EXECUTION_STATE_UNKNOWN"),
  );
  await assert.rejects(readFile(join(destination, "delete.txt"), "utf8"), { code: "ENOENT" });

  const resumed = await fixture.filesystem.execute(applyInput, callContext);
  assert.equal(resumed.synchronized, true);
  assert.equal(resumed.resumedEntries, 1);
  assert.equal(fixture.remoteRequests.filter((request) => request.op === "remove").length, 1);
  assert.equal((await fixture.filesystem.execute(applyInput, callContext)).replayed, true);
  assert.equal(fixture.remoteRequests.filter((request) => request.op === "remove").length, 1);
});

test("remote Windows fs.sync plans and applies through the fake PowerShell transport", async (t) => {
  const fixture = await createWindowsRemoteFixture(t);
  const source = "C:/Users/Test/DevSpace/sync-source";
  const destination = "C:/Users/Test/DevSpace/sync-destination";
  await fixture.filesystem.execute({ operation: "mkdir", target: "windows", path: source, recursive: true });
  await fixture.filesystem.execute({ operation: "mkdir", target: "windows", path: destination, recursive: true });
  await fixture.filesystem.execute({
    operation: "write",
    target: "windows",
    path: `${source}/copy.txt`,
    content: "copy\n",
  });
  await fixture.filesystem.execute({
    operation: "write",
    target: "windows",
    path: `${source}/update.txt`,
    content: "new\n",
  });
  await fixture.filesystem.execute({
    operation: "write",
    target: "windows",
    path: `${destination}/update.txt`,
    content: "old\n",
  });
  await fixture.filesystem.execute({
    operation: "write",
    target: "windows",
    path: `${destination}/delete.txt`,
    content: "delete\n",
  });
  const callContext = filesystemSyncCallContext("windows-sync");
  const plan = await fixture.filesystem.execute({
    operation: "sync",
    target: "windows",
    path: source,
    destination,
    sync: { phase: "plan", deleteMode: "trash" },
  }, callContext);
  assert.equal(plan.targetId, "windows");
  assert.deepEqual(syncEntryPaths(plan.copySet), ["copy.txt"]);
  assert.deepEqual(syncEntryPaths(plan.updateSet), ["update.txt"]);
  assert.deepEqual(syncEntryPaths(plan.deleteSet), ["delete.txt"]);

  const applied = await fixture.filesystem.execute({
    operation: "sync",
    target: "windows",
    path: source,
    destination,
    sync: {
      phase: "apply",
      planId: String(plan.planId),
      planDigest: String(plan.planDigest),
    },
  }, callContext);
  assert.equal(applied.synchronized, true);
  assert.equal((await fixture.filesystem.execute({
    operation: "read",
    target: "windows",
    path: `${destination}/copy.txt`,
  })).content, "copy\n");
  assert.equal((await fixture.filesystem.execute({
    operation: "read",
    target: "windows",
    path: `${destination}/update.txt`,
  })).content, "new\n");
  await assert.rejects(
    fixture.filesystem.execute({
      operation: "read",
      target: "windows",
      path: `${destination}/delete.txt`,
    }),
    hasCode("PATH_NOT_FOUND"),
  );
  assert.equal(fixture.remoteRequests.some((request) => request.op === "sync"), false);
});

test("remote Windows fs.sync resumes permanent deletion without a duplicate remove", async (t) => {
  const fixture = await createWindowsRemoteFixture(t, { unknownAfterOps: ["remove"] });
  const source = "C:/Users/Test/DevSpace/sync-permanent-source";
  const destination = "C:/Users/Test/DevSpace/sync-permanent-destination";
  await fixture.filesystem.execute({ operation: "mkdir", target: "windows", path: source, recursive: true });
  await fixture.filesystem.execute({ operation: "mkdir", target: "windows", path: destination, recursive: true });
  await fixture.filesystem.execute({
    operation: "write",
    target: "windows",
    path: `${destination}/delete.txt`,
    content: "delete\n",
  });
  const callContext = filesystemSyncCallContext("windows-permanent-resume");
  const plan = await fixture.filesystem.execute({
    operation: "sync",
    target: "windows",
    path: source,
    destination,
    sync: { phase: "plan", deleteMode: "permanent" },
  }, callContext);
  const applyInput = {
    operation: "sync" as const,
    target: "windows",
    path: source,
    destination,
    sync: {
      phase: "apply" as const,
      planId: String(plan.planId),
      planDigest: String(plan.planDigest),
    },
  };
  await assert.rejects(
    fixture.filesystem.execute(applyInput, callContext),
    hasCode("EXECUTION_STATE_UNKNOWN"),
  );
  const resumed = await fixture.filesystem.execute(applyInput, callContext);
  assert.equal(resumed.synchronized, true);
  assert.equal(resumed.resumedEntries, 1);
  assert.equal(fixture.remoteRequests.filter((request) => request.op === "remove").length, 1);
  assert.equal((await fixture.filesystem.execute(applyInput, callContext)).replayed, true);
  assert.equal(fixture.remoteRequests.filter((request) => request.op === "remove").length, 1);
});

test("remote file patch rechecks the original hash before atomic publication", async (t) => {
  const fixture = await createRemoteFixture(t);
  const remoteRoot = join(fixture.root, "remote-patch");
  await mkdir(remoteRoot);
  const path = join(remoteRoot, "remote.txt");
  await writeFile(path, "before\n");
  const hash = await fixture.filesystem.execute({
    operation: "hash",
    target: "remote",
    path,
  });
  const result = await fixture.filesystem.execute({
    operation: "patch",
    target: "remote",
    path,
    expectedSha256: String(hash.sha256),
    patch: [
      "*** Begin Patch",
      "*** Update File: remote.txt",
      "@@",
      "-before",
      "+after",
      "*** End Patch",
    ].join("\n"),
  });
  assert.equal(result.patched, true);
  assert.equal(await readFile(path, "utf8"), "after\n");
  assert.ok(fixture.sftpGets > 0);
  assert.ok(fixture.sftpPuts > 0);
});

test("fresh cached SFTP denial fails before transfer dispatch", async (t) => {
  const fixture = await createRemoteFixture(t, { sftpAvailable: false });
  const path = join(fixture.root, "must-not-publish.txt");
  await assert.rejects(
    fixture.filesystem.execute({
      operation: "write",
      target: "remote",
      path,
      content: `${"blocked".repeat(12_000)}\n`,
      overwrite: false,
    }),
    (error: unknown) => error instanceof UniversalBrokerError
      && error.code === "CAPABILITY_UNAVAILABLE",
  );
  assert.equal(fixture.executionCalls, 0);
  assert.equal(fixture.sftpPuts, 0);
  await assert.rejects(readFile(path, "utf8"), { code: "ENOENT" });
});

test("remote Windows fs uses PowerShell framing and SFTP atomic publication", async (t) => {
  const fixture = await createWindowsRemoteFixture(t);
  const directory = "C:/Users/Test/DevSpace/storage";
  const path = `${directory}/remote.txt`;
  const copied = `${directory}/copied.txt`;
  const moved = `${directory}/moved.txt`;
  const content = `${"windows-large-content-".repeat(5_000)}\n`;

  await fixture.filesystem.execute({
    operation: "mkdir",
    target: "windows",
    path: directory,
    recursive: true,
  });
  const written = await fixture.filesystem.execute({
    operation: "write",
    target: "windows",
    path,
    content,
  });
  assert.equal(written.path, path);
  assert.equal(written.size, Buffer.byteLength(content));
  assert.ok(fixture.sftpPuts > 0, "large Windows content must use SFTP staging");

  const read = await fixture.filesystem.execute({
    operation: "read",
    target: "windows",
    path,
    limit: 32,
  });
  assert.equal(read.content, content.slice(0, 32));
  assert.equal(read.truncated, true);

  const largeHash = await fixture.filesystem.execute({
    operation: "hash",
    target: "windows",
    path,
  });
  await fixture.filesystem.execute({
    operation: "write",
    target: "windows",
    path,
    content: "before\n",
    overwrite: true,
    expectedSha256: String(largeHash.sha256),
  });
  const original = await fixture.filesystem.execute({
    operation: "hash",
    target: "windows",
    path,
  });
  const patched = await fixture.filesystem.execute({
    operation: "patch",
    target: "windows",
    path,
    expectedSha256: String(original.sha256),
    patch: [
      "*** Begin Patch",
      "*** Update File: remote.txt",
      "@@",
      "-before",
      "+windows-patched",
      "*** End Patch",
    ].join("\n"),
  });
  assert.equal(patched.patched, true);
  assert.ok(fixture.sftpGets > 0);

  await fixture.filesystem.execute({
    operation: "copy",
    target: "windows",
    path,
    destination: copied,
  });
  await fixture.filesystem.execute({
    operation: "move",
    target: "windows",
    path: copied,
    destination: moved,
  });
  const windowsCursorContext = filesystemCursorCallContext("windows-pagination");
  const searched = await fixture.filesystem.execute({
    operation: "search",
    target: "windows",
    path: directory,
    query: "windows-patched",
    limit: 1,
  }, windowsCursorContext);
  assert.equal((searched.results as unknown[]).length, 1);
  assert.equal(typeof searched.nextCursor, "string");
  const searchedNext = await fixture.filesystem.execute({
    operation: "search",
    target: "windows",
    path: directory,
    query: "windows-patched",
    cursor: String(searched.nextCursor),
    limit: 1,
  }, windowsCursorContext);
  assert.ok([
    ...(searched.results as Array<{ path?: string }>),
    ...(searchedNext.results as Array<{ path?: string }>),
  ].some(
    (entry) => entry.path === path || entry.path === moved,
  ));

  const listed = await fixture.filesystem.execute({
    operation: "list",
    target: "windows",
    path: directory,
    limit: 1,
  }, windowsCursorContext);
  assert.equal((listed.entries as unknown[]).length, 1);
  assert.equal(typeof listed.nextCursor, "string");
  const listedNext = await fixture.filesystem.execute({
    operation: "list",
    target: "windows",
    path: directory,
    cursor: String(listed.nextCursor),
    limit: 1,
  }, windowsCursorContext);
  assert.equal((listedNext.entries as unknown[]).length, 1);

  for (const targetPath of [moved, path]) {
    await fixture.filesystem.execute({
      operation: "remove",
      target: "windows",
      path: targetPath,
      disposition: "permanent",
    });
  }
  await fixture.filesystem.execute({
    operation: "remove",
    target: "windows",
    path: directory,
    disposition: "permanent",
    recursive: true,
  });
  assert.ok(fixture.executionCalls >= 10);
  assert.equal(fixture.forgottenProcesses, 0);

  const command = windowsFilesystemCommand(
    { op: "stat", path },
  );
  assert.match(command, /powershell\.exe/u);
  assert.match(command, /-EncodedCommand/u);
  assert.doesNotMatch(command, /windows-large-content/u);
});

interface Fixture {
  root: string;
  targets: TargetRegistry;
  contexts: ContextRegistry;
  filesystem: UniversalFilesystemService;
}

interface RemoteFixture extends Fixture {
  execution: UniversalExecutionPlane;
  executionCalls: number;
  forgottenProcesses: number;
  sftpPuts: number;
  sftpGets: number;
  processCallContexts: Array<CapabilityCallContext | undefined>;
  remoteRequests: Array<Record<string, unknown>>;
}

interface WindowsRemoteFixture extends RemoteFixture {}

type FixtureOptions =
  | Partial<UniversalFilesystemOptions>
  | ((input: { root: string }) => Partial<UniversalFilesystemOptions>);

async function createFixture(
  t: test.TestContext,
  filesystemOptions: FixtureOptions = {},
): Promise<Fixture> {
  const root = await mkdtemp(join(tmpdir(), "devspace-v2-fs-test-"));
  t.after(() => rm(root, { recursive: true, force: true }));
  const resolvedOptions = typeof filesystemOptions === "function"
    ? filesystemOptions({ root })
    : filesystemOptions;
  const serverConfig = loadConfig({
    DEVSPACE_CONFIG_DIR: join(root, ".config"),
    DEVSPACE_ALLOWED_ROOTS: root,
    DEVSPACE_STATE_DIR: join(root, "legacy-state"),
    DEVSPACE_WORKTREE_ROOT: join(root, "worktrees"),
    DEVSPACE_OAUTH_OWNER_TOKEN: "v2-filesystem-test-owner-credential-123456",
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
  const filesystem = new UniversalFilesystemService(
    targets,
    contexts,
    {} as UniversalExecutionPlane,
    {
      sshControlDir: join(root, "ssh-control"),
      ...resolvedOptions,
      cursorStore: resolvedOptions.cursorStore ?? filesystemCursorStore(),
    },
  );
  return { root, targets, contexts, filesystem };
}

function atomicFilesystemWith(
  overrides: Partial<AtomicFilesystemOperations>,
): AtomicFilesystemOperations {
  return { ...nodeAtomicFilesystemOperations, ...overrides };
}

function filesystemError(code: string, message: string): NodeJS.ErrnoException {
  return Object.assign(new Error(message), { code });
}

function createFixtureLocalSyncAdapter(
  root: string,
  build: (
    base: FilesystemSyncAdapter,
    trash: RecoverableFilesystemTrash,
  ) => FilesystemSyncAdapter,
): { trashRoot: string; syncAdapter: FilesystemSyncAdapter } {
  const trashRoot = join(root, "filesystem-trash");
  const trash = new RecoverableFilesystemTrash(trashRoot);
  const base = createLocalFilesystemSyncAdapter("local", trash);
  return {
    trashRoot,
    syncAdapter: build(base, trash),
  };
}

async function createRemoteFixture(
  t: test.TestContext,
  options: { sftpAvailable?: boolean; unknownAfterOps?: string[] } = {},
): Promise<RemoteFixture> {
  const root = await mkdtemp(join(tmpdir(), "devspace-v2-fs-remote-test-"));
  t.after(() => rm(root, { recursive: true, force: true }));
  const targetConfig = join(root, "targets.json");
  await writeFile(targetConfig, JSON.stringify({
    version: 1,
    targets: {
      remote: {
        displayName: "Remote fixture",
        aliases: ["remote"],
        transport: "ssh",
        sshHost: "fixture.invalid",
        platform: "linux",
        defaultCwd: root,
      },
    },
  }));
  const serverConfig = loadConfig({
    DEVSPACE_CONFIG_DIR: join(root, ".config"),
    DEVSPACE_ALLOWED_ROOTS: root,
    DEVSPACE_STATE_DIR: join(root, "legacy-state"),
    DEVSPACE_WORKTREE_ROOT: join(root, "worktrees"),
    DEVSPACE_OAUTH_OWNER_TOKEN: "v2-filesystem-remote-owner-credential-123456",
    DEVSPACE_PUBLIC_BASE_URL: "http://127.0.0.1:17676",
    DEVSPACE_LOG_LEVEL: "silent",
    DEVSPACE_SKILL_PATHS: join(root, "skills"),
  });
  const targets = new TargetRegistry({
    configPath: targetConfig,
    execute: (async (executable: string, args: string[]) => {
      if (executable === "sftp") {
        if (options.sftpAvailable === false) throw new Error("SFTP subsystem unavailable");
        return { stdout: "", stderr: "" };
      }
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
  await targets.probe("remote");
  const contexts = new ContextRegistry({
    storePath: join(root, "v2-state", "contexts.json"),
    targets,
    serverConfig,
  });
  let executionCalls = 0;
  let forgottenProcesses = 0;
  const processCallContexts: Array<CapabilityCallContext | undefined> = [];
  const remoteRequests: Array<Record<string, unknown>> = [];
  const unknownAfterOps = [...(options.unknownAfterOps ?? [])];
  const execution = {
    async run(
      input: { command: string },
      callContext?: CapabilityCallContext,
    ): Promise<UniversalProcessSnapshot> {
      executionCalls += 1;
      processCallContexts.push(callContext);
      const request = decodePosixFilesystemCommand(input.command);
      if (request) remoteRequests.push(request);
      const started = Date.now();
      try {
        const result = await execFileAsync("/bin/sh", ["-lc", input.command], {
          maxBuffer: 2 * 1024 * 1024,
          env: { ...process.env, HOME: root },
        });
        if (request && unknownAfterOps[0] === request.op) {
          unknownAfterOps.shift();
          return processSnapshot("", undefined, started, "UNKNOWN");
        }
        return processSnapshot(result.stdout, 0, started);
      } catch (error) {
        const failure = error as Error & { stdout?: string; stderr?: string; code?: number };
        return processSnapshot(
          `${failure.stdout ?? ""}${failure.stderr ?? ""}`,
          typeof failure.code === "number" ? failure.code : 1,
          started,
        );
      }
    },
    stats() { return { active: 0, maximumConcurrent: 32, completed: executionCalls }; },
  } as unknown as UniversalExecutionPlane;
  let sftpPuts = 0;
  let sftpGets = 0;
  const filesystem = new UniversalFilesystemService(
    targets,
    contexts,
    execution,
    {
      sshControlDir: join(root, "ssh-control"),
      cursorStore: filesystemCursorStore(),
      sftpPut: async ({ localPath, remotePath }) => {
        sftpPuts += 1;
        await copyFile(localPath, remotePath);
      },
      sftpGet: async ({ localPath, remotePath }) => {
        sftpGets += 1;
        await copyFile(remotePath, localPath);
      },
    },
  );
  return {
    root,
    targets,
    contexts,
    filesystem,
    execution,
    get executionCalls() { return executionCalls; },
    get forgottenProcesses() { return forgottenProcesses; },
    get sftpPuts() { return sftpPuts; },
    get sftpGets() { return sftpGets; },
    get processCallContexts() { return processCallContexts; },
    get remoteRequests() { return remoteRequests; },
  };
}

async function createWindowsRemoteFixture(
  t: test.TestContext,
  options: { unknownAfterOps?: string[] } = {},
): Promise<WindowsRemoteFixture> {
  const root = await mkdtemp(join(tmpdir(), "devspace-v2-fs-windows-test-"));
  t.after(() => rm(root, { recursive: true, force: true }));
  const targetConfig = join(root, "targets.json");
  await writeFile(targetConfig, JSON.stringify({
    version: 1,
    targets: {
      windows: {
        displayName: "Windows fixture",
        aliases: ["windows"],
        transport: "ssh",
        sshHost: "windows.invalid",
        platform: "windows",
        shell: "powershell",
        defaultCwd: "C:/Users/Test",
      },
    },
  }));
  const serverConfig = loadConfig({
    DEVSPACE_CONFIG_DIR: join(root, ".config"),
    DEVSPACE_ALLOWED_ROOTS: root,
    DEVSPACE_STATE_DIR: join(root, "legacy-state"),
    DEVSPACE_WORKTREE_ROOT: join(root, "worktrees"),
    DEVSPACE_OAUTH_OWNER_TOKEN: "v2-windows-fs-owner-credential-123456",
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
          "architecture=AMD64",
          "home=C:\\Users\\Test",
          "temporary=C:\\Users\\Test\\AppData\\Local\\Temp\\",
          "git=1",
          "elevated=0",
          "",
        ].join("\n"),
        stderr: "",
      };
    }) as never,
  });
  const contexts = new ContextRegistry({
    storePath: join(root, "v2-state", "contexts.json"),
    targets,
    serverConfig,
  });
  const driveRoot = join(root, "drive-c");
  await mkdir(join(driveRoot, "Users", "Test", "AppData", "Local", "Temp"), { recursive: true });
  let executionCalls = 0;
  let forgottenProcesses = 0;
  const processCallContexts: Array<CapabilityCallContext | undefined> = [];
  const remoteRequests: Array<Record<string, unknown>> = [];
  const unknownAfterOps = [...(options.unknownAfterOps ?? [])];
  const execution = {
    async run(
      input: { command: string },
      callContext?: CapabilityCallContext,
    ): Promise<UniversalProcessSnapshot> {
      executionCalls += 1;
      processCallContexts.push(callContext);
      const started = Date.now();
      const cleanupPath = input.command.match(/Remove-Item\s+-LiteralPath\s+'((?:''|[^'])+)'/u)?.[1]
        ?.replaceAll("''", "'");
      if (cleanupPath) {
        await rm(mapWindowsFixturePath(cleanupPath, driveRoot), { force: true });
        return processSnapshot("", 0, started);
      }
      let response: Record<string, unknown>;
      try {
        const remoteScript = input.command.match(/-File\s+'((?:''|[^'])+)'/u)?.[1]
          ?.replaceAll("''", "'");
        if (!remoteScript) throw new Error("Windows filesystem command is missing its staged script.");
        const source = await readFile(mapWindowsFixturePath(remoteScript, driveRoot), "utf8");
        const request = decodeWindowsScript(source);
        remoteRequests.push(request);
        const data = await executeFakeWindowsFilesystemRequest(request, driveRoot);
        if (unknownAfterOps[0] === request.op) {
          unknownAfterOps.shift();
          return processSnapshot("", undefined, started, "UNKNOWN", "windows");
        }
        response = {
          ok: true,
          data,
        };
      } catch (error) {
        response = {
          ok: false,
          code: error instanceof UniversalBrokerError ? error.code : "TRANSPORT_INTERRUPTED",
          message: error instanceof Error ? error.message : String(error),
        };
      }
      return processSnapshot(
        `${REMOTE_WINDOWS_FILESYSTEM_RESULT_MARKER}${JSON.stringify(response)}\n`,
        0,
        started,
      );
    },
    stats() { return { active: 0, maximumConcurrent: 32, completed: executionCalls }; },
  } as unknown as UniversalExecutionPlane;
  let sftpPuts = 0;
  let sftpGets = 0;
  const filesystem = new UniversalFilesystemService(
    targets,
    contexts,
    execution,
    {
      sshControlDir: join(root, "ssh-control"),
      cursorStore: filesystemCursorStore(),
      sftpPut: async ({ localPath, remotePath }) => {
        sftpPuts += 1;
        const mapped = mapWindowsFixturePath(remotePath, driveRoot);
        await mkdir(join(mapped, ".."), { recursive: true });
        await copyFile(localPath, mapped);
      },
      sftpGet: async ({ localPath, remotePath }) => {
        sftpGets += 1;
        await copyFile(mapWindowsFixturePath(remotePath, driveRoot), localPath);
      },
    },
  );
  return {
    root,
    targets,
    contexts,
    filesystem,
    execution,
    get executionCalls() { return executionCalls; },
    get forgottenProcesses() { return forgottenProcesses; },
    get sftpPuts() { return sftpPuts; },
    get sftpGets() { return sftpGets; },
    get processCallContexts() { return processCallContexts; },
    get remoteRequests() { return remoteRequests; },
  };
}

function decodeWindowsScript(source: string): Record<string, unknown> {
  const requestBase64 = source.match(/\$RequestBase64\s*=\s*'([A-Za-z0-9+/]+={0,2})'/u)?.[1];
  if (!requestBase64) throw new Error("Windows filesystem command is missing its framed request.");
  return JSON.parse(Buffer.from(requestBase64, "base64").toString("utf8")) as Record<string, unknown>;
}

function decodePosixFilesystemCommand(command: string): Record<string, unknown> | undefined {
  const requestBase64 = command.match(/\s'([A-Za-z0-9+/]+={0,2})'$/u)?.[1];
  if (!requestBase64) return undefined;
  return JSON.parse(Buffer.from(requestBase64, "base64").toString("utf8")) as Record<string, unknown>;
}

async function executeFakeWindowsFilesystemRequest(
  request: Record<string, unknown>,
  driveRoot: string,
): Promise<Record<string, unknown>> {
  const operation = String(request.op ?? "");
  const options = (request.options && typeof request.options === "object")
    ? request.options as Record<string, unknown>
    : {};
  const remotePath = typeof request.path === "string" ? request.path : undefined;
  const remoteDestination = typeof request.destination === "string"
    ? request.destination
    : undefined;
  const path = remotePath ? mapWindowsFixturePath(remotePath, driveRoot) : undefined;
  const destination = remoteDestination
    ? mapWindowsFixturePath(remoteDestination, driveRoot)
    : undefined;

  switch (operation) {
    case "stat": {
      const required = requireFixturePath(path, remotePath);
      const metadata = await stat(required).catch(() => undefined);
      if (!metadata) throw fixtureError("PATH_NOT_FOUND", `Path not found: ${remotePath}`);
      return {
        path: remotePath,
        type: metadata.isDirectory() ? "directory" : "file",
        size: metadata.isFile() ? metadata.size : 0,
        mode: 0,
        mtimeMs: metadata.mtimeMs,
        birthtimeMs: metadata.birthtimeMs,
      };
    }
    case "list": {
      const required = requireFixturePath(path, remotePath);
      const entries = (await readdir(required, { withFileTypes: true }))
        .sort((left, right) => left.name.localeCompare(right.name));
      const offset = Number(options.offset ?? 0);
      const limit = Number(options.limit ?? 100);
      const page = entries.slice(offset, offset + limit).map((entry) => ({
        name: entry.name,
        type: entry.isDirectory() ? "directory" : "file",
      }));
      return {
        path: remotePath,
        entries: page,
        totalEntries: entries.length,
        offset,
        limit,
        ...(offset + page.length < entries.length ? { nextOffset: offset + page.length } : {}),
      };
    }
    case "read": {
      const required = requireFixturePath(path, remotePath);
      if (!await stat(required).catch(() => undefined)) {
        throw fixtureError("PATH_NOT_FOUND", `Path not found: ${remotePath}`);
      }
      const content = await readFile(required);
      const offset = Number(options.offset ?? 0);
      const maximum = Number(options.maxBytes ?? 12_000);
      const selected = content.subarray(offset, offset + maximum);
      const nextOffset = offset + selected.byteLength;
      return {
        path: remotePath,
        contentBase64: selected.toString("base64"),
        offset,
        bytesRead: selected.byteLength,
        size: content.byteLength,
        truncated: nextOffset < content.byteLength,
        ...(nextOffset < content.byteLength ? { nextOffset } : {}),
      };
    }
    case "search": {
      const required = requireFixturePath(path, remotePath);
      const query = String(request.query ?? "");
      const limit = Number(options.limit ?? 50);
      const entries = (await stat(required)).isDirectory()
        ? await readdir(required, { withFileTypes: true })
        : [];
      const candidates = entries.filter((entry) => entry.isFile()).map((entry) => entry.name);
      const results: Array<Record<string, unknown>> = [];
      for (const name of candidates) {
        const lines = (await readFile(join(required, name), "utf8")).split(/\r?\n/u);
        for (let index = 0; index < lines.length && results.length < limit; index += 1) {
          if (!lines[index]!.includes(query)) continue;
          results.push({
            path: `${remotePath!.replace(/[\\/]$/u, "")}/${name}`,
            line: index + 1,
            text: lines[index],
          });
        }
      }
      return { path: remotePath, query, results, visitedFiles: candidates.length, truncated: false };
    }
    case "hash": {
      const required = requireFixturePath(path, remotePath);
      const content = await readFile(required);
      return {
        path: remotePath,
        algorithm: "sha256",
        sha256: createHash("sha256").update(content).digest("hex"),
        size: content.byteLength,
      };
    }
    case "mkdir": {
      await mkdir(requireFixturePath(path, remotePath), { recursive: options.recursive === true });
      return { path: remotePath, created: true, mode: 0 };
    }
    case "write_content": {
      const required = requireFixturePath(path, remotePath);
      const existing = await fixtureExistingHash(required);
      verifyFixtureWrite(existing, options, remotePath!);
      await mkdir(join(required, ".."), { recursive: true });
      const bytes = Buffer.from(String(request.contentBase64 ?? ""), "base64");
      await writeFile(required, bytes);
      return fixturePublishedResult(remotePath!, required, existing !== undefined);
    }
    case "prepare_write": {
      const required = requireFixturePath(path, remotePath);
      const existing = await fixtureExistingHash(required);
      verifyFixtureWrite(existing, options, remotePath!);
      await mkdir(join(required, ".."), { recursive: true });
      return {
        path: remotePath,
        preimage: existing === undefined
          ? { exists: false }
          : { exists: true, type: "file", sha256: existing },
        mode: 0,
      };
    }
    case "publish_write": {
      const required = requireFixturePath(path, remotePath);
      const temporaryRemote = String(request.temporary ?? "");
      const temporary = mapWindowsFixturePath(temporaryRemote, driveRoot);
      const existing = await fixtureExistingHash(required);
      verifyFixtureWrite(existing, options, remotePath!);
      const expectedPreimage = request.preimage as { exists?: boolean; sha256?: string } | undefined;
      if (
        expectedPreimage?.exists !== (existing !== undefined)
        || (existing !== undefined && expectedPreimage.sha256 !== existing)
      ) {
        throw fixtureError("PRECONDITION_FAILED", `Destination preimage changed: ${remotePath}`);
      }
      const published = await atomicCopyFile(temporary, required, {
        overwrite: options.overwrite === true,
        expectedSha256: typeof options.expectedSha256 === "string"
          ? options.expectedSha256
          : undefined,
      });
      await rm(temporary, { force: true });
      return { ...published, path: remotePath };
    }
    case "cleanup": {
      const temporaryRemote = String(request.temporary ?? "");
      await rm(mapWindowsFixturePath(temporaryRemote, driveRoot), { recursive: true, force: true });
      return { path: temporaryRemote, removed: true };
    }
    case "copy": {
      const required = requireFixturePath(path, remotePath);
      const requiredDestination = requireFixturePath(destination, remoteDestination);
      const existing = await stat(requiredDestination).catch(() => undefined);
      if (existing && options.overwrite !== true) {
        throw fixtureError("PRECONDITION_FAILED", `Destination exists: ${remoteDestination}`);
      }
      await mkdir(join(requiredDestination, ".."), { recursive: true });
      const published = await atomicCopyFile(required, requiredDestination, {
        overwrite: options.overwrite === true,
      });
      return {
        source: remotePath,
        destination: remoteDestination,
        copied: true,
        overwritten: Boolean(existing),
        size: published.size,
        sha256: published.sha256,
      };
    }
    case "move": {
      const required = requireFixturePath(path, remotePath);
      const requiredDestination = requireFixturePath(destination, remoteDestination);
      const existing = await stat(requiredDestination).catch(() => undefined);
      if (existing && options.overwrite !== true) {
        throw fixtureError("PRECONDITION_FAILED", `Destination exists: ${remoteDestination}`);
      }
      await mkdir(join(requiredDestination, ".."), { recursive: true });
      const published = await safeMoveFile(required, requiredDestination, {
        overwrite: options.overwrite === true,
      });
      return {
        source: remotePath,
        destination: remoteDestination,
        moved: true,
        crossDevice: published.crossDevice,
      };
    }
    case "remove": {
      const required = requireFixturePath(path, remotePath);
      if (options.disposition === "trash") {
        const trashId = randomUUID();
        const entry = join(driveRoot, "Users", "Test", ".devspace", "trash", trashId);
        const payload = join(entry, "payload");
        await mkdir(entry, { recursive: true });
        await rename(required, payload);
        return {
          path: remotePath,
          removed: true,
          disposition: "trash",
          recoverable: true,
          trashId,
        };
      }
      await rm(required, { recursive: options.recursive === true, force: false });
      return { path: remotePath, removed: true, disposition: "permanent" };
    }
    default:
      throw fixtureError("PRECONDITION_FAILED", `Unsupported fixture operation: ${operation}`);
  }
}

function mapWindowsFixturePath(remotePath: string, driveRoot: string): string {
  const normalized = remotePath.replaceAll("\\", "/").replace(/^\/(?=[a-zA-Z]:\/)/u, "");
  const expanded = normalized === "~"
    ? "C:/Users/Test"
    : normalized.startsWith("~/")
      ? `C:/Users/Test/${normalized.slice(2)}`
      : normalized;
  const match = expanded.match(/^C:\/(.*)$/iu);
  if (!match) throw fixtureError("PRECONDITION_FAILED", `Unexpected Windows fixture path: ${remotePath}`);
  const segments = (match[1] ?? "").split("/").filter(Boolean);
  if (segments.some((segment) => segment === "..")) {
    throw fixtureError("PERMISSION_DENIED", `Windows fixture path escaped its drive: ${remotePath}`);
  }
  return join(driveRoot, ...segments);
}

function requireFixturePath(
  value: string | undefined,
  remote: string | undefined,
): string {
  if (!value || !remote) throw fixtureError("PRECONDITION_FAILED", "Fixture path is required.");
  return value;
}

async function fixtureExistingHash(path: string): Promise<string | undefined> {
  const metadata = await stat(path).catch(() => undefined);
  if (!metadata) return undefined;
  if (!metadata.isFile()) throw fixtureError("PATH_TYPE_MISMATCH", `Expected file: ${path}`);
  return createHash("sha256").update(await readFile(path)).digest("hex");
}

function verifyFixtureWrite(
  existingHash: string | undefined,
  options: Record<string, unknown>,
  path: string,
): void {
  if (existingHash && options.overwrite !== true) {
    throw fixtureError("PRECONDITION_FAILED", `Destination exists: ${path}`);
  }
  if (
    typeof options.expectedSha256 === "string"
    && options.expectedSha256.toLowerCase() !== existingHash
  ) {
    throw fixtureError("PRECONDITION_FAILED", `SHA-256 precondition failed: ${path}`);
  }
}

async function fixturePublishedResult(
  remotePath: string,
  localPath: string,
  overwritten: boolean,
): Promise<Record<string, unknown>> {
  const content = await readFile(localPath);
  return {
    path: remotePath,
    size: content.byteLength,
    mode: 0,
    sha256: createHash("sha256").update(content).digest("hex"),
    overwritten,
  };
}

function fixtureError(
  code: ConstructorParameters<typeof UniversalBrokerError>[0],
  message: string,
): UniversalBrokerError {
  return new UniversalBrokerError(code, message);
}

function processSnapshot(
  output: string,
  exitCode: number | undefined,
  startedAt: number,
  state: UniversalProcessSnapshot["state"] = "EXITED",
  targetId = "remote",
): UniversalProcessSnapshot {
  return {
    processId: "proc_fixture",
    targetId,
    transport: "ssh",
    cwd: "/",
    tty: false,
    state,
    startedAt: new Date(startedAt).toISOString(),
    ...(state === "EXITED" ? { endedAt: new Date().toISOString() } : {}),
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
    resourceUri: "devspace://process/proc_fixture/output/0/1048576",
    durable: false,
    ...(exitCode === undefined ? {} : { exitCode }),
  };
}

function filesystemSyncCallContext(label: string): CapabilityCallContext {
  return createCapabilityCallContextFromTrustedPrincipal({
    principalKeyFingerprint: createHash("sha256")
      .update(`filesystem-sync-test:${label}`)
      .digest("hex"),
  });
}

function filesystemCursorCallContext(label: string): CapabilityCallContext {
  return createCapabilityCallContextFromTrustedPrincipal({
    principalKeyFingerprint: createHash("sha256")
      .update(`filesystem-cursor-test:${label}`)
      .digest("hex"),
  });
}

function filesystemCursorStore(
  now: () => number = Date.now,
  ttlMs = 60_000,
  maximumSnapshotsPerPrincipal = 128,
): SignedSnapshotCursorStore {
  return new SignedSnapshotCursorStore({
    currentKey: {
      keyId: "filesystem-cursor-test-current",
      secret: Buffer.alloc(32, 0x5c),
    },
    ttlMs,
    maximumSnapshotsPerPrincipal,
    now,
  });
}

function syncEntryPaths(value: unknown): string[] {
  assert.ok(Array.isArray(value));
  return value.map((entry) => String((entry as { path?: unknown }).path)).sort();
}

function hasCode(code: string): (error: unknown) => boolean {
  return (error: unknown) => error instanceof Error
    && "code" in error
    && error.code === code;
}

function hasCursorReason(reason: string): (error: unknown) => boolean {
  return (error: unknown) => error instanceof CursorCapabilityError
    && error.reason === reason;
}
