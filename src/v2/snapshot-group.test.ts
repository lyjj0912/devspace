import assert from "node:assert/strict";
import {
  mkdir,
  mkdtemp,
  readFile,
  readdir,
  rename,
  rm,
  stat,
  symlink,
  writeFile,
} from "node:fs/promises";
import { realpathSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import Database from "better-sqlite3";
import {
  captureSnapshotGroup,
  restoreSnapshotGroup,
  type SnapshotGroupEntryRequest,
} from "./snapshot-group.js";

test("snapshot group captures and restores every mutable production store atomically enough for rollback", async (t) => {
  const root = await mkdtemp(join(realpathSync(tmpdir()), "devspace-snapshot-group-test-"));
  t.after(() => rm(root, { recursive: true, force: true }));

  const oauth = join(root, "oauth.sqlite");
  const authority = join(root, "authority.sqlite");
  const artifactCatalog = join(root, "artifacts.sqlite");
  const filesystemSync = join(root, "filesystem-sync.sqlite");
  createDatabase(oauth, "OLD_OAUTH");
  createDatabase(authority, "OLD_AUTHORITY");
  createDatabase(filesystemSync, "OLD_FILESYSTEM_SYNC");
  createDatabase(artifactCatalog, "OLD_ARTIFACT_CATALOG");

  const contextStore = join(root, "contexts.json");
  const cursorCurrent = join(root, "cursor-current.key");
  const cursorPrevious = join(root, "cursor-previous.key");
  const processState = join(root, "processes");
  const processOutput = join(root, "process-output");
  const artifactObjects = join(root, "artifact-objects");
  const artifactQuarantine = join(root, "artifact-quarantine");
  await writeFile(contextStore, "{\"version\":2,\"contexts\":[]}\n", { mode: 0o600 });
  await writeFile(cursorCurrent, "old-current-key\n", { mode: 0o600 });
  await mkdir(processState, { recursive: true });
  await mkdir(processOutput, { recursive: true });
  await mkdir(artifactObjects, { recursive: true });
  await mkdir(artifactQuarantine, { recursive: true });
  await writeFile(join(processState, "proc_old.json"), "{\"state\":\"OLD\"}\n");
  await writeFile(join(processOutput, "proc_old.log"), "old output\n");
  await writeFile(join(artifactObjects, "aa"), "old object\n");
  await writeFile(join(artifactQuarantine, "bb"), "old quarantine\n");

  const stores: SnapshotGroupEntryRequest[] = [
    { id: "oauth-main-and-connector-state", kind: "sqlite", path: oauth, required: true },
    { id: "authority-store", kind: "sqlite", path: authority, required: true },
    { id: "contexts-store", kind: "file", path: contextStore, required: true },
    { id: "process-metadata", kind: "directory", path: processState, required: true },
    { id: "process-output", kind: "directory", path: processOutput, required: true },
    { id: "filesystem-sync", kind: "sqlite", path: filesystemSync, required: true },
    { id: "artifact-catalog", kind: "sqlite", path: artifactCatalog, required: true },
    { id: "artifact-cas", kind: "directory", path: artifactObjects, required: true },
    { id: "artifact-quarantine", kind: "directory", path: artifactQuarantine, required: true },
    { id: "pagination-current-signing-key", kind: "file", path: cursorCurrent, required: true },
    { id: "pagination-previous-signing-key", kind: "file", path: cursorPrevious, required: false },
  ];

  const captured = await captureSnapshotGroup({
    snapshotRoot: join(root, "snapshot"),
    barrier: {
      kind: "PM2_STOPPED",
      processName: "devspace-v2-production",
      previousPid: 111,
    },
    entries: stores,
    now: () => "2026-08-20T00:00:00.000Z",
  });

  assert.match(captured.manifest.groupDigest, /^sha256:[a-f0-9]{64}$/u);
  assert.equal(captured.manifest.entries.length, stores.length);
  assert.equal(captured.manifest.entries.find((entry) => entry.id === "pagination-previous-signing-key")?.state, "absent");
  assert.equal((await stat(captured.manifestPath)).mode & 0o777, 0o600);

  writeDatabaseValue(oauth, "NEW_OAUTH");
  writeDatabaseValue(authority, "NEW_AUTHORITY");
  writeDatabaseValue(filesystemSync, "NEW_FILESYSTEM_SYNC");
  writeDatabaseValue(artifactCatalog, "NEW_ARTIFACT_CATALOG");
  await writeFile(`${oauth}-wal`, "stale wal\n");
  await writeFile(`${oauth}-shm`, "stale shm\n");
  await writeFile(`${authority}-wal`, "stale wal\n");
  await writeFile(`${filesystemSync}-wal`, "stale wal\n");
  await writeFile(`${filesystemSync}-shm`, "stale shm\n");
  await writeFile(`${artifactCatalog}-shm`, "stale shm\n");
  await writeFile(contextStore, "{\"version\":2,\"contexts\":[{\"bad\":true}]}\n", { mode: 0o600 });
  await writeFile(cursorCurrent, "new-current-key\n", { mode: 0o600 });
  await writeFile(cursorPrevious, "new-previous-key\n", { mode: 0o600 });
  await rm(processState, { recursive: true, force: true });
  await rm(processOutput, { recursive: true, force: true });
  await rm(artifactObjects, { recursive: true, force: true });
  await rm(artifactQuarantine, { recursive: true, force: true });
  await mkdir(processState, { recursive: true });
  await mkdir(processOutput, { recursive: true });
  await mkdir(artifactObjects, { recursive: true });
  await mkdir(artifactQuarantine, { recursive: true });
  await writeFile(join(processState, "proc_new.json"), "{\"state\":\"NEW\"}\n");
  await writeFile(join(processOutput, "proc_new.log"), "new output\n");
  await writeFile(join(artifactObjects, "cc"), "new object\n");
  await writeFile(join(artifactQuarantine, "dd"), "new quarantine\n");

  const restored = await restoreSnapshotGroup(captured.manifest);
  assert.equal(restored.verified, true);
  assert.equal(restored.entries.length, stores.length);
  await assert.rejects(stat(`${oauth}-wal`), /ENOENT/u);
  await assert.rejects(stat(`${oauth}-shm`), /ENOENT/u);
  await assert.rejects(stat(`${authority}-wal`), /ENOENT/u);
  await assert.rejects(stat(`${filesystemSync}-wal`), /ENOENT/u);
  await assert.rejects(stat(`${filesystemSync}-shm`), /ENOENT/u);
  await assert.rejects(stat(`${artifactCatalog}-shm`), /ENOENT/u);
  assert.equal(readDatabaseValue(oauth), "OLD_OAUTH");
  assert.equal(readDatabaseValue(authority), "OLD_AUTHORITY");
  assert.equal(readDatabaseValue(filesystemSync), "OLD_FILESYSTEM_SYNC");
  assert.equal(readDatabaseValue(artifactCatalog), "OLD_ARTIFACT_CATALOG");
  assert.equal(await readFile(contextStore, "utf8"), "{\"version\":2,\"contexts\":[]}\n");
  assert.equal(await readFile(cursorCurrent, "utf8"), "old-current-key\n");
  await assert.rejects(stat(cursorPrevious), /ENOENT/u);
  assert.deepEqual(await readdir(processState), ["proc_old.json"]);
  assert.deepEqual(await readdir(processOutput), ["proc_old.log"]);
  assert.deepEqual(await readdir(artifactObjects), ["aa"]);
  assert.deepEqual(await readdir(artifactQuarantine), ["bb"]);
});

test("snapshot capture rejects stale roots and manifests instead of reusing transaction state", async (t) => {
  const root = await mkdtemp(join(realpathSync(tmpdir()), "devspace-snapshot-fresh-root-"));
  t.after(() => rm(root, { recursive: true, force: true }));
  const source = join(root, "source.txt");
  await writeFile(source, "source\n", { mode: 0o600 });
  for (const [label, populate] of [
    ["empty", async (path: string) => mkdir(path, { mode: 0o700 })],
    ["manifest", async (path: string) => {
      await mkdir(path, { mode: 0o700 });
      await writeFile(join(path, "SNAPSHOT-GROUP.json"), "{}\n", { mode: 0o600 });
    }],
  ] as const) {
    const snapshotRoot = join(root, `snapshot-${label}`);
    await populate(snapshotRoot);
    await assert.rejects(
      captureSnapshotGroup({
        snapshotRoot,
        barrier: { kind: "PM2_STOPPED" },
        entries: [{ id: "source-file", kind: "file", path: source, required: true }],
      }),
      /new transaction-specific path/u,
    );
  }

  await assert.rejects(
    captureSnapshotGroup({
      snapshotRoot: join(root, "snapshot-before-barrier"),
      barrier: {
        kind: "PM2_STOPPED",
        establishedAt: "2026-08-20T00:00:01.000Z",
      },
      entries: [{ id: "source-file", kind: "file", path: source, required: true }],
      now: () => "2026-08-20T00:00:00.000Z",
    }),
    /may not precede its verified stop barrier/u,
  );
});

test("failed snapshot capture never publishes the final transaction root", async (t) => {
  const root = await mkdtemp(join(realpathSync(tmpdir()), "devspace-snapshot-publication-barrier-"));
  t.after(() => rm(root, { recursive: true, force: true }));
  const source = join(root, "source.txt");
  const missing = join(root, "missing.txt");
  const snapshotRoot = join(root, "snapshot");
  await writeFile(source, "source\n", { mode: 0o600 });

  await assert.rejects(
    captureSnapshotGroup({
      snapshotRoot,
      barrier: { kind: "PM2_STOPPED" },
      entries: [
        { id: "captured-before-fault", kind: "file", path: source, required: true },
        { id: "required-missing", kind: "file", path: missing, required: true },
      ],
    }),
    /Required snapshot store is missing/u,
  );

  await assert.rejects(stat(snapshotRoot), /ENOENT/u);
  assert.deepEqual(
    (await readdir(root)).filter((name) => name.startsWith(".snapshot.capture-")),
    [],
    "a handled capture failure must clean its unpublished staging directory",
  );
});

test("snapshot capture and restore reject symbolic-link ancestors before reading or writing", async (t) => {
  const root = await mkdtemp(join(realpathSync(tmpdir()), "devspace-snapshot-symlink-ancestor-"));
  t.after(() => rm(root, { recursive: true, force: true }));
  const actual = join(root, "actual");
  const alias = join(root, "alias");
  await mkdir(actual, { mode: 0o700 });
  await writeFile(join(actual, "store.txt"), "source\n", { mode: 0o600 });
  await symlink(actual, alias);
  await assert.rejects(
    captureSnapshotGroup({
      snapshotRoot: join(root, "snapshot-alias-source"),
      barrier: { kind: "PM2_STOPPED" },
      entries: [{ id: "aliased-store", kind: "file", path: join(alias, "store.txt"), required: true }],
    }),
    /symbolic-link component/u,
  );

  const mutableParent = join(root, "mutable");
  const mutableFile = join(mutableParent, "store.txt");
  await mkdir(mutableParent, { mode: 0o700 });
  await writeFile(mutableFile, "preimage\n", { mode: 0o600 });
  const captured = await captureSnapshotGroup({
    snapshotRoot: join(root, "snapshot-restore"),
    barrier: { kind: "PM2_STOPPED" },
    entries: [{ id: "mutable-store", kind: "file", path: mutableFile, required: true }],
  });
  await rename(mutableParent, join(root, "mutable-original"));
  const attacker = join(root, "attacker");
  await mkdir(attacker, { mode: 0o700 });
  await symlink(attacker, mutableParent);
  await assert.rejects(restoreSnapshotGroup(captured.manifest), /symbolic-link component/u);
  await assert.rejects(stat(join(attacker, "store.txt")), /ENOENT/u);
});

test("snapshot inventory treats SQLite WAL and SHM sidecars as mutable restore targets", async (t) => {
  const root = await mkdtemp(join(realpathSync(tmpdir()), "devspace-snapshot-sidecar-overlap-"));
  t.after(() => rm(root, { recursive: true, force: true }));
  const sqlite = join(root, "oauth.sqlite");
  createDatabase(sqlite, "OLD_OAUTH");

  for (const suffix of ["-wal", "-shm"] as const) {
    const sidecar = `${sqlite}${suffix}`;
    await writeFile(sidecar, `external control ${suffix}\n`, { mode: 0o600 });
    await assert.rejects(
      captureSnapshotGroup({
        snapshotRoot: join(root, `snapshot-${suffix.slice(1)}`),
        barrier: { kind: "PM2_STOPPED" },
        entries: [
          { id: "oauth-main-and-connector-state", kind: "sqlite", path: sqlite, required: true },
          { id: `external-${suffix.slice(1)}`, kind: "file", path: sidecar, required: true },
        ],
      }),
      /Snapshot stores overlap/u,
    );
    assert.equal(await readFile(sidecar, "utf8"), `external control ${suffix}\n`);
  }
});

function createDatabase(path: string, value: string): void {
  const database = new Database(path);
  try {
    database.pragma("journal_mode = WAL");
    database.exec("create table sentinel (value text not null)");
    database.prepare("insert into sentinel (value) values (?)").run(value);
  } finally {
    database.close();
  }
}

function writeDatabaseValue(path: string, value: string): void {
  const database = new Database(path);
  try {
    database.prepare("update sentinel set value = ?").run(value);
  } finally {
    database.close();
  }
}

function readDatabaseValue(path: string): string {
  const database = new Database(path, { readonly: true, fileMustExist: true });
  try {
    return database.prepare("select value from sentinel").pluck().get() as string;
  } finally {
    database.close();
  }
}
