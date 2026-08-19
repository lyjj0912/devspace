import assert from "node:assert/strict";
import { spawn, type ChildProcessWithoutNullStreams } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createInterface } from "node:readline";
import test from "node:test";
import Database from "better-sqlite3";
import {
  OperationAuthorityRegistry,
  actionFingerprint,
  actionResourceKeySha256,
} from "./authority.js";
import type { DurableAuthorityStore } from "./authority-store.js";
import {
  principalKeyFingerprint,
  resolveAuthorityPrincipal,
  type AuthorityPrincipalConfiguration,
} from "./authority-principal.js";
import {
  EXEC_RISK_CLASSIFIER_GENERATION,
  assertNoElevationCommand,
  authorityActionFromToolCall,
  commandRisk,
  execAction,
  mcpRisk,
  minimumAuthorityRisk,
  processAction,
  processRisk,
} from "./authority-policy.js";
import { UniversalBrokerError } from "./errors.js";

function registry(
  now: { value: number } = { value: Date.now() },
  storePath?: string,
  instanceId?: string,
) {
  return new OperationAuthorityRegistry({
    now: () => now.value,
    minimumRisk: minimumAuthorityRisk,
    ...(storePath ? { storePath } : {}),
    ...(instanceId ? { instanceId } : {}),
  });
}

const SINGLE_OWNER_PRINCIPAL: AuthorityPrincipalConfiguration = {
  environment: "production",
  mode: "single-owner",
  issuer: "https://issuer.example/",
  resource: "https://broker.example/mcp",
  ownerInstanceId: "owner-instance-a",
};

test("stable principal survives token scope changes and ten transport sessions", () => {
  const fingerprints = Array.from({ length: 10 }, (_, index) => resolveAuthorityPrincipal({
    sessionId: `transport-${index}`,
    authInfo: {
      clientId: "oauth-client-a",
      scopes: index % 2 === 0 ? ["devspace.read"] : ["devspace.read", "devspace.write"],
      resource: new URL("https://broker.example/mcp"),
    },
  }, SINGLE_OWNER_PRINCIPAL).fingerprint);
  assert.equal(new Set(fingerprints).size, 1);

  const otherClient = resolveAuthorityPrincipal({
    sessionId: "transport-other",
    authInfo: {
      clientId: "oauth-client-b",
      scopes: ["devspace.read", "devspace.write"],
      resource: new URL("https://broker.example/mcp"),
    },
  }, SINGLE_OWNER_PRINCIPAL);
  assert.notEqual(otherClient.fingerprint, fingerprints[0]);
});

test("production principal fails closed without clientId and never uses session fallback", () => {
  assert.throws(
    () => resolveAuthorityPrincipal({ sessionId: "must-not-be-a-principal" }, SINGLE_OWNER_PRINCIPAL),
    (error: unknown) => code(error) === "AUTHENTICATION_FAILED",
  );
  const developmentKey = {
    issuer: "https://development.example/",
    clientId: "explicit-test-client",
    resource: "https://development.example/mcp",
    ownerInstanceId: "explicit-test-owner",
  };
  const injected = resolveAuthorityPrincipal(
    { sessionId: "ignored-development-session" },
    {
      environment: "test",
      mode: "single-owner",
      developmentPrincipal: developmentKey,
    },
  );
  assert.equal(injected.source, "development-injection");
  assert.equal(injected.fingerprint, principalKeyFingerprint(developmentKey));
  assert.throws(
    () => resolveAuthorityPrincipal(
      { sessionId: "production-must-ignore-injection" },
      { ...SINGLE_OWNER_PRINCIPAL, developmentPrincipal: developmentKey },
    ),
    (error: unknown) => code(error) === "AUTHENTICATION_FAILED",
  );
  assert.throws(
    () => resolveAuthorityPrincipal({
      authInfo: {
        clientId: "oauth-client-a",
        scopes: ["devspace.write"],
        resource: new URL("https://different-resource.example/mcp"),
      },
    }, SINGLE_OWNER_PRINCIPAL),
    (error: unknown) => code(error) === "AUTHENTICATION_FAILED",
  );
  assert.throws(
    () => resolveAuthorityPrincipal({
      authInfo: {
        clientId: "oauth-client-a",
        scopes: ["devspace.write"],
        resource: new URL("https://broker.example/mcp"),
      },
    }, { ...SINGLE_OWNER_PRINCIPAL, ownerInstanceId: undefined }),
    (error: unknown) => code(error) === "AUTHENTICATION_FAILED",
  );
});

test("multi-user principal requires subject and rejects authority reuse across subjects", () => {
  const config: AuthorityPrincipalConfiguration = {
    environment: "production",
    mode: "multi-user",
    issuer: "https://issuer.example/",
    resource: "https://broker.example/mcp",
  };
  const resolveSubject = (subject?: string) => resolveAuthorityPrincipal({
    authInfo: {
      clientId: "shared-client",
      scopes: ["devspace.write"],
      resource: new URL("https://broker.example/mcp"),
      ...(subject ? { extra: { subject } } : {}),
    },
  }, config);
  const subjectA = resolveSubject("subject-a");
  const subjectB = resolveSubject("subject-b");
  assert.notEqual(subjectA.fingerprint, subjectB.fingerprint);
  assert.throws(
    () => resolveSubject(),
    (error: unknown) => code(error) === "AUTHENTICATION_FAILED",
  );

  const authority = registry();
  const descriptor = authorityActionFromToolCall("fs", {
    operation: "write",
    target: "local",
    path: "/tmp/multi-user-principal.txt",
    content: "subject-a\n",
  });
  const created = authority.create({
    taskId: "multi-user-boundary",
    authorityText: "Only subject A may use this exact action.",
    actions: [{ descriptor }],
  }, subjectA.fingerprint);
  assert.throws(
    () => authority.require(String(created.authorityId), subjectB.fingerprint, descriptor, "R1"),
    (error: unknown) => code(error) === "AUTHORITY_PRINCIPAL_MISMATCH",
  );
  authority.close();
});

test("legacy clientId-sessionId authority scopes are backed up and quarantined", async (t) => {
  const root = await mkdtemp(join(tmpdir(), "devspace-authority-legacy-migration-"));
  t.after(async () => rm(root, { recursive: true, force: true }));
  const storePath = join(root, "authority.sqlite");
  const legacy = new Database(storePath);
  legacy.exec(`
    create table operation_authority_scopes (
      scope_key text primary key,
      correction_epoch integer not null,
      updated_at_ms integer not null
    );
    create table operation_authorities (
      authority_id text primary key,
      task_id_sha256 text not null,
      authority_text_sha256 text not null,
      scope_key text not null,
      correction_epoch integer not null,
      created_at_ms integer not null,
      expires_at_ms integer not null,
      fingerprint text not null
    );
    pragma user_version = 2;
  `);
  legacy.prepare(
    "insert into operation_authority_scopes values (?, 0, ?)",
  ).run("legacy-client:legacy-session", 1_787_000_000_000);
  legacy.prepare(
    "insert into operation_authorities values (?, ?, ?, ?, 0, ?, ?, ?)",
  ).run(
    "authority_legacy_client_session",
    "legacy-task-sha256",
    "legacy-authority-text-sha256",
    "legacy-client:legacy-session",
    1_787_000_000_000,
    1_787_000_900_000,
    "legacy-fingerprint",
  );
  legacy.close();

  const migrated = registry(
    { value: 1_787_001_000_000 },
    storePath,
    "migration-process",
  );
  assert.throws(
    () => migrated.status("authority_legacy_client_session", "new-principal-fingerprint"),
    (error: unknown) => code(error) === "AUTHORITY_EXPIRED",
  );
  assert.equal((migrated.stats() as { authorities: number }).authorities, 0);
  migrated.close();

  const verified = new Database(storePath, { readonly: true, fileMustExist: true });
  assert.equal(verified.pragma("user_version", { simple: true }), 5);
  const quarantine = verified.prepare(
    `select authority_id, reason, backup_sha256
       from operation_authority_legacy_quarantine`,
  ).get() as {
    authority_id: string;
    reason: string;
    backup_sha256: string;
  };
  const migration = verified.prepare(
    `select backup_path, backup_sha256, quarantined_authorities
       from operation_authority_migrations`,
  ).get() as {
    backup_path: string;
    backup_sha256: string;
    quarantined_authorities: number;
  };
  const preservedLegacy = verified.prepare(
    "select count(*) as count from legacy_v2_operation_authorities",
  ).get() as { count: number };
  verified.close();

  assert.deepEqual(quarantine, {
    authority_id: "authority_legacy_client_session",
    reason: "AMBIGUOUS_LEGACY_CLIENT_SESSION_SCOPE",
    backup_sha256: migration.backup_sha256,
  });
  assert.equal(migration.quarantined_authorities, 1);
  assert.equal(preservedLegacy.count, 1);
  const backupBytes = await readFile(migration.backup_path);
  assert.equal(
    createHash("sha256").update(backupBytes).digest("hex"),
    migration.backup_sha256,
  );
});

test("schema v3 migrates to v5 with verified backup and quarantines unrecoverable resource bindings", async (t) => {
  const root = await mkdtemp(join(tmpdir(), "devspace-authority-v3-migration-"));
  t.after(async () => rm(root, { recursive: true, force: true }));
  const storePath = join(root, "authority.sqlite");
  const now = { value: 1_787_010_000_000 };
  const rawSecret = "V3_MIGRATION_RAW_SECRET_76a4";
  const principal = createHash("sha256").update(`principal:${rawSecret}`).digest("hex");
  const descriptor = authorityActionFromToolCall("exec", {
    target: "local",
    cwd: `/tmp/${rawSecret}`,
    command: `git push origin ${rawSecret}`,
  });
  const fingerprint = actionFingerprint(descriptor);
  const actionId = `action_${fingerprint}`;
  const legacy = new Database(storePath);
  legacy.exec(`
    create table operation_authority_tasks (
      task_instance_id text primary key,
      principal_key_fingerprint text not null,
      task_label_sha256 text,
      correction_epoch integer not null,
      created_at_ms integer not null,
      updated_at_ms integer not null
    );
    create table operation_authorities (
      authority_id text primary key,
      task_instance_id text not null,
      task_label_sha256 text,
      authority_text_sha256 text not null,
      principal_key_fingerprint text not null,
      approval_assurance text not null,
      correction_epoch integer not null,
      created_at_ms integer not null,
      expires_at_ms integer not null,
      fingerprint text not null,
      foreign key (task_instance_id) references operation_authority_tasks(task_instance_id)
    );
    create table operation_authority_actions (
      authority_id text not null,
      action_id text not null,
      ordinal integer not null,
      tool text not null,
      operation text not null,
      fingerprint text not null,
      minimum_risk text not null,
      risk text not null,
      maximum_uses integer not null,
      consumed_uses integer not null,
      primary key (authority_id, action_id),
      unique (authority_id, fingerprint),
      foreign key (authority_id) references operation_authorities(authority_id) on delete cascade
    );
    create table operation_authority_receipts (
      authority_id text not null,
      use_id text primary key,
      action_id text not null,
      reserved_at_ms integer not null,
      completed_at_ms integer,
      result text not null,
      error_code text,
      reason_code text,
      owner_instance_id text not null,
      foreign key (authority_id, action_id)
        references operation_authority_actions(authority_id, action_id) on delete cascade
    );
    create table operation_authority_legacy_quarantine (
      authority_id text primary key,
      legacy_scope_key text not null,
      legacy_task_id_sha256 text not null,
      legacy_fingerprint text not null,
      quarantined_at_ms integer not null,
      reason text not null,
      backup_sha256 text
    );
    create table operation_authority_migrations (
      migration_id text primary key,
      from_schema_version integer not null,
      to_schema_version integer not null,
      migrated_at_ms integer not null,
      backup_path text,
      backup_sha256 text,
      quarantined_authorities integer not null
    );
    pragma user_version = 3;
  `);
  legacy.prepare(
    "insert into operation_authority_tasks values (?, ?, ?, 0, ?, ?)",
  ).run("task_v3_fixture", principal, createHash("sha256").update(rawSecret).digest("hex"), now.value, now.value);
  legacy.prepare(
    "insert into operation_authorities values (?, ?, null, ?, ?, 'cooperative', 0, ?, ?, ?)",
  ).run(
    "authority_v3_fixture",
    "task_v3_fixture",
    createHash("sha256").update(`authority:${rawSecret}`).digest("hex"),
    principal,
    now.value,
    now.value + 900_000,
    createHash("sha256").update(`grant:${rawSecret}`).digest("hex"),
  );
  legacy.prepare(
    "insert into operation_authority_actions values (?, ?, 0, 'exec', 'run', ?, 'R3', 'R3', 1, 1)",
  ).run("authority_v3_fixture", actionId, fingerprint);
  legacy.prepare(
    "insert into operation_authority_receipts values (?, ?, ?, ?, null, 'PENDING', null, null, ?)",
  ).run(
    "authority_v3_fixture",
    "authority_use_v3_pending",
    actionId,
    now.value,
    "dead-v3-owner",
  );
  legacy.close();

  const migrated = registry(now, storePath, "v5-migration-owner");
  const status = migrated.status("authority_v3_fixture", principal) as {
    receipts: Array<{
      state: string;
      leaseState: string;
      resourceKeySha256: string;
      evidence?: { reasonCode?: string };
    }>;
  };
  assert.equal(status.receipts[0]?.state, "UNCERTAIN");
  assert.equal(status.receipts[0]?.leaseState, "FROZEN");
  assert.match(status.receipts[0]?.resourceKeySha256 ?? "", /^[a-f0-9]{64}$/u);
  assert.equal(status.receipts[0]?.evidence?.reasonCode, "LEGACY_PENDING_CLAIM_MIGRATED");
  assert.throws(
    () => migrated.prepareDispatch("authority_v3_fixture", principal, descriptor, "R3").claim(),
    (error: unknown) => code(error) === "AUTHORITY_CONSUMED",
  );
  migrated.close();

  const verified = new Database(storePath, { readonly: true, fileMustExist: true });
  assert.equal(verified.pragma("user_version", { simple: true }), 5);
  assert.equal(verified.pragma("integrity_check", { simple: true }), "ok");
  assert.deepEqual(verified.pragma("foreign_key_check"), []);
  const migration = verified.prepare(
    `select from_schema_version, to_schema_version, backup_path, backup_sha256,
            source_integrity_check, backup_integrity_check,
            post_integrity_check, foreign_key_violations,
            quarantined_authorities
       from operation_authority_migrations`,
  ).get() as {
    from_schema_version: number;
    to_schema_version: number;
    backup_path: string;
    backup_sha256: string;
    source_integrity_check: string;
    backup_integrity_check: string;
    post_integrity_check: string;
    foreign_key_violations: number;
    quarantined_authorities: number;
  };
  const quarantine = verified.prepare(
    "select reason from operation_authority_v3_action_quarantine",
  ).get() as { reason: string };
  verified.close();
  assert.deepEqual({
    from: migration.from_schema_version,
    to: migration.to_schema_version,
    source: migration.source_integrity_check,
    backup: migration.backup_integrity_check,
    post: migration.post_integrity_check,
    foreignKeys: migration.foreign_key_violations,
    quarantined: migration.quarantined_authorities,
    reason: quarantine.reason,
  }, {
    from: 3,
    to: 5,
    source: "ok",
    backup: "ok",
    post: "ok",
    foreignKeys: 0,
    quarantined: 1,
    reason: "LEGACY_ACTION_RESOURCE_BINDING_UNRECOVERABLE",
  });
  const backupBytes = await readFile(migration.backup_path);
  assert.equal(
    createHash("sha256").update(backupBytes).digest("hex"),
    migration.backup_sha256,
  );
  for (const path of [
    storePath,
    `${storePath}-wal`,
    `${storePath}-shm`,
    migration.backup_path,
  ]) {
    const bytes = await readFile(path).catch(() => undefined);
    if (bytes) assert.equal(bytes.includes(Buffer.from(rawSecret)), false, path);
  }
});

test("exact R1 authority is principal-bound, receipted, and bounded by uses", () => {
  const authority = registry();
  const descriptor = authorityActionFromToolCall("fs", {
    operation: "write",
    target: "local",
    path: "/tmp/example.txt",
    overwrite: true,
  });
  const created = authority.create({
    taskId: "write-example",
    authorityText: "Create or replace the exact example file.",
    actions: [{ descriptor, uses: 2 }],
  }, "client-a:session-a");
  const authorityId = String(created.authorityId);
  assert.match(String(created.taskInstanceId), /^task_[0-9a-f-]{36}$/u);
  assert.equal(created.approvalAssurance, "cooperative");
  assert.doesNotMatch(JSON.stringify(created), /human[-_ ]signed|host-attested/iu);

  const first = authority.require(authorityId, "client-a:session-a", descriptor, "R1");
  assert.ok(first);
  authority.record(first, "PASS", { verified: true });
  const second = authority.require(authorityId, "client-a:session-a", descriptor, "R1");
  assert.ok(second);
  authority.record(second, "FAIL", { verified: false });

  assert.throws(
    () => authority.require(authorityId, "client-a:session-a", descriptor, "R1"),
    (error: unknown) => code(error) === "AUTHORITY_CONSUMED",
  );
  assert.throws(
    () => authority.status(authorityId, "client-b:session-b"),
    (error: unknown) => code(error) === "AUTHORITY_PRINCIPAL_MISMATCH",
  );
  const status = authority.status(authorityId, "client-a:session-a");
  assert.equal((status.receipts as unknown[]).length, 2);
});

test("re-authorizing a consumed exact action creates a fresh authority", () => {
  const authority = registry();
  const descriptor = authorityActionFromToolCall("fs", {
    operation: "write",
    target: "local",
    contextId: "context-a",
    path: "example.txt",
    content: "first\n",
  });
  const input = {
    taskId: "repeat-write",
    authorityText: "Write the exact file again after the first authority is consumed.",
    actions: [{ descriptor }],
  };
  const first = authority.create(input, "client:session");
  const firstId = String(first.authorityId);
  const taskInstanceId = String(first.taskInstanceId);
  const reusedBeforeUse = authority.create({ ...input, taskInstanceId }, "client:session");
  assert.equal(reusedBeforeUse.authorityId, firstId);
  assert.equal(reusedBeforeUse.reused, true);
  const grant = authority.require(firstId, "client:session", descriptor, "R1");
  authority.record(grant, "PASS");
  const second = authority.create({ ...input, taskInstanceId }, "client:session");
  assert.notEqual(second.authorityId, firstId);
  assert.equal(second.reused, false);
});

test("filesystem authority binds context identity and payload hashes", () => {
  const a = authorityActionFromToolCall("fs", {
    operation: "write",
    target: "local",
    contextId: "context-a",
    path: "same.txt",
    content: "alpha\n",
  });
  const b = authorityActionFromToolCall("fs", {
    operation: "write",
    target: "local",
    contextId: "context-b",
    path: "same.txt",
    content: "alpha\n",
  });
  const c = authorityActionFromToolCall("fs", {
    operation: "write",
    target: "local",
    contextId: "context-a",
    path: "same.txt",
    content: "beta\n",
  });
  assert.notEqual(actionFingerprint(a), actionFingerprint(b));
  assert.notEqual(actionFingerprint(a), actionFingerprint(c));
});

test("exact action fingerprints bind every mutation dispatch dimension", () => {
  const fsBase = authorityActionFromToolCall("fs", {
    operation: "write",
    target: "local",
    path: "/tmp/exact-a.txt",
    content: "alpha\n",
  });
  for (const changed of [
    authorityActionFromToolCall("fs", {
      operation: "write",
      target: "company",
      path: "/tmp/exact-a.txt",
      content: "alpha\n",
    }),
    authorityActionFromToolCall("fs", {
      operation: "write",
      target: "local",
      path: "/tmp/exact-b.txt",
      content: "alpha\n",
    }),
    authorityActionFromToolCall("fs", {
      operation: "write",
      target: "local",
      path: "/tmp/exact-a.txt",
      content: "beta\n",
    }),
  ]) {
    assert.notEqual(actionFingerprint(fsBase), actionFingerprint(changed));
  }

  const execBase = authorityActionFromToolCall("exec", {
    target: "local",
    cwd: "/tmp",
    command: "git push origin main",
    mode: "foreground",
  });
  const execChanged = authorityActionFromToolCall("exec", {
    target: "local",
    cwd: "/tmp",
    command: "git push origin release",
    mode: "foreground",
  });
  assert.notEqual(actionFingerprint(execBase), actionFingerprint(execChanged));

  const mcpBase = authorityActionFromToolCall("mcp", {
    operation: "invoke",
    route: "jira",
    name: "create_issue",
    arguments: { project: "A", summary: "one" },
  });
  for (const changed of [
    authorityActionFromToolCall("mcp", {
      operation: "invoke",
      route: "computer-use",
      name: "create_issue",
      arguments: { project: "A", summary: "one" },
    }),
    authorityActionFromToolCall("mcp", {
      operation: "invoke",
      route: "jira",
      name: "update_issue",
      arguments: { project: "A", summary: "one" },
    }),
    authorityActionFromToolCall("mcp", {
      operation: "invoke",
      route: "jira",
      name: "create_issue",
      arguments: { project: "A", summary: "two" },
    }),
  ]) {
    assert.notEqual(actionFingerprint(mcpBase), actionFingerprint(changed));
  }

  const guiBase = authorityActionFromToolCall("gui", {
    operation: "act",
    target: "local",
    sessionId: "gui-1",
    generation: "generation-1",
    action: { type: "press", elementId: "confirm" },
  });
  for (const changed of [
    authorityActionFromToolCall("gui", {
      operation: "act",
      target: "local",
      sessionId: "gui-1",
      generation: "generation-2",
      action: { type: "press", elementId: "confirm" },
    }),
    authorityActionFromToolCall("gui", {
      operation: "act",
      target: "local",
      sessionId: "gui-1",
      generation: "generation-1",
      action: { type: "press", elementId: "cancel" },
    }),
  ]) {
    assert.notEqual(actionFingerprint(guiBase), actionFingerprint(changed));
  }
  assert.notEqual(actionFingerprint(fsBase), actionFingerprint(mcpBase));
});

test("verified-dead CLAIMED action recovers as cancelled and reclaimed without persisting raw payload", async (t) => {
  const root = await mkdtemp(join(tmpdir(), "devspace-authority-recovery-"));
  t.after(async () => rm(root, { recursive: true, force: true }));
  const storePath = join(root, "authority.sqlite");
  const now = { value: 1_787_050_000_000 };
  const rawSecret = "RAW_AUTHORITY_SECRET_9f6b7b8e";
  const scopeId = `oauth-client:${rawSecret}`;
  const descriptor = authorityActionFromToolCall("exec", {
    target: "local",
    cwd: `/tmp/${rawSecret}`,
    command: `git push origin ${rawSecret}`,
    mode: "foreground",
  });
  const fileDescriptor = authorityActionFromToolCall("fs", {
    operation: "write",
    target: "local",
    path: `/tmp/${rawSecret}.txt`,
    content: `file-content-${rawSecret}\n`,
    overwrite: false,
  });
  const patchDescriptor = authorityActionFromToolCall("fs", {
    operation: "patch",
    target: "local",
    path: `/tmp/${rawSecret}.txt`,
    patch: `*** Begin Patch\n*** Update File: fixture.txt\n@@\n-old\n+${rawSecret}\n*** End Patch`,
  });
  const credentialDescriptor = authorityActionFromToolCall("mcp", {
    operation: "invoke",
    route: "jira",
    name: "read_only_fixture",
    arguments: { credential: rawSecret, query: `payload-${rawSecret}` },
  });
  const first = registry(now, storePath, "process-generation-a");
  const created = first.create({
    taskId: `task-${rawSecret}`,
    authorityText: `Dispatch exactly once using ${rawSecret}.`,
    actions: [
      { id: rawSecret, descriptor, risk: "R3", uses: 1 },
      { id: `file-${rawSecret}`, descriptor: fileDescriptor },
      { id: `patch-${rawSecret}`, descriptor: patchDescriptor },
      { id: `credential-${rawSecret}`, descriptor: credentialDescriptor },
    ],
  }, scopeId);
  const authorityId = String(created.authorityId);
  const grant = first.require(authorityId, scopeId, descriptor, "R3");
  assert.ok(grant);
  assert.equal(
    ((first.status(authorityId, scopeId).receipts as Array<{ result: string }>)[0]?.result),
    "CLAIMED",
  );
  first.close();

  now.value += 1_000;
  const recovered = registry(now, storePath, "process-generation-b");
  const status = recovered.status(authorityId, scopeId) as {
    actions: Array<{ consumedUses: number }>;
    receipts: Array<{ result: string; evidence?: { errorCode?: string; reasonCode?: string } }>;
  };
  assert.equal(status.actions[0]?.consumedUses, 0);
  assert.equal(status.receipts[0]?.result, "CANCELLED_NOT_DISPATCHED");
  assert.equal(status.receipts[0]?.evidence?.errorCode, undefined);
  assert.equal(status.receipts[0]?.evidence?.reasonCode, "OWNER_RUN_DEAD_BEFORE_DISPATCH");
  const stats = recovered.stats() as {
    pendingReservations: number;
    recoveredPendingUses: number;
  };
  assert.equal(stats.pendingReservations, 0);
  assert.equal(stats.recoveredPendingUses, 1);
  const retry = recovered.prepareDispatch(authorityId, scopeId, descriptor, "R3");
  retry.claim();
  retry.cancelNotDispatched({
    providerCallCount: 0,
    proof: "TEST_RECOVERED_CLAIM_RETRY_ZERO",
  });
  recovered.close();

  for (const path of [storePath, `${storePath}-wal`, `${storePath}-shm`]) {
    const bytes = await readFile(path).catch(() => undefined);
    if (!bytes) continue;
    assert.equal(bytes.includes(Buffer.from(rawSecret)), false, path);
    assert.equal(bytes.includes(Buffer.from(scopeId)), false, path);
  }
});

test("restart after authority expiry still cancels a verified-zero CLAIMED use without replay", async (t) => {
  const root = await mkdtemp(join(tmpdir(), "devspace-authority-expired-recovery-"));
  t.after(async () => rm(root, { recursive: true, force: true }));
  const storePath = join(root, "authority.sqlite");
  const now = { value: 1_787_055_000_000 };
  const scopeId = "oauth-client:expired-recovery-client";
  const descriptor = authorityActionFromToolCall("exec", {
    target: "local",
    cwd: "/tmp",
    command: "git push origin expired-recovery-test",
    mode: "foreground",
  });
  const first = registry(now, storePath, "expired-process-a");
  const created = first.create({
    taskId: "expired-recovery",
    authorityText: "Dispatch this exact action once before expiry.",
    expiresInSeconds: 60,
    actions: [{ id: "one-shot", descriptor, risk: "R3", uses: 1 }],
  }, scopeId);
  const authorityId = String(created.authorityId);
  assert.ok(first.require(authorityId, scopeId, descriptor, "R3"));
  first.close();

  now.value += 61_000;
  const recovered = registry(now, storePath, "expired-process-b");
  const status = recovered.status(authorityId, scopeId) as {
    expired: boolean;
    actions: Array<{ consumedUses: number }>;
    receipts: Array<{ result: string }>;
  };
  assert.equal(status.expired, true);
  assert.equal(status.actions[0]?.consumedUses, 0);
  assert.deepEqual(status.receipts.map((receipt) => receipt.result), ["CANCELLED_NOT_DISPATCHED"]);
  assert.throws(
    () => recovered.require(authorityId, scopeId, descriptor, "R3"),
    (error: unknown) => code(error) === "AUTHORITY_EXPIRED",
  );
  recovered.close();
});

test("stale overlapping workers cannot reserve the same R3 action twice", async (t) => {
  const root = await mkdtemp(join(tmpdir(), "devspace-authority-overlap-"));
  t.after(async () => rm(root, { recursive: true, force: true }));
  const storePath = join(root, "authority.sqlite");
  const now = { value: 1_787_060_000_000 };
  const scopeId = "oauth-client:overlap-client";
  const descriptor = authorityActionFromToolCall("exec", {
    target: "local",
    cwd: "/tmp",
    command: "git push origin overlap-test",
    mode: "foreground",
  });
  const workerA = registry(now, storePath, "overlap-worker-a");
  const created = workerA.create({
    taskId: "overlap-one-shot",
    authorityText: "Dispatch the exact overlap test once.",
    actions: [{ id: "one-shot", descriptor, risk: "R3", uses: 1 }],
  }, scopeId);
  const authorityId = String(created.authorityId);
  const workerB = registry(now, storePath, "overlap-worker-b");

  const grant = workerA.require(authorityId, scopeId, descriptor, "R3");
  assert.ok(grant);
  assert.throws(
    () => workerB.require(authorityId, scopeId, descriptor, "R3"),
    (error: unknown) => code(error) === "AUTHORITY_CONSUMED",
  );
  assert.throws(
    () => workerB.release(authorityId, scopeId),
    (error: unknown) => code(error) === "PRECONDITION_FAILED",
  );
  workerA.record(grant, "PASS");
  workerA.close();
  workerB.close();

  const readback = registry(now, storePath, "overlap-worker-readback");
  const status = readback.status(authorityId, scopeId) as {
    actions: Array<{ consumedUses: number }>;
    receipts: Array<{ result: string }>;
  };
  assert.equal(status.actions[0]?.consumedUses, 1);
  assert.deepEqual(status.receipts.map((receipt) => receipt.result), ["PASS"]);
  readback.close();
});

test("opening a second live registry and re-saving a grant cannot recover or erase the first writer", async (t) => {
  const root = await mkdtemp(join(tmpdir(), "devspace-authority-live-owner-"));
  t.after(async () => rm(root, { recursive: true, force: true }));
  const storePath = join(root, "authority.sqlite");
  const now = { value: 1_787_064_000_000 };
  const principal = "live-owner-principal";
  const descriptor = authorityActionFromToolCall("fs", {
    operation: "write",
    target: "local",
    path: "/tmp/live-owner.txt",
    content: "live\n",
  });
  const workerA = registry(now, storePath, "live-owner-a");
  const created = workerA.create({
    taskId: "live-owner-task",
    authorityText: "Keep the first live writer current while another registry opens.",
    actions: [{ descriptor }],
  }, principal);
  const authorityId = String(created.authorityId);
  const dispatch = workerA.prepareDispatch(authorityId, principal, descriptor, "R1");
  dispatch.claim();

  const workerB = registry(now, storePath, "live-owner-b");
  const before = workerB.status(authorityId, principal) as {
    receipts: Array<{ state: string; leaseState: string }>;
  };
  assert.deepEqual(before.receipts.map((receipt) => receipt.state), ["CLAIMED"]);
  assert.deepEqual(before.receipts.map((receipt) => receipt.leaseState), ["ACTIVE"]);
  const storeB = (workerB as unknown as { store: DurableAuthorityStore }).store;
  const durableGrant = storeB.load().authorities.find(
    (authority) => authority.authorityId === authorityId,
  );
  assert.ok(durableGrant);
  storeB.saveAuthority(durableGrant);

  dispatch.markDispatched();
  dispatch.complete("PASS");
  const after = workerB.status(authorityId, principal) as {
    receipts: Array<{ state: string; leaseState: string }>;
  };
  assert.deepEqual(after.receipts.map((receipt) => receipt.state), ["PASS"]);
  assert.deepEqual(after.receipts.map((receipt) => receipt.leaseState), ["RELEASED"]);
  workerA.close();
  workerB.close();
});

test("a live owner in another OS process cannot be recovered or fenced out", async (t) => {
  const root = await mkdtemp(join(tmpdir(), "devspace-authority-cross-process-live-"));
  t.after(async () => rm(root, { recursive: true, force: true }));
  const storePath = join(root, "authority.sqlite");
  const now = { value: 1_787_064_500_000 };
  const principal = "cross-process-live-principal";
  const descriptor = authorityActionFromToolCall("fs", {
    operation: "write",
    target: "local",
    path: "/tmp/cross-process-live.txt",
    content: "live\n",
  });
  const owner = registry(now, storePath, "cross-process-live-owner-a");
  const created = owner.create({
    taskId: "cross-process-live-task",
    authorityText: "Keep the live parent writer active.",
    actions: [{ descriptor }],
  }, principal);
  const authorityId = String(created.authorityId);
  const dispatch = owner.prepareDispatch(authorityId, principal, descriptor, "R1");
  dispatch.claim();

  const observed = await runAuthorityChild(`
    import { OperationAuthorityRegistry } from "./src/v2/authority.ts";
    import { minimumAuthorityRisk } from "./src/v2/authority-policy.ts";
    const child = new OperationAuthorityRegistry({
      minimumRisk: minimumAuthorityRisk,
      storePath: process.env.B2_STORE_PATH,
      instanceId: "cross-process-live-owner-b",
      now: () => Number(process.env.B2_NOW_MS),
    });
    const status = child.status(
      String(process.env.B2_AUTHORITY_ID),
      String(process.env.B2_PRINCIPAL),
    );
    process.stdout.write(JSON.stringify({ status, stats: child.stats() }) + "\\n");
    child.close();
  `, {
    B2_STORE_PATH: storePath,
    B2_NOW_MS: String(now.value + 60_000),
    B2_AUTHORITY_ID: authorityId,
    B2_PRINCIPAL: principal,
  }) as {
    status: { receipts: Array<{ state: string; leaseState: string }> };
    stats: { recoveredPendingUses: number };
  };
  assert.equal(observed.stats.recoveredPendingUses, 0);
  assert.equal(observed.status.receipts[0]?.state, "CLAIMED");
  assert.equal(observed.status.receipts[0]?.leaseState, "ACTIVE");
  dispatch.markDispatched();
  dispatch.complete("PASS");
  owner.close();
});

test("verified-dead owner cancels CLAIMED but freezes DISPATCHED without replay", async (t) => {
  const root = await mkdtemp(join(tmpdir(), "devspace-authority-dead-owner-"));
  t.after(async () => rm(root, { recursive: true, force: true }));
  const childNow = 1_787_064_700_000;
  for (const crashState of ["CLAIMED", "DISPATCHED"] as const) {
    const storePath = join(root, `${crashState.toLowerCase()}.sqlite`);
    const principal = `dead-owner-${crashState.toLowerCase()}-principal`;
    const descriptor = authorityActionFromToolCall("fs", {
      operation: "write",
      target: "local",
      path: `/tmp/dead-owner-${crashState.toLowerCase()}.txt`,
      content: `${crashState}\n`,
    });
    const childResult = await runAuthorityChild(`
      import { OperationAuthorityRegistry } from "./src/v2/authority.ts";
      import { minimumAuthorityRisk, authorityActionFromToolCall } from "./src/v2/authority-policy.ts";
      const state = String(process.env.B2_CRASH_STATE);
      const principal = String(process.env.B2_PRINCIPAL);
      const descriptor = authorityActionFromToolCall("fs", JSON.parse(String(process.env.B2_ACTION)));
      const owner = new OperationAuthorityRegistry({
        minimumRisk: minimumAuthorityRisk,
        storePath: process.env.B2_STORE_PATH,
        instanceId: "dead-owner-child-" + state.toLowerCase(),
        now: () => Number(process.env.B2_NOW_MS),
      });
      const created = owner.create({
        taskId: "dead-owner-task-" + state.toLowerCase(),
        authorityText: "Crash at the exact durable barrier.",
        actions: [{ descriptor }],
      }, principal);
      const dispatch = owner.prepareDispatch(String(created.authorityId), principal, descriptor, "R1");
      dispatch.claim();
      if (state === "DISPATCHED") dispatch.markDispatched();
      process.stdout.write(JSON.stringify({ authorityId: created.authorityId }) + "\\n", () => process.exit(0));
    `, {
      B2_STORE_PATH: storePath,
      B2_NOW_MS: String(childNow),
      B2_CRASH_STATE: crashState,
      B2_PRINCIPAL: principal,
      B2_ACTION: JSON.stringify({
        operation: "write",
        target: "local",
        path: `/tmp/dead-owner-${crashState.toLowerCase()}.txt`,
        content: `${crashState}\n`,
      }),
    }) as { authorityId: string };

    const now = { value: childNow + 60_000 };
    const recovered = registry(now, storePath, `dead-owner-parent-${crashState.toLowerCase()}`);
    const status = recovered.status(childResult.authorityId, principal) as {
      actions: Array<{ consumedUses: number }>;
      receipts: Array<{ state: string; leaseState: string; providerCallCount?: number }>;
    };
    if (crashState === "CLAIMED") {
      assert.equal(status.actions[0]?.consumedUses, 0);
      assert.equal(status.receipts[0]?.state, "CANCELLED_NOT_DISPATCHED");
      assert.equal(status.receipts[0]?.leaseState, "RELEASED");
      assert.equal(status.receipts[0]?.providerCallCount, 0);
      const retry = recovered.prepareDispatch(
        childResult.authorityId,
        principal,
        descriptor,
        "R1",
      );
      retry.claim();
      retry.cancelNotDispatched({
        providerCallCount: 0,
        proof: "TEST_DEAD_OWNER_RETRY_PROVIDER_ZERO",
      });
    } else {
      assert.equal(status.actions[0]?.consumedUses, 1);
      assert.equal(status.receipts[0]?.state, "UNCERTAIN");
      assert.equal(status.receipts[0]?.leaseState, "FROZEN");
      assert.throws(
        () => recovered.prepareDispatch(
          childResult.authorityId,
          principal,
          descriptor,
          "R1",
        ).claim(),
        (error: unknown) => ["AUTHORITY_CONSUMED", "RESOURCE_BUSY"].includes(String(code(error))),
      );
    }
    recovered.close();
  }
});

test("concurrent OS processes get one exact open authority identity", async (t) => {
  const root = await mkdtemp(join(tmpdir(), "devspace-authority-get-or-create-"));
  t.after(async () => rm(root, { recursive: true, force: true }));
  const storePath = join(root, "authority.sqlite");
  const bootstrap = registry({ value: 1_787_064_800_000 }, storePath, "get-or-create-bootstrap");
  const seedDescriptor = authorityActionFromToolCall("fs", {
    operation: "write",
    target: "local",
    path: "/tmp/get-or-create-seed.txt",
    content: "seed\n",
  });
  const seed = bootstrap.create({
    taskId: "get-or-create-shared-task",
    authorityText: "Seed the broker-issued task identity.",
    actions: [{ descriptor: seedDescriptor }],
  }, "get-or-create-principal");
  const taskInstanceId = String(seed.taskInstanceId);
  bootstrap.close();
  const source = `
    import { OperationAuthorityRegistry } from "./src/v2/authority.ts";
    import { minimumAuthorityRisk, authorityActionFromToolCall } from "./src/v2/authority-policy.ts";
    const owner = new OperationAuthorityRegistry({
      minimumRisk: minimumAuthorityRisk,
      storePath: process.env.B2_STORE_PATH,
      instanceId: String(process.env.B2_INSTANCE_ID),
      now: () => Number(process.env.B2_NOW_MS),
    });
    process.stdout.write("READY\\n");
    process.stdin.once("data", () => {
      const descriptor = authorityActionFromToolCall("fs", {
        operation: "write",
        target: "local",
        path: "/tmp/get-or-create.txt",
        content: "once\\n",
      });
      const created = owner.create({
        taskInstanceId: String(process.env.B2_TASK_INSTANCE_ID),
        authorityText: "Create exactly one durable open grant.",
        actions: [{ descriptor, uses: 1 }],
      }, "get-or-create-principal");
      process.stdout.write(JSON.stringify(created) + "\\n", () => {
        owner.close();
        process.exit(0);
      });
    });
  `;
  const first = spawnReadyAuthorityChild(source, {
    B2_STORE_PATH: storePath,
    B2_INSTANCE_ID: "get-or-create-child-a",
    B2_NOW_MS: "1787064800000",
    B2_TASK_INSTANCE_ID: taskInstanceId,
  });
  const second = spawnReadyAuthorityChild(source, {
    B2_STORE_PATH: storePath,
    B2_INSTANCE_ID: "get-or-create-child-b",
    B2_NOW_MS: "1787064800000",
    B2_TASK_INSTANCE_ID: taskInstanceId,
  });
  await Promise.all([first.ready, second.ready]);
  first.child.stdin.write("GO\n");
  second.child.stdin.write("GO\n");
  const [firstResult, secondResult] = await Promise.all([first.result, second.result]);
  assert.equal(firstResult.authorityId, secondResult.authorityId);
  assert.equal([firstResult.reused, secondResult.reused].filter(Boolean).length, 1);
  const sqlite = new Database(storePath, { readonly: true, fileMustExist: true });
  const durable = sqlite.prepare(`
    select count(*) as count, count(distinct fingerprint) as fingerprints
      from operation_authorities
     where fingerprint = (
       select fingerprint from operation_authorities where authority_id = ?
     )
  `).get(firstResult.authorityId) as { count: number; fingerprints: number };
  sqlite.close();
  assert.deepEqual(durable, { count: 1, fingerprints: 1 });
});

test("resource leases have validated foreign-key ownership", async (t) => {
  const root = await mkdtemp(join(tmpdir(), "devspace-authority-lease-fk-"));
  t.after(async () => rm(root, { recursive: true, force: true }));
  const storePath = join(root, "authority.sqlite");
  const authority = registry({ value: 1_787_064_900_000 }, storePath, "lease-fk-owner");
  authority.close();
  const sqlite = new Database(storePath, { readonly: true, fileMustExist: true });
  const foreignKeys = sqlite.pragma(
    "foreign_key_list(operation_authority_resource_leases)",
  ) as Array<{ table: string }>;
  sqlite.close();
  assert.equal(foreignKeys.some((key) => key.table === "operation_authority_tasks"), true);
  assert.equal(foreignKeys.some((key) => key.table === "operation_authority_actions"), true);
  assert.equal(foreignKeys.some((key) => key.table === "operation_authority_claims"), true);
});

test("atomic claim, use, and resource lease admit one writer and advance the fence after release", async (t) => {
  const root = await mkdtemp(join(tmpdir(), "devspace-authority-resource-race-"));
  t.after(async () => rm(root, { recursive: true, force: true }));
  const storePath = join(root, "authority.sqlite");
  const now = { value: 1_787_065_000_000 };
  const principal = "resource-race-principal";
  const firstAction = authorityActionFromToolCall("fs", {
    operation: "write",
    target: "local",
    path: "/tmp/shared-resource.txt",
    content: "first\n",
  });
  const secondAction = authorityActionFromToolCall("fs", {
    operation: "patch",
    target: "local",
    path: "/tmp/shared-resource.txt",
    patch: "*** Begin Patch\n*** Update File: shared-resource.txt\n@@\n-first\n+second\n*** End Patch",
  });
  const workerA = registry(now, storePath, "resource-race-worker-a");
  const first = workerA.create({
    taskId: "resource-race-a",
    authorityText: "Write the shared resource with the first exact action.",
    actions: [{ descriptor: firstAction }],
  }, principal);
  const workerB = registry(now, storePath, "resource-race-worker-b");
  const second = workerB.create({
    taskId: "resource-race-b",
    authorityText: "Mutate the shared resource with the second exact action.",
    actions: [{ descriptor: secondAction }],
  }, principal);

  const firstDispatch = workerA.prepareDispatch(
    String(first.authorityId),
    principal,
    firstAction,
    "R1",
  );
  const secondDispatch = workerB.prepareDispatch(
    String(second.authorityId),
    principal,
    secondAction,
    "R1",
  );
  const firstClaim = firstDispatch.claim();
  assert.throws(
    () => secondDispatch.claim(),
    (error: unknown) => code(error) === "RESOURCE_BUSY",
  );
  firstDispatch.markDispatched();
  let providerCalls = 1;
  firstDispatch.complete("PASS");
  assert.equal(providerCalls, 1);
  workerA.close();
  workerB.close();

  const reopened = registry(now, storePath, "resource-race-worker-reopened");
  const reopenedDispatch = reopened.prepareDispatch(
    String(second.authorityId),
    principal,
    secondAction,
    "R1",
  );
  const nextClaim = reopenedDispatch.claim();
  assert.equal(nextClaim.resourceKeySha256, firstClaim.resourceKeySha256);
  assert.ok(nextClaim.fencingToken > firstClaim.fencingToken);
  reopenedDispatch.cancelNotDispatched({
    providerCallCount: 0,
    proof: "TEST_ADAPTER_PROVIDER_CALL_COUNTER",
  });
  reopened.close();

  const reopenedAgain = registry(now, storePath, "resource-race-worker-reopened-again");
  const afterCancel = reopenedAgain.prepareDispatch(
    String(second.authorityId),
    principal,
    secondAction,
    "R1",
  );
  const afterCancelClaim = afterCancel.claim();
  assert.ok(afterCancelClaim.fencingToken > nextClaim.fencingToken);
  afterCancel.cancelNotDispatched({
    providerCallCount: 0,
    proof: "TEST_ADAPTER_PROVIDER_CALL_COUNTER",
  });
  reopenedAgain.close();
  assert.equal(providerCalls, 1);
});

test("claim transaction rolls back use, fence, claim, and lease when a later SQL step fails", async (t) => {
  const root = await mkdtemp(join(tmpdir(), "devspace-authority-claim-rollback-"));
  t.after(async () => rm(root, { recursive: true, force: true }));
  const storePath = join(root, "authority.sqlite");
  const now = { value: 1_787_065_500_000 };
  const principal = "claim-rollback-principal";
  const descriptor = authorityActionFromToolCall("fs", {
    operation: "write",
    target: "local",
    path: "/tmp/claim-rollback.txt",
    content: "atomic\n",
  });
  const authority = registry(now, storePath, "claim-rollback-owner");
  const created = authority.create({
    taskId: "claim-rollback-task",
    authorityText: "Reserve every durable claim component atomically.",
    actions: [{ descriptor, uses: 1 }],
  }, principal);
  const authorityId = String(created.authorityId);
  const fault = new Database(storePath);
  fault.exec(`
    create trigger fail_claim_insert before insert on operation_authority_claims
    begin
      select raise(abort, 'injected claim insert failure');
    end;
  `);
  assert.throws(
    () => authority.prepareDispatch(authorityId, principal, descriptor, "R1").claim(),
    (error: unknown) => code(error) === "AUTHORITY_STATE_UNCERTAIN",
  );
  const rolledBack = fault.prepare(`
    select
      (select consumed_uses from operation_authority_actions where authority_id = ?) as uses,
      (select count(*) from operation_authority_claims where authority_id = ?) as claims,
      (select count(*) from operation_authority_resource_fences) as fences,
      (select count(*) from operation_authority_resource_leases) as leases
  `).get(authorityId, authorityId) as {
    uses: number;
    claims: number;
    fences: number;
    leases: number;
  };
  assert.deepEqual(rolledBack, { uses: 0, claims: 0, fences: 0, leases: 0 });
  fault.exec("drop trigger fail_claim_insert");
  fault.close();

  const retry = authority.prepareDispatch(authorityId, principal, descriptor, "R1");
  const claim = retry.claim();
  assert.equal(claim.fencingToken, 1);
  retry.cancelNotDispatched({
    providerCallCount: 0,
    proof: "TEST_CLAIM_ROLLBACK_PROVIDER_ZERO",
  });
  authority.close();
});

test("resource keys serialize process aliases and MCP routes without colliding across targets", () => {
  const binding = {
    targetId: "local",
    targetGeneration: "local-generation-1",
    targetTransport: "local" as const,
    tty: true,
    launchRisk: "R2" as const,
  };
  const processKeys = [
    processAction({ operation: "write", processId: "process-shared", chars: "payload" }, binding),
    processAction({ operation: "resize", processId: "process-shared", columns: 80, rows: 24 }, binding),
    processAction({ operation: "signal", processId: "process-shared", signal: "SIGTERM" }, binding),
    processAction({ operation: "forget", processId: "process-shared" }, binding),
  ].map(actionResourceKeySha256);
  assert.equal(new Set(processKeys).size, 1);
  assert.notEqual(
    processKeys[0],
    actionResourceKeySha256(processAction(
      { operation: "write", processId: "process-other", chars: "payload" },
      binding,
    )),
  );

  const localPath = authorityActionFromToolCall("fs", {
    operation: "write",
    target: "local",
    path: "/tmp/same-path.txt",
    content: "local\n",
  });
  const remotePath = authorityActionFromToolCall("fs", {
    operation: "write",
    target: "company",
    path: "/tmp/same-path.txt",
    content: "remote\n",
  });
  assert.notEqual(actionResourceKeySha256(localPath), actionResourceKeySha256(remotePath));

  const firstMcp = authorityActionFromToolCall("mcp", {
    operation: "invoke",
    route: "jira",
    name: "create_issue",
    arguments: { summary: "first" },
  });
  const secondMcp = authorityActionFromToolCall("mcp", {
    operation: "invoke",
    route: "jira",
    name: "update_issue",
    arguments: { summary: "second" },
  });
  assert.equal(actionResourceKeySha256(firstMcp), actionResourceKeySha256(secondMcp));
});

test("proven pre-dispatch cancellation reclaims one-shot use and releases only its lease", async (t) => {
  const root = await mkdtemp(join(tmpdir(), "devspace-authority-cancel-"));
  t.after(async () => rm(root, { recursive: true, force: true }));
  const storePath = join(root, "authority.sqlite");
  const now = { value: 1_787_066_000_000 };
  const principal = "cancelled-claim-principal";
  const descriptor = authorityActionFromToolCall("exec", {
    target: "local",
    cwd: "/tmp",
    command: "git push origin cancelled-before-spawn",
  });
  const authority = registry(now, storePath, "cancelled-claim-worker");
  const created = authority.create({
    taskId: "cancel-before-dispatch",
    authorityText: "Attempt the exact command only after final validation.",
    actions: [{ descriptor, risk: "R3", uses: 1 }],
  }, principal);
  const dispatch = authority.prepareDispatch(
    String(created.authorityId),
    principal,
    descriptor,
    "R3",
  );
  const cancelledClaim = dispatch.claim();
  dispatch.cancelNotDispatched({
    providerCallCount: 0,
    proof: "TEST_SPAWN_COUNTER_ZERO",
  });
  const cancelledStatus = authority.status(String(created.authorityId), principal) as {
    actions: Array<{ consumedUses: number }>;
    receipts: Array<{ state: string; resourceKeySha256: string; fencingToken: number }>;
  };
  assert.equal(cancelledStatus.actions[0]?.consumedUses, 0);
  assert.equal(cancelledStatus.receipts[0]?.state, "CANCELLED_NOT_DISPATCHED");
  assert.equal(cancelledStatus.receipts[0]?.resourceKeySha256, cancelledClaim.resourceKeySha256);

  const retry = authority.prepareDispatch(
    String(created.authorityId),
    principal,
    descriptor,
    "R3",
  );
  const retryClaim = retry.claim();
  assert.ok(retryClaim.fencingToken > cancelledClaim.fencingToken);
  retry.markDispatched();
  assert.throws(
    () => retry.cancelNotDispatched({
      providerCallCount: 0,
      proof: "TEST_SPAWN_COUNTER_ZERO",
    }),
    (error: unknown) => code(error) === "AUTHORITY_STATE_UNCERTAIN",
  );
  retry.complete("PASS");
  authority.close();
});

test("restart cancels CLAIMED and freezes DISPATCHED crashes without replay", async (t) => {
  const root = await mkdtemp(join(tmpdir(), "devspace-authority-crash-barriers-"));
  t.after(async () => rm(root, { recursive: true, force: true }));
  const now = { value: 1_787_067_000_000 };
  for (const crashState of ["CLAIMED", "DISPATCHED"] as const) {
    const storePath = join(root, `${crashState.toLowerCase()}.sqlite`);
    const principal = `crash-${crashState.toLowerCase()}-principal`;
    const descriptor = authorityActionFromToolCall("exec", {
      target: "local",
      cwd: `/tmp/${crashState.toLowerCase()}`,
      command: `git push origin ${crashState.toLowerCase()}-crash`,
    });
    const first = registry(now, storePath, `${crashState.toLowerCase()}-owner-a`);
    const created = first.create({
      taskId: `${crashState.toLowerCase()}-crash-task`,
      authorityText: `Crash at ${crashState} without replay.`,
      actions: [{ descriptor, risk: "R3", uses: 1 }],
    }, principal);
    const authorityId = String(created.authorityId);
    const dispatch = first.prepareDispatch(authorityId, principal, descriptor, "R3");
    dispatch.claim();
    let providerCalls = 0;
    if (crashState === "DISPATCHED") {
      dispatch.markDispatched();
      providerCalls = 1;
    }
    first.close();

    now.value += 1;
    const recovered = registry(now, storePath, `${crashState.toLowerCase()}-owner-b`);
    const status = recovered.status(authorityId, principal) as {
      receipts: Array<{ state: string; leaseState: string; evidence?: { reasonCode?: string } }>;
    };
    assert.equal(
      status.receipts[0]?.state,
      crashState === "CLAIMED" ? "CANCELLED_NOT_DISPATCHED" : "UNCERTAIN",
    );
    assert.equal(status.receipts[0]?.leaseState, crashState === "CLAIMED" ? "RELEASED" : "FROZEN");
    assert.equal(
      status.receipts[0]?.evidence?.reasonCode,
      crashState === "CLAIMED"
        ? "OWNER_RUN_DEAD_BEFORE_DISPATCH"
        : "NONTERMINAL_CLAIM_RECOVERED",
    );
    if (crashState === "CLAIMED") {
      const retry = recovered.prepareDispatch(authorityId, principal, descriptor, "R3");
      retry.claim();
      retry.cancelNotDispatched({ providerCallCount: 0, proof: "TEST_RETRY_ZERO" });
    } else {
      assert.throws(
        () => recovered.prepareDispatch(authorityId, principal, descriptor, "R3").claim(),
        (error: unknown) => ["AUTHORITY_CONSUMED", "RESOURCE_BUSY"].includes(String(code(error))),
      );
    }
    assert.equal(providerCalls, crashState === "DISPATCHED" ? 1 : 0);

    const sameResource = authorityActionFromToolCall("exec", {
      target: "local",
      cwd: `/tmp/${crashState.toLowerCase()}`,
      command: `git push origin replacement-${crashState.toLowerCase()}`,
    });
    const sameResourceAuthority = recovered.create({
      taskId: `same-resource-${crashState.toLowerCase()}`,
      authorityText: "Attempt a distinct action against the frozen resource.",
      actions: [{ descriptor: sameResource, risk: "R3", uses: 1 }],
    }, principal);
    const sameResourceDispatch = recovered.prepareDispatch(
      String(sameResourceAuthority.authorityId),
      principal,
      sameResource,
      "R3",
    );
    if (crashState === "CLAIMED") {
      sameResourceDispatch.claim();
      sameResourceDispatch.cancelNotDispatched({
        providerCallCount: 0,
        proof: "TEST_SAME_RESOURCE_AFTER_CANCEL_ZERO",
      });
    } else {
      assert.throws(
        () => sameResourceDispatch.claim(),
        (error: unknown) => code(error) === "RESOURCE_BUSY",
      );
    }

    const unrelated = authorityActionFromToolCall("exec", {
      target: "local",
      cwd: `/tmp/unrelated-${crashState.toLowerCase()}`,
      command: `git push origin unrelated-${crashState.toLowerCase()}`,
    });
    const unrelatedAuthority = recovered.create({
      taskId: `unrelated-${crashState.toLowerCase()}`,
      authorityText: "The unrelated resource remains writable.",
      actions: [{ descriptor: unrelated, risk: "R3", uses: 1 }],
    }, principal);
    const unrelatedDispatch = recovered.prepareDispatch(
      String(unrelatedAuthority.authorityId),
      principal,
      unrelated,
      "R3",
    );
    unrelatedDispatch.claim();
    unrelatedDispatch.cancelNotDispatched({
      providerCallCount: 0,
      proof: "TEST_UNRELATED_PROVIDER_CALL_ZERO",
    });
    recovered.close();
  }
});

test("persistent terminal SQL fault rolls back receipt and lease, then restart freezes without replay", async (t) => {
  const root = await mkdtemp(join(tmpdir(), "devspace-authority-terminal-rollback-"));
  t.after(async () => rm(root, { recursive: true, force: true }));
  const storePath = join(root, "authority.sqlite");
  const now = { value: 1_787_068_000_000 };
  const authority = registry(now, storePath, "terminal-fault-owner-a");
  const principal = "receipt-fault-principal";
  const descriptor = authorityActionFromToolCall("fs", {
    operation: "write",
    target: "local",
    path: "/tmp/receipt-fault.txt",
    content: "provider-success\n",
  });
  const created = authority.create({
    taskId: "receipt-fault",
    authorityText: "Persist a terminal receipt for the exact write.",
    actions: [{ descriptor }],
  }, principal);
  const dispatch = authority.prepareDispatch(String(created.authorityId), principal, descriptor, "R1");
  const claim = dispatch.claim();
  dispatch.markDispatched();
  const providerCalls = 1;
  const fault = new Database(storePath);
  fault.exec(`
    create trigger fail_terminal_lease_delete
    before delete on operation_authority_resource_leases
    begin
      select raise(abort, 'injected persistent lease delete failure');
    end;
    create trigger fail_terminal_lease_update
    before update of lease_state on operation_authority_resource_leases
    when new.lease_state != old.lease_state
    begin
      select raise(abort, 'injected persistent lease transition failure');
    end;
  `);
  assert.throws(
    () => dispatch.complete("PASS"),
    (error: unknown) => code(error) === "AUTHORITY_STATE_UNCERTAIN",
  );
  assert.equal(providerCalls, 1);
  const rolledBack = fault.prepare(`
    select c.state, c.provider_call_count, l.lease_state,
           l.action_claim_id, l.fencing_token
      from operation_authority_claims c
      join operation_authority_resource_leases l
        on l.resource_key_sha256 = c.resource_key_sha256
     where c.action_claim_id = ?
  `).get(claim.actionClaimId) as {
    state: string;
    provider_call_count: number | null;
    lease_state: string;
    action_claim_id: string;
    fencing_token: number;
  };
  assert.deepEqual(rolledBack, {
    state: "DISPATCHED",
    provider_call_count: null,
    lease_state: "ACTIVE",
    action_claim_id: claim.actionClaimId,
    fencing_token: claim.fencingToken,
  });
  authority.close();
  fault.exec("drop trigger fail_terminal_lease_delete");
  fault.exec("drop trigger fail_terminal_lease_update");
  fault.close();

  now.value += 1;
  const recovered = registry(now, storePath, "terminal-fault-owner-b");
  const status = recovered.status(String(created.authorityId), principal) as {
    receipts: Array<{ state: string; leaseState: string; evidence?: { reasonCode?: string } }>;
  };
  assert.equal(status.receipts[0]?.state, "UNCERTAIN");
  assert.equal(status.receipts[0]?.leaseState, "FROZEN");
  assert.equal(status.receipts[0]?.evidence?.reasonCode, "NONTERMINAL_CLAIM_RECOVERED");
  assert.throws(
    () => recovered.prepareDispatch(String(created.authorityId), principal, descriptor, "R1").claim(),
    (error: unknown) => ["AUTHORITY_CONSUMED", "RESOURCE_BUSY"].includes(String(code(error))),
  );
  assert.equal(providerCalls, 1);
  recovered.close();
});

test("stale fencing token cannot terminalize or release the current writer", () => {
  const now = { value: 1_787_069_000_000 };
  const authority = registry(now);
  const principal = "stale-fence-principal";
  const firstDescriptor = authorityActionFromToolCall("fs", {
    operation: "write",
    target: "local",
    path: "/tmp/stale-fence.txt",
    content: "first\n",
  });
  const secondDescriptor = authorityActionFromToolCall("fs", {
    operation: "patch",
    target: "local",
    path: "/tmp/stale-fence.txt",
    patch: "*** Begin Patch\n*** Update File: stale-fence.txt\n@@\n-first\n+second\n*** End Patch",
  });
  const firstAuthority = authority.create({
    taskId: "stale-fence-first",
    authorityText: "First exact write.",
    actions: [{ descriptor: firstDescriptor }],
  }, principal);
  const firstDispatch = authority.prepareDispatch(
    String(firstAuthority.authorityId),
    principal,
    firstDescriptor,
    "R1",
  );
  const stale = firstDispatch.claim();
  firstDispatch.markDispatched();
  firstDispatch.complete("PASS");

  const secondAuthority = authority.create({
    taskId: "stale-fence-second",
    authorityText: "Second exact mutation.",
    actions: [{ descriptor: secondDescriptor }],
  }, principal);
  const currentDispatch = authority.prepareDispatch(
    String(secondAuthority.authorityId),
    principal,
    secondDescriptor,
    "R1",
  );
  const current = currentDispatch.claim();
  currentDispatch.markDispatched();
  const store = (authority as unknown as { store: DurableAuthorityStore }).store;
  assert.equal(store.terminalizeClaim({
    authorityId: current.authorityId,
    actionClaimId: current.actionClaimId,
    resourceKeySha256: current.resourceKeySha256,
    fencingToken: stale.fencingToken,
    completedAtMs: now.value,
    state: "FAIL",
    errorCode: "STALE_WRITER_TEST",
    maximumReceipts: 256,
  }), false);
  currentDispatch.complete("PASS");
  assert.ok(current.fencingToken > stale.fencingToken);
  authority.close();
});

test("correction preserves an in-flight receipt and epochs remain monotonic across workers", async (t) => {
  const root = await mkdtemp(join(tmpdir(), "devspace-authority-correction-"));
  t.after(async () => rm(root, { recursive: true, force: true }));
  const storePath = join(root, "authority.sqlite");
  const now = { value: 1_787_070_000_000 };
  const scopeId = "oauth-client:correction-client";
  const descriptor = authorityActionFromToolCall("exec", {
    target: "local",
    cwd: "/tmp",
    command: "git push origin correction-test",
    mode: "foreground",
  });
  const workerA = registry(now, storePath, "correction-worker-a");
  const created = workerA.create({
    taskId: "correction-one-shot",
    authorityText: "Dispatch this exact action before correction.",
    actions: [{ id: "one-shot", descriptor, risk: "R3", uses: 1 }],
  }, scopeId);
  const authorityId = String(created.authorityId);
  const taskInstanceId = String(created.taskInstanceId);
  const workerB = registry(now, storePath, "correction-worker-b");
  const grant = workerA.require(authorityId, scopeId, descriptor, "R3");
  assert.ok(grant);

  const firstCorrection = workerA.invalidate(
    scopeId,
    taskInstanceId,
    "Stop authorizing the old action.",
  );
  assert.equal(firstCorrection.correctionEpoch, 1);
  assert.deepEqual(firstCorrection.invalidatedAuthorityIds, [authorityId]);
  workerA.record(grant, "PASS", { reasonCode: "ACTION_COMPLETED_AFTER_CORRECTION" });
  const replacementFromStaleWorker = workerB.create({
    taskInstanceId,
    taskId: "correction-one-shot",
    authorityText: "Dispatch this exact action before correction.",
    actions: [{ id: "one-shot", descriptor, risk: "R3", uses: 1 }],
  }, scopeId);
  assert.equal(replacementFromStaleWorker.correctionEpoch, 1);
  assert.notEqual(replacementFromStaleWorker.authorityId, authorityId);
  assert.throws(
    () => workerB.status(authorityId, scopeId),
    (error: unknown) => code(error) === "AUTHORITY_STALE",
  );
  const secondCorrection = workerB.invalidate(
    scopeId,
    taskInstanceId,
    "Apply a second correction from a stale worker.",
  );
  assert.equal(secondCorrection.correctionEpoch, 2);
  assert.deepEqual(secondCorrection.invalidatedAuthorityIds, [replacementFromStaleWorker.authorityId]);
  workerA.close();
  workerB.close();

  const sqlite = new Database(storePath, { readonly: true, fileMustExist: true });
  const receipt = sqlite.prepare(
    "select state, reason_code from operation_authority_claims where authority_id = ?",
  ).get(authorityId) as { state: string; reason_code: string | null } | undefined;
  const task = sqlite.prepare(
    "select correction_epoch from operation_authority_tasks where task_instance_id = ?",
  ).get(taskInstanceId) as { correction_epoch: number } | undefined;
  sqlite.close();
  assert.deepEqual(receipt, {
    state: "PASS",
    reason_code: "ACTION_COMPLETED_AFTER_CORRECTION",
  });
  assert.equal(task?.correction_epoch, 2);

  const readback = registry(now, storePath, "correction-worker-readback");
  assert.equal((readback.stats() as { authorities: number }).authorities, 0);
  assert.throws(
    () => readback.require(authorityId, scopeId, descriptor, "R3"),
    (error: unknown) => code(error) === "AUTHORITY_STALE",
  );
  const replacement = readback.create({
    taskInstanceId,
    taskId: "correction-replacement",
    authorityText: "Create a replacement authority after both corrections.",
    actions: [{ id: "replacement", descriptor, risk: "R3", uses: 1 }],
  }, scopeId);
  assert.equal(replacement.correctionEpoch, 2);
  readback.close();
});

test("R3 authority is one-shot and cannot authorize a different exact action", () => {
  const authority = registry();
  const descriptor = authorityActionFromToolCall("exec", {
    target: "local",
    cwd: "/tmp",
    command: "git push origin main",
    mode: "foreground",
  });
  assert.equal(minimumAuthorityRisk(descriptor), "R3");
  const created = authority.create({
    taskId: "push-main",
    authorityText: "Push this exact branch once.",
    actions: [{ descriptor, risk: "R3", uses: 1 }],
  }, "client:session");
  const authorityId = String(created.authorityId);
  const grant = authority.require(authorityId, "client:session", descriptor, "R3");
  assert.ok(grant);
  assert.throws(
    () => authority.require(authorityId, "client:session", descriptor, "R3"),
    (error: unknown) => code(error) === "AUTHORITY_CONSUMED",
  );

  const changed = authorityActionFromToolCall("exec", {
    target: "local",
    cwd: "/tmp",
    command: "git push --force origin main",
    mode: "foreground",
  });
  assert.notEqual(actionFingerprint(changed), actionFingerprint(descriptor));
  assert.throws(
    () => authority.require(authorityId, "client:session", changed, "R3"),
    (error: unknown) => code(error) === "AUTHORITY_ACTION_MISMATCH",
  );
});

test("task-local correction invalidates Task A without invalidating Task B", () => {
  const authority = registry();
  const descriptor = authorityActionFromToolCall("gui", {
    operation: "act",
    target: "local",
    sessionId: "gui-1",
    generation: "g1",
    action: { type: "press", elementId: "e1" },
  });
  const createdA = authority.create({
    taskId: "press-confirm",
    authorityText: "Press Confirm once.",
    actions: [{ descriptor, risk: "R3" }],
  }, "client:session");
  const createdB = authority.create({
    taskId: "parallel-task",
    authorityText: "Keep the parallel task valid.",
    actions: [{ descriptor, risk: "R3" }],
  }, "client:session");
  const authorityA = String(createdA.authorityId);
  const authorityB = String(createdB.authorityId);
  const correction = authority.invalidate(
    "client:session",
    String(createdA.taskInstanceId),
    "Do not press Confirm.",
  );
  assert.deepEqual(correction.invalidatedAuthorityIds, [authorityA]);
  assert.throws(
    () => authority.require(authorityA, "client:session", descriptor, "R3"),
    (error: unknown) => code(error) === "AUTHORITY_STALE",
  );
  assert.ok(authority.status(authorityB, "client:session"));
});

test("authority preview classifies exact actions without creating or consuming authority", () => {
  const authority = registry();
  const authorityStore = authority as unknown as { store: unknown };
  const originalStore = authorityStore.store;
  let storeCalls = 0;
  authorityStore.store = new Proxy({}, {
    get() {
      storeCalls += 1;
      throw new Error("authority_preview must not read or write the durable authority store");
    },
  });
  const read = authorityActionFromToolCall("fs", {
    operation: "read",
    target: "local",
    path: "/tmp/example.txt",
  });
  const write = authorityActionFromToolCall("fs", {
    operation: "write",
    target: "local",
    path: "/tmp/example.txt",
    content: "value\n",
  });
  const push = authorityActionFromToolCall("exec", {
    target: "local",
    cwd: "/tmp",
    command: "git push origin main",
  });
  const first = authority.preview([
    { id: "read", descriptor: read },
    { id: "write", descriptor: write, uses: 2 },
    { id: "push", descriptor: push },
  ]);
  const second = authority.preview([
    { id: "read", descriptor: read },
    { id: "write", descriptor: write, uses: 2 },
    { id: "push", descriptor: push },
  ]);
  authorityStore.store = originalStore;
  assert.equal(first.authorityRequired, true);
  assert.equal(first.actionCount, 3);
  assert.equal(first.authorityActionCount, 2);
  assert.equal(first.r0ActionCount, 1);
  assert.equal(first.planFingerprint, second.planFingerprint);
  assert.equal(storeCalls, 0);
  assert.deepEqual(
    (first.actions as Array<{ id: string; minimumRisk: string; maximumUses: number }>).map(
      ({ id, minimumRisk, maximumUses }) => ({ id, minimumRisk, maximumUses }),
    ),
    [
      { id: "read", minimumRisk: "R0", maximumUses: 0 },
      { id: "write", minimumRisk: "R1", maximumUses: 2 },
      { id: "push", minimumRisk: "R3", maximumUses: 1 },
    ],
  );
  assert.deepEqual(authority.stats(), {
    authorities: 0,
    tasks: 0,
    principals: 0,
    scopes: 0,
    pendingReservations: 0,
    recoveredPendingUses: 0,
    previews: 2,
  });
  assert.throws(
    () => authority.preview([{ descriptor: read, risk: "R1" }]),
    /is R0; omit risk and uses/u,
  );
  assert.throws(
    () => authority.preview([
      { id: "duplicate-one", descriptor: write },
      { id: "duplicate-two", descriptor: write },
    ]),
    /Duplicate exact authority actions.*combine repeated identical calls/u,
  );
  assert.throws(
    () => authority.create({
      taskId: "duplicate-create",
      authorityText: "Repeated exact actions must use one bounded action record.",
      actions: [
        { id: "duplicate-one", descriptor: write },
        { id: "duplicate-two", descriptor: write },
      ],
    }, "client:session"),
    /Duplicate exact authority actions.*combine repeated identical calls/u,
  );
});

test("R0 actions cannot be wrapped in authority and elevation commands fail closed", () => {
  const authority = registry();
  const read = authorityActionFromToolCall("fs", {
    operation: "read",
    target: "local",
    path: "/tmp/example.txt",
  });
  assert.equal(minimumAuthorityRisk(read), "R0");
  assert.throws(
    () => authority.create({
      taskId: "unnecessary-read",
      authorityText: "Read the file.",
      actions: [{ descriptor: read }],
    }, "client:session"),
    /must run without task authority/u,
  );

  for (const command of [
    "sudo -n id",
    "s'u'do -n id",
    "/usr/bin/env sudo id",
    "doas id",
    "pkexec sh",
    "osascript -e 'do shell script \"id\" with administrator privileges'",
    "powershell Start-Process cmd -Verb RunAs",
    "Start-Process cmd -Verb RunAs",
    "powershell -EncodedCommand=dGVzdA==",
    "sh -c 'sudo -n id'",
    "printf \"$(s'u'do -n id)\"",
    "printf \"`sudo -n id`\"",
    "env -u PATH sudo -n id",
    "env -S 'sudo -n id'",
  ]) {
    assert.throws(
      () => assertNoElevationCommand(command),
      (error: unknown) => code(error) === "ELEVATION_BLOCKED",
      command,
    );
  }
  assert.doesNotThrow(() => assertNoElevationCommand("printf \"sudo id\""));
  assert.doesNotThrow(() => assertNoElevationCommand("printf 'sudo id'"));
  assert.doesNotThrow(() => assertNoElevationCommand("printf '$(sudo id)'"));
  assert.equal(commandRisk("git status --short", "local"), "R0");
  assert.equal(commandRisk("git branch new-name", "local"), "R2");
  assert.equal(commandRisk("git diff --output=file", "local"), "R2");
  assert.equal(commandRisk("printf value > file", "local"), "R2");
  assert.equal(commandRisk("printf '$(date)'", "local"), "R0");
  assert.equal(commandRisk("printf \"$(date)\"", "local"), "R3");
  assert.equal(commandRisk("printf \"$(rm -rf /tmp/x)\"", "local"), "R3");
  assert.equal(commandRisk("printf '$(rm -rf /tmp/x)'", "local"), "R0");
  assert.equal(commandRisk("printf \"`rm -rf /tmp/x`\"", "local"), "R3");
  assert.equal(commandRisk("printf '`rm -rf /tmp/x`'", "local"), "R0");
  assert.equal(commandRisk("cat <(rm -rf /tmp/x)", "local"), "R3");
  assert.equal(commandRisk("source ./profile", "local"), "R3");
  assert.equal(commandRisk("eval 'git status'", "local"), "R3");
  assert.equal(commandRisk("node -e 'process.stdout.write(\"ok\")'", "local"), "R3");
  assert.equal(commandRisk("npx tsx ./script.ts", "local"), "R3");
  assert.equal(commandRisk("base64 --decode payload", "local"), "R3");
  assert.equal(commandRisk("npm run deploy", "local"), "R3");
  assert.equal(commandRisk("docker push example.test/image:latest", "local"), "R3");
  assert.equal(commandRisk("npm run arbitrary-script", "local"), "R2");
  assert.equal(commandRisk("npm run build", {
    targetId: "local",
    targetTransport: "local",
    targetPlatform: "macos",
    shellDialect: "zsh",
  }), "R1");
  assert.equal(commandRisk("npm run build", {
    targetId: "company",
    targetTransport: "ssh",
    targetPlatform: "macos",
    shellDialect: "zsh",
  }), "R2");
  assert.equal(commandRisk("git status --short", {
    targetId: "local",
    targetTransport: "local",
    targetPlatform: "macos",
    shellDialect: "zsh",
    mode: "background",
  }), "R1");
  assert.equal(commandRisk("git status --short", {
    targetId: "local",
    targetTransport: "local",
    targetPlatform: "macos",
    shellDialect: "zsh",
    tty: true,
  }), "R1");
  assert.equal(commandRisk("git status --short", {
    targetId: "local",
    targetTransport: "local",
    targetPlatform: "macos",
    shellDialect: "zsh",
    envProfile: "developer",
  }), "R2");
  for (const shellDialect of ["powershell", "cmd"] as const) {
    assert.equal(commandRisk("git status --short", {
      targetId: "windows",
      targetTransport: "ssh",
      targetPlatform: "windows",
      shellDialect,
    }), "R2");
  }
  assert.equal(commandRisk("git commit -m test", "local"), "R2");
  assert.equal(commandRisk("rm -rf /tmp/example", "local"), "R3");
  assert.equal(commandRisk("python3 -c 'import shutil; shutil.rmtree(\"/tmp/example\")'", "local"), "R3");
  assert.equal(commandRisk("find /tmp/example -delete", "local"), "R3");
  assert.equal(commandRisk("curl -d x=1 https://example.test", "local"), "R3");
  assert.equal(commandRisk("printf x | sh", "local"), "R3");
  assert.equal(commandRisk("env sh -c touch /tmp/x", "local"), "R3");
  for (const command of [
    "env -u PATH rm -rf /tmp/x",
    "env -C /tmp rm -rf x",
    "env --unset PATH rm -rf /tmp/x",
    "env --chdir /tmp rm -rf x",
    "env --chdir=/tmp rm -rf x",
    "env -S 'rm -rf /tmp/x'",
    "env --split-string 'rm -rf /tmp/x'",
    "env --argv0 broker rm -rf /tmp/x",
    "env --argv0=broker rm -rf /tmp/x",
    "env -- rm -rf /tmp/x",
  ]) {
    assert.equal(commandRisk(command, "local"), "R3", command);
  }
  for (const command of [
    "env KEY=value git status --short",
    "env -u PATH git status --short",
    "env -C /tmp git status --short",
    "env -- git status --short",
  ]) {
    assert.equal(commandRisk(command, "local"), "R2", command);
  }
  assert.equal(commandRisk("find /tmp -fprint /tmp/index", "local"), "R3");
  assert.equal(commandRisk("printf x | xargs touch", "local"), "R3");
  assert.equal(commandRisk("printf x | xargs rm -rf /tmp/x", "local"), "R3");
  assert.equal(commandRisk("nohup rm -rf /tmp/x", "local"), "R3");
  assert.equal(commandRisk("timeout 1 rm -rf /tmp/x", "local"), "R3");
  assert.equal(commandRisk("parallel rm -rf ::: /tmp/x", "local"), "R3");
  assert.equal(commandRisk("kill -9 123", "local"), "R3");
  assert.equal(commandRisk("pkill worker", "local"), "R3");
  assert.equal(commandRisk("ssh example.test rm -rf /tmp/x", "local"), "R3");
  assert.equal(commandRisk("{ rm -rf /tmp/x; }", "local"), "R3");
  assert.equal(commandRisk("if true; then rm -rf /tmp/x; fi", "local"), "R3");
  assert.equal(commandRisk("printf x | while read x; do rm -rf /tmp/x; done", "local"), "R3");
  assert.equal(commandRisk("printf ok # harmless\nrm -rf /tmp/x", "local"), "R3");
  assert.equal(commandRisk(`${["printf", ...Array.from({ length: 260 }, () => "x")].join(" ")}; rm -rf /tmp/x`, "local"), "R3");
  assert.equal(commandRisk("runner=rm; $runner -rf /tmp/x", "local"), "R3");
  assert.equal(commandRisk("python3.12 -c 'import shutil; shutil.rmtree(\"/tmp/x\")'", "local"), "R3");
  assert.equal(commandRisk("php8.3 -r 'unlink(\"/tmp/x\");'", "local"), "R3");
  assert.equal(commandRisk("awk 'BEGIN { system(\"rm -rf /tmp/x\") }'", "local"), "R3");
  assert.equal(commandRisk(String.raw`Remove-Item -Recurse C:\temp\x`, {
    targetId: "windows",
    targetTransport: "ssh",
    targetPlatform: "windows",
    shellDialect: "powershell",
  }), "R3");
  assert.equal(commandRisk(String.raw`$cmd='Remove-Item'; & $cmd -Recurse C:\temp\x`, {
    targetId: "windows",
    targetTransport: "ssh",
    targetPlatform: "windows",
    shellDialect: "powershell",
  }), "R3");
  assert.equal(commandRisk(String.raw`Invoke-Expression "Remove-Item -Recurse C:\temp\x"`, {
    targetId: "windows",
    targetTransport: "ssh",
    targetPlatform: "windows",
    shellDialect: "powershell",
  }), "R3");
  assert.equal(commandRisk(String.raw`del C:\temp\x`, {
    targetId: "windows",
    targetTransport: "ssh",
    targetPlatform: "windows",
    shellDialect: "cmd",
  }), "R3");
  assert.equal(commandRisk(String.raw`if exist C:\temp\x del C:\temp\x`, {
    targetId: "windows",
    targetTransport: "ssh",
    targetPlatform: "windows",
    shellDialect: "cmd",
  }), "R3");
  assert.equal(commandRisk(String.raw`set c=del & %c% C:\temp\x`, {
    targetId: "windows",
    targetTransport: "ssh",
    targetPlatform: "windows",
    shellDialect: "cmd",
  }), "R3");
  assert.equal(mcpRisk("invoke", { readOnly: true }), "R2");
  assert.equal(mcpRisk("invoke", {}), "R2");
  assert.equal(mcpRisk("invoke", { destructive: true }), "R2");
  assert.equal(mcpRisk("invoke", { riskDecision: "R0" }), "R0");
  assert.equal(mcpRisk("invoke", { riskDecision: "R3" }), "R3");
  assert.equal(commandRisk("git branch --delete obsolete", "local"), "R3");
  assert.equal(commandRisk("git tag --delete obsolete", "local"), "R3");
  assert.equal(commandRisk("git stash clear", "local"), "R3");
});

test("exec and process policy binds exact execution dimensions and raises mutations conservatively", () => {
  const baseExec = execAction(
    { command: "git status --short", mode: "auto" },
    "local",
    "/tmp/project",
    {
      targetGeneration: "target-generation-a",
      targetTransport: "local",
      targetPlatform: "macos",
      shellDialect: "zsh",
      effectiveEnvProfile: "developer",
      effectiveEnvProfileGeneration: "profile-generation-a",
    },
  );
  assert.equal(baseExec.parameters?.classifierGeneration, EXEC_RISK_CLASSIFIER_GENERATION);
  const execVariants = [
    execAction(
      { command: "git status --short ", mode: "auto" },
      "local",
      "/tmp/project",
      {
        targetGeneration: "target-generation-a",
        targetTransport: "local",
        targetPlatform: "macos",
        shellDialect: "zsh",
        effectiveEnvProfile: "developer",
        effectiveEnvProfileGeneration: "profile-generation-a",
      },
    ),
    execAction(
      { command: "git status --short", mode: "background" },
      "local",
      "/tmp/project",
      {
        targetGeneration: "target-generation-a",
        targetTransport: "local",
        targetPlatform: "macos",
        shellDialect: "zsh",
        effectiveEnvProfile: "developer",
        effectiveEnvProfileGeneration: "profile-generation-a",
      },
    ),
    execAction(
      { command: "git status --short", mode: "auto", tty: true },
      "local",
      "/tmp/project",
      {
        targetGeneration: "target-generation-a",
        targetTransport: "local",
        targetPlatform: "macos",
        shellDialect: "zsh",
        effectiveEnvProfile: "developer",
        effectiveEnvProfileGeneration: "profile-generation-a",
      },
    ),
    execAction(
      { command: "git status --short", mode: "auto" },
      "local",
      "/tmp/project",
      {
        targetGeneration: "target-generation-b",
        targetTransport: "local",
        targetPlatform: "macos",
        shellDialect: "zsh",
        effectiveEnvProfile: "developer",
        effectiveEnvProfileGeneration: "profile-generation-a",
      },
    ),
    execAction(
      { command: "git status --short", mode: "auto" },
      "local",
      "/tmp/project",
      {
        targetGeneration: "target-generation-a",
        targetTransport: "ssh",
        targetPlatform: "linux",
        shellDialect: "bash",
        effectiveEnvProfile: "developer",
        effectiveEnvProfileGeneration: "profile-generation-a",
      },
    ),
    execAction(
      { command: "git status --short", mode: "auto" },
      "local",
      "/tmp/project",
      {
        targetGeneration: "target-generation-a",
        targetTransport: "local",
        targetPlatform: "macos",
        shellDialect: "zsh",
        effectiveEnvProfile: "other-profile",
        effectiveEnvProfileGeneration: "profile-generation-a",
      },
    ),
    execAction(
      { command: "git status --short", mode: "auto" },
      "local",
      "/tmp/project",
      {
        targetGeneration: "target-generation-a",
        targetTransport: "local",
        targetPlatform: "macos",
        shellDialect: "zsh",
        effectiveEnvProfile: "developer",
        effectiveEnvProfileGeneration: "profile-generation-b",
      },
    ),
  ];
  for (const variant of execVariants) {
    assert.notEqual(actionFingerprint(variant), actionFingerprint(baseExec));
  }

  assert.equal(processRisk("poll"), "R0");
  assert.equal(processRisk("wait"), "R0");
  assert.equal(processRisk("list"), "R0");
  assert.equal(processRisk("restart_status"), "R0");
  assert.equal(processRisk("resize", { targetTransport: "local" }), "R1");
  assert.equal(processRisk("resize", { targetTransport: "ssh" }), "R2");
  assert.equal(processRisk("resize"), "R2");
  assert.equal(processRisk("write", { launchRisk: "R0" }), "R2");
  assert.equal(processRisk("write", { launchRisk: "R3" }), "R3");
  assert.equal(processRisk("signal", { signal: "SIGTERM" }), "R3");
  assert.equal(processRisk("signal", { signal: "unexpected" }), "R3");
  assert.equal(processRisk("forget"), "R3");
  assert.equal(processRisk("restart_broker"), "R3");
  assert.equal(processRisk("unknown"), "R3");

  const localResize = processAction(
    { operation: "resize", processId: "proc-1", columns: 80, rows: 24 },
    {
      targetId: "local",
      targetGeneration: "target-generation-a",
      targetTransport: "local",
      tty: true,
      launchRisk: "R1",
    },
  );
  const changedGenerationResize = processAction(
    { operation: "resize", processId: "proc-1", columns: 80, rows: 24 },
    {
      targetId: "local",
      targetGeneration: "target-generation-b",
      targetTransport: "local",
      tty: true,
      launchRisk: "R1",
    },
  );
  const remoteResize = processAction(
    { operation: "resize", processId: "proc-1", columns: 80, rows: 24 },
    { targetId: "company", targetTransport: "ssh", tty: true, launchRisk: "R1" },
  );
  assert.notEqual(actionFingerprint(localResize), actionFingerprint(changedGenerationResize));
  assert.notEqual(actionFingerprint(localResize), actionFingerprint(remoteResize));
});

function code(error: unknown): string | undefined {
  return error instanceof UniversalBrokerError ? error.code : undefined;
}

async function runAuthorityChild(
  source: string,
  environment: Record<string, string>,
): Promise<unknown> {
  const child = spawn(process.execPath, [
    "--import",
    "tsx",
    "--input-type=module",
    "--eval",
    source,
  ], {
    cwd: process.cwd(),
    env: { ...process.env, ...environment },
    stdio: ["ignore", "pipe", "pipe"],
  });
  let stdout = "";
  let stderr = "";
  child.stdout.setEncoding("utf8");
  child.stderr.setEncoding("utf8");
  child.stdout.on("data", (value: string) => { stdout += value; });
  child.stderr.on("data", (value: string) => { stderr += value; });
  const exitCode = await new Promise<number | null>((resolve, reject) => {
    child.once("error", reject);
    child.once("close", resolve);
  });
  assert.equal(exitCode, 0, stderr || stdout);
  const line = stdout.trim().split("\n").at(-1);
  assert.ok(line, stderr || "child produced no JSON output");
  return JSON.parse(line) as unknown;
}

function spawnReadyAuthorityChild(
  source: string,
  environment: Record<string, string>,
): {
  child: ChildProcessWithoutNullStreams;
  ready: Promise<void>;
  result: Promise<Record<string, unknown>>;
} {
  const child = spawn(process.execPath, [
    "--import",
    "tsx",
    "--input-type=module",
    "--eval",
    source,
  ], {
    cwd: process.cwd(),
    env: { ...process.env, ...environment },
    stdio: ["pipe", "pipe", "pipe"],
  });
  const lines = createInterface({ input: child.stdout });
  let readyResolve!: () => void;
  let resultResolve!: (value: Record<string, unknown>) => void;
  let resultReject!: (error: Error) => void;
  let stderr = "";
  child.stderr.setEncoding("utf8");
  child.stderr.on("data", (value: string) => { stderr += value; });
  const ready = new Promise<void>((resolve) => { readyResolve = resolve; });
  const result = new Promise<Record<string, unknown>>((resolve, reject) => {
    resultResolve = resolve;
    resultReject = reject;
  });
  lines.on("line", (line) => {
    if (line === "READY") readyResolve();
    else if (line.trim()) {
      try {
        resultResolve(JSON.parse(line) as Record<string, unknown>);
      } catch (error) {
        resultReject(error instanceof Error ? error : new Error(String(error)));
      }
    }
  });
  child.once("error", resultReject);
  child.once("close", (exitCode) => {
    if (exitCode !== 0) resultReject(new Error(stderr || `child exited ${String(exitCode)}`));
  });
  return { child, ready, result };
}
