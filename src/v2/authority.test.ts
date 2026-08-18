import assert from "node:assert/strict";
import test from "node:test";
import {
  OperationAuthorityRegistry,
  actionFingerprint,
} from "./authority.js";
import {
  assertNoElevationCommand,
  authorityActionFromToolCall,
  commandRisk,
  mcpRisk,
  minimumAuthorityRisk,
} from "./authority-policy.js";
import { UniversalBrokerError } from "./errors.js";

function registry(now: { value: number } = { value: Date.now() }) {
  return new OperationAuthorityRegistry({
    now: () => now.value,
    minimumRisk: minimumAuthorityRisk,
  });
}

test("exact R1 authority is session-bound, receipted, and bounded by uses", () => {
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
    (error: unknown) => code(error) === "AUTHORITY_EXPIRED",
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
  const reusedBeforeUse = authority.create(input, "client:session");
  assert.equal(reusedBeforeUse.authorityId, firstId);
  assert.equal(reusedBeforeUse.reused, true);
  const grant = authority.require(firstId, "client:session", descriptor, "R1");
  authority.record(grant, "PASS");
  const second = authority.create(input, "client:session");
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
});

test("correction invalidates every authority in the same session epoch", () => {
  const authority = registry();
  const descriptor = authorityActionFromToolCall("gui", {
    operation: "act",
    target: "local",
    sessionId: "gui-1",
    generation: "g1",
    action: { type: "press", elementId: "e1" },
  });
  const created = authority.create({
    taskId: "press-confirm",
    authorityText: "Press Confirm once.",
    actions: [{ descriptor, risk: "R3" }],
  }, "client:session");
  const authorityId = String(created.authorityId);
  const correction = authority.invalidate("client:session", "Do not press Confirm.");
  assert.deepEqual(correction.invalidatedAuthorityIds, [authorityId]);
  assert.throws(
    () => authority.require(authorityId, "client:session", descriptor, "R3"),
    (error: unknown) => code(error) === "AUTHORITY_EXPIRED",
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
    "/usr/bin/env sudo id",
    "doas id",
    "pkexec sh",
    "osascript -e 'do shell script \"id\" with administrator privileges'",
    "powershell Start-Process cmd -Verb RunAs",
  ]) {
    assert.throws(
      () => assertNoElevationCommand(command),
      (error: unknown) => code(error) === "ELEVATION_BLOCKED",
      command,
    );
  }
  assert.equal(commandRisk("git status --short", "local"), "R0");
  assert.equal(commandRisk("npm run build", "local"), "R1");
  assert.equal(commandRisk("npm run build", "company"), "R2");
  assert.equal(commandRisk("git commit -m test", "local"), "R2");
  assert.equal(commandRisk("rm -rf /tmp/example", "local"), "R3");
  assert.equal(commandRisk("python3 -c 'import shutil; shutil.rmtree(\"/tmp/example\")'", "local"), "R3");
  assert.equal(commandRisk("find /tmp/example -delete", "local"), "R3");
  assert.equal(commandRisk("curl -d x=1 https://example.test", "local"), "R3");
  assert.equal(commandRisk("printf x | sh", "local"), "R3");
  assert.equal(commandRisk("env sh -c touch /tmp/x", "local"), "R3");
  assert.equal(commandRisk("find /tmp -fprint /tmp/index", "local"), "R3");
  assert.equal(commandRisk("printf x | xargs touch", "local"), "R2");
  assert.equal(mcpRisk("invoke", { readOnly: true }), "R2");
  assert.equal(mcpRisk("invoke", { destructive: true }), "R3");
});

function code(error: unknown): string | undefined {
  return error instanceof UniversalBrokerError ? error.code : undefined;
}
