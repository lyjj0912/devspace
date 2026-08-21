import assert from "node:assert/strict";
import { mkdtemp, mkdir, readFile, readdir, rename, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import {
  checksumRecord,
  cleanupRecoveryFixture,
  planRecoveryFixture,
  prepareRecoveryFixture,
  verifyCleanFixture,
  verifyInputFixture,
  verifyRecoveredFixture,
} from "./personal-actual-host-recovery-fixture.mjs";

test("live recovery fixture is collision-safe, owner-bound, and exactly cleaned", async (t) => {
  const root = await mkdtemp(join(tmpdir(), "devspace-live-recovery-"));
  t.after(() => rm(root, { recursive: true, force: true }));
  const stateDirectory = join(root, "state");
  const processDirectory = join(stateDirectory, "processes");
  const outputDirectory = join(stateDirectory, "process-output");
  await mkdir(processDirectory, { recursive: true });
  await mkdir(outputDirectory, { recursive: true });
  const baseline = unsignedTemplate(join(outputDirectory, "proc_existing.log"));
  const baselinePath = join(processDirectory, "proc_existing.json");
  await writeFile(baselinePath, JSON.stringify({ ...baseline, checksum: checksumRecord(baseline) }));
  await writeFile(baseline.outputPath, "baseline");
  const baselineBytes = await readFile(baselinePath);
  const options = {
    fixtureId: "pdo-e2e-test-20260821",
    stateDirectory,
    outputDirectory,
    terminalCount: 1_000,
    expiredCount: 2,
    runningCount: 2,
    now: 1_800_000_000_000,
  };

  const plan = await planRecoveryFixture(options);
  assert.equal(plan.collisionCount, 0);
  assert.equal(plan.baselineRecordCount, 1);
  const prepared = await prepareRecoveryFixture(options);
  assert.equal(prepared.phase, "INPUT_READY");
  assert.equal(prepared.validRecordCount, 1_004);
  assert.equal(prepared.corruptRecordCount, 1);
  assert.deepEqual(prepared.states, { EXITED: 1_002, RUNNING: 2 });
  await assert.rejects(prepareRecoveryFixture(options), /prefix already exists/u);
  const verified = await verifyInputFixture(options);
  assert.equal(verified.phase, prepared.phase);
  assert.equal(verified.validRecordCount, prepared.validRecordCount);
  assert.deepEqual(verified.states, prepared.states);
  assert.deepEqual(await readFile(baselinePath), baselineBytes);

  for (let index = 0; index < 2; index += 1) {
    const processId = `proc_pdo-e2e-test-20260821-expired-${String(index).padStart(4, "0")}`;
    await rm(join(processDirectory, `${processId}.json`));
    await rm(join(outputDirectory, `${processId}.log`));
  }
  for (let index = 0; index < 2; index += 1) {
    const processId = `proc_pdo-e2e-test-20260821-running-${String(index).padStart(4, "0")}`;
    const path = join(processDirectory, `${processId}.json`);
    const { checksum: _checksum, ...record } = JSON.parse(await readFile(path, "utf8"));
    record.state = "UNKNOWN";
    record.endedAtMs = options.now + index;
    await writeFile(path, JSON.stringify({ ...record, checksum: checksumRecord(record) }));
  }
  const corrupt = join(processDirectory, "proc_pdo-e2e-test-20260821-corrupt.json");
  await rename(corrupt, `${corrupt}.corrupt-test`);
  const recovered = await verifyRecoveredFixture(options);
  assert.equal(recovered.phase, "RECOVERED");
  assert.equal(recovered.retainedTerminalCount, 1_000);
  assert.equal(recovered.prunedExpiredCount, 2);
  assert.deepEqual(recovered.reconciledRunningStates, ["UNKNOWN", "UNKNOWN"]);
  assert.equal(recovered.quarantinedCorruptCount, 1);

  const cleaned = await cleanupRecoveryFixture(options);
  assert.equal(cleaned.phase, "CLEAN");
  assert.equal(cleaned.baseline.changed.length, 0);
  await verifyCleanFixture(options);
  assert.deepEqual(await readFile(baselinePath), baselineBytes);
  assert.deepEqual((await readdir(processDirectory)).sort(), ["proc_existing.json"]);
  assert.deepEqual((await readdir(outputDirectory)).sort(), ["proc_existing.log"]);
});

test("live recovery fixture refuses output roots outside state", async () => {
  await assert.rejects(planRecoveryFixture({
    fixtureId: "pdo-e2e-test-20260821",
    stateDirectory: "/tmp/state",
    outputDirectory: "/tmp/output",
  }), /must stay inside/u);
});

function unsignedTemplate(outputPath) {
  return {
    schemaVersion: 1,
    processId: "proc_existing",
    principalKeyFingerprint: "a".repeat(64),
    targetId: "company",
    targetGeneration: `sha256:${"b".repeat(64)}`,
    transport: "ssh",
    cwd: "/tmp",
    tty: false,
    launchRisk: "R0",
    state: "RUNNING",
    startedAtMs: 1_799_999_000_000,
    outputPath,
    durable: false,
  };
}
