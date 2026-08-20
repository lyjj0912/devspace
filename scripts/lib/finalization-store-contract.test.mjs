import assert from "node:assert/strict";
import { spawn, spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import {
  chmodSync,
  copyFileSync,
  lstatSync,
  mkdirSync,
  mkdtempSync,
  realpathSync,
  readFileSync,
  readdirSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import test from "node:test";
import { DatabaseSync } from "node:sqlite";
import {
  bootstrapFinalizationStore,
  commitActivationPending,
  commitBaseProfileFinalPass,
  commitCanonicalFinalizationSeal,
  commitDraining,
  commitPostActivationVerified,
  commitPreparedFinalization,
  commitProfileGatesEvaluated,
  createFinalizationStoreBootstrapAuthorization,
  initializeFinalizationStore,
  readFinalizationStoreIdentity,
  readFinalizationStoreLedger,
  recoverFinalizationStoreControl,
  requestFinalizationStoreRollback,
  verifyFinalizationStoreRollback,
  FINALIZATION_STORE_ID,
} from "./finalization-store-contract.mjs";

const THIS_FILE = realpathSync(fileURLToPath(import.meta.url));
const MODULE_URL = pathToFileURL(join(dirname(THIS_FILE), "finalization-store-contract.mjs")).href;
const NODE = process.execPath;
const CANONICAL_NOW = "2026-08-20T00:00:00.000Z";
const DIGEST_RE = /^sha256:[a-f0-9]{64}$/u;

function tempRoot(label) {
  const root = realpathSync(mkdtempSync(join(realpathSync(tmpdir()), `${label}-`)));
  chmodSync(root, 0o700);
  return root;
}

function secureDir(path) {
  mkdirSync(path, { recursive: true, mode: 0o700 });
  chmodSync(path, 0o700);
  return path;
}

function secureFile(path, bytes) {
  writeFileSync(path, bytes, { mode: 0o600 });
  chmodSync(path, 0o600);
  return path;
}

function paths(root, name) {
  const stateRoot = secureDir(join(root, name, "state"));
  const controlRoot = secureDir(join(root, name, "control"));
  return {
    stateRoot,
    controlRoot,
    storePath: join(stateRoot, "lifecycle.sqlite"),
    controlPath: join(controlRoot, "lifecycle-finalization-head.json"),
  };
}

function key(fill) {
  const secret = Buffer.alloc(32, fill);
  return {
    keyId: `management-${createHash("sha256").update(secret).digest("hex").slice(0, 24)}`,
    secret,
  };
}

function bootstrap(storePaths, managementKey, now = CANONICAL_NOW) {
  const bootstrapAuthorization = createFinalizationStoreBootstrapAuthorization({
    storePath: storePaths.storePath,
    controlPath: storePaths.controlPath,
    key: managementKey,
    approvedAt: now,
  });
  return bootstrapFinalizationStore({
    storePath: storePaths.storePath,
    controlPath: storePaths.controlPath,
    key: managementKey,
    bootstrapAuthorization,
    now: () => now,
    requireDraft: true,
  });
}

function canonicalJson(value) {
  if (value === null || typeof value !== "object") {
    const encoded = JSON.stringify(value);
    if (encoded === undefined) throw new Error("not serializable");
    return encoded;
  }
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  const keys = Object.keys(value).sort();
  return `{${keys.map((field) => `${JSON.stringify(field)}:${canonicalJson(value[field])}`).join(",")}}`;
}

function digestJson(value) {
  return `sha256:${createHash("sha256").update(canonicalJson(value)).digest("hex")}`;
}

function digestFile(path) {
  return `sha256:${createHash("sha256").update(readFileSync(path)).digest("hex")}`;
}

function preparedRecord(draft, transactionId, overrides = {}) {
  const requestBindingDigest = overrides.requestBindingDigest ?? digestJson({ request: transactionId });
  const candidateIdentityDigest = overrides.candidateIdentityDigest ?? digestJson({ candidate: transactionId });
  const capturedAt = overrides.capturedAt ?? "2026-08-20T00:00:01.000Z";
  const preparedAt = overrides.preparedAt ?? "2026-08-20T00:00:02.000Z";
  const input = {
    requestBindingDigest,
    candidateIdentityDigest,
    purpose: overrides.purpose ?? "dedicated-store-contract-test",
    ...(overrides.largeText ? { largeText: overrides.largeText } : {}),
  };
  const snapshotUnsigned = {
    barrier: { transactionId, requestBindingDigest, candidateIdentityDigest },
    capturedAt,
  };
  const record = {
    schemaVersion: 2,
    state: "PREPARED",
    transactionId,
    preparedAt,
    input,
    inputDigest: digestJson(input),
    sourceRevision: "test-source-revision",
    runtimeIdentity: { digest: digestJson({ runtime: transactionId }) },
    immutableIdentity: { digest: digestJson({ immutable: transactionId }) },
    releasePackage: dirname(dirname(THIS_FILE)),
    releaseManifestSha256: digestJson({ manifest: transactionId }),
    releaseChecksumsSha256: digestJson({ checksums: transactionId }),
    moduleClosureDigest: digestJson({ moduleClosure: transactionId }),
    snapshotGroup: {
      manifest: {
        capturedAt,
        groupDigest: digestJson(snapshotUnsigned),
        barrier: { transactionId, requestBindingDigest, candidateIdentityDigest },
      },
    },
    gateEvidence: { manifestPath: "/non-release-fixture/gates.json", manifestSha256: digestJson({ gates: transactionId }) },
    productionSources: {
      activation: {
        approvalId: `approval-${transactionId}`,
        receiptId: `receipt-${transactionId}`,
        previousBindingId: null,
      },
    },
    destructivePlan: [],
    finalizationStore: draft,
  };
  return record;
}

function commitPrepared(storePaths, managementKey, transactionId, overrides = {}) {
  const draft = readFinalizationStoreIdentity({
    storePath: storePaths.storePath,
    controlPath: storePaths.controlPath,
    key: managementKey,
  });
  const record = preparedRecord(draft, transactionId, overrides);
  return {
    record,
    result: commitPreparedFinalization({
      storePath: storePaths.storePath,
      controlPath: storePaths.controlPath,
      key: managementKey,
      record,
      now: () => record.preparedAt,
    }),
  };
}

function noLock(storePaths) {
  assert.throws(
    () => lstatSync(`${storePaths.controlPath}.lock`),
    /ENOENT/u,
    "stale loser must not leave a live finalization control lock",
  );
}

async function collectChild(child) {
  let stdout = "";
  let stderr = "";
  child.stdout.on("data", (chunk) => { stdout += chunk; });
  child.stderr.on("data", (chunk) => { stderr += chunk; });
  const exit = await new Promise((resolve) => {
    child.on("exit", (code, signal) => resolve({ code, signal }));
  });
  return { ...exit, stdout, stderr };
}

function runChild(source, payload) {
  return spawn(NODE, [
    "--disable-warning=ExperimentalWarning",
    "--input-type=module",
    "-e",
    source,
    JSON.stringify(payload),
  ], {
    cwd: dirname(dirname(dirname(THIS_FILE))),
    stdio: ["ignore", "pipe", "pipe"],
  });
}

async function waitFor(predicate, timeoutMs = 5000) {
  const started = Date.now();
  while (Date.now() - started < timeoutMs) {
    if (predicate()) return true;
    await new Promise((resolve) => setTimeout(resolve, 1));
  }
  return false;
}

function hasTransitionResidue(storePath) {
  const parent = dirname(storePath);
  const prefix = `.${storePath.split("/").at(-1)}.transition-`;
  return readdirSync(parent).some((entry) => entry.startsWith(prefix));
}

test("wrong key, direct SQL append, trigger suffix truncation, and external control mismatch fail closed", () => {
  const root = tempRoot("finalization-store-auth");
  try {
    const storePaths = paths(root, "auth");
    const managementKey = key(1);
    const wrongKey = key(2);
    bootstrap(storePaths, managementKey);
    assert.throws(
      () => readFinalizationStoreIdentity({
        storePath: storePaths.storePath,
        controlPath: storePaths.controlPath,
        key: wrongKey,
      }),
      /foreign|authentication|key/u,
    );

    const anchor = readFinalizationStoreLedger({
      storePath: storePaths.storePath,
      controlPath: storePaths.controlPath,
      key: managementKey,
    }).anchor;
    const db = new DatabaseSync(storePaths.storePath);
    try {
      const payloadJson = canonicalJson({ forged: true });
      db.prepare(`
        insert into finalization_events
          (sequence, transaction_id, from_state, to_state, kind, payload_json,
           payload_digest, occurred_at, previous_transition_tag, event_tag,
           transition_tag, final_tag)
        values (1, ?, 'DRAFT', 'PREPARED', 'FORGED_SQL_EVENT', ?, ?, ?, ?, ?, ?, null)
      `).run(
        "tx-forged-sql",
        payloadJson,
        `sha256:${createHash("sha256").update(payloadJson).digest("hex")}`,
        "2026-08-20T00:00:01.000Z",
        anchor.anchorTag,
        `hmac-sha256:${"1".repeat(64)}`,
        `hmac-sha256:${"2".repeat(64)}`,
      );
    } finally {
      db.close();
    }
    assert.throws(
      () => readFinalizationStoreIdentity({
        storePath: storePaths.storePath,
        controlPath: storePaths.controlPath,
        key: managementKey,
      }),
      /canonical|authentication|control|head|event/u,
    );

    const truncated = paths(root, "truncated");
    bootstrap(truncated, managementKey);
    commitPrepared(truncated, managementKey, "tx-suffix-truncate");
    const controlBefore = readFileSync(truncated.controlPath);
    const oldControl = paths(root, "old-control");
    bootstrap(oldControl, managementKey);
    const draftControlBytes = readFileSync(oldControl.controlPath);
    const truncDb = new DatabaseSync(truncated.storePath);
    try {
      const triggerSql = truncDb.prepare(`
        select sql from sqlite_master
         where type = 'trigger' and name = 'finalization_events_no_delete'
      `).get().sql;
      truncDb.exec("drop trigger finalization_events_no_delete");
      truncDb.exec("delete from finalization_events where sequence >= 1");
      truncDb.exec(triggerSql);
    } finally {
      truncDb.close();
    }
    assert.throws(
      () => readFinalizationStoreIdentity({
        storePath: truncated.storePath,
        controlPath: truncated.controlPath,
        key: managementKey,
      }),
      /external|control|head|canonical|PREPARED/u,
      "valid-prefix suffix truncation must not resurrect DRAFT behind the external head",
    );
    writeFileSync(truncated.controlPath, draftControlBytes, { mode: 0o600 });
    chmodSync(truncated.controlPath, 0o600);
    assert.throws(
      () => readFinalizationStoreIdentity({
        storePath: truncated.storePath,
        controlPath: truncated.controlPath,
        key: managementKey,
      }),
      /path|storePath|control|head|inode|external/u,
      "stale external control from another store must not bind this database",
    );
    writeFileSync(truncated.controlPath, controlBefore, { mode: 0o600 });
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test("zero-byte residue, path symlinks, and owner/mode drift never bootstrap or read as DRAFT", () => {
  const root = tempRoot("finalization-store-paths");
  try {
    const managementKey = key(3);
    const zero = paths(root, "zero");
    secureFile(zero.storePath, Buffer.alloc(0));
    const zeroAuth = createFinalizationStoreBootstrapAuthorization({
      storePath: zero.storePath,
      controlPath: zero.controlPath,
      key: managementKey,
      approvedAt: CANONICAL_NOW,
    });
    assert.throws(
      () => bootstrapFinalizationStore({
        storePath: zero.storePath,
        controlPath: zero.controlPath,
        key: managementKey,
        bootstrapAuthorization: zeroAuth,
      }),
      /exists without external control|UNKNOWN/u,
    );
    assert.equal(lstatSync(zero.storePath).size, 0);

    const insecureRoot = secureDir(join(root, "insecure"));
    chmodSync(insecureRoot, 0o777);
    const insecureControl = secureDir(join(root, "insecure-control"));
    assert.throws(
      () => createFinalizationStoreBootstrapAuthorization({
        storePath: join(insecureRoot, "lifecycle.sqlite"),
        controlPath: join(insecureControl, "lifecycle-finalization-head.json"),
        key: managementKey,
        approvedAt: CANONICAL_NOW,
      }),
      /owner-only/u,
    );

    const symlinkCase = paths(root, "symlink");
    const symlinkTarget = secureFile(join(symlinkCase.stateRoot, "target.sqlite"), Buffer.alloc(0));
    symlinkSync(symlinkTarget, symlinkCase.storePath);
    assert.throws(
      () => initializeFinalizationStore({
        storePath: symlinkCase.storePath,
        controlPath: symlinkCase.controlPath,
        key: managementKey,
      }),
      /canonical real file|UNKNOWN|control/u,
    );

    const modeCase = paths(root, "mode");
    bootstrap(modeCase, managementKey);
    chmodSync(modeCase.controlPath, 0o644);
    assert.throws(
      () => readFinalizationStoreIdentity({
        storePath: modeCase.storePath,
        controlPath: modeCase.controlPath,
        key: managementKey,
      }),
      /owner-only/u,
    );
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test("bootstrap authorization is expiring and one-shot even after database and control loss", () => {
  const root = tempRoot("finalization-store-bootstrap-replay");
  try {
    const managementKey = key(31);
    const storePaths = paths(root, "replay");
    const authorization = createFinalizationStoreBootstrapAuthorization({
      storePath: storePaths.storePath,
      controlPath: storePaths.controlPath,
      key: managementKey,
      approvedAt: CANONICAL_NOW,
      expiresAt: "2026-08-20T00:01:00.000Z",
    });
    assert.equal(bootstrapFinalizationStore({
      storePath: storePaths.storePath,
      controlPath: storePaths.controlPath,
      key: managementKey,
      bootstrapAuthorization: authorization,
      now: () => CANONICAL_NOW,
    }).state, "DRAFT");
    assert.equal(lstatSync(`${storePaths.controlPath}.bootstrap-consumed.json`).mode & 0o777, 0o600);
    rmSync(storePaths.storePath);
    rmSync(storePaths.controlPath);
    assert.throws(
      () => bootstrapFinalizationStore({
        storePath: storePaths.storePath,
        controlPath: storePaths.controlPath,
        key: managementKey,
        bootstrapAuthorization: authorization,
        now: () => "2036-08-20T00:00:00.000Z",
      }),
      /already consumed|resurrection/u,
    );
    assert.equal(lstatSync(`${storePaths.controlPath}.bootstrap-consumed.json`).isFile(), true);
    assert.throws(
      () => bootstrapFinalizationStore({
        storePath: storePaths.storePath,
        controlPath: storePaths.controlPath,
        key: managementKey,
        bootstrapAuthorization: createFinalizationStoreBootstrapAuthorization({
          storePath: storePaths.storePath,
          controlPath: storePaths.controlPath,
          key: managementKey,
          approvedAt: CANONICAL_NOW,
          expiresAt: "2026-08-20T00:01:00.000Z",
        }),
        now: () => "2026-08-20T00:02:00.000Z",
      }),
      /already consumed|resurrection/u,
    );
    const expiredPaths = paths(root, "expired");
    const expired = createFinalizationStoreBootstrapAuthorization({
      storePath: expiredPaths.storePath,
      controlPath: expiredPaths.controlPath,
      key: managementKey,
      approvedAt: CANONICAL_NOW,
      expiresAt: "2026-08-20T00:01:00.000Z",
    });
    assert.throws(
      () => bootstrapFinalizationStore({
        storePath: expiredPaths.storePath,
        controlPath: expiredPaths.controlPath,
        key: managementKey,
        bootstrapAuthorization: expired,
        now: () => "2026-08-20T00:02:00.000Z",
      }),
      /invalid or foreign/u,
    );
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test("two-child bootstrap and exact transition contention have one mutating winner and no stale live lock", async () => {
  const root = tempRoot("finalization-store-contention");
  try {
    const managementKey = key(4);
    const initPaths = paths(root, "init");
    const childSource = `
      const mod = await import(${JSON.stringify(MODULE_URL)});
      const { createHash } = await import("node:crypto");
      const payload = JSON.parse(process.argv[1]);
      const secret = Buffer.from(payload.secretHex, "hex");
      const key = { keyId: "management-" + createHash("sha256").update(secret).digest("hex").slice(0, 24), secret };
      try {
        const bootstrapAuthorization = mod.createFinalizationStoreBootstrapAuthorization({
          storePath: payload.storePath,
          controlPath: payload.controlPath,
          key,
          approvedAt: payload.now,
        });
        const identity = mod.bootstrapFinalizationStore({
          storePath: payload.storePath,
          controlPath: payload.controlPath,
          key,
          bootstrapAuthorization,
          now: () => payload.now,
        });
        console.log(JSON.stringify({ ok: true, state: identity.state, revision: identity.revision }));
      } catch (error) {
        console.log(JSON.stringify({ ok: false, message: String(error.message || error) }));
      }
    `;
    const payload = {
      storePath: initPaths.storePath,
      controlPath: initPaths.controlPath,
      secretHex: Buffer.from(managementKey.secret).toString("hex"),
      now: CANONICAL_NOW,
    };
    const initChildren = [runChild(childSource, payload), runChild(childSource, payload)];
    const initResults = await Promise.all(initChildren.map(collectChild));
    const parsedInit = initResults.map((result) => JSON.parse(result.stdout.trim()));
    assert.equal(parsedInit.filter((result) => result.ok).length, 1, JSON.stringify(parsedInit));
    assert.equal(parsedInit.filter((result) => !result.ok).length, 1, JSON.stringify(parsedInit));
    assert.equal(readFinalizationStoreIdentity({
      storePath: initPaths.storePath,
      controlPath: initPaths.controlPath,
      key: managementKey,
    }).state, "DRAFT");
    noLock(initPaths);

    const transitionPaths = paths(root, "transition");
    bootstrap(transitionPaths, managementKey);
    const tx = "tx-contention";
    const record = preparedRecord(
      readFinalizationStoreIdentity({
        storePath: transitionPaths.storePath,
        controlPath: transitionPaths.controlPath,
        key: managementKey,
      }),
      tx,
    );
    const transitionSource = `
      const mod = await import(${JSON.stringify(MODULE_URL)});
      const { createHash } = await import("node:crypto");
      const payload = JSON.parse(process.argv[1]);
      const secret = Buffer.from(payload.secretHex, "hex");
      const key = { keyId: "management-" + createHash("sha256").update(secret).digest("hex").slice(0, 24), secret };
      try {
        const result = mod.commitPreparedFinalization({
          storePath: payload.storePath,
          controlPath: payload.controlPath,
          key,
          record: payload.record,
          now: () => payload.record.preparedAt,
        });
        console.log(JSON.stringify({ ok: true, resumed: result.resumed, state: result.identity.state }));
      } catch (error) {
        console.log(JSON.stringify({ ok: false, message: String(error.message || error) }));
      }
    `;
    const transitionPayload = {
      storePath: transitionPaths.storePath,
      controlPath: transitionPaths.controlPath,
      secretHex: Buffer.from(managementKey.secret).toString("hex"),
      record,
    };
    const transitionChildren = [runChild(transitionSource, transitionPayload), runChild(transitionSource, transitionPayload)];
    const transitionResults = await Promise.all(transitionChildren.map(collectChild));
    const parsedTransition = transitionResults.map((result) => JSON.parse(result.stdout.trim()));
    assert.equal(parsedTransition.filter((result) => result.ok && result.resumed === false).length, 1, JSON.stringify(parsedTransition));
    assert.equal(
      parsedTransition.filter((result) => (
        (result.ok && result.state === "PREPARED")
        || (!result.ok && /lock conflict|semantic conflict/u.test(result.message))
      )).length,
      2,
      JSON.stringify(parsedTransition),
    );
    noLock(transitionPaths);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test("exact replay succeeds, changed evidence fails, and lower-head rollback needs authenticated receipt", () => {
  const root = tempRoot("finalization-store-replay-rollback");
  try {
    const managementKey = key(5);
    const storePaths = paths(root, "main");
    const draft = bootstrap(storePaths, managementKey);
    const draftSnapshotPath = secureFile(join(root, "draft-lifecycle.sqlite"), readFileSync(storePaths.storePath));
    const tx = "tx-replay-rollback";
    const { record, result } = commitPrepared(storePaths, managementKey, tx);
    assert.equal(result.identity.state, "PREPARED");
    const replay = commitPreparedFinalization({
      storePath: storePaths.storePath,
      controlPath: storePaths.controlPath,
      key: managementKey,
      record,
      now: () => record.preparedAt,
    });
    assert.equal(replay.resumed, true);
    const changed = structuredClone(record);
    changed.input.purpose = "changed";
    changed.inputDigest = digestJson(changed.input);
    assert.throws(
      () => commitPreparedFinalization({
        storePath: storePaths.storePath,
        controlPath: storePaths.controlPath,
        key: managementKey,
        record: changed,
        now: () => changed.preparedAt,
      }),
      /replay differs/u,
    );

    const forged = paths(root, "forged-lower");
    bootstrap(forged, managementKey);
    commitPrepared(forged, managementKey, "tx-forged-lower");
    copyFileSync(draftSnapshotPath, forged.storePath);
    chmodSync(forged.storePath, 0o600);
    assert.throws(
      () => readFinalizationStoreIdentity({
        storePath: forged.storePath,
        controlPath: forged.controlPath,
        key: managementKey,
      }),
      /control|head|inode|external/u,
      "a lower database head without rollback authorization must not be accepted",
    );

    const snapshotRoot = secureDir(join(root, "snapshot"));
    const snapshotPath = secureFile(join(snapshotRoot, "lifecycle-finalization-store.sqlite"), readFileSync(draftSnapshotPath));
    const snapshotUnsigned = {
      schemaVersion: 1,
      capturedAt: "2026-08-20T00:00:03.000Z",
      snapshotRoot,
      barrier: {
        transactionId: tx,
        requestBindingDigest: record.input.requestBindingDigest,
        candidateIdentityDigest: record.input.candidateIdentityDigest,
      },
      entries: [{
        id: FINALIZATION_STORE_ID,
        kind: "sqlite",
        state: "captured",
        path: storePaths.storePath,
        snapshotPath,
        sha256: digestFile(snapshotPath),
        required: true,
        bytes: lstatSync(snapshotPath).size,
        mode: 0o600,
      }],
    };
    const snapshotManifest = { ...snapshotUnsigned, groupDigest: digestJson(snapshotUnsigned) };
    const manifestPath = secureFile(join(snapshotRoot, "SNAPSHOT-GROUP.json"), `${canonicalJson(snapshotManifest)}\n`);
    const journalPath = secureFile(join(root, "rollback.ndjson"), `${JSON.stringify({
      event: "ROLLBACK_REQUESTED",
      transactionId: tx,
      requestBindingDigest: record.input.requestBindingDigest,
      snapshotGroupDigest: snapshotManifest.groupDigest,
      requestedAt: "2026-08-20T00:00:04.000Z",
    })}\n`);
    const claimPath = secureFile(join(root, "worker-claim.json"), `${canonicalJson({
      transactionId: tx,
      requestBindingDigest: record.input.requestBindingDigest,
      claimId: "claim-authenticated-rollback",
    })}\n`);
    const requested = requestFinalizationStoreRollback({
      storePath: storePaths.storePath,
      controlPath: storePaths.controlPath,
      key: managementKey,
      transactionId: tx,
      requestBindingDigest: record.input.requestBindingDigest,
      candidateIdentityDigest: record.input.candidateIdentityDigest,
      snapshotManifestPath: manifestPath,
      snapshotManifestSha256: digestFile(manifestPath),
      rollbackJournalPath: journalPath,
      rollbackJournalSha256: digestFile(journalPath),
      workerClaimPath: claimPath,
      workerClaimSha256: digestFile(claimPath),
    });
    assert.equal(requested.resumed, false);
    assert.equal(requested.authorization.from.state, "PREPARED");
    assert.equal(requested.authorization.target.state, "DRAFT");

    const restoreEvidence = {
      groupDigest: snapshotManifest.groupDigest,
      verified: true,
      entries: [{ id: FINALIZATION_STORE_ID, verified: true }],
    };
    const restorePath = secureFile(join(root, "restore-evidence.json"), `${canonicalJson(restoreEvidence)}\n`);
    const terminal = {
      event: "ROLLBACK_RESTORE_VERIFIED",
      transactionId: tx,
      requestBindingDigest: record.input.requestBindingDigest,
      snapshotGroupDigest: snapshotManifest.groupDigest,
      requestJournalSha256: digestFile(journalPath),
      evidenceDigest: digestFile(restorePath),
    };
    writeFileSync(journalPath, `${readFileSync(journalPath, "utf8")}${JSON.stringify(terminal)}\n`, { mode: 0o600 });
    chmodSync(journalPath, 0o600);
    copyFileSync(snapshotPath, storePaths.storePath);
    chmodSync(storePaths.storePath, 0o600);
    const verified = verifyFinalizationStoreRollback({
      storePath: storePaths.storePath,
      controlPath: storePaths.controlPath,
      key: managementKey,
      transactionId: tx,
      requestBindingDigest: record.input.requestBindingDigest,
      candidateIdentityDigest: record.input.candidateIdentityDigest,
      snapshotManifestPath: manifestPath,
      snapshotManifestSha256: digestFile(manifestPath),
      rollbackJournalPath: journalPath,
      rollbackJournalSha256: digestFile(journalPath),
      workerClaimPath: claimPath,
      workerClaimSha256: digestFile(claimPath),
      restoreEvidencePath: restorePath,
      restoreEvidenceSha256: digestFile(restorePath),
      now: () => "2026-08-20T00:00:05.000Z",
    });
    assert.equal(verified.identity.state, "DRAFT");
    assert.equal(verified.identity.revision, draft.revision);
    assert.match(verified.identity.contentGeneration, DIGEST_RE);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test("SIGKILL leaves durable UNKNOWN until live-owner rejection and verified-dead recovery", async () => {
  const root = tempRoot("finalization-store-sigkill");
  try {
    const managementKey = key(6);
    const storePaths = paths(root, "transition");
    bootstrap(storePaths, managementKey);
    const tx = "tx-sigkill";
    const record = preparedRecord(
      readFinalizationStoreIdentity({
        storePath: storePaths.storePath,
        controlPath: storePaths.controlPath,
        key: managementKey,
      }),
      tx,
      { largeText: "x".repeat(8 * 1024 * 1024), preparedAt: "2026-08-20T00:00:06.000Z" },
    );
    const recordPath = secureFile(join(root, "sigkill-record.json"), `${canonicalJson(record)}\n`);
    const transitionSource = `
      const mod = await import(${JSON.stringify(MODULE_URL)});
      const { createHash } = await import("node:crypto");
      const { readFileSync } = await import("node:fs");
      const payload = JSON.parse(process.argv[1]);
      const secret = Buffer.from(payload.secretHex, "hex");
      const key = { keyId: "management-" + createHash("sha256").update(secret).digest("hex").slice(0, 24), secret };
      const record = JSON.parse(readFileSync(payload.recordPath, "utf8"));
      mod.commitPreparedFinalization({
        storePath: payload.storePath,
        controlPath: payload.controlPath,
        key,
        record,
        now: () => record.preparedAt,
      });
    `;
    const child = runChild(transitionSource, {
      storePath: storePaths.storePath,
      controlPath: storePaths.controlPath,
      secretHex: Buffer.from(managementKey.secret).toString("hex"),
      recordPath,
    });
    const observed = await waitFor(
      () => {
        try {
          lstatSync(`${storePaths.controlPath}.lock`);
          return true;
        } catch {
          return hasTransitionResidue(storePaths.storePath);
        }
      },
      7000,
    );
    assert.equal(observed, true, "transition lock or COW residue must be observable before SIGKILL");
    assert.throws(
      () => recoverFinalizationStoreControl({
        storePath: storePaths.storePath,
        controlPath: storePaths.controlPath,
        key: managementKey,
      }),
      /still live/u,
      "live owner cannot be adopted",
    );
    child.kill("SIGKILL");
    const killed = await collectChild(child);
    assert.equal(killed.signal, "SIGKILL");
    assert.throws(
      () => readFinalizationStoreIdentity({
        storePath: storePaths.storePath,
        controlPath: storePaths.controlPath,
        key: managementKey,
      }),
      /UNKNOWN|lock|PENDING|residue/u,
    );
    const recovered = recoverFinalizationStoreControl({
      storePath: storePaths.storePath,
      controlPath: storePaths.controlPath,
      key: managementKey,
    });
    assert.equal(recovered.identity.state, "PREPARED");
    noLock(storePaths);
    assert.equal(hasTransitionResidue(storePaths.storePath), false);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test("SIGKILL during init is recoverable only through the authenticated INIT intent", async () => {
  const root = tempRoot("finalization-store-init-kill");
  try {
    const managementKey = key(7);
    let recovered = false;
    for (let attempt = 0; attempt < 50 && !recovered; attempt += 1) {
      const storePaths = paths(root, `init-${attempt}`);
      const source = `
        const mod = await import(${JSON.stringify(MODULE_URL)});
        const { createHash } = await import("node:crypto");
        const payload = JSON.parse(process.argv[1]);
        const secret = Buffer.from(payload.secretHex, "hex");
        const key = { keyId: "management-" + createHash("sha256").update(secret).digest("hex").slice(0, 24), secret };
        const bootstrapAuthorization = mod.createFinalizationStoreBootstrapAuthorization({
          storePath: payload.storePath,
          controlPath: payload.controlPath,
          key,
          approvedAt: payload.now,
        });
        mod.bootstrapFinalizationStore({
          storePath: payload.storePath,
          controlPath: payload.controlPath,
          key,
          bootstrapAuthorization,
          now: () => payload.now,
        });
      `;
      const child = runChild(source, {
        storePath: storePaths.storePath,
        controlPath: storePaths.controlPath,
        secretHex: Buffer.from(managementKey.secret).toString("hex"),
        now: CANONICAL_NOW,
      });
      const lockObserved = await waitFor(() => {
        try {
          lstatSync(`${storePaths.controlPath}.lock`);
          return true;
        } catch {
          return false;
        }
      }, 250);
      if (!lockObserved) {
        child.kill("SIGKILL");
        await collectChild(child);
        continue;
      }
      child.kill("SIGKILL");
      await collectChild(child);
      assert.throws(
        () => readFinalizationStoreIdentity({
          storePath: storePaths.storePath,
          controlPath: storePaths.controlPath,
          key: managementKey,
        }),
        /UNKNOWN|lock|missing|control/u,
      );
      const recovery = recoverFinalizationStoreControl({
        storePath: storePaths.storePath,
        controlPath: storePaths.controlPath,
        key: managementKey,
      });
      assert.equal(recovery.recoveredLockKind, "INIT");
      assert.equal(recovery.identity.state, "DRAFT");
      recovered = true;
    }
    assert.equal(recovered, true, "test must observe and recover an authenticated INIT lock");
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test("the contract module has no exported generic append or boolean terminal shortcut", () => {
  const source = readFileSync(THIS_FILE.replace(/\.test\.mjs$/u, ".mjs"), "utf8");
  assert.doesNotMatch(source, /export function append/u);
  assert.doesNotMatch(source, /allowCanonicalSeal/u);
  assert.doesNotMatch(source, /terminal\s*:\s*boolean/u);

  const probe = spawnSync(NODE, [
    "--disable-warning=ExperimentalWarning",
    "--input-type=module",
    "-e",
    `
      const mod = await import(${JSON.stringify(MODULE_URL)});
      console.log(Object.keys(mod).filter((name) => /append|allowCanonicalSeal/.test(name)).join(","));
    `,
  ], { encoding: "utf8" });
  assert.equal(probe.status, 0, probe.stderr);
  assert.equal(probe.stdout.trim(), "");
});

test("terminal lifecycle requires owner-only digest-bound artifacts and recomputes their readback", async () => {
  const root = tempRoot("finalization-store-terminal-artifacts");
  try {
    const managementKey = key(41);
    const storePaths = paths(root, "terminal");
    bootstrap(storePaths, managementKey);
    const transactionId = "tx-terminal-artifacts";
    const { record } = commitPrepared(storePaths, managementKey, transactionId);
    const gateNames = [
      "G00 PROFILE", "G01 SOURCE", "G02 STATIC", "G03 UNIT", "G04 PROTOCOL", "G05 FUNCTIONAL",
      "G06 SECURITY", "G07 DURABILITY", "G08 LOAD", "G09 PACKAGE", "G10 STAGING", "G11 HOST",
      "G12 CONNECTOR", "G13 CUTOVER", "G16 CLEANUP", "G17 FINALIZATION",
    ];
    const preCutover = gateNames.map((gate, index) => index < 13 ? {
      profile: "BASE_SINGLE_OWNER", gate, applicability: "REQUIRED", result: "PASS",
      evidenceDigest: digestJson({ gate }),
    } : { profile: "BASE_SINGLE_OWNER", gate, applicability: "REQUIRED", result: "NOT_RUN" });
    const capabilities = [{
      profile: "BASE_SINGLE_OWNER", capability: "no-residue", applicability: "REQUIRED", result: "NOT_RUN",
    }];
    const profileApplicability = [
      { profile: "BASE_SINGLE_OWNER", applicability: "REQUIRED" },
      { profile: "MULTI_USER", applicability: "NOT_APPLICABLE" },
      { profile: "SIDECAR_AUTHORITY", applicability: "NOT_APPLICABLE" },
      { profile: "HOST_ATTESTED", applicability: "NOT_APPLICABLE" },
      { profile: "GUI_CAPTURE", applicability: "NOT_APPLICABLE" },
    ];
    const evaluation = {
      thresholdDigest: digestJson({ threshold: true }),
      manifestBindingDigest: digestJson({ manifest: true }),
      gateResults: preCutover,
      gateResultsDigest: digestJson(preCutover),
      capabilities,
      capabilitiesDigest: digestJson(capabilities),
      profileApplicability,
      profileApplicabilityDigest: digestJson(profileApplicability),
    };
    await commitProfileGatesEvaluated({
      ...storePaths, key: managementKey, transactionId, evaluation,
      now: () => "2026-08-20T00:00:03.000Z",
    });
    commitActivationPending({
      ...storePaths, key: managementKey, transactionId,
      activationBinding: record.productionSources.activation,
      now: () => "2026-08-20T00:00:04.000Z",
    });
    const readback = {
      installation: {
        activeBindingCount: 1, canonicalProcessCount: 1, legacyProcessCount: 0, residuePaths: [], routeCount: 1,
      },
      postActivation: { state: "POST_ACTIVATION_VERIFIED", receiptId: record.productionSources.activation.receiptId },
      runtimeEvidence: { health: 200, ready: 200, doctor: "PASS" },
    };
    const postProof = {
      schemaVersion: 1,
      kind: "POST_ACTIVATION_VERIFIED_PROOF",
      activatedAt: "2026-08-20T00:00:05.000Z",
      activationReceiptId: record.productionSources.activation.receiptId,
      postActivationEvidenceDigest: digestJson(readback),
      gateResult: {
        profile: "BASE_SINGLE_OWNER", gate: "G13 CUTOVER", applicability: "REQUIRED", result: "PASS",
        evidenceDigest: digestJson(readback),
      },
      readback,
    };
    const postPath = secureFile(join(root, "post-proof.json"), `${JSON.stringify(postProof, null, 2)}\n`);
    assert.throws(() => commitPostActivationVerified({
      ...storePaths, key: managementKey, transactionId, postActivationProof: postProof,
    }), /artifact reference/u, "inline terminal proof must not be accepted");
    commitPostActivationVerified({
      ...storePaths, key: managementKey, transactionId,
      postActivationProofArtifact: { path: postPath, sha256: digestFile(postPath) },
      now: () => postProof.activatedAt,
    });
    commitDraining({
      ...storePaths, key: managementKey, transactionId,
      now: () => "2026-08-20T00:00:06.000Z",
    });
    const finalGateResults = gateNames.map((gate) => ({
      profile: "BASE_SINGLE_OWNER", gate, applicability: "REQUIRED", result: "PASS",
      evidenceDigest: digestJson({ final: gate }),
    }));
    const residueEvidence = {
      canonicalProcessCount: 1,
      currentAuditTarget: root,
      legacyProcessNames: [],
      residuePaths: [],
      routeCount: 1,
    };
    const sealProof = {
      schemaVersion: 1,
      kind: "FINALIZATION_SEAL_PROOF",
      sealedAt: "2026-08-20T00:00:07.000Z",
      sealInputDigest: digestJson({ input: true }),
      finalArtifactsDigest: digestJson({ artifacts: true }),
      finalGateResults,
      finalGateResultsDigest: digestJson(finalGateResults),
      residueEvidence,
      residueEvidenceDigest: digestJson(residueEvidence),
    };
    const sealPath = secureFile(join(root, "seal-proof.json"), `${JSON.stringify(sealProof, null, 2)}\n`);
    commitCanonicalFinalizationSeal({
      ...storePaths, key: managementKey, transactionId,
      sealProofArtifact: { path: sealPath, sha256: digestFile(sealPath) },
      now: () => sealProof.sealedAt,
    });
    const finalReport = {
      status: "BASE_PROFILE_FINAL_PASS",
      gateResultsDigest: sealProof.finalGateResultsDigest,
    };
    const finalManifest = {
      finalArtifactsDigest: sealProof.finalArtifactsDigest,
      residueEvidenceDigest: sealProof.residueEvidenceDigest,
    };
    const finalManifestDigest = digestJson(finalManifest);
    const finalReportDigest = digestJson(finalReport);
    const finalPassProof = {
      schemaVersion: 1,
      kind: "BASE_PROFILE_FINAL_PASS_PROOF",
      completedAt: "2026-08-20T00:00:08.000Z",
      finalDigest: digestJson({
        finalManifestDigest,
        finalReportDigest,
        sealInputDigest: sealProof.sealInputDigest,
      }),
      finalManifest,
      finalManifestDigest,
      finalReport,
      finalReportDigest,
    };
    const finalPath = secureFile(join(root, "final-pass-proof.json"), `${JSON.stringify(finalPassProof, null, 2)}\n`);
    const completed = commitBaseProfileFinalPass({
      ...storePaths, key: managementKey, transactionId,
      finalPassProofArtifact: { path: finalPath, sha256: digestFile(finalPath) },
      now: () => finalPassProof.completedAt,
    });
    assert.equal(completed.identity.state, "BASE_PROFILE_FINAL_PASS");
    assert.equal(completed.identity.finalDigest, finalPassProof.finalDigest);

    const tampered = structuredClone(finalPassProof);
    tampered.finalReport.status = "FINAL_PASS";
    const tamperedPath = secureFile(join(root, "tampered-final-pass-proof.json"), `${JSON.stringify(tampered, null, 2)}\n`);
    assert.throws(() => commitBaseProfileFinalPass({
      ...storePaths, key: managementKey, transactionId,
      finalPassProofArtifact: { path: tamperedPath, sha256: digestFile(tamperedPath) },
    }), /report\/manifest|authenticated seal|digest-bound/u);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});
