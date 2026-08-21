import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import {
  chmod,
  mkdir,
  mkdtemp,
  readFile,
  rm,
  stat,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import {
  assertPersonalCandidateEnvironment,
  deployPersonalDirectOwnerCandidate,
} from "./personal-direct-owner-candidate.mjs";

const sourceRevision = "1".repeat(40);
const runtimeRevision = "2".repeat(40);
const buildDigest = `sha256:${"3".repeat(64)}`;
const schemaGeneration = `sha256:${"4".repeat(64)}`;
const manifestSha256 = `sha256:${"5".repeat(64)}`;
const dependencyEvidenceSha256 = `sha256:${"6".repeat(64)}`;

test("Personal candidate orchestration emits a clean environment and complete evidence chain", async (t) => {
  const fixture = await candidateFixture(t, "success");
  const processManager = new FakeProcessManager(fixture.releasePackage);
  const events = [];
  const deployment = await deployPersonalDirectOwnerCandidate(fixture.input, {
    verifyPackage: async () => {
      events.push("verify-package");
      return packagePass();
    },
    seedOauth: async (input) => {
      events.push("seed-oauth");
      await writeFile(input.tokenFile, "fixture-token-never-exposed\n", { mode: 0o600 });
      await writeFile(input.evidenceFile, `${JSON.stringify({ status: "PASS" })}\n`, { mode: 0o600 });
      await chmod(input.tokenFile, 0o600);
      await chmod(input.evidenceFile, 0o600);
      return {
        status: "PASS",
        rotationSequence: 0,
        readiness: { state: "PASS" },
      };
    },
    processManager,
    waitForJson: async (url) => {
      events.push(url.endsWith("/healthz") ? "health" : "readiness");
      return url.endsWith("/healthz")
        ? runtimeIdentity()
        : {
            status: "ready",
            httpStatus: 200,
            checks: [{ id: "canonical_connector", state: "PASS", evidence: { activationState: "ACTIVE" } }],
            identity: { ...runtimeIdentity(), acceptanceRunId: fixture.input.acceptanceRunId },
          };
    },
    verifyRuntime: async (input) => {
      events.push("verify-runtime");
      assert.equal(input.packageRoot, fixture.releasePackage);
      return { status: "PASS", ...runtimeIdentity() };
    },
    verifyLive: async (input) => {
      events.push("verify-live");
      assert.equal(input.acceptanceRunId, fixture.input.acceptanceRunId);
      assert.equal(input.connectorInstallationEpoch, 3);
      assert.equal(input.connectorRotationSequence, 0);
      return {
        status: "PERSONAL_DIRECT_OWNER_HTTP_LIVE_PASS",
        ...runtimeIdentity(),
        acceptanceRunId: input.acceptanceRunId,
        verifiedOperationIds: ["op_fixture"],
        verifiedMutationIds: ["op_fixture"],
        cleanup: "PATH_NOT_FOUND",
      };
    },
    now: () => Date.parse("2026-08-22T00:00:00.000Z"),
  });

  assert.equal(deployment.status, "CANDIDATE_READY");
  assert.equal(deployment.productProfile, "PERSONAL_DIRECT_OWNER");
  assert.equal(deployment.dependencyRoot, fixture.input.dependencyRoot);
  assert.equal(deployment.dependencyEvidence, fixture.input.dependencyEvidence);
  assert.equal(deployment.dependencyEvidenceSha256, dependencyEvidenceSha256);
  assert.equal(deployment.productionUntouched, undefined);
  assert.equal(deployment.rollback.productionUntouched, true);
  assert.deepEqual(events, [
    "verify-package",
    "seed-oauth",
    "health",
    "readiness",
    "verify-runtime",
    "verify-live",
  ]);
  assert.equal(processManager.started.length, 1);
  assert.equal(processManager.deleted.length, 0);
  assert.equal(processManager.saved, false);
  assert.equal(await mode(fixture.input.candidateEnvironment), "600");
  assert.equal(await mode(fixture.input.stateDir), "700");
  assert.equal(await mode(fixture.input.auditDir), "700");

  const candidateEnvironment = await readFile(fixture.input.candidateEnvironment, "utf8");
  const expectedEnvironment = processManager.started[0].expectedEnvironment;
  assertPersonalCandidateEnvironment(candidateEnvironment, expectedEnvironment);
  assert.match(candidateEnvironment, /DEVSPACE_OAUTH_OWNER_TOKEN='owner-secret-preserved'/u);
  assert.doesNotMatch(candidateEnvironment, /stale-production-state/u);
  assert.doesNotMatch(candidateEnvironment, /DEVSPACE_PERSONAL_STAGING_FIXTURE/u);
  assert.doesNotMatch(candidateEnvironment, /DEVSPACE_NEXT_AUTHORITY_STORE/u);
  assert.doesNotMatch(candidateEnvironment, /DEVSPACE_NEXT_LIFECYCLE_FINALIZATION_STORE/u);

  for (const file of [
    "PACKAGE-VERIFICATION.json",
    "CANDIDATE-OAUTH.json",
    "candidate-access-token.txt",
    "HEALTH.json",
    "READINESS.json",
    "RUNTIME-VERIFICATION.json",
    "HTTP-LIVE.json",
    "PROCESS.json",
    "DEPLOYMENT.json",
  ]) {
    assert.equal(await mode(join(fixture.input.auditDir, file)), "600", file);
  }
  const serialized = JSON.stringify(deployment);
  assert.equal(serialized.includes("fixture-token-never-exposed"), false);
  assert.equal(serialized.includes("owner-secret-preserved"), false);
});

test("Personal candidate orchestration deletes only its candidate process after a live-gate failure", async (t) => {
  const fixture = await candidateFixture(t, "failure");
  const processManager = new FakeProcessManager(fixture.releasePackage);
  await assert.rejects(
    deployPersonalDirectOwnerCandidate(fixture.input, {
      verifyPackage: async () => packagePass(),
      seedOauth: async (input) => {
        await writeFile(input.tokenFile, "fixture-token\n", { mode: 0o600 });
        await writeFile(input.evidenceFile, "{}\n", { mode: 0o600 });
        return { status: "PASS", rotationSequence: 0, readiness: { state: "PASS" } };
      },
      processManager,
      waitForJson: async (url) => url.endsWith("/healthz")
        ? runtimeIdentity()
        : { status: "ready", httpStatus: 200, checks: [], identity: runtimeIdentity() },
      verifyRuntime: async () => ({ status: "PASS" }),
      verifyLive: async () => { throw new Error("deterministic live failure"); },
      now: () => Date.parse("2026-08-22T00:10:00.000Z"),
    }),
    /deterministic live failure/u,
  );
  assert.equal(processManager.started.length, 1);
  assert.deepEqual(processManager.deleted, [fixture.input.processName]);
  assert.equal(processManager.saved, false);
  const failurePath = join(fixture.input.auditDir, "FAILURE.json");
  assert.equal(await mode(failurePath), "600");
  const failure = JSON.parse(await readFile(failurePath, "utf8"));
  assert.equal(failure.status, "ROLLED_BACK");
  assert.equal(failure.productionUntouched, true);
  assert.match(failure.error, /deterministic live failure/u);
  assert.equal(await readFile(fixture.productionSentinel, "utf8"), "production unchanged\n");
});

class FakeProcessManager {
  constructor(releasePackage) {
    this.releasePackage = releasePackage;
    this.started = [];
    this.deleted = [];
    this.saved = false;
  }

  async exists() { return false; }

  async start(input) {
    const environmentText = await readFile(input.environmentFile, "utf8");
    const expectedEnvironment = parseEnvironment(environmentText);
    this.started.push({ ...input, expectedEnvironment });
  }

  async delete(name) { this.deleted.push(name); }

  async inspect(name) {
    return {
      name,
      pid: 4242,
      status: "online",
      cwd: this.releasePackage,
      script: join(this.releasePackage, "scripts", "start-universal-broker-v2-production.sh"),
      restartCount: 0,
      createdAt: Date.parse("2026-08-22T00:00:00.000Z"),
    };
  }

  async errorLogPath() { return undefined; }
}

async function candidateFixture(t, suffix) {
  const root = await mkdtemp(join(tmpdir(), `devspace-personal-candidate-${suffix}-`));
  const releasePackage = join(root, "release-package");
  const dependencyRoot = join(root, "dependency");
  const dependencyEvidence = join(root, "dependency-evidence.json");
  const productionEnvironment = join(root, "production.env");
  const targetConfig = join(root, "targets.json");
  const routeConfig = join(root, "routes.json");
  const envProfileConfig = join(root, "env-profiles.json");
  const productionSentinel = join(root, "production-sentinel.txt");
  await mkdir(join(releasePackage, "scripts"), { recursive: true, mode: 0o700 });
  await mkdir(dependencyRoot, { recursive: true, mode: 0o700 });
  await writeFile(join(releasePackage, "BUILD-MANIFEST.json"), `${JSON.stringify({
    schemaVersion: 1,
    productProfile: "PERSONAL_DIRECT_OWNER",
    sourceRevision,
    runtimeRevision,
    buildDigest,
    schemaGeneration,
    files: [],
  })}\n`, { mode: 0o600 });
  await writeFile(
    join(releasePackage, "scripts", "start-universal-broker-v2-production.sh"),
    "#!/bin/sh\nexit 0\n",
    { mode: 0o755 },
  );
  await writeFile(dependencyEvidence, "{}\n", { mode: 0o600 });
  await writeFile(productionEnvironment, [
    "DEVSPACE_OAUTH_OWNER_TOKEN='owner-secret-preserved'",
    "DEVSPACE_NEXT_STATE_DIR='stale-production-state'",
    "DEVSPACE_PERSONAL_STAGING_FIXTURE='1'",
    "DEVSPACE_NEXT_AUTHORITY_STORE='stale-authority.sqlite'",
    "DEVSPACE_NEXT_LIFECYCLE_FINALIZATION_STORE='stale-lifecycle.sqlite'",
    "",
  ].join("\n"), { mode: 0o600 });
  await writeFile(targetConfig, "{}\n", { mode: 0o600 });
  await writeFile(routeConfig, "{}\n", { mode: 0o600 });
  await writeFile(envProfileConfig, "{}\n", { mode: 0o600 });
  await writeFile(productionSentinel, "production unchanged\n", { mode: 0o600 });
  await Promise.all([
    chmod(dependencyEvidence, 0o600),
    chmod(productionEnvironment, 0o600),
  ]);
  t.after(() => rm(root, { recursive: true, force: true }));
  const input = {
    releasePackage,
    dependencyRoot,
    dependencyEvidence,
    dependencyEvidenceSha256,
    manifestSha256,
    sourceRevision,
    runtimeRevision,
    productionEnvironment,
    candidateEnvironment: join(root, "candidate.env"),
    stateDir: join(root, "candidate-state"),
    auditDir: join(root, "candidate-audit"),
    processName: `devspace-personal-candidate-${suffix}`,
    dataPort: suffix === "success" ? 27678 : 27679,
    managementPort: suffix === "success" ? 28678 : 28679,
    connectorName: "myDevSpace",
    connectorInstallationEpoch: 3,
    acceptanceRunId: `candidate-${suffix}-20260822`,
    targetConfig,
    routeConfig,
    envProfileConfig,
  };
  return { root, releasePackage, productionSentinel, input };
}

function packagePass() {
  return {
    status: "PASS",
    productProfile: "PERSONAL_DIRECT_OWNER",
    sourceRevision,
    runtimeRevision,
    buildDigest,
    schemaGeneration,
    manifestSha256,
    sourceGateDigest: `sha256:${"7".repeat(64)}`,
    dependency: { evidenceSha256: dependencyEvidenceSha256 },
  };
}

function runtimeIdentity() {
  return {
    productProfile: "PERSONAL_DIRECT_OWNER",
    sourceRevision,
    runtimeRevision,
    buildDigest,
    schemaGeneration,
  };
}

function parseEnvironment(text) {
  return Object.fromEntries(text.trim().split("\n").filter(Boolean).map((line) => {
    const index = line.indexOf("=");
    return [line.slice(0, index), decodeShellLiteral(line.slice(index + 1))];
  }));
}

function decodeShellLiteral(value) {
  if (!value.startsWith("'") || !value.endsWith("'")) return value;
  return value.slice(1, -1).replaceAll(`'"'"'`, "'");
}

async function mode(path) {
  return ((await stat(path)).mode & 0o777).toString(8).padStart(3, "0");
}
