import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { chmod, mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import {
  createPersonalRuntimeManifest,
  verifyPersonalRuntime,
} from "./personal-direct-owner-runtime.mjs";

const REVISION = "a".repeat(40);

test("personal immutable runtime manifest verifies exact package and reused dependency identity", async (t) => {
  const root = await mkdtemp(join(tmpdir(), "devspace-personal-runtime-"));
  t.after(() => rm(root, { recursive: true, force: true }));
  const packageRoot = join(root, "package");
  const dependencyRoot = join(root, "dependencies");
  await mkdir(join(packageRoot, "dist", "v2"), { recursive: true });
  await mkdir(join(packageRoot, "contracts"), { recursive: true });
  await mkdir(join(packageRoot, "scripts"), { recursive: true });
  await mkdir(join(dependencyRoot, "node_modules", "fixture"), { recursive: true });
  const packageJson = { name: "fixture", version: "1.0.0", type: "module" };
  const lockfile = { name: "fixture", version: "1.0.0", lockfileVersion: 3, packages: {} };
  await Promise.all([
    writeFile(join(packageRoot, "package.json"), JSON.stringify(packageJson)),
    writeFile(join(packageRoot, "package-lock.json"), JSON.stringify(lockfile)),
    writeFile(join(dependencyRoot, "package.json"), JSON.stringify(packageJson)),
    writeFile(join(dependencyRoot, "package-lock.json"), JSON.stringify(lockfile)),
    writeFile(join(dependencyRoot, "node_modules", "fixture", "index.js"), "export default true;\n"),
    writeFile(join(packageRoot, "scripts", "start-universal-broker-v2-production.sh"), "#!/bin/sh\n", { mode: 0o700 }),
    writeFile(join(packageRoot, "dist", "cli.js"), "export {};\n"),
    writeFile(join(packageRoot, "dist", "v2", "runtime-contract-identity.js"),
      `export const RUNTIME_SCHEMA_GENERATION = "sha256:${"1".repeat(64)}";\n`),
    writeFile(join(packageRoot, "contracts", "build-capabilities.schema.json"), JSON.stringify({
      properties: {
        productVersion: { const: "2.1.1" },
        productProfile: { const: "PERSONAL_DIRECT_OWNER" },
        supportedProfiles: { const: ["PERSONAL_DIRECT_OWNER"] },
        resourceUriVersion: { const: "v1" },
        supportedOperations: {
          properties: Object.fromEntries([
            "target", "context", "fs", "exec", "process", "mcp", "artifact", "gui",
          ].map((name) => [name, { const: ["fixture"] }])),
        },
      },
    })),
  ]);
  const created = await createPersonalRuntimeManifest({
    packageRoot,
    sourceRevision: REVISION,
    runtimeRevision: REVISION,
  });
  const lockDigest = `sha256:${createHash("sha256").update(await readFile(join(packageRoot, "package-lock.json"))).digest("hex")}`;
  const evidencePath = join(dependencyRoot, "RUNTIME-DEPENDENCIES.json");
  await writeFile(evidencePath, `${JSON.stringify({
    manifestVersion: 1,
    lockfileSha256: lockDigest,
    nodeVersion: process.version,
    platform: `${process.platform}-${process.arch}`,
    nodeModules: { sha256: `sha256:${"2".repeat(64)}` },
  })}\n`, { mode: 0o600 });
  await chmod(evidencePath, 0o600);
  const evidenceDigest = `sha256:${createHash("sha256").update(await readFile(evidencePath)).digest("hex")}`;
  const verified = await verifyPersonalRuntime({
    packageRoot,
    entrypoint: join(packageRoot, "scripts", "start-universal-broker-v2-production.sh"),
    manifestPath: created.manifestPath,
    manifestSha256: created.manifestSha256,
    sourceRevision: REVISION,
    runtimeRevision: REVISION,
    dependencyRoot,
    dependencyEvidence: evidencePath,
    dependencyEvidenceSha256: evidenceDigest,
  });
  assert.equal(verified.status, "PASS");
  assert.equal(verified.productProfile, "PERSONAL_DIRECT_OWNER");

  await writeFile(join(packageRoot, "dist", "cli.js"), "export const tampered = true;\n");
  await assert.rejects(
    verifyPersonalRuntime({
      packageRoot,
      entrypoint: join(packageRoot, "scripts", "start-universal-broker-v2-production.sh"),
      manifestPath: created.manifestPath,
      manifestSha256: created.manifestSha256,
      sourceRevision: REVISION,
      runtimeRevision: REVISION,
      dependencyRoot,
      dependencyEvidence: evidencePath,
      dependencyEvidenceSha256: evidenceDigest,
    }),
    /differs from its immutable manifest/u,
  );
});
