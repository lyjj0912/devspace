import assert from "node:assert/strict";
import { chmod, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import {
  resolvedEnvProfileExecutionGeneration,
  UniversalEnvProfileRegistry,
} from "./env-profiles.js";

test("environment profile registry resolves target-bound environment, source files, and headers", async (t) => {
  const root = await mkdtemp(join(tmpdir(), "devspace-v2-env-profile-test-"));
  t.after(() => rm(root, { recursive: true, force: true }));
  const path = join(root, "profiles.json");
  await writeFile(path, JSON.stringify({
    version: 1,
    profiles: {
      example: {
        targets: ["local"],
        environment: { EXAMPLE_VALUE: "secret-value" },
        sourceFile: "~/.config/example.env",
        headers: { Authorization: "Bearer private" },
      },
    },
  }), { mode: 0o600 });
  await chmod(path, 0o600);
  const registry = new UniversalEnvProfileRegistry({ configPath: path });
  const resolved = await registry.resolve("example", "local");
  assert.equal(resolved.environment.EXAMPLE_VALUE, "secret-value");
  assert.equal(resolved.sourceFile, "~/.config/example.env");
  assert.equal(resolved.headers.Authorization, "Bearer private");
  const listed = await registry.list();
  assert.equal(JSON.stringify(listed).includes("secret-value"), false);
  assert.equal(JSON.stringify(listed).includes("Bearer private"), false);
  await assert.rejects(
    registry.resolve("example", "company"),
    (error: unknown) => error instanceof Error && "code" in error && error.code === "PERMISSION_DENIED",
  );
});

test("environment profile registry rejects loose permissions", async (t) => {
  const root = await mkdtemp(join(tmpdir(), "devspace-v2-env-profile-test-"));
  t.after(() => rm(root, { recursive: true, force: true }));
  const path = join(root, "profiles.json");
  await writeFile(path, JSON.stringify({ version: 1, profiles: {} }), { mode: 0o644 });
  await chmod(path, 0o644);
  const registry = new UniversalEnvProfileRegistry({ configPath: path });
  await assert.rejects(
    registry.list(),
    (error: unknown) => error instanceof Error && "code" in error && error.code === "PERMISSION_DENIED",
  );
});

test("environment profile generations bind exact profile and local source-file contents", async (t) => {
  const root = await mkdtemp(join(tmpdir(), "devspace-v2-env-profile-generation-"));
  t.after(() => rm(root, { recursive: true, force: true }));
  const path = join(root, "profiles.json");
  const sourcePath = join(root, "developer.env");
  const writeEnvironmentProfile = async (value: string) => {
    await writeFile(path, JSON.stringify({
      version: 1,
      profiles: {
        developer: {
          targets: ["local"],
          environment: { DEVSPACE_PROFILE_VALUE: value },
        },
      },
    }), { mode: 0o600 });
    await chmod(path, 0o600);
  };
  await writeEnvironmentProfile("one");
  const registry = new UniversalEnvProfileRegistry({ configPath: path });
  const first = await registry.resolve("developer", "local");
  await writeEnvironmentProfile("two");
  const second = await registry.resolve("developer", "local");
  assert.notEqual(second.generation, first.generation);

  await writeFile(sourcePath, "PROFILE_VALUE=one\n", { mode: 0o600 });
  await writeFile(path, JSON.stringify({
    version: 1,
    profiles: {
      developer: {
        targets: ["local"],
        sourceFile: sourcePath,
      },
    },
  }), { mode: 0o600 });
  await chmod(path, 0o600);
  const sourced = await registry.resolve("developer", "local");
  const sourceGenerationOne = await resolvedEnvProfileExecutionGeneration(sourced, "local");
  await writeFile(sourcePath, "PROFILE_VALUE=two\n", { mode: 0o600 });
  const sourceGenerationTwo = await resolvedEnvProfileExecutionGeneration(sourced, "local");
  assert.notEqual(sourceGenerationTwo, sourceGenerationOne);
});
