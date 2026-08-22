import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { chmod, mkdir, readFile, rm, stat, writeFile } from "node:fs/promises";
import { spawnSync } from "node:child_process";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const source = join(root, "native", "macos-gui-agent");
const output = process.env.DEVSPACE_MACOS_GUI_AGENT_OUTPUT
  ? resolve(process.env.DEVSPACE_MACOS_GUI_AGENT_OUTPUT)
  : join(root, "dist", "native", "macos-gui-agent");
if (output === root || output.startsWith(`${root}/src/`) || output.startsWith(`${root}/native/`)) {
  throw new Error("macOS GUI agent output must stay outside source inputs.");
}
await rm(output, { recursive: true, force: true });
if (process.platform !== "darwin") {
  process.stdout.write("MACOS_GUI_AGENT_BUILD_NOT_APPLICABLE\n");
  process.exit(0);
}
await mkdir(output, { recursive: true, mode: 0o700 });
await chmod(output, 0o700);
const build = spawnSync(join(source, "build.sh"), [output], {
  cwd: root,
  encoding: "utf8",
  timeout: 120_000,
});
assert.equal(build.error, undefined, build.error?.message);
assert.equal(build.status, 0, `${build.stdout}\n${build.stderr}`);
const appPath = join(output, "DevSpace GUI Agent.app");
const executablePath = join(appPath, "Contents", "MacOS", "devspace-gui-agent");
const appRelativePath = output.startsWith(`${root}/`)
  ? appPath.slice(root.length + 1)
  : appPath;
const executableRelativePath = output.startsWith(`${root}/`)
  ? executablePath.slice(root.length + 1)
  : executablePath;
const bytes = await readFile(executablePath);
const state = await stat(executablePath);
assert.equal(state.isFile(), true);
assert.equal(state.mode & 0o777, 0o700);
const signature = spawnSync("/usr/bin/codesign", ["-dvvv", "--requirements", "-", appPath], {
  encoding: "utf8",
  timeout: 10_000,
});
assert.equal(signature.status, 0, signature.stderr);
const signatureText = `${signature.stdout ?? ""}
${signature.stderr ?? ""}`;
const authority = /^Authority=(.+)$/mu.exec(signatureText)?.[1] ?? null;
const designatedRequirement = /^(?:# )?designated => (.+)$/mu.exec(signatureText)?.[1] ?? null;
const teamIdentifier = /^TeamIdentifier=(.+)$/mu.exec(signatureText)?.[1] ?? null;
const signatureKind = /Signature=adhoc/u.test(signatureText) ? "adhoc" : "certificate";
const manifest = {
  schemaVersion: 1,
  kind: "devspace.macos-gui-agent",
  protocol: "devspace-macos-gui-v1",
  bundleIdentifier: "com.devspace.gui-agent",
  platform: process.platform,
  architecture: process.arch,
  appRelativePath,
  executableRelativePath,
  executableSize: bytes.length,
  executableSha256: `sha256:${createHash("sha256").update(bytes).digest("hex")}`,
  executableMode: "0700",
  codeSigned: true,
  signatureKind,
  authority,
  teamIdentifier,
  designatedRequirement,
};
const manifestPath = join(output, "MANIFEST.json");
await writeFile(manifestPath, `${JSON.stringify(manifest, null, 2)}\n`, { mode: 0o600 });
await chmod(manifestPath, 0o600);
const verification = spawnSync("/usr/bin/codesign", ["--verify", "--deep", "--strict", appPath], {
  encoding: "utf8",
  timeout: 10_000,
});
assert.equal(verification.status, 0, verification.stderr);
process.stdout.write(`${JSON.stringify({ status: "PASS", manifestPath, executableSha256: manifest.executableSha256 })}\n`);
