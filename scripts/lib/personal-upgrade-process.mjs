import { isAbsolute, join, resolve } from "node:path";

export function personalProductionStartArguments(candidateRuntimePath, processName) {
  if (typeof candidateRuntimePath !== "string" || !isAbsolute(candidateRuntimePath)) {
    throw new Error("Candidate runtime path must be absolute.");
  }
  if (typeof processName !== "string" || !/^[A-Za-z0-9._-]+$/u.test(processName)) {
    throw new Error("Production process name is invalid.");
  }
  const runtime = resolve(candidateRuntimePath);
  return [
    join(runtime, "scripts", "start-universal-broker-v2-production.sh"),
    "--name",
    processName,
    "--cwd",
    runtime,
  ];
}
