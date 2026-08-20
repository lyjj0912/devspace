import { spawnSync } from "node:child_process";
import { chmodSync, renameSync, rmSync, writeFileSync } from "node:fs";
import { dirname, isAbsolute, resolve } from "node:path";
import { fileURLToPath } from "node:url";

export function cleanupCandidateBeforeCutover(options) {
  const pm2Executable = absolute(options?.pm2Executable, "PM2 executable");
  const lsofExecutable = absolute(options?.lsofExecutable, "lsof executable");
  const candidateName = boundedName(options?.candidateName);
  const candidatePort = boundedPort(options?.candidatePort);
  const candidateState = absolute(options?.candidateState, "candidate state");
  const run = options?.run ?? runCommand;
  const removeState = options?.removeState ?? ((path) => rmSync(path, { recursive: true, force: true }));

  requireSuccess(run(pm2Executable, ["delete", candidateName]), "PM2 candidate delete");
  requireSuccess(run(pm2Executable, ["save"]), "PM2 saved-state update");
  const pm2Readback = run(pm2Executable, ["jlist"]);
  requireSuccess(pm2Readback, "PM2 candidate absence readback");
  const processes = parsePm2List(pm2Readback.stdout);
  if (processes.some((process) => process?.name === candidateName)) {
    throw new Error(`PM2 candidate is still present after delete/save: ${candidateName}`);
  }

  const listenerReadback = run(lsofExecutable, [
    "-nP",
    `-iTCP:${candidatePort}`,
    "-sTCP:LISTEN",
    "-t",
  ]);
  if (listenerReadback.status === 0) {
    const listeners = String(listenerReadback.stdout ?? "").trim();
    throw new Error(`Candidate port still has a listener after PM2 cleanup: ${candidatePort}${listeners ? ` (${listeners})` : ""}`);
  }
  if (listenerReadback.status !== 1) {
    throw new Error(`Candidate listener readback failed: ${bounded(listenerReadback.stderr || listenerReadback.stdout)}`);
  }

  removeState(candidateState);
  const evidence = Object.freeze({
    version: 1,
    candidateName,
    candidatePort,
    pm2Deleted: true,
    pm2Saved: true,
    pm2Absent: true,
    listenerAbsent: true,
    candidateStateRemoved: true,
    completedAt: new Date().toISOString(),
  });
  if (options?.evidencePath) writeEvidence(absolute(options.evidencePath, "cleanup evidence"), evidence);
  return evidence;
}

function runCommand(executable, arguments_) {
  return spawnSync(executable, arguments_, { encoding: "utf8", timeout: 30_000, env: process.env });
}

function requireSuccess(result, operation) {
  if (result?.error) throw result.error;
  if (result?.status !== 0) {
    throw new Error(`${operation} failed: ${bounded(result?.stderr || result?.stdout)}`);
  }
}

function parsePm2List(value) {
  const text = String(value ?? "");
  const start = text.indexOf("[");
  if (start < 0) throw new Error("PM2 candidate absence readback did not return JSON.");
  let parsed;
  try { parsed = JSON.parse(text.slice(start)); } catch (error) {
    throw new Error(`PM2 candidate absence readback is invalid: ${error instanceof Error ? error.message : String(error)}`);
  }
  if (!Array.isArray(parsed)) throw new Error("PM2 candidate absence readback is not an array.");
  return parsed;
}

function writeEvidence(path, value) {
  const temporary = `${path}.${process.pid}.tmp`;
  writeFileSync(temporary, `${JSON.stringify(value, null, 2)}\n`, { mode: 0o600, flag: "wx" });
  chmodSync(temporary, 0o600);
  renameSync(temporary, path);
}

function absolute(value, name) {
  if (typeof value !== "string" || !isAbsolute(value) || /[\0\r\n]/u.test(value)) {
    throw new Error(`${name} must be an absolute path.`);
  }
  return resolve(value);
}

function boundedName(value) {
  if (typeof value !== "string" || !/^[A-Za-z0-9_.-]{1,128}$/u.test(value)) {
    throw new Error("Candidate PM2 name is invalid.");
  }
  return value;
}

function boundedPort(value) {
  const number = Number(value);
  if (!Number.isInteger(number) || number < 1 || number > 65_535) throw new Error("Candidate port is invalid.");
  return number;
}

function bounded(value) {
  return String(value ?? "").trim().slice(0, 2_000) || "no command output";
}

function parseCli(values) {
  const options = {};
  for (let index = 0; index < values.length; index += 2) {
    const flag = values[index];
    const value = values[index + 1];
    if (!flag?.startsWith("--") || value === undefined) throw new Error("Candidate cleanup options must be --name value pairs.");
    const key = flag.slice(2);
    if (key === "pm2") options.pm2Executable = value;
    else if (key === "lsof") options.lsofExecutable = value;
    else if (key === "name") options.candidateName = value;
    else if (key === "port") options.candidatePort = Number(value);
    else if (key === "state") options.candidateState = value;
    else if (key === "evidence") options.evidencePath = value;
    else throw new Error(`Unknown candidate cleanup option: ${flag}`);
  }
  return options;
}

if (process.argv[1] && resolve(process.argv[1]) === resolve(fileURLToPath(import.meta.url))) {
  try {
    const [command, ...arguments_] = process.argv.slice(2);
    if (command !== "cleanup") throw new Error("Usage: release-candidate-cleanup.mjs cleanup --pm2 PATH --lsof PATH --name NAME --port PORT --state PATH --evidence PATH");
    console.log(JSON.stringify(cleanupCandidateBeforeCutover(parseCli(arguments_)), null, 2));
  } catch (error) {
    console.error(error instanceof Error ? error.message : String(error));
    process.exitCode = 1;
  }
}
