#!/usr/bin/env node
import { createHash } from "node:crypto";
import {
  chmod,
  lstat,
  mkdir,
  readFile,
  realpath,
  writeFile,
} from "node:fs/promises";
import { dirname, isAbsolute, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import {
  digestOperationAuditPayload,
  verifyOperationAuditText,
} from "../dist/v2/operation-audit.js";
import { UNIVERSAL_TOOL_NAMES } from "../dist/v2/contracts.js";

export async function verifyPersonalHttpLive(input) {
  const dataBase = secureBaseUrl(input.dataBaseUrl, "data base URL");
  const managementBase = secureBaseUrl(input.managementBaseUrl, "management base URL");
  const packageRoot = await realDirectory(input.releasePackage, "release package");
  const manifest = JSON.parse(await readFile(join(packageRoot, "BUILD-MANIFEST.json"), "utf8"));
  const tokenFile = await ownerFile(input.tokenFile, "access-token file");
  const token = (await readFile(tokenFile, "utf8")).trim();
  if (token.length < 32 || /\s/u.test(token)) throw new Error("Candidate access token file is invalid.");
  const auditPath = absolute(input.auditPath, "audit path");
  const disposableRoot = absolute(input.disposableRoot, "disposable root");
  await assertAbsent(disposableRoot, "Disposable live-gate root already exists");
  const acceptanceRunId = safeIdentifier(input.acceptanceRunId, "acceptance run ID");
  const connectorEpoch = positiveInteger(input.connectorInstallationEpoch, "connector installation epoch");
  const connectorRotationSequence = nonNegativeInteger(
    input.connectorRotationSequence,
    "connector rotation sequence",
  );
  const target = safeIdentifier(input.target ?? "local", "target");
  const healthUrl = new URL(input.healthPath ?? "/healthz", dataBase);
  const mcpUrl = new URL(input.mcpPath ?? "/mcp", dataBase);
  const readyUrl = new URL(input.readyPath ?? "/readyz", managementBase);
  const headers = {
    Accept: "application/json, text/event-stream",
    Authorization: `Bearer ${token}`,
    "Content-Type": "application/json",
    "User-Agent": "devspace-personal-live-gate/1.0",
  };
  const receiptPayloads = new Map();
  const operationIds = new Set();
  const mutationIds = new Set();
  let statefulHeaders;
  let mixedOperationId;
  let primaryError;
  let cleanupPayload;
  try {
    const health = await getJson(healthUrl);
    verifyRuntimeIdentity(health, manifest, false, acceptanceRunId);
    const ready = await getJson(readyUrl);
    verifyRuntimeIdentity(ready.identity ?? {}, manifest, true, acceptanceRunId);
    if (ready.status !== "ready" || ready.httpStatus !== 200
      || !Array.isArray(ready.checks)
      || ready.checks.some((check) => check.state !== "PASS")) {
      throw new Error("Candidate readiness contains a non-PASS check.");
    }
    const connectorCheck = ready.checks.find((check) => check.id === "canonical_connector");
    if (connectorCheck?.evidence?.activationState !== "ACTIVE") {
      throw new Error("Candidate Personal connector is not ACTIVE.");
    }

    const unauthenticated = await postJsonRpc(mcpUrl, {
      Accept: headers.Accept,
      "Content-Type": headers["Content-Type"],
    }, initializeRequest("personal-live-unauthenticated"));
    if (unauthenticated.response.status !== 401) {
      throw new Error(`Unauthenticated MCP initialize returned ${unauthenticated.response.status}.`);
    }

    statefulHeaders = await initializeStateful(mcpUrl, headers);
    const toolList = await postJsonRpc(mcpUrl, statefulHeaders, {
      jsonrpc: "2.0",
      id: "personal-live-tools-list",
      method: "tools/list",
      params: {},
    });
    assertHttp(toolList, 200, "stateful tools/list");
    const names = toolList.body.result?.tools?.map((tool) => tool.name);
    if (JSON.stringify(names) !== JSON.stringify(UNIVERSAL_TOOL_NAMES)) {
      throw new Error(`Live tool surface differs: ${JSON.stringify(names)}`);
    }

    await toolCall(mcpUrl, statefulHeaders, "live-stateful-target", "target", {
      operation: "list",
    }, receiptPayloads, operationIds);
    await toolCall(mcpUrl, statefulHeaders, "live-stateful-mkdir", "fs", {
      operation: "mkdir",
      target,
      path: disposableRoot,
    }, receiptPayloads, operationIds, mutationIds, true);
    const statefulPath = join(disposableRoot, "stateful.txt");
    const statefulContent = "stateful live mutation\n";
    await toolCall(mcpUrl, statefulHeaders, "live-stateful-write", "fs", {
      operation: "write",
      target,
      path: statefulPath,
      content: statefulContent,
    }, receiptPayloads, operationIds, mutationIds, true);
    const statefulRead = await toolCall(mcpUrl, statefulHeaders, "live-stateful-read", "fs", {
      operation: "read",
      target,
      path: statefulPath,
    }, receiptPayloads, operationIds);
    if (statefulRead.data?.content !== statefulContent) throw new Error("Stateful readback differs.");
    const statefulHash = await toolCall(mcpUrl, statefulHeaders, "live-stateful-hash", "fs", {
      operation: "hash",
      target,
      path: statefulPath,
    }, receiptPayloads, operationIds);
    if (statefulHash.data?.sha256 !== sha256Hex(statefulContent)) throw new Error("Stateful hash differs.");

    const sessionlessPath = join(disposableRoot, "sessionless.txt");
    const sessionlessContent = "sessionless live mutation\n";
    await toolCall(mcpUrl, headers, "live-sessionless-write", "fs", {
      operation: "write",
      target,
      path: sessionlessPath,
      content: sessionlessContent,
    }, receiptPayloads, operationIds, mutationIds, true);
    const sessionlessRead = await toolCall(mcpUrl, headers, "live-sessionless-read", "fs", {
      operation: "read",
      target,
      path: sessionlessPath,
    }, receiptPayloads, operationIds);
    if (sessionlessRead.data?.content !== sessionlessContent) throw new Error("Sessionless readback differs.");
    const sessionlessHash = await toolCall(mcpUrl, headers, "live-sessionless-hash", "fs", {
      operation: "hash",
      target,
      path: sessionlessPath,
    }, receiptPayloads, operationIds);
    if (sessionlessHash.data?.sha256 !== sha256Hex(sessionlessContent)) {
      throw new Error("Sessionless hash differs.");
    }

    const mixedPath = join(disposableRoot, "mixed-retry.txt");
    const mixedBody = {
      jsonrpc: "2.0",
      id: "live-mixed-stateful-sessionless-exec",
      method: "tools/call",
      params: {
        name: "exec",
        arguments: {
          target,
          cwd: disposableRoot,
          command: `sleep 0.25; printf 'once\\n' >> ${shellQuote(mixedPath)}`,
          mode: "foreground",
          yieldMs: 5_000,
        },
      },
    };
    const [mixedStateful, mixedSessionless] = await Promise.all([
      postJsonRpc(mcpUrl, statefulHeaders, mixedBody),
      postJsonRpc(mcpUrl, headers, mixedBody),
    ]);
    assertHttp(mixedStateful, 200, "mixed stateful execution");
    assertHttp(mixedSessionless, 200, "mixed sessionless execution");
    const mixedStatefulPayload = successfulPayload(mixedStateful.body, "mixed stateful execution");
    const mixedSessionlessPayload = successfulPayload(mixedSessionless.body, "mixed sessionless execution");
    if (mixedStatefulPayload.operationId !== mixedSessionlessPayload.operationId) {
      throw new Error("Mixed stateful/sessionless retries returned different operation IDs.");
    }
    mixedOperationId = mixedStatefulPayload.operationId;
    rememberReceipt(mixedStatefulPayload, receiptPayloads, operationIds, mutationIds, true);
    const mixedRead = await toolCall(mcpUrl, headers, "live-mixed-read", "fs", {
      operation: "read",
      target,
      path: mixedPath,
    }, receiptPayloads, operationIds);
    if (mixedRead.data?.content !== "once\n") throw new Error("Mixed retry dispatched more than once.");
  } catch (error) {
    primaryError = error;
  } finally {
    try {
      const cleanup = await postJsonRpc(mcpUrl, headers, {
        jsonrpc: "2.0",
        id: "live-cleanup-root",
        method: "tools/call",
        params: {
          name: "fs",
          arguments: {
            operation: "remove",
            target,
            path: disposableRoot,
            recursive: true,
            disposition: "permanent",
          },
        },
      });
      assertHttp(cleanup, 200, "live cleanup");
      const payload = cleanup.body.result?.structuredContent;
      if (payload?.ok === true) {
        cleanupPayload = payload;
        rememberReceipt(payload, receiptPayloads, operationIds, mutationIds, true);
      } else if (payload?.error?.code !== "PATH_NOT_FOUND") {
        throw new Error(`Live cleanup failed: ${JSON.stringify(payload)}`);
      }
      const absent = await postJsonRpc(mcpUrl, headers, {
        jsonrpc: "2.0",
        id: "live-cleanup-readback",
        method: "tools/call",
        params: { name: "fs", arguments: { operation: "stat", target, path: disposableRoot } },
      });
      assertHttp(absent, 200, "cleanup absence readback");
      const absentPayload = absent.body.result?.structuredContent;
      if (absentPayload?.ok !== false || absentPayload?.error?.code !== "PATH_NOT_FOUND") {
        throw new Error("Disposable live-gate root still exists after cleanup.");
      }
    } catch (cleanupError) {
      if (primaryError) {
        throw new AggregateError([primaryError, cleanupError], "Live gate and cleanup both failed.");
      }
      throw cleanupError;
    } finally {
      if (statefulHeaders) {
        await fetch(mcpUrl, { method: "DELETE", headers: statefulHeaders }).catch(() => undefined);
      }
    }
  }
  if (primaryError) throw primaryError;
  if (!cleanupPayload) throw new Error("Live cleanup did not produce an acknowledged mutation.");

  const records = await waitForAudit(auditPath, operationIds);
  const byOperation = new Map(records.map((record) => [record.operationId, record]));
  for (const operationId of operationIds) {
    const record = byOperation.get(operationId);
    if (!record) throw new Error(`Audit record is missing: ${operationId}`);
    verifyAuditIdentity(
      record,
      manifest,
      acceptanceRunId,
      connectorEpoch,
      connectorRotationSequence,
    );
    const receipt = receiptPayloads.get(operationId);
    if (!receipt || digestOperationAuditPayload(receipt) !== record.receiptDigest) {
      throw new Error(`Audit receipt digest mismatch: ${operationId}`);
    }
    if (record.result !== "pass" || record.dispatchState !== "ACKNOWLEDGED") {
      throw new Error(`Live operation is not acknowledged PASS: ${operationId}`);
    }
    if (mutationIds.has(operationId) && !/^R[1-3]$/u.test(record.risk)) {
      throw new Error(`Live mutation has read-only audit risk: ${operationId}`);
    }
  }
  if (!mixedOperationId || records.filter((record) => record.operationId === mixedOperationId).length !== 1) {
    throw new Error("Mixed retry did not produce exactly one audit record.");
  }
  if (input.errorLog) await verifyErrorLog(input.errorLog, input.errorLogOffset ?? 0);

  return {
    status: "PERSONAL_DIRECT_OWNER_HTTP_LIVE_PASS",
    productProfile: manifest.productProfile,
    sourceRevision: manifest.sourceRevision,
    runtimeRevision: manifest.runtimeRevision,
    buildDigest: manifest.buildDigest,
    schemaGeneration: manifest.schemaGeneration,
    acceptanceRunId,
    connectorInstallationEpoch: connectorEpoch,
    connectorRotationSequence,
    toolNames: UNIVERSAL_TOOL_NAMES,
    verifiedOperationIds: [...operationIds],
    verifiedMutationIds: [...mutationIds],
    auditSequenceStart: Math.min(...[...operationIds].map((id) => byOperation.get(id).sequence)),
    auditSequenceEnd: Math.max(...[...operationIds].map((id) => byOperation.get(id).sequence)),
    auditLastEventDigest: records.at(-1)?.eventDigest,
    disposableRoot,
    cleanup: "PATH_NOT_FOUND",
  };
}

async function toolCall(
  url,
  headers,
  id,
  name,
  args,
  receipts,
  operations,
  mutations,
  mutation = false,
) {
  const response = await postJsonRpc(url, headers, {
    jsonrpc: "2.0",
    id,
    method: "tools/call",
    params: { name, arguments: args },
  });
  assertHttp(response, 200, `${name}.${String(args.operation ?? "run")}`);
  const payload = successfulPayload(response.body, `${name}.${String(args.operation ?? "run")}`);
  rememberReceipt(payload, receipts, operations, mutations, mutation);
  return payload;
}

function rememberReceipt(payload, receipts, operations, mutations, mutation = false) {
  if (!payload.operationId || receipts.has(payload.operationId)) {
    throw new Error(`Live result has a missing or duplicate operationId: ${payload.operationId}`);
  }
  receipts.set(payload.operationId, payload);
  operations.add(payload.operationId);
  if (mutation) mutations.add(payload.operationId);
}

function successfulPayload(body, label) {
  const payload = body.result?.structuredContent;
  if (!payload || payload.ok !== true || !payload.operationId) {
    throw new Error(`${label} failed: ${JSON.stringify(payload ?? body)}`);
  }
  return payload;
}

async function initializeStateful(url, headers) {
  const initialized = await postJsonRpc(url, headers, initializeRequest("personal-live-stateful"));
  assertHttp(initialized, 200, "stateful initialize");
  const sessionId = initialized.response.headers.get("mcp-session-id");
  if (!sessionId) throw new Error("Stateful initialize returned no MCP session ID.");
  const statefulHeaders = { ...headers, "mcp-session-id": sessionId };
  const ready = await postJsonRpc(url, statefulHeaders, {
    jsonrpc: "2.0",
    method: "notifications/initialized",
  });
  assertHttp(ready, 202, "stateful initialized notification");
  return statefulHeaders;
}

function initializeRequest(name) {
  return {
    jsonrpc: "2.0",
    id: `${name}-initialize`,
    method: "initialize",
    params: {
      protocolVersion: "2025-06-18",
      capabilities: {},
      clientInfo: { name, version: "1" },
    },
  };
}

async function postJsonRpc(url, headers, body) {
  const response = await fetch(url, { method: "POST", headers, body: JSON.stringify(body) });
  const text = await response.text();
  return { response, body: parseJsonRpcText(text) };
}

function parseJsonRpcText(text) {
  const trimmed = text.trim();
  if (!trimmed) return {};
  if (trimmed.startsWith("{") || trimmed.startsWith("[")) return JSON.parse(trimmed);
  const payload = trimmed.split(/\r?\n/u)
    .find((line) => line.startsWith("data:"))
    ?.slice("data:".length)
    .trim();
  if (!payload) throw new Error(`MCP response contains no JSON payload: ${trimmed.slice(0, 500)}`);
  return JSON.parse(payload);
}

function assertHttp(result, status, label) {
  if (result.response.status !== status) {
    throw new Error(`${label} returned HTTP ${result.response.status}: ${JSON.stringify(result.body)}`);
  }
}

async function getJson(url) {
  const response = await fetch(url);
  const text = await response.text();
  if (response.status !== 200) throw new Error(`${url.href} returned ${response.status}: ${text.slice(0, 500)}`);
  return JSON.parse(text);
}

function verifyRuntimeIdentity(identity, manifest, requirePrivateIdentity, runId) {
  for (const [field, expected] of [
    ["productProfile", "PERSONAL_DIRECT_OWNER"],
    ["runtimeRevision", manifest.runtimeRevision],
    ["buildDigest", manifest.buildDigest],
    ["schemaGeneration", manifest.schemaGeneration],
  ]) {
    if (identity[field] !== expected) throw new Error(`Live runtime identity mismatch: ${field}`);
  }
  if (requirePrivateIdentity) {
    if (identity.sourceRevision !== manifest.sourceRevision) {
      throw new Error("Live private runtime identity mismatch: sourceRevision");
    }
    if (identity.acceptanceRunId !== runId) {
      throw new Error("Live readiness acceptance run ID differs.");
    }
  }
}

async function waitForAudit(path, operationIds) {
  const deadline = Date.now() + 10_000;
  do {
    try {
      const records = verifyOperationAuditText(await readFile(path, "utf8"));
      if ([...operationIds].every((operationId) => records.some((record) => record.operationId === operationId))) {
        return records;
      }
    } catch (error) {
      if (!(error && typeof error === "object" && "code" in error && error.code === "ENOENT")) throw error;
    }
    await new Promise((resolve) => setTimeout(resolve, 20));
  } while (Date.now() < deadline);
  throw new Error("Live operation audit records did not flush before the deadline.");
}

function verifyAuditIdentity(record, manifest, runId, connectorEpoch, rotation) {
  for (const [field, expected] of [
    ["productProfile", "PERSONAL_DIRECT_OWNER"],
    ["sourceRevision", manifest.sourceRevision],
    ["runtimeRevision", manifest.runtimeRevision],
    ["buildDigest", manifest.buildDigest],
    ["schemaGeneration", manifest.schemaGeneration],
    ["acceptanceRunId", runId],
    ["connectorInstallationEpoch", connectorEpoch],
    ["connectorRotationSequence", rotation],
  ]) {
    if (record[field] !== expected) throw new Error(`Live audit identity mismatch ${record.operationId}: ${field}`);
  }
}

async function verifyErrorLog(path, offset) {
  const resolved = await ownerFile(path, "candidate error log", false);
  const text = (await readFile(resolved, "utf8")).slice(offset);
  for (const forbidden of ["v2_mcp_sessionless_rejected", "v2_mcp_request_error"]) {
    if (text.includes(forbidden)) throw new Error(`Candidate error log contains ${forbidden}.`);
  }
}

async function realDirectory(value, label) {
  const path = await realpath(absolute(value, label));
  const metadata = await lstat(path);
  if (!metadata.isDirectory() || metadata.isSymbolicLink()) throw new Error(`${label} must be a real directory.`);
  return path;
}

async function ownerFile(value, label, ownerOnly = true) {
  const path = await realpath(absolute(value, label));
  const metadata = await lstat(path);
  if (!metadata.isFile() || metadata.isSymbolicLink() || (ownerOnly && (metadata.mode & 0o077) !== 0)) {
    throw new Error(`${label} must be an owner-only regular file.`);
  }
  return path;
}

function absolute(value, label) {
  if (typeof value !== "string" || !isAbsolute(value)) throw new Error(`${label} must be absolute.`);
  return resolve(value);
}

function secureBaseUrl(value, label) {
  const url = new URL(value);
  if (url.protocol === "https:") return url;
  if (url.protocol === "http:" && ["127.0.0.1", "localhost", "::1"].includes(url.hostname)) return url;
  throw new Error(`${label} must be HTTPS or loopback HTTP.`);
}

function safeIdentifier(value, label) {
  if (typeof value !== "string" || !/^[A-Za-z0-9][A-Za-z0-9._:@/-]{0,255}$/u.test(value)) {
    throw new Error(`${label} is invalid.`);
  }
  return value;
}

function positiveInteger(value, label) {
  const number = Number(value);
  if (!Number.isSafeInteger(number) || number <= 0) throw new Error(`${label} must be positive.`);
  return number;
}

function nonNegativeInteger(value, label) {
  const number = Number(value);
  if (!Number.isSafeInteger(number) || number < 0) throw new Error(`${label} must be non-negative.`);
  return number;
}

async function assertAbsent(path, message) {
  try { await lstat(path); } catch (error) {
    if (error && typeof error === "object" && "code" in error && error.code === "ENOENT") return;
    throw error;
  }
  throw new Error(`${message}: ${path}`);
}

function sha256Hex(value) {
  return createHash("sha256").update(value).digest("hex");
}

function shellQuote(value) {
  return `'${value.replaceAll("'", `'"'"'`)}'`;
}

function parseOptions(values) {
  const result = new Map();
  for (let index = 0; index < values.length; index += 2) {
    const key = values[index];
    const value = values[index + 1];
    if (!key?.startsWith("--") || value === undefined) throw new Error("Options must use --name value pairs.");
    result.set(key.slice(2), value);
  }
  return result;
}

function required(options, key) {
  const value = options.get(key);
  if (!value) throw new Error(`--${key} is required.`);
  return value;
}

async function main() {
  const options = parseOptions(process.argv.slice(2));
  const outputPath = absolute(required(options, "output"), "output");
  await assertAbsent(outputPath, "Live-gate output already exists");
  const result = await verifyPersonalHttpLive({
    dataBaseUrl: required(options, "data-base-url"),
    managementBaseUrl: required(options, "management-base-url"),
    releasePackage: required(options, "release-package"),
    tokenFile: required(options, "token-file"),
    auditPath: required(options, "audit-path"),
    disposableRoot: required(options, "disposable-root"),
    acceptanceRunId: required(options, "acceptance-run-id"),
    connectorInstallationEpoch: required(options, "connector-installation-epoch"),
    connectorRotationSequence: required(options, "connector-rotation-sequence"),
    target: options.get("target") ?? "local",
    healthPath: options.get("health-path") ?? "/healthz",
    mcpPath: options.get("mcp-path") ?? "/mcp",
    readyPath: options.get("ready-path") ?? "/readyz",
    errorLog: options.get("error-log"),
    errorLogOffset: options.get("error-log-offset")
      ? nonNegativeInteger(options.get("error-log-offset"), "error-log offset")
      : undefined,
  });
  await mkdir(dirname(outputPath), { recursive: true, mode: 0o700 });
  await writeFile(outputPath, `${JSON.stringify(result, null, 2)}\n`, {
    encoding: "utf8",
    flag: "wx",
    mode: 0o600,
  });
  await chmod(outputPath, 0o600);
  process.stdout.write(`${JSON.stringify({ ...result, outputPath }, null, 2)}\n`);
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) await main();
