#!/usr/bin/env node

import { resolve } from "node:path";
import {
  ConnectorActivationReleaseDriver,
  loadCompiledConnectorActivationRuntime,
  preflightOwnerOnlyArtifactPath,
  preflightProductionApprovalDirectoryForReconcile,
  readOwnerOnlyJson,
  writeOwnerOnlyArtifactAtomic,
  writeProductionApprovalDirectoryAtomic,
} from "./lib/connector-activation-release-driver.mjs";

const REQUIRED_NODE_VERSION = "22.23.2";
const COMMANDS = Object.freeze({
  "staging-precheck": "createStagingActivationPrecheck",
  "staging-activate": "activateStagingConnector",
  "pre-cutover": "createPreCutoverHostCanary",
  "production-predecision": "createProductionActivationPredecision",
  "production-approve": "createProductionActivationApproval",
  "post-activation": "createPostActivationHostCanary",
  "rollback-challenge": "createRollbackHostChallenge",
  "rollback-host": "createRollbackHostReceipt",
  "rollback-verify": "verifyPersistedRollbackHostReceipt",
});

class UsageError extends Error {}

try {
  if (process.versions.node !== REQUIRED_NODE_VERSION) {
    throw new UsageError(`Connector activation release driver requires Node ${REQUIRED_NODE_VERSION}.`);
  }
  const { command, requestPath, outputPath } = parseArguments(process.argv.slice(2));
  const request = readOwnerOnlyJson(requestPath, `${command} request`);
  if (command === "production-approve") {
    if (resolve(outputPath) !== resolve(request.artifacts?.productionApprovalOutputDirectory ?? "")) {
      throw new UsageError("production-approve --output must equal the signed production approval output directory.");
    }
    preflightProductionApprovalDirectoryForReconcile(outputPath);
  } else if (command !== "rollback-verify") {
    if (command === "production-predecision"
      && resolve(outputPath) !== resolve(request.artifacts?.predecisionPath ?? "")) {
      throw new UsageError("production-predecision --output must equal its bound predecisionPath.");
    }
    if (command === "rollback-host" && resolve(outputPath) !== resolve(request.artifacts?.receiptPath ?? "")) {
      throw new UsageError("rollback-host --output must equal the receiptPath bound into its signed challenge.");
    }
    preflightOwnerOnlyArtifactPath(outputPath);
  }
  const runtime = await loadCompiledConnectorActivationRuntime();
  const driver = new ConnectorActivationReleaseDriver({ runtime });
  const result = driver[COMMANDS[command]](request);
  let summary;
  if (command === "rollback-verify") {
    summary = {
      status: "VERIFIED",
      kind: "ROLLBACK_HOST_RECEIPT",
      transactionId: result.transactionId,
      challengeId: result.challengeId,
      payloadDigest: result.signedPayloadDigest,
    };
  } else if (command === "production-approve") {
    summary = writeProductionApprovalDirectoryAtomic(outputPath, result);
  } else {
    const published = writeOwnerOnlyArtifactAtomic(outputPath, result);
    summary = command === "rollback-challenge"
      ? {
          ...published,
          challengeId: result.payload.challengeId,
          transactionId: result.payload.transactionId,
          receiptPath: result.payload.receiptPath,
          expiresAtMs: result.payload.expiresAtMs,
        }
      : published;
  }
  process.stdout.write(`${JSON.stringify(summary)}\n`);
} catch (error) {
  const usage = error instanceof UsageError;
  const message = error instanceof Error ? error.message : "Unknown release-driver failure.";
  process.stderr.write(`${JSON.stringify({
    status: "FAILED",
    code: usage ? "USAGE" : "VERIFICATION_FAILED",
    message: message.slice(0, 2_000),
  })}\n`);
  process.exitCode = usage ? 64 : 65;
}

function parseArguments(argv) {
  const command = argv[0];
  if (!Object.prototype.hasOwnProperty.call(COMMANDS, command)) {
    throw new UsageError(
      `Usage: connector-activation-release-driver.mjs <${Object.keys(COMMANDS).join("|")}> --request ABSOLUTE_PATH [--output ABSOLUTE_PATH]`,
    );
  }
  const options = new Map();
  for (let index = 1; index < argv.length; index += 2) {
    const flag = argv[index];
    const value = argv[index + 1];
    if (!["--request", "--output"].includes(flag) || value === undefined || options.has(flag)) {
      throw new UsageError("CLI flags must be unique --request/--output pairs.");
    }
    options.set(flag, value);
  }
  const requestPath = absoluteOption(options.get("--request"), "--request");
  if (command === "rollback-verify") {
    if (options.has("--output")) throw new UsageError("rollback-verify does not publish an output artifact.");
    return { command, requestPath };
  }
  return { command, requestPath, outputPath: absoluteOption(options.get("--output"), "--output") };
}

function absoluteOption(value, flag) {
  if (typeof value !== "string" || !value.startsWith("/") || /[\0\r\n]/u.test(value)) {
    throw new UsageError(`${flag} must name one absolute path.`);
  }
  return resolve(value);
}
