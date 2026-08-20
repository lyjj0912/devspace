#!/usr/bin/env node
import {
  createPrivateKey,
  generateKeyPairSync,
} from "node:crypto";
import {
  chmodSync,
  closeSync,
  constants,
  existsSync,
  fsyncSync,
  lstatSync,
  mkdirSync,
  openSync,
  readFileSync,
  unlinkSync,
  writeFileSync,
} from "node:fs";
import { homedir } from "node:os";
import { basename, dirname, isAbsolute, join, resolve } from "node:path";
import { pathToFileURL } from "node:url";
import { ArtifactCatalog } from "../dist/v2/artifact-catalog.js";
import { SqliteConnectorActivationRecoveryJournal } from "../dist/v2/connector-activation-journal.js";
import { loadCursorSigningKeyRing } from "../dist/v2/cursor-signing-key.js";
import { DurableFilesystemSync } from "../dist/v2/filesystem-sync.js";
import {
  loadExistingManagementAuthorizationKey,
  loadOrCreateManagementAuthorizationKey,
} from "../dist/v2/management-authorization.js";
import {
  bootstrapFinalizationStore,
  createFinalizationStoreBootstrapAuthorization,
  readFinalizationStoreIdentity,
} from "./lib/finalization-store-contract.mjs";
import {
  createGateProducerTrustAnchor,
  fileSha256,
  verifyGateProducerTrustAnchor,
} from "./lib/release-artifacts.mjs";

const DEFAULT_STATE_DIR = join(homedir(), ".local/share/devspace/universal-broker-v2-production");
const DEFAULT_IDENTITY_DIRECTORY = join(homedir(), ".devspace/identity");
const DEFAULT_ARTIFACT_MAXIMUM_ENTRIES = 1_000;
const DEFAULT_ARTIFACT_MAXIMUM_TOTAL_BYTES = 2 * 1024 * 1024 * 1024;

export function resolveProductionProvisioningPaths(options = {}) {
  const stateDir = canonicalAbsolute(options.stateDir ?? DEFAULT_STATE_DIR, "state directory");
  const identityDirectory = canonicalAbsolute(
    options.identityDirectory ?? DEFAULT_IDENTITY_DIRECTORY,
    "identity directory",
  );
  const finalizationControl = canonicalAbsolute(
    options.finalizationControl
      ?? join(dirname(stateDir), `${basename(stateDir)}-finalization-control/lifecycle-finalization-head.json`),
    "finalization control",
  );
  return Object.freeze({
    stateDir,
    identityDirectory,
    managementKey: join(stateDir, "management-authorization.key"),
    cursorKey: join(stateDir, "cursor-hmac-current.key"),
    gatePrivateKey: join(identityDirectory, "gate-producer-ed25519-private.pem"),
    gateTrustAnchor: join(identityDirectory, "gate-producer-trust-anchor.json"),
    lifecycleStore: join(stateDir, "lifecycle.sqlite"),
    finalizationControl,
    finalizationBootstrapConsumed: `${finalizationControl}.bootstrap-consumed.json`,
    connectorJournal: join(stateDir, "connector-activation-journal.sqlite"),
    filesystemSyncStore: join(stateDir, "filesystem-sync/sync.sqlite"),
    artifactCatalog: join(stateDir, "artifacts.sqlite"),
    artifactObjectRoot: join(stateDir, "artifact-objects"),
    artifactQuarantineRoot: join(stateDir, "artifacts/quarantine"),
  });
}

export function inspectProductionProvisioning(options) {
  const configuration = normalizeOptions(options);
  const paths = resolveProductionProvisioningPaths(configuration);
  const required = [
    "managementKey",
    "cursorKey",
    "gatePrivateKey",
    "gateTrustAnchor",
    "lifecycleStore",
    "finalizationControl",
    "finalizationBootstrapConsumed",
    "connectorJournal",
    "filesystemSyncStore",
    "artifactCatalog",
    "artifactObjectRoot",
    "artifactQuarantineRoot",
  ];
  const missing = required.filter((key) => !existsSync(paths[key]));
  const errors = [];
  let managementKey;
  let trustAnchor;
  let finalization;
  try {
    if (!missing.includes("managementKey")) {
      managementKey = loadExistingManagementAuthorizationKey({
        keyRef: paths.managementKey,
        stateDir: paths.stateDir,
      });
    }
    if (!missing.includes("gatePrivateKey")) validateGateProducerPrivateKey(paths.gatePrivateKey);
    if (managementKey && !missing.includes("gateTrustAnchor")) {
      trustAnchor = verifyGateProducerTrustAnchor({
        path: paths.gateTrustAnchor,
        sha256: `sha256:${fileSha256(paths.gateTrustAnchor)}`,
        key: managementKey,
        expectedOwnerInstanceId: configuration.ownerInstanceId,
        expectedEnvironment: configuration.environment,
      });
    }
    if (managementKey && !missing.includes("lifecycleStore") && !missing.includes("finalizationControl")) {
      finalization = readFinalizationStoreIdentity({
        storePath: paths.lifecycleStore,
        controlPath: paths.finalizationControl,
        key: managementKey,
      });
    }
    for (const key of required) {
      if (!missing.includes(key)) assertOwnerOnlyPath(paths[key], key.endsWith("Root") ? "directory" : "file");
    }
  } catch (error) {
    errors.push(error instanceof Error ? error.message : String(error));
  }
  return Object.freeze({
    status: missing.length === 0 && errors.length === 0 ? "READY" : "NOT_READY",
    ownerInstanceId: configuration.ownerInstanceId,
    environment: configuration.environment,
    paths,
    missing: Object.freeze(missing),
    errors: Object.freeze(errors),
    identities: Object.freeze({
      ...(managementKey ? { managementKeyId: managementKey.keyId } : {}),
      ...(trustAnchor ? {
        gateProducerKeyId: trustAnchor.gateProducer.keyId,
        gateTrustAnchorSha256: trustAnchor.sha256,
      } : {}),
      ...(finalization ? {
        finalizationState: finalization.state,
        finalizationRevision: finalization.revision,
        finalizationHead: finalization.contentGeneration,
      } : {}),
    }),
  });
}

export async function provisionProductionState(options) {
  const configuration = normalizeOptions(options);
  const paths = resolveProductionProvisioningPaths(configuration);
  for (const directory of [
    paths.stateDir,
    paths.identityDirectory,
    dirname(paths.finalizationControl),
    dirname(paths.filesystemSyncStore),
  ]) ensureOwnerOnlyDirectory(directory);

  const managementKey = loadOrCreateManagementAuthorizationKey({
    keyRef: paths.managementKey,
    stateDir: paths.stateDir,
  });
  const cursorKeys = loadCursorSigningKeyRing({
    currentKeyRef: paths.cursorKey,
    stateDir: paths.stateDir,
  });
  ensureGateProducerPrivateKey(paths.gatePrivateKey);
  const trustAnchor = existsSync(paths.gateTrustAnchor)
    ? verifyGateProducerTrustAnchor({
      path: paths.gateTrustAnchor,
      sha256: `sha256:${fileSha256(paths.gateTrustAnchor)}`,
      key: managementKey,
      expectedOwnerInstanceId: configuration.ownerInstanceId,
      expectedEnvironment: configuration.environment,
    })
    : createGateProducerTrustAnchor({
      path: paths.gateTrustAnchor,
      privateKeyPath: paths.gatePrivateKey,
      key: managementKey,
      ownerInstanceId: configuration.ownerInstanceId,
      environment: configuration.environment,
    });

  const lifecycleExists = existsSync(paths.lifecycleStore);
  const controlExists = existsSync(paths.finalizationControl);
  if (lifecycleExists !== controlExists) {
    throw new Error("Lifecycle finalization store/control are only partially provisioned; refusing DRAFT resurrection.");
  }
  const finalization = lifecycleExists
    ? readFinalizationStoreIdentity({
      storePath: paths.lifecycleStore,
      controlPath: paths.finalizationControl,
      key: managementKey,
    })
    : bootstrapFinalizationStore({
      storePath: paths.lifecycleStore,
      controlPath: paths.finalizationControl,
      key: managementKey,
      bootstrapAuthorization: createFinalizationStoreBootstrapAuthorization({
        storePath: paths.lifecycleStore,
        controlPath: paths.finalizationControl,
        key: managementKey,
      }),
    });

  const journal = new SqliteConnectorActivationRecoveryJournal({ storePath: paths.connectorJournal });
  const journalIdentity = journal.identity();
  journal.close();

  const sync = new DurableFilesystemSync({
    storePath: paths.filesystemSyncStore,
    trash: {
      trash: async () => {
        throw new Error("Provisioning does not execute filesystem sync operations.");
      },
    },
  });
  sync.initializeStore();

  const catalog = new ArtifactCatalog({
    catalogPath: paths.artifactCatalog,
    objectRoot: paths.artifactObjectRoot,
    quarantineRoot: paths.artifactQuarantineRoot,
    maximumEntries: DEFAULT_ARTIFACT_MAXIMUM_ENTRIES,
    maximumTotalBytes: DEFAULT_ARTIFACT_MAXIMUM_TOTAL_BYTES,
  });
  const artifactReconciliation = await catalog.reconcile();
  catalog.close();

  const inspected = inspectProductionProvisioning(configuration);
  if (inspected.status !== "READY") {
    throw new Error(`Production provisioning readback failed: ${JSON.stringify(inspected)}`);
  }
  return Object.freeze({
    ...inspected,
    identities: Object.freeze({
      ...inspected.identities,
      cursorKeyId: cursorKeys.currentKey.keyId,
      connectorJournalStoreId: journalIdentity.storeId,
      connectorJournalGeneration: journalIdentity.contentGeneration,
      finalizationState: finalization.state,
      finalizationRevision: finalization.revision,
      finalizationHead: finalization.contentGeneration,
    }),
    artifactReconciliation,
    gateTrustAnchorSha256: trustAnchor.sha256,
  });
}

function normalizeOptions(options = {}) {
  const ownerInstanceId = requiredBoundedText(options.ownerInstanceId, "owner instance id", 8, 512);
  const environment = requiredBoundedText(options.environment ?? "PRODUCTION", "environment", 1, 128);
  return Object.freeze({
    ownerInstanceId,
    environment,
    ...(options.stateDir ? { stateDir: options.stateDir } : {}),
    ...(options.identityDirectory ? { identityDirectory: options.identityDirectory } : {}),
    ...(options.finalizationControl ? { finalizationControl: options.finalizationControl } : {}),
  });
}

function ensureGateProducerPrivateKey(path) {
  try {
    return validateGateProducerPrivateKey(path);
  } catch (error) {
    if (error?.code !== "ENOENT") throw error;
  }
  ensureOwnerOnlyDirectory(dirname(path));
  const { privateKey } = generateKeyPairSync("ed25519");
  const pem = privateKey.export({ format: "pem", type: "pkcs8" });
  writeOwnerOnlyCreate(path, pem);
  return validateGateProducerPrivateKey(path);
}

function validateGateProducerPrivateKey(path) {
  assertOwnerOnlyPath(path, "file");
  const key = createPrivateKey(readFileSync(path));
  if (key.asymmetricKeyType !== "ed25519") throw new Error("Gate producer private key must be Ed25519.");
  return key;
}

function writeOwnerOnlyCreate(path, value) {
  let descriptor;
  try {
    descriptor = openSync(path, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL, 0o600);
    writeFileSync(descriptor, value);
    fsyncSync(descriptor);
    closeSync(descriptor);
    descriptor = undefined;
    fsyncDirectory(dirname(path));
  } catch (error) {
    if (descriptor !== undefined) closeSync(descriptor);
    if (error?.code !== "EEXIST") {
      try { unlinkSync(path); } catch {}
      throw error;
    }
  }
}

function ensureOwnerOnlyDirectory(path) {
  mkdirSync(path, { recursive: true, mode: 0o700 });
  chmodSync(path, 0o700);
  assertOwnerOnlyPath(path, "directory");
}

function assertOwnerOnlyPath(path, expectedType) {
  const metadata = lstatSync(path);
  if (metadata.isSymbolicLink()
    || (expectedType === "directory" ? !metadata.isDirectory() : !metadata.isFile())) {
    throw new Error(`${path} must be an owner-only ${expectedType}, not a symlink.`);
  }
  if ((metadata.mode & 0o077) !== 0 || (metadata.mode & 0o400) === 0) {
    throw new Error(`${path} must be accessible only by its owner.`);
  }
  if (typeof process.getuid === "function" && metadata.uid !== process.getuid()) {
    throw new Error(`${path} must be owned by the broker service user.`);
  }
}

function fsyncDirectory(path) {
  const descriptor = openSync(path, constants.O_RDONLY);
  try { fsyncSync(descriptor); } finally { closeSync(descriptor); }
}

function canonicalAbsolute(value, label) {
  if (typeof value !== "string" || !isAbsolute(value) || resolve(value) !== value || /[\0\r\n]/u.test(value)) {
    throw new Error(`${label} must be a canonical absolute path.`);
  }
  return value;
}

function requiredBoundedText(value, label, minimum, maximum) {
  if (typeof value !== "string" || value.length < minimum || value.length > maximum || /[\0\r\n]/u.test(value)) {
    throw new Error(`${label} is missing or invalid.`);
  }
  return value;
}

function parseCli(argv) {
  const [command, ...tokens] = argv;
  if (!new Set(["status", "apply"]).has(command)) throw new Error(usage());
  const options = {};
  while (tokens.length > 0) {
    const flag = tokens.shift();
    const value = tokens.shift();
    if (!value) throw new Error(`Missing value for ${flag}.\n${usage()}`);
    if (flag === "--state-dir") options.stateDir = value;
    else if (flag === "--identity-directory") options.identityDirectory = value;
    else if (flag === "--finalization-control") options.finalizationControl = value;
    else if (flag === "--owner-instance-id") options.ownerInstanceId = value;
    else if (flag === "--environment") options.environment = value;
    else throw new Error(`Unknown option: ${flag}\n${usage()}`);
  }
  return { command, options };
}

function usage() {
  return "Usage: provision-universal-broker-v2-production.mjs status|apply --owner-instance-id ID [--state-dir ABS] [--identity-directory ABS] [--finalization-control ABS] [--environment PRODUCTION]";
}

if (process.argv[1] && pathToFileURL(resolve(process.argv[1])).href === import.meta.url) {
  try {
    const { command, options } = parseCli(process.argv.slice(2));
    const result = command === "status"
      ? inspectProductionProvisioning(options)
      : await provisionProductionState(options);
    process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
    if (command === "status" && result.status !== "READY") process.exitCode = 3;
  } catch (error) {
    console.error(error instanceof Error ? error.message : String(error));
    process.exitCode = 1;
  }
}
