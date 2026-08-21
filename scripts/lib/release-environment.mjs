import {
  closeSync,
  fsyncSync,
  openSync,
  readFileSync,
  renameSync,
  unlinkSync,
  writeFileSync,
} from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

export const RUNTIME_STATE_PATH_KEYS = Object.freeze([
  "DEVSPACE_NEXT_AUTHORITY_STATE_DIR",
  "DEVSPACE_NEXT_AUTHORITY_STORE",
  "DEVSPACE_NEXT_CONNECTOR_ACTIVATION_JOURNAL",
  "DEVSPACE_NEXT_LIFECYCLE_FINALIZATION_STORE",
  "DEVSPACE_NEXT_CONTEXT_STORE",
  "DEVSPACE_NEXT_CONTEXT_WORKTREE_ROOT",
  "DEVSPACE_NEXT_PROCESS_OUTPUT_DIR",
  "DEVSPACE_NEXT_SSH_CONTROL_DIR",
  "DEVSPACE_NEXT_ARTIFACT_STAGING_DIR",
  "DEVSPACE_NEXT_ARTIFACT_CATALOG",
  "DEVSPACE_NEXT_ARTIFACT_OBJECT_ROOT",
  "DEVSPACE_NEXT_AUDIT_SINK",
  "DEVSPACE_NEXT_CURSOR_SIGNING_KEY_REF",
  "DEVSPACE_NEXT_CURSOR_PREVIOUS_SIGNING_KEY_REF",
  "DEVSPACE_NEXT_MANAGEMENT_AUTHORIZATION_KEY_REF",
]);

export const RETIRED_RELEASE_ENVIRONMENT_KEYS = Object.freeze([
  // Removed after Personal readiness stopped accepting legacy connector state.
  // The materializer still strips it from older owner files but never permits a new value.
  "DEVSPACE_PERSONAL_STAGING_FIXTURE",
]);

export const MANAGED_RELEASE_ENVIRONMENT_KEYS = Object.freeze([
  "DEVSPACE_V2_DEPLOYMENT_MODE",
  "DEVSPACE_V2_LEGACY_SCOPE_COMPATIBILITY",
  "DEVSPACE_NEXT_HOST",
  "DEVSPACE_NEXT_PORT",
  "DEVSPACE_NEXT_MANAGEMENT_PORT",
  "DEVSPACE_NEXT_PUBLIC_BASE_URL",
  "DEVSPACE_NEXT_MCP_PATH",
  "DEVSPACE_NEXT_STATE_DIR",
  "DEVSPACE_NEXT_OAUTH_STATE_DIR",
  "DEVSPACE_NEXT_TARGETS_FILE",
  "DEVSPACE_NEXT_MCP_ROUTES_FILE",
  "DEVSPACE_NEXT_ENV_PROFILE_CONFIG",
  "DEVSPACE_NEXT_SELF_MANAGEMENT_DIR",
  "DEVSPACE_NEXT_PM2_PROCESS_NAME",
  "DEVSPACE_NEXT_PM2_EXPECTED_SCRIPT",
  "DEVSPACE_NEXT_SELF_RESTART_DELAY_MS",
  "DEVSPACE_NEXT_SELF_RESTART_TIMEOUT_MS",
  "DEVSPACE_NEXT_ALLOWED_HOSTS",
  "DEVSPACE_TRUST_PROXY",
  "DEVSPACE_NEXT_AUTHORITY_OWNER_INSTANCE_ID",
  "DEVSPACE_OAUTH_OWNER_INSTANCE_ID",
  "DEVSPACE_NEXT_ACCEPTANCE_RUN_ID",
  "DEVSPACE_RELEASE_MANIFEST",
  "DEVSPACE_EXPECTED_RELEASE_MANIFEST_SHA256",
  "DEVSPACE_EXPECTED_SOURCE_REVISION",
  "DEVSPACE_EXPECTED_RUNTIME_REVISION",
  "DEVSPACE_EXPECTED_BUILD_DIGEST",
  "DEVSPACE_EXPECTED_SCHEMA_GENERATION",
  "DEVSPACE_EXPECTED_AUTHORITY_CONTRACT_GENERATION",
  "DEVSPACE_EXPECTED_CONFIG_SCHEMA_IDENTITY",
  "DEVSPACE_RUNTIME_PACKAGE_ROOT",
  "DEVSPACE_RUNTIME_DEPENDENCY_ROOT",
  "DEVSPACE_RUNTIME_DEPENDENCY_EVIDENCE",
  "DEVSPACE_EXPECTED_RUNTIME_DEPENDENCY_EVIDENCE_SHA256",
  "DEVSPACE_OAUTH_CANONICAL_CONNECTOR_NAME",
  "DEVSPACE_OAUTH_CONNECTOR_INSTALLATION_EPOCH",
  "DEVSPACE_NEXT_CANONICAL_CONNECTOR_NAME",
  "DEVSPACE_SOURCE_REVISION",
  "DEVSPACE_RUNTIME_REVISION",
  "DEVSPACE_BUILD_DIGEST",
  ...RUNTIME_STATE_PATH_KEYS,
  "DEVSPACE_NEXT_LIFECYCLE_FINALIZATION_CONTROL",
]);

const MANAGED = new Set(MANAGED_RELEASE_ENVIRONMENT_KEYS);
const STRIPPED = new Set([
  ...MANAGED_RELEASE_ENVIRONMENT_KEYS,
  ...RETIRED_RELEASE_ENVIRONMENT_KEYS,
]);
const ASSIGNMENT = /^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)=/u;

export function materializeReleaseEnvironment(options) {
  const sourcePath = resolve(requiredText(options?.sourcePath, "sourcePath"));
  const destinationPath = resolve(requiredText(options?.destinationPath, "destinationPath"));
  if (sourcePath === destinationPath) throw new Error("Release environment source and destination must differ.");
  const values = options?.values;
  if (!values || typeof values !== "object" || Array.isArray(values)) {
    throw new Error("Release environment values must be an object.");
  }
  const entries = Object.entries(values);
  for (const [key, value] of entries) {
    if (!MANAGED.has(key)) throw new Error(`Release environment key is not managed: ${key}`);
    if (typeof value !== "string" || /[\0\r\n]/u.test(value)) {
      throw new Error(`Release environment value is invalid: ${key}`);
    }
  }
  const kept = readFileSync(sourcePath, "utf8")
    .split("\n")
    .filter((line) => {
      const match = ASSIGNMENT.exec(line);
      return !match || !STRIPPED.has(match[1]);
    });
  while (kept.length > 0 && kept.at(-1) === "") kept.pop();
  const body = [
    ...(kept.length > 0 ? [...kept, ""] : []),
    "# Managed Universal Broker v2.1 runtime values.",
    ...entries.map(([key, value]) => `${key}=${shellQuote(value)}`),
    "",
  ].join("\n");
  writeAtomic(destinationPath, body);
  return Object.freeze({ destinationPath, keys: entries.map(([key]) => key) });
}

function writeAtomic(path, value) {
  const temporary = `${path}.tmp-${process.pid}-${Date.now()}`;
  let descriptor;
  try {
    descriptor = openSync(temporary, "wx", 0o600);
    writeFileSync(descriptor, value, "utf8");
    fsyncSync(descriptor);
    closeSync(descriptor);
    descriptor = undefined;
    renameSync(temporary, path);
    fsyncDirectory(dirname(path));
  } finally {
    if (descriptor !== undefined) closeSync(descriptor);
    try { unlinkSync(temporary); } catch (error) { if (error?.code !== "ENOENT") throw error; }
  }
}

function fsyncDirectory(path) {
  let descriptor;
  try {
    descriptor = openSync(path, "r");
    fsyncSync(descriptor);
  } catch (error) {
    if (!new Set(["EINVAL", "ENOTSUP", "EISDIR", "EPERM"]).has(error?.code)) throw error;
  } finally {
    if (descriptor !== undefined) closeSync(descriptor);
  }
}

function shellQuote(value) {
  return `'${value.replaceAll("'", `'"'"'`)}'`;
}

function requiredText(value, name) {
  if (typeof value !== "string" || value.length === 0 || /[\0\r\n]/u.test(value)) {
    throw new Error(`Release environment ${name} is missing or invalid.`);
  }
  return value;
}

function parseCli(values) {
  const options = { values: {} };
  for (let index = 0; index < values.length;) {
    const flag = values[index++];
    if (flag === "--source") options.sourcePath = values[index++];
    else if (flag === "--destination") options.destinationPath = values[index++];
    else if (flag === "--set") {
      const key = values[index++];
      const value = values[index++];
      if (!key || value === undefined || Object.hasOwn(options.values, key)) {
        throw new Error(`Invalid or duplicate --set value: ${key ?? "missing"}`);
      }
      options.values[key] = value;
    } else throw new Error(`Unknown release environment option: ${flag ?? "missing"}`);
  }
  return options;
}

if (process.argv[1] && resolve(process.argv[1]) === resolve(fileURLToPath(import.meta.url))) {
  try {
    const [command, ...arguments_] = process.argv.slice(2);
    if (command !== "materialize") throw new Error("Usage: release-environment.mjs materialize --source PATH --destination PATH --set KEY VALUE [...]");
    console.log(JSON.stringify(materializeReleaseEnvironment(parseCli(arguments_))));
  } catch (error) {
    console.error(error instanceof Error ? error.message : String(error));
    process.exitCode = 1;
  }
}
