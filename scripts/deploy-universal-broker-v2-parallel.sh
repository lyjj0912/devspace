#!/bin/bash
set -Eeuo pipefail
umask 077

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
RELEASE_PACKAGE=""
RUNTIME_ROOT="${DEVSPACE_RELEASE_RUNTIME_ROOT:-}"
BASE_ENVIRONMENT_FILE="${HOME:?HOME is required}/.devspace/universal-broker-v2-production.env"
ENVIRONMENT_FILE=""
IDENTITY_DIRECTORY="$HOME/.devspace/identity"
PROCESS_NAME="devspace-v2-candidate"
PORT="7679"
AUDIT=""
STATE_DIRECTORY=""
PUBLIC_BASE_URL=""
VERIFY_ONLY=0
CANONICAL_CONNECTOR_NAME="myDevSpace"
CONNECTOR_INSTALLATION_EPOCH="1"

usage() {
  echo "Usage: $0 --release-package DIR [--runtime-root DIR] [--base-environment-file FILE] [--environment-file FILE] [--identity-directory DIR] [--state-directory DIR] [--public-base-url URL] [--process-name NAME] [--port PORT] [--connector-name NAME] [--connector-installation-epoch N] [--audit DIR] [--verify-only]" >&2
}

while [[ "$#" -gt 0 ]]; do
  case "$1" in
    --release-package) RELEASE_PACKAGE="${2:-}"; shift 2 ;;
    --runtime-root) RUNTIME_ROOT="${2:-}"; shift 2 ;;
    --base-environment-file) BASE_ENVIRONMENT_FILE="${2:-}"; shift 2 ;;
    --environment-file) ENVIRONMENT_FILE="${2:-}"; shift 2 ;;
    --identity-directory) IDENTITY_DIRECTORY="${2:-}"; shift 2 ;;
    --state-directory) STATE_DIRECTORY="${2:-}"; shift 2 ;;
    --public-base-url) PUBLIC_BASE_URL="${2:-}"; shift 2 ;;
    --process-name) PROCESS_NAME="${2:-}"; shift 2 ;;
    --port) PORT="${2:-}"; shift 2 ;;
    --connector-name) CANONICAL_CONNECTOR_NAME="${2:-}"; shift 2 ;;
    --connector-installation-epoch) CONNECTOR_INSTALLATION_EPOCH="${2:-}"; shift 2 ;;
    --audit) AUDIT="${2:-}"; shift 2 ;;
    --verify-only) VERIFY_ONLY=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) usage; exit 2 ;;
  esac
done

[[ -n "$RELEASE_PACKAGE" && -d "$RELEASE_PACKAGE" ]] || { echo "--release-package must name an existing directory." >&2; exit 2; }
[[ "$PORT" =~ ^[0-9]+$ ]] && (( PORT > 0 && PORT < 65536 )) || { echo "Invalid candidate port: $PORT" >&2; exit 2; }
[[ "$PROCESS_NAME" =~ ^[A-Za-z0-9._-]+$ ]] || { echo "Invalid process name: $PROCESS_NAME" >&2; exit 2; }
[[ "$CANONICAL_CONNECTOR_NAME" =~ ^[A-Za-z][A-Za-z0-9._-]{0,127}$ ]] || { echo "Invalid canonical connector name." >&2; exit 2; }
[[ "$CONNECTOR_INSTALLATION_EPOCH" =~ ^[1-9][0-9]*$ ]] || { echo "Invalid connector installation epoch." >&2; exit 2; }
RELEASE_PACKAGE="$(cd "$RELEASE_PACKAGE" && pwd -P)"
RUNTIME_ROOT="${RUNTIME_ROOT:-$RELEASE_PACKAGE}"
[[ -d "$RUNTIME_ROOT" ]] || { echo "--runtime-root must name an existing directory." >&2; exit 2; }
RUNTIME_ROOT="$(cd "$RUNTIME_ROOT" && pwd -P)"
BASE_ENVIRONMENT_FILE="$(python3 -c 'import os,sys; print(os.path.abspath(os.path.expanduser(sys.argv[1])))' "$BASE_ENVIRONMENT_FILE")"
IDENTITY_DIRECTORY="$(python3 -c 'import os,sys; print(os.path.abspath(os.path.expanduser(sys.argv[1])))' "$IDENTITY_DIRECTORY")"
AUDIT="${AUDIT:-$HOME/.devspace/deployments/universal-broker-v2/parallel-$(date -u +%Y%m%dT%H%M%SZ)}"
mkdir -p "$AUDIT"
AUDIT="$(cd "$AUDIT" && pwd -P)"
chmod 700 "$AUDIT"
ENVIRONMENT_FILE="${ENVIRONMENT_FILE:-$AUDIT/parallel.env}"
ENVIRONMENT_FILE="$(python3 -c 'import os,sys; print(os.path.abspath(os.path.expanduser(sys.argv[1])))' "$ENVIRONMENT_FILE")"
STATE_DIRECTORY="${STATE_DIRECTORY:-$AUDIT/state}"
STATE_DIRECTORY="$(python3 -c 'import os,sys; print(os.path.abspath(os.path.expanduser(sys.argv[1])))' "$STATE_DIRECTORY")"
PUBLIC_BASE_URL="${PUBLIC_BASE_URL:-http://127.0.0.1:$PORT}"
if [[ "$ENVIRONMENT_FILE" == "$BASE_ENVIRONMENT_FILE" ]] \
  || { [[ -e "$ENVIRONMENT_FILE" && -e "$BASE_ENVIRONMENT_FILE" ]] && [[ "$ENVIRONMENT_FILE" -ef "$BASE_ENVIRONMENT_FILE" ]]; }; then
  echo "Parallel deployment refuses to overwrite the production environment file." >&2
  exit 2
fi

NODE="$(command -v node)" || { echo "Node.js is required." >&2; exit 1; }
NODE_MAJOR="$($NODE -p 'Number(process.versions.node.split(".")[0])')"
(( NODE_MAJOR >= 22 )) || { echo "Parallel deployment requires Node.js 22 or newer." >&2; exit 1; }

"$NODE" "$SCRIPT_DIR/release-artifacts.mjs" verify --package "$RELEASE_PACKAGE" >"$AUDIT/package-verification.json"
"$NODE" "$SCRIPT_DIR/release-artifacts.mjs" verify-runtime-tree \
  --package "$RELEASE_PACKAGE" --runtime-root "$RUNTIME_ROOT" >"$AUDIT/runtime-tree-verification.json"
MANIFEST="$RELEASE_PACKAGE/BUILD-MANIFEST.json"
IDENTITY_TSV="$("$NODE" -e '
const v=require(process.argv[1]);
process.stdout.write(["sourceRevision","runtimeRevision","buildDigest","schemaGeneration","authorityContractGeneration","configSchemaIdentity"].map(k=>v[k]).join("\t"));
' "$MANIFEST")"
IFS=$'\t' read -r SOURCE_REVISION RUNTIME_REVISION BUILD_DIGEST SCHEMA_GENERATION AUTHORITY_GENERATION CONFIG_SCHEMA_IDENTITY <<<"$IDENTITY_TSV"
OWNER_INSTANCE_ID="$($NODE "$SCRIPT_DIR/ensure-owner-instance-id.mjs" "$IDENTITY_DIRECTORY")"

if [[ "$VERIFY_ONLY" == 1 ]]; then
  "$NODE" -e '
const fs=require("node:fs"); const crypto=require("node:crypto");
const [path,owner]=process.argv.slice(1);
console.log(JSON.stringify({status:"VERIFIED",ownerInstanceId:owner,manifestSha256:`sha256:${crypto.createHash("sha256").update(fs.readFileSync(path)).digest("hex")}`},null,2));
' "$MANIFEST" "$OWNER_INSTANCE_ID"
  exit 0
fi

for command in pm2 curl; do command -v "$command" >/dev/null || { echo "Required command is unavailable: $command" >&2; exit 1; }; done
[[ -f "$BASE_ENVIRONMENT_FILE" ]] || { echo "Base environment file is unavailable: $BASE_ENVIRONMENT_FILE" >&2; exit 1; }
BASE_MODE="$(stat -f '%Lp' "$BASE_ENVIRONMENT_FILE" 2>/dev/null || stat -c '%a' "$BASE_ENVIRONMENT_FILE")"
[[ "$BASE_MODE" == 600 ]] || { echo "Base environment file must be mode 0600: $BASE_ENVIRONMENT_FILE ($BASE_MODE)" >&2; exit 1; }
EXISTING_PID="$(pm2 pid "$PROCESS_NAME" 2>/dev/null | tail -1 | tr -d '[:space:]')"
[[ -z "$EXISTING_PID" || "$EXISTING_PID" == 0 ]] || { echo "Parallel process already exists: $PROCESS_NAME" >&2; exit 1; }

mkdir -p "$(dirname "$ENVIRONMENT_FILE")"
mkdir -p "$STATE_DIRECTORY" "$STATE_DIRECTORY/config" "$STATE_DIRECTORY/oauth"
chmod 700 "$STATE_DIRECTORY" "$STATE_DIRECTORY/config" "$STATE_DIRECTORY/oauth"
ENVIRONMENT_NEXT="$AUDIT/environment.next"
ENVIRONMENT_SOURCE="$BASE_ENVIRONMENT_FILE"
if [[ -f "$ENVIRONMENT_FILE" ]]; then
  cp -p "$ENVIRONMENT_FILE" "$AUDIT/environment.before"
  ENVIRONMENT_SOURCE="$ENVIRONMENT_FILE"
fi
for candidate_environment in "$BASE_ENVIRONMENT_FILE" "$ENVIRONMENT_SOURCE"; do
  EXISTING_OWNER="$(/bin/bash -c 'set -a; source "$1"; printf "%s" "${DEVSPACE_NEXT_AUTHORITY_OWNER_INSTANCE_ID-}"' _ "$candidate_environment")"
  [[ -z "$EXISTING_OWNER" || "$EXISTING_OWNER" == "$OWNER_INSTANCE_ID" ]] || {
    echo "Existing ownerInstanceId differs from the provisioned stable identity: $candidate_environment" >&2
    exit 1
  }
done
python3 - "$ENVIRONMENT_SOURCE" "$ENVIRONMENT_NEXT" <<'PY'
import re,sys
source,target=sys.argv[1:]
managed={
  "DEVSPACE_V2_DEPLOYMENT_MODE","DEVSPACE_NEXT_HOST","DEVSPACE_NEXT_PORT","DEVSPACE_NEXT_MANAGEMENT_PORT",
  "DEVSPACE_NEXT_PUBLIC_BASE_URL","DEVSPACE_NEXT_MCP_PATH","DEVSPACE_NEXT_STATE_DIR","DEVSPACE_NEXT_OAUTH_STATE_DIR",
  "DEVSPACE_NEXT_TARGETS_FILE","DEVSPACE_NEXT_MCP_ROUTES_FILE","DEVSPACE_NEXT_ENV_PROFILE_CONFIG",
  "DEVSPACE_NEXT_CONTEXT_STORE","DEVSPACE_NEXT_CONTEXT_WORKTREE_ROOT","DEVSPACE_NEXT_PROCESS_OUTPUT_DIR",
  "DEVSPACE_NEXT_SELF_MANAGEMENT_DIR","DEVSPACE_NEXT_ARTIFACT_STAGING_DIR","DEVSPACE_NEXT_PM2_PROCESS_NAME",
  "DEVSPACE_NEXT_PM2_EXPECTED_SCRIPT","DEVSPACE_NEXT_AUTHORITY_STORE","DEVSPACE_NEXT_AUTHORITY_OWNER_INSTANCE_ID",
  "DEVSPACE_RELEASE_MANIFEST",
  "DEVSPACE_EXPECTED_SOURCE_REVISION","DEVSPACE_EXPECTED_RUNTIME_REVISION","DEVSPACE_EXPECTED_BUILD_DIGEST",
  "DEVSPACE_EXPECTED_SCHEMA_GENERATION","DEVSPACE_EXPECTED_AUTHORITY_CONTRACT_GENERATION","DEVSPACE_EXPECTED_CONFIG_SCHEMA_IDENTITY",
  "DEVSPACE_OAUTH_CANONICAL_CONNECTOR_NAME","DEVSPACE_OAUTH_CONNECTOR_INSTALLATION_EPOCH",
  "DEVSPACE_NEXT_CANONICAL_CONNECTOR_NAME","DEVSPACE_SOURCE_REVISION","DEVSPACE_RUNTIME_REVISION","DEVSPACE_BUILD_DIGEST",
}
pattern=re.compile(r"^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)=")
with open(target,"w",encoding="utf-8") as out:
  for line in open(source,encoding="utf-8"):
    match=pattern.match(line)
    if not match or match.group(1) not in managed: out.write(line)
PY
quote() { printf '%q' "$1"; }
START_SCRIPT="$RUNTIME_ROOT/scripts/start-universal-broker-v2-production.sh"
[[ -f "$START_SCRIPT" ]] || { echo "Runtime production start script is missing: $START_SCRIPT" >&2; exit 1; }
{
  printf 'DEVSPACE_V2_DEPLOYMENT_MODE=%s\n' "$(quote parallel)"
  printf 'DEVSPACE_NEXT_HOST=%s\n' "$(quote 127.0.0.1)"
  printf 'DEVSPACE_NEXT_PORT=%s\n' "$(quote "$PORT")"
  if (( PORT <= 64535 )); then
    printf 'DEVSPACE_NEXT_MANAGEMENT_PORT=%s\n' "$(quote "$((PORT + 1000))")"
  else
    printf 'DEVSPACE_NEXT_MANAGEMENT_PORT=%s\n' "$(quote "$((PORT - 1000))")"
  fi
  printf 'DEVSPACE_NEXT_PUBLIC_BASE_URL=%s\n' "$(quote "$PUBLIC_BASE_URL")"
  printf 'DEVSPACE_NEXT_MCP_PATH=%s\n' "$(quote /mcp-next)"
  printf 'DEVSPACE_NEXT_STATE_DIR=%s\n' "$(quote "$STATE_DIRECTORY")"
  printf 'DEVSPACE_NEXT_OAUTH_STATE_DIR=%s\n' "$(quote "$STATE_DIRECTORY/oauth")"
  printf 'DEVSPACE_NEXT_TARGETS_FILE=%s\n' "$(quote "$STATE_DIRECTORY/config/targets.json")"
  printf 'DEVSPACE_NEXT_MCP_ROUTES_FILE=%s\n' "$(quote "$STATE_DIRECTORY/config/mcp-routes.json")"
  printf 'DEVSPACE_NEXT_ENV_PROFILE_CONFIG=%s\n' "$(quote "$STATE_DIRECTORY/config/env-profiles.json")"
  printf 'DEVSPACE_NEXT_CONTEXT_STORE=%s\n' "$(quote "$STATE_DIRECTORY/contexts.json")"
  printf 'DEVSPACE_NEXT_CONTEXT_WORKTREE_ROOT=%s\n' "$(quote "$STATE_DIRECTORY/worktrees")"
  printf 'DEVSPACE_NEXT_PROCESS_OUTPUT_DIR=%s\n' "$(quote "$STATE_DIRECTORY/process-output")"
  printf 'DEVSPACE_NEXT_SELF_MANAGEMENT_DIR=%s\n' "$(quote "$STATE_DIRECTORY/self-management")"
  printf 'DEVSPACE_NEXT_ARTIFACT_STAGING_DIR=%s\n' "$(quote "$STATE_DIRECTORY/artifacts")"
  printf 'DEVSPACE_NEXT_PM2_PROCESS_NAME=%s\n' "$(quote "$PROCESS_NAME")"
  printf 'DEVSPACE_NEXT_PM2_EXPECTED_SCRIPT=%s\n' "$(quote "$START_SCRIPT")"
  printf 'DEVSPACE_NEXT_AUTHORITY_STORE=%s\n' "$(quote "$STATE_DIRECTORY/authority.sqlite")"
  printf 'DEVSPACE_NEXT_AUTHORITY_OWNER_INSTANCE_ID=%s\n' "$(quote "$OWNER_INSTANCE_ID")"
  printf 'DEVSPACE_RELEASE_MANIFEST=%s\n' "$(quote "$MANIFEST")"
  printf 'DEVSPACE_EXPECTED_SOURCE_REVISION=%s\n' "$(quote "$SOURCE_REVISION")"
  printf 'DEVSPACE_EXPECTED_RUNTIME_REVISION=%s\n' "$(quote "$RUNTIME_REVISION")"
  printf 'DEVSPACE_EXPECTED_BUILD_DIGEST=%s\n' "$(quote "$BUILD_DIGEST")"
  printf 'DEVSPACE_EXPECTED_SCHEMA_GENERATION=%s\n' "$(quote "$SCHEMA_GENERATION")"
  printf 'DEVSPACE_EXPECTED_AUTHORITY_CONTRACT_GENERATION=%s\n' "$(quote "$AUTHORITY_GENERATION")"
  printf 'DEVSPACE_EXPECTED_CONFIG_SCHEMA_IDENTITY=%s\n' "$(quote "$CONFIG_SCHEMA_IDENTITY")"
  printf 'DEVSPACE_OAUTH_CANONICAL_CONNECTOR_NAME=%s\n' "$(quote "$CANONICAL_CONNECTOR_NAME")"
  printf 'DEVSPACE_OAUTH_CONNECTOR_INSTALLATION_EPOCH=%s\n' "$(quote "$CONNECTOR_INSTALLATION_EPOCH")"
  printf 'DEVSPACE_NEXT_CANONICAL_CONNECTOR_NAME=%s\n' "$(quote "$CANONICAL_CONNECTOR_NAME")"
  printf 'DEVSPACE_SOURCE_REVISION=%s\n' "$(quote "$SOURCE_REVISION")"
  printf 'DEVSPACE_RUNTIME_REVISION=%s\n' "$(quote "$RUNTIME_REVISION")"
  printf 'DEVSPACE_BUILD_DIGEST=%s\n' "$(quote "$BUILD_DIGEST")"
} >>"$ENVIRONMENT_NEXT"
chmod 600 "$ENVIRONMENT_NEXT"

cp -p "$ENVIRONMENT_NEXT" "$ENVIRONMENT_FILE.next"
mv -f "$ENVIRONMENT_FILE.next" "$ENVIRONMENT_FILE"
STARTED=0
rollback() {
  local rc="$?"
  trap - ERR INT TERM
  if [[ "$STARTED" == 1 ]]; then pm2 delete "$PROCESS_NAME" >/dev/null 2>&1 || true; pm2 save >/dev/null 2>&1 || true; fi
  exit "$rc"
}
trap rollback ERR INT TERM
DEVSPACE_PRODUCTION_ENV_FILE="$ENVIRONMENT_FILE" pm2 start "$START_SCRIPT" \
  --name "$PROCESS_NAME" --interpreter /bin/bash --cwd "$RUNTIME_ROOT" --time >"$AUDIT/pm2-start.log" 2>&1
STARTED=1

HEALTH_URL="http://127.0.0.1:$PORT/healthz-next"
for _ in $(seq 1 120); do
  if curl --fail --silent --show-error --max-time 5 "$HEALTH_URL" >"$AUDIT/gateway-identity.json" 2>/dev/null; then break; fi
  sleep 0.5
done
curl --fail --silent --show-error --max-time 5 "$HEALTH_URL" >"$AUDIT/gateway-identity.json"
"$NODE" "$SCRIPT_DIR/release-artifacts.mjs" verify-gateway \
  --package "$RELEASE_PACKAGE" --identity "$AUDIT/gateway-identity.json" >"$AUDIT/gateway-verification.json"
if (( PORT <= 64535 )); then MANAGEMENT_PORT="$((PORT + 1000))"; else MANAGEMENT_PORT="$((PORT - 1000))"; fi
curl --fail --silent --show-error --max-time 5 "http://127.0.0.1:$MANAGEMENT_PORT/readyz" >"$AUDIT/runtime-identity.json"
"$NODE" "$SCRIPT_DIR/release-artifacts.mjs" verify-runtime \
  --package "$RELEASE_PACKAGE" --identity "$AUDIT/runtime-identity.json" >"$AUDIT/runtime-verification.json"
pm2 jlist >"$AUDIT/pm2-readback.json"
python3 - "$AUDIT/pm2-readback.json" "$PROCESS_NAME" "$RUNTIME_ROOT" "$START_SCRIPT" <<'PY'
import json,os,sys
path,name,cwd,script=sys.argv[1:]
items=json.load(open(path))
match=next((item for item in items if item.get("name")==name),None)
if not match: raise SystemExit("parallel process missing from PM2 readback")
env=match.get("pm2_env") or {}
if env.get("status")!="online": raise SystemExit("parallel process is not online")
if os.path.realpath(env.get("pm_cwd", ""))!=os.path.realpath(cwd): raise SystemExit("parallel process cwd is not the verified runtime root")
if os.path.realpath(env.get("pm_exec_path", ""))!=os.path.realpath(script): raise SystemExit("parallel process entrypoint is not the verified runtime root")
PY
pm2 save >"$AUDIT/pm2-save.log" 2>&1
trap - ERR INT TERM
"$NODE" - "$MANIFEST" "$AUDIT/deployment.json" "$PROCESS_NAME" "$PORT" "$RUNTIME_ROOT" <<'NODE'
const fs=require("node:fs"); const crypto=require("node:crypto");
const [manifestPath,output,processName,port,runtimeRoot]=process.argv.slice(2); const manifest=JSON.parse(fs.readFileSync(manifestPath));
const result={status:"STAGING_ONLINE",processName,port:Number(port),runtimeRoot,sourceRevision:manifest.sourceRevision,runtimeRevision:manifest.runtimeRevision,buildDigest:manifest.buildDigest,manifestSha256:`sha256:${crypto.createHash("sha256").update(fs.readFileSync(manifestPath)).digest("hex")}`};
fs.writeFileSync(output,JSON.stringify(result,null,2)+"\n",{mode:0o600}); console.log(JSON.stringify(result,null,2));
NODE
