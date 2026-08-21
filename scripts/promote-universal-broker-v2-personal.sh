#!/bin/bash
set -Eeuo pipefail
umask 077

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
RELEASE_PACKAGE=""
DEPENDENCY_ROOT=""
DEPENDENCY_EVIDENCE=""
CANDIDATE_PROCESS=""
PRODUCTION_PROCESS="devspace-v2-production"
PRODUCTION_ENV="$HOME/.devspace/universal-broker-v2-production.env"
AUDIT=""
ALLOW_UNATTESTED_STAGING=0
VERIFY_ONLY=0

usage() {
  echo "Usage: $0 --release-package DIR --dependency-root DIR --dependency-evidence FILE --candidate-process NAME [--production-process NAME] [--production-env FILE] [--audit DIR] [--staging-fixture] [--verify-only]" >&2
}

while [[ "$#" -gt 0 ]]; do
  case "$1" in
    --release-package) RELEASE_PACKAGE="${2:-}"; shift 2 ;;
    --dependency-root) DEPENDENCY_ROOT="${2:-}"; shift 2 ;;
    --dependency-evidence) DEPENDENCY_EVIDENCE="${2:-}"; shift 2 ;;
    --candidate-process) CANDIDATE_PROCESS="${2:-}"; shift 2 ;;
    --production-process) PRODUCTION_PROCESS="${2:-}"; shift 2 ;;
    --production-env) PRODUCTION_ENV="${2:-}"; shift 2 ;;
    --audit) AUDIT="${2:-}"; shift 2 ;;
    --staging-fixture) ALLOW_UNATTESTED_STAGING=1; shift ;;
    --verify-only) VERIFY_ONLY=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) usage; exit 2 ;;
  esac
done

for value in "$CANDIDATE_PROCESS" "$PRODUCTION_PROCESS"; do
  [[ "$value" =~ ^[A-Za-z0-9._-]+$ ]] || { echo "Invalid PM2 process name: $value" >&2; exit 2; }
done
for path in "$RELEASE_PACKAGE" "$DEPENDENCY_ROOT"; do
  [[ -n "$path" && -d "$path" ]] || { echo "Required directory is unavailable: $path" >&2; exit 2; }
done
[[ -f "$DEPENDENCY_EVIDENCE" ]] || { echo "Dependency evidence is unavailable: $DEPENDENCY_EVIDENCE" >&2; exit 2; }
[[ -f "$PRODUCTION_ENV" ]] || { echo "Production environment is unavailable: $PRODUCTION_ENV" >&2; exit 2; }
[[ "$(stat -f '%Lp' "$PRODUCTION_ENV" 2>/dev/null || stat -c '%a' "$PRODUCTION_ENV")" == 600 ]] || {
  echo "Production environment must be mode 0600." >&2
  exit 2
}

for command in node pm2 curl python3 sqlite3 shasum; do
  command -v "$command" >/dev/null || { echo "Required command is unavailable: $command" >&2; exit 1; }
done
(( $(node -p 'Number(process.versions.node.split(".")[0])') >= 22 )) || {
  echo "Personal promotion requires Node.js 22 or newer." >&2
  exit 1
}

RELEASE_PACKAGE="$(cd "$RELEASE_PACKAGE" && pwd -P)"
DEPENDENCY_ROOT="$(cd "$DEPENDENCY_ROOT" && pwd -P)"
DEPENDENCY_EVIDENCE="$(cd "$(dirname "$DEPENDENCY_EVIDENCE")" && pwd -P)/$(basename "$DEPENDENCY_EVIDENCE")"
PRODUCTION_ENV="$(cd "$(dirname "$PRODUCTION_ENV")" && pwd -P)/$(basename "$PRODUCTION_ENV")"
MANIFEST="$RELEASE_PACKAGE/BUILD-MANIFEST.json"
START_SCRIPT="$RELEASE_PACKAGE/scripts/start-universal-broker-v2-production.sh"
[[ -f "$MANIFEST" && -f "$START_SCRIPT" ]] || { echo "Release runtime is incomplete." >&2; exit 1; }

release_artifacts() {
  if [[ "$ALLOW_UNATTESTED_STAGING" == 1 ]]; then
    node "$SCRIPT_DIR/release-artifacts.mjs" "$@" --staging-fixture true
  else
    node "$SCRIPT_DIR/release-artifacts.mjs" "$@"
  fi
}
release_artifacts verify --package "$RELEASE_PACKAGE" >/dev/null
EVIDENCE_SHA="sha256:$(shasum -a 256 "$DEPENDENCY_EVIDENCE" | awk '{print $1}')"
release_artifacts verify-runtime-dependencies \
  --package "$RELEASE_PACKAGE" --dependency-root "$DEPENDENCY_ROOT" \
  --evidence "$DEPENDENCY_EVIDENCE" --evidence-sha256 "$EVIDENCE_SHA" >/dev/null

IDENTITY_JSON="$(node - "$MANIFEST" <<'NODE'
const value=require(process.argv[2]);
const crypto=require("node:crypto"),fs=require("node:fs");
process.stdout.write(JSON.stringify({
  sourceRevision:value.sourceRevision,
  runtimeRevision:value.runtimeRevision,
  buildDigest:value.buildDigest,
  schemaGeneration:value.schemaGeneration,
  authorityContractGeneration:value.authorityContractGeneration,
  configSchemaIdentity:value.configSchemaIdentity,
  manifestSha256:`sha256:${crypto.createHash("sha256").update(fs.readFileSync(process.argv[2])).digest("hex")}`,
}));
NODE
)"
RUNTIME_REVISION="$(python3 -c 'import json,sys; print(json.loads(sys.argv[1])["runtimeRevision"])' "$IDENTITY_JSON")"
AUDIT="${AUDIT:-$HOME/.devspace/deployments/universal-broker-v2/personal-promotion-${RUNTIME_REVISION}-$(date -u +%Y%m%dT%H%M%SZ)}"
mkdir -p "$AUDIT"
AUDIT="$(cd "$AUDIT" && pwd -P)"
chmod 700 "$AUDIT"

pm2 jlist >"$AUDIT/pm2.before.json"
python3 - "$AUDIT/pm2.before.json" "$PRODUCTION_PROCESS" "$CANDIDATE_PROCESS" "$RELEASE_PACKAGE" <<'PY' >"$AUDIT/processes.tsv"
import json,os,sys
path,production,candidate,release=sys.argv[1:]
items=json.load(open(path,encoding="utf-8"))
def one(name):
    found=[item for item in items if item.get("name")==name]
    if len(found)!=1: raise SystemExit(f"PM2 process count is not one for {name}: {len(found)}")
    env=found[0].get("pm2_env") or {}
    if env.get("status")!="online": raise SystemExit(f"PM2 process is not online: {name}")
    return env
old=one(production); staged=one(candidate)
if os.path.realpath(staged.get("pm_cwd", ""))!=os.path.realpath(release):
    raise SystemExit("Candidate cwd is not the verified release package")
print("\t".join([old.get("pm_cwd", ""),old.get("pm_exec_path", ""),staged.get("pm_cwd", ""),staged.get("pm_exec_path", "")]))
PY
IFS=$'\t' read -r OLD_CWD OLD_SCRIPT _CANDIDATE_CWD _CANDIDATE_SCRIPT <"$AUDIT/processes.tsv"
[[ -d "$OLD_CWD" && -f "$OLD_SCRIPT" ]] || { echo "Previous immutable runtime is unavailable." >&2; exit 1; }

ENVIRONMENT_JSON="$(/bin/bash -c '
set -a; source "$1"; set +a
python3 - <<"PY"
import json,os
keys=["DEVSPACE_NEXT_STATE_DIR","DEVSPACE_NEXT_OAUTH_STATE_DIR","DEVSPACE_NEXT_TARGETS_FILE","DEVSPACE_NEXT_MCP_ROUTES_FILE","DEVSPACE_NEXT_ENV_PROFILE_CONFIG","DEVSPACE_NEXT_PUBLIC_BASE_URL","DEVSPACE_NEXT_ALLOWED_HOSTS","DEVSPACE_NEXT_AUTHORITY_OWNER_INSTANCE_ID","DEVSPACE_OAUTH_CANONICAL_CONNECTOR_NAME","DEVSPACE_OAUTH_CONNECTOR_INSTALLATION_EPOCH"]
print(json.dumps({key:os.environ.get(key,"") for key in keys}))
PY
' _ "$PRODUCTION_ENV")"
env_value() { python3 -c 'import json,sys; print(json.loads(sys.argv[1]).get(sys.argv[2],""))' "$ENVIRONMENT_JSON" "$1"; }
STATE_DIR="$(env_value DEVSPACE_NEXT_STATE_DIR)"
OAUTH_STATE_DIR="$(env_value DEVSPACE_NEXT_OAUTH_STATE_DIR)"
TARGETS_FILE="$(env_value DEVSPACE_NEXT_TARGETS_FILE)"
ROUTES_FILE="$(env_value DEVSPACE_NEXT_MCP_ROUTES_FILE)"
PROFILES_FILE="$(env_value DEVSPACE_NEXT_ENV_PROFILE_CONFIG)"
PUBLIC_BASE_URL="$(env_value DEVSPACE_NEXT_PUBLIC_BASE_URL)"
ALLOWED_HOSTS="$(env_value DEVSPACE_NEXT_ALLOWED_HOSTS)"
OWNER_INSTANCE_ID="$(env_value DEVSPACE_NEXT_AUTHORITY_OWNER_INSTANCE_ID)"
CONNECTOR_NAME="$(env_value DEVSPACE_OAUTH_CANONICAL_CONNECTOR_NAME)"
CONNECTOR_EPOCH="$(env_value DEVSPACE_OAUTH_CONNECTOR_INSTALLATION_EPOCH)"
[[ -d "$STATE_DIR" && -d "$OAUTH_STATE_DIR" && -f "$OAUTH_STATE_DIR/devspace.sqlite" ]] || {
  echo "Existing production state/OAuth database is unavailable." >&2
  exit 1
}
for value in "$TARGETS_FILE" "$ROUTES_FILE" "$PROFILES_FILE"; do [[ -f "$value" ]] || { echo "Production configuration is unavailable: $value" >&2; exit 1; }; done
[[ "$PUBLIC_BASE_URL" == https://* && -n "$OWNER_INSTANCE_ID" && -n "$CONNECTOR_NAME" && "$CONNECTOR_EPOCH" =~ ^[1-9][0-9]*$ ]] || {
  echo "Existing production identity is incomplete." >&2
  exit 1
}
CONTROL_DIR="$(dirname "$STATE_DIR")/$(basename "$STATE_DIR")-finalization-control"
CONTROL_PATH="$CONTROL_DIR/lifecycle-finalization-head.json"
[[ -d "$CONTROL_DIR" && -f "$CONTROL_PATH" ]] || { echo "Finalization control preimage is unavailable." >&2; exit 1; }

READY_URL="http://127.0.0.1:8679/readyz"
curl -fsS --max-time 5 "$READY_URL" >"$AUDIT/candidate-ready.json"
release_artifacts verify-runtime --package "$RELEASE_PACKAGE" --identity "$AUDIT/candidate-ready.json" >/dev/null
python3 - "$AUDIT/candidate-ready.json" <<'PY'
import json,sys
value=json.load(open(sys.argv[1]))
if value.get("status")!="ready" or value.get("httpStatus")!=200: raise SystemExit("Candidate is not ready")
if any(check.get("state")!="PASS" for check in value.get("checks",[])): raise SystemExit("Candidate readiness contains a non-PASS check")
PY

cp -p "$PRODUCTION_ENV" "$AUDIT/production.env.before"
shasum -a 256 "$PRODUCTION_ENV" >"$AUDIT/production.env.before.sha256"
if command -v tailscale >/dev/null; then tailscale funnel status --json >"$AUDIT/funnel.before.json"; fi

ENV_NEXT="$AUDIT/production.env.next"
mapfile_args=(
  --source "$PRODUCTION_ENV" --destination "$ENV_NEXT"
  --set DEVSPACE_V2_DEPLOYMENT_MODE production
  --set DEVSPACE_NEXT_HOST 127.0.0.1
  --set DEVSPACE_NEXT_PORT 7678
  --set DEVSPACE_NEXT_MANAGEMENT_PORT 8678
  --set DEVSPACE_NEXT_PUBLIC_BASE_URL "$PUBLIC_BASE_URL"
  --set DEVSPACE_NEXT_MCP_PATH /mcp
  --set DEVSPACE_NEXT_STATE_DIR "$STATE_DIR"
  --set DEVSPACE_NEXT_OAUTH_STATE_DIR "$OAUTH_STATE_DIR"
  --set DEVSPACE_NEXT_TARGETS_FILE "$TARGETS_FILE"
  --set DEVSPACE_NEXT_MCP_ROUTES_FILE "$ROUTES_FILE"
  --set DEVSPACE_NEXT_ENV_PROFILE_CONFIG "$PROFILES_FILE"
  --set DEVSPACE_NEXT_SELF_MANAGEMENT_DIR "$STATE_DIR/self-management"
  --set DEVSPACE_NEXT_PM2_PROCESS_NAME "$PRODUCTION_PROCESS"
  --set DEVSPACE_NEXT_PM2_EXPECTED_SCRIPT "$START_SCRIPT"
  --set DEVSPACE_NEXT_SELF_RESTART_TIMEOUT_MS 120000
  --set DEVSPACE_NEXT_ALLOWED_HOSTS "$ALLOWED_HOSTS"
  --set DEVSPACE_TRUST_PROXY 1
  --set DEVSPACE_NEXT_AUTHORITY_OWNER_INSTANCE_ID "$OWNER_INSTANCE_ID"
  --set DEVSPACE_RELEASE_MANIFEST "$MANIFEST"
  --set DEVSPACE_EXPECTED_RELEASE_MANIFEST_SHA256 "$(python3 -c 'import json,sys; print(json.loads(sys.argv[1])["manifestSha256"])' "$IDENTITY_JSON")"
  --set DEVSPACE_EXPECTED_SOURCE_REVISION "$(python3 -c 'import json,sys; print(json.loads(sys.argv[1])["sourceRevision"])' "$IDENTITY_JSON")"
  --set DEVSPACE_EXPECTED_RUNTIME_REVISION "$RUNTIME_REVISION"
  --set DEVSPACE_EXPECTED_BUILD_DIGEST "$(python3 -c 'import json,sys; print(json.loads(sys.argv[1])["buildDigest"])' "$IDENTITY_JSON")"
  --set DEVSPACE_EXPECTED_SCHEMA_GENERATION "$(python3 -c 'import json,sys; print(json.loads(sys.argv[1])["schemaGeneration"])' "$IDENTITY_JSON")"
  --set DEVSPACE_EXPECTED_AUTHORITY_CONTRACT_GENERATION "$(python3 -c 'import json,sys; print(json.loads(sys.argv[1])["authorityContractGeneration"])' "$IDENTITY_JSON")"
  --set DEVSPACE_EXPECTED_CONFIG_SCHEMA_IDENTITY "$(python3 -c 'import json,sys; print(json.loads(sys.argv[1])["configSchemaIdentity"])' "$IDENTITY_JSON")"
  --set DEVSPACE_RUNTIME_PACKAGE_ROOT "$RELEASE_PACKAGE"
  --set DEVSPACE_RUNTIME_DEPENDENCY_ROOT "$DEPENDENCY_ROOT"
  --set DEVSPACE_RUNTIME_DEPENDENCY_EVIDENCE "$DEPENDENCY_EVIDENCE"
  --set DEVSPACE_EXPECTED_RUNTIME_DEPENDENCY_EVIDENCE_SHA256 "$EVIDENCE_SHA"
  --set DEVSPACE_PERSONAL_STAGING_FIXTURE 1
  --set DEVSPACE_OAUTH_CANONICAL_CONNECTOR_NAME "$CONNECTOR_NAME"
  --set DEVSPACE_OAUTH_CONNECTOR_INSTALLATION_EPOCH "$CONNECTOR_EPOCH"
  --set DEVSPACE_NEXT_CANONICAL_CONNECTOR_NAME "$CONNECTOR_NAME"
  --set DEVSPACE_SOURCE_REVISION "$(python3 -c 'import json,sys; print(json.loads(sys.argv[1])["sourceRevision"])' "$IDENTITY_JSON")"
  --set DEVSPACE_RUNTIME_REVISION "$RUNTIME_REVISION"
  --set DEVSPACE_BUILD_DIGEST "$(python3 -c 'import json,sys; print(json.loads(sys.argv[1])["buildDigest"])' "$IDENTITY_JSON")"
  --set DEVSPACE_NEXT_AUTHORITY_STATE_DIR "$STATE_DIR/authority-state"
  --set DEVSPACE_NEXT_AUTHORITY_STORE "$STATE_DIR/authority.sqlite"
  --set DEVSPACE_NEXT_CONNECTOR_ACTIVATION_JOURNAL "$STATE_DIR/connector-activation-journal.sqlite"
  --set DEVSPACE_NEXT_LIFECYCLE_FINALIZATION_STORE "$STATE_DIR/lifecycle.sqlite"
  --set DEVSPACE_NEXT_LIFECYCLE_FINALIZATION_CONTROL "$CONTROL_PATH"
  --set DEVSPACE_NEXT_CONTEXT_STORE "$STATE_DIR/contexts.json"
  --set DEVSPACE_NEXT_CONTEXT_WORKTREE_ROOT "$STATE_DIR/worktrees"
  --set DEVSPACE_NEXT_PROCESS_OUTPUT_DIR "$STATE_DIR/process-output"
  --set DEVSPACE_NEXT_SSH_CONTROL_DIR "$STATE_DIR/ssh-control"
  --set DEVSPACE_NEXT_ARTIFACT_STAGING_DIR "$STATE_DIR/artifacts"
  --set DEVSPACE_NEXT_ARTIFACT_CATALOG "$STATE_DIR/artifacts.sqlite"
  --set DEVSPACE_NEXT_ARTIFACT_OBJECT_ROOT "$STATE_DIR/artifact-objects"
  --set DEVSPACE_NEXT_AUDIT_SINK "$STATE_DIR/audit/operations.jsonl"
  --set DEVSPACE_NEXT_CURSOR_SIGNING_KEY_REF "$STATE_DIR/cursor-hmac-current.key"
  --set DEVSPACE_NEXT_MANAGEMENT_AUTHORIZATION_KEY_REF "$STATE_DIR/management-authorization.key"
)
node "$SCRIPT_DIR/lib/release-environment.mjs" materialize "${mapfile_args[@]}" >/dev/null
[[ "$(stat -f '%Lp' "$ENV_NEXT" 2>/dev/null || stat -c '%a' "$ENV_NEXT")" == 600 ]]
if grep -Eq '^DEVSPACE_NEXT_SELF_RESTART_DELAY_MS=' "$ENV_NEXT"; then
  echo "Removed self-restart delay leaked into the new environment." >&2
  exit 1
fi

if [[ "$VERIFY_ONLY" == 1 ]]; then
  printf '{"status":"VERIFIED","runtimeRevision":"%s","audit":"%s"}\n' "$RUNTIME_REVISION" "$AUDIT"
  exit 0
fi

PRODUCTION_MUTATION_STARTED=0
STATE_BACKED_UP=0
rollback() {
  local rc="${1:-1}"
  trap - ERR INT TERM
  set +e
  if [[ "$PRODUCTION_MUTATION_STARTED" == 1 ]]; then pm2 delete "$PRODUCTION_PROCESS" >"$AUDIT/rollback-delete-current.log" 2>&1; fi
  cp -p "$AUDIT/production.env.before" "$PRODUCTION_ENV"
  if [[ "$STATE_BACKED_UP" == 1 ]]; then
    rm -rf "$STATE_DIR" "$CONTROL_DIR"
    cp -a "$AUDIT/state.before" "$STATE_DIR"
    cp -a "$AUDIT/finalization-control.before" "$CONTROL_DIR"
    rm -f "$OAUTH_STATE_DIR/devspace.sqlite" "$OAUTH_STATE_DIR/devspace.sqlite-wal" "$OAUTH_STATE_DIR/devspace.sqlite-shm"
    cp -p "$AUDIT/oauth.sqlite.before" "$OAUTH_STATE_DIR/devspace.sqlite"
  fi
  if [[ "$PRODUCTION_MUTATION_STARTED" == 1 ]]; then
    DEVSPACE_PRODUCTION_ENV_FILE="$PRODUCTION_ENV" pm2 start "$OLD_SCRIPT" \
      --name "$PRODUCTION_PROCESS" --interpreter /bin/bash --cwd "$OLD_CWD" --time \
      >"$AUDIT/rollback-start-old.log" 2>&1
  fi
  pm2 save >"$AUDIT/rollback-pm2-save.log" 2>&1
  for _ in $(seq 1 120); do curl -fsS --max-time 3 http://127.0.0.1:7678/healthz >"$AUDIT/rollback-health.json" 2>/dev/null && break; sleep 0.5; done
  printf '{"status":"ROLLED_BACK","runtimeRevision":"%s","exitCode":%s}\n' "$RUNTIME_REVISION" "$rc" >"$AUDIT/result.json"
  exit "$rc"
}
trap 'rollback $?' ERR
trap 'rollback 130' INT
trap 'rollback 143' TERM

PRODUCTION_MUTATION_STARTED=1
pm2 stop "$PRODUCTION_PROCESS" >"$AUDIT/stop-old.log" 2>&1
cp -a "$STATE_DIR" "$AUDIT/state.before"
cp -a "$CONTROL_DIR" "$AUDIT/finalization-control.before"
sqlite3 "$OAUTH_STATE_DIR/devspace.sqlite" ".backup '$AUDIT/oauth.sqlite.before'"
sqlite3 "$AUDIT/oauth.sqlite.before" 'pragma integrity_check;' >"$AUDIT/oauth-integrity.before.txt"
[[ "$(cat "$AUDIT/oauth-integrity.before.txt")" == ok ]]
STATE_BACKED_UP=1
pm2 delete "$PRODUCTION_PROCESS" >"$AUDIT/delete-old.log" 2>&1
cp -p "$ENV_NEXT" "$PRODUCTION_ENV.next"
mv -f "$PRODUCTION_ENV.next" "$PRODUCTION_ENV"
DEVSPACE_PRODUCTION_ENV_FILE="$PRODUCTION_ENV" pm2 start "$START_SCRIPT" \
  --name "$PRODUCTION_PROCESS" --interpreter /bin/bash --cwd "$RELEASE_PACKAGE" --time \
  >"$AUDIT/start-new.log" 2>&1

wait_json() {
  local url="$1" output="$2"
  for _ in $(seq 1 120); do
    if curl -fsS --max-time 5 "$url" >"$output" 2>/dev/null; then return 0; fi
    sleep 0.5
  done
  curl -fsS --max-time 5 "$url" >"$output"
}
wait_json http://127.0.0.1:7678/healthz "$AUDIT/health.local.json"
wait_json http://127.0.0.1:8678/readyz "$AUDIT/ready.local.json"
release_artifacts verify-gateway --package "$RELEASE_PACKAGE" --identity "$AUDIT/health.local.json" >/dev/null
release_artifacts verify-runtime --package "$RELEASE_PACKAGE" --identity "$AUDIT/ready.local.json" >/dev/null
wait_json "$PUBLIC_BASE_URL/healthz" "$AUDIT/health.public.json"
release_artifacts verify-gateway --package "$RELEASE_PACKAGE" --identity "$AUDIT/health.public.json" >/dev/null
pm2 jlist >"$AUDIT/pm2.after.json"
python3 - "$AUDIT/pm2.after.json" "$PRODUCTION_PROCESS" "$RELEASE_PACKAGE" "$START_SCRIPT" <<'PY'
import json,os,sys
items,name,cwd,script=json.load(open(sys.argv[1])),sys.argv[2],sys.argv[3],sys.argv[4]
found=[item for item in items if item.get("name")==name]
if len(found)!=1: raise SystemExit("production PM2 count is not one")
env=found[0].get("pm2_env") or {}
if env.get("status")!="online" or os.path.realpath(env.get("pm_cwd",""))!=os.path.realpath(cwd) or os.path.realpath(env.get("pm_exec_path",""))!=os.path.realpath(script):
    raise SystemExit("production PM2 identity is not the verified release")
PY
pm2 delete "$CANDIDATE_PROCESS" >"$AUDIT/delete-candidate.log" 2>&1
pm2 save >"$AUDIT/pm2-save.log" 2>&1
trap - ERR INT TERM
printf '{"status":"PERSONAL_CUTOVER_PASS","runtimeRevision":"%s","previousRuntime":"%s","release":"%s","audit":"%s"}\n' \
  "$RUNTIME_REVISION" "$(basename "$OLD_CWD")" "$RELEASE_PACKAGE" "$AUDIT" | tee "$AUDIT/result.json"
