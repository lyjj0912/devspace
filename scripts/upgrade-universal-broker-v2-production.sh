#!/usr/bin/env bash
set -Eeuo pipefail
umask 077

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
SOURCE="$ROOT"
PROCESS_NAME="devspace-v2-production"
PRODUCTION_PORT=7678
CANDIDATE_PORT=7679
SSH_LOAD_TARGET="company"
SKIP_COMPANY_GATES=0
WINDOWS_LIVE_TARGET=""
RELEASE_ROOT="${HOME}/.devspace/releases/universal-broker-v2"
DEPLOYMENT_ROOT="${HOME}/.devspace/deployments/universal-broker-v2"
PRODUCTION_ENV="${HOME}/.devspace/universal-broker-v2-production.env"
CANONICAL_START="${HOME}/.devspace/start.sh"
CURRENT_AUDIT_LINK="${DEPLOYMENT_ROOT}/current"

usage() {
  cat <<'EOF'
Usage: upgrade-universal-broker-v2-production.sh [options]

Options:
  --source PATH              Clean pushed source worktree (default: repository root)
  --process-name NAME        PM2 process name (default: devspace-v2-production)
  --port PORT                Production port (default: 7678)
  --candidate-port PORT      Isolated candidate port (default: 7679)
  --ssh-load-target ID       Required real POSIX SSH load/live target (default: company)
  --skip-company-gates       Skip every company target/route gate for this transaction only
  --windows-live-target ID   Optional Windows target; when supplied its live canary is mandatory
  --release-root PATH        Immutable release root
  --deployment-root PATH     Upgrade audit root
  --production-env PATH      Active production environment file
  --canonical-start PATH     Canonical user start script
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --source) SOURCE="$2"; shift 2 ;;
    --process-name) PROCESS_NAME="$2"; shift 2 ;;
    --port) PRODUCTION_PORT="$2"; shift 2 ;;
    --candidate-port) CANDIDATE_PORT="$2"; shift 2 ;;
    --ssh-load-target) SSH_LOAD_TARGET="$2"; shift 2 ;;
    --skip-company-gates) SKIP_COMPANY_GATES=1; shift ;;
    --windows-live-target) WINDOWS_LIVE_TARGET="$2"; shift 2 ;;
    --release-root) RELEASE_ROOT="$2"; shift 2 ;;
    --deployment-root) DEPLOYMENT_ROOT="$2"; CURRENT_AUDIT_LINK="$2/current"; shift 2 ;;
    --production-env) PRODUCTION_ENV="$2"; shift 2 ;;
    --canonical-start) CANONICAL_START="$2"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Unknown option: $1" >&2; usage >&2; exit 2 ;;
  esac
done

SOURCE="$(cd "$SOURCE" && pwd -P)"
RELEASE_ROOT="$(mkdir -p "$RELEASE_ROOT" && cd "$RELEASE_ROOT" && pwd -P)"
DEPLOYMENT_ROOT="$(mkdir -p "$DEPLOYMENT_ROOT" && cd "$DEPLOYMENT_ROOT" && pwd -P)"
PRODUCTION_ENV="$(python3 -c 'import os,sys; print(os.path.abspath(os.path.expanduser(sys.argv[1])))' "$PRODUCTION_ENV")"
CANONICAL_START="$(python3 -c 'import os,sys; print(os.path.abspath(os.path.expanduser(sys.argv[1])))' "$CANONICAL_START")"
CURRENT_AUDIT_LINK="${DEPLOYMENT_ROOT}/current"

for command in git node npm pm2 curl python3; do
  command -v "$command" >/dev/null 2>&1 || { echo "Required command is missing: $command" >&2; exit 1; }
done
ACTIVE_TRANSACTION_STATUS="$(
  find "$DEPLOYMENT_ROOT" -maxdepth 2 -type f -name status.json -path '*/upgrade-*/*' -print0 2>/dev/null \
    | while IFS= read -r -d '' path; do
        python3 - "$path" <<'PYACTIVE'
import json,sys
try:
  value=json.load(open(sys.argv[1],encoding="utf-8"))
except Exception:
  raise SystemExit
if value.get("state") in {"PREPARED","ACCEPTED","SWITCHING","VERIFYING","ROLLING_BACK"}:
  print(sys.argv[1])
PYACTIVE
      done \
    | head -n1
)"
if [[ -n "$ACTIVE_TRANSACTION_STATUS" ]]; then
  echo "Existing nonterminal production upgrade must be inspected before a new submission: $ACTIVE_TRANSACTION_STATUS" >&2
  python3 -m json.tool "$ACTIVE_TRANSACTION_STATUS" >&2 || true
  exit 1
fi
ACTIVE_CANDIDATE="$(
  pm2 jlist | python3 -c 'import json,sys
items=json.load(sys.stdin)
for item in items:
  name=str(item.get("name") or "")
  status=str((item.get("pm2_env") or {}).get("status") or "")
  if name.startswith("devspace-v2-candidate-") and status not in {"stopped","errored"}:
    print(name)
    break'
)"
[[ -z "$ACTIVE_CANDIDATE" ]] || {
  echo "Existing candidate PM2 process must be inspected before a new submission: $ACTIVE_CANDIDATE" >&2
  exit 1
}
if command -v lsof >/dev/null 2>&1 && lsof -nP -iTCP:"$CANDIDATE_PORT" -sTCP:LISTEN -t 2>/dev/null | grep -q .; then
  echo "Candidate port already has a listener: $CANDIDATE_PORT" >&2
  exit 1
fi
GIT_EXECUTABLE="$(command -v git)"
[[ -f "$PRODUCTION_ENV" ]] || { echo "Production environment is missing: $PRODUCTION_ENV" >&2; exit 1; }
[[ "$PRODUCTION_PORT" =~ ^[0-9]+$ && "$CANDIDATE_PORT" =~ ^[0-9]+$ ]] || { echo "Ports must be integers." >&2; exit 1; }
[[ "$PRODUCTION_PORT" != "$CANDIDATE_PORT" ]] || { echo "Candidate port must differ from production port." >&2; exit 1; }

cd "$SOURCE"
BRANCH="$(git branch --show-current)"
[[ -n "$BRANCH" ]] || { echo "Source must be on a branch." >&2; exit 1; }
[[ -z "$(git status --porcelain=v1 --untracked-files=all)" ]] || { echo "Source worktree is not clean." >&2; git status --short >&2; exit 1; }
HEAD="$(git rev-parse HEAD)"
SOURCE_TREE="$(git rev-parse 'HEAD^{tree}')"
UPSTREAM="$(git rev-parse '@{upstream}' 2>/dev/null || true)"
[[ -n "$UPSTREAM" && "$HEAD" == "$UPSTREAM" ]] || { echo "HEAD must equal its upstream before production upgrade." >&2; exit 1; }
[[ "$(git rev-parse "origin/$BRANCH" 2>/dev/null || true)" == "$HEAD" ]] || { echo "origin/$BRANCH does not equal HEAD." >&2; exit 1; }

read_env() {
  local key="$1"
  /bin/bash -c 'set -a; source "$1"; key="$2"; printf "%s" "${!key-}"' _ "$PRODUCTION_ENV" "$key"
}
quote() { printf '%q' "$1"; }
write_env() {
  local path="$1" port="$2" state_dir="$3" oauth_state_dir="$4" process_name="$5" expected_script="$6"
  local temporary="${path}.tmp.$$"
  python3 - "$PRODUCTION_ENV" "$temporary" <<'PYENV'
import re,sys
source,destination=sys.argv[1:]
managed={
  "DEVSPACE_V2_DEPLOYMENT_MODE",
  "DEVSPACE_V2_LEGACY_SCOPE_COMPATIBILITY",
  "DEVSPACE_NEXT_HOST",
  "DEVSPACE_NEXT_PORT",
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
}
pattern=re.compile(r"^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)=")
kept=[]
for line in open(source,encoding="utf-8",errors="strict"):
  match=pattern.match(line)
  if match and match.group(1) in managed:
    continue
  kept.append(line.rstrip("\n"))
while kept and kept[-1]=="":
  kept.pop()
with open(destination,"w",encoding="utf-8") as handle:
  if kept:
    handle.write("\n".join(kept)+"\n")
  handle.write("# Managed Universal Broker v2.1 runtime values.\n")
PYENV
  {
    printf 'DEVSPACE_V2_DEPLOYMENT_MODE=%s\n' "$(quote production)"
    printf 'DEVSPACE_NEXT_HOST=%s\n' "$(quote 127.0.0.1)"
    printf 'DEVSPACE_NEXT_PORT=%s\n' "$(quote "$port")"
    printf 'DEVSPACE_NEXT_PUBLIC_BASE_URL=%s\n' "$(quote "$PUBLIC_BASE_URL")"
    printf 'DEVSPACE_NEXT_MCP_PATH=%s\n' "$(quote /mcp)"
    printf 'DEVSPACE_NEXT_STATE_DIR=%s\n' "$(quote "$state_dir")"
    printf 'DEVSPACE_NEXT_OAUTH_STATE_DIR=%s\n' "$(quote "$oauth_state_dir")"
    printf 'DEVSPACE_NEXT_TARGETS_FILE=%s\n' "$(quote "$TARGETS_FILE")"
    printf 'DEVSPACE_NEXT_MCP_ROUTES_FILE=%s\n' "$(quote "$ROUTES_FILE")"
    printf 'DEVSPACE_NEXT_ENV_PROFILE_CONFIG=%s\n' "$(quote "$ENV_PROFILES_FILE")"
    printf 'DEVSPACE_NEXT_SELF_MANAGEMENT_DIR=%s\n' "$(quote "$state_dir/self-management")"
    printf 'DEVSPACE_NEXT_PM2_PROCESS_NAME=%s\n' "$(quote "$process_name")"
    printf 'DEVSPACE_NEXT_PM2_EXPECTED_SCRIPT=%s\n' "$(quote "$expected_script")"
    printf 'DEVSPACE_NEXT_SELF_RESTART_DELAY_MS=%s\n' "$(quote 2000)"
    printf 'DEVSPACE_NEXT_SELF_RESTART_TIMEOUT_MS=%s\n' "$(quote 120000)"
    printf 'DEVSPACE_NEXT_ALLOWED_HOSTS=%s\n' "$(quote "$ALLOWED_HOSTS")"
    printf 'DEVSPACE_TRUST_PROXY=%s\n' "$(quote 1)"
  } >> "$temporary"
  chmod 600 "$temporary"
  mv -f "$temporary" "$path"
}
run_pm2_with_environment_file() {
  local environment_file="$1"
  shift
  (
    while IFS= read -r variable; do
      unset "$variable"
    done < <(compgen -A variable DEVSPACE_)
    export DEVSPACE_PRODUCTION_ENV_FILE="$environment_file"
    exec pm2 "$@"
  )
}

wait_http() {
  local url="$1" expected="$2" attempts="${3:-120}"
  local code="000"
  for ((index=0; index<attempts; index++)); do
    code="$(curl -sS --max-time 5 -o /dev/null -w '%{http_code}' "$url" || true)"
    [[ "$code" == "$expected" ]] && return 0
    sleep 0.5
  done
  echo "HTTP check failed: $url expected=$expected actual=$code" >&2
  return 1
}

PUBLIC_BASE_URL="$(read_env DEVSPACE_NEXT_PUBLIC_BASE_URL)"
TARGETS_FILE="$(read_env DEVSPACE_NEXT_TARGETS_FILE)"
ROUTES_FILE="$(read_env DEVSPACE_NEXT_MCP_ROUTES_FILE)"
ENV_PROFILES_FILE="$(read_env DEVSPACE_NEXT_ENV_PROFILE_CONFIG)"
ALLOWED_HOSTS="$(read_env DEVSPACE_NEXT_ALLOWED_HOSTS)"
PRODUCTION_STATE_DIR="$(read_env DEVSPACE_NEXT_STATE_DIR)"
CONFIGURED_OAUTH_STATE_DIR="$(read_env DEVSPACE_NEXT_OAUTH_STATE_DIR)"
[[ -n "$PUBLIC_BASE_URL" && -n "$TARGETS_FILE" && -n "$ROUTES_FILE" && -n "$ENV_PROFILES_FILE" ]] || {
  echo "Current production environment lacks required v2 paths." >&2
  exit 1
}
PUBLIC_BASE_URL="${PUBLIC_BASE_URL%/}"
PUBLIC_HOST="$(python3 -c 'from urllib.parse import urlparse; import sys; print(urlparse(sys.argv[1]).hostname or "")' "$PUBLIC_BASE_URL")"
[[ -n "$PUBLIC_HOST" ]] || { echo "Public base URL has no host: $PUBLIC_BASE_URL" >&2; exit 1; }
[[ -n "$ALLOWED_HOSTS" ]] || ALLOWED_HOSTS="localhost,127.0.0.1,::1,$PUBLIC_HOST,127.0.0.1:$PRODUCTION_PORT,127.0.0.1:$CANDIDATE_PORT"
[[ -n "$PRODUCTION_STATE_DIR" ]] || PRODUCTION_STATE_DIR="${HOME}/.local/share/devspace/universal-broker-v2-production"
for file in "$TARGETS_FILE" "$ROUTES_FILE" "$ENV_PROFILES_FILE"; do
  [[ -f "$file" ]] || { echo "Required owner configuration is missing: $file" >&2; exit 1; }
done

PM2_EXECUTABLE="$(command -v pm2)"
read -r PREVIOUS_PID PREVIOUS_CWD PREVIOUS_SCRIPT < <(
  pm2 jlist | python3 -c 'import json,sys
name=sys.argv[1]
items=json.load(sys.stdin)
match=next((x for x in items if x.get("name")==name),None)
if not match: raise SystemExit(f"PM2 process is missing: {name}")
env=match.get("pm2_env",{})
if env.get("status")!="online": raise SystemExit(f"PM2 process is not online: {env.get(chr(115)+chr(116)+chr(97)+chr(116)+chr(117)+chr(115))}")
print(match.get("pid"),env.get("pm_cwd"),env.get("pm_exec_path"),sep="\t")' "$PROCESS_NAME"
)
[[ "$PREVIOUS_PID" =~ ^[0-9]+$ && -d "$PREVIOUS_CWD" && -f "$PREVIOUS_SCRIPT" ]] || {
  echo "Unable to establish the current PM2 runtime authority." >&2
  exit 1
}
PRODUCTION_OAUTH_STATE_DIR="$CONFIGURED_OAUTH_STATE_DIR"
if [[ -z "$PRODUCTION_OAUTH_STATE_DIR" ]]; then
  PRODUCTION_OAUTH_STATE_DIR="$(
    cd "$PREVIOUS_CWD"
    set -a
    # shellcheck disable=SC1090
    source "$PRODUCTION_ENV"
    node --input-type=module - <<'NODE'
import { loadConfig } from "./dist/config.js";
import { loadUniversalBrokerNextConfig } from "./dist/v2/config.js";
console.log(loadUniversalBrokerNextConfig(loadConfig(), process.env).oauthStateDir);
NODE
  )"
fi
[[ -n "$PRODUCTION_OAUTH_STATE_DIR" && -d "$PRODUCTION_OAUTH_STATE_DIR" ]] || {
  echo "Production OAuth state directory is unavailable: $PRODUCTION_OAUTH_STATE_DIR" >&2
  exit 1
}
PRODUCTION_OAUTH_DATABASE="$PRODUCTION_OAUTH_STATE_DIR/devspace.sqlite"
[[ -f "$PRODUCTION_OAUTH_DATABASE" ]] || {
  echo "Production OAuth database is missing: $PRODUCTION_OAUTH_DATABASE" >&2
  exit 1
}
PREVIOUS_AUDIT_TARGET=""
if [[ -L "$CURRENT_AUDIT_LINK" ]]; then
  PREVIOUS_AUDIT_TARGET="$(python3 -c 'import os,sys; print(os.path.realpath(sys.argv[1]))' "$CURRENT_AUDIT_LINK")"
fi

STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
REQUESTED_AT="$(python3 -c 'import datetime; print(datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="microseconds").replace("+00:00","Z"))')"
TRANSACTION_ID="upgrade_$(python3 -c 'import uuid; print(uuid.uuid4())')"
AUDIT_DIR="${DEPLOYMENT_ROOT}/upgrade-${STAMP}-${HEAD:0:12}"
[[ ! -e "$AUDIT_DIR" ]] || { echo "Audit directory already exists: $AUDIT_DIR" >&2; exit 1; }
mkdir -m 700 "$AUDIT_DIR"
STATUS_PATH="$AUDIT_DIR/status.json"
REQUEST_PATH="$AUDIT_DIR/request.json"
WORKER_LOG="$AUDIT_DIR/worker.log"
RELEASE="$RELEASE_ROOT/$HEAD"
NEW_SCRIPT="$RELEASE/scripts/start-universal-broker-v2-production.sh"
CANDIDATE_NAME="devspace-v2-candidate-${HEAD:0:8}"
CANDIDATE_STATE="$AUDIT_DIR/candidate-state"
CANDIDATE_OAUTH_STATE="$CANDIDATE_STATE/oauth"
CANDIDATE_ENV="$AUDIT_DIR/candidate.env"
NEXT_ENV="$AUDIT_DIR/production.env.next"
ENV_BACKUP="$AUDIT_DIR/production.env.before"
START_BACKUP="$AUDIT_DIR/start.sh.before"
LIVE_EVIDENCE="$AUDIT_DIR/candidate-live.json"
NPM_CI_LOG="$AUDIT_DIR/npm-ci.log"
RELEASE_VERIFY_LOG="$AUDIT_DIR/release-verify.log"
if [[ "$SKIP_COMPANY_GATES" == 1 ]]; then
  FULL_LOAD_LOG="$AUDIT_DIR/full-load-company-skipped.json"
else
  FULL_LOAD_LOG="$AUDIT_DIR/full-load-real-${SSH_LOAD_TARGET}.log"
fi
RELEASE_CREATED=0
UPGRADE_SCHEDULED=0

cleanup_candidate() {
  pm2 delete "$CANDIDATE_NAME" >/dev/null 2>&1 || true
  pm2 save >/dev/null 2>&1 || true
  rm -rf "$CANDIDATE_STATE"
}
cleanup_on_exit() {
  cleanup_candidate
  if [[ "$UPGRADE_SCHEDULED" != 1 && "$RELEASE_CREATED" == 1 && -e "$RELEASE" ]]; then
    git -C "$SOURCE" worktree remove --force "$RELEASE" >/dev/null 2>&1 || true
    git -C "$SOURCE" worktree prune >/dev/null 2>&1 || true
  fi
}
trap cleanup_on_exit EXIT

if [[ -d "$RELEASE/.git" || -f "$RELEASE/.git" ]]; then
  [[ "$(git -C "$RELEASE" rev-parse HEAD)" == "$HEAD" ]] || { echo "Release path has another commit: $RELEASE" >&2; exit 1; }
  [[ -z "$(git -C "$RELEASE" status --porcelain=v1 --untracked-files=all)" ]] || { echo "Existing release is dirty: $RELEASE" >&2; exit 1; }
else
  git worktree add --detach "$RELEASE" "$HEAD"
  RELEASE_CREATED=1
fi

(
  cd "$RELEASE"
  npm ci 2>&1 | tee "$NPM_CI_LOG"
  npm run release:verify -- --require-clean 2>&1 | tee "$RELEASE_VERIFY_LOG"
  if [[ "$SKIP_COMPANY_GATES" == 1 ]]; then
    printf '%s\n' '{"ok":true,"skipped":true,"scope":"all-company-gates","reason":"explicit --skip-company-gates"}' \
      | tee "$FULL_LOAD_LOG"
  else
    DEVSPACE_V2_LOAD_TARGET_CONFIG="$TARGETS_FILE" \
    DEVSPACE_V2_LOAD_SSH_TARGET="$SSH_LOAD_TARGET" \
    DEVSPACE_V2_LOAD_REQUIRE_REAL_SSH=1 \
      npm run v2:load 2>&1 | tee "$FULL_LOAD_LOG"
  fi
)
DIST_EVIDENCE="$(
  cd "$RELEASE"
  node --input-type=module -e \
    'import { directoryEvidence } from "./dist/v2/production-upgrade-worker.js"; console.log(JSON.stringify(await directoryEvidence("./dist")));'
)"
read -r DIST_FILES DIST_SHA256 < <(
  python3 - "$DIST_EVIDENCE" <<'PYDIST'
import json,sys
value=json.loads(sys.argv[1])
print(int(value["files"]),value["sha256"])
PYDIST
)
[[ "$DIST_FILES" =~ ^[1-9][0-9]*$ && "$DIST_SHA256" =~ ^[0-9a-f]{64}$ ]] || {
  echo "Unable to establish release dist fingerprint: $DIST_EVIDENCE" >&2
  exit 1
}
chmod 600 "$NPM_CI_LOG" "$RELEASE_VERIFY_LOG" "$FULL_LOAD_LOG"
[[ -x "$NEW_SCRIPT" ]] || chmod 700 "$NEW_SCRIPT"

write_env "$CANDIDATE_ENV" "$CANDIDATE_PORT" "$CANDIDATE_STATE" "$CANDIDATE_OAUTH_STATE" "$CANDIDATE_NAME" "$NEW_SCRIPT"
pm2 delete "$CANDIDATE_NAME" >/dev/null 2>&1 || true
run_pm2_with_environment_file "$CANDIDATE_ENV" \
  start "$NEW_SCRIPT" \
  --name "$CANDIDATE_NAME" \
  --interpreter /bin/bash \
  --cwd "$RELEASE" \
  --time
wait_http "http://127.0.0.1:${CANDIDATE_PORT}/healthz" 200
LOCAL_METRICS="$(curl -sS --max-time 10 -H "Host: 127.0.0.1:${CANDIDATE_PORT}" -o /dev/null -w '%{http_code}' "http://127.0.0.1:${CANDIDATE_PORT}/metrics" || true)"
PUBLIC_HOST_METRICS="$(curl -sS --max-time 10 -H "Host: $PUBLIC_HOST" -o /dev/null -w '%{http_code}' "http://127.0.0.1:${CANDIDATE_PORT}/metrics" || true)"
[[ "$LOCAL_METRICS" == 200 && "$PUBLIC_HOST_METRICS" == 403 ]] || {
  echo "Candidate metrics boundary failed: local=$LOCAL_METRICS public-host=$PUBLIC_HOST_METRICS" >&2
  exit 1
}
UNAUTH="$(curl -sS --max-time 10 -o /dev/null -w '%{http_code}' -X POST -H 'content-type: application/json' \
  --data '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"upgrade-candidate","version":"1"}}}' \
  "http://127.0.0.1:${CANDIDATE_PORT}/mcp" || true)"
[[ "$UNAUTH" == 401 ]] || { echo "Candidate unauthenticated MCP returned $UNAUTH" >&2; exit 1; }

CANDIDATE_OAUTH_DATABASE="$CANDIDATE_OAUTH_STATE/devspace.sqlite"
[[ -f "$CANDIDATE_OAUTH_DATABASE" ]] || {
  echo "Candidate OAuth database is missing: $CANDIDATE_OAUTH_DATABASE" >&2
  exit 1
}
LIVE_ARGUMENTS=(
  --base-url "http://127.0.0.1:${CANDIDATE_PORT}"
  --mcp-url "http://127.0.0.1:${CANDIDATE_PORT}/mcp"
  --health-url "http://127.0.0.1:${CANDIDATE_PORT}/healthz"
  --artifact-fetch-base-url "http://127.0.0.1:${CANDIDATE_PORT}"
  --token-resource "${PUBLIC_BASE_URL}/mcp"
  --database "$CANDIDATE_OAUTH_DATABASE"
  --sessions 3
  --output "$LIVE_EVIDENCE"
)
if [[ "$SKIP_COMPANY_GATES" == 1 ]]; then
  LIVE_ARGUMENTS+=(--skip-company-gates)
else
  LIVE_ARGUMENTS+=(--company-target "$SSH_LOAD_TARGET")
fi
if [[ -n "$WINDOWS_LIVE_TARGET" ]]; then
  LIVE_ARGUMENTS+=(--windows-target "$WINDOWS_LIVE_TARGET")
fi
node "$RELEASE/scripts/verify-universal-broker-v2-live.mjs" "${LIVE_ARGUMENTS[@]}"
cleanup_candidate

cp -p "$PRODUCTION_ENV" "$ENV_BACKUP"
chmod 600 "$ENV_BACKUP"
if [[ -f "$CANONICAL_START" ]]; then
  cp -p "$CANONICAL_START" "$START_BACKUP"
else
  {
    printf '#!/bin/bash\nset -euo pipefail\n'
    printf 'export DEVSPACE_PRODUCTION_ENV_FILE=%q\n' "$PRODUCTION_ENV"
    printf 'exec %q\n' "$PREVIOUS_SCRIPT"
  } > "$START_BACKUP"
fi
chmod 700 "$START_BACKUP"
write_env "$NEXT_ENV" "$PRODUCTION_PORT" "$PRODUCTION_STATE_DIR" "$PRODUCTION_OAUTH_STATE_DIR" "$PROCESS_NAME" "$NEW_SCRIPT"
pm2 jlist | python3 -c 'import json,sys
items=json.load(sys.stdin)
out=[]
for item in items:
  env=item.get("pm2_env",{})
  out.append({
    "name":item.get("name"),
    "pid":item.get("pid"),
    "status":env.get("status"),
    "cwd":env.get("pm_cwd"),
    "script":env.get("pm_exec_path"),
  })
json.dump(out,sys.stdout,indent=2);sys.stdout.write("\n")' > "$AUDIT_DIR/pm2-before.json"
tailscale funnel status > "$AUDIT_DIR/funnel-before.txt" 2>&1 || true
chmod 600 "$AUDIT_DIR/pm2-before.json" "$AUDIT_DIR/funnel-before.txt"
if command -v sqlite3 >/dev/null 2>&1; then
  sqlite3 "$PRODUCTION_OAUTH_DATABASE" ".backup '$AUDIT_DIR/oauth-before.sqlite'"
else
  cp -p "$PRODUCTION_OAUTH_DATABASE" "$AUDIT_DIR/oauth-before.sqlite"
fi
chmod 600 "$AUDIT_DIR/oauth-before.sqlite"

python3 - \
  "$REQUEST_PATH" "$STATUS_PATH" "$TRANSACTION_ID" "$REQUESTED_AT" \
  "$PROCESS_NAME" "$PM2_EXECUTABLE" "$GIT_EXECUTABLE" "$PREVIOUS_PID" "$PREVIOUS_CWD" "$PREVIOUS_SCRIPT" "$PREVIOUS_AUDIT_TARGET" \
  "$HEAD" "$SOURCE_TREE" "$DIST_FILES" "$DIST_SHA256" "$RELEASE" "$NEW_SCRIPT" "$PRODUCTION_ENV" "$ENV_BACKUP" "$NEXT_ENV" \
  "$CANONICAL_START" "$START_BACKUP" "$AUDIT_DIR" "$CURRENT_AUDIT_LINK" "$WORKER_LOG" \
  "http://127.0.0.1:${PRODUCTION_PORT}/healthz" "${PUBLIC_BASE_URL}/healthz" \
  "${PUBLIC_BASE_URL}/metrics" "${PUBLIC_BASE_URL}/mcp" \
  "${PUBLIC_BASE_URL}/.well-known/oauth-protected-resource/mcp" "$LIVE_EVIDENCE" <<'PY'
import json,os,sys,tempfile
(
  request_path,status_path,transaction_id,requested_at,
  process_name,pm2_executable,git_executable,previous_pid,previous_cwd,previous_script,previous_audit_target,
  head,source_tree,dist_files,dist_sha256,release,new_script,production_env,env_backup,next_env,
  canonical_start,start_backup,audit_dir,current_audit_link,worker_log,
  local_health,public_health,public_metrics,public_mcp,oauth_metadata,live_evidence,
)=sys.argv[1:]
request={
  "version":1,
  "transactionId":transaction_id,
  "requestedAt":requested_at,
  "delayMs":2000,
  "timeoutMs":180000,
  "pm2ProcessName":process_name,
  "pm2Executable":pm2_executable,
  "gitExecutable":git_executable,
  "previous":{
    "pid":int(previous_pid),
    "cwd":previous_cwd,
    "script":previous_script,
    **({"auditTarget":previous_audit_target} if previous_audit_target else {}),
  },
  "next":{
    "commit":head,
    "sourceTree":source_tree,
    "release":release,
    "script":new_script,
    "dist":{"files":int(dist_files),"sha256":dist_sha256},
  },
  "productionEnvPath":production_env,
  "productionEnvBackupPath":env_backup,
  "nextEnvPath":next_env,
  "startScriptPath":canonical_start,
  "startScriptBackupPath":start_backup,
  "auditDirectory":audit_dir,
  "currentAuditLink":current_audit_link,
  "statusPath":status_path,
  "workerLogPath":worker_log,
  "localHealthUrl":local_health,
  "publicHealthUrl":public_health,
  "publicMetricsUrl":public_metrics,
  "publicMcpUrl":public_mcp,
  "oauthMetadataUrl":oauth_metadata,
  "expectedScopes":["devspace.read","devspace.write","devspace.exec","devspace.mcp","devspace.artifact","devspace.gui","offline_access"],
  **({"launchdLabel":f"com.devspace.production-upgrade.{transaction_id.replace('_','-',1)}"} if sys.platform=="darwin" else {}),
}
status={
  "version":1,
  "transactionId":transaction_id,
  "state":"PREPARED",
  "requestedAt":requested_at,
  "updatedAt":requested_at,
  "expectedDisconnect":True,
  "previous":request["previous"],
  "next":request["next"],
  "candidateEvidence":live_evidence,
  "history":[{"state":"PREPARED","at":requested_at}],
}
def write(path,value,mode=0o600):
  os.makedirs(os.path.dirname(path),exist_ok=True)
  fd,tmp=tempfile.mkstemp(prefix='.'+os.path.basename(path)+'.',dir=os.path.dirname(path))
  try:
    with os.fdopen(fd,'w') as f:
      json.dump(value,f,indent=2);f.write('\n');f.flush();os.fsync(f.fileno())
    os.chmod(tmp,mode);os.replace(tmp,path)
  finally:
    if os.path.exists(tmp):os.unlink(tmp)
write(request_path,request)
write(status_path,status)
PY
WORKER="$RELEASE/dist/v2/production-upgrade-worker.js"
[[ -f "$WORKER" ]] || { echo "Production upgrade worker is missing: $WORKER" >&2; exit 1; }
if [[ "$(uname -s)" == Darwin ]]; then
  LABEL="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["launchdLabel"])' "$REQUEST_PATH")"
  /bin/launchctl submit -l "$LABEL" -o "$WORKER_LOG" -e "$WORKER_LOG" -- \
    "$(command -v node)" "$WORKER" "$REQUEST_PATH"
else
  nohup "$(command -v node)" "$WORKER" "$REQUEST_PATH" >> "$WORKER_LOG" 2>&1 </dev/null &
fi
UPGRADE_SCHEDULED=1

python3 - "$STATUS_PATH" <<'PY'
import json,sys
status=json.load(open(sys.argv[1]))
print(json.dumps({
  "status":"UPGRADE_SCHEDULED",
  "transactionId":status["transactionId"],
  "statusPath":sys.argv[1],
  "expectedDisconnect":True,
  "next":status["next"],
},indent=2))
PY
