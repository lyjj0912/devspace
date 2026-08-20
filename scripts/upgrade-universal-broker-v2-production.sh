#!/usr/bin/env bash
set -Eeuo pipefail
umask 077

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
SOURCE="$ROOT"
PROCESS_NAME="devspace-v2-production"
PRODUCTION_PORT=7678
CANDIDATE_PORT=7679
CANDIDATE_PUBLIC_BASE_URL=""
SSH_LOAD_TARGET="company"
SSH_LOAD_READ_PATH="/etc/hosts"
SKIP_COMPANY_GATES=0
SKIP_COMPANY_CHROME_GATE=0
WINDOWS_LIVE_TARGET=""
RELEASE_ROOT="${HOME}/.devspace/releases/universal-broker-v2"
DEPLOYMENT_ROOT="${HOME}/.devspace/deployments/universal-broker-v2"
PRODUCTION_ENV="${HOME}/.devspace/universal-broker-v2-production.env"
CANONICAL_START="${HOME}/.devspace/start.sh"
CURRENT_AUDIT_LINK="${DEPLOYMENT_ROOT}/current"
IDENTITY_DIRECTORY="${HOME}/.devspace/identity"
STAGING_PRECHECK_REQUEST=""
STAGING_ACTIVATION_REQUEST=""
PRE_CUTOVER_REQUEST=""
PRODUCTION_APPROVAL_REQUEST=""
ROLLBACK_CHALLENGE_REQUEST=""
GATE_PRODUCER_PRIVATE_KEY=""
GATE_PRODUCER_TRUST_ANCHOR=""
EVIDENCE_WAIT_SECONDS=600

usage() {
  cat <<'EOF'
Usage: upgrade-universal-broker-v2-production.sh [options]

Options:
  --source PATH              Clean pushed source worktree (default: repository root)
  --process-name NAME        PM2 process name (default: devspace-v2-production)
  --port PORT                Production port (default: 7678)
  --candidate-port PORT      Isolated candidate port (default: 7679)
  --candidate-public-base-url URL
                             Required isolated HTTPS staging origin routed to the candidate
  --ssh-load-target ID       Required real POSIX SSH load/live target (default: company)
  --ssh-load-read-path PATH  Existing harmless remote file for SSH read NFR (default: /etc/hosts)
  --skip-company-gates       Skip every company target/route gate for this transaction only
  --skip-company-chrome-gate Skip only the company Chrome readiness/mutation canary
  --windows-live-target ID   Optional Windows target; when supplied its live canary is mandatory
  --release-root PATH        Immutable release root
  --deployment-root PATH     Upgrade audit root
  --production-env PATH      Active production environment file
  --canonical-start PATH     Canonical user start script
  --identity-directory PATH  Stable owner identity directory (never release-scoped)
  --staging-precheck-request PATH
                             Future/existing owner-only exact driver request
  --staging-activation-request PATH
                             Future/existing owner-only exact driver request
  --pre-cutover-request PATH Future/existing owner-only exact driver request
  --production-approval-request PATH
                             Future/existing owner-only exact driver request
  --rollback-challenge-request PATH
                             Future/existing owner-only exact driver request
  --gate-producer-private-key PATH
                             Existing owner-only Ed25519 gate producer private key
  --gate-producer-trust-anchor PATH
                             Existing management-authenticated gate producer trust anchor
  --evidence-wait-seconds N  Bounded request/Host rendezvous (default: 600)
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --source) SOURCE="$2"; shift 2 ;;
    --process-name) PROCESS_NAME="$2"; shift 2 ;;
    --port) PRODUCTION_PORT="$2"; shift 2 ;;
    --candidate-port) CANDIDATE_PORT="$2"; shift 2 ;;
    --candidate-public-base-url) CANDIDATE_PUBLIC_BASE_URL="$2"; shift 2 ;;
    --ssh-load-target) SSH_LOAD_TARGET="$2"; shift 2 ;;
    --ssh-load-read-path) SSH_LOAD_READ_PATH="$2"; shift 2 ;;
    --skip-company-gates) SKIP_COMPANY_GATES=1; shift ;;
    --skip-company-chrome-gate) SKIP_COMPANY_CHROME_GATE=1; shift ;;
    --windows-live-target) WINDOWS_LIVE_TARGET="$2"; shift 2 ;;
    --release-root) RELEASE_ROOT="$2"; shift 2 ;;
    --deployment-root) DEPLOYMENT_ROOT="$2"; CURRENT_AUDIT_LINK="$2/current"; shift 2 ;;
    --production-env) PRODUCTION_ENV="$2"; shift 2 ;;
    --canonical-start) CANONICAL_START="$2"; shift 2 ;;
    --identity-directory) IDENTITY_DIRECTORY="$2"; shift 2 ;;
    --staging-precheck-request) STAGING_PRECHECK_REQUEST="$2"; shift 2 ;;
    --staging-activation-request) STAGING_ACTIVATION_REQUEST="$2"; shift 2 ;;
    --pre-cutover-request) PRE_CUTOVER_REQUEST="$2"; shift 2 ;;
    --production-approval-request) PRODUCTION_APPROVAL_REQUEST="$2"; shift 2 ;;
    --rollback-challenge-request) ROLLBACK_CHALLENGE_REQUEST="$2"; shift 2 ;;
    --gate-producer-private-key) GATE_PRODUCER_PRIVATE_KEY="$2"; shift 2 ;;
    --gate-producer-trust-anchor) GATE_PRODUCER_TRUST_ANCHOR="$2"; shift 2 ;;
    --evidence-wait-seconds) EVIDENCE_WAIT_SECONDS="$2"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Unknown option: $1" >&2; usage >&2; exit 2 ;;
  esac
done
for gate_path in "$GATE_PRODUCER_PRIVATE_KEY" "$GATE_PRODUCER_TRUST_ANCHOR"; do
  [[ "$gate_path" == /* ]] || {
    echo "Gate producer key and trust-anchor paths must be absolute." >&2
    exit 2
  }
done

[[ "$EVIDENCE_WAIT_SECONDS" =~ ^[1-9][0-9]*$ && "$EVIDENCE_WAIT_SECONDS" -le 900 ]] || {
  echo "--evidence-wait-seconds must be an integer from 1 through 900." >&2
  exit 2
}
for request_path in \
  "$STAGING_PRECHECK_REQUEST" "$STAGING_ACTIVATION_REQUEST" "$PRE_CUTOVER_REQUEST" \
  "$PRODUCTION_APPROVAL_REQUEST" "$ROLLBACK_CHALLENGE_REQUEST"; do
  [[ "$request_path" == /* ]] || {
    echo "Every connector release-driver request path must be absolute." >&2
    exit 2
  }
done

SOURCE="$(cd "$SOURCE" && pwd -P)"
RELEASE_ROOT="$(mkdir -p "$RELEASE_ROOT" && cd "$RELEASE_ROOT" && pwd -P)"
DEPLOYMENT_ROOT="$(mkdir -p "$DEPLOYMENT_ROOT" && cd "$DEPLOYMENT_ROOT" && pwd -P)"
PRODUCTION_ENV="$(python3 -c 'import os,sys; print(os.path.abspath(os.path.expanduser(sys.argv[1])))' "$PRODUCTION_ENV")"
CANONICAL_START="$(python3 -c 'import os,sys; print(os.path.abspath(os.path.expanduser(sys.argv[1])))' "$CANONICAL_START")"
IDENTITY_DIRECTORY="$(python3 -c 'import os,sys; print(os.path.abspath(os.path.expanduser(sys.argv[1])))' "$IDENTITY_DIRECTORY")"
CURRENT_AUDIT_LINK="${DEPLOYMENT_ROOT}/current"

[[ "$EVIDENCE_WAIT_SECONDS" =~ ^[1-9][0-9]*$ && "$EVIDENCE_WAIT_SECONDS" -le 900 ]] || {
  echo "--evidence-wait-seconds must be an integer from 1 through 900." >&2
  exit 2
}
for request_path in \
  "$STAGING_PRECHECK_REQUEST" "$STAGING_ACTIVATION_REQUEST" "$PRE_CUTOVER_REQUEST" \
  "$PRODUCTION_APPROVAL_REQUEST" "$ROLLBACK_CHALLENGE_REQUEST"; do
  [[ "$request_path" == /* ]] || {
    echo "Every connector release-driver request path must be absolute." >&2
    exit 2
  }
done

for command in git node npm pm2 curl python3 sqlite3 lsof shasum; do
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
if value.get("state") in {
  "PREPARED","ACCEPTED","PREFLIGHT_VERIFIED","CONNECTOR_ACTIVATION_PREPARED",
  "CUTOVER_STOP_REQUESTED",
  "CUTOVER_PROCESSES_STOPPED","STATE_SNAPSHOTTED","ACTIVATED_PENDING_POSTCHECK",
  "RUNTIME_STARTED","POST_SWITCH_VERIFIED","POST_ACTIVATION_VERIFIED",
  "ROLLBACK_REQUESTED","ROLLBACK_RESTORING",
}:
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
absolute_path() {
  python3 -c 'import os,sys; print(os.path.abspath(os.path.expanduser(sys.argv[1])))' "$1"
}
file_sha256() {
  printf 'sha256:%s\n' "$(shasum -a 256 "$1" | awk '{print $1}')"
}
await_owner_only_request_copy() {
  local source_path="$1" destination_path="$2" label="$3"
  local attempts=$((EVIDENCE_WAIT_SECONDS * 4))
  local attempt result
  printf 'Awaiting %s at %s\n' "$label" "$source_path" >&2
  for ((attempt=0; attempt<attempts; attempt++)); do
    set +e
    python3 - "$source_path" "$destination_path" <<'PYOWNERREQUEST'
import errno,os,stat,sys,tempfile
source,destination=sys.argv[1:]
if not os.path.isabs(source) or os.path.abspath(source) != source:
  raise SystemExit("release-driver request path is not canonical absolute")
parent=os.path.dirname(source)
if os.path.realpath(parent) != parent:
  raise SystemExit("release-driver request ancestor contains a symbolic link")
parent_stat=os.lstat(parent)
if not stat.S_ISDIR(parent_stat.st_mode) or stat.S_ISLNK(parent_stat.st_mode):
  raise SystemExit("release-driver request parent is not a real directory")
if parent_stat.st_uid != os.getuid() or parent_stat.st_mode & 0o077:
  raise SystemExit("release-driver request parent is not owner-only")
flags=os.O_RDONLY | getattr(os,"O_NOFOLLOW",0)
try:
  descriptor=os.open(source,flags)
except FileNotFoundError:
  raise SystemExit(75)
try:
  metadata=os.fstat(descriptor)
  if not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != os.getuid() or metadata.st_mode & 0o077:
    raise SystemExit("release-driver request is not an owner-only regular file")
  chunks=[];size=0
  while True:
    chunk=os.read(descriptor,65536)
    if not chunk: break
    size+=len(chunk)
    if size > 1024*1024: raise SystemExit("release-driver request exceeds 1 MiB")
    chunks.append(chunk)
finally:
  os.close(descriptor)
data=b"".join(chunks)
destination_parent=os.path.dirname(destination)
if os.path.realpath(destination_parent) != destination_parent:
  raise SystemExit("audit request directory contains a symbolic link")
temporary=None
try:
  fd,temporary=tempfile.mkstemp(prefix="."+os.path.basename(destination)+".",dir=destination_parent)
  with os.fdopen(fd,"wb") as output:
    output.write(data);output.flush();os.fsync(output.fileno())
  os.chmod(temporary,0o600)
  os.link(temporary,destination)
  directory_fd=os.open(destination_parent,os.O_RDONLY)
  try: os.fsync(directory_fd)
  finally: os.close(directory_fd)
finally:
  if temporary and os.path.exists(temporary): os.unlink(temporary)
PYOWNERREQUEST
    result=$?
    set -e
    if [[ "$result" == 0 ]]; then return 0; fi
    if [[ "$result" != 75 ]]; then
      echo "$label failed owner-only request preflight: $source_path" >&2
      return "$result"
    fi
    sleep 0.25
  done
  echo "$label did not arrive within ${EVIDENCE_WAIT_SECONDS}s: $source_path" >&2
  return 1
}
run_connector_release_driver() {
  local command="$1" source_request="$2" audit_request="$3" output="$4" summary="$5"
  await_owner_only_request_copy "$source_request" "$audit_request" "$command request"
  local temporary_summary="${summary}.tmp"
  [[ ! -e "$temporary_summary" && ! -e "$summary" ]] || {
    echo "Connector release-driver summary path already exists: $summary" >&2
    return 1
  }
  DEVSPACE_RUNTIME_PACKAGE_ROOT="$IMMUTABLE_RUNTIME_ROOT" \
  DEVSPACE_RUNTIME_DEPENDENCY_ROOT="$RUNTIME_DEPENDENCY_ROOT" \
    node --import "$WORKER_DEPENDENCY_LOADER" "$CONNECTOR_RELEASE_DRIVER" "$command" \
      --request "$audit_request" --output "$output" >"$temporary_summary"
  chmod 600 "$temporary_summary"
  mv "$temporary_summary" "$summary"
  python3 - "$summary" "$command" "$output" <<'PYDRIVERSUMMARY'
import hashlib,json,os,sys
summary,command,output=sys.argv[1:]
value=json.load(open(summary,encoding="utf-8"))
if not isinstance(value,dict) or not value:
  raise SystemExit("connector release-driver emitted no success summary")
if command == "production-approve":
  if os.path.realpath(value.get("directoryPath", "")) != os.path.realpath(output):
    raise SystemExit("production approval summary points at another output directory")
  expected={
    "manifestPath":os.path.join(output,"manifest.json"),
    "productionActivationPrecheckPath":os.path.join(output,"production-activation-precheck.json"),
    "ownerManagementApprovalPath":os.path.join(output,"owner-management-approval.json"),
  }
  if any(os.path.realpath(value.get(key,"")) != os.path.realpath(path) for key,path in expected.items()):
    raise SystemExit("production approval summary paths are incomplete or foreign")
else:
  kinds={
    "staging-precheck":"STAGING_ACTIVATION_PRECHECK",
    "staging-activate":"STAGING_ACTIVATION",
    "pre-cutover":"PRE_CUTOVER_HOST_CANARY",
    "production-predecision":"PRODUCTION_ACTIVATION_PREDECISION",
    "rollback-challenge":"ROLLBACK_HOST_CHALLENGE",
  }
  if command not in kinds or value.get("kind") != kinds[command] or os.path.realpath(value.get("path","")) != os.path.realpath(output):
    raise SystemExit("connector release-driver summary identity or output path is invalid")
  digest="sha256:"+hashlib.sha256(open(output,"rb").read()).hexdigest()
  if value.get("sha256") != digest:
    raise SystemExit("connector release-driver output changed after verified publication")
PYDRIVERSUMMARY
}
quote() { printf '%q' "$1"; }
write_env() {
  local path="$1" port="$2" state_dir="$3" oauth_state_dir="$4" process_name="$5" expected_script="$6"
  local public_base_url="$7" allowed_hosts="$8"
  local authority_state_dir="$9" authority_store="${10}" context_store="${11}" context_worktree_root="${12}"
  local process_output_dir="${13}" artifact_staging_dir="${14}" artifact_catalog="${15}" artifact_object_root="${16}"
  local audit_sink="${17}" cursor_current_key="${18}" cursor_previous_key="${19}" management_authorization_key="${20}"
  local ssh_control_dir="${21}" connector_activation_journal="${22}" lifecycle_finalization_store="${23}"
  local lifecycle_finalization_control="${24}"
  local management_port
  if (( port <= 64535 )); then management_port="$((port + 1000))"; else management_port="$((port - 1000))"; fi
  node "$ROOT/scripts/lib/release-environment.mjs" materialize \
    --source "$PRODUCTION_ENV" --destination "$path" \
    --set DEVSPACE_V2_DEPLOYMENT_MODE production \
    --set DEVSPACE_NEXT_HOST 127.0.0.1 \
    --set DEVSPACE_NEXT_PORT "$port" \
    --set DEVSPACE_NEXT_MANAGEMENT_PORT "$management_port" \
    --set DEVSPACE_NEXT_PUBLIC_BASE_URL "$public_base_url" \
    --set DEVSPACE_NEXT_MCP_PATH /mcp \
    --set DEVSPACE_NEXT_STATE_DIR "$state_dir" \
    --set DEVSPACE_NEXT_OAUTH_STATE_DIR "$oauth_state_dir" \
    --set DEVSPACE_NEXT_TARGETS_FILE "$TARGETS_FILE" \
    --set DEVSPACE_NEXT_MCP_ROUTES_FILE "$ROUTES_FILE" \
    --set DEVSPACE_NEXT_ENV_PROFILE_CONFIG "$ENV_PROFILES_FILE" \
    --set DEVSPACE_NEXT_SELF_MANAGEMENT_DIR "$state_dir/self-management" \
    --set DEVSPACE_NEXT_PM2_PROCESS_NAME "$process_name" \
    --set DEVSPACE_NEXT_PM2_EXPECTED_SCRIPT "$expected_script" \
    --set DEVSPACE_NEXT_SELF_RESTART_TIMEOUT_MS 120000 \
    --set DEVSPACE_NEXT_ALLOWED_HOSTS "$allowed_hosts" \
    --set DEVSPACE_TRUST_PROXY 1 \
    --set DEVSPACE_NEXT_AUTHORITY_OWNER_INSTANCE_ID "$OWNER_INSTANCE_ID" \
    --set DEVSPACE_RELEASE_MANIFEST "$BUILD_MANIFEST" \
    --set DEVSPACE_EXPECTED_RELEASE_MANIFEST_SHA256 "$BUILD_MANIFEST_SHA256" \
    --set DEVSPACE_EXPECTED_SOURCE_REVISION "$MANIFEST_SOURCE_REVISION" \
    --set DEVSPACE_EXPECTED_RUNTIME_REVISION "$MANIFEST_RUNTIME_REVISION" \
    --set DEVSPACE_EXPECTED_BUILD_DIGEST "$MANIFEST_BUILD_DIGEST" \
    --set DEVSPACE_EXPECTED_SCHEMA_GENERATION "$MANIFEST_SCHEMA_GENERATION" \
    --set DEVSPACE_EXPECTED_AUTHORITY_CONTRACT_GENERATION "$MANIFEST_AUTHORITY_GENERATION" \
    --set DEVSPACE_EXPECTED_CONFIG_SCHEMA_IDENTITY "$MANIFEST_CONFIG_SCHEMA_IDENTITY" \
    --set DEVSPACE_RUNTIME_PACKAGE_ROOT "$IMMUTABLE_RELEASE" \
    --set DEVSPACE_RUNTIME_DEPENDENCY_ROOT "$RUNTIME_DEPENDENCY_ROOT" \
    --set DEVSPACE_RUNTIME_DEPENDENCY_EVIDENCE "$RUNTIME_DEPENDENCY_EVIDENCE" \
    --set DEVSPACE_EXPECTED_RUNTIME_DEPENDENCY_EVIDENCE_SHA256 "$RUNTIME_DEPENDENCY_EVIDENCE_SHA256" \
    --set DEVSPACE_OAUTH_CANONICAL_CONNECTOR_NAME "$CANONICAL_CONNECTOR_NAME" \
    --set DEVSPACE_OAUTH_CONNECTOR_INSTALLATION_EPOCH "$CONNECTOR_INSTALLATION_EPOCH" \
    --set DEVSPACE_NEXT_CANONICAL_CONNECTOR_NAME "$CANONICAL_CONNECTOR_NAME" \
    --set DEVSPACE_SOURCE_REVISION "$MANIFEST_SOURCE_REVISION" \
    --set DEVSPACE_RUNTIME_REVISION "$MANIFEST_RUNTIME_REVISION" \
    --set DEVSPACE_BUILD_DIGEST "$MANIFEST_BUILD_DIGEST" \
    --set DEVSPACE_NEXT_AUTHORITY_STATE_DIR "$authority_state_dir" \
    --set DEVSPACE_NEXT_AUTHORITY_STORE "$authority_store" \
    --set DEVSPACE_NEXT_CONNECTOR_ACTIVATION_JOURNAL "$connector_activation_journal" \
    --set DEVSPACE_NEXT_LIFECYCLE_FINALIZATION_STORE "$lifecycle_finalization_store" \
    --set DEVSPACE_NEXT_LIFECYCLE_FINALIZATION_CONTROL "$lifecycle_finalization_control" \
    --set DEVSPACE_NEXT_CONTEXT_STORE "$context_store" \
    --set DEVSPACE_NEXT_CONTEXT_WORKTREE_ROOT "$context_worktree_root" \
    --set DEVSPACE_NEXT_PROCESS_OUTPUT_DIR "$process_output_dir" \
    --set DEVSPACE_NEXT_SSH_CONTROL_DIR "$ssh_control_dir" \
    --set DEVSPACE_NEXT_ARTIFACT_STAGING_DIR "$artifact_staging_dir" \
    --set DEVSPACE_NEXT_ARTIFACT_CATALOG "$artifact_catalog" \
    --set DEVSPACE_NEXT_ARTIFACT_OBJECT_ROOT "$artifact_object_root" \
    --set DEVSPACE_NEXT_AUDIT_SINK "$audit_sink" \
    --set DEVSPACE_NEXT_CURSOR_SIGNING_KEY_REF "$cursor_current_key" \
    --set DEVSPACE_NEXT_CURSOR_PREVIOUS_SIGNING_KEY_REF "$cursor_previous_key" \
    --set DEVSPACE_NEXT_MANAGEMENT_AUTHORIZATION_KEY_REF "$management_authorization_key" \
    >/dev/null
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
assert_candidate_pm2_runtime() {
  local raw="$AUDIT_DIR/candidate-pm2-jlist.json"
  pm2 jlist >"$raw"
  python3 - "$raw" "$CANDIDATE_NAME" "$IMMUTABLE_RUNTIME_ROOT" "$IMMUTABLE_RUNTIME_ENTRYPOINT" <<'PYCANDIDATEPM2' >"$CANDIDATE_PM2_EVIDENCE"
import json,os,sys
path,name,expected_cwd,expected_script=sys.argv[1:]
items=json.load(open(path,encoding="utf-8"))
matches=[item for item in items if item.get("name")==name]
if len(matches) != 1:
  raise SystemExit(f"candidate PM2 process count is not one: {len(matches)}")
item=matches[0];env=item.get("pm2_env") or {}
observed={
  "name":name,
  "pid":item.get("pid"),
  "status":env.get("status"),
  "cwd":env.get("pm_cwd"),
  "script":env.get("pm_exec_path"),
}
if (
  observed["status"] != "online"
  or not isinstance(observed["pid"],int)
  or observed["pid"] < 1
  or os.path.realpath(observed["cwd"] or "/") != os.path.realpath(expected_cwd)
  or os.path.realpath(observed["script"] or "/") != os.path.realpath(expected_script)
):
  raise SystemExit(f"candidate PM2 runtime is not the immutable package command: {observed}")
json.dump({"status":"PASS",**observed},sys.stdout,indent=2);sys.stdout.write("\n")
PYCANDIDATEPM2
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
validate_release_report() {
  python3 - "$1" "$2" <<'PYRELEASEREPORT'
import json,sys
path,mode=sys.argv[1:]
value=json.load(open(path,encoding="utf-8"))
if value.get("mode") != mode:
  raise SystemExit(f"release report mode mismatch: {value.get('mode')}")
if mode == "pre-stage":
  valid=(
    value.get("status") == "PRE_STAGE_PASS"
    and value.get("finalReleaseEligible") is False
    and value.get("revision3Nfr",{}).get("gate") == "G08"
    and value.get("revision3Nfr",{}).get("status") == "NOT_RUN"
    and value.get("revision3Nfr",{}).get("releaseEligible") is False
  )
else:
  valid=(
    value.get("status") == "PASS"
    and value.get("finalReleaseEligible") is True
    and value.get("revision3Nfr",{}).get("status") == "BASE_PROFILE_NFR_PASS"
    and value.get("revision3Nfr",{}).get("releaseEligible") is True
  )
if not valid:
  raise SystemExit(f"release report is not eligible for {mode}: {json.dumps(value.get('revision3Nfr',{}),sort_keys=True)}")
PYRELEASEREPORT
}

PUBLIC_BASE_URL="$(read_env DEVSPACE_NEXT_PUBLIC_BASE_URL)"
TARGETS_FILE="$(read_env DEVSPACE_NEXT_TARGETS_FILE)"
ROUTES_FILE="$(read_env DEVSPACE_NEXT_MCP_ROUTES_FILE)"
ENV_PROFILES_FILE="$(read_env DEVSPACE_NEXT_ENV_PROFILE_CONFIG)"
ALLOWED_HOSTS="$(read_env DEVSPACE_NEXT_ALLOWED_HOSTS)"
PRODUCTION_STATE_DIR="$(read_env DEVSPACE_NEXT_STATE_DIR)"
CONFIGURED_OAUTH_STATE_DIR="$(read_env DEVSPACE_NEXT_OAUTH_STATE_DIR)"
EXISTING_OWNER_INSTANCE_ID="$(read_env DEVSPACE_NEXT_AUTHORITY_OWNER_INSTANCE_ID)"
CANONICAL_CONNECTOR_NAME="$(read_env DEVSPACE_OAUTH_CANONICAL_CONNECTOR_NAME)"
CONNECTOR_INSTALLATION_EPOCH="$(read_env DEVSPACE_OAUTH_CONNECTOR_INSTALLATION_EPOCH)"
[[ -n "$PUBLIC_BASE_URL" && -n "$TARGETS_FILE" && -n "$ROUTES_FILE" && -n "$ENV_PROFILES_FILE" ]] || {
  echo "Current production environment lacks required v2 paths." >&2
  exit 1
}
TARGETS_FILE="$(absolute_path "$TARGETS_FILE")"
ROUTES_FILE="$(absolute_path "$ROUTES_FILE")"
ENV_PROFILES_FILE="$(absolute_path "$ENV_PROFILES_FILE")"
PUBLIC_BASE_URL="${PUBLIC_BASE_URL%/}"
PUBLIC_HOST="$(python3 -c 'from urllib.parse import urlparse; import sys; print(urlparse(sys.argv[1]).hostname or "")' "$PUBLIC_BASE_URL")"
[[ -n "$PUBLIC_HOST" ]] || { echo "Public base URL has no host: $PUBLIC_BASE_URL" >&2; exit 1; }
[[ -n "$ALLOWED_HOSTS" ]] || ALLOWED_HOSTS="localhost,127.0.0.1,::1,$PUBLIC_HOST,127.0.0.1:$PRODUCTION_PORT,127.0.0.1:$CANDIDATE_PORT"
[[ -n "$CANDIDATE_PUBLIC_BASE_URL" ]] || {
  echo "--candidate-public-base-url is required; production public health cannot prove candidate identity." >&2
  exit 1
}
CANDIDATE_PUBLIC_URL_TSV="$(python3 - "$CANDIDATE_PUBLIC_BASE_URL" <<'PYCANDIDATEURL'
import ipaddress,sys
from urllib.parse import urlparse
value=urlparse(sys.argv[1])
if value.scheme != "https" or not value.hostname or value.username or value.password or value.query or value.fragment or value.path not in {"", "/"}:
  raise SystemExit("candidate public base URL must be a credential-free HTTPS origin without path, query, or fragment")
try:
  if ipaddress.ip_address(value.hostname).is_loopback:
    raise SystemExit("candidate public base URL must not be loopback")
except ValueError:
  if value.hostname.lower() == "localhost":
    raise SystemExit("candidate public base URL must not be localhost")
origin=f"{value.scheme}://{value.netloc}"
print(origin,value.hostname,value.netloc,sep="\t")
PYCANDIDATEURL
)" || { echo "Invalid --candidate-public-base-url: $CANDIDATE_PUBLIC_BASE_URL" >&2; exit 1; }
IFS=$'\t' read -r CANDIDATE_PUBLIC_BASE_URL CANDIDATE_PUBLIC_HOST CANDIDATE_PUBLIC_AUTHORITY <<<"$CANDIDATE_PUBLIC_URL_TSV"
PRODUCTION_PUBLIC_ORIGIN="$(python3 -c 'from urllib.parse import urlparse; import sys; value=urlparse(sys.argv[1]); print(f"{value.scheme}://{value.netloc}")' "$PUBLIC_BASE_URL")"
[[ "$CANDIDATE_PUBLIC_BASE_URL" != "$PRODUCTION_PUBLIC_ORIGIN" ]] || {
  echo "Candidate public origin must be isolated from production: $CANDIDATE_PUBLIC_BASE_URL" >&2
  exit 1
}
CANDIDATE_ALLOWED_HOSTS="${ALLOWED_HOSTS},localhost,127.0.0.1,::1,127.0.0.1:${CANDIDATE_PORT},${CANDIDATE_PUBLIC_HOST},${CANDIDATE_PUBLIC_AUTHORITY}"
[[ -n "$PRODUCTION_STATE_DIR" ]] || PRODUCTION_STATE_DIR="${HOME}/.local/share/devspace/universal-broker-v2-production"
PRODUCTION_STATE_DIR="$(absolute_path "$PRODUCTION_STATE_DIR")"
PRODUCTION_LIFECYCLE_FINALIZATION_STORE="$(read_env DEVSPACE_NEXT_LIFECYCLE_FINALIZATION_STORE)"
PRODUCTION_LIFECYCLE_FINALIZATION_STORE="$(absolute_path "${PRODUCTION_LIFECYCLE_FINALIZATION_STORE:-$PRODUCTION_STATE_DIR/lifecycle.sqlite}")"
PRODUCTION_LIFECYCLE_FINALIZATION_CONTROL="$(read_env DEVSPACE_NEXT_LIFECYCLE_FINALIZATION_CONTROL)"
PRODUCTION_LIFECYCLE_FINALIZATION_CONTROL="$(absolute_path "${PRODUCTION_LIFECYCLE_FINALIZATION_CONTROL:-$(dirname "$PRODUCTION_STATE_DIR")/$(basename "$PRODUCTION_STATE_DIR")-finalization-control/lifecycle-finalization-head.json}")"
CANONICAL_CONNECTOR_NAME="${CANONICAL_CONNECTOR_NAME:-myDevSpace}"
CONNECTOR_INSTALLATION_EPOCH="${CONNECTOR_INSTALLATION_EPOCH:-1}"
[[ "$CANONICAL_CONNECTOR_NAME" =~ ^[A-Za-z][A-Za-z0-9._-]{0,127}$ ]] || { echo "Canonical connector name is invalid." >&2; exit 1; }
[[ "$CONNECTOR_INSTALLATION_EPOCH" =~ ^[1-9][0-9]*$ ]] || { echo "Connector installation epoch is invalid." >&2; exit 1; }
OWNER_INSTANCE_ID="$(node "$ROOT/scripts/ensure-owner-instance-id.mjs" "$IDENTITY_DIRECTORY")"
[[ -z "$EXISTING_OWNER_INSTANCE_ID" || "$EXISTING_OWNER_INSTANCE_ID" == "$OWNER_INSTANCE_ID" ]] || {
  echo "Production ownerInstanceId differs from the stable provisioned identity." >&2
  exit 1
}
for gate_path in "$GATE_PRODUCER_PRIVATE_KEY" "$GATE_PRODUCER_TRUST_ANCHOR"; do
  [[ -f "$gate_path" && ! -L "$gate_path" ]] || { echo "Gate producer material is missing: $gate_path" >&2; exit 1; }
done
GATE_PRODUCER_TRUST_ANCHOR_SHA256="$(file_sha256 "$GATE_PRODUCER_TRUST_ANCHOR")"
RELEASE_TRUST_ARGS=(
  --gate-producer-trust-anchor "$GATE_PRODUCER_TRUST_ANCHOR"
  --gate-producer-trust-anchor-sha256 "$GATE_PRODUCER_TRUST_ANCHOR_SHA256"
  --management-key-ref "$PRODUCTION_MANAGEMENT_AUTHORIZATION_KEY"
  --state-dir "$(dirname "$PRODUCTION_MANAGEMENT_AUTHORIZATION_KEY")"
  --owner-instance-id "$OWNER_INSTANCE_ID"
  --environment PRODUCTION
)
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
PRODUCTION_AUTHORITY_STORE="$(read_env DEVSPACE_NEXT_AUTHORITY_STORE)"
PRODUCTION_AUTHORITY_STORE="$(absolute_path "${PRODUCTION_AUTHORITY_STORE:-$PRODUCTION_STATE_DIR/authority.sqlite}")"
PRODUCTION_AUTHORITY_STATE_DIR="$(read_env DEVSPACE_NEXT_AUTHORITY_STATE_DIR)"
PRODUCTION_AUTHORITY_STATE_DIR="$(absolute_path "${PRODUCTION_AUTHORITY_STATE_DIR:-$(dirname "$PRODUCTION_AUTHORITY_STORE")}")"
PRODUCTION_AUTHORITY_DATABASE="$PRODUCTION_AUTHORITY_STORE"
[[ -f "$PRODUCTION_AUTHORITY_DATABASE" ]] || {
  echo "Production authority database is missing: $PRODUCTION_AUTHORITY_DATABASE" >&2
  exit 1
}
PRODUCTION_CONNECTOR_ACTIVATION_JOURNAL="$(read_env DEVSPACE_NEXT_CONNECTOR_ACTIVATION_JOURNAL)"
PRODUCTION_CONNECTOR_ACTIVATION_JOURNAL="$(absolute_path "${PRODUCTION_CONNECTOR_ACTIVATION_JOURNAL:-$PRODUCTION_STATE_DIR/connector-activation-journal.sqlite}")"
PRODUCTION_CONTEXT_STORE="$(read_env DEVSPACE_NEXT_CONTEXT_STORE)"
PRODUCTION_CONTEXT_STORE="$(absolute_path "${PRODUCTION_CONTEXT_STORE:-$PRODUCTION_STATE_DIR/contexts.json}")"
PRODUCTION_CONTEXT_WORKTREE_ROOT="$(read_env DEVSPACE_NEXT_CONTEXT_WORKTREE_ROOT)"
PRODUCTION_CONTEXT_WORKTREE_ROOT="$(absolute_path "${PRODUCTION_CONTEXT_WORKTREE_ROOT:-$PRODUCTION_STATE_DIR/worktrees}")"
PRODUCTION_FILESYSTEM_SYNC_STORE="$(absolute_path "$PRODUCTION_STATE_DIR/filesystem-sync/sync.sqlite")"
PRODUCTION_PROCESS_OUTPUT_DIR="$(read_env DEVSPACE_NEXT_PROCESS_OUTPUT_DIR)"
PRODUCTION_PROCESS_OUTPUT_DIR="$(absolute_path "${PRODUCTION_PROCESS_OUTPUT_DIR:-$PRODUCTION_STATE_DIR/process-output}")"
PRODUCTION_SSH_CONTROL_DIR="$(read_env DEVSPACE_NEXT_SSH_CONTROL_DIR)"
PRODUCTION_SSH_CONTROL_DIR="$(absolute_path "${PRODUCTION_SSH_CONTROL_DIR:-${HOME}/.devspace/run/v2-ssh}")"
PRODUCTION_PROCESS_STATE_DIR="$(absolute_path "$(dirname "$PRODUCTION_PROCESS_OUTPUT_DIR")/processes")"
PRODUCTION_ARTIFACT_STAGING_DIR="$(read_env DEVSPACE_NEXT_ARTIFACT_STAGING_DIR)"
PRODUCTION_ARTIFACT_STAGING_DIR="$(absolute_path "${PRODUCTION_ARTIFACT_STAGING_DIR:-$PRODUCTION_STATE_DIR/artifacts}")"
PRODUCTION_ARTIFACT_CATALOG="$(read_env DEVSPACE_NEXT_ARTIFACT_CATALOG)"
PRODUCTION_ARTIFACT_CATALOG="$(absolute_path "${PRODUCTION_ARTIFACT_CATALOG:-$PRODUCTION_STATE_DIR/artifacts.sqlite}")"
PRODUCTION_ARTIFACT_OBJECT_ROOT="$(read_env DEVSPACE_NEXT_ARTIFACT_OBJECT_ROOT)"
PRODUCTION_ARTIFACT_OBJECT_ROOT="$(absolute_path "${PRODUCTION_ARTIFACT_OBJECT_ROOT:-$PRODUCTION_STATE_DIR/artifact-objects}")"
PRODUCTION_ARTIFACT_QUARANTINE_ROOT="$(absolute_path "$PRODUCTION_ARTIFACT_STAGING_DIR/quarantine")"
PRODUCTION_SELF_MANAGEMENT_DIR="$(read_env DEVSPACE_NEXT_SELF_MANAGEMENT_DIR)"
PRODUCTION_SELF_MANAGEMENT_DIR="$(absolute_path "${PRODUCTION_SELF_MANAGEMENT_DIR:-$PRODUCTION_STATE_DIR/self-management}")"
PRODUCTION_AUDIT_SINK="$(read_env DEVSPACE_NEXT_AUDIT_SINK)"
PRODUCTION_AUDIT_SINK="$(absolute_path "${PRODUCTION_AUDIT_SINK:-$PRODUCTION_STATE_DIR/audit/operations.jsonl}")"
PRODUCTION_CURSOR_CURRENT_KEY="$(read_env DEVSPACE_NEXT_CURSOR_SIGNING_KEY_REF)"
PRODUCTION_CURSOR_CURRENT_KEY="$(absolute_path "${PRODUCTION_CURSOR_CURRENT_KEY:-$PRODUCTION_STATE_DIR/cursor-hmac-current.key}")"
PRODUCTION_CURSOR_PREVIOUS_KEY="$(read_env DEVSPACE_NEXT_CURSOR_PREVIOUS_SIGNING_KEY_REF)"
if [[ -n "$PRODUCTION_CURSOR_PREVIOUS_KEY" ]]; then
  PRODUCTION_CURSOR_PREVIOUS_KEY="$(absolute_path "$PRODUCTION_CURSOR_PREVIOUS_KEY")"
fi
PRODUCTION_MANAGEMENT_AUTHORIZATION_KEY="$(read_env DEVSPACE_NEXT_MANAGEMENT_AUTHORIZATION_KEY_REF)"
PRODUCTION_MANAGEMENT_AUTHORIZATION_KEY="$(absolute_path "${PRODUCTION_MANAGEMENT_AUTHORIZATION_KEY:-$PRODUCTION_STATE_DIR/management-authorization.key}")"
PREVIOUS_AUDIT_TARGET=""
if [[ -L "$CURRENT_AUDIT_LINK" ]]; then
  PREVIOUS_AUDIT_TARGET="$(python3 -c 'import os,sys; print(os.path.realpath(sys.argv[1]))' "$CURRENT_AUDIT_LINK")"
fi
PREVIOUS_BUILD_MANIFEST="$(read_env DEVSPACE_RELEASE_MANIFEST)"
PREVIOUS_BUILD_MANIFEST="$(absolute_path "${PREVIOUS_BUILD_MANIFEST:-$PREVIOUS_CWD/BUILD-MANIFEST.json}")"
[[ -f "$PREVIOUS_BUILD_MANIFEST" ]] || {
  echo "Previous immutable build manifest is missing: $PREVIOUS_BUILD_MANIFEST" >&2
  exit 1
}
PREVIOUS_MIGRATION_MANIFEST_DIGEST="$(node -e '
const value=require(process.argv[1]);
if (!/^sha256:[a-f0-9]{64}$/.test(value.migrationManifestDigest ?? "")) process.exit(65);
process.stdout.write(value.migrationManifestDigest);
' "$PREVIOUS_BUILD_MANIFEST")"
PRODUCTION_MANAGEMENT_PORT="$((PRODUCTION_PORT <= 64535 ? PRODUCTION_PORT + 1000 : PRODUCTION_PORT - 1000))"
PREVIOUS_LOCAL_HEALTH_URL="http://127.0.0.1:${PRODUCTION_PORT}/healthz"
PREVIOUS_LOCAL_READY_URL="http://127.0.0.1:${PRODUCTION_MANAGEMENT_PORT}/readyz"
LOCAL_DOCTOR_URL="http://127.0.0.1:${PRODUCTION_MANAGEMENT_PORT}/doctorz"

STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
REQUESTED_AT="$(python3 -c 'import datetime; print(datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="microseconds").replace("+00:00","Z"))')"
TRANSACTION_ID="upgrade_$(python3 -c 'import uuid; print(uuid.uuid4())')"
TRANSACTION_UUID="${TRANSACTION_ID#upgrade_}"
PM2_WORKER_NAME="devspace-v2-upgrade-${TRANSACTION_UUID:0:8}"
AUDIT_DIR="${DEPLOYMENT_ROOT}/upgrade-${STAMP}-${HEAD:0:12}"
[[ ! -e "$AUDIT_DIR" ]] || { echo "Audit directory already exists: $AUDIT_DIR" >&2; exit 1; }
mkdir -m 700 "$AUDIT_DIR"
STATUS_PATH="$AUDIT_DIR/status.json"
REQUEST_PATH="$AUDIT_DIR/request.json"
WORKER_LOG="$AUDIT_DIR/worker.log"
SCHEDULER_EVIDENCE="$AUDIT_DIR/scheduler.json"
CLEANUP_MONITOR_LOG="$AUDIT_DIR/scheduler-cleanup.log"
CONNECTOR_EVIDENCE_DIR="$AUDIT_DIR/connector-evidence"
CONNECTOR_REQUEST_DIR="$CONNECTOR_EVIDENCE_DIR/requests"
CONNECTOR_DRIVER_SUMMARY_DIR="$CONNECTOR_EVIDENCE_DIR/driver-summaries"
STAGING_PRECHECK_REQUEST_AUDIT="$CONNECTOR_REQUEST_DIR/staging-precheck.json"
STAGING_ACTIVATION_REQUEST_AUDIT="$CONNECTOR_REQUEST_DIR/staging-activation.json"
PRE_CUTOVER_REQUEST_AUDIT="$CONNECTOR_REQUEST_DIR/pre-cutover.json"
PRODUCTION_PREDECISION_REQUEST_AUDIT="$CONNECTOR_REQUEST_DIR/production-predecision.json"
PRODUCTION_PREPARATION_REQUEST_AUDIT="$CONNECTOR_REQUEST_DIR/production-preparation.json"
ROLLBACK_CHALLENGE_REQUEST_AUDIT="$CONNECTOR_REQUEST_DIR/rollback-challenge.json"
STAGING_PRECHECK_ARTIFACT="$CONNECTOR_EVIDENCE_DIR/staging-activation-precheck.json"
STAGING_ACTIVATION_READBACK="$CONNECTOR_EVIDENCE_DIR/staging-activation-readback.json"
PRE_CUTOVER_ARTIFACT="$CONNECTOR_EVIDENCE_DIR/pre-cutover-host-canary.json"
PRODUCTION_APPROVAL_DIRECTORY="$CONNECTOR_EVIDENCE_DIR/production-approval"
PRODUCTION_PREDECISION_ARTIFACT="$CONNECTOR_EVIDENCE_DIR/production-predecision.json"
PRODUCTION_APPROVAL_MANIFEST="$PRODUCTION_APPROVAL_DIRECTORY/manifest.json"
PRODUCTION_ACTIVATION_PRECHECK_ARTIFACT="$PRODUCTION_APPROVAL_DIRECTORY/production-activation-precheck.json"
OWNER_APPROVAL_ARTIFACT="$PRODUCTION_APPROVAL_DIRECTORY/owner-management-approval.json"
ROLLBACK_HOST_CHALLENGE="$CONNECTOR_EVIDENCE_DIR/rollback-host-challenge.json"
ROLLBACK_HOST_RECEIPT="$CONNECTOR_EVIDENCE_DIR/rollback-host-receipt.json"
POST_ACTIVATION_CHALLENGE="$CONNECTOR_EVIDENCE_DIR/post-activation-challenge.json"
POST_ACTIVATION_RECEIPT="$CONNECTOR_EVIDENCE_DIR/post-activation-host-canary.json"
ROLLBACK_JOURNAL_PATH="$AUDIT_DIR/rollback-control.jsonl"
mkdir -m 700 "$CONNECTOR_EVIDENCE_DIR" "$CONNECTOR_REQUEST_DIR" "$CONNECTOR_DRIVER_SUMMARY_DIR"
PREVIOUS_READY_EVIDENCE="$AUDIT_DIR/previous-runtime-ready.json"
curl -fsS --max-time 10 "$PREVIOUS_LOCAL_READY_URL" >"$PREVIOUS_READY_EVIDENCE"
chmod 600 "$PREVIOUS_READY_EVIDENCE"
PREVIOUS_RUNTIME_IDENTITY_DIGEST="$(node - "$PREVIOUS_READY_EVIDENCE" <<'NODEPREVIOUSIDENTITY'
const { createHash } = require("node:crypto");
const { readFileSync } = require("node:fs");
const value = JSON.parse(readFileSync(process.argv[2], "utf8"));
if (value?.status !== "ready" || !value.identity || typeof value.identity !== "object" || Array.isArray(value.identity)) {
  process.exit(65);
}
const stable = (item) => {
  if (Array.isArray(item)) return `[${item.map(stable).join(",")}]`;
  if (item && typeof item === "object") return `{${Object.entries(item)
    .filter(([,child]) => child !== undefined)
    .sort(([left],[right]) => left < right ? -1 : left > right ? 1 : 0)
    .map(([key,child]) => `${JSON.stringify(key)}:${stable(child)}`).join(",")}}`;
  return JSON.stringify(item) ?? "null";
};
process.stdout.write(`sha256:${createHash("sha256").update(stable(value.identity)).digest("hex")}`);
NODEPREVIOUSIDENTITY
)"
RELEASE="$RELEASE_ROOT/$HEAD"
FINAL_IMMUTABLE_RELEASE="$RELEASE_ROOT/${HEAD}-package"
STAGING_RELEASE="$RELEASE_ROOT/${HEAD}-staging-fixture"
IMMUTABLE_RELEASE="$STAGING_RELEASE"
NEW_SCRIPT=""
CANDIDATE_NAME="devspace-v2-candidate-${HEAD:0:8}"
CANDIDATE_STATE="$AUDIT_DIR/candidate-state"
CANDIDATE_OAUTH_STATE="$CANDIDATE_STATE/oauth"
CANDIDATE_AUTHORITY_STATE_DIR="$CANDIDATE_STATE/authority"
CANDIDATE_AUTHORITY_STORE="$CANDIDATE_AUTHORITY_STATE_DIR/authority.sqlite"
CANDIDATE_CONNECTOR_ACTIVATION_JOURNAL="$CANDIDATE_STATE/connector-activation-journal.sqlite"
CANDIDATE_LIFECYCLE_FINALIZATION_STORE="$CANDIDATE_STATE/lifecycle.sqlite"
CANDIDATE_LIFECYCLE_FINALIZATION_CONTROL="$AUDIT_DIR/candidate-finalization-control/lifecycle-finalization-head.json"
CANDIDATE_CONTEXT_STORE="$CANDIDATE_STATE/contexts.json"
CANDIDATE_CONTEXT_WORKTREE_ROOT="$CANDIDATE_STATE/worktrees"
CANDIDATE_PROCESS_OUTPUT_DIR="$CANDIDATE_STATE/process-output"
CANDIDATE_SSH_CONTROL_DIR="$CANDIDATE_STATE/ssh-control"
CANDIDATE_ARTIFACT_STAGING_DIR="$CANDIDATE_STATE/artifacts"
CANDIDATE_ARTIFACT_CATALOG="$CANDIDATE_STATE/artifacts.sqlite"
CANDIDATE_ARTIFACT_OBJECT_ROOT="$CANDIDATE_STATE/artifact-objects"
CANDIDATE_AUDIT_SINK="$CANDIDATE_STATE/audit/operations.jsonl"
CANDIDATE_CURSOR_CURRENT_KEY="$CANDIDATE_STATE/cursor-hmac-current.key"
CANDIDATE_CURSOR_PREVIOUS_KEY=""
CANDIDATE_MANAGEMENT_AUTHORIZATION_KEY="$CANDIDATE_STATE/management-authorization.key"
CANDIDATE_ENV="$AUDIT_DIR/candidate.env"
NEXT_ENV="$AUDIT_DIR/production.env.next"
ENV_BACKUP="$AUDIT_DIR/production.env.before"
START_BACKUP="$AUDIT_DIR/start.sh.before"
LIVE_EVIDENCE="$AUDIT_DIR/candidate-live.json"
SELF_RESTART_EVIDENCE="$AUDIT_DIR/candidate-self-restart.json"
CANDIDATE_PM2_EVIDENCE="$AUDIT_DIR/candidate-pm2-runtime.json"
CANDIDATE_CLEANUP_EVIDENCE="$AUDIT_DIR/candidate-cleanup.json"
NPM_CI_LOG="$AUDIT_DIR/npm-ci.log"
PRE_STAGE_VERIFY_LOG="$AUDIT_DIR/release-verify-pre-stage.log"
PRE_STAGE_VERIFY_REPORT="$AUDIT_DIR/release-verify-pre-stage.json"
RELEASE_VERIFY_LOG="$AUDIT_DIR/release-verify-candidate-nfr.log"
RELEASE_VERIFY_REPORT="$AUDIT_DIR/release-verify-candidate-nfr.json"
if [[ "$SKIP_COMPANY_GATES" == 1 ]]; then
  FULL_LOAD_LOG="$AUDIT_DIR/full-load-company-skipped.json"
else
  FULL_LOAD_LOG="$AUDIT_DIR/full-load-real-${SSH_LOAD_TARGET}.log"
fi
RELEASE_CREATED=0
UPGRADE_SCHEDULED=0
RUNTIME_DEPENDENCY_STAGING=""

cleanup_candidate_before_cutover() {
  node "$ROOT/scripts/lib/release-candidate-cleanup.mjs" cleanup \
    --pm2 "$PM2_EXECUTABLE" --lsof "$(command -v lsof)" \
    --name "$CANDIDATE_NAME" --port "$CANDIDATE_PORT" \
    --state "$CANDIDATE_STATE" --evidence "$CANDIDATE_CLEANUP_EVIDENCE" \
    >"$AUDIT_DIR/candidate-cleanup-command.json"
}
cleanup_candidate_best_effort() {
  pm2 delete "$CANDIDATE_NAME" >/dev/null 2>&1 || true
  pm2 save >/dev/null 2>&1 || true
  rm -rf "$CANDIDATE_STATE"
}
cleanup_on_exit() {
  if [[ "$UPGRADE_SCHEDULED" != 1 ]]; then
    cleanup_candidate_best_effort
    if [[ -n "${STAGING_RELEASE:-}" && -d "$STAGING_RELEASE" ]]; then
      rm -rf "$STAGING_RELEASE" || true
    fi
  fi
  if [[ -n "$RUNTIME_DEPENDENCY_STAGING" && -e "$RUNTIME_DEPENDENCY_STAGING" ]]; then
    rm -rf "$RUNTIME_DEPENDENCY_STAGING" || true
  fi
  if [[ "$UPGRADE_SCHEDULED" != 1 && "$RELEASE_CREATED" == 1 && -e "$RELEASE" ]]; then
    git -C "$SOURCE" worktree remove --force "$RELEASE" >/dev/null 2>&1 || true
    git -C "$SOURCE" worktree prune >/dev/null 2>&1 || true
  fi
}
trap cleanup_on_exit EXIT

acquire_timeout_claim_guard() {
  local status_path="$1" shell_pid="$2"
  python3 - "$status_path" "$shell_pid" <<'PYTIMEOUTCLAIM'
import datetime,json,os,re,stat,sys,uuid
status_path=os.path.abspath(sys.argv[1]);shell_pid=int(sys.argv[2])
claim_path=status_path+".worker-claim.json"
def read_owner_json(path):
  descriptor=os.open(path,os.O_RDONLY|getattr(os,"O_NOFOLLOW",0))
  try:
    metadata=os.fstat(descriptor)
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != os.getuid() or metadata.st_mode & 0o077:
      raise SystemExit(f"owner-only JSON file identity is invalid: {path}")
    chunks=[];size=0
    while True:
      chunk=os.read(descriptor,65536)
      if not chunk: break
      size+=len(chunk)
      if size > 1024*1024: raise SystemExit(f"owner-only JSON file is too large: {path}")
      chunks.append(chunk)
  finally:
    os.close(descriptor)
  return json.loads(b"".join(chunks))
parent=os.path.dirname(claim_path)
parent_stat=os.lstat(parent)
if not stat.S_ISDIR(parent_stat.st_mode) or stat.S_ISLNK(parent_stat.st_mode):
  raise SystemExit("worker-claim parent is not a real directory")
if parent_stat.st_uid != os.getuid() or parent_stat.st_mode & 0o077 or os.path.realpath(parent) != parent:
  raise SystemExit("worker-claim parent is not owner-only canonical state")
status_stat=os.lstat(status_path)
if not stat.S_ISREG(status_stat.st_mode) or stat.S_ISLNK(status_stat.st_mode):
  raise SystemExit("upgrade status is not a regular file")
if status_stat.st_uid != os.getuid() or status_stat.st_mode & 0o077:
  raise SystemExit("upgrade status is not owner-only")
status=read_owner_json(status_path)
transaction_id=status.get("transactionId")
binding=status.get("requestBindingDigest")
if status.get("version") != 2 or status.get("state") != "PREPARED" or status.get("workerClaim") is not None:
  raise SystemExit(77)
if not isinstance(transaction_id,str) or not re.fullmatch(r"[A-Za-z0-9._-]{1,128}",transaction_id):
  raise SystemExit("upgrade status transaction identity is invalid")
if not isinstance(binding,str) or not re.fullmatch(r"sha256:[a-f0-9]{64}",binding):
  raise SystemExit("upgrade status request binding is invalid")
claim={
  "schemaVersion":1,
  "claimId":str(uuid.uuid4()),
  "claimPath":claim_path,
  "transactionId":transaction_id,
  "requestBindingDigest":binding,
  "pid":shell_pid,
  "acquiredAt":datetime.datetime.now(datetime.timezone.utc).isoformat(),
}
flags=os.O_WRONLY|os.O_CREAT|os.O_EXCL|getattr(os,"O_NOFOLLOW",0)
try:
  descriptor=os.open(claim_path,flags,0o600)
except FileExistsError:
  metadata=os.lstat(claim_path)
  if not stat.S_ISREG(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
    raise SystemExit(76)
  if metadata.st_uid != os.getuid() or metadata.st_mode & 0o077:
    raise SystemExit(76)
  try:
    existing=read_owner_json(claim_path)
    pid=existing.get("pid")
    matching=(
      existing.get("schemaVersion") == 1
      and existing.get("claimPath") == claim_path
      and existing.get("transactionId") == transaction_id
      and existing.get("requestBindingDigest") == binding
      and isinstance(existing.get("claimId"),str)
      and isinstance(pid,int) and pid > 0
    )
    if matching:
      os.kill(pid,0)
      raise SystemExit(75)
  except (OSError,ValueError,TypeError,json.JSONDecodeError):
    pass
  raise SystemExit(76)
try:
  payload=(json.dumps(claim,indent=2)+"\n").encode()
  os.write(descriptor,payload);os.fsync(descriptor)
finally:
  os.close(descriptor)
os.chmod(claim_path,0o600)
directory=os.open(parent,os.O_RDONLY)
try: os.fsync(directory)
finally: os.close(directory)
print(claim["claimId"])
PYTIMEOUTCLAIM
}

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
  npm run release:verify -- --mode=pre-stage --require-clean --report "$PRE_STAGE_VERIFY_REPORT" 2>&1 | tee "$PRE_STAGE_VERIFY_LOG"
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
validate_release_report "$PRE_STAGE_VERIFY_REPORT" pre-stage
if [[ -d "$STAGING_RELEASE" ]]; then
  node "$RELEASE/scripts/release-artifacts.mjs" verify \
    --staging-fixture true --package "$STAGING_RELEASE" \
    --source-revision "$HEAD" --runtime-revision "$HEAD" \
    >"$AUDIT_DIR/staging-release.json"
else
  (
    cd "$RELEASE"
    node scripts/release-artifacts.mjs create-staging-fixture \
      --source . --output "$STAGING_RELEASE" --source-revision "$HEAD" --runtime-revision "$HEAD"
  ) >"$AUDIT_DIR/staging-release.json"
fi
BUILD_MANIFEST="$IMMUTABLE_RELEASE/BUILD-MANIFEST.json"
MANIFEST_TSV="$(node -e '
const v=require(process.argv[1]);
process.stdout.write([
  v.sourceRevision,v.runtimeRevision,v.buildDigest,v.schemaGeneration,v.authorityContractGeneration,v.configSchemaIdentity,
  v.runtime?.cwd,v.runtime?.entrypoint,v.runtime?.dependencies?.lockfileSha256,v.migrationManifestDigest,
].join("\t"));
' "$BUILD_MANIFEST")"
IFS=$'\t' read -r MANIFEST_SOURCE_REVISION MANIFEST_RUNTIME_REVISION MANIFEST_BUILD_DIGEST MANIFEST_SCHEMA_GENERATION MANIFEST_AUTHORITY_GENERATION MANIFEST_CONFIG_SCHEMA_IDENTITY MANIFEST_RUNTIME_CWD MANIFEST_RUNTIME_ENTRYPOINT MANIFEST_DEPENDENCY_LOCK_SHA256 MANIFEST_MIGRATION_DIGEST <<<"$MANIFEST_TSV"
[[ "$MANIFEST_SOURCE_REVISION" == "$HEAD" && "$MANIFEST_RUNTIME_REVISION" == "$HEAD" ]] || {
  echo "Immutable release manifest revision does not bind the upgrade HEAD." >&2
  exit 1
}
BUILD_MANIFEST_SHA256="sha256:$(shasum -a 256 "$BUILD_MANIFEST" | awk '{print $1}')"
[[ "$MANIFEST_RUNTIME_CWD" == "." && "$MANIFEST_RUNTIME_ENTRYPOINT" == "scripts/start-universal-broker-v2-production.sh" ]] || {
  echo "Immutable release manifest has an unsupported runtime command." >&2
  exit 1
}
[[ "$MANIFEST_MIGRATION_DIGEST" =~ ^sha256:[a-f0-9]{64}$ ]] || {
  echo "Immutable release manifest has no canonical global migration digest." >&2
  exit 1
}
IMMUTABLE_RUNTIME_ROOT="$IMMUTABLE_RELEASE"
IMMUTABLE_RUNTIME_ENTRYPOINT="$IMMUTABLE_RELEASE/$MANIFEST_RUNTIME_ENTRYPOINT"
NEW_SCRIPT="$IMMUTABLE_RUNTIME_ENTRYPOINT"
node "$IMMUTABLE_RELEASE/scripts/release-artifacts.mjs" verify-runtime-command \
  --staging-fixture true \
  --package "$IMMUTABLE_RELEASE" --runtime-root "$IMMUTABLE_RUNTIME_ROOT" --entrypoint "$IMMUTABLE_RUNTIME_ENTRYPOINT" \
  --manifest-sha256 "$BUILD_MANIFEST_SHA256" \
  >"$AUDIT_DIR/immutable-runtime-command.json"
DEPENDENCY_LOCK_HEX="${MANIFEST_DEPENDENCY_LOCK_SHA256#sha256:}"
[[ "$DEPENDENCY_LOCK_HEX" =~ ^[0-9a-f]{64}$ ]] || { echo "Immutable release dependency lock digest is invalid." >&2; exit 1; }
RUNTIME_DEPENDENCY_ROOT="$RELEASE_ROOT/${HEAD}-dependencies-${DEPENDENCY_LOCK_HEX:0:16}"
RUNTIME_DEPENDENCY_EVIDENCE="$RUNTIME_DEPENDENCY_ROOT/RUNTIME-DEPENDENCIES.json"
if [[ -d "$RUNTIME_DEPENDENCY_ROOT" ]]; then
  node "$IMMUTABLE_RELEASE/scripts/release-artifacts.mjs" verify-runtime-dependencies \
    --staging-fixture true \
    --package "$IMMUTABLE_RELEASE" --dependency-root "$RUNTIME_DEPENDENCY_ROOT" \
    --evidence "$RUNTIME_DEPENDENCY_EVIDENCE" \
    >"$AUDIT_DIR/runtime-dependencies-existing.json"
else
  RUNTIME_DEPENDENCY_STAGING="$(mktemp -d "$RELEASE_ROOT/.runtime-dependencies-${HEAD:0:12}.XXXXXX")"
  cp -p "$IMMUTABLE_RELEASE/package.json" "$IMMUTABLE_RELEASE/package-lock.json" "$RUNTIME_DEPENDENCY_STAGING/"
  [[ -d "$RELEASE/node_modules" ]] || { echo "npm ci did not materialize runtime dependencies." >&2; exit 1; }
  mv "$RELEASE/node_modules" "$RUNTIME_DEPENDENCY_STAGING/node_modules"
  node "$IMMUTABLE_RELEASE/scripts/release-artifacts.mjs" seal-runtime-dependencies \
    --staging-fixture true \
    --package "$IMMUTABLE_RELEASE" --dependency-root "$RUNTIME_DEPENDENCY_STAGING" \
    >"$AUDIT_DIR/runtime-dependencies-sealed.json"
  mv "$RUNTIME_DEPENDENCY_STAGING" "$RUNTIME_DEPENDENCY_ROOT"
  RUNTIME_DEPENDENCY_STAGING=""
fi
RUNTIME_DEPENDENCY_EVIDENCE_SHA256="sha256:$(shasum -a 256 "$RUNTIME_DEPENDENCY_EVIDENCE" | awk '{print $1}')"
node "$IMMUTABLE_RELEASE/scripts/release-artifacts.mjs" verify-runtime-dependencies \
  --staging-fixture true \
  --package "$IMMUTABLE_RELEASE" --dependency-root "$RUNTIME_DEPENDENCY_ROOT" \
  --evidence "$RUNTIME_DEPENDENCY_EVIDENCE" --evidence-sha256 "$RUNTIME_DEPENDENCY_EVIDENCE_SHA256" \
  >"$AUDIT_DIR/runtime-dependencies-verification.json"
WORKER_DEPENDENCY_LOADER="$IMMUTABLE_RUNTIME_ROOT/scripts/lib/runtime-dependency-loader.mjs"
[[ -f "$WORKER_DEPENDENCY_LOADER" ]] || { echo "Production upgrade dependency loader is missing: $WORKER_DEPENDENCY_LOADER" >&2; exit 1; }
CONNECTOR_RELEASE_DRIVER="$IMMUTABLE_RUNTIME_ROOT/scripts/connector-activation-release-driver.mjs"
[[ -f "$CONNECTOR_RELEASE_DRIVER" ]] || { echo "Immutable connector activation release driver is missing: $CONNECTOR_RELEASE_DRIVER" >&2; exit 1; }
node "$RELEASE/scripts/release-artifacts.mjs" verify-runtime-tree \
  --staging-fixture true \
  --package "$IMMUTABLE_RELEASE" --runtime-root "$RELEASE" \
  >"$AUDIT_DIR/source-runtime-equivalence.json"
DIST_EVIDENCE="$(
  cd "$IMMUTABLE_RUNTIME_ROOT"
  DEVSPACE_RUNTIME_PACKAGE_ROOT="$IMMUTABLE_RUNTIME_ROOT" \
  DEVSPACE_RUNTIME_DEPENDENCY_ROOT="$RUNTIME_DEPENDENCY_ROOT" \
    node --import "$IMMUTABLE_RUNTIME_ROOT/scripts/lib/runtime-dependency-loader.mjs" \
      --input-type=module -e \
      'import { directoryEvidence } from "./dist/v2/production-upgrade-worker.js"; console.log(JSON.stringify(await directoryEvidence(process.argv[1])));' \
      "$RELEASE/dist"
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
chmod 600 "$NPM_CI_LOG" "$PRE_STAGE_VERIFY_LOG" "$PRE_STAGE_VERIFY_REPORT" "$FULL_LOAD_LOG"
[[ -f "$NEW_SCRIPT" ]] || { echo "Immutable runtime entrypoint is missing: $NEW_SCRIPT" >&2; exit 1; }

write_env "$CANDIDATE_ENV" "$CANDIDATE_PORT" "$CANDIDATE_STATE" "$CANDIDATE_OAUTH_STATE" "$CANDIDATE_NAME" "$NEW_SCRIPT" \
  "$CANDIDATE_PUBLIC_BASE_URL" "$CANDIDATE_ALLOWED_HOSTS" \
  "$CANDIDATE_AUTHORITY_STATE_DIR" "$CANDIDATE_AUTHORITY_STORE" "$CANDIDATE_CONTEXT_STORE" "$CANDIDATE_CONTEXT_WORKTREE_ROOT" \
  "$CANDIDATE_PROCESS_OUTPUT_DIR" "$CANDIDATE_ARTIFACT_STAGING_DIR" "$CANDIDATE_ARTIFACT_CATALOG" "$CANDIDATE_ARTIFACT_OBJECT_ROOT" \
  "$CANDIDATE_AUDIT_SINK" "$CANDIDATE_CURSOR_CURRENT_KEY" "$CANDIDATE_CURSOR_PREVIOUS_KEY" "$CANDIDATE_MANAGEMENT_AUTHORIZATION_KEY" \
  "$CANDIDATE_SSH_CONTROL_DIR" "$CANDIDATE_CONNECTOR_ACTIVATION_JOURNAL" "$CANDIDATE_LIFECYCLE_FINALIZATION_STORE" \
  "$CANDIDATE_LIFECYCLE_FINALIZATION_CONTROL"
pm2 delete "$CANDIDATE_NAME" >/dev/null 2>&1 || true
run_pm2_with_environment_file "$CANDIDATE_ENV" \
  start "$IMMUTABLE_RUNTIME_ENTRYPOINT" \
  --name "$CANDIDATE_NAME" \
  --interpreter /bin/bash \
  --cwd "$IMMUTABLE_RUNTIME_ROOT" \
  --time
assert_candidate_pm2_runtime
wait_http "http://127.0.0.1:${CANDIDATE_PORT}/healthz" 200
wait_http "${CANDIDATE_PUBLIC_BASE_URL}/healthz" 200
CANDIDATE_MANAGEMENT_PORT="$((CANDIDATE_PORT <= 64535 ? CANDIDATE_PORT + 1000 : CANDIDATE_PORT - 1000))"
curl -fsS --max-time 10 "http://127.0.0.1:${CANDIDATE_PORT}/healthz" >"$AUDIT_DIR/candidate-gateway-identity.json"
node "$RELEASE/scripts/release-artifacts.mjs" verify-gateway \
  --staging-fixture true \
  --package "$IMMUTABLE_RELEASE" --identity "$AUDIT_DIR/candidate-gateway-identity.json" \
  >"$AUDIT_DIR/candidate-gateway-verification.json"
curl -fsS --max-time 10 "${CANDIDATE_PUBLIC_BASE_URL}/healthz" >"$AUDIT_DIR/candidate-public-gateway-identity.json"
node "$RELEASE/scripts/release-artifacts.mjs" verify-gateway \
  --staging-fixture true \
  --package "$IMMUTABLE_RELEASE" --identity "$AUDIT_DIR/candidate-public-gateway-identity.json" \
  >"$AUDIT_DIR/candidate-public-gateway-verification.json"
curl -fsS --max-time 10 "http://127.0.0.1:${CANDIDATE_MANAGEMENT_PORT}/readyz" >"$AUDIT_DIR/candidate-runtime-identity.json"
node "$RELEASE/scripts/release-artifacts.mjs" verify-runtime \
  --staging-fixture true \
  --package "$IMMUTABLE_RELEASE" --identity "$AUDIT_DIR/candidate-runtime-identity.json" \
  >"$AUDIT_DIR/candidate-runtime-verification.json"
PRIVATE_METRICS="$(curl -sS --max-time 10 -H "Host: 127.0.0.1:${CANDIDATE_MANAGEMENT_PORT}" -o /dev/null -w '%{http_code}' "http://127.0.0.1:${CANDIDATE_MANAGEMENT_PORT}/metrics" || true)"
DATA_LOCAL_METRICS="$(curl -sS --max-time 10 -H "Host: 127.0.0.1:${CANDIDATE_PORT}" -o /dev/null -w '%{http_code}' "http://127.0.0.1:${CANDIDATE_PORT}/metrics" || true)"
CANDIDATE_PUBLIC_METRICS="$(curl -sS --max-time 10 -o /dev/null -w '%{http_code}' "${CANDIDATE_PUBLIC_BASE_URL}/metrics" || true)"
[[ "$PRIVATE_METRICS" == 200 && "$DATA_LOCAL_METRICS" == 404 && "$CANDIDATE_PUBLIC_METRICS" == 404 ]] || {
  echo "Candidate metrics boundary failed: private=$PRIVATE_METRICS data-local=$DATA_LOCAL_METRICS candidate-public=$CANDIDATE_PUBLIC_METRICS" >&2
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
  --public-health-url "${CANDIDATE_PUBLIC_BASE_URL}/healthz"
  --artifact-fetch-base-url "http://127.0.0.1:${CANDIDATE_PORT}"
  --token-resource "${CANDIDATE_PUBLIC_BASE_URL}/mcp"
  --database "$CANDIDATE_OAUTH_DATABASE"
  --sessions 3
  --output "$LIVE_EVIDENCE"
  --exercise-self-restart
  --self-restart-evidence "$SELF_RESTART_EVIDENCE"
)
if [[ "$SKIP_COMPANY_GATES" == 1 ]]; then
  LIVE_ARGUMENTS+=(--skip-company-gates)
else
  LIVE_ARGUMENTS+=(--company-target "$SSH_LOAD_TARGET")
  if [[ "$SKIP_COMPANY_CHROME_GATE" == 1 ]]; then
    LIVE_ARGUMENTS+=(--skip-company-chrome-gate)
  fi
fi
if [[ -n "$WINDOWS_LIVE_TARGET" ]]; then
  LIVE_ARGUMENTS+=(--windows-target "$WINDOWS_LIVE_TARGET")
fi
DEVSPACE_RUNTIME_PACKAGE_ROOT="$IMMUTABLE_RELEASE" \
DEVSPACE_RUNTIME_DEPENDENCY_ROOT="$RUNTIME_DEPENDENCY_ROOT" \
  node --import "$IMMUTABLE_RELEASE/scripts/lib/runtime-dependency-loader.mjs" \
    "$IMMUTABLE_RELEASE/scripts/verify-universal-broker-v2-live.mjs" "${LIVE_ARGUMENTS[@]}"
(
  cd "$SOURCE"
  DEVSPACE_REV3_NFR_PUBLIC_BASE_URL="$CANDIDATE_PUBLIC_BASE_URL" \
  DEVSPACE_REV3_NFR_MANAGEMENT_BASE_URL="http://127.0.0.1:${CANDIDATE_MANAGEMENT_PORT}" \
  DEVSPACE_REV3_NFR_SELF_RESTART_EVIDENCE="$SELF_RESTART_EVIDENCE" \
  DEVSPACE_REV3_NFR_SSH_TARGETS_FILE="$TARGETS_FILE" \
  DEVSPACE_REV3_NFR_SSH_TARGET="$SSH_LOAD_TARGET" \
  DEVSPACE_REV3_NFR_SSH_READ_PATH="$SSH_LOAD_READ_PATH" \
  DEVSPACE_REV3_NFR_SSH_EXECUTABLE=/usr/bin/ssh \
  DEVSPACE_REV3_NFR_SFTP_EXECUTABLE=/usr/bin/sftp \
    npm run release:verify -- --mode=release --require-clean --report "$RELEASE_VERIFY_REPORT" 2>&1 | tee "$RELEASE_VERIFY_LOG"
)
validate_release_report "$RELEASE_VERIFY_REPORT" release
chmod 600 "$RELEASE_VERIFY_LOG" "$RELEASE_VERIFY_REPORT" "$SELF_RESTART_EVIDENCE" "$LIVE_EVIDENCE"

# The staging fixture is deliberately non-release-eligible.  Only after its live
# G08 evidence exists do we assemble the immutable package whose signed ledger
# contains that evidence.  This breaks the former package-before-candidate
# cycle without allowing the fixture to reach the production worker.
if [[ -d "$FINAL_IMMUTABLE_RELEASE" ]]; then
  node "$RELEASE/scripts/release-artifacts.mjs" verify \
    "${RELEASE_TRUST_ARGS[@]}" \
    --package "$FINAL_IMMUTABLE_RELEASE" --source-revision "$HEAD" --runtime-revision "$HEAD" \
    >"$AUDIT_DIR/immutable-release.json"
else
  (
    cd "$SOURCE"
    DEVSPACE_REV3_NFR_PUBLIC_BASE_URL="$CANDIDATE_PUBLIC_BASE_URL" \
    DEVSPACE_REV3_NFR_MANAGEMENT_BASE_URL="http://127.0.0.1:${CANDIDATE_MANAGEMENT_PORT}" \
    DEVSPACE_REV3_NFR_SELF_RESTART_EVIDENCE="$SELF_RESTART_EVIDENCE" \
    DEVSPACE_REV3_NFR_SSH_TARGETS_FILE="$TARGETS_FILE" \
    DEVSPACE_REV3_NFR_SSH_TARGET="$SSH_LOAD_TARGET" \
    DEVSPACE_REV3_NFR_SSH_READ_PATH="$SSH_LOAD_READ_PATH" \
    DEVSPACE_REV3_NFR_SSH_EXECUTABLE=/usr/bin/ssh \
    DEVSPACE_REV3_NFR_SFTP_EXECUTABLE=/usr/bin/sftp \
      node scripts/release-artifacts.mjs create \
        "${RELEASE_TRUST_ARGS[@]}" --gate-producer-private-key "$GATE_PRODUCER_PRIVATE_KEY" \
        --source . --output "$FINAL_IMMUTABLE_RELEASE" --source-revision "$HEAD" --runtime-revision "$HEAD"
  ) >"$AUDIT_DIR/immutable-release.json"
fi

node "$RELEASE/scripts/release-artifacts.mjs" verify-runtime-tree \
  "${RELEASE_TRUST_ARGS[@]}" \
  --package "$FINAL_IMMUTABLE_RELEASE" --runtime-root "$STAGING_RELEASE" \
  >"$AUDIT_DIR/final-package-staging-runtime-equivalence.json"

# Dependency evidence binds the package manifest digest.  Re-seal the already
# installed dependency tree against the final attested manifest before any
# production request can reference it.
rm -f "$RUNTIME_DEPENDENCY_EVIDENCE"
node "$FINAL_IMMUTABLE_RELEASE/scripts/release-artifacts.mjs" seal-runtime-dependencies \
  "${RELEASE_TRUST_ARGS[@]}" \
  --package "$FINAL_IMMUTABLE_RELEASE" --dependency-root "$RUNTIME_DEPENDENCY_ROOT" \
  >"$AUDIT_DIR/runtime-dependencies-final-sealed.json"
RUNTIME_DEPENDENCY_EVIDENCE_SHA256="sha256:$(shasum -a 256 "$RUNTIME_DEPENDENCY_EVIDENCE" | awk '{print $1}')"

IMMUTABLE_RELEASE="$FINAL_IMMUTABLE_RELEASE"
BUILD_MANIFEST="$IMMUTABLE_RELEASE/BUILD-MANIFEST.json"
MANIFEST_TSV="$(node -e '
const v=require(process.argv[1]);
process.stdout.write([
  v.sourceRevision,v.runtimeRevision,v.buildDigest,v.schemaGeneration,v.authorityContractGeneration,v.configSchemaIdentity,
  v.runtime?.cwd,v.runtime?.entrypoint,v.runtime?.dependencies?.lockfileSha256,v.migrationManifestDigest,
].join("\t"));
' "$BUILD_MANIFEST")"
IFS=$'\t' read -r MANIFEST_SOURCE_REVISION MANIFEST_RUNTIME_REVISION MANIFEST_BUILD_DIGEST MANIFEST_SCHEMA_GENERATION MANIFEST_AUTHORITY_GENERATION MANIFEST_CONFIG_SCHEMA_IDENTITY MANIFEST_RUNTIME_CWD MANIFEST_RUNTIME_ENTRYPOINT MANIFEST_DEPENDENCY_LOCK_SHA256 MANIFEST_MIGRATION_DIGEST <<<"$MANIFEST_TSV"
[[ "$MANIFEST_SOURCE_REVISION" == "$HEAD" && "$MANIFEST_RUNTIME_REVISION" == "$HEAD" ]] || {
  echo "Final immutable release manifest revision does not bind the upgrade HEAD." >&2
  exit 1
}
BUILD_MANIFEST_SHA256="sha256:$(shasum -a 256 "$BUILD_MANIFEST" | awk '{print $1}')"
IMMUTABLE_RUNTIME_ROOT="$IMMUTABLE_RELEASE"
IMMUTABLE_RUNTIME_ENTRYPOINT="$IMMUTABLE_RELEASE/$MANIFEST_RUNTIME_ENTRYPOINT"
NEW_SCRIPT="$IMMUTABLE_RUNTIME_ENTRYPOINT"
WORKER_DEPENDENCY_LOADER="$IMMUTABLE_RUNTIME_ROOT/scripts/lib/runtime-dependency-loader.mjs"
CONNECTOR_RELEASE_DRIVER="$IMMUTABLE_RUNTIME_ROOT/scripts/connector-activation-release-driver.mjs"
node "$IMMUTABLE_RELEASE/scripts/release-artifacts.mjs" verify-runtime-command \
  "${RELEASE_TRUST_ARGS[@]}" \
  --package "$IMMUTABLE_RELEASE" --runtime-root "$IMMUTABLE_RUNTIME_ROOT" --entrypoint "$IMMUTABLE_RUNTIME_ENTRYPOINT" \
  --manifest-sha256 "$BUILD_MANIFEST_SHA256" \
  >"$AUDIT_DIR/final-immutable-runtime-command.json"
node "$IMMUTABLE_RELEASE/scripts/release-artifacts.mjs" verify-runtime-dependencies \
  "${RELEASE_TRUST_ARGS[@]}" \
  --package "$IMMUTABLE_RELEASE" --dependency-root "$RUNTIME_DEPENDENCY_ROOT" \
  --evidence "$RUNTIME_DEPENDENCY_EVIDENCE" --evidence-sha256 "$RUNTIME_DEPENDENCY_EVIDENCE_SHA256" \
  >"$AUDIT_DIR/runtime-dependencies-final-verification.json"

node "$RELEASE/scripts/release-artifacts.mjs" verify-runtime-tree \
  "${RELEASE_TRUST_ARGS[@]}" \
  --package "$IMMUTABLE_RELEASE" --runtime-root "$SOURCE" \
  >"$AUDIT_DIR/release-nfr-source-runtime-tree.json"
curl -fsS --max-time 10 "http://127.0.0.1:${CANDIDATE_PORT}/healthz" >"$AUDIT_DIR/candidate-local-gateway-post-nfr.json"
curl -fsS --max-time 10 "${CANDIDATE_PUBLIC_BASE_URL}/healthz" >"$AUDIT_DIR/candidate-public-gateway-post-nfr.json"
python3 - "$AUDIT_DIR/candidate-local-gateway-post-nfr.json" "$AUDIT_DIR/candidate-public-gateway-post-nfr.json" <<'PYPOSTNFRIDENTITY'
import json,sys
local=json.load(open(sys.argv[1],encoding="utf-8"))
public=json.load(open(sys.argv[2],encoding="utf-8"))
keys=(
  "status",
  "productVersion",
  "productProfile",
  "buildCapabilityDigest",
  "resourceUriVersion",
  "schemaGeneration",
  "authorityContractGeneration",
  "runtimeRevision",
  "startedAt",
)
mismatches=[key for key in keys if local.get(key) != public.get(key)]
if local.get("status") != "ok" or not isinstance(local.get("startedAt"),str) or not local["startedAt"] or mismatches:
  raise SystemExit(f"post-NFR public health does not resolve to the running candidate: mismatches={mismatches}")
PYPOSTNFRIDENTITY
node "$RELEASE/scripts/release-artifacts.mjs" verify-gateway \
  "${RELEASE_TRUST_ARGS[@]}" \
  --package "$IMMUTABLE_RELEASE" --identity "$AUDIT_DIR/candidate-local-gateway-post-nfr.json" \
  >"$AUDIT_DIR/candidate-local-gateway-post-nfr-verification.json"
node "$RELEASE/scripts/release-artifacts.mjs" verify-gateway \
  "${RELEASE_TRUST_ARGS[@]}" \
  --package "$IMMUTABLE_RELEASE" --identity "$AUDIT_DIR/candidate-public-gateway-post-nfr.json" \
  >"$AUDIT_DIR/candidate-public-gateway-post-nfr-verification.json"
node "$RELEASE/scripts/release-artifacts.mjs" verify-runtime-tree \
  "${RELEASE_TRUST_ARGS[@]}" \
  --package "$IMMUTABLE_RELEASE" --runtime-root "$IMMUTABLE_RUNTIME_ROOT" \
  >"$AUDIT_DIR/candidate-runtime-tree-post-nfr.json"

printf 'Connector evidence outputs: staging=%s activation=%s pre=%s production=%s rollbackChallenge=%s rollbackReceipt=%s\n' \
  "$STAGING_PRECHECK_ARTIFACT" "$STAGING_ACTIVATION_READBACK" "$PRE_CUTOVER_ARTIFACT" \
  "$PRODUCTION_APPROVAL_DIRECTORY" "$ROLLBACK_HOST_CHALLENGE" "$ROLLBACK_HOST_RECEIPT" >&2
run_connector_release_driver \
  staging-precheck "$STAGING_PRECHECK_REQUEST" "$STAGING_PRECHECK_REQUEST_AUDIT" \
  "$STAGING_PRECHECK_ARTIFACT" "$CONNECTOR_DRIVER_SUMMARY_DIR/staging-precheck.json"
run_connector_release_driver \
  staging-activate "$STAGING_ACTIVATION_REQUEST" "$STAGING_ACTIVATION_REQUEST_AUDIT" \
  "$STAGING_ACTIVATION_READBACK" "$CONNECTOR_DRIVER_SUMMARY_DIR/staging-activation.json"
run_connector_release_driver \
  pre-cutover "$PRE_CUTOVER_REQUEST" "$PRE_CUTOVER_REQUEST_AUDIT" \
  "$PRE_CUTOVER_ARTIFACT" "$CONNECTOR_DRIVER_SUMMARY_DIR/pre-cutover.json"
run_connector_release_driver \
  production-predecision "$PRODUCTION_APPROVAL_REQUEST" "$PRODUCTION_PREDECISION_REQUEST_AUDIT" \
  "$PRODUCTION_PREDECISION_ARTIFACT" "$CONNECTOR_DRIVER_SUMMARY_DIR/production-predecision.json"
python3 - \
  "$PRODUCTION_PREDECISION_REQUEST_AUDIT" "$PRODUCTION_PREDECISION_ARTIFACT" \
  "$PRODUCTION_PREPARATION_REQUEST_AUDIT" "$PRODUCTION_APPROVAL_DIRECTORY" \
  "$REQUEST_PATH" "$STATUS_PATH" "$TRANSACTION_ID" \
  "$PRODUCTION_LIFECYCLE_FINALIZATION_STORE" "$PRODUCTION_LIFECYCLE_FINALIZATION_CONTROL" <<'PYPREPARATIONREQUEST'
import json,os,sys,tempfile
(
  predecision_request_path,predecision_path,output_path,approval_directory,
  upgrade_request_path,status_path,transaction_id,finalization_store,finalization_control,
)=sys.argv[1:]
source=json.load(open(predecision_request_path,encoding="utf-8"))
artifacts=source.get("artifacts") or {}
expected={
  "predecisionPath":predecision_path,
  "productionPreparationRequestPath":output_path,
  "upgradeRequestPath":upgrade_request_path,
  "productionApprovalOutputDirectory":approval_directory,
}
if source.get("operation") != "PRODUCTION_PREDECISION" or source.get("schemaVersion") != 1:
  raise SystemExit("production predecision request identity is invalid")
if source.get("selection",{}).get("transactionId") != transaction_id:
  raise SystemExit("production predecision transaction differs from the shell transaction")
if any(os.path.realpath(artifacts.get(key,"")) != os.path.realpath(value) for key,value in expected.items()):
  raise SystemExit("production predecision artifact paths differ from the v4 transaction")
stores=source.get("stores") or {}
if os.path.realpath(stores.get("finalizationStorePath","")) != os.path.realpath(finalization_store):
  raise SystemExit("production predecision finalization store differs from production")
if os.path.realpath(stores.get("finalizationControlPath","")) != os.path.realpath(finalization_control):
  raise SystemExit("production predecision finalization control differs from production")
value={
  "schemaVersion":1,
  "operation":"PRODUCTION_APPROVE",
  "management":source.get("management"),
  "stores":{"finalizationStorePath":finalization_store,"finalizationControlPath":finalization_control},
  "selection":{"transactionId":transaction_id},
  "artifacts":{
    "predecisionPath":predecision_path,
    "productionApprovalOutputDirectory":approval_directory,
    "productionPreparationRequestPath":output_path,
    "snapshotManifestPath":os.path.join(os.path.dirname(status_path),"store-snapshot-preimage","SNAPSHOT-GROUP.json"),
    "statusPath":status_path,
    "upgradeRequestPath":upgrade_request_path,
    "workerClaimPath":status_path+".worker-claim.json",
  },
}
parent=os.path.dirname(output_path)
fd,temporary=tempfile.mkstemp(prefix="."+os.path.basename(output_path)+".",dir=parent)
try:
  with os.fdopen(fd,"w",encoding="utf-8") as output:
    json.dump(value,output,separators=(",",":"));output.write("\n");output.flush();os.fsync(output.fileno())
  os.chmod(temporary,0o600);os.link(temporary,output_path)
finally:
  if os.path.exists(temporary):os.unlink(temporary)
PYPREPARATIONREQUEST
printf 'Rollback challenge binding: transactionId=%s previousRuntimeIdentityDigest=%s previousMigrationManifestDigest=%s receiptPath=%s\n' \
  "$TRANSACTION_ID" "$PREVIOUS_RUNTIME_IDENTITY_DIGEST" "$PREVIOUS_MIGRATION_MANIFEST_DIGEST" "$ROLLBACK_HOST_RECEIPT" >&2
run_connector_release_driver \
  rollback-challenge "$ROLLBACK_CHALLENGE_REQUEST" "$ROLLBACK_CHALLENGE_REQUEST_AUDIT" \
  "$ROLLBACK_HOST_CHALLENGE" "$CONNECTOR_DRIVER_SUMMARY_DIR/rollback-challenge.json"

python3 - \
  "$PRODUCTION_PREDECISION_ARTIFACT" "$PRODUCTION_PREDECISION_REQUEST_AUDIT" "$PRE_CUTOVER_ARTIFACT" \
  "$PRODUCTION_CONNECTOR_ACTIVATION_JOURNAL" "$PRODUCTION_MANAGEMENT_AUTHORIZATION_KEY" \
  "$BUILD_MANIFEST" "$POST_ACTIVATION_CHALLENGE" <<'PYPOSTCHALLENGE'
import hashlib,json,os,sys,tempfile
(
  predecision_path,predecision_request_path,pre_path,journal_path,key_path,build_manifest_path,
  challenge_path,
)=sys.argv[1:]
envelope=json.load(open(predecision_path,encoding="utf-8"))
manifest=envelope.get("payload") or {}
request=json.load(open(predecision_request_path,encoding="utf-8"))
pre=json.load(open(pre_path,encoding="utf-8"))
build=json.load(open(build_manifest_path,encoding="utf-8"))
if envelope.get("schemaVersion") != 1 or envelope.get("kind") != "PRODUCTION_ACTIVATION_PREDECISION":
  raise SystemExit("production predecision identity is invalid")
if request.get("operation") != "PRODUCTION_PREDECISION" or request.get("schemaVersion") != 1:
  raise SystemExit("production predecision request identity is invalid")
management=request.get("management") or {}
if os.path.realpath(management.get("keyRef", "")) != os.path.realpath(key_path):
  raise SystemExit("production predecision request used a foreign management key")
if manifest.get("migrationManifestDigest") != build.get("migrationManifestDigest"):
  raise SystemExit("production predecision migration identity differs from the immutable build")
journal=manifest.get("journalIdentity") or {}
if os.path.realpath(journal.get("storePath", "")) != os.path.realpath(journal_path):
  raise SystemExit("production predecision journal identity differs from production configuration")
payload=pre.get("payload") or {}
if pre.get("schemaVersion") != 2 or pre.get("kind") != "PRE_CUTOVER_HOST_CANARY":
  raise SystemExit("PRE_CUTOVER artifact identity is invalid")
candidate=manifest.get("candidateIdentity")
if payload.get("candidateIdentity") != candidate:
  raise SystemExit("PRE_CUTOVER and production predecision candidate identities differ")
required_candidate=(
  "runtimeIdentityDigest","buildDigest","schemaGeneration","authorityContractGeneration",
  "buildCapabilityManifestDigest","generatedSchemaDigest","packageSha256",
)
if not isinstance(candidate,dict) or set(candidate) != set(required_candidate):
  raise SystemExit("production candidate identity is incomplete")
if any(not isinstance(candidate[key],str) or not candidate[key].startswith("sha256:") for key in required_candidate):
  raise SystemExit("production candidate identity contains a non-digest field")
challenge={
  "schemaVersion":1,
  "kind":"POST_ACTIVATION_CHALLENGE",
  "managementNonce":payload.get("managementNonce"),
  "managementCorrelationId":payload.get("managementCorrelationId"),
  "candidateIdentity":candidate,
  "productionEnvironmentIdentityDigest":manifest.get("productionEnvironmentIdentityDigest"),
  "productionRouteIdentityDigest":manifest.get("productionRouteIdentityDigest"),
}
if not all(isinstance(challenge[key],str) and challenge[key] for key in (
  "managementNonce","managementCorrelationId","productionEnvironmentIdentityDigest","productionRouteIdentityDigest",
)):
  raise SystemExit("POST challenge binding is incomplete")
parent=os.path.dirname(challenge_path)
fd,temporary=tempfile.mkstemp(prefix="."+os.path.basename(challenge_path)+".",dir=parent)
try:
  with os.fdopen(fd,"w",encoding="utf-8") as output:
    json.dump(challenge,output,indent=2);output.write("\n");output.flush();os.fsync(output.fileno())
  os.chmod(temporary,0o600);os.link(temporary,challenge_path)
  directory_fd=os.open(parent,os.O_RDONLY)
  try: os.fsync(directory_fd)
  finally: os.close(directory_fd)
finally:
  if os.path.exists(temporary): os.unlink(temporary)
PYPOSTCHALLENGE
cleanup_candidate_before_cutover
rm -rf "$STAGING_RELEASE"

cp -p "$PRODUCTION_ENV" "$ENV_BACKUP"
chmod 600 "$ENV_BACKUP"
[[ -f "$CANONICAL_START" ]] || {
  echo "Canonical process-manager definition is missing: $CANONICAL_START" >&2
  exit 1
}
cp -p "$CANONICAL_START" "$START_BACKUP"
chmod 700 "$START_BACKUP"
write_env "$NEXT_ENV" "$PRODUCTION_PORT" "$PRODUCTION_STATE_DIR" "$PRODUCTION_OAUTH_STATE_DIR" "$PROCESS_NAME" "$NEW_SCRIPT" \
  "$PUBLIC_BASE_URL" "$ALLOWED_HOSTS" \
  "$PRODUCTION_AUTHORITY_STATE_DIR" "$PRODUCTION_AUTHORITY_STORE" "$PRODUCTION_CONTEXT_STORE" "$PRODUCTION_CONTEXT_WORKTREE_ROOT" \
  "$PRODUCTION_PROCESS_OUTPUT_DIR" "$PRODUCTION_ARTIFACT_STAGING_DIR" "$PRODUCTION_ARTIFACT_CATALOG" "$PRODUCTION_ARTIFACT_OBJECT_ROOT" \
  "$PRODUCTION_AUDIT_SINK" "$PRODUCTION_CURSOR_CURRENT_KEY" "$PRODUCTION_CURSOR_PREVIOUS_KEY" "$PRODUCTION_MANAGEMENT_AUTHORIZATION_KEY" \
  "$PRODUCTION_SSH_CONTROL_DIR" "$PRODUCTION_CONNECTOR_ACTIVATION_JOURNAL" "$PRODUCTION_LIFECYCLE_FINALIZATION_STORE" \
  "$PRODUCTION_LIFECYCLE_FINALIZATION_CONTROL"
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
for database in "$PRODUCTION_OAUTH_DATABASE" "$PRODUCTION_AUTHORITY_DATABASE"; do
  [[ "$(sqlite3 "$database" 'pragma integrity_check;')" == ok ]] || {
    echo "Production database integrity check failed: $database" >&2
    exit 1
  }
  [[ -z "$(sqlite3 "$database" 'pragma foreign_key_check;')" ]] || {
    echo "Production database foreign-key check failed: $database" >&2
    exit 1
  }
done
OAUTH_PREFLIGHT_BACKUP="$AUDIT_DIR/oauth-preflight-before.sqlite"
AUTHORITY_PREFLIGHT_BACKUP="$AUDIT_DIR/authority-preflight-before.sqlite"
OAUTH_CUTOVER_BACKUP="$AUDIT_DIR/oauth-cutover-before.sqlite"
AUTHORITY_CUTOVER_BACKUP="$AUDIT_DIR/authority-cutover-before.sqlite"
SNAPSHOT_GROUP_ROOT="$AUDIT_DIR/store-snapshot-preimage"
sqlite3 "$PRODUCTION_OAUTH_DATABASE" ".backup '$OAUTH_PREFLIGHT_BACKUP'"
sqlite3 "$PRODUCTION_AUTHORITY_DATABASE" ".backup '$AUTHORITY_PREFLIGHT_BACKUP'"
chmod 600 "$OAUTH_PREFLIGHT_BACKUP" "$AUTHORITY_PREFLIGHT_BACKUP"
for database in "$OAUTH_PREFLIGHT_BACKUP" "$AUTHORITY_PREFLIGHT_BACKUP"; do
  [[ "$(sqlite3 "$database" 'pragma integrity_check;')" == ok ]] || {
    echo "Production database backup integrity check failed: $database" >&2
    exit 1
  }
  [[ -z "$(sqlite3 "$database" 'pragma foreign_key_check;')" ]] || {
    echo "Production database backup foreign-key check failed: $database" >&2
    exit 1
  }
done

CURRENT_CONNECTOR_JOURNAL_IDENTITY="$AUDIT_DIR/connector-journal-identity-before-schedule.json"
(
  cd "$IMMUTABLE_RUNTIME_ROOT"
  DEVSPACE_RUNTIME_PACKAGE_ROOT="$IMMUTABLE_RUNTIME_ROOT" \
  DEVSPACE_RUNTIME_DEPENDENCY_ROOT="$RUNTIME_DEPENDENCY_ROOT" \
    node --import "$WORKER_DEPENDENCY_LOADER" --input-type=module - \
      "$PRODUCTION_CONNECTOR_ACTIVATION_JOURNAL" <<'NODEJOURNALIDENTITY'
import { SqliteConnectorActivationRecoveryJournal } from "./dist/v2/connector-activation-journal.js";
const journal = new SqliteConnectorActivationRecoveryJournal({ storePath: process.argv[2] });
try {
  process.stdout.write(`${JSON.stringify(journal.identity(), null, 2)}\n`);
} finally {
  journal.close();
}
NODEJOURNALIDENTITY
) >"$CURRENT_CONNECTOR_JOURNAL_IDENTITY"
chmod 600 "$CURRENT_CONNECTOR_JOURNAL_IDENTITY"

(
  cd "$IMMUTABLE_RUNTIME_ROOT"
  DEVSPACE_RUNTIME_PACKAGE_ROOT="$IMMUTABLE_RUNTIME_ROOT" \
  DEVSPACE_RUNTIME_DEPENDENCY_ROOT="$RUNTIME_DEPENDENCY_ROOT" \
    node --import "$WORKER_DEPENDENCY_LOADER" --input-type=module - \
      "$REQUEST_PATH" "$STATUS_PATH" "$TRANSACTION_ID" "$REQUESTED_AT" "$EVIDENCE_WAIT_SECONDS" \
      "$PROCESS_NAME" "$PM2_EXECUTABLE" "$GIT_EXECUTABLE" \
      "$PREVIOUS_PID" "$PREVIOUS_CWD" "$PREVIOUS_SCRIPT" "$PREVIOUS_AUDIT_TARGET" \
      "$PREVIOUS_RUNTIME_IDENTITY_DIGEST" "$PREVIOUS_MIGRATION_MANIFEST_DIGEST" \
      "$PREVIOUS_LOCAL_HEALTH_URL" "$PREVIOUS_LOCAL_READY_URL" \
      "$ROLLBACK_HOST_CHALLENGE" "$ROLLBACK_HOST_RECEIPT" \
      "$HEAD" "$SOURCE_TREE" "$DIST_FILES" "$DIST_SHA256" \
      "$RELEASE" "$IMMUTABLE_RUNTIME_ROOT" "$IMMUTABLE_RUNTIME_ENTRYPOINT" \
      "$RUNTIME_DEPENDENCY_ROOT" "$RUNTIME_DEPENDENCY_EVIDENCE" "$RUNTIME_DEPENDENCY_EVIDENCE_SHA256" \
      "$BUILD_MANIFEST" "$BUILD_MANIFEST_SHA256" \
      "$PRODUCTION_ENV" "$ENV_BACKUP" "$NEXT_ENV" "$PRODUCTION_OAUTH_STATE_DIR" \
      "$PRODUCTION_OAUTH_DATABASE" "$OAUTH_CUTOVER_BACKUP" \
      "$PRODUCTION_AUTHORITY_DATABASE" "$AUTHORITY_CUTOVER_BACKUP" \
      "$SNAPSHOT_GROUP_ROOT" "$PRODUCTION_CONTEXT_STORE" "$PRODUCTION_CONTEXT_WORKTREE_ROOT" \
      "$PRODUCTION_FILESYSTEM_SYNC_STORE" "$PRODUCTION_PROCESS_STATE_DIR" "$PRODUCTION_PROCESS_OUTPUT_DIR" \
      "$PRODUCTION_SELF_MANAGEMENT_DIR" "$TARGETS_FILE" "$ROUTES_FILE" "$ENV_PROFILES_FILE" \
      "$PRODUCTION_ARTIFACT_CATALOG" "$PRODUCTION_ARTIFACT_OBJECT_ROOT" "$PRODUCTION_ARTIFACT_QUARANTINE_ROOT" \
      "$PRODUCTION_CURSOR_CURRENT_KEY" "$PRODUCTION_CURSOR_PREVIOUS_KEY" "$PRODUCTION_LIFECYCLE_FINALIZATION_STORE" \
      "$PRODUCTION_LIFECYCLE_FINALIZATION_CONTROL" \
      "$GATE_PRODUCER_TRUST_ANCHOR" "$GATE_PRODUCER_TRUST_ANCHOR_SHA256" \
      "$CANONICAL_START" "$START_BACKUP" "$AUDIT_DIR" "$CURRENT_AUDIT_LINK" "$WORKER_LOG" "$ROLLBACK_JOURNAL_PATH" \
      "$PUBLIC_BASE_URL" "$PRODUCTION_PORT" "$PRODUCTION_MANAGEMENT_PORT" \
      "$STAGING_PRECHECK_ARTIFACT" "$PRE_CUTOVER_ARTIFACT" \
      "$PRODUCTION_ACTIVATION_PRECHECK_ARTIFACT" "$OWNER_APPROVAL_ARTIFACT" \
      "$STAGING_PRECHECK_REQUEST_AUDIT" "$STAGING_ACTIVATION_REQUEST_AUDIT" "$STAGING_ACTIVATION_READBACK" \
      "$PRE_CUTOVER_REQUEST_AUDIT" "$PRODUCTION_PREDECISION_REQUEST_AUDIT" "$PRODUCTION_PREDECISION_ARTIFACT" \
      "$PRODUCTION_PREPARATION_REQUEST_AUDIT" "$PRODUCTION_APPROVAL_DIRECTORY" \
      "$ROLLBACK_CHALLENGE_REQUEST_AUDIT" "$CURRENT_CONNECTOR_JOURNAL_IDENTITY" \
      "$PRODUCTION_MANAGEMENT_AUTHORIZATION_KEY" "$POST_ACTIVATION_CHALLENGE" "$POST_ACTIVATION_RECEIPT" \
      "$CANDIDATE_NAME" \
      "$CONNECTOR_DRIVER_SUMMARY_DIR/staging-precheck.json" \
      "$CONNECTOR_DRIVER_SUMMARY_DIR/staging-activation.json" \
      "$CONNECTOR_DRIVER_SUMMARY_DIR/pre-cutover.json" \
      "$CONNECTOR_DRIVER_SUMMARY_DIR/production-predecision.json" \
      "$CONNECTOR_DRIVER_SUMMARY_DIR/rollback-challenge.json" <<'NODEREQUESTV4'
import { createHash, randomUUID } from "node:crypto";
import {
  chmodSync,
  closeSync,
  constants,
  existsSync,
  fsyncSync,
  linkSync,
  lstatSync,
  openSync,
  readFileSync,
  realpathSync,
  unlinkSync,
  writeFileSync,
} from "node:fs";
import { basename, dirname, resolve } from "node:path";
import {
  productionUpgradeLifecycleBindingDigest,
  productionUpgradeRequestBindingDigest,
} from "./dist/v2/production-upgrade-worker.js";
import {
  productionUpgradeCandidateIdentityDigest,
  serializeProductionUpgradeRequestV4,
  validateProductionUpgradeRequestV4,
} from "./dist/v2/production-upgrade-contract.js";
import {
  canonicalPathsOverlap,
  snapshotEntryMutablePaths,
} from "./dist/v2/snapshot-group.js";
import { loadExistingManagementAuthorizationKey } from "./dist/v2/management-authorization.js";
import { verifyConnectorRollbackHostChallenge } from "./scripts/lib/connector-rollback-evidence.mjs";
import { readFinalizationStoreIdentity } from "./scripts/lib/finalization-store-contract.mjs";

const [
  requestPath, statusPath, transactionId, requestedAt, evidenceWaitSecondsText,
  processName, pm2Executable, gitExecutable,
  previousPidText, previousCwd, previousScript, previousAuditTarget,
  previousRuntimeIdentityDigest, previousMigrationManifestDigest,
  previousLocalHealthUrl, previousLocalReadyUrl,
  rollbackChallengePath, rollbackReceiptPath,
  head, sourceTree, distFilesText, distSha256,
  sourceEvidenceRoot, immutableRuntimeRoot, immutableRuntimeEntrypoint,
  runtimeDependencyRoot, runtimeDependencyEvidence, runtimeDependencyEvidenceSha256,
  buildManifestPath, buildManifestSha256,
  productionEnvPath, productionEnvBackupPath, nextEnvPath, oauthStateDirectory,
  oauthDatabasePath, oauthDatabaseBackupPath,
  authorityDatabasePath, authorityDatabaseBackupPath,
  snapshotRoot, contextStore, contextWorktreeRoot,
  filesystemSyncStore, processStateDirectory, processOutputDirectory,
  selfManagementDirectory, targetsFile, routesFile, environmentProfilesFile,
  artifactCatalog, artifactObjectRoot, artifactQuarantineRoot,
  cursorCurrentKey, cursorPreviousKey, lifecycleFinalizationStore, lifecycleFinalizationControl,
  gateProducerTrustAnchorInputPath, gateProducerTrustAnchorInputSha256,
  canonicalStart, startBackup, auditDirectory, currentAuditLink, workerLogPath, rollbackJournalPath,
  publicBaseUrl, productionPort, productionManagementPort,
  stagingPrecheckPath, preCutoverPath, productionPrecheckPath, ownerApprovalPath,
  stagingPrecheckRequestPath, stagingActivationRequestPath, stagingActivationReadbackPath,
  preCutoverRequestPath, productionPredecisionRequestPath, productionPredecisionEnvelopePath,
  productionPreparationRequestPath, productionApprovalOutputDirectory,
  rollbackChallengeRequestPath, currentJournalIdentityPath,
  managementAuthorizationKeyRef, postChallengePath, postReceiptPath,
  candidateProcessName,
  stagingPrecheckSummaryPath, stagingActivationSummaryPath, preCutoverSummaryPath,
  productionPredecisionSummaryPath, rollbackChallengeSummaryPath,
] = process.argv.slice(2);

const sha256 = (value) => `sha256:${createHash("sha256").update(value).digest("hex")}`;
const stableJson = (value) => {
  if (Array.isArray(value)) return `[${value.map(stableJson).join(",")}]`;
  if (value && typeof value === "object") return `{${Object.entries(value)
    .filter(([, child]) => child !== undefined)
    .sort(([left], [right]) => left < right ? -1 : left > right ? 1 : 0)
    .map(([key, child]) => `${JSON.stringify(key)}:${stableJson(child)}`)
    .join(",")}}`;
  return JSON.stringify(value) ?? "null";
};
const ownerArtifact = (path, label) => {
  const resolved = resolve(path);
  const metadata = lstatSync(resolved);
  if (!metadata.isFile() || metadata.isSymbolicLink() || (metadata.mode & 0o077) !== 0
    || (typeof process.getuid === "function" && metadata.uid !== process.getuid())
    || realpathSync(resolved) !== resolved || realpathSync(dirname(resolved)) !== dirname(resolved)) {
    throw new Error(`${label} must be an owner-only canonical regular file.`);
  }
  const content = readFileSync(resolved);
  return { path: resolved, sha256: sha256(content), content };
};
const parseArtifact = (path, label) => {
  const artifact = ownerArtifact(path, label);
  return { ...artifact, value: JSON.parse(artifact.content.toString("utf8")) };
};
const publishJson = (path, value) => {
  const resolved = resolve(path);
  const parent = dirname(resolved);
  if (realpathSync(parent) !== parent || existsSync(resolved)) {
    throw new Error(`Refusing to overwrite or publish through a symlinked directory: ${resolved}`);
  }
  const temporary = resolve(parent, `.${basename(resolved)}.${process.pid}.${randomUUID()}.tmp`);
  let descriptor;
  try {
    descriptor = openSync(temporary, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL, 0o600);
    writeFileSync(descriptor, typeof value === "string" ? value : `${JSON.stringify(value, null, 2)}\n`, "utf8");
    fsyncSync(descriptor);
    closeSync(descriptor);
    descriptor = undefined;
    chmodSync(temporary, 0o600);
    linkSync(temporary, resolved);
    const directory = openSync(parent, constants.O_RDONLY);
    try { fsyncSync(directory); } finally { closeSync(directory); }
  } finally {
    if (descriptor !== undefined) closeSync(descriptor);
    if (existsSync(temporary)) unlinkSync(temporary);
  }
};

const evidenceWaitSeconds = Number(evidenceWaitSecondsText);
const timeoutMs = evidenceWaitSeconds * 1_000;
const buildManifestContent = readFileSync(resolve(buildManifestPath));
const buildManifest = JSON.parse(buildManifestContent.toString("utf8"));
if (sha256(buildManifestContent) !== buildManifestSha256) {
  throw new Error("Immutable build manifest digest changed before v4 request publication.");
}
const productionPredecisionEnvelopeArtifact = parseArtifact(
  productionPredecisionEnvelopePath,
  "production predecision envelope",
);
const productionPredecisionEnvelope = productionPredecisionEnvelopeArtifact.value;
const productionApprovalManifest = productionPredecisionEnvelope.payload;
const preCutover = parseArtifact(preCutoverPath, "PRE_CUTOVER evidence");
const stagingPrecheck = ownerArtifact(stagingPrecheckPath, "staging precheck evidence");
const postChallenge = ownerArtifact(postChallengePath, "POST activation challenge");
const currentJournalIdentity = parseArtifact(
  currentJournalIdentityPath,
  "connector journal identity readback",
).value;
const stagingPrecheckSummary = parseArtifact(stagingPrecheckSummaryPath, "staging precheck summary").value;
const stagingActivationSummary = parseArtifact(stagingActivationSummaryPath, "staging activation summary").value;
const preCutoverSummary = parseArtifact(preCutoverSummaryPath, "PRE_CUTOVER summary").value;
const productionPredecisionSummary = parseArtifact(
  productionPredecisionSummaryPath,
  "production predecision summary",
).value;
const rollbackChallengeSummary = parseArtifact(
  rollbackChallengeSummaryPath,
  "rollback challenge summary",
).value;

for (const [summary, artifact, kind] of [
  [stagingPrecheckSummary, stagingPrecheck, "STAGING_ACTIVATION_PRECHECK"],
  [stagingActivationSummary, ownerArtifact(stagingActivationReadbackPath, "staging activation readback"), "STAGING_ACTIVATION"],
  [preCutoverSummary, preCutover, "PRE_CUTOVER_HOST_CANARY"],
]) {
  if (summary.kind !== kind || resolve(summary.path ?? "") !== artifact.path || summary.sha256 !== artifact.sha256) {
    throw new Error(`${kind} differs from the verified release-driver summary.`);
  }
}
if (productionPredecisionSummary.kind !== "PRODUCTION_ACTIVATION_PREDECISION"
  || resolve(productionPredecisionSummary.path ?? "") !== productionPredecisionEnvelopeArtifact.path
  || productionPredecisionSummary.sha256 !== productionPredecisionEnvelopeArtifact.sha256) {
  throw new Error("Production predecision differs from the verified release-driver summary.");
}

if (productionPredecisionEnvelope.schemaVersion !== 1
  || productionPredecisionEnvelope.kind !== "PRODUCTION_ACTIVATION_PREDECISION"
  || productionApprovalManifest.migrationManifestDigest !== buildManifest.migrationManifestDigest
  || stableJson(productionApprovalManifest.journalIdentity) !== stableJson(currentJournalIdentity)) {
  throw new Error("Production predecision no longer matches build or current journal identity.");
}
if (resolve(currentJournalIdentity.storePath ?? "") !== resolve(productionApprovalManifest.journalIdentity.storePath ?? "")) {
  throw new Error("Connector journal store path changed before scheduling.");
}
const prePayload = preCutover.value?.payload;
const candidateIdentity = productionApprovalManifest.candidateIdentity;
if (preCutover.value?.schemaVersion !== 2
  || preCutover.value?.kind !== "PRE_CUTOVER_HOST_CANARY"
  || stableJson(prePayload?.candidateIdentity) !== stableJson(candidateIdentity)
  || candidateIdentity?.buildDigest !== buildManifest.buildDigest
  || candidateIdentity?.schemaGeneration !== buildManifest.schemaGeneration
  || candidateIdentity?.authorityContractGeneration !== buildManifest.authorityContractGeneration) {
  throw new Error("Production candidate identity differs from PRE_CUTOVER or immutable build identity.");
}

const rollbackChallenge = parseArtifact(rollbackChallengePath, "rollback Host challenge");
if (rollbackChallengeSummary.kind !== "ROLLBACK_HOST_CHALLENGE"
  || resolve(rollbackChallengeSummary.path ?? "") !== rollbackChallenge.path
  || rollbackChallengeSummary.sha256 !== rollbackChallenge.sha256) {
  throw new Error("Rollback challenge differs from the verified release-driver summary.");
}
const managementKey = loadExistingManagementAuthorizationKey({
  keyRef: managementAuthorizationKeyRef,
  stateDir: dirname(managementAuthorizationKeyRef),
});
verifyConnectorRollbackHostChallenge(
  rollbackChallenge.value,
  managementKey,
  {
    transactionId,
    previousRuntimeIdentityDigest,
    previousMainMigrationIdentityDigest: previousMigrationManifestDigest,
    receiptPath: resolve(rollbackReceiptPath),
  },
  Date.now(),
);
if (existsSync(rollbackReceiptPath) || existsSync(postReceiptPath)) {
  throw new Error("Future rollback and POST Host receipt targets must both be absent before scheduling.");
}

const releaseDriver = {
  "stagingPrecheckRequest": ownerArtifact(stagingPrecheckRequestPath, "staging precheck request"),
  "stagingActivationRequest": ownerArtifact(stagingActivationRequestPath, "staging activation request"),
  "stagingActivationReadback": ownerArtifact(stagingActivationReadbackPath, "staging activation readback"),
  "preCutoverRequest": ownerArtifact(preCutoverRequestPath, "PRE_CUTOVER request"),
  "productionPredecisionRequest": ownerArtifact(productionPredecisionRequestPath, "production predecision request"),
  "productionPredecisionEnvelope": {
    path: productionPredecisionEnvelopeArtifact.path,
    sha256: productionPredecisionEnvelopeArtifact.sha256,
  },
  "productionPreparationRequest": ownerArtifact(productionPreparationRequestPath, "production preparation request"),
  "productionApprovalOutputDirectory": resolve(productionApprovalOutputDirectory),
};
for (const [key, artifact] of Object.entries(releaseDriver)) {
  if (key !== "productionApprovalOutputDirectory") {
    releaseDriver[key] = { path: artifact.path, sha256: artifact.sha256 };
  }
}

const finalizationDraftIdentity = readFinalizationStoreIdentity({
  storePath: resolve(lifecycleFinalizationStore),
  controlPath: resolve(lifecycleFinalizationControl),
  key: managementKey,
});
if (finalizationDraftIdentity.state !== "DRAFT" || finalizationDraftIdentity.revision !== 1) {
  throw new Error("Production finalization store must be the exact DRAFT preimage before scheduling.");
}
const candidateIdentityDigest = productionUpgradeCandidateIdentityDigest(candidateIdentity);
const snapshotManifestPath = resolve(snapshotRoot, "SNAPSHOT-GROUP.json");
const workerClaimPath = `${resolve(statusPath)}.worker-claim.json`;
const captureDeadlineAt = new Date(Date.parse(requestedAt) + timeoutMs).toISOString();
const gateProducerTrustAnchor = parseArtifact(gateProducerTrustAnchorInputPath, "gate producer trust anchor");
if (gateProducerTrustAnchor.sha256 !== gateProducerTrustAnchorInputSha256) {
  throw new Error("Gate producer trust anchor digest changed before v4 request publication.");
}
const gateProducerPublicKeySha256 = buildManifest.gateProducer?.publicKeySha256;
const gateProducerKeyId = buildManifest.gateProducer?.keyId;
if (typeof gateProducerKeyId !== "string" || typeof gateProducerPublicKeySha256 !== "string") {
  throw new Error("Gate producer trust anchor lacks its key identity.");
}

const request={
  "version":4,
  "transactionId":transactionId,
  "requestedAt":requestedAt,
  "delayMs":0,
  "timeoutMs":timeoutMs,
  "pm2ProcessName":processName,
  "pm2Executable":pm2Executable,
  "gitExecutable":gitExecutable,
  "previous":{
    "pid":Number(previousPidText),
    "cwd":previousCwd,
    "script":previousScript,
    ...(previousAuditTarget ? { "auditTarget":previousAuditTarget } : {}),
    "runtimeIdentityDigest":previousRuntimeIdentityDigest,
    "migrationManifestDigest":previousMigrationManifestDigest,
    "localHealthUrl":previousLocalHealthUrl,
    "localReadyUrl":previousLocalReadyUrl,
    "rollbackHostChallenge":{
      "rollbackChallengeRequest":{
        "path":resolve(rollbackChallengeRequestPath),
        "sha256":ownerArtifact(rollbackChallengeRequestPath,"rollback challenge request").sha256,
      },
      "challengePath":rollbackChallenge.path,
      "challengeSha256":rollbackChallenge.sha256,
      "receiptPath":resolve(rollbackReceiptPath),
      "deadlineAt":captureDeadlineAt,
      "pollIntervalMs":250,
    },
  },
  "next":{
    "commit":head,
    "sourceTree":sourceTree,
    "sourceEvidenceRoot":sourceEvidenceRoot,
    "immutableRuntimeRoot":immutableRuntimeRoot,
    "immutableRuntimeEntrypoint":immutableRuntimeEntrypoint,
    "runtimeDependencies":{
      "root":runtimeDependencyRoot,
      "evidencePath":runtimeDependencyEvidence,
      "evidenceSha256":runtimeDependencyEvidenceSha256,
    },
    "dist":{"files":Number(distFilesText),"sha256":distSha256},
    "manifest":{
      "path":resolve(buildManifestPath),
      "sha256":buildManifestSha256,
      "buildDigest":buildManifest.buildDigest,
      "runtimeRevision":buildManifest.runtimeRevision,
      "schemaGeneration":buildManifest.schemaGeneration,
      "authorityContractGeneration":buildManifest.authorityContractGeneration,
      "configSchemaIdentity":buildManifest.configSchemaIdentity,
      "migrationManifestDigest":buildManifest.migrationManifestDigest,
      "buildCapabilityManifestDigest":candidateIdentity.buildCapabilityManifestDigest,
      "generatedSchemaDigest":candidateIdentity.generatedSchemaDigest,
      "packageSha256":candidateIdentity.packageSha256,
      "runtimeIdentityDigest":candidateIdentity.runtimeIdentityDigest,
    },
  },
  "oauthStateDirectory":oauthStateDirectory,
  "productionEnvPath":productionEnvPath,
  "productionEnvBackupPath":productionEnvBackupPath,
  "oauthDatabasePath":oauthDatabasePath,
  "oauthDatabaseBackupPath":oauthDatabaseBackupPath,
  "authorityDatabasePath":authorityDatabasePath,
  "authorityDatabaseBackupPath":authorityDatabaseBackupPath,
  "snapshotGroup":{
    "snapshotRoot":snapshotRoot,
    "manifestPath":snapshotManifestPath,
    "paginationPreviousSigningKey":cursorPreviousKey
      ? {"state":"PRESENT","path":cursorPreviousKey}
      : {"state":"ABSENT","path":resolve(dirname(cursorCurrentKey),"cursor-hmac-previous.key")},
    "barrier":{
      "kind":"PM2_STOPPED",
      "transactionId":transactionId,
      "processName":processName,
      "previousPid":Number(previousPidText),
      "previousRuntimeIdentityDigest":previousRuntimeIdentityDigest,
      "previousMigrationManifestDigest":previousMigrationManifestDigest,
      "candidateIdentityDigest":candidateIdentityDigest,
      "cutoverProcessNames":[processName,candidateProcessName].sort(),
      "captureDeadlineAt":captureDeadlineAt,
    },
    "entries":[
      {"id":"oauth-main-and-connector-state","kind":"sqlite","path":oauthDatabasePath,"required":true},
      {"id":"authority-store","kind":"sqlite","path":authorityDatabasePath,"required":true},
      {"id":"contexts-store","kind":"file","path":contextStore,"required":true},
      {"id":"process-metadata","kind":"directory","path":processStateDirectory,"required":true},
      {"id":"process-output","kind":"directory","path":processOutputDirectory,"required":true},
      {"id":"filesystem-sync","kind":"sqlite","path":filesystemSyncStore,"required":true},
      {"id":"artifact-catalog","kind":"sqlite","path":artifactCatalog,"required":true},
      {"id":"artifact-cas","kind":"directory","path":artifactObjectRoot,"required":true},
      {"id":"artifact-quarantine","kind":"directory","path":artifactQuarantineRoot,"required":true},
      {"id":"pagination-current-signing-key","kind":"file","path":cursorCurrentKey,"required":true},
      {"id":"lifecycle-finalization-store","kind":"sqlite","path":lifecycleFinalizationStore,"required":true},
      {"id":"runtime-environment","kind":"file","path":productionEnvPath,"required":true},
      {"id":"process-manager-definition","kind":"file","path":canonicalStart,"required":true},
      {"id":"public-route","kind":"file","path":routesFile,"required":true},
      {"id":"target-route-generation-config","kind":"file","path":targetsFile,"required":true},
      {"id":"pagination-previous-signing-key","kind":"file","path":cursorPreviousKey || resolve(dirname(cursorCurrentKey),"cursor-hmac-previous.key"),"required":false},
    ],
  },
  "cutoverProcessNames":[processName,candidateProcessName].sort(),
  "connectorLifecycle":{
    "bindingDigest":"sha256:0000000000000000000000000000000000000000000000000000000000000000",
    "stagingActivationPrecheck":{path:stagingPrecheck.path,sha256:stagingPrecheck.sha256},
    "preCutoverHostCanary":{path:preCutover.path,sha256:preCutover.sha256},
    "releaseDriver":releaseDriver,
    "journal":{"path":resolve(currentJournalIdentity.storePath),"identity":currentJournalIdentity},
    "postActivation":{
      "challengePath":postChallenge.path,
      "challengeSha256":postChallenge.sha256,
      "receiptPath":resolve(postReceiptPath),
      "deadlineAt":captureDeadlineAt,
      "pollIntervalMs":250,
      "runtimeIdentityUrl":`http://127.0.0.1:${productionManagementPort}/readyz`,
      "routeIdentityUrl":`http://127.0.0.1:${productionManagementPort}/route-identityz`,
    },
    "managementAuthorizationKeyRef":resolve(managementAuthorizationKeyRef),
    "managementNonce":prePayload.managementNonce,
    "managementCorrelationId":prePayload.managementCorrelationId,
    "candidateIdentity":candidateIdentity,
    "oauthResource":productionApprovalManifest.oauthResource,
    "productionEnvironmentIdentityDigest":productionApprovalManifest.productionEnvironmentIdentityDigest,
    "productionRouteIdentityDigest":productionApprovalManifest.productionRouteIdentityDigest,
    "finalization":{
      "storePath":resolve(lifecycleFinalizationStore),
      "controlPath":resolve(lifecycleFinalizationControl),
      "keyId":managementKey.keyId,
      "gateProducer":{
        "keyId":gateProducerKeyId,
        "publicKeySha256":gateProducerPublicKeySha256,
      },
      "gateProducerTrustAnchor":{
        "path":gateProducerTrustAnchor.path,
        "sha256":gateProducerTrustAnchor.sha256,
      },
      "preSnapshotIdentity":{
        "storeId":"lifecycle-finalization-store",
        "schemaVersion":2,
        "state":"DRAFT",
        "revision":1,
        "transactionId":null,
        "contentGeneration":finalizationDraftIdentity.contentGeneration,
        "controlEpoch":finalizationDraftIdentity.controlEpoch,
        "controlTag":finalizationDraftIdentity.controlTag,
        "identityDigest":finalizationDraftIdentity.preSnapshotIdentityDigest,
      },
    },
  },
  "rollbackJournalPath":rollbackJournalPath,
  "nextEnvPath":nextEnvPath,
  "startScriptPath":canonicalStart,
  "startScriptBackupPath":startBackup,
  "auditDirectory":auditDirectory,
  "currentAuditLink":currentAuditLink,
  "statusPath":statusPath,
  "workerClaimPath":workerClaimPath,
  "workerLogPath":workerLogPath,
  "localHealthUrl":`http://127.0.0.1:${productionPort}/healthz`,
  "localDoctorUrl":`http://127.0.0.1:${productionManagementPort}/doctorz`,
  "publicHealthUrl":`${publicBaseUrl}/healthz`,
  "publicMetricsUrl":`${publicBaseUrl}/metrics`,
  "publicMcpUrl":`${publicBaseUrl}/mcp`,
  "oauthMetadataUrl":`${publicBaseUrl}/.well-known/oauth-protected-resource/mcp`,
  "expectedScopes":["devspace.read","devspace.write","devspace.exec","devspace.mcp","devspace.artifact","devspace.gui","offline_access"],
  ...(process.platform === "darwin"
    ? { "launchdLabel":`com.devspace.production-upgrade.${transactionId.replace("_", "-")}` }
    : {}),
};
const externalControlPaths = [
  request.auditDirectory,
  request.statusPath,
  request.workerLogPath,
  request.rollbackJournalPath,
  request.connectorLifecycle.journal.path,
  request.connectorLifecycle.managementAuthorizationKeyRef,
  request.connectorLifecycle.stagingActivationPrecheck.path,
  request.connectorLifecycle.preCutoverHostCanary.path,
  ...Object.values(request.connectorLifecycle.releaseDriver)
    .filter((artifact) => typeof artifact === "object")
    .map((artifact) => artifact.path),
  request.connectorLifecycle.releaseDriver.productionApprovalOutputDirectory,
  request.connectorLifecycle.finalization.controlPath,
  request.connectorLifecycle.finalization.gateProducerTrustAnchor.path,
  request.connectorLifecycle.postActivation.challengePath,
  request.connectorLifecycle.postActivation.receiptPath,
  request.previous.rollbackHostChallenge.rollbackChallengeRequest.path,
  request.previous.rollbackHostChallenge.challengePath,
  request.previous.rollbackHostChallenge.receiptPath,
  request.productionEnvBackupPath,
  request.oauthDatabaseBackupPath,
  request.authorityDatabaseBackupPath,
  request.startScriptBackupPath,
  request.nextEnvPath,
];
for (const entry of request.snapshotGroup.entries) {
  for (const mutablePath of snapshotEntryMutablePaths(entry)) {
    for (const controlPath of externalControlPaths) {
      if (canonicalPathsOverlap(mutablePath, controlPath)) {
        throw new Error(`Mutable snapshot entry ${entry.id} overlaps external control state: ${controlPath}`);
      }
    }
  }
}
for (const controlPath of externalControlPaths.filter((path) => path !== request.auditDirectory)) {
  if (canonicalPathsOverlap(request.snapshotGroup.snapshotRoot, controlPath)) {
    throw new Error(`Snapshot root overlaps external control state: ${controlPath}`);
  }
}
request.connectorLifecycle.bindingDigest = productionUpgradeLifecycleBindingDigest(request);
const validatedRequest = validateProductionUpgradeRequestV4(request);
const requestBindingDigest = productionUpgradeRequestBindingDigest(validatedRequest);
const status={
  "version":2,
  "transactionId":transactionId,
  "requestBindingDigest":requestBindingDigest,
  "state":"PREPARED",
  "requestedAt":requestedAt,
  "updatedAt":requestedAt,
  "expectedDisconnect":true,
  "previous":validatedRequest.previous,
  "next":validatedRequest.next,
  "history":[{"state":"PREPARED","at":requestedAt}],
};
publishJson(requestPath, serializeProductionUpgradeRequestV4(validatedRequest));
publishJson(statusPath, status);
NODEREQUESTV4
)
WORKER="$IMMUTABLE_RUNTIME_ROOT/dist/v2/production-upgrade-worker-cli.js"
[[ -f "$WORKER" ]] || { echo "Production upgrade worker is missing: $WORKER" >&2; exit 1; }
WORKER_DEPENDENCY_LOADER="$IMMUTABLE_RUNTIME_ROOT/scripts/lib/runtime-dependency-loader.mjs"
[[ -f "$WORKER_DEPENDENCY_LOADER" ]] || { echo "Production upgrade dependency loader is missing: $WORKER_DEPENDENCY_LOADER" >&2; exit 1; }
CLEANUP_MONITOR="$IMMUTABLE_RUNTIME_ROOT/dist/v2/production-upgrade-cleanup-monitor.js"
[[ -f "$CLEANUP_MONITOR" ]] || { echo "Production upgrade cleanup monitor is missing: $CLEANUP_MONITOR" >&2; exit 1; }
SCHEDULER_KIND=""
LAUNCHD_RC=""
CLEANUP_MONITOR_PID=""
if [[ "$(uname -s)" == Darwin ]]; then
  LABEL="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["launchdLabel"])' "$REQUEST_PATH")"
  set +e
  /bin/launchctl submit -l "$LABEL" -o "$WORKER_LOG" -e "$WORKER_LOG" -- \
    /usr/bin/env \
      DEVSPACE_RUNTIME_PACKAGE_ROOT="$IMMUTABLE_RUNTIME_ROOT" \
      DEVSPACE_RUNTIME_DEPENDENCY_ROOT="$RUNTIME_DEPENDENCY_ROOT" \
      "$(command -v node)" --import "$WORKER_DEPENDENCY_LOADER" "$WORKER" "$REQUEST_PATH"
  LAUNCHD_RC=$?
  set -e
  if [[ "$LAUNCHD_RC" == 0 ]]; then
    SCHEDULER_KIND="launchd"
  else
    SCHEDULER_KIND="pm2"
    : > "$WORKER_LOG"
    chmod 600 "$WORKER_LOG"
    /usr/bin/env -i \
      HOME="$HOME" USER="${USER:-$(id -un)}" LOGNAME="${LOGNAME:-${USER:-$(id -un)}}" \
      PATH="$(dirname "$(command -v node)"):/usr/bin:/bin:/usr/sbin:/sbin" \
      TMPDIR="${TMPDIR:-/tmp}" LANG="${LANG:-C}" LC_ALL="${LC_ALL:-${LANG:-C}}" \
      PM2_HOME="${PM2_HOME:-$HOME/.pm2}" \
      DEVSPACE_UPGRADE_SCHEDULER=pm2 DEVSPACE_UPGRADE_PM2_WORKER_NAME="$PM2_WORKER_NAME" \
      DEVSPACE_RUNTIME_PACKAGE_ROOT="$IMMUTABLE_RUNTIME_ROOT" \
      DEVSPACE_RUNTIME_DEPENDENCY_ROOT="$RUNTIME_DEPENDENCY_ROOT" \
      "$PM2_EXECUTABLE" start "$WORKER" \
        --name "$PM2_WORKER_NAME" \
        --interpreter "$(command -v node)" \
        --node-args="--import=$WORKER_DEPENDENCY_LOADER" \
        --cwd "$IMMUTABLE_RUNTIME_ROOT" \
        --no-autorestart --merge-logs \
        --output "$WORKER_LOG" --error "$WORKER_LOG" --time \
        -- "$REQUEST_PATH"
    : > "$CLEANUP_MONITOR_LOG"
    chmod 600 "$CLEANUP_MONITOR_LOG"
    /usr/bin/env -i \
      HOME="$HOME" USER="${USER:-$(id -un)}" LOGNAME="${LOGNAME:-${USER:-$(id -un)}}" \
      PATH="$(dirname "$(command -v node)"):/usr/bin:/bin:/usr/sbin:/sbin" \
      TMPDIR="${TMPDIR:-/tmp}" LANG="${LANG:-C}" LC_ALL="${LC_ALL:-${LANG:-C}}" \
      PM2_HOME="${PM2_HOME:-$HOME/.pm2}" \
      /usr/bin/nohup "$(command -v node)" "$CLEANUP_MONITOR" \
        "$STATUS_PATH" "$PM2_EXECUTABLE" "$PM2_WORKER_NAME" "$AUDIT_DIR" 900000 \
        >> "$CLEANUP_MONITOR_LOG" 2>&1 </dev/null &
    CLEANUP_MONITOR_PID=$!
  fi
else
  SCHEDULER_KIND="nohup"
  DEVSPACE_RUNTIME_PACKAGE_ROOT="$IMMUTABLE_RUNTIME_ROOT" \
  DEVSPACE_RUNTIME_DEPENDENCY_ROOT="$RUNTIME_DEPENDENCY_ROOT" \
    nohup "$(command -v node)" --import "$WORKER_DEPENDENCY_LOADER" \
      "$WORKER" "$REQUEST_PATH" >> "$WORKER_LOG" 2>&1 </dev/null &
fi

python3 - "$SCHEDULER_EVIDENCE" "$TRANSACTION_ID" "$SCHEDULER_KIND" "$PM2_WORKER_NAME" "${LABEL:-}" "${LAUNCHD_RC:-}" "${CLEANUP_MONITOR_PID:-}" <<'PYSCHEDULER'
import datetime,json,os,sys,tempfile
path,transaction_id,kind,worker_name,label,launchd_rc,cleanup_monitor_pid=sys.argv[1:]
value={
  "version":1,
  "transactionId":transaction_id,
  "scheduler":kind,
  "workerName":worker_name if kind=="pm2" else None,
  "launchdLabel":label or None,
  "launchdSubmitStatus":int(launchd_rc) if launchd_rc else None,
  "cleanupMonitorPid":int(cleanup_monitor_pid) if cleanup_monitor_pid else None,
  "scheduledAt":datetime.datetime.now(datetime.timezone.utc).isoformat(),
}
fd,tmp=tempfile.mkstemp(prefix='.'+os.path.basename(path)+'.',dir=os.path.dirname(path))
try:
  with os.fdopen(fd,'w') as handle:
    json.dump(value,handle,indent=2);handle.write('\n');handle.flush();os.fsync(handle.fileno())
  os.chmod(tmp,0o600);os.replace(tmp,path)
finally:
  if os.path.exists(tmp):os.unlink(tmp)
PYSCHEDULER

CLAIMED_STATE=""
for ((attempt=0; attempt<100; attempt++)); do
  CLAIMED_STATE="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1])).get("state",""))' "$STATUS_PATH" 2>/dev/null || true)"
  case "$CLAIMED_STATE" in
    ACCEPTED|PREFLIGHT_VERIFIED|CONNECTOR_ACTIVATION_PREPARED|CUTOVER_STOP_REQUESTED|CUTOVER_PROCESSES_STOPPED|STATE_SNAPSHOTTED|ACTIVATED_PENDING_POSTCHECK|RUNTIME_STARTED|POST_SWITCH_VERIFIED|POST_ACTIVATION_VERIFIED|PASS|ROLLBACK_REQUESTED|ROLLBACK_RESTORING) break ;;
    FAIL|UNKNOWN|ROLLED_BACK|ROLLBACK_UNKNOWN)
      echo "Production upgrade worker terminated before scheduling completed: $CLAIMED_STATE" >&2
      exit 1
      ;;
  esac
  sleep 0.1
done
if [[ ! "$CLAIMED_STATE" =~ ^(ACCEPTED|PREFLIGHT_VERIFIED|CONNECTOR_ACTIVATION_PREPARED|CUTOVER_STOP_REQUESTED|CUTOVER_PROCESSES_STOPPED|STATE_SNAPSHOTTED|ACTIVATED_PENDING_POSTCHECK|RUNTIME_STARTED|POST_SWITCH_VERIFIED|POST_ACTIVATION_VERIFIED|PASS|ROLLBACK_REQUESTED|ROLLBACK_RESTORING)$ ]]; then
  set +e
  TIMEOUT_GUARD_CLAIM_ID="$(acquire_timeout_claim_guard "$STATUS_PATH" "$$")"
  TIMEOUT_GUARD_RC=$?
  set -e
  if [[ "$TIMEOUT_GUARD_RC" == 75 ]]; then
    UPGRADE_SCHEDULED=1
    echo "Detached upgrade worker owns the exact transaction claim; preserving scheduler and status." >&2
  elif [[ "$TIMEOUT_GUARD_RC" == 0 ]]; then
    [[ "$SCHEDULER_KIND" != pm2 ]] || {
      "$PM2_EXECUTABLE" delete "$PM2_WORKER_NAME" >/dev/null 2>&1 || true
      "$PM2_EXECUTABLE" save >/dev/null 2>&1 || true
    }
    [[ -z "${LABEL:-}" ]] || /bin/launchctl remove "$LABEL" >/dev/null 2>&1 || true
    python3 - "$STATUS_PATH" "$TIMEOUT_GUARD_CLAIM_ID" <<'PYCLAIM'
import datetime,json,os,stat,sys,tempfile
path,claim_id=sys.argv[1:];claim_path=path+".worker-claim.json"
def read_owner_json(path):
  descriptor=os.open(path,os.O_RDONLY|getattr(os,"O_NOFOLLOW",0))
  try:
    metadata=os.fstat(descriptor)
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != os.getuid() or metadata.st_mode & 0o077:
      raise SystemExit(f"owner-only JSON file identity is invalid: {path}")
    chunks=[];size=0
    while True:
      chunk=os.read(descriptor,65536)
      if not chunk: break
      size+=len(chunk)
      if size > 1024*1024: raise SystemExit(f"owner-only JSON file is too large: {path}")
      chunks.append(chunk)
  finally:
    os.close(descriptor)
  return json.loads(b"".join(chunks))
try:
  metadata=os.lstat(claim_path)
  if not stat.S_ISREG(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode) or metadata.st_mode & 0o077:
    raise SystemExit("timeout claim guard changed before status persistence")
  claim=read_owner_json(claim_path)
  value=read_owner_json(path)
  if claim.get("claimId") != claim_id or claim.get("claimPath") != claim_path:
    raise SystemExit("timeout claim guard identity changed")
  if value.get("version") != 2 or value.get("state") != "PREPARED" or value.get("workerClaim") is not None:
    raise SystemExit("upgrade status changed after timeout claim guard")
  if value.get("transactionId") != claim.get("transactionId") or value.get("requestBindingDigest") != claim.get("requestBindingDigest"):
    raise SystemExit("timeout claim guard does not bind the upgrade status")
  at=datetime.datetime.now(datetime.timezone.utc).isoformat()
  value.update({"state":"FAIL","updatedAt":at,"error":"Detached upgrade scheduler did not claim the PREPARED transaction."})
  value["history"]=[*value.get("history",[]),{"state":"FAIL","at":at}]
  fd,tmp=tempfile.mkstemp(prefix='.'+os.path.basename(path)+'.',dir=os.path.dirname(path))
  try:
    with os.fdopen(fd,'w') as handle:
      json.dump(value,handle,indent=2);handle.write('\n');handle.flush();os.fsync(handle.fileno())
    os.chmod(tmp,0o600);os.replace(tmp,path)
  finally:
    if os.path.exists(tmp):os.unlink(tmp)
finally:
  try:
    observed=read_owner_json(claim_path)
    if observed.get("claimId") == claim_id: os.unlink(claim_path)
  except FileNotFoundError:
    pass
  directory=os.open(os.path.dirname(path),os.O_RDONLY)
  try: os.fsync(directory)
  finally: os.close(directory)
PYCLAIM
    echo "Detached upgrade scheduler did not claim the transaction." >&2
    exit 1
  else
    UPGRADE_SCHEDULED=1
    echo "Upgrade claim ownership is uncertain; preserving scheduler, status, and immutable release for recovery." >&2
    exit 1
  fi
fi
UPGRADE_SCHEDULED=1

python3 - "$STATUS_PATH" "$SCHEDULER_EVIDENCE" <<'PY'
import json,sys
status=json.load(open(sys.argv[1]))
print(json.dumps({
  "status":"UPGRADE_SCHEDULED",
  "scheduler":json.load(open(sys.argv[2]))["scheduler"],
  "transactionId":status["transactionId"],
  "statusPath":sys.argv[1],
  "expectedDisconnect":True,
  "next":status["next"],
},indent=2))
PY
