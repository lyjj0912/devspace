#!/bin/bash
set -Eeuo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
SOURCE_ROOT="$(cd "$SCRIPT_DIR/.." && pwd -P)"
HOME_DIR="${HOME:?HOME is required}"
LEGACY_PM2_NAME="${DEVSPACE_PM2_NAME:-devspace}"
V2_PM2_NAME="${DEVSPACE_V2_PM2_NAME:-devspace-v2-production}"
V2_LOCAL_PORT="${DEVSPACE_V2_PRODUCTION_PORT:-7678}"
PUBLIC_HTTPS_PORT_OVERRIDE="${DEVSPACE_V2_PUBLIC_HTTPS_PORT:-}"
TARGETS_FILE="$HOME_DIR/.devspace/targets.v2.json"
ROUTES_FILE="$HOME_DIR/.devspace/mcp-routes.v2.json"
ENV_PROFILES_FILE="$HOME_DIR/.devspace/env-profiles.v2.json"
PRODUCTION_ENV="$HOME_DIR/.devspace/universal-broker-v2-production.env"
RELEASES_ROOT="$HOME_DIR/.devspace/releases/universal-broker-v2"
AUDIT_ROOT="$HOME_DIR/.devspace/deployments/universal-broker-v2"
PHASE9_EVIDENCE="${DEVSPACE_V2_PHASE9_EVIDENCE:-$AUDIT_ROOT/phase9-current.json}"
LOAD_SSH_TARGET="${DEVSPACE_V2_LOAD_SSH_TARGET:-company}"
COMPANY_TARGET="${DEVSPACE_V2_COMPANY_TARGET:-company}"
WINDOWS_TARGET="${DEVSPACE_V2_WINDOWS_TARGET:-windows}"
CHROME_ROUTE="${DEVSPACE_V2_CHROME_ROUTE:-company-chrome}"
JIRA_ROUTE="${DEVSPACE_V2_JIRA_ROUTE:-company-jira}"
COMPUTER_USE_ROUTE="${DEVSPACE_V2_COMPUTER_USE_ROUTE:-company-computer-use}"
EXTERNAL_STORAGE_ROOT="${DEVSPACE_V2_EXTERNAL_STORAGE_ROOT:-/Volumes/Untitled}"
GUI_APPLICATION="${DEVSPACE_V2_GUI_APPLICATION:-Finder}"

if [[ "$#" -ne 0 ]]; then
  echo "Usage: $0" >&2
  exit 2
fi
if ! [[ "$V2_LOCAL_PORT" =~ ^[0-9]+$ ]] || (( V2_LOCAL_PORT < 1 || V2_LOCAL_PORT > 65535 )); then
  echo "Invalid DEVSPACE_V2_PRODUCTION_PORT: $V2_LOCAL_PORT" >&2
  exit 2
fi

for command in git node npm pm2 curl sqlite3 python3 tailscale; do
  command -v "$command" >/dev/null || {
    echo "Required command is unavailable: $command" >&2
    exit 1
  }
done

cd "$SOURCE_ROOT"
[[ -z "$(git status --porcelain=v1 --untracked-files=all)" ]] || {
  echo "Source tree must be clean before production deployment." >&2
  exit 1
}
HEAD_SHA="$(git rev-parse HEAD)"
UPSTREAM_SHA="$(git rev-parse '@{upstream}')"
[[ "$HEAD_SHA" == "$UPSTREAM_SHA" ]] || {
  echo "Source HEAD is not equal to its pushed upstream revision." >&2
  exit 1
}
[[ -f "$PHASE9_EVIDENCE" ]] || {
  echo "Phase 9 ChatGPT evidence is missing: $PHASE9_EVIDENCE" >&2
  exit 1
}
python3 - "$PHASE9_EVIDENCE" "$HEAD_SHA" <<'PY'
import json, sys
path, expected_commit = sys.argv[1:]
value = json.load(open(path))
expected_tools = ["target", "context", "fs", "exec", "process", "mcp", "artifact", "gui"]
if value.get("status") != "PASS": raise SystemExit("Phase 9 evidence status is not PASS")
if value.get("sourceCommit") != expected_commit: raise SystemExit("Phase 9 evidence is for a different source commit")
if value.get("connectorName") != "myDevSpace-next": raise SystemExit("Phase 9 connector identity is invalid")
if int(value.get("freshChatGptSessions", 0)) < 5: raise SystemExit("Phase 9 has fewer than five fresh ChatGPT sessions")
if value.get("toolNames") != expected_tools: raise SystemExit("Phase 9 tool surface is not the fixed eight-tool contract")
required = {"local", "external-storage", "ssh", "mcp-mutation", "artifact", "gui"}
if not required.issubset(set(value.get("scenarios", []))): raise SystemExit("Phase 9 scenario evidence is incomplete")
PY

TIMESTAMP="$(date -u +%Y%m%dT%H%M%SZ)"
AUDIT="$AUDIT_ROOT/$TIMESTAMP-$HEAD_SHA"
RELEASE="$RELEASES_ROOT/$HEAD_SHA"
mkdir -p "$AUDIT_ROOT" "$RELEASES_ROOT"
mkdir "$AUDIT"
chmod 700 "$AUDIT"
printf '%s\n' "$HEAD_SHA" >"$AUDIT/source-commit"
git status --short --branch >"$AUDIT/source-status.txt"
git diff --exit-code >"$AUDIT/source-diff.txt"
git ls-remote origin "$(git branch --show-current)" >"$AUDIT/source-remote.txt"
cp -p "$PHASE9_EVIDENCE" "$AUDIT/phase9-evidence.json"

if [[ ! -d "$RELEASE/.git" && ! -f "$RELEASE/.git" ]]; then
  git worktree add --detach "$RELEASE" "$HEAD_SHA"
fi
cd "$RELEASE"
[[ "$(git rev-parse HEAD)" == "$HEAD_SHA" ]]
[[ -z "$(git status --porcelain=v1 --untracked-files=all)" ]]
npm ci >"$AUDIT/npm-ci.log" 2>&1
npm run release:verify -- --require-clean >"$AUDIT/release-verify.log" 2>&1
DEVSPACE_V2_LOAD_TARGET_CONFIG="$TARGETS_FILE" \
DEVSPACE_V2_LOAD_SSH_TARGET="$LOAD_SSH_TARGET" \
  npm run v2:load >"$AUDIT/load.log" 2>&1

BASE_CONFIG_JSON="$AUDIT/base-config.json"
node --input-type=module <<'NODE' >"$BASE_CONFIG_JSON"
import { loadConfig } from './dist/config.js';
const config = loadConfig();
console.log(JSON.stringify({
  host: config.host,
  port: config.port,
  publicBaseUrl: config.publicBaseUrl,
  stateDir: config.stateDir,
  allowedHosts: config.allowedHosts,
}, null, 2));
NODE
BASE_CONFIG_TSV="$(python3 - "$BASE_CONFIG_JSON" <<'PY'
import json, sys
value=json.load(open(sys.argv[1]))
print('\t'.join([
    str(value['host']),
    str(value['port']),
    str(value['publicBaseUrl']),
    str(value['stateDir']),
    ','.join(map(str, value.get('allowedHosts', []))),
]))
PY
)"
IFS=$'\t' read -r LEGACY_HOST LEGACY_PORT PUBLIC_BASE_URL BASE_STATE_DIR BASE_ALLOWED_HOSTS <<<"$BASE_CONFIG_TSV"
DATABASE="$BASE_STATE_DIR/devspace.sqlite"

PUBLIC_PARTS="$(node -e '
const url = new URL(process.argv[1]);
if (url.protocol !== "https:" || url.search || url.hash || url.username || url.password) process.exit(2);
const path = url.pathname === "/" ? "/" : url.pathname.replace(/\/+$/, "");
const serviceBase = url.origin + (path === "/" ? "" : path);
process.stdout.write([serviceBase, url.host, url.hostname, path, url.port || "443"].join("\t"));
' "$PUBLIC_BASE_URL")" || {
  echo "Production publicBaseUrl must be a credential-free HTTPS service base." >&2
  exit 1
}
IFS=$'\t' read -r PUBLIC_SERVICE_BASE PUBLIC_HOST PUBLIC_HOSTNAME PUBLIC_PATH PUBLIC_HTTPS_PORT <<<"$PUBLIC_PARTS"
if [[ -n "$PUBLIC_HTTPS_PORT_OVERRIDE" ]]; then PUBLIC_HTTPS_PORT="$PUBLIC_HTTPS_PORT_OVERRIDE"; fi
if ! [[ "$PUBLIC_HTTPS_PORT" =~ ^[0-9]+$ ]] || (( PUBLIC_HTTPS_PORT < 1 || PUBLIC_HTTPS_PORT > 65535 )); then
  echo "Invalid public HTTPS port: $PUBLIC_HTTPS_PORT" >&2
  exit 1
fi
LOCAL_V2_BASE="http://127.0.0.1:$V2_LOCAL_PORT"
LOCAL_V2_HEALTH="$LOCAL_V2_BASE/healthz"
LOCAL_V2_MCP="$LOCAL_V2_BASE/mcp"
LOCAL_LEGACY_HEALTH="http://127.0.0.1:$LEGACY_PORT/healthz"
PUBLIC_HEALTH="$PUBLIC_SERVICE_BASE/healthz"
PUBLIC_MCP="$PUBLIC_SERVICE_BASE/mcp"

[[ "$V2_LOCAL_PORT" != "$LEGACY_PORT" ]] || {
  echo "The v2 blue/green port must differ from the legacy production port." >&2
  exit 1
}
[[ -f "$DATABASE" ]] || { echo "Production OAuth database is missing: $DATABASE" >&2; exit 1; }
for file in "$TARGETS_FILE" "$ROUTES_FILE"; do
  [[ -f "$file" ]] || { echo "Required v2 configuration is missing: $file" >&2; exit 1; }
done
[[ "$(stat -f '%Lp' "$TARGETS_FILE" 2>/dev/null || stat -c '%a' "$TARGETS_FILE")" == "600" ]]
[[ "$(stat -f '%Lp' "$ROUTES_FILE" 2>/dev/null || stat -c '%a' "$ROUTES_FILE")" == "600" ]]

legacy_pid="$(pm2 pid "$LEGACY_PM2_NAME" 2>/dev/null | tail -1 | tr -d '[:space:]')"
[[ -n "$legacy_pid" && "$legacy_pid" != "0" ]] || {
  echo "Legacy production PM2 process is not online: $LEGACY_PM2_NAME" >&2
  exit 1
}
v2_pid="$(pm2 pid "$V2_PM2_NAME" 2>/dev/null | tail -1 | tr -d '[:space:]')"
[[ -z "$v2_pid" || "$v2_pid" == "0" ]] || {
  echo "A v2 production PM2 process already exists; roll it back before a new cutover: $V2_PM2_NAME" >&2
  exit 1
}
curl -fsS "$LOCAL_LEGACY_HEALTH" >"$AUDIT/legacy-health.before.json"

backup_file() {
  local source="$1" name="$2"
  if [[ -e "$source" || -L "$source" ]]; then
    cp -a "$source" "$AUDIT/$name.before"
  else
    : >"$AUDIT/$name.absent"
  fi
}
backup_file "$HOME_DIR/.devspace/start.sh" start.sh
backup_file "$PRODUCTION_ENV" production.env
backup_file "$TARGETS_FILE" targets.v2.json
backup_file "$ROUTES_FILE" mcp-routes.v2.json
backup_file "$ENV_PROFILES_FILE" env-profiles.v2.json
backup_file "$HOME_DIR/.devspace/auth.json" auth.json
pm2 jlist >"$AUDIT/pm2.before.json"
tailscale funnel status --json >"$AUDIT/funnel.before.json"
sqlite3 "$DATABASE" ".backup '$AUDIT/devspace.sqlite.before'"

switch_public_route() {
  local local_port="$1"
  if [[ "$PUBLIC_PATH" == "/" ]]; then
    tailscale funnel --bg --https="$PUBLIC_HTTPS_PORT" --yes "http://127.0.0.1:$local_port"
  else
    tailscale funnel --bg --https="$PUBLIC_HTTPS_PORT" --set-path="$PUBLIC_PATH" --yes "http://127.0.0.1:$local_port"
  fi
}
wait_health() {
  local url="$1" output="$2"
  for _ in $(seq 1 120); do
    if curl -fsS --max-time 5 "$url" >"$output" 2>/dev/null; then return 0; fi
    sleep 0.5
  done
  curl -fsS --max-time 5 "$url" >"$output"
}
assert_unauthenticated() {
  local url="$1" output="$2"
  local status
  status="$(curl -sS --max-time 10 -o "$output" -w '%{http_code}' -X POST \
    -H 'content-type: application/json' \
    --data '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"unauthenticated-gate","version":"1"}}}' \
    "$url")"
  [[ "$status" == "401" ]] || {
    echo "Unauthenticated MCP boundary returned $status for $url" >&2
    return 1
  }
}
restore_file() {
  local target="$1" name="$2"
  if [[ -e "$AUDIT/$name.before" || -L "$AUDIT/$name.before" ]]; then
    rm -rf "$target"
    cp -a "$AUDIT/$name.before" "$target"
  elif [[ -f "$AUDIT/$name.absent" ]]; then
    rm -rf "$target"
  fi
}

MUTATED=0
ROUTE_SWITCHED=0
V2_STARTED=0
ROLLBACK_NEEDED=1
rollback() {
  local rc="${1:-1}"
  trap - ERR INT TERM
  set +e
  if [[ "$ROLLBACK_NEEDED" -eq 1 ]]; then
    if [[ "$ROUTE_SWITCHED" -eq 1 ]]; then
      switch_public_route "$LEGACY_PORT" >"$AUDIT/rollback-funnel.log" 2>&1 || true
    fi
    if [[ "$V2_STARTED" -eq 1 ]]; then
      pm2 delete "$V2_PM2_NAME" >"$AUDIT/rollback-v2-pm2.log" 2>&1 || true
    fi
    restore_file "$PRODUCTION_ENV" production.env
    if [[ "$MUTATED" -eq 1 && -f "$AUDIT/devspace.sqlite.before" ]]; then
      pm2 stop "$LEGACY_PM2_NAME" >"$AUDIT/rollback-legacy-stop.log" 2>&1 || true
      cp -p "$AUDIT/devspace.sqlite.before" "$DATABASE.rollback"
      rm -f "$DATABASE-wal" "$DATABASE-shm"
      mv -f "$DATABASE.rollback" "$DATABASE"
      pm2 restart "$LEGACY_PM2_NAME" --update-env >"$AUDIT/rollback-legacy-restart.log" 2>&1 || true
    fi
    pm2 save >"$AUDIT/rollback-pm2-save.log" 2>&1 || true
    wait_health "$LOCAL_LEGACY_HEALTH" "$AUDIT/rollback-legacy-health.json" || true
    printf '{"status":"ROLLED_BACK","sourceCommit":"%s","exitCode":%s}\n' \
      "$HEAD_SHA" "$rc" >"$AUDIT/result.json"
    ln -sfn "$AUDIT" "$AUDIT_ROOT/current"
  fi
  exit "$rc"
}
trap 'rollback $?' ERR
trap 'rollback 130' INT
trap 'rollback 143' TERM

quote() { printf '%q' "$1"; }
V2_STATE_DIR="$BASE_STATE_DIR/universal-broker-v2-production"
ALLOWED_HOSTS="$BASE_ALLOWED_HOSTS,$PUBLIC_HOST,$PUBLIC_HOSTNAME,127.0.0.1:$V2_LOCAL_PORT,127.0.0.1"
ENV_NEXT="$AUDIT/production.env.new"
cat >"$ENV_NEXT" <<EOF
DEVSPACE_V2_DEPLOYMENT_MODE=$(quote production)
DEVSPACE_V2_LEGACY_SCOPE_COMPATIBILITY=$(quote true)
DEVSPACE_NEXT_HOST=$(quote 127.0.0.1)
DEVSPACE_NEXT_PORT=$(quote "$V2_LOCAL_PORT")
DEVSPACE_NEXT_PUBLIC_BASE_URL=$(quote "$PUBLIC_SERVICE_BASE")
DEVSPACE_NEXT_MCP_PATH=$(quote /mcp)
DEVSPACE_NEXT_STATE_DIR=$(quote "$V2_STATE_DIR")
DEVSPACE_NEXT_TARGETS_FILE=$(quote "$TARGETS_FILE")
DEVSPACE_NEXT_MCP_ROUTES_FILE=$(quote "$ROUTES_FILE")
DEVSPACE_NEXT_ENV_PROFILE_CONFIG=$(quote "$ENV_PROFILES_FILE")
DEVSPACE_NEXT_ALLOWED_HOSTS=$(quote "$ALLOWED_HOSTS")
DEVSPACE_TRUST_PROXY=$(quote 1)
EOF
chmod 600 "$ENV_NEXT"
mkdir -p "$(dirname "$PRODUCTION_ENV")" "$V2_STATE_DIR"
chmod 700 "$(dirname "$PRODUCTION_ENV")" "$V2_STATE_DIR"
cp -p "$ENV_NEXT" "$PRODUCTION_ENV.next"
mv -f "$PRODUCTION_ENV.next" "$PRODUCTION_ENV"
MUTATED=1

DEVSPACE_PRODUCTION_ENV_FILE="$PRODUCTION_ENV" \
  pm2 start "$RELEASE/scripts/start-universal-broker-v2-production.sh" \
    --name "$V2_PM2_NAME" \
    --interpreter /bin/bash \
    --cwd "$RELEASE" \
    --time >"$AUDIT/v2-pm2-start.log" 2>&1
V2_STARTED=1
wait_health "$LOCAL_V2_HEALTH" "$AUDIT/v2-health.local.json"
assert_unauthenticated "$LOCAL_V2_MCP" "$AUDIT/v2-mcp.local.unauthenticated.json"

node scripts/verify-universal-broker-v2-live.mjs \
  --base-url "$LOCAL_V2_BASE" \
  --mcp-url "$LOCAL_V2_MCP" \
  --health-url "$LOCAL_V2_HEALTH" \
  --artifact-fetch-base-url "$LOCAL_V2_BASE" \
  --token-resource "$PUBLIC_MCP" \
  --database "$DATABASE" \
  --sessions 5 \
  --company-target "$COMPANY_TARGET" \
  --windows-target "$WINDOWS_TARGET" \
  --external-storage-root "$EXTERNAL_STORAGE_ROOT" \
  --chrome-route "$CHROME_ROUTE" \
  --jira-route "$JIRA_ROUTE" \
  --computer-use-route "$COMPUTER_USE_ROUTE" \
  --gui-application "$GUI_APPLICATION" \
  --output "$AUDIT/live-canaries.local.json" \
  >"$AUDIT/live-canaries.local.log" 2>&1

switch_public_route "$V2_LOCAL_PORT" >"$AUDIT/funnel-cutover.log" 2>&1
ROUTE_SWITCHED=1
wait_health "$PUBLIC_HEALTH" "$AUDIT/v2-health.public.json"
assert_unauthenticated "$PUBLIC_MCP" "$AUDIT/v2-mcp.public.unauthenticated.json"
node scripts/verify-universal-broker-v2-live.mjs \
  --base-url "$PUBLIC_SERVICE_BASE" \
  --mcp-url "$PUBLIC_MCP" \
  --health-url "$PUBLIC_HEALTH" \
  --database "$DATABASE" \
  --sessions 5 \
  --company-target "$COMPANY_TARGET" \
  --windows-target "$WINDOWS_TARGET" \
  --external-storage-root "$EXTERNAL_STORAGE_ROOT" \
  --chrome-route "$CHROME_ROUTE" \
  --jira-route "$JIRA_ROUTE" \
  --computer-use-route "$COMPUTER_USE_ROUTE" \
  --gui-application "$GUI_APPLICATION" \
  --output "$AUDIT/live-canaries.public.json" \
  >"$AUDIT/live-canaries.public.log" 2>&1

# Exact routing rollback rehearsal while the immutable legacy process remains online.
switch_public_route "$LEGACY_PORT" >"$AUDIT/rollback-drill-to-legacy.log" 2>&1
wait_health "$PUBLIC_HEALTH" "$AUDIT/rollback-drill-legacy-health.json"
assert_unauthenticated "$PUBLIC_MCP" "$AUDIT/rollback-drill-legacy-mcp.json"
switch_public_route "$V2_LOCAL_PORT" >"$AUDIT/rollback-drill-to-v2.log" 2>&1
wait_health "$PUBLIC_HEALTH" "$AUDIT/rollback-drill-v2-health.json"
assert_unauthenticated "$PUBLIC_MCP" "$AUDIT/rollback-drill-v2-mcp.json"

bash scripts/configure-devspace-log-rotation.sh >"$AUDIT/log-rotation.log" 2>&1
pm2 save >"$AUDIT/pm2-save.log" 2>&1
pm2 jlist >"$AUDIT/pm2.after.json"
tailscale funnel status --json >"$AUDIT/funnel.after.json"

cat >"$AUDIT/route.json" <<EOF
{
  "publicServiceBase": $(node -e 'process.stdout.write(JSON.stringify(process.argv[1]))' "$PUBLIC_SERVICE_BASE"),
  "publicPath": $(node -e 'process.stdout.write(JSON.stringify(process.argv[1]))' "$PUBLIC_PATH"),
  "publicHttpsPort": $PUBLIC_HTTPS_PORT,
  "legacyLocalPort": $LEGACY_PORT,
  "v2LocalPort": $V2_LOCAL_PORT,
  "legacyPm2Name": $(node -e 'process.stdout.write(JSON.stringify(process.argv[1]))' "$LEGACY_PM2_NAME"),
  "v2Pm2Name": $(node -e 'process.stdout.write(JSON.stringify(process.argv[1]))' "$V2_PM2_NAME")
}
EOF
chmod 600 "$AUDIT/route.json"

ROLLBACK_NEEDED=0
trap - ERR INT TERM
cat >"$AUDIT/result.json" <<EOF
{
  "status": "CUTOVER_PASS",
  "sourceCommit": "$HEAD_SHA",
  "release": $(node -e 'process.stdout.write(JSON.stringify(process.argv[1]))' "$RELEASE"),
  "localHealth": "$LOCAL_V2_HEALTH",
  "publicHealth": "$PUBLIC_HEALTH",
  "protocolSessions": 10,
  "rollbackRehearsed": true,
  "legacyRuntimeRetainedForConnectorTransition": true,
  "productionConnectorReconnectPending": true,
  "ownerCredentialRotationPending": true,
  "oldOAuthRevocationPending": true
}
EOF
chmod 600 "$AUDIT/result.json"
ln -sfn "$AUDIT" "$AUDIT_ROOT/current"
echo "Universal Broker v2 blue/green production cutover passed: $HEAD_SHA"
