#!/bin/bash
set -Eeuo pipefail

HOME_DIR="${HOME:?HOME is required}"
AUDIT_ROOT="$HOME_DIR/.devspace/deployments/universal-broker-v2"
AUDIT=""
RESTORE_STATE=1
while [[ "$#" -gt 0 ]]; do
  case "$1" in
    --audit)
      AUDIT="${2:-}"
      shift 2
      ;;
    --preserve-current-state)
      RESTORE_STATE=0
      shift
      ;;
    *)
      echo "Usage: $0 [--audit <deployment-audit>] [--preserve-current-state]" >&2
      exit 2
      ;;
  esac
done
AUDIT="${AUDIT:-$AUDIT_ROOT/current}"
AUDIT="$(cd "$AUDIT" 2>/dev/null && pwd -P)" || {
  echo "Deployment audit is unavailable: $AUDIT" >&2
  exit 1
}
for file in route.json result.json base-config.json; do
  [[ -f "$AUDIT/$file" ]] || { echo "Audit file is missing: $AUDIT/$file" >&2; exit 1; }
done

readarray_safe() {
  python3 - "$AUDIT/route.json" "$AUDIT/base-config.json" <<'PY'
import json, sys
route=json.load(open(sys.argv[1])); base=json.load(open(sys.argv[2]))
print('\t'.join(map(str, [
    route['publicPath'], route['publicHttpsPort'], route['legacyLocalPort'],
    route['legacyPm2Name'], route['v2Pm2Name'], base['stateDir'],
])))
PY
}
IFS=$'\t' read -r PUBLIC_PATH PUBLIC_HTTPS_PORT LEGACY_PORT LEGACY_PM2_NAME V2_PM2_NAME BASE_STATE_DIR <<<"$(readarray_safe)"
DATABASE="$BASE_STATE_DIR/devspace.sqlite"
PRODUCTION_ENV="$HOME_DIR/.devspace/universal-broker-v2-production.env"
TARGETS_FILE="$HOME_DIR/.devspace/targets.v2.json"
ROUTES_FILE="$HOME_DIR/.devspace/mcp-routes.v2.json"
ENV_PROFILES_FILE="$HOME_DIR/.devspace/env-profiles.v2.json"
AUTH_FILE="$HOME_DIR/.devspace/auth.json"
START_SCRIPT="$HOME_DIR/.devspace/start.sh"

for command in pm2 curl tailscale sqlite3 python3 node; do
  command -v "$command" >/dev/null || { echo "Required command is unavailable: $command" >&2; exit 1; }
done

switch_legacy_route() {
  if [[ "$PUBLIC_PATH" == "/" ]]; then
    tailscale funnel --bg --https="$PUBLIC_HTTPS_PORT" --yes "http://127.0.0.1:$LEGACY_PORT"
  else
    tailscale funnel --bg --https="$PUBLIC_HTTPS_PORT" --set-path="$PUBLIC_PATH" --yes "http://127.0.0.1:$LEGACY_PORT"
  fi
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

switch_legacy_route
pm2 delete "$V2_PM2_NAME" >/dev/null 2>&1 || true
restore_file "$PRODUCTION_ENV" production.env
restore_file "$TARGETS_FILE" targets.v2.json
restore_file "$ROUTES_FILE" mcp-routes.v2.json
restore_file "$ENV_PROFILES_FILE" env-profiles.v2.json
restore_file "$AUTH_FILE" auth.json
restore_file "$START_SCRIPT" start.sh

if [[ "$RESTORE_STATE" -eq 1 && -f "$AUDIT/devspace.sqlite.before" ]]; then
  pm2 stop "$LEGACY_PM2_NAME" >/dev/null 2>&1 || true
  mkdir -p "$(dirname "$DATABASE")"
  cp -p "$AUDIT/devspace.sqlite.before" "$DATABASE.rollback"
  rm -f "$DATABASE-wal" "$DATABASE-shm"
  mv -f "$DATABASE.rollback" "$DATABASE"
fi
pm2 restart "$LEGACY_PM2_NAME" --update-env
for _ in $(seq 1 120); do
  if curl -fsS --max-time 5 "http://127.0.0.1:$LEGACY_PORT/healthz" >/dev/null 2>&1; then break; fi
  sleep 0.5
done
curl -fsS --max-time 5 "http://127.0.0.1:$LEGACY_PORT/healthz" >"$AUDIT/manual-rollback-health.json"
pm2 save
cat >"$AUDIT/manual-rollback-result.json" <<EOF
{
  "status": "ROLLBACK_PASS",
  "audit": $(node -e 'process.stdout.write(JSON.stringify(process.argv[1]))' "$AUDIT"),
  "stateRestored": $([[ "$RESTORE_STATE" -eq 1 ]] && echo true || echo false),
  "legacyLocalPort": $LEGACY_PORT
}
EOF
chmod 600 "$AUDIT/manual-rollback-result.json"
echo "Legacy DevSpace production service restored from $AUDIT"
