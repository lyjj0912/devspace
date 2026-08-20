#!/bin/bash
set -Eeuo pipefail

repo="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
process_name="devspace-next"
public_base_url=""
local_port=7677
funnel_port=""
verify=1

while [[ "$#" -gt 0 ]]; do
  case "$1" in
    --public-base-url)
      public_base_url="${2:-}"
      shift 2
      ;;
    --port)
      local_port="${2:-}"
      shift 2
      ;;
    --funnel-port)
      funnel_port="${2:-}"
      shift 2
      ;;
    --skip-verify)
      verify=0
      shift
      ;;
    *)
      echo "Unknown option: $1" >&2
      exit 2
      ;;
  esac
done

if [[ -z "$public_base_url" ]]; then
  echo "--public-base-url is required." >&2
  exit 2
fi
if ! [[ "$local_port" =~ ^[0-9]+$ ]] || (( local_port < 1 || local_port > 65535 )); then
  echo "Invalid --port: $local_port" >&2
  exit 2
fi
if [[ -n "$funnel_port" ]] \
  && { ! [[ "$funnel_port" =~ ^[0-9]+$ ]] || (( funnel_port < 1 || funnel_port > 65535 )); }; then
  echo "Invalid --funnel-port: $funnel_port" >&2
  exit 2
fi

public_parts="$(node -e '
const value = process.argv[1];
const url = new URL(value);
if (url.protocol !== "https:" || url.search || url.hash || url.username || url.password) process.exit(2);
const path = url.pathname === "/" ? "" : url.pathname.replace(/\/+$/, "");
process.stdout.write([url.origin + path, url.host, url.hostname, path || "/"].join("\t"));
' "$public_base_url")" || {
  echo "--public-base-url must be a credential-free HTTPS service base without a query or fragment." >&2
  exit 2
}
IFS=$'\t' read -r public_service_base public_host public_hostname funnel_path <<<"$public_parts"

cd "$repo"
if [[ -n "$(git status --porcelain=v1 --untracked-files=all)" ]]; then
  echo "Refusing to deploy Universal Broker v2 from a dirty Git tree." >&2
  exit 1
fi
if [[ "$verify" -eq 1 ]]; then
  npm run release:verify -- --require-clean
fi

config_dir="$HOME/.devspace"
state_dir="$HOME/.local/share/devspace/universal-broker-v2"
env_file="$config_dir/universal-broker-v2.env"
env_temp="$env_file.tmp-$$"
mkdir -p "$config_dir" "$state_dir"
chmod 700 "$config_dir" "$state_dir"
umask 077

quote() { printf '%q' "$1"; }
cat >"$env_temp" <<EOF
DEVSPACE_NEXT_HOST=$(quote 127.0.0.1)
DEVSPACE_NEXT_PORT=$(quote "$local_port")
DEVSPACE_NEXT_PUBLIC_BASE_URL=$(quote "$public_service_base")
DEVSPACE_NEXT_MCP_PATH=$(quote /mcp-next)
DEVSPACE_NEXT_STATE_DIR=$(quote "$state_dir")
DEVSPACE_NEXT_TARGETS_FILE=$(quote "$config_dir/targets.v2.json")
DEVSPACE_NEXT_MCP_ROUTES_FILE=$(quote "$config_dir/mcp-routes.v2.json")
DEVSPACE_NEXT_ENV_PROFILE_CONFIG=$(quote "$config_dir/env-profiles.v2.json")
DEVSPACE_NEXT_SELF_MANAGEMENT_DIR=$(quote "$state_dir/self-management")
DEVSPACE_NEXT_PM2_PROCESS_NAME=$(quote "$process_name")
DEVSPACE_NEXT_SELF_RESTART_TIMEOUT_MS=$(quote 120000)
DEVSPACE_NEXT_ALLOWED_HOSTS=$(quote "$public_host,$public_hostname,127.0.0.1:$local_port,127.0.0.1")
DEVSPACE_TRUST_PROXY=$(quote 1)
EOF
chmod 600 "$env_temp"
mv "$env_temp" "$env_file"

had_process=0
existing_pid="$(pm2 pid "$process_name" 2>/dev/null | tail -1 | tr -d '[:space:]')"
if [[ -n "$existing_pid" && "$existing_pid" != "0" ]]; then
  had_process=1
fi
funnel_added=0
rollback() {
  local rc="${1:-1}"
  trap - ERR INT TERM
  set +e
  if [[ "$funnel_added" -eq 1 ]]; then
    if [[ "$funnel_path" == "/" ]]; then
      tailscale funnel --https="$funnel_port" --yes off >/dev/null 2>&1 || true
    else
      tailscale funnel --https="$funnel_port" --set-path="$funnel_path" --yes off >/dev/null 2>&1 || true
    fi
  fi
  if [[ "$had_process" -eq 0 ]]; then
    pm2 delete "$process_name" >/dev/null 2>&1 || true
  fi
  pm2 save >/dev/null 2>&1 || true
  exit "$rc"
}
trap 'rollback $?' ERR
trap 'rollback 130' INT
trap 'rollback 143' TERM

if [[ "$had_process" -eq 1 ]]; then
  pm2 restart "$process_name" --update-env
else
  pm2 start "$repo/scripts/start-universal-broker-v2.sh" \
    --name "$process_name" \
    --interpreter /bin/bash \
    --cwd "$repo" \
    --time
fi

local_health="http://127.0.0.1:$local_port/healthz-next"
for _ in $(seq 1 120); do
  if curl --fail --silent --show-error --max-time 5 "$local_health" >/dev/null 2>&1; then break; fi
  sleep 0.25
done
curl --fail --silent --show-error --max-time 5 "$local_health" >/dev/null

if [[ -n "$funnel_port" ]]; then
  if [[ "$funnel_path" == "/" ]]; then
    tailscale funnel --bg --https="$funnel_port" --yes "http://127.0.0.1:$local_port"
  else
    tailscale funnel --bg --https="$funnel_port" --set-path="$funnel_path" --yes "http://127.0.0.1:$local_port"
  fi
  funnel_added=1
  public_health="$public_service_base/healthz-next"
  for _ in $(seq 1 120); do
    if curl --fail --silent --show-error --max-time 5 "$public_health" >/dev/null 2>&1; then break; fi
    sleep 0.5
  done
  curl --fail --silent --show-error --max-time 5 "$public_health" >/dev/null
fi

pm2 save
trap - ERR INT TERM
printf 'Universal Broker v2 deployed from %s at %s/mcp-next\n' "$(git rev-parse HEAD)" "$public_service_base"
