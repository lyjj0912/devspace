#!/bin/bash
set -euo pipefail

repo="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
env_file="${DEVSPACE_NEXT_ENV_FILE:-$HOME/.devspace/universal-broker-v2.env}"
expected_script_fallback="${DEVSPACE_NEXT_PM2_EXPECTED_SCRIPT-}"

if [[ ! -f "$env_file" ]]; then
  echo "Universal Broker v2 environment file is missing: $env_file" >&2
  exit 1
fi
mode="$(stat -f '%Lp' "$env_file" 2>/dev/null || stat -c '%a' "$env_file")"
if [[ "$mode" != "600" ]]; then
  echo "Universal Broker v2 environment file must be mode 0600: $env_file ($mode)" >&2
  exit 1
fi

if [[ -s "$HOME/.nvm/nvm.sh" ]]; then
  # shellcheck source=/dev/null
  source "$HOME/.nvm/nvm.sh"
  nvm use 22 >/dev/null
fi

# The owner-only environment file is the only runtime authority for DevSpace
# settings. PM2 and the serving broker may otherwise leak removed or stale
# DEVSPACE_* values into a candidate, upgrade, rollback, or ordinary restart.
while IFS= read -r variable; do
  unset "$variable"
done < <(compgen -A variable DEVSPACE_)

set -a
# shellcheck source=/dev/null
source "$env_file"
set +a

# The production wrapper supplies the exact script path as a fallback for older
# owner files. A value explicitly recorded in the environment file wins.
if [[ -z "${DEVSPACE_NEXT_PM2_EXPECTED_SCRIPT-}" && -n "$expected_script_fallback" ]]; then
  export DEVSPACE_NEXT_PM2_EXPECTED_SCRIPT="$expected_script_fallback"
fi

unset DEVSPACE_OAUTH_OWNER_TOKEN
exec node "$repo/dist/cli.js" serve-next
