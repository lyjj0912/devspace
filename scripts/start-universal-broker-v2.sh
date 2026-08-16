#!/bin/bash
set -euo pipefail

repo="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
env_file="${DEVSPACE_NEXT_ENV_FILE:-$HOME/.devspace/universal-broker-v2.env}"

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

set -a
# shellcheck source=/dev/null
source "$env_file"
set +a

unset DEVSPACE_OAUTH_OWNER_TOKEN
exec node "$repo/dist/cli.js" serve-next
