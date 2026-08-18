#!/bin/bash
set -euo pipefail

script_path="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)/$(basename "${BASH_SOURCE[0]}")"
repo="$(cd "$(dirname "$script_path")/.." && pwd -P)"
export DEVSPACE_NEXT_PM2_EXPECTED_SCRIPT="${DEVSPACE_NEXT_PM2_EXPECTED_SCRIPT:-$script_path}"
export DEVSPACE_NEXT_ENV_FILE="${DEVSPACE_PRODUCTION_ENV_FILE:-$HOME/.devspace/universal-broker-v2-production.env}"
exec "$repo/scripts/start-universal-broker-v2.sh"
