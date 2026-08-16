#!/bin/bash
set -euo pipefail

repo="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
export DEVSPACE_NEXT_ENV_FILE="${DEVSPACE_PRODUCTION_ENV_FILE:-$HOME/.devspace/universal-broker-v2-production.env}"
exec "$repo/scripts/start-universal-broker-v2.sh"
