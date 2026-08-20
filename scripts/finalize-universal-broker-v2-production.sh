#!/bin/bash
set -Eeuo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
HOME_DIR="${HOME:?HOME is required}"
COMMAND="${1:-}"
STORE="${DEVSPACE_NEXT_LIFECYCLE_FINALIZATION_STORE:-$HOME_DIR/.devspace/state/universal-broker-v2/lifecycle.sqlite}"
CONTROL="${DEVSPACE_NEXT_LIFECYCLE_FINALIZATION_CONTROL:-$HOME_DIR/.devspace/state/universal-broker-v2-finalization-control/lifecycle-finalization-head.json}"
STATE_DIR="${DEVSPACE_MANAGEMENT_AUTHORIZATION_STATE_DIR:-$HOME_DIR/.devspace/state/universal-broker-v2/management-authorization}"
KEY_REF="${DEVSPACE_MANAGEMENT_AUTHORIZATION_KEY_REF:-production-management}"
AUDIT="${DEVSPACE_DEPLOYMENT_AUDIT_ROOT:-$HOME_DIR/.devspace/deployments/universal-broker-v2/current}"

[[ -n "$COMMAND" ]] && shift
while [[ "$#" -gt 0 ]]; do
  case "$1" in
    --store) STORE="${2:-}"; shift 2 ;;
    --control) CONTROL="${2:-}"; shift 2 ;;
    --state-dir) STATE_DIR="${2:-}"; shift 2 ;;
    --key-ref) KEY_REF="${2:-}"; shift 2 ;;
    --audit) AUDIT="${2:-}"; shift 2 ;;
    *) echo "Usage: $0 <status|verify> [--store FILE --control FILE --state-dir DIR --key-ref REF --audit DIR]" >&2; exit 2 ;;
  esac
done

[[ "$COMMAND" == status || "$COMMAND" == verify ]] || {
  echo "Usage: $0 <status|verify> [--store FILE --control FILE --state-dir DIR --key-ref REF --audit DIR]" >&2
  exit 2
}
for path in "$STORE" "$CONTROL" "$STATE_DIR"; do
  [[ "$path" == /* ]] || { echo "Finalization paths must be absolute: $path" >&2; exit 2; }
done
[[ -f "$STORE" && -f "$CONTROL" && -d "$STATE_DIR" ]] || {
  echo "Finalization store/control/key state is unavailable." >&2
  exit 1
}

NODE="$(command -v node)" || { echo "Node.js is required." >&2; exit 1; }
NODE_MAJOR="$($NODE -p 'Number(process.versions.node.split(".")[0])')"
(( NODE_MAJOR >= 22 )) || { echo "Finalization requires Node.js 22 or newer; observed $($NODE --version)." >&2; exit 1; }

arguments=(
  "$SCRIPT_DIR/finalize-universal-broker-v2.mjs" "$COMMAND"
  --store "$STORE" --control "$CONTROL" --state-dir "$STATE_DIR" --key-ref "$KEY_REF"
)
if [[ "$COMMAND" == verify ]]; then
  [[ -d "$AUDIT" ]] || { echo "Deployment audit is unavailable: $AUDIT" >&2; exit 1; }
  AUDIT="$(cd "$AUDIT" && pwd -P)"
  arguments+=(--audit "$AUDIT")
fi
exec "$NODE" "${arguments[@]}"
