#!/bin/bash
set -Eeuo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
HOME_DIR="${HOME:?HOME is required}"
AUDIT_ROOT="$HOME_DIR/.devspace/deployments/universal-broker-v2"
COMMAND="${1:-}"
AUDIT=""
EVIDENCE=""
DRIVER=""
INTERRUPT_AFTER_ACTION=""

[[ -n "$COMMAND" ]] && shift
while [[ "$#" -gt 0 ]]; do
  case "$1" in
    --audit) AUDIT="${2:-}"; shift 2 ;;
    --evidence) EVIDENCE="${2:-}"; shift 2 ;;
    --driver) DRIVER="${2:-}"; shift 2 ;;
    --interrupt-after-action) INTERRUPT_AFTER_ACTION="${2:-}"; shift 2 ;;
    *)
      echo "Usage: $0 <prepare|seal> --evidence FILE [--audit DIR] [--driver FILE]" >&2
      exit 2
      ;;
  esac
done

[[ "$COMMAND" == prepare || "$COMMAND" == seal ]] || {
  echo "Usage: $0 <prepare|seal> --evidence FILE [--audit DIR] [--driver FILE]" >&2
  exit 2
}
[[ -n "$EVIDENCE" && -f "$EVIDENCE" ]] || { echo "Evidence file is missing: $EVIDENCE" >&2; exit 1; }
AUDIT="${AUDIT:-$AUDIT_ROOT/current}"
AUDIT="$(cd "$AUDIT" 2>/dev/null && pwd -P)" || { echo "Deployment audit is unavailable: $AUDIT" >&2; exit 1; }

NODE="$(command -v node)" || { echo "Node.js is required." >&2; exit 1; }
NODE_MAJOR="$($NODE -p 'Number(process.versions.node.split(".")[0])')"
(( NODE_MAJOR >= 22 )) || { echo "Finalization requires Node.js 22 or newer; observed $($NODE --version)." >&2; exit 1; }

arguments=(
  "$SCRIPT_DIR/finalize-universal-broker-v2.mjs"
  "$COMMAND"
  --audit "$AUDIT"
  --evidence "$EVIDENCE"
)
if [[ "$COMMAND" == seal ]]; then
  DRIVER="${DRIVER:-$SCRIPT_DIR/finalization-live-driver.mjs}"
  [[ -f "$DRIVER" ]] || { echo "Finalization driver is unavailable: $DRIVER" >&2; exit 1; }
  arguments+=(--driver "$DRIVER")
  [[ -z "$INTERRUPT_AFTER_ACTION" ]] || arguments+=(--interrupt-after-action "$INTERRUPT_AFTER_ACTION")
fi

# prepare only validates/copies inventory and the destructive plan into the audit
# directory. The driver is intentionally unreachable until seal.
exec "$NODE" "${arguments[@]}"
