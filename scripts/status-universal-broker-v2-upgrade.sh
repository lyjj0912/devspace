#!/usr/bin/env bash
set -euo pipefail
ROOT="${HOME}/.devspace/deployments/universal-broker-v2"
VALUE="${1:-}"
if [[ -z "$VALUE" ]]; then
  STATUS="$(find "$ROOT" -maxdepth 2 -type f -name status.json -path '*/upgrade-*/*' -print0 2>/dev/null | xargs -0 ls -1t 2>/dev/null | head -n1 || true)"
elif [[ -f "$VALUE" ]]; then
  STATUS="$VALUE"
else
  STATUS="$(find "$ROOT" -maxdepth 2 -type f -name status.json -path '*/upgrade-*/*' -print0 2>/dev/null | while IFS= read -r -d '' path; do
    python3 - "$path" "$VALUE" <<'PY'
import json,sys
try:v=json.load(open(sys.argv[1]))
except:raise SystemExit
if v.get('transactionId')==sys.argv[2]:print(sys.argv[1])
PY
  done | head -n1)"
fi
[[ -n "$STATUS" && -f "$STATUS" ]] || { echo "Production upgrade status not found: ${VALUE:-latest}" >&2; exit 1; }
python3 -m json.tool "$STATUS"
