#!/bin/bash
set -euo pipefail

funnel_port=""
funnel_path="/"
keep_state=0
while [[ "$#" -gt 0 ]]; do
  case "$1" in
    --funnel-port) funnel_port="${2:-}"; shift 2 ;;
    --funnel-path) funnel_path="${2:-}"; shift 2 ;;
    --keep-state) keep_state=1; shift ;;
    *) echo "Unknown option: $1" >&2; exit 2 ;;
  esac
done

if [[ -n "$funnel_port" ]]; then
  funnel_output="$(mktemp -t devspace-v2-funnel-off.XXXXXX)"
  command=(tailscale funnel --https="$funnel_port")
  if [[ "$funnel_path" != "/" ]]; then command+=(--set-path="$funnel_path"); fi
  command+=(--yes off)
  if ! "${command[@]}" >"$funnel_output" 2>&1; then
    if ! grep -q 'handler does not exist' "$funnel_output"; then
      cat "$funnel_output" >&2
      rm -f "$funnel_output"
      exit 1
    fi
  fi
  rm -f "$funnel_output"
fi
pm2 delete devspace-next >/dev/null 2>&1 || true
pm2 save
rm -f "$HOME/.devspace/universal-broker-v2.env"
if [[ "$keep_state" -ne 1 ]]; then
  rm -rf "$HOME/.local/share/devspace/universal-broker-v2"
fi
echo "Universal Broker v2 parallel deployment removed."
