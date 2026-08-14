#!/bin/bash
set -euo pipefail

repo=$(cd "$(dirname "$0")/.." && pwd -P)
desired_cwd=$repo
cd "$repo"

pid=$(pm2 pid devspace 2>/dev/null | tail -1 | tr -d '[:space:]')
current_cwd=
if [[ -n "$pid" && "$pid" != "0" ]] && command -v lsof >/dev/null 2>&1; then
  current_cwd=$(lsof -a -p "$pid" -d cwd -Fn 2>/dev/null | sed -n 's/^n//p' | head -1)
fi

if [[ -n "$pid" && "$pid" != "0" && "$current_cwd" != "$desired_cwd" ]]; then
  echo "DevSpace PM2 cwd drift detected; recreating only the devspace process."
  pm2 delete devspace
  pm2 start ecosystem.config.cjs --only devspace
else
  pm2 startOrReload ecosystem.config.cjs --only devspace
fi

pm2 save
