#!/bin/bash
set -euo pipefail

repo=$(cd "$(dirname "$0")/.." && pwd -P)
desired_cwd=$repo
credential_key=DEVSPACE_OAUTH_OWNER_TOKEN
cd "$repo"
unset "$credential_key"

pid=$(pm2 pid devspace 2>/dev/null | tail -1 | tr -d '[:space:]')
current_cwd=
credential_env_present=false
if [[ -n "$pid" && "$pid" != "0" ]] && command -v lsof >/dev/null 2>&1; then
  current_cwd=$(lsof -a -p "$pid" -d cwd -Fn 2>/dev/null | sed -n 's/^n//p' | head -1)
fi
if [[ -n "$pid" && "$pid" != "0" ]] \
  && ps eww -p "$pid" -o command= 2>/dev/null \
    | grep -q "${credential_key}="; then
  credential_env_present=true
fi

if [[ -n "$pid" && "$pid" != "0" ]] \
  && [[ "$current_cwd" != "$desired_cwd" || "$credential_env_present" == true ]]; then
  reasons=()
  [[ "$current_cwd" != "$desired_cwd" ]] && reasons+=("cwd drift")
  [[ "$credential_env_present" == true ]] && reasons+=("credential environment residue")
  printf 'DevSpace PM2 %s detected; recreating only the devspace process.\n' "$(IFS=', '; echo "${reasons[*]}")"
  pm2 delete devspace
  pm2 start ecosystem.config.cjs --only devspace
else
  pm2 startOrReload ecosystem.config.cjs --only devspace
fi

pm2 save
