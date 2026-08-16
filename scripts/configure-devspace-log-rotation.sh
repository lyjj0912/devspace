#!/bin/bash
set -euo pipefail

PM2_BIN="${PM2_BIN:-$(command -v pm2 || true)}"
if [[ -z "$PM2_BIN" || ! -x "$PM2_BIN" ]]; then
  echo "PM2 is unavailable." >&2
  exit 1
fi

if ! "$PM2_BIN" describe pm2-logrotate >/dev/null 2>&1; then
  "$PM2_BIN" install pm2-logrotate >/dev/null
fi

"$PM2_BIN" set pm2-logrotate:max_size 10M >/dev/null
"$PM2_BIN" set pm2-logrotate:retain 5 >/dev/null
"$PM2_BIN" set pm2-logrotate:compress true >/dev/null
"$PM2_BIN" set pm2-logrotate:dateFormat 'YYYY-MM-DD_HH-mm-ss' >/dev/null
"$PM2_BIN" set pm2-logrotate:workerInterval 30 >/dev/null
"$PM2_BIN" set pm2-logrotate:rotateInterval '0 0 * * *' >/dev/null
"$PM2_BIN" save >/dev/null

echo "PM2 log rotation configured: max_size=10M retain=5 compress=true daily rotation."
