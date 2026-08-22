#!/bin/zsh
set -euo pipefail
ROOT=${0:A:h}
OUT=${1:-$ROOT/build}
/bin/mkdir -p "$OUT"
/bin/chmod 700 "$OUT"
COMMON=(-std=c17 -O2 -Wall -Wextra -Werror -Wno-deprecated-declarations -I "$ROOT")
/usr/bin/clang $COMMON -framework Security -framework CoreFoundation \
  "$ROOT/devspace-approval-agent.c" -o "$OUT/devspace-approval-agent"
/usr/bin/clang $COMMON "$ROOT/devspace-privileged-helper.c" -o "$OUT/devspace-privileged-helper"
/bin/chmod 700 "$OUT/devspace-approval-agent" "$OUT/devspace-privileged-helper"
/usr/bin/codesign --force --sign - "$OUT/devspace-approval-agent"
/usr/bin/codesign --force --sign - "$OUT/devspace-privileged-helper"
/usr/bin/codesign --verify --strict "$OUT/devspace-approval-agent"
/usr/bin/codesign --verify --strict "$OUT/devspace-privileged-helper"
/usr/bin/shasum -a 256 "$OUT/devspace-approval-agent" "$OUT/devspace-privileged-helper"
