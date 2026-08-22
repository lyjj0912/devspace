#!/bin/zsh
set -euo pipefail
ROOT=${0:A:h}
OUT=${1:-$ROOT/build}
SIGNING_IDENTITY=${DEVSPACE_MACOS_CODESIGN_IDENTITY:--}
APP="$OUT/DevSpace Approval Agent.app"
CONTENTS="$APP/Contents"
MACOS="$CONTENTS/MacOS"
/bin/rm -rf "$OUT"
/bin/mkdir -p "$MACOS" "$CONTENTS/Resources"
/bin/chmod 700 "$OUT" "$APP" "$CONTENTS" "$MACOS" "$CONTENTS/Resources"
cat > "$CONTENTS/Info.plist" <<'PLIST'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>CFBundleExecutable</key><string>devspace-approval-agent</string>
<key>CFBundleIdentifier</key><string>com.devspace.approval-agent</string>
<key>CFBundleName</key><string>DevSpace Approval Agent</string>
<key>CFBundlePackageType</key><string>APPL</string>
<key>CFBundleVersion</key><string>1</string>
<key>LSUIElement</key><true/>
</dict></plist>
PLIST
COMMON=(-std=c17 -O2 -Wall -Wextra -Werror -Wno-deprecated-declarations -I "$ROOT")
/usr/bin/clang $COMMON -x objective-c -fobjc-arc -framework AppKit -framework Security -framework CoreFoundation   "$ROOT/devspace-approval-agent.c" -o "$MACOS/devspace-approval-agent"
/usr/bin/clang $COMMON "$ROOT/devspace-approval-relay.c" -o "$OUT/devspace-approval-relay"
/usr/bin/clang $COMMON "$ROOT/devspace-privileged-helper.c" -o "$OUT/devspace-privileged-helper"
/bin/chmod 700 "$MACOS/devspace-approval-agent" "$OUT/devspace-approval-relay" "$OUT/devspace-privileged-helper"
/bin/chmod 600 "$CONTENTS/Info.plist"
/usr/bin/codesign --force --deep --sign "$SIGNING_IDENTITY" --identifier com.devspace.approval-agent "$APP"
/usr/bin/codesign --force --sign "$SIGNING_IDENTITY" "$OUT/devspace-approval-relay"
/usr/bin/codesign --force --sign "$SIGNING_IDENTITY" "$OUT/devspace-privileged-helper"
/usr/bin/codesign --verify --deep --strict "$APP"
/usr/bin/codesign --verify --strict "$OUT/devspace-approval-relay"
/usr/bin/codesign --verify --strict "$OUT/devspace-privileged-helper"
/usr/bin/shasum -a 256 "$MACOS/devspace-approval-agent" "$OUT/devspace-approval-relay" "$OUT/devspace-privileged-helper"
