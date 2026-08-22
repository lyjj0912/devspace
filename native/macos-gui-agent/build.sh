#!/bin/zsh
set -euo pipefail
ROOT=${0:A:h}
OUT=${1:-$ROOT/build}
SIGNING_IDENTITY=${DEVSPACE_MACOS_CODESIGN_IDENTITY:--}
APP="$OUT/DevSpace GUI Agent.app"
CONTENTS="$APP/Contents"
MACOS="$CONTENTS/MacOS"
/bin/rm -rf "$APP"
/bin/mkdir -p "$MACOS" "$CONTENTS/Resources"
/bin/chmod 700 "$OUT" "$APP" "$CONTENTS" "$MACOS" "$CONTENTS/Resources"
cat > "$CONTENTS/Info.plist" <<'PLIST'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>CFBundleDevelopmentRegion</key><string>en</string>
  <key>CFBundleExecutable</key><string>devspace-gui-agent</string>
  <key>CFBundleIdentifier</key><string>com.devspace.gui-agent</string>
  <key>CFBundleInfoDictionaryVersion</key><string>6.0</string>
  <key>CFBundleName</key><string>DevSpace GUI Agent</string>
  <key>CFBundlePackageType</key><string>APPL</string>
  <key>CFBundleShortVersionString</key><string>1.0</string>
  <key>CFBundleVersion</key><string>1</string>
  <key>LSBackgroundOnly</key><true/>
  <key>LSUIElement</key><true/>
  <key>NSAccessibilityUsageDescription</key><string>DevSpace uses Accessibility only for user-requested GUI operations.</string>
  <key>NSScreenCaptureUsageDescription</key><string>DevSpace captures the screen only for user-requested GUI operations.</string>
</dict>
</plist>
PLIST
/usr/bin/clang \
  -fobjc-arc -fmodules -O2 -Wall -Wextra -Werror -Wno-deprecated-declarations \
  -mmacosx-version-min=12.0 \
  -framework Foundation -framework AppKit -framework ApplicationServices \
  -framework CoreGraphics -framework ImageIO -framework CoreServices \
  "$ROOT/devspace-gui-agent.m" \
  -o "$MACOS/devspace-gui-agent"
/bin/chmod 700 "$MACOS/devspace-gui-agent"
/bin/chmod 600 "$CONTENTS/Info.plist"
/usr/bin/codesign --force --deep --sign "$SIGNING_IDENTITY" --identifier com.devspace.gui-agent "$APP"
/usr/bin/codesign --verify --deep --strict "$APP"
