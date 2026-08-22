#!/bin/zsh
set -euo pipefail
ROOT=${0:A:h}
OUT=${1:-$ROOT/build}
SIGNING_IDENTITY=${DEVSPACE_MACOS_CODESIGN_IDENTITY:--}
BUNDLE_IDENTIFIER=${DEVSPACE_GUI_FIXTURE_BUNDLE_ID:-com.devspace.gui-fixture.actual20260822}
APP="$OUT/DevSpace GUI Fixture.app"
CONTENTS="$APP/Contents"
MACOS="$CONTENTS/MacOS"
/bin/rm -rf "$APP"
/bin/mkdir -p "$MACOS" "$CONTENTS/Resources"
/bin/chmod 700 "$OUT" "$APP" "$CONTENTS" "$MACOS" "$CONTENTS/Resources"
cat > "$CONTENTS/Info.plist" <<'PLIST'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>CFBundleExecutable</key><string>devspace-gui-fixture</string>
  <key>CFBundleIdentifier</key><string>__DEVSPACE_GUI_FIXTURE_BUNDLE_ID__</string>
  <key>CFBundleName</key><string>DevSpace GUI Fixture</string>
  <key>CFBundlePackageType</key><string>APPL</string>
  <key>CFBundleShortVersionString</key><string>1.0</string>
  <key>CFBundleVersion</key><string>1</string>
  <key>NSHighResolutionCapable</key><true/>
</dict></plist>
PLIST
/usr/bin/sed -i "" "s/__DEVSPACE_GUI_FIXTURE_BUNDLE_ID__/$BUNDLE_IDENTIFIER/g" "$CONTENTS/Info.plist"
/usr/bin/clang -fobjc-arc -fmodules -O2 -Wall -Wextra -Werror \
  -mmacosx-version-min=12.0 -framework Foundation -framework AppKit \
  "$ROOT/devspace-gui-fixture.m" -o "$MACOS/devspace-gui-fixture"
/bin/chmod 700 "$MACOS/devspace-gui-fixture"
/bin/chmod 600 "$CONTENTS/Info.plist"
/usr/bin/codesign --force --deep --sign "$SIGNING_IDENTITY" --identifier "$BUNDLE_IDENTIFIER" "$APP"
/usr/bin/codesign --verify --deep --strict "$APP"
