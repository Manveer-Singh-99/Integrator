#!/usr/bin/env bash
# Builds a Universal (arm64 Apple Silicon + x86_64 Intel, macOS 12.0+) Integrator.app bundle.
# Default output: app/target/bundle/Integrator.app (pass --install to also install into INSTALL_DIR).
#
# Configurable environment variables:
#   MACOSX_DEPLOYMENT_TARGET  Minimum supported macOS version        (default: 12.0)
#   INSTALL_DIR               Destination directory for --install    (default: /Applications)
#   APP_BUNDLE_ID             CFBundleIdentifier written to plist    (default: com.manveersingh.integrator)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
APP_DIR="$REPO_ROOT/app"
DEPLOY_TARGET="${MACOSX_DEPLOYMENT_TARGET:-12.0}"
INSTALL_DIR="${INSTALL_DIR:-/Applications}"
APP_BUNDLE_ID="${APP_BUNDLE_ID:-com.manveersingh.integrator}"
OUT_BUNDLE="$APP_DIR/target/bundle/Integrator.app"
INSTALL_TO_APPS=0

if [ "${1:-}" = "--install" ]; then
    INSTALL_TO_APPS=1
fi

for target in aarch64-apple-darwin x86_64-apple-darwin; do
    if ! rustup target list --installed | grep -qx "$target"; then
        echo "Installing Rust target $target..."
        rustup target add "$target"
    fi
done

echo "Building arm64 release (MACOSX_DEPLOYMENT_TARGET=$DEPLOY_TARGET)..."
MACOSX_DEPLOYMENT_TARGET="$DEPLOY_TARGET" cargo build \
    --manifest-path "$APP_DIR/Cargo.toml" \
    --release \
    --target aarch64-apple-darwin

echo "Building x86_64 release (MACOSX_DEPLOYMENT_TARGET=$DEPLOY_TARGET)..."
MACOSX_DEPLOYMENT_TARGET="$DEPLOY_TARGET" cargo build \
    --manifest-path "$APP_DIR/Cargo.toml" \
    --release \
    --target x86_64-apple-darwin

ARM_BIN="$APP_DIR/target/aarch64-apple-darwin/release/integrator"
INTEL_BIN="$APP_DIR/target/x86_64-apple-darwin/release/integrator"
ARM_CLIP="$APP_DIR/target/aarch64-apple-darwin/release/macos_clip_files"
INTEL_CLIP="$APP_DIR/target/x86_64-apple-darwin/release/macos_clip_files"

rm -rf "$OUT_BUNDLE"
mkdir -p "$OUT_BUNDLE/Contents/MacOS" "$OUT_BUNDLE/Contents/Resources"

lipo -create "$ARM_BIN" "$INTEL_BIN" -output "$OUT_BUNDLE/Contents/MacOS/integrator"
chmod 755 "$OUT_BUNDLE/Contents/MacOS/integrator"

if [ -f "$ARM_CLIP" ] && [ -f "$INTEL_CLIP" ]; then
    lipo -create "$ARM_CLIP" "$INTEL_CLIP" -output "$OUT_BUNDLE/Contents/MacOS/macos_clip_files"
    chmod 755 "$OUT_BUNDLE/Contents/MacOS/macos_clip_files"
fi

if [ -f "$APP_DIR/icons/icon.icns" ]; then
    cp "$APP_DIR/icons/icon.icns" "$OUT_BUNDLE/Contents/Resources/icon.icns"
fi

cat << EOF > "$OUT_BUNDLE/Contents/Info.plist"
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>CFBundleDevelopmentRegion</key>
	<string>English</string>
	<key>CFBundleDisplayName</key>
	<string>Integrator</string>
	<key>CFBundleExecutable</key>
	<string>integrator</string>
	<key>CFBundleIdentifier</key>
	<string>${APP_BUNDLE_ID}</string>
	<key>CFBundleInfoDictionaryVersion</key>
	<string>6.0</string>
	<key>CFBundleName</key>
	<string>Integrator</string>
	<key>CFBundlePackageType</key>
	<string>APPL</string>
	<key>CFBundleShortVersionString</key>
	<string>1.0.0</string>
	<key>CFBundleVersion</key>
	<string>1.0.0</string>
	<key>CSResourcesFileMapped</key>
	<true/>
	<key>LSMinimumSystemVersion</key>
	<string>${DEPLOY_TARGET}</string>
	<key>CFBundleIconFile</key>
	<string>icon.icns</string>
	<key>NSCameraUsageDescription</key>
	<string>Integrator captures your Mac camera when Shared Camera (Mac to Windows 11) is turned on.</string>
	<key>NSLocalNetworkUsageDescription</key>
	<string>Integrator uses your local and USB-C network to discover and connect securely with your paired Windows workstation.</string>
	<key>NSHighResolutionCapable</key>
	<true/>
</dict>
</plist>
EOF

codesign --force --deep --sign - "$OUT_BUNDLE"
echo "Built Universal app bundle: $OUT_BUNDLE"
file "$OUT_BUNDLE/Contents/MacOS/integrator"

mkdir -p "$SCRIPT_DIR/build"
rm -rf "$SCRIPT_DIR/build/Integrator.app"
ditto "$OUT_BUNDLE" "$SCRIPT_DIR/build/Integrator.app"
echo "Mirrored to: $SCRIPT_DIR/build/Integrator.app"

if [ "$INSTALL_TO_APPS" -eq 1 ]; then
    echo "Installing to ${INSTALL_DIR}/Integrator.app (note: ad-hoc re-sign may require re-enabling Accessibility permission)..."
    mkdir -p "$INSTALL_DIR"
    rm -rf "${INSTALL_DIR}/Integrator.app"
    ditto "$OUT_BUNDLE" "${INSTALL_DIR}/Integrator.app"
fi
