#!/bin/bash
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BUILD_DIR="$SCRIPT_DIR/build/IntegratorAudioDriver.driver"
CONTENTS_DIR="$BUILD_DIR/Contents"
MACOS_DIR="$CONTENTS_DIR/MacOS"

echo "🔨 Building IntegratorAudioDriver.driver (Universal arm64 + x86_64)..."

rm -rf "$SCRIPT_DIR/build"
mkdir -p "$MACOS_DIR"

clang -O3 -bundle \
    -arch arm64 -arch x86_64 \
    -isysroot "$(xcrun --show-sdk-path)" \
    -framework CoreAudio \
    -framework CoreFoundation \
    -Wall -Wextra -Wno-unused-parameter \
    -o "$MACOS_DIR/IntegratorAudioDriver" \
    "$SCRIPT_DIR/IntegratorAudioDriver.c"

cp "$SCRIPT_DIR/Info.plist" "$CONTENTS_DIR/Info.plist"

# Stable code sign (using persistent developer identity so TCC permissions never reset)
KEYCHAIN_PATH="$HOME/.integrator_codesign/integrator.keychain-db"
if [ -f "$KEYCHAIN_PATH" ]; then
    security unlock-keychain -p "integrator" "$KEYCHAIN_PATH" 2>/dev/null || true
    codesign --force --keychain "$KEYCHAIN_PATH" --sign "Integrator Development Code Signing" "$BUILD_DIR"
else
    codesign -s - --force "$BUILD_DIR"
fi

echo "✅ Successfully built: $BUILD_DIR"
file "$MACOS_DIR/IntegratorAudioDriver"
