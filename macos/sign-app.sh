#!/usr/bin/env bash
set -euo pipefail

TARGET="${1:-/Applications/Integrator.app}"
KEYCHAIN_PATH="$HOME/.integrator_codesign/integrator.keychain-db"

if [ ! -f "$KEYCHAIN_PATH" ]; then
    echo "❌ Integrator developer keychain not found at $KEYCHAIN_PATH"
    exit 1
fi

security unlock-keychain -p "integrator" "$KEYCHAIN_PATH" 2>/dev/null || true
echo "Signing $TARGET with persistent Integrator Development Code Signing identity..."
codesign --force --deep --keychain "$KEYCHAIN_PATH" --sign "Integrator Development Code Signing" "$TARGET"
echo "✅ Signed successfully! Designated Requirement:"
codesign -d -r- "$TARGET"
