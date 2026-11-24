#!/usr/bin/env bash
# ==============================================================================
# Integrator Persistent Code-Signing Helper (`sign-app.sh`)
# ==============================================================================
#
# 1. MODULE PURPOSE & ARCHITECTURAL SCOPE
#    Re-signs a built `Integrator.app` (or other macOS bundle) using the local
#    persistent `"Integrator Development Code Signing"` certificate stored in
#    `~/.integrator_codesign/integrator.keychain-db`. Keeping the certificate
#    constant preserves macOS TCC Designated Requirements across rebuilds.
#
# 2. ARCHITECTURAL LINKAGES & DEPENDENCIES
#    - Upstream Callers: Manual signing / post-build tooling after `cargo build`
#      or bundle modifications; pairs with `macos/build-universal-app.sh`.
#    - Downstream Callees: `/usr/bin/security`, `/usr/bin/codesign`.
#
# 3. EXECUTION MODEL
#    Single-threaded sequential script (`set -euo pipefail`).
#
# 4. SECURITY & SAFETY INVARIANTS
#    - Verifies both the persistent keychain database and target `.app` bundle
#      exist before unlocking or invoking `codesign`.
#    - Runs `codesign --verify --deep --strict` after signing to confirm seal integrity.
#
# Usage:
#   ./macos/sign-app.sh [path/to/Integrator.app]
#
# Configurable environment variables:
#   INTEGRATOR_KEYCHAIN_PASS  Keychain unlock password (default: integrator)
# ==============================================================================

set -euo pipefail

TARGET="${1:-/Applications/Integrator.app}"
KEYCHAIN_PATH="$HOME/.integrator_codesign/integrator.keychain-db"
SIGNING_PASS="${INTEGRATOR_KEYCHAIN_PASS:-integrator}"

if [ ! -e "$TARGET" ]; then
    echo "❌ Target bundle not found: $TARGET" >&2
    exit 1
fi

if [ ! -f "$KEYCHAIN_PATH" ]; then
    echo "❌ Integrator developer keychain not found at $KEYCHAIN_PATH (run ./macos/build-universal-app.sh first)" >&2
    exit 1
fi

# Unlock the dedicated signing keychain in case the login session locked it.
security unlock-keychain -p "$SIGNING_PASS" "$KEYCHAIN_PATH" 2>/dev/null || true
echo "Signing $TARGET with persistent Integrator Development Code Signing identity..."
codesign --force --deep --keychain "$KEYCHAIN_PATH" --sign "Integrator Development Code Signing" "$TARGET"
codesign --verify --deep --strict "$TARGET"
echo "✅ Signed successfully! Designated Requirement:"
codesign -d -r- "$TARGET"
