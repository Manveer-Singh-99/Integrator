#!/usr/bin/env bash
# ==============================================================================
# Integrator Universal macOS Application Bundle Builder (`build-universal-app.sh`)
# ==============================================================================
#
# 1. MODULE PURPOSE & ARCHITECTURAL SCOPE
#    Compiles Universal (`aarch64-apple-darwin` + `x86_64-apple-darwin`) or
#    single-architecture (`--native` / `--arm64` / `--x86_64`) macOS release
#    binaries for `integrator` and the fallback clipboard helper `macos_clip_files`,
#    bundles optional native resources (`IntegratorAudioDriver`, installer scripts,
#    application icon), generates `Info.plist` with all required macOS TCC usage
#    descriptions (Camera, Microphone, Bluetooth, Local Network), and code-signs
#    the bundle with Integrator's persistent development signing identity so
#    Accessibility / Input Monitoring TCC approvals persist across builds.
#
# 2. ARCHITECTURAL LINKAGES & DEPENDENCIES
#    - Upstream Callers: Release packaging / developer `--install` workflows.
#    - Downstream Callees: `cargo build`, `lipo`, `macos/audio-driver/build-audio-driver.sh`,
#      `openssl`, `security`, `codesign`, `ditto`.
#
# 3. THREADING & EXECUTION MODEL
#    Single-threaded sequential shell build pipeline (`set -euo pipefail`).
#
# 4. SECURITY & SAFETY INVARIANTS
#    - Validates bundle identifier, deployment target, and version strings before
#      interpolating into `Info.plist`.
#    - Declares explicit TCC usage descriptions (`NSCameraUsageDescription`,
#      `NSMicrophoneUsageDescription`, `NSBluetoothAlwaysUsageDescription`,
#      `NSLocalNetworkUsageDescription`) so macOS never aborts on TCC requests.
#    - Uses persistent certificate keychain (`~/.integrator_codesign`) rather than
#      ad-hoc signatures so TCC Designated Requirement remains stable across rebuilds.
#
# Configurable environment variables:
#   MACOSX_DEPLOYMENT_TARGET  Minimum supported macOS version        (default: 12.0)
#   INSTALL_DIR               Destination directory for --install    (default: /Applications)
#   APP_BUNDLE_ID             CFBundleIdentifier written to plist    (default: com.manveersingh.integrator)
# ==============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
APP_DIR="$REPO_ROOT/app"
DEPLOY_TARGET="${MACOSX_DEPLOYMENT_TARGET:-12.0}"
INSTALL_DIR="${INSTALL_DIR:-/Applications}"
APP_BUNDLE_ID="${APP_BUNDLE_ID:-com.manveersingh.integrator}"
APP_VERSION="$(sed -n 's/^version = "\(.*\)"/\1/p' "$APP_DIR/Cargo.toml" | head -n 1)"
APP_VERSION="${APP_VERSION:-1.0.0}"
OUT_BUNDLE="$APP_DIR/target/bundle/Integrator.app"
INSTALL_TO_APPS=0
ARCH_MODE="universal"

for arg in "$@"; do
    case "$arg" in
        --install)
            INSTALL_TO_APPS=1
            ;;
        --universal)
            ARCH_MODE="universal"
            ;;
        --native)
            HOST_ARCH="$(uname -m)"
            case "$HOST_ARCH" in
                arm64)  ARCH_MODE="arm64" ;;
                x86_64) ARCH_MODE="x86_64" ;;
                *)
                    echo "Unsupported host architecture for --native: '$HOST_ARCH'" >&2
                    exit 1
                    ;;
            esac
            ;;
        --arm64)
            ARCH_MODE="arm64"
            ;;
        --x86_64)
            ARCH_MODE="x86_64"
            ;;
        *)
            echo "Unknown option: $arg (expected: [--native|--arm64|--x86_64|--universal] [--install])" >&2
            exit 1
            ;;
    esac
done

case "$ARCH_MODE" in
    universal) TARGETS=("aarch64-apple-darwin" "x86_64-apple-darwin") ;;
    arm64)     TARGETS=("aarch64-apple-darwin") ;;
    x86_64)    TARGETS=("x86_64-apple-darwin") ;;
esac

# Reject characters that could corrupt XML Info.plist or shell templates.
for pair in "APP_BUNDLE_ID:$APP_BUNDLE_ID" "DEPLOY_TARGET:$DEPLOY_TARGET" "APP_VERSION:$APP_VERSION"; do
    key="${pair%%:*}"
    val="${pair#*:}"
    case "$val" in
        ''|*'<'*|*'>'*|*'&'*|*'"'*|*"'"*)
            echo "Invalid XML-unsafe value for ${key}: '${val}'" >&2
            exit 1
            ;;
    esac
done

for target in "${TARGETS[@]}"; do
    if ! rustup target list --installed | grep -qx "$target"; then
        echo "Installing Rust target $target..."
        rustup target add "$target"
    fi
done

# Ensure the universal CoreAudio HAL driver plugin is freshly compiled before bundling.
if [ -x "$REPO_ROOT/macos/audio-driver/build-audio-driver.sh" ]; then
    echo "Building universal CoreAudio HAL audio driver..."
    bash "$REPO_ROOT/macos/audio-driver/build-audio-driver.sh"
fi

for target in "${TARGETS[@]}"; do
    echo "Building $target release (MACOSX_DEPLOYMENT_TARGET=$DEPLOY_TARGET)..."
    MACOSX_DEPLOYMENT_TARGET="$DEPLOY_TARGET" cargo build \
        --manifest-path "$APP_DIR/Cargo.toml" \
        --release \
        --target "$target"
done

rm -rf "$OUT_BUNDLE"
mkdir -p "$OUT_BUNDLE/Contents/MacOS" "$OUT_BUNDLE/Contents/Resources"

if [ "$ARCH_MODE" = "universal" ]; then
    ARM_BIN="$APP_DIR/target/aarch64-apple-darwin/release/integrator"
    INTEL_BIN="$APP_DIR/target/x86_64-apple-darwin/release/integrator"
    ARM_CLIP="$APP_DIR/target/aarch64-apple-darwin/release/macos_clip_files"
    INTEL_CLIP="$APP_DIR/target/x86_64-apple-darwin/release/macos_clip_files"

    lipo -create "$ARM_BIN" "$INTEL_BIN" -output "$OUT_BUNDLE/Contents/MacOS/integrator"
    chmod 755 "$OUT_BUNDLE/Contents/MacOS/integrator"

    if [ -f "$ARM_CLIP" ] && [ -f "$INTEL_CLIP" ]; then
        lipo -create "$ARM_CLIP" "$INTEL_CLIP" -output "$OUT_BUNDLE/Contents/MacOS/macos_clip_files"
        chmod 755 "$OUT_BUNDLE/Contents/MacOS/macos_clip_files"
    fi
else
    SINGLE_TARGET="${TARGETS[0]}"
    SINGLE_BIN="$APP_DIR/target/${SINGLE_TARGET}/release/integrator"
    SINGLE_CLIP="$APP_DIR/target/${SINGLE_TARGET}/release/macos_clip_files"

    cp "$SINGLE_BIN" "$OUT_BUNDLE/Contents/MacOS/integrator"
    chmod 755 "$OUT_BUNDLE/Contents/MacOS/integrator"

    if [ -f "$SINGLE_CLIP" ]; then
        cp "$SINGLE_CLIP" "$OUT_BUNDLE/Contents/MacOS/macos_clip_files"
        chmod 755 "$OUT_BUNDLE/Contents/MacOS/macos_clip_files"
    fi
fi

if [ -f "$APP_DIR/icons/icon.icns" ]; then
    cp "$APP_DIR/icons/icon.icns" "$OUT_BUNDLE/Contents/Resources/icon.icns"
fi

if [ -d "$REPO_ROOT/macos/audio-driver/build/IntegratorAudioDriver.driver" ]; then
    cp -R "$REPO_ROOT/macos/audio-driver/build/IntegratorAudioDriver.driver" "$OUT_BUNDLE/Contents/Resources/"
fi

if [ -f "$REPO_ROOT/macos/audio-driver/install-audio-driver.sh" ]; then
    cp "$REPO_ROOT/macos/audio-driver/install-audio-driver.sh" "$OUT_BUNDLE/Contents/Resources/"
    chmod 755 "$OUT_BUNDLE/Contents/Resources/install-audio-driver.sh"
fi

if [ -f "$REPO_ROOT/macos/install-macos.sh" ]; then
    cp "$REPO_ROOT/macos/install-macos.sh" "$OUT_BUNDLE/Contents/Resources/"
    chmod 755 "$OUT_BUNDLE/Contents/Resources/install-macos.sh"
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
	<string>${APP_VERSION}</string>
	<key>CFBundleVersion</key>
	<string>${APP_VERSION}</string>
	<key>CSResourcesFileMapped</key>
	<true/>
	<key>LSMinimumSystemVersion</key>
	<string>${DEPLOY_TARGET}</string>
	<key>CFBundleIconFile</key>
	<string>icon.icns</string>
	<key>NSCameraUsageDescription</key>
	<string>Integrator captures your Mac camera when Shared Camera &amp; Mic (Mac to Windows 11) is turned on.</string>
	<key>NSMicrophoneUsageDescription</key>
	<string>Integrator captures your Mac microphone when Shared Camera &amp; Mic (Mac to Windows 11) is turned on.</string>
	<key>NSBluetoothAlwaysUsageDescription</key>
	<string>Integrator uses Bluetooth Low Energy (BLE) magic packets to discover nearby paired Mac and Windows workstations even when Wi-Fi broadcasts are restricted.</string>
	<key>NSLocalNetworkUsageDescription</key>
	<string>Integrator uses your local and USB-C network to discover and connect securely with your paired Windows workstation.</string>
	<key>NSHighResolutionCapable</key>
	<true/>
</dict>
</plist>
EOF

# Ensure persistent developer code signing identity exists so TCC permissions (Accessibility, Input Monitoring) NEVER reset across builds
KEYCHAIN_PATH="$HOME/.integrator_codesign/integrator.keychain-db"
CERT_PATH="$HOME/.integrator_codesign/cert.pem"
SIGNING_PASS="${INTEGRATOR_KEYCHAIN_PASS:-integrator}"

if [ ! -f "$KEYCHAIN_PATH" ] || [ ! -f "$CERT_PATH" ]; then
    echo "Creating persistent Integrator developer code-signing identity (so Accessibility permissions never reset)..."
    mkdir -p "$HOME/.integrator_codesign"
    chmod 700 "$HOME/.integrator_codesign"
    CNF_PATH="$HOME/.integrator_codesign/cert.cnf"
    KEY_PATH="$HOME/.integrator_codesign/key.pem"
    P12_PATH="$HOME/.integrator_codesign/cert.p12"
    cat << 'CNF_EOF' > "$CNF_PATH"
[ req ]
default_bits       = 2048
distinguished_name = req_dn
prompt             = no
[ req_dn ]
CN = Integrator Development Code Signing
[ v3_ca ]
basicConstraints = critical, CA:FALSE
keyUsage = digitalSignature
extendedKeyUsage = 1.3.6.1.5.5.7.3.3
CNF_EOF
    openssl req -x509 -new -nodes -keyout "$KEY_PATH" -out "$CERT_PATH" -days 3650 -config "$CNF_PATH" -extensions v3_ca
    chmod 600 "$KEY_PATH"
    openssl pkcs12 -export -out "$P12_PATH" -inkey "$KEY_PATH" -in "$CERT_PATH" -passout "pass:${SIGNING_PASS}" -certpbe PBE-SHA1-3DES -keypbe PBE-SHA1-3DES -macalg sha1
    chmod 600 "$P12_PATH"
    security delete-keychain "$KEYCHAIN_PATH" 2>/dev/null || true
    security create-keychain -p "$SIGNING_PASS" "$KEYCHAIN_PATH"
    security unlock-keychain -p "$SIGNING_PASS" "$KEYCHAIN_PATH"
    security set-keychain-settings "$KEYCHAIN_PATH"
    security import "$P12_PATH" -k "$KEYCHAIN_PATH" -P "$SIGNING_PASS" -T /usr/bin/codesign
    security set-key-partition-list -S apple-tool:,apple:,codesign: -s -k "$SIGNING_PASS" "$KEYCHAIN_PATH"
    security add-trusted-cert -d -r trustRoot -p codeSign "$CERT_PATH" 2>/dev/null || true
fi

security unlock-keychain -p "$SIGNING_PASS" "$KEYCHAIN_PATH" 2>/dev/null || true
echo "Signing bundle with persistent Integrator identity (prevents TCC permission resets)..."
codesign --force --deep --keychain "$KEYCHAIN_PATH" --sign "Integrator Development Code Signing" "$OUT_BUNDLE"
codesign --verify --deep --strict "$OUT_BUNDLE"
echo "Built ${ARCH_MODE} app bundle: $OUT_BUNDLE"
file "$OUT_BUNDLE/Contents/MacOS/integrator"

mkdir -p "$SCRIPT_DIR/build"
rm -rf "$SCRIPT_DIR/build/Integrator.app"
ditto "$OUT_BUNDLE" "$SCRIPT_DIR/build/Integrator.app"
echo "Mirrored to: $SCRIPT_DIR/build/Integrator.app"

if [ "$INSTALL_TO_APPS" -eq 1 ]; then
    echo "Installing to ${INSTALL_DIR}/Integrator.app (signed with persistent identity: Accessibility permissions will NOT reset)..."
    mkdir -p "$INSTALL_DIR"
    rm -rf "${INSTALL_DIR}/Integrator.app"
    ditto "$OUT_BUNDLE" "${INSTALL_DIR}/Integrator.app"
fi
