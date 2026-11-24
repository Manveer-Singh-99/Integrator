#!/bin/bash
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DRIVER_SRC="$SCRIPT_DIR/build/IntegratorAudioDriver.driver"
TARGET_DIR="/Library/Audio/Plug-Ins/HAL"

if [ ! -d "$DRIVER_SRC" ]; then
    echo "⚠️ Driver not built yet. Running build-audio-driver.sh..."
    bash "$SCRIPT_DIR/build-audio-driver.sh"
fi

echo "📦 Installing IntegratorAudioDriver.driver to $TARGET_DIR..."

if [ "$EUID" -ne 0 ]; then
    sudo rm -rf "$TARGET_DIR/IntegratorAudioDriver.driver"
    sudo cp -R "$DRIVER_SRC" "$TARGET_DIR/"
    sudo chown -R root:wheel "$TARGET_DIR/IntegratorAudioDriver.driver"
    sudo chmod -R 755 "$TARGET_DIR/IntegratorAudioDriver.driver"
    echo "🔄 Restarting coreaudiod to register the new HAL device..."
    sudo launchctl kickstart -kp system/com.apple.audio.coreaudiod
else
    rm -rf "$TARGET_DIR/IntegratorAudioDriver.driver"
    cp -R "$DRIVER_SRC" "$TARGET_DIR/"
    chown -R root:wheel "$TARGET_DIR/IntegratorAudioDriver.driver"
    chmod -R 755 "$TARGET_DIR/IntegratorAudioDriver.driver"
    echo "🔄 Restarting coreaudiod to register the new HAL device..."
    launchctl kickstart -kp system/com.apple.audio.coreaudiod
fi

echo "✅ Integrator Audio Driver installed successfully!"
echo "🔊 'Windows PC (Integrator)' will now appear in System Settings > Sound and Control Center."
