#!/usr/bin/env bash
# Backwards compatibility forwarding wrapper
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TARGET="$SCRIPT_DIR/../Legacy/macos/install-macos.sh"

if [ -f "$TARGET" ]; then
    exec bash "$TARGET" "$@"
else
    echo "Error: Legacy script not found at $TARGET" >&2
    exit 1
fi
