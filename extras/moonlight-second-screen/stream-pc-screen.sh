#!/bin/bash
export PATH="/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin"
if [ -n "$1" ]; then
    PC_IP="$1"
else
    IFS="|" read -r CONN_MODE PC_IP MAC_IP <<< "$(/usr/local/bin/detect-pc-link.sh)"
fi

killall Moonlight 2>/dev/null || true
for i in {1..15}; do
    pgrep -x Moonlight >/dev/null || break
    sleep 0.2
done

# Disable V-Sync in Moonlight on macOS to prevent VTMetalRenderer's m_PendingPresentationCount
# leak when CAMetalLayer drops a drawable without firing addPresentedHandler: (which otherwise
# causes a permanent 100ms SDL_CondWaitTimeout stall per frame / ~10 FPS cap after a few hours).
defaults write com.moonlight-stream.Moonlight "hosts.1.localaddress" -string "$PC_IP"
defaults write com.moonlight-stream.Moonlight "hosts.1.manualaddress" -string "192.168.137.1"
defaults write com.moonlight-stream.Moonlight enableVsync -bool false
defaults write com.moonlight-stream.Moonlight framePacing -bool false

for i in {1..30}; do
    if nc -z -G 1 "$PC_IP" 47989 >/dev/null 2>&1; then
        break
    fi
    sleep 0.3
done

nohup /Applications/Moonlight.app/Contents/MacOS/Moonlight stream "$PC_IP" Desktop --no-vsync --no-frame-pacing --quit-after >/dev/null 2>&1 </dev/null &
disown
