#!/bin/bash
export PATH="/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin"

if [ -n "$1" ]; then
    PC_IP="$1"
else
    IFS="|" read -r CONN_MODE PC_IP MAC_IP <<< "$(/usr/local/bin/detect-pc-link.sh)"
fi

if [ -n "$2" ]; then
    PORT="$2"
else
    if nc -z -G 1 "$PC_IP" 48989 >/dev/null 2>&1; then
        PORT=48989
    else
        PORT=47989
    fi
fi

if [ "$PORT" = "48989" ]; then
    HOST_NAME="HP-Omen-Mac2"
else
    HOST_NAME="HP-Omen"
fi

# Stop any prior Moonlight instance cleanly
killall Moonlight 2>/dev/null || true
for i in {1..15}; do
    pgrep -x Moonlight >/dev/null || break
    sleep 0.2
done

# Update both paired host entries (HP-Omen :47989 and HP-Omen-Mac2 :48989) with current PC_IP
# Disable V-Sync in Moonlight on macOS to prevent VTMetalRenderer's m_PendingPresentationCount
# leak when CAMetalLayer drops a drawable without firing addPresentedHandler: (which otherwise
# causes a permanent 100ms SDL_CondWaitTimeout stall per frame / ~10 FPS cap after a few hours).
for idx in 1 2; do
    huuid=$(defaults read com.moonlight-stream.Moonlight "hosts.${idx}.uuid" 2>/dev/null || true)
    defaults write com.moonlight-stream.Moonlight "hosts.${idx}.localaddress" -string "$PC_IP"
    defaults write com.moonlight-stream.Moonlight "hosts.${idx}.manualaddress" -string "$PC_IP"
    if [ "$huuid" = "07AF9583-7646-D429-688D-CA33E7DD6A2C" ]; then
        defaults write com.moonlight-stream.Moonlight "hosts.${idx}.localport" -int 48989
        defaults write com.moonlight-stream.Moonlight "hosts.${idx}.manualport" -int 48989
    elif [ "$huuid" = "07AF9583-7646-D429-688D-CA33E7DD6A1B" ]; then
        defaults write com.moonlight-stream.Moonlight "hosts.${idx}.localport" -int 47989
        defaults write com.moonlight-stream.Moonlight "hosts.${idx}.manualport" -int 47989
    fi
done

defaults write com.moonlight-stream.Moonlight width -int 2560
defaults write com.moonlight-stream.Moonlight height -int 1600
defaults write com.moonlight-stream.Moonlight fps -int 60
defaults write com.moonlight-stream.Moonlight enableVsync -bool false
defaults write com.moonlight-stream.Moonlight framePacing -bool false

nohup bash -c '
    for i in {1..70}; do
        if nc -z -G 1 "'"$PC_IP"'" "'"$PORT"'" >/dev/null 2>&1; then
            break
        fi
        sleep 0.4
    done
    exec /Applications/Moonlight.app/Contents/MacOS/Moonlight stream "'"$HOST_NAME"'" Desktop --no-vsync --no-frame-pacing --quit-after
' >/dev/null 2>&1 </dev/null &
disown
