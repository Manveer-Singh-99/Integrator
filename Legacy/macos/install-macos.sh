#!/bin/bash
# One-command macOS installer for Mac <-> Windows USB-C Direct Link (10.99.99.2/24)
# Runs an event-driven watchdog daemon via scutil dynamic store notifications (0% CPU, zero polling).
# Automatically adapts to macOS Internet Sharing (bridge100) and port changes (en3/en5).

set -e
if [ "$(id -u)" -ne 0 ]; then
    echo "Please run with sudo: sudo bash $0"
    exit 1
fi

mkdir -p /usr/local/bin

cat << 'EOF' > /usr/local/bin/apple-usb-ncm-watchdog.sh
#!/bin/bash
# Apple USB-C CDC-NCM Dynamic Link Watchdog for macOS
# Automatically bridges 10.99.99.2/24 and 192.168.2.1/24 across macOS Internet Sharing & Direct Link.
# Event-driven via scutil dynamic store notifications (0% CPU / zero polling).

export PATH="/usr/bin:/bin:/usr/sbin:/sbin:/usr/local/bin"

send_hint() {
    local msg="$1"
    local host="$2"
    local port="$3"
    # Try bash native /dev/udp first (<1ms, no subshell)
    if ! (echo -n "$msg" > "/dev/udp/$host/$port") 2>/dev/null; then
        /usr/bin/python3 -c "import socket; s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.sendto(b'$msg', ('$host', $port))" 2>/dev/null || true
    fi
}

sync_network() {
    local bridge_up=0
    if ifconfig bridge100 >/dev/null 2>&1; then
        local st
        st=$(ifconfig bridge100 2>/dev/null | awk '/status:/ {print $2}')
        if [ "$st" = "active" ]; then
            bridge_up=1
        fi
    fi

    if [ "$bridge_up" -eq 1 ]; then
        # Case A: macOS Internet Sharing is ACTIVE (bridge100 exists and is active)
        # Ensure 10.99.99.2 is aliased onto bridge100 alongside 192.168.2.1
        if ! ifconfig bridge100 2>/dev/null | grep -q "10.99.99.2"; then
            ifconfig bridge100 alias 10.99.99.2 netmask 255.255.255.0 2>/dev/null || true
        fi

        # Remove stale aliases from enslaved or inactive physical interfaces
        for iface in en3 en5; do
            if ifconfig "$iface" 2>/dev/null | grep -q "10.99.99.2"; then
                ifconfig "$iface" -alias 10.99.99.2 2>/dev/null || true
            fi
            if ifconfig "$iface" 2>/dev/null | grep -q "192.168.2.1"; then
                ifconfig "$iface" -alias 192.168.2.1 2>/dev/null || true
            fi
        done

        # Notify Windows bridge that Internet Sharing is ON (enables default route + DNS)
        send_hint "ON" "10.99.99.1" 47901
        send_hint "ON" "192.168.2.2" 47901
    else
        # Case B: Direct USB-C Link (Internet Sharing is OFF, bridge100 absent/inactive)
        local active_nic=""
        for iface in en3 en5; do
            if ifconfig "$iface" 2>/dev/null | grep -q "status: active"; then
                active_nic="$iface"
                break
            fi
        done

        if [ -n "$active_nic" ]; then
            # Physical cable is connected to active_nic
            if ! ifconfig "$active_nic" 2>/dev/null | grep -q "10.99.99.2"; then
                ifconfig "$active_nic" inet 10.99.99.2 netmask 255.255.255.0 up 2>/dev/null || true
            fi

            # Internet sharing is off: ensure 192.168.2.1 is stripped
            for iface in en3 en5 bridge100; do
                if ifconfig "$iface" 2>/dev/null | grep -q "192.168.2.1"; then
                    ifconfig "$iface" -alias 192.168.2.1 2>/dev/null || true
                fi
            done

            # Strip 10.99.99.2 from any inactive physical port
            for iface in en3 en5; do
                if [ "$iface" != "$active_nic" ] && ifconfig "$iface" 2>/dev/null | grep -q "10.99.99.2"; then
                    ifconfig "$iface" -alias 10.99.99.2 2>/dev/null || true
                fi
            done

            # Notify Windows bridge that Internet Sharing is OFF (drops default route so PC uses Wi-Fi)
            send_hint "OFF" "10.99.99.1" 47901
        else
            # Cable unplugged
            send_hint "OFF" "10.99.99.1" 47901
        fi
    fi
}

# Run immediate sync at startup
sync_network

# Event loop: listen to macOS configd dynamic store notifications
while true; do
    (
        echo "n.add State:/Network/Interface/(en3|en5|bridge100)/.*"
        echo "n.watch"
        while true; do sleep 86400; done
    ) | scutil | while read -r line; do
        case "$line" in
            *"notification changes"*)
                # Coalesce burst notifications over 1 second
                while read -t 1 discard; do :; done
                sync_network
                ;;
        esac
    done
    sleep 2
done
EOF
chmod +x /usr/local/bin/apple-usb-ncm-watchdog.sh

cat << 'EOF' > /Library/LaunchDaemons/com.antigravity.usbncm.plist
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.antigravity.usbncm</string>
    <key>ProgramArguments</key>
    <array>
        <string>/usr/local/bin/apple-usb-ncm-watchdog.sh</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>StandardOutPath</key>
    <string>/var/log/apple-usb-ncm.log</string>
    <key>StandardErrorPath</key>
    <string>/var/log/apple-usb-ncm.err</string>
</dict>
</plist>
EOF

chown root:wheel /Library/LaunchDaemons/com.antigravity.usbncm.plist
chmod 644 /Library/LaunchDaemons/com.antigravity.usbncm.plist
launchctl bootout system /Library/LaunchDaemons/com.antigravity.usbncm.plist 2>/dev/null || true
launchctl bootstrap system /Library/LaunchDaemons/com.antigravity.usbncm.plist

# Install Moonlight helper scripts if present
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if [ -d "$SCRIPT_DIR/../moonlight-second-screen" ]; then
    EXTRAS_DIR="$SCRIPT_DIR/../moonlight-second-screen"
elif [ -d "$SCRIPT_DIR/../../Legacy/moonlight-second-screen" ]; then
    EXTRAS_DIR="$SCRIPT_DIR/../../Legacy/moonlight-second-screen"
elif [ -d "$SCRIPT_DIR/../extras/moonlight-second-screen" ]; then
    EXTRAS_DIR="$SCRIPT_DIR/../extras/moonlight-second-screen"
fi
if [ -f "$EXTRAS_DIR/detect-pc-link.sh" ]; then
    cp "$EXTRAS_DIR/detect-pc-link.sh" /usr/local/bin/detect-pc-link.sh
    chmod +x /usr/local/bin/detect-pc-link.sh
fi
if [ -f "$EXTRAS_DIR/stream-pc-screen.sh" ]; then
    cp "$EXTRAS_DIR/stream-pc-screen.sh" /usr/local/bin/stream-pc-screen.sh
    chmod +x /usr/local/bin/stream-pc-screen.sh
fi

echo "macOS USB-C NCM dynamic watchdog installed & running."
echo "Configured at 10.99.99.2/24 (Direct Link) and 192.168.2.1/24 (macOS Internet Sharing)."
echo "Test connection with: ping 10.99.99.1"
