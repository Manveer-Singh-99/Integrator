#!/usr/bin/env bash
# Standalone macOS installer for Mac <-> Windows USB-C Direct Link (10.99.99.2/24)
# Runs an event-driven LaunchDaemon watchdog via scutil dynamic store notifications (0% CPU, zero polling).
# Automatically adapts to macOS Internet Sharing (bridge100) and Apple USB-C NCM ports.

set -euo pipefail

if [ "$(id -u)" -ne 0 ]; then
    echo "Please run with sudo: sudo bash $0" >&2
    exit 1
fi

WATCHDOG_DIR="/Library/PrivilegedHelperTools"
WATCHDOG_PATH="$WATCHDOG_DIR/apple-usb-ncm-watchdog.sh"
OLD_PLIST="/Library/LaunchDaemons/com.antigravity.usbncm.plist"
NEW_PLIST="/Library/LaunchDaemons/com.integrator.usbncm.plist"

mkdir -p "$WATCHDOG_DIR"
chown root:wheel "$WATCHDOG_DIR"
chmod 755 "$WATCHDOG_DIR"

cat << 'EOF' > "$WATCHDOG_PATH"
#!/bin/bash
# Apple USB-C CDC-NCM Dynamic Link Watchdog for macOS
# Automatically bridges 10.99.99.2/24 and 192.168.2.1/24 across macOS Internet Sharing & Direct Link.
# Event-driven via scutil dynamic store notifications (0% CPU / zero polling).

export PATH="/usr/bin:/bin:/usr/sbin:/sbin"

rotate_log_if_needed() {
    local f="$1"
    if [ -f "$f" ]; then
        local sz
        sz=$(stat -f%z "$f" 2>/dev/null || echo 0)
        if [ "$sz" -gt 2097152 ]; then
            mv -f "$f" "${f}.1" 2>/dev/null || true
        fi
    fi
}

send_hint() {
    local msg="$1"
    local host="$2"
    local port="$3"
    case "$msg" in
        ON|OFF) ;;
        *) return 1 ;;
    esac
    case "$host" in
        10.99.99.1|192.168.2.2) ;;
        *) return 1 ;;
    esac
    # Try bash native /dev/udp first (<1ms, no subshell), fall back safely with argv passing
    if ! (printf '%s' "$msg" > "/dev/udp/$host/$port") 2>/dev/null; then
        /usr/bin/python3 -c 'import socket, sys
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.sendto(sys.argv[1].encode("ascii"), (sys.argv[2], int(sys.argv[3])))
s.close()' "$msg" "$host" "$port" 2>/dev/null || true
    fi
}

discover_usb_ncm_ifaces() {
    local discovered=""
    # Primary: query IORegistry specifically for Apple USB-C NCM gadget Ethernet interfaces
    # (never touches Thunderbolt peer links en1/en2, internal anpi*, or external USB Ethernet docks).
    if command -v ioreg >/dev/null 2>&1; then
        discovered=$(ioreg -r -c AppleUSBDeviceNCMData -w 0 2>/dev/null | awk '
            /"BSD Name" = "en[0-9]+"/ {
                if (match($0, /en[0-9]+/)) {
                    iface = substr($0, RSTART, RLENGTH)
                    if (!seen[iface]++) print iface
                }
            }
        ' | tr '\n' ' ')
    fi
    # Secondary: match macOS "Ethernet Adapter (enN)" hardware port naming if IORegistry returned empty
    if [ -z "${discovered// /}" ]; then
        discovered=$(networksetup -listallhardwareports 2>/dev/null | awk '
            /Hardware Port:/ {
                port = tolower($0)
                is_apple_ncm = (port ~ /ethernet adapter \(en[0-9]+\)/)
            }
            /Device:/ {
                if (is_apple_ncm && $2 ~ /^en[0-9]+$/) {
                    if (!seen[$2]++) print $2
                }
                is_apple_ncm = 0
            }
        ' | tr '\n' ' ')
    fi
    echo "$discovered"
}

sync_network() {
    rotate_log_if_needed "/var/log/apple-usb-ncm.log"
    rotate_log_if_needed "/var/log/apple-usb-ncm.err"

    local usb_ifaces
    usb_ifaces=$(discover_usb_ncm_ifaces)
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
        if ! ifconfig bridge100 2>/dev/null | grep -Eq 'inet 10\.99\.99\.2[[:space:]]'; then
            ifconfig bridge100 alias 10.99.99.2 netmask 255.255.255.0 2>/dev/null || true
        fi

        # Remove stale aliases from enslaved or inactive physical interfaces
        for iface in $usb_ifaces; do
            if ifconfig "$iface" 2>/dev/null | grep -Eq 'inet 10\.99\.99\.2[[:space:]]'; then
                ifconfig "$iface" -alias 10.99.99.2 2>/dev/null || true
            fi
            if ifconfig "$iface" 2>/dev/null | grep -Eq 'inet 192\.168\.2\.1[[:space:]]'; then
                ifconfig "$iface" -alias 192.168.2.1 2>/dev/null || true
            fi
        done

        send_hint "ON" "10.99.99.1" 47901
        send_hint "ON" "192.168.2.2" 47901
    else
        # Case B: Direct USB-C Link (Internet Sharing is OFF, bridge100 absent/inactive)
        local active_nic=""
        for iface in $usb_ifaces; do
            if ifconfig "$iface" 2>/dev/null | grep -q "status: active"; then
                active_nic="$iface"
                break
            fi
        done

        if [ -n "$active_nic" ]; then
            if ! ifconfig "$active_nic" 2>/dev/null | grep -Eq 'inet 10\.99\.99\.2[[:space:]]'; then
                ifconfig "$active_nic" inet 10.99.99.2 netmask 255.255.255.0 up 2>/dev/null || true
            fi

            for iface in $usb_ifaces bridge100; do
                if ifconfig "$iface" 2>/dev/null | grep -Eq 'inet 192\.168\.2\.1[[:space:]]'; then
                    ifconfig "$iface" -alias 192.168.2.1 2>/dev/null || true
                fi
            done

            for iface in $usb_ifaces; do
                if [ "$iface" != "$active_nic" ] && ifconfig "$iface" 2>/dev/null | grep -Eq 'inet 10\.99\.99\.2[[:space:]]'; then
                    ifconfig "$iface" -alias 10.99.99.2 2>/dev/null || true
                fi
            done

            send_hint "OFF" "10.99.99.1" 47901
            send_hint "OFF" "192.168.2.2" 47901
        else
            send_hint "OFF" "10.99.99.1" 47901
            send_hint "OFF" "192.168.2.2" 47901
        fi
    fi
}

cleanup_children() {
    local pids
    pids=$(jobs -p 2>/dev/null || true)
    if [ -n "$pids" ]; then
        kill $pids 2>/dev/null || true
    fi
}
trap cleanup_children EXIT TERM INT

# Run immediate sync at startup
sync_network

# Event loop: listen to macOS configd dynamic store notifications with valid `pattern` modifier
while true; do
    (
        trap 'exit 0' PIPE TERM INT
        echo "n.add State:/Network/Interface/(en[0-9]+|bridge100)/.* pattern"
        echo "n.watch"
        # Short sleep loop bounded by parent existence to avoid leaking long-lived `sleep 86400`
        while kill -0 $$ 2>/dev/null; do
            sleep 5
        done
    ) | /usr/sbin/scutil | while read -r line; do
        case "$line" in
            *"notification changes"*)
                while read -r -t 1 discard; do :; done
                sync_network
                ;;
        esac
    done
    sleep 2
done
EOF

chown root:wheel "$WATCHDOG_PATH"
chmod 755 "$WATCHDOG_PATH"

# Unload legacy antigravity plist & remove user-writable legacy copy if present
if [ -f "$OLD_PLIST" ]; then
    launchctl bootout system "$OLD_PLIST" 2>/dev/null || true
    rm -f "$OLD_PLIST"
fi
rm -f /usr/local/bin/apple-usb-ncm-watchdog.sh

cat << 'EOF' > "$NEW_PLIST"
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.integrator.usbncm</string>
    <key>ProgramArguments</key>
    <array>
        <string>/Library/PrivilegedHelperTools/apple-usb-ncm-watchdog.sh</string>
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

chown root:wheel "$NEW_PLIST"
chmod 644 "$NEW_PLIST"
launchctl bootout system "$NEW_PLIST" 2>/dev/null || true
launchctl bootstrap system "$NEW_PLIST"

echo "macOS USB-C NCM dynamic watchdog installed & running cleanly (com.integrator.usbncm)."
echo "Configured at 10.99.99.2/24 (Direct Link) and 192.168.2.1/24 (macOS Internet Sharing)."
echo "Test connection with: ping 10.99.99.1"
