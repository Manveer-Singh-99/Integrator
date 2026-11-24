#!/usr/bin/env bash
# ==============================================================================
# Integrator USB-C CDC-NCM Dynamic Link Installer (`install-macos.sh`)
# ==============================================================================
#
# 1. MODULE PURPOSE & ARCHITECTURAL SCOPE
#    Installs a root-owned macOS LaunchDaemon watchdog (`com.integrator.usbncm`)
#    driven by `scutil` dynamic store notifications (`0%` CPU, zero polling).
#    Automatically maintains the macOS USB-C CDC-NCM direct link IPv4 address
#    (`MAC_DIRECT_IP`, defaulting to `10.99.99.2/24`) whether macOS Internet
#    Sharing (`bridge100`) is active or idle, and transmits lightweight UDP sharing
#    hint packets (`ON` / `OFF`) to the paired Windows NCM bridge service.
#
# 2. ARCHITECTURAL LINKAGES & DEPENDENCIES
#    - Upstream Callers: Guided installer command shown in Integrator Setup
#      Assistant (`app/src/setup.rs`) or direct `sudo bash macos/install-macos.sh`.
#    - Downstream Callees: `/usr/sbin/scutil`, `ioreg` (`AppleUSBDeviceNCMData`),
#      `networksetup`, `ifconfig`, `/dev/udp` (with `/usr/bin/python3` fallback),
#      `launchctl bootstrap system`.
#    - Cross-Platform Flow: Coordinates interface aliases with Windows companion
#      bridge (`windows/AppleUsbNcmBridge.cs`) over UDP port `HINT_PORT` (`47901`).
#
# 3. EXECUTION & CONCURRENCY MODEL
#    Installer writes a root-owned standalone daemon script under
#    `/Library/PrivilegedHelperTools` and registers a persistent LaunchDaemon plist.
#    The watchdog daemon reacts purely to `State:/Network/Interface/.*` kernel events.
#
# 4. SECURITY & SAFETY INVARIANTS
#    - Strict Input Validation: All configurable IPs, ports, byte sizes, identifiers,
#      and paths are strictly validated before generating the privileged script or XML plist.
#    - Safe Least-Privilege Permissions: Root-owned (`root:wheel`, `0755` / `0644`),
#      upgrading/cleaning legacy writable scripts in `/usr/local/bin/` and old plists.
#    - Explicit `PATH`: Daemon pins `/usr/bin:/bin:/usr/sbin:/sbin` to prevent hijacking.
#
# Configurable environment variables (override before invoking `sudo -E` or inline):
#   MAC_DIRECT_IP        macOS Direct Link IPv4 address             (default: 10.99.99.2)
#   WIN_DIRECT_IP        Windows peer Direct Link IPv4 address      (default: 10.99.99.1)
#   DIRECT_NETMASK       IPv4 subnet mask for Direct Link           (default: 255.255.255.0)
#   SHARING_GW_IP        macOS Internet Sharing gateway IPv4        (default: 192.168.2.1)
#   WIN_SHARING_IP       Windows peer Internet Sharing IPv4         (default: 192.168.2.2)
#   BRIDGE_IFACE         macOS Internet Sharing bridge interface    (default: bridge100)
#   HINT_PORT            UDP port for ON/OFF sharing hint packets   (default: 47901)
#   MAX_LOG_BYTES        Log rotation threshold in bytes            (default: 2097152)
#   WATCHDOG_DIR         Directory where watchdog script is placed  (default: /Library/PrivilegedHelperTools)
#   LOG_DIR              Directory for watchdog stdout/stderr logs  (default: /var/log)
#   PLIST_LABEL          LaunchDaemon reverse-DNS label             (default: com.integrator.usbncm)
#   NEW_PLIST            LaunchDaemon plist destination path        (default: /Library/LaunchDaemons/${PLIST_LABEL}.plist)
#   OLD_PLIST            Legacy plist path to remove during upgrade (default: /Library/LaunchDaemons/com.antigravity.usbncm.plist)
#   LEGACY_WATCHDOG_PATH Legacy user-writable watchdog copy path    (default: /usr/local/bin/apple-usb-ncm-watchdog.sh)
# ==============================================================================

set -euo pipefail

if [ "$(id -u)" -ne 0 ]; then
    echo "Please run with sudo: sudo bash $0" >&2
    exit 1
fi

# Configurable network parameters with safe defaults matching Integrator USB-C bridge conventions.
MAC_DIRECT_IP="${MAC_DIRECT_IP:-10.99.99.2}"
WIN_DIRECT_IP="${WIN_DIRECT_IP:-10.99.99.1}"
DIRECT_NETMASK="${DIRECT_NETMASK:-255.255.255.0}"
SHARING_GW_IP="${SHARING_GW_IP:-192.168.2.1}"
WIN_SHARING_IP="${WIN_SHARING_IP:-192.168.2.2}"
BRIDGE_IFACE="${BRIDGE_IFACE:-bridge100}"
HINT_PORT="${HINT_PORT:-47901}"
MAX_LOG_BYTES="${MAX_LOG_BYTES:-2097152}"

# Configurable installation paths and LaunchDaemon metadata.
WATCHDOG_DIR="${WATCHDOG_DIR:-/Library/PrivilegedHelperTools}"
WATCHDOG_PATH="${WATCHDOG_DIR}/apple-usb-ncm-watchdog.sh"
LOG_DIR="${LOG_DIR:-/var/log}"
LOG_STDOUT="${LOG_DIR}/apple-usb-ncm.log"
LOG_STDERR="${LOG_DIR}/apple-usb-ncm.err"
PLIST_LABEL="${PLIST_LABEL:-com.integrator.usbncm}"
NEW_PLIST="${NEW_PLIST:-/Library/LaunchDaemons/${PLIST_LABEL}.plist}"
OLD_PLIST="${OLD_PLIST:-/Library/LaunchDaemons/com.antigravity.usbncm.plist}"
LEGACY_WATCHDOG_PATH="${LEGACY_WATCHDOG_PATH:-/usr/local/bin/apple-usb-ncm-watchdog.sh}"

# Validates that a given value is a strict dotted-quad IPv4 address (0-255 per octet).
validate_ipv4() {
    local var_name="$1"
    local ip="$2"
    case "$ip" in
        ''|.*|*.|*..*)
            echo "Invalid IPv4 address for ${var_name}: '${ip}'" >&2
            exit 1
            ;;
    esac
    local IFS='.'
    local -a octets
    read -r -a octets <<< "$ip"
    if [ "${#octets[@]}" -ne 4 ]; then
        echo "Invalid IPv4 address for ${var_name}: '${ip}'" >&2
        exit 1
    fi
    local o
    for o in "${octets[@]}"; do
        case "$o" in
            ''|*[!0-9]*)
                echo "Invalid IPv4 address for ${var_name}: '${ip}'" >&2
                exit 1
                ;;
        esac
        if [ "$((10#$o))" -lt 0 ] || [ "$((10#$o))" -gt 255 ]; then
            echo "Invalid IPv4 address for ${var_name}: '${ip}'" >&2
            exit 1
        fi
    done
}

# Validates that a given value is a decimal integer within [min, max].
validate_uint_range() {
    local var_name="$1"
    local val="$2"
    local min_val="$3"
    local max_val="$4"
    case "$val" in
        ''|*[!0-9]*)
            echo "Invalid integer for ${var_name}: '${val}'" >&2
            exit 1
            ;;
    esac
    local num=$((10#$val))
    if [ "$num" -lt "$min_val" ] || [ "$num" -gt "$max_val" ]; then
        echo "Out-of-range value for ${var_name}: '${val}' (expected ${min_val}..${max_val})" >&2
        exit 1
    fi
}

# Validates that identifiers injected into shell/plist templates contain only safe characters.
validate_identifier() {
    local var_name="$1"
    local val="$2"
    case "$val" in
        ''|*[!A-Za-z0-9._-]*)
            echo "Invalid identifier for ${var_name}: '${val}'" >&2
            exit 1
            ;;
    esac
}

# Validates that filesystem paths injected into XML plist templates contain no XML metacharacters.
validate_plist_path() {
    local var_name="$1"
    local val="$2"
    case "$val" in
        ''|*'<'*|*'>'*|*'&'*|*'"'*|*"'"*)
            echo "Invalid path for ${var_name}: '${val}'" >&2
            exit 1
            ;;
    esac
}

# Removes legacy antigravity LaunchDaemon and user-writable watchdog copies cleanly.
cleanup_legacy_install() {
    if [ -n "$OLD_PLIST" ] && [ "$OLD_PLIST" != "$NEW_PLIST" ] && [ -f "$OLD_PLIST" ]; then
        launchctl bootout system "$OLD_PLIST" 2>/dev/null || true
        rm -f "$OLD_PLIST"
    fi
    if [ -n "$LEGACY_WATCHDOG_PATH" ] && [ "$LEGACY_WATCHDOG_PATH" != "$WATCHDOG_PATH" ]; then
        rm -f "$LEGACY_WATCHDOG_PATH"
    fi
}

validate_ipv4 "MAC_DIRECT_IP" "$MAC_DIRECT_IP"
validate_ipv4 "WIN_DIRECT_IP" "$WIN_DIRECT_IP"
validate_ipv4 "DIRECT_NETMASK" "$DIRECT_NETMASK"
validate_ipv4 "SHARING_GW_IP" "$SHARING_GW_IP"
validate_ipv4 "WIN_SHARING_IP" "$WIN_SHARING_IP"
validate_uint_range "HINT_PORT" "$HINT_PORT" 1 65535
validate_uint_range "MAX_LOG_BYTES" "$MAX_LOG_BYTES" 1024 1073741824
validate_identifier "BRIDGE_IFACE" "$BRIDGE_IFACE"
validate_identifier "PLIST_LABEL" "$PLIST_LABEL"
validate_plist_path "WATCHDOG_PATH" "$WATCHDOG_PATH"
validate_plist_path "NEW_PLIST" "$NEW_PLIST"
validate_plist_path "LOG_STDOUT" "$LOG_STDOUT"
validate_plist_path "LOG_STDERR" "$LOG_STDERR"

mkdir -p "$WATCHDOG_DIR" "$LOG_DIR" "$(dirname "$NEW_PLIST")"
chown root:wheel "$WATCHDOG_DIR"
chmod 755 "$WATCHDOG_DIR"

# Write configured parameter header first (expanded), then append watchdog logic verbatim (quoted).
cat << EOF > "$WATCHDOG_PATH"
#!/bin/bash
# Apple USB-C CDC-NCM Dynamic Link Watchdog for macOS
# Automatically bridges ${MAC_DIRECT_IP} and ${SHARING_GW_IP} across macOS Internet Sharing & Direct Link.
# Event-driven via scutil dynamic store notifications (0% CPU / zero polling).

MAC_DIRECT_IP="${MAC_DIRECT_IP}"
WIN_DIRECT_IP="${WIN_DIRECT_IP}"
DIRECT_NETMASK="${DIRECT_NETMASK}"
SHARING_GW_IP="${SHARING_GW_IP}"
WIN_SHARING_IP="${WIN_SHARING_IP}"
BRIDGE_IFACE="${BRIDGE_IFACE}"
HINT_PORT="${HINT_PORT}"
LOG_STDOUT="${LOG_STDOUT}"
LOG_STDERR="${LOG_STDERR}"
MAX_LOG_BYTES="${MAX_LOG_BYTES}"
EOF

cat << 'EOF' >> "$WATCHDOG_PATH"

export PATH="/usr/bin:/bin:/usr/sbin:/sbin"

# Rotates daemon stdout/stderr logs once they exceed MAX_LOG_BYTES (keeps one .1 backup).
rotate_log_if_needed() {
    local f="$1"
    if [ -f "$f" ]; then
        local sz
        sz=$(stat -f%z "$f" 2>/dev/null || echo 0)
        if [ "$sz" -gt "$MAX_LOG_BYTES" ]; then
            mv -f "$f" "${f}.1" 2>/dev/null || true
        fi
    fi
}

# Returns 0 when interface $1 currently owns exact IPv4 address $2 (`inet <ip>`).
iface_has_ip() {
    local iface="$1"
    local target_ip="$2"
    ifconfig "$iface" 2>/dev/null | awk -v ip="$target_ip" '
        $1 == "inet" && $2 == ip { found = 1; exit }
        END { exit (found ? 0 : 1) }
    '
}

# Sends an authenticated-allowlist "ON"/"OFF" UDP sharing state hint to configured peer IP/port.
send_hint() {
    local msg="$1"
    local host="$2"
    local port="$3"
    case "$msg" in
        ON|OFF) ;;
        *) return 1 ;;
    esac
    case "$host" in
        "$WIN_DIRECT_IP"|"$WIN_SHARING_IP") ;;
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

# Discovers BSD interface names (enX) belonging strictly to Apple USB-C CDC-NCM gadget ports.
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

# Reconciles bridge100 vs direct USB-C NCM interface IPs and emits Windows sharing state hints.
sync_network() {
    rotate_log_if_needed "$LOG_STDOUT"
    rotate_log_if_needed "$LOG_STDERR"

    local usb_ifaces
    usb_ifaces=$(discover_usb_ncm_ifaces)
    local bridge_up=0
    if ifconfig "$BRIDGE_IFACE" >/dev/null 2>&1; then
        local st
        st=$(ifconfig "$BRIDGE_IFACE" 2>/dev/null | awk '/status:/ {print $2}')
        if [ "$st" = "active" ]; then
            bridge_up=1
        fi
    fi

    if [ "$bridge_up" -eq 1 ]; then
        # Case A: macOS Internet Sharing is ACTIVE (bridge interface exists and is active)
        if ! iface_has_ip "$BRIDGE_IFACE" "$MAC_DIRECT_IP"; then
            ifconfig "$BRIDGE_IFACE" alias "$MAC_DIRECT_IP" netmask "$DIRECT_NETMASK" 2>/dev/null || true
        fi

        # Remove stale aliases from enslaved or inactive physical interfaces
        for iface in $usb_ifaces; do
            if iface_has_ip "$iface" "$MAC_DIRECT_IP"; then
                ifconfig "$iface" -alias "$MAC_DIRECT_IP" 2>/dev/null || true
            fi
            if iface_has_ip "$iface" "$SHARING_GW_IP"; then
                ifconfig "$iface" -alias "$SHARING_GW_IP" 2>/dev/null || true
            fi
        done

        send_hint "ON" "$WIN_DIRECT_IP" "$HINT_PORT"
        send_hint "ON" "$WIN_SHARING_IP" "$HINT_PORT"
    else
        # Case B: Direct USB-C Link (Internet Sharing is OFF, bridge absent/inactive)
        local active_nic=""
        for iface in $usb_ifaces; do
            if ifconfig "$iface" 2>/dev/null | grep -q "status: active"; then
                active_nic="$iface"
                break
            fi
        done

        if [ -n "$active_nic" ]; then
            if ! iface_has_ip "$active_nic" "$MAC_DIRECT_IP"; then
                ifconfig "$active_nic" inet "$MAC_DIRECT_IP" netmask "$DIRECT_NETMASK" up 2>/dev/null || true
            fi

            for iface in $usb_ifaces "$BRIDGE_IFACE"; do
                if iface_has_ip "$iface" "$SHARING_GW_IP"; then
                    ifconfig "$iface" -alias "$SHARING_GW_IP" 2>/dev/null || true
                fi
            done

            for iface in $usb_ifaces; do
                if [ "$iface" != "$active_nic" ] && iface_has_ip "$iface" "$MAC_DIRECT_IP"; then
                    ifconfig "$iface" -alias "$MAC_DIRECT_IP" 2>/dev/null || true
                fi
            done

            send_hint "OFF" "$WIN_DIRECT_IP" "$HINT_PORT"
            send_hint "OFF" "$WIN_SHARING_IP" "$HINT_PORT"
        else
            send_hint "OFF" "$WIN_DIRECT_IP" "$HINT_PORT"
            send_hint "OFF" "$WIN_SHARING_IP" "$HINT_PORT"
        fi
    fi
}

# Terminates any background pipeline jobs cleanly when the daemon receives SIGTERM/SIGINT.
cleanup_children() {
    local pid
    for pid in $(jobs -p 2>/dev/null || true); do
        kill "$pid" 2>/dev/null || true
    done
}
trap cleanup_children EXIT TERM INT

# Run immediate sync at startup
sync_network

# Event loop: listen to macOS configd dynamic store notifications with valid `pattern` modifier
while true; do
    (
        trap 'exit 0' PIPE TERM INT
        echo "n.add State:/Network/Interface/(en[0-9]+|${BRIDGE_IFACE})/.* pattern"
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

cleanup_legacy_install

cat << EOF > "$NEW_PLIST"
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>${PLIST_LABEL}</string>
    <key>ProgramArguments</key>
    <array>
        <string>${WATCHDOG_PATH}</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>StandardOutPath</key>
    <string>${LOG_STDOUT}</string>
    <key>StandardErrorPath</key>
    <string>${LOG_STDERR}</string>
</dict>
</plist>
EOF

chown root:wheel "$NEW_PLIST"
chmod 644 "$NEW_PLIST"
launchctl bootout system "$NEW_PLIST" 2>/dev/null || true
launchctl bootstrap system "$NEW_PLIST"

echo "macOS USB-C NCM dynamic watchdog installed & running cleanly (${PLIST_LABEL})."
echo "Configured at ${MAC_DIRECT_IP} (netmask ${DIRECT_NETMASK}, Direct Link) and ${SHARING_GW_IP} (macOS Internet Sharing)."
echo "Test connection with: ping ${WIN_DIRECT_IP}"
