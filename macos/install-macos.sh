#!/bin/bash
# One-command macOS installer for Mac <-> Windows USB-C Direct Link (10.99.99.2/24)
# Uses a one-shot LaunchDaemon (KeepAlive = false) so zero background processes run on macOS.

set -e
if [ "$(id -u)" -ne 0 ]; then
    echo "Please run with sudo: sudo bash $0"
    exit 1
fi

mkdir -p /usr/local/bin

cat << 'EOF' > /usr/local/bin/apple-usb-ncm-watchdog.sh
#!/bin/bash
# One-shot setup at boot: configure both en3 and en5 physical USB-C ports with 10.99.99.2 and alias 192.168.2.1
for iface in en3 en5; do
    if ifconfig "$iface" >/dev/null 2>&1; then
        ifconfig "$iface" inet 10.99.99.2 netmask 255.255.255.0 up 2>/dev/null || true
        ifconfig "$iface" alias 192.168.2.1 netmask 255.255.255.0 2>/dev/null || true
    fi
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
    <false/>
</dict>
</plist>
EOF

chown root:wheel /Library/LaunchDaemons/com.antigravity.usbncm.plist
chmod 644 /Library/LaunchDaemons/com.antigravity.usbncm.plist
launchctl bootout system /Library/LaunchDaemons/com.antigravity.usbncm.plist 2>/dev/null || true
launchctl bootstrap system /Library/LaunchDaemons/com.antigravity.usbncm.plist

echo "macOS USB-C NCM configured at 10.99.99.2/24 (en3)."
echo "Test connection with: ping 10.99.99.1"
