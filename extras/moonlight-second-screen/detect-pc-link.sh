#!/bin/bash
# Mutual detection of USB-C (10.99.99.x or 192.168.2.x) vs Wi-Fi on Mac

USBC_ACTIVE=0
for iface in bridge100 en3 en5; do
    st=$(ifconfig "$iface" 2>/dev/null | awk '/status:/ {print $2}')
    if [ "$st" = "active" ]; then
        USBC_ACTIVE=1
        break
    fi
done

CONN_MODE=""
PC_IP=""
MAC_IP=""

# 1. Probe direct link-local 10.99.99.1
if [ "$USBC_ACTIVE" -eq 1 ] && ping -c 1 -W 150 10.99.99.1 >/dev/null 2>&1; then
    CONN_MODE="USB-C"
    PC_IP="10.99.99.1"
    MAC_IP="10.99.99.2"
# 2. Probe macOS Internet Sharing link 192.168.2.2
elif [ "$USBC_ACTIVE" -eq 1 ] && ping -c 1 -W 150 192.168.2.2 >/dev/null 2>&1; then
    CONN_MODE="USB-C"
    PC_IP="192.168.2.2"
    MAC_IP="192.168.2.1"
elif [ "$USBC_ACTIVE" -eq 1 ]; then
    # 3. Probe any other 192.168.2.x IP assigned by DHCP
    for ip in $(arp -an 2>/dev/null | awk -F'[()]' '{print $2}' | grep '^192\.168\.2\.' | grep -v '^192\.168\.2\.1$'); do
        if ping -c 1 -W 150 "$ip" >/dev/null 2>&1; then
            CONN_MODE="USB-C"
            PC_IP="$ip"
            MAC_IP="192.168.2.1"
            break
        fi
    done
fi

# 4. Fall back to Wi-Fi
if [ -z "$PC_IP" ]; then
    CONN_MODE="Wi-Fi"
    PC_IP="192.168.137.1"
    MAC_IP=$(ipconfig getifaddr en0 2>/dev/null || echo "192.168.137.58")
fi

# Update Moonlight settings if user or root
CURRENT_USER=$(stat -f "%Su" /dev/console 2>/dev/null || echo "$USER")
if [ "$(id -u)" -eq 0 ] && [ -n "$CURRENT_USER" ] && [ "$CURRENT_USER" != "root" ]; then
    sudo -u "$CURRENT_USER" defaults write com.moonlight-stream.Moonlight "hosts.1.localaddress" -string "$PC_IP"
    sudo -u "$CURRENT_USER" defaults write com.moonlight-stream.Moonlight "hosts.1.manualaddress" -string "192.168.137.1"
else
    defaults write com.moonlight-stream.Moonlight "hosts.1.localaddress" -string "$PC_IP"
    defaults write com.moonlight-stream.Moonlight "hosts.1.manualaddress" -string "192.168.137.1"
fi

echo "${CONN_MODE}|${PC_IP}|${MAC_IP}"
