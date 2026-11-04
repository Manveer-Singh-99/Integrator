#!/bin/bash
# Instant check: only probe 10.99.99.1 if en3 or en5 is physically active
USBC_ACTIVE=0
for iface in en3 en5; do
    st=$(ifconfig "$iface" 2>/dev/null | awk "/status:/ {print \$2}")
    if [ "$st" = "active" ]; then
        USBC_ACTIVE=1
        if [ "$(id -u)" -eq 0 ] && ! ifconfig "$iface" 2>/dev/null | grep -q "10.99.99.2"; then
            ifconfig "$iface" inet 10.99.99.2 netmask 255.255.255.0 up 2>/dev/null || true
        fi
    fi
done

if [ "$USBC_ACTIVE" -eq 1 ] && ping -c 1 -W 200 10.99.99.1 >/dev/null 2>&1; then
    CONN_MODE="USB-C"
    PC_IP="10.99.99.1"
    MAC_IP="10.99.99.2"
else
    CONN_MODE="Wi-Fi"
    PC_IP="192.168.137.1"
    MAC_IP=$(ipconfig getifaddr en0 2>/dev/null || echo "192.168.137.58")
fi

if [ "$(id -u)" -eq 0 ]; then
    sudo -u manveersingh defaults write com.moonlight-stream.Moonlight "hosts.1.localaddress" -string "$PC_IP"
    sudo -u manveersingh defaults write com.moonlight-stream.Moonlight "hosts.1.manualaddress" -string "192.168.137.1"
else
    defaults write com.moonlight-stream.Moonlight "hosts.1.localaddress" -string "$PC_IP"
    defaults write com.moonlight-stream.Moonlight "hosts.1.manualaddress" -string "192.168.137.1"
fi

echo "${CONN_MODE}|${PC_IP}|${MAC_IP}"
