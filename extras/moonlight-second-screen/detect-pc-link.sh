#!/bin/bash
# Mutual detection of USB-C (10.99.99.x or 192.168.2.x), Hotspot (192.168.137.1), or Wi-Fi LAN on Mac

USBC_ACTIVE=0
for iface in bridge100 en3 en5; do
    st=$(ifconfig "$iface" 2>/dev/null | awk '/status:/ {print $2}')
    if [ "$st" = "active" ]; then
        USBC_ACTIVE=1
        break
    fi
done

# Auto-heal direct link static IP on active NCM adapter if Internet Sharing (bridge100) is OFF
if ! ifconfig bridge100 >/dev/null 2>&1; then
    for iface in en3 en5; do
        if ifconfig "$iface" 2>/dev/null | grep -q "status: active" && ! ifconfig "$iface" 2>/dev/null | grep -q "inet 10.99.99.2"; then
            networksetup -setmanual "Ethernet Adapter ($iface)" 10.99.99.2 255.255.255.0 2>/dev/null || true
            sleep 0.1
        fi
    done
fi

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

# 4. Fall back to Wi-Fi (Windows Mobile Hotspot 192.168.137.1 or Shared Router LAN via mDNS)
if [ -z "$PC_IP" ]; then
    CONN_MODE="Wi-Fi"
    MAC_IP=$(ipconfig getifaddr en0 2>/dev/null || echo "192.168.137.58")
    if ping -c 1 -W 150 192.168.137.1 >/dev/null 2>&1; then
        PC_IP="192.168.137.1"
    else
        for cand in $(dscacheutil -q host -a name HP-Omen.local 2>/dev/null | awk '/^ip_address:/ {print $2}' | grep -vE '^(10\.99\.99\.|192\.168\.2\.)'); do
            if ping -c 1 -W 150 "$cand" >/dev/null 2>&1 || nc -z -G 1 "$cand" 47989 >/dev/null 2>&1; then
                PC_IP="$cand"
                break
            fi
        done
        [ -z "$PC_IP" ] && PC_IP="192.168.137.1"
    fi
fi

# Update Moonlight host addresses (for both Primary HP-Omen and Secondary HP-Omen-Mac2)
CURRENT_USER=$(stat -f "%Su" /dev/console 2>/dev/null || echo "$USER")
for idx in 1 2; do
    if [ "$(id -u)" -eq 0 ] && [ -n "$CURRENT_USER" ] && [ "$CURRENT_USER" != "root" ]; then
        sudo -u "$CURRENT_USER" defaults write com.moonlight-stream.Moonlight "hosts.${idx}.localaddress" -string "$PC_IP"
        sudo -u "$CURRENT_USER" defaults write com.moonlight-stream.Moonlight "hosts.${idx}.manualaddress" -string "$PC_IP"
    else
        defaults write com.moonlight-stream.Moonlight "hosts.${idx}.localaddress" -string "$PC_IP"
        defaults write com.moonlight-stream.Moonlight "hosts.${idx}.manualaddress" -string "$PC_IP"
    fi
done

echo "${CONN_MODE}|${PC_IP}|${MAC_IP}"
