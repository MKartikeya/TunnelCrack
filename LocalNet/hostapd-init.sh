#!/bin/bash
set -e

# Upstream internet interface
UPSTREAM_IF="enx98fc84e0c08a"  # Ethernet connection to Internet

echo "[*] Stopping NetworkManager ..."
sudo systemctl stop NetworkManager

echo "[*] Unblocking all wireless devices..."
sudo rfkill unblock all

echo "[*] Cleaning up old AP interface if any..."
sudo iw dev ap0 del 2>/dev/null || true

echo "[*] Creating AP interface (using phy0/wlp0s20f3 as base)..."
sudo iw phy phy0 interface add ap0 type __ap

echo "[*] Bringing up AP interface..."
sudo ip link set ap0 up

echo "[*] Assigning IP 146.190.62.1/24 to ap0..."
sudo ip addr add 146.190.62.1/24 dev ap0

echo "[*] Enabling IP forwarding and proxy ARP..."
sudo sysctl -w net.ipv4.ip_forward=1
sudo sysctl -w net.ipv4.conf.ap0.proxy_arp=1

echo "[*] Getting gateway for upstream interface ($UPSTREAM_IF)..."
GATEWAY=$(ip route | grep "default via" | grep "$UPSTREAM_IF" | awk '{print $3}')
if [ -z "$GATEWAY" ]; then
    GATEWAY=$(ip route show default | awk '/default/ {print $3; exit}')
fi

if [ -n "$GATEWAY" ]; then
    sudo ip route add 146.190.62.39 via $GATEWAY dev $UPSTREAM_IF
    echo "[+] Host route added: 146.190.62.39 via $GATEWAY dev $UPSTREAM_IF"
else
    echo "[!] Warning: Could not determine gateway, skipping host route"
fi

echo "[*] Setting up iptables rules..."
# Allow DHCP traffic on ap0
sudo iptables -I INPUT -i ap0 -p udp --dport 67:68 -j ACCEPT
sudo iptables -I OUTPUT -o ap0 -p udp --sport 67:68 -j ACCEPT

# NAT and forwarding rules (routing through Ethernet)
sudo iptables -t nat -A POSTROUTING -o $UPSTREAM_IF -j MASQUERADE
sudo iptables -t nat -A POSTROUTING -s 146.190.62.0/24 -o $UPSTREAM_IF -j MASQUERADE
sudo iptables -A FORWARD -i ap0 -o $UPSTREAM_IF -j ACCEPT
sudo iptables -A FORWARD -i $UPSTREAM_IF -o ap0 -m state --state RELATED,ESTABLISHED -j ACCEPT

echo "[+] Routing configured: ap0 -> $UPSTREAM_IF (Ethernet)"
echo "[+] WiFi interface (wlp0s20f3/phy0) being used only for AP broadcast"

echo "[*] Starting hostapd..."
sudo hostapd /etc/hostapd/hostapd-evil.conf
