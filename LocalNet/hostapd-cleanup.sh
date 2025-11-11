#!/bin/bash

echo "[+] Stopping hostapd and dnsmasq..."
sudo pkill hostapd 2>/dev/null || true
sudo pkill dnsmasq 2>/dev/null || true

echo "[+] Removing host route for target IP..."
sudo ip route del 146.190.62.39 2>/dev/null || true

echo "[+] Restoring original iptables rules..."
if [ -f /tmp/iptables-before-setup.rules ]; then
    sudo iptables-restore < /tmp/iptables-before-setup.rules
    echo "[✓] iptables rules restored from backup"
else
    echo "[!] No backup found, flushing and resetting to defaults..."
    sudo iptables -t nat -F
    sudo iptables -t mangle -F
    sudo iptables -F
    sudo iptables -X
    sudo iptables -P INPUT ACCEPT
    sudo iptables -P FORWARD ACCEPT
    sudo iptables -P OUTPUT ACCEPT
fi

echo "[+] Removing AP interface..."
sudo iw dev ap0 del 2>/dev/null || true

echo "[+] Disabling IP forwarding..."
sudo sysctl -w net.ipv4.ip_forward=0

echo "[+] Restarting NetworkManager..."
sudo systemctl restart NetworkManager

sleep 2

echo "[+] Checking network connectivity..."
if ping -c 1 8.8.8.8 &> /dev/null; then
    echo "[✓] Internet connection restored!"
else
    echo "[!] Warning: No internet connectivity detected"
    echo "[!] You may need to manually reconnect or run: sudo systemctl restart NetworkManager"
fi

echo "[+] Done! Wi-Fi and networking restored."
