#!/bin/bash
set -e

UPSTREAM_IF="enp2s0" 

sudo systemctl stop NetworkManager
sudo rfkill unblock all

echo "Creating new interface ap0"
sudo iw dev ap0 del 2>/dev/null || true
sudo iw phy phy0 interface add ap0 type __ap
sudo ip link set ap0 up

echo "Assigning IP 146.190.62.1/24 to ap0"
sudo ip addr add 192.168.50.1/24 dev ap0
sudo sysctl -w net.ipv4.ip_forward=1
sudo sysctl -w net.ipv4.conf.ap0.proxy_arp=1

echo "Routing"
sudo iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
sudo iptables -A FORWARD -i eth0 -o wlan0 -m state --state RELATED,ESTABLISHED -j ACCEPT
sudo iptables -A FORWARD -i wlan0 -o eth0 -j ACCEPT

echo "Starting hostapd"
sudo hostapd /etc/hostapd/hostapd-server.conf
