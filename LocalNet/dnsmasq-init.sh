#!/bin/bash
set -e

echo "[*] Backing up and disabling systemd-resolved for dnsmasq..."

# Backup resolv.conf if it's a symlink
if [ -L /etc/resolv.conf ]; then
    echo "[+] Backing up existing resolv.conf symlink..."
    sudo cp -L /etc/resolv.conf ~/resolv.conf.backup
fi

# Stop systemd-resolved
echo "[+] Stopping systemd-resolved..."
sudo systemctl stop systemd-resolved

# Replace resolv.conf with a static one
echo "[+] Creating temporary resolv.conf with public DNS servers..."
echo "nameserver 8.8.8.8" | sudo tee /etc/resolv.conf > /dev/null

# Confirm
echo "[+] systemd-resolved disabled, dnsmasq can bind to port 53."
