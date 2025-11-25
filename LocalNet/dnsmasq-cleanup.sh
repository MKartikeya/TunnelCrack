#!/bin/bash
set -e

echo "[*] Restoring systemd-resolved..."

# Removing temporary resolv.conf
sudo rm -f /etc/resolv.conf

echo "[+] Restoring /etc/resolv.conf symlink..."
sudo ln -s /run/systemd/resolve/stub-resolv.conf /etc/resolv.conf

# Restart systemd-resolved
echo "[+] Restarting systemd-resolved service..."
sudo systemctl start systemd-resolved

# Restoring backup 
if [ -f ~/resolv.conf.backup ]; then
    echo "[+] Backup copy stored at ~/resolv.conf.backup ."
fi

echo "[.] DNS resolution restored."
