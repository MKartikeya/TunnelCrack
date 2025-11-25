#!/usr/bin/env python3
import subprocess
import sys
import os

def run(cmd):
    print("[+] " + " ".join(cmd))
    subprocess.run(cmd, check=False)

def main():
    print("\n=== Restoring DNS configuration ===\n")

    # 1. Remove the iptables rules
    print("[+] Removing firewall rules")

    run(["iptables", "-t", "nat", "-D", "OUTPUT", "-p", "udp", "--dport", "53","-j", "DNAT", "--to-destination", "8.8.8.8"])
    run(["iptables", "-t", "nat", "-D", "OUTPUT", "-p", "tcp", "--dport", "53","-j", "DNAT", "--to-destination", "8.8.8.8"])

    run(["iptables", "-D", "OUTPUT", "-p", "udp", "--dport", "53","!", "-d", "8.8.8.8", "-j", "REJECT"])
    run(["iptables", "-D", "OUTPUT", "-p", "tcp", "--dport", "53","!", "-d", "8.8.8.8", "-j", "REJECT"])

    # 2. Restore systemd-resolved
    print("[+] Re-enabling systemd-resolved")
    run(["systemctl", "enable", "systemd-resolved"])
    run(["systemctl", "start", "systemd-resolved"])

    # 3. Restore /etc/resolv.conf symlink
    print("[+] Restoring /etc/resolv.conf")
    run(["rm", "-f", "/etc/resolv.conf"])
    run(["ln", "-s", "/run/systemd/resolve/stub-resolv.conf", "/etc/resolv.conf"])

    print("\n=== DNS RESTORED TO NORMAL ===\n")

if __name__ == "__main__":
    if os.geteuid() != 0:
        print("Run as root: sudo python3 restore_dns.py")
        sys.exit(1)
    main()
