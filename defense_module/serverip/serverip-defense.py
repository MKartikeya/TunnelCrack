#!/usr/bin/env python3

import subprocess
import sys
import os

def run(cmd):
    print("[+] " + " ".join(cmd))
    subprocess.run(cmd, check=False)

class DNSEnforcer:

    def enforce_google_dns():
        print("\n=== Enabling Forced DNS to Google (8.8.8.8) ===\n")

        # dsiabling systemd-resolved
        print("[+] Disabling systemd-resolved")
        run(["systemctl", "stop", "systemd-resolved"])
        run(["systemctl", "disable", "systemd-resolved"])

        # removing /etc/resolv.conf
        if os.path.exists("/etc/resolv.conf"):
            print("[+] Removing /etc/resolv.conf")
            run(["rm", "-f", "/etc/resolv.conf"])

        # adding google nameserver
        print("[+] Setting /etc/resolv.conf to use Google DNS")
        with open("/etc/resolv.conf", "w") as f:
            f.write("nameserver 8.8.8.8\n")

        # iptables firewall rules
        print("[+] Adding firewall rules to enforce Google DNS only")

        # NAT redirecting all DNS
        run(["iptables", "-t", "nat", "-A", "OUTPUT", "-p", "udp","--dport", "53", "-j", "DNAT", "--to-destination", "8.8.8.8"])
        run(["iptables", "-t", "nat", "-A", "OUTPUT", "-p", "tcp","--dport", "53", "-j", "DNAT", "--to-destination", "8.8.8.8"])

        # rejecting DNS not going to Google
        run(["iptables", "-A", "OUTPUT", "-p", "udp", "--dport", "53","!", "-d", "8.8.8.8", "-j", "REJECT"])
        run(["iptables", "-A", "OUTPUT", "-p", "tcp", "--dport", "53","!", "-d", "8.8.8.8", "-j", "REJECT"])

        print("\n=== DNS FORCED TO GOOGLE ONLY ===")

class DNSSpoofDetector:

    def detect_dns_spoofing(self):
        hostname = input("VPN hostname to check: ").strip()
        if not hostname:
            print("Error: Hostname required")
            return

        while True:
            print("\nTrusted DNS method:")
            print("  1. DNS over HTTPS (Cloudflare)")
            print("  2. DNS over HTTPS (Google)")
            print("  3. DNS over TLS")
            method = input("\nSelect (1-3): ").strip()

            print(f"\nChecking {hostname}...")

            try:
                print("  [1/2] Querying local DNS...")
                local_ip = self._query_local_dns(hostname)
                print(f"        Local DNS: {local_ip}")

                print("  [2/2] Querying trusted DNS...")
                if method == '1':
                    trusted_ip = self._query_doh_cloudflare(hostname)
                    # trusted_ip = self._query_doh_google(hostname)
                elif method == '2':
                    trusted_ip = self._query_doh_google(hostname)
                elif method == '3':
                    trusted_ip = self._query_dot(hostname)
                else:
                    print("[!] Invalid input, defaulting to Google DoH")
                    trusted_ip = self._query_doh_google(hostname)

                print(f"        Trusted DNS: {trusted_ip}")

                print("\n" + "=" * 50)
                if local_ip != trusted_ip:
                    print("[!] DNS SPOOFING DETECTED!")
                    print(f"    Local DNS returns: {local_ip}")
                    print(f"    Actual IP is: {trusted_ip}")
                    print("=" * 50)
                else:
                    print("[.] No DNS spoofing detected")
                    print(f"    Both resolve to: {local_ip}")
                    print("=" * 50)

            except Exception as e:
                print(f"\n[!] Detection failed: {e}")
                return

    # LOCAL DNS
    def _query_local_dns(self, hostname):
        result = subprocess.run(
            ["nslookup", hostname],
            capture_output=True, text=True, timeout=5
        )
        for line in result.stdout.split('\n'):
            if 'Address:' in line and '#53' not in line:
                ip = line.split('Address:')[1].strip()
                if ip and not ip.startswith("127"):
                    return ip
        raise Exception("Could not parse local DNS response")

    # CLOUDFLARE DOH
    def _query_doh_cloudflare(self, hostname):
        import requests
        url = "https://1.1.1.1/dns-query"
        headers = {"accept": "application/dns-json"}
        params = {"name": hostname, "type": "A"}
        r = requests.get(url, headers=headers, params=params, timeout=10).json()
        return r["Answer"][0]["data"]

    # GOOGLE DOH
    def _query_doh_google(self, hostname):
        import requests
        url = "https://dns.google/resolve"
        params = {"name": hostname, "type": "A"}
        r = requests.get(url, params=params, timeout=10).json()
        return r["Answer"][0]["data"]

    # DNS OVER TLS
    def _query_dot(self, hostname):
        import dns.message, dns.query, dns.rdatatype, ssl

        q = dns.message.make_query(hostname, dns.rdatatype.A)

        ctx = ssl.create_default_context()
        ctx.check_hostname = True
        ctx.verify_mode = ssl.CERT_REQUIRED

        resp = dns.query.tls(
            q=q,
            where="1.1.1.1",
            port=853,
            timeout=5,
            ssl_context=ctx,
            server_hostname="cloudflare-dns.com"
        )

        for ans in resp.answer:
            for item in ans.items:
                if hasattr(item, "address"):
                    return item.address

        raise Exception("No TLS DNS answer received")

def main():
    if os.geteuid() != 0:
        print("Run as root: sudo python3 integrated_dns_tool.py")
        sys.exit(1)

    detector = DNSSpoofDetector()

    while True:
        print("1. Enforce Authenticated DNS (Google 8.8.8.8)")
        print("2. Detect DNS Spoofing (DoH/DoT)")
        choice = input("\nSelect an option: ").strip()

        if choice == "1":
            DNSEnforcer.enforce_google_dns()
            return
        elif choice == "2":
            detector.detect_dns_spoofing()
        else:
            return


if __name__ == "__main__":
    main()
