#!/usr/bin/env python3
import subprocess, json, os, sys, time

class APCleanup:
    def __init__(self, cfg="/tmp/evil-twin-config.json"):
        try:
            with open(cfg) as f:
                self.c = json.load(f)
        except:
            self.c = {'ap_interface': 'ap0', 'wifi_interface': None}

    def sh(self, cmd):
        subprocess.run(cmd, shell=True, stdout=subprocess.DEVNULL,
                       stderr=subprocess.DEVNULL)

    def kill_procs(self):
        for p in ["hostapd", "dnsmasq"]:
            self.sh(f"pkill -9 {p}")
        time.sleep(1)

    def remove_iface(self):
        ap = self.c.get("ap_interface", "ap0")
        self.sh(f"iw dev {ap} del")

    def iptables_reset(self):
        self.sh("iptables -F")
        self.sh("iptables -t nat -F")
        self.sh("iptables -X")
        self.sh("iptables -P INPUT ACCEPT")
        self.sh("iptables -P FORWARD ACCEPT")
        self.sh("iptables -P OUTPUT ACCEPT")

    def disable_forward(self):
        self.sh("sysctl -w net.ipv4.ip_forward=0")
        self.sh("sysctl -w net.ipv4.conf.all.rp_filter=1")
        self.sh("sysctl -w net.ipv4.conf.default.rp_filter=1")

    def restore_resolv(self):
        b = "/tmp/resolv.conf.backup"
        if os.path.exists(b):
            self.sh(f"cp {b} /etc/resolv.conf")
        else:
            with open("/etc/resolv.conf", "w") as f:
                f.write("nameserver 8.8.8.8\nnameserver 1.1.1.1\n")

    def restore_wifi(self):
        w = self.c.get("wifi_interface")
        if not w:
            return
        self.sh(f"ip link set {w} down")
        self.sh(f"iw dev {w} set type managed")
        self.sh(f"ip link set {w} up")

    def restart_services(self):
        self.sh("systemctl start NetworkManager")
        self.sh("systemctl start systemd-resolved")

    def cleanup_files(self):
        for f in [
            "/var/log/hostapd-evil.log",
            "/var/log/dnsmasq-evil.log",
            "/tmp/hostapd-evil.conf",
            "/tmp/dnsmasq-evil.conf",
            "/tmp/evil-twin-config.json",
            "/tmp/iptables-backup.rules",
            "/tmp/resolv.conf.backup",
        ]:
            try: os.remove(f)
            except: pass

    def run(self):
        print("[*] Cleaning up AP...")
        self.kill_procs()
        self.remove_iface()
        self.iptables_reset()
        self.disable_forward()
        self.restore_resolv()
        self.restore_wifi()
        self.restart_services()
        self.cleanup_files()
        print("[*] Cleanup complete")

if __name__ == "__main__":
    if os.geteuid() != 0:
        print("[*] Run as root")
        sys.exit(1)
    APCleanup().run()
