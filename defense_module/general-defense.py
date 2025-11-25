#!/usr/bin/env python3
"""
TunnelCrack Detection Suite
"""

import subprocess
import re
import ipaddress
import platform
import socket
import sys

RFC1918 = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16")
]

CGNAT = ipaddress.ip_network("100.64.0.0/10")
BENCH = ipaddress.ip_network("198.18.0.0/15")
SAFE_LOCAL_RANGES = RFC1918
VPN_IFACE_KEYWORDS = ["tun", "tap", "ppp", "utun", "wg", "vpn"]

def run(cmd):
    try:
        return subprocess.check_output(cmd, shell=True, text=True, stderr=subprocess.DEVNULL).strip()
    except:
        return ""

def get_os():
    return platform.system().lower()

def iface_is_tunnel(name):
    if not name:
        return False
    return any(k in name.lower() for k in VPN_IFACE_KEYWORDS)

def get_routes():
    osn = get_os()
    if "linux" in osn:
        return parse_linux(run("ip route"))
    elif "darwin" in osn:
        return parse_mac(run("netstat -rn"))
    elif "windows" in osn:
        return parse_windows(run("route print"))
    return []

def parse_linux(out):
    routes = []
    for l in out.splitlines():
        if not l.strip():
            continue
        if l.startswith("default"):
            dev = re.search(r"dev\s+(\S+)", l)
            routes.append(("0.0.0.0/0", dev.group(1) if dev else None))
        else:
            m = re.match(r"(\S+)\s+.*dev\s+(\S+)", l)
            if m:
                routes.append((m.group(1), m.group(2)))
    return routes

def parse_mac(out):
    routes = []
    start = False
    for l in out.splitlines():
        if l.lower().startswith("destination"):
            start = True
            continue
        if not start:
            continue
        parts = re.split(r"\s+", l.strip())
        if len(parts) < 6:
            continue
        dest, gw, flags, refs, use, iface = parts[:6]
        if dest == "default":
            routes.append(("0.0.0.0/0", iface))
        else:
            if "/" not in dest:
                try:
                    ipaddress.ip_address(dest)
                    dest = dest + "/32"
                except:
                    continue
            routes.append((dest, iface))
    return routes

def parse_windows(out):
    routes = []
    capture = False
    lines = out.splitlines()
    for i, l in enumerate(lines):
        if "IPv4 Route Table" in l:
            capture = True
            continue
        if not capture:
            continue
        if l.strip().startswith("Network Destination"):
            j = i + 1
            while j < len(lines):
                line = lines[j].strip()
                j += 1
                if not line:
                    continue
                parts = re.split(r"\s+", line)
                if len(parts) < 5:
                    break
                dest, mask, gateway, interface, metric = parts[:5]
                if dest == "0.0.0.0":
                    routes.append(("0.0.0.0/0", interface))
                else:
                    try:
                        net = str(ipaddress.ip_network(dest + "/" + mask, strict=False))
                        routes.append((net, interface))
                    except:
                        pass
            break
    return routes

def analyze_vpn_routing():
    print("\n=== VPN Routing ===")
    
    routes = get_routes()
    if not routes:
        print("VPN: NO | LocalNet: NO | ServerIP: NO | Other: NO")
        print("Verdict: NO VPN")
        return

    ifaces = {iface for (_, iface) in routes if iface}
    tunnel_ifaces = [i for i in ifaces if iface_is_tunnel(i)]
    vpn_present = bool(tunnel_ifaces)

    localnet_vuln = serverip_vuln = other_vulns = False

    for net, iface in routes:
        if not iface or iface_is_tunnel(iface):
            continue
        try:
            n = ipaddress.ip_network(net, strict=False)
        except:
            continue
        if n.prefixlen == 0:
            continue

        if not any(n.subnet_of(r) for r in SAFE_LOCAL_RANGES):
            localnet_vuln = True
        if n.prefixlen >= (32 if n.version == 4 else 128):
            serverip_vuln = True
        if n.subnet_of(CGNAT) or n.subnet_of(BENCH) or n.prefixlen < 8:
            other_vulns = True

    print(f"VPN: {'YES' if vpn_present else 'NO'} | LocalNet: {'YES' if localnet_vuln else 'NO'} | ServerIP: {'YES' if serverip_vuln else 'NO'} | Other: {'YES' if other_vulns else 'NO'}")
    
    if not vpn_present:
        print("Verdict: NO VPN")
    elif localnet_vuln or serverip_vuln or other_vulns:
        print("Verdict: VULNERABLE")
    else:
        print("Verdict: SAFE")

def get_lan_subnet():
    osn = get_os()
    
    if "linux" in osn or "darwin" in osn:
        out = run("ip -o addr show scope global")
        m = re.search(r'(\d+\.\d+\.\d+\.\d+)/(\d+)', out)
        if m:
            return f"{m.group(1)}/{m.group(2)}"
    elif "windows" in osn:
        out = run("ipconfig")
        ipm = re.search(r"IPv4 Address.*?:\s*([\d\.]+)", out)
        smm = re.search(r"Subnet Mask.*?:\s*([\d\.]+)", out)
        if ipm and smm:
            try:
                net = ipaddress.ip_network(ipm.group(1) + "/" + smm.group(1), strict=False)
                return str(net)
            except:
                pass
    return None

def detect_dhcp_static_routes():
    return bool(run("sudo journalctl -b | grep -i 'option 121'").strip())

def dns_resolves_to_private(domain):
    if not domain:
        return False
    out = run(f"nslookup {domain}")
    for ip in re.findall(r'Address:\s*([\d\.]+)', out):
        try:
            addr = ipaddress.ip_address(ip)
            if any(addr in r for r in RFC1918) or addr in CGNAT:
                return True
        except:
            continue
    return False

def disconnect_wifi():
    osn = get_os()
    if "linux" in osn:
        run("nmcli device disconnect $(nmcli device status | grep wifi | awk '{print $1}')")
    elif "darwin" in osn:
        run("networksetup -setairportpower en0 off")
    elif "windows" in osn:
        run("netsh interface set interface 'Wi-Fi' admin=disable")

def analyze_malicious_ap(domain_to_test=None):
    print("\n=== Malicious AP ===")
    
    reasons = []
    lan = get_lan_subnet()
    
    if lan:
        try:
            net = ipaddress.ip_network(lan, strict=False)
            if net.prefixlen < 16:
                reasons.append(f"Suspicious prefix: {lan}")
            if not any(net.subnet_of(r) for r in RFC1918 + [CGNAT]):
                reasons.append(f"Public subnet: {lan}")
            if net.subnet_of(BENCH):
                reasons.append(f"Benchmark range: {lan}")
        except:
            pass
    else:
        reasons.append("Cannot determine subnet")

    if detect_dhcp_static_routes():
        reasons.append("DHCP Option 121 detected")
    if domain_to_test and dns_resolves_to_private(domain_to_test):
        reasons.append(f"DNS spoofing: {domain_to_test}")

    malicious = len(reasons) > 0
    print(f"Status: {'MALICIOUS' if malicious else 'SAFE'}")
    
    if reasons:
        for r in reasons:
            print(f"  - {r}")

    if malicious:
        if input("\nDisconnect? (y/n): ").strip().lower() == 'y':
            disconnect_wifi()
            print("Disconnected")

def has_ipv6_address():
    out = run("ip -6 addr show")
    return any("scope" in line for line in out.splitlines() if line.strip().startswith("inet6"))

def ipv6_default_route():
    out = run("ip -6 route show default")
    if out and " dev " in out:
        return out.split(" dev ")[1].split()[0]
    return None

def test_ipv6_connectivity():
    try:
        import requests
        r = requests.get("https://ifconfig.co/ip", timeout=3)
        ip = r.text.strip()
        socket.inet_pton(socket.AF_INET6, ip)
        return ip
    except:
        return None

def analyze_ipv6_leak():
    print("\n=== IPv6 Leak ===")

    route_iface = ipv6_default_route()
    if not route_iface:
        print("Status: SAFE (disabled)")
        return

    if not has_ipv6_address():
        print("Status: SAFE (no global IPv6)")
        return

    ipv6_public = test_ipv6_connectivity()
    if not ipv6_public:
        print("Status: SAFE (no connectivity)")
        return

    if route_iface.startswith("tun") or route_iface.startswith("wg"):
        print(f"Status: SAFE (tunneled via {route_iface})")
    else:
        print(f"Status: LEAK ({ipv6_public} via {route_iface})")

def main():
    
    analyze_vpn_routing()
    analyze_malicious_ap()
    analyze_ipv6_leak()
    
    print()

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n")
        sys.exit(0)