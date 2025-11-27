#!/usr/bin/env python3
import argparse
import subprocess
import shlex
import os
import ipaddress
from datetime import datetime
import sys
import re


RFC1918 = ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"]
LINK_LOCAL = "169.254.0.0/16"
LOOPBACK = "127.0.0.0/8"


def sh(cmd, capture=False, check=False):
    if capture:
        return subprocess.check_output(cmd, shell=True, text=True)
    else:
        return subprocess.run(cmd, shell=True, check=check)

def sh_safe(cmd):
    try:
        subprocess.run(cmd, shell=True, check=True, stderr=subprocess.DEVNULL)
    except subprocess.CalledProcessError:
        pass

def shlex_q(s):
    return shlex.quote(s)

def is_private_ip(ip):
    try:
        addr = ipaddress.ip_address(ip)
        return addr.is_private or addr.is_link_local or addr.is_loopback
    except Exception:
        return True

def detect_management_interface():
    try:
        out = sh("ip route get 8.8.8.8", capture=True)
        parts = out.split()
        if "dev" in parts:
            i = parts.index("dev")
            if i+1 < len(parts):
                return parts[i+1]
    except Exception:
        pass
    return None

def detect_vpn_interface():
    try:
        rt = sh("ip -4 route show", capture=True)
        for line in rt.splitlines():
            if " dev " in line:
                dev = line.split(" dev ")[1].split()[0]
                if re.match(r"^(tun|wg|vpn|tap|utun)\S*$", dev):
                    return dev
        
        out = sh("ip -o link show", capture=True)
        for l in out.splitlines():
            name = l.split(':', 2)[1].strip().split('@')[0]
            if re.match(r"^(tun|wg|vpn|tap|utun)\S*$", name):
                return name
    except Exception:
        pass
    return None

def backup_state(pid):
    now = datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")
    ipt_backup = f"/tmp/iptables-backup-{pid}.rules"
    routes_backup = f"/tmp/routes-backup-{pid}.txt"
    ipf_backup = f"/tmp/ip_forward-before-{pid}.txt"
    
    sh(f"iptables-save > {shlex_q(ipt_backup)}", check=True)
    sh(f"ip -4 route show > {shlex_q(routes_backup)}", check=True)
    sh(f"cat /proc/sys/net/ipv4/ip_forward > {shlex_q(ipf_backup)}", check=True)
    
    return ipt_backup, routes_backup, ipf_backup

def write_restore_script(pid, ipt_backup, routes_backup, ipf_backup, removed_routes):
    script = f"/tmp/restore_tunnelcrack_{pid}.sh"
    
    with open(script, "w") as f:
        f.write("#!/usr/bin/env bash\n")
        f.write("set -e\n\n")
        
        f.write(f"echo '[RESTORE] Restoring iptables...'\n")
        f.write(f"iptables-restore < {shlex_q(ipt_backup)}\n")
        f.write("echo '[OK] iptables restored'\n\n")
        
        f.write(f"echo '[RESTORE] Restoring removed routes...'\n")
        for route_line in removed_routes:
            route_line = route_line.strip()
            if not route_line:
                continue
            f.write(f"ip route add {route_line} 2>/dev/null || true\n")
        f.write("echo '[OK] Routes restored'\n\n")
        
        f.write(f"echo '[RESTORE] Restoring ip_forward setting...'\n")
        f.write(f"if [ -f {shlex_q(ipf_backup)} ]; then\n")
        f.write(f"  cat {shlex_q(ipf_backup)} > /proc/sys/net/ipv4/ip_forward\n")
        f.write(f"  echo '[OK] ip_forward restored'\n")
        f.write(f"fi\n\n")
        
        f.write("echo '[COMPLETE] All settings restored'\n")
    
    os.chmod(script, 0o755)
    return script

def get_route_details(route_line):
    parts = route_line.split()
    if not parts:
        return None
    
    dest = parts[0]
    details = {"dest": dest, "full_line": route_line}
    
    if "via" in parts:
        idx = parts.index("via")
        if idx + 1 < len(parts):
            details["via"] = parts[idx + 1]
    
    if "dev" in parts:
        idx = parts.index("dev")
        if idx + 1 < len(parts):
            details["dev"] = parts[idx + 1]
    
    return details

def remove_public_onlink_routes(vpn_if):
    removed = []
    out = sh("ip -4 route show", capture=True)
    
    for line in out.splitlines():
        line = line.strip()
        if not line:
            continue
            
        if line.startswith("default"):
            continue
            
        if " dev " not in line or " via " in line:
            continue
        
        details = get_route_details(line)
        if not details:
            continue
            
        dest = details["dest"]
        ip_part = dest.split("/")[0]
        
        if ip_part.startswith("127.") or ip_part.startswith("169.254."):
            continue
        
        if is_private_ip(ip_part):
            continue
        
        if vpn_if and details.get("dev") == vpn_if:
            continue
        
        removed.append(line)
        sh_safe(f"ip route del {dest}")
    
    return removed

def delete_non_vpn_default_routes(vpn_if):
    removed = []
    out = sh("ip -4 route show", capture=True)
    
    for line in out.splitlines():
        line = line.strip()
        if not line.startswith("default"):
            continue
        
        if vpn_if and f" dev {vpn_if}" in line:
            continue
        
        removed.append(line)
        
        m = re.search(r"default via ([0-9.]+) dev (\S+)", line)
        if m:
            gw, dev = m.group(1), m.group(2)
            sh_safe(f"ip route del default via {shlex_q(gw)} dev {shlex_q(dev)}")
        else:
            sh_safe("ip route del default")
    
    return removed


def ensure_chain(chain):
    sh_safe(f"iptables -N {chain} 2>/dev/null")
    sh(f"iptables -F {chain}")

def rule_exists(chain, rule_spec):
    try:
        cmd = f"iptables -C {chain} {rule_spec}"
        result = subprocess.run(cmd, shell=True, stderr=subprocess.DEVNULL)
        return result.returncode == 0
    except Exception:
        return False

def add_rule(chain, rule_spec):
    if not rule_exists(chain, rule_spec):
        sh(f"iptables -A {chain} {rule_spec}")

def insert_jump_once(chain, position=1):
    sh_safe(f"iptables -D OUTPUT -j {chain} 2>/dev/null")
    sh(f"iptables -I OUTPUT {position} -j {chain}")

def get_local_subnets(vpn_if):
    local_subnets = []
    try:
        out = sh("ip -4 route show", capture=True)
        for line in out.splitlines():
            line = line.strip()
            if "proto kernel" in line and " dev " in line and " via " not in line:
                parts = line.split()
                dest = parts[0]
                
                if dest == "default":
                    continue
                
                if " dev " in line:
                    dev = line.split(" dev ")[1].split()[0]
                    if vpn_if and dev == vpn_if:
                        continue
                    
                    if dest.startswith("127."):
                        continue
                    
                    local_subnets.append(dest)
    except Exception as e:
        pass
    
    return local_subnets

def mode_disable_local_traffic(vpn_if, trusted_cidrs, mgmt_if):
    chain = "TC_DISABLE_LOCAL"
    ensure_chain(chain)
    
    #keeping all loopback traffic
    add_rule(chain, "-o lo -j ACCEPT")
    #keeping the traffic of any existing connection
    add_rule(chain, "-m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT")
    
    #allowing any packets that go out that VPN interface
    if vpn_if:
        add_rule(chain, f"-o {shlex_q(vpn_if)} -j ACCEPT")
    
    if mgmt_if:
        try:
            addr_out = sh(f"ip -o -f inet addr show {shlex_q(mgmt_if)}", capture=True)
            for line in addr_out.splitlines():
                parts = line.split()
                for i, p in enumerate(parts):
                    if p == "inet" and i + 1 < len(parts):
                        cidr = parts[i + 1]
                        #allowing all vpn related rules
                        if mgmt_if == vpn_if:
                            add_rule(chain, f"-d {shlex_q(cidr)} -j ACCEPT")
        except Exception:
            pass
    
    
    for cidr in RFC1918 + [LINK_LOCAL]:
        if subnet not in trusted_cidrs:
            add_rule(chain, f"-d {shlex_q(cidr)} -j DROP")
    
    local_subnets = get_local_subnets(vpn_if)
    for subnet in local_subnets:
        if subnet not in trusted_cidrs:
            add_rule(chain, f"-d {shlex_q(subnet)} -j DROP")
    
    #allowing other trusted ones
    for cidr in trusted_cidrs:
        add_rule(chain, f"-d {shlex_q(cidr)} -j ACCEPT")
    insert_jump_once(chain, position=1)

def mode_filter_rfc1918_only(vpn_if):
    removed_routes = remove_public_onlink_routes(vpn_if)
    
    chain = "TC_FILTER_RFC1918"
    ensure_chain(chain)
    
    add_rule(chain, f"-d {shlex_q(LOOPBACK)} -j RETURN")
    
    for cidr in RFC1918:
        add_rule(chain, f"-d {shlex_q(cidr)} -j RETURN")
    
    add_rule(chain, f"-d {shlex_q(LINK_LOCAL)} -j RETURN")
    
    if vpn_if:
        add_rule(chain, f"-o {shlex_q(vpn_if)} -j RETURN")
    
    add_rule(chain, "-j DROP")
    
    insert_jump_once(chain, position=1)
    
    return removed_routes

def mode_force_through_vpn(vpn_if):
    removed_routes = remove_public_onlink_routes(vpn_if)
    
    if vpn_if:
        removed_defaults = delete_non_vpn_default_routes(vpn_if)
        removed_routes.extend(removed_defaults)
    
    return removed_routes

def main():
    parser = argparse.ArgumentParser(
        description="TunnelCrack Countermeasures Implementation",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Modes:
  disable    - Block ALL local traffic (most restrictive)
  filter     - Allow RFC1918 only, block public IPs from bypassing VPN
  vpn-force  - Force public traffic through VPN by removing on-link routes
        """
    )
    parser.add_argument("--mode", required=True, choices=["disable", "filter", "vpn-force"], help="Countermeasure mode to apply")
    parser.add_argument("--vpn-if", help="VPN interface (auto-detected if omitted)")
    parser.add_argument("--trust", help="Comma-separated trusted CIDRs for local access", default="")
    
    args = parser.parse_args()
    
    trusted = [c.strip() for c in args.trust.split(",") if c.strip()]
    
    mgmt_if = detect_management_interface()
    vpn_if = args.vpn_if or detect_vpn_interface()
    
    pid = os.getpid()
    ipt_backup, routes_backup, ipf_backup = backup_state(pid)
    
    removed_routes = []
    
    if args.mode == "disable":
        mode_disable_local_traffic(vpn_if, trusted, mgmt_if)
        
    elif args.mode == "filter":
        removed_routes = mode_filter_rfc1918_only(vpn_if)
        
    elif args.mode == "vpn-force":
        removed_routes = mode_force_through_vpn(vpn_if)
    
    restore_script = write_restore_script(pid, ipt_backup, routes_backup, ipf_backup, removed_routes)
    
    print(f"\nMode: {args.mode}")
    print(f"Backups: {ipt_backup}, {routes_backup}, {ipf_backup}")
    print(f"Restore: sudo {restore_script}")

if __name__ == "__main__":
    main()