# Mtigations and Detections

Countermeasures against VPN traffic leakage attacks from the [TunnelCrack paper](https://papers.mathyvanhoef.com/usenix2023-tunnelcrack.pdf).

## Tools

### 1. `serverip-defense.py` - DNS Security Tool

Detects DNS spDoofing and enforces authenticated DNS.

**Usage:**
```bash
sudo python3 serverip-defense.py
```

**Features:**

**Option 1: Enforce Authenticated DNS**
- Forces all DNS queries to Google (8.8.8.8)
- Uses iptables to redirect/block other DNS servers
- Prevents DNS spoofing attacks permanently

**Option 2: Detect DNS Spoofing**
- Compares local DNS vs trusted DNS (DoH/DoT)
- Detects if attacker is spoofing DNS
- Use before connecting to VPN on untrusted networks

**Example:**
```bash
================ DNS SECURITY TOOL ================
1. Enforce Authenticated DNS (Google 8.8.8.8)
2. Detect DNS Spoofing (DoH/DoT)

Select an option: 2

VPN hostname to check: public-vpn-241.opengw.net

Trusted DNS method:
  1. DNS over HTTPS (Cloudflare)
  2. DNS over HTTPS (Google)
  3. DNS over TLS

Select (1-3): 2

Checking public-vpn-241.opengw.net...
  [1/2] Querying local DNS...
        Local DNS: 146.190.62.39
  [2/2] Querying trusted DNS...
        Trusted DNS: 219.100.37.187

==================================================
[!] DNS SPOOFING DETECTED!
    Local DNS returns: 146.190.62.39
    Actual IP is: 219.100.37.187
==================================================
```

**Restore DNS:**
```bash
sudo python3 restore_dns.py
```

---

### 2. `localnet-defense.py` - LocalNet Attack Defense

Prevents traffic leaks through routing and firewall rules.

**Usage:**
```bash
# Block all local traffic (maximum security)
sudo python3 localnet-defense.py --mode disable

# Allow RFC1918 only, block public IPs (recommended)
sudo python3 localnet-defense.py --mode filter

# Force public traffic through VPN
sudo python3 localnet-defense.py --mode vpn-force

# With trusted networks
sudo python3 localnet-defense.py --mode filter --trust "192.168.1.0/24"
```

**Modes:**

| Mode | Description |
|------|-------------|
| `disable` | Block ALL local traffic |
| `filter` | Allow RFC1918 private IPs only |
| `vpn-force` | Remove public IP routes |

**Restore:**
```bash
sudo /tmp/restore_tunnelcrack_<pid>.sh
```

---

### 3. `general-defense.py` - Detection Suite

Analyzes VPN security and detects malicious networks.

**Usage:**
```bash
python3 general-defense.py
```

**Detects:**
- LocalNet vulnerabilities
- ServerIP vulnerabilities  
- Malicious AP behavior
- IPv6 leaks

**Example:**
```bash
=== VPN Routing ===
VPN: YES | LocalNet: YES | ServerIP: NO | Other: NO
Verdict: VULNERABLE

=== Malicious AP ===
Status: MALICIOUS
  - Public subnet: 1.2.3.0/24

=== IPv6 Leak ===
Status: LEAK (2001:db8::1 via wlan0)
```

---

## Installation

```bash
# Install dependencies
pip3 install requests dnspython

# Or
sudo apt install python3-requests python3-dnspython iptables iproute2
```

---

## Quick Start

### On Untrusted Network (WiFi, Hotel, Airport)

**Before connecting to VPN:**

```bash
# Option 1: Detect spoofing once
sudo python3 serverip-defense.py
# Select: 2 (Detect DNS Spoofing)

# Option 2: Enforce authenticated DNS (permanent)
sudo python3 serverip-defense.py
# Select: 1 (Enforce Authenticated DNS)
```

**After connecting to VPN:**

```bash
# Apply LocalNet protection
sudo python3 localnet-defense.py --mode filter
```

**Regular monitoring:**

```bash
python3 general-defense.py
```



### DNS Spoofing Attack (ServerIP)

**Attack:**
1. Attacker's AP spoofs DNS
2. VPN hostname resolves to wrong IP
3. Traffic to that IP bypasses VPN tunnel

**Defense:**
- **Detection**: Compare local DNS vs DoH/DoT (encrypted, can't be spoofed)
- **Prevention**: Force all DNS to Google 8.8.8.8 with iptables

### LocalNet Attack

**Attack:**
1. Attacker assigns public IP ranges to "local network"
2. VPN excludes local traffic from tunnel
3. Traffic to those IPs leaks outside VPN

**Defense:**
- Block non-RFC1918 local traffic
- Force all public IPs through VPN tunnel

---

## Restore Everything

```bash
# Restore DNS
sudo python3 restore_dns.py

# Restore routing/firewall
sudo /tmp/restore_tunnelcrack_<pid>.sh
```

---

## Troubleshooting

**"Cannot determine VPN interface"**
```bash
sudo python3 localnet-defense.py --mode filter --vpn-if tun0
```

**"requests library not installed"**
```bash
pip3 install requests dnspython
```

**Can't access local printer/devices**
```bash
# Use filter mode with trusted networks
sudo python3 localnet-defense.py --mode filter --trust "192.168.1.0/24"
```

**DNS not working after enforcement**
```bash
# Restore normal DNS
sudo python3 restore_dns.py
```

---

## Summary

| Tool | Use When | Purpose |
|------|----------|---------|
| `serverip-defense.py` | Before VPN connection | Detect/prevent DNS spoofing |
| `localnet-defense.py` | After VPN connection | Prevent traffic leaks |
| `general-defense.py` | Anytime | Security audit |
| `restore_dns.py` | After using serverip-defense.py option 1 | Restore normal DNS |


---

## References

- Paper: https://papers.mathyvanhoef.com/usenix2023-tunnelcrack.pdf
- Website: https://tunnelcrack.mathyvanhoef.com/

---