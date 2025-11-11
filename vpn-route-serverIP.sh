#!/usr/bin/env bash

set -euo pipefail

CLIENT_IF="ap0"        
UPLINK_IF="enp2s0"    
IP_A="146.190.62.39"    
IP_B="219.100.37.57"    
VPN_PORT="443"          
MSS_CLAMP=true          


_ipt() { /sbin/iptables "$@"; }
_ipt_del() { _ipt "$@" 2>/dev/null || true; }

# ensure we are root
if [ "$(id -u)" -ne 0 ]; then
  echo "This script must be run as root: sudo $0 $*"
  exit 2
fi

start() {


  sysctl -w net.ipv4.ip_forward=1 >/dev/null

  sysctl -w net.ipv4.conf."$UPLINK_IF".rp_filter=0 >/dev/null || true
  sysctl -w net.ipv4.conf.all.rp_filter=0 >/dev/null || true

  _ipt_del -t nat -D PREROUTING -i "$CLIENT_IF" -p tcp --dport "$VPN_PORT" -d "$IP_A" -j DNAT --to-destination "$IP_B:$VPN_PORT"
  _ipt_del -t nat -D POSTROUTING -o "$UPLINK_IF" -d "$IP_B" -p tcp --dport "$VPN_PORT" -j MASQUERADE
  _ipt_del -D FORWARD -i "$CLIENT_IF" -o "$UPLINK_IF" -p tcp --dport "$VPN_PORT" -d "$IP_B" -m state --state NEW,ESTABLISHED -j ACCEPT
  _ipt_del -D FORWARD -i "$UPLINK_IF" -o "$CLIENT_IF" -p tcp --sport "$VPN_PORT" -s "$IP_B" -m state --state ESTABLISHED -j ACCEPT
  if $MSS_CLAMP; then
    _ipt_del -t mangle -D FORWARD -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu
  fi

  _ipt -t nat -A PREROUTING -i "$CLIENT_IF" -p tcp --dport "$VPN_PORT" -d "$IP_A" -j DNAT --to-destination "$IP_B:$VPN_PORT"

  _ipt -t nat -A POSTROUTING -o "$UPLINK_IF" -d "$IP_B" -p tcp --dport "$VPN_PORT" -j MASQUERADE

  _ipt -A FORWARD -i "$CLIENT_IF" -o "$UPLINK_IF" -p tcp --dport "$VPN_PORT" -d "$IP_B" -m state --state NEW,ESTABLISHED -j ACCEPT
  _ipt -A FORWARD -i "$UPLINK_IF" -o "$CLIENT_IF" -p tcp --sport "$VPN_PORT" -s "$IP_B" -m state --state ESTABLISHED -j ACCEPT

  if $MSS_CLAMP; then
    _ipt -t mangle -A FORWARD -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu
  fi
  
  sudo iptables -t mangle -A PREROUTING -i ap0 -s 192.168.50.0/24 -d 146.190.62.39 -p tcp --dport 443 -j MARK --set-mark 10
  sudo ip rule add fwmark 10 table 100
  sudo ip route add default via 10.8.72.1 dev enp2s0 table 100
  sudo iptables -t nat -A PREROUTING -i ap0 -p tcp -d 146.190.62.39 --dport 443 -j DNAT --to-destination 219.100.37.57:443
  sudo iptables -t nat -A POSTROUTING -o enp2s0 -p tcp -d 219.100.37.57 --dport 443 -j MASQUERADE



  echo
  echo "Current nat table (PREROUTING / POSTROUTING):"
  _ipt -t nat -L -n --line-numbers
  echo
  echo "Current FORWARD chain:"
  _ipt -L FORWARD -n --line-numbers
  echo
  echo "Done.To stop: sudo $0 stop"
}

stop() {
  _ipt_del -t nat -D PREROUTING -i "$CLIENT_IF" -p tcp --dport "$VPN_PORT" -d "$IP_A" -j DNAT --to-destination "$IP_B:$VPN_PORT"
  _ipt_del -t nat -D POSTROUTING -o "$UPLINK_IF" -d "$IP_B" -p tcp --dport "$VPN_PORT" -j MASQUERADE
  _ipt_del -D FORWARD -i "$CLIENT_IF" -o "$UPLINK_IF" -p tcp --dport "$VPN_PORT" -d "$IP_B" -m state --state NEW,ESTABLISHED -j ACCEPT
  _ipt_del -D FORWARD -i "$UPLINK_IF" -o "$CLIENT_IF" -p tcp --sport "$VPN_PORT" -s "$IP_B" -m state --state ESTABLISHED -j ACCEPT
  if $MSS_CLAMP; then
    _ipt_del -t mangle -D FORWARD -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu
  fi

  sysctl -w net.ipv4.conf."$UPLINK_IF".rp_filter=1 >/dev/null || true
  sysctl -w net.ipv4.conf.all.rp_filter=1 >/dev/null || true

  _ipt -t nat -L -n --line-numbers || true
  _ipt -L FORWARD -n --line-numbers || true

  echo "Done."
}

status() {
  echo
  echo "NAT table:"
  _ipt -t nat -L -n --line-numbers
  echo
  echo "FORWARD chain:"
  _ipt -L FORWARD -n --line-numbers
  echo
  echo "conntrack entries for $IP_B (if conntrack installed):"
  command -v conntrack >/dev/null && conntrack -L | grep "$IP_B" || true
}

case "${1:-}" in
  start) start ;;
  stop) stop ;;
  status) status ;;
  *) echo "Usage: $0 {start|stop|status}" ; exit 1 ;;
esac

