#!/bin/sh
# Run before Docker starts, so automatic container restarts cannot precede the policy.
set -eu
[ "$(id -u)" = 0 ] || { echo 'Run as root on the platform host' >&2; exit 1; }
for tool in iptables iptables-restore getent awk sort modprobe sysctl; do command -v "$tool" >/dev/null; done
# Same-bridge traffic must traverse the filter, including after a host reboot.
modprobe br_netfilter
sysctl -q -w net.bridge.bridge-nf-call-iptables=1
[ "$(sysctl -n net.bridge.bridge-nf-call-iptables)" = 1 ]
rules=$(mktemp)
trap 'rm -f -- "$rules"' EXIT HUP INT TERM
# Resolve operator-approved integration hosts before opening an atomic rules transaction.
{
 printf '%s\n' '*filter' ':VULNETIC-GATEWAY - [0:0]' ':VULNETIC-CORE - [0:0]' '-F VULNETIC-GATEWAY' '-F VULNETIC-CORE'
 printf '%s\n' '-A VULNETIC-GATEWAY -m conntrack --ctstate ESTABLISHED,RELATED -j RETURN' '-A VULNETIC-GATEWAY -j DROP'
 printf '%s\n' '-A VULNETIC-CORE -m conntrack --ctstate ESTABLISHED,RELATED -j RETURN'
 printf '%s\n' '-A VULNETIC-CORE -d 172.30.242.3 -p tcp --dport 5432 -j RETURN' '-A VULNETIC-CORE -d 172.30.241.3 -p tcp --dport 8789 -j RETURN' '-A VULNETIC-CORE -d 172.30.240.4 -p tcp --dport 8788 -j RETURN'
 for host in api.osv.dev services.nvd.nist.gov api.first.org www.cisa.gov; do
  getent ahostsv4 "$host" | awk '{print $1}' | sort -u | while read -r address; do
   printf '%s\n' "-A VULNETIC-CORE -d $address -p tcp --dport 443 -j RETURN"
  done
 done
 printf '%s\n' '-A VULNETIC-CORE -j DROP' 'COMMIT'
} > "$rules"
iptables-restore --wait 10 --noflush < "$rules"
iptables -w -N DOCKER-USER 2>/dev/null || true
for source in 172.30.240.4 172.30.241.3; do
 for parent in DOCKER-USER INPUT; do
  iptables -w -C "$parent" -s "$source" -j VULNETIC-GATEWAY 2>/dev/null || iptables -w -I "$parent" 1 -s "$source" -j VULNETIC-GATEWAY
 done
done
for source in 172.30.240.3 172.30.241.2 172.30.242.2; do
 for parent in DOCKER-USER INPUT; do
  iptables -w -C "$parent" -s "$source" -j VULNETIC-CORE 2>/dev/null || iptables -w -I "$parent" 1 -s "$source" -j VULNETIC-CORE
 done
done
# The operator creates this marker only after validating both public tunnel routes.
if [ -f /etc/vulnetic/origin-web-closed ]; then
 for firewall in iptables ip6tables; do
  $firewall -w -C INPUT -p tcp -m multiport --dports 80,443 -j DROP 2>/dev/null || $firewall -w -I INPUT 1 -p tcp -m multiport --dports 80,443 -j DROP
 done
fi
# The three protected Compose networks have IPv6 disabled. This does not alter host SSH or public ingress.
echo 'Vulnetic container network restrictions installed.'
