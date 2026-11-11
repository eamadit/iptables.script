#!/bin/bash
#if you are looking for a hardened firewall for macOS use this link: https://github.com/eamadit/pf.conf
#!/bin/bash
set -euo pipefail

# ==============================================================================
# 1. KERNEL NETWORK HARDENING (sysctl)
# ==============================================================================
# Reverse Path Filtering (blocks IP spoofing)
sysctl -w net.ipv4.conf.all.rp_filter=1 >/dev/null
sysctl -w net.ipv4.conf.default.rp_filter=1 >/dev/null

# Disable ICMP redirects (prevents Man-in-the-Middle route injection)
sysctl -w net.ipv4.conf.all.accept_redirects=0 >/dev/null
sysctl -w net.ipv4.conf.default.accept_redirects=0 >/dev/null
sysctl -w net.ipv4.conf.all.secure_redirects=0 >/dev/null
sysctl -w net.ipv4.conf.all.send_redirects=0 >/dev/null
sysctl -w net.ipv6.conf.all.accept_redirects=0 >/dev/null

# Ignore broadcast pings & bogus ICMP errors (prevents Smurf attacks & log floods)
sysctl -w net.ipv4.icmp_echo_ignore_broadcasts=1 >/dev/null
sysctl -w net.ipv4.icmp_ignore_bogus_error_responses=1 >/dev/null

# Disable source-routed packets (prevents routing bypasses)
sysctl -w net.ipv4.conf.all.accept_source_route=0 >/dev/null
sysctl -w net.ipv6.conf.all.accept_source_route=0 >/dev/null

# Enable TCP SYN Cookies & RFC 1337 TIME-WAIT assassination protection
sysctl -w net.ipv4.tcp_syncookies=1 >/dev/null
sysctl -w net.ipv4.tcp_rfc1337=1 >/dev/null

# Disable IP forwarding completely
sysctl -w net.ipv4.ip_forward=0 >/dev/null
sysctl -w net.ipv6.conf.all.forwarding=0 >/dev/null

# Disable IPv6 at the kernel stack level for total leak immunity
sysctl -w net.ipv6.conf.all.disable_ipv6=1 >/dev/null
sysctl -w net.ipv6.conf.default.disable_ipv6=1 >/dev/null

# ==============================================================================
# 2. DEFAULT-DENY POLICIES FIRST (Zero race-condition window)
# ==============================================================================
iptables -P INPUT DROP
iptables -P FORWARD DROP
iptables -P OUTPUT DROP

ip6tables -P INPUT DROP
ip6tables -P FORWARD DROP
ip6tables -P OUTPUT DROP

# ==============================================================================
# 3. FLUSH ALL TABLES & CUSTOM CHAINS
# ==============================================================================
for table in filter nat mangle raw security; do
    iptables -t "$table" -F
    iptables -t "$table" -X
done

ip6tables -F
ip6tables -X

# ==============================================================================
# 4. APPLICATION FIREWALL: "no-internet" GROUP (Top of OUTPUT)
# ==============================================================================
# Usage:
#   sudo groupadd no-internet
#   sg no-internet -c "/f1/firefox/firefox --no-remote -P offline"
#
# Optional: Uncomment ONLY if your isolated app crashes without localhost IPC
# (Warning: leaving this commented prevents local proxy/Tor pivots)
# iptables -A OUTPUT -m owner --gid-owner no-internet -d 127.0.0.0/8 -j ACCEPT

# Drop 100% of outbound traffic for the no-internet group
iptables -A OUTPUT -m owner --gid-owner no-internet -j DROP

# ==============================================================================
# 5. INPUT CHAIN (Strict Anti-Spoofing & Stateful Filtering)
# ==============================================================================
# Trust local loopback interface
iptables -A INPUT -i lo -j ACCEPT

# Drop external packets claiming to come from localhost (127.0.0.0/8)
iptables -A INPUT ! -i lo -s 127.0.0.0/8 -j DROP

# Drop malformed / out-of-state packets immediately
iptables -A INPUT -m conntrack --ctstate INVALID -j DROP

# Drop Bogon / Martian source IPs on public interfaces (optional: comment out if
# you are behind a standard home router using 192.168.x.x or 10.x.x.x!)
# iptables -A INPUT ! -i lo -s 0.0.0.0/8 -j DROP
# iptables -A INPUT ! -i lo -s 169.254.0.0/16 -j DROP

# Allow inbound replies to connections you initiated
iptables -A INPUT -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT

# Rate-limited logging of dropped unsolicited INPUT packets (max 3/min)
iptables -A INPUT -m limit --limit 3/min --limit-burst 5 -j LOG --log-prefix "[FW-IN-DROP] " --log-level 4

# ==============================================================================
# 6. OUTPUT CHAIN (Tight Egress, Anti-Tunneling & Audit Logging)
# ==============================================================================
# Trust local loopback interface
iptables -A OUTPUT -o lo -j ACCEPT

# Drop invalid outbound packets
iptables -A OUTPUT -m conntrack --ctstate INVALID -j DROP

# Allow packets belonging to already-established connections
iptables -A OUTPUT -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT

# DHCP lease renewals (UDP 68 -> 67)
iptables -A OUTPUT -p udp --sport 68 --dport 67 -j ACCEPT

# DNS (UDP + TCP 53)
iptables -A OUTPUT -p udp --dport 53 -m conntrack --ctstate NEW -j ACCEPT
iptables -A OUTPUT -p tcp --dport 53 -m conntrack --ctstate NEW -j ACCEPT

# NTP Time Sync (UDP 123 - keeps TLS/HTTPS certificates valid)
iptables -A OUTPUT -p udp --dport 123 -m conntrack --ctstate NEW -j ACCEPT

# Web (HTTP 80 / HTTPS 443)
iptables -A OUTPUT -p tcp --dport 80 -m conntrack --ctstate NEW -j ACCEPT
iptables -A OUTPUT -p tcp --dport 443 -m conntrack --ctstate NEW -j ACCEPT

# Email (IMAPS 993 / Submission 587)
iptables -A OUTPUT -p tcp --dport 993 -m conntrack --ctstate NEW -j ACCEPT
iptables -A OUTPUT -p tcp --dport 587 -m conntrack --ctstate NEW -j ACCEPT

# Outbound Ping: Rate-limited & capped at 84 bytes (blocks ICMP data tunneling!)
iptables -A OUTPUT -p icmp --icmp-type echo-request -m length --length 28:84 -m limit --limit 2/sec --limit-burst 5 -m conntrack --ctstate NEW -j ACCEPT

# Rate-limited logging of blocked outbound apps/ports (helps catch malware/leaks)
iptables -A OUTPUT -m limit --limit 5/min --limit-burst 10 -j LOG --log-prefix "[FW-OUT-DROP] " --log-level 4

# ==============================================================================
# 7. VERIFY ACTIVE RULES
# ==============================================================================
iptables -L -v -n --line-numbers
