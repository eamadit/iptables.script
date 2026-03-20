#!/bin/bash
iptables -F
ip6tables -F

iptables -A SSHBRUTE -m recent --name SSH --set --rsource
iptables -A SSHBRUTE -m recent --name SSH --update --seconds 300 --hitcount 10 --rsource --rttl -m limit --limit 1/sec --limit-burst 100 -j DROP
iptables -A SSHBRUTE -m recent --name SSH --update --seconds 300 --hitcount 10 --rsource --rttl -j DROP
#$IP4TABLES -A SSHBRUTE -j ACCEPT

iptables -A INPUT -p tcp ! --syn -m state --state NEW -j DROP
iptables -A FORWARD -p tcp ! --syn -m state --state NEW -j DROP

iptables -A INPUT -m state --state INVALID -j DROP
iptables -A FORWARD -m state --state INVALID -j DROP

iptables -A INPUT -p tcp -m tcp --tcp-flags FIN,SYN,RST,PSH,ACK,URG NONE -j DROP
iptables -A INPUT -p tcp -m tcp --tcp-flags SYN,FIN SYN,FIN -j DROP
iptables -A INPUT -p tcp -m tcp --tcp-flags SYN,RST SYN,RST -j DROP
iptables -A INPUT -p tcp -m tcp --tcp-flags FIN,RST FIN,RST -j DROP
iptables -A INPUT -p tcp -m tcp --tcp-flags ACK,FIN FIN -j DROP
iptables -A INPUT -p tcp -m tcp --tcp-flags ACK,URG URG -j DROP

iptables -A INPUT -m recent --name PORTSCAN --rcheck --seconds 86400 -j DROP
iptables -A FORWARD -m recent --name PORTSCAN --rcheck --seconds 86400 -j DROP
iptables -A INPUT -m recent --name PORTSCAN --remove
iptables -A FORWARD -m recent --name PORTSCAN --remove

ip6tables -P INPUT DROP
ip6tables -P OUTPUT DROP
ip6tables -P FORWARD DROP
iptables -P FORWARD DROP
iptables -P INPUT DROP
iptables -P OUTPUT DROP
iptables -A OUTPUT -p icmp -j ACCEPT
iptables -A OUTPUT -p tcp --dport 443 -j ACCEPT
iptables -A OUTPUT -p udp --dport 53 -j ACCEPT
iptables -A OUTPUT -p tcp --dport 80 -j ACCEPT
iptables -A OUTPUT -p tcp --dport 853 -j ACCEPT
iptables -A INPUT -p tcp -m state --state RELATED,ESTABLISHED -j ACCEPT
iptables -A INPUT -p udp -m state --state RELATED,ESTABLISHED -j ACCEPT
iptables -A INPUT -p icmp -m state --state RELATED,ESTABLISHED -j ACCEPT
iptables -A INPUT -i lo -j ACCEPT
iptables -A OUTPUT -o lo -j ACCEPT


iptables -L



#thank you https://gist.github.com/f1r-CTLF/3174f9f8ddc1edb37e03
