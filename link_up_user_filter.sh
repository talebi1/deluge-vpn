#!/usr/bin/env bash

VPNIF="tun0"
NETIF="eth0"
VPNUSER="vpn"
TABLE_ID=42 # Can be any integer 0-253
MARK_ID=0x10 # Any 32bit value

# Get network address from IP and network mask (CIDR)
# E.g. 10.1.2.15 16 -> 10.1.0.0
function getnetmask {
	IP=$1
	PREFIX=$2
	IFS=. read -r i1 i2 i3 i4 <<< $IP
	IFS=. read -r xx m1 m2 m3 m4 <<< $(for a in $(seq 1 32); do if [ $(((a - 1) % 8)) -eq 0 ]; then echo -n .; fi; if [ $a -le $PREFIX ]; then echo -n 1; else echo -n 0; fi; done)
	printf "%d.%d.%d.%d\n" "$((i1 & (2#$m1)))" "$((i2 & (2#$m2)))" "$((i3 & (2#$m3)))" "$((i4 & (2#$m4)))"
}

function get_nic_ip {
	ip addr show $1 | grep -Po '(?<= inet )([0-9\.]+)'
}

function get_nic_subnet_mask {
	ip addr show $1 | grep -Po '(?<= inet )([0-9\.\/]+)' | cut -d "/" -f2
}



VPN_IP=`get_nic_ip $VPNIF`

# Remove old table
ip route flush table $TABLE_ID

# Add rule to use TABLE_ID for marked packets
if [[ `ip rule list | grep -c $MARK_ID` == 0 ]]; then
	ip rule add from all fwmark $MARK_ID lookup $TABLE_ID
fi

ip route replace default via $VPN_IP table $TABLE_ID
ip route append default via 127.0.0.1 dev lo table $TABLE_ID
ip route flush cache

# Set reverse path source validation to lose mode
sysctl -w net.ipv4.conf.all.rp_filter=2
sysctl -w net.ipv4.conf.default.rp_filter=2
sysctl -w net.ipv4.conf.$VPNIF.rp_filter=2


LAN_IP=`get_nic_ip $NETIF`
SUBNET_MASK=`get_nic_subnet_mask $NETIF` # CIDR
LAN_NETWORK=`getnetmask $LAN_IP $SUBNET_MASK`
LAN_NETWORK="$LAN_NETWORK/$SUBNET_MASK" # Should be on the form 172.16.0.0/24

# For multiple ports, separate by comma: 6881,6889
# For port range, seperate by colon: 6881:6889
BITTORRENT_LISTEN_PORTS=6881:6891


DNS_PORT=53
# Use google DNS servers
DNS_IP1=8.8.4.4
DNS_IP2=8.8.8.8

#Remove iprules based on the custom comment we add with the rules.
COMMENT="deluge-vpn"
iptables-save | grep -v "${COMMENT}" | iptables-restore

# Mark packets from $VPNUSER
iptables -t mangle -A OUTPUT ! --dest $LAN_NETWORK  -m owner --uid-owner $VPNUSER -j MARK --set-mark $MARK_ID -m comment --comment "${COMMENT}"
iptables -t mangle -A OUTPUT --dest $LAN_NETWORK -p udp --dport $DNS_PORT -m owner --uid-owner $VPNUSER -j MARK --set-mark $MARK_ID -m comment --comment "${COMMENT}"
iptables -t mangle -A OUTPUT --dest $LAN_NETWORK -p tcp --dport $DNS_PORT -m owner --uid-owner $VPNUSER -j MARK --set-mark $MARK_ID -m comment --comment "${COMMENT}"
iptables -t mangle -A OUTPUT ! --src $LAN_NETWORK -j MARK --set-mark $MARK_ID -m comment --comment "${COMMENT}"

# Allow responses
iptables -A INPUT -i $VPNIF -m conntrack --ctstate ESTABLISHED -j ACCEPT -m comment --comment "${COMMENT}"

# Allow bittorrent
iptables -A INPUT -i $VPNIF -p tcp --match multiport --dport $BITTORRENT_LISTEN_PORTS -j ACCEPT -m comment --comment "${COMMENT}"
iptables -A INPUT -i $VPNIF -p udp --match multiport --dport $BITTORRENT_LISTEN_PORTS -j ACCEPT -m comment --comment "${COMMENT}"

# Block everything incoming on $VPNIF
iptables -A INPUT -i $VPNIF -j REJECT -m comment --comment "${COMMENT}"

# Set DNS for $VPNUSER
iptables -t nat -A OUTPUT --dest $LAN_NETWORK -p udp --dport $DNS_PORT -m owner --uid-owner $VPNUSER -j DNAT --to-destination $DNS_IP1 -m comment --comment "${COMMENT}"
iptables -t nat -A OUTPUT --dest $LAN_NETWORK -p tcp --dport $DNS_PORT -m owner --uid-owner $VPNUSER -j DNAT --to-destination $DNS_IP1 -m comment --comment "${COMMENT}"
iptables -t nat -A OUTPUT --dest $LAN_NETWORK -p udp --dport $DNS_PORT -m owner --uid-owner $VPNUSER -j DNAT --to-destination $DNS_IP2 -m comment --comment "${COMMENT}"
iptables -t nat -A OUTPUT --dest $LAN_NETWORK -p tcp --dport $DNS_PORT -m owner --uid-owner $VPNUSER -j DNAT --to-destination $DNS_IP2 -m comment --comment "${COMMENT}"

# Let $VPNUSER access lo and $VPNIF
iptables -A OUTPUT -o lo -m owner --uid-owner $VPNUSER -j ACCEPT -m comment --comment "${COMMENT}"
iptables -A OUTPUT -o $VPNIF -m owner --uid-owner $VPNUSER -j ACCEPT -m comment --comment "${COMMENT}"

# All packets on $VPNIF needs to be masqueraded
iptables -t nat -A POSTROUTING -o $VPNIF -j MASQUERADE -m comment --comment "${COMMENT}"

# Reject connections from predator ip going over $NETIF
iptables -A OUTPUT ! --src $LAN_NETWORK -o $NETIF -j REJECT -m comment --comment "${COMMENT}"
