#!/bin/sh
# Runs inside the FRR network namespace; ROUTER_ID, TUNNEL_NETWORK, TUNNEL_PREFIX_LEN come from the lab file.
# gre1 is brought up only after the filter is attached, so a failure leaves the adjacency down.
set -eu
ip_to_int() {
    IFS=. read -r a b c d <<EOF2
$1
EOF2
    echo $(( (a << 24) | (b << 16) | (c << 8) | d ))
}
TUNNEL_MASK=$(( (0xFFFFFFFF << (32 - TUNNEL_PREFIX_LEN)) & 0xFFFFFFFF ))
clang -O2 -target bpf -I/usr/include \
    -DROUTER_ID="$(ip_to_int "$ROUTER_ID")"U \
    -DTUNNEL_NET="$(ip_to_int "$TUNNEL_NETWORK")"U \
    -DTUNNEL_MASK="${TUNNEL_MASK}"U \
    -c announcement_filter.c -o announcement_filter.o
for _ in $(seq 30); do
    ip link show dev "$FILTER_INTERFACE" >/dev/null 2>&1 && break
    sleep 1
done
tc qdisc replace dev "$FILTER_INTERFACE" clsact
tc filter replace dev "$FILTER_INTERFACE" egress bpf direct-action obj announcement_filter.o sec tc
ip link set up dev "$FILTER_INTERFACE"
