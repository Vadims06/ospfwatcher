#!/bin/sh
# Runs inside the FRR network namespace; ROUTER_ID, TUNNEL_NET, TUNNEL_MASK come from the lab file.
set -e
ip_to_int() {
    IFS=. read -r a b c d <<EOF2
$1
EOF2
    echo $(( (a << 24) | (b << 16) | (c << 8) | d ))
}
clang -O2 -target bpf -I/usr/include \
    -DROUTER_ID="$(ip_to_int "$ROUTER_ID")"U \
    -DTUNNEL_NET="$(ip_to_int "$TUNNEL_NET")"U \
    -DTUNNEL_MASK="$(ip_to_int "$TUNNEL_MASK")"U \
    -c announcement_filter.c -o announcement_filter.o
tc qdisc replace dev "$FILTER_INTERFACE" clsact
tc filter replace dev "$FILTER_INTERFACE" egress bpf direct-action obj announcement_filter.o sec tc
