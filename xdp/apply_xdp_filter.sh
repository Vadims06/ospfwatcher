#!/bin/sh
ip l set dev ${VTAP_HOST_INTERFACE} xdp off &&
ip l set dev ${VTAP_HOST_INTERFACE} xdp obj xdp_drop.o sec xdp_drop