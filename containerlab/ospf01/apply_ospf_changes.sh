#!/bin/bash
# Applies OSPF changes from README (steps 6.1–6.6) on router6 with delay between steps.
# At the end, runs recovery: cost 6, remove stub 136.6/24, default TE, add 6.6.6.6 route.
# Run with sudo if your system requires it for docker: sudo ./apply_ospf_changes.sh
set -e

CONTAINER="${CONTAINER:-clab-ospf01-router6}"
STEP_DELAY="${STEP_DELAY:-5}"
DOCKER="${DOCKER:-docker}"

run_vtysh() {
  $DOCKER exec "$CONTAINER" vtysh "$@"
}

echo "Target: $CONTAINER, delay between steps: ${STEP_DELAY}s"
echo "---"

echo "[6.1] Change metric on interface eth1..."
run_vtysh -c "configure terminal" -c "interface eth1" -c "ip ospf cost 66"
sleep "$STEP_DELAY"

echo "[6.2] Add new stub network 10.10.136.6/24..."
run_vtysh -c "configure terminal" -c "interface eth1" -c "ip address 10.10.136.6/24"
sleep "$STEP_DELAY"

echo "[6.3] Change TE attributes..."
run_vtysh -c "configure terminal" -c "interface eth1" -c "link-params" \
  -c "metric 100" -c "admin-grp 0xaa" -c "unrsv-bw 0 1e+07" -c "max-bw 2e+08"
sleep "$STEP_DELAY"

echo "[6.4] Remove external type-2 subnet..."
run_vtysh -c "configure terminal" -c "no ip route 6.6.6.6/32 192.168.36.3"
sleep "$STEP_DELAY"

echo "[6.5] Shutdown adjacency (eth1)..."
run_vtysh -c "configure terminal" -c "interface eth1" -c "shutdown"
sleep "$STEP_DELAY"

echo "[6.6] Unshutdown adjacency (eth1)..."
run_vtysh -c "configure terminal" -c "interface eth1" -c "no shutdown"
sleep "$STEP_DELAY"

echo "---"
echo "[Recover] Add 6.6.6.6/32 route..."
run_vtysh -c "configure terminal" -c "ip route 6.6.6.6/32 192.168.36.3"
sleep "$STEP_DELAY"

echo "[Recover] Return OSPF cost on eth1 to default (6)..."
run_vtysh -c "configure terminal" -c "interface eth1" -c "ip ospf cost 6"
sleep "$STEP_DELAY"

echo "[Recover] Delete stub network 10.10.136.6/24..."
run_vtysh -c "configure terminal" -c "interface eth1" -c "no ip address 10.10.136.6/24"
sleep "$STEP_DELAY"

echo "[Recover] Restore TE attributes to default (router6 baseline)..."
run_vtysh -c "configure terminal" -c "interface eth1" -c "link-params" \
  -c "metric 63" -c "admin-grp 0x647a0001" -c "max-bw 1.25e+07" -c "max-bw 1e+08" \
  -c "unrsv-bw 0 1.23e+06" -c "unrsv-bw 5 1.23e+06" -c "exit-link-params"
sleep "$STEP_DELAY"

echo "---"
echo "Done."
