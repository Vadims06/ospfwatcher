#!/usr/bin/env bash
# Deploys every watcher of this checkout and its Fluent Bit. Run at boot by
# topolograph-ospfwatcher.service: the veth, netns and GRE of a containerlab
# topology do not survive a reboot.
set -uo pipefail
cd "$(dirname "$0")/.."

status=0
for config in watcher/watcher[0-9]*/config.yml; do
    [ -e "$config" ] || continue
    containerlab deploy --reconfigure -t "$config" || status=1
done
docker compose --profile fluent-bit up -d --force-recreate fluent-bit || status=1
exit $status
