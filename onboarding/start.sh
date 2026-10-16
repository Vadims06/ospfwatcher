#!/usr/bin/env bash
# Deploys every watcher of this checkout and its Fluent Bit. Run at boot by
# topolograph-ospfwatcher.service: the veth, netns and GRE of a containerlab
# topology do not survive a reboot.
# With watcher folders as arguments, only those are deployed and the others keep running.
set -uo pipefail
cd "$(dirname "$0")/.."

status=0
if [ $# -gt 0 ]; then
    # Fluent Bit is left to the caller: a restart is only needed when its inputs changed
    configs=("${@/%//config.yml}")
else
    # Fluent Bit first, so it tails every log before a watcher writes to it
    docker compose --profile fluent-bit up -d --force-recreate fluent-bit || status=1
    configs=(watcher/watcher[0-9]*/config.yml)
fi
for config in "${configs[@]}"; do
    [ -e "$config" ] || continue
    # Its old topology may still run; configure.sh stops it first
    [ ! -e "$(dirname "$config")/.pending-stop" ] || continue
    containerlab deploy --reconfigure -t "$config" || status=1
done
exit $status
