#!/usr/bin/env bash
# Takes every watcher of this checkout down, with the host rules a GRE watcher added:
# containerlab destroy leaves those behind. Run on stop by topolograph-ospfwatcher.service.
set -uo pipefail
cd "$(dirname "$0")/.."

status=0
registry_prefix=$(grep "^REGISTRY_PREFIX=" .env 2>/dev/null | cut -d= -f2- || true)
# The rules are listed from the topology configs, so they go before the topologies
docker run --rm --user 0:0 -e REGISTRY_PREFIX="$registry_prefix" \
    -v "$PWD":/home/watcher/watcher -w /home/watcher/watcher \
    --entrypoint python3 "${registry_prefix}vadims06/ospf-watcher:$(cat VERSION)" client.py --action print_gre_cleanup \
    | bash || status=1
for config in watcher/watcher[0-9]*/config.yml; do
    [ -e "$config" ] || continue
    containerlab destroy -t "$config" || status=1
done
docker compose --profile fluent-bit stop fluent-bit || status=1
exit $status
