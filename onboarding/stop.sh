#!/usr/bin/env bash
# Takes every watcher of this checkout down, with the host rules a GRE watcher added:
# containerlab destroy leaves those behind. Run on stop by topolograph-ospfwatcher.service.
set -uo pipefail
cd "$(dirname "$0")/.."

status=0
# Found by their comment, so a stop after a Docker crash still removes them
for table in nat filter; do
    rules=$(iptables -w -t "$table" -S) || { status=1; continue; }
    while read -r rule; do
        eval iptables -w -t "$table" "$rule" || status=1
    done < <(grep -- "--comment topolograph-ospfwatcher" <<<"$rules" | sed 's/^-A /-D /')
    [ "$table" = nat ] || continue
    # A GRE flow keeps its NAT after the rule goes, steering router packets to a removed watcher
    while read -r source destination; do
        conntrack -D -p gre -s "$source" -d "$destination" >/dev/null 2>&1
    done < <(grep -- "--comment topolograph-ospfwatcher" <<<"$rules" | sed -n 's|^-A [A-Z]* -s \([0-9.]*\)/32 -d \([0-9.]*\)/32 .*|\1 \2|p')
done
for config in watcher/watcher[0-9]*/config.yml; do
    [ -e "$config" ] || continue
    containerlab destroy -t "$config" || status=1
done
docker compose --profile fluent-bit stop fluent-bit || status=1
exit $status
