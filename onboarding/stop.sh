#!/usr/bin/env bash
# Takes every watcher of this checkout down, with the host rules a GRE watcher added:
# containerlab destroy leaves those behind. Run on stop by topolograph-ospfwatcher.service.
# With config.yml paths as arguments, only those watchers go and the others keep running.
set -uo pipefail
cd "$(dirname "$0")/.."

status=0
if [ $# -gt 0 ]; then
    for config in "$@"; do
        lab=$(sed -n 's/^name: *//p' "$config")
        # Also a lab that crashed or was stopped by hand: its containers or rules may be left
        containers=$(docker ps -aq --filter "label=containerlab=$lab") || { status=1; continue; }
        if [ -n "$containers" ]; then
            # A topology that stays up keeps its rules
            containerlab destroy -t "$config" || { status=1; continue; }
        fi
        # The rules are taken from the config, so a sibling's rules and flows stay
        while read -r chain rule; do
            # Exit 1 is a missing rule, already gone; any other failure leaves the rule in doubt
            iptables -w -C "$chain" $rule 2>/dev/null
            case $? in
                0) iptables -w -D "$chain" $rule || status=1 ;;
                1) ;;
                *) status=1 ;;
            esac
        done < <(sed -n 's/.*RULE="\([^"]*\)".*iptables -A \([A-Z]*\).*/\2 \1/p' "$config")
        while read -r source destination; do
            conntrack -D -p gre -s "$source" -d "$destination" >/dev/null 2>&1
        done < <(sed -n 's/.*RULE="-t nat .* -s \([0-9.]*\) -d \([0-9.]*\) .*/\1 \2/p' "$config")
    done
    exit $status
fi
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
