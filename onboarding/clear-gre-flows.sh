#!/usr/bin/env bash
# Drops the tracked GRE flows of the given watcher configs. A flow keeps the NAT
# it was created with: one opened before the watcher's rules existed bypasses them,
# one opened before a stop keeps steering router packets to a removed watcher.
set -uo pipefail
for config in "$@"; do
    while read -r source destination; do
        conntrack -D -p gre -s "$source" -d "$destination" >/dev/null 2>&1
    done < <(sed -n 's/.*RULE="-t nat .* -s \([0-9.]*\) -d \([0-9.]*\) .*/\1 \2/p' "$config")
done
exit 0
