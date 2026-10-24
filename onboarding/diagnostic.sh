#!/usr/bin/env bash
# Runs the watcher diagnostic with the host's iptables rules: the watcher image has no iptables binary.
# Usage, as root: onboarding/diagnostic.sh <watcher_num>
set -euo pipefail
cd "$(dirname "$0")/.."

if [ $# -ne 1 ]; then
    echo "usage: $0 <watcher_num>" >&2
    exit 2
fi
registry_prefix=$(grep "^REGISTRY_PREFIX=" .env 2>/dev/null | cut -d= -f2- || true)
image="${registry_prefix}vadims06/ospf-watcher:$(cat VERSION)"

iptables-save -c | docker run -i --rm \
    -v "$(pwd)":/home/watcher/watcher/ \
    --network host \
    "$image" diagnostic --watcher_num "$1" --iptables-save -
