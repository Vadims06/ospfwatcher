#!/usr/bin/env bash
# Configures and starts OSPF Watcher from its registration in Topolograph:
# the answers from the Add watcher wizard come back with the watcher token.
# Watchers of this checkout share one version, so every one of them is
# rebuilt from its own registration before anything restarts.
set -euo pipefail

usage() {
    echo "Usage: sudo ./configure.sh --url <topolograph-url> --token <watcher-token>" >&2
    exit 2
}

url=""
token=""
while [ $# -gt 0 ]; do
    case "$1" in
        --url) url="${2:-}"; shift 2 ;;
        --token) token="${2:-}"; shift 2 ;;
        *) usage ;;
    esac
done
[ -n "$url" ] && [ -n "$token" ] || usage
cd "$(dirname "$0")"
checkout=$(pwd)

missing=()
command -v docker >/dev/null 2>&1 || missing+=("docker")
docker compose version >/dev/null 2>&1 || missing+=("docker compose v2")
command -v containerlab >/dev/null 2>&1 || missing+=("containerlab")
command -v curl >/dev/null 2>&1 || missing+=("curl")
command -v git >/dev/null 2>&1 || missing+=("git")
command -v systemctl >/dev/null 2>&1 || missing+=("systemd")
[ "$(id -u)" -eq 0 ] || missing+=("root: run with sudo")
if [ ${#missing[@]} -gt 0 ]; then
    echo "Install or fix first: ${missing[*]}" >&2
    exit 1
fi

unregistered=()
for config in watcher/watcher[0-9]*/config.yml; do
    [ -e "$config" ] || continue
    grep -q "watcher_id:" "$config" || unregistered+=("$(dirname "$config")")
done
if [ ${#unregistered[@]} -gt 0 ]; then
    echo "Installed by hand, so configure.sh cannot rebuild them: ${unregistered[*]}" >&2
    echo "Move them to another checkout first." >&2
    exit 1
fi

version=$(cat VERSION)
host_id=$(cat /etc/machine-id 2>/dev/null || hostname)
ref=$(git describe --tags --exact-match 2>/dev/null || git symbolic-ref -q --short HEAD 2>/dev/null || git rev-parse --short HEAD)
answers_dir=watcher/.answers
rm -rf "$answers_dir"
mkdir -p "$answers_dir"
chmod 700 "$answers_dir"
trap 'rm -rf "$checkout/$answers_dir"' EXIT

# fetch <token> <file>: the watcher's configuration, or a message and exit status 1.
fetch() {
    local status
    if ! status=$(curl -sS -G -o "$2" -w '%{http_code}' \
            -H "Authorization: Bearer $1" \
            --data-urlencode "host_id=$host_id" \
            --data-urlencode "host_name=$(hostname)" \
            --data-urlencode "ref=$ref" \
            "${url%/}/api/watcher/config"); then
        echo "Cannot reach Topolograph at $url" >&2
        return 1
    fi
    case "$status" in
        200) return 0 ;;
        409) echo "Answers missing for the new version: $(cat "$2"). Answer them on the watcher page." >&2 ;;
        *) echo "Topolograph answered $status: $(cat "$2")" >&2 ;;
    esac
    return 1
}

echo "Fetching the watcher configuration from ${url%/}"
if ! fetch "$token" "$answers_dir/0.json"; then
    echo "Copy the command again from the watcher page." >&2
    exit 1
fi
watcher_id=$(grep -o '"watcher_id": *"[0-9a-f]*"' "$answers_dir/0.json" | grep -o '[0-9a-f]\{24\}')

# Every other watcher of this checkout is rebuilt from its own registration.
number=0
for config in watcher/watcher[0-9]*/config.yml; do
    [ -e "$config" ] || continue
    grep -Eq "watcher_id: '?$watcher_id'?$" "$config" && continue
    number=$((number + 1))
    sibling=$(grep -o "TOPOLOGRAPH_API_TOKEN: wt-[A-Za-z0-9]*" "$config" | head -1 | cut -d' ' -f2)
    if ! fetch "$sibling" "$answers_dir/$number.json"; then
        folder=$(dirname "$config")
        echo "$folder belongs to a watcher Topolograph no longer accepts. If it was deleted there, remove it:" >&2
        echo "  sudo containerlab destroy -t $checkout/$config && sudo rm -rf $checkout/$folder $checkout/fluentbit/watchers/$(basename "$folder").yaml" >&2
        exit 1
    fi
done

if grep -qs '"connection_mode": *"gre"' "$answers_dir"/*.json; then
    for tool in iptables conntrack; do
        command -v "$tool" >/dev/null 2>&1 || { echo "Install or fix first: $tool, needed by GRE mode" >&2; exit 1; }
    done
fi

[ -e .env ] || cp .env.template .env
[ -z "$(tail -c1 .env)" ] || echo >> .env
set_env() {
    grep -q "^$1=" .env && sed -i "s|^$1=.*|$1=$2|" .env || echo "$1=$2" >> .env
}
# Values the manifest maps to .env, such as the Docker Hub mirror.
curl -sSf -G -H "Authorization: Bearer $token" --data-urlencode "format=env" \
    "${url%/}/api/watcher/config" > "$answers_dir/env"
while IFS='=' read -r name value; do
    [ -n "$name" ] && set_env "$name" "${value//\'/}"
done < "$answers_dir/env"
set_env WATCHER_VERSION "$version"
set_env FLUENT_BIT_CONFIG onboarding.yaml
# Watchers sign in with their own token, never with a user login.
set_env TOPOLOGRAPH_WEB_API_USERNAME_EMAIL ""
set_env TOPOLOGRAPH_WEB_API_PASSWORD ""
registry_prefix=$(grep "^REGISTRY_PREFIX=" .env | cut -d= -f2- || true)
image="${registry_prefix}vadims06/ospf-watcher:${version}"

# A rebuild can rename a watcher's folder, so every old topology and Fluent Bit
# input goes first; the service below deploys all watchers again.
docker image inspect "$image" >/dev/null 2>&1 || docker pull "$image"
for config in watcher/watcher[0-9]*/config.yml; do
    [ -e "$config" ] || continue
    containerlab destroy -t "$config" >/dev/null 2>&1 || true
done

# One watcher that fails to build must not keep the others down
failed=0
for answer in "$answers_dir"/*.json; do
    docker run --rm --user 0:0 -e REGISTRY_PREFIX="$registry_prefix" \
        -v "$checkout":/home/watcher/watcher -w /home/watcher/watcher \
        --entrypoint python3 "$image" client.py --action add_watcher --answers "$answer" || failed=1
done
# Inputs of folders a rebuild renamed
for input in fluentbit/watchers/*.yaml; do
    [ -e "$input" ] || continue
    [ -d "watcher/$(basename "$input" .yaml)" ] || rm -f "$input"
done

unit=/etc/systemd/system/topolograph-ospfwatcher.service
sed "s|/opt/topolograph/ospfwatcher|$checkout|" onboarding/topolograph-ospfwatcher.service > "$unit"
systemctl daemon-reload
systemctl enable topolograph-ospfwatcher.service >/dev/null
echo "Starting the watchers of $checkout"
systemctl restart topolograph-ospfwatcher.service

[ "$failed" -eq 0 ] || { echo "Some watchers failed to build, see the errors above." >&2; exit 1; }
echo
echo "OSPF Watcher is running. Configure the router as the watcher page shows and follow the status in Topolograph."
