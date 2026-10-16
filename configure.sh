#!/usr/bin/env bash
# Configures and starts OSPF Watcher from its registration in Topolograph:
# the answers from the Add watcher wizard come back with the watcher token.
# Watchers of this checkout share one version, so every one of them is
# rebuilt from its own registration, and only those whose build changed restart.
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
# The path goes into the systemd unit and a sed replacement unquoted
[[ "$checkout" =~ ^[A-Za-z0-9._/-]+$ ]] || { echo "Move the checkout to a path of letters, digits, . _ / and - only: $checkout" >&2; exit 1; }

missing=()
command -v docker >/dev/null 2>&1 || missing+=("docker")
docker compose version >/dev/null 2>&1 || missing+=("docker compose v2")
command -v containerlab >/dev/null 2>&1 || missing+=("containerlab")
command -v curl >/dev/null 2>&1 || missing+=("curl")
command -v git >/dev/null 2>&1 || missing+=("git")
command -v flock >/dev/null 2>&1 || missing+=("flock")
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
    echo "Stop each with: sudo containerlab destroy -t <folder>/config.yml, move it out of this checkout and add it on Topolograph's Watchers page." >&2
    exit 1
fi

version=$(cat VERSION)
# A cloned image can ship an empty machine-id
host_id=$( [ -s /etc/machine-id ] && cat /etc/machine-id || hostname)
ref=$(git describe --tags --exact-match 2>/dev/null || git symbolic-ref -q --short HEAD 2>/dev/null || git rev-parse --short HEAD)
# Two runs would tear down and rebuild the same folders
exec 9> watcher/.configure.lock
flock -n 9 || { echo "Another configure.sh is running in this checkout." >&2; exit 1; }
answers_dir=watcher/.answers
rm -rf "$answers_dir"
mkdir -p "$answers_dir"
chmod 700 "$answers_dir"
torn_down=0
stopping=""
images_ready=0
unit_name=topolograph-ospfwatcher.service
# A lab is up only while every container of its topology runs, so a crashed node counts as down;
# receive_only_filter is one-shot and exits by design
is_lab_running() {
    local node nodes
    nodes=$(awk '/^  nodes:/ {in_nodes=1; next} in_nodes && /^  [^ ]/ {in_nodes=0}
        in_nodes && /^    [^ ]+:/ {node=$1; sub(":", "", node)}
        in_nodes && /^      kind: linux/ && node != "receive_only_filter" {print node}' "watcher/$1/config.yml")
    [ -n "$nodes" ] || return 1
    for node in $nodes; do
        [ -n "$(docker ps -q --filter "name=^$1-$node\$" --filter status=running)" ] || return 1
    done
}
# Fingerprint of the Fluent Bit inputs, which carry tokens and must not be printed
get_inputs_sum() {
    cat fluentbit/watchers/*.yaml 2>/dev/null | cksum || true
}
# Starts what is down and leaves running watchers alone; Fluent Bit restarts only for new inputs.
start_stopped() {
    local folder down=()
    systemctl is-active --quiet "$unit_name" || { systemctl restart "$unit_name"; return; }
    for folder in watcher/watcher[0-9]*/; do
        [ -d "$folder" ] || continue
        [ ! -e "${folder}.pending-stop" ] || continue
        is_lab_running "$(basename "$folder")" || down+=("${folder%/}")
    done
    if [ "$(get_inputs_sum)" != "$fluent_inputs_before" ]; then
        docker compose --profile fluent-bit up -d --force-recreate fluent-bit
    else
        docker compose --profile fluent-bit up -d fluent-bit
    fi
    [ ${#down[@]} -eq 0 ] || onboarding/start.sh "${down[@]}"
}
# Watchers taken down and not yet redeployed come back, also after Ctrl-C or a failed step
on_exit() {
    local status=$?
    # A mirror prefix stays only once its images are pulled
    if [ "$status" -ne 0 ] && [ "$images_ready" -eq 0 ] && [ -f "$checkout/$answers_dir/.env.before" ]; then
        cp "$checkout/$answers_dir/.env.before" "$checkout/.env"
    fi
    rm -rf "$checkout/$answers_dir"
    # An interrupted stop leaves the old folder behind, as a failed one does
    [ -z "$stopping" ] || leave_pending "$stopping"
    rm -rf "$checkout"/watcher/.before.*
    find "$checkout/watcher" -maxdepth 1 -type l -name 'watcher[0-9]*' -delete
    [ "$status" -eq 0 ] || [ "$torn_down" -eq 0 ] || start_stopped
}
fluent_inputs_before=$(get_inputs_sum)
trap on_exit EXIT
trap 'exit 130' INT TERM

# stop_saved <folder>: stops a watcher from its pre-rebuild copy, as its folder may be gone or replaced.
stop_saved() {
    local name=$1 status=0
    # containerlab finds the topology of a running lab by the path it was deployed from
    [ -e "watcher/$name" ] || ln -s ".before.$name" "watcher/$name"
    onboarding/stop.sh "watcher/.before.$name/config.yml" || status=1
    [ ! -L "watcher/$name" ] || rm -f "watcher/$name"
    return $status
}
# leave_pending <folder>: brings the old folder back and marks it, so no replacement of its watcher runs
# before the next configure.sh run has stopped it.
leave_pending() {
    local name=$1 watcher_id replacement
    watcher_id=$(grep -o "watcher_id: '\?[0-9a-f]\{24\}" "watcher/.before.$name/config.yml" | grep -o '[0-9a-f]\{24\}')
    for replacement in watcher/watcher[0-9]*/; do
        [ -n "$watcher_id" ] || break
        if grep -q "watcher_id: '\?$watcher_id" "${replacement}config.yml" 2>/dev/null; then
            rm -rf "$replacement"
        fi
    done
    rm -rf "watcher/$name"
    mv "watcher/.before.$name" "watcher/$name"
    : > "watcher/$name/.pending-stop"
}
# Fluent Bit inputs are copied from the folders that exist, so they never name a folder that is gone
sync_fluent_inputs() {
    local folder
    mkdir -p fluentbit/watchers
    rm -f fluentbit/watchers/*.yaml
    for folder in watcher/watcher[0-9]*/; do
        [ -e "${folder}fluent-bit.yaml" ] || continue
        install -m 600 "${folder}fluent-bit.yaml" "fluentbit/watchers/$(basename "$folder").yaml"
    done
}
# A stop that failed in an earlier run goes first, before the folders change again
for marker in watcher/watcher[0-9]*/.pending-stop; do
    [ -e "$marker" ] || continue
    folder=$(dirname "$marker")
    torn_down=1
    onboarding/stop.sh "$folder/config.yml" || { echo "Cannot stop $folder left from the previous run, fix that and run again." >&2; exit 1; }
    rm -f "$marker"
done

# fetch <token> <file>: the watcher's configuration, or a message and exit status 1.
fetch() {
    local status
    if ! status=$(curl -sS -G -o "$2" -w '%{http_code}' \
            -H "Authorization: Bearer $1" \
            --data-urlencode "host_id=$host_id" \
            --data-urlencode "host_name=$(hostname)" \
            --data-urlencode "ref=$ref" \
            --data-urlencode "watcher_ids=$watcher_ids" \
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

# Every watcher of this checkout comes back in one answer, with its current token or as deleted
watcher_ids=$(grep -ho "watcher_id: '\?[0-9a-f]\{24\}" watcher/watcher[0-9]*/config.yml 2>/dev/null \
    | grep -o '[0-9a-f]\{24\}' | paste -sd, - || true)
echo "Fetching the watcher configuration from ${url%/}"
if ! fetch "$token" "$answers_dir/0.json"; then
    echo "Copy the command again from the watcher page." >&2
    exit 1
fi
# Old GRE watchers need iptables too: their rules go before the new answers apply
if grep -qs '"connection_mode": *"gre"' "$answers_dir"/*.json || grep -qs 'iptables -A' watcher/watcher[0-9]*/config.yml; then
    for tool in iptables conntrack; do
        command -v "$tool" >/dev/null 2>&1 || { echo "Install or fix first: $tool, needed by GRE mode" >&2; exit 1; }
    done
fi

[ -e .env ] || cp .env.template .env
cp .env "$answers_dir/.env.before"
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
registry_prefix=$(grep "^REGISTRY_PREFIX=" .env | cut -d= -f2- || true)
image="${registry_prefix}vadims06/ospf-watcher:${version}"

docker image inspect "$image" >/dev/null 2>&1 || docker pull "$image"
run_client() {
    docker run --rm --user 0:0 -e REGISTRY_PREFIX="$registry_prefix" \
        -v "$checkout":/home/watcher/watcher -w /home/watcher/watcher \
        --entrypoint python3 "$image" client.py "$@"
}
# Every image is local before the running watchers go, so a missing one stops nothing
run_client --action print_images | while read -r pinned; do
    docker image inspect "$pinned" >/dev/null 2>&1 || docker pull "$pinned"
done
docker compose --profile fluent-bit pull --quiet fluent-bit
images_ready=1
# The old config is needed to stop a watcher whose folder the rebuild replaces or renames;
# the copy sits beside the folders because the config reaches ../../.env by relative path
declare -A inode_before
for folder in watcher/watcher[0-9]*/; do
    [ -d "$folder" ] || continue
    inode_before[$(basename "$folder")]=$(stat -c %i "$folder")
    # A copy left by a killed run would take the new one inside it
    rm -rf "watcher/.before.$(basename "$folder")"
    cp -a "$folder" "watcher/.before.$(basename "$folder")"
done

# A watcher whose build is unchanged gets its own folder back, so the same inode marks it to keep running
failed=0
run_client --action add_watcher --answers "$answers_dir/0.json" || failed=1
# A topology left running would keep its interfaces and ports after its folder changes;
# stop.sh also removes the GRE rules containerlab destroy leaves, the deploy adds the current ones back
unstopped=()
for name in "${!inode_before[@]}"; do
    [ "$(stat -c %i "watcher/$name" 2>/dev/null)" != "${inode_before[$name]}" ] || continue
    torn_down=1
    stopping=$name
    stop_saved "$name" || { leave_pending "$name"; unstopped+=("watcher/$name"); }
    stopping=""
done
sync_fluent_inputs
if [ ${#unstopped[@]} -gt 0 ]; then
    echo "Cannot stop ${unstopped[*]}, which stays as it is with nothing new for it. Fix that and run configure.sh again." >&2
    exit 1
fi

unit=/etc/systemd/system/$unit_name
# Replaced in one step, so a failed write never leaves a truncated unit
sed "s|/opt/topolograph/ospfwatcher|$checkout|" onboarding/topolograph-ospfwatcher.service > "$unit.new" && mv "$unit.new" "$unit"
systemctl daemon-reload
systemctl enable topolograph-ospfwatcher.service >/dev/null
echo "Starting the watchers of $checkout"
start_stopped
torn_down=0

[ "$failed" -eq 0 ] || { echo "Some watchers failed to build, see the errors above." >&2; exit 1; }
echo
echo "OSPF Watcher is running. Configure the router as the watcher page shows and follow the status in Topolograph."
