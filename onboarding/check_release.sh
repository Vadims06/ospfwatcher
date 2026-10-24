#!/bin/sh
# Stops a release whose version files disagree or whose pinned images are missing from Docker Hub.
# Usage: check_release.sh [tag]. With a tag the images must exist, which needs network access.
set -u
cd "$(dirname "$0")/.."
tag=${1:-}
version=$(cat VERSION)
watcher_image=vadims06/ospf-watcher:$version
status=0

fail() {
    echo "::error::$1"
    status=1
}

grep -qx "WATCHER_VERSION=$version" .env.template || fail ".env.template WATCHER_VERSION differs from VERSION $version"
[ -z "$tag" ] || [ "$tag" = "$version" ] || fail "tag $tag differs from VERSION $version"

# Services built locally have no registry image to check. Each step is captured on its own so a failure shows.
compose_json=$(WATCHER_VERSION=$version docker compose --profile '*' config --format json) || fail "docker compose config failed"
images=$(printf '%s' "$compose_json" | jq -r '.services[] | select(has("build") | not) | .image') || fail "reading the compose images failed"
images="$images
$watcher_image"

# check_pin <image>: an explicit tag, and Docker Hub only so one mirror prefix serves every image
check_pin() {
    case "${1##*/}" in
        *:*) ;;
        *) fail "$1: pin an explicit tag"; return ;;
    esac
    [ "${1##*:}" != latest ] || fail "$1: pin an explicit tag"
    case "$1" in
        */*) case "${1%%/*}" in *.*|*:*) fail "$1: only Docker Hub images, so one mirror prefix serves them all" ;; esac ;;
    esac
}

# is_published <image>
is_published() {
    name=${1%:*}
    case "$name" in */*) ;; *) name=library/$name ;; esac
    curl -fsS --max-time 20 -o /dev/null "https://hub.docker.com/v2/repositories/$name/tags/${1##*:}"
}

if [ -n "$tag" ]; then
    # The published watcher image lists every image it pins, including those this repo does not name
    if is_published "$watcher_image"; then
        pinned=$(docker run --rm -v "$PWD:/work" -w /work "$watcher_image" print-images) || fail "$watcher_image print-images failed"
        images="$images
$pinned"
    fi
fi

for image in $(echo "$images" | sort -u); do
    check_pin "$image"
    [ -z "$tag" ] || is_published "$image" || fail "$image is not published on Docker Hub"
done
exit $status
