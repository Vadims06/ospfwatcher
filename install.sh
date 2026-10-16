#!/bin/sh
# Downloads ospfwatcher at a pinned ref and hands over to configure.sh.
set -eu

REPO_URL=https://github.com/Vadims06/ospfwatcher
INSTALL_DIR=/opt/topolograph/ospfwatcher

usage() {
    echo "Usage: sudo bash install.sh --url <topolograph-url> --token <watcher-token> --ref <tag-or-branch>" >&2
    exit 2
}

url=""
token=""
ref=""
while [ $# -gt 0 ]; do
    case "$1" in
        --url) url="${2:-}"; shift 2 ;;
        --token) token="${2:-}"; shift 2 ;;
        --ref) ref="${2:-}"; shift 2 ;;
        *) usage ;;
    esac
done
[ -n "$url" ] && [ -n "$token" ] && [ -n "$ref" ] || usage
[ "$(id -u)" -eq 0 ] || { echo "Run with sudo." >&2; exit 1; }
command -v git >/dev/null 2>&1 || { echo "Install git first." >&2; exit 1; }

[ -d "$INSTALL_DIR" ] || git clone "$REPO_URL" "$INSTALL_DIR"
cd "$INSTALL_DIR"
git fetch --tags origin "$ref"
git checkout --detach FETCH_HEAD
exec ./configure.sh --url "$url" --token "$token"
