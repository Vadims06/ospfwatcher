#!/bin/bash

set -euo pipefail

# Base folder where the lab lives
LAB_DIR="$(dirname "$0")"
LOG_DIR="$LAB_DIR/watcher/logs"
LOG_FILE="$LOG_DIR/watcher1.ospf.log"
BRIDGE_NAME="br-dr"
# Own the log dir/file as the host user that runs the lab, so the log can be
# rotated/truncated on each run without a manual chmod. The watcher container runs
# as root and can still write regardless of owner.
OWNER="$(stat -c '%U:%G' "$LAB_DIR")"

create_log_file() {
    mkdir -p "$LOG_DIR"

    # Dir must be writable by OWNER so the stale log can be removed on each run.
    chown "$OWNER" "$LOG_DIR"
    chmod 775 "$LOG_DIR"

    # Create or truncate the log file owned by OWNER (group/other writable for the
    # root-running container's bind-mount writes).
    install -o "${OWNER%%:*}" -g "${OWNER##*:}" -m 664 /dev/null "$LOG_FILE"
    echo "[$(date)] Log file initialized at $LOG_FILE (owner $OWNER)"
}

ensure_brctl_installed() {
    if ! command -v brctl &>/dev/null; then
        echo "[$(date)] brctl not found, installing bridge-utils..."

        if [ -f /etc/debian_version ]; then
            sudo apt-get update
            sudo apt-get install -y bridge-utils
        elif [ -f /etc/redhat-release ]; then
            sudo yum install -y bridge-utils
        else
            echo "[$(date)] Unsupported OS. Please install 'bridge-utils' manually." >&2
            exit 1
        fi

        echo "[$(date)] bridge-utils installed."
    fi
}

ensure_mpls_modules() {
    echo "[$(date)] Loading MPLS kernel modules (required for OSPF TE / opaque-area LSAs)"
    sudo modprobe mpls_router
    sudo modprobe mpls_iptunnel
    sudo modprobe mpls_gso
}

setup_bridge() {
    if ! ip link show "$BRIDGE_NAME" &>/dev/null; then
        echo "[$(date)] Creating bridge: $BRIDGE_NAME"
        sudo brctl addbr "$BRIDGE_NAME"
        sudo ip link set up dev "$BRIDGE_NAME"
    else
        echo "[$(date)] Bridge $BRIDGE_NAME already exists"
    fi
}

main() {
    create_log_file
    ensure_brctl_installed
    ensure_mpls_modules
    setup_bridge
}

main