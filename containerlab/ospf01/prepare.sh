#!/bin/bash

set -euo pipefail

# Base folder where the lab lives
LAB_DIR="$(dirname "$0")"
LOG_DIR="$LAB_DIR/watcher/logs"
LOG_FILE="$LOG_DIR/watcher1.ospf.log"
BRIDGE_NAME="br-dr"
OWNER="systemd-network:systemd-journal"

create_log_file() {
    mkdir -p "$LOG_DIR"

    # Create or truncate the log file and set ownership
    install -o "${OWNER%%:*}" -g "${OWNER##*:}" -m 644 /dev/null "$LOG_FILE"
    echo "[$(date)] Log file initialized at $LOG_FILE"
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
    setup_bridge
}

main