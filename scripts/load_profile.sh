#!/usr/bin/env bash
# Shared runtime profile defaults for singleton venv deployment.

set -euo pipefail

: "${RUNTIME_PROFILE:=auto}"
if [[ "${RUNTIME_PROFILE}" == "auto" ]]; then
    RUNTIME_PROFILE="linux-rpi-venv"
fi

case "${RUNTIME_PROFILE}" in
    linux-rpi-venv)
        : "${NODE_ROLE:=primary}"
        : "${IFACE_AP:=wlan0}"
        : "${IFACE_WAN:=eth0}"
        : "${PORTAL_PORT:=5000}"
        : "${DATA_DIR:=/var/lib/captive-portal}"
        ;;
    windows-venv)
        : "${NODE_ROLE:=primary}"
        : "${PORTAL_PORT:=5000}"
        : "${DATA_DIR:=./data}"
        ;;
    *)
        echo "WARN: Unknown RUNTIME_PROFILE=${RUNTIME_PROFILE}; using existing environment values" >&2
        ;;
esac

export RUNTIME_PROFILE NODE_ROLE IFACE_AP IFACE_WAN PORTAL_PORT DATA_DIR
