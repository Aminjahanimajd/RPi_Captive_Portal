#!/usr/bin/env bash
# =============================================================================
# mount_secure_fs.sh — Federated LUKS Partition Management
# =============================================================================
#
# This script manages the lifecycle of the encrypted secure partition on a
# Raspberry Pi node.  It is called by the federation agent after the master
# key has been reconstructed from neighbour key shards.
#
# Partition layout assumed:
#   /dev/mmcblk0p3  — LUKS-encrypted secure partition
#   /mnt/secure     — mount point
#
# Key lifecycle:
#   1. On first boot: generate master key and split into N shards.
#      Distribute shards to neighbours via the federation API.
#   2. On subsequent boots: collect shards from neighbours, reconstruct key,
#      open LUKS partition, mount it.
#   3. On shutdown: unmount and close the LUKS mapper device.
#
# Usage:
#   sudo bash mount_secure_fs.sh create   # First-time LUKS partition setup
#   sudo bash mount_secure_fs.sh open     # Open and mount (called at boot)
#   sudo bash mount_secure_fs.sh close    # Unmount and close (called at shutdown)
#   sudo bash mount_secure_fs.sh status   # Show current status
# =============================================================================

set -euo pipefail

DEVICE="/dev/mmcblk0p3"
MAPPER_NAME="secure_partition"
MOUNT_POINT="/mnt/secure"
KEY_FILE_TMPFS="/run/master.key"   # tmpfs — never touches persistent storage

# ── Helpers ──────────────────────────────────────────────────────────────────

check_root() {
    [[ "${EUID}" -eq 0 ]] || { echo "ERROR: Run as root."; exit 1; }
}

require_cmd() {
    command -v "$1" &>/dev/null || { echo "ERROR: '$1' not found. Install cryptsetup."; exit 1; }
}

# ── create: initialise a new LUKS-encrypted partition ────────────────────────

cmd_create() {
    check_root
    require_cmd cryptsetup

    echo "==> WARNING: This will ERASE all data on ${DEVICE}."
    read -rp "Type YES to continue: " confirm
    [[ "${confirm}" == "YES" ]] || { echo "Aborted."; exit 0; }

    # Generate and temporarily store master key
    python3 -c "
import secrets, os, pathlib
key = secrets.token_bytes(32)
pathlib.Path('/run').mkdir(exist_ok=True)
with open('${KEY_FILE_TMPFS}', 'wb') as f:
    f.write(key)
os.chmod('${KEY_FILE_TMPFS}', 0o600)
print(f'Master key written to ${KEY_FILE_TMPFS} ({len(key)} bytes)')
"

    # Format partition with LUKS
    cryptsetup luksFormat --type luks2 \
        --cipher aes-xts-plain64 --key-size 512 --hash sha256 \
        --key-file "${KEY_FILE_TMPFS}" "${DEVICE}"

    echo "==> Opening LUKS device..."
    cryptsetup luksOpen "${DEVICE}" "${MAPPER_NAME}" --key-file "${KEY_FILE_TMPFS}"

    echo "==> Creating ext4 filesystem..."
    mkfs.ext4 "/dev/mapper/${MAPPER_NAME}"

    mkdir -p "${MOUNT_POINT}"
    mount "/dev/mapper/${MAPPER_NAME}" "${MOUNT_POINT}"
    chmod 750 "${MOUNT_POINT}"

    echo "✓ Secure partition created and mounted at ${MOUNT_POINT}"
    echo ""
    echo "IMPORTANT: The master key is in ${KEY_FILE_TMPFS} (tmpfs only)."
    echo "The federation agent will split and distribute this key to neighbours."
    echo "After distribution the key file will be wiped from tmpfs on next reboot."
}

# ── open: reconstruct key and mount ──────────────────────────────────────────

cmd_open() {
    check_root
    require_cmd cryptsetup

    if mountpoint -q "${MOUNT_POINT}"; then
        echo "Secure partition is already mounted at ${MOUNT_POINT}."
        exit 0
    fi

    # The federation agent writes the reconstructed key to KEY_FILE_TMPFS
    if [[ ! -f "${KEY_FILE_TMPFS}" ]]; then
        echo "ERROR: Master key not found at ${KEY_FILE_TMPFS}."
        echo "Federation bootstrap must complete before mounting."
        exit 1
    fi

    echo "==> Opening LUKS partition..."
    cryptsetup luksOpen "${DEVICE}" "${MAPPER_NAME}" --key-file "${KEY_FILE_TMPFS}"

    mkdir -p "${MOUNT_POINT}"
    echo "==> Mounting /dev/mapper/${MAPPER_NAME} → ${MOUNT_POINT}..."
    mount "/dev/mapper/${MAPPER_NAME}" "${MOUNT_POINT}"

    # Wipe key from tmpfs now that the partition is open
    shred -u "${KEY_FILE_TMPFS}"
    echo "==> Key file wiped from tmpfs."

    echo "✓ Secure partition mounted at ${MOUNT_POINT}"
}

# ── close: unmount and lock ───────────────────────────────────────────────────

cmd_close() {
    check_root
    require_cmd cryptsetup

    if mountpoint -q "${MOUNT_POINT}"; then
        echo "==> Unmounting ${MOUNT_POINT}..."
        umount "${MOUNT_POINT}"
    fi

    if cryptsetup status "${MAPPER_NAME}" &>/dev/null; then
        echo "==> Closing LUKS device..."
        cryptsetup luksClose "${MAPPER_NAME}"
    fi

    echo "✓ Secure partition closed."
}

# ── status ────────────────────────────────────────────────────────────────────

cmd_status() {
    echo "── Secure Partition Status ──────────────────────────────"
    echo "Device    : ${DEVICE}"
    echo "Mapper    : /dev/mapper/${MAPPER_NAME}"
    echo "Mount     : ${MOUNT_POINT}"
    echo ""

    if cryptsetup status "${MAPPER_NAME}" &>/dev/null; then
        echo "LUKS      : OPEN"
    else
        echo "LUKS      : CLOSED"
    fi

    if mountpoint -q "${MOUNT_POINT}"; then
        echo "Mount     : ACTIVE"
        df -h "${MOUNT_POINT}"
    else
        echo "Mount     : INACTIVE"
    fi
    echo "─────────────────────────────────────────────────────────"
}

# ── Entry point ───────────────────────────────────────────────────────────────

case "${1:-status}" in
    create) cmd_create ;;
    open)   cmd_open   ;;
    close)  cmd_close  ;;
    status) cmd_status ;;
    *)
        echo "Usage: $0 {create|open|close|status}"
        exit 1
        ;;
esac
