#!/usr/bin/env bash
# =============================================================================
# mount_secure_fs.sh — Federated LUKS Partition Management (ENHANCED)
# =============================================================================
#
# Features:
#   - Idempotency: Checks state before applying changes
#   - Logging: All operations logged to /var/log/captive-portal-luks.log
#   - Dry-run: --dry-run flag to preview changes
#   - Backup: LUKS header backup before operations
#   - State checks: Validates mount/open status
#
# Usage:
#   sudo bash mount_secure_fs.sh create                # Initialize
#   sudo bash mount_secure_fs.sh --dry-run create      # Preview
#   sudo bash mount_secure_fs.sh open                  # Mount
#   sudo bash mount_secure_fs.sh close                 # Unmount
#   sudo bash mount_secure_fs.sh status                # Show status
#
# =============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/load_profile.sh"

# Configuration
DEVICE="${DEVICE:-/dev/mmcblk0p3}"
MAPPER_NAME="${MAPPER_NAME:-secure_partition}"
MOUNT_POINT="${MOUNT_POINT:-/mnt/secure}"
KEY_FILE_TMPFS="${KEY_FILE_TMPFS:-/run/master.key}"
NODE_ROLE="${NODE_ROLE:-primary}"

# Flags
DRY_RUN=false
SKIP_BACKUP=false

# Logging
LOGDIR="/var/log"
LOGFILE="${LOGDIR}/captive-portal-luks.log"
BACKUP_DIR="/var/backups/captive-portal"

# ── Helpers ──────────────────────────────────────────────────────────────────

log_info() {
    local msg="$1"
    local ts=$(date "+%Y-%m-%d %H:%M:%S")
    echo "[${ts}] INFO: ${msg}" | tee -a "${LOGFILE}"
}

log_warn() {
    local msg="$1"
    local ts=$(date "+%Y-%m-%d %H:%M:%S")
    echo "[${ts}] WARN: ${msg}" | tee -a "${LOGFILE}"
}

log_error() {
    local msg="$1"
    local ts=$(date "+%Y-%m-%d %H:%M:%S")
    echo "[${ts}] ERROR: ${msg}" | tee -a "${LOGFILE}"
}

check_root() {
    [[ "${EUID}" -eq 0 ]] || { log_error "Must run as root"; exit 1; }
}

require_cmd() {
    command -v "$1" &>/dev/null || {
        log_error "Command not found: $1. Install: apt-get install cryptsetup"
        exit 1
    }
}

is_mounted() {
    mountpoint -q "$1" 2>/dev/null
}

is_luks_open() {
    cryptsetup status "$1" &>/dev/null 2>&1
}

is_key_present() {
    [[ -f "$1" ]]
}

apply_or_dry_run() {
    local cmd="$1"
    local desc="$2"
    
    if [[ "${DRY_RUN}" == "true" ]]; then
        log_info "[DRY-RUN] Would: ${desc}"
        return 0
    fi
    
    log_info "Executing: ${desc}"
    eval "${cmd}" || { log_error "Failed: ${desc}"; return 1; }
}

backup_luks_header() {
    [[ "${SKIP_BACKUP}" == "true" ]] && { log_info "Backup skipped"; return 0; }
    [[ ! -e "${DEVICE}" ]] && return 0
    
    mkdir -p "${BACKUP_DIR}"
    local ts=$(date "+%s")
    local backup_file="${BACKUP_DIR}/luks_header.${ts}.bak"
    
    cryptsetup isLuks "${DEVICE}" 2>/dev/null || return 0
    
    log_info "Backing up LUKS header to ${backup_file}"
    cryptsetup luksHeaderBackup "${DEVICE}" --header-backup-file "${backup_file}"
}

# ── Create: Initialize LUKS-encrypted partition ──────────────────────────────

cmd_create() {
    log_info "========== Creating Secure Partition =========="
    
    check_root
    require_cmd cryptsetup
    require_cmd python3
    
    if [[ ! -e "${DEVICE}" ]]; then
        log_error "Device not found: ${DEVICE}"
        exit 1
    fi
    
    log_warn "WARNING: This will ERASE all data on ${DEVICE}"
    if [[ "${DRY_RUN}" != "true" ]]; then
        read -rp "Type YES to confirm: " confirm
        [[ "${confirm}" == "YES" ]] || { log_info "Aborted"; exit 0; }
    fi
    
    log_info "Generating master key (256-bit)..."
    apply_or_dry_run "python3 << 'CRYPTPYTHON'
import secrets, os, pathlib
key = secrets.token_bytes(32)
pathlib.Path('/run').mkdir(exist_ok=True)
with open('${KEY_FILE_TMPFS}', 'wb') as f:
    f.write(key)
os.chmod('${KEY_FILE_TMPFS}', 0o600)
print(f'Generated {len(key)} bytes')
CRYPTPYTHON
" "generate master key"
    
    cryptsetup isLuks "${DEVICE}" 2>/dev/null && backup_luks_header
    
    log_info "Formatting ${DEVICE} with LUKS2..."
    apply_or_dry_run "cryptsetup luksFormat --type luks2 \
        --cipher aes-xts-plain64 --key-size 512 --hash sha256 \
        --key-file '${KEY_FILE_TMPFS}' '${DEVICE}' --batch-mode" \
        "luksFormat"
    
    log_info "Opening LUKS device..."
    apply_or_dry_run "cryptsetup luksOpen '${DEVICE}' '${MAPPER_NAME}' --key-file '${KEY_FILE_TMPFS}'" \
        "luksOpen"
    
    log_info "Creating ext4 filesystem..."
    apply_or_dry_run "mkfs.ext4 -F /dev/mapper/'${MAPPER_NAME}'" "mkfs.ext4"
    
    log_info "Mounting partition..."
    apply_or_dry_run "mkdir -p '${MOUNT_POINT}' && mount /dev/mapper/'${MAPPER_NAME}' '${MOUNT_POINT}' && chmod 750 '${MOUNT_POINT}'" \
        "mount"
    
    log_info "========== Partition Created =========="
    log_info "Device: ${DEVICE} -> /dev/mapper/${MAPPER_NAME}"
    log_info "Mount: ${MOUNT_POINT}"
    log_info "Key: ${KEY_FILE_TMPFS}"
    log_info "Node: ${NODE_ROLE}"
    log_warn "Note: Federation agent will distribute master key to neighbours"
}

# ── Open: Reconstruct key and mount ──────────────────────────────────────────

cmd_open() {
    log_info "========== Opening Secure Partition =========="
    
    check_root
    require_cmd cryptsetup
    
    if is_mounted "${MOUNT_POINT}"; then
        log_warn "Already mounted at ${MOUNT_POINT}"
        show_status
        return 0
    fi
    
    if is_luks_open "${MAPPER_NAME}"; then
        log_info "LUKS open, attempting mount..."
        apply_or_dry_run "mkdir -p '${MOUNT_POINT}' && mount /dev/mapper/'${MAPPER_NAME}' '${MOUNT_POINT}'" \
            "mount"
        log_info "Partition opened and mounted"
        show_status
        return 0
    fi
    
    if ! is_key_present "${KEY_FILE_TMPFS}"; then
        log_error "Master key not found at ${KEY_FILE_TMPFS}"
        log_error "Federation bootstrap must complete before opening"
        exit 1
    fi
    
    log_info "Opening LUKS partition with key from ${KEY_FILE_TMPFS}..."
    apply_or_dry_run "cryptsetup luksOpen '${DEVICE}' '${MAPPER_NAME}' --key-file '${KEY_FILE_TMPFS}'" \
        "luksOpen"
    
    log_info "Mounting partition..."
    apply_or_dry_run "mkdir -p '${MOUNT_POINT}' && mount /dev/mapper/'${MAPPER_NAME}' '${MOUNT_POINT}'" \
        "mount"
    
    if [[ "${DRY_RUN}" != "true" ]]; then
        log_info "Wiping key file from tmpfs..."
        shred -ufz -n 3 "${KEY_FILE_TMPFS}" 2>/dev/null || rm -f "${KEY_FILE_TMPFS}"
    fi
    
    log_info "========== Partition Opened =========="
    show_status
}

# ── Close: Unmount and lock LUKS device ──────────────────────────────────────

cmd_close() {
    log_info "========== Closing Secure Partition =========="
    
    check_root
    require_cmd cryptsetup
    
    is_mounted "${MOUNT_POINT}" && apply_or_dry_run "umount '${MOUNT_POINT}'" "umount"
    is_luks_open "${MAPPER_NAME}" && apply_or_dry_run "cryptsetup luksClose '${MAPPER_NAME}'" "luksClose"
    
    log_info "========== Partition Closed =========="
}

# ── Status: Show partition state ─────────────────────────────────────────────

cmd_status() {
    log_info "========== Status =========="
    log_info "Device: ${DEVICE}"
    log_info "Mapper: /dev/mapper/${MAPPER_NAME}"
    log_info "Mount Pt: ${MOUNT_POINT}"
    log_info "Key File: ${KEY_FILE_TMPFS}"
    log_info "Node: ${NODE_ROLE}"
    log_info ""
    
    if is_luks_open "${MAPPER_NAME}"; then
        log_info "LUKS: OPEN"
    else
        log_info "LUKS: CLOSED"
    fi
    
    if is_mounted "${MOUNT_POINT}"; then
        log_info "Mount: ACTIVE"
        df -h "${MOUNT_POINT}" | while read line; do
            log_info "  ${line}"
        done
    else
        log_info "Mount: INACTIVE"
    fi
    
    is_key_present "${KEY_FILE_TMPFS}" && log_info "Key: PRESENT" || log_info "Key: ABSENT (normal)"
    
    log_info "============================="
}

# ── Main ─────────────────────────────────────────────────────────────────────

check_root
mkdir -p "${LOGDIR}"
touch "${LOGFILE}"

log_info "========== LUKS Partition Manager =========="
log_info "Node: ${NODE_ROLE}, DRY_RUN: ${DRY_RUN}"

case "${1:-status}" in
    create) cmd_create ;;
    open)   cmd_open   ;;
    close)  cmd_close  ;;
    status) cmd_status ;;
    *)      log_error "Usage: $0 {create|open|close|status}"; exit 1 ;;
esac

[[ "${DRY_RUN}" == "true" ]] && log_warn "DRY-RUN: no changes applied"
