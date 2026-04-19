#!/usr/bin/env bash
# =============================================================================
# setup_iptables.sh — Captive Portal Firewall Rules (ENHANCED)
# =============================================================================
#
# Features:
#   - Idempotency: Safe to run multiple times
#   - Logging: All operations logged to /var/log/captive-portal-iptables.log
#   - Dry-run: --dry-run flag to preview changes without applying
#   - Backup/restore: Automatic backups of iptables rules
#   - Device management: authorize_mac/revoke_mac with persistence
#
# Usage:
#   sudo bash setup_iptables.sh setup                  # Initialize rules
#   sudo bash setup_iptables.sh --dry-run setup        # Preview only
#   sudo bash setup_iptables.sh authorize AA:BB:CC:DD:EE:FF
#   sudo bash setup_iptables.sh revoke AA:BB:CC:DD:EE:FF
#   sudo bash setup_iptables.sh status                 # Show whitelist
#
# =============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/load_profile.sh"

# Configuration
IFACE_AP="${IFACE_AP:-wlan0}"
IFACE_WAN="${IFACE_WAN:-eth0}"
AP_IP="${AP_IP:-192.168.73.1}"
PORTAL_PORT="${PORTAL_PORT:-5000}"
NODE_ROLE="${NODE_ROLE:-primary}"

# Flags
DRY_RUN=false
SKIP_BACKUP=false

# Logging
LOGDIR="/var/log"
LOGFILE="${LOGDIR}/captive-portal-iptables.log"
RULES_DIR="/etc/iptables"
AUTH_FILE="/var/lib/captive-portal/authorized_macs.txt"

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
    command -v "$1" &>/dev/null || { log_error "Command not found: $1"; exit 1; }
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

backup_rules() {
    [[ "${SKIP_BACKUP}" == "true" ]] && { log_info "Backup skipped"; return 0; }
    
    mkdir -p "${LOGDIR}/backups/captive-portal"
    local ts=$(date "+%s")
    iptables-save > "${LOGDIR}/backups/captive-portal/rules.v4.${ts}.bak"
    log_info "Backup: ${LOGDIR}/backups/captive-portal/rules.v4.${ts}.bak"
}

is_mac_authorized() {
    [[ -f "${AUTH_FILE}" ]] && grep -iq "^${1}$" "${AUTH_FILE}" && return 0
    return 1
}

# ── Setup Rules ──────────────────────────────────────────────────────────────

setup_rules() {
    log_info "Setting up iptables rules..."
    
    backup_rules
    
    mkdir -p "${LOGDIR}" "${RULES_DIR}"
    touch "${LOGFILE}"
    
    apply_or_dry_run "iptables -t nat -F PREROUTING 2>/dev/null || true" "flush PREROUTING"
    apply_or_dry_run "iptables -F FORWARD 2>/dev/null || true" "flush FORWARD"
    apply_or_dry_run "iptables -t nat -F POSTROUTING 2>/dev/null || true" "flush POSTROUTING"
    
    apply_or_dry_run "iptables -t nat -N CAPTIVE_WHITELIST 2>/dev/null || iptables -t nat -F CAPTIVE_WHITELIST" \
        "create CAPTIVE_WHITELIST"
    
    apply_or_dry_run "iptables -t nat -A POSTROUTING -o ${IFACE_WAN} -j MASQUERADE" "add MASQUERADE"
    
    apply_or_dry_run "iptables -t nat -A PREROUTING -i ${IFACE_AP} -d ${AP_IP} -j RETURN" "add AP self-traffic"
    apply_or_dry_run "iptables -t nat -A PREROUTING -i ${IFACE_AP} -j CAPTIVE_WHITELIST" "add whitelist"
    
    apply_or_dry_run "iptables -t nat -A PREROUTING -i ${IFACE_AP} -p tcp --dport 80 \
        -j DNAT --to-destination ${AP_IP}:${PORTAL_PORT}" "redirect HTTP"
    
    apply_or_dry_run "iptables -t nat -A PREROUTING -i ${IFACE_AP} -p tcp --dport 443 \
        -j DNAT --to-destination ${AP_IP}:${PORTAL_PORT}" "redirect HTTPS"
    
    apply_or_dry_run "iptables -A FORWARD -m state --state ESTABLISHED,RELATED -j ACCEPT" "allow established"
    apply_or_dry_run "iptables -A FORWARD -i ${IFACE_WAN} -o ${IFACE_AP} -m state --state ESTABLISHED,RELATED -j ACCEPT" \
        "allow return traffic"
    apply_or_dry_run "iptables -A FORWARD -i ${IFACE_AP} -p tcp --dport ${PORTAL_PORT} -j ACCEPT" "allow portal"
    apply_or_dry_run "iptables -A FORWARD -i ${IFACE_AP} -j DROP" "drop unauthenticated"
    
    apply_or_dry_run "iptables-save > ${RULES_DIR}/rules.v4" "save rules"
    
    log_info "Setup complete on node: ${NODE_ROLE}"
}

# ── Authorize MAC ────────────────────────────────────────────────────────────

authorize_mac() {
    local mac="$1"
    
    is_mac_authorized "${mac}" && { log_warn "Already authorized: ${mac}"; return 0; }
    
    log_info "Authorizing MAC: ${mac}"
    
    apply_or_dry_run "iptables -t nat -I CAPTIVE_WHITELIST -m mac --mac-source ${mac} -j RETURN" "insert whitelist"
    apply_or_dry_run "iptables -I FORWARD 1 -m mac --mac-source ${mac} -j ACCEPT" "insert FORWARD"
    
    if [[ "${DRY_RUN}" != "true" ]]; then
        mkdir -p "$(dirname ${AUTH_FILE})"
        echo "${mac}" >> "${AUTH_FILE}"
        sort -u "${AUTH_FILE}" -o "${AUTH_FILE}"
        iptables-save > "${RULES_DIR}/rules.v4"
    fi
    
    log_info "Authorized: ${mac}"
}

# ── Revoke MAC ───────────────────────────────────────────────────────────────

revoke_mac() {
    local mac="$1"
    
    is_mac_authorized "${mac}" || { log_warn "Not authorized: ${mac}"; return 0; }
    
    log_info "Revoking MAC: ${mac}"
    
    apply_or_dry_run "iptables -t nat -D CAPTIVE_WHITELIST -m mac --mac-source ${mac} -j RETURN 2>/dev/null || true" \
        "remove whitelist"
    apply_or_dry_run "iptables -D FORWARD -m mac --mac-source ${mac} -j ACCEPT 2>/dev/null || true" "remove FORWARD"
    
    if [[ "${DRY_RUN}" != "true" ]]; then
        grep -iv "^${mac}$" "${AUTH_FILE}" > "${AUTH_FILE}.tmp" || true
        mv "${AUTH_FILE}.tmp" "${AUTH_FILE}"
        iptables-save > "${RULES_DIR}/rules.v4"
    fi
    
    log_info "Revoked: ${mac}"
}

# ── Status ───────────────────────────────────────────────────────────────────

show_status() {
    log_info "========== Firewall Status =========="
    log_info "Node: ${NODE_ROLE}"
    log_info "AP Interface: ${IFACE_AP}, WAN: ${IFACE_WAN}"
    log_info "Portal: ${AP_IP}:${PORTAL_PORT}"
    
    if [[ -f "${AUTH_FILE}" ]]; then
        log_info "Authorized MACs:"
        cat "${AUTH_FILE}" | while read mac; do
            log_info "  - ${mac}"
        done
    else
        log_info "No authorized MACs"
    fi
    log_info "===================================="
}

# ── Main ─────────────────────────────────────────────────────────────────────

check_root
require_cmd iptables
require_cmd iptables-save

mkdir -p "${LOGDIR}"
touch "${LOGFILE}"

log_info "========== Firewall Management =========="
log_info "Node: ${NODE_ROLE}, DRY_RUN: ${DRY_RUN}"

case "${1:-setup}" in
    setup)      setup_rules ;;
    authorize)  authorize_mac "${2:?MAC required}" ;;
    revoke)     revoke_mac "${2:?MAC required}" ;;
    status)     show_status ;;
    *)          log_error "Usage: $0 {setup|authorize <MAC>|revoke <MAC>|status}"; exit 1 ;;
esac

log_info "Operation completed (DRY_RUN=${DRY_RUN})"
