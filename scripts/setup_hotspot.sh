#!/usr/bin/env bash
# =============================================================================
# setup_hotspot.sh — Configure Raspberry Pi as a WiFi Access Point (ENHANCED)
# =============================================================================
#
# Features:
#   - Idempotency: Safe to run multiple times
#   - Logging: All operations logged to /var/log/captive-portal-hotspot.log
#   - Dry-run: --dry-run flag to preview changes without applying
#   - Backup: Automatic backups before modifying configs
#   - Node profiles: Primary/neighbor auto-detection via NODE_ROLE env var
#
# Usage:
#   sudo bash setup_hotspot.sh                  # Normal run
#   sudo bash setup_hotspot.sh --dry-run        # Preview only
#   sudo bash setup_hotspot.sh --skip-backup    # Fast re-run (no backups)
#
# =============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/load_profile.sh"

# Configuration
IFACE_AP="${IFACE_AP:-wlan0}"
IFACE_WAN="${IFACE_WAN:-eth0}"
AP_IP="${AP_IP:-192.168.73.1}"
AP_SUBNET="${AP_SUBNET:-192.168.73.0/24}"
DHCP_RANGE_START="${DHCP_RANGE_START:-192.168.73.10}"
DHCP_RANGE_END="${DHCP_RANGE_END:-192.168.73.200}"
SSID="${SSID:-CaptivePortal-IoT}"
WPA_PASSPHRASE="${WPA_PASSPHRASE:-SecurePortal2024}"
PORTAL_PORT="${PORTAL_PORT:-5000}"
NODE_ROLE="${NODE_ROLE:-primary}"

# Flags
DRY_RUN=false
SKIP_BACKUP=false

# Logging
LOGDIR="/var/log"
LOGFILE="${LOGDIR}/captive-portal-hotspot.log"

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

backup_file() {
    local src="$1"
    local backup_dir="${LOGDIR}/backups/captive-portal"
    
    if [[ ! -f "${src}" ]]; then
        return 0
    fi
    
    if [[ "${SKIP_BACKUP}" == "true" ]]; then
        log_info "Backup skipped for ${src}"
        return 0
    fi
    
    mkdir -p "${backup_dir}"
    local ts=$(date "+%s")
    local backup_file="${backup_dir}/$(basename ${src}).${ts}.bak"
    cp "${src}" "${backup_file}"
    log_info "Backup created: ${backup_file}"
}

check_root() {
    [[ "${EUID}" -eq 0 ]] || { log_error "Must run as root"; exit 1; }
}

require_cmd() {
    command -v "$1" &>/dev/null || { log_error "Command not found: $1"; exit 1; }
}

require_interface() {
    ip link show "$1" &>/dev/null || { log_error "Interface not found: $1"; exit 1; }
}

is_already_configured() {
    grep -q "ssid=${SSID}" /etc/hostapd/hostapd.conf 2>/dev/null && return 0
    return 1
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

# ── Main ─────────────────────────────────────────────────────────────────────

while [[ $# -gt 0 ]]; do
    case "$1" in
        --dry-run)      DRY_RUN=true; shift ;;
        --skip-backup)  SKIP_BACKUP=true; shift ;;
        *)              log_error "Unknown flag: $1"; exit 1 ;;
    esac
done

check_root
require_cmd apt-get
require_cmd systemctl
require_interface "${IFACE_AP}"
require_interface "${IFACE_WAN}"

mkdir -p "${LOGDIR}"
touch "${LOGFILE}" || log_error "Cannot write to ${LOGFILE}"

log_info "========== Hotspot Setup (${NODE_ROLE}) =========="
log_info "SSID: ${SSID}, IP: ${AP_IP}, DRY_RUN: ${DRY_RUN}"

is_already_configured && log_warn "Already configured, updating..."

log_info "Installing dependencies..."
apply_or_dry_run "apt-get update -qq && apt-get install -y hostapd dnsmasq iptables-persistent curl" \
    "apt-get install packages"

log_info "Stopping services..."
apply_or_dry_run "systemctl stop hostapd dnsmasq || true" "stop services"

backup_file /etc/hostapd/hostapd.conf
backup_file /etc/dnsmasq.conf
backup_file /etc/default/hostapd

log_info "Configuring static IP..."
apply_or_dry_run "cat > /etc/network/interfaces.d/wlan0 << 'EOF'
auto ${IFACE_AP}
iface ${IFACE_AP} inet static
    address ${AP_IP}
    netmask 255.255.255.0
EOF
" "write static IP"

log_info "Configuring hostapd..."
apply_or_dry_run "cat > /etc/hostapd/hostapd.conf << 'EOF'
interface=${IFACE_AP}
driver=nl80211
ssid=${SSID}
hw_mode=g
channel=6
wmm_enabled=0
macaddr_acl=0
auth_algs=1
ignore_broadcast_ssid=0
wpa=2
wpa_passphrase=${WPA_PASSPHRASE}
wpa_key_mgmt=WPA-PSK
wpa_pairwise=TKIP
rsn_pairwise=CCMP
EOF
" "write hostapd config"

apply_or_dry_run "sed -i 's|#DAEMON_CONF=.*|DAEMON_CONF=\"/etc/hostapd/hostapd.conf\"|' /etc/default/hostapd" \
    "enable daemon config"

log_info "Configuring dnsmasq..."
apply_or_dry_run "cat > /etc/dnsmasq.conf << 'EOF'
interface=${IFACE_AP}
dhcp-range=${DHCP_RANGE_START},${DHCP_RANGE_END},24h
address=/#/${AP_IP}
EOF
" "write dnsmasq config"

log_info "Enabling IP forwarding..."
apply_or_dry_run "sed -i 's/#net.ipv4.ip_forward=1/net.ipv4.ip_forward=1/' /etc/sysctl.conf && sysctl -p /etc/sysctl.conf" \
    "enable IP forwarding"

log_info "Starting services..."
apply_or_dry_run "systemctl unmask hostapd && systemctl enable hostapd dnsmasq && systemctl start hostapd dnsmasq" \
    "enable and start services"

log_info "========== Setup Complete =========="
log_info "SSID: ${SSID}"
log_info "Password: ${WPA_PASSPHRASE}"
log_info "Portal: http://${AP_IP}:${PORTAL_PORT}"
log_info "Node Role: ${NODE_ROLE}"
log_info "Logs: ${LOGFILE}"

[[ "${DRY_RUN}" == "true" ]] && log_warn "DRY-RUN mode: no changes applied"
