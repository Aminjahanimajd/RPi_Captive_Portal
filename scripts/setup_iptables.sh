#!/usr/bin/env bash
# =============================================================================
# setup_iptables.sh — Captive Portal Traffic Redirection Rules
# =============================================================================
#
# This script configures iptables rules that implement the captive portal:
#
#   1. All new TCP connections on port 80/443 from UNAUTHENTICATED devices
#      are DNAT-ed to the portal web server (port 5000).
#   2. Once the portal authenticates a device it calls authorize_mac() which
#      inserts an ACCEPT rule for that MAC address BEFORE the DNAT rules.
#   3. Revoking access removes that ACCEPT rule so the device falls through
#      to the DNAT redirect again.
#
# The Flask backend calls this script (or an equivalent helper) via the OS
# when the admin authorises/revokes a device through the web interface.
#
# Run as root:  sudo bash setup_iptables.sh
# =============================================================================

set -euo pipefail

IFACE_AP="wlan0"
IFACE_WAN="eth0"
AP_IP="192.168.73.1"
PORTAL_PORT="5000"

# ── Flush existing captive-portal chains ────────────────────────────────────
echo "==> Setting up iptables rules..."

iptables -t nat -F PREROUTING   2>/dev/null || true
iptables -F FORWARD              2>/dev/null || true
iptables -t nat -F POSTROUTING  2>/dev/null || true

# ── Custom chains ───────────────────────────────────────────────────────────
# CAPTIVE_WHITELIST — authorised MACs jump here and RETURN (skip redirect)
iptables -t nat -N CAPTIVE_WHITELIST 2>/dev/null || iptables -t nat -F CAPTIVE_WHITELIST

# ── NAT / Masquerade for authorised devices ─────────────────────────────────
iptables -t nat -A POSTROUTING -o "${IFACE_WAN}" -j MASQUERADE

# ── PREROUTING: whitelist first, then redirect ──────────────────────────────
# 1) Bypass the portal for the AP itself
iptables -t nat -A PREROUTING -i "${IFACE_AP}" -d "${AP_IP}" -j RETURN

# 2) Jump to whitelist; authorised MACs will RETURN and not be redirected
iptables -t nat -A PREROUTING -i "${IFACE_AP}" -j CAPTIVE_WHITELIST

# 3) Redirect HTTP (80) to portal
iptables -t nat -A PREROUTING -i "${IFACE_AP}" -p tcp --dport 80 \
    -j DNAT --to-destination "${AP_IP}:${PORTAL_PORT}"

# 4) Redirect HTTPS (443) to portal (so HTTPS captive-portal detection works)
iptables -t nat -A PREROUTING -i "${IFACE_AP}" -p tcp --dport 443 \
    -j DNAT --to-destination "${AP_IP}:${PORTAL_PORT}"

# ── FORWARD: allow established/related; block unauthenticated new connections
iptables -A FORWARD -m state --state ESTABLISHED,RELATED -j ACCEPT
iptables -A FORWARD -i "${IFACE_WAN}" -o "${IFACE_AP}" -m state --state ESTABLISHED,RELATED -j ACCEPT

# Allow portal port through
iptables -A FORWARD -i "${IFACE_AP}" -p tcp --dport "${PORTAL_PORT}" -j ACCEPT

# Drop everything else from unauthenticated clients (whitelisted MACs have
# separate ACCEPT rules inserted by authorize_mac() below)
iptables -A FORWARD -i "${IFACE_AP}" -j DROP

# ── Save rules ──────────────────────────────────────────────────────────────
iptables-save > /etc/iptables/rules.v4
echo "==> Rules saved to /etc/iptables/rules.v4"

# ── Helper functions (called by Flask app via subprocess) ───────────────────

authorize_mac() {
    local MAC="$1"
    # Insert ACCEPT rule into whitelist chain so device bypasses the redirect
    iptables -t nat -I CAPTIVE_WHITELIST -m mac --mac-source "${MAC}" -j RETURN
    iptables -I FORWARD 1 -m mac --mac-source "${MAC}" -j ACCEPT
    echo "Authorised MAC: ${MAC}"
}

revoke_mac() {
    local MAC="$1"
    # Remove the ACCEPT rules for this MAC
    iptables -t nat -D CAPTIVE_WHITELIST -m mac --mac-source "${MAC}" -j RETURN 2>/dev/null || true
    iptables -D FORWARD -m mac --mac-source "${MAC}" -j ACCEPT 2>/dev/null || true
    echo "Revoked MAC: ${MAC}"
}

# ── CLI interface ────────────────────────────────────────────────────────────
case "${1:-setup}" in
    authorize) authorize_mac "${2:?MAC address required}" ;;
    revoke)    revoke_mac    "${2:?MAC address required}" ;;
    setup)     echo "✓ Captive portal iptables rules applied." ;;
    *)         echo "Usage: $0 {setup|authorize <MAC>|revoke <MAC>}" ;;
esac
