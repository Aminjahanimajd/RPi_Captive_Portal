#!/usr/bin/env bash
# =============================================================================
# setup_hotspot.sh — Configure Raspberry Pi as a WiFi Access Point
# =============================================================================
#
# Tested on Raspberry Pi OS (Bookworm) with:
#   - wlan0 : wireless interface used for the AP / captive portal
#   - eth0  : upstream internet connection (bridge for authorised devices)
#
# What this script does:
#   1. Installs hostapd, dnsmasq, and iptables-persistent
#   2. Configures hostapd (AP) on wlan0 (SSID: CaptivePortal-IoT)
#   3. Configures dnsmasq (DHCP + DNS) for connected devices
#   4. Sets a static IP on wlan0 (192.168.73.1)
#   5. Enables IP forwarding for authorised devices
#
# Run as root:  sudo bash setup_hotspot.sh
# =============================================================================

set -euo pipefail

IFACE_AP="wlan0"
IFACE_WAN="eth0"
AP_IP="192.168.73.1"
AP_SUBNET="192.168.73.0/24"
DHCP_RANGE_START="192.168.73.10"
DHCP_RANGE_END="192.168.73.200"
SSID="CaptivePortal-IoT"
WPA_PASSPHRASE="SecurePortal2024"   # Change this!
PORTAL_PORT="5000"

echo "==> Installing dependencies..."
apt-get update -qq
apt-get install -y hostapd dnsmasq iptables-persistent curl

echo "==> Stopping services for configuration..."
systemctl stop hostapd dnsmasq || true

# ── Static IP for the AP interface ─────────────────────────────────────────
echo "==> Configuring static IP on ${IFACE_AP}..."
cat > /etc/network/interfaces.d/wlan0 << EOF
auto ${IFACE_AP}
iface ${IFACE_AP} inet static
    address ${AP_IP}
    netmask 255.255.255.0
EOF

# ── hostapd configuration ───────────────────────────────────────────────────
echo "==> Writing hostapd configuration..."
cat > /etc/hostapd/hostapd.conf << EOF
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

# Tell hostapd where its config is
sed -i 's|#DAEMON_CONF=.*|DAEMON_CONF="/etc/hostapd/hostapd.conf"|' /etc/default/hostapd

# ── dnsmasq (DHCP + DNS redirect) ──────────────────────────────────────────
echo "==> Writing dnsmasq configuration..."
cat > /etc/dnsmasq.conf << EOF
interface=${IFACE_AP}
dhcp-range=${DHCP_RANGE_START},${DHCP_RANGE_END},24h
# Redirect all DNS queries to the portal IP so that the browser's captive
# portal detection triggers the redirect.
address=/#/${AP_IP}
EOF

# ── IP forwarding ───────────────────────────────────────────────────────────
echo "==> Enabling IP forwarding..."
sed -i 's/#net.ipv4.ip_forward=1/net.ipv4.ip_forward=1/' /etc/sysctl.conf
sysctl -p /etc/sysctl.conf

# ── Start services ──────────────────────────────────────────────────────────
echo "==> Starting hostapd and dnsmasq..."
systemctl unmask hostapd
systemctl enable hostapd dnsmasq
systemctl start hostapd dnsmasq

echo ""
echo "✓ Hotspot configured!"
echo "  SSID      : ${SSID}"
echo "  Password  : ${WPA_PASSPHRASE}"
echo "  Portal IP : http://${AP_IP}:${PORTAL_PORT}"
echo ""
echo "Next step: run setup_iptables.sh to configure captive-portal redirection."
