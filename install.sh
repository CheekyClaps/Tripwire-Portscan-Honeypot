#!/bin/bash

set -e

echo "======================================"
echo " Tripwire Honeypot Installer (Fedora) "
echo "======================================"

if [ "$EUID" -ne 0 ]; then
  echo "[!] Please run as root: sudo ./install.sh"
  exit 1
fi

echo "[*] Installing required system dependencies..."
dnf install -y libpcap-devel dbus-devel openssl-devel rust cargo

echo "[*] Building Tripwire in release mode..."
# Build as the user who invoked sudo to avoid messing up cargo cache permissions
if [ -n "$SUDO_USER" ]; then
    sudo -u "$SUDO_USER" cargo build --release
else
    cargo build --release
fi

echo "[*] Installing binary to /usr/local/bin/tripwire..."
if systemctl list-unit-files | grep -q tripwire.service; then
    echo "    -> Stopping existing tripwire service before overwrite..."
    systemctl stop tripwire.service || true
fi
cp target/release/tripwire /usr/local/bin/tripwire
chmod +x /usr/local/bin/tripwire

echo "[*] Setting required network capabilities..."
# This allows tripwire to capture packets without running fully as root
setcap cap_net_raw,cap_net_admin=eip /usr/local/bin/tripwire

echo "[*] Setting up configuration directory..."
mkdir -p /etc/tripwire
if [ ! -f /etc/tripwire/tripwire.yaml ]; then
    cp tripwire.yaml /etc/tripwire/
    echo "    -> Default config copied to /etc/tripwire/tripwire.yaml"
else
    echo "    -> Config already exists at /etc/tripwire/tripwire.yaml, skipping copy."
fi

echo "[*] Creating systemd service..."

REAL_USER=${SUDO_USER:-root}
REAL_UID=$(id -u "$REAL_USER")
REAL_GROUP=$(id -g -n "$REAL_USER")

echo ""
echo "--------------------------------------------------------"
echo " Service Execution User Selection"
echo "--------------------------------------------------------"
echo "Tripwire can run as your local user or as the secure 'nobody' user."
echo ""
echo " 1) Run as $REAL_USER (Required for Desktop Notifications)"
echo " 2) Run as nobody (More secure, but Webhooks & Syslog only)"
echo ""
read -p "Select an option [1 or 2]: " USER_CHOICE

cat <<EOF > /etc/systemd/system/tripwire.service
[Unit]
Description=Tripwire Portscan Honeypot
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/tripwire
Restart=on-failure
RestartSec=5
EOF

if [ "$USER_CHOICE" == "1" ]; then
    echo "    -> Configuring service to run as $REAL_USER"
    cat <<EOF >> /etc/systemd/system/tripwire.service
# Run as the user who installed it so desktop notifications work
User=$REAL_USER
Group=$REAL_GROUP
Environment="DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/$REAL_UID/bus"
Environment="DISPLAY=:0"
EOF
else
    echo "    -> Configuring service to run as nobody"
    cat <<EOF >> /etc/systemd/system/tripwire.service
# Run as an unprivileged user for security
User=nobody
Group=nobody
EOF
fi

cat <<EOF >> /etc/systemd/system/tripwire.service
# Retain capabilities needed for pcap
AmbientCapabilities=CAP_NET_RAW CAP_NET_ADMIN

[Install]
WantedBy=multi-user.target
EOF

echo "[*] Enabling and starting Tripwire service..."
systemctl daemon-reload
systemctl enable --now tripwire.service

sleep 2 # Give it a moment to start
echo "[*] Checking service status..."
if systemctl is-active --quiet tripwire.service; then
    echo "    -> [OK] Tripwire service is active and running."
else
    echo "    -> [ERROR] Tripwire service failed to start. Check logs: sudo journalctl -u tripwire -n 20"
fi

echo "======================================"
echo " Installation Complete! "
echo " - Configuration: /etc/tripwire/tripwire.yaml"
echo " - View Logs: sudo journalctl -u tripwire -f"
echo " - Manage Service: sudo systemctl {start|stop|restart|status} tripwire"
echo "======================================"
