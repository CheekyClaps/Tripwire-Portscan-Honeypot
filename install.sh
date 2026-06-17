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
cat <<EOF > /etc/systemd/system/tripwire.service
[Unit]
Description=Tripwire Portscan Honeypot
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/tripwire
Restart=on-failure
RestartSec=5
# Run as an unprivileged user for security
User=nobody
Group=nobody
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
