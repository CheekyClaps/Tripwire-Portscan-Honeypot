# Tripwire Portscan Honeypot

Tripwire is a lightweight, high-performance portscan honeypot and early warning system written in Rust. Designed specifically for Linux (tested on Fedora), it listens for uninvited connection attempts on configured network interfaces and ports, alerting you immediately to potential reconnaissance activities.

It utilizes `libpcap` with dynamic BPF (Berkeley Packet Filter) filtering to silently drop uninteresting traffic at the kernel level, ensuring minimal CPU and memory overhead.

## Features

* **High Performance:** Written in Rust, leveraging BPF for zero-overhead packet filtering.
* **Protocol Support:** Detects scans on TCP and UDP ports. Extracts TCP flags for advanced analysis.
* **Secure by Design:** Runs as the unprivileged `nobody` user with isolated Linux Capabilities (`CAP_NET_RAW` and `CAP_NET_ADMIN`).
* **Flexible Notifications:** 
    * Native Linux Desktop Notifications (`libnotify`).
    * System Logging (`syslog` / `journalctl`).
    * Webhooks (Discord, Slack, etc.).

---

## Installation

An automated deployment script is included to make installation seamless on Fedora/RHEL-based systems. It installs dependencies, compiles the binary in release mode, and sets up a systemd service.

1. Clone or download this repository.
2. Run the installer script:
   ```bash
   chmod +x install.sh
   sudo ./install.sh
   ```

The script will:
* Install `libpcap-devel`, `dbus-devel`, `openssl-devel`, and Rust.
* Build the `tripwire` binary and move it to `/usr/local/bin/tripwire`.
* Apply the necessary network capture capabilities.
* Create a default configuration at `/etc/tripwire/tripwire.yaml`.
* Setup and start the `tripwire.service` via `systemd`.

---

## Configuration

Once installed, Tripwire loads its configuration from `/etc/tripwire/tripwire.yaml`.

Example configuration:
```yaml
# Network interface to monitor (e.g., eth0, wlan0, lo)
interface: "lo" 

# Ports to monitor for uninvited connection attempts
tcp_ports:
  - 22
  - 80
  - 443
  - 8080

udp_ports:
  - 1194

# Alerting Preferences
notifications:
  desktop: true          # Native Linux desktop notifications
  syslog: true           # Log to systemd journal / syslog
  webhook_url: ""        # Provide a Discord/Slack webhook URL to receive remote alerts
```

**Note:** If you make changes to `/etc/tripwire/tripwire.yaml`, you must restart the service for them to take effect:
```bash
sudo systemctl restart tripwire
```

---

## Usage & Management

Because Tripwire runs as a `systemd` background service, you can manage it using standard Linux commands.

**Check Service Status:**
```bash
sudo systemctl status tripwire
```

**Start / Stop / Restart:**
```bash
sudo systemctl start tripwire
sudo systemctl stop tripwire
sudo systemctl restart tripwire
```

**View Alerts and Logs:**
If `syslog: true` is set in your configuration, all alerts and activity are logged to the system journal. You can view them in real-time using:
```bash
sudo journalctl -t tripwire -f
```

*(To test the honeypot locally, you can run `nc -z -v 127.0.0.1 8080` assuming `lo` and port `8080` are configured.)*
