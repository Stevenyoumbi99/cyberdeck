# CyberDeck — Installation Guide

> Complete setup instructions for development (Kali Linux VM on VMware) and
> production deployment (Raspberry Pi 4). Follow the relevant section for your
> target environment.
> Last updated: March 2026 — reflects v1.0.0.

---

## Table of Contents

1. [Prerequisites](#1-prerequisites)
2. [Development VM Setup (Kali Linux on VMware)](#2-development-vm-setup-kali-linux-on-vmware)
3. [Clone the Repository](#3-clone-the-repository)
4. [Install Dependencies](#4-install-dependencies)
5. [Configure the System](#5-configure-the-system)
6. [Run CyberDeck](#6-run-cyberdeck)
7. [Raspberry Pi 4 Deployment](#7-raspberry-pi-4-deployment)
8. [Hardware Setup (Pi)](#8-hardware-setup-pi)
9. [Verifying the Installation](#9-verifying-the-installation)
10. [Uninstallation](#10-uninstallation)

---

## 1. Prerequisites

### Common (both VM and Pi)

| Requirement        | Minimum version | Notes                                      |
|--------------------|----------------|--------------------------------------------|
| Python             | 3.10+          | Pre-installed on Kali Linux and Raspberry Pi OS |
| git                | 2.x            | For cloning the repository                 |
| nmap               | 7.x            | Required by lan_scan and pentest_tools     |
| pip3               | 22+            | For Python package installation            |

### VM only

- VMware Workstation Player (free) or VMware Workstation Pro
- Kali Linux 2024.x ISO from https://www.kali.org/get-kali/

### Raspberry Pi only

- Raspberry Pi 4 Model B (2 GB RAM minimum, 4 GB recommended)
- microSD card 32 GB+ (Class 10 / A1 speed rating)
- Raspberry Pi OS (64-bit) or Kali Linux ARM image
- USB WiFi adapter supporting monitor mode (e.g. Alfa AWUS036ACH)
- Official Raspberry Pi power supply (5V 3A USB-C)
- Optional: Official 7" touchscreen or HDMI display

---

## 2. Development VM Setup (Kali Linux on VMware)

### 2.1 Create the Virtual Machine

1. Download the Kali Linux VMware image from https://www.kali.org/get-kali/#kali-virtual-machines
2. Extract the `.7z` archive.
3. Open VMware → **Open a Virtual Machine** → select the extracted `.vmx` file.
4. Recommended VM settings (edit before first boot):
   - RAM: 4 GB minimum
   - CPUs: 2 cores
   - Disk: 80 GB (allow growth)
   - Network adapter: **NAT** (for internet access) or **Bridged** (to scan the host LAN)

### 2.2 First Boot

Default Kali credentials: `kali` / `kali`

Update the system before installing anything:

```bash
sudo apt update && sudo apt upgrade -y
```

### 2.3 Network Adapter for Scanning

The VM must be on the same network segment as the hosts you want to scan.

- **NAT**: The VM gets a private IP from VMware. Suitable for testing — you can
  scan other VMs but typically not the physical LAN.
- **Bridged**: The VM gets a real IP from your router. Required to scan physical
  devices on your network.

Change the network mode: VMware menu → **VM** → **Settings** → **Network Adapter**.

To confirm the interface name (usually `eth0`):
```bash
ip link show
```

Update `config/config.json` → `network.lan_interface` to match.

---

## 3. Clone the Repository

```bash
# Navigate to your preferred working directory
cd ~

# Clone via SSH (requires SSH key configured on GitHub)
git clone git@github.com:Stevenyoumbi99/cyberdeck.git

# OR clone via HTTPS (no SSH key needed)
git clone https://github.com/Stevenyoumbi99/cyberdeck.git

cd cyberdeck
```

### Set up Git identity (first time only)

```bash
git config --global user.name "Your Name"
git config --global user.email "your@email.com"
```

### Switch to the active development branch

```bash
git checkout dev
```

---

## 4. Install Dependencies

### 4.1 Automated Setup (recommended)

The `setup_env.sh` script installs everything in one command:

```bash
sudo bash scripts/setup_env.sh
```

This script:
1. Runs `apt update` and installs: `python3`, `python3-pip`, `git`, `nmap`,
   `aircrack-ng`, `bluez`, `tshark`, `nikto`, `enum4linux`
2. Runs `pip3 install -r requirements.txt`
3. Creates the `results/` and `logs/` directories
4. Verifies key tool versions

### 4.2 Manual Setup

If you prefer step-by-step control:

**System packages:**
```bash
sudo apt update
sudo apt install -y python3 python3-pip nmap tshark nikto enum4linux bluez aircrack-ng
```

**Python packages:**
```bash
pip3 install -r requirements.txt
```

**Create runtime directories:**
```bash
mkdir -p results logs
```

### 4.3 Python Dependencies (requirements.txt)

| Package       | Purpose                                              |
|---------------|------------------------------------------------------|
| `flask`       | Dashboard web server                                 |
| `jinja2`      | HTML template rendering (reports + dashboard)        |
| `scapy`       | Passive packet capture, ARP monitoring               |
| `numpy`       | Z-score anomaly detection calculations               |
| `scikit-learn`| Isolation Forest anomaly detection (ML)              |
| `requests`    | HTTP requests for TLS audit and OSINT                |
| `tkinter`     | GUI (built into Python — no pip install needed)      |

> **Note:** `tkinter` is part of Python's standard library. On some minimal
> Linux installations it may need to be installed separately:
> ```bash
> sudo apt install python3-tk
> ```

---

## 5. Configure the System

Open `config/config.json` and adjust the values for your environment.

### 5.1 Essential settings to change

**Network interface** — find your interface name with `ip link show`:
```json
"network": {
    "lan_interface": "eth0",
    "target_subnet": "192.168.X.0/24"
}
```

Set `target_subnet` to your network's CIDR range. To find it:
```bash
ip route | grep -v default
# Example output: 192.168.88.0/24 dev eth0
```

**WiFi interface** (Pi only) — check with `iwconfig` or `ip link show`:
```json
"network": {
    "wifi_interface": "wlan1",
    "wifi_monitor_interface": "wlan1mon"
}
```

### 5.2 Anomaly detection

For a new installation, leave `anomaly.min_samples` at `50`. The system will
build a statistical baseline over the first 50 scans automatically.

For testing on a VM where fewer scans will be run, lower it:
```json
"anomaly": {
    "min_samples": 5
}
```

### 5.3 Dashboard port

If port 5000 is already in use on your machine:
```json
"dashboard": {
    "port": 8080
}
```

---

## 6. Run CyberDeck

All commands are run from the project root (`~/cyberdeck/`).

### 6.1 Normal launch (GUI if display available, text menu otherwise)

```bash
sudo python3 launcher.py
```

> **Why sudo?** Passive packet capture (Scapy) and WiFi monitor mode require
> root privileges. Most CyberDeck modules work without root, but running with
> sudo ensures all modules have the permissions they need.

### 6.2 Force text menu (even with a display)

```bash
sudo python3 launcher.py 2>/dev/null | DISPLAY= python3 launcher.py
```

Or simply run via SSH — the system automatically detects the absence of a display
and falls back to the text menu.

### 6.3 Expected output on first launch

```
==================================================
  CYBERDECK — Portable Cyber Audit Platform
==================================================

2026-03-03 17:24:12 | INFO     | CyberDeck logger initialized (level=INFO)
2026-03-03 17:24:12 | INFO     | CyberDeck starting up (v1.0.0)
2026-03-03 17:24:12 | INFO     | Display detected — launching Tkinter GUI
[i] Display detected — launching graphical interface...
```

The Tkinter window opens. If no display is available:
```
2026-03-03 17:24:12 | INFO     | Starting text menu (headless / SSH mode)

  ┌─────────────────────────────────────┐
  │  CyberDeck — Select a module        │
  ├─────────────────────────────────────┤
  │  1. anomaly_detect                  │
  │  2. arp_monitor                     │
  ...
```

---

## 7. Raspberry Pi 4 Deployment

### 7.1 Flash the OS

1. Download Raspberry Pi Imager from https://www.raspberrypi.com/software/
2. Insert your microSD card.
3. Choose OS: **Kali Linux (ARM 64-bit)** or **Raspberry Pi OS (64-bit)**.
4. In Imager settings (gear icon), configure:
   - Hostname: `cyberdeck`
   - SSH: Enable
   - Username/password: set your credentials
   - WiFi (optional): if you want headless first boot
5. Flash to the microSD card.
6. Insert the card into the Pi and power on.

### 7.2 First connection (headless)

Find the Pi's IP address from your router's admin panel, then:

```bash
ssh pi@192.168.X.Y   # replace with actual IP
```

### 7.3 Deploy CyberDeck

On the Pi:

```bash
# Install git first
sudo apt update && sudo apt install -y git

# Clone the repository
git clone git@github.com:Stevenyoumbi99/cyberdeck.git
cd cyberdeck

# Run the setup script
sudo bash scripts/setup_env.sh
```

Or use the automated deploy script from your development machine:

```bash
# On your dev machine (not the Pi)
sudo bash scripts/deploy.sh
```

### 7.4 Configure for Pi hardware

Edit `config/config.json`:

```json
"network": {
    "lan_interface":           "eth0",
    "wifi_interface":          "wlan1",
    "wifi_monitor_interface":  "wlan1mon",
    "bluetooth_interface":     "hci0",
    "target_subnet":           "192.168.X.0/24"
}
```

Verify interface names on the Pi:
```bash
ip link show           # ethernet and WiFi interfaces
hciconfig              # Bluetooth adapter
```

### 7.5 Auto-start on boot (optional)

To have CyberDeck launch automatically when the Pi boots to a desktop:

```bash
mkdir -p ~/.config/autostart
cat > ~/.config/autostart/cyberdeck.desktop << EOF
[Desktop Entry]
Type=Application
Name=CyberDeck
Exec=sudo python3 /home/pi/cyberdeck/launcher.py
EOF
```

---

## 8. Hardware Setup (Pi)

### 8.1 USB WiFi Adapter (for wifi_audit)

1. Plug in the USB WiFi adapter.
2. Verify it appears as `wlan1`:
   ```bash
   iwconfig
   ```
3. Verify it supports monitor mode:
   ```bash
   iw list | grep "monitor"
   # Should show: * monitor
   ```
4. Test enabling monitor mode:
   ```bash
   sudo airmon-ng start wlan1
   # Should create wlan1mon
   ```

> If the adapter does not appear as `wlan1`, update `config.json` →
> `network.wifi_interface` to the correct interface name.

### 8.2 Bluetooth (for bluetooth_recon)

The Pi 4's built-in Bluetooth controller is used. Verify it is active:

```bash
hciconfig
# Should show: hci0    Type: Primary  Bus: UART
#              BD Address: XX:XX:XX:XX:XX:XX  ACL MTU: ...
#              UP RUNNING PSCAN
```

If it shows as DOWN:
```bash
sudo hciconfig hci0 up
```

### 8.3 Touchscreen (optional)

The official Raspberry Pi 7" touchscreen connects via DSI ribbon cable and works
out of the box with Raspberry Pi OS. The Tkinter GUI is automatically detected and
launched when the touchscreen is active.

For third-party HDMI displays, connect before boot — `_has_display()` in
`launcher.py` probes at startup.

---

## 9. Verifying the Installation

Run these checks after setup to confirm everything is working:

### 9.1 Python and dependencies

```bash
python3 --version            # Should be 3.10+
python3 -c "import flask; print(flask.__version__)"
python3 -c "import scapy; print('scapy OK')"
python3 -c "import numpy; print('numpy OK')"
python3 -c "import sklearn; print('sklearn OK')"
python3 -c "import tkinter; print('tkinter OK')"
```

### 9.2 System tools

```bash
nmap --version | head -1
nikto -Version
enum4linux 2>&1 | head -3
hciconfig                    # Pi only
airmon-ng --help | head -3   # Pi only
```

### 9.3 CyberDeck configuration

```bash
python3 -c "from utils.config_loader import load_config; c = load_config(); print('Config OK:', c['project']['version'])"
```

### 9.4 Run a test scan

```bash
sudo python3 launcher.py
```

Select **LAN SCAN** from the menu or GUI. A result file should appear in `results/`:

```bash
ls -la results/
# lan_scan_2026-03-03T17-24-12-059841.json
```

---

## 10. Uninstallation

### Remove the project directory

```bash
rm -rf ~/cyberdeck
```

### Remove Python packages (optional)

```bash
pip3 uninstall flask jinja2 scapy numpy scikit-learn requests
```

### Remove system packages (optional)

```bash
sudo apt remove nmap tshark nikto enum4linux bluez aircrack-ng
```
