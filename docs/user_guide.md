# CyberDeck — User Guide

> Step-by-step instructions for operators using the CyberDeck audit platform.
> This guide covers both the graphical interface (GUI) and the text menu (SSH/headless).
> Last updated: March 2026 — reflects v1.0.0.

---

## Table of Contents

1. [Starting CyberDeck](#1-starting-cyberdeck)
2. [Graphical Interface (GUI Mode)](#2-graphical-interface-gui-mode)
3. [Text Menu (Headless / SSH Mode)](#3-text-menu-headless--ssh-mode)
4. [Audit Modules — What Each One Does](#4-audit-modules--what-each-one-does)
5. [The Live Dashboard](#5-the-live-dashboard)
6. [Viewing Individual Scan Details](#6-viewing-individual-scan-details)
7. [Generating an HTML Audit Report](#7-generating-an-html-audit-report)
8. [Understanding Results](#8-understanding-results)
9. [Troubleshooting Common Issues](#9-troubleshooting-common-issues)

---

## 1. Starting CyberDeck

### Standard start

Open a terminal in the project directory and run:

```bash
sudo python3 launcher.py
```

> Root privileges (`sudo`) are required for packet capture modules (Scapy) and
> WiFi monitor mode. Non-capture modules work without root, but running with
> sudo ensures all modules function correctly.

### What happens at startup

1. The system prints the CyberDeck banner and initializes logging.
2. It checks whether a graphical display is available:
   - **Display found** → the Tkinter GUI window opens automatically.
   - **No display** (SSH, headless Pi) → the text menu appears in the terminal.
3. All scan results are saved to the `results/` directory as JSON files.
4. All activity is logged to `logs/cyberdeck.log`.

---

## 2. Graphical Interface (GUI Mode)

The GUI launches automatically when a display is available (desktop VM or Pi with
a screen attached).

### 2.1 Window Layout

```
┌──────────────────────────────────────────────────────────────┐
│  CYBER DECK                               v1.0.0 | MSc Cyber │
├──────────────────┬───────────────────────────────────────────┤
│  AUDIT MODULES   │  SCAN OUTPUT                               │
│                  │                                            │
│  [ANOMALY DETECT]│  [17:24:12] CyberDeck v1.0.0 ready.       │
│  [ARP MONITOR   ]│  [17:24:12] Select a module to begin.     │
│  [BLUETOOTH RECON│  [17:27:46] Starting LAN SCAN...          │
│  [LAN SCAN      ]│  [17:27:52] INFO    4 hosts found         │
│  [PASSIVE MONITOR│  [17:27:52] lan_scan complete — ready.    │
│  [PENTEST TOOLS ]│                                            │
│  [TLS AUDIT     ]│                                            │
│  [WIFI AUDIT    ]│                                            │
│  ──────────────  │                                            │
│  [DASHBOARD     ]│                                            │
│  [GENERATE REPORT│                                            │
│  [QUIT          ]│                                            │
├──────────────────┴───────────────────────────────────────────┤
│  Ready  |  Last scan: lan_scan  17:27:52                      │
└──────────────────────────────────────────────────────────────┘
```

### 2.2 Sidebar Buttons

| Button            | Action                                                        |
|-------------------|---------------------------------------------------------------|
| Module buttons    | Run that scan module; all buttons disabled while running      |
| `DASHBOARD`       | Start the Flask web server and open the dashboard in a browser |
| `GENERATE REPORT` | Generate an HTML audit report from all results and open it    |
| `QUIT`            | Close CyberDeck cleanly                                       |

### 2.3 Running a Scan

1. Click any module button (e.g. **LAN SCAN**).
2. All buttons are disabled while the scan runs — this prevents running two scans
   simultaneously.
3. The **SCAN OUTPUT** panel streams all log messages from the scan in real time,
   colour-coded by severity:
   - White — normal progress messages (INFO)
   - Amber — warnings (WARNING)
   - Red — errors (ERROR / CRITICAL)
   - Cyan — system messages (scan started, finished)
   - Green — success confirmation
4. When the scan finishes:
   - Buttons are re-enabled.
   - The status bar shows: `Ready | Last scan: lan_scan  17:27:52`
   - A result file is saved to `results/`.

### 2.4 Dashboard Button

Clicking **DASHBOARD**:
1. Starts the Flask web server in a background thread.
2. After 1.5 seconds (to let Flask bind to the port), automatically opens
   `http://localhost:5000` in your default browser.
3. If clicked again while the dashboard is already running, reopens the browser
   tab without starting a second server.

### 2.5 Generate Report Button

Clicking **GENERATE REPORT**:
1. Reads all scan result files from `results/`.
2. Deduplicates (keeps only the most recent result per module).
3. Renders a self-contained HTML report.
4. Saves it to `results/report_<timestamp>.html`.
5. Opens the report automatically in your default browser.

---

## 3. Text Menu (Headless / SSH Mode)

Appears automatically when no display is detected (SSH session or headless Pi).

### 3.1 Menu appearance

```
==================================================
  CyberDeck — Select a module
==================================================

  1. anomaly_detect
  2. arp_monitor
  3. bluetooth_recon
  4. lan_scan
  5. passive_monitor
  6. pentest_tools
  7. tls_audit
  8. wifi_audit
  9. dashboard

  0. Quit

Enter number:
```

### 3.2 Running a scan

1. Type the number next to the module you want to run and press **Enter**.
2. The scan runs synchronously — the terminal shows all log output.
3. When complete, the result is saved and the menu reappears.

### 3.3 Running the dashboard (text mode)

Select **9. dashboard**. Flask starts and logs:
```
2026-03-03 17:27:54 | INFO     | Starting dashboard on http://0.0.0.0:5000
2026-03-03 17:27:54 | INFO     | Open a browser on any device connected to
                                  this network and go to http://<IP>:5000
```

Open `http://<cyberdeck-ip>:5000` in any browser on your network.

Press **Ctrl+C** in the terminal to stop the dashboard and return to the menu.

### 3.4 Generating a report (text mode)

There is no separate report command in the text menu — generate reports from the
dashboard's **GENERATE HTML REPORT** button, or by running the generate report
functionality while the dashboard is open.

---

## 4. Audit Modules — What Each One Does

### 4.1 LAN Scan (`lan_scan`)

**What it does:** Discovers all active hosts on the network using Nmap. For each
host, it records the IP address, MAC address, hardware vendor (from OUI database),
hostname (via reverse DNS), and open ports.

**When to run it:** First — run LAN Scan before any other module. Several other
modules (`tls_audit`, `pentest_tools`) depend on the LAN Scan result to know which
hosts to target.

**What to look for:**
- Unexpected hosts (devices you don't recognize)
- Unusual open ports (especially: 22 SSH, 23 Telnet, 3389 RDP, 4444 Metasploit)
- High port counts on a single host

**Expected duration:** 15–60 seconds depending on subnet size and `lan_scan_timeout`
in config.

---

### 4.2 Passive Monitor (`passive_monitor`)

**What it does:** Listens passively on the network interface for `passive_capture_duration`
seconds (default: 60) and records all IP traffic without sending any packets. Shows
unique IP addresses seen and protocols used.

**When to run it:** During active network use to see what devices are communicating.

**What to look for:**
- IPs not found by LAN Scan (devices that are powered on but not responding to ping)
- Unexpected protocols (e.g. Telnet on port 23)
- High packet counts from a single source (potential scanner or malware)

**Expected duration:** Exactly `passive_capture_duration` seconds (default: 60).

---

### 4.3 ARP Monitor (`arp_monitor`)

**What it does:** Listens for ARP traffic and detects ARP spoofing attacks — where
one device claims to be another by advertising a fake MAC address for a known IP.
This is the basis of man-in-the-middle (MITM) attacks.

**When to run it:** Run during active network activity to catch spoofing in progress.

**What to look for:**
- Any **conflicts** — two different MAC addresses claiming the same IP is a strong
  indicator of ARP spoofing or misconfiguration.

**Expected duration:** 30–60 seconds (captures ARP traffic during that window).

---

### 4.4 Anomaly Detect (`anomaly_detect`)

**What it does:** Reads all historical scan results and applies statistical analysis
to detect unusual behaviour compared to what is normal for this network.

Two detection layers:
1. **Static rules** — always-on checks for known bad indicators (dangerous ports
   like 4444/Metasploit, unusually high port counts >20, new unknown hosts).
2. **Statistical** — Z-score comparison against a saved baseline. Values more than
   2.5 standard deviations from the mean are flagged as anomalies.

**When to run it:** After several LAN Scans have been performed (the baseline needs
at least `min_samples` data points to be reliable — default: 50).

**What to look for:**
- HIGH severity anomalies — immediate investigation required
- New hosts appearing that were not in the baseline
- Sudden increase in open ports on a known host

**Expected duration:** A few seconds (reads existing files, no network activity).

---

### 4.5 TLS Audit (`tls_audit`)

**What it does:** Reads the most recent LAN Scan result, identifies hosts with HTTPS
ports (443, 8443), and connects to each to inspect their SSL/TLS certificate and
negotiated protocol version.

**Checks performed:**
- Certificate expiry date (warns if < 30 days remaining, flags if already expired)
- Certificate validity dates (not yet valid)
- Hostname verification (does the certificate match the host's IP/hostname)
- TLS protocol version (flags TLS 1.0 and 1.1 as deprecated/insecure)
- Self-signed certificate detection

**When to run it:** After LAN Scan, whenever HTTPS services are present on the network.

**What to look for:**
- Expired or near-expiry certificates (service disruption risk)
- TLS 1.0/1.1 in use (vulnerable to known attacks — POODLE, BEAST)
- Self-signed certificates (no trusted CA validation — MITM risk)

**Expected duration:** 5–30 seconds depending on the number of HTTPS hosts.

---

### 4.6 Pentest Tools (`pentest_tools`)

**What it does:** Runs three penetration testing tools against discovered hosts:

| Tool         | What it does                                              |
|--------------|-----------------------------------------------------------|
| **Nmap**     | Deep port scan with service version detection             |
| **Nikto**    | Web server vulnerability scanner — checks for known CVEs, misconfigurations |
| **Enum4Linux**| Windows/Samba enumeration — enumerates shares, users, OS info via SMB |

**When to run it:** After LAN Scan, when you want detailed vulnerability information.

**What to look for:**
- Open services with known vulnerabilities (Nikto findings)
- Exposed SMB shares or user accounts (Enum4Linux findings)
- Unexpected services running on non-standard ports (Nmap version findings)

**Expected duration:** 2–10 minutes depending on the number of hosts and open ports.

---

### 4.7 WiFi Audit (`wifi_audit`) — Pi Only

**What it does:** Puts the USB WiFi adapter into monitor mode and passively captures
802.11 management frames to discover all wireless networks in range. Records SSID,
BSSID, channel, signal strength, and encryption type.

**Requires:** USB WiFi adapter supporting monitor mode connected as `wlan1`.
**Will fail on VMware** — there is no wlan1 interface in a standard VM.

**What to look for:**
- Open networks (no encryption)
- WEP encryption (broken — trivially crackable)
- Evil twin / rogue access points (same SSID as a known AP but different BSSID)
- Hidden SSIDs (show as blank — investigate)

**Expected duration:** `wifi_scan_duration` seconds (default: 15).

---

### 4.8 Bluetooth Recon (`bluetooth_recon`) — Pi Only

**What it does:** Performs a Bluetooth inquiry scan using the Pi's built-in
Bluetooth adapter (hci0) to discover nearby discoverable Bluetooth devices. Records
device name, address, device class, and supported services.

**Requires:** Pi built-in Bluetooth (hci0).
**Will fail on VMware** — there is no hci0 interface in a standard VM.

**What to look for:**
- Unauthorized Bluetooth devices in a secured area
- Devices advertising sensitive services (file transfer, serial port)
- Unknown device classes

**Expected duration:** `bluetooth_scan_duration` seconds (default: 10).

---

## 5. The Live Dashboard

The dashboard is a real-time web interface showing all scan results.

### 5.1 Opening the dashboard

**GUI:** Click **DASHBOARD** in the sidebar. The browser opens automatically.

**Text menu:** Select **9. dashboard**, then open `http://localhost:5000` in a browser.
From another device on the same network: `http://<cyberdeck-ip>:5000`.

### 5.2 Dashboard sections

**Summary cards (top):**

| Card            | What it shows                                           |
|-----------------|---------------------------------------------------------|
| Result Files    | Total number of scan result JSON files in `results/`   |
| Hosts Found     | Total hosts discovered across all LAN Scan results     |
| Issues          | Total combined issues (TLS + ARP conflicts + anomalies)|
| ARP Conflicts   | Total ARP conflicts detected                           |
| Anomalies       | Total anomalies flagged                                |

**Scan Results table:**

Shows all result files sorted **newest first** (by file modification time).
Columns: Module, Timestamp, Status badge, Summary, File link.

- Click the file link (e.g. `lan_scan_2026-03-03T17-24-12.json`) to open a
  formatted detail page for that specific scan.

**Generated Reports section:**

Lists all previously generated HTML report files. Click **Open report →** to view
any report in the browser.

### 5.3 Auto-refresh

The dashboard page automatically refreshes every **30 seconds**. This means if you
run a new scan from the GUI while the dashboard is open, the dashboard will pick it
up within 30 seconds without manual refresh.

---

## 6. Viewing Individual Scan Details

Clicking a filename link in the dashboard opens a dedicated detail page for that
scan at `http://localhost:5000/result/<filename>`.

This page shows the scan data in formatted tables specific to each module:

| Module            | What the detail page shows                                    |
|-------------------|---------------------------------------------------------------|
| LAN Scan          | Table: IP, MAC, Vendor, Hostname                             |
| Passive Monitor   | Capture stats + IP table + protocols table                   |
| ARP Monitor       | Packets analysed, conflicts count, conflict details table    |
| TLS Audit         | Per-host findings with issue severity badges                 |
| Anomaly Detect    | Stats + anomalies table (source, metric, value, threshold)   |
| Pentest Tools     | Nmap table (IP/Port/Protocol/Service/State/Version), Nikto, Enum4Linux |
| WiFi Audit        | Networks table (SSID/BSSID/Channel/Signal/Encryption)        |
| Bluetooth Recon   | Devices table (Name/Address/Class/Services)                  |

A **← Back to Dashboard** link at the top returns to the main dashboard.

---

## 7. Generating an HTML Audit Report

The HTML report is a self-contained file suitable for sharing with a client or
supervisor. It includes all findings from the most recent run of each module.

### 7.1 From the GUI

Click **GENERATE REPORT** in the sidebar. The report opens automatically in your
browser when ready.

### 7.2 From the dashboard browser

Click the **GENERATE HTML REPORT** button at the top of the dashboard page.
A link appears when the report is ready — click it to open.

### 7.3 Report contents

- **Header** with CyberDeck branding and generation timestamp
- **Risk banner**: RED (high severity issues found) / AMBER (medium) / GREEN (clean)
- **Summary statistics**: hosts, issues, high/medium counts, anomalies, conflicts
- **One section per module** with formatted tables and severity badges
- All CSS is inline — no internet required to view the report

### 7.4 Finding reports

Reports are saved to `results/report_<timestamp>.html`. They are also listed in
the **Generated Reports** section at the bottom of the dashboard.

---

## 8. Understanding Results

### 8.1 Status badges

| Badge     | Colour | Meaning                                           |
|-----------|--------|---------------------------------------------------|
| SUCCESS   | Green  | Scan completed with no errors                     |
| PARTIAL   | Amber  | Scan completed but some sub-tasks failed          |
| ERROR     | Red    | Scan failed — check the errors section            |

### 8.2 Result files

Every scan saves a JSON file to `results/` named:
```
<module>_<year>-<month>-<day>T<hour>-<min>-<sec>-<microsec>.json
```

Example: `lan_scan_2026-03-03T17-24-12-059841.json`

These files are read by the dashboard, the report generator, and the anomaly
detector. Do not rename or delete them during an active audit session.

### 8.3 The anomaly detection baseline

`results/baseline.json` is created automatically by `anomaly_detect`. It contains
the statistical baseline (mean, standard deviation) of normal network behaviour.
Do not delete it — it takes many scans to build.

---

## 9. Troubleshooting Common Issues

### CyberDeck starts but no GUI window appears

**Symptom:** The system prints "Display detected" but no window opens.

**Cause:** Tkinter is not installed or the display is not fully initialised.

**Fix:**
```bash
sudo apt install python3-tk
python3 -c "import tkinter; tkinter.Tk()"
```

If the second command shows a blank window, Tkinter is working and the issue is
elsewhere. If it prints an error, install python3-tk and retry.

---

### LAN Scan finds 0 hosts

**Symptom:** `lan_scan` reports `0 hosts found`.

**Causes and fixes:**
1. **Wrong interface** — check `config.json` → `network.lan_interface`.
   ```bash
   ip link show
   ip route
   ```
   Set `lan_interface` to the interface connected to your target network.

2. **Wrong subnet** — check `config.json` → `network.target_subnet`.
   ```bash
   ip route | grep -v default
   # Shows your actual subnet
   ```

3. **Not running as root** — Nmap ARP discovery requires root.
   ```bash
   sudo python3 launcher.py
   ```

---

### Dashboard port already in use

**Symptom:** Dashboard fails with `OSError: [Errno 98] Address already in use`.

**Fix:**
```bash
# Find what is using port 5000
sudo lsof -i :5000

# Kill it or change the port in config.json
"dashboard": { "port": 8080 }
```

---

### WiFi audit fails: "airmon-ng failed"

**Symptom:** `wifi_audit` reports `airmon-ng failed to enable monitor mode on wlan1`.

**Causes:**
- Running on VMware (no wlan1 interface) — expected behaviour, not a bug.
- USB WiFi adapter not connected to the Pi.
- Adapter does not support monitor mode.

**Fix for Pi:**
```bash
iwconfig          # confirm wlan1 exists
sudo airmon-ng check kill     # kill processes that block monitor mode
sudo airmon-ng start wlan1    # manually test monitor mode
```

---

### Bluetooth recon fails: "Bad file descriptor"

**Symptom:** `bluetooth_recon` reports `Error communicating with local bluetooth adapter`.

**Causes:**
- Running on VMware (no hci0) — expected behaviour, not a bug.
- Bluetooth service not running on the Pi.

**Fix for Pi:**
```bash
sudo systemctl start bluetooth
sudo hciconfig hci0 up
hciconfig    # verify hci0 is UP RUNNING
```

---

### Report generation fails: "No result files found"

**Symptom:** Clicking Generate Report shows this error.

**Fix:** Run at least one scan module first. The report requires at least one valid
result file in `results/`.

---

### Anomaly detect: "Not enough samples for statistical analysis"

**Symptom:** `anomaly_detect` runs but reports no statistical anomalies.

**Cause:** The baseline has fewer samples than `anomaly.min_samples` (default: 50).

**Fix:** Run more LAN Scans to build the baseline. For testing, temporarily lower
`min_samples` in `config.json`:
```json
"anomaly": { "min_samples": 5 }
```

---

### Log file grows too large

The log file at `logs/cyberdeck.log` automatically rotates at 5 MB (default) and
keeps 3 backup files. To clear logs manually:

```bash
truncate -s 0 logs/cyberdeck.log
rm -f logs/cyberdeck.log.1 logs/cyberdeck.log.2 logs/cyberdeck.log.3
```

To change the rotation settings:
```json
"logging": {
    "max_file_size_mb": 10,
    "backup_count": 5
}
```
