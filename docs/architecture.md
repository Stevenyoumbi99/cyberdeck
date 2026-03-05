# CyberDeck — System Architecture

> This document describes the complete system design, data flow, module contract,
> configuration schema, logging architecture, and key architectural decisions.
> Last updated: March 2026 — reflects v1.0.0 as implemented.

---

## Table of Contents

1. [System Overview](#1-system-overview)
2. [Directory Structure](#2-directory-structure)
3. [Boot Sequence & Data Flow](#3-boot-sequence--data-flow)
4. [Interface Modes](#4-interface-modes)
5. [Module Contract](#5-module-contract)
6. [Result Contract](#6-result-contract)
7. [Configuration Schema](#7-configuration-schema)
8. [Logging Architecture](#8-logging-architecture)
9. [Dashboard & Reporting Architecture](#9-dashboard--reporting-architecture)
10. [Hardware-to-Module Mapping](#10-hardware-to-module-mapping)
11. [Architectural Decisions](#11-architectural-decisions)

---

## 1. System Overview

CyberDeck is a portable, self-contained cybersecurity audit platform built on a
Raspberry Pi 4 running Kali Linux. It is designed to be plugged into any network
and immediately begin scanning, with results accessible via a local web dashboard
and exportable as HTML audit reports.

**Key design principles:**

- **No internet required at runtime** — all tools, dependencies, and templates are
  bundled on the device. Reports and dashboards are self-contained HTML files.
- **Single entry point** — `launcher.py` is the only script the operator ever runs.
  It handles display detection, config loading, logging, and interface selection.
- **Uniform module interface** — every scan module implements exactly one function:
  `run(config) -> dict`. The launcher calls this function identically regardless of
  which module is selected.
- **Separation of concerns** — modules only perform scans. Saving results, logging,
  and rendering are handled by utilities (`utils/`) outside the modules.
- **Dual interface** — a Tkinter GUI launches automatically when a display is
  present; the system transparently falls back to a text menu over SSH/headless.

---

## 2. Directory Structure

```
cyberdeck/
│
├── launcher.py              # Single entry point — boots the system, chooses interface
├── menu.py                  # Text menu for headless / SSH mode
│
├── config/
│   └── config.json          # All runtime settings (network, scan, logging, etc.)
│
├── modules/                 # Scan and service modules (one file per capability)
│   ├── __init__.py
│   ├── lan_scan.py          # Phase 1 — Nmap host and port discovery
│   ├── passive_monitor.py   # Phase 2 — Passive packet capture (Scapy)
│   ├── arp_monitor.py       # Phase 3 — ARP spoofing / conflict detection
│   ├── anomaly_detect.py    # Phase 4 — Z-score / Isolation Forest anomaly detection
│   ├── tls_audit.py         # Phase 5 — SSL/TLS certificate and protocol audit
│   ├── pentest_tools.py     # Phase 6 — Nmap deep scan, Nikto, Enum4Linux
│   ├── wifi_audit.py        # Phase 7 — 802.11 wireless network discovery (Pi only)
│   ├── bluetooth_recon.py   # Phase 7 — Bluetooth device discovery (Pi only)
│   └── dashboard.py         # Phase 9 — Flask live web dashboard (not a scan module)
│
├── ui/                      # Graphical interface (Tkinter)
│   ├── __init__.py
│   └── launcher_gui.py      # Phase 10 — Full GUI with sidebar, log panel, threading
│
├── utils/                   # Shared utilities used by all modules
│   ├── __init__.py
│   ├── config_loader.py     # Loads and validates config/config.json
│   ├── logger.py            # Initializes the shared "cyberdeck" named logger
│   ├── result_handler.py    # Saves result dicts to timestamped JSON files
│   └── report_generator.py  # Renders HTML audit reports from result files (Jinja2)
│
├── scripts/
│   ├── setup_env.sh         # Installs all system and Python dependencies
│   └── deploy.sh            # Raspberry Pi deployment helper
│
├── results/                 # Auto-created at runtime — scan results and reports
│   ├── lan_scan_<ts>.json
│   ├── report_<ts>.html
│   └── baseline.json        # Anomaly detection statistical baseline
│
├── logs/
│   └── cyberdeck.log        # Rotating log file (5 MB max, 3 backups)
│
├── docs/
│   ├── architecture.md      # This file
│   ├── installation.md
│   ├── user_guide.md
│   └── workflow.md
│
└── requirements.txt         # Python package dependencies
```

---

## 3. Boot Sequence & Data Flow

### 3.1 Startup (launcher.py `main()`)

```
launcher.py::main()
│
├─ [1] load_config()
│       Reads config/config.json → returns validated dict
│       FATAL if missing or malformed — system cannot start without config
│
├─ [2] init_logger(config)
│       Attaches console + rotating file handlers to "cyberdeck" logger
│       All subsequent output goes through this logger
│
├─ [3] _has_display()
│       Probes Tkinter by creating and immediately destroying a root window
│       True  → launch CyberDeckGUI(config).run()   [GUI mode, blocks]
│       False → enter text menu loop                  [headless/SSH mode]
│
└─ [4] Text menu loop (headless only)
        while True:
            selected = show_menu()       # blocks on user input
            if selected is None: exit    # user chose Quit
            run_module(selected, config) # import + run + save
```

### 3.2 Module Execution Cycle

```
run_module(module_name, config)
│
├─ importlib.import_module("modules.<module_name>")
│       Dynamic import — module name is known only at runtime
│
├─ module.run(config)  →  result dict
│       The module performs its scan and returns a standardized dict
│       (see Section 5 — Module Contract)
│
└─ save_result(result, config)
        Writes result as:
        results/<module_name>_<timestamp>.json
        e.g. results/lan_scan_2026-03-03T17-24-12-059841.json
```

### 3.3 GUI Module Execution (Tkinter)

In GUI mode the same logic applies but runs in a **background thread** to keep
the UI responsive:

```
Main thread (Tkinter event loop)
│
│   User clicks [LAN SCAN]
│       │
│       └─ _on_module_click("lan_scan")
│               Disables all buttons
│               Spawns daemon worker thread
│
Worker thread
│   module.run(config) → result
│   save_result(result, config)
│   logger.info(...)        ← goes to _QueueHandler → queue.Queue
│   root.after(0, _on_scan_done)  ← schedules UI update on main thread
│
Main thread (via root.after polling every 100ms)
│   _poll_queue() — drains queue, appends lines to log Text widget
│   _on_scan_done() — re-enables buttons, updates status bar
```

---

## 4. Interface Modes

### 4.1 Graphical Interface (GUI mode)

Activated when `_has_display()` returns `True` (desktop VM or Pi with screen).

**File:** `ui/launcher_gui.py` — class `CyberDeckGUI`

**Layout:**
```
┌─────────────────────────────────────────────────────────────┐
│  CYBER DECK                              v1.0.0 | MSc Cyber │  ← header
├──────────────┬──────────────────────────────────────────────┤
│ AUDIT MODULES│  SCAN OUTPUT                                  │
│              │                                               │
│ [ANOMALY   ] │  [17:24:12] CyberDeck v1.0.0 ready.          │
│ [ARP MONITOR]│  [17:24:12] Select a module to begin.        │
│ [BLUETOOTH ] │  [17:24:46] Starting LAN SCAN...             │
│ [LAN SCAN  ] │  [17:24:52] lan_scan finished — success       │
│ [PASSIVE   ] │                                               │
│ [PENTEST   ] │                                               │
│ [TLS AUDIT ] │                                               │
│ [WIFI AUDIT] │                                               │
│ ─────────── │                                               │
│ [DASHBOARD ] │                                               │
│ [REPORT    ] │                                               │
│ [QUIT      ] │                                               │
├──────────────┴──────────────────────────────────────────────┤
│  Ready  |  Last scan: lan_scan  17:24:52                     │  ← status bar
└─────────────────────────────────────────────────────────────┘
```

**Thread-safe logging:** A custom `_QueueHandler` (subclass of `logging.Handler`)
is attached to the "cyberdeck" logger. Every `logger.info()` call anywhere in the
system puts a `(level, message)` tuple into a `queue.Queue`. The main thread polls
this queue every 100 ms via `root.after(100, _poll_queue)` and appends lines to
the read-only `tk.Text` log panel. This is the only safe way to update Tkinter
widgets from background threads.

### 4.2 Text Menu (headless / SSH mode)

Activated when no display is detected (SSH session, no `$DISPLAY`).

**File:** `menu.py` — function `show_menu()`

Displays a numbered list of available modules, reads a number from stdin, returns
the module name string. Returns `None` when the user enters `0` (Quit).

Module discovery is automatic: `menu.py` and `ui/launcher_gui.py` both scan the
`modules/` directory for `.py` files at startup, excluding `__init__.py` and
`dashboard.py` (which has its own dedicated button/entry).

---

## 5. Module Contract

Every file in `modules/` (except `__init__.py` and `dashboard.py`) must implement
exactly one public function:

```python
def run(config: dict) -> dict:
    """
    Execute the scan and return a standardized result dict.

    Args:
        config: The full config dict loaded from config/config.json.
                The module reads only the keys it needs.

    Returns:
        dict: Standardized result (see Section 6 — Result Contract).
    """
```

**Rules:**
- The module must **not** call `save_result()` — that is the launcher's job.
- The module must **not** call `init_logger()` — logging is already configured.
- The module should use `logging.getLogger("cyberdeck")` to log progress.
- The module must return a result dict even on failure (use `status: "error"`
  and populate the `errors` list).
- The module must never call `sys.exit()`.

---

## 6. Result Contract

Every module returns a dict with this exact schema:

```json
{
  "module":    "lan_scan",
  "timestamp": "2026-03-03T17:24:12.059841",
  "status":    "success",
  "data":      { ... },
  "errors":    []
}
```

| Field       | Type   | Values                              | Description                        |
|-------------|--------|-------------------------------------|------------------------------------|
| `module`    | string | e.g. `"lan_scan"`                   | Must match the filename (no `.py`) |
| `timestamp` | string | ISO 8601 with microseconds          | Set by the module at scan time     |
| `status`    | string | `"success"` / `"error"` / `"partial"` | `"partial"` = some data, some errors |
| `data`      | dict   | Module-specific                     | All scan findings                  |
| `errors`    | list   | List of error strings               | Empty `[]` on full success         |

**Filename generated by `save_result()`:**
```
results/lan_scan_2026-03-03T17-24-12-059841.json
                 ─────── ──────────────────────
                 module  timestamp (colons/dots replaced with dashes)
```

### Module-specific `data` schemas

| Module             | Key fields in `data`                                                      |
|--------------------|---------------------------------------------------------------------------|
| `lan_scan`         | `hosts_found`, `hosts[]` (ip, mac, vendor, hostname)                      |
| `passive_monitor`  | `total_packets`, `unique_ips[]`, `protocols{}`                            |
| `arp_monitor`      | `packets_analysed`, `conflicts_found`, `conflicts[]`                      |
| `anomaly_detect`   | `method`, `samples_analysed`, `anomalies_found`, `anomalies[]`            |
| `tls_audit`        | `hosts_audited`, `findings[]` (host, subject, issuer, tls_version, issues[]) |
| `pentest_tools`    | `nmap{}` (findings[], targets_scanned), `nikto{}`, `enum4linux{}`         |
| `wifi_audit`       | `networks_found`, `networks[]` (ssid, bssid, channel, signal, encryption) |
| `bluetooth_recon`  | `devices_found`, `devices[]` (name, address, device_class, services[])    |

---

## 7. Configuration Schema

**File:** `config/config.json`

```jsonc
{
  "project": {
    "name": "CyberDeck",
    "version": "1.0.0"
  },

  "network": {
    "lan_interface":           "eth0",      // Wired interface for LAN scanning
    "wifi_interface":          "wlan1",     // USB WiFi adapter (Pi only)
    "wifi_monitor_interface":  "wlan1mon",  // Monitor mode interface created by airmon-ng
    "bluetooth_interface":     "hci0",      // Bluetooth adapter (Pi built-in)
    "target_subnet":           "192.168.88.0/24"  // Network range to scan
  },

  "scan": {
    "lan_scan_timeout":        30,   // seconds — Nmap host discovery timeout
    "port_range":              "1-1024",  // Port range for Nmap
    "wifi_scan_duration":      15,   // seconds — passive 802.11 capture
    "bluetooth_scan_duration": 10,   // seconds — Bluetooth inquiry scan
    "passive_capture_duration":60    // seconds — Scapy packet capture
  },

  "anomaly": {
    "dev_mode":       false,          // true = use mock data (no nmap needed)
    "method":         "zscore",       // "zscore" or "isolation_forest"
    "threshold":      2.5,            // Z-score cutoff for flagging outliers
    "baseline_file":  "results/baseline.json",  // path to statistical baseline
    "min_samples":    50              // minimum samples before ML detection
  },

  "output": {
    "results_dir":   "results/",     // where scan JSON files are saved
    "logs_dir":      "logs/",        // where cyberdeck.log is written
    "report_format": "html"          // currently only "html" is supported
  },

  "logging": {
    "level":           "INFO",       // DEBUG / INFO / WARNING / ERROR
    "log_to_file":     true,         // write to logs/cyberdeck.log
    "log_to_console":  true,         // print to stdout
    "max_file_size_mb": 5,           // rotate log file at this size
    "backup_count":    3             // keep this many rotated log files
  },

  "dashboard": {
    "host": "0.0.0.0",  // bind to all interfaces (accessible on LAN)
    "port": 5000        // Flask HTTP port
  },

  "osint": {
    "dev_mode":          false,
    "enable_external":   true,
    "allowed_domains":   ["tesla.com", "mit.edu", "owasp.org"],
    "dns_enabled":       true,
    "whois_enabled":     true,
    "ct_enabled":        true,
    "harvester_enabled": true,
    "harvester_timeout": 120,
    "maltego_export":    true
  }
}
```

All paths (`results_dir`, `logs_dir`, `baseline_file`) are relative to the project
root and resolved to absolute paths at runtime by each utility that uses them.

---

## 8. Logging Architecture

All logging in the project uses a single **named logger** called `"cyberdeck"`.

```
launcher.py
  └─ init_logger(config)
       │
       ├─ StreamHandler  → stdout   (if logging.log_to_console == true)
       │    format: "2026-03-03 17:24:12 | INFO     | message"
       │
       └─ RotatingFileHandler → logs/cyberdeck.log
            max size: 5 MB (default)
            backup count: 3 (cyberdeck.log.1, .2, .3)

Every module:
  logger = logging.getLogger("cyberdeck")  # same object, already configured
  logger.info("...")   # flows through both handlers automatically
```

**In GUI mode**, a third handler is added temporarily:

```
_QueueHandler (ui/launcher_gui.py)
  └─ puts (levelname, message) tuples into queue.Queue
       ↑                              ↓
  called from                   read by
  background threads             _poll_queue() on main thread
                                 every 100ms via root.after()
                                 → appended to log Text widget
```

The `logger.propagate = False` setting prevents log messages from also going to
the root Python logger (which would cause duplicates if Flask or Scapy configure
the root logger).

---

## 9. Dashboard & Reporting Architecture

### 9.1 Flask Dashboard (`modules/dashboard.py`)

The dashboard is a persistent Flask web server, not a scan module. It starts in a
background thread when the user clicks `[DASHBOARD]`.

**Routes:**

| Method | Route                    | Description                                          |
|--------|--------------------------|------------------------------------------------------|
| GET    | `/`                      | Main dashboard — loads all results, renders HTML     |
| GET    | `/api/results`           | JSON list of all result metadata (no `data` field)   |
| GET    | `/api/result/<filename>` | Full JSON body of one result file                    |
| GET    | `/result/<filename>`     | Human-readable HTML detail page for one scan         |
| POST   | `/api/report`            | Trigger report generation; returns `{filename}`      |
| GET    | `/reports/<filename>`    | Serve a previously generated HTML report             |

**Result ordering:** `_load_results()` sorts by `os.path.getmtime()` (newest first)
so the most recently run scan always appears at the top of the table, regardless of
module name alphabetical order.

**Baseline exclusion:** `_load_results()` skips any JSON file that does not contain
a `"module"` key. This prevents `baseline.json` (saved by `anomaly_detect`) from
causing Jinja2 `Undefined` serialization errors.

### 9.2 HTML Report Generator (`utils/report_generator.py`)

Generates a standalone, self-contained HTML file from all current scan results.

```
generate_report(results, config)
│
├─ _filter_for_report(results)
│    Deduplicate: keep only the newest result per module
│    Exclude: dashboard session records (module == "dashboard")
│    Exclude: results with empty data{}
│
├─ Aggregate statistics
│    total_hosts, total_issues, total_high, total_medium,
│    total_anomalies, total_conflicts
│
├─ jinja2.Environment.from_string(_HTML_TEMPLATE)
│    Renders module-specific sections:
│    lan_scan → host table
│    pentest_tools → nmap/nikto/enum4linux tables
│    tls_audit → findings cards
│    anomaly_detect → anomaly table
│    wifi_audit → SSID table
│    bluetooth_recon → device table
│
└─ Write to results/report_<ISO_timestamp>.html
     Self-contained: all CSS inline, no internet required
     Risk banner: RED (high issues) / AMBER (medium) / GREEN (clean)
```

---

## 10. Hardware-to-Module Mapping

| Module            | Required Hardware        | Works on VM? | Notes                              |
|-------------------|--------------------------|--------------|------------------------------------|
| `lan_scan`        | Ethernet (eth0)          | Yes          | Needs nmap installed               |
| `passive_monitor` | Any network interface    | Yes          | Needs Scapy + root                 |
| `arp_monitor`     | Any network interface    | Yes          | Needs Scapy + root                 |
| `anomaly_detect`  | None (reads results/)    | Yes          | Needs numpy + scikit-learn         |
| `tls_audit`       | Network access           | Yes          | Reads lan_scan results             |
| `pentest_tools`   | Network access           | Yes          | Needs nmap, nikto, enum4linux      |
| `wifi_audit`      | USB WiFi adapter (wlan1) | **No**       | Needs monitor mode + airmon-ng     |
| `bluetooth_recon` | Bluetooth adapter (hci0) | **No**       | Needs bluez + hci0 device          |
| `dashboard`       | None                     | Yes          | Reads results/, starts Flask       |

**WiFi and Bluetooth modules** are hardware-only and will log an error on VMware.
They are designed exclusively for the Raspberry Pi 4 with:
- A USB 802.11 adapter that supports monitor mode (e.g. Alfa AWUS036ACH)
- The Pi's built-in Bluetooth controller (hci0)

---

## 11. Architectural Decisions

### Why `importlib` for module loading?

Module names are selected by the user at runtime. Using `importlib.import_module()`
allows the launcher to load any module by name without hardcoding imports. This
makes adding a new module as simple as dropping a `.py` file in `modules/` — no
changes to `launcher.py` or `menu.py` required.

### Why a single named logger?

`logging.getLogger("cyberdeck")` always returns the same object. `init_logger()`
attaches handlers once in `launcher.py`. Every module then calls
`logging.getLogger("cyberdeck")` and automatically writes to the same console and
file handlers without any additional setup. This is the standard Python pattern for
library/application logging.

### Why `queue.Queue` for GUI logging?

Tkinter is **not thread-safe** — calling any widget method from a background thread
causes race conditions and random crashes. The queue pattern is the canonical
solution: background threads put messages into the queue, the main thread reads from
it via `root.after()` at regular intervals and performs all widget updates.

### Why embedded Jinja2 templates (not separate `.html` files)?

The Raspberry Pi runs as a standalone appliance. Separate template files would
require managing paths relative to the project root, and could be accidentally
deleted or moved. Embedding templates as Python string constants makes each file
fully self-contained — `dashboard.py` and `report_generator.py` work regardless of
where the project is cloned.

### Why Flask for the dashboard instead of a heavier framework?

Flask is lightweight (no ORM, no auth layer needed), already in the Kali Linux
ecosystem, and starts in under a second. The dashboard serves a single LAN segment
during an audit — it never needs to scale. `use_reloader=False` and `debug=False`
prevent Flask from forking the process, which would destroy the logger hierarchy set
up in `launcher.py`.

### Why `mtime`-based sorting in `_load_results()`?

Result filenames start with the module name (`lan_scan_...`, `wifi_audit_...`).
Alphabetical sorting would always show wifi_audit before tls_audit before lan_scan
regardless of when each was run. Sorting by `os.path.getmtime()` reflects actual
execution order, so the most recently run scan always appears first.
