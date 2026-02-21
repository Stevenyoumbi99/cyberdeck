
# CLAUDE.md - CyberDeck Project Instructions

> This file provides context for Claude Code to understand the CyberDeck project.
> Read this entirely before making any changes.

---

## Project Overview

**CyberDeck** is a portable cybersecurity audit platform built on Raspberry Pi 4 running Kali Linux.

**Purpose:** MSc Cyber & Data "Projet Fil Rouge" — a team-based academic project demonstrating cybersecurity, data analysis, AI integration, and embedded systems.

**What it does:**
- Boots into a menu-driven interface
- User selects an audit mode (WiFi scan, LAN scan, Bluetooth recon, etc.)
- The selected module executes and collects data
- Results are saved as standardized JSON
- A dashboard displays findings and generates reports
- Anomaly detection uses AI (Z-score / Isolation Forest) to flag threats

---

## Supervisor Philosophy (CRITICAL)

```
"If it works but you don't understand → disappointed."
"If it fails but you deeply understand → satisfied."
```

**This means:**
- Understanding is more important than working code
- Every line of code must be explainable
- Comments should explain WHY, not just WHAT
- When in doubt, explain the reasoning

---

## Rules for Claude Code

### Git Rules
- ❌ Do NOT commit without explicit permission
- ❌ Do NOT push to GitHub without explicit permission
- ❌ Do NOT run any git commands unless asked
- ✅ Ask before any version control operation

### Code Rules
- ✅ Explain changes BEFORE making them
- ✅ Ask for confirmation before modifying existing files
- ✅ Add comments explaining logic in all new code
- ✅ Follow PEP8 style guidelines
- ✅ Use type hints on all functions
- ✅ Write docstrings for every function

### Development Rules
- ✅ Test code logic before considering it complete
- ✅ Handle errors gracefully (try/except with logging)
- ✅ Use the centralized logger, never print()
- ✅ Read from config, never hardcode values

---

## Current Development Phase

### Phase 4: Build the Core Engine (CURRENT)

Build these utilities in order — each depends on the previous:

| Order | File | Purpose | Status |
|-------|------|---------|--------|
| 1 | `utils/config_loader.py` | Read and validate config.json | TODO |
| 2 | `utils/logger.py` | Centralized logging for all modules | TODO |
| 3 | `utils/result_handler.py` | Save module output as JSON files | TODO |
| 4 | `menu.py` | Dynamic CLI menu from modules/ folder | TODO |
| 5 | `launcher.py` | Main entry point, orchestrates everything | TODO |

### Phase 5: Module Development (NEXT)
Build the actual scanning modules after core engine works.

---

## Architecture Contracts

### The Module Contract

Every file in `modules/` MUST implement this exact pattern:

```python
"""
CyberDeck Module: module_name
=============================
Description of what this module does.

Dependencies: List required packages
Config fields: List which config sections it reads
Output format: Describe the data structure returned
Limitations: Known limitations or requirements
"""

import logging
from datetime import datetime

logger = logging.getLogger("cyberdeck")


def run(config: dict) -> dict:
    """
    Execute the module's main function.

    Args:
        config: The full config dictionary from config.json

    Returns:
        dict: Standardized result with keys:
              module, timestamp, status, data, errors
    """
    logger.info("Starting module_name...")

    try:
        # Module logic here
        # Read config: interface = config["network"]["lan_interface"]
        
        result_data = {}  # Actual results go here

        logger.info("module_name completed successfully")

        return {
            "module": "module_name",
            "timestamp": datetime.now().isoformat(),
            "status": "success",
            "data": result_data,
            "errors": []
        }

    except Exception as e:
        logger.error(f"module_name failed: {e}")

        return {
            "module": "module_name",
            "timestamp": datetime.now().isoformat(),
            "status": "error",
            "data": {},
            "errors": [str(e)]
        }
```

### Result Schema

ALL modules return this exact JSON structure:

```json
{
  "module": "string - module name",
  "timestamp": "string - ISO format datetime",
  "status": "string - success|error|partial",
  "data": "object - module-specific results",
  "errors": "array - list of error messages (empty if success)"
}
```

### Logger Usage

ALL modules use the shared logger — never use print():

```python
import logging
logger = logging.getLogger("cyberdeck")

logger.debug("Detailed technical info")
logger.info("Normal operation milestone")
logger.warning("Unexpected but not breaking")
logger.error("Something failed")
```

---

## Module Inventory

### Core Utilities (utils/)

| File | Purpose | Phase |
|------|---------|-------|
| `config_loader.py` | Read config.json, validate, provide defaults | Phase 4 |
| `logger.py` | Initialize centralized "cyberdeck" logger | Phase 4 |
| `result_handler.py` | Save result dicts as JSON to results/ | Phase 4 |
| `report_generator.py` | Generate HTML audit reports | Phase 9 |

### Scanning Modules (modules/)

| File | Purpose | Hardware | Phase |
|------|---------|----------|-------|
| `passive_monitor.py` | Capture packets, log traffic patterns | eth0 | Phase 5 |
| `lan_scan.py` | ARP discovery, port scanning, OS fingerprinting | eth0 | Phase 5 |
| `wifi_audit.py` | Monitor mode, list SSIDs, channels, encryption | wlan1 | Phase 5 |
| `bluetooth_recon.py` | Device discovery, MACs, device classes | hci0 | Phase 5 |
| `pentest_tools.py` | Wrapper around nmap, nikto, enum4linux | various | Phase 5 |
| `anomaly_detect.py` | Z-score / Isolation Forest threat detection | n/a | Phase 6 |
| `dashboard.py` | Flask web UI displaying results | n/a | Phase 9 |

---

## Configuration Reference

The central config file is `config/config.json`:

```json
{
  "project": {
    "name": "CyberDeck",
    "version": "1.0.0"
  },
  "network": {
    "lan_interface": "eth0",
    "wifi_interface": "wlan1",
    "wifi_monitor_interface": "wlan1mon",
    "bluetooth_interface": "hci0",
    "target_subnet": "192.168.1.0/24"
  },
  "scan": {
    "lan_scan_timeout": 30,
    "port_range": "1-1024",
    "wifi_scan_duration": 15,
    "bluetooth_scan_duration": 10,
    "passive_capture_duration": 60
  },
  "anomaly": {
    "method": "zscore",
    "threshold": 2.5,
    "baseline_file": "results/baseline.json",
    "min_samples": 50
  },
  "output": {
    "results_dir": "results/",
    "logs_dir": "logs/",
    "report_format": "html"
  },
  "logging": {
    "level": "INFO",
    "log_to_file": true,
    "log_to_console": true,
    "max_file_size_mb": 5,
    "backup_count": 3
  },
  "dashboard": {
    "host": "0.0.0.0",
    "port": 5000
  }
}
```

---

## Hardware Mapping

| Hardware | Linux Interface | Used By | Purpose |
|----------|-----------------|---------|---------|
| Ethernet | eth0 | lan_scan, passive_monitor | Wired LAN scanning |
| Built-in WiFi | wlan0 | dashboard | Network access (not for auditing) |
| External WiFi | wlan1 / wlan1mon | wifi_audit | Monitor mode, packet injection |
| Bluetooth | hci0 | bluetooth_recon | Device discovery |
| Touchscreen | HDMI + USB | menu, dashboard | User interface |

---

## Git Workflow

### Branches
- `main` — Stable releases only, never develop here
- `dev` — Integration branch, merge features here first
- `feature/*` — One branch per module (e.g., `feature/lan-scan`)

### Commit Message Format
```
type(scope): short description

Types: feat, fix, docs, refactor, test, chore
Examples:
  feat(lan_scan): add ARP discovery function
  fix(logger): handle missing log directory
  docs(architecture): add data flow diagram
```

### Workflow
1. `git pull origin dev` before starting work
2. `git checkout -b feature/thing` for new work
3. Make changes, commit with meaningful messages
4. Merge to dev when tested
5. Merge dev to main for releases

---

## File Structure

```
cyberdeck/
├── launcher.py              # Entry point — loads config, menu, runs modules
├── menu.py                  # CLI menu — lists modules dynamically
├── requirements.txt         # Python dependencies
├── README.md                # Project overview
├── CLAUDE.md                # This file — instructions for Claude Code
├── .gitignore               # Ignore results/, logs/, __pycache__/
│
├── config/
│   └── config.json          # Central configuration
│
├── modules/
│   ├── __init__.py
│   ├── passive_monitor.py   # Traffic capture
│   ├── lan_scan.py          # Network discovery
│   ├── wifi_audit.py        # Wireless recon
│   ├── bluetooth_recon.py   # Bluetooth scanning
│   ├── pentest_tools.py     # Security tool wrappers
│   ├── anomaly_detect.py    # AI threat detection
│   └── dashboard.py         # Web UI
│
├── utils/
│   ├── __init__.py
│   ├── config_loader.py     # Read config.json
│   ├── logger.py            # Centralized logging
│   ├── result_handler.py    # Save JSON results
│   └── report_generator.py  # HTML reports
│
├── results/                 # Scan outputs (git-ignored)
├── logs/                    # Log files (git-ignored)
├── tests/                   # Unit tests
├── docs/                    # Documentation
└── scripts/                 # Helper scripts (deploy.sh, setup_env.sh)
```

---

## Development Environment

- **Coding:** Kali Linux VM (VMware on Windows)
- **Deployment:** Raspberry Pi 4 with Kali Linux
- **Workflow:** Code in VM → Push to GitHub → Pull to Pi

---

## Quick Reference

### To implement a new module:
1. Create `modules/new_module.py`
2. Implement `run(config) -> dict` following the contract
3. Use `logging.getLogger("cyberdeck")` for logging
4. Return standardized result dict
5. Module auto-appears in menu

### To test a module standalone:
```bash
python -m modules.lan_scan
```

### To run the system:
```bash
python launcher.py
```

---

## Remember

> Build to understand, not just to deliver.

Every architectural decision has a reason. If you don't know why something is designed a certain way, ask before changing it.