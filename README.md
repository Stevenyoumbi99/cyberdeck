# CyberDeck

**Portable Cybersecurity Audit Platform**

MSc Cyber & Data — Projet Fil Rouge

## Overview

CyberDeck is a portable, embedded, modular cyber operations console built on a Raspberry Pi 4 running Kali Linux. It autonomously analyzes local networks, detects security anomalies using lightweight AI, and generates audit reports, all from a self-contained, battery-powered unit.

## Features

- **Passive Network Monitoring** — Traffic capture and pattern analysis
- **LAN Scanning** — ARP discovery, port scanning, OS fingerprinting
- **WiFi Auditing** — Monitor mode, wireless reconnaissance
- **Bluetooth Recon** — Device discovery and classification
- **Pentest Toolkit** — Wrappers around industry tools (nmap, nikto, enum4linux)
- **Anomaly Detection** — Z-score and Isolation Forest based threat detection
- **OSINT Recon Engine** — Internal discovery and external intelligence gathering (DNS, WHOIS, Certificate Transparency, TheHarvester) with exposure scoring and Maltego export
- **Dashboard & Reports** — Flask web UI with HTML audit report generation

## Architecture

The system uses a plugin-based architecture. Every module implements `run(config)` and returns a standardized JSON result. Modules are discovered dynamically, adding a new mode means adding one file to `modules/`.

See [docs/architecture.md](docs/architecture.md) for the full system design.

## Quick Start

```bash
# Clone the repository
git clone https://github.com/Bravecupidon/cyberdeck.git
cd cyberdeck

# Install dependencies
pip install -r requirements.txt

# Run the launcher
python launcher.py
```

## Project Structure

```
cyberdeck/
├── launcher.py          # Entry point
├── menu.py              # CLI mode selection
├── config/              # Central configuration
├── modules/             # All operational modes
├── utils/               # Shared utilities (logger, config loader, etc.)
├── results/             # Scan output files (git-ignored)
├── logs/                # Log files (git-ignored)
├── tests/               # Unit tests
├── docs/                # Project documentation
└── scripts/             # Helper & automation scripts
```

## Git Workflow

- `main` — Stable releases only
- `dev` — Integration branch
- `feature/*` — One branch per module

See [docs/workflow.md](docs/workflow.md) for branching and commit conventions.

## Team

MSc Cyber & Data (ESAIP)
