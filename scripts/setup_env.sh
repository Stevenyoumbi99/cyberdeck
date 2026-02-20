#!/bin/bash
# CyberDeck Environment Setup
# Installs all required system packages and Python dependencies
# Run this on a fresh Kali Linux installation (VM or Raspberry Pi)
#
# Usage: sudo bash scripts/setup_env.sh

echo "=== CyberDeck Environment Setup ==="
echo ""

# System packages
echo "[1/4] Installing system packages..."
apt update
apt install -y python3 python3-pip git nmap aircrack-ng bluez tshark nikto enum4linux

# Python dependencies
echo "[2/4] Installing Python dependencies..."
pip3 install -r requirements.txt

# Create directories
echo "[3/4] Creating required directories..."
mkdir -p results logs

# Verify installation
echo "[4/4] Verifying installation..."
python3 --version
git --version
nmap --version | head -1

echo ""
echo "[OK] Environment setup complete."
echo "[i] Run: python3 launcher.py"
