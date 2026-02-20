#!/bin/bash
# CyberDeck Deploy Script
# Pulls the latest stable code to the Raspberry Pi
#
# Usage: bash scripts/deploy.sh

echo "=== CyberDeck Deployment ==="
echo ""

# Pull latest from dev branch
git pull origin dev

# Install/update dependencies
pip3 install -r requirements.txt

# Create required directories
mkdir -p results logs

echo ""
echo "[OK] Deployment complete."
echo "[i] Run: python3 launcher.py"
