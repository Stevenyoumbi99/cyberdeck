"""
CyberDeck Module: bluetooth_recon

Description:
Performs basic Bluetooth reconnaissance using bluetoothctl.
Scans for nearby Bluetooth devices for a limited time and
returns discovered devices in a structured format.

Dependencies:
- bluetoothctl (BlueZ)

Config fields:
- timeout (int): scan duration in seconds (default: 5)

Output format:
{
  "module": "bluetooth_recon",
  "timestamp": "...",
  "status": "success|error",
  "data": {
      "device_count": int,
      "devices": [
          {"mac": "...", "name": "..."}
      ]
  },
  "errors": []
}

Limitations:
- Requires Bluetooth adapter
- May need root privileges
"""

import subprocess
import time
import logging
from datetime import datetime

logger = logging.getLogger("cyberdeck")


def run(config: dict) -> dict:
    timeout = int(config.get("timeout", 5))
    devices = []

    logger.info("Starting bluetooth_recon module")

    try:
        # Start bluetoothctl
        proc = subprocess.Popen(
            ["bluetoothctl"],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )

        # Start scanning
        proc.stdin.write("scan on\n")
        proc.stdin.flush()
        time.sleep(timeout)

        # List devices
        proc.stdin.write("devices\n")
        proc.stdin.flush()
        time.sleep(1)

        # Stop scan and exit
        proc.stdin.write("scan off\n")
        proc.stdin.write("quit\n")
        proc.stdin.flush()

        try:
            output, _ = proc.communicate(timeout=3)
        except subprocess.TimeoutExpired:
            proc.kill()
            output = ""

        for line in output.splitlines():
            if line.startswith("Device"):
                parts = line.split(" ", 2)
                if len(parts) >= 3:
                    devices.append({
                        "mac": parts[1],
                        "name": parts[2]
                    })

        return {
            "module": "bluetooth_recon",
            "timestamp": datetime.now().isoformat(),
            "status": "success",
            "data": {
                "device_count": len(devices),
                "devices": devices
            },
            "errors": []
        }

    except FileNotFoundError:
        return {
            "module": "bluetooth_recon",
            "timestamp": datetime.now().isoformat(),
            "status": "error",
            "data": {},
            "errors": ["bluetoothctl not found"]
        }

    except Exception as e:
        logger.error(f"bluetooth_recon failed: {e}")
        return {
            "module": "bluetooth_recon",
            "timestamp": datetime.now().isoformat(),
            "status": "error",
            "data": {},
            "errors": [str(e)]
        }

