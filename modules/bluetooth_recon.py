"""
CyberDeck Module: bluetooth_recon
===================================
Discovers nearby Bluetooth devices that are in discoverable mode by
sending an HCI inquiry over the Bluetooth adapter.

How it works:
    Bluetooth Classic discovery uses an "inquiry" procedure defined in
    the Bluetooth spec. The adapter broadcasts an inquiry packet on all
    79 frequency channels. Devices in discoverable mode respond with:
      - Their MAC address (BD_ADDR — 6 bytes, unique per device)
      - Their Class of Device (CoD — 24-bit integer encoding device type)

    After discovery, we query each device for its human-readable name
    using a "Remote Name Request" — a separate HCI command per device.

    PyBluez wraps all of this into a single discover_devices() call.

Dependencies:
    PyBluez / python3-bluetooth
    Install on Kali: sudo apt install python3-bluetooth

Config fields:
    config["network"]["bluetooth_interface"]   — adapter name, e.g. "hci0"
    config["scan"]["bluetooth_scan_duration"]  — inquiry duration in seconds

Output format:
    data = {
        "interface":      str  — Bluetooth adapter used
        "duration_seconds": int  — how long the scan ran
        "devices_found":  int  — number of discoverable devices seen
        "devices": [
            {
                "mac":          str  — Bluetooth MAC address (BD_ADDR)
                "name":         str  — human-readable device name (may be empty)
                "device_class": str  — decoded device type, e.g. "Phone", "Computer"
                "cod_raw":      int  — raw Class of Device integer (for reference)
            }
        ]
    }

Limitations:
    - Requires root/sudo (HCI raw socket access)
    - Only discovers devices in discoverable mode — most phones hide by default
    - Bluetooth Classic only — BLE (Low Energy) devices use a different protocol
    - Range is typically 10m (Class 2) to 100m (Class 1)
    - Cannot be tested on a VM without a physical Bluetooth adapter passed through
    - Name lookup adds ~5s per device on top of the inquiry duration
"""

import logging
from datetime import datetime

import bluetooth  # PyBluez — wraps Linux HCI Bluetooth API

logger = logging.getLogger("cyberdeck")

# Maps the Major Device Class (bits 8-12 of CoD) to a readable label.
# CoD is a 24-bit integer: bits 23-13 = major service class,
# bits 12-8 = major device class, bits 7-2 = minor device class.
_MAJOR_DEVICE_CLASS = {
    0x00: "Miscellaneous",
    0x01: "Computer",
    0x02: "Phone",
    0x03: "Network Access Point",
    0x04: "Audio / Video",
    0x05: "Peripheral",
    0x06: "Imaging",
    0x07: "Wearable",
    0x08: "Toy",
    0x09: "Health",
    0x1F: "Uncategorized",
}


def run(config: dict) -> dict:
    """
    Scan for nearby discoverable Bluetooth devices.

    Args:
        config: Full config dictionary from config.json

    Returns:
        dict: Standardized result with keys:
              module, timestamp, status, data, errors
    """
    logger.info("Starting bluetooth_recon...")

    interface = config["network"]["bluetooth_interface"]
    duration = config["scan"]["bluetooth_scan_duration"]

    # PyBluez uses a device index (int), not a name like "hci0".
    # hci0 = index 0, hci1 = index 1, etc.
    # We parse the trailing digit from the interface name.
    device_id = _parse_device_id(interface)

    logger.info(
        "Scanning for Bluetooth devices on %s for %ds...", interface, duration
    )

    try:
        devices = _scan_devices(device_id, duration)

        logger.info(
            "bluetooth_recon completed — %d device(s) found", len(devices)
        )

        result_data = {
            "interface": interface,
            "duration_seconds": duration,
            "devices_found": len(devices),
            "devices": devices,
        }

        return {
            "module": "bluetooth_recon",
            "timestamp": datetime.now().isoformat(),
            "status": "success",
            "data": result_data,
            "errors": [],
        }

    except Exception as e:
        logger.error("bluetooth_recon failed: %s", e)

        return {
            "module": "bluetooth_recon",
            "timestamp": datetime.now().isoformat(),
            "status": "error",
            "data": {},
            "errors": [str(e)],
        }


def _scan_devices(device_id: int, duration: int) -> list:
    """
    Run a Bluetooth inquiry and return a list of discovered devices.

    discover_devices() blocks for approximately `duration` seconds while
    the adapter performs the HCI inquiry. It then issues a Remote Name
    Request for each discovered device to retrieve its friendly name.

    Args:
        device_id: HCI adapter index (0 for hci0, 1 for hci1, etc.)
        duration:  Inquiry duration in seconds (rounded to nearest 1.28s
                   internally by the Bluetooth spec — 10s → ~10.24s)

    Returns:
        list: One dict per discovered device
    """
    # discover_devices returns a list of (mac, name, cod) tuples when
    # lookup_names=True and lookup_class=True are both set.
    # lookup_names triggers a separate Remote Name Request per device.
    raw_devices = bluetooth.discover_devices(
        duration=duration,
        device_id=device_id,
        lookup_names=True,
        lookup_class=True,
        flush_cache=True,   # ignore cached results from previous scans
    )

    devices = []
    for mac, name, cod in raw_devices:
        device_class = _decode_device_class(cod)

        logger.info(
            "Found: %s  name=%r  class=%s  cod=0x%06X",
            mac, name, device_class, cod
        )

        devices.append({
            "mac": mac,
            "name": name or "",          # name is None if lookup failed
            "device_class": device_class,
            "cod_raw": cod,
        })

    return devices


def _decode_device_class(cod: int) -> str:
    """
    Decode the Major Device Class from a raw Class of Device integer.

    The CoD is a 24-bit field. The major device class occupies bits 12-8
    (5 bits). We extract it with a right-shift and bitmask, then look it
    up in our label table.

    Example:
        cod = 0x5A020C  (a phone)
        major = (0x5A020C >> 8) & 0x1F = 0x02 → "Phone"

    Args:
        cod: Raw 24-bit Class of Device integer from the Bluetooth inquiry

    Returns:
        str: Human-readable device class label
    """
    # Shift right by 8 bits to align the major class field, then mask
    # to 5 bits (0x1F = 0b11111) to isolate just the major class value
    major = (cod >> 8) & 0x1F
    return _MAJOR_DEVICE_CLASS.get(major, f"Unknown (0x{major:02X})")


def _parse_device_id(interface: str) -> int:
    """
    Extract the integer device index from an HCI interface name.

    PyBluez identifies adapters by index (0, 1, 2...) rather than by
    the Linux interface name (hci0, hci1...). We strip the "hci" prefix
    and convert the remainder to int.

    Args:
        interface: Interface name string, e.g. "hci0"

    Returns:
        int: Device index (e.g. 0 for "hci0")
    """
    try:
        return int(interface.replace("hci", ""))
    except ValueError:
        # Fallback to adapter 0 if the name format is unexpected
        logger.warning(
            "Could not parse device index from '%s', defaulting to 0", interface
        )
        return 0
