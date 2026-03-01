"""
CyberDeck Module: wifi_audit
=============================
Scans for nearby WiFi networks by putting the wireless adapter into monitor
mode and capturing 802.11 beacon frames broadcast by access points.

How it works:
    Every WiFi access point continuously broadcasts "beacon frames" to
    announce its presence. These contain the SSID, supported rates,
    channel, and capability flags (including encryption type).
    In normal "managed" mode, your adapter ignores beacons from other
    networks. In "monitor" mode it captures everything in the air.

    Sequence:
        1. Call airmon-ng to put wlan1 into monitor mode → wlan1mon
        2. Sniff 802.11 beacon frames for wifi_scan_duration seconds
        3. Parse each unique BSSID (access point MAC) once
        4. Restore wlan1 to managed mode
        5. Return structured list of networks found

Dependencies:
    scapy>=2.5.0     (pre-installed on Kali)
    airmon-ng        (part of aircrack-ng suite — pre-installed on Kali)

Config fields:
    config["network"]["wifi_interface"]         — base interface, e.g. "wlan1"
    config["network"]["wifi_monitor_interface"] — monitor interface, e.g. "wlan1mon"
    config["scan"]["wifi_scan_duration"]        — seconds to sniff for beacons

Output format:
    data = {
        "interface":        str  — monitor interface used
        "duration_seconds": int  — how long the scan ran
        "networks_found":   int  — number of unique access points seen
        "networks": [
            {
                "ssid":       str  — network name (empty string if hidden)
                "bssid":      str  — access point MAC address
                "channel":    int  — WiFi channel (1-14 for 2.4GHz, 36+ for 5GHz)
                "signal_dbm": int  — signal strength in dBm (e.g. -65)
                "encryption": str  — "Open" / "WEP" / "WPA" / "WPA2" / "WPA3"
            }
        ]
    }

Limitations:
    - Requires root/sudo
    - Requires a WiFi adapter that supports monitor mode (wlan1 on the Pi)
    - The built-in Pi WiFi (wlan0) does NOT support monitor mode — use wlan1
    - Putting an interface into monitor mode disconnects it from any network
    - Cannot be tested on a VM without a physical USB WiFi adapter passed through
    - Channel hopping is not implemented — the adapter stays on its current channel
      so networks on other channels may be missed (full coverage needs airodump-ng)
"""

import logging
import subprocess
from datetime import datetime

from scapy.all import sniff
from scapy.layers.dot11 import Dot11, Dot11Beacon, Dot11Elt, RadioTap

logger = logging.getLogger("cyberdeck")


def run(config: dict) -> dict:
    """
    Put WiFi adapter into monitor mode, sniff beacon frames, restore adapter.

    Args:
        config: Full config dictionary from config.json

    Returns:
        dict: Standardized result with keys:
              module, timestamp, status, data, errors
    """
    logger.info("Starting wifi_audit...")

    iface = config["network"]["wifi_interface"]
    monitor_iface = config["network"]["wifi_monitor_interface"]
    duration = config["scan"]["wifi_scan_duration"]

    errors = []

    try:
        # --- Step 1: Enable monitor mode ---
        logger.info("Enabling monitor mode on %s", iface)
        _enable_monitor_mode(iface)

        # --- Step 2: Sniff beacon frames ---
        logger.info("Scanning for WiFi networks on %s for %ds...", monitor_iface, duration)
        networks = _scan_networks(monitor_iface, duration)
        logger.info("Scan complete — %d unique network(s) found", len(networks))

    except Exception as e:
        logger.error("wifi_audit failed during scan: %s", e)
        errors.append(str(e))
        networks = []

    finally:
        # --- Step 3: Always restore managed mode ---
        # We use finally so the adapter is restored even if an exception occurred.
        # Leaving an adapter stuck in monitor mode breaks normal WiFi connectivity.
        logger.info("Restoring %s to managed mode", monitor_iface)
        try:
            _disable_monitor_mode(monitor_iface)
        except Exception as e:
            logger.error("Failed to restore managed mode on %s: %s", iface, e)
            errors.append(f"Could not restore managed mode: {e}")

    result_data = {
        "interface": monitor_iface,
        "duration_seconds": duration,
        "networks_found": len(networks),
        "networks": networks,
    }

    status = "success" if not errors else ("partial" if networks else "error")

    logger.info(
        "wifi_audit completed — %d network(s), status: %s", len(networks), status
    )

    return {
        "module": "wifi_audit",
        "timestamp": datetime.now().isoformat(),
        "status": status,
        "data": result_data,
        "errors": errors,
    }


def _enable_monitor_mode(iface: str) -> None:
    """
    Use airmon-ng to put the WiFi interface into monitor mode.

    airmon-ng checks for processes that might interfere (like NetworkManager),
    kills them, then sets the adapter to monitor mode and creates a new
    interface named <iface>mon (e.g. wlan1 → wlan1mon).

    Args:
        iface: Base interface name, e.g. "wlan1"

    Raises:
        RuntimeError: If airmon-ng returns a non-zero exit code
    """
    # Kill processes that interfere with monitor mode (e.g. NetworkManager, wpa_supplicant)
    # timeout=15 prevents hanging if airmon-ng stalls — killing processes should be fast
    subprocess.run(["airmon-ng", "check", "kill"], capture_output=True, timeout=15)

    # Enable monitor mode — creates wlan1mon
    # timeout=30 prevents the module from hanging indefinitely if the driver is unresponsive
    result = subprocess.run(
        ["airmon-ng", "start", iface],
        capture_output=True,
        text=True,
        timeout=30
    )

    if result.returncode != 0:
        raise RuntimeError(
            f"airmon-ng failed to enable monitor mode on {iface}: {result.stderr}"
        )

    logger.debug("airmon-ng output: %s", result.stdout)


def _disable_monitor_mode(monitor_iface: str) -> None:
    """
    Restore the WiFi interface from monitor mode back to managed mode.

    We accept the monitor interface name directly (from config) rather than
    constructing it by appending "mon" to the base name. This keeps the
    function consistent with how _scan_networks receives its interface, and
    means the config's wifi_monitor_interface is the single source of truth.

    Args:
        monitor_iface: Monitor interface name, e.g. "wlan1mon"
    """
    result = subprocess.run(
        ["airmon-ng", "stop", monitor_iface],
        capture_output=True,
        text=True,
        timeout=30
    )

    if result.returncode != 0:
        raise RuntimeError(
            f"airmon-ng failed to stop monitor mode on {monitor_iface}: {result.stderr}"
        )

    logger.debug("airmon-ng stop output: %s", result.stdout)


def _scan_networks(monitor_iface: str, duration: int) -> list:
    """
    Sniff 802.11 beacon frames and parse unique access points.

    Each access point broadcasts beacon frames roughly 10 times per second.
    We collect all beacons during the capture window, then deduplicate by
    BSSID so each access point appears once in the results.

    Args:
        monitor_iface: Monitor mode interface name, e.g. "wlan1mon"
        duration:      How many seconds to sniff

    Returns:
        list: List of network dicts, one per unique BSSID
    """
    # Dict keyed by BSSID so we naturally deduplicate — later beacons from
    # the same AP overwrite earlier ones (same data, just refreshed signal)
    networks = {}

    def _handle_packet(pkt):
        """Called by scapy for every packet captured — filters for beacons."""
        # Only process 802.11 beacon frames
        # Dot11Beacon is the management frame type that APs use to announce themselves
        if not (pkt.haslayer(Dot11Beacon) and pkt.haslayer(Dot11)):
            return

        bssid = pkt[Dot11].addr2  # addr2 is the transmitter (AP MAC)
        if not bssid:
            return

        # Extract SSID and channel from the tagged parameters (Dot11Elt chain)
        ssid = ""
        channel = 0
        elt = pkt.getlayer(Dot11Elt)
        while elt:
            # ID 0 = SSID element
            if elt.ID == 0:
                try:
                    ssid = elt.info.decode("utf-8", errors="replace").strip()
                except Exception:
                    ssid = ""
            # ID 3 = DS Parameter Set (current channel)
            elif elt.ID == 3 and elt.info:
                channel = elt.info[0]
            elt = elt.payload.getlayer(Dot11Elt)

        # Extract signal strength from RadioTap header (added by the driver)
        # dBm_AntSignal is typically negative: -30 (strong) to -90 (weak)
        signal_dbm = 0
        if pkt.haslayer(RadioTap):
            signal_dbm = getattr(pkt[RadioTap], "dBm_AntSignal", 0) or 0

        # Determine encryption type from the capability field and RSN/WPA IEs
        encryption = _get_encryption(pkt)

        networks[bssid] = {
            "ssid": ssid,
            "bssid": bssid,
            "channel": channel,
            "signal_dbm": int(signal_dbm),
            "encryption": encryption,
        }

    # Capture packets — scapy calls _handle_packet for each one
    sniff(iface=monitor_iface, prn=_handle_packet, timeout=duration, store=False)

    # Sort by signal strength descending (strongest signal first)
    return sorted(networks.values(), key=lambda n: n["signal_dbm"], reverse=True)


def _get_encryption(pkt) -> str:
    """
    Determine the encryption type of an access point from its beacon frame.

    Encryption is encoded in two places:
      1. The Capability Information field — bit 4 set means WEP (legacy)
      2. Information Elements (tagged parameters):
         - IE ID 48 = RSN (Robust Security Network) → WPA2 or WPA3
         - IE ID 221 with OUI 00:50:f2:01 = Microsoft WPA IE → WPA

    We check in order: WPA3 → WPA2 → WPA → WEP → Open

    Args:
        pkt: Scapy packet containing a Dot11Beacon layer

    Returns:
        str: One of "WPA3", "WPA2", "WPA", "WEP", "Open"
    """
    rsn_elt = None
    wpa_elt = None

    elt = pkt.getlayer(Dot11Elt)
    while elt:
        if elt.ID == 48:
            rsn_elt = elt  # RSN IE → WPA2 or WPA3
        elif elt.ID == 221 and hasattr(elt, "info") and len(elt.info) >= 4:
            # Vendor-specific IE with Microsoft OUI (00:50:f2) and type 01 = WPA
            if elt.info[:4] == b"\x00\x50\xf2\x01":
                wpa_elt = elt
        elt = elt.payload.getlayer(Dot11Elt)

    if rsn_elt:
        # Check AKM suite list for SAE (Simultaneous Authentication of Equals)
        # SAE is the WPA3 key exchange — OUI 00:0f:ac, suite type 8
        rsn_info = bytes(rsn_elt.info) if hasattr(rsn_elt, "info") else b""
        if b"\x00\x0f\xac\x08" in rsn_info:
            return "WPA3"
        return "WPA2"

    if wpa_elt:
        return "WPA"

    # Fall back to capability field — bit 4 (0x0010) set means privacy (WEP)
    cap = pkt[Dot11Beacon].cap if pkt.haslayer(Dot11Beacon) else 0
    if cap & 0x0010:
        return "WEP"

    return "Open"
