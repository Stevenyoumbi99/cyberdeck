"""
CyberDeck Module: arp_monitor
==============================
Passively monitors ARP traffic to detect ARP spoofing attacks (MITM).

How ARP works:
    ARP (Address Resolution Protocol) maps IP addresses to MAC addresses on
    a local network. When a host wants to talk to 192.168.1.1, it broadcasts
    "Who has 192.168.1.1?" and the owner responds "I do — my MAC is AA:BB:CC..."

How ARP spoofing works:
    An attacker sends forged ARP replies claiming "I am 192.168.1.1 — my MAC
    is XX:XX:XX..." (the attacker's MAC). Victims update their ARP cache and
    start sending traffic intended for the gateway to the attacker instead.
    This is a Man-in-the-Middle (MITM) attack.

How we detect it:
    We build an IP→MAC mapping table as ARP packets arrive. If we ever see
    the same IP claimed by a NEW and DIFFERENT MAC address, that's a conflict
    — a strong indicator of ARP spoofing.

    Note: Legitimate MAC changes do happen (e.g. router replaced, NIC changed)
    but they are rare. Any conflict should be investigated.

Dependencies:
    scapy>=2.5.0  (pre-installed on Kali)

Config fields:
    config["network"]["lan_interface"]         — interface to monitor, e.g. "eth0"
    config["scan"]["passive_capture_duration"] — how many seconds to listen

Output format:
    data = {
        "interface":        str  — interface monitored
        "duration_seconds": int  — how long the capture ran
        "packets_analysed": int  — total ARP packets seen
        "arp_table": {
            "ip": "mac"  — final learned IP→MAC mappings
        }
        "conflicts_found":  int  — number of MAC conflicts detected
        "conflicts": [
            {
                "ip":       str  — IP address that was claimed by multiple MACs
                "original": str  — first MAC seen for this IP
                "spoofed":  str  — conflicting MAC (possible attacker)
                "severity": str  — always "high" — ARP conflicts are serious
                "reason":   str  — human-readable explanation
            }
        ]
    }

Limitations:
    - Requires root/sudo (raw socket capture)
    - Only sees ARP traffic on the local broadcast domain (same subnet)
    - Cannot see through routers — each subnet must be monitored separately
    - Legitimate MAC changes (replaced hardware) will trigger a false positive
    - A short capture window may miss an ongoing attack — longer is better
"""

import logging
from datetime import datetime

from scapy.all import ARP, sniff

logger = logging.getLogger("cyberdeck")


def run(config: dict) -> dict:
    """
    Sniff ARP packets and detect IP→MAC conflicts indicating MITM attacks.

    Args:
        config: Full config dictionary from config.json

    Returns:
        dict: Standardized result with keys:
              module, timestamp, status, data, errors
    """
    logger.info("Starting arp_monitor...")

    interface = config["network"]["lan_interface"]
    duration = config["scan"]["passive_capture_duration"]

    logger.info(
        "Monitoring ARP traffic on %s for %ds...", interface, duration
    )

    try:
        # arp_table maps IP → MAC as we learn associations from ARP packets
        # conflicts accumulates any IP that claims more than one MAC
        arp_table = {}
        conflicts = []
        packets_seen = [0]   # use list so the closure can mutate it

        def _handle_arp(pkt):
            """
            Process each ARP packet — called by scapy for every captured frame.

            ARP has two operation types:
              op=1 (who-has / request)  — "Who has IP X?"
              op=2 (is-at  / reply)     — "I have IP X, my MAC is Y"

            Both can be used to build the IP→MAC table.
            Replies are more authoritative, but requests also reveal senders.
            """
            if not pkt.haslayer(ARP):
                return

            packets_seen[0] += 1
            arp = pkt[ARP]

            # psrc = sender IP, hwsrc = sender MAC
            # These are present in both requests and replies
            ip = arp.psrc
            mac = arp.hwsrc

            # Skip broadcast/empty entries
            if not ip or not mac or ip == "0.0.0.0" or mac == "ff:ff:ff:ff:ff:ff":
                return

            if ip not in arp_table:
                # First time we see this IP — record it
                arp_table[ip] = mac
                logger.debug("ARP learned: %s → %s", ip, mac)

            elif arp_table[ip] != mac:
                # This IP was previously associated with a DIFFERENT MAC.
                # This is an ARP conflict — possible spoofing attack.
                logger.warning(
                    "ARP CONFLICT: %s was %s, now claims %s — possible MITM!",
                    ip, arp_table[ip], mac
                )

                # Only record each conflict once to avoid duplicate entries
                # from repeated spoofed packets
                already_recorded = any(
                    c["ip"] == ip and c["spoofed"] == mac
                    for c in conflicts
                )

                if not already_recorded:
                    conflicts.append({
                        "ip": ip,
                        "original": arp_table[ip],
                        "spoofed": mac,
                        "severity": "high",
                        "reason": (
                            f"IP {ip} was mapped to {arp_table[ip]} but now "
                            f"claims MAC {mac} — ARP spoofing / MITM suspected"
                        ),
                    })

                # Update table to the latest MAC so we can track further changes
                arp_table[ip] = mac

        # Sniff ARP packets only — BPF filter "arp" reduces CPU load
        # by discarding non-ARP frames before Python even sees them
        sniff(
            iface=interface,
            filter="arp",
            prn=_handle_arp,
            timeout=duration,
            store=False,
        )

        logger.info(
            "arp_monitor completed — %d ARP packet(s), %d host(s) learned, %d conflict(s)",
            packets_seen[0], len(arp_table), len(conflicts)
        )

        result_data = {
            "interface": interface,
            "duration_seconds": duration,
            "packets_analysed": packets_seen[0],
            "arp_table": arp_table,
            "conflicts_found": len(conflicts),
            "conflicts": conflicts,
        }

        # Use "partial" if conflicts were found — not an error, but not clean either
        status = "success" if not conflicts else "partial"

        return {
            "module": "arp_monitor",
            "timestamp": datetime.now().isoformat(),
            "status": status,
            "data": result_data,
            "errors": [],
        }

    except Exception as e:
        logger.error("arp_monitor failed: %s", e)

        return {
            "module": "arp_monitor",
            "timestamp": datetime.now().isoformat(),
            "status": "error",
            "data": {},
            "errors": [str(e)],
        }
