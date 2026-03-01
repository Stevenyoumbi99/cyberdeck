"""
CyberDeck Module: passive_monitor
==================================
Silently captures network packets on an interface for a fixed duration
and summarises the traffic patterns observed.

Unlike lan_scan (which actively probes), this module sends nothing —
it only listens. This makes it undetectable on the network.

Dependencies:
    scapy>=2.5.0  (pip install scapy — pre-installed on Kali)

Config fields:
    config["network"]["lan_interface"]         — interface to sniff, e.g. "eth0"
    config["scan"]["passive_capture_duration"] — how many seconds to listen

Output format:
    data = {
        "interface":        str  — interface that was monitored
        "duration_seconds": int  — how long the capture ran
        "total_packets":    int  — total packets captured
        "total_bytes":      int  — total bytes across all packets
        "protocols": {
            "TCP":  int,   — count of TCP packets
            "UDP":  int,   — count of UDP packets
            "ICMP": int,   — count of ICMP packets
            "ARP":  int,   — count of ARP packets
            "Other": int   — count of all other protocols
        },
        "unique_ips": [str, ...]  — all unique IPs seen (src or dst)
        "top_conversations": [
            {
                "src":     str  — source IP
                "dst":     str  — destination IP
                "packets": int  — number of packets in this direction
            }
        ]  — top 10 src→dst pairs by packet count
    }

Limitations:
    - Requires root/sudo (raw socket capture)
    - Captures all traffic on the interface, including unrelated traffic
    - On a switched network, only sees traffic to/from this host (not all LAN traffic)
    - To see all LAN traffic on a switch, use a mirror/SPAN port or a hub
"""

import logging
from collections import Counter, defaultdict
from datetime import datetime

from scapy.all import sniff
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.l2 import ARP

logger = logging.getLogger("cyberdeck")


def run(config: dict) -> dict:
    """
    Capture packets passively for a configured duration and summarise findings.

    Args:
        config: Full config dictionary from config.json

    Returns:
        dict: Standardized result with keys:
              module, timestamp, status, data, errors
    """
    logger.info("Starting passive_monitor...")

    interface = config["network"]["lan_interface"]
    duration = config["scan"]["passive_capture_duration"]

    logger.info(
        "Listening on %s for %d second(s)...", interface, duration
    )

    try:
        # sniff() blocks for `timeout` seconds, collecting all packets it sees.
        # store=True keeps packets in memory so we can analyse them after capture.
        # iface sets which network interface to listen on.
        packets = sniff(iface=interface, timeout=duration, store=True)

        logger.info("Capture complete — %d packet(s) received", len(packets))

        # Analyse the captured packets into a structured summary
        result_data = _analyse_packets(packets, interface, duration)

        logger.info(
            "passive_monitor completed — %d packets, %d unique IPs",
            result_data["total_packets"],
            len(result_data["unique_ips"]),
        )

        return {
            "module": "passive_monitor",
            "timestamp": datetime.now().isoformat(),
            "status": "success",
            "data": result_data,
            "errors": [],
        }

    except Exception as e:
        logger.error("passive_monitor failed: %s", e)

        return {
            "module": "passive_monitor",
            "timestamp": datetime.now().isoformat(),
            "status": "error",
            "data": {},
            "errors": [str(e)],
        }


def _analyse_packets(packets, interface: str, duration: int) -> dict:
    """
    Walk through captured packets and build a traffic summary.

    For each packet we extract:
      - Protocol label (TCP / UDP / ICMP / ARP / Other)
      - Source and destination IP (if it has an IP layer)
      - Packet size in bytes

    We then aggregate these into counts, unique IP sets, and conversation tallies.

    Args:
        packets:   Scapy PacketList returned by sniff()
        interface: Interface name (recorded in output for reference)
        duration:  Capture duration in seconds (recorded in output)

    Returns:
        dict: Structured traffic summary
    """
    # Counters accumulate totals as we loop through packets
    protocol_counts = Counter()   # {"TCP": 42, "UDP": 18, ...}
    conversation_counts = Counter()  # {("192.168.1.1", "192.168.1.2"): 5, ...}
    unique_ips = set()            # All IPs seen, source or destination
    total_bytes = 0

    for pkt in packets:
        # len(pkt) gives the total captured frame size in bytes
        total_bytes += len(pkt)

        # --- Classify protocol ---
        # We check layers from most specific to least specific.
        # A TCP packet has both IP and TCP layers — we label it "TCP".
        if pkt.haslayer(TCP):
            protocol_counts["TCP"] += 1
        elif pkt.haslayer(UDP):
            protocol_counts["UDP"] += 1
        elif pkt.haslayer(ICMP):
            protocol_counts["ICMP"] += 1
        elif pkt.haslayer(ARP):
            protocol_counts["ARP"] += 1
            # ARP has its own address fields (psrc/pdst), not IP layer
            arp = pkt[ARP]
            if arp.psrc:
                unique_ips.add(arp.psrc)
            if arp.pdst:
                unique_ips.add(arp.pdst)
        else:
            protocol_counts["Other"] += 1

        # --- Extract IP addresses ---
        # Only IP packets have src/dst IP fields.
        # ARP is handled above separately.
        if pkt.haslayer(IP):
            src = pkt[IP].src
            dst = pkt[IP].dst
            unique_ips.add(src)
            unique_ips.add(dst)
            # Track how many packets flowed from src → dst
            conversation_counts[(src, dst)] += 1

    # --- Build top 10 conversations ---
    # most_common(10) returns [(key, count), ...] sorted by count descending
    top_conversations = [
        {"src": src, "dst": dst, "packets": count}
        for (src, dst), count in conversation_counts.most_common(10)
    ]

    # Remove the placeholder "0.0.0.0" that ARP sometimes produces
    unique_ips.discard("0.0.0.0")

    return {
        "interface": interface,
        "duration_seconds": duration,
        "total_packets": len(packets),
        "total_bytes": total_bytes,
        "protocols": dict(protocol_counts),
        "unique_ips": sorted(unique_ips),   # sorted for consistent output
        "top_conversations": top_conversations,
    }
