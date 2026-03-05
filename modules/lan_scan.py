"""
CyberDeck Module: lan_scan
==========================
Discovers devices on the local network and scans their open ports.

Scan runs in two phases:
    1. Host discovery — ping scan the entire subnet to find live IPs (fast)
    2. Port scan     — for each live host, probe ports and detect services

Dependencies:
    python-nmap  (pip install python-nmap)
    nmap binary  (sudo apt install nmap  — pre-installed on Kali)

Config fields:
    config["network"]["target_subnet"]   — CIDR range to scan, e.g. "192.168.1.0/24"
    config["network"]["lan_interface"]   — interface name, used for logging only
    config["scan"]["lan_scan_timeout"]   — per-host timeout in seconds
    config["scan"]["port_range"]         — port range string, e.g. "1-1024"

Output format:
    data = {
        "subnet":      str   — subnet that was scanned
        "interface":   str   — interface from config
        "hosts_found": int   — number of live hosts discovered
        "hosts": [
            {
                "ip":         str  — IPv4 address
                "mac":        str  — MAC address (empty if not on local subnet)
                "hostname":   str  — reverse DNS name (empty if not resolved)
                "state":      str  — "up" or "down"
                "open_ports": [
                    {
                        "port":     int  — port number
                        "protocol": str  — "tcp" or "udp"
                        "service":  str  — service name, e.g. "http"
                        "version":  str  — version string if detected
                    }
                ]
            }
        ]
    }

Limitations:
    - MAC addresses only visible when scanning the local subnet (requires ARP, layer 2)
    - OS detection (-O) requires root/sudo — omitted to allow unprivileged testing
    - Some hosts block ICMP ping; they may appear as down even if alive
    - Accuracy depends on nmap version installed on the system
"""

import logging
from datetime import datetime

import nmap  # python-nmap: thin wrapper that calls nmap binary and parses XML output

logger = logging.getLogger("cyberdeck")


def run(config: dict) -> dict:
    """
    Execute the LAN scan: discover hosts then scan their ports.

    Args:
        config: Full config dictionary from config.json

    Returns:
        dict: Standardized result with keys:
              module, timestamp, status, data, errors
    """
    logger.info("Starting lan_scan...")

    # Read all settings from config — never hardcode network values
    subnet = config["network"]["target_subnet"]
    interface = config["network"]["lan_interface"]
    timeout = config["scan"]["lan_scan_timeout"]
    port_range = config["scan"]["port_range"]

    logger.info("Scanning subnet %s on interface %s", subnet, interface)

    errors = []

    try:
        # --- Phase 1: Host discovery ---
        # Ping scan (-sn) finds which IPs are alive without probing ports.
        # This is fast and gives us the target list for the slower port scan.
        live_hosts = _discover_hosts(subnet, timeout)
        logger.info("Host discovery complete — %d live host(s) found", len(live_hosts))

        # --- Phase 2: Port scan each live host ---
        # Scan ports and detect service versions (-sV) for each live host.
        # We scan hosts one at a time so a slow host doesn't block the others.
        host_results = []
        for ip in live_hosts:
            logger.info("Scanning ports on %s", ip)
            host_data, host_errors = _scan_host(ip, port_range, timeout)
            host_results.append(host_data)
            errors.extend(host_errors)

        result_data = {
            "subnet": subnet,
            "interface": interface,
            "hosts_found": len(host_results),
            "hosts": host_results,
        }

        logger.info(
            "lan_scan completed — %d host(s) scanned, %d error(s)",
            len(host_results),
            len(errors),
        )

        # Use "partial" status if the scan ran but some hosts had errors
        status = "success" if not errors else "partial"

        return {
            "module": "lan_scan",
            "timestamp": datetime.now().isoformat(),
            "status": status,
            "data": result_data,
            "errors": errors,
        }

    except Exception as e:
        logger.error("lan_scan failed: %s", e)

        return {
            "module": "lan_scan",
            "timestamp": datetime.now().isoformat(),
            "status": "error",
            "data": {},
            "errors": [str(e)],
        }


def _discover_hosts(subnet: str, timeout: int) -> list:
    """
    Ping scan a subnet and return a list of live IP addresses.

    Uses nmap's -sn (no port scan) flag — this sends ICMP echo requests
    and ARP requests (on local subnets) to find which hosts respond.
    Much faster than a full port scan for initial discovery.

    Args:
        subnet:  CIDR notation subnet, e.g. "192.168.1.0/24"
        timeout: Per-host timeout in seconds

    Returns:
        list: IP address strings for hosts that responded (state == "up")
    """
    nm = nmap.PortScanner()

    # -sn  = ping scan, no port probing
    # --host-timeout = give up on a host after this many seconds
    arguments = f"-sn --host-timeout {timeout}s"

    logger.debug("Running host discovery: nmap %s %s", arguments, subnet)
    nm.scan(hosts=subnet, arguments=arguments)

    # Filter to only hosts nmap confirmed as "up"
    live = [host for host in nm.all_hosts() if nm[host].state() == "up"]

    return live


def _scan_host(ip: str, port_range: str, timeout: int) -> tuple:
    """
    Port scan a single host and return its open ports and service info.

    Uses -sV (service version detection) to identify what is running on
    each open port. nmap sends probe packets and matches responses against
    its service fingerprint database.

    Args:
        ip:         IPv4 address string to scan
        port_range: Port range string, e.g. "1-1024"
        timeout:    Per-host timeout in seconds

    Returns:
        tuple: (host_dict, errors_list)
            host_dict — structured data for this host
            errors_list — list of error strings if anything went wrong
    """
    nm = nmap.PortScanner()
    errors = []

    # -sV  = service/version detection on open ports
    # -p   = port range to scan
    # --host-timeout = give up on this host after N seconds
    arguments = f"-sV -p {port_range} --host-timeout {timeout}s"

    logger.debug("Running port scan: nmap %s %s", arguments, ip)

    try:
        nm.scan(hosts=ip, arguments=arguments)
    except nmap.PortScannerError as e:
        # This happens if the nmap binary is missing or the arguments are invalid
        errors.append(f"nmap error on {ip}: {e}")
        return {"ip": ip, "mac": "", "hostname": "", "state": "error", "open_ports": []}, errors

    # Guard: nmap may return no data if the host went down between discovery and scan
    if ip not in nm.all_hosts():
        errors.append(f"No scan data returned for {ip}")
        return {"ip": ip, "mac": "", "hostname": "", "state": "unknown", "open_ports": []}, errors

    host = nm[ip]

    # --- Extract hostname ---
    # nmap returns a list of hostname dicts: [{"name": "router.local", "type": "PTR"}]
    # We take the first one if available, otherwise empty string
    hostnames = host.hostnames()
    hostname = hostnames[0]["name"] if hostnames else ""

    # --- Extract MAC address ---
    # ARP resolution only works on the local subnet (layer 2 broadcast).
    # Across a router, nmap cannot see the MAC — the field will be absent.
    mac = host.get("addresses", {}).get("mac", "")

    # --- Extract open ports ---
    # host.all_protocols() returns ["tcp"] or ["tcp", "udp"] depending on scan type
    open_ports = []
    for proto in host.all_protocols():
        for port_num, port_info in host[proto].items():
            if port_info["state"] == "open":
                open_ports.append({
                    "port": port_num,
                    "protocol": proto,
                    # "name" is the well-known service name (e.g. "http", "ssh")
                    "service": port_info.get("name", ""),
                    # "version" is the banner/fingerprint string (e.g. "OpenSSH 8.9")
                    "version": port_info.get("version", ""),
                })

    return {
        "ip": ip,
        "mac": mac,
        "hostname": hostname,
        "state": host.state(),
        "open_ports": open_ports,
    }, errors
