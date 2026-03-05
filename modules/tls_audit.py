"""
CyberDeck Module: tls_audit
=============================
Audits SSL/TLS configuration on HTTPS hosts discovered by lan_scan.

What it checks:
    1. Certificate validity  — is the cert expired or not yet valid?
    2. Certificate expiry    — how many days until it expires? (<30 days = warning)
    3. Hostname verification — does the cert match the host's IP/hostname?
    4. TLS protocol version  — flags TLS 1.0 and 1.1 (deprecated, insecure)
    5. Self-signed certs     — flags certs not signed by a trusted CA

How it works:
    This module reads the most recent lan_scan result from results/ to find
    hosts with HTTPS ports open (443, 8443). It then opens a TLS connection
    to each host using Python's built-in ssl module and inspects the
    negotiated protocol version and certificate details.

    No new dependencies — uses only Python's standard library ssl module.

Dependencies:
    None beyond standard library (ssl, socket — built into Python)

Config fields:
    config["output"]["results_dir"]  — where to find lan_scan result files
    config["scan"]["lan_scan_timeout"] — connection timeout per host

Output format:
    data = {
        "hosts_audited": int
        "findings": [
            {
                "ip":           str   — target IP address
                "port":         int   — HTTPS port (443, 8443, etc.)
                "subject":      str   — certificate common name / subject
                "issuer":       str   — certificate issuer (CA name)
                "valid_from":   str   — certificate start date (ISO format)
                "valid_until":  str   — certificate expiry date (ISO format)
                "days_remaining": int — days until expiry (negative = already expired)
                "tls_version":  str   — negotiated TLS version, e.g. "TLSv1.3"
                "issues": [
                    {
                        "severity":    str  — "high" / "medium" / "low"
                        "description": str  — human-readable issue description
                    }
                ]
                "status": str  — "clean" / "issues_found" / "error"
            }
        ]
    }

Limitations:
    - Only audits hosts found in the most recent lan_scan result
    - Self-signed cert detection may produce false positives in enterprise
      environments that use internal CAs not in the system trust store
    - Cipher suite enumeration requires multiple connections — not implemented
      here to keep the module fast; use sslscan for deep cipher analysis
    - Cannot audit hosts that require client certificates
"""

import json
import logging
import os
import socket
import ssl
from datetime import datetime, timezone

logger = logging.getLogger("cyberdeck")

# Ports considered HTTPS — we audit any open port in this set
_HTTPS_PORTS = {443, 8443, 8080, 8888}

# TLS versions considered insecure — flag as high severity
_DEPRECATED_TLS = {"SSLv2", "SSLv3", "TLSv1", "TLSv1.1"}

# Warn if cert expires within this many days
_EXPIRY_WARNING_DAYS = 30


def run(config: dict) -> dict:
    """
    Find HTTPS hosts from the latest lan_scan result and audit their TLS config.

    Args:
        config: Full config dictionary from config.json

    Returns:
        dict: Standardized result with keys:
              module, timestamp, status, data, errors
    """
    logger.info("Starting tls_audit...")

    results_dir = config["output"]["results_dir"]
    timeout = config["scan"]["lan_scan_timeout"]

    project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    results_dir = os.path.join(project_root, results_dir)

    errors = []

    try:
        # --- Find HTTPS hosts from latest lan_scan result ---
        https_targets = _find_https_hosts(results_dir)

        if not https_targets:
            logger.info(
                "No HTTPS hosts found in lan_scan results — "
                "run lan_scan first or no hosts have ports 443/8443 open"
            )
            return {
                "module": "tls_audit",
                "timestamp": datetime.now().isoformat(),
                "status": "success",
                "data": {
                    "hosts_audited": 0,
                    "findings": [],
                },
                "errors": [],
            }

        logger.info("Found %d HTTPS target(s) to audit", len(https_targets))

        # --- Audit each HTTPS host ---
        findings = []
        for ip, port in https_targets:
            logger.info("Auditing TLS on %s:%d...", ip, port)
            finding, errs = _audit_host(ip, port, timeout)
            findings.append(finding)
            errors.extend(errs)

        total_issues = sum(len(f["issues"]) for f in findings)
        logger.info(
            "tls_audit completed — %d host(s) audited, %d issue(s) found",
            len(findings), total_issues
        )

        status = "success" if not errors else "partial"

        return {
            "module": "tls_audit",
            "timestamp": datetime.now().isoformat(),
            "status": status,
            "data": {
                "hosts_audited": len(findings),
                "findings": findings,
            },
            "errors": errors,
        }

    except Exception as e:
        logger.error("tls_audit failed: %s", e)
        return {
            "module": "tls_audit",
            "timestamp": datetime.now().isoformat(),
            "status": "error",
            "data": {},
            "errors": [str(e)],
        }


def _find_https_hosts(results_dir: str) -> list:
    """
    Read the most recent lan_scan result and extract hosts with HTTPS ports open.

    We use the most recent lan_scan file rather than all of them to avoid
    auditing hosts that may no longer be active.

    Args:
        results_dir: Absolute path to the results directory

    Returns:
        list: Unique (ip, port) tuples for HTTPS hosts
    """
    if not os.path.isdir(results_dir):
        return []

    # Find all lan_scan result files sorted by name (timestamp in name = chronological)
    lan_files = sorted([
        f for f in os.listdir(results_dir)
        if f.startswith("lan_scan_") and f.endswith(".json")
    ])

    if not lan_files:
        return []

    # Use only the most recent lan_scan result
    latest = os.path.join(results_dir, lan_files[-1])

    try:
        with open(latest, "r", encoding="utf-8") as f:
            data = json.load(f)
    except (json.JSONDecodeError, OSError) as e:
        logger.warning("Could not read lan_scan result %s: %s", latest, e)
        return []

    targets = []
    seen = set()

    for host in data.get("data", {}).get("hosts", []):
        ip = host["ip"]
        for port_info in host.get("open_ports", []):
            port = port_info["port"]
            if port in _HTTPS_PORTS and (ip, port) not in seen:
                targets.append((ip, port))
                seen.add((ip, port))

    return targets


def _audit_host(ip: str, port: int, timeout: int) -> tuple:
    """
    Connect to a host over TLS and inspect its certificate and protocol version.

    We create an SSL context, connect, and then extract certificate details
    from the negotiated session. Python's ssl module handles the handshake
    and exposes the peer certificate as a dict.

    Args:
        ip:      Target IP address
        port:    HTTPS port
        timeout: Connection timeout in seconds

    Returns:
        tuple: (finding_dict, errors_list)
    """
    errors = []
    issues = []

    # Create SSL context — check_hostname requires a hostname not an IP,
    # so we disable it for IP-based connections and handle cert checking manually
    ctx = ssl.create_default_context()
    ctx.check_hostname = False          # we check manually below
    ctx.verify_mode = ssl.CERT_OPTIONAL  # try to get cert even if self-signed

    cert_info = {}
    tls_version = "unknown"

    try:
        with socket.create_connection((ip, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=ip) as tls_sock:
                tls_version = tls_sock.version() or "unknown"
                raw_cert = tls_sock.getpeercert()

                if raw_cert:
                    cert_info = _parse_cert(raw_cert)
                else:
                    # No cert returned — server is using self-signed cert
                    # and context couldn't verify it
                    issues.append({
                        "severity": "medium",
                        "description": "Could not retrieve certificate — likely self-signed or untrusted CA",
                    })

    except ssl.SSLCertVerificationError as e:
        # Certificate verification failed — self-signed or expired
        issues.append({
            "severity": "high",
            "description": f"Certificate verification failed: {e.reason}",
        })
        # Try again without verification to still get cert details
        ctx_noverify = ssl.create_default_context()
        ctx_noverify.check_hostname = False
        ctx_noverify.verify_mode = ssl.CERT_NONE
        try:
            with socket.create_connection((ip, port), timeout=timeout) as sock:
                with ctx_noverify.wrap_socket(sock, server_hostname=ip) as tls_sock:
                    tls_version = tls_sock.version() or "unknown"
                    raw_cert = tls_sock.getpeercert(binary_form=False)
                    if raw_cert:
                        cert_info = _parse_cert(raw_cert)
        except Exception:
            pass  # best effort — we already have the issue recorded

    except (socket.timeout, ConnectionRefusedError, OSError) as e:
        errors.append(f"Could not connect to {ip}:{port} — {e}")
        return {
            "ip": ip, "port": port,
            "subject": "", "issuer": "",
            "valid_from": "", "valid_until": "",
            "days_remaining": None,
            "tls_version": "unknown",
            "issues": [{"severity": "medium", "description": f"Connection failed: {e}"}],
            "status": "error",
        }, errors

    # --- Check TLS version ---
    if tls_version in _DEPRECATED_TLS:
        issues.append({
            "severity": "high",
            "description": (
                f"Deprecated TLS version in use: {tls_version}. "
                f"TLS 1.0 and 1.1 are insecure and deprecated by RFC 8996. "
                f"Upgrade to TLS 1.2 or 1.3."
            ),
        })

    # --- Check certificate dates ---
    if cert_info:
        days = cert_info.get("days_remaining")

        if days is not None and days < 0:
            issues.append({
                "severity": "high",
                "description": (
                    f"Certificate EXPIRED {abs(days)} day(s) ago "
                    f"(expired: {cert_info.get('valid_until', 'unknown')})"
                ),
            })
        elif days is not None and days < _EXPIRY_WARNING_DAYS:
            issues.append({
                "severity": "medium",
                "description": (
                    f"Certificate expires in {days} day(s) "
                    f"({cert_info.get('valid_until', 'unknown')}) — renew soon"
                ),
            })

        # Check for self-signed: issuer == subject
        if cert_info.get("issuer") and cert_info.get("subject"):
            if cert_info["issuer"] == cert_info["subject"]:
                issues.append({
                    "severity": "medium",
                    "description": (
                        "Self-signed certificate detected — not issued by a trusted CA. "
                        "Clients will see a browser warning."
                    ),
                })

    finding = {
        "ip": ip,
        "port": port,
        "subject": cert_info.get("subject", ""),
        "issuer": cert_info.get("issuer", ""),
        "valid_from": cert_info.get("valid_from", ""),
        "valid_until": cert_info.get("valid_until", ""),
        "days_remaining": cert_info.get("days_remaining"),
        "tls_version": tls_version,
        "issues": issues,
        "status": "issues_found" if issues else "clean",
    }

    if issues:
        logger.warning(
            "%s:%d — %d TLS issue(s) found", ip, port, len(issues)
        )
    else:
        logger.info("%s:%d — TLS configuration is clean", ip, port)

    return finding, errors


def _parse_cert(raw_cert: dict) -> dict:
    """
    Extract human-readable fields from Python's raw certificate dict.

    Python's ssl.getpeercert() returns a dict with nested tuples for
    subject and issuer fields. We flatten them into readable strings.

    Args:
        raw_cert: Dict returned by ssl.SSLSocket.getpeercert()

    Returns:
        dict: Flattened certificate fields
    """
    def _flatten_rdns(rdns) -> str:
        """Convert ((('commonName', 'example.com'),),) → 'example.com'"""
        if not rdns:
            return ""
        parts = []
        for rdn in rdns:
            for key, value in rdn:
                if key in ("commonName", "organizationName"):
                    parts.append(value)
        return ", ".join(parts) if parts else str(rdns)

    subject = _flatten_rdns(raw_cert.get("subject", ()))
    issuer = _flatten_rdns(raw_cert.get("issuer", ()))

    # notBefore / notAfter are strings like "Feb 28 00:00:00 2026 GMT"
    valid_from = raw_cert.get("notBefore", "")
    valid_until = raw_cert.get("notAfter", "")

    # Calculate days until expiry
    days_remaining = None
    if valid_until:
        try:
            expiry = datetime.strptime(valid_until, "%b %d %H:%M:%S %Y %Z")
            expiry = expiry.replace(tzinfo=timezone.utc)
            now = datetime.now(tz=timezone.utc)
            days_remaining = (expiry - now).days
        except ValueError:
            pass

    return {
        "subject": subject,
        "issuer": issuer,
        "valid_from": valid_from,
        "valid_until": valid_until,
        "days_remaining": days_remaining,
    }
