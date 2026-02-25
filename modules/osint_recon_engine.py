"""
CyberDeck Module: osint_recon_engine
===================================

Internal discovery (local, on-site):
- Discovers live hosts in target_subnet (nmap -sn)
- Best-effort hostname collection (reverse DNS)
- Extracts domains from discovered hostnames (e.g., host.company.com -> company.com)

External intelligence gathering (internet-connected):
- DNS enumeration (A/AAAA/MX/NS/TXT/CNAME)
- WHOIS lookup (registrar/org/dates/nameservers)
- Certificate Transparency (crt.sh) subdomain discovery (no API key)
- TheHarvester (optional, via subprocess) to collect emails/subdomains

Maltego:
- We do not "automate Maltego" (GUI tool), but we export a Maltego-friendly CSV
  so analysts can import and pivot inside Maltego (realistic + persuasive).

Dependencies:
- Required (full mode): nmap
- Optional (external OSINT): theHarvester
- Optional Python libs: requests, dnspython, python-whois
  (module degrades gracefully if missing)

Config fields used (config/config.json):
- network.target_subnet
- scan.lan_scan_timeout
- output.results_dir

Optional osint config (recommended):
- osint.enable_external (bool, default True)
- osint.allowed_domains (list[str])  # safety gate: only run external OSINT for these
- osint.ct_enabled (bool, default True)
- osint.dns_enabled (bool, default True)
- osint.whois_enabled (bool, default True)
- osint.harvester_enabled (bool, default True)
- osint.harvester_timeout (int, default 120)
- osint.maltego_export (bool, default True)
- osint.dev_mode (bool, default False)  # for Windows local smoke testing

Output format (data):
{
  "internal_discovery": {
     "target_subnet": "...",
     "live_hosts_count": int,
     "hosts": [{"ip": "...", "hostname": "...|None", "domain": "...|None"}]
  },
  "external_osint": {
     "enabled": bool,
     "domains": [
        {
          "domain": "...",
          "dns": {...},
          "whois": {...},
          "ct": {...},
          "theharvester": {...},
          "subdomains": [...],
          "emails": [...],
          "exposure_flags": [...],
          "risk_score": float
        }
     ]
  },
  "correlation": {
     "domains_discovered": [...],
     "domains_count": int,
     "max_domain_risk": float,
     "avg_domain_risk": float
  },
  "exports": {
     "maltego_csv": [ "...path..." ]
  }
}

Limitations:
- Reverse DNS depends on local DNS/mDNS environment.
- External OSINT may be rate-limited or unavailable; module returns partial in that case.
"""

from __future__ import annotations

import csv
import logging
import re
import shutil
import socket
import subprocess
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

logger = logging.getLogger("cyberdeck")


# ---------- Safe optional imports (avoid crashes on Windows / minimal env) ----------

def _import_requests():
    try:
        import requests  # type: ignore
        return requests
    except Exception:
        return None


def _import_dns_resolver():
    try:
        import dns.resolver  # type: ignore
        return dns.resolver
    except Exception:
        return None


def _import_whois():
    try:
        import whois  # type: ignore
        return whois
    except Exception:
        return None


# ---------- Small utilities ----------

def _now_iso() -> str:
    return datetime.now().isoformat()


def _extract_domain(hostname: str) -> Optional[str]:
    """
    Simple domain extraction.
    Example: web.company.com -> company.com

    Why simple:
    - No heavy public suffix list dependency
    - Works for most academic demo cases
    """
    h = hostname.strip().strip(".").lower()
    if "." not in h:
        return None
    parts = h.split(".")
    if len(parts) < 2:
        return None
    return ".".join(parts[-2:])


def _reverse_dns(ip: str) -> Optional[str]:
    """Best-effort reverse DNS."""
    try:
        hostname, _, _ = socket.gethostbyaddr(ip)
        return hostname
    except Exception:
        return None


# ---------- Internal discovery (autonomous) ----------

def _nmap_ping_sweep(target_subnet: str, timeout_s: int) -> Tuple[List[str], List[str]]:
    """
    Runs: nmap -sn <subnet> -oG -
    Parses live IPs.

    Returns:
      (ips, errors)
    """
    if not shutil.which("nmap"):
        return [], ["nmap not found. Install on Kali/RPi: sudo apt install nmap"]

    cmd = ["nmap", "-sn", target_subnet, "-oG", "-"]

    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=max(5, timeout_s),
            check=False,
        )
    except subprocess.TimeoutExpired:
        return [], [f"nmap ping sweep timed out after {timeout_s}s"]
    except Exception as exc:
        return [], [f"nmap execution error: {exc}"]

    if proc.returncode != 0:
        return [], [f"nmap failed (code={proc.returncode}): {proc.stderr.strip()}"]

    ips: Set[str] = set()
    # Grepable output example:
    # Host: 192.168.1.10 ()  Status: Up
    for line in proc.stdout.splitlines():
        line = line.strip()
        if line.startswith("Host:") and "Status: Up" in line:
            parts = line.split()
            if len(parts) >= 2:
                ips.add(parts[1].strip())

    return sorted(ips), []


# ---------- External OSINT (no Shodan key required) ----------

def _dns_enumeration(domain: str) -> Dict[str, Any]:
    resolver = _import_dns_resolver()
    if resolver is None:
        return {"error": "dnspython not installed (pip install dnspython)"}

    out: Dict[str, Any] = {}
    for rtype in ["A", "AAAA", "MX", "NS", "TXT", "CNAME"]:
        try:
            answers = resolver.resolve(domain, rtype, lifetime=4)
            out[rtype] = [str(a).strip() for a in answers]
        except Exception:
            out[rtype] = []
    return out


def _whois_lookup(domain: str) -> Dict[str, Any]:
    whois_mod = _import_whois()
    if whois_mod is None:
        return {"error": "python-whois not installed (pip install python-whois)"}

    try:
        w = whois_mod.whois(domain)
        # Keep selected fields only (whois output is often messy/unbounded).
        return {
            "domain_name": str(getattr(w, "domain_name", "")),
            "registrar": str(getattr(w, "registrar", "")),
            "org": str(getattr(w, "org", "")),
            "creation_date": str(getattr(w, "creation_date", "")),
            "expiration_date": str(getattr(w, "expiration_date", "")),
            "name_servers": [str(x) for x in (getattr(w, "name_servers", []) or [])],
            "country": str(getattr(w, "country", "")),
        }
    except Exception as exc:
        return {"error": f"whois failed: {exc}"}


def _crtsh_subdomains(domain: str) -> Dict[str, Any]:
    """
    Certificate Transparency enumeration using crt.sh JSON (no API key).
    """
    requests = _import_requests()
    if requests is None:
        return {"error": "requests not installed (pip install requests)"}

    url = f"https://crt.sh/?q=%25.{domain}&output=json"

    try:
        r = requests.get(url, timeout=8)
        if r.status_code != 200:
            return {"error": f"crt.sh HTTP {r.status_code}"}

        try:
            data = r.json()
        except Exception:
            return {"error": "crt.sh returned non-JSON content"}

        subs: Set[str] = set()
        if isinstance(data, list):
            for item in data:
                name_val = str(item.get("name_value", "")).strip()
                if not name_val:
                    continue
                for line in name_val.splitlines():
                    s = line.strip().lower()
                    if s.endswith(domain) and "*" not in s:
                        subs.add(s)

        return {"subdomains": sorted(subs), "count": len(subs)}
    except Exception as exc:
        return {"error": f"crt.sh failed: {exc}"}


def _run_theharvester(domain: str, timeout_s: int) -> Dict[str, Any]:
    """
    Calls theHarvester via subprocess if installed.
    We keep parsing conservative (regex-based) because theHarvester output varies by version.

    Why subprocess:
    - Most persuasive for the project (real OSINT automation)
    - Still safe: timeout prevents "hanging" the Raspberry
    - Optional: if not installed, we return a clean error and continue
    """
    if not shutil.which("theHarvester"):
        return {"enabled": False, "error": "theHarvester not installed"}

    cmd = ["theHarvester", "-d", domain, "-b", "crtsh"]

    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=max(10, timeout_s),
            check=False,
        )
    except subprocess.TimeoutExpired:
        return {"enabled": True, "error": f"theHarvester timed out after {timeout_s}s"}
    except Exception as exc:
        return {"enabled": True, "error": f"theHarvester execution error: {exc}"}

    if proc.returncode != 0:
        return {"enabled": True, "error": proc.stderr.strip() or f"return_code={proc.returncode}"}

    # Conservative parsing
    emails = sorted(set(re.findall(r"[A-Za-z0-9._%+-]+@" + re.escape(domain), proc.stdout)))
    subdomains = sorted(
        set(s.lower() for s in re.findall(r"([A-Za-z0-9.-]+\." + re.escape(domain) + r")", proc.stdout))
    )

    return {
        "enabled": True,
        "emails": emails,
        "subdomains": subdomains,
        "raw_summary": f"stdout_len={len(proc.stdout)}",
    }


# ---------- Correlation / scoring ----------

def _exposure_flags(dns: Dict[str, Any]) -> List[str]:
    """
    Explainable flags derived from DNS results (simple but defensible in a viva).
    """
    flags: List[str] = []

    txt_records = " ".join(dns.get("TXT", []) or []).lower()
    if "v=spf1" not in txt_records:
        flags.append("missing_spf_record")

    if not (dns.get("MX") or []):
        flags.append("no_mx_records")

    return flags


def _risk_score(flags: List[str], subdomain_count: int, email_count: int) -> float:
    """
    0..100 score.
    Why simple:
    - explainable
    - avoids "black box" scoring
    """
    score = 0.0
    score += 15.0 * len(flags)
    score += min(subdomain_count * 1.0, 25.0)
    score += min(email_count * 2.0, 20.0)
    return float(min(score, 100.0))


def _export_maltego_csv(exports_dir: Path, domain: str, subdomains: List[str], emails: List[str]) -> str:
    """
    Export a Maltego-friendly CSV:
    type,value
    Domain,example.com
    DNSName,sub.example.com
    EmailAddress,user@example.com
    """
    exports_dir.mkdir(parents=True, exist_ok=True)
    out_path = exports_dir / f"maltego_seed_{domain}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"

    with out_path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["type", "value"])
        writer.writerow(["Domain", domain])
        for s in subdomains:
            writer.writerow(["DNSName", s])
        for e in emails:
            writer.writerow(["EmailAddress", e])

    return str(out_path)


# ---------- Module entrypoint (contract) ----------

def run(config: dict) -> dict:
    """
    Execute osint_recon_engine.

    Returns standardized result dict:
    {module, timestamp, status, data, errors}
    """
    logger.info("Starting osint_recon_engine...")

    errors: List[str] = []

    try:
        # Required config
        target_subnet = str(config["network"]["target_subnet"])
        timeout_s = int(config["scan"]["lan_scan_timeout"])
        results_dir = Path(str(config["output"]["results_dir"]))

        # Optional OSINT config
        osint_cfg = config.get("osint", {})
        dev_mode = bool(osint_cfg.get("dev_mode", False))

        enable_external = bool(osint_cfg.get("enable_external", True))
        dns_enabled = bool(osint_cfg.get("dns_enabled", True))
        whois_enabled = bool(osint_cfg.get("whois_enabled", True))
        ct_enabled = bool(osint_cfg.get("ct_enabled", True))
        harvester_enabled = bool(osint_cfg.get("harvester_enabled", True))
        harvester_timeout = int(osint_cfg.get("harvester_timeout", 120))
        maltego_export = bool(osint_cfg.get("maltego_export", True))

        # Safety gate (important when doing external OSINT):
        # We only run external OSINT for domains in allowed_domains.
        allowed_domains = osint_cfg.get("allowed_domains", [])
        if not isinstance(allowed_domains, list):
            allowed_domains = []

        # -------------------------
        # 1) Internal discovery
        # -------------------------
        if dev_mode:
            # Windows-friendly: no nmap required, predictable output for local tests.
            logger.warning("osint_recon_engine running in dev_mode (mock internal discovery).")
            ips = ["192.168.1.10", "192.168.1.20"]
            scan_errors = []
        else:
            ips, scan_errors = _nmap_ping_sweep(target_subnet, timeout_s)

        errors.extend(scan_errors)

        hosts: List[Dict[str, Any]] = []
        discovered_domains: Set[str] = set()

        for ip in ips:
            hostname = _reverse_dns(ip) if not dev_mode else f"host{ip.split('.')[-1]}.example.com"
            domain = _extract_domain(hostname) if hostname else None

            if domain:
                discovered_domains.add(domain)

            hosts.append({"ip": ip, "hostname": hostname, "domain": domain})

        internal_data = {
            "target_subnet": target_subnet,
            "live_hosts_count": len(ips),
            "hosts": hosts,
        }

        # -------------------------
        # 2) External OSINT
        # -------------------------
        external_data: Dict[str, Any] = {"enabled": enable_external, "domains": []}
        exports: Dict[str, Any] = {}

        # Select domains eligible for external OSINT
        # - If allowed_domains provided, only use those that match discovered domains
        # - If allowed_domains is empty, we skip external OSINT for safety (and report why)
        eligible_domains = sorted(d for d in discovered_domains if d in allowed_domains)

        if enable_external and not allowed_domains:
            errors.append(
                "External OSINT skipped: config.osint.allowed_domains is empty. "
                "Add authorized domains to allowed_domains to enable external OSINT."
            )

        if enable_external and eligible_domains:
            for domain in eligible_domains:
                dns = _dns_enumeration(domain) if dns_enabled else {"disabled": True}
                whois = _whois_lookup(domain) if whois_enabled else {"disabled": True}
                ct = _crtsh_subdomains(domain) if ct_enabled else {"disabled": True}
                harv = _run_theharvester(domain, harvester_timeout) if harvester_enabled else {"disabled": True}

                subdomains: Set[str] = set()
                emails: Set[str] = set()

                if isinstance(ct, dict) and isinstance(ct.get("subdomains"), list):
                    subdomains.update(str(x).lower() for x in ct["subdomains"])

                if isinstance(harv, dict) and harv.get("enabled") is True:
                    subdomains.update(str(x).lower() for x in (harv.get("subdomains") or []))
                    emails.update(str(x).lower() for x in (harv.get("emails") or []))

                flags = _exposure_flags(dns if isinstance(dns, dict) else {})
                score = _risk_score(flags, len(subdomains), len(emails))

                if maltego_export:
                    export_path = _export_maltego_csv(results_dir / "exports", domain, sorted(subdomains), sorted(emails))
                    exports.setdefault("maltego_csv", []).append(export_path)

                external_data["domains"].append(
                    {
                        "domain": domain,
                        "dns": dns,
                        "whois": whois,
                        "ct": ct,
                        "theharvester": harv,
                        "subdomains": sorted(subdomains),
                        "emails": sorted(emails),
                        "exposure_flags": flags,
                        "risk_score": score,
                    }
                )

        # -------------------------
        # 3) Correlation summary
        # -------------------------
        scores = [float(d.get("risk_score", 0.0)) for d in external_data.get("domains", [])]
        correlation = {
            "domains_discovered": sorted(discovered_domains),
            "domains_count": len(discovered_domains),
            "eligible_domains": eligible_domains,
            "max_domain_risk": max(scores) if scores else 0.0,
            "avg_domain_risk": (sum(scores) / len(scores)) if scores else 0.0,
        }

        status = "success" if not errors else "partial"

        return {
            "module": "osint_recon_engine",
            "timestamp": _now_iso(),
            "status": status,
            "data": {
                "internal_discovery": internal_data,
                "external_osint": external_data,
                "correlation": correlation,
                "exports": exports,
                "notes": {
                    "shodan": {
                        "enabled": False,
                        "reason": "No Shodan API key provided. Using DNS/WHOIS/CT/TheHarvester."
                    }
                },
            },
            "errors": errors,
        }

    except Exception as e:
        logger.error(f"osint_recon_engine failed: {e}")
        return {
            "module": "osint_recon_engine",
            "timestamp": _now_iso(),
            "status": "error",
            "data": {},
            "errors": [str(e)],
        }