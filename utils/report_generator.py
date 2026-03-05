"""
CyberDeck Report Generator
===========================
Generates self-contained HTML audit reports from module result dicts.

How it works:
    Accepts a list of module result dicts (the standard CyberDeck JSON output
    format) and renders them into a single, self-contained HTML file using an
    embedded Jinja2 template.

    "Self-contained" means all CSS is inlined — no external stylesheets, fonts,
    or JavaScript libraries are fetched at runtime. This is critical for the Pi
    deployment: during an audit the Pi may not have internet access, and the
    HTML report must be openable on any machine by simply double-clicking the file.

    Each module gets a dedicated Jinja2 block that knows how to present its own
    data structure (hosts table for lan_scan, conversation list for passive_monitor,
    TLS finding cards for tls_audit, etc.). Unknown modules fall back to a formatted
    JSON dump so future modules are automatically included without changing this file.

Usage:
    from utils.report_generator import generate_report
    path = generate_report(results, config)
    print(f"Report saved to: {path}")

Args:
    results (list): List of module result dicts already loaded from JSON files.
                    Each dict follows the standard CyberDeck result schema:
                    { module, timestamp, status, data, errors }
    config  (dict): Full config dictionary from config.json.
                    Uses config["output"]["results_dir"] to determine where to
                    save the output HTML file, and config["project"]["version"]
                    for the report footer.

Returns:
    str: Absolute path to the generated HTML file.

Dependencies:
    jinja2 >= 3.1.0   (pip install jinja2)
"""

import json
import logging
import os
from datetime import datetime

from jinja2 import BaseLoader, Environment

logger = logging.getLogger("cyberdeck")


# ---------------------------------------------------------------------------
# Embedded HTML/Jinja2 template
# ---------------------------------------------------------------------------
# All CSS is inline — no external dependencies. The template uses Jinja2
# conditionals to branch on r.module and render module-specific tables,
# then falls back to a generic JSON <pre> block for any unknown module.
# This means adding a new module never requires changing this template —
# it will just display its raw data until a dedicated block is added.
# ---------------------------------------------------------------------------

_HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>CyberDeck Audit Report &mdash; {{ report_timestamp }}</title>
    <style>
        * { box-sizing: border-box; margin: 0; padding: 0; }
        body {
            font-family: 'Courier New', monospace;
            background: #0a0e1a;
            color: #c8d8e8;
            font-size: 14px;
            line-height: 1.6;
        }
        .header {
            background: linear-gradient(135deg, #0d1b2a, #1a2a4a);
            border-bottom: 2px solid #00d4ff;
            padding: 24px 40px;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        .header h1 { font-size: 28px; color: #00d4ff; letter-spacing: 2px; text-transform: uppercase; }
        .header h1 span { color: #ff6b35; }
        .header-meta { text-align: right; color: #7a9ab8; font-size: 12px; }
        .header-meta strong { color: #c8d8e8; }
        .container { padding: 32px 40px; max-width: 1200px; margin: 0 auto; }
        .summary-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
            gap: 16px;
            margin-bottom: 32px;
        }
        .stat-card {
            background: #111827;
            border: 1px solid #1e3a5f;
            border-radius: 6px;
            padding: 20px;
            text-align: center;
        }
        .stat-card.alert   { border-color: #ff4444; background: #1a0a0a; }
        .stat-card.warning { border-color: #ff9900; background: #1a1200; }
        .stat-card.clean   { border-color: #00cc66; background: #001a0d; }
        .stat-number { font-size: 36px; font-weight: bold; color: #00d4ff; }
        .stat-card.alert   .stat-number { color: #ff4444; }
        .stat-card.warning .stat-number { color: #ff9900; }
        .stat-card.clean   .stat-number { color: #00cc66; }
        .stat-label { color: #7a9ab8; font-size: 11px; text-transform: uppercase; margin-top: 4px; }
        .risk-banner {
            padding: 12px 18px;
            border-radius: 4px;
            font-weight: bold;
            font-size: 13px;
            margin-bottom: 28px;
            letter-spacing: 1px;
        }
        .risk-critical { background: #3d0000; border: 2px solid #ff4444; color: #ff4444; }
        .risk-warning  { background: #2d1a00; border: 2px solid #ff9900; color: #ff9900; }
        .risk-clean    { background: #002d16; border: 2px solid #00cc66; color: #00cc66; }
        .section {
            background: #111827;
            border: 1px solid #1e3a5f;
            border-radius: 6px;
            margin-bottom: 24px;
            overflow: hidden;
        }
        .section-header {
            background: #0d1b2a;
            padding: 14px 20px;
            border-bottom: 1px solid #1e3a5f;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        .section-header h2 { color: #00d4ff; font-size: 16px; letter-spacing: 1px; }
        .section-meta { color: #7a9ab8; font-size: 11px; }
        .section-body { padding: 20px; }
        table { width: 100%; border-collapse: collapse; margin-top: 12px; }
        th {
            background: #0d1b2a;
            color: #00d4ff;
            padding: 8px 12px;
            text-align: left;
            font-size: 11px;
            text-transform: uppercase;
            letter-spacing: 1px;
        }
        td { padding: 8px 12px; border-bottom: 1px solid #1e2d40; }
        tr:last-child td { border-bottom: none; }
        tr:hover td { background: #0d1b2a; }
        .badge {
            display: inline-block;
            padding: 2px 8px;
            border-radius: 3px;
            font-size: 11px;
            font-weight: bold;
            text-transform: uppercase;
        }
        .badge-high    { background: #3d0000; color: #ff4444; border: 1px solid #ff4444; }
        .badge-medium  { background: #2d1a00; color: #ff9900; border: 1px solid #ff9900; }
        .badge-low     { background: #1a2d00; color: #aaff44; border: 1px solid #aaff44; }
        .badge-success { background: #002d16; color: #00cc66; border: 1px solid #00cc66; }
        .badge-error   { background: #3d0000; color: #ff4444; border: 1px solid #ff4444; }
        .badge-partial { background: #2d1a00; color: #ff9900; border: 1px solid #ff9900; }
        pre {
            background: #0a0e1a;
            border: 1px solid #1e3a5f;
            border-radius: 4px;
            padding: 14px;
            overflow-x: auto;
            white-space: pre-wrap;
            word-wrap: break-word;
            color: #7dd3fc;
            font-size: 12px;
        }
        .alert-box {
            background: #1a0a0a;
            border: 1px solid #ff4444;
            border-radius: 4px;
            padding: 12px 16px;
            color: #ff8888;
            margin-top: 12px;
        }
        .clean-box {
            background: #001a0d;
            border: 1px solid #00cc66;
            border-radius: 4px;
            padding: 12px 16px;
            color: #66ffaa;
            margin-top: 12px;
        }
        .tls-card {
            margin-top: 16px;
            border: 1px solid #1e3a5f;
            border-radius: 4px;
            overflow: hidden;
        }
        .tls-card-header { background: #0d1b2a; padding: 8px 14px; color: #00d4ff; }
        .tls-card-body   { padding: 12px 14px; }
        .footer {
            text-align: center;
            padding: 24px;
            color: #3a5a7a;
            font-size: 11px;
            border-top: 1px solid #1e3a5f;
            margin-top: 24px;
        }
        p { margin-bottom: 4px; }
        .sub-heading { margin-top: 16px; color: #7a9ab8; font-size: 12px; }
    </style>
</head>
<body>

<div class="header">
    <div>
        <h1>Cyber<span>Deck</span> &mdash; Audit Report</h1>
    </div>
    <div class="header-meta">
        <div><strong>Generated:</strong> {{ report_timestamp }}</div>
        <div><strong>Modules run:</strong> {{ results|length }}</div>
        <div><strong>Total issues:</strong> {{ total_issues }}</div>
    </div>
</div>

<div class="container">

    {# Risk banner — highest severity present drives the colour #}
    {% if total_high > 0 %}
    <div class="risk-banner risk-critical">
        &#9888; CRITICAL &mdash; {{ total_high }} high-severity issue(s) detected. Immediate action required.
    </div>
    {% elif total_medium > 0 %}
    <div class="risk-banner risk-warning">
        &#9888; WARNING &mdash; {{ total_medium }} medium-severity issue(s) detected. Review recommended.
    </div>
    {% else %}
    <div class="risk-banner risk-clean">
        &#10003; CLEAN &mdash; No significant issues detected across {{ results|length }} module(s).
    </div>
    {% endif %}

    {# Executive summary cards #}
    <div class="summary-grid">
        <div class="stat-card">
            <div class="stat-number">{{ results|length }}</div>
            <div class="stat-label">Modules Run</div>
        </div>
        <div class="stat-card">
            <div class="stat-number">{{ total_hosts }}</div>
            <div class="stat-label">Hosts Discovered</div>
        </div>
        <div class="stat-card {% if total_high > 0 %}alert{% elif total_medium > 0 %}warning{% else %}clean{% endif %}">
            <div class="stat-number">{{ total_issues }}</div>
            <div class="stat-label">Total Issues</div>
        </div>
        <div class="stat-card {% if total_anomalies > 0 %}alert{% else %}clean{% endif %}">
            <div class="stat-number">{{ total_anomalies }}</div>
            <div class="stat-label">Anomalies Flagged</div>
        </div>
        <div class="stat-card {% if total_conflicts > 0 %}alert{% else %}clean{% endif %}">
            <div class="stat-number">{{ total_conflicts }}</div>
            <div class="stat-label">ARP Conflicts</div>
        </div>
    </div>

    {# One collapsible section per module result #}
    {% for r in results %}
    <div class="section">
        <div class="section-header">
            <h2>{{ r.module | upper | replace("_", " ") }}</h2>
            <div class="section-meta">
                {{ r.timestamp }}
                &nbsp;|&nbsp;
                <span class="badge badge-{{ r.status }}">{{ r.status }}</span>
            </div>
        </div>
        <div class="section-body">

            {# Always show module errors at the top #}
            {% if r.errors %}
            <div class="alert-box">
                <strong>Errors during scan:</strong>
                {% for e in r.errors %}<div style="margin-top:4px;">{{ e }}</div>{% endfor %}
            </div>
            {% endif %}

            {# ----------------------------------------------------------------
               lan_scan — hosts table with open ports
            ---------------------------------------------------------------- #}
            {% if r.module == "lan_scan" %}
            <p>
                Subnet: <strong>{{ r.data.get("subnet", "&mdash;") }}</strong>
                &nbsp;|&nbsp; Interface: <strong>{{ r.data.get("interface", "&mdash;") }}</strong>
                &nbsp;|&nbsp; Hosts found: <strong>{{ r.data.get("hosts_found", 0) }}</strong>
            </p>
            {% if r.data.get("hosts") %}
            <table>
                <thead>
                    <tr><th>IP Address</th><th>MAC</th><th>Hostname</th><th>State</th><th>Open Ports</th></tr>
                </thead>
                <tbody>
                    {% for host in r.data.hosts %}
                    <tr>
                        <td>{{ host.ip }}</td>
                        <td>{{ host.mac or "&mdash;" }}</td>
                        <td>{{ host.hostname or "&mdash;" }}</td>
                        <td><span class="badge badge-success">{{ host.state }}</span></td>
                        <td>
                            {% if host.open_ports %}
                                {% for p in host.open_ports %}
                                    {{ p.port }}/{{ p.protocol }}({{ p.service }}){% if not loop.last %}, {% endif %}
                                {% endfor %}
                            {% else %}&mdash;{% endif %}
                        </td>
                    </tr>
                    {% endfor %}
                </tbody>
            </table>
            {% else %}
            <div class="clean-box">No hosts discovered.</div>
            {% endif %}

            {# ----------------------------------------------------------------
               passive_monitor — protocol breakdown + top conversations
            ---------------------------------------------------------------- #}
            {% elif r.module == "passive_monitor" %}
            <p>
                Interface: <strong>{{ r.data.get("interface", "&mdash;") }}</strong>
                &nbsp;|&nbsp; Duration: <strong>{{ r.data.get("duration_seconds", "&mdash;") }}s</strong>
                &nbsp;|&nbsp; Packets: <strong>{{ r.data.get("total_packets", 0) }}</strong>
                &nbsp;|&nbsp; Bytes: <strong>{{ r.data.get("total_bytes", 0) }}</strong>
                &nbsp;|&nbsp; Unique IPs: <strong>{{ r.data.get("unique_ips", []) | length }}</strong>
            </p>
            {% if r.data.get("protocols") %}
            <table>
                <thead><tr><th>Protocol</th><th>Packet Count</th></tr></thead>
                <tbody>
                    {% for proto, count in r.data.protocols.items() %}
                    <tr><td>{{ proto }}</td><td>{{ count }}</td></tr>
                    {% endfor %}
                </tbody>
            </table>
            {% endif %}
            {% if r.data.get("top_conversations") %}
            <p class="sub-heading">Top Conversations</p>
            <table>
                <thead><tr><th>Source</th><th>Destination</th><th>Packets</th></tr></thead>
                <tbody>
                    {% for c in r.data.top_conversations %}
                    <tr><td>{{ c.src }}</td><td>{{ c.dst }}</td><td>{{ c.packets }}</td></tr>
                    {% endfor %}
                </tbody>
            </table>
            {% endif %}

            {# ----------------------------------------------------------------
               arp_monitor — conflict alerts + learned ARP table
            ---------------------------------------------------------------- #}
            {% elif r.module == "arp_monitor" %}
            <p>
                Interface: <strong>{{ r.data.get("interface", "&mdash;") }}</strong>
                &nbsp;|&nbsp; Duration: <strong>{{ r.data.get("duration_seconds", "&mdash;") }}s</strong>
                &nbsp;|&nbsp; Packets analysed: <strong>{{ r.data.get("packets_analysed", 0) }}</strong>
            </p>
            {% if r.data.get("conflicts_found", 0) > 0 %}
            <div class="alert-box">
                <strong>&#9888; ARP Conflicts Detected &mdash; Possible MITM Attack!</strong>
                {% for c in r.data.get("conflicts", []) %}
                <div style="margin-top:6px;">
                    IP {{ c.ip }}: previously <code>{{ c.old_mac }}</code>, now seen as <code>{{ c.new_mac }}</code>
                </div>
                {% endfor %}
            </div>
            {% else %}
            <div class="clean-box">&#10003; No ARP conflicts detected &mdash; no MITM attack observed.</div>
            {% endif %}
            {% if r.data.get("arp_table") %}
            <p class="sub-heading">Learned ARP Table</p>
            <table>
                <thead><tr><th>IP Address</th><th>MAC Address</th></tr></thead>
                <tbody>
                    {% for ip, mac in r.data.arp_table.items() %}
                    <tr><td>{{ ip }}</td><td>{{ mac }}</td></tr>
                    {% endfor %}
                </tbody>
            </table>
            {% endif %}

            {# ----------------------------------------------------------------
               tls_audit — per-host TLS cards with issue severity badges
            ---------------------------------------------------------------- #}
            {% elif r.module == "tls_audit" %}
            <p>Hosts audited: <strong>{{ r.data.get("hosts_audited", 0) }}</strong></p>
            {% if r.data.get("findings") %}
                {% for f in r.data.findings %}
                <div class="tls-card">
                    <div class="tls-card-header">
                        {{ f.ip }}:{{ f.port }}
                        {% if f.subject %}&mdash; {{ f.subject }}{% endif %}
                        &nbsp;&nbsp;
                        <span class="badge badge-{% if f.issues %}high{% else %}success{% endif %}">{{ f.status }}</span>
                    </div>
                    <div class="tls-card-body">
                        <div>Issuer: <strong>{{ f.issuer or "&mdash;" }}</strong></div>
                        <div>
                            Validity: {{ f.valid_from or "&mdash;" }} &rarr; {{ f.valid_until or "&mdash;" }}
                            {% if f.days_remaining is not none %}({{ f.days_remaining }} days remaining){% endif %}
                        </div>
                        <div>TLS version: <strong>{{ f.tls_version }}</strong></div>
                        {% if f.issues %}
                        <div style="margin-top:10px;">
                            {% for issue in f.issues %}
                            <div style="margin: 4px 0;">
                                <span class="badge badge-{{ issue.severity }}">{{ issue.severity }}</span>
                                &nbsp;{{ issue.description }}
                            </div>
                            {% endfor %}
                        </div>
                        {% endif %}
                    </div>
                </div>
                {% endfor %}
            {% else %}
            <div class="clean-box">No HTTPS hosts found in LAN scan results, or no TLS issues detected.</div>
            {% endif %}

            {# ----------------------------------------------------------------
               anomaly_detect — anomaly table or clean baseline confirmation
            ---------------------------------------------------------------- #}
            {% elif r.module == "anomaly_detect" %}
            <p>
                Method: <strong>{{ r.data.get("method", "&mdash;") }}</strong>
                &nbsp;|&nbsp; Samples analysed: <strong>{{ r.data.get("samples_analysed", 0) }}</strong>
                &nbsp;|&nbsp; Baseline: <strong>{{ r.data.get("baseline_status", "&mdash;") }}</strong>
            </p>
            {% if r.data.get("anomalies") %}
            <table>
                <thead>
                    <tr><th>Module</th><th>Metric</th><th>Value</th><th>Baseline Mean</th><th>Severity</th><th>Description</th></tr>
                </thead>
                <tbody>
                    {% for a in r.data.anomalies %}
                    <tr>
                        <td>{{ a.get("module", "&mdash;") }}</td>
                        <td>{{ a.get("metric", "&mdash;") }}</td>
                        <td>{{ a.get("value", "&mdash;") }}</td>
                        <td>{{ a.get("baseline", "&mdash;") }}</td>
                        <td><span class="badge badge-{{ a.get('severity', 'medium') }}">{{ a.get("severity", "&mdash;") }}</span></td>
                        <td>{{ a.get("description", "&mdash;") }}</td>
                    </tr>
                    {% endfor %}
                </tbody>
            </table>
            {% else %}
            <div class="clean-box">&#10003; No anomalies detected &mdash; behaviour is within normal baseline.</div>
            {% endif %}

            {# ----------------------------------------------------------------
               pentest_tools — nmap, nikto, enum4linux findings tables
            ---------------------------------------------------------------- #}
            {% elif r.module == "pentest_tools" %}
            <p>Target: <strong>{{ r.data.get("target", "&mdash;") }}</strong></p>
            {% set nmap_findings = r.data.get("nmap", {}).get("findings", []) %}
            {% set nikto_findings = r.data.get("nikto", {}).get("findings", []) %}
            {% set enum_findings  = r.data.get("enum4linux", {}).get("findings", []) %}
            {% if nmap_findings %}
            <p class="sub-heading">Nmap &mdash; {{ nmap_findings | length }} finding(s)</p>
            <table>
                <thead><tr><th>IP</th><th>Port</th><th>Protocol</th><th>State</th><th>Service</th><th>Version</th></tr></thead>
                <tbody>
                    {% for f in nmap_findings %}
                    <tr>
                        <td>{{ f.ip }}</td><td>{{ f.port }}</td><td>{{ f.protocol }}</td>
                        <td><span class="badge badge-medium">{{ f.state }}</span></td>
                        <td>{{ f.service }}</td><td>{{ f.version or "&mdash;" }}</td>
                    </tr>
                    {% endfor %}
                </tbody>
            </table>
            {% endif %}
            {% if nikto_findings %}
            <p class="sub-heading">Nikto &mdash; {{ nikto_findings | length }} finding(s)</p>
            <table>
                <thead><tr><th>Host</th><th>Finding</th></tr></thead>
                <tbody>{% for f in nikto_findings %}<tr><td>{{ f.host }}</td><td>{{ f.finding }}</td></tr>{% endfor %}</tbody>
            </table>
            {% endif %}
            {% if enum_findings %}
            <p class="sub-heading">Enum4linux &mdash; {{ enum_findings | length }} finding(s)</p>
            <table>
                <thead><tr><th>Host</th><th>Finding</th></tr></thead>
                <tbody>{% for f in enum_findings %}<tr><td>{{ f.host }}</td><td>{{ f.finding }}</td></tr>{% endfor %}</tbody>
            </table>
            {% endif %}
            {% if not nmap_findings and not nikto_findings and not enum_findings %}
            <div class="clean-box">No significant findings from pentest tools.</div>
            {% endif %}

            {# ----------------------------------------------------------------
               wifi_audit — SSID table with colour-coded encryption badges
            ---------------------------------------------------------------- #}
            {% elif r.module == "wifi_audit" %}
            <p>
                Interface: <strong>{{ r.data.get("interface", "&mdash;") }}</strong>
                &nbsp;|&nbsp; Networks found: <strong>{{ r.data.get("networks_found", 0) }}</strong>
            </p>
            {% if r.data.get("networks") %}
            <table>
                <thead><tr><th>SSID</th><th>BSSID</th><th>Channel</th><th>RSSI (dBm)</th><th>Encryption</th></tr></thead>
                <tbody>
                    {% for n in r.data.networks %}
                    <tr>
                        <td>{{ n.ssid or "(hidden)" }}</td>
                        <td>{{ n.bssid }}</td>
                        <td>{{ n.channel }}</td>
                        <td>{{ n.rssi }}</td>
                        <td>
                            <span class="badge badge-{% if n.encryption in ('OPEN', 'WEP') %}high{% else %}success{% endif %}">
                                {{ n.encryption }}
                            </span>
                        </td>
                    </tr>
                    {% endfor %}
                </tbody>
            </table>
            {% else %}
            <div class="clean-box">No wireless networks detected.</div>
            {% endif %}

            {# ----------------------------------------------------------------
               bluetooth_recon — discovered device table
            ---------------------------------------------------------------- #}
            {% elif r.module == "bluetooth_recon" %}
            <p>
                Interface: <strong>{{ r.data.get("interface", "&mdash;") }}</strong>
                &nbsp;|&nbsp; Devices found: <strong>{{ r.data.get("devices_found", 0) }}</strong>
            </p>
            {% if r.data.get("devices") %}
            <table>
                <thead><tr><th>Name</th><th>MAC Address</th><th>Device Class</th></tr></thead>
                <tbody>
                    {% for d in r.data.devices %}
                    <tr>
                        <td>{{ d.name or "Unknown" }}</td>
                        <td>{{ d.mac }}</td>
                        <td>{{ d.device_class }}</td>
                    </tr>
                    {% endfor %}
                </tbody>
            </table>
            {% else %}
            <div class="clean-box">No Bluetooth devices discovered within range.</div>
            {% endif %}

            {# ----------------------------------------------------------------
               Generic fallback — JSON dump for any module without a dedicated block
            ---------------------------------------------------------------- #}
            {% else %}
            <pre>{{ r.data | tojson(indent=2) }}</pre>
            {% endif %}

        </div>{# end section-body #}
    </div>{# end section #}
    {% endfor %}

</div>{# end container #}

<div class="footer">
    CyberDeck v{{ version }} &mdash; MSc Cyber &amp; Data &mdash; ESAIP
    &nbsp;|&nbsp;
    Report generated {{ report_timestamp }}
</div>

</body>
</html>
"""


# ---------------------------------------------------------------------------
# Report filtering
# ---------------------------------------------------------------------------

# Modules that are system/session records, not scan findings.
# Dashboard saves a result every time it stops — that's a session log, not
# an audit finding, so it has no place in the report.
_EXCLUDE_FROM_REPORT = {"dashboard"}


def _filter_for_report(results: list) -> list:
    """
    Prepare results for the HTML report by deduplicating and removing noise.

    Two rules applied in order:
        1. Skip modules in _EXCLUDE_FROM_REPORT (e.g. 'dashboard').
        2. Keep only the MOST RECENT result per module — the report should
           reflect the current state of the network, not every historical run.
           Historical runs are still accessible via the dashboard file list.

    The caller passes results sorted newest-first (as _load_results() does),
    so the first occurrence of each module name is always the latest run.

    Args:
        results: Full list of result dicts, newest-first.

    Returns:
        list: One entry per scan module, most recent run only, no session records.
    """
    seen: set = set()
    filtered: list = []

    for r in results:
        module = r.get("module", "")

        # Skip session-record modules
        if module in _EXCLUDE_FROM_REPORT:
            continue

        # Skip results with completely empty data (incomplete early test runs)
        if not r.get("data"):
            continue

        # First occurrence = most recent (list is newest-first)
        if module not in seen:
            seen.add(module)
            filtered.append(r)

    return filtered


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def generate_report(results: list, config: dict) -> str:
    """
    Render the HTML report template and save it to the results directory.

    Calculates aggregated statistics (total hosts, issues per severity,
    anomalies, ARP conflicts) from the result list, feeds them as Jinja2
    context variables, renders the embedded template, and writes the output
    HTML file to config["output"]["results_dir"].

    Args:
        results: List of module result dicts (standard CyberDeck schema).
        config:  Full config dict from config.json.

    Returns:
        str: Absolute path to the saved HTML report file.
    """

    # ------------------------------------------------------------------
    # Filter: one entry per module, newest only, no session records
    # ------------------------------------------------------------------
    results = _filter_for_report(results)

    # ------------------------------------------------------------------
    # Aggregate statistics — used for the executive summary cards and
    # the risk banner at the top of the report.
    # ------------------------------------------------------------------
    total_hosts = 0       # Sum of hosts_found across lan_scan results
    total_issues = 0      # Grand total: TLS issues + ARP conflicts + anomalies
    total_high = 0        # High-severity count → drives the risk banner colour
    total_medium = 0      # Medium-severity count
    total_anomalies = 0   # Flagged anomalies from anomaly_detect
    total_conflicts = 0   # ARP conflicts from arp_monitor

    for r in results:
        data = r.get("data", {})
        module = r.get("module", "")

        if module == "lan_scan":
            total_hosts += data.get("hosts_found", 0)

        elif module == "arp_monitor":
            # Every ARP conflict is classified as high severity — it indicates
            # an active MITM attack (attacker is poisoning the ARP table).
            conflicts = data.get("conflicts_found", 0)
            total_conflicts += conflicts
            total_high += conflicts
            total_issues += conflicts

        elif module == "anomaly_detect":
            # Anomalies are medium severity by default (they may be false positives
            # on a new baseline). Individual anomaly records carry their own severity.
            anomalies = data.get("anomalies_found", 0)
            total_anomalies += anomalies
            total_medium += anomalies
            total_issues += anomalies

        elif module == "tls_audit":
            for finding in data.get("findings", []):
                for issue in finding.get("issues", []):
                    total_issues += 1
                    severity = issue.get("severity", "medium")
                    if severity == "high":
                        total_high += 1
                    elif severity == "medium":
                        total_medium += 1

    # ------------------------------------------------------------------
    # Render the Jinja2 template
    # ------------------------------------------------------------------
    # We use BaseLoader + from_string() to load our template from a Python
    # string rather than from a file on disk. This keeps report_generator.py
    # fully self-contained — no templates/ directory needed.
    env = Environment(loader=BaseLoader())

    # Register json.dumps as the "tojson" Jinja2 filter so the generic
    # fallback block can pretty-print unknown module data.
    env.filters["tojson"] = lambda val, indent=2: json.dumps(val, indent=indent)

    template = env.from_string(_HTML_TEMPLATE)

    report_timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    version = config.get("project", {}).get("version", "1.0.0")

    html = template.render(
        results=results,
        report_timestamp=report_timestamp,
        total_hosts=total_hosts,
        total_issues=total_issues,
        total_high=total_high,
        total_medium=total_medium,
        total_anomalies=total_anomalies,
        total_conflicts=total_conflicts,
        version=version,
    )

    # ------------------------------------------------------------------
    # Write the HTML file to the results directory
    # ------------------------------------------------------------------
    project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    results_dir = os.path.join(project_root, config["output"]["results_dir"])
    os.makedirs(results_dir, exist_ok=True)

    timestamp_str = datetime.now().strftime("%Y-%m-%dT%H-%M-%S")
    filename = f"report_{timestamp_str}.html"
    report_path = os.path.join(results_dir, filename)

    with open(report_path, "w", encoding="utf-8") as fh:
        fh.write(html)

    logger.info("HTML audit report saved to %s", report_path)
    return report_path
