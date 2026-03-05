"""
CyberDeck Module: dashboard
============================
Flask web dashboard that displays scan results in real time.

How it works:
    This module starts a Flask web server bound to the configured host and port
    (default: 0.0.0.0:5000, meaning every network interface — accessible from
    any device on the same LAN as the CyberDeck).

    On each page load, the dashboard reads the results/ directory fresh from
    disk. This means results update automatically as new scans complete —
    no restart needed. The operator runs a scan from the menu (in another
    terminal or SSH session), and the dashboard page just needs a browser
    refresh to show the new data.

    The "Generate Report" button POSTs to /api/report which calls
    report_generator.generate_report() and returns the path to the HTML file.
    That file can then be downloaded and shared with the client.

    Press Ctrl+C in the terminal to stop the Flask server. The run() function
    catches KeyboardInterrupt and returns a standardized result dict so the
    launcher can continue normally.

Routes:
    GET  /                   Main dashboard — renders all latest results
    GET  /api/results        JSON list of all result files (metadata only)
    GET  /api/result/<file>  JSON body of a single result file
    POST /api/report         Generate HTML report; returns {"path": "..."} JSON
    GET  /reports/<file>     Serve a previously generated HTML report file

Config fields:
    config["dashboard"]["host"]      — Bind address (default 0.0.0.0)
    config["dashboard"]["port"]      — TCP port (default 5000)
    config["output"]["results_dir"]  — Folder to read results from and save reports to

Output format:
    data = {
        "host":        str  — address Flask was bound to
        "port":        int  — port Flask was bound to
        "uptime_seconds": float — how long the server ran before Ctrl+C
    }

Limitations:
    - Single-threaded Flask dev server — fine for audit use, not for production
    - No authentication — only run on trusted LAN segments during an engagement
    - No WebSocket push — the browser must manually refresh to see new results

Dependencies:
    flask >= 3.0.0   (pip install flask)
"""

import json
import logging
import os
import time
from datetime import datetime

from flask import Flask, jsonify, render_template_string, send_from_directory

from utils.report_generator import generate_report

logger = logging.getLogger("cyberdeck")


# ---------------------------------------------------------------------------
# Dashboard HTML template — embedded as a Python string.
# ---------------------------------------------------------------------------
# Using render_template_string() avoids needing a templates/ directory.
# The dashboard uses a 30-second meta-refresh so the operator doesn't have
# to manually reload the page during an active audit session.
# ---------------------------------------------------------------------------

_DASHBOARD_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta http-equiv="refresh" content="30">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>CyberDeck Dashboard</title>
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
            padding: 18px 32px;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        .header h1 { font-size: 22px; color: #00d4ff; letter-spacing: 2px; text-transform: uppercase; }
        .header h1 span { color: #ff6b35; }
        .header-right { text-align: right; color: #7a9ab8; font-size: 12px; }
        .container { padding: 28px 32px; max-width: 1100px; margin: 0 auto; }
        .summary-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(160px, 1fr));
            gap: 14px;
            margin-bottom: 28px;
        }
        .stat-card {
            background: #111827;
            border: 1px solid #1e3a5f;
            border-radius: 6px;
            padding: 16px;
            text-align: center;
        }
        .stat-card.alert   { border-color: #ff4444; background: #1a0a0a; }
        .stat-card.clean   { border-color: #00cc66; background: #001a0d; }
        .stat-number { font-size: 32px; font-weight: bold; color: #00d4ff; }
        .stat-card.alert .stat-number { color: #ff4444; }
        .stat-card.clean .stat-number { color: #00cc66; }
        .stat-label { color: #7a9ab8; font-size: 11px; text-transform: uppercase; margin-top: 4px; }
        .section {
            background: #111827;
            border: 1px solid #1e3a5f;
            border-radius: 6px;
            margin-bottom: 20px;
            overflow: hidden;
        }
        .section-header {
            background: #0d1b2a;
            padding: 12px 18px;
            border-bottom: 1px solid #1e3a5f;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        .section-header h2 { color: #00d4ff; font-size: 15px; letter-spacing: 1px; }
        .section-body { padding: 18px; }
        table { width: 100%; border-collapse: collapse; }
        th {
            background: #0d1b2a;
            color: #00d4ff;
            padding: 7px 12px;
            text-align: left;
            font-size: 11px;
            text-transform: uppercase;
            letter-spacing: 1px;
        }
        td { padding: 7px 12px; border-bottom: 1px solid #1e2d40; }
        tr:last-child td { border-bottom: none; }
        tr:hover td { background: #0d1b2a; }
        .badge {
            display: inline-block;
            padding: 2px 7px;
            border-radius: 3px;
            font-size: 11px;
            font-weight: bold;
            text-transform: uppercase;
        }
        .badge-success { background: #002d16; color: #00cc66; border: 1px solid #00cc66; }
        .badge-error   { background: #3d0000; color: #ff4444; border: 1px solid #ff4444; }
        .badge-partial { background: #2d1a00; color: #ff9900; border: 1px solid #ff9900; }
        .btn {
            display: inline-block;
            padding: 10px 20px;
            border-radius: 4px;
            font-family: 'Courier New', monospace;
            font-size: 13px;
            font-weight: bold;
            cursor: pointer;
            text-transform: uppercase;
            letter-spacing: 1px;
            border: none;
        }
        .btn-primary {
            background: #00d4ff;
            color: #0a0e1a;
        }
        .btn-primary:hover { background: #00aacc; }
        .actions { margin-bottom: 24px; display: flex; gap: 12px; align-items: center; }
        .notice {
            background: #0d1b2a;
            border: 1px solid #1e3a5f;
            border-radius: 4px;
            padding: 10px 14px;
            color: #7a9ab8;
            font-size: 12px;
        }
        #report-msg { color: #00cc66; font-size: 12px; display: none; }
        .footer {
            text-align: center;
            padding: 20px;
            color: #3a5a7a;
            font-size: 11px;
            border-top: 1px solid #1e3a5f;
            margin-top: 20px;
        }
        a { color: #00d4ff; text-decoration: none; }
        a:hover { text-decoration: underline; }
    </style>
</head>
<body>

<div class="header">
    <div>
        <h1>Cyber<span>Deck</span> &mdash; Live Dashboard</h1>
        <div style="color:#7a9ab8; font-size:11px; margin-top:4px;">
            Auto-refreshes every 30 seconds &mdash; {{ now }}
        </div>
    </div>
    <div class="header-right">
        <div><strong>Results loaded:</strong> {{ results|length }}</div>
        <div><strong>Total issues:</strong> {{ total_issues }}</div>
    </div>
</div>

<div class="container">

    {# Summary cards #}
    <div class="summary-grid">
        <div class="stat-card">
            <div class="stat-number">{{ results|length }}</div>
            <div class="stat-label">Result Files</div>
        </div>
        <div class="stat-card">
            <div class="stat-number">{{ total_hosts }}</div>
            <div class="stat-label">Hosts Found</div>
        </div>
        <div class="stat-card {% if total_issues > 0 %}alert{% else %}clean{% endif %}">
            <div class="stat-number">{{ total_issues }}</div>
            <div class="stat-label">Issues</div>
        </div>
        <div class="stat-card {% if total_conflicts > 0 %}alert{% else %}clean{% endif %}">
            <div class="stat-number">{{ total_conflicts }}</div>
            <div class="stat-label">ARP Conflicts</div>
        </div>
        <div class="stat-card {% if total_anomalies > 0 %}alert{% else %}clean{% endif %}">
            <div class="stat-number">{{ total_anomalies }}</div>
            <div class="stat-label">Anomalies</div>
        </div>
    </div>

    {# Action bar #}
    <div class="actions">
        <button class="btn btn-primary" onclick="generateReport()">Generate HTML Report</button>
        <span id="report-msg"></span>
        <span class="notice">&#8635; Page auto-refreshes every 30 s</span>
    </div>

    {# Results table — one row per JSON file #}
    <div class="section">
        <div class="section-header">
            <h2>Scan Results</h2>
            <span style="color:#7a9ab8; font-size:11px;">{{ results|length }} file(s) in results/</span>
        </div>
        <div class="section-body">
        {% if results %}
        <table>
            <thead>
                <tr><th>Module</th><th>Timestamp</th><th>Status</th><th>Summary</th><th>File</th></tr>
            </thead>
            <tbody>
            {% for r in results %}
            <tr>
                <td><strong>{{ r.module | upper | replace("_"," ") }}</strong></td>
                <td>{{ r.timestamp }}</td>
                <td><span class="badge badge-{{ r.status }}">{{ r.status }}</span></td>
                <td>{{ r.summary }}</td>
                <td><a href="/result/{{ r.filename }}" target="_blank">{{ r.filename }}</a></td>
            </tr>
            {% endfor %}
            </tbody>
        </table>
        {% else %}
        <div style="color:#7a9ab8; padding:12px 0;">
            No result files found in results/. Run a scan from the CyberDeck menu first.
        </div>
        {% endif %}
        </div>
    </div>

    {# Reports section — list generated HTML reports #}
    {% if reports %}
    <div class="section">
        <div class="section-header">
            <h2>Generated Reports</h2>
            <span style="color:#7a9ab8; font-size:11px;">{{ reports|length }} report(s)</span>
        </div>
        <div class="section-body">
        <table>
            <thead><tr><th>File</th><th>Link</th></tr></thead>
            <tbody>
            {% for rep in reports %}
            <tr>
                <td>{{ rep }}</td>
                <td><a href="/reports/{{ rep }}" target="_blank">Open report &rarr;</a></td>
            </tr>
            {% endfor %}
            </tbody>
        </table>
        </div>
    </div>
    {% endif %}

</div>

<div class="footer">
    CyberDeck Dashboard &mdash; MSc Cyber &amp; Data &mdash; ESAIP
</div>

<script>
    function generateReport() {
        var msg = document.getElementById("report-msg");
        msg.style.display = "inline";
        msg.style.color = "#00d4ff";
        msg.textContent = "Generating report...";
        var xhr = new XMLHttpRequest();
        xhr.open("POST", "/api/report");
        xhr.setRequestHeader("Content-Type", "application/json");
        xhr.onload = function() {
            if (xhr.status === 200) {
                var data = JSON.parse(xhr.responseText);
                msg.innerHTML =
                    "<span style='color:#00cc66'>Report ready &rarr; </span>" +
                    "<a href='/reports/" + data.filename + "' target='_blank' " +
                    "style='color:#00d4ff; font-weight:bold;'>" +
                    data.filename + "</a>";
            } else {
                msg.style.color = "#ff4444";
                try {
                    var errData = JSON.parse(xhr.responseText);
                    msg.textContent = "Error: " + (errData.error || "Unknown error");
                } catch (e) {
                    msg.textContent = "Error generating report (check terminal for details).";
                }
            }
        };
        xhr.onerror = function() {
            msg.style.color = "#ff4444";
            msg.textContent = "Connection error — is the dashboard still running?";
        };
        xhr.send();
    }
</script>

</body>
</html>
"""


# ---------------------------------------------------------------------------
# Per-result detail page — rendered by GET /result/<filename>
# ---------------------------------------------------------------------------

_DETAIL_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{{ module | upper | replace("_"," ") }} &mdash; CyberDeck</title>
    <style>
        * { box-sizing: border-box; margin: 0; padding: 0; }
        body { font-family: 'Courier New', monospace; background: #0a0e1a; color: #c8d8e8; font-size: 14px; line-height: 1.6; }
        .header { background: linear-gradient(135deg, #0d1b2a, #1a2a4a); border-bottom: 2px solid #00d4ff; padding: 18px 32px; display: flex; justify-content: space-between; align-items: center; }
        .header h1 { font-size: 20px; color: #00d4ff; letter-spacing: 2px; text-transform: uppercase; }
        .header h1 span { color: #ff6b35; }
        .back-link { color: #7a9ab8; font-size: 12px; text-decoration: none; display: block; margin-bottom: 6px; }
        .back-link:hover { color: #00d4ff; }
        .header-right { text-align: right; color: #7a9ab8; font-size: 12px; }
        .container { padding: 28px 32px; max-width: 1100px; margin: 0 auto; }
        .section { background: #111827; border: 1px solid #1e3a5f; border-radius: 6px; margin-bottom: 20px; overflow: hidden; }
        .section-header { background: #0d1b2a; padding: 12px 18px; border-bottom: 1px solid #1e3a5f; display: flex; justify-content: space-between; align-items: center; }
        .section-header h2 { color: #00d4ff; font-size: 15px; letter-spacing: 1px; }
        .section-body { padding: 18px; }
        table { width: 100%; border-collapse: collapse; }
        th { background: #0d1b2a; color: #00d4ff; padding: 7px 12px; text-align: left; font-size: 11px; text-transform: uppercase; letter-spacing: 1px; }
        td { padding: 7px 12px; border-bottom: 1px solid #1e2d40; }
        tr:last-child td { border-bottom: none; }
        tr:hover td { background: #0d1b2a; }
        .badge { display: inline-block; padding: 2px 7px; border-radius: 3px; font-size: 11px; font-weight: bold; text-transform: uppercase; }
        .badge-success { background: #002d16; color: #00cc66; border: 1px solid #00cc66; }
        .badge-error   { background: #3d0000; color: #ff4444; border: 1px solid #ff4444; }
        .badge-partial { background: #2d1a00; color: #ff9900; border: 1px solid #ff9900; }
        .stat { padding: 6px 0; color: #c8d8e8; }
        .stat strong { color: #00d4ff; }
        .clean { color: #00cc66; }
        .alert { color: #ff4444; }
        .warn  { color: #ff9900; }
        pre { background: #0a0e1a; border: 1px solid #1e3a5f; border-radius: 4px; padding: 12px; overflow-x: auto; font-size: 12px; white-space: pre-wrap; }
        .footer { text-align: center; padding: 20px; color: #3a5a7a; font-size: 11px; border-top: 1px solid #1e3a5f; margin-top: 20px; }
        a { color: #00d4ff; text-decoration: none; }
        a:hover { text-decoration: underline; }
    </style>
</head>
<body>

<div class="header">
    <div>
        <a class="back-link" href="/">&#8592; Back to Dashboard</a>
        <h1>Cyber<span>Deck</span> &mdash; {{ module | upper | replace("_"," ") }}</h1>
    </div>
    <div class="header-right">
        <div><span class="badge badge-{{ status }}">{{ status }}</span></div>
        <div style="margin-top:6px;">{{ timestamp }}</div>
        <div style="margin-top:4px; font-size:11px;">{{ filename }}</div>
    </div>
</div>

<div class="container">

{% if errors %}
<div class="section" style="border-color:#ff4444;">
    <div class="section-header"><h2 style="color:#ff4444;">Errors</h2></div>
    <div class="section-body">
    {% for e in errors %}
    <div class="alert" style="padding:4px 0;">&#9888; {{ e }}</div>
    {% endfor %}
    </div>
</div>
{% endif %}

{# ─── LAN SCAN ─────────────────────────────────────────────────────── #}
{% if module == "lan_scan" %}
<div class="section">
    <div class="section-header">
        <h2>Hosts Discovered</h2>
        <span style="color:#7a9ab8; font-size:11px;">{{ data.hosts_found or 0 }} host(s)</span>
    </div>
    <div class="section-body">
    {% if data.hosts %}
    <table>
        <thead><tr><th>IP Address</th><th>MAC Address</th><th>Vendor</th><th>Hostname</th></tr></thead>
        <tbody>
        {% for host in data.hosts %}
        <tr>
            <td>{{ host.ip or "—" }}</td>
            <td>{{ host.mac or "—" }}</td>
            <td>{{ host.vendor or "—" }}</td>
            <td>{{ host.hostname or "—" }}</td>
        </tr>
        {% endfor %}
        </tbody>
    </table>
    {% else %}
    <div style="color:#7a9ab8;">No hosts recorded.</div>
    {% endif %}
    </div>
</div>

{# ─── PASSIVE MONITOR ──────────────────────────────────────────────── #}
{% elif module == "passive_monitor" %}
<div class="section">
    <div class="section-header"><h2>Capture Summary</h2></div>
    <div class="section-body">
        <div class="stat">Total packets captured: <strong>{{ data.total_packets or 0 }}</strong></div>
        <div class="stat">Unique IPs seen: <strong>{{ data.unique_ips | length if data.unique_ips else 0 }}</strong></div>
    </div>
</div>
{% if data.unique_ips %}
<div class="section">
    <div class="section-header"><h2>Unique IP Addresses</h2></div>
    <div class="section-body">
    <table>
        <thead><tr><th>IP Address</th></tr></thead>
        <tbody>{% for ip in data.unique_ips %}<tr><td>{{ ip }}</td></tr>{% endfor %}</tbody>
    </table>
    </div>
</div>
{% endif %}
{% if data.protocols %}
<div class="section">
    <div class="section-header"><h2>Protocols Seen</h2></div>
    <div class="section-body">
    <table>
        <thead><tr><th>Protocol</th><th>Packet Count</th></tr></thead>
        <tbody>{% for proto, count in data.protocols.items() %}<tr><td>{{ proto }}</td><td>{{ count }}</td></tr>{% endfor %}</tbody>
    </table>
    </div>
</div>
{% endif %}

{# ─── ARP MONITOR ──────────────────────────────────────────────────── #}
{% elif module == "arp_monitor" %}
<div class="section">
    <div class="section-header"><h2>ARP Summary</h2></div>
    <div class="section-body">
        <div class="stat">Packets analysed: <strong>{{ data.packets_analysed or 0 }}</strong></div>
        <div class="stat">Conflicts found:
            <strong class="{{ 'alert' if data.conflicts_found else 'clean' }}">{{ data.conflicts_found or 0 }}</strong>
        </div>
    </div>
</div>
{% if data.conflicts %}
<div class="section" style="border-color:#ff4444;">
    <div class="section-header"><h2 style="color:#ff4444;">ARP Conflicts</h2></div>
    <div class="section-body">
    <table>
        <thead><tr><th>IP</th><th>MAC 1</th><th>MAC 2</th><th>Time</th></tr></thead>
        <tbody>
        {% for c in data.conflicts %}
        <tr>
            <td>{{ c.ip or "—" }}</td>
            <td>{{ c.mac1 or "—" }}</td>
            <td>{{ c.mac2 or "—" }}</td>
            <td>{{ c.time or "—" }}</td>
        </tr>
        {% endfor %}
        </tbody>
    </table>
    </div>
</div>
{% endif %}

{# ─── TLS AUDIT ────────────────────────────────────────────────────── #}
{% elif module == "tls_audit" %}
<div class="section">
    <div class="section-header">
        <h2>TLS Audit Results</h2>
        <span style="color:#7a9ab8; font-size:11px;">{{ data.hosts_audited or 0 }} host(s)</span>
    </div>
    <div class="section-body">
    {% if data.findings %}
    {% for finding in data.findings %}
    <div style="margin-bottom:18px;">
        <div style="color:#00d4ff; font-weight:bold; margin-bottom:8px;">{{ finding.host or "Unknown host" }}</div>
        {% if finding.issues %}
        <table>
            <thead><tr><th>Issue</th><th>Severity</th></tr></thead>
            <tbody>
            {% for issue in finding.issues %}
            <tr>
                <td>{{ issue.description if issue.description is defined else issue }}</td>
                <td><span class="badge badge-{{ 'error' if issue.severity == 'HIGH' else 'partial' }}">{{ issue.severity or "INFO" }}</span></td>
            </tr>
            {% endfor %}
            </tbody>
        </table>
        {% else %}
        <div class="clean">&#10003; No issues found.</div>
        {% endif %}
    </div>
    {% endfor %}
    {% else %}
    <div style="color:#7a9ab8;">No hosts audited.</div>
    {% endif %}
    </div>
</div>

{# ─── ANOMALY DETECT ───────────────────────────────────────────────── #}
{% elif module == "anomaly_detect" %}
<div class="section">
    <div class="section-header"><h2>Anomaly Detection</h2></div>
    <div class="section-body">
        <div class="stat">Samples analysed: <strong>{{ data.samples_analysed or 0 }}</strong></div>
        <div class="stat">Anomalies found:
            <strong class="{{ 'warn' if data.anomalies_found else 'clean' }}">{{ data.anomalies_found or 0 }}</strong>
        </div>
    </div>
</div>
{% if data.anomalies %}
<div class="section" style="border-color:#ff9900;">
    <div class="section-header"><h2 style="color:#ff9900;">Anomalies Detected</h2></div>
    <div class="section-body">
    <table>
        <thead><tr><th>Source</th><th>Metric</th><th>Value</th><th>Threshold</th></tr></thead>
        <tbody>
        {% for a in data.anomalies %}
        <tr>
            <td>{{ a.ip or a.source or "—" }}</td>
            <td>{{ a.metric or "—" }}</td>
            <td>{{ a.value or "—" }}</td>
            <td>{{ a.threshold or "—" }}</td>
        </tr>
        {% endfor %}
        </tbody>
    </table>
    </div>
</div>
{% endif %}

{# ─── PENTEST TOOLS ────────────────────────────────────────────────── #}
{% elif module == "pentest_tools" %}
<div class="section">
    <div class="section-header">
        <h2>Nmap Findings</h2>
        <span style="color:#7a9ab8; font-size:11px;">{{ (data.nmap or {}).targets_scanned or 0 }} target(s) scanned</span>
    </div>
    <div class="section-body">
    {% if data.nmap and data.nmap.findings %}
    <table>
        <thead><tr><th>IP</th><th>Port</th><th>Protocol</th><th>Service</th><th>State</th><th>Version</th></tr></thead>
        <tbody>
        {% for f in data.nmap.findings %}
        <tr>
            <td>{{ f.ip or "—" }}</td>
            <td>{{ f.port or "—" }}</td>
            <td>{{ f.protocol or "—" }}</td>
            <td>{{ f.service or "—" }}</td>
            <td><span class="badge badge-{{ 'success' if f.state == 'open' else 'partial' }}">{{ f.state or "—" }}</span></td>
            <td>{{ f.version or "—" }}</td>
        </tr>
        {% endfor %}
        </tbody>
    </table>
    {% else %}
    <div style="color:#7a9ab8;">No open ports found.</div>
    {% endif %}
    </div>
</div>
{% if data.nikto and data.nikto.findings %}
<div class="section">
    <div class="section-header"><h2>Nikto Findings</h2></div>
    <div class="section-body">
    <table>
        <thead><tr><th>Host</th><th>Finding</th></tr></thead>
        <tbody>
        {% for f in data.nikto.findings %}
        <tr><td>{{ f.host or "—" }}</td><td>{{ f.description if f.description is defined else f }}</td></tr>
        {% endfor %}
        </tbody>
    </table>
    </div>
</div>
{% endif %}
{% if data.enum4linux and data.enum4linux.findings %}
<div class="section">
    <div class="section-header"><h2>Enum4Linux Findings</h2></div>
    <div class="section-body">
    <table>
        <thead><tr><th>Finding</th></tr></thead>
        <tbody>
        {% for f in data.enum4linux.findings %}<tr><td>{{ f }}</td></tr>{% endfor %}
        </tbody>
    </table>
    </div>
</div>
{% endif %}

{# ─── WIFI AUDIT ───────────────────────────────────────────────────── #}
{% elif module == "wifi_audit" %}
<div class="section">
    <div class="section-header">
        <h2>Wireless Networks</h2>
        <span style="color:#7a9ab8; font-size:11px;">{{ data.networks_found or 0 }} network(s)</span>
    </div>
    <div class="section-body">
    {% if data.networks %}
    <table>
        <thead><tr><th>SSID</th><th>BSSID</th><th>Channel</th><th>Signal</th><th>Encryption</th></tr></thead>
        <tbody>
        {% for n in data.networks %}
        <tr>
            <td>{{ n.ssid or "Hidden" }}</td>
            <td>{{ n.bssid or "—" }}</td>
            <td>{{ n.channel or "—" }}</td>
            <td>{{ n.signal or "—" }}</td>
            <td>{{ n.encryption or "—" }}</td>
        </tr>
        {% endfor %}
        </tbody>
    </table>
    {% else %}
    <div style="color:#7a9ab8;">No networks captured.</div>
    {% endif %}
    </div>
</div>

{# ─── BLUETOOTH RECON ──────────────────────────────────────────────── #}
{% elif module == "bluetooth_recon" %}
<div class="section">
    <div class="section-header">
        <h2>Bluetooth Devices</h2>
        <span style="color:#7a9ab8; font-size:11px;">{{ data.devices_found or 0 }} device(s)</span>
    </div>
    <div class="section-body">
    {% if data.devices %}
    <table>
        <thead><tr><th>Name</th><th>Address</th><th>Class</th><th>Services</th></tr></thead>
        <tbody>
        {% for d in data.devices %}
        <tr>
            <td>{{ d.name or "Unknown" }}</td>
            <td>{{ d.address or "—" }}</td>
            <td>{{ d.device_class or "—" }}</td>
            <td>{{ d.services | join(", ") if d.services else "—" }}</td>
        </tr>
        {% endfor %}
        </tbody>
    </table>
    {% else %}
    <div style="color:#7a9ab8;">No devices found.</div>
    {% endif %}
    </div>
</div>

{# ─── FALLBACK ─────────────────────────────────────────────────────── #}
{% else %}
<div class="section">
    <div class="section-header"><h2>Raw Data</h2></div>
    <div class="section-body"><pre>{{ data | tojson(indent=2) }}</pre></div>
</div>
{% endif %}

</div>

<div class="footer">
    CyberDeck &mdash; Scan Detail &mdash; {{ filename }}
</div>

</body>
</html>
"""


# ---------------------------------------------------------------------------
# Helper functions
# ---------------------------------------------------------------------------

def _get_results_dir(config: dict) -> str:
    """
    Resolve the absolute path to the results directory.

    We store results_dir as a relative path in config.json (e.g. "results/")
    so the project can be cloned anywhere. Here we join it with the project
    root (two levels up from this file: modules/ → project root).

    Args:
        config: Full config dict from config.json.

    Returns:
        str: Absolute path to results directory.
    """
    project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    return os.path.join(project_root, config["output"]["results_dir"])


def _summarise_result(data: dict, module: str) -> str:
    """
    Build a short one-line summary string for a result, shown in the dashboard table.

    Each module exposes different data fields, so we extract the most
    relevant metric per module type.

    Args:
        data:   The "data" field from a module result dict.
        module: The module name string (e.g. "lan_scan").

    Returns:
        str: Human-readable summary (e.g. "4 hosts found").
    """
    if module == "lan_scan":
        return f"{data.get('hosts_found', 0)} host(s) found"
    if module == "passive_monitor":
        return (
            f"{data.get('total_packets', 0)} packets captured, "
            f"{len(data.get('unique_ips', []))} unique IP(s)"
        )
    if module == "arp_monitor":
        conflicts = data.get("conflicts_found", 0)
        packets = data.get("packets_analysed", 0)
        return f"{packets} ARP packet(s), {conflicts} conflict(s)"
    if module == "tls_audit":
        hosts = data.get("hosts_audited", 0)
        issues = sum(len(f.get("issues", [])) for f in data.get("findings", []))
        return f"{hosts} HTTPS host(s) audited, {issues} issue(s)"
    if module == "anomaly_detect":
        return (
            f"{data.get('anomalies_found', 0)} anomaly(ies), "
            f"{data.get('samples_analysed', 0)} sample(s)"
        )
    if module == "pentest_tools":
        nmap = len(data.get("nmap", {}).get("findings", []))
        return f"{nmap} nmap finding(s)"
    if module == "wifi_audit":
        return f"{data.get('networks_found', 0)} wireless network(s)"
    if module == "bluetooth_recon":
        return f"{data.get('devices_found', 0)} Bluetooth device(s)"
    return ""


def _load_results(results_dir: str) -> list:
    """
    Read all JSON result files from the results directory.

    Files are sorted newest-first (by filename, which contains the ISO
    timestamp). We add a "filename" key and a "summary" one-liner so the
    dashboard template doesn't need to call Python functions directly.

    Args:
        results_dir: Absolute path to the results/ directory.

    Returns:
        list: List of enriched result dicts, newest first.
              Each dict has the standard keys plus "filename" and "summary".
    """
    if not os.path.isdir(results_dir):
        return []

    loaded = []
    json_files = sorted(
        [f for f in os.listdir(results_dir) if f.endswith(".json")],
        key=lambda f: os.path.getmtime(os.path.join(results_dir, f)),
        reverse=True,   # newest first (by actual file modification time)
    )

    for filename in json_files:
        filepath = os.path.join(results_dir, filename)
        try:
            with open(filepath, "r", encoding="utf-8") as fh:
                result = json.load(fh)
            # Skip files that don't follow the standard module result schema
            # (e.g. baseline.json saved by anomaly_detect has no "module" key).
            if "module" not in result:
                continue
            result["filename"] = filename
            result["summary"] = _summarise_result(
                result.get("data", {}),
                result.get("module", ""),
            )
            loaded.append(result)
        except (json.JSONDecodeError, OSError) as exc:
            logger.warning("Could not load result file %s: %s", filename, exc)

    return loaded


def _aggregate_stats(results: list) -> dict:
    """
    Walk all loaded results and compute the summary card numbers.

    The same logic as in report_generator.generate_report() — kept in sync
    manually. If you add a new severity source, update both places.

    Args:
        results: List of enriched result dicts from _load_results().

    Returns:
        dict: Keys: total_hosts, total_issues, total_conflicts, total_anomalies.
    """
    total_hosts = 0
    total_issues = 0
    total_conflicts = 0
    total_anomalies = 0

    for r in results:
        data = r.get("data", {})
        module = r.get("module", "")

        if module == "lan_scan":
            total_hosts += data.get("hosts_found", 0)
        elif module == "arp_monitor":
            c = data.get("conflicts_found", 0)
            total_conflicts += c
            total_issues += c
        elif module == "anomaly_detect":
            a = data.get("anomalies_found", 0)
            total_anomalies += a
            total_issues += a
        elif module == "tls_audit":
            for f in data.get("findings", []):
                total_issues += len(f.get("issues", []))

    return {
        "total_hosts": total_hosts,
        "total_issues": total_issues,
        "total_conflicts": total_conflicts,
        "total_anomalies": total_anomalies,
    }


# ---------------------------------------------------------------------------
# Flask application factory
# ---------------------------------------------------------------------------

def _create_app(config: dict) -> Flask:
    """
    Build and configure the Flask application.

    We use an application factory pattern rather than a module-level app
    object so the config dict (read at run-time from config.json) is
    accessible to all route handlers via closure.

    Args:
        config: Full config dict from config.json.

    Returns:
        Flask: Configured Flask application instance.
    """
    app = Flask(__name__)

    # Suppress Flask's default banner and access logs so they don't
    # clutter the CyberDeck console output.
    log = logging.getLogger("werkzeug")
    log.setLevel(logging.WARNING)

    results_dir = _get_results_dir(config)

    # ------------------------------------------------------------------
    # Route: GET / — main dashboard page
    # ------------------------------------------------------------------
    @app.route("/")
    def index():
        """
        Render the main dashboard.

        Loads all result files fresh on each request so the page always
        shows the latest scan data without needing a server restart.
        """
        results = _load_results(results_dir)
        stats = _aggregate_stats(results)

        # List generated HTML reports for the "Generated Reports" section
        reports = sorted(
            [f for f in os.listdir(results_dir) if f.startswith("report_") and f.endswith(".html")],
            reverse=True,
        ) if os.path.isdir(results_dir) else []

        return render_template_string(
            _DASHBOARD_TEMPLATE,
            results=results,
            reports=reports,
            now=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            **stats,
        )

    # ------------------------------------------------------------------
    # Route: GET /api/results — JSON list of all result metadata
    # ------------------------------------------------------------------
    @app.route("/api/results")
    def api_results():
        """
        Return a JSON array of all result file metadata (module, timestamp,
        status, summary, filename). Clients can poll this endpoint to build
        their own dashboards or integrations.
        """
        results = _load_results(results_dir)
        # Strip the full data dict — metadata only to keep the response small
        metadata = [
            {
                "filename": r["filename"],
                "module": r.get("module", ""),
                "timestamp": r.get("timestamp", ""),
                "status": r.get("status", ""),
                "summary": r.get("summary", ""),
            }
            for r in results
        ]
        return jsonify(metadata)

    # ------------------------------------------------------------------
    # Route: GET /api/result/<filename> — single result file body
    # ------------------------------------------------------------------
    @app.route("/api/result/<filename>")
    def api_result(filename: str):
        """
        Return the full JSON body of a single result file.

        Args:
            filename: The bare filename (e.g. lan_scan_2026-02-23T07-10-36.json).
                      Path traversal characters are rejected by Flask automatically.
        """
        filepath = os.path.join(results_dir, filename)
        if not os.path.isfile(filepath) or not filename.endswith(".json"):
            return jsonify({"error": "File not found"}), 404
        try:
            with open(filepath, "r", encoding="utf-8") as fh:
                data = json.load(fh)
            return jsonify(data)
        except (json.JSONDecodeError, OSError) as exc:
            return jsonify({"error": str(exc)}), 500

    # ------------------------------------------------------------------
    # Route: GET /result/<filename> — formatted detail page for one scan
    # ------------------------------------------------------------------
    @app.route("/result/<filename>")
    def result_detail(filename: str):
        """
        Render a human-readable detail page for a single scan result file.

        Shows module-specific tables (hosts, ports, anomalies, etc.) rather
        than raw JSON. Each module type has a dedicated rendering block in
        _DETAIL_TEMPLATE.
        """
        filepath = os.path.join(results_dir, filename)
        if not os.path.isfile(filepath) or not filename.endswith(".json"):
            return "<h1 style='color:#ff4444;font-family:monospace;padding:40px'>Result not found.</h1>", 404
        try:
            with open(filepath, "r", encoding="utf-8") as fh:
                result = json.load(fh)
            if "module" not in result:
                return "<h1 style='color:#ff4444;font-family:monospace;padding:40px'>Invalid result file.</h1>", 400
            return render_template_string(
                _DETAIL_TEMPLATE,
                module=result.get("module", ""),
                timestamp=result.get("timestamp", ""),
                status=result.get("status", "unknown"),
                errors=result.get("errors", []),
                data=result.get("data", {}),
                filename=filename,
            )
        except (json.JSONDecodeError, OSError) as exc:
            return f"<pre style='color:#ff4444;padding:40px'>Error: {exc}</pre>", 500

    # ------------------------------------------------------------------
    # Route: POST /api/report — generate HTML report from all results
    # ------------------------------------------------------------------
    @app.route("/api/report", methods=["POST"])
    def api_generate_report():
        """
        Load all current result files and generate an HTML audit report.

        Calls report_generator.generate_report() with the full list of
        result dicts and the config dict. Returns the report filename so
        the browser can redirect or open it.
        """
        results = _load_results(results_dir)
        if not results:
            return jsonify({"error": "No result files found — run scans first"}), 400

        try:
            report_path = generate_report(results, config)
            filename = os.path.basename(report_path)
            logger.info("Report generated via dashboard: %s", filename)
            return jsonify({"path": report_path, "filename": filename})
        except Exception as exc:
            logger.error("Report generation failed: %s", exc)
            return jsonify({"error": str(exc)}), 500

    # ------------------------------------------------------------------
    # Route: GET /reports/<filename> — serve a generated HTML report
    # ------------------------------------------------------------------
    @app.route("/reports/<filename>")
    def serve_report(filename: str):
        """
        Serve a previously generated HTML report file for download/viewing.

        Flask's send_from_directory() restricts the path to results_dir,
        preventing directory traversal attacks.

        Args:
            filename: The report filename (e.g. report_2026-03-01T12-00-00.html).
        """
        return send_from_directory(results_dir, filename)

    return app


# ---------------------------------------------------------------------------
# Module entry point
# ---------------------------------------------------------------------------

def run(config: dict) -> dict:
    """
    Start the Flask dashboard server and block until the user presses Ctrl+C.

    The Flask development server runs in a single thread. This is intentional:
    during an audit the server handles one or two concurrent connections at
    most (the auditor and maybe a colleague). Multi-threading adds complexity
    for no practical gain in this use case.

    Args:
        config: Full config dict from config.json.

    Returns:
        dict: Standard CyberDeck result dict. Status is "success" if the
              server started and stopped cleanly (Ctrl+C), "error" otherwise.
    """
    host = config["dashboard"]["host"]
    port = config["dashboard"]["port"]

    logger.info("Starting dashboard on http://%s:%d", host, port)
    logger.info(
        "Open a browser on any device connected to this network and go to "
        "http://<this-machine-IP>:%d — press Ctrl+C here to stop.",
        port,
    )

    app = _create_app(config)
    start_time = time.time()
    errors = []

    try:
        # use_reloader=False — the reloader forks the process which breaks
        # the logger hierarchy we set up in launcher.py.
        # debug=False       — we don't want Flask's interactive debugger
        #                     running on a device accessible to the whole LAN.
        app.run(host=host, port=port, debug=False, use_reloader=False)

    except KeyboardInterrupt:
        # Normal exit — user pressed Ctrl+C to stop the dashboard
        logger.info("Dashboard stopped by user (Ctrl+C)")

    except OSError as exc:
        # Most likely the port is already in use
        msg = f"Could not start dashboard on port {port}: {exc}"
        logger.error(msg)
        errors.append(msg)

    uptime = round(time.time() - start_time, 1)

    return {
        "module": "dashboard",
        "timestamp": datetime.now().isoformat(),
        "status": "success" if not errors else "error",
        "data": {
            "host": host,
            "port": port,
            "uptime_seconds": uptime,
        },
        "errors": errors,
    }
