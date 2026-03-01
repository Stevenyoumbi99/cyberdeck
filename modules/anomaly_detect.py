"""
CyberDeck Module: anomaly_detect
==================================
Analyses saved scan results to detect unusual or suspicious network behaviour.

This module performs NO network activity — it reads JSON files from results/
and applies two independent detection layers:

Layer 1 — Static Rules (always-on, baseline-independent):
    Checks every scan result for hardcoded indicators of compromise regardless
    of what the baseline says. This handles the "cold start" problem where the
    network is already compromised when the CyberDeck is first connected.

    Rules checked:
      - Known dangerous ports open (e.g. 4444 Metasploit, 1337, 31337)
      - Host has an unusually high number of open ports (>20)
      - New host seen that was never in the baseline

Layer 2 — Z-score / Isolation Forest (baseline comparison):
    Builds or loads a statistical baseline of normal behaviour, then compares
    the most recent scan data against it to flag statistical outliers.

    Z-score: measures how many standard deviations a value is from the mean.
             A Z-score > threshold (e.g. 2.5) means the value is unusually high.

    Isolation Forest: ML algorithm that isolates anomalies by random partitioning.
                      Points that are easy to isolate (few splits needed) are
                      flagged as anomalies. Works without labelled training data.

Cold start problem:
    If the CyberDeck is plugged into an already-compromised network, the baseline
    will learn the compromised state as "normal". Layer 1 (static rules) mitigates
    this by flagging known-bad indicators on every run, independent of history.

Dependencies:
    numpy>=1.24.0        (pip install numpy — or: sudo apt install python3-numpy)
    scikit-learn>=1.3.0  (pip install scikit-learn — or: sudo apt install python3-sklearn)

Config fields:
    config["anomaly"]["method"]         — "zscore" or "isolation_forest"
    config["anomaly"]["threshold"]      — Z-score cutoff, e.g. 2.5
    config["anomaly"]["baseline_file"]  — path to save/load baseline JSON
    config["anomaly"]["min_samples"]    — minimum samples for reliable statistics
    config["output"]["results_dir"]     — where to find scan result files

Output format:
    data = {
        "method":           str   — detection method used
        "samples_analysed": int   — number of result files read
        "baseline_status":  str   — "new" / "updated" / "loaded"
        "anomalies_found":  int   — total anomalies across both layers
        "anomalies": [
            {
                "layer":       str  — "static_rules" or "statistical"
                "source":      str  — which module produced the data, e.g. "lan_scan"
                "ip":          str  — affected IP address
                "metric":      str  — what was measured, e.g. "open_ports"
                "value":       any  — the actual observed value
                "score":       float — Z-score or isolation score (None for static rules)
                "reason":      str  — human-readable explanation
                "severity":    str  — "high" / "medium" / "low"
            }
        ]
    }
"""

import json
import logging
import os
from datetime import datetime

import numpy as np
from sklearn.ensemble import IsolationForest

logger = logging.getLogger("cyberdeck")

# --- Static rule definitions ---

# Ports associated with common malware, RATs, and pentest frameworks.
# These are flagged regardless of baseline — a host should never have these open.
_DANGEROUS_PORTS = {
    4444:  "Metasploit default handler",
    1337:  "Common backdoor / leet port",
    31337: "Back Orifice RAT",
    8080:  "Common proxy / C2 port (review if unexpected)",
    8888:  "Common reverse shell port",
    6667:  "IRC — often used by botnets for C2",
    9001:  "Tor relay / common RAT port",
    3389:  "RDP — flag if unexpected on a Linux host",
    5900:  "VNC — remote access, flag if unintended",
    23:    "Telnet — unencrypted, should never be open",
}

# A host with more than this many open ports is suspicious
_MAX_NORMAL_PORTS = 20


def run(config: dict) -> dict:
    """
    Run both detection layers against saved scan results.

    Args:
        config: Full config dictionary from config.json

    Returns:
        dict: Standardized result with keys:
              module, timestamp, status, data, errors
    """
    logger.info("Starting anomaly_detect...")

    method = config["anomaly"]["method"]
    threshold = config["anomaly"]["threshold"]
    baseline_path = config["anomaly"]["baseline_file"]
    min_samples = config["anomaly"]["min_samples"]
    results_dir = config["output"]["results_dir"]

    # Resolve paths relative to the project root
    project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    results_dir = os.path.join(project_root, results_dir)
    baseline_path = os.path.join(project_root, baseline_path)

    errors = []
    all_anomalies = []

    try:
        # --- Load all saved scan results ---
        scan_results = _load_scan_results(results_dir)
        logger.info("Loaded %d scan result file(s) from %s", len(scan_results), results_dir)

        if not scan_results:
            return _make_result("success", {
                "method": method,
                "samples_analysed": 0,
                "baseline_status": "no_data",
                "anomalies_found": 0,
                "anomalies": [],
            }, [], "No scan results found — run scanning modules first")

        # --- Extract metrics from all results ---
        # metrics is a list of dicts, one per result file, with numeric features
        metrics = _extract_metrics(scan_results)
        logger.info("Extracted metrics from %d result(s)", len(metrics))

        # --- Layer 1: Static rules ---
        # Run against every scan result, independent of baseline
        logger.info("Running Layer 1: static rule checks...")
        static_anomalies = _check_static_rules(scan_results)
        all_anomalies.extend(static_anomalies)
        logger.info("Static rules: %d anomaly/anomalies found", len(static_anomalies))

        # --- Layer 2: Statistical detection ---
        # Needs at least a few samples to be meaningful
        logger.info("Running Layer 2: %s statistical detection...", method)
        baseline, baseline_status = _load_or_build_baseline(baseline_path, metrics)

        if len(metrics) < 2:
            logger.warning(
                "Only %d sample(s) available — statistical detection needs at least 2. "
                "Run more scans to improve accuracy (min_samples target: %d)",
                len(metrics), min_samples
            )
            stat_anomalies = []
        else:
            if method == "zscore":
                stat_anomalies = _detect_zscore(metrics, baseline, threshold)
            else:
                stat_anomalies = _detect_isolation_forest(metrics, baseline)

        if len(metrics) < min_samples:
            logger.warning(
                "Sample count %d below min_samples=%d — results are indicative only",
                len(metrics), min_samples
            )

        all_anomalies.extend(stat_anomalies)
        logger.info("Statistical detection: %d anomaly/anomalies found", len(stat_anomalies))

        # --- Update baseline with latest data ---
        _save_baseline(baseline_path, metrics, baseline_status)

        result_data = {
            "method": method,
            "samples_analysed": len(scan_results),
            "baseline_status": baseline_status,
            "anomalies_found": len(all_anomalies),
            "anomalies": all_anomalies,
        }

        logger.info(
            "anomaly_detect completed — %d sample(s), %d anomaly/anomalies found",
            len(scan_results), len(all_anomalies)
        )

        return _make_result("success", result_data, errors)

    except Exception as e:
        logger.error("anomaly_detect failed: %s", e)
        return _make_result("error", {}, [str(e)])


# ---------------------------------------------------------------------------
# Data loading
# ---------------------------------------------------------------------------

def _load_scan_results(results_dir: str) -> list:
    """
    Read all JSON files from results/ excluding baseline.json and anomaly results.

    Args:
        results_dir: Absolute path to the results directory

    Returns:
        list: Parsed JSON dicts from each scan result file
    """
    results = []

    if not os.path.isdir(results_dir):
        return results

    for filename in sorted(os.listdir(results_dir)):
        # Skip non-JSON, baseline file, and anomaly_detect's own past results
        if not filename.endswith(".json"):
            continue
        if filename == "baseline.json":
            continue
        if filename.startswith("anomaly_detect"):
            continue

        filepath = os.path.join(results_dir, filename)
        try:
            with open(filepath, "r", encoding="utf-8") as f:
                data = json.load(f)
                results.append(data)
        except (json.JSONDecodeError, OSError) as e:
            logger.warning("Could not read result file %s: %s", filename, e)

    return results


def _extract_metrics(scan_results: list) -> list:
    """
    Convert raw scan results into numeric feature vectors for statistical analysis.

    We extract these features from each result:
      - lan_scan:        number of open ports per host (one entry per host)
      - passive_monitor: total packets, unique IP count, TCP ratio

    Args:
        scan_results: List of parsed scan result dicts

    Returns:
        list: List of metric dicts, each with "source", "ip", and numeric fields
    """
    metrics = []

    for result in scan_results:
        module = result.get("module", "")
        data = result.get("data", {})

        if module == "lan_scan":
            for host in data.get("hosts", []):
                metrics.append({
                    "source": "lan_scan",
                    "ip": host["ip"],
                    "open_ports": len(host.get("open_ports", [])),
                })

        elif module == "passive_monitor":
            total = data.get("total_packets", 0)
            protocols = data.get("protocols", {})
            tcp_count = protocols.get("TCP", 0)
            unique_ips = len(data.get("unique_ips", []))

            # TCP ratio: what fraction of traffic is TCP (0.0 to 1.0)
            tcp_ratio = (tcp_count / total) if total > 0 else 0.0

            metrics.append({
                "source": "passive_monitor",
                "ip": "network",   # passive monitor is network-wide, not per-host
                "total_packets": total,
                "unique_ips": unique_ips,
                "tcp_ratio": tcp_ratio,
            })

    return metrics


# ---------------------------------------------------------------------------
# Layer 1: Static rules
# ---------------------------------------------------------------------------

def _check_static_rules(scan_results: list) -> list:
    """
    Check all scan results against hardcoded rules for known-bad indicators.

    These rules fire regardless of what the baseline says — they catch threats
    that were present from day one (the cold start problem).

    Args:
        scan_results: List of parsed scan result dicts

    Returns:
        list: Anomaly dicts for each rule violation found
    """
    anomalies = []

    for result in scan_results:
        module = result.get("module", "")
        data = result.get("data", {})

        if module == "lan_scan":
            for host in data.get("hosts", []):
                ip = host["ip"]
                open_ports = host.get("open_ports", [])
                port_numbers = {p["port"] for p in open_ports}

                # Rule 1: Check for known dangerous ports
                for port in port_numbers:
                    if port in _DANGEROUS_PORTS:
                        anomalies.append({
                            "layer": "static_rules",
                            "source": "lan_scan",
                            "ip": ip,
                            "metric": "dangerous_port",
                            "value": port,
                            "score": None,
                            "reason": f"Port {port} open — {_DANGEROUS_PORTS[port]}",
                            "severity": "high",
                        })

                # Rule 2: Unusually high port count
                if len(port_numbers) > _MAX_NORMAL_PORTS:
                    anomalies.append({
                        "layer": "static_rules",
                        "source": "lan_scan",
                        "ip": ip,
                        "metric": "open_ports",
                        "value": len(port_numbers),
                        "score": None,
                        "reason": (
                            f"{len(port_numbers)} open ports exceeds threshold "
                            f"of {_MAX_NORMAL_PORTS} — possible port scan target or compromised host"
                        ),
                        "severity": "medium",
                    })

    return anomalies


# ---------------------------------------------------------------------------
# Layer 2: Statistical detection
# ---------------------------------------------------------------------------

def _detect_zscore(metrics: list, baseline: dict, threshold: float) -> list:
    """
    Flag data points whose Z-score exceeds the configured threshold.

    Z-score formula: z = (value - mean) / std_deviation

    A Z-score of 2.5 means the value is 2.5 standard deviations above the mean.
    In a normal distribution, only ~0.6% of values exceed this — so it's unusual.

    Args:
        metrics:   List of metric dicts from current scan results
        baseline:  Dict of {metric_name: {"mean": float, "std": float}}
        threshold: Z-score cutoff from config (e.g. 2.5)

    Returns:
        list: Anomaly dicts for each data point exceeding the threshold
    """
    anomalies = []

    for m in metrics:
        source = m["source"]

        # Get the numeric fields for this metric (exclude non-numeric metadata)
        numeric_fields = {
            k: v for k, v in m.items()
            if k not in ("source", "ip") and isinstance(v, (int, float))
        }

        for field, value in numeric_fields.items():
            key = f"{source}_{field}"

            if key not in baseline:
                continue  # No baseline data for this metric yet

            mean = baseline[key]["mean"]
            std = baseline[key]["std"]

            # Avoid division by zero — if std is 0, all values are identical
            # so there can be no statistical outlier
            if std == 0:
                continue

            z = abs((value - mean) / std)

            if z > threshold:
                anomalies.append({
                    "layer": "statistical",
                    "source": source,
                    "ip": m["ip"],
                    "metric": field,
                    "value": value,
                    "score": round(z, 3),
                    "reason": (
                        f"Z-score {z:.2f} exceeds threshold {threshold} "
                        f"(mean={mean:.2f}, std={std:.2f})"
                    ),
                    "severity": "high" if z > threshold * 1.5 else "medium",
                })

    return anomalies


def _detect_isolation_forest(metrics: list, baseline: dict) -> list:
    """
    Use Isolation Forest to flag anomalous data points.

    Isolation Forest works by building random decision trees and measuring
    how many splits are needed to isolate each data point. Anomalies
    are isolated with fewer splits (shorter path length) than normal points.

    The model returns a score: -1 = anomaly, 1 = normal.

    Args:
        metrics:  List of metric dicts
        baseline: Not used directly — IF trains on all available data

    Returns:
        list: Anomaly dicts for points labelled -1 by the model
    """
    anomalies = []

    # Group metrics by source type — we train one model per source
    # because lan_scan and passive_monitor have different feature sets
    by_source = {}
    for m in metrics:
        by_source.setdefault(m["source"], []).append(m)

    for source, source_metrics in by_source.items():
        # Extract numeric feature matrix
        feature_keys = [
            k for k in source_metrics[0].keys()
            if k not in ("source", "ip") and isinstance(source_metrics[0][k], (int, float))
        ]

        if not feature_keys:
            continue

        X = np.array([
            [m[k] for k in feature_keys]
            for m in source_metrics
        ])

        # Need at least 2 samples to train
        if len(X) < 2:
            continue

        # contamination="auto" lets the model decide the anomaly threshold
        clf = IsolationForest(contamination="auto", random_state=42)
        labels = clf.fit_predict(X)   # -1 = anomaly, 1 = normal
        scores = clf.score_samples(X)  # lower score = more anomalous

        for i, (label, score) in enumerate(zip(labels, scores)):
            if label == -1:
                m = source_metrics[i]
                anomalies.append({
                    "layer": "statistical",
                    "source": source,
                    "ip": m["ip"],
                    "metric": "multivariate",
                    "value": {k: m[k] for k in feature_keys},
                    "score": round(float(score), 4),
                    "reason": (
                        f"Isolation Forest flagged this data point as anomalous "
                        f"(score={score:.4f}, lower = more anomalous)"
                    ),
                    "severity": "medium",
                })

    return anomalies


# ---------------------------------------------------------------------------
# Baseline management
# ---------------------------------------------------------------------------

def _load_or_build_baseline(baseline_path: str, metrics: list) -> tuple:
    """
    Load existing baseline from disk or build a new one from all metrics.

    The baseline stores the mean and standard deviation for each numeric metric.
    These are used by the Z-score detector to judge whether a new value is unusual.

    Args:
        baseline_path: Absolute path to baseline.json
        metrics:       All extracted metrics from scan results

    Returns:
        tuple: (baseline_dict, status_string)
            baseline_dict — {metric_key: {"mean": float, "std": float, "count": int}}
            status_string — "loaded", "new", or "updated"
    """
    if os.path.isfile(baseline_path):
        try:
            with open(baseline_path, "r", encoding="utf-8") as f:
                baseline = json.load(f)
            logger.info("Baseline loaded from %s", baseline_path)
            return baseline, "loaded"
        except (json.JSONDecodeError, OSError) as e:
            logger.warning("Could not load baseline, rebuilding: %s", e)

    # Build baseline from all available metrics
    baseline = _build_baseline(metrics)
    return baseline, "new"


def _build_baseline(metrics: list) -> dict:
    """
    Compute mean and standard deviation for each numeric metric across all samples.

    Args:
        metrics: List of metric dicts

    Returns:
        dict: {metric_key: {"mean": float, "std": float, "count": int}}
    """
    # Group values by metric key (e.g. "lan_scan_open_ports")
    grouped = {}

    for m in metrics:
        source = m["source"]
        for k, v in m.items():
            if k in ("source", "ip") or not isinstance(v, (int, float)):
                continue
            key = f"{source}_{k}"
            grouped.setdefault(key, []).append(v)

    baseline = {}
    for key, values in grouped.items():
        arr = np.array(values, dtype=float)
        baseline[key] = {
            "mean": float(np.mean(arr)),
            "std": float(np.std(arr)),
            "count": len(arr),
        }

    return baseline


def _save_baseline(baseline_path: str, metrics: list, current_status: str) -> None:
    """
    Rebuild and save the baseline incorporating all current metrics.

    We always rebuild from all metrics rather than doing incremental updates.
    This keeps the baseline accurate as the sample count grows.

    Args:
        baseline_path:  Absolute path to save baseline.json
        metrics:        All extracted metrics from scan results
        current_status: "new" or "loaded" — determines logged status
    """
    try:
        os.makedirs(os.path.dirname(baseline_path), exist_ok=True)
        baseline = _build_baseline(metrics)
        with open(baseline_path, "w", encoding="utf-8") as f:
            json.dump(baseline, f, indent=2)
        action = "created" if current_status == "new" else "updated"
        logger.info("Baseline %s at %s", action, baseline_path)
    except OSError as e:
        logger.error("Could not save baseline: %s", e)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_result(status: str, data: dict, errors: list, warning: str = None) -> dict:
    """Build a standardized module result dict."""
    if warning:
        logger.warning(warning)
    return {
        "module": "anomaly_detect",
        "timestamp": datetime.now().isoformat(),
        "status": status,
        "data": data,
        "errors": errors,
    }
