"""
CyberDeck Module: anomaly_detect
================================

Implements:
- Baseline collection saved to anomaly.baseline_file
- Z-score detection (default)
- Optional Isolation Forest (if sklearn installed and baseline has enough samples)

This module:
- Collects lightweight local features:
  - lan_host_count from nmap ping sweep
  - rx_bps / tx_bps from /proc/net/dev (Linux only)
- Works on Windows in dev_mode (mock features) for local smoke tests

Dependencies:
- Required for full mode: nmap (for host_count)
- numpy (required)
- scikit-learn (optional if method == isolation_forest)

Config fields used:
- network.target_subnet
- network.lan_interface
- scan.lan_scan_timeout
- anomaly.method ("zscore"|"isolation_forest")
- anomaly.threshold
- anomaly.baseline_file
- anomaly.min_samples
Optional:
- anomaly.dev_mode (bool, default False)

Output format (data):
{
  "method": "...",
  "baseline_file": "...",
  "baseline_samples": int,
  "current_features": {...},
  "anomalies": [...],
  "risk_score": float,
  "recommendations": [...]
}
"""

from __future__ import annotations

import json
import logging
import shutil
import subprocess
import time
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import numpy as np

logger = logging.getLogger("cyberdeck")


def _now_iso() -> str:
    return datetime.now().isoformat()


def _safe_read_json(path: Path) -> Optional[Dict[str, Any]]:
    try:
        return json.loads(path.read_text(encoding="utf-8", errors="ignore"))
    except Exception:
        return None


def _safe_write_json(path: Path, data: Dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")


def _nmap_ping_sweep_count(target_subnet: str, timeout_s: int) -> Tuple[int, List[str]]:
    """
    Returns:
      host_count, errors
    """
    if not shutil.which("nmap"):
        return 0, ["nmap not found. Install on Kali/RPi: sudo apt install nmap"]

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
        return 0, [f"nmap timed out after {timeout_s}s"]
    except Exception as exc:
        return 0, [f"nmap execution error: {exc}"]

    if proc.returncode != 0:
        return 0, [f"nmap failed (code={proc.returncode}): {proc.stderr.strip()}"]

    count = 0
    for line in proc.stdout.splitlines():
        line = line.strip()
        if line.startswith("Host:") and "Status: Up" in line:
            count += 1

    return count, []


def _read_proc_net_dev(interface: str) -> Optional[Tuple[int, int]]:
    """
    Linux-only throughput read.
    Returns RX bytes, TX bytes or None if unavailable (Windows).
    """
    proc_path = Path("/proc/net/dev")
    if not proc_path.exists():
        return None

    try:
        for line in proc_path.read_text(encoding="utf-8", errors="ignore").splitlines():
            if ":" not in line:
                continue
            ifname, stats = line.split(":", 1)
            if ifname.strip() != interface:
                continue
            fields = stats.split()
            rx_bytes = int(fields[0])
            tx_bytes = int(fields[8])
            return rx_bytes, tx_bytes
    except Exception:
        return None

    return None


def _throughput_bps(interface: str, interval_s: float = 1.0) -> Tuple[float, float]:
    """
    Compute RX/TX bytes per second using /proc/net/dev.
    Returns (rx_bps, tx_bps). If not supported, returns (0,0).
    """
    a = _read_proc_net_dev(interface)
    if not a:
        return 0.0, 0.0

    time.sleep(max(0.2, interval_s))

    b = _read_proc_net_dev(interface)
    if not b:
        return 0.0, 0.0

    rx_bps = (b[0] - a[0]) / interval_s
    tx_bps = (b[1] - a[1]) / interval_s
    return max(rx_bps, 0.0), max(tx_bps, 0.0)


def _load_baseline(path: Path) -> Dict[str, Any]:
    if not path.exists():
        return {"samples": []}
    doc = _safe_read_json(path)
    if not doc or "samples" not in doc or not isinstance(doc["samples"], list):
        return {"samples": []}
    return doc


def _append_sample(baseline: Dict[str, Any], features: Dict[str, float]) -> None:
    baseline.setdefault("samples", [])
    baseline["samples"].append({"timestamp": _now_iso(), "features": features})


def _zscore_detect(samples: List[Dict[str, Any]], current: Dict[str, float], threshold: float) -> List[Dict[str, Any]]:
    """
    Explainable detection: per-feature z-score vs baseline mean/std.
    """
    if not samples:
        return []

    names = list(current.keys())
    mat = []
    for s in samples:
        feat = s.get("features", {})
        mat.append([float(feat.get(k, 0.0)) for k in names])

    X = np.array(mat, dtype=float)
    mu = X.mean(axis=0)
    sigma = X.std(axis=0)
    sigma = np.where(sigma == 0, 1.0, sigma)  # avoid division by zero

    cur = np.array([current[k] for k in names], dtype=float)
    z = (cur - mu) / sigma

    anomalies: List[Dict[str, Any]] = []
    for i, name in enumerate(names):
        zi = float(z[i])
        if abs(zi) >= threshold:
            anomalies.append(
                {
                    "feature": name,
                    "value": float(cur[i]),
                    "zscore": zi,
                    "reason": (
                        f"{name} deviates from baseline: mean={float(mu[i]):.2f}, "
                        f"std={float(sigma[i]):.2f}, z={zi:.2f} (threshold={threshold})."
                    ),
                }
            )
    return anomalies


def _isolation_forest_detect(samples: List[Dict[str, Any]], current: Dict[str, float]) -> List[Dict[str, Any]]:
    """
    Optional ML detection: Isolation Forest.
    Only meaningful when baseline has enough samples.
    """
    try:
        from sklearn.ensemble import IsolationForest  # type: ignore
    except Exception:
        return [
            {
                "feature": "isolation_forest",
                "value": 0.0,
                "zscore": 0.0,
                "reason": "scikit-learn not installed. Install: pip install scikit-learn",
            }
        ]

    names = list(current.keys())
    mat = []
    for s in samples:
        feat = s.get("features", {})
        mat.append([float(feat.get(k, 0.0)) for k in names])

    X = np.array(mat, dtype=float)
    cur_vec = np.array([[current[k] for k in names]], dtype=float)

    model = IsolationForest(contamination=0.05, random_state=42)
    model.fit(X)

    pred = int(model.predict(cur_vec)[0])  # -1 anomaly, 1 normal
    score = float(model.decision_function(cur_vec)[0])

    if pred == -1:
        return [
            {
                "feature": "isolation_forest",
                "value": score,
                "zscore": 0.0,
                "reason": f"Isolation Forest flagged anomaly (decision_score={score:.4f}).",
            }
        ]
    return []


def _risk_score(anomalies: List[Dict[str, Any]]) -> float:
    if not anomalies:
        return 0.0
    base = 10.0 * len(anomalies)
    z_bonus = 0.0
    for a in anomalies:
        z_bonus += min(abs(float(a.get("zscore", 0.0))) * 5.0, 20.0)
    return float(min(base + z_bonus, 100.0))


def _recommendations(anomalies: List[Dict[str, Any]]) -> List[str]:
    if not anomalies:
        return ["No anomaly detected. Keep collecting baseline samples to improve detection."]

    feats = {a.get("feature", "") for a in anomalies}
    recs: List[str] = []
    if "lan_host_count" in feats:
        recs.append("Host count changed: verify unknown devices and DHCP leases.")
    if "net_rx_bps" in feats or "net_tx_bps" in feats:
        recs.append("Throughput anomaly: inspect top talkers; check for scans/exfiltration.")
    return recs


def run(config: dict) -> dict:
    """
    Execute anomaly_detect.
    """
    logger.info("Starting anomaly_detect...")

    try:
        subnet = str(config["network"]["target_subnet"])
        iface = str(config["network"].get("lan_interface", "eth0"))
        timeout_s = int(config["scan"]["lan_scan_timeout"])

        anomaly_cfg = config["anomaly"]
        method = str(anomaly_cfg.get("method", "zscore")).lower()
        threshold = float(anomaly_cfg.get("threshold", 2.5))
        baseline_file = Path(str(anomaly_cfg.get("baseline_file", "results/baseline.json")))
        min_samples = int(anomaly_cfg.get("min_samples", 50))
        dev_mode = bool(anomaly_cfg.get("dev_mode", False))

        errors: List[str] = []

        # 1) Collect features autonomously
        if dev_mode:
            logger.warning("anomaly_detect running in dev_mode (mock features).")
            host_count = 5
            rx_bps, tx_bps = 1000.0, 800.0
            scan_errors = []
        else:
            host_count, scan_errors = _nmap_ping_sweep_count(subnet, timeout_s)
            rx_bps, tx_bps = _throughput_bps(iface, interval_s=1.0)

        errors.extend(scan_errors)

        current_features: Dict[str, float] = {
            "lan_host_count": float(host_count),
            "net_rx_bps": float(rx_bps),
            "net_tx_bps": float(tx_bps),
        }

        # 2) Baseline update
        baseline = _load_baseline(baseline_file)
        samples = baseline.get("samples", [])
        if not isinstance(samples, list):
            samples = []
            baseline["samples"] = samples

        _append_sample(baseline, current_features)
        _safe_write_json(baseline_file, baseline)

        baseline_samples = len(baseline["samples"])

        # 3) Detection (exclude current sample from baseline stats)
        anomalies: List[Dict[str, Any]] = []
        status = "success"

        if baseline_samples < max(5, min_samples):
            status = "partial"
            errors.append(f"Baseline learning in progress ({baseline_samples}/{min_samples}).")
        else:
            history = baseline["samples"][:-1]
            if method == "zscore":
                anomalies = _zscore_detect(history, current_features, threshold)
            elif method == "isolation_forest":
                anomalies = _isolation_forest_detect(history, current_features)
            else:
                raise ValueError(f"Unknown anomaly method: {method}")

        risk = _risk_score(anomalies)
        recs = _recommendations(anomalies)

        data_out = {
            "method": method,
            "baseline_file": str(baseline_file),
            "baseline_samples": baseline_samples,
            "current_features": current_features,
            "anomalies": anomalies,
            "risk_score": risk,
            "recommendations": recs,
        }

        return {
            "module": "anomaly_detect",
            "timestamp": _now_iso(),
            "status": "success" if not errors and status == "success" else status,
            "data": data_out,
            "errors": errors,
        }

    except Exception as e:
        logger.error(f"anomaly_detect failed: {e}")
        return {
            "module": "anomaly_detect",
            "timestamp": _now_iso(),
            "status": "error",
            "data": {},
            "errors": [str(e)],
        }