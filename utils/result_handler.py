"""
CyberDeck Result Handler
========================
Saves module results as standardized JSON files in results/.
File naming: {module}_{timestamp}.json

Every scanning module returns a dict with this schema:
    {
        "module":    str   — e.g. "lan_scan"
        "timestamp": str   — ISO format, e.g. "2025-02-16T14:30:05.123456"
        "status":    str   — "success" | "error" | "partial"
        "data":      dict  — module-specific scan results
        "errors":    list  — empty on success, error strings on failure
    }

This module's job is to persist that dict to disk so the dashboard
and report generator can read it later without re-running the scan.

Usage:
    from utils.result_handler import save_result
    path = save_result(result_dict, config)
"""

import json
import logging
import os

logger = logging.getLogger("cyberdeck")


def save_result(result: dict, config: dict) -> str:
    """
    Save a module result dict to a timestamped JSON file in results/.

    The filename is built from the module name and the timestamp already
    inside the result dict. This keeps the filename and file contents
    consistent — the timestamp in the name matches the one inside the file.

    Example output file: results/lan_scan_2025-02-16T14-30-05.json

    Args:
        result: Standardized result dict from a module.
                Must contain "module" and "timestamp" keys.
        config: Full config dict (uses config["output"]["results_dir"])

    Returns:
        str: Absolute path to the saved JSON file

    Raises:
        KeyError: If "module" or "timestamp" keys are missing from result
        OSError: If the file cannot be written (e.g. permission denied)
    """
    results_dir = config["output"]["results_dir"]

    # Resolve the results directory relative to the project root.
    # Same pattern used in config_loader and logger for consistency.
    project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    full_results_dir = os.path.join(project_root, results_dir)

    # Create the results/ directory if it doesn't exist.
    # exist_ok=True silently succeeds if the directory is already there.
    os.makedirs(full_results_dir, exist_ok=True)

    # Build the filename from the result's own module name and timestamp.
    # Colons are illegal in filenames on Windows; dots can confuse extensions.
    # We keep microseconds (replacing the dot separator) so that two results
    # from the same module within the same second get unique filenames.
    # Result: "2025-02-16T14:30:05.123456" → "2025-02-16T14-30-05-123456"
    module_name = result["module"]
    timestamp_raw = result["timestamp"]
    timestamp_safe = timestamp_raw.replace(":", "-").replace(".", "-")

    filename = f"{module_name}_{timestamp_safe}.json"
    full_path = os.path.join(full_results_dir, filename)

    # Write the result dict as indented JSON.
    # indent=2 makes the file human-readable when inspected directly.
    # ensure_ascii=False preserves any non-ASCII characters in scan data
    # (e.g. device names with special characters).
    # On a Raspberry Pi with an SD card, disk-full or permission errors are
    # realistic — we log before re-raising so the failure appears in the log.
    try:
        with open(full_path, "w", encoding="utf-8") as f:
            json.dump(result, f, indent=2, ensure_ascii=False)
    except OSError as e:
        logger.error("Failed to write result file %s: %s", full_path, e)
        raise

    logger.info("Result saved: %s (status=%s)", filename, result["status"])

    return full_path
