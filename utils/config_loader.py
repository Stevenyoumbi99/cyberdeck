"""
CyberDeck Config Loader
=======================
Reads and validates config/config.json.
Provides default values for missing fields.

This module is the single point of entry for all configuration.
It runs once at startup (called by launcher.py) and its output
is passed as a parameter to every module that needs settings.

Why centralize config loading?
- Modules don't need to handle file I/O or JSON parsing themselves
- Validation happens once, in one place
- If the config is broken, we fail early with a clear error message
  rather than failing silently inside a module mid-scan

Usage:
    from utils.config_loader import load_config
    config = load_config()
"""

import json
import os

# Note: this module intentionally does NOT use the centralized logger.
# config_loader runs first (step 1 of the boot sequence), before logger.py
# has been initialized. Using exceptions for errors here is correct — if config
# fails to load, there is no logging system to report to anyway.


# These are the top-level sections that MUST exist in config.json.
# If any of these are missing, the system cannot run safely.
# - network: hardware-specific interfaces — no safe generic defaults possible
# - output: directories that modules write to — must be explicitly configured
# Note: 'logging' and 'scan' are NOT required here because DEFAULTS covers them.
REQUIRED_SECTIONS = ["network", "output"]

# Default values for optional fields.
# These are used as fallbacks if a key is missing from config.json.
# This makes the system more resilient to incomplete config files.
DEFAULTS = {
    "project": {
        "name": "CyberDeck",
        "version": "unknown"
    },
    "scan": {
        "lan_scan_timeout": 30,
        "port_range": "1-1024",
        "wifi_scan_duration": 15,
        "bluetooth_scan_duration": 10,
        "passive_capture_duration": 60
    },
    "anomaly": {
        "method": "zscore",
        "threshold": 2.5,
        "baseline_file": "results/baseline.json",
        "min_samples": 50
    },
    "dashboard": {
        "host": "0.0.0.0",
        "port": 5000
    },
    "logging": {
        "level": "INFO",
        "log_to_file": True,
        "log_to_console": True,
        "max_file_size_mb": 5,
        "backup_count": 3
    }
}


def load_config(path: str = "config/config.json") -> dict:
    """
    Load and validate the configuration file.

    Steps:
        1. Resolve the file path relative to the project root
        2. Read and parse the JSON file
        3. Check that all required sections are present
        4. Merge in defaults for any missing optional fields
        5. Return the final config dictionary

    Args:
        path: Path to config.json (default: config/config.json)

    Returns:
        dict: Validated configuration dictionary

    Raises:
        FileNotFoundError: If config file doesn't exist at the given path
        json.JSONDecodeError: If the file exists but contains invalid JSON
        KeyError: If a required section is missing from the config
    """
    # Resolve path relative to the project root (the directory containing
    # this file's parent). This ensures the loader works regardless of
    # which directory the script is launched from.
    project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    full_path = os.path.join(project_root, path)

    # Fail early with a clear message if the config file is missing.
    # Without config, nothing else can run safely.
    if not os.path.exists(full_path):
        raise FileNotFoundError(
            f"Config file not found: {full_path}\n"
            f"Make sure config/config.json exists in the project root."
        )

    # Open and parse the JSON file.
    # json.JSONDecodeError will be raised automatically if the file is
    # malformed — we let it propagate so the caller sees a clear error.
    with open(full_path, "r") as f:
        config = json.load(f)

    # Validate that all required sections are present.
    # These sections contain fields that other modules depend on directly.
    _validate_required_sections(config)

    # Merge defaults into the loaded config.
    # This fills in optional sections/fields that may have been omitted,
    # so downstream modules can always safely access these keys.
    config = _apply_defaults(config)

    return config


def _validate_required_sections(config: dict) -> None:
    """
    Check that all required top-level sections exist in the config.

    Why validate? If a required section like 'network' or 'output' is
    missing, modules will crash with a confusing KeyError deep in their
    logic. It's better to catch this here and give a clear error message.

    Args:
        config: The raw parsed config dictionary

    Raises:
        KeyError: If a required section is missing
    """
    for section in REQUIRED_SECTIONS:
        if section not in config:
            raise KeyError(
                f"Missing required section '{section}' in config.json. "
                f"Required sections are: {REQUIRED_SECTIONS}"
            )


def _apply_defaults(config: dict) -> dict:
    """
    Merge default values into the config for any missing optional fields.

    We use a shallow merge strategy: if an entire section is missing,
    we copy the default section. If a section exists but a specific key
    is missing within it, we add just that key from the defaults.

    This means a partial config (e.g. missing 'dashboard') will still
    work — it just uses the default dashboard host and port.

    Args:
        config: The validated config dictionary

    Returns:
        dict: Config with defaults applied for any missing fields
    """
    for section, default_values in DEFAULTS.items():
        if section not in config:
            # The entire section is missing — use the full default block
            config[section] = default_values
        else:
            # Section exists — fill in only the missing individual keys
            for key, value in default_values.items():
                if key not in config[section]:
                    config[section][key] = value

    return config
