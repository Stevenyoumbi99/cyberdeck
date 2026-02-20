"""
CyberDeck Config Loader
=======================
Reads and validates config/config.json.
Provides default values for missing fields.

Usage:
    from utils.config_loader import load_config
    config = load_config()
"""

# TODO: Phase 4 — Implement config loader
# - Read config/config.json
# - Validate required fields exist
# - Provide sensible defaults for optional fields
# - Return config as a Python dictionary

import json
import os


def load_config(path: str = "config/config.json") -> dict:
    """
    Load and validate the configuration file.

    Args:
        path: Path to config.json (default: config/config.json)

    Returns:
        dict: Validated configuration dictionary

    Raises:
        FileNotFoundError: If config file doesn't exist
        json.JSONDecodeError: If config file is invalid JSON
    """
    # TODO: Implement in Phase 4
    pass
