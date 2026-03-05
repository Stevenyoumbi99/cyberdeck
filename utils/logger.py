"""
CyberDeck Logger
================
Centralized logging setup for all modules.
All modules use: logging.getLogger("cyberdeck")

How Python's named logger works:
    logging.getLogger("cyberdeck") always returns the SAME logger object,
    no matter which module calls it. This means init_logger() only needs
    to be called once (in launcher.py), and every module automatically
    inherits the same handlers and log level.

Log format:
    2025-02-16 14:30:05 | INFO     | LAN scan started on eth0

Usage:
    from utils.logger import init_logger
    init_logger(config)
"""

import logging
import os
import sys
from logging.handlers import RotatingFileHandler

# The shared logger name used across the entire project.
# Every module gets this same logger via: logging.getLogger(LOGGER_NAME)
LOGGER_NAME = "cyberdeck"

# Log line format: timestamp | level (padded to 8 chars) | message
LOG_FORMAT = "%(asctime)s | %(levelname)-8s | %(message)s"
DATE_FORMAT = "%Y-%m-%d %H:%M:%S"


def init_logger(config: dict) -> logging.Logger:
    """
    Initialize the centralized CyberDeck logger.

    Reads settings from config["logging"] and attaches up to two handlers:
    - Console handler: prints to stdout (useful during development)
    - File handler: writes to logs/cyberdeck.log with automatic rotation

    File rotation prevents the log file from growing indefinitely.
    When the file reaches max_file_size_mb, it is renamed to
    cyberdeck.log.1 and a new cyberdeck.log is started.
    Up to backup_count old files are kept, then the oldest is deleted.

    Args:
        config: Full config dictionary (uses config["logging"] section)

    Returns:
        logging.Logger: The configured "cyberdeck" logger instance
    """
    log_cfg = config["logging"]

    # Convert the string level from config (e.g. "INFO") to a logging
    # constant (e.g. logging.INFO). getattr is used because the level
    # names are attributes of the logging module.
    # Fallback to INFO if the value in config is unrecognised.
    level = getattr(logging, log_cfg.get("level", "INFO").upper(), logging.INFO)

    # Get (or create) the named logger. If init_logger is accidentally
    # called twice, this returns the same object — we guard against
    # duplicate handlers being added below.
    logger = logging.getLogger(LOGGER_NAME)
    logger.setLevel(level)

    # Prevent messages from bubbling up to the root logger.
    # Without this, any library that configures the root logger (Flask, Scapy,
    # etc.) would cause every cyberdeck log line to appear twice.
    logger.propagate = False

    # Guard: if handlers are already attached, the logger was already
    # initialized. Skip setup to avoid duplicate log lines.
    if logger.handlers:
        return logger

    formatter = logging.Formatter(fmt=LOG_FORMAT, datefmt=DATE_FORMAT)

    # --- Console handler ---
    # Prints log lines to the terminal. Useful during development and
    # when running the system interactively on the Pi's touchscreen.
    if log_cfg.get("log_to_console", True):
        # Write to stdout, not stderr. stderr is conventionally reserved for
        # errors; operational audit logs belong on stdout.
        console_handler = logging.StreamHandler(stream=sys.stdout)
        console_handler.setFormatter(formatter)
        logger.addHandler(console_handler)

    # --- Rotating file handler ---
    # Writes log lines to a file. Rotation keeps disk usage bounded,
    # which matters on a Raspberry Pi with limited storage.
    if log_cfg.get("log_to_file", True):
        log_dir = config["output"].get("logs_dir", "logs/")

        # Resolve the logs directory relative to the project root,
        # same approach used in config_loader.py for consistency.
        project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        full_log_dir = os.path.join(project_root, log_dir)

        # Create the logs/ directory if it doesn't exist yet.
        # exist_ok=True means no error if it already exists.
        os.makedirs(full_log_dir, exist_ok=True)

        log_file = os.path.join(full_log_dir, "cyberdeck.log")

        # Convert MB from config to bytes, which is what RotatingFileHandler expects.
        max_bytes = log_cfg.get("max_file_size_mb", 5) * 1024 * 1024
        backup_count = log_cfg.get("backup_count", 3)

        file_handler = RotatingFileHandler(
            filename=log_file,
            maxBytes=max_bytes,
            backupCount=backup_count,
            encoding="utf-8"
        )
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)

    logger.info("CyberDeck logger initialized (level=%s)", log_cfg.get("level", "INFO"))

    return logger
