"""
CyberDeck Menu
==============
Dynamic CLI menu that discovers available modules from the modules/ folder
and prompts the user to select one.

Why dynamic discovery?
    Instead of hardcoding a list of modules, we scan the modules/ directory
    at runtime. This means adding a new module file (e.g. modules/dns_recon.py)
    automatically makes it appear in the menu — no changes needed here.

Usage:
    Called by launcher.py — not run directly.
    selected = show_menu()   # returns a module name string, or None to quit
"""

import logging
import os

logger = logging.getLogger("cyberdeck")

# Note: this module uses print() for all user-facing UI output (menu display,
# prompts, error messages). This is intentional — print() renders to the user's
# terminal, while the logger records events to the audit log. Both serve
# different purposes here. The "never print()" rule applies to module logic,
# not to UI rendering.

# Files in modules/ that are not scannable modules and must be excluded.
# __init__.py is a Python package marker, not a runnable module.
EXCLUDED_FILES = {"__init__.py"}


def _discover_modules() -> list[str]:
    """
    Scan the modules/ directory and return a sorted list of module names.

    We derive the modules/ path relative to this file's location so the
    menu works regardless of which directory the script is launched from.

    Returns:
        list[str]: Sorted module names without .py extension,
                   e.g. ["bluetooth_recon", "lan_scan", "wifi_audit"]
    """
    # __file__ is menu.py; its parent is the project root where modules/ lives
    project_root = os.path.dirname(os.path.abspath(__file__))
    modules_dir = os.path.join(project_root, "modules")

    module_names = []

    try:
        filenames = os.listdir(modules_dir)
    except FileNotFoundError:
        logger.error("modules/ directory not found at: %s", modules_dir)
        return []

    for filename in filenames:
        # Only include .py files that aren't in the exclusion list
        if filename.endswith(".py") and filename not in EXCLUDED_FILES:
            # Strip the .py extension to get the importable module name
            module_names.append(filename[:-3])

    # Sort alphabetically so the menu order is consistent across runs.
    # Without sorting, os.listdir() returns files in filesystem order,
    # which can vary between systems and even between reboots.
    return sorted(module_names)


def _format_display_name(module_name: str) -> str:
    """
    Convert a snake_case module name to a readable display label.

    This is purely cosmetic — the underlying module_name is unchanged
    and is what gets returned to launcher.py for importing.

    Example: "lan_scan" → "Lan Scan"

    Args:
        module_name: The module filename without .py extension

    Returns:
        str: Human-readable label for the menu
    """
    # Replace underscores with spaces and capitalise each word
    return module_name.replace("_", " ").title()


def show_menu() -> str | None:
    """
    Display the CyberDeck module selection menu and return the user's choice.

    Loops until the user enters a valid selection or chooses to quit.
    Input is validated: only integers within the displayed range are accepted.

    Returns:
        str: The selected module name (e.g. "lan_scan"), ready for importing
        None: If the user chose to quit
    """
    modules = _discover_modules()

    if not modules:
        # This would only happen if the modules/ folder is empty or missing.
        # Log it so the failure appears in the audit log.
        logger.error("No modules found in modules/ directory.")
        print("[!] No modules available. Check the modules/ directory.")
        return None

    logger.info("Menu loaded with %d modules", len(modules))

    while True:
        # Print the header banner
        print("\n" + "=" * 40)
        print("  CyberDeck — Audit Mode Selection")
        print("=" * 40)

        # Print a numbered list of available modules
        for i, module_name in enumerate(modules, start=1):
            display = _format_display_name(module_name)
            print(f"  [{i}] {display}")

        # Quit is always the last option
        print("  [0] Quit")
        print("=" * 40)

        # Read and validate user input
        raw = input("Select an option: ").strip()

        # Validate: input must be a digit, and within the valid range
        if not raw.isdigit():
            print("[!] Invalid input. Please enter a number.")
            continue

        choice = int(raw)

        if choice == 0:
            logger.info("User selected quit from menu")
            return None

        if 1 <= choice <= len(modules):
            selected = modules[choice - 1]
            logger.info("User selected module: %s", selected)
            return selected

        # Number was valid but out of range
        print(f"[!] Please enter a number between 0 and {len(modules)}.")
