"""
CyberDeck Launcher
==================
Main entry point for the CyberDeck system.

Boot sequence (order matters — each step depends on the previous):
    1. load_config()        — parse and validate config/config.json
    2. init_logger(config)  — set up logging (needs config for level/paths)
    3. show_menu()          — display module list, get user selection
    4. import_module()      — dynamically load the chosen module by name
    5. module.run(config)   — execute the scan, get result dict
    6. save_result()        — persist result to results/ as JSON
    7. loop back to step 3

Usage:
    python launcher.py
"""

import importlib
import logging
import sys

from utils.config_loader import load_config
from utils.logger import init_logger
from utils.result_handler import save_result
from menu import show_menu

# Module-level logger — only used after init_logger() has been called in main()
logger = logging.getLogger("cyberdeck")


def run_module(module_name: str, config: dict) -> None:
    """
    Dynamically import a module from the modules/ package and execute it.

    Why importlib instead of a normal import?
        Normal imports are written at code time: `import modules.lan_scan`.
        Here we don't know the module name until the user picks it at runtime.
        importlib.import_module() lets us construct the import path as a string.

    The full import path is "modules.<module_name>" — e.g. "modules.lan_scan".
    This works because modules/ has an __init__.py, making it a Python package.

    Args:
        module_name: The module filename without .py, e.g. "lan_scan"
        config: Full config dict, passed directly to the module's run() function
    """
    import_path = f"modules.{module_name}"

    logger.info("Importing module: %s", import_path)

    try:
        # Dynamically load the module by its dotted path string
        module = importlib.import_module(import_path)
    except ImportError as e:
        # This would happen if the file exists but has a syntax error,
        # or imports a package that isn't installed.
        logger.error("Failed to import %s: %s", import_path, e)
        print(f"[!] Could not load module '{module_name}': {e}")
        return

    # Verify the module follows the contract — it must have a run() function.
    # Without this check, a missing run() would give an unhelpful AttributeError.
    if not hasattr(module, "run"):
        logger.error("Module '%s' does not implement run(config) — skipping", module_name)
        print(f"[!] Module '{module_name}' is missing a run() function.")
        return

    logger.info("Running module: %s", module_name)
    print(f"\n[>] Starting {module_name}...\n")

    # Execute the module. The result always follows the standard schema:
    # { module, timestamp, status, data, errors }
    # Wrapped in try/except because a module bug could raise an unhandled
    # exception despite the contract. We catch it here so one broken module
    # doesn't kill the entire session — the user returns to the menu instead.
    try:
        result = module.run(config)
    except Exception as e:
        logger.error("Module '%s' raised an unhandled exception: %s", module_name, e)
        print(f"[!] Module '{module_name}' crashed unexpectedly: {e}")
        return

    # Save the result to disk regardless of whether the scan succeeded or failed.
    # A failed scan result is still useful — it records that the attempt was made.
    # save_result() can raise OSError (e.g. disk full on the Pi's SD card) —
    # we catch it so a save failure doesn't crash the session.
    try:
        saved_path = save_result(result, config)
    except OSError as e:
        logger.error("Could not save result for '%s': %s", module_name, e)
        print(f"[!] Result could not be saved: {e}")
        return

    # Print a brief summary to the terminal so the user knows what happened
    status = result.get("status", "unknown")
    print(f"\n[✓] Module finished — status: {status}")
    print(f"[✓] Result saved to: {saved_path}")

    if result.get("errors"):
        print("[!] Errors reported:")
        for err in result["errors"]:
            print(f"    - {err}")


def main() -> None:
    """
    Main entry point. Runs the full boot sequence then loops on the menu.

    The outer try/except catches fatal startup errors (missing config,
    broken JSON) and prints a clean message before exiting. Once the system
    is running, individual module errors are caught inside run_module() so
    one bad scan doesn't kill the session.
    """
    print("=" * 50)
    print("  CYBERDECK — Portable Cyber Audit Platform")
    print("=" * 50)
    print()

    # --- Step 1: Load configuration ---
    # This must happen before anything else. If it fails, we cannot proceed.
    try:
        config = load_config()
    except (FileNotFoundError, KeyError, ValueError) as e:
        # No logger yet — print directly since logging isn't initialised
        print(f"[FATAL] Failed to load config: {e}")
        sys.exit(1)

    # --- Step 2: Initialise logging ---
    # From this point on, all output goes through the logger.
    init_logger(config)
    logger.info("CyberDeck starting up (v%s)", config["project"].get("version", "?"))

    # --- Step 3-6: Menu loop ---
    # After startup, the system loops: show menu → run module → save result → repeat.
    # The loop exits cleanly when the user selects "Quit" (show_menu returns None).
    while True:
        selected_module = show_menu()

        if selected_module is None:
            # User chose to quit
            logger.info("CyberDeck shutting down — user quit")
            print("\n[i] Goodbye.\n")
            sys.exit(0)

        run_module(selected_module, config)


if __name__ == "__main__":
    main()
