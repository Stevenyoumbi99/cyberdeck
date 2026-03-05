"""
CyberDeck GUI Launcher
=======================
Tkinter-based graphical interface for the CyberDeck system.

Why Tkinter?
    Tkinter is Python's built-in GUI toolkit — no extra installation needed.
    It creates a native OS window that works on the Raspberry Pi's touchscreen
    directly, without needing a browser. This makes CyberDeck feel like a
    standalone appliance rather than a terminal script.

Architecture — the threading problem:
    Tkinter's event loop MUST run on the main thread. But scan modules like
    lan_scan or passive_monitor can take minutes to complete. If we called
    module.run() directly in the button handler, the UI would freeze for the
    entire duration — buttons unresponsive, window can't be moved or closed.

    Solution: two-thread model.
        Main thread  → Tkinter event loop (always running, always responsive)
        Worker thread → module.run(config) (one at a time, runs in background)

    Communication between threads:
        We cannot touch Tkinter widgets from a background thread — that causes
        race conditions and crashes. Instead we use a queue.Queue() as a message
        channel: the worker thread puts log messages into the queue, and the
        main thread polls the queue every 100 ms using root.after() to pull them
        out and append them to the log widget safely.

    Custom log handler:
        We attach a _QueueHandler to the "cyberdeck" logger. Every logger.info()
        or logger.warning() call in any module automatically goes into the queue
        and appears in the GUI log — no changes needed in the modules.

Layout:
    ┌────────────────────────────────────────────────────┐
    │  CYBERDECK — Portable Cybersecurity Audit Platform │  ← header
    ├──────────────┬─────────────────────────────────────┤
    │              │                                      │
    │  [LAN SCAN]  │  > CyberDeck v1.0.0 ready           │
    │  [PASSIVE..] │  > Select a module to begin         │  ← log panel
    │  [WIFI AUDIT]│  [06:05] lan_scan: Found 4 hosts    │
    │  [BLUETOOTH] │                                      │
    │  [PENTEST..] │                                      │
    │  [ARP MON..] │                                      │
    │  [TLS AUDIT] │                                      │
    │  [ANOMALY..] │                                      │
    │  [DASHBOARD] │                                      │
    │              │                                      │
    │  ─────────── │                                      │
    │  [REPORT]    │                                      │
    │  [QUIT]      │                                      │
    ├──────────────┴─────────────────────────────────────┤
    │  Status: Ready | Last: lan_scan 06:05:39            │  ← status bar
    └────────────────────────────────────────────────────┘

Usage:
    from ui.launcher_gui import CyberDeckGUI
    gui = CyberDeckGUI(config)
    gui.run()   # blocks until the user closes the window

Config fields used:
    config["project"]["version"]    — displayed in the header
    config["output"]["results_dir"] — passed to generate_report()

Dependencies:
    tkinter   — built into Python (no pip install)
    threading — built into Python
    queue     — built into Python
"""

import importlib
import logging
import os
import queue
import threading
import webbrowser
from datetime import datetime

import tkinter as tk

from utils.config_loader import load_config
from utils.result_handler import save_result
from utils.report_generator import generate_report


logger = logging.getLogger("cyberdeck")


# ---------------------------------------------------------------------------
# Colour palette — matches the dashboard and report dark theme
# ---------------------------------------------------------------------------
_C = {
    "bg":          "#0a0e1a",   # page background
    "bg_panel":    "#111827",   # sidebar and card backgrounds
    "bg_header":   "#0d1b2a",   # header bar
    "border":      "#1e3a5f",   # subtle borders
    "accent":      "#00d4ff",   # cyan — primary accent (titles, active)
    "accent2":     "#ff6b35",   # orange — brand secondary
    "text":        "#c8d8e8",   # body text
    "text_muted":  "#7a9ab8",   # secondary / placeholder text
    "success":     "#00cc66",   # green — clean / OK
    "warning":     "#ff9900",   # amber — partial / warning
    "danger":      "#ff4444",   # red — error / critical
    "btn_bg":      "#1a2a3a",   # module button background (resting)
    "btn_active":  "#00d4ff",   # module button background (running)
}


# ---------------------------------------------------------------------------
# Custom logging handler — bridges the Python logger to the Tkinter queue
# ---------------------------------------------------------------------------

class _QueueHandler(logging.Handler):
    """
    A logging.Handler that puts formatted log records into a queue.Queue.

    Attached to the root "cyberdeck" logger so that every logger.info(),
    logger.warning(), etc. call anywhere in the system (modules, utils, ...)
    automatically arrives in the GUI log panel without any changes to the
    existing modules.

    Thread safety: queue.Queue.put() is thread-safe by design, so this
    handler can be called from background scan threads without issues.
    """

    def __init__(self, log_queue: queue.Queue) -> None:
        super().__init__()
        self._queue = log_queue

    def emit(self, record: logging.LogRecord) -> None:
        """Format the record and put it on the queue for the UI thread to consume."""
        try:
            msg = self.format(record)
            # Attach the level name so the UI can colour-code the line
            self._queue.put((record.levelname, msg))
        except Exception:
            self.handleError(record)


# ---------------------------------------------------------------------------
# Module discovery — same logic as menu.py
# ---------------------------------------------------------------------------

_EXCLUDED = {"__init__.py", "dashboard.py"}   # dashboard has its own button


def _discover_modules() -> list:
    """
    Return sorted list of module names from the modules/ directory.

    Mirrors _discover_modules() in menu.py so both interfaces see the same
    set of modules. dashboard.py is excluded because it gets its own dedicated
    button with special handling (runs persistently in a thread).

    Returns:
        list[str]: e.g. ["arp_monitor", "lan_scan", "passive_monitor", ...]
    """
    project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    modules_dir = os.path.join(project_root, "modules")
    names = []
    for fname in os.listdir(modules_dir):
        if fname.endswith(".py") and fname not in _EXCLUDED:
            names.append(fname[:-3])
    return sorted(names)


def _format_btn_label(module_name: str) -> str:
    """Convert 'lan_scan' → 'LAN SCAN' for button labels."""
    return module_name.replace("_", " ").upper()


# ---------------------------------------------------------------------------
# Main GUI class
# ---------------------------------------------------------------------------

class CyberDeckGUI:
    """
    The CyberDeck graphical interface.

    Builds the Tkinter window and manages the scan lifecycle:
        button click → disable all buttons → run module in worker thread
        → stream log output via queue → re-enable buttons when done.
    """

    def __init__(self, config: dict) -> None:
        """
        Build the full UI and wire up all event handlers.

        Args:
            config: Full config dict from config.json, passed to every module.
        """
        self._config = config
        self._version = config.get("project", {}).get("version", "1.0.0")

        # Queue for thread-safe log communication: worker → main thread
        self._log_queue: queue.Queue = queue.Queue()

        # Track whether a scan is currently running (prevent concurrent scans)
        self._scan_running = False

        # References to all module buttons so we can enable/disable them
        self._module_buttons: list = []

        # Reference to the dashboard thread (None if not running)
        self._dashboard_thread: threading.Thread | None = None

        # Build the window
        self._root = tk.Tk()
        self._root.title("CyberDeck")
        self._root.configure(bg=_C["bg"])
        self._root.minsize(900, 600)

        # Intercept the window close button to clean up properly
        self._root.protocol("WM_DELETE_WINDOW", self._on_quit)

        # Build UI sections
        self._build_header()
        self._build_body()        # left sidebar + right log panel
        self._build_statusbar()

        # Attach our custom handler to the "cyberdeck" logger so all module
        # log output flows into the queue and appears in the log panel.
        handler = _QueueHandler(self._log_queue)
        handler.setFormatter(logging.Formatter("%(levelname)-8s %(message)s"))
        logging.getLogger("cyberdeck").addHandler(handler)

        # Start polling the queue — checks every 100 ms for new log messages.
        # root.after() schedules a callback on the main thread, so touching
        # Tkinter widgets inside _poll_queue() is safe.
        self._root.after(100, self._poll_queue)

        # Welcome message
        self._log("CyberDeck v" + self._version + " ready.", "INFO")
        self._log("Select a module from the left panel to begin.", "INFO")

    # ------------------------------------------------------------------
    # UI construction helpers
    # ------------------------------------------------------------------

    def _build_header(self) -> None:
        """Create the dark title bar at the top of the window."""
        header = tk.Frame(self._root, bg=_C["bg_header"], pady=14)
        header.pack(fill=tk.X, side=tk.TOP)

        # Left: project name
        title = tk.Label(
            header,
            text="CYBER",
            font=("Courier New", 20, "bold"),
            fg=_C["accent"],
            bg=_C["bg_header"],
        )
        title.pack(side=tk.LEFT, padx=(20, 0))

        tk.Label(
            header,
            text="DECK",
            font=("Courier New", 20, "bold"),
            fg=_C["accent2"],
            bg=_C["bg_header"],
        ).pack(side=tk.LEFT)


        # Right: version
        tk.Label(
            header,
            text=f"v{self._version}  |  MSc Cyber & Data",
            font=("Courier New", 10),
            fg=_C["text_muted"],
            bg=_C["bg_header"],
        ).pack(side=tk.RIGHT, padx=20)

    def _build_body(self) -> None:
        """Create the two-column body: sidebar (left) + log panel (right)."""
        body = tk.Frame(self._root, bg=_C["bg"])
        body.pack(fill=tk.BOTH, expand=True)

        self._build_sidebar(body)
        self._build_log_panel(body)

    def _build_sidebar(self, parent: tk.Frame) -> None:
        """
        Build the left panel with one button per discovered module plus
        dedicated buttons for Dashboard, Generate Report, and Quit.

        Buttons are stored in self._module_buttons so we can disable them
        all while a scan is running and re-enable when it finishes.
        """
        sidebar = tk.Frame(
            parent,
            bg=_C["bg_panel"],
            width=200,
            bd=0,
        )
        sidebar.pack(side=tk.LEFT, fill=tk.Y, padx=(0, 2))
        sidebar.pack_propagate(False)   # keep fixed width

        tk.Label(
            sidebar,
            text="AUDIT MODULES",
            font=("Courier New", 9, "bold"),
            fg=_C["text_muted"],
            bg=_C["bg_panel"],
            pady=10,
        ).pack(fill=tk.X, padx=10)

        # --- One button per discovered module ---
        modules = _discover_modules()
        for mod_name in modules:
            btn = tk.Button(
                sidebar,
                text=_format_btn_label(mod_name),
                font=("Courier New", 10),
                fg=_C["accent"],
                bg=_C["btn_bg"],
                activeforeground=_C["bg"],
                activebackground=_C["accent"],
                relief=tk.FLAT,
                bd=0,
                pady=8,
                cursor="hand2",
                # Use default argument to capture mod_name in the closure
                command=lambda name=mod_name: self._on_module_click(name),
            )
            btn.pack(fill=tk.X, padx=8, pady=2)
            self._module_buttons.append(btn)

        # --- Separator ---
        tk.Frame(sidebar, bg=_C["border"], height=1).pack(fill=tk.X, padx=8, pady=10)

        # --- Dashboard button (special — runs persistently in a thread) ---
        self._dashboard_btn = tk.Button(
            sidebar,
            text="DASHBOARD",
            font=("Courier New", 10),
            fg=_C["warning"],
            bg=_C["btn_bg"],
            activeforeground=_C["bg"],
            activebackground=_C["warning"],
            relief=tk.FLAT,
            bd=0,
            pady=8,
            cursor="hand2",
            command=self._on_dashboard_click,
        )
        self._dashboard_btn.pack(fill=tk.X, padx=8, pady=2)

        # --- Generate Report button ---
        tk.Button(
            sidebar,
            text="GENERATE REPORT",
            font=("Courier New", 10),
            fg=_C["success"],
            bg=_C["btn_bg"],
            activeforeground=_C["bg"],
            activebackground=_C["success"],
            relief=tk.FLAT,
            bd=0,
            pady=8,
            cursor="hand2",
            command=self._on_generate_report,
        ).pack(fill=tk.X, padx=8, pady=2)

        # --- Quit button ---
        tk.Button(
            sidebar,
            text="QUIT",
            font=("Courier New", 10),
            fg=_C["danger"],
            bg=_C["btn_bg"],
            activeforeground=_C["bg"],
            activebackground=_C["danger"],
            relief=tk.FLAT,
            bd=0,
            pady=8,
            cursor="hand2",
            command=self._on_quit,
        ).pack(fill=tk.X, padx=8, pady=2)

    def _build_log_panel(self, parent: tk.Frame) -> None:
        """
        Build the right panel: a scrollable text area that shows all log output.

        We use tk.Text with disabled state (read-only for the user) and add
        colour tags for different log levels so errors stand out visually.
        """
        log_frame = tk.Frame(parent, bg=_C["bg"])
        log_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        # Header row for the log panel
        log_header = tk.Frame(log_frame, bg=_C["bg_header"], pady=6)
        log_header.pack(fill=tk.X)
        tk.Label(
            log_header,
            text="SCAN OUTPUT",
            font=("Courier New", 10, "bold"),
            fg=_C["accent"],
            bg=_C["bg_header"],
            padx=12,
        ).pack(side=tk.LEFT)

        # Scrollable text widget — the main log display
        self._log_text = tk.Text(
            log_frame,
            bg=_C["bg"],
            fg=_C["text"],
            font=("Courier New", 11),
            relief=tk.FLAT,
            bd=0,
            padx=14,
            pady=10,
            state=tk.DISABLED,         # read-only — user cannot type here
            wrap=tk.WORD,
            insertbackground=_C["accent"],
        )
        self._log_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        # Scrollbar wired to the text widget
        scrollbar = tk.Scrollbar(log_frame, command=self._log_text.yview, bg=_C["bg_panel"])
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self._log_text.configure(yscrollcommand=scrollbar.set)

        # Colour tags — applied per line based on log level
        self._log_text.tag_configure("INFO",     foreground=_C["text"])
        self._log_text.tag_configure("WARNING",  foreground=_C["warning"])
        self._log_text.tag_configure("ERROR",    foreground=_C["danger"])
        self._log_text.tag_configure("CRITICAL", foreground=_C["danger"])
        self._log_text.tag_configure("DEBUG",    foreground=_C["text_muted"])
        self._log_text.tag_configure("SUCCESS",  foreground=_C["success"])
        self._log_text.tag_configure("SYSTEM",   foreground=_C["accent"])

    def _build_statusbar(self) -> None:
        """Create the bottom status bar showing current state and last scan."""
        bar = tk.Frame(self._root, bg=_C["bg_header"], pady=5)
        bar.pack(fill=tk.X, side=tk.BOTTOM)

        self._status_var = tk.StringVar(value="Ready")
        self._last_scan_var = tk.StringVar(value="—")

        tk.Label(
            bar,
            textvariable=self._status_var,
            font=("Courier New", 10),
            fg=_C["success"],
            bg=_C["bg_header"],
        ).pack(side=tk.LEFT, padx=14)

        tk.Label(
            bar,
            text=" | Last scan: ",
            font=("Courier New", 10),
            fg=_C["text_muted"],
            bg=_C["bg_header"],
        ).pack(side=tk.LEFT)

        tk.Label(
            bar,
            textvariable=self._last_scan_var,
            font=("Courier New", 10),
            fg=_C["text"],
            bg=_C["bg_header"],
        ).pack(side=tk.LEFT)

    # ------------------------------------------------------------------
    # Logging helpers
    # ------------------------------------------------------------------

    def _log(self, message: str, level: str = "INFO") -> None:
        """
        Append a timestamped line to the log panel.

        This method is called from the main thread only (either directly
        or through _poll_queue). It enables the text widget, inserts the
        line, then disables it again to keep it read-only.

        Args:
            message: The text to display.
            level:   Log level tag ("INFO", "WARNING", "ERROR", "SUCCESS", "SYSTEM")
        """
        timestamp = datetime.now().strftime("%H:%M:%S")
        line = f"[{timestamp}] {message}\n"

        self._log_text.configure(state=tk.NORMAL)
        self._log_text.insert(tk.END, line, level)
        self._log_text.configure(state=tk.DISABLED)

        # Auto-scroll to the bottom so the latest output is always visible
        self._log_text.see(tk.END)

    def _poll_queue(self) -> None:
        """
        Pull all pending log messages from the queue and display them.

        Scheduled with root.after() to run on the main thread every 100 ms.
        This is the only safe way to update Tkinter widgets from background
        thread output — the background thread writes to the queue, the main
        thread reads from it here.
        """
        try:
            while True:   # drain the queue in one pass
                level, msg = self._log_queue.get_nowait()
                self._log(msg, level)
        except queue.Empty:
            pass
        # Reschedule — runs forever until the window closes
        self._root.after(100, self._poll_queue)

    # ------------------------------------------------------------------
    # Button handlers
    # ------------------------------------------------------------------

    def _on_module_click(self, module_name: str) -> None:
        """
        Called when the user clicks a module button.

        Prevents concurrent scans (one at a time), then launches the module
        in a background thread so the UI stays responsive.

        Args:
            module_name: The module to run (e.g. "lan_scan").
        """
        if self._scan_running:
            self._log("A scan is already running. Please wait for it to finish.", "WARNING")
            return

        self._scan_running = True
        self._set_buttons_state(tk.DISABLED)
        self._status_var.set(f"Running: {module_name.replace('_', ' ').upper()}...")
        self._log(f"Starting {module_name}...", "SYSTEM")

        # Launch in a daemon thread — daemon=True means it is killed automatically
        # if the main window closes, preventing zombie scan processes.
        thread = threading.Thread(
            target=self._run_module_thread,
            args=(module_name,),
            daemon=True,
        )
        thread.start()

    def _run_module_thread(self, module_name: str) -> None:
        """
        Worker thread: import the module, run it, save the result.

        This mirrors run_module() in launcher.py but uses the queue for
        logging instead of print(), and calls self._on_scan_done() to
        update the UI when finished.

        Args:
            module_name: The module to import and run.
        """
        try:
            import_path = f"modules.{module_name}"
            module = importlib.import_module(import_path)

            if not hasattr(module, "run"):
                logger.error("Module '%s' has no run() function.", module_name)
                return

            result = module.run(self._config)

            # Save result to disk
            saved_path = save_result(result, self._config)
            status = result.get("status", "unknown")

            # These log calls go through _QueueHandler into the UI queue
            logger.info(
                "%s finished — status: %s | saved: %s",
                module_name, status, os.path.basename(saved_path),
            )

            if result.get("errors"):
                for err in result["errors"]:
                    logger.warning("  Error: %s", err)

        except Exception as exc:
            logger.error("Module '%s' crashed: %s", module_name, exc)

        finally:
            # Always re-enable the UI, even if the module crashed.
            # schedule_call() is not in Tkinter — use root.after(0, ...) instead.
            # after(0) queues the call to run on the main thread at the next idle.
            self._root.after(0, self._on_scan_done, module_name)

    def _on_scan_done(self, module_name: str) -> None:
        """
        Called on the main thread after a scan thread finishes.

        Re-enables all buttons and updates the status bar.

        Args:
            module_name: Which module just finished.
        """
        self._scan_running = False
        self._set_buttons_state(tk.NORMAL)
        self._status_var.set("Ready")
        timestamp = datetime.now().strftime("%H:%M:%S")
        self._last_scan_var.set(f"{module_name}  {timestamp}")
        self._log(f"{module_name} complete — ready for next scan.", "SUCCESS")

    def _on_dashboard_click(self) -> None:
        """
        Start the Flask dashboard in a background thread.

        Because dashboard.run() blocks on app.run(), we launch it in a
        daemon thread. The dashboard stays running until the window closes
        (daemon threads die with the main thread automatically).

        We prevent launching a second dashboard if one is already running.
        """
        if self._dashboard_thread and self._dashboard_thread.is_alive():
            port = self._config["dashboard"]["port"]
            self._log(
                f"Dashboard is already running — reopening http://localhost:{port}...",
                "WARNING",
            )
            webbrowser.open(f"http://localhost:{port}")
            return

        self._log("Starting Flask dashboard...", "SYSTEM")
        port = self._config["dashboard"]["port"]

        def _run_dashboard():
            try:
                from modules.dashboard import run as dashboard_run
                dashboard_run(self._config)
            except Exception as exc:
                logger.error("Dashboard error: %s", exc)

        self._dashboard_thread = threading.Thread(target=_run_dashboard, daemon=True)
        self._dashboard_thread.start()

        self._log(
            f"Dashboard running — opening http://localhost:{port} in your browser...",
            "SUCCESS",
        )

        # Open the browser after a short delay to let Flask finish binding to the port.
        # 1500 ms is enough for Flask to start on any machine; root.after() keeps this
        # on the main thread so there's no threading issue with webbrowser.
        self._root.after(1500, lambda: webbrowser.open(f"http://localhost:{port}"))

    def _on_generate_report(self) -> None:
        """
        Generate an HTML audit report from all current result files and
        open it in the default browser.

        Runs in a thread because generate_report() reads and renders many
        files — we don't want to freeze the UI during that.
        """
        self._log("Generating HTML audit report...", "SYSTEM")

        def _run():
            try:
                from modules.dashboard import _load_results, _get_results_dir

                results_dir = _get_results_dir(self._config)
                results = _load_results(results_dir)

                if not results:
                    logger.warning("No result files found — run some scans first.")
                    return

                report_path = generate_report(results, self._config)
                logger.info("Report saved: %s", report_path)

                # Open the report in the system's default browser.
                # webbrowser.open() works on the Pi (Chromium) and on Kali (Firefox).
                webbrowser.open(f"file://{report_path}")
                logger.info("Report opened in browser.")

            except Exception as exc:
                logger.error("Report generation failed: %s", exc)

        threading.Thread(target=_run, daemon=True).start()

    def _on_quit(self) -> None:
        """Close the window cleanly. Daemon threads are killed automatically."""
        logger.info("CyberDeck GUI closed by user.")
        self._root.destroy()

    # ------------------------------------------------------------------
    # Utility
    # ------------------------------------------------------------------

    def _set_buttons_state(self, state: str) -> None:
        """
        Enable or disable all module scan buttons.

        Called with tk.DISABLED when a scan starts, and tk.NORMAL when it ends.
        This prevents the user from launching two scans simultaneously.

        Args:
            state: tk.NORMAL or tk.DISABLED
        """
        for btn in self._module_buttons:
            btn.configure(state=state)

    # ------------------------------------------------------------------
    # Entry point
    # ------------------------------------------------------------------

    def run(self) -> None:
        """
        Start the Tkinter event loop. Blocks until the window is closed.

        This must be called from the main thread. Everything else (scans,
        dashboard, report generation) runs in daemon threads.
        """
        logger.info("CyberDeck GUI started")
        self._root.mainloop()
