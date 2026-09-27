"""
FocusGuard - Main Application Entrypoint (main.py)
--------------------------------------------------
Orchestrates application startup, command-line arguments, service installation,
and the inter-module event pipeline:
  [AuthModule] gates privileged actions in -> [ConfigManager] & [ServiceRunner]
  [ProcessMonitor] -> [EnforcementModule] -> [UIModule]
  [WatchdogManager] <== (Mutual Supervision) ==> [Main Process]
"""

import sys
import os
import time
import argparse
import getpass
import signal
from typing import Optional

# Core Architecture Modules
from config_manager import ConfigManager, get_config_manager
from auth_module import AuthModule, get_auth_module
from logger_module import LoggerModule, get_logger
from process_monitor import ProcessMonitor, get_process_monitor, AppState
from enforcement_module import EnforcementModule, get_enforcement_module
from ui_module import UIModule, get_ui_module
from watchdog_module import (
    WatchdogManager, get_watchdog_manager,
    MAIN_PID_FILE, WATCHDOG_PID_FILE
)
from service_runner import ServiceRunner, get_service_runner


def run_standalone_mode(supervised: bool = False) -> None:
    """
    Run FocusGuard in testing or foreground enforcement mode.
    
    Wire communication between modules:
      1. process_monitor detects process states, idle time, and input activity.
      2. enforcement_module subscribes to monitor events (warnings, terminations).
      3. enforcement_module triggers ui_module overlays and handles process kills.
      4. auth_module gates all time additions, settings edits, and shutdowns.
      
    Args:
        supervised (bool): If True, spawns and mutually supervises companion watchdog.
    """
    config = get_config_manager()
    auth = get_auth_module(config)
    logger = get_logger()
    ui = get_ui_module(config, auth, logger)
    enforcement = get_enforcement_module(config, auth, logger, ui)
    monitor = get_process_monitor(config)

    # Record main process PID
    my_pid = os.getpid()
    with open(MAIN_PID_FILE, "w", encoding="utf-8") as f:
        f.write(str(my_pid))

    logger.log_event("SYSTEM", "STARTUP", f"FocusGuard main process active (PID {my_pid}, Supervised={supervised}).")

    # Wire event pipeline: Monitor -> Enforcement
    enforcement.attach_monitor(monitor)

    # Optional mutual watchdog spawn
    watchdog_subproc = None
    if supervised:
        wd_mgr = get_watchdog_manager()
        watchdog_subproc = wd_mgr.spawn_watchdog_process(my_pid)
        print(f"[FocusGuard] Spawned secondary watchdog process (PID {watchdog_subproc.pid}).")

    # Start active monitoring
    monitor.start()

    print("\n" + "=" * 65)
    print("  FocusGuard — Active Time-Limit Enforcer")
    print("  Status: Active & Monitoring")
    print(f"  Configuration: {len(config.config.get('apps', {}))} app(s) monitored")
    print("  Press Ctrl+C to stop (if standalone) or use --stop with passcode")
    print("=" * 65 + "\n")

    # Handle graceful exit signals
    def signal_handler(sig, frame):
        print("\n[FocusGuard] Shutdown requested...")
        monitor.stop()
        if os.path.exists(MAIN_PID_FILE):
            try:
                os.remove(MAIN_PID_FILE)
            except Exception:
                pass
        sys.exit(0)

    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    try:
        while True:
            # Periodic status console ping
            time.sleep(3)
            # If supervised, verify companion watchdog is healthy
            if supervised and watchdog_subproc:
                if watchdog_subproc.poll() is not None:
                    # Watchdog was killed!
                    if not WatchdogManager.is_authorized_shutdown():
                        logger.log_event("WATCHDOG_ALERT", "SECURITY", "Watchdog companion was terminated! Resurrecting...")
                        watchdog_subproc = get_watchdog_manager().spawn_watchdog_process(my_pid)
    except KeyboardInterrupt:
        signal_handler(None, None)


def print_status() -> None:
    """Print current configuration, limits, and usage status to stdout."""
    config = get_config_manager()
    apps = config.config.get("apps", {})
    sched = config.config.get("lockout_schedule", {})

    print("\n" + "=" * 68)
    print(f"  FocusGuard System Status — {config.config.get('last_reset_date', 'Today')}")
    print("=" * 68)
    print(f"  System Idle Threshold : {config.config.get('idle_threshold_seconds', 60)} seconds")
    print(f"  Anti-Gaming Threshold : {config.config.get('input_event_threshold', 5)} events / 30s")
    print(f"  Cooldown Window       : {config.config.get('cooldown_window_seconds', 300)} seconds")
    sched_status = f"Active ({sched.get('allowed_start')} - {sched.get('allowed_end')})" if sched.get("enabled") else "Disabled"
    print(f"  Lockout Schedule      : {sched_status}")
    print("-" * 68)
    print(f"  {'Executable':<22} | {'Limit':<8} | {'Remaining':<12} | {'Active Today'}")
    print("-" * 68)

    for exe, data in apps.items():
        limit = f"{data.get('daily_limit_minutes', 0)} min"
        rem_m = round(data.get("remaining_seconds_today", 0) / 60.0, 1)
        rem = f"{rem_m} min"
        act_m = round(data.get("total_active_seconds_today", 0) / 60.0, 1)
        act = f"{act_m} min"
        print(f"  {exe:<22} | {limit:<8} | {rem:<12} | {act}")
    print("=" * 68 + "\n")


def main() -> None:
    """Command-line parsing and entrypoint dispatcher."""
    parser = argparse.ArgumentParser(
        description="FocusGuard - Active Desktop Application Time-Limit Enforcer for Windows",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python main.py                  # Run standalone in foreground for testing
  python main.py --install        # Install background service / startup task
  python main.py --uninstall      # Uninstall service (passcode-gated)
  python main.py --stop           # Gracefully stop running service (passcode-gated)
  python main.py --status         # Inspect limits, usage, and remaining times
  python main.py --settings       # Open graphical parent settings dashboard
  python main.py --add-time minecraft.exe 30   # Grant 30 minutes bonus time
        """
    )

    parser.add_argument("--install", action="store_true", help="Install FocusGuard to run at system startup")
    parser.add_argument("--uninstall", action="store_true", help="Uninstall FocusGuard startup service (requires passcode)")
    parser.add_argument("--stop", action="store_true", help="Stop running FocusGuard service (requires passcode)")
    parser.add_argument("--status", action="store_true", help="Show current application limits and usage")
    parser.add_argument("--settings", action="store_true", help="Open graphical settings dashboard")
    parser.add_argument("--supervised", action="store_true", help="Run with companion mutual watchdog supervision")
    parser.add_argument("--watchdog", action="store_true", help="Run in secondary watchdog mode")
    parser.add_argument("--peer-pid", type=int, help="Target peer PID for watchdog process")
    parser.add_argument("--add-time", nargs=2, metavar=("APP", "MINUTES"), help="Grant bonus minutes to an app")
    parser.add_argument("--reset", action="store_true", help="Force reset daily usage budgets (requires passcode)")

    args = parser.parse_args()
    config = get_config_manager()
    auth = get_auth_module(config)
    runner = get_service_runner()

    # 1. Install service
    if args.install:
        success, msg = runner.install()
        print(msg)
        sys.exit(0 if success else 1)

    # 2. Uninstall service
    if args.uninstall:
        passcode = getpass.getpass("Enter Parent Passcode to uninstall FocusGuard: ")
        success, msg = runner.uninstall(passcode)
        print(msg)
        sys.exit(0 if success else 1)

    # 3. Stop service
    if args.stop:
        passcode = getpass.getpass("Enter Parent Passcode to stop FocusGuard: ")
        success, msg = runner.stop(passcode)
        print(msg)
        sys.exit(0 if success else 1)

    # 4. Watchdog worker mode
    if args.watchdog:
        wd = get_watchdog_manager()
        wd.run_as_watchdog(peer_pid=args.peer_pid)
        sys.exit(0)

    # 5. Status inspection
    if args.status:
        print_status()
        sys.exit(0)

    # 6. Open settings GUI
    if args.settings:
        ui = get_ui_module(config, auth)
        ui.show_settings_window()
        # Keep Tk loop active if invoked standalone
        try:
            import tkinter as tk
            if tk._default_root:
                tk._default_root.mainloop()
        except Exception:
            pass
        sys.exit(0)

    # 7. Add time CLI
    if args.add_time:
        app_name, minutes_str = args.add_time
        try:
            minutes = int(minutes_str)
        except ValueError:
            print("Error: Minutes must be an integer.")
            sys.exit(1)

        passcode = getpass.getpass(f"Enter Parent Passcode to grant {minutes}m to {app_name}: ")
        if config.add_time(app_name, minutes, passcode):
            print(f"Success! Granted {minutes} bonus minutes to {app_name}.")
            # Also clear active cooldown in enforcement module if running
            get_enforcement_module().clear_cooldown(app_name)
        else:
            if auth.is_locked_out():
                print(f"Rate limited: Locked out for {auth.get_remaining_lockout_seconds()}s.")
            else:
                print("Access Denied: Invalid passcode.")
            sys.exit(1)
        sys.exit(0)

    # 8. Force reset usage
    if args.reset:
        passcode = getpass.getpass("Enter Parent Passcode to reset daily usage: ")
        if auth.verify_passcode(passcode):
            config.reset_daily_usage(force=True)
            print("Daily usage successfully reset for all applications.")
        else:
            print("Access Denied: Invalid passcode.")
            sys.exit(1)
        sys.exit(0)

    # Default action: run standalone enforcement engine
    run_standalone_mode(supervised=args.supervised)


if __name__ == "__main__":
    main()
