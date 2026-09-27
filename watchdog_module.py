"""
FocusGuard - Watchdog Resilience Module (watchdog_module.py)
-----------------------------------------------------------
Implements a mutual watchdog pattern between the primary FocusGuard service
and a secondary monitor process. If a user terminates one process via Task
Manager or taskkill, the surviving peer immediately relaunches it.
Termination is permitted only via an authenticated shutdown token.
"""

import os
import sys
import time
import subprocess
from typing import Optional

import psutil
from config_manager import ConfigManager, get_config_manager
from auth_module import AuthModule, get_auth_module
from logger_module import LoggerModule, get_logger

MAIN_PID_FILE = "focusguard_main.pid"
WATCHDOG_PID_FILE = "focusguard_watchdog.pid"
SHUTDOWN_TOKEN_FILE = "focusguard_shutdown.token"


class WatchdogManager:
    """
    Supervises the companion process and relaunches it if terminated without authorization.
    """

    def __init__(self, check_interval_seconds: float = 2.0):
        """
        Args:
            check_interval_seconds (float): Polling frequency for peer health checks.
        """
        self.interval = check_interval_seconds
        self.config_mgr = get_config_manager()
        self.auth_mod = get_auth_module(self.config_mgr)
        self.logger = get_logger()

    @staticmethod
    def create_shutdown_token(passcode: str) -> bool:
        """
        Create authorized shutdown token file after verifying passcode.
        
        Args:
            passcode (str): Parent/admin passcode.
            
        Returns:
            bool: True if authorized and token created.
        """
        auth = get_auth_module()
        if not auth.verify_passcode(passcode):
            return False

        try:
            with open(SHUTDOWN_TOKEN_FILE, "w", encoding="utf-8") as f:
                f.write(f"AUTHORIZED_SHUTDOWN_{int(time.time())}")
            return True
        except Exception:
            return False

    @staticmethod
    def is_authorized_shutdown() -> bool:
        """
        Check if an authorized shutdown token exists and is recent (< 60s).
        
        Returns:
            bool: True if authorized shutdown is in progress.
        """
        if not os.path.exists(SHUTDOWN_TOKEN_FILE):
            return False
        try:
            mtime = os.path.getmtime(SHUTDOWN_TOKEN_FILE)
            if time.time() - mtime < 60:
                return True
            # Expired token: clean up
            os.remove(SHUTDOWN_TOKEN_FILE)
            return False
        except Exception:
            return False

    @staticmethod
    def consume_shutdown_token() -> None:
        """Clean up shutdown token after processes exit."""
        if os.path.exists(SHUTDOWN_TOKEN_FILE):
            try:
                os.remove(SHUTDOWN_TOKEN_FILE)
            except Exception:
                pass

    def run_as_watchdog(self, peer_pid: Optional[int] = None) -> None:
        """
        Run in worker mode watching the main FocusGuard process.
        
        Args:
            peer_pid (int, optional): Process ID of main service.
        """
        my_pid = os.getpid()
        with open(WATCHDOG_PID_FILE, "w", encoding="utf-8") as f:
            f.write(str(my_pid))

        self.logger.log_event("WATCHDOG", "START", f"Watchdog process active (PID {my_pid}). Watching Main PID {peer_pid}.")

        while True:
            try:
                # 1. Check if authorized shutdown requested
                if self.is_authorized_shutdown():
                    self.logger.log_event("WATCHDOG", "EXIT", "Authorized shutdown detected. Watchdog terminating cleanly.")
                    break

                # 2. Check if peer PID is alive
                target_pid = peer_pid
                if not target_pid and os.path.exists(MAIN_PID_FILE):
                    try:
                        with open(MAIN_PID_FILE, "r") as f:
                            target_pid = int(f.read().strip())
                    except Exception:
                        pass

                peer_alive = False
                if target_pid:
                    try:
                        p = psutil.Process(target_pid)
                        peer_alive = p.is_running() and p.status() != psutil.STATUS_ZOMBIE
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        peer_alive = False

                if not peer_alive:
                    if self.is_authorized_shutdown():
                        break

                    self.logger.log_event(
                        "WATCHDOG_ALERT",
                        "SECURITY",
                        f"MAIN FOCUSGUARD PROCESS (PID {target_pid}) WAS TERMINATED UNEXPECTEDLY! Relaunching immediately..."
                    )
                    # Resurrect the main service
                    main_script = os.path.join(os.path.dirname(os.path.abspath(__file__)), "main.py")
                    new_proc = subprocess.Popen([sys.executable, main_script, "--supervised"])
                    peer_pid = new_proc.pid

            except Exception as e:
                print(f"[Watchdog] Supervision exception: {e}")

            time.sleep(self.interval)

        # Cleanup
        if os.path.exists(WATCHDOG_PID_FILE):
            try:
                os.remove(WATCHDOG_PID_FILE)
            except Exception:
                pass

    def spawn_watchdog_process(self, current_main_pid: int) -> subprocess.Popen:
        """
        Spawn secondary watchdog process from the main service.
        
        Args:
            current_main_pid (int): Main service PID to supervise.
            
        Returns:
            subprocess.Popen: Subprocess handle of spawned watchdog.
        """
        main_script = os.path.join(os.path.dirname(os.path.abspath(__file__)), "main.py")
        proc = subprocess.Popen(
            [sys.executable, main_script, "--watchdog", "--peer-pid", str(current_main_pid)],
            creationflags=subprocess.CREATE_NO_WINDOW if sys.platform.startswith("win") else 0
        )
        return proc


# Singleton instance
_global_watchdog: Optional[WatchdogManager] = None


def get_watchdog_manager() -> WatchdogManager:
    """Get or create singleton instance of WatchdogManager."""
    global _global_watchdog
    if _global_watchdog is None:
        _global_watchdog = WatchdogManager()
    return _global_watchdog
