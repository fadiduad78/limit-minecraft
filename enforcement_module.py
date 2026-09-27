"""
FocusGuard - Enforcement Module (enforcement_module.py)
-------------------------------------------------------
Subscribes to ProcessMonitor events to issue progressive notifications (10m,
5m, 1m), executes process tree force-kills upon time expiration or lockout
violation, and guards a post-termination cooldown window to suppress instant relaunch.
"""

import sys
import os
import time
import subprocess
from typing import Dict, Set, Optional, Callable

import psutil
from config_manager import ConfigManager, get_config_manager
from auth_module import AuthModule, get_auth_module
from logger_module import LoggerModule, get_logger
from ui_module import UIModule, get_ui_module
from process_monitor import ProcessMonitor, get_process_monitor


class EnforcementModule:
    """
    Handles process termination, warnings, and anti-relaunch cooldowns.
    
    Attributes:
        config_mgr (ConfigManager): Configuration manager reference.
        auth_mod (AuthModule): Passcode verification reference.
        logger (LoggerModule): Audit logger reference.
        ui_mod (UIModule): Graphical overlay manager reference.
        _cooldown_targets (dict): Mapping of app_name -> expiry timestamp.
    """

    def __init__(self, config_mgr: Optional[ConfigManager] = None,
                 auth_mod: Optional[AuthModule] = None,
                 logger: Optional[LoggerModule] = None,
                 ui_mod: Optional[UIModule] = None):
        """
        Initialize EnforcementModule with subsystem references.
        """
        self.config_mgr = config_mgr or get_config_manager()
        self.auth_mod = auth_mod or get_auth_module(self.config_mgr)
        self.logger = logger or get_logger()
        self.ui_mod = ui_mod or get_ui_module(self.config_mgr, self.auth_mod, self.logger)

        # Map of lowercase app executable -> epoch timestamp until which relaunch is forbidden
        self._cooldown_targets: Dict[str, float] = {}

    def attach_monitor(self, monitor: ProcessMonitor) -> None:
        """
        Subscribe enforcement handlers to the monitor event bus.
        
        Args:
            monitor (ProcessMonitor): The running process monitor.
        """
        monitor.subscribe("app_should_warn", self.handle_warning)
        monitor.subscribe("app_should_terminate", self.handle_termination_request)
        monitor.subscribe("app_started", self.handle_app_started)

    def handle_warning(self, app_name: str, remaining_seconds: int, warn_minutes: int) -> None:
        """
        Deliver non-blocking warning overlay at 10, 5, and 1 minute marks.
        
        Args:
            app_name (str): Monitored executable.
            remaining_seconds (int): Seconds remaining.
            warn_minutes (int): Minutes mark (10, 5, or 1).
        """
        print(f"[Enforcement] WARNING: {app_name} has {warn_minutes}m remaining ({remaining_seconds}s).")
        self.ui_mod.show_warning_toast(app_name, remaining_seconds, warn_minutes)

    def handle_termination_request(self, app_name: str, pid: int, reason: str) -> None:
        """
        Execute process tree termination and trigger lockout lock screen.
        
        Args:
            app_name (str): Monitored executable.
            pid (int): Target process ID to kill.
            reason (str): Cause of kill ('TIME_EXHAUSTED' or 'SCHEDULE_LOCKOUT').
        """
        app_key = app_name.lower()
        print(f"[Enforcement] TERMINATION TRIGGERED for {app_name} (PID: {pid}). Reason: {reason}")

        # 1. Kill the process and any child processes spawned by it
        self.force_kill_process_tree(pid, app_name, reason)

        # 2. Register cooldown window to prevent immediate relaunch
        cooldown_sec = self.config_mgr.config.get("cooldown_window_seconds", 300)
        self._cooldown_targets[app_key] = time.time() + cooldown_sec

        # 3. Present modal lock screen
        self.ui_mod.show_lockout_screen(
            app_name=app_name,
            reason=reason,
            on_time_added=lambda: self.clear_cooldown(app_key)
        )

    def handle_app_started(self, app_name: str, pid: int) -> None:
        """
        Inspect newly launched application. If in cooldown or zero time remaining, kill instantly.
        
        Args:
            app_name (str): Monitored executable name.
            pid (int): Newly launched PID.
        """
        app_key = app_name.lower()

        # Check schedule lockout
        if not self.config_mgr.is_within_allowed_schedule():
            self.logger.log_event("COOLDOWN_BLOCK", app_name, f"Relaunch blocked: Outside allowed schedule. Killing PID {pid}.")
            self.force_kill_process_tree(pid, app_name, "SCHEDULE_LOCKOUT_RELAUNCH")
            self.ui_mod.show_lockout_screen(app_name, reason="SCHEDULE_LOCKOUT")
            return

        # Check remaining time today
        rem_sec = self.config_mgr.get_remaining_seconds(app_key)
        if rem_sec <= 0:
            self.logger.log_event("COOLDOWN_BLOCK", app_name, f"Relaunch blocked: 0s remaining today. Killing PID {pid}.")
            self.force_kill_process_tree(pid, app_name, "TIME_EXHAUSTED_RELAUNCH")
            self.ui_mod.show_lockout_screen(app_name, reason="TIME_EXHAUSTED",
                                            on_time_added=lambda: self.clear_cooldown(app_key))
            return

        # Check active cooldown window
        cooldown_expiry = self._cooldown_targets.get(app_key, 0.0)
        if time.time() < cooldown_expiry:
            secs_left = int(cooldown_expiry - time.time())
            self.logger.log_event("COOLDOWN_BLOCK", app_name, f"Relaunch blocked: Cooldown active ({secs_left}s remaining). Killing PID {pid}.")
            self.force_kill_process_tree(pid, app_name, f"COOLDOWN_ACTIVE_{secs_left}s")
            self.ui_mod.show_lockout_screen(app_name, reason="TIME_EXHAUSTED",
                                            on_time_added=lambda: self.clear_cooldown(app_key))

    def force_kill_process_tree(self, pid: int, app_name: str = "", reason: str = "") -> bool:
        """
        Force-terminate a process and all its spawned descendants (process tree).
        
        Args:
            pid (int): Target process ID.
            app_name (str, optional): Executable name for audit logging.
            reason (str, optional): Explanatory reason for termination.
            
        Returns:
            bool: True if process was found and killed, False if already exited or failed.
        """
        if pid <= 0:
            return False

        self.logger.log_termination(app_name or f"PID-{pid}", pid, reason)

        # 1. On Windows, taskkill /F /T kills entire process tree cleanly
        if sys.platform.startswith("win"):
            try:
                subprocess.run(
                    ["taskkill", "/F", "/T", "/PID", str(pid)],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    timeout=5
                )
            except Exception:
                pass

        # 2. Use psutil as robust primary or fallback mechanism
        try:
            parent = psutil.Process(pid)
            children = parent.children(recursive=True)
            for child in children:
                try:
                    child.kill()
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass
            parent.kill()
            return True
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            return False
        except Exception as e:
            print(f"[Enforcement] Error killing PID {pid}: {e}")
            return False

    def is_in_cooldown(self, app_name: str) -> bool:
        """
        Check if an application is currently within its post-termination cooldown.
        
        Args:
            app_name (str): Process executable name.
            
        Returns:
            bool: True if cooldown is still in effect.
        """
        app_key = app_name.lower()
        expiry = self._cooldown_targets.get(app_key, 0.0)
        return time.time() < expiry

    def clear_cooldown(self, app_name: str) -> None:
        """
        Remove cooldown restriction for an app (e.g. after authorized time addition).
        
        Args:
            app_name (str): Process executable name.
        """
        app_key = app_name.lower()
        if app_key in self._cooldown_targets:
            del self._cooldown_targets[app_key]
            self.logger.log_event("COOLDOWN_LIFTED", app_name, "Cooldown restriction cleared by authorized action.")


# Singleton instance
_global_enforcement: Optional[EnforcementModule] = None


def get_enforcement_module(config_mgr: Optional[ConfigManager] = None,
                           auth_mod: Optional[AuthModule] = None,
                           logger: Optional[LoggerModule] = None,
                           ui_mod: Optional[UIModule] = None) -> EnforcementModule:
    """Get or create singleton instance of EnforcementModule."""
    global _global_enforcement
    if _global_enforcement is None:
        _global_enforcement = EnforcementModule(config_mgr, auth_mod, logger, ui_mod)
    return _global_enforcement
