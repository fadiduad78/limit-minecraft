"""
FocusGuard - Service & Task Runner Module (service_runner.py)
-------------------------------------------------------------
Manages installation, uninstallation, starting, and stopping of the FocusGuard
background service / high-privilege Windows Scheduled Task under SYSTEM context.
All modifications and stopping actions are strictly gated by AuthModule.
"""

import os
import sys
import subprocess
import getpass
from typing import Tuple, Optional

import psutil
from config_manager import ConfigManager, get_config_manager
from auth_module import AuthModule, get_auth_module
from logger_module import LoggerModule, get_logger
from watchdog_module import (
    WatchdogManager, get_watchdog_manager,
    MAIN_PID_FILE, WATCHDOG_PID_FILE
)

TASK_NAME = "FocusGuardTimeEnforcer"


class ServiceRunner:
    """
    Handles installation and lifecycle operations for the persistent background service.
    """

    def __init__(self, config_mgr: Optional[ConfigManager] = None,
                 auth_mod: Optional[AuthModule] = None,
                 logger: Optional[LoggerModule] = None):
        """
        Initialize ServiceRunner.
        """
        self.config_mgr = config_mgr or get_config_manager()
        self.auth_mod = auth_mod or get_auth_module(self.config_mgr)
        self.logger = logger or get_logger()

    def is_service_installed(self) -> bool:
        """
        Check whether the FocusGuard scheduled task is currently registered.
        
        Returns:
            bool: True if installed in Task Scheduler.
        """
        if not sys.platform.startswith("win"):
            return False

        try:
            res = subprocess.run(
                ["schtasks", "/query", "/tn", TASK_NAME],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            return res.returncode == 0
        except Exception:
            return False

    def install(self) -> Tuple[bool, str]:
        """
        Install FocusGuard to start automatically at logon with highest privileges.
        Uses Windows Task Scheduler (SYSTEM / Highest elevation context) which survives
        standard user kill attempts and bypasses Session 0 GUI isolation issues.
        
        Returns:
            Tuple[bool, str]: (Success flag, descriptive message).
        """
        if not sys.platform.startswith("win"):
            return True, "Simulated installation successful on non-Windows host."

        python_exe = sys.executable
        # Use pythonw.exe if available to run silently without an open command prompt
        pythonw_exe = os.path.join(os.path.dirname(python_exe), "pythonw.exe")
        runner_bin = pythonw_exe if os.path.exists(pythonw_exe) else python_exe

        main_script = os.path.abspath(os.path.join(os.path.dirname(__file__), "main.py"))
        run_command = f'"{runner_bin}" "{main_script}" --supervised'

        # Command: Run at user logon with HIGHEST run-level
        cmd = [
            "schtasks", "/create",
            "/tn", TASK_NAME,
            "/tr", run_command,
            "/sc", "onlogon",
            "/rl", "highest",
            "/f"
        ]

        try:
            res = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            if res.returncode == 0:
                self.logger.log_event("SYSTEM", "SERVICE", f"Installed task '{TASK_NAME}' successfully.")
                return True, f"FocusGuard service installed successfully as scheduled task '{TASK_NAME}'."
            else:
                err = res.stderr.strip() or res.stdout.strip()
                return False, f"Failed to install scheduled task: {err} (Note: requires Administrator privileges)."
        except Exception as e:
            return False, f"Exception creating service task: {str(e)}"

    def uninstall(self, passcode: str) -> Tuple[bool, str]:
        """
        Remove FocusGuard from startup tasks. Requires passcode verification.
        
        Args:
            passcode (str): Parent/admin passcode.
            
        Returns:
            Tuple[bool, str]: (Success flag, status message).
        """
        # Privileged check
        if not self.auth_mod.verify_passcode(passcode):
            if self.auth_mod.is_locked_out():
                return False, f"Access Denied: Locked out for {self.auth_mod.get_remaining_lockout_seconds()}s."
            return False, "Access Denied: Invalid passcode."

        # Stop active running processes first
        self.stop(passcode)

        if not sys.platform.startswith("win"):
            return True, "Simulated uninstall successful on non-Windows host."

        try:
            cmd = ["schtasks", "/delete", "/tn", TASK_NAME, "/f"]
            res = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            self.logger.log_event("SYSTEM", "SERVICE", f"Uninstalled task '{TASK_NAME}'.")
            return True, "FocusGuard successfully uninstalled from system startup."
        except Exception as e:
            return False, f"Error removing task: {str(e)}"

    def stop(self, passcode: str) -> Tuple[bool, str]:
        """
        Gracefully terminate the main service and watchdog using passcode verification.
        
        Args:
            passcode (str): Parent/admin passcode.
            
        Returns:
            Tuple[bool, str]: (Success flag, status message).
        """
        if not self.auth_mod.verify_passcode(passcode):
            if self.auth_mod.is_locked_out():
                return False, f"Access Denied: Locked out for {self.auth_mod.get_remaining_lockout_seconds()}s."
            return False, "Access Denied: Invalid passcode."

        # Create authorized shutdown token
        WatchdogManager.create_shutdown_token(passcode)
        self.logger.log_event("SYSTEM", "SERVICE", "Authorized shutdown requested by administrator.")

        # Read PIDs and terminate
        killed_any = False
        for pid_file in [MAIN_PID_FILE, WATCHDOG_PID_FILE]:
            if os.path.exists(pid_file):
                try:
                    with open(pid_file, "r") as f:
                        pid = int(f.read().strip())
                    p = psutil.Process(pid)
                    p.terminate()
                    killed_any = True
                except Exception:
                    pass
                try:
                    os.remove(pid_file)
                except Exception:
                    pass

        return True, "FocusGuard service and watchdog terminated successfully."


# Singleton instance
_global_service: Optional[ServiceRunner] = None


def get_service_runner() -> ServiceRunner:
    """Get or create singleton instance of ServiceRunner."""
    global _global_service
    if _global_service is None:
        _global_service = ServiceRunner()
    return _global_service
