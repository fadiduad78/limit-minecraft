"""
FocusGuard - Audit & Usage Logger Module (logger_module.py)
------------------------------------------------------------
Records state transitions, active vs. open application usage, warning events,
force-terminations, and authentication failures. Provides human-readable
and machine-parsable audit logs for parental/administrative inspection.
"""

import os
import sys
import json
import time
import datetime
from typing import Dict, Any, List, Optional


class LoggerModule:
    """
    Manages structured file logging and usage metric aggregation.
    
    Attributes:
        log_file (str): Path to primary activity log file.
        history_file (str): Path to persistent daily summary JSON file.
    """

    def __init__(self, log_file: str = "focusguard_activity.log", history_file: str = "focusguard_history.json"):
        """
        Initialize logger with log file paths.
        
        Args:
            log_file (str): Path for human-readable audit text log.
            history_file (str): Path for daily aggregated analytics JSON.
        """
        self.log_file = os.path.abspath(log_file)
        self.history_file = os.path.abspath(history_file)

    def log_event(self, category: str, app_name: str, message: str, metadata: Optional[Dict[str, Any]] = None) -> None:
        """
        Append a timestamped entry to the activity log.
        
        Args:
            category (str): Event category (e.g. 'STATE_CHANGE', 'WARNING', 'KILL', 'AUTH').
            app_name (str): Monitored app or 'SYSTEM'.
            message (str): Explanatory log message.
            metadata (dict, optional): Additional key-value pairs to log.
        """
        now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        meta_str = f" | {json.dumps(metadata)}" if metadata else ""
        line = f"[{now}] [{category:<12}] [{app_name:<16}] {message}{meta_str}\n"

        try:
            with open(self.log_file, "a", encoding="utf-8") as f:
                f.write(line)
        except Exception as e:
            print(f"[LoggerModule] File write error: {e}", file=sys.stderr)

    def log_state_transition(self, app_name: str, old_state: str, new_state: str, details: str = "") -> None:
        """
        Log an application state change (e.g. BACKGROUND -> ACTIVE).
        
        Args:
            app_name (str): Monitored process name.
            old_state (str): Previous state.
            new_state (str): Current state.
            details (str): Additional context (idle reason, input rate).
        """
        msg = f"Transition: {old_state} -> {new_state}"
        if details:
            msg += f" ({details})"
        self.log_event("STATE_CHANGE", app_name, msg)

    def log_usage_snapshot(self, app_name: str, active_seconds: float, open_seconds: float) -> None:
        """
        Log usage comparison e.g. 'Minecraft open 3h, but only 1h45m active'.
        
        Args:
            app_name (str): Monitored process name.
            active_seconds (float): Total active seconds today.
            open_seconds (float): Total open seconds today.
        """
        def format_duration(seconds: float) -> str:
            total_sec = int(seconds)
            h = total_sec // 3600
            m = (total_sec % 3600) // 60
            s = total_sec % 60
            if h > 0:
                return f"{h}h {m}m"
            elif m > 0:
                return f"{m}m {s}s"
            else:
                return f"{s}s"

        active_str = format_duration(active_seconds)
        open_str = format_duration(open_seconds)
        msg = f"Usage summary: Open {open_str}, but only {active_str} active time recorded."
        self.log_event("USAGE_SUMMARY", app_name, msg, {
            "active_seconds": active_seconds,
            "open_seconds": open_seconds,
            "efficiency_percent": round((active_seconds / max(1.0, open_seconds)) * 100, 1)
        })

    def log_warning(self, app_name: str, remaining_seconds: int, warn_minutes: int) -> None:
        """
        Log notification/warning delivered to user.
        
        Args:
            app_name (str): Monitored process name.
            remaining_seconds (int): Seconds left today.
            warn_minutes (int): Threshold minute mark (e.g. 10, 5, 1).
        """
        self.log_event("WARN_ALERT", app_name, f"Warning displayed to user: {warn_minutes} minute(s) remaining.", {
            "remaining_seconds": remaining_seconds
        })

    def log_termination(self, app_name: str, pid: int, reason: str) -> None:
        """
        Log forceful process kill upon time exhaustion or lockout rule violation.
        
        Args:
            app_name (str): Monitored process name.
            pid (int): Process ID terminated.
            reason (str): Cause of kill (e.g. 'TIME_EXHAUSTED', 'SCHEDULE_LOCKOUT').
        """
        self.log_event("TERMINATE", app_name, f"Process (PID {pid}) force-killed. Reason: {reason}")

    def log_auth_attempt(self, success: bool, action: str, details: str = "") -> None:
        """
        Log authentication outcomes for security audit.
        
        Args:
            success (bool): Whether verification passed.
            action (str): Privileged action attempted.
            details (str): Additional context or error details.
        """
        cat = "AUTH_SUCCESS" if success else "AUTH_FAIL"
        self.log_event(cat, "SECURITY", f"Action: {action}. Details: {details}")

    def get_recent_logs(self, max_lines: int = 50) -> List[str]:
        """
        Read the most recent entries from the activity log.
        
        Args:
            max_lines (int): Max number of trailing lines to return.
            
        Returns:
            List[str]: Log lines in chronological order.
        """
        if not os.path.exists(self.log_file):
            return ["No activity logged yet."]
        try:
            with open(self.log_file, "r", encoding="utf-8") as f:
                lines = f.readlines()
                return [line.strip() for line in lines[-max_lines:]]
        except Exception as e:
            return [f"Error reading log file: {e}"]


# Singleton instance
_global_logger: Optional[LoggerModule] = None


def get_logger() -> LoggerModule:
    """
    Get or create singleton instance of LoggerModule.
    """
    global _global_logger
    if _global_logger is None:
        _global_logger = LoggerModule()
    return _global_logger
