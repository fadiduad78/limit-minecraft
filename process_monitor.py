"""
FocusGuard - Active Process & Input Monitor (process_monitor.py)
---------------------------------------------------------------
Tracks running processes, foreground window state, system-wide idle time,
and rolling input activity to ensure only genuinely active usage counts
against the daily time allowance. Prevents auto-clicker / idle bypass gaming.
"""

import sys
import os
import time
import enum
import threading
from collections import deque
from typing import Dict, List, Set, Optional, Callable, Any

import psutil
from config_manager import ConfigManager, get_config_manager
from logger_module import LoggerModule, get_logger
import win32_compat


class AppState(enum.Enum):
    """
    Application operational states for time budgeting.
    """
    NOT_RUNNING = "NOT_RUNNING"
    RUNNING_BACKGROUND = "RUNNING_BACKGROUND"
    RUNNING_IDLE = "RUNNING_IDLE"
    RUNNING_ACTIVE = "RUNNING_ACTIVE"


class InputActivityTracker:
    """
    Maintains a rolling window of physical user input events (clicks, keys, mouse motion)
    to differentiate real gameplay from idle state or periodic auto-clicker nudges.
    """

    def __init__(self, window_seconds: float = 30.0, min_event_threshold: int = 5):
        """
        Args:
            window_seconds (float): Rolling time window in seconds.
            min_event_threshold (int): Minimum real input events required within window.
        """
        self.window_seconds = window_seconds
        self.min_event_threshold = min_event_threshold
        self._events: deque = deque()
        self._lock = threading.Lock()
        self._last_tick = 0
        self._last_cursor = (0, 0)
        self._running = False
        self._thread: Optional[threading.Thread] = None

    def start(self) -> None:
        """Start the background input sampling loop."""
        if self._running:
            return
        self._running = True
        self._thread = threading.Thread(target=self._sample_loop, daemon=True, name="FG-InputSampler")
        self._thread.start()

    def stop(self) -> None:
        """Stop the background sampling loop."""
        self._running = False
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=1.0)

    def record_event(self) -> None:
        """Manually or programmatically record an input event timestamp."""
        now = time.time()
        with self._lock:
            self._events.append(now)
            self._prune(now)

    def _prune(self, current_time: float) -> None:
        cutoff = current_time - self.window_seconds
        while self._events and self._events[0] < cutoff:
            self._events.popleft()

    def get_event_count(self) -> int:
        """
        Get count of input events within the rolling window.
        
        Returns:
            int: Number of detected input events in the active window.
        """
        now = time.time()
        with self._lock:
            self._prune(now)
            return len(self._events)

    def is_active_input_rate(self) -> bool:
        """
        Check if input event frequency meets the minimum activity threshold.
        
        Returns:
            bool: True if input count >= threshold.
        """
        return self.get_event_count() >= self.min_event_threshold

    def _sample_loop(self) -> None:
        """Background loop sampling Windows input subsystem at high frequency."""
        while self._running:
            try:
                # 1. Sample cursor position delta
                current_cursor = win32_compat.get_cursor_position()
                dx = abs(current_cursor[0] - self._last_cursor[0])
                dy = abs(current_cursor[1] - self._last_cursor[1])
                # Only count non-trivial mouse movements (ignore optical jitter)
                if dx > 4 or dy > 4:
                    self.record_event()
                    self._last_cursor = current_cursor

                # 2. Check if GetLastInputInfo tick has progressed
                idle_sec = win32_compat.get_system_idle_seconds()
                # If idle seconds is very close to 0, an input event just occurred
                if idle_sec < 0.2:
                    self.record_event()

            except Exception:
                pass
            time.sleep(0.2)


class ProcessMonitor:
    """
    Monitors target processes, checks foreground focus, evaluates idle time,
    maintains per-application state machines, and dispatches lifecycle events.
    """

    def __init__(self, config_mgr: Optional[ConfigManager] = None, logger: Optional[LoggerModule] = None):
        """
        Args:
            config_mgr (ConfigManager, optional): Configuration manager reference.
            logger (LoggerModule, optional): Activity logger reference.
        """
        self.config_mgr = config_mgr or get_config_manager()
        self.logger = logger or get_logger()

        # State tracking per monitored app executable:
        # app_key -> {"state": AppState, "pids": Set[int], "last_poll": float, "last_active_time": float}
        self.app_states: Dict[str, Dict[str, Any]] = {}
        self.input_tracker = InputActivityTracker(
            window_seconds=self.config_mgr.config.get("input_window_seconds", 30),
            min_event_threshold=self.config_mgr.config.get("input_event_threshold", 5)
        )

        # Event callbacks: event_name -> list of callable listeners
        self._listeners: Dict[str, List[Callable]] = {
            "app_started": [],
            "app_state_changed": [],
            "app_active": [],
            "app_should_warn": [],
            "app_should_terminate": []
        }

        self._running = False
        self._thread: Optional[threading.Thread] = None
        self._lock = threading.Lock()

        # Cache of processes to minimize CPU consumption during process enumeration
        self._cached_pids: Dict[int, str] = {}
        self._last_pid_scan_time = 0.0

    def subscribe(self, event_name: str, callback: Callable) -> None:
        """
        Subscribe a callback handler to a monitor lifecycle event.
        
        Args:
            event_name (str): One of 'app_started', 'app_state_changed',
                              'app_active', 'app_should_warn', 'app_should_terminate'.
            callback (Callable): Callback receiving event arguments.
        """
        if event_name in self._listeners:
            self._listeners[event_name].append(callback)

    def _emit(self, event_name: str, *args, **kwargs) -> None:
        """Dispatch event to all subscribed listeners safely."""
        for callback in self._listeners.get(event_name, []):
            try:
                callback(*args, **kwargs)
            except Exception as e:
                print(f"[ProcessMonitor] Listener exception in {event_name}: {e}")

    def start(self) -> None:
        """Start the continuous process monitoring and input tracking loop."""
        if self._running:
            return
        self._running = True
        self.input_tracker.start()
        self._thread = threading.Thread(target=self._monitor_loop, daemon=True, name="FG-ProcessMonitor")
        self._thread.start()
        self.logger.log_event("SYSTEM", "MONITOR", "ProcessMonitor engine started successfully.")

    def stop(self) -> None:
        """Stop the monitoring thread and input tracker."""
        self._running = False
        self.input_tracker.stop()
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=2.0)
        self.logger.log_event("SYSTEM", "MONITOR", "ProcessMonitor engine stopped.")

    def poll_once(self) -> Dict[str, Dict[str, Any]]:
        """
        Execute a single polling cycle across all monitored applications.
        
        Returns:
            dict: Current status dictionary for each monitored executable.
        """
        with self._lock:
            # 1. Update config parameters if updated dynamically
            self.input_tracker.window_seconds = self.config_mgr.config.get("input_window_seconds", 30)
            self.input_tracker.min_event_threshold = self.config_mgr.config.get("input_event_threshold", 5)
            idle_threshold = self.config_mgr.config.get("idle_threshold_seconds", 60)

            # 2. Get list of monitored app executables
            monitored_apps = self.config_mgr.config.get("apps", {})
            if not monitored_apps:
                return {}

            # 3. Discover running processes
            running_pids_by_app: Dict[str, Set[int]] = {app.lower(): set() for app in monitored_apps.keys()}
            all_running_pids: Dict[int, str] = {}

            now = time.time()
            for proc in psutil.process_iter(['pid', 'name']):
                try:
                    pname = (proc.info['name'] or "").lower()
                    pid = proc.info['pid']
                    all_running_pids[pid] = pname
                    if pname in running_pids_by_app:
                        running_pids_by_app[pname].add(pid)
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue

            # 4. Check active foreground window
            foreground_pid = win32_compat.get_foreground_window_pid()
            system_idle_seconds = win32_compat.get_system_idle_seconds()
            input_events_count = self.input_tracker.get_event_count()
            has_sufficient_input = self.input_tracker.is_active_input_rate()

            # Schedule lockout check
            within_schedule = self.config_mgr.is_within_allowed_schedule()

            poll_results: Dict[str, Dict[str, Any]] = {}

            # 5. Evaluate state machine for each monitored app
            for app_name, app_config in monitored_apps.items():
                app_key = app_name.lower()
                pids = running_pids_by_app.get(app_key, set())
                prev_info = self.app_states.setdefault(app_key, {
                    "state": AppState.NOT_RUNNING,
                    "pids": set(),
                    "last_poll": now,
                    "warned_thresholds": set()  # Tracks warnings sent today
                })

                old_state = prev_info["state"]
                elapsed_since_poll = max(0.0, now - prev_info.get("last_poll", now))
                prev_info["last_poll"] = now

                # State determination
                new_state = AppState.NOT_RUNNING
                state_reason = ""

                if not pids:
                    new_state = AppState.NOT_RUNNING
                    state_reason = "Process not found in running process list"
                else:
                    # Application is running. Is any PID of this app in the foreground?
                    is_foreground = (foreground_pid is not None and foreground_pid in pids)

                    if not is_foreground:
                        new_state = AppState.RUNNING_BACKGROUND
                        state_reason = "Running in background or minimized"
                    else:
                        # Foreground window belongs to this app. Now check idle & anti-gaming
                        is_system_idle = (system_idle_seconds >= idle_threshold)
                        if is_system_idle:
                            new_state = AppState.RUNNING_IDLE
                            state_reason = f"System idle for {int(system_idle_seconds)}s (threshold: {idle_threshold}s)"
                        elif not has_sufficient_input:
                            new_state = AppState.RUNNING_IDLE
                            state_reason = f"Low input activity ({input_events_count}/{self.input_tracker.min_event_threshold} events in 30s)"
                        else:
                            new_state = AppState.RUNNING_ACTIVE
                            state_reason = "Window focused and real input activity verified"

                # Check if app just launched
                if old_state == AppState.NOT_RUNNING and new_state != AppState.NOT_RUNNING:
                    first_pid = next(iter(pids)) if pids else 0
                    self.logger.log_event("APP_LAUNCH", app_name, f"Launched with PID(s): {list(pids)}")
                    self._emit("app_started", app_name, first_pid)

                # State transition handling
                if old_state != new_state:
                    self.logger.log_state_transition(app_name, old_state.value, new_state.value, state_reason)
                    self._emit("app_state_changed", app_name, old_state, new_state, state_reason)

                prev_info["state"] = new_state
                prev_info["pids"] = pids

                # Time accumulation: ONLY RUNNING_ACTIVE decrements remaining budget!
                active_delta = elapsed_since_poll if new_state == AppState.RUNNING_ACTIVE else 0.0
                open_delta = elapsed_since_poll if new_state != AppState.NOT_RUNNING else 0.0

                remaining_seconds = app_config.get("remaining_seconds_today", 0)

                if open_delta > 0 or active_delta > 0:
                    remaining_seconds = self.config_mgr.update_usage(app_name, active_delta, open_delta)

                if active_delta > 0:
                    self._emit("app_active", app_name, active_delta, remaining_seconds)

                # Enforcement checks:
                # A. Lockout schedule violation (e.g., trying to play after bedtime or during study hours)
                if pids and not within_schedule:
                    primary_pid = next(iter(pids))
                    self._emit("app_should_terminate", app_name, primary_pid, "SCHEDULE_LOCKOUT")

                # B. Daily time limit exhausted
                elif pids and remaining_seconds <= 0:
                    primary_pid = next(iter(pids))
                    self._emit("app_should_terminate", app_name, primary_pid, "TIME_EXHAUSTED")

                # C. Warning alerts (at 10 min, 5 min, 1 min marks)
                elif pids and remaining_seconds > 0:
                    warn_set = prev_info["warned_thresholds"]
                    rem_min = remaining_seconds / 60.0
                    for mark in [10, 5, 1]:
                        if rem_min <= mark and mark not in warn_set:
                            warn_set.add(mark)
                            self._emit("app_should_warn", app_name, remaining_seconds, mark)

                poll_results[app_name] = {
                    "state": new_state.value,
                    "reason": state_reason,
                    "pids": list(pids),
                    "remaining_seconds": remaining_seconds,
                    "remaining_minutes": round(remaining_seconds / 60.0, 1),
                    "idle_seconds": system_idle_seconds,
                    "input_events_last_30s": input_events_count
                }

            return poll_results

    def _monitor_loop(self) -> None:
        """Continuous execution loop."""
        while self._running:
            try:
                self.poll_once()
            except Exception as e:
                print(f"[ProcessMonitor] Exception in loop: {e}")
            poll_interval = self.config_mgr.config.get("poll_interval_seconds", 2)
            time.sleep(max(0.5, float(poll_interval)))


# Singleton instance
_global_monitor: Optional[ProcessMonitor] = None


def get_process_monitor(config_mgr: Optional[ConfigManager] = None) -> ProcessMonitor:
    """
    Get or create singleton instance of ProcessMonitor.
    """
    global _global_monitor
    if _global_monitor is None:
        _global_monitor = ProcessMonitor(config_mgr)
    return _global_monitor
