"""
FocusGuard - Windows Low-Level API Compatibility Layer (win32_compat.py)
------------------------------------------------------------------------
Provides rock-solid access to Windows User32, Kernel32, and Advapi32 APIs
using native pywin32 (if available) with automatic fallback to ctypes.windll.
Also provides mock/stub fallback when running in testing or non-Windows environments.
"""

import sys
import os
import time
from typing import Optional, Tuple

IS_WINDOWS = sys.platform.startswith("win")

# Try importing pywin32 first
try:
    import win32gui
    import win32process
    import win32api
    import win32con
    HAS_PYWIN32 = True
except ImportError:
    HAS_PYWIN32 = False

if IS_WINDOWS:
    import ctypes
    from ctypes import wintypes

    user32 = ctypes.windll.user32
    kernel32 = ctypes.windll.kernel32

    class LASTINPUTINFO(ctypes.Structure):
        _fields_ = [
            ("cbSize", wintypes.UINT),
            ("dwTime", wintypes.DWORD),
        ]

    class POINT(ctypes.Structure):
        _fields_ = [
            ("x", wintypes.LONG),
            ("y", wintypes.LONG),
        ]


def get_foreground_window_pid() -> Optional[int]:
    """
    Get the process ID (PID) of the application currently in the foreground.
    
    Returns:
        int: Process ID of the active foreground window, or None if no window is focused.
    """
    if not IS_WINDOWS:
        return None

    try:
        if HAS_PYWIN32:
            hwnd = win32gui.GetForegroundWindow()
            if not hwnd:
                return None
            _, pid = win32process.GetWindowThreadProcessId(hwnd)
            return pid
        else:
            hwnd = user32.GetForegroundWindow()
            if not hwnd:
                return None
            pid = wintypes.DWORD()
            user32.GetWindowThreadProcessId(hwnd, ctypes.byref(pid))
            return pid.value
    except Exception:
        return None


def get_foreground_window_title() -> str:
    """
    Get the title text of the current foreground window.
    
    Returns:
        str: Window title string.
    """
    if not IS_WINDOWS:
        return ""

    try:
        if HAS_PYWIN32:
            hwnd = win32gui.GetForegroundWindow()
            if hwnd:
                return win32gui.GetWindowText(hwnd)
            return ""
        else:
            hwnd = user32.GetForegroundWindow()
            if not hwnd:
                return ""
            length = user32.GetWindowTextLengthW(hwnd)
            buff = ctypes.create_unicode_buffer(length + 1)
            user32.GetWindowTextW(hwnd, buff, length + 1)
            return buff.value
    except Exception:
        return ""


def get_system_idle_seconds() -> float:
    """
    Get system-wide idle time (in seconds) since last user physical input
    (mouse movement, click, or keystroke) using GetLastInputInfo().
    
    Returns:
        float: Seconds since last input.
    """
    if not IS_WINDOWS:
        return 0.0

    try:
        if HAS_PYWIN32:
            last_input_tick = win32api.GetLastInputInfo()
            current_tick = win32api.GetTickCount()
            elapsed_ms = current_tick - last_input_tick
            # Handle 32-bit tick wrap-around if system uptime > 49.7 days
            if elapsed_ms < 0:
                elapsed_ms += 0x100000000
            return max(0.0, elapsed_ms / 1000.0)
        else:
            lii = LASTINPUTINFO()
            lii.cbSize = ctypes.sizeof(LASTINPUTINFO)
            if user32.GetLastInputInfo(ctypes.byref(lii)):
                current_tick = kernel32.GetTickCount()
                elapsed_ms = current_tick - lii.dwTime
                if elapsed_ms < 0:
                    elapsed_ms += 0x100000000
                return max(0.0, elapsed_ms / 1000.0)
            return 0.0
    except Exception:
        return 0.0


def get_cursor_position() -> Tuple[int, int]:
    """
    Get current mouse cursor coordinates (x, y).
    
    Returns:
        Tuple[int, int]: (x, y) screen coordinates.
    """
    if not IS_WINDOWS:
        return (0, 0)

    try:
        if HAS_PYWIN32:
            return win32gui.GetCursorPos()
        else:
            pt = POINT()
            if user32.GetCursorPos(ctypes.byref(pt)):
                return (pt.x, pt.y)
            return (0, 0)
    except Exception:
        return (0, 0)


def set_window_always_on_top(hwnd: int) -> bool:
    """
    Force a native window handle to stay permanently on top (HWND_TOPMOST).
    
    Args:
        hwnd (int): Native window handle.
        
    Returns:
        bool: True if call succeeded.
    """
    if not IS_WINDOWS or not hwnd:
        return False

    HWND_TOPMOST = -1
    SWP_NOMOVE = 0x0002
    SWP_NOSIZE = 0x0001
    SWP_SHOWWINDOW = 0x0040

    try:
        if HAS_PYWIN32:
            win32gui.SetWindowPos(
                hwnd,
                win32con.HWND_TOPMOST,
                0, 0, 0, 0,
                win32con.SWP_NOMOVE | win32con.SWP_NOSIZE | win32con.SWP_SHOWWINDOW
            )
            return True
        else:
            user32.SetWindowPos(
                hwnd,
                HWND_TOPMOST,
                0, 0, 0, 0,
                SWP_NOMOVE | SWP_NOSIZE | SWP_SHOWWINDOW
            )
            return True
    except Exception:
        return False
