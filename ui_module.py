"""
FocusGuard - User Interface Module (ui_module.py)
-------------------------------------------------
Provides always-on-top non-blocking alert toasts, persistent lock-screen
countdown overlays when time is exhausted, and a passcode-gated parent
settings dashboard for configuration management.
"""

import os
import sys
import time
import threading
from typing import Optional, Callable, Dict, Any, List

import tkinter as tk
from tkinter import ttk, messagebox, simpledialog

from config_manager import ConfigManager, get_config_manager
from auth_module import AuthModule, get_auth_module
from logger_module import LoggerModule, get_logger
import win32_compat

# Color Palette for Modern Clean Dark Theme
BG_COLOR = "#121418"
CARD_BG = "#1e222b"
ACCENT_COLOR = "#007acc"
WARNING_COLOR = "#e67e22"
DANGER_COLOR = "#e74c3c"
SUCCESS_COLOR = "#2ecc71"
TEXT_COLOR = "#ecf0f1"
TEXT_MUTED = "#95a5a6"


class UIModule:
    """
    Coordinates graphical overlays, warnings, and settings windows.
    Thread-safe invocation allows calls from process monitor and enforcement threads.
    """

    def __init__(self, config_mgr: Optional[ConfigManager] = None,
                 auth_mod: Optional[AuthModule] = None,
                 logger: Optional[LoggerModule] = None):
        """
        Initialize UIModule with core services.
        """
        self.config_mgr = config_mgr or get_config_manager()
        self.auth_mod = auth_mod or get_auth_module(self.config_mgr)
        self.logger = logger or get_logger()
        self._lock_window: Optional[tk.Toplevel] = None
        self._active_banners: List[tk.Toplevel] = []

    def _ensure_tk_root(self) -> Optional[tk.Tk]:
        """Ensure a hidden root Tk window exists for dialogs."""
        try:
            if not tk._default_root:
                root = tk.Tk()
                root.withdraw()
                return root
            return tk._default_root
        except Exception as e:
            # Headless or missing DISPLAY
            return None

    def show_warning_toast(self, app_name: str, remaining_seconds: int, warn_minutes: int) -> None:
        """
        Display a non-blocking, always-on-top warning toast banner.
        
        Args:
            app_name (str): Monitored executable name.
            remaining_seconds (int): Seconds of time remaining.
            warn_minutes (int): Threshold minute mark (e.g. 10, 5, 1).
        """
        self.logger.log_warning(app_name, remaining_seconds, warn_minutes)

        def _create_toast():
            try:
                root = self._ensure_tk_root()
                if not root:
                    print(f"\n[ALERT] {app_name}: {warn_minutes} minute(s) remaining today!\n")
                    return

                win = tk.Toplevel(root)
                win.title("FocusGuard Warning")
                win.configure(bg=CARD_BG)
                win.attributes("-topmost", True)
                win.overrideredirect(True)  # Frameless banner

                # Position banner at top-right of screen
                width, height = 380, 100
                screen_w = win.winfo_screenwidth()
                x = screen_w - width - 25
                y = 40
                win.geometry(f"{width}x{height}+{x}+{y}")

                # Border frame
                border = tk.Frame(win, bg=WARNING_COLOR, padx=2, pady=2)
                border.pack(fill="both", expand=True)

                content = tk.Frame(border, bg=CARD_BG, padx=14, pady=10)
                content.pack(fill="both", expand=True)

                title_lbl = tk.Label(
                    content,
                    text=f"FocusGuard — {warn_minutes} Minute Warning",
                    font=("Segoe UI", 11, "bold"),
                    fg=WARNING_COLOR,
                    bg=CARD_BG
                )
                title_lbl.pack(anchor="w")

                msg_lbl = tk.Label(
                    content,
                    text=f"{app_name} will close in {warn_minutes} minute(s).\nPlease save your progress now.",
                    font=("Segoe UI", 9),
                    fg=TEXT_COLOR,
                    bg=CARD_BG,
                    justify="left"
                )
                msg_lbl.pack(anchor="w", pady=(4, 0))

                # Make always topmost via Win32 if on Windows
                try:
                    win32_compat.set_window_always_on_top(win.winfo_id())
                except Exception:
                    pass

                # Auto dismiss after 8 seconds
                win.after(8000, lambda: win.destroy())
            except Exception as e:
                print(f"[UIModule] Toast creation note: {e}")

        # Run in separate thread or schedule on Tk mainloop
        threading.Thread(target=_create_toast, daemon=True).start()

    def show_lockout_screen(self, app_name: str, reason: str = "TIME_EXHAUSTED",
                            on_time_added: Optional[Callable[[], None]] = None) -> None:
        """
        Display persistent, always-on-top overlay when time is up. Cannot be closed
        without entering parental passcode to add more time or open dashboard.
        
        Args:
            app_name (str): Name of terminated application.
            reason (str): 'TIME_EXHAUSTED' or 'SCHEDULE_LOCKOUT'.
            on_time_added (Callable, optional): Callback invoked if time is granted.
        """
        def _create_lockout():
            try:
                root = self._ensure_tk_root()
                if not root:
                    print(f"\n[LOCKOUT] {app_name}: Time's up for today! App closed.\n")
                    return

                win = tk.Toplevel(root)
                win.title("FocusGuard — Time Expired")
                win.configure(bg=BG_COLOR)
                win.attributes("-topmost", True)
                win.resizable(False, False)

                # Modal grab to prevent user clicking behind
                try:
                    win.grab_set()
                except Exception:
                    pass

                # Center modal dialog on screen
                w, h = 520, 380
                sw = win.winfo_screenwidth()
                sh = win.winfo_screenheight()
                cx = (sw - w) // 2
                cy = (sh - h) // 2
                win.geometry(f"{w}x{h}+{cx}+{cy}")

                # Prevent standard closing
                def on_close():
                    messagebox.showinfo("FocusGuard", "Passcode required to unlock or add time.")
                win.protocol("WM_DELETE_WINDOW", on_close)

                # Header Icon / Banner
                hdr = tk.Frame(win, bg=DANGER_COLOR, height=8)
                hdr.pack(fill="x")

                container = tk.Frame(win, bg=BG_COLOR, padx=30, pady=25)
                container.pack(fill="both", expand=True)

                title_text = "TIME'S UP FOR TODAY" if reason == "TIME_EXHAUSTED" else "OUTSIDE ALLOWED HOURS"
                title = tk.Label(
                    container,
                    text=title_text,
                    font=("Segoe UI", 16, "bold"),
                    fg=DANGER_COLOR,
                    bg=BG_COLOR
                )
                title.pack(pady=(0, 8))

                subtext = (
                    f"The daily time limit for '{app_name}' has been reached."
                    if reason == "TIME_EXHAUSTED" else
                    f"'{app_name}' is currently blocked by your scheduled lockout hours."
                )
                desc = tk.Label(
                    container,
                    text=f"{subtext}\nThe application was closed to protect your screen balance.",
                    font=("Segoe UI", 10),
                    fg=TEXT_COLOR,
                    bg=BG_COLOR,
                    justify="center"
                )
                desc.pack(pady=(0, 20))

                # Passcode Box Frame
                auth_frame = tk.LabelFrame(
                    container,
                    text=" Parent / Admin Unlock ",
                    font=("Segoe UI", 9, "bold"),
                    fg=TEXT_MUTED,
                    bg=CARD_BG,
                    padx=15,
                    pady=15
                )
                auth_frame.pack(fill="x", pady=10)

                status_var = tk.StringVar(value="Enter passcode to grant additional time today:")
                status_lbl = tk.Label(
                    auth_frame,
                    textvariable=status_var,
                    font=("Segoe UI", 9),
                    fg=TEXT_COLOR,
                    bg=CARD_BG
                )
                status_lbl.pack(anchor="w", pady=(0, 6))

                entry_pass = tk.Entry(
                    auth_frame,
                    show="•",
                    font=("Segoe UI", 12),
                    bg="#2d3340",
                    fg="#ffffff",
                    insertbackground="#ffffff",
                    relief="flat"
                )
                entry_pass.pack(fill="x", pady=(0, 10))
                entry_pass.focus_set()

                # Buttons row for quick time increments
                btn_frame = tk.Frame(auth_frame, bg=CARD_BG)
                btn_frame.pack(fill="x")

                def handle_add_time(minutes: int):
                    passcode = entry_pass.get().strip()
                    if not passcode:
                        status_var.set("Please enter the parent passcode first.")
                        status_lbl.configure(fg=WARNING_COLOR)
                        return

                    if self.auth_mod.is_locked_out():
                        rem_s = self.auth_mod.get_remaining_lockout_seconds()
                        status_var.set(f"Rate limited! Locked out for {rem_s}s.")
                        status_lbl.configure(fg=DANGER_COLOR)
                        return

                    success = self.config_mgr.add_time(app_name, minutes, passcode)
                    if success:
                        self.logger.log_auth_attempt(True, f"ADD_TIME_{minutes}m", f"Granted to {app_name}")
                        messagebox.showinfo("Success", f"Granted +{minutes} minutes for {app_name}!")
                        win.destroy()
                        if on_time_added:
                            on_time_added()
                    else:
                        attempts = max(0, self.auth_mod.MAX_FAILED_ATTEMPTS - self.auth_mod.failed_attempts)
                        self.logger.log_auth_attempt(False, "ADD_TIME", f"Invalid passcode for {app_name}")
                        if self.auth_mod.is_locked_out():
                            status_var.set(f"Too many failed attempts! Locked out for {self.auth_mod.LOCKOUT_DURATION_SECONDS}s.")
                        else:
                            status_var.set(f"Incorrect passcode! {attempts} attempt(s) remaining.")
                        status_lbl.configure(fg=DANGER_COLOR)
                        entry_pass.delete(0, tk.END)

                btn15 = tk.Button(
                    btn_frame,
                    text="+15 Mins",
                    font=("Segoe UI", 9, "bold"),
                    bg=ACCENT_COLOR,
                    fg="#ffffff",
                    relief="flat",
                    cursor="hand2",
                    command=lambda: handle_add_time(15)
                )
                btn15.pack(side="left", expand=True, fill="x", padx=3)

                btn30 = tk.Button(
                    btn_frame,
                    text="+30 Mins",
                    font=("Segoe UI", 9, "bold"),
                    bg=ACCENT_COLOR,
                    fg="#ffffff",
                    relief="flat",
                    cursor="hand2",
                    command=lambda: handle_add_time(30)
                )
                btn30.pack(side="left", expand=True, fill="x", padx=3)

                btn60 = tk.Button(
                    btn_frame,
                    text="+60 Mins",
                    font=("Segoe UI", 9, "bold"),
                    bg=ACCENT_COLOR,
                    fg="#ffffff",
                    relief="flat",
                    cursor="hand2",
                    command=lambda: handle_add_time(60)
                )
                btn60.pack(side="left", expand=True, fill="x", padx=3)

                # Bottom control buttons
                bottom_frame = tk.Frame(container, bg=BG_COLOR)
                bottom_frame.pack(fill="x", pady=(15, 0))

                def open_settings_gated():
                    passcode = entry_pass.get().strip()
                    if not self.auth_mod.verify_passcode(passcode):
                        status_var.set("Enter valid passcode above to open settings.")
                        status_lbl.configure(fg=DANGER_COLOR)
                        return
                    win.destroy()
                    self.show_settings_window(pre_authenticated=True)

                settings_btn = tk.Button(
                    bottom_frame,
                    text="Open Parent Settings Dashboard",
                    font=("Segoe UI", 9),
                    bg=CARD_BG,
                    fg=TEXT_COLOR,
                    relief="flat",
                    cursor="hand2",
                    command=open_settings_gated
                )
                settings_btn.pack(side="right")

                # Native Win32 Topmost pinning
                try:
                    win32_compat.set_window_always_on_top(win.winfo_id())
                except Exception:
                    pass

            except Exception as e:
                print(f"[UIModule] Lockout window creation note: {e}")

        threading.Thread(target=_create_lockout, daemon=True).start()

    def show_settings_window(self, pre_authenticated: bool = False) -> None:
        """
        Open the full parent settings dashboard. Gated by passcode.
        
        Args:
            pre_authenticated (bool): If True, skips initial passcode prompt.
        """
        root = self._ensure_tk_root()
        if not root:
            print("[UIModule] Cannot launch GUI: Display server unavailable.")
            return

        if not pre_authenticated:
            passcode = simpledialog.askstring("FocusGuard Authentication", "Enter Parent Passcode:", show="•")
            if not passcode or not self.auth_mod.verify_passcode(passcode):
                if self.auth_mod.is_locked_out():
                    messagebox.showerror("Locked Out", f"Too many failed attempts. Frozen for {self.auth_mod.get_remaining_lockout_seconds()}s.")
                else:
                    messagebox.showerror("Access Denied", "Incorrect passcode.")
                return

        # Build Settings GUI
        win = tk.Toplevel(root)
        win.title("FocusGuard — Parent Settings & Control Dashboard")
        win.geometry("780x560")
        win.configure(bg=BG_COLOR)

        style = ttk.Style(win)
        style.theme_use("clam")
        style.configure("Treeview", background=CARD_BG, foreground=TEXT_COLOR, fieldbackground=CARD_BG, rowheight=26)
        style.configure("Treeview.Heading", background="#2b313d", foreground=TEXT_COLOR, font=("Segoe UI", 9, "bold"))

        notebook = ttk.Notebook(win)
        notebook.pack(fill="both", expand=True, padx=10, pady=10)

        # Tab 1: Monitored Applications
        apps_tab = tk.Frame(notebook, bg=BG_COLOR, padx=10, pady=10)
        notebook.add(apps_tab, text=" Monitored Apps & Limits ")

        cols = ("Executable", "Name", "Daily Limit (min)", "Remaining Today", "Active Today")
        tree = ttk.Treeview(apps_tab, columns=cols, show="headings", height=10)
        for c in cols:
            tree.heading(c, text=c)
            tree.column(c, width=130, anchor="center")
        tree.column("Executable", width=150, anchor="w")
        tree.column("Name", width=160, anchor="w")
        tree.pack(fill="both", expand=True)

        def refresh_apps_list():
            for row in tree.get_children():
                tree.delete(row)
            for exe, data in self.config_mgr.config.get("apps", {}).items():
                rem_mins = round(data.get("remaining_seconds_today", 0) / 60.0, 1)
                act_mins = round(data.get("total_active_seconds_today", 0) / 60.0, 1)
                tree.insert("", "end", values=(
                    exe,
                    data.get("display_name", exe),
                    data.get("daily_limit_minutes", 0),
                    f"{rem_mins}m",
                    f"{act_mins}m"
                ))

        refresh_apps_list()

        # Action Buttons for Apps
        btn_box = tk.Frame(apps_tab, bg=BG_COLOR)
        btn_box.pack(fill="x", pady=10)

        def add_app_dialog():
            dlg = tk.Toplevel(win)
            dlg.title("Add Monitored Application")
            dlg.geometry("380x280")
            dlg.configure(bg=CARD_BG, padx=20, pady=20)
            dlg.transient(win)
            dlg.grab_set()

            tk.Label(dlg, text="Executable Name (e.g. game.exe):", bg=CARD_BG, fg=TEXT_COLOR).pack(anchor="w")
            e_exe = tk.Entry(dlg, bg="#2d3340", fg="#ffffff", relief="flat")
            e_exe.pack(fill="x", pady=(2, 10))

            tk.Label(dlg, text="Friendly Display Name:", bg=CARD_BG, fg=TEXT_COLOR).pack(anchor="w")
            e_name = tk.Entry(dlg, bg="#2d3340", fg="#ffffff", relief="flat")
            e_name.pack(fill="x", pady=(2, 10))

            tk.Label(dlg, text="Daily Limit (minutes):", bg=CARD_BG, fg=TEXT_COLOR).pack(anchor="w")
            e_limit = tk.Entry(dlg, bg="#2d3340", fg="#ffffff", relief="flat")
            e_limit.insert(0, "60")
            e_limit.pack(fill="x", pady=(2, 15))

            def save_new():
                exe = e_exe.get().strip()
                name = e_name.get().strip()
                try:
                    limit = int(e_limit.get().strip())
                except ValueError:
                    messagebox.showerror("Error", "Limit must be an integer number of minutes.")
                    return

                if not exe:
                    messagebox.showerror("Error", "Executable name cannot be empty.")
                    return

                if not exe.lower().endswith(".exe"):
                    exe += ".exe"

                self.config_mgr.config.setdefault("apps", {})[exe.lower()] = {
                    "display_name": name or exe,
                    "daily_limit_minutes": limit,
                    "remaining_seconds_today": limit * 60,
                    "total_active_seconds_today": 0,
                    "total_open_seconds_today": 0
                }
                self.config_mgr.save()
                refresh_apps_list()
                dlg.destroy()

            tk.Button(dlg, text="Save Application", bg=SUCCESS_COLOR, fg="#ffffff", relief="flat", command=save_new).pack(fill="x")

        def remove_selected_app():
            sel = tree.selection()
            if not sel:
                messagebox.showwarning("Warning", "Select an application to remove.")
                return
            item = tree.item(sel[0])
            exe = item["values"][0]
            if messagebox.askyesno("Confirm", f"Remove '{exe}' from monitored applications?"):
                if exe in self.config_mgr.config.get("apps", {}):
                    del self.config_mgr.config["apps"][exe]
                    self.config_mgr.save()
                    refresh_apps_list()

        def edit_limit_dialog():
            sel = tree.selection()
            if not sel:
                messagebox.showwarning("Warning", "Select an application to edit.")
                return
            item = tree.item(sel[0])
            exe = item["values"][0]
            curr_limit = self.config_mgr.get_limit(exe)
            new_val = simpledialog.askinteger("Edit Daily Limit", f"Enter new daily limit (minutes) for {exe}:",
                                              initialvalue=curr_limit, minvalue=1, maxvalue=1440)
            if new_val is not None:
                # Update without re-prompting because parent is in settings
                self.config_mgr.config["apps"][exe]["daily_limit_minutes"] = new_val
                # adjust remaining time proportionally
                diff = (new_val - curr_limit) * 60
                rem = self.config_mgr.config["apps"][exe].get("remaining_seconds_today", 0)
                self.config_mgr.config["apps"][exe]["remaining_seconds_today"] = max(0, rem + diff)
                self.config_mgr.save()
                refresh_apps_list()

        tk.Button(btn_box, text="+ Add App", bg=ACCENT_COLOR, fg="#ffffff", relief="flat", padx=10, command=add_app_dialog).pack(side="left", padx=5)
        tk.Button(btn_box, text="Edit Limit", bg=CARD_BG, fg=TEXT_COLOR, relief="flat", padx=10, command=edit_limit_dialog).pack(side="left", padx=5)
        tk.Button(btn_box, text="Remove App", bg=DANGER_COLOR, fg="#ffffff", relief="flat", padx=10, command=remove_selected_app).pack(side="left", padx=5)
        tk.Button(btn_box, text="Reset Today's Usage", bg="#7f8c8d", fg="#ffffff", relief="flat", padx=10,
                  command=lambda: [self.config_mgr.reset_daily_usage(force=True), refresh_apps_list(), messagebox.showinfo("Reset", "Usage reset to daily limits.")]).pack(side="right", padx=5)

        # Tab 2: General & Anti-Gaming Rules
        rules_tab = tk.Frame(notebook, bg=BG_COLOR, padx=20, pady=20)
        notebook.add(rules_tab, text=" Rules & Anti-Gaming ")

        tk.Label(rules_tab, text="System Idle Threshold (seconds):", bg=BG_COLOR, fg=TEXT_COLOR, font=("Segoe UI", 10)).grid(row=0, column=0, sticky="w", pady=8)
        e_idle = tk.Entry(rules_tab, bg=CARD_BG, fg="#ffffff", relief="flat")
        e_idle.insert(0, str(self.config_mgr.config.get("idle_threshold_seconds", 60)))
        e_idle.grid(row=0, column=1, sticky="w", padx=10, pady=8)

        tk.Label(rules_tab, text="Anti-Gaming Input Threshold (events/30s):", bg=BG_COLOR, fg=TEXT_COLOR, font=("Segoe UI", 10)).grid(row=1, column=0, sticky="w", pady=8)
        e_input_thr = tk.Entry(rules_tab, bg=CARD_BG, fg="#ffffff", relief="flat")
        e_input_thr.insert(0, str(self.config_mgr.config.get("input_event_threshold", 5)))
        e_input_thr.grid(row=1, column=1, sticky="w", padx=10, pady=8)

        tk.Label(rules_tab, text="Relaunch Cooldown Window (seconds):", bg=BG_COLOR, fg=TEXT_COLOR, font=("Segoe UI", 10)).grid(row=2, column=0, sticky="w", pady=8)
        e_cooldown = tk.Entry(rules_tab, bg=CARD_BG, fg="#ffffff", relief="flat")
        e_cooldown.insert(0, str(self.config_mgr.config.get("cooldown_window_seconds", 300)))
        e_cooldown.grid(row=2, column=1, sticky="w", padx=10, pady=8)

        # Lockout Schedule
        sched = self.config_mgr.config.get("lockout_schedule", {})
        sched_enabled_var = tk.BooleanVar(value=sched.get("enabled", False))
        cb_sched = tk.Checkbutton(rules_tab, text="Enable Daily Lockout Schedule (Block outside allowed hours)",
                                  variable=sched_enabled_var, bg=BG_COLOR, fg=TEXT_COLOR, selectcolor=CARD_BG, font=("Segoe UI", 10, "bold"))
        cb_sched.grid(row=3, column=0, columnspan=2, sticky="w", pady=(15, 8))

        tk.Label(rules_tab, text="Allowed Start Time (HH:MM):", bg=BG_COLOR, fg=TEXT_COLOR).grid(row=4, column=0, sticky="w", pady=4)
        e_start = tk.Entry(rules_tab, bg=CARD_BG, fg="#ffffff", relief="flat")
        e_start.insert(0, sched.get("allowed_start", "08:00"))
        e_start.grid(row=4, column=1, sticky="w", padx=10, pady=4)

        tk.Label(rules_tab, text="Allowed End Time (HH:MM):", bg=BG_COLOR, fg=TEXT_COLOR).grid(row=5, column=0, sticky="w", pady=4)
        e_end = tk.Entry(rules_tab, bg=CARD_BG, fg="#ffffff", relief="flat")
        e_end.insert(0, sched.get("allowed_end", "21:00"))
        e_end.grid(row=5, column=1, sticky="w", padx=10, pady=4)

        def save_rules():
            try:
                idle = int(e_idle.get().strip())
                in_thr = int(e_input_thr.get().strip())
                cool = int(e_cooldown.get().strip())
                start_t = e_start.get().strip()
                end_t = e_end.get().strip()

                self.config_mgr.config["idle_threshold_seconds"] = idle
                self.config_mgr.config["input_event_threshold"] = in_thr
                self.config_mgr.config["cooldown_window_seconds"] = cool
                self.config_mgr.config["lockout_schedule"]["enabled"] = sched_enabled_var.get()
                self.config_mgr.config["lockout_schedule"]["allowed_start"] = start_t
                self.config_mgr.config["lockout_schedule"]["allowed_end"] = end_t

                self.config_mgr.save()
                messagebox.showinfo("Saved", "Rules and threshold configuration saved successfully.")
            except Exception as e:
                messagebox.showerror("Error", f"Failed saving rules: {e}")

        tk.Button(rules_tab, text="Save Rules & Schedule", bg=SUCCESS_COLOR, fg="#ffffff", relief="flat", padx=15, pady=5, command=save_rules).grid(row=6, column=0, columnspan=2, pady=20)

        # Tab 3: Security & Passcode
        sec_tab = tk.Frame(notebook, bg=BG_COLOR, padx=20, pady=20)
        notebook.add(sec_tab, text=" Security ")

        tk.Label(sec_tab, text="Change Parent Passcode", font=("Segoe UI", 12, "bold"), bg=BG_COLOR, fg=TEXT_COLOR).pack(anchor="w", pady=(0, 15))

        tk.Label(sec_tab, text="Current Passcode:", bg=BG_COLOR, fg=TEXT_COLOR).pack(anchor="w")
        e_cur_pass = tk.Entry(sec_tab, show="•", bg=CARD_BG, fg="#ffffff", relief="flat")
        e_cur_pass.pack(fill="x", pady=(2, 10))

        tk.Label(sec_tab, text="New Passcode (min 4 characters):", bg=BG_COLOR, fg=TEXT_COLOR).pack(anchor="w")
        e_new_pass = tk.Entry(sec_tab, show="•", bg=CARD_BG, fg="#ffffff", relief="flat")
        e_new_pass.pack(fill="x", pady=(2, 15))

        def update_passcode():
            cur_p = e_cur_pass.get()
            new_p = e_new_pass.get()
            ok, msg = self.auth_mod.change_passcode(cur_p, new_p)
            if ok:
                messagebox.showinfo("Security", msg)
                e_cur_pass.delete(0, tk.END)
                e_new_pass.delete(0, tk.END)
            else:
                messagebox.showerror("Security Error", msg)

        tk.Button(sec_tab, text="Update Passcode", bg=ACCENT_COLOR, fg="#ffffff", relief="flat", padx=15, pady=5, command=update_passcode).pack(anchor="w")

        # Tab 4: Audit & Activity Logs
        log_tab = tk.Frame(notebook, bg=BG_COLOR, padx=10, pady=10)
        notebook.add(log_tab, text=" Activity Log ")

        txt_logs = tk.Text(log_tab, bg=CARD_BG, fg=TEXT_COLOR, font=("Consolas", 9), relief="flat")
        txt_logs.pack(fill="both", expand=True)

        def reload_logs():
            txt_logs.delete("1.0", tk.END)
            for line in self.logger.get_recent_logs(80):
                txt_logs.insert(tk.END, line + "\n")
            txt_logs.see(tk.END)

        reload_logs()
        tk.Button(log_tab, text="Refresh Logs", bg=CARD_BG, fg=TEXT_COLOR, relief="flat", command=reload_logs).pack(anchor="e", pady=5)


# Singleton instance
_global_ui: Optional[UIModule] = None


def get_ui_module(config_mgr: Optional[ConfigManager] = None,
                 auth_mod: Optional[AuthModule] = None,
                 logger: Optional[LoggerModule] = None) -> UIModule:
    """Get or create singleton instance of UIModule."""
    global _global_ui
    if _global_ui is None:
        _global_ui = UIModule(config_mgr, auth_mod, logger)
    return _global_ui
