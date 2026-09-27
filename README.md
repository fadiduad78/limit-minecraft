# FocusGuard — Active Windows Desktop Application Time-Limit Enforcer

**FocusGuard** is a robust, modular parental control and digital wellbeing desktop application for Windows. It strictly enforces daily screen-time allowances on specified target applications (such as *Minecraft*, *Roblox*, *Fortnite*, etc.) using **active-use tracking**, **anti-gaming input verification**, **topmost modal overlays**, a **tamper-proof mutual watchdog**, and a **passcode-gated administrative boundary**.

---

## Architecture & Module Communication

FocusGuard is engineered as independent, decoupled modules communicating through clear event pipelines and authenticated interfaces:

```
                                  +---------------------+
                                  |   Parent / Admin    |
                                  +----------+----------+
                                             |  (Passcode Input)
                                             v
                                  +---------------------+
                                  |     auth_module     |
                                  +----------+----------+
                                             |
                   +-------------------------+-------------------------+
                   |  (Privileged Gate)                                |  (Privileged Gate)
                   v                                                   v
        +---------------------+                             +---------------------+
        |   config_manager    |                             |   service_runner    |
        |  (AES/HMAC Encrypted|                             | (Task Scheduler /   |
        |   Configuration)    |                             |  SYSTEM Service)    |
        +----------+----------+                             +----------+----------+
                   |                                                   |
                   v                                                   v
        +---------------------+                             +---------------------+
        |   process_monitor   |                             |   watchdog_module   |
        |  (Foreground, Idle, | <====== (Mutual Watchdog) =======>  | (Supervisor Process |
        |   Input Anti-Gaming)|                             |   Auto-Relaunch)    |
        +----------+----------+                             +---------------------+
                   |
                   | Events:
                   |  - app_started
                   |  - app_active(elapsed)
                   |  - app_should_warn(10m, 5m, 1m)
                   |  - app_should_terminate
                   v
        +---------------------+
        | enforcement_module  |
        +----------+----------+
                   |
                   | Renders Toasts / Modal Lockout
                   v
        +---------------------+                 +---------------------+
        |      ui_module      |                 |    logger_module    |
        |  (Topmost Overlay & |                 |  (Active vs Open    |
        |   Settings Panel)   |                 |   Audit Logging)    |
        +---------------------+                 +---------------------+
```

### Module Responsibilities:
1. `config_manager.py`: Stores application rules, daily limits, remaining time budgets, schedule restrictions, and salt/hash in an encrypted file (`focusguard_config.enc`) protected by Fernet AES symmetric encryption and HMAC-SHA256 tamper verification.
2. `auth_module.py`: Passcode gatekeeper using salted PBKDF2-HMAC-SHA256 (100,000 iterations). Enforces brute-force rate-limiting (locks out attempts for 60 seconds after 5 failed tries). All privileged actions must pass through this module.
3. `process_monitor.py`: State-machine engine tracking active application usage (`RUNNING_ACTIVE`, `RUNNING_IDLE`, `RUNNING_BACKGROUND`, `NOT_RUNNING`). Only `RUNNING_ACTIVE` decrements daily time. Enforces rolling window input event density to defeat mouse-nudging auto-clickers.
4. `enforcement_module.py`: Subscribes to monitor events. Dispatches non-blocking notifications at 10m, 5m, and 1m remaining. Executes process-tree kills (`taskkill /F /T` / `psutil`) when time is up, and maintains an anti-relaunch cooldown window.
5. `ui_module.py`: High-contrast dark-mode interface. Features always-on-top non-blocking warning toasts, a persistent modal lockout screen with passcode entry to grant bonus time, and a full parent settings dashboard.
6. `service_runner.py`: Installs FocusGuard into Windows Task Scheduler running under `HIGHEST` / `SYSTEM` elevation at system startup. Stopping or uninstalling is strictly gated by `auth_module`.
7. `watchdog_module.py`: Secondary supervisor process forming a mutual-watchdog pair with the main process. If either process is terminated from Task Manager, the surviving peer immediately resurrects it. Exit is only allowed via an authenticated shutdown token.
8. `logger_module.py`: Human-readable and machine-parsable audit logger. Records state transitions and tracks total open time vs. active engaged time (e.g., *"Minecraft open 3h 12m, but only 1h 45m active"*).
9. `win32_compat.py`: Native Windows User32 and Kernel32 API layer (via `pywin32` or direct `ctypes` bindings) for foreground window handle detection, physical idle tick calculation, and window z-ordering.
10. `main.py`: Unified CLI and operational entrypoint.

---

## Technical Justification: Python vs. C# (.NET)

FocusGuard is built using **Python with PyWin32 / ctypes / psutil**. Both platforms have strong capabilities on Windows, but Python was selected based on the following engineering merits:

| Criteria | Python (`pywin32` + `ctypes` + `psutil`) | C# (.NET 8/9 / WPF) |
|---|---|---|
| **Low-Level Process Tree Management** | `psutil` provides cross-architecture, battle-tested C extensions for walking child process trees (`proc.children(recursive=True)`), inspecting memory/CPU, and terminating entire trees cleanly across Windows session boundaries. | Requires writing and debugging complex native Win32 P/Invoke structures (`CreateToolhelp32Snapshot`, `PROCESSENTRY32`) or wrapping WMI queries. |
| **Direct Win32 API Access** | `pywin32` and standard library `ctypes` provide direct, zero-friction 1:1 bindings to User32 (`GetForegroundWindow`, `GetWindowThreadProcessId`, `GetLastInputInfo`, `SetWindowPos`). | Requires extensive P/Invoke DllImport signatures, unsafe code blocks, and manual struct layout marshalling. |
| **System Footprint & Startup** | Single standalone deployment, small memory footprint (~25MB), runs via lightweight Python background worker or `pythonw.exe`. | Requires .NET Runtime installation or large multi-megabyte self-contained AOT build. |
| **Session 0 GUI Isolation** | Runs smoothly in user desktop session under elevated scheduled task context, allowing modal Tkinter overlays to display directly over full-screen games without cross-session IPC proxies. | Windows Service (`ServiceBase`) running in Session 0 cannot display UI; requires separate UI agent process and complex WCF/gRPC named-pipe IPC. |
| **Extensibility & Tamper Resilience** | Symmetric file encryption, salted PBKDF2 hashing, and process-level mutual supervision can be modified and audited without recompilation steps. | Binary IL can be easily decompiled or IL-patched using tools like dnSpy or ILSpy. |

---

## Active-Use Tracking & Anti-Gaming Engine

Most parental control apps make a critical mistake: they treat any open process as "active." A child can leave a game minimized in the background while studying, and lose their allowance—or leave the game idling overnight to artificially consume time.

FocusGuard uses a **4-state operational machine**:

```
                       +-------------------+
                       |    NOT_RUNNING    |
                       +---------+---------+
                                 |  Process spawned
                                 v
                       +-------------------+
                       |RUNNING_BACKGROUND |  (Process running, but window not focused)
                       +---------+---------+
                                 |  Window gained foreground focus
                                 v
                       +-------------------+
            +--------> |   RUNNING_IDLE    |  (Focused, but system idle > 60s
            |          +---------+---------+   OR input event density < threshold)
            |                    |
No input or |                    | Real input events detected (clicks/keys/mouse motion)
idle timeout|                    v
            |          +-------------------+
            +--------- |  RUNNING_ACTIVE   | <--- ONLY THIS STATE DECREMENTS TIME!
                       +-------------------+
```

### Defeating Mouse-Jigglers & Auto-Clickers
To prevent trivial gaming of the idle check (e.g., using a mechanical mouse jiggler or a macro that nudges the cursor once every 59 seconds to keep `GetLastInputInfo()` fresh):
- FocusGuard maintains an in-memory rolling window of physical input timestamps (default: **30 seconds**).
- It verifies that the user generated a minimum number of distinct real input events (default: **5 events / 30 seconds**).
- If input rate falls below this threshold, the application instantly drops from `RUNNING_ACTIVE` into `RUNNING_IDLE`, pausing the time-decrement timer.

---

## Mutual Watchdog & Service Resilience Pattern

To prevent children or unauthorized users from simply opening Task Manager or executing `taskkill /F /IM python.exe`:

1. **High-Privilege Scheduled Task Execution**:
   - FocusGuard installs itself using Windows Task Scheduler (`schtasks.exe`) configured with `/RL HIGHEST` / `SYSTEM` elevation, configured to launch at logon.
2. **Dual-Process Mutual Watchdog**:
   - **Process A** (`main.py --supervised`): The core monitor and enforcement engine.
   - **Process B** (`main.py --watchdog`): The dedicated supervisor companion.
   - Process A monitors the PID of Process B. If Process B exits unexpectedly, Process A respawns it.
   - Process B monitors the PID of Process A. If Process B detects that Process A was killed, it immediately respawns Process A.
3. **Passcode-Gated Authorized Shutdown Protocol**:
   - The only way to stop FocusGuard is by providing the parent passcode (`python main.py --stop` or `--uninstall`).
   - `auth_module.verify_passcode()` authenticates the parent and generates a short-lived cryptographic shutdown token (`focusguard_shutdown.token`).
   - Both processes detect the token, verify its timestamp validity (<60 seconds), log the administrative stop event, and exit cleanly without triggering mutual resurrection.

---

## Installation & Setup Guide

### 1. Prerequisites
- Windows 10 or Windows 11 (64-bit).
- Python 3.9+ installed with `pip`.
- Administrative command prompt (for service installation).

### 2. Install Dependencies
```bash
pip install -r requirements.txt
```

*(Note: On Windows, this installs `psutil`, `cryptography`, and `pywin32`.)*

### 3. Initial Default Credentials
- Default Parent Passcode: `1234`
- *(Important: Change this immediately upon first run in the Settings Dashboard or via CLI!)*

---

## Command-Line Usage

FocusGuard features a single-command CLI interface:

### Run Standalone (Testing / Foreground Mode)
```bash
python main.py
```
Runs the active monitor in the foreground with live console logs. Ideal for testing rules and watching state transitions in real time.

### Check Current Status & Application Usage
```bash
python main.py --status
```
Prints an ASCII status table showing monitored apps, daily limits, remaining seconds, active time today, and lockout schedules:
```text
====================================================================
  FocusGuard System Status — 2026-09-27
====================================================================
  System Idle Threshold : 60 seconds
  Anti-Gaming Threshold : 5 events / 30s
  Cooldown Window       : 300 seconds
  Lockout Schedule      : Disabled
--------------------------------------------------------------------
  Executable             | Limit    | Remaining    | Active Today
--------------------------------------------------------------------
  minecraft.exe          | 60 min   | 60.0 min     | 0.0 min
  javaw.exe              | 60 min   | 60.0 min     | 0.0 min
  robloxplayerbeta.exe   | 45 min   | 45.0 min     | 0.0 min
====================================================================
```

### Launch Graphical Parent Settings Dashboard
```bash
python main.py --settings
```
Prompts for the parent passcode, then displays the tabbed management panel:
- **Monitored Apps & Limits**: Add apps, adjust minutes, remove executables, or reset daily usage.
- **Rules & Anti-Gaming**: Configure idle threshold, rolling input rate, and lockout schedule (e.g., block games between 21:00 and 08:00).
- **Security**: Update the parent passcode.
- **Activity Log**: View recent state transitions, active vs. open times, and authorization attempts.

### Grant Bonus Time Today (Passcode Gated)
```bash
python main.py --add-time minecraft.exe 30
```
Prompts for the passcode securely and grants 30 additional minutes of active gameplay today.

### Reset Daily Usage (Passcode Gated)
```bash
python main.py --reset
```

### Install as Persistent Windows Startup Service
*(Open Command Prompt or PowerShell as Administrator)*
```bash
python main.py --install
```
Registers FocusGuard with Windows Task Scheduler to run continuously with highest privileges.

### Gracefully Stop the Running Service (Passcode Gated)
```bash
python main.py --stop
```

### Uninstall the Service (Passcode Gated)
```bash
python main.py --uninstall
```
Prompts for the parent passcode, stops the mutual watchdog pair, and deletes the scheduled task registration from Windows.

---

## Running the Automated Test Suite

FocusGuard includes a test suite covering configuration encryption, HMAC tamper resistance, brute-force rate-limiting, the 4-stage process monitor state machine, rolling input activity verification, enforcement triggers, and watchdog shutdown tokens:

```bash
python -m unittest tests/test_focusguard.py -v
```

Output:
```text
test_auth_rate_limiting ... ok
test_config_encryption_and_tamper_protection ... ok
test_enforcement_and_cooldown_relaunch_kill ... ok
test_input_activity_tracker ... ok
test_privileged_actions_gated ... ok
test_process_monitor_state_machine_and_budget_decrement ... ok
test_watchdog_shutdown_token ... ok

----------------------------------------------------------------------
Ran 7 tests in 1.589s

OK
```

---

## File Structure

```text
focusguard/
├── main.py                 # Application CLI & pipeline orchestrator
├── config_manager.py       # AES-GCM/Fernet encrypted config & HMAC integrity
├── auth_module.py          # Salted PBKDF2 passcode verification & rate-limiting
├── process_monitor.py      # Active vs open tracking, foreground check, input anti-gaming
├── enforcement_module.py   # Warning alerts, process-tree termination, cooldown block
├── ui_module.py            # Always-on-top warning toasts, lockout screen & settings UI
├── service_runner.py       # Elevated Windows startup task installation & lifecycle
├── watchdog_module.py      # Mutual watchdog resilience & authorized shutdown token
├── logger_module.py        # Usage audit logs (active vs open duration comparison)
├── win32_compat.py         # Native Windows User32/Kernel32 ctypes & pywin32 wrapper
├── config.example.json     # Unencrypted JSON configuration template
├── requirements.txt        # Python dependency declarations
├── tests/
│   └── test_focusguard.py  # Comprehensive unit and integration test suite
└── README.md               # Complete architecture, technical justification & documentation
```

---

## Security Model Summary

- **No Plaintext Passcodes**: The passcode is salted with a 16-byte random salt and hashed using 100,000 PBKDF2-SHA256 iterations. The plaintext passcode is never stored, displayed, or written to disk.
- **Brute-Force Lockout**: 5 failed verification attempts freeze all authentication for 60 seconds.
- **Tamper-Evident Storage**: Configuration files are encrypted using symmetric Fernet keys. Any manual byte manipulation causes HMAC mismatch and is safely rejected.
- **Process Tree Termination**: Games running with child launcher processes (e.g., Minecraft Launcher launching `javaw.exe`) are killed completely across the process tree using native Win32 `taskkill /F /T` and `psutil` recursive termination.
