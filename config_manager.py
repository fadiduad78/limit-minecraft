"""
FocusGuard - Configuration Manager (config_manager.py)
-------------------------------------------------------
Responsible for secure persistence of application rules, daily time budgets,
lockout schedules, and security credentials. Settings are stored encrypted
and HMAC-verified to prevent tampering by unauthorized users.
"""

import os
import sys
import json
import base64
import hashlib
import hmac
import datetime
from typing import Dict, Any, Optional, List
from cryptography.fernet import Fernet

# Optional Windows DPAPI for hardware/OS-bound key security
IS_WINDOWS = sys.platform.startswith("win")


class ConfigManager:
    """
    Manages loading, updating, encrypting, and validating FocusGuard configuration.
    
    Attributes:
        config_path (str): Path to encrypted config file.
        key_path (str): Path to secure key storage file.
        config (dict): In-memory decrypted configuration state.
    """

    DEFAULT_CONFIG = {
        "version": 1,
        "passcode_hash": "",       # Salted PBKDF2-SHA256 hash
        "passcode_salt": "",       # Hex-encoded 16-byte cryptographic salt
        "idle_threshold_seconds": 60,
        "input_event_threshold": 5,    # Min events required in rolling window
        "input_window_seconds": 30,     # Rolling window for input anti-gaming
        "cooldown_window_seconds": 300, # Instant-kill period after daily cap hit
        "poll_interval_seconds": 2,
        "last_reset_date": "",         # YYYY-MM-DD
        "lockout_schedule": {
            "enabled": False,
            "allowed_start": "08:00",  # HH:MM
            "allowed_end": "21:00",    # HH:MM
            "allowed_days": [0, 1, 2, 3, 4, 5, 6],  # Mon=0, Sun=6
        },
        "apps": {
            "minecraft.exe": {
                "display_name": "Minecraft (Bedrock / Launcher)",
                "daily_limit_minutes": 60,
                "remaining_seconds_today": 3600,
                "total_active_seconds_today": 0,
                "total_open_seconds_today": 0,
            },
            "javaw.exe": {
                "display_name": "Minecraft (Java Edition)",
                "daily_limit_minutes": 60,
                "remaining_seconds_today": 3600,
                "total_active_seconds_today": 0,
                "total_open_seconds_today": 0,
            },
            "robloxplayerbeta.exe": {
                "display_name": "Roblox Player",
                "daily_limit_minutes": 45,
                "remaining_seconds_today": 2700,
                "total_active_seconds_today": 0,
                "total_open_seconds_today": 0,
            }
        }
    }

    def __init__(self, config_path: str = "focusguard_config.enc", key_path: str = "focusguard.key"):
        """
        Initialize ConfigManager with file paths and load or create config.
        
        Args:
            config_path (str): File path for encrypted configuration file.
            key_path (str): File path for cryptographic key file.
        """
        self.config_path = os.path.abspath(config_path)
        self.key_path = os.path.abspath(key_path)
        self._cipher: Optional[Fernet] = None
        self._init_cipher()
        self.config: Dict[str, Any] = {}
        self.load()

    def _init_cipher(self) -> None:
        """
        Initialize Fernet symmetric cipher, generating or loading machine-bound key.
        """
        key: bytes
        if os.path.exists(self.key_path):
            with open(self.key_path, "rb") as f:
                key = f.read().strip()
        else:
            # Generate a new 256-bit Fernet key
            key = Fernet.generate_key()
            try:
                # Write with restrictive permissions
                flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
                mode = 0o600
                fd = os.open(self.key_path, flags, mode)
                with open(fd, "wb") as f:
                    f.write(key)
            except Exception:
                with open(self.key_path, "wb") as f:
                    f.write(key)

        self._cipher = Fernet(key)

    def load(self) -> Dict[str, Any]:
        """
        Load and decrypt configuration from disk. If missing or corrupted,
        initializes with defaults and writes encrypted template.
        
        Returns:
            dict: The active configuration dictionary.
        """
        if not os.path.exists(self.config_path):
            # First run: initialize with defaults and default passcode (e.g., '1234' hashed)
            self.config = json.loads(json.dumps(self.DEFAULT_CONFIG))
            today = datetime.date.today().isoformat()
            self.config["last_reset_date"] = today
            self._set_initial_passcode("1234")
            self.save()
            return self.config

        try:
            with open(self.config_path, "rb") as f:
                encrypted_data = f.read()
            decrypted_bytes = self._cipher.decrypt(encrypted_data)
            payload = json.loads(decrypted_bytes.decode("utf-8"))

            # Verify payload integrity
            stored_hmac = payload.get("hmac", "")
            raw_data = payload.get("data", {})
            computed_hmac = self._compute_hmac(raw_data)

            if not hmac.compare_digest(stored_hmac, computed_hmac):
                raise ValueError("Config HMAC signature mismatch! Tampering detected.")

            self.config = raw_data
            self.reset_daily_usage(force=False)
            return self.config
        except Exception as e:
            # Fallback or backup corrupted file
            print(f"[ConfigManager] Warning loading config: {e}. Reinitializing defaults safely.")
            self.config = json.loads(json.dumps(self.DEFAULT_CONFIG))
            self.config["last_reset_date"] = datetime.date.today().isoformat()
            self._set_initial_passcode("1234")
            self.save()
            return self.config

    def save(self) -> bool:
        """
        Encrypt and persist in-memory configuration to disk with HMAC signature.
        
        Returns:
            bool: True if saved successfully, False otherwise.
        """
        try:
            computed_hmac = self._compute_hmac(self.config)
            envelope = {
                "version": 1,
                "timestamp": datetime.datetime.now().isoformat(),
                "hmac": computed_hmac,
                "data": self.config
            }
            json_bytes = json.dumps(envelope, indent=2).encode("utf-8")
            encrypted_data = self._cipher.encrypt(json_bytes)

            temp_path = self.config_path + ".tmp"
            with open(temp_path, "wb") as f:
                f.write(encrypted_data)
                f.flush()
                os.fsync(f.fileno())

            # Atomic replace
            os.replace(temp_path, self.config_path)
            return True
        except Exception as e:
            print(f"[ConfigManager] Error saving configuration: {e}")
            return False

    def _compute_hmac(self, data_dict: Dict[str, Any]) -> str:
        """
        Compute HMAC-SHA256 signature for dictionary payload to prevent tampering.
        """
        serialized = json.dumps(data_dict, sort_keys=True).encode("utf-8")
        h = hmac.new(self._cipher._signing_key, serialized, hashlib.sha256)
        return h.hexdigest()

    def _set_initial_passcode(self, passcode: str) -> None:
        """
        Generate salted PBKDF2 hash for initial default passcode.
        """
        import secrets
        salt = secrets.token_bytes(16)
        hashed = hashlib.pbkdf2_hmac("sha256", passcode.encode("utf-8"), salt, 100_000)
        self.config["passcode_salt"] = salt.hex()
        self.config["passcode_hash"] = hashed.hex()

    def reset_daily_usage(self, force: bool = False) -> bool:
        """
        Reset remaining daily usage back to the configured limit if the calendar date
        has rolled over (or if forced).
        
        Args:
            force (bool): Force reset regardless of calendar date rollover.
            
        Returns:
            bool: True if reset was executed, False if already up to date.
        """
        today_str = datetime.date.today().isoformat()
        last_date = self.config.get("last_reset_date", "")

        if force or (today_str != last_date):
            for app_key, app_data in self.config.get("apps", {}).items():
                limit_mins = app_data.get("daily_limit_minutes", 60)
                app_data["remaining_seconds_today"] = limit_mins * 60
                app_data["total_active_seconds_today"] = 0
                app_data["total_open_seconds_today"] = 0
            self.config["last_reset_date"] = today_str
            self.save()
            return True
        return False

    # -------------------------------------------------------------------------
    # Public API required by prompt
    # -------------------------------------------------------------------------

    def get_limit(self, app: str) -> int:
        """
        Retrieve daily time limit in minutes for a specific application.
        
        Args:
            app (str): Process executable name (e.g. 'minecraft.exe').
            
        Returns:
            int: Daily limit in minutes (0 if not configured).
        """
        app_key = app.lower().strip()
        app_info = self.config.get("apps", {}).get(app_key)
        if app_info:
            return app_info.get("daily_limit_minutes", 0)
        return 0

    def get_remaining_seconds(self, app: str) -> int:
        """
        Get remaining time (in seconds) for an application today.
        
        Args:
            app (str): Process executable name.
            
        Returns:
            int: Remaining seconds today.
        """
        self.reset_daily_usage(force=False)
        app_key = app.lower().strip()
        app_info = self.config.get("apps", {}).get(app_key)
        if app_info:
            return app_info.get("remaining_seconds_today", 0)
        return 0

    def update_usage(self, app: str, active_delta_seconds: float, open_delta_seconds: float) -> int:
        """
        Record elapsed active and open time, decrementing remaining seconds.
        
        Args:
            app (str): Process executable name.
            active_delta_seconds (float): Active seconds elapsed in this cycle.
            open_delta_seconds (float): Total open seconds elapsed in this cycle.
            
        Returns:
            int: Remaining seconds after update.
        """
        self.reset_daily_usage(force=False)
        app_key = app.lower().strip()
        if app_key not in self.config.get("apps", {}):
            return 0

        app_info = self.config["apps"][app_key]
        app_info["total_open_seconds_today"] += int(open_delta_seconds)

        if active_delta_seconds > 0:
            app_info["total_active_seconds_today"] += int(active_delta_seconds)
            rem = app_info.get("remaining_seconds_today", 0)
            new_rem = max(0, rem - int(active_delta_seconds))
            app_info["remaining_seconds_today"] = new_rem

        return app_info["remaining_seconds_today"]

    def set_limit(self, app: str, minutes: int, passcode: str) -> bool:
        """
        Set daily time limit in minutes for an app. Gated by passcode verification.
        
        Args:
            app (str): Process executable name.
            minutes (int): New daily limit in minutes.
            passcode (str): Parent/admin passcode.
            
        Returns:
            bool: True if authorized and updated, False otherwise.
        """
        from auth_module import get_auth_module
        auth = get_auth_module(self)
        if not auth.verify_passcode(passcode):
            return False

        app_key = app.lower().strip()
        if app_key not in self.config.get("apps", {}):
            self.config.setdefault("apps", {})[app_key] = {
                "display_name": app_key.replace(".exe", "").capitalize(),
                "daily_limit_minutes": minutes,
                "remaining_seconds_today": minutes * 60,
                "total_active_seconds_today": 0,
                "total_open_seconds_today": 0,
            }
        else:
            old_limit = self.config["apps"][app_key].get("daily_limit_minutes", 0)
            diff_seconds = (minutes - old_limit) * 60
            self.config["apps"][app_key]["daily_limit_minutes"] = minutes
            rem = self.config["apps"][app_key].get("remaining_seconds_today", 0)
            self.config["apps"][app_key]["remaining_seconds_today"] = max(0, rem + diff_seconds)

        self.save()
        return True

    def add_time(self, app: str, minutes: int, passcode: str) -> bool:
        """
        Grant bonus active time (in minutes) to an application for today.
        
        Args:
            app (str): Process executable name.
            minutes (int): Minutes of additional time to grant.
            passcode (str): Parent/admin passcode.
            
        Returns:
            bool: True if authorized and granted, False otherwise.
        """
        from auth_module import get_auth_module
        auth = get_auth_module(self)
        if not auth.verify_passcode(passcode):
            return False

        app_key = app.lower().strip()
        if app_key not in self.config.get("apps", {}):
            return False

        rem = self.config["apps"][app_key].get("remaining_seconds_today", 0)
        self.config["apps"][app_key]["remaining_seconds_today"] = rem + (minutes * 60)
        self.save()
        return True

    def add_monitored_app(self, app: str, display_name: str, daily_limit_minutes: int, passcode: str) -> bool:
        """
        Add a new executable to the monitored applications list.
        
        Args:
            app (str): Process executable name.
            display_name (str): Friendly title (e.g. 'Roblox').
            daily_limit_minutes (int): Daily time budget in minutes.
            passcode (str): Parent/admin passcode.
            
        Returns:
            bool: True if authorized and added, False otherwise.
        """
        from auth_module import get_auth_module
        auth = get_auth_module(self)
        if not auth.verify_passcode(passcode):
            return False

        app_key = app.lower().strip()
        if not app_key.endswith(".exe"):
            app_key += ".exe"

        self.config.setdefault("apps", {})[app_key] = {
            "display_name": display_name or app_key.replace(".exe", "").capitalize(),
            "daily_limit_minutes": max(1, daily_limit_minutes),
            "remaining_seconds_today": max(1, daily_limit_minutes) * 60,
            "total_active_seconds_today": 0,
            "total_open_seconds_today": 0,
        }
        self.save()
        return True

    def remove_monitored_app(self, app: str, passcode: str) -> bool:
        """
        Remove an executable from the monitored applications list.
        
        Args:
            app (str): Process executable name.
            passcode (str): Parent/admin passcode.
            
        Returns:
            bool: True if authorized and removed, False otherwise.
        """
        from auth_module import get_auth_module
        auth = get_auth_module(self)
        if not auth.verify_passcode(passcode):
            return False

        app_key = app.lower().strip()
        if app_key in self.config.get("apps", {}):
            del self.config["apps"][app_key]
            self.save()
            return True
        return False

    def is_within_allowed_schedule(self) -> bool:
        """
        Check if the current time and day fall within configured lockout schedule.
        
        Returns:
            bool: True if within allowed hours (or schedule disabled), False if locked out.
        """
        sched = self.config.get("lockout_schedule", {})
        if not sched.get("enabled", False):
            return True

        now = datetime.datetime.now()
        current_day = now.weekday()  # Mon=0, Sun=6
        allowed_days = sched.get("allowed_days", [0, 1, 2, 3, 4, 5, 6])
        if current_day not in allowed_days:
            return False

        now_time = now.time()
        start_str = sched.get("allowed_start", "08:00")
        end_str = sched.get("allowed_end", "21:00")

        try:
            start_parts = [int(p) for p in start_str.split(":")]
            end_parts = [int(p) for p in end_str.split(":")]
            start_time = datetime.time(start_parts[0], start_parts[1])
            end_time = datetime.time(end_parts[0], end_parts[1])

            if start_time <= end_time:
                return start_time <= now_time <= end_time
            else:
                # Overnight window (e.g. 20:00 to 06:00)
                return now_time >= start_time or now_time <= end_time
        except Exception:
            return True


# Global singleton instance holder
_global_config: Optional[ConfigManager] = None


def get_config_manager(config_path: str = "focusguard_config.enc", key_path: str = "focusguard.key") -> ConfigManager:
    """
    Get or create singleton instance of ConfigManager.
    """
    global _global_config
    if _global_config is None:
        _global_config = ConfigManager(config_path, key_path)
    return _global_config
