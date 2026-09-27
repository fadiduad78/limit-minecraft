"""
FocusGuard - Authentication & Authorization Module (auth_module.py)
-------------------------------------------------------------------
Provides passcode verification, brute-force rate-limiting, and gatekeeping
for all privileged modifications (altering limits, granting time, modifying
monitored applications, stopping the service, or uninstalling).
"""

import time
import hashlib
import secrets
from typing import Callable, Any, Tuple, Optional, Dict
from config_manager import ConfigManager, get_config_manager


class AuthModule:
    """
    Handles passcode verification, lockout enforcement, and privileged execution.
    
    Attributes:
        config_mgr (ConfigManager): Reference to configuration manager.
        failed_attempts (int): Current counter of consecutive invalid guesses.
        lockout_until (float): Epoch timestamp until which verification is frozen.
    """

    MAX_FAILED_ATTEMPTS: int = 5
    LOCKOUT_DURATION_SECONDS: int = 60
    PBKDF2_ITERATIONS: int = 100_000

    def __init__(self, config_mgr: Optional[ConfigManager] = None):
        """
        Initialize AuthModule with a ConfigManager instance.
        
        Args:
            config_mgr (ConfigManager, optional): Configuration manager instance.
        """
        self.config_mgr = config_mgr or get_config_manager()
        self.failed_attempts: int = 0
        self.lockout_until: float = 0.0

    def is_locked_out(self) -> bool:
        """
        Determine if authentication attempts are currently rate-limited.
        
        Returns:
            bool: True if rate limit lockout is active.
        """
        return time.time() < self.lockout_until

    def get_remaining_lockout_seconds(self) -> int:
        """
        Calculate remaining seconds in current rate-limit lockout.
        
        Returns:
            int: Seconds remaining until passcode attempts are allowed again.
        """
        remaining = self.lockout_until - time.time()
        return max(0, int(remaining))

    def get_lockout_info(self) -> Dict[str, Any]:
        """
        Retrieve current authentication lockout state.
        
        Returns:
            dict: Summary containing is_locked_out, remaining_seconds, and failed_attempts.
        """
        locked = self.is_locked_out()
        return {
            "is_locked_out": locked,
            "remaining_seconds": self.get_remaining_lockout_seconds() if locked else 0,
            "failed_attempts": self.failed_attempts,
            "max_attempts": self.MAX_FAILED_ATTEMPTS
        }

    def verify_passcode(self, passcode: str) -> bool:
        """
        Verify an input passcode against the stored salted hash with rate-limiting.
        
        Args:
            passcode (str): The candidate passcode to verify.
            
        Returns:
            bool: True if passcode matches, False if invalid or locked out.
        """
        now = time.time()
        if now < self.lockout_until:
            # Brute force protection active
            return False

        stored_hash = self.config_mgr.config.get("passcode_hash", "")
        stored_salt = self.config_mgr.config.get("passcode_salt", "")

        if not stored_hash or not stored_salt:
            # Unconfigured or corrupted: fail closed
            return False

        try:
            salt_bytes = bytes.fromhex(stored_salt)
            computed_hash = hashlib.pbkdf2_hmac(
                "sha256",
                passcode.encode("utf-8"),
                salt_bytes,
                self.PBKDF2_ITERATIONS
            ).hex()

            # Constant-time comparison to prevent timing attacks
            import hmac
            matches = hmac.compare_digest(stored_hash, computed_hash)

            if matches:
                # Success: reset failed attempts
                self.failed_attempts = 0
                return True
            else:
                self.failed_attempts += 1
                if self.failed_attempts >= self.MAX_FAILED_ATTEMPTS:
                    self.lockout_until = now + self.LOCKOUT_DURATION_SECONDS
                return False
        except Exception as e:
            print(f"[AuthModule] Verification error: {e}")
            return False

    def change_passcode(self, current_passcode: str, new_passcode: str) -> Tuple[bool, str]:
        """
        Update parent passcode after authenticating the current one.
        
        Args:
            current_passcode (str): Existing passcode.
            new_passcode (str): New passcode (must be at least 4 chars).
            
        Returns:
            Tuple[bool, str]: (Success flag, descriptive message).
        """
        if not self.verify_passcode(current_passcode):
            if self.is_locked_out():
                return False, f"Too many failed attempts. Locked out for {self.get_remaining_lockout_seconds()}s."
            return False, "Incorrect current passcode."

        if not new_passcode or len(new_passcode.strip()) < 4:
            return False, "New passcode must be at least 4 characters long."

        salt = secrets.token_bytes(16)
        hashed = hashlib.pbkdf2_hmac(
            "sha256",
            new_passcode.encode("utf-8"),
            salt,
            self.PBKDF2_ITERATIONS
        )

        self.config_mgr.config["passcode_salt"] = salt.hex()
        self.config_mgr.config["passcode_hash"] = hashed.hex()
        self.config_mgr.save()
        return True, "Passcode updated successfully."

    def execute_privileged_action(
        self,
        passcode: str,
        action_func: Callable[..., Any],
        *args: Any,
        **kwargs: Any
    ) -> Tuple[bool, Any, str]:
        """
        Gatekeep any privileged function call behind verified passcode and rate-limiting.
        
        Args:
            passcode (str): The provided passcode.
            action_func (Callable): Function to execute if verified.
            *args: Positional arguments for action_func.
            **kwargs: Keyword arguments for action_func.
            
        Returns:
            Tuple[bool, Any, str]: (Success flag, function return value, status/error message).
        """
        if self.is_locked_out():
            secs = self.get_remaining_lockout_seconds()
            return False, None, f"Rate-limit lockout active! Retry in {secs} seconds."

        if not self.verify_passcode(passcode):
            attempts_left = max(0, self.MAX_FAILED_ATTEMPTS - self.failed_attempts)
            if attempts_left == 0:
                return False, None, f"Invalid passcode. Locked out for {self.LOCKOUT_DURATION_SECONDS} seconds."
            return False, None, f"Invalid passcode. {attempts_left} attempt(s) remaining before lockout."

        try:
            result = action_func(*args, **kwargs)
            return True, result, "Action executed successfully."
        except Exception as e:
            return False, None, f"Execution failed: {str(e)}"


# Singleton instance
_global_auth: Optional[AuthModule] = None


def get_auth_module(config_mgr: Optional[ConfigManager] = None) -> AuthModule:
    """
    Get or create singleton instance of AuthModule.
    """
    global _global_auth
    if _global_auth is None:
        _global_auth = AuthModule(config_mgr)
    return _global_auth
