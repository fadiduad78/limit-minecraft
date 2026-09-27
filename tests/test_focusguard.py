"""
Unit & Integration Tests for FocusGuard
"""

import os
import sys
import time
import shutil
import unittest
from unittest.mock import MagicMock, patch

# Ensure workspace root is in python path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from config_manager import ConfigManager
from auth_module import AuthModule
from logger_module import LoggerModule
from process_monitor import ProcessMonitor, AppState, InputActivityTracker
from enforcement_module import EnforcementModule
from watchdog_module import WatchdogManager, SHUTDOWN_TOKEN_FILE


class TestFocusGuardSuite(unittest.TestCase):

    def setUp(self):
        self.test_dir = "/tmp/fg_test"
        os.makedirs(self.test_dir, exist_ok=True)
        self.config_path = os.path.join(self.test_dir, "test_config.enc")
        self.key_path = os.path.join(self.test_dir, "test.key")
        self.log_path = os.path.join(self.test_dir, "test.log")

        self.config_mgr = ConfigManager(self.config_path, self.key_path)
        self.auth_mod = AuthModule(self.config_mgr)
        self.logger = LoggerModule(self.log_path)

    def tearDown(self):
        if os.path.exists(self.test_dir):
            shutil.rmtree(self.test_dir, ignore_errors=True)
        if os.path.exists(SHUTDOWN_TOKEN_FILE):
            os.remove(SHUTDOWN_TOKEN_FILE)

    def test_config_encryption_and_tamper_protection(self):
        """Verify configuration is stored encrypted and HMAC prevents tampering."""
        self.assertTrue(os.path.exists(self.config_path))
        with open(self.config_path, "rb") as f:
            raw_data = f.read()

        # Must not be plaintext JSON
        self.assertNotIn(b"minecraft.exe", raw_data)

        # Verify correct decryption
        app_limit = self.config_mgr.get_limit("minecraft.exe")
        self.assertEqual(app_limit, 60)

        # Modify raw file to simulate attacker tampering
        corrupted = bytearray(raw_data)
        corrupted[20] ^= 0xFF
        with open(self.config_path, "wb") as f:
            f.write(corrupted)

        # Reload should detect tampering and revert safely to defaults
        new_mgr = ConfigManager(self.config_path, self.key_path)
        self.assertEqual(new_mgr.get_limit("minecraft.exe"), 60)

    def test_auth_rate_limiting(self):
        """Verify brute-force rate-limiting locks out after 5 consecutive failed attempts."""
        # Default initial passcode is '1234'
        self.assertTrue(self.auth_mod.verify_passcode("1234"))

        # 4 wrong attempts should not lock out yet
        for i in range(4):
            self.assertFalse(self.auth_mod.verify_passcode("wrong"))
            self.assertFalse(self.auth_mod.is_locked_out())

        # 5th wrong attempt triggers lockout
        self.assertFalse(self.auth_mod.verify_passcode("wrong"))
        self.assertTrue(self.auth_mod.is_locked_out())
        self.assertGreater(self.auth_mod.get_remaining_lockout_seconds(), 0)

        # Even correct passcode must now be rejected while locked out
        self.assertFalse(self.auth_mod.verify_passcode("1234"))

    def test_privileged_actions_gated(self):
        """Verify add_time and set_limit require passcode verification."""
        # Initial limit is 60 min, remaining 3600 sec
        self.assertEqual(self.config_mgr.get_remaining_seconds("minecraft.exe"), 3600)

        # Invalid passcode fails
        ok = self.config_mgr.add_time("minecraft.exe", 30, "wrong_pass")
        self.assertFalse(ok)
        self.assertEqual(self.config_mgr.get_remaining_seconds("minecraft.exe"), 3600)

        # Correct passcode grants time (+30 min = +1800s => 5400s)
        ok = self.config_mgr.add_time("minecraft.exe", 30, "1234")
        self.assertTrue(ok)
        self.assertEqual(self.config_mgr.get_remaining_seconds("minecraft.exe"), 5400)

        # Set limit
        ok = self.config_mgr.set_limit("minecraft.exe", 120, "1234")
        self.assertTrue(ok)
        self.assertEqual(self.config_mgr.get_limit("minecraft.exe"), 120)

    def test_input_activity_tracker(self):
        """Test rolling input activity window and threshold logic."""
        tracker = InputActivityTracker(window_seconds=1.0, min_event_threshold=3)
        self.assertEqual(tracker.get_event_count(), 0)
        self.assertFalse(tracker.is_active_input_rate())

        # Record 2 events (below threshold of 3)
        tracker.record_event()
        tracker.record_event()
        self.assertEqual(tracker.get_event_count(), 2)
        self.assertFalse(tracker.is_active_input_rate())

        # 3rd event reaches threshold
        tracker.record_event()
        self.assertEqual(tracker.get_event_count(), 3)
        self.assertTrue(tracker.is_active_input_rate())

        # Wait for rolling window to expire
        time.sleep(1.1)
        self.assertEqual(tracker.get_event_count(), 0)
        self.assertFalse(tracker.is_active_input_rate())

    def test_process_monitor_state_machine_and_budget_decrement(self):
        """Verify state machine: only RUNNING_ACTIVE decrements daily remaining time."""
        monitor = ProcessMonitor(self.config_mgr, self.logger)

        # Set remaining time to 100 seconds
        self.config_mgr.config["apps"]["testapp.exe"] = {
            "display_name": "Test App",
            "daily_limit_minutes": 10,
            "remaining_seconds_today": 100,
            "total_active_seconds_today": 0,
            "total_open_seconds_today": 0
        }

        # Case 1: NOT_RUNNING -> remaining time does not decrease
        with patch("psutil.process_iter", return_value=[]):
            res = monitor.poll_once()
            self.assertEqual(res["testapp.exe"]["state"], AppState.NOT_RUNNING.value)
            self.assertEqual(self.config_mgr.get_remaining_seconds("testapp.exe"), 100)

        # Mock a running process
        mock_proc = MagicMock()
        mock_proc.info = {"pid": 9999, "name": "testapp.exe"}

        # Case 2: Running, but NOT in foreground (RUNNING_BACKGROUND) -> budget preserved
        with patch("psutil.process_iter", return_value=[mock_proc]), \
             patch("win32_compat.get_foreground_window_pid", return_value=8888):  # Different PID focused
            res = monitor.poll_once()
            self.assertEqual(res["testapp.exe"]["state"], AppState.RUNNING_BACKGROUND.value)
            self.assertEqual(self.config_mgr.get_remaining_seconds("testapp.exe"), 100)

        # Case 3: Running, foreground, but IDLE (e.g. idle 70s > 60s threshold) -> RUNNING_IDLE -> budget preserved
        with patch("psutil.process_iter", return_value=[mock_proc]), \
             patch("win32_compat.get_foreground_window_pid", return_value=9999), \
             patch("win32_compat.get_system_idle_seconds", return_value=70.0):
            res = monitor.poll_once()
            self.assertEqual(res["testapp.exe"]["state"], AppState.RUNNING_IDLE.value)
            self.assertEqual(self.config_mgr.get_remaining_seconds("testapp.exe"), 100)

        # Case 4: Running, foreground, NOT idle (< 60s), and ACTIVE input -> RUNNING_ACTIVE
        # Add required events to input tracker
        for _ in range(6):
            monitor.input_tracker.record_event()

        with patch("psutil.process_iter", return_value=[mock_proc]), \
             patch("win32_compat.get_foreground_window_pid", return_value=9999), \
             patch("win32_compat.get_system_idle_seconds", return_value=2.0):
            # Advance poll
            monitor.app_states["testapp.exe"]["last_poll"] = time.time() - 10.0  # 10s elapsed
            res = monitor.poll_once()
            self.assertEqual(res["testapp.exe"]["state"], AppState.RUNNING_ACTIVE.value)
            # Budget should be decremented by ~10 seconds
            rem = self.config_mgr.get_remaining_seconds("testapp.exe")
            self.assertLessEqual(rem, 90)

    def test_enforcement_and_cooldown_relaunch_kill(self):
        """Verify enforcement terminates process and suppresses relaunch during cooldown."""
        ui_mock = MagicMock()
        enforcement = EnforcementModule(self.config_mgr, self.auth_mod, self.logger, ui_mock)

        # Trigger termination
        with patch.object(enforcement, "force_kill_process_tree") as mock_kill:
            enforcement.handle_termination_request("minecraft.exe", 1234, "TIME_EXHAUSTED")
            mock_kill.assert_called_once_with(1234, "minecraft.exe", "TIME_EXHAUSTED")
            ui_mock.show_lockout_screen.assert_called_once()
            self.assertTrue(enforcement.is_in_cooldown("minecraft.exe"))

        # User attempts to relaunch during active cooldown
        with patch.object(enforcement, "force_kill_process_tree") as mock_kill:
            enforcement.handle_app_started("minecraft.exe", 5678)
            # Must kill new PID instantly
            self.assertTrue(mock_kill.called)
            self.assertEqual(mock_kill.call_args[0][0], 5678)

        # Authorized unlock clears cooldown
        enforcement.clear_cooldown("minecraft.exe")
        self.assertFalse(enforcement.is_in_cooldown("minecraft.exe"))

    def test_watchdog_shutdown_token(self):
        """Verify authorized shutdown token creation and verification."""
        # Wrong passcode cannot create shutdown token
        self.assertFalse(WatchdogManager.create_shutdown_token("wrong"))
        self.assertFalse(WatchdogManager.is_authorized_shutdown())

        # Correct passcode creates valid shutdown token
        self.assertTrue(WatchdogManager.create_shutdown_token("1234"))
        self.assertTrue(WatchdogManager.is_authorized_shutdown())

        # Cleanup
        WatchdogManager.consume_shutdown_token()
        self.assertFalse(WatchdogManager.is_authorized_shutdown())


if __name__ == "__main__":
    unittest.main()
