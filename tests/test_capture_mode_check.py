from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from config.state_manager import StateManager
from diagnostics.capture_mode_check import diagnose_capture_mode


class CaptureModeCheckTests(unittest.TestCase):
    def test_default_state_is_ok(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            manager = StateManager(Path(tmp) / "state.toml")

            result = diagnose_capture_mode(manager)

            self.assertEqual(result.status, "ok")
            self.assertIn("tun", result.capture_modes)

    def test_rules_policy_without_tun_warns(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            manager = StateManager(Path(tmp) / "state.toml")
            manager.set("active_mode", "proxy")

            result = diagnose_capture_mode(manager)

            self.assertEqual(result.status, "warn")
            self.assertEqual(result.routing_policy, "global")
            self.assertEqual(result.default_route_action, "current")
            self.assertNotIn("tun", result.capture_modes)
            self.assertIn("capture_modes has no tun", result.message)
            self.assertIn("watchdog config set capture-modes local_proxy,tun", result.message)

    def test_direct_default_route_action_without_tun_is_ok(self) -> None:
        # default_route_action="direct" means "always bypass the VPN", so
        # lacking tun capture is the deliberate, correct outcome, not a risk.
        with tempfile.TemporaryDirectory() as tmp:
            manager = StateManager(Path(tmp) / "state.toml")
            manager.set("active_mode", "direct")

            result = diagnose_capture_mode(manager)

            self.assertEqual(result.status, "ok")
            self.assertEqual(result.default_route_action, "direct")

    def test_to_lines_round_trip_shape(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            manager = StateManager(Path(tmp) / "state.toml")

            result = diagnose_capture_mode(manager)
            lines = result.to_lines()

            self.assertTrue(any(line.startswith("STATUS=") for line in lines))
            self.assertTrue(any(line.startswith("CAPTURE_MODES=") for line in lines))
            self.assertTrue(any(line.startswith("ROUTING_POLICY=") for line in lines))
            self.assertTrue(any(line.startswith("DEFAULT_ROUTE_ACTION=") for line in lines))
            self.assertTrue(any(line.startswith("MESSAGE=") for line in lines))


if __name__ == "__main__":
    unittest.main()
