from __future__ import annotations

import unittest
from unittest.mock import patch

from core.watchdog import WatchdogRuntime, build_watchdog, select_driver
from drivers.legacy.adguard_driver import AdGuardDriver
from models.profile import Profile, ProfileSource, ProtocolType


class WatchdogCoreTests(unittest.TestCase):
    def setUp(self) -> None:
        self.profile = Profile(
            id="ad1",
            name="DK",
            protocol=ProtocolType.ADGUARD,
            config={"location": "DK"},
            source=ProfileSource.MANUAL,
        )

    def test_select_driver_routes_to_adguard(self) -> None:
        driver = select_driver(self.profile)
        self.assertIsInstance(driver, AdGuardDriver)

    @patch.object(AdGuardDriver, "connect", return_value=True)
    @patch.object(AdGuardDriver, "disconnect", return_value=True)
    @patch.object(AdGuardDriver, "health_check", return_value="ok")
    @patch.object(AdGuardDriver, "status", return_value=None)
    def test_runtime_delegates_to_driver_interface(self, status_mock, health_mock, disconnect_mock, connect_mock) -> None:
        runtime = WatchdogRuntime(driver=AdGuardDriver())
        self.assertTrue(runtime.connect(self.profile))
        self.assertTrue(runtime.disconnect())
        self.assertEqual(runtime.health_check(), "ok")

    def test_build_watchdog_returns_runtime(self) -> None:
        runtime = build_watchdog(self.profile)
        self.assertIsInstance(runtime.driver, AdGuardDriver)


if __name__ == "__main__":
    unittest.main()
