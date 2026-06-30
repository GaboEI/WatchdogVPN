from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock
from unittest.mock import patch

from core.watchdog import WatchdogRuntime, build_watchdog, select_driver
from config.state_manager import StateManager
from drivers.base import BaseDriver
from drivers.legacy.adguard_driver import AdGuardDriver
from models.connection_state import ConnectionState
from models.profile import Profile, ProfileSource, ProtocolType


class FakeDriver(BaseDriver):
    def __init__(self) -> None:
        self.connect_mock = Mock(return_value=True)
        self.disconnect_mock = Mock(return_value=True)
        self.health_check_mock = Mock(return_value="ok")
        self.status_mock = Mock(return_value=ConnectionState(status="connected", mode="rules"))
        self.is_available_mock = Mock(return_value=True)

    def connect(self, profile: Profile) -> bool:
        return bool(self.connect_mock(profile))

    def disconnect(self) -> bool:
        return bool(self.disconnect_mock())

    def health_check(self) -> str:
        return str(self.health_check_mock())

    def status(self) -> ConnectionState:
        return self.status_mock()

    def is_available(self) -> bool:
        return bool(self.is_available_mock())


class WatchdogCoreTests(unittest.TestCase):
    def setUp(self) -> None:
        self.profile = Profile(
            id="ad1",
            name="DK",
            protocol=ProtocolType.ADGUARD,
            config={"location": "DK"},
            source=ProfileSource.MANUAL,
        )
        self.tmpdir = tempfile.TemporaryDirectory()
        self.state_manager = StateManager(Path(self.tmpdir.name) / "state.toml")

    def tearDown(self) -> None:
        self.tmpdir.cleanup()

    def set_desired_state(self, desired_state: str) -> None:
        self.state_manager.set("vpn_desired_state", desired_state)

    def test_select_driver_routes_to_adguard(self) -> None:
        driver = select_driver(self.profile)
        self.assertIsInstance(driver, AdGuardDriver)

    @patch.object(AdGuardDriver, "connect", return_value=True)
    @patch.object(AdGuardDriver, "disconnect", return_value=True)
    @patch.object(AdGuardDriver, "health_check", return_value="ok")
    @patch.object(AdGuardDriver, "status", return_value=None)
    def test_runtime_delegates_to_driver_interface(self, status_mock, health_mock, disconnect_mock, connect_mock) -> None:
        self.set_desired_state("on")
        runtime = WatchdogRuntime(driver=AdGuardDriver(), state_manager=self.state_manager)
        self.assertTrue(runtime.connect(self.profile))
        self.assertTrue(runtime.disconnect())
        self.assertEqual(runtime.health_check(), "ok")

    def test_run_iteration_stands_by_when_user_disabled_vpn(self) -> None:
        self.set_desired_state("off")
        driver = FakeDriver()
        runtime = WatchdogRuntime(driver=driver, state_manager=self.state_manager)

        with self.assertLogs("core.watchdog", level="INFO") as logs:
            state = runtime.run_iteration()

        self.assertEqual(state.status, "standby")
        self.assertIn("standby mode - user disabled VPN", "\n".join(logs.output))
        driver.health_check_mock.assert_not_called()
        driver.status_mock.assert_not_called()

    def test_run_iteration_checks_health_when_user_enabled_vpn(self) -> None:
        self.set_desired_state("on")
        driver = FakeDriver()
        runtime = WatchdogRuntime(driver=driver, state_manager=self.state_manager)

        state = runtime.run_iteration()

        self.assertEqual(state.status, "connected")
        driver.health_check_mock.assert_called_once_with()
        driver.status_mock.assert_called_once_with()

    def test_health_check_returns_standby_when_user_disabled_vpn(self) -> None:
        self.set_desired_state("off")
        driver = FakeDriver()
        runtime = WatchdogRuntime(driver=driver, state_manager=self.state_manager)

        self.assertEqual(runtime.health_check(), "standby")
        driver.health_check_mock.assert_not_called()

    def test_build_watchdog_returns_runtime(self) -> None:
        runtime = build_watchdog(self.profile)
        self.assertIsInstance(runtime.driver, AdGuardDriver)


if __name__ == "__main__":
    unittest.main()
