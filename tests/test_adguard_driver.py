from __future__ import annotations

import unittest
from unittest.mock import patch

from drivers.legacy.adguard_driver import AdGuardDriver
from models.profile import Profile, ProfileSource, ProtocolType


class AdGuardDriverTests(unittest.TestCase):
    def setUp(self) -> None:
        self.driver = AdGuardDriver()
        self.profile = Profile(
            id="ad1",
            name="DK",
            protocol=ProtocolType.ADGUARD,
            config={"location": "DK"},
            source=ProfileSource.MANUAL,
        )

    @patch.object(AdGuardDriver, "_run")
    def test_connect_uses_vpnctl_connect(self, run_mock) -> None:
        run_mock.return_value.returncode = 0
        self.assertTrue(self.driver.connect(self.profile))
        run_mock.assert_called_once()
        args = run_mock.call_args.args[0]
        self.assertEqual(args[1:3], ["connect", "DK"])

    @patch.object(AdGuardDriver, "_run")
    def test_disconnect_uses_vpnctl_disconnect(self, run_mock) -> None:
        run_mock.return_value.returncode = 0
        self.assertTrue(self.driver.disconnect())
        run_mock.assert_called_once()
        self.assertEqual(run_mock.call_args.args[0][1], "disconnect")

    @patch.object(AdGuardDriver, "_truth_data", return_value={"STATUS": "UP", "TUN": "UP"})
    def test_health_check_ok(self, truth_mock) -> None:
        self.assertEqual(self.driver.health_check(), "ok")

    @patch.object(AdGuardDriver, "_truth_data", return_value={"STATUS": "DEGRADED", "TUN": "UP"})
    def test_health_check_degraded(self, truth_mock) -> None:
        self.assertEqual(self.driver.health_check(), "degraded")

    @patch.object(AdGuardDriver, "_truth_data", return_value={"STATUS": "DOWN", "TUN": "DOWN"})
    def test_health_check_down(self, truth_mock) -> None:
        self.assertEqual(self.driver.health_check(), "down")

    @patch.object(AdGuardDriver, "_truth_data", return_value={"STATUS": "UP", "TUN": "UP"})
    def test_status_maps_to_connection_state(self, truth_mock) -> None:
        state = self.driver.status()
        self.assertEqual(state.status, "connected")
        self.assertTrue(state.tun_active)

    @patch("drivers.legacy.adguard_driver.shutil.which", return_value="/usr/local/bin/vpnctl")
    @patch("drivers.legacy.adguard_driver.os.path.exists", return_value=True)
    def test_is_available_checks_required_binaries(self, exists_mock, which_mock) -> None:
        self.assertTrue(self.driver.is_available())


if __name__ == "__main__":
    unittest.main()
