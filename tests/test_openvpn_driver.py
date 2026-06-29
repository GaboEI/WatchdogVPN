from __future__ import annotations

import subprocess
import unittest
from unittest.mock import patch

from drivers.openvpn_driver import CONFIG_PATH, OpenVPNDriver
from models.profile import Profile, ProfileSource, ProtocolType


class OpenVPNDriverTests(unittest.TestCase):
    def setUp(self) -> None:
        self.driver = OpenVPNDriver()
        self.profile = Profile(
            id="openvpn-1",
            name="openvpn-demo",
            protocol=ProtocolType.OPENVPN,
            config={
                "raw_config": "client\ndev tun\nproto udp\nremote vpn.example.com 1194\n",
                "dev": "tun0",
            },
            source=ProfileSource.MANUAL,
        )

    @patch("drivers.openvpn_driver.shutil.which", return_value="/usr/sbin/openvpn")
    @patch("drivers.openvpn_driver.os.path.exists", return_value=False)
    @patch("drivers.openvpn_driver.os.access", return_value=False)
    def test_find_binary_falls_back_to_which(self, access_mock, exists_mock, which_mock) -> None:
        self.assertEqual(self.driver.find_openvpn_binary(), "/usr/sbin/openvpn")

    @patch.dict("drivers.openvpn_driver.os.environ", {"WATCHDOGVPN_OPENVPN_BIN": "/opt/openvpn"})
    @patch("drivers.openvpn_driver.os.path.exists", return_value=True)
    @patch("drivers.openvpn_driver.os.access", return_value=True)
    def test_find_binary_accepts_env_override(self, access_mock, exists_mock) -> None:
        self.assertEqual(self.driver.find_openvpn_binary(), "/opt/openvpn")

    @patch.object(OpenVPNDriver, "find_openvpn_binary", return_value="/usr/sbin/openvpn")
    @patch("drivers.openvpn_driver.subprocess.run")
    def test_check_version_returns_output(self, run_mock, binary_mock) -> None:
        run_mock.return_value.stdout = "OpenVPN 2.6.0"
        run_mock.return_value.stderr = ""
        self.assertEqual(self.driver.check_version(), "OpenVPN 2.6.0")
        run_mock.assert_called_once_with(
            ["/usr/sbin/openvpn", "--version"],
            text=True,
            capture_output=True,
            check=False,
        )

    @patch.object(OpenVPNDriver, "find_openvpn_binary", return_value=None)
    def test_check_version_raises_when_missing(self, binary_mock) -> None:
        with self.assertRaises(FileNotFoundError):
            self.driver.check_version()

    @patch.object(OpenVPNDriver, "find_openvpn_binary", return_value="/usr/sbin/openvpn")
    def test_is_available_uses_binary_presence(self, binary_mock) -> None:
        self.assertTrue(self.driver.is_available())

    @patch.object(OpenVPNDriver, "find_openvpn_binary", return_value=None)
    def test_is_available_is_false_when_missing(self, binary_mock) -> None:
        self.assertFalse(self.driver.is_available())

    def test_generate_openvpn_config_writes_temp_file(self) -> None:
        try:
            raw_config = self.driver.generate_openvpn_config(self.profile)
            self.assertIn("remote vpn.example.com 1194", raw_config)
            self.assertEqual(CONFIG_PATH.read_text(encoding="utf-8"), self.profile.config["raw_config"])
        finally:
            CONFIG_PATH.unlink(missing_ok=True)

    def test_generate_openvpn_config_rejects_non_openvpn_profile(self) -> None:
        profile = Profile("vless-1", "vless", ProtocolType.VLESS, {}, ProfileSource.MANUAL)
        with self.assertRaises(ValueError):
            self.driver.generate_openvpn_config(profile)

    def test_generate_openvpn_config_rejects_wrapped_profile(self) -> None:
        profile = Profile(
            "wrapped-1",
            "wrapped",
            ProtocolType.OPENVPN,
            {"raw_config": "client\nremote vpn.example.com 1194\n", "wrapper": "cloak"},
            ProfileSource.MANUAL,
        )
        with self.assertRaises(ValueError):
            self.driver.generate_openvpn_config(profile)

    @patch.object(OpenVPNDriver, "find_openvpn_binary", return_value="/usr/sbin/openvpn")
    @patch.object(OpenVPNDriver, "generate_openvpn_config")
    @patch("drivers.openvpn_driver.subprocess.Popen")
    def test_connect_starts_process(self, popen_mock, generate_mock, binary_mock) -> None:
        process = popen_mock.return_value
        process.poll.return_value = None

        self.assertTrue(self.driver.connect(self.profile))
        generate_mock.assert_called_once_with(self.profile)
        popen_mock.assert_called_once()
        self.assertEqual(popen_mock.call_args.args[0], ["/usr/sbin/openvpn", "--config", str(CONFIG_PATH)])
        self.assertIs(self.driver._process, process)
        self.assertIs(self.driver._active_profile, self.profile)
        self.assertIsNotNone(self.driver._connected_at)

    @patch.object(OpenVPNDriver, "find_openvpn_binary", return_value=None)
    @patch("drivers.openvpn_driver.subprocess.Popen")
    def test_connect_returns_false_when_binary_missing(self, popen_mock, binary_mock) -> None:
        self.assertFalse(self.driver.connect(self.profile))
        popen_mock.assert_not_called()

    @patch.object(OpenVPNDriver, "_cleanup_config")
    def test_disconnect_terminates_and_cleans_config(self, cleanup_mock) -> None:
        process = unittest.mock.Mock()
        process.poll.return_value = None
        self.driver._process = process
        self.driver._active_profile = self.profile
        self.driver._connected_at = unittest.mock.sentinel.connected_at

        self.assertTrue(self.driver.disconnect())
        process.terminate.assert_called_once()
        process.wait.assert_called()
        cleanup_mock.assert_called_once()
        self.assertIsNone(self.driver._process)
        self.assertIsNone(self.driver._active_profile)
        self.assertIsNone(self.driver._connected_at)

    @patch.object(OpenVPNDriver, "_cleanup_config")
    def test_disconnect_kills_hung_process(self, cleanup_mock) -> None:
        process = unittest.mock.Mock()
        process.poll.return_value = None
        process.wait.side_effect = [subprocess.TimeoutExpired(cmd="openvpn", timeout=5), None]
        self.driver._process = process

        self.assertTrue(self.driver.disconnect())
        process.terminate.assert_called_once()
        process.kill.assert_called_once()
        self.assertEqual(process.wait.call_count, 2)
        cleanup_mock.assert_called_once()

    def test_status_returns_standby_without_process(self) -> None:
        self.assertEqual(self.driver.status().status, "standby")

    @patch.object(OpenVPNDriver, "_vpn_interface_active", return_value=True)
    def test_status_returns_connected_when_process_alive(self, tun_mock) -> None:
        process = unittest.mock.Mock()
        process.poll.return_value = None
        self.driver._process = process
        self.driver._active_profile = self.profile

        state = self.driver.status()
        self.assertEqual(state.status, "connected")
        self.assertEqual(state.mode, "openvpn")
        self.assertTrue(state.tun_active)
        self.assertFalse(state.proxy_active)

    def test_health_check_down_without_process(self) -> None:
        self.assertEqual(self.driver.health_check(), "down")

    @patch.object(OpenVPNDriver, "_vpn_interface_active", return_value=False)
    def test_health_check_degraded_without_tun(self, tun_mock) -> None:
        process = unittest.mock.Mock()
        process.poll.return_value = None
        self.driver._process = process
        self.assertEqual(self.driver.health_check(), "degraded")

    @patch.object(OpenVPNDriver, "_vpn_interface_active", return_value=True)
    def test_health_check_ok_with_process_and_tun(self, tun_mock) -> None:
        process = unittest.mock.Mock()
        process.poll.return_value = None
        self.driver._process = process
        self.assertEqual(self.driver.health_check(), "ok")


if __name__ == "__main__":
    unittest.main()
