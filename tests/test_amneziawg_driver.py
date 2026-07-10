from __future__ import annotations

import subprocess
import unittest
from unittest.mock import Mock, patch

from drivers.amneziawg_driver import (
    CONFIG_NAME,
    HANDSHAKE_TIMEOUT_SECONDS,
    INTERFACE_NAME,
    AmneziaWGDriver,
)
from models.profile import Profile, ProfileSource, ProtocolType


AWG_RAW_CONFIG = """\
[Interface]
Address = 10.8.1.5/32
DNS = 1.1.1.1
PrivateKey = fakePrivateKey123=
Jc = 4
Jmin = 10
Jmax = 50
S1 = 99
S2 = 137

[Peer]
PublicKey = fakePeerPublicKey456=
AllowedIPs = 0.0.0.0/0, ::/0
Endpoint = 192.0.2.1:51820
PersistentKeepalive = 25
"""


class AmneziaWGDriverTests(unittest.TestCase):
    def setUp(self) -> None:
        self.driver = AmneziaWGDriver()
        self.profile = Profile(
            id="awg-test-1",
            name="awg-paris",
            protocol=ProtocolType.AMNEZIAWG,
            config={"raw": AWG_RAW_CONFIG},
            source=ProfileSource.MANUAL,
        )

    def tearDown(self) -> None:
        self.driver._cleanup_runtime()

    # --- Binary detection ---

    @patch("drivers.amneziawg_driver.shutil.which", return_value="/usr/bin/awg-quick")
    @patch("drivers.amneziawg_driver.os.path.exists", return_value=False)
    @patch("drivers.amneziawg_driver.os.access", return_value=False)
    def test_find_quick_tool_falls_back_to_which(self, _access, _exists, _which) -> None:
        self.assertEqual(self.driver.find_quick_tool(), "/usr/bin/awg-quick")

    @patch("drivers.amneziawg_driver.os.path.exists", return_value=True)
    @patch("drivers.amneziawg_driver.os.access", return_value=True)
    def test_find_quick_tool_prefers_awg_quick(self, _access, _exists) -> None:
        result = self.driver.find_quick_tool()
        self.assertEqual(result, "/usr/local/bin/awg-quick")

    @patch("drivers.amneziawg_driver.shutil.which", side_effect=lambda n: "/usr/bin/wg-quick" if n == "wg-quick" else None)
    @patch("drivers.amneziawg_driver.os.path.exists", return_value=False)
    @patch("drivers.amneziawg_driver.os.access", return_value=False)
    def test_find_quick_tool_fallback_wg_quick(self, _access, _exists, _which) -> None:
        result = self.driver.find_quick_tool()
        self.assertEqual(result, "/usr/bin/wg-quick")

    @patch.dict("drivers.amneziawg_driver.os.environ", {"WATCHDOGVPN_AMNEZIAWG_BIN": "/opt/awg-quick"})
    @patch("drivers.amneziawg_driver.os.path.exists", return_value=True)
    @patch("drivers.amneziawg_driver.os.access", return_value=True)
    def test_find_quick_tool_env_var_override(self, _access, _exists) -> None:
        self.assertEqual(self.driver.find_quick_tool(), "/opt/awg-quick")

    @patch("drivers.amneziawg_driver.shutil.which", return_value=None)
    @patch("drivers.amneziawg_driver.os.path.exists", return_value=False)
    @patch("drivers.amneziawg_driver.os.access", return_value=False)
    def test_find_quick_tool_none_when_missing(self, _access, _exists, _which) -> None:
        self.assertIsNone(self.driver.find_quick_tool())

    @patch.object(AmneziaWGDriver, "check_version", return_value="amneziawg-tools v1.0.0")
    @patch.object(AmneziaWGDriver, "find_quick_tool", return_value="/usr/bin/awg-quick")
    def test_is_available_true(self, _tool, _version) -> None:
        self.assertTrue(self.driver.is_available())

    @patch.object(AmneziaWGDriver, "find_quick_tool", return_value=None)
    def test_is_available_false(self, _tool) -> None:
        self.assertFalse(self.driver.is_available())

    @patch.object(AmneziaWGDriver, "find_quick_tool", return_value=None)
    def test_get_tool_raises_when_missing(self, _tool) -> None:
        with self.assertRaises(FileNotFoundError):
            self.driver.get_tool()

    @patch.object(AmneziaWGDriver, "find_wg_tool", return_value="/usr/bin/awg")
    @patch("drivers.amneziawg_driver.subprocess.run")
    def test_check_version_returns_output(self, run_mock, _wg) -> None:
        run_mock.return_value.stdout = "amneziawg-tools v1.0.0"
        run_mock.return_value.stderr = ""
        self.assertEqual(self.driver.check_version(), "amneziawg-tools v1.0.0")
        run_mock.assert_called_once_with(
            ["/usr/bin/awg", "--version"],
            text=True,
            capture_output=True,
            check=False,
        )

    @patch.object(AmneziaWGDriver, "find_wg_tool", return_value=None)
    def test_check_version_raises_when_missing(self, _wg) -> None:
        with self.assertRaises(FileNotFoundError):
            self.driver.check_version()

    # --- Config ---

    def test_write_config_creates_temp_file(self) -> None:
        self.driver._write_config(self.profile)
        self.assertIsNotNone(self.driver._config_path)
        self.assertEqual(self.driver._config_path.name, CONFIG_NAME)
        self.assertEqual(self.driver._config_path.stem, INTERFACE_NAME)
        self.assertTrue(self.driver._config_path.exists())
        content = self.driver._config_path.read_text(encoding="utf-8")
        self.assertIn("[Interface]", content)
        self.assertIn("Jc = 4", content)

    def test_write_config_rejects_non_amneziawg(self) -> None:
        profile = Profile("wg-1", "wg", ProtocolType.WIREGUARD, {"raw": "test"}, ProfileSource.MANUAL)
        with self.assertRaises(ValueError):
            self.driver._write_config(profile)

    def test_write_config_rejects_missing_raw(self) -> None:
        profile = Profile("awg-2", "awg", ProtocolType.AMNEZIAWG, {}, ProfileSource.MANUAL)
        with self.assertRaises(ValueError):
            self.driver._write_config(profile)

    def test_cleanup_runtime_removes_file(self) -> None:
        self.driver._write_config(self.profile)
        config_path = self.driver._config_path
        self.driver._cleanup_runtime()
        self.assertIsNotNone(config_path)
        self.assertFalse(config_path.exists())

    def test_cleanup_runtime_no_error_when_missing(self) -> None:
        self.driver._cleanup_runtime()

    # --- Connect ---

    @patch.object(AmneziaWGDriver, "_interface_exists", side_effect=[False, True])
    @patch.object(AmneziaWGDriver, "find_quick_tool", return_value="/usr/bin/awg-quick")
    @patch("drivers.amneziawg_driver.subprocess.run")
    def test_connect_success(self, run_mock, _tool, _iface) -> None:
        run_mock.return_value.returncode = 0
        run_mock.return_value.stdout = ""
        run_mock.return_value.stderr = ""

        self.assertTrue(self.driver.connect(self.profile))
        self.assertIsNotNone(self.driver._config_path)
        run_mock.assert_called_once_with(
            ["/usr/bin/awg-quick", "up", str(self.driver._config_path)],
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertIs(self.driver._active_profile, self.profile)
        self.assertIsNotNone(self.driver._connected_at)

    @patch.object(AmneziaWGDriver, "find_quick_tool", return_value="/usr/bin/awg-quick")
    @patch("drivers.amneziawg_driver.subprocess.run")
    def test_connect_failure_cleans_up(self, run_mock, _tool) -> None:
        run_mock.return_value.returncode = 1
        run_mock.return_value.stdout = ""
        run_mock.return_value.stderr = "error"

        self.assertFalse(self.driver.connect(self.profile))
        self.assertIsNone(self.driver._config_path)
        self.assertIsNone(self.driver._active_profile)

    @patch.object(AmneziaWGDriver, "find_quick_tool", return_value=None)
    def test_connect_returns_false_when_no_binary(self, _tool) -> None:
        self.assertFalse(self.driver.connect(self.profile))

    # --- Disconnect ---

    @patch.object(AmneziaWGDriver, "_interface_exists", return_value=False)
    @patch.object(AmneziaWGDriver, "find_quick_tool", return_value="/usr/bin/awg-quick")
    @patch("drivers.amneziawg_driver.subprocess.run")
    def test_disconnect_success(self, run_mock, _tool, _iface) -> None:
        self.driver._write_config(self.profile)
        config_path = self.driver._config_path
        self.driver._active_profile = self.profile
        self.driver._connected_at = Mock()

        run_mock.return_value.returncode = 0
        run_mock.return_value.stdout = ""
        run_mock.return_value.stderr = ""

        self.assertTrue(self.driver.disconnect())
        self.assertIsNone(self.driver._active_profile)
        self.assertIsNone(self.driver._connected_at)
        self.assertIsNotNone(config_path)
        self.assertFalse(config_path.exists())

    @patch.object(AmneziaWGDriver, "_delete_interface", return_value=False)
    @patch.object(AmneziaWGDriver, "_interface_exists", return_value=True)
    @patch.object(AmneziaWGDriver, "find_quick_tool", return_value="/usr/bin/awg-quick")
    @patch("drivers.amneziawg_driver.subprocess.run")
    def test_connect_refuses_stale_interface_when_delete_fails(self, run_mock, _tool, _iface, delete_mock) -> None:
        self.assertFalse(self.driver.connect(self.profile))
        delete_mock.assert_called_once()
        run_mock.assert_not_called()

    @patch.object(AmneziaWGDriver, "_interface_exists", return_value=False)
    def test_disconnect_without_connect_no_crash(self, _iface) -> None:
        self.assertTrue(self.driver.disconnect())

    # --- Health Check ---

    @patch.object(AmneziaWGDriver, "_interface_exists", return_value=False)
    def test_health_check_down_without_interface(self, _iface) -> None:
        self.assertEqual(self.driver.health_check(), "down")

    @patch.object(AmneziaWGDriver, "_ping_through_interface", return_value=True)
    @patch.object(AmneziaWGDriver, "_latest_handshake_age", return_value=30)
    @patch.object(AmneziaWGDriver, "_interface_exists", return_value=True)
    def test_health_check_ok(self, _iface, _hs, _ping) -> None:
        self.driver._active_profile = self.profile
        self.assertEqual(self.driver.health_check(), "ok")

    @patch.object(AmneziaWGDriver, "_latest_handshake_age", return_value=None)
    @patch.object(AmneziaWGDriver, "_interface_exists", return_value=True)
    def test_health_check_degraded_no_handshake(self, _iface, _hs) -> None:
        self.driver._active_profile = self.profile
        self.assertEqual(self.driver.health_check(), "degraded")

    @patch.object(AmneziaWGDriver, "_latest_handshake_age", return_value=HANDSHAKE_TIMEOUT_SECONDS + 10)
    @patch.object(AmneziaWGDriver, "_interface_exists", return_value=True)
    def test_health_check_degraded_old_handshake(self, _iface, _hs) -> None:
        self.driver._active_profile = self.profile
        self.assertEqual(self.driver.health_check(), "degraded")

    @patch.object(AmneziaWGDriver, "_ping_through_interface", return_value=False)
    @patch.object(AmneziaWGDriver, "_latest_handshake_age", return_value=10)
    @patch.object(AmneziaWGDriver, "_interface_exists", return_value=True)
    def test_health_check_degraded_no_ping(self, _iface, _hs, _ping) -> None:
        self.driver._active_profile = self.profile
        self.assertEqual(self.driver.health_check(), "degraded")

    # --- Status ---

    @patch.object(AmneziaWGDriver, "_interface_exists", return_value=False)
    def test_status_standby_without_interface(self, _iface) -> None:
        state = self.driver.status()
        self.assertEqual(state.status, "standby")

    @patch.object(AmneziaWGDriver, "_interface_exists", return_value=True)
    def test_status_connected_with_interface(self, _iface) -> None:
        self.driver._active_profile = self.profile
        state = self.driver.status()
        self.assertEqual(state.status, "connected")
        self.assertEqual(state.mode, "amneziawg")
        self.assertTrue(state.tun_active)
        self.assertFalse(state.proxy_active)
        self.assertEqual(state.active_profile_id, "awg-test-1")


if __name__ == "__main__":
    unittest.main()
