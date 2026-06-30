from __future__ import annotations

import json
import subprocess
import unittest
from unittest.mock import Mock, patch

from drivers.openvpn_cloak_driver import (
    CLOAK_CONFIG_PATH,
    CLOAK_LOG_PATH,
    OC_OVPN_CONFIG_PATH,
    OC_OVPN_LOG_PATH,
    OpenVPNCloakDriver,
)
from models.profile import Profile, ProfileSource, ProtocolType


_CLOAK_CONFIG_DICT = {
    "Transport": "direct",
    "ProxyMethod": "openvpn",
    "EncryptionMethod": "chacha20-poly1305",
    "UID": "fakeUID==",
    "PublicKey": "fakePubKey==",
    "BrowserSig": "chrome",
    "NumConn": 4,
    "RemoteHost": "138.124.58.47",
    "RemotePort": "8443",
    "ServerName": "tile.openstreetmap.org",
    "LocalHost": "127.0.0.1",
    "LocalPort": "1984",
    "StreamTimeout": 300,
}

_OVPN_CONFIG = """\
client
dev tun
proto tcp
remote 127.0.0.1 1984
resolv-retry infinite
nobind
persist-key
persist-tun
<ca>
-----BEGIN CERTIFICATE-----
fakecert
-----END CERTIFICATE-----
</ca>
verb 3
"""


def _make_profile(**overrides) -> Profile:
    config = {
        "raw_config": _OVPN_CONFIG,
        "cloak_config": _CLOAK_CONFIG_DICT,
        "wrapper": "cloak",
    }
    config.update(overrides.pop("config_overrides", {}))
    return Profile(
        id=overrides.pop("id", "oc-test-1"),
        name=overrides.pop("name", "oc-paris"),
        protocol=overrides.pop("protocol", ProtocolType.OPENVPN_CLOAK),
        config=config,
        source=ProfileSource.MANUAL,
        **overrides,
    )


class OpenVPNCloakDriverTests(unittest.TestCase):
    def setUp(self) -> None:
        self.driver = OpenVPNCloakDriver()
        self.profile = _make_profile()

    def tearDown(self) -> None:
        for p in (OC_OVPN_CONFIG_PATH, CLOAK_CONFIG_PATH, OC_OVPN_LOG_PATH, CLOAK_LOG_PATH):
            try:
                p.unlink(missing_ok=True)
            except OSError:
                pass

    # --- Binary detection ---

    @patch("drivers.openvpn_cloak_driver.shutil.which", return_value="/usr/sbin/openvpn")
    @patch("drivers.openvpn_cloak_driver.os.path.exists", return_value=False)
    @patch("drivers.openvpn_cloak_driver.os.access", return_value=False)
    def test_find_openvpn_falls_back_to_which(self, _access, _exists, _which) -> None:
        self.assertEqual(self.driver.find_openvpn_binary(), "/usr/sbin/openvpn")

    @patch.dict("drivers.openvpn_cloak_driver.os.environ", {"WATCHDOGVPN_OPENVPN_BIN": "/opt/openvpn"})
    @patch("drivers.openvpn_cloak_driver.os.path.exists", return_value=True)
    @patch("drivers.openvpn_cloak_driver.os.access", return_value=True)
    def test_find_openvpn_env_override(self, _access, _exists) -> None:
        self.assertEqual(self.driver.find_openvpn_binary(), "/opt/openvpn")

    @patch("drivers.openvpn_cloak_driver.shutil.which", return_value="/usr/local/bin/ck-client")
    @patch("drivers.openvpn_cloak_driver.os.path.exists", return_value=False)
    @patch("drivers.openvpn_cloak_driver.os.access", return_value=False)
    def test_find_ck_client_falls_back_to_which(self, _access, _exists, _which) -> None:
        self.assertEqual(self.driver.find_ck_client_binary(), "/usr/local/bin/ck-client")

    @patch.dict("drivers.openvpn_cloak_driver.os.environ", {"WATCHDOGVPN_CK_CLIENT_BIN": "/opt/ck-client"})
    @patch("drivers.openvpn_cloak_driver.os.path.exists", return_value=True)
    @patch("drivers.openvpn_cloak_driver.os.access", return_value=True)
    def test_find_ck_client_env_override(self, _access, _exists) -> None:
        self.assertEqual(self.driver.find_ck_client_binary(), "/opt/ck-client")

    @patch.object(OpenVPNCloakDriver, "find_openvpn_binary", return_value="/usr/sbin/openvpn")
    @patch.object(OpenVPNCloakDriver, "find_ck_client_binary", return_value="/usr/bin/ck-client")
    def test_is_available_true_when_both_present(self, _ck, _ovpn) -> None:
        self.assertTrue(self.driver.is_available())

    @patch.object(OpenVPNCloakDriver, "find_openvpn_binary", return_value=None)
    @patch.object(OpenVPNCloakDriver, "find_ck_client_binary", return_value="/usr/bin/ck-client")
    def test_is_available_false_when_openvpn_missing(self, _ck, _ovpn) -> None:
        self.assertFalse(self.driver.is_available())

    @patch.object(OpenVPNCloakDriver, "find_openvpn_binary", return_value="/usr/sbin/openvpn")
    @patch.object(OpenVPNCloakDriver, "find_ck_client_binary", return_value=None)
    def test_is_available_false_when_ck_missing(self, _ck, _ovpn) -> None:
        self.assertFalse(self.driver.is_available())

    @patch.object(OpenVPNCloakDriver, "find_openvpn_binary", return_value="/usr/sbin/openvpn")
    @patch("drivers.openvpn_cloak_driver.subprocess.run")
    def test_check_version_returns_output(self, run_mock, _bin) -> None:
        run_mock.return_value.stdout = "OpenVPN 2.6.0"
        run_mock.return_value.stderr = ""
        self.assertEqual(self.driver.check_version(), "OpenVPN 2.6.0")

    @patch.object(OpenVPNCloakDriver, "find_openvpn_binary", return_value=None)
    def test_check_version_raises_when_missing(self, _bin) -> None:
        with self.assertRaises(FileNotFoundError):
            self.driver.check_version()

    # --- Configuraciones ---

    def test_write_configs_creates_both_files(self) -> None:
        self.driver._write_configs(self.profile)
        self.assertTrue(OC_OVPN_CONFIG_PATH.exists())
        self.assertTrue(CLOAK_CONFIG_PATH.exists())
        ovpn_content = OC_OVPN_CONFIG_PATH.read_text(encoding="utf-8")
        self.assertIn("remote 127.0.0.1 1984", ovpn_content)
        cloak_data = json.loads(CLOAK_CONFIG_PATH.read_text(encoding="utf-8"))
        self.assertEqual(cloak_data["RemoteHost"], "138.124.58.47")

    def test_write_configs_accepts_cloak_as_json_string(self) -> None:
        profile = _make_profile(config_overrides={"cloak_config": json.dumps(_CLOAK_CONFIG_DICT)})
        self.driver._write_configs(profile)
        self.assertTrue(CLOAK_CONFIG_PATH.exists())

    def test_write_configs_rejects_wrong_protocol(self) -> None:
        profile = _make_profile(protocol=ProtocolType.OPENVPN)
        with self.assertRaises(ValueError):
            self.driver._write_configs(profile)

    def test_write_configs_rejects_missing_raw_config(self) -> None:
        profile = _make_profile(config_overrides={"raw_config": ""})
        with self.assertRaises(ValueError):
            self.driver._write_configs(profile)

    def test_write_configs_rejects_missing_cloak_config(self) -> None:
        profile = _make_profile(config_overrides={"cloak_config": None})
        with self.assertRaises(ValueError):
            self.driver._write_configs(profile)

    def test_write_configs_rejects_invalid_json_string(self) -> None:
        profile = _make_profile(config_overrides={"cloak_config": "not json {"})
        with self.assertRaises(ValueError):
            self.driver._write_configs(profile)

    # --- Connect ---

    @patch("drivers.openvpn_cloak_driver.time.sleep")
    @patch.object(OpenVPNCloakDriver, "find_openvpn_binary", return_value="/usr/sbin/openvpn")
    @patch.object(OpenVPNCloakDriver, "find_ck_client_binary", return_value="/usr/bin/ck-client")
    @patch("drivers.openvpn_cloak_driver.subprocess.Popen")
    def test_connect_success(self, popen_mock, _ck, _ovpn, _sleep) -> None:
        ck_process = Mock()
        ck_process.poll.return_value = None
        ovpn_process = Mock()
        ovpn_process.poll.return_value = None
        popen_mock.side_effect = [ck_process, ovpn_process]

        self.assertTrue(self.driver.connect(self.profile))
        self.assertIs(self.driver._ck_process, ck_process)
        self.assertIs(self.driver._openvpn_process, ovpn_process)
        self.assertIs(self.driver._active_profile, self.profile)
        self.assertIsNotNone(self.driver._connected_at)
        self.assertEqual(popen_mock.call_count, 2)
        ck_call_args = popen_mock.call_args_list[0].args[0]
        self.assertEqual(ck_call_args[0], "/usr/bin/ck-client")
        self.assertIn(str(CLOAK_CONFIG_PATH), ck_call_args)
        ovpn_call_args = popen_mock.call_args_list[1].args[0]
        self.assertEqual(ovpn_call_args[0], "/usr/sbin/openvpn")

    @patch.object(OpenVPNCloakDriver, "find_openvpn_binary", return_value=None)
    @patch.object(OpenVPNCloakDriver, "find_ck_client_binary", return_value="/usr/bin/ck-client")
    def test_connect_returns_false_when_openvpn_missing(self, _ck, _ovpn) -> None:
        self.assertFalse(self.driver.connect(self.profile))

    @patch.object(OpenVPNCloakDriver, "find_openvpn_binary", return_value="/usr/sbin/openvpn")
    @patch.object(OpenVPNCloakDriver, "find_ck_client_binary", return_value=None)
    def test_connect_returns_false_when_ck_missing(self, _ck, _ovpn) -> None:
        self.assertFalse(self.driver.connect(self.profile))

    @patch("drivers.openvpn_cloak_driver.time.sleep")
    @patch.object(OpenVPNCloakDriver, "find_openvpn_binary", return_value="/usr/sbin/openvpn")
    @patch.object(OpenVPNCloakDriver, "find_ck_client_binary", return_value="/usr/bin/ck-client")
    @patch("drivers.openvpn_cloak_driver.subprocess.Popen")
    def test_connect_aborts_when_ck_crashes(self, popen_mock, _ck, _ovpn, _sleep) -> None:
        ck_process = Mock()
        ck_process.poll.return_value = 1
        popen_mock.return_value = ck_process

        self.assertFalse(self.driver.connect(self.profile))
        self.assertEqual(popen_mock.call_count, 1)
        self.assertIsNone(self.driver._active_profile)

    # --- Disconnect ---

    @patch.object(OpenVPNCloakDriver, "_cleanup_configs")
    def test_disconnect_terminates_both_processes(self, cleanup_mock) -> None:
        ck_process = Mock()
        ck_process.poll.return_value = None
        ovpn_process = Mock()
        ovpn_process.poll.return_value = None
        self.driver._ck_process = ck_process
        self.driver._openvpn_process = ovpn_process
        self.driver._active_profile = self.profile

        self.assertTrue(self.driver.disconnect())
        ovpn_process.terminate.assert_called_once()
        ck_process.terminate.assert_called_once()
        self.assertIsNone(self.driver._active_profile)
        cleanup_mock.assert_called_once()

    def test_disconnect_without_connect_no_crash(self) -> None:
        self.assertTrue(self.driver.disconnect())

    @patch.object(OpenVPNCloakDriver, "_cleanup_configs")
    def test_disconnect_kills_hung_openvpn(self, _cleanup) -> None:
        ovpn_process = Mock()
        ovpn_process.poll.return_value = None
        ovpn_process.wait.side_effect = [subprocess.TimeoutExpired(cmd="openvpn", timeout=5), None]
        self.driver._openvpn_process = ovpn_process

        self.assertTrue(self.driver.disconnect())
        ovpn_process.terminate.assert_called_once()
        ovpn_process.kill.assert_called_once()

    @patch.object(OpenVPNCloakDriver, "_cleanup_configs")
    def test_disconnect_kills_hung_ck_client(self, _cleanup) -> None:
        ck_process = Mock()
        ck_process.poll.return_value = None
        ck_process.wait.side_effect = [subprocess.TimeoutExpired(cmd="ck-client", timeout=5), None]
        self.driver._ck_process = ck_process

        self.assertTrue(self.driver.disconnect())
        ck_process.terminate.assert_called_once()
        ck_process.kill.assert_called_once()

    # --- Health Check ---

    def test_health_check_down_without_processes(self) -> None:
        self.assertEqual(self.driver.health_check(), "down")

    def test_health_check_down_when_ck_died(self) -> None:
        ck = Mock()
        ck.poll.return_value = 1
        ovpn = Mock()
        ovpn.poll.return_value = None
        self.driver._ck_process = ck
        self.driver._openvpn_process = ovpn
        self.assertEqual(self.driver.health_check(), "down")

    def test_health_check_down_when_openvpn_died(self) -> None:
        ck = Mock()
        ck.poll.return_value = None
        ovpn = Mock()
        ovpn.poll.return_value = 1
        self.driver._ck_process = ck
        self.driver._openvpn_process = ovpn
        self.assertEqual(self.driver.health_check(), "down")

    @patch.object(OpenVPNCloakDriver, "_vpn_interface_active", return_value=False)
    def test_health_check_degraded_no_tun(self, _tun) -> None:
        ck = Mock()
        ck.poll.return_value = None
        ovpn = Mock()
        ovpn.poll.return_value = None
        self.driver._ck_process = ck
        self.driver._openvpn_process = ovpn
        self.assertEqual(self.driver.health_check(), "degraded")

    @patch.object(OpenVPNCloakDriver, "_vpn_interface_active", return_value=True)
    def test_health_check_ok_with_both_alive_and_tun(self, _tun) -> None:
        ck = Mock()
        ck.poll.return_value = None
        ovpn = Mock()
        ovpn.poll.return_value = None
        self.driver._ck_process = ck
        self.driver._openvpn_process = ovpn
        self.assertEqual(self.driver.health_check(), "ok")

    # --- Status ---

    def test_status_standby_without_processes(self) -> None:
        self.assertEqual(self.driver.status().status, "standby")

    def test_status_standby_when_ck_died(self) -> None:
        ck = Mock()
        ck.poll.return_value = 1
        self.driver._ck_process = ck
        self.driver._openvpn_process = Mock()
        self.driver._openvpn_process.poll.return_value = None
        self.assertEqual(self.driver.status().status, "standby")

    @patch.object(OpenVPNCloakDriver, "_vpn_interface_active", return_value=True)
    def test_status_connected_when_both_alive(self, _tun) -> None:
        ck = Mock()
        ck.poll.return_value = None
        ovpn = Mock()
        ovpn.poll.return_value = None
        self.driver._ck_process = ck
        self.driver._openvpn_process = ovpn
        self.driver._active_profile = self.profile

        state = self.driver.status()
        self.assertEqual(state.status, "connected")
        self.assertEqual(state.mode, "openvpn_cloak")
        self.assertTrue(state.tun_active)
        self.assertFalse(state.proxy_active)
        self.assertEqual(state.active_profile_id, "oc-test-1")


if __name__ == "__main__":
    unittest.main()
