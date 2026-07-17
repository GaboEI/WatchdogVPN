from __future__ import annotations

import json
import subprocess
import unittest
from unittest.mock import Mock, patch

from drivers.openvpn_cloak_driver import (
    CLOAK_CONFIG_NAME,
    OC_OVPN_CONFIG_NAME,
    OpenVPNCloakDriver,
)
from models.profile import Profile, ProfileSource, ProtocolType


_CLOAK_CONFIG_DICT = {
    "Transport": "direct",
    "ProxyMethod": "openvpn",
    "EncryptionMethod": "chacha20-poly1305",
    "UID": "TEST-ONLY-NOT-A-UID",
    "PublicKey": "TEST-ONLY-NOT-A-PUBLIC-KEY",
    "BrowserSig": "chrome",
    "NumConn": 4,
    "RemoteHost": "192.0.2.10",
    "RemotePort": "8443",
    "ServerName": "cdn.example.invalid",
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
TEST-ONLY-NOT-A-CERTIFICATE
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
        self.driver._cleanup_configs()

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

    @patch.object(OpenVPNCloakDriver, "check_version", return_value="OpenVPN 2.6.0\nck-client 2.8.0")
    def test_is_available_true_when_versions_pass(self, _version) -> None:
        self.assertTrue(self.driver.is_available())

    @patch.object(OpenVPNCloakDriver, "find_openvpn_binary", return_value=None)
    @patch.object(OpenVPNCloakDriver, "find_ck_client_binary", return_value="/usr/bin/ck-client")
    def test_is_available_false_when_openvpn_missing(self, _ck, _ovpn) -> None:
        self.assertFalse(self.driver.is_available())

    @patch.object(OpenVPNCloakDriver, "find_openvpn_binary", return_value="/usr/sbin/openvpn")
    @patch.object(OpenVPNCloakDriver, "find_ck_client_binary", return_value=None)
    def test_is_available_false_when_ck_missing(self, _ck, _ovpn) -> None:
        self.assertFalse(self.driver.is_available())

    @patch.object(OpenVPNCloakDriver, "find_ck_client_binary", return_value="/usr/bin/ck-client")
    @patch.object(OpenVPNCloakDriver, "find_openvpn_binary", return_value="/usr/sbin/openvpn")
    @patch("drivers.openvpn_cloak_driver.subprocess.run")
    def test_check_version_returns_output(self, run_mock, _ovpn, _ck) -> None:
        openvpn_result = Mock(stdout="OpenVPN 2.6.0", stderr="")
        ck_result = Mock(stdout="ck-client 2.8.0", stderr="")
        run_mock.side_effect = [openvpn_result, ck_result]
        self.assertEqual(self.driver.check_version(), "OpenVPN 2.6.0\nck-client 2.8.0")
        self.assertEqual(run_mock.call_args_list[0].args[0], ["/usr/sbin/openvpn", "--version"])
        self.assertEqual(run_mock.call_args_list[1].args[0], ["/usr/bin/ck-client", "-v"])

    @patch.object(OpenVPNCloakDriver, "find_openvpn_binary", return_value=None)
    def test_check_version_raises_when_missing(self, _bin) -> None:
        with self.assertRaises(FileNotFoundError):
            self.driver.check_version()

    # --- Configuration files ---

    def test_write_configs_creates_both_files(self) -> None:
        self.driver._write_configs(self.profile)
        self.assertIsNotNone(self.driver._ovpn_config_path)
        self.assertIsNotNone(self.driver._cloak_config_path)
        self.assertEqual(self.driver._ovpn_config_path.name, OC_OVPN_CONFIG_NAME)
        self.assertEqual(self.driver._cloak_config_path.name, CLOAK_CONFIG_NAME)
        self.assertTrue(self.driver._ovpn_config_path.exists())
        self.assertTrue(self.driver._cloak_config_path.exists())
        ovpn_content = self.driver._ovpn_config_path.read_text(encoding="utf-8")
        self.assertIn("remote 127.0.0.1 1984", ovpn_content)
        cloak_data = json.loads(self.driver._cloak_config_path.read_text(encoding="utf-8"))
        self.assertEqual(cloak_data["RemoteHost"], "192.0.2.10")

    def test_write_configs_accepts_cloak_as_json_string(self) -> None:
        profile = _make_profile(config_overrides={"cloak_config": json.dumps(_CLOAK_CONFIG_DICT)})
        self.driver._write_configs(profile)
        self.assertIsNotNone(self.driver._cloak_config_path)
        self.assertTrue(self.driver._cloak_config_path.exists())

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
    @patch.object(OpenVPNCloakDriver, "_wait_for_ready", return_value=True)
    @patch.object(OpenVPNCloakDriver, "_capture_route_snapshot", return_value=True)
    @patch("drivers.openvpn_cloak_driver.subprocess.Popen")
    def test_connect_success(self, popen_mock, _snapshot, _ready, _ck, _ovpn, _sleep) -> None:
        ck_process = Mock()
        ck_process.poll.return_value = None
        ck_process.pid = 1111
        ovpn_process = Mock()
        ovpn_process.poll.return_value = None
        ovpn_process.pid = 2222
        popen_mock.side_effect = [ck_process, ovpn_process]

        self.assertTrue(self.driver.connect(self.profile))
        self.assertIs(self.driver._ck_process, ck_process)
        self.assertIs(self.driver._openvpn_process, ovpn_process)
        self.assertIs(self.driver._active_profile, self.profile)
        self.assertIsNotNone(self.driver._connected_at)
        self.assertEqual(popen_mock.call_count, 2)
        ck_call_args = popen_mock.call_args_list[0].args[0]
        self.assertEqual(ck_call_args[0], "/usr/bin/ck-client")
        self.assertIn(str(self.driver._cloak_config_path), ck_call_args)
        ovpn_call_args = popen_mock.call_args_list[1].args[0]
        self.assertEqual(ovpn_call_args[1:4], ["--nnp", "--inh-caps=-all,+net_admin,+net_raw", "--ambient-caps=-all,+net_admin,+net_raw"])
        self.assertEqual(ovpn_call_args[4], "--")
        self.assertEqual(ovpn_call_args[5], "/usr/sbin/openvpn")
        self.assertEqual(ovpn_call_args[6:8], ["--config", str(self.driver._ovpn_config_path)])
        self.assertEqual(
            ovpn_call_args[-9:],
            [
                "--dev",
                self.driver._expected_interface,
                "--dev-type",
                "tun",
                "--status",
                str(self.driver._ovpn_status_path),
                "1",
                "--status-version",
                "3",
            ],
        )

    @patch("drivers.openvpn_cloak_driver.time.sleep")
    @patch.object(OpenVPNCloakDriver, "find_openvpn_binary", return_value="/usr/sbin/openvpn")
    @patch.object(OpenVPNCloakDriver, "find_ck_client_binary", return_value="/usr/bin/ck-client")
    @patch.object(OpenVPNCloakDriver, "_wait_for_ready", return_value=True)
    @patch.object(OpenVPNCloakDriver, "_capture_route_snapshot", return_value=True)
    @patch("drivers.openvpn_cloak_driver.subprocess.Popen")
    def test_connect_disconnects_stale_processes_before_starting_new_ones(
        self, popen_mock, _snapshot, _ready, _ck, _ovpn, _sleep
    ) -> None:
        # Regression guard for WDCLI-001.
        stale_ck = Mock()
        stale_ck.poll.return_value = None
        stale_ovpn = Mock()
        stale_ovpn.poll.return_value = None
        self.driver._ck_process = stale_ck
        self.driver._openvpn_process = stale_ovpn
        self.driver._active_profile = self.profile

        new_ck = Mock()
        new_ck.poll.return_value = None
        new_ck.pid = 3333
        new_ovpn = Mock()
        new_ovpn.poll.return_value = None
        new_ovpn.pid = 4444
        popen_mock.side_effect = [new_ck, new_ovpn]

        self.assertTrue(self.driver.connect(self.profile))

        stale_ck.terminate.assert_called_once()
        stale_ovpn.terminate.assert_called_once()
        self.assertIs(self.driver._ck_process, new_ck)
        self.assertIs(self.driver._openvpn_process, new_ovpn)

    def test_connect_refuses_spawn_after_failed_teardown(self) -> None:
        self.driver._ck_process = Mock()
        with (
            patch.object(self.driver, "disconnect", return_value=False) as disconnect_mock,
            patch.object(OpenVPNCloakDriver, "find_openvpn_binary") as openvpn_mock,
            patch.object(OpenVPNCloakDriver, "find_ck_client_binary") as cloak_mock,
        ):
            self.assertFalse(self.driver.connect(self.profile))

        disconnect_mock.assert_called_once_with()
        openvpn_mock.assert_not_called()
        cloak_mock.assert_not_called()
        self.assertIn("teardown failed", self.driver.last_error)


    @patch.object(OpenVPNCloakDriver, "find_openvpn_binary", return_value=None)
    @patch.object(OpenVPNCloakDriver, "find_ck_client_binary", return_value="/usr/bin/ck-client")
    def test_connect_returns_false_when_openvpn_missing(self, _ck, _ovpn) -> None:
        # Regression: confirmed live 2026-07-17 - this branch returned
        # False with last_error left unset (empty), so every layer above it
        # (NativePolicyDriver, watchdog status, journalctl) had nothing to
        # show beyond a generic "connect failed" - install.sh's own Cloak
        # client install prompt defaulting to "no" silently skipped it on
        # every non-interactive `install.sh --yes` install, and this was
        # the only place that could have explained why.
        self.assertFalse(self.driver.connect(self.profile))
        self.assertIn("openvpn", self.driver.last_error)

    @patch.object(OpenVPNCloakDriver, "find_openvpn_binary", return_value="/usr/sbin/openvpn")
    @patch.object(OpenVPNCloakDriver, "find_ck_client_binary", return_value=None)
    def test_connect_returns_false_when_ck_missing(self, _ck, _ovpn) -> None:
        self.assertFalse(self.driver.connect(self.profile))
        self.assertIn("ck-client", self.driver.last_error)

    @patch("drivers.openvpn_cloak_driver.time.sleep")
    @patch.object(OpenVPNCloakDriver, "find_openvpn_binary", return_value="/usr/sbin/openvpn")
    @patch.object(OpenVPNCloakDriver, "find_ck_client_binary", return_value="/usr/bin/ck-client")
    @patch.object(OpenVPNCloakDriver, "_capture_route_snapshot", return_value=True)
    @patch("drivers.openvpn_cloak_driver.subprocess.Popen")
    def test_connect_aborts_when_ck_crashes(self, popen_mock, _snapshot, _ck, _ovpn, _sleep) -> None:
        ck_process = Mock()
        ck_process.poll.return_value = 1
        ck_process.pid = 1111
        popen_mock.return_value = ck_process

        self.assertFalse(self.driver.connect(self.profile))
        self.assertEqual(popen_mock.call_count, 1)
        self.assertIsNone(self.driver._active_profile)

    @patch.object(OpenVPNCloakDriver, "find_openvpn_binary", return_value="/usr/sbin/openvpn")
    @patch.object(OpenVPNCloakDriver, "find_ck_client_binary", return_value="/usr/bin/ck-client")
    @patch.object(OpenVPNCloakDriver, "_capture_route_snapshot", return_value=False)
    @patch("drivers.openvpn_cloak_driver.subprocess.Popen")
    def test_connect_aborts_before_spawning_when_route_snapshot_is_unavailable(
        self, popen_mock, _snapshot, _ck, _ovpn
    ) -> None:
        self.assertFalse(self.driver.connect(self.profile))

        popen_mock.assert_not_called()
        self.assertIsNone(self.driver._runtime_dir)

    def _live_process(self, pid: int) -> Mock:
        process = Mock()
        process.poll.return_value = None
        process.pid = pid
        return process

    def _assert_startup_rolled_back(self) -> None:
        self.assertIsNone(self.driver._ck_process)
        self.assertIsNone(self.driver._openvpn_process)
        self.assertIsNone(self.driver._active_profile)
        self.assertIsNone(self.driver._runtime_dir)

    @patch.object(OpenVPNCloakDriver, "find_openvpn_binary", return_value="/usr/sbin/openvpn")
    @patch.object(OpenVPNCloakDriver, "find_ck_client_binary", return_value="/usr/bin/ck-client")
    @patch("drivers.openvpn_cloak_driver.subprocess.Popen")
    def test_connect_rolls_back_partial_config_creation_failure(
        self, popen_mock, _ck, _ovpn
    ) -> None:
        def create_runtime_then_fail(_profile) -> None:
            self.driver._ensure_runtime_paths()
            raise OSError("simulated config write failure")

        with patch.object(
            self.driver, "_write_configs", side_effect=create_runtime_then_fail
        ):
            self.assertFalse(self.driver.connect(self.profile))

        popen_mock.assert_not_called()
        self._assert_startup_rolled_back()

    @patch.object(OpenVPNCloakDriver, "find_openvpn_binary", return_value="/usr/sbin/openvpn")
    @patch.object(OpenVPNCloakDriver, "find_ck_client_binary", return_value="/usr/bin/ck-client")
    @patch.object(OpenVPNCloakDriver, "_reset_logs", return_value=False)
    @patch("drivers.openvpn_cloak_driver.subprocess.Popen")
    def test_connect_rolls_back_when_private_log_reset_fails(
        self, popen_mock, _reset, _ck, _ovpn
    ) -> None:
        self.assertFalse(self.driver.connect(self.profile))

        popen_mock.assert_not_called()
        self._assert_startup_rolled_back()

    @patch.object(OpenVPNCloakDriver, "find_openvpn_binary", return_value="/usr/sbin/openvpn")
    @patch.object(OpenVPNCloakDriver, "find_ck_client_binary", return_value="/usr/bin/ck-client")
    @patch.object(OpenVPNCloakDriver, "_reset_logs", return_value=True)
    @patch.object(OpenVPNCloakDriver, "_configure_readiness", side_effect=RuntimeError("bad readiness"))
    @patch("drivers.openvpn_cloak_driver.subprocess.Popen")
    def test_connect_rolls_back_when_readiness_configuration_fails(
        self, popen_mock, _readiness, _reset, _ck, _ovpn
    ) -> None:
        self.assertFalse(self.driver.connect(self.profile))

        popen_mock.assert_not_called()
        self._assert_startup_rolled_back()

    @patch.object(OpenVPNCloakDriver, "find_openvpn_binary", return_value="/usr/sbin/openvpn")
    @patch.object(OpenVPNCloakDriver, "find_ck_client_binary", return_value="/usr/bin/ck-client")
    @patch.object(OpenVPNCloakDriver, "_capture_route_snapshot", return_value=True)
    @patch("drivers.openvpn_cloak_driver.Path.open", side_effect=OSError("log open failure"))
    @patch("drivers.openvpn_cloak_driver.subprocess.Popen")
    def test_connect_rolls_back_when_cloak_log_open_fails(
        self, popen_mock, _open, _snapshot, _ck, _ovpn
    ) -> None:
        self.assertFalse(self.driver.connect(self.profile))

        popen_mock.assert_not_called()
        self._assert_startup_rolled_back()

    @patch.object(OpenVPNCloakDriver, "find_openvpn_binary", return_value="/usr/sbin/openvpn")
    @patch.object(OpenVPNCloakDriver, "find_ck_client_binary", return_value="/usr/bin/ck-client")
    @patch.object(OpenVPNCloakDriver, "_capture_route_snapshot", return_value=True)
    @patch("drivers.openvpn_cloak_driver.subprocess.Popen", side_effect=OSError("ck spawn failure"))
    def test_connect_rolls_back_when_cloak_spawn_fails(
        self, popen_mock, _snapshot, _ck, _ovpn
    ) -> None:
        self.assertFalse(self.driver.connect(self.profile))

        popen_mock.assert_called_once()
        self._assert_startup_rolled_back()

    @patch.object(OpenVPNCloakDriver, "find_openvpn_binary", return_value="/usr/sbin/openvpn")
    @patch.object(OpenVPNCloakDriver, "find_ck_client_binary", return_value="/usr/bin/ck-client")
    @patch.object(OpenVPNCloakDriver, "_capture_route_snapshot", return_value=True)
    @patch("drivers.openvpn_cloak_driver.record_child_process", side_effect=OSError("record failure"))
    @patch("drivers.openvpn_cloak_driver.subprocess.Popen")
    def test_connect_rolls_back_unrecorded_cloak_child(
        self, popen_mock, _record, _snapshot, _ck, _ovpn
    ) -> None:
        cloak = self._live_process(1111)
        popen_mock.return_value = cloak

        self.assertFalse(self.driver.connect(self.profile))

        cloak.terminate.assert_called_once()
        self._assert_startup_rolled_back()

    @patch("drivers.openvpn_cloak_driver.time.sleep")
    @patch.object(OpenVPNCloakDriver, "find_openvpn_binary", return_value="/usr/sbin/openvpn")
    @patch.object(OpenVPNCloakDriver, "find_ck_client_binary", return_value="/usr/bin/ck-client")
    @patch.object(OpenVPNCloakDriver, "_capture_route_snapshot", return_value=True)
    @patch("drivers.openvpn_cloak_driver.subprocess.Popen")
    def test_connect_rolls_back_cloak_when_openvpn_spawn_fails(
        self, popen_mock, _snapshot, _ck, _ovpn, _sleep
    ) -> None:
        cloak = self._live_process(1111)
        popen_mock.side_effect = [cloak, OSError("openvpn spawn failure")]

        self.assertFalse(self.driver.connect(self.profile))

        cloak.terminate.assert_called_once()
        self._assert_startup_rolled_back()

    @patch("drivers.openvpn_cloak_driver.time.sleep")
    @patch.object(OpenVPNCloakDriver, "find_openvpn_binary", return_value="/usr/sbin/openvpn")
    @patch.object(OpenVPNCloakDriver, "find_ck_client_binary", return_value="/usr/bin/ck-client")
    @patch.object(OpenVPNCloakDriver, "_capture_route_snapshot", return_value=True)
    @patch("drivers.openvpn_cloak_driver.record_child_process")
    @patch.object(OpenVPNCloakDriver, "_cleanup_expected_interface", return_value=True)
    @patch("drivers.openvpn_cloak_driver.subprocess.Popen")
    def test_connect_rolls_back_unrecorded_openvpn_child(
        self, popen_mock, _interface, record_mock, _snapshot, _ck, _ovpn, _sleep
    ) -> None:
        cloak = self._live_process(1111)
        openvpn = self._live_process(2222)
        popen_mock.side_effect = [cloak, openvpn]
        record_mock.side_effect = [None, OSError("openvpn record failure")]

        self.assertFalse(self.driver.connect(self.profile))

        cloak.terminate.assert_called_once()
        openvpn.terminate.assert_called_once()
        self._assert_startup_rolled_back()

    @patch("drivers.openvpn_cloak_driver.time.sleep")
    @patch.object(OpenVPNCloakDriver, "find_openvpn_binary", return_value="/usr/sbin/openvpn")
    @patch.object(OpenVPNCloakDriver, "find_ck_client_binary", return_value="/usr/bin/ck-client")
    @patch.object(OpenVPNCloakDriver, "_capture_route_snapshot", return_value=True)
    @patch.object(OpenVPNCloakDriver, "_wait_for_ready", return_value=False)
    @patch.object(OpenVPNCloakDriver, "_cleanup_expected_interface", return_value=True)
    @patch("drivers.openvpn_cloak_driver.subprocess.Popen")
    def test_connect_rolls_back_both_children_when_readiness_fails(
        self, popen_mock, _interface, _ready, _snapshot, _ck, _ovpn, _sleep
    ) -> None:
        cloak = self._live_process(1111)
        openvpn = self._live_process(2222)
        popen_mock.side_effect = [cloak, openvpn]

        self.assertFalse(self.driver.connect(self.profile))

        cloak.terminate.assert_called_once()
        openvpn.terminate.assert_called_once()
        self._assert_startup_rolled_back()

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

    @patch.object(OpenVPNCloakDriver, "_cleanup_configs")
    def test_disconnect_reports_failed_kill(self, _cleanup) -> None:
        ovpn_process = Mock()
        ovpn_process.poll.return_value = None
        ovpn_process.wait.side_effect = [
            subprocess.TimeoutExpired(cmd="openvpn", timeout=5),
            subprocess.TimeoutExpired(cmd="openvpn", timeout=5),
        ]
        ck_process = Mock()
        ck_process.poll.return_value = None
        self.driver._openvpn_process = ovpn_process
        self.driver._ck_process = ck_process

        self.assertFalse(self.driver.disconnect())
        ovpn_process.terminate.assert_called_once()
        ovpn_process.kill.assert_called_once()
        ck_process.terminate.assert_called_once()

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

    @patch.object(OpenVPNCloakDriver, "_readiness_evidence_ready", return_value=True)
    @patch.object(OpenVPNCloakDriver, "_vpn_interface_active", return_value=True)
    def test_health_check_ok_with_both_alive_and_tun(self, _tun, _evidence) -> None:
        ck = Mock()
        ck.poll.return_value = None
        ovpn = Mock()
        ovpn.poll.return_value = None
        self.driver._ck_process = ck
        self.driver._openvpn_process = ovpn
        self.assertEqual(self.driver.health_check(), "ok")

    # --- Status ---

    @patch.object(OpenVPNCloakDriver, "_vpn_interface_active", return_value=False)
    @patch("drivers.openvpn_cloak_driver.any_recorded_child_alive", return_value=False)
    def test_status_standby_without_processes(self, alive_mock, tun_mock) -> None:
        self.assertEqual(self.driver.status().status, "standby")

    @patch.object(OpenVPNCloakDriver, "_vpn_interface_active", return_value=True)
    @patch("drivers.openvpn_cloak_driver.any_recorded_child_alive", return_value=False)
    def test_status_reports_runtime_mismatch_when_interface_orphaned(self, alive_mock, tun_mock) -> None:
        self.assertEqual(self.driver.status().status, "runtime_mismatch")

    @patch.object(OpenVPNCloakDriver, "_vpn_interface_active", return_value=False)
    @patch("drivers.openvpn_cloak_driver.any_recorded_child_alive", return_value=True)
    def test_status_reports_runtime_mismatch_when_recorded_child_alive(self, alive_mock, tun_mock) -> None:
        self.assertEqual(self.driver.status().status, "runtime_mismatch")

    def test_status_keeps_live_openvpn_and_runtime_when_ck_dies(self) -> None:
        self.driver._ensure_runtime_paths()
        children_path = self.driver._runtime_dir / "children.json"
        children_path.write_text("{\"ck_process\": {\"pid\": 999999}}", encoding="utf-8")
        before = children_path.read_text(encoding="utf-8")
        ck = Mock()
        ck.poll.return_value = 1
        ovpn = Mock()
        ovpn.poll.return_value = None
        self.driver._ck_process = ck
        self.driver._openvpn_process = ovpn
        self.driver._active_profile = self.profile

        state = self.driver.status()

        self.assertEqual(state.status, "runtime_mismatch")
        self.assertIn("ck-client", state.last_failure_reason)
        self.assertIs(self.driver._ck_process, ck)
        self.assertIs(self.driver._openvpn_process, ovpn)
        self.assertTrue(self.driver._runtime_dir.exists())
        self.assertEqual(children_path.read_text(encoding="utf-8"), before)
        self.assertTrue(self.driver.disconnect())
        ovpn.terminate.assert_called_once()
        self.assertIsNone(self.driver._runtime_dir)

    @patch.object(OpenVPNCloakDriver, "_readiness_evidence_ready", return_value=True)

    @patch.object(OpenVPNCloakDriver, "_vpn_interface_active", return_value=True)
    def test_status_connected_when_both_alive(self, _evidence, _tun) -> None:
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
    @patch.object(OpenVPNCloakDriver, "_readiness_evidence_ready", return_value=False)
    @patch.object(OpenVPNCloakDriver, "_vpn_interface_active", return_value=True)
    def test_status_rejects_live_processes_without_current_generation_evidence(
        self, _interface, _evidence
    ) -> None:
        ck = Mock()
        ck.poll.return_value = None
        ovpn = Mock()
        ovpn.poll.return_value = None
        self.driver._ck_process = ck
        self.driver._openvpn_process = ovpn
        self.driver._active_profile = self.profile

        state = self.driver.status()

        self.assertEqual(state.status, "runtime_mismatch")
        self.assertFalse(state.tun_active)
        self.assertIn("readiness evidence", state.last_failure_reason)

    def test_readiness_rejects_unrelated_tun_and_requires_current_evidence(self) -> None:
        self.driver._ensure_runtime_paths()
        self.driver._configure_readiness(self.profile)
        expected = self.driver._expected_interface
        result = Mock(returncode=0, stdout="7: tap9: <BROADCAST>\n")
        with (
            patch("drivers.openvpn_cloak_driver.shutil.which", return_value="/usr/bin/ip"),
            patch("drivers.openvpn_cloak_driver.subprocess.run", return_value=result),
        ):
            self.assertFalse(self.driver._vpn_interface_active())
            result.stdout = f"7: {expected}: <POINTOPOINT>\n"
            self.assertTrue(self.driver._vpn_interface_active())

        self.assertFalse(self.driver._readiness_evidence_ready())
        self.driver._ovpn_status_path.write_text("OpenVPN STATISTICS\n", encoding="utf-8")
        self.driver._ovpn_log_path.write_text("Initialization Sequence Completed\n", encoding="utf-8")
        self.assertTrue(self.driver._readiness_evidence_ready())

    def test_readiness_owns_a_short_tap_name_when_profile_requests_tap(self) -> None:
        profile = _make_profile(config_overrides={"dev": "tap"})
        self.driver._ensure_runtime_paths()
        options = self.driver._configure_readiness(profile)

        self.assertEqual(self.driver._expected_device_type, "tap")
        # Must start with "tap" literally - OpenVPN rejects a topology-subnet
        # PUSH_REPLY on a --dev name not prefixed with tun/tap, regardless of
        # an explicit --dev-type (confirmed live, see openvpn_cloak_driver.py).
        self.assertTrue(self.driver._expected_interface.startswith("tapwd"))
        self.assertLessEqual(len(self.driver._expected_interface), 15)
        self.assertEqual(options[0:4], ("--dev", self.driver._expected_interface, "--dev-type", "tap"))

    @patch.object(OpenVPNCloakDriver, "_readiness_evidence_ready", return_value=False)
    @patch.object(OpenVPNCloakDriver, "_vpn_interface_active", return_value=True)
    def test_health_rejects_interface_without_current_generation_evidence(
        self, _interface, _evidence
    ) -> None:
        ck = Mock()
        ck.poll.return_value = None
        ovpn = Mock()
        ovpn.poll.return_value = None
        self.driver._ck_process = ck
        self.driver._openvpn_process = ovpn

        self.assertEqual(self.driver.health_check(), "degraded")


    def test_status_keeps_live_ck_client_and_runtime_when_openvpn_dies(self) -> None:
        self.driver._ensure_runtime_paths()
        children_path = self.driver._runtime_dir / "children.json"
        children_path.write_text("{\"openvpn_process\": {\"pid\": 999999}}", encoding="utf-8")
        before = children_path.read_text(encoding="utf-8")
        ck = Mock()
        ck.poll.return_value = None
        ovpn = Mock()
        ovpn.poll.return_value = 1
        self.driver._ck_process = ck
        self.driver._openvpn_process = ovpn
        self.driver._active_profile = self.profile

        state = self.driver.status()

        self.assertEqual(state.status, "runtime_mismatch")
        self.assertIn("openvpn", state.last_failure_reason)
        self.assertIs(self.driver._ck_process, ck)
        self.assertIs(self.driver._openvpn_process, ovpn)
        self.assertEqual(children_path.read_text(encoding="utf-8"), before)
        self.assertTrue(self.driver.disconnect())
        ck.terminate.assert_called_once()
        self.assertIsNone(self.driver._runtime_dir)

    def test_disconnect_retains_children_and_runtime_when_termination_is_unverified(self) -> None:
        self.driver._ensure_runtime_paths()
        runtime_dir = self.driver._runtime_dir
        children_path = runtime_dir / "children.json"
        children_path.write_text("{\"openvpn_process\": {\"pid\": 999999}}", encoding="utf-8")
        ovpn = Mock()
        ovpn.poll.return_value = None
        ovpn.wait.side_effect = [
            subprocess.TimeoutExpired(cmd="openvpn", timeout=5),
            subprocess.TimeoutExpired(cmd="openvpn", timeout=5),
        ]
        ck = Mock()
        ck.poll.return_value = 1
        self.driver._openvpn_process = ovpn
        self.driver._ck_process = ck
        self.driver._active_profile = self.profile

        self.assertFalse(self.driver.disconnect())

        self.assertIs(self.driver._openvpn_process, ovpn)
        self.assertIs(self.driver._ck_process, ck)
        self.assertIs(self.driver._active_profile, self.profile)
        self.assertTrue(runtime_dir.exists())
        self.assertTrue(children_path.exists())
        ovpn.terminate.assert_called_once()
        ovpn.kill.assert_called_once()

    @patch("drivers.openvpn_cloak_driver.shutil.which", return_value="/usr/bin/ip")
    @patch("drivers.openvpn_cloak_driver.subprocess.run")
    def test_capture_route_snapshot_records_private_preconnect_routes(
        self, run_mock, _which
    ) -> None:
        self.driver._ensure_runtime_paths()
        run_mock.return_value = Mock(
            returncode=0,
            stdout="default via 192.0.2.1 dev eth0\n192.0.2.10 via 192.0.2.1 dev eth0\n",
        )

        self.assertTrue(self.driver._capture_route_snapshot())

        self.assertEqual(
            self.driver._route_snapshot_path.read_text(encoding="utf-8"),
            "192.0.2.10 via 192.0.2.1 dev eth0\ndefault via 192.0.2.1 dev eth0\n",
        )
        self.assertEqual(self.driver._route_snapshot_path.stat().st_mode & 0o777, 0o600)

    @patch("drivers.openvpn_cloak_driver.shutil.which", return_value="/usr/bin/ip")
    @patch("drivers.openvpn_cloak_driver.subprocess.run")
    def test_cleanup_removes_only_new_preserved_openvpn_endpoint_route(
        self, run_mock, _which
    ) -> None:
        self.driver._ensure_runtime_paths()
        self.driver._route_snapshot_captured = True
        self.driver._route_snapshot_path.write_text(
            "default via 192.0.2.1 dev eth0\n", encoding="utf-8"
        )
        self.driver._ovpn_log_path.write_text(
            "Preserving recently used remote address: [AF_INET]198.51.100.7:443\n",
            encoding="utf-8",
        )
        baseline = "default via 192.0.2.1 dev eth0\n"
        unrelated = "203.0.113.9 via 192.0.2.1 dev eth0 metric 200\n"
        orphan = "198.51.100.7 via 192.0.2.1 dev eth0 metric 200\n"
        run_mock.side_effect = [
            Mock(returncode=0, stdout=baseline + unrelated + orphan),
            Mock(returncode=0, stdout=""),
            Mock(returncode=0, stdout=baseline + unrelated),
        ]

        self.assertTrue(self.driver._cleanup_openvpn_endpoint_routes())

        self.assertEqual(
            run_mock.call_args_list[1].args[0],
            ["ip", "route", "del", "198.51.100.7", "via", "192.0.2.1", "dev", "eth0", "metric", "200"],
        )

    @patch("drivers.openvpn_cloak_driver.shutil.which", return_value="/usr/bin/ip")
    @patch("drivers.openvpn_cloak_driver.subprocess.run")
    def test_cleanup_removes_new_server_route_logged_by_openvpn(
        self, run_mock, _which
    ) -> None:
        self.driver._ensure_runtime_paths()
        self.driver._route_snapshot_captured = True
        self.driver._route_snapshot_path.write_text(
            "default via 192.0.2.1 dev eth0\n", encoding="utf-8"
        )
        self.driver._ovpn_log_path.write_text(
            "net_route_v4_add: 198.51.100.7/32 via 192.0.2.1 dev [NULL] table 0 metric 200\n",
            encoding="utf-8",
        )
        baseline = "default via 192.0.2.1 dev eth0\n"
        orphan = "198.51.100.7 via 192.0.2.1 dev eth0 metric 200\n"
        run_mock.side_effect = [
            Mock(returncode=0, stdout=baseline + orphan),
            Mock(returncode=0, stdout=""),
            Mock(returncode=0, stdout=baseline),
        ]

        self.assertTrue(self.driver._cleanup_openvpn_endpoint_routes())

        self.assertEqual(
            run_mock.call_args_list[1].args[0],
            ["ip", "route", "del", "198.51.100.7", "via", "192.0.2.1", "dev", "eth0", "metric", "200"],
        )

    @patch("drivers.openvpn_cloak_driver.shutil.which", return_value="/usr/bin/ip")
    @patch("drivers.openvpn_cloak_driver.subprocess.run")
    def test_cleanup_keeps_preexisting_route_to_same_openvpn_endpoint(
        self, run_mock, _which
    ) -> None:
        self.driver._ensure_runtime_paths()
        self.driver._route_snapshot_captured = True
        route = "198.51.100.7 via 192.0.2.1 dev eth0 metric 200\n"
        self.driver._route_snapshot_path.write_text(route, encoding="utf-8")
        self.driver._ovpn_log_path.write_text(
            "Preserving recently used remote address: [AF_INET]198.51.100.7:443\n",
            encoding="utf-8",
        )
        run_mock.side_effect = [
            Mock(returncode=0, stdout=route),
            Mock(returncode=0, stdout=route),
        ]

        self.assertTrue(self.driver._cleanup_openvpn_endpoint_routes())

        self.assertEqual(run_mock.call_count, 2)
        self.assertEqual(run_mock.call_args_list[0].args[0], ["ip", "-o", "route", "show"])
        self.assertEqual(run_mock.call_args_list[1].args[0], ["ip", "-o", "route", "show"])

    @patch("drivers.openvpn_cloak_driver.shutil.which", return_value="/usr/bin/ip")
    @patch("drivers.openvpn_cloak_driver.subprocess.run")
    def test_cleanup_retains_runtime_when_orphaned_endpoint_route_cannot_be_removed(
        self, run_mock, _which
    ) -> None:
        self.driver._ensure_runtime_paths()
        self.driver._route_snapshot_captured = True
        self.driver._route_snapshot_path.write_text("", encoding="utf-8")
        self.driver._ovpn_log_path.write_text(
            "Preserving recently used remote address: [AF_INET]198.51.100.7:443\n",
            encoding="utf-8",
        )
        run_mock.side_effect = [
            Mock(returncode=0, stdout="198.51.100.7 via 192.0.2.1 dev eth0 metric 200\n"),
            Mock(returncode=2, stdout="", stderr="operation not permitted"),
        ]

        self.assertFalse(self.driver._cleanup_openvpn_endpoint_routes())

    @patch.object(OpenVPNCloakDriver, "_vpn_interface_active", return_value=False)
    @patch("drivers.openvpn_cloak_driver.subprocess.run")
    @patch("drivers.openvpn_cloak_driver.shutil.which", return_value="/usr/bin/ip")
    def test_cleanup_expected_interface_deletes_only_current_generation(
        self, _which, run_mock, _active
    ) -> None:
        self.driver._expected_interface = "wdtunowned"

        self.assertTrue(self.driver._cleanup_expected_interface())

        run_mock.assert_called_once_with(
            ["ip", "link", "delete", "dev", "wdtunowned"],
            text=True,
            capture_output=True,
            check=False,
        )

    @patch("drivers.openvpn_cloak_driver.shutil.which", return_value=None)
    def test_cleanup_expected_interface_fails_closed_without_ip_tool(self, _which) -> None:
        self.driver._expected_interface = "wdtunowned"

        self.assertFalse(self.driver._cleanup_expected_interface())

    @patch.object(OpenVPNCloakDriver, "_cleanup_expected_interface", return_value=False)
    @patch("drivers.openvpn_cloak_driver.kill_all_recorded_children")
    def test_disconnect_retains_runtime_when_interface_cleanup_cannot_be_verified(
        self, _kill_recorded, _cleanup_interface
    ) -> None:
        self.driver._ensure_runtime_paths()
        runtime_dir = self.driver._runtime_dir
        self.driver._expected_interface = "wdtunowned"
        ck = Mock()
        ck.poll.return_value = None
        ovpn = Mock()
        ovpn.poll.return_value = None
        self.driver._ck_process = ck
        self.driver._openvpn_process = ovpn
        self.driver._active_profile = self.profile

        self.assertFalse(self.driver.disconnect())

        self.assertIs(self.driver._ck_process, ck)
        self.assertIs(self.driver._openvpn_process, ovpn)
        self.assertTrue(runtime_dir.exists())
        ck.terminate.assert_called_once()
        ovpn.terminate.assert_called_once()



if __name__ == "__main__":
    unittest.main()
