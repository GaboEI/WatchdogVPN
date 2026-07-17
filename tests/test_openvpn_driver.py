from __future__ import annotations

import subprocess
import unittest
from unittest.mock import patch

from drivers.openvpn_driver import CONFIG_NAME, OpenVPNDriver
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

    @patch.object(OpenVPNDriver, "check_version", return_value="OpenVPN 2.6.0")
    def test_is_available_checks_version(self, version_mock) -> None:
        self.assertTrue(self.driver.is_available())

    @patch.object(OpenVPNDriver, "find_openvpn_binary", return_value=None)
    def test_is_available_is_false_when_missing(self, binary_mock) -> None:
        self.assertFalse(self.driver.is_available())

    def test_generate_openvpn_config_writes_temp_file(self) -> None:
        try:
            raw_config = self.driver.generate_openvpn_config(self.profile)
            self.assertIn("remote vpn.example.com 1194", raw_config)
            self.assertIsNotNone(self.driver._config_path)
            self.assertEqual(self.driver._config_path.name, CONFIG_NAME)
            self.assertEqual(self.driver._config_path.read_text(encoding="utf-8"), self.profile.config["raw_config"])
        finally:
            self.driver._cleanup_runtime()

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
    @patch.object(OpenVPNDriver, "_wait_for_ready", return_value=True)
    @patch.object(OpenVPNDriver, "generate_openvpn_config")
    @patch("drivers.openvpn_driver.subprocess.Popen")
    def test_connect_starts_process(self, popen_mock, generate_mock, ready_mock, binary_mock) -> None:
        process = popen_mock.return_value
        process.poll.return_value = None
        process.pid = 4242
        self.driver.last_error = "old OpenVPN failure"

        self.assertTrue(self.driver.connect(self.profile))
        generate_mock.assert_called_once_with(self.profile)
        ready_mock.assert_called_once_with(self.profile)
        popen_mock.assert_called_once()
        command = popen_mock.call_args.args[0]
        self.assertEqual(command[1:4], ["--nnp", "--inh-caps=-all,+net_admin,+net_raw", "--ambient-caps=-all,+net_admin,+net_raw"])
        self.assertEqual(command[5:8], ["/usr/sbin/openvpn", "--config", str(self.driver._config_path)])
        self.assertEqual(
            command[-9:],
            [
                "--dev",
                self.driver._expected_interface,
                "--dev-type",
                "tun",
                "--status",
                str(self.driver._status_path),
                "1",
                "--status-version",
                "3",
            ],
        )
        self.assertEqual(command[4], "--")
        self.assertIs(self.driver._process, process)
        self.assertIs(self.driver._active_profile, self.profile)
        self.assertIsNotNone(self.driver._connected_at)
        self.assertEqual(self.driver.last_error, "")

    @patch.object(OpenVPNDriver, "find_openvpn_binary", return_value="/usr/sbin/openvpn")
    @patch.object(OpenVPNDriver, "_wait_for_ready", return_value=True)
    @patch.object(OpenVPNDriver, "generate_openvpn_config")
    @patch("drivers.openvpn_driver.subprocess.Popen")
    def test_connect_disconnects_stale_process_before_starting_new_one(
        self, popen_mock, generate_mock, ready_mock, binary_mock
    ) -> None:
        # Regression guard for WDCLI-001.
        stale_process = unittest.mock.Mock()
        stale_process.poll.return_value = None
        self.driver._process = stale_process
        self.driver._active_profile = self.profile

        new_process = unittest.mock.Mock()
        new_process.poll.return_value = None
        new_process.pid = 9999
        popen_mock.return_value = new_process

        self.assertTrue(self.driver.connect(self.profile))

        stale_process.terminate.assert_called_once()
        self.assertIs(self.driver._process, new_process)

    def test_connect_refuses_spawn_after_failed_teardown(self) -> None:
        self.driver._process = unittest.mock.Mock()
        with (
            patch.object(self.driver, "disconnect", return_value=False) as disconnect_mock,
            patch.object(OpenVPNDriver, "find_openvpn_binary") as binary_mock,
        ):
            self.assertFalse(self.driver.connect(self.profile))

        disconnect_mock.assert_called_once_with()
        binary_mock.assert_not_called()
        self.assertIn("teardown failed", self.driver.last_error)


    @patch.object(OpenVPNDriver, "find_openvpn_binary", return_value=None)
    @patch("drivers.openvpn_driver.subprocess.Popen")
    def test_connect_returns_false_when_binary_missing(self, popen_mock, binary_mock) -> None:
        self.assertFalse(self.driver.connect(self.profile))
        popen_mock.assert_not_called()
        self.assertEqual(self.driver.last_error, "required binary not found: openvpn")

    @patch.object(OpenVPNDriver, "_cleanup_runtime")
    def test_disconnect_terminates_and_cleans_runtime(self, cleanup_mock) -> None:
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

    @patch.object(OpenVPNDriver, "_cleanup_runtime")
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

    @patch.object(OpenVPNDriver, "_cleanup_runtime")
    def test_disconnect_reports_failed_kill(self, cleanup_mock) -> None:
        process = unittest.mock.Mock()
        process.poll.return_value = None
        process.wait.side_effect = [
            subprocess.TimeoutExpired(cmd="openvpn", timeout=5),
            subprocess.TimeoutExpired(cmd="openvpn", timeout=5),
        ]
        self.driver._process = process

        self.assertFalse(self.driver.disconnect())
        process.terminate.assert_called_once()
        process.kill.assert_called_once()
        cleanup_mock.assert_called_once()

    @patch.object(OpenVPNDriver, "_vpn_interface_active", return_value=False)
    @patch("drivers.openvpn_driver.any_recorded_child_alive", return_value=False)
    def test_status_returns_standby_without_process(self, alive_mock, tun_mock) -> None:
        self.assertEqual(self.driver.status().status, "standby")

    @patch.object(OpenVPNDriver, "_vpn_interface_active", return_value=True)
    @patch("drivers.openvpn_driver.any_recorded_child_alive", return_value=False)
    def test_status_reports_runtime_mismatch_when_interface_orphaned(self, alive_mock, tun_mock) -> None:
        self.assertEqual(self.driver.status().status, "runtime_mismatch")

    @patch.object(OpenVPNDriver, "_vpn_interface_active", return_value=False)
    @patch("drivers.openvpn_driver.any_recorded_child_alive", return_value=True)
    def test_status_reports_runtime_mismatch_when_recorded_child_alive(self, alive_mock, tun_mock) -> None:
        self.assertEqual(self.driver.status().status, "runtime_mismatch")
    @patch.object(OpenVPNDriver, "_readiness_evidence_ready", return_value=True)

    @patch.object(OpenVPNDriver, "_vpn_interface_active", return_value=True)
    def test_status_returns_connected_when_process_alive(self, evidence_mock, tun_mock) -> None:
        process = unittest.mock.Mock()
        process.poll.return_value = None
        self.driver._process = process
        self.driver._active_profile = self.profile

        state = self.driver.status()
        self.assertEqual(state.status, "connected")
        self.assertEqual(state.mode, "openvpn")
        self.assertTrue(state.tun_active)
        self.assertFalse(state.proxy_active)

    @patch.object(OpenVPNDriver, "_cleanup_runtime")
    def test_status_reconciles_state_when_process_died_unexpectedly(self, cleanup_mock) -> None:
        process = unittest.mock.Mock()
        process.poll.return_value = 1
        self.driver._process = process
        self.driver._active_profile = self.profile
        self.driver._connected_at = unittest.mock.sentinel.connected_at

        state = self.driver.status()

        self.assertEqual(state.status, "standby")
        self.assertIsNone(self.driver._process)
        self.assertIsNone(self.driver._active_profile)
        self.assertIsNone(self.driver._connected_at)
        cleanup_mock.assert_called_once()

    def test_health_check_down_without_process(self) -> None:
        self.assertEqual(self.driver.health_check(), "down")

    @patch.object(OpenVPNDriver, "_vpn_interface_active", return_value=False)
    def test_health_check_degraded_without_tun(self, tun_mock) -> None:
        process = unittest.mock.Mock()
        process.poll.return_value = None
        self.driver._process = process
        self.assertEqual(self.driver.health_check(), "degraded")

    @patch.object(OpenVPNDriver, "_readiness_evidence_ready", return_value=True)
    @patch.object(OpenVPNDriver, "_vpn_interface_active", return_value=True)
    def test_health_check_ok_with_process_and_tun(self, tun_mock, evidence_mock) -> None:
        process = unittest.mock.Mock()
        process.poll.return_value = None
        self.driver._process = process
        self.assertEqual(self.driver.health_check(), "ok")
    @patch.object(OpenVPNDriver, "_readiness_evidence_ready", return_value=False)
    @patch.object(OpenVPNDriver, "_vpn_interface_active", return_value=True)
    def test_status_rejects_live_process_without_current_generation_evidence(
        self, _interface, _evidence
    ) -> None:
        process = unittest.mock.Mock()
        process.poll.return_value = None
        self.driver._process = process
        self.driver._active_profile = self.profile

        state = self.driver.status()

        self.assertEqual(state.status, "runtime_mismatch")
        self.assertFalse(state.tun_active)
        self.assertIn("readiness evidence", state.last_failure_reason)

    def test_readiness_rejects_unrelated_tun_and_requires_current_evidence(self) -> None:
        self.driver._ensure_runtime_paths()
        self.driver._configure_readiness(self.profile)
        expected = self.driver._expected_interface
        result = unittest.mock.Mock(returncode=0, stdout="7: tun0: <POINTOPOINT>\n")
        with (
            patch("drivers.openvpn_driver.shutil.which", return_value="/usr/bin/ip"),
            patch("drivers.openvpn_driver.subprocess.run", return_value=result),
        ):
            self.assertFalse(self.driver._vpn_interface_active(self.profile))
            result.stdout = f"7: {expected}: <POINTOPOINT>\n"
            self.assertTrue(self.driver._vpn_interface_active(self.profile))

        self.assertFalse(self.driver._readiness_evidence_ready())
        self.driver._status_path.write_text("OpenVPN STATISTICS\n", encoding="utf-8")
        self.driver._log_path.write_text("Initialization Sequence Completed\n", encoding="utf-8")
        self.assertTrue(self.driver._readiness_evidence_ready())

    def test_readiness_owns_a_short_tap_name_when_profile_requests_tap(self) -> None:
        profile = Profile(
            id="openvpn-tap",
            name="openvpn-tap",
            protocol=ProtocolType.OPENVPN,
            config={"raw_config": "client\ndev tap\n", "dev": "tap"},
            source=ProfileSource.MANUAL,
        )
        self.driver._ensure_runtime_paths()
        options = self.driver._configure_readiness(profile)

        self.assertEqual(self.driver._expected_device_type, "tap")
        # Must start with "tap" literally - OpenVPN rejects a topology-subnet
        # PUSH_REPLY on a --dev name not prefixed with tun/tap, regardless of
        # an explicit --dev-type (confirmed live, see openvpn_driver.py).
        self.assertTrue(self.driver._expected_interface.startswith("tapwd"))
        self.assertLessEqual(len(self.driver._expected_interface), 15)
        self.assertEqual(options[0:4], ("--dev", self.driver._expected_interface, "--dev-type", "tap"))

    @patch.object(OpenVPNDriver, "_readiness_evidence_ready", return_value=False)
    @patch.object(OpenVPNDriver, "_vpn_interface_active", return_value=True)
    def test_health_rejects_interface_without_current_generation_evidence(
        self, _interface, _evidence
    ) -> None:
        process = unittest.mock.Mock()
        process.poll.return_value = None
        self.driver._process = process

        self.assertEqual(self.driver.health_check(), "degraded")



if __name__ == "__main__":
    unittest.main()
