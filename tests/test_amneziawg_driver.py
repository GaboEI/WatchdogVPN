from __future__ import annotations

import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

from drivers.amneziawg_driver import (
    CONFIG_NAME,
    HANDSHAKE_TIMEOUT_SECONDS,
    INTERFACE_NAME,
    ROUTE_TABLE,
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

    @patch("drivers.amneziawg_driver.shutil.which", return_value="/usr/bin/awg")
    @patch("drivers.amneziawg_driver.os.path.exists", return_value=False)
    @patch("drivers.amneziawg_driver.os.access", return_value=False)
    def test_find_wg_tool_falls_back_to_which(self, _access, _exists, _which) -> None:
        self.assertEqual(self.driver.find_wg_tool(), "/usr/bin/awg")

    @patch("drivers.amneziawg_driver.os.path.exists", return_value=True)
    @patch("drivers.amneziawg_driver.os.access", return_value=True)
    def test_find_wg_tool_prefers_awg(self, _access, _exists) -> None:
        result = self.driver.find_wg_tool()
        self.assertEqual(result, "/usr/local/bin/awg")

    @patch("drivers.amneziawg_driver.shutil.which", side_effect=lambda n: "/usr/bin/amneziawg-go" if n == "amneziawg-go" else None)
    @patch("drivers.amneziawg_driver.os.path.exists", return_value=False)
    @patch("drivers.amneziawg_driver.os.access", return_value=False)
    def test_find_userspace_tool_falls_back_to_which(self, _access, _exists, _which) -> None:
        result = self.driver.find_userspace_tool()
        self.assertEqual(result, "/usr/bin/amneziawg-go")

    @patch.dict("drivers.amneziawg_driver.os.environ", {"WATCHDOGVPN_AMNEZIAWG_BIN": "/opt/awg"})
    @patch("drivers.amneziawg_driver.os.path.exists", return_value=True)
    @patch("drivers.amneziawg_driver.os.access", return_value=True)
    def test_find_wg_tool_env_var_override(self, _access, _exists) -> None:
        self.assertEqual(self.driver.find_wg_tool(), "/opt/awg")

    @patch("drivers.amneziawg_driver.shutil.which", return_value=None)
    @patch("drivers.amneziawg_driver.os.path.exists", return_value=False)
    @patch("drivers.amneziawg_driver.os.access", return_value=False)
    def test_find_wg_tool_none_when_missing(self, _access, _exists, _which) -> None:
        self.assertIsNone(self.driver.find_wg_tool())

    @patch.object(AmneziaWGDriver, "check_version", return_value="amneziawg-tools v1.0.0")
    @patch.object(AmneziaWGDriver, "find_userspace_tool", return_value="/usr/bin/amneziawg-go")
    @patch.object(AmneziaWGDriver, "find_ip_tool", return_value="/usr/bin/ip")
    def test_is_available_true(self, _ip, _go, _version) -> None:
        self.assertTrue(self.driver.is_available())

    @patch.object(AmneziaWGDriver, "find_ip_tool", return_value=None)
    def test_is_available_false(self, _ip) -> None:
        self.assertFalse(self.driver.is_available())

    @patch.object(AmneziaWGDriver, "find_wg_tool", return_value=None)
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
        with self.assertRaisesRegex(FileNotFoundError, "awg was not found"):
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
        self.assertNotIn("Address =", content)
        self.assertNotIn("DNS =", content)

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

    @patch.object(AmneziaWGDriver, "_ensure_src_valid_mark")
    @patch.object(AmneziaWGDriver, "_interface_exists", side_effect=[False, True])
    @patch.object(AmneziaWGDriver, "find_wg_tool", return_value="/usr/bin/awg")
    @patch.object(AmneziaWGDriver, "find_ip_tool", return_value="/usr/bin/ip")
    @patch("drivers.amneziawg_driver.subprocess.run")
    def test_connect_success(self, run_mock, _ip, _awg, _iface, _src_valid_mark) -> None:
        run_mock.return_value.returncode = 0
        run_mock.return_value.stdout = ""
        run_mock.return_value.stderr = ""

        self.assertTrue(self.driver.connect(self.profile))
        self.assertIsNotNone(self.driver._config_path)
        calls = [call.args[0] for call in run_mock.call_args_list]
        self.assertIn(["/usr/bin/ip", "link", "add", INTERFACE_NAME, "type", "amneziawg"], calls)
        self.assertIn(["/usr/bin/awg", "setconf", INTERFACE_NAME, str(self.driver._config_path)], calls)
        self.assertIn(["/usr/bin/ip", "-4", "address", "add", "10.8.1.5/32", "dev", INTERFACE_NAME], calls)
        self.assertIn(["/usr/bin/awg", "set", INTERFACE_NAME, "fwmark", ROUTE_TABLE], calls)
        self.assertIn(
            ["/usr/bin/ip", "-4", "rule", "add", "not", "fwmark", ROUTE_TABLE, "table", ROUTE_TABLE],
            calls,
        )
        self.assertIs(self.driver._active_profile, self.profile)
        self.assertIsNotNone(self.driver._connected_at)

    @patch.object(AmneziaWGDriver, "_interface_exists", return_value=False)
    @patch.object(AmneziaWGDriver, "find_userspace_tool", return_value=None)
    @patch.object(AmneziaWGDriver, "find_wg_tool", return_value="/usr/bin/awg")
    @patch.object(AmneziaWGDriver, "find_ip_tool", return_value="/usr/bin/ip")
    @patch("drivers.amneziawg_driver.subprocess.run")
    def test_connect_failure_cleans_up(self, run_mock, _ip, _awg, _go, _iface) -> None:
        run_mock.return_value.returncode = 1
        run_mock.return_value.stdout = ""
        run_mock.return_value.stderr = "PrivateKey = should-not-leak\nRTNETLINK answers: Operation not permitted"

        self.assertFalse(self.driver.connect(self.profile))
        self.assertIsNone(self.driver._config_path)
        self.assertIsNone(self.driver._active_profile)
        self.assertIn("amneziawg interface creation failed with code 1", self.driver.last_error)
        self.assertIn("RTNETLINK answers: Operation not permitted", self.driver.last_error)
        self.assertNotIn("should-not-leak", self.driver.last_error)

    @patch.object(AmneziaWGDriver, "find_wg_tool", return_value=None)
    def test_connect_returns_false_when_no_binary(self, _tool) -> None:
        self.assertFalse(self.driver.connect(self.profile))
        self.assertIn("awg was not found", self.driver.last_error)

    @patch.object(AmneziaWGDriver, "_ensure_src_valid_mark")
    @patch.object(AmneziaWGDriver, "_interface_exists", side_effect=[False, False, False, False, True])
    @patch.object(AmneziaWGDriver, "find_wg_tool", return_value="/usr/bin/awg")
    @patch.object(AmneziaWGDriver, "find_ip_tool", return_value="/usr/bin/ip")
    @patch("drivers.amneziawg_driver.subprocess.run")
    def test_connect_disconnects_stale_userspace_process_before_starting_new_one(
        self, run_mock, _ip, _awg, _iface, _src_valid_mark
    ) -> None:
        # Regression guard for WDCLI-001, covering the userspace-fallback
        # path (kernel module unavailable) - AmneziaWGDriver already
        # self-heals its kernel interface via _interface_exists(), but its
        # userspace fallback process had the same unguarded overwrite as
        # the other drivers.
        run_mock.return_value.returncode = 0
        run_mock.return_value.stdout = ""
        run_mock.return_value.stderr = ""
        stale_userspace_process = Mock()
        stale_userspace_process.poll.return_value = None
        self.driver._userspace_process = stale_userspace_process
        self.driver._active_profile = self.profile

        self.assertTrue(self.driver.connect(self.profile))

        stale_userspace_process.terminate.assert_called_once()

    def test_ensure_src_valid_mark_passes_when_already_one(self) -> None:
        with (
            patch.object(type(self.driver), "_src_valid_mark_path") as path_mock,
            tempfile.TemporaryDirectory() as tmp,
        ):
            path = Path(tmp) / "src_valid_mark"
            path.write_text("1\n", encoding="utf-8")
            path_mock.return_value = path
            self.driver._ensure_src_valid_mark()

    def test_ensure_src_valid_mark_raises_with_actionable_message_when_zero(self) -> None:
        with (
            patch.object(type(self.driver), "_src_valid_mark_path") as path_mock,
            tempfile.TemporaryDirectory() as tmp,
        ):
            path = Path(tmp) / "src_valid_mark"
            path.write_text("0\n", encoding="utf-8")
            path_mock.return_value = path
            with self.assertRaises(RuntimeError) as ctx:
                self.driver._ensure_src_valid_mark()
        self.assertIn("src_valid_mark", str(ctx.exception))
        self.assertIn(f"sysctl -w net.ipv4.conf.{INTERFACE_NAME}.src_valid_mark=1", str(ctx.exception))

    def test_ensure_src_valid_mark_raises_when_unreadable(self) -> None:
        with (
            patch.object(type(self.driver), "_src_valid_mark_path") as path_mock,
            tempfile.TemporaryDirectory() as tmp,
        ):
            path_mock.return_value = Path(tmp) / "does-not-exist" / "src_valid_mark"
            with self.assertRaises(RuntimeError) as ctx:
                self.driver._ensure_src_valid_mark()
        self.assertIn("could not read", str(ctx.exception))

    def test_sanitize_error_detail_truncation_keeps_the_tail(self) -> None:
        # A long, fixed-shape prefix (e.g. a subprocess banner) must not
        # crowd out what happened most recently, which is consistently more
        # actionable for field debugging than a predictable prefix.
        text = f"{'banner ' * 200}most recent failure reason"
        result = self.driver._sanitize_error_detail(text)
        self.assertTrue(result.startswith("..."))
        self.assertIn("most recent failure reason", result)

    def test_userspace_log_tail_char_cap_keeps_the_end(self) -> None:
        self.driver._write_config(self.profile)
        self.driver._reset_log()
        self.driver._userspace_log_path.write_text(
            f"{'x' * 1000}\nreal failure line at the end", encoding="utf-8"
        )

        tail = self.driver._userspace_log_tail()
        self.assertTrue(tail.startswith("..."))
        self.assertIn("real failure line at the end", tail)

    @patch.object(AmneziaWGDriver, "_wait_for_uapi_socket", return_value=True)
    @patch.object(AmneziaWGDriver, "_wait_for_interface", return_value=True)
    @patch.object(AmneziaWGDriver, "find_userspace_tool", return_value="/usr/bin/amneziawg-go")
    @patch("drivers.amneziawg_driver.subprocess.Popen")
    @patch("drivers.amneziawg_driver.subprocess.run")
    def test_create_interface_uses_userspace_fallback(self, run_mock, popen_mock, _go, _wait, _socket) -> None:
        run_mock.return_value.returncode = 2
        run_mock.return_value.stdout = ""
        run_mock.return_value.stderr = "Unknown device type"
        popen_mock.return_value.pid = 5555

        self.driver._write_config(self.profile)
        self.driver._reset_log()
        self.driver._create_interface()

        popen_mock.assert_called_once()
        self.assertEqual(popen_mock.call_args.args[0], ["/usr/bin/amneziawg-go", INTERFACE_NAME])

    @patch.object(AmneziaWGDriver, "_wait_for_uapi_socket", return_value=False)
    @patch.object(AmneziaWGDriver, "_wait_for_interface", return_value=True)
    @patch.object(AmneziaWGDriver, "find_userspace_tool", return_value="/usr/bin/amneziawg-go")
    @patch("drivers.amneziawg_driver.subprocess.Popen")
    @patch("drivers.amneziawg_driver.subprocess.run")
    def test_create_interface_fails_when_uapi_socket_never_appears(
        self, run_mock, popen_mock, _go, _wait, _socket
    ) -> None:
        run_mock.return_value.returncode = 2
        run_mock.return_value.stdout = ""
        run_mock.return_value.stderr = "Unknown device type"
        popen_mock.return_value.pid = 5555

        self.driver._write_config(self.profile)
        self.driver._reset_log()
        with self.assertRaises(RuntimeError) as ctx:
            self.driver._create_interface()

        self.assertIn("uapi socket did not appear at", str(ctx.exception))

    def test_wait_for_uapi_socket_true_when_socket_exists(self) -> None:
        with (
            patch.object(type(self.driver), "_uapi_socket_path") as socket_path_mock,
            tempfile.TemporaryDirectory() as tmp,
        ):
            socket_path = Path(tmp) / f"{INTERFACE_NAME}.sock"
            socket_path.write_text("")
            socket_path_mock.return_value = socket_path
            self.assertTrue(self.driver._wait_for_uapi_socket(timeout=0.2))

    def test_wait_for_uapi_socket_false_when_missing(self) -> None:
        with (
            patch.object(type(self.driver), "_uapi_socket_path") as socket_path_mock,
            tempfile.TemporaryDirectory() as tmp,
        ):
            socket_path_mock.return_value = Path(tmp) / f"{INTERFACE_NAME}.sock"
            self.assertFalse(self.driver._wait_for_uapi_socket(timeout=0.1))

    def test_userspace_log_tail_reads_recent_lines(self) -> None:
        self.driver._write_config(self.profile)
        self.driver._reset_log()
        # amneziawg-go's own stdout/stderr, kept in a dedicated file separate
        # from the driver's own _log() debug lines.
        self.driver._userspace_log_path.write_text("line one\nline two\n", encoding="utf-8")

        self.assertEqual(self.driver._userspace_log_tail(), "line one\nline two")

    def test_userspace_log_tail_ignores_driver_debug_log(self) -> None:
        self.driver._write_config(self.profile)
        self.driver._reset_log()
        self.driver._log("unrelated driver debug line")

        self.assertEqual(self.driver._userspace_log_tail(), "")

    def test_userspace_log_tail_empty_without_runtime_dir(self) -> None:
        self.assertEqual(self.driver._userspace_log_tail(), "")

    # --- Disconnect ---

    @patch.object(AmneziaWGDriver, "_interface_exists", return_value=False)
    @patch.object(AmneziaWGDriver, "find_ip_tool", return_value="/usr/bin/ip")
    @patch("drivers.amneziawg_driver.subprocess.run")
    def test_disconnect_success(self, run_mock, _ip, _iface) -> None:
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
    @patch.object(AmneziaWGDriver, "find_wg_tool", return_value="/usr/bin/awg")
    @patch.object(AmneziaWGDriver, "find_ip_tool", return_value="/usr/bin/ip")
    @patch("drivers.amneziawg_driver.subprocess.run")
    def test_connect_refuses_stale_interface_when_delete_fails(self, run_mock, _ip, _awg, _iface, delete_mock) -> None:
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
    @patch("drivers.amneziawg_driver.any_recorded_child_alive", return_value=False)
    def test_status_standby_without_interface(self, _alive, _iface) -> None:
        state = self.driver.status()
        self.assertEqual(state.status, "standby")

    @patch.object(AmneziaWGDriver, "_interface_exists", return_value=True)
    @patch("drivers.amneziawg_driver.any_recorded_child_alive", return_value=False)
    def test_status_reports_runtime_mismatch_when_active_profile_none_but_interface_up(
        self, _alive, _iface
    ) -> None:
        # Regression guard for the short-circuit bug: `self._active_profile
        # is None or not self._interface_exists()` used to skip the
        # interface check entirely whenever there was no active profile
        # (always true after disconnect()), so an orphaned interface never
        # got detected.
        state = self.driver.status()
        self.assertEqual(state.status, "runtime_mismatch")

    @patch.object(AmneziaWGDriver, "_interface_exists", return_value=False)
    @patch("drivers.amneziawg_driver.any_recorded_child_alive", return_value=True)
    def test_status_reports_runtime_mismatch_when_recorded_child_alive(self, _alive, _iface) -> None:
        state = self.driver.status()
        self.assertEqual(state.status, "runtime_mismatch")

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
