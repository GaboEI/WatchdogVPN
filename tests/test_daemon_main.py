from __future__ import annotations

import os
import signal
import socket
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

from cli.ipc.client import WatchdogIPCClient
import logging

from daemon.main import (
    CAP_NET_ADMIN,
    CAP_NET_BIND_SERVICE,
    CAPABILITY_WARNING,
    LOG_LEVEL_ENV,
    _has_required_capabilities,
    _resolve_log_level,
    main,
    _parse_cap_eff,
)
from daemon import systemd_helper


def wait_for_path(path: Path, timeout: float = 5.0) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if path.exists():
            return
        time.sleep(0.02)
    raise TimeoutError(f"timed out waiting for {path}")


class DaemonMainSubprocessTests(unittest.TestCase):
    def test_standalone_subprocess_serves_status_and_stops_on_sigterm(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            request_socket = root / "control.sock"
            event_socket = root / "control.events.sock"
            config_dir = root / "config"
            env = dict(os.environ)
            env.pop("NOTIFY_SOCKET", None)
            env["WATCHDOGVPN_CONFIG_DIR"] = str(config_dir)
            env["WATCHDOGVPN_EVENT_SOCKET_PATH"] = str(event_socket)
            # Isolate driver runtime dirs (children.json, owner.pid) from
            # the real /run/user/<uid> - otherwise a stray directory left
            # by an unrelated earlier process on the host can make this
            # subprocess's SingBoxDriver.status() report runtime_mismatch
            # instead of standby.
            env["WATCHDOGVPN_RUNTIME_DIR"] = str(root / "runtime")
            process = subprocess.Popen(
                [
                    sys.executable,
                    "-m",
                    "daemon.main",
                    "--standalone",
                    "--socket-path",
                    str(request_socket),
                ],
                cwd=Path(__file__).resolve().parents[1],
                env=env,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            try:
                wait_for_path(request_socket)
                client = WatchdogIPCClient(request_socket, event_socket, timeout=2.0)
                response = client.status()

                self.assertTrue(response.ok)
                self.assertEqual(response.payload["state"]["status"], "standby")

                process.send_signal(signal.SIGTERM)
                stdout, stderr = process.communicate(timeout=5.0)
            finally:
                if process.poll() is None:
                    process.kill()
                    process.communicate(timeout=5.0)

            self.assertEqual(process.returncode, 0, stderr)
            self.assertEqual(stdout, "")
            self.assertFalse(request_socket.exists())
            self.assertFalse(event_socket.exists())


class DaemonStartupProtectionTests(unittest.TestCase):
    @patch("daemon.main.IPCServer")
    @patch("daemon.main.systemd_helper.notify")
    @patch("daemon.main.build_watchdog")
    def test_failed_restart_barrier_never_starts_ipc_or_announces_ready(
        self, build_watchdog_mock, notify_mock, ipc_server_mock
    ) -> None:
        runtime = Mock()
        runtime.startup.return_value = Mock(status="kill_switch_failed")
        build_watchdog_mock.return_value = runtime

        self.assertEqual(main([]), 1)

        runtime.driver.reconcile_stale_tun_state.assert_called_once_with()
        runtime.startup.assert_called_once_with(require_restart_protection=True)
        ipc_server_mock.assert_not_called()
        notify_mock.assert_called_once_with(
            "STATUS=restart protection unavailable; daemon is not ready"
        )


class DaemonShutdownTests(unittest.TestCase):
    def test_sigterm_path_stops_ipc_before_runtime_shutdown(self) -> None:
        runtime = Mock()
        runtime.startup.return_value = Mock(status="standby")
        runtime.shutdown.return_value = True
        runtime.app_config = Mock()

        def request_stop(event) -> None:
            event.set()

        with (
            patch("daemon.main.build_watchdog") as build_watchdog_mock,
            patch("daemon.main.systemd_helper.notify") as notify_mock,
            patch("daemon.main._install_signal_handlers", side_effect=request_stop),
            patch("daemon.main.IPCServer") as ipc_server_mock,
            patch("daemon.main.WatchdogLoop") as watchdog_loop_mock,
            patch("daemon.main.ScheduledRotationLoop") as scheduled_loop_mock,
        ):
            build_watchdog_mock.return_value = runtime

            self.assertEqual(main([]), 0)

        runtime.startup.assert_called_once_with(require_restart_protection=True)
        runtime.shutdown.assert_called_once_with()
        ipc_server_mock.return_value.start.assert_called_once_with()
        ipc_server_mock.return_value.stop.assert_called_once_with()
        watchdog_loop_mock.return_value.stop.assert_called_once_with()
        scheduled_loop_mock.return_value.stop.assert_called_once_with()
        notify_mock.assert_any_call("STOPPING=1")

    def test_shutdown_does_not_clean_runtime_while_ipc_worker_is_alive(self) -> None:
        runtime = Mock()
        runtime.startup.return_value = Mock(status="standby")
        runtime.app_config = Mock()

        def request_stop(event) -> None:
            event.set()

        with (
            patch("daemon.main.build_watchdog") as build_watchdog_mock,
            patch("daemon.main.systemd_helper.notify") as notify_mock,
            patch("daemon.main._install_signal_handlers", side_effect=request_stop),
            patch("daemon.main.IPCServer") as ipc_server_mock,
            patch("daemon.main.WatchdogLoop"),
            patch("daemon.main.ScheduledRotationLoop"),
        ):
            build_watchdog_mock.return_value = runtime
            ipc_server_mock.return_value.stop.return_value = False

            self.assertEqual(main([]), 1)

        runtime.shutdown.assert_not_called()
        notify_mock.assert_any_call("STATUS=runtime cleanup failed during shutdown")

class DaemonCapabilityTests(unittest.TestCase):
    def test_parse_cap_eff_from_proc_status_fixture(self) -> None:
        status_text = "Name:\tpython3\nCapEff:\t0000000000001400\n"

        self.assertEqual(_parse_cap_eff(status_text), 0x1400)

    def test_required_capabilities_are_detected(self) -> None:
        cap_eff = (1 << CAP_NET_ADMIN) | (1 << CAP_NET_BIND_SERVICE)

        self.assertTrue(_has_required_capabilities(f"CapEff:\t{cap_eff:016x}\n"))
        self.assertFalse(_has_required_capabilities(f"CapEff:\t{(1 << CAP_NET_ADMIN):016x}\n"))
        self.assertFalse(_has_required_capabilities("Name:\tpython3\n"))
        self.assertFalse(_has_required_capabilities("CapEff:\tnot-hex\n"))

    def test_standalone_warning_prints_when_required_caps_are_missing(self) -> None:
        with patch("daemon.main.Path.read_text", return_value="CapEff:\t0000000000000000\n"):
            with patch("sys.stderr") as stderr:
                from daemon.main import _warn_if_standalone_lacks_capabilities

                _warn_if_standalone_lacks_capabilities()

        stderr.write.assert_any_call(CAPABILITY_WARNING)


class DaemonLoggingConfigTests(unittest.TestCase):
    """Regression coverage for a real-host finding: the daemon had no
    logging configuration at all in production (no logging.basicConfig
    anywhere), so every LOGGER.info() call was silently dropped and the two
    swallow points that only did logger.exception()/.warning() were
    invisible at any verbosity. These tests exercise the resolver in
    isolation, without ever starting the real daemon (main()), since that
    would touch real kill-switch/TUN/DNS state."""

    def test_resolve_log_level_defaults_to_info(self) -> None:
        with patch.dict(os.environ, {}, clear=False):
            os.environ.pop(LOG_LEVEL_ENV, None)
            self.assertEqual(_resolve_log_level(), logging.INFO)

    def test_resolve_log_level_accepts_valid_values_case_insensitively(self) -> None:
        with patch.dict(os.environ, {LOG_LEVEL_ENV: "debug"}):
            self.assertEqual(_resolve_log_level(), logging.DEBUG)
        with patch.dict(os.environ, {LOG_LEVEL_ENV: "ERROR"}):
            self.assertEqual(_resolve_log_level(), logging.ERROR)

    def test_resolve_log_level_falls_back_to_info_on_invalid_value(self) -> None:
        with patch.dict(os.environ, {LOG_LEVEL_ENV: "NOPE"}):
            with patch("sys.stderr") as stderr:
                level = _resolve_log_level()

        self.assertEqual(level, logging.INFO)
        stderr.write.assert_any_call(
            f"Warning: invalid {LOG_LEVEL_ENV}='NOPE', falling back to INFO"
        )


class SystemdHelperTests(unittest.TestCase):
    def test_notify_is_gated_on_notify_socket(self) -> None:
        with patch.dict(os.environ, {}, clear=True):
            systemd_helper.notify("READY=1")

    def test_notify_sends_datagram_to_unix_socket(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            notify_socket = Path(tmp) / "notify.sock"
            receiver = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
            receiver.bind(str(notify_socket))
            receiver.settimeout(2.0)
            try:
                with patch.dict(os.environ, {"NOTIFY_SOCKET": str(notify_socket)}):
                    systemd_helper.notify("READY=1")
                data = receiver.recv(1024)
            finally:
                receiver.close()

        self.assertEqual(data, b"READY=1")


if __name__ == "__main__":
    unittest.main()
