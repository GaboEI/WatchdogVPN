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
from unittest.mock import patch

from cli.ipc.client import WatchdogIPCClient
from daemon.main import (
    CAP_NET_ADMIN,
    CAP_NET_BIND_SERVICE,
    CAPABILITY_WARNING,
    _has_required_capabilities,
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
