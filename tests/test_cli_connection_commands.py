from __future__ import annotations

import json
import os
import signal
import subprocess
import sys
import tempfile
import time
import unittest
from contextlib import redirect_stderr, redirect_stdout
from io import StringIO
from pathlib import Path
from unittest.mock import patch

import cli.main
from cli.ipc.errors import DaemonNotRunningError
from daemon.protocol import Response


ROOT_DIR = Path(__file__).resolve().parents[1]
WATCHDOG = ROOT_DIR / "bin" / "watchdog"


def wait_for_path(path: Path, timeout: float = 5.0) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if path.exists():
            return
        time.sleep(0.02)
    raise TimeoutError(f"timed out waiting for {path}")


class CliConnectionCommandTests(unittest.TestCase):
    def test_connect_uses_ipc_client(self) -> None:
        response = Response(
            ok=True,
            payload={
                "profile_id": "p1",
                "state": {
                    "status": "connected",
                    "mode": "rules",
                    "active_profile_id": "p1",
                    "tun_active": True,
                    "proxy_active": False,
                    "kill_switch_active": True,
                },
            },
        )
        with patch("cli.main.WatchdogIPCClient") as client_cls:
            client_cls.return_value.connect.return_value = response
            with redirect_stdout(StringIO()) as stdout:
                result = cli.main.main(["connect", "p1"])

        self.assertEqual(result, 0)
        client_cls.return_value.connect.assert_called_once_with("p1")
        self.assertIn("Connected", stdout.getvalue())
        self.assertIn("Profile: p1", stdout.getvalue())
        self.assertIn("Status: connected", stdout.getvalue())

    def test_disconnect_json_outputs_response_envelope(self) -> None:
        response = Response(ok=True, payload={"state": {"status": "standby", "mode": "standby"}})
        with patch("cli.main.WatchdogIPCClient") as client_cls:
            client_cls.return_value.disconnect.return_value = response
            with redirect_stdout(StringIO()) as stdout:
                result = cli.main.main(["disconnect", "--json"])

        self.assertEqual(result, 0)
        data = json.loads(stdout.getvalue())
        self.assertEqual(data["type"], "response")
        self.assertTrue(data["ok"])
        client_cls.return_value.disconnect.assert_called_once_with()

    def test_status_uses_ipc_client(self) -> None:
        response = Response(ok=True, payload={"state": {"status": "standby", "mode": "standby"}})
        with patch("cli.main.WatchdogIPCClient") as client_cls:
            client_cls.return_value.status.return_value = response
            with redirect_stdout(StringIO()) as stdout:
                result = cli.main.main(["status"])

        self.assertEqual(result, 0)
        client_cls.return_value.status.assert_called_once_with()
        self.assertIn("Status: standby", stdout.getvalue())

    def test_rotate_passes_force_flag(self) -> None:
        response = Response(ok=True, payload={"state": {"status": "recovered", "mode": "rules"}})
        with patch("cli.main.WatchdogIPCClient") as client_cls:
            client_cls.return_value.rotate.return_value = response
            with redirect_stdout(StringIO()):
                result = cli.main.main(["rotate", "--force"])

        self.assertEqual(result, 0)
        client_cls.return_value.rotate.assert_called_once_with(force=True)

    def test_daemon_error_response_returns_70(self) -> None:
        response = Response(ok=False, error="profile not found: missing")
        with patch("cli.main.WatchdogIPCClient") as client_cls:
            client_cls.return_value.connect.return_value = response
            with redirect_stderr(StringIO()) as stderr:
                result = cli.main.main(["connect", "missing"])

        self.assertEqual(result, 70)
        self.assertIn("profile not found: missing", stderr.getvalue())

    def test_ipc_error_uses_exception_exit_code(self) -> None:
        with patch("cli.main.WatchdogIPCClient") as client_cls:
            client_cls.return_value.status.side_effect = DaemonNotRunningError()
            with redirect_stderr(StringIO()) as stderr:
                result = cli.main.main(["status"])

        self.assertEqual(result, DaemonNotRunningError.exit_code)
        self.assertIn("WatchdogVPN daemon is not running", stderr.getvalue())


class CliConnectionCommandEndToEndTests(unittest.TestCase):
    def test_watchdog_status_json_against_standalone_daemon(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            request_socket = root / "control.sock"
            event_socket = root / "control.events.sock"
            config_dir = root / "config"
            env = dict(os.environ)
            env.pop("NOTIFY_SOCKET", None)
            env["WATCHDOGVPN_CONFIG_DIR"] = str(config_dir)
            env["WATCHDOGVPN_SOCKET_PATH"] = str(request_socket)
            env["WATCHDOGVPN_EVENT_SOCKET_PATH"] = str(event_socket)
            env["PYTHONPATH"] = str(ROOT_DIR)
            daemon = subprocess.Popen(
                [
                    sys.executable,
                    "-m",
                    "daemon.main",
                    "--standalone",
                    "--socket-path",
                    str(request_socket),
                ],
                cwd=ROOT_DIR,
                env=env,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            try:
                wait_for_path(request_socket)
                result = subprocess.run(
                    [str(WATCHDOG), "status", "--json"],
                    cwd=ROOT_DIR,
                    env=env,
                    text=True,
                    capture_output=True,
                    check=False,
                )
                daemon.send_signal(signal.SIGTERM)
                _, daemon_stderr = daemon.communicate(timeout=5.0)
            finally:
                if daemon.poll() is None:
                    daemon.kill()
                    daemon.communicate(timeout=5.0)

        self.assertEqual(result.returncode, 0, result.stderr)
        data = json.loads(result.stdout)
        self.assertTrue(data["ok"])
        self.assertEqual(data["payload"]["state"]["status"], "standby")
        self.assertEqual(daemon.returncode, 0, daemon_stderr)


if __name__ == "__main__":
    unittest.main()
