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
    def setUp(self) -> None:
        # _connection_lifecycle_summary() reads real persisted vpn_desired_state
        # through StateManager/resolve_config_dir(). Without isolation these
        # tests read the machine's actual installed/user state instead of a
        # controlled default, so results depend on ambient local state left
        # over from unrelated real VPN activity on this host.
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        env_patcher = patch.dict(os.environ, {"WATCHDOGVPN_CONFIG_DIR": tmp.name})
        env_patcher.start()
        self.addCleanup(env_patcher.stop)

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
        self.assertIn("Daemon: reachable", stdout.getvalue())
        self.assertIn("Status: connected", stdout.getvalue())
        self.assertIn("Actual runtime state: connected", stdout.getvalue())

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
        self.assertTrue(data["payload"]["lifecycle"]["daemon_reachable"])
        self.assertTrue(data["payload"]["lifecycle"]["disconnected_cleanly"])
        self.assertTrue(data["payload"]["lifecycle"]["cleanup_expectations"]["applies"])
        client_cls.return_value.disconnect.assert_called_once_with()

    def test_disconnect_human_output_documents_cleanup_expectations(self) -> None:
        response = Response(
            ok=True,
            payload={
                "state": {
                    "status": "standby",
                    "mode": "standby",
                    "proxy_active": False,
                    "tun_active": False,
                    "lan_gateway_status": "disabled",
                }
            },
        )
        with patch("cli.main.WatchdogIPCClient") as client_cls:
            client_cls.return_value.disconnect.return_value = response
            with redirect_stdout(StringIO()) as stdout:
                result = cli.main.main(["disconnect"])

        self.assertEqual(result, 0)
        output = stdout.getvalue()
        self.assertIn("Disconnected", output)
        self.assertIn("Disconnected cleanly: on", output)
        self.assertIn("Cleanup expectations:", output)
        self.assertIn("process_cleanup", output)
        self.assertIn("dns_restore", output)

    def test_status_uses_ipc_client(self) -> None:
        response = Response(ok=True, payload={"state": {"status": "standby", "mode": "standby"}})
        with patch("cli.main.WatchdogIPCClient") as client_cls:
            client_cls.return_value.status.return_value = response
            with redirect_stdout(StringIO()) as stdout:
                result = cli.main.main(["status"])

        self.assertEqual(result, 0)
        client_cls.return_value.status.assert_called_once_with()
        self.assertIn("Status: standby", stdout.getvalue())
        self.assertIn("Desired state:", stdout.getvalue())
        self.assertIn("Disconnected cleanly:", stdout.getvalue())

    def test_status_json_includes_lifecycle_contract(self) -> None:
        response = Response(
            ok=True,
            payload={
                "state": {
                    "status": "connected",
                    "mode": "rules",
                    "active_profile_id": "p1",
                    "proxy_active": True,
                    "tun_active": False,
                    "kill_switch_active": False,
                }
            },
        )
        with patch("cli.main.WatchdogIPCClient") as client_cls:
            client_cls.return_value.status.return_value = response
            with redirect_stdout(StringIO()) as stdout:
                result = cli.main.main(["status", "--json"])

        self.assertEqual(result, 0)
        data = json.loads(stdout.getvalue())
        lifecycle = data["payload"]["lifecycle"]
        self.assertTrue(lifecycle["daemon_reachable"])
        self.assertEqual(lifecycle["actual_runtime_state"], "connected")
        self.assertEqual(lifecycle["active_profile_id"], "p1")
        self.assertTrue(lifecycle["runtime_active"])
        self.assertFalse(lifecycle["disconnected_cleanly"])

    def test_status_json_surfaces_critical_effective_runtime_mismatch(self) -> None:
        response = Response(
            ok=True,
            payload={
                "state": {
                    "status": "runtime_mismatch",
                    "mode": "sing-box",
                    "proxy_active": True,
                    "kill_switch_active": False,
                    "kill_switch_status": "partial",
                    "kill_switch_method": "nftables",
                    "kill_switch_consistent": False,
                    "runtime_mismatch_severity": "critical",
                    "runtime_artifacts": [
                        "owned_listener:tcp/2080",
                        "kill_switch:nftables/partial",
                    ],
                }
            },
        )
        with patch("cli.main.WatchdogIPCClient") as client_cls:
            client_cls.return_value.status.return_value = response
            with redirect_stdout(StringIO()) as stdout:
                result = cli.main.main(["status", "--json"])

        self.assertEqual(result, 0)
        lifecycle = json.loads(stdout.getvalue())["payload"]["lifecycle"]
        self.assertTrue(lifecycle["runtime_active"])
        self.assertTrue(lifecycle["failure_or_degraded"])
        self.assertFalse(lifecycle["disconnected_cleanly"])
        self.assertEqual(lifecycle["kill_switch_status"], "partial")
        self.assertFalse(lifecycle["kill_switch_consistent"])
        self.assertEqual(lifecycle["runtime_mismatch_severity"], "critical")
        self.assertEqual(
            lifecycle["runtime_artifacts"],
            ["owned_listener:tcp/2080", "kill_switch:nftables/partial"],
        )

    def test_status_human_prints_runtime_mismatch_evidence_and_recovery(self) -> None:
        response = Response(
            ok=True,
            payload={
                "state": {
                    "status": "runtime_mismatch",
                    "mode": "sing-box",
                    "runtime_mismatch_severity": "critical",
                    "runtime_artifacts": ["missing_proxy_listener:tcp/2081"],
                    "kill_switch_status": "inactive",
                }
            },
        )
        with patch("cli.main.WatchdogIPCClient") as client_cls:
            client_cls.return_value.status.return_value = response
            with redirect_stdout(StringIO()) as stdout:
                result = cli.main.main(["status", "--no-color"])

        self.assertEqual(result, 0)
        output = stdout.getvalue()
        self.assertIn("Runtime mismatch severity: critical", output)
        self.assertIn("missing_proxy_listener:tcp/2081", output)
        self.assertIn("watchdog disconnect", output)

    def test_rotate_passes_force_flag(self) -> None:
        response = Response(ok=True, payload={"state": {"status": "recovered", "mode": "rules"}})
        with patch("cli.main.WatchdogIPCClient") as client_cls:
            client_cls.return_value.rotate.return_value = response
            with redirect_stdout(StringIO()):
                result = cli.main.main(["rotate", "--force"])

        self.assertEqual(result, 0)
        client_cls.return_value.rotate.assert_called_once_with(force=True)

    def test_rotate_json_reports_runtime_safety_path(self) -> None:
        response = Response(
            ok=True,
            payload={
                "state": {
                    "status": "recovered",
                    "mode": "rules",
                    "active_profile_id": "p2",
                    "proxy_active": True,
                }
            },
        )
        with patch("cli.main.WatchdogIPCClient") as client_cls:
            client_cls.return_value.rotate.return_value = response
            with redirect_stdout(StringIO()) as stdout:
                result = cli.main.main(["rotate", "--json"])

        self.assertEqual(result, 0)
        client_cls.return_value.rotate.assert_called_once_with(force=False)
        data = json.loads(stdout.getvalue())
        self.assertEqual(data["payload"]["lifecycle"]["command"], "rotate")
        self.assertEqual(data["payload"]["lifecycle"]["actual_runtime_state"], "recovered")
        self.assertFalse(data["payload"]["lifecycle"]["cleanup_expectations"]["applies"])

    def test_daemon_error_response_returns_70(self) -> None:
        response = Response(ok=False, error="profile not found: missing")
        with patch("cli.main.WatchdogIPCClient") as client_cls:
            client_cls.return_value.connect.return_value = response
            with redirect_stderr(StringIO()) as stderr:
                result = cli.main.main(["connect", "missing"])

        self.assertEqual(result, 70)
        self.assertIn("profile not found: missing", stderr.getvalue())
        self.assertIn("hint: run: watchdog profile list", stderr.getvalue())

    def test_daemon_error_json_includes_recovery_hints(self) -> None:
        response = Response(
            ok=False,
            payload={"error_kind": "profile_not_found"},
            error="profile not found: missing",
        )
        with patch("cli.main.WatchdogIPCClient") as client_cls:
            client_cls.return_value.connect.return_value = response
            with redirect_stdout(StringIO()) as stdout:
                result = cli.main.main(["connect", "missing", "--json"])

        self.assertEqual(result, 70)
        data = json.loads(stdout.getvalue())
        self.assertIs(data["payload"]["lifecycle"]["profile_available"], False)
        self.assertIn("watchdog profile list", data["payload"]["recovery_hints"][0])

    def test_connect_invalid_input_reports_indeterminate_profile_availability(self) -> None:
        # Regression guard for WDCLI-005: an empty/malformed profile_id has
        # no profile identity to assess - must not default to True the way
        # the old substring-matching heuristic silently did.
        response = Response(
            ok=False,
            payload={"error_kind": "invalid_input"},
            error="profile_id must be a non-empty string",
        )
        with patch("cli.main.WatchdogIPCClient") as client_cls:
            client_cls.return_value.connect.return_value = response
            with redirect_stdout(StringIO()) as stdout:
                result = cli.main.main(["connect", "", "--json"])

        self.assertEqual(result, 70)
        data = json.loads(stdout.getvalue())
        self.assertIsNone(data["payload"]["lifecycle"]["profile_available"])

    def test_connect_driver_failure_reports_profile_available_true(self) -> None:
        response = Response(
            ok=False,
            payload={"error_kind": "connect_failed", "state": {"status": "standby"}},
            error="connect failed",
        )
        with patch("cli.main.WatchdogIPCClient") as client_cls:
            client_cls.return_value.connect.return_value = response
            with redirect_stdout(StringIO()) as stdout:
                result = cli.main.main(["connect", "p1", "--json"])

        self.assertEqual(result, 70)
        data = json.loads(stdout.getvalue())
        self.assertIs(data["payload"]["lifecycle"]["profile_available"], True)

    def test_connect_cleanup_failure_reports_profile_available_true(self) -> None:
        response = Response(
            ok=False,
            payload={"error_kind": "cleanup_failed", "state": {"status": "cleanup_failed"}},
            error="runtime cleanup failed",
        )
        with patch("cli.main.WatchdogIPCClient") as client_cls:
            client_cls.return_value.connect.return_value = response
            with redirect_stdout(StringIO()) as stdout:
                result = cli.main.main(["connect", "p1", "--json"])

        self.assertEqual(result, 70)
        data = json.loads(stdout.getvalue())
        self.assertIs(data["payload"]["lifecycle"]["profile_available"], True)
        self.assertEqual(data["payload"]["lifecycle"]["actual_runtime_state"], "cleanup_failed")


    def test_rotate_all_failed_reports_ok_false_and_exit_70(self) -> None:
        # Regression guard for WDCLI-002: rotate must not report success
        # when the resulting status is a terminal failure.
        response = Response(
            ok=False,
            payload={
                "state": {"status": "all_failed", "mode": "standby"},
                "performed": True,
            },
            error="rotation did not recover a healthy connection: status=all_failed",
        )
        with patch("cli.main.WatchdogIPCClient") as client_cls:
            client_cls.return_value.rotate.return_value = response
            with redirect_stdout(StringIO()) as stdout:
                result = cli.main.main(["rotate", "--force", "--json"])

        self.assertEqual(result, 70)
        data = json.loads(stdout.getvalue())
        self.assertFalse(data["ok"])
        self.assertTrue(data["payload"]["lifecycle"]["failure_or_degraded"])

    def test_rotate_gate_off_reports_performed_false_with_exit_0(self) -> None:
        # Regression guard for WDCLI-004: a no-op rotate (VPN intentionally
        # off) must stay exit 0 / ok:true, distinguished via "performed".
        response = Response(
            ok=True,
            payload={
                "state": {"status": "standby", "mode": "standby"},
                "performed": False,
            },
        )
        with patch("cli.main.WatchdogIPCClient") as client_cls:
            client_cls.return_value.rotate.return_value = response
            with redirect_stdout(StringIO()) as stdout:
                result = cli.main.main(["rotate", "--force"])

        self.assertEqual(result, 0)
        self.assertIn("Rotation skipped", stdout.getvalue())

    def test_status_json_surfaces_persisted_last_failure(self) -> None:
        response = Response(
            ok=True,
            payload={
                "state": {
                    "status": "standby",
                    "mode": "standby",
                    "last_failure_reason": "all_failed",
                    "last_failure_at": "2026-07-12T10:00:00+00:00",
                }
            },
        )
        with patch("cli.main.WatchdogIPCClient") as client_cls:
            client_cls.return_value.status.return_value = response
            with redirect_stdout(StringIO()) as stdout:
                result = cli.main.main(["status", "--json"])

        self.assertEqual(result, 0)
        data = json.loads(stdout.getvalue())
        lifecycle = data["payload"]["lifecycle"]
        self.assertTrue(lifecycle["failure_or_degraded"])
        self.assertEqual(lifecycle["last_failure_reason"], "all_failed")
        self.assertEqual(lifecycle["last_failure_at"], "2026-07-12T10:00:00+00:00")

    def test_ipc_error_uses_exception_exit_code(self) -> None:
        with patch("cli.main.WatchdogIPCClient") as client_cls:
            client_cls.return_value.status.side_effect = DaemonNotRunningError()
            with redirect_stderr(StringIO()) as stderr:
                result = cli.main.main(["status"])

        self.assertEqual(result, DaemonNotRunningError.exit_code)
        self.assertIn("WatchdogVPN daemon is not running", stderr.getvalue())
        self.assertIn("hint: start the daemon", stderr.getvalue())

    def test_ipc_error_json_reports_daemon_unreachable(self) -> None:
        with patch("cli.main.WatchdogIPCClient") as client_cls:
            client_cls.return_value.status.side_effect = DaemonNotRunningError()
            with redirect_stdout(StringIO()) as stdout:
                result = cli.main.main(["status", "--json"])

        self.assertEqual(result, DaemonNotRunningError.exit_code)
        data = json.loads(stdout.getvalue())
        self.assertFalse(data["ok"])
        self.assertFalse(data["payload"]["lifecycle"]["daemon_reachable"])
        self.assertEqual(data["payload"]["lifecycle"]["actual_runtime_state"], "unknown")
        self.assertIn("sudo systemctl start watchdogvpn", data["payload"]["recovery_hints"][0])

    def test_status_human_shows_last_failure_line(self) -> None:
        response = Response(
            ok=True,
            payload={
                "state": {
                    "status": "standby",
                    "mode": "standby",
                    "last_failure_reason": "all_failed",
                    "last_failure_at": "2026-07-12T10:00:00+00:00",
                }
            },
        )
        with patch("cli.main.WatchdogIPCClient") as client_cls:
            client_cls.return_value.status.return_value = response
            with redirect_stdout(StringIO()) as stdout:
                result = cli.main.main(["status"])

        self.assertEqual(result, 0)
        self.assertIn("Last failure: all_failed at 2026-07-12T10:00:00+00:00", stdout.getvalue())

    def test_argparse_error_with_json_flag_emits_json_envelope_on_stdout(self) -> None:
        # Regression guard for WDCLI-009: argparse-level errors (missing
        # required arg here) used to always print plain text to stderr and
        # ignore --json entirely.
        stdout = StringIO()
        stderr = StringIO()
        with redirect_stdout(stdout), redirect_stderr(stderr):
            with self.assertRaises(SystemExit) as ctx:
                cli.main.main(["connect", "--json"])

        self.assertEqual(ctx.exception.code, 2)
        self.assertEqual(stderr.getvalue(), "")
        data = json.loads(stdout.getvalue())
        self.assertFalse(data["ok"])
        self.assertIn("profile_id", data["error"])

    def test_argparse_error_without_json_flag_stays_plain_text_on_stderr(self) -> None:
        stdout = StringIO()
        stderr = StringIO()
        with redirect_stdout(stdout), redirect_stderr(stderr):
            with self.assertRaises(SystemExit) as ctx:
                cli.main.main(["connect"])

        self.assertEqual(ctx.exception.code, 2)
        self.assertEqual(stdout.getvalue(), "")
        self.assertIn("profile_id", stderr.getvalue())

    def test_status_human_marks_failure_or_degraded_state(self) -> None:
        response = Response(
            ok=True,
            payload={
                "state": {
                    "status": "connected",
                    "mode": "tun",
                    "active_profile_id": "p1",
                    "tun_active": True,
                    "proxy_active": True,
                    "lan_gateway_status": "degraded",
                }
            },
        )
        with patch("cli.main.WatchdogIPCClient") as client_cls:
            client_cls.return_value.status.return_value = response
            with redirect_stdout(StringIO()) as stdout:
                result = cli.main.main(["status"])

        self.assertEqual(result, 0)
        self.assertIn("LAN gateway: degraded", stdout.getvalue())
        self.assertIn("Failure/degraded: on", stdout.getvalue())


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
            # Isolate driver runtime dirs from the real /run/user/<uid> -
            # otherwise a stray directory left by an unrelated earlier
            # process on the host can make this subprocess's
            # SingBoxDriver.status() report runtime_mismatch instead of
            # standby.
            env["WATCHDOGVPN_RUNTIME_DIR"] = str(root / "runtime")
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
