from __future__ import annotations

import os
import socket
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from drivers import runtime_paths


def _wait_until(predicate, timeout: float = 5.0) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return True
        time.sleep(0.05)
    return predicate()


class RuntimePathsTests(unittest.TestCase):
    def test_make_runtime_dir_writes_owner_pid_and_private_file(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            with patch.dict(runtime_paths.os.environ, {"WATCHDOGVPN_RUNTIME_DIR": tmp}):
                runtime_dir = runtime_paths.make_runtime_dir("watchdogvpn-test-")
                config_path = runtime_dir / "config.txt"
                runtime_paths.write_private_file(config_path, "secret")

                self.assertEqual((runtime_dir / runtime_paths.OWNER_PID_NAME).read_text(encoding="utf-8"), str(runtime_paths.os.getpid()))
                self.assertEqual(config_path.read_text(encoding="utf-8"), "secret")
                self.assertEqual(config_path.stat().st_mode & 0o777, 0o600)

    def test_cleanup_stale_runtime_dirs_preserves_live_owner(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            with patch.dict(runtime_paths.os.environ, {"WATCHDOGVPN_RUNTIME_DIR": tmp}):
                live_dir = Path(tmp) / "watchdogvpn-test-live"
                stale_dir = Path(tmp) / "watchdogvpn-test-stale"
                live_dir.mkdir()
                stale_dir.mkdir()
                runtime_paths.write_private_file(live_dir / runtime_paths.OWNER_PID_NAME, str(runtime_paths.os.getpid()))
                runtime_paths.write_private_file(stale_dir / runtime_paths.OWNER_PID_NAME, "999999999")

                runtime_paths.cleanup_stale_runtime_dirs("watchdogvpn-test-")

                self.assertTrue(live_dir.exists())
                self.assertFalse(stale_dir.exists())


class ChildProcessTrackingTests(unittest.TestCase):
    def _spawn_sleeper(self) -> subprocess.Popen:
        return subprocess.Popen([sys.executable, "-c", "import time; time.sleep(30)"])

    def _stop(self, proc: subprocess.Popen) -> None:
        if proc.poll() is None:
            proc.kill()
        proc.wait()

    def test_record_and_kill_recorded_children_terminates_matching_process(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            runtime_dir = Path(tmp)
            proc = self._spawn_sleeper()
            try:
                runtime_paths.record_child_process(
                    runtime_dir, "process", proc.pid, Path(sys.executable).name
                )

                runtime_paths.kill_recorded_children(runtime_dir)

                self.assertTrue(_wait_until(lambda: proc.poll() is not None))
            finally:
                self._stop(proc)

    def test_kill_recorded_children_refuses_pid_reuse_mismatch(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            runtime_dir = Path(tmp)
            proc = self._spawn_sleeper()
            try:
                runtime_paths.record_child_process(
                    runtime_dir, "process", proc.pid, "totally-different-binary"
                )

                runtime_paths.kill_recorded_children(runtime_dir)

                time.sleep(0.3)
                self.assertIsNone(proc.poll(), "must refuse to kill on exe_hint mismatch")
            finally:
                self._stop(proc)

    def test_any_recorded_child_alive_detects_live_hint_matched_process(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            with patch.dict(runtime_paths.os.environ, {"WATCHDOGVPN_RUNTIME_DIR": tmp}):
                runtime_dir = Path(tmp) / "watchdogvpn-test-orphan"
                runtime_dir.mkdir()
                proc = self._spawn_sleeper()
                try:
                    runtime_paths.record_child_process(
                        runtime_dir, "process", proc.pid, Path(sys.executable).name
                    )

                    self.assertTrue(runtime_paths.any_recorded_child_alive("watchdogvpn-test-"))
                finally:
                    self._stop(proc)

    def test_any_recorded_child_alive_false_when_hint_does_not_match(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            with patch.dict(runtime_paths.os.environ, {"WATCHDOGVPN_RUNTIME_DIR": tmp}):
                runtime_dir = Path(tmp) / "watchdogvpn-test-orphan"
                runtime_dir.mkdir()
                proc = self._spawn_sleeper()
                try:
                    runtime_paths.record_child_process(runtime_dir, "process", proc.pid, "wrong-binary")

                    self.assertFalse(runtime_paths.any_recorded_child_alive("watchdogvpn-test-"))
                finally:
                    self._stop(proc)

    def test_any_recorded_child_alive_false_with_no_children(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            with patch.dict(runtime_paths.os.environ, {"WATCHDOGVPN_RUNTIME_DIR": tmp}):
                self.assertFalse(runtime_paths.any_recorded_child_alive("watchdogvpn-test-"))

    def test_owned_processes_returns_hint_verified_recorded_child(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            with patch.dict(runtime_paths.os.environ, {"WATCHDOGVPN_RUNTIME_DIR": tmp}):
                runtime_dir = Path(tmp) / "watchdogvpn-test-owned"
                runtime_dir.mkdir()
                proc = self._spawn_sleeper()
                try:
                    hint = Path(sys.executable).name
                    runtime_paths.record_child_process(runtime_dir, "process", proc.pid, hint)

                    observed = runtime_paths.owned_processes(
                        "watchdogvpn-test-", executable_names=(hint,)
                    )

                    self.assertIn(proc.pid, {process.pid for process in observed})
                finally:
                    self._stop(proc)

    def test_owned_processes_does_not_claim_unrelated_matching_executable(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            with patch.dict(runtime_paths.os.environ, {"WATCHDOGVPN_RUNTIME_DIR": tmp}):
                hint = Path(sys.executable).name

                observed = runtime_paths.owned_processes(
                    "watchdogvpn-test-", executable_names=(hint,)
                )

                self.assertNotIn(os.getpid(), {process.pid for process in observed})

    def test_owned_processes_recovers_process_from_private_runtime_argv(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            with patch.dict(runtime_paths.os.environ, {"WATCHDOGVPN_RUNTIME_DIR": tmp}):
                runtime_dir = Path(tmp) / "watchdogvpn-test-recover"
                runtime_dir.mkdir()
                config_path = runtime_dir / "config.json"
                config_path.write_text("{}", encoding="utf-8")
                proc = subprocess.Popen(
                    [
                        sys.executable,
                        "-c",
                        "import time; time.sleep(30)",
                        str(config_path),
                    ]
                )
                try:
                    hint = Path(os.path.realpath(sys.executable)).name

                    observed = runtime_paths.owned_processes(
                        "watchdogvpn-test-", executable_names=(hint,)
                    )

                    self.assertIn(proc.pid, {process.pid for process in observed})
                finally:
                    self._stop(proc)

    def test_observe_tcp_listener_ports_maps_socket_to_owned_pid(self) -> None:
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.addCleanup(listener.close)
        listener.bind(("127.0.0.1", 0))
        listener.listen()
        port = listener.getsockname()[1]

        observation = runtime_paths.observe_tcp_listener_ports(
            (runtime_paths.OwnedProcess(pid=os.getpid(), executable="python"),)
        )

        self.assertTrue(observation.observable)
        self.assertIn(port, observation.ports)

    def test_cleanup_stale_runtime_dirs_kills_recorded_child_only_when_owner_is_dead(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            with patch.dict(runtime_paths.os.environ, {"WATCHDOGVPN_RUNTIME_DIR": tmp}):
                stale_dir = Path(tmp) / "watchdogvpn-test-stale"
                stale_dir.mkdir()
                runtime_paths.write_private_file(stale_dir / runtime_paths.OWNER_PID_NAME, "999999999")
                live_dir = Path(tmp) / "watchdogvpn-test-live"
                live_dir.mkdir()
                runtime_paths.write_private_file(
                    live_dir / runtime_paths.OWNER_PID_NAME, str(runtime_paths.os.getpid())
                )

                stale_proc = self._spawn_sleeper()
                live_proc = self._spawn_sleeper()
                try:
                    hint = Path(sys.executable).name
                    runtime_paths.record_child_process(stale_dir, "process", stale_proc.pid, hint)
                    runtime_paths.record_child_process(live_dir, "process", live_proc.pid, hint)

                    runtime_paths.cleanup_stale_runtime_dirs("watchdogvpn-test-")

                    self.assertTrue(_wait_until(lambda: stale_proc.poll() is not None))
                    self.assertFalse(stale_dir.exists())
                    self.assertIsNone(live_proc.poll())
                    self.assertTrue(live_dir.exists())
                finally:
                    self._stop(stale_proc)
                    self._stop(live_proc)

    def test_kill_all_recorded_children_ignores_owner_liveness(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            with patch.dict(runtime_paths.os.environ, {"WATCHDOGVPN_RUNTIME_DIR": tmp}):
                live_dir = Path(tmp) / "watchdogvpn-test-live"
                live_dir.mkdir()
                runtime_paths.write_private_file(
                    live_dir / runtime_paths.OWNER_PID_NAME, str(runtime_paths.os.getpid())
                )

                proc = self._spawn_sleeper()
                try:
                    runtime_paths.record_child_process(
                        live_dir, "process", proc.pid, Path(sys.executable).name
                    )

                    runtime_paths.kill_all_recorded_children("watchdogvpn-test-")

                    self.assertTrue(_wait_until(lambda: proc.poll() is not None))
                    self.assertTrue(live_dir.exists(), "kill_all_recorded_children must not remove directories")
                finally:
                    self._stop(proc)


if __name__ == "__main__":
    unittest.main()
