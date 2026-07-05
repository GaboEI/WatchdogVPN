from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from config.app_config import AppConfig
from config.persistence import atomic_write_text
from daemon.scheduled_rotation_loop import DISABLED_POLL_SECONDS, ScheduledRotationLoop


class FakeWorker:
    def __init__(self, running: bool = True) -> None:
        self.running = running
        self.rotation_calls = 0
        self.raise_on_submit = False

    def is_running(self) -> bool:
        return self.running

    def submit_scheduled_rotation(self) -> None:
        if self.raise_on_submit:
            raise RuntimeError("runtime worker is not running")
        self.rotation_calls += 1


class ScriptedWait:
    def __init__(self, stop_after: list[bool]) -> None:
        self.stop_after = list(stop_after)
        self.intervals: list[float] = []

    def __call__(self, interval: float) -> bool:
        self.intervals.append(interval)
        if not self.stop_after:
            return True
        return self.stop_after.pop(0)


class ScheduledRotationLoopTests(unittest.TestCase):
    def test_disabled_by_default_polls_without_triggering(self) -> None:
        worker = FakeWorker()
        wait = ScriptedWait(stop_after=[False, False, True])
        with tempfile.TemporaryDirectory() as tmp:
            app_config = AppConfig(Path(tmp) / "config.toml")
            loop = ScheduledRotationLoop(worker, app_config=app_config, wait=wait)
            loop._run()

        self.assertEqual(worker.rotation_calls, 0)
        self.assertEqual(wait.intervals, [DISABLED_POLL_SECONDS] * 3)

    def test_triggers_on_configured_hourly_interval(self) -> None:
        worker = FakeWorker()
        wait = ScriptedWait(stop_after=[False, True])
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "config.toml"
            atomic_write_text(path, "[rotation]\nscheduled_interval_hours = 3\n")
            app_config = AppConfig(path)
            loop = ScheduledRotationLoop(worker, app_config=app_config, wait=wait)
            loop._run()

        self.assertEqual(worker.rotation_calls, 1)
        self.assertEqual(wait.intervals, [3 * 3600.0, 3 * 3600.0])

    def test_treats_corrupt_config_as_disabled(self) -> None:
        worker = FakeWorker()
        wait = ScriptedWait(stop_after=[True])
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "config.toml"
            path.write_text("not valid toml [[[", encoding="utf-8")
            app_config = AppConfig(path)
            loop = ScheduledRotationLoop(worker, app_config=app_config, wait=wait)
            loop._run()

        self.assertEqual(worker.rotation_calls, 0)
        self.assertEqual(wait.intervals, [DISABLED_POLL_SECONDS])

    def test_skips_trigger_when_worker_not_running(self) -> None:
        worker = FakeWorker(running=False)
        wait = ScriptedWait(stop_after=[False, True])
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "config.toml"
            atomic_write_text(path, "[rotation]\nscheduled_interval_hours = 4\n")
            app_config = AppConfig(path)
            loop = ScheduledRotationLoop(worker, app_config=app_config, wait=wait)
            loop._run()

        self.assertEqual(worker.rotation_calls, 0)

    def test_tolerates_worker_stopping_between_check_and_submit(self) -> None:
        worker = FakeWorker(running=True)
        worker.raise_on_submit = True
        wait = ScriptedWait(stop_after=[False, True])
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "config.toml"
            atomic_write_text(path, "[rotation]\nscheduled_interval_hours = 5\n")
            app_config = AppConfig(path)
            loop = ScheduledRotationLoop(worker, app_config=app_config, wait=wait)
            loop._run()  # must not raise

    def test_start_and_stop_run_real_thread_and_shut_down_quickly(self) -> None:
        worker = FakeWorker()
        with tempfile.TemporaryDirectory() as tmp:
            app_config = AppConfig(Path(tmp) / "config.toml")
            loop = ScheduledRotationLoop(worker, app_config=app_config)
            loop.start()
            try:
                self.assertTrue(loop._thread.is_alive())
            finally:
                loop.stop(timeout=2.0)
            self.assertFalse(loop._thread.is_alive())


if __name__ == "__main__":
    unittest.main()
