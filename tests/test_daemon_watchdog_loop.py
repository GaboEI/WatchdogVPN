from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from config.app_config import AppConfig
from config.persistence import atomic_write_text
from daemon.watchdog_loop import FALLBACK_INTERVAL_SECONDS, WatchdogLoop


class FakeWorker:
    def __init__(self, running: bool = True) -> None:
        self.running = running
        self.tick_calls = 0
        self.raise_on_submit = False

    def is_running(self) -> bool:
        return self.running

    def submit_tick(self) -> None:
        if self.raise_on_submit:
            raise RuntimeError("runtime worker is not running")
        self.tick_calls += 1


class ScriptedWait:
    """Deterministic stand-in for threading.Event.wait: records the
    requested interval each call and returns pre-scripted stop decisions,
    so the loop body runs without any real sleeping."""

    def __init__(self, stop_after: list[bool]) -> None:
        self.stop_after = list(stop_after)
        self.intervals: list[float] = []

    def __call__(self, interval: float) -> bool:
        self.intervals.append(interval)
        if not self.stop_after:
            return True
        return self.stop_after.pop(0)


class WatchdogLoopTests(unittest.TestCase):
    def test_ticks_until_wait_signals_stop(self) -> None:
        worker = FakeWorker()
        wait = ScriptedWait(stop_after=[False, False, True])
        with tempfile.TemporaryDirectory() as tmp:
            app_config = AppConfig(Path(tmp) / "config.toml")
            loop = WatchdogLoop(worker, app_config=app_config, wait=wait)
            loop._run()

        self.assertEqual(worker.tick_calls, 2)
        self.assertEqual(wait.intervals, [30.0, 30.0, 30.0])

    def test_uses_configured_check_interval(self) -> None:
        worker = FakeWorker()
        wait = ScriptedWait(stop_after=[True])
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "config.toml"
            atomic_write_text(path, "[watchdog]\ncheck_interval_seconds = 45\n")
            app_config = AppConfig(path)
            loop = WatchdogLoop(worker, app_config=app_config, wait=wait)
            loop._run()

        self.assertEqual(wait.intervals, [45.0])

    def test_falls_back_to_default_interval_on_corrupt_config(self) -> None:
        worker = FakeWorker()
        wait = ScriptedWait(stop_after=[True])
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "config.toml"
            path.write_text("not valid toml [[[", encoding="utf-8")
            app_config = AppConfig(path)
            loop = WatchdogLoop(worker, app_config=app_config, wait=wait)
            loop._run()

        self.assertEqual(wait.intervals, [FALLBACK_INTERVAL_SECONDS])

    def test_skips_tick_when_worker_not_running(self) -> None:
        worker = FakeWorker(running=False)
        wait = ScriptedWait(stop_after=[False, True])
        with tempfile.TemporaryDirectory() as tmp:
            app_config = AppConfig(Path(tmp) / "config.toml")
            loop = WatchdogLoop(worker, app_config=app_config, wait=wait)
            loop._run()

        self.assertEqual(worker.tick_calls, 0)

    def test_tolerates_worker_stopping_between_check_and_submit(self) -> None:
        worker = FakeWorker(running=True)
        worker.raise_on_submit = True
        wait = ScriptedWait(stop_after=[False, True])
        with tempfile.TemporaryDirectory() as tmp:
            app_config = AppConfig(Path(tmp) / "config.toml")
            loop = WatchdogLoop(worker, app_config=app_config, wait=wait)
            loop._run()  # must not raise

    def test_start_and_stop_run_real_thread_and_shut_down_quickly(self) -> None:
        worker = FakeWorker()
        with tempfile.TemporaryDirectory() as tmp:
            app_config = AppConfig(Path(tmp) / "config.toml")
            loop = WatchdogLoop(worker, app_config=app_config)
            loop.start()
            try:
                self.assertTrue(loop._thread.is_alive())
            finally:
                loop.stop(timeout=2.0)
            self.assertFalse(loop._thread.is_alive())


if __name__ == "__main__":
    unittest.main()
