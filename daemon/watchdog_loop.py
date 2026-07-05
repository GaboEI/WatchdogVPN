from __future__ import annotations

import logging
import threading
import time
from typing import Callable

from config.app_config import AppConfig, MIN_WATCHDOG_CHECK_INTERVAL_SECONDS
from config.persistence import PersistentStoreError, PersistentValidationError
from daemon.runtime_worker import RuntimeWorker


LOGGER = logging.getLogger(__name__)

FALLBACK_INTERVAL_SECONDS = 30.0


class WatchdogLoop:
    """Autonomous background ticker for WatchdogRuntime.run_iteration().

    This is the piece v1 covered with a separate `vpn-watchdog.timer`
    systemd unit (deleted in Phase 2.6 as unreachable dead code, redesign
    deferred to Phase 14). It only enqueues ticks onto the existing
    RuntimeWorker queue (see RuntimeWorker.submit_tick) so every tick is
    serialized with IPC-triggered connect/disconnect/rotate commands on the
    same single worker thread - this loop never calls into WatchdogRuntime
    directly.
    """

    def __init__(
        self,
        worker: RuntimeWorker,
        app_config: AppConfig | None = None,
        wait: Callable[[float], bool] | None = None,
    ) -> None:
        self.worker = worker
        self.app_config = app_config or AppConfig()
        self._stop_event = threading.Event()
        self._wait = wait or self._stop_event.wait
        self._thread = threading.Thread(
            target=self._run,
            name="watchdogvpn-watchdog-loop",
            daemon=True,
        )

    def start(self) -> None:
        if self._thread.is_alive():
            return
        self._thread.start()

    def stop(self, timeout: float | None = 5.0) -> None:
        self._stop_event.set()
        if self._thread.is_alive():
            self._thread.join(timeout=timeout)

    def _run(self) -> None:
        while not self._stop_event.is_set():
            interval = self._current_interval_seconds()
            if self._wait(interval):
                return
            self._tick()

    def _current_interval_seconds(self) -> float:
        try:
            config = self.app_config.load()
        except (PersistentStoreError, PersistentValidationError):
            LOGGER.error(
                "watchdog_loop_config_invalid falling_back_to=%s",
                FALLBACK_INTERVAL_SECONDS,
                exc_info=True,
            )
            return FALLBACK_INTERVAL_SECONDS
        seconds = config.get("watchdog", {}).get("check_interval_seconds", FALLBACK_INTERVAL_SECONDS)
        return max(float(seconds), float(MIN_WATCHDOG_CHECK_INTERVAL_SECONDS))

    def _tick(self) -> None:
        if not self.worker.is_running():
            return
        try:
            self.worker.submit_tick()
        except RuntimeError:
            # Worker stopped between the is_running() check and here - the
            # daemon is shutting down, nothing to recover from.
            return
