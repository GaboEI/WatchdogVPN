from __future__ import annotations

import logging
import threading
from typing import Callable

from config.app_config import AppConfig
from config.persistence import PersistentStoreError, PersistentValidationError
from daemon.runtime_worker import RuntimeWorker


LOGGER = logging.getLogger(__name__)

DISABLED_POLL_SECONDS = 60.0
SECONDS_PER_HOUR = 3600.0


class ScheduledRotationLoop:
    """Optional, separate timer for proactive rotation (Task 14.2).

    Distinct from WatchdogLoop (Task 14.1, health-driven): this fires
    every rotation.scheduled_interval_hours regardless of health status.
    0 (the default) means disabled - the loop keeps polling at
    DISABLED_POLL_SECONDS so re-enabling it via config takes effect without
    a daemon restart, without hammering AppConfig while off.

    Like WatchdogLoop, this only enqueues onto RuntimeWorker's single queue
    (submit_scheduled_rotation) - it never rotates directly. The timer only
    decides *when*; WatchdogRuntime.scheduled_rotate() decides *whether*
    (its own gate, plus an empty-pool guard) and *how* (the same
    pool_builder/RotationEngine path as reactive and manual rotation).
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
            name="watchdogvpn-scheduled-rotation-loop",
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
            if interval is None:
                if self._wait(DISABLED_POLL_SECONDS):
                    return
                continue
            if self._wait(interval):
                return
            self._trigger()

    def _current_interval_seconds(self) -> float | None:
        try:
            config = self.app_config.load()
        except (PersistentStoreError, PersistentValidationError):
            LOGGER.error("scheduled_rotation_loop_config_invalid", exc_info=True)
            return None
        hours = config.get("rotation", {}).get("scheduled_interval_hours", 0)
        if not hours:
            return None
        return float(hours) * SECONDS_PER_HOUR

    def _trigger(self) -> None:
        if not self.worker.is_running():
            return
        try:
            self.worker.submit_scheduled_rotation()
        except RuntimeError:
            # Worker stopped between the is_running() check and here - the
            # daemon is shutting down, nothing to recover from.
            return
