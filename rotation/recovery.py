from __future__ import annotations

import logging
import math
import time
from dataclasses import dataclass, field
from typing import Callable


LOGGER = logging.getLogger(__name__)


MIN_BACKOFF_INTERVAL_SECONDS = 1.0
MAX_BACKOFF_INTERVAL_SECONDS = 86_400.0


@dataclass(slots=True)
class AllFailedAction:
    kill_switch_active: bool
    notified: bool
    message: str


@dataclass
class Recovery:
    """Backoff and all-nodes-fail handling between rotation cycles.

    This intentionally has no knowledge of vpn_desired_state: the watchdog
    loop (Task 8.5) is responsible for checking
    WatchdogRuntime.automatic_actions_enabled() (Task 7.1) before calling
    into recovery/rotation at all, so "never stop retrying unless
    vpn_desired_state = off" is satisfied by that existing gate rather than
    duplicated here. The backoff below has no upper bound on retry count -
    it only caps the wait *interval*, so it never stops retrying on its own.
    """

    base_interval_seconds: float = 10.0
    max_interval_seconds: float = 300.0
    clock: Callable[[], float] = time.monotonic

    _consecutive_failures: int = field(default=0, init=False, repr=False)
    _retry_started_at: float | None = field(default=None, init=False, repr=False)
    _retry_interval_seconds: float = field(default=0.0, init=False, repr=False)

    @property
    def consecutive_failures(self) -> int:
        return self._consecutive_failures

    @staticmethod
    def _normalized_interval(value: object, field: str, default: float) -> float:
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            LOGGER.error("recovery_backoff_config_invalid field=%s action=use_default", field)
            return default
        try:
            interval = float(value)
        except OverflowError:
            LOGGER.error("recovery_backoff_config_invalid field=%s action=use_default", field)
            return default
        if not math.isfinite(interval):
            LOGGER.error("recovery_backoff_config_invalid field=%s action=use_default", field)
            return default
        if interval < MIN_BACKOFF_INTERVAL_SECONDS:
            LOGGER.error("recovery_backoff_config_invalid field=%s action=clamp_minimum", field)
            return MIN_BACKOFF_INTERVAL_SECONDS
        if interval > MAX_BACKOFF_INTERVAL_SECONDS:
            LOGGER.error("recovery_backoff_config_invalid field=%s action=clamp_maximum", field)
            return MAX_BACKOFF_INTERVAL_SECONDS
        return interval

    def _interval_bounds(self) -> tuple[float, float]:
        base = self._normalized_interval(
            self.base_interval_seconds,
            "base_interval_seconds",
            10.0,
        )
        maximum = self._normalized_interval(
            self.max_interval_seconds,
            "max_interval_seconds",
            300.0,
        )
        if maximum < base:
            LOGGER.error(
                "recovery_backoff_config_invalid field=max_interval_seconds action=raise_to_base"
            )
            maximum = base
        return base, maximum

    def backoff_interval(self, attempt: int) -> float:
        if isinstance(attempt, bool) or not isinstance(attempt, int) or attempt <= 0:
            return 0.0
        interval, maximum = self._interval_bounds()
        remaining_doublings = attempt - 1
        while remaining_doublings > 0 and interval < maximum:
            if interval >= maximum / 2:
                return maximum
            interval *= 2
            remaining_doublings -= 1
        return interval

    def record_failure(self) -> float:
        self._consecutive_failures += 1
        interval = self.backoff_interval(self._consecutive_failures)
        self._retry_started_at = self.clock()
        self._retry_interval_seconds = interval
        LOGGER.warning(
            "recovery_backoff consecutive_failures=%d interval_seconds=%.1f",
            self._consecutive_failures,
            interval,
        )
        return interval

    def record_success(self) -> None:
        if self._consecutive_failures:
            LOGGER.info("recovery_backoff_reset consecutive_failures=%d", self._consecutive_failures)
        self._consecutive_failures = 0
        self._retry_started_at = None
        self._retry_interval_seconds = 0.0

    def can_retry_now(self, force: bool = False) -> bool:
        if force:
            return True
        if self._retry_started_at is None:
            return True
        elapsed = self.clock() - self._retry_started_at
        return elapsed >= self._retry_interval_seconds

    def handle_all_failed(self, kill_switch_active: bool) -> AllFailedAction:
        interval = self.record_failure()
        if kill_switch_active:
            message = (
                f"all rotation candidates failed (consecutive_failures="
                f"{self._consecutive_failures}); kill switch active, "
                f"blocking traffic outside the tunnel, retrying in {interval:.1f}s"
            )
            LOGGER.error("recovery_all_failed kill_switch=on %s", message)
            return AllFailedAction(kill_switch_active=True, notified=True, message=message)

        message = (
            f"all rotation candidates failed (consecutive_failures="
            f"{self._consecutive_failures}); falling back to the normal "
            f"network, retrying in {interval:.1f}s"
        )
        LOGGER.error("recovery_all_failed kill_switch=off %s", message)
        return AllFailedAction(kill_switch_active=False, notified=True, message=message)

    def handle_rotation_unavailable(self, kill_switch_active: bool, reason: str) -> AllFailedAction:
        interval = self.record_failure()
        if kill_switch_active:
            message = (
                f"rotation unavailable (reason={reason}, consecutive_failures="
                f"{self._consecutive_failures}); kill switch active, "
                f"blocking traffic outside the tunnel, retrying in {interval:.1f}s"
            )
            LOGGER.error("recovery_rotation_unavailable kill_switch=on %s", message)
            return AllFailedAction(kill_switch_active=True, notified=True, message=message)

        message = (
            f"rotation unavailable (reason={reason}, consecutive_failures="
            f"{self._consecutive_failures}); retrying in {interval:.1f}s"
        )
        LOGGER.error("recovery_rotation_unavailable kill_switch=off %s", message)
        return AllFailedAction(kill_switch_active=False, notified=True, message=message)
