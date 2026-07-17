from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from typing import Callable

from dns.models import DNSPolicy
from drivers.base import BaseDriver
from models.profile import Profile


LOGGER = logging.getLogger(__name__)

HealthCheckFn = Callable[[Profile, BaseDriver], str]


@dataclass(slots=True)
class RotationResult:
    profile: Profile | None
    success: bool
    attempts: int
    category: str
    rolled_back: bool = False
    cleanup_failed: bool = False


@dataclass
class RotationEngine:
    recent_keep: int = 5
    min_seconds_between_rotations: float = 120.0
    conservative_interval_multiplier: float = 2.0
    max_attempts_per_cycle: int = 8
    max_fails_before_rollback: int = 4
    max_degraded_seconds_before_rollback: float = 60.0
    warmup_seconds: float = 3.0
    clock: Callable[[], float] = time.monotonic
    sleep: Callable[[float], None] = time.sleep

    _last_profile_id: str | None = field(default=None, init=False, repr=False)
    _recent_profile_ids: list[str] = field(default_factory=list, init=False, repr=False)
    _last_good_profile_id: str | None = field(default=None, init=False, repr=False)
    _last_rotation_at: float | None = field(default=None, init=False, repr=False)
    _cleanup_barrier_failed: bool = field(default=False, init=False, repr=False)

    @staticmethod
    def pool_size_category(pool_size: int) -> str:
        if pool_size == 0:
            return "unavailable"
        if pool_size == 1:
            return "single"
        if pool_size <= 3:
            return "conservative"
        return "full"

    def _blocked_ids(self) -> set[str]:
        blocked = set(self._recent_profile_ids)
        if self._last_profile_id:
            blocked.add(self._last_profile_id)
        return blocked

    def candidates(self, pool: list[Profile]) -> list[Profile]:
        blocked = self._blocked_ids()
        filtered = [profile for profile in pool if profile.id not in blocked]
        if filtered:
            return filtered
        if pool:
            LOGGER.info("rotation_fallback_all_blocked pool_size=%d", len(pool))
        return list(pool)

    def can_rotate_now(self, category: str = "full", force: bool = False) -> bool:
        if force:
            return True
        if self._last_rotation_at is None:
            return True
        interval = self.min_seconds_between_rotations
        if category == "conservative":
            interval *= self.conservative_interval_multiplier
        elapsed = self.clock() - self._last_rotation_at
        return elapsed >= interval

    def _remember(self, profile_id: str) -> None:
        self._last_profile_id = profile_id
        items = [profile_id] + [pid for pid in self._recent_profile_ids if pid != profile_id]
        self._recent_profile_ids = items[: self.recent_keep]

    def record_successful_profile(self, profile_id: str) -> None:
        """Seed rotation history from a successful non-rotation connection."""

        if not profile_id:
            return
        self._remember(profile_id)
        self._last_good_profile_id = profile_id

    def _try_profile(
        self,
        profile: Profile,
        driver: BaseDriver,
        health_check: HealthCheckFn,
        dns_policy: DNSPolicy | None = None,
    ) -> str:
        preflight = getattr(driver, "preflight_profile", None)
        if callable(preflight):
            try:
                preflight_ok = bool(preflight(profile))
            except Exception:
                preflight_ok = False
                LOGGER.error(
                    "rotation_preflight_exception profile_id=%s",
                    profile.id,
                    exc_info=True,
                )
            if not preflight_ok:
                LOGGER.warning("rotation_preflight_failed profile_id=%s", profile.id)
                return "preflight_failed"
        try:
            disconnected = driver.disconnect()
        except Exception:
            disconnected = False
            LOGGER.error("rotation_cleanup_barrier_exception profile_id=%s", profile.id, exc_info=True)
        if not disconnected:
            self._cleanup_barrier_failed = True
            LOGGER.error("rotation_cleanup_barrier_failed profile_id=%s", profile.id)
            return "cleanup_failed"
        connected = driver.connect(profile, dns_policy=dns_policy)
        if not connected:
            return "down"
        if self.warmup_seconds > 0:
            self.sleep(self.warmup_seconds)
        return health_check(profile, driver)

    def _rollback(
        self,
        pool: list[Profile],
        driver: BaseDriver,
        health_check: HealthCheckFn,
        dns_policy: DNSPolicy | None = None,
    ) -> Profile | None:
        if not self._last_good_profile_id:
            LOGGER.info("rollback_skip reason=no_known_good")
            return None
        target = next((p for p in pool if p.id == self._last_good_profile_id), None)
        if target is None:
            LOGGER.info("rollback_skip reason=last_good_not_in_pool profile_id=%s", self._last_good_profile_id)
            return None
        LOGGER.info("rollback_start profile_id=%s", target.id)
        status = self._try_profile(target, driver, health_check, dns_policy=dns_policy)
        if status == "ok":
            LOGGER.info("rollback_ok profile_id=%s", target.id)
            self._remember(target.id)
            return target
        LOGGER.warning("rollback_fail profile_id=%s status=%s", target.id, status)
        return None

    def _single_node_check(
        self,
        profile: Profile,
        driver: BaseDriver,
        health_check: HealthCheckFn,
        dns_policy: DNSPolicy | None = None,
    ) -> RotationResult:
        LOGGER.info("rotation_single_node_check profile_id=%s", profile.id)
        status = self._try_profile(profile, driver, health_check, dns_policy=dns_policy)
        success = status == "ok"
        cleanup_failed = status == "cleanup_failed"
        if success:
            self._remember(profile.id)
            self._last_good_profile_id = profile.id
        else:
            LOGGER.warning("rotation_single_node_fail profile_id=%s status=%s", profile.id, status)
        self._last_rotation_at = self.clock()
        return RotationResult(
            profile=profile if success else None,
            success=success,
            attempts=1,
            category="single",
            cleanup_failed=cleanup_failed,
        )

    def rotate(
        self,
        pool: list[Profile],
        driver: BaseDriver,
        health_check: HealthCheckFn,
        force: bool = False,
        dns_policy: DNSPolicy | None = None,
    ) -> RotationResult:
        self._cleanup_barrier_failed = False
        category = self.pool_size_category(len(pool))

        if category == "unavailable":
            LOGGER.warning("rotation_unavailable reason=pool_empty")
            return RotationResult(profile=None, success=False, attempts=0, category=category)

        if category == "single":
            return self._single_node_check(pool[0], driver, health_check, dns_policy=dns_policy)

        if not self.can_rotate_now(category=category, force=force):
            LOGGER.info("rotation_skip reason=anti_loop_time category=%s", category)
            return RotationResult(profile=None, success=False, attempts=0, category=category)

        candidates = self.candidates(pool)
        cycle_start = self.clock()
        attempts = 0
        failures = 0
        rollback_attempted = False

        for profile in candidates:
            if attempts >= self.max_attempts_per_cycle:
                break
            attempts += 1
            LOGGER.info(
                "rotation_try profile_id=%s attempt=%d/%d category=%s",
                profile.id,
                attempts,
                self.max_attempts_per_cycle,
                category,
            )

            status = self._try_profile(profile, driver, health_check, dns_policy=dns_policy)

            if status == "cleanup_failed":
                self._last_rotation_at = self.clock()
                return RotationResult(
                    profile=None,
                    success=False,
                    attempts=attempts,
                    category=category,
                    cleanup_failed=True,
                )

            if status == "ok":
                LOGGER.info("rotation_try_ok profile_id=%s", profile.id)
                self._remember(profile.id)
                self._last_good_profile_id = profile.id
                self._last_rotation_at = self.clock()
                return RotationResult(profile=profile, success=True, attempts=attempts, category=category)

            LOGGER.warning("rotation_try_fail profile_id=%s status=%s", profile.id, status)
            failures += 1
            elapsed = self.clock() - cycle_start
            if not rollback_attempted and (
                failures >= self.max_fails_before_rollback
                or elapsed >= self.max_degraded_seconds_before_rollback
            ):
                rollback_attempted = True
                rollback_target = self._rollback(pool, driver, health_check, dns_policy=dns_policy)
                if self._cleanup_barrier_failed:
                    self._last_rotation_at = self.clock()
                    return RotationResult(
                        profile=None,
                        success=False,
                        attempts=attempts,
                        category=category,
                        cleanup_failed=True,
                    )
                if rollback_target is not None:
                    self._last_rotation_at = self.clock()
                    return RotationResult(
                        profile=rollback_target,
                        success=True,
                        attempts=attempts,
                        category=category,
                        rolled_back=True,
                    )

        final_rollback_target = None
        if not rollback_attempted:
            final_rollback_target = self._rollback(pool, driver, health_check, dns_policy=dns_policy)

        self._last_rotation_at = self.clock()

        if self._cleanup_barrier_failed:
            return RotationResult(
                profile=None,
                success=False,
                attempts=attempts,
                category=category,
                cleanup_failed=True,
            )

        if final_rollback_target is not None:
            LOGGER.info("rotation_end_rollback profile_id=%s", final_rollback_target.id)
            return RotationResult(
                profile=final_rollback_target,
                success=True,
                attempts=attempts,
                category=category,
                rolled_back=True,
            )

        LOGGER.error("rotation_all_failed attempts=%d failures=%d category=%s", attempts, failures, category)
        return RotationResult(
            profile=None,
            success=False,
            attempts=attempts,
            category=category,
            rolled_back=False,
        )
