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

    def _try_profile(
        self,
        profile: Profile,
        driver: BaseDriver,
        health_check: HealthCheckFn,
        dns_policy: DNSPolicy | None = None,
    ) -> str:
        driver.disconnect()
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
        )

    def rotate(
        self,
        pool: list[Profile],
        driver: BaseDriver,
        health_check: HealthCheckFn,
        force: bool = False,
        dns_policy: DNSPolicy | None = None,
    ) -> RotationResult:
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
