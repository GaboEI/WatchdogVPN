from __future__ import annotations

import unittest

from dns.models import DNSPolicy
from drivers.base import BaseDriver
from models.connection_state import ConnectionState
from models.profile import Profile, ProfileSource, ProtocolType
from rotation.rotation_engine import RotationEngine


def make_profile(profile_id: str) -> Profile:
    return Profile(
        id=profile_id,
        name=profile_id,
        protocol=ProtocolType.VLESS,
        config={},
        source=ProfileSource.MANUAL,
        in_rotation_pool=True,
        enabled=True,
    )


class FakeClock:
    def __init__(self, start: float = 0.0) -> None:
        self.value = start

    def __call__(self) -> float:
        return self.value

    def advance(self, seconds: float) -> None:
        self.value += seconds


class ScriptedDriver(BaseDriver):
    def __init__(self) -> None:
        self.connect_results: dict[str, bool] = {}
        self.connect_calls: list[str] = []
        self.connect_dns_policies: list[DNSPolicy | None] = []
        self.disconnect_calls = 0
        self.connected_profile_id: str | None = None

    def connect(
        self,
        profile: Profile,
        dns_policy: DNSPolicy | None = None,
        *,
        mode: str = "global",
        groups=None,
        app_policy=None,
        final_policy: str = "current_profile",
    ) -> bool:
        self.connect_calls.append(profile.id)
        self.connect_dns_policies.append(dns_policy)
        ok = self.connect_results.get(profile.id, True)
        self.connected_profile_id = profile.id if ok else None
        return ok

    def disconnect(self) -> bool:
        self.disconnect_calls += 1
        self.connected_profile_id = None
        return True

    def health_check(self) -> str:
        return "ok"

    def status(self) -> ConnectionState:
        return ConnectionState(status="connected" if self.connected_profile_id else "standby")

    def is_available(self) -> bool:
        return True


def make_engine(**overrides) -> RotationEngine:
    defaults = dict(
        clock=FakeClock(),
        sleep=lambda seconds: None,
        warmup_seconds=3.0,
    )
    defaults.update(overrides)
    return RotationEngine(**defaults)


def health_check_from(statuses: dict[str, str]):
    def _check(profile: Profile, driver: BaseDriver) -> str:
        return statuses.get(profile.id, "ok")

    return _check


class RotationEnginePoolSizeTests(unittest.TestCase):
    def test_pool_size_category(self) -> None:
        self.assertEqual(RotationEngine.pool_size_category(0), "unavailable")
        self.assertEqual(RotationEngine.pool_size_category(1), "single")
        self.assertEqual(RotationEngine.pool_size_category(2), "conservative")
        self.assertEqual(RotationEngine.pool_size_category(3), "conservative")
        self.assertEqual(RotationEngine.pool_size_category(4), "full")

    def test_rotate_empty_pool_returns_unavailable(self) -> None:
        engine = make_engine()
        driver = ScriptedDriver()

        result = engine.rotate([], driver, health_check_from({}))

        self.assertFalse(result.success)
        self.assertEqual(result.category, "unavailable")
        self.assertEqual(result.attempts, 0)
        self.assertEqual(driver.connect_calls, [])


class RotationEngineSingleNodeTests(unittest.TestCase):
    def test_single_node_success(self) -> None:
        engine = make_engine()
        driver = ScriptedDriver()
        profile = make_profile("a")

        result = engine.rotate([profile], driver, health_check_from({"a": "ok"}))

        self.assertTrue(result.success)
        self.assertEqual(result.category, "single")
        self.assertEqual(result.profile.id, "a")
        self.assertEqual(driver.connect_calls, ["a"])

    def test_single_node_forwards_dns_policy_to_driver_connect(self) -> None:
        engine = make_engine()
        driver = ScriptedDriver()
        profile = make_profile("a")
        policy = DNSPolicy()

        engine.rotate([profile], driver, health_check_from({"a": "ok"}), dns_policy=policy)

        self.assertEqual(driver.connect_dns_policies, [policy])

    def test_single_node_failure(self) -> None:
        engine = make_engine()
        driver = ScriptedDriver()
        profile = make_profile("a")

        result = engine.rotate([profile], driver, health_check_from({"a": "down"}))

        self.assertFalse(result.success)
        self.assertIsNone(result.profile)
        self.assertEqual(result.category, "single")

    def test_single_node_disconnects_before_connect(self) -> None:
        engine = make_engine()
        driver = ScriptedDriver()
        profile = make_profile("a")

        engine.rotate([profile], driver, health_check_from({"a": "ok"}))

        self.assertEqual(driver.disconnect_calls, 1)


class RotationEngineSelectionTests(unittest.TestCase):
    def test_picks_first_healthy_candidate_in_full_pool(self) -> None:
        engine = make_engine()
        driver = ScriptedDriver()
        pool = [make_profile(pid) for pid in ("a", "b", "c", "d")]

        result = engine.rotate(pool, driver, health_check_from({"a": "down", "b": "ok"}))

        self.assertTrue(result.success)
        self.assertEqual(result.profile.id, "b")
        self.assertEqual(result.attempts, 2)
        self.assertEqual(driver.connect_calls, ["a", "b"])

    def test_disconnects_before_every_attempt_no_orphan_processes(self) -> None:
        engine = make_engine()
        driver = ScriptedDriver()
        pool = [make_profile(pid) for pid in ("a", "b", "c")]

        engine.rotate(pool, driver, health_check_from({"a": "down", "b": "down", "c": "ok"}))

        self.assertEqual(driver.disconnect_calls, len(driver.connect_calls))

    def test_warmup_sleep_called_after_each_successful_connect(self) -> None:
        sleep_calls: list[float] = []
        engine = make_engine(sleep=lambda seconds: sleep_calls.append(seconds), warmup_seconds=3.0)
        driver = ScriptedDriver()
        pool = [make_profile("a")]

        engine.rotate(pool, driver, health_check_from({"a": "ok"}))

        self.assertEqual(sleep_calls, [3.0])

    def test_max_attempts_per_cycle_caps_tries(self) -> None:
        engine = make_engine(max_attempts_per_cycle=3, max_fails_before_rollback=99)
        driver = ScriptedDriver()
        pool = [make_profile(pid) for pid in ("a", "b", "c", "d", "e")]

        result = engine.rotate(
            pool,
            driver,
            health_check_from({"a": "down", "b": "down", "c": "down", "d": "down", "e": "down"}),
        )

        self.assertFalse(result.success)
        self.assertEqual(result.attempts, 3)


class RotationEngineAntiLoopTests(unittest.TestCase):
    def test_does_not_repeat_last_used_profile(self) -> None:
        engine = make_engine()
        driver = ScriptedDriver()
        pool = [make_profile(pid) for pid in ("a", "b")]

        first = engine.rotate(pool, driver, health_check_from({"a": "ok", "b": "ok"}))
        second = engine.rotate(pool, driver, health_check_from({"a": "ok", "b": "ok"}), force=True)

        self.assertEqual(first.profile.id, "a")
        self.assertEqual(second.profile.id, "b")

    def test_falls_back_to_full_pool_when_all_blocked(self) -> None:
        engine = make_engine(recent_keep=1)
        driver = ScriptedDriver()
        pool = [make_profile("a")]

        first = engine.rotate(pool, driver, health_check_from({"a": "ok"}))
        second = engine.rotate(pool, driver, health_check_from({"a": "ok"}), force=True)

        self.assertTrue(first.success)
        self.assertEqual(second.category, "single")
        self.assertTrue(second.success)


class RotationEngineTimeGateTests(unittest.TestCase):
    def test_skips_rotation_within_min_seconds_between(self) -> None:
        clock = FakeClock()
        engine = make_engine(clock=clock)
        driver = ScriptedDriver()
        pool = [make_profile(pid) for pid in ("a", "b", "c", "d")]

        first = engine.rotate(pool, driver, health_check_from({"a": "ok"}))
        clock.advance(10)
        second = engine.rotate(pool, driver, health_check_from({"a": "ok"}))

        self.assertTrue(first.success)
        self.assertFalse(second.success)
        self.assertEqual(second.attempts, 0)
        self.assertEqual(driver.connect_calls, ["a"])

    def test_force_bypasses_time_gate(self) -> None:
        clock = FakeClock()
        engine = make_engine(clock=clock)
        driver = ScriptedDriver()
        pool = [make_profile(pid) for pid in ("a", "b", "c", "d")]

        engine.rotate(pool, driver, health_check_from({"a": "ok"}))
        clock.advance(1)
        second = engine.rotate(pool, driver, health_check_from({"a": "ok", "b": "ok"}), force=True)

        self.assertTrue(second.success)

    def test_conservative_pool_uses_wider_interval(self) -> None:
        clock = FakeClock()
        engine = make_engine(clock=clock, min_seconds_between_rotations=100.0, conservative_interval_multiplier=2.0)
        driver = ScriptedDriver()
        pool = [make_profile(pid) for pid in ("a", "b", "c")]

        first = engine.rotate(pool, driver, health_check_from({"a": "ok"}))
        clock.advance(150)
        second = engine.rotate(pool, driver, health_check_from({"a": "ok", "b": "ok"}))

        self.assertTrue(first.success)
        self.assertEqual(first.category, "conservative")
        self.assertFalse(second.success)
        self.assertEqual(second.attempts, 0)


class RotationEngineRollbackTests(unittest.TestCase):
    def test_rollback_triggered_after_max_fails(self) -> None:
        engine = make_engine(max_fails_before_rollback=2, max_degraded_seconds_before_rollback=999, recent_keep=10)
        driver = ScriptedDriver()
        pool = [make_profile(pid) for pid in ("a", "b", "c", "d")]

        first = engine.rotate(pool, driver, health_check_from({"a": "ok"}))
        second = engine.rotate(
            pool,
            driver,
            health_check_from({"a": "ok", "b": "down", "c": "down", "d": "ok"}),
            force=True,
        )

        self.assertEqual(first.profile.id, "a")
        self.assertTrue(second.success)
        self.assertTrue(second.rolled_back)
        self.assertEqual(second.profile.id, "a")
        self.assertEqual(second.attempts, 2)

    def test_rollback_skipped_when_no_known_good(self) -> None:
        engine = make_engine(max_fails_before_rollback=1, max_degraded_seconds_before_rollback=999)
        driver = ScriptedDriver()
        pool = [make_profile(pid) for pid in ("a", "b")]

        result = engine.rotate(pool, driver, health_check_from({"a": "down", "b": "down"}))

        self.assertFalse(result.success)
        self.assertFalse(result.rolled_back)

    def test_end_of_loop_rollback_reports_success(self) -> None:
        engine = make_engine(max_fails_before_rollback=99, max_degraded_seconds_before_rollback=999, recent_keep=10)
        driver = ScriptedDriver()
        pool = [make_profile(pid) for pid in ("a", "b", "c")]

        first = engine.rotate(pool, driver, health_check_from({"a": "ok"}))
        second = engine.rotate(
            pool,
            driver,
            health_check_from({"a": "ok", "b": "down", "c": "down"}),
            force=True,
        )

        self.assertTrue(first.success)
        self.assertTrue(second.success)
        self.assertTrue(second.rolled_back)
        self.assertEqual(second.profile.id, "a")
        self.assertEqual(second.attempts, 2)


if __name__ == "__main__":
    unittest.main()
