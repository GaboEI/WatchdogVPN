from __future__ import annotations

import unittest

from rotation.recovery import Recovery


class FakeClock:
    def __init__(self, start: float = 0.0) -> None:
        self.value = start

    def __call__(self) -> float:
        return self.value

    def advance(self, seconds: float) -> None:
        self.value += seconds


def make_recovery(**overrides) -> Recovery:
    defaults = dict(base_interval_seconds=10.0, max_interval_seconds=300.0, clock=FakeClock())
    defaults.update(overrides)
    return Recovery(**defaults)


class BackoffIntervalTests(unittest.TestCase):
    def test_exponential_growth_until_cap(self) -> None:
        recovery = make_recovery()

        self.assertEqual(recovery.backoff_interval(0), 0.0)
        self.assertEqual(recovery.backoff_interval(1), 10.0)
        self.assertEqual(recovery.backoff_interval(2), 20.0)
        self.assertEqual(recovery.backoff_interval(3), 40.0)
        self.assertEqual(recovery.backoff_interval(4), 80.0)
        self.assertEqual(recovery.backoff_interval(5), 160.0)
        self.assertEqual(recovery.backoff_interval(6), 300.0)
        self.assertEqual(recovery.backoff_interval(20), 300.0)


class RecordFailureSuccessTests(unittest.TestCase):
    def test_record_failure_increments_consecutive_count(self) -> None:
        recovery = make_recovery()

        recovery.record_failure()
        recovery.record_failure()

        self.assertEqual(recovery.consecutive_failures, 2)

    def test_record_failure_returns_backoff_interval_for_that_attempt(self) -> None:
        recovery = make_recovery()

        first = recovery.record_failure()
        second = recovery.record_failure()

        self.assertEqual(first, 10.0)
        self.assertEqual(second, 20.0)

    def test_record_success_resets_consecutive_failures(self) -> None:
        recovery = make_recovery()
        recovery.record_failure()
        recovery.record_failure()

        recovery.record_success()

        self.assertEqual(recovery.consecutive_failures, 0)

    def test_record_success_allows_immediate_retry(self) -> None:
        recovery = make_recovery()
        recovery.record_failure()

        recovery.record_success()

        self.assertTrue(recovery.can_retry_now())


class CanRetryNowTests(unittest.TestCase):
    def test_true_before_any_failure(self) -> None:
        recovery = make_recovery()
        self.assertTrue(recovery.can_retry_now())

    def test_false_within_backoff_window(self) -> None:
        clock = FakeClock()
        recovery = make_recovery(clock=clock)

        recovery.record_failure()

        self.assertFalse(recovery.can_retry_now())

    def test_true_after_backoff_window_elapses(self) -> None:
        clock = FakeClock()
        recovery = make_recovery(clock=clock)

        recovery.record_failure()
        clock.advance(10.0)

        self.assertTrue(recovery.can_retry_now())

    def test_force_bypasses_backoff_window(self) -> None:
        recovery = make_recovery()
        recovery.record_failure()

        self.assertTrue(recovery.can_retry_now(force=True))

    def test_never_permanently_blocked_even_after_many_failures(self) -> None:
        clock = FakeClock()
        recovery = make_recovery(clock=clock)

        for _ in range(50):
            recovery.record_failure()

        self.assertEqual(recovery.backoff_interval(recovery.consecutive_failures), 300.0)
        clock.advance(300.0)
        self.assertTrue(recovery.can_retry_now())


class AllFailedTests(unittest.TestCase):
    def test_without_kill_switch_does_not_block_traffic(self) -> None:
        recovery = make_recovery()

        action = recovery.handle_all_failed(kill_switch_active=False)

        self.assertFalse(action.kill_switch_active)
        self.assertTrue(action.notified)
        self.assertEqual(recovery.consecutive_failures, 1)

    def test_with_kill_switch_blocks_traffic(self) -> None:
        recovery = make_recovery()

        action = recovery.handle_all_failed(kill_switch_active=True)

        self.assertTrue(action.kill_switch_active)
        self.assertTrue(action.notified)

    def test_all_failed_schedules_backoff(self) -> None:
        clock = FakeClock()
        recovery = make_recovery(clock=clock)

        recovery.handle_all_failed(kill_switch_active=False)

        self.assertFalse(recovery.can_retry_now())
        clock.advance(10.0)
        self.assertTrue(recovery.can_retry_now())


if __name__ == "__main__":
    unittest.main()
