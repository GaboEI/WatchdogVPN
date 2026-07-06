from __future__ import annotations

import subprocess
import unittest
from datetime import datetime, timedelta, timezone

from diagnostics.time_check import diagnose_time


UTC_NOW = datetime(2026, 7, 6, 12, 0, 0, tzinfo=timezone.utc)


def _runner(stdout: str = "", returncode: int = 0, stderr: str = ""):
    def run(*args, **kwargs):
        return subprocess.CompletedProcess(
            args=args[0],
            returncode=returncode,
            stdout=stdout,
            stderr=stderr,
        )

    return run


class TimeCheckTests(unittest.TestCase):
    def test_synchronized_clock_with_small_skew_is_ok(self) -> None:
        result = diagnose_time(
            now=lambda: UTC_NOW,
            runner=_runner("NTPSynchronized=yes\nSystemClockSynchronized=yes\n"),
            reference_fetcher=lambda url, timeout: UTC_NOW - timedelta(seconds=2),
        )

        self.assertEqual(result.status, "ok")
        self.assertTrue(result.system_time_available)
        self.assertEqual(result.ntp_state, "synchronized")
        self.assertEqual(result.skew_seconds, 2)

    def test_unsynchronized_ntp_warns_without_mutating_time(self) -> None:
        result = diagnose_time(
            now=lambda: UTC_NOW,
            runner=_runner("NTPSynchronized=no\nSystemClockSynchronized=no\n"),
            reference_fetcher=lambda url, timeout: UTC_NOW,
        )

        self.assertEqual(result.status, "warn")
        self.assertEqual(result.ntp_state, "unsynchronized")
        self.assertIn("synchronization is not active", result.message)

    def test_single_positive_timedatectl_signal_counts_as_synchronized(self) -> None:
        result = diagnose_time(
            now=lambda: UTC_NOW,
            runner=_runner("NTPSynchronized=yes\n"),
            reference_fetcher=lambda url, timeout: UTC_NOW,
        )

        self.assertEqual(result.status, "ok")
        self.assertEqual(result.ntp_state, "synchronized")

    def test_severe_clock_skew_warns_about_handshake_risk(self) -> None:
        result = diagnose_time(
            now=lambda: UTC_NOW,
            runner=_runner("NTPSynchronized=yes\nSystemClockSynchronized=yes\n"),
            reference_fetcher=lambda url, timeout: UTC_NOW - timedelta(seconds=301),
        )

        self.assertEqual(result.status, "warn")
        self.assertEqual(result.skew_seconds, 301)
        self.assertIn("TLS and VPN handshakes may fail", result.message)

    def test_reference_fetch_failure_warns_that_skew_is_unknown(self) -> None:
        def fetch(url: str, timeout: float):
            raise TimeoutError("timeout")

        result = diagnose_time(
            now=lambda: UTC_NOW,
            runner=_runner("NTPSynchronized=yes\nSystemClockSynchronized=yes\n"),
            reference_fetcher=fetch,
        )

        self.assertEqual(result.status, "warn")
        self.assertIsNone(result.skew_seconds)
        self.assertIn("clock skew could not be checked", result.message)

    def test_timedatectl_failure_reports_unknown_ntp_state(self) -> None:
        result = diagnose_time(
            now=lambda: UTC_NOW,
            runner=_runner(returncode=1, stderr="not booted with systemd"),
            reference_fetcher=lambda url, timeout: UTC_NOW,
        )

        self.assertEqual(result.status, "warn")
        self.assertEqual(result.ntp_state, "unknown")
        self.assertIn("NTP synchronization state is unknown", result.message)


if __name__ == "__main__":
    unittest.main()
