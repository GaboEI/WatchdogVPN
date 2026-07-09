from __future__ import annotations

import json
import subprocess
import tempfile
import unittest
from pathlib import Path

from metrics.models import MetricsBucket, MetricsDocument
from metrics.store import MetricsStore


ROOT_DIR = Path(__file__).resolve().parents[1]
WATCHDOG = ROOT_DIR / "bin" / "watchdog"


class CliStatsCommandTests(unittest.TestCase):
    def run_watchdog(
        self,
        args: list[str],
        tmp: str,
        *,
        check: bool = True,
    ) -> subprocess.CompletedProcess[str]:
        env = {
            "WATCHDOGVPN_CONFIG_DIR": tmp,
            "WATCHDOGVPN_METRICS_FILE": str(Path(tmp) / "metrics.json"),
            "PYTHONPATH": str(ROOT_DIR),
        }
        result = subprocess.run(
            [str(WATCHDOG), *args],
            text=True,
            capture_output=True,
            env=env,
            check=False,
        )
        if check and result.returncode != 0:
            self.fail(f"command failed: {result.stderr}\nstdout={result.stdout}")
        return result

    def seed_metrics(self, tmp: str) -> Path:
        path = Path(tmp) / "metrics.json"
        MetricsStore(path).save(
            MetricsDocument(
                enabled=True,
                retention_days=5,
                buckets=(
                    MetricsBucket(
                        bucket_start="2026-07-06T10:00:00+00:00",
                        bucket_end="2026-07-06T11:00:00+00:00",
                        counters={
                            "command.connect.success": 3,
                            "profile.office.connect.success": 2,
                            "rule_group.work": 4,
                            "route_action.group:secure": 5,
                            "dns_query.secret.example": 9,
                        },
                    ),
                ),
            )
        )
        return path

    def test_stats_status_json_missing_does_not_create_metrics_file(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "metrics.json"

            result = self.run_watchdog(["stats", "status", "--json"], tmp)
            data = json.loads(result.stdout)

            self.assertEqual(data["metrics_status"], "missing")
            self.assertFalse(data["enabled"])
            self.assertEqual(data["redaction_mode"], "aggregate")
            self.assertFalse(data["detailed_history_supported"])
            self.assertFalse(path.exists())

    def test_stats_summary_json_filters_unknown_counter_keys(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            self.seed_metrics(tmp)

            result = self.run_watchdog(["stats", "summary", "--json"], tmp)
            data = json.loads(result.stdout)

            self.assertEqual(data["total_events"], 23)
            self.assertEqual(data["withheld_counter_keys"], 1)
            self.assertEqual(data["counters"]["command.connect.success"], 3)
            self.assertEqual(data["counters"]["profile.office.connect.success"], 2)
            self.assertEqual(data["counters"]["rule_group.work"], 4)
            self.assertEqual(data["counters"]["route_action.group:secure"], 5)
            self.assertNotIn("dns_query.secret.example", data["counters"])

    def test_stats_purge_requires_confirmation(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            self.seed_metrics(tmp)

            rejected = self.run_watchdog(["stats", "purge"], tmp, check=False)
            self.assertNotEqual(rejected.returncode, 0)
            self.assertIn("stats purge requires --yes", rejected.stderr)

            accepted = self.run_watchdog(["stats", "purge", "--yes"], tmp)
            self.assertIn("Metrics purged.", accepted.stdout)
            self.assertFalse((Path(tmp) / "metrics.json").exists())

    def test_stats_purge_json_reports_no_history(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            self.seed_metrics(tmp)

            result = self.run_watchdog(["stats", "purge", "--yes", "--json"], tmp)

        data = json.loads(result.stdout)
        self.assertTrue(data["purged"])
        self.assertFalse(data["history_included"])
        self.assertFalse(data["detailed_history_supported"])

    def test_stats_privacy_mode_detailed_does_not_enable_history_support(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            result = self.run_watchdog(["stats", "privacy-mode", "detailed"], tmp)
            self.assertIn("Detailed request history is not implemented", result.stdout)

            status = self.run_watchdog(["stats", "status", "--json"], tmp)
            data = json.loads(status.stdout)
            self.assertTrue(data["enabled"])
            self.assertEqual(data["redaction_mode"], "detailed")
            self.assertFalse(data["detailed_history_supported"])

    def test_stats_privacy_mode_json_detailed_does_not_claim_history(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            result = self.run_watchdog(["stats", "privacy-mode", "detailed", "--json"], tmp)

        data = json.loads(result.stdout)
        self.assertEqual(data["redaction_mode"], "detailed")
        self.assertFalse(data["history_included"])
        self.assertFalse(data["detailed_history_supported"])

    def test_stats_privacy_mode_off_disables_metrics(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            self.seed_metrics(tmp)

            self.run_watchdog(["stats", "privacy-mode", "off"], tmp)
            data = json.loads(
                self.run_watchdog(["stats", "status", "--json"], tmp).stdout
            )

            self.assertFalse(data["enabled"])
            self.assertEqual(data["redaction_mode"], "off")


if __name__ == "__main__":
    unittest.main()
