from __future__ import annotations

import json
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch

from config.persistence import PersistentValidationError
from models.connection_state import ConnectionState
from metrics.models import MetricsBucket, MetricsDocument, MetricsRedactionMode
from metrics.recorder import MetricsRecorder
from metrics.store import MetricsStore


class MetricsModelTests(unittest.TestCase):
    def test_default_document_is_disabled_aggregate_and_bounded(self) -> None:
        document = MetricsDocument()

        self.assertFalse(document.enabled)
        self.assertEqual(document.redaction_mode, MetricsRedactionMode.AGGREGATE)
        self.assertEqual(document.retention_days, 7)
        self.assertEqual(document.max_bytes, 1024 * 1024)
        self.assertEqual(document.buckets, ())

    def test_rejects_unknown_fields(self) -> None:
        with self.assertRaises(PersistentValidationError):
            MetricsDocument.from_dict({"future": True})

    def test_rejects_invalid_retention(self) -> None:
        with self.assertRaises(PersistentValidationError):
            MetricsDocument(retention_days=0)

    def test_rejects_invalid_redaction_mode(self) -> None:
        with self.assertRaises(PersistentValidationError):
            MetricsDocument.from_dict({"redaction_mode": "raw"})

    def test_rejects_non_object_bucket_entries(self) -> None:
        with self.assertRaises(PersistentValidationError):
            MetricsDocument.from_dict({"buckets": ["bad"]})

    def test_rejects_negative_counter(self) -> None:
        with self.assertRaises(PersistentValidationError):
            MetricsBucket(
                bucket_start="2026-07-06T00:00:00+00:00",
                bucket_end="2026-07-06T01:00:00+00:00",
                counters={"route.current": -1},
            )


class MetricsStoreTests(unittest.TestCase):
    def test_load_missing_returns_default_document(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            document = MetricsStore(Path(tmp) / "metrics.json").load()

        self.assertFalse(document.enabled)
        self.assertEqual(document.redaction_mode, MetricsRedactionMode.AGGREGATE)

    def test_save_and_load_round_trip(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "metrics.json"
            store = MetricsStore(path)
            document = MetricsDocument(
                enabled=True,
                retention_days=3,
                buckets=(
                    MetricsBucket(
                        bucket_start="2026-07-06T00:00:00+00:00",
                        bucket_end="2026-07-06T01:00:00+00:00",
                        counters={"route.current": 2},
                    ),
                ),
            )

            store.save(document)
            restored = store.load()

        self.assertTrue(restored.enabled)
        self.assertEqual(restored.retention_days, 3)
        self.assertEqual(restored.buckets[0].counters["route.current"], 2)
        self.assertIsNotNone(restored.updated_at)

    def test_increment_noops_when_metrics_file_is_missing(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "metrics.json"
            store = MetricsStore(path)

            self.assertFalse(
                store.increment(
                    {"command.connect.success": 1},
                    now=datetime(2026, 7, 6, 12, 30, tzinfo=timezone.utc),
                )
            )

            self.assertFalse(path.exists())
            self.assertFalse(path.with_name("metrics.json.lock").exists())

    def test_increment_merges_into_hourly_bucket_when_enabled(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "metrics.json"
            store = MetricsStore(path)
            store.save(MetricsDocument(enabled=True))

            self.assertTrue(
                store.increment(
                    {"command.connect.success": 1},
                    now=datetime(2026, 7, 6, 12, 30, tzinfo=timezone.utc),
                )
            )
            self.assertTrue(
                store.increment(
                    {"command.connect.success": 2, "recovery.status.recovered": 1},
                    now=datetime(2026, 7, 6, 12, 45, tzinfo=timezone.utc),
                )
            )
            restored = store.load()

        self.assertEqual(len(restored.buckets), 1)
        self.assertEqual(
            restored.buckets[0].counters,
            {"command.connect.success": 3, "recovery.status.recovered": 1},
        )

    def test_increment_prunes_expired_buckets(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "metrics.json"
            store = MetricsStore(path)
            store.save(
                MetricsDocument(
                    enabled=True,
                    retention_days=1,
                    buckets=(
                        MetricsBucket(
                            bucket_start="2026-07-04T00:00:00+00:00",
                            bucket_end="2026-07-04T01:00:00+00:00",
                            counters={"old": 1},
                        ),
                    ),
                )
            )

            store.increment(
                {"new": 1},
                now=datetime(2026, 7, 6, 12, 0, tzinfo=timezone.utc),
            )
            restored = store.load()

        self.assertEqual(len(restored.buckets), 1)
        self.assertEqual(restored.buckets[0].counters, {"new": 1})

    def test_save_rejects_document_above_size_limit(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "metrics.json"
            store = MetricsStore(path)
            document = MetricsDocument(
                max_bytes=1024,
                buckets=(
                    MetricsBucket(
                        bucket_start="2026-07-06T00:00:00+00:00",
                        bucket_end="2026-07-06T01:00:00+00:00",
                        counters={f"counter.{index}": index for index in range(100)},
                    ),
                ),
            )

            with self.assertRaises(PersistentValidationError):
                store.save(document)

            self.assertFalse(path.exists())

    def test_prune_removes_expired_buckets(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "metrics.json"
            store = MetricsStore(path)
            store.save(
                MetricsDocument(
                    retention_days=1,
                    buckets=(
                        MetricsBucket(
                            bucket_start="2026-07-04T00:00:00+00:00",
                            bucket_end="2026-07-04T01:00:00+00:00",
                            counters={"route.direct": 1},
                        ),
                        MetricsBucket(
                            bucket_start="2026-07-06T00:00:00+00:00",
                            bucket_end="2026-07-06T01:00:00+00:00",
                            counters={"route.current": 1},
                        ),
                    ),
                )
            )

            pruned = store.prune(datetime(2026, 7, 6, 12, 0, tzinfo=timezone.utc))

        self.assertEqual(len(pruned.buckets), 1)
        self.assertEqual(pruned.buckets[0].counters, {"route.current": 1})

    def test_purge_removes_metrics_file(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "metrics.json"
            store = MetricsStore(path)
            store.save(MetricsDocument(enabled=True))

            self.assertTrue(store.purge())
            self.assertFalse(path.exists())
            self.assertFalse(store.purge())

    def test_metrics_path_uses_environment_override(self) -> None:
        with patch.dict("os.environ", {"WATCHDOGVPN_METRICS_FILE": "/tmp/wdvpn-metrics.json"}):
            store = MetricsStore()

        self.assertEqual(store.path, Path("/tmp/wdvpn-metrics.json"))

    def test_load_rejects_non_object(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "metrics.json"
            path.write_text("[]", encoding="utf-8")

            with self.assertRaises(PersistentValidationError):
                MetricsStore(path).load()

    def test_atomic_save_does_not_leave_temp_files(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "metrics.json"

            MetricsStore(path).save(MetricsDocument())

            self.assertTrue(path.exists())
            self.assertEqual(list(Path(tmp).glob("*.tmp")), [])
            json.loads(path.read_text(encoding="utf-8"))


class MetricsRecorderTests(unittest.TestCase):
    def test_recorder_writes_aggregate_runtime_counters_when_enabled(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "metrics.json"
            store = MetricsStore(path)
            store.save(MetricsDocument(enabled=True))
            recorder = MetricsRecorder(store)

            recorder.record_connection_result(profile_id="profile one", connected=True)
            recorder.record_manual_rotation(
                ConnectionState(
                    active_profile_id="profile one",
                    mode="rules",
                    status="recovered",
                )
            )
            recorder.record_route_action("group:secure")
            recorder.record_rule_group("custom group")
            restored = store.load()

        counters = restored.buckets[0].counters
        self.assertEqual(counters["command.connect.attempt"], 1)
        self.assertEqual(counters["command.connect.success"], 1)
        self.assertEqual(counters["profile.profile_one.connect.success"], 1)
        self.assertEqual(counters["rotation.manual.status.recovered"], 1)
        self.assertEqual(counters["route_action.group:secure"], 1)
        self.assertEqual(counters["rule_group.custom_group"], 1)


if __name__ == "__main__":
    unittest.main()
