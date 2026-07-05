from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from rules.ruleset_trust import (
    RuleSetFailureBehavior,
    RuleSetKind,
    RuleSetLoadState,
    RuleSetStatus,
    RuleSetTrustPolicy,
    RuleSetTrustRegistry,
)
from rules.ruleset_trust_store import RuleSetTrustStore


SHA256_A = "a" * 64
SHA256_B = "b" * 64


class RuleSetTrustPolicyTests(unittest.TestCase):
    def test_remote_policy_requires_sha256_pin(self) -> None:
        with self.assertRaises(ValueError):
            RuleSetTrustPolicy(
                id="ads",
                kind="remote",
                source="https://rules.example/ads.srs",
            )

    def test_critical_remote_defaults_to_fail_closed(self) -> None:
        policy = RuleSetTrustPolicy(
            id="sensitive",
            kind="remote",
            source="https://rules.example/sensitive.srs",
            expected_sha256=SHA256_A,
            critical=True,
        )

        self.assertEqual(policy.kind, RuleSetKind.REMOTE)
        self.assertEqual(policy.failure_behavior, RuleSetFailureBehavior.FAIL_CLOSED)
        self.assertEqual(policy.expected_sha256, SHA256_A)

    def test_non_critical_defaults_to_warn_and_skip(self) -> None:
        policy = RuleSetTrustPolicy(
            id="optimize",
            kind="remote",
            source="https://rules.example/optimize.srs",
            expected_sha256=SHA256_A,
            critical=False,
        )

        self.assertEqual(policy.failure_behavior, RuleSetFailureBehavior.WARN_AND_SKIP)

    def test_rejects_invalid_sha256_and_stale_window(self) -> None:
        with self.assertRaises(ValueError):
            RuleSetTrustPolicy(
                id="bad-checksum",
                kind="remote",
                source="https://rules.example/bad.srs",
                expected_sha256="not-a-sha256",
            )
        with self.assertRaises(ValueError):
            RuleSetTrustPolicy(
                id="bad-stale",
                kind="remote",
                source="https://rules.example/bad.srs",
                expected_sha256=SHA256_A,
                update_interval_seconds=3600,
                max_stale_seconds=60,
            )

    def test_round_trip(self) -> None:
        policy = RuleSetTrustPolicy(
            id="ads",
            kind="remote",
            source="https://rules.example/ads.srs",
            expected_sha256=SHA256_A,
            critical=True,
            update_interval_seconds=3600,
            max_stale_seconds=7200,
        )

        restored = RuleSetTrustPolicy.from_dict(policy.to_dict())

        self.assertEqual(restored.to_dict(), policy.to_dict())


class RuleSetStatusTests(unittest.TestCase):
    def test_failed_and_stale_require_error(self) -> None:
        for state in (RuleSetLoadState.FAILED, RuleSetLoadState.STALE):
            with self.subTest(state=state):
                with self.assertRaises(ValueError):
                    RuleSetStatus(id="ads", state=state)

    def test_loaded_status_serializes_checksum(self) -> None:
        status = RuleSetStatus(
            id="ads",
            state="loaded",
            loaded_sha256=SHA256_B,
            last_loaded_at="2026-07-05T12:00:00Z",
        )

        self.assertEqual(status.state, RuleSetLoadState.LOADED)
        self.assertEqual(status.to_dict()["loaded_sha256"], SHA256_B)

    def test_registry_returns_default_not_evaluated_status(self) -> None:
        registry = RuleSetTrustRegistry()

        status = registry.status_for("missing")

        self.assertEqual(status.state, RuleSetLoadState.NOT_EVALUATED)

    def test_registry_round_trip_and_store_load(self) -> None:
        registry = RuleSetTrustRegistry(
            policies={
                "ads": RuleSetTrustPolicy(
                    id="ads",
                    kind="remote",
                    source="https://rules.example/ads.srs",
                    expected_sha256=SHA256_A,
                )
            },
            statuses={
                "ads": RuleSetStatus(
                    id="ads",
                    state="failed",
                    error="sha256 mismatch",
                )
            },
        )

        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "ruleset-trust.json"
            path.write_text(
                json.dumps(registry.to_dict()),
                encoding="utf-8",
            )
            loaded = RuleSetTrustStore(path).load()

        self.assertEqual(loaded.policy_for("ads").failure_behavior.value, "fail-closed")
        self.assertEqual(loaded.status_for("ads").state, RuleSetLoadState.FAILED)


if __name__ == "__main__":
    unittest.main()
