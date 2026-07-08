from __future__ import annotations

import hashlib
import json
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from rules.models import Rule, RuleGroup
from rules.ruleset_lifecycle import (
    RuleSetLifecycleError,
    RuleSetLifecycleManager,
    RuleSetRuntimeError,
    referenced_rule_set_ids,
)
from rules.ruleset_trust import (
    RuleSetLoadState,
    RuleSetStatus,
    RuleSetTrustPolicy,
    RuleSetTrustRegistry,
)
from rules.ruleset_trust_store import RuleSetTrustStore


def source_ruleset(domain: str = "example.com") -> bytes:
    return json.dumps({"version": 1, "rules": [{"domain": [domain]}]}).encode("utf-8")


class RuleSetLifecycleManagerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmpdir = tempfile.TemporaryDirectory()
        self.root = Path(self.tmpdir.name)
        self.trust_path = self.root / "ruleset-trust.json"
        self.cache_dir = self.root / "cache"

    def tearDown(self) -> None:
        self.tmpdir.cleanup()

    def manager(self, payload: bytes | Exception, now: datetime | None = None) -> RuleSetLifecycleManager:
        def fetch(_source: str, _timeout: float) -> bytes:
            if isinstance(payload, Exception):
                raise payload
            return payload

        return RuleSetLifecycleManager(
            store=RuleSetTrustStore(self.trust_path),
            cache_dir=self.cache_dir,
            fetch_rule_set=fetch,
            now=lambda: now or datetime(2026, 7, 8, tzinfo=timezone.utc),
        )

    def write_registry(self, registry: RuleSetTrustRegistry) -> None:
        self.trust_path.write_text(json.dumps(registry.to_dict()), encoding="utf-8")

    def remote_policy(self, payload: bytes, *, critical: bool = True) -> RuleSetTrustPolicy:
        return RuleSetTrustPolicy(
            id="remote-ads",
            kind="remote",
            source="https://rules.example/ads.json",
            expected_sha256=hashlib.sha256(payload).hexdigest(),
            critical=critical,
            update_interval_seconds=3600,
            max_stale_seconds=7200,
        )

    def test_refresh_downloads_verifies_and_caches_remote_ruleset(self) -> None:
        payload = source_ruleset()
        policy = self.remote_policy(payload)
        self.write_registry(RuleSetTrustRegistry(policies={policy.id: policy}))

        results = self.manager(payload).refresh(force=True)
        registry = RuleSetTrustStore(self.trust_path).load()
        status = registry.status_for(policy.id)

        self.assertEqual(results[0].state, "loaded")
        self.assertTrue(results[0].refreshed)
        self.assertEqual(status.state, RuleSetLoadState.LOADED)
        self.assertEqual(Path(status.cache_path).read_bytes(), payload)

    def test_sha256_mismatch_fails_closed_without_cache_write(self) -> None:
        payload = source_ruleset()
        policy = self.remote_policy(payload)
        self.write_registry(RuleSetTrustRegistry(policies={policy.id: policy}))

        results = self.manager(source_ruleset("changed.example")).refresh(force=True)
        status = RuleSetTrustStore(self.trust_path).load().status_for(policy.id)

        self.assertEqual(results[0].state, "failed")
        self.assertIn("sha256 mismatch", results[0].error)
        self.assertEqual(status.state, RuleSetLoadState.FAILED)
        self.assertEqual(list(self.cache_dir.glob("*")), [])

    def test_failed_refresh_uses_fresh_stale_cache(self) -> None:
        payload = source_ruleset()
        policy = self.remote_policy(payload)
        cache_path = self.cache_dir / "existing.json"
        cache_path.parent.mkdir(parents=True)
        cache_path.write_bytes(payload)
        loaded_at = "2026-07-08T00:00:00Z"
        self.write_registry(
            RuleSetTrustRegistry(
                policies={policy.id: policy},
                statuses={
                    policy.id: RuleSetStatus(
                        id=policy.id,
                        state="loaded",
                        loaded_sha256=hashlib.sha256(payload).hexdigest(),
                        last_loaded_at=loaded_at,
                        last_checked_at=loaded_at,
                        cache_path=str(cache_path),
                    )
                },
            )
        )
        now = datetime(2026, 7, 8, 1, 30, tzinfo=timezone.utc)

        results = self.manager(RuleSetLifecycleError("network down"), now=now).refresh(force=True)
        status = RuleSetTrustStore(self.trust_path).load().status_for(policy.id)

        self.assertEqual(results[0].state, "stale")
        self.assertTrue(results[0].used_existing_cache)
        self.assertEqual(status.cache_path, str(cache_path))
        self.assertEqual(cache_path.read_bytes(), payload)

    def test_malformed_source_ruleset_is_rejected(self) -> None:
        payload = b'{"rules": [{"unsupported": ["x"]}]}'
        policy = self.remote_policy(payload)
        self.write_registry(RuleSetTrustRegistry(policies={policy.id: policy}))

        results = self.manager(payload).refresh(force=True)

        self.assertEqual(results[0].state, "failed")
        self.assertIn("malformed source rule-set", results[0].error)

    def test_runtime_plan_refuses_missing_critical_policy(self) -> None:
        group = RuleGroup(
            name="custom",
            rules=[Rule(id="r1", action="block", conditions={"ruleset_remote": ["missing"]})],
        )
        self.write_registry(RuleSetTrustRegistry())

        with self.assertRaises(RuleSetRuntimeError):
            self.manager(source_ruleset()).runtime_plan([group])

    def test_runtime_plan_declares_loaded_local_cache(self) -> None:
        payload = source_ruleset()
        policy = self.remote_policy(payload)
        self.write_registry(RuleSetTrustRegistry(policies={policy.id: policy}))
        group = RuleGroup(
            name="custom",
            rules=[Rule(id="r1", action="block", conditions={"ruleset_remote": [policy.id]})],
        )

        plan = self.manager(payload).runtime_plan([group])

        self.assertIn(policy.id, plan.tags)
        self.assertEqual(plan.declarations[0]["type"], "local")
        self.assertEqual(plan.declarations[0]["format"], "source")
        self.assertTrue(Path(plan.declarations[0]["path"]).exists())

    def test_referenced_rule_set_ids_ignores_disabled_groups_and_rules(self) -> None:
        groups = [
            RuleGroup(
                name="custom",
                rules=[
                    Rule(id="on", action="block", conditions={"ruleset_builtin": ["geo"]}),
                    Rule(
                        id="off",
                        action="block",
                        enabled=False,
                        conditions={"ruleset_remote": ["remote"]},
                    ),
                ],
            ),
            RuleGroup(
                name="block",
                enabled=False,
                rules=[Rule(id="hidden", action="block", conditions={"ruleset_remote": ["x"]})],
            ),
        ]

        self.assertEqual(referenced_rule_set_ids(groups), {"geo"})


if __name__ == "__main__":
    unittest.main()
