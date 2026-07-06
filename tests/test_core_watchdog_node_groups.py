from __future__ import annotations

import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import MagicMock, patch

from app_policy.models import AppPolicy, AppPolicyMode, AppPolicyRule
from app_policy.store import AppPolicyStore
from config.app_config import AppConfig
from config.profile_store import ProfileStore
from config.provider_store import ProviderStore
from config.state_manager import StateManager
from core.watchdog import WatchdogRuntime
from drivers.base import BaseDriver
from models.connection_state import ConnectionState
from models.profile import Profile, ProfileSource, ProtocolType
from node_groups.models import NodeGroup, NodeGroupResiliencePolicy, NodeGroupSelectionMode
from node_groups.store import NodeGroupStore
from rotation.health_checker import HealthCheckResult
from rotation.recovery import Recovery
from rotation.rotation_engine import RotationEngine
from rules.models import Rule, RuleGroup
from rules.rule_store import RuleStore


class FakeDriver(BaseDriver):
    def __init__(self, health: str = "ok") -> None:
        self.health = health
        self.connected_profile_id = ""

    def connect(self, profile: Profile, dns_policy=None, **kwargs) -> bool:
        self.connected_profile_id = profile.id
        return True

    def disconnect(self) -> bool:
        self.connected_profile_id = ""
        return True

    def health_check(self) -> str:
        return self.health

    def status(self) -> ConnectionState:
        return ConnectionState(
            active_profile_id=self.connected_profile_id,
            status="connected" if self.connected_profile_id else "standby",
            mode="rules",
        )

    def is_available(self) -> bool:
        return True


class FakeKillSwitch:
    def __init__(self) -> None:
        self.active = False
        self.enable_calls = 0
        self.tunnel_interface = "wdvpn-tun0"
        self.block_ipv6 = True
        self.allow_lan = True
        self.allowed_endpoints: tuple[str, ...] = ()

    def enable(self) -> bool:
        self.enable_calls += 1
        self.active = True
        return True

    def disable(self) -> bool:
        self.active = False
        return True

    def is_active(self) -> bool:
        return self.active

    def status(self) -> dict:
        return {}


class NodeGroupRuntimeIntegrationTests(unittest.TestCase):
    """Task 14.6 — the node-group selector feeds RotationEngine's candidate
    pool instead of competing with it; rotation_engine.py is never touched.
    """

    def setUp(self) -> None:
        self.tmpdir = tempfile.TemporaryDirectory()
        root = Path(self.tmpdir.name)
        self.state_manager = StateManager(root / "state.toml")
        self.state_manager.set("vpn_desired_state", "on")
        self.profile_store = ProfileStore(root / "profiles.json")
        self.provider_store = ProviderStore(root / "providers.json")
        self.node_group_store = NodeGroupStore(root / "node_groups.json")
        self.rule_store = RuleStore(root / "rules")
        self.app_policy_store = AppPolicyStore(root / "app_policy.json")

        self.resilient = Profile(
            id="r1", name="Resilient", protocol=ProtocolType.VLESS,
            config={}, source=ProfileSource.MANUAL, enabled=True,
        )
        self.compat = Profile(
            id="c1", name="Compat", protocol=ProtocolType.WIREGUARD,
            config={}, source=ProfileSource.MANUAL, enabled=True,
        )
        self.profile_store.add(self.resilient)
        self.profile_store.add(self.compat)

    def tearDown(self) -> None:
        self.tmpdir.cleanup()

    def _make_runtime(self, driver: BaseDriver, kill_switch: FakeKillSwitch | None = None) -> WatchdogRuntime:
        clock_value = [0.0]
        clock = lambda: clock_value[0]
        app_config = MagicMock(spec=AppConfig)
        app_config.load.return_value = {
            "watchdog": {},
            "kill_switch": {"enabled": True},
            "rotation": {"enabled": True},
        }
        return WatchdogRuntime(
            driver=driver,
            state_manager=self.state_manager,
            profile_store=self.profile_store,
            provider_store=self.provider_store,
            node_group_store=self.node_group_store,
            rule_store=self.rule_store,
            app_policy_store=self.app_policy_store,
            app_config=app_config,
            rotation_engine=RotationEngine(clock=clock, sleep=lambda s: None, warmup_seconds=0.0),
            recovery=Recovery(clock=clock),
            kill_switch=kill_switch or FakeKillSwitch(),
        )

    # ---- _effective_node_group() ----

    def test_no_enabled_rule_or_app_policy_means_no_effective_group(self) -> None:
        runtime = self._make_runtime(FakeDriver())

        name, group = runtime._effective_node_group()

        self.assertIsNone(name)
        self.assertIsNone(group)

    def test_enabled_rule_targeting_a_group_is_found(self) -> None:
        self.node_group_store.add(NodeGroup(name="paris", member_profile_ids=["r1"]))
        self.rule_store.add_group(
            RuleGroup(
                name="custom",
                rules=[Rule(id="rr", action="group:paris", conditions={"domain": ["example.com"]})],
            )
        )
        runtime = self._make_runtime(FakeDriver())

        name, group = runtime._effective_node_group()

        self.assertEqual(name, "paris")
        self.assertEqual(group.name, "paris")

    def test_disabled_rule_targeting_a_group_is_ignored(self) -> None:
        self.node_group_store.add(NodeGroup(name="paris", member_profile_ids=["r1"]))
        self.rule_store.add_group(
            RuleGroup(
                name="custom",
                rules=[
                    Rule(
                        id="rr",
                        action="group:paris",
                        conditions={"domain": ["example.com"]},
                        enabled=False,
                    )
                ],
            )
        )
        runtime = self._make_runtime(FakeDriver())

        name, group = runtime._effective_node_group()

        self.assertIsNone(name)
        self.assertIsNone(group)

    def test_disabled_group_targeting_a_group_is_ignored(self) -> None:
        self.node_group_store.add(NodeGroup(name="paris", member_profile_ids=["r1"]))
        self.rule_store.add_group(
            RuleGroup(
                name="custom",
                enabled=False,
                rules=[Rule(id="rr", action="group:paris", conditions={"domain": ["example.com"]})],
            )
        )
        runtime = self._make_runtime(FakeDriver())

        name, group = runtime._effective_node_group()

        self.assertIsNone(name)
        self.assertIsNone(group)

    def test_higher_priority_tier_wins_when_multiple_groups_are_targeted(self) -> None:
        # "custom" outranks "recommended" in PRIORITY_TIER_ORDER - reuses
        # the same precedence RuleEngine already uses for real traffic.
        self.node_group_store.add(NodeGroup(name="paris", member_profile_ids=["r1"]))
        self.node_group_store.add(NodeGroup(name="berlin", member_profile_ids=["c1"]))
        self.rule_store.add_group(
            RuleGroup(
                name="recommended",
                rules=[Rule(id="rec", action="group:berlin", conditions={"domain": ["a.com"]})],
            )
        )
        self.rule_store.add_group(
            RuleGroup(
                name="custom",
                rules=[Rule(id="cus", action="group:paris", conditions={"domain": ["b.com"]})],
            )
        )
        runtime = self._make_runtime(FakeDriver())

        name, _ = runtime._effective_node_group()

        self.assertEqual(name, "paris")

    def test_app_policy_default_action_targeting_a_group_is_found(self) -> None:
        self.node_group_store.add(NodeGroup(name="paris", member_profile_ids=["r1"]))
        self.app_policy_store.save(
            AppPolicy(enabled=True, mode=AppPolicyMode.WHITELIST, default_action="group:paris")
        )
        runtime = self._make_runtime(FakeDriver())

        name, group = runtime._effective_node_group()

        self.assertEqual(name, "paris")
        self.assertEqual(group.name, "paris")

    def test_app_policy_rule_targeting_a_group_is_found(self) -> None:
        self.node_group_store.add(NodeGroup(name="paris", member_profile_ids=["r1"]))
        self.app_policy_store.save(
            AppPolicy(
                enabled=True,
                mode=AppPolicyMode.BLACKLIST,
                default_action="current",
                rules=[
                    AppPolicyRule(id="secure", action="group:paris", match={"process_name": ["curl"]})
                ],
            )
        )
        runtime = self._make_runtime(FakeDriver())

        name, group = runtime._effective_node_group()

        self.assertEqual(name, "paris")

    def test_disabled_app_policy_is_ignored(self) -> None:
        self.node_group_store.add(NodeGroup(name="paris", member_profile_ids=["r1"]))
        self.app_policy_store.save(
            AppPolicy(enabled=False, mode=AppPolicyMode.WHITELIST, default_action="group:paris")
        )
        runtime = self._make_runtime(FakeDriver())

        name, group = runtime._effective_node_group()

        self.assertIsNone(name)
        self.assertIsNone(group)

    # ---- _compatible_pool() ----

    def test_pool_is_legacy_when_no_group_is_targeted(self) -> None:
        self.resilient.in_rotation_pool = True
        self.profile_store.update(self.resilient)
        runtime = self._make_runtime(FakeDriver())

        pool = runtime._compatible_pool({"rotation": {}})

        self.assertEqual([p.id for p in pool], ["r1"])

    def test_pool_is_group_scoped_and_scored_when_a_group_is_targeted(self) -> None:
        # in_rotation_pool is deliberately left False on both profiles -
        # group membership must not depend on it (ADR 0002).
        self.node_group_store.add(
            NodeGroup(
                name="paris",
                member_profile_ids=["r1", "c1"],
                resilience_policy=NodeGroupResiliencePolicy.PREFERRED,
            )
        )
        self.rule_store.add_group(
            RuleGroup(name="custom", rules=[Rule(id="rr", action="group:paris", conditions={"domain": ["a.com"]})])
        )
        runtime = self._make_runtime(FakeDriver())

        pool = runtime._compatible_pool({"rotation": {}})

        # PREFERRED ranks resilient (r1) above compatibility (c1).
        self.assertEqual([p.id for p in pool], ["r1", "c1"])

    def test_latency_end_to_end_measure_persist_rank_then_expire(self) -> None:
        """Task 14.7's full cycle, with real reads/writes throughout - not
        a mocked field: measure a real latency via _checked_and_recorded,
        confirm it is persisted, confirm it breaks a ranking tie in
        _compatible_pool, then backdate it past the configured staleness
        window (same technique tests.test_pool_builder already uses for
        health cooldown expiry) and confirm the group-scoped pool falls
        back to the id tie-break instead of trusting stale data.
        """
        # Both are compatibility (equal resilience_score under PREFERRED),
        # so only latency can break the tie between them. "s1" is the FAST
        # one and "c1" is SLOW, deliberately the opposite of their
        # alphabetical order - if the pool order matched id order instead,
        # that would prove latency was NOT actually deciding anything.
        slow = self.compat  # id "c1"
        fast = Profile(
            id="s1", name="Fast", protocol=ProtocolType.SHADOWSOCKS,
            config={}, source=ProfileSource.MANUAL, enabled=True,
        )
        self.profile_store.add(fast)
        self.node_group_store.add(
            NodeGroup(name="paris", member_profile_ids=["c1", "s1"])
        )
        self.rule_store.add_group(
            RuleGroup(name="custom", rules=[Rule(id="rr", action="group:paris", conditions={"domain": ["a.com"]})])
        )
        runtime = self._make_runtime(FakeDriver())
        runtime.app_config = MagicMock(spec=AppConfig)
        runtime.app_config.load.return_value = {
            "rotation": {"latency_max_stale_seconds": 300},
        }

        # 1. Real measurements persisted via the real _checked_and_recorded
        #    path (mocking only the network call, not the persistence).
        with patch(
            "core.watchdog.health_checker.check_with_latency",
            return_value=HealthCheckResult(status="ok", latency_ms=900.0),
        ):
            runtime._checked_and_recorded(slow, FakeDriver())
        with patch(
            "core.watchdog.health_checker.check_with_latency",
            return_value=HealthCheckResult(status="ok", latency_ms=20.0),
        ):
            runtime._checked_and_recorded(fast, FakeDriver())

        self.assertEqual(self.profile_store.get("c1").latency_ms, 900.0)
        self.assertEqual(self.profile_store.get("s1").latency_ms, 20.0)

        # 2. Latency breaks the tie in the real group-scoped pool: "s1"
        #    (fast) ranks first despite "c1" < "s1" alphabetically -
        #    proves latency is actually deciding, not the id fallback.
        pool = runtime._compatible_pool({"rotation": {"latency_max_stale_seconds": 300}})
        self.assertEqual([p.id for p in pool], ["s1", "c1"])

        # 3. Backdate the faster node's measurement past staleness.
        stale = self.profile_store.get("s1")
        stale.last_latency_check = datetime.now(timezone.utc) - timedelta(seconds=999999)
        self.profile_store.update(stale)

        # 4. Both now effectively unmeasured for ranking purposes - the
        #    order flips back to the id tie-break ("c1" < "s1"), proving
        #    the stale measurement stopped being trusted instead of
        #    silently keeping "s1" ranked first forever.
        pool_after_expiry = runtime._compatible_pool({"rotation": {"latency_max_stale_seconds": 300}})
        self.assertEqual([p.id for p in pool_after_expiry], ["c1", "s1"])

    def test_pool_is_empty_fail_closed_when_targeted_group_does_not_exist(self) -> None:
        self.rule_store.add_group(
            RuleGroup(name="custom", rules=[Rule(id="rr", action="group:missing", conditions={"domain": ["a.com"]})])
        )
        runtime = self._make_runtime(FakeDriver())

        pool = runtime._compatible_pool({"rotation": {}})

        self.assertEqual(pool, [])

    def test_disabled_node_group_fails_closed_to_empty_pool(self) -> None:
        self.node_group_store.add(NodeGroup(name="paris", enabled=False, member_profile_ids=["r1"]))
        self.rule_store.add_group(
            RuleGroup(name="custom", rules=[Rule(id="rr", action="group:paris", conditions={"domain": ["a.com"]})])
        )
        runtime = self._make_runtime(FakeDriver())

        pool = runtime._compatible_pool({"rotation": {}})

        self.assertEqual(pool, [])

    def test_pool_is_restricted_to_the_manual_pin(self) -> None:
        self.node_group_store.add(
            NodeGroup(
                name="paris",
                member_profile_ids=["r1", "c1"],
                selection_mode=NodeGroupSelectionMode.MANUAL,
                manual_profile_id="c1",
            )
        )
        self.rule_store.add_group(
            RuleGroup(name="custom", rules=[Rule(id="rr", action="group:paris", conditions={"domain": ["a.com"]})])
        )
        runtime = self._make_runtime(FakeDriver())

        pool = runtime._compatible_pool({"rotation": {}})

        self.assertEqual([p.id for p in pool], ["c1"])

    def test_manual_pin_does_not_fall_back_to_a_different_profile_when_pin_is_unhealthy(self) -> None:
        self.compat.enabled = False
        self.profile_store.update(self.compat)
        self.node_group_store.add(
            NodeGroup(
                name="paris",
                member_profile_ids=["r1", "c1"],
                selection_mode=NodeGroupSelectionMode.MANUAL,
                manual_profile_id="c1",
            )
        )
        self.rule_store.add_group(
            RuleGroup(name="custom", rules=[Rule(id="rr", action="group:paris", conditions={"domain": ["a.com"]})])
        )
        runtime = self._make_runtime(FakeDriver())

        pool = runtime._compatible_pool({"rotation": {}})

        # Empty, not [r1] - "decisions are respected," no silent swap.
        self.assertEqual(pool, [])

    def test_resilient_only_group_fails_closed_when_no_resilient_candidate_is_healthy(self) -> None:
        self.resilient.enabled = False
        self.profile_store.update(self.resilient)
        self.node_group_store.add(
            NodeGroup(
                name="paris",
                member_profile_ids=["r1", "c1"],
                resilience_policy=NodeGroupResiliencePolicy.RESILIENT_ONLY,
            )
        )
        self.rule_store.add_group(
            RuleGroup(name="custom", rules=[Rule(id="rr", action="group:paris", conditions={"domain": ["a.com"]})])
        )
        runtime = self._make_runtime(FakeDriver())

        pool = runtime._compatible_pool({"rotation": {}})

        self.assertEqual(pool, [])

    # ---- end-to-end: fail-closed reaches the kill switch ----

    def test_missing_group_reaches_kill_switch_end_to_end(self) -> None:
        # Pool is empty (fail-closed on a missing group) before
        # RotationEngine ever reaches a live health check, so no patch is
        # needed here - this proves the empty-pool path alone is what
        # trips the kill switch.
        self.rule_store.add_group(
            RuleGroup(name="custom", rules=[Rule(id="rr", action="group:missing", conditions={"domain": ["a.com"]})])
        )
        kill_switch = FakeKillSwitch()
        runtime = self._make_runtime(FakeDriver(), kill_switch=kill_switch)

        result = runtime.rotate_now(force=True)

        self.assertEqual(result.status, "kill_switch_active")
        self.assertTrue(kill_switch.active)
        self.assertEqual(kill_switch.enable_calls, 1)

    def test_resilient_only_exhaustion_reaches_kill_switch_end_to_end(self) -> None:
        self.resilient.enabled = False
        self.profile_store.update(self.resilient)
        self.node_group_store.add(
            NodeGroup(
                name="paris",
                member_profile_ids=["r1", "c1"],
                resilience_policy=NodeGroupResiliencePolicy.RESILIENT_ONLY,
            )
        )
        self.rule_store.add_group(
            RuleGroup(name="custom", rules=[Rule(id="rr", action="group:paris", conditions={"domain": ["a.com"]})])
        )
        kill_switch = FakeKillSwitch()
        runtime = self._make_runtime(FakeDriver(), kill_switch=kill_switch)

        result = runtime.rotate_now(force=True)

        self.assertEqual(result.status, "kill_switch_active")
        self.assertTrue(kill_switch.active)

    @patch("core.watchdog.health_checker.check_with_latency", return_value=HealthCheckResult(status="ok"))
    def test_targeted_group_actually_connects_to_the_best_candidate(self, _hc) -> None:
        self.node_group_store.add(
            NodeGroup(name="paris", member_profile_ids=["r1", "c1"], resilience_policy=NodeGroupResiliencePolicy.PREFERRED)
        )
        self.rule_store.add_group(
            RuleGroup(name="custom", rules=[Rule(id="rr", action="group:paris", conditions={"domain": ["a.com"]})])
        )
        driver = FakeDriver()
        runtime = self._make_runtime(driver)

        result = runtime.rotate_now(force=True)

        self.assertEqual(result.status, "recovered")
        self.assertEqual(self.state_manager.get("active_profile_id"), "r1")


class NodeGroupAutoTestRuntimeTests(unittest.TestCase):
    """Task 14.8 — auto-test is a serialized runtime action that measures
    candidates without changing active_profile_id.
    """

    def setUp(self) -> None:
        self.tmpdir = tempfile.TemporaryDirectory()
        root = Path(self.tmpdir.name)
        self.state_manager = StateManager(root / "state.toml")
        self.profile_store = ProfileStore(root / "profiles.json")
        self.provider_store = ProviderStore(root / "providers.json")
        self.node_group_store = NodeGroupStore(root / "node_groups.json")
        self.rule_store = RuleStore(root / "rules")
        self.app_policy_store = AppPolicyStore(root / "app_policy.json")

        self.resilient = Profile(
            id="r1", name="Resilient", protocol=ProtocolType.VLESS,
            config={}, source=ProfileSource.MANUAL, enabled=True,
        )
        self.profile_store.add(self.resilient)

    def tearDown(self) -> None:
        self.tmpdir.cleanup()

    def _make_runtime(self, driver: BaseDriver, kill_switch: FakeKillSwitch | None = None) -> WatchdogRuntime:
        app_config = MagicMock(spec=AppConfig)
        app_config.load.return_value = {
            "watchdog": {},
            "kill_switch": {"enabled": True},
            "rotation": {
                "enabled": True,
                "health_status_cooldown_seconds": 300,
                "latency_max_stale_seconds": 300,
                "test_url": "https://example.com",
                "test_timeout_seconds": 5,
            },
        }
        return WatchdogRuntime(
            driver=driver,
            state_manager=self.state_manager,
            profile_store=self.profile_store,
            provider_store=self.provider_store,
            node_group_store=self.node_group_store,
            rule_store=self.rule_store,
            app_policy_store=self.app_policy_store,
            app_config=app_config,
            rotation_engine=RotationEngine(clock=lambda: 0.0, sleep=lambda s: None, warmup_seconds=0.0),
            recovery=Recovery(clock=lambda: 0.0),
            kill_switch=kill_switch or FakeKillSwitch(),
        )

    def test_auto_test_measures_persists_and_ranks_without_activating_profile(self) -> None:
        second_resilient = Profile(
            id="r2", name="Second", protocol=ProtocolType.TROJAN,
            config={}, source=ProfileSource.MANUAL, enabled=True,
        )
        self.profile_store.add(second_resilient)
        self.node_group_store.add(NodeGroup(name="paris", member_profile_ids=["r1", "r2"]))
        driver = FakeDriver()
        runtime = self._make_runtime(driver)

        def fake_check(profile: Profile, checked_driver: BaseDriver, verify=None) -> HealthCheckResult:
            latency = 100.0 if profile.id == "r1" else 10.0
            return HealthCheckResult(status="ok", latency_ms=latency)

        with patch("core.watchdog.health_checker.check_with_latency", side_effect=fake_check):
            payload = runtime.node_group_auto_test("paris")

        self.assertEqual(payload["result"], "selected")
        self.assertEqual(payload["selected_profile_id"], "r2")
        self.assertEqual([item["profile_id"] for item in payload["candidates"]], ["r2", "r1"])
        self.assertEqual(driver.connected_profile_id, "")
        self.assertEqual(self.state_manager.get("active_profile_id", ""), "")
        self.assertEqual(self.profile_store.get("r1").latency_ms, 100.0)
        self.assertEqual(self.profile_store.get("r2").latency_ms, 10.0)

    def test_auto_test_records_connect_failure_as_down_and_unavailable(self) -> None:
        self.node_group_store.add(NodeGroup(name="paris", member_profile_ids=["r1"]))
        driver = FakeDriver()
        driver.connect = MagicMock(return_value=False)  # type: ignore[method-assign]
        runtime = self._make_runtime(driver)

        payload = runtime.node_group_auto_test("paris")

        self.assertEqual(payload["result"], "unavailable")
        self.assertIsNone(payload["selected_profile_id"])
        self.assertEqual(payload["tested"][0]["health_status"], "down")
        self.assertEqual(self.profile_store.get("r1").health_status, "down")

    def test_auto_test_does_not_report_degraded_candidate_as_selected(self) -> None:
        self.node_group_store.add(NodeGroup(name="paris", member_profile_ids=["r1"]))
        runtime = self._make_runtime(FakeDriver())

        with patch(
            "core.watchdog.health_checker.check_with_latency",
            return_value=HealthCheckResult(status="degraded", latency_ms=50.0),
        ):
            payload = runtime.node_group_auto_test("paris")

        self.assertEqual(payload["tested"][0]["health_status"], "degraded")
        self.assertEqual(payload["result"], "unavailable")
        self.assertIsNone(payload["selected_profile_id"])
        self.assertEqual(payload["candidates"], [])

    def test_auto_test_checks_disconnect_after_connect_failure(self) -> None:
        self.node_group_store.add(NodeGroup(name="paris", member_profile_ids=["r1"]))
        driver = FakeDriver()
        driver.connect = MagicMock(return_value=False)  # type: ignore[method-assign]
        driver.disconnect = MagicMock(return_value=False)  # type: ignore[method-assign]
        runtime = self._make_runtime(driver)

        with self.assertRaisesRegex(RuntimeError, "failed to disconnect profile: r1"):
            runtime.node_group_auto_test("paris")

    def test_auto_test_disconnects_when_deep_check_raises(self) -> None:
        self.node_group_store.add(NodeGroup(name="paris", member_profile_ids=["r1"]))
        driver = FakeDriver()
        driver.disconnect = MagicMock(return_value=True)  # type: ignore[method-assign]
        runtime = self._make_runtime(driver)

        with patch(
            "core.watchdog.health_checker.check_with_latency",
            side_effect=RuntimeError("probe failed"),
        ):
            with self.assertRaisesRegex(RuntimeError, "probe failed"):
                runtime.node_group_auto_test("paris")

        driver.disconnect.assert_called_once()

    def test_auto_test_rejects_active_connection(self) -> None:
        self.node_group_store.add(NodeGroup(name="paris", member_profile_ids=["r1"]))
        driver = FakeDriver()
        driver.connect(self.resilient)
        runtime = self._make_runtime(driver)

        with self.assertRaisesRegex(RuntimeError, "requires standby/disconnected state"):
            runtime.node_group_auto_test("paris")

    def test_auto_test_rejects_active_kill_switch(self) -> None:
        self.node_group_store.add(NodeGroup(name="paris", member_profile_ids=["r1"]))
        kill_switch = FakeKillSwitch()
        kill_switch.active = True
        runtime = self._make_runtime(FakeDriver(), kill_switch=kill_switch)

        with self.assertRaisesRegex(RuntimeError, "kill switch to be inactive"):
            runtime.node_group_auto_test("paris")

    def test_auto_test_rejects_disabled_group(self) -> None:
        self.node_group_store.add(NodeGroup(name="paris", enabled=False, member_profile_ids=["r1"]))
        runtime = self._make_runtime(FakeDriver())

        with self.assertRaisesRegex(RuntimeError, "node group is disabled: paris"):
            runtime.node_group_auto_test("paris")


if __name__ == "__main__":
    unittest.main()
