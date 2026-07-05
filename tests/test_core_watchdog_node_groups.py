from __future__ import annotations

import tempfile
import unittest
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

    def test_pool_is_empty_fail_closed_when_targeted_group_does_not_exist(self) -> None:
        self.rule_store.add_group(
            RuleGroup(name="custom", rules=[Rule(id="rr", action="group:missing", conditions={"domain": ["a.com"]})])
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

    @patch("core.watchdog.health_checker.check", return_value="ok")
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


if __name__ == "__main__":
    unittest.main()
