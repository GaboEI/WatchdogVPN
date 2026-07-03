from __future__ import annotations

import unittest

from app_policy.models import AppPolicy, AppPolicyRule
from rules.models import Rule, RuleGroup
from rules.singbox import build_singbox_route_rules


class BuildSingboxRouteRulesTests(unittest.TestCase):
    def test_empty_groups_yields_only_final_rule(self) -> None:
        rules = build_singbox_route_rules([], current_outbound_tag="vps")
        self.assertEqual(rules, [{"action": "route", "outbound": "vps"}])

    def test_block_action_becomes_reject(self) -> None:
        group = RuleGroup(
            name="block",
            rules=[Rule(id="b1", action="block", conditions={"domain_suffix": [".ads.com"]})],
        )
        rules = build_singbox_route_rules([group], current_outbound_tag="vps")
        self.assertEqual(rules[0], {"domain_suffix": [".ads.com"], "action": "reject"})

    def test_direct_action_targets_direct_outbound(self) -> None:
        group = RuleGroup(
            name="app",
            rules=[Rule(id="a1", action="direct", conditions={"process_name": ["steam"]})],
        )
        rules = build_singbox_route_rules([group], current_outbound_tag="vps")
        self.assertEqual(
            rules[0],
            {"process_name": ["steam"], "action": "route", "outbound": "direct"},
        )

    def test_current_profile_auto_select_and_group_all_target_current_outbound(self) -> None:
        group = RuleGroup(
            name="custom",
            rules=[
                Rule(id="c1", action="current_profile", conditions={"domain": ["a.com"]}),
                Rule(id="c2", action="auto_select", conditions={"domain": ["b.com"]}),
                Rule(id="c3", action="group:vless-pool", conditions={"domain": ["c.com"]}),
            ],
        )
        rules = build_singbox_route_rules([group], current_outbound_tag="vps")
        self.assertEqual(rules[0]["outbound"], "vps")
        self.assertEqual(rules[1]["outbound"], "vps")
        self.assertEqual(rules[2]["outbound"], "vps")

    def test_disabled_rule_and_group_are_skipped(self) -> None:
        disabled_group = RuleGroup(
            name="custom",
            enabled=False,
            rules=[Rule(id="c1", action="block", conditions={"domain": ["a.com"]})],
        )
        disabled_rule_group = RuleGroup(
            name="block",
            rules=[
                Rule(
                    id="b1",
                    action="block",
                    conditions={"domain": ["b.com"]},
                    enabled=False,
                )
            ],
        )
        rules = build_singbox_route_rules(
            [disabled_group, disabled_rule_group], current_outbound_tag="vps"
        )
        self.assertEqual(rules, [{"action": "route", "outbound": "vps"}])

    def test_priority_order_preserved(self) -> None:
        block = RuleGroup(
            name="block",
            rules=[Rule(id="b1", action="block", conditions={"domain": ["a.com"]})],
        )
        custom = RuleGroup(
            name="custom",
            rules=[Rule(id="c1", action="direct", conditions={"domain": ["b.com"]})],
        )
        rules = build_singbox_route_rules([custom, block], current_outbound_tag="vps")
        self.assertEqual(rules[0]["action"], "reject")
        self.assertEqual(rules[1]["outbound"], "direct")

    def test_ruleset_conditions_are_skipped_not_mismapped(self) -> None:
        group = RuleGroup(
            name="custom",
            rules=[
                Rule(id="r1", action="block", conditions={"ruleset_builtin": ["geosite:cn"]}),
                Rule(id="r2", action="direct", conditions={"domain": ["a.com"]}),
            ],
        )
        rules = build_singbox_route_rules([group], current_outbound_tag="vps")
        # r1 is skipped entirely (not translated with a wrong/partial match),
        # only r2 and the trailing final rule remain.
        self.assertEqual(len(rules), 2)
        self.assertEqual(
            rules[0],
            {"domain": ["a.com"], "action": "route", "outbound": "direct"},
        )

    def test_imported_family_included_in_priority_order(self) -> None:
        imported = RuleGroup(
            name="imported-20260702",
            rules=[Rule(id="i1", action="block", conditions={"domain": ["a.com"]})],
        )
        recommended = RuleGroup(
            name="recommended",
            rules=[Rule(id="r1", action="direct", conditions={"domain": ["b.com"]})],
        )
        rules = build_singbox_route_rules(
            [recommended, imported], current_outbound_tag="vps"
        )
        self.assertEqual(rules[0]["action"], "reject")  # imported (tier 4) before recommended (tier 5)
        self.assertEqual(rules[1]["outbound"], "direct")

    def test_final_policy_block(self) -> None:
        rules = build_singbox_route_rules([], current_outbound_tag="vps", final_policy="block")
        self.assertEqual(rules, [{"action": "reject"}])

    def test_final_policy_direct(self) -> None:
        rules = build_singbox_route_rules([], current_outbound_tag="vps", final_policy="direct")
        self.assertEqual(rules, [{"action": "route", "outbound": "direct"}])

    def test_multi_value_conditions_preserved_as_lists(self) -> None:
        group = RuleGroup(
            name="custom",
            rules=[
                Rule(
                    id="c1",
                    action="direct",
                    conditions={"domain": ["a.com", "b.com"], "port": ["80", "443"]},
                )
            ],
        )
        rules = build_singbox_route_rules([group], current_outbound_tag="vps")
        self.assertEqual(rules[0]["domain"], ["a.com", "b.com"])
        self.assertEqual(rules[0]["port"], ["80", "443"])

    def test_app_policy_is_inserted_at_start_of_app_tier(self) -> None:
        custom = RuleGroup(
            name="custom",
            rules=[Rule(id="custom", action="direct", conditions={"domain": ["custom.example"]})],
        )
        app_group = RuleGroup(
            name="app",
            rules=[Rule(id="app", action="direct", conditions={"process_name": ["legacy-app"]})],
        )
        imported = RuleGroup(
            name="imported-20260703",
            rules=[Rule(id="imported", action="block", conditions={"domain": ["imported.example"]})],
        )
        policy = AppPolicy(
            enabled=True,
            mode="blacklist",
            rules=[
                AppPolicyRule(
                    id="curl",
                    action="current",
                    match={"process_path": ["/usr/bin/curl"], "user_id": [1000]},
                )
            ],
        )

        rules = build_singbox_route_rules(
            [imported, app_group, custom],
            current_outbound_tag="vps",
            app_policy=policy,
        )

        self.assertEqual(rules[0]["domain"], ["custom.example"])
        self.assertEqual(
            rules[1],
            {
                "process_path": ["/usr/bin/curl"],
                "user_id": [1000],
                "action": "route",
                "outbound": "vps",
            },
        )
        self.assertEqual(rules[2]["process_name"], ["legacy-app"])
        self.assertEqual(rules[3]["domain"], ["imported.example"])

    def test_app_policy_whitelist_adds_catch_all_default(self) -> None:
        policy = AppPolicy(
            enabled=True,
            mode="whitelist",
            default_action="block",
            rules=[
                AppPolicyRule(
                    id="browser",
                    action="direct",
                    match={"process_path_regex": ["^/usr/lib/firefox/.+"]},
                )
            ],
        )

        rules = build_singbox_route_rules(
            [],
            current_outbound_tag="vps",
            app_policy=policy,
        )

        self.assertEqual(
            rules,
            [
                {
                    "process_path_regex": ["^/usr/lib/firefox/.+"],
                    "action": "route",
                    "outbound": "direct",
                },
                {"action": "reject"},
                {"action": "route", "outbound": "vps"},
            ],
        )

    def test_disabled_app_policy_does_not_change_rules(self) -> None:
        policy = AppPolicy(
            enabled=False,
            mode="blacklist",
            default_action="block",
            rules=[
                AppPolicyRule(
                    id="blocked",
                    action="block",
                    match={"process_name": ["curl"]},
                )
            ],
        )

        rules = build_singbox_route_rules(
            [],
            current_outbound_tag="vps",
            app_policy=policy,
        )

        self.assertEqual(rules, [{"action": "route", "outbound": "vps"}])


if __name__ == "__main__":
    unittest.main()
