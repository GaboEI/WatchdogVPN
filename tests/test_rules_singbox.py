from __future__ import annotations

import unittest

from rules.models import Rule, RuleGroup
from rules.singbox import build_singbox_route_rules


class BuildSingboxRouteRulesTests(unittest.TestCase):
    def test_empty_groups_yields_only_final_rule(self) -> None:
        rules = build_singbox_route_rules([], current_outbound_tag="vps")
        self.assertEqual(rules, [{"outbound": "vps"}])

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
        self.assertEqual(rules[0], {"process_name": ["steam"], "outbound": "direct"})

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
        self.assertEqual(rules, [{"outbound": "vps"}])

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
        self.assertEqual(rules[0], {"domain": ["a.com"], "outbound": "direct"})

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
        self.assertEqual(rules, [{"outbound": "direct"}])

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


if __name__ == "__main__":
    unittest.main()
