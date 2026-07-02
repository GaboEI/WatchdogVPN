from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from rules.models import Rule, RuleGroup
from rules.rule_engine import RuleEngine, RuleMatch, TrafficInfo, rule_matches
from rules.rule_store import RuleStore


class TrafficInfoTests(unittest.TestCase):
    def test_domain_is_normalized(self) -> None:
        traffic = TrafficInfo(domain="Example.COM.")
        self.assertEqual(traffic.domain, "example.com")

    def test_empty_domain_becomes_none(self) -> None:
        traffic = TrafficInfo(domain=".")
        self.assertIsNone(traffic.domain)


class RuleMatchesTests(unittest.TestCase):
    def test_domain_exact(self) -> None:
        rule = Rule(id="r1", action="block", conditions={"domain": ["example.com"]})
        self.assertTrue(rule_matches(rule, TrafficInfo(domain="example.com")))
        self.assertFalse(rule_matches(rule, TrafficInfo(domain="www.example.com")))

    def test_domain_suffix(self) -> None:
        rule = Rule(id="r1", action="block", conditions={"domain_suffix": [".example.com"]})
        self.assertTrue(rule_matches(rule, TrafficInfo(domain="ads.example.com")))
        self.assertTrue(rule_matches(rule, TrafficInfo(domain="example.com")))
        self.assertFalse(rule_matches(rule, TrafficInfo(domain="notexample.com")))

    def test_domain_keyword(self) -> None:
        rule = Rule(id="r1", action="block", conditions={"domain_keyword": ["adserver"]})
        self.assertTrue(rule_matches(rule, TrafficInfo(domain="x.adserver.net")))
        self.assertFalse(rule_matches(rule, TrafficInfo(domain="example.com")))

    def test_domain_regex(self) -> None:
        rule = Rule(id="r1", action="block", conditions={"domain_regex": [r"^ad\d+\.example\.com$"]})
        self.assertTrue(rule_matches(rule, TrafficInfo(domain="ad42.example.com")))
        self.assertFalse(rule_matches(rule, TrafficInfo(domain="ad.example.com")))

    def test_domain_regex_invalid_pattern_never_matches(self) -> None:
        rule = Rule(id="r1", action="block", conditions={"domain_regex": ["("]})
        self.assertFalse(rule_matches(rule, TrafficInfo(domain="example.com")))

    def test_ip_cidr(self) -> None:
        rule = Rule(id="r1", action="block", conditions={"ip_cidr": ["10.0.0.0/8"]})
        self.assertTrue(rule_matches(rule, TrafficInfo(ip="10.1.2.3")))
        self.assertFalse(rule_matches(rule, TrafficInfo(ip="192.168.1.1")))

    def test_ip_cidr_ipv6(self) -> None:
        rule = Rule(id="r1", action="block", conditions={"ip_cidr": ["2001:db8::/32"]})
        self.assertTrue(rule_matches(rule, TrafficInfo(ip="2001:db8::1")))

    def test_ip_cidr_invalid_ip_never_matches(self) -> None:
        rule = Rule(id="r1", action="block", conditions={"ip_cidr": ["10.0.0.0/8"]})
        self.assertFalse(rule_matches(rule, TrafficInfo(ip="not-an-ip")))

    def test_port_exact(self) -> None:
        rule = Rule(id="r1", action="block", conditions={"port": ["443"]})
        self.assertTrue(rule_matches(rule, TrafficInfo(port=443)))
        self.assertFalse(rule_matches(rule, TrafficInfo(port=80)))

    def test_port_range_both_bounds(self) -> None:
        rule = Rule(id="r1", action="block", conditions={"port_range": ["20000:25000"]})
        self.assertTrue(rule_matches(rule, TrafficInfo(port=21000)))
        self.assertFalse(rule_matches(rule, TrafficInfo(port=19999)))

    def test_port_range_open_lower_bound(self) -> None:
        rule = Rule(id="r1", action="block", conditions={"port_range": [":3500"]})
        self.assertTrue(rule_matches(rule, TrafficInfo(port=1)))
        self.assertFalse(rule_matches(rule, TrafficInfo(port=3501)))

    def test_port_range_open_upper_bound(self) -> None:
        rule = Rule(id="r1", action="block", conditions={"port_range": ["4500:"]})
        self.assertTrue(rule_matches(rule, TrafficInfo(port=65000)))
        self.assertFalse(rule_matches(rule, TrafficInfo(port=4499)))

    def test_protocol_case_insensitive(self) -> None:
        rule = Rule(id="r1", action="block", conditions={"protocol": ["TLS"]})
        self.assertTrue(rule_matches(rule, TrafficInfo(protocol="tls")))

    def test_network(self) -> None:
        rule = Rule(id="r1", action="direct", conditions={"network": ["udp"]})
        self.assertTrue(rule_matches(rule, TrafficInfo(network="udp")))
        self.assertFalse(rule_matches(rule, TrafficInfo(network="tcp")))

    def test_process_name_case_sensitive(self) -> None:
        rule = Rule(id="r1", action="direct", conditions={"process_name": ["firefox"]})
        self.assertTrue(rule_matches(rule, TrafficInfo(process_name="firefox")))
        self.assertFalse(rule_matches(rule, TrafficInfo(process_name="Firefox")))

    def test_process_path(self) -> None:
        rule = Rule(id="r1", action="direct", conditions={"process_path": ["/usr/bin/curl"]})
        self.assertTrue(rule_matches(rule, TrafficInfo(process_path="/usr/bin/curl")))

    def test_missing_traffic_field_never_matches(self) -> None:
        rule = Rule(id="r1", action="block", conditions={"domain": ["example.com"]})
        self.assertFalse(rule_matches(rule, TrafficInfo(ip="10.0.0.1")))

    def test_multiple_values_in_one_condition_is_or(self) -> None:
        rule = Rule(
            id="r1", action="block", conditions={"domain": ["a.com", "b.com"]}
        )
        self.assertTrue(rule_matches(rule, TrafficInfo(domain="b.com")))
        self.assertFalse(rule_matches(rule, TrafficInfo(domain="c.com")))

    def test_multiple_condition_types_is_and(self) -> None:
        rule = Rule(
            id="r1",
            action="block",
            conditions={"domain_suffix": [".example.com"], "port": ["443"]},
        )
        self.assertTrue(rule_matches(rule, TrafficInfo(domain="a.example.com", port=443)))
        self.assertFalse(rule_matches(rule, TrafficInfo(domain="a.example.com", port=80)))
        self.assertFalse(rule_matches(rule, TrafficInfo(domain="other.com", port=443)))

    def test_ruleset_conditions_never_match_locally(self) -> None:
        rule = Rule(id="r1", action="block", conditions={"ruleset_builtin": ["geosite:cn"]})
        self.assertFalse(rule_matches(rule, TrafficInfo(domain="example.cn")))


class RuleEngineTests(unittest.TestCase):
    def test_rejects_invalid_final_policy(self) -> None:
        with self.assertRaises(ValueError):
            RuleEngine(final_policy="group:custom")

    def test_returns_final_policy_when_nothing_matches(self) -> None:
        engine = RuleEngine(final_policy="direct")
        result = engine.evaluate(TrafficInfo(domain="example.com"), groups=[])
        self.assertEqual(result, RuleMatch(action="direct", group_name=None, rule_id=None))

    def test_block_group_wins_over_custom(self) -> None:
        engine = RuleEngine()
        block = RuleGroup(
            name="block",
            rules=[Rule(id="b1", action="block", conditions={"domain": ["example.com"]})],
        )
        custom = RuleGroup(
            name="custom",
            rules=[Rule(id="c1", action="direct", conditions={"domain": ["example.com"]})],
        )
        result = engine.evaluate(TrafficInfo(domain="example.com"), groups=[custom, block])
        self.assertEqual(result.action, "block")
        self.assertEqual(result.group_name, "block")
        self.assertEqual(result.rule_id, "b1")

    def test_priority_order_block_custom_app_imported_recommended(self) -> None:
        engine = RuleEngine()
        groups = [
            RuleGroup(
                name="recommended",
                rules=[Rule(id="rec", action="auto_select", conditions={"domain": ["x.com"]})],
            ),
            RuleGroup(
                name="imported-20260702",
                rules=[Rule(id="imp", action="block", conditions={"domain": ["x.com"]})],
            ),
            RuleGroup(
                name="app",
                rules=[Rule(id="app", action="direct", conditions={"domain": ["x.com"]})],
            ),
            RuleGroup(
                name="custom",
                rules=[Rule(id="cus", action="current_profile", conditions={"domain": ["x.com"]})],
            ),
        ]
        # custom beats app/imported/recommended
        result = engine.evaluate(TrafficInfo(domain="x.com"), groups=groups)
        self.assertEqual(result.rule_id, "cus")

        # remove custom -> app should win next
        result = engine.evaluate(
            TrafficInfo(domain="x.com"), groups=[g for g in groups if g.name != "custom"]
        )
        self.assertEqual(result.rule_id, "app")

        # remove app too -> imported wins
        result = engine.evaluate(
            TrafficInfo(domain="x.com"),
            groups=[g for g in groups if g.name not in {"custom", "app"}],
        )
        self.assertEqual(result.rule_id, "imp")

        # only recommended left
        result = engine.evaluate(
            TrafficInfo(domain="x.com"),
            groups=[g for g in groups if g.name == "recommended"],
        )
        self.assertEqual(result.rule_id, "rec")

    def test_disabled_group_is_skipped(self) -> None:
        engine = RuleEngine()
        block = RuleGroup(
            name="block",
            enabled=False,
            rules=[Rule(id="b1", action="block", conditions={"domain": ["example.com"]})],
        )
        result = engine.evaluate(TrafficInfo(domain="example.com"), groups=[block])
        self.assertEqual(result.group_name, None)

    def test_disabled_rule_is_skipped(self) -> None:
        engine = RuleEngine()
        block = RuleGroup(
            name="block",
            rules=[
                Rule(
                    id="b1",
                    action="block",
                    conditions={"domain": ["example.com"]},
                    enabled=False,
                )
            ],
        )
        result = engine.evaluate(TrafficInfo(domain="example.com"), groups=[block])
        self.assertIsNone(result.group_name)

    def test_imported_family_sorted_by_priority_then_name(self) -> None:
        engine = RuleEngine()
        low_priority = RuleGroup(
            name="imported-a",
            priority=50,
            rules=[Rule(id="low", action="direct", conditions={"domain": ["x.com"]})],
        )
        high_priority = RuleGroup(
            name="imported-b",
            priority=10,
            rules=[Rule(id="high", action="block", conditions={"domain": ["x.com"]})],
        )
        result = engine.evaluate(
            TrafficInfo(domain="x.com"), groups=[low_priority, high_priority]
        )
        self.assertEqual(result.rule_id, "high")

    def test_first_matching_rule_wins_within_group(self) -> None:
        engine = RuleEngine()
        group = RuleGroup(
            name="custom",
            rules=[
                Rule(id="first", action="direct", conditions={"domain_keyword": ["example"]}),
                Rule(id="second", action="block", conditions={"domain": ["example.com"]}),
            ],
        )
        result = engine.evaluate(TrafficInfo(domain="example.com"), groups=[group])
        self.assertEqual(result.rule_id, "first")

    def test_group_action_is_returned_verbatim(self) -> None:
        engine = RuleEngine()
        group = RuleGroup(
            name="custom",
            rules=[Rule(id="c1", action="group:vless-pool", conditions={"domain": ["x.com"]})],
        )
        result = engine.evaluate(TrafficInfo(domain="x.com"), groups=[group])
        self.assertEqual(result.action, "group:vless-pool")

    def test_real_store_integration(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store = RuleStore(Path(tmp) / "rules")
            store.ensure_default_groups()
            store.add_group(
                RuleGroup(
                    name="app",
                    rules=[
                        Rule(
                            id="steam-direct",
                            action="direct",
                            conditions={"process_name": ["steam"]},
                        )
                    ],
                )
            )
            engine = RuleEngine()
            result = engine.evaluate(
                TrafficInfo(process_name="steam"), groups=store.list_groups()
            )
            self.assertEqual(result.action, "direct")
            self.assertEqual(result.group_name, "app")


if __name__ == "__main__":
    unittest.main()
