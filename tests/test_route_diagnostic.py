from __future__ import annotations

import unittest

from app_policy.models import AppPolicy, AppPolicyRule
from diagnostics.routing import diagnose_route
from rules.models import Rule, RuleGroup
from rules.rule_engine import TrafficInfo
from rules.ruleset_trust import RuleSetStatus, RuleSetTrustPolicy, RuleSetTrustRegistry


SHA256_A = "a" * 64


class RouteDiagnosticTests(unittest.TestCase):
    def test_domain_match_reports_rule_and_route_action(self) -> None:
        result = diagnose_route(
            traffic=TrafficInfo(domain="cdn.ads.example"),
            rule_groups=[
                RuleGroup(
                    name="block",
                    rules=[
                        Rule(
                            id="ads",
                            action="block",
                            conditions={"domain_suffix": [".ads.example"]},
                        )
                    ],
                )
            ],
        )

        data = result.to_dict()
        self.assertEqual(data["confidence"], "definitive")
        self.assertEqual(data["route_action"], "block")
        self.assertEqual(data["route_action_status"], "applies")
        self.assertEqual(data["route_source"]["group_name"], "block")
        self.assertEqual(data["route_source"]["rule_id"], "ads")
        self.assertFalse(data["runtime_observation"])

    def test_ip_match_reports_rule_action(self) -> None:
        result = diagnose_route(
            traffic=TrafficInfo(ip="203.0.113.42"),
            rule_groups=[
                RuleGroup(
                    name="custom",
                    rules=[
                        Rule(
                            id="direct-net",
                            action="direct",
                            conditions={"ip_cidr": ["203.0.113.0/24"]},
                        )
                    ],
                )
            ],
        )

        self.assertEqual(result.route_action, "direct")
        self.assertEqual(result.route_source["rule_id"], "direct-net")

    def test_no_rule_match_reports_default_route_action(self) -> None:
        result = diagnose_route(
            traffic=TrafficInfo(domain="other.example"),
            rule_groups=[
                RuleGroup(
                    name="custom",
                    rules=[
                        Rule(
                            id="only-example",
                            action="direct",
                            conditions={"domain": ["example.com"]},
                        )
                    ],
                )
            ],
            routing_state={"default_route_action": "block"},
        )

        self.assertEqual(result.route_action, "block")
        self.assertEqual(result.route_source["source"], "final")
        self.assertTrue(result.no_rule_match)

    def test_global_policy_ignores_rules_and_uses_default_route_action(self) -> None:
        result = diagnose_route(
            traffic=TrafficInfo(domain="example.com"),
            rule_groups=[
                RuleGroup(
                    name="custom",
                    rules=[
                        Rule(
                            id="would-block-under-rule-policy",
                            action="block",
                            conditions={"domain": ["example.com"]},
                        )
                    ],
                )
            ],
            routing_state={
                "routing_policy": "global",
                "default_route_action": "direct",
            },
        )

        self.assertEqual(result.confidence.value, "definitive")
        self.assertEqual(result.route_action, "direct")
        self.assertEqual(result.rule_evaluation, "ignored-by-global-policy")
        self.assertIsNone(result.rule_explanation)

    def test_process_app_policy_can_override_route_source(self) -> None:
        result = diagnose_route(
            traffic=TrafficInfo(domain="example.com", process_name="curl"),
            rule_groups=[],
            app_policy=AppPolicy(
                enabled=True,
                rules=[
                    AppPolicyRule(
                        id="curl-block",
                        action="block",
                        match={"process_name": ["curl"]},
                    )
                ],
            ),
        )

        self.assertEqual(result.route_action, "block")
        self.assertEqual(result.route_source["source"], "app-policy")

    def test_missing_ruleset_policy_is_reported(self) -> None:
        result = diagnose_route(
            traffic=TrafficInfo(domain="example.com"),
            rule_groups=[
                RuleGroup(
                    name="custom",
                    rules=[
                        Rule(
                            id="remote",
                            action="block",
                            conditions={"ruleset_remote": ["missing-policy"]},
                        )
                    ],
                )
            ],
            trust_registry=RuleSetTrustRegistry(),
        )

        self.assertEqual(result.confidence.value, "runtime-required")
        self.assertIsNotNone(result.rule_explanation)
        rule_set = result.rule_explanation.unevaluated_rule_sets[0]
        self.assertEqual(rule_set.state, "not-evaluated")
        self.assertIsNone(rule_set.failure_behavior)

    def test_stale_ruleset_policy_is_reported(self) -> None:
        policy = RuleSetTrustPolicy(
            id="builtin-example",
            kind="built-in",
            source="/tmp/builtin.json",
            critical=False,
        )
        registry = RuleSetTrustRegistry(
            policies={policy.id: policy},
            statuses={
                policy.id: RuleSetStatus(
                    id=policy.id,
                    state="stale",
                    error="using stale cache within policy window",
                )
            },
        )

        result = diagnose_route(
            traffic=TrafficInfo(domain="example.com"),
            rule_groups=[
                RuleGroup(
                    name="custom",
                    rules=[
                        Rule(
                            id="builtin",
                            action="block",
                            conditions={"ruleset_builtin": [policy.id]},
                        )
                    ],
                )
            ],
            trust_registry=registry,
        )

        self.assertIsNotNone(result.rule_explanation)
        rule_set = result.rule_explanation.unevaluated_rule_sets[0]
        self.assertEqual(rule_set.state, "stale")
        self.assertEqual(rule_set.failure_behavior, "warn-and-skip")

    def test_failed_critical_ruleset_policy_is_reported(self) -> None:
        policy = RuleSetTrustPolicy(
            id="remote-sensitive",
            kind="remote",
            source="https://rules.example/sensitive.srs",
            expected_sha256=SHA256_A,
            critical=True,
        )
        registry = RuleSetTrustRegistry(
            policies={policy.id: policy},
            statuses={
                policy.id: RuleSetStatus(
                    id=policy.id,
                    state="failed",
                    error="malformed source rule-set",
                )
            },
        )

        result = diagnose_route(
            traffic=TrafficInfo(domain="example.com"),
            rule_groups=[
                RuleGroup(
                    name="custom",
                    rules=[
                        Rule(
                            id="remote",
                            action="block",
                            conditions={"ruleset_remote": [policy.id]},
                        )
                    ],
                )
            ],
            trust_registry=registry,
        )

        self.assertIsNotNone(result.rule_explanation)
        rule_set = result.rule_explanation.unevaluated_rule_sets[0]
        self.assertEqual(rule_set.state, "failed")
        self.assertEqual(rule_set.failure_behavior, "fail-closed")
        self.assertEqual(rule_set.error, "malformed source rule-set")


if __name__ == "__main__":
    unittest.main()
