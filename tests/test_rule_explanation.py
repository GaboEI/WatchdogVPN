from __future__ import annotations

import json
import unittest

from rules.explanation import (
    RuleExplainer,
    RuleExplanationConfidence,
    RuleExplanationPathResult,
    RuleExplanationSkipReason,
)
from rules.models import Rule, RuleGroup
from rules.rule_engine import TrafficInfo


class RuleExplainerTests(unittest.TestCase):
    def test_rejects_invalid_final_policy(self) -> None:
        with self.assertRaises(ValueError):
            RuleExplainer(final_policy="group:custom")

    def test_local_match_is_definitive(self) -> None:
        group = RuleGroup(
            name="block",
            rules=[
                Rule(
                    id="ads",
                    action="block",
                    conditions={"domain_suffix": [".ads.example"]},
                )
            ],
        )

        result = RuleExplainer().explain(
            TrafficInfo(domain="cdn.ads.example"),
            [group],
        )

        self.assertEqual(result.confidence, RuleExplanationConfidence.DEFINITIVE)
        self.assertIsNotNone(result.matched)
        self.assertEqual(result.matched.action, "block")
        self.assertEqual(result.matched.group_name, "block")
        self.assertEqual(result.matched.rule_id, "ads")
        self.assertEqual(result.priority_path[0].result, RuleExplanationPathResult.MATCHED)

    def test_no_local_match_returns_final_action_definitively(self) -> None:
        group = RuleGroup(
            name="custom",
            rules=[
                Rule(
                    id="direct-example",
                    action="direct",
                    conditions={"domain": ["example.com"]},
                )
            ],
        )

        result = RuleExplainer(final_policy="block").explain(
            TrafficInfo(domain="other.example"),
            [group],
        )

        self.assertEqual(result.confidence, RuleExplanationConfidence.DEFINITIVE)
        self.assertIsNotNone(result.matched)
        self.assertEqual(result.matched.source, "final")
        self.assertEqual(result.matched.action, "block")
        self.assertEqual(result.priority_path[0].result, RuleExplanationPathResult.NO_MATCH)

    def test_missing_input_records_skipped_condition_and_partial_confidence(self) -> None:
        group = RuleGroup(
            name="custom",
            rules=[
                Rule(
                    id="https-only",
                    action="direct",
                    conditions={"domain": ["example.com"], "port": ["443"]},
                )
            ],
        )

        result = RuleExplainer().explain(TrafficInfo(domain="example.com"), [group])

        self.assertEqual(result.confidence, RuleExplanationConfidence.PARTIAL)
        self.assertEqual(result.matched.source, "final")
        self.assertEqual(result.skipped_conditions[0].condition, "port")
        self.assertEqual(
            result.skipped_conditions[0].reason,
            RuleExplanationSkipReason.MISSING_INPUT,
        )
        self.assertEqual(result.priority_path[0].result, RuleExplanationPathResult.SKIPPED)

    def test_remote_or_builtin_ruleset_requires_runtime_confidence(self) -> None:
        group = RuleGroup(
            name="custom",
            rules=[
                Rule(
                    id="geo",
                    action="block",
                    conditions={"ruleset_builtin": ["geosite:category-ads"]},
                ),
                Rule(
                    id="local",
                    action="direct",
                    conditions={"domain": ["example.com"]},
                ),
            ],
        )

        result = RuleExplainer().explain(TrafficInfo(domain="example.com"), [group])

        self.assertEqual(result.confidence, RuleExplanationConfidence.RUNTIME_REQUIRED)
        self.assertEqual(result.matched.rule_id, "local")
        self.assertEqual(result.unevaluated_rule_sets[0].kind, "built-in")
        self.assertEqual(result.unevaluated_rule_sets[0].values, ["geosite:category-ads"])
        self.assertEqual(
            result.priority_path[0].result,
            RuleExplanationPathResult.RUNTIME_REQUIRED,
        )

    def test_remote_ruleset_is_not_relevant_when_local_and_condition_fails(self) -> None:
        group = RuleGroup(
            name="custom",
            rules=[
                Rule(
                    id="remote-and-domain",
                    action="block",
                    conditions={
                        "ruleset_remote": ["https://rules.example/set.srs"],
                        "domain": ["blocked.example"],
                    },
                )
            ],
        )

        result = RuleExplainer(final_policy="direct").explain(
            TrafficInfo(domain="allowed.example"),
            [group],
        )

        self.assertEqual(result.confidence, RuleExplanationConfidence.DEFINITIVE)
        self.assertEqual(result.matched.source, "final")
        self.assertEqual(result.matched.action, "direct")
        self.assertEqual(result.unevaluated_rule_sets, [])

    def test_implicit_and_conditions_report_missing_branch_as_partial(self) -> None:
        group = RuleGroup(
            name="custom",
            rules=[
                Rule(
                    id="domain-and-port",
                    action="block",
                    conditions={"domain": ["example.com"], "port": ["443"]},
                )
            ],
        )

        result = RuleExplainer().explain(TrafficInfo(domain="example.com"), [group])

        self.assertEqual(result.confidence, RuleExplanationConfidence.PARTIAL)
        self.assertEqual(result.skipped_conditions[0].condition, "port")
        self.assertEqual(result.priority_path[0].result, RuleExplanationPathResult.SKIPPED)

    def test_empty_input_is_unknown_when_no_runtime_rule_sets_are_relevant(self) -> None:
        group = RuleGroup(
            name="custom",
            rules=[
                Rule(
                    id="needs-domain",
                    action="direct",
                    conditions={"domain": ["example.com"]},
                )
            ],
        )

        result = RuleExplainer().explain(TrafficInfo(), [group])

        self.assertEqual(result.confidence, RuleExplanationConfidence.UNKNOWN)
        self.assertEqual(result.matched.source, "final")
        self.assertEqual(result.skipped_conditions[0].reason.value, "missing-input")

    def test_to_dict_is_stable_and_json_serializable(self) -> None:
        group = RuleGroup(
            name="custom",
            rules=[
                Rule(
                    id="remote",
                    action="block",
                    conditions={"ruleset_remote": ["https://rules.example/set.srs"]},
                ),
                Rule(
                    id="local",
                    action="direct",
                    conditions={"domain": ["example.com"], "port": ["443"]},
                ),
            ],
        )

        result = RuleExplainer().explain(TrafficInfo(domain="example.com"), [group])
        data = result.to_dict()

        self.assertEqual(
            list(data.keys()),
            [
                "input_traffic",
                "matched",
                "priority_path",
                "skipped_conditions",
                "unevaluated_rule_sets",
                "confidence",
            ],
        )
        self.assertEqual(data["confidence"], "runtime-required")
        self.assertEqual(data["input_traffic"]["domain"], "example.com")
        self.assertEqual(data["input_traffic"]["port"], None)
        self.assertEqual(data["matched"]["source"], "final")
        self.assertEqual(data["unevaluated_rule_sets"][0]["kind"], "remote")
        json.dumps(data, sort_keys=True)


if __name__ == "__main__":
    unittest.main()
