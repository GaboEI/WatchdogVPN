from __future__ import annotations

import unittest

from app_policy.models import AppPolicy, AppPolicyRule
from diagnostics.route_dns import diagnose_route_dns
from dns.models import DNSChannel, DNSChannelName, DNSPolicy, DNSRule, Resolver
from rules.models import Rule, RuleGroup
from rules.rule_engine import TrafficInfo


class RouteDNSDiagnosticTests(unittest.TestCase):
    def test_direct_route_uses_direct_dns_channel(self) -> None:
        result = diagnose_route_dns(
            traffic=TrafficInfo(domain="example.com"),
            rule_groups=[
                RuleGroup(
                    name="custom",
                    rules=[
                        Rule(
                            id="example-direct",
                            action="direct",
                            conditions={"domain": ["example.com"]},
                        )
                    ],
                )
            ],
            dns_policy=DNSPolicy(
                channels={
                    DNSChannelName.DIRECT: DNSChannel(
                        name=DNSChannelName.DIRECT,
                        resolvers=[Resolver(uri="udp://1.1.1.1")],
                    )
                }
            ),
        )

        self.assertEqual(result.confidence.value, "definitive")
        self.assertEqual(result.route_action, "direct")
        self.assertEqual(result.dns_channel, "direct")
        self.assertEqual(result.dns_path, "direct")

    def test_app_policy_block_rejects_dns(self) -> None:
        result = diagnose_route_dns(
            traffic=TrafficInfo(domain="example.com", process_name="curl"),
            rule_groups=[],
            dns_policy=DNSPolicy(),
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
        self.assertIsNone(result.dns_channel)
        self.assertEqual(result.dns_path, "blocked")
        self.assertIn("app policy block", result.dns_reason)

    def test_dns_diversion_rule_overrides_route_based_channel(self) -> None:
        result = diagnose_route_dns(
            traffic=TrafficInfo(domain="secure.example"),
            rule_groups=[
                RuleGroup(
                    name="custom",
                    rules=[
                        Rule(
                            id="secure-direct",
                            action="direct",
                            conditions={"domain": ["secure.example"]},
                        )
                    ],
                )
            ],
            dns_policy=DNSPolicy(
                rules_enabled=True,
                rules=[
                    DNSRule(
                        id="secure-proxy-dns",
                        pattern="domain:secure.example",
                        channel=DNSChannelName.PROXY,
                    )
                ],
            ),
        )

        self.assertEqual(result.route_action, "direct")
        self.assertEqual(result.dns_channel, "proxy")
        self.assertIn("secure-proxy-dns", result.dns_reason)

    def test_selected_channel_without_resolver_is_reported_unavailable(self) -> None:
        result = diagnose_route_dns(
            traffic=TrafficInfo(domain="example.com"),
            rule_groups=[],
            dns_policy=DNSPolicy(),
        )

        self.assertEqual(result.dns_channel, "proxy")
        self.assertEqual(result.dns_path, "unavailable")
        self.assertIn("no configured resolver", result.dns_reason)

    def test_runtime_required_rules_do_not_claim_dns_channel(self) -> None:
        result = diagnose_route_dns(
            traffic=TrafficInfo(domain="example.com"),
            rule_groups=[
                RuleGroup(
                    name="custom",
                    rules=[
                        Rule(
                            id="remote",
                            action="block",
                            conditions={"ruleset_remote": ["https://rules.example/set.srs"]},
                        )
                    ],
                )
            ],
            dns_policy=DNSPolicy(),
        )

        self.assertEqual(result.confidence.value, "runtime-required")
        self.assertIsNone(result.dns_channel)
        self.assertEqual(result.dns_path, "unknown")
        self.assertIn("runtime-evaluated", result.dns_reason)

    def test_unevaluated_app_policy_matchers_make_confidence_partial(self) -> None:
        result = diagnose_route_dns(
            traffic=TrafficInfo(domain="example.com", process_name="curl"),
            rule_groups=[],
            dns_policy=DNSPolicy(),
            app_policy=AppPolicy(
                enabled=True,
                rules=[
                    AppPolicyRule(
                        id="user-policy",
                        action="direct",
                        match={"user": ["gabodev"]},
                    )
                ],
            ),
        )

        self.assertEqual(result.confidence.value, "partial")

    def test_unevaluated_dns_patterns_make_confidence_partial(self) -> None:
        result = diagnose_route_dns(
            traffic=TrafficInfo(domain="example.com"),
            rule_groups=[],
            dns_policy=DNSPolicy(
                rules_enabled=True,
                rules=[
                    DNSRule(
                        id="regex-dns",
                        pattern="regex:.*\\.example$",
                        channel=DNSChannelName.DIRECT,
                    )
                ],
            ),
        )

        self.assertEqual(result.confidence.value, "partial")


if __name__ == "__main__":
    unittest.main()
