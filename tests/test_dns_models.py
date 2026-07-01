from __future__ import annotations

import unittest

from dns.models import (
    DNSChannel,
    DNSChannelName,
    DNSMode,
    DNSPolicy,
    DNSRule,
    Resolver,
    StaticIPEntry,
)


class DNSModelTests(unittest.TestCase):
    def test_dns_policy_round_trip(self) -> None:
        policy = DNSPolicy(
            mode=DNSMode.ADVANCED,
            channels={
                DNSChannelName.DIRECT: DNSChannel(
                    name=DNSChannelName.DIRECT,
                    resolvers=[Resolver(uri="local"), Resolver(uri="dhcp://auto")],
                ),
                DNSChannelName.PROXY: DNSChannel(
                    name=DNSChannelName.PROXY,
                    resolvers=[Resolver(uri="https://1.1.1.1/dns-query", label="Cloudflare")],
                ),
            },
            static_ips=[StaticIPEntry(domain="Example.COM.", ip="203.0.113.10")],
            rules=[
                DNSRule(
                    id="rule1",
                    pattern="domain:example.com",
                    channel=DNSChannelName.PROXY,
                    priority=10,
                )
            ],
            test_domain="GSTATIC.COM.",
            ttl="12h",
            static_ip_enabled=True,
            rules_enabled=True,
            ecs_direct_enabled=True,
        )

        restored = DNSPolicy.from_dict(policy.to_dict())

        self.assertEqual(restored, policy)
        self.assertEqual(restored.test_domain, "gstatic.com")
        self.assertEqual(restored.static_ips[0].domain, "example.com")

    def test_dns_channel_rejects_more_than_four_resolvers(self) -> None:
        with self.assertRaises(ValueError):
            DNSChannel(
                name=DNSChannelName.FINAL,
                resolvers=[
                    Resolver(uri="udp://1.1.1.1"),
                    Resolver(uri="udp://8.8.8.8"),
                    Resolver(uri="udp://9.9.9.9"),
                    Resolver(uri="udp://208.67.222.222"),
                    Resolver(uri="udp://94.140.14.14"),
                ],
            )

    def test_resolver_rejects_empty_uri(self) -> None:
        with self.assertRaises(ValueError):
            Resolver(uri=" ")

    def test_resolver_rejects_invalid_uri(self) -> None:
        with self.assertRaises(ValueError):
            Resolver(uri="udp://dns.example.com")

    def test_dns_rule_requires_channel_for_use_channel_action(self) -> None:
        with self.assertRaises(ValueError):
            DNSRule(id="missing-channel", pattern="domain:example.com")

    def test_dns_policy_rejects_channel_key_mismatch(self) -> None:
        with self.assertRaises(ValueError):
            DNSPolicy(
                channels={
                    DNSChannelName.DIRECT: DNSChannel(
                        name=DNSChannelName.PROXY,
                        resolvers=[Resolver(uri="local")],
                    )
                }
            )


if __name__ == "__main__":
    unittest.main()
