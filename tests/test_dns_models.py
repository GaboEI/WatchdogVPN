from __future__ import annotations

import unittest

from dns.models import (
    DEFAULT_FAKEIP_INET4_RANGE,
    DEFAULT_FAKEIP_INET6_RANGE,
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
            ecs_direct_subnet="203.0.113.0/24",
            fakeip_inet4_range="198.18.0.0/15",
            fakeip_inet6_range="fc00::/18",
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

    def test_dns_policy_has_default_fakeip_ranges(self) -> None:
        policy = DNSPolicy()

        self.assertEqual(policy.fakeip_inet4_range, DEFAULT_FAKEIP_INET4_RANGE)
        self.assertEqual(policy.fakeip_inet6_range, DEFAULT_FAKEIP_INET6_RANGE)
        self.assertEqual(policy.proxy_resolution_channel, "fakeip")
        self.assertFalse(policy.ecs_direct_enabled)
        self.assertIsNone(policy.ecs_direct_subnet)

    def test_dns_policy_rejects_invalid_proxy_resolution_channel(self) -> None:
        with self.assertRaises(ValueError):
            DNSPolicy(proxy_resolution_channel="ecs")

    def test_dns_policy_rejects_invalid_fakeip_ranges(self) -> None:
        with self.assertRaises(ValueError):
            DNSPolicy(fakeip_inet4_range="fc00::/18")
        with self.assertRaises(ValueError):
            DNSPolicy(fakeip_inet6_range="198.18.0.0/15")

    def test_dns_policy_requires_subnet_when_ecs_is_enabled(self) -> None:
        with self.assertRaises(ValueError):
            DNSPolicy(ecs_direct_enabled=True)

    def test_dns_policy_rejects_invalid_ecs_subnet(self) -> None:
        with self.assertRaises(ValueError):
            DNSPolicy(ecs_direct_subnet="not-a-subnet")


if __name__ == "__main__":
    unittest.main()
