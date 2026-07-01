from __future__ import annotations

import unittest

from dns.models import DNSChannel, DNSChannelName, DNSMode, Resolver
from dns.tester import (
    DEFAULT_TEST_DOMAIN,
    DNSTester,
    ResolverTestResult,
    default_auto_channel_candidates,
)


class FakeProbe:
    def __init__(self, latencies: dict[str, float], failures: set[str] | None = None):
        self.latencies = latencies
        self.failures = failures or set()
        self.calls: list[str] = []

    def __call__(
        self,
        resolver: Resolver,
        test_domain: str,
        timeout: float,
    ) -> ResolverTestResult:
        self.calls.append(resolver.uri)
        if resolver.uri in self.failures:
            return ResolverTestResult(
                resolver=resolver,
                ok=False,
                error="failed",
                test_domain=test_domain,
            )
        return ResolverTestResult(
            resolver=resolver,
            ok=True,
            latency_ms=self.latencies.get(resolver.uri, 100.0),
            test_domain=test_domain,
        )


class DNSTesterTests(unittest.TestCase):
    def test_rank_resolvers_orders_success_by_latency_before_failures(self) -> None:
        resolvers = [
            Resolver(uri="udp://1.1.1.1"),
            Resolver(uri="udp://8.8.8.8"),
            Resolver(uri="udp://9.9.9.9"),
        ]
        probe = FakeProbe(
            latencies={
                "udp://1.1.1.1": 20.0,
                "udp://8.8.8.8": 10.0,
            },
            failures={"udp://9.9.9.9"},
        )
        tester = DNSTester(probe=probe, max_workers=1)

        results = tester.rank_resolvers(resolvers, "Example.COM.")

        self.assertEqual([result.resolver.uri for result in results], [
            "udp://8.8.8.8",
            "udp://1.1.1.1",
            "udp://9.9.9.9",
        ])
        self.assertEqual(results[0].test_domain, "example.com")
        self.assertTrue(results[0].ok)
        self.assertFalse(results[-1].ok)

    def test_rank_resolvers_tests_at_most_four_enabled_resolvers(self) -> None:
        resolvers = [
            Resolver(uri="udp://1.1.1.1"),
            Resolver(uri="udp://8.8.8.8"),
            Resolver(uri="udp://9.9.9.9", enabled=False),
            Resolver(uri="tcp://1.1.1.1"),
            Resolver(uri="tcp://8.8.8.8"),
            Resolver(uri="tcp://9.9.9.9"),
        ]
        probe = FakeProbe(latencies={})
        tester = DNSTester(probe=probe, max_workers=1)

        results = tester.rank_resolvers(resolvers)

        self.assertEqual(len(results), 4)
        self.assertEqual(probe.calls, [
            "udp://1.1.1.1",
            "udp://8.8.8.8",
            "tcp://1.1.1.1",
            "tcp://8.8.8.8",
        ])

    def test_test_channel_selects_only_working_ranked_resolvers(self) -> None:
        channel = DNSChannel(
            name=DNSChannelName.PROXY,
            resolvers=[
                Resolver(uri="https://1.1.1.1/dns-query"),
                Resolver(uri="https://9.9.9.9/dns-query"),
            ],
        )
        probe = FakeProbe(
            latencies={"https://9.9.9.9/dns-query": 5.0},
            failures={"https://1.1.1.1/dns-query"},
        )
        tester = DNSTester(probe=probe)

        result = tester.test_channel(channel)

        self.assertEqual(result.channel, DNSChannelName.PROXY)
        self.assertEqual([resolver.uri for resolver in result.selected], [
            "https://9.9.9.9/dns-query"
        ])

    def test_recommend_auto_setup_builds_policy_from_successful_results(self) -> None:
        candidates = {
            DNSChannelName.DIRECT: (
                Resolver(uri="local"),
                Resolver(uri="dhcp://auto"),
            ),
            DNSChannelName.PROXY: (
                Resolver(uri="https://1.1.1.1/dns-query"),
                Resolver(uri="https://9.9.9.9/dns-query"),
            ),
        }
        probe = FakeProbe(
            latencies={
                "local": 1.0,
                "dhcp://auto": 2.0,
                "https://9.9.9.9/dns-query": 4.0,
            },
            failures={"https://1.1.1.1/dns-query"},
        )
        tester = DNSTester(probe=probe)

        recommendation = tester.recommend_auto_setup(candidates, DEFAULT_TEST_DOMAIN)

        self.assertEqual(recommendation.policy.mode, DNSMode.AUTO)
        self.assertEqual(
            [resolver.uri for resolver in recommendation.policy.channels[DNSChannelName.DIRECT].resolvers],
            ["local", "dhcp://auto"],
        )
        self.assertEqual(
            [resolver.uri for resolver in recommendation.policy.channels[DNSChannelName.PROXY].resolvers],
            ["https://9.9.9.9/dns-query"],
        )
        self.assertNotIn(DNSChannelName.FINAL, recommendation.policy.channels)

    def test_default_auto_candidates_cover_all_channels(self) -> None:
        candidates = default_auto_channel_candidates()

        self.assertEqual(set(candidates), set(DNSChannelName))
        for resolvers in candidates.values():
            self.assertLessEqual(len(resolvers), 4)
            self.assertTrue(resolvers)


if __name__ == "__main__":
    unittest.main()
