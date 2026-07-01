from __future__ import annotations

import unittest

from dns.models import DNSChannel, DNSChannelName, DNSMode, DNSPolicy, Resolver
from dns.singbox import (
    DNS_HIJACK_INBOUND_TAGS,
    build_dns_hijack_inbounds,
    build_dns_hijack_route,
    build_singbox_dns_config,
)


class SingBoxDNSConfigTests(unittest.TestCase):
    def test_builds_channel_servers_rules_and_final(self) -> None:
        policy = DNSPolicy(
            mode=DNSMode.ADVANCED,
            channels={
                DNSChannelName.BOOTSTRAP: DNSChannel(
                    name=DNSChannelName.BOOTSTRAP,
                    resolvers=[Resolver(uri="udp://1.1.1.1")],
                ),
                DNSChannelName.DIRECT: DNSChannel(
                    name=DNSChannelName.DIRECT,
                    resolvers=[Resolver(uri="local"), Resolver(uri="dhcp://auto")],
                ),
                DNSChannelName.PROXY: DNSChannel(
                    name=DNSChannelName.PROXY,
                    resolvers=[
                        Resolver(uri="https://1.1.1.1/dns-query"),
                        Resolver(uri="tls://dns.adguard-dns.com"),
                    ],
                ),
                DNSChannelName.FINAL: DNSChannel(
                    name=DNSChannelName.FINAL,
                    resolvers=[Resolver(uri="udp://9.9.9.9")],
                ),
            },
        )

        result = build_singbox_dns_config(policy, proxy_outbound_tag="vless-demo")

        self.assertIsNotNone(result)
        assert result is not None
        config = result.config
        self.assertEqual(config["final"], "watchdogvpn-final-1")
        self.assertEqual(config["rules"], [
            {"outbound": "direct", "server": "watchdogvpn-direct-1"},
            {"outbound": "vless-demo", "server": "watchdogvpn-proxy-1"},
        ])
        self.assertEqual(result.channel_servers[DNSChannelName.DIRECT], (
            "watchdogvpn-direct-1",
            "watchdogvpn-direct-2",
        ))
        servers = {server["tag"]: server for server in config["servers"]}
        self.assertEqual(servers["watchdogvpn-direct-1"]["type"], "local")
        self.assertEqual(servers["watchdogvpn-direct-2"]["type"], "dhcp")
        self.assertEqual(servers["watchdogvpn-proxy-1"]["type"], "https")
        self.assertEqual(servers["watchdogvpn-proxy-1"]["detour"], "vless-demo")
        self.assertEqual(servers["watchdogvpn-proxy-1"]["path"], "/dns-query")
        self.assertEqual(servers["watchdogvpn-proxy-2"]["type"], "tls")
        self.assertEqual(servers["watchdogvpn-proxy-2"]["server_port"], 853)
        self.assertEqual(
            servers["watchdogvpn-proxy-2"]["domain_resolver"],
            "watchdogvpn-bootstrap-1",
        )
        self.assertEqual(servers["watchdogvpn-final-1"]["type"], "udp")

    def test_off_policy_returns_none(self) -> None:
        policy = DNSPolicy(mode=DNSMode.OFF)

        self.assertIsNone(build_singbox_dns_config(policy, proxy_outbound_tag="proxy"))

    def test_disabled_resolvers_are_ignored(self) -> None:
        policy = DNSPolicy(
            channels={
                DNSChannelName.FINAL: DNSChannel(
                    name=DNSChannelName.FINAL,
                    resolvers=[
                        Resolver(uri="udp://1.1.1.1", enabled=False),
                        Resolver(uri="tcp://8.8.8.8"),
                    ],
                )
            }
        )

        result = build_singbox_dns_config(policy, proxy_outbound_tag="proxy")

        self.assertIsNotNone(result)
        assert result is not None
        self.assertEqual(len(result.config["servers"]), 1)
        self.assertEqual(result.config["servers"][0]["type"], "tcp")
        self.assertEqual(result.config["servers"][0]["server"], "8.8.8.8")

    def test_builds_dns_hijack_inbounds_when_enabled(self) -> None:
        inbounds = build_dns_hijack_inbounds(DNSPolicy(tun_hijack=True))

        self.assertEqual(
            [inbound["tag"] for inbound in inbounds],
            list(DNS_HIJACK_INBOUND_TAGS),
        )
        self.assertEqual([inbound["network"] for inbound in inbounds], ["udp", "tcp"])
        for inbound in inbounds:
            self.assertEqual(inbound["type"], "direct")
            self.assertEqual(inbound["listen"], "127.0.0.1")
            self.assertEqual(inbound["listen_port"], 53)
            self.assertEqual(inbound["override_port"], 53)

    def test_dns_hijack_inbounds_are_disabled_for_off_or_non_hijack_policy(self) -> None:
        self.assertEqual(build_dns_hijack_inbounds(DNSPolicy(mode=DNSMode.OFF)), [])
        self.assertEqual(build_dns_hijack_inbounds(DNSPolicy(tun_hijack=False)), [])

    def test_builds_dns_hijack_route_when_enabled(self) -> None:
        route = build_dns_hijack_route(DNSPolicy(tun_hijack=True))

        self.assertEqual(route, {
            "rules": [
                {
                    "inbound": list(DNS_HIJACK_INBOUND_TAGS),
                    "action": "hijack-dns",
                }
            ]
        })

    def test_dns_hijack_route_is_disabled_for_off_or_non_hijack_policy(self) -> None:
        self.assertIsNone(build_dns_hijack_route(DNSPolicy(mode=DNSMode.OFF)))
        self.assertIsNone(build_dns_hijack_route(DNSPolicy(tun_hijack=False)))


if __name__ == "__main__":
    unittest.main()
