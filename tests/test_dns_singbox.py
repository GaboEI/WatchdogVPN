from __future__ import annotations

import unittest

from dns.models import DNSChannel, DNSChannelName, DNSMode, DNSPolicy, Resolver
from dns.singbox import build_singbox_dns_config


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


if __name__ == "__main__":
    unittest.main()
