from __future__ import annotations

import unittest

from dns.models import (
    DNSChannel,
    DNSChannelName,
    DNSMode,
    DNSPolicy,
    DNSRule,
    DNSRuleAction,
    Resolver,
    StaticIPEntry,
)
from dns.singbox import (
    DNS_HIJACK_INBOUND_TAGS,
    FAKEIP_SERVER_TAG,
    STATIC_IP_SERVER_TAG,
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
            {"outbound": "vless-demo", "server": FAKEIP_SERVER_TAG},
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
        self.assertEqual(servers[FAKEIP_SERVER_TAG]["type"], "fakeip")
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

    def test_adds_fakeip_server_for_proxy_resolution_channel(self) -> None:
        policy = DNSPolicy(
            channels={
                DNSChannelName.PROXY: DNSChannel(
                    name=DNSChannelName.PROXY,
                    resolvers=[Resolver(uri="https://1.1.1.1/dns-query")],
                ),
                DNSChannelName.FINAL: DNSChannel(
                    name=DNSChannelName.FINAL,
                    resolvers=[Resolver(uri="udp://9.9.9.9")],
                ),
            },
            fakeip_inet4_range="198.18.0.0/15",
            fakeip_inet6_range="fc00::/18",
        )

        result = build_singbox_dns_config(policy, proxy_outbound_tag="vless-demo")

        self.assertIsNotNone(result)
        assert result is not None
        servers = {server["tag"]: server for server in result.config["servers"]}
        self.assertEqual(servers[FAKEIP_SERVER_TAG], {
            "type": "fakeip",
            "tag": FAKEIP_SERVER_TAG,
            "inet4_range": "198.18.0.0/15",
            "inet6_range": "fc00::/18",
        })
        self.assertIn(
            {"outbound": "vless-demo", "server": FAKEIP_SERVER_TAG},
            result.config["rules"],
        )

    def test_skips_fakeip_when_proxy_resolution_uses_proxy_dns(self) -> None:
        policy = DNSPolicy(
            proxy_resolution_channel="proxy",
            channels={
                DNSChannelName.PROXY: DNSChannel(
                    name=DNSChannelName.PROXY,
                    resolvers=[Resolver(uri="https://1.1.1.1/dns-query")],
                ),
            },
        )

        result = build_singbox_dns_config(policy, proxy_outbound_tag="vless-demo")

        self.assertIsNotNone(result)
        assert result is not None
        servers = {server["tag"]: server for server in result.config["servers"]}
        self.assertNotIn(FAKEIP_SERVER_TAG, servers)
        self.assertEqual(result.config["rules"], [
            {"outbound": "vless-demo", "server": "watchdogvpn-proxy-1"},
        ])

    def test_adds_ecs_client_subnet_only_to_direct_rule_when_enabled(self) -> None:
        policy = DNSPolicy(
            ecs_direct_enabled=True,
            ecs_direct_subnet="203.0.113.0/24",
            channels={
                DNSChannelName.DIRECT: DNSChannel(
                    name=DNSChannelName.DIRECT,
                    resolvers=[Resolver(uri="udp://9.9.9.9")],
                ),
                DNSChannelName.PROXY: DNSChannel(
                    name=DNSChannelName.PROXY,
                    resolvers=[Resolver(uri="https://1.1.1.1/dns-query")],
                ),
                DNSChannelName.FINAL: DNSChannel(
                    name=DNSChannelName.FINAL,
                    resolvers=[Resolver(uri="tcp://8.8.8.8")],
                ),
            },
        )

        result = build_singbox_dns_config(policy, proxy_outbound_tag="vless-demo")

        self.assertIsNotNone(result)
        assert result is not None
        self.assertEqual(result.config["rules"], [
            {
                "outbound": "direct",
                "server": "watchdogvpn-direct-1",
                "client_subnet": "203.0.113.0/24",
            },
            {"outbound": "vless-demo", "server": FAKEIP_SERVER_TAG},
        ])
        self.assertNotIn("client_subnet", result.config)

    def test_does_not_add_ecs_client_subnet_when_disabled(self) -> None:
        policy = DNSPolicy(
            ecs_direct_subnet="203.0.113.0/24",
            channels={
                DNSChannelName.DIRECT: DNSChannel(
                    name=DNSChannelName.DIRECT,
                    resolvers=[Resolver(uri="udp://9.9.9.9")],
                ),
            },
        )

        result = build_singbox_dns_config(policy, proxy_outbound_tag="vless-demo")

        self.assertIsNotNone(result)
        assert result is not None
        self.assertEqual(result.config["rules"], [
            {"outbound": "direct", "server": "watchdogvpn-direct-1"},
        ])

    def test_static_ip_map_resolves_before_upstream_dns(self) -> None:
        policy = DNSPolicy(
            static_ip_enabled=True,
            static_ips=[
                StaticIPEntry(domain="Example.COM.", ip="203.0.113.10"),
                StaticIPEntry(domain="api.example.com", ip="2001:db8::10"),
                StaticIPEntry(
                    domain="disabled.example.com",
                    ip="203.0.113.20",
                    enabled=False,
                ),
            ],
            channels={
                DNSChannelName.DIRECT: DNSChannel(
                    name=DNSChannelName.DIRECT,
                    resolvers=[Resolver(uri="udp://9.9.9.9")],
                ),
                DNSChannelName.FINAL: DNSChannel(
                    name=DNSChannelName.FINAL,
                    resolvers=[Resolver(uri="tcp://8.8.8.8")],
                ),
            },
        )

        result = build_singbox_dns_config(policy, proxy_outbound_tag="vless-demo")

        self.assertIsNotNone(result)
        assert result is not None
        self.assertEqual(result.config["rules"][0], {
            "domain": ["example.com", "api.example.com"],
            "server": STATIC_IP_SERVER_TAG,
        })
        servers = {server["tag"]: server for server in result.config["servers"]}
        self.assertEqual(servers[STATIC_IP_SERVER_TAG], {
            "type": "hosts",
            "tag": STATIC_IP_SERVER_TAG,
            "predefined": {
                "example.com": "203.0.113.10",
                "api.example.com": "2001:db8::10",
            },
        })

    def test_static_ip_map_supports_multiple_ips_per_domain(self) -> None:
        policy = DNSPolicy(
            static_ip_enabled=True,
            static_ips=[
                StaticIPEntry(domain="example.com", ip="203.0.113.10"),
                StaticIPEntry(domain="example.com", ip="2001:db8::10"),
            ],
            channels={
                DNSChannelName.FINAL: DNSChannel(
                    name=DNSChannelName.FINAL,
                    resolvers=[Resolver(uri="tcp://8.8.8.8")],
                ),
            },
        )

        result = build_singbox_dns_config(policy, proxy_outbound_tag="vless-demo")

        self.assertIsNotNone(result)
        assert result is not None
        servers = {server["tag"]: server for server in result.config["servers"]}
        self.assertEqual(
            servers[STATIC_IP_SERVER_TAG]["predefined"]["example.com"],
            ["203.0.113.10", "2001:db8::10"],
        )

    def test_static_ip_map_is_not_emitted_when_disabled(self) -> None:
        policy = DNSPolicy(
            static_ip_enabled=False,
            static_ips=[StaticIPEntry(domain="example.com", ip="203.0.113.10")],
            channels={
                DNSChannelName.FINAL: DNSChannel(
                    name=DNSChannelName.FINAL,
                    resolvers=[Resolver(uri="tcp://8.8.8.8")],
                ),
            },
        )

        result = build_singbox_dns_config(policy, proxy_outbound_tag="vless-demo")

        self.assertIsNotNone(result)
        assert result is not None
        servers = {server["tag"]: server for server in result.config["servers"]}
        self.assertNotIn(STATIC_IP_SERVER_TAG, servers)
        self.assertFalse(
            any(
                rule.get("server") == STATIC_IP_SERVER_TAG
                for rule in result.config["rules"]
            )
        )

    def test_dns_diversion_rules_route_to_selected_channels_by_priority(self) -> None:
        policy = DNSPolicy(
            rules_enabled=True,
            rules=[
                DNSRule(
                    id="proxy-last",
                    pattern="suffix:proxy.example.com",
                    channel=DNSChannelName.PROXY,
                    priority=20,
                ),
                DNSRule(
                    id="direct-first",
                    pattern="domain:Direct.Example.COM.",
                    channel=DNSChannelName.DIRECT,
                    priority=10,
                ),
                DNSRule(
                    id="disabled",
                    pattern="keyword:disabled",
                    channel=DNSChannelName.FINAL,
                    enabled=False,
                    priority=5,
                ),
            ],
            channels={
                DNSChannelName.DIRECT: DNSChannel(
                    name=DNSChannelName.DIRECT,
                    resolvers=[Resolver(uri="udp://9.9.9.9")],
                ),
                DNSChannelName.PROXY: DNSChannel(
                    name=DNSChannelName.PROXY,
                    resolvers=[Resolver(uri="https://1.1.1.1/dns-query")],
                ),
                DNSChannelName.FINAL: DNSChannel(
                    name=DNSChannelName.FINAL,
                    resolvers=[Resolver(uri="tcp://8.8.8.8")],
                ),
            },
        )

        result = build_singbox_dns_config(policy, proxy_outbound_tag="vless-demo")

        self.assertIsNotNone(result)
        assert result is not None
        self.assertEqual(result.config["rules"][:2], [
            {
                "domain": ["direct.example.com"],
                "server": "watchdogvpn-direct-1",
            },
            {
                "domain_suffix": ["proxy.example.com"],
                "server": "watchdogvpn-proxy-1",
            },
        ])
        self.assertNotIn(
            {"domain_keyword": ["disabled"], "server": "watchdogvpn-final-1"},
            result.config["rules"],
        )

    def test_dns_diversion_rules_are_after_static_ip_and_before_base_rules(self) -> None:
        policy = DNSPolicy(
            static_ip_enabled=True,
            static_ips=[StaticIPEntry(domain="static.example.com", ip="203.0.113.10")],
            rules_enabled=True,
            rules=[
                DNSRule(
                    id="proxy",
                    pattern="keyword:proxy",
                    channel=DNSChannelName.PROXY,
                )
            ],
            channels={
                DNSChannelName.DIRECT: DNSChannel(
                    name=DNSChannelName.DIRECT,
                    resolvers=[Resolver(uri="udp://9.9.9.9")],
                ),
                DNSChannelName.PROXY: DNSChannel(
                    name=DNSChannelName.PROXY,
                    resolvers=[Resolver(uri="https://1.1.1.1/dns-query")],
                ),
            },
        )

        result = build_singbox_dns_config(policy, proxy_outbound_tag="vless-demo")

        self.assertIsNotNone(result)
        assert result is not None
        self.assertEqual(result.config["rules"][:4], [
            {
                "domain": ["static.example.com"],
                "server": STATIC_IP_SERVER_TAG,
            },
            {
                "domain_keyword": ["proxy"],
                "server": "watchdogvpn-proxy-1",
            },
            {"outbound": "direct", "server": "watchdogvpn-direct-1"},
            {"outbound": "vless-demo", "server": FAKEIP_SERVER_TAG},
        ])

    def test_dns_diversion_reject_rule_emits_reject_action(self) -> None:
        policy = DNSPolicy(
            rules_enabled=True,
            rules=[
                DNSRule(
                    id="reject-ads",
                    pattern="suffix:ads.example.com",
                    action=DNSRuleAction.REJECT,
                )
            ],
            channels={
                DNSChannelName.FINAL: DNSChannel(
                    name=DNSChannelName.FINAL,
                    resolvers=[Resolver(uri="tcp://8.8.8.8")],
                ),
            },
        )

        result = build_singbox_dns_config(policy, proxy_outbound_tag="vless-demo")

        self.assertIsNotNone(result)
        assert result is not None
        self.assertEqual(result.config["rules"][0], {
            "domain_suffix": ["ads.example.com"],
            "action": "reject",
        })

    def test_dns_diversion_rule_fails_when_selected_channel_has_no_server(self) -> None:
        policy = DNSPolicy(
            rules_enabled=True,
            rules=[
                DNSRule(
                    id="missing-channel",
                    pattern="domain:example.com",
                    channel=DNSChannelName.PROXY,
                )
            ],
            channels={
                DNSChannelName.FINAL: DNSChannel(
                    name=DNSChannelName.FINAL,
                    resolvers=[Resolver(uri="tcp://8.8.8.8")],
                ),
            },
        )

        with self.assertRaises(ValueError):
            build_singbox_dns_config(policy, proxy_outbound_tag="vless-demo")

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
