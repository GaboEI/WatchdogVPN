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
    _validate_domain_resolver_graph,
    build_dns_hijack_inbounds,
    build_dns_hijack_route,
    build_singbox_dns_config,
    build_tun_domain_preservation_route,
    fakeip_policy_ready,
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
                        Resolver(uri="tls://dns.quad9.net"),
                    ],
                ),
                DNSChannelName.FINAL: DNSChannel(
                    name=DNSChannelName.FINAL,
                    resolvers=[Resolver(uri="udp://9.9.9.9")],
                ),
            },
        )

        result = build_singbox_dns_config(
            policy, proxy_outbound_tag="vless-demo", allow_fakeip=True
        )

        self.assertIsNotNone(result)
        assert result is not None
        config = result.config
        self.assertEqual(config["final"], "watchdogvpn-final-1")
        self.assertEqual(config["rules"], [
            {"query_type": ["A", "AAAA"], "server": FAKEIP_SERVER_TAG},
        ])
        self.assertEqual(result.direct_domain_resolver, "watchdogvpn-direct-1")
        self.assertEqual(result.proxy_domain_resolver, FAKEIP_SERVER_TAG)
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

    def test_hostname_bootstrap_uses_an_independent_ip_bootstrap(self) -> None:
        policy = DNSPolicy(
            channels={
                DNSChannelName.BOOTSTRAP: DNSChannel(
                    name=DNSChannelName.BOOTSTRAP,
                    resolvers=[
                        Resolver(uri="https://bootstrap.example.test/dns-query"),
                        Resolver(uri="udp://1.1.1.1"),
                    ],
                ),
                DNSChannelName.PROXY: DNSChannel(
                    name=DNSChannelName.PROXY,
                    resolvers=[Resolver(uri="https://resolver.example.test/dns-query")],
                ),
            },
        )

        result = build_singbox_dns_config(policy, proxy_outbound_tag="vless-demo")

        self.assertIsNotNone(result)
        assert result is not None
        servers = {server["tag"]: server for server in result.config["servers"]}
        self.assertEqual(
            servers["watchdogvpn-bootstrap-1"]["domain_resolver"],
            "watchdogvpn-bootstrap-2",
        )
        self.assertNotIn("domain_resolver", servers["watchdogvpn-bootstrap-2"])
        self.assertEqual(
            servers["watchdogvpn-proxy-1"]["domain_resolver"],
            "watchdogvpn-bootstrap-2",
        )
        for tag, server in servers.items():
            self.assertNotEqual(server.get("domain_resolver"), tag)

    def test_ip_bootstrap_has_no_domain_resolver_and_resolves_hostname_servers(
        self,
    ) -> None:
        policy = DNSPolicy(
            channels={
                DNSChannelName.BOOTSTRAP: DNSChannel(
                    name=DNSChannelName.BOOTSTRAP,
                    resolvers=[Resolver(uri="udp://1.1.1.1")],
                ),
                DNSChannelName.FINAL: DNSChannel(
                    name=DNSChannelName.FINAL,
                    resolvers=[Resolver(uri="tls://resolver.example.test")],
                ),
            },
        )

        result = build_singbox_dns_config(policy, proxy_outbound_tag="vless-demo")

        self.assertIsNotNone(result)
        assert result is not None
        servers = {server["tag"]: server for server in result.config["servers"]}
        self.assertNotIn("domain_resolver", servers["watchdogvpn-bootstrap-1"])
        self.assertEqual(
            servers["watchdogvpn-final-1"]["domain_resolver"],
            "watchdogvpn-bootstrap-1",
        )

    def test_hostname_resolver_rejects_disabled_only_independent_bootstrap(
        self,
    ) -> None:
        policy = DNSPolicy(
            channels={
                DNSChannelName.BOOTSTRAP: DNSChannel(
                    name=DNSChannelName.BOOTSTRAP,
                    resolvers=[
                        Resolver(uri="https://bootstrap.example.test/dns-query"),
                        Resolver(uri="udp://1.1.1.1", enabled=False),
                    ],
                ),
                DNSChannelName.PROXY: DNSChannel(
                    name=DNSChannelName.PROXY,
                    resolvers=[Resolver(uri="https://resolver.example.test/dns-query")],
                ),
            },
        )

        with self.assertRaisesRegex(
            ValueError, "enabled bootstrap resolver using an IP address"
        ):
            build_singbox_dns_config(policy, proxy_outbound_tag="vless-demo")

    def test_domain_resolver_graph_rejects_self_and_multi_node_cycles(self) -> None:
        with self.assertRaisesRegex(ValueError, "alpha -> alpha"):
            _validate_domain_resolver_graph(
                [
                    {
                        "tag": "alpha",
                        "type": "https",
                        "domain_resolver": "alpha",
                    }
                ]
            )

        with self.assertRaisesRegex(ValueError, "alpha -> beta -> alpha"):
            _validate_domain_resolver_graph(
                [
                    {
                        "tag": "alpha",
                        "type": "https",
                        "domain_resolver": "beta",
                    },
                    {
                        "tag": "beta",
                        "type": "https",
                        "domain_resolver": "alpha",
                    },
                ]
            )

    def test_off_policy_returns_none(self) -> None:
        policy = DNSPolicy(mode=DNSMode.OFF)

        self.assertIsNone(build_singbox_dns_config(policy, proxy_outbound_tag="proxy"))

    def test_default_policy_resolves_real_hostnames_out_of_the_box(self) -> None:
        """Regression: a bare DNSPolicy() - what DNSPolicyStore.load() returns
        for a fresh install/profile that never ran `watchdog dns channel`/
        `resolver` by hand - used to have an empty channel map, so this
        function returned None and generate_singbox_config() never added a
        "dns" block. The kill switch's own nftables rules unconditionally
        DNAT port 53 to the companion's DNS listener regardless of DNS
        policy, so every hostname lookup silently timed out into a listener
        that was never started - while raw-IP traffic worked fine. Confirmed
        live 2026-07-16: real WireGuard handshake, real routed ping,
        zero working hostname lookups on a fresh install."""
        policy = DNSPolicy()

        result = build_singbox_dns_config(policy, proxy_outbound_tag="proxy")

        self.assertIsNotNone(result)
        self.assertTrue(result.config["servers"])

    def test_explicitly_empty_channels_still_returns_none(self) -> None:
        # The fix is a better default, not a floor: a caller that explicitly
        # configures zero resolvers still gets no DNS block, same as today.
        policy = DNSPolicy(channels={})

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

        result = build_singbox_dns_config(
            policy, proxy_outbound_tag="vless-demo", allow_fakeip=True
        )

        self.assertIsNotNone(result)
        assert result is not None
        servers = {server["tag"]: server for server in result.config["servers"]}
        self.assertEqual(servers[FAKEIP_SERVER_TAG], {
            "type": "fakeip",
            "tag": FAKEIP_SERVER_TAG,
            "inet4_range": "198.18.0.0/15",
            "inet6_range": "fc00::/18",
        })
        self.assertEqual(result.proxy_domain_resolver, FAKEIP_SERVER_TAG)

    def test_fakeip_server_omitted_when_caller_gate_disallows_it(self) -> None:
        # Regression: allow_fakeip is the driver-level gate (TUN active,
        # non-native transport) - a policy with FakeIP fully configured and
        # ready must still not get a fakeip server without it, e.g. for a
        # native-transport companion's own DNS config.
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
        )

        result = build_singbox_dns_config(
            policy, proxy_outbound_tag="vless-demo", allow_fakeip=False
        )

        self.assertIsNotNone(result)
        assert result is not None
        servers = {server["tag"]: server for server in result.config["servers"]}
        self.assertNotIn(FAKEIP_SERVER_TAG, servers)
        self.assertNotEqual(result.proxy_domain_resolver, FAKEIP_SERVER_TAG)

    def test_fakeip_policy_ready_requires_an_enabled_proxy_resolver(self) -> None:
        empty = DNSPolicy(
            channels={
                DNSChannelName.PROXY: DNSChannel(name=DNSChannelName.PROXY)
            }
        )
        disabled = DNSPolicy(
            channels={
                DNSChannelName.PROXY: DNSChannel(
                    name=DNSChannelName.PROXY,
                    resolvers=[Resolver(uri="udp://1.1.1.1", enabled=False)],
                )
            }
        )
        ready = DNSPolicy(
            channels={
                DNSChannelName.PROXY: DNSChannel(
                    name=DNSChannelName.PROXY,
                    resolvers=[Resolver(uri="udp://1.1.1.1")],
                )
            }
        )

        self.assertFalse(fakeip_policy_ready(empty))
        self.assertFalse(fakeip_policy_ready(disabled))
        self.assertTrue(fakeip_policy_ready(ready))

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
        self.assertIsNone(result.direct_domain_resolver)
        self.assertEqual(result.proxy_domain_resolver, "watchdogvpn-proxy-1")
        self.assertEqual(result.config["rules"], [])

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

        result = build_singbox_dns_config(
            policy, proxy_outbound_tag="vless-demo", allow_fakeip=True
        )

        self.assertIsNotNone(result)
        assert result is not None
        self.assertEqual(result.config["rules"], [
            {"query_type": ["A", "AAAA"], "server": FAKEIP_SERVER_TAG},
        ])
        self.assertEqual(result.direct_domain_resolver, {
            "server": "watchdogvpn-direct-1",
            "client_subnet": "203.0.113.0/24",
        })
        self.assertEqual(result.proxy_domain_resolver, FAKEIP_SERVER_TAG)
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
        self.assertEqual(result.config["rules"], [])
        self.assertEqual(result.direct_domain_resolver, "watchdogvpn-direct-1")
        self.assertIsNone(result.proxy_domain_resolver)

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

        result = build_singbox_dns_config(
            policy, proxy_outbound_tag="vless-demo", allow_fakeip=True
        )

        self.assertIsNotNone(result)
        assert result is not None
        self.assertEqual(result.config["rules"][:2], [
            {
                "domain": ["direct.example.com"],
                "server": "watchdogvpn-direct-1",
            },
            {
                "domain_suffix": ["proxy.example.com"],
                "server": FAKEIP_SERVER_TAG,
            },
        ])
        self.assertNotIn(
            {"domain_keyword": ["disabled"], "server": "watchdogvpn-final-1"},
            result.config["rules"],
        )

    def test_dns_diversion_proxy_rule_uses_proxy_resolver_when_fakeip_disabled(self) -> None:
        policy = DNSPolicy(
            proxy_resolution_channel="proxy",
            rules_enabled=True,
            rules=[
                DNSRule(
                    id="proxy-domain",
                    pattern="domain:proxy.example.com",
                    channel=DNSChannelName.PROXY,
                ),
            ],
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
        self.assertEqual(result.config["rules"], [
            {
                "domain": ["proxy.example.com"],
                "server": "watchdogvpn-proxy-1",
            }
        ])

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

        result = build_singbox_dns_config(
            policy, proxy_outbound_tag="vless-demo", allow_fakeip=True
        )

        self.assertIsNotNone(result)
        assert result is not None
        self.assertEqual(result.config["rules"], [
            {
                "domain": ["static.example.com"],
                "server": STATIC_IP_SERVER_TAG,
            },
            {
                "domain_keyword": ["proxy"],
                "server": FAKEIP_SERVER_TAG,
            },
            # FakeIP catch-all, always last: explicit exceptions above
            # (static IP map, user diversion rules) are checked first.
            {
                "query_type": ["A", "AAAA"],
                "server": FAKEIP_SERVER_TAG,
            },
        ])
        self.assertEqual(result.direct_domain_resolver, "watchdogvpn-direct-1")
        self.assertEqual(result.proxy_domain_resolver, FAKEIP_SERVER_TAG)

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

        # Regression: a TUN's auto_route/strict_route captures system DNS
        # queries addressed to the real LAN resolver via the tun inbound
        # itself, not via our loopback listeners — those need protocol
        # sniffing plus a destination-independent "protocol: dns" match to
        # be hijacked, or they silently fall through to the catch-all rule
        # and get forwarded to the VPN outbound as if bound for a real,
        # routable address (confirmed via live traffic reproduction with
        # sing-box debug logs, Task 12.5). The inbound-tag rule stays for
        # anything explicitly pointed at the loopback listeners.
        self.assertEqual(route, {
            "rules": [
                {"action": "sniff"},
                {"protocol": ["dns"], "action": "hijack-dns"},
                {
                    "inbound": list(DNS_HIJACK_INBOUND_TAGS),
                    "action": "hijack-dns",
                },
            ]
        })

    def test_dns_hijack_route_is_disabled_for_off_or_non_hijack_policy(self) -> None:
        self.assertIsNone(build_dns_hijack_route(DNSPolicy(mode=DNSMode.OFF)))
        self.assertIsNone(build_dns_hijack_route(DNSPolicy(tun_hijack=False)))


class TunDomainPreservationRouteTests(unittest.TestCase):
    """Live-verified 2026-07-16 in a disposable VM (both route-options and
    this FakeIP+resolve mechanism): a sing-box outbound receiving a raw IP
    destination reached some real relays' TCP layer fine but got no
    application response at all, while the same traffic carrying a domain
    name (as SOCKS naturally does) worked normally. This rule restores the
    domain for FakeIP-range TUN destinations before sniff/hijack-dns run."""

    def test_returns_the_resolve_rule_when_allowed_and_ready(self) -> None:
        policy = DNSPolicy(
            fakeip_inet4_range="198.18.0.0/15",
            fakeip_inet6_range="fc00::/18",
        )

        route = build_tun_domain_preservation_route(
            policy, tun_inbound_tag="watchdogvpn-tun-in", allow_fakeip=True
        )

        self.assertEqual(route, {
            "rules": [
                {
                    "action": "resolve",
                    "inbound": ["watchdogvpn-tun-in"],
                    "ip_cidr": ["198.18.0.0/15", "fc00::/18"],
                }
            ]
        })

    def test_none_when_caller_gate_disallows_it(self) -> None:
        # allow_fakeip=False is the driver-level gate (native transport or
        # no TUN) - must win even with a fully-ready, opted-in policy.
        policy = DNSPolicy()
        self.assertTrue(policy.tun_domain_preservation)
        self.assertTrue(fakeip_policy_ready(policy))

        route = build_tun_domain_preservation_route(
            policy, tun_inbound_tag="watchdogvpn-tun-in", allow_fakeip=False
        )

        self.assertIsNone(route)

    def test_none_when_policy_opts_out(self) -> None:
        policy = DNSPolicy(tun_domain_preservation=False)
        self.assertTrue(fakeip_policy_ready(policy))

        route = build_tun_domain_preservation_route(
            policy, tun_inbound_tag="watchdogvpn-tun-in", allow_fakeip=True
        )

        self.assertIsNone(route)

    def test_none_when_fakeip_not_ready(self) -> None:
        policy = DNSPolicy(
            channels={
                DNSChannelName.DIRECT: DNSChannel(
                    name=DNSChannelName.DIRECT,
                    resolvers=[Resolver(uri="udp://1.1.1.1")],
                ),
            }
        )
        self.assertFalse(fakeip_policy_ready(policy))

        route = build_tun_domain_preservation_route(
            policy, tun_inbound_tag="watchdogvpn-tun-in", allow_fakeip=True
        )

        self.assertIsNone(route)


if __name__ == "__main__":
    unittest.main()
