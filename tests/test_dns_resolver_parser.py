from __future__ import annotations

import unittest

from dns.presets import RESOLVER_PRESETS, get_resolver_preset
from dns.resolver_parser import (
    ResolverParseError,
    ResolverTransport,
    parse_resolver_uri,
)


class ResolverParserTests(unittest.TestCase):
    def test_parse_local_and_dhcp(self) -> None:
        local = parse_resolver_uri("local")
        dhcp = parse_resolver_uri("dhcp://auto")

        self.assertEqual(local.transport, ResolverTransport.LOCAL)
        self.assertTrue(local.is_local)
        self.assertEqual(dhcp.transport, ResolverTransport.DHCP)
        self.assertTrue(dhcp.is_local)

    def test_parse_udp_tcp_tls_and_https(self) -> None:
        udp = parse_resolver_uri("udp://1.1.1.1")
        tcp = parse_resolver_uri("tcp://8.8.8.8:53")
        tls = parse_resolver_uri("tls://dns.example.com:853")
        https = parse_resolver_uri("https://dns.example.com/dns-query")

        self.assertEqual(udp.transport, ResolverTransport.UDP)
        self.assertEqual(udp.host, "1.1.1.1")
        self.assertEqual(tcp.port, 53)
        self.assertEqual(tls.host, "dns.example.com")
        self.assertEqual(tls.port, 853)
        self.assertEqual(https.path, "/dns-query")

    def test_parse_ipv6_literals(self) -> None:
        udp = parse_resolver_uri("udp://[2400:3200::1]")
        tls = parse_resolver_uri("tls://[2606:4700:4700::1111]:853")
        https = parse_resolver_uri("https://[2606:4700:4700::1111]/dns-query")

        self.assertEqual(udp.host, "2400:3200::1")
        self.assertEqual(tls.port, 853)
        self.assertEqual(https.path, "/dns-query")

    def test_reject_invalid_resolver_forms(self) -> None:
        invalid = [
            "",
            "dns://1.1.1.1",
            "udp://dns.example.com",
            "tcp://1.1.1.1/path",
            "tls://bad_host_name",
            "https://dns.example.com",
            "https://dns.example.com/",
            "https://user:pass@dns.example.com/dns-query",
            "https://dns.example.com/dns-query?x=1",
            "udp://1.1.1.1:99999",
            "dhcp://manual",
        ]

        for uri in invalid:
            with self.subTest(uri=uri):
                with self.assertRaises(ResolverParseError):
                    parse_resolver_uri(uri)

    def test_presets_are_valid_and_adguard_is_ordinary_preset(self) -> None:
        preset_ids = {preset.id for preset in RESOLVER_PRESETS}

        self.assertIn("adguard-doh", preset_ids)
        self.assertIn("adguard-tls", preset_ids)
        for preset in RESOLVER_PRESETS:
            self.assertGreater(len(preset.resolvers), 0)
            for resolver in preset.resolvers:
                parse_resolver_uri(resolver.uri)

        adguard = get_resolver_preset("adguard-doh")
        self.assertIsNotNone(adguard)
        self.assertIn("public", adguard.tags if adguard else ())
        self.assertNotIn("service", adguard.tags if adguard else ())

    def test_missing_preset_returns_none(self) -> None:
        self.assertIsNone(get_resolver_preset("missing"))


if __name__ == "__main__":
    unittest.main()
