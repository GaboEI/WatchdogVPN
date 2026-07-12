from __future__ import annotations

import base64
import json
import unittest
from unittest.mock import patch
from urllib.request import Request

from parsers import (
    ParseError,
    detect_scheme,
    fetch_and_parse,
    fetch_subscription,
    parse_clash_yaml,
    parse_openvpn_config,
    parse_singbox_json,
    parse_uri,
    parse_wg_config,
)
from parsers.subscription import _parse_subscription_userinfo
from models.profile import ProtocolType


class UriParserTests(unittest.TestCase):
    def test_detect_scheme(self) -> None:
        self.assertEqual(detect_scheme("vless://uuid@example.com:443?encryption=none"), "vless")
        with self.assertRaises(ParseError):
            detect_scheme("mailto:test@example.com")

    def test_parse_vless(self) -> None:
        profile = parse_uri("vless://uuid@example.com:443?encryption=none&security=reality")
        self.assertEqual(profile.protocol, ProtocolType.VLESS)
        self.assertEqual(profile.config["host"], "example.com")
        self.assertEqual(profile.config["port"], 443)
        self.assertEqual(profile.config["uuid"], "uuid")

    def test_invalid_uri_port_raises_parse_error(self) -> None:
        with self.assertRaisesRegex(ParseError, "invalid port"):
            parse_uri("vless://uuid@example.com:notaport?encryption=none")
        with self.assertRaisesRegex(ParseError, "invalid port"):
            parse_uri("vless://uuid@example.com:99999?encryption=none")

    def test_remote_uri_rejects_loopback_endpoint(self) -> None:
        with self.assertRaisesRegex(ParseError, "local endpoint"):
            parse_uri("vless://uuid@127.0.0.1:443?encryption=none")
        with self.assertRaisesRegex(ParseError, "local endpoint"):
            parse_uri("trojan://secret@localhost:443?security=tls")

    def test_remote_uri_allows_explicit_local_testing(self) -> None:
        profile = parse_uri("vless://uuid@127.0.0.1:443?encryption=none&allow_local=true")
        self.assertEqual(profile.protocol, ProtocolType.VLESS)
        self.assertEqual(profile.config["host"], "127.0.0.1")

    def test_parse_uri_decodes_fragment_name(self) -> None:
        profile = parse_uri("vless://uuid@example.com:443?encryption=none#Austria%2C%20Vienna%20%5B3GBIT%5D")
        self.assertEqual(profile.name, "Austria, Vienna [3GBIT]")
        self.assertEqual(profile.config["fragment"], "Austria, Vienna [3GBIT]")

    def test_parse_vmess(self) -> None:
        payload = base64.urlsafe_b64encode(
            json.dumps(
                {
                    "v": "2",
                    "ps": "demo",
                    "add": "vmess.example.com",
                    "port": "443",
                    "id": "uuid-1234",
                    "aid": "0",
                    "scy": "auto",
                    "net": "ws",
                    "tls": "tls",
                    "sni": "sni.example.com",
                    "host": "cdn.example.com",
                    "path": "/ws",
                    "fp": "firefox",
                }
            ).encode("utf-8")
        ).decode("utf-8")
        profile = parse_uri(f"vmess://{payload}")
        self.assertEqual(profile.protocol, ProtocolType.VMESS)
        self.assertEqual(profile.name, "demo")
        self.assertEqual(profile.config["host"], "vmess.example.com")
        self.assertEqual(profile.config["port"], 443)
        self.assertEqual(profile.config["uuid"], "uuid-1234")
        self.assertEqual(profile.config["alter_id"], "0")
        self.assertEqual(profile.config["security"], "auto")
        self.assertEqual(profile.config["network"], "ws")
        self.assertEqual(profile.config["tls"], "tls")
        self.assertEqual(profile.config["sni"], "sni.example.com")
        self.assertEqual(profile.config["transport_host"], "cdn.example.com")
        self.assertEqual(profile.config["path"], "/ws")
        self.assertEqual(profile.config["fingerprint"], "firefox")

    def test_parse_trojan(self) -> None:
        profile = parse_uri("trojan://secret@example.com:443?security=tls")
        self.assertEqual(profile.protocol, ProtocolType.TROJAN)
        self.assertEqual(profile.config["host"], "example.com")
        self.assertEqual(profile.config["password"], "secret")

    def test_parse_trojan_path_authority_variant(self) -> None:
        profile = parse_uri("trojan:///secret@example.com:443?security=tls#demo")
        self.assertEqual(profile.protocol, ProtocolType.TROJAN)
        self.assertEqual(profile.name, "demo")
        self.assertEqual(profile.config["host"], "example.com")
        self.assertEqual(profile.config["port"], 443)
        self.assertEqual(profile.config["password"], "/secret")

    def test_parse_trojan_unescaped_slash_in_password(self) -> None:
        profile = parse_uri("trojan://sec/ret/value@example.com:443?security=tls#demo")
        self.assertEqual(profile.protocol, ProtocolType.TROJAN)
        self.assertEqual(profile.name, "demo")
        self.assertEqual(profile.config["host"], "example.com")
        self.assertEqual(profile.config["port"], 443)
        self.assertEqual(profile.config["password"], "sec/ret/value")

    def test_parse_hysteria2_alias(self) -> None:
        profile = parse_uri("hy2://password@example.com:443?sni=example.com")
        self.assertEqual(profile.protocol, ProtocolType.HYSTERIA2)
        self.assertEqual(profile.config["host"], "example.com")
        self.assertEqual(profile.config["password"], "password")

    def test_parse_hysteria2_user_password_keeps_full_auth(self) -> None:
        profile = parse_uri("hy2://user:secret@example.com:443?sni=example.com")
        self.assertEqual(profile.protocol, ProtocolType.HYSTERIA2)
        self.assertEqual(profile.config["password"], "user:secret")

    def test_parse_shadowsocks_base64(self) -> None:
        payload = base64.urlsafe_b64encode(b"chacha20-ietf-poly1305:secret@example.com:8388").decode("utf-8")
        profile = parse_uri(f"ss://{payload}#ss-demo")
        self.assertEqual(profile.protocol, ProtocolType.SHADOWSOCKS)
        self.assertEqual(profile.name, "ss-demo")
        self.assertEqual(profile.config["method"], "chacha20-ietf-poly1305")
        self.assertEqual(profile.config["host"], "example.com")
        self.assertEqual(profile.config["port"], 8388)

    def test_parse_tuic(self) -> None:
        profile = parse_uri("tuic://uuid:secret@example.com:443?sni=example.com")
        self.assertEqual(profile.protocol, ProtocolType.TUIC)
        self.assertEqual(profile.config["uuid"], "uuid")
        self.assertEqual(profile.config["password"], "secret")

    def test_parse_wireguard(self) -> None:
        profile = parse_uri("wg://publickey@example.com:51820?private_key=secret&allowed_ips=0.0.0.0/0")
        self.assertEqual(profile.protocol, ProtocolType.WIREGUARD)
        self.assertEqual(profile.config["public_key"], "publickey")
        self.assertEqual(profile.config["private_key"], "secret")
        self.assertEqual(profile.config["port"], 51820)

    def test_invalid_uri_raises(self) -> None:
        with self.assertRaises(ParseError):
            parse_uri("vless://example.com")
        with self.assertRaises(ParseError):
            parse_uri("vmess://not-base64")
        with self.assertRaises(ParseError):
            parse_uri("ss://badpayload")
        with self.assertRaises(ParseError):
            parse_uri("ftp://example.com")

    def test_parse_wireguard_config(self) -> None:
        profile = parse_wg_config(
            """
            [Interface]
            PrivateKey = private-key
            Address = 10.0.0.2/32
            DNS = 1.1.1.1
            MTU = 1420

            [Peer]
            PublicKey = public-key
            Endpoint = wg.example.com:51820
            AllowedIPs = 0.0.0.0/0, ::/0
            PersistentKeepalive = 25
            """
        )
        self.assertEqual(profile.protocol, ProtocolType.WIREGUARD)
        self.assertEqual(profile.config["private_key"], "private-key")
        self.assertEqual(profile.config["public_key"], "public-key")
        self.assertEqual(profile.config["endpoint"], "wg.example.com:51820")
        self.assertEqual(profile.config["allowed_ips"], "0.0.0.0/0, ::/0")
        self.assertEqual(profile.config["mtu"], "1420")
        self.assertEqual(profile.config["runtime_validation"]["private_key_reuse"], "checked_at_connect_time")

    def test_parse_amneziawg_config(self) -> None:
        profile = parse_wg_config(
            """
            [Interface]
            PrivateKey = private-key
            Address = 10.0.0.2/32
            Jc = 4
            Jmin = 10
            Jmax = 20

            [Peer]
            PublicKey = public-key
            Endpoint = awg.example.com:51820
            AllowedIPs = 0.0.0.0/0, ::/0
            """
        )
        self.assertEqual(profile.protocol, ProtocolType.AMNEZIAWG)
        self.assertEqual(profile.config["private_key"], "private-key")
        self.assertEqual(profile.config["public_key"], "public-key")
        self.assertEqual(profile.config["endpoint"], "awg.example.com:51820")

    def test_parse_wireguard_config_errors(self) -> None:
        with self.assertRaises(ParseError):
            parse_wg_config("[Interface]\nPrivateKey = x\n")
        with self.assertRaises(ParseError):
            parse_wg_config("[Peer]\nPublicKey = x\nEndpoint = y\n")
        with self.assertRaises(ParseError):
            parse_wg_config(
                """
                [Interface]
                PrivateKey = private-key

                [Peer]
                Endpoint = wg.example.com:51820
                """
            )


class SingboxJsonParserTests(unittest.TestCase):
    def test_parse_single_outbound_dict(self) -> None:
        profiles = parse_singbox_json(
            {
                "type": "vless",
                "tag": "primary",
                "server": "sb.example.com",
                "server_port": 443,
                "uuid": "uuid-1",
            }
        )
        self.assertEqual(len(profiles), 1)
        self.assertEqual(profiles[0].protocol, ProtocolType.VLESS)
        self.assertEqual(profiles[0].name, "primary")
        self.assertEqual(profiles[0].config["server"], "sb.example.com")
        self.assertEqual(profiles[0].config["server_port"], 443)

    def test_parse_multi_outbound_json(self) -> None:
        profiles = parse_singbox_json(
            json.dumps(
                {
                    "outbounds": [
                        {"type": "vmess", "tag": "vm1", "server": "vmess.example.com", "server_port": 443},
                        {"type": "trojan", "tag": "tr1", "server": "trojan.example.com", "server_port": 443},
                        {"type": "direct", "tag": "bypass"},
                    ]
                }
            )
        )
        self.assertEqual([profile.protocol for profile in profiles], [ProtocolType.VMESS, ProtocolType.TROJAN])
        self.assertEqual([profile.name for profile in profiles], ["vm1", "tr1"])

    def test_parse_singbox_json_errors(self) -> None:
        with self.assertRaises(ParseError):
            parse_singbox_json("not json")
        with self.assertRaises(ParseError):
            parse_singbox_json(json.dumps(["invalid", "shape"]))
        with self.assertRaisesRegex(ParseError, "no supported profiles"):
            parse_singbox_json(json.dumps({"outbounds": [{"type": "direct", "tag": "bypass"}]}))


class OpenVPNConfigParserTests(unittest.TestCase):
    def test_parse_openvpn_config(self) -> None:
        profile = parse_openvpn_config(
            """
            client
            dev tun
            proto udp
            remote vpn.example.com 1194
            auth-user-pass

            <ca>
            certificate body ignored by directive parser
            </ca>
            """
        )
        self.assertEqual(profile.protocol, ProtocolType.OPENVPN)
        self.assertEqual(profile.name, "openvpn-vpn.example.com-1194")
        self.assertEqual(profile.config["host"], "vpn.example.com")
        self.assertEqual(profile.config["port"], 1194)
        self.assertEqual(profile.config["proto"], "udp")
        self.assertEqual(profile.config["dev"], "tun")
        self.assertEqual(profile.config["compatibility_category"], "standard")
        self.assertIn("raw_config", profile.config)

    def test_parse_openvpn_config_errors(self) -> None:
        with self.assertRaises(ParseError):
            parse_openvpn_config("")
        with self.assertRaises(ParseError):
            parse_openvpn_config("client\ndev tun\n")


class ClashYamlParserTests(unittest.TestCase):
    def test_parse_clash_yaml(self) -> None:
        profiles = parse_clash_yaml(
            """
            proxies:
              - name: vless-1
                type: vless
                server: vless.example.com
                port: 443
                uuid: uuid-1
              - name: trojan-1
                type: trojan
                server: trojan.example.com
                port: 443
                password: secret
              - name: bypass
                type: direct
            """
        )
        self.assertEqual([profile.protocol for profile in profiles], [ProtocolType.VLESS, ProtocolType.TROJAN])
        self.assertEqual([profile.name for profile in profiles], ["vless-1", "trojan-1"])
        self.assertEqual(profiles[0].config["server"], "vless.example.com")
        self.assertEqual(profiles[1].config["password"], "secret")

    def test_parse_clash_yaml_errors(self) -> None:
        with self.assertRaises(ParseError):
            parse_clash_yaml("foo: bar")
        with self.assertRaises(ParseError):
            parse_clash_yaml("proxies:\n  name: bad")
        with self.assertRaisesRegex(ParseError, "no supported profiles"):
            parse_clash_yaml("proxies:\n  - name: bypass\n    type: direct\n")


class SubscriptionParserTests(unittest.TestCase):
    def test_fetch_and_parse_invalid_url_raises_parse_error(self) -> None:
        with self.assertRaisesRegex(ParseError, "invalid subscription URL"):
            fetch_and_parse("TU_URL_REAL_DEL_PROVIDER")

    @patch("parsers.subscription.urlopen")
    def test_fetch_uses_subscription_user_agent(self, urlopen_mock) -> None:
        urlopen_mock.return_value.__enter__.return_value.read.return_value = json.dumps(
            {
                "outbounds": [
                    {"type": "vless", "tag": "sb1", "server": "vless.example.com", "server_port": 443}
                ]
            }
        ).encode("utf-8")

        with patch.dict(
            "os.environ",
            {"WATCHDOGVPN_SUBSCRIPTION_USER_AGENT": "watchdog-test-agent"},
            clear=False,
        ):
            fetch_and_parse("https://example.com/sub")

        request = urlopen_mock.call_args.args[0]
        self.assertIsInstance(request, Request)
        self.assertEqual(request.get_header("User-agent"), "watchdog-test-agent")

    @patch("parsers.subscription.urlopen")
    def test_fetch_and_parse_base64_lines(self, urlopen_mock) -> None:
        payload = "\n".join(
            [
                "vless://uuid@example.com:443?encryption=none",
                "trojan://secret@example.com:443",
            ]
        ).encode("utf-8")
        encoded = base64.b64encode(payload).decode("utf-8")
        urlopen_mock.return_value.__enter__.return_value.read.return_value = encoded.encode("utf-8")

        profiles = fetch_and_parse("https://example.com/sub")

        self.assertEqual([profile.protocol for profile in profiles], [ProtocolType.VLESS, ProtocolType.TROJAN])
        self.assertEqual(profiles[0].config["host"], "example.com")
        self.assertEqual(profiles[1].config["password"], "secret")

    @patch("parsers.subscription.urlopen")
    def test_fetch_and_parse_json(self, urlopen_mock) -> None:
        urlopen_mock.return_value.__enter__.return_value.read.return_value = json.dumps(
            {
                "outbounds": [
                    {"type": "vless", "tag": "sb1", "server": "vless.example.com", "server_port": 443}
                ]
            }
        ).encode("utf-8")

        profiles = fetch_and_parse("https://example.com/sub")

        self.assertEqual(len(profiles), 1)
        self.assertEqual(profiles[0].name, "sb1")
        self.assertEqual(profiles[0].protocol, ProtocolType.VLESS)

    @patch("parsers.subscription.urlopen")
    def test_fetch_and_parse_yaml(self, urlopen_mock) -> None:
        urlopen_mock.return_value.__enter__.return_value.read.return_value = (
            """
            proxies:
              - name: clash1
                type: trojan
                server: clash.example.com
                port: 443
                password: secret
            """
        ).encode("utf-8")

        profiles = fetch_and_parse("https://example.com/sub")

        self.assertEqual(len(profiles), 1)
        self.assertEqual(profiles[0].name, "clash1")
        self.assertEqual(profiles[0].protocol, ProtocolType.TROJAN)

    @patch("parsers.subscription.urlopen")
    def test_fetch_and_parse_rejects_html_response(self, urlopen_mock) -> None:
        urlopen_mock.return_value.__enter__.return_value.read.return_value = (
            "<!doctype html><html><body>login required</body></html>"
        ).encode("utf-8")

        with self.assertRaisesRegex(ParseError, "looks like HTML"):
            fetch_and_parse("https://example.com/sub")

    @patch("parsers.subscription.urlopen")
    def test_fetch_and_parse_base64_without_supported_profiles(self, urlopen_mock) -> None:
        encoded = base64.b64encode(b"ftp://example.com\nnot-a-profile").decode("utf-8")
        urlopen_mock.return_value.__enter__.return_value.read.return_value = encoded.encode("utf-8")

        with self.assertRaisesRegex(ParseError, "no supported profiles"):
            fetch_and_parse("https://example.com/sub")

    @patch("parsers.subscription.urlopen")
    def test_fetch_and_parse_errors(self, urlopen_mock) -> None:
        from urllib.error import URLError

        urlopen_mock.side_effect = URLError("boom")
        with self.assertRaises(ParseError):
            fetch_and_parse("https://example.com/sub")

        urlopen_mock.side_effect = None
        urlopen_mock.return_value.__enter__.return_value.read.return_value = b""
        with self.assertRaises(ParseError):
            fetch_and_parse("https://example.com/sub")

        urlopen_mock.return_value.__enter__.return_value.read.return_value = b"@@@"
        with self.assertRaises(ParseError):
            fetch_and_parse("https://example.com/sub")


class SubscriptionUserinfoTests(unittest.TestCase):
    def test_parse_subscription_userinfo_computes_used_and_limit(self) -> None:
        metadata = _parse_subscription_userinfo(
            "upload=805306368; download=268435456; total=10737418240; expire=1893456000"
        )

        self.assertEqual(metadata["traffic_used"], "1.0 GB")
        self.assertEqual(metadata["traffic_limit"], "10.0 GB")
        self.assertEqual(metadata["expires_at"], "2030-01-01")

    def test_parse_subscription_userinfo_handles_missing_header(self) -> None:
        self.assertEqual(_parse_subscription_userinfo(None), {})
        self.assertEqual(_parse_subscription_userinfo(""), {})

    def test_parse_subscription_userinfo_ignores_malformed_pairs(self) -> None:
        metadata = _parse_subscription_userinfo("upload=notanumber; total=5000000000")

        self.assertNotIn("traffic_used", metadata)
        self.assertEqual(metadata["traffic_limit"], "4.7 GB")

    @patch("parsers.subscription.urlopen")
    def test_fetch_subscription_reads_userinfo_header(self, urlopen_mock) -> None:
        response = urlopen_mock.return_value.__enter__.return_value
        response.read.return_value = json.dumps(
            {
                "outbounds": [
                    {"type": "vless", "tag": "sb1", "server": "vless.example.com", "server_port": 443}
                ]
            }
        ).encode("utf-8")
        response.headers.items.return_value = [
            ("Subscription-Userinfo", "upload=100; download=100; total=1000; expire=1893456000"),
            ("Content-Type", "application/json"),
        ]

        result = fetch_subscription("https://example.com/sub")

        self.assertEqual(len(result.profiles), 1)
        self.assertEqual(result.metadata["traffic_used"], "200.0 B")
        self.assertEqual(result.metadata["traffic_limit"], "1000.0 B")
        self.assertEqual(result.metadata["expires_at"], "2030-01-01")

    @patch("parsers.subscription.urlopen")
    def test_fetch_subscription_without_header_reports_no_metadata(self, urlopen_mock) -> None:
        urlopen_mock.return_value.__enter__.return_value.read.return_value = json.dumps(
            {
                "outbounds": [
                    {"type": "vless", "tag": "sb1", "server": "vless.example.com", "server_port": 443}
                ]
            }
        ).encode("utf-8")

        result = fetch_subscription("https://example.com/sub")

        self.assertEqual(result.metadata, {})

    @patch("parsers.subscription.urlopen")
    def test_fetch_and_parse_is_unaffected_by_headers(self, urlopen_mock) -> None:
        # fetch_and_parse's return shape/behavior must stay list[Profile],
        # unchanged by the header-capturing refactor.
        response = urlopen_mock.return_value.__enter__.return_value
        response.read.return_value = json.dumps(
            {
                "outbounds": [
                    {"type": "vless", "tag": "sb1", "server": "vless.example.com", "server_port": 443}
                ]
            }
        ).encode("utf-8")
        response.headers.items.return_value = [
            ("Subscription-Userinfo", "upload=100; download=100; total=1000"),
        ]

        profiles = fetch_and_parse("https://example.com/sub")

        self.assertEqual(len(profiles), 1)
        self.assertEqual(profiles[0].protocol, ProtocolType.VLESS)


if __name__ == "__main__":
    unittest.main()
