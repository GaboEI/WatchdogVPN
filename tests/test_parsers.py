from __future__ import annotations

import base64
import json
import unittest

from parsers import ParseError, detect_scheme, parse_singbox_json, parse_uri, parse_wg_config
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

    def test_parse_vmess(self) -> None:
        payload = base64.urlsafe_b64encode(
            json.dumps(
                {
                    "v": "2",
                    "ps": "demo",
                    "add": "vmess.example.com",
                    "port": "443",
                    "id": "uuid-1234",
                }
            ).encode("utf-8")
        ).decode("utf-8")
        profile = parse_uri(f"vmess://{payload}")
        self.assertEqual(profile.protocol, ProtocolType.VMESS)
        self.assertEqual(profile.name, "demo")
        self.assertEqual(profile.config["host"], "vmess.example.com")
        self.assertEqual(profile.config["port"], 443)
        self.assertEqual(profile.config["uuid"], "uuid-1234")

    def test_parse_trojan(self) -> None:
        profile = parse_uri("trojan://secret@example.com:443?security=tls")
        self.assertEqual(profile.protocol, ProtocolType.TROJAN)
        self.assertEqual(profile.config["host"], "example.com")
        self.assertEqual(profile.config["password"], "secret")

    def test_parse_hysteria2_alias(self) -> None:
        profile = parse_uri("hy2://password@example.com:443?sni=example.com")
        self.assertEqual(profile.protocol, ProtocolType.HYSTERIA2)
        self.assertEqual(profile.config["host"], "example.com")
        self.assertEqual(profile.config["password"], "password")

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

    def test_parse_wireguard_config(self) -> None:
        profile = parse_wg_config(
            """
            [Interface]
            PrivateKey = private-key
            Address = 10.0.0.2/32
            DNS = 1.1.1.1

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


if __name__ == "__main__":
    unittest.main()
