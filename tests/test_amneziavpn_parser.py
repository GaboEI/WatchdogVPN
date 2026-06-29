from __future__ import annotations

import base64
import json
import struct
import unittest
import zlib

from parsers.amneziavpn_format import is_amneziavpn_format, parse_amneziavpn
from parsers.uri import ParseError
from models.profile import ProtocolType


def _encode_payload(data: dict) -> str:
    """Serializa un dict al formato vpn:// de AmneziaVPN."""
    raw = json.dumps(data).encode()
    compressed = zlib.compress(raw)
    header = struct.pack(">I", len(raw))
    b64 = base64.urlsafe_b64encode(header + compressed).decode().rstrip("=")
    return f"vpn://{b64}"


_CLOAK_CONF = {
    "BrowserSig": "chrome",
    "EncryptionMethod": "aes-gcm",
    "NumConn": 1,
    "ProxyMethod": "openvpn",
    "PublicKey": "fakePubKey==",
    "RemoteHost": "10.0.0.1",
    "RemotePort": "8443",
    "ServerName": "example.com",
    "StreamTimeout": 300,
    "Transport": "direct",
    "UID": "fakeUID==",
}

_OVPN_CONFIG = (
    "client\ndev tun\nproto tcp\nremote 127.0.0.1 1194\nnobind\n"
    "<ca>\n-----BEGIN CERTIFICATE-----\nfake\n-----END CERTIFICATE-----\n</ca>\n"
    "dhcp-option DNS $PRIMARY_DNS\ndhcp-option DNS $SECONDARY_DNS\n"
)

_MINIMAL_PAYLOAD = {
    "containers": [
        {
            "cloak": {
                "last_config": json.dumps(_CLOAK_CONF),
                "port": "8443",
                "subnet_address": "10.8.1.0",
                "transport_proto": "tcp",
            },
            "container": "amnezia-openvpn-cloak",
            "openvpn": {
                "last_config": json.dumps({
                    "clientId": "testclientid",
                    "config": _OVPN_CONFIG,
                }),
            },
        }
    ],
    "defaultContainer": "amnezia-openvpn-cloak",
    "description": "test-server",
    "dns1": "8.8.8.8",
    "dns2": "8.8.4.4",
    "hostName": "10.0.0.1",
    "nameOverriddenByUser": False,
}

_VALID_VPN = _encode_payload(_MINIMAL_PAYLOAD)


class IsAmneziaVpnFormatTests(unittest.TestCase):
    def test_detects_vpn_prefix(self) -> None:
        self.assertTrue(is_amneziavpn_format("vpn://somedata"))

    def test_rejects_empty(self) -> None:
        self.assertFalse(is_amneziavpn_format(""))

    def test_rejects_plain_ovpn(self) -> None:
        self.assertFalse(is_amneziavpn_format("client\ndev tun\nremote 1.2.3.4 1194"))

    def test_rejects_vless_uri(self) -> None:
        self.assertFalse(is_amneziavpn_format("vless://uuid@host:443"))


class ParseAmneziaVpnTests(unittest.TestCase):
    def test_rejects_non_vpn_prefix(self) -> None:
        with self.assertRaises(ParseError):
            parse_amneziavpn("not a vpn:// string")

    def test_rejects_invalid_base64(self) -> None:
        with self.assertRaises(ParseError):
            parse_amneziavpn("vpn://!!!invalid!!!")

    def test_parses_openvpn_cloak_container(self) -> None:
        profiles = parse_amneziavpn(_VALID_VPN)
        self.assertEqual(len(profiles), 1)
        p = profiles[0]
        self.assertEqual(p.protocol, ProtocolType.OPENVPN_CLOAK)

    def test_profile_has_raw_config(self) -> None:
        p = parse_amneziavpn(_VALID_VPN)[0]
        self.assertIn("remote 127.0.0.1 1194", p.config["raw_config"])

    def test_profile_has_cloak_config(self) -> None:
        p = parse_amneziavpn(_VALID_VPN)[0]
        ck = p.config["cloak_config"]
        self.assertEqual(ck["RemoteHost"], "10.0.0.1")
        self.assertEqual(ck["RemotePort"], "8443")
        self.assertEqual(ck["ServerName"], "example.com")
        self.assertEqual(ck["UID"], "fakeUID==")
        self.assertEqual(ck["PublicKey"], "fakePubKey==")

    def test_cloak_config_has_local_host_port(self) -> None:
        p = parse_amneziavpn(_VALID_VPN)[0]
        ck = p.config["cloak_config"]
        self.assertEqual(ck["LocalHost"], "127.0.0.1")
        self.assertEqual(ck["LocalPort"], "1194")

    def test_dns_placeholders_replaced(self) -> None:
        p = parse_amneziavpn(_VALID_VPN)[0]
        raw = p.config["raw_config"]
        self.assertNotIn("$PRIMARY_DNS", raw)
        self.assertNotIn("$SECONDARY_DNS", raw)
        self.assertIn("8.8.8.8", raw)
        self.assertIn("8.8.4.4", raw)

    def test_profile_name_uses_description(self) -> None:
        p = parse_amneziavpn(_VALID_VPN)[0]
        self.assertEqual(p.name, "test-server")

    def test_profile_host_stored(self) -> None:
        p = parse_amneziavpn(_VALID_VPN)[0]
        self.assertEqual(p.config["host"], "10.0.0.1")

    def test_profile_client_id_stored(self) -> None:
        p = parse_amneziavpn(_VALID_VPN)[0]
        self.assertEqual(p.config["client_id"], "testclientid")

    def test_wrapper_field(self) -> None:
        p = parse_amneziavpn(_VALID_VPN)[0]
        self.assertEqual(p.config["wrapper"], "cloak")

    def test_cloak_localport_derived_from_remote(self) -> None:
        payload = dict(_MINIMAL_PAYLOAD)
        ovpn_with_port_2000 = _OVPN_CONFIG.replace("127.0.0.1 1194", "127.0.0.1 2000")
        payload["containers"] = [dict(payload["containers"][0])]
        payload["containers"][0] = dict(payload["containers"][0])
        payload["containers"][0]["openvpn"] = {
            "last_config": json.dumps({
                "clientId": "other",
                "config": ovpn_with_port_2000,
            })
        }
        p = parse_amneziavpn(_encode_payload(payload))[0]
        self.assertEqual(p.config["cloak_config"]["LocalPort"], "2000")

    def test_unsupported_container_raises(self) -> None:
        payload = dict(_MINIMAL_PAYLOAD)
        payload["containers"] = [{"container": "amnezia-wireguard"}]
        with self.assertRaises(ParseError):
            parse_amneziavpn(_encode_payload(payload))

    def test_empty_containers_raises(self) -> None:
        payload = dict(_MINIMAL_PAYLOAD)
        payload["containers"] = []
        with self.assertRaises(ParseError):
            parse_amneziavpn(_encode_payload(payload))

    def test_existing_localport_not_overridden(self) -> None:
        cloak_with_port = dict(_CLOAK_CONF)
        cloak_with_port["LocalPort"] = "9999"
        cloak_with_port["LocalHost"] = "127.0.0.1"
        payload = dict(_MINIMAL_PAYLOAD)
        payload["containers"] = [dict(payload["containers"][0])]
        payload["containers"][0] = dict(payload["containers"][0])
        payload["containers"][0]["cloak"] = dict(payload["containers"][0]["cloak"])
        payload["containers"][0]["cloak"]["last_config"] = json.dumps(cloak_with_port)
        p = parse_amneziavpn(_encode_payload(payload))[0]
        self.assertEqual(p.config["cloak_config"]["LocalPort"], "9999")

    def test_real_vpn_file(self) -> None:
        try:
            with open("/home/gabodev/Escritorio/temporales/amnezia_config.vpn") as f:
                content = f.read().strip()
        except FileNotFoundError:
            self.skipTest("archivo .vpn real no disponible")
        profiles = parse_amneziavpn(content)
        self.assertEqual(len(profiles), 1)
        p = profiles[0]
        self.assertEqual(p.protocol, ProtocolType.OPENVPN_CLOAK)
        self.assertEqual(p.config["cloak_config"]["RemoteHost"], "138.124.58.47")
        self.assertEqual(p.config["cloak_config"]["RemotePort"], "8443")
        self.assertEqual(p.config["cloak_config"]["LocalPort"], "1194")
        self.assertIn("-----BEGIN CERTIFICATE-----", p.config["raw_config"])
        self.assertIn("-----BEGIN PRIVATE KEY-----", p.config["raw_config"])


if __name__ == "__main__":
    unittest.main()
