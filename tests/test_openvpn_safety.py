from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from config.profile_store import ProfileStore
from drivers.openvpn_cloak_driver import OpenVPNCloakDriver
from drivers.openvpn_driver import OpenVPNDriver
from drivers.openvpn_process import build_openvpn_command
from models.profile import Profile, ProfileSource, ProtocolType
from parsers.amneziavpn_format import _parse_openvpn_cloak
from parsers.openvpn_config import parse_openvpn_config
from parsers.openvpn_safety import (
    OpenVPNConfigValidationError,
    validate_openvpn_config,
    validate_openvpn_profile,
)
from parsers.uri import ParseError
from providers.manual_provider import ManualProvider


SAFE_CONFIG = """\
client
dev tun
proto udp
remote vpn.example.com 1194
auth SHA256
cipher AES-256-GCM
auth-user-pass
<ca>
TEST-CA
</ca>
<cert>
TEST-CERT
</cert>
<key>
TEST-KEY
</key>
<tls-auth>
TEST-TA
</tls-auth>
key-direction 1
"""


def _profile(protocol: ProtocolType, raw_config: str) -> Profile:
    config = {"raw_config": raw_config}
    if protocol is ProtocolType.OPENVPN_CLOAK:
        config["cloak_config"] = {"Transport": "direct", "ProxyMethod": "openvpn"}
    return Profile(
        id="test-openvpn",
        name="test-openvpn",
        protocol=protocol,
        config=config,
        source=ProfileSource.MANUAL,
    )


class OpenVPNConfigSafetyTests(unittest.TestCase):
    def test_accepts_real_corpus_shape_and_managed_inline_data(self) -> None:
        directives = validate_openvpn_config(SAFE_CONFIG)

        self.assertEqual(directives["remote"], [["vpn.example.com", "1194"]])
        self.assertEqual(directives["auth-user-pass"], [[]])

    def test_accepts_explicit_inline_file_references(self) -> None:
        config = """\
client
remote vpn.example.com 1194
ca [inline]
<ca>
TEST-CA
</ca>
tls-auth [inline] 1
<tls-auth>
TEST-TA
</tls-auth>
"""
        self.assertIn("ca", validate_openvpn_config(config))

    def test_rejects_executable_control_and_external_path_directives(self) -> None:
        cases = {
            "script-security": "script-security 2",
            "up": "up /bin/echo compromised",
            "down": "down /bin/echo compromised",
            "route-up": "route-up /bin/echo compromised",
            "route-pre-down": "route-pre-down /bin/echo compromised",
            "ipchange": "ipchange /bin/echo compromised",
            "tls-verify": "tls-verify /bin/echo compromised",
            "tls-crypt-v2-verify": "tls-crypt-v2-verify /bin/echo compromised",
            "auth-user-pass-verify": "auth-user-pass-verify /bin/echo via-file",
            "client-connect": "client-connect /bin/echo compromised",
            "client-disconnect": "client-disconnect /bin/echo compromised",
            "learn-address": "learn-address /bin/echo compromised",
            "plugin": "plugin /tmp/evil.so",
            "management": "management 127.0.0.1 7505",
            "config": "config /tmp/other.ovpn",
            "providers": "providers /tmp/evil-provider.so",
            "pkcs11-providers": "pkcs11-providers /tmp/evil-pkcs11.so",
            "engine": "engine dynamic",
            "iproute": "iproute /tmp/evil-route",
            "ca": "ca /etc/shadow",
            "auth-user-pass": "auth-user-pass /etc/shadow",
            "dns-updown": "dns-updown /bin/echo compromised",
            "socks-proxy": "socks-proxy proxy.example 1080 /etc/shadow",
        }
        for directive, line in cases.items():
            with self.subTest(directive=directive):
                with self.assertRaises(OpenVPNConfigValidationError) as raised:
                    validate_openvpn_config(f"client\nremote vpn.example.com 1194\n{line}\n")
                self.assertIn(directive, str(raised.exception))
                self.assertNotIn("compromised", str(raised.exception))
                self.assertNotIn("/etc/shadow", str(raised.exception))

    def test_rejects_quoted_and_double_dash_bypass_forms(self) -> None:
        for line in ('"up" "/bin/echo compromised"', "--plugin /tmp/evil.so"):
            with self.subTest(line=line):
                with self.assertRaises(OpenVPNConfigValidationError):
                    validate_openvpn_config(f"client\nremote vpn.example.com 1194\n{line}\n")

    def test_rejects_malformed_or_unknown_inline_blocks(self) -> None:
        cases = (
            "client\nremote vpn.example.com 1194\n<plugin>\nX\n</plugin>\n",
            "client\nremote vpn.example.com 1194\n<ca>\n</ca>\n",
            "client\nremote vpn.example.com 1194\n<ca>\nX\n</cert>\n",
            "client\nremote vpn.example.com 1194\n<ca>\nX\n",
        )
        for config in cases:
            with self.subTest(config=config):
                with self.assertRaises(OpenVPNConfigValidationError):
                    validate_openvpn_config(config)

    def test_parser_converts_safety_failure_without_exposing_payload(self) -> None:
        with self.assertRaises(ParseError) as raised:
            parse_openvpn_config("client\nremote vpn.example.com 1194\nup /bin/echo secret\n")
        self.assertIn("up", str(raised.exception))
        self.assertNotIn("secret", str(raised.exception))

    def test_store_rejects_unsafe_profile_but_driver_boundary_handles_legacy_data(self) -> None:
        unsafe = _profile(ProtocolType.OPENVPN, "client\nremote vpn.example.com 1194\nplugin /tmp/evil.so\n")
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaises(OpenVPNConfigValidationError):
                ProfileStore(Path(tmp) / "profiles.json").add(unsafe)

        with self.assertRaises(OpenVPNConfigValidationError):
            validate_openvpn_profile(unsafe)

    def test_drivers_reject_unsafe_profile_before_runtime_file_creation(self) -> None:
        unsafe_plain = _profile(ProtocolType.OPENVPN, "client\nremote vpn.example.com 1194\nup /bin/echo bad\n")
        plain = OpenVPNDriver()
        try:
            with self.assertRaises(OpenVPNConfigValidationError):
                plain.generate_openvpn_config(unsafe_plain)
            self.assertIsNone(plain._runtime_dir)
        finally:
            plain._cleanup_runtime()

        unsafe_cloak = _profile(ProtocolType.OPENVPN_CLOAK, "client\nremote vpn.example.com 1194\nplugin /tmp/evil.so\n")
        cloak = OpenVPNCloakDriver()
        try:
            with self.assertRaises(OpenVPNConfigValidationError):
                cloak._write_configs(unsafe_cloak)
            self.assertIsNone(cloak._runtime_dir)
        finally:
            cloak._cleanup_configs()

    def test_manual_watchdog_profile_import_rejects_unsafe_openvpn(self) -> None:
        unsafe = _profile(
            ProtocolType.OPENVPN,
            "client\nremote vpn.example.com 1194\nplugin /tmp/evil.so\n",
        )
        with tempfile.TemporaryDirectory() as tmp:
            provider = ManualProvider(
                ProfileStore(Path(tmp) / "profiles.json"),
                rotation_prompt=lambda _profile: False,
            )
            with self.assertRaises(ParseError) as raised:
                provider.from_text(json.dumps(unsafe.to_dict()))
            self.assertIn("plugin", str(raised.exception))
            self.assertNotIn("/tmp/evil.so", str(raised.exception))
            self.assertEqual(provider.profile_store.list(), [])

    def test_amneziavpn_openvpn_cloak_import_rejects_unsafe_openvpn(self) -> None:
        container = {
            "openvpn": {
                "last_config": '{"config":"client\\nremote 127.0.0.1 1194\\nup /bin/echo compromised\\n"}',
            },
            "cloak": {"last_config": "{}"},
        }
        with self.assertRaises(ParseError) as raised:
            _parse_openvpn_cloak(container, "vpn.example.com", "1.1.1.1", "1.0.0.1", "")
        self.assertIn("up", str(raised.exception))
        self.assertNotIn("compromised", str(raised.exception))


class OpenVPNProcessIsolationTests(unittest.TestCase):
    @patch("drivers.openvpn_process.shutil.which", return_value="/usr/bin/setpriv")
    def test_command_drops_all_but_network_capabilities(self, _which) -> None:
        command = build_openvpn_command("/usr/sbin/openvpn", Path("/run/watchdogvpn/openvpn.conf"))

        self.assertEqual(
            command,
            [
                "/usr/bin/setpriv",
                "--nnp",
                "--inh-caps=-all,+net_admin,+net_raw",
                "--ambient-caps=-all,+net_admin,+net_raw",
                "--",
                "/usr/sbin/openvpn",
                "--config",
                "/run/watchdogvpn/openvpn.conf",
            ],
        )

    @patch("drivers.openvpn_process.shutil.which", return_value=None)
    def test_missing_setpriv_fails_closed(self, _which) -> None:
        with self.assertRaisesRegex(RuntimeError, "setpriv is required"):
            build_openvpn_command("/usr/sbin/openvpn", Path("/run/watchdogvpn/openvpn.conf"))
