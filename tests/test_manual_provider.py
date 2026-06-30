from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from config.profile_store import ProfileStore
from models.profile import ProtocolType
from parsers.uri import ParseError
from providers.manual_provider import ManualProvider


class ManualProviderTests(unittest.TestCase):
    def _provider(self, path: Path, rotation: bool = False) -> ManualProvider:
        return ManualProvider(ProfileStore(path), rotation_prompt=lambda _profile: rotation)

    def test_from_uri_saves_profile_and_rotation_choice(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store_path = Path(tmp) / "profiles.json"
            provider = self._provider(store_path, rotation=True)

            profile = provider.from_uri("vless://uuid@example.com:443?encryption=none&security=reality")

            stored = ProfileStore(store_path).get(profile.id)
            self.assertIsNotNone(stored)
            self.assertEqual(profile.protocol, ProtocolType.VLESS)
            self.assertTrue(profile.in_rotation_pool)
            self.assertEqual(stored, profile)

    def test_from_text_parses_wireguard_config(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            provider = self._provider(Path(tmp) / "profiles.json")

            profile = provider.from_text(
                """
                [Interface]
                PrivateKey = private-key
                Address = 10.0.0.2/32

                [Peer]
                PublicKey = public-key
                Endpoint = wg.example.com:51820
                AllowedIPs = 0.0.0.0/0
                """
            )

            self.assertEqual(profile.protocol, ProtocolType.WIREGUARD)
            self.assertEqual(profile.config["endpoint"], "wg.example.com:51820")

    def test_from_text_parses_openvpn_config(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            provider = self._provider(Path(tmp) / "profiles.json")

            profile = provider.from_text(
                """
                client
                dev tun
                proto udp
                remote vpn.example.com 1194
                """
            )

            self.assertEqual(profile.protocol, ProtocolType.OPENVPN)
            self.assertEqual(profile.config["host"], "vpn.example.com")

    def test_from_text_saves_all_singbox_profiles_and_returns_first(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store_path = Path(tmp) / "profiles.json"
            provider = self._provider(store_path, rotation=True)

            profile = provider.from_text(
                json.dumps(
                    {
                        "outbounds": [
                            {
                                "type": "vless",
                                "tag": "vless-1",
                                "server": "vless.example.com",
                                "server_port": 443,
                            },
                            {
                                "type": "trojan",
                                "tag": "trojan-1",
                                "server": "trojan.example.com",
                                "server_port": 443,
                            },
                        ]
                    }
                )
            )

            stored = ProfileStore(store_path).list()
            self.assertEqual(profile.id, "vless-1")
            self.assertEqual([p.id for p in stored], ["vless-1", "trojan-1"])
            self.assertTrue(all(p.in_rotation_pool for p in stored))

    def test_from_text_saves_all_clash_profiles(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store_path = Path(tmp) / "profiles.json"
            provider = self._provider(store_path)

            provider.from_text(
                """
                proxies:
                  - name: ss-1
                    type: ss
                    server: ss.example.com
                    port: 8388
                    cipher: chacha20-ietf-poly1305
                    password: secret
                  - name: http-1
                    type: http
                    server: http.example.com
                    port: 8080
                """
            )

            stored = ProfileStore(store_path).list()
            self.assertEqual([p.protocol for p in stored], [ProtocolType.SHADOWSOCKS, ProtocolType.HTTP])
            self.assertEqual([p.id for p in stored], ["ss-1", "http-1"])

    def test_from_file_reads_and_saves_profile(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            input_path = Path(tmp) / "profile.txt"
            input_path.write_text("trojan://secret@example.com:443?security=tls#trojan-demo", encoding="utf-8")
            provider = self._provider(Path(tmp) / "profiles.json")

            profile = provider.from_file(str(input_path))

            self.assertEqual(profile.id, "trojan-demo")
            self.assertEqual(profile.protocol, ProtocolType.TROJAN)

    def test_from_clipboard_returns_none_when_clipboard_empty(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            provider = self._provider(Path(tmp) / "profiles.json")
            with patch.object(provider, "_read_clipboard_text", return_value=None):
                self.assertIsNone(provider.from_clipboard())

    def test_from_clipboard_imports_text_when_available(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            provider = self._provider(Path(tmp) / "profiles.json")
            with patch.object(
                provider,
                "_read_clipboard_text",
                return_value="hy2://password@example.com:443?sni=example.com#hy2-demo",
            ):
                profile = provider.from_clipboard()

            self.assertIsNotNone(profile)
            self.assertEqual(profile.protocol, ProtocolType.HYSTERIA2)

    def test_duplicate_ids_are_preserved_with_suffix(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store_path = Path(tmp) / "profiles.json"
            provider = self._provider(store_path)

            first = provider.from_uri("vless://uuid@example.com:443?encryption=none")
            second = provider.from_uri("vless://uuid@example.com:443?encryption=none")

            self.assertEqual(first.id, "example.com")
            self.assertEqual(second.id, "example.com-2")
            self.assertEqual([p.id for p in ProfileStore(store_path).list()], ["example.com", "example.com-2"])

    def test_invalid_input_raises_parse_error(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            provider = self._provider(Path(tmp) / "profiles.json")
            with self.assertRaises(ParseError):
                provider.from_text("not a supported profile")

    def test_provider_subscription_url_is_not_manual_profile(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            provider = self._provider(Path(tmp) / "profiles.json")
            with self.assertRaises(ParseError):
                provider.from_uri("https://netz.tg/u22aygmb7uPC68W3")

    def test_status_reports_manual_profiles(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            provider = self._provider(Path(tmp) / "profiles.json")
            provider.from_uri("vless://uuid@example.com:443?encryption=none")

            status = provider.status()

            self.assertEqual(status["provider"], "manual")
            self.assertEqual(status["profiles"], 1)
            self.assertEqual(status["last_imported"], 1)


if __name__ == "__main__":
    unittest.main()
