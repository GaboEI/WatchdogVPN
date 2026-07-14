from __future__ import annotations

import json
import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from threading import Barrier
from unittest.mock import patch

from config.profile_store import ProfileStore
from models.profile import Profile, ProfileSource, ProtocolType
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
                                "uuid": "uuid-1",
                            },
                            {
                                "type": "trojan",
                                "tag": "trojan-1",
                                "server": "trojan.example.com",
                                "server_port": 443,
                                "password": "secret",
                            },
                        ]
                    }
                )
            )

            stored = ProfileStore(store_path).list()
            self.assertEqual(profile.id, "vless-1")
            self.assertEqual([p.id for p in stored], ["vless-1", "trojan-1"])
            self.assertTrue(all(p.in_rotation_pool for p in stored))

    def test_from_text_imports_watchdog_profile_json(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store_path = Path(tmp) / "profiles.json"
            provider = self._provider(store_path)
            source_profile = Profile(
                id="wg-json",
                name="WireGuard JSON",
                protocol=ProtocolType.WIREGUARD,
                config={
                    "server": "wg.example.com",
                    "server_port": 51820,
                    "private_key": "private",
                    "public_key": "public",
                    "local_address": "10.0.0.2/32",
                },
                source=ProfileSource.MANUAL,
            )

            profile = provider.from_text(json.dumps(source_profile.to_dict()))

            self.assertEqual(profile.id, "wg-json")
            self.assertEqual(profile.protocol, ProtocolType.WIREGUARD)
            self.assertEqual(ProfileStore(store_path).get("wg-json"), profile)

    def test_from_text_normalizes_watchdog_vmess_id_to_uuid(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            provider = self._provider(Path(tmp) / "profiles.json")
            source_profile = Profile(
                id="vmess-json",
                name="VMess JSON",
                protocol=ProtocolType.VMESS,
                config={
                    "host": "vmess.example.com",
                    "port": 8880,
                    "id": "vmess-uuid",
                    "tls": True,
                },
                source=ProfileSource.MANUAL,
            )

            profile = provider.from_text(json.dumps(source_profile.to_dict()))

            self.assertEqual(profile.config["uuid"], "vmess-uuid")

    def test_watchdog_profile_json_missing_secret_is_not_persisted(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store_path = Path(tmp) / "profiles.json"
            provider = self._provider(store_path)
            source_profile = Profile(
                id="visible-label",
                name="Visible label",
                protocol=ProtocolType.TROJAN,
                config={"host": "trojan.example.com", "port": 443},
                source=ProfileSource.MANUAL,
            )

            with self.assertRaisesRegex(ParseError, "non-empty password"):
                provider.from_text(json.dumps(source_profile.to_dict()))
            self.assertEqual(ProfileStore(store_path).list(), [])

    def test_from_text_normalizes_watchdog_wireguard_raw_config(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            provider = self._provider(Path(tmp) / "profiles.json")
            source_profile = Profile(
                id="wg-json",
                name="WireGuard JSON",
                protocol=ProtocolType.WIREGUARD,
                config={
                    "raw_config": (
                        "[Interface]\nPrivateKey = private-key\nAddress = 10.0.0.2/32\n"
                        "[Peer]\nPublicKey = public-key\nEndpoint = wg.example.com:51820\n"
                        "AllowedIPs = 0.0.0.0/0\n"
                    )
                },
                source=ProfileSource.MANUAL,
            )

            profile = provider.from_text(json.dumps(source_profile.to_dict()))

            self.assertEqual(profile.config["private_key"], "private-key")
            self.assertEqual(profile.config["public_key"], "public-key")
            self.assertEqual(profile.config["endpoint"], "wg.example.com:51820")

    def test_from_text_imports_v2ray_trojan_outbound(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            provider = self._provider(Path(tmp) / "profiles.json")

            profile = provider.from_text(
                json.dumps(
                    {
                        "outbounds": [
                            {
                                "protocol": "trojan",
                                "settings": {
                                    "servers": [
                                        {
                                            "address": "trojan.example.com",
                                            "port": 5222,
                                            "password": "secret",
                                        }
                                    ]
                                },
                                "streamSettings": {
                                    "network": "tcp",
                                    "security": "tls",
                                    "tlsSettings": {"serverName": "trojan.example.com"},
                                },
                            }
                        ]
                    }
                )
            )

            self.assertEqual(profile.protocol, ProtocolType.TROJAN)
            self.assertEqual(profile.config["server"], "trojan.example.com")
            self.assertEqual(profile.config["server_port"], 5222)

    def test_from_text_imports_hysteria2_yaml(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            provider = self._provider(Path(tmp) / "profiles.json")

            profile = provider.from_text(
                """
                server: hy.example.com:44333
                auth: password
                tls:
                  sni: hy.example.com
                  insecure: true
                obfs:
                  type: salamander
                  salamander:
                    password: obfs-secret
                bandwidth:
                  up: 100 mbps
                  down: 100 mbps
                """
            )

            self.assertEqual(profile.protocol, ProtocolType.HYSTERIA2)
            self.assertEqual(profile.config["server"], "hy.example.com")
            self.assertEqual(profile.config["server_port"], 44333)
            self.assertEqual(profile.config["obfs_password"], "obfs-secret")

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

    def test_multi_profile_duplicate_later_item_leaves_store_unchanged(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store_path = Path(tmp) / "profiles.json"
            provider = self._provider(store_path)
            ProfileStore(store_path).add(
                Profile(
                    id="existing",
                    name="existing",
                    protocol=ProtocolType.VLESS,
                    config={"host": "example.com", "port": 443, "uuid": "existing-uuid"},
                    source=ProfileSource.MANUAL,
                )
            )
            before = store_path.read_bytes()

            with self.assertRaisesRegex(ParseError, "manual import contains duplicate profiles"):
                provider.from_text(
                    "\n".join(
                        (
                            "vless://duplicate-uuid@duplicate.example.com:443?encryption=none#duplicate",
                            "vless://duplicate-uuid@duplicate.example.com:443?encryption=none#duplicate",
                        )
                    )
                )

            self.assertEqual(store_path.read_bytes(), before)
            self.assertEqual([profile.id for profile in ProfileStore(store_path).list()], ["existing"])
            self.assertEqual(provider.last_imported, [])

    def test_multi_profile_storage_failure_leaves_store_unchanged(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store_path = Path(tmp) / "profiles.json"
            store = ProfileStore(store_path)
            provider = ManualProvider(store, rotation_prompt=lambda _profile: False)
            store.add(
                Profile(
                    id="existing",
                    name="existing",
                    protocol=ProtocolType.VLESS,
                    config={"host": "example.com", "port": 443, "uuid": "existing-uuid"},
                    source=ProfileSource.MANUAL,
                )
            )
            before = store_path.read_bytes()

            with patch.object(store, "_save_raw", side_effect=OSError("injected storage failure")):
                with self.assertRaisesRegex(OSError, "injected storage failure"):
                    provider.from_text(
                        "\n".join(
                            (
                                "vless://first-uuid@first.example.com:443?encryption=none#first",
                                "vless://second-uuid@second.example.com:443?encryption=none#second",
                            )
                        )
                    )

            self.assertEqual(store_path.read_bytes(), before)
            self.assertEqual([profile.id for profile in ProfileStore(store_path).list()], ["existing"])
            self.assertEqual(provider.last_imported, [])

    def test_concurrent_multi_profile_imports_keep_each_batch_complete(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store_path = Path(tmp) / "profiles.json"
            barrier = Barrier(2)

            def import_batch(prefix: str) -> list[str]:
                provider = self._provider(store_path)
                barrier.wait()
                provider.from_text(
                    "\n".join(
                        (
                            f"vless://{prefix}-one@example.com:443?encryption=none#shared",
                            f"vless://{prefix}-two@example.com:443?encryption=none#shared",
                        )
                    )
                )
                return [profile.config["uuid"] for profile in provider.last_imported]

            with ThreadPoolExecutor(max_workers=2) as executor:
                imported = list(executor.map(import_batch, ("alpha", "beta")))

            stored = ProfileStore(store_path).list()
            stored_uuids = [profile.config["uuid"] for profile in stored]
            self.assertEqual(len(stored), 4)
            self.assertEqual(set(stored_uuids), {"alpha-one", "alpha-two", "beta-one", "beta-two"})
            self.assertEqual({tuple(batch) for batch in imported}, {
                ("alpha-one", "alpha-two"),
                ("beta-one", "beta-two"),
            })
            for batch in imported:
                positions = sorted(stored_uuids.index(uuid) for uuid in batch)
                self.assertEqual(positions[1] - positions[0], 1)

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

    def test_duplicate_profile_import_is_rejected_without_secret_leak(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store_path = Path(tmp) / "profiles.json"
            provider = self._provider(store_path)

            first = provider.from_uri("vless://uuid@example.com:443?encryption=none")

            with self.assertRaises(ParseError) as captured:
                provider.from_uri("vless://uuid@example.com:443?encryption=none")

            self.assertEqual(first.id, "example.com")
            self.assertEqual(str(captured.exception), "profile already exists: example.com")
            self.assertNotIn("uuid", str(captured.exception))
            self.assertEqual([p.id for p in ProfileStore(store_path).list()], ["example.com"])

    def test_same_name_different_endpoint_is_allowed_with_suffix(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store_path = Path(tmp) / "profiles.json"
            provider = self._provider(store_path)

            first = provider.from_uri("vless://uuid-a@first.example.com:443?encryption=none#demo")
            second = provider.from_uri("vless://uuid-b@second.example.com:443?encryption=none#demo")

            self.assertEqual(first.id, "demo")
            self.assertEqual(second.id, "demo-2")
            self.assertEqual([p.id for p in ProfileStore(store_path).list()], ["demo", "demo-2"])

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
