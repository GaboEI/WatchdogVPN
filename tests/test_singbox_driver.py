from __future__ import annotations

import json
import unittest
from unittest.mock import patch

from drivers.singbox_driver import SingBoxDriver
from models.profile import Profile, ProfileSource, ProtocolType


class SingBoxDriverBinaryTests(unittest.TestCase):
    def setUp(self) -> None:
        self.driver = SingBoxDriver()

    @patch("drivers.singbox_driver.shutil.which", return_value="/usr/bin/sing-box")
    @patch("drivers.singbox_driver.os.path.exists", return_value=False)
    @patch("drivers.singbox_driver.os.access", return_value=False)
    def test_find_binary_falls_back_to_which(self, access_mock, exists_mock, which_mock) -> None:
        self.assertEqual(self.driver.find_singbox_binary(), "/usr/bin/sing-box")

    @patch("drivers.singbox_driver.shutil.which", return_value=None)
    @patch("drivers.singbox_driver.os.path.exists", return_value=False)
    @patch("drivers.singbox_driver.os.access", return_value=False)
    def test_find_binary_returns_none_when_missing(self, access_mock, exists_mock, which_mock) -> None:
        self.assertIsNone(self.driver.find_singbox_binary())

    @patch.object(SingBoxDriver, "find_singbox_binary", return_value="/usr/bin/sing-box")
    @patch("drivers.singbox_driver.subprocess.run")
    def test_check_version_returns_output(self, run_mock, binary_mock) -> None:
        run_mock.return_value.stdout = "sing-box version 1.10.0"
        run_mock.return_value.stderr = ""
        self.assertEqual(self.driver.check_version(), "sing-box version 1.10.0")
        run_mock.assert_called_once_with(
            ["/usr/bin/sing-box", "version"],
            text=True,
            capture_output=True,
            check=False,
        )

    @patch.object(SingBoxDriver, "find_singbox_binary", return_value=None)
    def test_check_version_raises_when_missing(self, binary_mock) -> None:
        with self.assertRaises(FileNotFoundError):
            self.driver.check_version()

    @patch.object(SingBoxDriver, "find_singbox_binary", return_value="/usr/bin/sing-box")
    def test_is_available_uses_binary_presence(self, binary_mock) -> None:
        self.assertTrue(self.driver.is_available())

    @patch.object(SingBoxDriver, "find_singbox_binary", return_value=None)
    def test_is_available_is_false_when_missing(self, binary_mock) -> None:
        self.assertFalse(self.driver.is_available())


class SingBoxDriverConfigTests(unittest.TestCase):
    def setUp(self) -> None:
        self.driver = SingBoxDriver()

    def _profile(self, protocol: ProtocolType, **config) -> Profile:
        return Profile(
            id=config.pop("id", f"{protocol.value}-1"),
            name=config.pop("name", f"{protocol.value}-demo"),
            protocol=protocol,
            config=config,
            source=ProfileSource.MANUAL,
        )

    @patch.object(SingBoxDriver, "_write_config")
    def test_generate_singbox_config_vless_reality(self, write_mock) -> None:
        profile = self._profile(
            ProtocolType.VLESS,
            host="vless.example.com",
            port=443,
            uuid="uuid-1",
            sni="example.com",
            reality_public_key="pubkey",
            short_id="abcd",
        )
        config = self.driver.generate_singbox_config(profile)

        self.assertEqual(config["log"]["level"], "warning")
        self.assertEqual(config["inbounds"][0]["type"], "socks")
        outbound = config["outbounds"][0]
        self.assertEqual(outbound["type"], "vless")
        self.assertEqual(outbound["server"], "vless.example.com")
        self.assertEqual(outbound["server_port"], 443)
        self.assertEqual(outbound["uuid"], "uuid-1")
        self.assertTrue(outbound["tls"]["enabled"])
        self.assertEqual(outbound["tls"]["reality"]["public_key"], "pubkey")
        self.assertEqual(outbound["tls"]["reality"]["short_id"], "abcd")
        write_mock.assert_called_once()

    @patch.object(SingBoxDriver, "_write_config")
    def test_generate_singbox_config_covers_other_protocols(self, write_mock) -> None:
        cases = [
            (ProtocolType.VMESS, {"host": "vmess.example.com", "port": 443, "uuid": "u1"}),
            (ProtocolType.TROJAN, {"host": "trojan.example.com", "port": 443, "password": "secret"}),
            (ProtocolType.HYSTERIA2, {"host": "h2.example.com", "port": 443, "password": "secret"}),
            (ProtocolType.TUIC, {"host": "tuic.example.com", "port": 443, "uuid": "u2", "password": "secret"}),
            (ProtocolType.SHADOWSOCKS, {"host": "ss.example.com", "port": 8388, "method": "aes-128-gcm", "password": "secret"}),
            (ProtocolType.WIREGUARD, {"host": "wg.example.com", "port": 51820, "private_key": "priv", "public_key": "pub"}),
            (ProtocolType.SOCKS, {"host": "socks.example.com", "port": 1080, "username": "user", "password": "pass"}),
            (ProtocolType.HTTP, {"host": "http.example.com", "port": 8080, "username": "user", "password": "pass"}),
        ]
        for protocol, cfg in cases:
            with self.subTest(protocol=protocol):
                profile = self._profile(protocol, **cfg)
                config = self.driver.generate_singbox_config(profile)
                self.assertEqual(config["outbounds"][0]["type"], protocol.value if protocol is not ProtocolType.SHADOWSOCKS else "shadowsocks")
                self.assertEqual(config["inbounds"][1]["type"], "http")
        self.assertEqual(write_mock.call_count, len(cases))

    @patch.object(SingBoxDriver, "_write_config")
    def test_generate_singbox_config_rejects_unsupported(self, write_mock) -> None:
        profile = self._profile(ProtocolType.ADGUARD)
        with self.assertRaises(ValueError):
            self.driver.generate_singbox_config(profile)

    @patch.object(SingBoxDriver, "_write_config")
    def test_config_written_is_json_serializable(self, write_mock) -> None:
        profile = self._profile(ProtocolType.TROJAN, host="trojan.example.com", port=443, password="secret")
        config = self.driver.generate_singbox_config(profile)
        json.dumps(config)
        write_mock.assert_called_once()


if __name__ == "__main__":
    unittest.main()
