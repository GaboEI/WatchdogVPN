from __future__ import annotations

import json
import subprocess
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

    @patch.dict("drivers.singbox_driver.os.environ", {"WATCHDOGVPN_SINGBOX_BIN": "/opt/karing/sing-box"})
    @patch("drivers.singbox_driver.os.path.exists", return_value=True)
    @patch("drivers.singbox_driver.os.access", return_value=True)
    def test_find_binary_accepts_env_override_for_compatible_cores(self, access_mock, exists_mock) -> None:
        self.assertEqual(self.driver.find_singbox_binary(), "/opt/karing/sing-box")

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
            pbk="pubkey",
            sid="abcd",
            fp="firefox",
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
        self.assertEqual(outbound["tls"]["utls"]["fingerprint"], "firefox")
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


class SingBoxDriverProcessTests(unittest.TestCase):
    def setUp(self) -> None:
        self.driver = SingBoxDriver()
        self.profile = Profile(
            id="vless-1",
            name="vless-demo",
            protocol=ProtocolType.VLESS,
            config={"host": "vless.example.com", "port": 443, "uuid": "uuid-1"},
            source=ProfileSource.MANUAL,
        )

    @patch.object(SingBoxDriver, "find_singbox_binary", return_value="/usr/bin/sing-box")
    @patch.object(SingBoxDriver, "generate_singbox_config")
    @patch("drivers.singbox_driver.subprocess.Popen")
    def test_connect_starts_process(self, popen_mock, generate_mock, binary_mock) -> None:
        process = popen_mock.return_value
        process.poll.return_value = None

        self.assertTrue(self.driver.connect(self.profile))
        generate_mock.assert_called_once_with(self.profile)
        popen_mock.assert_called_once()
        self.assertIs(self.driver._process, process)
        self.assertIs(self.driver._active_profile, self.profile)
        self.assertIsNotNone(self.driver._connected_at)
        self.assertEqual(popen_mock.call_args.args[0], ["/usr/bin/sing-box", "run", "-c", "/tmp/watchdogvpn_singbox.json"])

    @patch.object(SingBoxDriver, "find_singbox_binary", return_value=None)
    @patch.object(SingBoxDriver, "generate_singbox_config")
    @patch("drivers.singbox_driver.subprocess.Popen")
    def test_connect_returns_false_when_binary_missing(self, popen_mock, generate_mock, binary_mock) -> None:
        self.assertFalse(self.driver.connect(self.profile))
        generate_mock.assert_not_called()
        popen_mock.assert_not_called()

    @patch.object(SingBoxDriver, "_cleanup_config")
    def test_disconnect_terminates_and_cleans_config(self, cleanup_mock) -> None:
        process = unittest.mock.Mock()
        process.poll.return_value = None
        self.driver._process = process
        self.driver._active_profile = self.profile
        self.driver._connected_at = unittest.mock.sentinel.connected_at

        self.assertTrue(self.driver.disconnect())
        process.terminate.assert_called_once()
        process.wait.assert_called()
        cleanup_mock.assert_called_once()
        self.assertIsNone(self.driver._process)
        self.assertIsNone(self.driver._active_profile)
        self.assertIsNone(self.driver._connected_at)

    @patch.object(SingBoxDriver, "_cleanup_config")
    def test_disconnect_kills_hung_process(self, cleanup_mock) -> None:
        process = unittest.mock.Mock()
        process.poll.return_value = None
        process.wait.side_effect = [subprocess.TimeoutExpired(cmd="sing-box", timeout=5), None]
        self.driver._process = process

        self.assertTrue(self.driver.disconnect())
        process.terminate.assert_called_once()
        process.kill.assert_called_once()
        self.assertEqual(process.wait.call_count, 2)
        cleanup_mock.assert_called_once()

    def test_status_returns_standby_without_process(self) -> None:
        state = self.driver.status()
        self.assertEqual(state.status, "standby")

    def test_status_returns_connected_when_process_alive(self) -> None:
        process = unittest.mock.Mock()
        process.poll.return_value = None
        self.driver._process = process
        self.driver._active_profile = self.profile
        self.driver._connected_at = unittest.mock.sentinel.connected_at

        state = self.driver.status()
        self.assertEqual(state.status, "connected")
        self.assertEqual(state.active_profile_id, "vless-1")
        self.assertIs(state.connected_at, unittest.mock.sentinel.connected_at)
        self.assertTrue(state.proxy_active)
        self.assertTrue(state.tun_active)

    def test_status_returns_standby_when_process_dead(self) -> None:
        process = unittest.mock.Mock()
        process.poll.return_value = 1
        self.driver._process = process

        state = self.driver.status()
        self.assertEqual(state.status, "standby")


class SingBoxDriverHealthTests(unittest.TestCase):
    def setUp(self) -> None:
        self.driver = SingBoxDriver()
        self.process = unittest.mock.Mock()
        self.process.poll.return_value = None
        self.driver._process = self.process

    @patch.object(SingBoxDriver, "_http_via_proxy", return_value=True)
    @patch.object(SingBoxDriver, "_wait_for_proxy_port", return_value=True)
    def test_health_check_ok(self, port_mock, http_mock) -> None:
        self.assertEqual(self.driver.health_check(), "ok")

    @patch.object(SingBoxDriver, "_http_via_proxy", return_value=False)
    @patch.object(SingBoxDriver, "_wait_for_proxy_port", return_value=True)
    def test_health_check_degraded_when_proxy_http_fails(self, port_mock, http_mock) -> None:
        self.assertEqual(self.driver.health_check(), "degraded")

    @patch.object(SingBoxDriver, "_http_via_proxy", return_value=False)
    @patch.object(SingBoxDriver, "_wait_for_proxy_port", return_value=False)
    def test_health_check_degraded_when_ports_closed(self, port_mock, http_mock) -> None:
        self.assertEqual(self.driver.health_check(), "degraded")

    def test_health_check_down_when_process_missing(self) -> None:
        self.driver._process = None
        self.assertEqual(self.driver.health_check(), "down")

    def test_health_check_down_when_process_dead(self) -> None:
        self.process.poll.return_value = 1
        self.assertEqual(self.driver.health_check(), "down")

    @patch("drivers.singbox_driver.shutil.which", return_value="/usr/bin/curl")
    @patch("drivers.singbox_driver.subprocess.run")
    def test_http_via_proxy_uses_curl_socks(self, run_mock, which_mock) -> None:
        run_mock.return_value.returncode = 0
        self.assertTrue(self.driver._http_via_proxy("https://example.com"))
        args = run_mock.call_args.args[0]
        self.assertIn("--socks5-hostname", args)
        self.assertIn("127.0.0.1:2080", args)


if __name__ == "__main__":
    unittest.main()
