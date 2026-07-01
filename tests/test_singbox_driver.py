from __future__ import annotations

import json
import subprocess
import unittest
from unittest.mock import patch

from dns.models import DNSChannel, DNSChannelName, DNSPolicy, Resolver
from drivers.singbox_driver import SingBoxDriver
from models.profile import Profile, ProfileSource, ProtocolType
from parsers.wg_config import parse_wg_config


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

    @patch.object(SingBoxDriver, "check_version", return_value="sing-box version 1.10.0")
    def test_is_available_checks_version(self, version_mock) -> None:
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
    @patch.object(SingBoxDriver, "_outbound_bind_interface", return_value=None)
    def test_generate_singbox_config_vless_reality(self, bind_mock, write_mock) -> None:
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
    @patch.object(SingBoxDriver, "_outbound_bind_interface", return_value=None)
    def test_generate_singbox_config_covers_other_protocols(self, bind_mock, write_mock) -> None:
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
    @patch.object(SingBoxDriver, "_outbound_bind_interface", return_value=None)
    def test_config_written_is_json_serializable(self, bind_mock, write_mock) -> None:
        profile = self._profile(ProtocolType.TROJAN, host="trojan.example.com", port=443, password="secret")
        config = self.driver.generate_singbox_config(profile)
        json.dumps(config)
        write_mock.assert_called_once()

    @patch.object(SingBoxDriver, "_write_config")
    @patch.object(SingBoxDriver, "_outbound_bind_interface", return_value=None)
    def test_generate_singbox_config_hysteria2_extended_options(self, bind_mock, write_mock) -> None:
        profile = self._profile(
            ProtocolType.HYSTERIA2,
            host="hy2.example.com",
            port=44333,
            password="secret",
            sni="hy2.example.com",
            alpn="h3",
            allowInsecure="true",
            obfsPassword="obfs-secret",
            uploadMbps="100",
            downloadMbps="200",
        )
        config = self.driver.generate_singbox_config(profile)
        outbound = config["outbounds"][0]
        self.assertEqual(outbound["type"], "hysteria2")
        self.assertEqual(outbound["tls"]["alpn"], ["h3"])
        self.assertTrue(outbound["tls"]["insecure"])
        self.assertEqual(outbound["obfs"]["password"], "obfs-secret")
        self.assertEqual(outbound["up_mbps"], 100)
        self.assertEqual(outbound["down_mbps"], 200)

    @patch.object(SingBoxDriver, "_write_config")
    @patch.object(SingBoxDriver, "_outbound_bind_interface", return_value=None)
    def test_generate_singbox_config_trojan_tls_options(self, bind_mock, write_mock) -> None:
        profile = self._profile(
            ProtocolType.TROJAN,
            host="trojan.example.com",
            port=5222,
            password="/secret",
            sni="trojan.example.com",
            fp="firefox",
            alpn="http/1.1",
        )
        config = self.driver.generate_singbox_config(profile)
        outbound = config["outbounds"][0]
        self.assertEqual(outbound["type"], "trojan")
        self.assertEqual(outbound["password"], "/secret")
        self.assertEqual(outbound["tls"]["utls"]["fingerprint"], "firefox")
        self.assertEqual(outbound["tls"]["alpn"], ["http/1.1"])

    @patch.object(SingBoxDriver, "_write_config")
    @patch.object(SingBoxDriver, "_outbound_bind_interface", return_value=None)
    def test_generate_singbox_config_vmess_standard_tls_ws_options(self, bind_mock, write_mock) -> None:
        profile = self._profile(
            ProtocolType.VMESS,
            host="vmess.example.com",
            port="443",
            uuid="uuid-1",
            alter_id="0",
            security="auto",
            tls="tls",
            sni="sni.example.com",
            fingerprint="firefox",
            alpn="h2,http/1.1",
            network="ws",
            path="/ws",
            transport_host="cdn.example.com",
        )
        config = self.driver.generate_singbox_config(profile)
        outbound = config["outbounds"][0]
        self.assertEqual(outbound["type"], "vmess")
        self.assertEqual(outbound["alter_id"], 0)
        self.assertEqual(outbound["security"], "auto")
        self.assertTrue(outbound["tls"]["enabled"])
        self.assertEqual(outbound["tls"]["server_name"], "sni.example.com")
        self.assertEqual(outbound["tls"]["utls"]["fingerprint"], "firefox")
        self.assertEqual(outbound["tls"]["alpn"], ["h2", "http/1.1"])
        self.assertEqual(outbound["transport"]["type"], "ws")
        self.assertEqual(outbound["transport"]["path"], "/ws")
        self.assertEqual(outbound["transport"]["headers"]["Host"], "cdn.example.com")

    @patch.object(SingBoxDriver, "_write_config")
    @patch.object(SingBoxDriver, "_outbound_bind_interface", return_value=None)
    def test_generate_singbox_config_tuic_standard_options(self, bind_mock, write_mock) -> None:
        profile = self._profile(
            ProtocolType.TUIC,
            host="tuic.example.com",
            port=443,
            uuid="uuid-1",
            password="secret",
            sni="tuic.example.com",
            alpn="h3",
            insecure="true",
            congestion_control="cubic",
            udp_relay_mode="native",
        )
        config = self.driver.generate_singbox_config(profile)
        outbound = config["outbounds"][0]
        self.assertEqual(outbound["type"], "tuic")
        self.assertEqual(outbound["congestion_control"], "cubic")
        self.assertEqual(outbound["udp_relay_mode"], "native")
        self.assertTrue(outbound["tls"]["insecure"])
        self.assertEqual(outbound["tls"]["alpn"], ["h3"])

    @patch.object(SingBoxDriver, "_write_config")
    @patch.object(SingBoxDriver, "_outbound_bind_interface", return_value=None)
    def test_generate_singbox_config_proxy_credentials_are_optional(self, bind_mock, write_mock) -> None:
        socks_profile = self._profile(ProtocolType.SOCKS, host="socks.example.com", port=1080)
        http_profile = self._profile(ProtocolType.HTTP, host="http.example.com", port=8080)

        socks_outbound = self.driver.generate_singbox_config(socks_profile)["outbounds"][0]
        http_outbound = self.driver.generate_singbox_config(http_profile)["outbounds"][0]

        self.assertNotIn("username", socks_outbound)
        self.assertNotIn("password", socks_outbound)
        self.assertNotIn("username", http_outbound)
        self.assertNotIn("password", http_outbound)

    @patch.object(SingBoxDriver, "_write_config")
    @patch.object(SingBoxDriver, "_outbound_bind_interface", return_value=None)
    def test_generate_singbox_config_wireguard_from_standard_conf(self, bind_mock, write_mock) -> None:
        profile = parse_wg_config(
            """
            [Interface]
            PrivateKey = private-key
            Address = 10.0.0.2/32, fd00::2/128
            MTU = 1420

            [Peer]
            PublicKey = public-key
            Endpoint = wg.example.com:51820
            AllowedIPs = 0.0.0.0/0, ::/0
            PersistentKeepalive = 25
            """
        )
        config = self.driver.generate_singbox_config(profile)
        outbound = config["outbounds"][0]
        self.assertEqual(outbound["type"], "wireguard")
        self.assertEqual(outbound["server"], "wg.example.com")
        self.assertEqual(outbound["server_port"], 51820)
        self.assertEqual(outbound["local_address"], ["10.0.0.2/32", "fd00::2/128"])
        self.assertEqual(outbound["private_key"], "private-key")
        self.assertEqual(outbound["peer_public_key"], "public-key")
        self.assertEqual(outbound["mtu"], 1420)

    @patch.object(SingBoxDriver, "_write_config")
    @patch.dict("drivers.singbox_driver.os.environ", {"WATCHDOGVPN_SINGBOX_BIND_INTERFACE": "enp4s0"})
    def test_generate_singbox_config_applies_env_bind_interface(self, write_mock) -> None:
        profile = self._profile(ProtocolType.VLESS, host="vless.example.com", port=443, uuid="uuid-1")
        config = self.driver.generate_singbox_config(profile)
        self.assertEqual(config["outbounds"][0]["bind_interface"], "enp4s0")

    @patch.object(SingBoxDriver, "_write_config")
    @patch.dict("drivers.singbox_driver.os.environ", {"WATCHDOGVPN_SINGBOX_BIND_INTERFACE": "off"})
    def test_generate_singbox_config_can_disable_bind_interface(self, write_mock) -> None:
        profile = self._profile(ProtocolType.VLESS, host="vless.example.com", port=443, uuid="uuid-1")
        config = self.driver.generate_singbox_config(profile)
        self.assertNotIn("bind_interface", config["outbounds"][0])

    @patch.object(SingBoxDriver, "_write_config")
    @patch.object(SingBoxDriver, "_outbound_bind_interface", return_value=None)
    def test_generate_singbox_config_adds_dns_policy_without_changing_outbound(
        self,
        bind_mock,
        write_mock,
    ) -> None:
        profile = self._profile(
            ProtocolType.VLESS,
            host="vless.example.com",
            port=443,
            uuid="uuid-1",
        )
        dns_policy = DNSPolicy(
            channels={
                DNSChannelName.DIRECT: DNSChannel(
                    name=DNSChannelName.DIRECT,
                    resolvers=[Resolver(uri="local")],
                ),
                DNSChannelName.PROXY: DNSChannel(
                    name=DNSChannelName.PROXY,
                    resolvers=[Resolver(uri="https://1.1.1.1/dns-query")],
                ),
                DNSChannelName.FINAL: DNSChannel(
                    name=DNSChannelName.FINAL,
                    resolvers=[Resolver(uri="udp://9.9.9.9")],
                ),
            }
        )

        config = self.driver.generate_singbox_config(profile, dns_policy=dns_policy)

        self.assertEqual(config["outbounds"][0]["type"], "vless")
        self.assertEqual(config["outbounds"][0]["tag"], "vless-demo")
        self.assertEqual(config["dns"]["final"], "watchdogvpn-final-1")
        self.assertEqual(config["dns"]["rules"], [
            {"outbound": "direct", "server": "watchdogvpn-direct-1"},
            {"outbound": "vless-demo", "server": "watchdogvpn-fakeip"},
        ])
        dns_inbounds = {
            inbound["tag"]: inbound
            for inbound in config["inbounds"]
            if inbound["tag"].startswith("watchdogvpn-dns-")
        }
        self.assertEqual(set(dns_inbounds), {
            "watchdogvpn-dns-udp-in",
            "watchdogvpn-dns-tcp-in",
        })
        self.assertEqual(dns_inbounds["watchdogvpn-dns-udp-in"]["network"], "udp")
        self.assertEqual(dns_inbounds["watchdogvpn-dns-tcp-in"]["network"], "tcp")
        self.assertEqual(config["route"]["rules"], [
            {
                "inbound": [
                    "watchdogvpn-dns-udp-in",
                    "watchdogvpn-dns-tcp-in",
                ],
                "action": "hijack-dns",
            }
        ])
        dns_servers = {server["tag"]: server for server in config["dns"]["servers"]}
        self.assertEqual(dns_servers["watchdogvpn-fakeip"]["type"], "fakeip")
        self.assertEqual(dns_servers["watchdogvpn-direct-1"]["type"], "local")
        self.assertEqual(dns_servers["watchdogvpn-proxy-1"]["detour"], "vless-demo")
        self.assertEqual(dns_servers["watchdogvpn-final-1"]["server"], "9.9.9.9")

    @patch.object(SingBoxDriver, "_write_config")
    @patch.object(SingBoxDriver, "_outbound_bind_interface", return_value=None)
    def test_generate_singbox_config_skips_dns_hijack_when_disabled(
        self,
        bind_mock,
        write_mock,
    ) -> None:
        profile = self._profile(
            ProtocolType.VLESS,
            host="vless.example.com",
            port=443,
            uuid="uuid-1",
        )
        dns_policy = DNSPolicy(
            tun_hijack=False,
            channels={
                DNSChannelName.FINAL: DNSChannel(
                    name=DNSChannelName.FINAL,
                    resolvers=[Resolver(uri="udp://9.9.9.9")],
                ),
            },
        )

        config = self.driver.generate_singbox_config(profile, dns_policy=dns_policy)

        self.assertIn("dns", config)
        self.assertNotIn("route", config)
        self.assertFalse(
            any(
                inbound["tag"].startswith("watchdogvpn-dns-")
                for inbound in config["inbounds"]
            )
        )

    @patch("drivers.singbox_driver.shutil.which", return_value="/usr/sbin/ip")
    @patch("drivers.singbox_driver.subprocess.run")
    def test_detect_default_interface_skips_tunnels(self, run_mock, which_mock) -> None:
        run_mock.return_value.returncode = 0
        run_mock.return_value.stdout = (
            "default via 10.20.0.2 dev tun0 table 2022\n"
            "default via 192.168.0.1 dev enp4s0 proto dhcp metric 100\n"
        )
        self.assertEqual(self.driver._detect_default_interface(), "enp4s0")


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

        with patch.object(SingBoxDriver, "health_check", return_value="ok"):
            self.assertTrue(self.driver.connect(self.profile))
            generate_mock.assert_called_once_with(self.profile, dns_policy=None)
            popen_mock.assert_called_once()
            self.assertIs(self.driver._process, process)
            self.assertIs(self.driver._active_profile, self.profile)
            self.assertIsNotNone(self.driver._connected_at)
            args = popen_mock.call_args.args[0]
            self.assertEqual(args[:3], ["/usr/bin/sing-box", "run", "-c"])
            self.assertEqual(args[3], str(self.driver._config_path))

    @patch.object(SingBoxDriver, "find_singbox_binary", return_value="/usr/bin/sing-box")
    @patch.object(SingBoxDriver, "generate_singbox_config")
    @patch("drivers.singbox_driver.subprocess.Popen")
    def test_connect_forwards_dns_policy_to_generated_config(
        self, popen_mock, generate_mock, binary_mock
    ) -> None:
        process = popen_mock.return_value
        process.poll.return_value = None
        policy = DNSPolicy(
            channels={
                DNSChannelName.DIRECT: DNSChannel(
                    name=DNSChannelName.DIRECT,
                    resolvers=[Resolver(uri="udp://1.1.1.1")],
                ),
            }
        )

        with patch.object(SingBoxDriver, "health_check", return_value="ok"):
            self.assertTrue(self.driver.connect(self.profile, dns_policy=policy))
            generate_mock.assert_called_once_with(self.profile, dns_policy=policy)

    @patch.object(SingBoxDriver, "find_singbox_binary", return_value=None)
    @patch.object(SingBoxDriver, "generate_singbox_config")
    @patch("drivers.singbox_driver.subprocess.Popen")
    def test_connect_returns_false_when_binary_missing(self, popen_mock, generate_mock, binary_mock) -> None:
        self.assertFalse(self.driver.connect(self.profile))
        generate_mock.assert_not_called()
        popen_mock.assert_not_called()

    @patch.object(SingBoxDriver, "_cleanup_runtime")
    def test_disconnect_terminates_and_cleans_runtime(self, cleanup_mock) -> None:
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

    @patch.object(SingBoxDriver, "_cleanup_runtime")
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

    @patch.object(SingBoxDriver, "_cleanup_runtime")
    def test_disconnect_reports_failed_kill(self, cleanup_mock) -> None:
        process = unittest.mock.Mock()
        process.poll.return_value = None
        process.wait.side_effect = [
            subprocess.TimeoutExpired(cmd="sing-box", timeout=5),
            subprocess.TimeoutExpired(cmd="sing-box", timeout=5),
        ]
        self.driver._process = process

        self.assertFalse(self.driver.disconnect())
        process.terminate.assert_called_once()
        process.kill.assert_called_once()
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
        self.assertFalse(state.tun_active)

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

    @patch.object(SingBoxDriver, "_public_ip_via_proxy", return_value="203.0.113.10")
    @patch.object(SingBoxDriver, "_http_via_proxy", return_value=True)
    @patch.object(SingBoxDriver, "_wait_for_proxy_port", return_value=True)
    def test_health_check_ok(self, port_mock, http_mock, ip_mock) -> None:
        self.assertEqual(self.driver.health_check(), "ok")

    @patch.object(SingBoxDriver, "_public_ip_via_proxy", return_value=None)
    @patch.object(SingBoxDriver, "_http_via_proxy", return_value=True)
    @patch.object(SingBoxDriver, "_wait_for_proxy_port", return_value=True)
    def test_health_check_degraded_when_public_ip_check_fails(self, port_mock, http_mock, ip_mock) -> None:
        self.assertEqual(self.driver.health_check(), "degraded")

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

    @patch("drivers.singbox_driver.shutil.which", return_value="/usr/bin/curl")
    @patch("drivers.singbox_driver.subprocess.run")
    def test_public_ip_via_proxy_logs_observed_ip(self, run_mock, which_mock) -> None:
        run_mock.return_value.returncode = 0
        run_mock.return_value.stdout = "203.0.113.10\n"
        run_mock.return_value.stderr = ""
        self.assertEqual(self.driver._public_ip_via_proxy(), "203.0.113.10")
        args = run_mock.call_args.args[0]
        self.assertIn("--socks5-hostname", args)
        self.assertIn("127.0.0.1:2080", args)
        self.assertIn("https://api.ipify.org", args)


if __name__ == "__main__":
    unittest.main()
